extern crate ctrlc;
extern crate pcap;
extern crate etherparse;
extern crate tls_parser;

use std::collections::HashMap;
use std::time::SystemTime;
use pcap::Device;
//use etherparse::SlicedPacket;
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use tls_parser::tls;
use tls_parser::tls_extensions;
//use iptables;

#[allow(dead_code)]
#[derive(Debug)]
struct ClientCacheEntry {
    ts: SystemTime,
    sni: String,
}

#[allow(dead_code)]
#[derive(Debug)]
struct ServerCacheEntry {
    ts: SystemTime,
    seq: u32,
    data: Vec<u8>, // TCP fragment for reassembly
}

fn main() {
    println!("Start");

    // Setup our cache
    let mut client_cache = HashMap::new();
    let mut server_cache = HashMap::new();

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    // http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
    //ACK == 1 && RST == 0 && SYN == 0 && FIN == 0
    //Must accept TCP fragments
    let bpf_client_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)";
    let bpf_server_4 = "tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2) and 
        (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)";

    let mut client_cap = Device::lookup().unwrap().open().unwrap();
    match client_cap.filter(bpf_client_4){
        Ok(_) => (),
        Err(err) => println!("BPF error {}", err.to_string()),
    }

    let mut server_cap = Device::lookup().unwrap().open().unwrap();
    match server_cap.filter(bpf_server_4){
        Ok(_) => (),
        Err(err) => println!("BPF error {}", err.to_string()),
    }

    while let Ok(packet) = client_cap.next() {
        let pkt = PacketHeaders::from_ethernet_slice(&packet)
            .expect("Failed to decode packet");
        //println!("Everything: {:?}", pkt);

        let ip_src: [u8;4];
        let ip_dst: [u8;4];

        match pkt.ip.unwrap() {
            Version6(_) => panic!("IPv6 not yet implemented"),
            Version4(ref value) => {
                /* The next match stmt should come here. Will do when we break this out async */
                ip_src = value.source;
                ip_dst = value.destination;
            }
        }
        //println!("IP_src: {:?}", ip_src);
        //println!("IP_dst: {:?}", ip_dst);

        match pkt.transport.unwrap() {
            Udp(_) => println!("UDP transport captured when TCP expected"),
            Tcp(ref value) => {
                //println!("tcp_port: {:?}", tcp_port);
                match parse_sni(pkt.payload) {
                    Err(_) => panic!("Cannot parse SNI"),
                    Ok(sni) => {
                        println!("Inserting client_cache key: {:?} sni: {:?}", derive_cache_key(&ip_src, &ip_dst, &value.source_port), sni);
                        client_cache.insert(derive_cache_key(&ip_src, &ip_dst, &value.source_port), ClientCacheEntry {
                            ts: SystemTime::now(),
                            sni: sni,
                        });

                        while let Ok(resp_packet) = server_cap.next() {
                            let resp_pkt = PacketHeaders::from_ethernet_slice(&resp_packet)
                                .expect("Failed to decode resp_packet");
                            //println!("Everything: {:?}", resp_pkt);

                            let resp_ip_src: [u8;4];
                            let resp_ip_dst: [u8;4];

                            match resp_pkt.ip.unwrap() {
                                Version6(_) => panic!("IPv6 not yet implemented"),
                                Version4(ref value) => {
                                    /* The next match stmt should come here. Will do when we break this out async */
                                    resp_ip_src = value.source;
                                    resp_ip_dst = value.destination;
                                }
                            }
                            //println!("resp_IP_src: {:?}", resp_ip_src);
                            //println!("resp_IP_dst: {:?}", resp_ip_dst);

                            match resp_pkt.transport.unwrap() {
                                Udp(_) => println!("UDP transport captured when TCP expected"),
                                Tcp(ref tcp) => {
                                    println!("resp_tcp_seq: {:?}", tcp.sequence_number);
                                    println!("payload_len: {:?}", resp_pkt.payload.len());

                                    let key = derive_cache_key(&resp_ip_dst, &resp_ip_src, &tcp.destination_port);
                                    if client_cache.contains_key(&key) {
                                        println!("Found client_cache key {:?}", key);
                                        match server_cache.get(&key) {
                                            Some(ref entry) => {
                                                println!("Found server_cache key {:?}", key);
                                                println!("server_cache: {:?}", entry);
                                                match parse_cert(&resp_pkt.payload) {
                                                    Ok(cert) => println!("X509_cert: {:?}", cert),
                                                    Err(err) => {
                                                        println!("parse_cert_err: {:?}", err);
                                                        // Update server_cache.get(&key)
                                                    }
                                                }
                                            }
                                            _ => {
                                                match parse_cert(&resp_pkt.payload) {
                                                    Ok(cert) => println!("X509_cert: {:?}", cert),
                                                    Err(_) => {
                                                        server_cache.insert(key, ServerCacheEntry {
                                                            ts: SystemTime::now(),
                                                            seq: tcp.sequence_number + resp_pkt.payload.len() as u32,
                                                            data: resp_pkt.payload.to_vec(),
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("Finish");
}

// Parse the X.509 cert from TLS ServerHello Messages
fn parse_cert(payload: &[u8]) -> Result<String, &str> {
   match tls::parse_tls_plaintext(payload) {
        Ok(value) => {
            println!("furst: {:?}", value);
        }
       _ => return Err("parse_cert: Error parsing plaintext TLS payload"),
   }
    Err("parse_cert: General error")
}


// Die gracefully
fn euthanize() {
    println!("Ctrl-C exiting");
    std::process::exit(0);
}

// Parse out the SNI from passed TLS payload
fn parse_sni(payload: &[u8]) -> Result<String, &str> {
    match tls::parse_tls_plaintext(payload) {
        Ok(value) => {
            match value.1.msg[0] {
                tls::TlsMessage::Handshake(ref handshake) => {
                    match handshake {
                        tls::TlsMessageHandshake::ClientHello(ref ch) => {
                            match tls_extensions::parse_tls_extensions(ch.ext.unwrap()) {
                                Ok(extensions) => {
                                    for ext in extensions.1.iter() {
                                        match ext {
                                            tls_extensions::TlsExtension::SNI(sni) => {
                                                return Ok(String::from_utf8(sni[0].1.to_vec()).unwrap());
                                            }
                                            _ => (),
                                        }
                                    }
                                }
                                _ => return Err("parse_sni: Error parsing TLS extensions"),
                            }
                        }
                        _ => return Err("parse_sni: TLS ClientHello not found in handshake msg"),
                    }
                }
                _ => return Err("parse_sni: Incorrect TLS msg type"),
            }
        }
        _ => return Err("parse_sni: Error parsing plaintext TLS payload"),
    }
    Err("parse_sni: General error")
}

// Derives a cache key from unique pairing of values
fn derive_cache_key(src: &[u8;4], dst: &[u8;4], port: &u16) -> String {
    let delim = "_".to_string();
    let mut key = "".to_string();
    for n in src.iter() {
        key.push_str(&n.to_string());
        key.push_str(&delim);
    }
    for n in dst.iter() {
        key.push_str(&n.to_string());
        key.push_str(&delim);
    }
    key.push_str(&port.to_string());
    key
}
