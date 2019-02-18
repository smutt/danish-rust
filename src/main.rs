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
struct ClientCacheEntry {
    ts: SystemTime,
    sni: String,
}

#[allow(dead_code)]
struct ServerCacheEntry<'a> {
    ts: SystemTime,
    seq: u8,
    data: &'a[u8], // TCP fragment for reassembly
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
    let bpf_client_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)";
    let bpf_server_4 = "tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2) and 
        (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)";
    //ACK == 1 && RST == 0 && SYN == 0 && FIN == 0
    //Must accept TCP fragments

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
        //println!("received packet! {:?}", packet);

        let pkt = PacketHeaders::from_ethernet_slice(&packet)
            .expect("Failed to decode packet");

        let ip_src: [u8;4];
        let ip_dst: [u8;4];
        let tcp_port: u16;

        println!("Everything: {:?}", pkt);
        match pkt.ip.unwrap() {
            Version6(ref _value) => panic!("IPv6 not yet implemented"),
            Version4(ref value) => {
                ip_src = value.source;
                ip_dst = value.destination;
            }
        }
        println!("IP_src: {:?}", ip_src);
        println!("IP_dst: {:?}", ip_dst);

        match pkt.transport.unwrap() {
            Udp(ref _value) => panic!("UDP transport captured when TCP expected"),
            Tcp(ref value) => {
                tcp_port = value.source_port;
                println!("tcp_port: {:?}", tcp_port);
                match parse_sni(pkt.payload) {
                    Err(_err) => panic!("Cannot parse SNI"), // TODO: Need to do better than this 
                    Ok(sni) => {
                        println!("sni: {:?}", sni);
                        println!("Inserting client_cache key: {:?}", derive_cache_key(&ip_src, &ip_dst, &tcp_port));
                        client_cache.insert(derive_cache_key(&ip_src, &ip_dst, &tcp_port), ClientCacheEntry {
                            ts: SystemTime::now(),
                            sni: sni,
                        });


                        while let Ok(resp_packet) = server_cap.next() {
                            //println!("resp_packet! {:?}", resp_packet);
                            let resp_pkt = PacketHeaders::from_ethernet_slice(&resp_packet)
                                .expect("Failed to decode resp_packet");
                            //println!("Everything: {:?}", resp_pkt);

                            let resp_ip_src: [u8;4];
                            let resp_ip_dst: [u8;4];
                            let resp_tcp_port: u16;

                            match resp_pkt.ip.unwrap() {
                                Version6(ref _value) => panic!("IPv6 not yet implemented"),
                                Version4(ref value) => {
                                    resp_ip_src = value.source;
                                    resp_ip_dst = value.destination;
                                }
                            }
                            println!("resp_IP_src: {:?}", resp_ip_src);
                            println!("resp_IP_dst: {:?}", resp_ip_dst);

                            match resp_pkt.transport.unwrap() {
                                Udp(ref _value) => panic!("UDP transport captured when TCP expected"),
                                Tcp(ref value) => {
                                    resp_tcp_port = value.destination_port;
                                    println!("resp_tcp_port: {:?}", resp_tcp_port);
                                    let key = derive_cache_key(&resp_ip_dst, &resp_ip_src, &resp_tcp_port);
                                    if client_cache.contains_key(&key) {
                                        println!("Found key {:?}", key);
                                        if server_cache.contains_key(&key) {
                                            println!("TODO");
                                        }else{
                                            server_cache.insert(key, ServerCacheEntry {
                                                ts: SystemTime::now(),
                                                seq: 0,
                                                data: &[0, 1, 3, 4],
                                                //data: &resp_pkt.payload.clone(),
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
    println!("Finish");
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
