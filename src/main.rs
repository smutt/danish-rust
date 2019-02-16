extern crate ctrlc;
extern crate pcap;
extern crate etherparse;
extern crate tls_parser;

use std::collections::HashMap;
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
    ts: u8,
}

#[allow(dead_code)]
struct ServerCacheEntry<'a> {
    ts: u8,
    seq: u8,
    data: &'a[u8],
}

fn main() {
    println!("Start");

    // Setup our cache
    //let mut ClientCache: HashMap<String, ClientCacheEntry>;
    let mut client_cache = HashMap::new();
    let mut _server_cache: HashMap<String, ServerCacheEntry>;

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    // http://serverfault.com/questions/574405/tcpdump-server-hello-certificate-filter
    let bpf_hello_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)";
    //   BPF_REPLY_4 = 'tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2)' \
    //        ' and (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)'
    //ACK == 1 && RST == 0 && SYN == 0 && FIN == 0
    //Must accept TCP fragments

    let mut cap = Device::lookup().unwrap().open().unwrap();
    match cap.filter(bpf_hello_4){
        Ok(_) => (),
        Err(err) => println!("BPF error {}", err.to_string()),
    }

    while let Ok(packet) = cap.next() {
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
                        client_cache.insert(derive_cache_key(sni, tcp_port, ip_src, ip_dst), ClientCacheEntry { ts: 0 });
                        //println!("client_cache: {:?}", client_cache);
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
        Err(_) => (),
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
    }
    Err("parse_sni: General error")
}

// Derives a cache key from unique pairing of values
fn derive_cache_key(sni: String, port: u16, ip_src: [u8;4], ip_dst: [u8;4]) -> String {
    println!("\n {:?} {:?} {:?} {:?}", sni, port, ip_src, ip_dst);
    "derps".to_string()
}
