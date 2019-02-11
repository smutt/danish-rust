extern crate ctrlc;
extern crate pcap;
extern crate etherparse;
extern crate nom;
extern crate tls_parser;

use pcap::Device;
//use etherparse::SlicedPacket;
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use nom::IResult;
use tls_parser::tls;
//use tls_parser::tls_extensions;
//use iptables;

fn main() {
    println!("Start");

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
            Udp(ref _value) => panic!("UDP transport when TCP expected"),
            Tcp(ref value) => {
                tcp_port = value.source_port;
                println!("tcp_port: {:?}", tcp_port);
                match parse_sni(pkt.payload) {
                    Err(_err) => panic!("Cannot parse SNI"), // TODO: Need to do better than this 
                    Ok(sni) => {
                        println!("sni: {:?}", sni);
                        // Here is where we create the cache entry
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

// Parse out the SNI from passed payload
fn parse_sni(payload: &[u8]) -> Result<(&str), ParseError> {
    //println!("\npayload: {:?}", payload);
    //println!("\ntls: {:?}", tls::parse_tls_plaintext(payload));
    match tls::parse_tls_plaintext(payload) {
	      IResult::Done(_remain, record) => {
            println!("tls: {:?}", record);
	      },
	      IResult::Incomplete(_) => panic!("Defragmentation required (TLS record)"),
	      IResult::Error(e) => panic!("parse_tls_record_with_header failed: {:?}",e),

    }
    Ok("derps")
}

///Errors in the given data, placeholder for now
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ParseError {
    Foo(usize),
    Bar(usize),
}
