extern crate ctrlc;
extern crate pcap;
extern crate etherparse;

use pcap::Device;
use etherparse::SlicedPacket;
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use iptables;

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
        println!("received packet! {:?}", packet);

        // Look into PacketHeaders instead of slices
        let slices: SlicedPacket = match SlicedPacket::from_ethernet(&packet) {
            Err(_err) => {
                panic!("Cannot parse pkt"); // TODO: Need to do better than this 
            }
            Ok(layers) => {
                println!("link: {:?}", layers.link);
                println!("vlan: {:?}", layers.vlan);
                println!("ip: {:?}", layers.ip);
                println!("transport: {:?}", layers.transport);
                layers
            }
        };

        println!("payload: {:?}", slices.payload);
        for ii in slices.payload {
            println!("{:x}", ii);
        }

        let pkt = PacketHeaders::from_ethernet_slice(&packet)
            .expect("Failed to decode packet");

        println!("Everything: {:?}", pkt);
        println!("etype: {:?}", pkt.link.unwrap().ether_type);
        match pkt.ip.unwrap() {
            Version4(ref value) => println!("proto: {:?}", value.protocol),
            Version6(ref _value) => panic!("IPv6 not yet implemented")
        }
        match pkt.transport.unwrap() {
            Udp(ref _value) => panic!("UDP transport when TCP expected"),
            Tcp(ref value) => println!("tcp_src_port: {:?}", value.source_port)
        }
    }
    println!("Finish");
}

// Die gracefully
fn euthanize() {
    println!("Ctrl-C exiting");
    std::process::exit(0);
}
