#[macro_use]
extern crate log;
extern crate env_logger;
extern crate ctrlc;
extern crate pcap;
extern crate etherparse;
extern crate tls_parser;
extern crate nom;
extern crate trust_dns;
extern crate resolv_conf;

use std::str::FromStr;
use std::thread;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use std::time::SystemTime;
use pcap::Device;
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use tls_parser::tls;
use tls_parser::tls_extensions;
use trust_dns::client::{Client, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RecordType};
use resolv_conf::{Config, ScopedIp};
//use iptables;

//Types of errors we can generate from parse_cert()
#[derive(Debug)]
enum CertParseError {
    IncompleteTlsRecord,
    WrongTlsRecord,
}

//Types of errors we can generate from parse_sni()
#[derive(Debug)]
enum SniParseError {
    TlsExtensionError,
    ClientHelloNotFound,
    IncorrectMsgType,
    PayloadParsing,
    General,
}

#[derive(Debug, Clone)]
struct ClientCacheEntry {
    ts: SystemTime, // Last touched timestamp
    sni: String, // SNI
    tlsa: Option<Vec<trust_dns::rr::RData>>, // DNS TLSA RRSET
    response: bool, // Have we queried and gotten a response yet?
}

#[derive(Debug, Clone)]
struct ServerCacheEntry {
    ts: SystemTime, // Last touched timestamp
    seq: Option<u32>, // TCP sequence number for reassembly
    data: Option<Vec<u8>>, // TCP fragment for reassembly
    cert_chain: Option<Vec<Vec<u8>>>, // DER-encoded X.509 certificates
}

fn main() {
    env_logger::builder().default_format_timestamp(false).init();
    debug!("Start");

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    let mut threads = vec![]; // Our threads

    // Setup our cache
    let client_cache = Arc::new(Mutex::new(HashMap::<String, ClientCacheEntry>::new()));
    let client_cache_cl_ptr = Arc::clone(&client_cache);
    let client_cache_sr_ptr = Arc::clone(&client_cache);
    //let mut client_cache: HashMap<String, ClientCacheEntry> = HashMap::new();
    let mut server_cache: HashMap<String, ServerCacheEntry> = HashMap::new();

    let client_4_thr = thread::spawn(move || {
        // Setup DNS
        match read_resolv_conf() {
            Err(err) => panic!("Error reading /etc/resolv.conf {:?}", err),
            Ok(resolv_conf_contents) => {
                match Config::parse(resolv_conf_contents) {
                    Err(err) => panic!("Error parsing /etc/resolv.conf {:?}", err),
                    Ok(resolv_conf_parsed) => {
                        let mut ii = 0;
                        let resolver = loop {
                            if resolv_conf_parsed.nameservers.len() == ii {
                                panic!("Zero IPv4 nameservers found in /etc/resolv.conf");
                            }
                            match resolv_conf_parsed.nameservers[ii] {
                                ScopedIp::V4(ip) => {
                                    break ip.to_string() + ":53";
                                }
                                ScopedIp::V6(ref _ip, ref _scope) => (),
                            }
                            ii = ii + 1;
                        };
                        debug!("DNS resolver found: {:?}", resolver);
                        let conn = UdpClientConnection::new(resolver.parse().unwrap()).unwrap();
                        let client = SyncClient::new(conn);

                        // Setup pcap listen
                        // ACK == 1 && RST == 0 && SYN == 0 && FIN == 0 && must accept TCP fragments
                        let bpf_client_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)";
                        let mut client_cap = Device::lookup().unwrap().open().unwrap();
                        match client_cap.filter(bpf_client_4){
                            Ok(_) => (),
                            Err(err) => error!("BPF error {}", err.to_string()),
                        }

                        while let Ok(packet) = client_cap.next() {
                            let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet");
                            //debug!("Everything: {:?}", pkt);

                            let ip_src: [u8;4];
                            let ip_dst: [u8;4];
                            match pkt.ip.unwrap() {
                                Version6(_) => {
                                    warn!("IPv6 packet captured, but not yet implemented");
                                    continue;
                                }
                                Version4(ref value) => {
                                    ip_src = value.source;
                                    ip_dst = value.destination;
                                    match pkt.transport.unwrap() {
                                        Udp(_) => error!("UDP transport captured when TCP expected"),
                                        Tcp(ref value) => {
                                            match parse_sni(pkt.payload) {
                                                Err(_) => error!("Error parsing SNI"),
                                                Ok(sni) => {
                                                    let key = derive_cache_key(&ip_src, &ip_dst, &value.source_port);
                                                    debug!("Inserting client_cache entry: {:?} sni: {:?}", key, sni);
                                                    client_cache_cl_ptr.lock().unwrap().insert(
                                                        derive_cache_key(&ip_src, &ip_dst, &value.source_port),
                                                        ClientCacheEntry {
                                                            ts: SystemTime::now(),
                                                            sni: sni.clone(),
                                                            tlsa: None,
                                                            response: false,
                                                        });

                                                    let qname = "_443._tcp.".to_owned() + &sni.clone();
                                                    let name = Name::from_str(&qname).unwrap();
                                                    let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::TLSA).unwrap();
                                                    debug!("{:?}", response);
                                                    if response.answers().len() == 0 { // TODO: Get smarter about recognizing NXDOMAIN
                                                        debug!("{:?} TLSA returned NXDOMAIN", qname);
                                                        client_cache_cl_ptr.lock().unwrap().remove(&key);
                                                        client_cache_cl_ptr.lock().unwrap().insert(key, ClientCacheEntry {
                                                            ts: SystemTime::now(),
                                                            sni: sni.clone(),
                                                            tlsa: None,
                                                            response: true,
                                                        });
                                                    } else {
                                                        debug!("{:?} TLSA returned RRSET", qname);
                                                        client_cache_cl_ptr.lock().unwrap().remove(&key);
                                                        client_cache_cl_ptr.lock().unwrap().insert(key, ClientCacheEntry {
                                                            ts: SystemTime::now(),
                                                            sni: sni.clone(),
                                                            tlsa: Some(
                                                                response.answers().iter().map(|rr| rr.rdata().clone()).collect::<Vec<_>>()
                                                            ),
                                                            response: true,
                                                        });
                                                        for answer in response.answers() {
                                                            debug!("{:?}", answer.rdata());
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
    });
    threads.push(client_4_thr);

    let server_4_thr = thread::spawn(move || {
        // ACK == 1 && RST == 0 && SYN == 0 && FIN == 0 && must accept TCP fragments
        let bpf_server_4 = "tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2) and 
        (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)";

        let mut server_cap = Device::lookup().unwrap().open().unwrap();
        match server_cap.filter(bpf_server_4){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        while let Ok(resp_packet) = server_cap.next() {
            let resp_pkt = PacketHeaders::from_ethernet_slice(&resp_packet)
                .expect("Failed to decode resp_packet");
            //debug!("Everything: {:?}", resp_pkt);

            /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
            So a 60 byte packet was 64 bytes on the wire.
            Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
            Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
            The chances of us actually needing that small of a packet are close to zero. */
            if resp_packet.len() <= 60 {
                continue;
            }
            let resp_ip_src: [u8;4];
            let resp_ip_dst: [u8;4];

            match resp_pkt.ip.unwrap() {
                Version6(_) => {
                    warn!("IPv6 packet captured, but not yet implemented");
                    continue;
                }
                Version4(ref value) => {
                    resp_ip_src = value.source;
                    resp_ip_dst = value.destination;
                    match resp_pkt.transport.unwrap() {
                        Udp(_) => warn!("UDP transport captured when TCP expected"),
                        Tcp(ref tcp) => {
                            //debug!("resp_tcp_seq: {:?}", tcp.sequence_number);
                            //debug!("payload_len: {:?}", resp_pkt.payload.len());
                            let key = derive_cache_key(&resp_ip_dst, &resp_ip_src, &tcp.destination_port);
                            if client_cache_sr_ptr.lock().unwrap().contains_key(&key) {
                                debug!("Found client_cache key {:?}", key);

                                /* The Certificate TLS message may not be the first TLS message we receive.
                                It will also likely span multiple TCP packets. Thus we need to test every payload
                                received to see if it is complete, if not we need to store it until we get the
                                next segment and test completeness again. If it is complete, but still not a
                                Certificate TLS message we need to flush cache and start waiting again. */
                                match server_cache.get(&key) {
                                    Some(ref entry) => {
                                        if entry.cert_chain.is_some() {
                                            debug!("Ignoring server_cache key {:?}", key);
                                            continue;
                                        }

                                        debug!("Found server_cache key {:?}", key);
                                        let mut raw_tls = entry.data.clone().unwrap();
                                        raw_tls.extend_from_slice(&resp_pkt.payload);
                                        match parse_cert(&raw_tls[..]) {
                                            Ok(cert_chain) => {
                                                debug!("TLS cert found, len: {:?}", cert_chain.len());
                                                debug!("Finalizing server_cache entry: {:?}", key);
                                                server_cache.insert(key, ServerCacheEntry {
                                                    ts: SystemTime::now(),
                                                    seq: None,
                                                    data: None,
                                                    cert_chain: Some(cert_chain.clone()),
                                                });
                                            }
                                            Err(err) => {
                                                match err {
                                                    CertParseError::IncompleteTlsRecord | CertParseError::WrongTlsRecord => {
                                                        if entry.seq.unwrap() == tcp.sequence_number {
                                                            debug!("Updating server_cache entry: {:?}", key);
                                                            server_cache.insert(key, ServerCacheEntry {
                                                                ts: SystemTime::now(),
                                                                seq: Some(tcp.sequence_number + resp_pkt.payload.len() as u32),
                                                                data: Some(raw_tls),
                                                                cert_chain: None,
                                                            });
                                                        }else{
                                                            debug!("Out-of-order TCP datagrams detected"); // TODO
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        debug!("No server_cache key {:?}", key);
                                        match parse_cert(&resp_pkt.payload) {
                                            Ok(cert_chain) => {
                                                debug!("cert_len: {:?}", cert_chain.len());
                                                debug!("Finalizing server_cache entry: {:?}", key);
                                                server_cache.insert(key, ServerCacheEntry {
                                                    ts: SystemTime::now(),
                                                    seq: None,
                                                    data: None,
                                                    cert_chain: Some(cert_chain.clone()),
                                                });
                                            }
                                            Err(err)=> {
                                                match err {
                                                    CertParseError::IncompleteTlsRecord | CertParseError::WrongTlsRecord => {
                                                        debug!("Inserting server_cache entry: {:?}", key);
                                                        server_cache.insert(key, ServerCacheEntry {
                                                            ts: SystemTime::now(),
                                                            seq: Some(tcp.sequence_number + resp_pkt.payload.len() as u32),
                                                            data: Some(resp_pkt.payload.to_vec()),
                                                            cert_chain: None,
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
    });
    threads.push(server_4_thr);

    for thr in threads {
        thr.join().unwrap();
    }

    debug!("Finish");
}

// Die gracefully
fn euthanize() {
    info!("Ctrl-C exiting");
    std::process::exit(0);
}

// Return contents of /etc/resolv.conf or Err
fn read_resolv_conf() -> Result<String, std::io::Error> {
    let path = Path::new("/etc/resolv.conf");
    let mut handle = File::open(path)?;
    let mut contents = String::new();
    handle.read_to_string(&mut contents)?;
    return Ok(contents);
}

// Parse the X.509 cert from TLS ServerHello Messages
// Recursively call parse_tls_plaintext() until we find the TLS Certificate Record or Error
fn parse_cert(payload: &[u8]) -> Result<Vec<Vec<u8>>, CertParseError> {
    //debug!("Entered parse_cert() payload.len: {:?}", payload.len());
    //debug!("hex {:?}", payload.iter().map(|h| format!("{:X}", h)).collect::<Vec<_>>());
    match tls::parse_tls_plaintext(payload) {
        Ok(plaintext) => {
            for msg in plaintext.1.msg.iter() {
                match msg {
                    tls::TlsMessage::Handshake(ref handshake) => {
                        //debug!("parse_cert>handshake: {:?}", handshake);
                        match handshake {
                            tls::TlsMessageHandshake::Certificate(ref cert_record) => {
                                return Ok(cert_record.cert_chain.iter().map(|c| c.data.to_vec()).collect::<Vec<_>>());
                            }
                            _ => return parse_cert(&plaintext.0),
                        }
                    }
                    _ => return parse_cert(&plaintext.0),
                }
            }
            return Err(CertParseError::WrongTlsRecord);
        }
        _ => return Err(CertParseError::IncompleteTlsRecord),
    }
}

// Parse out the SNI from passed TLS payload
fn parse_sni(payload: &[u8]) -> Result<String, SniParseError> {
    match tls::parse_tls_plaintext(payload) {
        Ok(value) => {
            match value.1.msg[0] { // TODO Problematic because we don't iterate through all messages
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
                                _ => return Err(SniParseError::TlsExtensionError),
                            }
                        }
                        _ => return Err(SniParseError::ClientHelloNotFound),
                    }
                }
                _ => return Err(SniParseError::IncorrectMsgType),
            }
        }
        _ => return Err(SniParseError::PayloadParsing),
    }
    Err(SniParseError::General)
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
