/*
Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
All rights reserved.
 */

//////////////
// INCLUDES //
//////////////
#[macro_use]
extern crate log;
use std::{iter, time, thread};
use std::time::{Duration, SystemTime};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use tls_parser::tls;
use tls_parser::tls_extensions;
use resolv::{Resolver, Class, RecordType};
use resolv::record::TLSA;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use sha2::{Sha256, Sha512, Digest};
use pcap::{Capture, Device};
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use iptables;
use x509_parser;
use simpath::Simpath;
use ipaddress::{ipv4, ipv6};
use structopt::StructOpt;

///////////////
// CONSTANTS //
///////////////
const DNS_TIMEOUT: u64 = 1000; // Timeout for DNS queries in milliseconds, must be divisible by DNS_TIMEOUT_DECREMENT
const DNS_TIMEOUT_DECREMENT: u64 = 20; // Decrement for counting down to zero from DNS_TIMEOUT in milliseconds
const IPT_DELIM: &str = "_"; // iptables delimeter for child chains (IPT_DANISH_CHAIN + IPT_DELIM + TRUNCATED_HASH)
const IPT_MAX_CHARS: usize = 28; // maxchars for iptables chain names on Linux
const IPT_SUBCHAIN_MIN_CHARS: usize = 3; // minchars for --sub-chain 
const IPT_SUBCHAIN_MAX_CHARS: usize = 8; // maxchars for --sub-chain 
const CACHE_MIN_STALENESS: u64 = 10; // minimum seconds for a stale [client || server] cache entry to live before deletion
const ACL_CACHE_DELAY: u64 = 10; // Sleep this many seconds between acl_cache cleanup cycles
const ACL_SHORT_TIMEOUT: u64 = 60; // How many seconds do our short ACLs remain installed?
const ACL_LONG_TIMEOUT: u64 = 600; // How many seconds do our long ACLs remain installed?
const IPV6TABLES_DIRS: [&str; 6] = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]; // Where we might find ip6tables executable

/////////////
// STRUCTS //
/////////////
// Types of errors we can generate from parse_cert()
#[derive(Debug)]
enum CertParseError {
    IncompleteTlsRecord,
    WrongTlsRecord,
}

// Types of errors we can generate from parse_sni()
#[derive(Debug)]
enum SniParseError {
    TlsExtensionError,
    ClientHelloNotFound,
    IncorrectMsgType,
    PayloadParsing,
    General,
}

#[derive(Debug, Clone)]
struct ClientCacheEntry { // Key in hashmap is from derive_cache_key()
    ts: SystemTime, // Last touched timestamp
    sni: String, // SNI
    tlsa: Option<Vec<TLSA>>, // DNS TLSA RRSET
    response: bool, // Have we queried and gotten a response yet?
    rpz_blocked: bool, // True if RPZ checking failed and ACL was installed
    stale: bool, // Entry can be deleted at next cleanup
}

#[derive(Debug, Clone)]
struct ServerCacheEntry { // Key in hashmap is from derive_cache_key()
    ts: SystemTime, // Last touched timestamp
    seq: Option<u32>, // TCP sequence number for reassembly
    data: Option<Vec<u8>>, // TCP fragment for reassembly
    stale: bool, // Entry can be deleted at next cleanup
}

#[derive(Debug, Clone)]
struct AclCacheEntry { // Key in hashmap is iptables chain name
    ts: SystemTime, // Last touched timestamp
    insert_ts: SystemTime, // When were these ACLs inserted? None if not yet inserted.
    sni: String, // SNI
    short_active: bool, // Is the short term ACL active?
    short_ipv4: bool, // Is the short term ACL IPv4 or IPv6?
}

#[derive(Debug, StructOpt)]
struct Opt {
    /// iptables/ip6tables top chain
    #[structopt(short = "c", long = "chain", default_value = "OUTPUT")]
    chain: String,
    /// pcap interface to listen on, typically a network interface
    #[structopt(short = "i", long = "interface", default_value = "eth0")]
    iface: String,
    /// enable RPZ operation
    #[structopt(short = "r", long = "rpz")]
    rpz: bool,
    /// iptables/ip6tables sub-chain for ACLs
    #[structopt(short = "s", long = "sub-chain", default_value = "danish")]
    sub_chain: String,
}

///////////////
// FUNCTIONS //
///////////////

///////////////////
// TLS FUNCTIONS //
///////////////////
// TODO get stricter about the kinds of TLS packets we accept. crib from the python
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

// TODO get stricter about the kinds of TLS packets we accept. crib from the python
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

// Parse TLS server hello for both IPv4 and IPv6
fn parse_server_hello(acl_cache: &Arc<RwLock<HashMap::<String, AclCacheEntry>>>,
                      client_cache: &Arc<RwLock<HashMap<String, ClientCacheEntry>>>,
                      server_cache: &Arc<RwLock<HashMap<String, ServerCacheEntry>>>,
                      ip_src: ipaddress::IPAddress, ip_dst: ipaddress::IPAddress,
                      tcp_header: etherparse::TcpHeader, payload: &[u8]) {

    let key = derive_cache_key(&ip_dst, &ip_src, &tcp_header.destination_port);
    let client_seen = client_cache.read().contains_key(&key) && !client_cache.read().get(&key).unwrap().stale;
    if client_seen {
        //debug!("Found client_cache key {:?}", key);

        /* The Certificate TLS message may not be the first TLS message we receive.
        It will also likely span multiple TCP packets. Thus we need to test every payload
        received to see if it is complete, if not we need to store it until we get the
        next segment and test completeness again. If it is complete, but still not a
        Certificate TLS message we need to flush cache and start waiting again. */

        let server_seen = server_cache.read().contains_key(&key);
        if server_seen {
            if let Some(entry) = server_cache.write().get_mut(&key) {
                if entry.stale {
                    //debug!("Ignoring server_cache key {:?}", key);
                    return
                }

                //debug!("Found server_cache key {:?}", key);
                let mut raw_tls = entry.data.clone().unwrap();
                raw_tls.extend_from_slice(&payload);
                match parse_cert(&raw_tls[..]) {
                    Ok(cert_chain) => {
                        debug!("TLS cert found, len: {:?}", cert_chain.len());

                        debug!("Handling validation cert_len: {:?}", cert_chain.len());
                        handle_validation(Arc::clone(&acl_cache), Arc::clone(&client_cache),
                                          cert_chain.clone(), ip_src, ip_dst, tcp_header.destination_port);

                        debug!("Finalizing server_cache entry: {:?}", key);
                        entry.ts = SystemTime::now();
                        entry.seq = None;
                        entry.data = None;
                        entry.stale = true;
                    }
                    Err(err) => {
                        match err { // TODO: Why check errors if they all result in the same action
                            CertParseError::IncompleteTlsRecord | CertParseError::WrongTlsRecord => {
                                if entry.seq.unwrap() == tcp_header.sequence_number {
                                    debug!("Updating server_cache entry: {:?}", key);
                                    entry.ts = SystemTime::now();
                                    entry.seq = Some(tcp_header.sequence_number + payload.len() as u32);
                                    entry.data = Some(raw_tls);
                                    entry.stale = false;
                                }else{
                                    debug!("Out-of-order TCP datagrams detected {:?}", key); // TODO: This error doesn't tell the whole story
                                }
                            }
                        }
                    }
                }
            } else {
                panic!("Inconsistent server_cache {:?}", key);
            }
        } else { // if server_seen
            //debug!("No server_cache key {:?}", key);
            match parse_cert(&payload) {
                Ok(cert_chain) => {
                    debug!("cert_len: {:?}", cert_chain.len());

                    debug!("Handling validation cert_len: {:?}", cert_chain.len());
                    handle_validation(Arc::clone(&acl_cache), Arc::clone(&client_cache),
                                      cert_chain.clone(), ip_src, ip_dst, tcp_header.destination_port);

                    debug!("Finalizing server_cache entry: {:?}", key);
                    server_cache.write().insert(key.clone(), ServerCacheEntry {
                        ts: SystemTime::now(),
                        seq: None,
                        data: None,
                        stale: true,
                    });
                }
                Err(err)=> {
                    match err { // TODO: Why check errors if they all result in the same action
                        CertParseError::IncompleteTlsRecord | CertParseError::WrongTlsRecord => {
                            debug!("Inserting server_cache entry: {:?}", key);
                            server_cache.write().insert(key, ServerCacheEntry {
                                ts: SystemTime::now(),
                                seq: Some(tcp_header.sequence_number + payload.len() as u32),
                                data: Some(payload.to_vec()),
                                stale: false,
                            });
                        }
                    }
                }
            }
        }
    } else {
        debug!("ServerHello begun but no client_cache entry for {:?}", key);
    }
}

///////////////////
// DNS FUNCTIONS //
///////////////////
// Perform DNS TLSA lookup and update client_cache
// TODO: Rewrite using async/await once it's final
fn dns_lookup_tlsa(client_cache: Arc<RwLock<HashMap<String, ClientCacheEntry>>>, key: String) {
    thread::spawn(move || {
        let qname = "_443._tcp.".to_owned() + &client_cache.read().get(&key).unwrap().sni.clone();
        let mut resolver = Resolver::new().unwrap();
        match resolver.query(&qname.into_bytes(), Class::IN, RecordType::TLSA) {
            Ok(mut response) => {
                if let Some(entry) = client_cache.write().get_mut(&key) {
                    entry.response = true;
                    entry.tlsa = Some(response.answers::<TLSA>().map(|t| t.data).collect::<Vec<_>>());
                    entry.ts = SystemTime::now();
                }else{
                    panic!("Failed to update client_cache");
                }
            },
            Err(_err) => {
                if let Some(entry) = client_cache.write().get_mut(&key) {
                    entry.response = true;
                    entry.stale = true;
                    entry.ts = SystemTime::now();
                }else{
                    panic!("Failed to update client_cache");
                }
            }
        }
        debug!("Updated client_cache {:?}", key);
    });
}

//////////////////////////
// VALIDATION FUNCTIONS //
//////////////////////////
// Kicks off TLSA validation thread once X.509 cert has been received
// Determines validation disposition and installs ACLs if necessary
// TODO: Rewrite using async/await once it's final
fn handle_validation(acl_cache: Arc<RwLock<HashMap<String, AclCacheEntry>>>,
                     cl_cache: Arc<RwLock<HashMap<String, ClientCacheEntry>>>,
                     cert_chain: Vec<Vec<u8>>, src: ipaddress::IPAddress, dst: ipaddress::IPAddress, port: u16) {

    debug!("Entered handle_validation {:?} {:?} {:?}", src, dst, port);

    thread::spawn(move || {
        let key = derive_cache_key(&dst, &src, &port);
        let sni = cl_cache.read().get(&key).unwrap().sni.clone();
        let mut ii = DNS_TIMEOUT;
        loop {
            if cl_cache.read().get(&key).unwrap().response == true {
                match cl_cache.read().get(&key).unwrap().tlsa {
                    Some(ref tlsa) => {
                        if validate_tlsa(tlsa, &cert_chain) {
                            debug!("Valid TLSA for {:?}", sni);
                        }else{
                            debug!("Invalid TLSA for {:?}", sni);
                            let chain = unique_chain_name(&sni);
                            match iptables::new(false) { // Create iptables chain and insert ACLs
                                Err(err) => panic!("Fatal iptables error {:?}", err),
                                Ok(ipt) => {
                                    ipt_add_chain(&ipt, &chain).expect("Fatal iptables error at add_chain");
                                    if src.is_ipv4() {
                                        ipt_add_short(&ipt, &chain, &src, &dst, port).expect("Fatal iptables error at add_short");
                                    }
                                    ipt_add_long(&ipt, &chain, &sni).expect("Fatal iptables error at add_long");
                                }
                            }
                            if ipv6_enabled() {
                                match iptables::new(true) { // Create ip6tables chain and insert ACLs
                                    Err(err) => panic!("Fatal ip6tables error {:?}", err),
                                    Ok(ipt6) => {
                                        ipt_add_chain(&ipt6, &chain).expect("Fatal ip6tables error at add_chain");
                                        if src.is_ipv6() {
                                            ipt_add_short(&ipt6, &chain, &src, &dst, port).expect("Fatal ip6tables error at add_short");
                                        }
                                        ipt_add_long(&ipt6, &chain, &sni).expect("Fatal ip6tables error at add_long");
                                    }
                                }
                            }

                            debug!("Inserting new acl_cache entry {:?}", chain);
                            acl_cache.write().insert(chain, AclCacheEntry {
                                ts: SystemTime::now(),
                                insert_ts: SystemTime::now(),
                                sni: sni.clone(),
                                short_active: true,
                                short_ipv4: src.is_ipv4(),
                            });
                        }
                        break;
                    }
                    _ => {
                        debug!("Validation ignored for {:?}", sni);
                        break;
                    }
                }
            }else{
                if ii <= 0 {
                    break;
                }
                thread::sleep(time::Duration::from_millis(DNS_TIMEOUT_DECREMENT));
                debug!("{:?} Slept {:?} ms awaiting DNS response for {:?}", ii, DNS_TIMEOUT_DECREMENT, sni);
                ii = ii - DNS_TIMEOUT_DECREMENT;
            }
        };

        // Mark client_cache entry as stale
        if let Some(entry) = cl_cache.write().get_mut(&key) {
            entry.stale = true;
            entry.ts = SystemTime::now();
        }else{
            panic!("Failed to update cl_cache");
        }
    });
}

// Validates X.509 cert against TLSA 
// Takes RData of DNS TLSA RRSET and DER encoded X.509 cert chain
// Returns True on valid and False on invalid
fn validate_tlsa(tlsa_rrset: &Vec<TLSA>, cert_chain: &Vec<Vec<u8>>) -> bool {
    //debug!("Entered validate_tlsa() tlsa_rrset: {:?}", tlsa_rrset);
    let mut certs: Vec<Vec<u8>>;
    for tlsa in tlsa_rrset {
        //debug!("tlsa: {:?}", tlsa);
        match tlsa.selector {
            0 => certs = cert_chain.clone(),
            1 => {
                certs = cert_chain.clone(); // TODO: remove these lines when I'm better at rust
                certs.clear();
                for cc in cert_chain.iter() {
                    match x509_parser::parse_subject_public_key_info(cc) {
                        Err(err) => {
                            warn!("Error parsing SPKI from X.509 record {:?} \n {:?}", err, cc);
                            return true; // Do no harm
                        }
                        Ok(spki) => {
                            certs.push(spki.1.subject_public_key.data.to_vec());
                        }
                    }
                }
            }
            _ => {
                debug!("Invalid TLSA selector, assuming Full");
                certs = cert_chain.clone();
            }
        }

        match tlsa.usage {
            0 => {
                match tlsa.matching_type {
                    0 => {
                        for cert in certs {
                            if tlsa.data == cert.as_slice() {
                                return true;
                            }
                        }
                    }
                    1 => {
                        for cert in certs {
                            if tlsa.data == Sha256::digest(&cert).as_slice() {
                                return true;
                            }
                        }
                    }
                    2 => {
                        for cert in certs {
                            if tlsa.data == Sha512::digest(&cert).as_slice() {
                                return true;
                            }
                        }
                    }
                    _ => debug!("Unsupported TLSA::matching_type {:?}", tlsa.matching_type),
                }
            }
            1 | 3 => {
                match tlsa.matching_type {
                    0 => {
                        if tlsa.data == certs[0].as_slice() {
                            return true;
                        }
                    }
                    1 => {
                        if tlsa.data == Sha256::digest(&certs[0]).as_slice(){
                            return true;
                        }
                    }
                    2 => {
                        if tlsa.data == Sha512::digest(&certs[0]).as_slice() {
                            return true;
                        }
                    }
                    _ => debug!("Unsupported TLSA::matching_type {:?}", tlsa.matching_type),
                }
            }
            2 => {
                match tlsa.matching_type {
                    0 => {
                        if tlsa.data == certs[certs.len()-1].as_slice() {
                            return true;
                        }
                    }
                    1 => {
                        if tlsa.data == Sha256::digest(&certs[certs.len()-1]).as_slice() {
                            return true;
                        }
                    }
                    2 => {
                        if tlsa.data == Sha512::digest(&certs[certs.len()-1]).as_slice() {
                            return true;
                        }
                    }
                    _ => debug!("Unsupported TLSA::matching_type {:?}", tlsa.matching_type),
                }
            }
            _ => debug!("Unsupported TLSA::usage {:?}", tlsa.usage),
        }
    }
    return false;
}

// Perform DNS A/AAAA lookup for RPZ and update client_cache
// TODO: Rewrite using async/await once it's final
fn handle_rpz(acl_cache: Arc<RwLock<HashMap::<String, AclCacheEntry>>>,
              client_cache: Arc<RwLock<HashMap<String, ClientCacheEntry>>>, key: String) {

    thread::spawn(move || {
        let sni = client_cache.read().get(&key).unwrap().sni.clone();
        let mut resolver = Resolver::new().unwrap();
        match resolver.query(&sni.clone().into_bytes(), Class::IN, RecordType::A) {
            Ok(_) => { },
            Err(_) => {
                match resolver.query(&sni.clone().into_bytes(), Class::IN, RecordType::AAAA) {
                    Ok(_) => { },
                    Err(_) => {
                        if let Some(cl_entry) = client_cache.write().get_mut(&key) {
                            for (_key, acl_entry) in acl_cache.read().iter() {
                                if acl_entry.sni == cl_entry.sni {
                                    return; // ACL already exists
                                }
                            }
                            cl_entry.rpz_blocked = true;
                            cl_entry.stale = true;
                            cl_entry.ts = SystemTime::now();

                            let chain = unique_chain_name(&sni);
                            match iptables::new(false) { // Create iptables chain and insert ACL
                                Err(err) => panic!("Fatal iptables error {:?}", err),
                                Ok(ipt) => {
                                    ipt_add_long(&ipt, &chain, &sni).expect("Fatal iptables error at add_long for rpz");
                                }
                            }
                            if ipv6_enabled() {
                                match iptables::new(true) { // Create ip6tables chain and insert ACL
                                    Err(err) => panic!("Fatal ip6tables error {:?}", err),
                                    Ok(ipt6) => {
                                        ipt_add_long(&ipt6, &chain, &sni).expect("Fatal ip6tables error at add_long for rpz");
                                    }
                                }
                            }
                            debug!("Inserting new acl_cache entry {:?}", chain);
                            acl_cache.write().insert(chain, AclCacheEntry {
                                ts: SystemTime::now(),
                                insert_ts: SystemTime::now(),
                                sni: sni.clone(),
                                short_active: false,
                                short_ipv4: false,
                            });
                        } else {
                            panic!("Failed to update client_cache");
                        }
                    }
                }
            }
        }
    });
}

///////////////////
// ACL FUNCTIONS //
///////////////////
// Adds a new iptables chain and links it to main Danish chain
fn ipt_add_chain(ipt: &iptables::IPTables, chain: &String) -> Result<(), iptables::error::IPTError> {
    debug!("Creating then inserting into {:?}", chain);
    let cli_opts: Opt = Opt::from_args();
    ipt.new_chain("filter", &chain)?;
    ipt.insert_unique("filter", &chain, "-j RETURN", 1)?;
    ipt.insert_unique("filter", &cli_opts.sub_chain, &format!("{} {}", "-j", &chain), 1)?;
    return Ok(());
}

// Adds short term ingress and egress ACLs to a chain
fn ipt_add_short(ipt: &iptables::IPTables, chain: &String, src: &ipaddress::IPAddress,
                 dst: &ipaddress::IPAddress, port: u16) -> Result<(), iptables::error::IPTError> {

    let short_ingress = format!("{}{}{}{}{}{}{}{}{}", "--destination ", &dst.to_string(), " ",
                                "--source ", &src.to_string(), " ",
                                "-p tcp --sport 443 --dport ", format!("{}", port), " -j DROP");
    ipt.insert_unique("filter", &chain, &short_ingress, 1)?;
    debug!("Inserted short_ingress: {:?}", short_ingress);

    let short_egress = format!("{}{}{}{}{}{}{}{}{}", "--destination ", &src.to_string(), " ",
                               "--source ", &dst.to_string(), " ",
                               "-p tcp --dport 443 --sport ", format!("{}", port), " -j DROP");
    ipt.insert_unique("filter", &chain, &short_egress, 1)?;
    debug!("Inserted short_egress: {:?}", short_egress);
    return Ok(());
}

// Add long term egress ACL to a chain
fn ipt_add_long(ipt: &iptables::IPTables, chain: &String, sni: &String) -> Result<(), iptables::error::IPTError> {
    let long_egress =  format!("{}{}{}", "-p tcp --dport 443 -m string --algo bm --string ", &sni, " -j DROP");
    debug!("long_egress: {:?}", long_egress);
    ipt.insert_unique("filter", &chain, &long_egress, 1)?;
    return Ok(());
}

// Delinks then deletes an existing iptables chain
fn ipt_del_chain(ipt: &iptables::IPTables, chain: &String) -> Result<(), iptables::error::IPTError> {
    debug!("Deleting chain {:?}", chain);
    let cli_opts: Opt = Opt::from_args();
    ipt.delete("filter", &cli_opts.sub_chain, &format!("{} {}", "-j", &chain))?;
    ipt.flush_chain("filter", &chain)?;
    ipt.delete_chain("filter", &chain)?;
    return Ok(());
}

// Deletes short term ingress and egress ACLs in a chain
fn ipt_del_short(ipt: &iptables::IPTables, chain: &String) -> Result<(), iptables::error::IPTError> {
    debug!("Deleting short acls in chain {:?}", chain);
    for acl in ipt.list("filter", &chain)?.iter() {
        if acl.contains("--sport") {
            ipt.delete("filter", &chain, &acl.replace(&format!("{}{}", "-A ", &chain), ""))?;
        }
    }
    return Ok(());
}

// Deletes long term ACL in a chain
fn ipt_del_long(ipt: &iptables::IPTables, chain: &String) -> Result<(), iptables::error::IPTError> {
    debug!("Deleting long acl in chain {:?}", chain);
    for acl in ipt.list("filter", &chain)?.iter() {
        if acl.contains("--string") {
            ipt.delete("filter", &chain, &acl.replace(&format!("{}{}", "-A ", &chain), ""))?;
        }
    }
    return Ok(());
}

// Returns an unused iptables and ip6tables chain name
fn unique_chain_name(name: &str) -> String {
    let cli_opts: Opt = Opt::from_args();
    let id_len: usize = (IPT_MAX_CHARS - cli_opts.sub_chain.len() - IPT_DELIM.len()) / 2;
    let hash = Sha256::digest(&name.as_bytes()).to_vec()[0..id_len].to_vec();
    let attempt = format!("{}{}{}", cli_opts.sub_chain, IPT_DELIM,
                          hash.iter().map(|x| format!("{:x}", x)).collect::<String>());

    match iptables::new(false) {
        Err(err) => panic!("Fatal iptables error {:?}", err),
        Ok(ipt) => {
            for existing in ipt.list_chains("filter").expect("FATAL iptables error").iter() {
                if &attempt == existing {
                    debug!("iptables chain already exists {:?}", attempt);
                    let mut rng = thread_rng();
                    return unique_chain_name(&iter::repeat(())
                                             .map(|()| rng.sample(Alphanumeric)).take(attempt.len())
                                             .fold(String::new(), |a, b| format!("{}{}", a, b)));
                }
            }
        }
    }
    if ipv6_enabled() {
        match iptables::new(true) {
            Err(err) => panic!("Fatal ip6tables error {:?}", err),
            Ok(ipt6) => {
                for existing in ipt6.list_chains("filter").expect("FATAL ip6tables error").iter() {
                    if &attempt == existing {
                        debug!("ip6tables chain already exists {:?}", attempt);
                        let mut rng = thread_rng();
                        return unique_chain_name(&iter::repeat(())
                                                 .map(|()| rng.sample(Alphanumeric)).take(attempt.len())
                                                 .fold(String::new(), |a, b| format!("{}{}", a, b)));
                    }
                }
            }
        }
    }
    return attempt;
}

///////////////////////
// GENERAL FUNCTIONS //
///////////////////////
// Die gracefully
fn euthanize() {
    info!("Ctrl-C exiting");

    let cli_opts: Opt = Opt::from_args();

    // teardown iptables
    match iptables::new(false) {
        Err(_) => panic!("FATAL iptables error"),
        Ok(ipt) => {
            ipt.delete("filter", &cli_opts.chain.to_uppercase(), &format!("{} {}", "-j", cli_opts.sub_chain)).expect("FATAL iptables error");
            let sub_chains = ipt.list_chains("filter").expect("FATAL iptables error");
            ipt.flush_chain("filter", &cli_opts.sub_chain).expect("FATAL iptables error");

            for chain in sub_chains.iter() {
                if chain.starts_with(&format!("{}{}", cli_opts.sub_chain, IPT_DELIM)) {
                    ipt.flush_chain("filter", chain).expect("FATAL iptables error");
                    ipt.delete_chain("filter", chain).expect("FATAL iptables error");
                }
            }

            ipt.delete_chain("filter", &cli_opts.sub_chain).expect("FATAL iptables error");
        }
    }

    // teardown ip6tables
    if ipv6_enabled() {
        match iptables::new(true) {
            Err(_) => panic!("FATAL ip6tables error"),
            Ok(ipt) => {
                ipt.delete("filter", &cli_opts.chain.to_uppercase(), &format!("{} {}", "-j", cli_opts.sub_chain)).expect("FATAL ip6tables error");
                let sub_chains = ipt.list_chains("filter").expect("FATAL ip6tables error");
                ipt.flush_chain("filter", &cli_opts.sub_chain).expect("FATAL ip6tables error");

                for chain in sub_chains.iter() {
                    if chain.starts_with(&format!("{}{}", cli_opts.sub_chain, IPT_DELIM)) {
                        ipt.flush_chain("filter", chain).expect("FATAL ip6tables error");
                        ipt.delete_chain("filter", chain).expect("FATAL ip6tables error");
                    }
                }

                ipt.delete_chain("filter", &cli_opts.sub_chain).expect("FATAL ip6tables error");
            }
        }
    }

    std::process::exit(0);
}

// Derives a cache key from unique pairing of values
// Source and destination are from perspective of TLS CLIENTHELLO
fn derive_cache_key(src: &ipaddress::IPAddress, dst: &ipaddress::IPAddress, port: &u16) -> String {
    let delim = "_".to_string();
    let mut key = src.to_s();
    key.push_str(&delim);
    key.push_str(&dst.to_s());
    key.push_str(&delim);
    key.push_str(&port.to_string());
    key
}

// Returns display formatted string for ipv4 address
fn ipv4_display(ip: &[u8;4]) -> String {
    return ip.iter().map(|x| format!(".{}", x)).collect::<String>().split_off(1);
}

// Returns display formatted string for ipv6 address
fn ipv6_display(ip: &[u8;16]) -> String {
    let mut rv = "".to_string();
    for ii in 0..16 {
        if ii % 2 == 0 && ii != 0 {
            rv.push_str(":");
        }
        rv.push_str(&format!("{:01$x}", &ip[ii], 2));
    }
    rv
}

// Is this machine IPv6 capable?
// TODO: For now we only check if ip6tables exists, could be smarter maybe
fn ipv6_enabled() -> bool {
    let mut simp = Simpath::new("PATH");
    for dir in IPV6TABLES_DIRS.iter() {
        simp.add_directory(dir)
    }
    match simp.find("ip6tables") {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

/////////////////////////////
// BEGIN PROGRAM EXECUTION //
/////////////////////////////
fn main() {
    env_logger::builder().default_format_timestamp(false).init();
    debug!("Start");

    let cli_opts: Opt = Opt::from_args();

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    let mut threads = vec![]; // Our threads

    // Setup our caches
    // TODO: We may get better cache entry atomicity if we use crate chashmap
    let client_cache_v4 = Arc::new(RwLock::new(HashMap::<String, ClientCacheEntry>::new())); // client_4_thr
    let client_cache_v4_srv = Arc::clone(&client_cache_v4); // server_4_thr
    let client_cache_v6 = Arc::new(RwLock::new(HashMap::<String, ClientCacheEntry>::new())); // client_6_thr
    let client_cache_v6_srv = Arc::clone(&client_cache_v6); // server_6_thr

    let server_cache_v4 = Arc::new(RwLock::new(HashMap::<String, ServerCacheEntry>::new())); // server_4_thr
    let server_cache_v6 = Arc::new(RwLock::new(HashMap::<String, ServerCacheEntry>::new())); // server_6_thr

    let acl_cache_v4 = Arc::new(RwLock::new(HashMap::<String, AclCacheEntry>::new())); // client_4_thr
    let acl_cache_v6 = Arc::clone(&acl_cache_v4); // client_6_thr
    let acl_cache_v4_srv = Arc::clone(&acl_cache_v4); // server_4_thr
    let acl_cache_v6_srv = Arc::clone(&acl_cache_v4); // server_6_thr
    let acl_cache_clean = Arc::clone(&acl_cache_v4); // acl_clean_thr

    // Check our input
    if cli_opts.chain.to_uppercase() != "OUTPUT".to_string() && cli_opts.chain.to_uppercase() != "FORWARD".to_string() {
        panic!("Invalid iptables/ip6tables chain {:?}", cli_opts.chain.to_uppercase());
    }
    if cli_opts.sub_chain.len() > IPT_SUBCHAIN_MAX_CHARS { 
        panic!("sub-chain argument too long {:?}", cli_opts.sub_chain);
    }
    if cli_opts.sub_chain.len() < IPT_SUBCHAIN_MIN_CHARS {
        panic!("sub-chain argument too short {:?}", cli_opts.sub_chain);
    }
    if !cli_opts.sub_chain.is_ascii() {
        panic!("non-ASCII character in sub-chain");
    }
    for cc in cli_opts.sub_chain.chars() {
        if !cc.is_ascii_alphanumeric() {
            panic!("Invalid ASCII character in sub-chain");
        }
    }
    match Device::list().unwrap().iter().find(|iface| iface.name == cli_opts.iface) {
        Some(_) => { },
        _ => panic!("Invalid interface {:?}", cli_opts.iface),
    }

    // Setup iptables
    match iptables::new(false) {
        Err(_) => panic!("FATAL iptables error"),
        Ok(ipt) => {
            ipt.new_chain("filter", &cli_opts.sub_chain).expect("FATAL iptables error");
            ipt.insert_unique("filter", &cli_opts.sub_chain, "-j RETURN", 1).expect("FATAL iptables error");
            ipt.insert_unique("filter", &cli_opts.chain.to_uppercase(), &format!("{} {}", "-j", &cli_opts.sub_chain), 1).expect("FATAL iptables error");
            if ipv6_enabled() {
                match iptables::new(true) {
                    Err(_) => panic!("FATAL ip6tables error"),
                    Ok(ipt6) => {
                        ipt6.new_chain("filter", &cli_opts.sub_chain).expect("FATAL ip6tables error");
                        ipt6.insert_unique("filter", &cli_opts.sub_chain, "-j RETURN", 1).expect("FATAL ip6tables error");
                        ipt6.insert_unique("filter", &cli_opts.chain.to_uppercase(), &format!("{} {}", "-j", &cli_opts.sub_chain), 1).expect("FATAL ip6tables error");
                    }
                }
            }
        }
    }
    drop(cli_opts);

    // ACL clean up thread
    let acl_clean_thr = thread::Builder::new().name("acl_clean".to_string()).spawn(move || {
        loop {
            thread::sleep(time::Duration::new(ACL_CACHE_DELAY, 0));
            debug!("Investigating acl_cache staleness {:?}", acl_cache_clean.read().len());
            let mut short_stale = Vec::new();
            let mut long_stale = Vec::new();
            for (key,entry) in acl_cache_clean.read().iter() {
                if entry.short_active {
                    if SystemTime::now() > entry.insert_ts + Duration::new(ACL_SHORT_TIMEOUT, 0) {
                        short_stale.push(key.clone());
                    }
                }
                if SystemTime::now() > entry.insert_ts + Duration::new(ACL_LONG_TIMEOUT, 0) {
                    long_stale.push(key.clone());
                }
            }

            // Delete ip6tables entries first if enabled
            // Don't remove acl_cache entries or stale Vectors until iptables entries are deleted
            if short_stale.len() > 0 || long_stale.len() > 0 {
                if ipv6_enabled() {
                    match iptables::new(true) {
                        Err(_) => panic!("FATAL ip6tables error"),
                        Ok(ipt6) => {
                            for key in short_stale.iter() {
                                if let Some(entry) = acl_cache_clean.read().get(key) {
                                    if !entry.short_ipv4 {
                                        ipt_del_short(&ipt6, &key).expect("FATAL ip6tables error");
                                    }
                                }else{
                                    panic!("Failed to read acl_cache");
                                }
                            }
                            for key in long_stale.iter() {
                                ipt_del_long(&ipt6, &key).expect("FATAL ip6tables error");
                                ipt_del_chain(&ipt6, &key).expect("FATAL ip6tables error");
                                debug!("Deleted stale acl_cache entry {:?}", key);
                            }
                        }
                    }
                }
                match iptables::new(false) {
                    Err(_) => panic!("FATAL iptables error"),
                    Ok(ipt) => {
                        for key in short_stale.iter() {
                            if let Some(entry) = acl_cache_clean.write().get_mut(key) {
                                if entry.short_ipv4 {
                                    ipt_del_short(&ipt, &key).expect("FATAL iptables error");
                                }
                                entry.short_active = false;
                                entry.ts = SystemTime::now();
                            }else{
                                panic!("Failed to update acl_cache");
                            }
                        }
                        for key in long_stale.iter() {
                            ipt_del_long(&ipt, &key).expect("FATAL iptables error");
                            ipt_del_chain(&ipt, &key).expect("FATAL iptables error");
                            acl_cache_clean.write().remove(key);
                            debug!("Deleted stale acl_cache entry {:?}", key);
                        }
                    }
                }
            }
        }
    }).unwrap();
    threads.push(acl_clean_thr);

    let client_4_thr = thread::Builder::new().name("client_4".to_string()).spawn(move || {
        let bpf_client_4 = "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) and (dst port 443)";
        let mut capture = Capture::from_device(Opt::from_args().iface.as_str()).unwrap().open().unwrap();
        match capture.filter(bpf_client_4){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        while let Ok(packet) = capture.next() {
            debug!("Investigating client_cache_v4 staleness {:?}", client_cache_v4.read().len());
            let mut stale = Vec::new();
            for (key,entry) in client_cache_v4.read().iter() {
                if entry.stale {
                    if entry.ts < SystemTime::now() - Duration::new(CACHE_MIN_STALENESS, 0) {
                        stale.push(key.clone());
                        debug!("Found stale client_cache_v4 entry {:?}", key);
                    }
                }
            }
            for key in stale.iter() {
                client_cache_v4.write().remove(key);
                debug!("Deleted stale client_cache_v4 entry {:?}", key);
            }
            drop(stale);

            let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet in client_4_thr");
            //debug!("Everything: {:?}", pkt);

            match pkt.ip.unwrap() {
                Version6(_) => {
                    warn!("IPv6 packet captured when IPv4 expected");
                    continue;
                }
                Version4(ipv4) => {
                    match pkt.transport.unwrap() {
                        Udp(_) => error!("UDP transport captured when TCP expected"),
                        Tcp(tcp) => {
                            match parse_sni(pkt.payload) { // Let's assume SNI comes in one packet
                                Err(err) => {
                                    match err {
                                        SniParseError::ClientHelloNotFound | SniParseError::IncorrectMsgType =>
                                            debug!("SNI not found in pkt, likely not TLS ClientHello"),
                                        _ => error!("Error parsing SNI"),
                                    }
                                }
                                Ok(sni) => {
                                    let key = derive_cache_key(&ipv4::new(ipv4_display(&ipv4.source)).unwrap(),
                                                               &ipv4::new(ipv4_display(&ipv4.destination)).unwrap(),
                                                               &tcp.source_port);

                                    debug!("Inserting client_cache_v4 entry: {:?} sni: {:?}", key, sni);
                                    client_cache_v4.write().insert(key.clone(),
                                        ClientCacheEntry {
                                            ts: SystemTime::now(),
                                            sni: sni.clone(),
                                            tlsa: None,
                                            response: false,
                                            rpz_blocked: false,
                                            stale: false,
                                        });
                                    dns_lookup_tlsa(Arc::clone(&client_cache_v4), key.clone());
                                    if Opt::from_args().rpz {
                                        handle_rpz(Arc::clone(&acl_cache_v4), Arc::clone(&client_cache_v4), key.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }).unwrap();
    threads.push(client_4_thr);

    let server_4_thr = thread::Builder::new().name("server_4".to_string()).spawn(move || {
        let bpf_server_4 = "tcp and src port 443 and (tcp[tcpflags] & tcp-ack = 16) and (tcp[tcpflags] & tcp-syn != 2) and 
        (tcp[tcpflags] & tcp-fin != 1) and (tcp[tcpflags] & tcp-rst != 1)";

        let mut capture = Capture::from_device(Opt::from_args().iface.as_str()).unwrap().open().unwrap();
        match capture.filter(bpf_server_4){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        while let Ok(packet) = capture.next() {
            debug!("Investigating server_cache_v4 staleness {:?}", server_cache_v4.read().len());
            let mut stale = Vec::new();
            for (key,entry) in server_cache_v4.read().iter() {
                if entry.stale {
                    if entry.ts < SystemTime::now() - Duration::new(CACHE_MIN_STALENESS, 0) {
                        stale.push(key.clone());
                        debug!("Found stale server_cache_v4 entry {:?}", key);
                    }
                }
            }
            for key in stale.iter() {
                server_cache_v4.write().remove(key);
                debug!("Deleted stale server_cache_v4 entry {:?}", key);
            }
            drop(stale);

            /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
            So a 60 byte packet was 64 bytes on the wire.
            Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
            Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
            The chances of us actually needing that small of a packet are close to zero. */
            if packet.len() <= 60 {
                continue;
            }

            let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet in server_4_thr");
            //debug!("Everything: {:?}", pkt);

            match pkt.ip.unwrap() {
                Version6(_) => {
                    warn!("IPv6 packet captured, but IPv4 expected");
                    continue;
                }
                Version4(ipv4) => {
                    match pkt.transport.unwrap() {
                        Udp(_) => warn!("UDP transport captured when TCP expected"),
                        Tcp(tcp) => {
                            //debug!("resp_tcp_seq: {:?}", tcp.sequence_number);
                            //debug!("payload_len: {:?}", pkt.payload.len());
                            parse_server_hello(&acl_cache_v4_srv, &client_cache_v4_srv, &server_cache_v4,
                                               ipv4::new(ipv4_display(&ipv4.source)).unwrap(),
                                               ipv4::new(ipv4_display(&ipv4.destination)).unwrap(),
                                               tcp, pkt.payload);
                        }
                    }
                }
            }
        }
    }).unwrap();
    threads.push(server_4_thr);

    if ipv6_enabled() {
        let client_6_thr = thread::Builder::new().name("client_6".to_string()).spawn(move || {
            let bpf_client_6 = "ip6 and tcp and dst port 443";
            let mut capture = Capture::from_device(Opt::from_args().iface.as_str()).unwrap().open().unwrap();
            match capture.filter(bpf_client_6){
                Ok(_) => (),
                Err(err) => error!("BPF error {}", err.to_string()),
            }

            while let Ok(packet) = capture.next() {
                debug!("Investigating client_cache_v6 staleness {:?}", client_cache_v6.read().len());
                let mut stale = Vec::new();
                for (key,entry) in client_cache_v6.read().iter() {
                    if entry.stale {
                        if entry.ts < SystemTime::now() - Duration::new(CACHE_MIN_STALENESS, 0) {
                            stale.push(key.clone());
                            debug!("Found stale client_cache_v6 entry {:?}", key);
                        }
                    }
                }
                for key in stale.iter() {
                    client_cache_v6.write().remove(key);
                    debug!("Deleted stale client_cache_v6 entry {:?}", key);
                }
                drop(stale);

                let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet in client_6_thr");
                //debug!("Everything: {:?}", pkt);

                match pkt.ip.unwrap() {
                    Version4(_) => {
                        warn!("IPv4 packet captured when IPv6 expected");
                        continue;
                    }
                    Version6(ipv6) => {
                        if pkt.payload.len() > 64 { // Somewhat arbitrary minimum
                            if pkt.payload[0] == 22 && pkt.payload[5] == 1 { // tls.handshake and tls.handshake.type.client_hello
                                match pkt.transport.unwrap() {
                                    Udp(_) => error!("UDP transport captured when TCP expected"),
                                    Tcp(tcp) => {
                                        match parse_sni(pkt.payload) { // Let's assume SNI comes in one packet
                                            Err(err) => {
                                                match err {
                                                    SniParseError::ClientHelloNotFound | SniParseError::IncorrectMsgType =>
                                                        debug!("SNI not found in pkt, likely not TLS ClientHello"),
                                                    _ => error!("Error parsing SNI"),
                                                }
                                            }
                                            Ok(sni) => {
                                                let key = derive_cache_key(&ipv6::new(ipv6_display(&ipv6.source)).unwrap(),
                                                                           &ipv6::new(ipv6_display(&ipv6.destination)).unwrap(),
                                                                           &tcp.source_port);

                                                debug!("Inserting client_cache_v6 entry: {:?} sni: {:?}", key, sni);
                                                client_cache_v6.write().insert(key.clone(), ClientCacheEntry {
                                                    ts: SystemTime::now(),
                                                    sni: sni.clone(),
                                                    tlsa: None,
                                                    response: false,
                                                    rpz_blocked: false,
                                                    stale: false,
                                                });
                                                dns_lookup_tlsa(Arc::clone(&client_cache_v6), key.clone());
                                                if Opt::from_args().rpz {
                                                    handle_rpz(Arc::clone(&acl_cache_v6), Arc::clone(&client_cache_v6), key.clone());
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
        }).unwrap();
        threads.push(client_6_thr);

        let server_6_thr = thread::Builder::new().name("server_6".to_string()).spawn(move || {
            let bpf_server_6 = "ip6 and tcp and src port 443";

            let mut capture = Capture::from_device(Opt::from_args().iface.as_str()).unwrap().open().unwrap();
            match capture.filter(bpf_server_6){
                Ok(_) => (),
                Err(err) => error!("BPF error {}", err.to_string()),
            }

            while let Ok(packet) = capture.next() {
                debug!("Investigating server_cache_v6 staleness {:?}", server_cache_v6.read().len());
                let mut stale = Vec::new();
                for (key,entry) in server_cache_v6.read().iter() {
                    if entry.stale {
                        if entry.ts < SystemTime::now() - Duration::new(CACHE_MIN_STALENESS, 0) {
                            stale.push(key.clone());
                            debug!("Found stale server_cache_v6 entry {:?}", key);
                        }
                    }
                }
                for key in stale.iter() {
                    server_cache_v6.write().remove(key);
                    debug!("Deleted stale server_cache_v6 entry {:?}", key);
                }
                drop(stale);

                /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
                So a 60 byte packet was 64 bytes on the wire.
                Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
                Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
                The chances of us actually needing that small of a packet are close to zero. */
                if packet.len() <= 60 {
                    continue;
                }

                let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet in server_6_thr");
                //debug!("Everything: {:?}", pkt);

                match pkt.ip.unwrap() {
                    Version4(_) => {
                        warn!("IPv4 packet captured, but IPv6 expected");
                        continue;
                    }
                    Version6(ipv6) => {
                        match pkt.transport.unwrap() {
                            Udp(_) => warn!("UDP transport captured when TCP expected"),
                            Tcp(tcp) => {
                                //debug!("resp_tcp_seq: {:?}", tcp.sequence_number);
                                //debug!("payload_len: {:?}", pkt.payload.len());
                                if pkt.payload.len() > 0 {
                                    if tcp.ack && !tcp.rst && !tcp.syn && !tcp.fin {
                                        parse_server_hello(&acl_cache_v6_srv, &client_cache_v6_srv, &server_cache_v6,
                                                           ipv6::new(ipv6_display(&ipv6.source)).unwrap(),
                                                           ipv6::new(ipv6_display(&ipv6.destination)).unwrap(),
                                                           tcp, pkt.payload);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }).unwrap();
        threads.push(server_6_thr);
    }

    for thr in threads {
        thr.join().unwrap();
    }

    debug!("Finish");
}
