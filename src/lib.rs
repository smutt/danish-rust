/*
Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
All rights reserved.
*/

#[macro_use]
extern crate log;

use std::{iter, time, thread};
use std::time::SystemTime;
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
use iptables;
use x509_parser;
use simpath::Simpath;
use ipaddress;
use structopt::StructOpt;

// CONSTANTS
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
    /// enable RPZ operation
    #[structopt(short = "r", long = "rpz")]
    rpz: bool,
    /// iptables/ip6tables sub-chain for ACLs
    #[structopt(short = "s", long = "sub-chain", default_value = "danish")]
    sub_chain: String,
}

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

// Perform DNS A/AAAA lookup for RPZ and update client_cache
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

// Perform DNS TLSA lookup and update client_cache
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

// Kicks off TLSA validation thread once X.509 cert has been received
// Determines validation disposition and installs ACLs if necessary
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