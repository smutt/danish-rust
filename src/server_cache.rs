use std::collections::HashMap;

pub struct ServerCache {
    cache: HashMap
}

// Danish server cache entry for IPv4, IPv6 not yet implemented
#[derive(Clone)]
pub struct CacheEntry {
    ts: u8, // insert timestamp
    sni: str,
    tcp_port: u16,
    ip_src: [u8;4],
    ip_dst: [u8;4],
    seq: u8,
}

impl ServerCache {
    ///Constructs a ServerCache
    pub fn new() {

    }
}
