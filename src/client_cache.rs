use std::collections::HashMap;

pub struct ClientCache {
    cache: HashMap
}

// Danish client cache entry for IPv4, IPv6 not yet implemented
#[derive(Clone)]
pub struct CacheEntry {
    ts: u8, // insert timestamp
    sni: str,
    tcp_port: u16,
    ip_src: [u8;4],
    ip_dst: [u8;4],
}

impl ClientCache {
    ///Constructs a ClientCache
    pub fn new() {

    }
}
