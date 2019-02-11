use std::collections::HashMap;

pub struct ClientCache {
    cache: HashMap,
}

// Danish client cache entry for IPv4, IPv6 not yet implemented
#[derive(Clone)]
pub struct CacheEntry {
    sni: String
    tcp_port: u8,
    ip_src: [u8;4],
    ip_dst: [u8;4],
}

impl ClientCache {
    ///Constructs a ClientCache
    pub fn new() {

    }
}
