/*
Copyright (c) 2019, Andrew McConachie <andrew@depht.com>
All rights reserved.
*/

include!("lib.rs");

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

    let acl_cache_v4 = Arc::new(RwLock::new(HashMap::<String, AclCacheEntry>::new())); // server_4_thr
    let acl_cache_v6 = Arc::clone(&acl_cache_v4); // server_6_thr
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
        let mut capture = Device::lookup().unwrap().open().unwrap();
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
                                            stale: false,
                                        });
                                    dns_lookup_tlsa(Arc::clone(&client_cache_v4), key.clone());
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

        let mut capture = Device::lookup().unwrap().open().unwrap();
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
                            parse_server_hello(&acl_cache_v4, &client_cache_v4_srv, &server_cache_v4,
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
            let mut capture = Device::lookup().unwrap().open().unwrap();
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
                                                    stale: false,
                                                });
                                                dns_lookup_tlsa(Arc::clone(&client_cache_v6), key.clone());
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

            let mut capture = Device::lookup().unwrap().open().unwrap();
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
                                        parse_server_hello(&acl_cache_v6, &client_cache_v6_srv, &server_cache_v6,
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
