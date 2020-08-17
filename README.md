## Overview

[![Build Status](https://travis-ci.org/smutt/danish-rust.svg?branch=master)](https://travis-ci.org/smutt/danish-rust)

Danish is an experiment in middle-box DANE (RFC 6698) for HTTPS.

Danish is a daemon that listens for HTTPS TLS handshake traffic and captures the TLS/SNI and certificates. It then performs DNS lookups for DNS TLSA records to determine if the responding server is sending the correct X.509 certificate in its TLS ServerHello message.

If the certificates and DNS TLSA records do NOT match, iptables/ip6tables ACLs are installed to block user traffic to the offending website. ACLs are installed to both blackhole the immediate TCP traffic and prevent any further attempts at users connecting to the offending website. Users are then prevented from connecting to the offending website for the TTL of the relevant DNS TLSA RR.

This is a full rewrite of
[Python Danish](https://github.com/smutt/danish) in Rust. For the
Python version of Danish go to [Python Danish](https://github.com/smutt/danish)

## Supported Protocols and Versions
Danish currently supports TLS 1.0 - 1.2, IPv4/IPv6.

## Installation
Once compiled Danish is just an executable. Put the executable and the
danish man page somewhere on your system and you're good to go.

## Requirements
* Linux
* iptables
* ip6tables for IPv6 support
* kernel module [kmod-ipt-filter](https://openwrt.org/packages/pkgdata/iptables-mod-filter)
* iptables module [iptables-mod-filter](https://openwrt.org/packages/pkgdata/iptables-mod-filter)

### Building Danish
1. Install the [rust compiler](https://www.rust-lang.org/tools/install)
2. Fork this repository
3. Compile Danish **cargo build**

**Danish requires the following development libraries for
compilation.**
* lib-pcap
* lib-pthread

## Options
**-c, --chain**
 iptables/ip6tables top level chain. Only chains allowed are OUTPUT
 and FORWARD. Use OUTPUT to run danish in host mode and FORWARD to run
 danish in middlebox mode. Default value is OUTPUT.

**-i, --interface**
pcap interface to listen on, typically the network interface with the
default route. Default value is eth0.

**-h, --help**
display help and exit

**-r, --rpz**
Enable Response Policy Zones(RPZ) operation. If enabled danish will
block any SNI that fails resolution for A and AAAA. Default value is disabled.

**-s, --sub-chain**
iptables/ip6tables sub-chain for installing ACLs. Special chain used
only for danish ACLs. Default value is danish.

**-v,--version**
display version information and then exit

