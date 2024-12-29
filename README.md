<h2>
  RUST-SNMP
  <a href="https://crates.io/crates/snmp2"><img alt="crates.io page" src="https://img.shields.io/crates/v/snmp2.svg"></img></a>
  <a href="https://docs.rs/snmp2"><img alt="docs.rs page" src="https://docs.rs/snmp2/badge.svg"></img></a>
  <a href="https://github.com/roboplc/snmp2/actions/workflows/ci.yml">
    <img alt="GitHub Actions CI" src="https://github.com/roboplc/snmp2/actions/workflows/ci.yml/badge.svg"></img>
  </a>
</h2>

Dependency-free basic SNMP v1/v2 client in Rust.

This is a fork of the original [snmp](https://crates.io/crates/snmp) crate
which has been abandoned long time ago.

SNMP2 is a part of [RoboPLC](https://www.roboplc.com) project.

New features added to the fork:

- SNMP v1 support (including v1 traps)
- MIBs support (requires `mibs` feature and `libnetsnmp` library installed)
- Async session (requires `tokio` feature)
- Crate code has been refactored and cleaned up
- OIDs have been migrated to
  [asn1](https://docs.rs/asn1-rs/latest/asn1_rs/struct.Oid.html)
- Slightly improved PDU API, added a trap example

Supports:

- GET
- GETNEXT
- GETBULK
- SET
- Basic SNMP v1/v2 types
- Synchronous/Asynchronous requests
- UDP transport
- MIBs (with `mibs` feature, requires `libnetsnmp`)

Currently does not support:

- SNMPv3

## TODO

- SNMPv3


# Examples

## GET NEXT

```rust,no_run
use std::time::Duration;
use snmp2::{SyncSession, Value, Oid};

let sys_descr_oid = Oid::from(&[1,3,6,1,2,1,1,1,]).unwrap();
let agent_addr    = "198.51.100.123:161";
let community     = b"f00b4r";
let timeout       = Duration::from_secs(2);

let mut sess = SyncSession::new_v2c(agent_addr, community, Some(timeout), 0).unwrap();
let mut response = sess.getnext(&sys_descr_oid).unwrap();
if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
    println!("myrouter sysDescr: {}", String::from_utf8_lossy(sys_descr));
}
```

## GET BULK

```rust,no_run
use std::time::Duration;
use snmp2::{SyncSession, Oid};

let system_oid      = Oid::from(&[1,3,6,1,2,1,1,]).unwrap();
let agent_addr      = "[2001:db8:f00:b413::abc]:161";
let community       = b"f00b4r";
let timeout         = Duration::from_secs(2);
let non_repeaters   = 0;
let max_repetitions = 7; // number of items in "system" OID

let mut sess = SyncSession::new_v2c(agent_addr, community, Some(timeout), 0).unwrap();
let response = sess.getbulk(&[&system_oid], non_repeaters, max_repetitions).unwrap();

for (name, val) in response.varbinds {
    println!("{} => {:?}", name, val);
}
```

## SET

```rust,no_run
use std::time::Duration;
use snmp2::{SyncSession, Value, Oid};

let syscontact_oid  = Oid::from(&[1,3,6,1,2,1,1,4,0]).unwrap();
let contact         = Value::OctetString(b"Thomas A. Anderson");
let agent_addr      = "[2001:db8:f00:b413::abc]:161";
let community       = b"f00b4r";
let timeout         = Duration::from_secs(2);

let mut sess = SyncSession::new_v2c(agent_addr, community, Some(timeout), 0).unwrap();
let response = sess.set(&[(&syscontact_oid, contact)]).unwrap();

assert_eq!(response.error_status, snmp2::snmp::ERRSTATUS_NOERROR);
for (name, val) in response.varbinds {
    println!("{} => {:?}", name, val);
}
```

## TRAPS

```rust,no_run
use std::net::UdpSocket;
use snmp2::Pdu;

let socket = UdpSocket::bind("0.0.0.0:1162").expect("Could not bind socket");
loop {
    let mut buf = [0; 1500];
    let size = socket.recv(&mut buf).expect("Could not receive data");
    let data = &buf[..size];
    let pdu = Pdu::from_bytes(data).expect("Could not parse PDU");
    println!("Version: {}", pdu.version().unwrap());
    println!("Community: {}", std::str::from_utf8(pdu.community).unwrap());
    for (name, value) in pdu.varbinds {
        println!("{}={:?}", name, value);
    }
}
```

## Async session

```rust,no_run
use std::time::Duration;
use snmp2::{AsyncSession, Value, Oid};

async fn get_next() {
    // timeouts should be handled by the caller with `tokio::time::timeout`
    let sys_descr_oid = Oid::from(&[1,3,6,1,2,1,1,1,]).unwrap();
    let agent_addr    = "198.51.100.123:161";
    let community     = b"f00b4r";
    let mut sess = AsyncSession::new_v2c(agent_addr, community, 0).await.unwrap();
    let mut response = sess.getnext(&sys_descr_oid).await.unwrap();
    if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
        println!("myrouter sysDescr: {}", String::from_utf8_lossy(sys_descr));
    }
}
```

## Working with MIBs

Prepare the system

```shell
apt-get install libsnmp-dev snmp-mibs-downloader
```

```rust,ignore
use snmp2::{mibs::{self, MibConversion as _}, Oid};

mibs::init(&mibs::Config::new().mibs(&["./ibmConvergedPowerSystems.mib"]))
    .unwrap();
let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
let name = snmp_oid.mib_name().unwrap();
assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
let snmp_oid2 = Oid::from_mib_name(&name).unwrap();
assert_eq!(snmp_oid, snmp_oid2);
```

## MSRV

1.68.0

## Copyright

Copyright 2016 Hroi Sigurdsson

Copyright 2024 Serhij Symonenko, Bohemia Automation Limited

Licensed under the [Apache License, Version
2.0](http://www.apache.org/licenses/LICENSE-2.0) or the [MIT
license](http://opensource.org/licenses/MIT), at your option. This file may not
be copied, modified, or distributed except according to those terms.
