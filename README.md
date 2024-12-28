# RUST-SNMP

Dependency-free basic SNMP v1/v2 client in Rust.

This is a fork of the original [snmp](https://crates.io/crates/snmp) crate
which has been abandoned long time ago.

New features added to the fork:

- SNMP v1 support
- MIBs support (requires `libnetsnmp`)
- Crate code has been refactored and cleaned up
- OIDs have been migrated to
  [asn1](https://docs.rs/asn1-rs/latest/asn1_rs/struct.Oid.html) (via
  [der-parser](https://docs.rs/der-parser))

Supports:

- GET
- GETNEXT
- GETBULK
- SET
- Basic SNMP v1/v2 types
- Synchronous requests
- UDP transport
- MIBs (with `mibs` feature, requires `libnetsnmp`, read more in
  [snmptools](https://docs.rs/snmptools/latest/snmptools/) docs how to prepare the system)

Currently does not support:

- SNMPv3

## TODO

- Transport-agnostic API
- SNMPv3


# Examples

## GET NEXT

```no_run
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

## Working with MIBs

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

## Copyright

Copyright 2016 Hroi Sigurdsson
Copyright 2024 Serhij Symonenko, Bohemia Automation Limited

Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
<LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
option. This file may not be copied, modified, or distributed
except according to those terms.