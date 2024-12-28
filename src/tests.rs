use super::{pdu, snmp, Oid};
use super::{AsnReader, Error, Version};

#[test]
fn build_getnext_pdu() {
    let mut pdu = pdu::Buf::default();
    pdu::build_getnext(
        Version::V2C,
        b"tyS0n43d",
        1_251_699_618,
        &Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap(),
        &mut pdu,
    );

    let expected = &[
        0x30, 0x2b, 0x02, 0x01, 0x01, 0x04, 0x08, 0x74, 0x79, 0x53, 0x30, 0x6e, 0x34, 0x33, 0x64,
        0xa1, 0x1c, 0x02, 0x04, 0x4a, 0x9b, 0x6b, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
        0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];

    println!("{:?}", pdu);
    println!("{:?}", &expected[..]);

    assert_eq!(&pdu[..], &expected[..]);
}

#[test]
fn asn_read_byte() {
    let bytes = [1, 2, 3, 4];
    let mut reader = AsnReader::from_bytes(&bytes[..]);
    let a = reader.read_byte().unwrap();
    let b = reader.read_byte().unwrap();
    let c = reader.read_byte().unwrap();
    let d = reader.read_byte().unwrap();
    assert_eq!(&[a, b, c, d], &bytes[..]);
    assert_eq!(reader.read_byte(), Err(Error::AsnEof));
}

#[test]
fn asn_parse_getnext_pdu() {
    let pdu = &[
        0x30, 0x2b, 0x02, 0x01, 0x01, 0x04, 0x08, 0x74, 0x79, 0x53, 0x30, 0x6e, 0x34, 0x33, 0x64,
        0xa1, 0x1c, 0x02, 0x04, 0x4a, 0x9b, 0x6b, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
        0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    let mut reader = AsnReader::from_bytes(&pdu[..]);
    reader
        .read_asn_sequence(|rdr| {
            let version = rdr.read_asn_integer()?;
            assert_eq!(version, Version::V2C as i64);
            let community = rdr.read_asn_octetstring()?;
            assert_eq!(community, b"tyS0n43d");
            println!("version: {}", version);
            let msg_ident = rdr.peek_byte()?;
            println!("msg_ident: {}", msg_ident);
            assert_eq!(msg_ident, snmp::MSG_GET_NEXT);
            rdr.read_constructed(msg_ident, |rdr| {
                let req_id = rdr.read_asn_integer()?;
                let error_status = rdr.read_asn_integer()?;
                let error_index = rdr.read_asn_integer()?;
                println!(
                    "req_id: {}, error_status: {}, error_index: {}",
                    req_id, error_status, error_index
                );
                assert_eq!(req_id, 1_251_699_618);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                rdr.read_asn_sequence(|rdr| {
                    rdr.read_asn_sequence(|rdr| {
                        let name = rdr.read_asn_objectidentifier()?;
                        let expected = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
                        println!("name: {}", name);
                        assert_eq!(name, expected);
                        rdr.read_asn_null()
                    })
                })
            })
        })
        .unwrap();
}

#[test]
#[cfg(feature = "mibs")]
fn test_mib() {
    use crate::mibs::MibConversion as _;

    super::mibs::init(&super::mibs::Config::new().mibs(&["./ibmConvergedPowerSystems.mib"]))
        .unwrap();
    let snmp_oid = Oid::from(&[1, 3, 6, 1, 4, 1, 2, 6, 201, 3]).unwrap();
    let name = snmp_oid.mib_name().unwrap();
    assert_eq!(name, "IBM-CPS-MIB::cpsSystemSendTrap");
    let snmp_oid2 = Oid::from_mib_name(&name).unwrap();
    assert_eq!(snmp_oid, snmp_oid2);
}
