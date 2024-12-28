#![allow(unknown_lints, clippy::doc_markdown)]

use std::fmt;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::num::Wrapping;
use std::ptr;
use std::time::Duration;

#[cfg(feature = "mibs")]
pub use snmptools::init as init_mibs;

pub use der_parser::Oid;

#[cfg(target_pointer_width = "32")]
const USIZE_LEN: usize = 4;
#[cfg(target_pointer_width = "64")]
const USIZE_LEN: usize = 8;

/// SNMP protocol version.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i64)]
pub enum SnmpVersion {
    /// SNMPv1
    V1 = 0,
    /// SNMPv2c
    V2C = 1,
}

#[cfg(test)]
mod tests;

/// SNMP error type.
#[derive(Debug, PartialEq)]
pub enum SnmpError {
    /// ASN.1 parsing error.
    AsnParseError,
    /// ASN.1 invalid length.
    AsnInvalidLen,
    /// ASN.1 wrong type.
    AsnWrongType,
    /// ASN.1 unsupported type.
    AsnUnsupportedType,
    /// ASN.1 unexpected end of file.
    AsnEof,
    /// ASN.1 integer overflow.
    AsnIntOverflow,

    /// Invalid SNMP version.
    UnsupportedVersion,
    /// Invalid request ID.
    RequestIdMismatch,
    /// Invalid SNMP community string.
    CommunityMismatch,
    /// Value out of range.
    ValueOutOfRange,

    /// Socket send error.
    SendError,
    /// Socket receive error.
    ReceiveError,
}

impl From<std::num::TryFromIntError> for SnmpError {
    fn from(_: std::num::TryFromIntError) -> SnmpError {
        SnmpError::AsnIntOverflow
    }
}

type SnmpResult<T> = Result<T, SnmpError>;

const BUFFER_SIZE: usize = 4096;

pub mod asn1 {
    #![allow(dead_code, clippy::identity_op, clippy::eq_op)]

    pub const PRIMITIVE: u8 = 0b0000_0000;
    pub const CONSTRUCTED: u8 = 0b0010_0000;

    pub const CLASS_UNIVERSAL: u8 = 0b0000_0000;
    pub const CLASS_APPLICATION: u8 = 0b0100_0000;
    pub const CLASS_CONTEXTSPECIFIC: u8 = 0b1000_0000;
    pub const CLASS_PRIVATE: u8 = 0b1100_0000;

    pub const TYPE_BOOLEAN: u8 = CLASS_UNIVERSAL | PRIMITIVE | 1;
    pub const TYPE_INTEGER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 2;
    pub const TYPE_OCTETSTRING: u8 = CLASS_UNIVERSAL | PRIMITIVE | 4;
    pub const TYPE_NULL: u8 = CLASS_UNIVERSAL | PRIMITIVE | 5;
    pub const TYPE_OBJECTIDENTIFIER: u8 = CLASS_UNIVERSAL | PRIMITIVE | 6;
    pub const TYPE_SEQUENCE: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 16;
    pub const TYPE_SET: u8 = CLASS_UNIVERSAL | CONSTRUCTED | 17;
}

pub mod snmp {
    #![allow(dead_code, clippy::identity_op, clippy::eq_op)]

    use super::asn1;

    pub const MSG_GET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 0;
    pub const MSG_GET_NEXT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 1;
    pub const MSG_RESPONSE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 2;
    pub const MSG_SET: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 3;
    pub const MSG_GET_BULK: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 5;
    pub const MSG_INFORM: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 6;
    pub const MSG_TRAP: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 7;
    pub const MSG_REPORT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::CONSTRUCTED | 8;

    pub const TYPE_IPADDRESS: u8 = asn1::CLASS_APPLICATION | 0;
    pub const TYPE_COUNTER32: u8 = asn1::CLASS_APPLICATION | 1;
    pub const TYPE_UNSIGNED32: u8 = asn1::CLASS_APPLICATION | 2;
    pub const TYPE_GAUGE32: u8 = TYPE_UNSIGNED32;
    pub const TYPE_TIMETICKS: u8 = asn1::CLASS_APPLICATION | 3;
    pub const TYPE_OPAQUE: u8 = asn1::CLASS_APPLICATION | 4;
    pub const TYPE_COUNTER64: u8 = asn1::CLASS_APPLICATION | 6;

    pub const SNMP_NOSUCHOBJECT: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x0; // 80=128
    pub const SNMP_NOSUCHINSTANCE: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x1; // 81=129
    pub const SNMP_ENDOFMIBVIEW: u8 = asn1::CLASS_CONTEXTSPECIFIC | asn1::PRIMITIVE | 0x2; // 82=130

    pub const ERRSTATUS_NOERROR: u32 = 0;
    pub const ERRSTATUS_TOOBIG: u32 = 1;
    pub const ERRSTATUS_NOSUCHNAME: u32 = 2;
    pub const ERRSTATUS_BADVALUE: u32 = 3;
    pub const ERRSTATUS_READONLY: u32 = 4;
    pub const ERRSTATUS_GENERR: u32 = 5;
    pub const ERRSTATUS_NOACCESS: u32 = 6;
    pub const ERRSTATUS_WRONGTYPE: u32 = 7;
    pub const ERRSTATUS_WRONGLENGTH: u32 = 8;
    pub const ERRSTATUS_WRONGENCODING: u32 = 9;
    pub const ERRSTATUS_WRONGVALUE: u32 = 10;
    pub const ERRSTATUS_NOCREATION: u32 = 11;
    pub const ERRSTATUS_INCONSISTENTVALUE: u32 = 12;
    pub const ERRSTATUS_RESOURCEUNAVAILABLE: u32 = 13;
    pub const ERRSTATUS_COMMITFAILED: u32 = 14;
    pub const ERRSTATUS_UNDOFAILED: u32 = 15;
    pub const ERRSTATUS_AUTHORIZATIONERROR: u32 = 16;
    pub const ERRSTATUS_NOTWRITABLE: u32 = 17;
    pub const ERRSTATUS_INCONSISTENTNAME: u32 = 18;
}

pub mod pdu {
    use der_parser::Oid;

    use crate::SnmpVersion;

    use super::{asn1, snmp, Value, BUFFER_SIZE};
    use std::{fmt, mem, ops, ptr};

    pub struct Buf {
        len: usize,
        buf: [u8; BUFFER_SIZE],
    }

    impl fmt::Debug for Buf {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_list().entries(&self[..]).finish()
        }
    }

    impl Default for Buf {
        fn default() -> Buf {
            Buf {
                len: 0,
                buf: [0; BUFFER_SIZE],
            }
        }
    }

    impl ops::Deref for Buf {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.buf[BUFFER_SIZE - self.len..]
        }
    }

    impl Buf {
        fn available(&mut self) -> &mut [u8] {
            &mut self.buf[..(BUFFER_SIZE - self.len)]
        }

        fn push_chunk(&mut self, chunk: &[u8]) {
            let offset = BUFFER_SIZE - self.len;
            self.buf[(offset - chunk.len())..offset].copy_from_slice(chunk);
            self.len += chunk.len();
        }

        fn push_byte(&mut self, byte: u8) {
            self.buf[BUFFER_SIZE - self.len - 1] = byte;
            self.len += 1;
        }

        fn reset(&mut self) {
            self.len = 0;
        }

        fn scribble_bytes<F>(&mut self, mut f: F)
        where
            F: FnMut(&mut [u8]) -> usize,
        {
            let scribbled = f(self.available());
            self.len += scribbled;
        }

        fn push_constructed<F>(&mut self, ident: u8, mut f: F)
        where
            F: FnMut(&mut Self),
        {
            let before_len = self.len;
            f(self);
            let written = self.len - before_len;
            self.push_length(written);
            self.push_byte(ident);
        }

        fn push_sequence<F>(&mut self, f: F)
        where
            F: FnMut(&mut Self),
        {
            self.push_constructed(asn1::TYPE_SEQUENCE, f);
        }

        // fn push_set<F>(&mut self, f: F)
        //     where F: FnMut(&mut Self)
        // {
        //     self.push_constructed(asn1::TYPE_SET, f)
        // }

        #[allow(clippy::cast_possible_truncation)]
        fn push_length(&mut self, len: usize) {
            if len < 128 {
                // short form
                self.push_byte(len as u8);
            } else {
                // long form
                let num_leading_nulls = (len.leading_zeros() / 8) as usize;
                let length_len = mem::size_of::<usize>() - num_leading_nulls;
                let leading_byte = length_len as u8 | 0b1000_0000;
                self.scribble_bytes(|o| {
                    assert!(o.len() > length_len);
                    let bytes = len.to_be_bytes();
                    let write_offset = o.len() - length_len - 1;
                    o[write_offset] = leading_byte;
                    o[write_offset + 1..].copy_from_slice(&bytes[num_leading_nulls..]);
                    length_len + 1
                });
            }
        }

        fn push_integer(&mut self, n: i64) {
            let len = self.push_i64(n);
            self.push_length(len);
            self.push_byte(asn1::TYPE_INTEGER);
        }

        fn push_endofmibview(&mut self) {
            self.push_chunk(&[snmp::SNMP_ENDOFMIBVIEW, 0]);
        }

        fn push_nosuchobject(&mut self) {
            self.push_chunk(&[snmp::SNMP_NOSUCHOBJECT, 0]);
        }

        fn push_nosuchinstance(&mut self) {
            self.push_chunk(&[snmp::SNMP_NOSUCHINSTANCE, 0]);
        }

        fn push_counter32(&mut self, n: u32) {
            let len = self.push_i64(i64::from(n));
            self.push_length(len);
            self.push_byte(snmp::TYPE_COUNTER32);
        }

        fn push_unsigned32(&mut self, n: u32) {
            let len = self.push_i64(i64::from(n));
            self.push_length(len);
            self.push_byte(snmp::TYPE_UNSIGNED32);
        }

        fn push_timeticks(&mut self, n: u32) {
            let len = self.push_i64(i64::from(n));
            self.push_length(len);
            self.push_byte(snmp::TYPE_TIMETICKS);
        }

        fn push_opaque(&mut self, bytes: &[u8]) {
            self.push_chunk(bytes);
            self.push_length(bytes.len());
            self.push_byte(snmp::TYPE_OPAQUE);
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        fn push_counter64(&mut self, n: u64) {
            let len = self.push_i64(n as i64);
            self.push_length(len);
            self.push_byte(snmp::TYPE_COUNTER64);
        }

        fn push_i64(&mut self, mut n: i64) -> usize {
            let (null, num_null_bytes) = if n.is_negative() {
                (0xffu8, ((!n).leading_zeros() / 8) as usize)
            } else {
                (0x00u8, (n.leading_zeros() / 8) as usize)
            };
            n = n.to_be();
            let count = unsafe {
                let wbuf = self.available();
                let mut src_ptr = std::ptr::from_ref::<i64>(&n).cast::<u8>();
                let mut dst_ptr = wbuf.as_mut_ptr().add(wbuf.len() - mem::size_of::<i64>());
                let mut count = mem::size_of::<i64>() - num_null_bytes;
                if count == 0 {
                    count = 1;
                }
                // preserve sign
                if (*src_ptr.add(mem::size_of::<i64>() - count) ^ null) > 127u8 {
                    count += 1;
                }
                assert!(wbuf.len() >= count);
                #[allow(clippy::cast_possible_wrap)]
                let offset = (mem::size_of::<i64>() - count) as isize;
                src_ptr = src_ptr.offset(offset);
                dst_ptr = dst_ptr.offset(offset);
                ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);
                count
            };
            self.len += count;
            count
        }

        fn push_boolean(&mut self, boolean: bool) {
            if boolean {
                self.push_byte(0x1);
            } else {
                self.push_byte(0x0);
            }
            self.push_length(1);
            self.push_byte(asn1::TYPE_BOOLEAN);
        }

        fn push_ipaddress(&mut self, ip: [u8; 4]) {
            self.push_chunk(&ip);
            self.push_length(ip.len());
            self.push_byte(snmp::TYPE_IPADDRESS);
        }

        fn push_null(&mut self) {
            self.push_chunk(&[asn1::TYPE_NULL, 0]);
        }

        fn push_object_identifier_raw(&mut self, input: &[u8]) {
            self.push_chunk(input);
            self.push_length(input.len());
            self.push_byte(asn1::TYPE_OBJECTIDENTIFIER);
        }

        #[allow(clippy::cast_possible_truncation)]
        fn push_object_identifier(&mut self, input: &[u32]) {
            assert!(input.len() >= 2);
            let length_before = self.len;

            self.scribble_bytes(|output| {
                let mut pos = output.len() - 1;
                let (head, tail) = input.split_at(2);
                assert!(head[0] < 3 && head[1] < 40);

                // encode the subids in reverse order
                for subid in tail.iter().rev() {
                    let mut subid = *subid;
                    let mut last_byte = true;
                    loop {
                        assert!(pos != 0);
                        if last_byte {
                            // continue bit is cleared
                            output[pos] = (subid & 0b0111_1111) as u8;
                            last_byte = false;
                        } else {
                            // continue bit is set
                            output[pos] = (subid | 0b1000_0000) as u8;
                        }
                        pos -= 1;
                        subid >>= 7;

                        if subid == 0 {
                            break;
                        }
                    }
                }

                // encode the head last
                output[pos] = (head[0] * 40 + head[1]) as u8;
                output.len() - pos
            });
            let length_after = self.len;
            self.push_length(length_after - length_before);
            self.push_byte(asn1::TYPE_OBJECTIDENTIFIER);
        }

        fn push_octet_string(&mut self, bytes: &[u8]) {
            self.push_chunk(bytes);
            self.push_length(bytes.len());
            self.push_byte(asn1::TYPE_OCTETSTRING);
        }
    }

    pub fn build_get(
        version: SnmpVersion,
        community: &[u8],
        req_id: i32,
        oid: &Oid,
        buf: &mut Buf,
    ) {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET, |buf| {
                buf.push_sequence(|buf| {
                    buf.push_sequence(|buf| {
                        buf.push_null(); // value
                        buf.push_object_identifier_raw(oid.as_bytes()); // name
                    });
                });
                buf.push_integer(0); // error index
                buf.push_integer(0); // error status
                buf.push_integer(i64::from(req_id));
            });
            buf.push_octet_string(community);
            buf.push_integer(version as i64);
        });
    }

    pub fn build_getnext(
        version: SnmpVersion,
        community: &[u8],
        req_id: i32,
        oid: &Oid,
        buf: &mut Buf,
    ) {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET_NEXT, |buf| {
                buf.push_sequence(|buf| {
                    buf.push_sequence(|buf| {
                        buf.push_null(); // value
                        buf.push_object_identifier_raw(oid.as_bytes()); // name
                    });
                });
                buf.push_integer(0); // error index
                buf.push_integer(0); // error status
                buf.push_integer(i64::from(req_id));
            });
            buf.push_octet_string(community);
            buf.push_integer(version as i64);
        });
    }

    pub fn build_getbulk(
        version: SnmpVersion,
        community: &[u8],
        req_id: i32,
        oids: &[&Oid],
        non_repeaters: u32,
        max_repetitions: u32,
        buf: &mut Buf,
    ) {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_GET_BULK, |buf| {
                buf.push_sequence(|buf| {
                    for oid in oids.iter().rev() {
                        buf.push_sequence(|buf| {
                            buf.push_null(); // value
                            buf.push_object_identifier_raw(oid.as_bytes()); // name
                        });
                    }
                });
                buf.push_integer(i64::from(max_repetitions));
                buf.push_integer(i64::from(non_repeaters));
                buf.push_integer(i64::from(req_id));
            });
            buf.push_octet_string(community);
            buf.push_integer(version as i64);
        });
    }

    pub fn build_set(
        version: SnmpVersion,
        community: &[u8],
        req_id: i32,
        values: &[(&Oid, Value)],
        buf: &mut Buf,
    ) {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_SET, |buf| {
                buf.push_sequence(|buf| {
                    for &(oid, ref val) in values.iter().rev() {
                        buf.push_sequence(|buf| {
                            match *val {
                                Value::Boolean(b) => buf.push_boolean(b),
                                Value::Null => buf.push_null(),
                                Value::Integer(i) => buf.push_integer(i),
                                Value::OctetString(ostr) => buf.push_octet_string(ostr),
                                Value::ObjectIdentifier(ref objid) => {
                                    buf.push_object_identifier_raw(objid.as_bytes());
                                }
                                Value::IpAddress(ip) => buf.push_ipaddress(ip),
                                Value::Counter32(i) => buf.push_counter32(i),
                                Value::Unsigned32(i) => buf.push_unsigned32(i),
                                Value::Timeticks(tt) => buf.push_timeticks(tt),
                                Value::Opaque(bytes) => buf.push_opaque(bytes),
                                Value::Counter64(i) => buf.push_counter64(i),
                                _ => return,
                            }
                            buf.push_object_identifier_raw(oid.as_bytes()); // name
                        });
                    }
                });
                buf.push_integer(0);
                buf.push_integer(0);
                buf.push_integer(i64::from(req_id));
            });
            buf.push_octet_string(community);
            buf.push_integer(version as i64);
        });
    }

    pub fn build_response(
        version: SnmpVersion,
        community: &[u8],
        req_id: i32,
        values: &[(&[u32], Value)],
        buf: &mut Buf,
    ) {
        buf.reset();
        buf.push_sequence(|buf| {
            buf.push_constructed(snmp::MSG_RESPONSE, |buf| {
                buf.push_sequence(|buf| {
                    for &(name, ref val) in values.iter().rev() {
                        buf.push_sequence(|buf| {
                            match *val {
                                Value::Boolean(b) => buf.push_boolean(b),
                                Value::Null => buf.push_null(),
                                Value::Integer(i) => buf.push_integer(i),
                                Value::OctetString(ostr) => buf.push_octet_string(ostr),
                                Value::ObjectIdentifier(ref objid) => {
                                    buf.push_object_identifier_raw(objid.as_bytes());
                                }
                                Value::IpAddress(ip) => buf.push_ipaddress(ip),
                                Value::Counter32(i) => buf.push_counter32(i),
                                Value::Unsigned32(i) => buf.push_unsigned32(i),
                                Value::Timeticks(tt) => buf.push_timeticks(tt),
                                Value::Opaque(bytes) => buf.push_opaque(bytes),
                                Value::Counter64(i) => buf.push_counter64(i),
                                Value::EndOfMibView => buf.push_endofmibview(),
                                Value::NoSuchObject => buf.push_nosuchobject(),
                                Value::NoSuchInstance => buf.push_nosuchinstance(),
                                _ => return,
                            }
                            buf.push_object_identifier(name); // name
                        });
                    }
                });
                buf.push_integer(0);
                buf.push_integer(0);
                buf.push_integer(i64::from(req_id));
            });
            buf.push_octet_string(community);
            buf.push_integer(version as i64);
        });
    }
}

fn decode_i64(i: &[u8]) -> SnmpResult<i64> {
    if i.len() > mem::size_of::<i64>() {
        return Err(SnmpError::AsnIntOverflow);
    }
    let mut bytes = [0u8; 8];
    bytes[(mem::size_of::<i64>() - i.len())..].copy_from_slice(i);

    let mut ret = unsafe { mem::transmute::<[u8; 8], i64>(bytes).to_be() };
    {
        //sign extend
        let shift_amount = (mem::size_of::<i64>() - i.len()) * 8;
        ret = (ret << shift_amount) >> shift_amount;
    }
    Ok(ret)
}

/// ASN.1/DER decoder iterator.
///
/// Supports:
///
/// - types required by SNMP.
///
/// Does not support:
///
/// - extended tag IDs.
/// - indefinite lengths (disallowed by DER).
/// - INTEGER values not representable by i64.
pub struct AsnReader<'a> {
    inner: &'a [u8],
}

impl<'a> Clone for AsnReader<'a> {
    fn clone(&self) -> AsnReader<'a> {
        AsnReader { inner: self.inner }
    }
}

impl fmt::Debug for AsnReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> AsnReader<'a> {
    pub fn from_bytes(bytes: &[u8]) -> AsnReader {
        AsnReader { inner: bytes }
    }

    pub fn peek_byte(&mut self) -> SnmpResult<u8> {
        if self.inner.is_empty() {
            Err(SnmpError::AsnEof)
        } else {
            Ok(self.inner[0])
        }
    }

    pub fn read_byte(&mut self) -> SnmpResult<u8> {
        match self.inner.split_first() {
            Some((head, tail)) => {
                self.inner = tail;
                Ok(*head)
            }
            _ => Err(SnmpError::AsnEof),
        }
    }

    pub fn read_length(&mut self) -> SnmpResult<usize> {
        if let Some((head, tail)) = self.inner.split_first() {
            let o: usize;
            if head < &128 {
                // short form
                o = *head as usize;
                self.inner = tail;
                Ok(o)
            } else if head == &0xff {
                Err(SnmpError::AsnInvalidLen) // reserved for future use
            } else {
                // long form
                let length_len = (*head & 0b0111_1111) as usize;
                if length_len == 0 {
                    // Indefinite length. Not allowed in DER.
                    return Err(SnmpError::AsnInvalidLen);
                }

                let mut bytes = [0u8; USIZE_LEN];
                bytes[(USIZE_LEN - length_len)..].copy_from_slice(&tail[..length_len]);

                o = unsafe { mem::transmute::<[u8; USIZE_LEN], usize>(bytes).to_be() };
                self.inner = &tail[length_len..];
                Ok(o)
            }
        } else {
            Err(SnmpError::AsnEof)
        }
    }

    pub fn read_i64_type(&mut self, expected_ident: u8) -> SnmpResult<i64> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        decode_i64(val)
    }

    pub fn read_raw(&mut self, expected_ident: u8) -> SnmpResult<&'a [u8]> {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (val, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;
        Ok(val)
    }

    pub fn read_constructed<F>(&mut self, expected_ident: u8, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        let ident = self.read_byte()?;
        if ident != expected_ident {
            return Err(SnmpError::AsnWrongType);
        }
        let seq_len = self.read_length()?;
        if seq_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (seq_bytes, remaining) = self.inner.split_at(seq_len);
        let mut reader = AsnReader::from_bytes(seq_bytes);
        self.inner = remaining;
        f(&mut reader)
    }

    //
    // ASN
    //

    pub fn read_asn_boolean(&mut self) -> SnmpResult<bool> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len != 1 {
            return Err(SnmpError::AsnInvalidLen);
        }
        match self.read_byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnmpError::AsnParseError), // DER mandates 1/0 for booleans
        }
    }

    pub fn read_asn_integer(&mut self) -> SnmpResult<i64> {
        self.read_i64_type(asn1::TYPE_INTEGER)
    }

    pub fn read_asn_octetstring(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(asn1::TYPE_OCTETSTRING)
    }

    pub fn read_asn_null(&mut self) -> SnmpResult<()> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_NULL {
            return Err(SnmpError::AsnWrongType);
        }
        let null_len = self.read_length()?;
        if null_len != 0 {
            Err(SnmpError::AsnInvalidLen)
        } else {
            Ok(())
        }
    }

    pub fn read_asn_objectidentifier(&mut self) -> SnmpResult<Oid<'a>> {
        let ident = self.read_byte()?;
        if ident != asn1::TYPE_OBJECTIDENTIFIER {
            return Err(SnmpError::AsnWrongType);
        }
        let val_len = self.read_length()?;
        if val_len > self.inner.len() {
            return Err(SnmpError::AsnInvalidLen);
        }
        let (input, remaining) = self.inner.split_at(val_len);
        self.inner = remaining;

        Ok(Oid::new(input.into()))
    }

    pub fn read_asn_sequence<F>(&mut self, f: F) -> SnmpResult<()>
    where
        F: Fn(&mut AsnReader) -> SnmpResult<()>,
    {
        self.read_constructed(asn1::TYPE_SEQUENCE, f)
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn read_snmp_counter32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_COUNTER32).map(|v| v as u32)
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn read_snmp_unsigned32(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_UNSIGNED32).map(|v| v as u32)
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn read_snmp_timeticks(&mut self) -> SnmpResult<u32> {
        self.read_i64_type(snmp::TYPE_TIMETICKS).map(|v| v as u32)
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn read_snmp_counter64(&mut self) -> SnmpResult<u64> {
        self.read_i64_type(snmp::TYPE_COUNTER64).map(|v| v as u64)
    }

    pub fn read_snmp_opaque(&mut self) -> SnmpResult<&'a [u8]> {
        self.read_raw(snmp::TYPE_OPAQUE)
    }

    pub fn read_snmp_ipaddress(&mut self) -> SnmpResult<[u8; 4]> {
        let val = self.read_raw(snmp::TYPE_IPADDRESS)?;
        if val.len() != 4 {
            return Err(SnmpError::AsnInvalidLen);
        }
        unsafe { Ok(ptr::read(val.as_ptr().cast())) }
    }
}

pub enum Value<'a> {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(&'a [u8]),
    ObjectIdentifier(Oid<'a>),
    Sequence(AsnReader<'a>),
    Set(AsnReader<'a>),
    Constructed(u8, AsnReader<'a>),

    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(&'a [u8]),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,

    SnmpGetRequest(AsnReader<'a>),
    SnmpGetNextRequest(AsnReader<'a>),
    SnmpGetBulkRequest(AsnReader<'a>),
    SnmpResponse(AsnReader<'a>),
    SnmpSetRequest(AsnReader<'a>),
    SnmpInformRequest(AsnReader<'a>),
    SnmpTrap(AsnReader<'a>),
    SnmpReport(AsnReader<'a>),
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Boolean(v) => write!(f, "BOOLEAN: {}", v),
            Value::Integer(n) => write!(f, "INTEGER: {}", n),
            Value::OctetString(slice) => {
                write!(f, "OCTET STRING: {}", String::from_utf8_lossy(slice))
            }
            Value::ObjectIdentifier(ref obj_id) => write!(f, "OBJECT IDENTIFIER: {}", obj_id),
            Value::Null => write!(f, "NULL"),
            Value::Sequence(ref val) => write!(f, "SEQUENCE: {:#?}", val),
            Value::Set(ref val) => write!(f, "SET: {:?}", val),
            Value::Constructed(ident, ref val) => write!(f, "CONSTRUCTED-{}: {:#?}", ident, val),
            Value::IpAddress(val) => {
                write!(f, "IP ADDRESS: {}.{}.{}.{}", val[0], val[1], val[2], val[3])
            }
            Value::Counter32(val) => write!(f, "COUNTER32: {}", val),
            Value::Unsigned32(val) => write!(f, "UNSIGNED32: {}", val),
            Value::Timeticks(val) => write!(f, "TIMETICKS: {}", val),
            Value::Opaque(val) => write!(f, "OPAQUE: {:?}", val),
            Value::Counter64(val) => write!(f, "COUNTER64: {}", val),
            Value::EndOfMibView => write!(f, "END OF MIB VIEW"),
            Value::NoSuchObject => write!(f, "NO SUCH OBJECT"),
            Value::NoSuchInstance => write!(f, "NO SUCH INSTANCE"),
            Value::SnmpGetRequest(ref val) => write!(f, "SNMP GET REQUEST: {:#?}", val),
            Value::SnmpGetNextRequest(ref val) => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            Value::SnmpGetBulkRequest(ref val) => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            Value::SnmpResponse(ref val) => write!(f, "SNMP RESPONSE: {:#?}", val),
            Value::SnmpSetRequest(ref val) => write!(f, "SNMP SET REQUEST: {:#?}", val),
            Value::SnmpInformRequest(ref val) => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            Value::SnmpTrap(ref val) => write!(f, "SNMP TRAP: {:#?}", val),
            Value::SnmpReport(ref val) => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}

impl<'a> Iterator for AsnReader<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        if let Ok(ident) = self.peek_byte() {
            let ret: SnmpResult<Value> = match ident {
                asn1::TYPE_BOOLEAN => self.read_asn_boolean().map(Value::Boolean),
                asn1::TYPE_NULL => self.read_asn_null().map(|()| Value::Null),
                asn1::TYPE_INTEGER => self.read_asn_integer().map(Value::Integer),
                asn1::TYPE_OCTETSTRING => self.read_asn_octetstring().map(Value::OctetString),
                asn1::TYPE_OBJECTIDENTIFIER => self
                    .read_asn_objectidentifier()
                    .map(Value::ObjectIdentifier),
                asn1::TYPE_SEQUENCE => self
                    .read_raw(ident)
                    .map(|v| Value::Sequence(AsnReader::from_bytes(v))),
                asn1::TYPE_SET => self
                    .read_raw(ident)
                    .map(|v| Value::Set(AsnReader::from_bytes(v))),
                snmp::TYPE_IPADDRESS => self.read_snmp_ipaddress().map(Value::IpAddress),
                snmp::TYPE_COUNTER32 => self.read_snmp_counter32().map(Value::Counter32),
                snmp::TYPE_UNSIGNED32 => self.read_snmp_unsigned32().map(Value::Unsigned32),
                snmp::TYPE_TIMETICKS => self.read_snmp_timeticks().map(Value::Timeticks),
                snmp::TYPE_OPAQUE => self.read_snmp_opaque().map(Value::Opaque),
                snmp::TYPE_COUNTER64 => self.read_snmp_counter64().map(Value::Counter64),
                snmp::MSG_GET => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpGetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_NEXT => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpGetNextRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_BULK => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpGetBulkRequest(AsnReader::from_bytes(v))),
                snmp::MSG_RESPONSE => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpResponse(AsnReader::from_bytes(v))),
                snmp::MSG_SET => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpSetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_INFORM => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpInformRequest(AsnReader::from_bytes(v))),
                snmp::MSG_TRAP => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpTrap(AsnReader::from_bytes(v))),
                snmp::MSG_REPORT => self
                    .read_raw(ident)
                    .map(|v| Value::SnmpReport(AsnReader::from_bytes(v))),
                ident if ident & asn1::CONSTRUCTED == asn1::CONSTRUCTED => self
                    .read_raw(ident)
                    .map(|v| Value::Constructed(ident, AsnReader::from_bytes(v))),
                _ => Err(SnmpError::AsnUnsupportedType),
            };
            ret.ok()
        } else {
            None
        }
    }
}

/// Synchronous SNMPv2 client.
pub struct SyncSession {
    version: SnmpVersion,
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: [u8; BUFFER_SIZE],
}

impl SyncSession {
    pub fn new_v1<SA>(
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(
            SnmpVersion::V1,
            destination,
            community,
            timeout,
            starting_req_id,
        )
    }

    pub fn new_v2c<SA>(
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(
            SnmpVersion::V2C,
            destination,
            community,
            timeout,
            starting_req_id,
        )
    }

    pub fn new<SA>(
        version: SnmpVersion,
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match destination.to_socket_addrs()?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0))?,
            Some(SocketAddr::V6(_)) => UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0))?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No address found",
                ))
            }
        };
        socket.set_read_timeout(timeout)?;
        socket.connect(destination)?;
        Ok(SyncSession {
            version,
            socket,
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; 4096],
        })
    }

    fn send_and_recv(socket: &UdpSocket, pdu: &pdu::Buf, out: &mut [u8]) -> SnmpResult<usize> {
        if let Ok(_pdu_len) = socket.send(&pdu[..]) {
            match socket.recv(out) {
                Ok(len) => Ok(len),
                Err(_) => Err(SnmpError::ReceiveError),
            }
        } else {
            Err(SnmpError::SendError)
        }
    }

    pub fn get(&mut self, oid: &Oid) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_get(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
        );
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes, self.version)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }

    pub fn getnext(&mut self, oid: &Oid) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_getnext(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
        );
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes, self.version)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }

    pub fn getbulk(
        &mut self,
        oids: &[&Oid],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_getbulk(
            self.version,
            self.community.as_slice(),
            req_id,
            oids,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        );
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes, self.version)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }

    /// # Panics if any of the values are not one of these supported types:
    ///   - `Boolean`
    ///   - `Null`
    ///   - `Integer`
    ///   - `OctetString`
    ///   - `ObjectIdentifier`
    ///   - `IpAddress`
    ///   - `Counter32`
    ///   - `Unsigned32`
    ///   - `Timeticks`
    ///   - `Opaque`
    ///   - `Counter64`
    pub fn set(&mut self, values: &[(&Oid, Value)]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        pdu::build_set(
            self.version,
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
        );
        let recv_len = Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf[..])?;
        self.req_id += Wrapping(1);
        let pdu_bytes = &self.recv_buf[..recv_len];
        let resp = SnmpPdu::from_bytes(pdu_bytes, self.version)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
}

#[derive(Debug)]
pub struct SnmpPdu<'a> {
    #[allow(dead_code)]
    version: i64,
    community: &'a [u8],
    pub message_type: SnmpMessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Varbinds<'a>,
}

impl<'a> SnmpPdu<'a> {
    pub fn from_bytes(bytes: &'a [u8], snmp_version: SnmpVersion) -> SnmpResult<SnmpPdu<'a>> {
        let seq = AsnReader::from_bytes(bytes).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version != snmp_version as i64 {
            return Err(SnmpError::UnsupportedVersion);
        }
        let community = rdr.read_asn_octetstring()?;
        let ident = rdr.peek_byte()?;
        let message_type = SnmpMessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i64::from(i32::MIN) || req_id > i64::from(i32::MAX) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i64::from(i32::MAX) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i64::from(i32::MAX) {
            return Err(SnmpError::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);

        Ok(SnmpPdu {
            version,
            community,
            message_type,
            req_id: i32::try_from(req_id)?,
            error_status: u32::try_from(error_status)?,
            error_index: u32::try_from(error_index)?,
            varbinds,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum SnmpMessageType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    Response,
    SetRequest,
    InformRequest,
    Trap,
    Report,
}

impl SnmpMessageType {
    pub fn from_ident(ident: u8) -> SnmpResult<SnmpMessageType> {
        Ok(match ident {
            snmp::MSG_GET => SnmpMessageType::GetRequest,
            snmp::MSG_GET_NEXT => SnmpMessageType::GetNextRequest,
            snmp::MSG_GET_BULK => SnmpMessageType::GetBulkRequest,
            snmp::MSG_RESPONSE => SnmpMessageType::Response,
            snmp::MSG_SET => SnmpMessageType::SetRequest,
            snmp::MSG_INFORM => SnmpMessageType::InformRequest,
            snmp::MSG_TRAP => SnmpMessageType::Trap,
            snmp::MSG_REPORT => SnmpMessageType::Report,
            _ => return Err(SnmpError::AsnWrongType),
        })
    }
}

#[derive(Clone)]
pub struct Varbinds<'a> {
    inner: AsnReader<'a>,
}

impl fmt::Debug for Varbinds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // f.debug_list().entries(self.clone()).finish()
        let mut ds = f.debug_struct("Varbinds");
        for (name, val) in self.clone() {
            ds.field(&format!("{}", name), &format!("{:?}", val));
        }
        ds.finish()
    }
}

impl<'a> Varbinds<'a> {
    fn from_bytes(bytes: &'a [u8]) -> Varbinds<'a> {
        Varbinds {
            inner: AsnReader::from_bytes(bytes),
        }
    }
}

impl<'a> Iterator for Varbinds<'a> {
    type Item = (Oid<'a>, Value<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(seq) = self.inner.read_raw(asn1::TYPE_SEQUENCE) {
            let mut pair = AsnReader::from_bytes(seq);
            if let (Ok(name), Some(value)) = (pair.read_asn_objectidentifier(), pair.next()) {
                return Some((name, value));
            }
        }
        None
    }
}
