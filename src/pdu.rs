#[cfg(feature = "v3")]
use crate::v3;
#[cfg(feature = "v3_aws_lc_rs")]
use crate::v3_aws_lc_rs;
use crate::{
    asn1::{self, AsnReader},
    snmp, Error, MessageType, Oid, Result, Value, Varbinds, Version, BUFFER_SIZE,
};
use std::{
    fmt, mem,
    net::{IpAddr, Ipv4Addr},
    ops, ptr,
};

pub(crate) struct Buf {
    len: usize,
    #[cfg(not(feature = "heap_buffers"))]
    buf: [u8; BUFFER_SIZE],

    #[cfg(feature = "heap_buffers")]
    buf: Box<[u8]>,
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
            #[cfg(not(feature = "heap_buffers"))]
            buf: [0; BUFFER_SIZE],
            #[cfg(feature = "heap_buffers")]
            buf: vec![0; BUFFER_SIZE].into_boxed_slice(),
        }
    }
}

impl ops::Deref for Buf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[BUFFER_SIZE - self.len..]
    }
}

impl ops::DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[BUFFER_SIZE - self.len..]
    }
}

impl Buf {
    pub fn available(&mut self) -> &mut [u8] {
        &mut self.buf[..(BUFFER_SIZE - self.len)]
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) {
        let offset = BUFFER_SIZE - self.len;
        self.buf[(offset - chunk.len())..offset].copy_from_slice(chunk);
        self.len += chunk.len();
    }

    pub fn push_byte(&mut self, byte: u8) {
        self.buf[BUFFER_SIZE - self.len - 1] = byte;
        self.len += 1;
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }

    pub fn scribble_bytes<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut [u8]) -> usize,
    {
        let scribbled = f(self.available());
        self.len += scribbled;
    }

    pub fn push_constructed<F>(&mut self, ident: u8, mut f: F)
    where
        F: FnMut(&mut Self),
    {
        let before_len = self.len;
        f(self);
        let written = self.len - before_len;
        self.push_length(written);
        self.push_byte(ident);
    }

    pub fn push_sequence<F>(&mut self, f: F)
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
    pub fn push_length(&mut self, len: usize) {
        if len < 128 {
            // short form
            self.push_byte(len as u8);
        } else {
            // long form
            let num_leading_nulls = (len.leading_zeros() / 8) as usize;
            let length_len = mem::size_of::<usize>() - num_leading_nulls;
            let leading_byte = length_len as u8 | 0b1000_0000;
            self.scribble_bytes(|o| {
                if o.len() <= length_len {
                    return 0;
                }
                let bytes = len.to_be_bytes();
                let write_offset = o.len() - length_len - 1;
                o[write_offset] = leading_byte;
                o[write_offset + 1..].copy_from_slice(&bytes[num_leading_nulls..]);
                length_len + 1
            });
        }
    }

    pub fn push_integer(&mut self, n: i64) {
        let len = self.push_i64(n);
        self.push_length(len);
        self.push_byte(asn1::TYPE_INTEGER);
    }

    pub fn push_endofmibview(&mut self) {
        self.push_chunk(&[snmp::SNMP_ENDOFMIBVIEW, 0]);
    }

    pub fn push_nosuchobject(&mut self) {
        self.push_chunk(&[snmp::SNMP_NOSUCHOBJECT, 0]);
    }

    pub fn push_nosuchinstance(&mut self) {
        self.push_chunk(&[snmp::SNMP_NOSUCHINSTANCE, 0]);
    }

    pub fn push_counter32(&mut self, n: u32) {
        let len = self.push_i64(i64::from(n));
        self.push_length(len);
        self.push_byte(snmp::TYPE_COUNTER32);
    }

    pub fn push_unsigned32(&mut self, n: u32) {
        let len = self.push_i64(i64::from(n));
        self.push_length(len);
        self.push_byte(snmp::TYPE_UNSIGNED32);
    }

    pub fn push_timeticks(&mut self, n: u32) {
        let len = self.push_i64(i64::from(n));
        self.push_length(len);
        self.push_byte(snmp::TYPE_TIMETICKS);
    }

    pub fn push_opaque(&mut self, bytes: &[u8]) {
        self.push_chunk(bytes);
        self.push_length(bytes.len());
        self.push_byte(snmp::TYPE_OPAQUE);
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub fn push_counter64(&mut self, n: u64) {
        let len = self.push_i64(n as i64);
        self.push_length(len);
        self.push_byte(snmp::TYPE_COUNTER64);
    }

    pub fn push_i64(&mut self, mut n: i64) -> usize {
        let (null, num_null_bytes) = if n.is_negative() {
            (0xffu8, ((!n).leading_zeros() / 8) as usize)
        } else {
            (0x00u8, (n.leading_zeros() / 8) as usize)
        };
        n = n.to_be();
        let count = unsafe {
            let wbuf = self.available();
            let mut src_ptr = ptr::addr_of!(n).cast::<u8>();
            let mut dst_ptr = wbuf.as_mut_ptr().add(wbuf.len() - mem::size_of::<i64>());
            let mut count = mem::size_of::<i64>() - num_null_bytes;
            if count == 0 {
                count = 1;
            }
            // preserve sign
            if (*src_ptr.add(mem::size_of::<i64>() - count) ^ null) > 127u8 {
                count += 1;
            }
            if wbuf.len() < count {
                return 0;
            }
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

    pub fn push_boolean(&mut self, boolean: bool) {
        if boolean {
            self.push_byte(0x1);
        } else {
            self.push_byte(0x0);
        }
        self.push_length(1);
        self.push_byte(asn1::TYPE_BOOLEAN);
    }

    pub fn push_ipaddress(&mut self, ip: [u8; 4]) {
        self.push_chunk(&ip);
        self.push_length(ip.len());
        self.push_byte(snmp::TYPE_IPADDRESS);
    }

    pub fn push_null(&mut self) {
        self.push_chunk(&[asn1::TYPE_NULL, 0]);
    }

    pub fn push_object_identifier_raw(&mut self, input: &[u8]) {
        self.push_chunk(input);
        self.push_length(input.len());
        self.push_byte(asn1::TYPE_OBJECTIDENTIFIER);
    }

    #[allow(dead_code, clippy::cast_possible_truncation)]
    pub fn push_object_identifier(&mut self, input: &[u32]) {
        if input.len() < 2 {
            return;
        }
        let length_before = self.len;

        self.scribble_bytes(|output| {
            let mut pos = output.len() - 1;
            let (head, tail) = input.split_at(2);
            if head[0] >= 3 || head[1] >= 40 {
                return 0;
            }

            // encode the subids in reverse order
            for subid in tail.iter().rev() {
                let mut subid = *subid;
                let mut last_byte = true;
                loop {
                    if pos == 0 {
                        return 0;
                    }
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

    pub fn push_octet_string(&mut self, bytes: &[u8]) {
        self.push_chunk(bytes);
        self.push_length(bytes.len());
        self.push_byte(asn1::TYPE_OCTETSTRING);
    }
}

/// For reply: non_repeaters = error_status, max_repetitions = error_index
#[allow(clippy::too_many_arguments, clippy::unnecessary_wraps)]
#[inline]
pub(crate) fn build(
    version: Version,
    community: &[u8],
    ident: u8,
    req_id: i32,
    values: &[(&Oid, Value)],
    non_repeaters: u32,
    max_repetitions: u32,
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    #[cfg(feature = "v3")]
    if version == Version::V3 {
        return v3::build(
            ident,
            req_id,
            values,
            non_repeaters,
            max_repetitions,
            buf,
            security,
        );
    }
    #[cfg(feature = "v3_aws_lc_rs")]
    if version == Version::V3 {
        return v3_aws_lc_rs::build(
            ident,
            req_id,
            values,
            non_repeaters,
            max_repetitions,
            buf,
            security,
        );
    }
    buf.reset();
    buf.push_sequence(|buf| {
        build_inner(req_id, ident, values, max_repetitions, non_repeaters, buf);
        buf.push_octet_string(community);
        buf.push_integer(version as i64);
    });
    Ok(())
}

#[inline]
pub(crate) fn build_inner(
    req_id: i32,
    ident: u8,
    values: &[(&Oid, Value)],
    non_repeaters: u32,
    max_repetitions: u32,
    buf: &mut Buf,
) {
    buf.push_constructed(ident, |buf| {
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
                        Value::EndOfMibView => buf.push_endofmibview(),
                        Value::NoSuchObject => buf.push_nosuchobject(),
                        Value::NoSuchInstance => buf.push_nosuchinstance(),
                        _ => return,
                    }
                    buf.push_object_identifier_raw(oid.as_bytes());
                });
            }
        });
        buf.push_integer(non_repeaters.into());
        buf.push_integer(max_repetitions.into());
        buf.push_integer(i64::from(req_id));
    });
}

pub(crate) fn build_get(
    version: Version,
    community: &[u8],
    req_id: i32,
    oid: &Oid,
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    build(
        version,
        community,
        snmp::MSG_GET,
        req_id,
        &[(oid, Value::Null)],
        0,
        0,
        buf,
        #[cfg(feature = "v3")]
        security,
        #[cfg(feature = "v3_aws_lc_rs")]
        security,
    )
}

pub(crate) fn build_get_many(
    version: Version,
    community: &[u8],
    req_id: i32,
    oids: &[&Oid],
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    build(
        version,
        community,
        snmp::MSG_GET,
        req_id,
        oids.iter()
            .map(|&oid| (oid, Value::Null))
            .collect::<Vec<_>>()
            .as_slice(),
        0,
        0,
        buf,
        #[cfg(feature = "v3")]
        security,
        #[cfg(feature = "v3_aws_lc_rs")]
        security,
    )
}

pub(crate) fn build_getnext(
    version: Version,
    community: &[u8],
    req_id: i32,
    oid: &Oid,
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    build(
        version,
        community,
        snmp::MSG_GET_NEXT,
        req_id,
        &[(oid, Value::Null)],
        0,
        0,
        buf,
        #[cfg(feature = "v3")]
        security,
        #[cfg(feature = "v3_aws_lc_rs")]
        security,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_getbulk(
    version: Version,
    community: &[u8],
    req_id: i32,
    oids: &[&Oid],
    non_repeaters: u32,
    max_repetitions: u32,
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    build(
        version,
        community,
        snmp::MSG_GET_BULK,
        req_id,
        oids.iter()
            .map(|&oid| (oid, Value::Null))
            .collect::<Vec<_>>()
            .as_slice(),
        non_repeaters,
        max_repetitions,
        buf,
        #[cfg(feature = "v3")]
        security,
        #[cfg(feature = "v3_aws_lc_rs")]
        security,
    )
}

pub(crate) fn build_set(
    version: Version,
    community: &[u8],
    req_id: i32,
    values: &[(&Oid, Value)],
    buf: &mut Buf,
    #[cfg(feature = "v3")] security: Option<&v3::Security>,
    #[cfg(feature = "v3_aws_lc_rs")] security: Option<&v3_aws_lc_rs::Security>,
) -> Result<()> {
    build(
        version,
        community,
        snmp::MSG_SET,
        req_id,
        values,
        0,
        0,
        buf,
        #[cfg(feature = "v3")]
        security,
        #[cfg(feature = "v3_aws_lc_rs")]
        security,
    )
}

#[derive(Debug, Clone)]
pub struct Pdu<'a> {
    pub(crate) version: i64,
    pub community: &'a [u8],
    pub message_type: MessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub varbinds: Varbinds<'a>,
    pub v1_trap_info: Option<V1TrapInfo<'a>>,
    #[cfg(any(feature = "v3", feature = "v3_aws_lc_rs"))]
    pub v3_msg_id: i32,
}

#[derive(Debug, Clone)]
pub struct V1TrapInfo<'a> {
    pub enterprise: Oid<'a>,
    pub agent_addr: IpAddr,
    pub generic_trap: i64,
    pub specific_trap: i64,
    pub timestamp: u32,
}

impl<'a> Pdu<'a> {
    pub fn version(&self) -> Result<Version> {
        self.version.try_into()
    }

    fn parse_trap_v1(mut rdr: AsnReader<'a>, version: i64, community: &'a [u8]) -> Result<Pdu<'a>> {
        if version != Version::V1 as i64 {
            return Err(Error::AsnWrongType);
        }
        let oid = rdr.read_asn_objectidentifier()?;
        let addr = IpAddr::V4(Ipv4Addr::from(rdr.read_snmp_ipaddress()?));
        let generic_type = rdr.read_asn_integer()?;
        let specific_code = rdr.read_asn_integer()?;
        let timestamp = rdr.read_snmp_timeticks()?;
        let varbind_bytes = rdr.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);
        Ok(Pdu {
            version,
            community,
            message_type: MessageType::TrapV1,
            req_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds,
            v1_trap_info: Some(V1TrapInfo {
                enterprise: oid,
                agent_addr: addr,
                generic_trap: generic_type,
                specific_trap: specific_code,
                timestamp,
            }),
            #[cfg(any(feature = "v3", feature = "v3_aws_lc_rs"))]
            v3_msg_id: 0,
        })
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Pdu<'a>> {
        Self::from_bytes_inner(
            bytes,
            #[cfg(any(feature = "v3", feature = "v3_aws_lc_rs"))]
            None,
        )
    }

    #[cfg(feature = "v3")]
    pub fn from_bytes_with_security(
        bytes: &'a [u8],
        security: Option<&'a mut v3::Security>,
    ) -> Result<Pdu<'a>> {
        {
            Self::from_bytes_inner(bytes, security)
        }
    }

    #[cfg(feature = "v3_aws_lc_rs")]
    pub fn from_bytes_with_security(
        bytes: &'a [u8],
        security: Option<&'a mut v3_aws_lc_rs::Security>,
    ) -> Result<Pdu<'a>> {
        {
            Self::from_bytes_inner(bytes, security)
        }
    }

    pub(crate) fn from_bytes_inner(
        bytes: &'a [u8],
        #[cfg(feature = "v3")] security: Option<&'a mut v3::Security>,
        #[cfg(feature = "v3_aws_lc_rs")] security: Option<&'a mut v3_aws_lc_rs::Security>,
    ) -> Result<Pdu<'a>> {
        let seq = AsnReader::from_bytes(bytes).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version != Version::V1 as i64
            && version != Version::V2C as i64
            && version != Version::V3 as i64
        {
            return Err(Error::UnsupportedVersion);
        }

        if version == Version::V3 as i64 {
            #[cfg(feature = "v3")]
            {
                if let Some(security) = security {
                    return Self::parse_v3(bytes, rdr, security);
                }
                return Err(Error::AuthFailure(v3::AuthErrorKind::SecurityNotProvided));
            }
            #[cfg(feature = "v3_aws_lc_rs")]
            {
                if let Some(security) = security {
                    return Self::parse_v3_aws_lc_rs(bytes, rdr, security);
                }
                return Err(Error::AuthFailure(
                    v3_aws_lc_rs::AuthErrorKind::SecurityNotProvided,
                ));
            }
            #[cfg(not(any(feature = "v3", feature = "v3_aws_lc_rs")))]
            {
                return Err(Error::UnsupportedVersion);
            }
        }

        let community = rdr.read_asn_octetstring()?;

        let ident = rdr.peek_byte()?;
        let message_type = MessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        if message_type == MessageType::TrapV1 {
            return Self::parse_trap_v1(response_pdu, version, community);
        }

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i64::from(i32::MIN) || req_id > i64::from(i32::MAX) {
            return Err(Error::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i64::from(i32::MAX) {
            return Err(Error::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i64::from(i32::MAX) {
            return Err(Error::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?;
        let varbinds = Varbinds::from_bytes(varbind_bytes);

        Ok(Pdu {
            version,
            community,
            message_type,
            req_id: i32::try_from(req_id)?,
            error_status: u32::try_from(error_status)?,
            error_index: u32::try_from(error_index)?,
            varbinds,
            v1_trap_info: None,
            #[cfg(any(feature = "v3", feature = "v3_aws_lc_rs"))]
            v3_msg_id: 0,
        })
    }
    pub(crate) fn validate(
        &self,
        expected_type: MessageType,
        expected_req_id: i32,
        expected_community: &[u8],
    ) -> Result<()> {
        if self.message_type != expected_type {
            return Err(Error::AsnWrongType);
        }
        if self.req_id != expected_req_id {
            return Err(Error::RequestIdMismatch);
        }
        if self.community != expected_community {
            return Err(Error::CommunityMismatch);
        }
        Ok(())
    }
}
