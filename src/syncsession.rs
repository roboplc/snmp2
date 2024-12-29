use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    num::Wrapping,
    time::Duration,
};

use crate::{
    pdu::{self, Pdu},
    Error, MessageType, Oid, Result, Value, Version, BUFFER_SIZE,
};

/// Synchronous SNMP client
pub struct SyncSession {
    version: Version,
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
            Version::V1,
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
            Version::V2C,
            destination,
            community,
            timeout,
            starting_req_id,
        )
    }

    pub fn new<SA>(
        version: Version,
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
        socket.set_write_timeout(timeout)?;
        socket.connect(destination)?;
        Ok(Self {
            version,
            socket,
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; 4096],
        })
    }

    fn send_and_recv<'a>(
        socket: &UdpSocket,
        pdu: &pdu::Buf,
        out: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        if let Ok(_pdu_len) = socket.send(pdu) {
            match socket.recv(out) {
                Ok(len) => Ok(&out[..len]),
                Err(_) => Err(Error::Receive),
            }
        } else {
            Err(Error::Send)
        }
    }

    pub fn get(&mut self, oid: &Oid) -> Result<Pdu> {
        let req_id = self.req_id.0;
        pdu::build_get(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
        );
        let resp = Pdu::from_bytes(Self::send_and_recv(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf,
        )?)?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn getnext(&mut self, oid: &Oid) -> Result<Pdu> {
        let req_id = self.req_id.0;
        pdu::build_getnext(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
        );
        let resp = Pdu::from_bytes(Self::send_and_recv(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf,
        )?)?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn getbulk(
        &mut self,
        oids: &[&Oid],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Pdu> {
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
        let resp = Pdu::from_bytes(Self::send_and_recv(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf[..],
        )?)?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn set(&mut self, values: &[(&Oid, Value)]) -> Result<Pdu> {
        let req_id = self.req_id.0;
        pdu::build_set(
            self.version,
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
        );
        let resp = Pdu::from_bytes(Self::send_and_recv(
            &self.socket,
            &self.send_pdu,
            &mut self.recv_buf,
        )?)?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }
}
