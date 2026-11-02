use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::Wrapping,
};

use crate::{
    BUFFER_SIZE, Error, MessageType, Oid, Result, Value, Version,
    pdu::{self, Pdu},
};
use tokio::net::{ToSocketAddrs, UdpSocket, lookup_host};

#[cfg(feature = "v3")]
use crate::v3;

/// Asynchronous SNMP client
///
/// Request IDs are reserved before network I/O, so dropping a request future
/// does not cause the next request to reuse its ID. A late reply can still be
/// queued on the socket; the next operation rejects a mismatched ID with
/// [`Error::RequestIdMismatch`] rather than returning data for another request.
/// This client does not automatically skip stale replies or retry operations.
pub struct AsyncSession {
    version: Version,
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    #[cfg(not(feature = "heap_buffers"))]
    recv_buf: [u8; BUFFER_SIZE],
    #[cfg(feature = "heap_buffers")]
    recv_buf: Box<[u8]>,
    #[cfg(feature = "v3")]
    security: Option<v3::Security>,
}

impl AsyncSession {
    pub async fn new_v1<SA>(
        destination: SA,
        community: &[u8],
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(Version::V1, destination, community, starting_req_id).await
    }

    pub async fn new_v2c<SA>(
        destination: SA,
        community: &[u8],
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(Version::V2C, destination, community, starting_req_id).await
    }

    #[cfg(feature = "v3")]
    pub async fn new_v3<SA>(
        destination: SA,
        starting_req_id: i32,
        security: v3::Security,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let mut session = Self::new(Version::V3, destination, &[], starting_req_id).await?;
        session.community.clone_from(&security.username);
        session.security = Some(security);
        Ok(session)
    }

    async fn new<SA>(
        version: Version,
        destination: SA,
        community: &[u8],
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match lookup_host(destination).await?.next() {
            Some(SocketAddr::V4(addr)) => {
                let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
                s.connect(addr).await?;
                s
            }
            Some(SocketAddr::V6(addr)) => {
                let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
                s.connect(addr).await?;
                s
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No address found",
                ));
            }
        };
        Ok(Self {
            version,
            socket,
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            #[cfg(not(feature = "heap_buffers"))]
            #[allow(clippy::large_stack_arrays)]
            recv_buf: [0; BUFFER_SIZE],
            #[cfg(feature = "heap_buffers")]
            recv_buf: vec![0u8; BUFFER_SIZE].into_boxed_slice(),
            #[cfg(feature = "v3")]
            security: None,
        })
    }

    /// Returns the version of the session, e.g. Version::V1.
    /// This is useful for determining whether bulk get is supported.
    pub fn version(&self) -> Version {
        self.version
    }

    #[cfg(not(feature = "v3"))]
    #[allow(clippy::unused_self, clippy::unused_async)]
    pub async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "v3")]
    pub async fn init(&mut self) -> Result<()> {
        if let Some(ref mut security) = self.security {
            security.reset_engine_id();
            security.reset_engine_counters();
            // send a request to get the engine id
            let req_id = self.req_id.0;
            v3::build_init(req_id, &mut self.send_pdu);
            self.req_id += Wrapping(1);
            if let Err(e) = Pdu::from_bytes_inner(
                Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
                Some(security),
            ) && e != Error::AuthUpdated
            {
                return Err(e);
            }
            if security.need_init() {
                return Err(Error::AuthFailure(v3::AuthErrorKind::NotAuthenticated));
            }
        }
        Ok(())
    }

    /// Checks if KeyExtension affects this session privacy and then re-inits session with different KeyExtension
    ///
    /// # Returns
    /// 'Ok(Some(new_key_extension))' When new_key_extension method was set
    /// 'Ok(None)' When security disabled
    /// or Auth type is not AuthPriv
    /// or when Auth-Priv pair is not the one that needs key extension
    /// or when KeyExtension was not set for the session.
    /// 'Err(error)' when 'init()' failed with error returned from 'init()'
    #[cfg(feature = "v3")]
    pub async fn try_another_key_extension_method(&mut self) -> Result<Option<v3::KeyExtension>> {
        if let Some(ref mut security) = self.security
            && let Some(new_method) = security.another_key_extension_method()
        {
            security.authoritative_state = v3::AuthoritativeState::default();
            self.init().await?;
            return Ok(Some(new_method));
        }
        Ok(None)
    }

    #[cfg(not(feature = "v3"))]
    #[allow(clippy::unused_self)]
    fn prepare(&mut self) {}

    #[cfg(feature = "v3")]
    fn prepare(&mut self) {
        if let Some(ref mut security) = self.security {
            security.correct_authoritative_engine_time();
        }
    }

    async fn send_and_recv<'a>(
        socket: &UdpSocket,
        pdu: &pdu::Buf,
        out: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        if let Ok(_pdu_len) = socket.send(pdu).await {
            match socket.recv(out).await {
                Ok(len) => Ok(&out[..len]),
                Err(_) => Err(Error::Receive),
            }
        } else {
            Err(Error::Send)
        }
    }

    pub async fn get(&mut self, oid: &Oid<'_>) -> Result<Pdu<'_>> {
        self.prepare();
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);
        pdu::build_get(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub async fn get_many(&mut self, oids: &[&Oid<'_>]) -> Result<Pdu<'_>> {
        self.prepare();
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);
        pdu::build_get_many(
            self.version,
            self.community.as_slice(),
            req_id,
            oids,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub async fn getnext(&mut self, oid: &Oid<'_>) -> Result<Pdu<'_>> {
        self.prepare();
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);
        pdu::build_getnext(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub async fn getbulk(
        &mut self,
        oids: &[&Oid<'_>],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Pdu<'_>> {
        self.prepare();
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);
        pdu::build_getbulk(
            self.version,
            self.community.as_slice(),
            req_id,
            oids,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub async fn set(&mut self, values: &[(&Oid<'_>, Value<'_>)]) -> Result<Pdu<'_>> {
        self.prepare();
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);
        pdu::build_set(
            self.version,
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf).await?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Get,
        GetMany,
        GetNext,
        GetBulk,
        Set,
    }

    async fn invoke<'a>(
        session: &'a mut AsyncSession,
        op: Operation,
        oid: &Oid<'_>,
    ) -> Result<Pdu<'a>> {
        match op {
            Operation::Get => session.get(oid).await,
            Operation::GetMany => session.get_many(&[oid]).await,
            Operation::GetNext => session.getnext(oid).await,
            Operation::GetBulk => session.getbulk(&[oid], 0, 1).await,
            Operation::Set => session.set(&[(oid, Value::Integer(1))]).await,
        }
    }

    async fn reply(agent: &UdpSocket, expected_id: i32, reply_id: i32, oid: &Oid<'_>) {
        let mut packet = [0; 2048];
        let (n, peer) = agent.recv_from(&mut packet).await.unwrap();
        assert_eq!(Pdu::from_bytes(&packet[..n]).unwrap().req_id, expected_id);
        let mut response = pdu::Buf::default();
        pdu::build(
            Version::V2C,
            b"public",
            crate::snmp::MSG_RESPONSE,
            reply_id,
            &[(oid, Value::Integer(42))],
            0,
            0,
            &mut response,
            #[cfg(feature = "v3")]
            None,
        )
        .unwrap();
        agent.send_to(&response, peer).await.unwrap();
    }

    #[test]
    fn cancellation_consumes_ids_and_rejects_late_replies() {
        // The default buffers are large stack arrays. Allow the nested test futures
        // enough stack without changing the library's buffer feature configuration.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(exercise_cancellation());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn exercise_cancellation() {
        // Bound the entire test, not the timing of individual UDP packets.
        Box::pin(tokio::time::timeout(Duration::from_secs(5), async {
            for op in [Operation::Get, Operation::GetMany, Operation::GetNext,
                Operation::GetBulk, Operation::Set] {
                let agent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut session = AsyncSession::new_v2c(
                    agent.local_addr().unwrap(), b"public", i32::MAX,
                ).await.unwrap();
                let first_oid = Oid::from(&[1,3,6,1,2,1,1,1,0]).unwrap();
                let second_oid = Oid::from(&[1,3,6,1,2,1,1,2,0]).unwrap();
                let mut packet = [0; 2048];
                let mut abandoned = Box::pin(invoke(&mut session, op, &first_oid));
                tokio::select! {
                    result = &mut abandoned => panic!("request completed without a response: {result:?}"),
                    received = agent.recv_from(&mut packet) => {
                        let (n, _) = received.unwrap();
                        assert_eq!(Pdu::from_bytes(&packet[..n]).unwrap().req_id, i32::MAX);
                    }
                }
                // Exactly what dropping a timeout's inner future does.
                drop(abandoned);
                assert_eq!(session.req_id.0, i32::MIN, "{op:?}");

                let (result, ()) = tokio::join!(
                    invoke(&mut session, op, &second_oid),
                    reply(&agent, i32::MIN, i32::MAX, &first_oid),
                );
                assert!(matches!(result, Err(Error::RequestIdMismatch)), "{op:?}");

                // A rejected stale packet also consumes its request ID.
                let (result, ()) = tokio::join!(
                    invoke(&mut session, op, &second_oid),
                    reply(&agent, i32::MIN + 1, i32::MIN + 1, &second_oid),
                );
                let response = result.unwrap();
                assert_eq!(response.req_id, i32::MIN + 1);
            }
        })).await.expect("local UDP regression test timed out");
    }
}
