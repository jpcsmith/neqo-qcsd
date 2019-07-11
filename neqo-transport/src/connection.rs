// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// The class implementing a QUIC connection.

#![allow(dead_code)]
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Debug};
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use neqo_common::{hex, matches, qdebug, qerror, qinfo, qtrace, qwarn, Datagram, Decoder, Encoder};
use neqo_crypto::{
    Agent, AntiReplay, Client, Epoch, HandshakeState, Record, RecordList, SecretAgentInfo, Server,
};

use crate::crypto::{Crypto, CryptoGenerator};
use crate::dump::*;
use crate::events::{ConnectionEvent, ConnectionEvents};
use crate::flow_mgr::{FlowControlGenerator, FlowMgr};
use crate::frame::{
    decode_frame, AckRange, Frame, FrameGenerator, FrameGeneratorToken, FrameType, StreamType,
    TxMode,
};
use crate::packet::{
    decode_packet_hdr, decrypt_packet, encode_packet, ConnectionId, PacketDecoder, PacketHdr,
    PacketNumberDecoder, PacketType,
};
use crate::recovery::{LossRecovery, LossRecoveryMode};
use crate::recv_stream::{RecvStream, RX_STREAM_DATA_WINDOW};
use crate::send_stream::{SendStream, StreamGenerator};
use crate::stats::Stats;
use crate::stream_id::{StreamId, StreamIndex, StreamIndexes};
use crate::tparams::consts as tp_const;
use crate::tparams::{TransportParameters, TransportParametersHandler};
use crate::tracking::{AckGenerator, AckTracker, PNSpace};
use crate::{AppError, ConnectionError, Error, Res};

#[derive(Debug, Default)]
struct Packet(Vec<u8>);

pub const QUIC_VERSION: u32 = 0xff00_0014;
const NUM_EPOCHS: Epoch = 4;
const CID_LENGTH: usize = 8;

pub const LOCAL_STREAM_LIMIT_BIDI: u64 = 16;
pub const LOCAL_STREAM_LIMIT_UNI: u64 = 16;
const LOCAL_MAX_DATA: u64 = 0x3FFF_FFFF_FFFF_FFFE; // 2^62-1

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn peer(self) -> Self {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

impl ::std::fmt::Display for Role {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Init,
    WaitInitial,
    Handshaking,
    Connected,
    Closing {
        error: ConnectionError,
        frame_type: FrameType,
        msg: String,
        timeout: Instant,
    },
    Closed(ConnectionError),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ZeroRttState {
    Init,
    Enabled,
    Sending,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq)]
struct Path {
    local: SocketAddr,
    remote: SocketAddr,
    local_cids: Vec<ConnectionId>,
    remote_cid: ConnectionId,
}

impl Path {
    // Used to create a path when receiving a packet.
    pub fn new(d: &Datagram, peer_cid: ConnectionId) -> Path {
        Path {
            local: d.dst,
            remote: d.src,
            local_cids: Vec::new(),
            remote_cid: peer_cid,
        }
    }

    pub fn received_on(&self, d: &Datagram) -> bool {
        self.local == d.dst && self.remote == d.src
    }
}

pub struct Connection {
    version: crate::packet::Version,
    role: Role,
    state: State,
    tps: Rc<RefCell<TransportParametersHandler>>,
    /// What we are doing with 0-RTT.
    zero_rtt_state: ZeroRttState,
    /// Network paths.  Right now, this tracks at most one path, so it uses `Option`.
    paths: Option<Path>,
    /// The connection IDs that we will accept.
    /// This includes any we advertise in NEW_CONNECTION_ID that haven't been bound to a path yet.
    /// During the handshake at the server, it also includes the randomized DCID pick by the client.
    valid_cids: Vec<ConnectionId>,
    retry_token: Option<Vec<u8>>,
    pub(crate) crypto: Crypto,
    pub(crate) acks: AckTracker,
    // TODO(ekr@rtfm.com): Prioritized generators, rather than a vec
    generators: Vec<Box<FrameGenerator>>,
    idle_timeout: Option<Instant>,
    pub(crate) indexes: StreamIndexes,
    connection_ids: HashMap<u64, (Vec<u8>, [u8; 16])>, // (sequence number, (connection id, reset token))
    pub(crate) send_streams: BTreeMap<StreamId, SendStream>,
    pub(crate) recv_streams: BTreeMap<StreamId, RecvStream>,
    pmtu: usize,
    pub(crate) flow_mgr: Rc<RefCell<FlowMgr>>,
    loss_recovery: LossRecovery,
    events: Rc<RefCell<ConnectionEvents>>,
    token: Option<Vec<u8>>,
    send_vn: Option<(PacketHdr, SocketAddr, SocketAddr)>,
    send_retry: Option<PacketType>, // This will be PacketType::Retry.
    stats: Stats,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:?} Connection: {:?} {:?}",
            self.role, self.state, self.paths
        ))
    }
}

impl Connection {
    pub fn new_client<S: ToString, PA: ToString, PI: IntoIterator<Item = PA>>(
        server_name: S,
        protocols: PI,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Res<Connection> {
        let dcid = ConnectionId::generate(CID_LENGTH);
        let mut c = Connection::new(
            Role::Client,
            Client::new(server_name)?.into(),
            None,
            protocols,
            Some(Path {
                local: local_addr,
                remote: remote_addr,
                local_cids: vec![ConnectionId::generate(CID_LENGTH)],
                remote_cid: dcid.clone(),
            }),
        );
        c.crypto.states[0] = Some(c.crypto.create_initial_state(Role::Client, &dcid));
        Ok(c)
    }

    pub fn new_server<
        CS: ToString,
        CI: IntoIterator<Item = CS>,
        PA: ToString,
        PI: IntoIterator<Item = PA>,
    >(
        certs: CI,
        protocols: PI,
        anti_replay: &AntiReplay,
    ) -> Res<Connection> {
        Ok(Connection::new(
            Role::Server,
            Server::new(certs)?.into(),
            Some(anti_replay),
            protocols,
            None,
        ))
    }

    fn set_tp_defaults(tps: &mut TransportParameters) {
        tps.set_integer(
            tp_const::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            RX_STREAM_DATA_WINDOW,
        );
        tps.set_integer(
            tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            RX_STREAM_DATA_WINDOW,
        );
        tps.set_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI, RX_STREAM_DATA_WINDOW);
        tps.set_integer(tp_const::INITIAL_MAX_STREAMS_BIDI, LOCAL_STREAM_LIMIT_BIDI);
        tps.set_integer(tp_const::INITIAL_MAX_STREAMS_UNI, LOCAL_STREAM_LIMIT_UNI);
        tps.set_integer(tp_const::INITIAL_MAX_DATA, LOCAL_MAX_DATA);
        tps.set_empty(tp_const::DISABLE_MIGRATION);
    }

    fn new<A: ToString, I: IntoIterator<Item = A>>(
        r: Role,
        agent: Agent,
        anti_replay: Option<&AntiReplay>,
        protocols: I,
        paths: Option<Path>,
    ) -> Connection {
        let tphandler = Rc::new(RefCell::new(TransportParametersHandler::default()));
        Connection::set_tp_defaults(&mut tphandler.borrow_mut().local);
        let crypto = Crypto::new(agent, protocols, tphandler.clone(), anti_replay)
            .expect("TLS should be configured successfully");

        Connection {
            version: QUIC_VERSION,
            role: r,
            state: match r {
                Role::Client => State::Init,
                Role::Server => State::WaitInitial,
            },
            paths,
            valid_cids: Vec::new(),
            tps: tphandler,
            zero_rtt_state: ZeroRttState::Init,
            retry_token: None,
            generators: vec![
                Box::new(AckGenerator {}),
                Box::new(CryptoGenerator::default()),
                Box::new(FlowControlGenerator::default()),
                Box::new(StreamGenerator::default()),
            ],
            crypto,
            acks: AckTracker::default(),
            idle_timeout: None,
            indexes: StreamIndexes::new(),
            connection_ids: HashMap::new(),
            send_streams: BTreeMap::new(),
            recv_streams: BTreeMap::new(),
            pmtu: 1280,
            flow_mgr: Rc::new(RefCell::new(FlowMgr::default())),
            loss_recovery: LossRecovery::new(),
            events: Rc::new(RefCell::new(ConnectionEvents::default())),
            token: None,
            send_vn: None,
            send_retry: None,
            stats: Stats::default(),
        }
    }

    /// Set ALPN preferences. Strings that appear earlier in the list are given
    /// higher preference.
    pub fn set_alpn<A: ToString, I: IntoIterator<Item = A>>(&mut self, protocols: I) -> Res<()> {
        self.crypto.tls.set_alpn(protocols)?;
        Ok(())
    }

    /// Access the latest resumption token on the connection.
    pub fn resumption_token(&self) -> Option<Vec<u8>> {
        if self.state != State::Connected {
            return None;
        }
        match self.crypto.tls {
            Agent::Client(ref c) => match c.resumption_token() {
                Some(ref t) => {
                    qtrace!("TLS token {}", hex(&t));
                    let mut enc = Encoder::default();
                    enc.encode_vvec_with(|enc_inner| {
                        self.tps
                            .borrow()
                            .remote
                            .as_ref()
                            .expect("should have transport parameters")
                            .encode(enc_inner);
                    });
                    enc.encode(&t[..]);
                    qinfo!("resumption token {}", hex(&enc[..]));
                    Some(enc.into())
                }
                None => None,
            },
            Agent::Server(_) => None,
        }
    }

    /// Enable resumption, using a token previously provided.
    /// This can only be called once and only on the client.
    /// After calling the function, it should be possible to attempt 0-RTT
    /// if the token supports that.
    pub fn set_resumption_token(&mut self, now: Instant, token: &[u8]) -> Res<()> {
        if self.state != State::Init {
            qerror!([self] "set token in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        qinfo!([self] "resumption token {}", hex(token));
        let mut dec = Decoder::from(token);
        let tp_slice = match dec.decode_vvec() {
            Some(v) => v,
            _ => return Err(Error::InvalidResumptionToken),
        };
        qtrace!([self] "  transport parameters {}", hex(&tp_slice));
        let mut dec_tp = Decoder::from(tp_slice);
        let tp = TransportParameters::decode(&mut dec_tp)?;

        let tok = dec.decode_remainder();
        qtrace!([self] "  TLS token {}", hex(&tok));
        match self.crypto.tls {
            Agent::Client(ref mut c) => c.set_resumption_token(&tok)?,
            Agent::Server(_) => return Err(Error::WrongRole),
        }

        self.tps.borrow_mut().remote_0rtt = Some(tp);
        self.set_initial_limits();
        // Start up TLS, which has the effect of setting up all the necessary
        // state for 0-RTT.  This only stages the CRYPTO frames.
        self.client_start(now)
    }

    pub fn send_ticket(&mut self, now: Instant, extra: &[u8]) -> Res<()> {
        let tps = &self.tps;
        match self.crypto.tls {
            Agent::Server(ref mut s) => {
                let mut enc = Encoder::default();
                enc.encode_vvec_with(|mut enc_inner| {
                    tps.borrow().local.encode(&mut enc_inner);
                });
                enc.encode(extra);
                let records = s.send_ticket(now, &enc)?;
                qinfo!([self] "send session ticket {}", hex(&enc));
                self.buffer_crypto_records(records);
                Ok(())
            }
            Agent::Client(_) => Err(Error::WrongRole),
        }
    }

    /// Get the current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get the state of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Get statistics
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    // This function wraps a call to another function and sets the connection state
    // properly if that call fails.
    fn capture_error<T>(&mut self, now: Instant, frame_type: FrameType, res: Res<T>) -> Res<T> {
        if let Err(v) = &res {
            #[cfg(debug_assertions)]
            let msg = format!("{:?}", v);
            #[cfg(not(debug_assertions))]
            let msg = String::from("");
            self.set_state(State::Closing {
                error: ConnectionError::Transport(v.clone()),
                frame_type,
                msg,
                timeout: self.get_closing_period_time(now),
            });
        }
        res
    }

    /// For use with process().  Errors there can be ignored, but this needs to
    /// ensure that the state is updated.
    fn absorb_error(&mut self, now: Instant, res: Res<()>) {
        let _ = self.capture_error(now, 0, res);
    }

    /// Call in to process activity on the connection. Either new packets have
    /// arrived or a timeout has expired (or both).
    pub fn process_input<I>(&mut self, in_dgrams: I, now: Instant)
    where
        I: IntoIterator<Item = Datagram>,
    {
        for dgram in in_dgrams {
            let res = self.input(dgram, now);
            self.absorb_error(now, res);
        }

        self.cleanup_streams();

        self.check_loss_detection_timeout(now);

        if let Some(idle_timeout) = self.idle_timeout {
            if now >= idle_timeout {
                // Timer expired. Reconnect?
                // TODO(agrover@mozilla.com) reinitialize many members of
                // struct Connection
                self.state = State::Init;
            }
        }

        if self.state == State::Init {
            let res = self.client_start(now);
            self.absorb_error(now, res);
        }
    }

    /// Get the time that we next need to be called back, relative to `now`.
    fn next_delay(&self, now: Instant) -> Option<Duration> {
        let time = match (self.loss_recovery.get_timer(), self.acks.ack_time()) {
            (Some(t_lr), Some(t_ack)) => Some(min(t_lr, t_ack)),
            (Some(t), _) | (_, Some(t)) => Some(t),
            _ => None,
        };

        // TODO(agrover, mt) - need to analyze and fix #47
        // rather than just clamping to zero here.
        time.map(|t| max(now, t).duration_since(now))
    }

    /// Get output packets, as a result of receiving packets, or actions taken
    /// by the application.
    /// Returns datagrams to send, and how long to wait before calling again
    /// even if no incoming packets.
    pub fn process_output(&mut self, now: Instant) -> (Vec<Datagram>, Option<Duration>) {
        match &self.state {
            State::Closing { error, timeout, .. } => {
                if *timeout > now {
                    (self.output(now), None)
                } else {
                    // Close timeout expired, move to Closed
                    let st = State::Closed(error.clone());
                    self.set_state(st);
                    (Vec::new(), None)
                }
            }
            State::Closed(..) => (Vec::new(), None),
            _ => (self.output(now), self.next_delay(now)),
        }
    }

    /// Process input and generate output.
    pub fn process<I>(&mut self, in_dgrams: I, now: Instant) -> (Vec<Datagram>, Option<Duration>)
    where
        I: IntoIterator<Item = Datagram>,
    {
        self.process_input(in_dgrams, now);
        self.process_output(now)
    }

    fn is_valid_cid(&self, cid: &ConnectionId) -> bool {
        self.valid_cids.contains(cid) || self.paths.iter().any(|p| p.local_cids.contains(cid))
    }

    fn input(&mut self, d: Datagram, now: Instant) -> Res<()> {
        let mut slc = &d[..];

        qinfo!([self] "input {}", hex( &**d));

        // Handle each packet in the datagram
        while !slc.is_empty() {
            let mut hdr = match decode_packet_hdr(self, slc) {
                Ok(h) => h,
                _ => {
                    qinfo!([self] "Received indecipherable packet header {}", hex(slc));
                    return Ok(()); // Drop the remainder of the datagram.
                }
            };
            self.stats.packets_rx += 1;
            match (&hdr.tipe, &self.state, &self.role) {
                (PacketType::VN(_), State::WaitInitial, Role::Client) => {
                    self.set_state(State::Closed(ConnectionError::Transport(
                        Error::VersionNegotiation,
                    )));
                    return Err(Error::VersionNegotiation);
                }
                (PacketType::Retry { odcid, token }, State::WaitInitial, Role::Client) => {
                    if self.retry_token.is_some() {
                        qwarn!("received another Retry, dropping it");
                        return Ok(());
                    }
                    if token.is_empty() {
                        qwarn!("received Retry, but no token, dropping it");
                        return Ok(());
                    }
                    match self.paths.iter_mut().find(|p| p.remote_cid == *odcid) {
                        None => {
                            qwarn!("received Retry, but not for us, dropping it");
                            return Ok(());
                        }
                        Some(path) => {
                            path.remote_cid = hdr.scid.expect("Retry pkt must have SCID");
                        }
                    }
                    self.retry_token = Some(token.clone());
                    return Ok(());
                }
                (PacketType::VN(_), ..) | (PacketType::Retry { .. }, ..) => {
                    qwarn!("dropping {:?}", hdr.tipe);
                    return Ok(());
                }
                _ => {}
            };

            if let Some(version) = hdr.version {
                if version != self.version {
                    qwarn!(
                        "hdr version {:?} and self.version {} disagree",
                        hdr.version,
                        self.version,
                    );
                    qwarn!([self] "Sending VN on next output");
                    self.send_vn = Some((hdr, d.src, d.dst));
                    return Ok(());
                }
            }

            match self.state {
                State::Init => {
                    qinfo!([self] "Received message while in Init state");
                    return Ok(());
                }
                State::WaitInitial => {
                    qinfo!([self] "Received packet in WaitInitial");
                    if self.role == Role::Server {
                        if hdr.dcid.len() < 8 {
                            qwarn!([self] "Peer DCID is too short");
                            return Ok(());
                        }
                        self.crypto.states[0] =
                            Some(self.crypto.create_initial_state(self.role, &hdr.dcid));
                    }
                }
                State::Handshaking | State::Connected => {
                    if !self.is_valid_cid(&hdr.dcid) {
                        qinfo!([self] "Ignoring packet with CID {:?}", hdr.dcid);
                        return Ok(());
                    }
                }
                State::Closing { .. } => {
                    // Don't bother processing the packet. Instead ask to get a
                    // new close frame.
                    self.flow_mgr.borrow_mut().set_need_close_frame(true);
                    return Ok(());
                }
                State::Closed(..) => {
                    // Do nothing.
                    return Ok(());
                }
            }

            qdebug!([self] "Received unverified packet {:?}", hdr);

            // Decryption failure, or not having keys is not fatal.
            // If the state isn't available, or we can't decrypt the packet, drop
            // the rest of the datagram on the floor, but don't generate an error.
            let largest_acknowledged = self
                .loss_recovery
                .largest_acknowledged(PNSpace::from(hdr.epoch));
            let res = match self.crypto.obtain_crypto_state(self.role, hdr.epoch) {
                Ok(cs) => match cs.rx.as_ref() {
                    Some(rx) => {
                        let pn_decoder = PacketNumberDecoder::new(largest_acknowledged);
                        decrypt_packet(rx, pn_decoder, &mut hdr, slc)
                    }
                    _ => Err(Error::KeysNotFound),
                },
                Err(e) => Err(e),
            };
            slc = &slc[hdr.hdr_len + hdr.body_len()..];
            let body = match res {
                Ok(b) => b,
                _ => {
                    // TODO(mt): Check for stateless reset, which is fatal.
                    continue;
                }
            };
            dump_packet(self, "rx", &hdr, &body);

            // TODO(ekr@rtfm.com): Have the server blow away the initial
            // crypto state if this fails? Otherwise, we will get a panic
            // on the assert for doesn't exist.
            // OK, we have a valid packet.

            // TODO(ekr@rtfm.com): Filter for valid for this epoch.

            let ack_eliciting = self.input_packet(hdr.epoch, Decoder::from(&body[..]), now)?;
            let space = PNSpace::from(hdr.epoch);
            if self.acks[space].is_duplicate(hdr.pn) {
                qdebug!([self] "Received duplicate packet epoch={} pn={}", hdr.epoch, hdr.pn);
                self.stats.dups_rx += 1;
                continue;
            }
            self.acks[space].set_received(now, hdr.pn, ack_eliciting);

            if matches!(self.state, State::WaitInitial) {
                if self.role == Role::Server {
                    assert!(matches!(hdr.tipe, PacketType::Initial(..)));
                    // A server needs to accept the client's selected CID during the handshake.
                    self.valid_cids.push(hdr.dcid.clone());
                    // Install a path.
                    assert!(self.paths.is_none());
                    let mut p = Path::new(&d, hdr.scid.unwrap());
                    p.local_cids.push(ConnectionId::generate(CID_LENGTH));
                    self.paths = Some(p);

                    // SecretAgentPreinfo::early_data() always returns false for a server,
                    // but a non-zero maximum tells us if we are accepting 0-RTT.
                    self.zero_rtt_state = if self.crypto.tls.preinfo()?.max_early_data() > 0 {
                        ZeroRttState::Accepted
                    } else {
                        ZeroRttState::Rejected
                    };
                } else {
                    let p = self
                        .paths
                        .iter_mut()
                        .find(|p| p.received_on(&d))
                        .expect("should have a path for sending Initial");
                    // Start using the server's CID.
                    p.remote_cid = hdr.scid.unwrap();
                }
                self.set_state(State::Handshaking);
            }

            if !self.paths.iter().any(|p| p.received_on(&d)) {
                // Right now, we don't support any form of migration.
                // So generate an error if a packet is received on a new path.
                return Err(Error::InvalidMigration);
            }
        }

        Ok(())
    }

    // Return whether the packet had ack-eliciting frames.
    fn input_packet(&mut self, epoch: Epoch, mut d: Decoder, now: Instant) -> Res<(bool)> {
        let mut ack_eliciting = false;

        // Handle each frame in the packet
        while d.remaining() > 0 {
            let f = decode_frame(&mut d)?;
            ack_eliciting |= f.ack_eliciting();
            let t = f.get_type();
            let res = self.input_frame(epoch, f, now);
            self.capture_error(now, t, res)?;
        }

        Ok(ack_eliciting)
    }

    fn output_vn(
        &mut self,
        recvd_hdr: PacketHdr,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Datagram {
        qinfo!("Sending VN Packet instead of normal output");
        let hdr = PacketHdr::new(
            0,
            // Actual version we support and a greased value.
            PacketType::VN(vec![QUIC_VERSION, 0x4a4a_4a4a]),
            Some(0),
            recvd_hdr.scid.unwrap().clone(),
            Some(recvd_hdr.dcid.clone()),
            0, // unused
            0, // unused
        );

        // Do not save any state when generating VN pkt, so cs is not
        // retained.
        let cs = self.crypto.create_initial_state(self.role, &recvd_hdr.dcid);
        let packet = encode_packet(cs.tx.as_ref().unwrap(), &hdr, &[]);
        self.stats.packets_tx += 1;
        Datagram::new(local, remote, packet)
    }

    fn output(&mut self, now: Instant) -> Vec<Datagram> {
        if let Some((vn_hdr, remote, local)) = self.send_vn.take() {
            return vec![self.output_vn(vn_hdr, remote, local)];
        }

        // Can't call a method on self while iterating over self.paths
        let paths = mem::replace(&mut self.paths, None);
        let mut out_dgrams = Vec::new();
        let mut errors = Vec::new();
        for p in &paths {
            match self.output_path(&p, now) {
                Ok(ref mut dgrams) => out_dgrams.append(dgrams),
                Err(e) => errors.push(e),
            };
        }
        self.paths = paths;

        let closing = match self.state {
            State::Closing { .. } => true,
            _ => false,
        };
        if !closing && !errors.is_empty() {
            self.absorb_error(now, Err(errors.pop().unwrap()));
            // We just closed, so run this again to produce CONNECTION_CLOSE.
            self.output(now)
        } else {
            out_dgrams // TODO(ekr@rtfm.com): When to call back next.
        }
    }

    // Iterate through all the generators, inserting as many frames as will
    // fit.
    fn output_path(&mut self, path: &Path, now: Instant) -> Res<Vec<Datagram>> {
        let mut out_packets = Vec::new();

        let mut initial_only = false;

        // Frames for different epochs must go in different packets, but then these
        // packets can go in a single datagram
        for epoch in 0..NUM_EPOCHS {
            let space = PNSpace::from(epoch);
            let mut encoder = Encoder::default();
            let mut ds = Vec::new();
            let mut tokens = Vec::new();

            // Try to make our own crypo state and if we can't, skip this epoch.
            {
                let cs = match self.crypto.obtain_crypto_state(self.role, epoch) {
                    Ok(c) => c,
                    _ => continue,
                };
                if cs.tx.is_none() {
                    continue;
                }
            }

            let mut ack_eliciting = false;
            let mut is_crypto_packet = false;
            // Copy generators out so that we can iterate over it and pass
            // self to the functions.
            let mut generators = mem::replace(&mut self.generators, Vec::new());
            for generator in &mut generators {
                // TODO(ekr@rtfm.com): Fix TxMode
                while let Some((frame, token)) =
                    generator.generate(self, now, epoch, TxMode::Normal, self.pmtu - encoder.len())
                {
                    ack_eliciting = ack_eliciting || frame.ack_eliciting();
                    is_crypto_packet = match frame {
                        Frame::Crypto { .. } => true,
                        _ => is_crypto_packet,
                    };
                    frame.marshal(&mut encoder);
                    if let Some(t) = token {
                        tokens.push(t);
                    }
                    assert!(encoder.len() <= self.pmtu);
                    if encoder.len() == self.pmtu {
                        // Filled this packet, get another one.
                        ds.push((encoder, ack_eliciting, is_crypto_packet, tokens));
                        encoder = Encoder::default();
                        tokens = Vec::new();
                        ack_eliciting = false;
                        is_crypto_packet = false;
                    }
                }
            }
            self.generators = generators;

            if encoder.len() > 0 {
                ds.push((encoder, ack_eliciting, is_crypto_packet, tokens))
            }

            for (encoded, ack_eliciting, is_crypto, tokens) in ds {
                qdebug!([self] "Need to send a packet");

                initial_only = epoch == 0;
                let hdr = PacketHdr::new(
                    0,
                    match epoch {
                        0 => {
                            let token = match &self.retry_token {
                                Some(v) => v.clone(),
                                _ => Vec::new(),
                            };
                            PacketType::Initial(token)
                        }
                        1 => {
                            assert!(self.zero_rtt_state != ZeroRttState::Rejected);
                            self.zero_rtt_state = ZeroRttState::Sending;
                            PacketType::ZeroRTT
                        }
                        2 => PacketType::Handshake,
                        3 => PacketType::Short,
                        _ => unimplemented!(), // TODO(ekr@rtfm.com): Key Update.
                    },
                    Some(self.version),
                    path.remote_cid.clone(),
                    path.local_cids.first().cloned(),
                    self.loss_recovery.next_pn(space),
                    epoch,
                );
                self.stats.packets_tx += 1;
                self.loss_recovery.on_packet_sent(
                    space,
                    hdr.pn,
                    ack_eliciting,
                    is_crypto,
                    tokens,
                    now,
                );

                // Failure to have the state here is an internal error.
                let cs = self
                    .crypto
                    .obtain_crypto_state(self.role, hdr.epoch)
                    .unwrap();
                let packet = encode_packet(cs.tx.as_ref().unwrap(), &hdr, &encoded);
                dump_packet(self, "tx", &hdr, &encoded);
                out_packets.push(packet);
            }
        }

        // Put packets in UDP datagrams
        let mut out_dgrams = out_packets
            .into_iter()
            .inspect(|p| qdebug!([self] "packet {}", hex(p)))
            .fold(Vec::new(), |mut vec: Vec<Datagram>, packet| {
                let new_dgram: bool = vec
                    .last()
                    .map(|dgram| dgram.len() + packet.len() > self.pmtu)
                    .unwrap_or(true);
                if new_dgram {
                    vec.push(Datagram::new(path.local, path.remote, packet));
                } else {
                    vec.last_mut().unwrap().d.extend(packet);
                }
                vec
            });

        // Pad Initial packets sent by the client to 1200 bytes.
        if self.role == Role::Client && initial_only && !out_dgrams.is_empty() {
            qdebug!([self] "pad Initial to 1200");
            out_dgrams.last_mut().unwrap().resize(1200, 0);
        }

        out_dgrams
            .iter()
            .for_each(|dgram| qdebug!([self] "Datagram length: {}", dgram.len()));

        Ok(out_dgrams)
    }

    fn client_start(&mut self, now: Instant) -> Res<()> {
        qinfo!([self] "client_start");
        self.handshake(now, 0, None)?;
        self.set_state(State::WaitInitial);
        if self.crypto.tls.preinfo()?.early_data() {
            qdebug!([self] "Enabling 0-RTT");
            self.zero_rtt_state = ZeroRttState::Enabled;
        }
        Ok(())
    }

    fn get_closing_period_time(&self, now: Instant) -> Instant {
        // Spec says close time should be at least PTO times 3.
        now + (self.loss_recovery.pto() * 3)
    }

    /// Close the connection.
    pub fn close<S: Into<String>>(&mut self, now: Instant, error: AppError, msg: S) {
        self.set_state(State::Closing {
            error: ConnectionError::Application(error),
            frame_type: 0,
            msg: msg.into(),
            timeout: self.get_closing_period_time(now),
        });
    }

    /// Buffer crypto records for sending.
    fn buffer_crypto_records(&mut self, records: RecordList) {
        for r in records {
            assert_eq!(r.ct, 22);
            qdebug!([self] "Adding CRYPTO data {:?}", r);
            self.crypto.streams[r.epoch as usize].tx.send(&r.data);
        }
    }

    fn set_initial_limits(&mut self) {
        let swapped = mem::replace(&mut self.tps, Rc::default());
        {
            let tph = swapped.borrow();
            let tps = tph.remote();
            self.indexes.peer_max_stream_bidi =
                StreamIndex::new(tps.get_integer(tp_const::INITIAL_MAX_STREAMS_BIDI));
            self.indexes.peer_max_stream_uni =
                StreamIndex::new(tps.get_integer(tp_const::INITIAL_MAX_STREAMS_UNI));
            self.flow_mgr
                .borrow_mut()
                .conn_increase_max_credit(tps.get_integer(tp_const::INITIAL_MAX_DATA));
        }
        mem::replace(&mut self.tps, swapped);
    }

    fn handshake(&mut self, now: Instant, epoch: u16, data: Option<&[u8]>) -> Res<()> {
        qdebug!("Handshake epoch={} data={:0x?}", epoch, data);
        let mut rec: Option<Record> = None;

        if let Some(d) = data {
            qdebug!([self] "Handshake received {:0x?} ", d);
            rec = Some(Record {
                ct: 22, // TODO(ekr@rtfm.com): Symbolic constants for CT. This is handshake.
                epoch,
                data: d.to_vec(),
            });
        }

        let mut m = self.crypto.tls.handshake_raw(now, rec);

        if matches!(m, Ok(_)) && *self.crypto.tls.state() == HandshakeState::AuthenticationPending {
            // TODO(ekr@rtfm.com): IMPORTANT: This overrides
            // authentication and so is fantastically dangerous.
            // Fix before shipping.
            qwarn!([self] "marking connection as authenticated without checking");
            self.crypto.tls.authenticated();
            m = self.crypto.tls.handshake_raw(now, None);
        }
        match m {
            Err(e) => {
                qwarn!([self] "Handshake failed");
                return Err(match self.crypto.tls.alert() {
                    Some(a) => Error::CryptoAlert(*a),
                    _ => Error::CryptoError(e),
                });
            }
            Ok(msgs) => self.buffer_crypto_records(msgs),
        }
        if self.crypto.tls.state().connected() {
            qinfo!([self] "TLS handshake completed");

            if self.crypto.tls.info().map(SecretAgentInfo::alpn).is_none() {
                // 120 = no_application_protocol
                let err = Error::CryptoAlert(120);
                return Err(err);
            }

            self.set_state(State::Connected);
            self.set_initial_limits();
        }
        Ok(())
    }

    fn input_frame(&mut self, epoch: Epoch, frame: Frame, now: Instant) -> Res<()> {
        match frame {
            Frame::Padding => {
                // Ignore
            }
            Frame::Ping => {
                // Ack elicited with no further handling needed
            }
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
            } => {
                self.handle_ack(
                    epoch,
                    largest_acknowledged,
                    ack_delay,
                    first_ack_range,
                    ack_ranges,
                    now,
                )?;
            }
            Frame::ResetStream {
                stream_id,
                application_error_code,
                ..
            } => {
                // TODO(agrover@mozilla.com): use final_size for connection MaxData calc
                if let (_, Some(rs)) = self.obtain_stream(stream_id.into())? {
                    rs.reset(application_error_code);
                }
            }
            Frame::StopSending {
                stream_id,
                application_error_code,
            } => {
                self.events
                    .borrow_mut()
                    .send_stream_stop_sending(stream_id.into(), application_error_code);
                if let (Some(ss), _) = self.obtain_stream(stream_id.into())? {
                    ss.reset(application_error_code);
                }
            }
            Frame::Crypto { offset, data } => {
                qdebug!(
                    [self]
                    "Crypto frame on epoch={} offset={}, data={:0x?}",
                    epoch,
                    offset,
                    &data
                );
                let rx = &mut self.crypto.streams[epoch as usize].rx;
                rx.inbound_frame(offset, data)?;
                if rx.data_ready() {
                    let mut buf = Vec::new();
                    let read = rx.read_to_end(&mut buf)?;
                    qdebug!("Read {} bytes", read);
                    self.handshake(now, epoch, Some(&buf))?;
                }
            }
            Frame::NewToken { token } => self.token = Some(token),
            Frame::Stream {
                fin,
                stream_id,
                offset,
                data,
            } => {
                if let (_, Some(rs)) = self.obtain_stream(stream_id.into())? {
                    rs.inbound_stream_frame(fin, offset, data)?;
                }
            }
            Frame::MaxData { maximum_data } => self
                .flow_mgr
                .borrow_mut()
                .conn_increase_max_credit(maximum_data),
            Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                if let (Some(ss), _) = self.obtain_stream(stream_id.into())? {
                    ss.set_max_stream_data(maximum_stream_data);
                }
            }
            Frame::MaxStreams {
                stream_type,
                maximum_streams,
            } => {
                let peer_max = match stream_type {
                    StreamType::BiDi => &mut self.indexes.peer_max_stream_bidi,
                    StreamType::UniDi => &mut self.indexes.peer_max_stream_uni,
                };

                if maximum_streams > *peer_max {
                    *peer_max = maximum_streams;
                    self.events.borrow_mut().send_stream_creatable(stream_type);
                }
            }
            Frame::DataBlocked { data_limit } => {
                // Should never happen since we set data limit to 2^62-1
                qwarn!([self] "Received DataBlocked with data limit {}", data_limit);
            }
            Frame::StreamDataBlocked { stream_id, .. } => {
                // TODO(agrover@mozilla.com): how should we be using
                // currently-unused stream_data_limit?

                let stream_id: StreamId = stream_id.into();

                // Terminate connection with STREAM_STATE_ERROR if send-only
                // stream (-transport 19.13)
                if stream_id.is_send_only(self.role()) {
                    return Err(Error::StreamStateError);
                }

                if let (_, Some(rs)) = self.obtain_stream(stream_id)? {
                    rs.maybe_send_flowc_update();
                }
            }
            Frame::StreamsBlocked { stream_type, .. } => {
                let local_max = match stream_type {
                    StreamType::BiDi => &mut self.indexes.local_max_stream_bidi,
                    StreamType::UniDi => &mut self.indexes.local_max_stream_uni,
                };

                self.flow_mgr
                    .borrow_mut()
                    .max_streams(*local_max, stream_type)
            }
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
            } => {
                self.connection_ids
                    .insert(sequence_number, (connection_id, stateless_reset_token));
            }
            Frame::RetireConnectionId { sequence_number } => {
                self.connection_ids.remove(&sequence_number);
            }
            Frame::PathChallenge { data } => self.flow_mgr.borrow_mut().path_response(data),
            Frame::PathResponse { .. } => {
                // Should never see this, we don't support migration atm and
                // do not send path challenges
                qwarn!([self] "Received Path Response");
            }
            Frame::ConnectionClose {
                close_type,
                error_code,
                frame_type,
                reason_phrase,
            } => {
                let reason_phrase = String::from_utf8_lossy(&reason_phrase);
                qinfo!([self]
                       "ConnectionClose received. Closing. Close type: {:?} Error code: {} frame type {:x} reason {}",
                       close_type,
                       error_code,
                       frame_type,
                       reason_phrase);
                self.events.borrow_mut().connection_closed(
                    close_type,
                    error_code,
                    frame_type,
                    &reason_phrase,
                );
                self.set_state(State::Closed(ConnectionError::Application(error_code)));
            }
        };

        Ok(())
    }

    fn handle_ack(
        &mut self,
        epoch: Epoch,
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
        now: Instant,
    ) -> Res<()> {
        qinfo!(
            [self]
            "Rx ACK epoch={}, largest_acked={}, first_ack_range={}, ranges={:?}",
            epoch,
            largest_acknowledged,
            first_ack_range,
            ack_ranges
        );

        let acked_ranges =
            Frame::decode_ack_frame(largest_acknowledged, first_ack_range, ack_ranges)?;
        let (mut acked_packets, mut lost_packets) = self.loss_recovery.on_ack_received(
            PNSpace::from(epoch),
            largest_acknowledged,
            acked_ranges,
            Duration::from_millis(ack_delay),
            now,
        );
        for acked in &mut acked_packets {
            acked.mark_acked(self);
        }
        for lost in &mut lost_packets {
            lost.mark_lost(self);
        }

        Ok(())
    }

    /// When the server rejects 0-RTT we need to drop a bunch of stuff.
    fn client_0rtt_rejected(&mut self) {
        if self.zero_rtt_state != ZeroRttState::Sending {
            return;
        }

        // Tell 0-RTT packets that they were "lost".
        // TODO(mt) remove these from "bytes in flight" when we
        // have a congestion controller.
        for mut dropped in self.loss_recovery.drop_0rtt() {
            dropped.mark_lost(self);
        }
        self.send_streams.clear();
        self.recv_streams.clear();
        self.events.borrow_mut().client_0rtt_rejected();
    }

    fn set_state(&mut self, state: State) {
        if state != self.state {
            qinfo!([self] "State change from {:?} -> {:?}", self.state, state);
            self.state = state;
            match &self.state {
                State::Connected => {
                    if self.role == Role::Server {
                        // Remove the randomized client CID from the list of acceptable CIDs.
                        assert_eq!(1, self.valid_cids.len());
                        self.valid_cids.clear();
                    } else {
                        self.zero_rtt_state =
                            if self.crypto.tls.info().unwrap().early_data_accepted() {
                                ZeroRttState::Accepted
                            } else {
                                self.client_0rtt_rejected();
                                ZeroRttState::Rejected
                            }
                    }
                }
                State::Closing { .. } => {
                    self.send_streams.clear();
                    self.recv_streams.clear();
                    self.generators.clear();
                    self.generators.push(Box::new(CloseGenerator {}));
                    self.flow_mgr.borrow_mut().set_need_close_frame(true);
                }
                State::Closed(..) => {
                    // Equivalent to spec's "draining" state -- never send anything.
                    self.send_streams.clear();
                    self.recv_streams.clear();
                    self.generators.clear();
                }
                _ => {}
            }
        }
    }

    fn cleanup_streams(&mut self) {
        let recv_to_remove = self
            .recv_streams
            .iter()
            .filter(|(_, stream)| stream.is_terminal())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        let mut removed_bidi = 0;
        let mut removed_uni = 0;
        for id in &recv_to_remove {
            self.recv_streams.remove(&id);
            if id.is_peer_initiated(self.role()) {
                if id.is_bidi() {
                    removed_bidi += 1;
                } else {
                    removed_uni += 1;
                }
            }
        }

        // Send max_streams updates if we removed peer-initiated recv streams.
        if removed_bidi > 0 {
            self.indexes.local_max_stream_bidi += removed_bidi;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.indexes.local_max_stream_bidi, StreamType::BiDi)
        }
        if removed_uni > 0 {
            self.indexes.local_max_stream_uni += removed_uni;
            self.flow_mgr
                .borrow_mut()
                .max_streams(self.indexes.local_max_stream_uni, StreamType::UniDi)
        }

        let send_to_remove = self
            .send_streams
            .iter()
            .filter(|(_, stream)| stream.is_terminal())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();

        for id in send_to_remove {
            self.send_streams.remove(&id);
        }
    }

    /// Get or make a stream, and implicitly open additional streams as
    /// indicated by its stream id.
    fn obtain_stream(
        &mut self,
        stream_id: StreamId,
    ) -> Res<(Option<&mut SendStream>, Option<&mut RecvStream>)> {
        match (&self.state, self.zero_rtt_state) {
            (State::Connected, _) | (State::Handshaking, ZeroRttState::Accepted) => (),
            _ => return Err(Error::ConnectionState),
        }

        // May require creating new stream(s)
        if stream_id.is_peer_initiated(self.role()) {
            let next_stream_idx = if stream_id.is_bidi() {
                &mut self.indexes.local_next_stream_bidi
            } else {
                &mut self.indexes.local_next_stream_uni
            };
            let stream_idx: StreamIndex = stream_id.into();

            if stream_idx >= *next_stream_idx {
                let recv_initial_max_stream_data = if stream_id.is_bidi() {
                    if stream_idx > self.indexes.local_max_stream_bidi {
                        qwarn!([self] "peer bidi stream create blocked, next={:?} max={:?}",
                               stream_idx,
                               self.indexes.local_max_stream_bidi);
                        return Err(Error::StreamLimitError);
                    }
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
                } else {
                    if stream_idx > self.indexes.local_max_stream_uni {
                        qwarn!([self] "peer uni stream create blocked, next={:?} max={:?}",
                               stream_idx,
                               self.indexes.local_max_stream_uni);
                        return Err(Error::StreamLimitError);
                    }
                    self.tps
                        .borrow()
                        .local
                        .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI)
                };

                loop {
                    let next_stream_id =
                        next_stream_idx.to_stream_id(stream_id.stream_type(), stream_id.role());
                    self.recv_streams.insert(
                        next_stream_id,
                        RecvStream::new(
                            next_stream_id,
                            recv_initial_max_stream_data,
                            self.flow_mgr.clone(),
                            self.events.clone(),
                        ),
                    );

                    if next_stream_id.is_uni() {
                        self.events
                            .borrow_mut()
                            .new_stream(next_stream_id, StreamType::UniDi);
                    } else {
                        let send_initial_max_stream_data = self
                            .tps
                            .borrow()
                            .remote()
                            .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
                        self.send_streams.insert(
                            next_stream_id,
                            SendStream::new(
                                next_stream_id,
                                send_initial_max_stream_data,
                                self.flow_mgr.clone(),
                                self.events.clone(),
                            ),
                        );
                        self.events
                            .borrow_mut()
                            .new_stream(next_stream_id, StreamType::BiDi);
                    }

                    *next_stream_idx += 1;
                    if *next_stream_idx > stream_idx {
                        break;
                    }
                }
            }
        }

        Ok((
            self.send_streams.get_mut(&stream_id),
            self.recv_streams.get_mut(&stream_id),
        ))
    }

    /// Create a stream.
    // Returns new stream id
    pub fn stream_create(&mut self, st: StreamType) -> Res<u64> {
        // Can't make streams while closing, otherwise rely on the stream limits.
        match self.state {
            State::Closing { .. } | State::Closed { .. } => return Err(Error::ConnectionState),
            State::WaitInitial | State::Handshaking => {
                if matches!(
                    self.zero_rtt_state,
                    ZeroRttState::Init | ZeroRttState::Rejected
                ) {
                    return Err(Error::ConnectionState);
                }
            }
            _ => (),
        }
        if self.tps.borrow().remote.is_none() && self.tps.borrow().remote_0rtt.is_none() {
            return Err(Error::ConnectionState);
        }

        Ok(match st {
            StreamType::UniDi => {
                if self.indexes.peer_next_stream_uni >= self.indexes.peer_max_stream_uni {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.indexes.peer_max_stream_uni, StreamType::UniDi);
                    qwarn!([self] "local uni stream create blocked, next={:?} max={:?}",
                           self.indexes.peer_next_stream_uni,
                           self.indexes.peer_max_stream_uni);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .indexes
                    .peer_next_stream_uni
                    .to_stream_id(StreamType::UniDi, self.role);
                self.indexes.peer_next_stream_uni += 1;
                let initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote()
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_UNI);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );
                new_id.as_u64()
            }
            StreamType::BiDi => {
                if self.indexes.peer_next_stream_bidi >= self.indexes.peer_max_stream_bidi {
                    self.flow_mgr
                        .borrow_mut()
                        .streams_blocked(self.indexes.peer_max_stream_bidi, StreamType::BiDi);
                    qwarn!([self] "local bidi stream create blocked, next={:?} max={:?}",
                           self.indexes.peer_next_stream_bidi,
                           self.indexes.peer_max_stream_bidi);
                    return Err(Error::StreamLimitError);
                }
                let new_id = self
                    .indexes
                    .peer_next_stream_bidi
                    .to_stream_id(StreamType::BiDi, self.role);
                self.indexes.peer_next_stream_bidi += 1;
                let send_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .remote()
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);

                self.send_streams.insert(
                    new_id,
                    SendStream::new(
                        new_id,
                        send_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );

                let recv_initial_max_stream_data = self
                    .tps
                    .borrow()
                    .local
                    .get_integer(tp_const::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);

                self.recv_streams.insert(
                    new_id,
                    RecvStream::new(
                        new_id,
                        recv_initial_max_stream_data,
                        self.flow_mgr.clone(),
                        self.events.clone(),
                    ),
                );
                new_id.as_u64()
            }
        })
    }

    /// Send data on a stream.
    /// Returns how many bytes were successfully sent. Could be less
    /// than total, based on receiver credit space available, etc.
    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Res<usize> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.send(data)
    }

    /// Bytes that stream_send() is guaranteed to accept for sending.
    /// i.e. that will not be blocked by flow credits or send buffer max
    /// capacity.
    pub fn stream_avail_send_space(&self, stream_id: u64) -> Res<u64> {
        let stream = self
            .send_streams
            .get(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        Ok(min(
            stream.avail(),
            self.flow_mgr.borrow().conn_credit_avail(),
        ))
    }

    /// Close the stream. Enqueued data will be sent.
    pub fn stream_close_send(&mut self, stream_id: u64) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.close();
        Ok(())
    }

    /// Abandon transmission of in-flight and future stream data.
    pub fn stream_reset_send(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        let stream = self
            .send_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.reset(err);
        Ok(())
    }

    /// Read buffered data from stream. bool says whether read bytes includes
    /// the final data on stream.
    pub fn stream_recv(&mut self, stream_id: u64, data: &mut [u8]) -> Res<(usize, bool)> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        let rb = stream.read(data)?;
        Ok((rb.0 as usize, rb.1))
    }

    /// Application is no longer interested in this stream.
    pub fn stream_stop_sending(&mut self, stream_id: u64, err: AppError) -> Res<()> {
        let stream = self
            .recv_streams
            .get_mut(&stream_id.into())
            .ok_or_else(|| Error::InvalidStreamId)?;

        stream.stop_sending(err);
        Ok(())
    }

    /// Get events that indicate state changes on the connection.
    pub fn events(&mut self) -> Vec<ConnectionEvent> {
        // Turn it into a vec for simplicity's sake
        self.events.borrow_mut().events().into_iter().collect()
    }

    fn check_loss_detection_timeout(&mut self, now: Instant) {
        qdebug!([self] "check_loss_timeouts");

        match self.loss_recovery.check_loss_timer(now) {
            LossRecoveryMode::None => {}
            LossRecoveryMode::LostPackets(mut packets) => {
                qinfo!([self] "lost packets: {}", packets.len());
                for lost in packets.iter_mut() {
                    lost.mark_lost(self);
                }
            }
            LossRecoveryMode::CryptoTimerExpired => {
                qinfo!(
                    [self]
                    "check_loss_detection_timeout - retransmit_unacked_crypto"
                );
                // TODO
                // if (has unacknowledged crypto data):
                //   RetransmitUnackedCryptoData()
                // else if (endpoint is client without 1-RTT keys):
                //   // Client sends an anti-deadlock packet: Initial is padded
                //   // to earn more anti-amplification credit,
                //   // a Handshake packet proves address ownership.
                //   if (has Handshake keys):
                //      SendOneHandshakePacket()
                //    else:
                //      SendOnePaddedInitialPacket()
            }
            LossRecoveryMode::PTO => {
                qinfo!(
                    [self]
                    "check_loss_detection_timeout -send_one_or_two_packets"
                );
                // TODO
                // SendOneOrTwoPackets()
            }
        }
    }
}

impl ::std::fmt::Display for Connection {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?} {:p}", self.role, self as *const Connection)
    }
}

impl PacketDecoder for Connection {
    fn get_cid_len(&self) -> usize {
        CID_LENGTH
    }
}

struct CloseGenerator {}

impl FrameGenerator for CloseGenerator {
    fn generate(
        &mut self,
        c: &mut Connection,
        _now: Instant,
        epoch: Epoch,
        _mode: TxMode,
        _remaining: usize,
    ) -> Option<(Frame, Option<Box<FrameGeneratorToken>>)> {
        if epoch != 3 {
            return None;
        }

        if let State::Closing {
            error: cerr,
            frame_type,
            msg: reason,
            ..
        } = c.state()
        {
            if c.flow_mgr.borrow().need_close_frame() {
                c.flow_mgr.borrow_mut().set_need_close_frame(false);
                return Some((
                    Frame::ConnectionClose {
                        close_type: cerr.into(),
                        error_code: match cerr {
                            ConnectionError::Application(e) => *e,
                            ConnectionError::Transport(e) => e.code(),
                        },
                        frame_type: *frame_type,
                        reason_phrase: Vec::from(reason.clone()),
                    },
                    None,
                ));
            }
        } else {
            qerror!(
                "CloseGenerator.generate() called when in {:?}, not State::Closing",
                c.state()
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::StreamType;
    use std::convert::TryFrom;
    use test_fixture::{self, fixture_init, loopback, now};

    // This is fabulous: because test_fixture uses the public API for Connection,
    // it gets a different type to the ones that are referenced via super::*.
    // Thus, this code can't use default_client() and default_server() from
    // test_fixture because they produce different types.
    //
    // These are a direct copy of those functions.
    pub fn default_client() -> Connection {
        fixture_init();
        Connection::new_client(
            test_fixture::DEFAULT_SERVER_NAME,
            test_fixture::DEFAULT_ALPN,
            loopback(),
            loopback(),
        )
        .expect("create a default client")
    }
    pub fn default_server() -> Connection {
        fixture_init();
        Connection::new_server(
            test_fixture::DEFAULT_KEYS,
            test_fixture::DEFAULT_ALPN,
            &test_fixture::anti_replay(),
        )
        .expect("create a default server")
    }

    #[test]
    fn test_stream_id_methods() {
        let id1 = StreamIndex::new(4).to_stream_id(StreamType::BiDi, Role::Client);
        assert_eq!(id1.is_bidi(), true);
        assert_eq!(id1.is_uni(), false);
        assert_eq!(id1.is_client_initiated(), true);
        assert_eq!(id1.is_server_initiated(), false);
        assert_eq!(id1.role(), Role::Client);
        assert_eq!(id1.is_self_initiated(Role::Client), true);
        assert_eq!(id1.is_self_initiated(Role::Server), false);
        assert_eq!(id1.is_peer_initiated(Role::Client), false);
        assert_eq!(id1.is_peer_initiated(Role::Server), true);
        assert_eq!(id1.is_send_only(Role::Server), false);
        assert_eq!(id1.is_send_only(Role::Client), false);
        assert_eq!(id1.is_recv_only(Role::Server), false);
        assert_eq!(id1.is_recv_only(Role::Client), false);
        assert_eq!(id1.as_u64(), 16);

        let id2 = StreamIndex::new(8).to_stream_id(StreamType::UniDi, Role::Server);
        assert_eq!(id2.is_bidi(), false);
        assert_eq!(id2.is_uni(), true);
        assert_eq!(id2.is_client_initiated(), false);
        assert_eq!(id2.is_server_initiated(), true);
        assert_eq!(id2.role(), Role::Server);
        assert_eq!(id2.is_self_initiated(Role::Client), false);
        assert_eq!(id2.is_self_initiated(Role::Server), true);
        assert_eq!(id2.is_peer_initiated(Role::Client), true);
        assert_eq!(id2.is_peer_initiated(Role::Server), false);
        assert_eq!(id2.is_send_only(Role::Server), true);
        assert_eq!(id2.is_send_only(Role::Client), false);
        assert_eq!(id2.is_recv_only(Role::Server), false);
        assert_eq!(id2.is_recv_only(Role::Client), true);
        assert_eq!(id2.as_u64(), 35);
    }

    #[test]
    fn test_conn_stream_create() {
        let mut client = default_client();
        let (res, _) = client.process(vec![], now());
        let mut server = default_server();
        let (res, _) = server.process(res, now());

        let (res, _) = client.process(res, now());
        // client now in State::Connected
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 2);
        assert_eq!(client.stream_create(StreamType::UniDi).unwrap(), 6);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 0);
        assert_eq!(client.stream_create(StreamType::BiDi).unwrap(), 4);

        let _ = server.process(res, now());
        // server now in State::Connected
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 3);
        assert_eq!(server.stream_create(StreamType::UniDi).unwrap(), 7);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 1);
        assert_eq!(server.stream_create(StreamType::BiDi).unwrap(), 5);
    }

    #[test]
    fn test_conn_handshake() {
        qdebug!("---- client: generate CH");
        let mut client = default_client();
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        assert_eq!(res.first().unwrap().len(), 1200);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
        let mut server = default_server();
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: SH..FIN -> FIN");
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: FIN -> ACKS");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: ACKS -> 0");
        let (res, _) = client.process(res, now());
        assert!(res.is_empty());
        qdebug!("Output={:0x?}", res);

        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    #[test]
    // tests stream send/recv after connection is established.
    fn test_conn_stream() {
        let mut client = default_client();
        let mut server = default_server();

        qdebug!("---- client");
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[0]: CRYPTO[CH]

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);
        // <<-- Initial[0]: CRYPTO[SH] ACK[0]
        // <<-- Handshake[0]: CRYPTO[EE, CERT, CV, FIN]

        qdebug!("---- client");
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*client.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // -->> Initial[1]: ACK[0]
        // -->> Handshake[0]: CRYPTO[FIN], ACK[0]

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        assert_eq!(*server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);
        // ACKs
        // -->> nothing

        qdebug!("---- client");
        // Send
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id, &vec![6; 100]).unwrap();
        client.stream_send(client_stream_id, &vec![7; 40]).unwrap();
        client
            .stream_send(client_stream_id, &vec![8; 4000])
            .unwrap();

        // Send to another stream but some data after fin has been set
        let client_stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
        client.stream_send(client_stream_id2, &vec![6; 60]).unwrap();
        client.stream_close_send(client_stream_id2).unwrap();
        client
            .stream_send(client_stream_id2, &vec![7; 50])
            .unwrap_err();
        let (res, _) = client.process(res, now());
        assert_eq!(res.len(), 4);

        qdebug!("---- server");
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1); // Just an ACK.
        assert_eq!(*server.state(), State::Connected);
        qdebug!("Output={:0x?}", res);

        let mut buf = vec![0; 4000];

        let mut stream_ids = server.events().into_iter().filter_map(|evt| match evt {
            ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
            _ => None,
        });
        let stream_id = stream_ids.next().expect("should have a new stream event");
        let (received, fin) = server.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(received, 4000);
        assert_eq!(fin, false);
        let (received, fin) = server.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(received, 140);
        assert_eq!(fin, false);

        let stream_id = stream_ids
            .next()
            .expect("should have a second new stream event");
        let (received, fin) = server.stream_recv(stream_id, &mut buf).unwrap();
        assert_eq!(received, 60);
        assert_eq!(fin, true);
    }

    /// Drive the handshake between the client and server.
    fn handshake(client: &mut Connection, server: &mut Connection) {
        let mut a = client;
        let mut b = server;
        let mut records = Vec::new();
        let is_done = |c: &mut Connection| match c.state() {
            // TODO(mt): Finish on Closed and not Closing.
            State::Connected | State::Closing { .. } | State::Closed(..) => true,
            _ => false,
        };
        while !is_done(a) {
            let (r, _) = a.process(records, now());
            records = r;
            mem::swap(&mut a, &mut b);
        }
    }

    fn connect(client: &mut Connection, server: &mut Connection) {
        handshake(client, server);
        assert_eq!(*client.state(), State::Connected);
        assert_eq!(*server.state(), State::Connected);
    }

    fn assert_error(c: &Connection, err: ConnectionError) {
        match c.state() {
            // TODO(mt): Finish on Closed and not Closing.
            State::Closing { error, .. } | State::Closed(error) => {
                assert_eq!(*error, err);
            }
            _ => panic!("bad state {:?}", c.state()),
        }
    }

    #[test]
    fn test_no_alpn() {
        fixture_init();
        let mut client =
            Connection::new_client("example.com", &["bad-alpn"], loopback(), loopback()).unwrap();
        let mut server = default_server();

        handshake(&mut client, &mut server);
        // TODO (mt): errors are immediate, which means that we never send CONNECTION_CLOSE
        // and the client never sees the server's rejection of its handshake.
        //assert_error(&client, ConnectionError::Transport(Error::CryptoAlert(120)));
        assert_error(&server, ConnectionError::Transport(Error::CryptoAlert(120)));
    }

    #[test]
    fn test_dup_server_flight1() {
        qdebug!("---- client: generate CH");
        let mut client = default_client();
        let (res, _) = client.process(Vec::new(), now());
        assert_eq!(res.len(), 1);
        assert_eq!(res.first().unwrap().len(), 1200);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- server: CH -> SH, EE, CERT, CV, FIN");
        let mut server = default_server();
        let (res, _) = server.process(res, now());
        assert_eq!(res.len(), 1);
        qdebug!("Output={:0x?}", res);

        qdebug!("---- client: SH..FIN -> FIN");
        let (res2, _) = client.process(res.clone(), now());
        assert_eq!(res2.len(), 1);
        qdebug!("Output={:0x?}", res);

        assert_eq!(2, client.stats().packets_rx);
        assert_eq!(0, client.stats().dups_rx);

        qdebug!("---- Dup, ignored");
        let (res2, _) = client.process(res.clone(), now());
        assert_eq!(res2.len(), 0);
        qdebug!("Output={:0x?}", res);

        // Four packets total received, two of them are dups
        assert_eq!(4, client.stats().packets_rx);
        assert_eq!(2, client.stats().dups_rx);
    }

    fn exchange_ticket(client: &mut Connection, server: &mut Connection) -> Vec<u8> {
        server.send_ticket(now(), &[]).expect("can send ticket");
        let (dgrams, _timer) = server.process_output(now());
        assert_eq!(dgrams.len(), 1);
        client.process_input(dgrams, now());
        assert_eq!(*client.state(), State::Connected);
        client.resumption_token().expect("should have token")
    }

    #[test]
    fn resume() {
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let token = exchange_ticket(&mut client, &mut server);
        let mut client = default_client();
        client
            .set_resumption_token(now(), &token[..])
            .expect("should set token");
        let mut server = default_server();
        connect(&mut client, &mut server);
        assert!(client.crypto.tls.info().unwrap().resumed());
        assert!(server.crypto.tls.info().unwrap().resumed());
    }

    #[test]
    fn zero_rtt_negotiate() {
        // Note that the two servers in this test will get different anti-replay filters.
        // That's OK because we aren't testing anti-replay.
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let token = exchange_ticket(&mut client, &mut server);
        let mut client = default_client();
        client
            .set_resumption_token(now(), &token[..])
            .expect("should set token");
        let mut server = default_server();
        connect(&mut client, &mut server);
        assert!(client.crypto.tls.info().unwrap().early_data_accepted());
        assert!(server.crypto.tls.info().unwrap().early_data_accepted());
    }

    #[test]
    fn zero_rtt_send_recv() {
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let token = exchange_ticket(&mut client, &mut server);
        let mut client = default_client();
        client
            .set_resumption_token(now(), &token[..])
            .expect("should set token");
        let mut server = default_server();

        // Send ClientHello.
        let (client_hs, _) = client.process(Vec::new(), now());
        assert_eq!(client_hs.len(), 1);

        // Now send a 0-RTT packet.
        // TODO(mt) work out how to coalesce this with the ClientHello.
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client
            .stream_send(client_stream_id, &vec![1, 2, 3])
            .unwrap();
        let (client_0rtt, _) = client.process(Vec::new(), now());
        assert_eq!(client_0rtt.len(), 1);

        let (server_hs, _) = server.process(client_hs.into_iter().chain(client_0rtt), now());
        assert_eq!(server_hs.len(), 1); // Should produce ServerHello etc...

        let server_stream_id = server
            .events()
            .into_iter()
            .find_map(|evt| match evt {
                ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .expect("should have received a new stream event");
        assert_eq!(client_stream_id, server_stream_id);
    }

    #[test]
    fn zero_rtt_send_coalesce() {
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let token = exchange_ticket(&mut client, &mut server);
        let mut client = default_client();
        client
            .set_resumption_token(now(), &token[..])
            .expect("should set token");
        let mut server = default_server();

        // Write 0-RTT before generating any packets.
        // This should result in a datagram that coalesces Initial and 0-RTT.
        let client_stream_id = client.stream_create(StreamType::UniDi).unwrap();
        client
            .stream_send(client_stream_id, &vec![1, 2, 3])
            .unwrap();
        let (client_0rtt, _) = client.process(Vec::new(), now());
        assert_eq!(client_0rtt.len(), 1);

        // Do a simple decode of the datagram.
        let mut dec = Decoder::from(&client_0rtt[0][..]);
        let initial_type = dec.decode_byte().unwrap(); // Initial
        assert_eq!(initial_type & 0b11110000, 0b11000000);
        let version = dec.decode_uint(4).unwrap();
        assert_eq!(version, QUIC_VERSION.into());
        let dcil_scil = dec.decode_byte().unwrap();
        println!("DCIL/SCIL {}", dcil_scil);
        let dcil = (dcil_scil >> 4) + 3;
        assert!(dcil >= 8);
        let scil = match dcil_scil & 0xf {
            0 => 0,
            v => v + 3,
        };
        dec.skip(usize::try_from(dcil + scil).unwrap());
        let token_len = dec.decode_varint().unwrap();
        dec.skip(usize::try_from(token_len).unwrap());
        let initial_len = dec.decode_varint().unwrap();
        dec.skip(usize::try_from(initial_len).unwrap());
        let zrtt_type = dec.decode_byte().unwrap();
        assert_eq!(zrtt_type & 0b11110000, 0b11010000);

        let (server_hs, _) = server.process(client_0rtt, now());
        assert_eq!(server_hs.len(), 1); // Should produce ServerHello etc...

        let server_stream_id = server
            .events()
            .into_iter()
            .find_map(|evt| match evt {
                ConnectionEvent::NewStream { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .expect("should have received a new stream event");
        assert_eq!(client_stream_id, server_stream_id);
    }

    #[test]
    fn zero_rtt_send_reject() {
        let mut client = default_client();
        let mut server = default_server();
        connect(&mut client, &mut server);

        let token = exchange_ticket(&mut client, &mut server);
        let mut client = default_client();
        client
            .set_resumption_token(now(), &token[..])
            .expect("should set token");
        // Using a freshly initialized anti-replay context
        // should result in the server rejecting 0-RTT.
        let ar = AntiReplay::new(now(), test_fixture::ANTI_REPLAY_WINDOW, 1, 3)
            .expect("setup anti-replay");
        let mut server =
            Connection::new_server(test_fixture::DEFAULT_KEYS, test_fixture::DEFAULT_ALPN, &ar)
                .unwrap();

        // Send ClientHello.
        let (client_hs, _) = client.process(Vec::new(), now());
        assert_eq!(client_hs.len(), 1);

        // Write some data on the client.
        let stream_id = client.stream_create(StreamType::UniDi).unwrap();
        let msg = &[1, 2, 3];
        client.stream_send(stream_id, msg).unwrap();
        let (client_0rtt, _) = client.process(Vec::new(), now());
        assert_eq!(client_0rtt.len(), 1);

        let (server_hs, _) = server.process(client_hs.into_iter().chain(client_0rtt), now());
        assert_eq!(server_hs.len(), 1); // Should produce ServerHello etc...

        // The server shouldn't receive that 0-RTT data.
        let recvd_stream_evt = |e| matches!(e, ConnectionEvent::NewStream { .. });
        assert!(!server.events().into_iter().any(recvd_stream_evt));

        // Client should get a rejection.
        let _ = client.process(server_hs, now());
        let recvd_0rtt_reject = |e| e == ConnectionEvent::ZeroRttRejected;
        assert!(client.events().into_iter().any(recvd_0rtt_reject));

        // ...and the client stream should be gone.
        let res = client.stream_send(stream_id, msg);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidStreamId);
    }

    #[test]
    fn test_vn() {
        let mut server = default_server();

        // Make a packet with a bad version
        let hdr = PacketHdr::new(
            0,
            PacketType::Initial(vec![]),
            Some(0xbad),
            ConnectionId::generate(8),
            Some(ConnectionId::generate(8)),
            0, // pn
            0, // epoch
        );
        let agent = Client::new(test_fixture::DEFAULT_SERVER_NAME)
            .unwrap()
            .into();
        let tphandler = Rc::new(RefCell::new(TransportParametersHandler::default()));
        let mut crypto = Crypto::new(agent, test_fixture::DEFAULT_ALPN, tphandler, None).unwrap();
        let cs = crypto.create_initial_state(Role::Client, &hdr.dcid);
        let packet = encode_packet(cs.tx.as_ref().unwrap(), &hdr, &vec![0; 16]);
        let dgram = Datagram::new(loopback(), loopback(), packet);

        // "send" it
        let (ret_dgram, _) = server.process(vec![dgram], now());

        // We should have received a VN packet.
        assert_eq!(ret_dgram.len(), 1);
        let ret_pkt = &ret_dgram[0];
        let ret_hdr = decode_packet_hdr(&server, &*ret_pkt).unwrap();
        assert!(match &ret_hdr.tipe {
            PacketType::VN(vns) if vns.len() == 2 => true,
            _ => false,
        });
    }
}
