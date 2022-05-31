// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use qlog::QlogStreamer;

use neqo_common::{self as common, event::Provider, hex, qlog::NeqoQlog, Datagram, Role};
use neqo_common::{ qtrace, qinfo, qwarn, qerror };
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, AuthenticationStatus, Cipher
};
use neqo_http3::{
    self, Error, Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Output,
};
use neqo_qpack::QpackSettings;
use neqo_transport::{
    CongestionControlAlgorithm, Connection, ConnectionId, Error as TransportError,
    FixedConnectionIdManager, QuicVersion,
};

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::{ Instant, Duration };
use std::boxed::Box;
use std::sync::{ Arc, Weak, Mutex };
use std::sync::atomic::{ AtomicU32, Ordering };
use std::sync::mpsc::{ channel, RecvTimeoutError };
use std::thread::JoinHandle;
use neqo_csdef::{ ConfigFile, Resource };
use neqo_csdef::event::HEventConsumer;
use neqo_csdef::flow_shaper::{ FlowShaper, FlowShaperLogger, FlowShaperBuilder, Config as FlowShaperConfig };
use neqo_csdef::defences::{
    Defencev2, FrontConfig, StaticSchedule, Front, Tamaraw, RRSharedDefenceBuilder,
    RRSharedDefence,
};
use neqo_csdef::dependency_tracker::UrlDependencyTracker;

use structopt::StructOpt;
use url::{Origin, Url, Host};

const QUIET: bool = false;


#[derive(Debug)]
pub enum ClientError {
    Http3Error(neqo_http3::Error),
    IoError(io::Error),
    QlogError,
    TransportError(neqo_transport::Error),
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<neqo_http3::Error> for ClientError {
    fn from(err: neqo_http3::Error) -> Self {
        Self::Http3Error(err)
    }
}

impl From<qlog::Error> for ClientError {
    fn from(_err: qlog::Error) -> Self {
        Self::QlogError
    }
}

impl From<neqo_transport::Error> for ClientError {
    fn from(err: neqo_transport::Error) -> Self {
        Self::TransportError(err)
    }
}

type Res<T> = Result<T, ClientError>;

/// Track whether a key update is needed.
#[derive(Debug, PartialEq, Eq)]
struct KeyUpdateState(bool);

impl KeyUpdateState {
    pub fn maybe_update<F, E>(&mut self, update_fn: F) -> Res<()>
    where
        F: FnOnce() -> Result<(), E>,
        E: Into<ClientError>,
    {
        if self.0 {
            if let Err(e) = update_fn() {
                let e = e.into();
                match e {
                    ClientError::TransportError(TransportError::KeyUpdateBlocked)
                    | ClientError::Http3Error(Error::TransportError(
                        TransportError::KeyUpdateBlocked,
                    )) => (),
                    _ => return Err(e),
                }
            } else {
                qinfo!("Keys updated");
                self.0 = false;
            }
        }
        Ok(())
    }

    fn needed(&self) -> bool {
        self.0
    }
}


#[derive(Debug, StructOpt)]
pub struct ShapingArgs {
    #[structopt(
        long,
        possible_values=&["none", "schedule", "front", "tamaraw"],
        display_order=1001,
    )]
    /// Specify the defence (if any) to be used for shaping.
    defence: Option<String>,

    #[structopt(long, required_if("defence", "front"), display_order=1001)]
    /// Seed for the random number generator used by the defence (if applicable).
    defence_seed: Option<u64>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// Size of the packets when using non-schedule defences.
    defence_packet_size: Option<u32>,

    #[structopt(long, required_if("defence", "schedule"), requires("defence"), display_order=1002)]
    /// The target schedule for adding chaff or shaping.
    target_trace: Option<PathBuf>,

    #[structopt(
        long,
        required_if("defence", "schedule"),
        possible_values=&["chaff-only", "chaff-and-shape"],
        display_order=1002,
    )]
    /// Specify whether `target_trace` corresponds to a padding trace
    target_trace_type: Option<String>,

    #[structopt(long, requires("defence"), display_order=1003)]
    /// Maximum number of packets added to the FRONT defence from the client
    front_max_client_pkts: Option<u32>,

    #[structopt(long, requires("defence"), display_order=1003)]
    /// Maximum number of packets added to the FRONT defence from the server
    front_max_server_pkts: Option<u32>,

    #[structopt(long, requires("defence"), display_order=1003)]
    /// Maximum value in seconds at which the distribution peak will occur.
    front_peak_max: Option<f64>,

    #[structopt(long, requires("defence"), display_order=1003)]
    /// Minimum value in seconds at which the distribution peak will occur.
    front_peak_min: Option<f64>,

    #[structopt(long, default_value = "5", display_order=1004)]
    /// Incoming rate for the Tamaraw defence in milliseconds
    tamaraw_rate_in: u64,

    #[structopt(long, default_value = "20", display_order=1004)]
    /// Outgoing rate for the Tamaraw defence in milliseconds
    tamaraw_rate_out: u64,

    #[structopt(long, default_value = "100", display_order=1004)]
    /// Number of packets to whose multiple Tamaraw will pad each direction
    tamaraw_modulo: u32,

    #[structopt(long, number_of_values = 1)]
    /// Read URL dependencies from the the specified file. The file must
    /// be a header-less CSV with "url, url-dependency" on each line,
    /// where url-dependency can be the empty string. All the URLs in
    /// the file will be added to the list of URLs to download.
    url_dependencies_from: Option<PathBuf>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// Drop unsatisified shaping events when true, delay when false
    drop_unsat_events: Option<bool>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// The MSD limit excess value
    msd_limit_excess: Option<u64>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// The maximum number of chaff streams
    max_chaff_streams: Option<u32>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// Whether to allow empty resources if no resources are available
    use_empty_resources: Option<bool>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// Configuration for shaping
    shaper_config: Option<String>,

    #[structopt(short = "dummy-urls", long, number_of_values = 5)]
    /// Dummy URLs to use in shaping
    dummy_urls: Vec<Url>,

    #[structopt(long, display_order=1001)]
    /// Whether to select padding to URLs by size instead of type
    dont_select_padding_by_size: bool,

    #[structopt(long, display_order=1001)]
    /// Duration after the defence is complete to wait before closing.
    /// Allows responses from the server to be delivered
    tail_wait: Option<u64>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// File to which to log chaff stream ids
    chaff_ids_log: Option<String>,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// File to which to log the defence schedule as events are encountered
    defence_event_log: Option<String>,

    #[structopt(long, display_order=1001)]
    /// If true, will not download URLs but instead only use them to generate chaff
    only_chaff: bool,

    #[structopt(long, requires("defence"), display_order=1001)]
    /// The maximum UDP packet size to accept
    max_udp_payload_size: Option<u64>,
}


#[derive(Debug, StructOpt)]
#[structopt(
    name = "neqo-client",
    about = "A basic QUIC HTTP/0.9 and HTTP/3 client."
)]
pub struct Args {
    #[structopt(short = "a", long, default_value = "h3-29")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP/3 no matter what the ALPN says.
    alpn: String,

    urls: Vec<Url>,

    #[structopt(short = "m", default_value = "GET")]
    method: String,

    #[structopt(short = "h", long, number_of_values = 2)]
    header: Vec<String>,

    #[structopt(
        name = "encoder-table-size",
        short = "e",
        long,
        default_value = "16384"
    )]
    max_table_size_encoder: u64,

    #[structopt(
        name = "decoder-table-size",
        short = "f",
        long,
        default_value = "16384"
    )]
    max_table_size_decoder: u64,

    #[structopt(name = "max-blocked-streams", short = "b", long, default_value = "10")]
    max_blocked_streams: u16,

    #[structopt(name = "max-push", short = "p", long, default_value = "0")]
    max_concurrent_push_streams: u64,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(name = "download-in-series", long)]
    /// Download resources in series using separate connections
    download_in_series: bool,

    #[structopt(name = "output-read-data", long)]
    /// Output received data to stdout
    output_read_data: bool,

    #[structopt(name = "qlog-dir", long)]
    /// Enable QLOG logging and QLOG traces to this directory
    qlog_dir: Option<PathBuf>,

    #[structopt(name = "output-dir", long)]
    /// Save contents of fetched URLs to a directory
    output_dir: Option<PathBuf>,

    #[structopt(name = "qns-test", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_test: Option<String>,

    #[structopt(short = "r", long)]
    /// Client attemps to resume connections when there are multiple connections made.
    /// Use this for 0-RTT: the stack always attempts 0-RTT on resumption.
    resume: bool,

    #[structopt(name = "key-update", long)]
    /// Attempt to initiate a key update immediately after confirming the connection.
    key_update: bool,

    #[structopt(short = "c", long, number_of_values = 1)]
    /// The set of TLS cipher suites to enable.
    /// From: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
    ciphers: Vec<String>,

    #[structopt(flatten)]
    shaping_args: ShapingArgs,
}

impl Args {
    fn get_ciphers(&self) -> Vec<Cipher> {
        self.ciphers
            .iter()
            .filter_map(|c| match c.as_str() {
                "TLS_AES_128_GCM_SHA256" => Some(TLS_AES_128_GCM_SHA256),
                "TLS_AES_256_GCM_SHA384" => Some(TLS_AES_256_GCM_SHA384),
                "TLS_CHACHA20_POLY1305_SHA256" => Some(TLS_CHACHA20_POLY1305_SHA256),
                _ => None,
            })
            .collect::<Vec<_>>()
    }
}

fn emit_datagram(socket: &UdpSocket, d: Option<Datagram>) -> io::Result<()> {
    if let Some(d) = d {
        let sent = socket.send(&d[..])?;
        if sent != d.len() {
            qwarn!("Unable to send all {} bytes of datagram", d.len());
        }
    }
    Ok(())
}

fn get_output_file(
    url: &Url,
    output_dir: &Option<PathBuf>,
    all_paths: &mut Vec<PathBuf>,
) -> Option<File> {
    if let Some(ref dir) = output_dir {
        let mut out_path = dir.clone();

        let url_path = if url.path() == "/" {
            // If no path is given... call it "root"?
            "root"
        } else {
            // Omit leading slash
            &url.path()[1..]
        };
        out_path.push(url_path);

        if all_paths.contains(&out_path) {
            qwarn!("duplicate path {}", out_path.display());
            return None;
        }

        qinfo!("Saving {} to {:?}", url.clone().into_string(), out_path);

        let f = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)
        {
            Err(_) => return None,
            Ok(f) => f,
        };

        all_paths.push(out_path);
        Some(f)
    } else {
        None
    }
}

fn process_loop(
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    socket: &UdpSocket,
    client: &mut Http3Client,
    handler: &mut Handler,
    _origin: Origin,
) -> Res<neqo_http3::Http3State> {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return Ok(client.state());
        }

        qtrace!("[process_loop] Calling handle...");
        let mut exiting = !handler.handle(client)?;
        qtrace!("[process_loop] Handle returned: {}", exiting);

        let mut callback_duration = None;
        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => {
                    if let Err(e) = emit_datagram(&socket, Some(dgram)) {
                        qerror!("[process_loop] UDP write error: {}", e);
                        client.close(Instant::now(), 0, e.to_string());
                        exiting = true;
                        break;
                    }
                }
                Output::Callback(duration) => {
                    socket.set_read_timeout(Some(duration)).unwrap();
                    callback_duration = Some(duration);
                    qtrace!("[process_loop] callback in {} ms ({} ns)", duration.as_millis(), duration.as_nanos());
                    break;
                }
                Output::None => {
                    // Not strictly necessary, since we're about to exit
                    socket.set_read_timeout(None).unwrap();
                    exiting = true;
                    break;
                }
            }
        }

        if exiting {
            let urls = handler.url_deps.lock().unwrap();
            qtrace!("[process_loop] Exiting with {} of {} resources remaining, {} streams existing",
                urls.remaining(), urls.len(), handler.streams.len());
            return Ok(client.state());
        }

        if handler.streams.is_empty() {
            if let Some(duration) = callback_duration {
                let max_timeout = Duration::from_millis(10);
                if duration > max_timeout {
                    // The fact that exiting was false means that we still have some resources
                    // We set a short timeout as we may need to request a stream due to
                    // dependencies being satisfied in the meantime
                    qtrace!("[process_loop] No open streams, setting read timeout to 10 ms");
                    socket.set_read_timeout(Some(max_timeout)).unwrap();
                }
            }
        }

        if let Some(duration) = callback_duration {
            // socket.recv will block for multiple milliseconds for each call. Instead, just skip
            // the recv for short callback durations
            if duration < Duration::from_millis(1) {
                continue;
            }
        }

        match socket.recv(&mut buf[..]) {
            Err(ref err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted => {}
            Err(err) => {
                qerror!("[process_loop] UDP error: {}", err);
                exit(1)
            }
            Ok(sz) => {
                if sz == buf.len() {
                    qinfo!("[process_loop] Received more than {} bytes", buf.len());
                    continue;
                }
                if sz > 0 {
                    let d = Datagram::new(*remote_addr, *local_addr, &buf[..sz]);
                    client.process_input(d, Instant::now());
                    handler.maybe_key_update(client)?;
                }
            }
        };
    }
}

struct Handler<'a> {
    streams: HashMap<u64, ((u16, Url), Option<File>)>,
    url_queue: VecDeque<(u16, Url)>, // u16 is a key into url_deps
    all_paths: Vec<PathBuf>,
    args: &'a Args,
    key_update: KeyUpdateState,
    url_deps: Arc<Mutex<UrlDependencyTracker>>,
    is_done_shaping: bool,
    completion_state: (bool, bool, bool),
    url_completion_queue: Option<std::sync::mpsc::Sender<Url>>,
    ready_to_request: bool,
    origin: Origin,
}

impl<'a> std::fmt::Display for Handler<'a> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Handler({})", self.origin.ascii_serialization())
    }
}

impl<'a> Handler<'a> {
    fn download_urls(&mut self, client: &mut Http3Client) {
        loop {
            if self.args.shaping_args.only_chaff || self.url_queue.is_empty() {
                break;
            }
            if !self.download_next(client) {
                break;
            }
        }
    }

    fn download_next(&mut self, client: &mut Http3Client) -> bool {
        if self.key_update.needed() {
            qinfo!([self], "Deferring requests until first key update");
            return false;
        }

        assert!(!self.url_queue.is_empty(), "download_next called with empty queue");

        let position = {
            let url_deps = self.url_deps.lock().unwrap();
            self.url_queue.iter()
                .position(|(id, _)| url_deps.is_downloadable(*id))
        };

        let (id, url) = match position
        {
            Some(index) => {
                self.url_queue.swap_remove_front(index).unwrap()
            }
            None => {
                if !QUIET {
                    qinfo!([self], "None of the URLs are currently downloadable.");
                }
                return false;
            }
        };

        match client.fetch(
            Instant::now(),
            &self.args.method,
            &url.scheme(),
            &url.host_str().unwrap(),
            &url.path(),
            &to_headers(&self.args.header),
        ) {
            Ok(client_stream_id) => {
                qinfo!(
                    [self], "Successfully created stream id {} for {}", client_stream_id, url
                );
                let _ = client.stream_close_send(client_stream_id);

                let out_file = get_output_file(&url, &self.args.output_dir, &mut self.all_paths);

                self.streams.insert(client_stream_id, ((id, url), out_file));
                true
            }
            e @ Err(Error::TransportError(TransportError::StreamLimitError))
            | e @ Err(Error::StreamLimitError)
            // | e @ Err(Error::AlreadyClosed)
            | e @ Err(Error::Unavailable) => {
                qinfo!([self], "Cannot create stream {:?}", e);
                self.url_queue.push_front((id, url));
                false
            }
            Err(e) => {
                panic!("Can't create stream {}", e);
            }
        }
    }

    fn maybe_key_update(&mut self, c: &mut Http3Client) -> Res<()> {
        self.key_update.maybe_update(|| c.initiate_key_update())?;
        self.download_urls(c);
        Ok(())
    }

    fn done(&mut self, client: &mut Http3Client) -> bool {
        let new_state = (
            self.streams.is_empty(), self.url_queue.is_empty(), self.is_done_shaping
        );
        if new_state != self.completion_state {
            qinfo!([self], "Checking if done: streams is empty: {:?} | url_queue is empty: {:?} | is done shaping: {:?}", new_state.0, new_state.1, new_state.2);
            if (!self.completion_state.0 || !self.completion_state.1) && (new_state.0 && new_state.1) {
                // If either there were running streams, or the URL queue was not empty, but now
                // there are no running streams and the URL queue is empty, then signal that we are
                // done.
                if let Some(fs) = client.get_flow_shaper_mut() {
                    fs.borrow_mut().on_application_complete();
                }
            }
            self.completion_state = new_state;
        }

        if self.is_done_shaping && self.url_queue.is_empty() && !self.streams.is_empty() {
            if !QUIET {
                let pending_streams = self.streams.keys().cloned().collect::<Vec<u64>>();
                qinfo!([self], "Pending streams: {:?}", pending_streams);
            }
        }
        ((self.streams.is_empty() && self.url_queue.is_empty()) || self.args.shaping_args.only_chaff) && self.is_done_shaping
    }

    fn handle(&mut self, client: &mut Http3Client) -> Res<bool> {
        // println!("Checking if client is done shaping: {:?}", client.is_done_shaping());
        // self.is_done_shaping = client.is_done_shaping();
        while let Some(event) = client.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    client.authenticated(AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    fin,
                } => match self.streams.get(&stream_id) {
                    Some(((id, url), out_file)) => {
                        if out_file.is_none() && !QUIET {
                            qinfo!([self], "READ HEADERS[{}]: fin={} {:?}", stream_id, fin, headers);
                        }

                        if fin {
                            if out_file.is_none() {
                                qinfo!([self], "<FIN[{}]>", stream_id);
                            }

                            self.url_deps.lock().unwrap().resource_downloaded(*id);
                            self.url_completion_queue
                                .as_mut()
                                .expect("Queue to exist since we have streams")
                                .send(url.clone()).unwrap();

                            self.download_urls(client);
                            self.streams.remove(&stream_id);

                            if self.streams.is_empty() && self.url_queue.is_empty() {
                                // Signal that we have no more URLs to process,
                                // and instead are waiting on the defence
                                self.url_completion_queue = None;
                            }

                            if self.done(client) {
                                if client.is_being_shaped() {
                                    client.close(Instant::now(), 0, "kthx4shaping!");
                                } else {
                                    client.close(Instant::now(), 0, "kthxbye!");
                                }
                                return Ok(false);
                            }
                        }
                    }
                    None => {
                        qerror!([self], "Data on unexpected stream: {}", stream_id);
                        return Ok(false);
                    }
                },
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut stream_done = false;
                    match self.streams.get_mut(&stream_id) {
                        None => {
                            qerror!([self], "Data on unexpected stream: {}", stream_id);
                            return Ok(false);
                        }
                        Some(((id, url), out_file)) => loop {
                            let mut data = vec![0; 4096];
                            let (sz, fin) = client
                                .read_response_data(Instant::now(), stream_id, &mut data)
                                .expect("Read should succeed");

                            if let Some(out_file) = out_file {
                                if sz > 0 {
                                    out_file.write_all(&data[..sz])?;
                                }
                            } else if !self.args.output_read_data {
                                if !QUIET {
                                    qinfo!("READ[{}]: {} bytes", stream_id, sz);
                                }
                            } else if let Ok(txt) = String::from_utf8(data.clone()) {
                                if !QUIET {
                                    qinfo!("READ[{}]: {}", stream_id, txt);
                                }
                            } else {
                                if !QUIET {
                                    qinfo!("READ[{}]: 0x{}", stream_id, hex(&data));
                                }
                            }

                            if fin {
                                if out_file.is_none() {
                                    qinfo!("<FIN[{}]>", stream_id);
                                }

                                self.url_deps.lock().unwrap().resource_downloaded(*id);
                                self.url_completion_queue
                                    .as_mut()
                                    .expect("Queue to exist since we have streams")
                                    .send(url.clone()).unwrap();
                                self.download_urls(client);

                                stream_done = true;
                                break;
                            }

                            if sz == 0 {
                                break;
                            }
                        },
                    }

                    if stream_done {
                        self.streams.remove(&stream_id);

                        if self.streams.is_empty() && self.url_queue.is_empty() {
                            // Signal that we have no more URLs to process,
                            // and instead are waiting on the defence
                            self.url_completion_queue = None;
                        }

                        if self.done(client) {
                            if client.is_being_shaped() {
                                client.close(Instant::now(), 0, "kthx4shaping!");
                            } else {
                                client.close(Instant::now(), 0, "kthxbye!");
                            }
                            return Ok(false);
                        }
                    }
                }
                Http3ClientEvent::StateChange(Http3State::Connected)
                | Http3ClientEvent::RequestsCreatable => {
                    self.ready_to_request = true;
                    self.download_urls(client);
                }
                Http3ClientEvent::FlowShapingDone(should_close) => {
                    self.is_done_shaping = true;

                    if should_close {
                        client.close(Instant::now(), 0, "kthx4shaping!");
                        return Ok(false);
                    }
                }
                Http3ClientEvent::ResumptionToken{..} => {
                    qwarn!([self], "Unhandled resumption token.");
                }
                Http3ClientEvent::StateChange(Http3State::Closing(err)) => {
                    panic!("[{}] Unexpected closing due to error: {:?}", self, err);
                }
                _ => {
                    qwarn!([self], "Unhandled event {:?}", event);
                }
            }
        }

        // check for connection done outside loop because dummy events are not
        // notified to main.rs
        if self.done(client) {
            if client.is_being_shaped() {
                client.close(Instant::now(), 0, "kthx4shaping!");
            } else {
                client.close(Instant::now(), 0, "kthxbye!");
            }
            return Ok(false);
        } else if self.ready_to_request && self.streams.is_empty() && !self.url_queue.is_empty() {
            self.download_urls(client);
        }
        qtrace!([self], "state summary is ready_to_request={}, streams.is_empty()={}, url_queue.is_empty()={}, is_done_shaping={}",
            self.ready_to_request, self.streams.is_empty(), self.url_queue.is_empty(), self.is_done_shaping);
        Ok(true)
    }
}

fn to_headers(values: &[impl AsRef<str>]) -> Vec<Header> {
    values
        .iter()
        .scan(None, |state, value| {
            if let Some(name) = state.take() {
                *state = None;
                Some(Some((name, value.as_ref().to_string()))) // TODO use a real type
            } else {
                *state = Some(value.as_ref().to_string());
                Some(None)
            }
        })
        .filter_map(|x| x)
        .collect()
}


fn build_defence(args: &ShapingArgs) -> Option<Box<dyn Defencev2 + Send>> {
    let defence = args.defence.as_deref();
    qtrace!("Defence is {:?}", defence);
    if matches!(defence, None | Some("none")) {
        return None;
    }
    let defence_type = defence.unwrap();

    let mut front_config = match args.shaper_config.clone() {
        Some(filename) => {
            let configs = ConfigFile::load(&filename)
                .expect("Unable to load config file");

             configs.front_defence.unwrap_or(FrontConfig::default())
        },
        None => FrontConfig::default()
    };

    let defence: Box<dyn Defencev2 + Send> = match defence_type {
        "schedule" => {
            let filename = args.target_trace.clone()
                .and_then(|p| p.into_os_string().to_str().map(str::to_owned))
                .expect("filename to be specified");
            let is_padding = matches!(args.target_trace_type.as_deref(), Some("chaff-only"));

            Box::new(StaticSchedule::from_file(&filename, is_padding).unwrap())
        }
        "front" => {
            front_config.n_client_packets = args.front_max_client_pkts
                .unwrap_or(front_config.n_client_packets);
            front_config.n_server_packets = args.front_max_server_pkts
                .unwrap_or(front_config.n_server_packets);
            front_config.peak_maximum = args.front_peak_max
                .unwrap_or(front_config.peak_maximum);
            front_config.peak_minimum = args.front_peak_min
                .unwrap_or(front_config.peak_minimum);
            front_config.packet_size = args.defence_packet_size
                .unwrap_or(front_config.packet_size);
            front_config.seed = args.defence_seed.clone();

            Box::new(Front::new(front_config))
        }
        "tamaraw" => {
            let packet_length = args.defence_packet_size.unwrap_or(1450);
            Box::new(Tamaraw::new(
                Duration::from_millis(args.tamaraw_rate_in),
                Duration::from_millis(args.tamaraw_rate_out),
                packet_length, args.tamaraw_modulo
            ))
        }
        other => panic!("unknown defence: {:?}", other),
    };

    qinfo!("Defence: {:?}", defence);
    Some(defence)
}


fn build_flow_shaper(
    args: &ShapingArgs, resources: Vec<Resource>, header: &Vec<String>, defence: RRSharedDefence,
    logger: Arc<Mutex<FlowShaperLogger>>
) -> FlowShaper {
    qinfo!("Enabling connection shaping.");

    let mut builder = FlowShaperBuilder::new();
    let mut config = match args.shaper_config.clone() {
        Some(filename) => {
            let configs = ConfigFile::load(&filename)
                .expect("Unable to load config file");

            configs.flow_shaper.unwrap_or(FlowShaperConfig::default())
        },
        None => FlowShaperConfig::default()
    };

    if let Some(value) = args.msd_limit_excess {
        config.max_stream_data_excess = value;
    }

    if let Some(value) = args.use_empty_resources {
        config.use_empty_resources = value;
    }

    if let Some(value) = args.tail_wait {
        config.tail_wait = value;
    }

    if let Some(value) = args.max_chaff_streams {
        config.max_chaff_streams = value;
    }

    if let Some(value) = args.max_udp_payload_size {
        config.max_udp_payload_size = value;
    }

    if let Some(value) = args.drop_unsat_events {
        config.drop_unsat_events = value;
    }

    builder.config(config);
    builder.chaff_resources(&resources);
    builder.chaff_headers(&to_headers(&header));
    builder.logger(Some(logger));

    builder.from_defence(Box::new(defence))
}


fn client(
    args: Arc<Args>,
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
    url_deps: Arc<Mutex<UrlDependencyTracker>>,
    url_completion_queue: std::sync::mpsc::Sender<Url>,
    origin: Origin,
    defence: Option<RRSharedDefence>,
    logger: Arc<Mutex<FlowShaperLogger>>
) -> Res<()> {
    let quic_protocol = match args.alpn.as_str() {
        "h3-27" => QuicVersion::Draft27,
        "h3-28" => QuicVersion::Draft28,
        "h3-29" => QuicVersion::Draft29,
        "h3-30" => QuicVersion::Draft30,
        _ => QuicVersion::default(),
    };
    let mut shaping = false;

    let mut transport = Connection::new_client(
        hostname,
        &[&args.alpn],
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        local_addr,
        remote_addr,
        &CongestionControlAlgorithm::NewReno,
        quic_protocol,
    )?;
    let ciphers = args.get_ciphers();
    if !ciphers.is_empty() {
        transport.set_ciphers(&ciphers)?;
    }
    let mut client = Http3Client::new_with_conn(
        transport,
        &Http3Parameters {
            qpack_settings: QpackSettings {
                max_table_size_encoder: args.max_table_size_encoder,
                max_table_size_decoder: args.max_table_size_decoder,
                max_blocked_streams: args.max_blocked_streams,
            },
            max_concurrent_push_streams: args.max_concurrent_push_streams,
        },
    );

    // If there are no dummy-urls, extract them from the list of URLs
    let n_urls = if !args.shaping_args.only_chaff { 5 } else { 20 };

    let chaff_resources = match (&args.shaping_args.dummy_urls,
                                 args.shaping_args.dont_select_padding_by_size) {
        (vec, _) if !vec.is_empty() => vec.iter().cloned().map(|x| x.into()).collect(),
        (_, true) => url_deps.lock().unwrap().select_padding_urls(n_urls)
            .into_iter().map(|x| x.into()).collect(),
        (_, false) => url_deps.lock().unwrap().select_padding_urls_by_size(n_urls)
    };
    let chaff_resources = chaff_resources.iter()
        .filter(|res| res.url().origin() == origin)
        .cloned()
        .collect();

    if let Some(flow_shaper) = defence
        .map(|d| build_flow_shaper(&args.shaping_args, chaff_resources, &args.header, d, logger))
    {
        client = client.with_flow_shaper(flow_shaper);
        shaping = true;
    }

    let qlog = qlog_new(&*args, hostname, client.connection_id())?;
    client.set_qlog(qlog);

    let key_update = KeyUpdateState(args.key_update);
    let url_queue: VecDeque<(u16, Url)> = url_deps.lock().unwrap()
        .urls().iter()
        .filter(|(_, url)| url.origin() == origin)
        .cloned()
        .collect();
    let mut h = Handler {
        streams: HashMap::new(),
        url_queue,
        all_paths: Vec::new(),
        args: &args,
        key_update,
        url_deps,
        is_done_shaping: !shaping,
        completion_state: (false, false, !shaping),
        url_completion_queue: Some(url_completion_queue),
        ready_to_request: false,
        origin: origin.clone(),
    };

    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h, origin)?;

    Ok(())
}

fn qlog_new(args: &Args, hostname: &str, cid: &ConnectionId) -> Res<NeqoQlog> {
    if let Some(qlog_dir) = &args.qlog_dir {
        let mut qlog_path = qlog_dir.to_path_buf();
        let filename = format!("{}-{}.qlog", hostname, cid);
        qlog_path.push(filename);

        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&qlog_path)?;

        let streamer = QlogStreamer::new(
            qlog::QLOG_VERSION.to_string(),
            Some("Example qlog".to_string()),
            Some("Example qlog description".to_string()),
            None,
            std::time::Instant::now(),
            common::qlog::new_trace(Role::Client),
            Box::new(f),
        );

        Ok(NeqoQlog::enabled(streamer, qlog_path)?)
    } else {
        Ok(NeqoQlog::disabled())
    }
}



static NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(0);

struct ParallelClient {
    id: u32,
    lifeline: Weak<()>,
    handle: Option<JoinHandle<Res<()>>>,
}

impl std::fmt::Display for ParallelClient {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "PClient({})", self.id)
    }
}

impl ParallelClient {
    fn is_running(&self) -> bool {
        qtrace!([self], "Has strong references: {}", self.lifeline.strong_count());
        self.lifeline.strong_count() > 0
    }

    fn join(&mut self) -> std::thread::Result<Res<()>> {
        self.handle.take().unwrap().join()
    }

    fn new(_scheme: String, host: Host<String>, port: u16, args: Arc<Args>,
        url_deps: Arc<Mutex<UrlDependencyTracker>>, url_completion_queue: std::sync::mpsc::Sender<Url>,
        origin: Origin, defence: Option<RRSharedDefence>,
        logger: Arc<Mutex<FlowShaperLogger>>,
    ) -> Res<ParallelClient>  {
        qtrace!("Creating new client.");
        let id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("t{}", id);

        let lifeline = Arc::new(());
        let lifeline_weak = Arc::downgrade(&lifeline);
        assert!(lifeline_weak.strong_count() == 1);

        let handle = std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let _lifeline = lifeline;
                qtrace!("Thread starting.");

                let addrs: Vec<_> = format!("{}:{}", host, port).to_socket_addrs()?.filter(|x| x.is_ipv4()).collect();
                let remote_addr = *addrs.first().unwrap();

                let local_addr = match remote_addr {
                    SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
                    SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
                };

                let socket = match UdpSocket::bind(local_addr) {
                    Err(e) => {
                        qerror!("[{}] Unable to bind UDP socket: {}", origin.ascii_serialization(), e);
                        exit(1)
                    }
                    Ok(s) => s,
                };

                socket.connect(&remote_addr)
                    .expect("Unable to connect UDP socket");

                qinfo!("[{}] H3 Client connecting: {:?} -> {:?}",
                    origin.ascii_serialization(), socket.local_addr().unwrap(), remote_addr);

                let result = client(
                    args,
                    socket,
                    local_addr,
                    remote_addr,
                    &format!("{}", host),
                    url_deps.clone(),
                    url_completion_queue,
                    origin.clone(),
                    defence,
                    logger,
                )?;
                qtrace!("Thread ending with result: {:?}", result);

                Ok(result)
            })
            .unwrap();

        Ok(ParallelClient {
            id: id,
            lifeline: lifeline_weak,
            handle: Some(handle),
        })
    }
}

fn build_flow_shaper_logger(args: &ShapingArgs) -> FlowShaperLogger {
    let mut logger = FlowShaperLogger::default();
    if let Some(filename) = args.chaff_ids_log.as_ref() {
        logger.set_chaff_ids_log(filename).expect("invalid file");
    }
    if let Some(filename) = args.defence_event_log.as_ref() {
        logger.set_defence_event_log(filename).expect("invalid file");
    }
    logger
}


fn main() -> Res<()> {
    init();

    let mut args = Args::from_args();

    let url_deps = match &args.shaping_args.url_dependencies_from {
        Some(path_buf) => {
            let tracker = UrlDependencyTracker::from_json(path_buf.as_path());
            args.urls = tracker.urls().iter().map(|x| x.1.clone()).collect();
            tracker

        },
        None => UrlDependencyTracker::from_urls(&args.urls)
    };

    if let Some(testcase) = args.qns_test.as_ref() {
        match testcase.as_str() {
            "http3" => {}
            "handshake" | "transfer" | "retry" => {
                args.use_old_http = true;
            }
            "zerortt" | "resumption" => {
                if args.urls.len() < 2 {
                    qwarn!("Warning: resumption tests won't work without >1 URL");
                    exit(127);
                }
                args.use_old_http = true;
                args.resume = true;
            }
            "multiconnect" => {
                args.use_old_http = true;
                args.download_in_series = true;
            }
            "chacha20" => {
                args.use_old_http = true;
                args.ciphers.clear();
                args.ciphers
                    .extend_from_slice(&[String::from("TLS_CHACHA20_POLY1305_SHA256")]);
            }
            "keyupdate" => {
                args.use_old_http = true;
                args.key_update = true;
            }
            _ => exit(127),
        }
    }


    let logger = Arc::new(Mutex::new(build_flow_shaper_logger(&args.shaping_args)));
    let args = Arc::new(args);
    let (tx, rx) = channel::<Url>();
    let mut tx = Some(tx);

    let url_deps = Arc::new(Mutex::new(url_deps));
    let mut clients_by_origin: HashMap<Origin, ParallelClient> = HashMap::new();
    let mut pending_urls_by_origin: HashMap<Origin, Vec<(u16, Url)>> = HashMap::new();

    for (id, url) in &url_deps.lock().unwrap().urls() {
        let origin = url.origin();
        if origin.is_tuple() {
            let entry = pending_urls_by_origin.entry(origin).or_default();
            entry.push((*id, url.clone()));
        } else {
            qinfo!("Opaque origin {:?}", origin);
        }
    }

    let mut manager = build_defence(&args.shaping_args)
        .map(|defence| RRSharedDefenceBuilder::new(defence));

    loop {
        let new_origins: Vec<Origin> = pending_urls_by_origin.iter()
            .filter(|(_, urls)|
                urls.iter().any(|(id, _)| url_deps.lock().unwrap().is_downloadable(*id))
            )
            .map(|(origin, _)| origin)
            .cloned().collect();

        for origin in &new_origins {
            if let Origin::Tuple(_scheme, host, port) = origin.clone() {
                let defence = manager.as_mut().map(|mgr| mgr.new_shared());
                let client = ParallelClient::new(
                    _scheme, host, port, args.clone(), url_deps.clone(), tx.clone().unwrap(),
                    origin.clone(), defence, logger.clone()
                )?;
                clients_by_origin.insert(origin.clone(), client);
            }

            // Since they will be downloaded, remove them from the pending hashmap
            pending_urls_by_origin.remove(origin);
        }

        // We no longer need to create tx queues, so close the copy we have
        // to all detecting when all clients have disconnected
        if pending_urls_by_origin.is_empty() {
            if let Some(tx_queue) = tx {
                drop(tx_queue);
                tx = None;
            }
        }

        // Wait to read from the receive queue, if it's an error
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(url) => qinfo!("[main] Received notice of completion: {}", url),
            Err(RecvTimeoutError::Disconnected) => {
                qinfo!("[main] Received signal that all URLs are complete");
                if let Some(mgr) = manager.as_mut() {
                    mgr.on_all_applications_complete();
                }
                break;
            }
            Err(RecvTimeoutError::Timeout) => (),
        };

        // Check for completion
        let completed: Vec<Origin> = clients_by_origin.iter()
            .filter(|(_, pclient)| !pclient.is_running())
            .map(|(origin, _)| origin.clone())
            .collect();

        for origin in completed {
            qtrace!("[main] joining stopped thread for {:?}", origin);
            let mut pclient = clients_by_origin.remove(&origin).expect("was just found in the map");
            match pclient.join() {
                Ok(res) => {
                    qtrace!("[main] thread had ended okay {:?}", origin);
                    res?
                }
                Err(e) => {
                    qerror!("[main] thread ended in an error: {:?} {:?}", origin, e);
                    std::panic::resume_unwind(e)
                }
            };
        }
    }

    for (origin, mut pclient) in clients_by_origin.drain() {
        qinfo!("[main] Waiting for thread to exit for origin: {:?}", origin);
        match pclient.join() {
            Ok(res) => {
                qtrace!("[main] thread had ended okay: {:?}", origin);
                res?
            }
            Err(e) => {
                qerror!("[main] thread ended in an error: {:?} {:?}", origin, e);
                std::panic::resume_unwind(e)
            }
        };
    }

    Ok(())
}
