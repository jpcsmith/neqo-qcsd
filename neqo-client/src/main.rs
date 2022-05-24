// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "deny-warnings", deny(warnings))]
#![warn(clippy::use_self)]

use qlog::QlogStreamer;

use neqo_common::{self as common, event::Provider, hex, qlog::NeqoQlog, Datagram, Role};
use neqo_crypto::{
    constants::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
    init, AuthenticationStatus, Cipher, ResumptionToken,
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
use neqo_csdef::{ ConfigFile, Resource };
use neqo_csdef::event::HEventConsumer;
use neqo_csdef::flow_shaper::{ FlowShaper, FlowShaperBuilder, Config as FlowShaperConfig };
use neqo_csdef::defences::{ Defencev2, FrontConfig, StaticSchedule, Front, Tamaraw };
use neqo_csdef::dependency_tracker::UrlDependencyTracker;

use structopt::StructOpt;
use url::{Origin, Url};

const QUIET: bool = true;


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
                println!("Keys updated");
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
            eprintln!("Unable to send all {} bytes of datagram", d.len());
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
            eprintln!("duplicate path {}", out_path.display());
            return None;
        }

        eprintln!("Saving {} to {:?}", url.clone().into_string(), out_path);

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
) -> Res<neqo_http3::Http3State> {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return Ok(client.state());
        }

        let mut exiting = !handler.handle(client)?;

        let mut callback_duration = None;
        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => {
                    if let Err(e) = emit_datagram(&socket, Some(dgram)) {
                        eprintln!("UDP write error: {}", e);
                        client.close(Instant::now(), 0, e.to_string());
                        exiting = true;
                        break;
                    }
                }
                Output::Callback(duration) => {
                    socket.set_read_timeout(Some(duration)).unwrap();
                    callback_duration = Some(duration);
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
            let urls = handler.url_deps.borrow();
            println!("Exiting with {} of {} resources remaining, {} streams existing",
                     urls.remaining(), urls.len(), handler.streams.len());
            return Ok(client.state());
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
                eprintln!("UDP error: {}", err);
                exit(1)
            }
            Ok(sz) => {
                if sz == buf.len() {
                    eprintln!("Received more than {} bytes", buf.len());
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
    url_deps: Rc<RefCell<UrlDependencyTracker>>,
    is_done_shaping: bool,
    completion_state: (bool, bool, bool)
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
            println!("Deferring requests until first key update");
            return false;
        }

        assert!(!self.url_queue.is_empty(), "download_next called with empty queue");

        let (id, url) = match self.url_queue.iter()
            .position(|(id, _)| self.url_deps.borrow().is_downloadable(*id))
        {
            Some(index) => {
                self.url_queue.swap_remove_front(index).unwrap()
            }
            None => {
                if !QUIET {
                    println!("None of the URLs are currently downloadable.");
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
                println!(
                    "Successfully created stream id {} for {}",
                    client_stream_id, url
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
                println!("Cannot create stream {:?}", e);
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
            println!("Checking if done: streams is empty: {:?} | url_queue is empty: {:?} | is done shaping: {:?}", new_state.0, new_state.1, new_state.2);
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
            let pending_streams = self.streams.keys().cloned().collect::<Vec<u64>>();
            println!("Pending streams: {:?}", pending_streams);
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
                    Some(((id, _), out_file)) => {
                        if out_file.is_none() && !QUIET {
                            println!("READ HEADERS[{}]: fin={} {:?}", stream_id, fin, headers);
                        }

                        if fin {
                            if out_file.is_none() {
                                println!("<FIN[{}]>", stream_id);
                            }

                            self.url_deps.borrow_mut().resource_downloaded(*id);
                            self.download_urls(client);
                            self.streams.remove(&stream_id);

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
                        println!("Data on unexpected stream: {}", stream_id);
                        return Ok(false);
                    }
                },
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut stream_done = false;
                    match self.streams.get_mut(&stream_id) {
                        None => {
                            println!("Data on unexpected stream: {}", stream_id);
                            return Ok(false);
                        }
                        Some(((id, _), out_file)) => loop {
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
                                    println!("READ[{}]: {} bytes", stream_id, sz); 
                                }
                            } else if let Ok(txt) = String::from_utf8(data.clone()) {
                                if !QUIET {
                                    println!("READ[{}]: {}", stream_id, txt);
                                }
                            } else {
                                if !QUIET {
                                    println!("READ[{}]: 0x{}", stream_id, hex(&data));
                                }
                            }

                            if fin {
                                if out_file.is_none() {
                                    println!("<FIN[{}]>", stream_id);
                                }

                                self.url_deps.borrow_mut().resource_downloaded(*id);
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
                    println!("Unhandled resumption token.");
                }
                _ => {
                    println!("Unhandled event {:?}", event);
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
        }
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


fn build_flow_shaper(args: &ShapingArgs, resources: Vec<Resource>, header: &Vec<String>) -> Option<FlowShaper> {
    let defence = args.defence.as_deref();
    if matches!(defence, None | Some("none")) {
        return None;
    }
    let defence_type = defence.unwrap();

    println!("Enabling connection shaping.");

    let mut builder = FlowShaperBuilder::new();
    let (mut config, mut front_config) = match args.shaper_config.clone() {
        Some(filename) => {
            let configs = ConfigFile::load(&filename)
                .expect("Unable to load config file");

            (configs.flow_shaper.unwrap_or(FlowShaperConfig::default()),
             configs.front_defence.unwrap_or(FrontConfig::default()))
        },
        None => (FlowShaperConfig::default(), FrontConfig::default())
    };

    if let Some(value) = args.msd_limit_excess {
        config.max_stream_data_excess = value;
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

    if let Some(filename) = args.chaff_ids_log.as_ref() {
        builder.chaff_ids_log(filename);
    }
    if let Some(filename) = args.defence_event_log.as_ref() {
        builder.defence_event_log(filename);
    }

    let defence: Box<dyn Defencev2> = match defence_type {
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
    println!("Defence: {:?}", defence);

    Some(builder.from_defence(defence))
}


fn client(
    args: &Args,
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    hostname: &str,
    url_deps: Rc<RefCell<UrlDependencyTracker>>,
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
        (_, true) => url_deps.borrow().select_padding_urls(n_urls)
            .into_iter().map(|x| x.into()).collect(),
        (_, false) => url_deps.borrow().select_padding_urls_by_size(n_urls) 
    };

    if let Some(flow_shaper) = build_flow_shaper(
        &args.shaping_args, chaff_resources, &args.header)
    {
        client = client.with_flow_shaper(flow_shaper);
        shaping = true;
    }

    let qlog = qlog_new(args, hostname, client.connection_id())?;
    client.set_qlog(qlog);

    let key_update = KeyUpdateState(args.key_update);
    let url_queue = VecDeque::from(url_deps.borrow().urls());
    let mut h = Handler {
        streams: HashMap::new(),
        url_queue,
        all_paths: Vec::new(),
        args: &args,
        key_update,
        url_deps,
        is_done_shaping: !shaping,
        completion_state: (false, false, !shaping)
    };

    process_loop(&local_addr, &remote_addr, &socket, &mut client, &mut h)?;

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
    let url_deps = Rc::new(RefCell::new(url_deps));

    if let Some(testcase) = args.qns_test.as_ref() {
        match testcase.as_str() {
            "http3" => {}
            "handshake" | "transfer" | "retry" => {
                args.use_old_http = true;
            }
            "zerortt" | "resumption" => {
                if args.urls.len() < 2 {
                    eprintln!("Warning: resumption tests won't work without >1 URL");
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

    let mut urls_by_origin: HashMap<Origin, Vec<Url>> = HashMap::new();
    for url in &args.urls {
        let entry = urls_by_origin.entry(url.origin()).or_default();
        entry.push(url.clone());
    }

    for ((_scheme, host, port), urls) in urls_by_origin.into_iter().filter_map(|(k, v)| match k {
        Origin::Tuple(s, h, p) => Some(((s, h, p), v)),
        Origin::Opaque(x) => {
            eprintln!("Opaque origin {:?}", x);
            None
        }
    }) {
        let addrs: Vec<_> = format!("{}:{}", host, port).to_socket_addrs()?.collect();
        let remote_addr = *addrs.first().unwrap();

        let local_addr = match remote_addr {
            SocketAddr::V4(..) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0; 4])), 0),
            SocketAddr::V6(..) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0),
        };

        let socket = match UdpSocket::bind(local_addr) {
            Err(e) => {
                eprintln!("Unable to bind UDP socket: {}", e);
                exit(1)
            }
            Ok(s) => s,
        };
        socket
            .connect(&remote_addr)
            .expect("Unable to connect UDP socket");

        println!(
            "{} Client connecting: {:?} -> {:?}",
            if args.use_old_http { "H9" } else { "H3" },
            socket.local_addr().unwrap(),
            remote_addr
        );

        if !args.use_old_http {
            client(
                &args,
                socket,
                local_addr,
                remote_addr,
                &format!("{}", host),
                url_deps.clone(),
            )?;
        } else if !args.download_in_series {
            let token = if args.resume {
                // Download first URL using a separate connection, save the token and use it for
                // the remaining URLs
                if urls.len() < 2 {
                    eprintln!("Warning: resumption tests won't work without >1 URL");
                    exit(127)
                }

                old::old_client(
                    &args,
                    &socket,
                    local_addr,
                    remote_addr,
                    &format!("{}", host),
                    &urls[..1],
                    None,
                )?
            } else {
                None
            };

            old::old_client(
                &args,
                &socket,
                local_addr,
                remote_addr,
                &format!("{}", host),
                &urls[1..],
                token,
            )?;
        } else {
            let mut token: Option<ResumptionToken> = None;

            for url in urls {
                token = old::old_client(
                    &args,
                    &socket,
                    local_addr,
                    remote_addr,
                    &format!("{}", host),
                    &[url],
                    token,
                )?;
            }
        }
    }

    Ok(())
}

mod old {
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::fs::File;
    use std::io::{ErrorKind, Write};
    use std::net::{SocketAddr, UdpSocket};
    use std::path::PathBuf;
    use std::process::exit;
    use std::rc::Rc;
    use std::time::Instant;

    use url::Url;

    use super::{qlog_new, KeyUpdateState, Res};

    use neqo_common::{event::Provider, Datagram};
    use neqo_crypto::{AuthenticationStatus, ResumptionToken};
    use neqo_transport::{
        CongestionControlAlgorithm, Connection, ConnectionEvent, Error, FixedConnectionIdManager,
        Output, QuicVersion, State, StreamType,
    };

    use super::{emit_datagram, get_output_file, Args};

    struct HandlerOld<'b> {
        streams: HashMap<u64, Option<File>>,
        url_queue: VecDeque<Url>,
        all_paths: Vec<PathBuf>,
        args: &'b Args,
        token: Option<ResumptionToken>,
        key_update: KeyUpdateState,
    }

    impl<'b> HandlerOld<'b> {
        fn download_urls(&mut self, client: &mut Connection) {
            loop {
                if self.url_queue.is_empty() {
                    break;
                }
                if !self.download_next(client) {
                    break;
                }
            }
        }

        fn download_next(&mut self, client: &mut Connection) -> bool {
            if self.key_update.needed() {
                println!("Deferring requests until after first key update");
                return false;
            }
            let url = self
                .url_queue
                .pop_front()
                .expect("download_next called with empty queue");
            match client.stream_create(StreamType::BiDi) {
                Ok(client_stream_id) => {
                    println!("Successfully created stream id {}", client_stream_id);
                    let req = format!("GET {}\r\n", url.path());
                    client
                        .stream_send(client_stream_id, req.as_bytes())
                        .unwrap();
                    let _ = client.stream_close_send(client_stream_id);
                    let out_file =
                        get_output_file(&url, &self.args.output_dir, &mut self.all_paths);
                    self.streams.insert(client_stream_id, out_file);
                    true
                }
                e @ Err(Error::StreamLimitError) | e @ Err(Error::ConnectionState) => {
                    println!("Cannot create stream {:?}", e);
                    self.url_queue.push_front(url);
                    false
                }
                Err(e) => {
                    panic!("Can't create stream {}", e);
                }
            }
        }

        /// Read and maybe print received data from a stream.
        // Returns bool: was fin received?
        fn read_from_stream(
            client: &mut Connection,
            stream_id: u64,
            output_read_data: bool,
            maybe_out_file: &mut Option<File>,
        ) -> Res<bool> {
            let mut data = vec![0; 4096];
            loop {
                let (sz, fin) = client.stream_recv(stream_id, &mut data)?;
                if sz == 0 {
                    return Ok(fin);
                }

                if let Some(out_file) = maybe_out_file {
                    out_file.write_all(&data[..sz])?;
                } else if !output_read_data {
                    println!("READ[{}]: {} bytes", stream_id, sz);
                } else {
                    println!(
                        "READ[{}]: {}",
                        stream_id,
                        String::from_utf8(data.clone()).unwrap()
                    )
                }
                if fin {
                    return Ok(true);
                }
            }
        }

        fn maybe_key_update(&mut self, c: &mut Connection) -> Res<()> {
            self.key_update.maybe_update(|| c.initiate_key_update())?;
            self.download_urls(c);
            Ok(())
        }

        fn handle(&mut self, client: &mut Connection) -> Res<bool> {
            while let Some(event) = client.next_event() {
                match event {
                    ConnectionEvent::AuthenticationNeeded => {
                        client.authenticated(AuthenticationStatus::Ok, Instant::now());
                    }
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        let mut maybe_maybe_out_file = self.streams.get_mut(&stream_id);
                        match &mut maybe_maybe_out_file {
                            None => {
                                println!("Data on unexpected stream: {}", stream_id);
                                return Ok(false);
                            }
                            Some(maybe_out_file) => {
                                let fin_recvd = Self::read_from_stream(
                                    client,
                                    stream_id,
                                    self.args.output_read_data,
                                    maybe_out_file,
                                )?;

                                if fin_recvd {
                                    if maybe_out_file.is_none() {
                                        println!("<FIN[{}]>", stream_id);
                                    }
                                    self.streams.remove(&stream_id);
                                    if self.streams.is_empty() && self.url_queue.is_empty() {
                                        client.close(Instant::now(), 0, "kthxbye!");
                                        return Ok(false);
                                    }
                                }
                            }
                        }
                    }
                    ConnectionEvent::SendStreamWritable { stream_id } => {
                        println!("stream {} writable", stream_id)
                    }
                    ConnectionEvent::SendStreamComplete { stream_id } => {
                        println!("stream {} complete", stream_id);
                    }
                    ConnectionEvent::SendStreamCreatable { stream_type } => {
                        println!("stream {:?} creatable", stream_type);
                        if stream_type == StreamType::BiDi {
                            self.download_urls(client);
                        }
                    }
                    ConnectionEvent::StateChange(State::WaitInitial)
                    | ConnectionEvent::StateChange(State::Handshaking)
                    | ConnectionEvent::StateChange(State::Connected) => {
                        println!("{:?}", event);
                        self.download_urls(client);
                    }
                    ConnectionEvent::StateChange(State::Confirmed) => {
                        self.maybe_key_update(client)?;
                    }
                    ConnectionEvent::ResumptionToken(token) => {
                        self.token = Some(token);
                    }
                    _ => {
                        println!("Unhandled event {:?}", event);
                    }
                }
            }

            Ok(true)
        }
    }

    fn process_loop_old(
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        socket: &UdpSocket,
        client: &mut Connection,
        handler: &mut HandlerOld,
    ) -> Res<State> {
        let buf = &mut [0u8; 2048];
        loop {
            if let State::Closed(..) = client.state() {
                return Ok(client.state().clone());
            }

            let mut exiting = !handler.handle(client)?;

            loop {
                let output = client.process_output(Instant::now());
                match output {
                    Output::Datagram(dgram) => {
                        if let Err(e) = emit_datagram(&socket, Some(dgram)) {
                            eprintln!("UDP write error: {}", e);
                            client.close(Instant::now(), 0, e.to_string());
                            exiting = true;
                            break;
                        }
                    }
                    Output::Callback(duration) => {
                        socket.set_read_timeout(Some(duration)).unwrap();
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
                return Ok(client.state().clone());
            }

            let sz = match socket.recv(&mut buf[..]) {
                Err(ref err)
                    if err.kind() == ErrorKind::WouldBlock
                        || err.kind() == ErrorKind::Interrupted =>
                {
                    0
                }
                Err(err) => {
                    eprintln!("UDP error: {}", err);
                    exit(1)
                }
                Ok(sz) => sz,
            };
            if sz == buf.len() {
                eprintln!("Received more than {} bytes", buf.len());
                continue;
            }
            if sz > 0 {
                let d = Datagram::new(*remote_addr, *local_addr, &buf[..sz]);
                client.process_input(d, Instant::now());
                handler.maybe_key_update(client)?;
            }
        }
    }

    pub fn old_client(
        args: &Args,
        socket: &UdpSocket,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        origin: &str,
        urls: &[Url],
        token: Option<ResumptionToken>,
    ) -> Res<Option<ResumptionToken>> {
        let (quic_protocol, alpn) = match args.alpn.as_str() {
            "hq-27" => (QuicVersion::Draft27, "hq-27"),
            "hq-28" => (QuicVersion::Draft28, "hq-28"),
            "hq-30" => (QuicVersion::Draft30, "hq-30"),
            _ => (QuicVersion::Draft29, "hq-29"),
        };

        let mut client = Connection::new_client(
            origin,
            &[alpn],
            Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
            local_addr,
            remote_addr,
            &CongestionControlAlgorithm::NewReno,
            quic_protocol,
        )?;

        if let Some(tok) = token {
            client.enable_resumption(Instant::now(), tok)?;
        }

        let ciphers = args.get_ciphers();
        if !ciphers.is_empty() {
            client.set_ciphers(&ciphers)?;
        }

        client.set_qlog(qlog_new(args, origin, &client.odcid().unwrap())?);

        let key_update = KeyUpdateState(args.key_update);
        let mut h = HandlerOld {
            streams: HashMap::new(),
            url_queue: VecDeque::from(urls.to_vec()),
            all_paths: Vec::new(),
            args: &args,
            token: None,
            key_update,
        };

        process_loop_old(&local_addr, &remote_addr, &socket, &mut client, &mut h)?;

        let token = if args.resume {
            // If we haven't received an event, take a token if there is one.
            // Lots of servers don't provide NEW_TOKEN, but a session ticket
            // without NEW_TOKEN is better than nothing.
            h.token
                .or_else(|| client.take_resumption_token(Instant::now()))
        } else {
            None
        };
        Ok(token)
    }
}
