use std::fs::File;
use std::io::{self, BufRead};
use std::num;
use std::time::{ Duration, Instant };
use std::collections::{ HashMap, VecDeque, HashSet };
use std::convert::TryFrom;
use std::cmp::max;
use std::cell::RefCell;
use rand::Rng; // for rayleigh sampling
use std::fmt::Display;

use neqo_common::{
    qdebug, qinfo, qlog::NeqoQlog, qtrace
};

use crate::stream_id::StreamId;


const DEBUG_INITIAL_MAX_DATA: u64 = 3000;

const DEBUG_PAD_PACKET_SIZE: i32 = 1000;

// The value below is taken from the QUIC Connection class and defines the 
// buffer that is allocated for receiving data.
const RX_STREAM_DATA_WINDOW: u64 = 0x10_0000; // 1MiB
// taken from transport connection
const LOCAL_MAX_DATA: u64 = 0x3FFF_FFFF_FFFF_FFFF; // 2^62-1


#[derive(Debug)]
pub enum TraceLoadError {
    Io(io::Error),
    Parse(String),
}

impl From<num::ParseIntError> for TraceLoadError {
    fn from(err: num::ParseIntError) -> TraceLoadError {
        TraceLoadError::Parse(err.to_string())
    }
}

impl From<num::ParseFloatError> for TraceLoadError {
    fn from(err: num::ParseFloatError) -> TraceLoadError {
        TraceLoadError::Parse(err.to_string())
    }
}

impl From<io::Error> for TraceLoadError {
    fn from(err: io::Error) -> TraceLoadError {
        TraceLoadError::Io(err)
    }
}


type Trace = Vec<(Duration, i32)>;

pub fn load_trace(filename: &str) -> Result<Trace, TraceLoadError> {
    let mut packets = Vec::new();

    let file = File::open(filename)?;
    for line in io::BufReader::new(file).lines() {
        let line = line?;
        let mut line_iter = line.split(",");
        let timestamp: f64 = line_iter.next()
            .ok_or(TraceLoadError::Parse("no timestamp".to_owned()))
            .and_then(|s| s.parse::<f64>().map_err(TraceLoadError::from))?;
        let size: i32 = line_iter.next()
            .ok_or(TraceLoadError::Parse("no size".to_owned()))
            .and_then(|s| s.parse::<i32>().map_err(TraceLoadError::from))?;

        packets.push((Duration::from_secs_f64(timestamp), size));
    }

    Ok(packets)
}

// TODO(ldolfi): possibly use rgsl.randist.rayleigh
fn rayleigh_cdf_inv(u: f64, sigma: u64) -> f64{
    let foo = (1.-u).ln();
    let bar = (-2.*foo).sqrt();

    return (sigma as f64)*bar;
}


#[derive(Debug, Eq, PartialEq)]
pub enum FlowShapingEvent {
    SendMaxData(u64),
    SendMaxStreamData { stream_id: u64, new_limit: u64 },
    SendPaddingFrames(u32),
    CloseConnection,
}

#[derive(Debug, Default)]
struct FlowShapingEvents {
    // This is in a RefCell to allow borrowing a mutable reference in an
    // immutable context
    events: RefCell<VecDeque<FlowShapingEvent>>
}

impl FlowShapingEvents {
    pub(self) fn send_max_data(&self, new_limit: u64) {
        self.insert(FlowShapingEvent::SendMaxData(new_limit));
    }

    pub fn send_max_stream_data(&self, stream_id: StreamId, new_limit: u64) {
        self.insert(FlowShapingEvent::SendMaxStreamData {
            stream_id: stream_id.as_u64(), new_limit
        });
    }

    pub(self) fn send_pad_frames(&self, pad_size: u32) {
        self.insert(FlowShapingEvent::SendPaddingFrames(pad_size));
    }

    pub(self) fn send_connection_close(&self) {
        self.insert(FlowShapingEvent::CloseConnection)
    }

    fn insert(&self, event: FlowShapingEvent) {
        self.events.borrow_mut().push_back(event);
    }


    /// Pop the first max_stream_data event with the specified stream 
    /// id. Return true iff the event was found and removed.
    pub(self) fn cancel_max_stream_data(&self, stream_id: StreamId) -> bool {
        type FSE = FlowShapingEvent;

        let position = self.events.borrow().iter().position(|item| match item {
            FSE::SendMaxStreamData { stream_id: sid, .. } => *sid == stream_id.as_u64(),
            _ => false
        });

        match position {
            Some(index) => {
                self.events.borrow_mut().remove(index);
                true
            },
            None => false
        }
    }

    #[must_use]
    pub fn next_event(&mut self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().pop_front()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }
}

#[derive(Debug, Default)]
struct FlowShapingStreams {
    // Hash set keeping track of stream ids of streams currently being shaped
    streams: RefCell<HashSet<u64>>
}

impl FlowShapingStreams {
    // add a padding stream to the shaping streams
    pub(self) fn add_padding_stream(&self, stream_id: u64) -> bool {
        self.streams.borrow_mut().insert(stream_id)
    }

    pub(self) fn contains(&self, stream_id: u64) -> bool {
        self.streams.borrow().contains(&stream_id)
    }
}


/// Shaper for the connection. Assumes that it operates on the client,
/// and not the server.
#[derive(Debug)]
pub struct FlowShaper {
    // The control interval
    interval: Duration,

    out_target: VecDeque<(u32, u32)>,
    in_target: VecDeque<(u32, u32)>,

    start_time: Option<Instant>,

    // The current maximum amount of data that may be received
    // on the connection.
    rx_max_data: u64,
    rx_progress: u64,

    events: FlowShapingEvents,

    // padding parameters
    padding_params: HashMap <String, u64>,
    pad_out_target: VecDeque <(u32, u32)>,
    pad_in_target: VecDeque <(u32, u32)>,
    shaping_streams: FlowShapingStreams,

}

impl Display for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QCD FlowShaper")
    }
}


impl FlowShaper {
    /// Start shaping the traffic using the current time as the reference
    /// point.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Report the next instant at which the FlowShaper should be called for
    /// processing events.
    pub fn next_signal_time(&self) -> Option<Instant> {
        self.in_target.front()
            .map(|(ts, _)| Duration::from_millis(u64::from(*ts)))
            .zip(self.start_time)
            .map(|(dur, start)| max(start + dur, Instant::now()))
    }

    pub fn process_timer(&mut self, now: Instant) {
        if let Some(start_time) = self.start_time {
            self.process_timer_(now.duration_since(start_time));
        }
    }

    fn process_timer_(&mut self, since_start: Duration) {
        if let Some((ts, _)) = self.in_target.front() {
            let next = Duration::from_millis(u64::from(*ts));
            if next < since_start {
                let (_, size) = self.in_target.pop_front()
                    .expect("the deque to be non-empty");

                self.rx_progress = self.rx_progress.saturating_add(u64::from(size));
                if self.rx_progress > self.rx_max_data {
                    self.events.send_max_stream_data(StreamId::new(0), self.rx_progress);
                }
            }
        }
        // add padding
        if let Some((ts, _)) = self.pad_out_target.front() {
            let next = Duration::from_millis(u64::from(*ts));
            if next < since_start {
                let (_, size) = self.pad_out_target.pop_front()
                    .expect("the deque to be non-empty");
                
                self.events.send_pad_frames(size);
            }
        }

        // check dequeues empty, if so send connection close event
        // TODO (ldolfi): use check only on dequeues actually in use
        if self.in_target.is_empty() && self.pad_out_target.is_empty() {
            self.events.send_connection_close();
        }
    }

    pub fn new(interval: Duration, trace: &Trace) -> FlowShaper {
        assert!(trace.len() > 0);

        // Bin the trace
        let mut bins: HashMap<(u32, bool), i32> = HashMap::new();
        let interval_ms = interval.as_millis();

        for (timestamp, size) in trace.iter() {
            let timestamp = timestamp.as_millis();
            let bin = u32::try_from(timestamp - (timestamp % interval_ms))
                .expect("timestamp in millis to fit in u32");

            assert!(*size != 0, "trace sizes should be non-zero");
            bins.entry((bin, *size > 0))
                .and_modify(|e| *e += size)
                .or_insert(*size);
        }

        let mut in_target: Vec<(u32, u32)> = bins
            .iter()
            .filter(|&((_, inc), _)| !*inc)
            .map(|((ts, _), size)| (*ts, u32::try_from(size.abs()).unwrap()))
            .collect();
        in_target.sort();

        let mut out_target: Vec<(u32, u32)> = bins
            .iter()
            .filter(|((_, inc), _)| *inc)
            .map(|((ts, _), size)| (*ts, u32::try_from(*size).unwrap()))
            .collect();
        out_target.sort();

        FlowShaper{
            interval,
            in_target: VecDeque::from(in_target),
            out_target: VecDeque::from(out_target),
            start_time: None,
            rx_max_data: DEBUG_INITIAL_MAX_DATA,
            rx_progress: 0,
            events: FlowShapingEvents::default(),
            padding_params: HashMap::new(),
            pad_out_target: VecDeque::new(),
            pad_in_target: VecDeque::new(),
            shaping_streams: FlowShapingStreams::default(),
        }
    }

    /// Create a new FlowShaper from a CSV trace file
    pub fn new_from_file(filename: &str, interval: Duration) -> Result<Self, TraceLoadError> {
        load_trace(filename).map(|trace| Self::new(interval, &trace))
    }

    /// Return the initial values for transport parameters
    pub fn tparam_defaults() -> [(u64, u64); 3] {
        [
            (0x04, LOCAL_MAX_DATA),
            // Disable the peer sending data on bidirectional streams openned
            // by this endpoint (initial_max_stream_data_bidi_local)
            (0x05, 20),
            // Disable the peer sending data on bidirectional streams that
            // they open (initial_max_stream_data_bidi_remote)
            (0x06, 20),
            // Disable the peer sending data on unidirectional streams that
            // they open (initial_max_stream_data_uni)
            // (0x07, 20),
        ]
    }

    // Return the default values for padding trace
    // currently set to parametrs in Gong2020
    pub fn pparam_defaults() -> [(String, u64); 4] {
        [
            // Client's padding budget in number of packets
            ("pad_client_max_n".to_string(), 2500),
            // minimum padding time in seconds
            ("pad_max_w".to_string(), 3),
            // maximum padding time in seconds
            ("pad_min_w".to_string(), 1),
            // Client's padding budget in number of packets
            ("pad_server_max_n".to_string(), 2500),
        ]
    }

    pub fn set_padding_param(&mut self, k: String, v: u64) {
        self.padding_params.insert(k,v);
    }

    // creates new Trace of dummy packets sampled from rayleigh distribution
    pub fn new_padding_trace(&self) -> Result<Trace, TraceLoadError>{
        qinfo!([self], "Creating padding traces.");
        let mut schedule = Vec::new();
        // get params
        let cpacket_budget = match self.padding_params.get("pad_client_max_n") {
            Some(v) => v,
            None => return Err(TraceLoadError::Parse("padding parameter not found".to_string()))
        };
        let min_w = match self.padding_params.get("pad_min_w") {
            Some(v) => v,
            None => return Err(TraceLoadError::Parse("padding parameter not found".to_string()))
        };
        let max_w = match self.padding_params.get("pad_max_w") {
            Some(v) => v,
            None => return Err(TraceLoadError::Parse("padding parameter not found".to_string()))
        };
        let spacket_budget = match self.padding_params.get("pad_server_max_n") {
            Some(v) => v,
            None => return Err(TraceLoadError::Parse("padding parameter not found".to_string()))
        };
        // sample n_C and w_c
        let _n_c: u64 = rand::thread_rng().gen_range(1,cpacket_budget+1);
        let _w_c: u64 = rand::thread_rng().gen_range(*min_w,max_w+1);
        println!("n_c: {}\tw_c: {}", _n_c, _w_c);
        // sample timetable
        let mut count = 0u64;
        let mut t;
        while count < _n_c {
            count += 1;
            let u: f64 = rand::thread_rng().gen_range(0.,1.);
            t = rayleigh_cdf_inv(u, _w_c);
            schedule.push((Duration::from_secs_f64(t), DEBUG_PAD_PACKET_SIZE as i32));
            println!("{}.  {}", count, t);
        }
        // sample n_s
        let _n_s: u64 = rand::thread_rng().gen_range(1,spacket_budget+1);
        let _w_s: u64 = rand::thread_rng().gen_range(*min_w,max_w+1);
        println!("n_s: {}\tw_s: {}", _n_s, _w_s);
        // sample timetable
        count = 0;
        let mut t;
        while count < _n_s {
            count += 1;
            let u: f64 = rand::thread_rng().gen_range(0.,1.);
            t = rayleigh_cdf_inv(u, _w_s);
            schedule.push((Duration::from_secs_f64(t), -DEBUG_PAD_PACKET_SIZE as i32));
            println!("{}.  {}", count, t);
        }

        return Ok(schedule);
    }

    pub fn set_padding_trace(&mut self, interval: Duration, trace: &Trace) {
        assert!(trace.len() > 0);

        // Bin the trace
        let mut bins: HashMap<(u32, bool), i32> = HashMap::new();
        let interval_ms = interval.as_millis();

        for (timestamp, size) in trace.iter() {
            let timestamp = timestamp.as_millis();
            let bin = u32::try_from(timestamp - (timestamp % interval_ms))
                .expect("timestamp in millis to fit in u32");

            assert!(*size != 0, "trace sizes should be non-zero");
            bins.entry((bin, *size > 0))
                .and_modify(|e| *e += size)
                .or_insert(*size);
        }
        // padding frames should now be added here according to schedule
        // let mut pad_out_target: Vec<(u32, u32)> = bins
        //     .iter()
        //     .map(|((ts, _), size)| (*ts, u32::try_from(*size).unwrap()))
        //     .collect();
        // pad_out_target.sort();

        let mut pad_in_target: Vec<(u32, u32)> = bins
            .iter()
            .filter(|&((_, inc), _)| !*inc)
            .map(|((ts, _), size)| (*ts, u32::try_from(size.abs()).unwrap()))
            .collect();
        pad_in_target.sort();

        let mut pad_out_target: Vec<(u32, u32)> = bins
            .iter()
            .filter(|((_, inc), _)| *inc)
            .map(|((ts, _), size)| (*ts, u32::try_from(*size).unwrap()))
            .collect();
        pad_out_target.sort();

        self.pad_out_target = VecDeque::from(pad_out_target);
        self.pad_in_target = VecDeque::from(pad_in_target);
    }

    /// Queue events related to a new stream being created by the peer.
    pub fn on_stream_incoming(&self, stream_id: u64) {
        let stream_id = StreamId::new(stream_id);
        assert!(stream_id.is_server_initiated());
        assert!(stream_id.is_uni(), "Servers dont initiate BiDi streams in HTTP3");

        // Do nothing, as unidirectional streams were not flow controlled
    }

    /// Queue events related to a new stream being created by this
    /// endpoint.
    pub fn on_stream_created(&self, stream_id: u64) {
        let stream_id = StreamId::new(stream_id);
        assert!(stream_id.is_client_initiated());

        if stream_id.is_bidi() {
            self.events.send_max_stream_data(stream_id, RX_STREAM_DATA_WINDOW);
            qdebug!([self], "Added send_max_stream_data event to stream {} limit {}", stream_id, RX_STREAM_DATA_WINDOW);
        }
    }

    /// Records the creation of a stream for padding.
    ///
    /// Assumes that no events have been dequeud since the call of the
    /// associated `on_new_stream` call for the `stream_id`.
    pub fn on_new_padding_stream(&self, stream_id: u64) {
        assert!(self.events.cancel_max_stream_data(StreamId::new(stream_id)));
        qdebug!([self], "Removed max stream data event from stream {}", stream_id);
        self.add_padding_stream(stream_id);
    }

    pub fn add_padding_stream(&self, stream_id: u64) {
        assert!(self.shaping_streams.add_padding_stream(stream_id));
    }

    // returns true if the stream_id is contained in the set of streams
    // being currently shaped
    pub fn is_shaping_stream(&self, stream_id: u64) -> bool {
        self.shaping_streams.contains(stream_id)
    }

    pub fn next_event(&mut self) -> Option<FlowShapingEvent> {
        self.events.next_event()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        self.events.has_events()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    type FSE = FlowShapingEvent;

    const CLIENT_BIDI_STREAM_ID: u64 = 0b100;
    const SERVER_BIDI_STREAM_ID: u64 = 0b101;
    const CLIENT_UNI_STREAM_ID: u64 =  0b110;
    const SERVER_UNI_STREAM_ID: u64 =  0b111;

    fn create_shaper() -> FlowShaper {
        let vec = vec![
                (Duration::from_millis(2), 1350), (Duration::from_millis(16), -4800),
                (Duration::from_millis(21), 600), (Duration::from_millis(22), -350),
            ];
        FlowShaper::new(Duration::from_millis(5), &vec)
    }

    #[test]
    fn test_sanity() {
        let trace = load_trace("../data/nytimes.csv").expect("Load failed");
        FlowShaper::new(Duration::from_millis(10), &trace);
    }

    #[test]
    fn test_next_signal_time() {
        let mut shaper = create_shaper();
        assert_eq!(shaper.next_signal_time(), None);

        shaper.start();
        assert_eq!(shaper.next_signal_time(),
                   Some(shaper.start_time.unwrap() + Duration::from_millis(15)))
    }

    #[test]
    fn test_process_timer() {
        let mut shaper = create_shaper();

        shaper.process_timer_(Duration::from_millis(3));
        assert_eq!(shaper.next_event(), None);

        shaper.process_timer_(Duration::from_millis(17));
        shaper.process_timer_(Duration::from_millis(21));

        assert_eq!(shaper.next_event(), Some(FSE::SendMaxData(4800)));
        assert_eq!(shaper.next_event(), Some(FSE::SendMaxData(5150)));
    }

    #[test]
    fn test_on_stream_created_uni() {
        // It's a unidirectional stream, so we do not queue any events
        let mut shaper = create_shaper();
        shaper.on_stream_created(CLIENT_UNI_STREAM_ID);
        assert_eq!(shaper.next_event(), None);
    }

    #[test]
    fn test_on_stream_created_bidi() {
        // It's a unidirectional stream, so we do not queue any events
        let mut shaper = create_shaper();
        shaper.on_stream_created(CLIENT_BIDI_STREAM_ID);
        assert_eq!(
            shaper.events.next_event(),
            Some(FSE::SendMaxStreamData {
                stream_id: CLIENT_BIDI_STREAM_ID, new_limit: RX_STREAM_DATA_WINDOW
            }));
    }

    #[test]
    fn test_on_stream_created_bidi_padding() {
        // If a stream is identified as being for a padding URL, its max data
        // should not be increased
        let mut shaper = create_shaper();

        shaper.on_stream_created(CLIENT_BIDI_STREAM_ID);
        shaper.on_new_padding_stream(CLIENT_BIDI_STREAM_ID);
        assert_eq!(shaper.events.next_event(), None);
    }

    #[test]
    fn test_on_stream_incoming_uni() {
        let mut shaper = create_shaper();
        shaper.on_stream_incoming(SERVER_UNI_STREAM_ID);

        // Incoming Unidirectional streams are not blocked initially, as we do not 
        // expect padding resources to arrive on them.
        assert_eq!(shaper.events.next_event(), None);
    }

    #[test]
    #[should_panic]
    fn test_on_stream_incoming_bidi() {
        // We assume that the server never opens bidi streams in H3
        let shaper = create_shaper();
        shaper.on_stream_incoming(SERVER_BIDI_STREAM_ID);
    }

}
