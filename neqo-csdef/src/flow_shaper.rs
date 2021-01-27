use std::time::{ Duration, Instant };
use std::collections::{ HashMap, VecDeque, HashSet };
use std::convert::TryFrom;
use csv::{self, Writer};
use serde::{Deserialize};
use std::cmp::max;
use std::env; // for reading env variables
use std::fmt::Display;
use std::fs::OpenOptions;
use url::Url;

use neqo_common::{ qdebug, qwarn, qtrace };

use crate::{ Result, dummy_schedule_log_file };
use crate::stream_id::StreamId;
use crate::defences::Defence;
use crate::chaff_stream::ChaffStreamMap;
use crate::events::{ FlowShapingEvents, FlowShapingApplicationEvents };
pub use crate::events::{ FlowShapingEvent };


fn debug_check_var_(env_key: &str) -> bool {
    match env::var(env_key) {
        Ok(s) => s != "",
        _ => false
    }
}

fn debug_save_ids_path() -> String {
    match env::var("CSDEF_DUMMY_ID") {
        Ok(s) => s,
        _ => String::from("")
    }
}

fn debug_enable_save_ids() -> bool {
    debug_check_var_("CSDEF_DUMMY_ID")
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// The control interval in milliseconds
    control_interval: u64,
    initial_md: u64,
    rx_stream_data_window: u64,
    local_md: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            control_interval: 5,
            initial_md: 3000,
            rx_stream_data_window: 1048576,
            local_md: 4611686018427387903,
        }
    }
}

type Trace = Vec<(Duration, i32)>;

pub fn load_trace(filename: &str) -> Result<Trace> {
    let mut packets: Trace = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(filename)?;

    for result in reader.deserialize() {
        let record: (f64, i32) = result?;
        packets.push((Duration::from_secs_f64(record.0), record.1));
    }

    Ok(packets)
}

fn log_trace(trace: &Trace) -> Result<()> {
    if let Some(csv_path) = dummy_schedule_log_file() {
        let mut wtr = Writer::from_path(csv_path)?;

        for (d, s) in trace.iter() {
            wtr.write_record(&[d.as_secs_f64().to_string(), s.to_string()])?;
        }
        wtr.flush()?;
    }

    Ok(())
}



// #[derive(Debug, Default)]
// struct FlowShapingStreams {
//     // HashMap keeping track of stream ids of streams currently being shaped
//     // For each id keeps the Url of dummy resource and flag indicating
//     // if the stream is ready to receive MSD
//     streams: RefCell<HashMap<u64, Url>>,
//     is_open: RefCell<HashMap<u64, bool>>,
//     max_stream_datas: RefCell<HashMap<u64,u64>>,
// }
//
// impl FlowShapingStreams {
//     // add a padding stream to the shaping streams
//     pub(self) fn add_padding_stream(&self, stream_id: u64, dummy_url: Url) -> bool {
//         self.is_open.borrow_mut().insert(stream_id, false);
//         self.streams.borrow_mut().insert(stream_id, dummy_url).is_none()
//     }
//
//     pub(self) fn open_stream(&self, stream_id: u64) -> bool {
//         self.is_open.borrow_mut().insert(stream_id, true).is_some()
//     }
//
//     pub(self) fn remove_dummy_stream(&self, stream_id: &u64) -> Option<Url> {
//         self.is_open.borrow_mut().remove(stream_id);
//         self.max_stream_datas.borrow_mut().remove(stream_id);
//         self.streams.borrow_mut().remove(stream_id)
//     }
//
//     pub(self) fn contains(&self, stream_id: u64) -> bool {
//         self.streams.borrow().contains_key(&stream_id)
//     }
//
//     pub(self) fn insert(&self, stream_id: u64, max_stream_data: u64) -> Option<u64> {
//         self.max_stream_datas.borrow_mut().insert(stream_id, max_stream_data)
//     }
//
//     // pub(self) fn len(&self) -> usize {
//     //     self.streams.borrow().len()
//     // }
//
//     pub(self) fn is_open(&self, stream_id: u64) -> bool {
//         if let Some(open) = self.is_open.borrow().get(&stream_id) {
//             return *open;
//         } else {
//             return false;
//         }
//     }
//     // returns true if any of the shaping streams is open
//     pub(self) fn has_open(&self) -> bool {
//         for s in self.is_open.borrow().values() {
//             if *s {return true;}
//         }
//         false
//     }
//
//     // pub(self) fn get(&self, stream_id: StreamId) -> Option<&u64> {
//     //     self.max_stream_datas.borrow().get(&stream_id)
//     // }
//
//     // pub(self) fn get_mut(&self, stream_id: StreamId) -> Option<&mut u64> {
//     //     self.max_stream_datas.borrow_mut().get_mut(&stream_id)
//     // }
// }

#[derive(Debug, Default)]
pub struct FlowShaperBuilder {
    config: Config,

    pad_only_mode: bool,
}

impl FlowShaperBuilder {
    pub fn new() -> Self {
        FlowShaperBuilder::default()
    }

    pub fn config(&mut self, config: Config) -> &mut Self {
        self.config = config;
        self
    }

    pub fn control_interval(&mut self, interval: u64) -> &mut Self {
        self.config.control_interval = interval;
        self
    }

    pub fn pad_only_mode(&mut self, pad_only_mode: bool) -> &mut Self {
        self.pad_only_mode = pad_only_mode;
        self
    }

    pub fn from_trace(self, trace: &Trace) -> FlowShaper {
        FlowShaper::new(self.config, trace, self.pad_only_mode)
    }

    pub fn from_defence(self, defence: &impl Defence) -> FlowShaper {
        let mut mut_self = self;
        mut_self.pad_only_mode(defence.is_padding_only());

        let unmut_self = mut_self;
        unmut_self.from_trace(&defence.trace())
    }

    /// Create a new FlowShaper from a CSV trace file
    pub fn from_csv(self, filename: &str) -> Result<FlowShaper> {
        load_trace(filename)
            .map(|trace| FlowShaper::new(self.config, &trace, self.pad_only_mode))
    }
}


/// Shaper for the connection. Assumes that it operates on the client,
/// and not the server.
#[derive(Debug, Default)]
pub struct FlowShaper {
    /// General configuration
    config: Config,
    /// Whether we are padding or shaping
    pad_only_mode: bool,

    /// The target traces
    out_target: VecDeque<(u32, u32)>,
    in_target: VecDeque<(u32, u32)>,

    /// The time that the flow shaper was started
    start_time: Option<Instant>,

    /// Event Queues
    events: FlowShapingEvents,
    application_events: FlowShapingApplicationEvents,

    /// Streams used for sending chaff traffic
    chaff_streams: ChaffStreamMap,
}

impl Display for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QCD FlowShaper")
    }
}


impl FlowShaper {
    pub fn new(config: Config, trace: &Trace, pad_only_mode: bool) -> FlowShaper {
        assert!(trace.len() > 0);
        log_trace(trace).expect("Unable to log trace.");

        // Bin the trace
        let mut bins: HashMap<(u32, bool), i32> = HashMap::new();
        let interval_ms: u128 = config.control_interval as u128;

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
FlowShaper{ config,
            in_target: VecDeque::from(in_target),
            out_target: VecDeque::from(out_target),
            pad_only_mode: pad_only_mode,
            ..FlowShaper::default()
        }
    }


    /// Start shaping the traffic using the current time as the reference
    /// point.
    pub fn start(&mut self) {
        qtrace!([self], "starting shaping.");
        self.start_time = Some(Instant::now());
    }

    /// Report the next instant at which the FlowShaper should be called for
    /// processing events.
    pub fn next_signal_time(&self) -> Option<Instant> {
        self.next_signal_offset()
            .map(u64::from)
            .map(Duration::from_millis)
            .zip(self.start_time)
            .map(|(dur, start)| max(start + dur, Instant::now()))
    }

    fn next_signal_offset(&self) -> Option<u32> {
        vec![self.in_target.front(), self.out_target.front()]
                 .iter()
                 .filter_map(|x| x.map(|(ts, _)| *ts))
                 .min()
    }

    pub fn process_timer(&mut self, now: Instant) {
        if let Some(start_time) = self.start_time {
            self.process_timer_(now.duration_since(start_time));
        }
    }

    fn process_timer_(&mut self, since_start: Duration) {
        if self.pad_only_mode {
            // dummy packets out
            if let Some((ts, _)) = self.out_target.front() {
                let next = Duration::from_millis(u64::from(*ts));
                if next < since_start {
                    let (_, size) = self.out_target.pop_front()
                        .expect("the deque to be non-empty");

                    qtrace!([self], "sending {} padding bytes", size);
                    self.events.send_pad_frames(size);
                }
            }

            // dummy packets in
            if self.chaff_streams.has_open() {
                if let Some((ts, _)) = self.in_target.front() {
                    let next = Duration::from_millis(u64::from(*ts));
                    if next < since_start {
                        let (_, size) = self.in_target.pop_front()
                            .expect("the deque to be non-empty");
                        qtrace!([self], "pulling {} padding bytes", size);

                        // find first available dummy stream to transfer data
                        let (_, stream) = self.chaff_streams
                            .iter_mut()
                            .find(|(_, stream)| stream.is_open())
                            .expect("chaff_streams has some open stream");
                        stream.pull_data(size as u64, &mut self.events);
                    }
                }
            } else {
                qwarn!([self], "No chaff stream open to get data.");
            }

            // check dequeues empty, if so send connection close event
            if self.in_target.is_empty() && self.out_target.is_empty() {
                qtrace!([self], "shaping complete, closing connection");
                self.application_events.send_connection_close();
            }
        }
    }


    /// Return the initial values for transport parameters
    pub fn tparam_defaults(&self) -> [(u64, u64); 3] {
        [
            (0x04, self.config.local_md),
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
        qtrace!([self], "notified of stream {} being created", stream_id);

        if stream_id.is_bidi() {
            self.events.send_max_stream_data(&stream_id, self.config.rx_stream_data_window);
            qdebug!([self], "Added send_max_stream_data event to stream {} limit {}",
                    stream_id, self.config.rx_stream_data_window);
        }
    }

    /// Records the creation of a stream for padding.
    ///
    /// Assumes that no events have been dequeud since the call of the
    /// associated `on_new_stream` call for the `stream_id`.
    pub fn on_new_padding_stream(&mut self, stream_id: u64, dummy_url: Url) {
        assert!(self.events.cancel_max_stream_data(StreamId::new(stream_id)));
        qdebug!([self], "Removed max stream data event from stream {}", stream_id);
        self.add_padding_stream(stream_id, dummy_url);
        // Queued events should be drained immediately after closing stream
        // this now is a double safety in case there were no open dummy
        // streams when the last one was closed.
        // TODO (ldolfi): use `drain_queue_with_id`
        // FIXME(jsmith) This does not track the stream's size in the chaff_streams mapping
        while self.events.has_queue_events() {
            match self.events.next_queued() {
                Some(e) => {
                    match e {
                        FlowShapingEvent::SendMaxStreamData{ stream_id: _ , new_limit: lim } => {
                            qdebug!([self], "Adding queues MSD to stream {} with new_limit {}", stream_id, lim);
                            self.events.send_max_stream_data(&StreamId::from(stream_id), lim);
                        },
                        _ => {}
                    }
                }
                None => assert!(!self.events.has_queue_events())
            }
        }
    }

    pub fn add_padding_stream(&mut self, stream_id: u64, dummy_url: Url) {
        qtrace!([self], "adding a padding stream for {}: {}", stream_id, dummy_url);
        assert!(self.chaff_streams.add_padding_stream(stream_id, dummy_url));
    }

    // signals that the stream is ready to receive MSD frames
    pub fn open_for_shaping(&mut self, stream_id: u64) -> bool {
        qdebug!([self], "Opening stream {} for shaping", stream_id);

        if debug_enable_save_ids(){
            let csv_path = debug_save_ids_path();
            let csv_file = OpenOptions::new()
                            .write(true)
                            .create(true)
                            .append(true)
                            .open(csv_path)
                            .unwrap();
            let mut wtr = csv::Writer::from_writer(csv_file);
            wtr.write_record(&[stream_id.to_string()])
                .expect("Failed writing dummy stream id");
            wtr.flush().expect("Failed saving dummy stream id");
        }

        self.chaff_streams.open_stream(&stream_id);
        true
    }

    pub fn remove_dummy_stream(&mut self, stream_id: u64) -> Url{
        qtrace!([self], "removing chaff stream {}", stream_id);
        self.events.remove_by_id(&stream_id);
        let dummy_url = self.chaff_streams.remove_dummy_stream(&stream_id);

        // check if there are orphaned events
        // transfer the MSD events to a dummy stream currently open
        if self.events.has_queue_events() && self.chaff_streams.has_open() {
            // find first available dummy stream to transfer data
            // FIXME(jsmith): This needs to account for the amount of available bytes on the new stream
            for (id, stream) in self.chaff_streams.iter() {
                if stream.is_open() {
                    self.events.drain_queue_with_id(*id);
                    break;
                }
            }
        }

        qdebug!("Removed dummy stream {} after receiving FIN", stream_id);
        dummy_url
    }

    pub fn reopen_dummy_stream(&self, dummy_url: Url) {
        qtrace!([self], "reopenning dummy stream for URL {}", dummy_url);
        self.application_events.reopen_stream(dummy_url);
    }

    // returns true if the stream_id is contained in the set of streams
    // being currently shaped
    pub fn is_shaping_stream(&self, stream_id: u64) -> bool {
        self.chaff_streams.contains(&stream_id)
    }

    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.next_event()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        self.events.has_events()
    }

    pub fn next_application_event(&self) -> Option<FlowShapingEvent> {
        self.application_events.next_event()
    }

    #[must_use]
    pub fn has_application_events(&self) -> bool {
        self.application_events.has_events()
    }
}

/// Select count padding URLs from the slice of URLs.
///
/// Prefers image URLs (png, jpg) followed by script URLs (js) and
/// decides based on the extension of the URL's path.
pub fn select_padding_urls(urls: &[Url], count: usize) -> Vec<Url> {
    let mut result: Vec<&Url> = vec![];

    result.extend(urls.iter().filter(
            |u| u.path().ends_with(".png") || u.path().ends_with(".jpg")
        ));
    result.extend(urls.iter().filter(|u| u.path().ends_with(".js")));

    if result.len() >= count {
        return result.iter().take(count).cloned().cloned().collect()
    }

    // Use arbitrary additional URLs to make the required number
    let mut result: HashSet<&Url> = result.iter().cloned().collect();
    for url in urls {
        result.insert(url);

        if result.len() == count {
            break;
        }
    }

    assert!(result.len() >= count, "Not enough URLs to be used for padding.");
    return result.iter().cloned().cloned().collect()

}


#[cfg(test)]
mod tests {
    use super::*;

    // The value below is taken from the QUIC Connection class and defines the
    // buffer that is allocated for receiving data.
    const RX_STREAM_DATA_WINDOW: u64 = 0x10_0000; // 1MiB

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
        FlowShaper::new(Config::default(), &vec, true)
    }

    fn create_shaper_with_trace(vec: Vec<(u64, i32)>, interval: u64) -> FlowShaper {
        let vec = vec
            .into_iter()
            .map(|(time, size)| (Duration::from_millis(time), size)).collect();

        FlowShaper::new(
            Config{ control_interval: interval, ..Config::default() },
            &vec, true)
    }

    #[test]
    fn test_select_padding_urls() {
        let urls = vec![
            Url::parse("https://a.com").unwrap(),
            Url::parse("https://a.com/image.png").unwrap(),
            Url::parse("https://a.com/image.jpg").unwrap(),
            Url::parse("https://b.com").unwrap(),
        ];
        assert_eq!(select_padding_urls(&urls, 2)[..], urls[1..3]);

        let urls = vec![
            Url::parse("https://a.com").unwrap(),
            Url::parse("https://a.com/image.png").unwrap(),
            Url::parse("https://b.com").unwrap(),
            Url::parse("https://b.com/image-2.jpg").unwrap(),
        ];
        assert_eq!(select_padding_urls(&urls, 2), vec![urls[1].clone(), urls[3].clone()]);

        let urls = vec![
            Url::parse("https://b.com/script.js").unwrap(),
            Url::parse("https://a.com/image.png").unwrap(),
            Url::parse("https://a.com").unwrap(),
            Url::parse("https://b.com").unwrap(),
        ];
        assert_eq!(select_padding_urls(&urls, 2), vec![urls[1].clone(), urls[0].clone()]);
    }

    #[test]
    fn test_select_padding_urls_insufficient_urls() {
        let urls = vec![
            Url::parse("https://b.com/script.js").unwrap(),
            Url::parse("https://a.com/image.png").unwrap(),
            Url::parse("https://a.com").unwrap(),
            Url::parse("https://b.com").unwrap(),
        ];

        assert_eq!(
            select_padding_urls(&urls, 3).iter().collect::<HashSet<&Url>>(),
            urls[0..3].iter().collect::<HashSet<&Url>>()
        );
    }

    #[test]
    fn test_sanity() {
        let trace = load_trace("../data/nytimes.csv").expect("Load failed");

        assert_eq!(trace[0], (Duration::from_secs(0), 74));
        FlowShaper::new(Config::default(), &trace, true);
    }

    #[test]
    fn test_next_signal_offset() {
        let shaper = create_shaper_with_trace(
            vec![(100, 1500), (150, -1350), (200, 700)], 1);
        assert_eq!(shaper.next_signal_offset().unwrap(), 100);

        let shaper = create_shaper_with_trace(
            vec![(2, 1350), (16, -4800), (21, 600), (22, -350)], 1);
        assert_eq!(shaper.next_signal_offset().unwrap(), 2);

        let shaper = create_shaper_with_trace(
            vec![(0, 1350), (16, -4800), (21, 600), (22, -350)], 1);
        assert_eq!(shaper.next_signal_offset().unwrap(), 0);

        let shaper = create_shaper_with_trace(
            vec![(2, 1350), (16, -4800), (21, 600), (22, -350)], 5);
        assert_eq!(shaper.next_signal_offset().unwrap(), 0);
    }

    #[test]
    fn test_next_signal_time() {
        let mut shaper = create_shaper();
        assert_eq!(shaper.next_signal_time(), None);

        shaper.start();
        // next_signal_time() also will take the greater of the time and now
        assert!(shaper.next_signal_time()
                > Some(shaper.start_time.unwrap() + Duration::from_millis(0)))
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
        let  shaper = create_shaper();
        shaper.on_stream_created(CLIENT_UNI_STREAM_ID);
        assert_eq!(shaper.next_event(), None);
    }

    #[test]
    fn test_on_stream_created_bidi() {
        // It's a unidirectional stream, so we do not queue any events
        let  shaper = create_shaper();
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
        shaper.on_new_padding_stream(CLIENT_BIDI_STREAM_ID, Url::parse("").expect("foo"));
        assert_eq!(shaper.events.next_event(), None);
    }

    #[test]
    fn test_on_stream_incoming_uni() {
        let  shaper = create_shaper();
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

    #[test]
    fn test_chaff_streams_always_considered_shaped() {
        let mut shaper = create_shaper();

        shaper.add_padding_stream(46, Url::parse("https://b.com").unwrap());
        assert!(shaper.is_shaping_stream(46));
        shaper.remove_dummy_stream(46);
        assert!(shaper.is_shaping_stream(46));
    }

}
