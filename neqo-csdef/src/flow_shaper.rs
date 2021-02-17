use std::cmp::max;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::env; // for reading env variables
use std::fmt::Display;
use std::fs::OpenOptions;
use std::time::{ Duration, Instant };
use serde::Deserialize;
use url::Url;

use neqo_common::{ qwarn, qdebug, qtrace };

use crate::{ Result, dummy_schedule_log_file };
use crate::trace::{ Trace, Packet };
use crate::stream_id::StreamId;
use crate::defences::Defence;
use crate::chaff_stream::{ ChaffStream, ChaffStreamMap };
use crate::events::{
    FlowShapingEvents, FlowShapingApplicationEvents, HEventConsumer,
    StreamEventConsumer
};
pub use crate::events::{ FlowShapingEvent };

const BLOCKED_STREAM_LIMIT: u64 = 1500;


fn debug_save_ids_path() -> Option<String> {
    match env::var("CSDEF_DUMMY_ID") {
        Ok(s) => Some(s),
        _ => None
    }
}

#[derive(Debug, Deserialize, Clone)]
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

    pub fn from_trace(&self, trace: &Trace) -> FlowShaper {
        FlowShaper::new(self.config.clone(), trace, self.pad_only_mode)
    }

    pub fn from_defence(&mut self, defence: &impl Defence) -> FlowShaper {
        self.pad_only_mode(defence.is_padding_only());
        self.from_trace(&defence.trace())
    }

    /// Create a new FlowShaper from a CSV trace file
    pub fn from_csv(&self, filename: &str) -> Result<FlowShaper> {
        Ok(FlowShaper::new(self.config.clone(), &Trace::from_file(filename)?,
                        self.pad_only_mode))
    }
}


/// Shaper for the connection. Assumes that it operates on the client,
/// and not the server.
#[derive(Default)]
pub struct FlowShaper {
    /// General configuration
    config: Config,
    /// Whether we are padding or shaping
    pad_only_mode: bool,

    /// The target trace
    target: Trace,

    /// The time that the flow shaper was started
    start_time: Option<Instant>,

    /// Event Queues
    events: Rc<RefCell<FlowShapingEvents>>,
    application_events: FlowShapingApplicationEvents,

    /// Streams used for sending chaff traffic
    chaff_streams: ChaffStreamMap,
    app_streams: ChaffStreamMap,

    /// CSV Writer for debug logging of dummy ids
    dummy_id_file: Option<csv::Writer<std::fs::File>>,
}


impl FlowShaper {
    pub fn new(config: Config, trace: &Trace, pad_only_mode: bool) -> FlowShaper {
        assert!(trace.len() > 0);
        if let Some(filename) = dummy_schedule_log_file() {
            trace.to_file(&filename).expect("Unable to log trace.");
        }

        let target = trace.clone().sampled(
            u32::try_from(config.control_interval).unwrap()
        );

        let dummy_id_file = debug_save_ids_path()
            .map(|filename| {
                let writer = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(filename)
                    .unwrap();

                csv::Writer::from_writer(writer)
            });

        FlowShaper{
            config,
            target,
            dummy_id_file,
            pad_only_mode: pad_only_mode,
            ..FlowShaper::default()
        }
    }

    /// Start shaping the traffic using the current time as the reference
    /// point.
    pub fn start(&mut self) {
        qdebug!([self], "starting shaping.");
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
        self.target.front().map(|pkt| pkt.timestamp())
    }

    pub fn process_timer(&mut self, now: Instant) {
        if let Some(start_time) = self.start_time {
            self.process_timer_(now.duration_since(start_time).as_millis());
        }
    }

    fn process_timer_(&mut self, since_start: u128) {
        let pop_front: bool = match self.target.front().cloned() {
            Some(pkt) if (pkt.timestamp() as u128) < since_start =>  {
                match self.target.front_mut().unwrap() {
                    Packet::Incoming(_, mut length) => {
                        let pulled = self.pull_traffic(length);
                        length -= pulled;
                        length == 0
                    },
                    Packet::Outgoing(_, mut length) => {
                        let pushed = self.push_traffic(length);
                        length -= pushed;
                        length == 0
                    }
                }
            },
            Some(_) | None => false,
        };

        // TODO(jsmith): Evaluate whether we should discard or requeue.
        // This question also generally applies to data that should be
        // transfered before the first chaff streams are available as well
        // as the data that wouldve been lost when we remove a dummy stream
        // with pending outgoing MSD frames.
        if pop_front {
            self.target.pop_front();
        }

        // check dequeues empty, if so send connection close event
        if self.target.is_empty() {
            qdebug!([self], "shaping complete, notify client");
            self.application_events.is_done_shaping();
        }
    }

    /// Push amount bytes to the server and return the amount of data
    /// pushed.
    ///
    /// Data is pushed first from application streams if they're being
    /// shaped, then chaff-streams, then finally using padding frames.
    fn push_traffic(&mut self, amount: u32) -> u32 {
        assert!(amount > 0);
        let amount = u64::from(amount);
        let mut remaining = amount;

        if !self.pad_only_mode && remaining > 0 {
            let pushed = self.app_streams.push_data(remaining);
            qdebug!([self], "sent {} application bytes", pushed);
            remaining -= pushed;
        }

        if remaining > 0 {
            // TODO(jsmith): Use Chaff GET requests as padding.
            // We should perhaps generally use GET requests for chaff
            // traffic as padding instead of having them interleave with
            // the data.
            let pushed = self.chaff_streams.push_data(remaining);
            qdebug!([self], "sent {} chaff-stream bytes", pushed);
            remaining -= pushed;
        }

        if remaining > 0 {
            qdebug!([self], "sending {} padding bytes", remaining);
            self.events.borrow_mut().send_pad_frames(u32::try_from(remaining).unwrap());
        }

        // Since we can send padding bytes, we always push the full amount
        u32::try_from(amount).expect("unmodified amount was casted from u32")
    }

    fn pull_traffic(&mut self, amount: u32) -> u32 {
        qtrace!([self], "attempting to pull {} bytes of data.", amount);
        let mut remaining: u64 = amount.into();

        if !self.pad_only_mode && self.app_streams.can_pull() {
            let pulled = self.app_streams.pull_data(remaining);
            qdebug!([self], "pulled {} application data", pulled);
            remaining -= pulled;
        }

        if remaining > 0 && self.chaff_streams.can_pull() {
            let pulled = self.chaff_streams.pull_data(remaining);
            qdebug!([self], "pulled {} chaff data", pulled);
            remaining -= pulled;
        } else if remaining > 0 && !self.chaff_streams.can_pull() {
            qwarn!([self], "No chaff streams with available pull capacity.");
        }

        amount - u32::try_from(remaining).unwrap()
    }

    /// Return the initial values for transport parameters
    pub fn tparam_defaults(&self) -> [(u64, u64); 3] {
        [
            (0x04, self.config.local_md),
            // Disable the peer sending data on bidirectional streams openned
            // by this endpoint (initial_max_stream_data_bidi_local)
            (0x05, BLOCKED_STREAM_LIMIT),
            // Disable the peer sending data on bidirectional streams that
            // they open (initial_max_stream_data_bidi_remote)
            (0x06, BLOCKED_STREAM_LIMIT),
            // Disable the peer sending data on unidirectional streams that
            // they open (initial_max_stream_data_uni)
            // (0x07, BLOCKED_STREAM_LIMIT),
        ]
    }

    // TODO: Need to adjust below here for data streams ----
    fn maybe_send_queued_msd(&mut self) {
        // FIXME(jsmith): This needs to account for available bytes
        // Better yet, it would better to just push the queued MSD
        // back onto the trace so that it is handled in the main code
        let queued_msd = self.events.borrow().get_queued_msd();
        if queued_msd > 0 {
            let pulled = self.chaff_streams.pull_data(queued_msd);

            if pulled > 0 && pulled < queued_msd {
                self.events.borrow_mut().consume_queued_msd(pulled);
            }
        }
    }

    // returns true if the stream_id is contained in the set of streams
    // being currently shaped
    pub fn is_shaping_stream(&self, stream_id: u64) -> bool {
        // TODO: Need to figure out what this should do
        self.chaff_streams.contains(&stream_id)
    }

    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().next_event()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        self.events.borrow().has_events()
    }

    pub fn next_application_event(&self) -> Option<FlowShapingEvent> {
        self.application_events.next_event()
    }

    #[must_use]
    pub fn has_application_events(&self) -> bool {
        self.application_events.has_events()
    }

    fn get_stream_mut(&mut self, stream_id: &u64) -> Option<&mut ChaffStream> {
        match self.chaff_streams.get_mut(stream_id) {
            Some(stream) => Some(stream),
            None => self.app_streams.get_mut(stream_id),
        }
    }

    fn maybe_fetch_chaff(&mut self, url: &Url) {
        // TODO: Ensure sufficient chaff data available
        qdebug!([self], "reopenning dummy stream for URL {}", url);
        self.application_events.reopen_stream(url.clone());
    }
}

impl Display for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "FlowShaper")
    }
}

impl std::fmt::Debug for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "FlowShaper {{ config: {:?}, pad_only_mode: {:?}, start_time: {:?}, ... }}",
               self.config, self.pad_only_mode, self.start_time)
    }
}


impl HEventConsumer for FlowShaper {
    fn awaiting_header_data(&mut self, stream_id: u64, min_remaining: u64) {
        self.get_stream_mut(&stream_id)
            .expect("Stream to already be tracked.")
            .awaiting_header_data(min_remaining);
    }

    fn on_data_frame(&mut self, stream_id: u64, length: u64) {
        self.get_stream_mut(&stream_id)
            .expect("Stream to already be tracked.")
            .on_data_frame(length);
    }

    fn on_http_request_sent(&mut self, stream_id: u64, url: &Url, is_chaff: bool) {
        let streams = if is_chaff {
            qdebug!([self], "notified of chaff request sent on stream {}", stream_id);

            if let Some(writer) = self.dummy_id_file.as_mut() {
                writer.write_record(&[stream_id.to_string()])
                    .expect("Failed writing dummy stream id");
                writer.flush().expect("Failed saving dummy stream id");
            }

            &mut self.chaff_streams
        } else {
            qdebug!([self], "notified of request sent on stream {}", stream_id);

            &mut self.app_streams
        };

        streams.insert(ChaffStream::new(
                stream_id, url.clone(), self.events.clone(), BLOCKED_STREAM_LIMIT,
                is_chaff || !self.pad_only_mode));

        qtrace!([self], "chaff-streams: {}, app-streams: {}", self.chaff_streams.len(),
                self.app_streams.len());
    }
}

impl StreamEventConsumer for FlowShaper {
    fn on_first_byte_sent(&mut self, stream_id: u64) {
        if StreamId::new(stream_id).is_uni() {
            return;
        }

        assert!(StreamId::new(stream_id).is_client_initiated());
        qdebug!([self], "first byte sent on {}", stream_id);

        self.get_stream_mut(&stream_id)
            .expect("Stream should already be tracked.")
            .open();

        // Queued events should be drained immediately after closing stream
        // this now is a double safety in case there were no open dummy
        // streams when the last one was closed.
        self.maybe_send_queued_msd();
    }

    fn data_consumed(&mut self, stream_id: u64, amount: u64) {
        if StreamId::new(stream_id).is_uni() {
            return;
        }

        self.get_stream_mut(&stream_id)
            .expect("Stream to be tracked.")
            .data_consumed(amount);
    }

    fn on_fin_received(&mut self, stream_id: u64) {
        self.events.borrow_mut().remove_by_id(&stream_id);

        let stream = self.get_stream_mut(&stream_id)
            .expect("Stream should be tracked.");
        stream.close_receiving();
        let url = stream.url().clone();

        if self.chaff_streams.contains(&stream_id) {
            self.maybe_fetch_chaff(&url);
        }
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

    fn create_shaper() -> FlowShaper {
        FlowShaper::new(
            Config::default(),
            &Trace::new(&[(2, 1350), (16, -4800), (21, 600), (22, -350)]),
            true)
    }

    fn create_shaper_with_trace(vec: Vec<(u32, i32)>, interval: u64) -> FlowShaper {
        FlowShaper::new(
            Config{ control_interval: interval, ..Config::default() },
            &Trace::new(&vec), true)
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
}
