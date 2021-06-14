use std::cell::RefCell;
use std::cmp::max;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::Display;
use std::io::{ Write, BufWriter };
use std::rc::Rc;
use std::time::{ Duration, Instant };

use neqo_common::{ qwarn, qdebug, qtrace, qinfo };
use serde::Deserialize;
use url::Url;

use crate::Result;
use crate::trace::Packet;
use crate::stream_id::StreamId;
use crate::defences::{ Defencev2, StaticSchedule };
use crate::chaff_stream::{ ChaffStream, ChaffStreamMap };
use crate::event::{
    FlowShapingEvents, FlowShapingApplicationEvents, HEventConsumer,
    StreamEventConsumer, Provider
};
use crate::chaff_manager::ChaffManager;
use crate::Resource;
pub use crate::event::{ FlowShapingEvent };


const BLOCKED_STREAM_LIMIT: u64 = 16;
const DEFAULT_MSD_EXCESS: u64 = 1000;


#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(default)]
pub struct Config {
    /// The control interval in milliseconds
    pub control_interval: u64,
    pub rx_stream_data_window: u64,
    pub local_md: u64,

    /// The initial max stream data of an incoming stream
    pub initial_max_stream_data: u64,
    /// Additional leeway on the max stream data of each stream
    pub max_stream_data_excess: u64,

    /// The maximum number of chaff streams to open
    pub max_chaff_streams: u32,
    /// The amount of chaff data to retain available
    pub low_watermark: u64,

    /// Whether to drop unsatisfied shaping events
    pub drop_unsat_events: bool,
}


impl Default for Config {
    fn default() -> Self {
        Config {
            control_interval: 5,
            rx_stream_data_window: 1048576,
            local_md: 4611686018427387903,
            initial_max_stream_data: BLOCKED_STREAM_LIMIT,
            max_stream_data_excess: DEFAULT_MSD_EXCESS,
            max_chaff_streams: 5,
            low_watermark: 1_000_000,
            drop_unsat_events: false,
        }
    }
}


#[derive(Default)]
/// Keeps details to be logged on shutdown later
struct FlowShaperLogger {
    chaff_ids_log: Option<BufWriter<std::fs::File>>,
    defence_event_log: Option<BufWriter<std::fs::File>>,
}

impl FlowShaperLogger {
    fn set_chaff_ids_log(&mut self, filename: &str) -> Result<()> {
        assert!(self.chaff_ids_log.is_none(), "already set");

        let file = std::fs::File::create(filename)?;
        self.chaff_ids_log = Some(BufWriter::new(file));
        Ok(())
    }

    fn chaff_stream_id(&mut self, stream_id: u64) -> Result<()> {
        if let Some(writer) = self.chaff_ids_log.as_mut() {
            let output = format!("{}\n", stream_id);
            writer.write_all(output.as_bytes())?;
        }
        Ok(())
    }

    fn set_defence_event_log(&mut self, filename: &str) -> Result<()> {
        assert!(self.defence_event_log.is_none(), "already set");

        let file = std::fs::File::create(filename)?;
        self.defence_event_log = Some(BufWriter::new(file));
        Ok(())
    }

    fn defence_event(&mut self, packet: &Packet) -> Result<()> {
        if let Some(writer) = self.defence_event_log.as_mut() {
            let output = format!(
                "{},{}\n", packet.duration().as_secs_f64(), packet.signed_length());
            writer.write_all(output.as_bytes())?;
        }
        Ok(())
    }
}


#[derive(Debug, Default)]
pub struct FlowShaperBuilder {
    config: Config,
    chaff_resources: Vec<Resource>,

    chaff_ids_log: Option<String>,
    defence_event_log: Option<String>,
}

impl FlowShaperBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn config(&mut self, config: Config) -> &mut Self {
        self.config = config;
        self
    }

    pub fn chaff_urls(&mut self, urls: &[Url]) -> &mut Self {
        self.chaff_resources = urls.iter()
            .cloned()
            .map(Resource::from)
            .collect();
        self
    }

    pub fn chaff_headers(&mut self, headers: &[(String, String)]) -> &mut Self {
        self.chaff_resources.iter_mut()
            .for_each(|res| res.headers = headers.iter().cloned().collect());
        self
    }

    pub fn chaff_ids_log(&mut self, filename: &str) -> &mut Self {
        self.chaff_ids_log = Some(filename.into());
        self
    }

    pub fn defence_event_log(&mut self, filename: &str) -> &mut Self {
        self.defence_event_log = Some(filename.into());
        self
    }

    pub fn control_interval(&mut self, interval: u64) -> &mut Self {
        self.config.control_interval = interval;
        self
    }

    pub fn from_defence(&mut self, defence: Box<dyn Defencev2>) -> FlowShaper {
        let mut shaper = FlowShaper::new(self.config.clone(), defence);
        for resource in self.chaff_resources.iter() {
            shaper.chaff_manager.add_resource(resource.clone());
        }

        if let Some(filename) = self.chaff_ids_log.as_ref() {
            shaper.log.set_chaff_ids_log(filename).expect("invalid file");
        }
        if let Some(filename) = self.defence_event_log.as_ref() {
            shaper.log.set_defence_event_log(filename).expect("invalid file");
        }

        shaper
    }
}


/// Shaper for the connection. Assumes that it operates on the client,
/// and not the server.
pub struct FlowShaper {
    /// General configuration
    config: Config,

    /// The enacted defence
    defence: Box<dyn Defencev2>,

    /// The amount of incoming data that we were unable to send and is now pending
    incoming_backlog: u32,

    /// The next timepoint for pulling incoming data
    next_ci: Duration,

    /// The time that the flow shaper was started
    start_time: Option<Instant>,

    /// Used to signal that sending has been unthrottled
    is_sending_unthrottled: bool,

    /// Event Queues
    events: Rc<RefCell<FlowShapingEvents>>,
    application_events: Rc<RefCell<FlowShapingApplicationEvents>>,
    chaff_manager: ChaffManager,

    /// Streams used for sending chaff traffic
    chaff_streams: ChaffStreamMap,
    app_streams: ChaffStreamMap,

    log: FlowShaperLogger,
}


impl Default for FlowShaper {
    fn default() -> Self {
        FlowShaper::new(Config::default(), Box::new(StaticSchedule::empty()))
    }
}


impl FlowShaper {
    pub fn new(config: Config, defence: Box<dyn Defencev2>) -> Self {
        let application_events = Rc::new(RefCell::new(FlowShapingApplicationEvents::default()));
        let chaff_manager = ChaffManager::new(
            config.max_chaff_streams, config.low_watermark, application_events.clone());

        let shaper = FlowShaper{
            next_ci: Duration::from_millis(config.control_interval),
            config,
            defence,
            chaff_manager,
            application_events,
            start_time: None,
            is_sending_unthrottled: false,
            app_streams: Default::default(),
            chaff_streams: Default::default(),
            events: Default::default(),
            log: FlowShaperLogger::default(),
            incoming_backlog: 0,
        };

        qinfo!([shaper], "New flow shaper created {:?}", shaper);
        shaper
    }

    /// Start shaping the traffic using the current time as the reference
    /// point.
    pub fn start(&mut self) {
        qdebug!([self], "starting shaping.");
        self.start_time = Some(Instant::now());
    }

    pub fn is_complete(&self) -> bool {
        self.defence.is_complete() && self.incoming_backlog == 0
    }

    /// Report the next instant at which the FlowShaper should be called for
    /// processing events.
    pub fn next_signal_time(&self) -> Option<Instant> {
        if self.has_events() {
            Some(Instant::now())
        } else {
            self.defence.next_event_at()
                .map(|dur| std::cmp::min(self.next_ci, dur))
                .or(Some(self.next_ci))
                .zip(self.start_time)
                .map(|(dur, start)| max(start + dur, Instant::now()))
        }
    }

    pub fn process_timer(&mut self, now: Instant) {
        if let Some(start_time) = self.start_time {
            self.process_timer_(now.duration_since(start_time));
        }
    }

    fn process_timer_(&mut self, since_start: Duration) {
        if self.is_complete() {
            return;
        }

        let ci_index = since_start.as_millis() / u128::from(self.config.control_interval);
        let previous_ci = ci_index * u128::from(self.config.control_interval);

        let mut incoming_length = if self.next_ci <= since_start {
            // We have reached the next incoming control interval
            //
            // Update to the next control interval
            self.next_ci = Duration::from_millis(
                u64::try_from(ci_index+1).unwrap() * u64::from(self.config.control_interval));

            // Reset the amount waiting to be pulled
            let length = self.incoming_backlog;
            self.incoming_backlog = 0;

            length
        } else {
            // Do nothing, since we havent reached the next control interval
            0
        };
        // By definition, the next control interval is after now, and the previous control
        // interval could be equal to since_start.
        assert!(since_start < self.next_ci);

        while let Some(pkt) = self.defence.next_event(since_start) {
            self.log.defence_event(&pkt).expect("logging failed");

            match pkt {
                Packet::Outgoing(_, length) => {
                    let pushed = self.push_traffic(length);
                    assert_eq!(pushed, length, "Pushes are always fully completed.");
                }
                Packet::Incoming(time, length) if u128::from(time) <= previous_ci => {
                    // This packet should have been pulled at the previous control interval
                    // Add it to the amount that we should be pulling now.
                    incoming_length += length;
                }
                Packet::Incoming(_, length) => {
                    // This packet is before or at the current time, but but after the
                    // previous control interval. Note by definition of previous and next
                    // control intervals, the next control interval is strictly > since_start.
                    //
                    // We can therefore add it to the next batch to be pulled
                    self.incoming_backlog += length;
                }
            };
        }

        // Perform the actual pulling of the incoming data
        if incoming_length > 0 {
            qtrace!([self], "Pulling data for CI {} of total length {}",
                    previous_ci, incoming_length);
            let pulled = self.pull_traffic(incoming_length);

            // If we failed to pull all the data, only store the remaineder if
            // we are not configure to drop the amount
            if !self.config.drop_unsat_events  {
                self.incoming_backlog += incoming_length - pulled;
            }
        }

        if self.is_complete() {
            // The entry guard above ensures that we know this recently completed
            if self.defence.is_padding_only() {
                qdebug!([self], "padding complete, notifying client");
                self.application_events.borrow_mut().done_shaping();
            } else {
                qdebug!([self], "shaping complete, closing connection");
                self.application_events.borrow_mut().close_connection();
            }
        } else if self.defence.is_outgoing_complete() && !self.is_sending_unthrottled {
            // We're done with outgoing but not incoming
            self.unthrottle_sending();
        }
    }

    fn unthrottle_sending(&mut self) {
        self.is_sending_unthrottled = true;

        qtrace!([self], "unthrottling sending on chaff streams");
        self.chaff_streams.iter_mut()
            .for_each(|(_, stream)| stream.unthrottle_sending());
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
        qtrace!([self], "attempting to push data: {}", amount);

        if !self.defence.is_padding_only() && remaining > 0 {
            let pushed = self.app_streams.push_data(remaining);
            if pushed > 0 {
                qdebug!([self], "pushed bytes: {{ source: \"app-stream\", bytes: {} }}",
                        pushed);
            }
            remaining -= pushed;
        }

        if remaining > 0 {
            let pushed = self.chaff_streams.push_data(remaining);
            if pushed > 0 {
                qdebug!([self], "pushed bytes: {{ source: \"chaff-stream\", bytes: {} }}",
                        pushed);
            }
            remaining -= pushed;
        }

        if remaining > 0 {
            self.events.borrow_mut().send_pad_frames(u32::try_from(remaining).unwrap());
            qdebug!([self], "pushed bytes: {{ source: \"padding\", bytes: {} }}", remaining);
        }

        // Since we can send padding bytes, we always push the full amount
        u32::try_from(amount).expect("unmodified amount was casted from u32")
    }

    fn pull_traffic(&mut self, amount: u32) -> u32 {
        qtrace!([self], "attempting to pull {} bytes of data.", amount);
        let mut remaining: u64 = amount.into();

        if !self.defence.is_padding_only() && self.app_streams.can_pull() {
            let pulled = self.app_streams.pull_data(remaining);
            qdebug!([self], "pulled bytes: {{ source: \"app-stream\", bytes: {} }}", pulled);
            remaining -= pulled;
        }

        if remaining > 0 && self.chaff_streams.can_pull() {
            let pulled = self.chaff_streams.pull_data(remaining);
            qdebug!([self], "pulled bytes: {{ source: \"chaff-stream\", bytes: {} }}", pulled);
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
            (0x05, self.config.initial_max_stream_data),
            // Disable the peer sending data on bidirectional streams that
            // they open (initial_max_stream_data_bidi_remote)
            (0x06, self.config.initial_max_stream_data),
            // Disable the peer sending data on unidirectional streams that
            // they open (initial_max_stream_data_uni)
            // (0x07, self.config.initial_max_stream_data),
        ]
    }

    // returns true if the stream_id is contained in the set of streams
    // being currently shaped
    pub fn is_chaff_stream(&self, stream_id: u64) -> bool {
        self.chaff_streams.contains(&stream_id)
    }

    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().next_event()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        self.events.borrow().has_events()
    }

    pub fn next_application_event(&mut self) -> Option<FlowShapingEvent> {
        self.application_events.borrow_mut().next_event()
    }

    #[must_use]
    pub fn has_application_events(&self) -> bool {
        self.application_events.borrow_mut().has_events()
    }

    fn get_stream_mut(&mut self, stream_id: &u64) -> Option<&mut ChaffStream> {
        match self.chaff_streams.get_mut(stream_id) {
            Some(stream) => Some(stream),
            None => self.app_streams.get_mut(stream_id),
        }
    }

    fn get_stream(&self, stream_id: &u64) -> Option<&ChaffStream> {
        match self.chaff_streams.get(stream_id) {
            Some(stream) => Some(stream),
            None => self.app_streams.get(stream_id),
        }
    }

    pub fn send_budget_available(&self, stream_id: u64) -> u64 {
        self.get_stream(&stream_id)
            .expect("Stream to already be tracked.")
            .send_budget_available()
    }

    pub fn is_send_throttled(&self, stream_id: u64) -> bool {
        if StreamId::is_bidi(stream_id.into()) {
            self.get_stream(&stream_id)
                .expect("Stream to already be tracked.")
                .is_send_throttled()
        } else {
            false
        }
    }

    pub fn is_recv_throttled(&self, stream_id: u64) -> bool {
        if StreamId::is_bidi(stream_id.into()) {
            self.get_stream(&stream_id)
                .expect("Stream to already be tracked.")
                .is_recv_throttled()
        } else {
            false
        }
    }
}

impl Display for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "FlowShaper")
    }
}

impl std::fmt::Debug for FlowShaper {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "FlowShaper {{ config: {:?}, start_time: {:?}, ... }}",
               self.config, self.start_time)
    }
}


impl HEventConsumer for FlowShaper {
    fn awaiting_header_data(&mut self, stream_id: u64, min_remaining: u64) {
        self.get_stream_mut(&stream_id)
            .expect("Stream to already be tracked.")
            .awaiting_header_data(min_remaining);
    }

    fn on_content_length(&mut self, stream_id: u64, length: u64) {
        self.get_stream_mut(&stream_id)
            .expect("Stream to already be tracked.")
            .on_content_length(length);
    }

    fn on_data_frame(&mut self, stream_id: u64, length: u64) {
        self.get_stream_mut(&stream_id)
            .expect("Stream to already be tracked.")
            .on_data_frame(length);
    }

    fn on_http_request_sent(&mut self, stream_id: u64, resource: &Resource, is_chaff: bool) {
        qdebug!([self], "notified of http request sent \
                {{ stream_id: {}, resource: {:?}, is_chaff: {} }}", stream_id, resource, is_chaff);

        let mut stream = ChaffStream::new(
            stream_id, resource.url.clone(), self.events.clone(),
            self.config.initial_max_stream_data,
            self.config.max_stream_data_excess,
            is_chaff || !self.defence.is_padding_only()
        ).with_headers(&resource.headers);

        if is_chaff && resource.length > 0 {
            stream = stream.with_msd_limit(resource.length)
        }
        if is_chaff && self.is_sending_unthrottled {
            stream.unthrottle_sending();
        }

        let streams = if is_chaff {
            self.log.chaff_stream_id(stream_id).expect("log unsuccessful");
            &mut self.chaff_streams
        } else {
            &mut self.app_streams
        };

        streams.insert(stream);

        if !self.chaff_manager.has_started() {
            self.chaff_manager.start();
        }

        qtrace!([self], "chaff-streams: {}, app-streams: {}", self.chaff_streams.len(),
                self.app_streams.len());
    }

    fn on_application_complete(&mut self) {
        self.defence.on_application_complete();
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
    }

    fn data_sent(&mut self, stream_id: u64, amount: u64) {
        if StreamId::new(stream_id).is_uni() {
            return;
        }

        self.get_stream_mut(&stream_id)
            .expect("Stream should already be tracked.")
            .data_sent(amount)
    }

    fn data_queued(&mut self, stream_id: u64, amount: u64) {
        if StreamId::new(stream_id).is_uni() {
            return;
        }

        self.get_stream_mut(&stream_id)
            .expect("Stream should already be tracked.")
            .data_queued(amount)
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
        // We have disabled PUSH streams, so these should only be control streams
        // from the server
        if StreamId::new(stream_id).is_uni() {
            return;
        }

        let unsent_msd_increase = self.events.borrow_mut().remove_by_id(&stream_id);
        if !self.config.drop_unsat_events && unsent_msd_increase > 0 {
            self.incoming_backlog += u32::try_from(unsent_msd_increase).unwrap();
            qtrace!([self], "Unsatisifed excess MSD of stream {} added to backlog: {}",
                    stream_id, unsent_msd_increase);
        }

        let stream = self.get_stream_mut(&stream_id)
            .expect(&format!("Stream should be tracked: {:?}", stream_id));
        stream.close_receiving();

        let resource = Resource::new(
            stream.url().clone(), stream.headers().clone(), stream.data_length());
        self.chaff_manager.add_resource(resource);

        // Possibly open new chaff streams
        self.chaff_manager.request_chaff_streams(&self.chaff_streams);
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

    fn drain(defence: &mut Box<dyn Defencev2>) -> Vec<(u32, i32)> {
        let mut remaining = Vec::new();
        while let Some(pkt) = defence.next_event(Duration::from_millis(10000)) {
            remaining.push(pkt.as_tuple());
        }
        remaining
    }

    fn create_shaper() -> FlowShaper {
        let packets = vec![(2, 1350), (16, -4800), (21, 600), (22, -350)];
        let packets: Vec<Packet> = packets.into_iter().map(Packet::from).collect();
        let schedule = StaticSchedule::new(&packets, true);

        FlowShaper::new(Config::default(), Box::new(schedule))
    }

    fn create_shaper_with_trace(vec: Vec<(u32, i32)>, interval: u64) -> FlowShaper {
        let packets: Vec<Packet> = vec.into_iter().map(Packet::from).collect();
        let schedule = StaticSchedule::new(&packets, true);

        FlowShaper::new(
            Config{ control_interval: interval, ..Config::default() }, Box::new(schedule))
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
    fn test_next_signal_time() {
        let mut shaper = create_shaper();
        assert_eq!(shaper.next_signal_time(), None);

        shaper.start();
        // next_signal_time() also will take the greater of the time and now
        assert!(shaper.next_signal_time()
                > Some(shaper.start_time.unwrap() + Duration::from_millis(0)))
    }

    #[test]
    fn process_timer_should_not_block() {
        let mut shaper = create_shaper_with_trace(
            vec![(1, -1500), (3, 1350), (10, -700), (18, 500)], 1);
        shaper.process_timer_(Duration::from_millis(10));

        let mut events = shaper.events.borrow_mut();
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendPaddingFrames(1350)));
    }

    #[test]
    fn process_timer_pulls_traffic() {
        let mut shaper = create_shaper_with_trace(
            vec![(3, -1500), (9, 1350), (17, -700), (18, 500)], 1);
        shaper.on_http_request_sent(4, &Resource::from(Url::parse("https://a.com").unwrap()), true);
        shaper.on_first_byte_sent(4);
        shaper.data_consumed(4, BLOCKED_STREAM_LIMIT);
        shaper.on_data_frame(4, 6000);

        shaper.process_timer_(Duration::from_millis(5));

        let mut events = shaper.events.borrow_mut();
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendMaxStreamData {
            stream_id: 4, new_limit: BLOCKED_STREAM_LIMIT + 1500, increase: 1500
        }));

        assert_eq!(drain(&mut shaper.defence), vec![(9, 1350), (17, -700), (18, 500)]);
    }

    #[test]
    fn process_timer_pulls_and_pushes_multiple() {
        let mut shaper = create_shaper_with_trace(
            vec![(1, -1200), (3, 1350), (10, -700), (12, 600), (15, 800)], 1);
        shaper.on_http_request_sent(4, &Resource::from(Url::parse("https://a.com").unwrap()), true);
        shaper.on_first_byte_sent(4);
        shaper.data_consumed(4, BLOCKED_STREAM_LIMIT);
        shaper.on_data_frame(4, 6000);

        shaper.process_timer_(Duration::from_millis(14));

        let mut events = shaper.events.borrow_mut();
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendPaddingFrames(1350)));
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendPaddingFrames(600)));
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendMaxStreamData {
            stream_id: 4, new_limit: BLOCKED_STREAM_LIMIT + 1900, increase: 1900
        }));

        assert_eq!(drain(&mut shaper.defence), vec![(15, 800)]);
    }

    #[test]
    fn process_timer_pulls_per_ci() {
        let mut shaper = create_shaper_with_trace(
            vec![(1, -100), (2, -200), (4, -400), (6, -350)], 3);

        // Fake open a stream, and increase the limit by 6000 bytes
        shaper.on_http_request_sent(
            4, &Resource::from(Url::parse("https://a.com").unwrap()), true);
        shaper.on_first_byte_sent(4);
        shaper.data_consumed(4, BLOCKED_STREAM_LIMIT);
        shaper.on_data_frame(4, 6000);

        assert_eq!(shaper.next_ci, Duration::from_millis(3));
        assert_eq!(shaper.incoming_backlog, 0);

        shaper.process_timer_(Duration::from_millis(1));
        assert_eq!(shaper.next_ci, Duration::from_millis(3));
        assert_eq!(shaper.incoming_backlog, 100);

        shaper.process_timer_(Duration::from_millis(5));
        assert_eq!(shaper.next_ci, Duration::from_millis(6));
        assert_eq!(shaper.incoming_backlog, 400);
        let mut events = shaper.events.borrow_mut();
        assert_eq!(events.next_event(), Some(FlowShapingEvent::SendMaxStreamData {
            stream_id: 4, new_limit: BLOCKED_STREAM_LIMIT + 300, increase: 300
        }));
    }
}
