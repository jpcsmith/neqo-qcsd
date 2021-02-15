use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use url::Url;
use neqo_common::qtrace;
use crate::stream_id::StreamId;
use crate::events::FlowShapingEvents;

const DEFAULT_RX_DATA_WINDOW: u64 = 1048576;
const MAX_FRAME_OVERHEAD: u64 = 16;


#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChaffStreamState {
    Created{ initial_msd: u64, throttled: bool },
    ReceivingHeaders {
        max_stream_data: u64,
        max_stream_data_limit: u64,
        data_consumed: u64,
    },
    ReceivingData {
        max_stream_data: u64,
        max_stream_data_limit: u64,
        data_consumed: u64,
        data_length: u64,
    },
    Unthrottled { data_length: u64 },
    Closed { data_length: u64 },
}

impl ChaffStreamState {
    fn new(initial_msd: u64, throttled: bool) -> Self {
        Self::Created { initial_msd, throttled }
    }

    fn name(&self) -> &str {
        match self {
            Self::Created { .. } => "Created",
            Self::ReceivingHeaders { .. } => "ReceivingHeaders",
            Self::ReceivingData { .. } => "ReceivingData",
            Self::Closed { .. } => "Closed",
            Self::Unthrottled { .. } => "Unthrottled",
        }
    }

    fn data_length(&self) -> Option<u64> {
        match self {
            Self::ReceivingData { data_length, .. } | Self::Unthrottled { data_length, .. }
            | Self::Closed { data_length, .. } => Some(*data_length),
            Self::Created { .. } | Self::ReceivingHeaders { .. } => None
        }
    }

    fn is_throttled(&self) -> bool {
        match self {
            Self::Created { throttled, .. } => *throttled,
            Self::ReceivingHeaders { .. } | Self::ReceivingData { .. } 
            | Self::Closed { .. } => true,
            Self::Unthrottled { .. } => false
        }
    }

    #[allow(dead_code)]
    fn msd_available(&self) -> u64 {
        match self {
            Self::ReceivingHeaders { max_stream_data, max_stream_data_limit, .. }
            | Self::ReceivingData { max_stream_data, max_stream_data_limit, .. } => {
                max_stream_data_limit - max_stream_data
            },
            Self::Created { .. } | Self::Closed { .. } => 0,
            Self::Unthrottled { .. } => std::u64::MAX,
        }
    }
}


#[derive(Debug, PartialEq, Eq)]
enum SendState {
    Throttled { pending: u64, allowed: u64, },
    Unthrottled,
    Closed,
}

impl SendState {
    pub fn throttled() -> Self {
        Self::Throttled { pending: 0, allowed: 0 }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Throttled { .. } => "Throttled [Send]",
            Self::Unthrottled => "Unthrottled [Send]",
            Self::Closed => "Closed [Send]"
        }
    }
}


#[derive(Debug)]
pub(crate) struct ChaffStream {
    stream_id: StreamId,
    url: Url,
    state: ChaffStreamState,
    send_state: SendState,
    events: Rc<RefCell<FlowShapingEvents>>,
}

impl ChaffStream {
    pub fn new(
        stream_id: u64,
        url: Url,
        events: Rc<RefCell<FlowShapingEvents>>,
        initial_msd: u64,
    ) -> Self {
        ChaffStream {
            stream_id: StreamId::new(stream_id),
            url,
            state: ChaffStreamState::new(initial_msd, false),
            send_state: SendState::Unthrottled,
            events,
        }
    }

    pub fn new_t(
        stream_id: u64,
        url: Url,
        events: Rc<RefCell<FlowShapingEvents>>,
        initial_msd: u64,
        throttled: bool,
    ) -> Self {
        ChaffStream {
            stream_id: StreamId::new(stream_id),
            url,
            state: ChaffStreamState::new(initial_msd, throttled),
            send_state: if throttled { SendState::throttled() } 
                        else { SendState::Unthrottled },
            events,
        }
    }

    pub fn is_throttled(&self) -> bool {
        self.state.is_throttled()
    }

    pub fn msd_available(&self) -> u64 {
        self.state.msd_available()
    }

    pub fn open(&mut self) {
        self.state = match self.state {
            ChaffStreamState::Created { initial_msd, throttled: true } => {
                ChaffStreamState::ReceivingHeaders {
                    max_stream_data: initial_msd,
                    max_stream_data_limit: initial_msd,
                    data_consumed: 0,
                }
            },
            ChaffStreamState::Created { initial_msd, throttled: false, .. } => {
                self.events.borrow_mut()
                    .send_max_stream_data(&self.stream_id, DEFAULT_RX_DATA_WINDOW, 
                                          DEFAULT_RX_DATA_WINDOW - initial_msd);

                ChaffStreamState::Unthrottled{ data_length: 0 }
            },
            _ => panic!("Cannot open stream from current state!")
        };
    }

    pub fn close(&mut self) {
        let closed_state = ChaffStreamState::Closed {
            data_length: self.state.data_length().unwrap_or(0)
        };
        qtrace!([self], "{} -> {}", self.state.name(), closed_state.name());
        self.state = closed_state;
    }

    pub fn close_sending(&mut self) {
        qtrace!([self], "{} -> {}", self.send_state.name(), SendState::Closed.name());
        self.send_state = SendState::Closed;
    }

    pub fn close_receiving(&mut self) {
        self.close()
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self.state,
            ChaffStreamState::ReceivingHeaders{ .. } | ChaffStreamState::ReceivingData { .. }
        )
    }

    /// Pull data on this stream. Return the amount of data pulled.
    pub fn pull_data(&mut self, amount: u64) -> u64 {
        let msd_available = self.msd_available();

        match self.state {
            ChaffStreamState::ReceivingHeaders{ ref mut max_stream_data, .. }
            | ChaffStreamState::ReceivingData{ ref mut max_stream_data, .. } => {
                match std::cmp::min(amount, msd_available) {
                    0 => 0,
                    pull_amount => {
                        *max_stream_data += pull_amount;
                        self.events.borrow_mut()
                            .send_max_stream_data(
                                &self.stream_id, *max_stream_data, pull_amount);
                        pull_amount
                    }
                }
            },
            _ => panic!("Cannot pull data for stream in current state!")
        }
    }

    pub fn data_consumed(&mut self, amount: u64) {
        qtrace!([self], "Recording consumption of {} data.", amount);
        match self.state {
            ChaffStreamState::ReceivingHeaders {
                ref mut data_consumed, max_stream_data_limit, ..  }
            | ChaffStreamState::ReceivingData {
                ref mut data_consumed, max_stream_data_limit, ..  } => {
                *data_consumed += amount;
                qtrace!("New values: {} <= {}", *data_consumed, max_stream_data_limit);
                // TODO: Enable assert once we actually control
                // assert!(*data_consumed <= max_stream_data_limit);
            },
            ChaffStreamState::Closed{ .. } | ChaffStreamState::Unthrottled { .. } => (),
            _ => panic!("Data should not be consumed in the current state.")
        };

    }

    pub fn awaiting_header_data(&mut self, min_remaining: u64) {
        qtrace!([self], "Needs {} bytes for header data {:?}.", min_remaining, self.state);
        match self.state {
            ChaffStreamState::ReceivingHeaders {
                ref mut max_stream_data_limit, data_consumed, .. }
            | ChaffStreamState::ReceivingData {
                ref mut max_stream_data_limit, data_consumed, ..
            } => {
                *max_stream_data_limit = std::cmp::max(
                    data_consumed + min_remaining + MAX_FRAME_OVERHEAD,
                    *max_stream_data_limit);
            },
            ChaffStreamState::Closed { .. } | ChaffStreamState::Unthrottled { .. } => (),
            _ => panic!("Should not receive data frame in other states!")
        }
    }

    /// Called when HTTP/3 has parsed a data frame's length on this stream.
    ///
    /// Increase the MSD limit by the length of the data. Depending on how
    /// many header frames were before this data frame, the actual MSD limit
    /// may be different from the amount of data available by up to 14 bytes
    /// per header frame received on the stream.
    pub fn on_data_frame(&mut self, length: u64) {
        qtrace!([self], "Encountered data frame with length {}, {:?}", length, self.state);
        match self.state {
            ChaffStreamState::ReceivingHeaders{
                max_stream_data, max_stream_data_limit, data_consumed,
            } => {
                assert!(data_consumed + length >= max_stream_data_limit);
                self.state = ChaffStreamState::ReceivingData {
                    max_stream_data,
                    max_stream_data_limit: data_consumed + length,
                    data_consumed,
                    data_length: length,
                }
            },
            ChaffStreamState::ReceivingData {
                ref mut max_stream_data_limit, data_consumed, ref mut data_length, ..
            } => {
                // It seems to be possible to receive multiple HTTP/3 data
                // frames in response to a request, we therefore aggregate
                // their lengths
                assert!(data_consumed + length >= *max_stream_data_limit);
                // It's not possible to encounter another dataframe without having parsed
                // the previous, so we only consider bytes consumed in determining the new 
                // limit.
                *max_stream_data_limit = data_consumed + length;
                *data_length += length;
            },
            ChaffStreamState::Unthrottled { ref mut data_length } => {
                *data_length += length;
            },
            ChaffStreamState::Closed{ .. } => (),
            _ => panic!("Should not receive data frame in other states!")
        }
    }

    /// Called to indicate the new or retransmitted data is awaiting 
    /// being sent on this stream.
    pub fn data_queued(&mut self, amount: u64) {
        match &mut self.send_state {
            SendState::Throttled { pending, .. } => *pending += amount,
            SendState::Unthrottled => (),
            SendState::Closed => panic!("Data queued while the stream is closed."),
        }
    }

    /// Called to indicate that data was sent on the stream.
    pub fn data_sent(&mut self, amount: u64) {
        match &mut self.send_state {
            SendState::Throttled { pending, allowed } => {
                assert!(amount <= *pending, "More data sent than was known pending.");
                assert!(amount <= *allowed, "More data sent than was allowed.");

                *pending -= amount;
                *allowed -= amount;
            },
            SendState::Unthrottled => (),
            SendState::Closed => panic!("Data sent while the stream is closed."),
        }
    }

    pub fn push_data(&mut self, amount: u64) -> u64 {
        match &mut self.send_state {
            SendState::Throttled { pending, allowed } => {
                assert!(*allowed <= *pending);
                let pushed = std::cmp::min(*pending - *allowed, amount);
                *allowed += pushed;

                pushed
            },
            SendState::Unthrottled | SendState::Closed => {
                panic!("Cannot push data in this state.");
            }
        }
    }
}


impl ::std::fmt::Display for ChaffStream {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "ChaffStream({})", self.stream_id)
    }
}


#[derive(Debug, Default)]
pub(crate) struct ChaffStreamMap(HashMap<u64, ChaffStream>);


impl ChaffStreamMap {
    /// Pull data from various streams amounting to `amount`.
    /// Return the actual amount pulled.
    pub fn pull_data(&mut self, amount: u64) -> u64 {
        let mut remaining = amount;

        for (_, stream) in self.iter_mut()
            .filter(|(_, stream)| stream.msd_available() > 0)
        {
            assert!(stream.msd_available() > 0);
            let pulled = stream.pull_data(remaining);

            remaining -= pulled;
            if remaining == 0 {
                break;
            }
        }

        amount - remaining
    }

    /// Send up to the specified amount of data, return the acutal amount 
    /// sent.
    pub fn push_data(&mut self, _amount: u64) -> u64 {
        // TODO(jsmith): Implement
        0
    }

    pub fn pull_available(&self) -> u64 {
        self.iter().fold(0, |total, (_, stream)| total + stream.msd_available())
    }

    pub fn can_pull(&self) -> bool {
        self.pull_available() > 0
    }

    // add a padding stream to the shaping streams
    pub fn insert(&mut self, stream: ChaffStream) {
        assert!(self.0.insert(stream.stream_id.as_u64(), stream).is_none())
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, stream_id: &u64) -> Option<&mut ChaffStream> {
        self.0.get_mut(stream_id)
    }

    pub fn open_stream(&mut self, stream_id: &u64) {
        self.0.get_mut(stream_id)
            .expect("chaff stream should already have been created")
            .open();
    }

    pub fn remove_dummy_stream(&mut self, stream_id: &u64) -> Url {
        if let Some(stream) = self.0.get_mut(stream_id) {
            stream.close();
            return stream.url.clone();
        } else {
            panic!("chaff stream should already have been created");
        }
    }

    pub fn contains(&self, stream_id: &u64) -> bool {
        self.0.contains_key(stream_id)
    }

    #[allow(dead_code)]
    pub fn has_open(&self) -> bool {
        self.0.iter().any(|(_, stream)| stream.is_open())
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> std::collections::hash_map::Iter<u64, ChaffStream> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<u64, ChaffStream> {
        self.0.iter_mut()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn create_stream(throttled: bool) -> ChaffStream {
        ChaffStream::new_t(0, Url::parse("https://a.com").unwrap(), 
                           Rc::new(RefCell::new(FlowShapingEvents::default())),
                           20, throttled)
    }

    mod recv_state {
        use super::*;
        use crate::events::FlowShapingEvent;
        use super::ChaffStreamState as State;


        #[test]
        fn test_creation() {
            let stream = create_stream(true);

            assert!(matches!(stream.state, State::Created { .. }));
            assert_eq!(stream.is_throttled(), true);

            let stream = ChaffStream::new_t(
                0, Url::parse("https://a.com").unwrap(), 
                Rc::new(RefCell::new(FlowShapingEvents::default())),
                20, false);
            assert!(matches!(stream.state, State::Created { .. }));
            assert_eq!(stream.is_throttled(), false);
        }

        #[test]
        fn test_open_throttled() {
            let events = Rc::new(RefCell::new(FlowShapingEvents::default()));
            let mut stream = ChaffStream::new_t(
                0, Url::parse("https://a.com").unwrap(), events.clone(), 20, true);
            stream.open();

            assert!(matches!(stream.state, State::ReceivingHeaders { .. }));
            assert_eq!(events.borrow().has_events(), false);
        }

        #[test]
        fn test_open_unthrottled() {
            let events = Rc::new(RefCell::new(FlowShapingEvents::default()));
            let mut stream = ChaffStream::new_t(
                0, Url::parse("https://a.com").unwrap(), events.clone(), 20, false);
            stream.open();

            assert!(matches!(stream.state, State::Unthrottled { data_length: 0 }));
            assert_eq!(events.borrow().has_events(), true);
            assert_eq!(events.borrow_mut().next_event(), Some(
                    FlowShapingEvent::SendMaxStreamData {
                        stream_id: 0,
                        new_limit: DEFAULT_RX_DATA_WINDOW,
                        increase: DEFAULT_RX_DATA_WINDOW - 20
                    }));
        }

        #[test]
        fn test_on_data_frame_throttled() {
            let mut stream = ChaffStream::new_t(
                0, Url::parse("https://a.com").unwrap(), 
                Rc::new(RefCell::new(FlowShapingEvents::default())),
                100, true);
            stream.open();

            assert!(matches!(stream.state, State::ReceivingHeaders { 
                max_stream_data_limit: 100, .. }));
            // We consume 80 bytes and encounter the first data frame
            stream.data_consumed(80);
            stream.on_data_frame(2100);
            assert!(matches!(stream.state, State::ReceivingData { 
                max_stream_data_limit: 2180, .. }));

            // We consume the previous frame and encounter the second data frame
            stream.data_consumed(2100);
            stream.on_data_frame(3200);
            assert!(matches!(stream.state, State::ReceivingData { 
                max_stream_data_limit: 5380, .. }));
        }

        #[test]
        fn test_on_data_frame_unthrottled() {
            let mut stream = ChaffStream::new_t(
                0, Url::parse("https://a.com").unwrap(), 
                Rc::new(RefCell::new(FlowShapingEvents::default())), 100, false);
            stream.open();

            assert!(matches!(stream.state, State::Unthrottled { data_length: 0 }));
            stream.on_data_frame(2100);
            assert!(matches!(stream.state, State::Unthrottled { data_length: 2100 }));
            stream.on_data_frame(3200);
            assert!(matches!(stream.state, State::Unthrottled { data_length: 5300 }));
        }

        #[test]
        fn test_data_consumed_throttled() {
            let mut stream = create_stream(true);
            stream.open();

            assert!(matches!(
                    stream.state, State::ReceivingHeaders { data_consumed: 0, .. }));
            stream.data_consumed(3000);
            assert!(matches!(
                    stream.state, State::ReceivingHeaders { data_consumed: 3000, .. }));

            stream.data_consumed(1000);
            assert!(matches!(
                    stream.state, State::ReceivingHeaders { data_consumed: 4000, .. }));
        }

        #[test]
        fn test_data_consumed_unthrottled() {
            let mut stream = create_stream(false);
            stream.open();

            assert!(matches!(stream.state, State::Unthrottled { .. }));
            stream.data_consumed(3000);
            assert!(matches!(stream.state, State::Unthrottled { .. }));
            stream.data_consumed(1000);
            assert!(matches!(stream.state, State::Unthrottled { .. }));
        }

        #[test]
        fn test_awaiting_header_data_unthrottled() {
            let mut stream = create_stream(false);
            stream.open();

            assert!(matches!(stream.state, State::Unthrottled { .. }));
            stream.awaiting_header_data(45);
            assert!(matches!(stream.state, State::Unthrottled { .. }));
            stream.awaiting_header_data(99);
            assert!(matches!(stream.state, State::Unthrottled { .. }));
        }

        #[test]
        fn test_awaiting_header_data_throttled() {
            let mut stream = create_stream(true);

            stream.open();
            assert_eq!(stream.state, State::ReceivingHeaders { 
                max_stream_data_limit: 20, max_stream_data: 20, data_consumed: 0
            });
            stream.awaiting_header_data(45);
            assert_eq!(stream.state, State::ReceivingHeaders { 
                max_stream_data_limit: 45 + MAX_FRAME_OVERHEAD, 
                max_stream_data: 20, data_consumed: 0
            });

            stream.awaiting_header_data(90);
            assert_eq!(stream.state, State::ReceivingHeaders { 
                max_stream_data_limit: 90 + MAX_FRAME_OVERHEAD, 
                max_stream_data: 20, data_consumed: 0
            });

            stream.data_consumed(70);
            stream.awaiting_header_data(100);
            assert_eq!(stream.state, State::ReceivingHeaders { 
                max_stream_data_limit: 170 + MAX_FRAME_OVERHEAD, 
                max_stream_data: 20, data_consumed: 70
            });
        }

        #[test]
        #[should_panic]
        fn test_pull_data_non_open() {
            let mut stream = create_stream(true);
            stream.pull_data(1000);
        }

        #[test]
        fn test_pull_data() {
            let mut stream = create_stream(true);
            let events = stream.events.clone();

            stream.open();
            let pulled = stream.pull_data(1000);
            assert_eq!(pulled, 0);
            assert_eq!(stream.state, State::ReceivingHeaders {
                max_stream_data_limit: 20, max_stream_data: 20, data_consumed: 0,
            });
            assert_eq!(events.borrow().has_events(), false);

            stream.on_data_frame(5000);
            let pulled = stream.pull_data(2000);
            assert_eq!(pulled, 2000);
            assert_eq!(stream.state, State::ReceivingData {
                max_stream_data_limit: 5000, max_stream_data: 2020, data_consumed: 0,
                data_length: 5000,
            });
            assert_eq!(events.borrow_mut().next_event(), Some(
                    FlowShapingEvent::SendMaxStreamData {
                        stream_id: 0, new_limit: 2020, increase: 2000
                    }));
        }

        #[test]
        fn test_data_queued() {
            let mut stream = create_stream(true);

            assert_eq!(stream.send_state, SendState::Throttled { pending: 0, allowed: 0, });
            stream.data_queued(1000);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 1000, allowed: 0, });
            stream.data_queued(1500);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 2500, allowed: 0, });
        }

        #[test]
        #[should_panic(expected = "More data sent than was allowed.")]
        fn test_data_sent_no_budget() {
            let mut stream = create_stream(true);
            stream.send_state = SendState::Throttled { pending: 500, allowed: 100, };
            stream.data_sent(500);
        }

        #[test]
        #[should_panic(expected = "More data sent than was known pending.")]
        fn test_data_sent_desync() {
            let mut stream = create_stream(true);
            stream.send_state = SendState::Throttled { pending: 100, allowed: 500, };
            stream.data_sent(500);
        }

        #[test]
        fn test_data_sent() {
            let mut stream = create_stream(true);
            stream.send_state = SendState::Throttled { pending: 900, allowed: 500, };

            stream.data_sent(300);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 600, allowed: 200 });
        }

        #[test]
        fn test_push_data() {
            let mut stream = create_stream(true);

            let pushed = stream.push_data(500);
            assert_eq!(pushed, 0);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 0, allowed: 0 });

            stream.data_queued(300);
            let pushed = stream.push_data(400);
            assert_eq!(pushed, 300);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 300, allowed: 300 });

            stream.data_queued(200);
            let pushed = stream.push_data(500);
            assert_eq!(pushed, 200);
            assert_eq!(stream.send_state, SendState::Throttled { pending: 500, allowed: 500 });
        }

        #[test]
        fn test_close_receiving() {
            let mut stream = create_stream(true);

            stream.close_receiving();
            assert_eq!(stream.state, ChaffStreamState::Closed { data_length: 0 });
        }

        #[test]
        fn test_close_sending() {
            let mut stream = create_stream(true);

            stream.close_sending();
            assert_eq!(stream.send_state, SendState::Closed);
        }
    }

    mod unthrottled {
        use super::*;

        #[test]
        fn test_data_sent() {
            let mut stream = create_stream(false);

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.data_sent(500);
            assert_eq!(stream.send_state, SendState::Unthrottled);
        }

        #[test]
        fn test_data_queued() {
            let mut stream = create_stream(false);

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.data_queued(1000);
            assert_eq!(stream.send_state, SendState::Unthrottled);
        }

        #[test]
        #[should_panic(expected = "Cannot push data in this state.")]
        fn test_push_data() {
            let mut stream = create_stream(false);

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.push_data(3000);
        }
    }
}
