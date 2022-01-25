use std::collections::HashMap;
use std::rc::Rc;
use std::cell::{ RefCell, Cell };
use url::Url;
use neqo_common::{qtrace, qwarn};
use crate::stream_id::StreamId;
use crate::event::FlowShapingEvents;

const DEFAULT_RX_DATA_WINDOW: u64 = 1048576;


#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecvState {
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

impl RecvState {
    fn new(initial_msd: u64, throttled: bool) -> Self {
        Self::Created { initial_msd, throttled }
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
            Self::ReceivingHeaders { .. } | Self::ReceivingData { .. } => true,
            Self::Unthrottled { .. } | Self::Closed { .. } => false
        }
    }

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

    #[cfg(test)]
    fn max_stream_data_limit(&self) -> Option<u64> {
        match self {
            Self::ReceivingHeaders { max_stream_data_limit, .. }
            | Self::ReceivingData { max_stream_data_limit, .. } 
                => Some(*max_stream_data_limit),
            Self::Created { .. } | Self::Closed { .. } | Self::Unthrottled { .. } 
                => None,
        }

    }

    /// Ensure that there is at least `credit` more limit available than data 
    /// consumed to this point.
    fn make_available(&mut self, credit: u64) {
        match self {
            Self::ReceivingHeaders { max_stream_data_limit, data_consumed, .. } 
            | Self::ReceivingData { max_stream_data_limit, data_consumed, .. } => {
                if *data_consumed + credit > *max_stream_data_limit {
                    *max_stream_data_limit = *data_consumed + credit;
                }
            },
            Self::Created {..} | Self::Closed {..} | Self::Unthrottled {..}
                => panic!("Cannot increase limit in this state"),
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
        SendState::with_limits(0, 0)
    }

    pub fn with_limits(pending: u64, allowed: u64) -> Self {
        assert!(allowed <= pending, "Throttled cannot have more allowed than pending.");
        SendState::Throttled { pending, allowed }
    }

    pub fn is_throttled(&self) -> bool {
        match self {
            Self::Throttled { .. } => true,
            Self::Unthrottled | Self::Closed => false
        }
    }

    pub fn pending_bytes(&self) -> u64 {
        match self {
            Self::Throttled { pending, .. } => *pending,
            Self::Unthrottled | Self::Closed => 0,
        }
    }

    pub fn allowed_to_send(&self) -> u64 {
        match self {
            Self::Throttled { allowed, .. } => *allowed,
            Self::Unthrottled | Self::Closed => std::u64::MAX,
        }
    }
}


#[derive(Debug)]
pub(crate) struct ChaffStream {
    stream_id: StreamId,
    url: Url,
    headers: Vec<(String, String)>,
    initial_msd_limit: Option<u64>,
    msd_excess: u64,
    recv_state: RecvState,
    send_state: SendState,
    events: Rc<RefCell<FlowShapingEvents>>,
}

impl ChaffStream {
    pub fn new(
        stream_id: u64,
        url: Url,
        events: Rc<RefCell<FlowShapingEvents>>,
        initial_msd: u64,
        msd_excess: u64,
        throttled: bool,
    ) -> Self {
        let stream = ChaffStream {
            stream_id: StreamId::new(stream_id),
            url,
            recv_state: RecvState::new(initial_msd, throttled),
            send_state: if throttled { SendState::throttled() }
                        else { SendState::Unthrottled },
            events,
            initial_msd_limit: None,
            msd_excess,
            headers: Vec::new(),
        };
        qtrace!([stream], "stream created {:?}", stream);
        stream
    }

    pub fn with_headers(mut self, headers: &[(String, String)]) -> Self {
        self.headers = headers.iter().cloned().collect();
        self
    }

    pub fn headers(&self) -> &Vec<(String, String)> {
        &self.headers
    }

    pub fn with_msd_limit(mut self, msd_limit: u64) -> Self {
        assert!(matches!(self.recv_state, RecvState::Created { .. }));
        assert!(msd_limit > 0, "cannot create with a zero msd limit");

        match self.recv_state {
            RecvState::Created { initial_msd, .. } => {
                self.initial_msd_limit = Some(std::cmp::max(msd_limit, initial_msd));
                qtrace!([&self], "updated MSD limit: max(initial_msd={}, {})",
                        initial_msd, msd_limit);
            },
            _ => unreachable!("must be in the created state.")
        };
        self
    }

    fn transition_send(&mut self, next: SendState) {
        qtrace!([self], "SendState: {:?} -> {:?}", self.send_state, next);
        self.send_state = next;
    }

    fn transition_recv(&mut self, next: RecvState) {
        qtrace!([self], "RecvState: {:?} -> {:?}", self.recv_state, next);
        self.recv_state = next;
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    #[cfg(test)]
    fn is_throttled(&self) -> bool {
        self.is_recv_throttled() || self.is_send_throttled()
    }

    pub fn is_recv_throttled(&self) -> bool {
        self.recv_state.is_throttled()
    }

    pub fn is_send_throttled(&self) -> bool {
        self.send_state.is_throttled()
    }

    pub fn unthrottle_sending(&mut self) {
        match self.send_state {
            SendState::Throttled{..} => self.transition_send(SendState::Unthrottled),
            SendState::Unthrottled | SendState::Closed => (),
        }
    }

    pub fn msd_available(&self) -> u64 {
        self.recv_state.msd_available()
    }

    pub fn pending_bytes(&self) -> u64 {
        self.send_state.pending_bytes()
    }

    pub fn open(&mut self) {
        match self.recv_state {
            RecvState::Created { initial_msd, throttled: true } => {
                let mut state = RecvState::ReceivingHeaders {
                    max_stream_data: initial_msd,
                    max_stream_data_limit: initial_msd,
                    data_consumed: 0,
                };
                state.make_available(
                    std::cmp::max(self.initial_msd_limit.unwrap_or(0), self.msd_excess)
                );
                self.transition_recv(state);
            },
            RecvState::Created { initial_msd, throttled: false, .. } => {
                self.events.borrow_mut()
                    .send_max_stream_data(&self.stream_id, DEFAULT_RX_DATA_WINDOW,
                                          DEFAULT_RX_DATA_WINDOW - initial_msd);

                self.transition_recv(RecvState::Unthrottled{ data_length: 0 });
            },
            _ => {
                qwarn!([self], "Trying to open stream in state {:?}", self.recv_state);
                return;
            }
        };
    }

    pub fn data_length(&self) -> u64 {
        self.recv_state.data_length().unwrap_or(0)
    }

    pub fn close_receiving(&mut self) {
        let data_length = self.recv_state.data_length().unwrap_or(0);
        self.transition_recv(RecvState::Closed { data_length });
    }

    #[cfg(test)]
    pub fn close_sending(&mut self) {
        self.transition_send(SendState::Closed);
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self.recv_state,
            RecvState::ReceivingHeaders{ .. } | RecvState::ReceivingData { .. }
        )
    }

    /// Note that this is not the opposite of is_open()
    pub fn is_recv_closed(&self) -> bool {
        // We consider a stream to be closed once the receive side is closed,
        // as an HTTP request must precede the response.
        matches!(self.recv_state, RecvState::Closed { .. })
    }

    /// Pull data on this stream. Return the amount of data pulled.
    pub fn pull_data(&mut self, amount: u64) -> u64 {
        let amount = std::cmp::min(amount, self.msd_available());
        if amount > 0 {
            qtrace!([self], "pulling data {}: {:?}", amount, self.recv_state);
        }

        match &mut self.recv_state {
            RecvState::ReceivingHeaders{ max_stream_data, .. }
            | RecvState::ReceivingData{ max_stream_data, .. } => {
                if amount == 0 { return 0 }

                *max_stream_data += amount;

                assert!(amount > 0);
                self.events.borrow_mut()
                    .send_max_stream_data(&self.stream_id, *max_stream_data, amount);

                qtrace!([self], "pulled data {:?}", self.recv_state);
                amount
            },
            RecvState::Created { .. } | RecvState::Unthrottled { .. }
            | RecvState::Closed { .. } 
                => panic!("Cannot pull data for stream in current state!"),
        }
    }

    pub fn data_consumed(&mut self, amount: u64) {
        match &mut self.recv_state {
            RecvState::ReceivingHeaders { data_consumed, max_stream_data_limit, ..  }
            | RecvState::ReceivingData { data_consumed, max_stream_data_limit, ..  } => {
                assert!(data_consumed <= max_stream_data_limit);
                *data_consumed += amount;

                self.recv_state.make_available(self.msd_excess);
                qtrace!([self], "data consumed {}: {:?}", amount, self.recv_state);
            },
            RecvState::Closed{ .. } | RecvState::Unthrottled { .. } => (),
            _ => panic!("Data should not be consumed in the current state.")
        };

    }

    pub fn awaiting_header_data(&mut self, min_remaining: u64) {
        qtrace!([self], "Needs {} bytes for header data {:?}.", min_remaining, self.recv_state);
        match self.recv_state {
            RecvState::ReceivingHeaders { .. } | RecvState::ReceivingData { ..  } => { 
                self.recv_state.make_available(
                    std::cmp::max(min_remaining, self.msd_excess));
                qtrace!([self], "{:?}", self.recv_state);
            },
            RecvState::Closed { .. } | RecvState::Unthrottled { .. } => (),
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
        qtrace!([self], "Encountered data frame with length {}, {:?}", length, self.recv_state);
        match self.recv_state {
            RecvState::ReceivingHeaders{ 
                max_stream_data, data_consumed, max_stream_data_limit, 
            } => {
                let mut state = RecvState::ReceivingData {
                    max_stream_data,
                    max_stream_data_limit,
                    data_consumed,
                    data_length: length,
                };
                state.make_available(std::cmp::max(length, self.msd_excess));

                self.transition_recv(state);
            },
            RecvState::ReceivingData { ref mut data_length, .. } => {
                // It seems to be possible to receive multiple HTTP/3 data
                // frames in response to a request, we therefore aggregate
                // their lengths
                // It's not possible to encounter another dataframe without having parsed
                // the previous, so we only consider bytes consumed in determining the new
                // limit.
                *data_length += length;

                self.recv_state.make_available(std::cmp::max(length, self.msd_excess));
                qtrace!([self], "{:?}", self.recv_state);
            },
            RecvState::Unthrottled { ref mut data_length } => {
                *data_length += length;
            },
            RecvState::Closed{ .. } => (),
            _ => panic!("Should not receive data frame in other states!")
        }
    }

    pub fn on_content_length(&mut self, amount: u64) {
        qtrace!([self], "Notified of content-length of {}", amount);
        match self.recv_state {
            RecvState::ReceivingHeaders { ref mut max_stream_data_limit, .. } 
            | RecvState::ReceivingData { ref mut max_stream_data_limit, .. } => {
                *max_stream_data_limit = std::cmp::max(*max_stream_data_limit, amount);
            }
            RecvState::Created { .. } => panic!("header received in created state."),
            | RecvState::Unthrottled { .. } | RecvState::Closed { .. } => ()
        }
    }

    /// Called to indicate the new or retransmitted data is awaiting
    /// being sent on this stream.
    pub fn data_queued(&mut self, amount: u64) {
        qtrace!([self], "data queued: {}", amount);
        match &mut self.send_state {
            SendState::Throttled { pending, .. } => *pending += amount,
            SendState::Unthrottled => (),
            SendState::Closed => panic!("Data queued while the stream is closed."),
        }
    }

    /// Called to indicate that data was sent on the stream.
    pub fn data_sent(&mut self, amount: u64) {
        qtrace!([self], "data sent: {}", amount);
        match &mut self.send_state {
            SendState::Throttled { pending: _, allowed: _ } => {
                // assert!(amount <= *pending, "More data sent than was known pending.");
                // assert!(amount <= *allowed, "More data sent than was allowed.");

                // *pending -= amount;
                // *allowed -= amount;
            },
            SendState::Unthrottled => (),
            SendState::Closed => panic!("Data sent while the stream is closed."),
        }
    }

    pub fn blocked_pending_bytes(&self) -> u64 {
        self.send_state.pending_bytes() - self.send_state.allowed_to_send()
    }

    pub fn send_budget_available(&self) -> u64 {
        self.send_state.allowed_to_send()
    }

    pub fn push_data(&mut self, amount: u64) -> u64 {
        let pushed = match &mut self.send_state {
            SendState::Throttled { pending, allowed } => {
                assert!(*allowed <= *pending);
                let pushed = std::cmp::min(*pending - *allowed, amount);
                *allowed += pushed;

                pushed
            },
            SendState::Unthrottled | SendState::Closed => {
                panic!("Cannot push data in this state.");
            }
        };

        qtrace!([self], "released data to be sent: {}", pushed);
        pushed
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
        // TODO(jsmith): We ought to pull data from streams that are in the
        // receiving header phase first, so that they open up.
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

    /// Push up to the specified amount of data, return the acutal amount
    /// pushed. Streams are selected in order of their stream id.
    pub fn push_data(&mut self, amount: u64) -> u64 {
        let remaining = Cell::new(amount);

        // Sort blocked streams in order of their open state and stream ID
        // This places closed streams before open streams, and then lower
        // stream id first
        let mut streams: Vec<&mut ChaffStream> = self.0.values_mut()
            .filter(|stream| stream.blocked_pending_bytes() > 0)
            .collect();
        streams.sort_by_key(|stream| (stream.is_open(), stream.stream_id));

        streams.iter_mut()
            .take_while(|_| remaining.get() > 0)
            .for_each(|stream| {
                let pushed = stream.push_data(remaining.get());
                remaining.set(remaining.get() - pushed);
            });

        amount - remaining.take()
    }

    pub fn pull_available(&self) -> u64 {
        self.iter().fold(0, |total, (_, stream)| total + stream.msd_available())
    }

    pub fn push_available(&self) -> u64 {
        self.iter().fold(0, |total, (_, stream)| total + stream.pending_bytes())
    }

    pub fn can_pull(&self) -> bool {
        self.pull_available() > 0
    }

    // add a padding stream to the shaping streams
    pub fn insert(&mut self, stream: ChaffStream) {
        assert!(self.0.insert(stream.stream_id.as_u64(), stream).is_none())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get_mut(&mut self, stream_id: &u64) -> Option<&mut ChaffStream> {
        self.0.get_mut(stream_id)
    }

    pub fn get(&self, stream_id: &u64) -> Option<&ChaffStream> {
        self.0.get(stream_id)
    }

    pub fn contains(&self, stream_id: &u64) -> bool {
        self.0.contains_key(stream_id)
    }

    #[allow(dead_code)]
    pub fn has_open(&self) -> bool {
        self.0.iter().any(|(_, stream)| stream.is_open())
    }

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

    const MAX_FRAME_OVERHEAD: u64 = 1500;


    mod recv_state {
        use super::*;

        macro_rules! test_make_available {
            ($name:ident, $state:expr, $amount:literal, $expected:literal) => {
                #[test]
                fn $name() {
                    let mut state = $state;
                    state.make_available($amount);
                    assert_eq!(state.max_stream_data_limit(), Some($expected));
                }
            };
        }

        test_make_available!(
            make_available_rhdr_sufficient, RecvState::ReceivingHeaders { 
                max_stream_data: 1000, max_stream_data_limit: 1000, data_consumed: 0
            }, 500, 1000);
        test_make_available!(
            make_available_rhdr_inrease, RecvState::ReceivingHeaders { 
                max_stream_data: 2000, max_stream_data_limit: 3000, data_consumed: 1900
            }, 2000, 3900);
        test_make_available!(
            make_available_rdata_sufficient, RecvState::ReceivingData { 
                max_stream_data: 1000, max_stream_data_limit: 1000, data_consumed: 500,
                data_length: 900,
            }, 600, 1100);
    }

    struct StreamBuilder {
        stream_id: u64,
        throttled: bool,
        initial_msd: u64,
        recv_open: bool,
        events: Rc<RefCell<FlowShapingEvents>>,
    }

    impl StreamBuilder {
        fn new(stream_id: u64) -> StreamBuilder {
            StreamBuilder {
                stream_id: stream_id,
                throttled: false,
                initial_msd: 0,
                recv_open: false,
                events: Default::default()
            }
        }

        fn throttled(&mut self, state: bool) -> &mut Self {
            self.throttled = state;
            self
        }

        fn with_initial_msd(&mut self, initial_msd: u64) -> &mut Self {
            self.initial_msd = initial_msd;
            self
        }

        fn with_events(&mut self, events: &Rc<RefCell<FlowShapingEvents>>) -> &mut Self {
            self.events = events.clone();
            self
        }

        fn with_recv_open(&mut self) -> &mut Self {
            self.recv_open = true;
            self
        }

        fn opened(&mut self) -> ChaffStream {
            self.recv_open = true;
            self.build()
        }

        fn with_send_state(&mut self, state: SendState) -> ChaffStream {
            let mut stream = self.build();
            stream.send_state = state;
            stream
        }

        fn build(&mut self) -> ChaffStream {
            let mut stream = ChaffStream::new(
                self.stream_id, Url::parse("https://www.example.com").unwrap(),
                Default::default(), self.initial_msd, MAX_FRAME_OVERHEAD, self.throttled);
            if self.recv_open {
                stream.open();
            }
            stream
        }
    }

    mod throttled {
        use super::*;
        use crate::event::{ FlowShapingEvent, Provider };

        fn throttled_stream() -> StreamBuilder {
            let mut bldr = StreamBuilder::new(0);
            bldr.with_initial_msd(20).throttled(true);
            bldr
        }

        #[test]
        fn test_creation() {
            let stream = ChaffStream::new(
                0, Url::parse("https://a.com").unwrap(),
                Rc::new(RefCell::new(FlowShapingEvents::default())),
                20, MAX_FRAME_OVERHEAD, true);

            assert!(matches!(stream.recv_state, RecvState::Created { .. }));
            assert_eq!(stream.is_throttled(), true);

            let stream = ChaffStream::new(
                0, Url::parse("https://a.com").unwrap(),
                Rc::new(RefCell::new(FlowShapingEvents::default())),
                20, MAX_FRAME_OVERHEAD, false);
            assert!(matches!(stream.recv_state, RecvState::Created { .. }));
            assert_eq!(stream.is_throttled(), false);
        }

        #[test]
        fn test_open() {
            let mut stream = throttled_stream().build();
            let events = stream.events.clone();

            stream.open();
            assert!(matches!(stream.recv_state, RecvState::ReceivingHeaders { .. }));
            assert_eq!(events.borrow().has_events(), false);
        }

        #[test]
        fn test_on_data_frame() {
            let mut stream = throttled_stream()
                .with_initial_msd(100)
                .opened();

            assert!(matches!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD, .. }));
            // We consume 80 bytes and encounter the first data frame
            stream.data_consumed(80);
            stream.on_data_frame(2100);
            assert!(matches!(stream.recv_state, RecvState::ReceivingData {
                max_stream_data_limit: 2180, .. }));

            // We consume the previous frame and encounter the second data frame
            stream.data_consumed(2100);
            stream.on_data_frame(3200);
            assert!(matches!(stream.recv_state, RecvState::ReceivingData {
                max_stream_data_limit: 5380, .. }));
        }

        #[test]
        fn test_data_consumed() {
            let mut stream = throttled_stream().opened();

            assert!(matches!(
                    stream.recv_state,
                    RecvState::ReceivingHeaders { data_consumed: 0, .. }));
            stream.data_consumed(3000);
            assert!(matches!(
                    stream.recv_state,
                    RecvState::ReceivingHeaders { data_consumed: 3000, .. }));

            stream.data_consumed(1000);
            assert!(matches!(
                    stream.recv_state,
                    RecvState::ReceivingHeaders { data_consumed: 4000, .. }));
        }

        #[test]
        fn test_awaiting_header_data() {
            let mut stream = throttled_stream().opened();

            assert_eq!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD, max_stream_data: 20,
                data_consumed: 0
            });
            stream.awaiting_header_data(45);
            assert_eq!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD,
                max_stream_data: 20, data_consumed: 0
            });

            stream.awaiting_header_data(90);
            assert_eq!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD,
                max_stream_data: 20, data_consumed: 0
            });

            stream.data_consumed(70);
            stream.awaiting_header_data(100);
            assert_eq!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD + 70,
                max_stream_data: 20, data_consumed: 70
            });
        }

        #[test]
        #[should_panic]
        fn test_pull_data_non_open() {
            let mut stream = throttled_stream().build();
            stream.pull_data(1000);
        }

        #[test]
        fn test_pull_data() {
            let mut stream = throttled_stream().opened();
            let events = stream.events.clone();

            let pulled = stream.pull_data(1000);
            assert_eq!(pulled, 1000);
            assert_eq!(stream.recv_state, RecvState::ReceivingHeaders {
                max_stream_data_limit: MAX_FRAME_OVERHEAD, 
                max_stream_data: 1020, data_consumed: 0,
            });
            assert_eq!(events.borrow().has_events(), true);

            stream.on_data_frame(5000);
            let pulled = stream.pull_data(2000);
            assert_eq!(pulled, 2000);
            assert_eq!(stream.recv_state, RecvState::ReceivingData {
                max_stream_data_limit: 5000, max_stream_data: 3020, data_consumed: 0,
                data_length: 5000,
            });
            assert_eq!(events.borrow_mut().next_event(), Some(
                    FlowShapingEvent::SendMaxStreamData {
                        stream_id: 0, new_limit: 1020, increase: 1000
                    }));
        }

        #[test]
        fn test_data_queued() {
            let mut stream = throttled_stream().build();
            assert_eq!(stream.send_state.pending_bytes(), 0);
            assert_eq!(stream.send_state.allowed_to_send(), 0);

            stream.data_queued(1000);
            assert_eq!(stream.send_state.pending_bytes(), 1000);
            assert_eq!(stream.send_state.allowed_to_send(), 0);

            stream.data_queued(1500);
            assert_eq!(stream.send_state.pending_bytes(), 2500);
            assert_eq!(stream.send_state.allowed_to_send(), 0);
        }

        #[test]
        #[should_panic(expected = "More data sent than was allowed.")]
        fn test_data_sent_no_budget() {
            let mut stream = throttled_stream()
                .with_send_state(SendState::Throttled { pending: 500, allowed: 100, });

            stream.data_sent(500);
        }

        #[test]
        #[should_panic(expected = "More data sent than was known pending.")]
        fn test_data_sent_desync() {
            let mut stream = throttled_stream()
                .with_send_state(SendState::Throttled { pending: 100, allowed: 500, });

            stream.data_sent(500);
        }

        #[test]
        fn test_data_sent() {
            let mut stream = throttled_stream()
                .with_send_state(SendState::Throttled { pending: 900, allowed: 500, });

            stream.data_sent(300);
            assert_eq!(stream.send_state.allowed_to_send(), 200);
            assert_eq!(stream.send_state.pending_bytes(), 600);
        }

        #[test]
        fn test_push_data() {
            let mut stream = throttled_stream().build();

            let pushed = stream.push_data(500);
            assert_eq!(pushed, 0);
            assert_eq!(stream.send_state.allowed_to_send(), 0);
            assert_eq!(stream.send_state.pending_bytes(), 0);

            stream.data_queued(300);
            let pushed = stream.push_data(400);
            assert_eq!(pushed, 300);
            assert_eq!(stream.send_state.allowed_to_send(), 300);
            assert_eq!(stream.send_state.pending_bytes(), 300);

            stream.data_queued(200);
            let pushed = stream.push_data(500);
            assert_eq!(pushed, 200);
            assert_eq!(stream.send_state.allowed_to_send(), 500);
            assert_eq!(stream.send_state.pending_bytes(), 500);
        }

        #[test]
        fn test_close_receiving() {
            let mut stream = throttled_stream().build();

            stream.close_receiving();
            assert_eq!(stream.recv_state, RecvState::Closed { data_length: 0 });
        }

        #[test]
        fn test_close_sending() {
            let mut stream = throttled_stream().build();

            stream.close_sending();
            assert_eq!(stream.send_state, SendState::Closed);
        }

        #[test]
        fn unthrottle_sending() {
            let mut stream = throttled_stream().build();

            assert!(matches!(stream.send_state, SendState::Throttled{..}));
            stream.unthrottle_sending();
            assert!(matches!(stream.send_state, SendState::Unthrottled));
        }
    }

    mod unthrottled {
        use super::*;
        use crate::event::{ FlowShapingEvent, Provider };

        fn unthrottled_stream() -> StreamBuilder {
            let mut builder = StreamBuilder::new(0);
            builder.with_initial_msd(20).throttled(false);
            builder
        }

        #[test]
        fn test_awaiting_header_data() {
            let mut stream = unthrottled_stream().opened();

            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
            stream.awaiting_header_data(45);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
            stream.awaiting_header_data(99);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
        }

        #[test]
        fn test_data_consumed() {
            let mut stream = unthrottled_stream().opened();

            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
            stream.data_consumed(3000);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
            stream.data_consumed(1000);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { .. }));
        }

        #[test]
        fn test_on_data_frame_unthrottled() {
            let mut stream = unthrottled_stream()
                .with_initial_msd(100)
                .opened();

            assert!(matches!(stream.recv_state, RecvState::Unthrottled { data_length: 0 }));
            stream.on_data_frame(2100);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { data_length: 2100 }));
            stream.on_data_frame(3200);
            assert!(matches!(stream.recv_state, RecvState::Unthrottled { data_length: 5300 }));
        }

        #[test]
        fn test_open() {
            let stream = unthrottled_stream().opened();
            let events = stream.events.clone();

            assert!(matches!(stream.recv_state, RecvState::Unthrottled { data_length: 0 }));
            assert_eq!(events.borrow().has_events(), true);
            assert_eq!(events.borrow_mut().next_event(), Some(
                    FlowShapingEvent::SendMaxStreamData {
                        stream_id: 0,
                        new_limit: DEFAULT_RX_DATA_WINDOW,
                        increase: DEFAULT_RX_DATA_WINDOW - 20
                    }));
        }

        #[test]
        fn test_data_sent() {
            let mut stream = unthrottled_stream().build();

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.data_sent(500);
            assert_eq!(stream.send_state, SendState::Unthrottled);
        }

        #[test]
        fn test_data_queued() {
            let mut stream = unthrottled_stream().build();

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.data_queued(1000);
            assert_eq!(stream.send_state, SendState::Unthrottled);
        }

        #[test]
        #[should_panic(expected = "Cannot push data in this state.")]
        fn test_push_data() {
            let mut stream = unthrottled_stream().build();

            assert_eq!(stream.send_state, SendState::Unthrottled);
            stream.push_data(3000);
        }
    }

    mod chaff_map {
        use super::*;

        fn throttled_stream(stream_id: u64) -> StreamBuilder {
            let mut builder = StreamBuilder::new(stream_id);
            builder.with_initial_msd(20).throttled(true);
            builder
        }

        #[test]
        fn push_data() {
            let mut map = ChaffStreamMap::default();
            let events: Rc<RefCell<FlowShapingEvents>> = Default::default();
            let initial_state = [(0, 100, 100), (4, 500, 300), (8, 600, 100)];
            // We make this sum to the exact amount that is pushed because
            // hashset iteration order is non-deterministic and we may end up with
            // multiple different but valid solutions.
            let expected_state = [(0, 100, 100), (4, 500, 500), (8, 600, 600)];

            for (stream_id, pending, allowed) in &initial_state {
                map.insert(throttled_stream(*stream_id)
                           .with_events(&events)
                           .with_send_state(SendState::with_limits(*pending, *allowed)));
            }

            let pushed = map.push_data(700);
            assert_eq!(pushed, 700);

            for (stream_id, pending, allowed) in &expected_state {
                let stream = map.get_mut(stream_id).unwrap();
                assert_eq!(stream.send_state.allowed_to_send(), *allowed,
                           "stream: {:?}", stream_id);
                assert_eq!(stream.send_state.pending_bytes(), *pending);
            }
        }

        #[test]
        fn push_data_partial() {
            let mut map = ChaffStreamMap::default();
            let events: Rc<RefCell<FlowShapingEvents>> = Default::default();
            let initial_state = [(0, 300, 100), (4, 200, 200), (8, 600, 000)];
            let expected_state = [(0, 300, 300), (4, 200, 200), (8, 600, 600)];

            for (stream_id, pending, allowed) in &initial_state {
                map.insert(throttled_stream(*stream_id)
                           .with_events(&events)
                           .with_send_state(SendState::with_limits(*pending, *allowed)));
            }

            let pushed = map.push_data(1000);
            assert_eq!(pushed, 800);

            for (stream_id, pending, allowed) in &expected_state {
                let stream = map.get_mut(stream_id).unwrap();
                assert_eq!(stream.send_state.allowed_to_send(), *allowed);
                assert_eq!(stream.send_state.pending_bytes(), *pending);
            }
        }

        #[test]
        fn push_data_to_open() {
            // Push data should first select streams that are not receive openned yet,
            // so that the initial GET requests are sent
            let mut map = ChaffStreamMap::default();
            let events: Rc<RefCell<FlowShapingEvents>> = Default::default();

            map.insert(throttled_stream(0).with_events(&events)
                       .with_recv_open()
                       .with_send_state(SendState::with_limits(300, 100)));
            map.insert(throttled_stream(4).with_events(&events)
                       .with_send_state(SendState::with_limits(200, 50)));
            map.insert(throttled_stream(8).with_events(&events)
                       .with_recv_open()
                       .with_send_state(SendState::with_limits(1000, 50)));
            map.insert(throttled_stream(12).with_events(&events)
                       .with_send_state(SendState::with_limits(300, 0)));

            let pushed = map.push_data(500);
            assert_eq!(pushed, 500);

            let stream = map.get(&4).unwrap();
            assert_eq!(stream.send_state.allowed_to_send(), 200);
            assert_eq!(stream.send_state.pending_bytes(), 200);

            let stream = map.get(&12).unwrap();
            assert_eq!(stream.send_state.allowed_to_send(), 300);
            assert_eq!(stream.send_state.pending_bytes(), 300);

            let stream = map.get(&0).unwrap();
            assert_eq!(stream.send_state.allowed_to_send(), 150);
            assert_eq!(stream.send_state.pending_bytes(), 300);

            let stream = map.get(&8).unwrap();
            assert_eq!(stream.send_state.allowed_to_send(), 50);
            assert_eq!(stream.send_state.pending_bytes(), 1000);
        }
    }
}
