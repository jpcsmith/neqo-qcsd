use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use url::Url;
use neqo_common::qtrace;
use crate::stream_id::StreamId;
use crate::events::FlowShapingEvents;


#[derive(Debug)]
pub(crate) enum ChaffStreamState {
    Created{ initial_msd: u64 },
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
    Closed { data_length: u64 }
}

impl ChaffStreamState {
    fn new(initial_msd: u64) -> Self {
        Self::Created { initial_msd }
    }

    fn name(&self) -> &str {
        match self {
            Self::Created { .. } => "Created",
            Self::ReceivingHeaders { .. } => "ReceivingHeaders",
            Self::ReceivingData { .. } => "ReceivingData",
            Self::Closed { .. } => "Closed",
        }
    }

    fn data_length(&self) -> Option<u64> {
        match self {
            Self::ReceivingData { data_length, .. }
            | Self::Closed { data_length, .. } => Some(*data_length),
            Self::Created { .. } | Self::ReceivingHeaders { .. } => None
        }
    }

    #[allow(dead_code)]
    fn msd_available(&self) -> u64 {
        match self {
            Self::ReceivingHeaders { max_stream_data, max_stream_data_limit, .. }
            | Self::ReceivingData { max_stream_data, max_stream_data_limit, .. } => {
                max_stream_data_limit - max_stream_data
            },
            Self::Created { .. } | Self::Closed { .. } => 0
        }
    }
}


#[derive(Debug)]
pub(crate) struct ChaffStream {
    stream_id: StreamId,
    url: Url,
    state: ChaffStreamState,
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
            state: ChaffStreamState::new(initial_msd),
            events,
        }
    }

    pub fn msd_available(&self) -> u64 {
        self.state.msd_available()
    }

    pub fn open(&mut self) {
        match self.state {
            ChaffStreamState::Created { initial_msd } => {
                self.state = ChaffStreamState::ReceivingHeaders {
                    max_stream_data: initial_msd,
                    max_stream_data_limit: initial_msd,
                    data_consumed: 0,
                };
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

    pub fn is_open(&self) -> bool {
        matches!(
            self.state,
            ChaffStreamState::ReceivingHeaders{ .. } | ChaffStreamState::ReceivingData { .. }
        )
    }

    /// Pull data on this stream. Return the amount of data pulled.
    pub fn pull_data(&mut self, amount: u64) -> u64 {
        let pull_amount = std::cmp::min(amount, self.msd_available());

        match self.state {
            ChaffStreamState::ReceivingHeaders{ ref mut max_stream_data, .. }
            | ChaffStreamState::ReceivingData{ ref mut max_stream_data, .. } => {
                *max_stream_data += pull_amount;
                self.events.borrow_mut()
                    .send_max_stream_data(&self.stream_id, *max_stream_data, pull_amount);

                pull_amount
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
            ChaffStreamState::Closed{ .. } => (),
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
                    data_consumed + min_remaining + 16,
                    *max_stream_data_limit);
            },
            ChaffStreamState::Closed{ .. } => (),
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
                    max_stream_data: max_stream_data,
                    max_stream_data_limit: data_consumed + length,
                    data_consumed: data_consumed,
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
                *max_stream_data_limit = data_consumed + length;
                *data_length += length;
            }
            ChaffStreamState::Closed{ .. } => (),
            _ => panic!("Should not receive data frame in other states!")
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
// TODO: Use a HashSet


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

    pub fn pull_available(&self) -> u64 {
        self.iter().fold(0, |total, (_, stream)| total + stream.msd_available())
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


