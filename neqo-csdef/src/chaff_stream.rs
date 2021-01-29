use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use url::Url;
use neqo_common::qtrace;
use crate::stream_id::StreamId;
use crate::events::FlowShapingEvents;


#[derive(Debug)]
pub(crate) enum ChaffStreamState {
    Created,
    Open {
        max_stream_data: u64
    },
    Closed
}


#[derive(Debug)]
pub(crate) struct ChaffStream {
    stream_id: StreamId,
    url: Url,
    state: ChaffStreamState,
    events: Rc<RefCell<FlowShapingEvents>>,
    initial_msd: u64,
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
            state: ChaffStreamState::Created,
            events,
            initial_msd,
        }
    }

    pub fn open(&mut self) {
        match self.state {
            ChaffStreamState::Created => {
                // TODO: This should not be zero or hard-coded but instead
                // w.e. is the size that they actually are openned at according
                // to the config
                self.state = ChaffStreamState::Open{ max_stream_data: 20 };
            },
            _ => panic!("Cannot open stream from current state!")
        };
    }

    pub fn close(&mut self) {
        qtrace!([self], "state {:?} -> Closed", self.state);
        self.state = ChaffStreamState::Closed{};
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, ChaffStreamState::Open{..})
    }

    pub fn pull_data(&mut self, size: u64) {
        match self.state {
            ChaffStreamState::Open{ ref mut max_stream_data } => {
                *max_stream_data += size;
                self.events.borrow_mut()
                    .send_max_stream_data(&self.stream_id, *max_stream_data, size);
            },
            _ => panic!("Cannot pull data for stream in current state!")
        };
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


