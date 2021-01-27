use std::collections::HashMap;
use url::Url;
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
}

impl ChaffStream {
    pub fn new(stream_id: u64, url: Url) -> Self {
        ChaffStream {
            stream_id: StreamId::new(stream_id),
            url,
            state: ChaffStreamState::Created }
    }

    pub fn open(&mut self) {
        match self.state {
            ChaffStreamState::Created => {
                // TODO: This should not be zero but instead w.e. is the size that
                // they actually are openned at according to the config
                self.state = ChaffStreamState::Open{ max_stream_data: 0 };
            },
            _ => panic!("Cannot open stream from current state!")
        };
    }

    pub fn close(&mut self) {
        self.state = ChaffStreamState::Closed{};
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, ChaffStreamState::Open{..})
    }

    pub fn pull_data(&mut self, size: u64, events: &mut FlowShapingEvents) {
        match self.state {
            ChaffStreamState::Open{ ref mut max_stream_data } => {
                *max_stream_data += size;
                events.send_max_stream_data(&self.stream_id, *max_stream_data);
            },
            _ => panic!("Cannot pull data for stream in current state!")
        };
    }
}


#[derive(Debug, Default)]
pub(crate) struct ChaffStreamMap(HashMap<u64, ChaffStream>);


impl ChaffStreamMap {
    // add a padding stream to the shaping streams
    pub fn add_padding_stream(&mut self, stream_id: u64, dummy_url: Url) -> bool {
        self.0.insert(stream_id, ChaffStream::new(stream_id, dummy_url))
            .is_none()
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

    pub fn iter(&self) -> std::collections::hash_map::Iter<u64, ChaffStream> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<u64, ChaffStream> {
        self.0.iter_mut()
    }
}


