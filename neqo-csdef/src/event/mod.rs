mod provider;

use std::collections::VecDeque;
use std::cell::RefCell;
use std::fmt::Display;

use neqo_common::qdebug;
use crate::stream_id::StreamId;
use crate::Resource;

pub use self::provider::Provider;


pub trait HEventConsumer {
    fn awaiting_header_data(&mut self, stream_id: u64, min_remaining: u64);
    fn on_data_frame(&mut self, stream_id: u64, length: u64);
    fn on_http_request_sent(&mut self, stream_id: u64, resource: &Resource, is_chaff: bool);
}

pub trait StreamEventConsumer {
    fn on_first_byte_sent(&mut self, stream_id: u64);
    fn on_fin_received(&mut self, stream_id: u64);
    fn data_consumed(&mut self, stream_id: u64, amount: u64);
    fn data_sent(&mut self, stream_id: u64, amount: u64);
    fn data_queued(&mut self, stream_id: u64, amount: u64);
}


#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum FlowShapingEvent {
    SendMaxData(u64),
    SendMaxStreamData {
        stream_id: u64,
        new_limit: u64,
        increase: u64,
    },
    SendPaddingFrames(u32),
    CloseConnection,
    DoneShaping,
    RequestResource(Resource),
}

#[derive(Debug, Default)]
pub(crate) struct FlowShapingEvents {
    /// This is in a RefCell to allow borrowing a mutable reference in an
    /// immutable context
    events: RefCell<VecDeque<FlowShapingEvent>>,
    /// Queued MSD budget that needs to be sent.
    queued_msd: u64,
}

impl Display for FlowShapingEvents {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QCD FlowShapinEvents")
    }
}

impl FlowShapingEvents {
    pub fn send_max_stream_data(&self, stream_id: &StreamId, new_limit: u64, increase: u64) {
        self.insert(FlowShapingEvent::SendMaxStreamData {
            stream_id: stream_id.as_u64(), new_limit, increase
        });
    }

    pub fn send_pad_frames(&self, pad_size: u32) {
        self.insert(FlowShapingEvent::SendPaddingFrames(pad_size));
    }

    fn insert(&self, event: FlowShapingEvent) {
        self.events.borrow_mut().push_back(event);
    }

    pub fn remove_by_id(&mut self, id: &u64) {
        qdebug!([self], "Removing events for stream {}", *id);

        type FSE = FlowShapingEvent;

        let mut events = self.events.borrow_mut();

        let maybe_increase = events.iter()
            .filter_map(|e| match e {
                FSE::SendMaxStreamData{ stream_id, increase, ..  }
                    if stream_id == id =>  Some(increase),
                _ => None
            }).max();

        if let Some(size) = maybe_increase  {
            self.queued_msd += size
        }

        // remove events for id
        events.retain(|e| !matches!(e, FSE::SendMaxStreamData{ stream_id, .. }
                                    if stream_id == id));
    }

    pub fn get_queued_msd(&self) -> u64 {
        self.queued_msd
    }

    pub fn consume_queued_msd(&mut self, amount: u64) {
        assert!(self.queued_msd >= amount);
        self.queued_msd -= amount;
    }
}


impl Provider for FlowShapingEvents {
    type Event = FlowShapingEvent;

    fn next_event(&mut self) -> Option<Self::Event> {
        self.events.borrow_mut().pop_front()
    }

    fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }
}


#[derive(Debug, Default)]
pub(crate) struct FlowShapingApplicationEvents {
    // Events that concern the application layer (H3)
    events: RefCell<VecDeque<FlowShapingEvent>>
}

impl FlowShapingApplicationEvents {
    pub fn request_chaff_resource(&self, resource: &Resource) {
        self.insert(FlowShapingEvent::RequestResource(resource.clone()));
    }

    pub fn done_shaping(&self) {
        self.insert(FlowShapingEvent::DoneShaping)
    }

    pub fn close_connection(&self) {
        self.insert(FlowShapingEvent::CloseConnection)
    }

    fn insert(&self, event: FlowShapingEvent) {
        self.events.borrow_mut().push_back(event);
    }
}

impl Provider for FlowShapingApplicationEvents {
    type Event = FlowShapingEvent;

    fn next_event(&mut self) -> Option<Self::Event> {
        self.events.borrow_mut().pop_front()
    }

    fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }
}