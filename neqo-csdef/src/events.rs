use std::collections::VecDeque;
use std::cell::RefCell;
use std::fmt::Display;
use url::Url;

use neqo_common::qdebug;
use crate::stream_id::StreamId;


#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FlowShapingEvent {
    SendMaxData(u64),
    SendMaxStreamData {
        stream_id: u64,
        new_limit: u64,
        increase: u64,
    },
    SendPaddingFrames(u32),
    CloseConnection,
    ReopenStream(Url),
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

    /// Pop the first max_stream_data event with the specified stream
    /// id. Return true iff the event was found and removed.
    pub fn cancel_max_stream_data(&self, stream_id: StreamId) -> bool {
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

    /// Returns the queued MSD and sets it back to zero
    pub fn drain_queued_msd(&mut self) -> u64 {
        let result = self.queued_msd;
        self.queued_msd = 0;
        result
    }

    #[must_use]
    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().pop_front()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }
}

#[derive(Debug, Default)]
pub(crate) struct FlowShapingApplicationEvents {
    // Events that concern the application layer (H3)
    events: RefCell<VecDeque<FlowShapingEvent>>
}

impl FlowShapingApplicationEvents {

    pub fn send_connection_close(&self) {
        self.insert(FlowShapingEvent::CloseConnection)
    }

    pub fn reopen_stream(&self, url: Url) {
        self.insert(FlowShapingEvent::ReopenStream(url))
    }

    fn insert(&self, event: FlowShapingEvent) {
        self.events.borrow_mut().push_back(event);
    }

    #[must_use]
    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().pop_front()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }
}
