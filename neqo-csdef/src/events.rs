use std::collections::VecDeque;
use std::cell::RefCell;
use std::fmt::Display;
use url::Url;

use neqo_common::{ qdebug, qwarn };
use crate::stream_id::StreamId;


#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FlowShapingEvent {
    SendMaxData(u64),
    SendMaxStreamData { stream_id: u64, new_limit: u64 },
    SendPaddingFrames(u32),
    CloseConnection,
    ReopenStream(Url),
}

#[derive(Debug, Default)]
pub(crate) struct FlowShapingEvents {
    // This is in a RefCell to allow borrowing a mutable reference in an
    // immutable context
    events: RefCell<VecDeque<FlowShapingEvent>>,
    queue: RefCell<VecDeque<FlowShapingEvent>>
}

impl Display for FlowShapingEvents {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "QCD FlowShapinEvents")
    }
}

impl FlowShapingEvents {
    // pub(self) fn send_max_data(&self, new_limit: u64) {
    //     self.insert(FlowShapingEvent::SendMaxData(new_limit));
    // }

    pub fn send_max_stream_data(&self, stream_id: &StreamId, new_limit: u64) {
        self.insert(FlowShapingEvent::SendMaxStreamData {
            stream_id: stream_id.as_u64(), new_limit
        });
    }

    pub fn send_pad_frames(&self, pad_size: u32) {
        self.insert(FlowShapingEvent::SendPaddingFrames(pad_size));
    }

    fn insert(&self, event: FlowShapingEvent) {
        self.events.borrow_mut().push_back(event);
    }

    pub fn remove_by_id(&self, id: &u64) {
        qdebug!([self], "Removing events for stream {}", *id);
        // queue events not yet consumed
        let mut queue = VecDeque::<u64>::new();
        for e in self.events.borrow_mut().iter() {
            match e {
                FlowShapingEvent::SendMaxStreamData{ stream_id, new_limit } => {
                    if *stream_id == *id {
                        queue.push_back(*new_limit);
                    }
                },
                _ => {}
            }
        }
        // add max MSd to queue
        let new_limit = queue.iter().max();
        match new_limit {
            Some(lim) => self.queue.borrow_mut()
                             .push_back(FlowShapingEvent::SendMaxStreamData{stream_id: *id, new_limit: *lim}),
            None => {}
        }
        // remove events for id
        self.events.borrow_mut().retain(|e| match e {
            FlowShapingEvent::SendMaxStreamData{ stream_id, new_limit: _ } => {
                *stream_id != *id
            },
            _ => true
        });
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

    // FIXME(jsmith): This does not keep track of the max stream data
    pub fn drain_queue_with_id (&self, id: u64) {
        while let Some(e) =  self.queue.borrow_mut().pop_front() {
            match e {
                FlowShapingEvent::SendMaxStreamData{ stream_id: _, new_limit} => {
                    self.send_max_stream_data(&StreamId::from(id), new_limit);
                },
                _ => {
                    qwarn!([self], "Dequeueing events not implemented yet");
                }
            }
        }
    }

    #[must_use]
    pub fn next_event(&self) -> Option<FlowShapingEvent> {
        self.events.borrow_mut().pop_front()
    }

    #[must_use]
    pub fn has_events(&self) -> bool {
        !self.events.borrow().is_empty()
    }

    #[must_use]
    pub fn has_queue_events(&self) -> bool {
        !self.queue.borrow().is_empty()
    }

    #[must_use]
    pub fn next_queued(&self) -> Option<FlowShapingEvent> {
        self.queue.borrow_mut().pop_front()
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
