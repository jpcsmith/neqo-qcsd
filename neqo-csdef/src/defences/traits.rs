use std::time::{ Duration, Instant };
use crate::trace::Packet;


#[derive(Debug)]
pub struct CapacityInfo {
    pub app_incoming: u64,
    pub chaff_incoming: u64,
    pub incoming_used: u64, 
}

impl CapacityInfo {
    pub fn available_incoming(&self, is_padding_only: bool) -> u64 {
        let avail = if is_padding_only {
            self.chaff_incoming
        } else {
            self.app_incoming + self.chaff_incoming
        };
        avail.saturating_sub(self.incoming_used)
    }
}

pub trait Defencev2: std::fmt::Debug {
    /// Return the next event at or before or at the specified time point.
    /// May be called repeatedly with the same time point.
    ///
    /// The times of the packets returned must be monotonically increasing 
    /// (not strictly increasing).
    fn next_event(&mut self, since_start: Duration) -> Option<Packet>;

    fn next_event_with_details(
        &mut self, since_start: Duration, _capacity: CapacityInfo
    ) -> Option<Packet> {
        self.next_event(since_start)
    }

    /// Return the interval in milliseconds when then next event will occur,
    /// relative from the start of shaping. 
    fn next_event_at(&self) -> Option<Duration>;

    /// True if the defence is done and there will be no more events, false otherwise.
    fn is_complete(&self) -> bool;

    /// True if the outgoing direction of the defence is done and there will be 
    /// no more events in that direction, false otherwise.
    fn is_outgoing_complete(&self) -> bool;

    /// True if the defence is a padding only defence, false otherweise.
    fn is_padding_only(&self) -> bool;

    /// To be called when the application is done sending and receiving data.
    fn on_application_complete(&mut self);

    /// Return the reference point to use as the start time of th defence
    fn start(&mut self) -> Instant {
        Instant::now()
    }
}
