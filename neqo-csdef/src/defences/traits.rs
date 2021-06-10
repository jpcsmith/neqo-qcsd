use std::time::Duration;
use crate::trace::{ Trace, Packet };

/// Trait for defence implementations to be used with FlowShaper
pub trait Defence {
    /// Return a trace to be shaped or padded towards.
    fn trace(&self) -> Trace;
    /// True if the defence is a padding only defence, false otherweise.
    fn is_padding_only(&self) -> bool;
}


pub trait Defencev2 {
    /// Return the next event at or before or at the specified time point.
    /// May be called repeatedly with the same time point.
    ///
    /// The times of the packets returned must be monotonically increasing 
    /// (not strictly increasing).
    fn next_event(&mut self, since_start: Duration) -> Option<Packet>;

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
}


// #[derive(Debug)]
// pub struct StaticSchedule {
//     trace: Trace,
//     is_padding: bool,
// }
// 
// impl StaticSchedule {
//     pub fn new(trace: &Trace, is_padding: bool) -> Self {
//         StaticSchedule {
//             trace: trace.clone(),
//             is_padding
//         }
//     }
// }
// 
// impl Defencev2 for StaticSchedule {
//     fn next_event(&mut self, since_start: u128) -> Option<Packet> {
//         if self.trace.front()
//             .map_or(false, |pkt| u128::from(pkt.timestamp()) <= since_start) 
//         {
//             self.trace.pop_front()
//         } else {
//             None
//         }
//     }
// 
//     fn is_complete(&self) -> bool { self.trace.is_empty() }
//     fn is_padding_only(&self) -> bool { self.is_padding }
//     fn on_application_complete(&mut self) {}
// }


