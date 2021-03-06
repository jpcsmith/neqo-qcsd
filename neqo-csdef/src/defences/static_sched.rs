use std::time::Duration;
use std::convert::TryInto;
use std::collections::VecDeque;

use crate::trace::Packet;
use crate::defences::traits::Defencev2 as Defence;
use crate::Result;


pub struct StaticSchedule {
    trace: VecDeque<Packet>,
    is_padding: bool,
}

impl StaticSchedule {
    /// Construct a new static schedule according with the provided packets.
    /// Packets will be sorted according to packet ordering.
    pub fn new(trace: &Vec<Packet>, is_padding: bool) -> Self {
        let mut trace: Vec<Packet> = trace.iter().cloned().collect();
        trace.sort();

        StaticSchedule { trace: trace.into(), is_padding, }
    }

    /// Return a new empty chaff-only static schedule that adds no padding
    /// to the connection.
    pub fn empty() -> Self {
        StaticSchedule { trace: VecDeque::new(), is_padding: true }
    }

    /// Read the schedule from the specified CSV file.
    ///
    /// The CSV should have no headers, and each row should be of the form
    /// time,size where time is a floating point value in seconds and size
    /// is a signed integer packet size (positive is outgoing).
    pub fn from_file(filename: &str, is_padding: bool) -> Result<Self> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(filename)?;

        let mut packets: Vec<Packet> = Vec::new();
        for result in reader.deserialize() {
            let record: (f64, i32) = result?;
            let timestamp: u32 = Duration::from_secs_f64(record.0)
                .as_millis().try_into()
                .expect("timestamps to fit within 32 bits");
            packets.push(Packet::from((timestamp, record.1)));
        }

        Ok(Self::new(&packets, is_padding))
    }
}


impl Defence for StaticSchedule {
    fn next_event(&mut self, since_start: Duration) -> Option<Packet> { 
        match self.trace.front().map(|x| x.timestamp()) {
            Some(time) if u128::from(time) <= since_start.as_millis() => {
                self.trace.pop_front()
            },
            Some(_) | None => None
        }
    }

    fn next_event_at(&self) -> Option<Duration> { 
        self.trace.front().map(|pkt| pkt.duration())
    }

    fn is_complete(&self) -> bool { self.trace.is_empty() }
    fn is_outgoing_complete(&self) -> bool { 
        self.trace.iter().find(|pkt| pkt.is_outgoing()).is_none()
    }

    fn is_padding_only(&self) -> bool { self.is_padding }
    fn on_application_complete(&mut self) {}
}

impl std::fmt::Debug for StaticSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticSchedule")
            .field("is_padding", &self.is_padding) 
            .field("next", &self.trace.front())
            .field("remaining", &self.trace.len())
            .finish()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ms { ($dur:expr) => { Duration::from_millis($dur) }; }
    macro_rules! as_trace {
        ($vec:expr) => {
            $vec.into_iter().map(Packet::from).collect::<Vec<Packet>>()
        };
    }

    #[test]
    fn next_event_sorts() {
        let mut schedule = StaticSchedule::new(
            &as_trace!(vec![(10, 1500), (0, -300), (5, 100), (0, 150)]), true
        );

        assert_eq!(schedule.next_event(ms!(1)), Some(Packet::from((0, 150))));
        assert_eq!(schedule.next_event(ms!(4)), Some(Packet::from((0, -300))));
        assert_eq!(schedule.next_event(ms!(4)), None);
        assert_eq!(schedule.next_event(ms!(10)), Some(Packet::from((5, 100))));
        assert_eq!(schedule.next_event(ms!(11)), Some(Packet::from((10, 1500))));
        assert_eq!(schedule.next_event(ms!(11)), None);
    }

    #[test]
    fn next_event_at() {
        let schedule = StaticSchedule::new(
            &as_trace!(vec![(10, 1500), (0, -300), (5, 100), (0, 150)]), true
        );
        assert_eq!(schedule.next_event_at(), Some(ms!(0)));

        let schedule = StaticSchedule::new(&as_trace!(vec![(10, 1500), (5, 100)]), false);
        assert_eq!(schedule.next_event_at(), Some(ms!(5)));

        let schedule = StaticSchedule::new(&vec![], false);
        assert_eq!(schedule.next_event_at(), None);
    }

    #[test]
    fn is_complete() {
        let schedule = StaticSchedule::new(&as_trace!(vec![(10, 1500), (5, 100)]), false);
        assert!(!schedule.is_complete());

        let schedule = StaticSchedule::new(&vec![], true);
        assert!(schedule.is_complete());
    }

    #[test]
    fn is_outgoing_complete() {
        let schedule = StaticSchedule::new(&as_trace!(vec![(10, 1500), (5, 100)]), false);
        assert!(!schedule.is_complete());
        assert!(!schedule.is_outgoing_complete());

        let schedule = StaticSchedule::new(&as_trace!(vec![(10, -1500), (5, -100)]), true);
        assert!(!schedule.is_complete());
        assert!(schedule.is_outgoing_complete());

        let schedule = StaticSchedule::new(&vec![], true);
        assert!(schedule.is_complete());
        assert!(schedule.is_outgoing_complete());
    }
}
