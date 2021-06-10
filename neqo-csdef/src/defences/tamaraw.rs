use std::time::Duration;
use std::convert::TryFrom;

use crate::trace::Packet;
use crate::defences::traits::Defencev2 as Defence;


/// The Tamaraw defence of Cai et al. which sends at constant but differing 
/// incoming and outgoing rates.
///
///  X. Cai, R. Nithyanand, T. Wang, R. Johnson, and I. Goldberg, 
///  "A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses,"
///  in CCS 2014, doi: 10.1145/2660267.2660362. 
#[derive(Debug)]
pub struct Tamaraw {
    rate_in: u128,
    rate_out: u128,
    packet_length: u32,
    modulo: u32,

    next_outgoing: u128,
    next_incoming: u128,
    final_outgoing: Option<u128>,
    final_incoming: Option<u128>,

    is_app_done: bool,
}

impl Tamaraw {
    /// Create a new instance of Tamaraw.
    ///
    /// The instance has `rate_in` and `rate_out` between each pair of incoming
    /// and outgoing packets and packets of specified length. 
    ///
    /// The number of outgoing and incoming packets will be padded to a multiple of modulo.
    pub fn new(rate_in: Duration, rate_out: Duration, packet_length: u32, modulo: u32) -> Self {
        Tamaraw { 
            rate_in: rate_in.as_millis(),
            rate_out: rate_out.as_millis(),
            packet_length, modulo,

            next_outgoing: 0,
            next_incoming: 0,
            final_outgoing: None,
            final_incoming: None,

            is_app_done: false,
        }
    }

    fn next_event_inner(&mut self, since_start: u128, is_outgoing: bool) -> Option<Packet> {
        let (next, rate, final_time) = if is_outgoing {
            (&mut self.next_outgoing, self.rate_out, self.final_outgoing)
        } else { 
            (&mut self.next_incoming, self.rate_in, self.final_incoming)
        };

        if *next <= since_start && (final_time.is_none() || *next <= final_time.unwrap()) {
            let packet = if is_outgoing {
                Packet::Outgoing(u32::try_from(*next).unwrap(), self.packet_length)
            } else {
                Packet::Incoming(u32::try_from(*next).unwrap(), self.packet_length)
            };
            *next += rate;
            Some(packet)
        } else {
            None
        }
    }
}

impl Defence for Tamaraw {
    fn next_event(&mut self, since_start: Duration) -> Option<Packet> {
        let since_start = since_start.as_millis();
        let is_outgoing = self.next_outgoing <= self.next_incoming;
        self.next_event_inner(since_start, is_outgoing)
            .or_else(|| self.next_event_inner(since_start, !is_outgoing)) 
    }

    fn next_event_at(&self) -> Option<Duration> {
        let next = std::cmp::min(self.next_outgoing, self.next_incoming);
        Some(Duration::from_millis(u64::try_from(next).unwrap()))
    }

    fn on_application_complete(&mut self) { 
        assert!(!self.is_app_done, "Application already completed.");
        self.is_app_done = true;

        let modulo = u128::from(self.modulo);

        let sent = self.next_outgoing / self.rate_out;
        let to_be_sent = modulo - (sent % modulo);
        self.final_outgoing = Some(self.next_outgoing + (to_be_sent - 1) * self.rate_out);

        let sent = self.next_incoming / self.rate_in;
        let to_be_sent = modulo - (sent % modulo);
        self.final_incoming = Some(self.next_incoming + (to_be_sent - 1) * self.rate_in);
    }

    fn is_outgoing_complete(&self) -> bool {
        self.final_outgoing.is_some()
            && self.final_outgoing.unwrap() < self.next_outgoing
    }

    fn is_complete(&self) -> bool {
        self.final_incoming.is_some() && self.final_outgoing.is_some()
            && self.final_incoming.unwrap() < self.next_incoming
            && self.final_outgoing.unwrap() < self.next_outgoing
    }

    fn is_padding_only(&self) -> bool { false }
}


#[cfg(test)]
mod tests {
    use super::*;
    macro_rules! ms { ($dur:expr) => { Duration::from_millis($dur) }; }

    #[test]
    fn next_event() {
        let mut tamaraw = Tamaraw::new(
            Duration::from_millis(5), Duration::from_millis(20), 1500, 100
        );
        assert_eq!(tamaraw.next_event(ms!(1)), Some(Packet::from((0, 1500))));
        assert_eq!(tamaraw.next_event(ms!(1)), Some(Packet::from((0, -1500))));
        assert_eq!(tamaraw.next_event(ms!(6)), Some(Packet::from((5, -1500))));
        assert_eq!(tamaraw.next_event(ms!(7)), None);
        assert_eq!(tamaraw.next_event(ms!(21)), Some(Packet::from((10, -1500))));
        assert_eq!(tamaraw.next_event(ms!(21)), Some(Packet::from((15, -1500))));
        assert_eq!(tamaraw.next_event(ms!(21)), Some(Packet::from((20, 1500))));
        assert_eq!(tamaraw.next_event(ms!(21)), Some(Packet::from((20, -1500))));
    }

    #[test]
    fn completes() {
        let mut tamaraw = Tamaraw::new(
            Duration::from_millis(5), Duration::from_millis(20), 1500, 4
        );
        assert_eq!(tamaraw.is_complete(), false);

        let mut n_outgoing = 0;
        let mut n_incoming = 0;

        for _ in 0..7 {
            match tamaraw.next_event(ms!(21)) {
                Some(pkt) if pkt.is_outgoing() => n_outgoing += 1,
                Some(_) => n_incoming += 1,
                None => panic!("Should not be out of packets.")
            };
        }
        assert_eq!(tamaraw.is_complete(), false);

        tamaraw.on_application_complete();
        assert_eq!(tamaraw.is_complete(), false);

        let mut last_incoming = None;
        let mut last_outgoing = None;
        let mut next_pkt = tamaraw.next_event(ms!(300));
        while next_pkt.is_some() {
            let pkt = next_pkt.unwrap();
            if pkt.is_outgoing() {
                last_outgoing = Some(pkt);
                n_outgoing += 1;
            } else {
                last_incoming = Some(pkt);
                n_incoming += 1;
            }
            next_pkt = tamaraw.next_event(ms!(300));
        }
        assert_eq!(last_outgoing, Some(Packet::from((60, 1500))));
        assert!(n_outgoing > 0 && n_outgoing %  4 == 0);
        assert_eq!(last_incoming, Some(Packet::from((35, -1500))));
        assert!(n_incoming > 0 && n_incoming %  4 == 0);
        println!("{} {}", n_outgoing, n_incoming);

        assert_eq!(tamaraw.is_complete(), true);
    }

    #[test]
    fn next_event_at() {
        let mut tamaraw = Tamaraw::new(ms!(3), ms!(4), 1500, 4);
        assert_eq!(tamaraw.next_event_at(), Some(ms!(0)));
        tamaraw.next_event(ms!(2));
        assert_eq!(tamaraw.next_event_at(), Some(ms!(0)));
        tamaraw.next_event(ms!(3));
        assert_eq!(tamaraw.next_event_at(), Some(ms!(3)));
        tamaraw.next_event(ms!(3));
        assert_eq!(tamaraw.next_event_at(), Some(ms!(4)));
        tamaraw.next_event(ms!(5));
        assert_eq!(tamaraw.next_event_at(), Some(ms!(6)));
        tamaraw.next_event(ms!(7));
        assert_eq!(tamaraw.next_event_at(), Some(ms!(8)));
    }
}
