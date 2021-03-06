use std::collections::VecDeque;
use std::time::Duration;
use std::convert::{ TryInto, TryFrom };
use std::cmp::Ordering;

use csv::{self, Writer};
use crate::Result;


#[derive(Eq, Debug, Clone)]
pub enum Packet {
    Incoming(u32, u32),
    Outgoing(u32, u32),
}


impl Packet {
    pub fn is_outgoing(&self) -> bool { matches!(self, Packet::Outgoing(..)) }
    pub fn is_incoming(&self) -> bool { !self.is_outgoing() }

    pub fn length(&self) -> u32 {
        match self {
            Self::Incoming(_, len) | Self::Outgoing(_, len) => *len
        }
    }

    pub fn signed_length(&self) -> i32 {
        match self {
            Self::Outgoing(_, len) => i32::try_from(*len).unwrap(),
            Self::Incoming(_, len) => i32::try_from(*len).unwrap() * -1,
        }
    }

    pub fn timestamp(&self) -> u32 {
        match self {
            Self::Incoming(time, _) | Self::Outgoing(time, _) => *time
        }
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.timestamp().into())
    }

    pub fn as_tuple(&self) -> (u32, i32) {
        (self.timestamp(), self.signed_length())
    }
}


impl<T> std::convert::From<(T, i32)> for Packet where 
    T: TryInto<u32> ,
    <T as TryInto<u32>>::Error: std::fmt::Debug
{
    fn from(tuple: (T, i32)) -> Self {
        assert!(tuple.1 != 0);

        match tuple {
            (time, length) if length.is_positive() => {
                Packet::Outgoing(time.try_into().unwrap(), u32::try_from(length).unwrap())
            },
            (time, length) if length.is_negative() => {
                Packet::Incoming(time.try_into().unwrap(), u32::try_from(length.abs()).unwrap())
            },
            _ => panic!("Packets with zero bytes not allowed!"),
        }
    }
}


impl std::convert::Into<(u32, i32)> for Packet {
    fn into(self) -> (u32, i32) {
        (self.timestamp(), self.signed_length())
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = (self.timestamp(), self.is_incoming(), self.length());
        let rhs = (other.timestamp(), other.is_incoming(), other.length());
        lhs.cmp(&rhs)
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.as_tuple() == other.as_tuple()
    }
}


#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Trace(VecDeque<Packet>);


impl Trace {
    pub fn new<'a, I, V>(input: I) -> Self
        where I: IntoIterator<Item=&'a V>,
              V: Into<Packet> + Clone + 'a
    {
        let mut packets: Vec<Packet> = input.into_iter()
            .map(|x| x.clone().into())
            .collect();
        packets.sort();

        Trace(VecDeque::from(packets))
    }

    pub fn empty() -> Self {
        Trace(VecDeque::new())
    }

    pub fn sampled(self, interval_ms: u32) -> Self {
        let mut packets: Vec<(u32, i32)> = self.0.into_iter()
            .map(|x| x.as_tuple())
            .map(|(time, len)| (time - (time % interval_ms), len))
            .collect();

        // Sort. All packets will packets with the same bin & direction are
        // grouped together.
        packets.sort();

        let mut group = Vec::new();
        let mut groups = Vec::new();
        for (bin, len) in packets {
            match group.last() {
                None => group.push((bin, len)),
                Some((prev_bin, prev_len)) => {
                    match (*prev_bin == bin, prev_len.signum() == len.signum()) {
                        (true, true) => {
                            group.push((bin, len));
                        },
                        (false, _) | (_, false) => {
                            groups.push(group);

                            group = Vec::new();
                            group.push((bin, len));
                        }
                    }
                }
            }
        }
        groups.push(group);

        let packets: Vec<(u32, i32)> = groups.iter().map(
            |group| group.iter().fold(
                (0, 0), |(_, total), (bin, len)| (*bin, total + *len)
            )
        ).collect();

        Trace::new(&packets)

    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn remove(&mut self, index: usize) -> Option<Packet> {
        self.0.remove(index)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn new_sampled<'a, I, V>(input: I, interval_ms: u32) -> Self
        where I: IntoIterator<Item=&'a V>,
              V: Into<Packet> + Clone + 'a
    {
        Trace::new(input).sampled(interval_ms)
    }

    pub fn pop_front(&mut self) -> Option<Packet> {
        self.0.pop_front()
    }

    pub fn front(&self) -> Option<&Packet> {
        self.0.front()
    }

    pub fn front_mut(&mut self) -> Option<&mut Packet> {
        self.0.front_mut()
    }

    pub fn next_incoming(&self) -> Option<(usize, &Packet)> {
        self.iter().enumerate().find(|(_, pkt)| pkt.is_incoming())
    }

    pub fn next_incoming_mut(&mut self) -> Option<(usize, &mut Packet)> {
        self.0.iter_mut().enumerate().find(|(_, pkt)| pkt.is_incoming())
    }

    pub fn next_outgoing(&self) -> Option<(usize, &Packet)> {
        self.iter().enumerate().find(|(_, pkt)| pkt.is_outgoing())
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<Packet> {
        self.0.iter()
    }

    pub fn retain<F>(&mut self, f: F)
        where F: FnMut(&Packet) -> bool
    {
        self.0.retain(f)
    }

    pub fn from_file(filename: &str) -> Result<Trace> {
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

        packets.sort();

        Ok(Trace::new(&packets))
    }

    pub fn to_file(&self, csv_path: &str) -> Result<()> {
        let mut wtr = Writer::from_path(csv_path)?;

        for pkt in self.iter() {
            wtr.write_record(
                &[pkt.duration().as_secs_f64().to_string(), pkt.signed_length().to_string()]
            )?;
        }
        wtr.flush()?;

        Ok(())
    }
}

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n_incoming = self.iter()
            .filter(|pkt| pkt.is_incoming())
            .count();
        let n_outgoing = self.len() - n_incoming;

        match self.front() {
            None => write!(f, "Trace(next: None)"),
            Some(pkt) => write!(f, "Trace(next: {:?}, in: {}, out: {})",
                                pkt, n_incoming, n_outgoing)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    mod packet {
        use super::*;
        #[test]
        fn test_from_pair() {
            assert_eq!(Packet::from((31, -1500)), Packet::Incoming(31, 1500));
            assert_eq!(Packet::from((18, 1200)), Packet::Outgoing(18, 1200));
        }

        #[test]
        fn test_length() {
            assert_eq!(Packet::Incoming(0, 1500).length(), 1500);
            assert_eq!(Packet::Outgoing(0, 1200).length(), 1200);
        }

        #[test]
        fn test_signed_length() {
            assert_eq!(Packet::Outgoing(0, 900).signed_length(), 900);
            assert_eq!(Packet::Incoming(0, 1800).signed_length(), -1800);
        }

        #[test]
        fn test_timestamp() {
            assert_eq!(Packet::Outgoing(13, 1200).timestamp(), 13);
            assert_eq!(Packet::Incoming(21, 400).timestamp(), 21);
        }

        #[test]
        fn test_eq() {
            assert_eq!(Packet::Outgoing(13, 1200), Packet::Outgoing(13, 1200));
            assert_eq!(Packet::Incoming(33, 500), Packet::Incoming(33, 500));

            assert_ne!(Packet::Incoming(33, 700), Packet::Incoming(20, 700));
            assert_ne!(Packet::Incoming(7, 800), Packet::Incoming(7, 2000));
            assert_ne!(Packet::Outgoing(18, 700), Packet::Outgoing(18, 84));
            assert_ne!(Packet::Outgoing(41, 3100), Packet::Outgoing(7, 3100));

            assert_ne!(Packet::Incoming(10, 100), Packet::Outgoing(10, 100));
        }

        #[test]
        fn test_cmp() {
            type Pkt = Packet;
            let comparisons = [
                // Packets are compared by times regardless of type
                (Pkt::Outgoing(13, 1200), Pkt::Outgoing(10, 1800), Ordering::Greater),
                (Pkt::Incoming(13, 2000), Pkt::Incoming(21, 900), Ordering::Less),
                (Pkt::Incoming(15, 900), Pkt::Outgoing(83, 100), Ordering::Less),

                // Same type and time are compared according to length
                (Packet::Outgoing(13, 1200), Packet::Outgoing(13, 1200), Ordering::Equal),
                (Pkt::Incoming(10, 700), Pkt::Incoming(10, 2000), Ordering::Less),
                (Pkt::Outgoing(30, 2100), Pkt::Outgoing(30, 2000), Ordering::Greater),

                // Same time, but different types are compared according to type
                // Outgoing is smaller than incoming, since for time 0 we would want
                // outgoing packets first
                (Packet::Outgoing(13, 1200), Packet::Incoming(13, 1200), Ordering::Less),
                (Pkt::Incoming(10, 700), Pkt::Outgoing(10, 2000), Ordering::Greater),
                (Pkt::Outgoing(30, 2100), Pkt::Incoming(30, 2000), Ordering::Less),
            ];

            for case in &comparisons {
                assert_eq!(case.0.cmp(&case.1), case.2, "{:?}", case);
            }
        }
    }

    mod trace {
        use super::*;

        #[test]
        fn test_front() {
            let trace = Trace::new(&[(2, 1350), (16, -4800), (21, 600), (22, -350)]);
            assert_eq!(trace.front(), Some(&Packet::Outgoing(2, 1350)));

            let trace = Trace::new(&[(16, -4800), (21, 600), (22, -350)]);
            assert_eq!(trace.front(), Some(&Packet::Incoming(16, 4800)));
        }

        #[test]
        fn test_front_with_sampling() {
            let trace = Trace::new(&[(11, 1350), (13, -4800), (16, 600), (22, -350)])
                .sampled(5);
            assert_eq!(trace.front(), Some(&Packet::Outgoing(10, 1350)));

            let trace = Trace::new(&[(11, 1350), (13, -4800), (14, 600), (22, -350)])
                .sampled(5);
            assert_eq!(trace.front(), Some(&Packet::Outgoing(10, 1950)));

            let trace = Trace::new(&[(21, -1350), (22, -700), (25, -600), (30, -350)])
                .sampled(10);
            assert_eq!(trace.front(), Some(&Packet::Incoming(20, 2650)));
        }

        #[test]
        fn test_pop_front() {
            let mut trace = Trace::new(&[(11, 1350), (13, -4800), (14, -600), (22, 350)])
                .sampled(5);
            assert_eq!(trace.front(), Some(&Packet::Outgoing(10, 1350)));
            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(10, 1350)));

            assert_eq!(trace.front(), Some(&Packet::Incoming(10, 5400)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(10, 5400)));

            assert_eq!(trace.front(), Some(&Packet::Outgoing(20, 350)));
            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(20, 350)));

            assert_eq!(trace.front(), None);
        }

        #[test]
        fn test_new_sampled() {
            let mut trace = Trace::new_sampled(
                &[(2, 1350), (3, -4800), (4, -600), (6, 350), (8, 200), (11, -100)], 5);
            println!("{:?}", trace);

            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(0, 1350)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(0, 5400)));
            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(5, 550)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(10, 100)));
        }

        #[test]
        fn test_new_sampled2() {
            let mut trace = Trace::new_sampled(
                &[(11, 1350), (13, -4800), (16, 600), (22, -350)], 10
            );

            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(10, 1950)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(10, 4800)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(20, 350)));
        }
    }
}
