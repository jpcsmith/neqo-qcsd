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
            Self::Outgoing(_, len) => *len as i32,
            Self::Incoming(_, len) => *len as i32 * -1,
        }
    }

    pub fn timestamp(&self) -> u32 {
        match self { 
            Self::Incoming(time, _) | Self::Outgoing(time, _) => *time 
        }
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.timestamp() as u64)
    }

    pub fn as_tuple(&self) -> (u32, i32) {
        (self.timestamp(), self.signed_length())
    }
}

impl std::convert::From<(u32, i32)> for Packet {
    fn from(tuple: (u32, i32)) -> Self {
        assert!(tuple.1 != 0);

        match tuple {
            (time, length) if length.is_positive() => {
                Packet::Outgoing(time, u32::try_from(length).unwrap())
            },
            (time, length) if length.is_negative() => {
                Packet::Incoming(time, u32::try_from(length.abs()).unwrap())
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
        let order = self.timestamp().cmp(&other.timestamp());
        match order {
            Ordering::Equal => self.signed_length().cmp(&other.signed_length()),
            Ordering::Less | Ordering::Greater => order,
        }
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


#[derive(Default)]
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

    pub fn pop_front(&mut self) -> Option<Packet> {
        self.0.pop_front()
    }

    pub fn front(&self) -> Option<&Packet> {
        self.0.front()
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


pub(crate) struct Resampler {
    trace: Trace,
    interval: u32,
}


impl Resampler {
    pub fn front(&self) -> Option<Packet> {
        if self.interval == 0 {
            self.trace.front().cloned()
        } else {
            let bin = |p: &Packet| p.timestamp() - (p.timestamp() % self.interval);

            match self.trace.front() {
                Some(front_pkt) => {
                    let front_bin = bin(front_pkt);
                    let front_acc = self.trace.iter()
                        .filter(|pkt| pkt.is_outgoing() == front_pkt.is_outgoing())
                        .take_while(|pkt| bin(pkt) == front_bin)
                        .fold(0, |acc, pkt| acc + pkt.signed_length());

                    Some(Packet::from((front_bin, front_acc)))
                },
                None => None,
            }
        }
    }

    pub fn pop_front(&mut self) -> Option<Packet> {
        if self.interval == 0 {
            self.trace.pop_front()
        } else {
            let interval = self.interval;
            let bin = |p: &Packet| p.timestamp() - (p.timestamp() % interval);
            let front_pkt = self.trace.front().cloned();

            match front_pkt {
                Some(front_pkt) => {
                    let front_bin = bin(&front_pkt);
                    let front_acc = self.trace.iter()
                        .filter(|pkt| pkt.is_outgoing() == front_pkt.is_outgoing())
                        .take_while(|pkt| bin(pkt) == front_bin)
                        .fold(0, |acc, pkt| acc + pkt.signed_length());

                    self.trace.retain(|pkt| (
                            pkt.is_outgoing() != front_pkt.is_outgoing() 
                            || bin(pkt) != front_bin
                    ));

                    Some(Packet::from((front_bin, front_acc)))
                },
                None => None,
            }
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

            assert_eq!(
                Pkt::Outgoing(13, 1200).cmp(&Pkt::Outgoing(10, 1800)), Ordering::Greater);
            assert_eq!(Pkt::Incoming(13, 2000).cmp(&Pkt::Incoming(21, 900)), Ordering::Less);
            assert_eq!(
                Packet::Outgoing(13, 1200).cmp(&Packet::Outgoing(13, 1200)), Ordering::Equal);
            assert_eq!(
                Pkt::Outgoing(13, 700).cmp(&Pkt::Incoming(10, 2000)), Ordering::Greater);
            assert_eq!(Pkt::Incoming(71, 900).cmp(&Pkt::Outgoing(100, 400)), Ordering::Less);
            assert_eq!(Pkt::Incoming(10, 1000).cmp(&Pkt::Outgoing(10, 1000)), Ordering::Less);
            assert_eq!(
                Pkt::Outgoing(10, 1000).cmp(&Pkt::Incoming(10, 1000)), Ordering::Greater);
        }
    }

    mod resample {
        use super::*;

        #[test]
        fn test_front() {
            let trace = Resampler {
                trace: Trace::new(&[(2, 1350), (16, -4800), (21, 600), (22, -350)]),
                interval: 0,
            };
            assert_eq!(trace.front(), Some(Packet::Outgoing(2, 1350)));

            let trace = Resampler {
                trace: Trace::new(&[(16, -4800), (21, 600), (22, -350)]), 
                interval: 0,
            };
            assert_eq!(trace.front(), Some(Packet::Incoming(16, 4800)));
        }

        #[test]
        fn test_front_with_sampling() {
            let trace = Resampler {
                trace: Trace::new(&[(11, 1350), (13, -4800), (16, 600), (22, -350)]),
                interval: 5
            };
            assert_eq!(trace.front(), Some(Packet::Outgoing(10, 1350)));

            let trace = Resampler {
                trace: Trace::new(&[(11, 1350), (13, -4800), (14, 600), (22, -350)]),
                interval: 5,
            };
            assert_eq!(trace.front(), Some(Packet::Outgoing(10, 1950)));

            let trace = Resampler {
                trace: Trace::new(&[(21, -1350), (22, -700), (25, -600), (30, -350)]),
                interval: 10,
            };
            assert_eq!(trace.front(), Some(Packet::Incoming(20, 2650)));
        }

        #[test]
        fn test_pop_front() {
            let mut trace = Resampler {
                trace: Trace::new(&[(11, 1350), (13, -4800), (14, -600), (22, 350)]),
                interval: 5
            };
            assert_eq!(trace.front(), Some(Packet::Outgoing(10, 1350)));
            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(10, 1350)));

            assert_eq!(trace.front(), Some(Packet::Incoming(10, 5400)));
            assert_eq!(trace.pop_front(), Some(Packet::Incoming(10, 5400)));

            assert_eq!(trace.front(), Some(Packet::Outgoing(20, 350)));
            assert_eq!(trace.pop_front(), Some(Packet::Outgoing(20, 350)));

            assert_eq!(trace.front(), None);
        }
    }
}
