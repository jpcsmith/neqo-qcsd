// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::mem;

use crate::codec::Decoder;

/// IncrementalDecoder incrementally processes input from incomplete input.
/// Use this to process data that might be incomplete when it arrives.
///
/// ```
/// use neqo_common::{Decoder, IncrementalDecoder, IncrementalDecoderResult};
///
/// let mut dec = IncrementalDecoder::decode_vec(1);
/// let input = &[1, 0];
/// match dec.consume(&mut Decoder::from(&input[..])) {
///    IncrementalDecoderResult::Buffer(v) => println!("complete {:?}", v),
///    IncrementalDecoderResult::InProgress => println!("still waiting"),
///    _ => unreachable!(),
/// }
/// ```
#[derive(Clone, Debug)]
pub enum IncrementalDecoder {
    Idle,
    BeforeVarint,
    InUint { v: u64, remaining: usize },
    InBufferLen(Box<IncrementalDecoder>),
    InBuffer { v: Vec<u8>, remaining: usize },
    Ignoring { remaining: usize },
}

/// IncrementalDecoderResult is the result of decoding a partial input.
/// You only get an error if the decoder completed its last instruction.
#[derive(Debug, PartialEq)]
pub enum IncrementalDecoderResult {
    InProgress,
    Uint(u64),
    Buffer(Vec<u8>),
    Ignored,
    Error,
}

impl IncrementalDecoder {
    /// Decode a buffer of fixed size.
    pub fn decode(n: usize) -> IncrementalDecoder {
        IncrementalDecoder::InBuffer {
            v: Vec::new(),
            remaining: n,
        }
    }

    /// Decode an unsigned integer of fixed size.
    pub fn decode_uint(n: usize) -> IncrementalDecoder {
        IncrementalDecoder::InUint { v: 0, remaining: n }
    }

    /// Decode a QUIC variable-length integer.
    pub fn decode_varint() -> IncrementalDecoder {
        IncrementalDecoder::BeforeVarint
    }

    /// Decode a vector that as a fixed-sized length prefix.
    pub fn decode_vec(n: usize) -> IncrementalDecoder {
        IncrementalDecoder::InBufferLen(Box::new(IncrementalDecoder::decode_uint(n)))
    }

    /// Decode a vector that as a varint-sized length prefix.
    pub fn decode_vvec() -> IncrementalDecoder {
        IncrementalDecoder::InBufferLen(Box::new(IncrementalDecoder::decode_varint()))
    }

    /// Ignore a certain number of bytes.
    pub fn ignore(n: usize) -> IncrementalDecoder {
        IncrementalDecoder::Ignoring { remaining: n }
    }

    /// For callers that might need to request additional data, provide an indication
    /// of the minimum amount of data that should be requested to make progress.
    /// The guarantee is that this will never return a value larger than a subsequent
    /// call to `consume()` will use.  This returns 0 if it is idle.
    pub fn min_remaining(&self) -> usize {
        match self {
            IncrementalDecoder::BeforeVarint => 1,
            IncrementalDecoder::InUint { remaining, .. }
            | IncrementalDecoder::InBuffer { remaining, .. }
            | IncrementalDecoder::Ignoring { remaining } => *remaining,
            IncrementalDecoder::InBufferLen(in_len) => in_len.min_remaining(),
            _ => 0,
        }
    }

    fn consume_uint_part(mut v: u64, amount: usize, dv: &mut Decoder) -> u64 {
        if amount == 0 {
            v
        } else {
            if amount < 8 {
                v <<= amount * 8;
            }
            v | dv.decode_uint(amount).unwrap()
        }
    }

    fn consume_uint_remainder(
        &mut self,
        mut v: u64,
        mut remaining: usize,
        dv: &mut Decoder,
    ) -> IncrementalDecoderResult {
        if remaining <= dv.remaining() {
            v = IncrementalDecoder::consume_uint_part(v, remaining, dv);
            *self = IncrementalDecoder::Idle;
            IncrementalDecoderResult::Uint(v)
        } else {
            let r = dv.remaining();
            v = IncrementalDecoder::consume_uint_part(v, r, dv);
            remaining -= r;
            *self = IncrementalDecoder::InUint { v, remaining };
            IncrementalDecoderResult::InProgress
        }
    }

    fn consume_buffer_remainder(
        &mut self,
        mut v: Vec<u8>,
        remaining: usize,
        dv: &mut Decoder,
    ) -> IncrementalDecoderResult {
        if remaining <= dv.remaining() {
            let b = dv.decode(remaining).unwrap();
            v.extend_from_slice(b);
            *self = IncrementalDecoder::Idle;
            IncrementalDecoderResult::Buffer(v)
        } else {
            let b = dv.decode_remainder();
            v.extend_from_slice(b);
            *self = IncrementalDecoder::InBuffer {
                v,
                remaining: remaining - b.len(),
            };
            IncrementalDecoderResult::InProgress
        }
    }

    /// Consume data incrementally from |dv|.
    pub fn consume(&mut self, dv: &mut Decoder) -> IncrementalDecoderResult {
        match mem::replace(self, IncrementalDecoder::Idle) {
            IncrementalDecoder::Idle => IncrementalDecoderResult::Error,

            IncrementalDecoder::InUint { v, remaining } => {
                self.consume_uint_remainder(v, remaining, dv)
            }

            IncrementalDecoder::BeforeVarint => {
                let (v, remaining) = match dv.decode_byte() {
                    Some(b) => (
                        u64::from(b & 0x3f),
                        match b >> 6 {
                            0 => 0,
                            1 => 1,
                            2 => 3,
                            3 => 7,
                            _ => unreachable!(),
                        },
                    ),
                    None => return IncrementalDecoderResult::Error,
                };
                if remaining == 0 {
                    *self = IncrementalDecoder::Idle;
                    IncrementalDecoderResult::Uint(v)
                } else {
                    self.consume_uint_remainder(v, remaining, dv)
                }
            }

            IncrementalDecoder::InBufferLen(mut len_decoder) => match len_decoder.consume(dv) {
                IncrementalDecoderResult::InProgress => {
                    *self = IncrementalDecoder::InBufferLen(len_decoder);
                    IncrementalDecoderResult::InProgress
                }
                IncrementalDecoderResult::Uint(n) => {
                    self.consume_buffer_remainder(Vec::with_capacity(n as usize), n as usize, dv)
                }
                _ => unreachable!(),
            },

            IncrementalDecoder::InBuffer { v, remaining } => {
                self.consume_buffer_remainder(v, remaining, dv)
            }

            IncrementalDecoder::Ignoring { remaining } => {
                if remaining <= dv.remaining() {
                    let _ = dv.decode(remaining);
                    *self = IncrementalDecoder::Idle;
                    IncrementalDecoderResult::Ignored
                } else {
                    *self = IncrementalDecoder::Ignoring {
                        remaining: remaining - dv.remaining(),
                    };
                    let _ = dv.decode_remainder();
                    IncrementalDecoderResult::InProgress
                }
            }
        }
    }
}

impl Default for IncrementalDecoder {
    fn default() -> IncrementalDecoder {
        IncrementalDecoder::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Encoder;

    #[test]
    fn simple_incremental() {
        let b = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut dec = IncrementalDecoder::decode(b.len());
        let mut i = 0;
        while i < b.len() {
            // Feed in b in increasing-sized chunks.
            let incr = if i < b.len() / 2 { i + 1 } else { b.len() - i };
            let mut dv = Decoder::from(&b[i..i + incr]);
            i += incr;
            match dec.consume(&mut dv) {
                IncrementalDecoderResult::InProgress => {
                    assert!(i < b.len());
                }
                IncrementalDecoderResult::Buffer(res) => {
                    assert_eq!(i, b.len());
                    assert_eq!(res, b);
                }
                _ => unreachable!(),
            }
        }
    }

    // Take a |decoder|, an encoded buffer |db|, and an |expected| outcome and run
    // the buffer through the encoder several times and check the result.
    // Split the buffer in a different position each time.
    fn run_split(decoder: IncrementalDecoder, mut db: Encoder, expected: IncrementalDecoderResult) {
        eprintln!(
            "decode {:?} ; with {:?} ; expect {:?}",
            decoder, db, expected
        );

        // Add padding so that we can verify that the reader doesn't over-consume.
        db.encode_byte(0xff);

        for tail in 1..db.len() {
            let split = db.len() - tail;
            let mut dv = Decoder::from(&db[0..split]);
            eprintln!("  split at {}: {:?}", split, dv);

            // Clone the basic decoder for each iteration of the loop.
            let mut dec = decoder.clone();
            let mut res = dec.consume(&mut dv);
            assert_eq!(dv.remaining(), 0);
            assert!(dec.min_remaining() < tail);

            if tail > 1 {
                assert_eq!(res, IncrementalDecoderResult::InProgress);
                assert!(dec.min_remaining() > 0);
                let mut dv = Decoder::from(&db[split..]);
                eprintln!("  split remainder {}: {:?}", split, dv);
                res = dec.consume(&mut dv);
                assert_eq!(dv.remaining(), 1);
            }

            assert_eq!(dec.min_remaining(), 0);
            assert_eq!(res, expected);
        }
    }

    struct UintTestCase {
        b: String,
        v: u64,
    }

    impl UintTestCase {
        pub fn run(&self, dec: IncrementalDecoder) {
            run_split(
                dec,
                Encoder::from_hex(&self.b),
                IncrementalDecoderResult::Uint(self.v),
            );
        }
    }

    macro_rules! uint_tc {
        [$( $b:expr => $v:expr ),+ $(,)?] => {
            vec![ $( UintTestCase { b: String::from($b), v: $v, } ),+]
        };
    }

    #[test]
    fn uint() {
        for c in uint_tc![
            "00" => 0,
            "0000000000" => 0,
            "01" => 1,
            "0123" => 0x123,
            "012345" => 0x12345,
            "ffffffffffffffff" => 0xffffffffffffffff,
        ] {
            c.run(IncrementalDecoder::decode_uint(c.b.len() / 2));
        }
    }

    #[test]
    fn varint() {
        for c in uint_tc![
            "00" => 0,
            "01" => 1,
            "3f" => 63,
            "4040" => 64,
            "7fff" => 16383,
            "80004000" => 16384,
            "bfffffff" => (1 << 30) - 1,
            "c000000040000000" => 1 << 30,
            "ffffffffffffffff" => (1 << 62) - 1,
        ] {
            c.run(IncrementalDecoder::decode_varint());
        }
    }

    struct BufTestCase {
        b: String,
        v: String,
    }

    impl BufTestCase {
        pub fn run(&self, dec: IncrementalDecoder) {
            run_split(
                dec,
                Encoder::from_hex(&self.b),
                IncrementalDecoderResult::Buffer(Encoder::from_hex(&self.v).into()),
            );
        }
    }

    macro_rules! buf_tc {
        [$( $b:expr => $v:expr ),+ $(,)?] => {
            vec![ $( BufTestCase { b: String::from($b), v: String::from($v), } ),+]
        };
    }

    #[test]
    fn vec() {
        for c in buf_tc![
            "00" => "",
            "0100" => "00",
            "01ff" => "ff",
            "03012345" => "012345",
        ] {
            c.run(IncrementalDecoder::decode_vec(1));
        }
        for c in buf_tc![
            "0000" => "",
            "000100" => "00",
            "0001ff" => "ff",
            "0003012345" => "012345",
        ] {
            c.run(IncrementalDecoder::decode_vec(2));
        }
    }

    #[test]
    fn vvec() {
        for c in buf_tc![
            "00" => "",
            "0100" => "00",
            "01ff" => "ff",
            "03012345" => "012345",
        ] {
            c.run(IncrementalDecoder::decode_vvec());
        }
    }

    #[test]
    fn zero_len() {
        let enc = Encoder::from_hex("ff");
        let mut dec = Decoder::new(&enc);
        let mut incr = IncrementalDecoder::decode(0);
        assert_eq!(
            incr.consume(&mut dec),
            IncrementalDecoderResult::Buffer(Vec::new())
        );
        match incr {
            IncrementalDecoder::Idle => {}
            _ => panic!("should be idle"),
        };
        assert_eq!(dec.remaining(), enc.len());
    }

    #[test]
    fn ignore() {
        let enc = Encoder::from_hex("12345678");
        run_split(
            IncrementalDecoder::ignore(4),
            enc,
            IncrementalDecoderResult::Ignored,
        );
    }
}
