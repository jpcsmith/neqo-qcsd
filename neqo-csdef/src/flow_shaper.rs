use std::fs::File;
use std::io::{self, BufRead};
use std::num;
use std::time::{ Duration, Instant };
use std::collections::{ HashMap, VecDeque };
use std::convert::TryFrom;


#[derive(Debug)]
pub enum TraceLoadError {
    Io(io::Error),
    Parse(String),
}

impl From<num::ParseIntError> for TraceLoadError {
    fn from(err: num::ParseIntError) -> TraceLoadError {
        TraceLoadError::Parse(err.to_string())
    }
}

impl From<num::ParseFloatError> for TraceLoadError {
    fn from(err: num::ParseFloatError) -> TraceLoadError {
        TraceLoadError::Parse(err.to_string())
    }
}

impl From<io::Error> for TraceLoadError {
    fn from(err: io::Error) -> TraceLoadError {
        TraceLoadError::Io(err)
    }
}


type Trace = Vec<(Duration, i32)>;

pub fn load_trace(filename: &str) -> Result<Trace, TraceLoadError> {
    let mut packets = Vec::new();

    let file = File::open(filename)?;
    for line in io::BufReader::new(file).lines() {
        let line = line?;
        let mut line_iter = line.split(",");
        let timestamp: f64 = line_iter.next()
            .ok_or(TraceLoadError::Parse("no timestamp".to_owned()))
            .and_then(|s| s.parse::<f64>().map_err(TraceLoadError::from))?;
        let size: i32 = line_iter.next()
            .ok_or(TraceLoadError::Parse("no size".to_owned()))
            .and_then(|s| s.parse::<i32>().map_err(TraceLoadError::from))?;

        packets.push((Duration::from_secs_f64(timestamp), size));
    }

    Ok(packets)
}


#[derive(Debug,Eq,PartialEq)]
pub enum Cmd {
    IncreaseMaxData(u64),
}


#[derive(Debug)]
pub struct FlowShaper {
    // The control interval
    interval: Duration,

    out_target: VecDeque<(u32, i32)>,
    in_target: VecDeque<(u32, i32)>,

    start_time: Option<Instant>
}


impl FlowShaper {
    /// Start shaping the traffic using the current time as the reference
    /// point.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Report the next instant at which the FlowShaper should be called for 
    /// processing events.
    pub fn next_signal_time(&self) -> Option<Instant> {
        self.in_target.front()
            .map(|(ts, _)| Duration::from_millis(u64::from(*ts)))
            .zip(self.start_time)
            .map(|(dur, start)| start + dur)
    }

    pub fn process_timer(&mut self, now: Instant) -> Option<Cmd> {
        self.process_timer_(now.duration_since(self.start_time?))
    }

    fn process_timer_(&mut self, since_start: Duration) -> Option<Cmd> {
        if let Some((ts, _)) = self.in_target.front() {
            let next = Duration::from_millis(u64::from(*ts));
            if next < since_start {
                let (_, size) = self.in_target.pop_front()
                    .expect("the deque to be non-empty");
                return Some(Cmd::IncreaseMaxData(
                    u64::try_from(size).expect("absolute sizes")));
            } 
        }

        None
    }

    pub fn new(interval: Duration, trace: &Trace) -> FlowShaper {
        assert!(trace.len() > 0);

        // Bin the trace
        let mut bins: HashMap<(u32, bool), i32> = HashMap::new();
        let interval_ms = interval.as_millis();

        for (timestamp, size) in trace.iter() {
            let timestamp = timestamp.as_millis();
            let bin = u32::try_from(timestamp - (timestamp % interval_ms))
                .expect("timestamp in millis to fit in u32");

            assert!(*size != 0, "trace sizes should be non-zero");
            bins.entry((bin, *size > 0))
                .and_modify(|e| *e += size)
                .or_insert(*size);
        }

        let mut in_target: Vec<(u32, i32)> = bins
            .iter()
            .filter(|&((_, inc), _)| !*inc)
            .map(|((ts, _), size)| (*ts, size.abs()))
            .collect();
        in_target.sort();

        let mut out_target: Vec<(u32, i32)> = bins
            .iter()
            .filter(|((_, inc), _)| *inc)
            .map(|((ts, _), size)| (*ts, *size))
            .collect();
        out_target.sort();

        FlowShaper{ 
            interval,
            in_target: VecDeque::from(in_target), 
            out_target: VecDeque::from(out_target),
            start_time: None
        }
    }
}






#[cfg(test)]
mod tests {
    use super::*;

    fn create_shaper() -> FlowShaper {
        let vec = vec![
                (Duration::from_millis(2), 1350), (Duration::from_millis(16), -800),
                (Duration::from_millis(21), 600), (Duration::from_millis(22), -350),
            ];
        FlowShaper::new(Duration::from_millis(5), &vec)
    }

    #[test]
    fn test_sanity() {
        let trace = load_trace("../data/nytimes.csv").expect("Load failed");
        FlowShaper::new(Duration::from_millis(10), &trace);
    }

    #[test]
    fn test_next_signal_time() {
        let mut shaper = create_shaper();
        assert_eq!(shaper.next_signal_time(), None);

        shaper.start();
        assert_eq!(shaper.next_signal_time(), 
                   Some(shaper.start_time.unwrap() + Duration::from_millis(15)))
    }

    #[test]
    fn test_process_timer() {
        let mut shaper = create_shaper();
        assert_eq!(shaper.process_timer_(Duration::from_millis(3)), None);
        assert_eq!(shaper.process_timer_(Duration::from_millis(17)),
                   Some(Cmd::IncreaseMaxData(800)));
        assert_eq!(shaper.process_timer_(Duration::from_millis(21)),
                   Some(Cmd::IncreaseMaxData(350)));
    }
}
