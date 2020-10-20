use std::fs::File;
use std::io::{self, BufRead};
use std::num;
use std::time::Duration;
use std::collections::HashMap;
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


pub struct FlowShaper {
    // The control interval
    interval: Duration,

    // The target trace, binned into control intervals
    out_target: Vec<(u32, i32)>,
    in_target: Vec<(u32, i32)>,
}

impl FlowShaper {
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
            .map(|((ts, _), size)| (*ts, *size))
            .collect();
        in_target.sort();

        let mut out_target: Vec<(u32, i32)> = bins
            .iter()
            .filter(|((_, inc), _)| *inc)
            .map(|((ts, _), size)| (*ts, *size))
            .collect();
        out_target.sort();

        FlowShaper{ interval, in_target, out_target }
    }
}






#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanity() {
        let trace = load_trace("../../nytimes.csv").expect("Load failed");
        FlowShaper::new(Duration::from_millis(10), &trace);
    }
}
