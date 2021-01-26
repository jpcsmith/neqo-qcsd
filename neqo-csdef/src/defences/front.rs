use std::time::Duration;
use rand::Rng; // for rayleigh sampling
use neqo_common::qinfo;
use serde::Deserialize;
use crate::Trace;
use crate::defences::Defence;


// TODO(ldolfi): possibly use rgsl.randist.rayleigh
fn rayleigh_cdf_inv(u: f64, sigma: f64) -> f64{
    let foo = (1.-u).ln();
    let bar = (-2.*foo).sqrt();

    return sigma*bar;
}


#[derive(Debug, Deserialize)]
pub struct FrontConfig {
    /// The number of dummy bursts sent by the client
    pub n_client_packets: u32,
    /// The number of dummy bursts sent by the server
    pub n_server_packets: u32,
    /// The size of each dummy burst
    pub packet_size: u32,
    /// The minimum value for the distribution peak
    pub peak_minimum: f64,
    /// The maximum value for the distribution peak
    pub peak_maximum: f64,
}

impl Default for FrontConfig {
    fn default() -> Self { 
        FrontConfig{
            n_client_packets: 900,
            n_server_packets: 1200,
            packet_size: 700,
            peak_minimum: 0.1,
            peak_maximum: 2.5
        }
    }
}

#[derive(Default)]
pub struct FrontDefence {
    config: FrontConfig,
}

impl FrontDefence {
    pub fn new(config: FrontConfig) -> Self {
        FrontDefence{ config }
    }

    fn sample_timestamps(&self, n_packets: u32) -> Trace {
        let config = &self.config;

        let n_packets: u64 = rand::thread_rng().gen_range(1, (n_packets + 1).into());
        let weight: f64 = rand::thread_rng().gen_range(
            config.peak_minimum, config.peak_maximum);
        println!("n_packets: {}\tw: {}", n_packets, weight);

        std::iter::repeat_with(move || {
            let timestamp = rayleigh_cdf_inv(rand::thread_rng().gen_range(0.,1.), weight);

            (Duration::from_secs_f64(timestamp), config.packet_size as i32)
        }).take(n_packets as usize).collect()
    }

    pub fn create_trace(&self) -> Trace {
        qinfo!("Creating padding traces.");

        self.sample_timestamps(self.config.n_server_packets)
            .into_iter()
            .map(|(t, l)| (t, l * -1))
            .chain(self.sample_timestamps(self.config.n_client_packets))
            .collect()
    }

}

impl Defence for FrontDefence {
    fn trace(&self) -> Trace { self.create_trace() }
    fn is_padding_only(&self) -> bool { true }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_create_trace() {
        let trace = FrontDefence::new(FrontConfig{ 
            packet_size: 500, ..Default::default() 
        }).create_trace();

        // All packets should be of absolute size 500
        assert!(trace.iter().all(|(_, l)| l.abs() == 500));

        // Packets should be going in both directions
        assert!(trace.iter().any(|(_, l)| *l < 0));
        assert!(trace.iter().any(|(_, l)| *l > 0));
    }
}
