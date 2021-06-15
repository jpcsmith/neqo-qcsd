use std::time::Duration;
use std::convert::TryFrom;
use serde::Deserialize;
use rand::{ Rng, StdRng, SeedableRng }; // for rayleigh sampling

use crate::trace::Packet;
use crate::defences::{ Defencev2, StaticSchedule };


// TODO(ldolfi): possibly use rgsl.randist.rayleigh
fn rayleigh_cdf_inv(u: f64, sigma: f64) -> f64{
    let foo = (1.-u).ln();
    let bar = (-2.*foo).sqrt();

    return sigma*bar;
}


#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(default)]
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
    /// The seed to use for the front defence
    pub seed: Option<u64>,
}

impl Default for FrontConfig {
    fn default() -> Self { 
        FrontConfig{
            n_client_packets: 900,
            n_server_packets: 1200,
            packet_size: 1450,
            peak_minimum: 0.1,
            peak_maximum: 2.5,
            seed: None,
        }
    }
}


fn sample_timestamps(peak_min: f64, peak_max: f64, max_packets: u32, rng: &mut impl Rng) 
        -> Vec<Duration> {

    let n_packets: u64 = rng.gen_range(1, (max_packets + 1).into());
    let weight: f64 = rng.gen_range(peak_min, peak_max);
    println!("n_packets: {}\tw: {}", n_packets, weight);

    std::iter::repeat_with(move || {
        Duration::from_secs_f64(rayleigh_cdf_inv(rng.gen_range(0.,1.), weight))
    }).take(usize::try_from(n_packets).unwrap()).collect()
}


/// The FRONT defence of Gong and Wang which adds chaff traffic according to
/// the Rayleigh distribution.
///
/// J. Gong and T. Wang, "Zero-delay Lightweight Defenses against Website Fingerprinting," 
/// in 29ᵗʰ USENIX Security Symposium (USENIX Security 20)
#[derive(Debug)]
pub struct Front {
    config: FrontConfig,
    schedule: StaticSchedule,
}


impl Front {
    /// Generate a new instance of the FRONT defence according to the sepcified 
    /// config.
    pub fn new(config: FrontConfig) -> Self {
        let mut rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_rng(rand::thread_rng()).unwrap(),
        };
        let packet_size = i32::try_from(config.packet_size)
            .expect("fits within an i32");

        let in_packets = sample_timestamps(
                config.peak_minimum, config.peak_maximum, config.n_server_packets, &mut rng)
            .into_iter().map(|t| Packet::from((t.as_millis(), packet_size * -1)));
        let out_packets = sample_timestamps(
                config.peak_minimum, config.peak_maximum, config.n_client_packets, &mut rng)
            .into_iter().map(|t| Packet::from((t.as_millis(), packet_size)));
        let packets: Vec<Packet> = out_packets.chain(in_packets).collect();

        Front {
            config,
            schedule: StaticSchedule::new(&packets, true)
        }
    }
}

impl Defencev2 for Front {
    fn next_event(&mut self, since_start: Duration) -> Option<Packet> {
        self.schedule.next_event(since_start)
    }
    fn next_event_at(&self) -> Option<Duration> { self.schedule.next_event_at() }
    fn is_complete(&self) -> bool { self.schedule.is_complete() }
    fn is_outgoing_complete(&self) -> bool { self.schedule.is_outgoing_complete() }
    fn is_padding_only(&self) -> bool { true }
    fn on_application_complete(&mut self) { self.schedule.on_application_complete() }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reproducible() {
        let mut config = FrontConfig::default();
        config.seed = Some(42);

        let mut front1 = Front::new(config.clone());
        let mut front2 = Front::new(config);

        for i in 0..10000 {
            let duration = Duration::from_millis(i);
            assert_eq!(front1.next_event(duration), front2.next_event(duration));
        }
    }
}
