pub mod flow_shaper;
pub mod defences;
pub mod stream_id;
mod events;
mod error;
mod chaff_stream;

pub use crate::error::{
    Error, ErrorKind, Result
};

use std::{ env, fs, io };
use std::time::Duration;
use serde::Deserialize;

pub type Trace = Vec<(Duration, i32)>;

/// Returns true iff the CSDEF_NO_SHAPING environment variable is set to a
/// non-empty string.
pub fn debug_disable_shaping() -> bool {
    debug_disable_shaping_("CSDEF_NO_SHAPING")
}

fn debug_disable_shaping_(env_key: &str) -> bool {
    match env::var(env_key) {
        Ok(s) => s != "",
        _ => false
    }
}

pub fn shaper_config_file() -> Option<String> {
    match env::var("CSDEF_SHAPER_CONFIG") {
        Ok(s) => Some(s),
        Err(_) => None
    }
}

pub fn dummy_schedule_log_file() -> Option<String> {
    match env::var("CSDEF_DUMMY_SCHEDULE") {
        Ok(s) => Some(s),
        Err(_) => None
    }

}


#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub flow_shaper: Option<flow_shaper::Config>,
    pub front_defence: Option<defences::FrontConfig>
}

impl ConfigFile {
    pub fn load(filename: &str) -> Result<ConfigFile> {
        let toml_string = fs::read_to_string(filename)?;
        toml::from_str(&toml_string)
            .or(Err(Error::from(io::Error::new(io::ErrorKind::Other, "Invalid TOML file."))))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Use different keys to prevent interfering with each other,
    // as env is for the process and rust uses multiple threads.
    #[test]
    fn test_disable_shaping_unset() {
        let key = "CSDEF_NO_SHAPING_T1";
        assert!(!debug_disable_shaping_(&key));
    }

    #[test]
    fn test_disable_shaping_empty_string() {
        let key = "CSDEF_NO_SHAPING_T2";
        env::set_var(&key, "");
        assert!(!debug_disable_shaping_(&key));
    }

    #[test]
    fn test_disable_shaping_set() {
        let key = "CSDEF_NO_SHAPING_T3";
        env::set_var(&key, "y");
        assert!(debug_disable_shaping_(&key));

        env::set_var(&key, "true");
        assert!(debug_disable_shaping_(&key));

        env::set_var(&key, "");
        assert!(!debug_disable_shaping_(&key));
    }
}
