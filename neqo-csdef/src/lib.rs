pub mod flow_shaper;
pub mod defences;
pub mod stream_id;
pub mod events;
pub mod trace;
mod error;
mod chaff_stream;

pub use crate::error::{
    Error, ErrorKind, Result
};

use std::{ env, fs, io };
use serde::Deserialize;


trait Env {
    fn get_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}


#[derive(Default)]
struct ProcessEnv;
impl Env for ProcessEnv {}


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

/// Returns the path to the input trace file and true if the file is associated
/// with a padding-only defence.
///
/// Environemt Variables:
///     CSDEF_INPUT_TRACE:      Padding-only defence input file
///     CSDEF_INPUT_TRACE_S:    Shaping defence input file
pub fn debug_use_trace_file() -> Option<(String, bool)> {
    trace_file_from_env(&ProcessEnv::default())
}

fn trace_file_from_env<T: Env>(env: &T) -> Option<(String, bool)> {
    match (env.get_var("CSDEF_INPUT_TRACE"), env.get_var("CSDEF_INPUT_TRACE_S")) {
        (Some(_), Some(_)) => panic!("Do not set both CSDEF_INPUT_TRACE and \
                                     CSDEF_INPUT_TRACE_S"),
        (Some(s), None) => Some((s, true)),
        (None, Some(s)) => Some((s, false)),
        (None, None) => None,
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
    use std::collections::HashMap;


    #[derive(Default)]
    struct TestEnv(HashMap<String, String>);

    impl TestEnv {
        fn new(initial_state: &[(&str, &str)]) -> Self {
            let mut map: HashMap<String, String> = HashMap::new();

            for (key, value) in initial_state {
                map.insert((*key).into(), (*value).into());
            }

            TestEnv(map)
        }
    }

    impl Env for TestEnv {
        fn get_var(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

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

    #[test]
    fn trace_file_from_env_unset() {
        let env = TestEnv::new(&[]);
        assert_eq!(trace_file_from_env(&env), None);
    }

    #[test]
    fn trace_file_from_env_pad_only() {
        let env = TestEnv::new(&[("CSDEF_INPUT_TRACE", "/some/path.csv")]);
        assert_eq!(trace_file_from_env(&env), Some(("/some/path.csv".into(), true)));
    }

    #[test]
    fn trace_file_from_env_chaff_only() {
        let env = TestEnv::new(&[("CSDEF_INPUT_TRACE_S", "/my/path.csv")]);
        assert_eq!(trace_file_from_env(&env), Some(("/my/path.csv".into(), false)));
    }

    #[test]
    #[should_panic(expected = "Do not set both")]
    fn trace_file_from_env_no_duplicate() {
        let env = TestEnv::new(
            &[("CSDEF_INPUT_TRACE", "pathA.csv"), ("CSDEF_INPUT_TRACE_S", "pathB.csv"),]
        );
        trace_file_from_env(&env);
    }
}
