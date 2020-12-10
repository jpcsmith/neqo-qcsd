pub mod flow_shaper;
pub mod stream_id;

use std::env;

pub const DEBUG_SHAPER_CONFIG: &str = "/Users/luca/Documents/ETHZ2/Thesis/code/neqo-qcd/neqo-csdef/src/config.toml";

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

pub fn shaper_config_file() -> String {
    match env::var("CSDEF_SHAPER_CONFIG") {
        Ok(s) => s,
        _ => String::from(DEBUG_SHAPER_CONFIG)
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
