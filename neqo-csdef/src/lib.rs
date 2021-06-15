pub mod flow_shaper;
pub mod defences;
pub mod stream_id;
pub mod event;
pub mod trace;
pub mod dependency_tracker;
mod error;
mod chaff_stream;
mod chaff_manager;

pub use crate::error::{
    Error, ErrorKind, Result
};

use std::{ fs, io };
use serde::Deserialize;
use url::Url;


#[macro_export]
macro_rules! url {
    ($name:literal) => {
        Url::parse($name).expect("valid url")
    };
    ($scheme:expr, $host:expr, $path:expr) => {
        Url::parse(&format!("{}://{}{}", $scheme, $host, $path)).expect("valid url")
    };
}


#[derive(Debug, Deserialize, PartialEq)]
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


#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Resource {
    url: Url,
    headers: Vec<(String, String)>,
    length: u64,
}

impl Resource {
    pub fn new(url: Url, headers: Vec<(String, String)>, length: u64) -> Self {
        Resource { url, headers, length }
    }

    pub(crate) fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &Vec<(String, String)> {
        &self.headers
    }
}

impl From<Url> for Resource {
    fn from(url: Url) -> Self {
        Resource::new(url, Vec::new(), 0)
    }
}



#[cfg(test)]
mod lib_tests {
    use super::*;


    #[test]
    fn partially_deserialise_flow_shaper() {
        let config_txt = "
        [flow_shaper]
        control_interval = 10
        ";

        let config: ConfigFile = toml::from_str(config_txt).unwrap();

        assert_eq!(config.front_defence, None);
        assert_eq!(config.flow_shaper, 
                   Some(flow_shaper::Config {
                       control_interval: 10,
                       ..flow_shaper::Config::default()
                   }));
    }

    #[test]
    fn partially_deserialise_front() {
        let config_txt = "
        [front_defence]
        packet_size = 300
        n_server_packets = 21
        ";

        let config: ConfigFile = toml::from_str(config_txt).unwrap();

        assert_eq!(config.flow_shaper, None);
        assert_eq!(config.front_defence, 
                   Some(defences::FrontConfig {
                       n_server_packets: 21,
                       packet_size: 300,
                       ..defences::FrontConfig::default()
                   }));
    }
}
