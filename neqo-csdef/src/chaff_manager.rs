use std::rc::Rc;
use std::cell::RefCell;
use std::convert::TryInto;
use std::collections::HashMap;
use url::Url;
use crate::event::FlowShapingApplicationEvents;
use crate::chaff_stream::ChaffStreamMap;


macro_rules! http_hdr {
    ($key:literal, $value:literal) => {
        ($key.to_string(), $value.to_string())
    };
}


#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct Resource {
    url: Url,
    headers: Vec<(String, String)>,
    body_length: Option<u64>,
}

impl Resource {
    fn new(url: Url, headers: Vec<(String, String)>) -> Self {
        let mut headers = headers;
        headers.retain(|(key, _)| key.to_lowercase() != "accept-encoding");
        headers.retain(|(key, _)| !key.to_lowercase().starts_with("if-"));

        headers.push(http_hdr!("accept-encoding", "identity"));

        Resource { url, headers, body_length: None }
    }

    fn with_length(mut self, body_length: u64) -> Self {
        self.body_length = Some(body_length);
        self
    }
}

impl From<&Url> for Resource {
    fn from(url: &Url) -> Self {
        Resource::new(url.clone(), Vec::new())
    }
}


#[derive(Debug)]
pub(crate) struct ChaffManager {
    /// The maximum number of chaff streams available at a given time
    max_streams: u32,
    /// The minimum available chaff data to attempt to maintain, in bytes.
    low_watermark: u64,

    resources: HashMap<String, Resource>,
    events: Rc<RefCell<FlowShapingApplicationEvents>>,
    has_started: bool,
}

impl ChaffManager {
    fn new(
        max_streams: u32, 
        low_watermark: u64,
        events: Rc<RefCell<FlowShapingApplicationEvents>>
    ) -> Self {
        ChaffManager {
            max_streams,
            low_watermark,
            events,
            has_started: false,
            resources: Default::default(),
        }
    }

    /// Cannot be called after we've started
    pub fn add_chaff_resource(&mut self, url: Url, headers: Vec<(String, String)>) {
        assert!(!self.resources.contains_key(url.as_str()));
        assert!(!self.has_started, "cannot add resource as already started");
        self.add_resource(Resource::new(url, headers));
    }

    fn add_resource(&mut self, resource: Resource) {
        self.resources.insert(resource.url.as_str().into(), resource);
    }

    /// Called when the HTTP stack is ready and able to send requests.
    /// Requests all initially added chaff resources. 
    pub fn start(&mut self) {
        assert!(!self.has_started, "already started");

        for resource in self.resources.values() {
            self.events.borrow_mut().request_chaff_resource(&resource.url, &resource.headers);
        }
        self.has_started = true;
    }

    /// Call when an HTTP response has been received on a stream with the 
    /// length of the HTTP response body.
    pub fn on_http_response_received(
        &mut self, url: Url, request_headers: Vec<(String, String)>, body_length: u64
    ) {
        assert!(self.has_started, "response received when not started");
        self.add_resource(Resource::new(url, request_headers)
                          .with_length(body_length));
    }

    /// Request chaff streams such that the anticipated amount of data 
    /// in total will be greater than the low watermark.
    /// Will not attempt to create more than max_streams in total, but 
    /// calling this function repeatedly without waiting for the streams to
    /// be created will result in too many streams being created.
    pub fn request_chaff_streams(&mut self, streams: &ChaffStreamMap) {
        // TODO: Add logging
        if streams.pull_available() >= self.low_watermark {
            return;
        }

        let mut chaff_needed = self.low_watermark - streams.pull_available();

        let stream_count: u32 = streams.iter()
            .filter(|(_, stream)| !stream.is_recv_closed())
            .count()
            .try_into().unwrap();
        let mut remaining_streams = self.max_streams.saturating_sub(stream_count);

        if remaining_streams == 0 {
            return;
        }

        if let Some(resource) = self.largest_resource().cloned() {
            let body_length = resource.body_length
                .expect("largest resource should have a length");

            while remaining_streams > 0 && chaff_needed > 0 {
                self.request_resource(&resource);

                chaff_needed = chaff_needed.saturating_sub(body_length);
                remaining_streams -= 1;
            }
        }
    }

    fn request_resource(&mut self, resource: &Resource) {
        self.events.borrow_mut().request_chaff_resource(&resource.url, &resource.headers);
    }

    fn largest_resource(&self) -> Option<&Resource> {
        let mut largest_len = 0;
        let mut largest = None;

        for resource in self.resources.values() {
            if let Some(length) = resource.body_length {
                if length >= largest_len {
                    largest = Some(resource);
                    largest_len = length;
                }
            }
        }

        largest
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use crate::event::{ FlowShapingEvent as FSE, Provider };
    use crate::chaff_stream::ChaffStream;

    macro_rules! assert_unord_eq {
        ($lhs:expr, $rhs:expr) => {

        let mut lhs_map: HashMap<_, u32> = HashMap::new();
        $lhs.iter().for_each(|elem| *lhs_map.entry(elem).or_insert(0) += 1);

        let mut rhs_map: HashMap<_, u32> = HashMap::new();
        $rhs.iter().for_each(|elem| *rhs_map.entry(elem).or_insert(0) += 1);

        assert_eq!(lhs_map, rhs_map);
        };
    }

    macro_rules! url {
        ($name:literal) => {
            Url::parse($name).expect("valid url in test")
        };
    }

    fn default_hdrs() -> Vec<(String, String)> {
        vec![http_hdr!("accept-encoding", "identity")]
    }

    fn chaff_manager() -> ChaffManager {
        ChaffManager::new(5, 1_000_000, Default::default())
    }

    #[test]
    fn requests_initial_resources() -> Result<(), Box<dyn Error>> {
        let mut manager = chaff_manager();
        let events = manager.events.clone();

        manager.add_chaff_resource(Url::parse("https://a.com")?, Vec::new());
        manager.add_chaff_resource(Url::parse("https://b.com")?, Vec::new());
        manager.add_chaff_resource(Url::parse("https://c.com")?, Vec::new());

        manager.start();

        let events: Vec<FSE> = events.borrow_mut().events().collect();
        let expected = [
            FSE::RequestResource{ 
                url: Url::parse("https://a.com")?, headers: default_hdrs() },
            FSE::RequestResource{ 
                url: Url::parse("https://b.com")?, headers: default_hdrs() },
            FSE::RequestResource{ 
                url: Url::parse("https://c.com")?, headers: default_hdrs() },
        ];
        assert_unord_eq!(&events, &expected);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "cannot add resource as already started")]
    fn add_chaff_resource_errs_after_started() {
        let mut manager = chaff_manager();
        manager.start();
        manager.add_chaff_resource(Url::parse("https://a.com").unwrap(), Vec::new());
    }

    #[test]
    #[should_panic(expected = "already started")]
    fn start_panics_if_started() {
        let mut manager = chaff_manager();
        manager.start();
        manager.start();
    }

    #[test]
    fn tracks_completed_resource_lengths() -> Result<(), Box<dyn Error>> {
        let mut manager = chaff_manager();
        manager.start();

        let url = Url::parse("https://z.com")?;
        manager.on_http_response_received(url.clone(), Vec::new(), 25000);

        assert_eq!(manager.resources.get(url.as_str()), Some(
                &Resource { 
                    url: url.clone(), headers: default_hdrs(), body_length: Some(25000), 
                }));

        Ok(())
    }

    #[test]
    fn tracks_last_resource_length() -> Result<(), Box<dyn Error>> {
        let url = Url::parse("https://y.com")?;
        let mut manager = chaff_manager();
        manager.start();

        manager.on_http_response_received(url.clone(), Vec::new(), 15000);
        assert_eq!(manager.resources.get(url.as_str()),
                   Some(&Resource { 
                       url: url.clone(), headers: default_hdrs(), body_length: Some(15000), 
                   }));
        manager.on_http_response_received(url.clone(), Vec::new(), 4000);
        assert_eq!(manager.resources.get(url.as_str()),
                   Some(&Resource {
                       url: url.clone(), headers: default_hdrs(), body_length: Some(4000), 
                   }));

        Ok(())
    }

    #[test]
    fn requests_chaff_streams() -> Result<(), Box<dyn Error>> {
        let headers = vec![("cache-control".into(), "no-cache".into())];
        let streams = ChaffStreamMap::default();
        let mut manager = ChaffManager::new(5, 1_000_000, Default::default());
        manager.start();
        manager.on_http_response_received(Url::parse("https://a.com")?, Vec::new(), 50_000);
        manager.on_http_response_received(
            Url::parse("https://b.com")?, headers.clone(), 250_000);
        manager.on_http_response_received(Url::parse("https://c.com")?, Vec::new(), 100_000);

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();

        let expected_hdrs = [headers, vec![http_hdr!("accept-encoding", "identity")]].concat();
        let expected: Vec<FSE> = std::iter::repeat(FSE::RequestResource {
            url: Url::parse("https://b.com")?, headers: expected_hdrs
        }).take(4).collect();

        assert_unord_eq!(&events, &expected);

        Ok(())
    }

    #[test]
    fn requests_less_than_max_streams() -> Result<(), Box<dyn Error>> {
        let mut streams = ChaffStreamMap::default();
        streams.insert(ChaffStream::new(
            0, Url::parse("https://a.com")?, Default::default(), 20, true));
        streams.insert(ChaffStream::new(
            4, Url::parse("https://b.com")?, Default::default(), 20, false));

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.on_http_response_received(Url::parse("https://a.com")?, Vec::new(), 8000);
        manager.on_http_response_received(Url::parse("https://b.com")?, Vec::new(), 6000);
        manager.on_http_response_received(Url::parse("https://c.com")?, Vec::new(), 10000);

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 1);

        Ok(())
    }

    #[test]
    fn doesnt_ignore_closed_sending() -> Result<(), Box<dyn Error>> {
        let mut streams = ChaffStreamMap::default();
        let mut stream = ChaffStream::new(
            0, Url::parse("https://a.com")?, Default::default(), 20, true);
        // The receive side is still open and so this consumes an slot
        stream.close_sending();
        streams.insert(stream);

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.on_http_response_received(Url::parse("https://a.com")?, Vec::new(), 8000);
        manager.on_http_response_received(Url::parse("https://b.com")?, Vec::new(), 6000);
        manager.on_http_response_received(Url::parse("https://c.com")?, Vec::new(), 10000);

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 2);

        Ok(())
    }

    #[test]
    fn ignores_closed_receiving() -> Result<(), Box<dyn Error>> {
        let mut streams = ChaffStreamMap::default();
        let mut stream = ChaffStream::new(
            0, Url::parse("https://a.com")?, Default::default(), 20, true);
        stream.close_receiving();
        streams.insert(stream);

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.on_http_response_received(Url::parse("https://a.com")?, Vec::new(), 8000);
        manager.on_http_response_received(Url::parse("https://b.com")?, Vec::new(), 6000);
        manager.on_http_response_received(Url::parse("https://c.com")?, Vec::new(), 10000);

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 3);

        Ok(())
    }

    #[test]
    fn chaff_resource_adds_identity_encoding() {
        let resource = Resource::new(url!("https://b.nl"), Vec::new()); 
        assert_eq!(resource.headers, vec![http_hdr!("accept-encoding", "identity")]);
    }

    #[test]
    fn chaff_resource_replaces_identity_encoding() {
        let resource = Resource::new(
            url!("https://a.nl"), vec![
                http_hdr!("Accept-Encoding", "gzip"),
                http_hdr!("ACCEPT-ENCODING", "zip")
            ]);

        assert_eq!(resource.headers, vec![http_hdr!("accept-encoding", "identity")]);
    }

    #[test]
    fn chaff_resource_removes_conditional_headers() {
        let resource = Resource::new(
            url!("https://a.nl"), vec![
                http_hdr!("Accept", "text/html"),
                http_hdr!("If-Modified-Since", "Mon, 18 Jul 2016 02:36:04 GMT"),
                http_hdr!("If-None-Match", "c561c68d0ba92bbeb8b0fff2a9199f722e3a621a"),
            ]);
        assert_eq!(resource.headers, vec![
            http_hdr!("Accept", "text/html"),
            http_hdr!("accept-encoding", "identity")
        ]);
    }
}
