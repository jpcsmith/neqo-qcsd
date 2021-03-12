use std::rc::Rc;
use std::cell::RefCell;
use std::convert::TryInto;
use std::collections::HashMap;
use url::Url;
use neqo_common::qtrace;
use crate::event::FlowShapingApplicationEvents;
use crate::chaff_stream::ChaffStreamMap;
use crate::Resource;


macro_rules! http_hdr {
    ($key:literal, $value:literal) => {
        ($key.to_string(), $value.to_string())
    };
}


#[derive(Debug)]
pub(crate) struct ChaffManager {
    /// The maximum number of chaff streams available at a given time
    max_streams: u32,
    /// The minimum available chaff data to attempt to maintain, in bytes.
    low_watermark: u64,

    resources: HashMap<Url, Resource>,
    events: Rc<RefCell<FlowShapingApplicationEvents>>,
    has_started: bool,
}

impl ChaffManager {
    pub fn new(
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

    /// Add a resource to be tracked by the chaff manager, replacing any existing
    /// resource entries with the same URL.
    pub fn add_resource(&mut self, resource: Resource) {
        let resource_str = format!("{:?}", resource);

        if let Some(old) = self.resources.insert(resource.url.clone(), resource) {
            qtrace!([self], "update {:?} -> {}", old, resource_str);
        } else {
            qtrace!([self], "added {}", resource_str);
        }
    }

    /// Called when the HTTP stack is ready and able to send requests.
    /// Requests one of each resource added up to this point.
    pub fn start(&mut self) {
        assert!(!self.has_started, "already started");
        qtrace!([self], "starting with {} initial resources", self.resources.len());

        for resource in self.resources.values() {
            self.request(&resource);
        }
        self.has_started = true;
    }

    pub fn has_started(&self) -> bool {
        self.has_started
    }

    fn modify_headers(headers: &Vec<(String, String)>) -> Vec<(String, String)> {
        headers.iter()
            .filter(|(key, _)| key.to_lowercase() != "accept-encoding")
            .filter(|(key, _)| !key.to_lowercase().starts_with("if-"))
            .cloned()
            .chain(Some(http_hdr!("accept-encoding", "identity")))
            .collect()
    }

    fn request(&self, resource: &Resource) {
        let headers = ChaffManager::modify_headers(&resource.headers);
        let resource = resource.clone().with_headers(headers);
        self.events.borrow_mut().request_chaff_resource(&resource);
        qtrace!([self], "issued request for {:?}", resource);
    }

    /// Request chaff streams such that the anticipated amount of data
    /// in total will be greater than the low watermark.
    /// Will not attempt to create more than max_streams in total, but
    /// calling this function repeatedly without waiting for the streams to
    /// be created will result in too many streams being created.
    pub fn request_chaff_streams(&mut self, streams: &ChaffStreamMap) {
        if streams.pull_available() >= self.low_watermark {
            qtrace!([self], "skipping requests, available data exceeds watermark: {}",
                    self.low_watermark);
            return;
        }

        let mut chaff_needed = self.low_watermark - streams.pull_available();
        qtrace!([self], "below low watermark by {}", chaff_needed);

        let stream_count: u32 = streams.iter()
            .filter(|(_, stream)| !stream.is_recv_closed())
            .count()
            .try_into().unwrap();
        qtrace!([self], "existing chaff streams: {} of {}", stream_count,
                self.max_streams);

        let mut remaining_streams = self.max_streams.saturating_sub(stream_count);

        if remaining_streams == 0 {
            return;
        }

        if let Some(resource) = self.largest_resource().cloned() {
            let length = resource.length;
            assert!(length > 0, "largest resource should have a length");

            while remaining_streams > 0 && chaff_needed > 0 {
                self.request(&resource);

                chaff_needed = chaff_needed.saturating_sub(length);
                remaining_streams -= 1;
            }
        }

        qtrace!([self], "requests complete with {} streams still available and {} below watermark",
                remaining_streams, chaff_needed);
    }

    fn largest_resource(&self) -> Option<&Resource> {
        self.resources.values().max_by_key(|resource| resource.length)
    }
}

impl std::fmt::Display for ChaffManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChaffManager")
    }
}


#[cfg(test)]
mod tests {
    use super::*;
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
    fn requests_initial_resources() {
        let mut manager = chaff_manager();
        let events = manager.events.clone();

        manager.add_resource(Resource::from(url!("https://a.com")));
        manager.add_resource(Resource::from(url!("https://b.com")));
        manager.add_resource(Resource::from(url!("https://c.com")));

        manager.start();

        let events: Vec<FSE> = events.borrow_mut().events().collect();
        let expected = [
            FSE::RequestResource(Resource::new(url!("https://a.com"), default_hdrs(), 0)),
            FSE::RequestResource(Resource::new(url!("https://b.com"), default_hdrs(), 0)),
            FSE::RequestResource(Resource::new(url!("https://c.com"), default_hdrs(), 0)),
        ];
        assert_unord_eq!(&events, &expected);
    }


    #[test]
    #[should_panic(expected = "already started")]
    fn start_panics_if_started() {
        let mut manager = chaff_manager();
        manager.start();
        manager.start();
    }

    #[test]
    fn tracks_completed_resource_lengths() {
        let mut manager = chaff_manager();
        manager.start();

        let url = url!("https://z.com");
        manager.add_resource(Resource::new(url.clone(), vec![], 25000));

        assert_eq!(manager.resources.get(&url), Some(
                &Resource { url: url.clone(), headers: vec![], length: 25000 }));
    }

    #[test]
    fn tracks_last_resource_length() {
        let url = url!("https://y.com");
        let mut manager = chaff_manager();
        manager.start();

        manager.add_resource(Resource::new(url.clone(), vec![], 15000));
        assert_eq!(manager.resources.get(&url),
                   Some(&Resource { url: url.clone(), headers: vec![], length: 15000 }));
        manager.add_resource(Resource::new(url.clone(), vec![], 4000));
        assert_eq!(manager.resources.get(&url),
                   Some(&Resource { url: url.clone(), headers: vec![], length: 4000 }));
    }

    #[test]
    fn requests_chaff_streams() {
        let headers = vec![http_hdr!("cache-control", "no-cache")];
        let streams = ChaffStreamMap::default();
        let mut manager = ChaffManager::new(5, 1_000_000, Default::default());
        manager.start();

        manager.add_resource(Resource::new(url!("https://a.com"), vec![], 50_000));
        manager.add_resource(Resource::new(url!("https://b.com"), headers.clone(), 250_000));
        manager.add_resource(Resource::new(url!("https://c.com"), vec![], 100_000));

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();

        let expected_hdrs = [headers, vec![http_hdr!("accept-encoding", "identity")]].concat();
        let expected: Vec<FSE> = std::iter::repeat(
            FSE::RequestResource(Resource::new(url!("https://b.com"), expected_hdrs, 250_000))
        ).take(4).collect();

        assert_unord_eq!(&events, &expected);
    }

    #[test]
    fn requests_less_than_max_streams() {
        let mut streams = ChaffStreamMap::default();
        streams.insert(ChaffStream::new(
            0, url!("https://a.com"), Default::default(), 20, true));
        streams.insert(ChaffStream::new(
            4, url!("https://b.com"), Default::default(), 20, false));

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.add_resource(Resource::new(url!("https://a.com"), Vec::new(), 8000));
        manager.add_resource(Resource::new(url!("https://b.com"), Vec::new(), 6000));
        manager.add_resource(Resource::new(url!("https://c.com"), Vec::new(), 10000));

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn doesnt_ignore_closed_sending() {
        let mut streams = ChaffStreamMap::default();
        let mut stream = ChaffStream::new(
            0, url!("https://a.com"), Default::default(), 20, true);
        // The receive side is still open and so this consumes an slot
        stream.close_sending();
        streams.insert(stream);

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.add_resource(Resource::new(url!("https://a.com"), Vec::new(), 8000));
        manager.add_resource(Resource::new(url!("https://b.com"), Vec::new(), 6000));
        manager.add_resource(Resource::new(url!("https://c.com"), Vec::new(), 10000));

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn ignores_closed_receiving() {
        let mut streams = ChaffStreamMap::default();
        let mut stream = ChaffStream::new(
            0, url!("https://a.com"), Default::default(), 20, true);
        stream.close_receiving();
        streams.insert(stream);

        let mut manager = ChaffManager::new(3, 1_000_000, Default::default());
        manager.start();
        manager.add_resource(Resource::new(url!("https://a.com"), Vec::new(), 8000));
        manager.add_resource(Resource::new(url!("https://b.com"), Vec::new(), 6000));
        manager.add_resource(Resource::new(url!("https://c.com"), Vec::new(), 10000));

        manager.request_chaff_streams(&streams);

        let events: Vec<FSE> = manager.events.borrow_mut().events().collect();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn modify_headers_adds_identity_encoding() {
        assert_eq!(ChaffManager::modify_headers(&vec![]),
                   vec![http_hdr!("accept-encoding", "identity")]);
    }

    #[test]
    fn modify_headers_replaces_identity_encoding() {
        let modified = ChaffManager::modify_headers(&vec![
            http_hdr!("Accept-Encoding", "gzip"),
            http_hdr!("ACCEPT-ENCODING", "zip")
        ]);

        assert_eq!(modified, vec![http_hdr!("accept-encoding", "identity")]);
    }

    #[test]
    fn modify_headers_removes_conditional_headers() {
        let modified = ChaffManager::modify_headers(&vec![
            http_hdr!("Accept", "text/html"),
            http_hdr!("If-Modified-Since", "Mon, 18 Jul 2016 02:36:04 GMT"),
            http_hdr!("If-None-Match", "c561c68d0ba92bbeb8b0fff2a9199f722e3a621a"),
        ]);

        assert_eq!(modified, vec![
            http_hdr!("Accept", "text/html"),
            http_hdr!("accept-encoding", "identity")
        ]);
    }
}
