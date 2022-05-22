use std::fs::File;
use std::path::Path;
use std::io::BufReader;
use serde_json;
use serde::Deserialize;
use url::Url;

use crate::Resource as ChaffResource;


#[derive(Debug, Deserialize, Clone)]
struct Resource {
    id: u16,
    url: String,

    /// Resource type such as Script, Stylesheet, etc.
    #[serde(rename = "type")]
    resource_type: String,

    /// Whether we have prior knowledge that the resource
    /// is successfully downloadable
    #[serde(rename = "done")]
    known_to_be_valid: bool,

    /// The previously observed content-length header value
    content_length: Option<u64>,

    /// Whether this resource should be prioritised as chaff
    #[serde(default)]
    chaff_priority: bool,

    /// The unencoded data length observed
    data_length: u64,

    /// Whether this has been successfully downloaded
    #[serde(skip)]
    has_completed: bool,

    /// The ids of the resource's dependencies
    #[serde(skip)]
    depends_on: Vec<u16>,
}


#[derive(Debug, Default)]
pub struct UrlDependencyTracker {
    /// Tuples of dependency and whether it has completed downloading 
    dependencies: Vec<Resource>,
}


impl UrlDependencyTracker {
    pub fn from_urls(urls: &[Url]) -> Self {
        let dependencies = (0..).zip(urls)
            .map(|(id, url)| Resource {
                id,
                url: url.to_string(),
                resource_type: "Unknown".into(),
                known_to_be_valid: false,
                content_length: None,
                data_length: 0,
                has_completed: false,
                depends_on: Vec::new(),
                chaff_priority: false,
            }).collect();

        UrlDependencyTracker { dependencies }
    }


    pub fn from_json(path: &Path) -> Self {
        let file = File::open(path).expect("unable to open file");
        let reader = BufReader::new(file);

        #[derive(Deserialize)] struct Link { source: u16, target: u16 }
        #[derive(Deserialize)] struct Graph { nodes: Vec<Resource>, links: Vec<Link>, }
        let data: Graph = serde_json::from_reader(reader).expect("unable to parse json");

        // Assert that each index matches the id
        (0..).zip(data.nodes.iter()).for_each(|(idx, res)| assert_eq!(res.id, idx));

        let mut dependencies = data.nodes.clone();
        for link in data.links {
            dependencies[usize::from(link.target)].depends_on.push(link.source);
        }

        UrlDependencyTracker { dependencies }
    }

    pub fn urls(&self) -> Vec<(u16, Url)> {
        self.dependencies.iter()
            .map(|res| (res.id, Url::parse((*res.url).into()).unwrap()))
            .collect()
    }

    /// Inform the manager that a resource has been downloaded.
    pub fn resource_downloaded(&mut self, id: u16) {
        let id = usize::from(id);
        assert!(!self.dependencies[id].has_completed, "already completed");
        self.dependencies[id].has_completed = true;
    }

    /// Return true iff the url has no outstanding dependencies
    pub fn is_downloadable(&self, id: u16) -> bool {
        self.dependencies[usize::from(id)].depends_on.iter()
            .all(|dep_id| self.dependencies[usize::from(*dep_id)].has_completed)
    }

    /// Select up to count padding URLs.
    ///
    /// Prefers image URLs followed by script, stylesheet, and font URLs and
    /// decides based on the the type information provided to the tracker.
    pub fn select_padding_urls(&self, count: usize) -> Vec<Url> {
        let not_only_priority = !self.dependencies.iter().any(|res| res.chaff_priority);

        let mut urls: Vec<(&String, Url)> = self.dependencies.iter()
            .filter(|res| not_only_priority || res.chaff_priority)
            .map(|res| (&res.resource_type, Url::parse((*res.url).into()).unwrap()))
            .collect();

        urls.sort_by_key(|(res_type, _)| match res_type.as_str() {
            "Image" => 1,
            "Font" | "Stylesheet" | "Script" => 2,
            "Document" => 3,
            _ => 4,
        });

        urls.into_iter().take(count).map(|(_, url)| url).collect()
    }

    /// Select up to count padding URLs.
    ///
    /// Prefers padding URLs which have a large, known content length.
    /// resorts to selecting by type to break ties.
    pub fn select_padding_urls_by_size(&self, count: usize) -> Vec<ChaffResource> {
        let not_only_priority = !self.dependencies.iter().any(|res| res.chaff_priority);

        let mut urls: Vec<(&String, u64, Url)> = self.dependencies.iter()
            .filter(|res| not_only_priority || res.chaff_priority)
            .map(|res| (&res.resource_type, 
                        // Use 1 for None as unknown is better than a 0 content length
                        std::cmp::max(res.content_length.unwrap_or(1), res.data_length),
                        Url::parse((*res.url).into()).unwrap()))
            .collect();

        // Sorts in ascending order so the largest sizes are at the end of
        // the list. Reverse to take the largest sizes
        urls.sort_by_key(|(res_type, size, _)| match res_type.as_str() {
            "Image" => (*size, 4),
            "Font" | "Stylesheet" | "Script" => (*size, 3),
            "Document" => (*size, 2),
            _ => (*size, 1),
        });
        urls.into_iter().rev().take(count)
            .map(|(_, length, url)| ChaffResource{ url, length, headers: Vec::new() })
            .collect()
    }

    /// Return the number of URLs remaining to be collected
    pub fn remaining(&self) -> usize {
        self.dependencies.iter().filter(|x| !x.has_completed).count()
    }

    pub fn remaining_urls(&self) -> Vec<Url>  {
        self.dependencies.iter().filter(|x| !x.has_completed)
            .map(|res| Url::parse((*res.url).into()).unwrap())
            .collect()
    }

    /// Return the number of elements in the tracker
    pub fn len(&self) -> usize {
        self.dependencies.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::url;

    #[test]
    fn from_json() {
        let tracker = UrlDependencyTracker::from_json(
            Path::new("../tests/dep-graph.json"));
        assert_eq!(tracker.dependencies.len(), 16);
        assert!(tracker.dependencies[0].depends_on.is_empty());
        assert_eq!(tracker.dependencies[1].depends_on, [0, ]);
        assert_eq!(tracker.dependencies[15].depends_on, [0, 4, 12]);
    }

    fn create_tracker() -> UrlDependencyTracker {
        UrlDependencyTracker {
            dependencies: vec![
                Resource {
                    id: 0, url: "https://z.com".into(), resource_type: "Document".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![],
                    content_length: Some(5000), data_length: 0, chaff_priority: false
                },
                Resource {
                    id: 1, url: "https://a.z.com".into(), resource_type: "Script".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![0, ],
                    content_length: None, data_length: 0, chaff_priority: false
                },
                Resource {
                    id: 2, url: "https://b.z.com".into(), resource_type: "Script".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![0, 1],
                    content_length: Some(3000), data_length: 0, chaff_priority: false
                },
                Resource {
                    id: 3, url: "https://c.z.com".into(), resource_type: "Image".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![2, ],
                    content_length: Some(0), data_length: 0, chaff_priority: false
                }
            ]
        }
    }

    #[test]
    fn resource_downloaded_sets_completed() {
        let mut tracker = create_tracker();

        assert!(!tracker.dependencies[0].has_completed);
        assert!(!tracker.dependencies[1].has_completed);

        tracker.resource_downloaded(0);
        assert!(tracker.dependencies[0].has_completed);

        tracker.resource_downloaded(1);
        assert!(tracker.dependencies[1].has_completed);
    }

    #[test]
    fn is_downloadable_checks_dependencies() {
        let mut tracker = create_tracker();

        // This is downloadable since it has no dependencies
        assert!(tracker.is_downloadable(0));
        // These have unfulfilled deps
        assert!(!tracker.is_downloadable(1));
        assert!(!tracker.is_downloadable(2));
        assert!(!tracker.is_downloadable(3));

        tracker.resource_downloaded(0);
        assert!(tracker.is_downloadable(1));
        assert!(!tracker.is_downloadable(2));
        assert!(!tracker.is_downloadable(3));

        tracker.resource_downloaded(1);
        assert!(tracker.is_downloadable(2));
        assert!(!tracker.is_downloadable(3));
    }

    #[test]
    fn select_padding_url_sorts_by_type() {
        let tracker = create_tracker();
        assert_eq!(tracker.select_padding_urls(3), [
           url!("https://c.z.com"), url!("https://a.z.com"), url!("https://b.z.com")
        ]);
    }

    #[test]
    fn select_padding_url_sorts_by_size() {
        let tracker = create_tracker();
        assert_eq!(tracker.select_padding_urls_by_size(4), [
           ChaffResource::new(url!("https://z.com"), Vec::new(), 5000),
           ChaffResource::new(url!("https://b.z.com"), Vec::new(), 3000),
           ChaffResource::new(url!("https://a.z.com"), Vec::new(), 1),
           ChaffResource::new(url!("https://c.z.com"), Vec::new(), 0),
        ]);
    }

    #[test]
    fn select_padding_urls_priority() {
        let mut tracker = create_tracker();
        tracker.dependencies[1].chaff_priority = true;

        assert_eq!(tracker.select_padding_urls(2), [url!("https://a.z.com")]);
        assert_eq!(tracker.select_padding_urls_by_size(3), [
            ChaffResource::new(url!("https://a.z.com"), Vec::new(), 1)
        ]);
    }
}
