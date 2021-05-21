use std::fs::File;
use std::path::Path;
use std::io::BufReader;
use serde_json;
use serde::Deserialize;
use url::Url;


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
                has_completed: false,
                depends_on: Vec::new(),
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
        let mut urls: Vec<(&String, Url)> = self.dependencies.iter()
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
                },
                Resource {
                    id: 1, url: "https://a.z.com".into(), resource_type: "Script".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![0, ],
                },
                Resource {
                    id: 2, url: "https://b.z.com".into(), resource_type: "Script".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![0, 1],
                },
                Resource {
                    id: 3, url: "https://c.z.com".into(), resource_type: "Image".into(),
                    known_to_be_valid: true, has_completed: false, depends_on: vec![2, ],
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
}
