use std::fs::File;
use std::collections::HashSet;
use std::path::Path;
use std::{ error, io };

use url::Url;


fn _load_dependencies(reader: &mut impl io::Read) 
        -> Result<(Vec<Url>, Vec<(Url, Url)>), Box<dyn error::Error>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(reader);
    let mut urls = HashSet::new();
    let mut deps = Vec::new();

    for result in reader.records() {
        let result = result?;

        assert!(&result[0] != "", "First entry shouldnt be empty");
        let target = Url::parse(&result[0])?;
        urls.insert(target.clone());

        if &result[1] != "" {
            let depends_on = Url::parse(&result[1])?;
            urls.insert(depends_on.clone());
            deps.push((target, depends_on));
        }
    }

    let mut urls: Vec<Url> = urls.into_iter().collect();
    urls.sort();

    Ok((urls, deps))
}

pub fn load_dependencies(filename: &Path) 
       -> Result<(Vec<Url>, Vec<(Url, Url)>), Box<dyn error::Error>> {
    _load_dependencies(&mut File::open(filename)?)
}


#[derive(Debug, Default)]
pub struct UrlDependencyTracker {
    /// Dependency tuples of (url, dependency) 
    dependencies: Vec<(Url, Url)>,
}


impl UrlDependencyTracker {
    pub fn new(dependencies: &[(Url, Url)]) -> UrlDependencyTracker {
        UrlDependencyTracker { 
            dependencies: dependencies.to_vec(),
        }
    }

    /// Inform the manager that a resource has been downloaded.
    pub fn resource_downloaded(&mut self, url: &Url) {
        self.dependencies.retain(|(_, dep)| dep != url);
    }

    /// Return true iff the url has no outstanding dependencies
    #[allow(dead_code)]
    pub fn is_downloadable(&self, url: &Url) -> bool {
        for (target, _) in self.dependencies.iter() {
            if target == url {
                return false;
            }
        }
        true
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> UrlDependencyTracker {
        let url_deps = [
            (Url::parse("http://a.com/1.png").unwrap(),
            Url::parse("http://a.com").unwrap()),
            (Url::parse("http://a.com/2.png").unwrap(),
            Url::parse("http://a.com").unwrap()),
        ];

        UrlDependencyTracker::new(&url_deps)
    }

    #[test]
    fn test_is_downloadable() {
        let deps = create_manager();

        assert!(deps.is_downloadable(&Url::parse("http://a.com").unwrap()));
        assert!(deps.is_downloadable(&Url::parse("http://b.com").unwrap()));
        assert!(!deps.is_downloadable(&Url::parse("http://a.com/1.png").unwrap()));
        assert!(!deps.is_downloadable(&Url::parse("http://a.com/2.png").unwrap()));
    }

    #[test]
    fn test_request_complete() {
        let mut deps = create_manager();
        let target = Url::parse("http://a.com/1.png").unwrap();
        let dependency = Url::parse("http://a.com").unwrap();

        assert!(!deps.is_downloadable(&target));
        assert!(deps.is_downloadable(&dependency));
        deps.resource_downloaded(&dependency);
        assert!(deps.is_downloadable(&target));
    }

    #[test]
    fn test_load_dependencies() {
        let mut data = io::BufReader::new(
            "https://a.com,\n\
            https://b.com,\n\
            https://a.com/1.png,https://a.com\n\
            https://a.com/2.png,https://a.com\n".as_bytes());
        let expected_urls = 
            &["https://a.com", "https://a.com/1.png", "https://a.com/2.png", "https://b.com"]
            .iter().map(|x| Url::parse(x).unwrap()).collect::<Vec<Url>>();

        let expected_deps = 
            &[("https://a.com/1.png", "https://a.com"), 
              ("https://a.com/2.png", "https://a.com")]
            .iter().map(|(a, b)| (Url::parse(a).unwrap(), Url::parse(b).unwrap()))
            .collect::<Vec<(Url, Url)>>();

        let (urls, dependencies) = _load_dependencies(&mut data).unwrap();

        assert_eq!(&urls, expected_urls);
        assert_eq!(&dependencies, expected_deps);
    }
}