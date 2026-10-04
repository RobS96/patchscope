//! HTTP for the research sources: one trait so tests run on recorded
//! responses, a real client (TLS 1.3/1.2 via rustls + aws-lc-rs, OS trust
//! store, bounded timeouts and body sizes) and an on-disk cache that also
//! powers offline mode.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
    fn post_json(&self, url: &str, body: &str) -> Result<Vec<u8>, String>;
}

/// Largest response accepted (the CISA KEV catalogue is ~2 MB).
const MAX_BODY: u64 = 64 * 1024 * 1024;

pub struct UreqClient {
    agent: ureq::Agent,
}

impl UreqClient {
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(Self::roots())
            .unversioned_rustls_crypto_provider(provider)
            .build();
        let config = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(Duration::from_secs(90)))
            .user_agent(concat!(
                "patchscope/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/RobS96/patchscope)"
            ))
            .build();
        UreqClient { agent: config.into() }
    }

    /// The operating system's trust store, unless `SSL_CERT_FILE` names a
    /// PEM bundle (the OpenSSL convention, used by proxies and CI images
    /// whose CA is not in the OS store).
    fn roots() -> ureq::tls::RootCerts {
        let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
            return ureq::tls::RootCerts::PlatformVerifier;
        };
        let certs: Vec<ureq::tls::Certificate<'static>> = std::fs::read(&path)
            .map(|pem| {
                ureq::tls::parse_pem(&pem)
                    .filter_map(|item| match item {
                        Ok(ureq::tls::PemItem::Certificate(c)) => Some(c.to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if certs.is_empty() {
            ureq::tls::RootCerts::PlatformVerifier
        } else {
            ureq::tls::RootCerts::Specific(Arc::new(certs))
        }
    }

    fn read(resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>, url: &str) -> Result<Vec<u8>, String> {
        let mut resp = resp.map_err(|e| format!("{url}: {e}"))?;
        resp.body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| format!("{url}: {e}"))
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        Self::read(self.agent.get(url).call(), url)
    }
    fn post_json(&self, url: &str, body: &str) -> Result<Vec<u8>, String> {
        Self::read(
            self.agent
                .post(url)
                .header("Content-Type", "application/json")
                .send(body.as_bytes()),
            url,
        )
    }
}

/// FNV-1a: a stable cache key across Rust versions and platforms.
fn fnv1a(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in p.bytes().chain(std::iter::once(0)) {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

/// Caches responses on disk. Fresh entries are served without a request;
/// in offline mode any cached entry is served and nothing is fetched, and
/// the age of the oldest entry served is kept for the report.
pub struct CachedHttp<'a> {
    inner: &'a dyn HttpClient,
    dir: Option<PathBuf>,
    ttl: Duration,
    offline: bool,
    /// Offline: when the oldest entry served since the last
    /// [`CachedHttp::take_offline_as_of`] was written.
    oldest_served: Mutex<Option<SystemTime>>,
}

impl<'a> CachedHttp<'a> {
    pub fn new(inner: &'a dyn HttpClient, dir: Option<PathBuf>, ttl: Duration, offline: bool) -> Self {
        if let Some(d) = &dir {
            let _ = std::fs::create_dir_all(d);
        }
        CachedHttp {
            inner,
            dir,
            ttl,
            offline,
            oldest_served: Mutex::new(None),
        }
    }

    /// Offline only: the Unix time of the oldest cached response served
    /// since the last call (None online, or when nothing was served).
    pub fn take_offline_as_of(&self) -> Option<u64> {
        self.oldest_served
            .lock()
            .expect("lock")
            .take()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    }

    fn cached(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.dir.as_ref()?.join(key);
        let meta = std::fs::metadata(&path).ok()?;
        let modified = meta.modified().ok();
        let fresh = modified
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age < self.ttl);
        let body = (fresh || self.offline).then(|| std::fs::read(&path).ok()).flatten()?;
        if self.offline
            && let Some(m) = modified
        {
            let mut oldest = self.oldest_served.lock().expect("lock");
            if oldest.is_none_or(|o| m < o) {
                *oldest = Some(m);
            }
        }
        Some(body)
    }

    fn store(&self, key: &str, body: &[u8]) {
        if let Some(d) = &self.dir {
            // Write then rename, so a crash never leaves a truncated entry.
            let tmp = d.join(format!("{key}.tmp{}", std::process::id()));
            if std::fs::write(&tmp, body).is_ok() {
                let _ = std::fs::rename(&tmp, d.join(key));
            }
        }
    }

    fn through(&self, key: String, fetch: impl FnOnce() -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
        if let Some(b) = self.cached(&key) {
            return Ok(b);
        }
        if self.offline {
            return Err("offline and not cached".into());
        }
        let body = fetch()?;
        self.store(&key, &body);
        Ok(body)
    }
}

impl HttpClient for CachedHttp<'_> {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.through(fnv1a(&["GET", url]), || self.inner.get(url))
    }
    fn post_json(&self, url: &str, body: &str) -> Result<Vec<u8>, String> {
        self.through(fnv1a(&["POST", url, body]), || self.inner.post_json(url, body))
    }
}

/// Recorded responses for tests. URLs are matched by prefix, longest first,
/// so one entry can answer a family of requests.
#[derive(Default)]
pub struct FakeHttp {
    routes: Vec<(String, Result<String, String>)>,
    pub requests: Mutex<Vec<String>>,
    posts: HashMap<String, String>,
    /// (url, text the body must contain, answer), checked before `posts`.
    posts_when: Vec<(String, String, Result<String, String>)>,
}

impl FakeHttp {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn route(mut self, url_prefix: &str, body: &str) -> Self {
        self.routes.push((url_prefix.to_string(), Ok(body.to_string())));
        self.routes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        self
    }
    pub fn fail(mut self, url_prefix: &str, err: &str) -> Self {
        self.routes.push((url_prefix.to_string(), Err(err.to_string())));
        self.routes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        self
    }
    /// Answer a POST to `url` with `body`.
    pub fn post_route(mut self, url: &str, body: &str) -> Self {
        self.posts.insert(url.to_string(), body.to_string());
        self
    }
    /// Answer a POST to `url` whose body contains `needle` with `body`
    /// (first match wins; checked before [`FakeHttp::post_route`]).
    pub fn post_route_when(mut self, url: &str, needle: &str, body: &str) -> Self {
        self.posts_when
            .push((url.to_string(), needle.to_string(), Ok(body.to_string())));
        self
    }
    /// Fail a POST to `url` whose body contains `needle`.
    pub fn post_fail_when(mut self, url: &str, needle: &str, err: &str) -> Self {
        self.posts_when
            .push((url.to_string(), needle.to_string(), Err(err.to_string())));
        self
    }
    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("lock").len()
    }
}

impl HttpClient for FakeHttp {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.requests.lock().expect("lock").push(format!("GET {url}"));
        for (p, r) in &self.routes {
            if url.starts_with(p.as_str()) {
                return r.clone().map(String::into_bytes);
            }
        }
        Err(format!("FakeHttp: no route for {url}"))
    }
    fn post_json(&self, url: &str, body: &str) -> Result<Vec<u8>, String> {
        self.requests.lock().expect("lock").push(format!("POST {url} {body}"));
        if let Some((_, _, r)) = self
            .posts_when
            .iter()
            .find(|(u, n, _)| u == url && body.contains(n.as_str()))
        {
            return r.clone().map(String::into_bytes);
        }
        self.posts
            .get(url)
            .map(|b| b.clone().into_bytes())
            .ok_or_else(|| format!("FakeHttp: no POST route for {url}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_serves_fresh_entries_and_offline_mode() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeHttp::new().route("https://x/", "hello");
        let c = CachedHttp::new(&fake, Some(dir.path().to_path_buf()), Duration::from_secs(3600), false);
        assert_eq!(c.get("https://x/a").unwrap(), b"hello");
        assert_eq!(c.get("https://x/a").unwrap(), b"hello");
        assert_eq!(fake.request_count(), 1, "second request is served from cache");

        let empty = FakeHttp::new();
        let off = CachedHttp::new(&empty, Some(dir.path().to_path_buf()), Duration::ZERO, true);
        assert_eq!(
            off.get("https://x/a").unwrap(),
            b"hello",
            "offline serves stale entries"
        );
        assert!(off.get("https://x/b").is_err());
        assert_eq!(empty.request_count(), 0, "offline never fetches");
        let as_of = off.take_offline_as_of().expect("offline remembers how old its data is");
        assert!(as_of <= crate::util::unix_now() && as_of + 60 > crate::util::unix_now());
        assert_eq!(off.take_offline_as_of(), None, "taken");
        assert_eq!(c.take_offline_as_of(), None, "online: not tracked");
    }

    #[test]
    fn cache_keys_differ_by_body() {
        assert_ne!(fnv1a(&["POST", "u", "a"]), fnv1a(&["POST", "u", "b"]));
        assert_ne!(fnv1a(&["ab", "c"]), fnv1a(&["a", "bc"]));
    }

    #[test]
    fn fake_routes_by_longest_prefix() {
        let f = FakeHttp::new()
            .route("https://a/", "short")
            .route("https://a/b/", "long");
        assert_eq!(f.get("https://a/b/c").unwrap(), b"long");
        assert_eq!(f.get("https://a/x").unwrap(), b"short");
    }
}
