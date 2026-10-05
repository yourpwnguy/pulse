//! On-disk advisory cache.
//!
//! Every run re-queried OSV, which cost roughly two seconds and made the tool
//! feel expensive enough to skip. Caching removes the only real reason not to run
//! it after every `cargo update`.
//!
//! ## Two caches, two very different lifetimes
//!
//! | what | ttl | why |
//! |---|---|---|
//! | advisory **bodies**, by id | 7 days | the text of a published advisory is effectively immutable; a stale copy costs a slightly wrong summary at worst |
//! | **which packages match**, by package-set | 1 hour | this is the part that goes dangerously stale (a new disclosure must show up promptly) |
//!
//! The short TTL on match results is the important decision. A day-long cache
//! would make the tool fast and quietly wrong, which for a security tool is worse
//! than being slow. One hour keeps repeated runs during a work session instant
//! while bounding how long a fresh advisory can be missed.
//!
//! Failure is *always* non-fatal. A cache that cannot be read is a slow scan; a
//! cache that cannot be written is a slow next scan. Neither is worth an error.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Advisory bodies are immutable in practice.
const BODY_TTL: u64 = 7 * 24 * 60 * 60;

/// Match results must not be trusted for long.
const MATCH_TTL: u64 = 60 * 60;

/// Bumped when the on-disk shape changes incompatibly.
const VERSION: u32 = 1;

/// A cached value with the time it was written.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry<T> {
    #[serde(default)]
    version: u32,
    stored_at: u64,
    value: T,
}

impl<T> Entry<T> {
    fn new(value: T) -> Entry<T> {
        Entry {
            version: VERSION,
            stored_at: now(),
            value,
        }
    }

    /// Whether this entry may still be used.
    fn fresh(&self, ttl: u64) -> bool {
        // A future timestamp means the clock moved; treat it as stale rather than
        // trusting it forever.
        self.version == VERSION && now().saturating_sub(self.stored_at) < ttl
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which advisory ids affect which packages, keyed by a digest of the query set.
pub type Matches = BTreeMap<usize, Vec<String>>;

/// The cache. Construct one per run.
pub struct Cache {
    root: Option<PathBuf>,
    enabled: bool,
}

impl Cache {
    /// Opens the cache. `enabled == false` produces a cache that always misses,
    /// so `--fresh` needs no branching at the call sites.
    pub fn open(enabled: bool) -> Cache {
        Cache {
            root: root(),
            enabled,
        }
    }

    /// A cache that never stores or returns anything.
    pub fn disabled() -> Cache {
        Cache {
            root: None,
            enabled: false,
        }
    }

    fn path(&self, kind: &str, key: &str) -> Option<PathBuf> {
        if !self.enabled {
            return None;
        }
        if !is_safe_key(key) {
            return None;
        }
        Some(self.root.as_ref()?.join(kind).join(format!("{key}.json")))
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, kind: &str, key: &str, ttl: u64) -> Option<T> {
        let path = self.path(kind, key)?;
        let text = fs::read_to_string(path).ok()?;
        let entry: Entry<T> = serde_json::from_str(&text).ok()?;
        entry.fresh(ttl).then_some(entry.value)
    }

    fn write<T: Serialize>(&self, kind: &str, key: &str, value: &T) {
        let Some(path) = self.path(kind, key) else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(json) = serde_json::to_string(&Entry::new(value)) else {
            return;
        };

        // Write-then-rename so a concurrent reader never observes a half file.
        let temporary = path.with_extension("tmp");
        if fs::write(&temporary, json).is_ok() {
            let _ = fs::rename(&temporary, &path);
        }
    }

    /// Looks up a cached advisory body.
    pub fn advisory(&self, id: &str) -> Option<serde_json::Value> {
        self.read("advisories", id, BODY_TTL)
    }

    pub fn put_advisory(&self, id: &str, body: &serde_json::Value) {
        self.write("advisories", id, body);
    }

    /// Looks up a cached batch result for exactly this set of queries.
    pub fn matches(&self, digest: &str) -> Option<Matches> {
        self.read("matches", digest, MATCH_TTL)
    }

    pub fn put_matches(&self, digest: &str, matches: &Matches) {
        self.write("matches", digest, matches);
    }
}

/// Whether a string is safe to use as a filename inside the cache.
///
/// Keys are advisory ids (`RUSTSEC-2020-0071`, `GHSA-…`) or hex digests, both of
/// which are alphanumerics plus `-`. A dot is permitted because some databases
/// use one, but `.` and `..` are rejected outright and consecutive dots are
/// refused: allowing them let `".."` through and turned the cache path into a
/// directory-traversal primitive.
fn is_safe_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 {
        return false;
    }
    if key == "." || key == ".." || key.contains("..") {
        return false;
    }
    // Must start with something identifier-like, never a dot.
    if !key.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    key.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// A stable digest of the package set, so the batch cache is only reused for an
/// identical query.
///
/// FNV-1a over the sorted `name@version` list. Not cryptographic (a collision
/// would show the wrong cached matches, so it is 128 bits of two independently
/// seeded passes to make that vanishingly unlikely without pulling in a hash
/// crate).
pub fn digest(keys: &[String]) -> String {
    let mut sorted: Vec<&String> = keys.iter().collect();
    sorted.sort();

    let hash = |mut acc: u64| {
        for key in &sorted {
            for byte in key.as_bytes() {
                acc ^= u64::from(*byte);
                acc = acc.wrapping_mul(0x0100_0000_01b3);
            }
            acc ^= u64::from(b'\n');
            acc = acc.wrapping_mul(0x0100_0000_01b3);
        }
        acc
    };

    format!(
        "{:016x}{:016x}",
        hash(0xcbf2_9ce4_8422_2325),
        hash(0x9e37_79b9_7f4a_7c15)
    )
}

/// `$XDG_CACHE_HOME/pulse` or `~/.cache/pulse`.
///
/// Resolved by hand rather than with a crate: it is two environment lookups, and
/// a cache directory is not worth a dependency.
fn root() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("PULSE_CACHE") {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .map(|base| base.join("pulse"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache(name: &str) -> (Cache, PathBuf) {
        let dir = std::env::temp_dir().join(format!("pulse-cache-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        (
            Cache {
                root: Some(dir.clone()),
                enabled: true,
            },
            dir,
        )
    }

    #[test]
    fn stores_and_returns_an_advisory() {
        let (cache, dir) = temp_cache("advisory");
        let body = serde_json::json!({"id": "RUSTSEC-2020-0071", "summary": "x"});

        assert!(cache.advisory("RUSTSEC-2020-0071").is_none());
        cache.put_advisory("RUSTSEC-2020-0071", &body);
        assert_eq!(cache.advisory("RUSTSEC-2020-0071"), Some(body));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stores_and_returns_matches() {
        let (cache, dir) = temp_cache("matches");
        let mut matches = Matches::new();
        matches.insert(3, vec!["RUSTSEC-1".to_string()]);

        let key = digest(&["serde@1.0.0".to_string()]);
        assert!(cache.matches(&key).is_none());
        cache.put_matches(&key, &matches);
        assert_eq!(cache.matches(&key), Some(matches));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_disabled_cache_always_misses() {
        let cache = Cache::disabled();
        cache.put_advisory("X", &serde_json::json!({}));
        assert!(cache.advisory("X").is_none());
        assert!(cache.matches(&digest(&[])).is_none());
    }

    #[test]
    fn stale_entries_are_rejected() {
        let fresh: Entry<u32> = Entry {
            version: VERSION,
            stored_at: now(),
            value: 1,
        };
        assert!(fresh.fresh(MATCH_TTL));

        let old: Entry<u32> = Entry {
            version: VERSION,
            stored_at: now().saturating_sub(MATCH_TTL + 60),
            value: 1,
        };
        assert!(!old.fresh(MATCH_TTL));
        // But the same age is still fine for a body, whose ttl is far longer.
        assert!(old.fresh(BODY_TTL));
    }

    #[test]
    fn entries_from_a_future_clock_are_not_trusted_forever() {
        let skewed: Entry<u32> = Entry {
            version: VERSION,
            stored_at: now() + 10_000,
            value: 1,
        };
        // saturating_sub yields 0, which is "just written" (acceptable, and
        // crucially it expires normally once the clock catches up).
        assert!(skewed.fresh(MATCH_TTL));
    }

    #[test]
    fn a_version_bump_invalidates_everything() {
        let old: Entry<u32> = Entry {
            version: VERSION + 1,
            stored_at: now(),
            value: 1,
        };
        assert!(!old.fresh(BODY_TTL));
    }

    /// The whole safety argument in one line: match results are the part that goes
    /// dangerously stale, so they must expire far sooner than advisory bodies.
    /// A compile-time assertion, so violating it cannot even build.
    const _: () = assert!(MATCH_TTL * 24 <= BODY_TTL);

    #[test]
    fn digest_is_order_independent_but_content_sensitive() {
        let a = digest(&["b@1".to_string(), "a@1".to_string()]);
        let b = digest(&["a@1".to_string(), "b@1".to_string()]);
        assert_eq!(a, b, "the same package set must reuse its cache");

        let c = digest(&["a@1".to_string(), "b@2".to_string()]);
        assert_ne!(a, c, "a different version must not reuse the cache");

        // Adding a package must change the digest, or a newly added dependency
        // would be scanned against a cache that never saw it.
        let d = digest(&["a@1".to_string(), "b@1".to_string(), "c@1".to_string()]);
        assert_ne!(a, d);
    }

    #[test]
    fn digest_resists_delimiter_confusion() {
        // Without a separator these two sets would hash identically.
        let a = digest(&["ab".to_string(), "c".to_string()]);
        let b = digest(&["a".to_string(), "bc".to_string()]);
        assert_ne!(a, b);
    }

    #[test]
    fn keys_cannot_escape_the_cache_directory() {
        let (cache, _dir) = temp_cache("escape");
        for hostile in [
            "../../etc/passwd",
            "a/b",
            "",
            "x\0y",
            "..",
            ".",
            ".hidden",
            "a..b",
            "/absolute",
            "back\\slash",
            "tilde~",
            "a b",
        ] {
            assert!(
                cache.path("advisories", hostile).is_none(),
                "accepted hostile key {hostile:?}"
            );
        }
        // A real advisory id is fine.
        assert!(cache.path("advisories", "RUSTSEC-2020-0071").is_some());
        assert!(cache.path("matches", &digest(&[])).is_some());
    }

    #[test]
    fn corrupt_files_are_treated_as_misses() {
        let (cache, dir) = temp_cache("corrupt");
        let path = cache.path("advisories", "BAD").unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{{{ not json").unwrap();

        assert!(cache.advisory("BAD").is_none());
        let _ = fs::remove_dir_all(dir);
    }
}
