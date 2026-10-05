//! The OSV client: the crate's only network I/O.
//!
//! Deliberately thin. It batches queries, fetches details, and hands back
//! domain values; it makes no decisions about severity, fixes, or priority.
//! Everything worth testing lives in [`wire`] and [`crate::triage`], which are
//! pure.
//!
//! Because this module is the only impure part of the pipeline, no trait is
//! needed to make the rest of the program testable — the pure functions can be
//! called with hand-built values directly. That is why v0.1.0 has no
//! `AdvisorySource` trait with exactly one implementation.

pub mod cache;
mod wire;

use std::collections::BTreeMap;

use crate::domain::{Advisory, Package};
use crate::error::{Error, Result};
use crate::render::{Reporter, Stage};

use cache::Cache;
use wire::{BatchRequest, BatchResponse, PackageQuery, Vulnerability};

const BATCH_ENDPOINT: &str = "https://api.osv.dev/v1/querybatch";
const VULN_ENDPOINT: &str = "https://api.osv.dev/v1/vulns";

/// OSV caps `querybatch` at 1000 queries per request.
const MAX_BATCH: usize = 1000;

/// Advisories affecting the scanned packages, keyed by package.
pub type Advisories = BTreeMap<Package, Vec<Advisory>>;

/// A configured OSV client.
pub struct Client {
    agent: ureq::Agent,
    cache: Cache,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(true)
    }
}

impl Client {
    /// `cached == false` forces every lookup to hit the network (`--fresh`).
    pub fn new(cached: bool) -> Client {
        Client {
            cache: Cache::open(cached),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(std::time::Duration::from_secs(10))
                .timeout_read(std::time::Duration::from_secs(30))
                .user_agent(concat!("pulse/", env!("CARGO_PKG_VERSION")))
                .build(),
        }
    }

    /// Looks up every advisory affecting the given packages.
    ///
    /// Two phases, because OSV's batch endpoint returns identifiers only:
    /// one batched call per 1000 packages to find *which* packages are hit,
    /// then one detail fetch per *unique* advisory. Real trees hit a handful of
    /// distinct advisories no matter how many packages they contain, so the
    /// detail fetches stay in the single digits.
    pub fn advisories(&self, packages: &[Package], reporter: &Reporter) -> Result<Advisories> {
        if packages.is_empty() {
            return Ok(Advisories::new());
        }

        reporter.begin(Stage::Query);

        // The batch cache is keyed on the exact package set, so it is only reused
        // for an identical query. Its ttl is deliberately short — see `cache`.
        let keys: Vec<String> = packages
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        let digest = cache::digest(&keys);

        let hits = match self.cache.matches(&digest) {
            Some(cached) => {
                reporter.detail("cached · nothing re-queried");
                cached
            }
            None => {
                reporter.detail(format!("POST /v1/querybatch · {} queries", packages.len()));
                let fresh = self.find_advisory_ids(packages)?;
                self.cache.put_matches(&digest, &fresh);
                fresh
            }
        };
        let matched: usize = hits.values().map(Vec::len).sum();
        reporter.detail(format!("{matched} advisories matched"));
        reporter.finish(
            Stage::Query,
            format!(
                "{} {} matched",
                matched,
                if matched == 1 {
                    "advisory"
                } else {
                    "advisories"
                }
            ),
        );
        if hits.is_empty() {
            return Ok(Advisories::new());
        }

        // Fetch each advisory once, however many packages it affects.
        let mut details: BTreeMap<String, Vulnerability> = BTreeMap::new();
        let mut unique_ids: Vec<&String> = hits.values().flatten().collect();
        unique_ids.sort();
        unique_ids.dedup();

        // Now the size of the remaining work is known, so the bar can switch from
        // sweeping to filling.
        reporter.begin(Stage::Fetch);
        reporter.total(unique_ids.len());
        let fetch_total = unique_ids.len();

        for id in unique_ids {
            reporter.detail(id.clone());
            match self.load(id) {
                Ok(vulnerability) => {
                    details.insert(id.clone(), vulnerability);
                }
                // One unreachable advisory must not void an otherwise complete
                // scan, but the omission has to be visible: a silent gap in a
                // security report is a lie.
                Err(error) => {
                    eprintln!("pulse: warning: skipping {id}: {error}");
                }
            }
            reporter.tick();
        }
        reporter.finish(Stage::Fetch, format!("{fetch_total} fetched"));
        reporter.dwell();

        let mut advisories = Advisories::new();
        for (index, ids) in hits {
            let package = &packages[index];
            let mut matched: Vec<Advisory> = ids
                .iter()
                .filter_map(|id| details.get(id))
                .filter_map(|vulnerability| vulnerability.to_advisory(package))
                // OSV already filtered by version, but we re-check locally so
                // that a mis-parsed range shows up as a missing finding rather
                // than a confidently wrong one.
                .filter(|advisory| {
                    advisory.affected.intervals.is_empty()
                        && advisory.affected.versions.is_empty()
                        || advisory.affected.contains(&package.version)
                })
                .collect();

            if matched.is_empty() {
                continue;
            }

            matched.sort_by(|a, b| a.id.cmp(&b.id));
            matched.dedup_by(|a, b| a.id == b.id);
            advisories.insert(package.clone(), matched);
        }

        Ok(advisories)
    }

    /// Phase one: which packages have advisories, and which ones.
    /// Keys are indices into `packages`.
    fn find_advisory_ids(&self, packages: &[Package]) -> Result<BTreeMap<usize, Vec<String>>> {
        let mut hits: BTreeMap<usize, Vec<String>> = BTreeMap::new();

        for (chunk_index, chunk) in packages.chunks(MAX_BATCH).enumerate() {
            let request = BatchRequest {
                queries: chunk.iter().map(PackageQuery::new).collect(),
            };

            let response: BatchResponse = self
                .agent
                .post(BATCH_ENDPOINT)
                .send_json(&request)
                .map_err(|e| Error::Advisory(format!("batch query failed: {e}")))?
                .into_json()
                .map_err(|e| Error::Advisory(format!("malformed batch response: {e}")))?;

            // Results are positional: results[i] answers queries[i].
            for (offset, result) in response.results.iter().enumerate() {
                if result.vulns.is_empty() {
                    continue;
                }
                let index = chunk_index * MAX_BATCH + offset;
                hits.entry(index)
                    .or_default()
                    .extend(result.vulns.iter().map(|v| v.id.clone()));
            }
        }

        Ok(hits)
    }

    /// Phase two: full detail for one advisory, from the cache when possible.
    ///
    /// Bodies are cached as raw JSON rather than as [`Vulnerability`] so that a
    /// change to our own wire structs cannot silently misread a cached file: serde
    /// re-parses it through exactly the same path a fresh response takes.
    fn load(&self, id: &str) -> Result<Vulnerability> {
        if let Some(body) = self.cache.advisory(id) {
            if let Ok(vulnerability) = serde_json::from_value(body) {
                return Ok(vulnerability);
            }
            // A body we can no longer parse is not worth keeping; fall through and
            // refetch it.
        }

        let body: serde_json::Value = self
            .agent
            .get(&format!("{VULN_ENDPOINT}/{id}"))
            .call()
            .map_err(|e| Error::Advisory(format!("{e}")))?
            .into_json()
            .map_err(|e| Error::Advisory(format!("malformed advisory: {e}")))?;

        self.cache.put_advisory(id, &body);
        serde_json::from_value(body)
            .map_err(|e| Error::Advisory(format!("malformed advisory: {e}")))
    }
}
