//! OSV wire format, and the pure mapping from it into the domain.
//!
//! Every type in here is private to the [`crate::osv`] module. The rest of the
//! crate never sees OSV's nested JSON — it sees [`Advisory`]. That boundary is
//! the one genuinely good abstraction in the reference implementation and it is
//! kept.
//!
//! The mapping is a pure function, so it is tested against recorded API
//! responses without touching the network.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::domain::{
    Advisory, AffectedInterval, AffectedRange, Bound, Ecosystem, Package, Severity,
};

// ─── Request ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(super) struct BatchRequest {
    pub queries: Vec<PackageQuery>,
}

#[derive(Debug, Serialize)]
pub(super) struct PackageQuery {
    pub package: QueryPackage,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub(super) struct QueryPackage {
    pub name: String,
    pub ecosystem: &'static str,
}

impl PackageQuery {
    pub fn new(package: &Package) -> PackageQuery {
        PackageQuery {
            package: QueryPackage {
                name: package.name.clone(),
                ecosystem: package.ecosystem.as_osv(),
            },
            version: package.version.to_string(),
        }
    }
}

// ─── Batch response ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct BatchResponse {
    #[serde(default)]
    pub results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchResult {
    #[serde(default)]
    pub vulns: Vec<VulnStub>,
}

#[derive(Debug, Deserialize)]
pub(super) struct VulnStub {
    pub id: String,
}

// ─── Vulnerability detail ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    /// Long-form advisory text (Markdown).
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// RFC 3339 publication timestamp, used to age the finding.
    #[serde(default)]
    pub published: Option<String>,
    /// Present only on retracted advisories. Acting on a withdrawn advisory
    /// wastes an engineer's afternoon, so these are dropped.
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    #[serde(default)]
    pub database_specific: Option<TopLevelDatabaseSpecific>,
    #[serde(default)]
    pub affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SeverityEntry {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub score: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TopLevelDatabaseSpecific {
    /// GitHub advisories put their severity word here. RustSec does not.
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Affected {
    #[serde(default)]
    pub package: Option<AffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ecosystem_specific: Option<EcosystemSpecific>,
    #[serde(default)]
    pub database_specific: Option<AffectedDatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AffectedPackage {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct EcosystemSpecific {
    #[serde(default)]
    pub affects: Option<Affects>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Affects {
    #[serde(default)]
    pub functions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AffectedDatabaseSpecific {
    /// RustSec marks unmaintained/yanked notices here. `null` is common, hence
    /// the double option collapse below.
    #[serde(default)]
    pub informational: Option<String>,
    /// RustSec also repeats the CVSS vector here on some entries.
    #[serde(default)]
    pub cvss: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Range {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// Exactly one field is populated per event.
#[derive(Debug, Deserialize)]
pub(super) struct Event {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
}

// ─── Mapping into the domain ────────────────────────────────────────────────

impl Vulnerability {
    /// Flattens the wire representation into an [`Advisory`] for one package.
    ///
    /// Takes the package because a single advisory can cover many packages
    /// across many ecosystems (GHSA routinely does). The reference
    /// implementation flat-mapped every `affected` entry together, so a Cargo
    /// package could inherit an npm package's version ranges. Here the entries
    /// are filtered to the package being asked about, first.
    ///
    /// Returns `None` for withdrawn advisories.
    pub fn to_advisory(&self, package: &Package) -> Option<Advisory> {
        if self.withdrawn.is_some() {
            return None;
        }

        let relevant: Vec<&Affected> = self
            .affected
            .iter()
            .filter(|a| a.matches(package))
            .collect();

        let mut intervals = Vec::new();
        let mut versions = Vec::new();
        let mut functions = Vec::new();
        let mut informational = None;
        let mut vectors: Vec<String> = self
            .severity
            .iter()
            .filter(|s| is_cvss_vector(s))
            .filter_map(|s| s.score.clone())
            .collect();

        for affected in relevant {
            for range in &affected.ranges {
                intervals.extend(range.to_intervals());
            }
            versions.extend(affected.versions.iter().filter_map(|v| parse_lenient(v)));

            if let Some(specific) = &affected.ecosystem_specific {
                if let Some(affects) = &specific.affects {
                    functions.extend(affects.functions.iter().cloned());
                }
            }

            if let Some(specific) = &affected.database_specific {
                if informational.is_none() {
                    informational = specific.informational.clone();
                }
                if let Some(cvss) = &specific.cvss {
                    vectors.push(cvss.clone());
                }
            }
        }

        functions.sort();
        functions.dedup();

        let database_word = self
            .database_specific
            .as_ref()
            .and_then(|d| d.severity.as_deref());

        Some(Advisory {
            id: self.id.clone(),
            aliases: self.aliases.clone(),
            summary: self.summary.clone(),
            details: self.details.clone(),
            age_days: self
                .published
                .as_deref()
                .and_then(crate::domain::days_since),
            severity: Severity::resolve(&vectors, database_word),
            informational,
            affected_functions: functions,
            affected: AffectedRange::new(intervals, versions),
            url: format!("https://osv.dev/vulnerability/{}", self.id),
        })
    }
}

impl Affected {
    /// Whether this entry describes the package we asked about.
    fn matches(&self, package: &Package) -> bool {
        let Some(reference) = &self.package else {
            // No package block: assume the advisory is single-package and
            // applies. Being permissive here only risks a false positive that
            // the version-range check below will usually reject anyway.
            return true;
        };

        let name_matches = reference
            .name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(&package.name));

        let ecosystem_matches = match reference.ecosystem.as_deref() {
            // OSV suffixes some ecosystems (e.g. "Debian:11"), so compare the
            // prefix before the colon.
            Some(eco) => {
                let base = eco.split(':').next().unwrap_or(eco);
                base.eq_ignore_ascii_case(package.ecosystem.as_osv())
                    || matches!(package.ecosystem, Ecosystem::CratesIo)
                        && base.eq_ignore_ascii_case("crates.io")
            }
            None => true,
        };

        name_matches && ecosystem_matches
    }
}

impl Range {
    /// Pairs the flat event list into intervals.
    ///
    /// OSV events are a sequence: an `introduced` opens an interval and the next
    /// `fixed` or `last_affected` closes it. `GIT` ranges are skipped because
    /// their events are commit hashes, not versions.
    fn to_intervals(&self) -> Vec<AffectedInterval> {
        if self.kind.as_deref() == Some("GIT") {
            return Vec::new();
        }

        let mut intervals = Vec::new();
        let mut open: Option<Version> = None;

        for event in &self.events {
            if let Some(raw) = &event.introduced {
                // An unclosed previous interval runs to infinity.
                if let Some(start) = open.take() {
                    intervals.push(AffectedInterval::new(start, Bound::Unbounded));
                }
                // OSV writes "0" for "from the beginning".
                open = Some(parse_lenient(raw).unwrap_or_else(|| Version::new(0, 0, 0)));
                continue;
            }

            if let Some(raw) = &event.fixed {
                if let Some(fixed) = parse_lenient(raw) {
                    let start = open.take().unwrap_or_else(|| Version::new(0, 0, 0));
                    intervals.push(AffectedInterval::new(start, Bound::Fixed(fixed)));
                }
                continue;
            }

            if let Some(raw) = &event.last_affected {
                if let Some(last) = parse_lenient(raw) {
                    let start = open.take().unwrap_or_else(|| Version::new(0, 0, 0));
                    intervals.push(AffectedInterval::new(start, Bound::LastAffected(last)));
                }
            }
        }

        if let Some(start) = open {
            intervals.push(AffectedInterval::new(start, Bound::Unbounded));
        }

        intervals
    }
}

fn is_cvss_vector(entry: &SeverityEntry) -> bool {
    entry.kind.as_deref().is_some_and(|k| k.starts_with("CVSS"))
}

/// Parses a version, tolerating the partial forms advisories use.
///
/// OSV range boundaries are not always strict semver: `"0"`, `"1.2"`, and
/// `"0.2.7-0"` all appear in real data. Padding missing components keeps the
/// comparison meaningful instead of discarding the boundary.
fn parse_lenient(raw: &str) -> Option<Version> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Ok(version) = Version::parse(raw) {
        return Some(version);
    }

    // Split off any pre-release/build metadata before padding the core.
    let (core, suffix) = match raw.find(['-', '+']) {
        Some(index) => (&raw[..index], &raw[index..]),
        None => (raw, ""),
    };

    let mut components = core.split('.');
    let major = components.next()?.parse::<u64>().ok()?;
    let minor = components.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = components.next().unwrap_or("0").parse::<u64>().ok()?;

    Version::parse(&format!("{major}.{minor}.{patch}{suffix}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Provenance, Rating};

    fn package(name: &str, version: &str) -> Package {
        Package::new(Ecosystem::CratesIo, name, Version::parse(version).unwrap())
    }

    fn parse(json: &str) -> Vulnerability {
        serde_json::from_str(json).expect("fixture should deserialize")
    }

    /// Trimmed but structurally faithful copy of the real OSV response, kept
    /// verbatim in the shape the API returns.
    const RUSTSEC_2020_0071: &str = r#"{
      "id": "RUSTSEC-2020-0071",
      "summary": "Potential segfault in the time crate",
      "aliases": ["CVE-2020-26235", "GHSA-wcg3-cvx6-7396"],
      "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
      ],
      "database_specific": {"license": "CC0-1.0"},
      "affected": [
        {
          "package": {"name": "time", "ecosystem": "crates.io"},
          "ranges": [
            {
              "type": "SEMVER",
              "events": [
                {"introduced": "0.0.0-0"}, {"fixed": "0.2.0"},
                {"introduced": "0.2.1-0"}, {"fixed": "0.2.1"},
                {"introduced": "0.2.7-0"}, {"fixed": "0.2.23"}
              ]
            }
          ],
          "ecosystem_specific": {
            "affects": {"functions": ["time::at", "time::now"], "arch": []}
          },
          "database_specific": {"informational": null, "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        }
      ]
    }"#;

    #[test]
    fn maps_real_rustsec_advisory() {
        let advisory = parse(RUSTSEC_2020_0071)
            .to_advisory(&package("time", "0.1.44"))
            .expect("not withdrawn");

        assert_eq!(advisory.id, "RUSTSEC-2020-0071");
        assert!(advisory.aliases.contains(&"CVE-2020-26235".to_string()));
        assert_eq!(
            advisory.url,
            "https://osv.dev/vulnerability/RUSTSEC-2020-0071"
        );

        // Severity computed from the vector, not left unknown as before.
        assert_eq!(advisory.severity.rating, Rating::Medium);
        assert_eq!(advisory.severity.score, Some(6.2));
        assert_eq!(advisory.severity.provenance, Provenance::Cvss3);

        // Reachability evidence carried through.
        assert_eq!(advisory.affected_functions, vec!["time::at", "time::now"]);
        assert!(!advisory.is_informational());
    }

    #[test]
    fn resolves_the_correct_fix_not_the_first_one() {
        let wire = parse(RUSTSEC_2020_0071);

        // The regression that motivated this rewrite: 0.2.7 must map to 0.2.23.
        let advisory = wire.to_advisory(&package("time", "0.2.7")).unwrap();
        let installed = Version::parse("0.2.7").unwrap();
        assert!(advisory.affected.contains(&installed));
        assert_eq!(
            advisory.affected.fix_for(&installed),
            Some(&Version::parse("0.2.23").unwrap()),
            "must not report the advisory's first `fixed` event"
        );

        // And a 0.1.x user gets their own interval's bound.
        let installed = Version::parse("0.1.44").unwrap();
        assert_eq!(
            advisory.affected.fix_for(&installed),
            Some(&Version::parse("0.2.0").unwrap())
        );
    }

    #[test]
    fn ignores_affected_entries_for_other_packages() {
        // A GHSA covering both an npm and a Cargo package. The Cargo package
        // must not inherit the npm ranges.
        let json = r#"{
          "id": "GHSA-multi",
          "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
          "affected": [
            {
              "package": {"name": "lodash", "ecosystem": "npm"},
              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]
            },
            {
              "package": {"name": "mycrate", "ecosystem": "crates.io"},
              "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}]}]
            }
          ]
        }"#;

        let advisory = parse(json)
            .to_advisory(&package("mycrate", "1.0.1"))
            .unwrap();
        assert_eq!(advisory.affected.intervals.len(), 1);
        assert_eq!(
            advisory.affected.fix_for(&Version::parse("1.0.1").unwrap()),
            Some(&Version::parse("1.0.5").unwrap())
        );
        // The npm range would have claimed everything below 99.0.0.
        assert!(!advisory
            .affected
            .contains(&Version::parse("50.0.0").unwrap()));
    }

    #[test]
    fn drops_withdrawn_advisories() {
        let json = r#"{
          "id": "RUSTSEC-withdrawn",
          "withdrawn": "2023-01-01T00:00:00Z",
          "affected": [{"package": {"name": "x", "ecosystem": "crates.io"}}]
        }"#;
        assert!(parse(json).to_advisory(&package("x", "1.0.0")).is_none());
    }

    #[test]
    fn detects_informational_notices() {
        let json = r#"{
          "id": "RUSTSEC-2020-0036",
          "summary": "failure is unmaintained",
          "affected": [
            {
              "package": {"name": "failure", "ecosystem": "crates.io"},
              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
              "database_specific": {"informational": "unmaintained"}
            }
          ]
        }"#;
        let advisory = parse(json)
            .to_advisory(&package("failure", "0.1.8"))
            .unwrap();
        assert!(advisory.is_informational());
        assert_eq!(advisory.informational.as_deref(), Some("unmaintained"));
    }

    #[test]
    fn uses_github_severity_word_when_no_vector_is_present() {
        let json = r#"{
          "id": "GHSA-word-only",
          "database_specific": {"severity": "MODERATE"},
          "affected": [{"package": {"name": "x", "ecosystem": "crates.io"}}]
        }"#;
        let advisory = parse(json).to_advisory(&package("x", "1.0.0")).unwrap();
        assert_eq!(advisory.severity.rating, Rating::Medium);
        assert_eq!(advisory.severity.provenance, Provenance::Database);
    }

    #[test]
    fn skips_git_ranges() {
        let json = r#"{
          "id": "X",
          "affected": [
            {
              "package": {"name": "x", "ecosystem": "crates.io"},
              "ranges": [
                {"type": "GIT", "events": [{"introduced": "abc123def"}, {"fixed": "fff999"}]}
              ]
            }
          ]
        }"#;
        let advisory = parse(json).to_advisory(&package("x", "1.0.0")).unwrap();
        assert!(advisory.affected.intervals.is_empty());
    }

    #[test]
    fn handles_unclosed_and_last_affected_events() {
        let json = r#"{
          "id": "X",
          "affected": [
            {
              "package": {"name": "x", "ecosystem": "crates.io"},
              "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.2"}]},
                {"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}
              ]
            }
          ]
        }"#;
        let advisory = parse(json).to_advisory(&package("x", "1.0.0")).unwrap();

        assert!(advisory
            .affected
            .contains(&Version::parse("1.4.2").unwrap()));
        assert!(!advisory
            .affected
            .contains(&Version::parse("1.4.3").unwrap()));
        // Unbounded interval from 2.0.0 onwards.
        assert!(advisory
            .affected
            .contains(&Version::parse("9.9.9").unwrap()));
        // Neither bound is a fix.
        assert_eq!(
            advisory.affected.fix_for(&Version::parse("1.2.0").unwrap()),
            None
        );
    }

    #[test]
    fn parses_partial_version_boundaries() {
        assert_eq!(parse_lenient("0"), Some(Version::new(0, 0, 0)));
        assert_eq!(parse_lenient("1.2"), Some(Version::new(1, 2, 0)));
        assert_eq!(parse_lenient("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(
            parse_lenient("0.2.7-0"),
            Some(Version::parse("0.2.7-0").unwrap())
        );
        // A pre-release sorts below its release, which the interval math needs.
        assert!(parse_lenient("0.2.7-0").unwrap() < Version::parse("0.2.7").unwrap());
        assert_eq!(parse_lenient(""), None);
        assert_eq!(parse_lenient("not-a-version"), None);
    }

    #[test]
    fn deserializes_unknown_fields_without_failing() {
        // OSV adds fields over time; the client must not break when it does.
        let json = r#"{
          "id": "X",
          "brand_new_field": {"nested": [1, 2, 3]},
          "affected": [{"package": {"name": "x", "ecosystem": "crates.io"}, "future": true}]
        }"#;
        assert!(parse(json).to_advisory(&package("x", "1.0.0")).is_some());
    }
}
