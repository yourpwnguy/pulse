//! Advisories and version ranges.
//!
//! The important type here is [`AffectedRange`], which fixes the reference
//! implementation's most dangerous bug. Given an OSV range like
//!
//! ```text
//! introduced 0.0.0-0, fixed 0.2.0, introduced 0.2.1-0, fixed 0.2.1, …,
//! introduced 0.2.7-0, fixed 0.2.23
//! ```
//!
//! (this is the real shape of RUSTSEC-2020-0071) the old code took the *first*
//! `fixed` event it could find and told the user to upgrade to `0.2.0`, which is
//! still vulnerable. Remediation advice that leaves you exploited is worse than
//! no advice, because you stop looking.
//!
//! Version ranges are a half-open interval sequence: a version is affected if it
//! falls in some `[introduced, fixed)`. The correct fix for an affected version
//! is the `fixed` bound of *the interval that version actually falls into*.

use semver::Version;
use serde::{Deserialize, Serialize};

use super::severity::Severity;

/// Where an affected interval stops.
///
/// OSV distinguishes these three cases and conflating them causes real errors:
/// `Fixed` means a patched release exists, `LastAffected` means the range has a
/// known upper bound but *no* patch, and `Unbounded` means every later version is
/// affected. Only `Fixed` licenses us to tell the user to upgrade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "bound", rename_all = "snake_case")]
pub enum Bound {
    /// Exclusive upper bound: this version and everything after it is patched.
    Fixed(Version),
    /// Inclusive upper bound with no known patch.
    LastAffected(Version),
    /// No upper bound recorded.
    Unbounded,
}

/// One affected version interval, `[introduced, end)` or `[introduced, end]`
/// depending on the [`Bound`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AffectedInterval {
    pub introduced: Version,
    pub end: Bound,
}

impl AffectedInterval {
    pub fn new(introduced: Version, end: Bound) -> AffectedInterval {
        AffectedInterval { introduced, end }
    }

    pub fn contains(&self, version: &Version) -> bool {
        if version < &self.introduced {
            return false;
        }
        match &self.end {
            Bound::Fixed(fixed) => version < fixed,
            Bound::LastAffected(last) => version <= last,
            Bound::Unbounded => true,
        }
    }

    /// The patched version, if this interval was closed by one.
    pub fn fix(&self) -> Option<&Version> {
        match &self.end {
            Bound::Fixed(version) => Some(version),
            Bound::LastAffected(_) | Bound::Unbounded => None,
        }
    }
}

/// The set of versions of one package that an advisory affects.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AffectedRange {
    /// Sorted, non-overlapping intervals.
    pub intervals: Vec<AffectedInterval>,
    /// Explicitly enumerated affected versions, for advisories that list
    /// versions instead of (or in addition to) ranges.
    pub versions: Vec<Version>,
}

impl AffectedRange {
    /// Builds a range from unordered intervals, normalising as it goes.
    pub fn new(mut intervals: Vec<AffectedInterval>, versions: Vec<Version>) -> AffectedRange {
        intervals.sort_by(|a, b| a.introduced.cmp(&b.introduced));
        AffectedRange {
            intervals,
            versions,
        }
    }

    pub fn contains(&self, version: &Version) -> bool {
        self.versions.contains(version) || self.intervals.iter().any(|i| i.contains(version))
    }

    /// The lowest version that fixes `version`, or `None` if no fix is known.
    ///
    /// This is the whole point of the type: resolve the fix from the interval
    /// containing the version in use, not from the first `fixed` event in the
    /// advisory.
    pub fn fix_for(&self, version: &Version) -> Option<&Version> {
        self.intervals
            .iter()
            .find(|i| i.contains(version))
            .and_then(|i| i.fix())
    }
}

/// A vulnerability advisory, flattened from whatever the database returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    /// Database identifier, e.g. `RUSTSEC-2020-0071`.
    pub id: String,
    /// Cross-database identifiers for the same issue (CVE, GHSA), so the user
    /// can recognise something they have already triaged elsewhere.
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// Full advisory text, usually Markdown. Shown on demand rather than by
    /// default: it is frequently hundreds of lines, and burying the decision
    /// under prose is how a report stops being read.
    pub details: Option<String>,
    pub severity: Severity,
    /// Days since publication, when the database says. Turns an abstract
    /// severity into a concrete, uncomfortable fact: *public for 412 days*.
    pub age_days: Option<u32>,
    /// Whether this advisory is a maintenance/quality notice (unmaintained
    /// crate, yanked release) rather than an exploitable defect. RustSec ships
    /// plenty of these and mixing them into a vulnerability list is how a report
    /// loses credibility.
    pub informational: Option<String>,
    /// Affected functions, from OSV's `ecosystem_specific.affects.functions`.
    /// Evidence for reachability: if none of these symbols appear in your code,
    /// the finding deserves a lower position in the queue.
    pub affected_functions: Vec<String>,
    pub affected: AffectedRange,
    pub url: String,
}

impl Advisory {
    /// True if this advisory is informational rather than a live vulnerability.
    pub fn is_informational(&self) -> bool {
        self.informational.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::severity::Severity;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn interval(introduced: &str, fixed: Option<&str>) -> AffectedInterval {
        AffectedInterval::new(
            v(introduced),
            match fixed {
                Some(f) => Bound::Fixed(v(f)),
                None => Bound::Unbounded,
            },
        )
    }

    /// The exact range from RUSTSEC-2020-0071. The reference implementation
    /// answered `0.2.0` for a `0.1.44` user; the correct answer is `0.2.23`.
    fn rustsec_2020_0071() -> AffectedRange {
        AffectedRange::new(
            vec![
                interval("0.0.0-0", Some("0.2.0")),
                interval("0.2.1-0", Some("0.2.1")),
                interval("0.2.2-0", Some("0.2.2")),
                interval("0.2.3-0", Some("0.2.3")),
                interval("0.2.4-0", Some("0.2.4")),
                interval("0.2.5-0", Some("0.2.5")),
                interval("0.2.6-0", Some("0.2.6")),
                interval("0.2.7-0", Some("0.2.23")),
            ],
            vec![],
        )
    }

    #[test]
    fn resolves_fix_from_the_containing_interval() {
        let range = rustsec_2020_0071();

        // A 0.1.x user's real fix is 0.2.0 — the bound of *their* interval.
        assert_eq!(range.fix_for(&v("0.1.44")), Some(&v("0.2.0")));
        // A 0.2.7 user's real fix is 0.2.23, NOT the advisory's first `fixed`.
        assert_eq!(range.fix_for(&v("0.2.7")), Some(&v("0.2.23")));
        assert_eq!(range.fix_for(&v("0.2.22")), Some(&v("0.2.23")));
    }

    #[test]
    fn membership_respects_half_open_intervals() {
        let range = rustsec_2020_0071();

        assert!(range.contains(&v("0.1.44")));
        assert!(range.contains(&v("0.2.7")));
        assert!(range.contains(&v("0.2.22")));

        // The fixed bound itself is not affected.
        assert!(!range.contains(&v("0.2.23")));
        assert!(!range.contains(&v("0.3.0")));
        // Nor is a version between a `fixed` and the next `introduced`.
        assert!(!range.contains(&v("0.2.0")));
        assert!(range.fix_for(&v("0.2.23")).is_none());
    }

    #[test]
    fn open_ended_range_has_no_fix() {
        let range = AffectedRange::new(vec![interval("1.0.0", None)], vec![]);
        assert!(range.contains(&v("1.0.0")));
        assert!(range.contains(&v("99.0.0")));
        assert!(!range.contains(&v("0.9.0")));
        assert_eq!(range.fix_for(&v("1.2.3")), None);
    }

    #[test]
    fn last_affected_is_inclusive_and_offers_no_fix() {
        // "affected through 1.4.2, no patch released" must not be reported as
        // "upgrade to 1.4.2", and must not swallow every later version either.
        let range = AffectedRange::new(
            vec![AffectedInterval::new(
                v("1.0.0"),
                Bound::LastAffected(v("1.4.2")),
            )],
            vec![],
        );

        assert!(range.contains(&v("1.4.2")));
        assert!(!range.contains(&v("1.4.3")));
        assert_eq!(range.fix_for(&v("1.2.0")), None);
    }

    #[test]
    fn enumerated_versions_are_matched_exactly() {
        let range = AffectedRange::new(vec![], vec![v("1.2.3"), v("1.2.5")]);
        assert!(range.contains(&v("1.2.3")));
        assert!(range.contains(&v("1.2.5")));
        assert!(!range.contains(&v("1.2.4")));
        // No interval means no fix can be inferred.
        assert_eq!(range.fix_for(&v("1.2.3")), None);
    }

    #[test]
    fn unordered_input_is_normalised() {
        let range = AffectedRange::new(
            vec![
                interval("0.2.7-0", Some("0.2.23")),
                interval("0.0.0-0", Some("0.2.0")),
            ],
            vec![],
        );
        assert_eq!(range.intervals[0].introduced, v("0.0.0-0"));
        assert_eq!(range.fix_for(&v("0.2.10")), Some(&v("0.2.23")));
    }

    #[test]
    fn informational_advisories_are_flagged() {
        let mut advisory = Advisory {
            id: "RUSTSEC-2020-0036".into(),
            aliases: vec![],
            summary: Some("failure is unmaintained".into()),
            details: None,
            age_days: None,
            severity: Severity::unrated(),
            informational: Some("unmaintained".into()),
            affected_functions: vec![],
            affected: AffectedRange::default(),
            url: "https://osv.dev/vulnerability/RUSTSEC-2020-0036".into(),
        };
        assert!(advisory.is_informational());
        advisory.informational = None;
        assert!(!advisory.is_informational());
    }
}
