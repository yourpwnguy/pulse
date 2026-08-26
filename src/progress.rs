//! Progress across runs — real numbers only.
//!
//! This module replaces an earlier XP/level/streak/badge system. That system was
//! removed on purpose, and the reasoning is worth keeping written down because it
//! is easy to re-introduce by accident:
//!
//! * A level and an XP total say nothing about your dependency tree. They are a
//!   scoreboard *about* the work rather than a view *of* it, so they compete with
//!   the report for attention while adding no decision.
//! * A variable-ratio bonus made a security tool feel like a slot machine. It was
//!   effective and it was wrong: the thing being gamified has to be the thing that
//!   matters, or people optimise the game.
//!
//! What survives is the part that was genuinely motivating: **momentum made
//! visible.** Going from seven issues to two is worth showing, because it is true,
//! it is caused by your work, and it tells you where you stand. Everything here is
//! a count of real findings.
//!
//! Pure: given the same history and report it always produces the same delta.

use serde::{Deserialize, Serialize};

use crate::domain::Rating;
use crate::history::History;
use crate::triage::{Finding, Report};

/// What changed since the previous run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Delta {
    /// Findings that were open last time and are gone now.
    pub fixed: Vec<String>,
    /// Findings that appeared since last time.
    pub introduced: Vec<String>,
    /// Findings still open, carried over.
    pub carried: usize,
    /// `YYYY-MM-DD` of the previous run, if there was one.
    pub last_run: Option<String>,
    /// Whole days since the previous run.
    pub days_since: Option<u32>,
    /// Total findings resolved across every run. The one cumulative number worth
    /// keeping: it is a count of real vulnerabilities that are no longer present.
    pub lifetime_fixed: u64,
    /// True when there is nothing to compare against.
    pub first_run: bool,
}

impl Delta {
    /// Whether anything changed worth mentioning.
    pub fn is_notable(&self) -> bool {
        !self.fixed.is_empty() || !self.introduced.is_empty()
    }

    /// Net movement in the number of open findings. Negative is good.
    pub fn net(&self) -> i64 {
        self.introduced.len() as i64 - self.fixed.len() as i64
    }
}

/// Stable identity for a finding across runs.
///
/// Excludes the version: when a package is upgraded past the advisory the
/// fingerprint disappears, which is exactly the signal "this got fixed". Including
/// the version would make every bump look like one fix plus one new problem.
pub fn fingerprint(finding: &Finding) -> String {
    format!(
        "{}|{}|{}",
        finding.project, finding.package, finding.advisory
    )
}

/// Compares the current report against stored history.
pub fn compare(history: &History, report: &Report, today: crate::domain::Date) -> Delta {
    let current: Vec<String> = report.findings.iter().map(fingerprint).collect();

    let fixed: Vec<String> = history
        .open_findings
        .iter()
        .filter(|old| !current.contains(old))
        .cloned()
        .collect();

    let introduced: Vec<String> = current
        .iter()
        .filter(|new| !history.open_findings.contains(new))
        .cloned()
        .collect();

    let days_since = history
        .last_run
        .as_deref()
        .and_then(crate::domain::Date::parse)
        .map(|last| last.days_until(today).max(0) as u32);

    Delta {
        carried: current.len() - introduced.len(),
        lifetime_fixed: history.lifetime_fixed + fixed.len() as u64,
        first_run: history.last_run.is_none(),
        last_run: history.last_run.clone(),
        days_since,
        fixed,
        introduced,
    }
}

/// The headline facts about a report, in the order a person needs them.
///
/// Assembled here rather than in the renderer so the numbers on screen are
/// provably the numbers in the report, and so they can be asserted in tests.
#[derive(Debug, Clone, PartialEq)]
pub struct Headline {
    pub issues: usize,
    /// Resolvable right now with a semver-compatible bump.
    pub fixable: usize,
    /// No patch exists; you are waiting on someone else.
    pub blocked: usize,
    /// Needs a breaking change — a decision, not a command.
    pub needs_decision: usize,
    /// Highest CVSS score present, if any advisory carried one.
    pub worst_score: Option<f64>,
    pub worst_rating: Rating,
    /// Days since the oldest still-open advisory was published.
    pub oldest_days: Option<u32>,
    pub packages: usize,
    pub projects: usize,
}

impl Headline {
    pub fn of(report: &Report) -> Headline {
        use crate::domain::Effort;

        let fixable = report
            .findings
            .iter()
            .filter(|f| f.effort.is_some_and(Effort::is_compatible))
            .count();
        let needs_decision = report
            .findings
            .iter()
            .filter(|f| f.effort == Some(Effort::Breaking))
            .count();

        Headline {
            issues: report.findings.len(),
            fixable,
            blocked: report
                .findings
                .iter()
                .filter(|f| !f.fix.is_available())
                .count(),
            needs_decision,
            worst_score: report
                .findings
                .iter()
                .filter_map(|f| f.severity.score)
                .max_by(f64::total_cmp),
            worst_rating: report
                .findings
                .iter()
                .map(|f| f.severity.rating)
                .max()
                .unwrap_or(Rating::Unknown),
            oldest_days: report.findings.iter().filter_map(|f| f.age_days).max(),
            packages: report.summary.packages_scanned,
            projects: report.summary.projects,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Date, Ecosystem, Effort, Origin, Provenance, Severity};
    use crate::triage::{Fix, Priority, Summary};
    use semver::Version;

    fn date(iso: &str) -> Date {
        Date::parse(iso).unwrap()
    }

    fn finding(
        package: &str,
        effort: Option<Effort>,
        score: Option<f64>,
        age: Option<u32>,
    ) -> Finding {
        Finding {
            project: "app".into(),
            ecosystem: Ecosystem::CratesIo,
            package: package.into(),
            version: Version::new(1, 0, 0),
            advisory: format!("ADV-{package}"),
            aliases: vec![],
            summary: None,
            details: None,
            age_days: age,
            severity: Severity {
                rating: match score {
                    Some(s) if s >= 7.0 => Rating::High,
                    Some(_) => Rating::Medium,
                    None => Rating::Unknown,
                },
                score,
                vector: None,
                provenance: Provenance::Unrated,
            },
            informational: None,
            origin: Origin::Direct,
            fix: match effort {
                Some(_) => Fix::Available {
                    version: Version::new(1, 0, 5),
                },
                None => Fix::Unavailable,
            },
            effort,
            remediation: None,
            affected_functions: vec![],
            priority: Priority::Act,
            rationale: String::new(),
            url: String::new(),
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            projects: vec!["app".into()],
            summary: Summary {
                projects: 1,
                packages_scanned: 42,
                ..Summary::default()
            },
            findings,
            skipped_projects: vec![],
        }
    }

    fn history(open: &[&str], lifetime: u64) -> History {
        History {
            last_run: Some("2026-01-01".into()),
            open_findings: open.iter().map(|s| format!("app|{s}|ADV-{s}")).collect(),
            lifetime_fixed: lifetime,
            ..History::default()
        }
    }

    #[test]
    fn first_run_has_nothing_to_compare() {
        let delta = compare(&History::default(), &report(vec![]), date("2026-01-02"));
        assert!(delta.first_run);
        assert!(!delta.is_notable());
        assert_eq!(delta.net(), 0);
        assert_eq!(delta.days_since, None);
    }

    #[test]
    fn counts_what_was_fixed() {
        let delta = compare(
            &history(&["a", "b"], 5),
            &report(vec![]),
            date("2026-01-03"),
        );
        assert_eq!(delta.fixed.len(), 2);
        assert!(delta.introduced.is_empty());
        assert_eq!(delta.lifetime_fixed, 7);
        assert_eq!(delta.net(), -2, "net movement should be an improvement");
        assert_eq!(delta.days_since, Some(2));
    }

    #[test]
    fn counts_what_appeared() {
        let delta = compare(
            &history(&[], 0),
            &report(vec![finding("new", None, None, None)]),
            date("2026-01-02"),
        );
        assert_eq!(delta.introduced.len(), 1);
        assert_eq!(delta.net(), 1);
        // A new disclosure is not a failure, so nothing is deducted anywhere.
        assert_eq!(delta.lifetime_fixed, 0);
    }

    #[test]
    fn carried_findings_are_neither_fixed_nor_new() {
        let delta = compare(
            &history(&["a"], 0),
            &report(vec![finding("a", None, None, None)]),
            date("2026-01-02"),
        );
        assert!(delta.fixed.is_empty());
        assert!(delta.introduced.is_empty());
        assert_eq!(delta.carried, 1);
        assert!(!delta.is_notable());
    }

    #[test]
    fn fingerprint_ignores_version_so_an_upgrade_reads_as_a_fix() {
        let mut before = finding("time", None, None, None);
        before.version = Version::new(0, 1, 44);
        let mut after = before.clone();
        after.version = Version::new(0, 2, 23);
        assert_eq!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn headline_splits_fixable_from_blocked_from_decisions() {
        let r = report(vec![
            finding("quick", Some(Effort::Trivial), Some(7.5), Some(120)),
            finding("dropin", Some(Effort::Compatible), Some(4.4), Some(30)),
            finding("breaking", Some(Effort::Breaking), Some(6.2), Some(1826)),
            finding("stuck", None, None, Some(9)),
        ]);
        let h = Headline::of(&r);

        assert_eq!(h.issues, 4);
        // Only the two semver-compatible ones can be fixed by a command.
        assert_eq!(h.fixable, 2);
        assert_eq!(h.needs_decision, 1);
        assert_eq!(h.blocked, 1);
        assert_eq!(h.worst_score, Some(7.5));
        assert_eq!(h.worst_rating, Rating::High);
        assert_eq!(h.oldest_days, Some(1826));
        assert_eq!(h.packages, 42);
    }

    #[test]
    fn headline_of_a_clean_report_is_all_zeroes() {
        let h = Headline::of(&report(vec![]));
        assert_eq!(h.issues, 0);
        assert_eq!(h.fixable, 0);
        assert_eq!(h.blocked, 0);
        assert_eq!(h.worst_score, None);
        assert_eq!(h.oldest_days, None);
        // Still reports what was examined, so "clean" is verifiable.
        assert_eq!(h.packages, 42);
    }

    #[test]
    fn comparison_is_deterministic() {
        let h = history(&["a", "b"], 1);
        let r = report(vec![finding("a", None, None, None)]);
        assert_eq!(
            compare(&h, &r, date("2026-01-02")),
            compare(&h, &r, date("2026-01-02"))
        );
    }
}
