//! Core triage types: the vocabulary of the output.
//!
//! These types define the shape of what pulse tells the user. Each one has a
//! clear role and none of them depend on I/O, rendering, or any other module
//! outside `domain`. The key design decision is that these types are *flat*:
//! `Finding` holds presentation-ready values rather than nested domain objects,
//! because it *is* the JSON schema. This means the JSON output is stable even
//! if internal types change.
//!
//! The `Priority` enum is the heart of the tool: it's the work queue, not a
//! score. `Act < Plan < Monitor < Note` means sorting a finding list puts the
//! work that matters first, and `--fail-on` becomes a simple `<=` comparison.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::domain::{Ecosystem, Origin, Severity};

/// What to do about a finding.
///
/// `Ord` runs `Act < Plan < Monitor < Note`, i.e. ascending order *is*
/// descending urgency, so sorting a finding list puts the work that matters
/// first and `--fail-on` becomes a `<=` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// High impact and a patched release exists. Highest return on effort.
    Act,
    /// A patched release exists but the impact is lower, or unrated. Schedule it.
    Plan,
    /// No patched release. Upgrading is not an option; watch upstream, mitigate,
    /// or drop the dependency.
    Monitor,
    /// Not an exploitable defect — an unmaintained or yanked notice. Kept
    /// because it is useful, separated because calling it a vulnerability makes
    /// the whole report untrustworthy.
    Note,
}

impl Priority {
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::Act => "act",
            Priority::Plan => "plan",
            Priority::Monitor => "monitor",
            Priority::Note => "note",
        }
    }

    /// One-line explanation of the bucket, printed as a section heading.
    pub fn describe(self) -> &'static str {
        match self {
            Priority::Act => "patch available, high impact",
            Priority::Plan => "patch available, lower impact",
            Priority::Monitor => "no patch available",
            Priority::Note => "informational, not an exploitable defect",
        }
    }
}

/// Whether a patched release exists for the version in use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Fix {
    /// Upgrade to this version or later.
    Available { version: Version },
    /// The advisory records no fixed release for the affected range.
    Unavailable,
}

impl Fix {
    pub fn version(&self) -> Option<&Version> {
        match self {
            Fix::Available { version } => Some(version),
            Fix::Unavailable => None,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Fix::Available { .. })
    }
}

/// One vulnerable package in one project, triaged.
///
/// Flat by design: this struct *is* the `--format json` schema, so it holds
/// presentation-ready values rather than nested domain objects whose shape may
/// change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub project: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: Version,
    pub advisory: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// Full advisory prose. Shown only with `--full`: it runs to hundreds of
    /// lines, and burying the decision under prose is how a report stops being read.
    pub details: Option<String>,
    /// How long this has been public, in days. `None` when the database omits it.
    pub age_days: Option<u32>,
    pub severity: Severity,
    /// Set when the advisory is a maintenance notice rather than a defect;
    /// carries the kind, e.g. `unmaintained` or `yanked`.
    pub informational: Option<String>,
    pub origin: Origin,
    pub fix: Fix,
    /// How much work the upgrade is. `None` when there is no fix to apply.
    pub effort: Option<crate::domain::Effort>,
    /// The exact command or edit that resolves this. `None` when nothing to do.
    pub remediation: Option<String>,
    /// Symbols the advisory says are affected. Not a reachability *claim* — a
    /// starting point for `grep`, and the honest limit of what a lockfile scanner
    /// can know without call-graph analysis.
    pub affected_functions: Vec<String>,
    pub priority: Priority,
    /// Why this finding landed in this bucket.
    pub rationale: String,
    pub url: String,
}

/// Aggregate counts.
///
/// Named fields rather than a map, so the JSON schema is stable and a consumer
/// can rely on every key existing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub projects: usize,
    pub packages_scanned: usize,
    /// Packages a database cannot identify (git and path dependencies). Reported
    /// because "no findings" means less when part of the tree was never checked.
    pub packages_unscannable: usize,
    pub findings: usize,
    pub act: usize,
    pub plan: usize,
    pub monitor: usize,
    pub note: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// Findings whose severity we could not establish. Tracked explicitly
    /// because the reference implementation's scorer treated these as zero risk,
    /// which let a project full of unrated advisories report a perfect score.
    pub unrated: usize,
    /// High or critical findings with no patch. The genuinely alarming number,
    /// and the one a severity-sorted list hides at the bottom.
    pub unpatchable_severe: usize,
    /// Findings in dependencies the project declares itself, and can fix alone.
    pub direct: usize,
    /// Findings resolvable by a semver-compatible bump — the quick wins.
    pub quick_wins: usize,
}

/// A project that was found but deliberately not scanned.
///
/// Carried in the report rather than discarded: a skipped project is a blind
/// spot, and an unreported blind spot turns "no findings" into a false
/// reassurance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkippedProject {
    pub name: String,
    /// Why it was skipped, in the user's own vocabulary (`--exclude foo`).
    pub reason: String,
}

/// The complete result of a scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub projects: Vec<String>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    /// Projects found on disk but excluded from this scan.
    #[serde(default)]
    pub skipped_projects: Vec<SkippedProject>,
}

impl Report {
    /// True if any finding is at least as urgent as `threshold`.
    ///
    /// Used for the process exit code. Note that the default threshold is
    /// [`Priority::Act`]: failing a build over a vulnerability with no available
    /// patch teaches people to pass `--no-verify`, so unactionable findings do
    /// not break the build unless asked for explicitly.
    pub fn exceeds(&self, threshold: Priority) -> bool {
        self.findings.iter().any(|f| f.priority <= threshold)
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}
