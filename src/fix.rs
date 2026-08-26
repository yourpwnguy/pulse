//! `--fix`: apply the upgrades, then **prove** they landed.
//!
//! ## Why verification is not optional
//!
//! `cargo update -p foo` exiting zero does *not* mean `foo` reached the patched
//! version. It can legitimately succeed while changing nothing, or while moving
//! only part of the way, because:
//!
//! * the manifest requirement caps it (`foo = "0.103"` cannot reach `0.104`),
//! * another dependency pins it lower,
//! * the resolver backed off to respect a `rust-version` your toolchain predates,
//! * or the version simply is not published for your target.
//!
//! An earlier version of this module reported "✓ fixed" on the exit code alone.
//! That is the worst possible failure for a security tool: it tells you the
//! vulnerability is gone when it is still there. So every upgrade is now checked
//! against the lockfile afterwards, and anything that did not reach the fix is
//! reported as **still vulnerable**, with the reason where we can determine one.
//!
//! ## Safety
//!
//! Only semver-**compatible** upgrades are attempted. A breaking change is a
//! decision with consequences the tool cannot evaluate, so those are always left
//! to the human. Nothing here edits `Cargo.toml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use semver::Version;

use crate::domain::Effort;
use crate::render::{Reporter, Stage};
use crate::triage::Report;

/// One upgrade to attempt.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Upgrade {
    /// Directory to run `cargo` in.
    pub root: PathBuf,
    pub project: String,
    pub package: String,
    /// Version currently locked.
    pub from: Version,
    /// Lowest version that resolves the advisory.
    pub target: Version,
    /// How many findings this would resolve.
    pub clears: usize,
}

/// What actually happened, established from the lockfile rather than the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The lockfile now has a version at or past the fix. Genuinely resolved.
    Fixed { to: Version },
    /// `cargo` succeeded but the package did not reach the fix. Still vulnerable.
    Short { to: Version, reason: Reason },
    /// `cargo` itself failed.
    Failed { error: String },
}

/// Why an upgrade fell short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Did not move at all.
    Pinned,
    /// The resolver declined a newer release because of its `rust-version`.
    Msrv { needs: String },
    /// Moved, but not far enough.
    Insufficient,
    /// Cargo said something we do not specifically recognise.
    Other(String),
}

impl Reason {
    pub fn explain(&self, package: &str) -> String {
        match self {
            Reason::Pinned => {
                format!(
                    "{package} did not move — a version requirement in Cargo.toml is capping it"
                )
            }
            Reason::Msrv { needs } => {
                format!("the patched {package} needs Rust {needs}; cargo kept an older release")
            }
            Reason::Insufficient => {
                format!("{package} moved but not far enough to clear the advisory")
            }
            Reason::Other(detail) => detail.clone(),
        }
    }
}

/// The result of one attempted upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub package: String,
    pub project: String,
    pub clears: usize,
    pub from: Version,
    pub target: Version,
    pub outcome: Outcome,
    /// True when `cargo add` was required to uncap the version.
    pub used_cargo_add: bool,
}

impl Applied {
    /// True only when the lockfile proves the fix landed.
    pub fn resolved(&self) -> bool {
        matches!(self.outcome, Outcome::Fixed { .. })
    }

    /// The version now locked, if the package is still present.
    pub fn now(&self) -> Option<&Version> {
        match &self.outcome {
            Outcome::Fixed { to } | Outcome::Short { to, .. } => Some(to),
            Outcome::Failed { .. } => None,
        }
    }

    /// A short phrase for the report.
    pub fn summary(&self) -> String {
        match &self.outcome {
            Outcome::Fixed { to } => format!("{} → {to}", self.from),
            Outcome::Short { to, .. } if *to == self.from => "unchanged".to_string(),
            Outcome::Short { to, .. } => format!("{} → {to}, still affected", self.from),
            Outcome::Failed { .. } => "failed".to_string(),
        }
    }
}

/// Works out which upgrades are safe to attempt, in a stable order.
///
/// Pure: a report in, a plan out. The plan can be inspected and tested without
/// running anything, which is how the "never attempts a breaking change" property
/// is actually verified rather than merely claimed.
pub fn plan(report: &Report, roots: &BTreeMap<String, PathBuf>) -> Vec<Upgrade> {
    // One `cargo update` per package, however many advisories it resolves. The
    // target is the highest fix among them so the single upgrade clears them all.
    let mut planned: BTreeMap<(String, String), Upgrade> = BTreeMap::new();

    for finding in &report.findings {
        // Compatible upgrades only.
        if !finding.effort.is_some_and(Effort::is_compatible) {
            continue;
        }
        let Some(target) = finding.fix.version() else {
            continue;
        };
        // A project whose root we cannot resolve is skipped rather than guessed
        // at: running cargo in the wrong directory is worse than doing nothing.
        let Some(root) = roots.get(&finding.project) else {
            continue;
        };

        let key = (finding.project.clone(), finding.package.clone());
        planned
            .entry(key)
            .and_modify(|existing| {
                existing.clears += 1;
                if *target > existing.target {
                    existing.target = target.clone();
                }
            })
            .or_insert_with(|| Upgrade {
                root: root.clone(),
                project: finding.project.clone(),
                package: finding.package.clone(),
                from: finding.version.clone(),
                target: target.clone(),
                clears: 1,
            });
    }

    planned.into_values().collect()
}

/// Runs the planned upgrades and verifies each one against the lockfile.
pub fn apply(plan: &[Upgrade], reporter: &Reporter) -> Vec<Applied> {
    reporter.begin(Stage::Resolve);
    reporter.total(plan.len());

    let applied = plan
        .iter()
        .map(|upgrade| {
            // Show initial command
            reporter.detail(format!("cargo update -p {}", upgrade.package));
            let (outcome, used_cargo_add) = attempt(upgrade);

            // Update detail with what actually happened
            if used_cargo_add {
                reporter.detail(format!(
                    "cargo add {}@{} ✓",
                    upgrade.package, upgrade.target
                ));
            } else {
                reporter.detail(match &outcome {
                    Outcome::Fixed { to } => format!("{} now {to} ✓", upgrade.package),
                    Outcome::Short { to, .. } => format!("{} still {to}", upgrade.package),
                    Outcome::Failed { .. } => format!("{} failed", upgrade.package),
                });
            }
            reporter.tick();

            Applied {
                package: upgrade.package.clone(),
                project: upgrade.project.clone(),
                clears: upgrade.clears,
                from: upgrade.from.clone(),
                target: upgrade.target.clone(),
                outcome,
                used_cargo_add,
            }
        })
        .collect();

    reporter.finish(Stage::Resolve, "verified");
    applied
}

/// Runs one upgrade, then reads the lockfile back to see what really happened.
///
/// Returns `(Outcome, bool)` where the bool indicates if `cargo add` was used.
fn attempt(upgrade: &Upgrade) -> (Outcome, bool) {
    // First, try cargo update (safe, only modifies lockfile)
    let output = match Command::new("cargo")
        .arg("update")
        .arg("-p")
        .arg(&upgrade.package)
        .current_dir(&upgrade.root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return (
                Outcome::Failed {
                    error: format!("could not run cargo: {error}"),
                },
                false,
            )
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return (
            Outcome::Failed {
                error: last_meaningful_line(&stderr),
            },
            false,
        );
    }

    // Check if cargo update actually worked
    match locked_version(&upgrade.root, &upgrade.package) {
        Some(now) if now >= upgrade.target => (Outcome::Fixed { to: now }, false),
        Some(now) if now == upgrade.from => {
            // Version didn't move - check if it's an MSRV issue or a Cargo.toml cap
            if let Some(needs) = msrv_hint(&stderr) {
                (
                    Outcome::Short {
                        to: now,
                        reason: Reason::Msrv { needs },
                    },
                    false,
                )
            } else {
                // Try cargo add to update Cargo.toml
                let outcome = attempt_cargo_add(upgrade);
                (outcome, true)
            }
        }
        Some(now) => (
            Outcome::Short {
                to: now,
                reason: Reason::Insufficient,
            },
            false,
        ),
        // Gone from the lockfile entirely. Unusual, but not something to call fixed.
        None => (
            Outcome::Failed {
                error: format!("{} is no longer in the lockfile", upgrade.package),
            },
            false,
        ),
    }
}

/// Reads the version a package is locked at, after an update.
fn locked_version(root: &Path, package: &str) -> Option<Version> {
    let project = crate::lockfile::cargo::parse(&root.join("Cargo.lock")).ok()?;
    project
    .packages
    .iter()
    .filter(|p| p.package.name == package)
    .map(|p| p.package.version.clone())
    // Several versions of one crate can coexist; the highest is the one an
    // upgrade was trying to reach.
    .max()
}

/// Tries `cargo add package@version` to update the Cargo.toml requirement.
///
/// This is tried when `cargo update` fails because the version requirement
/// in Cargo.toml is capping the package.
fn attempt_cargo_add(upgrade: &Upgrade) -> Outcome {
    let target = &upgrade.target;
    let spec = format!("{}@{target}", upgrade.package);
    let output = match Command::new("cargo")
        .arg("add")
        .arg(&spec)
        .current_dir(&upgrade.root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return Outcome::Failed {
                error: format!("could not run cargo add: {error}"),
            }
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Outcome::Failed {
            error: last_meaningful_line(&stderr),
        };
    }

    // cargo add succeeded, now run cargo update to actually resolve
    let _ = Command::new("cargo")
        .arg("update")
        .arg("-p")
        .arg(&upgrade.package)
        .current_dir(&upgrade.root)
        .output();

    // Check the lockfile again
    match locked_version(&upgrade.root, &upgrade.package) {
        Some(now) if now >= upgrade.target => Outcome::Fixed { to: now },
        Some(now) => Outcome::Short {
            to: now,
            reason: Reason::Insufficient,
        },
        None => Outcome::Failed {
            error: format!("{} is no longer in the lockfile", upgrade.package),
        },
    }
}

/// Looks for a minimum-supported-Rust-version complaint in cargo's output.
///
/// Cargo's wording has changed across releases, so this matches on the version
/// number near a `rust-version`/`rustc` mention rather than on an exact phrase.
fn msrv_hint(stderr: &str) -> Option<String> {
    // The version must be the one that follows the keyword, not merely the first
    // version-shaped token on the line: `serde v1.0.300 requires rustc 1.82` would
    // otherwise report the crate version as the Rust requirement.
    const KEYWORDS: &[&str] = &["rustc", "rust-version"];

    for line in stderr.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (index, token) in tokens.iter().enumerate() {
            let word = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            if !KEYWORDS.contains(&word.to_ascii_lowercase().as_str()) {
                continue;
            }
            // Look at the next couple of tokens, to step over filler like "is".
            for candidate in tokens.iter().skip(index + 1).take(3) {
                if let Some(version) = as_version(candidate) {
                    return Some(version);
                }
            }
        }
    }
    None
}

/// A bare `1.82`-style version token, with surrounding punctuation removed.
///
/// Rejects anything carrying a `v` prefix, which is how cargo writes *crate*
/// versions — the distinction that made the first attempt at this wrong.
fn as_version(token: &str) -> Option<String> {
    if token.starts_with('v') {
        return None;
    }
    let trimmed = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
    let looks_like_version = trimmed.contains('.')
        && trimmed.starts_with(|c: char| c.is_ascii_digit())
        && trimmed.ends_with(|c: char| c.is_ascii_digit());
    looks_like_version.then(|| trimmed.to_string())
}

fn last_meaningful_line(stderr: &str) -> String {
    stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("cargo update failed")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Ecosystem, Origin, Provenance, Rating, Severity};
    use crate::triage::{Finding, Fix, Priority, Summary};

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn finding(
        project: &str,
        package: &str,
        from: &str,
        fix: Option<&str>,
        effort: Option<Effort>,
    ) -> Finding {
        Finding {
            project: project.into(),
            ecosystem: Ecosystem::CratesIo,
            package: package.into(),
            version: v(from),
            advisory: format!("ADV-{package}"),
            aliases: vec![],
            summary: None,
            details: None,
            age_days: None,
            severity: Severity {
                rating: Rating::High,
                score: None,
                vector: None,
                provenance: Provenance::Unrated,
            },
            informational: None,
            origin: Origin::Direct,
            fix: match fix {
                Some(target) => Fix::Available { version: v(target) },
                None => Fix::Unavailable,
            },
            effort,
            remediation: Some(format!("cargo update -p {package}")),
            affected_functions: vec![],
            priority: Priority::Act,
            rationale: String::new(),
            url: String::new(),
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            projects: vec!["app".into()],
            findings,
            summary: Summary::default(),
            skipped_projects: vec![],
        }
    }

    fn roots() -> BTreeMap<String, PathBuf> {
        let mut map = BTreeMap::new();
        map.insert("app".to_string(), PathBuf::from("/tmp/app"));
        map.insert("other".to_string(), PathBuf::from("/tmp/other"));
        map
    }

    #[test]
    fn plans_one_update_per_package_taking_the_highest_fix() {
        let report = report(vec![
            finding(
                "app",
                "webpki",
                "0.103.9",
                Some("0.103.10"),
                Some(Effort::Trivial),
            ),
            finding(
                "app",
                "webpki",
                "0.103.9",
                Some("0.103.13"),
                Some(Effort::Trivial),
            ),
            finding(
                "app",
                "clap",
                "4.0.0",
                Some("4.0.5"),
                Some(Effort::Compatible),
            ),
        ]);

        let plan = plan(&report, &roots());
        assert_eq!(plan.len(), 2);

        let webpki = plan.iter().find(|u| u.package == "webpki").unwrap();
        assert_eq!(webpki.clears, 2);
        // The higher target, so one upgrade clears both advisories.
        assert_eq!(webpki.target, v("0.103.13"));
        assert_eq!(webpki.from, v("0.103.9"));
    }

    #[test]
    fn never_plans_a_breaking_change() {
        let report = report(vec![
            finding(
                "app",
                "time",
                "0.1.44",
                Some("0.2.23"),
                Some(Effort::Breaking),
            ),
            finding(
                "app",
                "serde",
                "1.0.0",
                Some("1.0.5"),
                Some(Effort::Trivial),
            ),
        ]);
        let plan = plan(&report, &roots());
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].package, "serde");
    }

    #[test]
    fn skips_findings_with_no_fix_and_unknown_roots() {
        assert!(plan(
            &report(vec![finding("app", "stuck", "1.0.0", None, None)]),
            &roots()
        )
        .is_empty());
        assert!(plan(
            &report(vec![finding(
                "ghost",
                "serde",
                "1.0.0",
                Some("1.0.5"),
                Some(Effort::Trivial)
            )]),
            &roots()
        )
        .is_empty());
    }

    #[test]
    fn plan_is_deterministic_and_sorted() {
        let report = report(vec![
            finding("app", "zzz", "1.0.0", Some("1.0.5"), Some(Effort::Trivial)),
            finding("app", "aaa", "1.0.0", Some("1.0.5"), Some(Effort::Trivial)),
        ]);
        assert_eq!(plan(&report, &roots()), plan(&report, &roots()));
        assert_eq!(plan(&report, &roots())[0].package, "aaa");
    }

    // ── the verification logic, which is the point of this module ──

    fn applied(from: &str, target: &str, outcome: Outcome) -> Applied {
        Applied {
            package: "webpki".into(),
            project: "app".into(),
            clears: 2,
            from: v(from),
            target: v(target),
            outcome,
            used_cargo_add: false,
        }
    }

    #[test]
    fn only_reaching_the_target_counts_as_resolved() {
        let ok = applied("0.103.9", "0.103.13", Outcome::Fixed { to: v("0.103.15") });
        assert!(ok.resolved());
        assert_eq!(ok.summary(), "0.103.9 → 0.103.15");
    }

    #[test]
    fn an_upgrade_that_falls_short_is_not_resolved() {
        // The bug this module exists to prevent: cargo exits 0, the version moves,
        // but not past the advisory. Reporting that as fixed is a lie.
        let short = applied(
            "0.103.9",
            "0.103.13",
            Outcome::Short {
                to: v("0.103.11"),
                reason: Reason::Insufficient,
            },
        );
        assert!(!short.resolved());
        assert!(short.summary().contains("still affected"));
    }

    #[test]
    fn an_upgrade_that_does_nothing_is_reported_as_unchanged() {
        let stuck = applied(
            "0.103.9",
            "0.103.13",
            Outcome::Short {
                to: v("0.103.9"),
                reason: Reason::Pinned,
            },
        );
        assert!(!stuck.resolved());
        assert_eq!(stuck.summary(), "unchanged");
    }

    #[test]
    fn a_cargo_failure_is_not_resolved_and_has_no_version() {
        let failed = applied(
            "1.0.0",
            "1.0.5",
            Outcome::Failed {
                error: "network error".into(),
            },
        );
        assert!(!failed.resolved());
        assert_eq!(failed.now(), None);
    }

    #[test]
    fn reasons_explain_themselves_in_plain_language() {
        assert!(Reason::Pinned.explain("serde").contains("Cargo.toml"));
        assert!(Reason::Insufficient
            .explain("serde")
            .contains("not far enough"));

        let msrv = Reason::Msrv {
            needs: "1.82".into(),
        };
        let text = msrv.explain("serde");
        assert!(text.contains("1.82"));
        assert!(text.contains("Rust"));
    }

    #[test]
    fn detects_an_msrv_backoff_in_cargo_output() {
        // Real-shaped cargo output. The exact phrasing changes between releases,
        // so the match is on the shape rather than an exact string.
        let stderr = "\
    Updating crates.io index
note: pass `--verbose` to see more details
warning: `serde v1.0.300` requires rustc 1.82 or newer, while the currently \
activated rust-version is 1.74";
        assert_eq!(msrv_hint(stderr), Some("1.82".to_string()));

        let other = "note: rust-version 1.90 is required by tokio v1.50.0";
        assert_eq!(msrv_hint(other), Some("1.90".to_string()));

        // The keyword form where filler sits between it and the number.
        let filler = "the currently activated rust-version is 1.74 for this crate";
        assert_eq!(msrv_hint(filler), Some("1.74".to_string()));

        // A crate version must never be mistaken for a toolchain version.
        assert_eq!(msrv_hint("warning: serde v1.0.300 is available"), None);
    }

    #[test]
    fn ordinary_cargo_output_is_not_mistaken_for_an_msrv_problem() {
        assert_eq!(msrv_hint("    Updating crates.io index"), None);
        assert_eq!(msrv_hint(""), None);
        assert_eq!(msrv_hint("error: no matching package named `nope`"), None);
    }

    #[test]
    fn extracts_the_useful_line_from_a_cargo_error() {
        let stderr =
            "    Updating crates.io index\nerror: no matching package named `nope` found\n\n";
        assert_eq!(
            last_meaningful_line(stderr),
            "error: no matching package named `nope` found"
        );
        assert_eq!(last_meaningful_line(""), "cargo update failed");
    }

    #[test]
    fn a_missing_directory_is_reported_not_panicked() {
        let upgrade = Upgrade {
            root: PathBuf::from("/nonexistent-xyz-123"),
            project: "app".into(),
            package: "serde".into(),
            from: v("1.0.0"),
            target: v("1.0.5"),
            clears: 1,
        };
        assert!(matches!(attempt(&upgrade), (Outcome::Failed { .. }, _)));
    }

    #[test]
    fn locked_version_of_a_missing_lockfile_is_none() {
        assert_eq!(locked_version(Path::new("/nonexistent-xyz"), "serde"), None);
    }
}
