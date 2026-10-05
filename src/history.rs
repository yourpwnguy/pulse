//! Progress state, persisted between runs.
//!
//! This reverses a decision made earlier in the rewrite, and the distinction
//! matters. The reference implementation persisted the *dependency index* (a
//! copy of data that lives in the lockfile, which went stale the moment anyone
//! ran `cargo update`, and which could therefore report findings for a tree that
//! no longer existed). That was a cache pretending to be a source of truth.
//!
//! This file stores something the lockfile cannot: **what the user has already
//! seen and already fixed.** That is genuinely new information, it cannot be
//! recomputed, and if it is lost the worst outcome is a reset counter rather than
//! a wrong security answer. Findings are still computed fresh on every run.
//!
//! Failure is always non-fatal. A vulnerability report must never be withheld
//! because a progress file could not be written.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::progress::{fingerprint, Delta};
use crate::triage::Report;

/// Bumped when the on-disk shape changes incompatibly.
const CURRENT_VERSION: u32 = 1;

/// Everything remembered between runs.
///
/// Deliberately small. An earlier version stored xp, levels, streaks and badges;
/// all of that was a scoreboard rather than information, and it is gone. What
/// remains is the minimum needed to answer "what changed since last time", which
/// is the one genuinely motivating thing a tool can tell you.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct History {
    #[serde(default)]
    pub version: u32,
    /// Total findings resolved across every run.
    #[serde(default)]
    pub lifetime_fixed: u64,
    /// `YYYY-MM-DD` of the previous run.
    #[serde(default)]
    pub last_run: Option<String>,
    /// Fingerprints open at the end of the previous run, so the next run can say
    /// what was fixed and what is new.
    #[serde(default)]
    pub open_findings: Vec<String>,
    /// Projects the user has chosen to stop scanning.
    ///
    /// This is a *suppression* list, which is the one kind of state a security tool
    /// must never keep quietly. Every run reports how many projects it skipped, so
    /// an ignored project cannot silently become an unmonitored one.
    #[serde(default)]
    pub ignored_projects: Vec<String>,
}

impl History {
    /// Loads history, returning a default on any problem.
    ///
    /// A corrupt or unreadable progress file is not worth an error message: the
    /// user came here for a vulnerability report, and losing a streak is a
    /// cosmetic failure.
    pub fn load() -> History {
        let Some(path) = path() else {
            return History::default();
        };
        let Ok(text) = fs::read_to_string(path) else {
            return History::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Records the outcome of this run for the next one to compare against.
    ///
    /// Returns `Err` only to let the caller warn; callers are expected to ignore
    /// it rather than fail the run.
    pub fn save(
        report: &Report,
        delta: &Delta,
        today: &str,
        ignored_projects: &[String],
    ) -> std::io::Result<()> {
        History {
            version: CURRENT_VERSION,
            lifetime_fixed: delta.lifetime_fixed,
            last_run: Some(today.to_string()),
            open_findings: report.findings.iter().map(fingerprint).collect(),
            ignored_projects: ignored_projects.to_vec(),
        }
        .write()
    }

    /// Writes this history to disk.
    ///
    /// The primitive behind [`History::save`], exposed separately because
    /// `--projects` changes the ignore list without producing a report to derive
    /// progress from. Without this, `pulse --projects --ignore x` would show the
    /// effect of the change and then forget it.
    pub fn write(&self) -> std::io::Result<()> {
        let Some(path) = path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json =
            serde_json::to_string_pretty(self).map_err(|e| std::io::Error::other(e.to_string()))?;

        // Write-then-rename so an interrupted run cannot leave a truncated file that
        // would silently reset the user's progress.
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, json)?;
        fs::rename(&temporary, &path)
    }
}

/// Location of the progress file, following the XDG base directory spec on Unix.
///
/// Resolved by hand rather than with the `directories` crate: it is two
/// environment variable lookups, and the reference implementation's dependency
/// existed only to serve the persistence layer that has since been deleted.
fn path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("PULSE_HISTORY") {
        return Some(PathBuf::from(explicit));
    }

    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
        })?;

    Some(base.join("pulse/history.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_a_clean_slate() {
        let history = History::default();
        assert_eq!(history.lifetime_fixed, 0);
        assert!(history.last_run.is_none());
        assert!(history.open_findings.is_empty());
        assert!(history.ignored_projects.is_empty());
    }

    #[test]
    fn round_trips_through_json() {
        let history = History {
            version: CURRENT_VERSION,
            lifetime_fixed: 42,
            last_run: Some("2026-02-04".into()),
            open_findings: vec!["app|time|RUSTSEC-1".into()],
            ignored_projects: vec!["scratch".into()],
        };
        let json = serde_json::to_string(&history).unwrap();
        assert_eq!(serde_json::from_str::<History>(&json).unwrap(), history);
    }

    #[test]
    fn stores_no_game_state() {
        // Guard against re-introducing a scoreboard: the file must contain only
        // information, not points.
        let json = serde_json::to_string(&History::default()).unwrap();
        for banned in ["xp", "streak", "badge", "level"] {
            assert!(!json.contains(banned), "history still stores {banned:?}");
        }
    }

    #[test]
    fn tolerates_missing_fields_from_older_versions() {
        // Forward compatibility: a file written by an earlier build must load.
        let history: History = serde_json::from_str("{}").unwrap();
        assert_eq!(history, History::default());

        let partial: History = serde_json::from_str(r#"{"lifetime_fixed": 500}"#).unwrap();
        assert_eq!(partial.lifetime_fixed, 500);
        assert!(partial.open_findings.is_empty());
    }

    #[test]
    fn corrupt_history_does_not_propagate() {
        // Simulated via the same code path `load` uses.
        assert_eq!(
            serde_json::from_str::<History>("{{{ not json").unwrap_or_default(),
            History::default()
        );
    }

    #[test]
    fn explicit_override_wins() {
        // Guards the test hook used by the integration suite.
        let previous = std::env::var_os("PULSE_HISTORY");
        std::env::set_var("PULSE_HISTORY", "/tmp/pulse-test-history.json");
        assert_eq!(path(), Some(PathBuf::from("/tmp/pulse-test-history.json")));
        match previous {
            Some(value) => std::env::set_var("PULSE_HISTORY", value),
            None => std::env::remove_var("PULSE_HISTORY"),
        }
    }
}
