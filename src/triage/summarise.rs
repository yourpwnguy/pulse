//! Report summarisation.
//!
//! Counts everything the caller needs in one pass: how many findings per
//! bucket, per severity, how many are direct, how many are quick wins, and
//! the genuinely alarming count — high or critical with no patch.

use crate::domain::{Effort, Project, Rating};

use super::types::{Finding, Priority, Summary};

/// Counts all the things.
pub(crate) fn summarise(projects: &[Project], findings: &[Finding]) -> Summary {
    let mut summary = Summary {
        projects: projects.len(),
        packages_scanned: projects.iter().map(|p| p.scanned_count()).sum(),
        packages_unscannable: projects.iter().map(|p| p.unscannable.len()).sum(),
        findings: findings.len(),
        ..Summary::default()
    };

    for finding in findings {
        match finding.priority {
            Priority::Act => summary.act += 1,
            Priority::Plan => summary.plan += 1,
            Priority::Monitor => summary.monitor += 1,
            Priority::Note => summary.note += 1,
        }

        match finding.severity.rating {
            Rating::Critical => summary.critical += 1,
            Rating::High => summary.high += 1,
            Rating::Medium => summary.medium += 1,
            Rating::Low => summary.low += 1,
            Rating::Unknown => summary.unrated += 1,
            Rating::None => {}
        }

        let severe = matches!(finding.severity.rating, Rating::Critical | Rating::High);
        if severe && !finding.fix.is_available() && finding.priority != Priority::Note {
            summary.unpatchable_severe += 1;
        }

        if finding.origin.is_direct() {
            summary.direct += 1;
        }

        if finding.effort.is_some_and(Effort::is_compatible) {
            summary.quick_wins += 1;
        }
    }

    summary
}
