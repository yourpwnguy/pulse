//! The triage policy, in one readable place.
//!
//! Two questions, in this order: *can this be fixed?* and *how much does it
//! matter?* Fixability comes first because it decides whether there is any work
//! to schedule at all.
//!
//! `prioritise()` and `explain()` are kept next to each other so the two
//! cannot drift apart — if the policy changes, the explanation changes with it.
//!
//! ## Why this ordering matters
//!
//! The reference implementation sorted by severity alone, which put unfixable
//! criticals above one-line fixes. The result was a report that started with
//! "here are things you cannot do" and ended with "here is what you can fix
//! today." Nobody reads past the first page of that report. By putting
//! fixability first, the top of the queue is always actionable work.
//!
//! ## The `Note` bucket
//!
//! Informational advisories (unmaintained, yanked) go into `Note`, not `Monitor`.
//! Calling an unmaintained notice a "vulnerability" makes the whole report
//! untrustworthy, so they're kept separate with language that says what they
//! are rather than what they're not.

use crate::domain::{Origin, Rating, Severity};

use super::types::{Finding, Fix, Priority};

/// The triage policy.
///
/// Two questions, in this order: *can this be fixed?* and *how much does it
/// matter?* Fixability comes first because it decides whether there is any work
/// to schedule at all.
pub(crate) fn prioritise(informational: bool, rating: Rating, fix: &Fix) -> Priority {
    if informational {
        return Priority::Note;
    }

    if !fix.is_available() {
        return Priority::Monitor;
    }

    match rating {
        Rating::Critical | Rating::High => Priority::Act,
        // Unknown severity with an available patch is deliberately `Plan`, never
        // dropped: unrated is not the same as harmless.
        _ => Priority::Plan,
    }
}

/// Builds the human-readable justification. Kept next to the policy so the two
/// cannot drift apart.
pub(crate) fn explain(
    severity: &Severity,
    informational: Option<&str>,
    fix: &Fix,
    origin: &Origin,
    priority: Priority,
) -> String {
    let impact = match (&severity.score, severity.rating) {
        (Some(score), rating) => format!("{} severity (CVSS {score:.1})", rating.as_str()),
        (None, Rating::Unknown) => "unrated severity".to_string(),
        (None, rating) => format!("{} severity", rating.as_str()),
    };

    let ownership = match origin {
        Origin::Direct => "a direct dependency you can bump yourself".to_string(),
        Origin::Transitive { depth, .. } => match origin.chain() {
            Some(chain) => format!("reached via {chain} (depth {depth})"),
            None => format!("a transitive dependency (depth {depth})"),
        },
    };

    match priority {
        Priority::Note => {
            let kind = informational.unwrap_or("informational");
            format!("{kind} advisory, not an exploitable defect; {ownership}")
        }
        Priority::Monitor => {
            format!("{impact}, but no patched release exists; {ownership}. Track upstream, mitigate, or replace the dependency")
        }
        Priority::Act | Priority::Plan => {
            let target = match fix.version() {
                Some(version) => format!("upgrade to {version} or later"),
                None => "a patch is available".to_string(),
            };
            format!("{impact}, {target}; {ownership}")
        }
    }
}

/// Derives the priority and rationale for a finding, reusing the policy and
/// explanation functions.
pub(crate) fn derive_priority_and_rationale(finding: &mut Finding) {
    finding.priority = prioritise(
        finding.informational.is_some(),
        finding.severity.rating,
        &finding.fix,
    );
    finding.rationale = explain(
        &finding.severity,
        finding.informational.as_deref(),
        &finding.fix,
        &finding.origin,
        finding.priority,
    );
}
