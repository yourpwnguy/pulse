//! Alias merging: collapsing the same issue reported by multiple databases.
//!
//! OSV aggregates several databases, so one vulnerability in `time` arrives as
//! both `RUSTSEC-2020-0071` and `GHSA-wcg3-cvx6-7396`, each listing the other in
//! its `aliases`. Reporting both is not a cosmetic problem: it inflates every
//! count, and the two records disagree about the fix version (RustSec's ranges
//! resolve to `0.2.0`, GitHub's to `0.2.23`). A reviewer who sees the same CVE
//! twice with two different answers stops believing the tool.
//!
//! ## The merging strategy
//!
//! Two findings merge when they concern the same package in the same project and
//! their identifier sets intersect. The merged record keeps the *worst* severity
//! and the *highest* fix version, because when databases disagree the
//! conservative answer is the one that leaves you patched.
//!
//! ## Why merging is scoped to one project
//!
//! The same aliased pair in two projects yields one finding per project, not one
//! finding total. A finding's identity is `project|package|advisory`, so merging
//! across projects would incorrectly combine findings that affect different
//! codebases and need different fixes.
//!
//! ## What happens during a merge
//!
//! 1. Severity: prefer a known rating over `Unknown`; otherwise keep the worse.
//! 2. Fix version: take the higher one (satisfies both databases).
//! 3. Aliases: union all identifiers so the finding is recognisable whichever
//!    database the reader is used to.
//! 4. Affected functions: union the lists (different databases may track
//!    different symbols).
//! 5. Priority and rationale: re-derived from the merged facts.

use crate::domain::{Effort, Rating};

use super::policy::derive_priority_and_rationale;
use super::types::{Finding, Fix};

/// Collapses findings that are the same underlying issue.
///
/// Merging is scoped to one project: the same aliased pair in two projects
/// yields one finding per project.
pub(crate) fn merge_aliases(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());

    'next: for finding in findings {
        for existing in &mut merged {
            if same_package(existing, &finding) && shares_identifier(existing, &finding) {
                absorb(existing, finding);
                continue 'next;
            }
        }
        merged.push(finding);
    }

    merged
}

fn same_package(a: &Finding, b: &Finding) -> bool {
    a.project == b.project && a.package == b.package && a.version == b.version
}

/// Every name this finding is known by.
pub(crate) fn identifiers(finding: &Finding) -> impl Iterator<Item = &str> {
    std::iter::once(finding.advisory.as_str()).chain(finding.aliases.iter().map(String::as_str))
}

fn shares_identifier(a: &Finding, b: &Finding) -> bool {
    identifiers(a).any(|id| identifiers(b).any(|other| id.eq_ignore_ascii_case(other)))
}

/// Folds `other` into `primary`, keeping the more cautious of each value.
fn absorb(primary: &mut Finding, other: Finding) {
    // Prefer a known severity over an unrated one; otherwise keep the worse.
    let replace_severity = match (primary.severity.rating, other.severity.rating) {
        (Rating::Unknown, o) if o != Rating::Unknown => true,
        (p, o) if o != Rating::Unknown && o > p => true,
        _ => false,
    };
    if replace_severity {
        primary.severity = other.severity.clone();
    }

    // When databases disagree, take the higher fix: it satisfies both.
    match (&primary.fix, &other.fix) {
        (Fix::Unavailable, Fix::Available { .. }) => primary.fix = other.fix.clone(),
        (Fix::Available { version: ours }, Fix::Available { version: theirs }) if theirs > ours => {
            primary.fix = other.fix.clone();
        }
        _ => {}
    }

    if primary.summary.is_none() {
        primary.summary = other.summary.clone();
    }
    if primary.informational.is_none() {
        primary.informational = other.informational.clone();
    }

    // Record every identifier so the finding is recognisable whichever database
    // the reader is used to.
    let mut aliases: Vec<String> = primary
        .aliases
        .iter()
        .cloned()
        .chain(std::iter::once(other.advisory.clone()))
        .chain(other.aliases.iter().cloned())
        .filter(|id| !id.eq_ignore_ascii_case(&primary.advisory))
        .collect();
    aliases.sort();
    aliases.dedup();
    primary.aliases = aliases;

    let mut functions = std::mem::take(&mut primary.affected_functions);
    functions.extend(other.affected_functions);
    functions.sort();
    functions.dedup();
    primary.affected_functions = functions;

    // A merged, higher fix version changes how much work the upgrade is.
    if let Some(target) = primary.fix.version().cloned() {
        primary.effort = Some(Effort::classify(&primary.version, &target));
        primary.remediation = Some(crate::domain::remediation(
            &primary.package,
            &primary.version,
            &target,
            primary.origin.is_direct(),
        ));
    }

    // The merged facts may imply a different decision, so re-derive it.
    derive_priority_and_rationale(primary);
}
