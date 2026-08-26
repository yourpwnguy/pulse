//! Finding sort order: deterministic, useful ordering.
//!
//! The sort order is designed to put the work that matters first:
//!
//! 1. **Priority bucket** (`Act < Plan < Monitor < Note`): fixability before
//!    impact, because a one-line fix beats an unfixable critical.
//!
//! 2. **Severity rating** (within a bucket): worse first.
//!
//! 3. **CVSS score** (within a rating): higher first.
//!
//! 4. **Effort** (`Trivial < Compatible < Breaking`): easier first.
//!
//! 5. **Origin depth** (shallower first): direct dependencies first, because
//!    you can fix them yourself.
//!
//! 6. **Stable tie-breakers** (package, version, advisory, project): deterministic
//!    output regardless of input order.
//!
//! ## Why this ordering matters
//!
//! The reference implementation sorted by severity alone, which put unfixable
//! criticals above one-line fixes. The result was a report that started with
//! "here are things you cannot do" and ended with "here is what you can fix
//! today." Nobody reads past the first page of that report.
//!
//! By putting fixability first, the top of the queue is always actionable work.
//! The `--fail-on` threshold becomes a simple `<=` comparison on this sorted
//! list.

use super::types::Finding;

/// Sorts findings by actionability then severity.
///
/// The sort is deterministic (all tie-breakers are explicit) and puts the
/// work that matters first.
pub(crate) fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(b.severity.rating.cmp(&a.severity.rating))
            .then(
                b.severity
                    .score
                    .unwrap_or(0.0)
                    .total_cmp(&a.severity.score.unwrap_or(0.0)),
            )
            .then(a.effort.cmp(&b.effort))
            .then(a.origin.depth().cmp(&b.origin.depth()))
            .then(a.package.cmp(&b.package))
            .then(a.version.cmp(&b.version))
            .then(a.advisory.cmp(&b.advisory))
            .then(a.project.cmp(&b.project))
    });
}
