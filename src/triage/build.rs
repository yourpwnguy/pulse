//! Finding construction: building a triaged finding from raw inputs.
//!
//! This is the single place where advisory data is transformed into a triaged
//! finding. The transformation involves:
//!
//! 1. **Fix resolution**: `AffectedRange::fix_for()` finds the correct fix from
//!    the interval *containing your version*, not the first `fixed` event. This
//!    is a security-critical fix that the reference implementation got wrong.
//!
//! 2. **Effort classification**: `Effort::classify()` determines if the upgrade
//!    is trivial, compatible, or breaking under Cargo's semver rules.
//!
//! 3. **Remediation text**: `domain::remediation()` generates the copy-pasteable
//!    command or edit instruction.
//!
//! 4. **Priority assignment**: `prioritise()` applies the policy (fixability
//!    before impact).
//!
//! 5. **Rationale generation**: `explain()` builds the human-readable
//!    justification, kept next to the policy so the two cannot drift apart.
//!
//! Keeping all of this in one place means the transformation from "advisory
//! exists" to "here's what to do about it" is traceable and testable.

use crate::domain::{Advisory, Effort, Origin, Package};

use super::policy::{explain, prioritise};
use super::types::{Finding, Fix};

/// Builds a single `Finding` from its inputs.
pub(crate) fn build_finding(
    project: &str,
    package: &Package,
    origin: &Origin,
    advisory: &Advisory,
) -> Finding {
    let fix = match advisory.affected.fix_for(&package.version) {
        Some(version) => Fix::Available {
            version: version.clone(),
        },
        None => Fix::Unavailable,
    };

    let effort = fix
        .version()
        .map(|target| Effort::classify(&package.version, target));
    let remediation = fix.version().map(|target| {
        crate::domain::remediation(&package.name, &package.version, target, origin.is_direct())
    });

    let priority = prioritise(advisory.is_informational(), advisory.severity.rating, &fix);
    let rationale = explain(
        &advisory.severity,
        advisory.informational.as_deref(),
        &fix,
        origin,
        priority,
    );

    Finding {
        project: project.to_string(),
        ecosystem: package.ecosystem,
        package: package.name.clone(),
        version: package.version.clone(),
        advisory: advisory.id.clone(),
        aliases: advisory.aliases.clone(),
        summary: advisory.summary.clone(),
        details: advisory.details.clone(),
        age_days: advisory.age_days,
        severity: advisory.severity.clone(),
        informational: advisory.informational.clone(),
        origin: origin.clone(),
        fix,
        effort,
        remediation,
        affected_functions: advisory.affected_functions.clone(),
        priority,
        rationale,
        url: advisory.url.clone(),
    }
}
