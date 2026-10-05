//! Triage: turning matches into decisions.
//!
//! This is the module that justifies the program's existence. Finding that
//! `time 0.1.44` has an advisory is a solved problem (OSV gives it away and
//! `cargo audit` has done it for years). The unsolved problem is what a person
//! does on Monday morning with forty repositories and two hundred matches.
//!
//! So the output here is not a list of vulnerabilities, and explicitly not a
//! score. It is a **queue**, ordered by what is worth doing, where every entry
//! carries the reasoning that put it there. Two properties matter:
//!
//! * **Explainable.** Every finding has a `rationale` in plain English. A
//!   number you cannot argue with is a number you cannot act on.
//! * **Actionable.** The top of the queue is "high impact, patch exists, you own
//!   the dependency". The bottom is "nothing to upgrade to" and "not actually a
//!   vulnerability". Sorting by severity alone puts unfixable problems above
//!   one-line fixes, which is why severity-sorted reports get ignored.
//!
//! Everything in this module is a pure function over owned values.

mod build;
mod merge;
mod policy;
mod sort;
mod summarise;
mod types;

pub use types::{Finding, Fix, Priority, Report, SkippedProject, Summary};

use crate::domain::Project;
use crate::osv::Advisories;

use build::build_finding;
use merge::merge_aliases;
use sort::sort_findings;
use summarise::summarise;

/// Correlates parsed projects with advisory lookups and triages the result.
///
/// Pure: given the same projects and advisories it always produces the same
/// report, in the same order.
pub fn triage(projects: &[Project], advisories: &Advisories) -> Report {
    let mut findings = Vec::new();

    for project in projects {
        for resolved in &project.packages {
            let Some(matches) = advisories.get(&resolved.package) else {
                continue;
            };

            for advisory in matches {
                findings.push(build_finding(
                    &project.name,
                    &resolved.package,
                    &resolved.origin,
                    advisory,
                ));
            }
        }
    }

    sort_findings(&mut findings);

    // Collapse the same issue reported by several databases, then re-sort
    // because merging can change a finding's severity and therefore its bucket.
    let mut findings = merge_aliases(findings);
    sort_findings(&mut findings);

    findings.dedup_by(|a, b| {
        a.project == b.project
            && a.package == b.package
            && a.version == b.version
            && a.advisory == b.advisory
    });

    let summary = summarise(projects, &findings);
    Report {
        projects: projects.iter().map(|p| p.name.clone()).collect(),
        findings,
        summary,
        skipped_projects: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::domain::{
        AffectedInterval, AffectedRange, Bound, Ecosystem, Provenance, ResolvedPackage,
    };

    fn version(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    fn package(name: &str, v: &str) -> crate::domain::Package {
        crate::domain::Package::new(Ecosystem::CratesIo, name, version(v))
    }

    fn severity(rating: crate::domain::Rating, score: Option<f64>) -> crate::domain::Severity {
        crate::domain::Severity {
            rating,
            score,
            vector: None,
            provenance: if score.is_some() {
                Provenance::Cvss3
            } else {
                Provenance::Unrated
            },
        }
    }

    fn advisory(
        id: &str,
        rating: crate::domain::Rating,
        fixed: Option<&str>,
    ) -> crate::domain::Advisory {
        crate::domain::Advisory {
            id: id.to_string(),
            aliases: vec![],
            summary: Some(format!("summary for {id}")),
            details: None,
            age_days: Some(100),
            severity: severity(
                rating,
                if rating == crate::domain::Rating::Unknown {
                    None
                } else {
                    Some(7.5)
                },
            ),
            informational: None,
            affected_functions: vec![],
            affected: AffectedRange::new(
                vec![AffectedInterval::new(
                    version("0.0.0"),
                    match fixed {
                        Some(f) => Bound::Fixed(version(f)),
                        None => Bound::Unbounded,
                    },
                )],
                vec![],
            ),
            url: format!("https://osv.dev/vulnerability/{id}"),
        }
    }

    fn project(
        name: &str,
        packages: Vec<(crate::domain::Package, crate::domain::Origin)>,
    ) -> Project {
        Project {
            name: name.to_string(),
            root: PathBuf::from(format!("/tmp/{name}")),
            lockfile: PathBuf::from(format!("/tmp/{name}/Cargo.lock")),
            ecosystem: Ecosystem::CratesIo,
            packages: packages
                .into_iter()
                .map(|(package, origin)| ResolvedPackage { package, origin })
                .collect(),
            unscannable: vec![],
        }
    }

    fn advisories(
        entries: Vec<(crate::domain::Package, Vec<crate::domain::Advisory>)>,
    ) -> Advisories {
        entries.into_iter().collect()
    }

    #[test]
    fn severe_and_patchable_becomes_act() {
        let pkg = package("openssl", "0.10.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory(
                    "RUSTSEC-1",
                    crate::domain::Rating::Critical,
                    Some("0.10.55"),
                )],
            )]),
        );

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.priority, Priority::Act);
        assert_eq!(
            finding.fix,
            Fix::Available {
                version: version("0.10.55")
            }
        );
        assert!(finding.rationale.contains("upgrade to 0.10.55"));
        assert!(finding.rationale.contains("direct dependency"));
        assert_eq!(report.summary.act, 1);
        assert_eq!(report.summary.direct, 1);
    }

    #[test]
    fn lower_severity_with_a_patch_becomes_plan() {
        let pkg = package("lowrisk", "1.0.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory(
                    "RUSTSEC-2",
                    crate::domain::Rating::Low,
                    Some("1.0.1"),
                )],
            )]),
        );
        assert_eq!(report.findings[0].priority, Priority::Plan);
        assert_eq!(report.summary.plan, 1);
    }

    #[test]
    fn no_patch_becomes_monitor_even_when_critical() {
        let pkg = package("stuck", "1.0.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory("RUSTSEC-3", crate::domain::Rating::Critical, None)],
            )]),
        );

        let finding = &report.findings[0];
        assert_eq!(finding.priority, Priority::Monitor);
        assert_eq!(finding.fix, Fix::Unavailable);
        assert!(finding.rationale.contains("no patched release"));
        // The dangerous case is counted separately so it cannot hide at the
        // bottom of the queue.
        assert_eq!(report.summary.unpatchable_severe, 1);
    }

    #[test]
    fn informational_advisories_are_not_vulnerabilities() {
        let pkg = package("failure", "0.1.8");
        let mut informational = advisory("RUSTSEC-4", crate::domain::Rating::Unknown, None);
        informational.informational = Some("unmaintained".into());

        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(pkg, vec![informational])]),
        );

        let finding = &report.findings[0];
        assert_eq!(finding.priority, Priority::Note);
        assert!(finding.rationale.contains("unmaintained"));
        assert_eq!(report.summary.note, 1);
        // An unmaintained notice must not inflate the alarming counter.
        assert_eq!(report.summary.unpatchable_severe, 0);
    }

    #[test]
    fn unrated_severity_is_planned_not_discarded() {
        // The exact case the old scorer silently treated as zero risk.
        let pkg = package("mystery", "1.0.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory(
                    "RUSTSEC-5",
                    crate::domain::Rating::Unknown,
                    Some("2.0.0"),
                )],
            )]),
        );

        let finding = &report.findings[0];
        assert_eq!(finding.priority, Priority::Plan);
        assert!(finding.rationale.contains("unrated severity"));
        assert_eq!(report.summary.unrated, 1);
        assert_eq!(report.summary.findings, 1);
    }

    #[test]
    fn transitive_findings_explain_the_dependency_chain() {
        let pkg = package("time", "0.1.44");
        let origin = crate::domain::Origin::Transitive {
            depth: 2,
            path: vec!["chrono".into(), "time".into()],
        };
        let report = triage(
            &[project("app", vec![(pkg.clone(), origin)])],
            &advisories(vec![(
                pkg,
                vec![advisory(
                    "RUSTSEC-6",
                    crate::domain::Rating::High,
                    Some("0.2.23"),
                )],
            )]),
        );

        let finding = &report.findings[0];
        assert!(finding.rationale.contains("chrono → time"));
        assert!(finding.rationale.contains("depth 2"));
        assert_eq!(report.summary.direct, 0);
    }

    #[test]
    fn queue_is_ordered_by_actionability_then_severity() {
        let critical_unfixable = package("a-unfixable", "1.0.0");
        let medium_fixable = package("b-medium", "1.0.0");
        let critical_fixable = package("c-critical", "1.0.0");
        let informational = package("d-informational", "1.0.0");

        let mut note = advisory("RUSTSEC-N", crate::domain::Rating::Unknown, None);
        note.informational = Some("unmaintained".into());

        let report = triage(
            &[project(
                "app",
                vec![
                    (critical_unfixable.clone(), crate::domain::Origin::Direct),
                    (medium_fixable.clone(), crate::domain::Origin::Direct),
                    (critical_fixable.clone(), crate::domain::Origin::Direct),
                    (informational.clone(), crate::domain::Origin::Direct),
                ],
            )],
            &advisories(vec![
                (
                    critical_unfixable,
                    vec![advisory("R-1", crate::domain::Rating::Critical, None)],
                ),
                (
                    medium_fixable,
                    vec![advisory(
                        "R-2",
                        crate::domain::Rating::Medium,
                        Some("2.0.0"),
                    )],
                ),
                (
                    critical_fixable,
                    vec![advisory(
                        "R-3",
                        crate::domain::Rating::Critical,
                        Some("2.0.0"),
                    )],
                ),
                (informational, vec![note]),
            ]),
        );

        let order: Vec<&str> = report.findings.iter().map(|f| f.package.as_str()).collect();
        // A fixable critical outranks an unfixable one: it is work that can
        // actually be completed today.
        assert_eq!(
            order,
            vec!["c-critical", "b-medium", "a-unfixable", "d-informational"]
        );
    }

    #[test]
    fn shallower_dependencies_sort_first_within_a_bucket() {
        let deep = package("deep", "1.0.0");
        let shallow = package("shallow", "1.0.0");

        let report = triage(
            &[project(
                "app",
                vec![
                    (
                        deep.clone(),
                        crate::domain::Origin::Transitive {
                            depth: 5,
                            path: vec![
                                "a".into(),
                                "b".into(),
                                "c".into(),
                                "d".into(),
                                "deep".into(),
                            ],
                        },
                    ),
                    (shallow.clone(), crate::domain::Origin::Direct),
                ],
            )],
            &advisories(vec![
                (
                    deep,
                    vec![advisory("R-1", crate::domain::Rating::High, Some("2.0.0"))],
                ),
                (
                    shallow,
                    vec![advisory("R-2", crate::domain::Rating::High, Some("2.0.0"))],
                ),
            ]),
        );

        assert_eq!(report.findings[0].package, "shallow");
    }

    #[test]
    fn same_advisory_in_two_projects_yields_one_finding_each() {
        let pkg = package("shared", "1.0.0");
        let report = triage(
            &[
                project(
                    "app-one",
                    vec![(pkg.clone(), crate::domain::Origin::Direct)],
                ),
                project(
                    "app-two",
                    vec![(pkg.clone(), crate::domain::Origin::Direct)],
                ),
            ],
            &advisories(vec![(
                pkg,
                vec![advisory("R-1", crate::domain::Rating::High, Some("2.0.0"))],
            )]),
        );

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.summary.projects, 2);
        let projects: Vec<&str> = report.findings.iter().map(|f| f.project.as_str()).collect();
        assert_eq!(projects, vec!["app-one", "app-two"]);
    }

    #[test]
    fn clean_scan_reports_nothing() {
        let report = triage(
            &[project(
                "app",
                vec![(package("safe", "1.0.0"), crate::domain::Origin::Direct)],
            )],
            &Advisories::new(),
        );
        assert!(report.is_clean());
        assert_eq!(report.summary.findings, 0);
        assert_eq!(report.summary.packages_scanned, 1);
        assert!(!report.exceeds(Priority::Note));
    }

    #[test]
    fn gate_compares_by_urgency() {
        let pkg = package("x", "1.0.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory(
                    "R-1",
                    crate::domain::Rating::Medium,
                    Some("2.0.0"),
                )],
            )]),
        );

        // The only finding is `Plan`.
        assert!(!report.exceeds(Priority::Act));
        assert!(report.exceeds(Priority::Plan));
        assert!(report.exceeds(Priority::Monitor));
    }

    #[test]
    fn unactionable_findings_do_not_trip_the_default_gate() {
        // Deliberate policy: a critical with no patch cannot fail a build by
        // default, because a gate nobody can satisfy gets switched off.
        let pkg = package("stuck", "1.0.0");
        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(
                pkg,
                vec![advisory("R-1", crate::domain::Rating::Critical, None)],
            )]),
        );

        assert!(!report.exceeds(Priority::Act));
        assert!(report.exceeds(Priority::Monitor));
        assert_eq!(report.summary.unpatchable_severe, 1);
    }

    /// The real duplicate observed against the live API: RustSec and GitHub
    /// describe the same `time` bug and disagree about the fix version.
    #[test]
    fn collapses_the_same_issue_reported_by_two_databases() {
        let pkg = package("time", "0.1.44");

        let mut rustsec = advisory(
            "RUSTSEC-2020-0071",
            crate::domain::Rating::Medium,
            Some("0.2.0"),
        );
        rustsec.aliases = vec!["CVE-2020-26235".into(), "GHSA-wcg3-cvx6-7396".into()];
        rustsec.affected_functions = vec!["time::now".into()];

        let mut ghsa = advisory(
            "GHSA-wcg3-cvx6-7396",
            crate::domain::Rating::Medium,
            Some("0.2.23"),
        );
        ghsa.aliases = vec!["CVE-2020-26235".into()];
        ghsa.affected_functions = vec!["time::at".into()];

        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(pkg, vec![ghsa, rustsec])]),
        );

        assert_eq!(report.findings.len(), 1, "one issue must yield one finding");
        assert_eq!(report.summary.findings, 1);

        let finding = &report.findings[0];
        // The conservative fix wins: 0.2.23 satisfies both databases.
        assert_eq!(
            finding.fix,
            Fix::Available {
                version: version("0.2.23")
            }
        );
        // Every identifier is retained so the finding stays recognisable.
        assert!(finding.aliases.contains(&"CVE-2020-26235".to_string()));
        assert!(
            merge::identifiers(finding).any(|id| id == "RUSTSEC-2020-0071"),
            "must still be findable by its RustSec id"
        );
        // Evidence from both records is unioned.
        assert_eq!(finding.affected_functions, vec!["time::at", "time::now"]);
        // The rationale reflects the merged fix, not a stale one.
        assert!(finding.rationale.contains("0.2.23"));
    }

    #[test]
    fn merging_keeps_the_worse_severity_and_upgrades_the_bucket() {
        let pkg = package("thing", "1.0.0");

        // One database rates it unknown, the other critical.
        let mut unrated = advisory("RUSTSEC-X", crate::domain::Rating::Unknown, Some("1.0.5"));
        unrated.aliases = vec!["CVE-2024-0001".into()];
        let mut critical = advisory("GHSA-X", crate::domain::Rating::Critical, Some("1.0.5"));
        critical.aliases = vec!["CVE-2024-0001".into()];

        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(pkg, vec![unrated, critical])]),
        );

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity.rating, crate::domain::Rating::Critical);
        // Severity changed, so the decision must be re-derived.
        assert_eq!(finding.priority, Priority::Act);
        assert_eq!(report.summary.act, 1);
        assert_eq!(report.summary.unrated, 0);
    }

    #[test]
    fn unrelated_advisories_for_one_package_are_kept_apart() {
        // Two genuinely different bugs in the same crate must not be merged.
        let pkg = package("busy", "1.0.0");
        let first = advisory("RUSTSEC-A", crate::domain::Rating::High, Some("1.1.0"));
        let second = advisory("RUSTSEC-B", crate::domain::Rating::High, Some("1.2.0"));

        let report = triage(
            &[project(
                "app",
                vec![(pkg.clone(), crate::domain::Origin::Direct)],
            )],
            &advisories(vec![(pkg, vec![first, second])]),
        );

        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn merging_is_scoped_to_one_project() {
        // The same aliased pair in two projects yields one finding per project.
        let pkg = package("time", "0.1.44");
        let mut rustsec = advisory("RUSTSEC-1", crate::domain::Rating::Medium, Some("0.2.0"));
        rustsec.aliases = vec!["CVE-1".into()];
        let mut ghsa = advisory("GHSA-1", crate::domain::Rating::Medium, Some("0.2.23"));
        ghsa.aliases = vec!["CVE-1".into()];

        let report = triage(
            &[
                project(
                    "app-one",
                    vec![(pkg.clone(), crate::domain::Origin::Direct)],
                ),
                project(
                    "app-two",
                    vec![(pkg.clone(), crate::domain::Origin::Direct)],
                ),
            ],
            &advisories(vec![(pkg, vec![rustsec, ghsa])]),
        );

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].project, "app-one");
        assert_eq!(report.findings[1].project, "app-two");
    }

    #[test]
    fn triage_is_deterministic() {
        let pkg_a = package("a", "1.0.0");
        let pkg_b = package("b", "1.0.0");
        let projects = [project(
            "app",
            vec![
                (pkg_a.clone(), crate::domain::Origin::Direct),
                (pkg_b.clone(), crate::domain::Origin::Direct),
            ],
        )];
        let db = advisories(vec![
            (
                pkg_a,
                vec![advisory("R-1", crate::domain::Rating::High, Some("2.0.0"))],
            ),
            (
                pkg_b,
                vec![advisory("R-2", crate::domain::Rating::High, Some("2.0.0"))],
            ),
        ]);

        assert_eq!(triage(&projects, &db), triage(&projects, &db));
    }
}
