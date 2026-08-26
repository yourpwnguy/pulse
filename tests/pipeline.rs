//! End-to-end tests over the pure pipeline.
//!
//! These drive the real code path — discovery, parsing, graph construction,
//! correlation, triage, rendering — with the network replaced by hand-built
//! advisories. No mocking framework and no trait indirection is required,
//! because the only impure step ([`pulse::osv::Client`]) is a separate leaf
//! module rather than something threaded through the logic.

use std::path::PathBuf;

use pulse::domain::{
    Advisory, AffectedInterval, AffectedRange, Bound, Ecosystem, Origin, Package, Provenance,
    Rating, Severity,
};
use pulse::osv::Advisories;
use pulse::progress::Delta;
use pulse::render::{self, Format, Layout, Style, View};
use pulse::triage::{Fix, Priority};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn version(raw: &str) -> semver::Version {
    semver::Version::parse(raw).unwrap()
}

/// The genuine RUSTSEC-2020-0071 shape, including the multi-interval range that
/// makes naive fix extraction wrong.
fn rustsec_2020_0071() -> Advisory {
    Advisory {
    id: "RUSTSEC-2020-0071".into(),
    aliases: vec!["CVE-2020-26235".into(), "GHSA-wcg3-cvx6-7396".into()],
    summary: Some("Potential segfault in the time crate".into()),
    details: Some("### Impact\n\nThe affected functions set environment variables without synchronization. On Unix-like operating systems, this can crash in multithreaded programs.".into()),
    age_days: Some(1900),
    severity: Severity {
      rating: Rating::Medium,
      score: Some(6.2),
      vector: Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into()),
      provenance: Provenance::Cvss3,
    },
    informational: None,
    affected_functions: vec!["time::at".into(), "time::now".into()],
    affected: AffectedRange::new(
      vec![
        AffectedInterval::new(version("0.0.0-0"), Bound::Fixed(version("0.2.0"))),
        AffectedInterval::new(version("0.2.7-0"), Bound::Fixed(version("0.2.23"))),
      ],
      vec![],
    ),
    url: "https://osv.dev/vulnerability/RUSTSEC-2020-0071".into(),
  }
}

fn time_advisories() -> Advisories {
    let mut db = Advisories::new();
    db.insert(
        Package::new(Ecosystem::CratesIo, "time", version("0.1.44")),
        vec![rustsec_2020_0071()],
    );
    db
}

#[test]
fn parses_the_dependency_graph_from_a_real_lockfile() {
    let project = pulse::parse_lockfile(&fixture("vulnerable-app/Cargo.lock")).unwrap();

    assert_eq!(project.name, "vulnerable-app");
    // 5 registry packages; local code and the git dependency are excluded.
    assert_eq!(project.scanned_count(), 5);
    assert_eq!(project.direct_count(), 2);
    assert_eq!(project.unscannable, vec!["forked-thing 0.3.0".to_string()]);

    let time = project
        .packages
        .iter()
        .find(|p| p.package.name == "time")
        .expect("time must be in the tree");

    // The whole point: we know *why* time is present.
    assert_eq!(
        time.origin,
        Origin::Transitive {
            depth: 2,
            path: vec!["chrono".into(), "time".into()],
        }
    );
}

#[test]
fn triages_a_transitive_finding_end_to_end() {
    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &time_advisories()).unwrap();

    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];

    assert_eq!(finding.package, "time");
    assert_eq!(finding.version, version("0.1.44"));
    assert_eq!(finding.advisory, "RUSTSEC-2020-0071");
    assert_eq!(finding.project, "vulnerable-app");

    // Medium + patch available => schedule it, do not scream about it.
    assert_eq!(finding.priority, Priority::Plan);
    assert_eq!(
        finding.fix,
        Fix::Available {
            version: version("0.2.0")
        }
    );

    // The rationale must explain both the severity and the ownership.
    assert!(finding.rationale.contains("CVSS 6.2"));
    assert!(finding.rationale.contains("chrono → time"));

    assert_eq!(report.summary.projects, 1);
    assert_eq!(report.summary.packages_scanned, 5);
    assert_eq!(report.summary.packages_unscannable, 1);
    assert_eq!(report.summary.medium, 1);
    assert_eq!(report.summary.direct, 0);
}

#[test]
fn discovery_recurses_and_prunes_build_directories() {
    let report = pulse::scan_offline(&[fixture("nested")], &time_advisories()).unwrap();

    // inner-app is found; the copy under `target/` must never be scanned.
    assert_eq!(report.projects, vec!["inner-app".to_string()]);
    assert_eq!(report.summary.projects, 1);
    assert!(!report
        .findings
        .iter()
        .any(|f| f.project == "should-never-be-scanned"));
}

#[test]
fn overlapping_paths_are_not_double_counted() {
    let report = pulse::scan_offline(
        &[fixture("nested"), fixture("nested/inner-app")],
        &time_advisories(),
    )
    .unwrap();

    assert_eq!(report.summary.projects, 1);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn direct_dependency_of_a_second_project_is_reported_separately() {
    let report = pulse::scan_offline(
        &[fixture("vulnerable-app"), fixture("nested/inner-app")],
        &time_advisories(),
    )
    .unwrap();

    assert_eq!(report.summary.projects, 2);
    assert_eq!(report.findings.len(), 2);

    // Same advisory, same package, different ownership — and the direct one
    // sorts first because it is the cheaper fix.
    assert_eq!(report.findings[0].project, "inner-app");
    assert!(report.findings[0].origin.is_direct());
    assert!(report.findings[0].rationale.contains("bump yourself"));

    assert_eq!(report.findings[1].project, "vulnerable-app");
    assert!(!report.findings[1].origin.is_direct());

    assert_eq!(report.summary.direct, 1);
}

#[test]
fn clean_tree_produces_an_empty_report() {
    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &Advisories::new()).unwrap();

    assert!(report.is_clean());
    assert_eq!(report.summary.findings, 0);
    // Still reports what it looked at, so "clean" is verifiable.
    assert_eq!(report.summary.packages_scanned, 5);
    assert!(!report.exceeds(Priority::Note));
}

#[test]
fn human_output_is_readable_and_uncoloured_when_piped() {
    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &time_advisories()).unwrap();

    let mut buffer = Vec::new();
    render::render(
        &mut buffer,
        &report,
        &Delta::default(),
        Format::Human,
        Layout::of(100),
        Style::Plain,
        View::default(),
    )
    .unwrap();
    let text = String::from_utf8(buffer).unwrap();

    assert!(
        !text.contains('\x1b'),
        "piped output must contain no escapes"
    );
    // Plain-language bucket labels, not internal jargon.
    assert!(text.contains("when you can"));
    // Stats banner sits above the findings.
    assert!(text.find("pulse").unwrap() < text.find("when you can").unwrap());
    assert!(text.contains("time 0.1.44"));
    assert!(text.contains("→ 0.2.0"));
    assert!(text.contains("RUSTSEC-2020-0071"));
    assert!(text.contains("chrono → time"));
    // Doki greets the user.
    // Blind spots are disclosed rather than hidden.
    assert!(text.contains("git/path"));
    // 0.1 → 0.2 is breaking under Cargo's rules, so it is labelled honestly
    // rather than sold as a quick win.
    assert!(text.contains("breaking"));
    // A concrete instruction, not just a diagnosis.
    assert!(text.contains("needs upstream") || text.contains("edit Cargo.toml"));
    // How long the exposure has been public.
    assert!(text.contains("1900d"));
}

#[test]
fn json_output_is_machine_readable() {
    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &time_advisories()).unwrap();

    let mut buffer = Vec::new();
    render::render(
        &mut buffer,
        &report,
        &Delta::default(),
        Format::Json,
        Layout::of(100),
        Style::Plain,
        View::default(),
    )
    .unwrap();

    let value: serde_json::Value = serde_json::from_slice(&buffer).unwrap();
    assert_eq!(value["findings"][0]["package"], "time");
    assert_eq!(value["findings"][0]["priority"], "plan");
    assert_eq!(value["findings"][0]["fix"]["version"], "0.2.0");
    assert_eq!(value["findings"][0]["origin"]["depth"], 2);
    assert_eq!(value["summary"]["packages_scanned"], 5);
}

#[test]
fn a_severe_patchable_finding_trips_the_default_gate() {
    // Same package, but an advisory severe enough to demand action.
    let mut severe = rustsec_2020_0071();
    severe.severity = Severity {
        rating: Rating::Critical,
        score: Some(9.8),
        vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
        provenance: Provenance::Cvss3,
    };

    let mut db = Advisories::new();
    db.insert(
        Package::new(Ecosystem::CratesIo, "time", version("0.1.44")),
        vec![severe],
    );

    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &db).unwrap();

    assert_eq!(report.findings[0].priority, Priority::Act);
    assert!(report.exceeds(Priority::Act));
    assert_eq!(report.summary.act, 1);
    assert_eq!(report.summary.critical, 1);
}

#[test]
fn missing_paths_report_an_error_rather_than_a_clean_scan() {
    // The dangerous failure mode for a security tool: scanning nothing and
    // announcing success.
    let result = pulse::scan_offline(&[fixture("does-not-exist")], &Advisories::new());
    assert!(result.is_err());
}

// ── Scope control ───────────────────────────────────────────────────────────

/// Runs the real pipeline up to (but not including) the network, so scope
/// filtering can be tested without hitting OSV.
fn scan_with_scope(paths: &[PathBuf], exclude: &[&str], ignored: &[&str]) -> pulse::triage::Report {
    let exclude: Vec<String> = exclude.iter().map(|s| s.to_string()).collect();
    let ignored: Vec<String> = ignored.iter().map(|s| s.to_string()).collect();
    pulse::scan_offline_scoped(paths, &time_advisories(), &exclude, &ignored).unwrap()
}

#[test]
fn report_names_the_projects_in_scope() {
    let report = scan_with_scope(&[fixture("nested"), fixture("vulnerable-app")], &[], &[]);

    // The header can only say "which projects?" if the report carries the names.
    assert_eq!(
        report.projects,
        vec!["inner-app".to_string(), "vulnerable-app".to_string()]
    );
}

#[test]
fn exclude_removes_a_project_and_records_why() {
    let report = scan_with_scope(
        &[fixture("nested"), fixture("vulnerable-app")],
        &["vulnerable"],
        &[],
    );

    assert_eq!(report.projects, vec!["inner-app".to_string()]);
    assert_eq!(report.skipped_projects.len(), 1);
    assert_eq!(report.skipped_projects[0].name, "vulnerable-app");
    // The reason uses the user's own vocabulary so the effect is traceable.
    assert!(report.skipped_projects[0].reason.contains("--exclude"));

    // And its findings are genuinely gone, not merely hidden.
    assert!(report.findings.iter().all(|f| f.project == "inner-app"));
}

#[test]
fn ignored_projects_are_skipped_but_still_disclosed() {
    let report = scan_with_scope(
        &[fixture("nested"), fixture("vulnerable-app")],
        &[],
        &["inner"],
    );

    assert_eq!(report.projects, vec!["vulnerable-app".to_string()]);
    assert_eq!(report.skipped_projects[0].name, "inner-app");
    assert!(report.skipped_projects[0].reason.contains("ignored"));
}

#[test]
fn scope_matching_is_case_insensitive_and_matches_paths() {
    // By name, in the wrong case.
    let report = scan_with_scope(&[fixture("vulnerable-app")], &["VULNERABLE-APP"], &[]);
    assert!(report.projects.is_empty());

    // By a path fragment rather than the project name.
    let report = scan_with_scope(&[fixture("nested")], &["nested"], &[]);
    assert!(report.projects.is_empty());
}

#[test]
fn an_empty_pattern_never_matches_everything() {
    // A stray `--exclude ""` must not silently disable the whole scan.
    let report = scan_with_scope(&[fixture("vulnerable-app")], &[""], &[]);
    assert_eq!(report.projects, vec!["vulnerable-app".to_string()]);
    assert!(report.skipped_projects.is_empty());
}

#[test]
fn skipped_projects_survive_note_filtering() {
    // `--show-notes` rebuilds the report; the blind-spot list must not be lost.
    let report = scan_with_scope(
        &[fixture("nested"), fixture("vulnerable-app")],
        &["nested"],
        &[],
    );
    assert_eq!(report.skipped_projects.len(), 1);
}

#[test]
fn duplicate_project_names_are_disambiguated() {
    // `tests/fixtures/dup/` holds two lockfiles whose root packages share a name.
    // Left alone they would collide in the finding fingerprint and merge.
    let report = scan_with_scope(&[fixture("dup")], &[], &[]);

    assert_eq!(report.projects.len(), 2);
    assert_ne!(
        report.projects[0], report.projects[1],
        "names must be unique or findings from different projects merge"
    );
    assert!(report.projects.iter().all(|n| n.starts_with("twin")));

    // Both projects' findings survive as separate entries.
    assert_eq!(report.findings.len(), 2);
    let mut projects: Vec<&str> = report.findings.iter().map(|f| f.project.as_str()).collect();
    projects.sort();
    projects.dedup();
    assert_eq!(projects.len(), 2);
}

// ── --fix planning ──────────────────────────────────────────────────────────

#[test]
fn fix_plans_only_compatible_upgrades() {
    use std::collections::BTreeMap;

    // The vulnerable-app fixture's only finding is `time 0.1.44 → 0.2.23`, which
    // is breaking under Cargo's 0.x rules. `--fix` must refuse to touch it.
    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &time_advisories()).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].effort,
        Some(pulse::domain::Effort::Breaking)
    );

    let mut roots = BTreeMap::new();
    roots.insert("vulnerable-app".to_string(), fixture("vulnerable-app"));

    assert!(
        pulse::fix::plan(&report, &roots).is_empty(),
        "--fix must never apply a breaking change on its own"
    );
}

#[test]
fn fix_plan_needs_a_known_project_root() {
    use std::collections::BTreeMap;

    let report = pulse::scan_offline(&[fixture("vulnerable-app")], &time_advisories()).unwrap();
    // No roots supplied: running cargo in a guessed directory would be worse than
    // doing nothing.
    assert!(pulse::fix::plan(&report, &BTreeMap::new()).is_empty());
}
