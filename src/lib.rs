//! pulse — triage known vulnerabilities in a dependency tree.
//!
//! # Layering
//!
//! Dependencies point in one direction only:
//!
//! ```text
//! domain   ← pure types and the logic that belongs to them; no I/O
//!   ↑
//! lockfile ← disk    → domain      ┐ the only two impure modules
//! osv      ← network → domain      ┘
//!   ↑
//! triage   ← domain  → Report      pure: correlate, prioritise, explain
//!   ↑
//! render   ← Report  → bytes       pure formatting, decides nothing
//!   ↑
//! cli/lib  ← wiring, exit codes
//! ```
//!
//! The shape is "functional core, imperative shell". All the logic worth getting
//! right — CVSS scoring, version-range matching, prioritisation — is a pure
//! function over owned values, so its tests need no network, no temporary
//! directories, and no mocking. I/O is pushed to two leaf modules that contain
//! no decisions.
//!
//! This is also why there are no traits here. The reference implementation
//! defined `Parser`, `AdvisorySource`, and `Store`, each with exactly one
//! implementation, to make the code testable. Separating pure logic from I/O
//! achieves the same testability with no indirection at all: a trait with one
//! implementor is a layer of misdirection charging rent.

pub mod cli;
pub mod domain;
pub mod error;
pub mod fix;
pub mod history;
pub mod lockfile;
pub mod osv;
pub mod progress;
pub mod render;
pub mod triage;

use std::io::Write;
use std::path::Path;

use domain::{Date, Project};
use error::Result;
use history::History;
use render::Layout;
use triage::{Priority, Report, SkippedProject};

/// Outcome of a run, so the caller can choose an exit code without re-deriving
/// the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No finding met the configured gate.
    Pass,
    /// At least one finding met the gate.
    Gated,
}

/// Everything the caller decides before a run.
#[derive(Debug, Clone)]
pub struct Options {
    pub format: render::Format,
    pub style: render::Style,
    pub view: render::View,
    /// `None` never fails the run.
    pub gate: Option<Priority>,
    /// Include informational (unmaintained/yanked) notices.
    pub show_notes: bool,
    /// Read and write the progress file.
    pub history: bool,
    /// Skip projects matching any of these, for this run only.
    pub exclude: Vec<String>,
    /// Add to the remembered skip list.
    pub ignore: Vec<String>,
    /// Remove from the remembered skip list.
    pub unignore: Vec<String>,
    /// List discovered projects and stop, without querying the network.
    pub list_projects: bool,
    /// Apply semver-compatible upgrades, then re-scan.
    pub fix: bool,
    /// Use the on-disk advisory cache.
    pub cache: bool,
    /// Resolved terminal widths.
    pub layout: Layout,
}

/// Scans the given paths and writes a report.
///
/// The whole program in one readable sequence: discover, parse, look up, triage,
/// score progress, render. Each step is a plain function call and the data flows
/// one way.
pub fn run(
    paths: &[std::path::PathBuf],
    out: &mut dyn Write,
    options: &Options,
) -> Result<Outcome> {
    let mut history = if options.history {
        History::load()
    } else {
        History::default()
    };

    // Apply requested skip-list changes before scanning, so `pulse --ignore x`
    // demonstrates its own effect immediately.
    let ignore_changed = update_ignored(&mut history.ignored_projects, options);

    let today = Date::today().unwrap_or(Date {
        year: 1970,
        month: 1,
        day: 1,
    });

    // The animation owns stderr for the duration of the scan. `Live` erases its
    // region and restores the cursor in `Drop`, so no error path below can leave
    // the terminal in a broken state.
    let (mut report, projects) = {
        let live = render::Live::start(options.style);
        let progress = live.reporter();

        let projects = discover_projects(paths, &progress)?;
        let (projects, skipped) = partition(projects, &options.exclude, &history.ignored_projects);

        // `--projects` is pure discovery: no network call.
        if options.list_projects {
            drop(live);
            render::projects(out, &projects, &skipped, options.layout, options.style)?;
            if ignore_changed && options.history {
                persist_ignores(&history);
            }
            return Ok(Outcome::Pass);
        }

        // One request covers every project: the same crate at the same version in
        // ten repositories is one query, not ten.
        let packages = unique_packages(&projects);
        let advisories = osv::Client::new(options.cache).advisories(&packages, &progress)?;

        let mut report = triage_with_progress(&projects, &advisories, &progress);
        if !options.show_notes {
            report = without_notes(report);
        }
        report.skipped_projects = skipped;
        (report, projects)
    };

    let mut delta = progress::compare(&history, &report, today);
    let mut view = options.view;

    // `--fix` applies the safe upgrades, then re-scans so the user *sees* the
    // findings disappear. Closing the loop in one command is the point: completion
    // is the reward, and a second manual invocation dilutes it.
    if options.fix {
        let roots: std::collections::BTreeMap<String, std::path::PathBuf> = projects
            .iter()
            .map(|p| (p.name.clone(), p.root.clone()))
            .collect();
        let plan = fix::plan(&report, &roots);

        if plan.is_empty() {
            render::nothing_to_fix(out, options.layout, options.style)?;
        } else {
            let applied = {
                let live = render::Live::start(options.style);
                fix::apply(&plan, &live.reporter())
            };
            render::fixed(out, &applied, options.layout, options.style)?;

            // Re-read the lockfiles: they changed underneath us.
            let live = render::Live::start(options.style);
            let progress = live.reporter();
            let projects = discover_projects(paths, &progress)?;
            let (projects, skipped) =
                partition(projects, &options.exclude, &history.ignored_projects);
            let packages = unique_packages(&projects);
            let advisories = osv::Client::new(options.cache).advisories(&packages, &progress)?;

            report = triage_with_progress(&projects, &advisories, &progress);
            if !options.show_notes {
                report = without_notes(report);
            }
            report.skipped_projects = skipped;
            drop(live);

            delta = progress::compare(&history, &report, today);
            view.after_fix = true;
        }
    }

    render::render(
        out,
        &report,
        &delta,
        options.format,
        options.layout,
        options.style,
        view,
    )?;

    // Persisting progress must never take down a successful report.
    if options.history || ignore_changed {
        if let Err(error) =
            History::save(&report, &delta, &today.to_iso(), &history.ignored_projects)
        {
            eprintln!("pulse: note: could not save progress: {error}");
        }
    }

    Ok(match options.gate {
        Some(threshold) if report.exceeds(threshold) => Outcome::Gated,
        _ => Outcome::Pass,
    })
}

/// Writes only the skip list, for the `--projects` path which produces no report.
fn persist_ignores(history: &History) {
    let mut stored = history.clone();
    stored.version = 1;
    if let Err(error) = stored.write() {
        eprintln!("pulse: note: could not save ignore list: {error}");
    }
}

/// Discovery and parsing, narrated.
///
/// The three stages here are genuinely separate pieces of work, and reporting
/// them separately is what turns a silent pause into something worth watching.
fn discover_projects(
    paths: &[std::path::PathBuf],
    progress: &render::Reporter,
) -> Result<Vec<Project>> {
    progress.begin(render::Stage::Discover);
    let mut lockfiles = Vec::new();
    for path in paths {
        for lockfile in lockfile::discover(path)? {
            // Overlapping arguments (`pulse . ./sub`) must not double-count.
            if lockfiles.contains(&lockfile) {
                continue;
            }
            progress.detail(lockfile.display().to_string());
            lockfiles.push(lockfile);
        }
    }
    lockfiles.sort();
    progress.finish(
        render::Stage::Discover,
        format!(
            "{} {}",
            lockfiles.len(),
            if lockfiles.len() == 1 {
                "project"
            } else {
                "projects"
            }
        ),
    );
    progress.dwell();

    progress.begin(render::Stage::Parse);
    progress.total(lockfiles.len());
    let mut projects = Vec::new();
    for lockfile in &lockfiles {
        let project = lockfile::parse(lockfile)?;
        progress.detail(format!(
            "{} · {} packages",
            project.name,
            project.scanned_count()
        ));
        progress.tick();
        projects.push(project);
    }
    let packages: usize = projects.iter().map(Project::scanned_count).sum();
    progress.finish(render::Stage::Parse, format!("{packages} packages"));
    progress.dwell();

    progress.begin(render::Stage::Graph);
    projects.sort_by(|a, b| a.lockfile.cmp(&b.lockfile));
    disambiguate(&mut projects);
    let direct: usize = projects.iter().map(Project::direct_count).sum();
    progress.detail(format!("{direct} direct dependencies"));
    progress.detail(format!(
        "{} reached transitively",
        packages.saturating_sub(direct)
    ));
    progress.finish(
        render::Stage::Graph,
        format!("{direct} direct · {} deep", packages.saturating_sub(direct)),
    );
    progress.dwell();

    Ok(projects)
}

/// Triage, with the scoring and merging steps surfaced.
///
/// The work is done by [`triage::triage`]; this only narrates it. Counting the
/// evidence afterwards keeps the pure function pure.
fn triage_with_progress(
    projects: &[Project],
    advisories: &osv::Advisories,
    progress: &render::Reporter,
) -> Report {
    progress.begin(render::Stage::Score);
    for advisory in advisories.values().flatten() {
        if let (Some(score), Some(vector)) = (advisory.severity.score, &advisory.severity.vector) {
            progress.detail(format!("{vector}  →  {score:.1}"));
        }
    }
    let scored = advisories
        .values()
        .flatten()
        .filter(|a| a.severity.score.is_some())
        .count();
    let unrated = advisories.values().flatten().count() - scored;
    progress.finish(
        render::Stage::Score,
        format!("{scored} scored · {unrated} unrated"),
    );
    progress.dwell();

    progress.begin(render::Stage::Resolve);
    let report = triage::triage(projects, advisories);
    for finding in &report.findings {
        if let Some(version) = finding.fix.version() {
            progress.detail(format!(
                "{} {} → {version}",
                finding.package, finding.version
            ));
        }
    }
    let patchable = report
        .findings
        .iter()
        .filter(|f| f.fix.is_available())
        .count();
    progress.finish(render::Stage::Resolve, format!("{patchable} patchable"));
    progress.dwell();

    progress.begin(render::Stage::Merge);
    let raw: usize = advisories.values().map(Vec::len).sum();
    progress.detail(format!(
        "{raw} advisories → {} findings",
        report.findings.len()
    ));
    progress.finish(
        render::Stage::Merge,
        format!("{raw} → {}", report.findings.len()),
    );
    progress.dwell();

    progress.begin(render::Stage::Triage);
    let summary = &report.summary;
    progress.detail(format!("{} urgent", summary.act));
    progress.detail(format!("{} queued", summary.plan));
    progress.finish(
        render::Stage::Triage,
        format!("{} urgent · {} queued", summary.act, summary.plan),
    );
    progress.dwell();

    report
}

/// Applies `--ignore` / `--unignore` to the remembered skip list, returning
/// whether anything changed.
fn update_ignored(ignored: &mut Vec<String>, options: &Options) -> bool {
    let mut changed = false;

    for name in &options.ignore {
        if !ignored.iter().any(|e| e.eq_ignore_ascii_case(name)) {
            ignored.push(name.clone());
            changed = true;
        }
    }

    for name in &options.unignore {
        let before = ignored.len();
        ignored.retain(|e| !e.eq_ignore_ascii_case(name));
        changed |= ignored.len() != before;
    }

    ignored.sort();
    changed
}

/// Splits discovered projects into those to scan and those to skip.
///
/// Skipped projects carry the reason they were skipped, so the report can say
/// *why* something was never examined.
fn partition(
    projects: Vec<Project>,
    exclude: &[String],
    ignored: &[String],
) -> (Vec<Project>, Vec<SkippedProject>) {
    let mut kept = Vec::new();
    let mut skipped = Vec::new();

    for project in projects {
        if let Some(pattern) = matching(&project, exclude) {
            skipped.push(SkippedProject {
                name: project.name,
                reason: format!("--exclude {pattern}"),
            });
            continue;
        }
        if let Some(pattern) = matching(&project, ignored) {
            skipped.push(SkippedProject {
                name: project.name,
                reason: format!("ignored: {pattern}"),
            });
            continue;
        }
        kept.push(project);
    }

    (kept, skipped)
}

/// Whether a project matches any pattern, and which one.
///
/// Case-insensitive substring match against the project name or its lockfile
/// path — forgiving enough to type from memory. `--projects` exists so the effect
/// of a pattern can be checked before anyone relies on it.
fn matching<'a>(project: &Project, patterns: &'a [String]) -> Option<&'a String> {
    let name = project.name.to_ascii_lowercase();
    let path = project.lockfile.to_string_lossy().to_ascii_lowercase();

    patterns.iter().find(|pattern| {
        let needle = pattern.trim().to_ascii_lowercase();
        !needle.is_empty() && (name.contains(&needle) || path.contains(&needle))
    })
}

/// Discovers and parses every lockfile under the given paths, without narration.
/// Used by the offline test helpers.
fn load_projects(paths: &[std::path::PathBuf]) -> Result<Vec<Project>> {
    let mut projects = Vec::new();
    let mut seen = Vec::new();

    for path in paths {
        for lockfile in lockfile::discover(path)? {
            // Overlapping arguments (`pulse . ./sub`) must not double-count.
            if seen.contains(&lockfile) {
                continue;
            }
            seen.push(lockfile.clone());
            projects.push(lockfile::parse(&lockfile)?);
        }
    }

    projects.sort_by(|a, b| a.lockfile.cmp(&b.lockfile));
    disambiguate(&mut projects);
    Ok(projects)
}

/// Makes project names unique.
///
/// Two directories can easily produce the same project name — a crate and a
/// vendored copy of itself, or `foo/` and `archive/foo/`. That is not merely
/// confusing in the report: a finding's identity is `project|package|advisory`,
/// so duplicate names would collide in the triage de-duplicator and in the
/// progress file, silently merging two different projects' findings into one.
///
/// Colliding names gain the nearest distinguishing parent directory.
fn disambiguate(projects: &mut [Project]) {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for project in projects.iter() {
        *counts.entry(project.name.clone()).or_default() += 1;
    }

    for project in projects.iter_mut() {
        if counts.get(&project.name).copied().unwrap_or(0) < 2 {
            continue;
        }
        if let Some(parent) = project
            .root
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| *n != project.name)
        {
            project.name = format!("{} ({parent})", project.name);
        } else if let Some(grandparent) = project
            .root
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
        {
            project.name = format!("{} ({grandparent})", project.name);
        }
    }
}

/// Deduplicates packages across projects before querying.
fn unique_packages(projects: &[Project]) -> Vec<domain::Package> {
    let mut packages: Vec<domain::Package> = projects
        .iter()
        .flat_map(|p| p.packages.iter().map(|r| r.package.clone()))
        .collect();
    packages.sort();
    packages.dedup();
    packages
}

/// Drops informational findings and recomputes the counts that referenced them.
fn without_notes(report: Report) -> Report {
    let projects = report.projects;
    let skipped = report.skipped_projects;
    let findings: Vec<triage::Finding> = report
        .findings
        .into_iter()
        .filter(|f| f.priority != Priority::Note)
        .collect();

    let mut summary = report.summary;
    summary.findings = findings.len();
    summary.note = 0;

    Report {
        projects,
        findings,
        summary,
        skipped_projects: skipped,
    }
}

/// Convenience wrapper used by the integration tests: the whole pipeline except
/// the network call, so a report can be produced from fixtures on disk.
pub fn scan_offline(paths: &[std::path::PathBuf], advisories: &osv::Advisories) -> Result<Report> {
    let projects = load_projects(paths)?;
    Ok(triage::triage(&projects, advisories))
}

/// Like [`scan_offline`], but exercising the scope filters too.
///
/// Exists so the integration suite can cover `--exclude` / `--ignore` against
/// real fixtures on disk without a network call.
pub fn scan_offline_scoped(
    paths: &[std::path::PathBuf],
    advisories: &osv::Advisories,
    exclude: &[String],
    ignored: &[String],
) -> Result<Report> {
    let discovered = load_projects(paths)?;
    let (projects, skipped) = partition(discovered, exclude, ignored);
    let mut report = triage::triage(&projects, advisories);
    report.skipped_projects = skipped;
    Ok(report)
}

/// Parses a single lockfile. Exposed for tests and for callers embedding pulse.
pub fn parse_lockfile(path: &Path) -> Result<Project> {
    lockfile::parse(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{Ecosystem, Origin, Package, ResolvedPackage};
    use semver::Version;
    use std::path::PathBuf;

    fn project(name: &str, packages: &[(&str, &str)]) -> Project {
        Project {
            name: name.into(),
            root: PathBuf::from("/tmp"),
            lockfile: PathBuf::from("/tmp/Cargo.lock"),
            ecosystem: Ecosystem::CratesIo,
            packages: packages
                .iter()
                .map(|(n, v)| ResolvedPackage {
                    package: Package::new(Ecosystem::CratesIo, *n, Version::parse(v).unwrap()),
                    origin: Origin::Direct,
                })
                .collect(),
            unscannable: vec![],
        }
    }

    #[test]
    fn deduplicates_packages_across_projects() {
        let projects = [
            project("a", &[("serde", "1.0.0"), ("time", "0.1.44")]),
            project("b", &[("serde", "1.0.0"), ("clap", "4.0.0")]),
        ];

        let packages = unique_packages(&projects);
        assert_eq!(packages.len(), 3, "serde must be queried once, not twice");

        // Sorted for a stable request body.
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["clap", "serde", "time"]);
    }

    #[test]
    fn distinct_versions_are_separate_queries() {
        let projects = [
            project("a", &[("serde", "1.0.0")]),
            project("b", &[("serde", "1.0.1")]),
        ];
        assert_eq!(unique_packages(&projects).len(), 2);
    }
}
