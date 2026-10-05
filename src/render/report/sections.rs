//! Section rendering: one priority bucket (Act, Plan, Monitor, Note).
//!
//! Each section has an icon, a label, and a count. The sections are rendered in
//! priority order, with the most urgent first. Empty sections are skipped.
//!
//! ## Why sections exist
//!
//! The report is a work queue, not a list. Sections group findings by what to do
//! about them, not by what they are. This is why the section labels are actions
//! ("fix now", "when you can", "blocked upstream") rather than severity levels.
//!
//! ## Grouping within sections
//!
//! Findings are grouped by package: four advisories in one crate are one
//! `cargo update`. The group shows the highest fix among the members, so that
//! single upgrade clears all of them. This is the key insight that makes the
//! report actionable (you don't need to read 47 individual entries, you need
//! to run 3 commands).

use std::io::Write;

use crate::error::Result;
use crate::triage::{Priority, Report};

use crate::render::layout::Layout;
use crate::render::line::Line;
use crate::render::style::{Style, CORAL, IRIS, SKY, SLATE};

use super::group::Group;

/// Renders one priority bucket.
pub(crate) fn section(
    out: &mut dyn Write,
    report: &Report,
    bucket: Priority,
    layout: Layout,
    style: Style,
    view: super::View,
) -> Result<()> {
    let groups: Vec<Group> = group(report)
        .into_iter()
        .filter(|g| g.priority == bucket)
        .collect();
    if groups.is_empty() {
        return Ok(());
    }

    let (label, icon, colour) = match bucket {
        Priority::Act => ("fix now", "◆", CORAL),
        Priority::Plan => ("when you can", "◇", SKY),
        Priority::Monitor => ("blocked upstream", "○", IRIS),
        Priority::Note => ("worth knowing", "·", SLATE),
    };

    let issues: usize = groups.iter().map(|g| g.members.len()).sum();
    writeln!(
        out,
        "{}",
        Line::indent(2)
            .paint(style, colour, icon)
            .plain(" ")
            .bold(style, colour, label)
            .dim(style, &format!("   {issues}"))
    )?;

    // Show project names when there are multiple projects in scope
    let show_project = report.projects.len() > 1;

    for group in &groups {
        group.write(out, layout, style, view, show_project)?;
    }
    writeln!(out)?;
    Ok(())
}

/// Groups findings by package within one project.
///
/// The unit of work is a package upgrade, not an advisory: four advisories in one
/// crate are one `cargo update`.
fn group(report: &Report) -> Vec<Group<'_>> {
    let mut groups: Vec<Group> = Vec::new();

    for finding in &report.findings {
        let existing = groups.iter_mut().find(|g| {
            g.package == finding.package
                && g.project == finding.project
                && g.version == finding.version.to_string()
        });

        match existing {
            Some(group) => {
                // You perform one upgrade, at the urgency of the worst thing it fixes.
                group.priority = group.priority.min(finding.priority);
                if let Some(candidate) = finding.fix.version() {
                    let improves = match group.target {
                        Some(current) => candidate > current,
                        None => true,
                    };
                    if improves {
                        group.target = Some(candidate);
                        group.effort = finding.effort;
                        group.remediation = finding.remediation.as_ref();
                    }
                }
                group.members.push(finding);
            }
            None => groups.push(Group {
                package: &finding.package,
                version: finding.version.to_string(),
                project: &finding.project,
                target: finding.fix.version(),
                effort: finding.effort,
                remediation: finding.remediation.as_ref(),
                origin: &finding.origin,
                priority: finding.priority,
                members: vec![finding],
            }),
        }
    }

    groups
}
