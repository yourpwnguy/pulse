//! The action line: the single next command to run.
//!
//! One command, with its payoff. Presenting eight equal options is how a report
//! gets postponed.

use std::io::Write;

use crate::domain::Effort;
use crate::error::Result;
use crate::triage::Report;

use crate::render::layout::Layout;
use crate::render::line::{truncate, Line};
use crate::render::style::{Style, GOLD};

use super::Headline;

/// Renders the single next action line, if one exists.
pub(crate) fn action(
    out: &mut dyn Write,
    report: &Report,
    headline: &Headline,
    layout: Layout,
    style: Style,
    view: super::View,
) -> Result<()> {
    let Some((command, count)) = batches(report, view.after_fix).into_iter().next() else {
        return Ok(());
    };

    let payoff = if count == headline.issues {
        format!("fixes all {count}")
    } else {
        format!("fixes {count} of {}", headline.issues)
    };

    // The command is the one thing that must never be truncated — it has to stay
    // copy-pasteable. If the payoff will not fit beside it, the payoff moves down.
    let command = truncate(&command, layout.body().saturating_sub(2));
    let mut line = Line::indent(2)
        .bold(style, GOLD, "▸ ")
        .bold(style, GOLD, &command);

    if line.width() + 2 + payoff.chars().count() <= layout.total {
        line = line
            .pad_to(layout.total.saturating_sub(payoff.chars().count()))
            .dim(style, &payoff);
        writeln!(out, "{line}")?;
    } else {
        writeln!(out, "{line}")?;
        writeln!(
            out,
            "{}",
            Line::indent(4).dim(style, &truncate(&payoff, layout.room(4)))
        )?;
    }

    // Only advertise --fix when it would actually do something.
    if headline.fixable > 1 {
        writeln!(
            out,
            "{}",
            Line::indent(4)
                .dim(style, "or ")
                .paint(style, GOLD, "pulse --fix")
                .dim(style, &format!("  to apply all {} ", headline.fixable))
        )?;
    }
    writeln!(out)?;
    Ok(())
}

/// Groups compatible fixes by the command that applies them, most productive
/// first. Breaking changes are excluded: they are decisions, not commands.
///
/// When `after_fix` is true, generates `cargo add` commands instead of
/// `cargo update` for packages that are capped by Cargo.toml requirements.
fn batches(report: &Report, after_fix: bool) -> Vec<(String, usize)> {
    let mut groups: Vec<(String, usize)> = Vec::new();
    for finding in &report.findings {
        if !finding.effort.is_some_and(Effort::is_compatible) {
            continue;
        }
        // After a failed fix, show the command that actually works: cargo add
        let command = if after_fix {
            finding
                .fix
                .version()
                .map(|v| format!("cargo add {}@{v}", finding.package))
                .or_else(|| finding.remediation.clone())
        } else {
            finding.remediation.clone()
        };
        let Some(command) = command else {
            continue;
        };
        match groups.iter_mut().find(|(existing, _)| *existing == command) {
            Some((_, count)) => *count += 1,
            None => groups.push((command, 1)),
        }
    }
    groups.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    groups
}
