//! Presentation. Takes a finished [`Report`] and writes it somewhere.
//!
//! Rendering is strictly downstream of triage: nothing here decides anything, it
//! only formats decisions already made. That is why the JSON and human renderers
//! cannot disagree about severity or priority (neither of them computes either).

mod json;
pub mod layout;
pub mod line;
pub mod live;
pub mod mascot;
pub mod panel;
mod projects;
mod report;
pub mod style;

use std::io::Write;

use crate::domain::Project;
use crate::error::Result;
use crate::progress::Delta;
use crate::triage::{Report, SkippedProject};

pub use layout::Layout;
pub use live::{Live, Reporter, Stage};
pub use report::View;
pub use style::Style;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Aligned text for a person reading a terminal.
    Human,
    /// The [`Report`] structure verbatim, for a machine.
    Json,
}

pub fn render(
    out: &mut dyn Write,
    report: &Report,
    delta: &Delta,
    format: Format,
    layout: Layout,
    style: Style,
    view: View,
) -> Result<()> {
    match format {
        Format::Human => report::render(out, report, delta, layout, style, view),
        Format::Json => json::render(out, report, delta),
    }
}

/// Lists discovered projects instead of scanning them.
pub fn projects(
    out: &mut dyn Write,
    projects: &[Project],
    skipped: &[SkippedProject],
    layout: Layout,
    style: Style,
) -> Result<()> {
    self::projects::render(out, projects, skipped, layout, style)
}

/// Reports that there was nothing `--fix` could safely do.
pub fn nothing_to_fix(out: &mut dyn Write, layout: Layout, style: Style) -> Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "{}",
        line::Line::indent(2)
            .paint(style, style::IRIS, mascot::Mood::Think.face())
            .plain("  ")
            .dim(
                style,
                &line::truncate(
                    "nothing here can be upgraded safely \u{2014} what is left needs you",
                    layout.room(14)
                )
            )
    )?;
    Ok(())
}

/// Reports what `--fix` did, and (crucially) what it did *not* manage.
///
/// Anything that did not reach the patched version is reported as still
/// vulnerable, with the reason. Claiming a fix that did not land is the worst
/// thing this tool could do.
pub fn fixed(
    out: &mut dyn Write,
    applied: &[crate::fix::Applied],
    layout: Layout,
    style: Style,
) -> Result<()> {
    use crate::fix::Outcome;
    use line::Line;

    let resolved: Vec<_> = applied.iter().filter(|a| a.resolved()).collect();
    let short: Vec<_> = applied.iter().filter(|a| !a.resolved()).collect();
    let cleared: usize = resolved.iter().map(|a| a.clears).sum();

    writeln!(out)?;

    if !resolved.is_empty() {
        let mood = if short.is_empty() {
            mascot::Mood::Cheer
        } else {
            mascot::Mood::Happy
        };
        writeln!(
            out,
            "{}",
            Line::indent(2)
                .paint(style, mood.colour(), mood.face())
                .plain("  ")
                .bold(style, style::MINT, "verified")
                .plain("  ")
                .dim(
                    style,
                    &format!(
                        "{} {} upgraded · {cleared} {} gone",
                        resolved.len(),
                        if resolved.len() == 1 {
                            "package"
                        } else {
                            "packages"
                        },
                        if cleared == 1 { "issue" } else { "issues" },
                    )
                )
        )?;
        for entry in &resolved {
            writeln!(
                out,
                "{}",
                Line::indent(4)
                    .paint(style, style::MINT, "✓")
                    .plain(" ")
                    .paint(style, style::SKY, &entry.package)
                    .pad_to(28)
                    .dim(style, &entry.summary())
            )?;
        }
    }

    // The important half. An upgrade that did not land is still a vulnerability,
    // and it is reported with the reason so the next step is obvious.
    if !short.is_empty() {
        if !resolved.is_empty() {
            writeln!(out)?;
        }
        let mood = mascot::Mood::Worried;
        writeln!(
            out,
            "{}",
            Line::indent(2)
                .paint(style, mood.colour(), mood.face())
                .plain("  ")
                .bold(style, style::GOLD, "still affected")
                .plain("  ")
                .dim(
                    style,
                    &format!(
                        "{} {} did not reach the patch",
                        short.len(),
                        if short.len() == 1 {
                            "package"
                        } else {
                            "packages"
                        }
                    )
                )
        )?;
        for entry in &short {
            writeln!(
                out,
                "{}",
                Line::indent(4)
                    .paint(style, style::CORAL, "×")
                    .plain(" ")
                    .paint(style, style::SKY, &entry.package)
                    .pad_to(28)
                    .dim(style, &entry.summary())
            )?;

            let detail = match &entry.outcome {
                Outcome::Short { reason, .. } => reason.explain(&entry.package),
                Outcome::Failed { error } => error.clone(),
                Outcome::Fixed { .. } => continue,
            };
            writeln!(
                out,
                "{}",
                Line::indent(6).dim(style, &line::truncate(&detail, layout.room(6)))
            )?;
        }
    }

    Ok(())
}
