//! Hints and caveats: closing suggestions and blind spots.
//!
//! ## Caveats
//!
//! A security tool that hides its own limits manufactures confidence, which is
//! worse than reporting nothing. Caveats state plainly what was not checked
//! (git/path dependencies), what was not rated (unrated severities), and what
//! was skipped (excluded projects). These are not warnings, they are facts about
//! the scan's coverage.
//!
//! ## Hints
//!
//! Every report ends with exactly one hint, chosen by what helps *right now*.
//! The hints are ordered by proximity to action:
//!
//! 1. After `--fix`: "a requirement in Cargo.toml is capping these" (the fix
//!    didn't land, here's why)
//! 2. When fixes exist: "pulse --fix" (one command)
//! 3. When breaking changes exist: "pulse -f" (read first)
//! 4. When nothing can be upgraded: "nothing to upgrade to yet"
//! 5. When projects were skipped: "pulse -P" (see what was skipped)
//! 6. When findings exist but no hint applies: "pulse -f" (full text)
//!
//! The goal is to never leave the reader at a dead end. Every report ends with
//! a next step, even if that step is "read the advisory."

use std::io::Write;

use crate::domain::Effort;
use crate::error::Result;
use crate::triage::Report;

use crate::render::layout::Layout;
use crate::render::line::{truncate, Line};
use crate::render::style::{Style, GOLD, SLATE};

use super::Headline;

/// Blind spots, stated plainly. A security tool that hides its own limits
/// manufactures confidence, which is worse than reporting nothing.
pub(crate) fn caveats(
    out: &mut dyn Write,
    report: &Report,
    layout: Layout,
    style: Style,
) -> Result<()> {
    let s = &report.summary;
    let mut notes = Vec::new();

    if s.unrated > 0 {
        notes.push(format!("{} unrated", s.unrated));
    }
    if s.packages_unscannable > 0 {
        notes.push(format!(
            "{} git/path deps unchecked",
            s.packages_unscannable
        ));
    }
    if !report.skipped_projects.is_empty() {
        notes.push(format!(
            "{} {} skipped",
            report.skipped_projects.len(),
            super::plural(report.skipped_projects.len(), "project", "projects")
        ));
    }

    if notes.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "{}",
        Line::indent(2)
            .paint(style, GOLD, "!")
            .plain(" ")
            // indent(2) + "! " is a four-column prefix, so the budget is room(4).
            .dim(style, &truncate(&notes.join(" · "), layout.room(4)))
    )?;
    Ok(())
}

/// One closing suggestion, so the report never dead-ends.
pub(crate) fn hint(
    out: &mut dyn Write,
    report: &Report,
    headline: &Headline,
    layout: Layout,
    style: Style,
    view: super::View,
) -> Result<()> {
    // Ordered by how much the suggestion helps *right now*.
    let hint = if view.after_fix && headline.fixable > 0 {
        // `--fix` already ran and these survived, so the blocker is a requirement in
        // the manifest. `cargo add` is the command that actually moves it.
        let example = report
            .findings
            .iter()
            .find(|f| f.effort.is_some_and(Effort::is_compatible))
            .and_then(|f| f.fix.version().map(|v| (f.package.clone(), v.clone())));

        match example {
            Some((package, version)) => {
                return write_hint(
                    out,
                    layout,
                    style,
                    &format!(
            "a requirement in Cargo.toml is capping these · try: cargo add {package}@{version}"
          ),
                );
            }
            None => "a requirement in Cargo.toml is capping these",
        }
    } else if headline.fixable > 0 {
        "pulse --fix   upgrade these for you, then re-check"
    } else if headline.needs_decision > 0 {
        "pulse -f   read the advisory before deciding on a breaking bump"
    } else if headline.blocked > 0 {
        "nothing to upgrade to yet · pulse will tell you when there is"
    } else if !report.skipped_projects.is_empty() {
        "pulse -P   see every project and what is skipped"
    } else if headline.issues > 0 {
        "pulse -f   full advisory text"
    } else {
        return Ok(());
    };

    write_hint(out, layout, style, hint)
}

pub(crate) fn write_hint(
    out: &mut dyn Write,
    layout: Layout,
    style: Style,
    text: &str,
) -> Result<()> {
    writeln!(
        out,
        "{}",
        Line::indent(2).paint(style, SLATE, &truncate(text, layout.room(2)))
    )?;
    Ok(())
}
