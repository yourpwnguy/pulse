//! Group rendering: a package and every advisory affecting it.
//!
//! The unit of work is a package upgrade, not an advisory: four advisories in one
//! crate are one `cargo update`. The target shown is the highest fix among the
//! members, so that single upgrade clears all of them.

use std::io::Write;

use crate::domain::{Effort, Origin, Rating};
use crate::error::Result;
use crate::triage::Finding;

use crate::render::layout::Layout;
use crate::render::line::{truncate, Line};
use crate::render::style::{Style, GOLD, IRIS, MINT, SKY, SLATE};

/// Lines of advisory prose shown by `--full` before deferring to the URL.
///
/// Enough to convey the impact; not enough to bury the next finding.
const EXCERPT: usize = 14;

/// A package and every advisory affecting it.
///
/// The unit of work is a package upgrade, not an advisory: four advisories in one
/// crate are one `cargo update`. The target shown is the highest fix among the
/// members, so that single upgrade clears all of them.
pub(crate) struct Group<'a> {
    pub package: &'a str,
    pub version: String,
    pub project: &'a str,
    pub target: Option<&'a semver::Version>,
    pub effort: Option<Effort>,
    pub remediation: Option<&'a String>,
    pub origin: &'a Origin,
    pub priority: super::Priority,
    pub members: Vec<&'a Finding>,
}

impl Group<'_> {
    pub fn write(
        &self,
        out: &mut dyn Write,
        layout: Layout,
        style: Style,
        view: super::View,
        show_project: bool,
    ) -> Result<()> {
        let worst = self
            .members
            .iter()
            .map(|f| f.severity.rating)
            .max()
            .unwrap_or(Rating::Unknown);

        // ── project name (when multiple projects exist) ──
        if show_project {
            writeln!(
                out,
                "{}",
                Line::indent(2).bold(style, SKY, &truncate(self.project, layout.body()))
            )?;
        }

        // ── headline: the upgrade, how hard, how bad, where from ──
        let (arrow, arrow_colour) = match self.target {
            Some(v) => (format!("→ {v}"), MINT),
            None => ("no patch".to_string(), SLATE),
        };
        let (tag, tag_colour) = match self.effort {
            Some(Effort::Trivial) => ("quick", GOLD),
            Some(Effort::Compatible) => ("drop-in", MINT),
            Some(Effort::Breaking) => ("breaking", IRIS),
            None => ("", SLATE),
        };

        // Every column is checked against the line's ACTUAL width rather than a
        // precomputed position. Precomputed columns silently overflow as soon as a
        // package name is longer than expected, and an overflowing line wraps.
        let limit = layout.total;
        let impact = match self.members.len() {
            1 => severity(self.members[0]),
            n => format!("{n} issues"),
        };
        let origin = match self.origin.chain() {
            Some(chain) => format!("via {chain}"),
            None => "direct".to_string(),
        };

        // Reserve room for the tag and impact so a long name cannot eat the row.
        let reserved = tag.len() + impact.chars().count() + 6;
        let label = truncate(
            &format!("{} {}", self.package, self.version),
            layout
                .body()
                .saturating_sub(reserved + arrow.chars().count() + 2),
        );

        let mut head =
            Line::indent(4)
                .bold(style, SKY, &label)
                .plain(" ")
                .paint(style, arrow_colour, &arrow);

        // Anything that does not fit moves to its own row.
        let mut overflow: Vec<String> = Vec::new();
        let name_col = head.width().max(4 + (layout.body() * 42 / 100));

        let fits = |head: Line, text: &str, colour, column: usize| -> (Line, bool) {
            let target = column.max(head.width() + 2);
            if target + text.chars().count() <= limit {
                (head.pad_to(target).paint(style, colour, text), true)
            } else {
                (head, false)
            }
        };

        if !tag.is_empty() {
            let (next, placed) = fits(head, tag, tag_colour, name_col);
            head = next;
            if !placed {
                overflow.push(tag.to_string());
            }
        }

        let (next, placed) = fits(head, &impact, worst.colour_hint(), name_col + 10);
        head = next;
        if !placed {
            overflow.push(impact.clone());
        }

        if layout.is_wide() {
            let (next, placed) = fits(head, &origin, SLATE, name_col + 22);
            head = next;
            if !placed {
                overflow.push(origin);
            }
        } else {
            overflow.push(origin);
        }

        writeln!(out, "{head}")?;

        if !overflow.is_empty() {
            writeln!(
                out,
                "{}",
                Line::indent(6).dim(style, &truncate(&overflow.join(" · "), layout.room(6)))
            )?;
        }

        // ── the command, once per package ──
        // After a failed fix, show cargo add instead of cargo update
        let command_text = if view.after_fix {
            self.target
                .map(|v| format!("cargo add {}@{v}", self.package))
        } else {
            self.remediation.cloned()
        };
        if let Some(command) = &command_text {
            let line = match self.effort {
                // A breaking change is an instruction, not something to paste.
                Some(Effort::Breaking) => Line::indent(6).dim(style, command),
                _ => Line::indent(6).paint(style, GOLD, command),
            };
            writeln!(out, "{line}")?;
        }

        // ── one row per advisory ──
        let single = self.members.len() == 1;
        for finding in &self.members {
            let id = truncate(&finding.advisory, 24);
            let age = finding
                .age_days
                .map(|d| format!("{d}d"))
                .unwrap_or_default();
            // Columns are budgeted from the real width, so a wide terminal gives
            // the summary more room instead of leaving a gap.
            let reserved = 6 + if single { 0 } else { 12 } + id.chars().count() + age.len() + 6;
            let room = layout.summary(reserved);

            let mut row = Line::indent(6);
            if !single {
                row = row
                    .paint(
                        style,
                        finding.severity.rating.colour_hint(),
                        &severity(finding),
                    )
                    .pad_to(18);
            }
            row = row
                .dim(
                    style,
                    &truncate(finding.summary.as_deref().unwrap_or("no description"), room),
                )
                .pad_to(
                    layout
                        .body()
                        .saturating_sub(id.chars().count() + age.len() + 2),
                )
                .paint(style, SLATE, &id)
                .plain("  ")
                .paint(style, SLATE, &age);
            writeln!(out, "{row}")?;

            if view.full {
                self.excerpt(out, finding, layout, style)?;
            }
        }
        Ok(())
    }

    /// A capped excerpt of the advisory, then the link.
    ///
    /// Bounded on purpose: dumping the whole document inline printed 75 lines for
    /// a single finding, which stopped being a report.
    fn excerpt(
        &self,
        out: &mut dyn Write,
        finding: &Finding,
        layout: Layout,
        style: Style,
    ) -> Result<()> {
        writeln!(out)?;
        let width = layout.room(8);

        match finding.details.as_deref() {
            Some(details) => {
                let wrapped = super::wrap::wrap(details, width);
                let shown = wrapped.len().min(EXCERPT);
                for text in wrapped.iter().take(EXCERPT) {
                    writeln!(out, "{}", Line::indent(8).dim(style, text))?;
                }
                if wrapped.len() > shown {
                    writeln!(
                        out,
                        "{}",
                        Line::indent(8).paint(
                            style,
                            SLATE,
                            &format!("… {} more lines", wrapped.len() - shown)
                        )
                    )?;
                }
            }
            None => writeln!(
                out,
                "{}",
                Line::indent(8).dim(style, "(no long-form details published)")
            )?,
        }

        // A truncated URL is useless, so these two sit at a shallower indent rather
        // than being cut. They are the one thing a reader may need to copy exactly.
        if let Some(vector) = &finding.severity.vector {
            writeln!(
                out,
                "{}",
                Line::indent(6).paint(style, SKY, &truncate(vector, layout.room(6)))
            )?;
        }
        writeln!(
            out,
            "{}",
            Line::indent(6).paint(style, SLATE, &truncate(&finding.url, layout.room(6)))
        )?;
        Ok(())
    }
}

/// Formats a finding's severity as a short string.
pub(crate) fn severity(finding: &Finding) -> String {
    match finding.severity.score {
        Some(score) => format!("{} {score:.1}", finding.severity.rating.as_str()),
        None => finding.severity.rating.as_str().to_string(),
    }
}
