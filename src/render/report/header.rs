//! Header panel and movement text.
//!
//! The header panel is everything a person needs before deciding whether to read
//! on. Every value in the status line changes a decision: how many, how many you
//! can fix *right now*, how bad the worst one is, how long you have been exposed.

use std::io::Write;

use crate::error::Result;
use crate::progress::Delta;
use crate::triage::Report;

use crate::render::layout::Layout;
use crate::render::line::{truncate, Line};
use crate::render::mascot::{self, Mood};
use crate::render::panel::{stat, Board};
use crate::render::style::{severity_colour, Style};

/// Renders the header panel with stats, Doki mascot, and movement text.
pub(crate) fn header(
    out: &mut dyn Write,
    report: &Report,
    headline: &super::Headline,
    delta: &Delta,
    mood: Mood,
    layout: Layout,
    style: Style,
) -> Result<()> {
    let worst_colour = severity_colour(headline.worst_rating);

    // Row 1: how much, and how much of it you can act on.
    let mut counts = Vec::new();
    if headline.issues == 0 {
        counts.push(stat::clear());
    } else {
        counts.push(stat::issues(headline.issues, worst_colour));
        if headline.fixable > 0 {
            counts.push(stat::fixable(headline.fixable));
        }
        if headline.needs_decision > 0 {
            counts.push(stat::decisions(headline.needs_decision));
        }
        if headline.blocked > 0 {
            counts.push(stat::blocked(headline.blocked));
        }
    }

    // Row 2: how much of the backlog is one command away.
    //
    // Labelled precisely rather than as bare progress: a nearly full bar here means
    // "this is easy", not "you are nearly safe", and the label has to say so.
    let bar = (headline.issues > 0 && headline.fixable > 0).then(|| {
        (
            headline.fixable,
            headline.issues,
            format!(
                "{} of {} fixable right now",
                headline.fixable, headline.issues
            ),
        )
    });

    // Row 3: how bad, and how long.
    let mut detail = Vec::new();
    if let Some(score) = headline.worst_score {
        detail.push(stat::worst(
            score,
            headline.worst_rating.as_str(),
            worst_colour,
        ));
    }
    if let Some(days) = headline.oldest_days {
        detail.push(stat::oldest(days));
    }
    if report.summary.unrated > 0 {
        detail.push(stat::unrated(report.summary.unrated));
    }

    let board = Board {
        counts,
        bar,
        detail,
        scope: format!(
            "{} {} · {} {}",
            headline.packages,
            super::plural(headline.packages, "package", "packages"),
            headline.projects,
            super::plural(headline.projects, "project", "projects"),
        ),
        movement: movement(delta),
        // No trace in the static report: a frozen animation frame is clutter.
        trace: None,
        frame: 0,
        layout,
        style,
    };

    for line in board.render() {
        writeln!(out, "{line}")?;
    }

    // Doki reacts beside the board rather than inside it, where there is room for
    // the whole character.
    writeln!(out)?;
    let body = mascot::body(mood);
    for (row, art) in body.iter().enumerate() {
        let mut line = Line::indent(4)
            .paint(style, mood.colour(), art)
            .pad_to(4 + mascot::BODY_WIDTH + 3);
        if row == 1 {
            line = line
                .paint(style, crate::render::style::ROSE, "♡")
                .plain(" ")
                .dim(style, &truncate(mood.line(), layout.room(20)));
        }
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    Ok(())
}

/// Movement since the previous run, phrased as fact.
fn movement(delta: &Delta) -> Option<String> {
    if delta.first_run {
        return Some("first run · this becomes your baseline".to_string());
    }

    let mut parts = Vec::new();
    if !delta.fixed.is_empty() {
        parts.push(format!("{} fixed", delta.fixed.len()));
    }
    // A newly published advisory is not the reader's failure, so it is stated
    // flatly and never framed as a loss.
    if !delta.introduced.is_empty() {
        parts.push(format!("{} new", delta.introduced.len()));
    }
    if parts.is_empty() {
        return None;
    }

    let when = match delta.days_since {
        Some(0) => " today".to_string(),
        Some(1) => " since yesterday".to_string(),
        Some(days) => format!(" in {days}d"),
        None => String::new(),
    };
    Some(format!("{}{when}", parts.join(" · ")))
}
