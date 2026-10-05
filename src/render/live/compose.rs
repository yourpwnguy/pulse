//! Frame composition for the live animation.
//!
//! Builds one frame of the live animation: the stats board, Doki character,
//! checklist, and detail lines. Pure apart from reading shared state, so the
//! layout is unit-testable without a terminal.
//!
//! ## The frame structure
//!
//! A frame is composed of:
//!
//! 1. **Stats board** (top): live counters, progress bar, scope, ECG trace
//! 2. **Doki character** (middle): the mascot with dialogue
//! 3. **Checklist** (bottom): stages with ticks, spinner, detail lines
//!
//! ## Why this matters
//!
//! The live animation narrates real work that already happened silently. This is
//! the difference between "it is thinking" and "it is getting somewhere." The
//! checklist shows completed stages with ✓, the current stage with a spinner,
//! and pending stages with ·. This is what keeps someone watching instead of
//! opening another terminal.
//!
//! ## Height invariant
//!
//! The frame is always exactly `REGION` rows (24). If a frame grows taller,
//! the bottom rows are silently truncated (that's how a completed stage ends
//! up with no tick against it). The `debug_assert!` catches this during
//! development.

use std::sync::Arc;

use super::state::{lock, Shared};
use super::Stage;

use crate::render::layout::Layout;
use crate::render::line::{truncate, Line};
use crate::render::mascot::{self, Mood};
use crate::render::panel::{Board, Stat};
use crate::render::style::{Style, FAINT, GOLD, MINT, ROSE, SKY};

/// Cell width of a progress bar.
const BAR: usize = 12;

/// Builds one frame.
///
/// Pure apart from reading the shared state, so the layout is unit-testable
/// without a terminal.
pub(crate) fn compose(shared: &Arc<Shared>, frame: usize, style: Style) -> Vec<Line> {
    let done = lock(&shared.done).clone();
    let current = *lock(&shared.current);
    let detail = lock(&shared.detail).clone();
    let progress = shared.done_count.load(std::sync::atomic::Ordering::Relaxed);
    let total = shared.total.load(std::sync::atomic::Ordering::Relaxed);

    // Doki's face tracks the stage, so the mascot reacts to the work rather than
    // looping independently of it. Blended with the busy animation so it also moves
    // *within* a long stage.
    let mood = match current {
        Some(stage) => {
            if frame % 24 < 18 {
                stage.mood()
            } else {
                mascot::busy(frame)
            }
        }
        None if done.len() == Stage::all().len() => Mood::Purr,
        None => mascot::idle(frame),
    };

    // Live counters: what has actually been established so far. These tick up while
    // you watch, which is the difference between "it is thinking" and "it is getting
    // somewhere".
    let mut counts: Vec<Stat> = Vec::new();
    for (stage, summary) in &done {
        if matches!(stage, Stage::Parse | Stage::Query) {
            counts.push(Stat::new(summary.clone(), SKY));
        }
    }
    if counts.is_empty() {
        counts.push(Stat::new("starting up", SKY));
    }

    // The bar mirrors how far through the pipeline we are, so the board itself shows
    // progress rather than only the checklist below it.
    let steps = Stage::all().len();
    let board = Board {
        counts,
        bar: Some((
            done.len(),
            steps,
            format!("step {} of {steps}", (done.len() + 1).min(steps)),
        )),
        // No detail row here: it would repeat the checklist immediately below, and the
        // rows are needed to keep the whole live view inside an 80x24 terminal.
        detail: Vec::new(),
        scope: headline(&done, current),
        movement: None,
        trace: Some(mascot::wave(frame, 9)),
        frame,
        layout: Layout::detect(),
        style,
    };

    let mut lines = board.render();
    lines.push(Line::new());

    // ── the character, with what it is saying beside it ──
    //
    // Side by side rather than stacked: the same information in four rows instead of
    // eight, which is what keeps the whole live view on one screen.
    let saying = match current {
        Some(stage) => stage.saying(),
        None if done.len() == Stage::all().len() => "all done \u{2014} here is what I found",
        None => "waking up…",
    };

    let body = mascot::body(mood);
    // A small hop while working, so the character is never perfectly still.
    let hop = usize::from(current.is_some() && frame % 20 < 7);

    for (row, art) in body.iter().enumerate() {
        let mut line = Line::indent(3 + hop)
            .paint(style, mood.colour(), art)
            .pad_to(3 + mascot::BODY_WIDTH + 4);
        if row == 1 {
            line = line
                .paint(style, ROSE, mascot::heartbeat(frame))
                .plain(" ")
                .dim(style, saying);
        }
        lines.push(line);
    }
    lines.push(Line::new());

    // ── the checklist ──
    for (stage, summary) in &done {
        lines.push(
            Line::indent(3)
                .paint(style, MINT, "✓")
                .plain(" ")
                .dim(style, stage.label())
                .pad_to(36)
                .dim(style, summary),
        );
    }

    if let Some(stage) = current {
        let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut line = Line::indent(3)
            .paint(style, GOLD, spinner[frame % spinner.len()])
            .plain(" ")
            .paint(style, SKY, stage.label())
            .pad_to(36);

        line = if total > 0 {
            let filled = (progress * BAR / total.max(1)).min(BAR);
            line.paint(style, GOLD, &"▰".repeat(filled))
                .paint(style, FAINT, &"▱".repeat(BAR - filled))
                .plain(" ")
                .dim(style, &format!("{progress}/{total}"))
        } else {
            sweep(line, frame, style)
        };
        lines.push(line);

        // Verbose detail, indented under its stage.
        for text in &detail {
            lines.push(Line::indent(7).paint(style, FAINT, "└ ").paint(
                style,
                FAINT,
                &truncate(text, 58),
            ));
        }
    }

    // ── what has not started yet ──
    //
    // Computed by set difference rather than `skip(done.len())`, which silently
    // duplicates a stage whenever one completes out of order.
    for stage in Stage::all() {
        let finished = done.iter().any(|(s, _)| *s == stage);
        if finished || current == Some(stage) {
            continue;
        }
        lines.push(Line::indent(3).paint(style, FAINT, "·").plain(" ").paint(
            style,
            FAINT,
            stage.label(),
        ));
    }

    // Silent truncation is how a finished stage ends up with no tick against it, so
    // an over-tall frame is a bug rather than something to quietly trim.
    debug_assert!(
        lines.len() <= super::REGION,
        "live frame is {} rows but REGION is {}",
        lines.len(),
        super::REGION
    );
    lines.truncate(super::REGION);
    lines
}

/// The header's summary of where the run is up to.
fn headline(done: &[(Stage, String)], current: Option<Stage>) -> String {
    let total = Stage::all().len();
    match current {
        Some(stage) => format!("step {} of {total} · {}…", done.len() + 1, stage.label()),
        None if done.len() == total => "done".to_string(),
        None => "waking up…".to_string(),
    }
}

/// An indeterminate bar: a highlight sweeping back and forth.
///
/// Deliberately not a partially filled bar (that would depict progress which is
/// not happening).
fn sweep(line: Line, frame: usize, style: Style) -> Line {
    let period = BAR * 2 - 2;
    let step = frame % period;
    let position = if step < BAR { step } else { period - step };

    (0..BAR).fold(line, |acc, i| {
        let glyph = if i.abs_diff(position) <= 1 {
            "▰"
        } else {
            "▱"
        };
        let colour = if i == position {
            GOLD
        } else if i.abs_diff(position) == 1 {
            ROSE
        } else {
            FAINT
        };
        acc.paint(style, colour, glyph)
    })
}
