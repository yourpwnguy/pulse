//! The stats board.
//!
//! A rounded panel of real numbers. No mascot inside it (Doki lives beside the
//! work, where there is room for the full character.
//!
//! ## Why it is capped
//!
//! The panel is capped at [`MAX`] columns rather than filling the terminal. An
//! earlier version spanned the full width, and on a 120-column terminal five
//! short facts floating in 118 columns read as *empty* rather than *spacious*.
//! Density is the point: a board should look like a dashboard, not like a mostly
//! blank box.
//!
//! ## Why the rows are shaped like this
//!
//! Reading order matches decision order:
//!
//! 1. **counts** (how much is there, and how much can I act on)
//! 2. **the bar** (how much of it is one command away)
//! 3. **severity and age** (how bad, and how long)
//! 4. **scope and movement** (what was examined, and what changed)
//!
//! Every row goes through [`Board::row`], which pads to a width the board
//! computed. There is a test asserting the result is a rectangle at every
//! terminal size, because a ragged border is the most visible defect possible.

use super::layout::Layout;
use super::line::{truncate, Line};
use super::mascot;
use super::style::{Colour, Style, CORAL, FAINT, GOLD, IRIS, MINT, PETAL, ROSE, SKY, SLATE};

/// Widest the board is ever drawn. Beyond this it stops looking dense.
const MAX: usize = 82;

/// Cells in the progress bar.
const BAR: usize = 12;

/// One labelled statistic.
pub struct Stat {
    pub value: String,
    pub colour: Colour,
}

impl Stat {
    pub fn new(value: impl Into<String>, colour: Colour) -> Stat {
        Stat {
            value: value.into(),
            colour,
        }
    }
}

/// The board's contents. Assembled by the caller so this module holds no policy.
pub struct Board {
    /// Row 1: headline counts.
    pub counts: Vec<Stat>,
    /// Row 2: `(done, total, label)` for the bar. `None` hides the row.
    pub bar: Option<(usize, usize, String)>,
    /// Row 3: severity and age.
    pub detail: Vec<Stat>,
    /// Row 4: what was scanned and what moved.
    pub scope: String,
    /// Movement since the last run, coloured separately because it is the line
    /// most worth reading.
    pub movement: Option<String>,
    /// A scrolling ECG trace on the title row, while work is in flight.
    ///
    /// `None` for the static report: an animation frozen at frame zero is just
    /// clutter.
    pub trace: Option<String>,
    pub frame: usize,
    pub layout: Layout,
    pub style: Style,
}

impl Board {
    /// Total columns the board occupies, including borders.
    fn width(&self) -> usize {
        self.layout.total.min(MAX)
    }

    /// Column at which content stops and the closing decoration begins.
    fn content_end(&self) -> usize {
        self.width().saturating_sub(3)
    }

    /// Renders the board. Height varies with content; width never does.
    pub fn render(&self) -> Vec<Line> {
        let mut rows = vec![self.edge('╭', '╮')];

        rows.push(self.title());
        if !self.counts.is_empty() {
            rows.push(self.stats(&self.counts, 2));
        }
        if let Some((done, total, label)) = &self.bar {
            rows.push(self.progress(*done, *total, label));
        }
        if !self.detail.is_empty() {
            rows.push(self.stats(&self.detail, 3));
        }
        rows.push(self.footer());

        rows.push(self.edge('╰', '╯'));
        rows
    }

    fn edge(&self, left: char, right: char) -> Line {
        Line::indent(2)
            .paint(self.style, ROSE, &left.to_string())
            .fill_to(self.style, ROSE, "─", self.width() - 1)
            .paint(self.style, ROSE, &right.to_string())
    }

    /// `│  ♡  pulse  doki is watching              ▂▅█▅▂▁ ✧ │`
    fn title(&self) -> Line {
        let mut line = Line::indent(2)
            .paint(self.style, ROSE, "│")
            .plain("  ")
            .paint(self.style, ROSE, mascot::heartbeat(self.frame))
            .plain("  ")
            .bold(self.style, ROSE, "pulse")
            .plain("  ")
            .dim(self.style, mascot::NAME)
            .dim(self.style, " is watching");

        // The trace sits hard against the border, where the eye lands last and motion
        // is least distracting.
        if let Some(trace) = &self.trace {
            let cells = trace.chars().count();
            if line.width() + cells + 2 <= self.content_end() {
                line = line
                    .pad_to(self.content_end().saturating_sub(cells))
                    .paint(self.style, ROSE, trace);
            }
        }
        self.close(line, true)
    }

    /// A row of statistics, separated by generous spacing so each reads as its own
    /// figure rather than as prose.
    fn stats(&self, stats: &[Stat], gap: usize) -> Line {
        let mut line = Line::indent(2).paint(self.style, ROSE, "│").plain("  ");

        for (index, stat) in stats.iter().enumerate() {
            let separator = if index > 0 { gap } else { 0 };
            if line.width() + separator + stat.value.chars().count() > self.content_end() {
                break;
            }
            line = line
                .space(separator)
                .paint(self.style, stat.colour, &stat.value);
        }

        self.close(line, false)
    }

    /// `│  ▰▰▰▰▰▰▰▰▰▱  6 of 7 fixable right now          ❀ │`
    fn progress(&self, done: usize, total: usize, label: &str) -> Line {
        // `checked_div` rather than a guard: a zero total means there is nothing to
        // show progress against, and an empty bar is the right answer there.
        let filled = (done * BAR).checked_div(total).map_or(0, |n| n.min(BAR));

        let line = Line::indent(2)
            .paint(self.style, ROSE, "│")
            .plain("  ")
            .paint(self.style, GOLD, &"▰".repeat(filled))
            .paint(self.style, FAINT, &"▱".repeat(BAR - filled))
            .plain("  ")
            .dim(
                self.style,
                &truncate(label, self.content_end().saturating_sub(20)),
            );
        self.close(line, true)
    }

    /// Scope and movement, dimmest because it is context.
    fn footer(&self) -> Line {
        let mut line = Line::indent(2)
            .paint(self.style, ROSE, "│")
            .plain("  ")
            .dim(self.style, &truncate(&self.scope, self.content_end() - 6));

        if let Some(moved) = &self.movement {
            let room = self.content_end().saturating_sub(line.width() + 3);
            if room > 8 {
                line = line
                    .dim(self.style, " · ")
                    .paint(self.style, MINT, &truncate(moved, room));
            }
        }
        self.close(line, false)
    }

    /// Pads a row out to the border and closes it.
    ///
    /// `decorate` places a drifting petal. Only some rows get one: twinkling on
    /// every row looked like a rendering fault rather than decoration.
    fn close(&self, line: Line, decorate: bool) -> Line {
        let glyph = if decorate {
            mascot::sparkle(self.frame)
        } else {
            " "
        };
        line.pad_to(self.content_end())
            .paint(self.style, PETAL, glyph)
            .plain(" ")
            .paint(self.style, ROSE, "│")
    }
}

/// Convenience constructors so callers do not repeat the colour choices, and so
/// the same figure is always the same colour wherever it appears.
pub mod stat {
    use super::{Colour, Stat, CORAL, GOLD, IRIS, MINT, SKY, SLATE};

    pub fn issues(count: usize, worst: Colour) -> Stat {
        Stat::new(
            format!("{count} {}", if count == 1 { "issue" } else { "issues" }),
            worst,
        )
    }

    /// The single most decision-relevant number, so it gets the action colour.
    pub fn fixable(count: usize) -> Stat {
        Stat::new(format!("{count} fixable now"), GOLD)
    }

    pub fn blocked(count: usize) -> Stat {
        Stat::new(format!("{count} blocked"), IRIS)
    }

    pub fn decisions(count: usize) -> Stat {
        Stat::new(
            format!(
                "{count} {} a decision",
                if count == 1 { "needs" } else { "need" }
            ),
            IRIS,
        )
    }

    pub fn worst(score: f64, rating: &str, colour: Colour) -> Stat {
        Stat::new(format!("worst {score:.1} {rating}"), colour)
    }

    pub fn oldest(days: u32) -> Stat {
        Stat::new(format!("oldest {days}d"), SLATE)
    }

    pub fn clear() -> Stat {
        Stat::new("all clear", MINT)
    }

    pub fn unrated(count: usize) -> Stat {
        Stat::new(format!("{count} unrated"), SLATE)
    }

    pub fn critical(count: usize) -> Stat {
        Stat::new(format!("{count} critical"), CORAL)
    }

    pub fn packages(count: usize) -> Stat {
        Stat::new(format!("{count} packages"), SKY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    fn board(layout: Layout) -> Board {
        Board {
            counts: vec![stat::issues(7, CORAL), stat::fixable(6), stat::blocked(1)],
            bar: Some((6, 7, "6 of 7 fixable right now".to_string())),
            detail: vec![stat::worst(9.8, "critical", CORAL), stat::oldest(412)],
            scope: "288 packages · 3 projects".to_string(),
            movement: Some("3 fixed in 3d".to_string()),
            trace: None,
            frame: 0,
            layout,
            style: Style::Plain,
        }
    }

    /// The invariant. A ragged border is the most visible defect possible.
    #[test]
    fn the_board_is_always_a_rectangle() {
        for columns in [56, 60, 72, 80, 100, 140, 200] {
            for style in [Style::Plain, Style::Colour] {
                let mut b = board(Layout::of(columns));
                b.style = style;
                let rows = b.render();

                let expected = rows[0].width();
                for row in &rows {
                    assert_eq!(
                        row.width(),
                        expected,
                        "ragged board at {columns} cols: {:?}",
                        row.to_string()
                    );
                }
            }
        }
    }

    #[test]
    fn the_board_is_capped_so_it_never_looks_empty() {
        // The complaint this fixes: spanning a 200-column terminal left five short
        // facts floating in a mostly blank box.
        let wide = board(Layout::of(200)).render();
        assert!(
            wide[0].width() <= MAX + 2,
            "board is {} cells, cap is {MAX}",
            wide[0].width()
        );

        // And it still shrinks for a genuinely narrow terminal.
        let narrow = board(Layout::of(60)).render();
        assert!(narrow[0].width() < wide[0].width());
    }

    #[test]
    fn stays_rectangular_as_the_animation_advances() {
        // The sparkle and the trace both change per frame; neither may change the width.
        let mut widths = std::collections::HashSet::new();
        for frame in 0..40 {
            let mut b = board(Layout::of(100));
            b.frame = frame;
            b.trace = Some(mascot::wave(frame, 9));
            for row in b.render() {
                widths.insert(row.width());
            }
        }
        assert_eq!(widths.len(), 1, "width drifts across frames: {widths:?}");
    }

    #[test]
    fn the_trace_appears_only_when_supplied() {
        let mut working = board(Layout::of(100));
        working.trace = Some(mascot::wave(0, 9));
        assert!(working.render()[1].to_string().contains('█'));

        // The static report passes none, because a frozen animation is clutter.
        assert!(!board(Layout::of(100)).render()[1].to_string().contains('█'));
    }

    #[test]
    fn the_bar_is_proportional_and_bounded() {
        let render = |done, total| {
            let mut b = board(Layout::of(100));
            b.bar = Some((done, total, "x".to_string()));
            b.render()[3].to_string()
        };

        assert_eq!(render(0, 7).matches('▰').count(), 0);
        assert_eq!(render(7, 7).matches('▰').count(), BAR);
        assert!(render(6, 7).matches('▰').count() > BAR / 2);
        // Never divides by zero, never overflows the bar.
        assert_eq!(render(0, 0).matches('▰').count(), 0);
        assert_eq!(render(99, 7).matches('▰').count(), BAR);
    }

    #[test]
    fn rows_are_omitted_rather_than_left_blank() {
        // A clean report has no bar and no severity row; the board should shrink
        // rather than show empty rows.
        let mut clean = board(Layout::of(100));
        clean.counts = vec![stat::clear()];
        clean.bar = None;
        clean.detail = vec![];
        clean.movement = None;

        let rows = clean.render();
        // borders + title + counts + scope
        assert_eq!(
            rows.len(),
            5,
            "clean board should omit the bar and detail rows"
        );
        assert!(rows.iter().all(|r| r.width() == rows[0].width()));
    }

    #[test]
    fn drops_stats_that_do_not_fit_rather_than_wrapping() {
        let narrow = board(Layout::of(56)).render()[2].to_string();
        let wide = board(Layout::of(100)).render()[2].to_string();

        // The most important count survives at any width.
        assert!(narrow.contains("7 issues"));
        assert!(wide.contains("7 issues") && wide.contains("1 blocked"));
    }

    #[test]
    fn names_the_mascot() {
        let text = board(Layout::of(100)).render()[1].to_string();
        assert!(text.contains(mascot::NAME));
    }

    #[test]
    fn long_values_are_truncated_not_wrapped() {
        let mut b = board(Layout::of(60));
        b.scope = "x".repeat(500);
        b.movement = Some("y".repeat(500));
        let rows = b.render();
        assert!(rows.iter().all(|r| r.width() == rows[0].width()));
    }

    #[test]
    fn plain_style_emits_no_escapes() {
        for row in board(Layout::of(80)).render() {
            assert!(!row.to_string().contains('\x1b'));
        }
    }

    #[test]
    fn every_row_fits_the_terminal() {
        for columns in [56, 60, 80, 120] {
            let layout = Layout::of(columns);
            for row in board(layout).render() {
                assert!(
                    UnicodeWidthStr::width(row.to_string().as_str()) <= layout.total,
                    "row exceeds {columns}-column terminal"
                );
            }
        }
    }
}
