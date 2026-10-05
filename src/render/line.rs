//! `Line`: text that knows its own display width.
//!
//! Every alignment bug in the reference implementation had the same shape:
//! something measured a string that had already been coloured. Escape sequences
//! carry bytes but occupy no cells, so `format!("{:<20}", painted)` pads to the
//! wrong place and the column bends.
//!
//! The fix is not discipline, it is a type. A [`Line`] tracks the width of the
//! *visible* text as it is assembled, so padding is always correct and the
//! mistake is unrepresentable. Nothing in this crate formats a coloured string
//! with a width specifier; it cannot, because colouring returns a `Line` and
//! `Line` only pads itself.
//!
//! Widths are counted in terminal **cells** via `unicode-width`: a CJK glyph is
//! one `char` occupying two cells, so counting characters is as wrong as
//! counting bytes.

use std::fmt;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::style::{Colour, Style};

/// A single row of output, plus the number of cells it occupies.
#[derive(Debug, Clone, Default)]
pub struct Line {
    text: String,
    width: usize,
}

impl Line {
    pub fn new() -> Line {
        Line::default()
    }

    /// Starts a line with `n` leading spaces.
    pub fn indent(n: usize) -> Line {
        Line {
            text: " ".repeat(n),
            width: n,
        }
    }

    /// Appends uncoloured text.
    pub fn plain(mut self, text: &str) -> Line {
        self.width += UnicodeWidthStr::width(text);
        self.text.push_str(text);
        self
    }

    /// Appends coloured text. The width recorded is the width of the *visible*
    /// characters, so the escape sequence never influences layout.
    pub fn paint(mut self, style: Style, colour: Colour, text: &str) -> Line {
        self.width += UnicodeWidthStr::width(text);
        self.text.push_str(&style.paint(colour, text));
        self
    }

    /// Appends bold coloured text.
    pub fn bold(mut self, style: Style, colour: Colour, text: &str) -> Line {
        self.width += UnicodeWidthStr::width(text);
        self.text.push_str(&style.bold(colour, text));
        self
    }

    /// Appends recessive text.
    pub fn dim(self, style: Style, text: &str) -> Line {
        let colour = super::style::SLATE;
        self.paint(style, colour, text)
    }

    /// Appends another line, carrying its measured width across.
    ///
    /// Needed for framing: a card row is assembled independently and then nested
    /// inside its border, and the border can only align if the inner width
    /// survives the move.
    pub fn append(mut self, other: Line) -> Line {
        self.width += other.width;
        self.text.push_str(&other.text);
        self
    }

    /// Appends `n` spaces.
    pub fn space(self, n: usize) -> Line {
        self.plain(&" ".repeat(n))
    }

    /// Pads with spaces until the line occupies `cells`. A no-op if already wider.
    pub fn pad_to(mut self, cells: usize) -> Line {
        if self.width < cells {
            let gap = cells - self.width;
            self.text.push_str(&" ".repeat(gap));
            self.width += gap;
        }
        self
    }

    /// Repeats `glyph` until the line occupies `cells`.
    pub fn fill_to(mut self, style: Style, colour: Colour, glyph: &str, cells: usize) -> Line {
        let unit = UnicodeWidthStr::width(glyph).max(1);
        while self.width + unit <= cells {
            self.width += unit;
            self.text.push_str(&style.paint(colour, glyph));
        }
        self
    }

    /// Cells currently occupied.
    pub fn width(&self) -> usize {
        self.width
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0
    }

    /// The assembled string, escape sequences included.
    pub fn into_string(self) -> String {
        self.text
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Truncates to `cells`, appending an ellipsis when it does.
///
/// Character-boundary safe: `&s[..n]` panics when `n` lands inside a multi-byte
/// character, which is the bug the old renderer shipped.
pub fn truncate(text: &str, cells: usize) -> String {
    let flat = text.replace('\n', " ");
    if UnicodeWidthStr::width(flat.as_str()) <= cells {
        return flat;
    }

    // Leave one cell for the ellipsis.
    let budget = cells.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0;
    for ch in flat.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w > budget {
            break;
        }
        used += w;
        out.push(ch);
    }
    format!("{}…", out.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::style::{KIN, ROSE};

    #[test]
    fn width_ignores_escape_sequences() {
        let coloured = Line::new().paint(Style::Colour, ROSE, "hello");
        let plain = Line::new().plain("hello");

        assert_eq!(coloured.width(), 5);
        assert_eq!(plain.width(), 5);
        // The coloured string is longer in bytes but identical in width — which
        // is precisely the trap this type removes.
        assert!(coloured.to_string().len() > plain.to_string().len());
    }

    #[test]
    fn padding_a_coloured_line_lands_in_the_right_column() {
        let a = Line::new()
            .paint(Style::Colour, ROSE, "ab")
            .pad_to(10)
            .plain("|");
        let b = Line::new().plain("abcd").pad_to(10).plain("|");

        assert_eq!(a.width(), 11);
        assert_eq!(b.width(), 11);
    }

    #[test]
    fn width_is_measured_in_cells_not_chars() {
        // 3 chars, 9 bytes, 6 cells.
        let cjk = Line::new().plain("日本語");
        assert_eq!(cjk.width(), 6);
        assert_eq!(cjk.pad_to(10).width(), 10);
    }

    #[test]
    fn pad_to_never_shrinks() {
        let line = Line::new().plain("a longer string");
        let width = line.width();
        assert_eq!(line.pad_to(3).width(), width);
    }

    #[test]
    fn fill_to_stops_before_overflowing() {
        let line = Line::indent(2).fill_to(Style::Plain, KIN, "─", 10);
        assert_eq!(line.width(), 10);

        // A double-width filler must not overshoot.
        let wide = Line::new().fill_to(Style::Plain, KIN, "▰", 5);
        assert!(wide.width() <= 5);
    }

    #[test]
    fn plain_style_emits_no_escapes() {
        let line = Line::new()
            .paint(Style::Plain, ROSE, "a")
            .bold(Style::Plain, KIN, "b")
            .dim(Style::Plain, "c");
        assert_eq!(line.to_string(), "abc");
        assert_eq!(line.width(), 3);
    }

    #[test]
    fn truncate_is_character_boundary_safe() {
        let text = "日本語のテキストがとても長い";
        let cut = truncate(text, 7);
        assert!(UnicodeWidthStr::width(cut.as_str()) <= 7);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn truncate_leaves_short_text_alone() {
        assert_eq!(truncate("short", 40), "short");
        assert_eq!(truncate("two\nlines", 40), "two lines");
    }

    #[test]
    fn builder_composes_left_to_right() {
        let line = Line::indent(2)
            .plain("a")
            .space(3)
            .plain("b")
            .pad_to(12)
            .plain("|");
        assert_eq!(line.to_string(), "  a   b     |");
    }
}
