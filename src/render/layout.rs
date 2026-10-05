//! Layout: how wide things are allowed to be.
//!
//! The previous renderer hardcoded 76 columns. On an 80-column terminal that is
//! merely tight; on the 200-column terminal most people actually use it wastes
//! more than half the screen and pushes content downward, which is what turned a
//! short report into something you had to scroll.
//!
//! Width is resolved **once**, at the edge, and passed down. Nothing below asks
//! the terminal how wide it is, so every renderer is a pure function of a `Layout`
//! and can be tested at any width.

use terminal_size::{terminal_size, Width};

/// Resolved widths for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Total usable columns.
    pub total: usize,
}

/// Below this we stop trying to be clever and just print narrow.
const MIN: usize = 56;

/// Prose stops being readable past roughly this many columns, so the report is
/// capped even on a very wide terminal. Wide *columns* are useful; wide
/// paragraphs are not.
const MAX: usize = 118;

impl Layout {
    /// Detects the terminal width, falling back to a sane default when output is
    /// redirected.
    pub fn detect() -> Layout {
        // `COLUMNS` wins when set. It is the conventional override, it makes the
        // layout testable inside a pty, and it lets someone pin the width for
        // reproducible output without having to redirect.
        let columns = std::env::var("COLUMNS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|w| *w > 0)
            .or_else(|| terminal_size().map(|(Width(w), _)| usize::from(w)))
            // A pipe has no width. 100 keeps columns aligned in a log or a pasted
            // snippet without wrapping in a default-size terminal.
            .unwrap_or(100);

        Layout::of(columns)
    }

    /// Builds a layout for an explicit width. Used by tests.
    pub fn of(columns: usize) -> Layout {
        // Leave two columns of breathing room on the right so text never touches
        // the edge, which reads as if it has been cut off.
        let usable = columns.saturating_sub(2);
        Layout {
            total: usable.clamp(MIN, MAX),
        }
    }

    /// Width available inside the standard two-space indent.
    pub fn body(self) -> usize {
        self.room(2)
    }

    /// Width available to content that starts at `indent` columns.
    ///
    /// Takes the indent explicitly because assuming it is the source of a whole
    /// family of off-by-the-indent overflows: a row indented four columns that
    /// truncates to `body()` is two columns too wide.
    pub fn room(self, indent: usize) -> usize {
        self.total.saturating_sub(indent)
    }

    /// Width of the summary column in a finding row: everything left of the
    /// advisory identifier and age.
    ///
    /// Computed from the total so a wide terminal gives the summary more room
    /// rather than leaving a gap.
    pub fn summary(self, reserved: usize) -> usize {
        self.body().saturating_sub(reserved).max(20)
    }

    /// Whether there is room to place detail beside a label rather than under it.
    pub fn is_wide(self) -> bool {
        self.total >= 96
    }
}

impl Default for Layout {
    fn default() -> Self {
        Layout::of(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_terminals_are_clamped_up() {
        // Below MIN the layout stops shrinking; sub-56-column output is illegible
        // whatever we do, and shrinking further only makes the columns collide.
        assert_eq!(Layout::of(20).total, MIN);
        assert_eq!(Layout::of(40).total, MIN);
    }

    #[test]
    fn wide_terminals_are_capped() {
        // Long lines of prose are harder to read, not easier.
        assert_eq!(Layout::of(300).total, MAX);
        assert_eq!(Layout::of(200).total, MAX);
    }

    #[test]
    fn typical_widths_pass_through_with_breathing_room() {
        assert_eq!(Layout::of(80).total, 78);
        assert_eq!(Layout::of(100).total, 98);
        assert_eq!(Layout::of(120).total, 118);
    }

    #[test]
    fn body_accounts_for_the_indent() {
        assert_eq!(Layout::of(100).body(), 96);
    }

    #[test]
    fn room_is_measured_from_the_given_indent() {
        let layout = Layout::of(100);
        assert_eq!(layout.room(2), layout.body());
        assert_eq!(layout.room(4), 94);
        assert_eq!(layout.room(8), 90);
        // Deeper than the terminal is wide must not underflow.
        assert_eq!(layout.room(500), 0);
    }

    #[test]
    fn summary_grows_with_the_terminal() {
        // The whole point: a wider terminal must give content more room rather
        // than leaving empty space on the right.
        let narrow = Layout::of(80).summary(30);
        let wide = Layout::of(160).summary(30);
        assert!(wide > narrow, "{wide} should exceed {narrow}");
    }

    #[test]
    fn summary_never_collapses_to_nothing() {
        // Even if the reserved columns exceed the terminal, there must be room
        // for something legible.
        assert!(Layout::of(60).summary(500) >= 20);
    }

    #[test]
    fn wide_mode_engages_only_when_there_is_real_room() {
        assert!(!Layout::of(80).is_wide());
        assert!(Layout::of(120).is_wide());
    }

    #[test]
    fn columns_env_overrides_detection() {
        // Guards the override the width checks rely on.
        let previous = std::env::var_os("COLUMNS");

        std::env::set_var("COLUMNS", "72");
        assert_eq!(Layout::detect().total, 70);

        // Nonsense must not beat real detection.
        std::env::set_var("COLUMNS", "not-a-number");
        assert!(Layout::detect().total >= MIN);
        std::env::set_var("COLUMNS", "0");
        assert!(Layout::detect().total >= MIN);

        match previous {
            Some(value) => std::env::set_var("COLUMNS", value),
            None => std::env::remove_var("COLUMNS"),
        }
    }

    #[test]
    fn redirected_output_gets_a_stable_default() {
        // Piped output must not depend on the terminal that happened to launch it,
        // or diffing two runs becomes noise.
        assert_eq!(Layout::default().total, 98);
    }
}
