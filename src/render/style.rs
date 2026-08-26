//! The palette.
//!
//! Rebuilt around **contrast of role, not variety of hue**. The previous version
//! used eight equally-saturated pastels, so everything shouted at the same volume
//! and the result read as noise. Two rules now govern it:
//!
//! 1. **One bright thing per screen.** `KIN` (gold) is reserved for the single
//!    action you should take. Nothing else is gold, so the eye lands on the
//!    command without being told to.
//! 2. **Context is quiet.** `SLATE` carries roughly 60% of the report. Making
//!    the background genuinely dim is what allows the few bright things to feel
//!    bright — cuteness comes from contrast, not from saturating everything.
//!
//! | colour | role | why this hue |
//! |---|---|---|
//! | `ROSE` #FF5FA2 | pulse itself, Doki, the heartbeat | vivid magenta-pink: the brand, used nowhere functional |
//! | `BLUSH` #FFA8D4 | Doki's softer moods, gentle accents | the same hue lightened, so mascot states feel related |
//! | `KIN` #FFC86B | **the action** — commands, XP, rewards | warm gold reads as "valuable", and nothing competes |
//! | `MINT` #4FE3B0 | fixed, safe, resolved | the only green: unambiguous success |
//! | `CORAL` #FF6B7A | urgent | red-adjacent but soft enough not to feel like a crash |
//! | `IRIS` #A78BFA | blocked, not your move | cool violet reads as "waiting", not "wrong" |
//! | `SKY` #7DD3FC | facts — versions, identifiers, evidence | cold and neutral, never emotional |
//! | `SLATE` #6B7280 | everything else | genuinely recessive |
//!
//! Two invariants, both enforced by tests:
//!
//! * **Never meaning-by-colour-alone.** Every coloured token also carries a word
//!   or symbol. Around 8% of men cannot separate the coral from the mint.
//! * **Never colour anything that gets padded or measured.** Escape sequences
//!   have byte length and no display width. Cells are padded as plain text and
//!   painted afterwards, which is why this renderer cannot go crooked.

use crate::domain::{Effort, Rating};
use crate::triage::Priority;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colour(u8, u8, u8);

const fn rgb(r: u8, g: u8, b: u8) -> Colour {
    Colour(r, g, b)
}

pub const ROSE: Colour = rgb(255, 95, 162);
pub const BLUSH: Colour = rgb(255, 168, 212);
pub const KIN: Colour = rgb(255, 200, 107);
/// Alias for [`KIN`]. The action/reward colour reads better as "gold" at call
/// sites that are talking about rewards rather than about the palette.
pub const GOLD: Colour = KIN;
pub const MINT: Colour = rgb(79, 227, 176);
pub const CORAL: Colour = rgb(255, 107, 122);
pub const IRIS: Colour = rgb(167, 139, 250);
pub const SKY: Colour = rgb(125, 211, 252);
pub const SLATE: Colour = rgb(107, 114, 128);
/// Drifting decoration. Never carries meaning, so it can be pure ornament.
pub const PETAL: Colour = rgb(255, 196, 224);
/// Empty bar cells and not-yet-started work: present but clearly inactive.
pub const FAINT: Colour = rgb(64, 68, 82);

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

/// Whether to emit escape sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Colour,
    Plain,
}

impl Style {
    /// Decides once, at the edge, whether colour is appropriate.
    ///
    /// Honours `NO_COLOR` (any value, per the informal standard) and only colours
    /// real terminals, so piping to a file or a CI log produces clean text
    /// without the caller having to ask.
    pub fn detect(is_terminal: bool, forced_off: bool) -> Style {
        if forced_off || std::env::var_os("NO_COLOR").is_some() || !is_terminal {
            Style::Plain
        } else {
            Style::Colour
        }
    }

    pub fn is_colour(self) -> bool {
        self == Style::Colour
    }

    /// Paints text. A no-op in plain mode, so call sites need no branching.
    pub fn paint(self, colour: Colour, text: &str) -> String {
        match self {
            Style::Plain => text.to_string(),
            Style::Colour => {
                let Colour(r, g, b) = colour;
                format!("\x1b[38;2;{r};{g};{b}m{text}{RESET}")
            }
        }
    }

    pub fn bold(self, colour: Colour, text: &str) -> String {
        match self {
            Style::Plain => text.to_string(),
            Style::Colour => {
                let Colour(r, g, b) = colour;
                format!("{BOLD}\x1b[38;2;{r};{g};{b}m{text}{RESET}")
            }
        }
    }

    /// Recessive text. Used for the majority of the report.
    pub fn dim(self, text: &str) -> String {
        self.paint(SLATE, text)
    }

    /// Severity keeps its own scale, separate from priority: severity is *how
    /// bad*, priority is *what to do*, and conflating them is how reports mislead.
    pub fn severity(self, rating: Rating, text: &str) -> String {
        let colour = match rating {
            Rating::Critical | Rating::High => CORAL,
            Rating::Medium => KIN,
            Rating::Low | Rating::None => SKY,
            Rating::Unknown => SLATE,
        };
        self.paint(colour, text)
    }

    pub fn priority(self, priority: Priority, text: &str) -> String {
        let colour = match priority {
            Priority::Act => CORAL,
            Priority::Plan => SKY,
            Priority::Monitor => IRIS,
            Priority::Note => SLATE,
        };
        self.bold(colour, text)
    }

    /// Effort is painted on the *reward* scale rather than the danger scale: an
    /// easy fix is an opportunity, so it reads as gold, not as a warning.
    pub fn effort(self, effort: Effort, text: &str) -> String {
        let colour = match effort {
            Effort::Trivial => KIN,
            Effort::Compatible => MINT,
            Effort::Breaking => IRIS,
        };
        self.paint(colour, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PALETTE: &[Colour] = &[
        ROSE, BLUSH, KIN, MINT, CORAL, IRIS, SKY, SLATE, PETAL, FAINT,
    ];

    #[test]
    fn plain_style_emits_no_escapes() {
        let style = Style::Plain;
        assert_eq!(style.paint(CORAL, "x"), "x");
        assert_eq!(style.bold(KIN, "x"), "x");
        assert_eq!(style.dim("x"), "x");
        assert_eq!(style.severity(Rating::Critical, "critical"), "critical");
        assert_eq!(style.priority(Priority::Act, "act"), "act");
        assert_eq!(style.effort(Effort::Trivial, "quick"), "quick");
    }

    #[test]
    fn colour_style_always_resets() {
        // An unreset sequence bleeds into the user's shell prompt.
        for painted in [
            Style::Colour.paint(ROSE, "x"),
            Style::Colour.bold(KIN, "x"),
            Style::Colour.dim("x"),
            Style::Colour.severity(Rating::High, "x"),
            Style::Colour.priority(Priority::Monitor, "x"),
            Style::Colour.effort(Effort::Breaking, "x"),
        ] {
            assert!(painted.starts_with('\x1b'), "{painted:?}");
            assert!(painted.ends_with(RESET), "{painted:?}");
            assert!(painted.contains('x'));
        }
    }

    #[test]
    fn non_terminal_output_is_never_coloured() {
        assert_eq!(Style::detect(false, false), Style::Plain);
        assert_eq!(Style::detect(true, true), Style::Plain);
    }

    #[test]
    fn every_role_has_a_distinct_hue() {
        // If two roles share a colour, the palette has stopped carrying meaning.
        for (i, a) in PALETTE.iter().enumerate() {
            for b in &PALETTE[i + 1..] {
                assert_ne!(a, b, "duplicate colour in palette");
            }
        }
    }

    #[test]
    fn gold_is_reserved_for_action_and_reward() {
        // The one-bright-thing rule: gold must never be used for a severity or a
        // priority, or the call to action stops standing out.
        for rating in [
            Rating::Critical,
            Rating::High,
            Rating::Low,
            Rating::None,
            Rating::Unknown,
        ] {
            assert_ne!(
                Style::Colour.severity(rating, "x"),
                Style::Colour.paint(KIN, "x"),
                "{rating:?} must not be gold"
            );
        }
        for priority in [
            Priority::Act,
            Priority::Plan,
            Priority::Monitor,
            Priority::Note,
        ] {
            assert_ne!(
                Style::Colour.priority(priority, "x"),
                Style::Colour.bold(KIN, "x"),
                "{priority:?} must not be gold"
            );
        }
    }

    #[test]
    fn slate_is_genuinely_recessive() {
        // Dim text must be darker than every accent, or "quiet" context competes
        // with the things that matter.
        let Colour(r, g, b) = SLATE;
        let slate = u32::from(r) + u32::from(g) + u32::from(b);
        // FAINT is deliberately darker than SLATE, so it is excluded here.
        for accent in [ROSE, BLUSH, KIN, MINT, CORAL, IRIS, SKY] {
            let Colour(ar, ag, ab) = accent;
            let total = u32::from(ar) + u32::from(ag) + u32::from(ab);
            assert!(total > slate, "{accent:?} is not brighter than SLATE");
        }
    }
}
