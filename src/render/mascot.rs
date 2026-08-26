//! Doki — the cat who watches your dependencies.
//!
//! One face, many expressions, always exactly [`CELLS`] columns wide so it can sit
//! inside a bordered panel without making the border ragged.
//!
//! Two things live here, and both exist to make the tool feel *alive while it is
//! working*:
//!
//! * **Doki's face**, which is a pure function of what the tool is doing or has
//!   found. It cannot smile at an unpatched critical.
//! * **The heartbeat wave**, an ECG trace that scrolls while work is in flight.
//!   A tool called `pulse` should have a pulse, and a moving trace communicates
//!   "something is happening" faster than any spinner.
//!
//! Kaomoji rather than emoji: they render in a fixed number of cells at any font
//! size, need no colour-emoji support, and are the native idiom of the aesthetic.

use crate::domain::Rating;

use super::style::{Colour, CORAL, GOLD, MINT, ROSE, SKY, SLATE};

/// The cat's name. Surfaced in the interface so it reads as a character
/// rather than as decoration.
pub const NAME: &str = "doki";

/// Display width of every face. Fixed so panels stay rectangular.
pub const CELLS: usize = 9;

/// Doki's expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mood {
    // ── resting ──
    Idle,
    Blink,
    Wink,
    Glance,
    // ── working ──
    Sniff,
    Think,
    Read,
    Pounce,
    // ── pleased ──
    Happy,
    Cheer,
    Love,
    Purr,
    // ── concerned ──
    Worried,
    Startled,
    Hurt,
    // ── other ──
    Sleep,
}

impl Mood {
    /// Doki's face. Every arm is exactly [`CELLS`] columns; there is a test.
    pub fn face(self) -> &'static str {
        match self {
            Mood::Idle => "(=˶•ω•˶=)",
            Mood::Blink => "(=˶-ω-˶=)",
            Mood::Wink => "(=˶•ω^˶=)",
            Mood::Glance => "(=˶◜ω◝˶=)",
            Mood::Sniff => "(=˶•ᴗ•˶=)",
            Mood::Think => "(=˶･ᴖ･˶=)",
            Mood::Read => "(=˶◉ω◉˶=)",
            Mood::Pounce => "(=˶>ω<˶=)",
            Mood::Happy => "(=˶^ω^˶=)",
            Mood::Cheer => "(=˶✧ω✧˶=)",
            Mood::Love => "(=˶♡ω♡˶=)",
            Mood::Purr => "(=˶ᵕωᵕ˶=)",
            Mood::Worried => "(=˶;ω;˶=)",
            Mood::Startled => "(=˶OωO˶=)",
            Mood::Hurt => "(=˶╥ω╥˶=)",
            Mood::Sleep => "(=˶-ω-˶=)",
        }
    }

    /// Body colour, so the emotional read lands before any text is parsed.
    pub fn colour(self) -> Colour {
        match self {
            Mood::Happy | Mood::Cheer | Mood::Purr => MINT,
            Mood::Love => ROSE,
            Mood::Worried | Mood::Startled => GOLD,
            Mood::Hurt => CORAL,
            Mood::Sniff | Mood::Think | Mood::Read | Mood::Pounce => SKY,
            Mood::Sleep => SLATE,
            _ => ROSE,
        }
    }

    /// What Doki says. Short, warm, never scolding — a tool that makes you feel
    /// told off gets closed once and not reopened.
    pub fn line(self) -> &'static str {
        match self {
            Mood::Cheer => "you cleared a whole batch!",
            Mood::Love => "you fixed something, nice",
            Mood::Purr => "nothing left to fix — doki is pleased",
            Mood::Happy => "doki feels safe here",
            Mood::Idle => "just some housekeeping",
            Mood::Think => "found a little work for later",
            Mood::Worried => "one thing is bothering doki",
            Mood::Startled => "oh! that one is big",
            Mood::Hurt => "doki cannot fix this one alone",
            Mood::Sleep => "nothing to do",
            Mood::Pounce => "everything is fixable!",
            Mood::Blink | Mood::Wink | Mood::Glance => "",
            Mood::Sniff => "sniffing around...",
            Mood::Read => "reading advisories...",
        }
    }

    /// Mood from what the report actually says.
    ///
    /// Takes numbers rather than a `Report` so the mascot has no dependency on the
    /// domain: it is a presentation detail, and wiring it to the report is how a
    /// mascot ends up deciding what "severe" means.
    ///
    /// Reacts to *what you just did* before *what is left*, because nagging over
    /// progress is how a tool loses its user.
    pub fn from_report(
        issues: usize,
        blocked: usize,
        critical: usize,
        all_fixable: bool,
        fixed_now: usize,
    ) -> Mood {
        // 1. celebrate work that was actually done
        //
        // Only moods whose dialogue is *about fixing* may be used here. Reaching for
        // `Happy` ("doki feels safe here") once produced that line while four issues
        // were still open, which is the kind of small lie that costs a tool its
        // credibility.
        if fixed_now > 0 {
            return if fixed_now >= 3 {
                Mood::Cheer
            } else {
                Mood::Love
            };
        }

        // 2. nothing left at all
        if issues == 0 {
            return Mood::Purr;
        }

        // 3. something genuinely alarming
        if critical > 0 {
            return Mood::Startled;
        }
        if blocked > 0 {
            return Mood::Hurt;
        }

        // 4. plenty to do, but all of it is one command away
        if all_fixable {
            return Mood::Pounce;
        }

        // 5. a lot to wade through
        if issues > 8 {
            return Mood::Worried;
        }

        Mood::Think
    }

    /// Mood for a severity, used when a single finding is being highlighted.
    pub fn from_rating(rating: Rating) -> Mood {
        match rating {
            Rating::Critical => Mood::Startled,
            Rating::High => Mood::Worried,
            Rating::Medium => Mood::Think,
            _ => Mood::Idle,
        }
    }

    pub fn is_alarmed(self) -> bool {
        matches!(self, Mood::Worried | Mood::Startled | Mood::Hurt)
    }

    pub fn is_happy(self) -> bool {
        matches!(self, Mood::Happy | Mood::Cheer | Mood::Love | Mood::Purr)
    }
}

/// Columns the character occupies.
pub const BODY_WIDTH: usize = 10;

/// Rows the character occupies.
pub const BODY_HEIGHT: usize = 4;

/// The full character, for the live view where there is room for it.
///
/// Returned as plain strings so [`super::line::Line`] can measure and colour
/// them; building escape sequences here would defeat the width tracking that
/// keeps the layout honest.
pub fn body(mood: Mood) -> [String; BODY_HEIGHT] {
    [
        "  ╱╲___╱╲".to_string(),
        format!(" ( {} )", mood.eyes()),
        "  ╲     ╱".to_string(),
        "   ╲___╱".to_string(),
    ]
}

impl Mood {
    /// The eyes-and-mouth cluster, without the `(=` `=)` frame.
    ///
    /// An explicit table rather than a slice of [`Mood::face`]. Slicing that string
    /// by byte offset split the multi-byte `˶` cheeks — a panic waiting for the
    /// first person to open the live view, and the exact bug class this crate has
    /// been removing everywhere else. A test keeps the two tables in step.
    pub fn eyes(self) -> &'static str {
        match self {
            Mood::Idle => "˶•ω•˶",
            Mood::Blink => "˶-ω-˶",
            Mood::Wink => "˶•ω^˶",
            Mood::Glance => "˶◜ω◝˶",
            Mood::Sniff => "˶•ᴗ•˶",
            Mood::Think => "˶･ᴖ･˶",
            Mood::Read => "˶◉ω◉˶",
            Mood::Pounce => "˶>ω<˶",
            Mood::Happy => "˶^ω^˶",
            Mood::Cheer => "˶✧ω✧˶",
            Mood::Love => "˶♡ω♡˶",
            Mood::Purr => "˶ᵕωᵕ˶",
            Mood::Worried => "˶;ω;˶",
            Mood::Startled => "˶OωO˶",
            Mood::Hurt => "˶╥ω╥˶",
            Mood::Sleep => "˶-ω-˶",
        }
    }
}

/// The resting animation: blink, glance and the occasional wink.
///
/// Doki is never perfectly still. The three events run on different periods so
/// the loop does not read as a repeating cycle even though it is.
pub fn idle(frame: usize) -> Mood {
    match frame % 44 {
        20 | 21 => Mood::Blink,
        30..=33 => Mood::Glance,
        38 | 39 => Mood::Wink,
        _ => Mood::Idle,
    }
}

/// The working animation: alternates so it reads as busy rather than frozen.
pub fn busy(frame: usize) -> Mood {
    match (frame / 6) % 4 {
        0 => Mood::Sniff,
        1 => Mood::Read,
        2 => Mood::Sniff,
        _ => Mood::Think,
    }
}

/// A scrolling ECG trace.
///
/// A tool named `pulse` should have one. The trace is a repeating cardiac
/// waveform — flat baseline, a sharp spike, a small echo, then rest — scrolled one
/// cell per frame. Motion plus an uneven rhythm is what reads as *alive*; a
/// uniform bar reads as a machine.
pub fn wave(frame: usize, cells: usize) -> String {
    // One full beat, drawn with block glyphs (all single-width).
    const BEAT: &[char] = &[
        '▁', '▁', '▁', '▂', '▅', '█', '▅', '▂', '▁', '▁', '▂', '▃', '▂', '▁', '▁', '▁', '▁', '▁',
    ];

    (0..cells).map(|i| BEAT[(frame + i) % BEAT.len()]).collect()
}

/// A twinkle glyph for the given frame, or a space.
pub fn sparkle(frame: usize) -> &'static str {
    match frame % 16 {
        0 | 1 => "✧",
        8 | 9 => "·",
        _ => " ",
    }
}

/// A single beating heart, for places too narrow for the full trace.
pub fn heartbeat(frame: usize) -> &'static str {
    const BEATS: &[&str] = &[
        "♡", "♥", "❤", "♥", "♡", "♡", "♥", "❤", "♥", "♡", "♡", "♡", "♡", "♡",
    ];
    BEATS[frame % BEATS.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    const ALL: &[Mood] = &[
        Mood::Idle,
        Mood::Blink,
        Mood::Wink,
        Mood::Glance,
        Mood::Sniff,
        Mood::Think,
        Mood::Read,
        Mood::Pounce,
        Mood::Happy,
        Mood::Cheer,
        Mood::Love,
        Mood::Purr,
        Mood::Worried,
        Mood::Startled,
        Mood::Hurt,
        Mood::Sleep,
    ];

    /// The invariant that keeps the bordered panel rectangular.
    #[test]
    fn every_face_is_exactly_the_documented_width() {
        for mood in ALL {
            assert_eq!(
                UnicodeWidthStr::width(mood.face()),
                CELLS,
                "{mood:?} face {:?} is {} cells, expected {CELLS}",
                mood.face(),
                UnicodeWidthStr::width(mood.face())
            );
        }
    }

    /// The two glyph tables must agree, or the character and the inline face stop
    /// looking like the same creature.
    #[test]
    fn face_and_eyes_stay_in_step() {
        for mood in ALL {
            assert_eq!(
                mood.face(),
                format!("(={}=)", mood.eyes()),
                "{mood:?} face and eyes disagree"
            );
        }
    }

    #[test]
    fn the_character_is_the_documented_size_for_every_mood() {
        // Exercises `body` for every mood, which is what would have caught the
        // byte-slicing panic that used to live in `eyes`.
        for mood in ALL {
            let rows = body(*mood);
            assert_eq!(rows.len(), BODY_HEIGHT);
            for row in &rows {
                let cells = UnicodeWidthStr::width(row.as_str());
                assert!(
                    cells <= BODY_WIDTH,
                    "{mood:?} row {row:?} is {cells} cells, max {BODY_WIDTH}"
                );
            }
        }
    }

    #[test]
    fn clean_tree_is_happy() {
        assert_eq!(Mood::from_report(0, 0, 0, false, 0), Mood::Purr);
    }

    #[test]
    fn blocked_findings_are_the_worst_mood() {
        assert_eq!(Mood::from_report(3, 1, 0, false, 0), Mood::Hurt);
        assert!(Mood::Hurt.is_alarmed());
    }

    #[test]
    fn fixing_overrides_the_backlog_and_scales() {
        assert_eq!(Mood::from_report(5, 1, 0, false, 1), Mood::Love);
        assert_eq!(Mood::from_report(5, 1, 0, false, 2), Mood::Love);
        assert_eq!(Mood::from_report(5, 1, 0, false, 4), Mood::Cheer);
    }

    #[test]
    fn the_reaction_scales_with_the_situation() {
        // A critical outranks a merely blocked finding.
        assert_eq!(Mood::from_report(3, 1, 1, false, 0), Mood::Startled);
        // Everything fixable is an opportunity, not a worry.
        assert_eq!(Mood::from_report(6, 0, 0, true, 0), Mood::Pounce);
        // A big pile with no single alarming item.
        assert_eq!(Mood::from_report(20, 0, 0, false, 0), Mood::Worried);
        // A small pile.
        assert_eq!(Mood::from_report(2, 0, 0, false, 0), Mood::Think);
    }

    /// The mood's dialogue has to match the situation it was chosen for.
    ///
    /// Regression: `from_report` used to return `Happy` after two fixes, and
    /// `Happy` says "doki feels safe here" — which appeared on screen while four
    /// issues were still open.
    #[test]
    fn never_claims_safety_while_issues_remain() {
        const REASSURING: &[&str] = &["safe", "nothing left", "nothing to do"];

        for issues in [1usize, 2, 5, 20] {
            for blocked in [0usize, 1] {
                for critical in [0usize, 1] {
                    for all_fixable in [false, true] {
                        for fixed_now in [0usize, 1, 2, 5] {
                            let mood = Mood::from_report(
                                issues,
                                blocked,
                                critical,
                                all_fixable,
                                fixed_now,
                            );
                            let line = mood.line();
                            for phrase in REASSURING {
                                assert!(
                                    !line.contains(phrase),
                                    "with {issues} issues open, {mood:?} says {line:?}"
                                );
                            }
                        }
                    }
                }
            }
        }

        // And the clean state does reassure.
        assert!(Mood::from_report(0, 0, 0, false, 0)
            .line()
            .contains("nothing left"));
    }

    #[test]
    fn has_a_name() {
        assert!(!NAME.is_empty());
    }

    #[test]
    fn severity_maps_to_a_proportionate_reaction() {
        assert_eq!(Mood::from_rating(Rating::Critical), Mood::Startled);
        assert_eq!(Mood::from_rating(Rating::High), Mood::Worried);
        assert!(!Mood::from_rating(Rating::Low).is_alarmed());
    }

    #[test]
    fn idle_animation_blinks_glances_and_mostly_rests() {
        let moods: Vec<Mood> = (0..44).map(idle).collect();
        assert!(moods.contains(&Mood::Blink));
        assert!(moods.contains(&Mood::Glance));
        assert!(moods.contains(&Mood::Wink));

        let resting = moods.iter().filter(|m| **m == Mood::Idle).count();
        assert!(resting > 30, "doki is twitching: {resting}/44 at rest");
    }

    #[test]
    fn busy_animation_actually_changes() {
        let moods: Vec<Mood> = (0..24).map(busy).collect();
        let distinct: std::collections::HashSet<_> = moods.iter().collect();
        assert!(distinct.len() >= 2, "busy doki looks frozen");
    }

    #[test]
    fn wave_is_the_requested_width_and_scrolls() {
        for cells in [1, 8, 16, 40] {
            let trace = wave(0, cells);
            assert_eq!(UnicodeWidthStr::width(trace.as_str()), cells);
        }

        // It must move, or it is just a bar.
        assert_ne!(wave(0, 16), wave(1, 16));
        // And it must come back around rather than drifting off.
        assert_eq!(wave(0, 16), wave(18, 16));
    }

    #[test]
    fn wave_has_a_spike_and_a_baseline() {
        // A flat trace would not read as a heartbeat.
        let trace = wave(0, 18);
        assert!(trace.contains('█'), "no spike in the trace");
        assert!(
            trace.chars().filter(|c| *c == '▁').count() > 6,
            "not enough baseline for the spike to stand out"
        );
    }

    #[test]
    fn heartbeat_rhythm_is_uneven() {
        let beats: Vec<&str> = (0..14).map(heartbeat).collect();
        assert!(beats.iter().filter(|b| **b == "♡").count() > 6);
        assert!(beats.contains(&"❤"));
    }

    #[test]
    fn sparkle_is_occasional() {
        let on = (0..32).filter(|f| sparkle(*f) != " ").count();
        assert!(on > 0 && on < 16, "sparkle should be rare, got {on}/32");
    }

    #[test]
    fn no_mood_scolds_the_user() {
        for mood in ALL {
            let line = mood.line();
            // Blink, wink, and glance are visual animations — no dialogue expected.
            if !matches!(mood, Mood::Blink | Mood::Wink | Mood::Glance) {
                assert!(!line.is_empty());
            }
            for banned in [
                "fail",
                "should have",
                "you didn't",
                "bad",
                "wrong",
                "stupid",
            ] {
                assert!(!line.contains(banned), "{mood:?} scolds: {line}");
            }
        }
    }

    #[test]
    fn happy_and_alarmed_are_mutually_exclusive() {
        for mood in ALL {
            assert!(!(mood.is_happy() && mood.is_alarmed()), "{mood:?}");
        }
    }
}
