//! The live scan: motion while pulse works.
//!
//! A tool that prints nothing for two seconds reads as *frozen*, and first
//! contact is where users are lost. This narrates the same two seconds: a HUD, an
//! animated Doki, a checklist that ticks, and per-stage detail lines showing the
//! actual CVSS vectors and version resolutions as they happen.
//!
//! Everything shown is real work that already happened silently. Surfacing it is
//! free, and it is the only way anyone discovers the tool does more than grep a
//! database.
//!
//! ## Invariants
//!
//! * **Fixed height.** The region is [`REGION`] rows and every frame is padded to
//!   exactly that. Frames that grow silently lose their bottom rows (that is how
//!   a completed stage ends up with no tick against it.
//! * **stderr only.** `pulse -o json > out.json` must stay clean.
//! * **Inert when redirected.** A CI log should not collect 300 frames.
//! * **The cursor always comes back.** Hidden on start, restored in `Drop`, so no
//!   error path can leave an invisible cursor behind.

mod compose;
mod state;

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::mascot::Mood;
use super::style::Style;

/// Frame interval. ~25fps: smooth and responsive.
const FRAME: Duration = Duration::from_millis(62);

/// Minimum time a stage stays on screen.
///
/// Long enough to read the line and see the bar move; short enough that nine
/// stages take about one second. Only applies when a terminal is watching.
const DWELL: Duration = Duration::from_millis(220);

/// Total rows the animation owns. Sized for the worst-case frame with margin.
const REGION: usize = 24;

/// A step in the pipeline, in execution order.
///
/// An enum rather than strings so the pipeline and the renderer cannot disagree
/// about what exists, and so `all()` can render the not-yet-started steps greyed
/// out (an unfinished list is what keeps you watching).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Discover,
    Parse,
    Graph,
    Query,
    Fetch,
    Score,
    Resolve,
    Merge,
    Triage,
}

impl Stage {
    pub const fn all() -> [Stage; 9] {
        use Stage::*;
        [
            Discover, Parse, Graph, Query, Fetch, Score, Resolve, Merge, Triage,
        ]
    }

    /// The label shown in the checklist.
    pub const fn label(self) -> &'static str {
        match self {
            Stage::Discover => "discovering lockfiles",
            Stage::Parse => "parsing lockfiles",
            Stage::Graph => "walking dependency graph",
            Stage::Query => "querying osv.dev",
            Stage::Fetch => "fetching advisories",
            Stage::Score => "scoring cvss vectors",
            Stage::Resolve => "resolving fix versions",
            Stage::Merge => "merging aliases",
            Stage::Triage => "triaging",
        }
    }

    /// What Doki says while this stage runs.
    ///
    /// First person, curious, never technical for its own sake. The tool is doing
    /// real work and the line names it, so reading the dialogue teaches you what
    /// the tool actually does.
    pub const fn saying(self) -> &'static str {
        match self {
            Stage::Discover => "sniffing around for lockfiles…",
            Stage::Parse => "reading what you depend on…",
            Stage::Graph => "working out who dragged in what…",
            Stage::Query => "asking osv if it knows these…",
            Stage::Fetch => "pulling the advisories down…",
            Stage::Score => "doing the cvss arithmetic…",
            Stage::Resolve => "checking which versions actually fix it…",
            Stage::Merge => "same bug, two databases \u{2014} merging…",
            Stage::Triage => "sorting by what is worth your time…",
        }
    }

    /// Doki's expression while this stage runs, so the mascot's behaviour tracks
    /// the work rather than looping independently of it.
    const fn mood(self) -> Mood {
        match self {
            Stage::Discover => Mood::Sniff,
            Stage::Parse | Stage::Fetch => Mood::Read,
            Stage::Query => Mood::Pounce,
            Stage::Merge | Stage::Triage => Mood::Think,
            _ => Mood::Sniff,
        }
    }
}

/// The handle the pipeline uses to report what it is doing.
///
/// Cloneable and cheap. When the animation is inert (redirected output, tests)
/// every method is a no-op, so calling code never branches on whether a terminal
/// is present.
#[derive(Clone)]
pub struct Reporter(Option<Arc<state::Shared>>);

impl Reporter {
    /// A reporter that discards everything.
    pub fn silent() -> Reporter {
        Reporter(None)
    }

    /// Marks a stage as started.
    pub fn begin(&self, stage: Stage) {
        if let Some(shared) = &self.0 {
            *state::lock(&shared.started) = std::time::Instant::now();
            *state::lock(&shared.current) = Some(stage);
            state::lock(&shared.detail).clear();
            shared.total.store(0, Ordering::Relaxed);
            shared.done_count.store(0, Ordering::Relaxed);
        }
    }

    /// Adds a detail line under the running stage. This is the verbose output:
    /// real vectors, real version resolutions, real request counts.
    pub fn detail(&self, text: impl Into<String>) {
        if let Some(shared) = &self.0 {
            let mut detail = state::lock(&shared.detail);
            detail.push(text.into());
            // Keep only the most recent lines: the region is fixed, and older
            // detail has already been read.
            let overflow = detail.len().saturating_sub(2); // DETAIL_ROWS = 2
            detail.drain(..overflow);
        }
    }

    /// Switches the bar from sweeping to filling.
    pub fn total(&self, total: usize) {
        if let Some(shared) = &self.0 {
            shared.total.store(total, Ordering::Relaxed);
        }
    }

    /// Advances determinate progress.
    pub fn tick(&self) {
        if let Some(shared) = &self.0 {
            shared.done_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Holds the current stage on screen for at least [`DWELL`].
    ///
    /// Without this, a warm cache finishes nine stages in about two milliseconds and
    /// the entire narration is a single flicker (all the work, none of the sense
    /// that anything happened). Pacing is a deliberate cost: roughly a third of a
    /// second per stage, only when someone is watching.
    ///
    /// A no-op when the animation is inert, so scripts and CI pay nothing.
    pub fn dwell(&self) {
        let Some(shared) = &self.0 else {
            return;
        };
        let elapsed = state::lock(&shared.started).elapsed();
        if let Some(remaining) = DWELL.checked_sub(elapsed) {
            thread::sleep(remaining);
        }
    }

    /// Completes the running stage, recording its summary.
    pub fn finish(&self, stage: Stage, summary: impl Into<String>) {
        if let Some(shared) = &self.0 {
            state::lock(&shared.done).push((stage, summary.into()));
            *state::lock(&shared.current) = None;
            state::lock(&shared.detail).clear();
        }
    }
}

/// A running animation. Cleans up on drop.
pub struct Live {
    shared: Option<Arc<state::Shared>>,
    handle: Option<JoinHandle<()>>,
}

impl Live {
    /// Starts the animation, or returns an inert handle when stderr is not a
    /// terminal or colour is disabled.
    pub fn start(style: Style) -> Live {
        if !style.is_colour() || !std::io::stderr().is_terminal() {
            return Live {
                shared: None,
                handle: None,
            };
        }

        let shared = Arc::new(state::Shared {
            done: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            detail: Mutex::new(Vec::new()),
            started: Mutex::new(std::time::Instant::now()),
            done_count: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            running: AtomicBool::new(true),
        });

        let worker = Arc::clone(&shared);
        let handle = thread::spawn(move || animate(&worker, style));

        Live {
            shared: Some(shared),
            handle: Some(handle),
        }
    }

    pub fn reporter(&self) -> Reporter {
        Reporter(self.shared.as_ref().map(Arc::clone))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let Some(shared) = self.shared.take() else {
            return;
        };
        shared.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }

        // Erase the region and restore the cursor. Done here rather than in the
        // worker so it still happens if the thread panicked.
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[{REGION}A\x1b[0J\x1b[?25h");
        let _ = err.flush();
    }
}

/// The render loop.
fn animate(shared: &Arc<state::Shared>, style: Style) {
    let mut err = std::io::stderr();
    let _ = write!(err, "\x1b[?25l");

    // Reserve the region so the first redraw has somewhere to go.
    let _ = write!(err, "{}", "\n".repeat(REGION));

    let mut frame = 0usize;
    while shared.running.load(Ordering::Relaxed) {
        let lines = compose::compose(shared, frame, style);

        let mut out = String::new();
        out.push_str(&format!("\r\x1b[{REGION}A"));
        for row in 0..REGION {
            out.push_str("\x1b[2K");
            if let Some(line) = lines.get(row) {
                out.push_str(&line.to_string());
            }
            out.push('\n');
        }
        let _ = write!(err, "{out}");
        let _ = err.flush();

        frame = frame.wrapping_add(1);
        thread::sleep(FRAME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::line::Line;
    use crate::render::style::Style;

    fn shared() -> std::sync::Arc<state::Shared> {
        std::sync::Arc::new(state::Shared {
            done: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            detail: Mutex::new(Vec::new()),
            started: Mutex::new(std::time::Instant::now()),
            done_count: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            running: AtomicBool::new(true),
        })
    }

    fn reporter_for(shared: &std::sync::Arc<state::Shared>) -> Reporter {
        Reporter(Some(std::sync::Arc::clone(shared)))
    }

    fn text(lines: &[Line]) -> String {
        lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn frame_never_exceeds_the_region() {
        let shared = shared();
        let reporter = reporter_for(&shared);

        for stage in Stage::all() {
            reporter.begin(stage);
            reporter.detail("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            reporter.detail("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            reporter.detail("ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
            for frame in [0, 7, 23] {
                let lines = compose::compose(&shared, frame, Style::Colour);
                assert!(
                    lines.len() <= REGION,
                    "{stage:?} frame {frame} is {} rows, region is {REGION}",
                    lines.len()
                );
            }
            reporter.finish(stage, "done");
        }
    }

    #[test]
    fn every_finished_stage_gets_a_tick() {
        let shared = shared();
        let reporter = reporter_for(&shared);

        for stage in Stage::all() {
            reporter.begin(stage);
            reporter.finish(stage, "ok");
        }

        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        for stage in Stage::all() {
            assert!(
                rendered.contains(stage.label()),
                "{stage:?} missing from the final frame"
            );
        }
        assert_eq!(rendered.matches('✓').count(), Stage::all().len());
        assert!(rendered.contains("done"));
    }

    #[test]
    fn pending_stages_are_listed_before_they_run() {
        let shared = shared();
        reporter_for(&shared).begin(Stage::Discover);

        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        assert!(rendered.contains("triaging"));
        assert!(rendered.contains("merging aliases"));
    }

    #[test]
    fn detail_lines_are_capped_and_keep_the_newest() {
        let shared = shared();
        let reporter = reporter_for(&shared);
        reporter.begin(Stage::Score);
        for i in 0..10 {
            reporter.detail(format!("line {i}"));
        }

        let detail = state::lock(&shared.detail);
        assert_eq!(detail.len(), 2); // DETAIL_ROWS = 2
        assert_eq!(detail[1], "line 9");
    }

    #[test]
    fn determinate_progress_shows_a_counter() {
        let shared = shared();
        let reporter = reporter_for(&shared);
        reporter.begin(Stage::Fetch);
        reporter.total(7);
        reporter.tick();
        reporter.tick();

        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        assert!(rendered.contains("2/7"));
    }

    #[test]
    fn indeterminate_progress_shows_no_counter() {
        let shared = shared();
        reporter_for(&shared).begin(Stage::Query);
        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        assert!(!rendered.contains('/'));
    }

    #[test]
    fn header_names_the_running_stage() {
        let shared = shared();
        reporter_for(&shared).begin(Stage::Query);
        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        assert!(rendered.contains("querying osv.dev"));
    }

    #[test]
    fn header_carries_no_score() {
        let shared = shared();
        reporter_for(&shared).begin(Stage::Query);
        let rendered = text(&compose::compose(&shared, 0, Style::Plain));
        for banned in ["xp", "lv ", "streak", "guardian"] {
            assert!(
                !rendered.contains(banned),
                "live header mentions {banned:?}"
            );
        }
    }

    #[test]
    fn silent_reporter_is_inert() {
        let reporter = Reporter::silent();
        reporter.begin(Stage::Query);
        reporter.detail("x");
        reporter.total(5);
        reporter.tick();
        reporter.finish(Stage::Query, "done");
    }

    #[test]
    fn inert_live_spawns_no_thread() {
        let live = Live::start(Style::Plain);
        assert!(live.shared.is_none());
        live.reporter().tick();
    }

    #[test]
    fn frames_change_over_time() {
        let shared = shared();
        reporter_for(&shared).begin(Stage::Query);
        let a = text(&compose::compose(&shared, 0, Style::Plain));
        let b = text(&compose::compose(&shared, 3, Style::Plain));
        assert_ne!(a, b, "a still frame reads as a hang");
    }
}

/// Renders a sequence of frames to strings, for inspecting the animation without
/// a terminal. Test-only helper.
#[cfg(test)]
pub fn preview(frames: &[usize], done: &[(Stage, String)], current: Option<Stage>) -> Vec<String> {
    let shared = std::sync::Arc::new(state::Shared {
        done: Mutex::new(done.to_vec()),
        current: Mutex::new(current),
        detail: Mutex::new(vec![
            "serde 1.0.228".into(),
            "tokio 1.35.1".into(),
            "rustls 0.23.5".into(),
        ]),
        started: Mutex::new(std::time::Instant::now()),
        done_count: AtomicUsize::new(184),
        total: AtomicUsize::new(288),
        running: AtomicBool::new(true),
    });

    frames
        .iter()
        .map(|f| {
            compose::compose(&shared, *f, Style::Plain)
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect()
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    #[test]
    fn a_stage_never_appears_twice_in_the_checklist() {
        let done = vec![
            (Stage::Discover, "3 projects".to_string()),
            (Stage::Parse, "288 packages".to_string()),
            (Stage::Graph, "12 direct".to_string()),
        ];
        let frame = preview(&[0], &done, Some(Stage::Fetch)).remove(0);

        let checklist: Vec<&str> = frame
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with('✓') || t.starts_with('·') || t.starts_with('⠋') || t.starts_with('⠙')
            })
            .collect();

        for stage in Stage::all() {
            let seen = checklist
                .iter()
                .filter(|l| l.contains(stage.label()))
                .count();
            assert!(
                seen <= 1,
                "{stage:?} appears {seen} times in the checklist:\n{}",
                checklist.join("\n")
            );
        }

        assert_eq!(
            checklist.len(),
            Stage::all().len(),
            "expected every stage to be listed once"
        );
    }

    #[test]
    fn the_frame_shows_the_panel_the_trace_and_the_work() {
        let done = vec![(Stage::Discover, "3 projects".to_string())];
        let frame = preview(&[0], &done, Some(Stage::Fetch)).remove(0);

        assert!(frame.contains('╭') && frame.contains('╰'));
        assert!(frame.contains("pulse"));
        assert!(frame.contains("╱╲___╱╲"), "the character is missing");
        assert!(frame.contains('█'), "no ecg trace");
        assert!(frame.contains('✓'));
        assert!(frame.contains("184/288"));
        assert!(frame.contains("serde 1.0.228"));
        assert!(frame.contains("step 2 of 9"));
        assert!(frame.contains("╱╲___╱╲"), "the character is missing");
        assert!(
            Stage::all().iter().any(|s| frame.contains(s.saying())),
            "no dialogue on screen"
        );
    }
}
