GOAL: Polish existing Rust codebase, one module at a time, remove bloat, no functionality change.
DECISIONS:
- order: smallest-risk leaf modules first, lib.rs last (done)
- em-dash purge done per-module (hard rule: none in comments/docs; user-facing
  strings keep byte-identical output via \u{2014} escape in source)
- verify with cargo test + clippy per module, commit per change (done, 14 commits)
INVARIANTS:
- CLI output, exit codes, JSON format unchanged (verified: output strings escaped, not reworded)
- All 19 integration + 214 unit tests pass, clippy 0 warnings, fmt clean
- No new features, no renames
DONE:
- baseline: 19 integration pass
- domain/render layering: Rating::colour_hint removed, render::style::severity_colour is single owner (34ed6b1)
- clippy.toml msrv 1.74 -> 1.88 to match Cargo.toml (34ed6b1)
- cli.rs docs purge (aaf89c9)
- osv/mod.rs filter-chain indent (4e74a7e)
- osv/wire.rs redundant ecosystem disjunct removed, Ecosystem import scoped to tests (7aff289, 61402a1)
- fix.rs indent + doc purge, output preserved via escape (972b22b, c3ad1ba)
- render small files: line/layout/json indent, per-char alloc removed in truncate (6148cec)
- render/mod.rs + panel.rs doc purge, output preserved (c3ad1ba)
- projects.rs doc purge, output preserved (e0a2b96)
- live/mod.rs misplaced mood() doc fixed, dialogue preserved (42bf500)
- live/compose.rs fully-qualified paths replaced with imports (fa0a947)
- report/* indent + doc purge (f546401)
- mascot.rs doc purge, dialogue preserved (1fccdb6)
- lib.rs scan_once extracted for initial + post-fix scans (f90dfbb)
- domain/triage/osv/history/progress/lockfile/tests doc purge (f53ea72)
- ARCHITECTURE.md + README.md hyphen pass (89990d4)
- triage/*, lockfile/cargo.rs, history.rs, progress.rs, live/state.rs, wrap.rs, error.rs, domain package/project/age/advisory/effort: reviewed, no bloat, left alone
ATTEMPTS:
- (none failed; one fixup commit 61402a1 for test import after 7aff289)
NEXT:
- done. Working tree clean, ready for feature work.
OPEN QUESTIONS:
- (none)
