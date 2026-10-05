GOAL: Polish existing Rust codebase, one module at a time, remove bloat, no functionality change.
DECISIONS:
- order: smallest-risk leaf modules first, lib.rs last
- em-dash purge done per-module as part of each module cleanup (hard rule: no em dashes)
- verify with cargo test + cargo clippy per module, commit per change
INVARIANTS:
- CLI output, exit codes, JSON format unchanged
- All 19 integration tests + unit tests must pass
- No new features, no renames without reason
DONE:
- baseline: cargo test 19 passed
ATTEMPTS:
NEXT:
- module 1: src/error.rs
- module 2: src/domain/mod.rs + domain/* 
- module 3: src/cli.rs
- module 4: src/history.rs, src/progress.rs
- module 5: src/lockfile/*
- module 6: src/osv/*
- module 7: src/triage/*
- module 8: src/fix.rs
- module 9: src/render/* (style, line, layout, panel, projects, json, live, report, mascot)
- module 10: src/lib.rs + src/main.rs
- final: cargo fmt, test, clippy full pass
OPEN QUESTIONS:
