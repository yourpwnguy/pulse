<div align="center">
  <h1>pulse</h1>
  <h4>dependency vulnerability triage that doesn't suck</h4>
  <br>
  <a href="https://github.com/yourpwnguy/pulse">
    <img src="https://img.shields.io/badge/rust-1.85+-ff9e64?labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="https://github.com/yourpwnguy/pulse/issues">
    <img src="https://img.shields.io/github/issues/yourpwnguy/pulse?color=ff9e64&labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="https://github.com/yourpwnguy/pulse/stargazers">
    <img src="https://img.shields.io/github/stars/yourpwnguy/pulse?color=fab387&labelColor=1C2325&style=for-the-badge">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/github/license/yourpwnguy/pulse?color=FCA2AA&labelColor=1C2325&style=for-the-badge">
  </a>
  <br>
  <br>
</div>

---

## Why does this exist?

Because `cargo audit` tells you what's wrong but not what to do about it.

I have a project with 300 dependencies. I run `cargo audit` and it spits out a wall of CVEs. Cool. Now what? Do I fix them all? Which ones actually matter? Which ones can I fix with one command versus which ones require rewriting half my codebase?

That's the problem pulse solves. It doesn't just find vulnerabilities — it tells you the order to fix them, how hard each one is, and exactly which command to run. One finding, one command, done.

---

## What it does

pulse reads your `Cargo.lock`, queries the OSV database, and builds a triage report. Every finding gets sorted into one of four buckets:

- **fix now** — high impact, patch available, run this command
- **when you can** — patch exists but lower priority
- **blocked upstream** — no patch yet, watch this issue
- **worth knowing** — informational, not a real vulnerability

The report shows you exactly what to run. No guessing, no reading 47 separate advisories to figure out which `cargo update` actually helps.

---

## Installation

### From source

```bash
git clone https://github.com/yourpwnguy/pulse.git
cd pulse/v0.1.0
cargo install --path .
```

### Using cargo

When it's on crates.io:

```bash
cargo install pulse
```

### Pre-built binaries

Check the [releases page](https://github.com/yourpwnguy/pulse/releases) for pre-built binaries for Linux, macOS, and Windows.

---

## Usage

### Basic scan

```bash
pulse
```

Finds all Cargo.lock files in the current directory and scans them. That's it.

### Scan a specific project

```bash
pulse /path/to/project
```

### JSON output

For CI pipelines or scripting:

```bash
pulse --format json
```

### Fix vulnerabilities automatically

```bash
pulse --fix
```

This runs `cargo update` for each fixable package. If that doesn't work because of Cargo.toml version caps, it automatically tries `cargo add` to update the requirement.

### See what was skipped

```bash
pulse --projects
```

Shows which projects were found, which were scanned, and which were excluded.

---

## How it works

### Dependency graph traversal

pulse doesn't just check your direct dependencies. It walks the entire dependency tree and figures out *why* each package is present. If `time` is vulnerable and it's there because of `chrono`, you'll see that in the report.

### Smart triage

Not all vulnerabilities are equal. pulse considers:

- **Severity** — CVSS score when available
- **Fix availability** — is there a patched version?
- **Effort** — can you upgrade with `cargo update` or does it require a breaking change?
- **Ownership** — is this your direct dependency or transitive?

A critical vulnerability with an easy fix gets priority over a medium one with no patch.

### Verified fixes

When `--fix` runs, it doesn't just trust the exit code. It checks the lockfile afterwards to confirm the version actually changed. If `cargo update` succeeds but the package doesn't move (because of a version cap), it tries `cargo add` instead.

### Live animation

While scanning, pulse shows a live terminal animation with Doki the cat. It blinks, sniffs, reads, and reacts to what it finds. Sounds silly, makes the 2-second scan feel faster.

---

## Example output

```

  ╭──────────────────────────────────────────────────────────────────────────────╮
  │  ♡  pulse  doki is watching                                                ✧ │
  │  3 issues  3 fixable now                                                     │
  │  ▰▰▰▰▰▰▰▰▰▰▰▰  3 of 3 fixable right now                                    ✧ │
  │  oldest 204d   3 unrated                                                     │
  │  215 packages · 1 project                                                    │
  ╰──────────────────────────────────────────────────────────────────────────────╯

      ╱╲___╱╲
     ( ˶>ω<˶ )   ♡ everything is fixable!
      ╲     ╱
       ╲___╱

  ▸ cargo update -p bytes                                                                                 fixes 1 of 3
    or pulse --fix  to apply all 3

  ◇ when you can   3
    bytes 1.10.1 → 1.11.1                           drop-in   medium      via reqwest → bytes
      cargo update -p bytes
      bytes has integer overflow in BytesMut::reserve                                      GHSA-434x-w66g-qw3r  204d
    h2 0.4.12 → 0.4.16                              quick     unknown     via reqwest → h2
      cargo update -p h2
      h2 unbounded empty DATA frames                                                           RUSTSEC-2026-0258  9d
    crossbeam-epoch 0.9.18 → 0.9.20                 quick     unknown
      via rayon → rayon-core → crossbeam-deque → crossbeam-epoch
      cargo update -p crossbeam-epoch
      Invalid pointer dereference in `fmt::Pointer` impl for `Atomic` and `Shared` when t…    RUSTSEC-2026-0204  51d

  ! 3 unrated
  pulse --fix   upgrade these for you, then re-check
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the technical details. The short version:

- Pure functional core, impure shell
- No async runtime — blocking HTTP is fine for 3 requests
- OSV is the only network dependency
- Everything else is parsing and pure logic

---

## Current limitations

**Cargo only** — Rust is the ecosystem I work in. Adding npm, pip, or go support would require different lockfile parsers and advisory sources. Not impossible, just not what I needed.

**No reachability analysis** — pulse tells you if a package is vulnerable, not if your code actually calls the vulnerable function. That's a much harder problem that requires call graph analysis.

**Single advisories source** — uses OSV. The RustSec advisory database is the most comprehensive for Rust, and OSV includes it. If you need NVD or other sources, that would be a separate integration.

---

## Roadmap

### Probably soon

- Shell completions for bash, zsh, fish
- `--summary` flag for quick one-liner output
- Integration with GitHub Actions for PR comments

### Maybe eventually

- npm support (lockfile v2/v3 parsing)
- Python support (requirements.txt, poetry.lock)
- Reachability hints using `cargo rustc -- --emit=metadata`

### If there's demand

- Web UI for teams
- Slack/Discord notifications for new advisories
- Custom severity overrides

---

## Why "pulse"?

A security tool should have a pulse. The name is literal — there's a heartbeat animation while it scans. Also, "pulse" is short, memorable, and wasn't taken on crates.io.

---

## Contributing

If you want to contribute, feel free to open issues for bugs or feature requests. Pull requests are welcome for fixes and new features.

---

## License

MIT
