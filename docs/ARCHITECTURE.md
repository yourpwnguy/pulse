# pulse - Architecture (v0.1.0)

## What this is

**pulse triages known vulnerabilities in a Rust dependency tree.** It answers a
different question from `cargo audit`:

| Tool | Question |
|---|---|
| `cargo audit` | *Is this project vulnerable?* |
| pulse | *Given everything that's vulnerable, what do I fix first, and why?* |

Detection is a commodity - OSV gives the advisory data away for free. The
scarce thing is a ranked, deduplicated, explained worklist. So pulse's output is
not a list of CVEs and explicitly **not a score**; it's a queue in which every
entry carries the reasoning that put it there.

```
pulse                     # scan ., human output, exit 1 on actionable findings
pulse ~/code --format json --fail-on plan
```

---

## 1 · Layering

Dependencies point one way. Nothing below reaches upward.

```
        ┌──────────────────────────────────────────────┐
        │ cli.rs · main.rs · lib.rs::run               │  wiring, exit codes
        └───────────────────────┬──────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────┐
        │ render/  human · json · style                │  Report → bytes
        └───────────────────────┬──────────────────────┘   (decides nothing)
                                │
        ┌───────────────────────▼──────────────────────┐
        │ triage/   correlate · prioritise · explain   │  ← THE PRODUCT
        └───────────────────────┬──────────────────────┘   (pure)
                                │
        ┌───────────────┴───────────────┐
        │                               │
┌───────▼─────────┐          ┌──────────▼──────────┐
│ lockfile/       │          │ osv/                │   ← the ONLY impure code
│ disk → domain   │          │ network → domain    │
└───────┬─────────┘          └──────────┬──────────┘
        └───────────────┬───────────────┘
                        │
        ┌───────────────▼──────────────────────────────┐
        │ domain/  package · project · advisory ·      │  pure types + their
        │          severity (CVSS)                     │  logic. zero I/O.
        └──────────────────────────────────────────────┘
```

**Data flow is a straight line, once, with no state:**

```
paths → discover → parse(+graph) → dedupe packages → OSV lookup
      → correlate → merge aliases → prioritise → sort → render → exit code
```

### Why this structure

Directories are named for the *transformation* they perform, not for the
patterns they contain (`ingest`/`triage`/`render`, not `services`/`helpers`/
`utils`). Two consequences fall out:

- **You can locate any change from its description.** "Fix version resolution"
  is `domain/advisory.rs`. "Severity is wrong" is `domain/severity.rs`. "Output
  is ugly" is `render/`.
- **The compiler enforces the layering.** `domain` imports nothing from the
  crate. It cannot accidentally grow a network call.

---

## 2 · The central decision: functional core, imperative shell

All the logic worth getting right - CVSS scoring, version-range matching, alias
merging, prioritisation - is a **pure function over owned values**. I/O lives in
two leaf modules (`lockfile`, `osv`) that make no decisions.

This is why **v0.1.0 has no traits.** The reference implementation defined three
(`Parser`, `AdvisorySource`, `Store`), each with exactly one unit-struct
implementation, in order to be testable. But a trait with one implementor isn't
an abstraction, it's indirection charging rent - you pay in `dyn` dispatch,
extra files, and a jump to find real behaviour, and collect nothing.

Separating pure logic from I/O buys the same testability for free. The
integration suite builds a `BTreeMap<Package, Vec<Advisory>>` by hand and drives
the real pipeline with **no mocking framework, no network, and no tempdirs**:

```rust
let report = pulse::scan_offline(&[fixture("vulnerable-app")], &advisories)?;
assert_eq!(report.findings[0].priority, Priority::Plan);
```

235 tests, ~1:1 test-to-implementation ratio, full suite in **under 10ms**.

---

## 3 · Domain modelling

Three deliberate choices, each fixing a real defect found in the reference code:

**Versions are `semver::Version`, never `String`.** Every interesting question
is a version comparison, and string comparison gets them wrong - `"0.10.0" <
"0.9.0"` is `true`. There's a test asserting exactly that, as a tripwire.

**Severity carries provenance.**

```rust
struct Severity { rating: Rating, score: Option<f64>, vector: Option<String>, provenance: Provenance }
```

A severity without provenance isn't evidence. The report shows whether a number
was computed locally from a CVSS vector, taken from a vendor's word, or is
genuinely unknown. `Rating::Unknown` is a first-class value that is never
silently treated as "safe".

**Origin explains *who can fix it*.**

```rust
enum Origin { Direct, Transitive { depth: usize, path: Vec<String> } }
```

Derived from a BFS over the lockfile graph. This is the axis existing scanners
bury: a vulnerable direct dependency is a one-line change you own; one five
levels down may need an upstream maintainer first. Completely different work,
and the report says which - `reached via ureq → rustls → rustls-webpki (depth 3)`.

---

## 4 · Correctness work (the actual security engineering)

Four bugs in the reference implementation, verified against the live OSV API.
These are the reason the rewrite exists.

### 4.1 Severity was silently always unknown → score was always 100

`extract_severity` read `database_specific.severity`. That field **does not exist
on RustSec advisories** (they carry `{"license": "CC0-1.0"}`). It returned
`None`, the scorer weighted `None` as 0 penalty, and a project full of real
advisories reported a perfect 100/100.

**Fix:** implement the CVSS v3.1 base-score equations, including the
specification's integer-arithmetic `Roundup` (naive `(x*10).ceil()/10.0` is
wrong for values just below a tenth). Tested against published NVD scores.

We **refuse to score CVSS v4.0** rather than invent a number, and fall back to
the database's word - mapping GitHub's `MODERATE` onto `Medium`, which the old
code's exact-match on `"MEDIUM"` dropped on the floor.

### 4.2 Remediation advice pointed at still-vulnerable versions

Ranges are interval *sequences*. RUSTSEC-2020-0071 really looks like:

```
introduced 0.0.0-0, fixed 0.2.0, introduced 0.2.1-0, fixed 0.2.1, …, introduced 0.2.7-0, fixed 0.2.23
```

`.find_map(|e| e.fixed)` returned the **first** `fixed` - `0.2.0`. For a user on
`0.2.7` the real fix is `0.2.23`. The tool told you to upgrade to a version that
was still exploitable, which is worse than saying nothing because you stop
looking.

**Fix:** `AffectedRange::fix_for(version)` finds the interval *containing your
version* and returns that interval's bound. `Bound` distinguishes `Fixed`
(a patch exists) from `LastAffected` (upper bound, no patch) from `Unbounded` -
only `Fixed` licenses an upgrade recommendation.

### 4.3 Cross-package range contamination

One advisory can cover many packages across ecosystems (GHSA routinely does).
The old code flat-mapped every `affected[]` entry together, so a Cargo crate
could inherit an npm package's version ranges. **Fix:** filter `affected[]` to
the package being asked about *before* extracting anything.

### 4.4 The same vulnerability reported two or three times

OSV aggregates databases, so one `time` bug arrives as both
`RUSTSEC-2020-0071` and `GHSA-wcg3-cvx6-7396`, each listing the other as an
alias - **and they disagree about the fix** (`0.2.0` vs `0.2.23`). Found by
running against the live API, not by reading code.

**Fix:** merge findings whose identifier sets intersect, within a package.
When databases disagree, keep the **worst severity and the highest fix version** -
the conservative answer leaves you patched. Verified live: 3 findings → 2, and
three genuinely distinct `rustls-webpki` bugs correctly stay separate.

Also fixed: withdrawn advisories are dropped; informational RustSec notices
(unmaintained/yanked) are separated from exploitable defects, because calling an
unmaintained crate a vulnerability costs the whole report its credibility.

---

## 4.5 · Effort, batching, and the reward loop

Three additions that exist to move the report from *diagnosis* to *action*.

**Effort classification.** `domain/effort.rs` compares the installed version to
the fix under Cargo's semver rules. `0.103.9 → 0.103.13` is a patch bump and gets
labelled `quick win`; `0.1.44 → 0.2.23` is **breaking**, because for `0.x`
releases the minor is the compatibility axis. No other scanner draws this
distinction, and it is the difference between a five-minute task and an
afternoon.

**Remediation batching.** Findings whose fixes are semver-compatible are grouped
by the command that applies them, and the most productive command is promoted to
the top of the report:

```
▸ start here   one command clears 4
  cargo update -p rustls-webpki
```

Breaking changes are deliberately excluded from batches: they are decisions, not
commands.

**The progress loop.** `progress.rs` diffs the current report against the
previous run and reports movement (`✓ 6 fixed since last run`) before it reports
problems.

Two invariants keep this from corrupting the tool's purpose:

- **XP is only ever earned by fixing.** Nothing pays out for having few findings,
  and nothing pays out for suppressing one. The fastest route to a reward must
  never be to hide a vulnerability.
- **Newly disclosed advisories cost nothing.** A CVE published overnight is not
  the user's failure, so it never reduces XP or resets a streak. It is reported
  in neutral language (`3 newly disclosed`).

---

## 5 · Was the 0–100 score worth keeping? No.

**The 0–100 score was a gimmick and it's gone.** Reasons, in order of severity:

1. **It was broken in the exact case it existed for** (§4.1): unknown severity →
   0 penalty → 100/100 while genuinely vulnerable.
2. **The weights were unfalsifiable.** Why is a critical 25 and a medium 7?
   There's no answer, so the number can't be argued with - and a number you
   can't argue with is one you can't act on.
3. **Averaging across projects actively hid the problem.** `score_overall` was
   the mean of project scores, so nine clean repos mathematically concealed one
   compromised one. That's the opposite of what a fleet view is for.
4. **It compressed away everything that determines what you do.** Is there a
   patch? Do I own the dependency? Is it reachable? A scalar throws all of it out.

What replaced it keeps the *useful* instinct (a glanceable signal, a
prioritisation) without the fiction:

```rust
enum Priority { Act, Plan, Monitor, Note }
```

- **Act** - high impact *and* a patch exists. Highest return on effort.
- **Plan** - a patch exists, lower or unrated impact.
- **Monitor** - no patch. Upgrading isn't an option; mitigate or replace.
- **Note** - not an exploitable defect (unmaintained/yanked).

Ordering is `Act < Plan < Monitor < Note`, so ascending order *is* descending
urgency and `--fail-on` is a `<=` comparison. Every finding carries a plain
English `rationale`. **Fixability is checked before impact**, which is why a
fixable critical outranks an unfixable one: it's work that can actually be
finished today.

Counts that a bucket could hide are surfaced separately -
`unpatchable_severe`, `unrated`, `packages_unscannable` - so the report discloses
its own blind spots instead of manufacturing confidence.

---

## 5.4 · The interface is part of the product

An audit tool that goes unread has zero value regardless of how correct it is, so
the presentation layer is engineered rather than decorated.

**Grouped by package, not advisory.** `render/report/group.rs` folds every
advisory for one package into a single block, and sets the target to the *highest*
fix among them, so the one upgrade shown resolves all of them. On a real tree this
turned a 22-line wall into an 8-line block. The unit of work is a package upgrade;
the report is now shaped like the work.

**Exactly one call to action.** `render/report/action.rs` prints a single command with its
payoff (`clears 4 findings`). Forty equally-weighted problems is not a task list -
it is a reason to close the terminal.

**Doki** (`render/mascot.rs`) is a companion whose mood is a *pure function of the
report*. It cannot be cheerful while something is unpatched, and it reacts to what
you fixed before mentioning what remains. Attachment to a small creature returns
people to a tool more reliably than a number does; making the mood derived rather
than decorative is what keeps it from lying.

**Motion, on one line.** `render/live/` runs a worker thread that redraws a
single stderr line at ~12fps: a heartbeat with a real cardiac rhythm (two beats,
then rest - uneven timing is what reads as alive), a blinking face, and a bar that
*sweeps* while the work size is unknown and *fills* once it is known. An
indeterminate wait must never be drawn as a partially filled bar, because that
depicts progress which is not happening.

It is one line by design: multi-line animation needs cursor-up sequences that
corrupt the display on wrap or resize. The cursor is hidden on start and restored
in `Drop`, so no error path can leave the terminal broken, and the whole thing is
inert unless stderr is a TTY - a CI log should not collect 200 frames. The frame
composer is a pure function, so the animation is unit-tested without a terminal.

**Vertical rhythm.** Every section emits its own trailing blank line and never a
leading one. The previous layout mixed both conventions, which is why gaps were
uneven - two blanks in some combinations, none in others. One convention makes
spacing correct for every combination without any section knowing about the rest.

**Ordering follows the peak-end rule.** Progress first (your effort mattered),
action second, backlog third, caveats last, and a single closing
hint so the report never dead-ends.

---

## 5.5 · Scope must be auditable

A tool that decides what to scan by walking the filesystem has to be able to show
its work. `pulse -P` lists the discovered projects and makes no network call, so
the scanned set can be checked before anyone relies on it.

Two consequences shaped the design:

- **Skipped projects live in the `Report`** (`skipped_projects`), not in a local
  variable in `main`. A suppression list is the one kind of state a security tool
  must never keep quietly, so every run names what it skipped and why.
- **Project names are forced unique** (`lib.rs::disambiguate`). A finding's
  identity is `project|package|advisory`; two directories yielding the same name -
  a crate and a vendored copy, or `foo/` and `archive/foo/` - would have collided
  in both the triage de-duplicator and the progress file, silently merging two
  projects' findings. Collisions now gain the distinguishing parent directory:
  `pulse` and `pulse (v0.1.0)`.

Alignment in this view is measured with `unicode-width`, in terminal *cells*.
Character counts are not enough - a CJK glyph is one `char` occupying two cells -
and this is the same class of bug as the byte-based padding that made the old
renderer panic.

---

## 5.6 · `--fix`

`fix.rs` closes the loop: apply the upgrades, re-scan, watch the findings
disappear. Completion is the reward, and a second manual invocation dilutes it.

The safety boundary is the whole design. `--fix` only ever runs
`cargo update -p <name>`, which is bounded by the manifest's existing
requirements and reversible from version control. It **never** applies a breaking
change - including a `0.x` minor bump, which Cargo treats as breaking - and never
edits `Cargo.toml`. Rewriting a manifest is a different level of trust than a
v0.1.0 has earned.

`plan()` is pure: report in, upgrades out. It can be asserted against without
running a subprocess, which is how the "never applies a breaking change" property
is actually tested rather than merely claimed. A project whose root cannot be
resolved is skipped rather than guessed at - running cargo in the wrong directory
is worse than doing nothing.

---

## 6 · What was deleted, and why

| Removed | Reason |
|---|---|
| `Store` trait + `JsonStore` + data dir | Persisted a *stale-by-construction* cache of the dependency index - data that lives in the lockfile and went stale the moment anyone ran `cargo update`. Replaced by `history.rs`, which stores only what *cannot* be recomputed: what the user has already seen and fixed. Findings are still computed fresh every run. |
| `init` / `status` / `check` commands | Existed only to manage that cache. One stateless command replaces four. |
| `Parser`, `AdvisorySource` traits | One implementation each; testability achieved by purity instead (§2). |
| 0–100 scoring | §5. |
| `output/vulnbox.rs` box drawing | Padded with `str::len` (**bytes**) and sliced with `&s[..n]` - a guaranteed **panic** on any non-ASCII advisory summary, and misaligned boxes once ANSI codes were counted. Replaced by indentation, which cannot misalign. |
| `ansi256_from_rgb` | Reimplemented, incorrectly, what wasn't needed. ~12 lines of ANSI now. |
| `indicatif` progress bar | Created, never incremented, immediately cleared. Rendered `0/N` and vanished. |
| `chrono`, `directories`, `console`, `color-eyre`, `path` | Needed only by the deleted features. (`color-eyre` also pulled a transitive dep that **doesn't compile** on current Rust - the old project does not build.) |

Dependencies went **12 → 7**, all mainstream: `clap`, `serde`, `serde_json`,
`toml`, `semver`, `ureq`, `walkdir`. No async runtime: the program makes a
handful of requests and exits, so `tokio` would be ceremony.

Errors are a hand-rolled 5-variant enum implementing `std::error::Error` - six
known failure modes that `main` matches on to pick exit codes. `anyhow` would
have bought nothing.

---

## 7 · Tradeoffs, stated plainly

- **Stateless means re-querying OSV every run.** ~4.4s for 287 packages. The
  honest fix is an HTTP cache keyed by advisory ID - *not* the deleted project
  index. Deferred, not forgotten.
- **Cargo only.** The reference implementation half-wired npm: discovered
  `package-lock.json`, never parsed it, and shipped an `npm` ecosystem field that
  did nothing. Claiming one ecosystem and delivering it beats claiming two and
  delivering 1.5.
- **`ecosystem_specific.affects.functions` is surfaced, not evaluated.** pulse
  prints affected symbols as a starting point for `grep`. It does **not** claim
  reachability - that needs call-graph analysis. Stating the limit is the point.
- **No dev/build-dependency distinction.** `Cargo.lock` doesn't record it; that
  needs `cargo metadata`. Depth is the available proxy and it's honest about it.
- **CVSS v4.0 unscored.** Large interpolation table; refusing beats guessing.
- **Exit codes:** `0` clean, `1` gated findings, `2` tool error. Conflating 1 and
  2 is how a CI job goes green because the network was down.
- **The default gate is `act`, deliberately.** Failing a build over a
  vulnerability with no available patch teaches people to pass `--no-verify`. A
  gate nobody can satisfy is a gate that gets switched off.

---

## 8 · Where this goes next

Ordered by value per unit of work:

1. **Advisory cache** (`~/.cache/pulse`, keyed by ID + `modified`). Kills the
   only real performance complaint. Reintroduces disk state - but as a *cache
   with an invalidation key*, which is what the old index should have been.
2. **npm support.** `package-lock.json` v2/v3 `packages` entries carry `dev` and
   `optional` flags, so npm gets a **true runtime/dev split** - better fidelity
   than Cargo. `Ecosystem` is already an enum and `lockfile::parse` already
   dispatches on filename; this is one new module.
3. **`--baseline report.json`.** Diff against a previous run and gate only on
   *new* findings. This is what makes the tool adoptable in CI on a legacy repo
   with 40 pre-existing findings, and it's cheap because the JSON schema is
   already stable and round-trips through serde.
4. **`cargo metadata` integration** for real dev/build classification - the
   single largest noise reduction available, since most audit noise is
   dev-only dependencies.
5. **Reachability, honestly.** Cross-reference `affected_functions` against the
   crate's own source. Even a naive symbol grep would beat the status quo, and
   the data is already fetched and modelled.

Explicit non-goals: plugins, a daemon, a config file format, an async runtime,
an SBOM generator, a web dashboard.

---

## 9 · Repository layout

```
v0.1.0/
├── Cargo.toml                  self-contained workspace
├── ARCHITECTURE.md
└── src/
    ├── main.rs                 imperative shell: args → exit code
    ├── lib.rs                  run(): the pipeline in one readable sequence
    ├── cli.rs                  clap definitions only, no logic
    ├── error.rs                5 typed variants, no error crate
    ├── domain/                 pure. no I/O. imports nothing from the crate.
    │   ├── mod.rs              re-exports
    │   ├── package.rs          Ecosystem · Package · Origin
    │   ├── project.rs          Project · ResolvedPackage
    │   ├── advisory.rs         Advisory · AffectedRange · Bound  ← fix resolution
    │   ├── severity.rs         Rating · Severity · CVSS v3.1 base score
    │   ├── effort.rs           Effort classification (Trivial/Compatible/Breaking)
    │   └── age.rs              Date arithmetic without chrono
    ├── lockfile/               disk → domain
    │   ├── mod.rs              discovery, pruning
    │   └── cargo.rs            Cargo.lock + BFS dependency graph
    ├── osv/                    network → domain
    │   ├── mod.rs              batching, dedup, the only HTTP
    │   ├── wire.rs             private serde types + pure mapping
    │   └── cache.rs            two-tier advisory cache (7-day bodies, 1-hour matches)
    ├── triage/                 correlate · merge aliases · prioritise · explain
    │   ├── mod.rs              public API: triage() function
    │   ├── types.rs            Priority · Fix · Finding · Summary · Report
    │   ├── policy.rs           prioritise() and explain() - the triage policy
    │   ├── merge.rs            alias merging across databases
    │   ├── sort.rs             deterministic finding order
    │   ├── build.rs            Finding construction from raw inputs
    │   └── summarise.rs        aggregate counts
    ├── fix.rs                  --fix: apply upgrades, verify against lockfile
    ├── progress.rs             cross-run diffing (Delta, Headline)
    ├── history.rs              persistent state (JSON, atomic writes)
    └── render/
        ├── mod.rs              format dispatch, Format enum
        ├── report/             human-readable report
        │   ├── mod.rs          View struct, render() entry point
        │   ├── header.rs       stats panel, Doki body, movement text
        │   ├── action.rs       single next command line
        │   ├── group.rs        package grouping and rendering
        │   ├── sections.rs     priority bucket sections
        │   ├── hints.rs        caveats and closing suggestions
        │   └── wrap.rs         word wrapping for advisory prose
        ├── live/               animated scan narration
        │   ├── mod.rs          Live, Reporter, Stage enum
        │   ├── state.rs        shared state for animation thread
        │   └── compose.rs      frame composition (pure, testable)
        ├── json.rs             the Report *is* the schema
        ├── mascot.rs           Doki: mood, expressions, body art
        ├── panel.rs            bordered stats board
        ├── projects.rs         project list view
        ├── style.rs            ~12 lines of ANSI, honours NO_COLOR
        ├── line.rs             Line type (ANSI-safe, CJK-safe width)
        └── layout.rs           terminal width detection and clamping
```

`tests/pipeline.rs` drives the whole pipeline over `tests/fixtures/`, including
a `nested/target/Cargo.lock` that must never be scanned and overlapping paths
that must not double-count.
