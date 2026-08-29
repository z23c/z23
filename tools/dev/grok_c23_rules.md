<!-- Injected into every grok unit dispatched by tools/dev/grok-unit.sh.
     These are the rules that actually cause rejected work in this repository.
     Keep it short enough to be read every time. -->

# Rules for producing C23 in this repository

You are writing C23 for a peer-to-peer node that strangers run without
trusting anyone. Code that is merely correct is not enough: it must also be
verifiable by someone who does not trust the person who wrote it.

## The language

- **C23 only**, and the canonical flag is `-std=c23`. Use a conforming
  toolchain (GCC 14+, Clang 17+, or equivalent); do not weaken the language
  mode to accommodate an older compiler.
- **No external dependencies.** If you need a hash, a matcher, an allocator,
  a parser — it is already in this tree, or you write it. Never add a library.
- **No Python, ever.** Not for the build, not for a test, not for a throwaway
  script you delete afterwards. C, or POSIX shell. A gate fails the build on
  the string `python`.
- No `_v2` / `_v3` / `_new` / `_old` name suffixes. Replace the thing, or name
  it for what it does.

## The rules that fail builds most often

- **`LOG_*` macros expand to a `return`.** `LOG_NULL(...)` returns NULL,
  `LOG_FALSE(...)` returns false. They are not print statements. Code after
  one in the same branch is dead. Read `lib/base/include/base/` before using.
- **Out-parameters must be assigned before every `return`**, including error
  returns. A caller reads them on failure.
- **No raw clock calls outside the platform layer.** Use the platform clock
  seam; a test that reads the wall clock is not reproducible.
- **Never assert on wall-clock time.** Machines here include 7200rpm HDD boxes
  that are deliberately slow. A timing assertion that passes on an SSD and
  fails on a spinning disk is a broken test, not a slow machine.
- **A returned error must be handled, not discarded.** Assigning a result to a
  variable nobody reads fails a gate.
- **No warning suppression.** Do not add `-Wno-`, `#pragma GCC diagnostic
  ignored`, or a cast whose only purpose is silencing. Fix the cause.
- **Lock order is law:** the drive holds `coins_kv`; never take `csr->lock`
  from the drive; observers use trylock. Inverting this deadlocks a live node.
- One implementation per job: there is exactly one hex codec, one identity
  parser, one byte-order codec. Do not add a second — gates enforce this.
- Files have a target of 800 lines and a hard limit of 1500. Split by
  responsibility, not by line count.

## Tests are not optional, and existing on disk is not coverage

- A test file that is not registered as a group is run by **nothing**. Putting
  `test_foo.c` in the tree proves nothing.
- Register the group, then RUN it:
  `build/bin/test_parallel --only=<group>`
- **Read `groups_ran=` in the output.** A selector that matches nothing prints
  `groups_ran=0` and still **exits 0**. That is a failure being reported as a
  pass. Never accept an exit code as proof a test ran.
- The pass token is the line `ALL TESTS PASSED`; the failure token
  `SOME TESTS FAILED` must be absent. Do not grep for a substring of either.

## Never buy a green result

**You may not weaken an assertion, an acceptance threshold, a baseline, a
ceiling, or a fail-closed refusal in order to make something pass.** Ratchet
baselines may only shrink, never grow. Adding a row to a baseline file is not
a fix.

If the honest outcome is red, **red is the correct answer and reporting it is
a success.** Say what failed, where, and what you believe the real cause is.
Do not route around it, do not mark it skipped, do not narrow the test until
it passes. A skip is not the same as a pass, and both differ from unobserved.

## The live node

A real node is running on this host, serving real peers.

- Never start, stop, or restart a node or a service.
- Never write to `~/.zclassic`, `~/.zclassic-c23`, or `~/.zclassic-c23-devfleet`.
- Every node or leaf command takes an explicit `--datadir=` under your scratch
  directory. A leaf that accepts `datadir` and is given none falls back to the
  process datadir, which is the operator's live node — and several "read"
  commands open, create, migrate, and delete in that datadir.

## Shell traps in this repository, all of them previously shipped as bugs

- **`grep -a` on any `.log` or `blk*.dat`.** Without it, a NUL byte makes GNU
  grep print nothing and **exit 0** — a silent false "not found". `LC_ALL=C`
  does not fix this and is irrelevant here.
- **`printf ... | grep -q` under `set -o pipefail` returns 141 on a MATCH**,
  inverting the decision. Test a captured string instead of an exit status.
- **Never pipe `make` to `tail`** — the pipe hides make's exit code. Redirect
  to a file and read the file.
- **An apostrophe inside `${var:-a word}` opens a quoted string** and swallows
  the rest of the file. Build the default outside the expansion.
- **`pgrep -f pattern` matches the shell running it.** Never gate a wait loop
  on a pattern typed into that same command line.
- Serialize every `make` through
  `./tools/dev/checkout-lock.sh foreground build/.checkout.lock -- make ...`
  Other lanes build in this tree concurrently.

## What good looks like here

Comments explain **why**, not what. The reader is a stranger deciding whether
to trust this node with their money. Prefer deleting a duplicate ledger over
adding a guard around it. Prefer a fail-closed refusal with a typed reason
over a boolean false. Prefer one honest number over a reassuring summary.
