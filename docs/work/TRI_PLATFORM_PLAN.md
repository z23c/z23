<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Tri-platform mission: build, sync, and install on Linux, macOS, Windows

Ordering authority remains [`FORWARD_PLAN.md`](./FORWARD_PLAN.md). This file
owns one cross-cutting question that no single item there owns: **what a
person on a Mac or a Windows machine can actually do with Z23 today, and the
ordered work that closes the gap.**

Z23 was developed primarily on Linux. That is not a defect by itself — it is
a defect only where a Linux assumption is *silent*: where a harness, a gate,
or an install path answers confidently on Linux and answers wrongly, or not
at all, somewhere else. Every item below is aimed at a silent assumption.

Do not copy live heights, dated benchmarks, or host state here. Where this
file states a fact, it names the command that produced it, so a reader can
re-run it instead of trusting the prose.

## The three verbs

A platform is not "supported" as one boolean. Z23 has three independent
claims, and they are at three different stages on each platform:

| Verb | Means | Proven by |
|---|---|---|
| **build** | the C23 source compiles and links natively into a node binary | `make z23` + that platform's binary audit |
| **sync** | the node joins the ZClassic network and reaches the peer tip | a chain-sync receipt observed on that platform |
| **install** | a stranger with no toolchain gets a running node in one command | a published bootstrap for that platform's triple |

Conflating them is how a platform gets called "working" when only the first
verb holds. The table below keeps them apart.

## Verified baseline

Re-derived on 2026-08-30 from the commands named; do not trust the cells
without re-running them.

| | Linux x86_64 | macOS arm64 | Windows x86_64 |
|---|---|---|---|
| build | yes, primary | yes, native Clang (`AGENTS.md` §Verified platform baseline) | yes, native UCRT64 PE (`docs/WINDOWS.md`) |
| sync | yes | **no receipt** — startup evidence only, explicitly not chain-sync acceptance | boot and block sync ported; no observed full-sync receipt |
| install | bootstrap published | **none** | **none** |

The install row is the sharpest and the least ambiguous. Asked directly:

```bash
packaging/release/build_release.sh --print-bootstrap-platforms   # linux-x86_64
packaging/release/build_release.sh --print-runtime-platforms     # linux-x86_64 darwin-arm64 windows-x86_64
```

The cutter already produces a **runtime** for all three. It produces a
**bootstrap** for one. `packaging/install/install.sh` therefore carries
`PUBLISHED_PLATFORMS=" linux-x86_64 "` and `packaging/install/install.ps1`
carries `$BootPins = @{}`. Both refuse honestly rather than 404, which is the
correct behaviour for an unpublished platform — but it means the answer to
"can my friend with a Mac run this" is still no, and the missing piece is
packaging, not portability.

## 1. The darwin naming split — CLOSED

Two vocabularies disagreed about the name of the same machine. The front door
normalised `arm64` to `aarch64`, so a Mac named itself `darwin-aarch64`, while
`packaging/release/build_release.sh`, `lib/platform/src/toolchain.c`,
`config/platform/macos_capabilities.def` and
[`BOOTSTRAP_PLAN.md`](./BOOTSTRAP_PLAN.md) all name the Mac artifact
`darwin-arm64`. `tools/lint/check_published_platforms.sh` compares the two by
exact string.

Nothing was red, because the front door claimed only `linux-x86_64` and the
two sets never met. They would have met the moment anyone published the Mac,
and every Mac alive would then have been told *"no runtime is published for
darwin-aarch64; published: darwin-arm64"* — a refusal naming a machine that
does not exist, for a machine we do ship.

Resolved toward the machine's own name, which is what four of the five
authorities already used: the shims and the C front door no longer rewrite
`arm64`, so a Mac names itself `darwin-arm64` and a Linux arm box keeps
`linux-aarch64`. Only the `amd64`/`x86_64` alias is still folded, because
every publisher spells that one `x86_64`.

The rail that makes it stay closed is check 7 in
`tools/lint/check_published_platforms.sh`. Checks 1-6 all ask whether a claim
EXCEEDS what is produced; check 7 asks the other direction — whether what is
produced is REACHABLE by the machine it is for. It reads the fold table out of
`packaging/install/install.sh` rather than restating it, so the gate cannot
hold a second copy that drifts, and it refuses any produced platform whose cpu
is a fold source. Its selftest case restores the old `arm64` fold and asserts
the gate goes red, so the bug is frozen as a regression rather than written
down as a caution.

## 2. Publish a bootstrap for the two runtimes that already exist

The runtime exists for all three; only `linux-x86_64` has a bootstrap. Per
`docs/WINDOWS.md`, a Windows artifact must be cut on Windows (vendored
archives are configured with no target, `vendor/lib` has one slot per archive
name, and `opensslconf.h` and `event2/event-config.h` are generated per <!-- doc-path-ok: generated by libevent's configure into the build tree, never a repo file -->
target, so two targets cannot coexist in one checkout). The same one-host-per-target
rule holds for `darwin-arm64`, which `build_release.sh` already states must
be cut natively on Apple hardware.

So this item is not a cross-build; it is a cut on each machine plus the
second-stage installer and service lifecycle behind it. Order:

1. `darwin-arm64` — the Mac lane is furthest along and `install.sh` already
   has the POSIX fetch path; it needs the case arm, the `BOOT_*` row, and a
   real digest from a native cut.
2. `windows-x86_64` — `install.ps1` needs its first `$BootPins` row, and
   `make windows-service-install` already owns the lifecycle.

`check_published_platforms.sh` holds the sentinel that every checked-in digest
is the all-zero value; keep it that way — the cutter writes real digests into
copies, never into the checkout.

## 3. Earn a sync receipt on each platform

Building is not syncing, and this repository is already careful to say so:
`AGENTS.md` calls the macOS baseline "startup evidence, not chain-sync
acceptance", and the Windows data-directory receipt is recorded as
*unobserved* because Wine returned 77 rather than proving native SID/DACL
semantics.

Keep that honesty and close the gap the only way that counts — run the
existing acceptance on the real hardware and record what it says:

```bash
make mvp                      # honest criterion reporter; BLOCKED is not green
make test-two-node-peer-tip
make mvp-coldstart-to-tip-stopwatch
```

A named BLOCKED result is evidence of an unmet prerequisite. It is never
permission to weaken the assertion, and a Wine or emulation result is never a
substitute for the platform's own receipt.

## 4. Make the harness stop assuming Linux, with a gate rather than a note

The node's platform seams are guarded and audited. The **harness** around
them — acceptance scripts, lint gates, operator probes — is where the silent
Linux assumptions still live, and it is exactly the layer an agent runs
first, so a wrong answer here costs a cycle before any C compiles.

Measured on this tree with `git grep` over tracked `*.sh`:

| Assumption | Sites | Files | Non-Linux fallback |
|---|---|---|---|
| `ss(8)` for port probing | 23 | 19 | 1 |
| `nproc` for job count | 38 | 27 | Apple ships no `nproc`; a stripped PATH silently yields 8 workers |
| `stat -c` (GNU spelling) | 96 | 45 | BSD/macOS `stat` needs `-f` |
| `sed -i` (GNU spelling) | 28 | 10 | BSD/macOS `sed -i` requires an argument |

`tools/scripts/two_node_peer_tip.sh` already carries the shape the rest
should follow: try `ss`, fall back to `lsof`, then `netstat`, and **refuse by
name** when no probe exists rather than treating "cannot tell" as "port is
free". That last clause is the point — every one of these, read carelessly,
fails *open*.

Extract the fallback into one sourced helper rather than copying it 19 times,
then add a gate that refuses a *new* bare `ss`/`nproc`/`stat -c`/`sed -i` in a
tracked script, ratcheted against a baseline of the existing sites the way
`check_pipefail_status_pipe.sh` ratchets its own class. Prefer
`getconf _NPROCESSORS_ONLN` over `nproc`, which is what
`docs/GETTING_STARTED.md` already tells a reader to type.

## 5. The pipefail inversion class — CLOSED, and now ratcheted

`check_pipefail_status_pipe.sh` explains the bug precisely: under
`set -o pipefail`, `producer | grep -q needle` reports 141 when the needle IS
present, because `grep -q` exits at the first match and the producer takes
SIGPIPE. A match and a miss become indistinguishable. In a lint gate — which
greps *for* a violation — the inverted read is a hollow PASS.

The gate used to ratchet only the `printf`/`echo` producer shape, and said in
its own header that an arbitrary producer was "a different, larger job". That
job is done in two halves: 27 sites converted by hand, then the gate widened
to count a `-q` grep behind ANY producer (`grep`, `egrep`, `fgrep`,
`gate_grep`) and the remainder ratcheted.

The measured reconciliation is worth recording, because a hand grep gets it
badly wrong. A naive `git grep '| grep -q'` over pipefail scripts reports
~183 sites; the gate's quote-aware tokeniser — which strips comments, joins
continuation lines, and refuses to count value pipelines or scripts without
pipefail — reports that widening the producer set added exactly **7 files and
9 sites**, because the 27 hand conversions had already cleared nearly the
whole class. Total after widening: 137 sites in 51 files, and
`RATCHET_CEILING` is now that exact total rather than a number with slack in
it. **Do not reconcile this against a hand grep**; the tokeniser is the
authority and the header says so.

What remains is burn-down, not design. Each of the 137 is converted the same
way — capture, then test — and every conversion should keep the assertion it
replaced rather than merely its shape: `arch_score.sh` and `soak_evidence.sh`
each gained a real "the command itself failed" arm that the pipeline had been
swallowing. The ratchet is shrink-only and there is deliberately no
allow-comment escape hatch, so the counts can only go down.

## 6. Make a refusal name the thing that is missing — CLOSED

An agent's cost is measured in cycles lost to a diagnosis, and this
repository's refusals are usually excellent at naming their cause. One on the
critical path was not. On a checkout with no installed hooks and no staged
`event2/` headers, the push-proof gate refused with:

```
"status":"failed","detail":"proof_generation_dependency_unavailable"
```

and wrote no log. The gate was right to refuse — it materialises a fixed
twenty-entry dependency list into the proof generation worktree and three
entries were absent — but recovering *which* meant reading
`tools/dev/dev_proof.c` and hand-checking twenty paths.

The refusal now names the first missing path and the target that produces it
(`make vendor` for a `vendor/` entry, `make install-hooks` for the git-hook
pair). The sibling refusal above it is split out too: it fired on the same
code while nothing was missing from the checkout at all — it means the
generation's own build tree could not be created — and now says
`proof_generation_build_dir_unwritable` and names the directory. Conflating
the two sent a reader hunting a vendored archive that was present all along.

## What this is not

- Not a rewrite of the platform seams. They are audited and they refuse by
  name; that design is working.
- Not permission to weaken a refusal, an assertion, or an acceptance
  threshold to make a platform look green. A platform that cannot prove a
  claim must keep saying so.
- Not a cross-build project. One host per target is the deliberate, cheaper,
  correct answer, and `docs/WINDOWS.md` already argues why.
- Not Intel macOS. It remains unmeasured, and nothing here covers it.

## Continuation

Items 1, 5 and 6 are closed. Item 4 is the remaining Linux-side work, needs no
other hardware, and unblocks honest measurement everywhere else — take it
next. Items 2 and 3 need the Mac and the Windows box; item 2 was blocked on
item 1 and is now unblocked. Follow the integration cadence in
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md) §"Integration cadence" for each slice.
