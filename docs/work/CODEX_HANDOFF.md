# Codex development handoff — Z23

Codex is now a primary executor on this codebase. This document is the contract
it works under. It is written to be read cold, by an executor with no memory of
this repository and no access to the conversations that produced it.

Read [`AGENTS.md`](../../AGENTS.md) and [`docs/DEVELOPING.md`](../DEVELOPING.md)
first. This document does not replace them; it says how Codex specifically
should work, what it owns, and what it must never do.

## 1. Division of authority

| Role | Owns |
|---|---|
| **Codex** | Implementation. Debugging. Test writing. Refactors. Multi-file edits. Evidence gathering. |
| **Claude** | Planning, decomposition, review, gating, integration, and every push to `main`. |

Codex works on a branch and stops. It does not merge, does not push to `main`,
and does not decide that a unit is finished — it presents evidence and Claude
rules on it. This is not ceremony: four boxes and several agents share `main` as
their only coordination channel, and a single unreviewed push to it corrupts
every other box's view of the world.

**Codex never touches production.** Not the live node, not a datadir, not a
systemd unit, not the referee checkout. Ever. See §3.

## 2. What "the binary must be strong" means here

The product is one self-contained C23 binary that is a ZClassic full node,
bit-for-bit consensus-compatible with `zclassicd`, plus an optional
decentralized C23 package commons. Eight properties matter, and no track is
allowed to starve the others:

1. **Correct** — consensus, custody, and durability are absolute priority.
2. **Secure** — peer-controlled input never sizes an allocation or a loop bound.
3. **Efficient** — sync fast, stay fast, bounded memory.
4. **Well-architected** — one owner per fact. See the cloned-ledger rule in §5.
5. **Legible** — logging and telemetry that answer "is it healthy, and if not why".
6. **Usable** — a competent operator succeeds on first contact without reading source.
7. **Documented** — docs that are true, and that stay true.
8. **Agent-first** — an agent can change it, prove the change, and be caught when wrong.

## 3. Non-negotiable rules

Breaking any of these destroys work — often silently, often someone else's.
They are listed in the order that they most often bite.

**Datadir isolation.** NEVER run any `zclassic23`/`z23`/`zcl-*` command that
accepts a `datadir` input without `--datadir=/tmp/...`. In this project a
"read-only" command WRITES to the datadir — it leaves WAL sidecars behind. The
authority is `lib/test/src/test_read_leaf_no_datadir_write.c`, never a hand
count. Reproduce against a throwaway copy under `/tmp`, always.

**The live node is untouchable.** Never stop, restart, signal, or attach to it.
Never touch `~/.zclassic-c23-devfleet`, `~/.zclassic`, or any systemd unit. A
production node is running while you work. You may read its log (bound your
`tail`/`grep` — it reaches hundreds of megabytes) and you may copy files out of
its datadir to `/tmp` and inspect the copies.

**Never `git stash`.** The stash is SHARED across every worktree on the box.
Several lanes run concurrently; a stash silently eats another lane's work. Park
work-in-progress as a commit instead.

**`printf ... | grep -q PAT` is broken here.** Under `set -o pipefail` a MATCH
returns **141**, not 0, because `grep -q` exits at the first match and `printf`
takes SIGPIPE. A gate written this way reports a found violation as CLEAN.
Use the helpers in `tools/scripts/sh_str.sh`. Do not bulk-rewrite existing
occurrences elsewhere in the tree as a side quest.

**`$(file >...)` executes under `make -n`.** `$(file ...)` is a make FUNCTION,
expanded when make merely PRINTS a recipe. It has broken dry runs on cold
checkouts before.

**Gate on the PASS token, never the exit code.** A run is green only when
`ALL TESTS PASSED` is present AND `SOME TESTS FAILED` is absent. A zero exit
code alone is not a pass.

**Always `make t-fast-exact`. Never `build/bin/test_parallel_fast` directly** —
run directly it lacks `ulimit -s unlimited` and produces false SIGSEGVs. Never
treat `make build-only` as green. Never set `ZCL_TEST_CACHE=1` for a merge claim.

**`LOG_*` macros RETURN from the enclosing function.** Using one where control
must continue silently truncates the function.

**No Rust. No Python. No new external dependencies.** This project writes its
own C23. This is a standing product decision, not a preference.

**Respect the file-size ceiling gate (E1).** `file_size_ceiling_lib_drift_count.txt`
must stay at 21. Do not bump a baseline to fit a change — restructure instead.

**The push gate fails closed on unmapped files.** Any file you change must map
to a focused test group in
`app/controllers/include/controllers/agent_impact_rules.def`. If it does not,
add the mapping — do not reach for `--no-verify`.

**Committed fleet files carry onion addresses only.** Never a clearnet IP, a
hostname, a username, or a local path.

## 4. Definition of done

A unit is done when all of the following are true, and Codex says so with
evidence rather than assertion:

1. The change is on its own branch, committed. **Commit before you finish** — a
   lane in this repo has already ended with its work uncommitted in a worktree.
2. A test exists that **fails before the change and passes after**, and both
   runs are pasted. For a bug fix this is not optional: a fix without a
   reproducing test is a claim, not a result.
3. `make t-fast-exact ONLY="<groups>"` is green on the PASS-token rule, run
   cold, after the final edit.
4. `make lint-fast` is green.
5. The report states plainly what was **not** fixed, and what residual risk the
   change leaves behind.

Claude will independently re-run the gates and read the diff. Reports that
overstate are worse than useless — they burn the reviewer's trust for every
later unit. A unit that honestly reports "I narrowed it to X, here is the
evidence, I could not prove the last step" is a good unit.

## 5. Traps specific to this codebase

These are failure modes this project has actually suffered. They recur.

**Cloned ledgers.** The recurring architectural bug is the same fact stored in
two places and then reconciled. The doctrine is to fix it by **DELETING a
copy**, never by adding a reconciliation guard. A patch that adds a "keep these
two in sync" path is moving in the wrong direction.

**Consolidation that isn't.** "I collapsed four copies into one" is only true if
the ARGUMENT LISTS collapsed too. Divergence that merely moved into a parameter
is not consolidation, and will be rejected.

**Turning a truthful failure into a false pass.** This codebase deliberately
reports unclean shutdowns, deliberately refuses to serve headers that fail a
hash check, and deliberately fails a gate it cannot satisfy. When you meet a
red signal, the question is "why is this true", never "how do I make it green".
Making the reporting path lie is the most damaging change you can make here.

**Green that checks nothing.** There is a documented class of proof harnesses
that pass without testing anything. When you add a test, ask what it would take
for it to fail, and prove it can.

**Stale narratives.** Documents in this repo have confidently described states
that the code contradicts. A "permanent blocker" here once turned out to be a
stale binary. Verify a claim against the code before building on it, including
claims in this document.

**Version-suffixed names.** No `_v2`, `_v3`, no numbered directories beside an
old one. Canonicalize in place; the running artifact's identity must stay
traceable to a commit.

## 6. Shape of a work unit

Every unit Codex receives, and every unit it reports back, uses this shape:

- **Goal** — one sentence, in terms of product behaviour.
- **Why now** — what it unblocks or what it is costing today.
- **Files** — the exact set. A unit that sprawls beyond its file set should stop
  and report, not widen.
- **Non-goals** — what to deliberately leave alone.
- **Acceptance** — how a reviewer proves it without trusting the executor.
- **Gates** — the exact `t-fast-exact` group list.

Units are sized to be independently landable. If two units touch the same file,
they are sequenced, not parallelised — concurrent lanes must own disjoint files.

## 7. The work program

Tracks are ordered so that earlier ones make later ones cheaper. Within a
track, units are listed in dependency order. Priority is independent of track:
**P0 means it is harming the product right now.**

Units marked *(in review)* already have a branch and are being gated; Codex
should not start them.

---

### Track A — Correctness of what we serve  *(P0)*

**A1. Seeded-node early-header availability.** *(P0 — bounded repair landed)*

This was investigated twice and misdiagnosed both times, so the corrected
account matters more than the fix.

The visible symptom was `getheaders: refusing to serve header ...
reason=header-hash-mismatch`, in a contiguous run from height 1 and in further
runs elsewhere, each about 64 heights wide. The recurring 64 looked like a
stride or checkpoint segment in header index derivation. It is not. It is
`for (int guard = 0; guard < 64; guard++)` in
`getheaders_next_servable_successor()` (`lib/net/src/msg_headers.c`): one
`getheaders` whose locator lands in an unservable span probes 64 successors,
refuses each, and returns a zero-header reply. The window was the probe, not
the data.

The real cause is data availability. `struct block_index_flat`, the on-disk row
of `block_index.bin`, persists no `hashMerkleRoot`, no `nNonce` and no
`nSolution` — three of a header's seven fields. An entry hydrated from it can
never bind on its own, and on a snapshot-seeded box the only stores holding
full header bytes hold nothing below the seed floor. **The node was refusing
correctly.** What it did wrong was describe a header it had never assembled as
a hash mismatch, which is what sent two investigations after index corruption.

Fixed: the refusal is now named `no-header-bytes` and counted, the WARN is
throttled per reason so an availability storm cannot bury a genuine
forged-solution refusal, and the index fill no longer reads the whole block
just to discard most of it.

Fixed after that diagnosis: the first honest serve miss arms one immutable,
64-header peer repair span. The node requests only headers, independently
hash-binds and full-PoW verifies every response, and caches only proved bytes
in the bounded resident serve cache. It neither downloads block bodies nor
adds a new durable authority. A retry preserves partial progress and the exact
span. `getheaders_serve_refusals_no_header_bytes()` remains the attribution
counter for the initial local availability miss.

Also fixed: a peer that sends `sendheaders` now receives one verified current
tip header on that connection. Normal block relay still excludes the source
peer to prevent echo, but the one-shot negotiation proof lets a mesh observer
record an accepted-header vote even when it supplied node2's tip and the chain
is otherwise quiet. Duplicate `sendheaders` messages produce no extra proof.

*Deliberately not done:* the 64-probe guard was left alone. Shortening it on
the first `no-header-bytes` would break the real case of scattered bodies, and
raising it walks millions of entries per request — a denial-of-service surface.
Changing it needs its own evidence.

**A2. Foreign writers can silently corrupt an indexed block store.** *(P1)*

One box showed `read_block_pread_hash_mismatch` where the returned digest was
not block-hash shaped. It did not reproduce on an independently synced box.
Cause: its `blocks/blk*.dat` files were **hardlinked to another node's data
directory**, and that other node was running and appending to them. The
positions in the index still pointed at what were now different bytes. The
repo's own tripwire had already fired hundreds of times —
`blk000NN.dat has N hard links — shared blk file; foreign appends can
invalidate indexed positions` — and nothing acted on it.

Two units here. Operationally: never share block files between data
directories; replace such hardlinks with real copies before repairing
positions, or the repair is immediately undone. In the product: a warning that
fires hundreds of times and changes nothing is not a safeguard. Sharing should
be detected at open and refused or quarantined, not narrated.

Also landed alongside: `disk_block_locate_payload` now refuses a position with
no block frame instead of reading a large raw window and parsing whatever it
finds.

**A3. Consensus parity holes.** *(P1, large)*
Several known gaps (nullifier backfill, Sapling-root parity, a non-canonical
BLS12-381 infinity encoding that is currently accepted) are replay-gated:
changing them alters historical validation. Each needs a full-chain replay
before it can move. Treat as one unit each, and never "fix" one without the
replay evidence — an unreplayed correctness change here is a consensus fork.

### Track B — Durability and lifecycle  *(P0)*

**B1. Bounded shutdown drain.** *(P0, medium — in review)*
An unbounded wait in the diagnostics drain let a shutdown stage block until the
watchdog forced an unclean exit before durability ran, which cost the next boot
a multi-minute integrity check and a very large memory peak. Root-caused and
fixed on a branch.

**B2. Name the dumper that blocks.** *(P1, small)*
B1 makes the hang survivable, not absent. Add per-dumper timing to the bundle
walk so the next occurrence identifies the culprit from its own output rather
than requiring a stack from a live process.

**B3. Make unclean boot cheap.** *(P1, medium)*
Even with B1, an unclean exit remains possible. The recovery path should be
proportional: bounded memory, incremental verification, and a progress signal.
An operator should never face a silent multi-minute stall with no output.

---

### Track C — Telemetry and logging  *(P1, do early — it pays for itself)*

Everything else on this list gets easier once the node can explain itself.

**C1. Log level discipline and hot-path rate limiting.** *(P1, medium)*
The live log reaches hundreds of megabytes, dominated by a handful of call
sites emitting at ERROR for conditions that are expected and recurring. Two
changes: correct the levels (an expected, handled condition is not an ERROR),
and add rate-limiting/deduplication so a repeating condition logs once with a
count rather than thousands of times.
*Acceptance:* a defined workload produces a bounded log; each distinct
condition still appears at least once; no condition becomes invisible.
*Non-goal:* do not silence anything. Suppression that loses the last
occurrence of a real fault is worse than the volume.

**C2. A failing batch must back off and latch.** *(P1, small)*
A backfill service retried the same impossible unit of work every few seconds
for over half a day without ever succeeding. Any repeating job that fails
identically must back off and eventually latch into a named, reportable
blocker, using the existing typed-blocker convention rather than a new one.
*Acceptance:* a job wired to fail always reaches its named blocker state within
a bounded number of attempts and stops hot-looping — proven by test.

**C3. One health verdict.** *(P1, medium)*
An operator should be able to ask one question and get one answer: is this node
healthy, and if not, what is the single most important reason. The condition
engine and typed blockers already exist; the gap is a single authoritative
verdict rather than a log to be read by eye.

---

### Track D — Peer connectivity  *(P1)*

**D1. Judge peers on current height, not handshake height.** *(P1, medium — in review)*
The fleet acceptance gate compared a peer's `startingheight` — a value fixed at
handshake — against our advancing tip, so a healthy peer could never pass. Same
class as an earlier bug in the same file that required a peer state a syncing
peer never reaches.
*Standing lesson for Codex:* when a gate never passes, suspect the gate.

**D2. Identity stability is a fleet property.** *(done)*
The node's default onion identity is ephemeral — a new address every boot —
while the mesh addresses peers by committed address. `-onion-persist` is now
set in the supervised unit itself. Retained here because the diagnostic rule
generalises: **before believing a peer-transport verdict, check whether that
peer's published address changed.**

**D3. Connect easily, fast, and strongly.** *(P2, large)*
The stated product goal. Concretely: reduce time-to-first-useful-peer, make
dial failures name their cause, hole-punching and reachability for boxes behind
NAT, and a peer-selection policy that prefers peers that actually serve. This
track only becomes meaningful once A1 is fixed — until then a new peer cannot
finish syncing regardless of how well it connects.

---

### Track E — Efficiency  *(P1)*

**E1. The tip-finalize rate bug.** *(P1, large)*
One stage dominates the fold round and chronically exceeds its step budget,
flapping in and out of a degraded condition. This is a long-standing known
bottleneck. Measure before changing; the repo has a documented history of
"accelerated" paths that were slower than plain C.

**E2. RPC front door exhaustion.** *(P1, medium)*
The front door has been observed reaching a large number of CLOSE_WAIT sockets
while worker slots sat idle — connections accepted, never reaped. Fix the
ownership/close path, and add a test that exercises client disconnects at
various points in the request lifecycle.

**E3. Bounded memory.** *(P2, medium)*
Peak memory currently forces an oversized supervision envelope. Reducing the
peak lets the envelope shrink, which is what makes co-tenancy on a box safe.

---

### Track F — Operator experience  *(P2)*

**F1. First contact.** *(P2, medium)*
Walk the real journey — install, first boot, first sync — and fix the specific
moments where a competent operator would be confused or stuck. Judge it as
someone meeting the software for the first time, not as someone who wrote it.

**F2. Failure messages that name the action.** *(P2, medium)*
For each common failure (no peers, disk full, corrupt datadir, port in use,
wrong permissions) the message should say what happened, why, and what to do.
Grep for the current text before assuming it is bad — some of it is good.

**F3. Command surface consistency.** *(P2, medium)*
Naming, flag ergonomics, discoverability, and `--help` quality across the
command registry.

---

### Track G — Documentation  *(P2)*

**G1. Delete what is false.** *(P2, small)*
At least one work document confidently describes a transport failure that the
live evidence contradicts. Find the documents making claims the code
contradicts and correct or delete them. A confidently wrong document is worse
than a missing one — it has already misdirected work here.

**G2. Keep public docs generic.** *(P2, small)*
`docs/` is read by people with one checkout and no lanes. No live counts, no
host state, no per-box paths in prose. Maintainer-only pages must be labelled.

---

### Track H — Agent-first tooling  *(P1, do early)*

Every hour spent here is repaid by every later unit, and by every other agent
working on the other boxes.

**H1. Nothing unmapped, nothing unproven.** *(P1, small)*
The push gate fails closed on files with no impact rule — good. Audit the
mapping for files that are mapped to a group that does not actually exercise
them, which is a hollow pass rather than a missing one.

**H2. Keep the gates fast.** *(P1, medium)*
Focused-group selection and caching are what make an agent able to iterate.
Protect that: measure gate wall time, and treat a regression in it as a defect.

**H3. Machine-readable truth.** *(P1, medium)*
Prefer typed, structured status output over prose an agent has to parse. Where
an agent currently greps a log to learn something, expose it as a field.

---

## 8. Suggested order of attack

1. **A1** — nothing else in the product matters as much as being able to serve a
   chain from the beginning.
2. **C2, C1** — cheap, and they stop the log from hiding the next bug.
3. **B2, B3** — close out the durability work while it is fresh.
4. **H1, H3** — make the next twenty units cheaper.
5. **E2, E1** — the two measured bottlenecks.
6. **D3, F1** — the product-quality goals, once the foundation holds.
7. **A3** — the replay-gated consensus work, deliberately, one at a time.

## 9. Known-red on arrival

One `make lint` gate fails on `main` today, independently of any work in this
document. It is recorded here so nobody spends an afternoon rediscovering it,
and so nobody "fixes" a gate by weakening it:

- **`check-proc-self-shim`** — flagged in `lib/test/src/test_peer_disconnect_log.c`.

`lint-fast` (the 20-gate subset) is green. If you meet a red gate not on this
list, it is probably yours.

Verify this section rather than trusting it — it dates from when the document
was written, and the whole point of §5 is that stale claims here mislead.

## 10. Reporting

For each unit, report:

- what changed, as a diff;
- the failing-before / passing-after test output, both pasted;
- the exact gate command and its PASS-token lines;
- the branch and commit;
- **what you did not fix, and what risk remains.**

The last line is the one that matters most. An executor that reliably reports
its own limits can be trusted with larger units. One that reports only successes
cannot be trusted with any.
