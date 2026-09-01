# AI safety gates

Most of this repository is developed by AI agents. That is not a footnote about
tooling — it is the threat model.

## Claim scope: evidence says exactly one thing

Z23 follows **VERIFY, DON'T TRUST**. Evidence must be described at the
same scope as the observation it records:

- A hash verifies byte identity.
- A signature verifies that a key made a statement.
- A build receipt verifies the declared build observation under its bound
  inputs.
- A test receipt verifies the declared test observation under its bound
  inputs.
- A reproduction receipt verifies that another signer reported the same
  declared result under bound inputs.
- None of these alone proves general correctness, security, safety, usefulness,
  or suitability for acceptance.

Workers and coding agents are untrusted producers of independently verifiable
evidence. Each receiving node verifies the exact objects and applies its own
local policy. Fetching source does not authorize building or testing, and those
actions do not authorize installation, linking, execution, wallet access,
consensus changes, canonical-datadir mutation, or deployment.

`check-doc-claims` also scans the durable entry documents for narrow positive-
reliance phrases such as the forbidden examples below. The examples are kept
inside a fence so the gate can distinguish documentation of the rule from
product language:

```text
trustworthy package
trusted worker
trusted build
trust us
proven safe
guaranteed secure
proof that this code is safe
```

The check intentionally permits phrases such as `untrusted input`, `trust
boundary`, precise cryptographic terminology, and the North Star phrase
`VERIFY, DON'T TRUST`.

An AI agent is very good at producing a confident, well-written, plausible
sentence about work it did not finish. It does not do this maliciously; it does
it because "the wedge is cleared" is a natural continuation of a transcript in
which it tried to clear a wedge. A human reviewer reading that sentence has no
cheap way to tell it from a true one. Over enough iterations the documentation
describes a node that does not exist, and the next agent reads that
documentation as ground truth and builds on it.

This project has run that experiment involuntarily and has the receipts. So the
countermeasure here is not "review more carefully" or a style guide asking for
humility. It is a set of lint gates that make specific categories of unprovable
claim **fail the build**. An agent cannot talk its way past `exit 1`.

Every gate below is a standalone script, runs in `make lint` (and therefore
`make ci` and the pre-push hook), and needs no build, no node, and no network —
filesystem and `grep`. Each section names the actual failure it was written for.

---

## `check-no-uncited-victory` — a win must come with a receipt

**Script:** `tools/scripts/check_no_uncited_victory.sh`

**The failure it was written for.** Quoting the script's own header: *"this repo
shipped 9+ 'cured / at tip / fully synced' claims in six weeks, every one later
false, and the owner counted ~103 'wedge FIXED' -> re-wedge cycles."* Each of
those claims was written in good faith at the end of a long session that had
genuinely made progress. None survived contact with the node the next morning.
The claim outlived the state it described, and the next session started from
the claim.

**What it does.** It scans exactly one file: `docs/HANDOFF.md`, the single page
in the tree permitted to carry live node state. It splits that file into
blank-line-delimited paragraphs. Any paragraph containing a **victory phrase**
— matched case-insensitively and word-bounded, so "secured" never trips "cured"
— fails unless the *same paragraph* also carries a **citation token**.

The victory phrases are the ones this project actually got wrong: `at tip`,
`at-tip`, `reaches tip`, `holds tip`, `fully synced`, `cured`, `unwedged`,
`wedge cleared`, `wedge closed`, `wedge fixed`, `soak window open`,
`soak window running`, `proven live`, `live-proven`, `stable at tip`.

A citation token is machine-checkable evidence of a real, dated, ledgered
proof: `uptime-ledger`, `slo-summary:`, `VERDICT=PASS`, `WALL_CLOCK_SECONDS`,
`gap_vs_oracle`, or a `ts=<digits>` timestamp. There is a last-resort per-
paragraph override, `<!-- victory-ok: <reason> -->`, intended for narrating a
*historical* event — never a current-state claim.

**Why it cannot be satisfied by writing better prose.** The gate does not
evaluate whether the claim is *true*. It cannot. It enforces something an agent
can't fake with fluency: the claim and its evidence must be adjacent in the
same paragraph. To pass, you have to go get a ledger line — which means the
proof job has to have actually run.

**The hollow-gate rule.** If `docs/HANDOFF.md` is missing, or is shorter than
ten lines, the gate **fails** rather than reporting clean. A gate that quietly
passes on an empty scan set is worse than no gate, because it produces a green
check for nothing. The script also ships a hermetic `--selftest` that proves
both directions before you trust it: a clean doc passes, an uncited victory
trips, a cited victory passes, the override passes, and a stubbed-out or
missing doc fails.

---

## `check-honest-witness` — a remedy that reports success must observe the symptom moving

**Script:** `tools/lint/check_honest_witness.sh`

**The failure it was written for.** A self-healing Condition in this codebase is
a triple: *detect*, *remedy*, *witness*. The witness is the post-condition that
decides whether the remedy actually worked. The architecture's Law 7 states the
hard rule: **a remedy that returns ok without moving the symptom is a lie.**

Three real conditions broke it — `stale_validate_headers_repair`,
`peer_floor_violated`, and `sync_state_stuck`. Their witnesses checked that the
poison the remedy had just deleted was gone, or re-read a state-machine field
the remedy itself had force-set. Both are tautologies. The result: every tick,
the healer detected a problem, "fixed" it, confirmed its own fix, and logged
success — while the chain tip did not move at all. A self-healing system that
reports continuous successful healing is *indistinguishable from a working one*
in the logs. That is the worst possible failure mode, and it is exactly what an
AI agent writing a plausible witness function will produce by default.

**What it does.** For every `static bool witness_<name>(...)` in
`engine/conditions/src/*.c`, the gate extracts the function body and fails it if
**any** of three properties hold:

1. **TRIVIAL** — every return is a bare `return true;` / `return false;`. A
   constant post-condition observes nothing.
2. **PURE-INVERSE** — the body is essentially `return !detect_<x>();`. "The
   poison I named is gone" is a restatement of the remedy, not forward progress.
3. **NO-OBSERVABLE** — the body references none of an allowlist of
   observable-progress tokens: real height/cursor advance, the reducer
   frontier, block-map iteration, a durable `SELECT`, or a bounded external
   read such as a peer height.

The allowlist has a deliberate set of exclusions, and they are the point:
state-machine reads (`sync_get_state()`) and poison-flag reads do **not**
count as observing progress. They are precisely what the three broken witnesses
were doing.

The exemplar of an honest witness is `engine/conditions/src/block_failed_mask_at_tip.c`:
`current_tip_height(ms) > g_tip_at_detect` — the tip moved. That is a fact about
the world, not about the healer.

**Enforcement level.** Run bare, the script defaults to WARN. `make lint`
invokes it as `ZCL_LINT_MODE=FAIL`, which fails on any violation and ignores the
grandfather baseline entirely. A documented, reviewed exception is possible per
witness via a `// honest-witness-ok:<reason>` comment inside the body — visible
in the diff, with a reason attached.

---

## `check-no-stale-pinned-facts` — don't hand-write a number that has a live source

**Script:** `tools/lint/check_no_stale_pinned_facts.sh`

**The failure it was written for.** The owner's directive, quoted in the script:
*"don't ever rely on stale documents — build tools that make staleness
impossible."* The triggering case was a hand-written size-in-megabytes claim
about the compiled artifact that stayed in the docs long after the real
artifact had grown well past it. Nobody lied; the number simply had no reason
to change when the thing it described did.

This is the same disease as an uncited victory, one level down. A pinned number
is a claim with an expiry date and no expiry mechanism. Correcting it buys you
one release cycle; **removing** it fixes it permanently.

**What it does.** It scans `CLAUDE.md`, `README.md`, and every tracked
`docs/**/*.md`, minus the two sanctioned exceptions — `docs/HANDOFF.md` (the
one live-state page, which is *supposed* to carry current numbers, and is
policed instead by `check-no-uncited-victory`) and `docs/work/archive/**`
(frozen historical narratives, where pinning a past value is the whole point).

Two classes:

- **Artifact-size claims — HARD, never grandfathered.** A size figure
  qualifying the compiled binary is always a violation, because that value has
  a live source: `tools/scripts/binary_size.sh`. The fix is to write
  size-agnostic prose or quote the derived value. This is the owner's named
  case and carries no exemption path.
- **Live-state height pins — RATCHET.** A line that asserts the node's current
  chain position (a trigger like `H*=`, `wedged at`, `stuck at`, `currently
  held`, `live tip`, next to a height-shaped number) is a violation anywhere
  except the live-state page. New ones fail; a pre-existing corpus is
  grandfathered in a **shrink-only** baseline file. The baseline is a debt
  ledger, not a permission slip.

A per-line `<!-- stale-ok: <reason> -->` marker (non-empty reason required)
exempts a line that legitimately records a constant or a dated measurement — a
benchmark log row, an immutable positioning statement in an ADR.

**A gap that was closed, and the rule it left behind.** The sibling gate
`tools/scripts/check_doc_counts.sh`, which machine-checks code-derived counts
(test groups, ports, adapters, condition registrations) against a canonical
`DOC-COUNTS` block in [`CODEBASE_MAP.md`](./CODEBASE_MAP.md), once scanned
`CLAUDE.md` and `docs/**` but **not** `README.md`. The single most-read file in
the repository was the one file exempt from that gate — which is why several
counts in it rotted undetected. Its scan set is now every tracked `*.md` via
`git ls-files`, so `README.md` is covered. The durable repair applied to
`README.md` was still not to correct the numbers but to delete them and point at
the derived source instead; prose with no number in it cannot go stale, and that
remains the rule for the entry documents regardless of gate coverage.

---

## `check-test-registration` — a test that never runs is worse than no test

**Script:** `tools/scripts/check_test_registration.sh`

**The failure it was written for.** From the script's header: on 2026-06-22,
three test entry points — `test_refold_from_anchor_fatal`,
`test_refold_auto_arm`, and `test_anchor_selfmint` — lived in dedicated
`tests/harness/src/test_<name>.c` files and were **compiled and linked into the test
binaries**, yet appeared in neither the canonical test group catalog of the parallel
runner nor the legacy serial runner's dispatch. They had been written,
reviewed, and merged. *"They therefore proved NOTHING — green forever, never
executed."*

This is the specific way an AI agent's test-writing goes wrong. Writing the test
file is the part that looks like the work; wiring it into a runner is a
one-line registration in a different file, and it is exactly the kind of step
that gets dropped. The failure is silent and permanent, and it makes the suite
*more* dangerous than if the test were absent — a missing test is a known gap,
an unregistered test is a false assurance.

**What it does.** It enumerates every filename-matching entry point (a
`tests/harness/src/test_<name>.c` defining `int test_<name>(void)`) and requires each
to be dispatched by at least one runner — registered as
`ZCL_TEST_GROUP(<name>)` in `tools/dev/test_group_catalog.def`, or called as
`test_<name>()` from `test.c`. Anything
dispatched by neither is an orphan and fails. Helper and sub-test functions
whose names don't match their host filename are deliberately not entry points,
so multi-test files produce no false positives.

It also rejects **duplicate** catalog registrations, because a duplicate row runs
the same group twice and inflates the advertised group count — hiding the
absence of a genuinely distinct test behind a healthy-looking total.

**It refuses to trust itself.** Two properties worth copying into any gate you
write:

- The duplicate detector runs a **positive and a negative control** on every
  invocation — clean input must pass, known-duplicate input must be rejected
  with the offending name — before it is allowed to judge the real registry. A
  detector that has silently stopped detecting is the failure mode a decorative
  check dies of.
- There is a **fail-loud floor**: if parsing the catalog yields fewer than 100
  entries, the gate exits `2` (fatal) rather than reporting clean, on the
  grounds that the macro shape must have drifted and a real orphan could slip
  through a near-empty scan. Likewise a missing runner file, or a `grep` that
  errors, aborts. **The gate never reports "clean" off a broken scan.**

---

## Copy-prove: the destructive parameter does not exist

**Script:** `tools/repro_on_copy.sh` (`make repro-on-copy`)

This one is not a lint gate, and it is the most important design in this
document, because it demonstrates the pattern the gates only approximate.

**The rule** is that a recovery or consensus-critical fix is proven on a
throwaway copy of the datadir before it is allowed anywhere near the live node.
**The failures it was written for** are two real catastrophes preserved in the
script's header: a reducer fix that collapsed the public chain tip from over
three million down to 47,279, and an import path that reset a node to a height
of roughly 199.

The obvious way to implement the rule is a policy — "always pass `--copy`",
"never point this at the live datadir" — enforced by a warning, a confirmation
prompt, or a code review. Every one of those is a request that an agent under
pressure can rationalize past, and a prompt is something an agent will answer
"yes" to.

**So the harness has no destructive setting to choose.** The destination is
computed, never supplied: a fresh `$HOME/.zclassic-c23-COPY-<timestamp>-<slug>`
path that must not already exist and must not sit inside the source. The script
says so in a comment where a reader would look for the option — *"no
caller-controlled dest"*. There is no `--dest`, no `--in-place`, no
`--i-know-what-im-doing`. The caller can choose the source, the ports, the peer,
how much to copy, and how long to watch. It cannot choose to run against the
live datadir, because the parameter that would express that intent was never
written. Isolation is likewise structural rather than advisory: an isolated
`HOME`, isolated RPC/P2P/file-service/HTTPS ports, and a connection forced to a
dead sink unless a peer is explicitly named.

**And it refuses to be a rubber stamp.** The harness is a tip-regression
detector — it boots the copy, watches the public tip, and **fails loudly if the
tip ever drops**, which is precisely how the two catastrophes above are now
caught on scrap disk instead of production. With `--expect-climb-past=H` it
becomes a progress gate: a run that boots successfully and then sits flat is a
FAIL, not a pass. "It started without crashing" is not evidence that a recovery
path recovers anything, and the harness will not accept it as such.

---

## The shared principle

Read together, these five say one thing:

> **A claim that cannot be checked by a machine is not accepted, no matter how
> confident the author.**

Each gate takes a category of statement an AI agent will produce fluently and
sincerely — *it's fixed*, *the healer is working*, *this test covers it*,
*here's the number*, *I verified it safely* — and requires an artifact the
agent cannot generate by writing well: an evidence token in the same paragraph,
a read of a value the remedy doesn't control, a registration row in a runner, a
derived source instead of a literal, an unforgeable tip climb on a copy.

Two design habits are worth stealing if you are adding a gate of your own:

- **Fail on an empty or broken scan set.** Every gate here refuses to print
  "clean" when it cannot see what it is supposed to be checking. A green check
  produced by a gate that scanned nothing is a lie the gate tells on your
  behalf.
- **Prefer deleting the affordance to warning about it.** A gate stops a bad
  claim after it is written. A missing parameter stops the intent from being
  expressible. The second is stronger, and where the shape of the problem
  allows it, it is the one to reach for.

Related: [`DEFENSIVE_CODING.md`](./DEFENSIVE_CODING.md) (the full gate list and
the coding rules they enforce), [`FRAMEWORK.md`](./FRAMEWORK.md) (Law 7 and the
detect/remedy/witness contract), [`TENACITY.md`](./TENACITY.md) (the copy-prove
recovery doctrine), and [`work/fast-path.md`](./work/fast-path.md) (the
diagnosis algorithm the copy-prove harness sits inside).
