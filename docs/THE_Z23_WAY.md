<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# The Z23 way

One standard for Claude, Codex and humans. If this page and a deep document
disagree, the deep document wins and this page is the bug. Authority rules stay
in [AGENTS.md](../AGENTS.md).

<!-- claim: symbol-present dev.lane.new engine/composition/commands/dev.def # lane creation leaf -->
<!-- claim: symbol-present dev.land.submit engine/composition/commands/dev.def # queue a signed tip -->
<!-- claim: symbol-present dev.land.status engine/composition/commands/dev.def # read the queue -->
<!-- claim: symbol-present agent-verify Makefile # one-trip verify target -->
<!-- claim: symbol-present lint-fast Makefile # fast lint subset -->
<!-- claim: symbol-present install-hooks Makefile # native git hooks -->
<!-- claim: symbol-present custody-check Makefile # wallet custody gate -->
<!-- claim: symbol-present check-architecture-tree Makefile # placement gate -->
<!-- claim: file-present core/UNSEAL.md # unseal ritual -->
<!-- claim: file-present docs/agent/AGENT_TRAPS.md # intentional-behavior list -->
<!-- claim: file-present docs/dev/CODEBASE_MAP.md # ownership map -->

## What Z23 is

Z23 is a public ZClassic full node in one self-contained C23 binary: it
validates the chain bit-for-bit like `zclassicd`, joins P2P, holds wallet state
and can serve over embedded Tor. Its optional Commons publishes, fetches,
builds and reproduces content-addressed packages with no central registry.
North Star: software made for you, not imposed on you, with exact source
identity and independent reproduction.

## The loop

1. **Get a lane.** On a maintainer host run `devworker prepare z23 NAME <sha>`,
   which runs `build/bin/z23-dev dev lane new` and gives you a private
   worktree at the exact base. Volunteers use a plain clone and follow
   [CONTRIBUTING.md](../.github/CONTRIBUTING.md). Never edit another
   worker's checkout. Run heavy builds through `devbuild --wait` where a host
   has it; elsewhere run `make` directly. Build first with `make dev-bin`.
2. **Brief.** `build/bin/z23 code guide <paths>` returns the nearest
   `AGENTS.md` rules, test groups, wiki lessons and first commands. Then
   `code map`, `code owner <path>` and `code impact <path>`; search with
   `git grep`. Check [AGENT_TRAPS.md](agent/AGENT_TRAPS.md) before repairing
   something that may be intentional.
3. **Edit** the smallest owned surface. Reuse existing C23 first; no Python;
   never weaken an assertion or threshold. Write the test first and watch it
   fail for the intended reason, then fix it.
4. **Verify** with `make agent-verify ONLY=<exact groups>` (find a file's group
   with `build/bin/z23 code tests <path>`). `ONLY=` is mandatory and exact. Add
   `make lint-fast` for a quick check and `make check-architecture-tree` after
   moving files. A cached or zero-test run is not a pass.
5. **Review.** One reviewer who is not the author, of any model, reads the
   exact commit. Commits are signed; an AI-written commit ends with a
   `Co-Authored-By:` trailer naming the model.
6. **Land.** `build/bin/z23-dev dev land submit --worktree=$PWD`, then
   `build/bin/z23-dev dev land status`. The land queue proves the tip (full
   lint once, every affected group) and publishes it. Nobody pushes `main` by
   hand; `make install-hooks` installs the native hook that guards it. A
   refusal names its reason: fix the cause, do not route around it.

A push is a checkpoint, not completion: fetch `origin/main`, integrate,
continue. Fleet work coordinates through native tasks, claims and receipts,
never GitHub issues. Volunteers use `card:` pull requests.

## Boundaries

Source access, builds and isolated tests never permit:

- **Consensus and `core/`.** No predicate changes; `core/` is sealed
  (`core/MANIFEST.sha3`) and changes only through [core/UNSEAL.md](../core/UNSEAL.md).
- **Custody.** No spending funds, exporting keys or weakening custody; run
  `make custody-check` for wallet work.
- **Canonical datadirs.** No delete, reindex or hand edit of a live datadir.
- **Spends and unreviewed production.** No deploy or promotion of a build that
  is not reviewed and landed; one host at a time, never two deploys at once.
- **Secrets.** No keys, grants or tokens in logs, argv, commits or messages.

Stop and escalate only for these, a destructive production action or an
assertion that would need weakening. Decide everything else, record it and
continue. Verify, do not trust: a hash identifies bytes, a signature identifies
a key, a receipt binds an observation; none alone proves correctness. P0 is
always consensus, custody and public-node health.

## Where deep detail lives

Open one section, never the whole file.

| Need | Read |
| --- | --- |
| Fresh machine | [DEVELOPING.md section 0](dev/DEVELOPING.md#0-first-hour-on-a-clean-machine) |
| Order of work | [The normal loop](dev/DEVELOPING.md#the-normal-loop) |
| Find code | [1. Orient](dev/DEVELOPING.md#1-orient), [2. Inspect](dev/DEVELOPING.md#2-inspect-exact-context) |
| Edit and ownership | [3. Edit](dev/DEVELOPING.md#3-edit-within-ownership-boundaries) |
| Feedback and proof | [4. Feedback](dev/DEVELOPING.md#4-receive-fast-local-feedback), [5. Proof](dev/DEVELOPING.md#5-build-and-focused-proof) |
| Landing | [6. Integrate](dev/DEVELOPING.md#6-integrate-and-push-a-coherent-slice) |
| Hosts and build scheduler | [Maintainer hosts](dev/DEVELOPING.md#maintainer-hosts) |
| Exact incantations | [COOKBOOK.md](dev/COOKBOOK.md) |
| Who owns what | [CODEBASE_MAP.md](dev/CODEBASE_MAP.md) |
| Intentional behavior | [AGENT_TRAPS.md](agent/AGENT_TRAPS.md) |
| Current work order | [FORWARD_PLAN.md](work/FORWARD_PLAN.md#current-mission) |
| Joining a fleet, mail, wiki, gateway | [FLEET_GUIDE.md](agent/FLEET_GUIDE.md) |
| Defensive coding and claim markers | [DEFENSIVE_CODING.md](DEFENSIVE_CODING.md) |
| Consensus or custody work | [SECURITY_AND_INTEGRITY.md](node/SECURITY_AND_INTEGRITY.md), [CONSENSUS_PARITY_DOCTRINE.md](CONSENSUS_PARITY_DOCTRINE.md) |
