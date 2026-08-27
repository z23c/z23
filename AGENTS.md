<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 agent entry point

This is the model-neutral operating contract for coding agents. Read it before
changing the repository. Detailed procedure belongs in
[`docs/DEVELOPING.md`](./docs/DEVELOPING.md); current priorities belong in
[`docs/work/FORWARD_PLAN.md`](./docs/work/FORWARD_PLAN.md); current state of the
maintainer's hosted node belongs only in
[`docs/HANDOFF.md`](./docs/HANDOFF.md).

The disposition this repository expects from an agent — act when the rails
hold, and build the missing rail rather than remembering to avoid it — is
[`docs/CODE_FEARLESSLY.md`](./docs/CODE_FEARLESSLY.md).

## North Star

Z23 exists to make useful software abundant without taking control away from
the user. **Software made for you, not imposed on you.**

A person should be able to describe what they want a device to do. AI workers
reuse existing C23 parts first, create only what is missing, build the result
quickly, show its real behavior, reproduce the exact result on another
machine, and let the user accept and use that exact version.

AI workers are replaceable. Z23 is the durable layer: exact source identity,
reusable packages, dependency graphs, bounded builds, independent
reproduction, local policy, distribution, release history, and preservation.
The result must remain usable even when the original agent, vendor, registry,
or company disappears.

The work is one journey:

> Describe desired behavior → reuse existing C23 first → create only missing
> code → build fast → show the real consequence → reproduce it on another
> node → accept the exact version → use it in a real application.

The user should feel: "I can make my device work exactly the way I want."
Keep complexity hidden but inspectable. Give the user one obvious next
action.

## Product

Z23 is a public ZClassic blockchain full node first. One self-contained
C23 binary validates the ZClassic chain, participates in its P2P network, holds
transparent and shielded wallet state, and can expose its services through an
embedded Tor onion service. It must remain bit-for-bit consensus-compatible
with `zclassicd`.

The node also provides an optional decentralized C23 software commons. Ordinary
full nodes can publish, discover, fetch, verify, build, independently reproduce,
and serve exact C23 packages without GitHub or a central package registry.

## Operating rules

**VERIFY, DON'T TRUST.** Any agent may propose code. Any node may perform
computation. No result is accepted because of who produced it. Each receiving
node independently verifies exact objects, signatures, roots, and evidence
under its own local policy.

Evidence establishes only its exact stated claim. A hash identifies bytes; a
signature identifies the key that made a statement; a receipt records a bound
observation. None of these alone proves that arbitrary code is safe, correct,
secure, useful, or worthy of acceptance.

Downloaded C is inert by default. Fetching and storing are separate from
building and testing. Building and testing are separate from installing,
linking, executing, or deploying. None grants wallet, consensus,
canonical-datadir, or deployment authority.

Every change should improve at least one of these: reuse useful C23 code;
shorten the path from intent to working software; make the result smaller,
faster, safer, or easier to customize; remove duplication or central
dependency; improve exact reproduction and long-term preservation. Prefer
deletion, reuse, and composition over new abstractions. Keep the blockchain
small and sovereign. Keep the large software corpus off-chain and
content-addressed. Do not force ZCL as the only payment method. Do not turn
Z23 into a company, another AI harness, or a speculative token product.

The near-term proof is one person creating or improving a real C23
application from reusable parts, seeing the consequence, reproducing it
elsewhere, accepting the exact version, and using it.

AI workers are replaceable proposal engines. The fast
development reactor is factory equipment, not the public product; expand it
only when that directly advances public-node or C23 Commons acceptance.

## Durable priority order

1. **P0 — consensus, wallet/custody, and public-node correctness.** Consensus
   parity is inviolable. Private keys and production state remain
   operator-controlled.
2. **P1 — public-node V1 acceptance and reliability.** The acceptance contract
   is [`docs/MVP.md`](./docs/MVP.md).
3. **P2 — decentralized C23 Commons product acceptance.** Packages and
   evidence remain content-addressed, independently verifiable, bounded, and
   locally accepted.
4. **P3 — developer and orchestration machinery**, only when it unblocks P1 or
   P2.
5. **P4 — simulation-only economics, marketplace expansion, and speculative
   features.** There is no live ZC23 token economics today.

The blockchain wins resource and authority contention. Package activity may
never delay or acquire authority over consensus, block processing, transaction
relay, synchronization, peer health, wallet custody, or deployment.

## First session

The following sequence was re-run from this checkout on 2026-08-12. Derive
catalogs from the binary instead of copying counts into prose.

1. Inspect the checkout and upstream before changing anything:

   ```bash
   pwd
   git status --short --branch
   git fetch origin main
   git rev-parse HEAD origin/main
   ```

2. On a fresh clone, arm dependencies and local hooks:

   ```bash
   make setup
   ```

   It ends with `Next: make doctor`; that is an optional environment check.

3. Build the public binary:

   ```bash
   make -j"$(getconf _NPROCESSORS_ONLN)"
   ```

4. Ask the built binary for the current command tree and source map:

   ```bash
   build/bin/z23 code guide
   build/bin/z23 discover help
   build/bin/z23 code map
   ```

   Descend with `discover help <path>`, search with the positional
   `discover search <query>`, and inspect exact input keys with
   `discover schema <leaf>`. The generated full catalog is
   [`docs/API_REFERENCE.md`](./docs/API_REFERENCE.md).

5. List or run registered test groups through the canonical runner:

   ```bash
   make t-list
   make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<substring>
   make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel TEST_PARALLEL_ARGS=--no-cache
   ```

   `ONLY=` is mandatory for `t-fast`. Do not invoke `test_zcl` directly.

<!-- claim: symbol-present t-fast Makefile # focused registered-test target -->
<!-- claim: symbol-present test-parallel Makefile # full registered-test target -->
<!-- claim: symbol-present discover.schema config/commands/root.def # live schema leaf -->
<!-- claim: symbol-present code.map config/commands/code.def # live source-map leaf -->
<!-- claim: file-present docs/API_REFERENCE.md # generated command catalog -->

## Verified platform baseline

The public node has native Linux and macOS build paths. macOS does not use a
Linux virtual machine. On 2026-08-26, `make z23` completed on an arm64
`Mac16,10` running macOS 26.0.1 with Apple Clang 17.0.0. The resulting Mach-O
executable passed its dependency audit with Apple system libraries and
frameworks as its only dynamic dependencies. The registered crypto group
passed 3/3 groups, including secp256k1, Ed25519, Equihash, BLS12-381, and hash
coverage. Native RNG, thread QoS, binary A/B promotion, sandbox capability,
backtrace capability, process introspection, and the 46-case SQLite group also
passed their platform contracts. A fresh isolated test-lane datadir reached
`phase=serving`, `stage=ready`, height 0 with RPC bound, then completed a
graceful shutdown. This is startup evidence, not chain-sync acceptance.

The macOS capability boundary is explicit: the public node, wallet, P2P, RPC,
database, and cryptography build natively; embedded full Tor, Linux Landlock
and seccomp confinement, signal-context self-backtraces, the inotify developer
watcher, and `O_TMPFILE` consensus snapshot export are currently unavailable.
Those paths refuse or report unavailable instead of claiming Linux guarantees.
Only arm64 macOS is measured; Intel macOS remains unverified. Build and test
instructions are in [`docs/GETTING_STARTED.md`](./docs/GETTING_STARTED.md).

## Orient before editing

Read, in order:

- [`docs/work/FORWARD_PLAN.md`](./docs/work/FORWARD_PLAN.md) for the current
  ordered mission.
- [`docs/DEVELOPING.md`](./docs/DEVELOPING.md) for the normal development loop,
  integration gates, and exact build profiles.
- [`docs/CODEBASE_MAP.md`](./docs/CODEBASE_MAP.md) for source ownership and
  navigation.
- [`docs/AGENT_TRAPS.md`](./docs/AGENT_TRAPS.md) before repairing something
  that may be intentional or already complete.
- [`docs/SECURITY_AND_INTEGRITY.md`](./docs/SECURITY_AND_INTEGRITY.md) and
  [`docs/CONSENSUS_PARITY_DOCTRINE.md`](./docs/CONSENSUS_PARITY_DOCTRINE.md)
  when work approaches a security, custody, or consensus boundary.

On the maintainer host only, read [`docs/HANDOFF.md`](./docs/HANDOFF.md), then
verify it against the running node:

```bash
build/bin/z23 status
build/bin/z23 dumpstate reducer_frontier
```

A document can be stale; the node cannot. Do not copy live height, soak, or
deployment state into durable entry documents.

Use the built-in code navigator before broad text search. When raw search is
needed, scope it to the tracked tree with `git grep` or `git ls-files`; never
recursively scan the repository root, which can contain scratch data and full
untracked worktrees.

## Authority and safety boundaries

Agents may inspect, edit, build, and test source in the checkout and isolated
fixtures. Agents do not implicitly have authority to:

- change a consensus predicate or the byte-sealed consensus core;
- spend funds, export private keys, or weaken wallet custody;
- mutate a canonical datadir or perform live database surgery;
- deploy, restart, or promote a production node;
- weaken an assertion, acceptance threshold, or fail-closed refusal to obtain
  a green result;
- execute fetched package source outside the explicit bounded build/test
  lifecycle;
- publish, sign, or accept evidence on another operator's behalf.

Consensus-core edits require the explicit unseal/reseal ritual documented in
[`docs/CONSENSUS_PARITY_DOCTRINE.md`](./docs/CONSENSUS_PARITY_DOCTRINE.md).
Recovery work is copy-first; see [`docs/TENACITY.md`](./docs/TENACITY.md).
Deployment and custody actions remain owner-gated.

Escalate only for a consensus or custody risk, a destructive production
action, irreconcilable authority ambiguity, a missing human product decision,
an assertion that would need weakening, or genuine completion of the current
mission.

## Development contract

- Never use Python. Do not add `.py` files, `python3` shebangs, Python
  heredocs, or `python3`/`python` invocations. Compiled code is C23. Operator
  and test glue is POSIX or bash shell, or a small in-tree C23 helper such as
  `tools/sqlq.c` and `tools/jsonq.c`. JSON is extracted with grep/sed/awk for
  flat fields, or `build/bin/jsonq` for nested documents. SQLite inspection
  uses `build/bin/sqlq`. Do not add Python as a fallback, optional path, or
  "legacy" exception.
- Preserve unrelated dirty work. Never reset, overwrite, or fold it into your
  commit.
- Maintain one primary writer per component. Coordinate through committed
  source identity; `origin/main` is the shared integration blackboard.
- Fetch current `origin/main` before work and before each push. Integrate it
  safely, then rerun affected gates.
- Use typed native commands to inspect and operate a running node. Git,
  compilers, `make`, and bounded shell scripts remain normal repository tools.
- Add a native command only for a recurring operator or agent product need,
  not for a one-off development convenience.
- Keep tests scoped to local fixtures, isolated datadirs, and consenting peers.
- Use existing CAS, task, candidate, action, receipt, queue, and signature
  authorities. Do not create a parallel source of truth for convenience.
- No consensus or custody claim is complete because a unit test passed. Run
  the acceptance that observes the real invariant.

Mandatory defensive rules are enforced by `make lint` and explained in
[`docs/DEFENSIVE_CODING.md`](./docs/DEFENSIVE_CODING.md). In particular:

- every application write uses the ActiveRecord save lifecycle;
- every error return logs context;
- every allocation is checked;
- every native command failure sets an explanatory response body;
- custody-bearing models retain their before/after-save hooks.

## Completion and continuation

A coherent slice is ready to push only when its focused acceptance is green,
required generated files are current, lint passes at the required scope, and
the commit contains no unrelated work. Push normally and verify the exact
remote SHA.

A push is a checkpoint, not completion. A status report does not suspend work.
After each coherent push, fetch current `origin/main`, integrate it, and
continue through the mission's ordered continuation queue. Stop only when the
complete acceptance is green or one of the named escalation conditions is
reached.

For substantial assignments, managers should provide a compact mission
capsule instead of repeating the repository doctrine:

```text
NORTH STAR
USER OUTCOME
CURRENT BASELINE
OWNED SURFACE
INVARIANTS
ACCEPTANCE
CONTINUATION QUEUE
ESCALATE ONLY IF
```

The curated documentation map is [`docs/README.md`](./docs/README.md).
