<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

<p align="center">
  <img src="docs/assets/z23-banner.svg" alt="Z23 — software made for you, not imposed on you" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="docs/assets/badges/license.svg" alt="license: Apache-2.0"></a>
  <img src="docs/assets/badges/language.svg" alt="language: C23">
  <a href="docs/MVP.md"><img src="docs/assets/badges/status.svg" alt="status: pre-v1"></a>
  <a href="#try-it"><img src="docs/assets/badges/start.svg" alt="start: make commons-demo"></a>
</p>

# Z23

**Software made for you, not imposed on you.**

Z23 is one self-contained C23 binary that is two things at once:

- **A full node** for the 100% proof-of-work ZClassic chain — consensus-compatible
  with `zclassicd`, wallet custody behind your keys and nothing else, explorer
  and API served over the node's own persistent Tor onion address.
- **A software commons** — describe what you want in plain words. Your node finds
  C23 that already does part of it, creates only the missing behavior, builds and
  verifies everything on your machine, and lets you accept one exact version and
  keep it.

The point is ownership that survives platforms. Source is content-addressed,
releases are independently reproducible, distribution needs no central registry,
and the person who wrote the code can disappear without taking the software with
them. AI workers are replaceable; the network, the exact source history and your
authority over your own machine remain.

---

## Status

| Layer | Where it stands |
| --- | --- |
| **Full node** | Implemented; pre-V1 acceptance is tracked by [`make mvp`](docs/MVP.md). One self-contained C23 binary validates the proof-of-work chain, holds wallet custody behind local keys, and can serve its explorer and API over a persistent Tor onion address. Mutable hosted-node state belongs only in [`docs/HANDOFF.md`](docs/HANDOFF.md). |
| **Onion mesh** | Hardening. Nodes find each other over Tor onion services — hardcoded onion seeds and peer-published `/directory.json` bootstrap discovery, and `ops mesh join` adds a peer you trust directly. No node referees the others: each one validates the chain for itself, and missing header data is backfilled peer to peer rather than trusted from a single source. |
| **C23 Commons** | Built, transport-gated. The full loop — describe, reuse, build, accept, fetch, reproduce, serve — runs locally today via `make commons-demo`; the peer-to-peer swarm opens over mesh transport once that transport proves itself. |
| **Acceptance** | Honest by construction. [`make mvp`](docs/MVP.md) prints PASS only after observing the whole declared criterion; anything unavailable is named BLOCKED, never silently green. |

---

## Try it

```bash
git clone https://github.com/z23c/z23
cd z23
make -j"$(getconf _NPROCESSORS_ONLN)" z23
make commons-demo        # (optional first: make setup — arms git hooks + LSP config)
```

Three fresh nodes start on empty datadirs inside your machine. Nothing outside
it is contacted. Exit `0` means every promise below held; each one asserts
itself and stops at the first that does not:

1. **Ask** for a behavior; reuse C23 another node already published.
2. **Build and accept** one exact result — and watch the behavior you asked for,
   before anything is published anywhere.
3. A second node **fetches those bytes peer to peer** and rebuilds them
   byte-identical. Altered source, an unknown dependency, a stale acceptance:
   each refused by name, never by silence.
4. **Kill the original publisher.** A third node still fetches, reproduces and
   runs those exact bytes from whoever still holds them.

![make commons-demo — the whole loop, end to end](docs/assets/z23-term-commons-demo.svg)

Reproduce means what it sounds like: the second node re-derives identical source
from content addresses it verified itself, then builds a byte-identical program.

The same journey with B and C on separate physical hosts — the publisher's
machine itself gone — is `make commons-multihost-acceptance`:

![what the demo measured](docs/assets/z23-term-commons-proof.svg)

---

## The flow

**DESCRIBE → REUSE → CREATE → SEE → KEEP → SHARE**

![Describe, reuse, create, see, keep, share](docs/assets/z23-journey.svg)

- **DESCRIBE** — say what you want the software to do, in your own words.
- **REUSE** — Z23 looks for C23 in the commons that already does part of it.
- **CREATE** — only the missing behavior is written, built and tested.
- **SEE** — you experience the changed application before anything is published.
- **KEEP** — you accept one exact version, by hand, and it stays yours.
- **SHARE** — peers fetch that exact source, reproduce it, and preserve it.

SEE is what the rest is in service of. Packages, roots and publication are
machinery; the moment that matters is the application doing what you asked, on
your screen, before anyone has published anything.

---

## Build C23 without guessing

Ask the checkout what already exists before writing another copy. These native
queries derive their answers from the current source and command registry:

```bash
build/bin/z23 code guide
build/bin/z23 code have --input='{"text":"bounded parser"}'
build/bin/z23 code map
build/bin/z23 code group lib/ontology
build/bin/z23 code file lib/ontology/include/ontology/ontology.h
build/bin/z23 code capsule zcl_ontology_evaluate_formula_v1
build/bin/z23 code provenance relations zcl_ontology_evaluate_formula_v1
build/bin/z23 code impact lib/ontology/src/ontology_formula.c
build/bin/z23 code tests lib/ontology/src/ontology_formula.c
build/bin/z23 discover schema code.have --side=input
```

Run the exact group returned by `code tests`, then the fast defensive checks:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact ONLY=<exact-group>
make lint-fast
```

Do not copy command, module, symbol or test counts into prose. `code map`,
`code group`, the generated [API reference](docs/API_REFERENCE.md), and the
[capability inventory](docs/CAPABILITY_INVENTORY.jsonl) derive the live surface
from the current tree.

### Ontology and retrieval evidence

Z23's self-knowledge foundation has canonical identities for the source
universe, terms, predicates, contexts, assertions, coverage, domains, formulas,
Horn rules, manifests and derivations. The bounded, paraconsistent evaluator
can report `PROVED`, `DISPROVED`, `BOTH`, `UNKNOWN` or `INCOMPLETE` without
turning a contradiction into arbitrary truth. Missing accepted coverage or
type evidence, unsupported execution tiers, and exhausted memory, fact, step,
recursion, derivation or time budgets remain explicitly `INCOMPLETE`.

This is strong groundwork, not an omniscience claim. The source-universe
observer currently records candidate readings but cannot yet prove every
canonical path projection, so it reports unverified or incomplete. Horn rules
and the canonical `isa` and `genls` taxonomy are admitted as exact rooted
objects. The low-level IO-free library now saturates admitted,
range-restricted Horn rules to a bounded fixed point over a locally revalidated
manifest closure; positive and explicit-negative derivations remain
independent in the evaluator, while the current executable fixture proves
their independent observation; imported facts are visible only through exact
context roots. Executable negative-rule and equality-constraint fixtures are
still required before those admitted Horn forms are claimed end to end.
The separate general-formula evaluator still accepts exact-tier predicates.
`code provenance relations <symbol>` now exposes a bounded, typed relation
projection over the current source and command-registry roots: `isa`, exact
definition/declaration occurrences, source group, registered command execution
contract, and required focused-test routes. It stays `INCOMPLETE` because a
static execution contract is not a runtime observation and a required test is
not an accepted receipt. Native execution of arbitrary Horn questions and the
receipt join remain unfinished rather than being simulated by this projection.

Optional signed-int8 concept-card vectors are strictly `MODEL_HINT` evidence.
They may propose or order fuzzy candidates, but cannot prove identity, truth,
completeness, compatibility, ownership, authority, calls, permission, safety,
and cannot omit a mandatory proof or test. Canonical codecs and root bindings
exist today; an embedding-model runner, production ranker and live vector-search
command do not. Exact facts, contexts, coverage and receipts remain
authoritative.

### Working asynchronously with other agents

Keep one writer per component and use committed source identity on
`origin/main` as the shared development blackboard. Nodes exchange remote work
through the existing CAS-backed task, candidate, action, work-context and
receipt chain—not through a second agent queue or repeated transcripts:

```bash
build/bin/z23 zcode task board
build/bin/z23 zcode task pull --input='{"task_root":"<64hex>"}'
build/bin/z23 zcode work pull --input='{"task_root":"<64hex>"}'
```

Exact push admission is still a checkout-local transitional service:

```bash
make dev-bin
build/bin/z23-dev dev proof status
build/bin/z23-dev dev proof wait
```

Peers should send immutable roots first and request only missing closure
objects. Pulling verifies inert bytes; it neither executes nor accepts them. A
receipt proves only its exact bound observation, every receiver applies local
policy, and peer-local token or transport metrics stay outside portable work
roots. Consensus, synchronization and wallet custody always preempt background
package, indexing, ontology and proof work.

---

## The game on the cover

Every good box shows the toy. This one flies.

`zdogace` is a real-time 3D dogfight: two teams of AI pilots over a neon grid
city. Nothing in that picture is faked for marketing — the HUD stamps the
replay and state roots every frame was re-derived from, the same
verify-don't-trust discipline the node applies to blocks and packages. The
game is an ordinary C23 app assembled from small commons packages: the arena,
the flight model, the pilots.

![the red ace turns, fires, and takes the match — a verified replay, 30 fps](docs/assets/z23-flyover-hero.gif)

Ask for a change. See it fly. Keep that exact version. Share it peer to peer.

> *"Make the aircraft turn faster."*
> *"Add a blue engine trail."*
> *"Make these enemies cooperate."*
> *"Add a new building I can enter."*

---

## Principles that do not bend

- **C23 source first.** Small, fast, portable native software.
- **Permissive open source.** Public commons releases are author-signed and
  carry an allowlisted permissive license; your node refuses to announce or
  serve anything that does not verify. See
  [P2P source hosting](docs/P2P_SOURCE_HOSTING.md).
- **Local verification.** Your machine re-derives what it was told, from content
  addresses it checked itself. Nothing is accepted because a server said so.
- **No privileged coordinator.** Discovery is peer to peer; no central registry
  is required, and no node holds a position the others cannot.
- **Free reuse first, payment only where scarcity remains.** Copying source
  costs nothing and stays free. Compute, verification, storage and hosting are
  real costs; payment is optional, and current marketplace or token economics
  remain simulation-only. Z23 does not force ZCL as the only payment method.

---

## The chain

The same binary is a ZClassic full node. The chain can provide durable ordering,
payments, names and anchors, while application source and builds stay off-chain
where they belong—a blockchain is a terrible place to put a source tree and a
good place to agree on what happened first. A chain record never grants package
acceptance, execution, publication, wallet or deployment authority. The
development loop above does not wait on it: you can run the whole flow before
your node has caught up to the tip.

---

## Run the node

```bash
build/bin/z23 status
build/bin/z23 core sync diagnose
build/bin/z23 ops logs
```

Every command is a leaf of the native command registry, so nothing here has to
be memorised — `build/bin/z23 discover help` prints the live surface, and
`build/bin/z23 discover describe <leaf>` prints one command's typed contract.

Nodes meet each other over Tor onion services, so a node behind any NAT can
dial and be dialed without port forwarding:

```bash
# join an operator-directed peer (onion endpoint of the peer you trust)
build/bin/z23 zses invite accept --invite=<json>
build/bin/z23 ops mesh join --endpoint=<host>.onion:<port> --input='{"confirm":true}'
build/bin/z23 ops mesh join_status        # did the peer land? honest verdict
```

Onion identities persist in your datadir; the same node keeps the same
address across restarts.

![the live command surface](docs/assets/z23-term-command-surface.svg)

For development, start with `code guide`, route the changed path through
`code tests`, run the returned registered parallel group exactly, and let the
exact commit/base proof complete before pushing.
[`docs/DEVELOPING.md`](docs/DEVELOPING.md) is the maintained development and
receipt-admission contract.

---

## Go deeper

| | |
| --- | --- |
| **Public start here** | [Getting started](docs/GETTING_STARTED.md) |
| Agent entry point | [AGENTS.md](AGENTS.md) |
| The commons | [C23 Commons quickstart](docs/C23_COMMONS_QUICKSTART.md) |
| Verification | [Security and integrity](docs/SECURITY_AND_INTEGRITY.md) |
| Design | [Architecture north star](docs/ARCHITECTURE_NORTH_STAR.md) |
| Source map | [Codebase map](docs/CODEBASE_MAP.md) |
| Native API | [Generated API reference](docs/API_REFERENCE.md) |
| Exact capabilities | [Capability inventory](docs/CAPABILITY_INVENTORY.jsonl) |
| Ordered mission | [Forward plan](docs/work/FORWARD_PLAN.md) |
| Work ledger | [docs/work index](docs/work/README.md) |
| The market | [ZCODE plan](docs/work/ZCODE_PLAN.md) |
| Contributing | [Developing](docs/DEVELOPING.md) |
| Where it stands | [MVP criteria](docs/MVP.md) |

Z23 is Apache-2.0. The name is the chain (ZClassic) and the language (C23),
because the two are the same project.
