<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 agent contract

Shared by every coding agent (Claude Code, Codex, others). `CLAUDE.md` imports this file.

Z23 is a public ZClassic full node in one self-contained C23 binary. It validates the chain bit-for-bit like `zclassicd`, joins P2P, holds transparent and shielded wallet state, and can serve over embedded Tor.
An optional C23 Commons publishes, fetches, builds, reproduces and serves content-addressed packages without a central registry.
North Star: software made for you, not imposed on you, with exact source identity and independent reproduction.

Volunteers and the agents they drive: start at [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md). This file is for maintainers.

## Layout

- `core/` sealed consensus truth (`core/MANIFEST.sha3`); no nested guide, the seal gate rejects extra files. Edit only through [`core/UNSEAL.md`](core/UNSEAL.md).
- `engine/` composes and runs the node; `engine/reducer/` alone advances chain state.
- `contexts/<feature>/` feature rooms: wallet (custody-bearing; run `make custody-check`), explorer, naming, messaging, market, commons. No nested guide: the tree gate reads any file directly under `contexts/` as an unknown room. `contexts/commons/corpus/` is generated evidence.
- `cognition/` code intelligence, ontology, science, agent-development machinery.
- `platform/` portable base, `platform/ports/` and `platform/adapters/` for outside systems, packaging, deploy.
- `apps/` separate C23 programs that link neither `core/` nor `engine/`.
- `tools/` native commands, lint gates (`tools/lint/`), dev tooling, scripts.
- `tests/` harness and fixtures. `docs/` manuals. `vendor/` pinned third-party code.
- `.claude/` skills, agents, plugins. `.github/` public contribution rules.

## Commands

```bash
make doctor                                   # toolchain check
make -j"$(getconf _NPROCESSORS_ONLN)" z23     # build/bin/z23
make dev-bin                                  # fast development binaries
make t-list                                   # registered test groups
make t-fast ONLY=<group>                      # focused tests; ONLY is mandatory
make -j"$(getconf _NPROCESSORS_ONLN)" agent-verify ONLY=<g,g>  # one-trip verify
make lint-fast                                # fast lint subset
```

Never run `test_zcl` directly. Run full `make lint` once, at the candidate tip before landing.
On a maintainer host, prefix heavy commands with `devbuild --wait` ([Maintainer hosts](docs/dev/DEVELOPING.md#maintainer-hosts)).

Before editing, `build/bin/z23 code guide <paths>` (MCP: `z23_code sub=guide`) returns one brief: nearest `AGENTS.md` rules, test groups, wiki lessons, first commands.
Navigate with the binary before searching: `code map`, `code owner <path>`, `code impact <path>`, `discover help <path>`.
Search with `git grep`. Generated references (`docs/CAPABILITY_INVENTORY.jsonl`, `docs/API_REFERENCE.md`, corpus evidence) are excluded from search by `.ignore`; open them by path.

<!-- claim: symbol-present t-fast Makefile # focused registered-test target -->
<!-- claim: symbol-present test-parallel Makefile # full registered-test target -->
<!-- claim: symbol-present discover.schema engine/composition/commands/root.def # live schema leaf -->
<!-- claim: symbol-present code.map engine/composition/commands/code.def # live source-map leaf -->
<!-- claim: file-present docs/API_REFERENCE.md # generated command catalog -->

## Coding contract

- **C23 only. Never use Python:** no `.py` files, Python shebangs, invocations or heredocs. Glue is native C23 or small POSIX sh; the no-new-bash ratchet applies. Flat JSON: grep/sed/awk; nested JSON: `build/bin/jsonq`; SQLite: `build/bin/sqlq`.
- Reuse existing C23 first; create only what is missing. Prefer deletion and composition over new abstractions.
- Every application write follows the ActiveRecord save lifecycle. Check allocations, log contextual errors, give command failures explanatory bodies ([DEFENSIVE_CODING.md](docs/DEFENSIVE_CODING.md)).
- Use existing CAS, task, candidate, action, receipt, queue and signature authorities; add no competing source of truth.
- Tests use local fixtures, isolated datadirs and consenting peers. Never weaken an assertion or threshold to pass.
- Preserve unrelated dirty work; never reset, overwrite or commit it. Fetch `origin/main` before work and before every submit; never rewrite others' history.
- Check [AGENT_TRAPS.md](docs/agent/AGENT_TRAPS.md) before repairing behavior that may be intentional or complete.

## Authority and safety

Source inspection, editing, builds and isolated tests do not permit:

- consensus predicate changes or edits to the sealed `core/` (explicit unseal/reseal ritual only);
- spending funds, exporting keys or weakening custody;
- deleting, reindexing or hand-editing a canonical datadir (live database surgery);
- deploying, restarting into or promoting a build that is not reviewed and landed;
- secrets, keys or grants in logs, argv, commits or messages;
- fetched-source execution outside the bounded build/test lifecycle;
- publication, signing or acceptance on another operator's behalf.

Restarting a node and upgrading it to a reviewed, landed build are routine; `make deploy` keeps its explicit `ZCL_DEPLOY_ALLOW_CANONICAL=1` switch for the canonical lane. Deploy one host at a time and never run two deploys concurrently. Routine development, landing and reviewed deploys need no approval round.

**Verify, don't trust.** A hash identifies bytes, a signature identifies a signing key, a receipt binds an observation; none alone proves safety or correctness. Downloaded C is inert until built and tested under local policy. P0 is always consensus, custody and public-node health; builds, telemetry and agent work never delay them.
Escalate only for consensus or custody risk, a destructive production action (datadir delete or reindex), a spend, or an assertion that would need weakening; decide everything else, record the decision and continue. Read [SECURITY_AND_INTEGRITY.md](docs/node/SECURITY_AND_INTEGRITY.md) and [CONSENSUS_PARITY_DOCTRINE.md](docs/CONSENSUS_PARITY_DOCTRINE.md) before consensus or custody work.

## Review and landing

- Every unit needs one reviewer who is not its author, of any model.
- Commits are authored by the repository owner; an AI-written commit ends with a `Co-Authored-By:` trailer naming the model.
- Fleet work coordinates through native tasks and receipts, never GitHub issues or pull requests; volunteers use `card:` pull requests.
- After placement changes run `make check-architecture-tree`.
- Only the land queue pushes main: submit with `build/bin/z23-dev dev land submit --worktree=$PWD` and follow `dev land status`. A landing is a checkpoint; fetch, integrate and continue. See [section 6](docs/dev/DEVELOPING.md#6-integrate-and-push-a-coherent-slice).

## Where detail lives
- The one standard loop (lane, brief, verify, review, land) and the boundaries: [THE_Z23_WAY.md](docs/THE_Z23_WAY.md).

- Procedure: [DEVELOPING.md](docs/dev/DEVELOPING.md); open one section, never the whole file: [1. Orient](docs/dev/DEVELOPING.md#1-orient), [3. Edit within ownership](docs/dev/DEVELOPING.md#3-edit-within-ownership-boundaries), [4. Fast feedback](docs/dev/DEVELOPING.md#4-receive-fast-local-feedback), [5. Build and proof](docs/dev/DEVELOPING.md#5-build-and-focused-proof).
- Maintainer hosts, fleet priorities, scorecard tiers, lanes and trains, source baseline: [Maintainer hosts](docs/dev/DEVELOPING.md#maintainer-hosts), [AGENT_FLEET.md](docs/work/AGENT_FLEET.md), [FLEET_GUIDE.md](docs/agent/FLEET_GUIDE.md).
- Ownership map: [CODEBASE_MAP.md](docs/dev/CODEBASE_MAP.md). Current work order: [FORWARD_PLAN.md#now](docs/work/FORWARD_PLAN.md#now). Docs index: [docs/README.md](docs/README.md).
- Nested `AGENTS.md` files in `engine/`, `cognition/`, `platform/`, `apps/`, `tools/`, `tests/`, `docs/` and `vendor/` add area rules.
