# z23 — Metaverse MVP acceptance reference

> **Scoped simulation acceptance, not a work queue.** Current task selection
> lives only in [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md). Run the
> aggregate below only when that plan selects this scope.

**Metaverse MVP = "a stranger can build the node, take the five-command
metaverse tour, publish and verify a package in the commons, see their
property and spaces in the explorer, and read one honest page about what is
real and what is simulation."** Eight binary acceptance criteria (MM1–MM8),
each with a mechanical verification target. `make metaverse-verify` is the
aggregate; this page records which full claims it does and does not establish.

Mission context: *"Z23 is a metaverse where people and AI create real
things together, and nobody owns the world they build in."* The full program
specs are the four maintainer documents under `docs/work/`
(`ZCODE_PLAN.md`, `ZCODE_DEVELOPMENT_NETWORK.md`,
`ZCODE_SCIENTIFIC_METAVERSE.md`, `ZC23_LIVING_COMMONS.md`); the user-facing
entry point is [`docs/METAVERSE.md`](./METAVERSE.md). This file is the bar,
not the spec.

**Scope honesty — ZC23 is simulation-complete, never live.** No GENESIS,
MINT, SEND, wallet, custody, or consensus path is part of this MVP. Live ZC23
issuance stays blocked by design (challenge-mature founding contributions,
green shadow epochs, exact active-chain proofs, custody gates, owner
authorization per `docs/work/ZC23_LIVING_COMMONS.md`). A criterion that says
"simulation-complete" means: every simulated flow works end to end and every
live-money path fails closed with a typed, owner-gated error.

## Acceptance criteria

| # | Criterion | How we verify | Status |
|---|---|---|---|
| MM1 | **One-command metaverse tour on a fresh node** | `make metaverse-tour` drives an isolated regtest node (unique `/tmp` datadir, non-live ports, via `tools/scripts/isolated_node_env.sh`) through: publish a package to the local CAS, `metaverse space plan\|commit\|show`, `metaverse space scout plan\|run\|show`, and `zcode commons status` — script `tools/dev/metaverse_tour.sh`, exits 0 only when every step's typed output confirms | ✅ |
| MM2 | **ZCODE package lifecycle** | publish → search → fetch → third-party reproduction MATCH via `build/bin/zclassic23-package-verify --reproduce-against`; the registered groups `test_zcode_publish`, `test_zcode_fetch`, and `test_zcode_verify` (which execs the real verifier binary) pass under `make metaverse-verify` | ◐ |
| MM3 | **Property catalog is complete or honestly scoped** | all 9 kinds in `lib/metaverse/src/adapter_registry.c` are either `MV_WIRED` or carry an explicit out-of-MVP-scope decision asserted by the `test_metaverse_catalog` decision table — no silent gaps. The `MV_MVP_SCOPE` partition (4 datadir-provable kinds in scope, 5 out: 4 runtime/node.db, plus `character_sheet`, which is content-addressed and checkable but which no datadir path enumerates) is pinned by `t_mvp_scope_decision` | ✅ |
| MM4 | **ZC23 Living Commons simulation-complete** | `zcode.patronage.settle.plan\|commit` and `refund.plan\|commit` promoted from PLANNED fail-closed to simulation-READY in `config/commands/zcode.def`; dedicated unit groups `test_zcode_patronage`, `test_zcode_continuity`, `test_zcode_commons_projection` registered and green; `zcode commons status` reports `complete` or a named blocker (never silent `unknown`). The three unit groups are registered and green; the settle/refund promotion is the open half | ◐ |
| MM5 | **Metaverse web UX in the explorer** | `/metaverse` landing, `/metaverse/property`, `/metaverse/space`, `/metaverse/commons` pages render from live projections (pattern: `app/views/src/zcode_view*.c` + `app/controllers/src/zcode_site_controller.c`); render gate `test_metaverse_site` registered and green (18/18 checks; isolated-node HTTPS smoke returns 200 on all four routes) | ✅ |
| MM6 | **CLI UX is discoverable and documented** | every `metaverse.*` / `zcode.*` leaf has a complete declared schema and description in `config/commands/*.def`; `docs/API_REFERENCE.md` regenerates clean (`make docs-api-reference`) and the lint gate `check-api-reference-generated` stays green | ◐ |
| MM7 | **Metaverse test suite runs as one aggregate** | `make metaverse-verify` exists and is green: the MM4 unit groups, the registered zcode/metaverse/space groups' key members, the multi-daemon proofs `make test-zcode-dht-acceptance` + `make test-science-acceptance`, and `make metaverse-tour`; new fuzzers `fuzz_zcode_dht` and `fuzz_zcode_science` in `FUZZ_TARGETS`. The target and fuzzers exist; the full aggregate has not run green yet | ◐ |
| MM8 | **Docs tell the truth to a newcomer** | root `README.md` and `docs/GETTING_STARTED.md` describe the metaverse tour; `docs/METAVERSE.md` is the canonical user-facing page; `docs/README.md` maps all of it; load-bearing claims carry inline `claim`-annotation bindings so `check-doc-claims` fails on rot | ✅ |

**Legend:** ☐ unmet / not gated · ◐ a gate covers a **slice** (real regression
protection, not the full claim) · ✅ the full claim run-passes via its
verification target on this machine. Same update rule as
[`docs/MVP.md`](./MVP.md): a criterion earns ✅ only when its full claim
actually runs and passes; a SKIP for a missing local dependency stays ◐.

<!-- claim: symbol-present zcode_publish tools/dev/test_group_catalog.def # MM2 publish group -->
<!-- claim: symbol-present zcode_fetch tools/dev/test_group_catalog.def # MM2 fetch group -->
<!-- claim: symbol-present zcode_verify tools/dev/test_group_catalog.def # MM2 verify group -->
<!-- claim: symbol-present metaverse_catalog tools/dev/test_group_catalog.def # MM3 decision-table group -->
<!-- claim: symbol-present check-api-reference-generated Makefile # MM6 freshness gate -->
<!-- claim: file-present tools/scripts/isolated_node_env.sh # MM1 isolation helper -->
<!-- claim: file-present docs/work/ZC23_LIVING_COMMONS.md # scope honesty source -->

## Verification

When [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) selects this scoped
acceptance, run `make metaverse-verify` and the criterion-specific commands in
the table. A criterion moves only when its full mechanical proof changes; the
table does not choose the next repository task.

## Relationship to the v1 node MVP

The v1 bar remains [`docs/MVP.md`](./MVP.md) (MRS 8/8) and its critical path
remains [`docs/work/FORWARD_PLAN.md`](./work/FORWARD_PLAN.md). The owner
opened this metaverse lane on 2026-08-08 in parallel; nothing here
deprioritizes C3/C5/C6/C8, touches consensus (the core seal stays frozen),
or relaxes any owner-gated deploy/custody rule.
