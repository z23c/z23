# EXTENSION_POINTS.md — three surfaces under active construction

Where the current round's work lives and how to extend each. Every factual
sentence here is bound to a `claim:` annotation that `make lint`
(`check-doc-claims`) evaluates, so a section that goes stale fails the build
instead of misleading the next agent. Counts come from the machine-checked
`DOC-COUNTS` block in [`CODEBASE_MAP.md`](CODEBASE_MAP.md); none are typed here.

## 1. Crypto ownership — the vault

**Question it answers:** what does this node own, and what is allowed to move it.

- Read model: `contexts/wallet/services/src/vault_read.c` (+ `vault_read.h`, which states
  the two rules the design turns on).
- Command surface: `engine/composition/commands/vault.def`, handlers in
  `tools/command/native_vault_command.c` and `native_vault_session_command.c`.
- Proofs: `tests/harness/src/test_vault_{read,dispatch,session}.c`.

**The invariant that shapes every extension:** the vault contains no spend
logic and no balance mathematics of its own. Each asset class row is produced
by the primitive that already owns that number and names it in
`source_primitive`; the custody leaves dispatch to the handler that already
binds the action. To add an asset class, add a row that calls an existing
primitive and reports `determined=false` with a reason when it cannot — a class
that vanishes from the output is indistinguishable from a zero balance, which
is the bug this model exists to kill. Do not add a second transaction builder.

<!-- claim: file-present contexts/wallet/services/src/vault_read.c -->
<!-- claim: file-present engine/composition/commands/vault.def -->
<!-- claim: symbol-present source_primitive contexts/wallet/services/include/services/vault_read.h -->

## 2. Big integers — fixed-width today, variable-width landing

**State at this commit: there is no shared big-integer type.** What exists:

- `struct fr` — 256-bit, `uint64_t d[4]`, Montgomery form
  (`core/modules/sapling/include/sapling/fr.h`); the BLS12-381 scalar field.
- `struct fp` — 384-bit, `uint64_t d[6]` (`core/modules/sapling/include/sapling/bls12_381.h`);
  the base field, with AVX-512 paths in `fr_avx512.c` / `bn254_accel.c`.
- One file-static `struct bigint` — 288-bit, nine 32-bit limbs, private to
  `core/modules/sapling/src/jubjub.c` and reachable from nowhere else.

So the widths are compile-time constants chosen per curve, and the one general
routine is not shared. A variable-width type is being landed by a parallel
workflow; when it arrives it belongs in `core/modules/crypto/` (the primitives module),
not in `core/modules/sapling/`, which is the Sapling *protocol* layer that consumes it.
Two hard constraints on whoever lands it: `core/` is byte-sealed, so no
consensus predicate may change to accommodate a new representation, and any
speedup on a consensus-critical path needs the differential parity oracle
(`make check-groth16-parity`) rather than a benchmark.

The predicates below hold *because* the work has not landed. They fail the day
it does — which is the signal to rewrite this section, not to work around them.

<!-- claim: symbol-absent bigint core/modules/crypto/* # no shared big-integer type yet -->
<!-- claim: symbol-present bigint core/modules/sapling/src/jubjub.c # the only one today, file-static -->
<!-- claim: file-present core/modules/sapling/include/sapling/fr.h -->

## 3. Pluggable services — the declarative manifest

**Question it answers:** what a service is allowed to do, declared as data
rather than as code that runs.

- Contract: `engine/modules/kernel/include/kernel/service_manifest.h`
  (`zcl.service_manifest.v1`) — pointer-free, so a manifest is hashable and
  comparable; validation lives in `engine/modules/kernel/src/service_manifest.c`.
- Catalog: `engine/composition/services/catalog.def`, consumed by
  `engine/composition/src/service_catalog.c` via `ZCL_SERVICE_ENTRY(...)`.
- Rationale: [`adr/0004-capability-service-fabric-and-app-checkpoints.md`](adr/0004-capability-service-fabric-and-app-checkpoints.md).
- Proof: `tests/harness/src/test_service_manifest.c`.

Each entry declares role, trust class, dependencies, readiness evidence,
resource ceilings, restart policy, and descriptor grants. **Every entry is
`ZCL_SERVICE_ENFORCEMENT_SHADOW`: validating and hashing a manifest grants no
runtime authority.** An init implementation must still bind every descriptor,
IPC grant, generation, and peer, so a declaration here is a statement of intent
that nothing yet enforces — do not read the catalog as a sandbox. To add a
service, add one `ZCL_SERVICE_ENTRY` row and a test; promoting one to
`ZCL_SERVICE_ENFORCEMENT_ACTIVE` is a separate, owner-gated step that needs a
real binder first.

<!-- claim: file-present engine/composition/services/catalog.def -->
<!-- claim: symbol-present ZCL_SERVICE_ENFORCEMENT_SHADOW engine/composition/services/catalog.def -->
<!-- claim: symbol-absent ZCL_SERVICE_ENFORCEMENT_ACTIVE engine/composition/services/catalog.def # still shadow-only -->

---

The `.def`-registry pattern is the same in all three places and in the command
catalog, the diagnostics dumpers, and the condition registry: a header defines
the macro, a `.def` file holds one row per thing, and a `.c` file `#include`s
the `.def` to build a table. Add the row; never hand-edit the generated table.
