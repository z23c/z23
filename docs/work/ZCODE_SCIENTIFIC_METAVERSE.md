# ZCODE scientific metaverse and proof-of-contribution network

> User-facing entry point: [`../METAVERSE.md`](../METAVERSE.md); acceptance
> bar: [`../METAVERSE_MVP.md`](../METAVERSE_MVP.md). This is a scoped protocol
> specification, not a current-work queue. Current ordering lives only in
> [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

Status: owner-directed implementation plan, 2026-08-02. This plan extends the
live ZCODE package and agentic-development foundations. It does not displace
the sovereign-node MVP order in [`FORWARD_PLAN.md`](./FORWARD_PLAN.md), change
ZClassic consensus, authorize a deploy, or authorize movement of live funds.
The planned transferable asset is ZC23. Its immutable creation-backed issuance
covenant, denomination, patronage boundary, and LC0-LC5 order are authoritative
in [`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md).

## Mission and truth boundary

> **Z23 is a metaverse where people and AI create real things together,
> and nobody owns the world they build in.**

The scientific surface is one factual part of that shared world. Humans and AI
may propose and execute work together, but neither a model identity nor a human
identity establishes truth. The evidence graph records exactly what was asked,
run, observed, reproduced, and reviewed. No operator, committee, balance,
website, or model owns the world or gains authority over another participant's
conclusions.

ZCODE is an application overlay with this evidence flow:

```text
question -> preregistered study -> confined experiment -> signed evidence
         -> independent reproduction -> review -> local conclusion
         -> optional creation attribution under the ZC23 policy
```

ZClassic PoW supplies active-chain ordering, timestamps, reorg handling,
delayed election randomness, and ZSLP settlement. It does not establish
scientific truth, operator independence, data availability, or anonymity.
Scientific acceptance remains local and evidence-based.

The implementation must reuse the existing owners:

- `content.v2`, `vcs_object`, and the ZCODE package store own bytes and CAS.
- Existing ZVCS manifests own exact source trees.
- `vcs_package_lock`, `vcs_package_recipe`, toolchain capsules, and ZBuild own
  dependencies, build graphs, environments, and confined fixed actions.
- Existing `task.v1`, `candidate.v1`, `proof_policy.v1`, `review.v1`,
  `work_receipt.v1`, and `proof_set.v1` wires remain byte-stable.
- ZID/ZANC own identity and chain-anchored identity statements.
- The `zpkgswm` multiplexer owns package and ZCODE network traffic.
- The existing metaverse property `zcode_package:<root>` remains the only
  ZCODE package property kind.
- Generic ZSLP owns base token validity. ZC23 policy is an additional local
  application verdict, never a consensus predicate.

No second CAS, scheduler, identity system, transaction builder, socket stack,
or metaverse property kind may be added. Keep `core/` sealed. Use repository-
owned permissive C23 and add no mandatory run-time dependency.

## Canonical integrity rules

All new authority is a full domain-separated SHA3-256 root:

```text
chunk -> file manifest -> package/study object -> proof set
      -> signed checkpoint -> ZANC transaction -> PoW block
```

- 64-bit values are request IDs, counters, sequence numbers, heights, and
  times only; they are never roots or authority.
- HASH160 remains legacy transparent-address compatibility only.
- Canonical CAS, study, evidence, DHT, policy, committee, and checkpoint
  roots are 256 bits.
- Sign exact canonical binary wires, never display JSON.
- Prefixes may be displayed or indexed only if lookup resolves and rechecks
  the complete 256-bit root.
- New algorithms require a new version and explicit algorithm identifier;
  stacking a wider hash on SHA3-256 is not additive security.
- Every parser is exact-length, rejects trailing bytes, uses explicit little-
  endian integers, validates closed enums and bounds, and zeroes output on
  failure.

## Scientific object graph

The new canonical objects compose with the existing development graph:

```text
study_spec.v1 -> task.v1 -> candidate.v1
              -> benchmark/reproduce/review work_receipt.v1
              -> proof_set.v1 -> signed ZCODE package
              -> optional ZID/ZANC proof
```

### `study_spec.v1`

Fixed wire binding hypothesis root, null-hypothesis root, exact source,
dependency-lock and toolchain roots, protocol root, workloads/datasets root,
metrics root, estimator/tolerance root, environment-policy root, citations
root, preregistration-policy root, required reproductions, required reviews,
sequence, creation time, and expiry. A hypothesis and its null must be
distinct. The expiry must follow creation. Required counts are bounded and
nonzero. Text and datasets live in the existing CAS; the study wire binds
their roots.

### `benchmark_result.v1`

Fixed wire binding study, task, candidate, fixed action, achieved-environment,
raw-sample, and evidence roots, plus observation status, challenge block
height/hash, sequence, start time, and finish time. It records observations
and deliberately has no `true`, `accepted`, or `correct` field. Null and
negative results are valid statuses, not failures to publish.

### `reproduction.v1`

Fixed wire binding study, original result, reproduced result, comparison
policy, original/reproduced environment, reproducer identity, verdict,
sequence, and time. The closed verdict is `replicated`, `contradicted`, or
`inconclusive`. Original and reproduced result roots must differ.

### `science_findings.v1`

Fixed structured findings binding study, task, candidate, evaluated result,
proof set, methods, limitations, conflicts, optional retraction target, flags,
severity, sequence, and time. The object is formed first; the existing
`review.v1` then binds its root. This avoids a findings-root/review-root hash
cycle and does not introduce a second review signature system. The existing
signed review receipt authors the review.

### `curation_vote.v1`

Fixed signed local-discovery signal binding voter ZID, study/package property,
vote (`useful`, `interesting`, `flag`), sequence, expiry, and network. It is
not proof, money, committee weight, routing authority, or global truth.

### `contributor_binding.v1`

Canonical statement binding an existing ZID Ed25519 identity to a fresh ZCL
secp256k1 address/key. It binds network genesis, ZID, ZCL key/address,
predecessor binding, sequence, issue/expiry time, and active/rotate/revoke
operation. The exact body root is signed by both keys. Verification pins the
expected network and ZID and checks both signatures. Rotation points to the
prior binding; revocation cannot create a replacement key implicitly.

Implementation status (S2, remote coder, 2026-08-02): landed in
`contexts/commons/modules/vcs/include/vcs/zcode_contributor_binding.h` +
`contexts/commons/modules/vcs/src/zcode_contributor_binding.c` with focused tests appended to the
existing `zcode_contributor` group. The 184-byte body / 312-byte full wire is
domain-separated (`zcl.zcode.contributor_binding.v1` for the dual-signed body
root; `zcl.zcode.contributor_binding.root.v1` for the full-wire root a
successor's predecessor commits). The secp256k1 signature is 64-byte r||s
normalized to low-S, so sealing is byte-deterministic; the ZCL address hash
is validated as `hash160(zcl_pubkey)` at the codec layer. REVOKE carries the
key it retires (staying standalone dual-verifiable) and is terminal:
`vcs_zcode_contributor_binding_validate_successor()` rejects any successor of
a revoked binding, replay/skip sequencing, cross-network/cross-ZID links,
same-key rotations, new-key revocations, and tampered predecessors. S3/S6
consume only `root()` + `verify()`/`validate_successor()`; no
wallet/database/command surfaces were touched. Golden vectors are pinned in
`tests/harness/src/test_zcode_contributor.c` (`ZCB_KAT_*`).

Integration hardening (2026-08-02, same lane): `validate_at()` rejects use
before `issued_unix` (`ERR_NOT_YET_VALID`); `seal()` re-derives the Ed25519
public key from the supplied ZID secret and rejects a mismatch;
`validate_successor()` rejects non-increasing `issued_unix`
(`ERR_TIME_ORDER`). Golden v1 KATs unchanged.

### `contributor_binding.v2`

Three-signature rotation and delayed recovery (2026-08-02): 384-byte wire =
192-byte body (v1 fields + `activation_unix`) + ZID + current-ZCL + new-ZCL
signature slots under `zcl.zcode.contributor_binding.v2` /
`.root.v2` domains. ACTIVE signs both ZCL slots with the initial key; ROTATE
requires ZID + OLD ZCL + NEW ZCL; REVOKE keeps and signs with the retiring
key and zeroes the new slot; RECOVER (op 4) zeroes the current slot (old key
presumed lost), signs the new slot, and activates only at
`activation_unix >= issued_unix + 604800` — a separate delayed path, never a
fast rotation. `vcs_zcode_contributor_binding_validate_chain_v2()` adds the
retired-key reuse ban across the whole chain. v1 wire/KATs are frozen; v2
KATs (`ZCB2_KAT_*`) pinned deterministic across three runs.

Science-object hardening (S1 files, owner directive 2026-08-02):
findings/review time order corrected to match this spec (findings formed
first; `review->created_unix` may be LATER than the findings' creation —
rejected only when earlier); "may submit now"
(`vcs_zcode_study_spec_accepts_submission_at()`) is split from "evidence was
valid when created" — cross-object validators no longer consult the study
expiry against `now_unix`, so valid history re-verifies forever while
post-window submissions and future evidence (`ERR_EVIDENCE_FUTURE`) are
rejected; benchmark results must bind a canonical fixed-action root
(`ERR_ACTION_MISMATCH`); reproductions must compare the same
study/task/candidate/action across both results; findings must bind the
evaluated result's task and candidate roots.

## Fixed scientific actions

Extend the closed `vcs_build_action_v1` registry with:

- `c23.benchmark.v1`
- `c23.benchmark.reproduce.v1`
- existing `c23.review.v1` (retain its exact identifier)

Benchmark and reproduction actions use recipe-derived candidate inputs,
pinned toolchain/environment capsules, no network, bounded CPU/RAM/process/
output limits, raw sample manifests, and deterministic result envelopes.
Platform receipts are admissible only where that platform's native
confinement backend passes its escape suite. Downloaded scripts and arbitrary
shell remain forbidden.

AI agents may propose studies, execute fixed confined work, reproduce results,
and author signed reviews under metaverse grants. They receive no wallet keys,
threshold shares, raw-signing API, arbitrary shell, canonical deploy, or
release authority.

## Network overlay

Extend `zpkgswm`; do not add a socket stack.

- Stable node IDs derive from network genesis, a chain-anchored ZID, and
  delayed active-chain block hashes.
- ZID masters delegate online Ed25519 and Noise keys for at most 30 days.
- All ZCODE traffic requires a Noise-authenticated session. Direct and
  optional Tor routes retain the same channel binding.
- Kademlia parameters are fixed at `k=16`, `alpha=3`, at most 1,024 persisted
  contacts, a deterministic 64-candidate lookup pool with closest-16 active
  frontier, three parallel queries, and a 30-second lookup ceiling.
- Signed record kinds: `NODE` (6 hours), `PROVIDER` (2 hours), `POINTER`, and
  public `ANNOUNCEMENT` (7 days). Preserve conflicting valid records as
  equivocation evidence; do not hash-tie-break them into false agreement.
- A package targets eight providers. `durable` requires five signed storage
  acknowledgements across three declared owner groups. The API must call this
  declared diversity, never proof of different operators.
- Fetch order is local CAS, connected advertisers, DHT providers, then the
  exact existing manifest/chunk verifier.
- Persisted contacts, normal ZClassic peers, addrman/DNS/fixed seeds,
  ZENDP/ZDIR, manual peers, and optional Tor are additive hints. None owns an
  authoritative DHT signing key.
- Publishing over a direct route warns that peers observe IP, timing,
  requested roots, and volume. Tor does not unlink stable ZID signatures.

Native surfaces:

```text
zcode.network.status|peers|find                 # S6, implemented read-only
zcode.network.find.begin|poll|cancel            # S6, bounded async lifecycle
zcode.network.providers|publish|replication     # S7, implemented
zcode.network.policy.list|mutate                # S7, local/redacted
zcode.package.pin|unpin                         # S7, plan/commit
zcode.evidence.anchor|verify
ops state --subsystem=zcode_dht
```

Potential read resources (not implemented by S7; native typed commands remain
the only S7 operator surface, so no REST protocol silo was added):

```text
/api/v1/zcode/providers
/api/v1/zcode/dht-records
/api/v1/zcode/replication-receipts
/api/v1/zcode/evidence-checkpoints
```

### Future space and service discovery boundary

The metaverse is a federation of sovereign, user-hosted spaces, not one
global application. A future signed space manifest may advertise portals,
boards, mailboxes, doorbells, stores, labs, agent missions, and arbitrary
typed services. Provider and service discovery must therefore stay generic:
all of these objects reuse the existing `zpkgswm`, CAS, and DHT discovery
foundation rather than creating a second network stack or a protocol silo.
Agents may scout spaces and return signed evidence maps, but those maps are
evidence for local evaluation, never global authority.

Every node independently decides whether to discover, fetch, store, index,
serve, execute, forward, or interact with an object. Local policy may block a
full root, package, publisher ZID, service type, or local classification.
Shared blocklists are advisory and opt-in; no publisher, list, peer, or node
can globally ban content.

A doorbell is only an expiring, rate-limited signed request and can never
authorize remote code execution. BBS posts are signed, content-addressed
objects subject to local admission and indexing. Unknown C23 packages are
never executed automatically: execution requires explicit local policy and
the confined ZCODE executor. S7 supplies only the generic signed record,
transport, and local-policy foundation. It implements none of the space
manifests, doorbells, boards, mailboxes, service execution, or agent-mission
surfaces described here.

Canonical objects remain CAS truth. ActiveRecord rows are rebuildable,
bounded projections and caches. Every write uses the AR lifecycle.

## Science commands and discovery ranking

```text
zcode.science.study.plan|commit|show|list
zcode.science.work.plan|commit|status|receipt
zcode.science.review.submit
zcode.science.vote.submit
zcode.science.rank
```

Writes use expiring exact plans, `confirm:true`, durable idempotency, and stdin
for bodies or sensitive inputs. Existing `zcode.package.dev.*` and
`metaverse.build.*` become adapters to the same services rather than separate
implementations.

Personalized PageRank is deterministic and discovery-only:

- Nodes are ZCODE study/package properties; canonical citations are edges.
- Locally trusted signed curation votes influence personalization.
- Reproductions and reviews are local evidence filters.
- Integer mass is `10^12`, damping is `85/100`, iteration count is 32,
  ordering is full-root byte order, and remainders go to the earliest
  canonical nodes.
- Output binds algorithm version, graph root, seed-set root, filter-policy
  root, coverage, and truncation.
- Never rank people. Never use rank, votes, balances, or service volume for
  proof acceptance, committee authority, or rewards.

The pure S5 core is implemented in
`contexts/commons/modules/vcs/include/vcs/zcode_discovery_rank.h`. It accepts
only full property roots, canonical citation edges, locally aggregated seed
weights, and a filter-policy root. It normalizes all input order, rejects
duplicate or missing graph members, conserves exactly `10^12` integer mass,
and emits a canonical result ordered by mass then full root. The result binds
the graph, seed set, algorithm version, filter policy, returned coverage mass,
and truncation. Projection and the `zcode.science.rank` adapter remain
S3-dependent; this core has no person, proof-acceptance, wallet, reward,
database, network, or command input.

## Proof of contribution

### Bootstrap credential

A `c23.seed.v1` credential requires a permissively licensed public package,
frozen dependency lock, novel canonical semantic fingerprint, two pinned
independent C23 compiler capsules on one declared target, warnings-fatal
network-disabled compile/link success, dual ZID/ZCL signatures, durable DHT
replication, PoW anchoring, and a seven-day challenge period. Vendored or
generated code receives no credit. One credential is allowed per ZID.

The credential contributes selection weight 1, claims neither usefulness nor
safety, and earns no token by itself. Challenge-matured code, tests, fixes,
benchmarks, reproductions, negative findings, and structured reviews add
evidence points. Storage, signing, votes, PageRank, and transferred ZC23 add
no committee weight. One contribution root credits one identity.

### Committee election

- Epoch length: 8,064 active-chain blocks.
- Freeze candidates at the midpoint after compact `ZVAL` readiness records
  and referenced evidence are final.
- Election seed: next 64 ordered active-chain block hashes, after the existing
  finality policy.
- Weight: `1 +` challenge-matured evidence from the prior 26 epochs, linearly
  decayed and capped at 10,000.
- Sample distinct ZIDs without replacement using SHA3-derived 64-bit rejection
  sampling over canonical cumulative integer weights.
- Publish committee order, evidence snapshot root, seed heights/hashes,
  weights, concentration metrics, and policy root.
- One ZID gets at most one seat. Pseudonyms are not proof of different humans.
- At 100 seats, terms are four epochs and exactly 25 seats expire per epoch.
  Subjective liveness pings never change membership mid-epoch.

### Progressive custody

Do not create the transferable asset until three candidates are challenge-
mature and four shadow elections are green. Grow custody monotonically:

```text
3 candidates  -> 2-of-3 P2SH
5 candidates  -> 3-of-5 P2SH
9 candidates  -> 5-of-9 P2SH
15 candidates -> 8-of-15 P2SH
```

Replace approximately one quarter per epoch. Missing members produce
`quorum_unavailable`; thresholds never fall automatically. Honest signers
require individually signed approvals from two thirds of the committee over
the exact deterministic transaction. Script threshold remains the theft
boundary and the API must say that a compromised Script majority can bypass
the software certificate rule.

### ZC23 issuance and policy validity

Ticker `ZC23`, decimals 8, initial supply `1.00000000 ZC23`. Atomic epoch
capacity is `floor(50000 / 2^era) * 100000000`, with 208 epochs per era and no
fractional-era tail. Maximum policy-compliant supply remains exactly
`20,798,753.00000000 ZC23` = `2,079,875,300,000,000` atoms including genesis.
Checked `uint64_t` arithmetic is mandatory.

Every genesis or epoch atom must be assigned by exactly one challenge-matured
`creation_attribution.v1`. The ordered attribution sum equals actual MINT
exactly; actual MINT does not exceed the epoch cap; unissued atoms equal cap
minus MINT and expire permanently. There is no treasury remainder or
carry-forward. Upload, ordinary storage, DKG/signing, balance, patronage,
trading, votes, PageRank, popularity, and participation alone mint nothing.
Preservation qualifies only as a unique, mechanically demonstrated continuity
event under the Living Commons policy.

The outgoing committee's MINT pays the exact ordered creation set and
transfers the baton to the incoming committee. Confirm it before sharding
treasury UTXOs; do not build unconfirmed token chains. Burn the baton at zero
emission.

ZC23-aware clients expose a second verdict beside strict generic ZSLP:

```text
ZSLP_VALID + ZC23_POLICY_VALID
ZSLP_VALID + ZC23_POLICY_INVALID
UNKNOWN
HALTED_POLICY_VIOLATION
```

An off-schedule or unattributed but ZSLP-valid mint, or a stolen baton, halts
the ZC23 lineage;
clients never invent a replacement. Awards mature after both 8,064 additional
active-chain blocks and 604,800 seconds median-time-past. Reorg of the opening
anchor restarts maturity. Subjective review never changes payouts.

The genesis policy root is immutable. An incompatible policy requires a new
asset/version and explicit opt-in.

Every transaction plan binds policy/token/epoch, evidence, committee,
active-chain anchor, strict-valid confirmed inputs, scripts, quantities, fee,
expiry, and exact transaction bytes. Persist raw bytes and entry mapping
before relay; retry returns or rebroadcasts the same txid. Award state and
payout state are separate.

## Threshold ECDSA research boundary

Remain at 8-of-15 unless all activation gates pass: at least 150 challenge-
mature READY contributors for four epochs, two independent cryptographic
audits, three green 100-node DKG/sign/handoff rotations, and complete custody,
strict-ZSLP, reorg, backup, and sovereign-chain gates.

The selected target remains 51-of-100 ECDSA with a public 67-member Ed25519
certificate before honest nodes release shares. Fifty-one colluding shares
can steal by definition. Use a fresh aggregate secp256k1 key and dealerless
DKG each epoch; no immortal key and no rolling resharing.

CGGMP20 identifiable-abort work, if begun, is a clean-room permissive C23
research module with repository-owned constant-time bigint, Paillier, and ZK.
Do not copy or link GPL/OpenSSL implementations. It stays disabled for custody
until public vectors, differential checks, malicious-party tests, audits, and
WAN benchmarks pass. A failed gate names its blocker and leaves custody at
8-of-15; it never deploys experimental cryptography or lowers quorum.

## Ordered landing units

Each unit lands independently with focused adversarial tests, parallel
`build-only`, full link, `make lint`, uncached `test-parallel`, deterministic
projection rebuild checks where applicable, and no deployment.

| ID | Landing unit | Dependency | State / owner |
|---|---|---|---|
| S0 | Freeze this specification and coordination boundaries | existing ZCODE foundation | complete 2026-08-02, primary |
| S1 | Canonical science codecs, roots, cross-object validation, fixed benchmark/reproduction action identities | S0 | implemented and gate-verified 2026-08-02, primary |
| S2 | Dual-signed `contributor_binding.v1`, rotation/revocation/network replay gates | S0 | implemented 2026-08-02, remote coder; **hardened 2026-08-03** — validity windows + key derivation `0cd86d0f8`, science-object cross-validation H1–H3 `8909454b5`, three-signature rotation + delayed recovery + retired-key reuse ban H4 `b9e61cd48` (contributor_binding.v2) |
| S3 | CAS storage, rebuildable science projection, study/work/review/vote plan-commit services and commands | S1, S2 | **landed 2026-08-03 `bbe7f401f`**, main session — `contexts/commons/modules/vcs/src/zcode_science_index.c(+h)`, `cognition/services/src/zcode_science_service.c(+h)`, app/models science projection tables (schema bump 48→49 + validator pin 26→27), `tools/command/native_zcode_science_command.c`, `engine/composition/commands/zcode_science.def`, `tests/harness/src/test_zcode_science_store.c` |
| S4 | Closed benchmark/reproduction executors and environment/raw-sample receipts | S1, recipe-derived build graph | **landed 2026-08-03 `08c858042`**, main session — `contexts/commons/modules/vcs/src/hardware_profile.c(+h)`, `contexts/commons/modules/vcs/src/benchmark_method.c(+h)`, benchmark/reproduction executors + receipt codecs, `zcode.science.work.execute` (additive in `engine/composition/commands/zcode_science.def`), `tests/harness/src/test_zcode_benchmark_exec.c` |
| S5 | Deterministic discovery PageRank and golden graphs | S1, S3 | pure core implemented 2026-08-02, primary; **projection/command adapter landed 2026-08-03 `44afe2952`**, main session — `contexts/commons/modules/vcs/src/zcode_discovery_projection.c(+h)`, `zcode.science.discover` + `zcode.science.rank.snapshot` commands (additive def), `tests/harness/src/test_zcode_discovery_projection.c` — pure core files untouched |
| S2–S5 v1 acceptance proof | Two-node end-to-end acceptance: preregister → execute → reproduce → findings/review → discover → restart both nodes → rebuild from CAS hashes | S2–S5 | **landed 2026-08-03; root-only carrier upgraded by S7 on 2026-08-04**, main session — `tools/dev/science_acceptance.sh` (opt-in `make test-science-acceptance`, NOT in `make ci`), `tools/zcode_science_fixture.c`, `zcode.science.rebuild` operator leaf (def + handler + registry int-pin glue). Both nodes SIGTERM + cold boot, and `zcode.science.rebuild` remains byte-identical even after direct SQL wipe of the six projection tables; CAS object count is unchanged. **G1 CLOSED** — science objects ride the existing blob swarm and S7 removes the former out-of-band transport root: publish files signed generic POINTER/PROVIDER records, B begins with only the semantic science root, fetches through the existing verifier, re-derives the root and reaches `study.show found=true`. **G4 CLOSED** — findings command-leaf admission uses `zcode.science.findings.plan|commit`; the fixture composes the wire without touching CAS and review binds the CLI-admitted findings. Execution-context documents remain fixture-seeded content roots, not ledger objects. **G2 CLOSED** by the NEW_USER 4/hour bootstrap announce quota, deduped per-sync re-announce and supervisor clock-driven swarm (`net.zcode_swarm`, 1 s); the package leg is a hard positive regression gate. |
| S6 | Read-only Noise-bound DHT, persisted contacts, diagnostic dumper | S2 | **complete and gate-proven 2026-08-04 at `545e6b2b9`; not deployed** — deterministic iterative Kademlia with a 64-candidate pool, closest-16 active frontier, alpha=3 global query budget, eight fairly queued lookups, explicit candidate and replacement-probe states, stable/target/timeout termination, and a 30 s ceiling. Cold COLD/UNVERIFIED IDs bootstrap autonomously only through accepted chain-bound ZENDP endpoints, a fixed reachability index, deduped/backoff-bound connman requests, and fresh Noise/delegation authentication. Public `find.begin|poll|cancel` uses opaque lookup IDs plus separate owner tokens; `find` is its client-side wrapper. Replay request/response namespaces and retained service sessions are independent, local connection serials cannot alias peer claims, external chain/disk/DB/network work runs outside the DHT lock, and captured generations reject stale results. `make test-zcode-dht-acceptance` proves seven independent sparse-topology identities, broken-nearest-path recovery, eight simultaneous external callers, canonical persistence and zero-peer cold bootstrap. A deterministic 32-node model runs 12,000 transitions under continuous invariants, and the focused ASan+UBSan gate has zero suppressions. Focused DHT/Noise/transport/argv/connman/RPC, yardsale/store plus both store stress groups, the complete `make lint` gate set, the uncached suite (898 registered, 889 run, 0 cached, 9 policy-gated, 0 failed, 19 explicit self-skips), LTO, science acceptance, and both byte-reproducibility gates are green. Provider/root or generic space/service records and STORE/ack/replication remain S7 and were not added. |
| S7 | Generic provider/pointer/storage-ack discovery, local sovereignty, replication and root-only fetch adapters | S6 | **complete through S7.1 and gate-proven 2026-08-05; not deployed** — one exact 551-byte signed wire covers PROVIDER, POINTER and STORAGE_ACK, binding network genesis, namespace, semantic/transport roots, provider node ID, sequence/window and the chain-bound delegated signer. S7.1 derives a domain-separated DHT key and iterates signed record discovery over the existing k=16/alpha=3/64-candidate engine; `records.v1` is only a bounded cold cache. Opaque begin/poll/cancel capabilities, deterministic 64-result pagination, distinct-provider priority and separately preserved conflicts feed the synchronous provider/science wrappers. Closest-node publication persists key-free renewal intent, resumes under fresh delegation and stops on expiry, failed possession or local policy. A STORAGE_ACK can now be authored only after the package store verifies the root-bound manifest, every chunk, completeness and a local pin; STORE_RESULT is not an ACK, and byte loss/unpin/corruption prevents renewal. The single 1,024-rule policy engine decides DISCOVER/FETCH/STORE/INDEX/SERVE/FORWARD/EXECUTE by exact root, package, publisher ZID, service type or classification; advisory rules are opt-in and local rules never become global bans. Replication targets eight and says `durable` only for five live ACKs across three declared owner groups—never separate-operator proof. Provider-directed science fetch rechecks semantic/transport/publisher/service policy, uses accepted ZENDP plus connman and fresh Noise/delegation authentication, confines the swarm verifier to the selected root and falls back after absence, timeout, lies or corruption. Exact DHT and science daemon acceptances plus a separate 12-node hermetic sparse proof cover cold lookup, root-only transfer/rederivation, restart/rebuild, pagination, renewal, ACK loss, caps and one-node blocking. No space manifest, doorbell, board, mailbox, agent mission, arbitrary execution, consensus, wallet, deploy or second network stack was added. |
| S8 | Evidence checkpoints and ZANC anchors | S2, S7 | unclaimed |
| S9 | Seed credential, semantic novelty, maturity and challenge engine | S3, S4, S7, S8 | **fixture-only pure foundation landed 2026-08-07 `d623a3043`; active-chain S8 authority remains unclaimed** — exact dual-signed `c23.seed.v1`, novelty/source exclusions and seven-day height+MTP maturity/reorg validation; no credential is admitted to a live committee |
| S10 | Shadow evidence scoring, deterministic elections, rotation and concentration reporting | S9 | **fixture-only pure foundation landed 2026-08-07 `d623a3043`; rotation and authority remain unclaimed** — input-order-invariant evidence snapshots, 26-epoch decay, 10,000 cap, SHA3 rejection sampling without replacement, one ZID per seat and concentration metrics; four KAT elections explicitly confer no authority |
| S11 | Progressive P2SH transaction planning/signing in simulation only | S10 | owner-gated implementation |
| S12 | Owner-authorized native ZC23 genesis and one-epoch exposure | four green shadow epochs + Living Commons attribution/custody gates | owner-gated launch |
| S13 | Clean-room CGGMP research primitives/protocol and public artifacts | independent research gates | disabled research |
| S14 | 51-of-100 transition | all activation gates | owner-gated, blocked by design |

### Parallel ownership at publication

Primary lane owns for S1:

```text
contexts/commons/modules/vcs/include/vcs/zcode_science.h
contexts/commons/modules/vcs/src/zcode_science.c
contexts/commons/modules/vcs/include/vcs/build_action.h
contexts/commons/modules/vcs/src/build_action.c
tests/harness/src/test_zcode_science.c
tests/harness/src/test.c
tools/dev/test_group_catalog.def
cognition/controllers/include/controllers/agent_impact_rules.def
docs/work/ZCODE_SCIENTIFIC_METAVERSE.md
docs/work/ZCODE_DEVELOPMENT_NETWORK.md
docs/work/README.md
```

Primary lane additionally owns the S5 pure-core files:

```text
contexts/commons/modules/vcs/include/vcs/zcode_discovery_rank.h
contexts/commons/modules/vcs/src/zcode_discovery_rank.c
tests/harness/src/test_zcode_discovery_rank.c
```

The remote coder may claim S2 without touching those files:

```text
contexts/commons/modules/vcs/include/vcs/zcode_contributor_binding.h
contexts/commons/modules/vcs/src/zcode_contributor_binding.c
tests/harness/src/test_zcode_contributor.c
```

S2 should reuse the existing ZID Ed25519 and wallet/secp256k1 primitives,
produce exact body/full-wire KATs, pin the expected genesis and ZID during
verification, reject trailing/cross-network/replay/invalid-rotation wires,
and make no wallet/database/command changes. It may run the existing
`zcode_contributor` group; the primary lane will integrate any additional
central test registration after merge. Before starting another unit, update
this table on `main` to claim it and list an exact disjoint file scope.

### G1 carrier decision (science objects over the existing swarm and S7)

Gap G1 from the acceptance proof: science CAS objects have no node-to-node
path, so "reproduce on a second node" cannot work for real. Investigated
2026-08-03; the decision (smallest change, reuses the frozen wire):

- Science wires are 121–422 bytes — far under the 8 KiB blob ceiling.
  `contexts/commons/modules/vcs/src/blob_store.c` already moves arbitrary small CAS objects over
  the `zpkgswm` swarm as one-file/one-chunk content.v2 packages (the zendp/
  zdesc pattern); no new wire message, no new store.
- **Dual addressing**: the publisher mirrors each committed science wire
  into the package store via `vcs_blob_put` → a *blob root* (transport
  address). The *science root* (`SHA3(domain‖wire)`) stays the semantic
  address and is re-derived from the fetched bytes at admit time — never
  trusted from a claim. The swarm's manifest verification is untouched.
- **CLOSED 2026-08-03**, implemented exactly as recorded above and proven
  node-to-node: `zcode_science_publish()` / `zcode_science_admit()` in
  `cognition/services/src/zcode_science_carrier.c` (publish: CAS load → wire
  identify → root compare → `vcs_blob_put_to`; admit: `vcs_blob_get_from`
  → identify → idempotent `put_addressed` → full `zcode_science_rebuild`
  for the projection), kind tokens + `science_identify_wire()` covering
  all nine wire types (review/vote share len 219, split by magic),
  `zcode.science.publish` / `zcode.science.fetch` leaves (def + handlers
  mirroring `zcode.package.fetch`'s live-store-first / one-shot-store
  pattern), round-trip tests in `tests/harness/src/test_zcode_science_store.c`,
  and the acceptance script's G1 leg flipped to a positive proof:
  node A publishes its study pre-restart, node B schedules the fetch and
  — post-restart, with the hosting node's announce live — admits the
  blob, re-derives the identical science root and kind, and
  `study.show found=true` on B. `make test-science-acceptance` PASS.
- **Root-only discovery CLOSED 2026-08-04.** `zcode.science.publish` files a
  signed one-day science POINTER plus a two-hour PROVIDER through the generic
  S7 service. The acceptance proof starts B with only the science root; B
  resolves the transport root, fetches through the unchanged package verifier,
  and re-derives the semantic root from bytes before admission. No blob root
  crosses out of band. Records remain expiring, local evidence—not truth or
  possession proof—and a node's sovereignty policy may refuse any step.
- A science object >8 KiB (e.g. a large raw-sample manifest) needs a real
  multi-chunk package, not a blob — defer until such an object exists.

This is the complete prescribed order in §"Network overlay": local CAS,
connected advertisers, DHT pointer/provider evidence, then the exact existing
manifest/chunk verifier.

## Required adversarial coverage by phase

- Codecs/identity: malformed and trailing wires, wrong magic/version/network,
  domain confusion, signature replay, rotation/revocation, full-root lookup,
  and hash-prefix collisions.
- Science: hypothesis/result separation, raw-sample integrity, incompatible
  environments, null/negative results, contradictory reproductions, stale
  reviews, and retractions.
- Credentials: copied/renamed/delete-add farming, generated/vendor credit,
  compiler disagreement, dependency drift, license failure, and replay.
- DHT: poisoning, eclipse, churn, partitions, lying providers, corrupt
  chunks, gossip storms, quota exhaustion, route fallback, and restart rebuild.
- Ranking: golden graphs, input-order invariance, cycles, dangling nodes,
  rounding, seed changes, vote spam, and mechanical proof that ranking cannot
  affect evidence acceptance or money.
- Committee: deterministic sampling, contribution splitting, rotations,
  readiness loss, concentration, conflicting 51-quorums, 67-certificate
  behavior, and boundary reorgs.
- ZC23: forged/off-schedule or unattributed mints, attribution sum mismatch,
  capacity carry-forward, balance/patronage attempting to buy evidence or
  committee authority, baton theft/halt, duplicate payouts, concurrent
  commits, crash-before-relay, sharding, partial batches, and payout reorgs.
- CGGMP: malformed moduli/range proofs, malicious parties, identifiable abort,
  nonce reuse/rollback, complaints, 49 unavailable members, 51-collusion
  assumptions, coordinator failure, and cross-platform constant-time checks.
- Platform: Linux/macOS/Windows codec parity; execution receipts only after
  that platform's confinement escape tests pass.

## Non-negotiable rollout boundaries

- Public reproducible C23 is v1. Private data, embargoes, arbitrary stats
  scripts, GPUs, and network benchmarks are later versions.
- No live funds move automatically during development.
- No canonical node restart or deployment is part of these landing units.
- Direct Noise protects payloads, not IP/timing/volume metadata. Tor remains
  optional and does not unlink signed identity.
- Keys, addresses, signatures, and owner-group labels do not prove distinct
  humans, machines, or operators.
- ZC23 and committee activity are public transparent-ledger metadata; ZSLP
  has no private mode.
- Application anchoring and committee selection never modify ZClassic block
  or transaction validity.

References: the Tor distinction follows the public
[directory consensus specification](https://spec.torproject.org/dir-spec/computing-consensus.html);
discovery ranking follows the original
[PageRank paper](https://courses.cs.duke.edu/common/compsci092/papers/google/pagerank.pdf);
threshold research must account for the
[GG20 revisions](https://eprint.iacr.org/2020/540),
[Alpha-Rays attacks](https://eprint.iacr.org/2021/1621), and the
[NIST CGGMP preview/licensing record](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Fireblocks-c-PW01.pdf).
