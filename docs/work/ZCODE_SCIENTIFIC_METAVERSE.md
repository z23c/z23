# ZCODE scientific metaverse and proof-of-contribution network

> User-facing entry point: [`METAVERSE.md`](../commons/METAVERSE.md); acceptance
> bar: [`METAVERSE_MVP.md`](../commons/METAVERSE_MVP.md). This is a scoped protocol
> specification, not a current-work queue. Current ordering lives only in
> [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

Status: owner-directed implementation plan. It extends the
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

Implementation
(`contexts/commons/modules/vcs/include/vcs/zcode_contributor_binding.h`,
`contexts/commons/modules/vcs/src/zcode_contributor_binding.c`, tests in the
`zcode_contributor` group): the 184-byte body / 312-byte full wire is
domain-separated (`zcl.zcode.contributor_binding.v1` for the dual-signed body
root; `zcl.zcode.contributor_binding.root.v1` for the full-wire root a
successor's predecessor commits). The secp256k1 signature is 64-byte r||s
normalized to low-S, so sealing is byte-deterministic; the ZCL address hash
is validated as `hash160(zcl_pubkey)` at the codec layer. REVOKE carries the
key it retires (staying standalone dual-verifiable) and is terminal:
`vcs_zcode_contributor_binding_validate_successor()` rejects any successor of
a revoked binding, replay/skip sequencing, cross-network/cross-ZID links,
same-key rotations, new-key revocations, tampered predecessors, and
non-increasing `issued_unix` (`ERR_TIME_ORDER`). `validate_at()` rejects use
before `issued_unix` (`ERR_NOT_YET_VALID`); `seal()` re-derives the Ed25519
public key from the supplied ZID secret and rejects a mismatch. S3/S6 consume
only `root()` + `verify()`/`validate_successor()`; no wallet/database/command
surfaces are touched. Golden vectors are pinned in
`tests/harness/src/test_zcode_contributor.c` (`ZCB_KAT_*`).

### `contributor_binding.v2`

Three-signature rotation and delayed recovery: 384-byte wire =
192-byte body (v1 fields + `activation_unix`) + ZID + current-ZCL + new-ZCL
signature slots under `zcl.zcode.contributor_binding.v2` /
`.root.v2` domains. ACTIVE signs both ZCL slots with the initial key; ROTATE
requires ZID + OLD ZCL + NEW ZCL; REVOKE keeps and signs with the retiring
key and zeroes the new slot; RECOVER (op 4) zeroes the current slot (old key
presumed lost), signs the new slot, and activates only at
`activation_unix >= issued_unix + 604800` — a separate delayed path, never a
fast rotation. `vcs_zcode_contributor_binding_validate_chain_v2()` adds the
retired-key reuse ban across the whole chain. v1 wire/KATs are frozen; v2
KATs (`ZCB2_KAT_*`) are deterministic.

Science-object validation rules:
findings/review time order follows this spec (findings form
first; `review->created_unix` may be LATER than the findings' creation —
rejected only when earlier); "may submit now"
(`vcs_zcode_study_spec_accepts_submission_at()`) is split from "evidence was
valid when created": cross-object validators do not consult the study
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

## Landing units

Each unit lands independently with focused adversarial tests, parallel
`build-only`, full link, `make lint`, uncached `test-parallel`, deterministic
projection rebuild checks where applicable, and no deployment. Implemented
units are not deployed.

| ID | Landing unit | Dependency | State |
|---|---|---|---|
| S0 | Freeze this specification and coordination boundaries | existing ZCODE foundation | complete |
| S1 | Canonical science codecs, roots, cross-object validation, fixed benchmark/reproduction action identities | S0 | implemented, gate-verified |
| S2 | Dual-signed `contributor_binding.v1` (and `.v2` rotation, delayed recovery, retired-key reuse ban), network replay gates | S0 | implemented |
| S3 | CAS storage, rebuildable science projection, study/work/review/vote plan-commit services and commands | S1, S2 | implemented: `contexts/commons/modules/vcs/src/zcode_science_index.c`, `cognition/services/src/zcode_science_service.c`, science projection tables, `tools/command/native_zcode_science_command.c`, `engine/composition/commands/zcode_science.def`, `tests/harness/src/test_zcode_science_store.c` |
| S4 | Closed benchmark/reproduction executors and environment/raw-sample receipts | S1, recipe-derived build graph | implemented: `hardware_profile.c`, `benchmark_method.c`, `zcode.science.work.execute`, `tests/harness/src/test_zcode_benchmark_exec.c` |
| S5 | Deterministic discovery PageRank and golden graphs | S1, S3 | implemented: pure core plus `zcode_discovery_projection.c`, `zcode.science.discover` and `zcode.science.rank.snapshot` |
| S2–S5 v1 acceptance | Two-node end-to-end: preregister, execute, reproduce, findings/review, discover, restart both nodes, rebuild from CAS hashes | S2–S5 | implemented: `tools/dev/science_acceptance.sh` (opt-in `make test-science-acceptance`, NOT in `make ci`), `tools/zcode_science_fixture.c`, `zcode.science.rebuild`. Both nodes restart cold and `zcode.science.rebuild` stays byte-identical even after a direct SQL wipe of the six projection tables. Science objects ride the existing blob swarm and the S7 root-only carrier (see "Science object carrier"); findings admission uses `zcode.science.findings.plan|commit`; execution-context documents remain fixture-seeded content roots, not ledger objects; the swarm announce is bounded by the NEW_USER 4/hour quota and the supervised `net.zcode_swarm` clock, with the package leg a hard positive regression gate |
| S6 | Read-only Noise-bound DHT, persisted contacts, diagnostic dumper | S2 | implemented, not deployed: deterministic iterative Kademlia (64-candidate pool, closest-16 active frontier, alpha=3 global query budget, eight fairly queued lookups, 30 s ceiling). Cold COLD/UNVERIFIED IDs bootstrap only through accepted chain-bound ZENDP endpoints and fresh Noise/delegation authentication. Public `find.begin|poll|cancel` uses opaque lookup IDs plus separate owner tokens. External chain/disk/DB/network work runs outside the DHT lock. Gates: `make test-zcode-dht-acceptance` (seven sparse-topology identities, broken-nearest-path recovery, eight simultaneous callers, zero-peer cold bootstrap), a deterministic 32-node model under continuous invariants, and a focused ASan+UBSan gate with zero suppressions |
| S7 | Generic provider/pointer/storage-ack discovery, local sovereignty, replication and root-only fetch adapters | S6 | implemented, not deployed: one 551-byte signed wire covers PROVIDER, POINTER and STORAGE_ACK (network genesis, namespace, semantic/transport roots, provider node ID, sequence/window, chain-bound delegated signer). Signed record discovery runs over the S6 engine; `records.v1` is only a bounded cold cache. A STORAGE_ACK is authored only after the package store verifies the root-bound manifest, every chunk, completeness and a local pin; STORE_RESULT is not an ACK. The single 1,024-rule policy engine decides DISCOVER/FETCH/STORE/INDEX/SERVE/FORWARD/EXECUTE by exact root, package, publisher ZID, service type or classification; local rules never become global bans. Replication targets eight and says `durable` only for five live ACKs across three declared owner groups, never separate-operator proof. Provider-directed science fetch rechecks policy, authenticates with fresh Noise/delegation, confines the swarm verifier to the selected root and falls back after absence, timeout, lies or corruption. No space manifest, doorbell, board, mailbox, agent mission, arbitrary execution, consensus, wallet, deploy or second network stack exists |
| S8 | Evidence checkpoints and ZANC anchors | S2, S7 | unclaimed |
| S9 | Seed credential, semantic novelty, maturity and challenge engine | S3, S4, S7, S8 | fixture-only pure foundation: exact dual-signed `c23.seed.v1`, novelty/source exclusions and seven-day height+MTP maturity/reorg validation; no credential is admitted to a live committee; active-chain S8 authority unclaimed |
| S10 | Shadow evidence scoring, deterministic elections, rotation and concentration reporting | S9 | fixture-only pure foundation: input-order-invariant evidence snapshots, 26-epoch decay, 10,000 cap, SHA3 rejection sampling without replacement, one ZID per seat and concentration metrics; four KAT elections confer no authority; rotation and authority unclaimed |
| S11 | Progressive P2SH transaction planning/signing in simulation only | S10 | owner-gated implementation |
| S12 | Owner-authorized native ZC23 genesis and one-epoch exposure | four green shadow epochs + Living Commons attribution/custody gates | owner-gated launch |
| S13 | Clean-room CGGMP research primitives/protocol and public artifacts | independent research gates | disabled research |
| S14 | 51-of-100 transition | all activation gates | owner-gated, blocked by design |

Before starting a unit, update this table on `main` to claim it and list an
exact disjoint file scope.

### Science object carrier

Science CAS objects move node to node over the existing `zpkgswm` swarm, with no
new wire message and no new store. Science wires are 121 to 422 bytes, far under
the 8 KiB blob ceiling, so `contexts/commons/modules/vcs/src/blob_store.c` moves
them as one-file/one-chunk content.v2 packages.

- **Dual addressing.** The publisher mirrors each committed science wire into
  the package store via `vcs_blob_put`, giving a *blob root* (transport
  address). The *science root* (`SHA3(domain||wire)`) stays the semantic
  address and is re-derived from the fetched bytes at admit time, never
  trusted from a claim. The swarm's manifest verification is untouched.
- **Publish and admit.** `zcode_science_publish()` / `zcode_science_admit()` in
  `cognition/services/src/zcode_science_carrier.c` (publish: CAS load, wire
  identify, root compare, `vcs_blob_put_to`; admit: `vcs_blob_get_from`,
  identify, idempotent `put_addressed`, full `zcode_science_rebuild`).
  `science_identify_wire()` covers all nine wire types (review/vote share
  len 219, split by magic). The `zcode.science.publish` / `zcode.science.fetch`
  leaves mirror `zcode.package.fetch`.
- **Root-only discovery.** `zcode.science.publish` files a signed one-day
  science POINTER plus a two-hour PROVIDER through the generic S7 service. A
  second node started with only the science root resolves the transport root,
  fetches through the unchanged package verifier, and re-derives the semantic
  root from bytes before admission; no blob root crosses out of band. Records
  are expiring, local evidence, not truth or possession proof, and a node's
  sovereignty policy may refuse any step. `make test-science-acceptance`
  proves it.
- A science object over 8 KiB (for example a large raw-sample manifest) needs a
  real multi-chunk package, not a blob; deferred until such an object exists.

This is the prescribed order in "Network overlay": local CAS, connected
advertisers, DHT pointer/provider evidence, then the exact existing
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
