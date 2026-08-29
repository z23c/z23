# ZC23 Family Commons — evidence economics

Status: additive pre-genesis protocol foundation. All v2 objects and commands
are simulation-only and not owner-approved. They create no token, transaction,
wallet authority, custody authority, consensus rule, deployment authority, or
claim on a live ZCL balance. Existing Living Commons v1 bytes and projections
retain their original meaning.

## Public contract

The CAS/DHT transport is permissionless. The official `family-c23.v1` view is
not: before official clients index, advertise, replicate, serve, forward,
preview, or execute an object, that exact object and dependency closure need a
current Family Commons admission. New objects begin `PENDING`. Only a current
`SELF_SCREENED` or quorum-pass admission with complete coverage is visible.
Incomplete, opaque, stale, reorged, disputed, or reversed evidence immediately
fails closed.

`family-c23.v1` is an immutable root. A new policy is a new named profile and
root; no owner key can rewrite v1. The closed exclusions are explicit sexual
material, graphic gore, targeted hate, self-harm encouragement, harmful illegal
activity, gratuitous strong profanity, and software whose demonstrated primary
purpose is abuse. Neutral scientific, medical, historical, cybersecurity, and
dual-use education can pass as `CONTEXTUAL_SCIENCE`. Family admission says
nothing about factual accuracy, software quality, or security.

The canonical frozen policy root in this implementation is:

```text
family-c23.v1 = 460d650c5be714f27dde287c368eafb781467026a1c06a8215fbe17dc610ea86
```

The policy initializer domain-hashes the exact profile name and policy text;
the dedicated KAT rejects any drift.

## Package objects

The v2 foundation defines separate root domains for:

- `workspace_manifest.v1`: up to 4,096 canonically sorted module releases,
  source assignments, predecessors, sequences, typed-asset roots, and a sorted
  acyclic dependency graph. Duplicate semantic fingerprints are rejected.
- `typed_asset_manifest.v1`: closed kind, format root, content root, byte
  count, attribution, collection and signer. Only CC0-1.0 and CC-BY-4.0 are
  representable; BY requires attribution. Assets have no creation-award class.
- `module_passport.v1`: independent API, recipe, toolchain, tests, licence,
  semantic fingerprint, workspace lineage, source assignment, quality roots,
  signer and signature. Every authority root is mandatory.
- `quality_profile.v1`: the universal required-check mask plus an optional
  field-specific additive mask/rules root. A field profile cannot remove any
  universal check. Math, cryptography, biology, chemistry, physics, astronomy,
  networking, video, and games are closed field values.
- `mission.v1`: signed publisher, subject-tag, goal, optional patron-task and
  chain-time coordinates. Tags and missions are not economics inputs.
- `contribution_split.v1`: up to 64 sorted recipient bindings, exact atom
  amounts, and every participant signature. Checked addition must equal the
  frozen claim award exactly.
- `source_assignment.v1`: a fixed-size signed canonical wire distinguishing
  human, AI, canonical-import, mechanical-generation and vendor sources.
  Imports and vendor material must preserve upstream source and author roots;
  AI source counts normally, while mechanical and vendor source never count.
- `c23_corpus_rules.v1`: the immutable metric constants, including the `.c`,
  `.h`, `.def` input set, 80% overlap threshold, 4,096-entry shard/checkpoint
  caps, 256-item pages/batches, 50M/100M milestones, and 5-ACK/3-group durable
  hosting predicate. Its canonical root is KAT-bound.
- `c23_corpus_shard.v1`: up to 4,096 strictly lineage-sorted entries binding
  releases, Passports, proofs, source assignments, Family admissions and
  possession evidence. Counted production/test LOC and diagnostic physical
  lines/semantic units remain separate. Excluded entries carry a closed reason
  and contribute zero counted LOC. Stable cursors bind the exact shard root and
  cap every page at 256 entries.
- `c23_corpus_checkpoint.v1`: a signed sequence of at most 4,096 ordered,
  non-overlapping shard ranges with exact aggregate counts, census/policy/
  moderation roots, cutoff coordinates and replication evidence. A 50M or
  100M milestone requires the same amount to be durably hosted, and successor
  verification carries the verified 50M root through the chain before a 100M
  milestone can pass.
- `productivity_receipt.v1`: a signed fixed-size basis binding PROVEN work,
  human acceptance, signed release, independent Family admission, retrievable
  package and checkpoint roots. Structural validity alone is not shareability:
  the caller must provide a current external proof-chain verifier.
- `commons_admission.v1`: a signed fixed-size decision binding the exact
  content and dependency-closure roots, Family policy, moderation set, panel,
  evidence, chain time, expiry and predecessor. Pass states must match their
  roster tier and require complete content and closure coverage.

The CAS-derived `family_admission_projection` verifies every admission root
and signature, reconstructs each predecessor chain, selects the highest exact
sequence, and fails conflicts, missing ancestry, stale tips, expiry and roster
ratchets closed. Its entries are sorted by `(content_root, closure_root)` and
its immutable root is published behind an atomic process generation.

The composite access seam first calls the existing local-sovereignty policy,
then accepts exactly one closed intent: admitted `FAMILY_PUBLIC`, byte/root/
provider/expiry-bound `MODERATION_INTAKE`, operator-authorized redacted
`EXACT_ROOT_DIAGNOSTIC`, or a bounded closed-kind `PROTOCOL_CONTROL` frame.
It is inactive by default and no consumer is wired yet. Activation and every
new projection increment the admission generation; queued work binds that
generation and an immediate recheck observes a later restriction.

The current KAT roots for the canonical fixtures are:

```text
c23_corpus_rules.v1          ae0c059c8c925464a7d9376b17687b207027833f5337dc49944bcd1b55d3be23
c23_corpus_shard.v1          75b6c0fc6e6affe282a9ae3baeeb6424c36d95add766fd29ad2f0a42c872dcd7
c23_corpus_checkpoint.v1     7528b88dc8793b2ac150cb2de15e0930ea72883d131512b1a3534fa5fc655dca
productivity_receipt.v1      311f144c37b719d74cea628b9b6613262d1c7f8e838683ac1f54342236e7422a
commons_admission.v1         6acb9bf015d3aec35bd5db76e9a14e7713ecde291a29456593b0d2eecb1c196f
family_admission_projection  69cbb7b4cf90120d01d09074bc72ce61fdcb06f8409a46181fa9c7c5683fde4f
```

These objects compose the existing package CAS and its 64 MiB package bound;
they do not introduce another package store or database authority.

## Creation economics

`zc23_policy_candidate.v2` is valid only with both `SIMULATION_ONLY` and
`NOT_OWNER_APPROVED`, the exact 8,064-block and 604,800-second maturity rules,
the Family policy root, qualification/backlog roots, and this award schedule:

| Event | Atoms | ZC23 |
|---|---:|---:|
| Original module or first canonical C23 import | 100,000,000 | 1.00000000 |
| Accepted established-defect repair | 50,000,000 | 0.50000000 |
| Independently reproduced security finding | 50,000,000 | 0.50000000 |
| Independent later test/conformance suite | 25,000,000 | 0.25000000 |
| Independent reproduction | 25,000,000 | 0.25000000 |
| Reproduced performance-frontier improvement | 25,000,000 | 0.25000000 |
| New compatibility proof | 25,000,000 | 0.25000000 |
| Unique preservation milestone | 12,500,000 | 0.12500000 |

Assets, ordinary storage, downloads, reviews, moderation, agreement, blocking,
model expense, challenge volume, popularity, stake and patronage never mint.
Bandwidth reciprocity remains local nontransferable ZCODE Credit.

`creation_claim.v2` is structurally separate from epoch selection. A claim is
eligible only when independently matured, current under moderation, and free of
reorg, retraction, duplicate-semantic and moderation-reversal flags.
`epoch_creation_set.v2` selection is input-order invariant:

1. sort each category by `(maturity_height, maturity_mtp, claim_root)`;
2. rotate the first category from the previous epoch root and visit cyclically;
3. select whole claims only;
4. cap each recipient and workspace lineage at
   `min(capacity, max(1 ZC23, floor(capacity/100)))`;
5. defer claims that cross a cap or remaining capacity;
6. exclude invalidated and duplicate-semantic claims; and
7. expire unused capacity.

The result root commits the cutoff, prior epoch, capacity, selected claim order,
awarded atoms, and expired atoms. No MINT transaction is built.

## Decentralized moderation

Classification has two closed axes:

```text
audience = GENERAL | CONTEXTUAL_SCIENCE | MATURE | EXPLICIT | UNKNOWN
behavior = BENIGN | DUAL_USE | MALICIOUS | UNKNOWN
```

Only complete `GENERAL`/`CONTEXTUAL_SCIENCE` plus `BENIGN`/`DUAL_USE` coverage
votes PASS. Coverage must account exactly for metadata, documentation,
comments, strings, examples, media, typed assets, the dependency closure,
object count and bytes. Unsupported, encrypted, opaque, missing, truncated,
mutable, over-budget, or partial extraction votes `UNKNOWN`.

Receipts contain only roots, coverage coordinates, closed labels, reason-code
bits, chain-time coordinates and a signature. They have no fields for source
excerpts, raw prompts/responses, chain-of-thought, credentials, endpoints,
addresses, IPs, or datadir paths.

Panel selection is bound to a future block hash, excludes publisher-related
services, and admits one vote per declared operator group. Within a duplicate
group, the future-hash-minimum ZID is deterministic. Selection is without
replacement, maximizes distinct model families for the first three seats when
possible, and reports actual operator/model counts. Token balance, Score,
stake, popularity, patronage and model vendor are not selection inputs.

| Independent operator groups | Seats and quorum | State tier |
|---:|---:|---|
| 0 | founding self-screen 1/1 | `SELF_SCREENED` |
| 1 | 1/1 | `BOOTSTRAP_PASS` |
| 2 | 2/2 | `PEERED_PASS` |
| 3–4 | all, `ceil(2N/3)` | `EMERGING_PASS` |
| 5–6 | all, `ceil(2N/3)` | `DIVERSE_PASS` |
| 7+ | future-hash sample 7, 5/7 | `RESILIENT_PASS` |

A resilient appeal needs 11 available independent groups and 8/11; otherwise
it remains pending. PASS quorum admits, BLOCK quorum restricts, a mixed
non-quorum is `CONFLICTED`, and all missing/unknown is `UNKNOWN`.
`SELF_SCREENED` is visibly labelled and cannot qualify for issuance. At epoch
selection a claim needs challenge maturity and the highest independently
attainable current tier.

## Typed surfaces and present boundary

The shipped non-creating v2 readers are:

```text
zcode commons economics status
zcode commons corpus status
zcode commons impact status
zcode commons impact share
zcode moderation status
zcode moderation policy list
zcode moderation policy show --input='{"profile":"family-c23.v1"}'
```

The package/workspace plan-commit, asynchronous classification, durable panel,
challenge, appeal, REST resources and cross-surface Family enforcement remain
later additive slices. The admission projection and access-decision seam exist
only as an inactive library boundary; no command claims a package is admitted
and existing v1 package behavior is not reinterpreted. This is a deliberate
fail-closed delivery boundary, not a live moderation service. The policy
readers therefore report
`policy_selected_as_default:true`, `enforcement_complete:false`, and
`effective_default:false`; `default_public_view` remains false until the
cross-surface gate passes.

The corpus reader currently reports a zero verified lower bound and names the
missing checkpoint projection. Impact readers similarly fail closed:
`shareable:false` contains no slogan until the complete signed proof chain is
available, and neither reader posts externally.

## Mechanical evidence

`test_zcode_commons` freezes policy, asset, workspace and receipt KAT roots
and covers award drift, profile weakening, excluded licences, missing tests,
dependency cycles, semantic duplication, split arithmetic, dual maturity,
caps, backlog/expiry, input-order invariance, reorg exclusion, incomplete
coverage, contextual science, malicious labels, one-operator grouping,
future-hash selection, diversity, 1/2/3/5/7/15-service ratchets, 5/7 and 8/11
quorums, stale visibility and the self-screen issuance prohibition.

`test_zcode_family_admission` freezes the admission/projection KATs and covers
signed wire tamper, input-order invariance, exact content/closure lookup,
missing ancestry, restriction reversal, stale roster ratchets, local-policy
precedence, closed intake/diagnostic/control intents, inactive-default
compatibility and a queued-action generation reversal before execution.

Consensus parity remains untouched: no file under `core/` or the sealed
block-connection ordering layer is changed by this protocol.
