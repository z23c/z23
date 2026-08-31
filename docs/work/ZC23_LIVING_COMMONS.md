# ZC23 Living Commons

> Additive v2 evidence economics and the default decentralized Family Commons
> profile are specified in
> [`ZC23_FAMILY_COMMONS.md`](./ZC23_FAMILY_COMMONS.md). V2 never
> reinterprets the v1 authorities frozen in this document.

> User-facing entry point: [`../METAVERSE.md`](../METAVERSE.md); acceptance
> bar: [`../METAVERSE_MVP.md`](../METAVERSE_MVP.md). This is a scoped protocol
> and policy specification, not a current-work queue. Current ordering lives
> only in [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

Status: owner-directed specification, updated 2026-08-07. This document freezes the
safe pre-genesis policy and implementation order for creation-backed ZC23
issuance. It authorizes specifications, codecs, validation, rebuildable
projections, read-only views, and simulations only. It does **not** authorize a
live token, GENESIS, MINT, SEND, payout, wallet operation, custody movement,
deployment, service restart, canonical-datadir mutation, or consensus change.

## Purpose and public terminology

The project mission is:

> **Z23 is a metaverse where people and AI create real things together,
> and nobody owns the world they build in.**

Here, "metaverse" means the shared, permissionless creation environment formed
by the ZCODE package library, development network, evidence graph, and public
discovery surfaces. "Real things" means exact retrievable source, executable
C23 packages, tests, reproductions, reviews, repairs, compatibility work, and
preservation records—not engagement counters or a claim that software alone
can judge art.

"Nobody owns the world" does not erase authorship or a contributor's legal
rights. It means that no operator, AI provider, patron, token holder, committee,
package index, or website owns the shared protocol space or gains title to
another contributor's work. Contributors publish under explicit permissive
licences; everyone retains the freedoms those licences grant. A human and an
AI-assisted contributor use the same factual evidence rules. Neither identity
kind receives special truth, scoring, or issuance authority.

ZC23 is planned as a scarce, auditable patronage asset associated with a
growing public commons of executable C23 work. It may later be used as optional
commissioning capital for new work and continuity. Its mechanical promise is:

> Every policy-valid atomic unit of ZC23 exists because the public C23 commons
> grew, was tested, was independently reproduced, or was preserved.

Public names are fixed before token genesis:

| Name | Meaning |
|---|---|
| **ZCODE** | The protocol, network, package library, and development system |
| **ZC23** | The planned transferable ZSLP token ticker |
| **ZCODE Score** | Nontransferable, evidence-derived contribution score |
| **ZCODE Credit** | Local, nontransferable reciprocity/quota credit |
| **ZCODE Badges** | Identity-bound achievements |

Existing `zcl.zcode.*` domains, command roots, and internal ZCODE identifiers
remain. This is a public-language correction, not a destructive rename.
Compatibility surfaces such as `zcode reward score` remain explicitly legacy
and non-credit where their schemas already say so.

## One creation API

The native command tree is the common interface for people, AI agents, local
tools, and presentation adapters. It must make the complete creation loop easy
to discover without granting any adapter hidden authority:

```text
discover -> fetch/inspect -> task -> candidate -> prove/reproduce/review
         -> accept -> publish -> attribute -> preserve or commission again
```

Every shipped leaf is discoverable through `discover help`, searchable through
`discover search <query>`, and has an exact input contract through
`discover schema <leaf>`. Read operations report whether they are complete,
partial, or unknown and give the next safe diagnostic. They remain non-creating
on an absent workspace or datadir. Mutations use explicit plan/commit where
money, publication, installation, or other durable authority is involved.

The implemented foundation already exposes package search/show/recipe/verify,
package fetch and confined add, development create/use/improve/evidence/accept,
lane and task inspection, offline release preparation/sealing, signed ZCODE
Score receipts, read-only `zcode commons` verification, scratch-only shadow
attribution/epoch planning, simulation-only patronage offers/funding, and
continuity-policy inspection. Live settlement, refund, custody and issuance
remain planned and fail closed. No documentation or adapter may label a
planned leaf ready, a CAS object funded, a local result globally trusted, or a
simulation as a live transfer.

All adapters consume these same objects and services. A website or onion view
is a projection, never a second package catalog, evidence authority, identity
system, or database of truth. Public discovery, retrieval, inspection, build,
reproduction, and verification remain free and cannot require ZC23.

ZC23 conveys no copyright, title, exclusive licence, royalty, dividend, claim
against a contributor, promise of appreciation, or protocol judgment of
artistic merit. Public packages remain permissively licensed, discoverable,
retrievable, inspectable, buildable, reproducible, verifiable, and usable
without holding or paying ZC23. Tokens are never an access key.

## Cultural meaning and mechanical truth

Humans may describe the public collection as a living commons of executable
C23 art. Protocol objects verify objective facts only: authorship, exact
source, lineage, licensing, tests, defect reproduction, fixed-action results,
independent reproduction, review authorship, compatibility, preservation,
challenge maturity, and amount arithmetic.

No canonical wire, database authority, score rule, committee rule, or token
policy may contain or infer subjective fields such as `artistic_value`,
`beauty`, `importance`, `canonical_truth`, or `investment_value`. PageRank,
curation votes, popularity, balance, price, transfer volume, patronage volume,
market activity, storage volume, and model claims are discovery or cultural
signals only. They cannot establish correctness, safety, scientific truth,
proof acceptance, contributor authority, committee weight, score, badges, or
issuance.

## Immutable ZC23 Living Commons covenant

The planned ZC23 genesis policy root commits the following covenant verbatim in
meaning. An incompatible future policy requires a different token ID and
explicit user opt-in; no client may reinterpret the original lineage.

1. **NO CREATION, NO MINT.** An epoch may mint only the quantity assigned to
   challenge-matured, policy-eligible creation-attribution records, up to that
   epoch's cap. Unused capacity expires. It is never minted, carried forward,
   redirected to a treasury, or awarded for participation alone.
2. **COMPLETE SUPPLY ATTRIBUTION.** Every policy-valid minted atomic unit is
   accounted for by exactly one matured creation-attribution entry. The sum of
   an epoch's entries equals its actual MINT quantity exactly. Any
   unattributed unit makes the policy verdict invalid or unknown and can never
   be silently accepted. The initial genesis unit is subject to the same rule
   and must bind a matured founding creation attribution.
3. **THE COMMONS REMAINS FREE.** Holding ZC23 is never required to discover,
   fetch, inspect, build, reproduce, verify, or use public permissively
   licensed packages. Optional paid compute, commissions, maintenance
   contracts, and patronage may exist above the free foundation.
4. **MONEY NEVER BECOMES TRUTH.** ZC23 balance, transfer volume, patronage
   volume, marketplace activity, PageRank, popularity, or storage volume can
   never establish correctness, scientific truth, proof acceptance,
   contributor score, committee weight, or package safety.
5. **MONEY NEVER BUYS REPUTATION.** Transferred ZC23 creates no ZCODE Score,
   committee eligibility, ranking, badge, proof weight, or contributor
   identity. One contribution root may credit one contributor identity once.
6. **PATRONAGE CONTROLS ONLY THE PATRON'S FUNDS.** A holder may direct or lock
   their own ZC23 behind a task or package-continuity policy. That grants no
   control over protocol validity, another person's funds, committee
   selection, local-node policy, or the definition of acceptable evidence.
7. **NO IMPLIED PROPERTY RIGHT.** ZC23 conveys no copyright, exclusive
   licence, package title, release ownership, royalty, dividend, or claim
   against a contributor. A patronage receipt records support, not ownership.
8. **INCOMPATIBLE POLICY MEANS A NEW ASSET.** The genesis policy root remains
   immutable. A future incompatible issuance policy requires a new token ID
   and explicit user opt-in. Clients never reinterpret the original ZC23
   lineage.
9. **ZCLASSIC CONSENSUS REMAINS UNCHANGED.** ZC23 is an application overlay.
   It changes no ZClassic block validity, transaction validity, mining,
   Equihash parameters, activation rule, or proof-of-work consensus.

## Denomination and exact supply arithmetic

The planned denomination is eight decimal places:

```text
decimals                  = 8
atoms_per_ZC23             = 100000000
initial_supply_atoms       = 1 * 100000000
epochs_per_era             = 208
epoch_cap_atoms(era)       = floor(50000 / 2^era) * 100000000
maximum_policy_supply      = 20,798,753.00000000 ZC23
maximum_policy_atoms       = 2,079,875,300,000,000
```

The multiplication occurs after the whole-token floor. There is no
fractional-era tail. Eras stop after the whole-token epoch cap becomes zero.
Summing 208 epochs for whole-token caps `50000, 25000, ... , 1`, plus the one
genesis unit, yields exactly 20,798,753 ZC23. The maximum atomic supply fits in
both signed and unsigned 64-bit arithmetic, but implementations must still use
checked `uint64_t` add and multiply and zero their output on overflow.

The curve is a ceiling, not a promise to issue. For every epoch:

```text
actual_mint_atoms <= epoch_cap_atoms
unissued_atoms == epoch_cap_atoms - actual_mint_atoms
sum(creation_attribution.award_atoms) == actual_mint_atoms
```

Unissued atoms disappear from policy capacity at epoch close. They never enter
a carry pool, treasury, matching fund, later era, patronage budget, or passive
yield schedule.

## Existing owners and trust boundaries

No second truth system is permitted. The implementation reuses:

- package manifests, signed release envelopes, dependency locks, recipes,
  capsules, and the existing ZCODE CAS for public code and evidence bytes;
- `task.v1`, `candidate.v1`, `proof_policy.v1`, `proof_set.v1`,
  `work_receipt.v1`, and `lane_receipt.v1` for contribution evidence;
- the existing ZCODE Score receipt for objective nontransferable units;
- `contributor_binding` plus ZID/ZCL identity binding;
- ZANC/evidence checkpoints for active-chain anchoring and reorg handling;
- generic ZSLP for token transaction validity and the existing wallet
  plan/commit transaction machinery for any future owner-authorized plan;
- `zpkgswm`, signed provider records, DHT discovery, and local sovereignty
  policy for object distribution;
- the existing metaverse `zcode_package` property; and
- ActiveRecord tables only as bounded, wipe-rebuildable indexes.

ZSLP validity and ZC23 policy validity remain separate verdicts. A transaction
can be generically ZSLP-valid while violating the immutable ZC23 schedule or
attribution covenant. Such a lineage is `ZC23_POLICY_INVALID` or `UNKNOWN`,
never silently accepted. Off-schedule minting, baton theft, missing
attributions, or a contradictory active-chain anchor halts the policy lineage;
clients do not invent replacement authority.

## Creation attribution

The first new authority object is planned under the domain
`zcl.zcode.creation_attribution.v1\0`. It is factual, canonical, fixed-width or
strictly bounded, exact-length, little-endian, and domain-separated with a
full SHA3-256 identity. Parsing and validation zero output on failure.

An attribution binds the network genesis, immutable ZC23 policy root, epoch,
contributor-binding root, exact task and candidate, proof policy and proof set,
PROVEN lane receipt, ZCODE Score receipt, package and release, licence text or
licence-evidence root, a closed contribution category or mask, exact award in
atoms, opening anchor, maturity height and median-time-past, optional
predecessor attribution or release-lineage root, and creation time.

The v1 wire admits only mechanically demonstrated public source, born-red
repair, independent reproduction, compatibility maintenance, and preservation.
`SECURITY_FIX` is retained as a display label but has exactly the born-red
evidence and award class: v1 binds no structured security-finding authority,
so selecting that label cannot increase issuance. Benchmark and structured
review/negative-finding categories are not admitted by v1; existing science
receipts are useful evidence, but this wire has no independent field that can
bind them without overloading lineage. Adding them requires a separately
reviewed versioned authority, not reinterpretation of v1. Ordinary upload,
bandwidth, signing, voting, DHT publication, balance, payment, line count,
generated volume, formatting, renaming, version bumps, no-op rebuilds,
delete-and-readd novelty, copied/lightly transformed work, circular review,
or self-funded patronage is not a creation event.

Cross-object validation independently reloads and rederives every referenced
object. It rejects a task/candidate/policy/proof/lane/score mismatch; a lane
below PROVEN; invalid, immature, future, stale, or reorged evidence; absent or
non-permissive licensing; duplicate contribution roots; contributor-binding
mismatch; zero or overflowing awards; epoch mismatch; package/release/recipe/
lock substitution; contradictory source lineage; and any caller assertion not
proved by canonical bytes. One contribution root credits one contributor once.

Historical authorship and current payment authority are deliberately separate.
The contributor binding referenced by an attribution is verified at the
candidate's `created_unix`, when the authorship event occurred. Later key
rotation, binding expiry, or revocation does not erase valid history. Any
future payout path must independently re-check current authority at the time of
payment; historical validity never authorizes current funds.

`PUBLIC_SOURCE` lineage is authority, not a hint. `NONE` requires both an empty
lineage root and a signed root release with no parent. `RELEASE` reloads the
signed direct parent and proves exact parent root, package name, chain,
publisher key, and next publisher sequence. `PREDECESSOR_ATTRIBUTION` reloads
and recursively re-verifies the complete prior attribution, then proves that
its signed release is the direct parent. Recursion is bounded and arbitrary,
missing, substituted, cross-policy, future, or contradictory roots fail
closed.

Continuity creation is neutral with respect to patronage. The
`zcl.zcode.creation_event_key.v1\0` identity derives from the registered Score
evidence plus exact package, release, and toolchain capsule. A born-red fix,
independent reproduction, compatibility event, or preservation event may
qualify with a verified release/predecessor lineage and no patron at all. An
optional continuity policy may add a patron's caps or transition constraints,
but it neither creates the event nor changes its duplicate identity.

## Epoch creation set and fungibility

Before adding an epoch wire, implementation must re-audit the planned S10-S12
award/MINT path. At this specification freeze, those units are design-only;
there is no canonical award or epoch-MINT object to duplicate.

If no existing canonical mapping has landed, the minimum epoch creation set
binds network genesis, immutable policy, epoch, previous epoch-creation root,
strictly ordered unique attribution roots, count, epoch cap, awarded/minted
atoms, unissued atoms, committee/evidence snapshot, and opening/maturity
anchors. It validates every attribution and the three amount invariants above
with checked arithmetic. The exact ordered recipient mapping and epoch-creation
root are bound into the existing deterministic MINT transaction plan. Required
on-chain commitments reuse ZANC/evidence checkpoints rather than adding a
second narrative OP_RETURN.

ZC23 is fungible. After transfers and coin selection, a particular UTXO is not
a collectible permanently attached to one package. The valid statement is
aggregate and exact: all policy-valid issued supply is accounted for by
creation attributions. A display must never claim that a mixed token still
belongs to one historical work.

## First shadow epoch: implemented simulation and real-world blocker

The first shadow candidate is the real MIT-licensed
`zclassic23/sha3@0.1.0-dev.1` package. Its current exact evidence vertical is:

- package `ea54d7038792764c059a697792d46ee92fe75e29aa302d3c8db3a208a580876e`;
- task `ef7b6182c3560110e34fbfd70c98ee8b8107f6cb0d7b5a2b3315d92f275de5a7`;
- candidate `45654ffefad86f3f5d2096f3c829398be0e8d945508a80adedb458f29364a584`;
- proof policy `6e1021dd7f9d73533f35048cee3a95d555c7473cb1ffcffb3ef06f6f9270b08f`;
- proof set `b063663993af9232bfdc1431950135ecc1dc59caa612c078efca4704fa32f83b`;
- PROVEN lane `a9f923e63e54051535412f180f4720a797c7ab026ceae4bf9d62d2cced880101`;
- Score receipt `680882572af552040efb6ec202915a3d5c2f9704e2d389200c07ed770ba6bea8`.

The local Score is honestly 4/5. Its independent-reproduction evidence root is
`47ca7f1e8c41f062e9e6c66a58539c5daca5deff0f9279dfe7c1ec0990a5e88e`,
and its signer remains same-host/local-only. The O4 protocol simulation can now
derive, verify and optionally store a deterministic creation attribution and
ordered epoch-creation set when the separate policy qualification evaluator
returns ready. That exercises exact amount and lineage invariants; it does not
upgrade the Score receipt, prove physical independence, authorize genesis or
make the fixture's simulated units exist.

The permanent acceptance fixture uses the real self-hosted base package bytes,
signed release and Apache-2.0 `LICENSE`, then reloads the full task, candidate,
proof policy/set, PROVEN lane, Score, contributor binding, reproduction request,
approved-reproducer policy and deterministic challenge anchors. It proves
plan/commit idempotency and rejects a changed branch, missing predecessor,
duplicate candidate, policy substitution and one-atom accounting drift. The
fixture explicitly reports `physical_independence_proven=false`.

The qualification view is:

```text
z23 zcode commons shadow plan --input='{"workspace":"<scratch-cas>","score_receipt_root":"680882572af552040efb6ec202915a3d5c2f9704e2d389200c07ed770ba6bea8","policy_candidate_root":"<64hex>","reproduction_request_root":"<64hex>","reproduction_proof_set_root":"<64hex>","epoch":<n>,"now_unix":<seconds>}'
```

It reloads and rederives the task, candidate, policy, proof set, work receipts,
PROVEN lane, signed Score receipt, exact reproduction objects and generated
package-registry match. Once ready, the scratch-only object flow is:

```text
zcode commons shadow attribution plan|commit
zcode commons shadow epoch plan|commit
zcode commons shadow status
zcode commons shadow verify
```

Use `discover schema <leaf>` for the exact closed input keys. Plans write
nothing; commits store only root-addressed attribution/epoch wires in an
explicit scratch CAS. Every result says `simulated=true`, `token_exists=false`,
`funds_moved=false`, `custody_used=false`, and
`genesis_gate_satisfied=false`. A genuinely separate approved reproducer is
still required to clear the real SHA3 off-host gate. Until then no completed
real-world shadow epoch or independent-reproduction Score unit may be claimed.

## Independent reproduction and shadow-epoch contract

The independent-reproduction path has three distinct completion grades. They
must never be collapsed in code or presentation:

1. protocol and native-command implementation complete;
2. hermetic same-host, multi-process acceptance complete, explicitly labelled
   simulation rather than independent reproduction; and
3. a receipt from a genuinely separate, policy-approved reproducer imported
   and accepted.

Only grade 3 clears the real SHA3 shadow blocker. A different process, path,
user, container, VM, workspace, datadir, or signing key on the same physical
host remains same-host evidence. A signature cannot prove physical location.
Every qualification report therefore exposes the separate facts
`exact_reproduction_match`, `distinct_signer`, `signer_policy_approved`,
`declared_operator_group_distinct`, `remote_transport_used`, and
`physical_independence_proven`. V1 always reports the last fact as false; an
operator may supply trusted external knowledge outside the canonical object,
but the protocol must not rename that knowledge cryptographic proof.

### Existing-owner reuse map

No slice in this program creates a second identity, artifact, build report,
CAS, worker, scheduler, transport, verifier, proof set, grant ledger, package
store, chain simulator, or policy database.

| Required fact or operation | Existing authority reused | Boundary |
|---|---|---|
| Historical 4/5 contribution evidence | `zcl.zcode.score_receipt.v1`, `work_receipt.v1`, `proof_set.v1`, and the PROVEN lane | Score v1 bytes and semantics stay frozen; its independent bit remains forbidden |
| Exact package inputs | `content.v2`, package manifest/release, recipe, dependency lock, toolchain capsule | Public bytes only; no downloaded scripts, credentials, or machine-specific source paths |
| Reference and rebuilt outputs | `zcl.zcode_build.v1` package-build reports plus `build_artifact_manifest.v1` | Existing canonical output paths, SHA3 hashes, sizes, and dependency roots remain authoritative |
| Byte-identity verdict | `vcs_package_reproduce_compare` and `zclassic23-package-verify --emit --reproduce-against` | Exact package/recipe/lock/dependency/output match; no favorable-result selection |
| Confinement | existing package verifier and ZBuild worker | Declarative recipe, Landlock, seccomp, rlimits, no network, bounded resources; degraded confinement cannot qualify |
| Work transport and result | ZBuild worker, `zcode_work_swarm`, signed `work_receipt.v1`, `zpkgswm`, signed provider records, and DHT | Remote transport is reported as a fact, never inferred from a signer or hostname |
| Signer identity and history | contributor binding/ZID and existing delegated worker identity | Approval is checked at receipt time; later expiry preserves history but cannot authorize new work |
| Local package-verifier allowlist | `package_verify_policy` | Parsing/evaluation precedent only: mutable local configuration cannot define immutable issuance policy |
| Local discovery policy | `zcode_sovereignty_policy` | Remains per-node fetch/store/execute policy and cannot change a shadow-policy root |
| Metaverse property grants | existing property-grant evaluator/service | Continue to govern a holder's local property actions; never establish evidence truth, issuance, or reproducer approval |
| Attribution and accounting | `creation_attribution.v1`, `epoch_creation_set.v1`, and the rebuildable Commons projection | Scratch simulation only; no ZSLP transaction, wallet, custody, or second ledger |
| Opening and maturity anchors | existing deterministic chain-test/simnet owner | No second blockchain and no consensus edit |

`vcs_zcode_score_offhost_reproducer_approved()` remains fail-closed, and both
Score-v1 planning and validation continue to reject the independent bit. The
versioned extension is a separate policy-bound reproduction qualification over
the existing proof vertical. It does not upgrade or reinterpret the historical
Score receipt.

### Canonical shadow-policy candidate

The simulation authority consists of two new pure canonical objects:
`zcl.zcode.approved_reproducer_set.v1` and
`zcl.zcode.zc23_policy_candidate.v1`. The reproducer set contains sorted,
unique entries binding an Ed25519 work-receipt signer, existing contributor or
ZID binding root, declared operator-group root, fixed reproduction action root,
valid epoch/time interval, and set sequence/lineage. The policy candidate binds
network genesis, `ZC23`, eight decimals, the exact unchanged cap algorithm and
constants, challenge blocks/MTP delay, no-carry and complete-attribution rules,
closed creation categories, deterministic bounded shadow awards, reproducer-set
root, covenant-document root, policy version, and mandatory
`SIMULATION_ONLY` plus `NOT_OWNER_APPROVED` flags.

Fixture authorities are valid only under a structurally simulation-only policy.
They cannot be promoted to a production policy by configuration. Final economic
awards and the immutable mainnet policy root remain owner-gated. Shadow award
evaluation is pure from the exact policy-candidate bytes; commands and callbacks
cannot choose an amount.

### Portable challenge and qualification

A reproduction request composes existing roots rather than copying their
payloads into a new report: task, candidate, package, release, recipe, lock,
toolchain capsule, reference build report, output manifest, fixed action,
challenge nonce, requester, creation/expiry, confinement grade, and CPU,
memory, process, and output budgets. Export is a root-addressed `content.v2`
carrier containing every public byte required by another node and no wallet,
private key, API/SSH credential, canonical-datadir path, or absolute source
path. Plan is non-creating; commit writes canonical public objects only to an
explicit isolated scratch CAS.

The pure qualification evaluator reloads the complete proof set, request,
reference report, artifact manifest, reproduction work receipt, evidence report,
reproducer set, policy candidate, contributor bindings, and challenge facts.
It requires a canonical signed `REPRODUCE` PASS with exit status zero, exact
task/candidate/policy/toolchain/input/output bindings, byte-identical artifacts,
full confinement, approval valid at event time and epoch, signer separation,
fresh challenge, and unique signer/event. Publisher, candidate author, lane
signer, requester, and safely related operator group are refused where their
identity relationship is provable. Missing linkage remains unknown rather than
proof of independence. Contradictory valid results produce `CONTRADICTION`.

### Workspace and command safety

Every Commons/reproduction command requires an explicit workspace. Empty
strings, filesystem root, traversal, and implicit or canonical live datadirs
are rejected. Read plans remain literally non-creating on an absent path.
Commits require an explicit isolated scratch workspace and are deterministic,
idempotent, and root-addressed. They must report `simulated=true`,
`token_exists=false`, `funds_moved=false`, `custody_used=false`, and
`genesis_gate_satisfied=false`.

The ordered implementation is O0 contract/reuse freeze; O1 policy candidate
and reproducer set; O2 portable challenge; O3 policy-bound qualification; O4
scratch attribution/epoch plan-commit; O5 three-party same-host acceptance and
second-machine runbook; O6 four linked protocol shadow simulations with reorg
and byte-identical rebuild; then O7 seed credential and fixture-only shadow
elections. O7 may begin only after O1–O6 are green. P2SH, threshold signing,
DKG, live ZC23 GENESIS/MINT/SEND, and all custody work remain outside this
authorization.

### O5 portable acceptance boundary

The exact local acceptance command is `make zcode-reproduction-acceptance`.
It composes the three-process requester/reproducer/observer policy path with
the existing real `zpkgswm` wire, signed DHT discovery, corrupt-provider,
restart/resume, and projection-rebuild owners. The three processes use
separate scratch CAS and package stores and begin from root-addressed public
objects. The result is labelled exactly `distinct_signer_simulation=true`,
`approved_fixture_policy=true`, and `actual_off_host_credit=false`.

The portable second-machine procedure is
[`ZC23_REPRODUCTION_RUNBOOK.md`](./ZC23_REPRODUCTION_RUNBOOK.md). A confined
byte-identical rebuild is necessary but insufficient: the reproduced report
must also be bound into the existing signed work-receipt/proof-set path and
admitted under the approved-reproducer policy. No command, fixture, process
boundary, IP address, or hostname may manufacture physical independence.

### O6 four-epoch protocol simulation

`zcode commons shadow protocol verify` is a read-only, scratch-only verifier
for exactly four selected epoch roots and their deterministic fixture-branch
roots. It independently reloads the policy candidate, each canonical epoch,
every creation attribution and the complete task/candidate/proof/PROVEN/Score/
package/release/licence authority chain. It then checks exact predecessor
linkage, active opening and maturity anchors, no repeated candidate or
continuity event, checked cumulative accounting, and the rule that every
epoch's unused capacity expires rather than carrying forward.

The permanent fixture uses the actual permissively licensed `lib/base`,
`lib/sha3`, and `lib/codec` package trees as three distinct challenge-mature
contributions in epochs 0–2; epoch 3 intentionally issues zero. It rebuilds
the Commons projection twice after every epoch and requires byte-identical
roots. Replacing the fixture branch at the epoch-2 boundary invalidates the
old epoch and descendants; rebuilding epochs 2–3 gives deterministic new
roots while the old objects remain in CAS as inactive historical evidence.
Mixing branch roots or repeating a candidate fails closed.

Every row is labelled `reproduction_grade=same_host_fixture_only`. The report
also says `protocol_shadow_simulations=true`,
`owner_required_green_shadow_epochs=false`, and
`genesis_gate_satisfied=false`. These are protocol simulations, not the four
owner-required green shadow epochs, and they create no token, issuance,
custody, authority, or claim of physical independence.

## Patronage, commissions, and continuity

Patronage never creates protocol emission, proof status, score, committee
weight, ownership, or technical truth. It controls only funds the patron is
authorized to direct. V1 is limited to:

1. **EXACT_TASK_COMMISSION** — an existing task, proof policy, amount, expiry,
   and recipient rule; settlement requires the exact accepted candidate,
   complete proof set, PROVEN lane, valid score receipt, and selected challenge
   maturity.
2. **PACKAGE_CONTINUITY** — an exact package lineage, compiler/platform
   transition, proof policy, cycle and amount caps, total cap, and expiry;
   eligible work is demonstrated maintenance, repair, reproduction, or
   preservation rather than code churn.
3. **DIRECT_GIFT** — signed support for a public work or contributor, creating
   no score, committee weight, matching subsidy, proof status, or property
   right.

Before adding `patronage_intent.v1`, `patronage_funding.v1`,
`patronage_settlement.v1`, or `continuity_policy.v1`, audit and extend the
existing task, contract, marketplace, and transaction-plan owners where
possible. A v1 intent binds network genesis and exact ZC23 token ID (or an
explicit simulation placeholder), patron contributor/ZID binding, anonymous-
display choice, closed mode, exact target kind/root, task/policy roots where
required, amount in atoms, creation/expiry, refund height/time, sequence,
maximum ZCL fee, settlement trust mode, and a canonical no-authority flag.

An offer in CAS or DHT is **unfunded** unless a verified funding object and
strict-valid confirmed input prove otherwise. Safe implementation stops at an
unfunded signed offer, a fully simulated funded offer, and a clearly labelled
future 2-of-3 or committee-assisted settlement plan with CLTV refund. ZClassic
script cannot evaluate a ZCODE proof set; conditional proof settlement is not
trustless script enforcement. The committee/cosigner trust and custody gates
must be shown explicitly. Every financial mutation remains plan/commit with
confirmation, exact fee and transaction bytes, expiry, idempotency, reorg
recovery, and named unavailable blockers.

## Rebuildable Living Commons projection

One local projection may index canonical CAS and chain objects for read-only
`zcode commons` (or `zcode canon`) views. It is never authority and must rebuild
byte-identically after a wipe. Read commands remain literally non-creating on
an absent datadir.

Planned views expose policy-valid minted, attributed, and unattributed supply;
challenge-matured creation count; package/release additions; born-red defects;
independent reproductions; security repairs and negative findings;
compatibility-maintained lineages; exact unissued capacity; first integrity
failure; complete/partial/unknown verification; and the next safe diagnostic.
An onion/API presentation comes only after the command/model/service path and
consumes the same projection.

## Ordered safe implementation slices

| Slice | Deliverable | Hard stop |
|---|---|---|
| LC0 | Freeze this covenant, naming, arithmetic, trust boundaries, order, and tests | Specification only |
| LC1 | Pure creation-attribution codec, root, CAS cross-object validation, KATs and parser fuzzing | No database, command, token, or wallet mutation |
| LC2 | Pure epoch creation-set accounting plus simulated deterministic MINT-plan binding | No GENESIS, MINT, SEND, signing share, or live transaction |
| LC3 | One rebuildable projection and non-creating read-only commons commands | No new source of truth or REST silo |
| LC4 | Reused-owner patronage/continuity codecs and unfunded/simulated plan-commit flows | No live funds or custody claim |
| LC5 | Unique continuity-event validation and lineage views | No reward for churn, volume, or self-dealing |

Each code slice begins with born-red adversarial tests, lands as a coherent
green commit, integrates current `origin/main`, and records exact gate
receipts. Heavy lint, uncached suite, sanitizer, LTO, and reproducibility gates
run only when repository coordination permits them; a deferred gate is named,
never implied green.

## Permanent adversarial test plan

Coverage must include repeated-run wire KATs; malformed magic/version/enums/
lengths/trailing bytes; domain confusion; zero/substituted roots; checked
decimal conversion and `uint64_t` overflow; exact maximum supply; attribution
without PROVEN; immature/future/reorged evidence; duplicate contribution;
wrong contributor binding; package/release/recipe/lock or licence substitution;
epoch sums one atom below/above MINT; unattributed MINT; capacity carry-forward;
balance/patronage/rank attempting to affect score or committee weight;
patronage attempting to create emission; unfunded-as-funded display;
cross-task/candidate/policy settlement; refund/settlement/expiry races; reorg
recovery; idempotent commit/rebroadcast; sponsor/worker self-dealing;
projection wipe/rebuild; absent-datadir non-creation; two-node publication/
fetch/rebuild; parser fuzzing; and ASan/UBSan without suppressions.

## Acceptance statement and genesis blockers

The safe foundation is complete only when it can prove, without trusting a
website, committee narrative, or database cache:

> For every policy-valid atomic unit of issued ZC23, there is exactly one
> challenge-matured creation attribution binding it to verifiable public C23
> contribution evidence; total attributed amount equals total policy-valid
> issued supply; unused issuance capacity was never minted; and no token
> balance established technical truth or contributor authority.

Real custody and token genesis remain blocked on completion of the pure policy
and verification slices, challenge-mature founding contributions, green shadow
epochs, exact active-chain/reorg proofs, independent review, custody gates,
owner authorization, and a separately reviewed immutable genesis policy root.
Nothing in this document grants that authorization.

## Implementation ledger

Updated 2026-08-07. This is an implementation record, not token or deployment
authorization.

| State | Slice | Source commit | Integrated `main` | Evidence |
|---|---|---|---|---|
| DONE | LC0 covenant and terminology freeze | `03f13639d` | `1ff4db5a0` | full lint 134/134; pre-push source-wide suite |
| DONE | LC1 fixed creation-attribution wire, identity KAT, checked eight-decimal arithmetic | `0ff09fb68` | `9a8cc8672` | born-red unresolved-symbol gate, focused green, pre-push source-wide suite |
| DONE | LC1 independent CAS cross-object verifier | `f0d1af5a1` | `f9a5c61cb` | focused attribution/Score verticals, full lint 134/134, pre-push source-wide suite |
| DONE | LC2 ordered epoch creation-set wire and cap/no-tail arithmetic | `4cfaf6ebf` | `c41a51de1` | born-red unresolved-symbol gate, root KAT, full lint 134/134, pre-push source-wide suite |
| DONE | LC2 CAS attribution summation and observed-MINT equality gate | `4381781b8` | `36f6f3ae5` | one-atom under/over rejection, focused attribution/Score verticals, full lint 134/134 before integration, combined-tree lint-fast, pre-push source-wide suite |
| DONE | LC3 read-only canonical-CAS projection | `a3424aba6` | `a3424aba6` | absent-workspace non-creation, populated byte-identical rebuild, exact parsed totals, full lint 134/134, pre-push source-wide suite |
| DONE | LC3 `zcode commons` read views | `84a54696a` | `84a54696a` | born-red unresolved handlers; status/epoch/creation/lineage/verify/rebuild green; command-key and generated-reference gates; full lint 134/134; pre-push source-wide suite |
| DONE | LC4 simulation-only signed patronage intent | `94141b969` | `94141b969` | born-red unresolved symbols; exact wire, closed mode/trust/target enums, no-authority and simulation flags, focused green, full lint 134/134, pre-push source-wide suite |
| DONE | LC4 intent CAS authority revalidation | `c1123dbab` | `6da2651dd` | exact patron/recipient binding, task, policy, package/creation target and network reloads; focused green, full lint 134/134, normal pre-push source-wide suite |
| DONE | LC4 fully simulated funding receipt | `c804a20ae` | `c804a20ae` | exact intent reload, deterministic plan root, no-live-funds/no-transaction-bytes gates, focused green, full lint 134/134, pre-push source-wide suite |
| DONE | LC4 pure settlement/refund receipt | `f618eb6c5` | `f618eb6c5` | 504-byte wire KAT, truncation zeroing, closed simulation flags, complete-or-empty evidence, signature mutation, focused green, full lint 134/134, pre-push source-wide suite |
| DONE | LC4 settlement/refund CAS authority revalidation | `264df17ee` | `e2185eb7c` | historical intent/funding reload, full creation-evidence rederivation, exact target and recipient binding, maturity/reorg/refund gates, focused green, full lint 134/134, normal pre-push source-wide suite |
| DONE | Shared people-and-AI mission and API contract | `d9eea8e09` | `d9eea8e09` | exact mission language, same API/evidence rules, no-world-ownership boundary, READY-versus-PLANNED truth, generated API reference, full lint 134/134, normal pre-push source-wide suite |
| DONE | LC4 offer/funding plan-commit and exact-root show commands | `788f93149` | `c9c3e786a` | signed exact-wire input, caller-pinned context, CAS revalidation, absent-workspace plan non-creation, simulation/funding truth labels, planned settlement/refund/list fail closed, focused green and full lint 134/134 |
| DONE | Simulation-only transaction classification | `e90c17ed6` | `e90c17ed6` | exact non-chain declaration for funding CAS commit; API reverse-mapping gate green; 901 active pre-push test groups green |
| DONE | LC5 bounded signed continuity-policy wire | `a9cff6c45` | `d2facab04` | exact wire KAT, closed event/capsule enums, checked cycle and amount caps, anti-churn invariants, focused green, full lint 134/134, normal pre-push source-wide suite |
| DONE | LC5 continuity-policy CAS authority rederivation | `eb258785a` | `d2facab04` | historical package/release/proof-policy/capsule reloads, package-lineage and cap checks, focused green, normal pre-push source-wide suite |
| DONE | LC5 `zcode continuity plan\|commit\|status` commands | `90bb3d3cd` | `90bb3d3cd` | read-only plan on an absent workspace, exact signed CAS commit, exact-root status revalidation, lossless `uint64_t` display, no-funds/no-income/no-score/no-emission labels, focused green, full lint 134/134, normal pre-push source-wide suite |
| DONE | LC5 unique continuity-event validation | `ba9f8d0d0` | `dfa62d73f` | domain-separated event key KAT; one package/capsule transition or defect root credits once; born-red/security category splitting rejected; continuity policy and evidence independently reloaded; focused green, full lint 134/134, normal pre-push source-wide suite |
| DONE | LC4 rebuildable patronage list | `fc0813d2a` | `fc0813d2a` | deterministic CAS projection, historically signed intent/funding/continuity verification, first-failure reporting, absent-workspace non-creation, every row truthfully `funded:false` and `persisted:false`; focused green, full lint 134/134, normal pre-push 910-group suite |
| DONE | Living Commons parser truncation sweeps | `cbaae2112` | `cbaae2112` | every truncation of creation-attribution, epoch-creation, patronage-intent/funding/settlement and continuity-policy wires fails closed; focused GCC groups green; Clang 20 ASan+UBSan green with fail-fast UBSan; full lint 134/134; normal pre-push 910-group suite |
| DONE | Six-arm Living Commons parser fuzzer | `a0cfe7fe4` | `a0cfe7fe4` | shared libFuzzer owner, one seed per canonical parser, ASan+UBSan and leak detection; 1,537,885 mutations in 31 seconds at 49,609/s with no finding; full lint 134/134 |
| DONE | Historical binding time and complete public-source lineage | `7c2ebdea0` | `84a816754` | born-red expiry and arbitrary-lineage failures; event-time binding verification; signed release parent and recursively verified predecessor paths; focused green; normal pre-push 901/901 active groups |
| DONE | Neutral creation identity and security-label normalization | `66a81064e` | `66a81064e` | patron-independent event-key KAT; release-lineage continuity without funding; `SECURITY_FIX` normalized to born-red eligibility and award; focused green; normal pre-push 901/901 active groups |
| DONE | O0 reproduction owner/reuse contract freeze | `209aac342` | `209aac342` | Score v1 frozen; existing CAS, proof, build, artifact, identity, transport and chain-test owners mapped; no live authority granted |
| DONE | O1 simulation-only policy candidate and approved reproducer set | `08d7f1af2` | `08d7f1af2` | exact canonical roots, closed flags and award table, approval epoch/time bounds, focused green, full lint 134/134, normal pre-push 911-group suite |
| DONE | Shared mission/API and explicit scratch-workspace safety | `6df06b721` | `6df06b721` | exact people-and-AI mission, ready `zcode guide`, canonical/live workspace refusal, generated API reference, full lint 134/134, normal pre-push 911-group suite |
| DONE | O2 portable simulation-only reproduction challenge | `c41cebd99` | `c41cebd99` | 512-byte request KAT, public-root and confinement bindings, noncreating plan, idempotent scratch-CAS commit, focused green, full lint 134/134, normal pre-push 911-group suite |
| DONE | O3 policy-bound reproduction qualification | `307556653` | `307556653` | complete Score/proof/request/build/manifest/policy/identity CAS rederivation; missing output, missing approval identity, stale epoch and contradictory-result rejections; command readiness derives from the evaluator; physical independence remains explicitly unproven; focused/API gates and full lint 134/134 |
| DONE | O4 scratch attribution and epoch plan/commit | `3b45e7991` | `c7ddc1fd9` | full policy/Score/reproduction/binding/package/release/license reload; deterministic fixture anchors; exact award/mint equality; changed branch, missing predecessor, duplicate candidate, policy substitution and one-atom drift rejection; six typed shadow leaves; focused/API gates, full lint 134/134 and normal pre-push source-wide suite |
| DONE | O5 three-party portable reproduction acceptance | `6b933d4ea` | `6b933d4ea` | requester, reproducer and observer in distinct processes/workspaces/stores; root-addressed content/package transfer; independent qualification and byte-identical projection rebuild; real swarm/DHT corruption, cancellation, fallback, resume and restart owners composed by one exact 6/6 gate; `actual_off_host_credit=false`; full lint 134/134 and normal pre-push 902-group suite |
| DONE | O6 four linked protocol shadow simulations | `fc7b88bab`, `e237f13fa` | `e237f13fa` | actual base/SHA3/codec package verticals; three distinct mature creations followed by one empty epoch; exact predecessor and cumulative 300,000,000-atom equality; byte-identical rebuild after every epoch; boundary reorg and deterministic replacement roots; cross-epoch duplicate refusal; read-only typed report; focused creation/Score/catalog/API gates, full lint 134/134 and normal pre-push 902-group suite; `same_host_fixture_only`, real genesis gate false |
| DONE | O7 fixture-only C23 seed and shadow-election foundation | `d623a3043` | `37a8c8aa6` | exact 721-byte dual-signed seed wire; generated/vendor/copied exclusion; height+MTP maturity and reorg gates; canonical evidence snapshot; 26-epoch decay and 10,000 weight cap; unbiased weighted selection without replacement; one ZID per seat; concentration metrics; four frozen election KAT roots; focused green, full lint 134/134, 10,000 ASan+UBSan fuzz iterations and normal pre-push 903-group suite; `simulation_only=true`, `authority_conferred=false` |
| BLOCKED | Real SHA3 off-host independence gate | `fc62b9c4a` | `fc62b9c4a` | SHA3 Score remains honestly 4/5; local evidence and O5 same-host simulation do not prove physical independence or authorize a real shadow epoch, token genesis, mint or custody |

Historical-truth hardening began from fetched `origin/main` `7091051aa`
through lane integration `a96275b52`. Before the first slice was pushed, new
main `6b410bd34` was integrated through `84a816754`; no concurrent wallet file
was edited or overwritten. Normal hook-enabled pushes advanced remote main
through `84a816754`, `66a81064e`, and `fc62b9c4a`. Each push passed the
repository pre-push lane: 910 registered, 901 active run, zero cached, nine
policy-gated, zero failures. The final source also passed full lint 134/134,
the dedicated ZCODE ASan+UBSan lifecycle, default whole-program LTO, same-tree
byte reproduction
(`868e83bececddce7e6c0ba36b48962c46fcd7af5346f2c0ba92b23d6d3c1f118`,
22,809,352 bytes), and two-path local reproduction
(`ac79afa294c101aa77e8d81caaf4d65c1e61c30e9bbf00cb16627568caae58e6`,
22,809,432 bytes). Both reproduction
results are local and earn no independent-reproduction credit.

Before freezing this ledger, concurrent `origin/main` `8df6c3961` was merged
through `d77ccce74`. The disjoint vault changes were preserved exactly; the
Living Commons documentation did not overwrite them.

The `36f6f3ae5` push integrated concurrent `main` commit `00a0c54c8` through
lane merge `4c8e7abe2`; no concurrent file was overwritten. Two complete
pre-push attempts were blocked only by host-variable `test_simnet_perf`
detector measurements. The exact group then passed on the same combined SHA
(clean growth 1065 permille, injected growth 3437 permille), and the final
normal, hook-enabled push passed. The failed attempts are not counted as
passed gates.

The `e90c17ed6` push integrated concurrent `main` commit `8265c423f` through
lane merge `c9c3e786a`; no concurrent file was overwritten. Its first normal
push attempt exposed an uncovered transaction-shaped command in `test_api`.
The command was then explicitly classified as simulation-only/non-chain,
the focused API gate and full lint passed, and the second normal push passed
all 901 active pre-push groups. The failed attempt is not counted as a passed
gate.

Continuity authority integrated concurrent `main` through `def31919d` and
`d2facab04`. Unique continuity evidence later integrated concurrent commit
`64f6a8b66` through `dfa62d73f`; the combined tree exposed a pre-existing
pipefail-sensitive parity shell assertion, fixed narrowly in `db1a0f271`.
No concurrent implementation was overwritten, and the final normal pushes
passed the full source-wide suite.

The permanent parser truncation sweeps passed under GCC focused tests and
under Clang 20 ASan+UBSan with `UBSAN_OPTIONS=halt_on_error=1`. Receipt
`000022` records that the default GCC sanitizer profile is blocked before the
selected tests by the pre-existing Sapling AVX-512 inline assembly failing to
compile with "impossible constraints"; this is not counted as a sanitizer
pass. Clang receipts `000023` and `000024` are passes with no sanitizer
findings. Two different absolute-path builds produced a byte-identical shipped
binary, 22,793,048 bytes with SHA3-256
`29d8305557a31903e0bafca9f85f08bfda1bb26b93bb8d04ae896b83bd7e82e1`
(`000026`). This is `local_reproduction`, not approved independent off-host
reproduction and earns no independent-reproduction unit.

The permanent `fuzz_zcode_commons` target now has ten arms covering creation
attribution, epoch creation, patronage intent, patronage funding, patronage
settlement/refund, continuity policy, approved reproducer set, shadow policy
candidate, reproduction request and `c23.seed.v1` through the repository's
shared libFuzzer object tree.
Receipt `000027` is the born-red missing-target result; `000028` proves the
harness builds, and `000029` records 1,537,885 leak-detecting ASan+UBSan
mutations over the original six-arm harness with no finding. O7 additionally
built the expanded sanitizer harness and ran 10,000 mutations with no finding.
These bounded local runs are parser hardening, not claims of exhaustive
input-space coverage.

The final explicit `--no-cache` source-wide run executed 901 of 910 registered
groups; nine parameter-heavy groups were policy-gated and 22 tests reported
their documented self-skip markers. Its first attempt (`000033`) had one
load-sensitive failure in the runner's nested exact-selector self-test. The
exact group passed alone (`000034`), and the repository-prescribed complete
cold retry passed 901/901 with zero cached groups (`000035`). The failed first
attempt remains recorded and is not counted as a passed gate.

Final evidence closure integrated concurrent `main` commit `58f11e335`
through lane merge `af5865a0fa`; its service-envelope and live-state
documentation was retained without modification.

LC2's canonical set and verifier already own award truth: they independently
reload every ordered attribution, check active-chain maturity/reorg context,
checked-sum award atoms and require exact equality with observed MINT. The
existing generic ZSLP MINT builder has one recipient, while the durable wallet
intent owner binds exact transaction bytes. Therefore the final ordered
recipient/transaction adapter remains owner-gated with real custody and is not
replaced by a parallel canonical object. LC3 intentionally reports `partial`
or `unknown` rather than policy-valid supply until immutable-policy and
active-chain anchor context is wired. LC4 settlement/refund commands remain
planned because their validators require authentic active-chain,
immutable-policy and uniqueness callbacks; caller assertions cannot substitute
for those authorities. LC5 policy, commands and unique continuity validation
are complete.

No live token, GENESIS, MINT, SEND, wallet, canonical datadir, production port,
deployment, service, or consensus path was touched by these slices.

O3 began from fetched `origin/main` `c41cebd9967c88332e3dfa6bd2487283c7ddce88`.
No concurrent integration was required before source commit `307556653`.
The evaluator intentionally reports `remote_transport_used=false` and
`physical_independence_proven=false` for the same-host fixture. That fixture
proves protocol wiring only and does not clear the real SHA3 off-host blocker.
Before the O3 push, concurrent `origin/main` `468d0319281b6298f5e9669c877042c389069fac`
was integrated through merge `10a0480b4`. Its disjoint transaction-lab files
were preserved without modification.

O4 began from fetched `origin/main` `1db74339874030462d243830222bf0f4465b55f0`.
The first push attempt passed the complete pre-push source suite, then was
correctly rejected because concurrent `main` advanced to
`32f946668cc2b2df9adf562f57cc4d6f972e11a1`. That disjoint replayable
shielded-plan work was merged without modification through `c7ddc1fd9` before
the O4 integration retry. The failed race is not counted as a completed push.

O5 began from fetched `origin/main`
`f4e9d7653ffbe0c04f7e6e81e1cb78f3cb61ae29`. No concurrent integration was
required before source and integration commit `6b933d4ea`. The exact
`make zcode-reproduction-acceptance` gate passed all six selected permanent
groups with zero cache hits. Full lint passed 134/134. The normal hook-enabled
push ran 902 active groups with zero failures and zero cache hits; nine
parameter-heavy groups were policy-gated and 19 tests emitted their documented
self-skip markers. Pull verification then proved local HEAD and `origin/main`
were both `6b933d4ea53fd087468ccfedd73c0e53bcc6aca3`.

O6 began from fetched `origin/main`
`dc4a41e5b36b9ef989ec80b0940ae2ad090236e1`. Before integration, concurrent
vault reservation work at `9d1c2173369e2654b478df2860eb8f5ab474f1a4` was
merged without modification through `e0046058c`. The canonical replacement-
branch epoch roots are
`6207eef8dacd6f6f5b9ee30b0287924a6a2d48dceed41d1445b693679e19090a`,
`7160b9135614d8813bf05d222e0c892a7826a73bc8444f1acb294bc9145f13d9`,
`d8dc59fae773b8e16bd084699a6bea9d4bc9096e4d821ac0245ee3228694d755`,
and `f1e901fa6f2a4f3a85283c809d32bb65a8d65258f5f98d4129d6e460099c9dbd`.
Their cumulative simulated issue and cumulative attribution are both exactly
300,000,000 atoms. The first push attempt ran the complete source-wide suite
and failed only because the new leaf's explicit protocol parent branch was
missing; that attempt is not counted as a pass. Commit `e237f13fa` added the
branch, regenerated the API reference, and made the exact catalog test green.
The corrected normal push passed 902/902 active groups with zero cache hits;
nine parameter-heavy groups were policy-gated and 19 tests emitted documented
self-skip markers. Pull verification proved both local HEAD and `origin/main`
at `e237f13fa404aebe5b8431e673eaf17b839afb3a`. All four rows remain
`same_host_fixture_only`, `owner_required_green_shadow_epochs=false`, and
`genesis_gate_satisfied=false`.

O7 began from fetched `origin/main`
`04acb417569abe051528794c1c1eaee5950882ee`. No concurrent integration was
required before source and integration commit
`d623a3043125f054521e26d9c4a1e01c35132f7d`. The fixed seed wire root is
`ce3b43aabcc2a3feedaa489161bc76756d8e8a34fe14d280c0eac9293ec12c93`.
The four fixture election roots are
`911bf472f1eb07ee50fa706881aff82d0c56b2daa9c406697f79f4575a1c1610`,
`89e8c26d59957de264063915eead7640ac5da1d6f17bed8125ba0edd27bd1a06`,
`6cc3bbef00ccbd30206ac916beb62648ba223b83e5a6cc2cd2e959c95526f24b`,
and `f46912d939cdcfbfd8937429717851cfb771702469caca60cc59666bb418a1ce`.
The first lint attempt correctly found the test-group count ratchet at 911;
the documentation count was updated to the code-measured 912 and the complete
134-gate lint retry passed. The normal hook-enabled push then passed 903/903
active groups with zero cache hits; nine parameter-heavy groups were policy-
gated and 19 tests emitted documented self-skip markers. Pull verification
proved local HEAD and `origin/main` both at `d623a3043`. The seed authorities,
chain anchors and elections are test fixtures only: no production seed was
admitted and the elections set `simulation_only=true` and
`authority_conferred=false`.

While the O7 documentation push gate ran, concurrent `main` advanced to
`201f558b131b404949ebe07079d50db8710b21b3b`; the completed green push was
correctly rejected as stale. Its disjoint metaverse custody-reader contention
fix was merged without modification through `37a8c8aa6`. Both affected
focused groups and the complete 134-gate lint set passed on the combined tree
before the integration retry. The stale rejected push is not counted as a
completed publication.

Final O7 closure ran `make repro-verify`, which performed two clean whole-
program LTO builds from different absolute source paths. Both shipped binaries
were byte-identical at 22,924,056 bytes with SHA3-256
`6d73161684a038508e222ac6ce5e0fc7b3ad4d56a5762d81be2cd3701d926c39`.
This is same-host `local_reproduction` only; it does not prove physical
independence, award the withheld Score unit, or satisfy the real genesis gate.
