# ZC23 distribution — the rules (C2, owner-decided 2026-08-09)

> Retained simulation-only policy record, not a current-work queue. Current
> ordering lives only in [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

Phase C2 of [`MARKETPLACE_NEXT.md`](./MARKETPLACE_NEXT.md). This document
**decides**; [`ZC23_DISTRIBUTION_OPTIONS.md`](./ZC23_DISTRIBUTION_OPTIONS.md)
was the menu. The owner picked, with one standing guidance: **incentivize
the P2P ecosystem**, and the picks are suggestions to be tuned, not sacred
numbers. Everything here stays inside the frozen covenant
([`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md)): ZC23 stays
simulation-only — no live token, no GENESIS/MINT/SEND, no payout, no
consensus change — until the owner explicitly promotes. C3 is the
implementation plan that swaps the simulated receipt store for ZSLP
mint/send behind the same plan/commit commands; it is written next.

## 1. Name — Proof of Participation

Picked: **Proof of Participation**, always qualified in writing as
"participation = verified contribution". Anyone can show up; only
evidence mints. The mechanism is creation-backed issuance either way —
the name is marketing, the covenant language stays the protocol truth.

## 2. Distribution — evidence-scheduled emission only

Picked: **evidence-scheduled emission** (options-doc 2A). No genesis
pool, no bootstrap treasury. Every unit enters circulation the same way:
a public, versioned schedule maps evidence classes to weights; a weekly
epoch batch proposes mints from the verified evidence graph; the owner
reviews and commits (plan/commit — automation proposes, the owner
disposes). Schedule changes are public and versioned like code changes.

## 3. Evidence classes and first weight schedule

First schedule (mine to tune, per the owner; one line per class, weights
are shares of the epoch budget, not absolute amounts):

| Class | Evidence | Weight |
|---|---|---|
| **Creation** | New policy-valid C23 package published to the commons (exact retrievable source, tests) | **100** |
| **Reproduction** | Independent three-party reproduction of someone else's package (O5, [`ZC23_REPRODUCTION_RUNBOOK.md`](./ZC23_REPRODUCTION_RUNBOOK.md)) | **40** |
| **Repair** | Review, repair, or port merged into a commons package | **20** |
| **Preservation** | Availability proof for a hosted commons package, per epoch per package | **5** |

Anti-fraud rules (not tunable without a covenant change):

- Unverified publication earns **ZCODE Score, not ZC23**. Creation weight
  pays only once at least one independent reproduction exists — the
  reproduction is what stops self-minting spam.
- Reproduction pays the reproducer **and** unlocks the creator's mint in
  the same epoch, so verifying others is always worth more than waiting.
- Preservation pays only against a passing availability proof (the
  package actually serves when challenged), per epoch, per package —
  hoarding dead bytes earns nothing.

## 4. Supply — hard cap, self-tapering

Picked: **capped total** (ZCL-style scarcity): **21,000,000 ZC23**.

Emission: weekly epochs; each epoch's budget is

```
budget(epoch) = (cap − already_emitted) / 1040
```

1040 ≈ 20 years of weekly epochs. No halving table to govern, the cap
can never be exceeded, and emission decays smoothly (~10 %/yr) instead of
in steps. Weights from §3 split each epoch's budget pro-rata by verified
evidence points in that epoch; if an epoch has no verified evidence, its
budget simply does not emit (the remaining pool stays larger for later
epochs — non-issuance is not redistribution).

## 5. Owner self-dealing — same rules

Picked: **same rules**. The owner earns at the same weights, through the
same evidence, as everyone else — human and AI contributors already use
the same factual rules; the owner is not excepted. The one structural
difference that stays: the owner signs the mint batches (v1), which is
custody of the process, not a weight.

## 6. Hosting — yes, it earns (preservation class)

Picked: **hosting earns ZC23**, as the preservation class above —
not just ZCODE Credit. This is the P2P-ecosystem incentive the owner
asked for: keeping the commons' packages alive is first-class
participation. Guardrails: availability proofs (challenges that must
actually be served), per-epoch caps so preservation never outweighs
creation, and Credit still accrues separately as the reciprocity quota.

## 7. What C3 builds (next)

The v1 mechanics are already simulation-proven (`make metaverse-verify`
members MM4/MM8: patronage plan/fund/settle/refund with proof-conditioned
release, continuity epochs, commons attribution — CAS-stored,
simulation-only). C3, in order:

1. Encode this schedule as the versioned epoch-batch proposer (reads the
   verified evidence graph, emits a reviewable mint plan).
2. Swap the simulated receipt store for ZSLP mint/send behind the same
   plan/commit commands — still owner-signed per batch.
3. Availability-proof challenge loop for the preservation class.
4. Public schedule file + epoch receipts anyone can re-derive ("verified
   by acceptance proofs, never trusted" applies to the money too).

## 8. Codified in (C2 proposer slice, 2026-08-09)

Step 1 above landed as a simulation-only proposer, alongside the frozen era
curve (never inside it): `contexts/commons/modules/vcs/src/zcode_epoch_schedule.c` (header
`contexts/commons/modules/vcs/include/vcs/zcode_epoch_schedule.h`) encodes the 21,000,000 cap,
the `(cap − already_emitted) / 1040` weekly budget, and the 100/40/20/5
class weights, reading `already_emitted` from the commons projection's
minted totals. The native pair `zcode commons schedule propose plan|commit`
previews / persists a root-addressed proposal wire in the scratch CAS — a
reviewable schedule proposal, not a mint. Preservation evidence is counted
and skipped with the named reason `preservation_availability_proof_unavailable`
until step 3 lands. Tests: `test_zcode_epoch_schedule`.
