# Commuting tickets

This is a historical design proposal for per-group proof reuse, not a current
admission contract or implementation claim. The active route is
[DEVELOPING.md](../DEVELOPING.md). Only implemented receiving-node policy can
admit exact reusable evidence; this proposal grants no skip or publication
authority and does not create another receipt ledger.

## Purpose

The proposal keys a signed PASS verdict to one group's complete input closure
rather than only to the commit. The proposed fields and rules below require
independent qualification before use. A reduced or stale compiled catalog must
never define the complete group universe or silently omit current family
members. Source, toolchain, harness, isolation, selection, and receiver policy
all remain part of exact admission.

## The problem, measured

The push-hook proof (`dev proof ensure` and `dev proof wait`; see engine/composition/commands/dev.def) is keyed by (commit, base). Any base move invalidates the whole proof, including every group the move did not touch.

| Fact | Value | Source |
|---|---|---|
| Cost of one proof | 45 min | fleet proof logs |
| Worst stack in the window | rebased 8 times | fleet proof logs |
| Wall clock lost across the fleet | about 20 h | fleet proof logs, 2026-09-03 and 2026-09-04 |

The recorded runner had per-group caching and a `toolkey` in its suite verdict;
one historical run stored 483 fresh PASS verdicts. That count and toolkey alone
do not establish present receiver qualification. Derive current exact reuse
and its limitations from native receipts, not this proposed key.

## Input closure

The input closure of a group G is:

- every source file that G's test binary compiles or reads;
- the owning sources from `code tests` reversed: every file whose owning group is G;
- the test file;
- the headers those files include transitively;
- the toolchain epoch: compiler id, flags, and vendor archive hashes, as the build epoch already computes;
- the harness version.

## Ticket key

key(G, T) is SHA3-256 over the canonical list built at tip T:

1. the closure's repo-relative paths, sorted, each followed by the blob hash of its content at T;
2. then the toolchain epoch;
3. then the group name.

Any file change inside the closure changes the key. A change outside the closure does not.

Example of the canonical list and the resulting key form. The paths are illustrative; the hash and epoch fields are placeholders, not values from this checkout:

```
engine/modules/engine/src/engine_receipt.c <blob hash of content at tip>
tools/engine_unit.c <blob hash of content at tip>
<one line per closure file, in sorted repo-relative path order>
<toolchain epoch>
<group name>
```

key = SHA3-256 over those lines, rendered as 64 hex characters.

## Ticket record

| Field | Content |
|---|---|
| group | group name |
| key | key(G, tip) as defined above |
| verdict | PASS only; a FAIL is a result row, never a ticket |
| groups_ran | 1 |
| tip | commit where the ticket was produced |
| producer | producer node id |
| ts | production timestamp |
| signature | Ed25519 signature by the producer node's identity, over all fields above |

Tickets append to the fleet receipt ledger. The ledger is append-only and chained. See engine/modules/engine/src/engine_receipt.c for the record shape and its torn-line refusal.

## Admission rule

A train at tip T is green when, for every registered group G, there is a valid ticket whose key equals key(G, T). Groups with no valid ticket are re-proved; only those groups run. A proof produces tickets for exactly the groups it ran.

## What a base move costs

After a base move, re-proof cost is proportional to the number of groups whose closure intersects the diff between the old tip and the new tip. Measured expectation from tonight's trains:

| Change | Groups whose closure intersects the diff |
|---|---|
| 6-doc train | 0 |
| One-leaf change | 1 |

These are expectations of the proposed closure model, not current guarantees.
Documentation can affect generated inputs, build rules, or acceptance policy;
one leaf can affect several groups. No zero-reproof or single-group assertion
is valid without complete exact-input qualification and receiver admission.

## Revocation

A ticket is invalid when any of the following holds:

- its producer key is not in the fleet identity set;
- the toolchain epoch changed since the ticket was produced;
- the harness version changed since the ticket was produced.

There is no other expiry. Never trust a ticket without a verifiable signature. A node's own report is never evidence.

## Historical proposed assignments

These names are archived design context, not live ownership or leases. Current
writers coordinate through native claims; no permanent lead is required.

| Work | Owner |
|---|---|
| This specification | node1 |
| Ledger and admission side | node2, lane `proof-commuting-tickets` |

The file-to-group map comes from `code tests`, at 10 ms per file. Lane references: docs/agent/LANE_LAUNCH.md, docs/agent/LANE_REPORT.md. Node identity and reporting protocol: docs/agent/agent-protocol.md.
