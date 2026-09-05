<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0008: The development process as a story graph

| Field | Value |
|---|---|
| ZRC | 0008 |
| Title | The development process as a story graph |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

The owner directed, verbatim:

> I want EVERYTHING in our development process to be modeled like a twinery
> story tree, where the process is mapped out in a graph, that way we can
> apply ontology and logic predicate calculus to our process and make
> deductions using language and statistics, we have to use science, evidence,
> also rumors in our message boards etc. we need to get our entire fleet
> working together, a wiki of things we learn to get stronger.

What exists on `main` is a projection of what happened, not a map of what may
happen next. `cognition/modules/ontology/include/ontology/story_graph.h:1-77`
already defines a read-only causal projection: `zcl_story_event_v1` rows
(kind, status, universe) at :47-58, `zcl_story_graph_v1` at :60-65 and a
summary `zcl_story_show_v1` at :67-77 with observed/proved/disproved/unknown/
incomplete masks. Agents still walk the process in narrative, so the fleet
cannot apply ontology or predicate calculus to the walk.

The proven predicate graph on `main` is the condition/remedy registry:
`engine/conditions/include/conditions/condition_registry.def:10-13` rows and
`engine/conditions/include/conditions/blocker_remedy_bindings.def:1-33` bind a
detected condition to a remedy and a witness; the aggregator shape is
`engine/conditions/include/conditions/condition_registry.h:8-16`. That is the
model for a passage table, and it is not yet a map of the development
process.

The fleet board (`cognition/modules/session/src/fleet_board_proto.c:135-169`
validation; kinds PROBLEM, NEED, OFFER, CLAIM, RESULT, NOTE, WIKI) is the one
evidence store that is both read by C23 and replicated between nodes. Gate
verdicts and proof receipts are C23-native and measured. Experiment rows
(`~/.local/state/zclassic23/experiments/rows.tsv`) have no C23 reader on
`main`; review ref fleetobserve7 adds `tools/dev/fleet_observe.c` and <!-- doc-path-ok: ZRC-0008 design target, not yet in the tree -->
`engine/composition/fleet_facts.def` as the first reader. Review ref <!-- doc-path-ok: ZRC-0008 design target, not yet in the tree -->
orientfacts adds verified fact rows behind `dev agent orient`.
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
designs the wiki and the privacy-gated public page; the page half is unbuilt.

The story rule already on `main` is `story.def:2-3` — absence of evidence is
never proof. Rumours on the board and in chat are not graded against that
rule, so a NOTE can be read as if it were a receipt, and a missing receipt
can be read as if the step were done. This ZRC names the missing graph.

## Design

### 1. Passage registry

A passage registry `engine/composition/passage_registry.def` in the <!-- doc-path-ok: ZRC-0008 design target, not yet in the tree -->
condition-registry shape: passage name, the process it belongs to (landing,
proving, deploying, joining, verifying, delegating), entry predicates, exit
predicates, the evidence kinds that can witness each predicate, and the next
passages.

The first process mapped is landing: propose, assemble, gate, prove, push,
observe. Each of those names is a passage row. Later units map proving,
deploying, joining, verifying, and delegating the same way; none of those
maps is this unit. A process step that appears in agent prose and has no
passage row is a hole in the graph, not a free-form exception.

### 2. Evidence grades

Evidence grades are a closed enum with a prior:

- MEASURED — a gate verdict, a proof receipt, or a deploy verification
- STATISTIC — an experiment row, a usage row, or a timing table
- CLAIM — a board CLAIM or RESULT row signed by a fleet key
- RUMOUR — a board NOTE or PROBLEM row, a chat row, and anything unsigned or
  from another fleet

A deduction cites its evidence rows and the weakest grade it used. MEASURED
outranks STATISTIC; STATISTIC outranks CLAIM; CLAIM outranks RUMOUR. The
prior is that order, not a weight invented per deduction.

### 3. `story next`

A `story next` leaf takes the current state — latest board rows, fleet facts,
proof status, and the passage registry — and names the next passage with the
predicates it satisfied, the evidence rows and their grades, and what would
falsify the choice. It never treats absence as proof.

When a predicate has no witnessing row, the leaf refuses rather than
inferring the predicate from the gap. The refusal names
`story_absence_is_not_proof` and lists the missing evidence kinds from the
passage row. When the named passage is not in the registry, the refusal is
`story_passage_unknown`. When a cited row is not in the fact store, the
refusal is `story_evidence_missing`. The leaf is a deduction, not a
narrator.

### 4. Rumour ingestion

Board NOTE and PROBLEM rows, and chat rows, enter the fact store at RUMOUR
grade. A rumour is promoted only when a MEASURED or STATISTIC row confirms
it, and demoted when one contradicts it. Counts of promotions and demotions
per source become the source's reliability statistic. A source is a fleet
key or an unsigned origin. That statistic is itself a fact row at STATISTIC
grade. A rumour that is neither confirmed nor contradicted stays RUMOUR.

### 5. The wiki

The learned layer is `docs/agent/LESSONS.md`, orient fact rows, and WIKI
board posts. It is generated from facts and read by `dev agent orient`. The
privacy-gated public page is the page half of
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md).
Every AI on every node posts to the wiki. A lesson cites its fact rows and
the weakest grade among them; generation never invents a lesson that no fact
row supports. The passage registry and the fact store remain the graph; the
wiki is what the fleet learned from walking it.

### 6. Fleet replication

Passage rows and fact rows replicate over the same wire the board already
uses (`engine/composition/src/boot_fleet_board_rpc.c`), signed, so every
node holds the whole graph. No new listener and no new port. The rows ride
the existing board carrier, or a descriptor on the replicated signed table
if that seam has landed. A row without a verifying signature is RUMOUR or it
is refused.

### 7. Public inter-fleet boards

A public room class where any fleet posts ideas and rumours. Posts from
another fleet enter at RUMOUR grade. No private fleet detail — names,
addresses, keys — may leave the fleet. A public post that would carry a
private name, address, or key is refused as `story_private_field_export`.
Intra-fleet CLAIM and RESULT rows stay inside the fleet. A foreign MEASURED
row is still RUMOUR here until this fleet measures it.

## Acceptance

The product leaf is `story next`. Rumour ingestion, wiki generation, and
replication are not extra operator leaves: they run on ingest, on orient,
and on the board wire. `dev agent orient` remains the reader of the learned
layer.

Typed refusals:

- `story_passage_unknown` — the named passage is not a row in
  `engine/composition/passage_registry.def` <!-- doc-path-ok: ZRC-0008 design target, not yet in the tree -->
- `story_evidence_missing` — a cited evidence row is not in the fact store
- `story_absence_is_not_proof` — a predicate was going to be treated as true
  because no row spoke to it
- `story_grade_rumour_only` — a deduction's weakest grade is RUMOUR and the
  caller asked for more
- `story_private_field_export` — a public-room post would carry a private
  fleet name, address, or key

Gates:

- A lint gate: every process step named in `docs/agent/*.md` has a passage
  row in `engine/composition/passage_registry.def`. <!-- doc-path-ok: ZRC-0008 design target, not yet in the tree -->
- A test: a deduction with only RUMOUR evidence is reported as a rumour,
  never as a claim, a statistic, or a measurement.

Measurement: token spend per landed line, compared before the walk is
deduced and after it is deduced instead of narrated. The owner's target is
that the after figure is a large reduction of the before figure. The
comparison is the acceptance, not a threshold written here.

## Out of scope

This ZRC does not touch consensus, wallet, or anything under `core/`. It does
not change `zcl_story_event_v1`, `zcl_story_graph_v1`, or `zcl_story_show_v1`;
those remain the read-only causal projection of what happened. It does not
replace the condition/remedy registry; the passage registry copies that
shape. It does not land the public page designed in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md);
it consumes that design for the wiki's public half. It does not introduce
live token economics.

## Landing

Each design item above is one bounded change, and each change lands with the
passage rows that describe it.

- Passage registry, with the landing process mapped. This ZRC is landed with
  that unit.
- Evidence grades and the fact-store prior.
- The `story next` leaf and the named refusals.
- Rumour ingestion, promotion, demotion, and per-source reliability.
- Wiki generation from facts, orient read, and every-node posting; the
  public page remains
  [`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md).
- Fleet replication of passage and fact rows on the board wire.
- Public inter-fleet rooms at RUMOUR grade, with private-field refusal.

## Discussion

Board rows carrying `zrc-0008`, per
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md), until the native
wiki in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
carries the page for it.
