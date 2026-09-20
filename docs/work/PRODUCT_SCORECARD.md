<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Product workflow scorecard

## Preserved assessment — 2026-09-19

Source: operator-supplied assessment, carried forward on 2026-09-20.
Z23 snapshot: `61cb7b9bbdaaabd02e6833290ce8333a5d7ec5f0`.
These are **provisional judgments, not benchmarks**. Pi and OpenClaw versions
were not supplied and remain UNKNOWN. Their scores are frozen estimates, not
fresh measurements. No score has been increased or decreased here.

Scale: 0 absent/out of scope; 50 partial; 80 strong; 100 exceptional and
thoroughly demonstrated. Rival zeros in rows 17 and 18 mean out of scope,
not broken products. Do not average away gaps.

The baseline evidence and confidence for every row are the operator's
provisional assessment. New evidence must name dated product versions,
source/artifact identities and its exact limitations. Owner entries below
describe known work or lane guidance, not authority over an entire category.
UNKNOWN ownership is not permission to edit.

| Row | Category | Z23 | Pi | OpenClaw | Missing demonstrated workflow | Owner / current scope | Next acceptance |
|---|---|---:|---:|---:|---|---|---|
| 1 | Everyday coding | 50 | 90 | 80 | One useful existing C23 application edit through use of the accepted result | B: coding lane; exact application scope to be agreed | Repeat the same application task with identical inputs, models and budgets; include queue, build, proof, publication and use |
| 2 | Sessions/branching/compaction/steering | 45 | 95 | 80 | Resume, branch and steer a long task without losing its accepted constraints | UNKNOWN | Interrupt and compact a fixed session; resume each branch and verify task state and output |
| 3 | Models/provider switching | 45 | 90 | 85 | Switch an authorized provider while preserving task context and authority | UNKNOWN | Switch providers in the same task; verify continuity, failures, quota reporting and token/cost attribution |
| 4 | Tool discovery/programmatic control | 75 | 90 | 85 | Discover and invoke useful tools through a real client with clear failures | UNKNOWN | Discover schemas, run the fixed workflow, reject invalid input, recover and verify the result |
| 5 | Extensions/reusable tools | 40 | 90 | 80 | Reuse a supported extension/tool through the complete application task | UNKNOWN | Run equivalent tasks with supported extensions enabled and versions recorded |
| 6 | Persistent memory/recall | 40 | 55 | 80 | Recall an authorized prior decision after restart without stale or private-data leakage | UNKNOWN | Seed, revise and revoke fixed facts; restart and verify recall, provenance and access boundaries |
| 7 | Messaging/email/calendar | 20 | 20 | 80 | Complete an authorized communications workflow with a verifiable result | UNKNOWN | Use consenting fixture accounts to read, draft, explicitly authorize and reconcile a duplicate send |
| 8 | Browser/web automation | 15 | 25 | 80 | Complete a permitted browser task and recover from interruption | UNKNOWN | Exercise a fixed local site, changed page state and restart; verify the final user-visible state |
| 9 | Phone/voice/devices | 10 | 25 | 70 | Complete an authorized device workflow on a real supported device | UNKNOWN | Record supported device/version, perform the fixed request and verify acknowledgment and recovery |
| 10 | Scheduled/proactive work | 40 | 30 | 75 | Authorized scheduled work survives restart and runs only as permitted | UNKNOWN | Miss a scheduled acknowledgment, restart and reconcile the existing action without duplicate execution |
| 11 | Multi-machine coordination | 55 | 35 | 70 | Replicated task continues after submitter loss without human relay | A: continuity; remote source claims must be checked | Qualify bilateral routes, replicate complete inputs, remove submitter and verify peer resumption |
| 12 | Install/update/cross-platform UX | 40 | 85 | 75 | Real launch, update, saved work, restart and rollback on each platform | C/D lane guidance; exact source claims must be checked | Run shipping Linux/Mac/Windows artifacts separately; preserve and reopen a real saved application result |
| 13 | Status/failure recovery | 50 | 70 | 80 | Received/running/failed/published states and lost acknowledgments reconcile correctly | A: current landing-preparation slice; product recovery next | Restart receiver after acceptance but before acknowledgment; redeliver exact action and require one accepted result |
| 14 | Permissions/isolation | 65 | 35 | 75 | Real denied and revoked operations remain denied across restarts | UNKNOWN | Exercise scoped grants, revocation, stale evidence and hostile fixture inputs on each qualified platform |
| 15 | Local ownership/vendor independence | 80 | 90 | 90 | Useful accepted application remains usable after agent/vendor disappearance | A continuity lane; exact application owner pending | Remove submitter and block GitHub within the isolated demonstration; finish from durable peer objects |
| 16 | Required code-acceptance evidence | 75 | 35 | 55 | Complete independent proof binds the exact useful result accepted by a receiver | A integration slice; C independent verification lane | Reject wrong source/toolchain/artifact bindings and accept only the independently reproduced exact result |
| 17 | Private P2P software distribution | 65 | 0 | 10 | Peers distribute and a receiver explicitly accepts, runs and rolls back an exact application | A continuity / C verification / D receiver lane guidance | Use independent acceptance with submitting agent gone and GitHub blocked; verify CAS transfer, acceptance, launch and rollback |
| 18 | Shielded payments/file commerce | 60 | 0 | 0 | Authorized commerce completes and recovers with custody preserved | UNKNOWN; separate custody authority required | Use isolated permitted fixtures to verify payment/delivery/refund or recovery invariants; no production funds or keys |

## Comparison protocol v1 — recorded 2026-09-20

This protocol preserves the assessment; it is not evidence that a comparison
has run. Before each run, publish a fixed task packet containing the exact
application/source, input data, expected user-visible result, failure cases,
product and extension versions, model/version, budgets, hardware/platform,
network restrictions, cache state and repetition count. A missing binding
keeps that run ineligible for a comparative score claim.

Use matched models and budgets and comparable conditions. Include supported
extensions and disclose their setup and maintenance requirements. Do not
quietly restrict a rival's supported workflow or lower its frozen estimate.
Recheck rival versions and capabilities before new comparisons. Retain this
baseline and all contrary observations when publishing a dated revision.

Report every row separately. Record successes, failures, timeouts, incomplete
observations, model time, queue time, build time, proof time, publication time,
launch/use time, total elapsed time, token counters, actual cost where known,
and every human rescue. Subscription status does not establish zero cost or
unlimited capacity; list-price estimates are not actual charges. UNKNOWN is
an explicit result, not zero.

Independent verification must reproduce the expected behavior and verify exact
source, toolchain, platform, artifact and authority bindings. A hash or
signature alone does not prove correctness. Unit passes, LOC and commits do
not raise scores. A score change requires repeatable end-to-end evidence and
an explicit dated assessment. No comparison scores have changed in this file.

The shared fabric demonstration uses one agreed useful change to an existing
C23 application. Replicate its authorized signed task and complete inputs to
consenting qualified peers. Remove the submitting agent and block GitHub only
inside the isolated demonstration. Remaining peers build, independently verify,
distribute and let a receiver explicitly accept and run the exact result;
exercise rollback. No mandatory director, central build queue or human relay
may be required by this product journey. Main's development landing gates
remain mandatory and separate.

## Engineering observations — not score changes

- On 2026-09-20 the landing diagnostic and explicit lint-gate deduplication
  slice was independently fetched on origin at
  `a115621056bd31fc21a22b22630b89d0f6f6963a`. Native exact proof status validated
  its receipt against base `61cb7b9bbdaaabd02e6833290ce8333a5d7ec5f0`.
  Queue admission to observed publication was 50 minutes 13 seconds, including
  a stale-base retry. This is a lifecycle observation, not a speedup benchmark.
- The follow-up preparation job-policy candidate
  `26f135515d70a8c1ec166cfe5d5e19a5c2867908` had a failing registered witness,
  passing focused/affected tests, build/lint/generated checks and non-author
  source review before queue admission. Publication and matched performance
  evidence remain OPEN at this entry's creation.
- A 20-sample warm `resident-a` status observation had outer CLI p95 90.452 ms.
  Its empty task and missing evidence-age/next-action fields do not establish
  useful complete status. A/B/C/D identity bindings and available pool capacity
  were not verified. This sample does not satisfy row 13.
- Existing pinned A/B routes passed authenticated bounded commands and exact
  harmless object transfers in both directions. A coordination message was
  observed at B within 28 seconds; a later exact-ref reply acknowledged it.
  This does not establish submitter-loss or receiver-restart product acceptance.
