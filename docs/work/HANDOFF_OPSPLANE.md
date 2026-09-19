<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# C23 visibility handoff

Updated 2026-09-19. Resume the existing `opsplane` lane on branch
`lane/opsplane-consolidated`; use `devworker where z23 opsplane` to locate it.
Read the host operations policy and checkout agent contract first. Preserve
one writer, use the shared build scheduler, and fetch main before integration.

## Committed work

The cleanup checkpoint is `9de6234e5`, following status correctness and CLI
service-discovery reuse in `01bb259f9`, read-only storage and candidate report
fixes in `92b657504`, and integration of main `5e444b756` in `6e15618d9`.
Current HEAD also carries the final portability and documentation corrections.
Use Git and the exact proof receipt for current publication state.

- Worker status distinguishes absent evidence from unreadable evidence and
  validates the claim's task, attempt, worker, session and submitted fields.
- CLI service discovery captures one observation per invocation.
- Brief, mail pull and queue status leave missing directories absent. Pool
  status probes existing locks without creating them.
- Candidate identities retain the full supported ref. Sender storage is
  bounded; incomplete inventories report unknown totals. Test and publication
  reports remain separate from remote verification. Sender count is not proof.
- Build refusals expose an error diagnostic despite leading make warnings.
  Fixtures initialize storage explicitly instead of relying on status writes.

Two independent agents reviewed the changes; one writer applied them.

## Evidence and publication

At checkpoint `9de6234e5`, the 20 devagent test groups passed with no skips
(86.8 seconds), the steering group passed, and all 32 fast lint checks passed.
The first exact proof selected 84 groups: 83 passed and one failed because its
source-contract test expected the old CLI service call. Full lint also exposed
missing Windows declarations/descriptor flags, an absent file-purpose marker,
and stale wording in this handoff. Those findings prompted the final fixes;
they are not a passing exact receipt.

Read `dev proof status` for the current commit/base pair. Push only after its
passing receipt, then verify the exact remote SHA. Do not edit proof generations
or receipts, bypass hooks, or run another build in this checkout during proof.
The originating session retained red and green logs in its Linux acceptance
artifact directory and prepared a separate detailed handoff for direct transfer.

## Remaining acceptance

The actual external-client submission/progress/verified-result journey remains
incomplete. Local fixture passes and delivery reports do not prove publication.
The last measured warm full-CLI status p95 was 116.9 ms over 100 calls at an
older checkpoint; the target below 100 ms was not met. Remeasure the final binary.

Then exercise failed execution, duplicate delivery, restart, and stale/missing
progress through the actual client. Improve existing steer/cancel acknowledgment
and terminal outcomes next. Coordinate directly through existing native objects;
claim bounded scope and do not duplicate another developer's executor or landing
work. Production deployment and service activation remain separately authorized.

## Preserve during cleanup

Preserve signed C6 `3b112abab` and its completed handoff; do not resubmit its
landing request. Leave unrelated main-checkout work, canonical nodes, wallets,
verified archives and repository-managed proof/build caches intact. Retain the
current evidence. No blanket sweep or production restart belongs to this handoff.
