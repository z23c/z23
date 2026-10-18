<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel assignment adapter

This page adds dispatch and handoff mechanics. Authority remains in
[AGENTS.md](../../AGENTS.md); exact build, integration, and publication
procedure remains in [DEVELOPING.md](../DEVELOPING.md).

## Dispatch

1. Inspect existing worktree and
   component ownership before assigning work (on a managed host, read its policy
   and inspect the assigned lane first). Preserve dirty work and leases.
2. Record the full fetched `origin/main` commit. Give each worker a disjoint
   path contract and a concrete acceptance. Commands, Makefile, impact rules,
   and generated catalogs each need one primary writer.
3. Reuse an owned lane. When isolation is required, prepare a separate lane
   through the native `dev lane new` route under `devbuild --wait`, with an
   exact base and receiver-approved path. Do not replace a refusal with raw
   worktree creation or copied build outputs.
4. Establish native file claims before editing. Renew them before expiry and
   release them when a clean checkpoint is ready. A claim controls source
   writers; it does not authorize proof acceptance, deployment, or publication.
5. For distributed work, qualify authenticated bounded commands and exact
   object transfers in both directions. Preserve receiver concurrency and
   workspace policy; keep credentials local and endpoints out of coordination.
6. Pass a compact mission capsule:

   ```text
   NORTH STAR
   USER OUTCOME
   CURRENT BASELINE
   OWNED SURFACE
   INVARIANTS
   ACCEPTANCE
   CONTINUATION QUEUE
   ESCALATE ONLY IF
   ```

## Shared-store safety

Never stash, reset, rebase, or remove another worker's worktree. Never infer
ownership from a directory name or assume a missing directory makes a lease
safe to delete. Inspect Git registration, native claims, and current ownership.
Keep isolated test datadirs separate from canonical node state. Heavy work uses
`devbuild --wait`; services, timers, watchers, and nodes remain disabled unless
explicitly authorized.

## Handoff and integration

Return the exact signed commit, baseline, owned diff, literal acceptance, and
unresolved items using [LANE_REPORT.md](LANE_REPORT.md). A non-author reviews
the complete slice. Any authorized worker may then use the existing native
receipt-gated landing route; an agent identity or permanent lead is not an
acceptance authority. Fetch current `origin/main`, preserve queue items and
leases, rerun affected gates, and independently verify the resulting remote
commit. A queued request, board post, or handoff is not a publication receipt.

The local Git landing queue is filesystem-backed. It does not establish a
complete decentralized signed-commit promoter or authorize deployment.
Reclaim worktrees only through qualified native maintenance with exact
ownership and preservation checks. Unknown pushes require reconciliation;
never redispatch them merely because the original worker is absent.
