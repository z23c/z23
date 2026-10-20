<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Lane quickstart

The operating contract is [AGENTS.md](../../AGENTS.md); the exact build,
review, and native publication procedure is [DEVELOPING.md](../dev/DEVELOPING.md).
Dispatch: [LANE_LAUNCH.md](LANE_LAUNCH.md). Report:
[LANE_REPORT.md](LANE_REPORT.md).

1. Inspect the checkout, native
   ownership, dirty files, leases, and exact `origin/main` (on a managed host,
   read its policy and inspect the assigned lane first). Resume owned work
   in place; never manufacture a replacement queue or overwrite another lane.
2. If independent work needs another checkout, use the native `dev lane new`
   route under `devbuild --wait`, or `git worktree add -b lane/NAME` at the
   fetched `origin/main` under the host's development scratch root. Preserve
   a refusal and any partial lane; never bypass a refusal by copying
   dependencies or build outputs.
3. Claim the concrete source paths with `dev agent claim`. Record and renew
   `expires_unix`; stop writing after expiry until the claim is renewed.
4. Ask the built code navigator for source ownership and registered tests.
   Run the affected acceptance under `devbuild --wait` using the repository
   presets. Record executed, reused, failed, skipped, and unrun evidence.
5. Run the required lint and generated-artifact gates. Freeze source while a
   build, proof, or script reads it. Services and watchers stay disabled.
6. Commit normally, verify the signature under local trust policy, and hand
   the exact commit to a non-author reviewer. Release file claims once the
   clean checkpoint is stable; reacquire before further edits.
7. Authorized workers may drive the native receipt-gated landing route.
   Coordination does not require a permanent lead. Preserve other queued
   items and leases, and reconcile unknown pushes instead of redispatching.
   Independently verify the exact `origin/main` after native publication.

Report:

```text
head <full-sha>, base <full-sha>, acceptance <green|red|partial>,
ready for review | needs <exact condition>
```

A claim, clean worktree, or successful exit alone is not proof of completion.
