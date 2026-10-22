---
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
name: z23-lane
description: Use when assigning or reviewing parallel Z23 work. Keeps file ownership disjoint, derives the current origin/main baseline, and returns immutable commit identities without duplicating the canonical development contract.
---

This compatibility skill contains no independent workflow doctrine. Read
[`AGENTS.md`](../../../AGENTS.md), [`docs/THE_Z23_WAY.md`](../../../docs/THE_Z23_WAY.md) and
[`docs/dev/DEVELOPING.md`](../../../docs/dev/DEVELOPING.md), then use the compact
parallel-assignment adapter in
[`docs/agent/LANE_LAUNCH.md`](../../../docs/agent/LANE_LAUNCH.md).

Worktree layout is not workflow authority. Current state comes from
`git worktree list --porcelain`. Canonical product identities are defined by
the existing CAS and build-fabric types; the current local Git proof queue is
transitional and filesystem-backed. `origin/main` is the shared integration
blackboard. Use native lane and file-claim tools, renew leases, preserve
other owners, and run heavy work through `devbuild --wait`. No permanent lead
is required; eligible authorized workers use the existing native receipt-gated
landing route after non-author review. A lane handoff or queued request is not
publication. The local Git queue does not establish the complete decentralized
signed-commit promoter. Services and watchers remain operator opt-in.

@docs/agent/LANE_LAUNCH.md
