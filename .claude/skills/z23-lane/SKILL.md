---
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
name: z23-lane
description: Use when assigning or reviewing parallel Z23 work. Keeps file ownership disjoint, derives the current origin/main baseline, and returns immutable commit identities without duplicating the canonical development contract.
---

This compatibility skill contains no independent workflow doctrine. Read
[`AGENTS.md`](../../../AGENTS.md) and
[`docs/DEVELOPING.md`](../../../docs/DEVELOPING.md), then use the compact
parallel-assignment adapter in
[`docs/agent/LANE_LAUNCH.md`](../../../docs/agent/LANE_LAUNCH.md).

Worktree layout is not workflow authority. Current state comes from
`git worktree list --porcelain`. Canonical product identities are defined by
the existing CAS and build-fabric types; the current local Git proof queue is
transitional and filesystem-backed. `origin/main` is the shared integration
blackboard. The resident signed-commit promoter is not implemented yet; do not
claim that a lane handoff automatically proves or publishes code.

@docs/agent/LANE_LAUNCH.md
