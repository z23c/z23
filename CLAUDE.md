# Claude compatibility entry point

Claude is one replaceable coding-agent frontend for Z23. The project
contract is model-neutral; this file intentionally does not duplicate it.

Read, in order:

1. [`AGENTS.md`](./AGENTS.md) — durable product direction, priorities,
   authority boundaries, first commands, and continuation rules.
2. [`docs/work/FORWARD_PLAN.md`](./docs/work/FORWARD_PLAN.md) — current ordered
   development mission.
3. [`docs/DEVELOPING.md`](./docs/DEVELOPING.md) — detailed repository workflow,
   navigation, feedback, tests, integration, and push procedure.
4. On the maintainer host only,
   [`docs/HANDOFF.md`](./docs/HANDOFF.md) — current hosted-node state, which
   must be rechecked through the node's typed status commands.

Use Claude-specific skills or UI integrations only as adapters to those
documents. They do not grant extra consensus, custody, datadir, deployment, or
evidence authority.
