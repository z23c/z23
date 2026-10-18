# Claude compatibility entry point

Claude is one replaceable coding-agent frontend for Z23. The project contract
is model-neutral; this file only routes.

- **Public volunteer** (you or a human you work for contributes from a fork):
  read [`.github/CONTRIBUTING.md`](./.github/CONTRIBUTING.md) and nothing else
  first. The plugin's `z23-work` skill runs its work-card loop.
- **Maintainer or fleet member:** read [`AGENTS.md`](./AGENTS.md), then
  [`docs/agent/START_HERE.md`](./docs/agent/START_HERE.md). Procedure is in
  [`docs/DEVELOPING.md`](./docs/DEVELOPING.md), consulted by section; ordered
  work is in [`docs/work/FORWARD_PLAN.md`](./docs/work/FORWARD_PLAN.md). On the
  maintainer host only, [`docs/HANDOFF.md`](./docs/HANDOFF.md) holds live node
  state, which must be rechecked through the node's typed status commands.

Skills and UI integrations are adapters to those documents. They grant no extra
consensus, custody, datadir, deployment or evidence authority.
