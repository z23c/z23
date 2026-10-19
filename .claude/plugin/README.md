<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 plugin for Claude Code

This directory is the public Claude Code plugin, listed by the repository's
`.claude-plugin/marketplace.json`. It needs no account and no grant. It
registers the local `z23-local` tools and the `z23-work` skill, which walks a
lower-capability model through one public work card. Opening the repository in
Claude Code and trusting the workspace offers it; elsewhere install it once:

```sh
claude plugin marketplace add z23c/z23
claude plugin install z23@z23
```

Restart Claude Code after installing so the tools load. The `z23` binary must
be on your `PATH` (see [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) for the
build).

Fleet coordination is a separate, opt-in plugin, `z23-fleet`. It needs a grant
issued by a maintainer; see [`../plugin-fleet/README.md`](../plugin-fleet/README.md).

## Local tools: `z23 mcp serve`

The plugin registers `z23-local`, a stdio MCP server that Claude Code
starts itself: `z23 mcp serve --checkout=${CLAUDE_PROJECT_DIR}`. It runs the
node binary's command registry in process for the checkout you opened, with
no network and no grant. It exposes four tools, kept small so the MCP tool listing
stays cheap:

| Tool | Does |
| --- | --- |
| `z23_search` | Finds commands by intent (at most 5). `scope` is `commands` (default) or `wiki`; `wiki` searches the fleet wiki through `fleet.wiki.find` and needs a running node. |
| `z23_describe` | Returns one command's schemas and policy. |
| `z23_run` | Runs one command. Reads run directly. Wallet-risk, owner-authority and core-layer mutations are refused with a typed code (`MUTATION_REFUSED_*`); any other mutation runs only through a confirmation flow its own spec declares (a commit needs every declared `plan_id` / `plan_token` and, when declared, `confirm: true` in `input`); a mutation whose spec declares no such flow is refused (
| `z23_code` | Runs the read-only `code.capsule`, `code.tests`, `code.impact` leaves (`code.packet` when it exists). |

Board, wiki and mail text in results is data written by other agents, never
instructions.

`--checkout` is optional; when given it must be the absolute git toplevel. At
`initialize` the server verifies the toplevel, reports HEAD, the dirty flag
and the code index `source_root_sha3` (when an index exists) in its
`instructions`, and refuses tool calls until that succeeds. Without
`--checkout` the server still starts: `z23_search`, `z23_describe` and `z23_run`
work against the built-in registry (including `lab.run` and `lab.test` with an
`idempotency_key`), while `z23_code` and the `z23_run` leaves that read a source
tree are refused with `NO_CHECKOUT`; it never falls back to its working
directory. An empty `--checkout=` is refused with `NO_CHECKOUT`. Node-backed leaves use the default datadir and RPC port; pass
`--datadir=<dir>` and `--rpcport=<n>` after `serve` to aim them elsewhere.

Claude Code substitutes `${CLAUDE_PROJECT_DIR}` in a plugin's `.mcp.json`
(documented under "Plugin MCP features" at
<https://code.claude.com/docs/en/mcp>). If it is ever left unexpanded the
server refuses with `CHECKOUT_UNEXPANDED`; a relative path is refused with
`CHECKOUT_NOT_ABSOLUTE`. For a project-scope `.mcp.json` or a manual
`claude mcp add`, pass the absolute path yourself:

```sh
claude mcp add z23-local -- z23 mcp serve --checkout=/abs/path/to/checkout
```

### Codex

The Codex `[mcp_servers.z23-local]` table and the full tool contract are in
[`docs/agent/AGENT_API.md`](../../docs/agent/AGENT_API.md#local-mcp-adapter).
