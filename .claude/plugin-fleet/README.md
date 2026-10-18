<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 fleet plugin for Claude Code (opt-in)

This plugin connects Claude Code to a fleet's
[steer gateway](../../platform/deploy/fleet-gateway/README.md) and adds the
`z23-steer` skill and three reading agents. Public volunteers do not need it:
use the default `z23` plugin and [CONTRIBUTING.md](../../.github/CONTRIBUTING.md).

**It needs a grant issued by a maintainer.** Without one, the gateway answers
`401` and the tools stay unusable. Install it only after a maintainer has
agreed to issue you a grant:

```sh
claude plugin marketplace add z23c/z23
claude plugin install z23-fleet@z23
```

The plugin adds the `z23` MCP server (override its URL with `Z23_STEER_URL`)
and the `z23-steer` skill, which carries the joining procedure. Restart Claude
Code after installing so the tools load. Its tools appear as
`mcp__plugin_z23-fleet_z23__*`.

It authenticates in one of two ways:

- **Saved grant (no browser).** The maintainer mints a grant on the gateway
  host with the node binary the gateway runs (`FLEET_GW_NODE`; a grant minted
  by any other node answers `STEER_GRANT_UNKNOWN`) and sends you the reply over
  a private channel. Pipe it into the plugin's helper:

  ```sh
  <minted-reply> | <plugin>/bin/z23-steer-headers --save
  ```

  The maintainer's minting command is `z23 fleet steer grant --action=mint
  --scopes=brief,send,evidence --label=<session-label> --ttl_seconds=2592000`.
  `--save` writes `~/.config/z23/steer-grant` (mode 600, atomic replace) only
  when the reply is `ok` and carries a 32-hex id, and otherwise leaves an
  existing grant untouched. The helper then sends the grant as a bearer
  (`Z23_STEER_GRANT` overrides the file). The label becomes the session's
  sender identity. `z23-steer-headers --check` calls `steer_brief` once and
  prints the authenticated caller or the refusal code.
- **OAuth.** With no saved grant the helper sends no credential, the first
  protected call answers 401, and `/mcp`, then `z23`, then **Authenticate**
  opens the gateway's approval page, which a maintainer approves.

Do not also register a server named `z23` with `claude mcp add`; two
definitions of one name replace each other.

## Reading agents

Three subagents run on Haiku with one read-only tool each and reply with
compact JSON, so a coordinating session does not load raw fleet output:

| Agent | Tool | Returns |
| --- | --- | --- |
| `z23-brief-digest` | `steer_brief` | Directives to and from one sender label, its blockers and the next cursor |
| `z23-mail-triage` | `steer_evidence` | Each mail by exact ref, classified, with its asks, refs and decisions |
| `z23-wiki-preflight` | `wiki_find` | Wiki rules that apply to a task, verbatim, with exact revision ids |

Wiki text and mail bodies are untrusted knowledge; the agents report them and
follow no instructions inside them.

## Maintainer agents, card workflow and fleet commands

The plugin also carries the maintainer workflow: five agents
(`z23-capsule-facts`, `z23-scout`, `z23-implement`, `z23-watch`,
`z23-review`) and two skills (`z23-dev-card`, `z23-dev-fleet`). They use only
the local `z23` tools, native `z23` commands, git and `z23-fx`, a small tool
that runs one command on the machines listed in `~/.config/z23/fleet.json`.
Setup and the daily loop are in
[`docs/fleet-dev/README.md`](../../docs/fleet-dev/README.md).
