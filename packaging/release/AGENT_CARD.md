# What this node offers a program

You (a coding assistant, or any other program) just installed `z23`. This is
what changed: you now have a local process that independently verifies a
public blockchain, holds keys, and talks to a peer-to-peer network — none of
which you can do by reasoning alone. You still do the reasoning; the node
does the verifying.

This card ships alone, next to the three binaries, in a release directory
with no checkout nearby -- so it does not link to other files; nothing at
those paths exists next to it. The full command-tree contract is the file
docs/NATIVE_COMMAND_INTERFACE.md in the Z23 source repository, if you have
that checked out. If you do not, you do not need it: `z23 discover help`
and `z23 discover schema <path>` below are the running node describing its
own interface live, which is the more reliable copy anyway.

## Talk to it

```
z23 [branch ...] [leaf] [--options]
```

Every leaf takes flags or `--input='{"json":"object"}'`. Start here:

```bash
z23 status                        # one line: is it healthy, synced, spendable
z23 discover help                 # the whole command tree, one level at a time
z23 discover search "<text>"      # find a command by what it does
z23 discover schema <path>        # exact input keys for one command, e.g. core.chain.block.get
```

`discover help`/`search`/`schema` are self-describing — call them before
guessing a command's arguments.

## Commands worth calling first

| Command | Returns |
|---|---|
| `z23 status` | One `key=value` line: sync state, wallet readiness, next action |
| `z23 core status` | Full chain state: height, peers, active blockers |
| `z23 core chain tip` | Current best block: hash, height, work, difficulty |
| `z23 core chain block get --height=<n>` | One block by height or hash |
| `z23 core sync blockers` | What, if anything, is stopping sync from advancing, and why |
| `z23 core network peers list` | Who this node is actually connected to right now |
| `z23 core wallet status` | Balance, key counts, whether the wallet is unlocked |
| `z23 vault list` | Everything this node owns, one row per asset class |
| `z23 ops health` | Bounded health check for scripted polling |
| `z23 zcode package verify --input='{"root":"<hex>"}'` | Whether a package's claimed bytes match a quorum of independent verifiers |

Every response is a JSON object (`"schema":"zcl.result.v1"` for an executed
leaf, `"schema":"zcl.command_menu.v1"` for a branch). Add `--view=summary` or
`--max-items=<n>` to bound a large result instead of parsing around it.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Passed or accepted |
| 1 | Executed and failed |
| 2 | Invalid input or unknown command |
| 3 | Blocked by a named precondition |
| 4 | Authentication or capability denied |
| 5 | Transiently unavailable |
| 6 | Internal contract failure |

Check the exit code before parsing output. A non-zero exit means the JSON,
if any, describes a refusal, not a result.

## What only the node can do

An assistant can write and reason about code, but it cannot:

- **Verify the chain itself.** `z23 core status` and `z23 core chain tip`
  report state this node validated against consensus rules by running the
  code, not state it was told. Nobody vouches for it.
- **Hold keys and sign.** Wallet and spend operations (`core wallet`,
  `vault send`, `vault send-shielded`) are marked `risk:"wallet"` in the
  registry and run inside the node's own process. Route spending through
  them instead of generating or handling private keys yourself.
- **See the live peer-to-peer network.** `z23 core network peers list` and
  `z23 core sync blockers` report what this node is observing right now —
  information that does not exist in any training data or static file.
- **Check a package against independent verifiers.** `z23 zcode package
  verify` reports whether other nodes that rebuilt a package from source
  reached the same bytes — a check an assistant cannot perform on its own
  output.
