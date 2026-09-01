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

Two different flag styles coexist and mixing them up produces
`UNRECOGNIZED_FLAG`: the small set of *connection* flags — `-datadir=DIR`,
`-rpcport=PORT`, `-port=PORT`, `-httpsport=PORT`, `-fsport=PORT`,
`-operator-lane=NAME`, `-profile=NAME` — take a single dash; every
*per-leaf* argument (`--input=`, `--view=`, `--max-items=`, and named leaf
flags like `--height=` or `--address=`) takes a double dash. Get `-datadir`
wrong and the command never runs at all.

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
| `z23 zcode package verify -datadir=$HOME/.zclassic-c23 --input='{"root":"<hex>"}'` | Whether a package's claimed bytes match a quorum of independent verifiers |

Every response is a JSON object (`"schema":"zcl.result.v1"` for an executed
leaf, `"schema":"zcl.command_menu.v1"` for a branch). Add `--view=summary` or
`--max-items=<n>` to bound a large result instead of parsing around it.

## Bring the owner's C23 source onto this machine, without Git

There is no Git remote here. Source moves as ZVCS bundle files and, over the
peer network, as content-addressed packages — verified because the bytes
rehash to a root you already hold, never because you trust who sent them.

If you already have a `.zvsb` bundle file and its 64-hex source root (handed
to you directly, out of band — this step never touches the network):

```bash
z23 zcode workspace source bundle verify --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>"}'
z23 zcode workspace source bundle checkout --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>","workspace":"/tmp/zvcs-scratch","destination":"/tmp/source-scratch"}'
```

`verify` rehashes every blob and the tree root and writes nothing.
`checkout` repeats that check before writing, then materializes the exact
files into an *existing empty* destination — `create` and `import` are the
other two leaves in this family (`z23 discover schema
zcode.workspace.source.bundle.create`). None of the four take a `datadir`;
they are plain, local files.

To pull source over the P2P network instead, by root alone, first get a node
running with `-packagehost=1` (`z23 join` writes that flag, then restart the
node) and, if you already know a peer, tell it directly:

```bash
z23 core network peers add --address=<ip:port|v3.onion>
z23 zcode package fetch --input='{"datadir":"<datadir>","root":"<64hex-package-root>"}'
```

`fetch` takes a package root, not a peer — it pulls from whoever is already
connected and advertising that root, SHA3-verifying every chunk against the
root-committed manifest before it touches disk. Run against a node that
isn't hosting, it only persists a resumable record under
`<datadir>/zcode/downloads/<root-hex>`; a live `-packagehost=1` node is what
actually moves bytes.
`z23 zcode package library --input='{"datadir":"<datadir>"}'` lists what this
node has already reproduced, and names its own `next_command` when it has
nothing.

Once the package is present, reconstruct verified source from it:

```bash
z23 zcode workspace source package checkout --input='{"datadir":"<datadir>","package_root":"<64hex>","source_root":"<64hex>","accepted_work_root":"<64hex>","workspace":"/tmp/zvcs-scratch","destination":"/tmp/source-scratch"}'
```

This needs three roots, not one: the package root, the source tree root
inside it, and the accepted-work root it was published under — it
re-verifies the whole acceptance chain, not just the bytes.

### When a source root is all you have

If someone handed you a 64-hex source root and one or more serving peer
addresses, ask those peers for it directly:

```bash
z23 zcode workspace source bundle fetch --input='{"source_root":"<64hex>","output":"/tmp/source.zvsb","peers":"<ip:port>,<ip:port>"}'
z23 zcode workspace source bundle checkout --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>","workspace":"/tmp/zvcs-scratch","destination":"/tmp/source-scratch"}'
```

The peers are hints about who to ask, not who to trust. What arrives is
accepted only because it rehashes to the root you asked for, so a peer
that lies can waste your time and nothing else — a bundle that does not
rederive to that root is refused and no file is written. On the other
side of this, `publish` is how a machine offers its own workspace and
prints the root to hand over.

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
