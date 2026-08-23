# devfleet box contract

Each fleet box keeps main moving in one direction: every box self-syncs from
`origin/main`, reports its own state here, and reads the other boxes' files
instead of polling them live. `origin/main` is the shared blackboard.

Boxes are named with neutral IDs — `node1`, `node2`, `node3`, `node4` — never
hostnames, usernames, or DNS names.

## Privacy rule

**Committed files never contain clearnet IP addresses, hostnames, usernames,
or local filesystem paths.** Onion addresses are the committed network
identity: they are the censorship-resistant endpoint and reveal nothing about
location. Everything operator-specific lives in the box's local uncommitted
env at `~/.config/zclassic23-fleetsync/<box>.env` (see below). The
`deploy/devfleet/*.env` path is gitignored; do not commit one.

## Files per box

- `<box>.txt` — static identity: `BOX`, `ONION_ADDRESS`, `P2P_PORT` (the port
  the onion service forwards to), and `SOURCE_SHA`. Legacy publications use a
  40-hex Git commit; exact runtime publications use the binary's authoritative
  64-hex `source_id_sha256`.
- `<box>.sync` — heartbeat written by the sync loop: last synced SHA, node
  liveness, peer count, last action, named error if any.
- `<box>.status` — on-demand evidence (for example cross-host round-trip
  results), written by whoever ran the drill.

## Local env (uncommitted)

`~/.config/zclassic23-fleetsync/<box>.env` holds the operator-only values:

```sh
BOX=nodeN
DEVFLEET_DATADIR=/absolute/path/to/datadir
DEVFLEET_PORT=8055
DEVFLEET_RPCPORT=18255
DEVFLEET_FLAGS="-operator-lane=test -listen -tor -onion-persist -txindex -showmetrics=0"
PROD_UNIT=your-node.service      # optional; production auto-update
PROD_BIN=/absolute/path/to/live-binary
RESTART_PROD=auto                # or manual
PUSH_HEARTBEAT_SECONDS=1800
```

## Sync loop

On each box, after cloning and `make setup`:

```bash
make -j"$(nproc)"
tools/scripts/fleet_sync.sh <box>    # one manual run to validate
```

Then install a crontab entry (offset the minute per box):

```
4,19,34,49 * * * * /path/to/checkout/tools/scripts/fleet_sync.sh <box> >> ~/.local/state/zclassic23-fleetsync.log 2>&1
```

The loop fast-forwards to `origin/main`, rebuilds when HEAD moved, restarts
stale or dead instances, and pushes `<box>.sync` when state changes or the
heartbeat is older than `PUSH_HEARTBEAT_SECONDS`. It fails closed: a dirty or
diverged checkout, a failed build, or a failed restart is recorded as a named
`SYNC_ERROR` and never force-resolved.

Fleet commits use the checkout's configured Git author and email. Configure an
email associated with the operator's GitHub account when profile attribution
and its avatar are required; the box identity remains explicit in the commit
message and the committed record.

`RESTART_PROD=auto` lets the loop swap the production binary and restart its
systemd unit on new main. That restarts soak clocks; use `manual` on a box
whose production node is mid-acceptance.

## Onion mesh acceptance

The designated hub runs the mesh gate every five minutes, offset from its
sync loop:

```
2,7,12,17,22,27,32,37,42,47,52,57 * * * * /path/to/checkout/tools/scripts/fleet_mesh_acceptance.sh node1 >> ~/.local/state/zclassic23-fleet-mesh.log 2>&1
```

Each cycle pulls `origin/main`, validates `node1.txt` through `node4.txt`, and
first dials the hub's own published onion from a fresh mainnet instance in an
audited throwaway `/tmp` datadir. The hub counts only when that external path
reaches VERSION/VERACK; its long-running process is never used as its own
self-probe. The referee then dials every missing remote peer through its
published onion endpoint from the long-running isolated node. A remote peer
counts only after the P2P state machine reaches `active` (VERSION/VERACK
complete) and its handshake height matches the isolated node's tip at the
start or end of that bounded observation.

`mesh.status` records every node's published `SOURCE_SHA`, its identity kind,
and whether it is stale against the observed `main`. Git identities carry the
exact commit distance. `NODE*_STALE_SOURCE=yes` is the hard acceptance flag
for a Git source that predates
`355808b13b704624927d9c997a1d5677f17486f6`. An authoritative runtime
`source_id_sha256` cannot be
ordered against Git without a separate binding, so its staleness is explicitly
`unknown` rather than guessed. Staleness is evidence, not by itself a mesh
failure: a Git source that is still in main history and includes the required
onion-P2P baseline may interoperate. A missing, invalid, foreign, or pre-onion
Git source remains a named hard gap. Missing or malformed publications, a
failed fresh self-dial, refused remote dials, incomplete handshakes, and height
mismatches are also named. The script exits zero only on a 4/4 observation.
After two such observations at least four minutes apart it records `HOLD=pass`,
and later timer invocations leave that acceptance evidence untouched.

The mesh gate never installs a binary or signals either node. In particular,
it has no production-unit code path; production restart authority remains
solely in the separately configured sync loop.

The sync and mesh loops serialize on the same per-box lock. If a prior push
failed, the mesh loop may recover only commits whose complete changed-path set
is `mesh.status` and this box's `<box>.sync`; any other local commit or tracked
edit remains a named source-sync refusal.
