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
  the onion service forwards to), `SOURCE_SHA` of the checkout the node was
  built from.
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

`RESTART_PROD=auto` lets the loop swap the production binary and restart its
systemd unit on new main. That restarts soak clocks; use `manual` on a box
whose production node is mid-acceptance.
