# devfleet box contract

Each fleet box keeps main moving in one direction: every box self-syncs from
`origin/main`, reports its own state here, and reads the other boxes' files
instead of polling them live. `origin/main` is the shared blackboard.

## Files per box

- `<box>.txt` — static identity: `BOX`, `ONION_ADDRESS`, `P2P_ENDPOINT`,
  `SOURCE_SHA` of the checkout the node was built from.
- `<box>.env` — instance configuration consumed by
  `tools/scripts/fleet_sync.sh` (datadirs, ports, launch flags, production
  unit/binary, restart policy).
- `<box>.sync` — heartbeat written by the sync loop: last synced SHA, node
  liveness, peer count, last action, named error if any.
- `<box>.status` — on-demand evidence (for example cross-host round-trip
  results), written by whoever ran the drill.

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
