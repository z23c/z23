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
  the onion service forwards to), runtime `SOURCE_SHA`, and mandatory 40-hex
  `GIT_SHA`. These are separate claims: `SOURCE_SHA` identifies running bytes;
  `GIT_SHA` alone provides ancestry and commit time. A 40-hex legacy runtime
  identity is never guessed to be a Git object.
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
2,7,12,17,22,27,32,37,42,47,52,57 * * * * FLEET_MESH_GIT_MODE=local /path/to/referee-checkout/tools/scripts/fleet_mesh_acceptance.sh node1 >> ~/.local/state/zclassic23-fleet-mesh.log 2>&1
```

An explicit publish-mode cycle first reconciles `origin/main`; the default
local-only timer fetches the remote-tracking ref without moving its exact
pinned referee checkout. Each cycle validates
`node1.txt` through `node4.txt`, then dials the hub's own published onion from
a fresh mainnet instance in an audited throwaway `/tmp` datadir. The hub counts
only when that external path reaches VERSION/VERACK; its long-running process
is never used as its own self-probe. The referee then dials every missing
remote peer through its published onion endpoint from the long-running
isolated node. A remote peer counts only after the P2P state machine reaches
`active` (VERSION/VERACK complete) and its handshake height matches the
isolated node's tip at the start or end of that bounded observation.

`mesh.status` records every node's published `SOURCE_SHA`, `GIT_SHA`, commit
date, and exact commit distance. Every cycle stamps `NODE*_CURRENT=yes|no`,
`NODE*_STALE=yes|no`, and `NODE*_SOURCE_STATUS=CURRENT|STALE`. `CURRENT` means the
bound commit exists, is an ancestor of the observed `main`, and includes the
required onion baseline. Missing, malformed, foreign, unbound, and pre-floor
identities fail closed to `STALE`; commit time is `UNKNOWN` only when Git
cannot authoritatively resolve one. `NODE*_STALE_SOURCE=yes` is the compatible
legacy flag for a source that predates
`355808b13b704624927d9c997a1d5677f17486f6`. An authoritative runtime
`source_id_sha256` cannot be ordered against Git without `GIT_SHA`,
so an unbound publication is `STALE` rather than guessed. A stale publication
is a named mesh gap. Missing or malformed publications, a
failed fresh self-dial, refused remote dials, incomplete handshakes, and height
mismatches are also named. The script exits zero only on a 4/4 observation.
After two such observations at least four minutes apart it records `HOLD=pass`,
but later timer invocations continue refreshing source facts. The first 4/4
cycle atomically preserves the full status as
`deploy/devfleet/mesh.first-4of4.status`; later cycles never overwrite it.
The loud combined field is `NODE*_SOURCE_STAMP=CURRENT:<commit-date>` or
`STALE:<commit-date>` (`UNKNOWN` only for an unresolved object). Node2 also
carries a consecutive-silence clock. Its second silent observation emits a
timestamped `NODE2_REASSIGNMENT_RECORD=SILENT_PAST_TWO_CYCLES:...`; an active
observation resets the clock.

Node2 additionally gets one fresh inbound proof per cycle: a new process with
an empty isolated datadir dials node2's published onion. The latest result is
`NODE2_FRESH_INBOUND`; the first successful VERSION/VERACK edge is retained in
`NODE2_FIRST_REAL_PEER_EDGE_AT` and `NODE2_FIRST_REAL_PEER_EDGE_DETAIL`.

Connman starts before the frontend Tor service. Once this boot's dynhost
service yields its onion address, outbound peer streams become dial-ready and
may queue while local descriptor publication continues. Inbound reachability,
the public onion-ready status, and systemd `READY=1` remain gated on successful
descriptor publication.

The referee defaults to `FLEET_MESH_GIT_MODE=local`. Its detached checkout may
update local status and first-pass evidence, but recurring telemetry does not
commit, push, move `main`, or change product source identity. Publishing a
reviewed snapshot is a separate manual product-history action.

The recurring onion pair ledger follows the same rule: absent an explicit
`PAIR_PROBE_FILE`, it writes
`${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-referee/pair_probe.jsonl`.
Historic accepted rows remain recoverable from Git history, but a timer must
not append a source commit for telemetry.

The mesh gate never installs a binary or signals either node. In particular,
it has no production-unit code path; production restart authority remains
solely in the separately configured sync loop.

The sync and mesh loops serialize on the same per-box lock. If a prior push
failed, the mesh loop may recover only commits whose complete changed-path set
is `mesh.status` and this box's `<box>.sync`; any other local commit or tracked
edit remains a named source-sync refusal.

## Supervising the node (required)

The sync loop used to launch the node with a bare `setsid nohup`. Nothing
restarted it when it died, nothing recorded why, and the launcher redirected
with `>` so each restart destroyed the log of the crash it was restarting from.
A box whose node only runs until its first crash cannot hold a mesh together.

Each box runs its node under `deploy/zcl23-devfleet@.service` instead:

```bash
install -m644 deploy/zcl23-devfleet@.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zcl23-devfleet@<box>.service
systemctl --user status zcl23-devfleet@<box>.service
```

`Type=notify` matters: the node holds `READY=1` until its onion descriptor is
actually published, so `active` means the box is reachable at its `.onion`, not
merely that a process exists. `WatchdogSec=120` converts a silent hard wedge —
previously indistinguishable from a healthy node — into a bounded restart.

Two settings need care:

- **Pin the other boxes' onions.** Add one `-addnode=<onion>:<port>` per peer to
  `DEVFLEET_FLAGS` in `~/.config/zclassic23-fleetsync/<box>.env`. Without them a
  box's only mesh edges are the referee's per-cycle RPC injections, which
  evaporate on every restart — and a box the referee never reaches is never
  dialed at all.
- **Do not shrink the memory envelope.** `MemoryHigh` equals `MemoryMax` on
  purpose: a soft limit below the real need is a thrash zone, not a diet. Boot
  peaks near 19G running `sqlite.quick_check` after an unclean shutdown, against
  a steady state near 2.8G.

A box whose checkout is not at `~/github/zclassic23`, or whose devfleet datadir
is not `~/.zclassic-c23-devfleet`, overrides those lines with
`systemctl --user edit zcl23-devfleet@<box>`. systemd expands `${VAR}` only in
`Exec*` lines — in `ReadWritePaths=` and `StandardOutput=` a variable is
silently dropped, which yields no sandbox and a silent fallback to the journal.
Verify with `systemctl --user show <unit> -p ReadWritePaths -p StandardOutput`.
