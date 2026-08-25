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
- `<box>.identity` — which installation this box is, so a reader can ask
  whether two publications came from the same machine. `INSTALL_ID` is the
  pin, derived from the box's SSH host public keys; `MACHINE_TAG` separates
  two installs sharing a copied host key; `BOOT_TAG` changes every reboot and
  is what explains a heartbeat gap. Written by `tools/dev/fleet-identity.sh`.

## Install identity

Every value in `<box>.identity` is `sha256(SALT || raw)`. The raw name would be
a hash of the box's SSH host public keys, and publishing that raw is a locator:
internet scan services index host key blobs, so anyone holding scan data could
test a scanned address against the committed file and place a box. Committing
onions instead of clearnet addresses exists to prevent exactly that, and a raw
hostkey hash would quietly undo it. Salting keeps the file a stable pin for
whoever holds the salt and opaque to everyone else.

The salt lives beside the fleet addresses in the uncommitted operator env, and
is applied on the operator's own box — remote boxes never need it:

```sh
# ~/.config/zclassic23-fleetsync/fleet.env   (mode 0600, never committed)
ZCL_FLEET_ID_SALT=<hex>
ZCL_FLEET_NODE1_ADDR=<ssh destination>
```

```bash
tools/dev/fleet-identity.sh init             # once: create the salt
tools/dev/fleet-identity.sh gather --node N  # publish a box
tools/dev/fleet-identity.sh status           # check the whole fleet
```

Pinning is trust on first use: the committed file IS the pin. A changed
`INSTALL_ID` or `MACHINE_TAG` is an `IDENTITY_EVENT` that exits 3 and leaves
the pin untouched — silently rewriting it would erase the one fact worth
reporting. `status` exits 4 when a box was unreachable, so an unchecked fleet
never reports as an agreeing one. Rotating the salt renames every box and
lands as an event on all of them; the salt is configuration, not a secret whose
loss is dangerous.

The claim stays small on purpose: **same install — not same chip, not safe
machine.** It is convenience tier, and nothing in consensus, custody, datadir
handling, or deployment may depend on it. `METAL_TIER` is an optional
owner-gated field that would need a one-time root TPM enrolment; nothing
creates it, nothing waits on it, and its absence is normal.

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

## Cross-box checking

There used to be one designated box that dialed every other box on a timer
and wrote a single pass/fail file that the rest of the fleet was expected to
trust. That job has been retired. Nothing outside a log line ever actually
read the pass/fail file, and running the checker from a box's own working
copy while other work was actively changing that same copy meant the checker
was, at times, judging with code that no longer matched what it claimed to
be judging.

Cross-box checking does not belong to any one box. Every box keeps
validating the chain on its own and publishes what it has directly observed.
Any box that wants to compare notes with the others reads what they
published and checks it against its own copy of the chain — nobody's
published word is taken on faith. A box that goes quiet just means fewer
things could be compared that round; it does not make the others wrong.

The identity files below (`<box>.txt`) are still how boxes learn about each
other. They are plain publications, not judgments.

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
  box has no standing connection to the rest of the fleet at all — it only
  ever meets a peer if something else dials it in first, and that connection
  evaporates on every restart.
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
