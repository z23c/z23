# Running your own mesh

This project designates no fleet. There are no privileged machines, no
blessed peers, and no operator state in this repository — a clone is the same
for someone running one node on a laptop as for someone running twenty in a
rack. What follows is a guide for anyone who wants several machines of their
own to follow `main` and peer with each other.

Everything specific to your machines stays on your machines. Nothing in this
directory is ever written by a running box: it holds this page and the
`.example` templates beside it, and nothing else.

## Where your state lives

```
~/.config/zclassic23-fleetsync/<box>.env      # per-box configuration
~/.config/zclassic23-fleetsync/fleet.env      # identity salt + ssh addresses
${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23/fleet/
    <box>.txt        # what this box publishes: onion address, P2P port,
                     # running SOURCE_SHA, and a 40-hex GIT_SHA
    <box>.sync       # what the sync loop last observed
    <box>.status     # on-demand evidence, written by whoever ran a drill
    <box>.identity   # install pin (see below)
```

A "box" is whatever you call one of your machines — the label is a plain
name you choose, used only as a filename and a log prefix. Tools that read
this directory print `no local mesh configured` and exit 0 when it is empty,
which is what a fresh clone sees.

`<box>.txt` carries two separate claims that must never be conflated:
`SOURCE_SHA` identifies the bytes a daemon is running, `GIT_SHA` is a Git
commit and is the only thing that provides ancestry. A 40-hex runtime
identity is never guessed to be a Git object.

## Privacy

Prefer an onion address as a box's published network identity: it is the
censorship-resistant endpoint and it reveals nothing about where the machine
is. If you ever share a box file with someone, share one that has no clearnet
address, hostname, username, or local filesystem path in it.

## Per-box configuration

Copy `box.env.example` to `~/.config/zclassic23-fleetsync/<box>.env` and fill
it in. Nothing in it is committed, and the sync loop refuses to run without
it.

## Sync loop

On each machine, after cloning and `make setup`:

```bash
make -j"$(nproc)"
tools/scripts/fleet_sync.sh <box>    # one manual run to validate
```

Then a crontab entry, with the minute offset differently per machine so they
do not all rebuild at once:

```
4,19,34,49 * * * * /path/to/checkout/tools/scripts/fleet_sync.sh <box> >> ~/.local/state/zclassic23-fleetsync.log 2>&1
```

Each cycle fast-forwards to `origin/main`, rebuilds when HEAD moved, restarts
the node when the running daemon's baked source identity no longer matches the
binary just built, and records what it saw to `<box>.sync`.

**It never commits and never pushes.** An earlier version of this loop wrote
its observations to a tracked file and pushed them to `main` every cycle. That
is how a public repository filled with per-machine heartbeat commits naming
specific boxes, their onions and their ports — which made a project anyone can
join look like it had an in-crowd. What your box observes is yours; publishing
it is a separate, deliberate act.

It fails closed: local commits, a dirty tracked file, a failed build, or a
failed restart are recorded as a named `SYNC_ERROR` and never force-resolved.
It also verifies the result rather than the attempt — after a restart it
re-reads the new process's `/proc/<pid>/exe` and reports drift that persisted.

`RESTART_PROD=auto` lets the loop also swap a second, production binary and
restart its unit on new `main`. That resets any running soak clock; leave it
`manual` on a machine whose node is mid-acceptance.

## Install identity (optional)

`tools/dev/fleet-identity.sh` gives each of your machines a stable name tag so
you can tell whether two files came from the same installation. It is a
convenience tier and nothing in consensus, custody, datadir handling, or
deployment may depend on it. The claim is exactly: **same install — not same
chip, not safe machine.**

```bash
tools/dev/fleet-identity.sh init             # once: create the salt
tools/dev/fleet-identity.sh gather --box LABEL
tools/dev/fleet-identity.sh status           # check every box you pinned
```

Every stored value is `sha256(SALT || raw)`. The natural name for an
installation is a hash of its SSH host public keys, and writing that down raw
is a locator: internet scan services index host key blobs, so anyone who got a
copy of the file could match a scanned address to your machine. Salting keeps
the file a stable pin for you and opaque to everyone else. The salt lives in
`fleet.env` and is applied on your own machine, so remote boxes never need it.

Pinning is trust on first use: the stored file IS the pin. A changed
`INSTALL_ID` or `MACHINE_TAG` exits 3 and leaves the pin untouched — silently
rewriting it would erase the one fact worth reporting. `status` exits 4 when a
box was unreachable, so an unchecked mesh never reports as an agreeing one.
Rotating the salt renames every box and lands as an event on all of them; it
is configuration, not a secret whose loss is dangerous.

## Nobody is the referee

There is no designated box that checks the others and publishes a verdict the
rest are expected to trust. Every node validates the chain itself and reports
only what it observed directly. If you want to compare two of your machines,
read what each of them recorded and check it against your own copy of the
chain. A box that goes quiet means fewer things could be compared that round;
it does not make the others right or wrong.

The same rule is why this directory is empty of state: a file in a shared
repository that everyone is expected to believe is an authority, and this
project does not have one.

## Supervising the node

Run the node under systemd, never from a shell. `deploy/zcl23-devfleet@.service`
is a template unit for exactly this:

```bash
install -m644 deploy/zcl23-devfleet@.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zcl23-devfleet@<box>.service
```

Point the sync loop at a different unit with `MESH_UNIT` in your box env if
you name yours something else.

`Type=notify` matters: the node holds `READY=1` until its onion descriptor is
actually published, so `active` means the box is reachable at its `.onion`,
not merely that a process exists. `WatchdogSec` converts a silent hard wedge —
otherwise indistinguishable from a healthy node — into a bounded restart.

Two settings need care:

- **Pin your peers.** Add one `-addnode=<onion>:<port>` per peer to the node
  flags in your box env. Without them a box has no standing connection to your
  other machines at all — it only ever meets a peer if something else dials it
  in first, and that connection evaporates on every restart.
- **Do not shrink the memory envelope.** `MemoryHigh` equals `MemoryMax` on
  purpose: a soft limit below the real need is a thrash zone, not a diet. Boot
  can peak far above steady state when an unclean shutdown forces an integrity
  check on the database.

A machine whose checkout or datadir is not where the template expects it
overrides those lines with `systemctl --user edit`. systemd expands `${VAR}`
only in `Exec*` lines — in `ReadWritePaths=` and `StandardOutput=` a variable
is silently dropped, which yields no sandbox and a silent fallback to the
journal. Verify with
`systemctl --user show <unit> -p ReadWritePaths -p StandardOutput`.
