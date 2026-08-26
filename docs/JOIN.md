# Joining the network

"Joining" means two different things, and they are independent. Read the first
section if you want your node on the blockchain network; read the rest if you
also want it to take part in the C23 software commons.

## 1. Joining the blockchain P2P network — nothing to run

There is no join command for the chain, no registration, no invitation, and
nobody who can approve or refuse you. A node that starts is on the network.
Peer discovery is automatic and is described in
[`GETTING_STARTED.md`](GETTING_STARTED.md#syncing-to-the-chain-tip); the short
version is:

- The binary carries a small set of compiled-in seed addresses. It puts them
  in its address manager at boot, dials them, and from then on learns peers by
  gossip from whoever answers. Peers that are not in the compiled list show up
  in the peer set within a couple of minutes.
- **No DNS seeder is used — ever.** The node resolves no hostnames for peer
  discovery and trusts no certificate authority. `dns_seeds=0` in the
  `[net] bootstrap sources:` line the node prints on first boot is the
  deliberate, permanent value, not a misconfiguration.
- `.onion` directory seeds are the second bootstrap channel, used only on a
  build that links the real Tor fork (`make tor-full`) and is started with
  `-tor`.
- `-addnode=HOST:8033` and `~/.config/zclassic23/onion-seeds` let you add
  peers yourself. Neither is required.

There is no prerequisite. A fresh node validates every shielded proof it sees
using verifying keys compiled into the binary, so it syncs and serves with
nothing installed. The one thing it cannot do is *create* a shielded payment,
which needs the Zcash proving parameters — this repository neither ships nor
downloads those, and a node without them says so as a named capability rather
than refusing to run. See [`PARAMS.md`](PARAMS.md) if you intend to send.

Two things a fresh node does *not* get by itself, so you know what you are
choosing when you type nothing:

- **No fast start.** The instant-on path needs a `-fileservice=HOST` you
  supply. Without it the node logs the named blocker
  `bootstrap.no_state_source` and syncs from genesis, which is correct and
  slow.
- **No inbound reachability** unless you pass `-listen` and your port is
  actually reachable from outside, or you run the Tor build and publish an
  onion service. An outbound-only node syncs and relays fine; it just is not
  somewhere other people can bootstrap from.

## 2. Joining the C23 software commons — `z23 join`

The rest of this page is about the package commons, which is a separate,
optional layer riding on the peer connections your node already has. One
command does the work:

```bash
z23 join -datadir="$HOME/.zclassic-c23"
```

It is safe to run twice. It starts nothing, stops nothing, and signals nothing.

### What `join` actually does

Three things, and it reports all three:

1. **Reads your current posture** — whether this node is already hosting
   packages (`package_hosting`), already offering compile work
   (`build_worker`), and whether both are on (`joined`).
2. **Looks for a C23 compiler on this machine.** If there is none, the node
   will still host packages, but it will not advertise compile capacity it
   cannot deliver.
3. **Writes the flags into your node's own config file**, `z23.conf` inside
   your data directory: `packagehost=1` always, and `buildworker=1` only when
   a compiler was actually found. Anything else already in that file is left
   alone.

Command-line flags always beat the config file, so a service unit that passes
an explicit flag stays in charge.

### Then restart the node yourself

`join` deliberately does not restart anything. The service manager owns the
node process, and a second node process on one data directory corrupts it, so
there is no launcher hidden inside this command.

The unit that [`deploy/setup.sh`](../deploy/setup.sh) installs is named
`zclassic23`, so the restart is:

```bash
systemctl --user restart zclassic23
```

The command's `restart_command` field prints this installed unit name. If you
run the node some other way, substitute your own unit name. After the restart,
confirm the node came back with the flags applied:

```bash
z23 zcode package offered -datadir="$HOME/.zclassic-c23"
```

`serving_ready=true` means the resident package engine is live and has at
least one eligible NODE_ZCL23 peer. `peer_count` is the measured session count;
zero is never rewritten as a successful join.

### The two tiers

Joining is not one thing. There are two named tiers, and only the first is
required.

#### SWARM — this is what `join` gives you

Needs `-packagehost=1` and nothing else. It works over the ordinary peer
connections your node already makes.

- **No coins.** Nothing is spent.
- **No on-chain identity.** Nothing is registered.
- **No invitation.** Nobody approves you.

If you only ever run `z23 join -datadir="$HOME/.zclassic-c23"`, you are a
full member of the swarm. Your node hosts and serves package content to peers
exactly like any other.

#### DHT — an optional upgrade, never a blocker

The distributed hash table is a second, stronger discovery layer. It
additionally needs:

- `-v2transport`, the authenticated peer transport; and
- an **active on-chain ZID anchor**. Registering one is a transaction, and it
  **spends a fee**.

That is a real cost, so it is stated plainly and it is optional. A node with no
anchor is not second-class and is not "not joined" — it simply is not in the
DHT. Nothing in the swarm tier depends on it.

### Reading the verdict

`join` reports a **tuple**, not a pass/fail, and speed is never one of its
terms:

```
verdict:
  reachable    can a peer open a connection to this node
  responsive   does it answer what it is asked
  fresh        is what it would serve current
  serving      is it actually serving content
  latency_ms   measured, reported beside the four — never folded into them
```

Each dimension is reported independently. `reachable + slow + fresh` is a
perfectly good result and is not a failure. A single score that folded latency
into the verdict would grade a slow but honest machine as broken, and a
threshold tuned on fast storage would quietly exclude exactly the ordinary
hardware a permissionless network has to admit. If you want one number, derive
it yourself from the tuple and own that choice.

`latency_ms: -1` means **not measured**. That is not the same as fast.

#### `announcement`, and why `ready` is strict

Announcing yourself to the network is a promise, so the announcement state is
`ready` only when **all four** of these are confirmed:

| stage | meaning |
| --- | --- |
| `descriptor_published` | your onion service descriptor is published |
| `rendezvous_established` | a rendezvous point is established |
| `circuit_built` | a circuit is actually built |
| `listener_accepting` | your listener is accepting connections |

Three of four is not `ready`. Instead the state names the stage still
outstanding — `publishing-descriptor`, `establishing-rendezvous`,
`building-circuit`, `opening-listener` — so "still building circuits" is
something you can read rather than a silent not-ready.

A node that announces `ready` early gets dialled, fails the dial, and is scored
down for the broken promise rather than for being slow. Keeping `ready`
unreachable until the last stage confirms is what prevents that.

Alongside the state name is `state_signal`, which says *why* that stage is
outstanding: `unconfirmed` (not proven yet), `unobservable` (nothing here can
see it), or `failed`.

**`join` itself reports every one of those as `unobservable`**, and that is
correct: `join` runs as a short-lived command that started no Tor, opened no
listener and built no circuit, so it is in no position to confirm — or to
deny — any of them. It says so rather than guessing in either direction. Ask
the running node instead:

```bash
z23 status -datadir="$HOME/.zclassic-c23"
z23 core network onion health -datadir="$HOME/.zclassic-c23"
```

`joined` in the reply is a **configuration** fact — both flags are set — not a
reachability verdict. Read the tuple for that.

### Keeping the node current

```bash
z23 update
```

reports what this node would update to. It and the other update commands
(`z23 zcode node update check -datadir="$HOME/.zclassic-c23"`,
`z23 zcode node update apply -datadir="$HOME/.zclassic-c23"`) are **declared
but refused by name** today: there is no verified node-release feed yet, so
nothing on your node can prove a candidate build is the genuine newer release.
An unproven update channel is a remote code-execution path, so these refuse
loudly with a stated reason instead of quietly doing nothing or, worse,
installing something unverified. Update by rebuilding or reinstalling from
source until that changes.

## Where to go next

- [`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md) — publishing and
  using packages once you have joined.
- [`P2P_SOURCE_HOSTING.md`](P2P_SOURCE_HOSTING.md) — what package hosting
  actually serves.
- [`GETTING_STARTED.md`](GETTING_STARTED.md) — installing and running a node in
  the first place.
