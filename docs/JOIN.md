# Joining the network

If you have installed a Z23 node and want it to take part rather than just
follow along, this page is the whole story. One command does the work:

```bash
z23 join
```

It is safe to run twice. It starts nothing, stops nothing, and signals nothing.

## What `join` actually does

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

## Then restart the node yourself

`join` deliberately does not restart anything. The service manager owns the
node process, and a second node process on one data directory corrupts it, so
there is no launcher hidden inside this command. The reply tells you the
restart to run — for the unit the installer writes, that is:

```bash
systemctl --user restart z23
```

Substitute your own unit name if you run the node some other way. After the
restart, confirm the node came back with the flags applied:

```bash
z23 zcode work toolchain
```

## The two tiers

Joining is not one thing. There are two named tiers, and only the first is
required.

### SWARM — this is what `join` gives you

Needs `-packagehost=1` and nothing else. It works over the ordinary peer
connections your node already makes.

- **No coins.** Nothing is spent.
- **No on-chain identity.** Nothing is registered.
- **No invitation.** Nobody approves you.

If you only ever run `z23 join`, you are a full member of the swarm. Your node
hosts and serves package content to peers exactly like any other.

### DHT — an optional upgrade, never a blocker

The distributed hash table is a second, stronger discovery layer. It
additionally needs:

- `-v2transport`, the authenticated peer transport; and
- an **active on-chain ZID anchor**. Registering one is a transaction, and it
  **spends a fee**.

That is a real cost, so it is stated plainly and it is optional. A node with no
anchor is not second-class and is not "not joined" — it simply is not in the
DHT. Nothing in the swarm tier depends on it.

## Reading the verdict

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

### `announcement`, and why `ready` is strict

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
z23 status
z23 core network onion health
```

`joined` in the reply is a **configuration** fact — both flags are set — not a
reachability verdict. Read the tuple for that.

## Keeping the node current

```bash
z23 update
```

reports what this node would update to. It and the other update commands
(`z23 zcode node update check`, `z23 zcode node update apply`) are **declared
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
