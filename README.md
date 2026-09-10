<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23

**One C23 binary: a ZClassic full node you own, and a software commons that
answers to you.**

Z23 compiles to a single self-contained executable holding two sovereign
systems. The first is a ZClassic full node — P2P, transparent and shielded
wallet state, RPC, and its own block explorer. The second is an optional
commons for creating, verifying, reproducing, and preserving C23 software.
Both answer to the person running the node, not to an AI vendor, a package
registry, or a hosted service.

> **Status: pre-v1.** This is software to build, run, and inspect — not a
> finished product. The public-node acceptance contract is eight binary
> criteria — install, onion bootstrap, cold-start sync, shielded receive,
> store sale, seven-day soak, `kill -9` recovery, consensus parity — and it is
> not yet complete. Each one is tracked with its evidence, passing and
> failing, in [`docs/MVP.md`](docs/MVP.md). Rather than take a readiness number
> from this page, ask a running node for its own: `build/bin/z23 milestone`.

![A user-owned Z23 node containing a full node and C23 Commons, with replaceable AI workers outside its authority boundary](docs/assets/z23-hero.svg)

## Start here

```bash
git clone https://github.com/z23c/z23.git
cd z23
make doctor
make setup
make -j"$(getconf _NPROCESSORS_ONLN)" z23
build/bin/z23 discover help
```

On Linux that needs `gcc` 14+ (or `clang` with working `-std=c23`), GNU
`make`, a C++ compiler, and the usual fetch and checksum tools. There is no
Rust toolchain and no Rust library anywhere in the tree: shielded proving and
verification are native C23. You do not need the Zcash proving parameters to
sync and validate — the verifying keys are compiled in — only to *send*
shielded. The first build fetches pinned third-party sources, verifies each
against a pinned SHA-256, and compiles them locally; after that, builds are
offline. Prerequisites in full, macOS, Windows, and the container-free
`make portable` build are in [Getting Started](docs/GETTING_STARTED.md).

## Run a node

```bash
build/bin/z23
```

The node starts on `~/.zclassic-c23` with P2P on `8033` and RPC on `18232`. A
fresh datadir starts honestly empty — `getblockcount` returns `0` until real
state lands, never a phantom tip. `build/bin/z23 status` reports readiness and
the one next action worth taking; when sync stops, `core sync diagnose` says why
and `ops logs --pattern='<regex>'` returns bounded diagnostics. To survive
logout and reboot, use the shipped `systemd --user` unit:

```bash
sudo bash platform/deploy/setup.sh
systemctl --user start zclassic23
```

**Tor is bundled, and it is on.** A plain `make` builds the pinned embedded Tor
and links it, so the node reaches the onion network and publishes its own
`.onion` with no flag; `-no-tor` is the opt-out. Resolving no hostnames is
deliberate and permanent — the first boot prints `dns_seeds=0` because this
project trusts no DNS seeder and no certificate authority. The compiled seeds
are raw addresses plus onion directory nodes; peers gossip the rest.

The node is also its own web server, with no reverse proxy in front of it. The
explorer (`/explorer`, JSON API under `/api`) is served on the node's `.onion`
by default; add a certificate and key under the datadir's `ssl` directory and it
also serves HTTPS on `8443` near tip
([runbook](docs/BLOCK_EXPLORER_HOSTING.md)).

## What reaching the tip actually costs

**Full P2P sync from genesis** is the default and needs nothing you do not
already have — it is what `build/bin/z23` with no flags does. It is also the
slowest, because it validates the chain itself: proof-of-work, scripts, and
shielded proofs. Headers arrive quickly, bodies are the long pole, and a full
run takes hours. Choose it for state that is entirely self-derived.

**A peer's signed state offer** makes a first sync short without making it
credulous. Peers append a bundle height, digest, and producer to the handshake;
your node picks the newest offer within 576 blocks of that peer's own tip,
verifies each chunk before import, and installs it against the checkpoint
compiled into your own binary — no flag from you. If nothing acceptable arrives
within two minutes of your first peer, the node names
`bootstrap.stale_offers_only`, prints the newest height it did see, and folds
from genesis rather than dropping back silently. That machinery is built and
code-tested; a full fresh z23-to-z23 run to tip is not yet the proven everyday
path.

**Import from an existing `zclassicd` datadir**, if you already run the legacy
C++ node, is today's proven cold start. Headers first, then a normal boot;
skipping the first step leaves a header hole and the node pins.

```bash
build/bin/z23 --importblockindex "$HOME/.zclassic"
build/bin/z23
```

Naming a peer you already know shortens any of these — `-addnode=HOST:8033`,
plus `-fileservice=HOST` to pull the header seed and state bundle from that
host's file service. Every path, with its measured evidence, is in
[Sync](docs/SYNC.md).

## Consensus parity is the inviolable target

Z23 shares one network with the legacy `zclassicd` clients: same P2P protocol,
same blocks, and consensus divergence is a defect rather than a feature. A
read-only parity service diffs the UTXO set and tip against a local `zclassicd`
oracle whenever one resolves, and a from-genesis replay canary re-validates full
history through the current reducer — both are criterion 8, with their standing
verdicts, in [`docs/MVP.md`](docs/MVP.md).

## The C23 Commons

The same binary carries a commons for C23 software: content-addressed source
and packages, authenticated fetch of inert bytes, bounded build and test work,
and receipts another machine can re-check. The authority boundaries are the
point. Fetching bytes does not authorize building them, building does not
authorize installation, execution, or deployment, and chain work always has
priority over package work.

![Inert bytes travel between nodes, then each receiver verifies, rebuilds, and accepts or refuses locally](docs/assets/z23-verification.svg)

AI workers may search, propose, build, and test. They do not become a source of
truth, because what Z23 keeps is what another machine can check without them. A
hash identifies exact bytes; a signature identifies the key that made a
statement; a receipt records one bound observation. None of them alone shows
that arbitrary code is safe, correct, or useful, so acceptance stays a local
decision about one exact version — and the durability test is blunt: the
original worker, publisher, or company can disappear, and the accepted source
and evidence can still be checked and reproduced here. Start at
`build/bin/z23 zcode guide`.

## Working on Z23 itself

The command registry is generated from the running program, so no document can
drift away from it. Descend with `discover help <path>`, search with
`discover search <query>`, and read a leaf's exact input keys with
`discover schema <leaf>`. The source tree answers the same way — ask it instead
of grepping it, and ask it which tests own the file you touched:

```bash
build/bin/z23 code map
build/bin/z23 code room engine/reducer/services/src/reducer_ingest_service.c
build/bin/z23 code tests engine/reducer/services/src/reducer_ingest_service.c
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group>
```

`make t-list` lists every registered group, `ONLY=` is mandatory for `t-fast`,
and `make test-parallel` runs the whole set. `make lint-fast` gives feedback
while editing; publishing needs the full `make lint` gate set plus the impacted
groups, run in one isolated worktree against the exact commit pair and ending
in a signed receipt the pre-push hook requires, so a green push means the
evidence exists rather than that nobody looked.

The tree is authority-first: sealed consensus, crypto, and proofs in `core`,
the single chain-state-advancing room in `engine/reducer`, feature-first product
rooms in `contexts`, what the system needs from the outside world in
`platform/ports` and how an OS provides it in `platform/adapters`. Reusable
modules live beneath the authority that owns them, and the build refuses a file
placed outside its room; `build/bin/z23 code context-map` prints the view it
generates.

Building software here runs DESCRIBE → REUSE → CREATE → SEE → KEEP → SHARE, so
seeing the consequence comes before deciding to keep it. `zhello` is the
smallest prompt-to-pixel example — a reusable painter plus a native window — and
`zdemo` is the same package shape after customization. Headless modes render the
real frames and check deterministic digests; windowed modes put the consequence
on screen.

```bash
make zhello-selftest
make zdemo ZDEMO_ARGS=--frames=2
```

## Go deeper

- **Run it:** [Getting Started](docs/GETTING_STARTED.md) · [Sync](docs/SYNC.md) · [MVP acceptance](docs/MVP.md) · [Windows](docs/WINDOWS.md)
- **Understand it:** [How the Node Works](docs/HOW_THE_NODE_WORKS.md) · [Framework](docs/FRAMEWORK.md) · [API Reference](docs/API_REFERENCE.md)
- **Build with it:** [Developing](docs/DEVELOPING.md) · [Codebase Map](docs/CODEBASE_MAP.md) · [Commons Quickstart](docs/C23_COMMONS_QUICKSTART.md) · [Forward Plan](docs/work/FORWARD_PLAN.md)
- **License:** [Apache-2.0](LICENSE), with upstream notices preserved in [NOTICE](NOTICE)
