# Getting Started With Z23

This is the generic, fresh-machine setup guide: build the binary, then run it
either as a **production** full node + block explorer, or as an isolated
**development** instance. [`README.md`](../README.md) is the project overview;
[`docs/BUILD.md`](BUILD.md) is the focused build reference (vendored-library
sources/versions, fast dev-compile targets, sanitizer profiles); the
[`z23-dev`](../.claude/skills/z23-dev/SKILL.md) skill is the deep
developer workflow (code navigator, hot-swap tiers, push traps).
[`docs/HANDOFF.md`](HANDOFF.md) is maintainer-only live state for the
project's own hosted node — skip it unless you're operating that host.

The project is pre-v1 (see [`docs/MVP.md`](MVP.md)). It is fully usable for
building, developing against, and running a real ZClassic node; don't rely on
it as your only mainnet node yet.

---

## Build

**Prerequisites:**

- `gcc` 14+ (or `clang` with working `-std=c23` support) and GNU `make`.
- A C++ compiler (`c++`/`g++`), `autoconf`, `curl` or `wget`, `unzip`,
  `sha256sum`, and (optional — a fallback build path exists without it)
  `cmake`, for the one-time vendored-library build.
- No Rust toolchain or library. Shielded proving and verification are native
  C23 code in this repository.

No other external dependencies: everything else is stock `cc`/`ld`/`make`
and libc.

**Get the source and build:**

```bash
git clone https://github.com/z23c/z23.git
cd z23
make -j"$(nproc)"     # builds z23, zclassic-cli, zcl-rpc
```

For the smallest server-only build, use `make -j"$(nproc)" z23`. The
published node is a C23 executable with pinned project dependencies linked
statically; it does not inherit GTK/WebKit or the C++ LevelDB runtime from the
build host. The build fails closed if the ELF dependency audit finds one.

For a binary intended to move between x86-64 Linux machines, use
`make portable`. It needs no container or root access: it downloads a
checksum-pinned GLIBC 2.31 sysroot, rebuilds all linked archives through that
boundary, forces the baseline x86-64/SSE2 CPU, and executes a typed command
under the old loader before declaring success.

The first build needs internet access once: `make` auto-runs `make vendor`,
which fetches pinned third-party source tarballs (OpenSSL, libevent, LevelDB,
zlib, SQLite, the canonical Zcash Sapling prover), verifies each against a
pinned SHA-256, and compiles them locally into `vendor/lib/`. After that,
archives are cached and builds are offline. Exact versions, hashes, and the
vendoring model are in [`docs/BUILD.md`](BUILD.md).

**Optional — the real Tor onion service.** The default build links a Tor
*stub*, so `-tor` runs the node without publishing a `.onion`. To build the
real embedded Tor:

```bash
make tor-full
```

This initializes the pinned submodule and produces its four required static
archives with an embedding profile that avoids undeclared optional host
libraries. Later invocations are incremental. When `vendor/tor/libtor.a`
exists, the Makefile links it automatically and `-tor` publishes a real onion
address.

**Fast compile-check inner loop** (no link, good for verifying a change
compiles before a full build):

```bash
make -j"$(nproc)" build-only
```

**Where the binaries land:** `build/bin/z23` (the node),
`build/bin/zclassic-cli` (RPC client), `build/bin/zcl-rpc` (RPC helper).

**Sanity check:**

```bash
build/bin/z23 --version
build/bin/z23 status        # runs against a running node; see below
```

**Run the test suite and lint gates** before relying on a build:

```bash
make -j"$(nproc)" test-parallel   # the canonical test runner — do not invoke test_zcl directly
make lint            # defensive-coding + doc-accuracy gates
```

### Your one obvious next action

You have a working binary. There are two useful things to do with it: run the
public node (below), or tell it what you want C23 software on this device to
do. The second is the shorter path from intent to working software — it reuses
existing C23 first, creates only what is missing, builds and tests in
confinement, shows the real behavior, and ends in your explicit acceptance of
one exact version:

```bash
build/bin/z23 zcode guide
```

It answers with the current start command and the plain step order; every step
after it returns the next safe command. The full journey, including publishing,
fetching on a second node, and independent reproduction, is
[`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md); the developer-loop
detail is [`work/ZCODE_DEVELOPMENT_WALKTHROUGH.md`](work/ZCODE_DEVELOPMENT_WALKTHROUGH.md).

---

## Run in production

Start a full node with the default datadir (`~/.zclassic-c23`) and default
ports (P2P `8033`, RPC `18232`):

```bash
build/bin/z23
```

A fresh datadir starts honestly empty (`getblockcount` returns `0`) until a
verified header seed and complete-state bundle land — there is no phantom tip.
Check health at any time with:

```bash
build/bin/z23 status
```

### Syncing to the chain tip

Judge success by height **climbing toward the network tip**, never just "the
process stayed up." The easy path for a new Z23 node is instant-on from a
serving Z23 peer. Genesis IBD and a `zclassicd` datadir import remain available.

1. **Instant-on from a serving Z23 peer** (the easy new-node path). Point the
   node at one reachable Z23 peer. `-connect=HOST` and `-connect=HOST:8033`
   are the same command: the node uses that host's P2P port 8033 and its file
   service on 18034, fetches the header-chain seed plus complete-state bundle,
   verifies them against the compiled checkpoint, installs, then folds the
   remaining delta to tip. No `zclassicd` datadir, no extra flags:

   ```bash
   build/bin/z23 -connect=PEER.EXAMPLE:8033
   ```

   Optional: if you already have a `consensus-state-bundle-*.sqlite`, set
   `ZCL_CHECKPOINT_BUNDLE_SOURCE` in `~/.config/zclassic23/env` so systemd
   stages it before boot (`docs/ROM_DELIVERY.md` "Local bundle bootstrap").
   The install path still re-derives checkpoint authority; staging is only
   a courier.

2. **Plain P2P from genesis** (the sovereignty-preserving fallback). Start on
   an empty datadir with no `-connect` / no file-service seed; the node
   discovers peers (hardcoded legacy IP seeds plus a Tor `.onion` directory
   seed — no DNS seeders) and fully validates every block body itself. This
   is the most conservative path but is **slow**: a full from-genesis sync
   validates the entire chain's Equihash PoW, scripts, and Sapling/Sprout
   proofs, which takes on the order of hours depending on hardware. Use this
   when you want a node whose state is entirely self-derived and don't need
   it useful within minutes.

3. **Two-step import from an existing `zclassicd` datadir** (fast, requires
   you already run the legacy C++ node). Import headers first, then boot
   normally — order matters, skipping step 1 leaves a multi-million-header
   hole and the node pins:

   ```bash
   build/bin/z23 --importblockindex "$HOME/.zclassic"   # headers first, ~1 min
   build/bin/z23                                        # then a normal boot
   ```

   This still folds every real block body forward from your `zclassicd`
   archive (so a public explorer built this way has full history), and
   reaches tip far faster than genesis P2P sync — but it requires an
   existing local `zclassicd` datadir as the header/body source. Leave
   `zclassicd` running while this happens. Full detail:
   [`docs/SYNC.md`](SYNC.md) "Method 3".

A published/prebuilt starter-pack snapshot loader also exists
(`-load-snapshot-at-own-height`) as a faster-but-partial extra option; it
seeds transparent state quickly but the node's shielded-history gate
intentionally stops at the first unproven spend, and body-derived
projections (explorer token/tx/address history below the seed height) stay
empty until real bodies are folded. See [`docs/BOOTSTRAPPING.md`](BOOTSTRAPPING.md)
and [`docs/BLOCK_EXPLORER_HOSTING.md`](BLOCK_EXPLORER_HOSTING.md) §E before
choosing it for anything that needs full history (e.g. a public explorer).

### Hosting the block explorer

The node **is its own web server** — no nginx/reverse proxy. The explorer
(`/explorer`, JSON API under `/api`) is reachable two ways:

- **Over the onion service** — build the real Tor fork (above) and run
  `-tor`; the explorer is served on the node's `.onion`, visible via
  `z23 status`. No certificate needed.
- **Over HTTPS on clearnet** — drop a TLS certificate/key at
  `<datadir>/ssl/fullchain.pem` and `<datadir>/ssl/privkey.pem`; the HTTPS
  explorer starts on port `8443` once the node is near tip. Without a cert
  the node logs that the explorer is not on clearnet and stays onion-only —
  expected on a default build.

Full runbook (DNS, Let's Encrypt, the no-sudo-after-setup port-forwarder for
public `443`, and troubleshooting a site that stopped loading) is in
[`docs/BLOCK_EXPLORER_HOSTING.md`](BLOCK_EXPLORER_HOSTING.md).

### Exploring the metaverse

The node also hosts a permissionless creation commons — the ZCODE package
library, sovereign property, signed spaces, and the ZC23 Living Commons
projection. Start with the guide, then tour the read-only views against a
scratch datadir/workspace with zero commitment (empty listings are the honest
answer until you or your peers publish something):

```bash
build/bin/z23 zcode guide                       # the creator's map: find, inspect, fetch, create, improve
build/bin/z23 discover search metaverse         # orient in the live command tree
build/bin/z23 zcode package search --input='{"datadir":"/tmp/zcl23-tour"}'
build/bin/z23 metaverse property list --input='{"datadir":"/tmp/zcl23-tour"}'
build/bin/z23 zcode commons status --input='{"workspace":"/tmp/zcl23-tour-commons"}'
```

For the exact installed-node author, consumer, and independent-reproducer
package journey, continue with
[`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md).

Want a real committed space instead of an empty listing? `metaverse space
plan` then `metaverse space commit` returns the 64-hex root for
`metaverse space show --input='{"root":"<64hex>",...}'`.

The ZCODE package site is served alongside the explorer at `/zcode` (onion or
HTTPS). ZC23 patronage is **simulation-only** — there is no live token, and
every live-money path fails closed with a typed error. The full picture and
the acceptance bar: [`docs/METAVERSE.md`](METAVERSE.md) and
[`docs/METAVERSE_MVP.md`](METAVERSE_MVP.md).

### Running as a durable service

The repo ships a ready-to-use, already-generic `systemd --user` unit and a
one-time setup script — use them rather than hand-writing a unit:

```bash
sudo bash deploy/setup.sh              # one-time: installs the unit, enables linger
systemctl --user start zclassic23
systemctl --user status zclassic23
```

`deploy/setup.sh` installs [`deploy/zclassic23.service`](../deploy/zclassic23.service)
to `~/.config/systemd/user/zclassic23.service` and enables
[`loginctl` linger](https://www.freedesktop.org/software/systemd/man/loginctl.html)
so the service survives logout/reboot. The unit already uses
`%h`-relative paths and the default ports/datadir, so it works unmodified
after `git clone` into `~/zclassic23`; if you cloned elsewhere, edit the
`ExecStart=`/`ReadWritePaths=` lines to match. Operator-specific flags
(a stable external IP, seed peers) go in `~/.config/zclassic23/env` — copy
[`deploy/zclassic23.env.example`](../deploy/zclassic23.env.example) and edit
it; the unit sources this file optionally, so a fresh clone without it still
starts cleanly.

A minimal from-scratch example, if you'd rather not use the tracked unit
(substitute your own paths/ports):

```ini
[Unit]
Description=Z23 Full Node
After=network-online.target

[Service]
ExecStart=/path/to/z23/build/bin/z23 \
    -datadir=%h/.zclassic-c23 -port=8033 -rpcport=18232 -listen -txindex
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

### Key operational commands

The typed native command registry (`z23 <command>`) is the primary
operator/agent interface — no separate RPC client or log-scraping required:

```bash
build/bin/z23 status                              # one-line health + next action
build/bin/z23 discover help                        # enumerate the full command catalog
build/bin/z23 ops state --subsystem=<name>          # generic subsystem state dump
build/bin/z23 ops logs --pattern='error|warn'        # server-side log tail, no download
build/bin/z23 core storage query --sql='SELECT ...'  # SELECT-only SQL over node tables
```

Full reference: [`docs/NATIVE_COMMAND_INTERFACE.md`](NATIVE_COMMAND_INTERFACE.md).

---

## Run in development

Use a **separate datadir and non-default ports** so a dev instance never
collides with anything running in production on the same machine:

```bash
build/bin/z23 -datadir="$HOME/.zclassic-c23-dev" -port=8035 -rpcport=18234
```

(The repo's own [`deploy/zclassic23-test.service`](../deploy/zclassic23-test.service)
is a worked example of the same pattern: its own datadir, `-port=8035`,
`-rpcport=18234`, `-addnode=127.0.0.1:8034`, `-nobgvalidation` for a faster
boot — a template to copy, not something to install as-is.)

### The fast dev loop

For day-to-day C development the platform runs a persistent watcher so you
edit `.c` files and get a build+test verdict without manually invoking each
step:

```bash
make dev-watch                 # start the watcher once (verify-only mode)
# ... edit a .c file in your editor ...
build/bin/z23-dev status   # read the latest cycle verdict
```

Faster manual loops when you don't want the watcher running:

```bash
make -j"$(nproc)" build-only           # parallel compile-check, no link
make -j"$(nproc)" fast-rebuild         # changed-file compile + non-LTO local dev binary
make -j"$(nproc)" t-fast ONLY=<group>  # one focused test group, fastest iteration
```

These are the `make fast-rebuild` and `make t-fast ONLY=<group>` targets; the
parallel invocations above are the documented developer forms.

The dev binary lives at `build/bin/z23-dev` — a fast non-LTO local
build, for iteration only; never use it for production/release.

### Running the full test suite and lint

Before committing or pushing, run the canonical gates:

```bash
make -j"$(nproc)" test-parallel   # the canonical test runner (never invoke test_zcl directly)
make lint            # all defensive-coding + doc-accuracy gates
make ci              # local gate: lint + build + tests
```

### Going deeper

The [`z23-dev` skill](../.claude/skills/z23-dev/SKILL.md) is the
full developer operating manual: the source-code navigator
(`z23 code sym|refs|find`, cheaper than grepping), the hot-swap tiers
for the fastest live-data loop on a small set of read-only leaves, the eight
code shapes and where new code goes, the defensive-coding rules enforced by
`make lint`, and the push-time traps (focused-test mapping, the pre-push
SIGPIPE false-block). Read it before making any code change.

---

## Troubleshooting

**No peers** (`peer_count` stays at `0`):

```bash
build/bin/z23 status
build/bin/zclassic-cli getnetworkinfo
build/bin/zclassic-cli addnode "IP:PORT" "onetry"
```

Add custom onion seeds (one `.onion` per line, `#` comments allowed) at
`~/.config/zclassic23/onion-seeds` so the node can harvest peers without DNS.

**Stuck height** (not climbing toward tip): a stall is never silent — it is
always a growing gap or a named blocker.

```bash
build/bin/z23 status
build/bin/z23 core sync diagnose
build/bin/z23 dumpstate reducer_frontier
```

**Reading logs:**

```bash
build/bin/z23 ops logs --pattern='error|warn'
tail -f ~/.zclassic-c23/node.log
```

## Contributing

Read [`.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md) and
[`docs/DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md) before changing code —
CONTRIBUTING covers the two walls that are easiest to hit by accident: the
sealed consensus core under `core/`, and consensus-changing PRs, which are
declined on principle no matter how they are framed. Consensus parity with
`zclassicd` is inviolable; see
[`docs/CONSENSUS_PARITY_DOCTRINE.md`](CONSENSUS_PARITY_DOCTRINE.md).

To report a bug or propose a feature, use the forms in
[`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/); they ask for
`z23 status` output and the consensus question up front.

Next: [`HOW_THE_NODE_WORKS.md`](HOW_THE_NODE_WORKS.md) for the mental model,
and [`AGENT_TRAPS.md`](AGENT_TRAPS.md) for the list of things that look broken
but are intentional or already done.
