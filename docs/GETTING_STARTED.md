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
- **The Zcash zero-knowledge parameter files.** A mainnet node refuses to
  start without them and this repository neither ships nor downloads them.
  See ["The proving parameters"](#the-proving-parameters-required-before-the-first-mainnet-start)
  below — read that section before your first `build/bin/z23` run, not after.

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

## The proving parameters (required before the first mainnet start)

Mainnet blocks contain shielded transactions, and validating them needs the
Zcash zero-knowledge parameter files. **This repository does not ship them and
has no target that downloads them.** You have to put them on the machine
yourself. There is no way around this and no flag that skips it: a mainnet node
that cannot read all four files stops during boot with a named blocker rather
than syncing:

```
[crypto.params] mainnet requires zk params but 'sapling-spend.params' is
missing/unreadable (dir=$HOME/.zcash-params) — NOT advancing CRYPTO_READY;
parking alive-degraded after paging the operator
[boot] PARKED alive-degraded at gate 'crypto_params_missing'
```

A parked node opens no P2P listener, accepts no RPC, and connects to no peers.
It is not a crash loop — it stays up, states the reason, and waits for a
shutdown signal. If your very first run ends at that line, this section is what
you skipped.

The node looks in `$HOME/.zcash-params` by default; `-paramsdir=<dir>` points
it somewhere else. Exactly four files are required (the fifth file some
distributions ship, `sprout-proving.key`, is not):

| file | bytes | sha256 |
| --- | --- | --- |
| `sapling-spend.params` | 47958396 | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` |
| `sapling-output.params` | 3592860 | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` |
| `sprout-groth16.params` | 725523612 | `b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50` |
| `sprout-verifying.key` | 1449 | `4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82` |

They total roughly 777 MB. They are the public outputs of the Zcash
multi-party parameter ceremonies — the *same* files any Zcash-family node
uses, not something specific to this project. Consequences of that, both good:

- If this machine already runs `zcashd` or `zclassicd`, the files are already
  at `~/.zcash-params` and you are done — check, don't re-download.
- Otherwise get them however you can (a copy from another machine you control,
  a mirror, whatever your distribution packages) and then **verify the hashes
  above before starting the node**. The hashes are the trust anchor; where the
  bytes came from is not. This project pins no download host and trusts no
  certificate authority, which is exactly why the check is on you:

```bash
cd ~/.zcash-params && sha256sum -c <<'EOF'
8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13  sapling-spend.params
2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4  sapling-output.params
b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50  sprout-groth16.params
4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82  sprout-verifying.key
EOF
```

Regtest and testnet do not enforce this gate; mainnet does.

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
process stayed up." Three paths exist. Which one is available to you depends
on what you already have, so read the first line of each before picking:

- **Path 2, plain P2P from genesis, is the only one that needs nothing you
  do not already have.** It is what you get by typing `build/bin/z23` with no
  peer flags at all, and it is the path this page assumes for a first node.
- Paths 1 and 3 are faster but each needs an input you must obtain
  separately: path 1 needs the address of a serving peer that you learned
  from somewhere outside the software, and path 3 needs a `zclassicd` datadir
  already on the machine. Neither is a step you can follow from a clean clone
  with no prior contacts, and the node does not discover a file-service host
  on its own — with no `-fileservice`, it names the blocker
  `bootstrap.no_state_source` in the log and proceeds with path 2.

1. **Instant-on from serving Z23 peers** (fastest, but you must already know
   a peer address). Name one
   or more reachable Z23 peers with `-addnode`. Pair that with
   `-fileservice=HOST` so the node also fetches the header-chain seed plus
   complete-state bundle from that host's file service on port 18034,
   verifies them against the compiled checkpoint, installs, then folds the
   remaining delta to tip over P2P from every connected peer. No
   `zclassicd` datadir:

   ```bash
   build/bin/z23 -addnode=PEER.EXAMPLE:8033 -fileservice=PEER.EXAMPLE
   ```

   You can repeat `-addnode=` for additional peers so the remaining fold is
   not pinned to one host. `-connect=HOST` / `-connect=HOST:8033` still
   works as a pin-to-one-peer mode (P2P 8033 plus file service 18034 on
   that host only). Use it when you want no other peers, not as the default
   fast path.

   Optional: if you already have a `consensus-state-bundle-*.sqlite`, set
   `ZCL_CHECKPOINT_BUNDLE_SOURCE` in `~/.config/zclassic23/env` so systemd
   stages it before boot (`docs/ROM_DELIVERY.md` "Local bundle bootstrap").
   The install path still re-derives checkpoint authority; staging is only
   a courier.

2. **Plain P2P from genesis** (no prior contacts needed; this is the default).
   Start on an empty datadir with no `-connect` and no file-service seed. The
   node bootstraps from compiled-in seeds, then learns the rest of the network
   by gossip from whoever answers, and fully validates every block body
   itself. On its first boot it prints its own bootstrap inventory, which is
   the line to read if you want to know where its peers can come from:

   ```
   [net] bootstrap sources: dns_seeds=0 fixed_seeds=N onion_seeds=M
         operator_onion_seed_file=0 addrman_loaded_peers=0 total_sources=...
   ```

   `dns_seeds=0` is deliberate and permanent: this project resolves no
   hostnames and trusts no certificate authority, so there is no DNS seeder
   to be censored or spoofed. The compiled-in fixed seeds are raw IP
   addresses; the onion seeds are `.onion` directory nodes and are only
   dialled if you built the real Tor fork (`make tor-full`) and passed `-tor`
   — on a default (Tor-stub) build the fixed IP seeds are the whole bootstrap.
   Either way, the seeds are a starting point, not the network: within the
   first minute or two the node's peer set normally contains addresses that
   are not in the compiled list at all, because peers gossip addresses to each
   other.

   This is the most conservative path but is **slow**: a full from-genesis
   sync validates the entire chain's Equihash PoW, scripts, and
   Sapling/Sprout proofs. Headers arrive fast; block bodies are the long
   pole, and a full validation runs for many hours on ordinary hardware. Use
   this when you want a node whose state is entirely self-derived and don't
   need it useful within minutes.

   Two honest caveats about the compiled-in seeds. They are plain IP
   addresses baked into a release, so they go stale as machines churn — some
   fraction of them will be unreachable by the time you build. And a node
   whose only reachable seed is one host is trusting that host for its first
   view of the chain until gossip widens the peer set. If you already know
   any reachable peer, `-addnode=HOST:8033` short-circuits both problems, and
   `~/.config/zclassic23/onion-seeds` (one `.onion` per line) adds directory
   nodes without a rebuild.

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

**The node came up but nothing works — no RPC, no peers, no height.** Read the
last line it printed. If it says `PARKED alive-degraded at gate
'crypto_params_missing'`, the proving parameters are not installed; see
["The proving parameters"](#the-proving-parameters-required-before-the-first-mainnet-start).
A parked node is not a crash and not a hang — it is a stated refusal, and
every other symptom you might chase is downstream of it.

**No peers** (`peer_count` stays at `0`):

```bash
build/bin/z23 status
build/bin/zclassic-cli getnetworkinfo
build/bin/zclassic-cli addnode "IP:PORT" "onetry"
```

First find out what the node had to work with. Its first-boot log line
`[net] bootstrap sources: ...` names every source it knows, and
`Added N hardcoded seed nodes` confirms the compiled seeds went into the
address manager. If `fixed_seeds` is non-zero and you still have no peers,
the seeds themselves are unreachable from where you are — outbound TCP to
port `8033` is a good thing to test directly before blaming the node.

Two ways to fix it without waiting for a new release, both permanent for that
machine:

- `-addnode=HOST:8033` (repeatable) or the live `addnode ... onetry` above,
  for any peer address you can get hold of.
- `~/.config/zclassic23/onion-seeds`, one `.onion` directory node per line
  (`#` comments allowed), which the node re-reads on every seed round. This
  needs a Tor-capable build (`make tor-full`) and `-tor`; on a Tor-stub build
  the file is read but nothing can be dialled.

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
