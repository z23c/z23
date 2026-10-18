<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Getting Started With Z23

This is the generic, fresh-machine setup guide: build Z23 from source, then run
a ZClassic full node with its block explorer (web view of the chain), or start
an isolated development instance. First, prepare
the compiler and build utilities listed for your platform below; the first build
also needs internet access. A full node validates the chain and serves other
peers.

[`README.md`](../README.md) is the project overview;
[`docs/BUILD.md`](BUILD.md) is the focused build reference (vendored-library
sources/versions, fast dev-compile targets, sanitizer profiles), and
[`docs/DEVELOPING.md`](DEVELOPING.md) is the model-neutral developer workflow.
[`docs/HANDOFF.md`](HANDOFF.md) is maintainer-only live state for the
project's own hosted node — skip it unless you're operating that host.

The project is pre-v1 (see [`docs/MVP.md`](MVP.md)). It is fully usable for
building, developing against, and running a real ZClassic node; don't rely on
it as your only mainnet node yet.

Windows developers should start with [`WINDOWS.md`](WINDOWS.md). It separates
the native MSYS2 UCRT64 portability lane from the currently supported WSL2
full-node build and service lane. WSL2 means Windows Subsystem for Linux 2.

---

## Build

Z23 is written in C23, the 2023 edition of the C language standard.

**Prerequisites on Linux:**

- `gcc` 14+ (or `clang` with working `-std=c23` support) and GNU `make`.
- A C++ compiler (`c++`/`g++`), `autoconf`, `curl` or `wget`, `unzip`,
  `sha256sum`, and (optional — a fallback build path exists without it)
  `cmake`, for the one-time vendored-library build.
- MinGW (`gcc-mingw-w64-x86-64` on Debian/Ubuntu) is not needed for `make z23`,
  but is required by the Windows portability leg in `make pre-push-ci`.
- No Rust toolchain or library. Shielded proving and verification are native
  C23 code in this repository.
- No extra node runtime dependency. In particular you do *not* need the Zcash
  parameter files
  to run a node: the verifying keys are compiled in, so a fresh build syncs
  and validates shielded proofs out of the box. You need them only to *send*
  shielded — see ["The proving parameters"](#the-proving-parameters-optional--a-node-syncs-and-validates-without-them)
  below.

Project dependencies are built from pinned sources. The resulting node uses
the platform system libraries; see the dependency audit below.

**Prerequisites on macOS:** install Apple's command-line developer tools and the
GNU build utilities used by the source-identity and build-lease checks. Mach-O
is macOS's native executable format. The node uses it; no virtual machine or
Linux compatibility layer is involved.

```bash
xcode-select --install
brew install autoconf automake bash cmake coreutils findutils flock libtool make mingw-w64 pkgconf
export PATH="$(brew --prefix make)/libexec/gnubin:$(brew --prefix coreutils)/libexec/gnubin:$(brew --prefix findutils)/libexec/gnubin:$PATH"
```

Apple Clang 17 or newer is required. The `flock` formula supplies the build
lease primitive absent from the macOS base system. `bash` (4+) and `findutils`
(GNU find with `-printf`) are required by the source-identity capture that
selects every compile epoch and by `make lint`; Apple's stock bash 3.2 and BSD
find are not sufficient for either.
`mingw-w64` supplies the mandatory Windows compile/link evidence run by
`make pre-push-ci`; it does not turn that result into native Windows evidence.

**Get the source and build:**

1. Clone the source and enter the checkout.
2. Check prerequisites with `make doctor`.
3. Prepare local hooks and the compilation database with `make setup`.
4. Build the public node with four parallel jobs (`-j4`).

```bash
git clone https://github.com/z23c/z23.git
cd z23
make doctor
make setup
make -j4 z23
```

The public node serves this same clone-and-build sequence as a script at
`/install.sh`, so `curl -fsSL https://<site>/install.sh | sh` builds from
source and downloads no binary (a separate, digest-verified binary
bootstrap exists but stays unpublished until its signing gate is met).

This bounded command is suitable for a 16 GB machine, including a slow disk.
Increase `-j4` only after observing available memory and I/O wait. Use
`make -j4 all` when you also need the test harness, RPC helpers and package
verifier.
Other auxiliary programs have separate targets. The published node is a C23
executable with pinned project dependencies linked statically; it does not
inherit GTK/WebKit or the C++ LevelDB runtime from the build host. The build
fails closed if the ELF (Linux executable format) or Mach-O audit finds an
unapproved dynamic library.

For a binary intended to move between x86-64 Linux machines, use
`make portable`. It needs no container or root access: it downloads a
checksum-pinned
GLIBC 2.31 sysroot (C library and headers for the target), rebuilds all linked
archives through that boundary, forces the baseline x86-64/SSE2 CPU, and
executes a typed command under the old loader before declaring success.

At runtime, block-file startup scanning uses the node's storage classification.
Rotating disks and storage that could not be classified use one reader;
solid-state storage uses up to 16 readers, bounded by CPU and file counts.
No cache-pinning helper or privileged RAM setup is required for this policy.
`ZCL_BLOCK_SCAN_WORKERS` remains an optional override, capped at 64 and the
number of files. Invalid values fall back to the automatic policy.

On rotational disks, an existing block-index projection can be prefetched in
sequential 64 KiB reads before replay. Automatic SQLite cache sizing admits the
projection plus 25% growth only when it fits within one eighth of host RAM, one
quarter of available RAM, one quarter of observed cgroup headroom, and a 2 GiB
ceiling. Small projections keep the existing cache policy; insufficient memory
skips this optimization. `ZCL_BIP_PAGE_CACHE_KIB` preserves explicit cache
control. Prefetch uses a 64 KiB buffer and the reclaimable operating-system
cache; it does not pin memory or make RAM the durable storage authority. SQLite
still owns page validation, write-ahead log (WAL) recovery, and writes.
Slow-disk startup timing remains to be measured for this path.

The first build needs internet access once: `make` auto-runs `make vendor`,
which fetches pinned third-party source tarballs (OpenSSL, libevent, LevelDB,
zlib and SQLite, plus secp256k1 for Darwin or Windows), verifies each against a
pinned SHA-256 digest (content hash), and compiles them into `vendor/lib/`.
After that, archives are cached and builds are offline. Exact versions, hashes,
and the vendoring model are in [`docs/BUILD.md`](BUILD.md).

**Tor is bundled, and it is on.** Tor provides the onion network; a
`.onion` address identifies a service reachable through it. A plain `make`
builds the pinned embedded Tor and links it: the node reaches the onion
network and publishes its own `.onion` with no flag. The first build compiles
Tor once (about two minutes
on a 32-core box, dominated by its `configure`, so a small box is not much
slower); after that the archives are cached under `vendor/tor/` and reused,
and a new worktree hardlinks them from the checkout it was created from
instead of rebuilding.

`-no-tor` is the opt-out. It is refused on a canonical, soak or standby
operator lane — those serve the network, and a node quietly off the onion
network there is the failure this default exists to prevent.

`make tor-full` still exists and forces the Tor rebuild. `make tor-ready`
is the cheap front door (present → nothing, else hardlink, else build).

**The stub is a dev-only opt-in.** `make ZCL_TOR=stub ...` links
`vendor/lib/libtor_stub.a`, whose every entry point fails. It prints one
loud line while building, `zclassic23 -version` reports `tor: stub`, the
binary refuses `-tor`, the onion flags and onion-node mode at runtime, and
no ship or install step will package it.

**Fast compile-check inner loop** (compiles without linking an executable, for
verifying a change compiles before a full build):

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" build-only
```

**Where the binaries land:** RPC (remote procedure call) commands query or
control a running node.

| Binary | Purpose | Build target |
| --- | --- | --- |
| `build/bin/z23` | Full node | `make z23` |
| `build/bin/zclassic-cli` | RPC client | `make zclassic-cli` |
| `build/bin/zcl-rpc` | RPC helper | `make zcl-rpc` |

`make -j4 z23` builds only `z23`; `zclassic-cli` and `zcl-rpc` need
`make -j4 all` or their individual targets (`make zclassic-cli` and
`make zcl-rpc`).

**Sanity check:**

```bash
build/bin/z23 --version
build/bin/z23 status        # runs against a running node; see below
```

**Run the test suite and lint gates** before relying on a build:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel   # canonical runner; do not invoke test_zcl directly
make lint            # defensive-coding + doc-accuracy gates
```

### Platform capability boundary

P2P (peer-to-peer) services connect nodes to one another.

| Host | Public node | Development loop | Resident hot swap | Machine mesh |
| --- | --- | --- | --- | --- |
| Linux | Full node | Full native workflow | Eligible read-only C23 leaves | Noise authenticated transport + DHT (distributed hash table) identity |
| WSL2 | Full Linux node; keep the checkout on WSL ext4 | Linux workflow | Linux workflow | Noise transport + DHT identity |
| macOS arm64 | Native node; `make macos-acceptance` | Kernel-attested focused tests; native kqueue (event notification) directory watcher | Unavailable; rebuild/restart | Noise transport works; DHT identity requires on-chain provisioning |
| Windows MSYS2 UCRT64 | Native `z23.exe` portability lane | `make windows-acceptance` | Unavailable; rebuild/restart | Not yet measured |

Windows setup and the boundary between native MSYS2 and WSL2 are documented in
[`WINDOWS.md`](WINDOWS.md). Never share `build/` or `vendor/lib/` between
native Windows and WSL.

For standalone Windows platform fixtures, run
`.\tools\dev\windows-make.ps1 windows-acceptance-fixtures`.
This compiles the canonical fixture catalog and runs it with the hidden native
runner, reporting unavailable runtime cases explicitly. It does not build the
node or qualify native codeindex behavior; `windows-acceptance` includes those
additional checks.

#### macOS

The arm64 macOS build includes the node, wallet, P2P and RPC services,
databases, and native cryptography. The authenticated Noise transport works
natively and is armed with `-noisetransport`; private-machine mesh pairing then
needs only a provisioned on-chain DHT identity (`zcode network delegate`), the
same cross-platform prerequisite as Linux. The separate package verifier uses
Seatbelt, macOS's sandbox mechanism, for qualified confinement: its filesystem
is scoped, network access is denied, rlimits are enforced, and
`--require-full-isolation` succeeds. This is not resident-node confinement.
Linux Landlock/seccomp resident confinement, signal-context self-backtraces,
native hot-swap activation, and consensus snapshot export that requires
`O_TMPFILE` still report unavailable or refuse safely on macOS. The directory
watcher uses kqueue on macOS. `make macos-acceptance`
validates the closed matrix in
`engine/composition/platform/macos_capabilities.def`, unions its capability
evidence with the eight declarative required baseline groups, and executes the
resulting exact registered groups. It refuses any self-skip or unobserved
eligible environment. After that verdict it uses the canonical release cutter to
create a temporary five-member `darwin-arm64` runtime, verifies the macOS 14
floor, Mach-O dependency boundary and closed checksums, then executes the
packaged node's node-free code guide. This proves local packaging and execution,
not installation, notarization, publication or chain sync. The `self_backtrace`
group in that union proves the fail-closed macOS capability boundary; it does
not claim Linux signal-context backtraces on Darwin. Intel macOS has not yet
been measured.

Focused tests and proof identity checks do not substitute a reconstructed
pathname for `fexecve` (execution through an open file descriptor). The arm64
dev/test executor reads the embedded CodeDirectory identity (signed executable
code identity) through the already-open thin Mach-O descriptor, maps the locator
path with `POSIX_SPAWN_START_SUSPENDED`, and resumes the child only after the
kernel reports the same CodeDirectory hash for that mapped process. A
replacement therefore remains suspended and is killed before executing. This
development-only rail does not change the fail-closed production A/B and
hot-activation boundary.

Embedded Tor links the archives under `vendor/tor/`, built from the vendored
OpenSSL, libevent and zlib. `make tor-full` forces a rebuild. A development
build can use `make ZCL_TOR=stub`; it publishes no onion service and cannot
be shipped. Intel macOS remains unmeasured.

### First steps

Run the binary with no arguments. It prints the one-line node status, the
suggested next command, and, on a terminal, a `start:` line naming the three
verbs a new agent needs:

```bash
build/bin/z23
# start: z23 wiki · z23 lab run hello.c · z23 card
```

| Verb | What it does |
|---|---|
| `z23 wiki [topic]` | Walks the docs tree one topic at a time. |
| `z23 lab run <file.c>` | Compiles one C file and runs it confined; `tests/fixtures/lab/hello.c` is a checked-in example. `z23 lab test` runs a file against a list of cases. |
| `z23 card [--level=haiku]` | Lists the owner's public work cards; `z23 card show <id>` shows one. |

The same verbs are found by `z23 discover search "first steps"`.

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

## The proving parameters (optional — a node syncs and validates without them)

Mainnet blocks contain shielded transactions, and **validating** them needs the
zero-knowledge verifying keys. Those keys are compiled into the binary: they
are 6,357 bytes in total, each pinned by hash and checked before use, and a
node that fails that check refuses to start rather than pretending it can
validate. So a fresh clone syncs, validates every shielded proof, and serves
peers with nothing installed.

**Creating** a shielded transaction is different. That needs the proving keys,
which are roughly 777 MB and live in the four Zcash parameter files below.
This repository does not ship them and has no target that downloads them. A
node without them starts normally and reports one named capability blocker:

```
[crypto.params] shielded send unavailable — proving parameters not installed
```

You will see it in `z23 status`. Nothing else is affected: the node still
follows the chain, validates shielded proofs, and relays. If you only run a
node, you can stop reading here.

To send shielded:

1. Locate the four files below on a machine you control or obtain a copy.
2. Put them in the parameter directory.
3. Verify their hashes with the command below before starting the node.

The node looks in
`$HOME/.zcash-params` by default; `-paramsdir=<dir>` points it somewhere else.
Four files are required (the fifth some distributions ship,
`sprout-proving.key`, is not):

| file | bytes | sha256 |
| --- | --- | --- |
| `sapling-spend.params` | 47958396 | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` |
| `sapling-output.params` | 3592860 | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` |
| `sprout-groth16.params` | 725523612 | `b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50` |
| `sprout-verifying.key` | 1449 | `4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82` |

They are the public outputs of the Zcash multi-party parameter ceremonies —
the *same* files any Zcash-family node uses, not something specific to this
project. Consequences of that, both good:

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

`tools/scripts/zcash_params.sh` does the same check, and refuses to install a
file whose hash does not match. [`PARAMS.md`](PARAMS.md) explains why the
verifying keys are compiled in and the proving keys are not.

---

## Run in production

Start a full node with the default datadir (directory for node state),
`~/.zclassic-c23`, and default
ports (P2P `8033`; RPC `18232`):

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
  already on the machine.
- **A node with peers now asks them.** Once connected, a node reads the signed
  state offers its peers append to the handshake — bundle height, digest,
  producer — picks the newest one within 576 blocks of that peer's own tip (or
  at exactly the compiled checkpoint height, which is always acceptable no
  matter how old), and fetches and installs it with no flag from you, through
  the same chunk-by-chunk
  verification and the same checkpoint-bound install an operator-supplied bundle
  goes through (see [`SYNC.md`](SYNC.md), "State offers over the peer link").
  If nobody offers anything acceptable within two minutes of your first peer,
  the node stops waiting and says so — naming the newest height it did see, in
  `bootstrap.stale_offers_only` — and proceeds with path 2. A node with **no**
  peers at all still names `bootstrap.no_state_source` and folds from genesis;
  there is nobody to ask.

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
   dialled by a real-Tor build, which is the default; on a `ZCL_TOR=stub`
   build the fixed IP seeds are the whole bootstrap.
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

- **Over the onion service** — on by default; the explorer is served on the
  node's `.onion`, visible via `z23 status`. No certificate needed. (A
  `-no-tor` or `ZCL_TOR=stub` build has no onion address to serve it on.)
- **Over HTTPS on clearnet** — drop a TLS (Transport Layer Security)
  certificate/key at `<datadir>/ssl/fullchain.pem` and
  `<datadir>/ssl/privkey.pem`; the HTTPS explorer starts on port `8443`
  once the node is near tip. Without a cert the node logs that the explorer
  is not on clearnet and stays onion-only — expected on a default build.

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

The repository ships a `systemd --user` unit (a service managed by your
user account) and a one-time setup script; use them rather than
hand-writing a unit:

```bash
sudo bash platform/deploy/setup.sh              # one-time: installs the unit, enables linger
systemctl --user start zclassic23
systemctl --user status zclassic23
```

`platform/deploy/setup.sh` installs the
[tracked unit](../platform/deploy/zclassic23.service)
to `~/.config/systemd/user/zclassic23.service` and enables
[`loginctl` linger](https://www.freedesktop.org/software/systemd/man/loginctl.html)
so the service survives logout/reboot. The unit already uses
`%h`-relative paths and the default ports and datadir, so it works unmodified
with a checkout at `~/zclassic23`. The clone command above creates `~/z23`
if run from your home directory; adjust all checkout paths in the unit,
including `ExecStartPre=`, `ExecStart=` and `ReadWritePaths=`, to match.
The launcher also requires `build/bin/zcl-nodectl` (`make zcl-nodectl`).
Operator-specific flags
(a stable external IP, seed peers) go in `~/.config/zclassic23/env` — copy
[`platform/deploy/zclassic23.env.example`](../platform/deploy/zclassic23.env.example) and edit
it; the unit sources this file optionally, so a fresh clone without it still
starts cleanly and syncs over clearnet. The unit does not request Tor by
default; it no longer needs to, because a full build starts Tor on its own.
`ZCL_TOR_FLAG=-tor` in that environment file is now redundant and harmless.
Readiness stays fail-closed: it waits for onion descriptor publication rather
than silently reporting a clearnet-only node as ready.

**On macOS**, install the binary once, then use the provided LaunchAgent:

```bash
make install                              # default PREFIX=/usr/local; use ~/.local for rootless
make service-install                      # loads ~/Library/LaunchAgents/org.z23.zclassic.plist
launchctl list | grep org.z23.zclassic    # confirm it is loaded
```

Those Make targets are the checkout/development path. A verified
`darwin-arm64` release directory instead goes through the transactional native
installer:

```bash
tools/scripts/install_z23.sh --source=build/release/z23-darwin-arm64
```

That path verifies the closed manifest, refuses a node that does not stamp
`tor: full` (and, when the payload cannot run on this host, a missing
`z23.tor-stamp` sidecar), installs immutable generations under
`~/.local/lib/z23/generations/<sha256>` — each directory named by the exact
sha256 SHA256SUMS records for `z23`, the same digest `sha256sum -c --strict`
already verified the installed bytes against, never a hash of the manifest
file itself — switches `current` atomically, validates its plist with
`plutil`, uses `launchctl bootstrap`/`bootout`/`kickstart`, waits for typed
node readiness, qualifies the running image, and automatically restores
`last-good` if the candidate fails. `install_z23.sh --generation-status=<dir>`
reports that directory's provenance (`consistent`/`mismatch`) from the
installed tree alone. It operates on `~/.zclassic-c23`; use only with an
operator-approved release and datadir. The public download front door remains
disabled until the signed platform index and fresh-host acceptance in
[`docs/work/BOOTSTRAP_PLAN.md`](work/BOOTSTRAP_PLAN.md) are complete.

`tools/scripts/install_z23.sh` also installs the Markdown documentation tree
(`docs/**/*.md` only) at `<prefix>/share/z23/docs`, replacing the previous copy
by rename, on Linux and macOS, so `z23 wiki` works outside a checkout. The tree
comes from the `docs/` directory of the checkout holding the script, or from
`Z23_INSTALL_DOCS_DIR`; a script fetched on its own installs none.

`make service-install` fails closed if `$(PREFIX)/bin/z23` is missing, so
run `make install` first or use `make dev-service-install` to run the node
straight from `build/bin/z23`. The LaunchAgent starts at login, restarts on
crash, and logs to `~/.zclassic-c23/z23.{stdout,stderr}.log`. Stop it with
`make service-uninstall` or `launchctl unload ~/Library/LaunchAgents/org.z23.zclassic.plist`.

Pass extra node flags through the service template with
`ZCL_SERVICE_EXTRA_FLAGS`. For a development machine that should cold-start
quickly from the clearnet snapshot seeds rather than crawling every historical
block body from P2P, use:

```bash
make dev-service-install ZCL_SERVICE_EXTRA_FLAGS="-allow-clearnet-snapshot-fetch"
```

This is opt-in and unauthenticated: the node still validates the fetched
snapshot against consensus before trusting it, but the seed itself is not
signed by the chain. Omit the flag for a from-genesis P2P-only sync.

Once you have another synced z23 node on your LAN or VPN, point this Mac at
its file service so z23 nodes help each other bootstrap. The file service
listens on TCP 18034 by default:

```bash
make dev-service-install ZCL_SERVICE_FILESERVICE_PEER="192.168.1.50:18034"
```

If you only know the node's P2P address, use `ZCL_SERVICE_CONNECT_PEER` or
`ZCL_SERVICE_ADDNODE_PEER`. With `-connect`, the node talks only to that peer
and derives a file-service seed from it. With `-addnode`, the node keeps its
normal peer discovery AND treats the named peer as a snapshot seed, so one
known-good z23 peer can bootstrap this Mac without isolating it:

```bash
make dev-service-install ZCL_SERVICE_CONNECT_PEER="192.168.1.50:8033"
# or, keep normal peers and also use this one as a snapshot seed:
make dev-service-install ZCL_SERVICE_ADDNODE_PEER="192.168.1.50:8033"
# or, seed from several known z23 peers at once:
make dev-service-install \
  ZCL_SERVICE_ADDNODE_PEERS="192.168.1.50:8033 192.168.1.51:8033"
```

Installing a fetched snapshot into the canonical daily-driver datadir
(`~/.zclassic-c23`) requires an explicit opt-in environment variable:

```bash
make dev-service-install \
  ZCL_SERVICE_ADDNODE_PEER="192.168.1.50:8033" \
  ZCL_SERVICE_ENV_VARS="ZCL_DEPLOY_ALLOW_CANONICAL=1"
```

Without it, the bundle is verified and registered but the install is deferred
until you set the variable, so the default remains safe.

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

(The repo's own [`platform/deploy/zclassic23-test.service`](../platform/deploy/zclassic23-test.service)
is a worked example of the same pattern: its own datadir, `-port=8035`,
`-rpcport=18234`, `-addnode=127.0.0.1:8034`, `-nobgvalidation` for a faster
boot — a template to copy, not something to install as-is.)

A node started this way (no systemd unit) is stopped with the same binary,
run as its own RPC client against the matching `-datadir`/`-rpcport`:

```bash
build/bin/z23 -datadir="$HOME/.zclassic-c23-dev" -rpcport=18234 stop
```

**First run without touching mainnet:** the command above dials real
mainnet peers immediately — there is no flag that makes it stay offline on
its own. To sanity-check a fresh build without external peer or Tor traffic,
run a `-regtest` node pinned to a dead loopback connect sink, the same pattern
`tools/scripts/isolated_node_env.sh` uses for CI:

```bash
build/bin/z23 -datadir="$HOME/.zclassic-c23-regtest" -regtest \
    -nolegacyimport -no-tor -port=39001 -rpcport=39002 \
    -connect=127.0.0.1:39999
```

Regtest and testnet also disable automatic import from the mainnet
`~/.zclassic` path during argument parsing. The explicit `-nolegacyimport`
keeps this example safe with older binaries that lack that default.

### The fast dev loop

Use bounded manual builds and focused tests for ordinary development. Read
[AGENTS.md](../AGENTS.md) and [DEVELOPING.md](DEVELOPING.md) first. Keep
persistent watchers and services disabled unless explicitly requested.

The commands below are ordinary local developer forms. On a shared development
host, also read its policy, inspect the assigned lane, preserve ownership, and
prefix heavy commands with `devbuild --wait` while retaining repository job
presets. These host tools are not installed by repository setup; a fresh
personal machine uses the standard build procedure above.

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" build-only           # parallel compile-check, no link
make -j"$(getconf _NPROCESSORS_ONLN)" fast-rebuild         # changed-file compile + non-LTO local dev binary
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group>  # one focused test group, fastest iteration
```

These are the `make fast-rebuild` and `make t-fast ONLY=<group>` targets; the
parallel invocations above are the documented developer forms.

The dev binary lives at `build/bin/z23-dev` — a fast local build without
link-time optimization (LTO), for iteration only; never use it for
production/release.

### Running the full test suite and lint

Before committing or pushing, run the canonical gates:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel   # canonical runner (never invoke test_zcl directly)
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
last line it printed. A parked node is not a crash and not a hang — it is a
stated refusal, and every other symptom you might chase is downstream of it.
Missing proving parameters are *not* a cause: since they became optional, a
node without them boots normally and reports a capability blocker instead. If
the gate name is `crypto_params_missing`, the compiled-in verifying keys
failed their integrity check, which means the binary itself is damaged —
rebuild it rather than installing anything.

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
  needs a real-Tor build, which is the default; on a `ZCL_TOR=stub` build
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
and [`AGENT_TRAPS.md`](agent/AGENT_TRAPS.md) for the list of things that look broken
but are intentional or already done.
