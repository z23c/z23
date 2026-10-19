<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Overlay sync and onion marketplace

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

This is the operator map for everything **outside consensus** that moves
bytes between z23 nodes: FlyClient header proofs, the P2P block-piece swarm,
the file-service overlay, and the onion marketplace. Content hashes and
session key derivation here are SHA3-256. Block hashes, txids, merkle roots,
sighashes, Equihash, and the Noise P2P handshake stay SHA-256d /
HKDF-SHA256 so the node remains bit-for-bit consensus-compatible with
`zclassicd`.

Start with the live guides; they name the next safe command:

```bash
build/bin/z23 zcode guide
build/bin/z23 yardsale guide
build/bin/z23 discover help
```

## The onion lives inside this binary

There is no second program to install. These facts are load-bearing for
anyone touching `core/modules/net/src/tor_integration.c`, `onion_service.c`, or
`onion_stream.c`:

- **In-process, not a spawned daemon.** The vendored dynhost Tor fork is
  linked into z23 and its `tor_run_main()` loop runs on a thread we own
  (`g_tor_thread`; `core/modules/net/src/tor_integration.c`). Nothing ever forks,
  execs, or supervises an external `tor` binary. Supervisor liveness
  watches a proxy signal from our monitor poll — it does not instrument
  the vendored loop.
- **Hosting needs no egress machinery.** Default mode mints a fresh
  ephemeral onion service every boot; `-onion-persist` keeps one address
  across restarts (its second port mapping forwards `<onion>:<p2p_port>`
  to the local P2P listener, which is how peers dial us inbound);
  `-onion-rotate` deliberately archives the old identity. Hermetic onion
  tests (`test_onion_stream`, `test_onion_persistence`,
  `test_onion_directory`, …) pass on a host with zero network egress.
- **No SOCKS exists anywhere in this architecture** (owner decision).
  Outbound onion dials open raw dynhost streams that a
  socketpair bridge presents to connman as ordinary connected fds
  (`core/modules/net/src/onion_stream.c`), so reactor, handshake, and message
  layers are transport-unaware.
- **Onion peers are operator-directed only.** They are parsed locally,
  never DNS-resolved, never dialed clearnet, and never gossiped.
- **One honest boundary.** "No egress" above means hosting and hermetic
  testing run offline. Reaching a *remote* `.onion` across the internet
  still rides Tor-network circuits, so wide-area claims belong to
  `make mvp-onion-local`, which SKIPs loudly — never false-greens — when
  the binary links the offline stub or the host has no egress.

## Hash split (do not mix these)

| Surface | Digest / KDF | Why |
| --- | --- | --- |
| Block hash, txid, merkle, sighash, Equihash | SHA-256d / Equihash | Consensus parity with `zclassicd` |
| Noise P2P transport | HKDF-SHA256 (Noise spec) | Interop with the Bitcoin v2 handshake |
| FlyClient samples, MMB / MMR nodes | SHA3-256 with domain tags | Overlay proof, not a block hash |
| Snapshot / chunk / block-piece ids | SHA3-256 | Swarm integrity |
| File-service session key | X25519 + HKDF-SHA3-256 | Overlay confidentiality |
| File-service frame MAC and CTR | SHA3-256 | Overlay authenticity |
| Onion marketplace chunk ids | SHA3-256 | Paid delivery integrity |

A SHA3 of overlay bytes does not prove consensus. A block hash does not
authenticate a swarm piece. Evidence establishes only its exact stated claim.

## Fast overlay sync

Three native paths, in order of cost. Canonical chain state is still
locally validated; see [`SYNC.md`](SYNC.md).

1. **Block-piece swarm (default among caught-up z23 peers).** A node that
   already has bodies within 1024 headers of tip advertises SHA3-addressed
   64-block pieces over the file-service overlay. IBD nodes skip publishing
   so boot is not spent hashing a manifest they will replace. Source:
   `engine/composition/src/boot_snapshot_offer.c`, `core/modules/net/src/fast_sync.c`.
2. **FlyClient proofs.** Peers challenge header history (`zsnapshot` →
   `zfcchallenge` → `zfcproofs` → `zsnapreq`). Sample selection and MMB
   nodes are SHA3-256. This proves advertised header chainwork, not a UTXO
   root. Source: `core/modules/net/src/flyclient.c`, `core/modules/chain/src/mmb.c`.
3. **UTXO snapshot (opt-in).** Export takes DB read locks, so it stays
   behind `ZCL_PUBLISH_FASTSYNC_ON_BOOT`. Chunk hashes are SHA3-256.
   Activation remains contained until the unified installer can bind
   transparent, Sapling, Sprout, nullifier, cursor, log, and provenance
   state together.

```bash
# Speak z23 overlay to a peer (clearnet or onion).
build/bin/z23 -addnode=<z23_peer>

# Same path over a persistent onion identity.
build/bin/z23 -tor -onion-persist -addnode=<peer>.onion:<p2p_port>
```

Do not set `ZCL_PUBLISH_FASTSYNC_ON_BOOT` on a box that is still climbing
IBD. Block-piece serving is the cheap assist; snapshot export is the
expensive one.

## Secure overlay transport

The file-service port is a separate TCP (or onion) stream from consensus
P2P. Handshake:

1. Ephemeral X25519 public keys are exchanged.
2. Session key = HKDF-SHA3-256(salt = UTXO root, IKM = shared secret,
   info = domain `zcl.file-service.x25519-hkdf-sha3.v1` plus both public
   keys).
3. Each side sends a SHA3-256 key confirmation. Mixed-version peers fail
   closed; there is no SHA-256 KDF fallback.
4. Frames are 64 KiB, SHA3-authenticated, SHA3-CTR encrypted.

Paid marketplace delivery binds its signed request to these session public
keys. ROM fetch uses the same handshake with an all-zero UTXO root and
then verifies content SHA3; it never installs consensus state. See
[`ROM_DELIVERY.md`](../ROM_DELIVERY.md).

## Onion marketplace

Yardsale, package swarm, and the onion shop are the three sell surfaces.
The live command tree is the authority:

```bash
build/bin/z23 yardsale guide
build/bin/z23 discover schema yardsale.seller.arm
build/bin/z23 discover schema app.market.offer
build/bin/z23 discover schema app.shop.init
```

- **Yardsale** is on-chain 1/1 collectible sale. Gossip carries the ad
  pointer only. Plan first; `confirm:true` spends.
- **Package swarm** announces exact content-addressed roots and serves
  SHA3-verified chunks. Fetch is inert: no build, no install.
- **Onion shop** is the private storefront: persistent onion identity,
  product rows, Sapling pay, hash-verified download over the file-service
  overlay.

Details and custody rules: [`SELL.md`](SELL.md). A production / canonical
datadir is not mutated by these guides. Use an isolated `--datadir=` for
experiments.

## Vanity onion address

`core network onion vanity` searches for a v3 onion identity seed whose
address begins with a chosen prefix and writes the seed to a file you name.
It runs offline: no node and no Tor. It writes only to the path you name and
never replaces an existing file. The file is the Z23 raw 32-byte identity
seed, not Tor's own key file format.

```bash
# Figures first: expected tries and time at this machine's measured rate.
build/bin/z23 core network onion vanity \
  --input='{"prefix":"abc","estimate_only":true}'

# Search. Writes the 32-byte seed (mode 0600) and prints the address.
build/bin/z23 core network onion vanity \
  --input='{"prefix":"abc","output_path":"'"$HOME"'/vanity_seed"}'
```

Inputs: `prefix` (1 to 12 characters of `a-z` and `2-7`, upper case is
lower-cased; any other character is refused by name), `output_path` (must not
exist), `threads` (default: available CPUs minus one, at most 64),
`max_tries`, `timeout_s`, `estimate_only`, `accept_long_search`. The reply
carries the address, tries, seconds, tries per second, threads, expected
tries (32^length) and the path; it never carries the seed. A search whose
expected time exceeds one hour at a rate measured over 200 ms is refused
until `accept_long_search` is `true`. Ctrl-C stops all workers and writes
nothing.

Expected time to a first match is the mean; the distribution is geometric, so
a single run can be several times shorter or longer. Measured 2026-10-12 on
an Intel Xeon E3-1241 v3 (8 threads, shared with other builds, GCC 14.2.0):
about 650 candidates per second per thread and 3500 per second with 7
threads. One 4-character search took 698,943 tries in 199 s (expected
1,048,576).

| Prefix length | Expected tries | Expected time at 3500 tries/s |
|---|---|---|
| 5 | 33,554,432 | 2.7 hours |
| 6 | 1,073,741,824 | 3.5 days |
| 7 | 34,359,738,368 | 114 days |
| 8 | 1,099,511,627,776 | 10 years |

The rate is bounded by the in-tree ed25519 key derivation, one full scalar
multiplication per candidate. Dedicated vanity tools add a fixed point to the
previous public key instead and are orders of magnitude faster; the in-tree
API would need to expose a point addition on public keys and a way to derive
the matching secret scalar offset before this tool could do the same.

Security notes:

- The seed file is a private key. Anyone who reads it controls the address.
- Generate it on a machine you control. Never ask a service or another
  person to search for you: they would hold the key.
- The file is created mode 0600, flushed, then renamed into place; an existing
  `output_path` is never overwritten. A completed or failed run leaves no
  temporary file; a process that is killed mid-write can leave
  `<output_path>.tmp-xxxxxxxx` (mode 0600), which may hold the seed and should
  be deleted.
- Candidates come from the host CSPRNG, and candidate key material is wiped
  from memory after each test.

To use the seed, stop the node and place the file by hand at
`<datadir>/tor_data/onion_service/identity_seed` with mode 0600, then start
with `-onion-persist`. The command does not install the seed for you. If an
identity already exists there, `-onion-rotate` archives it; the old address
is lost to peers.

## What this is not

- Not a consensus fork. Do not SHA3 block hashes or Equihash.
- Not a Noise change. The Bitcoin-compatible P2P transport (BIP324 v2) stays
  HKDF-SHA256.
- Not a grant of wallet, deployment, or datadir authority. Fetching overlay
  bytes is storage; building and testing are separate; installing or
  deploying is operator-gated.
- Not a claim that a snapshot or swarm piece is sovereign. Background
  verification still has to promote assisted state.

## Source map

```bash
build/bin/z23 discover search flyclient
build/bin/z23 discover search file-service
build/bin/z23 discover search yardsale
build/bin/z23 code map
```

Primary files:

- `core/modules/crypto/src/{hmac_sha3,hkdf_sha3}.c` — overlay HMAC / HKDF
- `core/modules/net/src/tor_integration.c` — in-process Tor thread, identity persistence
- `core/modules/net/src/onion_stream.c` — dynhost raw stream ↔ socketpair bridge
- `core/modules/net/src/file_service_handshake.c` — X25519 + HKDF-SHA3-256
- `core/modules/net/src/fast_sync.c` — snapshot / piece manifests (SHA3 ids)
- `core/modules/net/src/flyclient.c` — FlyClient challenge / proof
- `core/modules/net/src/file_market_delivery.c` — paid overlay delivery
- `core/modules/net/src/file_market_delivery_onion.c` — onion GET path
- `engine/composition/src/boot_snapshot_offer.c` — boot-time swarm / snapshot publish
