<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Overlay sync and onion marketplace

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

This is the operator map for everything **outside consensus** that moves
bytes between z23 nodes: FlyClient header proofs, the P2P block-piece swarm,
the file-service overlay, and the onion marketplace. Content hashes and
session key derivation here are SHA3-256. Block hashes, txids, merkle roots,
sighashes, Equihash, and the Noise v2 P2P handshake stay SHA-256d /
HKDF-SHA256 so the node remains bit-for-bit consensus-compatible with
`zclassicd`.

Start with the live guides; they name the next safe command:

```bash
build/bin/z23 zcode guide
build/bin/z23 yardsale guide
build/bin/z23 discover help
```

## Hash split (do not mix these)

| Surface | Digest / KDF | Why |
| --- | --- | --- |
| Block hash, txid, merkle, sighash, Equihash | SHA-256d / Equihash | Consensus parity with `zclassicd` |
| Noise v2 P2P transport | HKDF-SHA256 (Noise spec) | Interop with the v2 handshake |
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
   `config/src/boot_snapshot_offer.c`, `lib/net/src/fast_sync.c`.
2. **FlyClient proofs.** Peers challenge header history (`zsnapshot` →
   `zfcchallenge` → `zfcproofs` → `zsnapreq`). Sample selection and MMB
   nodes are SHA3-256. This proves advertised header chainwork, not a UTXO
   root. Source: `lib/net/src/flyclient.c`, `lib/chain/src/mmb.c`.
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
[`ROM_DELIVERY.md`](ROM_DELIVERY.md).

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

## What this is not

- Not a consensus fork. Do not SHA3 block hashes or Equihash.
- Not a Noise v2 change. The Bitcoin-compatible v2 transport stays
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

- `lib/crypto/src/{hmac_sha3,hkdf_sha3}.c` — overlay HMAC / HKDF
- `lib/net/src/file_service_handshake.c` — X25519 + HKDF-SHA3-256
- `lib/net/src/fast_sync.c` — snapshot / piece manifests (SHA3 ids)
- `lib/net/src/flyclient.c` — FlyClient challenge / proof
- `lib/net/src/file_market_delivery.c` — paid overlay delivery
- `lib/net/src/file_market_delivery_onion.c` — onion GET path
- `config/src/boot_snapshot_offer.c` — boot-time swarm / snapshot publish
