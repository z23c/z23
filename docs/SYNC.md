<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Z23 Sync Guide

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

How a fresh z23 node reaches chain tip, plus the one legacy-bootstrap
path that exists only while the native peer network is still small. Primary =
z23-native; legacy = pulling data from the old C++ `zclassicd`. Overlay
proofs, swarm piece ids, and the file-service handshake use SHA3-256;
consensus block hashes stay SHA-256d. The operator map is
[`OVERLAY.md`](OVERLAY.md).

## Canonical Authority Model

Canonical chain state is always **locally validated and evidence-published**.
The only publishable active tip is one that passes the local validation and
evidence gate:

- `chain_advance_coordinator` chooses which input source may provide candidate
  headers or bodies.
- `chain_activation_controller` is the block-connection entrypoint.
- the chain-evidence logic (now in `chain_evidence_persistence_service`/`_authority_service`/`_snapshot`)
  decides whether a tip transition has enough local evidence to publish.
- `chain_state_repository` performs the atomic in-memory/persistent state
  update, and `chain_tip` is the public active-tip publication wrapper.
- `legacy_mirror_sync_service` may fetch candidate data from `zclassicd` and
  request work, but it cannot make `zclassicd` a consensus authority.

`zclassicd` is removable advisory infrastructure that may accelerate bootstrap.
Matching it is not proof of canonical state; diverging from it is not by itself
a reason to rewind or publish a tip. Health/status surfaces must keep
`consensus_authority=local_consensus_validation`; `candidate_*` fields describe
source and trust class only. Any `unsafe_overrides_total > 0` is fail-loud.

---

## Method 1 (native): P2P Fast Sync (~60 s design target, not yet the proven everyday path)

A fresh node downloads a verified UTXO snapshot from another z23 peer,
then catches up the tail via standard P2P. Activation is automatic — any peer
advertising service bit `NODE_ZCL23` (`lib/net/include/net/fast_sync.h`)
becomes a snapshot candidate. Caught-up z23 peers also advertise SHA3
block-piece manifests for IBD assist without the UTXO-export lock cost.
The machinery below is built and code-tested;
a full fresh z23-to-z23 sync-to-tip run has not yet been proven
end-to-end on a live network (see `docs/HANDOFF.md` C3 status) — today's
proven cold-start is Method 3 below. Overlay hashes and the file-service
KDF are SHA3-256; see [`OVERLAY.md`](OVERLAY.md).

```bash
build/bin/z23 -addnode=<z23_peer>
```

What happens:
1. Find a peer advertising `NODE_ZCL23`.
2. Receive a strict v2 UTXO snapshot manifest (protocol/schema version,
   anchor height/hash, serving peer tip, chainwork, UTXO SHA3, byte length,
   UTXO count, chunk size/count, and per-chunk hashes).
3. Download chunks in parallel, verify each chunk hash before import.
4. Verify the FlyClient MMR/MMB proof for the advertised header history and
   reject missing or non-competitive chainwork. This does **not** bind the
   peer's UTXO payload to ZClassic consensus; headers commit no UTXO root.
5. Verify the imported UTXO bytes exactly match the peer manifest's SHA3. This
   is integrity under assisted trust, not a consensus proof.
6. Keep the verified payload in staging. Runtime activation is Phase-0
   contained until one unified installer can atomically bind transparent,
   Sapling, Sprout, nullifier, cursor, log, and provenance state; only then may
   a future assisted mode delta-sync the finality window.

The current peer path is a verification/staging path, not a fresh-deployment
bootstrap authority. A contained activation ends in the typed
`snapshot_sync.activation_unified_installer_required` blocker and cannot enter
`SNAPSYNC_COMPLETE`.

### zclassic-only serving profile

`-profile=zclassic-only` is intended for power nodes whose job is to sync other
nodes quickly. Today it keeps consensus state, P2P, RPC, FlyClient/MMB proof
serving, and normal block relay; snapshot offer construction and payload serving
remain contained until the `coins_kv` payload-binding gate exists. It does not start explorer
cache prewarming, store/market services, onion hosting (unless `-tor` is set), or
file-service snapshot export and chunk/block-piece manifests.

Full, onion-node, and legacy-compat profiles keep the broader app surfaces. The
explorer profile keeps explorer APIs and cache prewarming but still avoids store
and file-service serving.

---

## Method 2 (native): Full P2P Sync (~7 h)

Trustless sync from genesis over the standard P2P protocol. No snapshot.

```bash
build/bin/z23 -addnode=<any_peer>
```

Headers → blocks → connect. Scripts/signatures below deferred proof validation
height (h=3,100,000, the latest mainnet checkpoint) are accepted; full validation
runs above that. Background
services then re-verify every hash, signature, and proof end to end.

Use when no snapshot source is available, or as the path toward local
sovereignty. The current end-to-end genesis-to-tip timing/validation claim still
requires exact-candidate proof; see `docs/HANDOFF.md`.

---

## Method 3 (legacy bootstrap, development only): Import from zclassicd

**This path exists because the native peer network is still small on mainnet.**
It reads data from a synced legacy `zclassicd` (C++) on the same machine to get
developer workstations to tip fast. Its block files, UTXO snapshots, and
height/hash answers seed candidates only — tip publication still requires the
local activation/evidence path (see Canonical Authority Model above). It goes
away once the native peer network is healthy.

Requirements: a local synced legacy `zclassicd` with `~/.zclassic/` (leave it
running — on the operator host it is isolated on P2P 8034 / RPC 8232 while
`z23` owns canonical P2P 8033).

This is the canonical home for the recipe — **two steps, in this order**:

```bash
# 1. Headers FIRST — imports ~3.1M headers in ~60-74 s from the legacy datadir.
build/bin/z23 --importblockindex $HOME/.zclassic

# 2. Then a NORMAL boot — legacy import is on by default; it auto-reads/links
#    ~/.zclassic and follows the legacy import path. Opt out with
#    -nolegacyimport. Current shielded-history completeness still gates serving.
build/bin/z23
```

Skipping step 1 is a footgun: importing UTXOs without the header import leaves a
~3.1M-header hole (headers=960) and the node pins. The old single-flag forms
(`-cold-import=`/`-fastimport=`) no longer exist. Passing one does **not**
silently no-op: the argv loop prints
`Warning: unrecognized flag '<f>' (ignored) — check spelling or docs/RUNBOOK.md`
to stderr on every boot (`config/src/args.c`). It is advisory, never fatal, so
grep stderr for `unrecognized flag` after any flag change.

**Caveat:** the legacy cold import is slow (a ~12k-block header band backfills
over P2P, and the first boot can latch a transient freeze that needs a restart).
The robust path for a known-good datadir is to copy one onto the target lane.

### Consolidated daily-driver loader (assisted legacy bootstrap)

The deployed path is `-load-snapshot-at-own-height`: it loads a
digest-verified borrowed UTXO snapshot above coins-best and folds forward.
Verify current sync state with `z23 status` /
`z23 dumpstate reducer_frontier`; `docs/HANDOFF.md` holds current
state, never this doc. The snapshot's `anchor_block_hash` must byte-equal
this node's in-binary PoW header at the seed height or boot FATALs — a
wrong-chain or missing anchor fails closed (`config/src/boot_refold_staged.c`,
the load-snapshot-at-own-height path; the anchor-hash cross-check is at ~line
585). When the seed height is above the coins-best active-chain window, the
loader extends that window forward to the PoW-proven header tip
(`active_chain_extend_window`, line 568) instead of FATAL-ing "Run
--importblockindex". The artifact is **release-assisted borrowed state**:
its payload digest authenticates bytes and the header match verifies chain
location, but neither proves the UTXO/Sapling/Sprout/nullifier contents because
ZClassic headers commit no such roots. The **fold-from-checkpoint** path
below (`-refold-from-anchor` / `-load-verify-boot`) folds forward from the
verified compiled checkpoint instead of accepting this loader's borrowed
tip-height seed; making it the cold-start default and deleting the
borrowed-seed machinery is still open work — design `work/never-stuck-plan.md`,
posture `HANDOFF.md`.

### Fold from checkpoint (skip the from-genesis reducer fold)

A **verified** `utxo-anchor.snapshot` artifact (produced offline by the
`-mint-anchor` ceremony, SHA3-bound to the compiled checkpoint) lets a fresh
node skip folding the reducer from genesis. It requires a SOURCE datadir that
already has headers *and* on-disk bodies — the two-step
`--importblockindex` recipe above satisfies this — plus the verified
`<DATADIR>/utxo-anchor.snapshot` file in place:

```bash
build/bin/z23 --importblockindex "$HOME/.zclassic"   # headers + legacy body link
build/bin/z23 -refold-from-anchor                    # or -load-verify-boot to auto-detect
```

What happens: the loader re-seeds `coins_kv` from the snapshot and
HARD-ASSERTs the result against the compiled checkpoint's SHA3 digest and
UTXO count (`coins_kv_verify_against_checkpoint`) — a mismatch FATALs rather
than silently falling back to a from-genesis fold. On success it forces all
eight reducer-stage cursors (`header_admit`, `validate_headers`,
`body_fetch`, `body_persist`, `script_validate`, `proof_validate`,
`utxo_apply`, `tip_finalize`) to the checkpoint height instead of genesis, so
the fold resumes at the checkpoint and climbs only the tail —
`current header tip − checkpoint height` blocks — over on-disk bodies,
instead of the full from-genesis span. The nightly anchor→tip replay canary
(`tools/scripts/replay_canary.sh`) measures this tail fold at roughly 45
minutes on the present chain length, versus hours for Method 2's full
genesis fold.

`-refold-from-anchor` is an explicit opt-in flag; `-load-verify-boot` reaches
the same reset automatically on a normal boot when a matching verified
snapshot is present and `coins_kv` is not already the proven authority —
with no snapshot present, or a SHA3 mismatch, the predicate is false and the
current boot path (cold-import seed) runs unchanged.

**This path is transparent-state only.** It marks the Sprout and Sapling
anchor/nullifier history below the checkpoint as empty rather than forging
it, which raises both `utxo_apply.anchor_backfill_gap` and
`utxo_apply.nullifier_backfill_gap` — see
[`docs/RUNBOOK.md`](RUNBOOK.md) "Shielded-History Wedge" for the cure. The
resulting posture is `release_assisted`, not the `sovereign`
(`coins_kv_contains_refold_marker`) bit — the currently-proven sovereignty
path is the complete consensus-state bundle install,
[`docs/work/sovereign-cutover-runbook.md`](work/sovereign-cutover-runbook.md).

Rules:
- The import flags **only run on an empty datadir** (or one below the legacy
  tip). They refuse if our active tip already meets/exceeds legacy.
- Legacy data is acceleration only. It must match compiled SHA3 windows,
  runtime windows, local consensus checks, or z23 quorum before it
  elevates trust.
- Force reimport after a first run:
  `build/bin/z23 -reimport-utxos -datadir=~/.zclassic-c23`

The live/default legacy reference is the `zclassicd` systemd user service (see
CLAUDE.md "Services"). `zclassicd-peer.service` is only the operator-specific
example unit committed under `deploy/examples/`.

### Legacy chain oracle boundary

All direct reads from local legacy `zclassicd` RPC go through
`rpc/legacy_rpc_client.h` for transport and `rpc/legacy_chain_oracle.h` for
typed chain data such as block hashes, MMB leaves, and chainwork. Boot-time MMB
catchup, fast-sync offer construction, FlyClient proof fallback, and the
zclassicd drift oracle share that transport instead of parsing JSON-RPC in
their own service code.

This boundary keeps legacy compatibility behind a small adapter. Assisted
snapshot acceptance still checks the manifest, advertised header proof,
PoW/chainwork, finality policy, and payload SHA3. Those checks do not promote
peer state to sovereignty; background full-history verification must do that.

---

## Verification Layers

Sync methods can reach different trust states. Background services must promote
assisted state only after full-history verification reaches the serving tip and
complete state commitments match. Current checks include:

| Service | What it verifies | Speed |
|---------|------------------|-------|
| `bg_hash_verify` | SHA256d of every block header | 83K blk/s |
| `bg_validation`  | Equihash, ECDSA, Groth16, merkle roots | 400–500 blk/s |
| Boot checks      | UTXO count + XOR commitment vs checkpoint | ~2 s |
| Post-import      | SHA3-256 full UTXO set vs hardcoded commitment | ~5 s |

See [`validation/VALIDATION_MATRIX.md`](validation/VALIDATION_MATRIX.md) for the full matrix.

Self-healing recovery mechanisms (missing UTXO, reorg unwind, wrong block on
disk, stale `coins_best_block`, download stall) are documented in
[`validation/VALIDATION_MATRIX.md`](validation/VALIDATION_MATRIX.md) → "Self-Healing
Mechanisms".

---

## Data Directory

```
~/.zclassic-c23/
├── node.db                  SQLite (UTXOs, block index, node state, wallet)
├── node.db-{wal,shm}        WAL companion files
├── consensus_snapshot.db    SQLite (snapshot under construction or applied)
├── blocks/
│   ├── blk*.dat             Block data (4B magic + 4B size + block)
│   ├── rev*.dat             Undo data for reorgs
│   └── index/               LevelDB block index (legacy / cold-import only)
├── block_index.bin          Optional flat file cache (instant restart load)
├── mmb_leaves.bin           Merkle Mountain Belt leaf cache
├── file_manifest.bin        File-service chunk manifest
├── explorer/                Block-explorer cache (factoids, CSS)
├── tor_data/                Embedded Tor state (when -tor is set)
├── .cookie                  RPC auth cookie
└── node.log                 Structured event log
```

`node_state` SQLite keys are documented in
[`validation/VALIDATION_MATRIX.md`](validation/VALIDATION_MATRIX.md) → "SQLite
`node_state` keys".

Finality policy: `ZCL_FINALITY_DEPTH=10`. Heights `<= tip - 10` are treated as
immutable for reorg refusal, snapshot eligibility, rolling SHA3 anchors,
block-window reuse, and diagnostics. Steady-state reorgs of 10 blocks or less
are allowed; 11-block reorgs are refused. IBD can still resolve deeper
competition before a verified immutable anchor is installed. These decisions are
centralized in `validation/sync_evidence_policy.h`. `COINBASE_MATURITY=100`
remains a consensus spend-maturity rule and does not control reorg depth or
immutable-prefix policy.

Snapshot protocol: z23 peers must speak
`FAST_SYNC_PROTOCOL_VERSION=2` and `FAST_SYNC_SNAPSHOT_SCHEMA_VERSION=1`.
Missing v2 fields, zero chainwork, non-final anchors, missing MMR/MMB roots,
or stale schemas are rejected. Legacy/non-v2 data may still be used locally
for bootstrap acceleration, but it is not trusted P2P snapshot sync.

Quorum model: votes are grouped by source class — local z23, local
zclassicd, remote z23 peers. Remote votes are keyed by unique peer and
expire by TTL; rolling-anchor commits require a matching source-class quorum when
multiple classes are available. Splits halt anchor extension and are visible
through the quorum/oracle dumpstate surface.

Rolling anchors: runtime SHA3 windows are persisted only for fully immutable
windows with local block bytes present, normal oracle policy, and quorum
approval. On load, runtime anchor files are checksum-, schema-, alignment-, and
continuity-checked against compiled anchors; failures discard the runtime file.

---

## Check sync status

Use `z23 status`, `z23 core sync status`, and
`z23 core sync validation`. The native RPC fallback is
`z23 rpc getblockchaininfo`. Status and state
surfaces include sync phase, local/header/peer heights, immutable height,
snapshot anchor, UTXO root, chainwork/quorum verdict, watchdog state, last
recovery, and active acceleration source where available.

For OOM-kill recovery, memory-pressure diagnosis, and the exact stuck-tip /
nuclear-reset recovery commands (which file list to delete — this node has no
`chainstate/` LevelDB directory; that name belongs to the legacy `zclassicd`
sibling install), see [`RUNBOOK.md`](./RUNBOOK.md) §"Tip Regressed / Stuck on
Wrong Fork" and §"High Memory Usage". After any reset the node re-syncs via
Method 1 or 2 from its configured peers.

---

## Architecture

```
        NATIVE                                   LEGACY BOOTSTRAP
┌──────────────────────┬──────────────────┐  ┌────────────────────┐
│  Method 1: fastsync  │ Method 2: full   │  │ Method 3: from     │
│  z23 peer     │ P2P from genesis │  │ zclassicd          │
│  ~60 s design target │ ~7 h             │  │ chainstate → SQLite│
│  (unproven — see     │                  │  │ ~20 s, dev-only    │
│  HANDOFF.md C3)      │                  │  │                    │
│  NODE_ZCL23 + chunks │ headers + blocks │  │                    │
└──────────┬───────────┴────────┬─────────┘  └─────────┬──────────┘
           │                    │                      │
           ▼                    ▼                      ▼
         ┌───────────────────────────────────────────────┐
         │           UTXO SET (SQLite)                   │
         │  1.35M entries · coins_best_block @ tip       │
         └────────────────────┬──────────────────────────┘
                              ▼
         ┌───────────────────────────────────────────────┐
         │        BACKGROUND VERIFICATION                │
         │  bg_hash_verify · bg_validation · checkpoints │
         └───────────────────────────────────────────────┘
```
