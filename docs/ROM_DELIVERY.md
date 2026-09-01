# ROM delivery — free-tier P2P distribution of the sync artifacts

z23 is a P2P file delivery system, and the files it delivers fastest
and most generously are its own bootstrap ("ROM") artifacts: the consensus-
state bundle (`zcl.consensus_state_bundle.v1`, see
[`docs/work/CONSENSUS-STATE-BUNDLE.md`](./work/CONSENSUS-STATE-BUNDLE.md)) and
header-chain seed data. A fresh node should be able to pull these from any
peer — free, unmetered, no payment — instead of folding block-by-block from
genesis. This page covers the trust model, the policy knobs that keep
generosity from becoming a bandwidth liability, the operator commands, and
the fetch recipe.

## Trust model — delivery is untrusted, content is verified

Nothing about who serves an artifact, how fast, or how many peers vouch for
it makes that artifact more trustworthy. A malicious or careless seeder can
waste a fetcher's bandwidth; it cannot poison the fetcher's state, because
every artifact is verified by content after download, never by transport:

1. **Whole-file digest.** The downloaded bundle is hashed (SHA3-256) and
   compared against the digest the fetcher already committed to before
   requesting chunks — a mismatch discards the whole file, no partial trust.
2. **Checkpoint re-derivation.** The installer re-derives the compiled
   checkpoint SHA3 from the bundle's contents and Pedersen-roots the Sapling
   frontier against the PoW header chain it has independently validated. See
   [`docs/work/CONSENSUS-STATE-BUNDLE.md`](./work/CONSENSUS-STATE-BUNDLE.md)
   for the full component list a bundle must independently prove.
3. **PoW header roots remain the anchor.** `hashFinalSaplingRoot` and the
   rest of the header commitment are validated against the header chain the
   node builds itself; a bundle's own claims about height/hash only matter
   once they tie back to that independently-validated chain.

The practical effect: seeding capability ships **enabled by default**. There
is no safety reason to gate it behind an opt-in, because a seeder cannot
corrupt what it serves — it can only be slow, rude, or absent, all of which
the policy layer below bounds.

## Policy layer

The policy surface lives in `core/modules/net/include/net/rom_seed_policy.h` /
`core/modules/net/src/rom_seed_policy.c`. It is deliberately narrow: config-backed
knobs, pure admission/boost decision helpers, and live counters. It never
opens a socket, reads a chunk off disk, or speaks the wire protocol — the
seed engine (the artifact registry + chunk-serving path, `dumpstate
rom_seed`) is the thing that calls into this header on every admission
decision and every completed/refused upload.

| Knob | Default | Purpose |
|---|---|---|
| `enabled` | on | Master switch. Off refuses every new upload regardless of load. |
| `global_up_bytes_per_sec` | 50 MB/s | Node-wide upload cap across all artifact serving. |
| `per_peer_up_bytes_per_sec` | 2 MB/s | Per-peer upload cap, so one requester cannot claim the whole global seat. |
| `max_concurrent_uploads` | 24 | Concurrency cap independent of bandwidth. |
| `generosity_boost_days` | 7 | A freshly-registered artifact gets a per-peer cap multiplier for its first N days — the network needs new ROM spread fast, before it has many seeders. |

Policy is persisted at `<datadir>/rom_seed_policy.json`, written tmp+rename
(crash-safe, never a torn read) and falling back to the compiled defaults on
a missing or corrupt file — the policy module never refuses to boot and
never crashes on a bad file. Owner-mutating changes go through
`rom_seed_policy_apply()`, which validates against fixed bounds
(`ROM_SEED_POLICY_MIN/MAX_*` in the header) and leaves the live policy
untouched on any validation failure — never a partial apply.

### Consensus always preempts artifact traffic

This is a hard rule, not a knob. Whatever the reducer/sync supervisor judges
necessary for consensus progress (headers, bodies, tx relay) outranks
artifact seeding. The sync supervisor calls
`rom_seed_policy_set_consensus_active(true)` whenever that pressure is live;
`rom_seed_policy_admit_upload()` then refuses new uploads until the signal
clears. A caller that never touches the signal gets
`rom_seed_policy_consensus_active() == false` forever — safe by default, no
silent seeding disablement from an unwired caller.

### The serve-path contract

A chunk-serving path is expected to call, in order:

1. `rom_seed_policy_admit_upload(current_active_uploads)` before accepting a
   new upload — false means refuse (disabled, consensus-preempted, or at the
   concurrency cap).
2. `rom_seed_policy_note_upload_started()` on acceptance.
3. `rom_seed_policy_effective_per_peer_cap(boosted)` to throttle bytes/sec
   for that peer, where `boosted` comes from
   `rom_seed_policy_is_boosted(artifact_first_seen_unix, now)`.
4. `rom_seed_policy_note_upload_finished(bytes_sent)` or
   `rom_seed_policy_note_upload_refused()` on completion/refusal.

If a sibling engine's serve path is shaped a little differently, wrap these
calls in a thin adapter — the surface is intentionally small so the wiring
stays trivial regardless of naming differences on either side.

## Serve-log ledger

`core/modules/net/include/net/rom_seed_ledger.h` /
`core/modules/net/src/rom_seed_ledger.c` is an append-only, retention-capped record
of completed (or aborted) serve sessions — which peer, which artifact, how
many chunks/bytes, when — stored in `<datadir>/rom_seed_ledger.db`
(`artifact_serve_log` table), following the same append-then-prune shape as
the `peer_sessions` ledger in `engine/modules/storage/src/peers_projection.c`. It caps
at `ROM_SEED_LEDGER_RETENTION_CAP` rows (delete-oldest past the cap) so
telemetry never grows unbounded. This is observability, not consensus state
or a rebuildable projection — there is no upstream event log this table
folds from; the ledger IS the append point.

`artifact_id` is an opaque 32-byte digest (the SHA3 root the caller already
has), so the ledger never needs to know the seed engine's own artifact-
metadata shape.

## Bundle replication — one disk to many seeders

The two-builder-verified consensus-state bundle (`docs/work/CONSENSUS-STATE-
BUNDLE.md`) is exported once and, today, tends to live on a single machine's
disk. Two pieces close that single point of failure without weakening
rom_seed's untrusted-delivery model: a **receipt-gated admission gate**
(`config/rom_bundle_admission.h`) and a **replication helper**
(`tools/scripts/rom-bundle-replicate.sh`).

**The gate.** `net/rom_seed.h`'s own `rom_seed_scan_datadir()` admits any
`consensus-state-bundle-*.sqlite` on structural grounds alone (SQLite magic +
size band) — correct for the primary datadir, where every fetcher
re-verifies content after download regardless. A **second**, operator-
designated directory (`-rombundlereplicadir=PATH`) goes through a stricter
path instead: `rom_bundle_admission_register()` computes the candidate
bundle's own SHA3-256 whole-file digest, then requires
`PATH/consensus_state_replay_receipt.v1` to self-verify (schema + its own
domain-separated binding digest — byte tampering fails here) **and** bind
that exact digest, before ever calling into the shared `rom_seed` registry.
No receipt, wrong receipt, or a receipt bound to a different bundle's bytes
all refuse — fail-closed, catalog untouched, nothing served. This check
deliberately does **not** require the serving node to be the exact binary
that produced/verified the receipt (unlike the ACTIVATE authority check in
`config/consensus_state_replay_receipt.h`, which does) — a seeding node is
almost never the node that ran `-verify-consensus-bundle`.

**The replicator.** `tools/scripts/rom-bundle-replicate.sh --bundle=... 
--receipt=... --dest=DIR` copies the bundle + receipt (renamed to the
canonical `consensus_state_replay_receipt.v1` the gate looks for) + a SHA3
record of the producing binary into `DIR`, then re-hashes both copies with
the standalone `rom_bundle_sha3` tool (`make tools/rom_bundle_sha3`; links
only `platform/modules/sha3/src/sha3.c`, no node libs) and refuses to report success
unless every digest matches the source exactly. `make rom-bundle-replicate
BUNDLE=... RECEIPT=... DEST=...` wraps the same script. Point a node's
`-rombundlereplicadir=DIR` at the result (or at a further copy of it, on a
different disk or a different machine entirely) to turn it into another
free-tier P2P recovery source for the same bundle.

## Operator commands

All three live under `ops.debug.rom_seed.*` (native command registry — see
[`docs/NATIVE_COMMAND_INTERFACE.md`](./NATIVE_COMMAND_INTERFACE.md)). They
nest under `ops.debug` rather than a new top-level `ops.*` branch because
the top-level `ops` menu is already at its listing-budget ceiling
(`ZCL_COMMAND_BRANCH_BUDGET`) — see the precedent comment above
`ops.debug.dash` in `engine/composition/commands/ops.def`:

```bash
z23 ops debug rom_seed status      # policy + live counters + ledger availability
z23 ops debug rom_seed enable      # owner-mutating: turn seeding on
z23 ops debug rom_seed disable     # owner-mutating: turn seeding off
z23 ops debug rom_seed artifacts   # every artifact served + per-artifact seed stats
```

`status` and `artifacts` are public reads; `enable`/`disable` are
owner-authenticated mutating leaves (idempotent — enabling an
already-enabled policy, or disabling an already-disabled one, returns the
same settled state). `dumpstate rom_seed_policy` and `dumpstate
rom_seed_ledger` expose the same data through the generic diagnostics
primitive, per the "Adding state introspection" convention in the repo's
`CLAUDE.md`.

`ops.debug.rom_seed.artifacts` reports `seed_stats` folded from the local
serve log today. The seed engine's own artifact registry (names, digests, the
free-tier artifact catalog) is a sibling subsystem (`dumpstate rom_seed`);
until it is wired into a given build, the `registry` section of the reply
honestly reports `available: false` rather than guessing at that lane's
shape.

## Fresh-node fetch recipe

A fresh node fetches the ROM artifacts from any peer that has them, verifies
by content, and installs — no operator setup required beyond a normal boot:

1. Boot with networking enabled (default). The node discovers peers via
   normal P2P bootstrap or, with `-tor`, the onion directory
   (`/directory.json`) served by any Tor-enabled peer.
2. The fetch engine (`dumpstate rom_fetch`, sibling subsystem) requests the
   consensus-state bundle and header-chain seed data from multiple seeders
   in parallel, verifying each downloaded chunk's position/length against the
   manifest before accepting it.
3. On whole-file digest match, the installer re-derives the checkpoint SHA3
   and Pedersen-roots the Sapling frontier against the independently
   validated PoW header chain (see Trust model above). Only a bundle that
   passes this re-derivation is installed.
4. The node then folds forward from the installed checkpoint via normal
   block-body sync to reach the live tip.

A node that never finds a peer serving these artifacts falls back to the
legacy two-step `--importblockindex` + boot recovery path (see the
Tenacity section of the repo's `CLAUDE.md`) — ROM delivery is an
acceleration, not a hard dependency.

## Local bundle bootstrap — byte delivery for a fresh datadir today

> Not to be confused with the legacy, transparent-only starter pack
> (`block_index.bin` + `utxo-seed-<height>.snapshot`,
> [`docs/BOOTSTRAPPING.md`](./BOOTSTRAPPING.md)) — a different artifact on a
> different autodetect loader (`boot_autodetect_bundle_snapshot`, not
> `boot_autodetect_consensus_bundle`). This section is about the
> **complete-state** `zcl.consensus_state_bundle.v1` artifact this whole page
> covers.

The recipe above needs a peer that is both reachable and already serving the
artifact. Today's P2P fetch client (`core/modules/net/src/rom_fetch.c`,
`ops.debug.rom_fetch.bundle`) is operator-driven by design: it commits to a
`(chunk_root, whole_sha3, size)` triple **before** requesting a single byte,
either from explicit operator input or a manifest parsed out of a peer's
`/directory.json` — see the trust-model note in
[`docs/work/wt-rom-fetch-engine.md`](./work/wt-rom-fetch-engine.md) ("do not
create a third activation door"). Automatic discovery of *which* manifest to
trust with zero prior operator input is explicitly still on that lane's "Next
(not done yet)" list. Until it lands, a genuinely first-boot node — no peers
proven yet, no digest an operator has committed to — has nothing in
`<datadir>/bundles/` for the zero-flag cold-boot autodetect
(`boot_autodetect_consensus_bundle`, `engine/composition/src/boot_auto_install_bundle.c`)
to find, and folds from genesis or waits on an operator to run the manual
fetch command.

**`platform/deploy/zclassic23-bundle-bootstrap.sh`** closes that gap the simplest way
available without opening any new activation door: it is a plain courier that
copies an operator/packaging-designated bundle straight into
`<datadir>/bundles/` so the *existing*, already-wired autodetect finds it with
no flags and no manual command at boot. It is not, and does not need to be, a
peer-fetch client — the bytes can come from anywhere (a bundle you exported
yourself, one copied off another node you operate, a future signed release
artifact once stable publication is unsealed — see `tools/release.sh`) because
this script establishes **zero** trust in them:

- it never opens, parses, or interprets the bundle as SQLite or as consensus
  content;
- its own SHA3-256 re-hash after copying (`build/bin/rom_bundle_sha3`, falling
  back to `openssl dgst -sha3-256` on a checkout that hasn't built that tool
  yet) is a **copy-integrity** check only — "did the bytes I just wrote match
  the bytes I just read" — not a content trust decision, exactly analogous to
  the copy-verify step in `tools/scripts/rom-bundle-replicate.sh`;
- the one and only trust boundary stays exactly where it already is: the
  RECEIPT / CHECKPOINT_ROM / CHECKPOINT_CONTENT authority resolved at INSTALL
  time
  (`engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c`),
  which independently re-derives the bundle's coins/anchor/nullifier content
  digests against the compiled-in checkpoint
  (`core/chainparams/src/checkpoints.c`) before ever lifting admission
  containment. A bundle this script stages is exactly as untrusted, until that
  gate passes, as one fetched cold from a stranger over ROM delivery above.

It is also fail-safe and idempotent, so it is safe to run unconditionally on
every boot: it no-ops (exit 0) when `<datadir>/bundles/` already holds a
`*.sqlite`, when the datadir already carries the durable
`consensus-bundle-installed.marker` (this datadir is already sovereign —
never stage bytes over or alongside installed state), or when no source was
given at all (the common case on a machine with no bundle of its own yet —
the node just falls back to normal sync, silently and correctly). A missing/
unreadable source or a post-copy digest mismatch fails closed (exit 1) with
nothing left half-written — copy-then-atomic-rename inside
`<datadir>/bundles/`, never visible at its final name until proven
byte-identical to the source. It also `chmod 0444`s the staged file before
that rename: the installer's immutable-admission check
(`engine/composition/src/consensus_state_snapshot_install.c`) refuses any bundle with a
write bit set for anyone, so this is required for the auto-install to ever
accept the staged file, not merely defense in depth.

**Usage** — one-shot, from the CLI:

```bash
make bundle-bootstrap SOURCE=/path/to/consensus-state-bundle-3056758.sqlite \
    [DATADIR=/path/to/datadir]   # DATADIR defaults to ~/.zclassic-c23
```

**Usage** — wired for every boot, zero manual steps thereafter: set
`ZCL_CHECKPOINT_BUNDLE_SOURCE=/path/to/consensus-state-bundle-<height>.sqlite`
in `~/.config/zclassic23/env` (see `platform/deploy/zclassic23.env.example`).
`platform/deploy/zclassic23.service`'s `ExecStartPre` then runs the bootstrap script
before every node start; leaving the variable unset (the default) makes the
step a no-op, so a fresh `~/.config/zclassic23/env` with nothing configured
behaves exactly as it does today.

**Where a bundle source comes from today:** the canonical producer is the
receipt-owning `-mint-anchor` full-validation fold, whose successful
finalization immediately invokes the contained exporter
(`docs/work/CONSENSUS-STATE-BUNDLE.md`); an operator running a second node
can also point `SOURCE` at a copy pulled from a first node they already
operate (optionally via `tools/scripts/rom-bundle-replicate.sh` for a
verified second-disk copy first). This is packaging/fleet plumbing, not a new
distribution channel — it complements peer-fetch (above) rather than
competing with it, and needs no change to the install/activation path either
way.
