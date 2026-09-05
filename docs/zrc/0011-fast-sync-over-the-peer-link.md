<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0011: Fast sync over the peer link

| Field | Value |
|---|---|
| ZRC | 0011 |
| Title | Fast sync over the peer link |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

A fresh z23 node on a 2-vCPU box was measured at four days to reach the
network tip. That number is the sum of several independent gaps, each
already named in the tree:

- **No automatic state source.** A bare node with no prior contacts finds no
  fast-start state source and folds from genesis; the
  `bootstrap.no_state_source` condition exists precisely to make that LOUD
  rather than let the node sit silently at height 0
  (`engine/conditions/src/no_state_source.c:28`). `docs/GETTING_STARTED.md:307`
  says it plainly: "the node does not discover a file-service host on its
  own."
- **Discovery today is a side channel, not the peer link.** A bundle is
  found either through an onion-only catalog page,
  `/directory.json` (`core/modules/net/src/onion_service.c:1158`), or an
  opt-in `-fileservice=HOST` TCP fetch on port 18034
  (`engine/composition/src/boot_bundle_fetch.c`), or an operator-supplied
  `ZCL_CHECKPOINT_BUNDLE_SOURCE`. None of these ride the P2P connection the
  node already has to every peer; a node with peers but no configured
  fileservice or catalog address gets no offer at all.
- **Body fetch is throttled by design, not by bandwidth.** Once a node is
  past the state source, the default backfill policy hands the download
  manager at most a ~13 blocks/second drip
  (`engine/modules/storage/include/storage/body_history.h:200`), because
  history work is deliberately subordinate to tip-chasing work in the
  download queue's own ordering.
- **Validation is single-threaded.** All eight staged-sync stages run on one
  supervisor thread, ticking every 2 seconds and draining a capped batch,
  which puts a ~50 blocks/second ceiling on refold even once bytes are
  local (`docs/work/refold-fold-rate-bottlenecks.md:24-31`).
- **The one existing state-bundle mechanism silently rots.** A binary
  upgrade can leave the exporter's stored producer session foreign to the
  running build; the exporter degrades and stops minting new bundles, but
  keeps ticking and reporting a healthy-looking `exports_ok=0,
  exports_failed=0` rather than an obvious failure
  (`engine/composition/src/bundle_exporter.c:167-207`). Every node that
  cold-starts against that producer inherits its staleness as raw crawl
  time.
- **What "verified" means today is narrower than it sounds.** The chain's
  MMR/MMB structures (`core/modules/chain/include/chain/mmr.h:38-86`,
  `core/modules/chain/include/chain/mmb.h`) prove accumulated PoW work over
  a leaf sequence, and an auxiliary MMB leaf additionally folds in a
  `utxo_root` — but ZClassic block headers do not commit that root
  (`core/modules/chain/include/chain/mmb.h:53-56`). A peer's offered UTXO
  state is evidence relative to that auxiliary structure, not a
  header-anchored, consensus-binding proof. The existing bundle installer
  compensates by re-deriving the bundle's content directly from the
  compiled checkpoint and the header chain's own PoW-protected Sapling root
  rather than trusting any offered root
  (`engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c:15-41`).
  Any fast-sync design has to be honest about this line: today, a peer can
  vouch for *which bytes* it holds, but the chain's own headers do not
  bind *which state* is correct.
- **The stream primitive exists but carries no bundle traffic.** ZRC-0002
  already put a general multiplexed, flow-controlled byte stream on the
  peer link. Nothing uses it for a checkpoint bundle: `rom_fetch_download`
  dials a raw TCP address or an onion stream directly
  (`core/modules/net/src/rom_fetch.c`, the `rom_fetch_download` driver
  starting near line 327), never the peer link's own established session.

None of these are independently mysterious. Together they mean a fresh node
has no way to ask a peer it is *already connected to*, "do you have a
recent, verifiable state, and can I have it," and no way to receive one
without an operator manually pointing it at a URL or bundle-server address.

## Design

### 1. Discovery rides the peer link

The existing peer handshake/inventory exchange gains a new, signed
**state-offer row**. A node holding an eligible bundle advertises it to
every peer it is already talking to; a node lacking a state source asks any
connected peer for its offers. No HTTP catalog and no central registry are
required for discovery to work — the offer is exchanged over the same
connection ZRC-0002's stream lane already rides. Onion and clearnet peers
offer identically, and a Tor-stub build is not excluded from offering or
consuming (it just cannot *also* serve the onion-catalog page from ZRC-0002's
sibling protocols; that is unrelated to this offer).

**State-offer row fields:**

| Field | Meaning |
|---|---|
| `bundle_height` | Height the bundle's state is asserted at. |
| `header_hash` | Block hash at `bundle_height`. |
| `content_digest` | Whole-bundle SHA3 digest, matching today's install-time check. |
| `chunk_tree_root` | Root of the chunk Merkle tree used for streamed transfer (see below). |
| `chunk_size` | Fixed chunk size in bytes for this bundle (see below). |
| `mmb_peaks_digest` | Digest of the offering peer's MMB peaks at `bundle_height`, for the sampling proof in step 3(a). |
| `producer_receipt_id` | Identifier of the mint that produced this bundle, for freshness accounting and dedup across peers offering the same bundle. |
| `signature` | Signed by the offering node's peer identity key over the above fields. |

An offer is a claim, not an authority — nothing about being offered a
bundle causes it to be trusted; sections 3 and 6 cover what a consumer does
with it.

### 2. Transfer is a resumable stream over the peer link

Bundle bytes move over the ZRC-0002 stream primitive as a new service name
(parallel to the tunnel's `tcp:<host>:<port>` naming), not as a new P2P
message and not as raw TCP or a separate onion stream.

- **Chunking.** The bundle is split into fixed 1 MiB chunks. Each chunk's
  hash is a leaf in the `chunk_tree_root` Merkle tree named in the offer.
  A consumer verifies each chunk against that root **before writing it to
  disk** — a corrupt or malicious chunk is caught at the chunk boundary,
  not only at the final whole-file digest check.
  - This makes the existing `ROM_FETCH` style whole-file digest check in
    `core/modules/net/src/rom_fetch.c` (the SHA3 mismatch path that unlinks
    and refuses) a second, redundant check, not the only one — a change
    that reduces write-then-discard rather than replacing the model.
- **Resumability and multi-peer fetch.** A consumer records which chunk
  indices it holds and verified; it can fetch missing chunks from any
  peer(s) offering the same `content_digest`, in any order, and resume
  after a restart without re-fetching verified chunks.
- **Rate caps.** Each peer link enforces a per-peer send rate cap for bundle
  chunks, independent of the body-fetch throttle in
  `body_history.h:200`, since this is a different traffic class (bulk
  state transfer, not block relay).
- **Serving is on by default.** Any full node holding a bundle it trusts
  (installed or self-produced) serves it to peers by default, subject to a
  documented bandwidth budget (bytes per peer per hour, see section 6), with
  an explicit opt-out flag for an operator who does not want to spend
  upload bandwidth this way.

### 3. Verification before install, sublinear in chain length

A consumer must not have to replay the whole chain to decide whether an
offer is worth fetching. Verification has four parts:

**(a) The offer's header is on the heaviest chain — a sampling proof, not a
full download.** The consumer asks the offering peer (or any peer) for a
FlyClient-style proof: a work-weighted sample of MMR/MMB peaks between a
checkpoint the operator can see and override, and `header_hash`, showing
that no lighter alternate chain could plausibly contain more accumulated
work up to that point without also containing headers the sample would have
caught. This reuses the existing MMR/MMB accumulator
(`core/modules/chain/include/chain/mmr.h`) as a work-proof structure; it
proves **work**, not state — see (b).

**(b) The bundle commits to the state it claims — honesty about what binds
today versus what a header commitment would add.**

| | Verifiable today | Requires a consensus change |
|---|---|---|
| Bundle bytes match what was minted | Yes — whole-file SHA3 + per-chunk Merkle proof (section 2) | — |
| Bundle content equals the compiled checkpoint's UTXO set/count, at the checkpoint height | Yes — re-derivation against `get_sha3_utxo_checkpoint()`, exactly as the installer already does (`consensus_state_snapshot_install_checkpoint_authority.c:34-39`) | — |
| Bundle's Sapling frontier matches the header chain's own `hashFinalSaplingRoot` | Yes — the installer already re-derives this from the PoW-protected header, not from the bundle (`consensus_state_snapshot_install_checkpoint_authority.c:131-137`) | — |
| Bundle content at an **arbitrary, non-checkpoint height** is bound to that height's block header | **No** — headers commit no UTXO/nullifier/note-commitment root (`chain/mmb.h:53-56`); an MMB `utxo_root` leaf is auxiliary evidence, not a consensus commitment | Yes — see phase 3 below |
| A sampling proof shows a header is on the heaviest chain | Yes — MMR/MMB peaks are a pure work accumulator (`chain/mmr.h:38-86`) | — |

Phase 1 and 2 of this ZRC (rollout, below) work entirely within the "Yes"
rows: fast sync at arbitrary heights is bounded by re-deriving against the
nearest compiled checkpoint plus forward header/PoW verification, exactly
as today's installer does, just fetched over the peer link instead of a
side channel. Trusting a bundle offered at a height between checkpoints,
with the same strength as today's checkpoint-bound install, needs the
header-commitment change named as phase 3.

**(c) The existing install checks remain, unconditionally.** Whole-file
SHA3, checkpoint re-derivation, and Sapling-root re-derivation
(`consensus_state_snapshot_install_checkpoint_authority.c`) are not relaxed
by this proposal; they are the floor every bundle clears regardless of how
it arrived.

**(d) Assume-valid shielded re-verification is explicit and overridable.**
Below the installed bundle height, full shielded proof re-verification
(Groth16/Sapling) is skipped by default once (a)-(c) pass, on the same
assume-valid principle used elsewhere in the codebase for
already-checkpoint-anchored history. This threshold:

- is visible in `z23 status` as a named field (the height below which proofs
  were assumed rather than re-verified),
- defaults to exactly the installed bundle's height — never further,
- is overridable by an operator flag that forces full re-verification from
  genesis regardless of any installed bundle.

### 4. Freshness contract

- An offer whose `bundle_height` is more than 576 blocks behind the
  offering peer's own reported tip is not offered at all — a stale offer is
  worse than no offer, because it teaches a consumer the wrong newest
  height.
- A consumer that, after asking its connected peers, finds only stale
  offers (or none) refuses loudly with a typed condition (see naming below)
  naming the newest height it actually saw, and then folds forward from
  that newest acceptable state — **never** silently drops back to genesis
  fold. This mirrors the existing `bootstrap.no_state_source` condition's
  "make the cause LOUD and self-clearing" contract
  (`engine/conditions/src/no_state_source.c:5-8`).
- The producer side mints on a fixed cadence of every 288 blocks (roughly
  double today's `MMR_COMMITMENT_INTERVAL` cadence spacing at 100 blocks;
  chosen so a producer restarting after a gap catches up within one day at
  mainnet block times).
- The producer recovers after a binary upgrade automatically: this ZRC
  names the owning fix as the **bundlefresh lane**, which must close the
  exact silent-degradation gap in `bundle_exporter.c:167-207` (a mismatched
  producer session must retry with a named cause rather than tick forever
  reporting a healthy-looking zero/zero) before phase 1 of this ZRC can be
  called done in production.

### 5. Measurement

Every fresh-node run records, as z23 facts (typed rows, not prose):

- `time_to_first_peer`
- `time_to_first_offer`
- `bytes_fetched`
- `verify_seconds`
- `install_seconds`
- `time_to_tip`
- `blocks_per_sec_post_install`
- `cpu_seconds`

**Target:** a fresh 2-vCPU node reaches the tip within 15 minutes of the
newest offer's height, plus forward validation of at most 576 blocks
(the same span the freshness contract in section 4 allows an offer to lag).

### 6. Security

- **No authority.** Any node may produce a bundle (subject to the existing
  exporter qualification gate) and any node may serve one it holds.
  Consumers trust proofs (section 3), never a peer's identity or position.
- **DoS caps**, all per connected peer:
  - maximum offers accepted per peer per session,
  - maximum chunk requests per second,
  - maximum bytes served per peer per hour (the "documented bandwidth
    budget" from section 2).
- **Chunk-root mismatch handling.** A chunk that fails its Merkle proof
  against `chunk_tree_root` drops the stream and scores the offending peer
  down, the same way other protocol violations are scored elsewhere in the
  peer-scoring path. It does **not** address-ban the peer: every inbound
  Tor-forwarded peer arrives from `127.0.0.1`, so an address ban would take
  down the node's entire inbound front door for one bad chunk from one
  onion peer — the same collective-punishment problem the ban path already
  guards against for other offenses
  (`core/modules/net/src/net.c:1866-1877`). Identity-level scoring, not
  address banning, is the mechanism available for a misbehaving onion peer.
- **Privacy.** Requesting offers and chunks reveals to the peers asked only
  "I am a node syncing," not the requester's height, holdings, or intent
  beyond that — the same exposure a node already accepts by connecting and
  exchanging headers.

## Typed conditions this proposal adds

Following the existing naming pattern in `engine/conditions/include/conditions/`
(one header per condition, dotted `<owner>.<condition>` blocker id):

| Condition | Raised when | Clears when |
|---|---|---|
| `bootstrap.stale_offers_only` | Every connected peer's newest offer is more than 576 blocks behind that peer's own tip, or no peer offers at all. | A peer offers a state within the freshness window, or the node's own H* climbs past the newest height seen in a stale offer (fold-forward self-heals it, same self-clearing shape as `bootstrap.no_state_source`). |
| `bundle_exporter.mint_stale_after_upgrade` | The exporter's stored producer session is foreign to the running build (the exact case named in `bundle_exporter.c:167-207`) and no automatic retry has succeeded. | The bundlefresh lane's retry succeeds and a fresh mint lands, or an operator restarts on a matching build and a mint succeeds. |
| `sync.chunk_root_mismatch` | A fetched chunk fails its Merkle proof against the offer's `chunk_tree_root`. | Self-clears per-stream (the stream is dropped and the condition is a scored incident, not a persistent blocker) — logged for peer-scoring, not left standing. |

## What exists today vs. what this adds

| Capability | Today | This ZRC |
|---|---|---|
| Discovery | Onion catalog page or opt-in `-fileservice=HOST`/env var; nothing over the peer link | Signed state-offer row over the existing peer handshake/inventory |
| Transfer | Raw TCP or a raw onion stream dialed directly by `rom_fetch_download` | Resumable, chunked, multi-peer stream over the ZRC-0002 stream lane |
| Chunk-level integrity | Whole-file SHA3 only, checked after full download | Per-chunk Merkle proof checked before each chunk is written, whole-file SHA3 retained |
| Work verification | Full header chain download, or trust the compiled checkpoint wholesale | FlyClient-style MMR/MMB sampling proof against an operator-visible checkpoint |
| State-to-header binding | None at arbitrary heights; checkpoint height only, via re-derivation against the compiled checkpoint | Same (checkpoint-height re-derivation) in phases 1-2; header commitment of the state root in phase 3 |
| Freshness | No contract; a stale or absent bundle looks the same as "healthy but nothing new" (`bundle_exporter.c:167-172`) | 576-block offer ceiling, loud typed refusal naming the newest height seen, fold-forward never silent-to-genesis |
| Serving | Nothing serves via the peer link at all | On by default for any node holding a trusted bundle, with a bandwidth budget and opt-out |
| Post-upgrade producer recovery | None — ticks forever reporting a healthy-looking zero/zero | Automatic retry named as the bundlefresh lane's acceptance line (phase 1) |

## Rollout

**Phase 1 — offers + streamed transfer of the existing bundle format,
existing verification, no consensus change.**
Owning lanes: `bundlefresh` (exporter post-upgrade recovery, closing
`bundle_exporter.c:167-207`), `offerlink` (state-offer row on the peer
handshake), `bundlestream` (chunked resumable transfer on the ZRC-0002
stream lane).
Acceptance: a fresh node with no `-fileservice`/env var set, connected only
to peers over the existing peer link, receives an offer, fetches a bundle
over the stream lane with per-chunk verification, installs it through the
unchanged existing install path (section 3c), and reaches the tip — with
the section 5 measurement rows recorded for the run.

**Phase 2 — MMR sampling proof against the checkpoint.**
Owning lane: `flyclient` (work-weighted sampling proof implementation and
wiring into the offer-acceptance path).
Acceptance: a consumer accepts an offer only after a sampling proof shows
the offered `header_hash` sits on the heaviest chain relative to an
operator-visible checkpoint, without downloading the intervening header
chain in full; a test demonstrates a lighter alternate-chain offer is
rejected by the sampling proof alone.

**Phase 3 — header commitment of the state root (consensus change).**
Not part of this ZRC's acceptance; requires its own ZRC because it changes
what a block header commits to. Owning lane: named in that future ZRC.
This ZRC's phase 1-2 work is designed so that when phase 3 lands, sections
1 and 2 (offer format, chunked transfer) are unchanged and only the
verification in section 3(b) tightens from "checkpoint-height re-derivation"
to "any-height header commitment."

## Acceptance

- Phase 1's acceptance line above, measured on a real fresh-node run with
  the section 5 rows recorded.
- A fresh 2-vCPU node reaches the tip within 15 minutes of the newest
  offer's height plus forward validation of at most 576 blocks (section 5
  target), on at least one measured run.
- `bootstrap.stale_offers_only` is raised (never a silent genesis fold) when
  every reachable peer's offers are all more than 576 blocks stale, and
  names the newest height seen.
- A chunk failing its Merkle-proof check is never written to disk, and the
  owning stream is dropped with `sync.chunk_root_mismatch` scored against
  the peer, without an address ban being applied.
- No existing install-time check (whole-file SHA3, checkpoint
  re-derivation, Sapling-root re-derivation) is weakened, removed, or
  bypassed by any phase-1 or phase-2 code path.

## Out of scope

- Phase 3's header-commitment consensus change itself (separate ZRC).
- NAT hole punching and onion-address discovery mechanics for finding peers
  in the first place — this ZRC assumes the node already has at least one
  connected peer and only changes what travels once connected.
- Any change to the staged-sync single-supervisor-thread refold ceiling
  (`docs/work/refold-fold-rate-bottlenecks.md`) — that bottleneck applies
  after a bundle installs, to blocks minted since, and is a separate
  performance lane.
- Any change to the default body-fetch throttle
  (`body_history.h:200`) for ordinary block relay outside of a bundle
  transfer.
- A public HTTP catalog or registry of bundle producers — this ZRC
  deliberately removes the need for one, it does not add a peer-link
  flavor of one.

## Landing

Not yet landed.

## Discussion

Board rows carrying `zrc-0011` (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) for how the
interim board works today), until
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
lands and the wiki page for this ZRC becomes the index.
