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
- **Discovery already rides the peer link across restarts — the gap is
  first-boot live consumption and the absence of a freshness signal, not
  "no discovery."** A ZCL23 handshake already pushes a `zfileaddr` message
  carrying the sender's own file-service port
  (`core/modules/net/src/msg_version.c:635-663`, dispatched by
  `handle_zfileaddr` in `core/modules/net/src/msgprocessor.c:1227-1246`),
  and the receiver caches `(ip, port, p2p_port, last_seen)` in the
  `file_services` table. `engine/composition/src/boot_bundle_fetch_peer_seeds.c`
  already reads up to `BBFPS_MAX` (8) of those cached rows back in as
  instant-on bundle-fetch seeds with zero operator input
  (`boot_bundle_fetch_arm_peer_seeds`, lines 107-188). That file's own
  header names the actual gap precisely:
  `boot_bundle_fetch_maybe` runs from `boot_select_state_source` in
  `app_init`, *before* `app_init_services` brings `connman` up
  (lines 48-54), so a node's very first process start — empty datadir,
  empty `file_services` table — has nobody cached to ask yet, and nothing
  re-runs the state-source decision once live peers actually connect later
  in the same run. Separately, `zfileaddr` carries only a port — no height,
  content digest, or freshness signal — so even a cached endpoint is dialled
  blind; the seed either turns out to have a fresh bundle or it does not,
  discovered only by trying.
  `docs/GETTING_STARTED.md:307` states the operator-visible symptom
  plainly: "the node does not discover a file-service host on its own"
  (true for the specific case this gap describes — first boot, nothing
  cached, no live peers consulted).
- **Background history backfill is throttled by design; foreground catchup
  is not the same lane.** The ~13 blocks/second figure sometimes quoted for
  this codebase (64 blocks per 5-second tick,
  `engine/modules/storage/include/storage/body_history.h:200-224`) governs
  only the *background* body-history backfill policy — the drip that closes
  a below-tip hole without an operator asking for it. It does not govern a
  node's foreground catchup toward the peer-reported tip: `dl_queue_order`
  in `core/modules/net/src/download.c:346-350` sorts every `DL_WORK_FORWARD`
  entry ahead of every `DL_WORK_HISTORY` entry regardless of height, and
  `dl_assign_to_peer` charges history fetches against their own subordinate
  in-flight lane so they structurally cannot compete with forward fetch for
  bandwidth. Foreground catchup instead runs peer-gap-gated batching: the
  staged-sync supervisor's per-stage drive calls `stage_effective_batch()`
  (`engine/supervisors/src/staged_sync_supervisor.c:387-399,463-477`), which
  defers to `catchup_cadence_drain_batch()`
  (`engine/jobs/src/catchup_cadence.c:104`,
  `engine/jobs/include/jobs/catchup_cadence.h`) whenever
  `catchup_cadence_active()` is true — i.e. peers are connected and the gap
  between the peer-reported tip and the node's own log head is at least
  `ZCL_CATCHUP_GAP_THRESHOLD` (default 500 blocks). While active, the
  per-stage drain batch widens to `ZCL_CATCHUP_DRAIN_BATCH` (default 2000,
  measured 36,810 blocks processed in a fixed 360s window on a frozen
  corpus vs. 29,000 at the 500-block value) and the per-child supervisor
  tick period shortens from the shared 2s default to `ZCL_CATCHUP_TICK_MS`
  (default 1000ms) for the eight staged-sync children only
  (`catchup_cadence.h`'s TICK-PERIOD OVERRIDE section). On a normal at-tip
  node or one with no peers this whole mechanism is provably inert
  (`catchup_cadence_drain_batch()` returns its argument unchanged) — it is
  specifically a catch-up accelerator, not the steady-state rate. What the
  *actual* achievable foreground catchup rate is on a 2-vCPU box —
  including any ceiling from validation cost, not just the batch/tick
  knobs above — is not asserted here; it is being measured directly (a
  pinned 2-CPU cold-start run on the Linux side) and will be recorded as
  z23 fact rows per section 4, not projected from code comments.
  `docs/work/refold-fold-rate-bottlenecks.md` describes an older scheduler
  shape (a flat 2s/100-batch ceiling with no catchup-cadence override) and
  is cited in this ZRC only as history of the problem, not as the current
  bottleneck — see the superseded note at the top of that document.
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
- **Transfer already verifies per-chunk before writing — the gap is the
  transport underneath it, not the verification.** The existing ROM
  manifest format (RMF) already binds every chunk's SHA3 digest into one
  `chunk_root` and verifies the fold (`rom_fetch_parse_manifest_blob`,
  `core/modules/net/include/net/rom_fetch.h:257-269`), verifies each
  received chunk against its own digest *before* the `pwrite` that lands
  it (`core/modules/net/src/rom_fetch.c:1098-1115`), journals progress for
  durable resume across restarts, and already fails a chunk over to the
  next peer on content-verify failure rather than failing the whole
  download (`rom_fetch_download_verified_parallel`,
  `core/modules/net/include/net/rom_fetch.h:284-302`). None of that needs
  reinventing. What is missing is underneath all of it: `rom_fetch`'s dial
  path uses `getaddrinfo()` with no SOCKS/Tor route, so an onion peer's
  cached file-service address is unreachable by construction and is
  filtered out before a fetch is even attempted
  (`boot_bundle_fetch_peer_seeds.c`'s address-validity check skips any
  `net_addr_is_tor()` row). ZRC-0002 already put a general multiplexed,
  flow-controlled byte stream on the peer link, usable identically over
  onion and clearnet, and nothing uses it for a bundle: transfer still
  means a separate raw dial, never the Noise session the node already has
  open to that same peer.

None of these are independently mysterious, and several are narrower than
they first look once traced to the code that already exists. Together they
still mean a fresh node has no reliable way to ask a peer it is *already
connected to*, "do you have a recent, verifiable state, and can I have it,"
receive a useful answer the moment that peer connects, and pull the bytes
without a separate raw dial — even though most of the pieces to do all
three already exist in some form.

## Design

### 1a. Offers: extend the existing advertisement, close the live-consumption gap

This is deliberately *not* a new discovery mechanism. It extends the
`zfileaddr` advertisement / `file_services` cache path that already exists
end to end (Problem, above) in two ways:

- **New fields on the advertisement.** `zfileaddr` (or a sibling message on
  the same handshake, if the two-byte `zfileaddr` wire cannot be widened
  without breaking old peers — that determination belongs to
  implementation, not this design) carries the fields below, signed, in
  addition to the port it carries today.
- **Live consumption, not just pre-network cache replay.** Today
  `boot_bundle_fetch_arm_peer_seeds()` runs once, before `connman` is up,
  against whatever a *previous* run cached
  (`boot_bundle_fetch_peer_seeds.c`). This proposal adds a second call
  path: when a live peer sends an offer carrying a height inside the
  freshness window (section 3), and the node currently has no acceptable
  state source, the state-source decision is re-evaluated against that
  live offer instead of only against the pre-network snapshot. This is
  exactly the "re-running the state-source decision after the network is
  up" step that file's own header names as deliberately out of scope for
  itself (`boot_bundle_fetch_peer_seeds.c`, LIMITATION paragraph) — 1a is
  that step.

**Offer fields (new, added to the existing advertisement):**

| Field | Meaning |
|---|---|
| `bundle_height` | Height the bundle's state is asserted at. |
| `header_hash` | Block hash at `bundle_height`. |
| `content_digest` | Whole-bundle SHA3 digest — the same digest RMF's whole-file check already verifies (`rom_fetch.h`). |
| `chunk_root` | The existing RMF per-chunk-digest fold (`rom_fetch_parse_manifest_blob`, `rom_fetch.h:257-269`) — not a new structure, named here so it can be advertised before a manifest fetch. |
| `chunk_size` | Named for completeness; phase 1 reuses the existing fixed `ROM_SEED_CHUNK_SIZE` (8 MiB, `core/modules/net/include/net/rom_seed.h:38`) rather than defining a new one. |
| `mmb_peaks_digest` | Digest of the offering peer's MMB peaks at `bundle_height`, for the sampling proof in step 3(a) (phase 2). |
| `producer_receipt_id` | Identifier of the mint that produced this bundle, for freshness accounting and dedup across peers offering the same bundle. |
| `signature` | Signed by the offering node's peer identity key over the above fields. |

An offer is a claim, not an authority — nothing about being offered a
bundle causes it to be trusted; sections 2 and 5 cover what a consumer does
with it, and every fetch phase 1a triggers still goes through the unchanged
existing verified-fetch path (1b) and the unchanged existing install path
(section 2c).

### 1b. Transfer: move the existing RMF fetch onto the peer-link stream

This is also deliberately *not* a new transfer mechanism. RMF's manifest
format, per-chunk verify-before-write, journaled resume, and per-chunk
multi-seeder failover (`rom_fetch_download_verified_parallel`,
`rom_fetch.h:284-302`) are unchanged by this proposal — every bound and
check in that path stays exactly as it is today. What moves is the
transport underneath it: instead of `rom_fetch`'s raw `getaddrinfo()` TCP
dial (which cannot reach an onion peer at all — Problem, above), the same
manifest-fetch driver opens a stream over the ZRC-0002 stream primitive to
a peer it already has an established link to, using a new stream service
name (parallel to the tunnel's `tcp:<host>:<port>` naming). Concretely:

- **Reachability, not re-verification, is the fix.** An onion-only
  file-service peer — filtered out today by the `net_addr_is_tor()` skip
  in `boot_bundle_fetch_peer_seeds.c` because `rom_fetch` cannot dial it —
  becomes usable, because a stream rides the Noise session the node
  already has open to that peer instead of a fresh raw socket.
- **Rate caps.** Each peer link enforces a per-peer send rate cap for
  bundle-stream chunks, independent of the background body-history
  backfill throttle (`body_history.h:200-224`) and of the foreground
  catchup-cadence batching described in the Problem section, since bundle
  transfer is a distinct traffic class (bulk state transfer, not block
  relay).
- **Serving is on by default.** Any full node holding a bundle it trusts
  (installed or self-produced) serves it to peers by default over this
  stream (and keeps serving it over the existing raw-TCP file-service path
  for peers still using that), subject to a documented bandwidth budget
  (bytes per peer per hour, see section 4), with an explicit opt-out flag
  for an operator who does not want to spend upload bandwidth this way.
- **Resumability and multi-peer fetch are already RMF's job, unchanged.**
  The journal sidecar and per-chunk peer failover already do this
  (`rom_fetch.h:275-287,289-303`); moving the transport does not touch
  either.

### 2. Verification before install, sublinear in chain length

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
| Bundle bytes match what was minted | Yes — whole-file SHA3 + per-chunk digest check against the manifest's chunk_root fold (section 1b, existing RMF path) | — |
| Bundle content equals the compiled checkpoint's UTXO set/count, at the checkpoint height | Yes — re-derivation against `get_sha3_utxo_checkpoint()`, exactly as the installer already does (`consensus_state_snapshot_install_checkpoint_authority.c:34-39`) | — |
| Bundle's Sapling frontier matches the header chain's own `hashFinalSaplingRoot` | Yes — the installer already re-derives this from the PoW-protected header, not from the bundle (`consensus_state_snapshot_install_checkpoint_authority.c:131-137`) | — |
| Bundle content at an **arbitrary, non-checkpoint height** is bound to that height's block header | **No** — headers commit no UTXO/nullifier/note-commitment root (`chain/mmb.h:53-56`); an MMB `utxo_root` leaf is auxiliary evidence, not a consensus commitment | Yes — see phase 3 below |
| A sampling proof shows a header is on the heaviest chain | Yes — MMR/MMB peaks are a pure work accumulator (`chain/mmr.h:38-86`) | — |

Phase 1 and 2 of this ZRC (rollout, below) work entirely within the "Yes"
rows: fast sync at arbitrary heights is bounded by re-deriving against the
nearest compiled checkpoint plus forward header/PoW verification, exactly
as today's installer does, just fetched over the peer link instead of a
side channel. **Phase 2's state-root commitment inside the bundle header
plus its sampled header proof do not, by themselves, bind the offered
state to a proof-of-work header** — sampling proves *work* (this header is
on the heaviest chain), and a state-root field inside the bundle header
only proves the bundle is internally self-consistent (its own claimed
state matches its own claimed root); neither one proves the *chain's*
headers commit to that state, because they do not (`chain/mmb.h:53-56`).
So through the end of phase 2, an independently derived checkpoint/state
authority remains required to trust bundle content at all — exactly the
re-derivation against `get_sha3_utxo_checkpoint()` and the PoW-protected
`hashFinalSaplingRoot` that the existing install path already performs
(`consensus_state_snapshot_install_checkpoint_authority.c:15-41,131-137`).
What phase 2 adds is narrower than "trust the state": it tightens what the
bundle format itself commits to (so a bundle cannot silently mismatch its
own claimed state root) and proves the offered header is on the heaviest
chain without a full header download — it does **not** remove the need for
checkpoint re-derivation, and this ZRC must not be read as claiming it
does. Binding an arbitrary height's state to that height's PoW-protected
header — trusting a bundle between checkpoints with the same strength as
today's checkpoint-bound install, without independent re-derivation — needs
the consensus change named as phase 3.

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

### 3. Freshness contract

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

### 4. Measurement

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
(the same span the freshness contract in section 3 allows an offer to lag).

### 5. Security

- **No authority.** Any node may produce a bundle (subject to the existing
  exporter qualification gate) and any node may serve one it holds.
  Consumers trust proofs (section 2), never a peer's identity or position.
- **DoS caps**, all per connected peer:
  - maximum offers accepted per peer per session,
  - maximum chunk requests per second,
  - maximum bytes served per peer per hour (the "documented bandwidth
    budget" from section 1b).
- **Chunk-root mismatch handling.** A chunk that fails its per-chunk digest check
  against `chunk_root` drops the stream and scores the offending peer
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
| `sync.chunk_root_mismatch` | A fetched chunk fails its per-chunk digest check against the offer's `chunk_root`. | Self-clears per-stream (the stream is dropped and the condition is a scored incident, not a persistent blocker) — logged for peer-scoring, not left standing. |

## What exists today vs. what this adds

| Capability | Today | This ZRC |
|---|---|---|
| Discovery | `zfileaddr` already advertises a port over the peer handshake and it is cached (`file_services` table), but only read back before `connman` is up, from a *previous* run's cache, with no height/digest/freshness field | Same advertisement, extended with signed height/digest/`chunk_root`/receipt fields, consumed live off a just-connected peer too — not only the pre-network cache |
| Transfer | RMF (`rom_fetch_download_verified_parallel`) already does per-chunk-verified, journaled, resumable, multi-seeder-failover transfer — but only over a raw `getaddrinfo()` TCP dial, unreachable for an onion-only peer | Identical RMF format and verification, moved onto the ZRC-0002 peer-link stream so an already-connected onion peer becomes reachable too; the raw-TCP path keeps working unchanged |
| Chunk-level integrity | Already per-chunk (RMF's `chunk_root` fold, verified before each `pwrite`) plus whole-file SHA3 — this was already true before this ZRC | Unchanged — this ZRC does not touch RMF's verification, only where the bytes travel and how the fetch is scheduled |
| Work verification | Full header chain download, or trust the compiled checkpoint wholesale | FlyClient-style MMR/MMB sampling proof against an operator-visible checkpoint (proves *work*, not state — phase 2) |
| Bundle self-consistency | Bundle content checked only against the compiled checkpoint at install | Bundle header additionally commits its own state root, so a bundle cannot silently disagree with itself (phase 2) — still not a chain-header commitment |
| State-to-header binding | None at arbitrary heights; checkpoint height only, via re-derivation against the compiled checkpoint | Unchanged through phase 2 — checkpoint-height re-derivation remains mandatory; header commitment of the state root at arbitrary heights arrives only in phase 3 (consensus change) |
| Freshness | No contract; a stale or absent bundle looks the same as "healthy but nothing new" (`bundle_exporter.c:167-172`) | 576-block offer ceiling, loud typed refusal naming the newest height seen, fold-forward never silent-to-genesis |
| Serving | Nothing serves via the peer link at all | On by default for any node holding a trusted bundle, with a bandwidth budget and opt-out |
| Post-upgrade producer recovery | None — ticks forever reporting a healthy-looking zero/zero | Automatic retry named as the bundlefresh lane's acceptance line (phase 1) |

## Rollout

**Phase 1 — offers on the existing advertisement + the existing RMF fetch
moved onto the peer-link stream, existing verification, no consensus
change.** Split into two owning lanes because they close two independent
gaps in already-existing machinery:

- **1a — `offerlink`.** Add the height/digest/`chunk_root`/receipt fields
  to the existing `zfileaddr`-style advertisement, and wire live
  consumption of a connected peer's offer into `boot_select_state_source`
  (closing the "re-run after the network is up" gap
  `boot_bundle_fetch_peer_seeds.c` names as out of its own scope). Fetch
  and install stay on the existing RMF path in this sub-phase.
- **1b — `bundlestream`.** Move the manifest fetch (`rom_fetch`) onto the
  ZRC-0002 stream primitive so an onion-only advertised peer becomes
  reachable, with RMF's manifest, chunking, verification, journal, resume,
  and failover unchanged.

Acceptance: a fresh node with no `-fileservice`/env var set, connected only
to peers over the existing peer link, receives a live offer from a
just-connected peer (1a), fetches the bundle over the peer-link stream
including from an onion-only offering peer (1b) with RMF's existing
per-chunk verification unchanged, installs it through the unchanged
existing install path (section 2c), and reaches the tip — with the
section 4 measurement rows recorded for the run. The `bundlefresh` lane
(exporter post-upgrade recovery, closing `bundle_exporter.c:167-207`) is
also required before phase 1 can be called done in production (section 3).

**Phase 2 — bundle-header state-root commitment + MMR sampling proof
against the checkpoint.**
Owning lane: `flyclient` (work-weighted sampling proof implementation and
wiring into the offer-acceptance path) plus the bundle-header state-root
field. Scope, stated precisely so this phase is not overclaimed: this adds
(i) a state-root field inside the *bundle header itself* so a bundle
cannot silently disagree with its own claimed roots, and (ii) a sampling
proof that the offered `header_hash` sits on the heaviest chain, without
downloading the intervening header chain in full. It does **not** make the
chain's block headers commit to that state root — that binding is
consensus-level and is phase 3's job — so checkpoint re-derivation
(section 2c) remains mandatory input to trust throughout phase 2, not an
optional belt-and-suspenders check.
Acceptance: (a) a sampling proof rejects a lighter alternate-chain offer,
demonstrated by a test; (b) a bundle whose state-root field disagrees with
its own re-derived content is rejected before install, demonstrated by a
test; (c) the ZRC-0011 install path still performs the unchanged phase-1
checkpoint re-derivation for every bundle regardless of (a)/(b) passing —
no code path installs on sampling-proof-plus-state-root alone.

**Phase 3 — header commitment of the state root (consensus change).**
Not part of this ZRC's acceptance; requires its own ZRC because it changes
what a block header commits to. Owning lane: named in that future ZRC.
This ZRC's phase 1-2 work is designed so that when phase 3 lands, sections
1a and 1b (offer format, chunked transfer) are unchanged and only the
verification in section 2(b) tightens from "checkpoint-height re-derivation"
to "any-height header commitment."

## Acceptance

- Phase 1's acceptance line above, measured on a real fresh-node run with
  the section 4 rows recorded.
- A fresh 2-vCPU node reaches the tip within 15 minutes of the newest
  offer's height plus forward validation of at most 576 blocks (section 4
  target), on at least one measured run.
- `bootstrap.stale_offers_only` is raised (never a silent genesis fold) when
  every reachable peer's offers are all more than 576 blocks stale, and
  names the newest height seen.
- A chunk failing its per-chunk digest check is never written to disk, and the
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
- Any change to the staged-sync catchup-cadence mechanism
  (`catchup_cadence.c`/`catchup_cadence.h`) or to whatever foreground
  ceiling the pinned 2-CPU measurement (Problem section) finds — that
  applies after a bundle installs, to blocks minted since, and is a
  separate performance lane. `docs/work/refold-fold-rate-bottlenecks.md`
  is superseded as a description of the current scheduler and is cited in
  this ZRC only as history.
- Any change to the default background body-history backfill throttle
  (`body_history.h:200-224`) for ordinary block relay outside of a bundle
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
