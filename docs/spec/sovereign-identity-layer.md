# Sovereign Identity Layer — chain-anchored master keys (Design)

One 130-byte record on-chain per identity — a master key — with an entire
signed, content-addressed data plane hanging off it, forever. The chain is
the smallest possible root of trust: a land registry of keys. Everything
else (service descriptors, names, packages, relay endpoints, messages) is
signed data moving over gossip and the ZCODE swarm, verified against the
chain, never touching it again. **Write once, sign forever.**

Status: **draft for owner review**. Nothing here is built unless cited.
All phases stay out of the byte-sealed `core/` tree and add no external
dependencies. This document supersedes the ZDIR-first framing; the relay
directory survives as one *application* of the identity layer (Phase 3),
not the headline.

## Background: the actual gap in Tor

Tor's anonymity engine (onion circuits, NTOR, rendezvous) is decentralized
and mature — it is not the target. The weak layers are identity and
directory:

- **~9-10 hardcoded Directory Authorities** vote hourly and majority-sign
  the relay consensus document; **~6 Bandwidth Authorities** decide which
  relays get traffic. Two small trust roots
  ([overview](https://arxiv.org/pdf/2004.09583)).
- A **single** compromised DirAuth can equivocate and feed a targeted
  client a malicious consensus undetectably
  ([Luo et al. 2025](https://arxiv.org/abs/2503.18345)).
- Onion services have **no PKI and no naming**: a v3 address is a raw
  ed25519 pubkey, descriptors sit in a snoop-prone HSDir DHT (address
  harvesting, intro-point DoS), and users paste 56-character blobs or buy
  commercial naming certificates.

The fillable gap is **identity and authenticity**, not circuits and not
bandwidth measurement. A fully-synced z23 node already holds a
globally consistent, censorship-resistant, PoW-committed bulletin board
that every other node agrees on byte-for-byte. Prior art (Antiblok,
SmartMeasurer, TorCoin) bolted this onto foreign smart-contract chains;
nobody has done it natively — same binary, own chain, own overlays.

## The primitive: write-once master-key anchoring

**On-chain (rare, tiny):** an identity's master ed25519 key (32 bytes),
anchored once. The only further on-chain writes are rotation and
revocation.

**Off-chain (frequent, free):** signed documents of the form
`{version, master_pubkey, seq, expiry, body, signature}`. Consumers verify
the signature against the chain-anchored key and enforce a monotonic
sequence number. Rotating a document costs a signature, not a transaction.

This mirrors Tor's internal design — an offline master identity key with
medium-term signing keys — with the root of trust moved from the address
string to the chain.

### Anti-enumeration: blinded record keys

Chain data is public, so naive on-chain service records would let any
observer enumerate all services (worse than Tor v3, where you cannot even
find a descriptor without knowing the address). Service-bound records are
therefore keyed by a **blinded key**:

```
blinded = SHA3-256("ZIDB" ‖ master_pubkey ‖ period_le64)
```

following Tor v3's blinded-pubkey pattern. Only someone who already knows
the master key (i.e. knows the service) can derive the record key.

### On-chain anchor formats

- **v1 (no new overlay):** ZNAM `SET_TEXT key="zid" value=<64-hex pubkey>`
  binds a human name to a master key using the existing registry
  (`contexts/naming/modules/znam/include/znam/znam.h`; text values ≤128 chars). Zero new
  protocol — usable the day the client codec ships.
- **v2 (dedicated `ZID` overlay):** lokad `ZID\0`, commands
  ANCHOR/ROTATE/REVOKE carrying raw 32-byte keys — for pseudonymous
  identities that don't want a name, and for machine-readable projections.
  Same push-framing as ZNAM/ZSLP via
  `core/modules/script/include/script/op_return_push.h`, inside the 223-byte
  standardness cap (`core/modules/script/include/script/standard.h:33`).

## Scaling to infinite services: anchor domains

Flat anchoring (one tx per identity) grows linearly — a million identities
is ~130 MB of chain and a million transactions. **Anchor domains** make the
L1 footprint constant per batch instead of per record, which is what makes
"any number of pluggable L2 services" an honest claim.

An **anchor domain** is:

- an **append-only MMR** (SHA3-256, domain-separated; codec in `contexts/wallet/modules/zid`)
  of 32-byte record digests, owned by one zid identity;
- **anchored on-chain via ZANC** — one ~40-byte OP_RETURN commits the
  tree root (`contexts/commons/modules/zanc`, lokad `ZANC`; its own doc lists "bind anchor to
  identity" as future work — zid is that layer);
- **served off-chain** — records and inclusion proofs move over the ZCODE
  swarm, verified locally against the anchored root.

**The scaling law:** L1 cost per domain is one anchor tx per batch cadence,
independent of batch size. 1,000 domains × 1 anchor/day × ~150 B ≈ 55
MB/year. The same million records anchored flat would cost ~130 MB and a
million transactions. Constant per batch, not per record.

**Nesting is the true "infinite":** a domain's root can itself be a record
in a parent domain's tree, so one anchor tx can commit arbitrarily many
sub-domains. Fractal scaling — an operator, a marketplace, or a whole
ecosystem under a single on-chain footprint.

**The plugin contract:** an L2 service is exactly four things — an identity
(zid master key), a domain name, a record schema, and an anchor cadence.
Third parties define new domains **permissionlessly**: no L1 change, no new
lokad, no coordination. They publish a signed `zid_doc` declaring the
domain; consumers who care, follow it. The domain registry is itself a
domain.

**Non-equivocation (CT-style):** the tree is append-only and anchor
documents carry the codec's monotonic `seq`. Two different roots anchored
for the same domain at the same seq are publicly attributable fraud —
visible to every synced node, not to a committee.

**Light-client proof chain, end to end:** FlyClient header proof → anchor
tx's block inclusion → domain MMR root → record inclusion proof → zid
signature → master-key anchor. Full authenticity for a descriptor, relay
record, or package release **without the 10 GB chain** — the sovereignty
story extended to light clients.

`z23 zcode proof walk` executes that chain as one read-only
command over evidence passed in, and reports each rung separately as
passed / failed / not_checked-with-a-reason
(`tools/command/native_proof_chain_command.c`, proven by the
`proof_chain` test group). Rungs 1-6 — header + Equihash PoW, tx merkle
inclusion, ZANC anchor decode, domain root, record inclusion via
`zid_tree_verify`, zid signature — are **node-free**: every input is
evidence in the caller's hand.

Rung 7 asks whether the master key itself is anchored on-chain and still
active, which no document can answer about itself, so it is **opt-in on
`--datadir`**: given one, the walk resolves the key against that node's
folded `zid_identities` projection (`db_zid_identity_find`, read-only)
and passes only on an **active** anchor — a rotated key fails and names
its successor, a revoked key fails, and a key with no row fails while
saying the answer is scoped to what that node has folded. Without a
`datadir` the rung stays `not_checked` and says what to pass. The report
never overstates either case: `node_free` says whether a database was
read, `chain_complete` is true only when all seven rungs passed, and
`verified_prefix` counts only consecutive passing rungs from rung 1.

**Hash conventions** (mirror `core/modules/chain/src/mmr.c`, with a zid-specific
leaf tag that blocks cross-protocol proof replay). All zid domain
separators are 4-byte uppercase lokad-style tags, same convention as the
on-chain lokads (ZNAM, `SLP\0`, ZANC):

```
Blinded:  SHA3-256("ZIDB" ‖ master_pubkey ‖ period_le64)
Leaf:     SHA3-256(0x00 ‖ "ZIDL" ‖ record_digest)
Internal: SHA3-256(0x01 ‖ left ‖ right)
Root:     SHA3-256(0x02 ‖ peak_0 ‖ … ‖ peak_k)
```

**Canonical wire formats** (everything that crosses the P2P/swarm boundary
is versioned and bounds-strict; verifiers must pin these exactly):

```
zid_doc:    version:1 ‖ pubkey:32 ‖ seq:8 ‖ expiry:8 ‖ body_len:2 ‖ body ‖ sig:64
zid_proof:  version:1 ‖ index:8 ‖ num_leaves:8 ‖ proof_len:2 ‖ siblings:32×n
```

**Efficiency contract:** `zid_tree_verify` is O(log n) hashes; proving is
O(n) per proof at batch cadence (operator-side rebuild — fine for
daily-scale anchors; all-leaves batch proving is a future operator
optimization, never a verifier cost).

## Post-quantum horizon (100-year asset security)

Design doctrine, already load-bearing: **only hash-based structures are
load-bearing on-chain.** Every signature scheme is disposable; every root
is a 32-byte SHA3 digest. Discrete-log primitives (secp256k1, ed25519,
X25519, Jubjub, BLS12-381) all fall to Shor; SHA3-256 commitments fall at
worst to quadratic Grover speedup. Consequences:

- **The anchor-domain pattern absorbs PQ signature size for free.** PQ
  signatures are large (SPHINCS+ ~8 KB, STARK sigs larger); the chain
  commits only roots, so migrating doc signing to any PQ scheme costs
  the chain zero bytes. Migration is a `zid_doc` version bump with an
  algorithm field, plus a hybrid period (ed25519 + PQ dual-signature)
  during transition. Master keys become hash commitments to PQ
  verification keys.
- **For 100-year collision margin**, root digests have a planned
  SHA3-384 upgrade path (quantum collision on SHA3-256 ≈ 2^85 — fine
  today, marginal at century scale). The versioned tags make this
  switchable without a flag day.
- **Recursive IVC STARK integration points** (hash-based, so PQ-native;
  integrate when a mature prover/verifier is available): (1) recursive
  chain-state proofs — the Bounded Node endgame: live state + one proof,
  history fully optional; (2) epoch-anchor validity proofs — upgrading
  attestation to math; (3) PQ ownership circuits — STARK-based shielded
  ownership, which also retires Groth16's trusted setup; (4) verifiable
  builds for the registry. `core/modules/crypto_registry` is the scheme-plugging
  surface; provers are heavy, so these land at epoch/IVC cadences, never
  per-message.
- **Lane discipline:** migrating L1 transparent ownership (P2PKH/PQ
  output types) is a consensus change and belongs to ZClassic network
  governance (parity doctrine) — out of this repo. The overlay stack
  (zid, domains, registry, descriptors, transport) can and should be
  PQ-ready years ahead of Q-day, because assets must migrate into
  hash-committed structures *before* quantum breaks discrete log, and
  the destination must be battle-tested when it matters.
- **Key rotation is a first-class ritual**, not an emergency path:
  assume signature migration every ~20 years over a 100-year horizon.

First-party domains: `zdesc` (A1 onion descriptors), `zdir` (A3 relay
endpoints), `zcode` (package releases). Each anchors at its own cadence;
each is just a schema over the same four-part contract.

## Bounded storage: no byte is stuck forever

A full node that must keep every byte it ever saw does not scale; one
whose bytes are sorted by fate does. There are exactly three kinds:

1. **Live state** (UTXO set, Sapling/Sprout frontiers, nullifiers,
   overlay projections) — kept, committed, provable. The baked ROM
   checkpoint (`core/chainparams/src/checkpoints.c`) already binds the
   consensus-side half at h=3,056,758.
2. **History** (block bodies) — re-derivable from peers; pruneable once
   the state past them is verified (pruning machinery exists:
   `MIN_BLOCKS_TO_KEEP` et al. in `main_constants.h`). What was missing
   is the proof story for *overlay* state after pruning — the epoch
   anchor below supplies it.
3. **Content** (packages, descriptors, files) — content-addressed,
   quota'd, garbage-collected, re-fetchable by hash (the swarm).

**The epoch anchor** is the mechanism that makes overlay state provable
without history. The OP_RETURN catalog projection
(`engine/models/src/op_return_index.c`) already maintains an incremental
digest-chain over every OP_RETURN the chain has ever carried — every
ZNAM name, ZSLP transfer, ZANC anchor, and future ZID record, in one
digest. Anchoring that digest via ZANC (label `zepoch@<height>`) commits
**the entire overlay state of the network in one ~40-byte transaction**:

- **Cross-checking for free:** the catalog digest is a deterministic
  function of chain data, so every honest node computes the same value.
  Independent operators anchoring the same epoch either agree (public
  confirmation) or disagree (publicly attributable fraud or bug).
- **Pruned-node / light-client story:** FlyClient → epoch anchor →
  catalog digest → per-record inclusion in the projections' digest
  chain. Overlay authenticity without the 10 GB.
- **Cadence is an operator decision.** Anchoring spends fees, so v1 is
  commands only (`core epoch status/anchor/verify`) — no auto-broadcast.
  A ~1000-block epoch (~1.7 days) costs ~15 anchors/month across the
  whole network if every operator anchors; one is sufficient.
- **Later:** the zid domain trees fold in as their own anchored domains;
  committing the catalog digest into the sealed `core/` checkpoint is
  the owner-gated Phase 4+ step that turns attestation into consensus.

**Domain batching rule (registry at scale):** individual `ZIDR` release
docs are self-verifying alone, but at volume they batch: each domain
operator folds the day's release digests (`SHA3-256` of each canonical
doc) into the domain MMR via `zid_tree_append`, and the domain root
rides the epoch anchor as one catalog record. A verifier then needs only
the epoch anchor + one `zid_proof` (~few hundred bytes) to confirm a
release was in the committed batch — inclusion at scale, with the
per-doc signature chain unchanged. Domains anchor at their own cadence;
the epoch anchor is the shared metronome, not a requirement.

## Threshold and aggregate signatures (crypto roadmap)

Threshold crypto matters here — but the primitive has to match the job,
and GG20 (threshold ECDSA) is the wrong one for a greenfield scheme.
GG20 exists to fit chains that only verify ECDSA: it is multi-round and
interactive, Paillier-based, and buys **no throughput** — the output is
one ordinary ECDSA signature and verification cost is unchanged. zid
controls its own signature scheme, so it takes the Schnorr family:

- **t-of-n domain control (high-availability services): FROST** —
  threshold Schnorr, two-round signing, one compact 64-byte signature
  from any t of n operators. This is the Zcash ecosystem's own standard
  (ZIP-312) and fits zid keys (ed25519/ristretto) or RedJubjub
  (`core/modules/sapling/include/sapling/jubjub.h` ships in-tree). A service run
  by n nodes keeps serving descriptors when any t are online; no single
  offline master key.
- **Massively aggregated attestations (A4 bandwidth receipts): BLS12-381**
  — pairing code already in-tree (`core/modules/sapling/src/bls12_381.c`). n
  measurement receipts aggregate to one 48-byte signature; the BWAuth
  replacement settles one signature per epoch instead of n.
- **Raw ingest performance: batch ed25519 verification** — multi-scalar
  batch verify in `core/modules/crypto` (~2× per-signature throughput for nodes
  consuming domain records). This is where "high performance" actually
  comes from at the codec layer — not from threshold schemes.
- **GG20's one real niche:** threshold custody of on-chain *transparent*
  ZCL, because the chain itself speaks secp256k1 ECDSA. That is the
  custody lane (`docs/CUSTODY_MODEL.md`), not the identity layer — and
  even there the modern successor is CGGMP21, not GG20.

Honest scoping: threshold signatures do not speed up anchoring — the MMR
batching already made L1 cost constant. What they buy is **key
availability** (no single key compromise/offline point) and **committee
compactness** (one signature regardless of committee size). Phase
placement: batch verify → Phase 2, FROST committees → Phase 3–4, BLS
receipts → Phase 4.

## Versioning doctrine (every layer, one rule set)

Three versioned layers, three different mechanisms — never mix them:

1. **Wire formats** carry a leading version byte (`zid_doc`, `zid_proof`,
   ZANC, every lokad-framed overlay). Rules: a version's semantics are
   frozen forever; decoders reject unknown versions loudly (never
   silently skip); new version = new byte + new decode path, old paths
   untouched. Strict decode, no trailing bytes.
2. **Domain schemas** are versioned by convention in names and anchor
   labels (`zepoch@<height>`, `zcode@<tip>`): a domain's record schema
   changes only by bumping its convention tag, so old anchors remain
   interpretable forever. Content freshness is **seq/expiry** (the
   zid_doc monotonic rule), never format versioning.
3. **Command schemas** follow the house pattern
   (`zcl.<command>.input.v1` in `engine/composition/commands/*.def`): additive
   optional keys within a version; any breaking input change bumps the
   schema version.

Algorithm agility is a wire-format concern: a future `zid_doc` v2 with
an algorithm field is a *new version*, not a mutation of v1.

## Applications, in build order

### A1 — Onion service descriptors (flagship)

The service's master key is anchored on-chain (v1: via ZNAM). Current
introduction-point descriptors are signed documents served from the
content-addressed ZCODE swarm (`contexts/commons/modules/vcs/src/package_swarm.c`,
wired in `core/modules/net/src/msgprocessor_zcode_swarm.c`). Clients fetch the blob
from any peer and verify it against the chain-anchored key.

- Kills HSDir address harvesting: no relay ever sees descriptors for
  services it doesn't serve; blinded keys prevent chain-side enumeration.
- Rotation is free: new `seq`, new signature, no transaction.
- Availability: the service itself seeds its descriptor; optional paid
  pinning (A4 rails) covers long-lived services later.

### A2 — ZNAM naming for onion services (already built — promote)

`ZNAM_TYPE_ONION` (znam.h:33) + `/n/<name>` resolution is a chain-verified,
CA-free naming layer Tor has never had. Surface it: name-based links on
the onion site, docs, resolver UX. See the ZClassicDNS contract in
`docs/spec/power-node-contract.md`.

### A3 — ZDIR relay directory (an application, not the headline)

A relay is a master key that signs endpoint announcements:

- **On-chain:** REGISTER/DEREGISTER anchor the relay's identity key and
  owner (first-input P2PKH signer, ZNAM convention). Nothing else.
  Operators write these with `core zdir register` / `core zdir deregister`
  (`tools/command/native_zdir_command.c` → the `zdir_*` RPCs in
  `contexts/naming/controllers/src/zdir_controller.c`), never on a timer.
- **TRANSFER is not implemented and is not a gap.** Command byte 3 is
  reserved for it and `zdir_parse` rejects it, because a parsed-but-
  unhandled command would be a silent stub. Handing a hostname to a new
  operator is DEREGISTER by the current owner followed by REGISTER from the
  new one — two ordinary txs that the projection already authorizes
  correctly, with no new opcode and no new authorization rule. The one
  thing the two-step gives up is seniority: the new owner's row starts at
  the re-registration height. That is a deliberate price, not an oversight
  — a transferable seniority is a tradeable one.
- **Off-chain:** endpoint and bandwidth updates are signed gossip
  announcements — exactly how Tor relays republish descriptors to the
  DirAuths today. Liveness never touches the chain; it comes from signed
  heartbeats plus each node's own reachability probing.
- **Selection:** per-client derivation `SHA3-256(block_hash ‖ client_key)`
  — per-client reproducible, globally diversified (a single deterministic
  global guard set would be an anonymity monoculture). Weighted by
  **seniority** (registration height), capped per owner address.

### A4 — Incentives (last, only if A1–A3 earn it)

A bandwidth-credit ZSLP token settling over the existing batched daily
SEND rails (`contexts/market/services/include/services/zslp_command_service.h`).
Weight must come from seniority and measurement, never raw stake: paying
for relays at scale attracts Sybils — in 2023 the Tor Project had to
remove relays tied to a crypto scheme
([report](https://securityaffairs.com/154535/digital-id/tor-project-removed-relays.html)).
Trustless bandwidth measurement is unsolved research (FlashFlow, TorCoin);
this phase is explicitly gated on A1–A3 proving the substrate.

## Economics: low cost, high use, no spam

The rule: **the chain is a land registry, not a message bus.** Cost scales
with influence sought, not with existence.

**Where ZCL fees are required (one tx each):**

| Action | Frequency |
|---|---|
| ZNAM register / renew / transfer / set_text (incl. `zid` anchor) | per name event |
| ZDIR register / deregister (transfer = deregister + register) | per relay identity event |
| ZSLP genesis / mint / send | settlement only — rewards batch to ~1 tx/day for all contributors |
| Descriptor master-key anchor | once per service, ever |

**Never required:** liveness heartbeats, descriptor blobs, endpoint
updates, zmsg off-chain messages, zgame traffic, file chunks, bandwidth
receipts, swarm WANT/DATA, addr gossip.

**Verified constants** (`core/modules/validation/include/validation/main_constants.h`):
`DEFAULT_MIN_RELAY_TX_FEE = 100` zatoshis, `MAX_BLOCK_SIZE = 2,000,000`
consensus / `DEFAULT_BLOCK_MAX_SIZE = 200,000` mining policy,
`ZCL_FINALITY_DEPTH = 10` (see below). At 150 s blocks: 576 blocks/day,
~115 MB/day soft capacity.

**Scale math:** 1,000 relays × ~27 txs/year × ~200 B ≈ 5 MB/year. 10k ZNAM
ops ≈ 2.5 MB/year. Even 100× growth is a rounding error against a chain
that reached ~10 GB in 8+ years. Bulk data lives in quota'd, pruneable
local stores (ZCODE CAS), never on-chain.

**Spam resistance without pricing out users:** fees alone don't stop spam
on a cheap chain (1M min-fee txs ≈ 0.1 ZCL). The defense is asymmetry:

- *Seniority weighting* — 10,000 freshly-registered relays buy ~zero
  selection weight; aging in requires sustained renewals. Cheap to be
  real, expensive and slow to fake.
- *Per-owner influence cap* — N relays from one address count once.
- *Deferrability* — directory writes aren't latency-critical; block-space
  attacks merely delay them while the attacker burns fees daily.
- *Projection quotas* (policy, not consensus) — max live relays per
  owner, update rate limits for ranking. Retunable without a fork.

The loop closes nicely: the identity layer's steady small fee stream funds
the very PoW that secures it.

## Finality, forks, and netsplit monitoring

`ZCL_FINALITY_DEPTH = 10`
(`core/modules/validation/include/validation/main_constants.h:33`) with deep-reorg
refusal (`reorg_is_allowed` / `height_is_immutable`, both declared in
`core/modules/validation/include/validation/checkpoint.h:38,43` — NOT in
`main_constants.h`, which holds only the constant) means a partition
surviving >10 blocks on both sides **never reconverges**. The refusal is not
silent: both refusal paths in `engine/jobs/src/utxo_apply_delta_reorg.c` raise
the named blocker `chain.reorg_refused_below_finality`. Rules:

- **Provisional below 10 deep, final at or beyond.** Anchors feed hints
  immediately but confer no influence until final — kills flapping from
  shallow reorgs. "Depth" is blocks built *on top*
  (`current_height - record_height`), which is the same boundary
  `height_is_immutable` draws and the same one `reorg_is_allowed` enforces;
  in wallet "confirmations" terms (which count the record's own block) that
  is 11. Implemented as a pure, total predicate in
  `core/modules/policy/include/policy/anchor_finality.h`
  (`anchor_confers_influence`), with the withdrawal rail — a reorg that
  drops a record below finality takes its weight back — in
  `core/modules/policy/src/anchor_finality.c` and proven in
  `tests/harness/src/test_anchor_finality.c`.
- **10 deep is anti-flapping, not trust.** It does not make anything safe.
  An attacker with ~10 blocks of private hashpower can rewrite the recent
  window; influence comes only from seniority (hours–days), never recency.
- **Netsplit detection is directory-safety infrastructure**, wired into
  the existing `engine/conditions` + supervisor liveness tree:
  1. peer tip disagreement at same-or-greater height,
  2. block-arrival rate divergence vs difficulty (minority-side signal),
  3. tip staleness beyond expected variance.
- On suspected split: **degraded mode** — new anchors gain no influence,
  pre-split final entries keep working, discovery falls back to addr
  gossip + onion seeds, and status surfaces `SUSPECTED_NETSPLIT` as a
  named blocker, never a silent halt.

## Risks and honest limits

- **Operator privacy is the deepest cost.** OP_RETURN can't ride a Sapling
  output, so anchoring is transparent: a t-address with a traceable
  funding history is permanently bound to "I operate this service/relay."
  Mitigations: fund via shielded → fresh transparent hop, one address per
  identity. The permanence is intrinsic and must be disclosed.
- **Key compromise** requires on-chain rotation — a tx, plus loss of
  seniority for influence-weighted applications. Master keys belong
  offline, like Tor's.
- **Availability vs Tor's 6 HSDir replicas** — a self-seeded descriptor
  has one seeder until pinning incentives exist (A4).
- **Directory soundness = ZClassic's PoW security** — a small chain;
  say so. The identity layer is advisory: independent discovery roots
  (hardcoded seeds, addr gossip) always remain.
- **Bandwidth measurement without trusted measurers is unsolved.**
- **Pruned nodes can't rebuild overlay projections locally** — a future
  ROM-checkpoint commitment of projection digests is a sealed-`core/`
  change, owner-gated, Phase 4+.
- This does not replace Tor's circuits, and Phase 4 incentives must be
  designed against mercenary-Sybil economics (2023 incident above).

## Phases

1. **Phase 1 — `contexts/wallet/modules/zid` codec (pure library, no networking).** Blinded
   key derivation (`SHA3-256("ZIDB" ‖ pubkey ‖ period)`), signed
   document encode/decode/verify with monotonic-seq rule, anchor-domain
   MMR (append/root/prove/**verify** — the verifier function everyone must
   agree on forever), canonical proof wire format, release-record codec,
   tests. No behavior change anywhere. **(done)**
2. **Phase 2 — epoch anchor + Sovereign Registry.** `core epoch
   status/anchor/verify` committing the OP_RETURN catalog digest per
   epoch (Bounded Node keystone); `zcode release sign/verify` over the
   release-record codec (the registry's first signed artifacts);
   cookbook docs. **(in progress)**
3. **Phase 3 — descriptor + directory applications.** The `zdesc` and
   `zdir` domain trees anchored per epoch, descriptor blobs via the
   swarm, ZNAM `zid` anchoring convention, signed endpoint gossip,
   seniority-capped per-client selection, netsplit degraded mode.
4. **Phase 4 — incentives.** Bandwidth receipts research, ZSLP credit
   token, batched settlement, FROST domain committees, BLS receipt
   aggregation; gated on earlier phases.

## Concrete files

Existing (built on): `contexts/naming/modules/znam/include/znam/znam.h`,
`contexts/market/modules/zslp/include/zslp/slp.h`,
`core/modules/script/include/script/op_return_push.h`,
`core/modules/script/include/script/standard.h` (223 B cap),
`engine/models/src/op_return_index.c`,
`contexts/commons/modules/vcs/src/package_swarm.c` + `contexts/commons/modules/vcs/include/vcs/package_swarm.h`,
`core/modules/net/src/msgprocessor_zcode_swarm.c`,
`core/modules/net/src/onion_ratelimit.c`, `core/modules/net/src/onion_service.c`,
`core/modules/net/src/noise_transport.c` + `core/modules/noise/src/noise_handshake.c`,
`core/modules/validation/include/validation/main_constants.h` (fee/finality/size
constants only),
`core/modules/validation/include/validation/checkpoint.h` (`reorg_is_allowed` /
`height_is_immutable` — the finality *predicates*),
`core/modules/policy/include/policy/anchor_finality.h` (provisional-vs-final gate on
directory influence, and the reorg withdrawal rail),
`contexts/commons/modules/zanc/include/zanc/zanc.h` (generic 32-byte on-chain anchor),
`core/modules/chain/src/mmr.c` (MMR hash conventions the domain tree mirrors),
`core/chainparams/src/checkpoints.c` (baked trust anchor),
`docs/spec/power-node-contract.md` (ZClassicDNS + onion gateway).

Built (Phase 1): `contexts/wallet/modules/zid/include/zid/zid.h`, `contexts/wallet/modules/zid/src/zid.c`,
`tests/harness/src/test_zid.c` — signed documents, blinded keys, anchor-domain
MMR with inclusion proofs.
