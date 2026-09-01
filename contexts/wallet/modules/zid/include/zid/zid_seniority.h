/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID seniority weighting — turn "this identity has been anchored on-chain
 * for a long time, under one owner" into a BOUNDED, PER-CLIENT dial-chance
 * multiplier for peer selection. Influence comes from age and sustained
 * presence, never from stake, balance, or how many identities an actor can
 * mint.
 *
 * WHY THIS SHAPE (read before "simplifying" any of it).
 *
 * 1. A burst of registrations buys nothing. Below
 *    ZID_SENIORITY_MIN_AGE_BLOCKS the score is EXACTLY 0.0 and the
 *    multiplier is EXACTLY 1.0 — the unweighted baseline. Ten thousand
 *    freshly-anchored relays therefore add zero selection weight, not
 *    "a little each".
 *
 *    HONEST LIMIT: this is a PATIENCE cost, not a resource cost, and it is
 *    not the same as "cannot be bought". An attacker can pre-anchor N
 *    identities under N addresses, wait out the ~3.5-day floor once, and
 *    hold N full-mass entries. Worse, seniority here is a pure function of
 *    (tip - anchor_height): nothing binds continuous control, nothing
 *    re-proves liveness, and nothing decays on inactivity — so an identity
 *    anchored in 2019 and dark ever since carries maximum seniority
 *    forever, and its keys are transferable off-chain for cash. Aging in
 *    cannot be RUSHED; the aged asset is freely purchasable. Binding
 *    seniority to sustained, re-proven liveness is the open work.
 *
 * 2. Seniority is capped PER OWNER, or it is farmable. An actor who
 *    anchored 500 identities in 2019 would otherwise hold 500x the
 *    influence of an honest operator who anchored one. Relays are grouped
 *    by owner_id (the first-input P2PKH signer, the same owner convention
 *    ZNAM uses); within an owner, the k-th relay keeps only
 *    ZID_SENIORITY_OWNER_DECAY^k of its score and everything past
 *    ZID_SENIORITY_MAX_RELAYS_PER_OWNER keeps nothing.
 *
 *    HONEST LIMIT: the bound is ~1.33x a single relay's mass PER OWNER
 *    ADDRESS, which is not the same as per actor. A fresh address per
 *    anchor is a fresh owner, so evading the cap costs one distinct UTXO
 *    and one fee per identity — cheap. The cap stops the lazy case (many
 *    relays under one visible owner, which is the shape of the 2023 Tor
 *    incident) and does not stop a deliberate one. Do not describe it as
 *    a per-actor bound.
 *
 * 3. There is NO GLOBAL ANSWER, on purpose. A deterministic weight every
 *    client computes identically would be an anonymity monoculture: one
 *    ranking, one top relay, one target that serves everybody. So
 *    seniority does not produce a ranking — it produces an influence MASS,
 *    and each client draws its own key from that mass through a per-client
 *    derivation (see the seam below). Two clients holding identical chain
 *    state and identical relay sets get DIFFERENT favourites, while the
 *    population-wide expectation stays proportional to seniority. The
 *    per-relay key is the Efraimidis-Spirakis weighted-sampling key
 *    u^(1/w): as w goes to 0 the key goes to 0 (a fresh relay is never
 *    anyone's favourite), and as w grows the key concentrates near 1.
 *
 * 4. ADVISORY, NEVER EXCLUSIVE. Every multiplier this module produces is
 *    in [1.0, ZID_SENIORITY_MAX_MULT]. 1.0 is "no opinion" — it is what a
 *    fresh relay, an over-quota relay, and an unknown relay all get. There
 *    is no value this module can return that lowers a peer's dial chance
 *    below the unweighted baseline, and none that removes a peer from
 *    consideration. The single sanctioned consumer is
 *    addrman_publish_reputation_weights() (core/modules/net/include/net/addrman.h),
 *    which clamps to the same bound in the callee, so the ceiling is
 *    enforced twice and by the shape of the API rather than by discipline.
 *    If a weighting scheme ever wants more than 4x of dynamic range, the
 *    answer is that it does not get more.
 *
 * 5. THE TABLE IS NO LONGER INERT. Until the address binding landed this
 *    module was computed, scored, owner-capped, drawn and then discarded,
 *    because nothing could say which dialable address an anchored identity
 *    owned. It can now: a SIGNED ENDPOINT RECORD (vcs/zendp_swarm.h) is a
 *    document the identity signed with its own master key, accepted only
 *    when that key resolves to an ACTIVE anchor on-chain, and the binding is
 *    built from those records by config/boot_seniority.h. Seniority cannot
 *    be borrowed by asserting somebody else's key, because the claim is
 *    signed by the key it names.
 *
 *    HONEST LIMIT, inherited whole from zendp_swarm.h: a verified record
 *    proves the identity SAID "reach me here". It does not prove that the
 *    party answering at that address IS that identity — binding the session
 *    to the key needs the Noise transport, which is default OFF because
 *    the live network speaks v1. Until that flips, the worst a false
 *    address claim buys is up to 4x the dial preference on an address the
 *    claimant does not control, which cannot exclude anyone and cannot
 *    exceed the bound in (4). A second limit worth naming: only an address
 *    a signed record vouches for can earn anything at all, so on today's
 *    network the overwhelming majority of peers still sit at exactly 1.0.
 *
 * PURE. No clock, no RNG, no I/O, no allocation, no chain access, no
 * database. Caller buffers only. contexts/wallet/modules/zid is rank 10 in
 * engine/composition/lib_module_order.def, below net/storage/validation, and this file
 * keeps it that way: whoever knows how to enumerate anchored relays and how
 * to reach addrman does the wiring; this module only does the arithmetic.
 * That is also why the cap constant below is a local copy rather than an
 * include (see ZID_SENIORITY_MAX_MULT).
 *
 * NOT CONSENSUS. Nothing here is a validity rule. Every constant in the
 * POLICY block is retunable by an operator edit + rebuild and could never
 * require a fork to change. A node that disagrees with every number here
 * still follows the same chain; it just dials a different peer first. */

#ifndef ZCL_ZID_SENIORITY_H
#define ZCL_ZID_SENIORITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── POLICY (retunable) ────────────────────────────────────────────
 *
 * THIS BLOCK IS THE ONE PLACE AN OPERATOR RETUNES SELECTION. Every
 * constant here is local policy: change it, rebuild, and this node weighs
 * peers differently. No other node has to agree, no chain rule references
 * any of it, and no value of any of them can make a block valid or
 * invalid. Nothing outside this block should hard-code a selection number.
 *
 * Block spacing is 150 s, so 576 blocks ~ 1 day. */

/* Minimum anchored age before an identity carries ANY weight. Under this,
 * the score is exactly 0 and the multiplier is exactly 1.0. This is the
 * anti-Sybil floor: a burst of registrations is worth nothing until it has
 * survived the floor, and surviving it costs elapsed time, which cannot be
 * bought in bulk. 2016 blocks ~ 3.5 days. */
#define ZID_SENIORITY_MIN_AGE_BLOCKS 2016

/* Blocks past the floor at which the score reaches 0.5. The curve is
 * saturating (asymptote 1.0), so seniority always keeps rising but with
 * ever-smaller returns — an ancient relay cannot run away with the
 * network. 100000 blocks ~ 174 days. */
#define ZID_SENIORITY_HALF_LIFE_BLOCKS 100000

/* Live-relay quota per owner: past this many relays, an owner's remaining
 * relays carry zero mass. A PROJECTION QUOTA, not a rule — an owner may
 * legitimately anchor more identities, they simply stop buying selection
 * weight. */
#define ZID_SENIORITY_MAX_RELAYS_PER_OWNER 4

/* Geometric decay applied to an owner's 2nd, 3rd, ... relay (ordered by
 * seniority, best first). With 0.25 and a quota of 4, one owner's total
 * mass is at most 1 + 1/4 + 1/16 + 1/64 = 1.328125 times a single relay's
 * — i.e. N relays from one owner count approximately once. */
#define ZID_SENIORITY_OWNER_DECAY 0.25

/* Maps post-cap mass (in [0, ~1.33]) onto the sampling weight w. Larger
 * makes senior relays win their own draw more often; it does NOT widen the
 * multiplier bound, which is fixed below. */
#define ZID_SENIORITY_MASS_SCALE 4.0

/* Hard ceiling on how many relays one ranking pass will consider. A
 * projection quota: it bounds the work and the caller's buffer, and an
 * oversized input is refused rather than silently truncated. */
#define ZID_SENIORITY_MAX_RELAYS 4096

/* RANKING UPDATE RATE LIMIT. The per-client derivation is re-keyed only
 * once per this many blocks, so the favourite set is stable for ~6 hours
 * instead of reshuffling every block. Two reasons, both load-bearing:
 * a per-block reshuffle would churn connections continuously, and it would
 * hand an attacker a fresh grinding attempt every 150 s. 144 blocks ~ 6 h.
 *
 * HONOURED AT RUNTIME. The caller (config/boot_seniority.h) runs a supervised
 * worker that rebuilds the table when — and only when — this epoch rolls, so
 * the favourite set rotates for the whole life of the process instead of
 * being pinned to whatever the tip happened to be during startup. The
 * decision is the pure boot_seniority_next_action(), so "rebuilds on a
 * boundary, idles between boundaries" is asserted with numbers rather than
 * asserted about a thread. */
#define ZID_SENIORITY_EPOCH_BLOCKS 144

/* ── BOUND (NOT policy — do not retune) ────────────────────────────
 *
 * The advisory ceiling. This is a deliberate LOCAL COPY of
 * ADDRMAN_REPUTATION_MAX_MULT (core/modules/net/include/net/addrman.h): contexts/wallet/modules/zid sits
 * BELOW core/modules/net in engine/composition/lib_module_order.def, so contexts/wallet/modules/zid may not
 * reference core/modules/net. The two are pinned equal by a static assertion in
 * tests/harness/src/test_zid_seniority.c, which is above both and can include
 * either — so this copy cannot silently drift, and widening one without the
 * other fails to COMPILE.
 *
 * Raising this is not a tuning decision, it is a change to how much any
 * reputation signal is allowed to bend peer selection, and it is out of
 * scope for seniority. */
#define ZID_SENIORITY_MAX_MULT 4.0

/* ── Inputs ────────────────────────────────────────────────────────── */

/* One anchored relay identity, as the caller reads it out of the on-chain
 * identity projection (engine/models/include/models/zid_identity.h supplies
 * every field: master_pubkey, owner_address, anchor_height).
 *
 * owner_id is an opaque, collision-resistant grouping key for the owning
 * P2PKH signer — equality is the only thing this module asks of it. The
 * node uses sha3-256 over the projection's owner_address string; a test may
 * use any distinct bytes. An all-zero owner_id means "owner unknown", and
 * an unknown owner is NOT pooled with other unknowns: each such relay is
 * treated as its own owner, because merging them would let one actor dodge
 * the cap by withholding the owner field. */
struct zid_relay_registration {
    uint8_t relay_id[32];       /* the identity's ed25519 master public key */
    uint8_t owner_id[32];       /* owner grouping key; all-zero = unknown */
    int32_t registration_height; /* anchor_height; negative = never anchored */
};

/* PER-CLIENT DERIVATION SEAM (owned by T5.1, not by this module).
 *
 * Contract: a PURE function of (this client's key, a chain-committed value
 * for the current ranking epoch, relay_id) producing a uniform 64-bit draw.
 * Same inputs, same output, forever — the client must be able to rederive
 * its own favourites without storing them, and two different clients must
 * get uncorrelated draws for the same relay. `ctx` carries the client key
 * and the epoch value; this module never inspects it.
 *
 * Returning false means "no draw available for this relay". That is NOT an
 * error and never excludes anyone: the relay keeps the 1.0 baseline
 * multiplier, exactly as an unknown relay would.
 *
 * The implementation lives in net/zdir_selection.h (zdir_client_key ->
 * zdir_epoch_seed -> zdir_candidate_score) and is plugged in by
 * engine/composition/src/boot_seniority.c. It is NOT visible from here and must not
 * be: contexts/wallet/modules/zid is rank 10 and core/modules/net is rank 93 in
 * engine/composition/lib_module_order.def, so this typedef is the whole of the contract
 * between them and the composition root does the joining. */
typedef bool (*zid_seniority_draw_fn)(void *ctx, const uint8_t relay_id[32],
                                      uint64_t *draw_out);

/* ── Outputs ───────────────────────────────────────────────────────── */

struct zid_seniority_weight {
    uint8_t relay_id[32];
    double  seniority;   /* [0,1] raw age score, before the owner cap */
    double  mass;        /* [0,1] influence mass, after the owner cap */
    double  multiplier;  /* [1.0, ZID_SENIORITY_MAX_MULT] for THIS client */
    int32_t owner_rank;  /* 0-based position within its owner's relay set */
    bool    over_owner_quota; /* true iff owner_rank >= the per-owner quota */
};

/* ── API ───────────────────────────────────────────────────────────── */

/* Raw seniority from anchored age. Returns 0.0 for a relay younger than the
 * floor, for a negative/absent registration height, and for a registration
 * in the future (a height above the tip is not evidence of age). Otherwise
 * strictly increasing in age, in (0,1). */
double zid_seniority_score(int32_t registration_height, int32_t tip_height);

/* The ranking epoch containing tip_height — tip_height rounded down to a
 * multiple of ZID_SENIORITY_EPOCH_BLOCKS. The caller feeds the block hash
 * AT this height to the derivation seam, so the per-client favourite set
 * changes once per epoch instead of once per block. Negative input yields
 * 0. */
int32_t zid_seniority_epoch_height(int32_t tip_height);

/* Combine an existing advisory multiplier with the seniority multiplier
 * into the ONE bounded value handed to addrman_publish_reputation_weights().
 *
 * This exists so that seniority does not need a second influence path.
 * Bandwidth reputation and seniority are two opinions about the same
 * address; they are merged HERE and issued as a single call, rather than
 * as two calls where the later one silently clobbers the earlier.
 *
 * Combines in excess-over-baseline space as a probabilistic OR:
 *   f = 1 - (1 - fa)(1 - fb),  fx = (x - 1) / (MAX - 1) clamped to [0,1]
 * so the result is monotone non-decreasing in BOTH inputs (neither signal
 * can ever be used to pull a peer down), is >= max(a, b), and can never
 * leave [1.0, ZID_SENIORITY_MAX_MULT]. Out-of-range inputs clamp rather
 * than reject: this is an advisory dial, and a bad input must degrade to
 * "no opinion", never to an exclusion. */
double zid_seniority_combine(double a, double b);

/* Score, owner-cap and per-client-weight a whole relay set.
 *
 * `out` receives one entry per input relay, SORTED ASCENDING BY relay_id
 * (a canonical order independent of input order, so two clients with the
 * same relay set produce byte-comparable tables and zid_seniority_find can
 * binary-search it). Nothing is ever dropped: a fresh, over-quota or
 * undrawable relay is still present, carrying multiplier 1.0. The output
 * is a set of ADVISORY BOOSTS, never a filter.
 *
 * Returns the number of entries written, or -1 on invalid input (NULL
 * relays/out/draw, n > ZID_SENIORITY_MAX_RELAYS, or out_cap < n) — all of
 * which log. n == 0 is valid and returns 0. */
int zid_seniority_rank(const struct zid_relay_registration *relays, size_t n,
                       int32_t tip_height,
                       zid_seniority_draw_fn draw, void *draw_ctx,
                       struct zid_seniority_weight *out, size_t out_cap);

/* Binary-search a table produced by zid_seniority_rank (which is why that
 * function sorts). Returns NULL when the relay is absent — an absent relay
 * has no opinion attached and must be dialled on the unweighted baseline. */
const struct zid_seniority_weight *
zid_seniority_find(const struct zid_seniority_weight *table, size_t n,
                   const uint8_t relay_id[32]);

#endif /* ZCL_ZID_SENIORITY_H */
