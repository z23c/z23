/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_rule_sweep — the FORWARD-facing consensus check.
 *
 * WHY THIS EXISTS. Every past-facing check this project has (deterministic
 * rebuild, full-chain replay to tip, historical UTXO-root agreement, the E13
 * consensus-parity lint) can be satisfied BY CONSTRUCTION by a build that
 * carries a rule change gated on a height we have not reached yet. All five
 * mainnet activation heights are <= 707,000 — roughly 2.5M blocks behind the
 * tip — so a candidate binary can reproduce every historical byte perfectly
 * and still contain `if (n_height >= 3400000) halvings--`. Nothing that only
 * replays the PAST can see that.
 *
 * This engine evaluates the PURE consensus schedule at a deterministic set of
 * heights that reaches millions of blocks into the FUTURE and folds every
 * answer into one SHA3-256 digest. Two independently produced binaries that
 * print the same digest agree on the whole forward schedule; a binary carrying
 * a future-gated rule prints a different digest even though its history is
 * byte-identical.
 *
 * COST. No daemon, no datadir, no disk reads, no network, no clock, no RNG, no
 * heap. Pure integer arithmetic over compiled-in parameter tables plus one
 * SHA3-256 fold, so it runs on the weakest box in the fleet (8 cores, 15 GB,
 * 7200rpm HDD, no compiler) in well under a second.
 *
 * WHAT IT CANNOT SEE. This digest covers the pure height-keyed SCHEDULE:
 * subsidy, halvings, upgrade activation, Equihash (N,K), PoW limit and
 * retarget window, the size caps, and the compiled checkpoint table. It does
 * NOT cover script semantics, signature hashing, or anything that needs a
 * block or a transaction as input. And because heights above the tip are
 * SAMPLED (stride + dense band), a rule gated on one isolated future height
 * that no sample lands on is not caught — see CRS_DEFAULT_STRIDE for the
 * coverage arithmetic. A schedule change of the realistic shape
 * (`h >= X` — which perturbs EVERY height above X) is always caught.
 *
 * ── THE SWEEP VECTOR ─────────────────────────────────────────────────────
 * The union of four families, deduplicated and evaluated in ASCENDING height
 * order so the digest is order-stable:
 *   1. every height in [0, CRS_LOW_DENSE_MAX]
 *   2. every halving boundary in range, and boundary +/- 1
 *   3. every vUpgrades[].nActivationHeight, and +/- 1
 *   4. tip .. tip+horizon at a fixed stride, with a dense band of
 *      +/- CRS_DEFAULT_BAND around each stride point
 * The tip is an explicit parameter (never read from a datadir or a peer) so
 * two boxes comparing digests must agree on the sweep vector deliberately
 * rather than by accident. tip, horizon, stride and band are all folded into
 * the digest preimage, so two digests computed over different vectors can
 * never collide into a false "we agree".
 *
 * ── THE DIGEST PREIMAGE ──────────────────────────────────────────────────
 * SHA3-256 over, in order:
 *   HEADER: domain "zcl.consensus_rule_sweep.v1" (NUL included), the network
 *           id string (length-prefixed), tip/horizon/stride/band/row-count as
 *           LE64, MAX_NETWORK_UPGRADES as LE32, then the height-invariant
 *           chain parameters (see crs_absorb_header for the exact field list).
 *   ROWS:   one fixed-width record per swept height, ascending (see
 *           crs_absorb_row).
 * Every multi-byte integer is little-endian and fixed width; no padding bytes
 * of any struct are ever hashed, so the digest does not depend on the ABI.
 *
 * Layering: this header is consumed by tools/consensus_rule_sweep.c (the CLI)
 * and by tests/harness/src/test_consensus_rule_sweep.c (the gate). Keeping the
 * engine here means the test drives the IDENTICAL code the tool ships, so a
 * green test is evidence about the tool and not about a parallel copy.
 */

#ifndef ZCL_TOOLS_CONSENSUS_RULE_SWEEP_H
#define ZCL_TOOLS_CONSENSUS_RULE_SWEEP_H

#include "base/hex.h"           /* the one hex codec */
#include "base/serialize_le.h"  /* the one fixed-width byte-order codec */
#include "chain/chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/upgrades.h"
#include "domain/consensus/subsidy.h"
#include "sha3/sha3.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Digest-preimage domain separator. Bump the version suffix (and only then)
 * when the preimage LAYOUT changes; a layout change makes old and new digests
 * incomparable, which is exactly what a different domain string signals. */
#define CRS_DOMAIN "zcl.consensus_rule_sweep.v1"
#define CRS_CHECKPOINT_DOMAIN "zcl.consensus_rule_sweep.v1/checkpoints"
#define CRS_VERSION_TAG "consensus_rule_sweep/v1"

/* Default tip. A PINNED CONSTANT, deliberately not the live chain tip: the
 * whole point is that two boxes must agree on the sweep vector, and a default
 * that drifted with the chain would make every comparison a coincidence. This
 * value is the mainnet tip recorded when the compiled checkpoint table was
 * harvested (core/chainparams/src/chainparams.c, "tip=3108561 at harvest
 * time"). Pass --tip=N to sweep from somewhere else; the tip is in the digest
 * preimage, so a mismatch shows up as a different digest, never as a silent
 * false agreement. */
#define CRS_DEFAULT_TIP 3108561

/* How far past the tip the sweep reaches. 4,000,000 blocks is ~9.5 years at
 * the post-Buttercup 75s spacing and covers the next two post-Buttercup
 * halving boundaries. */
#define CRS_DEFAULT_HORIZON 4000000

/* Sampling of the above-tip range. stride=1000 with band=4 evaluates 9 of
 * every 1000 future heights (0.9%) for ~36k rows and a few tens of
 * milliseconds. That is chosen for the weakest box in the fleet; a rule gated
 * on `h >= X` is caught regardless of stride because it perturbs every height
 * above X, and only a rule gated on an isolated single height can slip between
 * samples. Lower the stride when you want that residual covered too — it is in
 * the digest preimage, so a denser sweep can never be confused with the
 * canonical one, and `--stride=1` sweeps the forward range exhaustively. */
#define CRS_DEFAULT_STRIDE 1000
#define CRS_DEFAULT_BAND 4

/* Every height in [0, CRS_LOW_DENSE_MAX] is swept exhaustively: the slow-start
 * ramp, the genesis edge and the early founders-reward regime all live here. */
#define CRS_LOW_DENSE_MAX 2000

/* Capacity the caller should supply for the height vector. Sized so that even
 * `--stride=1` (the EXHAUSTIVE forward sweep, ~4M rows and a few seconds)
 * fits: the canonical vector needs ~38k of it, and the rest is untouched BSS
 * that never becomes resident. crs_build_vector fails closed with
 * CRS_ERR_CAPACITY rather than silently truncating a vector. */
#define CRS_MAX_HEIGHTS 4200000

/* Bounds on the CLI-supplied sweep parameters. The upper tip bound leaves room
 * for tip+horizon+band to stay inside int32_t without overflow. */
#define CRS_MAX_HORIZON 64000000
#define CRS_MAX_BAND 4096
#define CRS_MAX_TIP (INT32_MAX - CRS_MAX_HORIZON - CRS_MAX_BAND - 2)

enum crs_status {
    CRS_OK = 0,
    CRS_ERR_BAD_CONFIG = 1,   /* a sweep parameter is out of range */
    CRS_ERR_CAPACITY = 2,     /* the vector does not fit the supplied buffer */
    CRS_ERR_NULL = 3,         /* a required pointer argument was NULL */
};

struct crs_config {
    int32_t tip;
    int32_t horizon;
    int32_t stride;
    int32_t band;
};

/* One evaluated height. Nothing here is read from disk, a clock, or a peer:
 * every field is the return value of a pure consensus function applied to
 * (height, compiled parameters). */
struct crs_row {
    int32_t  height;
    int64_t  subsidy;                  /* domain_consensus_block_subsidy */
    uint8_t  subsidy_ok;               /* its zcl_result.ok */
    int32_t  subsidy_code;             /* its zcl_result.code */
    int32_t  halvings;                 /* consensus_halving */
    uint64_t upgrade_active_mask;      /* bit i = consensus_network_upgrade_active(.,h,i) */
    uint64_t upgrade_state_packed;     /* 2 bits per slot: consensus_upgrade_state */
    int32_t  epoch;                    /* consensus_current_epoch */
    uint32_t branch_id;                /* consensus_current_epoch_branch_id */
    uint32_t equihash_n;               /* chain_params_equihash_n */
    uint32_t equihash_k;               /* chain_params_equihash_k */
    uint8_t  pow_limit[32];            /* consensus.powLimit at this height */
    int64_t  target_spacing;           /* consensus_pow_target_spacing */
    int64_t  averaging_window_timespan;/* consensus_averaging_window_timespan */
    int64_t  min_actual_timespan;      /* consensus_min_actual_timespan */
    int64_t  max_actual_timespan;      /* consensus_max_actual_timespan */
    uint64_t max_block_size;           /* MAX_BLOCK_SIZE at this height */
    uint64_t max_tx_size_after_sapling;/* MAX_TX_SIZE_AFTER_SAPLING at this height */
    uint8_t  checkpoint_digest[32];    /* crs_checkpoint_table_digest */
};

/* Post-evaluation hook. The engine calls it on a SCRATCH copy of each row
 * after the pure functions have filled it in and before the row is folded into
 * the digest. Production always passes NULL; the test uses it to plant a
 * future-height bomb and prove the gate can FAIL, without editing one byte of
 * consensus source. */
typedef void (*crs_row_hook)(struct crs_row *row, void *ctx);

/* Verbose sink. The CLI passes a printer; callers that only want the digest
 * pass NULL. */
typedef void (*crs_row_sink)(const struct crs_row *row, void *ctx);

/* ── little-endian fixed-width absorb helpers ─────────────────────────────
 * Every value that reaches the sponge goes through one of these, so no struct
 * padding and no host byte order can ever influence the digest. The packing
 * itself is the tree's ONE byte-order codec (base/serialize_le.h) — these are
 * sponge adapters over it, not a thirteenth private shift ladder. */

static inline void crs_absorb_u8(struct sha3_256_ctx *ctx, uint8_t v)
{
    sha3_256_write(ctx, &v, 1);
}

static inline void crs_absorb_u32(struct sha3_256_ctx *ctx, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

static inline void crs_absorb_u64(struct sha3_256_ctx *ctx, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

static inline void crs_absorb_i32(struct sha3_256_ctx *ctx, int32_t v)
{
    uint8_t b[4];
    zcl_write_i32_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

static inline void crs_absorb_i64(struct sha3_256_ctx *ctx, int64_t v)
{
    uint8_t b[8];
    zcl_write_i64_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

static inline void crs_absorb_bytes(struct sha3_256_ctx *ctx,
                                    const void *p, size_t n)
{
    crs_absorb_u64(ctx, (uint64_t)n);            /* length-prefixed */
    if (n)
        sha3_256_write(ctx, (const unsigned char *)p, n);
}

/* IEEE-754 binary64, little-endian byte order. Used only for the checkpoint
 * table's fTransactionsPerDay, which is a sync-progress denominator and not a
 * consensus value; it is folded in anyway so a silent edit to the compiled
 * table is visible. */
static inline void crs_absorb_double(struct sha3_256_ctx *ctx, double v)
{
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(v), "binary64 required");
    memcpy(&bits, &v, sizeof(bits));
    crs_absorb_u64(ctx, bits);
}

/* Lowercase, NUL-terminated, 64 characters — the tree's one hex encoder. */
static inline void crs_hex32(const uint8_t digest[32], char out[65])
{
    zcl_hex_encode(digest, 32, out);
}

/* ── height-parameterised accessors for the flat size caps ────────────────
 * MAX_BLOCK_SIZE and MAX_TX_SIZE_AFTER_SAPLING are compile-time constants
 * today, so these look like they throw the height away — and that is the
 * point. They are read THROUGH a height the same way every other field is, so
 * the day either cap grows a height gate the sweep already covers it instead of
 * needing a new field. */
static inline uint64_t crs_max_block_size(int32_t height)
{
    (void)height;
    return (uint64_t)MAX_BLOCK_SIZE;
}

static inline uint64_t crs_max_tx_size_after_sapling(int32_t height)
{
    (void)height;
    return (uint64_t)MAX_TX_SIZE_AFTER_SAPLING;
}

/* ── the compiled checkpoint table ────────────────────────────────────────
 * NOTE, verified 2026-08-24 against core/chainparams/src/chainparams.c: the
 * mainnet_checkpoints[] STATIC INITIALIZER is 63 `{{0}}` placeholders, but
 * init_main_params() overwrites every one of them with a real block hash via
 * uint256_set_hex (chainparams.c:293-421) before chain_params_get() can hand
 * the table out. So at RUNTIME the table is fully populated. Read it through
 * chain_params_get()->checkpointData, never from the initializer. */
static inline void crs_checkpoint_table_digest(const struct chain_params *cp,
                                               uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    crs_absorb_bytes(&ctx, CRS_CHECKPOINT_DOMAIN, sizeof(CRS_CHECKPOINT_DOMAIN));

    const struct checkpoint_data *d = &cp->checkpointData;
    int n = d->nEntries;
    if (n < 0)
        n = 0;
    crs_absorb_i32(&ctx, n);
    crs_absorb_i64(&ctx, d->nTimeLastCheckpoint);
    crs_absorb_i64(&ctx, d->nTransactionsLastCheckpoint);
    crs_absorb_double(&ctx, d->fTransactionsPerDay);
    for (int i = 0; i < n; i++) {
        const struct checkpoint_entry *e = &d->entries[i];
        crs_absorb_i32(&ctx, e->height);
        sha3_256_write(&ctx, e->hash.data, sizeof(e->hash.data));
    }

    sha3_256_finalize(&ctx, out);
}

/* ── the sweep vector ─────────────────────────────────────────────────────*/

static inline int crs_cmp_i32(const void *a, const void *b)
{
    int32_t x = *(const int32_t *)a;
    int32_t y = *(const int32_t *)b;
    return (x > y) - (x < y);
}

static inline void crs_push(int32_t *v, size_t cap, size_t *n, int64_t h,
                            int32_t max_h, bool *overflow)
{
    if (h < 0 || h > (int64_t)max_h)
        return;
    if (*n >= cap) {
        *overflow = true;
        return;
    }
    v[(*n)++] = (int32_t)h;
}

/* Add h-1, h and h+1. Used for every boundary family: the classic consensus
 * fork seam is the off-by-one at an activation/halving edge. */
static inline void crs_push_triple(int32_t *v, size_t cap, size_t *n, int64_t h,
                                   int32_t max_h, bool *overflow)
{
    crs_push(v, cap, n, h - 1, max_h, overflow);
    crs_push(v, cap, n, h, max_h, overflow);
    crs_push(v, cap, n, h + 1, max_h, overflow);
}

static inline struct crs_config crs_default_config(void)
{
    return (struct crs_config){
        .tip     = CRS_DEFAULT_TIP,
        .horizon = CRS_DEFAULT_HORIZON,
        .stride  = CRS_DEFAULT_STRIDE,
        .band    = CRS_DEFAULT_BAND,
    };
}

static inline enum crs_status crs_validate_config(const struct crs_config *cfg)
{
    if (!cfg)
        return CRS_ERR_NULL;
    if (cfg->tip < 0 || cfg->tip > CRS_MAX_TIP)
        return CRS_ERR_BAD_CONFIG;
    if (cfg->horizon < 0 || cfg->horizon > CRS_MAX_HORIZON)
        return CRS_ERR_BAD_CONFIG;
    if (cfg->stride <= 0 || cfg->stride > CRS_MAX_HORIZON)
        return CRS_ERR_BAD_CONFIG;
    if (cfg->band < 0 || cfg->band > CRS_MAX_BAND)
        return CRS_ERR_BAD_CONFIG;
    return CRS_OK;
}

/* Build the deduplicated, ascending sweep vector into `out`. Deterministic:
 * same (config, params) in, same vector out, on any host. */
static inline enum crs_status crs_build_vector(const struct crs_config *cfg,
                                               const struct chain_params *cp,
                                               int32_t *out, size_t cap,
                                               size_t *out_n)
{
    if (!cfg || !cp || !out || !out_n)
        return CRS_ERR_NULL;
    *out_n = 0;
    enum crs_status st = crs_validate_config(cfg);
    if (st != CRS_OK)
        return st;

    const struct consensus_params *p = &cp->consensus;
    const int32_t max_h = cfg->tip + cfg->horizon + cfg->band;
    size_t n = 0;
    bool overflow = false;

    /* (1) exhaustive low band — genesis edge, slow-start ramp, early rules. */
    for (int32_t h = 0; h <= CRS_LOW_DENSE_MAX && h <= max_h; h++)
        crs_push(out, cap, &n, h, max_h, &overflow);

    /* (2) halving boundaries +/- 1, derived arithmetically from BOTH interval
     * families (pre-Buttercup and post-Buttercup) so no boundary depends on
     * this file agreeing with consensus_halving() about which regime applies.
     * Both the shifted and unshifted multiples are emitted: a superfluous
     * height costs one row, a missed boundary costs the whole check. */
    const int32_t shift = consensus_subsidy_slow_start_shift(p);
    const int32_t pre = p->nPreButtercupSubsidyHalvingInterval;
    const int32_t post = p->nPostButtercupSubsidyHalvingInterval;
    const int32_t bc = p->vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight;
    if (pre > 0) {
        for (int64_t h = 0; h <= (int64_t)max_h; h += pre) {
            crs_push_triple(out, cap, &n, h, max_h, &overflow);
            crs_push_triple(out, cap, &n, h + shift, max_h, &overflow);
        }
    }
    if (post > 0 && bc >= 0) {
        for (int64_t h = bc; h <= (int64_t)max_h; h += post) {
            crs_push_triple(out, cap, &n, h, max_h, &overflow);
            crs_push_triple(out, cap, &n, h + shift, max_h, &overflow);
        }
    }
    /* The founders-reward cliff is one block before the first shifted
     * pre-Buttercup boundary; pin it explicitly rather than by coincidence. */
    crs_push_triple(out, cap, &n, consensus_last_founders_reward_height(p),
                    max_h, &overflow);

    /* (3) every upgrade activation height +/- 1, including slots that are
     * disabled today — a disabled slot that acquires a height is exactly the
     * change this sweep exists to notice. */
    for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
        int32_t a = p->vUpgrades[i].nActivationHeight;
        if (a == NETWORK_UPGRADE_NO_ACTIVATION)
            continue;
        crs_push_triple(out, cap, &n, a, max_h, &overflow);
    }

    /* (4) tip .. tip+horizon at the stride, with a dense band around each
     * stride point. This is the FORWARD reach — the part no replay can do.
     * When the bands touch or overlap (2*band+1 >= stride) the sampled set IS
     * the contiguous range, so emit it once: that keeps `--stride=1` (the
     * exhaustive forward sweep) from pushing 9 duplicates per height and
     * hitting CRS_ERR_CAPACITY on a vector that actually fits. */
    const int64_t lo = (int64_t)cfg->tip - cfg->band;
    const int64_t hi = (int64_t)cfg->tip + cfg->horizon + cfg->band;
    if ((int64_t)2 * cfg->band + 1 >= cfg->stride) {
        for (int64_t h = lo; h <= hi; h++)
            crs_push(out, cap, &n, h, max_h, &overflow);
    } else {
        for (int64_t s = cfg->tip; s <= (int64_t)cfg->tip + cfg->horizon;
             s += cfg->stride) {
            for (int32_t d = -cfg->band; d <= cfg->band; d++)
                crs_push(out, cap, &n, s + d, max_h, &overflow);
        }
    }

    if (overflow)
        return CRS_ERR_CAPACITY;

    qsort(out, n, sizeof(out[0]), crs_cmp_i32);

    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (w == 0 || out[w - 1] != out[i])
            out[w++] = out[i];
    }
    *out_n = w;
    return CRS_OK;
}

/* ── per-height evaluation ────────────────────────────────────────────────*/

static inline void crs_eval_row(const struct chain_params *cp, int32_t height,
                                const uint8_t checkpoint_digest[32],
                                struct crs_row *row)
{
    const struct consensus_params *p = &cp->consensus;
    memset(row, 0, sizeof(*row));
    row->height = height;

    int64_t subsidy = 0;
    struct zcl_result r = domain_consensus_block_subsidy(height, p, &subsidy);
    row->subsidy_ok = r.ok ? 1u : 0u;
    row->subsidy_code = r.code;
    row->subsidy = r.ok ? subsidy : 0;

    row->halvings = consensus_halving(p, height);

    /* The FULL bitmask over every declared slot, disabled ones included: the
     * loop bound is MAX_NETWORK_UPGRADES, never "the slots with a height". */
    for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
        if (consensus_network_upgrade_active(p, height, (enum upgrade_index)i))
            row->upgrade_active_mask |= (uint64_t)1 << i;
        enum upgrade_state st = consensus_upgrade_state(height, p,
                                                        (enum upgrade_index)i);
        row->upgrade_state_packed |= ((uint64_t)(st & 0x3)) << (2 * i);
    }

    row->epoch = consensus_current_epoch(height, p);
    row->branch_id = consensus_current_epoch_branch_id(height, p);
    row->equihash_n = chain_params_equihash_n(cp, height);
    row->equihash_k = chain_params_equihash_k(cp, height);
    memcpy(row->pow_limit, p->powLimit.data, sizeof(row->pow_limit));
    row->target_spacing = consensus_pow_target_spacing(p, height);
    row->averaging_window_timespan =
        consensus_averaging_window_timespan(p, height);
    row->min_actual_timespan = consensus_min_actual_timespan(p, height);
    row->max_actual_timespan = consensus_max_actual_timespan(p, height);
    row->max_block_size = crs_max_block_size(height);
    row->max_tx_size_after_sapling = crs_max_tx_size_after_sapling(height);
    memcpy(row->checkpoint_digest, checkpoint_digest,
           sizeof(row->checkpoint_digest));
}

static inline void crs_absorb_row(struct sha3_256_ctx *ctx,
                                  const struct crs_row *row)
{
    crs_absorb_i32(ctx, row->height);
    crs_absorb_i64(ctx, row->subsidy);
    crs_absorb_u8(ctx, row->subsidy_ok);
    crs_absorb_i32(ctx, row->subsidy_code);
    crs_absorb_i32(ctx, row->halvings);
    crs_absorb_u64(ctx, row->upgrade_active_mask);
    crs_absorb_u64(ctx, row->upgrade_state_packed);
    crs_absorb_i32(ctx, row->epoch);
    crs_absorb_u32(ctx, row->branch_id);
    crs_absorb_u32(ctx, row->equihash_n);
    crs_absorb_u32(ctx, row->equihash_k);
    sha3_256_write(ctx, row->pow_limit, sizeof(row->pow_limit));
    crs_absorb_i64(ctx, row->target_spacing);
    crs_absorb_i64(ctx, row->averaging_window_timespan);
    crs_absorb_i64(ctx, row->min_actual_timespan);
    crs_absorb_i64(ctx, row->max_actual_timespan);
    crs_absorb_u64(ctx, row->max_block_size);
    crs_absorb_u64(ctx, row->max_tx_size_after_sapling);
    sha3_256_write(ctx, row->checkpoint_digest, sizeof(row->checkpoint_digest));
}

/* Height-invariant part of the preimage: the sweep vector's own definition
 * plus every compiled parameter the per-height functions read. Binding the
 * vector definition into the digest is what makes two digests comparable ONLY
 * when they described the same question. */
static inline void crs_absorb_header(struct sha3_256_ctx *ctx,
                                     const struct crs_config *cfg,
                                     const struct chain_params *cp,
                                     uint64_t rows)
{
    const struct consensus_params *p = &cp->consensus;

    crs_absorb_bytes(ctx, CRS_DOMAIN, sizeof(CRS_DOMAIN));
    crs_absorb_bytes(ctx, cp->strNetworkID, strlen(cp->strNetworkID));
    crs_absorb_bytes(ctx, cp->strCurrencyUnits, strlen(cp->strCurrencyUnits));
    crs_absorb_i64(ctx, cfg->tip);
    crs_absorb_i64(ctx, cfg->horizon);
    crs_absorb_i64(ctx, cfg->stride);
    crs_absorb_i64(ctx, cfg->band);
    crs_absorb_i64(ctx, CRS_LOW_DENSE_MAX);
    crs_absorb_u64(ctx, rows);
    crs_absorb_u32(ctx, (uint32_t)MAX_NETWORK_UPGRADES);

    crs_absorb_u8(ctx, p->fCoinbaseMustBeProtected ? 1u : 0u);
    crs_absorb_i32(ctx, p->nSubsidySlowStartInterval);
    crs_absorb_i32(ctx, consensus_subsidy_slow_start_shift(p));
    crs_absorb_i32(ctx, p->nPreButtercupSubsidyHalvingInterval);
    crs_absorb_i32(ctx, p->nPostButtercupSubsidyHalvingInterval);
    crs_absorb_i32(ctx, consensus_last_founders_reward_height(p));
    crs_absorb_i32(ctx, p->nMajorityEnforceBlockUpgrade);
    crs_absorb_i32(ctx, p->nMajorityRejectBlockOutdated);
    crs_absorb_i32(ctx, p->nMajorityWindow);
    sha3_256_write(ctx, p->powLimit.data, sizeof(p->powLimit.data));
    crs_absorb_i32(ctx, p->nPowAllowMinDifficultyBlocksAfterHeight);
    crs_absorb_u8(ctx, p->nPowAllowMinDifficultyEnabled ? 1u : 0u);
    crs_absorb_u8(ctx, p->scaleDifficultyAtUpgradeFork ? 1u : 0u);
    crs_absorb_i64(ctx, p->nPowAveragingWindow);
    crs_absorb_i64(ctx, p->nPowMaxAdjustDown);
    crs_absorb_i64(ctx, p->nPowMaxAdjustUp);
    crs_absorb_i64(ctx, p->nPreButtercupPowTargetSpacing);
    crs_absorb_i64(ctx, p->nPostButtercupPowTargetSpacing);
    sha3_256_write(ctx, p->nMinimumChainWork.data,
                   sizeof(p->nMinimumChainWork.data));
    sha3_256_write(ctx, p->hashGenesisBlock.data,
                   sizeof(p->hashGenesisBlock.data));

    /* The activation schedule itself — every slot, disabled ones included, so
     * a slot flipping from NETWORK_UPGRADE_NO_ACTIVATION to a real height is
     * visible even when no swept height crosses it. */
    for (int i = 0; i < MAX_NETWORK_UPGRADES; i++) {
        crs_absorb_i32(ctx, p->vUpgrades[i].nActivationHeight);
        crs_absorb_i32(ctx, p->vUpgrades[i].nProtocolVersion);
        crs_absorb_u32(ctx, NetworkUpgradeInfo[i].nBranchId);
        crs_absorb_u32(ctx, EquihashUpgradeInfo[i].N);
        crs_absorb_u32(ctx, EquihashUpgradeInfo[i].K);
    }

    crs_absorb_u32(ctx, cp->nEquihashN);
    crs_absorb_u32(ctx, cp->nEquihashK);
    crs_absorb_i32(ctx, cp->nDefaultPort);
    crs_absorb_u64(ctx, cp->nPruneAfterHeight);
    crs_absorb_bytes(ctx, cp->pchMessageStart, sizeof(cp->pchMessageStart));
    crs_absorb_u64(ctx, (uint64_t)cp->nFoundersRewardAddresses);
    for (size_t i = 0; i < cp->nFoundersRewardAddresses &&
                       i < MAX_FOUNDERS_ADDRESSES; i++)
        crs_absorb_bytes(ctx, cp->vFoundersRewardAddress[i],
                         strlen(cp->vFoundersRewardAddress[i]));

    crs_absorb_u64(ctx, crs_max_block_size(0));
    crs_absorb_u64(ctx, crs_max_tx_size_after_sapling(0));
    crs_absorb_u32(ctx, (uint32_t)MAX_BLOCK_SIGOPS);
    crs_absorb_u32(ctx, (uint32_t)MAX_TX_SIZE_BEFORE_SAPLING);
    crs_absorb_u32(ctx, (uint32_t)COINBASE_MATURITY);
    crs_absorb_u32(ctx, (uint32_t)MIN_BLOCK_VERSION);
    crs_absorb_u32(ctx, (uint32_t)TX_EXPIRY_HEIGHT_THRESHOLD);
}

/* Run the whole sweep and produce the digest.
 *
 * `hook` (may be NULL) is applied to each row after evaluation and before the
 * fold — the fail-arm seam. `sink` (may be NULL) receives each row after the
 * hook, for --verbose. `heights` is caller-owned scratch of `cap` entries; the
 * engine never allocates. */
static inline enum crs_status crs_run(const struct crs_config *cfg,
                                      const struct chain_params *cp,
                                      int32_t *heights, size_t cap,
                                      crs_row_hook hook, void *hook_ctx,
                                      crs_row_sink sink, void *sink_ctx,
                                      uint8_t out_digest[32], size_t *out_rows)
{
    if (!cfg || !cp || !heights || !out_digest)
        return CRS_ERR_NULL;
    if (out_rows)
        *out_rows = 0;

    size_t n = 0;
    enum crs_status st = crs_build_vector(cfg, cp, heights, cap, &n);
    if (st != CRS_OK)
        return st;

    uint8_t ckpt[32];
    crs_checkpoint_table_digest(cp, ckpt);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    crs_absorb_header(&ctx, cfg, cp, (uint64_t)n);

    for (size_t i = 0; i < n; i++) {
        struct crs_row row;
        crs_eval_row(cp, heights[i], ckpt, &row);
        if (hook)
            hook(&row, hook_ctx);
        if (sink)
            sink(&row, sink_ctx);
        crs_absorb_row(&ctx, &row);
    }

    sha3_256_finalize(&ctx, out_digest);
    if (out_rows)
        *out_rows = n;
    return CRS_OK;
}

static inline const char *crs_status_str(enum crs_status st)
{
    switch (st) {
    case CRS_OK:             return "ok";
    case CRS_ERR_BAD_CONFIG: return "sweep parameter out of range";
    case CRS_ERR_CAPACITY:   return "sweep vector exceeds the height buffer";
    case CRS_ERR_NULL:       return "null argument";
    }
    return "unknown";
}

#endif /* ZCL_TOOLS_CONSENSUS_RULE_SWEEP_H */
