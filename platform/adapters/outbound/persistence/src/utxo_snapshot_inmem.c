/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton */

#define _POSIX_C_SOURCE 200809L

#include "adapters/outbound/persistence/utxo_snapshot_inmem.h"

#include "crypto/sha3.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>  /* ssize_t */

/* ── coin storage ────────────────────────────────────────────────
 * Internal `coin_entry` is the owning record: we deep-copy the
 * script_pubkey on insert so the snapshot has stable storage
 * independent of caller lifetimes. */

struct coin_entry {
    struct utxo_outpoint op;
    uint64_t value_zat;
    uint32_t height;
    bool is_coinbase;
    uint8_t *script_pubkey;
    uint32_t script_pubkey_len;
};

/* ── undo log ────────────────────────────────────────────────────
 * Each apply_diff appends one frame to the undo log. revert_tip
 * pops the latest frame and reverses its operations: re-insert the
 * coins it spent (we kept full copies) and delete the coins it
 * created. */

struct undo_frame {
    uint32_t target_height;
    struct block_hash target_block;
    struct coin_entry *reinserts;    /* coins to re-insert on revert */
    size_t reinserts_len;
    struct utxo_outpoint *delete_ops;   /* outpoints to delete on revert */
    size_t deletes_len;
};

struct utxo_snapshot_inmem {
    pthread_mutex_t mu;

    struct coin_entry *coins;
    size_t coins_len;
    size_t coins_cap;

    struct undo_frame *undo;
    size_t undo_len;
    size_t undo_cap;

    uint32_t tip_height;
    struct block_hash tip_hash;
    bool has_tip;
};

/* ── helpers ─────────────────────────────────────────────────────*/

static int outpoint_cmp_inmem(const struct utxo_outpoint *a,
                              const struct utxo_outpoint *b)
{
    int c = memcmp(a->txid, b->txid, 32);
    if (c != 0) return c;
    if (a->vout < b->vout) return -1;
    if (a->vout > b->vout) return 1;
    return 0;
}

static ssize_t coins_find(struct utxo_snapshot_inmem *h,
                          const struct utxo_outpoint *op)
{
    /* Linear scan — fine for tests and ~1000 outpoints. A future
     * commit can drop a hashmap in front of this; the port surface
     * is unchanged. */
    for (size_t i = 0; i < h->coins_len; i++) {
        if (outpoint_cmp_inmem(&h->coins[i].op, op) == 0)
            return (ssize_t)i;
    }
    return -1;
}

static struct zcl_result coins_reserve(struct utxo_snapshot_inmem *h,
                                       size_t need)
{
    if (need <= h->coins_cap) return ZCL_OK;
    size_t cap = h->coins_cap ? h->coins_cap : 16;
    while (cap < need) cap *= 2;
    struct coin_entry *p = realloc(h->coins, cap * sizeof(*p));
    if (!p) return ZCL_ERR(UTXO_ERR_IO, "coins_reserve: realloc");
    h->coins = p;
    h->coins_cap = cap;
    return ZCL_OK;
}

static struct zcl_result undo_reserve(struct utxo_snapshot_inmem *h,
                                      size_t need)
{
    if (need <= h->undo_cap) return ZCL_OK;
    size_t cap = h->undo_cap ? h->undo_cap : 8;
    while (cap < need) cap *= 2;
    struct undo_frame *p = realloc(h->undo, cap * sizeof(*p));
    if (!p) return ZCL_ERR(UTXO_ERR_IO, "undo_reserve: realloc");
    h->undo = p;
    h->undo_cap = cap;
    return ZCL_OK;
}

static void coin_entry_release(struct coin_entry *e)
{
    free(e->script_pubkey);
    e->script_pubkey = NULL;
    e->script_pubkey_len = 0;
}

static struct zcl_result coin_entry_dup(struct coin_entry *dst,
                                        const struct utxo_outpoint *op,
                                        const struct utxo_coin *coin)
{
    dst->op = *op;
    dst->value_zat = coin->value_zat;
    dst->height = coin->height;
    dst->is_coinbase = coin->is_coinbase;
    dst->script_pubkey = NULL;
    dst->script_pubkey_len = 0;
    if (coin->script_pubkey_len > 0) {
        dst->script_pubkey = malloc(coin->script_pubkey_len);
        if (!dst->script_pubkey)
            return ZCL_ERR(UTXO_ERR_IO, "coin_dup: malloc spk");
        memcpy(dst->script_pubkey, coin->script_pubkey, coin->script_pubkey_len);
        dst->script_pubkey_len = coin->script_pubkey_len;
    }
    return ZCL_OK;
}

static void coins_remove_at(struct utxo_snapshot_inmem *h, size_t idx)
{
    coin_entry_release(&h->coins[idx]);
    /* Compact tail down to fill the gap. */
    if (idx + 1 < h->coins_len) {
        memmove(&h->coins[idx], &h->coins[idx + 1],
                (h->coins_len - idx - 1) * sizeof(struct coin_entry));
    }
    h->coins_len--;
}

/* ── port callbacks ──────────────────────────────────────────────*/

static struct zcl_result inmem_lookup(void *self_v,
                                      const struct utxo_outpoint *op,
                                      struct utxo_coin *coin_out)
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return ZCL_ERR(UTXO_ERR_IO, "lookup: null self");
    pthread_mutex_lock(&h->mu);
    ssize_t i = coins_find(h, op);
    if (i < 0) {
        pthread_mutex_unlock(&h->mu);
        return ZCL_ERR(UTXO_ERR_NOT_FOUND, "lookup: outpoint absent");
    }
    if (coin_out) {
        const struct coin_entry *e = &h->coins[i];
        coin_out->value_zat = e->value_zat;
        coin_out->height = e->height;
        coin_out->is_coinbase = e->is_coinbase;
        coin_out->script_pubkey_len = e->script_pubkey_len;
        coin_out->script_pubkey = e->script_pubkey;
    }
    pthread_mutex_unlock(&h->mu);
    return ZCL_OK;
}

static struct zcl_result inmem_apply_diff(void *self_v,
                                          const struct utxo_diff *diff)
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return ZCL_ERR(UTXO_ERR_IO, "apply_diff: null self");
    if (!diff || !diff->target_block)
        return ZCL_ERR(UTXO_ERR_IO, "apply_diff: null arg(s)");

    pthread_mutex_lock(&h->mu);

    /* Tip continuity: target_height must be tip+1 (or 0 if empty). */
    uint32_t expected = h->has_tip ? h->tip_height + 1 : 0;
    if (diff->target_height != expected) {
        pthread_mutex_unlock(&h->mu);
        return ZCL_ERR(UTXO_ERR_TIP_MISMATCH,
                       "apply_diff: target_height=%u, expected=%u",
                       diff->target_height, expected);
    }

    /* Validate spends exist; collect indices for removal AND copy the
     * coins into the undo frame's reinserts BEFORE we mutate. */
    struct coin_entry *reinserts = NULL;
    ssize_t *spend_idx = NULL;
    if (diff->spends_len > 0) {
        reinserts = calloc(diff->spends_len, sizeof(*reinserts));
        spend_idx = calloc(diff->spends_len, sizeof(*spend_idx));
        if (!reinserts || !spend_idx) {
            free(reinserts); free(spend_idx);
            pthread_mutex_unlock(&h->mu);
            return ZCL_ERR(UTXO_ERR_IO, "apply_diff: alloc undo arrays");
        }
        for (size_t i = 0; i < diff->spends_len; i++) {
            ssize_t k = coins_find(h, &diff->spends[i]);
            if (k < 0) {
                /* Undo any reinserts we already prepared. */
                for (size_t j = 0; j < i; j++)
                    coin_entry_release(&reinserts[j]);
                free(reinserts); free(spend_idx);
                pthread_mutex_unlock(&h->mu);
                return ZCL_ERR(UTXO_ERR_UNKNOWN_OUTPOINT,
                               "apply_diff: spends[%zu] unknown", i);
            }
            spend_idx[i] = k;
            /* Deep copy so revert can restore the script_pubkey. */
            struct utxo_coin tmp = {
                .value_zat = h->coins[k].value_zat,
                .height = h->coins[k].height,
                .is_coinbase = h->coins[k].is_coinbase,
                .script_pubkey_len = h->coins[k].script_pubkey_len,
                .script_pubkey = h->coins[k].script_pubkey,
            };
            struct zcl_result rc = coin_entry_dup(&reinserts[i],
                                                   &diff->spends[i], &tmp);
            if (!rc.ok) {
                for (size_t j = 0; j < i; j++)
                    coin_entry_release(&reinserts[j]);
                free(reinserts); free(spend_idx);
                pthread_mutex_unlock(&h->mu);
                return rc;
            }
        }
    }

    /* Validate creates don't collide with existing UTXOs. */
    for (size_t i = 0; i < diff->creates_len; i++) {
        if (coins_find(h, &diff->creates[i]) >= 0) {
            for (size_t j = 0; j < diff->spends_len; j++)
                coin_entry_release(&reinserts[j]);
            free(reinserts); free(spend_idx);
            pthread_mutex_unlock(&h->mu);
            return ZCL_ERR(UTXO_ERR_DOUBLE_SPEND,
                           "apply_diff: creates[%zu] collides", i);
        }
    }

    /* Reserve undo frame. */
    struct zcl_result r = undo_reserve(h, h->undo_len + 1);
    if (!r.ok) {
        for (size_t j = 0; j < diff->spends_len; j++)
            coin_entry_release(&reinserts[j]);
        free(reinserts); free(spend_idx);
        pthread_mutex_unlock(&h->mu);
        return r;
    }

    /* Reserve coins for creates (we'll deep-copy in). */
    r = coins_reserve(h, h->coins_len + diff->creates_len);
    if (!r.ok) {
        for (size_t j = 0; j < diff->spends_len; j++)
            coin_entry_release(&reinserts[j]);
        free(reinserts); free(spend_idx);
        pthread_mutex_unlock(&h->mu);
        return r;
    }

    /* Allocate delete_ops list for undo (outpoints of the new creates). */
    struct utxo_outpoint *delete_ops = NULL;
    if (diff->creates_len > 0) {
        delete_ops = calloc(diff->creates_len, sizeof(*delete_ops));
        if (!delete_ops) {
            for (size_t j = 0; j < diff->spends_len; j++)
                coin_entry_release(&reinserts[j]);
            free(reinserts); free(spend_idx);
            pthread_mutex_unlock(&h->mu);
            return ZCL_ERR(UTXO_ERR_IO, "apply_diff: alloc delete_ops");
        }
        memcpy(delete_ops, diff->creates,
               diff->creates_len * sizeof(*delete_ops));
    }

    /* All checks passed. Now perform the mutations. Remove spends in
     * descending index order so indices stay valid as we compact. */
    if (diff->spends_len > 1) {
        /* Sort spend_idx descending so each removal doesn't shift
         * later indices. */
        for (size_t i = 0; i + 1 < diff->spends_len; i++) {
            for (size_t j = i + 1; j < diff->spends_len; j++) {
                if (spend_idx[j] > spend_idx[i]) {
                    ssize_t t = spend_idx[i]; spend_idx[i] = spend_idx[j];
                    spend_idx[j] = t;
                }
            }
        }
    }
    for (size_t i = 0; i < diff->spends_len; i++)
        coins_remove_at(h, (size_t)spend_idx[i]);
    free(spend_idx);

    /* Add creates (deep copy). */
    for (size_t i = 0; i < diff->creates_len; i++) {
        struct coin_entry e = {0};
        r = coin_entry_dup(&e, &diff->creates[i], &diff->creates_coin[i]);
        if (!r.ok) {
            /* Partial state — best we can do is leave it; the caller
             * has already received an OOM and will likely tear down. */
            for (size_t j = 0; j < diff->spends_len; j++)
                coin_entry_release(&reinserts[j]);
            free(reinserts); free(delete_ops);
            pthread_mutex_unlock(&h->mu);
            return r;
        }
        h->coins[h->coins_len++] = e;
    }

    /* Commit undo frame + tip. */
    struct undo_frame *frame = &h->undo[h->undo_len++];
    frame->target_height = diff->target_height;
    frame->target_block = *diff->target_block;
    frame->reinserts = reinserts;
    frame->reinserts_len = diff->spends_len;
    frame->delete_ops = delete_ops;
    frame->deletes_len = diff->creates_len;

    h->tip_height = diff->target_height;
    h->tip_hash = *diff->target_block;
    h->has_tip = true;

    pthread_mutex_unlock(&h->mu);
    return ZCL_OK;
}

static struct zcl_result inmem_revert_tip(void *self_v,
                                          uint32_t expected_height)
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return ZCL_ERR(UTXO_ERR_IO, "revert_tip: null self");
    pthread_mutex_lock(&h->mu);
    if (!h->has_tip) {
        pthread_mutex_unlock(&h->mu);
        return ZCL_ERR(UTXO_ERR_TIP_MISMATCH,
                       "revert_tip: snapshot empty");
    }
    if (h->tip_height != expected_height) {
        pthread_mutex_unlock(&h->mu);
        return ZCL_ERR(UTXO_ERR_TIP_MISMATCH,
                       "revert_tip: tip=%u, expected=%u",
                       h->tip_height, expected_height);
    }
    struct undo_frame *frame = &h->undo[h->undo_len - 1];

    /* Delete the coins this frame created. */
    for (size_t i = 0; i < frame->deletes_len; i++) {
        ssize_t k = coins_find(h, &frame->delete_ops[i]);
        if (k >= 0) coins_remove_at(h, (size_t)k);
    }
    /* Re-insert the coins this frame spent. The reinserts already
     * own deep copies; just move them in. */
    struct zcl_result r = coins_reserve(h, h->coins_len + frame->reinserts_len);
    if (!r.ok) {
        pthread_mutex_unlock(&h->mu);
        return r;
    }
    for (size_t i = 0; i < frame->reinserts_len; i++) {
        h->coins[h->coins_len++] = frame->reinserts[i];
    }
    /* Release frame metadata; the reinserted coins are now owned by
     * h->coins so we don't free their script_pubkeys. */
    free(frame->reinserts);
    free(frame->delete_ops);
    h->undo_len--;

    if (h->undo_len == 0) {
        h->has_tip = false;
        h->tip_height = 0;
        memset(&h->tip_hash, 0, sizeof h->tip_hash);
    } else {
        struct undo_frame *prev = &h->undo[h->undo_len - 1];
        h->tip_height = prev->target_height;
        h->tip_hash = prev->target_block;
    }
    pthread_mutex_unlock(&h->mu);
    return ZCL_OK;
}

static uint32_t inmem_tip_height(void *self_v)
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return UINT32_MAX;
    pthread_mutex_lock(&h->mu);
    uint32_t r = h->has_tip ? h->tip_height : UINT32_MAX;
    pthread_mutex_unlock(&h->mu);
    return r;
}

static void inmem_tip_hash(void *self_v, struct block_hash *out)
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return;
    pthread_mutex_lock(&h->mu);
    if (out) *out = h->tip_hash;
    pthread_mutex_unlock(&h->mu);
}

/* Compare two coin_entry by outpoint, for sorting. */
static int coin_entry_cmp(const void *a_v, const void *b_v)
{
    const struct coin_entry *a = a_v;
    const struct coin_entry *b = b_v;
    return outpoint_cmp_inmem(&a->op, &b->op);
}

static struct zcl_result inmem_sha3_commitment(void *self_v,
                                               uint8_t out_digest[32])
{
    struct utxo_snapshot_inmem *h = self_v;
    if (!h) return ZCL_ERR(UTXO_ERR_IO, "sha3: null self");
    if (!out_digest) return ZCL_ERR(UTXO_ERR_IO, "sha3: null out");
    pthread_mutex_lock(&h->mu);

    /* Sort a temp copy by outpoint for canonical order. */
    struct coin_entry *sorted = NULL;
    if (h->coins_len > 0) {
        sorted = malloc(h->coins_len * sizeof(*sorted));
        if (!sorted) {
            pthread_mutex_unlock(&h->mu);
            return ZCL_ERR(UTXO_ERR_IO, "sha3: alloc sorted");
        }
        memcpy(sorted, h->coins, h->coins_len * sizeof(*sorted));
        qsort(sorted, h->coins_len, sizeof(*sorted), coin_entry_cmp);
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (size_t i = 0; i < h->coins_len; i++) {
        const struct coin_entry *e = &sorted[i];
        sha3_256_write(&ctx, e->op.txid, 32);
        uint8_t buf[16];
        for (int b = 0; b < 4; b++) buf[b]      = (uint8_t)(e->op.vout >> (8 * b));
        for (int b = 0; b < 8; b++) buf[4 + b]  = (uint8_t)(e->value_zat >> (8 * b));
        for (int b = 0; b < 4; b++) buf[12 + b] = (uint8_t)(e->height >> (8 * b));
        sha3_256_write(&ctx, buf, sizeof buf);
        uint8_t flags = e->is_coinbase ? 1 : 0;
        sha3_256_write(&ctx, &flags, 1);
        uint8_t spklen[4];
        for (int b = 0; b < 4; b++) spklen[b] = (uint8_t)(e->script_pubkey_len >> (8 * b));
        sha3_256_write(&ctx, spklen, 4);
        if (e->script_pubkey_len > 0)
            sha3_256_write(&ctx, e->script_pubkey, e->script_pubkey_len);
    }
    sha3_256_finalize(&ctx, out_digest);

    free(sorted);
    pthread_mutex_unlock(&h->mu);
    return ZCL_OK;
}

/* ── open / close ────────────────────────────────────────────────*/

struct zcl_result utxo_snapshot_inmem_open(
        struct utxo_snapshot_inmem **out_handle,
        struct utxo_snapshot_port *out_port)
{
    if (!out_handle || !out_port)
        return ZCL_ERR(UTXO_ERR_IO, "inmem_open: null arg(s)");
    struct utxo_snapshot_inmem *h = calloc(1, sizeof *h);
    if (!h) return ZCL_ERR(UTXO_ERR_IO, "inmem_open: calloc");
    pthread_mutex_init(&h->mu, NULL);

    out_port->self = h;
    out_port->lookup = inmem_lookup;
    out_port->apply_diff = inmem_apply_diff;
    out_port->revert_tip = inmem_revert_tip;
    out_port->tip_height = inmem_tip_height;
    out_port->tip_hash = inmem_tip_hash;
    out_port->sha3_commitment = inmem_sha3_commitment;

    *out_handle = h;
    return ZCL_OK;
}

void utxo_snapshot_inmem_close(struct utxo_snapshot_inmem *h)
{
    if (!h) return;
    for (size_t i = 0; i < h->coins_len; i++)
        coin_entry_release(&h->coins[i]);
    free(h->coins);
    for (size_t i = 0; i < h->undo_len; i++) {
        for (size_t j = 0; j < h->undo[i].reinserts_len; j++)
            coin_entry_release(&h->undo[i].reinserts[j]);
        free(h->undo[i].reinserts);
        free(h->undo[i].delete_ops);
    }
    free(h->undo);
    pthread_mutex_destroy(&h->mu);
    free(h);
}
