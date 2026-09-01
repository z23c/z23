/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Park shielded-history retries only while the selected block and all
 * three durable completeness markers remain exactly unchanged. */

#include "jobs/utxo_apply_history_hold.h"

#include "core/uint256.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "util/blocker.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct history_hold_markers {
    int64_t sprout_cursor;
    int64_t sapling_cursor;
    int64_t nullifier_cursor;
    bool sprout_found;
    bool sapling_found;
    bool nullifier_found;
};

struct history_hold_key {
    bool active;
    int height;
    int kind; /* 1=nullifier, 2=anchor */
    struct uint256 block_hash;
    struct history_hold_markers markers;
};

static pthread_mutex_t g_history_hold_lock = PTHREAD_MUTEX_INITIALIZER;
static struct history_hold_key g_history_hold;

static void stale_upstream_hash_blocker_set(int height)
{
    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d selected block changed while one or more upstream "
             "proof/script receipts remain hashless; utxo_apply holds until "
             "both stages bind receipts to the selected block hash",
             height);
    if (blocker_init(&rec, UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID,
                     "utxo_apply", BLOCKER_DEPENDENCY, reason)) {
        snprintf(rec.escape_action, sizeof(rec.escape_action),
                 "re-run script_validate and proof_validate for selected hash");
        (void)blocker_set(&rec);
    }
}

static bool markers_read(sqlite3 *db, struct history_hold_markers *markers)
{
    if (!db || !markers)
        return false;
    memset(markers, 0, sizeof(*markers));
    return anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SPROUT, &markers->sprout_cursor,
               &markers->sprout_found) &&
           anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SAPLING, &markers->sapling_cursor,
               &markers->sapling_found) &&
           nullifier_kv_activation_cursor(
               db, &markers->nullifier_cursor, &markers->nullifier_found);
}

static bool markers_equal(const struct history_hold_markers *a,
                          const struct history_hold_markers *b)
{
    return a->sprout_cursor == b->sprout_cursor &&
           a->sapling_cursor == b->sapling_cursor &&
           a->nullifier_cursor == b->nullifier_cursor &&
           a->sprout_found == b->sprout_found &&
           a->sapling_found == b->sapling_found &&
           a->nullifier_found == b->nullifier_found;
}

void utxo_apply_history_hold_clear(void)
{
    pthread_mutex_lock(&g_history_hold_lock);
    memset(&g_history_hold, 0, sizeof(g_history_hold));
    pthread_mutex_unlock(&g_history_hold_lock);
    blocker_clear(UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID);
}

bool utxo_apply_history_hold_active(void)
{
    pthread_mutex_lock(&g_history_hold_lock);
    bool active = g_history_hold.active;
    pthread_mutex_unlock(&g_history_hold_lock);
    return active;  // raw-return-ok:state-query-can-be-inactive
}

bool utxo_apply_history_hold_should_park(
    sqlite3 *db, int height, const struct uint256 *block_hash,
    bool proof_has_hash, const struct uint256 *proof_hash,
    bool script_has_hash, const struct uint256 *script_hash)
{
    if (!utxo_apply_history_hold_active())
        return false;  // raw-return-ok:no-active-history-memo
    int kind = 0;
    enum utxo_apply_history_hold_state state = utxo_apply_history_hold_check(
        db, height, block_hash, &kind);
    if (state == UTXO_HISTORY_HOLD_BLOCK_CHANGED) {
        /* Height-keyed rows are not authority for a new branch. Keep parking
         * until both upstream stages bind their receipts to the selected
         * hash; only then clear the old memo and permit one full reread. */
        bool proof_bound = proof_has_hash && proof_hash &&
                           uint256_eq(proof_hash, block_hash);
        bool script_bound = script_has_hash && script_hash &&
                            uint256_eq(script_hash, block_hash);
        if (proof_bound && script_bound) {
            utxo_apply_history_hold_clear();
            return false;
        }
        const char *causal_id = kind == 1 ? UTXO_APPLY_NF_GAP_BLOCKER_ID
                                         : UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID;
        if (blocker_exists(causal_id))
            return true;
        /* A present foreign hash is handled by the unconditional typed
         * mismatch gate in step_apply. A hashless legacy receipt cannot prove
         * authority for the replacement branch, so keep the cursor parked
         * here under an explicit dependency blocker. */
        if (!proof_has_hash || !proof_hash || !script_has_hash || !script_hash) {
            stale_upstream_hash_blocker_set(height);
            return true;
        }
        blocker_clear(UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID);
        return false;
    }
    if (state == UTXO_HISTORY_HOLD_MATCHES) {
        const char *id = kind == 1 ? UTXO_APPLY_NF_GAP_BLOCKER_ID
                                   : UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID;
        if (blocker_exists(id))
            return true;
        utxo_apply_history_hold_clear();
    } else if (state == UTXO_HISTORY_HOLD_ERROR) {
        /* Do not preserve a stale fast-path park on store ambiguity. The
         * normal shielded gate rereads and fails closed if the body needs the
         * unavailable marker. */
        utxo_apply_history_hold_clear();
    } else if (state == UTXO_HISTORY_HOLD_CHANGED) {
        blocker_clear(UTXO_APPLY_STALE_UPSTREAM_HASH_BLOCKER_ID);
    }
    return false;
}

enum utxo_apply_history_hold_state utxo_apply_history_hold_check(
    sqlite3 *db, int height, const struct uint256 *block_hash, int *kind_out)
{
    if (!block_hash || !kind_out)
        return UTXO_HISTORY_HOLD_ERROR;
    struct history_hold_markers markers;
    if (!markers_read(db, &markers))
        return UTXO_HISTORY_HOLD_ERROR;

    pthread_mutex_lock(&g_history_hold_lock);
    enum utxo_apply_history_hold_state state = UTXO_HISTORY_HOLD_CHANGED;
    if (g_history_hold.active && g_history_hold.height == height &&
        !uint256_eq(&g_history_hold.block_hash, block_hash)) {
        state = UTXO_HISTORY_HOLD_BLOCK_CHANGED;
        *kind_out = g_history_hold.kind;
    } else if (g_history_hold.active && g_history_hold.height == height &&
               markers_equal(&g_history_hold.markers, &markers)) {
        state = UTXO_HISTORY_HOLD_MATCHES;
        *kind_out = g_history_hold.kind;
    } else {
        memset(&g_history_hold, 0, sizeof(g_history_hold));
    }
    pthread_mutex_unlock(&g_history_hold_lock);
    return state;
}

bool utxo_apply_history_hold_record(sqlite3 *db, int height, int kind,
                                    const struct uint256 *block_hash)
{
    struct history_hold_markers markers;
    if (!block_hash || (kind != 1 && kind != 2) ||
        !markers_read(db, &markers)) {
        utxo_apply_history_hold_clear();
        return false;
    }
    pthread_mutex_lock(&g_history_hold_lock);
    g_history_hold.active = true;
    g_history_hold.height = height;
    g_history_hold.kind = kind;
    g_history_hold.block_hash = *block_hash;
    g_history_hold.markers = markers;
    pthread_mutex_unlock(&g_history_hold_lock);
    return true;
}
