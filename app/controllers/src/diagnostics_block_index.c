/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read-only dumpstate helpers for block-index and header-band diagnostics.
 * The registry owns routing and controller state; this file owns the heavier
 * JSON shape for these two main_state-backed dumpers.
 */

#include "controllers/diagnostics_internal.h"
#include "controllers/explorer_internal.h"

#include "chain/chain.h"
#include "jobs/stage_repair.h"
#include "models/database.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "json/json.h"
#include "services/block_index_integrity.h"
#include "services/block_index_loader.h"
#include "services/utxo_recovery_service.h"
#include "sync/sync_planner.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "views/format_helpers.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void diag_push_explorer_index_state_json(struct json_value *out,
                                         struct node_db *ndb)
{
    struct json_value obj = {0};
    sqlite3 *read_db = NULL;

    json_set_object(&obj);
    if (!ndb || !ndb->open || !ndb->db) {
        json_push_kv_str(&obj, "state", "unknown");
        json_push_kv_str(&obj, "reason", "database unavailable");
        json_push_kv(out, "explorer_index_state", &obj);
        json_free(&obj);
        return;
    }

    /* A supervisor stall can trigger this diagnostic automatically. Never
     * run history scans on g_node_db: its serialized connection mutex would
     * queue wallet/custody RPCs behind the diagnostic itself. The private
     * read-only handle sees the same authoritative file without monopolizing
     * the agent interface. Bound writer contention too; UNKNOWN is more
     * truthful than waiting 30 seconds for a debug bundle. */
    const char *datadir = diag_datadir();
    if (!datadir || !datadir[0] ||
        !explorer_open_readonly_db(datadir, &read_db)) {
        json_push_kv_str(&obj, "state", "unknown");
        json_push_kv_str(&obj, "reason", "read-only database unavailable");
        json_push_kv(out, "explorer_index_state", &obj);
        json_free(&obj);
        return;
    }
    sqlite3_busy_timeout(read_db, 250);

    struct explorer_history_validation v;
    int64_t height = sql_query_i64(read_db,
        "SELECT COALESCE(MAX(height),0) FROM blocks");
    explorer_validate_block_history(read_db, height, &v);
    sqlite3_close(read_db);
    json_push_kv_str(&obj, "state", v.usable ? "complete" : "degraded");
    json_push_kv_str(&obj, "reason", v.reason);
    json_push_kv_int(&obj, "height", v.max_height);
    json_push_kv_int(&obj, "blocks", v.block_rows);
    json_push_kv_int(&obj, "missing_heights", v.missing_heights);
    json_push_kv_int(&obj, "first_missing_height", v.first_missing_height);
    json_push_kv_int(&obj, "transactions", v.tx_rows);
    json_push_kv_int(&obj, "tx_outputs", v.tx_output_rows);
    json_push_kv_int(&obj, "integrity_receipts", v.integrity_rows);
    json_push_kv(out, "explorer_index_state", &obj);
    json_free(&obj);
}

static void push_block_status_flags(struct json_value *arr, unsigned nStatus)
{
    /* Lower 3 bits = validity level; the rest are flag bits. */
    static const struct { unsigned mask; const char *name; } flags[] = {
        { BLOCK_HAVE_DATA,    "BLOCK_HAVE_DATA" },
        { BLOCK_HAVE_UNDO,    "BLOCK_HAVE_UNDO" },
        { BLOCK_FAILED_VALID, "BLOCK_FAILED_VALID" },
        { BLOCK_FAILED_CHILD, "BLOCK_FAILED_CHILD" },
        { BLOCK_REVALIDATE_PENDING, "BLOCK_REVALIDATE_PENDING" },
    };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (nStatus & flags[i].mask) {
            struct json_value v = {0};
            json_set_str(&v, flags[i].name);
            json_push_back(arr, &v);
            json_free(&v);
        }
    }
}

static const char *block_validity_level_name(unsigned nStatus)
{
    switch (nStatus & BLOCK_VALID_MASK) {
        case BLOCK_VALID_UNKNOWN:      return "BLOCK_VALID_UNKNOWN";
        case BLOCK_VALID_HEADER:       return "BLOCK_VALID_HEADER";
        case BLOCK_VALID_TREE:         return "BLOCK_VALID_TREE";
        case BLOCK_VALID_TRANSACTIONS: return "BLOCK_VALID_TRANSACTIONS";
        case BLOCK_VALID_CHAIN:        return "BLOCK_VALID_CHAIN";
        case BLOCK_VALID_SCRIPTS:      return "BLOCK_VALID_SCRIPTS";
    }
    return "UNKNOWN";
}

static void push_block_ref(struct json_value *out, const char *prefix,
                           const struct block_index *bi)
{
    char key[64];
    snprintf(key, sizeof(key), "%s_height", prefix);
    json_push_kv_int(out, key, bi ? bi->nHeight : -1);

    snprintf(key, sizeof(key), "%s_hash", prefix);
    if (bi && bi->phashBlock) {
        char hex[65];
        uint256_get_hex(bi->phashBlock, hex);
        json_push_kv_str(out, key, hex);
    } else {
        json_push_kv_str(out, key, "");
    }
}

bool diag_header_band_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("diag", "header_band dump: output is NULL");
    json_set_object(out);

    struct main_state *ms = diag_main_state();
    bool blocker = blocker_exists(HEADER_BAND_BLOCKER_ID);
    json_push_kv_bool(out, "has_main_state", ms != NULL);
    json_push_kv_bool(out, "blocker_recorded", blocker);

    if (!ms) {
        json_push_kv_str(out, "state", blocker ? "blocker_without_state"
                                                : "unknown_no_state");
        json_push_kv_int(out, "remaining_headers", -1);
        return true;
    }

    struct active_chain *chain = &ms->chain_active;
    struct block_index *tip = active_chain_tip(chain);
    const struct block_index *island_root =
        tip ? utxo_recovery_block_ancestry_break(tip) : NULL;
    struct block_index *anchor =
        blocker ? syncsvc_header_band_backfill_anchor(chain) : NULL;

    push_block_ref(out, "active_tip", tip);
    push_block_ref(out, "island_root", island_root);
    push_block_ref(out, "backfill_anchor", anchor);
    json_push_kv_bool(out, "band_open", island_root != NULL);

    int remaining = -1;
    if (island_root && anchor && island_root->nHeight > anchor->nHeight)
        remaining = island_root->nHeight - anchor->nHeight;
    else if (!island_root)
        remaining = 0;
    json_push_kv_int(out, "remaining_headers", remaining);

    const char *state = "healthy";
    if (blocker && island_root && anchor)
        state = "backfilling";
    else if (blocker && island_root)
        state = "blocked_no_anchor";
    else if (blocker && !island_root)
        state = "closing_or_stale_blocker";
    else if (!blocker && island_root)
        state = "derived_band_without_blocker";
    json_push_kv_str(out, "state", state);
    return true;
}

static struct block_index *find_block_index_by_key(struct main_state *ms,
                                                    const char *key,
                                                    const char **source_out)
{
    if (source_out)
        *source_out = "missing";
    if (!ms || !key || !key[0])
        return NULL;

    bool is_num = true;
    for (const char *c = key; *c; c++) {
        if (*c < '0' || *c > '9') {
            is_num = false;
            break;
        }
    }
    if (is_num) {
        int height = atoi(key);
        struct block_index *bi = active_chain_at(&ms->chain_active, height);
        if (bi) {
            if (source_out)
                *source_out = "active_chain";
            return bi;
        }
        if (ms->pindex_best_header &&
            height <= ms->pindex_best_header->nHeight) {
            bi = block_index_get_ancestor(ms->pindex_best_header, height);
            if (bi && source_out)
                *source_out = "best_header_ancestor";
            return bi;
        }
        return NULL;
    }

    if (!zcl_is_hex_string(key, 64))
        return NULL;
    struct uint256 h;
    uint256_set_hex(&h, key);
    struct block_index *bi = block_map_find(&ms->map_block_index, &h);
    if (bi && source_out)
        *source_out = "block_map_hash";
    return bi;
}

bool diag_block_index_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("diag", "block_index dump: output is NULL");

    struct main_state *ms = diag_main_state();
    const char *lookup_source = "missing";
    struct block_index *bi = find_block_index_by_key(ms, key, &lookup_source);
    json_set_object(out);
    bool integrity_degraded = false;
    char integrity_reason[192] = "";
    {
        struct bii_recovery_status status;
        struct json_value integrity = {0};
        bii_get_recovery_status(&status);
        json_set_object(&integrity);
        json_push_kv_str(&integrity, "verdict",
                         bii_verdict_name(status.verdict));
        json_push_kv_str(&integrity, "action",
                         bii_recovery_action_name(status.action));
        json_push_kv_bool(&integrity, "degraded", status.degraded);
        json_push_kv_bool(&integrity, "unsafe_override",
                          status.unsafe_override);
        json_push_kv_int(&integrity, "last_check_unix", status.unix_time);
        if (status.reason[0])
            json_push_kv_str(&integrity, "reason", status.reason);
        json_push_kv(out, "integrity", &integrity);
        json_free(&integrity);
        integrity_degraded = status.degraded;
        snprintf(integrity_reason, sizeof(integrity_reason), "%.*s",
                 (int)sizeof(integrity_reason) - 1,
                 status.reason);
    }

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * app/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed integrity.degraded field above (the
     * block-index-integrity recovery verdict) — no new health logic. */
    {
        diag_push_health(out, !integrity_degraded,
                         integrity_degraded ? integrity_reason : "");
    }

    /* J5 blocks-hydrate per-row quarantine tally (process-monotonic). Global,
     * not per-block, so it is emitted regardless of whether `key` resolved a
     * block_index entry. */
    json_push_kv_int(out, "blocks_hydrate_quarantined",
                     block_index_blocks_hydrate_quarantined());

    /* Lane B3 RUNTIME poisoned-row quarantine tally (process-monotonic): poisoned
     * `blocks` rows purged by stage_repair_quarantine_blocks_row while syncing,
     * distinct from the boot-time blocks-hydrate tally above. Global, not
     * per-block. */
    json_push_kv_int(out, "runtime_row_quarantined",
                     stage_repair_runtime_row_quarantined());

    /* block_index.bin flat per-row PoW-target quarantine tally
     * (process-monotonic). Global, not per-block. */
    json_push_kv_int(out, "flat_row_quarantined",
                     block_index_flat_row_quarantined());

    /* Persisted-FAILED-bit trust reconcile tallies (process-monotonic): FAILED
     * bits stripped below the baked ROM checkpoint, and demoted to lazy
     * revalidation candidates above it (the "stale BLOCK_FAILED_VALID wedges
     * tip" defense). Global, not per-block. */
    json_push_kv_int(out, "failed_bits_stripped_below_checkpoint",
                     block_index_failed_bits_stripped());
    json_push_kv_int(out, "failed_bits_demoted_above_checkpoint",
                     block_index_failed_bits_demoted());

    if (!bi) {
        json_push_kv_bool(out, "found", false);
        json_push_kv_str(out, "key", key ? key : "");
        json_push_kv_str(out, "lookup_source", lookup_source);
        return true;
    }

    /* Snapshot every field we report under cs_main and release before any
     * JSON formatting. A concurrent reorg/restore writer mutates these
     * block_index fields (nStatus/nFile/nDataPos via
     * stage_repair_reducer_frontier.c, pprev/nChainWork via reorg) while
     * holding cs_main, so a lock-free read here can tear the multi-word
     * nChainWork or report a half-updated field set. cs_main is the inner
     * lock relative to the reducer's coins_kv/progress_store tx lock (that
     * lock is always taken first); taking ONLY cs_main here, and never
     * coins_kv while holding it, keeps the established order and cannot form
     * the ABBA cycle the lock-order law guards against. */
    struct {
        int64_t nHeight, nVersion, nTime, nBits, nChainTx, nTx;
        int64_t nFile, nDataPos, nUndoPos, nSequenceId, nStatus;
        bool have_hash, have_prev_hash, on_chain;
        char hash[65], hash_prev[65], chain_work[65];
    } snap = {0};

    if (ms)
        zcl_mutex_lock(&ms->cs_main);
    snap.nHeight = (int64_t)bi->nHeight;
    snap.nVersion = (int64_t)bi->nVersion;
    snap.nTime = (int64_t)bi->nTime;
    snap.nBits = (int64_t)bi->nBits;
    snap.nChainTx = (int64_t)bi->nChainTx;
    snap.nTx = (int64_t)bi->nTx;
    snap.nFile = (int64_t)bi->nFile;
    snap.nDataPos = (int64_t)bi->nDataPos;
    snap.nUndoPos = (int64_t)bi->nUndoPos;
    snap.nSequenceId = (int64_t)bi->nSequenceId;
    snap.nStatus = (int64_t)bi->nStatus;
    if (bi->phashBlock) {
        uint256_get_hex(bi->phashBlock, snap.hash);
        snap.have_hash = true;
    }
    if (bi->pprev && bi->pprev->phashBlock) {
        uint256_get_hex(bi->pprev->phashBlock, snap.hash_prev);
        snap.have_prev_hash = true;
    }
    arith_uint256_get_hex(&bi->nChainWork, snap.chain_work);
    if (ms) {
        struct block_index *at = active_chain_at(&ms->chain_active,
                                                 bi->nHeight);
        snap.on_chain = (at == bi);
        zcl_mutex_unlock(&ms->cs_main);
    }

    json_push_kv_bool(out, "found", true);
    json_push_kv_str(out, "lookup_source", lookup_source);
    json_push_kv_int(out, "nHeight", snap.nHeight);
    json_push_kv_int(out, "nVersion", snap.nVersion);
    json_push_kv_int(out, "nTime", snap.nTime);
    json_push_kv_int(out, "nBits", snap.nBits);
    json_push_kv_int(out, "nChainTx", snap.nChainTx);
    json_push_kv_int(out, "nTx", snap.nTx);
    json_push_kv_int(out, "nFile", snap.nFile);
    json_push_kv_int(out, "nDataPos", snap.nDataPos);
    json_push_kv_int(out, "nUndoPos", snap.nUndoPos);
    json_push_kv_int(out, "nSequenceId", snap.nSequenceId);
    json_push_kv_int(out, "nStatus_raw", snap.nStatus);
    json_push_kv_str(out, "nStatus_validity",
                     block_validity_level_name((unsigned)snap.nStatus));
    {
        struct json_value flags_arr = {0};
        json_set_array(&flags_arr);
        push_block_status_flags(&flags_arr, (unsigned)snap.nStatus);
        json_push_kv(out, "nStatus_flags", &flags_arr);
        json_free(&flags_arr);
    }
    json_push_kv_str(out, "hash", snap.have_hash ? snap.hash : "");
    json_push_kv_str(out, "hash_prev",
                     snap.have_prev_hash ? snap.hash_prev : "");
    json_push_kv_str(out, "nChainWork", snap.chain_work);
    json_push_kv_bool(out, "on_active_chain", snap.on_chain);
    return true;
}
