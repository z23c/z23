/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * nullifier_backfill_service — owner-gated C-3 remediation.
 *
 * This is an explicit owner-gated historical remediation, not a new automatic
 * recovery rung: the producer now writes nullifiers for all forward-applied
 * blocks, but pre-activation datadirs need a one-time populate-only walk.
 * The service replays historical block bodies only far enough to feed the
 * existing utxo_apply nullifier writer, then commits an explicit zero
 * completeness marker when the bounded historical gap has been populated. */
// repair-rung-ok:test_nullifier_backfill_service
// nullifier_backfill_dump_state_json, implements the diagnostics_dump_fn
// typedef (CLAUDE.md "Adding state introspection": `bool
// <name>_dump_state_json(...)`) mandated by the g_dumpers[] dispatch table
// in engine/controllers/src/diagnostics_registry.c; every other dumper in the
// codebase has the same bool signature for the same reason, so this is not
// a candidate for struct zcl_result conversion.

#include "services/nullifier_backfill_service.h"
#include "nullifier_backfill_chain.h"

#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "models/block.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NBF_SUBSYS "nullifier_backfill"

struct nbf_nullifier_entry {
    uint8_t bytes[32];
    int pool;
};

static bool nbf_collect_nullifiers(const struct block *blk,
                                   struct nbf_nullifier_entry **entries_out,
                                   size_t *count_out)
{
    if (entries_out) *entries_out = NULL;
    if (count_out) *count_out = 0;
    if (!blk || !entries_out || !count_out)
        LOG_FAIL(NBF_SUBSYS, "collect_nullifiers: invalid args");
    size_t count = 0;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        if (tx->num_joinsplit > (SIZE_MAX - count) / 2u ||
            tx->num_shielded_spend > SIZE_MAX - count -
                                       tx->num_joinsplit * 2u)
            LOG_FAIL(NBF_SUBSYS, "collect_nullifiers: count overflow");
        count += tx->num_joinsplit * 2u + tx->num_shielded_spend;
    }
    if (count == 0)
        return true;
    struct nbf_nullifier_entry *entries = zcl_calloc(
        count, sizeof(*entries), "nullifier_backfill_entries");
    if (!entries)
        return false;
    size_t at = 0;
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_joinsplit; j++) {
            for (size_t k = 0; k < 2; k++) {
                memcpy(entries[at].bytes,
                       tx->v_joinsplit[j].nullifiers[k].data, 32);
                entries[at++].pool = NULLIFIER_POOL_SPROUT;
            }
        }
        for (size_t j = 0; j < tx->num_shielded_spend; j++) {
            memcpy(entries[at].bytes,
                   tx->v_shielded_spend[j].nullifier.data, 32);
            entries[at++].pool = NULLIFIER_POOL_SAPLING;
        }
    }
    *entries_out = entries;
    *count_out = count;
    return true;
}

static bool nbf_reconcile_preloaded_nullifiers(sqlite3 *db,
                                               const struct block *blk,
                                               int64_t height)
{
    struct nbf_nullifier_entry *entries = NULL;
    size_t count = 0;
    if (!nbf_collect_nullifiers(blk, &entries, &count))
        LOG_RETURN(false, NBF_SUBSYS,
                   "reconcile_preloaded: collect failed h=%lld",
                   (long long)height);
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        for (size_t j = 0; j < i; j++) {
            if (entries[i].pool == entries[j].pool &&
                memcmp(entries[i].bytes, entries[j].bytes, 32) == 0) {
                LOG_WARN(NBF_SUBSYS,
                         "reconcile_preloaded: duplicate within block h=%lld",
                         (long long)height);
                ok = false;
                break;
            }
        }
    }
    for (size_t i = 0; ok && i < count; i++) {
        bool found = false;
        int64_t stored_height = -1;
        if (!nullifier_kv_get(db, entries[i].bytes, entries[i].pool,
                              &found, &stored_height)) {
            ok = false;
            break;
        }
        if (found && stored_height != height) {
            LOG_WARN(NBF_SUBSYS,
                     "reconcile_preloaded: height mismatch want=%lld got=%lld",
                     (long long)height, (long long)stored_height);
            ok = false;
        }
    }
    for (size_t i = 0; ok && i < count; i++) {
        bool found = false;
        if (!nullifier_kv_get(db, entries[i].bytes, entries[i].pool,
                              &found, NULL) ||
            (!found && !nullifier_kv_add(db, entries[i].bytes,
                                         entries[i].pool, height)))
            ok = false;
    }
    free(entries);
    return ok;
}

static bool nbf_parse_i64(const char *buf, int64_t *out)
{
    char *end = NULL;
    long long v;

    if (!buf || !out)
        LOG_FAIL(NBF_SUBSYS, "parse_i64: null arg");
    errno = 0;
    v = strtoll(buf, &end, 10);
    if (end == buf || errno == ERANGE)
        LOG_FAIL(NBF_SUBSYS, "parse_i64: malformed integer '%s'", buf);
    while (end && (*end == ' ' || *end == '\t' ||
                   *end == '\n' || *end == '\r'))
        end++;
    if (end && *end != '\0')
        LOG_FAIL(NBF_SUBSYS, "parse_i64: trailing bytes in '%s'", buf);
    *out = (int64_t)v;
    return true;
}

static struct zcl_result nbf_read_meta_i64(sqlite3 *db, const char *key,
                                           int64_t *out, bool *found)
{
    char buf[32] = {0};
    size_t len = 0;

    if (found)
        *found = false;
    if (out)
        *out = 0;
    if (!db || !key || !out || !found) {
        LOG_WARN(NBF_SUBSYS, "read_meta_i64: invalid args db=%p key=%p",
                 (void *)db, (const void *)key);
        return ZCL_ERR(-1, "read_meta_i64 invalid args");
    }
    progress_store_tx_lock();
    bool got = progress_meta_get(db, key, buf, sizeof(buf) - 1, &len, found);
    progress_store_tx_unlock();
    if (!got) {
        LOG_WARN(NBF_SUBSYS, "read_meta_i64: progress_meta_get failed key=%s",
                 key);
        return ZCL_ERR(-2, "progress_meta_get failed for %s", key);
    }
    if (!*found)
        return ZCL_OK;
    buf[sizeof(buf) - 1] = '\0';
    if (!nbf_parse_i64(buf, out))
        return ZCL_ERR(-3, "malformed progress marker %s=%s", key, buf);
    return ZCL_OK;
}

static bool nbf_tx_begin(sqlite3 *db)
{
    char *err = NULL;

    progress_store_tx_lock();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s", err ? err : sqlite3_errmsg(db));
        if (err)
            sqlite3_free(err);
        progress_store_tx_unlock();
        LOG_RETURN(false, NBF_SUBSYS, "BEGIN IMMEDIATE failed: %s", msg);
    }
    if (err)
        sqlite3_free(err);
    return true;
}

static bool nbf_tx_finish(sqlite3 *db, bool commit)
{
    char *err = NULL;
    const char *sql = commit ? "COMMIT" : "ROLLBACK";
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);

    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s", err ? err : sqlite3_errmsg(db));
        if (err)
            sqlite3_free(err);
        progress_store_tx_unlock();
        LOG_RETURN(false, NBF_SUBSYS, "%s failed: %s", sql, msg);
    }
    if (err)
        sqlite3_free(err);
    progress_store_tx_unlock();
    return true;
}

static bool nbf_set_resume_in_tx(sqlite3 *db, int64_t next_height)
{
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lld", (long long)next_height);

    if (n <= 0 || (size_t)n >= sizeof(buf))
        LOG_FAIL(NBF_SUBSYS, "set_resume: height format failed h=%lld",
                 (long long)next_height);
    if (!progress_meta_set_in_tx(db, NULLIFIER_BACKFILL_RESUME_KEY,
                                 buf, (size_t)n))
        LOG_FAIL(NBF_SUBSYS, "set_resume: progress_meta_set failed h=%lld",
                 (long long)next_height);
    return true;
}

static struct zcl_result nbf_reset_for_generation(
    sqlite3 *db,
    int64_t activation,
    const struct nbf_chain_binding *binding)
{
    bool ok;

    if (!nbf_tx_begin(db))
        return ZCL_ERR(-10, "begin failed while resetting backfill generation");
    ok = nullifier_kv_reset_mark_empty_below_in_tx(db, activation) &&
         progress_meta_delete_in_tx(db, NULLIFIER_BACKFILL_RESUME_KEY);
    if (ok && binding)
        ok = nbf_chain_binding_store_in_tx(db, binding) &&
             nbf_set_resume_in_tx(db, 0);
    else if (ok)
        ok = progress_meta_delete_in_tx(db, NULLIFIER_BACKFILL_CHAIN_KEY);
    if (!ok) {
        (void)nbf_tx_finish(db, false);
        LOG_WARN(NBF_SUBSYS, "reset_for_generation: reset failed");
        return ZCL_ERR(-11, "failed to reset nullifier backfill generation");
    }
    if (!nbf_tx_finish(db, true))
        return ZCL_ERR(-12, "commit failed resetting backfill generation");
    utxo_apply_nullifier_gap_blocker_refresh(db);
    return ZCL_OK;
}

static struct zcl_result nbf_prepare_generation(
    sqlite3 *db,
    int64_t activation,
    const struct nbf_chain_binding *captured,
    bool resume_found,
    int64_t resume,
    int64_t *start_out)
{
    struct nbf_chain_binding stored;
    bool binding_found = false;
    bool binding_valid = false;

    if (!start_out)
        return ZCL_ERR(-13, "prepare_generation missing start output");
    ZCL_CHECK(nbf_chain_binding_read(db, &stored, &binding_found,
                                     &binding_valid));

    if (binding_found && binding_valid &&
        nbf_chain_binding_equal(&stored, captured)) {
        *start_out = resume_found ? resume : 0;
        return ZCL_OK;
    }

    /* Rows without this exact receipt are not evidence, even when they came
     * from a legacy v3 preload: an unbound superset can false-reject a valid
     * selected-chain spend.  Discard every unbound/malformed/mismatched set
     * and deterministically reconstruct it from the selected prefix. */
    LOG_WARN(NBF_SUBSYS,
             "prepare_generation: stale/unproven generation discarded "
             "binding_found=%d binding_valid=%d resume_found=%d",
             binding_found, binding_valid, resume_found);
    ZCL_CHECK(nbf_reset_for_generation(db, activation, captured));
    *start_out = 0;
    return ZCL_OK;
}

static bool nbf_default_read_block(struct block *out, int64_t height,
                                   const char *datadir, void *user,
                                   bool *found_out)
{
    struct node_db *ndb = user;
    struct db_block row;
    struct disk_block_pos pos;

    if (found_out)
        *found_out = false;
    if (!out || !found_out || !ndb || !ndb->open || !datadir)
        LOG_FAIL(NBF_SUBSYS, "read_block: invalid args h=%lld ndb=%p",
                 (long long)height, (void *)ndb);
    if (height < 0 || height > INT_MAX)
        LOG_FAIL(NBF_SUBSYS, "read_block: height out of range h=%lld",
                 (long long)height);
    if (!db_block_find_by_height(ndb, (int)height, &row))
        return true;
    if (row.file_num < 0 || row.data_pos < 0)
        return true;

    disk_block_pos_init(&pos);
    pos.nFile = row.file_num;
    pos.nPos = (unsigned int)row.data_pos;
    if (!read_block_from_disk_pread(out, &pos, datadir))
        return true;
    *found_out = true;
    return true;
}

static struct zcl_result nbf_backfill_one(
    sqlite3 *db,
    const struct block *blk,
    int64_t height)
{
    struct delta_summary summary;
    bool commit = false;

    if (!blk || height < 0 || height > INT_MAX) {
        LOG_WARN(NBF_SUBSYS, "backfill_one: invalid args h=%lld blk=%p",
                 (long long)height, (const void *)blk);
        return ZCL_ERR(-20, "invalid backfill block h=%lld",
                       (long long)height);
    }
    memset(&summary, 0, sizeof(summary));
    summary.ok = true;
    summary.status = "ok";

    if (!nbf_tx_begin(db))
        return ZCL_ERR(-21, "begin failed at height %lld",
                       (long long)height);

    if (!utxo_apply_check_and_insert_nullifiers(db, blk, (int)height,
                                                &summary)) {
        (void)nbf_tx_finish(db, false);
        return ZCL_ERR(-22, "nullifier insert store failure at height %lld",
                       (long long)height);
    }
    if (!summary.ok) {
        if (!summary.status ||
            strcmp(summary.status, "shielded_double_spend") != 0 ||
            !nbf_reconcile_preloaded_nullifiers(db, blk, height)) {
            (void)nbf_tx_finish(db, false);
            return ZCL_ERR(-23, "historical nullifier conflict at height %lld "
                                "kind=%s",
                           (long long)height,
                           summary.failure_kind ? summary.failure_kind :
                                                  "(null)");
        }
    }
    if (!nbf_set_resume_in_tx(db, height + 1)) {
        (void)nbf_tx_finish(db, false);
        return ZCL_ERR(-24, "resume marker write failed at height %lld",
                       (long long)height);
    }
    commit = nbf_tx_finish(db, true);
    if (!commit)
        return ZCL_ERR(-25, "commit failed at height %lld",
                       (long long)height);
    return ZCL_OK;
}

static struct zcl_result nbf_finish_complete(
    const struct nullifier_backfill_config *cfg,
    sqlite3 *db,
    int64_t activation,
    const struct nbf_chain_binding *bound)
{
    bool ok;
    static const char complete[] = "0";
    struct nbf_chain_binding current;
    struct nbf_chain_binding persisted;
    bool persisted_found = false;
    bool persisted_valid = false;

    if (!nbf_tx_begin(db))
        return ZCL_ERR(-30, "begin failed while clearing nullifier gap");
    /* Final compare-and-set.  The canonical reducer lock order is
     * progress_store_tx_lock -> active_chain.write_lock (tip_finalize uses
     * the same edge).  Holding progress here prevents reducer tip publication
     * between this comparison and the durable marker commit.  Owner-gated
     * boot runs this before P2P/runtime services, so no alternate chain writer
     * is live. */
    struct zcl_result capture =
        nbf_chain_binding_capture(cfg, activation, &current);
    struct zcl_result receipt =
        nbf_chain_binding_read(db, &persisted, &persisted_found,
                               &persisted_valid);
    if (!capture.ok || !receipt.ok || !persisted_found || !persisted_valid ||
        !nbf_chain_binding_equal(bound, &current) ||
        !nbf_chain_binding_equal(bound, &persisted)) {
        (void)nbf_tx_finish(db, false);
        LOG_WARN(NBF_SUBSYS,
                 "finish_complete: selected chain changed; discarding run");
        if (capture.ok)
            ZCL_CHECK(nbf_reset_for_generation(db, activation, &current));
        else
            ZCL_CHECK(nbf_reset_for_generation(db, activation, NULL));
        return ZCL_ERR(-33, "selected chain changed during nullifier backfill; "
                            "generation discarded and restart required");
    }
    /* Completeness is explicit. An absent marker is unknown and first-adoption
     * initialization at a nonzero reducer cursor must conservatively recreate
     * a gap, so deleting this marker would lose the backfill proof on reboot. */
    ok = progress_meta_set_in_tx(db, NULLIFIER_BACKFILL_ACTIVATION_KEY,
                                 complete, sizeof(complete) - 1) &&
         progress_meta_delete_in_tx(db, NULLIFIER_BACKFILL_RESUME_KEY);
    if (!ok) {
        (void)nbf_tx_finish(db, false);
        LOG_WARN(NBF_SUBSYS, "finish_complete: marker update failed");
        return ZCL_ERR(-31, "failed to persist nullifier completion marker");
    }
    if (!nbf_tx_finish(db, true))
        return ZCL_ERR(-32, "commit failed while clearing nullifier gap");

    utxo_apply_nullifier_gap_blocker_refresh(db);
    blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    return ZCL_OK;
}

struct zcl_result nullifier_backfill_service_run(
    const struct nullifier_backfill_config *cfg,
    struct nullifier_backfill_report *report)
{
    struct nullifier_backfill_report local_report = {0};
    nullifier_backfill_read_block_fn reader;
    void *reader_user;
    sqlite3 *db;
    int64_t activation = 0;
    int64_t resume = 0;
    int64_t start = 0;
    bool activation_found = false;
    bool resume_found = false;
    struct nbf_chain_binding binding;

    if (!report)
        report = &local_report;
    memset(report, 0, sizeof(*report));

    if (!cfg || !cfg->progress_db) {
        LOG_WARN(NBF_SUBSYS, "run: missing config/progress db");
        return ZCL_ERR(-40, "missing nullifier backfill config/progress db");
    }
    db = cfg->progress_db;
    if (!nullifier_kv_ensure_schema(db)) {
        LOG_WARN(NBF_SUBSYS, "run: nullifier schema ensure failed");
        return ZCL_ERR(-41, "nullifier schema ensure failed");
    }
    if (!progress_meta_table_ensure(db)) {
        LOG_WARN(NBF_SUBSYS, "run: progress_meta schema ensure failed");
        return ZCL_ERR(-42, "progress_meta schema ensure failed");
    }

    ZCL_CHECK(nbf_read_meta_i64(db, NULLIFIER_BACKFILL_ACTIVATION_KEY,
                                &activation, &activation_found));
    report->activation_cursor = activation_found ? activation : 0;
    if (!activation_found) {
        LOG_WARN(NBF_SUBSYS,
                 "run: activation marker absent; history coverage unknown");
        return ZCL_ERR(-49, "nullifier activation marker absent; initialize "
                            "history coverage before backfill");
    }
    if (activation == 0) {
        report->already_complete = true;
        report->completed = true;
        utxo_apply_nullifier_gap_blocker_refresh(db);
        return ZCL_OK;
    }
    if (activation < 0 || activation > INT_MAX) {
        LOG_WARN(NBF_SUBSYS, "run: activation cursor too high: %lld",
                 (long long)activation);
        return ZCL_ERR(-43, "activation cursor out of range: %lld",
                       (long long)activation);
    }

    ZCL_CHECK(nbf_read_meta_i64(db, NULLIFIER_BACKFILL_RESUME_KEY,
                                &resume, &resume_found));
    if (resume_found && (resume < 0 || resume > activation)) {
        LOG_WARN(NBF_SUBSYS, "run: invalid resume marker %lld target=%lld",
                 (long long)resume, (long long)activation);
        return ZCL_ERR(-44, "invalid nullifier backfill resume marker %lld "
                            "for target %lld",
                       (long long)resume, (long long)activation);
    }

    ZCL_CHECK(nbf_chain_binding_capture(cfg, activation, &binding));
    ZCL_CHECK(nbf_prepare_generation(db, activation, &binding,
                                     resume_found, resume, &start));

    reader = cfg->read_block ? cfg->read_block : nbf_default_read_block;
    reader_user = cfg->read_block ? cfg->read_block_user : cfg->ndb;
    if (!reader) {
        LOG_WARN(NBF_SUBSYS, "run: no block reader available");
        return ZCL_ERR(-45, "no block reader available");
    }
    if (!cfg->read_block && (!cfg->ndb || !cfg->ndb->open || !cfg->datadir)) {
        LOG_WARN(NBF_SUBSYS, "run: default reader missing ndb/datadir");
        return ZCL_ERR(-46, "default block reader requires node db/datadir");
    }

    report->start_height = start;
    report->target_exclusive = activation;
    report->next_height = start;

    for (int64_t h = start; h < activation; h++) {
        struct block blk;
        bool found = false;
        struct zcl_result one;

        block_init(&blk);
        if (!reader(&blk, h, cfg->datadir, reader_user, &found)) {
            block_free(&blk);
            /* De-stormed: a stuck resume marker re-hits this same height on
             * every backfill tick until the reader fault clears. */
            static struct log_throttle thr = LOG_THROTTLE_INIT;
            if (log_throttle_should_emit(&thr, (uint64_t)h,
                                         platform_time_wall_unix(), 300, NULL))
                LOG_WARN(NBF_SUBSYS, "run: block reader failed at h=%lld",
                         (long long)h);
            return ZCL_ERR(-47, "block reader failed at height %lld",
                           (long long)h);
        }
        if (!found) {
            block_free(&blk);
            static struct log_throttle thr = LOG_THROTTLE_INIT;
            if (log_throttle_should_emit(&thr, (uint64_t)h,
                                         platform_time_wall_unix(), 300, NULL))
                LOG_WARN(NBF_SUBSYS,
                         "run: missing validated block body at h=%lld",
                         (long long)h);
            return ZCL_ERR(-48, "missing validated block body at height %lld; "
                                "nullifier gap marker left in place",
                           (long long)h);
        }

        one = nbf_chain_body_verify(&binding, &blk, h);
        if (!one.ok) {
            block_free(&blk);
            return one;
        }

        one = nbf_backfill_one(db, &blk, h);
        block_free(&blk);
        if (!one.ok)
            return one;
        report->blocks_scanned++;
        report->next_height = h + 1;
    }

    ZCL_CHECK(nbf_finish_complete(cfg, db, activation, &binding));
    report->completed = true;
    return ZCL_OK;
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: reads the
 * two durable progress.kv markers this owner-gated one-shot job leaves
 * behind (positive activation plus a smaller resume cursor means mid-run;
 * explicit zero means complete; absent is unknown/uninitialized). The companion
 * `utxo_apply.nullifier_backfill_gap` blocker remains visible for unknown or
 * positive coverage. No allocation;
 * progress_store_tx_lock is the same brief lock nbf_read_meta_i64 always
 * takes. */
bool nullifier_backfill_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    sqlite3 *db = progress_store_db();
    json_push_kv_bool(out, "progress_store_open", db != NULL);
    if (!db) {
        json_push_kv_bool(out, "gap_blocker_active",
                          blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));
        return true;
    }

    int64_t activation = 0, resume = 0;
    bool activation_found = false, resume_found = false;
    (void)nbf_read_meta_i64(db, NULLIFIER_BACKFILL_ACTIVATION_KEY,
                            &activation, &activation_found);
    (void)nbf_read_meta_i64(db, NULLIFIER_BACKFILL_RESUME_KEY,
                            &resume, &resume_found);

    json_push_kv_bool(out, "activation_cursor_present", activation_found);
    json_push_kv_int(out, "activation_cursor", activation);
    json_push_kv_bool(out, "resume_cursor_present", resume_found);
    json_push_kv_int(out, "resume_cursor", resume);
    json_push_kv_bool(out, "gap_blocker_active",
                      blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

    const char *status;
    if (!activation_found)
        status = "unknown_uninitialized";
    else if (activation == 0)
        status = "complete";
    else if (resume_found && resume < activation)
        status = "in_progress";
    else
        status = "pending_start";
    json_push_kv_str(out, "status", status);
    return true;
}
