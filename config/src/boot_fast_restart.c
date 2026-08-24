/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_fast_restart.h"

#include "config/boot_shutdown_marker.h"
#include "models/database.h"
#include "util/thread_registry.h"
#include "util/safe_alloc.h"
#include "event/event.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "services/block_index_loader.h"
#include "services/chain_restore_repair.h"
#include "services/chain_restore_boot_snapshot.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void boot_fast_restart_evaluate(const struct shutdown_clean_binding *binding,
                                const struct boot_fast_restart_facts *cur,
                                struct boot_fast_restart_verdict *out)
{
    if (!out)
        return;
    out->fast_restart = false;

    if (!binding || !binding->fr_valid) {
        snprintf(out->reason, sizeof(out->reason),
                 "no_fast_restart_binding");
        return;
    }
    if (!cur) {
        snprintf(out->reason, sizeof(out->reason), "no_current_facts");
        return;
    }

    /* node.db byte-consistency (P1). If quick_check actually ran this boot, the
     * DB was NOT proven byte-identical to shutdown — refuse to trust the rest. */
    if (!cur->node_db_clean) {
        snprintf(out->reason, sizeof(out->reason), "node_db_not_clean");
        return;
    }
    if (cur->block_index_count != binding->fr_block_index_count) {
        snprintf(out->reason, sizeof(out->reason),
                 "block_index_count %lld!=%lld",
                 (long long)cur->block_index_count,
                 (long long)binding->fr_block_index_count);
        return;
    }
    if (!cur->tip_hash_found) {
        snprintf(out->reason, sizeof(out->reason), "tip_hash_absent");
        return;
    }
    if (cur->tip_height != binding->fr_tip_height) {
        snprintf(out->reason, sizeof(out->reason),
                 "tip_height %lld!=%lld",
                 (long long)cur->tip_height,
                 (long long)binding->fr_tip_height);
        return;
    }
    if (!cur->coins_best_found) {
        snprintf(out->reason, sizeof(out->reason), "coins_best_absent");
        return;
    }
    if (cur->coins_best_height != binding->fr_coins_best_height) {
        snprintf(out->reason, sizeof(out->reason),
                 "coins_best_height %lld!=%lld",
                 (long long)cur->coins_best_height,
                 (long long)binding->fr_coins_best_height);
        return;
    }
    if (memcmp(cur->coins_best_hash, binding->fr_coins_best_hash, 32) != 0) {
        snprintf(out->reason, sizeof(out->reason), "coins_best_hash_mismatch");
        return;
    }

    out->fast_restart = true;
    snprintf(out->reason, sizeof(out->reason), "all-bindings-verified");
}

bool boot_fast_restart_try(struct main_state *ms,
                           struct block_index **out_tip)
{
    if (out_tip)
        *out_tip = NULL;
    if (!ms)
        return false;

    struct shutdown_clean_binding fr_b;
    if (!boot_shutdown_marker_peek_fast_restart_binding(&fr_b))
        return false;

    struct boot_fast_restart_facts facts;
    memset(&facts, 0, sizeof(facts));
    facts.node_db_clean = boot_shutdown_marker_quick_check_was_skipped();
    facts.block_index_count = (int64_t)ms->map_block_index.size;

    struct uint256 tip_hash_u;
    memcpy(tip_hash_u.data, fr_b.fr_tip_hash, 32);
    struct block_index *fr_tip = block_map_find(&ms->map_block_index,
                                                &tip_hash_u);
    if (fr_tip) {
        facts.tip_hash_found = true;
        facts.tip_height = fr_tip->nHeight;
    }

    int32_t cb_h = -1;
    bool cb_found = false;
    if (reducer_frontier_derive_coins_best_now(&cb_h, facts.coins_best_hash,
                                               &cb_found)) {
        facts.coins_best_found = cb_found;
        facts.coins_best_height = cb_h;
    }

    struct boot_fast_restart_verdict v;
    boot_fast_restart_evaluate(&fr_b, &facts, &v);
    chain_restore_record_fast_restart(v.fast_restart, facts.tip_height,
                                      v.reason);

    if (!v.fast_restart || !fr_tip) {
        printf("[boot] fast_restart NOT taken (%s) — full boot path\n",
               v.reason);
        return false;
    }

    chain_restore_set_trust_index_fastpath(true);
    int pop = chain_restore_rebuild_active_chain(ms, fr_tip, NULL);
    printf("[boot] fast_restart TAKEN (%s): installed tip h=%d in-memory "
           "(active_chain populated=%d); skipping disk chain-restore + "
           "finalize rebuild\n", v.reason, fr_tip->nHeight, pop);
    event_emitf(EV_BOOT_ACTIVATE, 0, "fast_restart=1 tip=%d populated=%d",
                fr_tip->nHeight, pop);
    if (out_tip)
        *out_tip = fr_tip;
    return true;
}

void boot_fast_restart_capture_shutdown_facts(struct main_state *ms)
{
    struct fast_restart_shutdown_facts fr;
    memset(&fr, 0, sizeof(fr));
    const char *why = "no_state";
    if (ms) {
        /* Bind ONLY the healthy at-tip case: the raw container tip
         * (active_chain_cached_tip — no authority resolve, since the tip
         * authority may already be stopped at teardown) must EQUAL the durable
         * finalized-tip authority read straight from progress.kv. When they
         * diverge — a reconciling / detached-island / snapshot-loader datadir
         * whose container tip lags the served (durable) tip — we refuse to
         * record a binding, so the next boot takes the full path. This is the
         * load-bearing safety: binding a lagging container tip (e.g. genesis on
         * a detached-island datadir) would fast-restart the node onto the WRONG
         * height. Equality guarantees a genesis-rooted, fully-installed tip. */
        struct block_index *ctip = active_chain_cached_tip(&ms->chain_active);
        int dh = -1;
        uint8_t dhash[32];
        bool durable = tip_finalize_stage_resolve_durable_tip(
                           progress_store_db(), &dh, dhash) && dh > 0;
        if (!ctip || !ctip->phashBlock || ctip->nHeight < 0) {
            why = "no_container_tip";
        } else if (!durable) {
            why = "no_durable_tip";
        } else if (ctip->nHeight != dh ||
                   memcmp(ctip->phashBlock->data, dhash, 32) != 0) {
            why = "container_tip_lags_durable_tip";
        } else {
            int32_t cb_h = -1;
            uint8_t cb_hash[32];
            bool cb_found = false;
            bool cb_ok = reducer_frontier_derive_coins_best_now(&cb_h, cb_hash,
                                                                &cb_found);
            fr.valid = true;
            fr.tip_height = ctip->nHeight;
            memcpy(fr.tip_hash, ctip->phashBlock->data, 32);
            /* Prefer the durable coins-best frontier; on a healthy at-tip node
             * it equals the tip, so fall back to the tip when the derive is
             * unavailable at teardown (a boot-side mismatch just declines). */
            if (cb_ok && cb_found) {
                fr.coins_best_height = cb_h;
                memcpy(fr.coins_best_hash, cb_hash, 32);
            } else {
                fr.coins_best_height = ctip->nHeight;
                memcpy(fr.coins_best_hash, ctip->phashBlock->data, 32);
            }
            fr.block_index_count = (int64_t)ms->map_block_index.size;
            /* mmb_leaves / sapling_ckpt_height reserved (not in the active
             * gate); the sapling checkpoint load self-verifies independently. */
            printf("[shutdown] fast-restart binding: tip_h=%lld coins_best_h=%lld"
                   " block_index=%zu\n", (long long)fr.tip_height,
                   (long long)fr.coins_best_height, ms->map_block_index.size);
        }
    }
    if (!fr.valid)
        printf("[shutdown] fast-restart binding NOT recorded (%s) — next boot "
               "takes the full path\n", why);
    boot_shutdown_marker_set_fast_restart_facts(fr.valid ? &fr : NULL);
}

void boot_fast_restart_arm_quick_check_skip_probe(void)
{
    /* Let node_db_open skip PRAGMA quick_check when the previous shutdown wrote
     * a matching content binding (consumed from the cache detect_unclean
     * populated). Must run BEFORE node.db opens. */
    node_db_set_quick_check_skip_probe(boot_shutdown_marker_quick_check_probe);
}

/* Runs one quick_check on a fresh read-only connection (no contention with the
 * live write handle). A failure is raised LOUDLY via EV_DB_ERROR +
 * EV_OPERATOR_NEEDED (the latter latches DEGRADED in the health surface until
 * an operator acts) — never silent. */
static void *boot_bg_quick_check_entry(void *arg)
{
    char *path = (char *)arg;
    if (!path)
        return NULL;

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        /* Could not even open read-only — surface it, but do not escalate to
         * OPERATOR_NEEDED (the live write handle owns the authoritative view). */
        event_emitf(EV_DB_ERROR, 0,
                    "bg_quick_check open failed rc=%d path=%s", rc, path);
        free(path);
        return NULL;
    }

    sqlite3_busy_timeout(db, 5000);
    sqlite3_stmt *st = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &st, NULL) ==
            SQLITE_OK &&
        st && sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:read-only-introspection
        const unsigned char *txt = sqlite3_column_text(st, 0);
        ok = txt && strcmp((const char *)txt, "ok") == 0;
        if (!ok) {
            const char *kind =
                boot_shutdown_marker_quick_check_was_skipped()
                    ? "verified-clean quick_check skip"
                    : "unclean/unverified deferral";
            fprintf(stderr,  // obs-ok:operator-surface-is-the-alert
                    "[ALERT] bg_quick_check: node.db integrity FAILED after a "
                    "%s: %s\n",
                    kind, txt ? (const char *)txt : "(no detail)");
            event_emitf(EV_DB_ERROR, 0,
                        "bg_quick_check failed result=%s",
                        txt ? (const char *)txt : "unknown");
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "condition=bg_quick_check_failed detail=node_db_integrity");
        }
    } else {
        event_emitf(EV_DB_ERROR, 0,
                    "bg_quick_check step failed: %s", sqlite3_errmsg(db));
    }
    if (st)
        sqlite3_finalize(st);
    sqlite3_close(db);

    if (ok) {
        if (boot_shutdown_marker_quick_check_was_skipped())
            printf("[boot] bg_quick_check ok (verified-clean skip confirmed)\n");
        else
            printf("[boot] bg_quick_check ok (deferred unclean recheck)\n");
    }
    free(path);
    return NULL;
}

void boot_fast_restart_start_bg_quick_check(const char *datadir)
{
    if (!datadir)
        return;
    if (!boot_shutdown_marker_quick_check_was_skipped() &&
        !boot_shutdown_marker_quick_check_was_deferred())
        return;

    char *path = zcl_malloc(1088, "bg_quick_check_path");
    if (!path)
        return;
    int n = snprintf(path, 1088, "%s/node.db", datadir);
    if (n < 0 || n >= 1088) {
        free(path);
        return;
    }
    if (thread_registry_spawn("bg_quick_check",
                              boot_bg_quick_check_entry, path, NULL) != 0) {
        fprintf(stderr,
                "WARNING: failed to spawn background quick_check thread\n");
        free(path);
    }
}
