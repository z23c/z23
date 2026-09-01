/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: -mint-anchor drive-loop pacing, the deferred-Sapling-rebuild wait,
 * and the balanced teardown shared by every short-of-anchor exit.
 *
 * Split out of boot_mint_anchor.c for the E1 file-size ceiling (the same seam
 * pattern as boot_mint_anchor_preflight.c / boot_mint_anchor_reset.c). */

#include "config/boot_mint_anchor_drive.h"

#include "jobs/proof_validate_stage.h"
#include "core/utiltime.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Drive-loop backoff. reducer_kick_unbudgeted returns immediately once the
 * frontier is stalled, so a no-progress round costs microseconds: without a
 * nap the loop below burns its whole 64-kick stall budget in about a second,
 * which is far too fast to distinguish a dead fold from one waiting on a
 * legitimate pause. */
void mint_drive_nap_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* THE PAUSE THAT IS NOT A WALL. The deferred Sapling commitment-tree rebuild
 * (sync_controller_sapling_tree.c sapling_tree_rebuild_deferred_thread) sets
 * g_sapling_tree_rebuilding for its whole run, and utxo_apply_step returns
 * JOB_IDLE on its FIRST line while that flag is set — deliberately, so no
 * anchor derived from the obsolete frontier is ever persisted. A mint booted
 * against a datadir whose tree is stale therefore opens with utxo_apply pinned
 * at 0 while every upstream stage runs ahead. That is the exact cursor shape
 * the stall detector reads as "walled" (ua=0 is the pipeline minimum, so it
 * even names utxo_apply as the walled stage), and the fold was being killed
 * ~1s in while a replay of ~1M commitments had barely started.
 *
 * So the wait is explicit and bounded: hold the stall counter while the pause
 * is up, and give up only after ZCL_MINT_REBUILD_WAIT_MAX_S (default 1h) so a
 * rebuild that never completes still fails closed rather than hanging forever.
 * 0 disables the wait entirely and restores the old count-it-as-a-stall
 * behaviour. */
#define MINT_REBUILD_WAIT_DEFAULT_S 3600
int mint_rebuild_wait_max_s(void)
{
    const char *e = getenv("ZCL_MINT_REBUILD_WAIT_MAX_S");
    if (!e || !e[0])
        return MINT_REBUILD_WAIT_DEFAULT_S;
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end == e || v < 0 || v > INT32_MAX)
        return MINT_REBUILD_WAIT_DEFAULT_S;
    return (int)v;
}

/* Set progress.kv's WAL auto-checkpoint threshold (pages; 0 disables SQLite's
 * automatic checkpoints). PRAGMA-only, under the progress-store tx lock. */
void mint_wal_autocheckpoint(sqlite3 *pdb, int pages)
{
    if (!pdb) return;
    char sql[64];
    snprintf(sql, sizeof(sql), "PRAGMA wal_autocheckpoint=%d", pages);
    progress_store_tx_lock();
    (void)sqlite3_exec(pdb, sql, NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* Balanced teardown for every drive-loop exit that stops the fold SHORT of the
 * anchor: restore durability first so the blocker/report writes land under
 * NORMAL and are checkpointed into the main db, restore WAL auto-checkpointing,
 * stop the lookahead pool, and leave the mint writer bracket. Kept in one place
 * so the walled path and the rebuild-wait timeout cannot drift apart. */
void mint_drive_stop(sqlite3 *pdb, bool mint_sync_off, bool wal_manual,
                            bool lookahead)
{
    if (mint_sync_off) {
        progress_store_set_sync_mode(/*ibd=*/false);
        (void)progress_store_checkpoint();
    }
    if (wal_manual)
        mint_wal_autocheckpoint(pdb, 1000);   /* restore default */
    if (lookahead)
        proof_validate_lookahead_stop();
    coins_ram_mint_drive_exit();
}

enum mint_rebuild_wait_result boot_mint_anchor_drive_rebuild_wait(
    struct mint_rebuild_wait_state *st)
{
    const int max_s = mint_rebuild_wait_max_s();
    if (st->started_us == 0)
        st->started_us = GetTimeMicros();
    if (!st->logged) {
        fprintf(stderr,
                "[mint-anchor] utxo_apply is paused by the deferred Sapling "
                "commitment-tree rebuild — waiting up to %ds for it to publish "
                "its frontier (this is not a wall; override with "
                "ZCL_MINT_REBUILD_WAIT_MAX_S)\n", max_s);
        st->logged = true;
    }
    if ((GetTimeMicros() - st->started_us) / 1000000 >= (int64_t)max_s) {
        /* Fail closed: a rebuild this long is its own defect, and a mint that
         * waits forever is indistinguishable from a hang. */
        fprintf(stderr,
                "[mint-anchor] the deferred Sapling commitment-tree rebuild "
                "did not finish within %ds — giving up. The fold never "
                "started; utxo_apply stayed paused the whole time. Check the "
                "sapling_tree_rebuild blocker before reading the stage cursors "
                "below as a wall.\n", max_s);
        return MINT_REBUILD_WAIT_TIMEOUT;
    }
    mint_drive_nap_ms(200);
    return MINT_REBUILD_WAIT_WAITING;
}
