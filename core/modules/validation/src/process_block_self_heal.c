/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-heal coordination for missing UTXOs and stuck-tip recovery.
 *
 * Contents:
 *   - s_utxo_* failure-tracking state
 *   - process_block_is_missing_utxo_failure
 *   - process_block_note_utxo_failure
 *   - ZCL_TESTING hooks */

#include <stdio.h>
#include <string.h>

#include "validation/process_block.h"
#include "validation/main_logic.h"
#include "validation/connect_block.h"
/* AUTHORITATIVE recovery retry routes through the reducer (cursor move +
 * reducer_kick) instead of the deleted block-disconnect engine — same app-layer
 * controller reach process_block_revalidate.c/process_block_invalidate.c
 * already take. Inline marker keeps the lib_layering baseline flat. */
#include "validation/chainstate.h"
#include "services/chain_activation_service.h"  // lib-layer-ok:self-heal-reducer-retry
#include "storage/node_db_runtime.h"
#include "event/event.h"

#include "process_block_internal.h"

/* ── self-heal state shared with core ─────────────────────────── */
int s_utxo_fail_count = 0;
int s_utxo_fail_height = -1;
int s_utxo_hot_loop_reported_height = -1;
int s_utxo_activation_paused_height = -1;

bool process_block_is_missing_utxo_failure(
    const struct validation_state *state)
{
    return state && state->reject_reason[0] &&
           strcmp(state->reject_reason,
                  "bad-txns-inputs-missingorspent") == 0;
}

void process_block_note_utxo_failure(struct main_state *ms,
                                     struct coins_view_cache *coins_tip,
                                     int height,
                                     const char *datadir)
{
    /* coins_tip retained in the signature (public API / test injection); the
     * UTXO unwind now goes through the reducer's inverse-delta machinery via
     * reducer_kick, not the legacy coins-view disconnect path. */
    (void)coins_tip;
    if (height == s_utxo_fail_height)
        s_utxo_fail_count++;
    else {
        s_utxo_fail_height = height;
        s_utxo_fail_count = 1;
        s_utxo_hot_loop_reported_height = -1;
        s_utxo_activation_paused_height = -1;
    }

    int durable_utxo_max_h =
        node_db_runtime_utxo_max_height(process_block_node_db_internal());

    if (durable_utxo_max_h > height + 10) {
        if (s_utxo_fail_count == 1 || s_utxo_fail_count == 5) {
            event_emitf(EV_BOOT_ACTIVATE, 0,
                "HISTORIC_UTXO_REPLAY_REFUSED h=%d utxo_max=%d fails=%d",
                height, durable_utxo_max_h, s_utxo_fail_count);
            fprintf(stderr,
                "[recovery] refusing destructive reimport loop: missing input "
                "at h=%d but durable UTXOs reach h=%d; activation should use "
                "the snapshot/coins anchor instead of replaying history.\n",
                height, durable_utxo_max_h);
        }
        if (s_utxo_fail_count >= 5)
            s_utxo_activation_paused_height = height;
        return;
    }

    if (s_utxo_fail_count >= 5) {
        /* After 5 failures at the same height, try disconnecting the tip
         * to retry from the previous UTXO state.  This is best-effort:
         * if undo data is unavailable the reimport flag path below is the
         * durable recovery route. */
        struct block_index *tip = ms ? active_chain_tip(&ms->chain_active)
                                     : NULL;
        if (tip && tip->pprev) {
            /* The STAGE owns the coins.db / UTXO unwind. Drive the stage-side
             * unwind exactly as the live reorg path does — move the
             * active-chain cursor DOWN one (a pure cursor move, no legacy
             * coins write), then kick the reducer so its inverse-delta
             * machinery rewinds the stage cursors and re-walks. The stage
             * holds its own inverse-delta rows, not the legacy undo file. */
            fprintf(stderr, // obs-ok:pre-existing-diagnostic
                "[recovery] %d UTXO failures at h=%d — stage-unwinding tip "
                "h=%d to retry (reducer-authoritative)\n",
                s_utxo_fail_count, height, tip->nHeight);
            if (active_chain_move_window_tip(&ms->chain_active, tip->pprev)) {
                (void)reducer_kick(process_block_activation_controller());
                s_utxo_fail_count = 0;
                s_utxo_fail_height = -1;
                fprintf(stderr, // obs-ok:pre-existing-diagnostic
                    "[recovery] Stage-unwound tip — retrying from h=%d\n",
                    active_chain_height(&ms->chain_active));
            }
        } else {
            fprintf(stderr, // obs-ok:pre-existing-diagnostic
                "[recovery] UTXO mismatch at h=%d: inputs missing. "
                "Chain tip and UTXO set are out of sync.\n"
                "[recovery] Restart with -reimport-utxos or delete "
                "chainstate/ to force fresh import.\n",
                height);
        }
    }

    process_block_maybe_write_needs_reimport_flag(height, datadir);
    process_block_maybe_trigger_hot_loop_exit(height, datadir);
}

#ifdef ZCL_TESTING
void process_block_test_set_utxo_fail_state(int height, int count)
{
    s_utxo_fail_height = height;
    s_utxo_fail_count = count;
    s_utxo_hot_loop_reported_height = -1;
    s_utxo_activation_paused_height = -1;
}

int process_block_test_get_utxo_fail_count(void)
{
    return s_utxo_fail_count;
}

void process_block_test_note_utxo_failure(int height, const char *datadir)
{
    process_block_note_utxo_failure(NULL, NULL, height, datadir);
}
#endif
