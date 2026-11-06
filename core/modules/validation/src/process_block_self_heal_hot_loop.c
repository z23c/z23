/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Missing-UTXO hot-loop and reimport policy.
 *
 * The failure coordinator owns s_utxo_* counters. This file owns the side
 * effects once those counters cross repair thresholds: needs_reimport flag
 * writes and shutdown request. */

#include "platform/time_compat.h"
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#include "event/event.h"
#include "storage/utxo_reimport_flag.h"

#include "process_block_internal.h"

void process_block_maybe_write_needs_reimport_flag(int height,
                                                   const char *datadir)
{
    if (s_utxo_fail_count < 3 || !datadir)
        return;

    /* Storage layout + on-disk format owned by the
     * utxo_reimport_flag primitive (engine/modules/storage/). */
    (void)utxo_reimport_flag_set(datadir);
    fprintf(stderr, // obs-ok:pre-existing-diagnostic
        "CRITICAL: %d UTXO failures at h=%d — "
        "wrote needs_reimport flag.\n",
        s_utxo_fail_count,
        height);
}

void process_block_maybe_trigger_hot_loop_exit(int height,
                                               const char *datadir)
{
    if (s_utxo_fail_count < 10 || !datadir)
        return;

    if (s_utxo_hot_loop_reported_height == height)
        return;

    char marker_path[512];
    snprintf(marker_path, sizeof(marker_path),
             "%s/last_reimport_attempted", datadir);
    struct stat mst;
    time_t now_s = platform_time_wall_time_t();
    bool reimport_recent =
        (stat(marker_path, &mst) == 0 &&
         now_s - mst.st_mtime < 600);

    if (reimport_recent) {
        event_emitf(EV_BOOT_ACTIVATE, 0,
            "FATAL_HOT_LOOP_STUCK h=%d fails=%d "
            "reimport_age_sec=%ld",
            height,
            s_utxo_fail_count,
            (long)(now_s - mst.st_mtime));
        fprintf(stderr, // obs-ok:pre-existing-diagnostic
            "CRITICAL: %d UTXO failures at h=%d "
            "but reimport was attempted %lds ago "
            "and did NOT heal the UTXO set. NOT "
            "auto-restarting (would bootloop). "
            "Operator intervention required — "
            "inspect `z23 ops timeline`, `z23 getnodelog`, "
            "and consider rolling the tip back "
            "to before the missing-input height "
            "and resyncing from P2P.\n",
            s_utxo_fail_count,
            height,
            (long)(now_s - mst.st_mtime));
        fflush(stderr);
    } else {
        event_emitf(EV_BOOT_ACTIVATE, 0,
            "FATAL_HOT_LOOP h=%d fails=%d "
            "reimport=1",
            height,
            s_utxo_fail_count);
        fprintf(stderr, // obs-ok:pre-existing-diagnostic
            "CRITICAL: %d consecutive UTXO "
            "failures at h=%d — requesting "
            "clean shutdown so systemd restart "
            "picks up needs_reimport flag.\n",
            s_utxo_fail_count,
            height);
        fflush(stderr);
        g_shutdown_requested = 1;
    }

    s_utxo_hot_loop_reported_height = height;
}

#ifdef ZCL_TESTING
void process_block_test_trigger_hot_loop_check(int height,
                                               const char *datadir)
{
    process_block_maybe_write_needs_reimport_flag(height, datadir);
    process_block_maybe_trigger_hot_loop_exit(height, datadir);
}
#endif
