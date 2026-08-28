/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "metrics/metrics.h"
#include "metrics/prometheus_metrics.h"
#include "metrics/stage_metrics.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "core/utiltime.h"
#include "util/timedata.h"
#include "event/event.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "sync/sync_state.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

_Atomic uint64_t g_transactions_validated = 0;
_Atomic uint64_t g_eh_solver_runs = 0;

static int64_t g_start_time = 0;
/* Supervisor liveness: the metrics printer loops on a 1 s cadence. It
 * heartbeats onto the tree (deadline=120 s) with the loop count as its
 * progress marker; no-progress gate disabled (the deadline covers a frozen
 * loop). The worker tid lives in g_metrics_child.worker_tid so the bounded
 * auto-restart path and metrics_stop() share one current handle. See
 * util/thread_liveness.h. */
static struct thread_liveness_child g_metrics_child = {
    .id = SUPERVISOR_INVALID_ID
};
/* Single-spawn guard for the metrics worker. Two concurrent metrics_start()
 * calls must not both spawn and overwrite the handle (which would orphan one
 * thread); the winner of this CAS is the only spawner, and metrics_stop()
 * pairs with it so only the matching join runs. */
static _Atomic bool g_metrics_started = false;

static bool stdout_is_terminal(void)
{
#ifdef _WIN32
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    return output != NULL && output != INVALID_HANDLE_VALUE &&
           GetConsoleMode(output, &mode) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

void metrics_print_art(void)
{
    printf(
        "               \033[0;1;30;90;43mXX\033[0;1;31;91;43m8"
        "\033[0;33;5;43;103m:...:\033[0;1;31;91;43m8\033[0;1;30;90;43mXS"
        "\033[0m                         \033[0;1;31;91;41mX"
        "\033[0;31;5;41;101m8XXX@\033[0;1;31;91;41m8\033[0m"
        "               \033[0;1;31;91;41m8\033[0;31;5;41;101mXXXX@"
        "\033[0m         \n");
    printf(
        "          \033[0;1;30;90;43m8\033[0;1;33;93;43m.."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m............."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m..\033[0;1;30;90;43m8"
        "\033[0m                 \033[0;31;5;41;101m.            t"
        "\033[0m       \033[0;31;5;41;101mt             X"
        "\033[0m    \n");
    printf(
        "       \033[0;1;30;90;43m8\033[0;1;33;93;43m."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m...."
        "\033[0;1;31;91;43m88\033[0;33;5;43;103m.\033[0;1;33;93;43m."
        "\033[0;1;31;91;43m8\033[0;31;43mt\033[0;1;30;90;43mX"
        "\033[0;31;43mt\033[0;1;31;91;43m88\033[0;33;5;43;103m."
        "\033[0;1;33;93;43m.\033[0;1;31;91;43m8\033[0;1;33;93;43m...."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m.\033[0;1;30;90;43m8"
        "\033[0m            \033[0;31;5;41;101m                 :"
        "\033[0m   \033[0;31;5;41;101m.                 t"
        "\033[0m  \n");
    printf(
        "     \033[0;1;30;90;43m8\033[0;1;33;93;43m......"
        "\033[0;1;31;91;43m8\033[0;1;30;90;43m8\033[0m"
        "              \033[0;1;31;91;43m8\033[0;1;33;93;43m......"
        "\033[0;1;30;90;43m8\033[0m        "
        "\033[0;31;5;41;101m%%                    ."
        "                     \033[0m \n");
    printf(
        "    \033[0;33;5;43;103m.\033[0;1;33;93;43m...."
        "\033[0;33;5;43;103m.\033[0;1;30;90;43m8\033[0m"
        "                    \033[0;1;31;91;43m88\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m.:\033[0m       "
        "\033[0;31;5;41;101m                                "
        "           .\033[0m\n");
    printf(
        "   \033[0;1;31;91;43m8\033[0;1;33;93;43m...."
        "\033[0;33;5;43;103m.\033[0;1;30;90;43m8\033[0m"
        "                       \033[0;33;5;43;103m:."
        "\033[0;1;33;93;43m..\033[0;33;5;43;103m.\033[0m     "
        "\033[0;31;5;41;101mX                                "
        "            \033[0m\n");
    printf(
        "  \033[0;1;31;91;43m8\033[0;1;33;93;43m................"
        "\033[0;1;31;91;43m8\033[0;37;43mX\033[0m "
        "\033[0;1;33;93;43m....\033[0;1;31;91;43m8\033[0;37;43mX\033[0m"
        "      \033[0;37;43m@\033[0;33;5;43;103m.\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m.\033[0m    "
        "\033[0;31;5;41;101mX                                "
        "            \033[0m\n");
    printf(
        " \033[0;33;5;43;103m.\033[0;1;33;93;43m...."
        "\033[0;33;5;43;103m.............\033[0;33;47m88"
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m....\033[0m"
        "         \033[0;37;5;43;103m@\033[0;1;33;93;43m..."
        "\033[0;33;5;43;103m:\033[0m    "
        "\033[0;31;5;41;101m                                "
        "            \033[0m\n");
    printf(
        "\033[0;33;47m8\033[0;1;31;91;43m8\033[0;1;33;93;43m...."
        "\033[0m             \033[0;1;33;93;43m:\033[0;1;31;91;43m8"
        "\033[0;1;33;93;43m....\033[0m           "
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m.\033[0;37;43m8\033[0m   "
        "\033[0;31;5;41;101m                                "
        "           \033[0m \n");
    printf(
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m..."
        "\033[0;1;31;91;43m8\033[0m             "
        "\033[0;1;33;93;43m......\033[0m            "
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m..."
        "\033[0;37;5;43;103m@\033[0m    "
        "\033[0;31;5;41;101m                                "
        "         .\033[0m \n");
    printf(
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m..."
        "\033[0;1;31;91;43m8\033[0m            "
        "\033[0;1;33;93;43m......\033[0m             "
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m..."
        "\033[0;33;5;43;103m.\033[0m     "
        "\033[0;31;5;41;101m                                "
        "       ;\033[0m  \n");
    printf(
        "\033[0;37;43m@\033[0;1;31;91;43m8\033[0;1;33;93;43m..."
        "\033[0;1;31;91;43m8\033[0m          "
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m..."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m:\033[0m"
        "              \033[0;33;5;43;103m.\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m.\033[0;33;47m8\033[0m      "
        "\033[0;31;5;41;101m.                              "
        "      \033[0m    \n");
    printf(
        " \033[0;1;33;93;43m.....\033[0m         "
        "\033[0;1;33;93;43m.....\033[0;1;31;91;43m8"
        "\033[0;33;5;43;103m................\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m:\033[0m         "
        "\033[0;31;5;41;101m.                             "
        "  .\033[0m      \n");
    printf(
        "  \033[0;1;31;91;43m8\033[0;1;33;93;43m..."
        "\033[0;33;5;43;103m.\033[0m      "
        "\033[0;37;43m@\033[0;1;33;93;43m..................."
        "\033[0;1;31;91;43m8\033[0;33;5;43;103m.."
        "\033[0;1;33;93;43m..\033[0;33;5;43;103m.\033[0m"
        "            \033[0;31;5;41;101m:                     "
        "      t\033[0m        \n");
    printf(
        "  \033[0;1;30;90;43m8\033[0;1;31;91;43m8"
        "\033[0;1;33;93;43m....\033[0m     "
        "\033[0;31;43mSSSSSSSSSSSSSSSSSS\033[0;1;30;90;43mX"
        "\033[0;33;5;43;103m:..\033[0;1;33;93;43m.."
        "\033[0;33;5;43;103m.\033[0m               "
        "\033[0;31;5;41;101mt                       S"
        "\033[0m          \n");
    printf(
        "    \033[0;1;33;93;43m....\033[0;1;31;91;43m8"
        "\033[0;1;33;93;43m.\033[0m                     "
        "\033[0;1;31;91;43m88\033[0;33;5;43;103m...:\033[0m"
        "                  \033[0;1;31;91;41m8"
        "\033[0;31;5;41;101m                   \033[0;1;31;91;41m8"
        "\033[0m            \n");
    printf(
        "     \033[0;1;31;91;43m88\033[0;1;33;93;43m....."
        "\033[0;1;30;90;43m8\033[0m               "
        "\033[0;1;30;90;43m8\033[0;1;33;93;43m."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m..."
        "\033[0;1;31;91;43m8\033[0;37;43m@\033[0m"
        "                      \033[0;31;5;41;101m:"
        "             :\033[0m               \n");
    printf(
        "       \033[0;1;30;90;43m8\033[0;33;5;43;103m."
        "\033[0;1;33;93;43m.....\033[0;1;31;91;43m8"
        "\033[0;33;5;43;103m.\033[0;1;33;93;43m.\033[0;1;31;91;43m8"
        "\033[0;31;43mS\033[0;1;30;90;43m@X8\033[0;31;43mS"
        "\033[0;1;30;90;43mX\033[0;1;31;91;43m8\033[0;33;5;43;103m."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m....."
        "\033[0;33;5;43;103m.\033[0;1;30;90;43m8\033[0m"
        "                          \033[0;31;5;41;101mt"
        "         X\033[0m                 \n");
    printf(
        "          \033[0;1;30;90;43mX\033[0;33;5;43;103m."
        "\033[0;1;31;91;43m8\033[0;1;33;93;43m..............."
        "\033[0;1;31;91;43m8\033[0;33;5;43;103m."
        "\033[0;1;30;90;43m@\033[0m"
        "                               \033[0;1;31;91;41m8"
        "\033[0;31;5;41;101m     \033[0;1;31;91;41m8"
        "\033[0m                   \n");
    printf(
        "               \033[0;1;30;90;43mX\033[0;1;31;91;43m8"
        "\033[0;33;5;43;103m.......\033[0;1;31;91;43m8"
        "\033[0;1;30;90;43mX\033[0m"
        "                                       "
        "\033[0;31;5;41;101m.\033[0m                      \n");
    printf("\n");
    printf("  Thank you for running a ZClassic node!\n");
    printf("  You're helping to strengthen the network"
           " and contributing to a social good :)\n");
    printf("\n");
}

static int estimate_net_height(const struct consensus_params *cp,
                               int cur_height, int64_t cur_time)
{
    int64_t now = GetAdjustedTime();
    if (cur_time >= now)
        return cur_height;
    int spacing = (int)consensus_pow_target_spacing(cp, cur_height);
    if (spacing <= 0) spacing = 150;
    int est = cur_height + (int)((now - cur_time) / spacing);
    return ((est + 5) / 10) * 10;
}

/* `ext` is this tick's external-gauge snapshot (see metrics.h): it carries
 * the tip height/time and the peer count, which used to be read here with
 * direct active_chain_tip() / connman_get_node_count() calls into
 * lib/validation and lib/net. */
static int print_stats(struct metrics_context *ctx,
                       const struct metrics_external_gauges *ext)
{
    int lines = 3;

    int height = (int)ext->tip_height;
    int64_t tip_time = ext->tip_time;

    zcl_mutex_lock(&ctx->ms->cs_main);
    struct block_index *best_hdr = ctx->ms->pindex_best_header;
    int hdr_height = best_hdr ? best_hdr->nHeight : height;
    int64_t hdr_time = best_hdr ? (int64_t)best_hdr->nTime : 0;
    bool importing = atomic_load(&ctx->ms->fImporting);
    bool reindexing = atomic_load(&ctx->ms->fReindex);
    zcl_mutex_unlock(&ctx->ms->cs_main);

    size_t connections = (size_t)(ext->connection_count > 0
                                      ? ext->connection_count : 0);

    bool downloading = importing || reindexing ||
                       (tip_time > 0 &&
                        (GetTime() - tip_time) > 24 * 60 * 60);

    if (downloading) {
        int net_h = hdr_height;
        if (hdr_time > 0)
            net_h = estimate_net_height(&ctx->params->consensus,
                                        hdr_height, hdr_time);
        if (net_h < 1) net_h = 1;
        int pct = height * 100 / net_h;
        printf("     Downloading blocks | %d / ~%d (%d%%)           \n",
               height, net_h, pct);
    } else {
        printf("           Block height | %d                      \n",
               height);
    }
    printf("            Connections | %zu    \n", connections);
    printf("\n");

    return lines;
}

static int print_mining_status(bool mining)
{
    int lines = 1;
    if (mining) {
        printf("Mining is active.\n");
        lines += 1;
    } else {
        printf("You are currently not mining.\n");
        printf("To enable mining, add 'gen=1' to your "
               "zclassic.conf and restart.\n");
        lines += 2;
    }
    printf("\n");
    return lines;
}

static int print_metrics(bool mining)
{
    int lines = 3;

    int64_t uptime = GetTime() - g_start_time;
    int days = (int)(uptime / 86400);
    int hours = (int)((uptime % 86400) / 3600);
    int minutes = (int)((uptime % 3600) / 60);
    int seconds = (int)(uptime % 60);

    if (days > 0)
        printf("Since starting this node %d days, %d hours, "
               "%d minutes, %d seconds ago:\n",
               days, hours, minutes, seconds);
    else if (hours > 0)
        printf("Since starting this node %d hours, "
               "%d minutes, %d seconds ago:\n",
               hours, minutes, seconds);
    else if (minutes > 0)
        printf("Since starting this node %d minutes, "
               "%d seconds ago:\n", minutes, seconds);
    else
        printf("Since starting this node %d seconds ago:\n", seconds);

    uint64_t validated = atomic_load(&g_transactions_validated);
    if (validated > 1)
        printf("- You have validated %lu transactions!\n",
               (unsigned long)validated);
    else if (validated == 1)
        printf("- You have validated a transaction!\n");
    else
        printf("- You have validated no transactions.\n");

    if (mining) {
        uint64_t runs = atomic_load(&g_eh_solver_runs);
        printf("- You have completed %lu Equihash solver runs.\n",
               (unsigned long)runs);
        lines++;
    }
    printf("\n");

    return lines;
}

static void *metrics_thread_fn(void *arg)
{
    struct metrics_context *ctx = (struct metrics_context *)arg;
    g_start_time = GetTime();

    bool is_tty = stdout_is_terminal();

    if (is_tty) {
        printf("\033[2J");
        metrics_print_art();
    }

    int64_t metrics_beats = 0;
    while (atomic_load(&ctx->running)) {
        int lines = 1;

        /* Landlock retrofit join — see os_sandbox_landlock_apply_to_self().
         * This thread predates -sandbox=steady's late sandbox entry, so it
         * must join that domain itself; idempotent no-op once joined (or
         * while the sandbox is inactive). Its one FS dependency beyond the
         * datadir grant — fopen("/proc/self/status") below, for RSS — is
         * covered by the extra read-only grant sr_sandbox_enter adds. */
        if (os_sandbox_active())
            (void)os_sandbox_landlock_apply_to_self();

        /* Heartbeat onto the supervisor tree (atomic-only; zero behavior
         * change). Loop count is the progress marker. */
        thread_liveness_beat(&g_metrics_child, ++metrics_beats);

        if (is_tty)
            printf("\033[J");

        /* One external-gauge snapshot per tick, taken BEFORE anything is
         * printed: the console block and the Prometheus block both read
         * it, so they now report the same tip height and peer count
         * instead of sampling the chain twice a few microseconds apart. */
        enum sync_state gss = sync_get_state();
        struct metrics_external_gauges ext = {
            .utxo_count = 0,
            .sync_state = (int)gss,
            .tip_advance_age_seconds = -1,
            .mirror_lag_blocks = -1,
            .mirror_lag_breach_seconds = 0,
            .mirror_lag_critical_seconds = 0,
            .magicbean_peer_count = 0,
            .zclassic_c23_peer_count = 0,
            .header_gap_blocks = -1,
            .tip_height = 0,
            .tip_time = 0,
            .connection_count = 0,
        };
        snprintf(ext.sync_state_name, sizeof(ext.sync_state_name), "%s",
                 sync_state_name(gss));
        if (ctx->external_gauges)
            ctx->external_gauges(&ext, ctx->external_gauges_ctx);

        lines += print_stats(ctx, &ext);
        lines += print_mining_status(ctx->mining);
        lines += print_metrics(ctx->mining);

        /* Update Prometheus node-level gauges */
        {
            int64_t gh = ext.tip_height;
            int64_t gpc = ext.connection_count;
            int64_t gup = GetTime() - g_start_time;

            /* RSS from /proc/self/status (Linux) */
            double grss = 0.0;
            FILE *sf = fopen("/proc/self/status", "r");
            if (sf) {
                char ln[256];
                while (fgets(ln, sizeof(ln), sf)) {
                    long kb;
                    if (sscanf(ln, "VmRSS: %ld kB", &kb) == 1) {
                        grss = (double)kb / 1024.0;
                        break;
                    }
                }
                fclose(sf);
            }

            metrics_prometheus_set_node_gauges(gh, gpc, grss, ext.utxo_count, gup);

            metrics_prometheus_set_sync_state(ext.sync_state, ext.sync_state_name);

            /* Must run after set_node_gauges (uptime) and set_sync_state
             * (sync state) above — metrics_prometheus_set_header_gap reads both
             * as same-tick context for its breach-seconds hysteresis. */
            metrics_prometheus_set_header_gap(ext.header_gap_blocks);

            metrics_prometheus_set_tip_advance_age(
                ext.tip_advance_age_seconds);

            metrics_prometheus_set_mirror_lag(ext.mirror_lag_blocks,
                                       ext.mirror_lag_breach_seconds,
                                       ext.mirror_lag_critical_seconds);

            metrics_prometheus_set_peer_kinds(ext.magicbean_peer_count,
                                       ext.zclassic_c23_peer_count);

            metrics_stage_set_samples(ext.stage_cursor, ext.stage_step_us_ewma);
        }

        if (is_tty) {
            printf("[Press Ctrl+C to exit] "
                   "[Set 'showmetrics=0' to hide]\n");
        } else {
            printf("----------------------------------------\n");
        }

        fflush(stdout);
        platform_sleep_ms(1000);

        if (is_tty)
            printf("\033[%dA", lines);
    }
    /* Publish the abnormal-exit signal so the supervisor can distinguish a
     * dead worker (respawn) from a slow one (stall). A graceful stop marks the
     * child complete first, so this EXITED is ignored there. */
    thread_liveness_worker_exited(&g_metrics_child);
    return NULL;
}

bool metrics_start(struct metrics_context *ctx)
{
    if (!ctx)
        return false;

    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_metrics_started, &expected, true)) {
        ctx->thread_started = true;
        return true; /* another caller already won the spawn */
    }

    atomic_store(&ctx->running, true);
    /* SAFE PERMANENT auto-restart: metrics is a pure periodic printer +
     * Prometheus gauge setter with no consensus/shared mutable state, so
     * re-entering its loop from scratch is a no-op on correctness. Storm cap:
     * 5 restarts / 60 s → then a permanent "thread_restart_storm_zcl_metrics"
     * blocker (never infinite-spawn). */
    // supervised:zcl_metrics (thread_liveness_register_restartable below)
    if (thread_registry_spawn("zcl_metrics", metrics_thread_fn, ctx,
                                  &g_metrics_child.worker_tid) != 0) {
        perror("metrics_start: thread_registry_spawn");
        atomic_store(&ctx->running, false);
        atomic_store(&g_metrics_started, false);
        return false;
    }
    (void)thread_liveness_register_restartable(&g_metrics_child, "zcl_metrics",
                                   /*deadline_secs=*/120,
                                   /*progress_quiet_us=*/0,
                                   metrics_thread_fn, ctx,
                                   /*intensity_max=*/5, /*period_secs=*/60);
    ctx->thread_started = true;
    return true;
}

void metrics_stop(struct metrics_context *ctx)
{
    if (!ctx)
        return;
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_metrics_started, &expected, false))
        return; /* not running */
    thread_liveness_stop_begin(&g_metrics_child);   /* no more auto-restart */
    atomic_store(&ctx->running, false);             /* signal the loop to exit */
    thread_liveness_stop_finish(&g_metrics_child);  /* join current tid + retire */
    ctx->thread_started = false;
}
