/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_runtime_sync_services.c — runtime service-kernel start/stop adapters
 * for the sync-adjacent services that influence the tip / header path.
 *
 * Part of the boot composition root. These ten adapters wrap the long-running
 * services that drive header and body acquisition toward the tip:
 *   - header_probe      (diagnostic header lag probe + supervised poll Job)
 *   - legacy_mirror     (always-on mirror sync against the legacy node)
 *   - gap_fill          (background body gap-fill)
 *   - zclassicd_oracle  (external-node height oracle)
 *   - rolling_anchor    (rolling SHA3 anchor supervisor contract)
 *
 * They are runtime-service start/stop WRAPPERS invoked through the runtime
 * service-kernel spec table (boot_register_runtime_services() in
 * boot_services.c); they are NOT part of the SIGTERM shutdown sequence and
 * touch no coins-flush ordering. Each wrapper operates purely on the
 * boot_svc_ctx passed as ctx — it owns no file-static. Each underlying
 * *_start / *_register owns its own worker thread and supervisor liveness
 * contract inside its service module, so no thread is spawned here.
 *
 * Registered into the runtime service kernel by boot_register_runtime_services()
 * in boot_services.c, so the ten prototypes live in config/boot_internal.h. */

#include "config/boot_internal.h"
#include "services/header_probe.h"
#include "jobs/header_probe_poll.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/gap_fill_service.h"
#include "services/zclassicd_oracle_service.h"
#include "services/rolling_anchor_service.h"
#include "services/segment_sealer_service.h"
#include "services/utxo_mirror_sync_service.h"
#include "net/connman.h"
#include "net/download.h"
#include "chain/chainparams.h"  /* fMineBlocksOnDemand (regtest legacy-mirror skip) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* See config/boot_internal.h for why this predicate is shared rather than
 * re-derived per service. app_ctx is the authority — boot_step_select_chain_
 * and_datadir derives the selected chain from exactly these two fields — with
 * chainparams as the fallback for a ctx-less caller. */
const char *boot_nonmain_network_name(const struct boot_svc_ctx *svc)
{
    if (!svc)
        return NULL;
    if (svc->app_ctx && svc->app_ctx->regtest)
        return "regtest";
    if (svc->app_ctx && svc->app_ctx->testnet)
        return "testnet";
    if (svc->params && strcmp(svc->params->strNetworkID, "main") != 0)
        return svc->params->strNetworkID;
    return NULL;
}

/* Initialize header_probe and register its supervised poll Job (runtime svc). */
bool boot_header_probe_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;
    struct header_probe_config cfg = {0};
    /* Keep header_probe initialized/running for diagnostics and manual
     * use, but leave lockstep catch-up ownership with legacy_mirror. */
    cfg.lag_threshold = 1000000000;
    {
        struct zcl_result hpr = header_probe_init(&cfg, svc->state, svc->params);
        if (!hpr.ok) {
            fprintf(stderr,  // obs-ok:header-probe-init-fail
                    "[header-probe] init failed: %s\n", hpr.message);
            return false;
        }
    }
    /* Register the polling cadence as a supervised Job in the network
     * domain. Same 30 s cadence, same RPC, same accept_block_header path;
     * the supervisor owns liveness so `z23 dumpstate supervisor`
     * exposes last_tick_age_us and ticks_run for the poll.
     *
     * MAINNET-ONLY, because that RPC is a co-located zclassicd on
     * 127.0.0.1:8232 and it is a MAINNET daemon — this poll would feed mainnet
     * headers into a regtest chain every 30 s, and it is an outbound dial into
     * the operator's live daemon from a fixture that was supposed to be sealed.
     * Measured: two dials in a 75 s `-regtest` fixture run. The init above
     * stays on every network (it dials nothing; it keeps the RPC + dumpstate
     * introspection available); only the polling dial is gated. */
    const char *net = boot_nonmain_network_name(svc);
    if (net) {
        printf("[header-probe] poll Job skipped on %s (it polls a mainnet "
               "zclassicd; a non-mainnet node must not dial it)\n", net);
        return true;
    }
    header_probe_poll_register();
    if (header_probe_poll_is_registered()) {
        printf("[header-probe] poll Job registered with net supervisor\n");
        return true;
    }
    fprintf(stderr,  // obs-ok:header-probe-poll-fallback
            "[header-probe] WARN poll Job register failed; "
            "header_probe RPC + state introspection still available\n");
    return true;  /* non-fatal — manual native diagnostics still work */
}

/* Stop the header_probe runtime service. */
void boot_header_probe_stop(void *ctx)
{
    (void)ctx;
    /* No-op: supervisor unregister happens at supervisor_stop(). */
}

/* Initialize and start the always-on legacy mirror sync (runtime svc). */
bool boot_legacy_mirror_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;
    const char *oracle_mode = getenv("ZCL_LEGACY_ORACLE_MODE");
    if (oracle_mode && strcmp(oracle_mode, "off") == 0) {
        printf("[legacy-mirror] disabled by -legacyoracle=off\n");
        return true;
    }
    /* The legacy mirror parity-compares this node against a co-located
     * zclassicd oracle. On regtest (fMineBlocksOnDemand) there is no zclassicd
     * regtest counterpart, so the mirror can only mis-compare against a
     * mainnet zclassicd — every height diverges, tripping mirror.hash-
     * disagreement / mirror.divergence_located and driving the node into an
     * oracle-divergence panic that stalls an otherwise-healthy regtest sync
     * (observed wedging make netdisrupt-stopwatch's follower). Skip it there;
     * on main/testnet the mirror runs unchanged. */
    if (svc->params && svc->params->fMineBlocksOnDemand) {
        printf("[legacy-mirror] skipped on regtest (no zclassicd counterpart)\n");
        return true;
    }
    struct legacy_mirror_sync_config cfg = {0};
    cfg.enabled = true;
    if (!legacy_mirror_sync_init(&cfg, svc->state, svc->coins_tip,
                                 svc->params, svc->datadir).ok)
        return false;
    if (legacy_mirror_sync_start().ok) {
        printf("[legacy-mirror] always-on mirror sync started\n");
        return true;
    }
    return false;
}

/* Stop the legacy mirror sync runtime service. */
void boot_legacy_mirror_stop(void *ctx)
{
    (void)ctx;
    legacy_mirror_sync_stop();
}

/* Start the background body gap-fill service (runtime svc). */
static void boot_gap_fill_dispatch_wake(void *ctx)
{
    connman_wake_message_handler((struct connman *)ctx);
}

bool boot_gap_fill_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;
    gap_fill_set_dispatch_wake(boot_gap_fill_dispatch_wake, svc->connman);
    struct zcl_result gr = gap_fill_start(svc->state, msg_get_download_mgr());
    if (gr.ok) {
        printf("[gap-fill] background gap-fill service started\n");
        return true;
    }
    gap_fill_set_dispatch_wake(NULL, NULL);
    fprintf(stderr, "WARNING: gap_fill_start failed: %s:%d code=%d %s\n",
            gr.source_file, gr.source_line, gr.code, gr.message);
    return false;
}

/* Stop the background body gap-fill service. */
void boot_gap_fill_stop(void *ctx)
{
    (void)ctx;
    gap_fill_stop();
}

/* Start the external zclassicd height oracle (runtime svc).
 *
 * MAINNET-ONLY. This service polls a co-located zclassicd on 127.0.0.1:8232 in
 * the background, and it used to ignore its ctx entirely — so a `-regtest`
 * fixture with a deliberately dead `-connect` sink still dialed the operator's
 * live daemon. A mainnet daemon's height is meaningless to a regtest or testnet
 * node anyway; the only thing the dial could produce was the leak. */
bool boot_zclassicd_oracle_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    const char *oracle_mode = getenv("ZCL_LEGACY_ORACLE_MODE");
    if (oracle_mode && strcmp(oracle_mode, "off") == 0) {
        printf("[oracle] zclassicd oracle disabled by -legacyoracle=off\n");
        return true;
    }
    const char *net = boot_nonmain_network_name(svc);
    if (net) {
        printf("[oracle] zclassicd height oracle skipped on %s (the oracle is "
               "a mainnet daemon; a non-mainnet node must not dial it)\n", net);
        return true;
    }
    if (zclassicd_oracle_start().ok)
        printf("[oracle] zclassicd oracle service started\n");
    return true;
}

/* Stop the external zclassicd height oracle. */
void boot_zclassicd_oracle_stop(void *ctx)
{
    (void)ctx;
    zclassicd_oracle_stop();
}

/* Register the rolling SHA3 anchor supervisor contract (runtime svc). */
bool boot_rolling_anchor_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;
    if (rolling_anchor_start(svc->state, svc->datadir).ok)
        printf("[rolling-anchor] supervisor contract registered\n");
    return true;
}

/* Stop the rolling SHA3 anchor service. */
void boot_rolling_anchor_stop(void *ctx)
{
    (void)ctx;
    rolling_anchor_stop();
}

/* Sealed-history segment sealer (runtime svc). Owns a file-static service
 * instance (the kernel calls start/stop once each); g_segment_sealer points at
 * it for `z23 dumpstate segment_sealer`. OFF BY DEFAULT — the thread runs
 * supervised and heartbeats, but seals nothing unless ZCL_SEGMENT_SEALER=1, so a
 * default node's on-disk state is unchanged. When enabled it seals finalized
 * (fully-below-frontier) 10k segments into <datadir>/segments; the fold's block
 * reader then serves those bodies from the hash-verified segment store instead
 * of an unverified blk*.dat re-read (block_parse_cache bpc_segment_try). */
static struct segment_sealer_service g_boot_segment_sealer;

static bool boot_segment_sealer_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->state)
        return false;
    segment_sealer_init(&g_boot_segment_sealer, svc->state, svc->datadir);
    g_segment_sealer = &g_boot_segment_sealer;
    struct zcl_result r = segment_sealer_start(&g_boot_segment_sealer);
    if (r.ok) {
        printf("[segment_sealer] runtime service started (sealed-history ROM)\n");
        return true;
    }
    fprintf(stderr, "WARNING: segment_sealer_start failed: %s:%d code=%d %s\n",
            r.source_file, r.source_line, r.code, r.message);
    g_segment_sealer = NULL;
    return false;
}

static void boot_segment_sealer_stop(void *ctx)
{
    (void)ctx;
    segment_sealer_stop(&g_boot_segment_sealer);
    g_segment_sealer = NULL;
}

/* Register the sealed-history sealer into the runtime service kernel (the
 * boot_utxo_mirror_sync_register pattern — keeps boot_services.c's spec table
 * unchanged). Called from boot_register_runtime_services(). */
bool boot_segment_sealer_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "segment_sealer",
        .start = boot_segment_sealer_start,
        .stop = boot_segment_sealer_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}

/* Start the explorer-mirror feeder that keeps node.db's `utxos` table synced
 * to the authoritative coins_kv set (runtime svc). Owns a file-static service
 * instance (the kernel calls start/stop once each); g_utxo_mirror_sync points
 * at it for diagnostics. node.db-only — never touches the consensus path. */
static struct utxo_mirror_sync_service g_boot_utxo_mirror;

bool boot_utxo_mirror_sync_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;
    const char *mirror_mode = getenv("ZCL_UTXO_MIRROR_MODE");
    if (mirror_mode && strcmp(mirror_mode, "off") == 0) {
        printf("[utxo_mirror] disabled by -utxomirror=off\n");
        return true;
    }
    struct node_db *ndb = boot_node_db(svc);
    if (!ndb || !ndb->open) {
        /* No mirror to feed (e.g. store-less runtime profile) — skip cleanly.
         * OPTIONAL service, so returning false only logs a non-fatal warning. */
        return false;
    }
    utxo_mirror_sync_init(&g_boot_utxo_mirror, ndb);
    g_utxo_mirror_sync = &g_boot_utxo_mirror;
    struct zcl_result r = utxo_mirror_sync_start(&g_boot_utxo_mirror);
    if (r.ok) {
        printf("[utxo_mirror] explorer-mirror feeder started\n");
        return true;
    }
    fprintf(stderr, "WARNING: utxo_mirror_sync_start failed: %s:%d code=%d %s\n",
            r.source_file, r.source_line, r.code, r.message);
    g_utxo_mirror_sync = NULL;
    return false;
}

/* Stop the explorer-mirror feeder. */
void boot_utxo_mirror_sync_stop(void *ctx)
{
    (void)ctx;
    utxo_mirror_sync_stop(&g_boot_utxo_mirror);
    g_utxo_mirror_sync = NULL;
}

/* Register the explorer-mirror feeder into the runtime service kernel (the
 * boot_utxo_parity_register pattern — keeps boot_services.c's spec table
 * unchanged). Called from boot_register_runtime_services(). */
bool boot_utxo_mirror_sync_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "utxo_mirror_sync",
        .start = boot_utxo_mirror_sync_start,
        .stop = boot_utxo_mirror_sync_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
