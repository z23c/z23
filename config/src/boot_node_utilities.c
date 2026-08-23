/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_node_utilities.c — node operator utility entry points.
 *
 * Part of the boot composition root (extracted from boot_services.c). This
 * unit holds the small operator-facing utilities that hang off the live boot
 * context: -addnode connection setup (app_add_node), the metrics thread
 * lifecycle (app_start_metrics / app_stop_metrics) with its injected external
 * gauge callback (boot_metrics_external_gauges), the Prometheus RPC-counter
 * source (app_wire_metrics_sources), the async sync-state observer that logs
 * sync-pipeline transitions (boot_sync_state_logger), and the bootstrap-source
 * report, which is where the single advisory peer-selection weight feed is
 * started (boot_seniority_start, config/boot_seniority.h — that whole subsystem
 * lives in its own translation unit).
 *
 * This TU is the single place that reads live subsystem state on behalf of
 * lib/metrics. lib/metrics deliberately links against neither lib/net,
 * lib/validation nor lib/rpc; every number it publishes about the chain tip,
 * the peer count, or the RPC middleware arrives through one of the two
 * callbacks defined here.
 *
 * Owns no file-statics. The public app_* entry points reach the live context
 * through boot_active_svc() (declared in boot_internal.h, called from main.c);
 * boot_metrics_external_gauges is private here (only app_start_metrics injects
 * it). boot_sync_state_logger is wired by app_init_services in boot_services.c,
 * so its prototype lives in config/boot_internal.h; app_wire_metrics_sources is
 * called unconditionally from main() and is declared in config/boot.h. */

#include "config/boot_internal.h"
#include "config/boot_seniority.h"
#include "services/node_health_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/sync_monitor.h"
#include "services/chain_state_service.h"
#include "jobs/reducer_frontier.h"
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "chain/chainparams.h"
#include "metrics/prometheus_metrics.h"
#include "rpc/http_middleware.h"
#include "validation/chainstate.h"
#include "sync/sync_state.h"
#include "event/event.h"
#include "net/connman.h"
#include "net/addrman.h"
#include "net/addnode_file.h"
#include "net/netbase.h"
#include "util/log_macros.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* External-gauge callback injected into the metrics thread: snapshots
 * sync state, UTXO count, tip-advance age, mirror lag, and peer counts. */
static void boot_metrics_external_gauges(
    struct metrics_external_gauges *out,
    void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    enum sync_state state;
    struct legacy_mirror_sync_stats lms = {0};
    struct node_health_snapshot nhs = {0};

    if (!out)
        return;

    state = sync_get_state();
    out->sync_state = (int)state;
    snprintf(out->sync_state_name, sizeof(out->sync_state_name), "%s",
             sync_state_name(state));

    if (svc && svc->node_db && svc->node_db->open)
        out->utxo_count = node_db_utxo_count(svc->node_db);

    out->tip_advance_age_seconds = sync_monitor_tip_advance_age();

    legacy_mirror_sync_stats_snapshot(&lms);
    out->mirror_lag_blocks = lms.enabled && lms.lag_known
                                  ? (int64_t)lms.lag : -1;
    out->mirror_lag_breach_seconds = lms.lag_breach_seconds;
    out->mirror_lag_critical_seconds = lms.lag_critical_seconds;

    if (svc && svc->state) {
        node_health_collect(&nhs, svc->node_db, svc->state);
        out->magicbean_peer_count = (int64_t)nhs.magicbean_peer_count;
        out->zclassic_c23_peer_count = (int64_t)nhs.zclassic_c23_peer_count;
    }

    /* header_gap_growing input: best-known header height minus served
     * height H*. csr_header_height() is a cheap in-memory, lock-guarded
     * read (see its doc comment — deliberately not csr_snapshot(), which
     * also runs SQLite queries); reducer_frontier_provable_tip_cached()
     * is a lock-free atomic. Both are safe to call from the metrics
     * thread. -1 until the chain-state repository has a header tip. */
    out->header_gap_blocks = -1;
    {
        int64_t hh = csr_header_height(csr_instance());
        if (hh >= 0) {
            int64_t served = (int64_t)reducer_frontier_provable_tip_cached();
            out->header_gap_blocks = hh - served;
        }
    }

    /* Per-reducer-stage telemetry (Phase E4): fixed 8-stage cursor +
     * step_us_ewma snapshot, forwarded to lib/metrics/src/stage_metrics.c
     * by the metrics tick (lib/metrics/src/metrics.c) since lib/ cannot
     * include these app/jobs headers directly. Order MUST match
     * metrics_stage_name()'s canonical order in
     * lib/metrics/include/metrics/stage_metrics.h — mirrors the same
     * fixed-order rows[] pattern diag_profile_push_stage_ewma() uses in
     * app/controllers/src/diagnostics_registry.c for the `profile`
     * command's stage_ewma block. */
    out->stage_cursor[0]       = (int64_t)header_admit_stage_cursor();
    out->stage_step_us_ewma[0] = header_admit_stage_step_us_ewma();
    out->stage_cursor[1]       = (int64_t)validate_headers_stage_cursor();
    out->stage_step_us_ewma[1] = validate_headers_stage_step_us_ewma();
    out->stage_cursor[2]       = (int64_t)body_fetch_stage_cursor();
    out->stage_step_us_ewma[2] = body_fetch_stage_step_us_ewma();
    out->stage_cursor[3]       = (int64_t)body_persist_stage_cursor();
    out->stage_step_us_ewma[3] = body_persist_stage_step_us_ewma();
    out->stage_cursor[4]       = (int64_t)script_validate_stage_cursor();
    out->stage_step_us_ewma[4] = script_validate_stage_step_us_ewma();
    out->stage_cursor[5]       = (int64_t)proof_validate_stage_cursor();
    out->stage_step_us_ewma[5] = proof_validate_stage_step_us_ewma();
    out->stage_cursor[6]       = (int64_t)utxo_apply_stage_cursor();
    out->stage_step_us_ewma[6] = utxo_apply_stage_step_us_ewma();
    out->stage_cursor[7]       = (int64_t)tip_finalize_stage_cursor();
    out->stage_step_us_ewma[7] = tip_finalize_stage_step_us_ewma();

    /* Active-chain tip + peer count. lib/metrics used to call
     * active_chain_tip() (lib/validation) and connman_get_node_count()
     * (lib/net) straight from its tick, bypassing this seam; both reads
     * belong here, where the boot context already owns cs_main and the
     * connman. The tip read is under cs_main exactly as it was. */
    if (svc && svc->state) {
        zcl_mutex_lock(&svc->state->cs_main);
        struct block_index *tip = active_chain_tip(&svc->state->chain_active);
        out->tip_height = tip ? (int64_t)tip->nHeight : 0;
        out->tip_time   = tip ? (int64_t)tip->nTime : 0;
        zcl_mutex_unlock(&svc->state->cs_main);
    }
    if (svc && svc->connman)
        out->connection_count = (int64_t)connman_get_node_count(svc->connman);
}

/* Prometheus `zcl_rpc_*` counter source. lib/metrics must not link against
 * lib/rpc, so the renderer pulls through this callback (registered by
 * app_wire_metrics_sources below) instead of calling
 * rpc_http_middleware_get_global()/stats_snapshot() itself. Called with the
 * renderer's lock held — do nothing here but snapshot and copy. */
static void boot_metrics_rpc_http_gauges(struct metrics_rpc_http_gauges *out,
                                         void *ctx)
{
    (void)ctx;
    if (!out)
        return;

    struct rpc_http_stats_snapshot snap;
    rpc_http_middleware_stats_snapshot(rpc_http_middleware_get_global(), &snap);

    out->allowed             = snap.allowed;
    out->rate_limited_global = snap.rate_limited_global;
    out->rate_limited_per_ip = snap.rate_limited_per_ip;
    out->banned_rejected     = snap.banned_rejected;
    out->bans_issued         = snap.bans_issued;
    out->auth_failures       = snap.auth_failures;
    out->tracked_ips         = (uint64_t)snap.tracked_ips;
    out->active_bans         = (uint64_t)snap.active_bans;
}

/* Wire the metrics sources that are NOT tied to the metrics thread's
 * lifetime. The Prometheus dump is served on demand (native `meta`
 * handler, HTTPS, and the RPC HTTP server), including on a node started
 * with -showmetrics=0 where app_start_metrics() never runs — so main()
 * calls this unconditionally rather than folding it into app_start_metrics. */
void app_wire_metrics_sources(void)
{
    metrics_prometheus_set_rpc_http_source(boot_metrics_rpc_http_gauges, NULL);
}

/* ── Utility functions ─────────────────────────────────────── */

/* Resolve and open an outbound connection to a -addnode host[:port]. */
void app_add_node(const char *host, int port)
{
    struct boot_svc_ctx *svc = boot_active_svc();
    char hostbuf[256];
    int parsed_port = 0;
    split_host_port(host, hostbuf, sizeof(hostbuf), &parsed_port);
    if (port <= 0)
        port = parsed_port;

    uint16_t use_port = port > 0 ? (uint16_t)port
                                 : svc->connman->manager.default_port;

    struct net_address addr;
    net_address_init(&addr);
    addr.svc.port = use_port;

    /* Operator-directed onion peer: parse the v3 hostname locally and dial
     * it through the embedded Tor stream bridge. A .onion name must NEVER
     * reach getaddrinfo — no DNS leak, no clearnet fallback. */
    if (net_name_is_onion(hostbuf)) {
        if (!net_addr_from_onion(hostbuf, &addr.svc.addr)) {
            printf("Invalid .onion addnode %s (not a v3 onion address; "
                   "never resolved via DNS)\n", hostbuf);
            return;
        }
        printf("Connecting to onion addnode %s:%u\n", hostbuf, use_port);
        connman_open_connection(svc->connman, &addr);
        return;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(hostbuf, NULL, &hints, &res) == 0 && res) {
        if (res->ai_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)res->ai_addr;
            memset(addr.svc.addr.ip, 0, 10);
            addr.svc.addr.ip[10] = 0xff;
            addr.svc.addr.ip[11] = 0xff;
            memcpy(addr.svc.addr.ip + 12, &s4->sin_addr, 4);
        } else if (res->ai_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)res->ai_addr;
            memcpy(addr.svc.addr.ip, &s6->sin6_addr, 16);
        }
        freeaddrinfo(res);

        printf("Connecting to addnode %s:%u\n", hostbuf, use_port);
        connman_open_connection(svc->connman, &addr);
    } else {
        printf("Failed to resolve addnode %s\n", hostbuf);
    }
}

static void app_add_node_from_file_cb(const char *host, uint16_t port, void *ctx)
{
    (void)ctx;
    app_add_node(host, (int)port);
}

void app_add_nodes_from_file(const char *path)
{
    if (!path || !*path)
        return;
    addnode_file_load(path, app_add_node_from_file_cb, NULL);
}

void app_log_bootstrap_sources(const struct chain_params *params,
                                struct connman *cm)
{
    if (!params || !cm)
        return;

    const char *home = getenv("HOME");
    bool operator_onion_seed_file = false;
    if (home) {
        char p[512];
        snprintf(p, sizeof(p), "%s/.config/zclassic23/onion-seeds", home);
        operator_onion_seed_file = access(p, R_OK) == 0;
    }
    /* The ONE advisory influence path into peer selection, and the supervised
     * worker that keeps it rotating with the ranking epoch — see
     * config/boot_seniority.h. Never blocks boot, never fails it. */
    boot_seniority_start(&cm->manager.addrman);
    size_t addrman_loaded = addrman_size(&cm->manager.addrman);
    size_t total_sources = params->nSeeds + params->nFixedSeeds +
                            params->nOnionSeeds +
                            (operator_onion_seed_file ? 1 : 0) +
                            (addrman_loaded > 0 ? 1 : 0);
    printf("[net] bootstrap sources: dns_seeds=%zu fixed_seeds=%zu "
           "onion_seeds=%zu operator_onion_seed_file=%d "
           "addrman_loaded_peers=%zu total_sources=%zu\n",
           params->nSeeds, params->nFixedSeeds, params->nOnionSeeds,
           operator_onion_seed_file ? 1 : 0, addrman_loaded, total_sources);
}

/* Start the Prometheus metrics thread with injected external gauges. */
void app_start_metrics(bool mining)
{
    struct boot_svc_ctx *svc = boot_active_svc();
    svc->metrics->ms = svc->state;
    svc->metrics->params = chain_params_get();
    svc->metrics->mining = mining;
    svc->metrics->external_gauges = boot_metrics_external_gauges;
    svc->metrics->external_gauges_ctx = svc;
    if (!metrics_start(svc->metrics))
        fprintf(stderr, "WARNING: failed to start metrics thread\n");
}

/* Stop the metrics thread. */
void app_stop_metrics(void)
{
    struct boot_svc_ctx *svc = boot_active_svc();
    metrics_stop(svc->metrics);
}

/* ── Sync state observer ──────────────────────────────────────── *
 * Async observer that logs sync state transitions, tip updates,
 * block connections, and reorgs. Provides high-level observability
 * of the sync pipeline without blocking any P2P or validation thread.
 *
 * Registered at boot via event_observe_async() for:
 *   EV_SYNC_STATE_CHANGE — sync FSM transitions
 *   EV_TIP_UPDATED       — chain tip advances
 *   EV_BLOCK_CONNECTED    — individual blocks connected
 *   EV_REORG_START        — chain reorganization begins */
void boot_sync_state_logger(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)ctx;
    const char *msg = (payload_len > 0 && payload) ? (const char *)payload : "";

    switch (type) {
    case EV_SYNC_STATE_CHANGE:
        printf("[observer] sync state → %s\n", msg);
        break;
    case EV_TIP_UPDATED:
        /* Only log major milestones to avoid flooding */
        break;
    case EV_BLOCK_CONNECTED:
        break; /* too noisy for printf, event log captures it */
    case EV_REORG_START:
        fprintf(stderr, "[observer] REORG: %s (peer=%u)\n", msg, peer_id);
        break;
    default:
        break;
    }
    fflush(stdout);
}
