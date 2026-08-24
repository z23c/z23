/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Clearnet frontend service lifecycle: the start/stop adapters for the
 * operator-facing surfaces — local file-transfer server, JSON-RPC HTTP
 * endpoint, block-explorer API cache, HTTPS explorer, the miner, the
 * embedded Tor onion service, and the store payment processor — plus the
 * onion request adapter and the spec-table registrar that wires them into
 * svc->frontend_kernel.
 *
 * Part of the boot composition root (paired with config/src/boot_services.c
 * via config/boot_internal.h). These services are OPTIONAL and gated on the
 * runtime profile; a start failure degrades the node rather than crashing it.
 * NONE of this file participates in the SIGTERM shutdown sequence — the
 * frontend kernel is torn down by zcl_service_kernel_stop_all() from
 * boot_services.c's shutdown path. The thread-spawning surfaces (HTTPS, Tor,
 * miner, file server) own their internal worker lifecycles inside the called
 * library functions; these adapters spawn no threads of their own.
 */

#include "config/boot_internal.h"
#include "config/boot_background_workers.h"
#include "config/boot_msg_callbacks.h"
#include "config/boot_zcode_swarm.h"
#include "controllers/api_controller.h"
#include "controllers/explorer_controller.h"
#include "controllers/store_buyer_controller.h"
#include "net/file_service.h"
#include "net/rom_seed.h"
#include "config/rom_bundle_admission.h"
#include "net/https_server.h"
#include "util/util.h"
#include "net/onion_service.h"
#include "net/tor_integration.h"
#include "util/log_macros.h"
#include "rpc/httpserver.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "vcs/package_store.h"
#include "config/boot_zcode_swarm.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

extern _Atomic int g_deferred_proof_validation_below_height;

/* Tor → controller bridge: hands an onion HTTP request straight to the same
 * controller surface the clearnet endpoints use (no SOCKS, no port). */
static size_t onion_request_adapter(const char *method, const char *path,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *response, size_t response_max,
                                    void *user_data);

static bool boot_file_service_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !boot_profile_has_file_service(svc->app_ctx))
        return true;
    if (svc->defer_offer_service) {
        printf("File service server deferred during fresh bootstrap receiver mode\n");
        return true;
    }
    fs_server_start(svc->datadir, (uint16_t)svc->app_ctx->fs_port);
    return true;
}

static void boot_file_service_stop(void *ctx)
{
    (void)ctx;
    fs_server_stop();
}

/* ROM artifact seeding: register + announce the free/capped ROM/sync artifacts
 * (consensus-state bundle + header seed) present in the datadir. Enabled by
 * default alongside the file service; disabled with -noromseed. Caps overridable
 * with -romseed-peer-bps / -romseed-global-bps / -romseed-max-inflight.
 *
 * -rombundlereplicadir=PATH additionally scans a SECOND, operator-designated
 * directory (typically fed by tools/scripts/rom-bundle-replicate.sh from a
 * second disk or a sibling node) and admits any consensus-state bundle found
 * there into the SAME rom_seed catalog, but ONLY through the receipt-gated
 * path (config/rom_bundle_admission.h) — a bundle with no adjoining verified
 * consensus_state_replay_receipt.v1 is never registered, so this node never
 * serves it. This is how a bundle+receipt pair produced/verified on one
 * machine turns any node holding a replicated copy into a P2P recovery
 * source, closing the "lives on ONE disk" single point of failure without
 * weakening rom_seed's own untrusted-delivery model (docs/ROM_DELIVERY.md) —
 * every fetcher still re-verifies content after download regardless of what
 * either scan path admitted. */
static bool boot_rom_seed_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !boot_profile_has_file_service(svc->app_ctx))
        return true;
    if (svc->defer_offer_service)
        return true;
    if (!GetBoolArg("-romseed", true)) {
        rom_seed_set_enabled(false);
        printf("ROM seed: disabled via -noromseed\n");
        return true;
    }
    rom_seed_set_enabled(true);

    int64_t peer_bps = GetArgInt("-romseed-peer-bps", 0);
    int64_t global_bps = GetArgInt("-romseed-global-bps", 0);
    int64_t inflight = GetArgInt("-romseed-max-inflight", 0);
    if (peer_bps > 0) rom_seed_set_peer_bps_cap((uint64_t)peer_bps);
    if (global_bps > 0) rom_seed_set_global_bps_cap((uint64_t)global_bps);
    if (inflight > 0) rom_seed_set_max_inflight_per_peer((uint32_t)inflight);

    rom_seed_start_scan(svc->datadir, (uint16_t)svc->app_ctx->fs_port);

    const char *replica_dir = GetArg("-rombundlereplicadir", "");
    if (replica_dir && replica_dir[0])
        rom_bundle_admission_start_scan(replica_dir);
    return true;
}

static void boot_rom_seed_stop(void *ctx)
{
    (void)ctx;
    rom_bundle_admission_stop_scan();
    rom_seed_stop_scan();
}

static bool boot_rpc_http_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx)
        return false;
    set_rpc_warmup_finished();
    rpc_http_start(svc->rpc_table, (uint16_t)svc->app_ctx->rpc_port,
                   svc->app_ctx->rpc_user, svc->app_ctx->rpc_password,
                   svc->datadir);
    return true;
}

static void boot_rpc_http_stop(void *ctx)
{
    (void)ctx;
    rpc_http_stop();
    /* Symmetry with boot_rpc_http_start's set_rpc_warmup_finished(). The
     * service kernel supports stop_all -> start_all (and start_all's own
     * partial-failure rollback stops this service mid-call), so leaving the
     * flag disarmed would bring the node back up answering RPC as "ready"
     * while it re-initialises — a wrong answer instead of a clear one. */
    set_rpc_warmup_started("RPC server restarting");
}

/* The rpc_http frontend service spec. boot_register_frontend_services()
 * installs exactly this value, so the restart regression test can drive a
 * stop_all -> start_all cycle over the REAL hooks without also booting Tor,
 * the explorer and the miner — and can never drift from what boots. */
struct zcl_service_spec boot_frontend_rpc_http_spec(struct boot_svc_ctx *svc)
{
    return (struct zcl_service_spec){
        .name = "rpc_http",
        .start = boot_rpc_http_start,
        .stop = boot_rpc_http_stop,
        .ctx = svc,
    };
}

/* Point the explorer + API cache backends at the local JSON-RPC endpoint,
 * preferring the .cookie credential and falling back to configured user/pass.
 * Also called once directly from app_init_services in boot_services.c. */
void boot_configure_frontend_rpc(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->app_ctx)
        return;

    char cookie_path[1024], cookie[256] = "";
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", svc->datadir);
    FILE *cf = fopen(cookie_path, "r");
    if (cf) {
        size_t n = fread(cookie, 1, sizeof(cookie) - 1, cf);
        fclose(cf);
        cookie[n] = '\0';
        char *nl = strchr(cookie, '\n');
        if (nl)
            *nl = '\0';
        char *colon = strchr(cookie, ':');
        if (colon) {
            *colon = '\0';
            api_set_rpc_backend(cookie, colon + 1, svc->app_ctx->rpc_port);
            explorer_set_rpc(cookie, colon + 1, svc->app_ctx->rpc_port);
            return;
        }
    }

    if (svc->app_ctx->rpc_user && svc->app_ctx->rpc_password) {
        api_set_rpc_backend(svc->app_ctx->rpc_user,
                            svc->app_ctx->rpc_password,
                            svc->app_ctx->rpc_port);
        explorer_set_rpc(svc->app_ctx->rpc_user,
                         svc->app_ctx->rpc_password,
                         svc->app_ctx->rpc_port);
        return;
    }

    api_set_rpc_backend(NULL, NULL, svc->app_ctx->rpc_port);
    explorer_set_rpc(NULL, NULL, svc->app_ctx->rpc_port);
}

static bool boot_api_cache_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !boot_profile_has_explorer(svc->app_ctx))
        return true;

    int chain_tip_h = active_chain_height(&svc->state->chain_active);
    int best_header = svc->state->pindex_best_header ?
        svc->state->pindex_best_header->nHeight : chain_tip_h;
    if (best_header - chain_tip_h > 1000) {
        printf("API cache refresh deferred during IBD "
               "(chain=%d, headers=%d, behind=%d)\n",
               chain_tip_h, best_header, best_header - chain_tip_h);
        return true;
    }

    boot_configure_frontend_rpc(svc);
    api_start_cache();
    return true;
}

static void boot_api_cache_stop(void *ctx)
{
    (void)ctx;
    api_stop_cache();
}

static bool boot_https_explorer_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !boot_profile_has_explorer(svc->app_ctx))
        return true;

    char cert_path[1024], key_path[1024];
    snprintf(cert_path, sizeof(cert_path), "%s/ssl/fullchain.pem",
             svc->datadir);
    snprintf(key_path, sizeof(key_path), "%s/ssl/privkey.pem",
             svc->datadir);
    if (access(cert_path, R_OK) != 0 || access(key_path, R_OK) != 0) {
        printf("HTTPS: no cert at %s - block explorer not on clearnet\n",
               cert_path);
        return true;
    }

    boot_configure_frontend_rpc(svc);

    int chain_tip_h = active_chain_height(&svc->state->chain_active);
    int best_header = svc->state->pindex_best_header ?
        svc->state->pindex_best_header->nHeight : chain_tip_h;
    bool near_tip = (best_header - chain_tip_h < 1000) &&
                    (chain_tip_h > g_deferred_proof_validation_below_height - 10000);
    /* Optional TLS servername (-httpsdomain=). NULL is fine: with a single
     * cert the server presents that cert regardless of SNI. */
    const char *https_domain = svc->app_ctx->https_domain;
    if (near_tip) {
        https_server_start_on_port(cert_path, key_path, https_domain,
                                   svc->app_ctx->https_port,
                                   svc->app_ctx->https_port - 363);
    } else {
        printf("HTTPS: deferred during IBD (chain=%d, headers=%d, "
               "behind=%d). Will start when near tip.\n",
               chain_tip_h, best_header, best_header - chain_tip_h);
        static char s_cert[1024], s_key[1024];
        strncpy(s_cert, cert_path, sizeof(s_cert) - 1);
        strncpy(s_key, key_path, sizeof(s_key) - 1);
        https_deferred_set(s_cert, s_key, https_domain);
    }
    return true;
}

static void boot_https_explorer_stop(void *ctx)
{
    (void)ctx;
    https_server_stop();
}

static bool boot_miner_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    const struct app_context *app = svc ? svc->app_ctx : NULL;
    if (!svc || !app || !app->gen)
        return true;

    svc->gen->ms = svc->state;
    svc->gen->coins_tip = svc->coins_tip;
    svc->gen->mempool = svc->mempool;
    svc->gen->params = svc->params;
    svc->gen->num_threads = app->gen_threads > 0 ? app->gen_threads : 1;
    svc->gen->block_found = boot_submit_mined_block;
    svc->gen->block_found_ctx = svc;
    svc->gen->coinbase_script.size = 0;

    if (app->miner_address) {
        size_t pk_pfx_len, sc_pfx_len;
        const unsigned char *pk_pfx = chain_params_base58_prefix(
            svc->params, B58_PUBKEY_ADDRESS, &pk_pfx_len);
        const unsigned char *sc_pfx = chain_params_base58_prefix(
            svc->params, B58_SCRIPT_ADDRESS, &sc_pfx_len);
        struct tx_destination dest;
        if (decode_destination(app->miner_address, pk_pfx, pk_pfx_len,
                               sc_pfx, sc_pfx_len, &dest))
            script_for_destination(&svc->gen->coinbase_script, &dest);
    }

    gen_start(svc->gen);
    return true;
}

static void boot_miner_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (svc && svc->gen && svc->gen->running)
        gen_stop(svc->gen);
}

bool boot_onion_tor_start_early(const struct app_context *app)
{
    if (!app || !app->datadir)
        return false;

    char onion_dir[512];
    snprintf(onion_dir, sizeof(onion_dir), "%s/onion-keys", app->datadir);
    struct stat onion_st;
    bool has_onion_keys = (stat(onion_dir, &onion_st) == 0);

    if (!boot_profile_has_onion(app) && !has_onion_keys) {
        if (app->onion_persist || app->onion_rotate)
            fprintf(stderr,
                    "Warning: -onion-persist/-onion-rotate have no effect: "
                    "Tor is not enabled (use -tor or "
                    "-profile=onion-node)\n");
        printf("Tor: skipped (use -tor or -profile=onion-node to enable)\n");
        return true;
    }

    tor_integration_mark_requested();
    tor_integration_configure_identity(app->onion_persist, app->onion_rotate);
    onion_service_start(app->datadir);
    tor_integration_set_handler(onion_request_adapter, NULL);
    printf("Starting embedded Tor (parallel with chain boot)...\n");
    if (!tor_integration_start(app->datadir, (uint16_t)app->p2p_port) ||
        !tor_integration_is_enabled()) {
        LOG_FAIL("onion_tor",
                 "Tor was requested (-tor or onion-node) but did not start; "
                 "refusing to report READY=1 as a no-onion node");
    }
    const char *onion = tor_integration_get_onion_address();
    if (onion)
        printf("Tor .onion address: %s\n", onion);
    else
        printf("Tor: bootstrapping...\n");
    return true;
}

static bool boot_onion_tor_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx)
        return false;
    return boot_onion_tor_start_early(svc->app_ctx);
}

static void boot_onion_tor_stop(void *ctx)
{
    (void)ctx;
    tor_integration_stop();
    onion_service_stop();
}

/* Store BUYER — the programmatic buying half of the store, gated on the same
 * profile as the store itself.
 *
 * This is a plain command registration rather than a service spec because it
 * must happen while the RPC table is still being built: app_init_services
 * calls it alongside the wallet and ZSLP registrations, long before
 * boot_rpc_http_start hands that table to the listener. It lives in this file
 * because this file already owns the store's lifecycle (the payment processor
 * below), not in boot_services.c, which is at its size ceiling. */
void boot_register_store_buyer_rpc(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->app_ctx || !boot_profile_has_store(svc->app_ctx))
        return;
    rpc_store_buyer_set_state(svc->app_ctx->datadir);
    register_store_buyer_rpc_commands(svc->rpc_table);
}

static bool boot_store_payment_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !boot_profile_has_store(svc->app_ctx))
        return true;
    if (svc->defer_payment_service) {
        printf("Store payment processor deferred during bootstrap receiver mode\n");
        return true;
    }
    if (!boot_start_payment_service(svc)) {
        fprintf(stderr,
                "WARNING: failed to start tracked payment processor thread\n");
    }
    return true;
}

static void boot_store_payment_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (svc)
        boot_join_payment_service(svc);
}

/* ZCODE package store (slice 2): local content-addressed store under
 * <datadir>/zcode, disabled by default (-packagehost=1 enables). A failure
 * to open is loud but never fatal — hosting simply stays off. */
static bool boot_zcode_store_start(void *ctx)
{
    (void)ctx;
    if (!GetBoolArg("-packagehost", false))
        return true;
    if (!vcs_package_store_open_global()) {
        fprintf(stderr,
                "WARNING: -packagehost=1 but the package store failed "
                "to open; hosting disabled\n");
        return true;
    }
    printf("ZCODE package store: hosting enabled (quota %llu bytes)\n",
           (unsigned long long)vcs_package_store_quota_bytes());
    return true;
}

static void boot_zcode_store_stop(void *ctx)
{
    (void)ctx;
    /* The swarm engine borrows the global store: it must be freed
     * BEFORE the store closes (slice 12). */
    boot_zcode_swarm_shutdown();
    if (vcs_package_store_global())
        vcs_package_store_close_global();
}

/* Register every clearnet frontend service into svc->frontend_kernel.
 * Called once from app_init_services in boot_services.c before the kernel
 * is started. Returns false on the first registration failure. */
bool boot_register_frontend_services(struct boot_svc_ctx *svc)
{
    /* ZCODE package swarm (slice 12): net↔vcs engine hooks. The engine
     * itself is created lazily on first use when -packagehost=1 and the
     * store is open; wiring the hooks is always safe. */
    boot_zcode_swarm_wire(svc);

    const struct zcl_service_spec specs[] = {
        {
            .name = "file_service",
            .start = boot_file_service_start,
            .stop = boot_file_service_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "rom_seed",
            .start = boot_rom_seed_start,
            .stop = boot_rom_seed_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        boot_frontend_rpc_http_spec(svc),
        {
            .name = "api_cache",
            .start = boot_api_cache_start,
            .stop = boot_api_cache_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "https_explorer",
            .start = boot_https_explorer_start,
            .stop = boot_https_explorer_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "miner",
            .start = boot_miner_start,
            .stop = boot_miner_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "onion_tor",
            .start = boot_onion_tor_start,
            .stop = boot_onion_tor_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "store_payment",
            .start = boot_store_payment_start,
            .stop = boot_store_payment_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "zcode_store",
            .start = boot_zcode_store_start,
            .stop = boot_zcode_store_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
    };

    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) {
        if (!zcl_service_kernel_register(&svc->frontend_kernel, &specs[i]))
            return false;
    }
    return true;
}

extern size_t onion_service_handle_request(const char *, const char *,
    const uint8_t *, size_t, uint8_t *, size_t);

static size_t onion_request_adapter(const char *method, const char *path,
    const uint8_t *req_data, size_t req_len,
    uint8_t *resp, size_t resp_max, void *ctx)
{
    (void)ctx;
    return onion_service_handle_request(method, path,
        req_data, req_len, resp, resp_max);
}
