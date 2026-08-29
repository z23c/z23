/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bg_verification.c — background validation / hash-verification
 * service-kernel entry points.
 *
 * Part of the boot composition root (extracted from boot_services.c). These
 * four start/stop adapters wrap the two long-running background re-verification
 * services — full proof/script validation (bg_validation) and historical block
 * hash verification (bg_hash_verify). They operate purely on
 * svc->bg_validation / svc->bg_hash_verify (storage owned by boot_svc_ctx) and
 * the g_bg_validation extern; they own no file-statics and spawn no thread of
 * their own (each underlying *_start owns its worker thread + liveness inside
 * its own service module).
 *
 * Registered into the runtime service kernel by boot_register_runtime_services()
 * in boot_services.c, so the four prototypes live in config/boot_internal.h. */

#include "config/boot_internal.h"
#include "util/util.h"  /* GetDataDir */
#include <stdio.h>

/* Start background full proof/script validation (runtime service kernel). */
bool boot_bg_validation_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx)
        return false;
    /* svc->datadir is the BASE datadir, but bodies are persisted under the
     * NET-SPECIFIC datadir (GetDataDir(true); reducer_ingest_service.c) —
     * the walker's pread must look there. Byte-identical on mainnet. */
    char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    bg_validation_init(&svc->bg_validation, svc->state, svc->node_db,
                       net_dir[0] ? net_dir : svc->datadir, svc->params);
    g_bg_validation = &svc->bg_validation;
    if (svc->app_ctx->no_bg_validation) {
        printf("[bg-valid] Disabled via -nobgvalidation\n");
        return true;
    }
    if (bg_validation_start(&svc->bg_validation)) {
        printf("[bg-valid] Started background full validation\n");
    } else {
        printf("[bg-valid] Deferred - already complete or chain not ready\n");
    }
    return true;
}

/* Stop background full validation (runtime service kernel). */
void boot_bg_validation_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (svc)
        bg_validation_stop(&svc->bg_validation);
}

/* Start background historical block hash verification (runtime service kernel). */
bool boot_bg_hash_verify_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx)
        return false;
    /* Same reason as boot_bg_validation_start above: svc->datadir is the BASE
     * datadir, but bodies are persisted under the NET-SPECIFIC one
     * (GetDataDir(true)). bg_hash_verify_init retains the bytes, not this
     * frame's buffer. Byte-identical on mainnet. */
    char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    bg_hash_verify_init(&svc->bg_hash_verify, svc->state, svc->node_db,
                        net_dir[0] ? net_dir : svc->datadir, svc->params);
    if (svc->app_ctx->no_bg_validation) {
        printf("[bg-hash] Disabled via -nobgvalidation\n");
        return true;
    }
    {
        struct zcl_result r = bg_hash_verify_start(&svc->bg_hash_verify);
        if (r.ok) {
            printf("[bg-hash] Started background hash verification\n");
        } else {
            printf("[bg-hash] Deferred - already complete or chain not ready (%s)\n",
                   r.message);
        }
    }
    return true;
}

/* Stop background hash verification (runtime service kernel). */
void boot_bg_hash_verify_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (svc)
        bg_hash_verify_stop(&svc->bg_hash_verify);
}
