/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wiring for the standing UTXO parity service. Kept in its own TU so the
 * 800-line composition-root mega-files (boot_services.c) gain only a single
 * registration call — this carries the start/stop bodies and the spec.
 *
 * Activation default — ON when a zclassicd oracle is configured (MVP C8):
 * boot tries to resolve the co-located zclassicd reference (RPC creds from
 * config or ~/.zclassic/zclassic.conf, exactly like legacy_mirror). If it
 * resolves, the standing parity service runs continuously, diffing the
 * UTXO/tip state at the supervised 60 s cadence. If no creds resolve (an
 * operator with no zclassicd), the reference stays unwired and the service is
 * a quiet no-op — no log spam, no health degradation. Operators can force the
 * service off with ZCL_PARITY_ORACLE=0 even when a daemon is present.
 *
 * The service is a READ-ONLY OBSERVER by construction: it only recomputes the
 * local SHA3 commitment and diffs it against the reference; it never writes the
 * chain, moves the tip, or touches liveness. The EV_CHAIN_TIP_COMMIT observer
 * and native introspection are always installed because they are cheap and never
 * touch the live node.
 */

#include "config/boot_internal.h"
#include "config/runtime.h"

#include "services/utxo_parity_service.h"
#include "services/utxo_reference_source.h"
#include "jobs/utxo_parity_poll.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Caller-owned backing store for the (dormant-by-default) zclassicd reference.
 * Static lifetime so the vtable's `self` pointer outlives the service. */
static struct utxo_reference_source           g_parity_ref;
static struct utxo_reference_source_zclassicd g_parity_ref_zclassicd;

/* Operator opt-out: ZCL_PARITY_ORACLE=0 keeps the service off even when a
 * zclassicd reference would resolve. Any other value (or unset) means ON when
 * the oracle is reachable — the C8 default. */
static bool boot_utxo_parity_opt_out(void)
{
    const char *v = getenv("ZCL_PARITY_ORACLE");
    return v && (v[0] == '0' || v[0] == 'n' || v[0] == 'N' ||
                 v[0] == 'f' || v[0] == 'F');
}

static bool boot_utxo_parity_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;

    /* Init with the service dormant; flip cfg.enabled on only once a reference
     * actually resolves below, so a creds-less box never even arms the gate. */
    struct utxo_parity_config cfg = {0};
    cfg.enabled = false;
    cfg.finality_depth = 100;       /* matches ORACLE_TIP_SAFETY_MARGIN */
    cfg.max_checks_per_tick = 1;    /* bound full-set SHA3 cost */
    snprintf(cfg.rpc.host, sizeof(cfg.rpc.host), "%s", "127.0.0.1");
    cfg.rpc.port = 8232;

    struct zcl_result r = utxo_parity_init(&cfg, app_runtime_node_db());
    if (!r.ok) {
        fprintf(stderr,  // obs-ok:utxo-parity-init-fail
                "[utxo-parity] init failed at %s:%d code=%d: %s\n",
                r.source_file ? r.source_file : "?", r.source_line,
                r.code, r.message);
        return false;
    }

    /* Always install the cheap, live-safe finalized-frontier observer +
     * leave the service introspectable via `z23 dumpstate`. */
    utxo_parity_observe_finalization();

    if (boot_utxo_parity_opt_out()) {
        printf("[utxo-parity] dormant (ZCL_PARITY_ORACLE=0 opt-out)\n");
        return true;
    }

    /* MAINNET-ONLY, on the one shared predicate (boot_nonmain_network_name,
     * config/boot_internal.h). The co-located reference daemon this service
     * resolves on the loopback RPC port above is a MAINNET one: comparing a
     * regtest or testnet node against it is a guaranteed false compare — and,
     * worse, an outbound dial into the operator's live daemon from a fixture
     * that was supposed to be sealed. A `-regtest` fixture was observed polling
     * it every 60 s on 2026-07-28, three log lines after the legacy mirror
     * correctly skipped. The cheap local finalization observer above stays
     * installed on every network; only the reference dial is gated. */
    const char *net = boot_nonmain_network_name(svc);
    if (net) {
        printf("[utxo-parity] dormant (network=%s — the zclassicd oracle is a "
               "mainnet daemon; a non-mainnet node must not dial it)\n", net);
        return true;
    }

    /* Auto-detect the co-located zclassicd: resolve its RPC reference (creds
     * from cfg or ~/.zclassic/zclassic.conf). When it resolves, ARM the
     * service (enabled=true) and register the supervised poll Job so it runs
     * continuously. When no creds resolve, leave the reference unwired and the
     * service quietly dormant — no health impact, no recurring noise. The
     * reference is height-only (coarse), so it can never false-page. */
    struct zcl_result zr = utxo_reference_source_zclassicd_init(
        &g_parity_ref, &g_parity_ref_zclassicd, &cfg.rpc);
    if (zr.ok) {
        /* Arm the run gate now that an oracle is present. Re-apply the fully
         * resolved RPC config (creds + port from ~/.zclassic/zclassic.conf)
         * so the coarse block-hash check uses the same credentials as the
         * UTXO reference source. */
        cfg.enabled = true;
        cfg.rpc = g_parity_ref_zclassicd.rpc;
        (void)utxo_parity_init(&cfg, app_runtime_node_db());
        utxo_parity_set_rpc_config(&g_parity_ref_zclassicd.rpc);
        utxo_parity_set_reference_source(&g_parity_ref);
        utxo_parity_poll_register();
        if (utxo_parity_poll_is_registered())
            printf("[utxo-parity] active: zclassicd oracle wired (%s:%d), "
                   "60s supervised parity poll registered\n",
                   g_parity_ref_zclassicd.rpc.host[0]
                       ? g_parity_ref_zclassicd.rpc.host : "127.0.0.1",
                   g_parity_ref_zclassicd.rpc.port);
    } else {
        /* One quiet line at boot; no zclassicd → the standing service is a
         * no-op. Not an error: a node without a reference daemon is normal. */
        printf("[utxo-parity] dormant (no zclassicd oracle: %s)\n",
               zr.message[0] ? zr.message : "no reference");
    }
    return true;  /* non-fatal: the observer + introspection still work */
}

static void boot_utxo_parity_stop(void *ctx)
{
    (void)ctx;
    /* No-op: supervisor unregister happens at supervisor_stop(); the static
     * reference store is process-lived. */
}

bool boot_utxo_parity_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "utxo_parity",
        .start = boot_utxo_parity_start,
        .stop = boot_utxo_parity_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
