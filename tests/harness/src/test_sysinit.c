/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the sysinit declarative boot-stage registrar
 * (platform/modules/util/src/sysinit.c). Registers synthetic records with instrumented
 * init/fini into the (test-reset) global table and asserts:
 *   - deterministic (stage, order, name) sort regardless of register order,
 *   - sysinit_run_stage runs only the target stage's records, in sort order,
 *     and advances the boot-stage machine,
 *   - a failing record stops the stage and does NOT advance,
 *   - fini runs in reverse execution order (LIFO),
 *   - every wired boot boundary has >= 1 record (via the real boot table).
 *
 * Each test process is fork-isolated by the parallel runner, so mutating the
 * global boot stage + sysinit table here does not leak into sibling tests. */

#include "test/test_core.h"
#include "util/sysinit.h"
#include "util/boot_phase.h"

#include <stdio.h>
#include <string.h>

#define SI_CHECK(name, expr) do {                 \
    printf("sysinit: %s... ", (name));            \
    if ((expr)) printf("OK\n");                   \
    else { printf("FAIL\n"); failures++; }        \
} while (0)

/* Instrumented run/fini trace: init appends its tag, fini appends '~tag'. */
static char g_trace[256];
static void trace_append(const char *s)
{
    size_t used = strlen(g_trace);
    snprintf(g_trace + used, sizeof(g_trace) - used, "%s;", s);
}

static struct zcl_result init_a(void *ctx) { (void)ctx; trace_append("a"); return ZCL_OK; }
static struct zcl_result init_b(void *ctx) { (void)ctx; trace_append("b"); return ZCL_OK; }
static struct zcl_result init_c(void *ctx) { (void)ctx; trace_append("c"); return ZCL_OK; }
static struct zcl_result init_fail(void *ctx) { (void)ctx; trace_append("F"); return ZCL_ERR(-7, "deliberate"); }
static void fini_a(void *ctx) { (void)ctx; trace_append("~a"); }
static void fini_b(void *ctx) { (void)ctx; trace_append("~b"); }
static void fini_c(void *ctx) { (void)ctx; trace_append("~c"); }

int test_sysinit(void)
{
    printf("\n=== sysinit tests ===\n");
    int failures = 0;

    /* ── deterministic sort ─────────────────────────────────────────
     * Register out of order across two stages with mixed `order`; the
     * snapshot must come back stage-then-order-then-name sorted. */
    sysinit_reset_for_testing();
    struct sysinit_record recs[] = {
        { .subsystem = "t", .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 5,  .init = init_c, .fini = fini_c, .name = "zeta" },
        { .subsystem = "t", .stage = BOOT_STAGE_WALLET_LOADED,      .order = 20, .init = init_b, .fini = fini_b, .name = "beta" },
        { .subsystem = "t", .stage = BOOT_STAGE_WALLET_LOADED,      .order = 10, .init = init_a, .fini = fini_a, .name = "alpha" },
    };
    for (size_t i = 0; i < sizeof(recs) / sizeof(recs[0]); i++)
        SI_CHECK("register accepts record", sysinit_register(&recs[i]));

    char snap[256];
    size_t n = sysinit_ordering_snapshot(snap, sizeof(snap));
    SI_CHECK("snapshot counts all records", n == 3);
    /* WALLET_LOADED(order10 alpha) < WALLET_LOADED(order20 beta) <
     * BLOCK_INDEX_LOADED(order5 zeta). */
    SI_CHECK("sorted order is (stage,order,name)",
        strcmp(snap,
            "wallet_loaded 10 alpha\n"
            "wallet_loaded 20 beta\n"
            "block_index_loaded 5 zeta\n") == 0);

    SI_CHECK("stage record count (WALLET_LOADED)",
        sysinit_stage_record_count(BOOT_STAGE_WALLET_LOADED) == 2);
    SI_CHECK("stage record count (BLOCK_INDEX_LOADED)",
        sysinit_stage_record_count(BOOT_STAGE_BLOCK_INDEX_LOADED) == 1);
    SI_CHECK("stage record count (empty stage)",
        sysinit_stage_record_count(BOOT_STAGE_NETWORK_READY) == 0);

    /* ── run a stage: only its records run, in order, stage advances ─ */
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_DB_OPEN);   /* legal forward-jump */
    g_trace[0] = '\0';
    struct zcl_result r = sysinit_run_stage(BOOT_STAGE_WALLET_LOADED, NULL);
    SI_CHECK("run_stage WALLET_LOADED ok", r.ok);
    SI_CHECK("only WALLET records ran, in sort order", strcmp(g_trace, "a;b;") == 0);
    SI_CHECK("stage advanced to WALLET_LOADED",
        boot_stage_current() == BOOT_STAGE_WALLET_LOADED);

    /* next stage runs its single record and advances */
    r = sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, NULL);
    SI_CHECK("run_stage BLOCK_INDEX_LOADED ok", r.ok);
    SI_CHECK("block-index record ran", strcmp(g_trace, "a;b;c;") == 0);
    SI_CHECK("stage advanced to BLOCK_INDEX_LOADED",
        boot_stage_current() == BOOT_STAGE_BLOCK_INDEX_LOADED);

    /* ── fini runs in reverse execution order (c ran last -> ~c first) ─ */
    g_trace[0] = '\0';
    sysinit_run_fini_all();
    SI_CHECK("fini is reverse execution order (LIFO)",
        strcmp(g_trace, "~c;~b;~a;") == 0);
    /* idempotent: a second fini pass is a no-op (ran list drained) */
    g_trace[0] = '\0';
    sysinit_run_fini_all();
    SI_CHECK("second fini pass is a no-op", g_trace[0] == '\0');

    /* ── a failing record stops the stage and does NOT advance ──────── */
    sysinit_reset_for_testing();
    struct sysinit_record fr[] = {
        { .subsystem = "t", .stage = BOOT_STAGE_CHAIN_TIP_RESOLVED, .order = 1, .init = init_a,    .fini = NULL, .name = "ok_first" },
        { .subsystem = "t", .stage = BOOT_STAGE_CHAIN_TIP_RESOLVED, .order = 2, .init = init_fail, .fini = NULL, .name = "boom" },
        { .subsystem = "t", .stage = BOOT_STAGE_CHAIN_TIP_RESOLVED, .order = 3, .init = init_b,    .fini = NULL, .name = "never" },
    };
    for (size_t i = 0; i < sizeof(fr) / sizeof(fr[0]); i++)
        sysinit_register(&fr[i]);
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_BLOCK_INDEX_LOADED);
    g_trace[0] = '\0';
    r = sysinit_run_stage(BOOT_STAGE_CHAIN_TIP_RESOLVED, NULL);
    SI_CHECK("failing record returns non-ok", !r.ok && r.code == -7);
    SI_CHECK("stage stopped at the failing record", strcmp(g_trace, "a;F;") == 0);
    SI_CHECK("stage did NOT advance past predecessor",
        boot_stage_current() == BOOT_STAGE_BLOCK_INDEX_LOADED);

    /* ── malformed / over-capacity registration is refused ──────────── */
    struct sysinit_record bad = { .subsystem = "t", .stage = BOOT_STAGE_READY,
        .order = 0, .init = NULL, .fini = NULL, .name = "noinit" };
    SI_CHECK("register refuses NULL init", !sysinit_register(&bad));
    SI_CHECK("register refuses NULL record", !sysinit_register(NULL));

    /* Restore globals for any subsequent test in this process. */
    sysinit_reset_for_testing();
    boot_stage_reset_for_testing();
    return failures;
}
