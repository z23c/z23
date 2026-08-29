/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simperf — CI-cheap algorithmic-cost detector for the block-connect / UTXO
 * path, driven through the deterministic RAM-only simulator.
 *
 * WHAT IT MEASURES
 * ----------------
 * It runs one fixed workload (mint N blocks of M transparent spends each,
 * folded by the REAL connect_block over a real coins_view_cache) at several
 * workload sizes, times the fold with per-thread CPU time, and reports how
 * much the per-transaction cost GROWS between the smallest and largest size.
 * Flat growth means the fold is still linear in the work it is given; growth
 * proportional to the workload means something on that path went superlinear.
 *
 * WHAT IT DOES NOT MEASURE — do not quote it as node performance
 * -------------------------------------------------------------
 * There is no disk, no network, no P2P, no mempool, no real PoW, and no real
 * script/Groth16 verification in this path. It is NOT the coldstart-to-tip
 * stopwatch and cannot replace it; the real wall-clock sync proof lives in the
 * separate timed-sync harness against a real peer. This tool exists to catch
 * one class of defect — an algorithmic-complexity regression — before it ever
 * reaches a slow real run.
 *
 * WHY THE GATE IS A RATIO
 * -----------------------
 * "ns per block <= K" is a machine constant that has to be re-tuned per host
 * and whose easiest maintenance is to raise it. The gated metric here is
 * dimensionless — per-tx cost at 4x work divided by per-tx cost at 1x work —
 * so the same threshold holds on a fast box, a slow box, and a loaded box.
 * See sim/simnet_perf.h and docs/SIMNET_PERF.md.
 *
 * PROVEN TO HAVE TEETH
 * --------------------
 * `--inject=coins-hash-collapse` arms a real, correctness-preserving O(1)->O(n)
 * regression in the UTXO map (coins/coins_fault.h). Run the same workload both
 * ways: the budget must PASS clean and FAIL armed. That comparison is also a
 * checked-in test group (`make t ONLY=simnet_perf`), so the detector's teeth
 * are re-proven on every suite run rather than assumed.
 *
 * Usage:
 *   build/bin/simperf [--blocks=N] [--txs-per-block=N] [--scales=1,2,4]
 *                     [--reps=N] [--funding-multiple=N]
 *                     [--inject=none|coins-hash-collapse]
 *                     [--expect='METRIC OP VALUE']... [--quiet]
 *
 * `--expect` takes exactly the chaos scenario DSL's assertion text
 * (docs/CHAOS_HARNESS.md `expect METRIC OP VALUE`, operators == != >= <= > <)
 * and may be repeated. With no --expect the calibrated default budget plus the
 * derived anti-vacuity assertions are applied.
 */

#include "chain/chainparams.h"
#include "sim/simnet_perf.h"
#include "util/parse_num.h"

#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Required by the node's whole-program link: thread_registry.h documents this
 * as the shutdown-signal flag every entry point must define. simperf runs no
 * background threads, but the symbol is referenced by code paths pulled in via
 * the full ALL_SRCS link (same as tools/sim/wire_sweep.c, tools/sim/chaos.c). */
volatile sig_atomic_t g_shutdown_requested = 0;

#define SIMPERF_MAX_EXPECTS 32

struct simperf_expect {
    char metric[64];
    char op[4];
    int64_t value;
};

static void usage(FILE *out)
{
    fprintf(out,
        "usage: simperf [--blocks=N] [--txs-per-block=N] [--scales=1,2,4]\n"
        "               [--reps=N] [--funding-multiple=N]\n"
        "               [--inject=none|coins-hash-collapse]\n"
        "               [--expect='METRIC OP VALUE']... [--quiet]\n"
        "\n"
        "metrics: fold_growth_permille total_growth_permille (gated,\n"
        "         machine-independent), fold_ns_per_tx total_ns_per_block\n"
        "         (informational, per-machine), measured_txs coins_at_end\n"
        "         scale_span points reps (anti-vacuity)\n");
}

/* Split "METRIC OP VALUE" (the chaos DSL's own assertion text) into an
 * expectation. Returns false on any malformed field. */
static bool parse_expect(const char *text, struct simperf_expect *out)
{
    char buf[192];
    if (!text || strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);

    char *save = NULL;
    const char *metric = strtok_r(buf, " \t", &save);
    const char *op = strtok_r(NULL, " \t", &save);
    const char *value = strtok_r(NULL, " \t", &save);
    if (!metric || !op || !value)
        return false;
    if (strtok_r(NULL, " \t", &save) != NULL)
        return false;
    if (strlen(metric) >= sizeof(out->metric) || strlen(op) >= sizeof(out->op))
        return false;
    int64_t parsed = 0;
    if (!zcl_parse_i64(value, &parsed))
        return false;
    snprintf(out->metric, sizeof(out->metric), "%s", metric);
    snprintf(out->op, sizeof(out->op), "%s", op);
    out->value = parsed;
    return true;
}

/* Parse "1,2,4" into cfg->scales. */
static bool parse_scales(const char *text, struct simnet_perf_config *cfg)
{
    char buf[128];
    if (!text || !*text || strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    cfg->scale_count = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        int64_t v = 0;
        if (!zcl_parse_i64(tok, &v) || v < 1 || v > 4096)
            return false;
        if (cfg->scale_count >= SIMNET_PERF_MAX_POINTS)
            return false;
        cfg->scales[cfg->scale_count++] = (int)v;
    }
    return cfg->scale_count >= 2;
}

static bool parse_int_flag(const char *arg, const char *name, int min, int max,
                           int *out)
{
    size_t n = strlen(name);
    if (strncmp(arg, name, n) != 0)
        return false;
    int64_t v = 0;
    if (!zcl_parse_i64(arg + n, &v) || v < min || v > max) {
        fprintf(stderr, "simperf: %s expects an integer in %d..%d\n", name,
                min, max);
        exit(2);
    }
    *out = (int)v;
    return true;
}

int main(int argc, char **argv)
{
    /* simnet value-copies chain_params_get(); select mainnet first, same as
     * tools/sim/chaos.c and tools/sim/wire_sweep.c. */
    chain_params_select(CHAIN_MAIN);

    struct simnet_perf_config cfg;
    simnet_perf_config_defaults(&cfg);

    struct simperf_expect expects[SIMPERF_MAX_EXPECTS];
    size_t expect_count = 0;
    bool quiet = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(stdout);
            return 0;
        }
        if (strcmp(a, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (parse_int_flag(a, "--blocks=", 1, 100000, &cfg.blocks))
            continue;
        if (parse_int_flag(a, "--txs-per-block=", 1, 1000, &cfg.txs_per_block))
            continue;
        if (parse_int_flag(a, "--reps=", 1, 64, &cfg.reps))
            continue;
        if (parse_int_flag(a, "--funding-multiple=", 1, 16,
                           &cfg.funding_multiple))
            continue;
        if (strncmp(a, "--scales=", 9) == 0) {
            if (!parse_scales(a + 9, &cfg)) {
                fprintf(stderr, "simperf: --scales wants 2..%d strictly "
                                "increasing sizes, e.g. --scales=1,2,4\n",
                        SIMNET_PERF_MAX_POINTS);
                return 2;
            }
            continue;
        }
        if (strncmp(a, "--inject=", 9) == 0) {
            const char *v = a + 9;
            if (strcmp(v, "none") == 0) {
                cfg.inject = SIMNET_PERF_INJECT_NONE;
            } else if (strcmp(v, "coins-hash-collapse") == 0) {
                cfg.inject = SIMNET_PERF_INJECT_COINS_HASH_COLLAPSE;
            } else {
                fprintf(stderr, "simperf: unknown --inject=%s "
                                "(none|coins-hash-collapse)\n", v);
                return 2;
            }
            continue;
        }
        if (strncmp(a, "--expect=", 9) == 0) {
            if (expect_count >= SIMPERF_MAX_EXPECTS) {
                fprintf(stderr, "simperf: too many --expect assertions\n");
                return 2;
            }
            if (!parse_expect(a + 9, &expects[expect_count])) {
                fprintf(stderr,
                        "simperf: malformed --expect='%s' — want "
                        "'METRIC OP VALUE'\n", a + 9);
                return 2;
            }
            expect_count++;
            continue;
        }
        fprintf(stderr, "simperf: unrecognized argument '%s'\n", a);
        usage(stderr);
        return 2;
    }

    /* Default budget: the calibrated growth ceiling plus derived anti-vacuity
     * assertions, so a workload that silently folded nothing FAILS instead of
     * reporting a flattering ratio over two empty runs. */
    if (expect_count == 0) {
        const int last_scale = cfg.scales[cfg.scale_count - 1];
        const int64_t want_txs = (int64_t)cfg.blocks * last_scale *
                                 ((int64_t)cfg.txs_per_block + 1);
        struct simperf_expect defaults[] = {
            { "fold_growth_permille",  "<=",
              SIMNET_PERF_GROWTH_BUDGET_PERMILLE },
            { "total_growth_permille", "<=",
              SIMNET_PERF_GROWTH_BUDGET_PERMILLE },
            { "measured_txs",          "==", want_txs },
            { "coins_at_end",          ">=", (int64_t)cfg.blocks * last_scale },
            { "points",                ">=", 2 },
        };
        for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++)
            expects[expect_count++] = defaults[i];
    }

    struct simnet_perf_result result;
    if (!simnet_perf_run(&cfg, &result)) {
        fprintf(stderr, "simperf: workload FAILED to run — no perf verdict\n");
        return 1;
    }

    if (!quiet) {
        printf("simperf: blocks=%d txs_per_block=%d reps=%d "
               "funding_multiple=%d inject=%s\n",
               cfg.blocks, cfg.txs_per_block, cfg.reps, cfg.funding_multiple,
               cfg.inject == SIMNET_PERF_INJECT_NONE
                   ? "none" : "coins-hash-collapse");
        simnet_perf_print(&result, stdout);
    }

    size_t failures = 0;
    for (size_t i = 0; i < expect_count; i++) {
        int64_t actual = 0;
        int rc = simnet_perf_expect(&result, expects[i].metric, expects[i].op,
                                   expects[i].value, &actual);
        if (rc == -3) {
            fprintf(stderr, "simperf: unknown expect metric '%s'\n",
                    expects[i].metric);
            return 2;
        }
        if (rc == -2) {
            fprintf(stderr, "simperf: unknown expect operator '%s'\n",
                    expects[i].op);
            return 2;
        }
        printf("expect %s %s %" PRId64 " (actual=%" PRId64 ") %s\n",
               expects[i].metric, expects[i].op, expects[i].value, actual,
               rc == 0 ? "PASS" : "FAIL");
        if (rc != 0)
            failures++;
    }

    if (failures > 0) {
        printf("SIMPERF BUDGET FAILED (%zu of %zu assertions)\n", failures,
               expect_count);
        return 1;
    }
    printf("SIMPERF ALL BUDGETS PASSED (%zu assertions)\n", expect_count);
    return 0;
}
