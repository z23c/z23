/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the simnet full-state trace (engine/modules/sim/include/sim/
 * simnet_trace.h, docs/CHAOS_HARNESS.md "Recording a full-state trace").
 *
 * Runs a real `mode simnet` chaos scenario (mint, deliver, partition, heal —
 * driving the actual simnet_cluster, not sim_peer counters) with `trace_dir`
 * set, then checks the resulting NDJSON trace file:
 *   1. it exists and has at least one line per node for each event kind
 *      exercised (mint, deliver, partition, heal);
 *   2. it carries a piece of subsystem-level detail no existing `expect`
 *      metric can express — a per-node UTXO commitment count and tip
 *      height — and its LITERAL recorded value is checked, not just that
 *      the key is present.
 *
 * Reuses tools/sim/chaos.c the same way tests/harness/src/test_chaos_harness.c
 * does (CHAOS_NO_MAIN + #include), so this test drives the real DSL
 * wiring (the `trace_dir` command and the chaos_trace_record() call sites
 * added to handle_simnet_mint/_deliver/_partition/_heal), not just the
 * simnet_trace.h library functions in isolation.
 */

#include "test/test_core.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHAOS_NO_MAIN
#include "../../../tools/sim/chaos.c"

#define TRACE_CHECK(name, expr) do { \
    printf("simnet_trace: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int write_temp_scenario_st(const char *body, char *path,
                                  size_t path_cap)
{
    int n = snprintf(path, path_cap, "/tmp/zcl_simnet_trace_scn_%d_XXXXXX",
                     (int)getpid());
    if (n < 0 || (size_t)n >= path_cap) return -1;
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        unlink(path);
        return -1;
    }
    size_t len = strlen(body);
    size_t wrote = fwrite(body, 1, len, fp);
    int close_rc = fclose(fp);
    if (wrote != len || close_rc != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}

static int run_temp_scenario_st(const char *body)
{
    char path[160];
    if (write_temp_scenario_st(body, path, sizeof(path)) != 0)
        return 99;

    struct chaos_ctx ctx;
    chaos_ctx_init(&ctx);
    ctx.scenario_path = path;
    int rc = run_scenario(&ctx);
    unlink(path);
    return rc;
}

/* The trace format guarantees "event":"NAME" and "node_id":N each appear
 * verbatim, at most once, per line — so a substring scan is a safe,
 * dependency-free stand-in for a real JSON parse in this in-process test.
 * (tools/sim/simnet_trace_query.c does the real parse-and-filter for
 * humans/scripts querying a trace after the fact.) */
static size_t count_lines_containing2(const char *path, const char *needle1,
                                      const char *needle2)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    char line[4096];
    size_t count = 0;
    while (fgets(line, sizeof(line), fp)) {
        bool m1 = !needle1 || strstr(line, needle1) != NULL;
        bool m2 = !needle2 || strstr(line, needle2) != NULL;
        if (m1 && m2) count++;
    }
    fclose(fp);
    return count;
}

int test_simnet_trace(void)
{
    /* write_failure_artifacts() (chaos.c) is real, used code — chaos.c's own
     * main() calls it on a failed scenario, and test_chaos_harness.c's TU
     * calls it directly to exercise it. This test's scenario always passes,
     * so this TU never reaches that path; under CHAOS_NO_MAIN that leaves it
     * unreferenced from here, which -Werror=unused-function would otherwise
     * flag. Mark it deliberately unreferenced rather than disabling the
     * warning. */
    (void)write_failure_artifacts;

    printf("\n=== simnet_trace tests ===\n");
    int failures = 0;

    char trace_dir_tmpl[160];
    int n = snprintf(trace_dir_tmpl, sizeof(trace_dir_tmpl),
                     "/tmp/zcl_simnet_trace_dir_%d_XXXXXX", (int)getpid());
    TRACE_CHECK("trace dir template built",
                n > 0 && (size_t)n < sizeof(trace_dir_tmpl));
    char *made_dir = mkdtemp(trace_dir_tmpl);
    TRACE_CHECK("trace temp dir created", made_dir != NULL);

    char trace_path[256];
    snprintf(trace_path, sizeof(trace_path), "%s/simnet_trace.jsonl",
             made_dir ? made_dir : "/nonexistent");

    /* 3-node cluster: mint on node 0 twice (with a relay+deliver after
     * each), sever node 0 from node 2 between the two mints, then heal and
     * fully resync. Exercises 4 distinct event kinds: simnet_mint,
     * simnet_deliver, simnet_partition, simnet_heal. Two non-byzantine
     * mints on node 0 and no spends deterministically leave exactly 2
     * unspent coinbase UTXOs at chain height (simnet's base height) + 2 —
     * SIM_CHAIN_BASE_HEIGHT (100) + 1 (first mint) + 1 (second mint) = 101 —
     * once the whole cluster reconverges. */
    char scenario_body[1024];
    snprintf(scenario_body, sizeof(scenario_body),
        "seed 0x1234abcd\n"
        "mode simnet\n"
        "trace_dir %s\n"
        "simnet_nodes 3\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_deliver\n"
        "simnet_partition a=0 b=2\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_deliver\n"
        "simnet_heal a=0 b=2\n"
        "simnet_deliver\n"
        "expect simnet_converged == 1\n"
        "expect simnet_tip_monotonic == 1\n",
        made_dir ? made_dir : "/nonexistent");

    int rc = run_temp_scenario_st(scenario_body);
    TRACE_CHECK("traced scenario passes", rc == 0);

    FILE *tf = fopen(trace_path, "rb");
    TRACE_CHECK("trace file exists", tf != NULL);
    if (tf) fclose(tf);

    /* One line per node (3) for every event kind exercised: 2 mints, 3
     * delivers, 1 partition, 1 heal. */
    TRACE_CHECK("mint events: 2 mints x 3 nodes = 6 lines",
                count_lines_containing2(trace_path,
                                        "\"event\":\"simnet_mint\"",
                                        NULL) == 6);
    TRACE_CHECK("deliver events: 3 delivers x 3 nodes = 9 lines",
                count_lines_containing2(trace_path,
                                        "\"event\":\"simnet_deliver\"",
                                        NULL) == 9);
    TRACE_CHECK("partition event: 1 x 3 nodes = 3 lines",
                count_lines_containing2(trace_path,
                                        "\"event\":\"simnet_partition\"",
                                        NULL) == 3);
    TRACE_CHECK("heal event: 1 x 3 nodes = 3 lines",
                count_lines_containing2(trace_path,
                                        "\"event\":\"simnet_heal\"",
                                        NULL) == 3);

    bool every_node_minted = true;
    for (int i = 0; i < 3; i++) {
        char node_needle[32];
        snprintf(node_needle, sizeof(node_needle), "\"node_id\":%d", i);
        if (count_lines_containing2(trace_path, "\"event\":\"simnet_mint\"",
                                    node_needle) < 1)
            every_node_minted = false;
    }
    TRACE_CHECK("every node has at least one mint-event line",
                every_node_minted);

    /* The literal-value proof: no existing `expect` metric names a per-node
     * UTXO commitment count or tip height (the `tip_height` metric is the
     * LEGACY sim_peer counter — always 0 in simnet mode, an entirely
     * different field never touched by any simnet_* command). Check the
     * EXACT recorded values at the final snapshot, not merely that the
     * "coins"/"chain" keys exist.
     *
     * `simnet_heal` only reopens the link between the two halves — it does
     * not itself deliver anything, so node 2 (on the far side of the
     * partition) is still one block behind at the `simnet_heal` snapshot
     * itself (confirmed by hand: tip_height 100 / utxo_count 1 there). Full
     * reconvergence (all 3 nodes at tip_height 101 / utxo_count 2) only
     * happens once the trailing `simnet_deliver` actually moves the block
     * across the just-healed link. That final deliver is seq 7 (1=mint,
     * 2=deliver, 3=partition, 4=mint, 5=deliver, 6=heal, 7=deliver) — each
     * seq number is unique to one event, so "\"seq\":7" alone pins down
     * exactly those 3 lines with no ambiguity about which event they are. */
    TRACE_CHECK("post-heal resync: all 3 nodes report tip_height 101",
                count_lines_containing2(trace_path,
                                        "\"seq\":7",
                                        "\"tip_height\":101") == 3);
    TRACE_CHECK("post-heal resync: all 3 nodes report utxo_count 2",
                count_lines_containing2(trace_path,
                                        "\"seq\":7",
                                        "\"utxo_count\":2") == 3);
    /* And the 32-byte XOR UTXO commitment itself (not just its count) is
     * identical across all 3 post-heal-resync lines -- a piece of state no
     * existing metric expresses at all. */
    {
        FILE *fp = fopen(trace_path, "rb");
        char line[4096];
        char first_hex[80];
        first_hex[0] = '\0';
        while (fp && fgets(line, sizeof(line), fp)) {
            if (!strstr(line, "\"seq\":7"))
                continue;
            const char *key = "\"commitment_hex\":\"";
            char *p = strstr(line, key);
            if (!p) continue;
            p += strlen(key);
            char *end = strchr(p, '"');
            if (!end || (size_t)(end - p) >= sizeof(first_hex)) continue;
            size_t len = (size_t)(end - p);
            if (first_hex[0] == '\0') {
                memcpy(first_hex, p, len);
                first_hex[len] = '\0';
            } else if (strncmp(first_hex, p, len) != 0 ||
                      strlen(first_hex) != len) {
                first_hex[0] = '\0';
                strcpy(first_hex, "MISMATCH");
                break;
            }
        }
        if (fp) fclose(fp);
        TRACE_CHECK("post-heal resync: commitment_hex is a real 64-char "
                    "hex digest identical across all 3 nodes",
                    strlen(first_hex) == 64 &&
                    strcmp(first_hex, "MISMATCH") != 0);
    }

    if (made_dir) {
        remove(trace_path);
        rmdir(made_dir);
    }

    if (failures == 0)
        printf("=== simnet_trace tests: ALL PASS ===\n\n");
    else
        printf("simnet_trace: failures=%d\n", failures);
    return failures;
}
