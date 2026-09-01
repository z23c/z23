/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the deterministic chaos scenario runner.
 */

#include "test/test_core.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHAOS_NO_MAIN
#include "../../../tools/sim/chaos.c"

#define CHAOS_CHECK(name, expr) do { \
    printf("chaos_harness: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int write_temp_scenario(const char *body, char *path, size_t path_cap)
{
    int n = snprintf(path, path_cap, "/tmp/zcl_chaos_harness_%d_XXXXXX",
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

static int run_temp_scenario(const char *body, struct chaos_ctx *ctx_out)
{
    char path[128];
    if (write_temp_scenario(body, path, sizeof(path)) != 0)
        return 99;

    struct chaos_ctx ctx;
    chaos_ctx_init(&ctx);
    ctx.scenario_path = path;

    int rc = run_scenario(&ctx);
    if (ctx_out) *ctx_out = ctx;
    unlink(path);
    return rc;
}

static int run_temp_scenario_with_seed(const char *body, uint64_t seed,
                                       struct chaos_ctx *ctx_out)
{
    char path[128];
    if (write_temp_scenario(body, path, sizeof(path)) != 0)
        return 99;

    struct chaos_ctx ctx;
    chaos_ctx_init(&ctx);
    ctx.scenario_path = path;
    ctx.seed_override = seed;
    ctx.seed_override_set = true;

    int rc = run_scenario(&ctx);
    if (ctx_out) *ctx_out = ctx;
    unlink(path);
    return rc;
}

static bool file_contains_text(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    int close_rc = fclose(fp);
    if (close_rc != 0) return false;
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

int test_chaos_harness(void)
{
    printf("\n=== chaos_harness tests ===\n");
    int failures = 0;

    struct chaos_ctx ctx;
    int rc = run_temp_scenario(
        "# valid smoke\n"
        "seed 0x2a\n"
        "boot_phase listening\n"
        "peer_count 3\n"
        "expect no_crash\n"
        "expect tip_height >= 0\n"
        "expect reorg_count == 0\n",
        &ctx);
    CHAOS_CHECK("valid scenario passes", rc == 0);
    CHAOS_CHECK("valid scenario records seed",
                ctx.seed_set && ctx.seed == 0x2a);
    CHAOS_CHECK("valid scenario records boot phase",
                strcmp(ctx.boot_phase, "listening") == 0);
    CHAOS_CHECK("valid scenario records peers", ctx.peer_count == 3);
    CHAOS_CHECK("valid scenario creates simulated peers",
                ctx.peers.count == 3 && ctx.peers.active_count == 3);
    CHAOS_CHECK("valid scenario counts expects", ctx.expect_count == 3);

    rc = run_temp_scenario(
        "# comments only\n"
        "\n"
        "   # also ignored\n",
        NULL);
    CHAOS_CHECK("comment-only scenario fails", rc != 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "unknown_command yes\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("unknown command fails", rc != 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "send_block peer=0 file=missing\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("send_block without peer setup fails", rc != 0);

    char block_path[128];
    CHAOS_CHECK("block fixture write succeeds",
                write_temp_scenario("synthetic block bytes\n", block_path,
                                    sizeof(block_path)) == 0);
    char send_block_scenario[512];
    int send_block_len = snprintf(
        send_block_scenario, sizeof(send_block_scenario),
        "seed 1\n"
        "peer_count 1\n"
        "send_block peer=0 file=%s height=7\n"
        "expect blocks_sent == 1\n"
        "expect block_bytes > 0\n"
        "expect tip_height == 7\n",
        block_path);
    rc = send_block_len > 0 && (size_t)send_block_len < sizeof(send_block_scenario)
        ? run_temp_scenario(send_block_scenario, &ctx)
        : 99;
    unlink(block_path);
    CHAOS_CHECK("send_block scenario passes", rc == 0);
    const struct sim_peer *block_peer = sim_peer_get(&ctx.peers, 0);
    CHAOS_CHECK("send_block records peer block state",
                ctx.peers.blocks_sent == 1 &&
                ctx.peers.block_bytes_sent > 0 &&
                ctx.block_bytes > 0 &&
                ctx.tip_height == 7 &&
                block_peer && block_peer->blocks_sent == 1 &&
                block_peer->block_bytes_sent > 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "send_block peer=0 file=tests/fixtures/blocks/synthetic_good_block.fixture\n"
        "expect blocks_sent == 1\n"
        "expect tip_height == 1\n",
        &ctx);
    CHAOS_CHECK("send_block checked-in fixture passes", rc == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 3\n"
        "kill_peer 1\n"
        "expect active_peers == 2\n"
        "expect killed_peers == 1\n",
        &ctx);
    CHAOS_CHECK("kill_peer scenario passes", rc == 0);
    CHAOS_CHECK("kill_peer records simulated peer state",
                ctx.peers.count == 3 &&
                ctx.peers.active_count == 2 &&
                ctx.peers.killed_count == 1 &&
                sim_peer_get(&ctx.peers, 1) &&
                !sim_peer_get(&ctx.peers, 1)->connected);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "kill_peer 3\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("kill_peer unknown peer fails", rc != 0);

    const char *seeded_churn_scenario =
        "seed 0x1234\n"
        "peer_count 5\n"
        "random_kill_peers count=2\n"
        "expect active_peers == 3\n"
        "expect killed_peers == 2\n";
    rc = run_temp_scenario(seeded_churn_scenario, &ctx);
    struct chaos_ctx ctx_again;
    int rc_again = run_temp_scenario(seeded_churn_scenario, &ctx_again);
    bool same_killed = true;
    for (unsigned i = 0; i < 5; i++) {
        same_killed = same_killed &&
            (ctx.peers.peers[i].connected ==
             ctx_again.peers.peers[i].connected);
    }
    CHAOS_CHECK("random_kill_peers seeded scenario passes",
                rc == 0 && rc_again == 0);
    CHAOS_CHECK("random_kill_peers is deterministic for seed",
                same_killed &&
                ctx.peers.active_count == 3 &&
                ctx.peers.killed_count == 2);

    rc = run_temp_scenario_with_seed(
        "seed not-a-number\n"
        "peer_count 4\n"
        "random_kill_peers count=2\n"
        "expect active_peers == 2\n"
        "expect killed_peers == 2\n",
        0xfeed, &ctx);
    CHAOS_CHECK("seed override supersedes scenario seed",
                rc == 0 &&
                ctx.seed_override_set &&
                ctx.seed == 0xfeed &&
                ctx.seed_set);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 2\n"
        "send_malformed_block peer=1 type=invalid_pow\n"
        "send_malformed_block type=bad_merkle peer=1\n"
        "expect malformed_blocks == 2\n"
        "expect consensus_rejects == 2\n"
        "expect active_peers == 2\n",
        &ctx);
    CHAOS_CHECK("send_malformed_block scenario passes", rc == 0);
    const struct sim_peer *mal_peer = sim_peer_get(&ctx.peers, 1);
    CHAOS_CHECK("send_malformed_block records peer rejection state",
                ctx.consensus_rejects == 2 &&
                ctx.peers.malformed_blocks_sent == 2 &&
                ctx.peers.malformed_blocks_rejected == 2 &&
                mal_peer && mal_peer->malformed_blocks_sent == 2 &&
                strcmp(mal_peer->last_malformed_type, "bad_merkle") == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "kill_peer 0\n"
        "send_malformed_block peer=0 type=invalid_pow\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("send_malformed_block disconnected peer fails", rc != 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "send_malformed_block peer=0 type=unknown_badness\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("send_malformed_block unknown type fails", rc != 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "advance_clock +60s\n"
        "advance_clock 2m\n"
        "expect clock_advance_count == 2\n"
        "expect tip_height == 3\n"
        "expect clock_advance_seconds == 180\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("advance_clock scenario passes", rc == 0);
    CHAOS_CHECK("advance_clock updates virtual clock",
                ctx.clock_advance_count == 2 &&
                ctx.clock_advance_seconds == 180 &&
                ctx.sim_monotonic_us == 180000000LL &&
                ctx.tip_height == 3);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 2\n"
        "at_event 10 kill_peer 0\n"
        "expect scheduled_events == 1\n"
        "expect active_peers == 1\n",
        &ctx);
    CHAOS_CHECK("at_event scenario passes", rc == 0);
    CHAOS_CHECK("at_event records dispatched event",
                ctx.scheduled_event_count == 1 &&
                ctx.last_event_height == 10 &&
                ctx.peers.active_count == 1);

    rc = run_temp_scenario(
        "seed 1\n"
        "boot_phase mempool_open\n"
        "advance_clock +1h\n"
        "expect mempool_prune_runs == 1\n",
        &ctx);
    CHAOS_CHECK("clock skew records mempool prune run", rc == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "boot_phase mempool_open\n"
        "advance_clock +1h\n"
        "expect clock_advance_seconds == 3600\n"
        "expect mempool_prune_runs == 1\n"
        "expect mempool_prunes == 1\n",
        &ctx);
    CHAOS_CHECK("advance_clock scenario passes", rc == 0);
    CHAOS_CHECK("advance_clock records simulated time effects",
                ctx.clock_advance_seconds == 3600 &&
                ctx.mempool_prune_runs == 1);

    rc = run_temp_scenario(
        "seed 1\n"
        "advance_clock bad-duration\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("bad advance_clock duration fails", rc != 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "trigger_oom_at chaos_test_alloc\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("trigger_oom_at scenario passes", rc == 0);
    CHAOS_CHECK("trigger_oom_at records synthetic fire",
                ctx.alloc_fault_triggered &&
                ctx.alloc_fault_count == 1 &&
                zcl_alloc_fault_armed_label() == NULL &&
                ctx.graceful_shutdowns == 1);

    zcl_alloc_fault_fail_next("unit_alloc");
    void *failed = zcl_malloc(16, "unit_alloc");
    void *after = zcl_malloc(16, "unit_alloc");
    CHAOS_CHECK("safe_alloc fault fails once",
                failed == NULL && after != NULL &&
                zcl_alloc_fault_armed_label() == NULL);
    free(after);
    zcl_alloc_fault_clear();

    rc = run_temp_scenario(
        "seed 1\n"
        "partition_network for=5s\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("partition_network scenario passes", rc == 0);
    CHAOS_CHECK("partition_network records armed window",
                ctx.net_partition_triggered &&
                ctx.net_partition_seconds == 5 &&
                net_partition_armed_until_unix() == ctx.net_partition_until);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "partition_network for=5s\n"
        "send_block peer=0 file=tests/fixtures/blocks/synthetic_good_block.fixture\n"
        "send_malformed_block peer=0 type=invalid_pow\n"
        "expect partition_drops == 2\n"
        "expect blocks_sent == 0\n"
        "expect consensus_rejects == 0\n"
        "expect tip_height == 0\n",
        &ctx);
    CHAOS_CHECK("partition drops peer messages", rc == 0);
    CHAOS_CHECK("partition drop counters record suppressed traffic",
                ctx.net_partition_drops == 2 &&
                ctx.peers.blocks_sent == 0 &&
                ctx.consensus_rejects == 0 &&
                ctx.tip_height == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "peer_count 1\n"
        "partition_network for=5s\n"
        "advance_clock +5s\n"
        "send_block peer=0 file=tests/fixtures/blocks/synthetic_good_block.fixture\n"
        "expect partition_drops == 0\n"
        "expect blocks_sent == 1\n"
        "expect tip_height == 1\n",
        &ctx);
    CHAOS_CHECK("partition expiry allows peer messages", rc == 0);

    net_partition_until_unix(42);
    CHAOS_CHECK("net partition active before deadline",
                net_partition_active_at(41) &&
                !net_partition_active_at(42));
    net_partition_clear();

    rc = run_temp_scenario(
        "seed 1\n"
        "auto_reindex_request anchor=3173739\n"
        "expect auto_reindex_pending == 1\n"
        "expect auto_reindex_terminal == 0\n"
        "expect auto_reindex_anchor == 3173739\n"
        "expect auto_reindex_count == 1\n"
        "expect auto_reindex_requests == 1\n"
        "auto_reindex_clear_if_covered coins_best=3173739\n"
        "expect auto_reindex_pending == 1\n"
        "expect auto_reindex_clears == 0\n"
        "auto_reindex_clear_if_covered coins_best=3173740\n"
        "expect auto_reindex_pending == 0\n"
        "expect auto_reindex_clears == 1\n",
        &ctx);
    CHAOS_CHECK("auto_reindex stale clear boundary passes", rc == 0);
    CHAOS_CHECK("auto_reindex stale clear records final metrics",
                ctx.auto_reindex_anchor == 0 &&
                ctx.auto_reindex_count == 0 &&
                ctx.auto_reindex_pending == 0 &&
                ctx.auto_reindex_terminal == 0 &&
                ctx.auto_reindex_requests == 1 &&
                ctx.auto_reindex_clears == 1);

    rc = run_temp_scenario(
        "seed 1\n"
        "auto_reindex_request anchor=5000\n"
        "auto_reindex_request anchor=4990\n"
        "auto_reindex_request anchor=4980\n"
        "expect auto_reindex_anchor == 4980\n"
        "expect auto_reindex_count == 3\n"
        "expect auto_reindex_requests == 3\n",
        &ctx);
    CHAOS_CHECK("auto_reindex moving-tip budget passes", rc == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "auto_reindex_request anchor=100\n"
        "auto_reindex_mark_terminal anchor=100\n"
        "auto_reindex_clear_if_covered coins_best=999\n"
        "expect auto_reindex_pending == 0\n"
        "expect auto_reindex_terminal == 1\n"
        "expect auto_reindex_count == -1\n"
        "expect auto_reindex_clears == 0\n",
        &ctx);
    CHAOS_CHECK("auto_reindex terminal marker is not stale-cleared", rc == 0);

    rc = run_temp_scenario(
        "seed 1\n"
        "expect tip_height > 0\n",
        NULL);
    CHAOS_CHECK("failing expect fails scenario", rc != 0);

    char fail_path[128];
    CHAOS_CHECK("artifact scenario write succeeds",
                write_temp_scenario(
                    "seed 0xfeed\n"
                    "expect tip_height > 0\n",
                    fail_path, sizeof(fail_path)) == 0);
    struct chaos_ctx fail_ctx;
    chaos_ctx_init(&fail_ctx);
    fail_ctx.scenario_path = fail_path;
    rc = run_scenario(&fail_ctx);
    fail_ctx.block_bytes = 12;
    fail_ctx.clock_advance_count = 2;
    fail_ctx.clock_advance_seconds = 30;
    fail_ctx.net_partition_seconds = 5;
    fail_ctx.net_partition_drops = 1;
    fail_ctx.auto_reindex_anchor = 3173739;
    fail_ctx.auto_reindex_count = 1;
    fail_ctx.auto_reindex_pending = 1;
    fail_ctx.auto_reindex_requests = 1;
    char artifact_dir[128];
    int dn = snprintf(artifact_dir, sizeof(artifact_dir),
                      "/tmp/zcl_chaos_artifacts_%d_XXXXXX", (int)getpid());
    char *made_dir = dn > 0 && (size_t)dn < sizeof(artifact_dir)
        ? mkdtemp(artifact_dir)
        : NULL;
    fail_ctx.artifact_dir = made_dir;
    int artifact_rc = made_dir ? write_failure_artifacts(&fail_ctx) : -1;
    char stem[128];
    char summary_path[320];
    char copied_path[320];
    sanitize_artifact_stem(fail_path, stem, sizeof(stem));
    snprintf(summary_path, sizeof(summary_path), "%s/%s.failure.txt",
             made_dir ? made_dir : "", stem);
    snprintf(copied_path, sizeof(copied_path), "%s/%s.scenario",
             made_dir ? made_dir : "", stem);
    CHAOS_CHECK("failure artifact writer succeeds",
                rc != 0 && artifact_rc == 0 &&
                file_contains_text(summary_path, "seed=0x000000000000feed") &&
                file_contains_text(summary_path, "block_bytes=12") &&
                file_contains_text(summary_path, "clock_advance_seconds=30") &&
                file_contains_text(summary_path, "partition_drops=1") &&
                file_contains_text(summary_path, "auto_reindex_anchor=3173739") &&
                file_contains_text(summary_path, "auto_reindex_pending=1") &&
                file_contains_text(summary_path, "replay_command=build/bin/zclassic23-chaos") &&
                file_contains_text(copied_path, "expect tip_height > 0"));
    unlink(summary_path);
    unlink(copied_path);
    if (made_dir) rmdir(made_dir);
    unlink(fail_path);

    rc = run_temp_scenario(
        "seed not-a-number\n"
        "expect no_crash\n",
        NULL);
    CHAOS_CHECK("bad seed fails", rc != 0);

    /* ── simnet mode: drives a REAL simnet_cluster (real
     * connect_block/disconnect_block/fork-choice), not sim_peer counters.
     * See tools/sim/chaos.c "simnet mode" block + docs/CHAOS_HARNESS.md. */

    rc = run_temp_scenario(
        "seed 0xC0A1E5C1\n"
        "mode simnet\n"
        "simnet_nodes 3\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_deliver\n"
        "expect simnet_converged == 1\n"
        "simnet_partition a=0 b=2\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_deliver\n"
        "simnet_heal a=0 b=2\n"
        "simnet_deliver\n"
        "expect simnet_converged == 1\n"
        "expect simnet_tip_monotonic == 1\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("simnet partition-then-heal converges", rc == 0);

    rc = run_temp_scenario(
        "seed 0xBEEF000000000002\n"
        "mode simnet\n"
        "simnet_nodes 2\n"
        "simnet_mint node=0\n"
        "simnet_mint node=0\n"
        "simnet_mint node=0\n"
        "simnet_mint node=1\n"
        "simnet_mint node=1\n"
        "simnet_mint node=1\n"
        "simnet_mint node=1\n"
        "simnet_relay node=0\n"
        "simnet_relay node=1\n"
        "simnet_deliver\n"
        "expect simnet_converged == 1\n"
        "expect simnet_tip_monotonic == 1\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("simnet competing-chains reorg converges on more work",
                rc == 0);

    CHAOS_CHECK("simnet mode requires 'mode simnet' first",
                run_temp_scenario(
                    "seed 1\n"
                    "simnet_nodes 2\n"
                    "expect no_crash\n",
                    NULL) != 0);

    CHAOS_CHECK("simnet_nodes rejects an out-of-range count",
                run_temp_scenario(
                    "seed 1\n"
                    "mode simnet\n"
                    "simnet_nodes 1\n"
                    "expect no_crash\n",
                    NULL) != 0);

    /* Two nodes permanently partitioned and left to mint conflicting
     * equal-length branches never converge; the auto-check at end of
     * a simnet-mode run must catch this and fail loudly instead of
     * silently reporting PASS. */
    rc = run_temp_scenario(
        "seed 0xDEADBEEF\n"
        "mode simnet\n"
        "simnet_nodes 2\n"
        "simnet_partition a=0 b=1\n"
        "simnet_mint node=0\n"
        "simnet_relay node=0\n"
        "simnet_mint node=1\n"
        "simnet_relay node=1\n"
        "simnet_deliver\n"
        "expect no_crash\n",
        &ctx);
    CHAOS_CHECK("simnet non-convergence is caught, not silently passed",
                rc != 0 && ctx.simnet_mode);

    if (failures == 0)
        printf("=== chaos_harness tests: ALL PASS ===\n\n");
    else
        printf("chaos_harness: failures=%d\n", failures);
    return failures;
}
