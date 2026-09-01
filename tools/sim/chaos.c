/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic chaos scenario runner.
 *
 * Runs declarative scenarios against simulated peers, virtual time, network
 * partitions, allocation faults, and crash/restart artifacts. The harness is
 * intentionally process-local so failures collapse into reproducible seeds
 * before they reach the production node paths.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chain/chainparams.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "net/net_fault.h"
#include "platform/time_compat.h"
#include "sim/sim_peer.h"
#include "sim/simnet_cluster.h"
#include "sim/simnet_trace.h"
#include "storage/boot_auto_reindex.h"
#include "util/parse_num.h"
#include "util/safe_alloc.h"

#define CHAOS_MAX_LINE 512
#define CHAOS_MAX_ARGS 16
#define CHAOS_MAX_EXPECTS 64
#define CHAOS_TMP_PATH 256
#define CHAOS_SIMNET_MIN_NODES 2
#define CHAOS_SIMNET_MAX_NODES 128

/* Per-node bookkeeping the chaos DSL keeps ON TOP of simnet_cluster so
 * `simnet_relay`/`simnet_heal` can target specific peers without the
 * cluster itself knowing about "partitions" (simnet_cluster only knows
 * broadcast + deliver). `mints` records every hash minted on this node in
 * order, so a heal can always do a full resync to the newly-reachable
 * peer regardless of what had already been relayed elsewhere. */
struct chaos_simnet_node {
    struct uint256 *mints;
    size_t mint_count;
    size_t mint_cap;
    size_t relayed_count;
    bool byzantine;   /* forges invalid blocks instead of honest mints */
};

/* Fixed sub-stream tag: byzantine role/class draws come from
 * splitmix64(seed ^ CHAOS_SIMNET_BYZ_TAG), disjoint from the scenario RNG, so
 * an all-honest cluster (no `honest=`) runs exactly as it did before roles. */
#define CHAOS_SIMNET_BYZ_TAG 0x42595A4E4F444531ULL  /* ASCII "BYZNODE1" */

static uint64_t chaos_splitmix64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

struct chaos_ctx {
    const char *scenario_path;
    const char *artifact_dir;
    uint64_t seed;
    uint64_t rng_state;
    bool seed_set;
    uint64_t seed_override;
    bool seed_override_set;
    char boot_phase[32];
    unsigned peer_count;
    struct sim_peer_set peers;
    struct platform_clock_source clock_src;
    int64_t sim_wall_unix;
    int64_t sim_monotonic_us;
    uint64_t clock_advance_count;
    uint64_t scheduled_event_count;
    int64_t last_event_height;
    bool crashed;
    int64_t tip_height;
    int64_t reorg_count;
    int64_t consensus_rejects;
    int64_t block_bytes;
    int64_t clock_advance_seconds;
    int64_t mempool_prune_runs;
    int64_t graceful_shutdowns;
    size_t expect_count;
    bool verbose;
    char alloc_fault_site[64];
    uint64_t alloc_fault_count;
    bool alloc_fault_triggered;
    int64_t net_partition_seconds;
    int64_t net_partition_until;
    bool net_partition_triggered;
    int64_t net_partition_drops;
    bool auto_reindex_datadir_ready;
    char auto_reindex_datadir[CHAOS_TMP_PATH];
    int64_t auto_reindex_anchor;
    int64_t auto_reindex_count;
    int64_t auto_reindex_requests;
    int64_t auto_reindex_clears;
    int64_t auto_reindex_pending;
    int64_t auto_reindex_terminal;

    /* Real-cluster ("simnet") mode: a chaos scenario drives an actual
     * simnet_cluster (real connect_block/disconnect_block, real
     * fork-choice) instead of the bookkeeping-only sim_peer counters
     * above. Backward compatible: a scenario that never says
     * `mode simnet` never touches any field below. */
    bool simnet_mode;
    struct simnet_cluster *simnet;
    size_t simnet_node_count;
    struct chaos_simnet_node *simnet_nodes;
    bool *simnet_partitioned;    /* node_count*node_count, row-major */
    int32_t *simnet_last_height; /* per node; INT32_MIN = unobserved */
    bool simnet_monotonic_ok;
    int simnet_honest_permille;  /* 1000 = all honest (the default) */
    uint64_t simnet_byz_rng;     /* byzantine role/class sub-stream state */

    /* Optional full-state trace (sim/simnet_trace.h, docs/CHAOS_HARNESS.md
     * "Recording a full-state trace"). NULL/unset means no trace is ever
     * written — every existing scenario and `make chaos` runs exactly as it
     * did before this field existed. Opt-in via `trace_dir PATH` (this
     * scenario file only) or `--trace-dir=PATH` (every scenario the process
     * runs). The writer is opened lazily on the first simnet event that
     * follows, once a cluster actually exists to snapshot. */
    bool trace_dir_set;
    char trace_dir[CHAOS_TMP_PATH];
    bool trace_writer_open;
    struct simnet_trace_writer trace_writer;
    uint64_t trace_seq;
};

typedef int (*chaos_handler_fn)(struct chaos_ctx *ctx, int argc, char **argv,
                                int line_no);

struct chaos_command {
    const char *name;
    chaos_handler_fn handler;
};

static const struct chaos_command *find_command(const char *name);

static int64_t chaos_clock_monotonic_us(void *user)
{
    const struct chaos_ctx *ctx = (const struct chaos_ctx *)user;
    return ctx ? ctx->sim_monotonic_us : 0;
}

static int64_t chaos_clock_wall_unix(void *user)
{
    const struct chaos_ctx *ctx = (const struct chaos_ctx *)user;
    return ctx ? ctx->sim_wall_unix : 0;
}

static void chaos_ctx_init(struct chaos_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    snprintf(ctx->boot_phase, sizeof(ctx->boot_phase), "idb_complete");
    ctx->rng_state = 0x9e3779b97f4a7c15ULL;
    sim_peer_set_init(&ctx->peers);
    ctx->sim_wall_unix = platform_time_wall_unix();
    ctx->clock_src.monotonic_us = chaos_clock_monotonic_us;
    ctx->clock_src.wall_unix = chaos_clock_wall_unix;
    ctx->clock_src.user = ctx;
    ctx->simnet_monotonic_ok = true;
}

static void chaos_simnet_cleanup(struct chaos_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->simnet_nodes) {
        for (size_t i = 0; i < ctx->simnet_node_count; i++)
            free(ctx->simnet_nodes[i].mints);
        free(ctx->simnet_nodes);
        ctx->simnet_nodes = NULL;
    }
    free(ctx->simnet_partitioned);
    ctx->simnet_partitioned = NULL;
    free(ctx->simnet_last_height);
    ctx->simnet_last_height = NULL;
    if (ctx->simnet) {
        simnet_cluster_free(ctx->simnet);
        ctx->simnet = NULL;
    }
    if (ctx->trace_writer_open) {
        simnet_trace_writer_close(&ctx->trace_writer);
        ctx->trace_writer_open = false;
    }
}

static const char *arg_value(int argc, char **argv, const char *key)
{
    size_t key_len = strlen(key);
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], key, key_len) == 0 && argv[i][key_len] == '=')
            return argv[i] + key_len + 1;
    }
    return NULL;
}

static char *trim_ascii(char *s)
{
    if (!s) return s;
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static int split_args(char *line, char **argv, int argv_cap)
{
    int argc = 0;
    char *p = line;
    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        if (argc >= argv_cap) return -E2BIG;
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

static bool parse_u64_auto(const char *s, uint64_t *out)
{
    if (!s || !*s || !out) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

static bool parse_duration_seconds(const char *s, int64_t *out)
{
    if (!s || !*s || !out) return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || v <= 0) return false;

    int64_t mult = 1;
    if (*end == '\0' || strcmp(end, "s") == 0) {
        mult = 1;
    } else if (strcmp(end, "m") == 0) {
        mult = 60;
    } else if (strcmp(end, "h") == 0) {
        mult = 60 * 60;
    } else if (strcmp(end, "d") == 0) {
        mult = 24 * 60 * 60;
    } else {
        return false;
    }

    if (v > INT64_MAX / mult) return false;
    *out = (int64_t)v * mult;
    return true;
}

static int fail_line(int line_no, const char *msg)
{
    fprintf(stderr, "chaos:%d: %s\n", line_no, msg);
    return -EINVAL;
}

static uint64_t chaos_rng_next(struct chaos_ctx *ctx)
{
    uint64_t x = ctx->rng_state;
    if (x == 0)
        x = 0x9e3779b97f4a7c15ULL;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    ctx->rng_state = x;
    return x * 0x2545f4914f6cdd1dULL;
}

static void chaos_set_seed(struct chaos_ctx *ctx, uint64_t seed)
{
    ctx->seed = seed;
    ctx->rng_state = seed ^ 0x9e3779b97f4a7c15ULL;
    ctx->seed_set = true;
}

static const char *path_basename(const char *path)
{
    const char *base = path;
    if (!path) return "scenario";
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    return *base ? base : "scenario";
}

static void sanitize_artifact_stem(const char *path, char *out,
                                   size_t out_len)
{
    const char *base = path_basename(path);
    size_t n = 0;
    if (out_len == 0) return;
    for (const unsigned char *p = (const unsigned char *)base;
         *p && n + 1 < out_len; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.')
            out[n++] = (char)*p;
        else
            out[n++] = '_';
    }
    if (n == 0 && out_len > 1)
        out[n++] = 'x';
    out[n] = '\0';
}

static int copy_file_bytes(const char *src_path, const char *dst_path)
{
    FILE *src = fopen(src_path, "rb");
    if (!src) return -errno;
    FILE *dst = fopen(dst_path, "wb");
    if (!dst) {
        int rc = -errno;
        fclose(src);
        return rc;
    }

    char buf[4096];
    int rc = 0;
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), src);
        if (n > 0 && fwrite(buf, 1, n, dst) != n) {
            rc = -EIO;
            break;
        }
        if (n < sizeof(buf)) {
            if (ferror(src))
                rc = -EIO;
            break;
        }
    }

    if (fclose(src) != 0 && rc == 0)
        rc = -EIO;
    if (fclose(dst) != 0 && rc == 0)
        rc = -EIO;
    return rc;
}

static void chaos_auto_reindex_refresh(struct chaos_ctx *ctx)
{
    int32_t anchor = 0;
    int count = 0;

    ctx->auto_reindex_anchor = 0;
    ctx->auto_reindex_count = 0;
    ctx->auto_reindex_pending = 0;
    ctx->auto_reindex_terminal = 0;

    if (!ctx->auto_reindex_datadir_ready)
        return;

    if (boot_auto_reindex_status(ctx->auto_reindex_datadir, &anchor, &count)) {
        ctx->auto_reindex_anchor = anchor;
        ctx->auto_reindex_count = count;
    }
    ctx->auto_reindex_pending =
        boot_auto_reindex_pending(ctx->auto_reindex_datadir) ? 1 : 0;
    ctx->auto_reindex_terminal =
        boot_auto_reindex_is_terminal(ctx->auto_reindex_datadir) ? 1 : 0;
}

static int chaos_auto_reindex_ensure_datadir(struct chaos_ctx *ctx,
                                             int line_no)
{
    if (ctx->auto_reindex_datadir_ready)
        return 0;

    char tmpl[CHAOS_TMP_PATH];
    int n = snprintf(tmpl, sizeof(tmpl),
                     "/tmp/zcl_chaos_auto_reindex_%ld_XXXXXX",
                     (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmpl))
        return fail_line(line_no, "auto_reindex temp path is too long");

    char *made = mkdtemp(tmpl);
    if (!made)
        return fail_line(line_no, "auto_reindex temp datadir failed");
    n = snprintf(ctx->auto_reindex_datadir,
                 sizeof(ctx->auto_reindex_datadir), "%s", made);
    if (n < 0 || (size_t)n >= sizeof(ctx->auto_reindex_datadir)) {
        (void)rmdir(made);
        return fail_line(line_no, "auto_reindex temp datadir path too long");
    }

    ctx->auto_reindex_datadir_ready = true;
    chaos_auto_reindex_refresh(ctx);
    return 0;
}

static void chaos_auto_reindex_cleanup(struct chaos_ctx *ctx)
{
    if (!ctx || !ctx->auto_reindex_datadir_ready)
        return;

    char marker[CHAOS_TMP_PATH + 32];
    int n = snprintf(marker, sizeof(marker), "%s/auto_reindex_request",
                     ctx->auto_reindex_datadir);
    if (n > 0 && (size_t)n < sizeof(marker))
        (void)remove(marker);
    (void)rmdir(ctx->auto_reindex_datadir);
    ctx->auto_reindex_datadir_ready = false;
    ctx->auto_reindex_datadir[0] = '\0';
}

static int write_failure_artifacts(const struct chaos_ctx *ctx)
{
    const char *dir = ctx && ctx->artifact_dir ? ctx->artifact_dir
                                               : "chaos-output";
    if (!ctx || !ctx->scenario_path || !*ctx->scenario_path)
        return -EINVAL;
    if (mkdir(dir, 0777) != 0 && errno != EEXIST)
        return -errno;

    char stem[128];
    sanitize_artifact_stem(ctx->scenario_path, stem, sizeof(stem));

    char summary_path[512];
    char scenario_path[512];
    int n = snprintf(summary_path, sizeof(summary_path),
                     "%s/%s.failure.txt", dir, stem);
    if (n < 0 || (size_t)n >= sizeof(summary_path))
        return -ENAMETOOLONG;
    n = snprintf(scenario_path, sizeof(scenario_path),
                 "%s/%s.scenario", dir, stem);
    if (n < 0 || (size_t)n >= sizeof(scenario_path))
        return -ENAMETOOLONG;

    FILE *summary = fopen(summary_path, "wb");
    if (!summary)
        return -errno;
    fprintf(summary, "scenario=%s\n", ctx->scenario_path);
    fprintf(summary, "seed=%s0x%016" PRIx64 "\n",
            ctx->seed_set ? "" : "(default)", ctx->seed);
    fprintf(summary, "boot_phase=%s\n", ctx->boot_phase);
    fprintf(summary, "peer_count=%u\n", ctx->peer_count);
    fprintf(summary, "expects=%zu\n", ctx->expect_count);
    fprintf(summary, "tip_height=%" PRId64 "\n", ctx->tip_height);
    fprintf(summary, "reorg_count=%" PRId64 "\n", ctx->reorg_count);
    fprintf(summary, "consensus_rejects=%" PRId64 "\n",
            ctx->consensus_rejects);
    fprintf(summary, "blocks_sent=%u\n", ctx->peers.blocks_sent);
    fprintf(summary, "block_bytes=%" PRId64 "\n", ctx->block_bytes);
    fprintf(summary, "malformed_blocks=%u\n",
            ctx->peers.malformed_blocks_sent);
    fprintf(summary, "active_peers=%u\n", ctx->peers.active_count);
    fprintf(summary, "killed_peers=%u\n", ctx->peers.killed_count);
    fprintf(summary, "clock_advance_count=%" PRIu64 "\n",
            ctx->clock_advance_count);
    fprintf(summary, "clock_advance_seconds=%" PRId64 "\n",
            ctx->clock_advance_seconds);
    fprintf(summary, "scheduled_events=%" PRIu64 "\n",
            ctx->scheduled_event_count);
    fprintf(summary, "simnet_mode=%d\n", ctx->simnet_mode ? 1 : 0);
    if (ctx->simnet_mode) {
        fprintf(summary, "simnet_node_count=%zu\n", ctx->simnet_node_count);
        fprintf(summary, "simnet_tip_monotonic=%d\n",
                ctx->simnet_monotonic_ok ? 1 : 0);
    }
    fprintf(summary, "alloc_faults=%" PRIu64 "\n", ctx->alloc_fault_count);
    fprintf(summary, "graceful_shutdowns=%" PRId64 "\n",
            ctx->graceful_shutdowns);
    fprintf(summary, "partition_seconds=%" PRId64 "\n",
            ctx->net_partition_seconds);
    fprintf(summary, "partition_until=%" PRId64 "\n",
            ctx->net_partition_until);
    fprintf(summary, "partition_drops=%" PRId64 "\n",
            ctx->net_partition_drops);
    fprintf(summary, "auto_reindex_anchor=%" PRId64 "\n",
            ctx->auto_reindex_anchor);
    fprintf(summary, "auto_reindex_count=%" PRId64 "\n",
            ctx->auto_reindex_count);
    fprintf(summary, "auto_reindex_pending=%" PRId64 "\n",
            ctx->auto_reindex_pending);
    fprintf(summary, "auto_reindex_terminal=%" PRId64 "\n",
            ctx->auto_reindex_terminal);
    fprintf(summary, "auto_reindex_requests=%" PRId64 "\n",
            ctx->auto_reindex_requests);
    fprintf(summary, "auto_reindex_clears=%" PRId64 "\n",
            ctx->auto_reindex_clears);
    fprintf(summary, "artifact_scenario=%s\n", scenario_path);
    fprintf(summary, "replay_command=build/bin/zclassic23-chaos --scenario=%s --verbose\n",
            scenario_path);
    int close_rc = fclose(summary);
    if (close_rc != 0)
        return -EIO;

    return copy_file_bytes(ctx->scenario_path, scenario_path);
}

static int handle_seed(struct chaos_ctx *ctx, int argc, char **argv,
                       int line_no)
{
    if (argc != 2) return fail_line(line_no, "seed requires one value");
    if (ctx->seed_override_set)
        return 0;
    uint64_t seed = 0;
    if (!parse_u64_auto(argv[1], &seed))
        return fail_line(line_no, "seed must be an integer or hex value");
    chaos_set_seed(ctx, seed);
    return 0;
}

static int handle_boot_phase(struct chaos_ctx *ctx, int argc, char **argv,
                             int line_no)
{
    if (argc != 2) return fail_line(line_no, "boot_phase requires one value");
    if (strcmp(argv[1], "idb_complete") != 0 &&
        strcmp(argv[1], "listening") != 0 &&
        strcmp(argv[1], "mempool_open") != 0) {
        return fail_line(line_no, "unknown boot_phase");
    }
    snprintf(ctx->boot_phase, sizeof(ctx->boot_phase), "%s", argv[1]);
    return 0;
}

static int handle_peer_count(struct chaos_ctx *ctx, int argc, char **argv,
                             int line_no)
{
    if (argc != 2) return fail_line(line_no, "peer_count requires one value");
    uint64_t n = 0;
    if (!parse_u64_auto(argv[1], &n) || n > 1024)
        return fail_line(line_no, "peer_count must be 0..1024");
    if (sim_peer_set_resize(&ctx->peers, (unsigned)n) != 0)
        return fail_line(line_no, "failed to create simulated peers");
    ctx->peer_count = (unsigned)n;
    return 0;
}

/* Defined further down alongside the rest of the simnet-mode handlers;
 * forward-declared so metric_value() (which predates simnet mode in this
 * file) can expose simnet_converged as an `expect` metric. */
static bool chaos_simnet_converged(const struct chaos_ctx *ctx);

static int compare_metric(int64_t actual, const char *op, int64_t expected)
{
    if (strcmp(op, "==") == 0) return actual == expected ? 0 : -1;
    if (strcmp(op, "!=") == 0) return actual != expected ? 0 : -1;
    if (strcmp(op, ">=") == 0) return actual >= expected ? 0 : -1;
    if (strcmp(op, "<=") == 0) return actual <= expected ? 0 : -1;
    if (strcmp(op, ">") == 0) return actual > expected ? 0 : -1;
    if (strcmp(op, "<") == 0) return actual < expected ? 0 : -1;
    return -2;
}

static bool metric_value(const struct chaos_ctx *ctx, const char *name,
                         int64_t *out)
{
    if (strcmp(name, "tip_height") == 0) {
        *out = ctx->tip_height;
        return true;
    }
    if (strcmp(name, "reorg_count") == 0) {
        *out = ctx->reorg_count;
        return true;
    }
    if (strcmp(name, "consensus_rejects") == 0) {
        *out = ctx->consensus_rejects;
        return true;
    }
    if (strcmp(name, "clock_advance_seconds") == 0) {
        *out = ctx->clock_advance_seconds;
        return true;
    }
    if (strcmp(name, "graceful_shutdowns") == 0) {
        *out = ctx->graceful_shutdowns;
        return true;
    }
    if (strcmp(name, "mempool_prune_runs") == 0 ||
        strcmp(name, "mempool_prunes") == 0) {
        *out = ctx->mempool_prune_runs;
        return true;
    }
    if (strcmp(name, "active_peers") == 0) {
        *out = (int64_t)ctx->peers.active_count;
        return true;
    }
    if (strcmp(name, "killed_peers") == 0) {
        *out = (int64_t)ctx->peers.killed_count;
        return true;
    }
    if (strcmp(name, "blocks_sent") == 0) {
        *out = (int64_t)ctx->peers.blocks_sent;
        return true;
    }
    if (strcmp(name, "block_bytes") == 0) {
        *out = ctx->block_bytes;
        return true;
    }
    if (strcmp(name, "malformed_blocks") == 0) {
        *out = (int64_t)ctx->peers.malformed_blocks_sent;
        return true;
    }
    if (strcmp(name, "clock_advance_count") == 0) {
        *out = (int64_t)ctx->clock_advance_count;
        return true;
    }
    if (strcmp(name, "scheduled_events") == 0) {
        *out = (int64_t)ctx->scheduled_event_count;
        return true;
    }
    if (strcmp(name, "alloc_faults") == 0) {
        *out = (int64_t)ctx->alloc_fault_count;
        return true;
    }
    if (strcmp(name, "partition_drops") == 0) {
        *out = ctx->net_partition_drops;
        return true;
    }
    if (strcmp(name, "sim_time") == 0) {
        *out = ctx->sim_wall_unix;
        return true;
    }
    if (strcmp(name, "auto_reindex_anchor") == 0) {
        *out = ctx->auto_reindex_anchor;
        return true;
    }
    if (strcmp(name, "auto_reindex_count") == 0) {
        *out = ctx->auto_reindex_count;
        return true;
    }
    if (strcmp(name, "auto_reindex_pending") == 0) {
        *out = ctx->auto_reindex_pending;
        return true;
    }
    if (strcmp(name, "auto_reindex_terminal") == 0) {
        *out = ctx->auto_reindex_terminal;
        return true;
    }
    if (strcmp(name, "auto_reindex_requests") == 0) {
        *out = ctx->auto_reindex_requests;
        return true;
    }
    if (strcmp(name, "auto_reindex_clears") == 0) {
        *out = ctx->auto_reindex_clears;
        return true;
    }
    if (strcmp(name, "simnet_converged") == 0) {
        *out = chaos_simnet_converged(ctx) ? 1 : 0;
        return true;
    }
    if (strcmp(name, "simnet_tip_monotonic") == 0) {
        *out = ctx->simnet_monotonic_ok ? 1 : 0;
        return true;
    }
    if (strcmp(name, "simnet_node_count") == 0) {
        *out = (int64_t)ctx->simnet_node_count;
        return true;
    }
    return false;
}

static int handle_expect(struct chaos_ctx *ctx, int argc, char **argv,
                         int line_no)
{
    if (argc < 2) return fail_line(line_no, "expect requires an assertion");
    if (ctx->expect_count >= CHAOS_MAX_EXPECTS)
        return fail_line(line_no, "too many expect assertions");
    ctx->expect_count++;

    if (argc == 2 && strcmp(argv[1], "no_crash") == 0) {
        if (ctx->crashed) {
            fprintf(stderr, "chaos:%d: expect no_crash failed\n", line_no);
            return -1;
        }
        return 0;
    }

    if (argc == 4) {
        int64_t actual = 0;
        int64_t expected = 0;
        if (!metric_value(ctx, argv[1], &actual))
            return fail_line(line_no, "unknown expect metric");
        if (!zcl_parse_i64(argv[3], &expected))
            return fail_line(line_no, "expect value must be an integer");
        int cmp = compare_metric(actual, argv[2], expected);
        if (cmp == -2) return fail_line(line_no, "unknown expect operator");
        if (cmp != 0) {
            fprintf(stderr,
                    "chaos:%d: expect failed: %s %s %" PRId64
                    " (actual=%" PRId64 ")\n",
                    line_no, argv[1], argv[2], expected, actual);
            return -1;
        }
        return 0;
    }

    return fail_line(line_no, "unsupported expect assertion");
}

static int handle_trigger_oom_at(struct chaos_ctx *ctx, int argc, char **argv,
                                 int line_no)
{
    if (argc != 2) return fail_line(line_no, "trigger_oom_at requires one label");
    if (strlen(argv[1]) >= sizeof(ctx->alloc_fault_site))
        return fail_line(line_no, "trigger_oom_at label too long");

    snprintf(ctx->alloc_fault_site, sizeof(ctx->alloc_fault_site), "%s",
             argv[1]);
    zcl_alloc_fault_fail_next(ctx->alloc_fault_site);
    void *p = zcl_malloc(1, ctx->alloc_fault_site);
    if (p) {
        free(p);
        return fail_line(line_no, "allocation fault did not fire");
    }
    if (zcl_alloc_fault_armed_label() != NULL)
        return fail_line(line_no, "allocation fault did not clear");
    ctx->alloc_fault_count++;
    ctx->alloc_fault_triggered = true;
    ctx->graceful_shutdowns++;
    return 0;
}

static int handle_kill_peer(struct chaos_ctx *ctx, int argc, char **argv,
                            int line_no)
{
    if (argc != 2) return fail_line(line_no, "kill_peer requires one peer id");
    uint64_t id = 0;
    if (!parse_u64_auto(argv[1], &id) || id > UINT32_MAX)
        return fail_line(line_no, "kill_peer id must be an integer");
    int rc = sim_peer_kill(&ctx->peers, (unsigned)id);
    if (rc == -ENOENT)
        return fail_line(line_no, "kill_peer id is not configured");
    if (rc == -EALREADY)
        return fail_line(line_no, "kill_peer id is already disconnected");
    if (rc != 0)
        return fail_line(line_no, "kill_peer failed");
    return 0;
}

static int handle_random_kill_peers(struct chaos_ctx *ctx, int argc,
                                    char **argv, int line_no)
{
    if (argc != 2)
        return fail_line(line_no, "random_kill_peers requires count=N");

    const char *count_arg = arg_value(argc, argv, "count");
    uint64_t count = 0;
    if (!count_arg || !parse_u64_auto(count_arg, &count) ||
        count > UINT32_MAX) {
        return fail_line(line_no,
                         "random_kill_peers count must be an integer");
    }
    if (count > ctx->peers.active_count)
        return fail_line(line_no,
                         "random_kill_peers count exceeds active peers");

    for (uint64_t killed = 0; killed < count; killed++) {
        unsigned active_index =
            (unsigned)(chaos_rng_next(ctx) % ctx->peers.active_count);
        unsigned selected = UINT32_MAX;
        for (unsigned i = 0, seen = 0; i < ctx->peers.count; i++) {
            if (!ctx->peers.peers[i].connected)
                continue;
            if (seen == active_index) {
                selected = i;
                break;
            }
            seen++;
        }
        if (selected == UINT32_MAX)
            return fail_line(line_no, "random_kill_peers selection failed");
        int rc = sim_peer_kill(&ctx->peers, selected);
        if (rc != 0)
            return fail_line(line_no, "random_kill_peers kill failed");
    }
    return 0;
}

static int handle_send_block(struct chaos_ctx *ctx, int argc, char **argv,
                             int line_no)
{
    if (argc != 3 && argc != 4)
        return fail_line(line_no,
                         "send_block requires peer=I file=PATH [height=N]");

    const char *peer_arg = arg_value(argc, argv, "peer");
    const char *path = arg_value(argc, argv, "file");
    const char *height_arg = arg_value(argc, argv, "height");
    uint64_t peer_id = 0;
    if (!peer_arg || !parse_u64_auto(peer_arg, &peer_id) ||
        peer_id > UINT32_MAX) {
        return fail_line(line_no, "send_block peer must be integer");
    }
    if (!path || !*path)
        return fail_line(line_no, "send_block file is required");
    int64_t height = 0;
    if (height_arg && (!zcl_parse_i64(height_arg, &height) || height <= 0))
        return fail_line(line_no, "send_block height must be a positive integer");

    const struct sim_peer *peer = sim_peer_get(&ctx->peers, (unsigned)peer_id);
    if (!peer)
        return fail_line(line_no, "send_block peer is not configured");
    if (!peer->connected)
        return fail_line(line_no, "send_block peer is disconnected");
    if (net_partition_active_at(platform_time_wall_unix())) {
        ctx->net_partition_drops++;
        return 0;
    }

    size_t bytes_read = 0;
    int rc = sim_peer_send_block(&ctx->peers, (unsigned)peer_id, path,
                                 &bytes_read);
    if (rc == -ENOENT)
        return fail_line(line_no, "send_block peer is not configured");
    if (rc == -ENOTCONN)
        return fail_line(line_no, "send_block peer is disconnected");
    if (rc == -ENODATA)
        return fail_line(line_no, "send_block fixture is empty");
    if (rc != 0)
        return fail_line(line_no, "send_block fixture could not be read");

    if (bytes_read > (size_t)(INT64_MAX - ctx->block_bytes))
        return fail_line(line_no, "send_block byte counter overflows");
    ctx->block_bytes += (int64_t)bytes_read;
    if (height_arg) {
        if (height > ctx->tip_height)
            ctx->tip_height = height;
    } else {
        ctx->tip_height++;
    }
    return 0;
}

static int handle_send_malformed_block(struct chaos_ctx *ctx, int argc,
                                       char **argv, int line_no)
{
    if (argc != 3)
        return fail_line(line_no,
                         "send_malformed_block requires peer=I type=ENUM");

    const char *peer_arg = arg_value(argc, argv, "peer");
    const char *type = arg_value(argc, argv, "type");
    uint64_t peer_id = 0;
    if (!peer_arg || !parse_u64_auto(peer_arg, &peer_id) ||
        peer_id > UINT32_MAX) {
        return fail_line(line_no, "send_malformed_block peer must be integer");
    }
    if (!type || !sim_peer_malformed_type_known(type))
        return fail_line(line_no, "send_malformed_block unknown type");

    const struct sim_peer *peer = sim_peer_get(&ctx->peers, (unsigned)peer_id);
    if (!peer)
        return fail_line(line_no, "send_malformed_block peer is not configured");
    if (!peer->connected)
        return fail_line(line_no, "send_malformed_block peer is disconnected");
    if (net_partition_active_at(platform_time_wall_unix())) {
        ctx->net_partition_drops++;
        return 0;
    }

    int rc = sim_peer_send_malformed_block(&ctx->peers, (unsigned)peer_id,
                                           type);
    if (rc == -ENOENT)
        return fail_line(line_no, "send_malformed_block peer is not configured");
    if (rc == -ENOTCONN)
        return fail_line(line_no, "send_malformed_block peer is disconnected");
    if (rc != 0)
        return fail_line(line_no, "send_malformed_block failed");

    ctx->consensus_rejects++;
    return 0;
}

static int handle_at_event(struct chaos_ctx *ctx, int argc, char **argv,
                           int line_no)
{
    if (argc < 3)
        return fail_line(line_no, "at_event requires HEIGHT COMMAND [ARGS]");
    int64_t event_height = 0;
    if (!zcl_parse_i64(argv[1], &event_height) || event_height < 0)
        return fail_line(line_no, "at_event height must be a non-negative integer");

    const struct chaos_command *cmd = find_command(argv[2]);
    if (!cmd)
        return fail_line(line_no, "at_event nested command is unknown");
    if (strcmp(argv[2], "at_event") == 0)
        return fail_line(line_no, "at_event cannot nest at_event");

    ctx->scheduled_event_count++;
    ctx->last_event_height = event_height;
    return cmd->handler(ctx, argc - 2, argv + 2, line_no);
}

static int handle_advance_clock(struct chaos_ctx *ctx, int argc, char **argv,
                                int line_no)
{
    if (argc != 2)
        return fail_line(line_no, "advance_clock requires one duration");

    const char *duration = argv[1];
    if (*duration == '+')
        duration++;

    int64_t seconds = 0;
    if (!parse_duration_seconds(duration, &seconds))
        return fail_line(line_no,
                         "advance_clock duration must be +Ns/+Nm/+Nh/+Nd");
    if (ctx->sim_wall_unix > INT64_MAX - seconds)
        return fail_line(line_no, "advance_clock wall time overflows");
    if (seconds > (INT64_MAX - ctx->sim_monotonic_us) / 1000000LL)
        return fail_line(line_no, "advance_clock monotonic time overflows");
    if (ctx->clock_advance_seconds > INT64_MAX - seconds)
        return fail_line(line_no, "advance_clock duration overflows");

    ctx->sim_wall_unix += seconds;
    ctx->sim_monotonic_us += seconds * 1000000LL;
    ctx->clock_advance_count++;
    ctx->clock_advance_seconds += seconds;
    if (ctx->peers.active_count > 0)
        ctx->tip_height += seconds / 60;
    if (strcmp(ctx->boot_phase, "mempool_open") == 0 && seconds >= 3600)
        ctx->mempool_prune_runs += seconds / 3600;
    return 0;
}

static int handle_partition_network(struct chaos_ctx *ctx, int argc,
                                    char **argv, int line_no)
{
    if (argc != 2)
        return fail_line(line_no, "partition_network requires for=DURATION");

    const char *duration = argv[1];
    if (strncmp(duration, "for=", 4) == 0)
        duration += 4;

    int64_t seconds = 0;
    if (!parse_duration_seconds(duration, &seconds))
        return fail_line(line_no,
                         "partition_network duration must be Ns/Nm/Nh/Nd");

    int64_t now = platform_time_wall_unix();
    if (now > INT64_MAX - seconds)
        return fail_line(line_no, "partition_network duration overflows");

    ctx->net_partition_seconds = seconds;
    ctx->net_partition_until = now + seconds;
    net_partition_until_unix(ctx->net_partition_until);
    if (!net_partition_active_at(now))
        return fail_line(line_no, "network partition did not arm");
    ctx->net_partition_triggered = true;
    return 0;
}

static int parse_anchor_arg(int argc, char **argv, const char *key,
                            int32_t *out, int line_no)
{
    const char *value = arg_value(argc, argv, key);
    int64_t parsed = 0;
    if (!value || !zcl_parse_i64(value, &parsed) ||
        parsed < 0 || parsed > INT32_MAX) {
        return fail_line(line_no,
                         "auto_reindex anchor/height must be 0..INT32_MAX");
    }
    *out = (int32_t)parsed;
    return 0;
}

static int handle_auto_reindex_request(struct chaos_ctx *ctx, int argc,
                                       char **argv, int line_no)
{
    if (argc != 2)
        return fail_line(line_no, "auto_reindex_request requires anchor=N");
    if (chaos_auto_reindex_ensure_datadir(ctx, line_no) != 0)
        return -EINVAL;

    int32_t anchor = 0;
    if (parse_anchor_arg(argc, argv, "anchor", &anchor, line_no) != 0)
        return -EINVAL;

    int count = boot_auto_reindex_request(ctx->auto_reindex_datadir, anchor);
    if (count == 0)
        return fail_line(line_no, "auto_reindex_request write failed");
    ctx->auto_reindex_requests++;
    chaos_auto_reindex_refresh(ctx);
    return 0;
}

static int handle_auto_reindex_mark_terminal(struct chaos_ctx *ctx, int argc,
                                             char **argv, int line_no)
{
    if (argc != 2)
        return fail_line(line_no,
                         "auto_reindex_mark_terminal requires anchor=N");
    if (chaos_auto_reindex_ensure_datadir(ctx, line_no) != 0)
        return -EINVAL;

    int32_t anchor = 0;
    if (parse_anchor_arg(argc, argv, "anchor", &anchor, line_no) != 0)
        return -EINVAL;
    if (!boot_auto_reindex_mark_terminal(ctx->auto_reindex_datadir, anchor))
        return fail_line(line_no, "auto_reindex terminal write failed");

    chaos_auto_reindex_refresh(ctx);
    return 0;
}

static int handle_auto_reindex_clear_if_covered(struct chaos_ctx *ctx,
                                                int argc, char **argv,
                                                int line_no)
{
    if (argc != 2)
        return fail_line(line_no,
                         "auto_reindex_clear_if_covered requires coins_best=N");
    if (chaos_auto_reindex_ensure_datadir(ctx, line_no) != 0)
        return -EINVAL;

    int32_t coins_best = 0;
    if (parse_anchor_arg(argc, argv, "coins_best", &coins_best, line_no) != 0)
        return -EINVAL;

    int32_t anchor = 0;
    int count = 0;
    if (boot_auto_reindex_status(ctx->auto_reindex_datadir, &anchor, &count) &&
        count > 0 && anchor > 0 && coins_best > anchor) {
        boot_auto_reindex_clear(ctx->auto_reindex_datadir);
        ctx->auto_reindex_clears++;
    }

    chaos_auto_reindex_refresh(ctx);
    return 0;
}

/* ── full-state trace: opt-in NDJSON snapshot per simnet event ──────────
 *
 * Additive instrumentation ONLY — a scenario that never says `trace_dir`
 * and a process never given `--trace-dir=` runs exactly as it did before
 * this existed (trace_dir_set stays false, so every trace_* helper below is
 * a no-op). See sim/simnet_trace.h for the file format and the
 * "why not a live diagnostics dumper" rationale, and docs/CHAOS_HARNESS.md
 * "Recording a full-state trace" for the operator-facing walkthrough.
 */

static int handle_trace_dir(struct chaos_ctx *ctx, int argc, char **argv,
                            int line_no)
{
    if (argc != 2)
        return fail_line(line_no, "trace_dir requires one directory path");
    if (ctx->trace_dir_set)
        return fail_line(line_no, "trace_dir is already set");
    if (strlen(argv[1]) >= sizeof(ctx->trace_dir))
        return fail_line(line_no, "trace_dir path is too long");
    snprintf(ctx->trace_dir, sizeof(ctx->trace_dir), "%s", argv[1]);
    ctx->trace_dir_set = true;
    return 0;
}

/* Lazily creates the trace directory and opens the writer on the first call
 * (a no-op on every call after). Only ever invoked from a simnet event
 * handler, so ctx->simnet already exists by the time this runs. */
static int chaos_trace_ensure_open(struct chaos_ctx *ctx, int line_no)
{
    if (!ctx->trace_dir_set || ctx->trace_writer_open)
        return 0;

    if (mkdir(ctx->trace_dir, 0777) != 0 && errno != EEXIST)
        return fail_line(line_no, "trace_dir could not be created");

    char path[sizeof(ctx->trace_dir) + 32];
    int n = snprintf(path, sizeof(path), "%s/simnet_trace.jsonl",
                     ctx->trace_dir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return fail_line(line_no, "trace_dir path is too long");

    if (!simnet_trace_writer_open(&ctx->trace_writer, path))
        return fail_line(line_no, "trace writer failed to open");
    ctx->trace_writer_open = true;
    return 0;
}

/* Called after every simnet_mint/simnet_deliver/simnet_partition/simnet_heal
 * that changed cluster state. A no-op unless `trace_dir` (or --trace-dir=)
 * was configured for this run. */
static int chaos_trace_record(struct chaos_ctx *ctx, int line_no,
                              const char *event)
{
    if (!ctx->trace_dir_set)
        return 0;
    int rc = chaos_trace_ensure_open(ctx, line_no);
    if (rc != 0)
        return rc;
    ctx->trace_seq++;
    if (!simnet_trace_write_event(&ctx->trace_writer, ctx->simnet,
                                  ctx->simnet_node_count, ctx->trace_seq,
                                  event))
        return fail_line(line_no, "trace write failed");
    return 0;
}

/* ── simnet mode: drive a real simnet_cluster instead of sim_peer ───────
 *
 * `mode simnet` switches a scenario file into this mode. From then on:
 *   simnet_nodes N              create an N-node cluster (uses `seed`)
 *   simnet_mint node=I          mint a block on node I
 *   simnet_relay node=I         broadcast node I's un-relayed mints to
 *                               every peer not currently partitioned
 *                               from I
 *   simnet_deliver               drain the deterministic delivery queue
 *   simnet_partition a=I b=J    sever the I<->J link
 *   simnet_heal a=I b=J         restore I<->J and resync both directions
 * A scenario mixes these with `expect simnet_converged == 1` /
 * `expect simnet_tip_monotonic == 1`; the harness ALSO re-checks both
 * automatically at end-of-run regardless of what the scenario wrote,
 * see run_scenario().
 */

static int handle_mode(struct chaos_ctx *ctx, int argc, char **argv,
                       int line_no)
{
    if (argc != 2) return fail_line(line_no, "mode requires one value");
    if (strcmp(argv[1], "simnet") != 0)
        return fail_line(line_no, "unknown mode (only 'simnet' is defined)");
    if (ctx->simnet_mode)
        return fail_line(line_no, "mode simnet is already active");
    if (ctx->peer_count > 0)
        return fail_line(line_no,
                         "mode simnet cannot follow legacy peer_count");
    ctx->simnet_mode = true;
    return 0;
}

static int handle_simnet_nodes(struct chaos_ctx *ctx, int argc, char **argv,
                               int line_no)
{
    if (!ctx->simnet_mode)
        return fail_line(line_no, "simnet_nodes requires 'mode simnet' first");
    if (ctx->simnet)
        return fail_line(line_no, "simnet_nodes already created a cluster");
    if (argc != 2 && argc != 3)
        return fail_line(line_no,
                         "simnet_nodes requires N [honest=<permille>]");
    uint64_t n = 0;
    if (!parse_u64_auto(argv[1], &n) || n < CHAOS_SIMNET_MIN_NODES ||
        n > CHAOS_SIMNET_MAX_NODES) {
        return fail_line(line_no, "simnet_nodes must be 2..128");
    }

    /* honest=<permille> (0..1000; 1000=all honest, the default). Integer
     * permille — NOT a float — for exact deterministic reproducibility. */
    int honest_permille = 1000;
    if (argc == 3) {
        const char *hv = arg_value(argc, argv, "honest");
        uint64_t permille = 0;
        if (!hv || !parse_u64_auto(hv, &permille) || permille > 1000)
            return fail_line(line_no,
                             "simnet_nodes honest= must be 0..1000 (permille)");
        honest_permille = (int)permille;
    }

    ctx->simnet = simnet_cluster_init((size_t)n, ctx->seed);
    if (!ctx->simnet)
        return fail_line(line_no, "simnet cluster init failed");
    ctx->simnet_node_count = (size_t)n;

    ctx->simnet_nodes = zcl_calloc((size_t)n, sizeof(*ctx->simnet_nodes),
                                   "chaos_simnet_nodes");
    ctx->simnet_partitioned =
        zcl_calloc((size_t)(n * n), sizeof(*ctx->simnet_partitioned),
                  "chaos_simnet_partition");
    ctx->simnet_last_height =
        zcl_calloc((size_t)n, sizeof(*ctx->simnet_last_height),
                  "chaos_simnet_height");
    if (!ctx->simnet_nodes || !ctx->simnet_partitioned ||
        !ctx->simnet_last_height) {
        chaos_simnet_cleanup(ctx);
        return fail_line(line_no, "simnet bookkeeping allocation failed");
    }
    for (uint64_t i = 0; i < n; i++)
        ctx->simnet_last_height[i] = INT32_MIN;
    ctx->simnet_monotonic_ok = true;

    /* Assign roles from the disjoint byzantine sub-stream. permille=1000 draws
     * nothing and tags nothing, so an all-honest cluster runs exactly as it did
     * before roles existed. Node 0 is always honest (convergence reference). */
    ctx->simnet_honest_permille = honest_permille;
    ctx->simnet_byz_rng = ctx->seed ^ CHAOS_SIMNET_BYZ_TAG;
    for (uint64_t i = 0; i < n; i++) {
        bool byz = false;
        if (i != 0 && honest_permille < 1000) {
            uint64_t r = chaos_splitmix64(&ctx->simnet_byz_rng);
            byz = (int)(r % 1000u) >= honest_permille;
        }
        ctx->simnet_nodes[i].byzantine = byz;
        if (byz && !simnet_cluster_set_role(ctx->simnet, (size_t)i,
                                            SIMNET_ROLE_BYZANTINE)) {
            chaos_simnet_cleanup(ctx);
            return fail_line(line_no, "simnet_nodes set_role failed");
        }
    }
    return 0;
}

static int chaos_simnet_parse_node(struct chaos_ctx *ctx, int argc,
                                   char **argv, const char *key,
                                   uint64_t *out, int line_no,
                                   const char *what)
{
    const char *value = arg_value(argc, argv, key);
    if (!value || !parse_u64_auto(value, out) ||
        *out >= ctx->simnet_node_count) {
        return fail_line(line_no, what);
    }
    return 0;
}

static int handle_simnet_mint(struct chaos_ctx *ctx, int argc, char **argv,
                              int line_no)
{
    if (!ctx->simnet)
        return fail_line(line_no, "simnet_mint requires simnet_nodes first");
    if (argc != 2) return fail_line(line_no, "simnet_mint requires node=I");
    uint64_t node_id = 0;
    int rc = chaos_simnet_parse_node(ctx, argc, argv, "node", &node_id,
                                     line_no,
                                     "simnet_mint node must be a valid index");
    if (rc != 0) return rc;

    struct chaos_simnet_node *ns = &ctx->simnet_nodes[node_id];
    struct uint256 hash;
    if (ns->byzantine) {
        /* Forge an invalid block; honest peers reject it on delivery. The hash
         * still flows through the mint history so relay/heal broadcast it. */
        uint64_t bs = chaos_splitmix64(&ctx->simnet_byz_rng);
        if (!simnet_cluster_byzantine_mint_on(ctx->simnet, (size_t)node_id, bs,
                                              &hash))
            return fail_line(line_no, "simnet_byzantine_mint failed");
    } else if (!simnet_cluster_mint_on(ctx->simnet, (size_t)node_id, &hash)) {
        return fail_line(line_no, "simnet_mint failed");
    }

    if (ns->mint_count == ns->mint_cap) {
        size_t new_cap = ns->mint_cap ? ns->mint_cap * 2 : 4;
        struct uint256 *grown = zcl_realloc(ns->mints,
                                            new_cap * sizeof(*grown),
                                            "chaos_simnet_mints");
        if (!grown)
            return fail_line(line_no, "simnet_mint OOM growing history");
        ns->mints = grown;
        ns->mint_cap = new_cap;
    }
    ns->mints[ns->mint_count++] = hash;
    return chaos_trace_record(ctx, line_no, "simnet_mint");
}

static int handle_simnet_relay(struct chaos_ctx *ctx, int argc, char **argv,
                               int line_no)
{
    if (!ctx->simnet)
        return fail_line(line_no, "simnet_relay requires simnet_nodes first");
    if (argc != 2) return fail_line(line_no, "simnet_relay requires node=I");
    uint64_t node_id = 0;
    int rc = chaos_simnet_parse_node(
        ctx, argc, argv, "node", &node_id, line_no,
        "simnet_relay node must be a valid index");
    if (rc != 0) return rc;

    struct chaos_simnet_node *ns = &ctx->simnet_nodes[node_id];
    if (ns->relayed_count >= ns->mint_count)
        return 0;

    bool *exclude = zcl_calloc(ctx->simnet_node_count, sizeof(*exclude),
                               "chaos_simnet_relay_mask");
    if (!exclude)
        return fail_line(line_no, "simnet_relay OOM building link mask");
    for (size_t to = 0; to < ctx->simnet_node_count; to++)
        exclude[to] =
            ctx->simnet_partitioned[node_id * ctx->simnet_node_count + to];

    for (size_t i = ns->relayed_count; i < ns->mint_count; i++) {
        if (!simnet_cluster_broadcast_except(ctx->simnet, (size_t)node_id,
                                             &ns->mints[i], exclude)) {
            free(exclude);
            return fail_line(line_no, "simnet_relay broadcast failed");
        }
    }
    ns->relayed_count = ns->mint_count;
    free(exclude);
    return 0;
}

static void chaos_simnet_track_heights(struct chaos_ctx *ctx)
{
    if (!ctx->simnet) return;
    for (size_t i = 0; i < ctx->simnet_node_count; i++) {
        int32_t h = 0;
        if (!simnet_cluster_tip_height(ctx->simnet, i, &h))
            continue;
        if (ctx->simnet_last_height[i] != INT32_MIN &&
            h < ctx->simnet_last_height[i]) {
            ctx->simnet_monotonic_ok = false;
        }
        ctx->simnet_last_height[i] = h;
    }
}

static int handle_simnet_deliver(struct chaos_ctx *ctx, int argc,
                                 char **argv, int line_no)
{
    (void)argv;
    if (!ctx->simnet)
        return fail_line(line_no, "simnet_deliver requires simnet_nodes first");
    if (argc != 1)
        return fail_line(line_no, "simnet_deliver takes no arguments");
    if (!simnet_cluster_deliver_pending(ctx->simnet))
        return fail_line(line_no, "simnet_deliver failed");
    chaos_simnet_track_heights(ctx);
    return chaos_trace_record(ctx, line_no, "simnet_deliver");
}

static int handle_simnet_partition(struct chaos_ctx *ctx, int argc,
                                   char **argv, int line_no)
{
    if (!ctx->simnet)
        return fail_line(line_no,
                         "simnet_partition requires simnet_nodes first");
    if (argc != 3)
        return fail_line(line_no, "simnet_partition requires a=I b=J");
    uint64_t a = 0, b = 0;
    int rc = chaos_simnet_parse_node(
        ctx, argc, argv, "a", &a, line_no,
        "simnet_partition a must be a valid index");
    if (rc != 0) return rc;
    rc = chaos_simnet_parse_node(ctx, argc, argv, "b", &b, line_no,
                                 "simnet_partition b must be a valid index");
    if (rc != 0) return rc;
    if (a == b)
        return fail_line(line_no, "simnet_partition a and b must differ");

    ctx->simnet_partitioned[a * ctx->simnet_node_count + b] = true;
    ctx->simnet_partitioned[b * ctx->simnet_node_count + a] = true;
    return chaos_trace_record(ctx, line_no, "simnet_partition");
}

static int chaos_simnet_resync(struct chaos_ctx *ctx, uint64_t from,
                               uint64_t to, int line_no)
{
    bool *exclude = zcl_calloc(ctx->simnet_node_count, sizeof(*exclude),
                               "chaos_simnet_heal_mask");
    if (!exclude)
        return fail_line(line_no, "simnet_heal OOM building resync mask");
    for (size_t peer = 0; peer < ctx->simnet_node_count; peer++)
        exclude[peer] = (peer != to);

    struct chaos_simnet_node *ns = &ctx->simnet_nodes[from];
    for (size_t i = 0; i < ns->mint_count; i++) {
        if (!simnet_cluster_broadcast_except(ctx->simnet, (size_t)from,
                                             &ns->mints[i], exclude)) {
            free(exclude);
            return fail_line(line_no, "simnet_heal resync broadcast failed");
        }
    }
    free(exclude);
    return 0;
}

static int handle_simnet_heal(struct chaos_ctx *ctx, int argc, char **argv,
                              int line_no)
{
    if (!ctx->simnet)
        return fail_line(line_no, "simnet_heal requires simnet_nodes first");
    if (argc != 3)
        return fail_line(line_no, "simnet_heal requires a=I b=J");
    uint64_t a = 0, b = 0;
    int rc = chaos_simnet_parse_node(ctx, argc, argv, "a", &a, line_no,
                                     "simnet_heal a must be a valid index");
    if (rc != 0) return rc;
    rc = chaos_simnet_parse_node(ctx, argc, argv, "b", &b, line_no,
                                 "simnet_heal b must be a valid index");
    if (rc != 0) return rc;
    if (a == b)
        return fail_line(line_no, "simnet_heal a and b must differ");

    ctx->simnet_partitioned[a * ctx->simnet_node_count + b] = false;
    ctx->simnet_partitioned[b * ctx->simnet_node_count + a] = false;

    /* Full resync in both directions: a healed peer may be missing blocks
     * relayed to OTHER peers while a<->b was severed, not just blocks
     * minted since the heal. */
    rc = chaos_simnet_resync(ctx, a, b, line_no);
    if (rc != 0) return rc;
    rc = chaos_simnet_resync(ctx, b, a, line_no);
    if (rc != 0) return rc;
    return chaos_trace_record(ctx, line_no, "simnet_heal");
}

static bool chaos_simnet_converged(const struct chaos_ctx *ctx)
{
    if (!ctx->simnet)
        return false;
    if (ctx->simnet_node_count < 2)
        return true;

    struct uint256 tip0;
    struct utxo_commitment digest0;
    if (!simnet_cluster_tip_hash(ctx->simnet, 0, &tip0) ||
        !simnet_cluster_coins_digest(ctx->simnet, 0, &digest0)) {
        return false;
    }
    for (size_t i = 1; i < ctx->simnet_node_count; i++) {
        struct uint256 tip;
        struct utxo_commitment digest;
        if (!simnet_cluster_tip_hash(ctx->simnet, i, &tip) ||
            !simnet_cluster_coins_digest(ctx->simnet, i, &digest)) {
            return false;
        }
        if (!uint256_eq(&tip0, &tip) ||
            !utxo_commitment_equal(&digest0, &digest)) {
            return false;
        }
    }
    return true;
}

static const struct chaos_command COMMANDS[] = {
    { "seed", handle_seed },
    { "boot_phase", handle_boot_phase },
    { "peer_count", handle_peer_count },
    { "expect", handle_expect },
    { "at_event", handle_at_event },
    { "kill_peer", handle_kill_peer },
    { "random_kill_peers", handle_random_kill_peers },
    { "send_block", handle_send_block },
    { "send_malformed_block", handle_send_malformed_block },
    { "advance_clock", handle_advance_clock },
    { "trigger_oom_at", handle_trigger_oom_at },
    { "partition_network", handle_partition_network },
    { "auto_reindex_request", handle_auto_reindex_request },
    { "auto_reindex_mark_terminal", handle_auto_reindex_mark_terminal },
    { "auto_reindex_clear_if_covered",
      handle_auto_reindex_clear_if_covered },
    { "mode", handle_mode },
    { "simnet_nodes", handle_simnet_nodes },
    { "simnet_mint", handle_simnet_mint },
    { "simnet_relay", handle_simnet_relay },
    { "simnet_deliver", handle_simnet_deliver },
    { "simnet_partition", handle_simnet_partition },
    { "simnet_heal", handle_simnet_heal },
    { "trace_dir", handle_trace_dir },
};

static const struct chaos_command *find_command(const char *name)
{
    for (size_t i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); i++) {
        if (strcmp(COMMANDS[i].name, name) == 0)
            return &COMMANDS[i];
    }
    return NULL;
}

static int run_scenario(struct chaos_ctx *ctx)
{
    net_partition_clear();
    platform_clock_set_source(&ctx->clock_src);
    if (ctx->seed_override_set)
        chaos_set_seed(ctx, ctx->seed_override);
    FILE *fp = fopen(ctx->scenario_path, "rb");
    if (!fp) {
        fprintf(stderr, "chaos: failed to open %s: %s\n",
                ctx->scenario_path, strerror(errno));
        platform_clock_clear_source();
        chaos_auto_reindex_cleanup(ctx);
        chaos_simnet_cleanup(ctx);
        return 1;
    }

    char line[CHAOS_MAX_LINE];
    int line_no = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        } else if (!feof(fp)) {
            fprintf(stderr, "chaos:%d: line too long\n", line_no);
            fclose(fp);
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }

        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *body = trim_ascii(line);
        if (*body == '\0') continue;

        char *argv[CHAOS_MAX_ARGS];
        int argc = split_args(body, argv, CHAOS_MAX_ARGS);
        if (argc < 0) {
            fprintf(stderr, "chaos:%d: too many arguments\n", line_no);
            fclose(fp);
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }

        const struct chaos_command *cmd = find_command(argv[0]);
        if (!cmd) {
            fprintf(stderr, "chaos:%d: unknown command '%s'\n",
                    line_no, argv[0]);
            fclose(fp);
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }
        int rc = cmd->handler(ctx, argc, argv, line_no);
        if (rc != 0) {
            fclose(fp);
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }
        if (ctx->verbose)
            printf("chaos:%d: %s OK\n", line_no, argv[0]);
    }

    fclose(fp);

    /* simnet mode: re-check the cluster invariants regardless of what the
     * scenario explicitly asserted. A drain here is a no-op if the last
     * command already drained the queue. */
    if (ctx->simnet_mode) {
        if (!ctx->simnet) {
            fprintf(stderr,
                    "chaos: mode simnet requires a simnet_nodes command\n");
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }
        if (!simnet_cluster_deliver_pending(ctx->simnet)) {
            fprintf(stderr,
                    "chaos: simnet final delivery drain failed\n");
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }
        chaos_simnet_track_heights(ctx);
        bool converged = chaos_simnet_converged(ctx);
        if (!converged) {
            fprintf(stderr,
                    "chaos: simnet invariant violation: cluster did not "
                    "converge (tip hash / coins digest differ across "
                    "nodes)\n");
        }
        if (!ctx->simnet_monotonic_ok) {
            fprintf(stderr,
                    "chaos: simnet invariant violation: a node's tip "
                    "height regressed\n");
        }
        if (!converged || !ctx->simnet_monotonic_ok) {
            platform_clock_clear_source();
            chaos_auto_reindex_cleanup(ctx);
            chaos_simnet_cleanup(ctx);
            return 1;
        }
    }

    if (ctx->expect_count == 0) {
        fprintf(stderr, "chaos: scenario has no expect assertions\n");
        platform_clock_clear_source();
        chaos_auto_reindex_cleanup(ctx);
        chaos_simnet_cleanup(ctx);
        return 1;
    }
    platform_clock_clear_source();
    chaos_auto_reindex_cleanup(ctx);
    chaos_simnet_cleanup(ctx);
    return 0;
}

#ifndef CHAOS_NO_MAIN
/* Standalone-binary-only: chaos.c is also #include-d into
 * test_chaos_harness.c (under CHAOS_NO_MAIN), whose translation unit is
 * linked into test_parallel alongside tests/harness/src/test_parallel.c, which
 * already defines this global — defining it unconditionally here would be
 * a duplicate-definition link error in that build. Every other standalone
 * ALL_SRCS tool (wire_sweep, wallet_dump, ...) defines its own copy the
 * same way, since boot_services.c declares it `extern`. */
volatile sig_atomic_t g_shutdown_requested = 0;

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --scenario=PATH [--seed=N] [--verbose] "
            "[--artifact-dir=PATH] [--trace-dir=PATH]\n",
            argv0);
}

int main(int argc, char **argv)
{
    struct chaos_ctx ctx;
    chaos_ctx_init(&ctx);

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--scenario=", 11) == 0) {
            ctx.scenario_path = argv[i] + 11;
        } else if (strncmp(argv[i], "--seed=", 7) == 0) {
            uint64_t seed = 0;
            if (!parse_u64_auto(argv[i] + 7, &seed)) {
                fprintf(stderr, "chaos: --seed must be an integer or hex value\n");
                return 2;
            }
            ctx.seed_override = seed;
            ctx.seed_override_set = true;
        } else if (strncmp(argv[i], "--artifact-dir=", 15) == 0) {
            ctx.artifact_dir = argv[i] + 15;
        } else if (strncmp(argv[i], "--trace-dir=", 12) == 0) {
            if (strlen(argv[i] + 12) >= sizeof(ctx.trace_dir)) {
                fprintf(stderr, "chaos: --trace-dir path is too long\n");
                return 2;
            }
            snprintf(ctx.trace_dir, sizeof(ctx.trace_dir), "%s",
                     argv[i] + 12);
            ctx.trace_dir_set = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            ctx.verbose = true;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!ctx.scenario_path || !*ctx.scenario_path) {
        usage(argv[0]);
        return 2;
    }

    /* `mode simnet` runs real connect_block/disconnect_block, which asserts
     * a chain_params_get() singleton is selected (test_parallel.c and
     * wire_sweep.c both do this once at process start for the same
     * reason). Harmless when the scenario never uses simnet mode. */
    chain_params_select(CHAIN_MAIN);

    int rc = run_scenario(&ctx);
    if (rc == 0) {
        printf("PASS %s seed=%s0x%016" PRIx64
               " boot_phase=%s peers=%u expects=%zu\n",
               ctx.scenario_path,
               ctx.seed_set ? "" : "(default)",
               ctx.seed,
               ctx.boot_phase,
               ctx.peer_count,
               ctx.expect_count);
    } else {
        printf("FAIL %s\n", ctx.scenario_path);
        if (ctx.simnet_mode) {
            printf("SIMNET REPRO SEED=0x%016" PRIx64 "\n", ctx.seed);
        }
        int artifact_rc = write_failure_artifacts(&ctx);
        if (artifact_rc == 0)
            printf("ARTIFACTS %s\n",
                   ctx.artifact_dir ? ctx.artifact_dir : "chaos-output");
        else
            fprintf(stderr, "chaos: failed to write artifacts: %s\n",
                    strerror(-artifact_rc));
    }
    return rc;
}
#endif
