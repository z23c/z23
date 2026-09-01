/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wire_sweep — nightly seed-fuzzing runner for the simnet_wire harness.
 *
 * Builds one scenario per seed in a range, picking an adversary archetype
 * and (for solo archetypes) a peer-internal sub-case deterministically from
 * the seed (no wall-clock, no external entropy — same seed always produces
 * the same scenario and the same fingerprint). Runs the scenario in-process
 * (pure in-memory transport, see simnet_wire.c — no real sockets) and, on
 * ANY monitor failure, saves a replay capsule via the existing
 * simnet_wire_save_capsule() into a stable, git-ignored artifact directory
 * (build/ is already gitignored — /tmp does not survive CI runners) and
 * prints the failing seed to stdout for standalone replay.
 *
 * This binary is intentionally standalone (its own `cc` invocation via the
 * Makefile's BUILD_NODE_TOOL pattern, same shape as tools/sim/chaos.c and
 * every other tool in that family) — it is NOT folded into the test_zcl /
 * test_parallel / zclassic23 link units, so a nightly sweep of thousands of
 * seeds never gates the normal build or `make ci`.
 *
 * Usage:
 *   build/bin/wire_sweep [--start=N] [--count=K] [--artifact-dir=PATH]
 *                        [--verbose]
 *
 * `make wire-sweep SEEDS=200` is the short local smoke run.
 *
 * KNOWN FINDING (FIXED — Step E, engine/modules/sim/src/simnet_wire.c): the
 * BAD_HANDSHAKE archetype's GARBAGE_AFTER_VERACK sub-case
 * (SIMNET_WIRE_BAD_HANDSHAKE_GARBAGE_AFTER_VERACK,
 * wire_start_garbage_after_verack() in simnet_wire_peer.c) used to hang for
 * seeds 0xf, 0x69, 0x8e: the adversary completes its own outbound
 * handshake then emits a 4-byte fragment that lands as an INCOMPLETE
 * 24-byte message header the node harmlessly parks in recv_msgs[0].
 * simnet_wire_idle() treated any recv_msg_count > 0 as "busy", so the run
 * spun to WIRE_SWEEP_MAX_TICKS even though no further bytes would ever
 * arrive to complete that header. The fix refines the idle predicate: only
 * a COMPLETE queued message (one msg_process_messages() can actually
 * drain) counts as pending work; an incomplete head-of-queue message with
 * no inbound bytes left is a quiescent state. The sweep now exercises all
 * three BAD_HANDSHAKE sub-cases (see wire_sweep_run_bad_handshake()); the
 * GARBAGE_AFTER_VERACK case reaches idle cleanly with the node still
 * connected (a valid "no halt, no crash" outcome — not a disconnect).
 */

#include "chain/chainparams.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "sim/simnet_wire.h"
#include "util/blocker.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Required by the node's whole-program link: thread_registry.h documents
 * this as the shutdown-signal flag every entry point must define (see
 * platform/modules/util/include/util/thread_registry.h). wire_sweep runs no background
 * threads, but the symbol is referenced by code paths pulled in via the
 * full ALL_SRCS link (same as tools/wallet_dump.c, tools/wallet_sim.c,
 * tools/bot.c, etc.). */
volatile sig_atomic_t g_shutdown_requested = 0;

#define WIRE_SWEEP_DEFAULT_START 1ULL
#define WIRE_SWEEP_DEFAULT_COUNT 64ULL
#define WIRE_SWEEP_DEFAULT_ARTIFACT_DIR "build/wire-sweep-output"
#define WIRE_SWEEP_MAX_TICKS 16000ULL
/* stuck_guard is deliberately 0 (disabled), matching the existing
 * sw_run_flood / sw_run_mixed precedent in test_simnet_wire.c: a FLOOD
 * peer's flood_active flag holds simnet_wire_idle() at "not idle" forever
 * by design, so the tick-signature "stuck" detector would false-positive
 * on every scenario that happens to draw a FLOOD peer. max_ticks (above)
 * is the real backstop — simnet_wire_run() LOG_FAILs (returns false) if
 * it exhausts max_ticks with events still pending, which still catches a
 * genuine hang without punishing FLOOD's intentional non-idle behavior. */
#define WIRE_SWEEP_STUCK_GUARD 0ULL
#define WIRE_SWEEP_MODE_COUNT 5u

/* Local deterministic RNG — self-contained, does not reach into
 * simnet_wire's internal splitmix64 helper (that helper is declared only
 * in the internal, non-public header; this tool must stick to the public
 * API in sim/simnet_wire.h per the harness ownership boundary). */
static uint64_t wire_sweep_splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

struct wire_sweep_opts {
    uint64_t start_seed;
    uint64_t count;
    const char *artifact_dir;
    bool verbose;
};

static void wire_sweep_usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--start=N] [--count=K] [--artifact-dir=PATH] "
            "[--verbose]\n",
            argv0);
}

static bool wire_sweep_parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s || !out)
        return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0')
        return false;
    *out = (uint64_t)v;
    return true;
}

static int wire_sweep_parse_args(int argc, char **argv,
                                 struct wire_sweep_opts *opts)
{
    opts->start_seed = WIRE_SWEEP_DEFAULT_START;
    opts->count = WIRE_SWEEP_DEFAULT_COUNT;
    opts->artifact_dir = WIRE_SWEEP_DEFAULT_ARTIFACT_DIR;
    opts->verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--seed=", 7) == 0 ||
            strncmp(argv[i], "--start=", 8) == 0) {
            const char *v = strchr(argv[i], '=') + 1;
            if (!wire_sweep_parse_u64(v, &opts->start_seed)) {
                fprintf(stderr, "wire_sweep: bad --start/--seed value\n");
                return -1;
            }
        } else if (strncmp(argv[i], "--count=", 8) == 0) {
            if (!wire_sweep_parse_u64(argv[i] + 8, &opts->count)) {
                fprintf(stderr, "wire_sweep: bad --count value\n");
                return -1;
            }
        } else if (strncmp(argv[i], "--artifact-dir=", 15) == 0) {
            opts->artifact_dir = argv[i] + 15;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            opts->verbose = true;
        } else {
            wire_sweep_usage(argv[0]);
            return -1;
        }
    }
    if (opts->count == 0) {
        fprintf(stderr, "wire_sweep: --count must be >= 1\n");
        return -1;
    }
    return 0;
}

struct wire_sweep_result {
    bool monitor_failed;
    bool scenario_build_failed;
    bool run_failed;
    struct simnet_wire_stats stats;
};

/* Classify a completed (or aborted) run. simnet_wire_run() returning false
 * is not, by itself, a monitor failure: for the solo archetypes (no
 * honest peer — the adversary IS peer 0), a parse-breaking sub-case makes
 * p2p_node_receive_bytes() reject the bytes and disconnect — see
 * simnet_wire_pump_to_nut()'s "NUT rejected inbound bytes" LOG_FAIL
 * (engine/modules/sim/src/simnet_wire.c:642). That is the harness correctly
 * refusing garbage, the same accepted outcome sw_run_bad_handshake
 * asserts for its DATA_BEFORE_VERSION case (`st.nut_disconnected`
 * expected true, not a failure). Genuinely bad outcomes are: (a) a real
 * hang — simnet_wire_run() exhausted max_ticks / hit the stuck guard
 * WITHOUT the nut ever disconnecting (nothing to explain why it never
 * went idle), or (b) an honest peer's connection getting caught in the
 * crossfire (the FLOOD+SLOWLORIS archetype has a real honest peer — a
 * disconnect there is a regression, since sw_run_mixed proves that
 * combination should always keep the honest link up). */
static void wire_sweep_classify(bool run_ok, bool got_stats,
                                size_t honest_peer_count,
                                struct wire_sweep_result *res)
{
    bool hang = !run_ok && got_stats && !res->stats.nut_disconnected;
    bool unexpected_honest_disconnect =
        !run_ok && got_stats && res->stats.nut_disconnected &&
        honest_peer_count > 0;
    res->run_failed = !run_ok;
    res->monitor_failed = !got_stats || res->stats.monitor_failed ||
                          hang || unexpected_honest_disconnect;
}

static void wire_sweep_maybe_save_capsule(const struct simnet_wire *wire,
                                          uint64_t seed,
                                          const char *artifact_dir,
                                          bool monitor_failed)
{
    if (!monitor_failed)
        return;
    char path[256];
    int n = snprintf(path, sizeof(path), "%s/seed_0x%016" PRIx64 ".tape",
                     artifact_dir, seed);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return;
    /* simnet_wire_save_capsule() itself LOG_FAILs (logs + returns false)
     * on write error; nothing further to do with the return here. */
    (void)simnet_wire_save_capsule(wire, path);
}

/* MALFORMED_FRAME solo (peer 0 IS the adversary, no honest peer), exactly
 * matching sw_run_malformed's shape. Uses the generic random-case entry
 * point (simnet_wire_start_peer_kind) — empirically all three internal
 * sub-cases (BAD_CHECKSUM/OVERSIZED/BAD_MAGIC) either complete cleanly or
 * cleanly disconnect for every seed tried, no hang observed. */
static void wire_sweep_run_malformed(uint64_t seed, const char *artifact_dir,
                                     struct wire_sweep_result *res)
{
    struct simnet_wire *wire = simnet_wire_create(1, seed);
    if (!wire) {
        res->scenario_build_failed = true;
        res->monitor_failed = true;
        return;
    }
    bool run_ok = simnet_wire_start_peer_kind(
                      wire, 0, SIMNET_WIRE_PEER_MALFORMED_FRAME) &&
                  simnet_wire_run(wire, WIRE_SWEEP_MAX_TICKS,
                                 WIRE_SWEEP_STUCK_GUARD);
    bool got_stats = simnet_wire_get_stats(wire, &res->stats);
    wire_sweep_classify(run_ok, got_stats, 0, res);
    wire_sweep_maybe_save_capsule(wire, seed, artifact_dir,
                                  res->monitor_failed);
    simnet_wire_free(wire);
}

/* BAD_HANDSHAKE solo, same no-honest-peer shape as sw_run_bad_handshake.
 * Covers all three sub-cases including GARBAGE_AFTER_VERACK, which no longer
 * hangs (the incomplete-recv-message idle fix in simnet_wire.c — see the
 * KNOWN FINDING note at the top of this file). */
static void wire_sweep_run_bad_handshake(uint64_t seed,
                                         const char *artifact_dir,
                                         struct wire_sweep_result *res)
{
    static const enum simnet_wire_bad_handshake_case cases[3] = {
        SIMNET_WIRE_BAD_HANDSHAKE_DATA_BEFORE_VERSION,
        SIMNET_WIRE_BAD_HANDSHAKE_VERACK_FIRST,
        SIMNET_WIRE_BAD_HANDSHAKE_GARBAGE_AFTER_VERACK,
    };
    uint64_t rng_state = seed ^ 0xB4D0u;
    enum simnet_wire_bad_handshake_case c =
        cases[wire_sweep_splitmix64(&rng_state) % 3u];

    struct simnet_wire *wire = simnet_wire_create(1, seed);
    if (!wire) {
        res->scenario_build_failed = true;
        res->monitor_failed = true;
        return;
    }
    bool run_ok = simnet_wire_start_bad_handshake_peer(wire, 0, c) &&
                  simnet_wire_run(wire, WIRE_SWEEP_MAX_TICKS,
                                 WIRE_SWEEP_STUCK_GUARD);
    bool got_stats = simnet_wire_get_stats(wire, &res->stats);
    wire_sweep_classify(run_ok, got_stats, 0, res);
    wire_sweep_maybe_save_capsule(wire, seed, artifact_dir,
                                  res->monitor_failed);
    simnet_wire_free(wire);
}

/* FLOOD solo / SLOWLORIS solo — peer 0 IS the adversary and also drives
 * its own handshake initiation (wire_start_stream_adversary(), gated on
 * peer_id == 0), matching sw_run_flood / sw_run_slowloris exactly. */
static void wire_sweep_run_stream_solo(uint64_t seed, const char *artifact_dir,
                                       enum simnet_wire_peer_kind kind,
                                       struct wire_sweep_result *res)
{
    struct simnet_wire *wire = simnet_wire_create(1, seed);
    if (!wire) {
        res->scenario_build_failed = true;
        res->monitor_failed = true;
        return;
    }
    bool run_ok = simnet_wire_start_peer_kind(wire, 0, kind) &&
                  simnet_wire_run(wire, WIRE_SWEEP_MAX_TICKS,
                                 WIRE_SWEEP_STUCK_GUARD);
    bool got_stats = simnet_wire_get_stats(wire, &res->stats);
    wire_sweep_classify(run_ok, got_stats, 0, res);
    wire_sweep_maybe_save_capsule(wire, seed, artifact_dir,
                                  res->monitor_failed);
    simnet_wire_free(wire);
}

/* Honest peer 0 + one FLOOD + one SLOWLORIS — reproduces sw_run_mixed
 * exactly, the only cross-kind combination the test suite proves safe
 * (see the file-header comment on why other cross-kind combinations are
 * out of scope for this sweep). */
static void wire_sweep_run_mixed(uint64_t seed, const char *artifact_dir,
                                 struct wire_sweep_result *res)
{
    struct wire_scenario_peer peers[] = {
        { SIMNET_WIRE_PEER_FLOOD, 1 },
        { SIMNET_WIRE_PEER_SLOWLORIS, 1 },
    };
    struct wire_scenario scenario = {
        .master_seed = seed,
        .peers = peers,
        .peer_kind_count = sizeof(peers) / sizeof(peers[0]),
        .honest_peer_count = 1,
        .duration_us = 15000000,
    };
    struct simnet_wire *wire = simnet_wire_create_scenario(&scenario);
    if (!wire) {
        res->scenario_build_failed = true;
        res->monitor_failed = true;
        return;
    }
    bool run_ok = simnet_wire_run(wire, WIRE_SWEEP_MAX_TICKS,
                                  WIRE_SWEEP_STUCK_GUARD);
    bool got_stats = simnet_wire_get_stats(wire, &res->stats);
    wire_sweep_classify(run_ok, got_stats, 1, res);
    wire_sweep_maybe_save_capsule(wire, seed, artifact_dir,
                                  res->monitor_failed);
    simnet_wire_free(wire);
}

/* Pick one of the five archetypes proven safe by test_simnet_wire.c and
 * run it. See the big comment above wire_sweep_run_bad_handshake() and
 * the file header for the architectural reasoning (docs/work/
 * wire-next-wave-specs.md F0) behind staying inside these five shapes
 * rather than combining every peer kind pairwise. */
static void wire_sweep_run_one(uint64_t seed, const char *artifact_dir,
                               struct wire_sweep_result *res)
{
    memset(res, 0, sizeof(*res));
    blocker_reset_for_testing();

    uint64_t rng_state = seed;
    uint64_t mode = wire_sweep_splitmix64(&rng_state) % WIRE_SWEEP_MODE_COUNT;

    switch (mode) {
    case 0:
        wire_sweep_run_malformed(seed, artifact_dir, res);
        break;
    case 1:
        wire_sweep_run_bad_handshake(seed, artifact_dir, res);
        break;
    case 2:
        wire_sweep_run_stream_solo(seed, artifact_dir,
                                   SIMNET_WIRE_PEER_FLOOD, res);
        break;
    case 3:
        wire_sweep_run_stream_solo(seed, artifact_dir,
                                   SIMNET_WIRE_PEER_SLOWLORIS, res);
        break;
    default:
        wire_sweep_run_mixed(seed, artifact_dir, res);
        break;
    }
}

static int wire_sweep_ensure_dir(const char *dir)
{
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
        fprintf(stderr, "wire_sweep: failed to create artifact dir %s: %s\n",
                dir, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct wire_sweep_opts opts;
    if (wire_sweep_parse_args(argc, argv, &opts) != 0)
        return 2;

    if (wire_sweep_ensure_dir(opts.artifact_dir) != 0)
        return 2;

    /* Same global init the test runners do before touching simnet_wire —
     * see tests/harness/src/test.c and tests/harness/src/test_parallel.c. Without
     * this, chain_params_get() (called deep inside connect_block via the
     * scenario's block-mint/validation path) hits an unset-params assert. */
    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    uint64_t failures = 0;
    uint64_t seed = opts.start_seed;
    for (uint64_t i = 0; i < opts.count; i++, seed++) {
        struct wire_sweep_result res;
        wire_sweep_run_one(seed, opts.artifact_dir, &res);

        if (res.monitor_failed) {
            failures++;
            printf("FAIL seed=0x%016" PRIx64
                   " scenario_build_failed=%d run_failed=%d "
                   "capsule=%s/seed_0x%016" PRIx64 ".tape\n",
                   seed,
                   res.scenario_build_failed, res.run_failed,
                   opts.artifact_dir, seed);
        } else if (opts.verbose) {
            printf("PASS seed=0x%016" PRIx64 " fingerprint=0x%016" PRIx64
                   " ticks=%" PRIu64 "\n",
                   seed, res.stats.fingerprint,
                   res.stats.ticks);
        }
    }

    printf("wire_sweep: ran %" PRIu64 " seeds [0x%016" PRIx64
           "..0x%016" PRIx64 "], %" PRIu64 " monitor failure(s)\n",
           opts.count, opts.start_seed,
           (opts.start_seed + opts.count - 1),
           failures);

    return failures == 0 ? 0 : 1;
}
