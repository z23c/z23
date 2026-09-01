/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 09_seed_replay — determinism as a debugging tool.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * The deterministic simulator's foundation primitive is `seed_tape_t`
 * (engine/modules/sim/include/sim/seed_tape.h): a single 64-bit seed expands into a
 * xoshiro256++ RNG stream AND a simulated monotonic/wall clock, both
 * reached via the `platform_rng_*` / `platform_clock_*` install-hook so
 * ordinary call sites (`rng_u64()`, `clock_now_monotonic_ns()`) see the
 * tape's values with zero code changes. While a tape is RECORDING it also
 * logs every clock advance and every injected external event (a stand-in
 * for "a peer message arrived", "a block landed", etc). The whole log can
 * be serialized to a file or an in-memory buffer, then reloaded in REPLAY
 * mode, where it reproduces the *exact same* RNG draws and event order —
 * and rejects any attempt to record something new (-EROFS).
 *
 * This program:
 *   1. Opens a tape with a FIXED seed and drives a tiny "sim run" — a
 *      few RNG draws (standing in for e.g. a mining nonce search) plus a
 *      few clock advances and injected peer-message events.
 *   2. Snapshots that live tape TWO ways at the identical instant:
 *        (a) a plain `seed_tape_save()` .bin file — the general
 *            save/reload mechanism a test or tool would use, and
 *        (b) a `postmortem_capture_write()` capsule — the SAME
 *            serialization, but wrapped with a manifest + proc/register
 *            snapshot, which is exactly what fires automatically from a
 *            SIGSEGV/SIGABRT handler in production (see
 *            engine/modules/sim/include/sim/postmortem.h).
 *   3. Keeps driving the ORIGINAL tape a few more draws, recording what
 *      "actually happens next" as the ground truth.
 *   4. Reloads BOTH snapshots in REPLAY mode and proves each one
 *      reproduces that exact ground-truth continuation, bit for bit, plus
 *      the exact injected-event queue in order.
 *
 * MENTAL MODEL
 * -------------
 * A seed tape turns "what happened" into a value you can serialize,
 * diff, and rewind. A crash is just a tape that got interrupted: the
 * postmortem capsule IS the tape at the moment of interruption, so
 * replaying the capsule after the fact deterministically reproduces every
 * RNG draw and every external event the crashing process saw, in order,
 * on a completely different machine, with no live process involved. This
 * is "every bug becomes a 64-bit seed" made concrete — a debugger can
 * `postmortem_capsule_load_tape()` the capsule and step the simulator
 * through the exact same sequence that led to the fault.
 *
 * TEST-ONLY NOTE: none. Every symbol used here (`seed_tape_*`,
 * `postmortem_*`, `rng_u64`, `seed_tape_advance`/`_inject`) is declared in
 * a PUBLIC header (engine/modules/sim/include/sim, platform/modules/platform/include/platform).
 * No #ifdef ZCL_TESTING is required to compile or link this file. (The
 * integrator still compiles the examples tree with -DZCL_TESTING per
 * instructions, which is harmless here.)
 */

#include "sim/seed_tape.h"
#include "sim/postmortem.h"
#include "platform/rng.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Fixed seed + fixed epoch: every run of this program produces the exact
 * same RNG draws, clock values, and console output. Change the seed and
 * the whole story changes too, but stays internally reproducible. */
#define TEACHING_SEED       0x5EED7A9E00000042ULL
#define TEACHING_START_WALL 1700000000LL /* 2023-11-14T22:13:20Z, arbitrary */
#define PEER_MESSAGE_TYPE   1u            /* seed_tape.h's suggested tag */

static const char *const kPeerMessages[3] = {
    "tx:aaaa1111", "block:bbbb2222", "ping:cccc3333"
};

/* Remove a postmortem capsule directory's known members + itself. We
 * know the exact file set postmortem_capture_write() writes (tape.bin,
 * manifest.json, procstatus.txt, log.txt, registers.txt, coremarker.txt)
 * so no recursive directory walk is needed. */
static void cleanup_capsule_dir(const char *dir)
{
    static const char *const kMembers[] = {
        "tape.bin", "manifest.json", "procstatus.txt",
        "log.txt", "registers.txt", "coremarker.txt",
    };
    char path[600];
    for (size_t i = 0; i < sizeof(kMembers) / sizeof(kMembers[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, kMembers[i]);
        unlink(path);
    }
    rmdir(dir);
}

int main(void)
{
    printf("=== 09_seed_replay: record a seed tape, snapshot it two ways, "
           "prove bit-identical replay ===\n\n");

    char scratch_dir[] = "/tmp/zcl_example_09_seed_replay_XXXXXX";
    if (!mkdtemp(scratch_dir)) {
        fprintf(stderr, "FAIL: mkdtemp scratch dir: %s\n", strerror(errno));
        return 1;
    }

    printf("[1/5] opening a fresh seed tape (seed=0x%016" PRIx64 ")...\n",
           (uint64_t)TEACHING_SEED);
    seed_tape_t *rec = seed_tape_open(TEACHING_SEED, TEACHING_START_WALL);
    if (!rec) {
        fprintf(stderr, "FAIL: seed_tape_open returned NULL\n");
        return 1;
    }
    /* Installing hooks platform_rng_u64()/platform_clock_*() to this
     * tape's virtual sources — every rng_u64() below is deterministic. */
    seed_tape_install(rec);

    printf("[2/5] driving a small 'sim run': 4 RNG draws (nonce "
           "stand-ins) + 3 clock advances (150s simulated block "
           "interval) + 3 injected peer-message events...\n");
    uint64_t pre_draws[4];
    for (int i = 0; i < 4; i++) pre_draws[i] = rng_u64();
    printf("      sample nonce draws: 0x%016" PRIx64 " 0x%016" PRIx64 " ...\n",
           pre_draws[0], pre_draws[1]);
    for (int i = 0; i < 3; i++) {
        int rc = seed_tape_advance(rec, 150 * 1000000 /* 150s in us */);
        assert(rc == 0 && "advance must succeed while RECORDING");
    }
    for (int i = 0; i < 3; i++) {
        int rc = seed_tape_inject(rec, PEER_MESSAGE_TYPE, kPeerMessages[i],
                                  strlen(kPeerMessages[i]));
        assert(rc == 0 && "inject must succeed while RECORDING");
    }

    printf("[3/5] snapshotting the LIVE tape two ways at this exact "
           "instant: a plain .bin file and a postmortem capsule (as if "
           "a crash happened right here)...\n");
    char tape_path[600];
    snprintf(tape_path, sizeof(tape_path), "%s/tape.bin", scratch_dir);
    if (seed_tape_save(rec, tape_path) != 0) {
        fprintf(stderr, "FAIL: seed_tape_save\n");
        return 1;
    }

    char capsule_dir[600];
    snprintf(capsule_dir, sizeof(capsule_dir), "%s/capsules", scratch_dir);
    char capsule_path[700];
    struct postmortem_capture_opts opts = {
        .dir = capsule_dir,
        .tape = rec,
        .crash_signal = 0, /* no real signal — this is a teaching capture */
        .crash_unix = TEACHING_START_WALL + 450,
        .reason = "09_seed_replay teaching capsule (no real crash)",
        .log_path = NULL,
    };
    if (postmortem_capture_write(&opts, capsule_path,
                                 sizeof(capsule_path)) != 0) {
        fprintf(stderr, "FAIL: postmortem_capture_write\n");
        return 1;
    }
    printf("      tape file:   %s\n", tape_path);
    printf("      capsule dir: %s\n", capsule_path);

    printf("[4/5] continuing the ORIGINAL tape 5 more RNG draws — this "
           "is the ground truth both reloaded snapshots must reproduce "
           "when replayed forward from the snapshot point...\n");
    uint64_t expected_continuation[5];
    for (int i = 0; i < 5; i++) expected_continuation[i] = rng_u64();
    seed_tape_uninstall();
    seed_tape_close(rec);

    printf("[5/5] reloading BOTH snapshots in REPLAY mode and proving "
           "bit-identical RNG continuation + identical event order...\n");

    struct { const char *label; seed_tape_t *tape; } replays[2] = {
        { "from plain .bin file", seed_tape_load(tape_path) },
        { "from postmortem capsule",
          postmortem_capsule_load_tape(capsule_path) },
    };

    int failures = 0;
    for (size_t r = 0; r < 2; r++) {
        seed_tape_t *rep = replays[r].tape;
        printf("      -- %s --\n", replays[r].label);
        if (!rep) {
            fprintf(stderr, "FAIL: reload (%s) returned NULL\n",
                    replays[r].label);
            failures++;
            continue;
        }

        seed_tape_install(rep);
        bool draws_match = true;
        for (int i = 0; i < 5; i++) {
            uint64_t v = rng_u64();
            if (v != expected_continuation[i]) draws_match = false;
        }
        seed_tape_uninstall();
        printf("      RNG continuation matches ground truth: %s\n",
               draws_match ? "yes" : "NO");
        if (!draws_match) failures++;

        /* A replay tape is read-only: it reproduces the recorded past,
         * it cannot record a new future. This is what makes a postmortem
         * capsule safe to hand to a debugger — stepping through it can
         * never silently diverge into "a different run". */
        int adv_rc = seed_tape_advance(rep, 1);
        printf("      replay tape rejects new writes (-EROFS): %s\n",
               (adv_rc == -EROFS) ? "yes" : "NO");
        if (adv_rc != -EROFS) failures++;

        bool events_match = true;
        for (int i = 0; i < 3; i++) {
            uint8_t type = 0;
            char payload[32];
            size_t len = 0;
            int ev = seed_tape_next_event(rep, &type, payload,
                                          sizeof(payload), &len);
            if (ev != 0 || type != PEER_MESSAGE_TYPE ||
                len != strlen(kPeerMessages[i]) ||
                memcmp(payload, kPeerMessages[i], len) != 0) {
                events_match = false;
            }
        }
        printf("      injected event queue replays in order: %s\n",
               events_match ? "yes" : "NO");
        if (!events_match) failures++;

        seed_tape_close(rep);
    }

    cleanup_capsule_dir(capsule_path);
    unlink(tape_path);
    rmdir(capsule_dir);
    rmdir(scratch_dir);

    if (failures != 0) {
        fprintf(stderr, "FAIL: %d mismatch(es) between recording and "
                        "replay — determinism is broken\n", failures);
        return 1;
    }

    printf("\n=== SUCCESS: both the plain .bin file and the postmortem "
          "capsule replayed the exact RNG stream and event order the "
          "original process produced — a crash capsule is a complete, "
          "replayable postmortem, no live process needed ===\n");
    return 0;
}

/* Production counterpart:
 * -----------------------
 * Production never calls seed_tape_open() directly — a real node's RNG
 * and clock always resolve to the real kernel sources (rng.h's
 * `getrandom(2)` default vtable, clock.h's `clock_gettime` default
 * vtable). The tape mechanism exists so a FAILURE can be captured the
 * same way a test drives one:
 *
 *   - `boot_postmortem_init_for_testing` / the production boot path in
 *     engine/composition/src/boot.c wires a real seed tape + `postmortem_install()`
 *     (engine/modules/sim/include/sim/postmortem.h) at process start, so a live
 *     node's SIGSEGV/SIGABRT handler calls `postmortem_capture_write()`
 *     automatically — the exact function this example calls by hand.
 *   - An operator (or Claude via native commands) lists and loads capsules
 *     with `z23 ops postmortem list` /
 *     `z23 ops postmortem replay <id>`
 *     (native controllers, backed by `postmortem_capsule_list()` /
 *     `postmortem_capsule_load_tape()` — the same two calls this example
 *     uses) to get the exact deterministic replay of what the node's RNG
 *     and event stream looked like at the moment it crashed, without
 *     needing the crashed process to still be running.
 */
