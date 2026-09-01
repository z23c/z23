/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * pthread_once guard on lazy Sapling caches.
 *
 * pedersen_hash.c::ensure_generators and
 * incremental_merkle_tree.c::ensure_sapling_empty_roots were guarded
 * by a plain `static bool`. Two threads racing the first call could
 * both observe the flag false and execute the init body concurrently:
 * interleaved writes into the shared backing buffer, and on weak
 * memory models the flag could become visible `true` before the
 * buffer writes drained — next reader gets a zero-generator.
 *
 * These tests race N threads through a barrier into the first call
 * from a cold state and assert:
 *   1. The init body executed exactly once (pthread_once contract).
 *   2. Every thread's observed output is identical and non-zero
 *      (all callers see the same fully-initialized cache).
 *
 * Pre-fix the body_runs == 1 assertion fails deterministically on
 * multi-core systems — concurrent first-callers all enter the body.
 * Post-fix pthread_once pins body_runs to exactly one. */

#include "test/test_core.h"
#include "platform/barrier.h"
#include "validation/main_state.h"
#include "sapling/pedersen_hash.h"
#include <pthread.h>
#include <stdatomic.h>

/* Observability + reset hooks exposed by core/modules/sapling/src/pedersen_hash.c
 * and core/modules/sapling/src/incremental_merkle_tree.c under -DZCL_TESTING. */
extern _Atomic int zcl_pedersen_generators_body_runs_for_test;
extern void zcl_pedersen_generators_reset_for_test(void);
extern _Atomic int zcl_sapling_empty_roots_body_runs_for_test;
extern void zcl_sapling_empty_roots_reset_for_test(void);

#define RACE_NTHREADS 16

/* ── pedersen_hash race ────────────────────────────────────── */

struct pedersen_race_worker {
    zcl_barrier_t *bar;
    uint8_t hash[32];
};

static void *pedersen_race_fn(void *p)
{
    struct pedersen_race_worker *w = p;
    uint8_t a[32] = { 0 };
    uint8_t b[32] = { 0 };
    a[0] = 0x11;
    b[0] = 0x22;
    zcl_barrier_wait(w->bar);
    pedersen_merkle_hash(0, a, b, w->hash);
    return NULL;
}

/* ── empty_roots race ─────────────────────────────────────── */

struct empty_roots_race_worker {
    zcl_barrier_t *bar;
    struct uint256 root;
};

static void *empty_roots_race_fn(void *p)
{
    struct empty_roots_race_worker *w = p;
    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    zcl_barrier_wait(w->bar);
    incremental_tree_empty_root(&t, &w->root);
    return NULL;
}

/* ── driver ───────────────────────────────────────────────── */

int test_sapling_lazy_init(void)
{
    int failures = 0;

    printf("pedersen_hash concurrent first-caller race... ");
    {
        zcl_pedersen_generators_reset_for_test();

        zcl_barrier_t bar;
        zcl_barrier_init(&bar, RACE_NTHREADS);

        struct pedersen_race_worker w[RACE_NTHREADS] = { 0 };
        pthread_t tids[RACE_NTHREADS];
        for (int i = 0; i < RACE_NTHREADS; i++) {
            w[i].bar = &bar;
            pthread_create(&tids[i], NULL, pedersen_race_fn, &w[i]);
        }
        for (int i = 0; i < RACE_NTHREADS; i++) pthread_join(tids[i], NULL);
        zcl_barrier_destroy(&bar);

        int body_runs = atomic_load(&zcl_pedersen_generators_body_runs_for_test);
        bool body_once = (body_runs == 1);

        uint8_t zero[32] = { 0 };
        bool nonzero = memcmp(w[0].hash, zero, 32) != 0;
        bool all_equal = true;
        for (int i = 1; i < RACE_NTHREADS; i++) {
            if (memcmp(w[0].hash, w[i].hash, 32) != 0) { all_equal = false; break; }
        }

        if (body_once && nonzero && all_equal) {
            printf("OK (body_runs=%d)\n", body_runs);
        } else {
            printf("FAIL (body_runs=%d nonzero=%d all_equal=%d)\n",
                   body_runs, nonzero, all_equal);
            failures++;
        }
    }

    printf("sapling_empty_roots concurrent first-caller race... ");
    {
        zcl_sapling_empty_roots_reset_for_test();

        zcl_barrier_t bar;
        zcl_barrier_init(&bar, RACE_NTHREADS);

        struct empty_roots_race_worker w[RACE_NTHREADS] = { 0 };
        pthread_t tids[RACE_NTHREADS];
        for (int i = 0; i < RACE_NTHREADS; i++) {
            w[i].bar = &bar;
            pthread_create(&tids[i], NULL, empty_roots_race_fn, &w[i]);
        }
        for (int i = 0; i < RACE_NTHREADS; i++) pthread_join(tids[i], NULL);
        zcl_barrier_destroy(&bar);

        int body_runs = atomic_load(&zcl_sapling_empty_roots_body_runs_for_test);
        bool body_once = (body_runs == 1);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        bool nonzero = memcmp(&w[0].root, &zero, sizeof(zero)) != 0;
        bool all_equal = true;
        for (int i = 1; i < RACE_NTHREADS; i++) {
            if (memcmp(&w[0].root, &w[i].root, sizeof(zero)) != 0) {
                all_equal = false;
                break;
            }
        }

        if (body_once && nonzero && all_equal) {
            printf("OK (body_runs=%d)\n", body_runs);
        } else {
            printf("FAIL (body_runs=%d nonzero=%d all_equal=%d)\n",
                   body_runs, nonzero, all_equal);
            failures++;
        }
    }

    return failures;
}
