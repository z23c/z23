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
#include "sapling/bn254_accel.h"
#include "sapling/fr.h"
#include "sapling/fr_accel.h"
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

/* ── fr / fr_avx512 / bn254_accel first-call race ──────────────
 *
 * fr.c (Jubjub d), fr_avx512.c (CPUID flags + Fr/Fp dispatch pointers) and
 * bn254_accel.c (CPUID flags + Fq dispatch pointer) published lazily computed
 * state through plain non-atomic flags and pointers: a C data race for
 * concurrent first callers. This section releases LAZY_THREADS threads from a
 * barrier into the first call of every one of them. It is a first-call race
 * only when it is the first user of those functions in the process, so it runs
 * FIRST in this group; `make t-tsan ONLY=test_sapling_lazy_init` is the lane
 * that reports the race on the unfixed code. Without TSan it asserts that every
 * racer sees identical results, equal to the portable reference. */

#define LAZY_THREADS 24
#define LAZY_ROUNDS 4

struct lazy_result {
    uint64_t fr_prod[4];
    uint64_t fp_prod[6];
    uint64_t bn_prod[4];
    uint8_t jub_sum[32];
    uint8_t jub_dbl[32];
    uint8_t jub_dec[32];
    bool jub_decoded;
    const char *fr_impl;
    const char *bn_impl;
};

struct lazy_shared {
    zcl_barrier_t barrier;
    struct lazy_result res[LAZY_THREADS];
};

struct lazy_arg {
    struct lazy_shared *sh;
    int idx;
};

static void lazy_fill(uint64_t *v, int n, uint64_t seed)
{
    for (int i = 0; i < n; i++)
        v[i] = (seed + (uint64_t)i) * 0x9e3779b97f4a7c15ULL;
    v[n - 1] &= 0x0fffffffffffffffULL; /* well below both moduli */
}

static void *lazy_worker(void *p)
{
    struct lazy_arg *a = p;
    struct lazy_shared *sh = a->sh;
    struct lazy_result *r = &sh->res[a->idx];

    uint64_t a4[4], b4[4], a6[6], b6[6];
    lazy_fill(a4, 4, 11); lazy_fill(b4, 4, 23);
    lazy_fill(a6, 6, 37); lazy_fill(b6, 6, 59);

    zcl_barrier_wait(&sh->barrier);

    /* Every initialiser is first reached here, at the same instant. */
    fr_mont_mul_accel(r->fr_prod, a4, b4);
    fp_mont_mul_accel(r->fp_prod, a6, b6);
    bn_fq_mont_mul_accel(r->bn_prod, a4, b4);
    r->fr_impl = fr_accel_implementation();
    r->bn_impl = bn254_accel_implementation();

    struct jub_point pt, sum, dbl;
    uint8_t yb[32] = {0};
    r->jub_decoded = false;
    for (uint8_t y = 2; y < 64 && !r->jub_decoded; y++) {
        yb[0] = y;
        r->jub_decoded = jub_from_bytes(&pt, yb);
    }
    if (r->jub_decoded) {
        jub_add(&sum, &pt, &pt);
        jub_double(&dbl, &pt);
        jub_to_bytes(r->jub_sum, &sum);
        jub_to_bytes(r->jub_dbl, &dbl);
        jub_to_bytes(r->jub_dec, &pt);
    }
    return NULL;
}

static bool lazy_same(const struct lazy_result *x, const struct lazy_result *y)
{
    return memcmp(x->fr_prod, y->fr_prod, sizeof x->fr_prod) == 0 &&
           memcmp(x->fp_prod, y->fp_prod, sizeof x->fp_prod) == 0 &&
           memcmp(x->bn_prod, y->bn_prod, sizeof x->bn_prod) == 0 &&
           memcmp(x->jub_sum, y->jub_sum, 32) == 0 &&
           memcmp(x->jub_dbl, y->jub_dbl, 32) == 0 &&
           memcmp(x->jub_dec, y->jub_dec, 32) == 0 &&
           x->jub_decoded == y->jub_decoded &&
           strcmp(x->fr_impl, y->fr_impl) == 0 &&
           strcmp(x->bn_impl, y->bn_impl) == 0;
}

static int lazy_fr_accel_race(void)
{
    int failures = 0;
    static struct lazy_shared sh;
    memset(&sh, 0, sizeof sh);

    for (int round = 0; round < LAZY_ROUNDS; round++) {
        pthread_t th[LAZY_THREADS];
        struct lazy_arg args[LAZY_THREADS];
        zcl_barrier_init(&sh.barrier, LAZY_THREADS);
        int started = 0;
        for (int i = 0; i < LAZY_THREADS; i++) {
            args[i].sh = &sh;
            args[i].idx = i;
            if (pthread_create(&th[i], NULL, lazy_worker, &args[i]) != 0)
                break;
            started++;
        }
        if (started != LAZY_THREADS) {
            printf("only %d/%d threads started... ", started, LAZY_THREADS);
            failures++;
        }
        for (int i = 0; i < LAZY_THREADS && i < started; i++)
            pthread_join(th[i], NULL);
        zcl_barrier_destroy(&sh.barrier);
        for (int i = 1; i < LAZY_THREADS; i++) {
            if (!lazy_same(&sh.res[0], &sh.res[i])) {
                printf("round %d: thread %d differs from thread 0... ", round, i);
                failures++;
                break;
            }
        }
    }

    uint64_t a4[4], b4[4], a6[6], b6[6], ref4[4], ref6[6], refb[4];
    lazy_fill(a4, 4, 11); lazy_fill(b4, 4, 23);
    lazy_fill(a6, 6, 37); lazy_fill(b6, 6, 59);
    fr_accel_mont_mul_portable(ref4, a4, b4);
    fp_accel_mont_mul_portable(ref6, a6, b6);
    bn254_accel_mont_mul_portable(refb, a4, b4);
    if (memcmp(ref4, sh.res[0].fr_prod, sizeof ref4) != 0) {
        printf("Fr dispatched != portable... ");
        failures++;
    }
    if (memcmp(ref6, sh.res[0].fp_prod, sizeof ref6) != 0) {
        printf("Fp dispatched != portable... ");
        failures++;
    }
    if (memcmp(refb, sh.res[0].bn_prod, sizeof refb) != 0) {
        printf("Fq dispatched != portable... ");
        failures++;
    }
    /* jub_add reads d; jub_double does not: they must agree on a real point. */
    if (!sh.res[0].jub_decoded ||
        memcmp(sh.res[0].jub_sum, sh.res[0].jub_dbl, 32) != 0) {
        printf("jub_add(P,P) != jub_double(P) or no probe point... ");
        failures++;
    }
    printf("%s (%s; %s)\n", failures ? "FAIL" : "OK",
           sh.res[0].fr_impl, sh.res[0].bn_impl);
    return failures;
}

/* ── driver ───────────────────────────────────────────────── */

int test_sapling_lazy_init(void)
{
    int failures = 0;

    printf("fr/fr_avx512/bn254_accel concurrent first-caller race... ");
    failures += lazy_fr_accel_race();

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
