/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The Sapling fixed generators are derived once, by whichever thread first
 * needs them, and every other thread must see the finished table.
 *
 * A node that defers proof validation may never have touched them before its
 * first shielded send, so a send-thread prover self-test and a validation
 * thread can enter the derivation at the same moment. This group releases
 * several threads at once into the first use of the generators and requires
 * that every thread computes the same result as a single-threaded
 * recomputation. Run under ThreadSanitizer (make t-tsan ONLY=sapling_fixed_generators)
 * it also fails on any data race in the derivation. It needs no parameter
 * files and runs in its own process, so the first use is the first use.
 */

#include "test/test_core.h"

#include "sapling/sapling.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define GEN_THREADS 8

#define GEN_CHECK(name, expr) do { \
    printf("sapling_fixed_generators: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct gen_job {
    _Atomic int *go;
    uint8_t ak[32];
    uint8_t nk[32];
    uint8_t cv[32];
    bool cv_ok;
};

static void *gen_thread(void *arg)
{
    struct gen_job *j = arg;
    while (!atomic_load(j->go))
        sched_yield();
    uint8_t seed[32] = {7};
    sapling_ask_to_ak(seed, j->ak);
    sapling_nsk_to_nk(seed, j->nk);
    j->cv_ok = sapling_value_commit(1000, seed, j->cv);
    return NULL;
}

int test_sapling_fixed_generators(void);
int test_sapling_fixed_generators(void)
{
    int failures = 0;
    printf("\n=== sapling fixed generators: concurrent first use ===\n");

    _Atomic int go = 0;
    struct gen_job jobs[GEN_THREADS];
    pthread_t th[GEN_THREADS];
    bool started[GEN_THREADS];
    memset(jobs, 0, sizeof(jobs));
    for (int i = 0; i < GEN_THREADS; i++) {
        jobs[i].go = &go;
        started[i] = pthread_create(&th[i], NULL, gen_thread, &jobs[i]) == 0;
    }
    atomic_store(&go, 1);
    int ran = 0;
    for (int i = 0; i < GEN_THREADS; i++)
        if (started[i]) {
            pthread_join(th[i], NULL);
            ran++;
        }
    GEN_CHECK("all threads ran", ran == GEN_THREADS);

    uint8_t seed[32] = {7};
    uint8_t ak[32], nk[32], cv[32];
    sapling_ask_to_ak(seed, ak);
    sapling_nsk_to_nk(seed, nk);
    bool cv_ok = sapling_value_commit(1000, seed, cv);
    bool agree = cv_ok;
    for (int i = 0; i < GEN_THREADS && agree; i++)
        agree = jobs[i].cv_ok && memcmp(jobs[i].ak, ak, 32) == 0 &&
                memcmp(jobs[i].nk, nk, 32) == 0 &&
                memcmp(jobs[i].cv, cv, 32) == 0;
    GEN_CHECK("every thread agrees with the single-threaded result", agree);
    return failures;
}
