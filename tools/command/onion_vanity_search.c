/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Vanity v3 onion identity search: prefix encoding, the public-key bit test,
 * and the worker pool. See command/onion_vanity.h. */

#include "command/onion_vanity.h"

#include "platform/clock.h"
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "support/cleanse.h"
#include "util/workpool.h"

#include <stdatomic.h>
#include <string.h>

/* Candidates drawn from the CSPRNG per call and per stop-flag check. */
#define OV_BATCH 16u

enum ov_stop {
    OV_RUNNING = 0,
    OV_FOUND,
    OV_TIMED_OUT,
    OV_INTERRUPTED,
    OV_FAILED,
};

struct ov_job {
    const struct onion_vanity_params *params;
    int64_t deadline_ns;
    atomic_uint_fast64_t claimed;
    atomic_int stop;
    uint8_t seed[32];
};

struct ov_worker {
    struct ov_job *job;
    uint64_t done;
};

static int ov_alphabet_value(char c)
{
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '2' && c <= '7')
        return 26 + (c - '2');
    return -1;
}

enum onion_vanity_prefix_status
onion_vanity_target_parse(const char *prefix, struct onion_vanity_target *target,
                          char *bad_char)
{
    if (!prefix || !target || !prefix[0])
        return ONION_VANITY_PREFIX_EMPTY;
    size_t length = strlen(prefix);
    if (length > ONION_VANITY_PREFIX_MAX)
        return ONION_VANITY_PREFIX_TOO_LONG;
    memset(target, 0, sizeof(*target));
    for (size_t i = 0; i < length; i++) {
        char c = prefix[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        int value = ov_alphabet_value(c);
        if (value < 0) {
            if (bad_char)
                *bad_char = prefix[i];
            return ONION_VANITY_PREFIX_BAD_CHAR;
        }
        target->text[i] = c;
        target->want = (target->want << 5) | (uint64_t)value;
    }
    target->length = length;
    target->bits = (unsigned)(5 * length);
    return ONION_VANITY_PREFIX_OK;
}

bool onion_vanity_pk_matches(const struct onion_vanity_target *target,
                             const uint8_t public_key[32])
{
    uint64_t head = 0;
    for (size_t i = 0; i < 8; i++)
        head = (head << 8) | public_key[i];
    return (head >> (64u - target->bits)) == target->want;
}

double onion_vanity_expected_tries(const struct onion_vanity_target *target)
{
    return (double)(UINT64_C(1) << target->bits);
}

static void ov_request_stop(struct ov_job *job, enum ov_stop reason)
{
    int expected = OV_RUNNING;
    (void)atomic_compare_exchange_strong(&job->stop, &expected, (int)reason);
}

/* Returns true when a limit stopped the job. */
static bool ov_limit_reached(struct ov_job *job)
{
    const struct onion_vanity_params *p = job->params;
    if (p->interrupt && atomic_load(p->interrupt)) {
        ov_request_stop(job, OV_INTERRUPTED);
        return true;
    }
    if (job->deadline_ns != 0 && clock_now_monotonic_ns() >= job->deadline_ns) {
        ov_request_stop(job, OV_TIMED_OUT);
        return true;
    }
    return false;
}

/* Reserve up to OV_BATCH candidates against max_tries; 0 when none remain. */
static size_t ov_claim(struct ov_job *job)
{
    uint64_t max = job->params->max_tries;
    if (max == 0)
        return OV_BATCH;
    uint64_t before = atomic_fetch_add(&job->claimed, OV_BATCH);
    if (before >= max)
        return 0;
    uint64_t left = max - before;
    return left < OV_BATCH ? (size_t)left : OV_BATCH;
}

static void ov_scan(struct ov_worker *w, const uint8_t *block, size_t count)
{
    struct ov_job *job = w->job;
    for (size_t i = 0; i < count && atomic_load(&job->stop) == OV_RUNNING; i++) {
        uint8_t pk[32], sk[32];
        ed25519_keypair(pk, sk, block + 32 * i);
        memory_cleanse(sk, sizeof(sk));
        w->done++;
        if (!onion_vanity_pk_matches(&job->params->target, pk))
            continue;
        int expected = OV_RUNNING;
        if (atomic_compare_exchange_strong(&job->stop, &expected, OV_FOUND))
            memcpy(job->seed, block + 32 * i, 32);
    }
}

static bool ov_worker_run(void *item)
{
    struct ov_worker *w = item;
    struct ov_job *job = w->job;
    uint8_t block[OV_BATCH * 32];
    while (atomic_load(&job->stop) == OV_RUNNING && !ov_limit_reached(job)) {
        size_t count = ov_claim(job);
        if (count == 0)
            break; /* max_tries claimed; other workers finish their batches */
        if (!zcl_random_secret_bytes(block, count * 32, "onion_vanity_batch")) {
            ov_request_stop(job, OV_FAILED);
            break;
        }
        ov_scan(w, block, count);
    }
    memory_cleanse(block, sizeof(block));
    return true;
}

static enum onion_vanity_status ov_status(int stop)
{
    switch (stop) {
    case OV_FOUND: return ONION_VANITY_FOUND;
    case OV_RUNNING: return ONION_VANITY_EXHAUSTED;
    case OV_TIMED_OUT: return ONION_VANITY_TIMED_OUT;
    case OV_INTERRUPTED: return ONION_VANITY_INTERRUPTED;
    default: return ONION_VANITY_FAILED;
    }
}

void onion_vanity_search(const struct onion_vanity_params *params,
                         struct onion_vanity_result *result)
{
    memset(result, 0, sizeof(*result));
    result->status = ONION_VANITY_FAILED;
    if (params->threads < 1 || params->threads > ONION_VANITY_THREADS_MAX ||
        params->target.length == 0)
        return;

    int64_t start = clock_now_monotonic_ns();
    struct ov_job job = { .params = params };
    job.deadline_ns = params->timeout_ns > 0 ? start + params->timeout_ns : 0;
    struct ov_worker workers[ONION_VANITY_THREADS_MAX];
    void *items[ONION_VANITY_THREADS_MAX];
    for (unsigned i = 0; i < params->threads; i++) {
        workers[i] = (struct ov_worker){ .job = &job };
        items[i] = &workers[i];
    }

    struct workpool pool;
    if (!workpool_init(&pool, (int)params->threads, params->threads,
                       ov_worker_run))
        return;
    bool ran = workpool_run(&pool, items, params->threads);
    workpool_destroy(&pool);

    for (unsigned i = 0; i < params->threads; i++)
        result->tries += workers[i].done;
    result->elapsed_ns = clock_now_monotonic_ns() - start;
    result->status = ran ? ov_status(atomic_load(&job.stop))
                         : ONION_VANITY_FAILED;
    if (result->status == ONION_VANITY_FOUND &&
        params->interrupt && atomic_load(params->interrupt))
        result->status = ONION_VANITY_INTERRUPTED;
    if (result->status == ONION_VANITY_FOUND)
        memcpy(result->seed, job.seed, sizeof(result->seed));
    memory_cleanse(job.seed, sizeof(job.seed));
}

double onion_vanity_measure_rate(unsigned threads, int64_t duration_ns,
                                 const atomic_int *interrupt)
{
    struct onion_vanity_params params = {
        .threads = threads, .timeout_ns = duration_ns, .interrupt = interrupt,
    };
    if (onion_vanity_target_parse("aaaaaaaaaaaa", &params.target, NULL) !=
        ONION_VANITY_PREFIX_OK)
        return 0.0;
    struct onion_vanity_result result;
    onion_vanity_search(&params, &result);
    memory_cleanse(result.seed, sizeof(result.seed));
    bool measured = result.status == ONION_VANITY_TIMED_OUT ||
                    result.status == ONION_VANITY_FOUND;
    if (!measured || result.elapsed_ns <= 0)
        return 0.0;
    return (double)result.tries * 1e9 / (double)result.elapsed_ns;
}
