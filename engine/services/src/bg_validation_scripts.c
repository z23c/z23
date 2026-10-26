/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
// one-result-type-ok:hot-script-verifier
// Internal background-validation verifier, not a new service surface. The
// bg_validation service walks the chain and converts a false return here into
// a logged per-block validation failure with the offending height/tx; the bool
// keeps the hot per-input verifier branch-free.
/*
 * bg_validation_scripts: parallel ECDSA script-signature verification for the
 * background full-validation pass. */

#include "bg_validation_internal.h"

#include "validation/tx_verifier.h"
#include "script/interpreter.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_qos.h"

#include <pthread.h>
#include <stdlib.h>

/* ── Parallel script verification ────────────────────────────── */

static bool verify_script_item(void *item)
{
    struct script_check_item *sc = item;
    struct tx_sig_checker tsc;
    tx_sig_checker_init(&tsc, sc->tx, sc->input_index,
                        sc->amount, sc->branch_id, &sc->txdata);
    struct sig_checker checker = tx_make_sig_checker(&tsc);

    ScriptError serror = SCRIPT_ERR_OK;
    return verify_script(&sc->tx->vin[sc->input_index].script_sig,
                         &sc->script_pub_key,
                         sc->flags, &checker,
                         sc->branch_id, &serror);
}

/* ── Worker thread for parallel verification ─────────────────── */

struct worker_ctx {
    struct script_check_item *items;
    size_t start;
    size_t count;
    bool result;
};

static void *worker_thread(void *arg)
{
    struct worker_ctx *w = arg;

    /* This is sovereignty verification, never the active reducer/network/RPC
     * path. Apply the calling-thread controls even though Darwin workers are
     * also born with a background-QoS attribute below: Linux I/O priority has
     * no pthread attribute, and the duplicate Darwin call is idempotent. */
    (void)zcl_thread_qos_background();

    w->result = true;
    for (size_t i = 0; i < w->count; i++) {
        if (!verify_script_item(&w->items[w->start + i])) {
            w->result = false;
            return NULL;
        }
    }
    return NULL;
}

/* ── Driver helpers for bg_validation_verify_scripts_parallel ── */

/* Small batches and single-worker runs are cheaper to verify inline. */
static bool should_verify_serially(int num_workers, size_t count)
{
    return num_workers <= 1 || count <= 4;
}

/* Verify items in order and return the index of the first item that fails,
 * or count when every item verifies. */
static size_t first_failed_script_item(struct script_check_item *items,
                                       size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!verify_script_item(&items[i]))
            return i;
    }
    return count;
}

/* Never start more workers than there are items to verify. */
static int clamp_worker_count(int num_workers, size_t count)
{
    if ((size_t)num_workers > count)
        return (int)count;
    return num_workers;
}

/* Allocate the three per-worker arrays. Every out pointer is written even on
 * failure so the caller can free whatever did allocate. Returns 0 on
 * success, -1 otherwise. */
static int alloc_worker_arrays(struct worker_ctx **workers_out,
                               pthread_t **threads_out,
                               bool **created_out,
                               int nthreads)
{
    *workers_out = zcl_calloc((size_t)nthreads,
                              sizeof(struct worker_ctx), "bg_valid workers");
    *threads_out = zcl_calloc((size_t)nthreads,
                              sizeof(pthread_t), "bg_valid threads");
    *created_out = zcl_calloc((size_t)nthreads,
                              sizeof(bool), "bg_valid created");
    if (*workers_out && *threads_out && *created_out)
        return 0;
    LOG_ERR("bg.validation", "worker array allocation failed (nthreads=%d)",
            nthreads);
}

/* Give each worker a contiguous range of items; the first (count % nthreads)
 * ranges take one extra item so the split covers count exactly. */
static void assign_worker_ranges(struct worker_ctx *workers,
                                 struct script_check_item *items,
                                 int nthreads, size_t count)
{
    size_t per_thread = count / (size_t)nthreads;
    size_t remainder = count % (size_t)nthreads;
    size_t offset = 0;

    for (int t = 0; t < nthreads; t++) {
        workers[t].items = items;
        workers[t].start = offset;
        workers[t].count = per_thread + (t < (int)remainder ? 1 : 0);
        workers[t].result = true;
        offset += workers[t].count;
    }
}

/* Outcome of preparing the worker pthread attribute. */
enum worker_attr_outcome {
    WORKER_ATTR_READY = 0,
    WORKER_ATTR_INIT_FAILED,            /* attr_rc_out holds the error */
    WORKER_ATTR_REFUSED_DESTROYED,      /* QoS refused, attribute destroyed ok */
    WORKER_ATTR_REFUSED_DESTROY_FAILED, /* QoS refused, destroy_rc_out holds it */
};

/* Initialize the worker attribute and try to tag it with background QoS.
 * On QoS refusal the attribute is destroyed here. */
static enum worker_attr_outcome prepare_worker_attr(pthread_attr_t *attr,
                                                    int *attr_rc_out,
                                                    int *destroy_rc_out)
{
    *attr_rc_out = 0;
    *destroy_rc_out = 0;

    int attr_rc = pthread_attr_init(attr);
    if (attr_rc != 0) {
        *attr_rc_out = attr_rc;
        return WORKER_ATTR_INIT_FAILED;
    }
    if (zcl_thread_qos_background_attr(attr))
        return WORKER_ATTR_READY;
    *destroy_rc_out = pthread_attr_destroy(attr);
    if (*destroy_rc_out != 0)
        return WORKER_ATTR_REFUSED_DESTROY_FAILED;
    return WORKER_ATTR_REFUSED_DESTROYED;
}

/* Attribute argument for pthread_create: the QoS-tagged attribute when it
 * is ready, NULL so each worker applies background QoS on entry instead. */
static pthread_attr_t *worker_create_attr(pthread_attr_t *attr,
                                          bool attr_ready)
{
    return attr_ready ? attr : NULL;
}

/* Join every thread that actually started and AND together the per-range
 * results. */
static bool join_workers_collect_results(struct worker_ctx *workers,
                                         pthread_t *threads,
                                         const bool *created,
                                         int nthreads)
{
    bool all_ok = true;
    for (int t = 0; t < nthreads; t++) {
        if (created[t])
            pthread_join(threads[t], NULL);
        if (!workers[t].result)
            all_ok = false;
    }
    return all_ok;
}

/* Verify all script items in parallel using num_workers threads.
 * Falls back to serial for small batches. */
bool bg_validation_verify_scripts_parallel(struct script_check_item *items,
                                           size_t count, int num_workers)
{
    if (count == 0)
        return true;

    /* Serial path for small batches or single-threaded mode */
    if (should_verify_serially(num_workers, count)) {
        if (first_failed_script_item(items, count) != count)
            return false;  // raw-return-ok:hot-per-input-verifier-caller-logs-height/tx
        return true;
    }

    /* Parallel: split work across threads */
    int nthreads = clamp_worker_count(num_workers, count);

    struct worker_ctx *workers;
    pthread_t *threads;
    bool *created;
    if (alloc_worker_arrays(&workers, &threads, &created, nthreads) != 0) {
        free(workers);
        free(threads);
        free(created);
        /* Fallback to serial */
        if (first_failed_script_item(items, count) != count)
            return false;  // raw-return-ok:hot-per-input-verifier-caller-logs-height/tx
        return true;
    }

    assign_worker_ranges(workers, items, nthreads, count);

    pthread_attr_t background_attr;
    int attr_rc = 0;
    int destroy_rc = 0;
    enum worker_attr_outcome attr_outcome =
        prepare_worker_attr(&background_attr, &attr_rc, &destroy_rc);
    bool background_attr_ready = (attr_outcome == WORKER_ATTR_READY);
    if (attr_outcome == WORKER_ATTR_INIT_FAILED)
        LOG_WARN("bg.validation",
                 "pthread_attr_init failed (%d); worker will apply background "
                 "QoS on entry", attr_rc);
    if (attr_outcome == WORKER_ATTR_REFUSED_DESTROY_FAILED)
        LOG_WARN("bg.validation",
                 "pthread_attr_destroy after QoS refusal failed: %d",
                 destroy_rc);

    for (int t = 0; t < nthreads; t++) {
        /* raw-pthread-ok: short-burst-joined-immediately */
        int rc = pthread_create(&threads[t],
                                worker_create_attr(&background_attr,
                                                   background_attr_ready),
                                worker_thread, &workers[t]);
        if (rc != 0) {
            /* Thread did not start. Two failure modes must NOT happen here:
             * (1) leaving workers[t].result == true for an unrun range would
             * report unverified script signatures as VALID — a silent hole in
             * the full-validation pass; (2) pthread_join on the garbage
             * threads[t] is undefined behavior. Run this range INLINE so it is
             * actually verified, and mark it not-created so the join loop skips
             * the uninitialized handle. */
            LOG_WARN("bg.validation",
                     "pthread_create failed (%d) for worker %d/%d; verifying its %zu items inline",
                     rc, t, nthreads, workers[t].count);
            worker_thread(&workers[t]);   /* sets workers[t].result honestly */
        } else {
            created[t] = true;
        }
    }

    if (background_attr_ready) {
        destroy_rc = pthread_attr_destroy(&background_attr);
        if (destroy_rc != 0)
            LOG_WARN("bg.validation",
                     "pthread_attr_destroy after worker creation failed: %d",
                     destroy_rc);
    }

    bool all_ok = join_workers_collect_results(workers, threads, created,
                                               nthreads);

    free(workers);
    free(threads);
    free(created);
    return all_ok;
}
