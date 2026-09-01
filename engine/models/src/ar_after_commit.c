/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ar_after_commit — per-transaction hook queue. See the header for the
 * semantics and for why the queue is keyed to the thread.
 *
 * ar-validate-skip:not-a-row
 *   This module owns a hook queue, not a table row. Validation belongs to the
 *   models whose saves it defers.
 *
 * Ownership: every queued entry owns a heap copy of the record it will be
 * handed. The copy is freed after the hook runs, and freed without running
 * anything on rollback. Draining swaps the queue out to a local first, so a
 * hook that saves another record during the drain (which then runs at depth
 * zero and fires immediately) cannot mutate the array being walked.
 */

#include "models/ar_after_commit.h"

#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

struct ar_commit_entry {
    void (*fn)(void *record, void *ctx);
    void *ctx;
    void *record;   /* owned copy */
};

/* Per-thread transaction state. See the header's "Scope, stated plainly". */
static _Thread_local int g_depth;
static _Thread_local struct ar_commit_entry *g_queue;
static _Thread_local size_t g_len;
static _Thread_local size_t g_cap;

static void ar_after_commit_free_queue(struct ar_commit_entry *q, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(q[i].record);
    free(q);
}

static void ar_after_commit_discard(void)
{
    ar_after_commit_free_queue(g_queue, g_len);
    g_queue = NULL;
    g_len = 0;
    g_cap = 0;
}

void ar_after_commit_note_begin(void)
{
    g_depth++;
}

void ar_after_commit_note_commit(bool committed)
{
    if (!committed) {
        /* SQLite can leave the transaction open after a failed COMMIT. Keep
         * the queue for the ROLLBACK the caller must now issue. */
        return;
    }
    if (g_depth > 0)
        g_depth--;
    if (g_depth != 0)
        return; /* an inner commit never drains; only the outermost does */

    /* Swap the queue out before firing so a hook that saves during the drain
     * (depth is zero now, so it fires immediately) cannot touch this array. */
    struct ar_commit_entry *q = g_queue;
    size_t n = g_len;
    g_queue = NULL;
    g_len = 0;
    g_cap = 0;

    for (size_t i = 0; i < n; i++)
        q[i].fn(q[i].record, q[i].ctx);
    ar_after_commit_free_queue(q, n);
}

void ar_after_commit_note_rollback(void)
{
    /* ROLLBACK aborts the whole transaction, however deeply the caller
     * thought it was nested. Discard everything and start over. */
    g_depth = 0;
    ar_after_commit_discard();
}

bool ar_after_commit_enqueue(void (*fn)(void *record, void *ctx), void *ctx,
                             void *record, size_t record_size)
{
    if (!fn)
        return true; /* nothing registered is not a failure */

    if (g_depth == 0) {
        /* No transaction: the statement has already succeeded and is durable
         * on its own, so the hook runs now against the caller's own record.
         * Nothing is copied and nothing can be rolled back out from under
         * it. */
        fn(record, ctx);
        return true;
    }

    if (!record || record_size == 0)
        LOG_FAIL("db", "after_commit: hook has no record size to copy — "
                        "register it with ar_register_after_commit(cbs, fn, "
                        "sizeof(*record))");
    if (g_len >= AR_AFTER_COMMIT_MAX_QUEUED)
        LOG_FAIL("db", "after_commit: %d hooks already queued in one "
                        "transaction — refusing the save rather than dropping "
                        "an observer notification",
                  AR_AFTER_COMMIT_MAX_QUEUED);

    if (g_len == g_cap) {
        size_t next = g_cap ? g_cap * 2 : 8;
        if (next > AR_AFTER_COMMIT_MAX_QUEUED)
            next = AR_AFTER_COMMIT_MAX_QUEUED;
        struct ar_commit_entry *grown = zcl_realloc(
            g_queue, next * sizeof(*grown), "after_commit queue");
        if (!grown)
            LOG_FAIL("db", "after_commit: cannot grow the hook queue to %zu",
                      next);
        g_queue = grown;
        g_cap = next;
    }

    void *copy = zcl_malloc(record_size, "after_commit record copy");
    if (!copy)
        LOG_FAIL("db", "after_commit: cannot copy a %zu-byte record",
                  record_size);
    memcpy(copy, record, record_size);

    g_queue[g_len].fn = fn;
    g_queue[g_len].ctx = ctx;
    g_queue[g_len].record = copy;
    g_len++;
    return true;
}

int ar_after_commit_depth(void)
{
    return g_depth;
}

int ar_after_commit_pending(void)
{
    return (int)g_len;
}

void ar_after_commit_reset(void)
{
    g_depth = 0;
    ar_after_commit_discard();
}
