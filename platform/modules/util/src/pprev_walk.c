/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "util/pprev_walk.h"

#include "chain/chain.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic uint64_t g_violations = 0;

static void emit_violation(const struct block_index *cur,
                           const struct block_index *prev,
                           int steps, int max_steps,
                           const char *call_site,
                           const char *reason)
{
    atomic_fetch_add(&g_violations, 1);
    fprintf(stderr,
        "[pprev-walk] violation site=%s reason=%s "
        "cur_h=%d prev_h=%d steps=%d max=%d\n",
        call_site ? call_site : "(unknown)",
        reason,
        cur ? cur->nHeight : -1,
        prev ? prev->nHeight : -1,
        steps, max_steps);
    fflush(stderr);
}

struct block_index *pprev_walk_safe(struct block_index *start,
                                    pprev_walk_pred keep_going,
                                    void *user,
                                    int max_steps,
                                    const char *call_site)
{
    if (!start || max_steps <= 0) return NULL;

    struct block_index *cur = start;
    int steps = 0;
    /* NULL predicate = "always continue", walks to genesis or
     * until the chain ends. Useful for callers that just want
     * the cycle/cap guard without a stop condition. */
    while (cur && (!keep_going || keep_going(cur, user))) {
        if (steps++ >= max_steps) {
            emit_violation(cur, NULL, steps, max_steps,
                           call_site, "step_cap");
            return NULL;
        }
        struct block_index *prev = cur->pprev;
        if (!prev) return cur; /* normal end of chain */
        if (prev->nHeight >= cur->nHeight) {
            emit_violation(cur, prev, steps, max_steps,
                           call_site, "non_monotonic");
            return NULL;
        }
        cur = prev;
    }
    return cur;
}

struct stop_height_ctx { int stop_h; };

static bool keep_until_height(const struct block_index *bi, void *user)
{
    struct stop_height_ctx *c = (struct stop_height_ctx *)user;
    return bi->nHeight > c->stop_h;
}

struct block_index *pprev_walk_until_height(struct block_index *start,
                                            int stop_height_exclusive,
                                            int max_steps,
                                            const char *call_site)
{
    struct stop_height_ctx c = { stop_height_exclusive };
    return pprev_walk_safe(start, keep_until_height, &c,
                           max_steps, call_site);
}

struct stop_target_ctx { const struct block_index *target; };

static bool keep_until_target(const struct block_index *bi, void *user)
{
    struct stop_target_ctx *c = (struct stop_target_ctx *)user;
    return bi != c->target;
}

struct block_index *pprev_walk_until_target(struct block_index *start,
                                            const struct block_index *target,
                                            int max_steps,
                                            const char *call_site)
{
    if (!target) return NULL;
    struct stop_target_ctx c = { target };
    struct block_index *r = pprev_walk_safe(start, keep_until_target, &c,
                                            max_steps, call_site);
    return r == target ? r : NULL;
}

int pprev_walk_depth(struct block_index *start,
                     int max_steps,
                     const char *call_site,
                     struct block_index **out_root)
{
    if (out_root) *out_root = NULL;
    if (!start || max_steps <= 0) return 0;
    struct block_index *cur = start;
    int depth = 0;
    while (cur && cur->pprev) {
        if (depth >= max_steps) {
            emit_violation(cur, NULL, depth, max_steps,
                           call_site, "step_cap");
            return -1;
        }
        struct block_index *prev = cur->pprev;
        if (prev->nHeight >= cur->nHeight) {
            emit_violation(cur, prev, depth, max_steps,
                           call_site, "non_monotonic");
            return -1;
        }
        cur = prev;
        depth++;
    }
    if (out_root) *out_root = cur;
    return depth;
}

uint64_t pprev_walk_violations(void)
{
    return atomic_load(&g_violations);
}
