/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Oracle policy — see services/oracle_policy.h for the contract.
 *
 * Implementation notes:
 *   - Sliding window is a fixed-size ring of disagreement records.
 *     Records older than `window_secs` are treated as if absent.
 *   - distinct_heights is counted over the live records only.
 *   - State transitions are one-way except via oracle_policy_clear().
 *     Once HALTED or PANIC, we stay there until the operator says
 *     otherwise — this is the safe default. */

// one-result-type-ok:state-machine-no-fallible-surface — E2 (one way
// out): this is a lock-guarded state machine with no fallible service
// surface to carry a zcl_result. Its bool returns are non-failing
// predicates/queries: chain_extension_allowed() is a yes/no gate and
// dump_state_json() follows the mandated `<name>_dump_state_json` ->
// bool introspection convention (see CLAUDE.md "Adding state
// introspection"), which must stay bool. State transitions are recorded
// via EV_ANCHOR_PANIC / EV_FORK_SUSPECTED / EV_CHAIN_HALTED events.

#include "platform/time_compat.h"
#include "services/oracle_policy.h"

#include "chain/sha3_windows.h"   /* SHA3_WINDOW_SIZE, g_sha3_windows_count */
#include "event/event.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OP_RING_SIZE 32

struct op_record {
    int     height;
    int64_t at_unix;
};

static struct {
    pthread_mutex_t lock;
    bool   initialized;

    int    window_secs;
    int    halt_distinct_heights;
    int    evidence_prefix_end_height;

    struct op_record ring[OP_RING_SIZE];
    int    ring_head;                /* next slot to write */
    int    ring_count;               /* min(N writes, OP_RING_SIZE) */

    _Atomic int state;               /* enum oracle_policy_state */
    _Atomic int64_t total_disagree;
    _Atomic int64_t total_halts;
    _Atomic int64_t total_panics;
    _Atomic int     last_h;
    _Atomic int64_t last_unix;
} g_op = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static int op_compute_evidence_prefix_end(void)
{
    /* The compile-time SHA3 windows cover heights
     *   [0 .. g_sha3_windows_count * SHA3_WINDOW_SIZE - 1].
     * A disagreement inside that range means our payload disagrees
     * with the compile-time anchor — the gravest possible failure. */
    if (g_sha3_windows_count == 0) return -1; // raw-return-ok:sentinel-no-compile-time-windows
    return (int)(g_sha3_windows_count * SHA3_WINDOW_SIZE) - 1;
}

void oracle_policy_init(const struct oracle_policy_config *cfg)
{
    pthread_mutex_lock(&g_op.lock);
    if (g_op.initialized) {
        pthread_mutex_unlock(&g_op.lock);
        return;
    }
    g_op.window_secs =
        (cfg && cfg->window_secs > 0) ? cfg->window_secs : 300;
    g_op.halt_distinct_heights =
        (cfg && cfg->halt_distinct_heights > 0)
            ? cfg->halt_distinct_heights : 3;
    g_op.evidence_prefix_end_height =
        (cfg && cfg->evidence_prefix_end_height > 0)
            ? cfg->evidence_prefix_end_height
            : op_compute_evidence_prefix_end();
    g_op.ring_head = 0;
    g_op.ring_count = 0;
    g_op.initialized = true;
    pthread_mutex_unlock(&g_op.lock);
    atomic_store(&g_op.state, OP_NORMAL);
}

/* Count distinct heights with at_unix >= cutoff in the ring.
 * Caller must hold g_op.lock. */
static int op_count_distinct_live(int64_t now)
{
    int64_t cutoff = now - (int64_t)g_op.window_secs;
    int distinct = 0;
    int seen[OP_RING_SIZE];
    int n_seen = 0;
    for (int i = 0; i < g_op.ring_count; i++) {
        struct op_record *r = &g_op.ring[i];
        if (r->at_unix < cutoff) continue;
        bool dup = false;
        for (int j = 0; j < n_seen; j++) {
            if (seen[j] == r->height) { dup = true; break; }
        }
        if (!dup) {
            seen[n_seen++] = r->height;
            distinct++;
        }
    }
    return distinct;
}

void oracle_policy_record_disagreement(int height,
                                        const char *our_hash_hex,
                                        const char *their_hash_hex)
{
    if (!g_op.initialized) {
        LOG_INFO("oracle_policy", "[oracle_policy] record_disagreement called before init " "(h=%d) — call oracle_policy_init() first", height);
        return;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    atomic_fetch_add(&g_op.total_disagree, 1);
    atomic_store(&g_op.last_h, height);
    atomic_store(&g_op.last_unix, now);

    int prefix_end;
    int distinct = 0;
    int first_h = -1, last_h = -1;
    bool transition_panic = false;
    bool transition_halt  = false;

    pthread_mutex_lock(&g_op.lock);
    g_op.ring[g_op.ring_head].height  = height;
    g_op.ring[g_op.ring_head].at_unix = now;
    g_op.ring_head = (g_op.ring_head + 1) % OP_RING_SIZE;
    if (g_op.ring_count < OP_RING_SIZE) g_op.ring_count++;

    prefix_end = g_op.evidence_prefix_end_height;
    distinct = op_count_distinct_live(now);

    /* Find first/last height in live window for the event payload. */
    int64_t cutoff = now - (int64_t)g_op.window_secs;
    for (int i = 0; i < g_op.ring_count; i++) {
        struct op_record *r = &g_op.ring[i];
        if (r->at_unix < cutoff) continue;
        if (first_h < 0 || r->height < first_h) first_h = r->height;
        if (last_h  < 0 || r->height > last_h)  last_h  = r->height;
    }

    enum oracle_policy_state cur =
        (enum oracle_policy_state)atomic_load(&g_op.state);
    if (cur != OP_PANIC) {
        if (prefix_end >= 0 && height <= prefix_end) {
            atomic_store(&g_op.state, OP_PANIC);
            transition_panic = true;
            atomic_fetch_add(&g_op.total_panics, 1);
        } else if (cur != OP_HALTED &&
                   distinct >= g_op.halt_distinct_heights) {
            atomic_store(&g_op.state, OP_HALTED);
            transition_halt = true;
            atomic_fetch_add(&g_op.total_halts, 1);
        }
    }
    pthread_mutex_unlock(&g_op.lock);

    if (transition_panic) {
        event_emitf(EV_ANCHOR_PANIC, 0,
                    "h=%d our=%s their=%s",
                    height,
                    our_hash_hex  ? our_hash_hex  : "",
                    their_hash_hex ? their_hash_hex : "");
        event_emitf(EV_CHAIN_HALTED, 0,
                    "reason=anchor_panic distinct_heights=%d", distinct);
        fprintf(stderr,
                "[oracle_policy] ANCHOR_PANIC at h=%d "
                "(our=%s their=%s) — recorded as evidence; extension NOT gated\n",
                height,
                our_hash_hex  ? our_hash_hex  : "",
                their_hash_hex ? their_hash_hex : "");
    } else if (transition_halt) {
        event_emitf(EV_FORK_SUSPECTED, 0,
                    "distinct_heights=%d within_secs=%d "
                    "first_h=%d last_h=%d",
                    distinct, g_op.window_secs, first_h, last_h);
        event_emitf(EV_CHAIN_HALTED, 0,
                    "reason=fork_suspected distinct_heights=%d",
                    distinct);
        fprintf(stderr,
                "[oracle_policy] FORK_SUSPECTED — %d distinct "
                "disagreement heights in last %d s (first=%d last=%d) — "
                "recorded as evidence; extension NOT gated\n",
                distinct, g_op.window_secs, first_h, last_h);
    }
}

bool oracle_policy_chain_extension_allowed(void)
{
    /* EVIDENCE-ONLY. The oracle is an EXTERNAL
     * comparator (zclassicd). A comparator that is merely wrong or behind
     * must NEVER gate our own chain extension — that would let an external
     * party stop our chain, violating the "stands alone / cannot get stuck
     * on an external comparator" property. Disagreement is still RECORDED
     * as evidence: oracle_policy_record_disagreement() keeps driving the
     * OP_HALTED / OP_PANIC state machine, emitting EV_FORK_SUSPECTED /
     * EV_ANCHOR_PANIC / EV_CHAIN_HALTED, and the divergence stays fully
     * visible via oracle_policy_get_state() and `z23 dumpstate`. The state
     * is now an observable signal, not a liveness gate — so this predicate
     * unconditionally allows extension regardless of OP_HALTED/OP_PANIC. */
    return true;  // raw-return-ok:evidence-only-never-gates-extension
}

enum oracle_policy_state oracle_policy_get_state(void)
{
    return (enum oracle_policy_state)atomic_load(&g_op.state);
}

void oracle_policy_clear(void)
{
    pthread_mutex_lock(&g_op.lock);
    g_op.ring_head = 0;
    g_op.ring_count = 0;
    pthread_mutex_unlock(&g_op.lock);
    atomic_store(&g_op.state, OP_NORMAL);
    LOG_WARN("oracle_policy", "[oracle_policy] state cleared by operator");
}

static const char *op_state_name(enum oracle_policy_state s)
{
    switch (s) {
        case OP_NORMAL: return "normal";
        case OP_HALTED: return "halted";
        case OP_PANIC:  return "panic";
    }
    return "unknown";
}

const char *oracle_policy_state_name(enum oracle_policy_state s)
{
    return op_state_name(s);
}

bool oracle_policy_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    enum oracle_policy_state s =
        (enum oracle_policy_state)atomic_load(&g_op.state);
    int64_t now = (int64_t)platform_time_wall_time_t();

    pthread_mutex_lock(&g_op.lock);
    int distinct = op_count_distinct_live(now);
    int ring_count = g_op.ring_count;
    int window_secs = g_op.window_secs;
    int halt_thresh = g_op.halt_distinct_heights;
    int prefix_end  = g_op.evidence_prefix_end_height;
    pthread_mutex_unlock(&g_op.lock);

    json_push_kv_str(out, "state", op_state_name(s));
    json_push_kv_int(out, "state_code", (int64_t)s);
    json_push_kv_int(out, "ring_count", ring_count);
    json_push_kv_int(out, "distinct_heights_in_window", distinct);
    json_push_kv_int(out, "window_secs", window_secs);
    json_push_kv_int(out, "halt_threshold", halt_thresh);
    json_push_kv_int(out, "evidence_prefix_end_height", prefix_end);
    json_push_kv_int(out, "total_disagree",
                     atomic_load(&g_op.total_disagree));
    json_push_kv_int(out, "total_halts",
                     atomic_load(&g_op.total_halts));
    json_push_kv_int(out, "total_panics",
                     atomic_load(&g_op.total_panics));
    json_push_kv_int(out, "last_h", atomic_load(&g_op.last_h));
    json_push_kv_int(out, "last_unix", atomic_load(&g_op.last_unix));
    return true;
}

void oracle_policy_reset_for_test(void)
{
    pthread_mutex_lock(&g_op.lock);
    g_op.initialized = false;
    g_op.ring_head = 0;
    g_op.ring_count = 0;
    pthread_mutex_unlock(&g_op.lock);
    atomic_store(&g_op.state, OP_NORMAL);
    atomic_store(&g_op.total_disagree, 0);
    atomic_store(&g_op.total_halts, 0);
    atomic_store(&g_op.total_panics, 0);
    atomic_store(&g_op.last_h, 0);
    atomic_store(&g_op.last_unix, 0);
}
