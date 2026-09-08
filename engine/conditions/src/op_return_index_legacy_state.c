/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * op_return_index_legacy_state — self-heal condition that fires when the
 * persisted op_return_index cursor state is a REFUSED legacy_v1/unknown
 * record, and raises a typed named blocker naming the exact remedy. See
 * conditions/op_return_index_legacy_state.h for the SYMPTOM/REMEDY/WITNESS
 * contract. Mirrors state_auditor_mismatch.c / catalog_lag_exceeded.c. */

#include "conditions/op_return_index_legacy_state.h"

#include "config/runtime.h"
#include "framework/condition.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>

/* blocker-id: op_return_index.legacy_state */
#define OP_RETURN_INDEX_LEGACY_STATE_BLOCKER_ID "op_return_index.legacy_state"

#ifdef ZCL_TESTING
static struct node_db *g_test_ndb;
static _Atomic int g_test_remedy_calls;
#endif

static struct node_db *runtime_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_test_ndb)
        return g_test_ndb;
#endif
    return app_runtime_node_db();
}

static bool detect_op_return_index_legacy_state(void)
{
    struct node_db *ndb = runtime_ndb();
    return ndb && op_return_index_state_is_legacy_refused(ndb);
}

static enum condition_remedy_result remedy_op_return_index_legacy_state(void)
{
    struct node_db *ndb = runtime_ndb();
    if (!ndb || !op_return_index_state_is_legacy_refused(ndb))
        return COND_REMEDY_SKIP;

    /* Non-destructive: raise/refresh a typed DEPENDENCY blocker naming the
     * remedy. No store is touched, no cursor rewound, no rebuild attempted
     * here — a foreign persisted record shape has no SAFE auto-repair; the
     * fix is the operator-run `z23 app oprindex rebuild`
     * (op_return_index_truncate), which the witness below detects
     * honestly. */
    struct blocker_record r;
    if (blocker_init(&r, OP_RETURN_INDEX_LEGACY_STATE_BLOCKER_ID,
                     "op_return_index", BLOCKER_DEPENDENCY,
                     "persisted op_return_index cursor state is a legacy_v1/"
                     "unknown record this binary refuses to reinterpret as "
                     "v2; run `z23 app oprindex rebuild` to re-derive it "
                     "from block bodies")) {
        r.escape_deadline_secs = 0; /* no auto-escape; witness clears it */
        (void)blocker_set(&r);
    }
    LOG_WARN("condition",
             "[condition:op_return_index_legacy_state] raised blocker %s: "
             "run `z23 app oprindex rebuild` to re-derive the catalog",
             OP_RETURN_INDEX_LEGACY_STATE_BLOCKER_ID);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_op_return_index_legacy_state(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct node_db *ndb = runtime_ndb();
    // honest-witness-ok: op_return_index_state_is_legacy_refused() re-reads
    // the live persisted record every call — it is not a cached/latched
    // decision. A false return here means the state was ACTUALLY rewritten
    // (the operator's rebuild dropped the legacy record and re-derived an
    // EMPTY/V2 one), i.e. real external state moved, not a coincidental
    // clean sample elsewhere.
    bool still_refused = ndb && op_return_index_state_is_legacy_refused(ndb);
    if (!still_refused)
        blocker_clear(OP_RETURN_INDEX_LEGACY_STATE_BLOCKER_ID);
    return !still_refused;
}

static struct condition c_op_return_index_legacy_state = {
    .name = "op_return_index_legacy_state",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 5,
    /* Rearm-forever (peer_floor's / state_auditor_mismatch's posture): a
     * foreign persisted record has no bounded-attempt auto-fix here — after
     * the page ladder, keep nudging every 10 min, unbounded, until the
     * operator runs the rebuild. The episode resets when detect() goes
     * false (the rebuild landed). */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_op_return_index_legacy_state,
    .remedy = remedy_op_return_index_legacy_state,
    .witness = witness_op_return_index_legacy_state,
    .witness_window_secs = 60,
};

void register_op_return_index_legacy_state(void)
{
    (void)condition_register(&c_op_return_index_legacy_state);
}

#ifdef ZCL_TESTING
void op_return_index_legacy_state_test_reset(void)
{
    g_test_ndb = NULL;
    atomic_store(&g_test_remedy_calls, 0);
    blocker_clear(OP_RETURN_INDEX_LEGACY_STATE_BLOCKER_ID);
}

void op_return_index_legacy_state_test_set_node_db(struct node_db *ndb)
{
    g_test_ndb = ndb;
}

int op_return_index_legacy_state_test_remedy(void)
{
    return (int)remedy_op_return_index_legacy_state();
}

bool op_return_index_legacy_state_test_detect(void)
{
    return detect_op_return_index_legacy_state();
}

bool op_return_index_legacy_state_test_witness(void)
{
    return witness_op_return_index_legacy_state(0);
}

int op_return_index_legacy_state_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
