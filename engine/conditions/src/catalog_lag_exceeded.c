/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catalog_lag_exceeded — self-heal condition that fires when an enabled
 * chain-data index (catalog_completeness) falls too far behind the reducer's
 * provable served height H*, and raises a typed named blocker naming the
 * lagging index's backfill as the dependency to advance. */

#include "conditions/catalog_lag_exceeded.h"

#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "storage/catalog_completeness.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Lag past H* (blocks) at which an ENABLED index counts as "exceeded". Chosen
 * generously so a normal catch-up burst (which the backfill services clear on
 * their own) never trips the condition — only a genuinely stuck index does. */
#define CATALOG_LAG_EXCEEDED_BLOCKS 1000

/* Minimum seconds between same-(index,cursor) keep-alive log lines from the
 * remedy. The blocker itself is unthrottled — only the log line is. */
#define CATALOG_LAG_KEEPALIVE_SECS 3600

/* The sustain state: an over-threshold index must survive TWO consecutive
 * detect passes before the symptom is declared, so a single-pass blip during a
 * legitimate reorg/catch-up never fires. g_lagging_name / g_armed_name alias the
 * static row name literals in catalog_completeness.c (stable lifetime), so
 * storing the pointers across passes is safe. */
static _Atomic bool          g_over_last_pass;
static _Atomic(const char *) g_lagging_name;      /* NULL until a firing pass */
static _Atomic int64_t       g_cursor_at_detect;  /* offending cursor at detect */

/* Progress tracker: the over-threshold index observed on the PREVIOUS pass and
 * its cursor then. A from-genesis backfill on a multi-million-block chain sits
 * far behind H* for a long time while it folds forward one bounded batch per
 * tick — that is healthy catch-up, not a stall, and must never raise a
 * dependency blocker that reads as "backfill wedged". Comparing the offending
 * index's cursor against its own previous-pass cursor distinguishes the two: an
 * ADVANCING cursor is normal progress (never fire); only a FROZEN cursor across
 * the poll interval is the genuine stall this condition names. */
static _Atomic(const char *) g_armed_name;        /* over-threshold index, prev pass */
static _Atomic int64_t       g_armed_cursor;      /* that index's cursor, prev pass */

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

/* Build the typed blocker id for an index. */
/* blocker-id: catalog.*.lag_exceeded */
static void lag_blocker_id(const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "catalog.%s.lag_exceeded", name ? name : "unknown");
}

/* Core sustain evaluator over a completeness snapshot. Returns true only on the
 * SECOND consecutive pass in which some enabled index is over the threshold,
 * latching that index (name + cursor) for the remedy/witness. */
static bool eval_over(const struct catalog_index_status *rows, size_t n)
{
    const struct catalog_index_status *w =
        catalog_completeness_worst_over(rows, n, CATALOG_LAG_EXCEEDED_BLOCKS);
    if (!w) {
        atomic_store(&g_over_last_pass, false);
        atomic_store(&g_armed_name, NULL);
        return false;
    }

    const char *armed = atomic_load(&g_armed_name);
    int64_t armed_cursor = atomic_load(&g_armed_cursor);
    bool same_index = armed && w->name && strcmp(armed, w->name) == 0;

    /* Record this pass's observation so the NEXT pass can judge advancement. */
    atomic_store(&g_over_last_pass, true);
    atomic_store(&g_armed_name, w->name);
    atomic_store(&g_armed_cursor, w->cursor);

    /* First over-threshold pass for THIS index: arm, wait to confirm. A single
     * blip during a reorg/catch-up burst never fires. */
    if (!same_index)
        return false;

    /* Same index over threshold two consecutive passes. A healthy backfill
     * ADVANCES its cursor every pass, so a still-advancing index is normal
     * from-genesis catch-up, not a stall — never raise the dependency blocker
     * for it. Only a FROZEN cursor (no advance across the ~5 s poll interval) is
     * the genuine stall this condition exists to name. */
    if (w->cursor > armed_cursor)
        return false;                 /* advancing — healthy backfill */

    /* Frozen — but if the index's own fold guard has already named a
     * STRUCTURAL floor ("<name>.below_snapshot_seed": bodies below the
     * snapshot seed were never downloaded, the forward-only fold can never
     * cross), "stalled and must resume" is a false claim. The structural
     * blocker is the truthful naming; do not pile a misleading one on top.
     * Observed live 2026-07-27: op_return_index frozen at -1 on the
     * snapshot-seeded canonical datadir. */
    {
        char seed_id[BLOCKER_ID_MAX];
        snprintf(seed_id, sizeof(seed_id), "%s.below_snapshot_seed",
                 w->name ? w->name : "unknown");
        if (blocker_exists(seed_id)) {
            /* Suppressed = no stall observed — reset the sustain so a later
             * genuine stall (seed floor crossed, then a real wedge) re-earns
             * its two-pass confirmation instead of firing on one pass. */
            atomic_store(&g_over_last_pass, false);
            atomic_store(&g_armed_name, NULL);
            return false;
        }
    }

    atomic_store(&g_lagging_name, w->name);
    atomic_store(&g_cursor_at_detect, w->cursor);
    return true;                      /* frozen + sustained + over threshold */
}

/* Snapshot the live catalog against the reducer's provable tip. */
static size_t snapshot_live(struct catalog_index_status *rows, size_t cap)
{
    int64_t hstar = (int64_t)reducer_frontier_provable_tip_cached();
    return catalog_completeness_snapshot(rows, cap, hstar);
}

static bool detect_catalog_lag_exceeded(void)
{
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t n = snapshot_live(rows, CATALOG_COMPLETENESS_MAX_INDEXES);
    return eval_over(rows, n);
}

static enum condition_remedy_result remedy_catalog_lag_exceeded(void)
{
    const char *name = atomic_load(&g_lagging_name);
    if (!name)
        return COND_REMEDY_SKIP;

    int64_t cursor = atomic_load(&g_cursor_at_detect);
    char id[BLOCKER_ID_MAX];
    lag_blocker_id(name, id, sizeof(id));

    /* Non-destructive: raise/refresh a typed DEPENDENCY blocker (waiting on that
     * index's own backfill service). No store is touched, no cursor rewound. The
     * blocker names the exact dependency an operator/agent can act on. There is
     * no per-index "kick tick" API to nudge here (the backfill services drive
     * themselves on their own supervised cadence), so the remedy is: name the
     * dependency loudly + let the service advance. */
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "index %s is > %d blocks behind H* and its cursor is NOT advancing "
             "(frozen at %lld across the poll interval); its backfill service is "
             "stalled and must resume",
             name, CATALOG_LAG_EXCEEDED_BLOCKS, (long long)cursor);
    struct blocker_record r;
    if (blocker_init(&r, id, "catalog_completeness", BLOCKER_DEPENDENCY,
                     reason)) {
        r.escape_deadline_secs = 0;   /* no auto-escape; witness clears it */
        (void)blocker_set(&r);
    }

    /* Rearm-forever is the right posture for an external-progress dependency
     * (see the cooldown comment below), but it means this remedy re-raises the
     * SAME blocker every cooldown for as long as the index stays frozen —
     * 540 fires on the canonical node, 2026-07-27. Emit on first raise and on
     * any change of (index, cursor), then one keep-alive per hour carrying the
     * suppressed count, so the line never reads as new while the alarm stays
     * visible and counted. */
    {
        static struct log_throttle t = LOG_THROTTLE_INIT;
        uint64_t key = 1469598103934665603ULL;
        for (const char *p = name; *p; p++)
            key = (key ^ (uint64_t)(unsigned char)*p) * 1099511628211ULL;
        key ^= (uint64_t)cursor * 1099511628211ULL;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&t, key, platform_time_wall_unix(),
                                     CATALOG_LAG_KEEPALIVE_SECS, &reps)) {
            LOG_INFO("condition",
                     "[condition:catalog_lag_exceeded] index=%s cursor=%lld "
                     "raised blocker %s (%llu identical raise(s) suppressed "
                     "since the last line)",
                     name, (long long)cursor, id, (unsigned long long)reps);
        }
    }

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_catalog_lag_exceeded(int64_t target_at_detect)
{
    (void)target_at_detect;
    const char *name = atomic_load(&g_lagging_name);
    if (!name)
        return true;                  /* nothing latched -> nothing to witness */

    /* Honest witness: read the offending index's cursor LIVE against the
     * reducer's provable served height (reducer_frontier_provable_tip_cached —
     * the same H* detect measured against) and require it to have ADVANCED past
     * the cursor recorded at detect. Counting anything else (blocker state, a
     * frozen FSM flag) would let the symptom self-certify cleared while the
     * index stays wedged. */
    int64_t hstar = (int64_t)reducer_frontier_provable_tip_cached();
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t n = catalog_completeness_snapshot(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, hstar);
    int64_t cursor_now = -1;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].name && strcmp(rows[i].name, name) == 0) {
            if (rows[i].enabled)
                cursor_now = rows[i].cursor;
            break;
        }
    }
    /* Superseded naming: if the index's fold guard has since named the
     * STRUCTURAL floor (below_snapshot_seed), the lag blocker's "stalled and
     * must resume" claim is false — the cursor cannot advance across the
     * seed floor. Clear the lag blocker and let the structural one carry the
     * truth. */
    {
        char seed_id[BLOCKER_ID_MAX];
        snprintf(seed_id, sizeof(seed_id), "%s.below_snapshot_seed",
                 name);
        if (blocker_exists(seed_id)) {
            char id[BLOCKER_ID_MAX];
            lag_blocker_id(name, id, sizeof(id));
            blocker_clear(id);
            return true;
        }
    }
    bool advanced = cursor_now > atomic_load(&g_cursor_at_detect);
    if (advanced) {
        char id[BLOCKER_ID_MAX];
        lag_blocker_id(name, id, sizeof(id));
        blocker_clear(id);            /* advanced -> the dependency cleared */
    }
    return advanced;                  /* real cursor movement, nothing else */
}

static struct condition c_catalog_lag_exceeded = {
    .name = "catalog_lag_exceeded",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 5,
    /* Rearm-forever (peer_floor's posture): a chain-data index catching up is
     * an external-progress dependency — after the page ladder, keep nudging
     * every 10 min, unbounded, until the backfill advances. The episode resets
     * when detect() goes false (the index caught back within threshold). */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_catalog_lag_exceeded,
    .remedy = remedy_catalog_lag_exceeded,
    .witness = witness_catalog_lag_exceeded,
    .witness_window_secs = 60,
};

void register_catalog_lag_exceeded(void)
{
    (void)condition_register(&c_catalog_lag_exceeded);
}

/* ── `z23 dumpstate catalog_coverage` ───────────────────────────
 *
 * The one place to answer: "this index is empty — does that mean anything?"
 *
 * catalog_completeness.h has said since it landed that "a later lane wires
 * catalog_completeness_snapshot() into `z23 ops state`". That lane
 * never happened, so the only way to see this data was to infer it from a
 * blocker message, one index at a time. Measured on the canonical node
 * 2026-07-28: op_return_index, zslp_ledger and znam_names all read 0 rows,
 * and there was no surface that said whether any of those zeros was
 * evidence of anything.
 *
 * It lives HERE rather than in a new file because this condition already
 * composes exactly these two reads — the live catalog and H* — to decide
 * whether to fire. Exposing what it sees is a diagnostic OF this condition,
 * not a new concern; a separate owner would be a second reader of one fact.
 *
 * Reentrant-safe, allocation-free, no store writes (catalog_completeness is
 * REPORT ONLY). See CLAUDE.md "Adding state introspection". */
bool catalog_coverage_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    int64_t hstar = (int64_t)reducer_frontier_provable_tip_cached();
    size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                             hstar);

    json_push_kv_int(out, "target_height", hstar);
    json_push_kv_int(out, "index_count", (int64_t)n);

    /* The headline an operator needs first: of the indexes that are actually
     * running, how many have covered everything they can reach? Only those
     * can make an empty table mean anything. */
    int64_t meaningful = 0, enabled = 0;
    for (size_t i = 0; i < n; i++) {
        if (!rows[i].enabled) continue;
        enabled++;
        if (catalog_index_emptiness_is_meaningful(&rows[i])) meaningful++;
    }
    json_push_kv_int(out, "enabled_count", enabled);
    json_push_kv_int(out, "complete_coverage_count", meaningful);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str (&row, "name", rows[i].name ? rows[i].name : "");
        json_push_kv_bool(&row, "enabled", rows[i].enabled);
        json_push_kv_bool(&row, "always_on", rows[i].always_on);
        json_push_kv_int (&row, "cursor", rows[i].cursor);
        json_push_kv_int (&row, "floor", rows[i].floor);
        json_push_kv_int (&row, "target", rows[i].target);
        json_push_kv_int (&row, "lag", rows[i].lag);
        json_push_kv_str (&row, "coverage",
                          catalog_coverage_name(
                              (enum catalog_coverage)rows[i].coverage));
        /* The decisive field. False does NOT mean the index is broken — it
         * means a zero row count from this index is not evidence of
         * anything, so no caller may conclude "nothing happened" from it. */
        json_push_kv_bool(&row, "emptiness_is_meaningful",
                          catalog_index_emptiness_is_meaningful(&rows[i]));
        json_push_back(&arr, &row);
        json_free(&row);
    }
    json_push_kv(out, "indexes", &arr);
    json_free(&arr);
    return true;
}

#ifdef ZCL_TESTING
void catalog_lag_exceeded_test_reset(void)
{
    atomic_store(&g_over_last_pass, false);
    atomic_store(&g_lagging_name, NULL);
    atomic_store(&g_cursor_at_detect, 0);
    atomic_store(&g_armed_name, NULL);
    atomic_store(&g_armed_cursor, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

bool catalog_lag_exceeded_test_feed(const struct catalog_index_status *rows,
                                    size_t n)
{
    return eval_over(rows, n);
}

int catalog_lag_exceeded_test_remedy(void)
{
    return (int)remedy_catalog_lag_exceeded();
}

int catalog_lag_exceeded_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

const char *catalog_lag_exceeded_test_lagging_name(void)
{
    return atomic_load(&g_lagging_name);
}
#endif
