// one-result-type-ok:fail-loud-predicates
/* E2 override: this module's public surface is pass/refuse PREDICATES
 * (check_pair) and best-effort sweeps. A refusal is not an error to
 * propagate — the reason travels via the typed blocker (PERMANENT,
 * named heights) + EV_OPERATOR_NEEDED + LOG_WARN, which is the whole
 * point of the fail-loud pack. zcl_result would duplicate that channel
 * with a code/message the callers must not branch on. */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * invariant_sentinel — see services/invariant_sentinel.h.
 *
 * Crash-only throughout: a firing check refuses/holds + blocker + page;
 * the process and every other stage keep running. */

#include "services/invariant_sentinel.h"

#include "invariant_sentinel_internal.h"
#include "services/authority_projection_audit.h"
#include "config/runtime.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/stage_helpers.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/utxo_recovery_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "coins/utxo_commitment.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/supervisor.h"
#include "validation/chain_linkage_check.h"

#include <inttypes.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define SWEEP_PERIOD_SECS            ((int64_t)60)
#define COMMITMENT_AUDIT_PERIOD_SECS ((int64_t)3600)
/* I4.5: this many reorg_detected increments in one sweep window at an
 * unmoving tip_finalize cursor = the oscillation wedge signature. */
#define SWEEP_OSCILLATION_THRESHOLD  10

/* ── counters / state (all atomic or lock-guarded; dumped via JSON) ── */
_Atomic uint64_t g_isn_pair_checks_total = 0;
_Atomic uint64_t g_isn_pair_violations_total = 0;
_Atomic uint64_t g_isn_sweeps_total = 0;
_Atomic uint64_t g_isn_sweep_violations_total = 0;
_Atomic int64_t  g_isn_last_sweep_unix = 0;
_Atomic uint64_t g_isn_commitment_audits_total = 0;
_Atomic uint64_t g_isn_commitment_mismatches_total = 0;
_Atomic uint64_t g_isn_commitment_skipped_tip_moved = 0;
_Atomic int64_t  g_isn_last_audit_unix = 0;
_Atomic bool     g_isn_sweep_blocker_active = false;
_Atomic bool     g_isn_audit_blocker_active = false;
/* Consecutive corruption-candidate audits before the diagnostic blocker is
 * raised. The hourly O(n) scan can race a mirror `DELETE FROM utxos`+reinsert
 * rebuild (the torn-scan guard keys on tip cursor + checkpoint and misses that
 * window — the cause of the live 6 false fires), so a single candidate verdict
 * is not trusted; reset on any clean/growth pass. */
_Atomic int      g_isn_commitment_candidate_streak = 0;
#define COMMITMENT_CANDIDATE_STREAK_RAISE 2

pthread_mutex_t g_isn_detail_lock = PTHREAD_MUTEX_INITIALIZER;
char g_isn_last_sweep_detail[200];
char g_isn_last_pair_detail[200];

/* Cross-sweep memory for the oscillation check (single sweep thread). */
uint64_t g_isn_prev_reorg_total = 0;
int64_t  g_isn_prev_tip_finalize_cursor = -1;
bool     g_isn_prev_sweep_valid = false;

/* Two-sweep confirmation memory (single sweep thread): a violation must
 * repeat on the NEXT sweep before it raises blocker/page/HOLD. */
char    g_isn_pending_invariant[16];
int     g_isn_pending_first_bad_h = -1;
bool    g_isn_pending_valid = false;

/* De-storm for the window-sweep "awaiting confirmation" WARN: while wedged it
 * re-prints every 60 s sweep with the SAME invariant/detail. Throttle to
 * first-occurrence + key change + 60 s keepalive (carrying repeat count). */
static struct log_throttle g_unconfirmed_throttle = LOG_THROTTLE_INIT;
static char g_unconfirmed_last_invariant[16], g_unconfirmed_last_detail[200];

/* Frontier memo (single sweep thread): the utxo_apply_log contiguous
 * ok=1 prefix verified by the last CLEAN sweep, and the cursor it was
 * verified under. Lets the next sweep extend the proof in one O(delta)
 * ranged scan instead of re-walking O(cursor - anchor) heights under the
 * global progress lock (which grows with uptime — the trusted anchor only
 * advances at boot/seed re-anchors). Invalidated on any violation or on a
 * cursor rewind (an unwind deleted log rows in the same txn it rewound
 * the cursor, so rows at/below the memo may be gone). */
int32_t g_isn_memo_ua_frontier = -1;
int64_t g_isn_memo_ua_cursor = -1;

#ifdef ZCL_TESTING
struct node_db *g_isn_test_ndb;
#endif

static struct node_db *sentinel_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_isn_test_ndb)
        return g_isn_test_ndb;
#endif
    return app_runtime_node_db();
}

/* Page once per fresh blocker write (the dedup discipline). */
static void sentinel_raise_blocker(const char *id, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void sentinel_raise_blocker(const char *id, const char *fmt, ...)
{
    char reason[BLOCKER_REASON_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);

    struct blocker_record rec;
    if (!blocker_init(&rec, id, "validation_pack", BLOCKER_PERMANENT,
                      reason))
        return;
    if (blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0, "check=%s %s", id, reason);
    LOG_WARN("validation_pack", "[validation_pack] %s: %s", id, reason);
}

/* ── Check 3: authority-pair self-check ─────────────────────────── */

/* resolve(hash) in the blocks projection: 1 = found (*out_h set),
 * 0 = unknown, -1 = read error (treated as unknown by callers — a
 * broken read must not block publishes). */
static int pair_resolve_height(struct node_db *ndb, const uint8_t hash[32],
                               int64_t *out_h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT height FROM blocks WHERE hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("validation_pack",
                 "[validation_pack] pair resolve prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
        return -1; // raw-return-ok:warned-on-previous-line
    }
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    int rc = AR_STEP_ROW_READONLY(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        *out_h = sqlite3_column_int64(st, 0);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

void invariant_sentinel_pair_violation(const char *site, int height,
                                       int64_t resolved_h)
{
    /* Suppress during a -mint-anchor / -refold-staged window. Both reset the
     * staged reducer to genesis and re-walk the frozen prefix while the active
     * chain tip is still the (torn) UPPER tip from the borrowed datadir copy.
     * Every projection-tip write in that window resolves the pair to a
     * DIFFERENT height, so this fires on EVERY pass — pure non-consensus churn
     * that dominates fold log-line volume and hammers
     * the progress.kv lock, starving the genesis..anchor fold. The same
     * refold_in_progress() guard already self-suppresses node_db_catchup and
     * utxo_mirror_sync for the identical reason. Scoped to mint/refold ONLY:
     * on a normal boot the key is absent and this stays fully active. Pure
     * suppression — no consensus value is read or written here. */
    if (refold_in_progress())
        return;

    atomic_fetch_add(&g_isn_pair_violations_total, 1);
    pthread_mutex_lock(&g_isn_detail_lock);
    snprintf(g_isn_last_pair_detail, sizeof(g_isn_last_pair_detail),
             "site=%s published_h=%d resolved_h=%lld",
             site ? site : "?", height, (long long)resolved_h);
    pthread_mutex_unlock(&g_isn_detail_lock);
    sentinel_raise_blocker("authority.pair_self_check",
                           "authority pair mismatch site=%s published_h=%d "
                           "resolved_h=%lld (write refused)",
                           site ? site : "?", height,
                           (long long)resolved_h);
}

bool invariant_sentinel_check_pair(struct node_db *ndb,
                                   const uint8_t hash[32], int height,
                                   const char *site)
{
    if (!hash) {
        LOG_WARN("validation_pack",
                 "[validation_pack] pair check NULL hash site=%s h=%d",
                 site ? site : "?", height);
        return true; /* malformed input is the caller's bug, not a hold */
    }
    if (height < 0)
        return true; /* tip reset (e.g. snapshot import) — not a publish */
    if (!ndb || !ndb->open || !ndb->db)
        return true; /* projection not wired (early boot / unit tests) */
    if (refold_in_progress())
        return true; /* mint/refold: torn UPPER tip vs genesis-up fold — the
                      * pair legitimately resolves to a different height every
                      * pass. Pass it (no read, no refusal, no retry, no spam)
                      * so the coordinator doesn't fight the doomed write. Same
                      * window the catchup/mirror-sync guards already skip; the
                      * key is absent on a normal boot, so this is mint/refold
                      * ONLY. No consensus value is touched. */

    atomic_fetch_add(&g_isn_pair_checks_total, 1);
    int64_t resolved_h = -1;
    int found = pair_resolve_height(ndb, hash, &resolved_h);
    if (found <= 0)
        return true; /* unknown hash (or read error): publishable */
    if (resolved_h == (int64_t)height)
        return true;

    invariant_sentinel_pair_violation(site, height, resolved_h);
    return false;
}

/* ── Check 4: window consistency sweep ──────────────────────────── */

void invariant_sentinel_sweep_evaluate(
    const struct invariant_sweep_inputs *in,
    struct invariant_sweep_verdict *out)
{
    memset(out, 0, sizeof(*out));
    out->first_bad_h = -1;

    /* I4.1 — pipeline ordering, restricted to the PROVEN pairs:
     *   tip_finalize <= utxo_apply   (step_finalize requires
     *                                 next_h < utxo_apply cursor)
     *   utxo_apply <= script_validate (apply consumes a script verdict
     *                                  row, written below that cursor)
     * The body_fetch / validate_headers cursors are deliberately NOT in
     * the ordering set: bodies and headers arrive through MULTIPLE
     * writers (direct P2P connect, legacy mirror, import), so a
     * downstream cursor legitimately overtakes body_fetch's own cursor
     * during live catch-up (script_validate may legitimately run ahead
     * of body_fetch while finalizing forward — not an inversion). */
    const struct { const char *a; int64_t va; const char *b; int64_t vb; }
    order[] = {
        { "tip_finalize", in->cur_tip_finalize,
          "utxo_apply", in->cur_utxo_apply },
        { "utxo_apply", in->cur_utxo_apply,
          "script_validate", in->cur_script_validate },
    };
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        if (order[i].va < 0 || order[i].vb < 0)
            continue; /* unknown cursor: skip the pair */
        if (order[i].va > order[i].vb) {
            out->violated = true;
            snprintf(out->invariant, sizeof(out->invariant), "I4.1");
            out->first_bad_h = (int)order[i].vb;
            snprintf(out->detail, sizeof(out->detail),
                     "cursor ordering: %s=%lld > %s=%lld",
                     order[i].a, (long long)order[i].va,
                     order[i].b, (long long)order[i].vb);
            return;
        }
    }

    /* I4.3 — utxo_apply log contiguity: the contiguous ok=1 prefix must
     * reach cursor-1 (an anchor can never manufacture a rowless hole; a
     * frontier below cursor-1 is a real hole/ok=0 row). */
    if (in->ua_log_frontier_known && in->cur_utxo_apply > 0 &&
        (int64_t)in->ua_log_frontier < in->cur_utxo_apply - 1) {
        out->violated = true;
        snprintf(out->invariant, sizeof(out->invariant), "I4.3");
        out->first_bad_h = in->ua_log_frontier + 1;
        snprintf(out->detail, sizeof(out->detail),
                 "utxo_apply log hole: contiguous ok=1 prefix h=%d but "
                 "cursor=%lld (first hole h=%d)",
                 in->ua_log_frontier, (long long)in->cur_utxo_apply,
                 in->ua_log_frontier + 1);
        return;
    }

    /* I4.4 — Invariant B re-asserted every minute: coins_applied must not
     * exceed utxo_apply's OWN contiguous ok=1 prefix + 1 (the torn-coin
     * shape, measured against the correct authority). */
    if (in->coins_applied_found && in->ua_log_frontier_known &&
        in->coins_applied > in->ua_log_frontier + 1) {
        out->violated = true;
        snprintf(out->invariant, sizeof(out->invariant), "I4.4");
        out->first_bad_h = in->ua_log_frontier + 1;
        snprintf(out->detail, sizeof(out->detail),
                 "coin tear: coins_applied=%d > utxo_apply ok=1 prefix=%d+1",
                 in->coins_applied, in->ua_log_frontier);
        return;
    }

    /* I4.5 — tip_finalize oscillation: many reorg_detected increments in
     * one window while the finalize cursor did not move = the wedge
     * signature. */
    if (in->prev_cur_tip_finalize >= 0 &&
        in->cur_tip_finalize == in->prev_cur_tip_finalize &&
        in->reorg_detected_total >= in->prev_reorg_detected_total &&
        in->reorg_detected_total - in->prev_reorg_detected_total >=
            SWEEP_OSCILLATION_THRESHOLD) {
        out->violated = true;
        snprintf(out->invariant, sizeof(out->invariant), "I4.5");
        out->first_bad_h = (int)in->cur_tip_finalize;
        snprintf(out->detail, sizeof(out->detail),
                 "tip_finalize oscillation: %llu reorg_detected in one "
                 "window at unmoving cursor=%lld",
                 (unsigned long long)(in->reorg_detected_total -
                                      in->prev_reorg_detected_total),
                 (long long)in->cur_tip_finalize);
        return;
    }
}

bool invariant_sentinel_confirm_violation(
    const struct invariant_sweep_verdict *v)
{
    if (!v || !v->violated) {
        g_isn_pending_valid = false;
        g_isn_pending_first_bad_h = -1;
        g_isn_pending_invariant[0] = '\0';
        return false;
    }
    bool confirmed =
        g_isn_pending_valid &&
        strncmp(g_isn_pending_invariant, v->invariant,
                sizeof(g_isn_pending_invariant)) == 0 &&
        g_isn_pending_first_bad_h == v->first_bad_h;
    g_isn_pending_valid = true;
    snprintf(g_isn_pending_invariant, sizeof(g_isn_pending_invariant), "%s",
             v->invariant);
    g_isn_pending_first_bad_h = v->first_bad_h;
    return confirmed;
}

bool invariant_sentinel_sweep_once(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return false; /* store not open yet — not a violation */

    struct invariant_sweep_inputs in;
    memset(&in, 0, sizeof(in));

    /* ATOMIC SNAPSHOT: every input is read under ONE hold of the
     * (recursive) progress_store_tx_lock — the same lock every stage
     * step's BEGIN IMMEDIATE..COMMIT runs under. Without it, a stage
     * commit landing between two reads makes the sweep see state from
     * TWO different transactions: I4.4 has zero slack (the stage
     * co-commits cursor+log+coins, so coins == frontier+1 EXACTLY in
     * steady state) and a single interleaved utxo_apply step false-fired
     * it as a "coin tear" on a healthy catching-up node; an unwind
     * committing between the cursor and frontier reads false-fired
     * I4.3/I4.1 the same way. The in-repo precedent
     * (reducer_frontier_compute_hstar) reads under one lock hold too. */
    progress_store_tx_lock();
    in.cur_tip_finalize =
        (int64_t)stage_cursor_persisted(db, "tip_finalize", "sentinel");
    in.cur_utxo_apply =
        (int64_t)stage_cursor_persisted(db, "utxo_apply", "sentinel");
    in.cur_script_validate =
        (int64_t)stage_cursor_persisted(db, "script_validate", "sentinel");
    in.cur_body_fetch =
        (int64_t)stage_cursor_persisted(db, "body_fetch", "sentinel");
    in.cur_validate_headers =
        (int64_t)stage_cursor_persisted(db, "validate_headers", "sentinel");

    /* Frontier proof: extend the memoized clean frontier in one O(delta)
     * ranged scan when valid; full anchor-rooted walk otherwise. A cursor
     * REWIND invalidates the memo (the unwind deleted rows at/below it). */
    int32_t ua_frontier = 0;
    if (in.cur_utxo_apply > 0) {
        if (g_isn_memo_ua_frontier >= 0 &&
            in.cur_utxo_apply >= g_isn_memo_ua_cursor) {
            in.ua_log_frontier_known =
                reducer_frontier_log_frontier_above(db, "utxo_apply_log",
                                                    "utxo_apply",
                                                    g_isn_memo_ua_frontier,
                                                    &ua_frontier);
        } else {
            in.ua_log_frontier_known =
                reducer_frontier_log_frontier(db, "utxo_apply_log",
                                              "utxo_apply", &ua_frontier);
        }
    }
    in.ua_log_frontier = ua_frontier;

    int32_t coins_applied = 0;
    bool coins_found = false;
    if (coins_kv_get_applied_height(db, &coins_applied, &coins_found)) {
        in.coins_applied = coins_applied;
        in.coins_applied_found = coins_found;
    }
    progress_store_tx_unlock();

    in.reorg_detected_total = tip_finalize_stage_reorg_detected_total();
    if (g_isn_prev_sweep_valid) {
        in.prev_reorg_detected_total = g_isn_prev_reorg_total;
        in.prev_cur_tip_finalize = g_isn_prev_tip_finalize_cursor;
    } else {
        in.prev_reorg_detected_total = in.reorg_detected_total;
        in.prev_cur_tip_finalize = -1;
    }
    g_isn_prev_reorg_total = in.reorg_detected_total;
    g_isn_prev_tip_finalize_cursor = in.cur_tip_finalize;
    g_isn_prev_sweep_valid = true;

    struct invariant_sweep_verdict v;
    invariant_sentinel_sweep_evaluate(&in, &v);

    atomic_fetch_add(&g_isn_sweeps_total, 1);
    atomic_store(&g_isn_last_sweep_unix, platform_time_wall_unix());

    if (v.violated) {
        /* Violations invalidate the frontier memo: re-prove from the
         * anchor until the state is clean again. */
        g_isn_memo_ua_frontier = -1;
        g_isn_memo_ua_cursor = -1;
        atomic_fetch_add(&g_isn_sweep_violations_total, 1);
        pthread_mutex_lock(&g_isn_detail_lock);
        snprintf(g_isn_last_sweep_detail, sizeof(g_isn_last_sweep_detail),
                 "%.32s %.160s", v.invariant, v.detail);
        pthread_mutex_unlock(&g_isn_detail_lock);
        /* TWO-SWEEP CONFIRMATION before blocker/page/HOLD: there is one
         * durably-committed window where cursors disagree BY DESIGN — a
         * reorg unwind commits {utxo_apply cursor + log deletes + coins
         * rewind} in one txn while tip_finalize's cursor is rewound by a
         * LATER separate txn at the top of its next step, so a sweep
         * sampling between them reads a real I4.1-shaped state on a
         * healthy node. That window is ms-scale; a REAL wedge persists
         * across consecutive 60 s sweeps at the same named heights. */
        if (invariant_sentinel_confirm_violation(&v)) {
            atomic_store(&g_isn_sweep_blocker_active, true);
            sentinel_raise_blocker("window.consistency", "%s %s",
                                   v.invariant, v.detail);
            if (v.first_bad_h >= 0)
                chain_linkage_hold_set("window_sweep", v.first_bad_h,
                                       v.detail);
        } else {
            bool changed = strcmp(v.invariant, g_unconfirmed_last_invariant)
                        || strcmp(v.detail, g_unconfirmed_last_detail);
            snprintf(g_unconfirmed_last_invariant,
                     sizeof g_unconfirmed_last_invariant, "%s", v.invariant);
            snprintf(g_unconfirmed_last_detail,
                     sizeof g_unconfirmed_last_detail, "%s", v.detail);
            uint64_t reps = 0;
            if (log_throttle_should_emit_changed(&g_unconfirmed_throttle,
                    changed, platform_time_wall_unix(), 60, &reps))
                LOG_WARN("validation_pack",
                         "[validation_pack] window sweep observed %s %s — "
                         "awaiting confirmation on the next sweep (reorg "
                         "unwind window / single-sweep transient) repeats=%llu",
                         v.invariant, v.detail, (unsigned long long)reps);
        }
    } else {
        (void)invariant_sentinel_confirm_violation(&v); /* reset pending */
        if (in.ua_log_frontier_known) {
            g_isn_memo_ua_frontier = in.ua_log_frontier;
            g_isn_memo_ua_cursor = in.cur_utxo_apply;
        }
        if (atomic_load(&g_isn_sweep_blocker_active)) {
            /* Self-clearing: a clean sweep releases the hold — repair
             * jobs may legitimately fix holes; crash-only and
             * recovery-friendly. */
            atomic_store(&g_isn_sweep_blocker_active, false);
            blocker_clear("window.consistency");
            chain_linkage_hold_clear("window_sweep");
            LOG_INFO("validation_pack",
                     "[validation_pack] window.consistency cleared by a "
                     "clean sweep");
        }
    }
    return true;
}

/* ── Check 5: commitment audit (hourly) ─────────────────────────── */

/* 16 per-txid-prefix range counts: localizes WHERE the set diverged (a
 * keyspace-tail truncation names itself as zeroed high ranges). */
static void audit_log_range_counts(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT substr(hex(txid),1,1), COUNT(*) FROM utxos GROUP BY 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("validation_pack",
                 "[validation_pack] range count prepare failed: %s",
                 sqlite3_errmsg(db));
        return;
    }
    char line[400];
    size_t off = 0;
    line[0] = '\0';
    while (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        const unsigned char *nib = sqlite3_column_text(st, 0);
        int64_t cnt = sqlite3_column_int64(st, 1);
        int n = snprintf(line + off, sizeof(line) - off, "%s%s=%lld",
                         off ? " " : "", nib ? (const char *)nib : "?",
                         (long long)cnt);
        if (n < 0 || (size_t)n >= sizeof(line) - off)
            break;
        off += (size_t)n;
    }
    sqlite3_finalize(st);
    LOG_WARN("validation_pack",
             "[validation_pack] utxos per-txid-prefix range counts: %s",
             line);
}

/* Release a latched commitment-audit diagnostic (blocker + any residual
 * chain_linkage hold) and reset the page-once gate. NO node.db access — safe to
 * call from any thread, including the condition-engine owner. Idempotent: a
 * no-op when nothing is latched. */
static void audit_clear_latched_blocker(const char *why)
{
    if (!atomic_load(&g_isn_audit_blocker_active))
        return;
    atomic_store(&g_isn_audit_blocker_active, false);
    blocker_clear("coins.commitment_spot_check");
    chain_linkage_hold_clear("commitment_audit");
    LOG_INFO("validation_pack",
             "[validation_pack] coins.commitment_spot_check cleared by %s",
             why ? why : "a clean audit");
}

bool invariant_sentinel_commitment_audit_once(void)
{
    struct node_db *ndb = sentinel_ndb();
    if (!ndb || !ndb->open || !ndb->db)
        return false;

    /* Bulk-import freeze: while g_utxo_commitment_skip is set the
     * incremental commitment (and therefore the co-committed checkpoint)
     * is deliberately frozen-stale against an advancing set. Auditing
     * against it would only ever classify staleness — skip the pass. */
    if (atomic_load_explicit(&g_utxo_commitment_skip, memory_order_relaxed))
        return true;

    struct utxo_commitment saved, computed;
    memset(&saved, 0, sizeof(saved));
    memset(&computed, 0, sizeof(computed));
    if (!utxo_commitment_load_checkpoint(ndb->db, &saved))
        return false; /* raw-return-ok:no checkpoint to audit against — skip */

    /* Torn-scan discard, keyed to the table's ACTUAL writer: every utxos
     * flush co-commits a fresh checkpoint in the same txn, so a stored
     * checkpoint that CHANGED during the O(n) scan proves the set moved
     * under us — the computed digest mixes two states. The tip cursor
     * check is kept as a cheap second witness. */
    int64_t tip_before = tip_finalize_stage_last_height();
    utxo_commitment_compute_db(ndb->db, &computed);
    int64_t tip_after = tip_finalize_stage_last_height();
    struct utxo_commitment saved_after;
    memset(&saved_after, 0, sizeof(saved_after));
    bool ckpt_after_ok =
        utxo_commitment_load_checkpoint(ndb->db, &saved_after);

    atomic_fetch_add(&g_isn_commitment_audits_total, 1);
    atomic_store(&g_isn_last_audit_unix, platform_time_wall_unix());

    if (tip_before != tip_after || !ckpt_after_ok ||
        !utxo_commitment_equal(&saved, &saved_after)) {
        atomic_fetch_add(&g_isn_commitment_skipped_tip_moved, 1);
        return true; /* discarded, no verdict */
    }

    if (utxo_commitment_equal(&saved, &computed)) {
        atomic_store(&g_isn_commitment_candidate_streak, 0);
        audit_clear_latched_blocker("a clean audit");
        return true;
    }

    /* Shared stale-vs-corruption classifier: growth past the checkpoint =
     * stale (legitimate); shrink or equal-count-different-hash = corruption
     * candidate. GROWTH is the EXPECTED steady state — the checkpoint is a
     * derived cache written only out-of-band (boot/recovery), never
     * co-committed by the live coins_kv mirror writer, so the `utxos`
     * projection legitimately runs AHEAD of it during forward sync. Resync the
     * checkpoint to the recomputed digest (the same refresh the boot path
     * performs) so it tracks the set, and release any blocker latched during an
     * earlier transient — the only OTHER clear is gated on EXACT equality, which
     * a perpetually-advancing set may never hit, so a transient latch would
     * otherwise strand the chain forever (the live 3164076 wedge). */
    if (!utxo_recovery_xor_mismatch_is_corruption_candidate(
            saved.count, computed.count)) {
        atomic_store(&g_isn_commitment_candidate_streak, 0);
        (void)utxo_commitment_resync_from_db(ndb->db, NULL);
        audit_clear_latched_blocker("a growth/stale resync");
        return true;
    }

    /* Corruption candidate (computed <= saved). Require
     * COMMITMENT_CANDIDATE_STREAK_RAISE consecutive candidate verdicts before
     * raising, to swallow the mirror-rebuild torn-scan race the guard above
     * misses (the live 6 false fires). */
    if (atomic_fetch_add(&g_isn_commitment_candidate_streak, 1) + 1
            < COMMITMENT_CANDIDATE_STREAK_RAISE)
        return true; /* not yet persistent — wait for the next audit */

    atomic_fetch_add(&g_isn_commitment_mismatches_total, 1);
    atomic_store(&g_isn_audit_blocker_active, true);
    audit_log_range_counts(ndb->db);
    sentinel_raise_blocker(
        "coins.commitment_spot_check",
        "XOR commitment mismatch vs checkpoint: count_expected=%llu "
        "count_got=%llu (corruption candidate; range counts logged)",
        (unsigned long long)saved.count,
        (unsigned long long)computed.count);
    /* Decoupled from chain_linkage: the `utxos` table is a
     * REBUILDABLE projection of the coins_kv authority — NOT the authority — and
     * this audit compares it only to a frozen out-of-band self-checkpoint, so it
     * cannot evidence coin-set-vs-chain corruption. A projection mismatch must
     * NEVER refuse a PoW-proven tip move: doing so would make tip_finalize roll
     * back an already-inserted finalized row via JOB_FATAL, pinning H* with no
     * auto-remedy. The consensus coin gate is
     * utxo_apply's per-block ok-verdict (tip_finalize upstream.ok), untouched.
     * The non-fatal blocker above is owned by state_window_inconsistent, which
     * re-derives the projection from the coins_kv authority and clears it — it
     * never freezes forward sync. */
    return true;
}

/* Auto-terminating owner hook (state_window_inconsistent): release a latched
 * commitment-audit diagnostic so a benign projection skew never pages forever.
 * NO node.db access — the checkpoint resync runs on the audit thread (the
 * growth branch) and the projection rebuild on the mirror thread; this only
 * clears the operator-facing signal. */
void invariant_sentinel_clear_commitment_blocker(void)
{
    atomic_store(&g_isn_commitment_candidate_streak, 0);
    audit_clear_latched_blocker("the auto-terminating owner");
}

/* ── supervisor children ────────────────────────────────────────── */

static struct liveness_contract g_sweep_contract;
static struct liveness_contract g_audit_contract;
static _Atomic supervisor_child_id g_sweep_id = SUPERVISOR_INVALID_ID;
static _Atomic supervisor_child_id g_audit_id = SUPERVISOR_INVALID_ID;
static _Atomic int64_t g_sweep_ticks = 0;
static _Atomic int64_t g_audit_ticks = 0;

static void sweep_tick(struct liveness_contract *c)
{
    (void)c;
    (void)invariant_sentinel_sweep_once();
    int64_t marker = atomic_fetch_add(&g_sweep_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_sweep_id), marker);
    supervisor_tick(atomic_load(&g_sweep_id));
}

static void audit_tick(struct liveness_contract *c)
{
    (void)c;
    (void)invariant_sentinel_commitment_audit_once();
    int64_t marker = atomic_fetch_add(&g_audit_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_audit_id), marker);
    supervisor_tick(atomic_load(&g_audit_id));
}

void invariant_sentinel_register(void)
{
    supervisor_domains_init();
    /* Sibling fail-loud check in the same validation-pack family: the redundant
     * authority(coins)-vs-projection(utxos) SHA3 cross-check (its own hourly
     * chain-domain child; raises the validation_pack-owned blocker
     * authority_projection_divergence). */
    ap_audit_register();
    if (atomic_load(&g_sweep_id) == SUPERVISOR_INVALID_ID) {
        liveness_contract_init(&g_sweep_contract, "chain.invariant_sweep");
        atomic_store(&g_sweep_contract.period_secs, SWEEP_PERIOD_SECS);
        atomic_store(&g_sweep_contract.deadline_secs, (int64_t)0);
        atomic_store(&g_sweep_contract.progress_max_quiet_us, (int64_t)0);
        g_sweep_contract.on_tick = sweep_tick;
        g_sweep_contract.on_stall = NULL;
        supervisor_child_id id =
            supervisor_register_in_domain(g_chain_sup, &g_sweep_contract);
        atomic_store(&g_sweep_id, id);
        if (id == SUPERVISOR_INVALID_ID)
            LOG_WARN("validation_pack",
                     "[validation_pack] sweep register failed");
    }
    if (atomic_load(&g_audit_id) == SUPERVISOR_INVALID_ID) {
        liveness_contract_init(&g_audit_contract, "coins.commitment_audit");
        atomic_store(&g_audit_contract.period_secs,
                     COMMITMENT_AUDIT_PERIOD_SECS);
        atomic_store(&g_audit_contract.deadline_secs, (int64_t)0);
        atomic_store(&g_audit_contract.progress_max_quiet_us, (int64_t)0);
        g_audit_contract.on_tick = audit_tick;
        g_audit_contract.on_stall = NULL;
        supervisor_child_id id =
            supervisor_register_in_domain(g_chain_sup, &g_audit_contract);
        atomic_store(&g_audit_id, id);
        if (id == SUPERVISOR_INVALID_ID)
            LOG_WARN("validation_pack",
                     "[validation_pack] audit register failed");
    }
}
