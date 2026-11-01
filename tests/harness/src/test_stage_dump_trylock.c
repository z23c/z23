/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_dump_trylock — the observability-under-load guard for the three
 * tail-stage dump-state views (utxo_apply / script_validate / proof_validate).
 *
 * A2: during catch-up the reducer holds progress_store_tx_lock around each
 * bulk fold. Before this fix the three dumpers took that lock BLOCKING, so an
 * RPC worker calling `dumpstate <stage>` queued behind the fold and, at a few
 * concurrent calls, the node's whole observability front door (dumpstate /
 * status) disappeared exactly while the node was busiest. The fix mirrors
 * reducer_frontier_dump: acquire the lock non-blocking (trylock) and, when the
 * fold owns it, emit {"snapshot_status":"progress_store_busy","retryable":true}
 * and return cleanly instead of blocking. This test proves each dumper takes
 * that busy path — WITHOUT blocking — while another thread holds the lock.
 *
 * A2 amplifier: the utxo_apply dumper's "lowest ok=0 row" query full-scanned
 * ~3.18M rows on a healthy node (no index on ok). utxo_apply_log_ensure_schema
 * now creates a partial index (idx_utxo_apply_log_ok0 ON utxo_apply_log(height)
 * WHERE ok=0); this test asserts EXPLAIN QUERY PLAN uses that index rather than
 * a full table scan.
 *
 * Diagnostics sweep (same theme, other reducer-starvable dumpers): the durable
 * peek in refold_progress_dump_state_json and the failure-summary read behind
 * validate_headers_stage_dump_state_json also took progress_store_tx_lock
 * BLOCKING. Both now trylock and emit a busy status
 * (durable_store_status / failure_summary_status == "progress_store_busy") when
 * the fold owns the lock; validate_headers_log grows a partial ok=0 index that
 * bounds the successful-trylock hold. The cases below prove the busy path
 * (non-blocking + labeled) and the index.
 *
 * Trust-tier sweep: sovereignty_dump_state_json (the dumper behind
 * `z23 status`'s trust-tier surface, event_agent_summary.c ->
 * agent_summary_posture_cache.c) had the SAME blocking-lock hazard — commit
 * cc4de081a's own message names `z23 status` as a victim of this bug
 * class. It now trylocks and, when the fold/importer owns the lock, answers
 * from a process-wide last-known-good trust-tier cache (durable_store_status
 * == "busy_stale_cache" once something has been observed, or
 * "unknown_progress_store_busy" the very first time) instead of blocking.
 * sovereignty_guard_allow() itself stays blocking (enforcement gate) — the
 * dumper's busy branch returns before ever reaching it, so it never inherits
 * that block. The case below proves: (1) busy-before-any-observation reports
 * "unknown_progress_store_busy" with trust_mode "unknown"; (2) a subsequent
 * free call populates the cache with the real trust tier; (3) a second busy
 * call then reports "busy_stale_cache" carrying THAT observed value.
 */

#include "test/test_core.h"

#include "controllers/diagnostics_internal.h"
#include "controllers/sovereignty_controller.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/refold_progress.h"
#include "jobs/script_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "services/chain_state_service.h"
#include "json/json.h"
#include "storage/progress_store.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <unistd.h>

/* Production schema-ensure for utxo_apply_log / validate_headers_log — declared
 * extern (private headers live under engine/jobs/src/), the same pattern
 * test_utxo_root_ladder_tripwire.c uses. */
extern bool utxo_apply_log_ensure_schema(struct sqlite3 *db);
extern bool validate_headers_log_ensure_schema(struct sqlite3 *db);

#define SD_CHECK(name, expr) do {                                 \
    printf("stage_dump_trylock: %s... ", (name));                 \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* ---- lock-holder thread: grabs progress_store_tx_lock and parks ---- */
struct locker {
    _Atomic int locked;   /* set once the lock is held */
    _Atomic int release;  /* main thread sets this to let the holder go */
};

static void *locker_thread(void *arg)
{
    struct locker *lk = (struct locker *)arg;
    progress_store_tx_lock();
    atomic_store(&lk->locked, 1);
    /* Hold until told to release (bounded spin so a stuck test can never wedge
     * the suite forever). */
    for (int i = 0; i < 500000 && !atomic_load(&lk->release); i++) {
        struct timespec ts = { 0, 200000 }; /* 0.2ms */
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    progress_store_tx_unlock();
    return NULL;
}

/* True iff `out` carries the busy/retryable marker AND no SQLite detail. */
static bool is_busy_marker(const struct json_value *out)
{
    const struct json_value *st = json_get(out, "snapshot_status");
    const struct json_value *rt = json_get(out, "retryable");
    if (!st || !rt)
        return false;
    const char *s = json_get_str(st);
    return s && strcmp(s, "progress_store_busy") == 0 && json_get_bool(rt);
}

/* True iff `out[key]` is exactly the string `expected`. */
static bool json_status_is(const struct json_value *out, const char *key,
                           const char *expected)
{
    const struct json_value *v = json_get(out, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, expected) == 0;
}

/* (A2) Each of the 3 dumpers returns the busy marker — fast, non-blocking —
 * while a helper thread holds progress_store_tx_lock. */
static int case_dumpers_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "busy");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("busy: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    /* Create the utxo_apply schema so the non-busy path would have real rows to
     * read; the other two dumpers hit the busy path before any table read. */
    SD_CHECK("busy: utxo_apply schema", db && utxo_apply_log_ensure_schema(db));

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("busy: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    /* Wait until the holder actually owns the lock. */
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    SD_CHECK("busy: locker holds the progress lock", atomic_load(&lk.locked));

    /* Each dumper must return true AND the busy marker, promptly. A blocking
     * lock would deadlock here (the holder only releases after we signal). */
    struct json_value out;

    json_init(&out);
    bool d1 = utxo_apply_dump_state_json(&out, NULL);
    SD_CHECK("busy: utxo_apply dump returns true", d1);
    SD_CHECK("busy: utxo_apply emits progress_store_busy", is_busy_marker(&out));

    json_init(&out);
    bool d2 = script_validate_dump_state_json(&out, NULL);
    SD_CHECK("busy: script_validate dump returns true", d2);
    SD_CHECK("busy: script_validate emits progress_store_busy",
             is_busy_marker(&out));

    json_init(&out);
    bool d3 = proof_validate_dump_state_json(&out, NULL);
    SD_CHECK("busy: proof_validate dump returns true", d3);
    SD_CHECK("busy: proof_validate emits progress_store_busy",
             is_busy_marker(&out));

    /* Release the holder and confirm the SAME dumper now takes the normal path
     * (no busy marker) — proves the trylock succeeds when the lock is free. */
    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    json_init(&out);
    bool d4 = utxo_apply_dump_state_json(&out, NULL);
    SD_CHECK("free: utxo_apply dump returns true", d4);
    SD_CHECK("free: utxo_apply no longer busy", !is_busy_marker(&out));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (A2 amplifier) The lowest-ok=0 query uses the partial index, not a full
 * table scan. */
static int case_utxo_apply_ok0_index_used(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "eqp");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("eqp: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    SD_CHECK("eqp: utxo_apply schema (creates index)",
             db && utxo_apply_log_ensure_schema(db));

    /* A body of healthy ok=1 rows and no ok=0 row — the exact production shape
     * where a full scan would be worst (walks every row to find nothing). */
    progress_store_tx_lock();
    bool ins_ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                      == SQLITE_OK;
    for (int h = 1; ins_ok && h <= 4000; h++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO utxo_apply_log (height,status,ok,spent_count,"
                 "added_count,total_value_delta,applied_at) "
                 "VALUES (%d,'VERIFIED',1,0,0,0,0)", h);
        ins_ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    }
    sqlite3_exec(db, ins_ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    SD_CHECK("eqp: rows inserted", ins_ok);

    /* EXPLAIN QUERY PLAN of the exact dumper query. Column 3 ("detail") must
     * name the partial index; it must NOT be a bare "SCAN utxo_apply_log". */
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool prep = sqlite3_prepare_v2(db,
        "EXPLAIN QUERY PLAN "
        "SELECT height, COALESCE(status,''), "
        "       COALESCE(first_failure_kind,''), first_failure_detail "
        "  FROM utxo_apply_log WHERE ok=0 "
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK;
    SD_CHECK("eqp: prepare EXPLAIN QUERY PLAN", prep);

    bool uses_index = false;
    bool bare_scan = false;
    while (prep && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *detail = sqlite3_column_text(st, 3);
        const char *d = detail ? (const char *)detail : "";
        if (strstr(d, "idx_utxo_apply_log_ok0"))
            uses_index = true;
        /* A full-table scan reads "SCAN utxo_apply_log" with no "USING INDEX". */
        if (strstr(d, "SCAN utxo_apply_log") && !strstr(d, "USING INDEX"))
            bare_scan = true;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();

    SD_CHECK("eqp: query plan uses idx_utxo_apply_log_ok0", uses_index);
    SD_CHECK("eqp: query plan is NOT a bare full-table scan", !bare_scan);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (diagnostics sweep) refold_progress + validate_headers dumps take the busy
 * path — fast, non-blocking, labeled — while a helper thread holds the lock,
 * then the normal path once it is free. */
static int case_diag_dumps_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "diag");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("diag: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    /* validate_headers needs its table so the FREE path has a real read; the
     * busy path returns before any table read. */
    SD_CHECK("diag: validate_headers schema",
             db && validate_headers_log_ensure_schema(db));

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("diag: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    SD_CHECK("diag: locker holds the progress lock", atomic_load(&lk.locked));

    /* A blocking lock would deadlock here (the holder only releases on signal). */
    struct json_value out;

    json_init(&out);
    bool r1 = refold_progress_dump_state_json(&out, NULL);
    SD_CHECK("diag: refold_progress dump returns true", r1);
    SD_CHECK("diag: refold_progress durable_store_status busy",
             json_status_is(&out, "durable_store_status", "progress_store_busy"));

    json_init(&out);
    bool v1 = validate_headers_stage_dump_state_json(&out, NULL);
    SD_CHECK("diag: validate_headers dump returns true", v1);
    SD_CHECK("diag: validate_headers failure_summary_status busy",
             json_status_is(&out, "failure_summary_status",
                            "progress_store_busy"));

    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    json_init(&out);
    bool r2 = refold_progress_dump_state_json(&out, NULL);
    SD_CHECK("free: refold_progress durable_store_status available",
             r2 && json_status_is(&out, "durable_store_status", "available"));

    json_init(&out);
    bool v2 = validate_headers_stage_dump_state_json(&out, NULL);
    SD_CHECK("free: validate_headers failure_summary_status available",
             v2 && json_status_is(&out, "failure_summary_status", "available"));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (diagnostics sweep amplifier) The validate_headers failure-summary ok=0 query
 * uses the partial index, not a full table scan. */
static int case_validate_headers_ok0_index_used(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "vheqp");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("vheqp: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    SD_CHECK("vheqp: validate_headers schema (creates index)",
             db && validate_headers_log_ensure_schema(db));

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool prep = sqlite3_prepare_v2(db,
        "EXPLAIN QUERY PLAN "
        "SELECT height, COALESCE(fail_reason, '') "
        "  FROM validate_headers_log WHERE ok=0 "
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK;
    SD_CHECK("vheqp: prepare EXPLAIN QUERY PLAN", prep);

    bool uses_index = false;
    bool bare_scan = false;
    while (prep && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *detail = sqlite3_column_text(st, 3);
        const char *d = detail ? (const char *)detail : "";
        if (strstr(d, "idx_validate_headers_log_ok0"))
            uses_index = true;
        if (strstr(d, "SCAN validate_headers_log") && !strstr(d, "USING INDEX"))
            bare_scan = true;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();

    SD_CHECK("vheqp: query plan uses idx_validate_headers_log_ok0", uses_index);
    SD_CHECK("vheqp: query plan is NOT a bare full-table scan", !bare_scan);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (trust-tier sweep) sovereignty_dump_state_json takes the busy path — fast,
 * non-blocking, labeled from the last-known-good cache — while a helper
 * thread holds progress_store_tx_lock; the very first busy observation (no
 * cache yet) is labeled distinctly from a later one (cache populated by an
 * intervening free call). */
static int case_sovereignty_dump_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "sov");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("sov: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("sov: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    SD_CHECK("sov: locker holds the progress lock", atomic_load(&lk.locked));

    /* A blocking lock would deadlock here (the holder only releases on
     * signal) — proves the dumper never queues behind the fold. First
     * observation ever: no cache published yet. */
    struct json_value out;
    json_init(&out);
    bool d1 = sovereignty_dump_state_json(&out, NULL);
    SD_CHECK("sov busy(1st): dump returns true", d1);
    SD_CHECK("sov busy(1st): durable_store_status unknown_progress_store_busy",
             json_status_is(&out, "durable_store_status",
                            "unknown_progress_store_busy"));
    SD_CHECK("sov busy(1st): trust_mode unknown",
             json_status_is(&out, "trust_mode", "unknown"));

    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    /* Free path: real trust tier computed and published to the cache. A
     * fresh datadir has no coins_kv migration stamp, so trust_mode == bare
     * (G-SOV part 3's !proven_authority disjunct). */
    json_init(&out);
    bool d2 = sovereignty_dump_state_json(&out, NULL);
    SD_CHECK("sov free: dump returns true", d2);
    SD_CHECK("sov free: durable_store_status available",
             json_status_is(&out, "durable_store_status", "available"));
    SD_CHECK("sov free: trust_mode == bare",
             json_status_is(&out, "trust_mode", "bare"));

    /* Second busy window: the cache now holds the value the free call just
     * observed, so the busy answer must carry THAT value, labeled stale. */
    struct locker lk2 = { 0, 0 };
    rc = pthread_create(&th, NULL, locker_thread, &lk2);
    SD_CHECK("sov: 2nd locker thread starts", rc == 0);
    if (rc == 0) {
        for (int i = 0; i < 500000 && !atomic_load(&lk2.locked); i++) {
            struct timespec ts = { 0, 200000 };
            nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
        }
        SD_CHECK("sov: 2nd locker holds the progress lock",
                 atomic_load(&lk2.locked));

        json_init(&out);
        bool d3 = sovereignty_dump_state_json(&out, NULL);
        SD_CHECK("sov busy(2nd): dump returns true", d3);
        SD_CHECK("sov busy(2nd): durable_store_status busy_stale_cache",
                 json_status_is(&out, "durable_store_status",
                                "busy_stale_cache"));
        SD_CHECK("sov busy(2nd): trust_mode == bare (from cache)",
                 json_status_is(&out, "trust_mode", "bare"));

        atomic_store(&lk2.release, 1);
        pthread_join(th, NULL);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Run the chain-evidence dumper once into a fresh value, report its return,
 * and hand the value to `check`; every value is json_free'd here. */
struct cev_reply {
    bool ret;
    bool busy_marker;       /* the typed busy marker (status + retryable) */
    bool has_status;        /* any snapshot_status key at all */
    bool sync_busy;         /* sync_state == busy_ingest */
    bool frontier_busy;     /* coins_frontier == busy_ingest */
    bool has_sync_state;
    bool has_normal_fields; /* active_tip, publish_state, health_reason */
    bool has_health_reason;
    bool exact_busy;        /* exactly the 4 documented busy fields, nothing else */
    bool any_normal;        /* ANY normal chain_evidence field present */
};

static void cev_dump(const char *key, struct cev_reply *r)
{
    struct json_value out;
    json_init(&out);
    memset(r, 0, sizeof(*r));
    r->ret = diag_chain_evidence_dump_state_json(&out, key);
    r->busy_marker = is_busy_marker(&out);
    r->has_status = json_get(&out, "snapshot_status") != NULL;
    r->sync_busy = json_status_is(&out, "sync_state", "busy_ingest");
    r->frontier_busy = json_status_is(&out, "coins_frontier", "busy_ingest");
    r->has_sync_state = json_get(&out, "sync_state") != NULL;
    r->has_health_reason = json_get(&out, "health_reason") != NULL;
    r->any_normal = json_get(&out, "active_tip") || json_get(&out, "publish_state") ||
                    r->has_health_reason || json_get(&out, "header_tip") ||
                    json_get(&out, "active_tip_hash") ||
                    json_get(&out, "contradiction_reason") ||
                    json_get(&out, "explorer_index_state");
    r->exact_busy = json_size(&out) == 4 && r->busy_marker &&
                    r->sync_busy && r->frontier_busy;
    r->has_normal_fields = json_get(&out, "active_tip") != NULL &&
                           json_get(&out, "publish_state") != NULL &&
                           r->has_health_reason;
    json_free(&out);
}

/* Chain-evidence dumper: while the reducer owns progress_store_tx_lock for
 * an ingest, the dumper answers the typed busy marker instead of queueing
 * behind it (a blocking dumper deadlocks here: the holder releases only on
 * our signal), and answers normally once the lock is free. */
static int case_chain_evidence_busy_ingest(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "cev");
    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("cev: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("cev: locker thread starts", rc == 0);
    if (rc == 0) {
        for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
            struct timespec ts = { 0, 200000 };
            nanosleep(&ts, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
        }
        SD_CHECK("cev: locker holds the progress lock",
                 atomic_load(&lk.locked));
        struct cev_reply r;
        cev_dump(NULL, &r);
        SD_CHECK("cev busy: dump returns true", r.ret);
        SD_CHECK("cev busy: progress_store_busy marker + retryable",
                 r.busy_marker);
        SD_CHECK("cev busy: sync_state busy_ingest", r.sync_busy);
        SD_CHECK("cev busy: coins_frontier busy_ingest", r.frontier_busy);
        SD_CHECK("cev busy: no normal chain_evidence field at all",
                 !r.any_normal);
        SD_CHECK("cev busy: reply is EXACTLY the 4 busy fields",
                 r.exact_busy);
        cev_dump("health_reason", &r);
        SD_CHECK("cev busy: health_reason key: exact busy shape, no normal field",
                 r.ret && r.exact_busy && !r.any_normal);
        atomic_store(&lk.release, 1);
        pthread_join(th, NULL);
        cev_dump(NULL, &r);
        SD_CHECK("cev free: dump returns true", r.ret);
        SD_CHECK("cev free: not the busy marker",
                 !r.busy_marker && !r.has_status && !r.sync_busy &&
                 !r.frontier_busy);
        SD_CHECK("cev free: normal fields present (sync_state, active_tip, "
                 "publish_state, health_reason)",
                 r.has_sync_state && r.has_normal_fields);
        cev_dump("health_reason", &r);
        SD_CHECK("cev free: health_reason key returns normal output",
                 r.ret && !r.busy_marker && r.has_health_reason);
    }
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Deterministic contested-lock cases for the chain-evidence dumper.
 *
 * Production order: an ingest owns progress_store_tx_lock (PS) for a whole
 * ingest and then publishes through the chain-state repository (CSR), so it
 * HOLDS PS and WAITS for CSR; csr_commit_tip / csr_clear_active_tip are the
 * inverse (CSR, then PS).  Thread H below holds csr->lock under a latch until
 * the main thread has seen the dumper answer, so nothing on the dumper's path
 * can ever get CSR while H lives.
 *
 *  - "ingest" scenario: thread I takes PS (latched: ps_held), then blocks on
 *    CSR (held by H).  PS is owned and I is parked on CSR at the moment the
 *    dumper runs.
 *  - "residual" scenario: PS is FREE (no I thread), so the dumper's PS probe
 *    succeeds and the dumper proceeds to the work behind it, exactly the state
 *    an ingest-in-flight leaves after the probe; CSR is held by H.
 *
 * In both, the dumper must answer the exact busy shape within the bound.  A
 * dumper that waits for CSR (the old blocking csr_snapshot) cannot answer
 * until H is released, so the bounded wait expires: the case then FAILS,
 * releases H on its own (so nothing hangs) and joins everything. */
struct contest {
    _Atomic int csr_held;   /* H owns csr->lock */
    _Atomic int ps_held;    /* I owns progress_store_tx_lock */
    _Atomic int i_waiting;  /* I is about to block on csr->lock */
    _Atomic int release_h;  /* main: H may drop csr->lock */
    _Atomic int i_done;
    _Atomic int d_done;
    struct cev_reply plain; /* dump(NULL) */
    struct cev_reply reason;/* dump("health_reason") */
    pthread_mutex_t mu;
    pthread_cond_t cv;
};

static void contest_set(struct contest *c, _Atomic int *flag)
{
    pthread_mutex_lock(&c->mu);
    atomic_store(flag, 1);
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

/* Block (bounded, condvar) until *flag is set; false on timeout. */
static bool contest_wait(struct contest *c, _Atomic int *flag, int secs)
{
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += secs;
    pthread_mutex_lock(&c->mu);
    int wrc = 0;
    while (wrc == 0 && !atomic_load(flag))
        wrc = pthread_cond_timedwait(&c->cv, &c->mu, &dl);
    bool ok = atomic_load(flag) != 0;
    pthread_mutex_unlock(&c->mu);
    return ok;
}

static void *contest_h_thread(void *arg)
{
    struct contest *c = (struct contest *)arg;
    pthread_mutex_lock(&csr_instance()->lock);
    contest_set(c, &c->csr_held);
    contest_wait(c, &c->release_h, 60); /* watchdog: never wedge the suite */
    pthread_mutex_unlock(&csr_instance()->lock);
    return NULL;
}

static void *contest_i_thread(void *arg)
{
    struct contest *c = (struct contest *)arg;
    contest_wait(c, &c->csr_held, 60);
    progress_store_tx_lock();            /* ingest: PS ... */
    contest_set(c, &c->ps_held);
    contest_set(c, &c->i_waiting);
    pthread_mutex_lock(&csr_instance()->lock); /* ... then wants CSR */
    pthread_mutex_unlock(&csr_instance()->lock);
    progress_store_tx_unlock();
    contest_set(c, &c->i_done);
    return NULL;
}

static void *contest_d_thread(void *arg)
{
    struct contest *c = (struct contest *)arg;
    contest_wait(c, &c->csr_held, 60);
    cev_dump(NULL, &c->plain);
    cev_dump("health_reason", &c->reason);
    contest_set(c, &c->d_done);
    return NULL;
}

static void contest_reset(struct contest *c)
{
    atomic_store(&c->csr_held, 0);
    atomic_store(&c->ps_held, 0);
    atomic_store(&c->i_waiting, 0);
    atomic_store(&c->release_h, 0);
    atomic_store(&c->i_done, 0);
    atomic_store(&c->d_done, 0);
    memset(&c->plain, 0, sizeof(c->plain));
    memset(&c->reason, 0, sizeof(c->reason));
}

/* Wait for the latches that define the contested state. */
static int contest_check_latch(struct contest *c, const char *tag,
                               bool ingest_owns_ps)
{
    int failures = 0;
    char name[160];
    bool latched = contest_wait(c, &c->csr_held, 20);
    if (ingest_owns_ps)
        latched = latched && contest_wait(c, &c->ps_held, 20) &&
                  contest_wait(c, &c->i_waiting, 20);
    snprintf(name, sizeof(name),
             "%s: latch reached (H holds CSR%s)", tag,
             ingest_owns_ps ? ", I holds PS and waits for CSR" : ", PS free");
    SD_CHECK(name, latched);
    return failures;
}

static int contest_check_replies(const struct contest *c, const char *tag)
{
    int failures = 0;
    char name[160];
    snprintf(name, sizeof(name), "%s: dump returns true", tag);
    SD_CHECK(name, c->plain.ret && c->reason.ret);
    snprintf(name, sizeof(name),
             "%s: reply is EXACTLY the busy shape (4 fixed fields, no "
             "normal chain_evidence field), both keys", tag);
    SD_CHECK(name, c->plain.exact_busy && c->reason.exact_busy &&
                   !c->plain.any_normal && !c->reason.any_normal);
    return failures;
}

static int contest_run(const char *tag, bool ingest_owns_ps)
{
    int failures = 0;
    static struct contest c = {
        .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };
    char name[160];
    contest_reset(&c);

    pthread_t th, ti, td;
    int rh = pthread_create(&th, NULL, contest_h_thread, &c);
    int ri = ingest_owns_ps ? pthread_create(&ti, NULL, contest_i_thread, &c)
                            : 0;
    SD_CHECK("contest: H and I threads start", rh == 0 && ri == 0);
    if (rh != 0 || ri != 0) {
        atomic_store(&c.release_h, 1);
        return failures + 1;
    }
    failures += contest_check_latch(&c, tag, ingest_owns_ps);
    int rd = pthread_create(&td, NULL, contest_d_thread, &c);
    SD_CHECK("contest: dumper thread starts", rd == 0);

    /* The dumper must answer while H still holds CSR. */
    bool answered = rd == 0 && contest_wait(&c, &c.d_done, 5);
    snprintf(name, sizeof(name),
             "%s: dumper answers within the bound while CSR is held "
             "(never queues behind the ingest)", tag);
    SD_CHECK(name, answered);
    contest_set(&c, &c.release_h);       /* now let the CSR holder go */
    pthread_join(th, NULL);
    if (ingest_owns_ps) {
        SD_CHECK("contest: the ingest completes after CSR is released",
                 contest_wait(&c, &c.i_done, 20));
        pthread_join(ti, NULL);
    }
    if (rd == 0)
        pthread_join(td, NULL);
    if (answered)
        failures += contest_check_replies(&c, tag);
    return failures;
}

static int case_chain_evidence_ingest_contention(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "cevcsr");
    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("cevcsr: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct chain_state_repository *csr = csr_instance();
    bool was_initialized = csr->initialized;
    if (!was_initialized)
        csr_init(csr, NULL, NULL, NULL, NULL, NULL, NULL);

    failures += contest_run("cevcsr ingest (I holds PS, waits CSR)", true);
    failures += contest_run("cevcsr residual (PS free, CSR held)", false);

    if (!was_initialized)
        csr_free(csr);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_stage_dump_trylock(void)
{
    int failures = 0;
    failures += case_dumpers_busy_path();
    failures += case_utxo_apply_ok0_index_used();
    failures += case_diag_dumps_busy_path();
    failures += case_validate_headers_ok0_index_used();
    failures += case_sovereignty_dump_busy_path();
    failures += case_chain_evidence_busy_ingest();
    failures += case_chain_evidence_ingest_contention();
    if (failures == 0)
        printf("test_stage_dump_trylock: ALL PASSED\n");
    else
        printf("test_stage_dump_trylock: %d FAILURE(S)\n", failures);
    return failures;
}
