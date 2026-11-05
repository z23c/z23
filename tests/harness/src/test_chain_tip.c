/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "services/chain_tip.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "event/event.h"

#include "config/db_service.h"
#include "config/runtime.h"
#include "core/uint256.h"
#include "models/database.h"
#include "validation/chainstate.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* What the last EV_TIP_UPDATED / EV_CHAIN_TIP_COMMIT carried: the peer id and
 * the exact payload text. */
struct tip_capture {
    int upd_n, com_n;
    uint32_t upd_peer, com_peer;
    char upd[160], com[160];
};

static void capture_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    struct tip_capture *c = ctx;
    if (type == EV_TIP_UPDATED) {
        c->upd_n++;
        c->upd_peer = peer_id;
        snprintf(c->upd, sizeof(c->upd), "%.*s", (int)payload_len,
                 (const char *)payload);
    } else if (type == EV_CHAIN_TIP_COMMIT) {
        c->com_n++;
        c->com_peer = peer_id;
        snprintf(c->com, sizeof(c->com), "%.*s", (int)payload_len,
                 (const char *)payload);
    }
}

static int g_tip_updated_count;
static int g_tip_commit_count;
static int g_last_tip_height;

static void observer(enum event_type type, uint32_t peer_id,
                     const void *payload, uint32_t payload_len, void *ctx)
{
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    if (type == EV_TIP_UPDATED) g_tip_updated_count++;
    if (type == EV_CHAIN_TIP_COMMIT) g_tip_commit_count++;
}

/* Every enumerator maps to its own name, and anything outside the table is
 * "unknown": UNSPECIFIED (0) is the lower boundary that must NOT be
 * rejected, one past the last enumerator and a huge value the upper ones. */
static int check_source_names(void)
{
    static const char *const want[] = {
        "unspecified", "connect", "disconnect", "snapshot", "restore",
        "boot_repair", "p2p_repair", "utxo_repair", "test",
    };
    int failures = 0;
    printf("tip_source_name: table boundaries... ");
    bool ok = true;
    for (int i = 0; i <= (int)TIP_FROM_TEST; i++)
        ok = ok && strcmp(tip_source_name((enum tip_source)i), want[i]) == 0;
    ok = ok && strcmp(tip_source_name((enum tip_source)-1), "unknown") == 0;
    ok = ok && strcmp(tip_source_name((enum tip_source)(TIP_FROM_TEST + 1)),
                      "unknown") == 0;
    ok = ok && strcmp(tip_source_name((enum tip_source)1000000), "unknown") == 0;
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

/* A NULL main_state is refused with code -1 and a message naming the source
 * and the reason (a NULL reason prints as empty). */
static int check_null_ms_refusal(void)
{
    int failures = 0;
    struct zcl_result r = chain_set_active_tip(NULL, NULL, TIP_FROM_SNAPSHOT,
                                               "why");
    printf("chain_set_active_tip: NULL ms code and message... ");
    if (!r.ok && r.code == -1 &&
        strstr(r.message, "NULL main_state src=snapshot reason=why") != NULL)
        printf("OK\n");
    else { printf("FAIL (code=%d msg='%s')\n", r.code, r.message); failures++; }
    return failures;
}

/* Continuation of check_event_payloads: the clear event and a tip without a
 * hash, on the state the set case (height 5) left behind. */
static int check_event_clear_and_hashless(struct main_state *ms,
                                          struct block_index *bi,
                                          struct tip_capture *cap)
{
    int failures = 0;
    char want_com[160];
    int from1 = active_chain_height(&ms->chain_active);
    cap->com_peer = 0xdeadu;
    bool ok2 = chain_set_active_tip(ms, NULL, TIP_FROM_TEST, NULL).ok;
    snprintf(want_com, sizeof(want_com), "from=%d to=-1 reason=", from1);
    printf("chain_set_active_tip: clear payload and peer id... ");
    if (ok2 && from1 == 5 && cap->com_n == 2 && cap->upd_n == 1 &&
        strcmp(cap->com, want_com) == 0 && cap->com_peer == 0)
        printf("OK\n");
    else {
        printf("FAIL (ok=%d from=%d com='%s')\n", ok2, from1, cap->com);
        failures++;
    }

    bi->phashBlock = NULL;
    bool ok3 = chain_set_active_tip(ms, bi, TIP_FROM_SNAPSHOT, "nohash").ok;
    printf("chain_set_active_tip: hashless tip payload... ");
    if (ok3 && cap->upd_n == 2 &&
        strcmp(cap->upd, "h=5 hash=(no-hash) src=snapshot") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d upd='%s')\n", ok3, cap->upd); failures++; }
    return failures;
}

/* The exact event text and peer id for a set, a clear and a hashless tip.
 * The 32-character hash prefix is compared against uint256_get_hex of a hash
 * with a distinct byte in every position. */
static int check_event_payloads(void)
{
    int failures = 0;
    struct tip_capture cap;
    memset(&cap, 0, sizeof(cap));
    cap.upd_peer = cap.com_peer = 0xdeadu;
    event_observe(EV_TIP_UPDATED, capture_observer, &cap);
    event_observe(EV_CHAIN_TIP_COMMIT, capture_observer, &cap);

    struct main_state ms;
    main_state_init(&ms);
    struct block_index bi;
    block_index_init(&bi);
    bi.nHeight = 5;
    struct uint256 hh;
    for (int i = 0; i < 32; i++) hh.data[i] = (uint8_t)(i + 1);
    bi.phashBlock = &hh;
    char full[65];
    uint256_get_hex(&hh, full);

    int from0 = active_chain_height(&ms.chain_active);
    bool ok1 = chain_set_active_tip(&ms, &bi, TIP_FROM_CONNECT, "set_h5").ok;
    char want_upd[160], want_com[160];
    snprintf(want_upd, sizeof(want_upd), "h=5 hash=%.32s src=connect", full);
    snprintf(want_com, sizeof(want_com), "from=%d to=5 reason=set_h5", from0);
    printf("chain_set_active_tip: set payloads and peer ids... ");
    if (ok1 && cap.upd_n == 1 && cap.com_n == 1 &&
        strcmp(cap.upd, want_upd) == 0 && strcmp(cap.com, want_com) == 0 &&
        cap.upd_peer == 0 && cap.com_peer == 0)
        printf("OK\n");
    else {
        printf("FAIL (ok=%d upd='%s' com='%s')\n", ok1, cap.upd, cap.com);
        failures++;
    }

    failures += check_event_clear_and_hashless(&ms, &bi, &cap);
    main_state_free(&ms);
    return failures;
}

#if !defined(_WIN32)
/* Redirect stdout into an anonymous file for the duration of fn(). */
static bool capture_stdout(void (*fn)(void *), void *arg, char *out, size_t n)
{
    FILE *tmp = tmpfile();
    if (!tmp) return false;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0 || dup2(fileno(tmp), STDOUT_FILENO) < 0) {
        if (saved >= 0) close(saved);
        fclose(tmp);
        return false;
    }
    fn(arg);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    rewind(tmp);
    size_t got = fread(out, 1, n - 1, tmp);
    out[got] = '\0';
    fclose(tmp);
    return true;
}

struct log_args { struct main_state *ms; struct block_index *bi; };

static void log_set_and_clear(void *p)
{
    struct log_args *a = p;
    (void)chain_set_active_tip(a->ms, a->bi, TIP_FROM_TEST, "log_set");
    (void)chain_set_active_tip(a->ms, NULL, TIP_FROM_TEST, "log_clear");
}

static int check_stdout_lines(void)
{
    int failures = 0;
    struct main_state ms;
    main_state_init(&ms);
    struct block_index bi;
    block_index_init(&bi);
    bi.nHeight = 5;
    struct uint256 hh;
    for (int i = 0; i < 32; i++) hh.data[i] = (uint8_t)(0x40 + i);
    bi.phashBlock = &hh;
    char full[65], want_set[200];
    uint256_get_hex(&hh, full);
    snprintf(want_set, sizeof(want_set),
             "[tip] h=5 hash=%.32s src=test reason=log_set\n", full);

    struct log_args args = { &ms, &bi };
    char out[1024];
    bool captured = capture_stdout(log_set_and_clear, &args, out, sizeof(out));
    printf("chain_set_active_tip: stdout [tip] lines... ");
    if (captured && strstr(out, want_set) != NULL &&
        strstr(out, "[tip] CLEARED (from h=5) src=test reason=log_clear\n"))
        printf("OK\n");
    else { printf("FAIL (captured=%d out='%s')\n", captured, out); failures++; }
    main_state_free(&ms);
    return failures;
}
#else
static int check_stdout_lines(void) { return 0; }
#endif

/* Pages this connection has written out of its cache so far. Only a cache
 * flush (the barrier) moves it while the probe transaction stays open. */
static int pages_written(sqlite3 *db)
{
    int cur = 0, hi = 0;
    if (sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_WRITE, &cur, &hi, 0) !=
        SQLITE_OK)
        return -1;
    return cur;
}

struct barrier_fx {
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context rt;
    char dir[256], path[320];
    bool open;
};

static bool barrier_fx_open(struct barrier_fx *f)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), "chain_tip", "barrier");
    snprintf(f->path, sizeof(f->path), "%s/node.db", f->dir);
    if (!node_db_open(&f->ndb, f->path)) return false;
    f->open = true;
    db_service_init(&f->svc);
    if (!db_service_attach(&f->svc, &f->ndb) ||
        !db_service_start_test_worker(&f->svc))
        return false;
    f->rt.db_service = &f->svc;
    app_runtime_set_current(&f->rt);
    /* Keep the dirty pages in the cache so only the barrier can write them,
     * and hold one write transaction open across the whole run. */
    return sqlite3_exec(f->ndb.db, "PRAGMA cache_size=-200000;", NULL, NULL,
                        NULL) == SQLITE_OK &&
           sqlite3_exec(f->ndb.db,
                        "CREATE TABLE IF NOT EXISTS tip_probe(b BLOB);"
                        "BEGIN IMMEDIATE;", NULL, NULL, NULL) == SQLITE_OK;
}

static void barrier_fx_close(struct barrier_fx *f)
{
    app_runtime_set_current(NULL);
    if (f->open) sqlite3_exec(f->ndb.db, "ROLLBACK;", NULL, NULL, NULL);
    db_service_stop(&f->svc);
    if (f->open) node_db_close(&f->ndb);
    test_cleanup_tmpdir(f->dir);
}

/* Dirty a fresh page, set the tip with the best header `gap` blocks ahead,
 * and report whether the call pushed bytes to disk (the cache flush). */
static bool barrier_step(struct barrier_fx *f, struct main_state *ms,
                         struct block_index *tip)
{
    int before;
    if (sqlite3_exec(f->ndb.db,
                     "INSERT INTO tip_probe VALUES(zeroblob(3000));", NULL,
                     NULL, NULL) != SQLITE_OK)
        return false;
    before = pages_written(f->ndb.db);
    bool ok = chain_set_active_tip(ms, tip, TIP_FROM_TEST, "barrier").ok;
    int after = pages_written(f->ndb.db);
    (void)chain_set_active_tip(ms, NULL, TIP_FROM_TEST, "barrier_clear");
    return ok && after > before;
}

/* Run `n` steps and return a bitmask-free summary: the flush count, plus the
 * index of the first and last flush, through the out parameters. */
static int barrier_run(struct barrier_fx *f, int gap, int n, int *first,
                       int *second, int *last)
{
    struct main_state ms;
    main_state_init(&ms);
    struct block_index tip, best;
    block_index_init(&tip);
    block_index_init(&best);
    tip.nHeight = 5;
    best.nHeight = 5 + gap;
    ms.pindex_best_header = &best;
    int count = 0;
    *first = *second = *last = -1;
    for (int i = 0; i < n; i++) {
        if (!barrier_step(f, &ms, &tip)) continue;
        if (count == 0) *first = i;
        else if (count == 1) *second = i;
        *last = i;
        count++;
    }
    ms.pindex_best_header = NULL;
    main_state_free(&ms);
    return count;
}

/* At a gap of 1000 or less every commit flushes; past it only every
 * CATCHUP_FSYNC_EVERY-th (100th) call does, so the flushes are exactly 100
 * calls apart. */
static int check_fsync_barrier(void)
{
    int failures = 0;
    struct barrier_fx fx;
    printf("chain_set_active_tip: fsync barrier cadence... ");
    if (!barrier_fx_open(&fx)) {
        printf("FAIL (fixture)\n");
        barrier_fx_close(&fx);
        return 1;
    }
    int a, b, c;
    int steady = barrier_run(&fx, 0, 6, &a, &b, &c);
    int edge = barrier_run(&fx, 1000, 6, &a, &b, &c);
    int ahead = barrier_run(&fx, -7, 4, &a, &b, &c);
    int sparse = barrier_run(&fx, 1001, 230, &a, &b, &c);
    int sparse_gap = (sparse >= 2) ? b - a : -1;
    if (steady == 6 && edge == 6 && ahead == 4 && sparse >= 2 &&
        sparse <= 3 && sparse_gap == 100 && (sparse == 2 || c - b == 100))
        printf("OK\n");
    else {
        printf("FAIL (steady=%d edge=%d ahead=%d sparse=%d gap=%d)\n", steady,
               edge, ahead, sparse, sparse_gap);
        failures++;
    }
    barrier_fx_close(&fx);
    return failures;
}

int test_chain_tip(void)
{
    int failures = 0;

    event_log_init();
    event_clear_observers(EV_TIP_UPDATED);
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    event_observe(EV_TIP_UPDATED, observer, NULL);
    event_observe(EV_CHAIN_TIP_COMMIT, observer, NULL);
    g_tip_updated_count = 0;
    g_tip_commit_count = 0;
    g_last_tip_height = -1;

    printf("tip_source_name: known sources... ");
    {
        if (strcmp(tip_source_name(TIP_FROM_CONNECT), "connect") == 0 &&
            strcmp(tip_source_name(TIP_FROM_SNAPSHOT), "snapshot") == 0 &&
            strcmp(tip_source_name(TIP_FROM_TEST), "test") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chain_set_active_tip: NULL ms returns false... ");
    {
        bool r = chain_set_active_tip(NULL, NULL, TIP_FROM_TEST, "null_ms").ok;
        if (!r) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chain_set_active_tip: set + clear emits events... ");
    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 5;
        struct uint256 hh = {0};
        hh.data[0] = 0xab;
        bi.phashBlock = &hh;

        int updated_before = g_tip_updated_count;
        int commit_before = g_tip_commit_count;
        bool ok1 = chain_set_active_tip(&ms, &bi,
                                        TIP_FROM_TEST, "set_h5").ok;
        bool ok2 = chain_set_active_tip(&ms, NULL,
                                        TIP_FROM_TEST, "clear").ok;

        if (ok1 && ok2 &&
            g_tip_updated_count == updated_before + 1 &&
            g_tip_commit_count == commit_before + 2)
            printf("OK\n");
        else {
            printf("FAIL (ok1=%d ok2=%d updated_delta=%d commit_delta=%d)\n",
                   ok1, ok2,
                   g_tip_updated_count - updated_before,
                   g_tip_commit_count - commit_before);
            failures++;
        }

        main_state_free(&ms);
    }

    event_clear_observers(EV_TIP_UPDATED);
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    failures += check_source_names();
    failures += check_null_ms_refusal();
    failures += check_event_payloads();
    /* check_event_payloads captures into a stack frame; drop its observers. */
    event_clear_observers(EV_TIP_UPDATED);
    event_clear_observers(EV_CHAIN_TIP_COMMIT);
    failures += check_stdout_lines();
    failures += check_fsync_barrier();
    return failures;
}
