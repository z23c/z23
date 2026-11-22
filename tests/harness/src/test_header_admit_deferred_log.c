/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_header_admit_deferred_log - the header_admit drain runs under the
 * reducer's batched durability scope, so the per-header EV_BLOCK_HEADER event
 * costs one pre-commit fdatasync per drive pass instead of two fsync barriers
 * per header (engine/supervisors/src/staged_sync_supervisor.c,
 * staged_tick_batched_sync).
 *
 * DURABILITY CONTRACT (what recovery relies on, and what this file pins):
 *   (1) the event is flushed by the stage pre-commit hook BEFORE the commit
 *       that makes the header_admit_log row and cursor durable; a failed flush
 *       vetoes the commit (core/modules/sync/src/stage_batch.c, hook in
 *       engine/reducer/services/src/reducer_body_fsync.c);
 *   (2) an event buffered but not yet flushed dies with the process; the
 *       cursor/row it belongs to never committed either, so the restart
 *       re-admits that header and re-emits the event;
 *   (3) an event flushed but whose commit never happened is re-emitted
 *       identically (the projection folds EV_BLOCK_HEADER idempotently).
 *
 * PART 1 (counters): admitting N headers through the production tick path
 *   takes 0 barrier appends (was N, i.e. 2N fsyncs); one pre-commit flush per
 *   pass. One direct scope pass over N headers is one flush total.
 * PART 2 (crash): each leg runs in a forked child that raise(SIGKILL)s itself
 *   at a deterministic point (before the deferred flush, after the flush but
 *   before the commit, after the commit). A second child resumes; a third
 *   digests header_admit_log, the event-log header set and the block-index
 *   projection commitment. Every digest must equal the undeferred golden
 *   run's.
 *
 * make t ONLY=header_admit_deferred_log
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "jobs/header_admit_stage.h"
#include "jobs/reducer_frontier.h"
#include "services/reducer_ingest_service.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "supervisors/staged_sync_supervisor.h"
#include "sync/stage.h"
#include "test/test_block_map.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"

#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define HDL_N 6        /* headers 0..5                                       */
#define HDL_KILL_AT 3  /* tick mode: the pass that admits header 3 is killed */
#define HDL_MAX_EV 32

#define HDL_CHECK(name, expr) do {                                  \
    printf("header_admit_deferred_log: %s... ", (name));            \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

enum hdl_mode { HDL_UNDEFERRED, HDL_TICK, HDL_SCOPE_PASS };
enum hdl_kill { HDL_NO_KILL, HDL_KILL_PRE_FLUSH, HDL_KILL_POST_FLUSH,
                HDL_KILL_POST_COMMIT };

struct hdl_chain {
    struct block_index *blocks;
    struct uint256 *hashes;
};

static bool hdl_chain_build(struct hdl_chain *sc)
{
    sc->blocks = zcl_malloc(HDL_N * sizeof(struct block_index), "hdl_blocks");
    sc->hashes = zcl_malloc(HDL_N * sizeof(struct uint256), "hdl_hashes");
    if (!sc->blocks || !sc->hashes)
        return false;
    for (int i = 0; i < HDL_N; i++) {
        block_index_init(&sc->blocks[i]);
        memset(&sc->hashes[i], 0, sizeof(struct uint256));
        sc->hashes[i].data[0] = (uint8_t)i;
        sc->hashes[i].data[2] = 0xAB;
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nTime = (uint32_t)(1000 + i);
        sc->blocks[i].nBits = 0x207fffff;
        if (i > 0)
            sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    return true;
}

static void hdl_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    snprintf(out, cap, "%s/%s", dir, leaf);
}

/* ── crash hooks (replace the real pre-commit hook for the killed pass) ── */

static bool hdl_hook_kill_pre_flush(void)
{
    raise(SIGKILL);
    return false;
}

static bool hdl_hook_kill_post_flush(void)
{
    (void)reducer_body_fsync_test_trigger_precommit(); /* the real flush */
    raise(SIGKILL);
    return false;
}

static void hdl_arm_kill(enum hdl_kill k)
{
    if (k == HDL_KILL_PRE_FLUSH)
        stage_batch_set_precommit_hook(hdl_hook_kill_pre_flush);
    else if (k == HDL_KILL_POST_FLUSH)
        stage_batch_set_precommit_hook(hdl_hook_kill_post_flush);
}

static uint64_t hdl_cursor_getter(void) { return header_admit_stage_cursor(); }

struct hdl_ctx {
    struct main_state ms;
    struct hdl_chain sc;
    event_log_t *log;
};

static bool hdl_open(struct hdl_ctx *x, const char *dir)
{
    reducer_frontier_test_set_compiled_anchor(0);
    blocker_module_init();
    memset(x, 0, sizeof(*x));
    if (!progress_store_open(dir))
        return false;
    char lp[600];
    hdl_path(lp, sizeof(lp), dir, "event.log");
    x->log = event_log_open(lp);
    if (!x->log)
        return false;
    event_log_set_singleton(x->log);
    main_state_init(&x->ms);
    if (!hdl_chain_build(&x->sc))
        return false;
    active_chain_move_window_tip(&x->ms.chain_active, &x->sc.blocks[HDL_N - 1]);
    if (!header_admit_stage_init(&x->ms))
        return false;
    event_log_test_reset_append_stats();
    reducer_body_fsync_test_reset();
    return true;
}

static void hdl_close(struct hdl_ctx *x)
{
    header_admit_stage_shutdown();
    event_log_set_singleton(NULL);
    event_log_close(x->log);
    progress_store_close();
}

static void hdl_write_stats(const char *dir)
{
    uint64_t barrier = 0, deferred = 0, barrier_us = 0;
    uint64_t flushes = 0, flush_us = 0;
    event_log_append_stats(&barrier, &deferred, &barrier_us);
    reducer_body_fsync_totals_snapshot(&flushes, &flush_us);
    char p[600];
    hdl_path(p, sizeof(p), dir, "stats");
    FILE *f = fopen(p, "w");
    if (!f)
        return;
    fprintf(f, "barrier_appends=%llu\ndeferred_appends=%llu\nflushes=%llu\n"
               "cursor=%llu\n",
            (unsigned long long)barrier, (unsigned long long)deferred,
            (unsigned long long)flushes,
            (unsigned long long)header_admit_stage_cursor());
    fclose(f);
}

/* One drive pass in the given mode. */
static void hdl_pass(struct hdl_ctx *x, enum hdl_mode mode, enum hdl_kill kill,
                     bool killing_pass)
{
    if (mode == HDL_UNDEFERRED) {
        (void)header_admit_stage_drain(1);
    } else if (mode == HDL_TICK) {
        bool stalled = false;
        if (killing_pass)
            hdl_arm_kill(kill);
        (void)staged_sync_supervisor_test_run_stage_tick(
            "staged.header_admit", NULL, header_admit_stage_drain,
            hdl_cursor_getter, NULL, &x->ms, &stalled, NULL);
    } else {
        reducer_enter_batched_body_sync();
        if (killing_pass)
            hdl_arm_kill(kill);
        (void)header_admit_stage_drain(100);
        reducer_exit_batched_body_sync();
    }
    if (killing_pass && kill == HDL_KILL_POST_COMMIT)
        raise(SIGKILL);
}

static int hdl_leg_run(const char *dir, enum hdl_mode mode, enum hdl_kill kill)
{
    struct hdl_ctx x;
    if (!hdl_open(&x, dir))
        return 2;
    for (int guard = 0; guard < 4 * HDL_N &&
                        header_admit_stage_cursor() < (uint64_t)HDL_N;
         guard++) {
        bool killing = kill != HDL_NO_KILL &&
            (mode == HDL_SCOPE_PASS ||
             header_admit_stage_cursor() == (uint64_t)HDL_KILL_AT);
        hdl_pass(&x, mode, kill, killing);
    }
    int rc = header_admit_stage_cursor() == (uint64_t)HDL_N ? 0 : 3;
    hdl_write_stats(dir);
    hdl_close(&x);
    return rc;
}

/* ── digest leg ────────────────────────────────────────────────────────── */


#define HDL_PAYLOAD_MAX 1600

struct hdl_evset {
    int n_total;
    int n_distinct;
    int dup_mismatch;
    uint8_t hash[HDL_MAX_EV][32];
    size_t len[HDL_MAX_EV];
    uint8_t payload[HDL_MAX_EV][HDL_PAYLOAD_MAX];
};

static bool hdl_ev_cb(uint64_t off, enum event_log_type type,
                      const void *payload, size_t len, void *user)
{
    (void)off;
    struct hdl_evset *s = user;
    if (type != EV_BLOCK_HEADER || len < 32 || len > HDL_PAYLOAD_MAX)
        return true;
    s->n_total++;
    for (int i = 0; i < s->n_distinct; i++) {
        if (memcmp(s->hash[i], payload, 32) == 0) {
            if (s->len[i] != len || memcmp(s->payload[i], payload, len) != 0)
                s->dup_mismatch++;
            return true;
        }
    }
    if (s->n_distinct < HDL_MAX_EV) {
        memcpy(s->hash[s->n_distinct], payload, 32);
        memcpy(s->payload[s->n_distinct], payload, len);
        s->len[s->n_distinct] = len;
        s->n_distinct++;
    }
    return true;
}

static void hdl_hex(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        fprintf(f, "%02x", b[i]);
}

static int hdl_leg_digest(const char *dir)
{
    reducer_frontier_test_set_compiled_anchor(0);
    if (!progress_store_open(dir))
        return 2;
    char lp[600], pp[600], op[600];
    hdl_path(lp, sizeof(lp), dir, "event.log");
    hdl_path(pp, sizeof(pp), dir, "proj.sqlite");
    hdl_path(op, sizeof(op), dir, "digest");
    event_log_t *log = event_log_open(lp);
    if (!log)
        return 3;
    struct hdl_evset *es = calloc(1, sizeof(*es));
    block_index_projection_t *proj = block_index_projection_open(pp, log);
    if (!es || !proj)
        return 4;
    (void)event_log_stream(log, 0, hdl_ev_cb, es);
    (void)block_index_projection_catch_up(proj);
    uint8_t commit[32] = {0};
    (void)block_index_projection_commitment(proj, commit);

    FILE *f = fopen(op, "w");
    if (!f)
        return 5;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(progress_store_db(),
            "SELECT height, hash FROM header_admit_log ORDER BY height",
            -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:digest-read
            fprintf(f, "row=%d:", sqlite3_column_int(st, 0));
            hdl_hex(f, sqlite3_column_blob(st, 1),
                    (size_t)sqlite3_column_bytes(st, 1));
            fprintf(f, "\n");
        }
    }
    sqlite3_finalize(st);
    fprintf(f, "events_distinct=%d\nevents_dup_mismatch=%d\n",
            es->n_distinct, es->dup_mismatch);
    fprintf(f, "proj_count=%llu\nproj_commit=",
            (unsigned long long)block_index_projection_count(proj));
    hdl_hex(f, commit, 32);
    fprintf(f, "\nevents_total=%d\n", es->n_total);
    fclose(f);
    block_index_projection_close(proj);
    event_log_close(log);
    progress_store_close();
    free(es);
    return 0;
}

/* ── parent-side helpers ───────────────────────────────────────────────── */

static int hdl_run_child(const char *dir, int which, enum hdl_mode mode,
                         enum hdl_kill kill, bool *sigkilled)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        int rc = which == 0 ? hdl_leg_run(dir, mode, kill)
                            : hdl_leg_digest(dir);
        fflush(NULL);
        _exit(rc);
    }
    int stt = 0;
    if (pid < 0 || waitpid(pid, &stt, 0) != pid)
        return -1;
    if (sigkilled)
        *sigkilled = WIFSIGNALED(stt) && WTERMSIG(stt) == SIGKILL;
    return WIFEXITED(stt) ? WEXITSTATUS(stt) : -2;
}

/* Value of "key=" in a small text file; -1 when absent. */
static long long hdl_kv(const char *dir, const char *leaf, const char *key)
{
    char p[600], line[256];
    hdl_path(p, sizeof(p), dir, leaf);
    FILE *f = fopen(p, "r");
    if (!f)
        return -1;
    size_t kl = strlen(key);
    long long v = -1;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, key, kl) == 0 && line[kl] == '=')
            v = atoll(line + kl + 1);
    fclose(f);
    return v;
}

/* True when the digest files agree on everything except events_total. */
static bool hdl_digests_equal(const char *a, const char *b)
{
    char pa[600], pb[600], la[256], lb[256];
    hdl_path(pa, sizeof(pa), a, "digest");
    hdl_path(pb, sizeof(pb), b, "digest");
    FILE *fa = fopen(pa, "r"), *fb = fopen(pb, "r");
    bool eq = fa && fb;
    while (eq) {
        char *ga = fgets(la, sizeof(la), fa);
        char *gb = fgets(lb, sizeof(lb), fb);
        if (!ga || !gb) {
            eq = !ga && !gb;
            break;
        }
        if (strncmp(la, "events_total=", 13) == 0 &&
            strncmp(lb, "events_total=", 13) == 0)
            continue;
        eq = strcmp(la, lb) == 0;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return eq;
}

static int hdl_part1_counters(void)
{
    int failures = 0;
    char dU[512], dT[512], dS[512];
    test_make_tmpdir(dU, sizeof(dU), "hadl", "undeferred");
    test_make_tmpdir(dT, sizeof(dT), "hadl", "tick");
    test_make_tmpdir(dS, sizeof(dS), "hadl", "scope");

    HDL_CHECK("undeferred leg ran",
              hdl_run_child(dU, 0, HDL_UNDEFERRED, HDL_NO_KILL, NULL) == 0);
    HDL_CHECK("tick leg ran",
              hdl_run_child(dT, 0, HDL_TICK, HDL_NO_KILL, NULL) == 0);
    HDL_CHECK("scope-pass leg ran",
              hdl_run_child(dS, 0, HDL_SCOPE_PASS, HDL_NO_KILL, NULL) == 0);

    long long ub = hdl_kv(dU, "stats", "barrier_appends");
    long long tb = hdl_kv(dT, "stats", "barrier_appends");
    long long td = hdl_kv(dT, "stats", "deferred_appends");
    long long tf = hdl_kv(dT, "stats", "flushes");
    long long sb = hdl_kv(dS, "stats", "barrier_appends");
    long long sd = hdl_kv(dS, "stats", "deferred_appends");
    long long sf = hdl_kv(dS, "stats", "flushes");
    printf("header_admit_deferred_log: MEASURE headers=%d "
           "undeferred: barrier_appends=%lld (=%lld fsyncs, %.1f/header); "
           "tick: barrier_appends=%lld deferred=%lld flushes=%lld "
           "(%.2f fdatasync/header); scope-pass: barrier_appends=%lld "
           "deferred=%lld flushes=%lld\n",
           HDL_N, ub, 2 * ub, (double)(2 * ub) / HDL_N, tb, td, tf,
           (double)tf / HDL_N, sb, sd, sf);

    HDL_CHECK("undeferred path pays one barrier append (2 fsyncs) per header",
              ub == HDL_N);
    HDL_CHECK("tick path performs no per-append barrier", tb == 0);
    HDL_CHECK("tick path buffers every header event", td == HDL_N);
    HDL_CHECK("tick path flushes once per pass, not twice per header",
              tf > 0 && tf <= HDL_N);
    HDL_CHECK("one scope pass over N headers is a single flush",
              sb == 0 && sd == HDL_N && sf == 1);

    HDL_CHECK("digest undeferred", hdl_run_child(dU, 1, 0, 0, NULL) == 0);
    HDL_CHECK("digest tick", hdl_run_child(dT, 1, 0, 0, NULL) == 0);
    HDL_CHECK("digest scope", hdl_run_child(dS, 1, 0, 0, NULL) == 0);
    HDL_CHECK("tick final state equals undeferred golden",
              hdl_digests_equal(dU, dT));
    HDL_CHECK("scope-pass final state equals undeferred golden",
              hdl_digests_equal(dU, dS));
    HDL_CHECK("projection folded all headers",
              hdl_kv(dU, "digest", "proj_count") == HDL_N);

    test_cleanup_tmpdir(dU);
    test_cleanup_tmpdir(dT);
    test_cleanup_tmpdir(dS);
    return failures;
}

static int hdl_crash_cycle(const char *label, enum hdl_mode mode,
                           enum hdl_kill kill, long long want_events_total)
{
    int failures = 0;
    char dG[512], dC[512], nm[160];
    test_make_tmpdir(dG, sizeof(dG), "hadl", "golden");
    test_make_tmpdir(dC, sizeof(dC), "hadl", label);
    int grc = hdl_run_child(dG, 0, HDL_UNDEFERRED, HDL_NO_KILL, NULL);
    int gdr = hdl_run_child(dG, 1, 0, 0, NULL);
    snprintf(nm, sizeof(nm), "%s: golden completed", label);
    HDL_CHECK(nm, grc == 0 && gdr == 0);

    bool killed = false;
    (void)hdl_run_child(dC, 0, mode, kill, &killed);
    snprintf(nm, sizeof(nm), "%s: crasher died by SIGKILL", label);
    HDL_CHECK(nm, killed);

    int rrc = hdl_run_child(dC, 0, HDL_TICK, HDL_NO_KILL, NULL);
    snprintf(nm, sizeof(nm), "%s: resumer reached the full header tip", label);
    HDL_CHECK(nm, rrc == 0);
    int drc = hdl_run_child(dC, 1, 0, 0, NULL);
    snprintf(nm, sizeof(nm), "%s: digest ran", label);
    HDL_CHECK(nm, drc == 0);

    snprintf(nm, sizeof(nm),
             "%s: log rows, event set and projection equal undeferred golden",
             label);
    HDL_CHECK(nm, hdl_digests_equal(dG, dC));
    snprintf(nm, sizeof(nm), "%s: duplicate re-emitted events are identical",
             label);
    HDL_CHECK(nm, hdl_kv(dC, "digest", "events_dup_mismatch") == 0);
    long long total = hdl_kv(dC, "digest", "events_total");
    printf("header_admit_deferred_log: MEASURE %s events_total=%lld "
           "(golden %lld)\n", label, total,
           hdl_kv(dG, "digest", "events_total"));
    snprintf(nm, sizeof(nm), "%s: exactly %lld header events on disk", label,
             want_events_total);
    HDL_CHECK(nm, total == want_events_total);

    test_cleanup_tmpdir(dG);
    test_cleanup_tmpdir(dC);
    return failures;
}

int test_header_admit_deferred_log(void);
int test_header_admit_deferred_log(void)
{
    printf("\n=== header_admit_deferred_log tests ===\n");
    int failures = 0;
    failures += hdl_part1_counters();
    /* Stop before the deferred flush: the unflushed event dies with the
     * process and so does the uncommitted cursor/row; the header re-admits. */
    failures += hdl_crash_cycle("tick_pre_flush", HDL_TICK,
                                HDL_KILL_PRE_FLUSH, HDL_N);
    /* Stop after the flush, before the commit: the event is durable, the row
     * is not; the header re-admits and re-emits one identical event. */
    failures += hdl_crash_cycle("tick_post_flush", HDL_TICK,
                                HDL_KILL_POST_FLUSH, HDL_N + 1);
    /* Stop after the commit: everything durable, nothing re-emitted. */
    failures += hdl_crash_cycle("tick_post_commit", HDL_TICK,
                                HDL_KILL_POST_COMMIT, HDL_N);
    /* A whole multi-header pass killed before its single flush. */
    failures += hdl_crash_cycle("scope_pre_flush", HDL_SCOPE_PASS,
                                HDL_KILL_PRE_FLUSH, HDL_N);
    printf("=== header_admit_deferred_log: %d failures ===\n", failures);
    return failures;
}
