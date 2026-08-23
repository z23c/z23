/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the debug bundle (app/controllers/src/
 * diagnostics_debug_bundle.c): the one-shot diagnostic capture behind the
 * `debugbundle` RPC / ops.debug.bundle native command and the
 * supervisor-stall auto-capture.
 *
 * Coverage:
 *   (a) debugbundle RPC end-to-end: a tmp datadir wired through
 *       diagnostics_controller_set_state, rpc_table_execute("debugbundle")
 *       returns { path, bytes, subsystems_captured, subsystems_failed,
 *       trigger=manual }; the file at the returned path exists, is exactly
 *       `bytes` long, parses as JSON, and carries the top-level contract
 *       (format, trigger, build, supervisor_stalls, subsystems with the
 *       registered dumpers keyed by name).
 *   (b) supervisor-stall trigger metadata: a direct debug_bundle_write
 *       with trigger "supervisor_stall" + child/reason lands trigger_child
 *       and trigger_stall_reason in the document.
 *   (c) no datadir: debug_bundle_write fails cleanly (false, empty path)
 *       rather than writing somewhere surprising.
 *
 * The auto-capture writer is an owned persistent worker.  This group exercises
 * its deterministic lifecycle (start, stop/join, rejection after revocation,
 * idempotent stop, restart) without depending on scheduling of an actual
 * automatic capture.
 * Dumpers run under the same minimal fixture test_health_rollup already
 * uses — every registered dumper must tolerate an unbooted process — so
 * no extra per-subsystem setup is paid here. */

#include "test/test_core.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBB_CHECK(name, expr) do { \
    printf("debug_bundle: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Read a whole file into a fresh NUL-terminated buffer (zcl_malloc'd;
 * caller frees). NULL on any failure. */
static char *dbb_read_file(const char *path, long *size_out)
{
    if (size_out) *size_out = 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0 || fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    char *buf = zcl_malloc((size_t)sz + 1, "debug_bundle_test_read");
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    if (size_out) *size_out = sz;
    return buf;
}

/* ── (d) bounded-drain harness ───────────────────────────────────────
 *
 * Runs diagnostics_controller_shutdown() on its own thread so the test can
 * put a DEADLINE on a call that, before the bounded drain landed, waited
 * forever on a capture lease. The live incident this pins: SIGTERM on a
 * healthy node, stage 'diagnostics-drain' blows its deadline, and the
 * watchdog force-exits UNCLEAN before the coins flush / WAL checkpoint /
 * clean marker ever run — costing the next boot a ~180 s quick_check. */
struct dbb_drain_probe {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    bool            done;
    bool            result;
};

static void *dbb_drain_thread(void *arg)
{
    struct dbb_drain_probe *p = arg;
    bool r = diagnostics_controller_shutdown();
    pthread_mutex_lock(&p->lock);
    p->result = r;
    p->done = true;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->lock);
    return NULL;
}

/* Wait up to `budget_ms` for the probe to finish. Returns whether it did. */
static bool dbb_drain_wait(struct dbb_drain_probe *p, int budget_ms)
{
    struct timespec deadline;
    platform_time_realtime_timespec(&deadline);
    deadline.tv_sec  += budget_ms / 1000;
    deadline.tv_nsec += (long)(budget_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&p->lock);
    while (!p->done) {
        if (pthread_cond_timedwait(&p->cond, &p->lock, &deadline) == ETIMEDOUT)
            break;
    }
    bool done = p->done;
    pthread_mutex_unlock(&p->lock);
    return done;
}

/* Parse the bundle file at `path` into `doc` (caller json_free's). */
static bool dbb_parse_bundle(const char *path, struct json_value *doc,
                             long *size_out)
{
    char *raw = dbb_read_file(path, size_out);
    if (!raw) return false;
    bool ok = json_read(doc, raw, strlen(raw)) && doc->type == JSON_OBJ;
    free(raw);
    return ok;
}

int test_debug_bundle(void)
{
    printf("\n=== debug_bundle tests ===\n");
    int failures = 0;

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "debug_bundle", "1");
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);
    diagnostics_controller_set_state(NULL, dir);
    /* rpc_table_execute refuses while the process is in warmup, which is
     * the default state in a bare test process (test_rpc.c gets past it in
     * an earlier warmup test). */
    set_rpc_warmup_finished();

    /* ── (a) debugbundle RPC end-to-end ──────────────────────────── */
    char bundle_path[1200] = {0};
    {
        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value result;
        json_init(&result);

        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_diagnostics_rpc_commands(&tbl);
        bool ok = rpc_table_execute(&tbl, "debugbundle", &params, &result);

        DBB_CHECK("rpc: execute returns true", ok);
        const char *path = json_get_str(json_get(&result, "path"));
        DBB_CHECK("rpc: path names a debug-bundle file",
                  path && strstr(path, "debug-bundle-") != NULL);
        DBB_CHECK("rpc: trigger is manual",
                  strcmp(json_get_str(json_get(&result, "trigger")),
                         "manual") == 0);
        size_t count = diagnostics_dumper_count();
        int64_t captured =
            json_get_int(json_get(&result, "subsystems_captured"));
        int64_t failed =
            json_get_int(json_get(&result, "subsystems_failed"));
        DBB_CHECK("rpc: captured + failed covers every registered dumper",
                  captured >= 1 && failed >= 0 &&
                  captured + failed == (int64_t)count);
        int64_t bytes = json_get_int(json_get(&result, "bytes"));
        DBB_CHECK("rpc: bytes > 0", bytes > 0);
        if (path) snprintf(bundle_path, sizeof(bundle_path), "%s", path);

        struct json_value doc;
        json_init(&doc);
        long fsize = 0;
        ok = dbb_parse_bundle(bundle_path, &doc, &fsize);
        DBB_CHECK("file: exists and parses as a JSON object", ok);
        if (ok) {
            DBB_CHECK("file: size matches the reported bytes",
                      fsize == (long)bytes);
            DBB_CHECK("file: format tag",
                      strcmp(json_get_str(json_get(&doc, "format")),
                             "zcl.debug_bundle.v1") == 0);
            DBB_CHECK("file: captured_at_utc present",
                      json_get(&doc, "captured_at_utc") != NULL);
            DBB_CHECK("file: trigger is manual",
                      strcmp(json_get_str(json_get(&doc, "trigger")),
                             "manual") == 0);
            const struct json_value *build = json_get(&doc, "build");
            DBB_CHECK("file: build block carries build_commit",
                      build && build->type == JSON_OBJ &&
                      json_get(build, "build_commit") != NULL);
            const struct json_value *stalls =
                json_get(&doc, "supervisor_stalls");
            DBB_CHECK("file: supervisor_stalls summary present",
                      stalls && stalls->type == JSON_OBJ &&
                      json_get(stalls, "children") != NULL);
            const struct json_value *subs = json_get(&doc, "subsystems");
            DBB_CHECK("file: subsystems object present",
                      subs && subs->type == JSON_OBJ);
            DBB_CHECK("file: supervisor dumper captured by name",
                      subs && json_get(subs, "supervisor") != NULL);
            json_free(&doc);
        }
        json_free(&params);
        json_free(&result);
    }

    /* ── (b) supervisor-stall trigger metadata ───────────────────── */
    char stall_path[1200] = {0};
    {
        struct debug_bundle_result res;
        bool ok = debug_bundle_write("supervisor_stall", "test.child",
                                     (int)SUPERVISOR_STALL_TIME_DEADLINE,
                                     &res);
        DBB_CHECK("stall write: returns true", ok);
        snprintf(stall_path, sizeof(stall_path), "%s", res.path);

        struct json_value doc;
        json_init(&doc);
        ok = dbb_parse_bundle(stall_path, &doc, NULL);
        DBB_CHECK("stall write: file parses", ok);
        if (ok) {
            DBB_CHECK("stall write: trigger is supervisor_stall",
                      strcmp(json_get_str(json_get(&doc, "trigger")),
                             "supervisor_stall") == 0);
            DBB_CHECK("stall write: trigger_child recorded",
                      strcmp(json_get_str(json_get(&doc, "trigger_child")),
                             "test.child") == 0);
            DBB_CHECK("stall write: trigger_stall_reason recorded",
                      strcmp(json_get_str(
                                 json_get(&doc, "trigger_stall_reason")),
                             "time_deadline") == 0);
            json_free(&doc);
        }
    }

    /* ── (c) no datadir: clean failure, no surprise write ────────── */
    {
        diagnostics_controller_set_state(NULL, "");
        struct debug_bundle_result res;
        bool ok = debug_bundle_write("manual", NULL,
                                     (int)SUPERVISOR_STALL_NONE, &res);
        DBB_CHECK("no datadir: write fails cleanly", !ok);
        DBB_CHECK("no datadir: no path returned", res.path[0] == '\0');
    }

    if (bundle_path[0]) unlink(bundle_path);
    if (stall_path[0]) unlink(stall_path);
    DBB_CHECK("shutdown: owned worker joins",
              diagnostics_controller_shutdown());
    {
        struct debug_bundle_result res;
        DBB_CHECK("shutdown: new manual capture is refused",
                  !debug_bundle_write("manual", NULL,
                                      (int)SUPERVISOR_STALL_NONE, &res));
        DBB_CHECK("shutdown: refused capture returns no path",
                  res.path[0] == '\0');
    }
    DBB_CHECK("shutdown: repeated call is idempotent",
              diagnostics_controller_shutdown());
    diagnostics_controller_set_state(NULL, dir); /* restart is supported */
    {
        struct debug_bundle_result res;
        bool ok = debug_bundle_write("manual", NULL,
                                     (int)SUPERVISOR_STALL_NONE, &res);
        DBB_CHECK("restart: manual capture is accepted again", ok);
        if (ok && res.path[0])
            unlink(res.path);
    }
    DBB_CHECK("restart: owned worker joins",
              diagnostics_controller_shutdown());

    /* ── (d) the shutdown drain is BOUNDED ───────────────────────── */
    {
        diagnostics_controller_set_state(NULL, dir);   /* worker live again */

        /* One capture lease held open stands in for the live failure mode:
         * a capture blocked inside a single dumper, which the walk can only
         * cancel at the NEXT dumper boundary. */
        DBB_CHECK("drain: a capture lease can be taken before shutdown",
                  debug_bundle_capture_lease_acquire_for_test());
        debug_bundle_set_drain_budget_ms_for_test(200);

        struct dbb_drain_probe probe = {
            .lock = PTHREAD_MUTEX_INITIALIZER,
            .cond = PTHREAD_COND_INITIALIZER,
            .done = false,
            .result = false,
        };
        pthread_t th;
        bool spawned = pthread_create(&th, NULL, dbb_drain_thread,
                                      &probe) == 0;
        DBB_CHECK("drain: probe thread starts", spawned);

        bool returned = spawned && dbb_drain_wait(&probe, 5000);
        DBB_CHECK("drain: returns inside its budget with a capture live",
                  returned);
        DBB_CHECK("drain: an undrained capture reports false (never a "
                  "silent clean pass)",
                  returned && !probe.result);

        /* Release the lease: the drain must then report a true, complete
         * drain — the fix must not turn every shutdown into 'undrained'. */
        debug_bundle_capture_lease_release_for_test();
        if (spawned)
            pthread_join(th, NULL);
        DBB_CHECK("drain: reports true once the capture is gone",
                  diagnostics_controller_shutdown());

        debug_bundle_set_drain_budget_ms_for_test(0);   /* restore default */
    }

    rmdir(dir);
    return failures;
}
