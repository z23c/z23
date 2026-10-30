/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the pre-RPC boot-status beacon (platform/modules/util/src/boot_status.c).
 *
 * Coverage:
 *   - phase derivation for every boot stage + rpc_bound/serving booleans
 *   - JSON serialization round-trips through the reader (write_json -> file ->
 *     boot_status_read recovers every field)
 *   - the writer (init/note_stage/set_height) publishes an atomically-readable
 *     <datadir>/boot_status.json the node-free reader recovers
 *   - typed recovery progress + named blockers survive writer/read round-trips
 *   - the reader fails closed on missing, malformed, corrupt, or contradictory
 *     documents
 *
 * Node-free and filesystem-scoped to a private mkdtemp dir, so it runs under
 * the parallel test driver without touching any live datadir. */

#include "test/test_core.h"
#include "util/boot_status.h"
#include "util/boot_phase.h"
#include "platform/private_file.h"
#include "base/log_level.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>

/* Run the real caller in a bounded child; the parent's stderr and writer
 * state stay intact even if capture setup or the caller fails. */
static bool bs_diagnostic_call(const char *dir, bool publish)
{
    if (!publish) {
        char why[128] = "sentinel";
        return !boot_status_read(dir, NULL, why, sizeof(why)) && !why[0];
    }
    char target[600];
    int n = snprintf(target, sizeof(target), "%s/%s", dir,
                     ZCL_BOOT_STATUS_FILENAME);
    if (n < 0 || (size_t)n >= sizeof(target))
        return false;
    boot_status_init(dir);
    boot_status_note_stage((int)BOOT_STAGE_DB_OPEN);
    boot_status_init(NULL);
    struct stat st;
    return lstat(target, &st) == -1 && errno == ENOENT;
}

static void bs_diagnostic_child(FILE *capture, const char *dir, bool publish)
{
    sigset_t signals;
    if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &signals, NULL) != 0 ||
        signal(SIGALRM, SIG_DFL) == SIG_ERR)
        _exit(2);
    alarm(10);
    if (dup2(fileno(capture), STDERR_FILENO) < 0)
        _exit(2);
    if (fclose(capture) != 0)
        _exit(2);
    zcl_log_level_set(ZCL_LOG_ALL);
    bool ok = bs_diagnostic_call(dir, publish);
    if (fflush(stderr) != 0)
        _exit(2);
    _exit(ok ? 0 : 1);
}

static bool bs_capture_diagnostic(const char *dir, bool publish, char log[2048])
{
    log[0] = '\0';
    FILE *capture = tmpfile();
    if (!capture)
        return false;
    pid_t child = fork();
    if (child == 0)
        bs_diagnostic_child(capture, dir, publish);
    int status = 0;
    pid_t waited = -1;
    if (child > 0) {
        do { waited = waitpid(child, &status, 0); }
        while (waited < 0 && errno == EINTR);
    }
    bool ok = waited == child && child > 0 && WIFEXITED(status);
    if (ok)
        ok = WEXITSTATUS(status) == 0;
    if (fseek(capture, 0, SEEK_SET) != 0)
        ok = false;
    size_t n = fread(log, 1, 2047, capture);
    log[n] = '\0';
    if (ferror(capture) || !feof(capture))
        ok = false;
    if (fclose(capture) != 0)
        ok = false;
    return ok;
}

#define BS_CHECK(name, expr) do {          \
    printf("boot_status: %s... ", (name)); \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void bs_write_file(const char *dir, const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (body[0])
            (void)!write(fd, body, strlen(body));
        close(fd);
    }
}

static int bs_diagnostic_checks(const char *dir)
{
    int failures = 0;
    char missing[512], target[600], log[2048];
    int n = snprintf(missing, sizeof(missing), "%s/absent-parent", dir);
    BS_CHECK("missing parent path fits", n > 0 && (size_t)n < sizeof(missing));
    if (failures)
        return failures;
    n = snprintf(target, sizeof(target), "%s/%s", missing,
                 ZCL_BOOT_STATUS_FILENAME);
    BS_CHECK("missing beacon path fits", n > 0 && (size_t)n < sizeof(target));
    if (failures)
        return failures;
    bool captured = bs_capture_diagnostic(missing, true, log);
    BS_CHECK("publication failure continues with no beacon", captured);
    BS_CHECK("publication warning names destination and private repair",
             captured && strstr(log, target) && strstr(log, missing) &&
             strstr(log, "create or repair the private directory") &&
             strstr(log, "retry publication"));
    captured = bs_capture_diagnostic(dir, false, log);
    BS_CHECK("NULL out refusal preserves empty error buffer", captured);
    BS_CHECK("reader refusal identifies out and caller repair",
             captured && strstr(log, "out required") &&
             strstr(log, "supply an output snapshot"));
    return failures;
}

int test_boot_status(void)
{
    printf("\n=== boot_status tests ===\n");
    int failures = 0;

    /* ── phase derivation ─────────────────────────────────────────── */
    {
        bool rb = true, sv = true;
        BS_CHECK("INIT phase is starting",
            strcmp(boot_status_phase_for_stage(BOOT_STAGE_INIT, &rb, &sv),
                   "starting") == 0);
        BS_CHECK("INIT not rpc_bound / not serving", !rb && !sv);

        BS_CHECK("DB_OPEN phase is loading",
            strcmp(boot_status_phase_for_stage(BOOT_STAGE_DB_OPEN, &rb, &sv),
                   "loading") == 0);
        BS_CHECK("DB_OPEN not serving", !sv);

        const char *p = boot_status_phase_for_stage(BOOT_STAGE_READY, &rb, &sv);
        BS_CHECK("READY phase is serving", strcmp(p, "serving") == 0);
        BS_CHECK("READY is rpc_bound and serving", rb && sv);

        BS_CHECK("SHUTDOWN phase is shutdown",
            strcmp(boot_status_phase_for_stage(BOOT_STAGE_SHUTDOWN_REQUESTED,
                                               &rb, &sv), "shutdown") == 0);
    }

    /* ── serialize -> read round-trip (no writer state) ───────────── */
    char tmpl[PATH_MAX];
    char *dir = test_mkdtemp(tmpl, sizeof(tmpl), "zcl_bootstatus");
    BS_CHECK("mkdtemp created a scratch datadir", dir != NULL);
    if (!dir)
        return failures;

    failures += bs_diagnostic_checks(dir);

    {
        struct boot_status_snapshot in;
        memset(&in, 0, sizeof(in));
        snprintf(in.phase, sizeof(in.phase), "loading");
        snprintf(in.stage, sizeof(in.stage), "db_open");
        in.stage_ordinal = (int32_t)BOOT_STAGE_DB_OPEN;
        in.height = 123456;
        in.rpc_bound = false;
        in.serving = false;
        in.started_unix = 1700000000;
        in.updated_unix = 1700000042;
        in.elapsed_s = 42;
        snprintf(in.activity, sizeof(in.activity), "reindex_chainstate");
        in.progress_current = 120000;
        in.progress_target = 478544;
        snprintf(in.blocker, sizeof(in.blocker), "reindex_read_failed");
        snprintf(in.blocker_reason, sizeof(in.blocker_reason),
                 "block 120001 is unreadable");

        char buf[1024];
        size_t n = boot_status_write_json(&in, buf, sizeof(buf));
        BS_CHECK("write_json produced bytes", n > 0 && n < sizeof(buf));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME, buf);

        struct boot_status_snapshot out;
        char why[128];
        bool ok = boot_status_read(dir, &out, why, sizeof(why));
        BS_CHECK("read recovered the beacon", ok);
        BS_CHECK("phase round-trips", strcmp(out.phase, "loading") == 0);
        BS_CHECK("stage round-trips", strcmp(out.stage, "db_open") == 0);
        BS_CHECK("stage_ordinal round-trips",
                 out.stage_ordinal == (int32_t)BOOT_STAGE_DB_OPEN);
        BS_CHECK("height round-trips", out.height == 123456);
        BS_CHECK("rpc_bound round-trips", out.rpc_bound == false);
        BS_CHECK("serving round-trips", out.serving == false);
        BS_CHECK("started_unix round-trips", out.started_unix == 1700000000);
        BS_CHECK("updated_unix round-trips", out.updated_unix == 1700000042);
        BS_CHECK("elapsed_s round-trips", out.elapsed_s == 42);
        BS_CHECK("activity round-trips",
                 strcmp(out.activity, "reindex_chainstate") == 0);
        BS_CHECK("progress current round-trips",
                 out.progress_current == 120000);
        BS_CHECK("progress target round-trips",
                 out.progress_target == 478544);
        BS_CHECK("blocker round-trips",
                 strcmp(out.blocker, "reindex_read_failed") == 0);
        BS_CHECK("blocker reason round-trips",
                 strcmp(out.blocker_reason, "block 120001 is unreadable") == 0);
    }

    /* ── writer publishes a readable beacon ───────────────────────── */
    {
        boot_status_init(dir);
        boot_status_note_stage((int)BOOT_STAGE_DB_OPEN);
        boot_status_set_height(478544);
        boot_status_set_progress("reindex_chainstate", 120000, 478544);
        boot_status_set_blocker("reindex_read_failed",
                                "block 120001 is unreadable");

        struct boot_status_snapshot out;
        char why[128];
        bool ok = boot_status_read(dir, &out, why, sizeof(why));
        BS_CHECK("writer recovery beacon is readable", ok);
        BS_CHECK("writer carried recovery activity",
                 strcmp(out.activity, "reindex_chainstate") == 0);
        BS_CHECK("writer carried recovery progress",
                 out.progress_current == 120000 &&
                 out.progress_target == 478544);
        BS_CHECK("writer carried named blocker",
                 strcmp(out.blocker, "reindex_read_failed") == 0);

        boot_status_set_progress(NULL, -1, -1);
        boot_status_set_blocker(NULL, NULL);
        boot_status_note_stage((int)BOOT_STAGE_READY);
        ok = boot_status_read(dir, &out, why, sizeof(why));
        BS_CHECK("writer beacon is readable", ok);
        BS_CHECK("writer reached serving phase",
                 strcmp(out.phase, "serving") == 0);
        BS_CHECK("writer stage is ready", strcmp(out.stage, "ready") == 0);
        BS_CHECK("writer marks serving true", out.serving == true);
        BS_CHECK("writer marks rpc_bound true", out.rpc_bound == true);
        BS_CHECK("writer carried the height", out.height == 478544);
        BS_CHECK("writer cleared recovery before serving",
                 out.activity[0] == '\0' && out.progress_current == -1 &&
                 out.progress_target == -1);
        BS_CHECK("writer set a start time", out.started_unix > 0);

        /* Disarm so later tests' boot_stage_advance_to calls don't write into
         * this scratch dir (which we remove below). */
        boot_status_init(NULL);
    }

    /* One durable publication = one file flush (inside the replace) plus one
     * parent-directory flush. A duplicate explicit flush cost a third
     * journal commit per boot stage. */
    {
        boot_status_init(dir);
        unsigned long base = platform_private_flush_events();
        boot_status_note_stage((int)BOOT_STAGE_DB_OPEN);
        unsigned long used = platform_private_flush_events() - base;
        printf("boot_status: flushes per publish = %lu\n", used);
        BS_CHECK("publish uses exactly two flushes", used == 2);
        struct boot_status_snapshot pub;
        char pwhy[128];
        BS_CHECK("published beacon is complete and readable",
                 boot_status_read(dir, &pub, pwhy, sizeof(pwhy)) &&
                 strcmp(pub.stage, "db_open") == 0);
        boot_status_init(NULL);
    }


    /* Intra-stage heartbeat: long block-index work must refresh
     * updated_unix without pretending the stage advanced. */
    {
        boot_status_init(dir);
        boot_status_note_stage((int)BOOT_STAGE_WALLET_LOADED);
        struct boot_status_snapshot first, second;
        char why[128];
        BS_CHECK("heartbeat fixture readable",
                 boot_status_read(dir, &first, why, sizeof(why)));
        BS_CHECK("heartbeat fixture is wallet_loaded",
                 strcmp(first.stage, "wallet_loaded") == 0);
        (void)sleep(1);
        boot_status_heartbeat();
        BS_CHECK("heartbeat rewrite readable",
                 boot_status_read(dir, &second, why, sizeof(why)));
        BS_CHECK("heartbeat keeps wallet_loaded",
                 strcmp(second.stage, "wallet_loaded") == 0);
        BS_CHECK("heartbeat advances updated_unix",
                 second.updated_unix > first.updated_unix);
        BS_CHECK("heartbeat advances elapsed_s",
                 second.elapsed_s >= first.elapsed_s);
        boot_status_init(NULL);
    }

    /* ── reader fails closed on absent / empty / malformed ────────── */
    {
        char empty_dir[PATH_MAX];
        char *ed = test_mkdtemp(empty_dir, sizeof(empty_dir),
                                "zcl_bootstatus_empty");
        struct boot_status_snapshot out;
        char why[128];
        BS_CHECK("read of missing file returns false",
                 ed && !boot_status_read(ed, &out, why, sizeof(why)));

        bs_write_file(dir, "empty_status.json", "");
        /* point the reader at an explicitly malformed doc */
        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME, "not json at all {{{");
        BS_CHECK("read of malformed file returns false",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME,
            "{\"schema\":\"zcl.boot_status.v1\",\"phase\":\"starting\","
            "\"stage\":\"init\",\"stage_ordinal\":0,\"height\":-1,"
            "\"rpc_bound\":false,\"serving\":false,\"started_unix\":1,"
            "\"updated_unix\":1,\"elapsed_s\":0}TRAILING");
        BS_CHECK("valid beacon prefix with trailing junk is rejected",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME, "{}");
        BS_CHECK("empty object is corrupt, not a boot status",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME,
            "{\"schema\":\"wrong.v1\",\"phase\":\"loading\","
            "\"stage\":\"db_open\",\"stage_ordinal\":3,\"height\":-1,"
            "\"rpc_bound\":false,\"serving\":false,\"started_unix\":1,"
            "\"updated_unix\":1,\"elapsed_s\":0}");
        BS_CHECK("wrong schema is rejected",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME,
            "{\"schema\":\"zcl.boot_status.v1\",\"phase\":7,"
            "\"stage\":\"db_open\",\"stage_ordinal\":3,\"height\":-1,"
            "\"rpc_bound\":false,\"serving\":false,\"started_unix\":1,"
            "\"updated_unix\":1,\"elapsed_s\":0}");
        BS_CHECK("wrong required field type is rejected",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME,
            "{\"schema\":\"zcl.boot_status.v1\",\"phase\":\"loading\","
            "\"stage\":\"db_open\",\"stage_ordinal\":3,\"height\":-1,"
            "\"rpc_bound\":true,\"serving\":true,\"started_unix\":1,"
            "\"updated_unix\":1,\"elapsed_s\":0}");
        BS_CHECK("contradictory serving state is rejected",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME,
            "{\"schema\":\"zcl.boot_status.v1\",\"phase\":\"serving\","
            "\"stage\":\"ready\",\"stage_ordinal\":9,\"height\":1,"
            "\"rpc_bound\":true,\"serving\":true,\"started_unix\":1,"
            "\"updated_unix\":1,\"elapsed_s\":0,"
            "\"activity\":\"reindex_chainstate\","
            "\"progress_current\":1,\"progress_target\":2}");
        BS_CHECK("serving cannot retain an active boot recovery",
                 !boot_status_read(dir, &out, why, sizeof(why)));

        BS_CHECK("read with NULL datadir returns false",
                 !boot_status_read(NULL, &out, why, sizeof(why)));

        if (ed) {
            char p[600];
            snprintf(p, sizeof(p), "%s", ed);
            (void)rmdir(p);
        }
    }

    /* Best-effort cleanup of the scratch dir + files. */
    {
        char p[600];
        snprintf(p, sizeof(p), "%s/%s", dir, ZCL_BOOT_STATUS_FILENAME);
        (void)unlink(p);
        snprintf(p, sizeof(p), "%s/empty_status.json", dir);
        (void)unlink(p);
        (void)rmdir(dir);
    }

    return failures;
}
