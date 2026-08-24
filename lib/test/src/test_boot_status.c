/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the pre-RPC boot-status beacon (lib/util/src/boot_status.c).
 *
 * Coverage:
 *   - phase derivation for every boot stage + rpc_bound/serving booleans
 *   - JSON serialization round-trips through the reader (write_json -> file ->
 *     boot_status_read recovers every field)
 *   - the writer (init/note_stage/set_height) publishes an atomically-readable
 *     <datadir>/boot_status.json the node-free reader recovers
 *   - the reader fails closed (returns false) on a missing/empty/malformed file
 *
 * Node-free and filesystem-scoped to a private mkdtemp dir, so it runs under
 * the parallel test driver without touching any live datadir. */

#include "test/test_core.h"
#include "util/boot_status.h"
#include "util/boot_phase.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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
    char tmpl[] = "/tmp/zcl_bootstatus_XXXXXX";
    char *dir = mkdtemp(tmpl);
    BS_CHECK("mkdtemp created a scratch datadir", dir != NULL);
    if (!dir)
        return failures;

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
    }

    /* ── writer publishes a readable beacon ───────────────────────── */
    {
        boot_status_init(dir);
        boot_status_note_stage((int)BOOT_STAGE_DB_OPEN);
        boot_status_set_height(478544);
        boot_status_note_stage((int)BOOT_STAGE_READY);

        struct boot_status_snapshot out;
        char why[128];
        bool ok = boot_status_read(dir, &out, why, sizeof(why));
        BS_CHECK("writer beacon is readable", ok);
        BS_CHECK("writer reached serving phase",
                 strcmp(out.phase, "serving") == 0);
        BS_CHECK("writer stage is ready", strcmp(out.stage, "ready") == 0);
        BS_CHECK("writer marks serving true", out.serving == true);
        BS_CHECK("writer marks rpc_bound true", out.rpc_bound == true);
        BS_CHECK("writer carried the height", out.height == 478544);
        BS_CHECK("writer set a start time", out.started_unix > 0);

        /* Disarm so later tests' boot_stage_advance_to calls don't write into
         * this scratch dir (which we remove below). */
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
        char empty_dir[] = "/tmp/zcl_bootstatus_empty_XXXXXX";
        char *ed = mkdtemp(empty_dir);
        struct boot_status_snapshot out;
        char why[128];
        BS_CHECK("read of missing file returns false",
                 ed && !boot_status_read(ed, &out, why, sizeof(why)));

        bs_write_file(dir, "empty_status.json", "");
        /* point the reader at an explicitly malformed doc */
        bs_write_file(dir, ZCL_BOOT_STATUS_FILENAME, "not json at all {{{");
        BS_CHECK("read of malformed file returns false",
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
