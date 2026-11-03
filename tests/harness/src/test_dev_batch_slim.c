/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_batch_slim: dev.batch.slim (tools/command/native_dev_batch_slim.c),
 * the C form of the slim-stacks.sh bridge, on a temp lab with a fake systemctl
 * and a fake process table. Stacks: 3 and 20 and 100 are finished (old
 * build/), 5 has a fresh build, 10 has a running gate unit, 12 has a process
 * whose cwd is inside it, 7 has nothing to free. The cap is applied in version
 * order after the skips (3 and 20 go, 100 stays at --max 2, though it sorts
 * first as text); --dry-run deletes nothing; a symlink inside build/ is
 * removed without touching its target. */

#include "test/test_dev_batch_fixture.h"

#include <time.h>

static bool dbs_stack(const struct dbf *f, const char *n, bool build,
                      bool tmpd, long age_s)
{
    char dir[1500], p[1700];
    struct timeval tv[2];
    (void)snprintf(dir, sizeof(dir), "%s/development/z23/z23-stacks%s", f->home, n);
    if (!dbf_mkdirs(dir))
        return false;
    (void)snprintf(p, sizeof(p), "%s/keep.txt", dir);
    if (!dbf_put(p, "source\n"))
        return false;
    if (build) {
        (void)snprintf(p, sizeof(p), "%s/build/obj", dir);
        if (!dbf_mkdirs(p))
            return false;
        (void)snprintf(p, sizeof(p), "%s/build/obj/a.o", dir);
        if (!dbf_put(p, "o\n"))
            return false;
        (void)snprintf(p, sizeof(p), "%s/build", dir);
        tv[0].tv_sec = tv[1].tv_sec = time(NULL) - age_s;
        tv[0].tv_usec = tv[1].tv_usec = 0;
        if (utimes(p, tv) != 0)
            return false;
    }
    if (tmpd) {
        (void)snprintf(p, sizeof(p), "%s/test-tmp", dir);
        if (!dbf_mkdirs(p))
            return false;
    }
    return true;
}

static bool dbs_has(const struct dbf *f, const char *n, const char *rel)
{
    char p[1700];
    (void)snprintf(p, sizeof(p), "%s/development/z23/z23-stacks%s/%s", f->home, n, rel);
    return dbf_exists(p);
}

int test_dev_batch_slim(void);
int test_dev_batch_slim(void)
{
    int failures = 0;
    struct dbf f;
    char sysctl[1000], proc[1000], outside[1000], link[1700], dump[8192];
    struct zcl_command_reply reply;
    const char *dry[] = {"dry_run", NULL};

    ASSERT(dbf_setup(&f, "slim"));
    ASSERT(dbs_stack(&f, "3", true, true, 3 * 3600));
    ASSERT(dbs_stack(&f, "5", true, true, 600));
    ASSERT(dbs_stack(&f, "10", true, false, 3 * 3600));
    ASSERT(dbs_stack(&f, "12", true, false, 3 * 3600));
    ASSERT(dbs_stack(&f, "20", true, true, 3 * 3600));
    ASSERT(dbs_stack(&f, "100", true, false, 3 * 3600));
    ASSERT(dbs_stack(&f, "7", false, false, 0));
    (void)snprintf(sysctl, sizeof(sysctl), "%s/systemctl", f.fakes);
    ASSERT(dbf_exec(sysctl, "#!/bin/sh\necho '  z23-gate-stack-s10.service loaded active running gate'\n"));
    /* a process whose cwd is inside stack 12 */
    (void)snprintf(proc, sizeof(proc), "%s/proc", f.root);
    {
        char pd[1200], target[1700];
        (void)snprintf(pd, sizeof(pd), "%s/4242", proc);
        ASSERT(dbf_mkdirs(pd));
        (void)snprintf(target, sizeof(target),
                       "%s/development/z23/z23-stacks12/build/obj", f.home);
        (void)snprintf(link, sizeof(link), "%s/cwd", pd);
        ASSERT(symlink(target, link) == 0);
    }
    /* a symlink inside stack 3's build/ to a file outside it must survive */
    (void)snprintf(outside, sizeof(outside), "%s/outside.txt", f.root);
    ASSERT(dbf_put(outside, "precious\n"));
    (void)snprintf(link, sizeof(link),
                   "%s/development/z23/z23-stacks3/build/obj/out", f.home);
    ASSERT(symlink(outside, link) == 0);

    TEST("slim: the leaf is registered and declares its keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.batch.slim", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "dry_run") != NULL);
        ASSERT(strstr(spec->input_keys, "max") != NULL);
        PASS();
    }

    TEST("slim --dry-run: names what would be slimmed and deletes nothing") {
        const char *pairs[] = {"systemctl", sysctl, "proc_dir", proc, "max", "2", NULL};
        dbf_call(zcl_native_handle_dev_batch_slim, &f, pairs, dry, &reply, dump,
                 sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "slim-stacks: would slim z23-stacks3 (") != NULL);
        ASSERT(strstr(dump, "slim-stacks: would slim z23-stacks20 (") != NULL);
        ASSERT(strstr(dump, "would slim z23-stacks100") == NULL);
        ASSERT(strstr(dump, "\"count\":2") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(dbs_has(&f, "3", "build/obj/a.o") && dbs_has(&f, "20", "test-tmp"));
        PASS();
    }

    TEST("slim: finished stacks lose build/ and test-tmp/ in version order, up to --max; the rest stay") {
        const char *pairs[] = {"systemctl", sysctl, "proc_dir", proc, "max", "2", NULL};
        dbf_call(zcl_native_handle_dev_batch_slim, &f, pairs, NULL, &reply, dump,
                 sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "slim-stacks: slimmed z23-stacks3 (") != NULL);
        ASSERT(strstr(dump, "slim-stacks: slimmed z23-stacks20 (") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(!dbs_has(&f, "3", "build") && !dbs_has(&f, "3", "test-tmp"));
        ASSERT(!dbs_has(&f, "20", "build") && !dbs_has(&f, "20", "test-tmp"));
        ASSERT(dbs_has(&f, "3", "keep.txt") && dbs_has(&f, "20", "keep.txt"));
        ASSERT(dbf_exists(outside));
        /* skipped: fresh build, running unit, busy cwd, over the cap */
        ASSERT(dbs_has(&f, "5", "build/obj/a.o"));
        ASSERT(dbs_has(&f, "10", "build/obj/a.o"));
        ASSERT(dbs_has(&f, "12", "build/obj/a.o"));
        ASSERT(dbs_has(&f, "100", "build/obj/a.o"));
        PASS();
    }

    TEST("slim: a later call frees the stack the cap held back, and still spares the busy ones") {
        const char *pairs[] = {"systemctl", sysctl, "proc_dir", proc, NULL};
        dbf_call(zcl_native_handle_dev_batch_slim, &f, pairs, NULL, &reply, dump,
                 sizeof(dump));
        ASSERT(strstr(dump, "slim-stacks: slimmed z23-stacks100 (") != NULL);
        ASSERT(strstr(dump, "\"count\":1") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(!dbs_has(&f, "100", "build"));
        ASSERT(dbs_has(&f, "5", "build") && dbs_has(&f, "10", "build") &&
               dbs_has(&f, "12", "build"));
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(f.root);
    if (failures == 0)
        printf("test_dev_batch_slim: all passed\n");
    else
        printf("test_dev_batch_slim: %d FAILED\n", failures);
    return failures;
}
