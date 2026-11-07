/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_batch_ledger: dev.batch.requeue (tools/command/native_dev_batch_
 * ledger.c), the C form of the requeue.sh bridge, on a temp lab. A dirty lane
 * and a missing directory are refused with nothing written; a clean lane's
 * stacked.tsv rows are dropped and the lane is appended to stack-pending.txt
 * once, with the bridge's bytes (LANE<TAB>NOTE, rows of other lanes kept in
 * order); the call waits on the stack tick lock (flock(2)) while another
 * holder has it. */

#include "test/test_dev_batch_fixture.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/file.h>
#include <time.h>

struct dbl_run {
    const struct dbf *f;
    const char *lane;
    struct zcl_command_reply reply;
    char dump[2048];
};

static void *dbl_requeue_thread(void *arg)
{
    struct dbl_run *r = arg;
    const char *pairs[] = {"worktree", r->lane, "note", "waited", NULL};
    dbf_call(zcl_native_handle_dev_batch_requeue, r->f, pairs, NULL, &r->reply,
             r->dump, sizeof(r->dump));
    return NULL;
}

/* While another process holds the tick lock, requeue changes nothing; once
 * it is released the call completes. */
static bool dbl_waits_for_lock(const struct dbf *f, const char *lane,
                               const char *pending)
{
    char lockp[1000], text[4096];
    struct dbl_run r = {.f = f, .lane = lane};
    struct timespec nap = {0, 300 * 1000 * 1000};
    pthread_t th;
    int fd;
    bool held_unchanged, done_after;
    (void)snprintf(lockp, sizeof(lockp), "%s/.stack-tick.lock", f->state);
    fd = open(lockp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0)
        return false;
    if (pthread_create(&th, NULL, dbl_requeue_thread, &r) != 0) {
        (void)close(fd);
        return false;
    }
    (void)nanosleep(&nap, NULL);
    (void)dbf_slurp(pending, text, sizeof(text));
    held_unchanged = strstr(text, "waited") == NULL;
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
    (void)pthread_join(th, NULL);
    (void)dbf_slurp(pending, text, sizeof(text));
    done_after = strstr(text, "\twaited\n") != NULL &&
                 r.reply.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&r.reply);
    return held_unchanged && done_after;
}

int test_dev_batch_ledger(void);
int test_dev_batch_ledger(void)
{
    int failures = 0;
    struct dbf f;
    char la[900], lb[900], lc[900], sa[41], sb[41], sc[41];
    char ledger[1200], pending[1200], before[8192], after[8192], dump[4096];
    struct zcl_command_reply reply;

    ASSERT(dbf_setup(&f, "ledger"));
    ASSERT(dbf_lane(&f, "lane-a", "a1.c", la, sa));
    ASSERT(dbf_lane(&f, "lane-b", "b1.c", lb, sb));
    ASSERT(dbf_lane(&f, "lane-c", "c1.c", lc, sc));
    (void)snprintf(ledger, sizeof(ledger), "%s/stacked.tsv", f.state);
    (void)snprintf(pending, sizeof(pending), "%s/stack-pending.txt", f.state);
    {
        char rows[4096];
        (void)snprintf(rows, sizeof(rows), "%s\t%s\ts10\n%s\t%s\ts10\n%s\t%s\ts11\n",
                       la, sa, lb, sb, la, sa);
        ASSERT(dbf_put(ledger, rows));
        ASSERT(dbf_put(pending, "/elsewhere/lane\tearlier note\n"));
    }

    TEST("requeue: the leaf is registered and declares its keys") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "dev.batch.requeue", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "worktree") != NULL);
        ASSERT(strstr(spec->input_keys, "state_dir") != NULL);
        PASS();
    }

    TEST("requeue: a dirty lane is refused with a body and nothing is written") {
        char mod[1000];
        (void)snprintf(mod, sizeof(mod), "%s/a1.c", la);
        ASSERT(dbf_put(mod, "int dirty;\n"));
        ASSERT(dbf_slurp(ledger, before, sizeof(before)));
        const char *pairs[] = {"worktree", la, "note", "n", NULL};
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "LANE_DIRTY");
        ASSERT(strstr(reply.error.message, "uncommitted tracked changes") != NULL);
        ASSERT(dbf_slurp(ledger, after, sizeof(after)));
        ASSERT_STR_EQ(before, after);
        ASSERT(dbf_slurp(pending, after, sizeof(after)));
        ASSERT_STR_EQ(after, "/elsewhere/lane\tearlier note\n");
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("requeue: a dirty lane with a path longer than the message keeps its reason") {
        char name[240], lp[900], sha[41], mod[1000];
        (void)snprintf(name, sizeof(name), "long-%0200d", 0);
        ASSERT(dbf_lane(&f, name, "x.c", lp, sha));
        ASSERT(strlen(lp) > sizeof(reply.error.message));
        (void)snprintf(mod, sizeof(mod), "%s/x.c", lp);
        ASSERT(dbf_put(mod, "int dirty;\n"));
        {
            const char *pairs[] = {"worktree", lp, "note", "n", NULL};
            dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                     dump, sizeof(dump));
        }
        ASSERT(reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "LANE_DIRTY");
        ASSERT(strstr(reply.error.message, "uncommitted tracked changes") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("requeue: a missing lane with a path longer than the message keeps its reason") {
        char gone[512];
        (void)snprintf(gone, sizeof(gone), "/nonexistent/%0120d/%0120d/%0120d",
                       0, 0, 0);
        ASSERT(strlen(gone) > sizeof(reply.error.message));
        {
            const char *pairs[] = {"worktree", gone, "note", "n", NULL};
            dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                     dump, sizeof(dump));
        }
        ASSERT_STR_EQ(reply.error.code, "NOT_A_LANE");
        ASSERT(strstr(reply.error.message, "not a directory") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("requeue: a missing directory, a missing or tabbed note are refused") {
        const char *gone[] = {"worktree", "/nonexistent/lane-z", "note", "n", NULL};
        const char *nonote[] = {"worktree", lb, NULL};
        const char *tabbed[] = {"worktree", lb, "note", "a\tb", NULL};
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, gone, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "NOT_A_LANE");
        zcl_command_reply_free(&reply);
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, nonote, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "BAD_INPUT");
        zcl_command_reply_free(&reply);
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, tabbed, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "BAD_INPUT");
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(ledger, after, sizeof(after)));
        ASSERT_STR_EQ(before, after);
        PASS();
    }

    TEST("requeue: a clean lane's ledger rows go and it is pending once, in the bridge's bytes") {
        char want[4096], got[4096];
        const char *pairs[] = {"worktree", lb, "note", "lane-b: triaged, fixed", NULL};
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "\"ledger_rows_dropped\":1") != NULL);
        ASSERT(strstr(dump, "requeue: lane-b at ") != NULL);
        zcl_command_reply_free(&reply);
        (void)snprintf(want, sizeof(want), "%s\t%s\ts10\n%s\t%s\ts11\n", la, sa,
                       la, sa);
        ASSERT(dbf_slurp(ledger, got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        (void)snprintf(want, sizeof(want),
                       "/elsewhere/lane\tearlier note\n%s\tlane-b: triaged, fixed\n",
                       lb);
        ASSERT(dbf_slurp(pending, got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        /* A second requeue changes nothing: the lane is pending already. */
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(pending, after, sizeof(after)));
        ASSERT_STR_EQ(got, after);
        PASS();
    }

    TEST("requeue: a bare lane name resolves under the lab, every row of the lane goes, state-dir is honoured") {
        char got[4096], where[1300];
        const char *co[] = {"checkout", "--", "a1.c", NULL};
        const char *pairs[] = {"worktree", "lane-a", "note", "bare", "state-dir", where, NULL};
        (void)snprintf(where, sizeof(where), "%s", f.state);
        ASSERT(dbf_git(la, co));
        dbf_call(zcl_native_handle_dev_batch_requeue, &f, pairs, NULL, &reply,
                 dump, sizeof(dump));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strstr(dump, "\"ledger_rows_dropped\":2") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(dbf_slurp(ledger, got, sizeof(got)));
        ASSERT_STR_EQ(got, "");
        ASSERT(dbf_slurp(pending, got, sizeof(got)));
        ASSERT(strstr(got, "lane-a\tbare\n") != NULL);
        PASS();
    }

    TEST("requeue: the call waits while another process holds the tick lock") {
        ASSERT(dbl_waits_for_lock(&f, lc, pending));
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(f.root);
    if (failures == 0)
        printf("test_dev_batch_ledger: all passed\n");
    else
        printf("test_dev_batch_ledger: %d FAILED\n", failures);
    return failures;
}
