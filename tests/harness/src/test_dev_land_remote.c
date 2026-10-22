/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.receive / dev.land.send
 * (tools/command/native_dev_land_remote.c). Local fixtures only: a bare
 * origin, a queue-host checkout, a sender clone, and ssh/scp replaced through
 * ZCL_LAND_REMOTE_XPORT by a stub that logs argv (tab separated) and copies
 * the bundle into a local inbox. No network is touched. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/state_root.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct dlt_rig {
    char base[512], origin[600], queue[600], sender[600], state[700];
    char stub[700], log[700], inbox[700], cfg[700], cwd[1024];
    char base_sha[64];
};

static void dlt_cd(const char *dir)
{
    if (chdir(dir) != 0) {
        printf("chdir FAILED\n");
        abort();
    }
}

static int dlt_run(const char *const *argv, char *out, size_t cap)
{
    char sink[2];
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             60000);
}

#define DLT_GIT(out, cap, dir, ...)                                          \
    dlt_run((const char *const[]){"git", "-C", dir, __VA_ARGS__, NULL}, out, \
            cap)

static bool dlt_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static bool dlt_commit(const char *dir, const char *file, const char *body)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, file);
    return dlt_write(path, body, 0644) &&
           DLT_GIT(NULL, 0, dir, "add", "-A") == 0 &&
           DLT_GIT(NULL, 0, dir, "commit", "--quiet", "--no-verify", "-m",
                   file) == 0;
}

static bool dlt_mark(const char *dir)
{
    char p[1400];
    (void)DLT_GIT(NULL, 0, dir, "init", "--quiet", "-b", "main");
    (void)snprintf(p, sizeof(p), "%s/engine", dir);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/engine/composition", dir);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/engine/composition/commands", dir);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/tools", dir);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/tools/dev", dir);
    (void)mkdir(p, 0755);
    return true;
}

/* A stub for ssh and scp: logs "<prog>\t<arg>...", copies the bundle scp is
 * given into the inbox, and answers a receive with canned JSON. */
static bool dlt_stub(struct dlt_rig *r)
{
    char body[2400];
    (void)snprintf(
        body, sizeof(body),
        "#!/bin/sh\nprog=$1\nshift\n"
        "{ printf '%%s' \"$prog\"; for a in \"$@\"; do printf '\\t%%s' \"$a\"; "
        "done; printf '\\n'; } >> '%s'\n"
        "case $prog in\n"
        "scp) cp \"$4\" '%s/' ;;\n"
        "ssh) case \"$*\" in *receive*) "
        "printf '%%s\\n' '{\"ok\":true,\"seq\":7}' ;; esac ;;\n"
        "esac\nexit 0\n",
        r->log, r->inbox);
    return dlt_write(r->stub, body, 0755);
}

static bool dlt_rig(struct dlt_rig *r, const char *tag)
{
    char p[1400];
    memset(r, 0, sizeof(*r));
    if (!getcwd(r->cwd, sizeof(r->cwd)))
        return false;
    test_make_tmpdir(r->base, sizeof(r->base), "dev_land_remote", tag);
    (void)snprintf(r->origin, sizeof(r->origin), "%s/origin.git", r->base);
    (void)snprintf(r->queue, sizeof(r->queue), "%s/queue", r->base);
    (void)snprintf(r->sender, sizeof(r->sender), "%s/sender", r->base);
    (void)snprintf(r->state, sizeof(r->state), "%s/state", r->base);
    (void)snprintf(r->stub, sizeof(r->stub), "%s/xport.sh", r->base);
    (void)snprintf(r->log, sizeof(r->log), "%s/xport.log", r->base);
    (void)snprintf(r->inbox, sizeof(r->inbox), "%s/inbox", r->base);
    (void)snprintf(r->cfg, sizeof(r->cfg), "%s/gitconfig", r->base);
    (void)mkdir(r->state, 0700);
    (void)mkdir(r->inbox, 0700);
    if (!dlt_write(r->cfg,
                   "[user]\n\tname = land\n\temail = land@z23.invalid\n"
                   "[commit]\n\tgpgsign = false\n[init]\n"
                   "\tdefaultBranch = main\n",
                   0644))
        return false;
    (void)setenv("GIT_CONFIG_GLOBAL", r->cfg, 1);
    (void)setenv("GIT_CONFIG_SYSTEM", "/dev/null", 1);
    (void)setenv("XDG_STATE_HOME", r->state, 1);
    (void)setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    (void)setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    (void)setenv("ZCL_LAND_REMOTE_XPORT", r->stub, 1);
    if (DLT_GIT(NULL, 0, r->base, "init", "--quiet", "--bare", "-b", "main",
                "origin.git") != 0)
        return false;
    (void)mkdir(r->queue, 0755);
    (void)dlt_mark(r->queue);
    (void)snprintf(p, sizeof(p), "%s/Makefile", r->queue);
    if (!dlt_write(p, "all:\n", 0644))
        return false;
    (void)snprintf(p, sizeof(p), "%s/engine/composition/commands/root.def",
                   r->queue);
    (void)dlt_write(p, "\n", 0644);
    (void)snprintf(p, sizeof(p), "%s/tools/dev/test_group_catalog.def",
                   r->queue);
    (void)dlt_write(p, "\n", 0644);
    if (!dlt_commit(r->queue, "base.txt", "base\n") ||
        DLT_GIT(NULL, 0, r->queue, "remote", "add", "origin", r->origin) != 0 ||
        DLT_GIT(NULL, 0, r->queue, "push", "--quiet", "origin", "main") != 0 ||
        DLT_GIT(NULL, 0, r->base, "clone", "--quiet", r->origin, "sender") != 0)
        return false;
    (void)dlt_stub(r);
    if (DLT_GIT(r->base_sha, sizeof(r->base_sha), r->queue, "rev-parse",
                "HEAD") != 0)
        return false;
    r->base_sha[strcspn(r->base_sha, "\n")] = '\0';
    return true;
}

static void dlt_done(const struct dlt_rig *r)
{
    dlt_cd(r->cwd);
    (void)unsetenv("ZCL_LAND_PROOF_STUB");
    (void)unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    (void)unsetenv("ZCL_LAND_REMOTE_XPORT");
    (void)unsetenv("GIT_CONFIG_GLOBAL");
    (void)unsetenv("GIT_CONFIG_SYSTEM");
    (void)unsetenv("XDG_STATE_HOME");
}

struct dlt_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlt_begin(struct dlt_call *c, const char *leaf)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(), leaf, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land.v1");
}

static void dlt_end(struct dlt_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dlt_refused(const struct dlt_call *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

static void dlt_receive(struct dlt_call *c, const struct dlt_rig *r,
                        const char *bundle, const char *lane)
{
    dlt_begin(c, "dev.land.receive");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "lane", lane);
    (void)json_push_kv_str(&c->input, "note", "from the test");
    dlt_cd(r->queue);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static void dlt_send(struct dlt_call *c, const struct dlt_rig *r,
                     const char *note)
{
    dlt_begin(c, "dev.land.send");
    (void)json_push_kv_str(&c->input, "host", "queue-host");
    (void)json_push_kv_str(&c->input, "lane", "mac");
    if (note)
        (void)json_push_kv_str(&c->input, "note", note);
    dlt_cd(r->sender);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static bool dlt_bundle(const struct dlt_rig *r, const char *name, bool two,
                       char out[700])
{
    (void)snprintf(out, 700, "%s/%s.bundle", r->base, name);
    if (two)
        return DLT_GIT(NULL, 0, r->sender, "branch", "-f", "extra", "HEAD") ==
                   0 &&
               DLT_GIT(NULL, 0, r->sender, "bundle", "create", "--quiet", out,
                       "HEAD", "extra", "^origin/main") == 0;
    return DLT_GIT(NULL, 0, r->sender, "bundle", "create", "--quiet", out,
                   "HEAD", "^origin/main") == 0;
}

static bool dlt_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    (void)fclose(f);
    return true;
}

static void dlt_wt(const struct dlt_rig *r, const char *lane, char out[900])
{
    char st[600];
    (void)platform_state_root(st, sizeof(st));
    (void)snprintf(out, 900, "%s/land-remote/%s", st, lane);
    (void)r;
}

static int dlt_receive_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char bundle[700], two[700], wt[900], head[100], text[256];
    if (!dlt_rig(&r, "recv") || !dlt_commit(r.sender, "a.txt", "a\n") ||
        !dlt_bundle(&r, "one", false, bundle) ||
        !dlt_bundle(&r, "two", true, two)) {
        printf("rig setup FAILED\n");
        return 1;
    }
    dlt_wt(&r, "mac", wt);

    TEST("land.receive: a good bundle queues a row from the lane worktree") {
        dlt_receive(&c, &r, bundle, "mac");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&c.reply.data, "seq")) >= 1);
        ASSERT(DLT_GIT(head, sizeof(head), wt, "rev-parse", "HEAD") == 0);
        ASSERT(DLT_GIT(text, sizeof(text), r.queue, "rev-parse",
                       "refs/heads/remote/mac") == 0);
        ASSERT_STR_EQ(head, text);
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: a bundle with two heads refuses RECEIVE_BAD_BUNDLE") {
        dlt_receive(&c, &r, two, "dual");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_BUNDLE"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: a bad lane name refuses RECEIVE_BAD_LANE") {
        dlt_receive(&c, &r, bundle, "Bad_Lane");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_LANE"));
        dlt_end(&c);
        dlt_receive(&c, &r, bundle, "-lead");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_LANE"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: a missing bundle refuses RECEIVE_BAD_BUNDLE") {
        dlt_receive(&c, &r, "/nonexistent/none.bundle", "mac");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_BUNDLE"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: a dirty lane worktree refuses and is left untouched") {
        char file[1000], again[700], before[100];
        (void)snprintf(file, sizeof(file), "%s/a.txt", wt);
        ASSERT(dlt_write(file, "edited\n", 0644));
        ASSERT(dlt_commit(r.sender, "b.txt", "b\n"));
        ASSERT(dlt_bundle(&r, "three", false, again));
        ASSERT(DLT_GIT(before, sizeof(before), wt, "rev-parse", "HEAD") == 0);
        dlt_receive(&c, &r, again, "mac");
        ASSERT(dlt_refused(&c, "RECEIVE_WORKTREE_DIRTY"));
        ASSERT(strstr(c.reply.error.evidence, "land-remote/mac") != NULL);
        ASSERT(dlt_slurp(file, text, sizeof(text)));
        ASSERT_STR_EQ(text, "edited\n");
        ASSERT(DLT_GIT(head, sizeof(head), wt, "rev-parse", "HEAD") == 0);
        ASSERT_STR_EQ(head, before);
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: an unsigned tip relays TIP_UNSIGNED") {
        (void)unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlt_receive(&c, &r, bundle, "fresh");
        ASSERT(dlt_refused(&c, "TIP_UNSIGNED"));
        dlt_end(&c);
        PASS();
    }

_test_next:;
    dlt_done(&r);
    return failures;
}

static int dlt_send_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char logtext[4096], copied[900], out[2048], tip[100];
    if (!dlt_rig(&r, "send")) {
        printf("rig setup FAILED\n");
        return 1;
    }

    TEST("land.send: a dirty tracked tree refuses SEND_DIRTY_TREE") {
        char p[900];
        (void)snprintf(p, sizeof(p), "%s/base.txt", r.sender);
        ASSERT(dlt_write(p, "dirty\n", 0644));
        dlt_send(&c, &r, NULL);
        ASSERT(dlt_refused(&c, "SEND_DIRTY_TREE"));
        ASSERT(access(r.log, F_OK) != 0);
        dlt_end(&c);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "checkout", "--quiet", "--",
                       "base.txt") == 0);
        PASS();
    }

    TEST("land.send: nothing ahead of origin/main refuses SEND_NOTHING_AHEAD") {
        dlt_send(&c, &r, NULL);
        ASSERT(dlt_refused(&c, "SEND_NOTHING_AHEAD"));
        ASSERT(access(r.log, F_OK) != 0);
        dlt_end(&c);
        PASS();
    }

    TEST("land.send: a forbidden character in the note refuses") {
        ASSERT(dlt_commit(r.sender, "a.txt", "a\n"));
        dlt_send(&c, &r, "x; rm -rf ~");
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_send(&c, &r, "it's");
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        ASSERT(access(r.log, F_OK) != 0);
        dlt_end(&c);
        PASS();
    }

    TEST("land.send: bundle holds origin/main..HEAD and the note is one "
         "quoted argument") {
        ASSERT(dlt_commit(r.sender, "b.txt", "b\n"));
        dlt_send(&c, &r, "fix the thing (v2)");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(json_get(&c.reply.data, "remote"), "ok")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "ahead")), (int64_t)2);
        ASSERT(DLT_GIT(tip, sizeof(tip), r.sender, "rev-parse", "HEAD") == 0);
        tip[strcspn(tip, "\n")] = '\0';
        (void)snprintf(copied, sizeof(copied), "%s/mac-%.12s.bundle", r.inbox,
                       tip);
        ASSERT(access(copied, F_OK) == 0);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "bundle", "verify", copied) ==
               0);
        ASSERT(strstr(out, r.base_sha) != NULL);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "bundle", "list-heads",
                       copied) == 0);
        ASSERT(strncmp(out, tip, 40) == 0);
        ASSERT(DLT_GIT(NULL, 0, r.queue, "fetch", "--quiet", copied,
                       "HEAD:refs/heads/chk") == 0);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "rev-list", "--count",
                       "origin/main..chk") == 0);
        ASSERT_STR_EQ(out, "2\n");
        ASSERT(dlt_slurp(r.log, logtext, sizeof(logtext)));
        ASSERT(strstr(logtext, "\t'--note=fix the thing (v2)'\n") != NULL ||
               strstr(logtext, "\t'--note=fix the thing (v2)'") != NULL);
        ASSERT(strstr(logtext, "\t'--lane=mac'\t") != NULL ||
               strstr(logtext, "\t'--lane=mac'\n") != NULL);
        ASSERT(strstr(logtext, "\tqueue-host\tz23-dev\tdev\tland\treceive\t'--bundle=") != NULL);
        dlt_end(&c);
        PASS();
    }

_test_next:;
    dlt_done(&r);
    return failures;
}

int test_dev_land_remote(void);
int test_dev_land_remote(void)
{
    int failures = dlt_receive_cases() + dlt_send_cases();
    if (failures == 0)
        printf("test_dev_land_remote: all passed\n");
    else
        printf("test_dev_land_remote: %d FAILED\n", failures);
    return failures;
}
