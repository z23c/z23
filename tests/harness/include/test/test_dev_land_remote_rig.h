/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The local rig shared by the dev.land.send / receive / offer tests
 * (test_dev_land_remote.c) and the qualify / admission tests
 * (test_dev_land_remote_qualify.c): a bare origin, a queue-host checkout, a
 * sender clone, ssh/scp replaced by a logging stub, and small helpers to call
 * a leaf in-process. No network is touched. */
#ifndef ZCL_TEST_DEV_LAND_REMOTE_RIG_H
#define ZCL_TEST_DEV_LAND_REMOTE_RIG_H

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/state_root.h"
#include "test/test_core.h"
#include "util/spawn.h"

#include <stdint.h>
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

static inline void dlt_cd(const char *dir)
{
    if (chdir(dir) != 0) {
        printf("chdir FAILED\n");
        abort();
    }
}

static inline int dlt_run(const char *const *argv, char *out, size_t cap)
{
    char sink[2];
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             60000);
}

#define DLT_GIT(out, cap, dir, ...)                                          \
    dlt_run((const char *const[]){"git", "-C", dir, __VA_ARGS__, NULL}, out, \
            cap)

static inline bool dlt_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static inline bool dlt_commit(const char *dir, const char *file, const char *body)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, file);
    return dlt_write(path, body, 0644) &&
           DLT_GIT(NULL, 0, dir, "add", "-A") == 0 &&
           DLT_GIT(NULL, 0, dir, "commit", "--quiet", "--no-verify", "-m",
                   file) == 0;
}

static inline bool dlt_mark(const char *dir)
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
static inline bool dlt_stub(struct dlt_rig *r)
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

static inline bool dlt_rig(struct dlt_rig *r, const char *tag)
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

static inline void dlt_done(const struct dlt_rig *r)
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

static inline void dlt_begin(struct dlt_call *c, const char *leaf)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(), leaf, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land.v1");
}

static inline void dlt_end(struct dlt_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static inline bool dlt_refused(const struct dlt_call *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

static inline void dlt_receive_at(struct dlt_call *c, const char *cwd,
                           const char *bundle, const char *lane,
                           const char *checkout)
{
    dlt_begin(c, "dev.land.receive");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "lane", lane);
    (void)json_push_kv_str(&c->input, "note", "from the test");
    if (checkout)
        (void)json_push_kv_str(&c->input, "checkout", checkout);
    dlt_cd(cwd);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static inline void dlt_receive(struct dlt_call *c, const struct dlt_rig *r,
                        const char *bundle, const char *lane)
{
    dlt_receive_at(c, r->queue, bundle, lane, NULL);
}

static inline void dlt_send_co(struct dlt_call *c, const struct dlt_rig *r,
                        const char *note, const char *remote_checkout)
{
    dlt_begin(c, "dev.land.send");
    (void)json_push_kv_str(&c->input, "host", "queue-host");
    (void)json_push_kv_str(&c->input, "lane", "mac");
    if (note)
        (void)json_push_kv_str(&c->input, "note", note);
    if (remote_checkout)
        (void)json_push_kv_str(&c->input, "remote_checkout", remote_checkout);
    dlt_cd(r->sender);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static inline void dlt_send(struct dlt_call *c, const struct dlt_rig *r,
                     const char *note)
{
    dlt_send_co(c, r, note, NULL);
}

/* A lane z23-lint: answers --list with the core gates and fails the gate
 * named in build/precheck-fail, read relative to the cwd. */
#define DLT_PC_LINT                                                          \
    "#!/bin/sh\n"                                                            \
    "if [ \"$1\" = --list ]; then printf 'check-file-size-ceiling\\n"        \
    "check-cyclomatic-complexity\\ncheck-core-seal\\ncheck-arm-symbol-single\\n'; exit 0; fi\n" \
    "if [ -f build/precheck-fail ] && [ \"$1\" = \"$(cat build/precheck-fail)\" ]; then\n" \
    "  echo \"gate $1 failed\"; exit 1\n"                                    \
    "fi\n"                                                                   \
    "exit 0\n"

static inline void dlt_send_pc(struct dlt_call *c, const struct dlt_rig *r,
                        const char *note, const char *mode)
{
    dlt_begin(c, "dev.land.send");
    (void)json_push_kv_str(&c->input, "host", "queue-host");
    (void)json_push_kv_str(&c->input, "lane", "mac");
    if (note)
        (void)json_push_kv_str(&c->input, "note", note);
    if (mode)
        (void)json_push_kv_str(&c->input, "precheck", mode);
    dlt_cd(r->sender);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static inline bool dlt_bundle(const struct dlt_rig *r, const char *name, bool two,
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

static inline bool dlt_slurp(const char *path, char *out, size_t cap)
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

static inline void dlt_wt(const struct dlt_rig *r, const char *lane, char out[900])
{
    char st[600];
    (void)platform_state_root(st, sizeof(st));
    (void)snprintf(out, 900, "%s/land-remote/%s", st, lane);
    (void)r;
}

/* dev.land.send --commit and --bundle_out, on a fresh rig. */
static inline void dlt_send_x(struct dlt_call *c, const struct dlt_rig *r,
                       const char *commit, const char *bundle_out, bool host)
{
    dlt_begin(c, "dev.land.send");
    if (host)
        (void)json_push_kv_str(&c->input, "host", "queue-host");
    (void)json_push_kv_str(&c->input, "lane", "mac");
    if (commit)
        (void)json_push_kv_str(&c->input, "commit", commit);
    if (bundle_out)
        (void)json_push_kv_str(&c->input, "bundle_out", bundle_out);
    dlt_cd(r->sender);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

/* dev.land.attest_offer and dev.land.verify_offer_receipt. */
static inline void dlt_attest(struct dlt_call *c, const char *cwd, const char *bundle,
                       const char *offer, const char *out)
{
    dlt_begin(c, "dev.land.attest_offer");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "offer", offer);
    (void)json_push_kv_str(&c->input, "receipt_out", out);
    dlt_cd(cwd);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static inline void dlt_vfy(struct dlt_call *c, const char *receipt, const char *offer)
{
    dlt_begin(c, "dev.land.verify_offer_receipt");
    (void)json_push_kv_str(&c->input, "receipt", receipt);
    if (offer)
        (void)json_push_kv_str(&c->input, "offer", offer);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

/* Copies a receipt with the first character of one field's value changed. */
static inline bool dlt_tweak(const char *src, const char *dst, const char *key)
{
    char text[2048], pat[40];
    char *p;
    if (!dlt_slurp(src, text, sizeof(text)))
        return false;
    (void)snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(text, pat);
    p = p ? strchr(p + strlen(pat), ':') : NULL;
    p = p ? strchr(p, '"') : NULL;
    if (!p)
        return false;
    p[1] = p[1] == 'a' ? 'b' : 'a';
    return dlt_write(dst, text, 0644);
}

/* The qualify_offer and receive-policy cases (test_dev_land_remote_qualify.c);
 * failures, run from the test_dev_land_remote group. */
int dlq_remote_cases(void);

#endif
