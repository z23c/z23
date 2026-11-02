/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.receive / dev.land.send
 * (tools/command/native_dev_land_remote.c). Local fixtures only: a bare
 * origin, a queue-host checkout, a sender clone, and ssh/scp replaced through
 * ZCL_LAND_REMOTE_XPORT by a stub that logs argv (tab separated) and copies
 * the bundle into a local inbox. No network is touched. */

#include "test/test_core.h"
#include "test/test_dev_land_remote_rig.h"

#include "command/native_command.h"
#include "command/native_dev_land_precheck.h"
#include "command/native_dev_land_remote_shared.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/logical_cpu.h"
#include "platform/state_root.h"
#include "util/spawn.h"
#include "zsha256/zsha256.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

    TEST("land.receive: --checkout from an unrelated cwd queues a row") {
        dlt_receive_at(&c, "/", bundle, "away", r.queue);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&c.reply.data, "seq")) >= 1);
        ASSERT(DLT_GIT(text, sizeof(text), r.queue, "rev-parse",
                       "refs/heads/remote/away") == 0);
        dlt_end(&c);
        PASS();
    }

    TEST("land.receive: --checkout naming a non-checkout refuses "
         "RECEIVE_BAD_CHECKOUT") {
        dlt_receive_at(&c, r.queue, bundle, "away2", "/");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_CHECKOUT"));
        dlt_end(&c);
        dlt_receive_at(&c, r.queue, bundle, "away2", "relative/dir");
        ASSERT(dlt_refused(&c, "RECEIVE_BAD_CHECKOUT"));
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
        ASSERT(strstr(logtext, "\t'--lane=mac'\t'--note=fix the thing (v2)'\n") != NULL);
        ASSERT(strstr(logtext, "\tqueue-host\tz23-dev\tdev\tland\treceive\t'--bundle=") != NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.send: --remote_checkout is one quoted --checkout argument") {
        char logtext2[8192];
        dlt_send_co(&c, &r, NULL, "/srv/queue-co");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        ASSERT(dlt_slurp(r.log, logtext2, sizeof(logtext2)));
        ASSERT(strstr(logtext2, "\t'--lane=mac'\t'--checkout=/srv/queue-co'\n") !=
               NULL);
        PASS();
    }

    TEST("land.send: a relative or dashed remote_checkout refuses") {
        dlt_send_co(&c, &r, NULL, "relative/co");
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_send_co(&c, &r, NULL, "-oProxyCommand=x");
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_send_co(&c, &r, NULL, "/srv/it's");
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        PASS();
    }


    TEST("land.send: a failing precheck refuses before any bundle or ssh") {
        char lint[900], fail[900];
        (void)snprintf(fail, sizeof(fail), "%s/build", r.sender);
        (void)mkdir(fail, 0755);
        (void)snprintf(lint, sizeof(lint), "%s/build/bin", r.sender);
        (void)mkdir(lint, 0755);
        (void)snprintf(lint, sizeof(lint), "%s/build/bin/z23-lint", r.sender);
        (void)snprintf(fail, sizeof(fail), "%s/build/precheck-fail", r.sender);
        ASSERT(dlt_write(lint, DLT_PC_LINT, 0755));
        ASSERT(dlt_write(fail, "check-core-seal\n", 0644));
        (void)remove(r.log);
        zcl_dev_land_precheck_test_force(true);
        dlt_send_pc(&c, &r, "n", NULL);
        ASSERT(dlt_refused(&c, "PRECHECK_FAILED"));
        ASSERT(access(r.log, F_OK) != 0);
        dlt_end(&c);
        PASS();
    }

    TEST("land.send: precheck=skip sends with the note marker, no gate runs") {
        char logtext3[8192];
        (void)remove(r.log);
        dlt_send_pc(&c, &r, "why", "skip");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        ASSERT(dlt_slurp(r.log, logtext3, sizeof(logtext3)));
        ASSERT(strstr(logtext3, "'--note=why [precheck skipped]'") != NULL);
        PASS();
    }

    TEST("land.send: a bad or caller-supplied `sent` precheck refuses BAD_INPUT") {
        (void)remove(r.log);
        dlt_send_pc(&c, &r, "n", "bogus");
        ASSERT(dlt_refused(&c, "BAD_INPUT"));
        dlt_end(&c);
        dlt_send_pc(&c, &r, "n", "sent");
        ASSERT(dlt_refused(&c, "BAD_INPUT"));
        ASSERT(strstr(c.reply.error.message, "skip") != NULL);
        dlt_end(&c);
        ASSERT(access(r.log, F_OK) != 0);
        PASS();
    }

_test_next:;
    zcl_dev_land_precheck_test_force(false);
    dlt_done(&r);
    return failures;
}

static bool dlt_sha_file(const char *path, char hex[ZSHA256_HEX_LEN])
{
    static uint8_t blob[1 << 20];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f)
        return false;
    n = fread(blob, 1, sizeof(blob), f);
    if (fclose(f) != 0 || n == 0 || n == sizeof(blob))
        return false;
    zsha256_hex(blob, n, hex);
    return true;
}

static int dlt_single_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char one[64], two[64], out[4096], path[900], hex[ZSHA256_HEX_LEN];
    char copied[900], spec[256], *ref;
    if (!dlt_rig(&r, "single")) {
        printf("rig setup FAILED\n");
        return 1;
    }
    ASSERT(dlt_commit(r.sender, "a.txt", "a\n"));
    ASSERT(dlt_commit(r.sender, "b.txt", "b\n"));
    ASSERT(DLT_GIT(one, sizeof(one), r.sender, "rev-parse", "HEAD~1") == 0);
    ASSERT(DLT_GIT(two, sizeof(two), r.sender, "rev-parse", "HEAD") == 0);
    one[strcspn(one, "\n")] = '\0';
    two[strcspn(two, "\n")] = '\0';
    (void)snprintf(copied, sizeof(copied), "%s/mac-%.12s.bundle", r.inbox, one);

    TEST("land.send --commit: the second commit of a mixed branch refuses "
         "SEND_NOT_SINGLE") {
        dlt_send_x(&c, &r, two, NULL, true);
        ASSERT(dlt_refused(&c, "SEND_NOT_SINGLE"));
        ASSERT(strstr(c.reply.error.message, "cherry-pick") != NULL);
        dlt_end(&c);
        ASSERT(access(r.log, F_OK) != 0);
        PASS();
    }

    TEST("land.send --commit: an unresolvable or dashed commit refuses "
         "SEND_BAD_ARGUMENT") {
        dlt_send_x(&c, &r, "no-such-commit", NULL, true);
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_send_x(&c, &r, "-x", NULL, true);
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.send --commit: the first commit sends alone, dirty tree and "
         "all") {
        char p[900];
        (void)snprintf(p, sizeof(p), "%s/base.txt", r.sender);
        ASSERT(dlt_write(p, "dirty\n", 0644));
        dlt_send_x(&c, &r, one, NULL, true);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "ahead")), (int64_t)1);
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "commit")), one) == 0);
        ASSERT(json_get_bool(json_get(json_get(&c.reply.data, "remote"), "ok")));
        dlt_end(&c);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "checkout", "--quiet", "--",
                       "base.txt") == 0);
        ASSERT(access(copied, F_OK) == 0);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "bundle", "list-heads",
                       copied) == 0);
        ASSERT(strncmp(out, one, 40) == 0);
        ref = strchr(out, ' ');
        ASSERT(ref != NULL);
        ref++;
        ref[strcspn(ref, "\n")] = '\0';
        (void)snprintf(spec, sizeof(spec), "%s:refs/heads/one", ref);
        ASSERT(DLT_GIT(NULL, 0, r.queue, "fetch", "--quiet", copied, spec) == 0);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "rev-list", "--count",
                       "origin/main..refs/heads/one") == 0);
        ASSERT_STR_EQ(out, "1\n");
        PASS();
    }

    TEST("land.send --bundle_out: writes the bundle and its sha256 with no "
         "ssh or scp") {
        char b[900];
        (void)snprintf(b, sizeof(b), "%s/out.bundle", r.base);
        (void)remove(r.log);
        dlt_send_x(&c, &r, one, b, false);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(access(b, F_OK) == 0);
        ASSERT(access(r.log, F_OK) != 0);
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "bundle")), b) == 0);
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "commit")), one) == 0);
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "lane")), "mac") == 0);
        ASSERT(dlt_sha_file(b, hex));
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "bundle_sha256")),
                      hex) == 0);
        dlt_end(&c);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "bundle", "verify", b) == 0);
        ASSERT(DLT_GIT(out, sizeof(out), r.queue, "bundle", "list-heads", b) == 0);
        ASSERT(strncmp(out, one, 40) == 0);
        PASS();
    }

    TEST("land.send: no lane on branch lane/<x> sends as lane <x>; a branch "
         "that is no lane name refuses naming it") {
        char b[900];
        (void)snprintf(b, sizeof(b), "%s/derived.bundle", r.base);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "switch", "--quiet", "-c",
                       "lane/zed") == 0);
        dlt_begin(&c, "dev.land.send");
        (void)json_push_kv_str(&c.input, "commit", one);
        (void)json_push_kv_str(&c.input, "bundle_out", b);
        dlt_cd(r.sender);
        zcl_native_handle_dev_land_remote(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "lane")), "zed");
        dlt_end(&c);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "switch", "--quiet", "-c",
                       "Not_A_Lane") == 0);
        dlt_begin(&c, "dev.land.send");
        (void)json_push_kv_str(&c.input, "commit", one);
        (void)json_push_kv_str(&c.input, "bundle_out", b);
        dlt_cd(r.sender);
        zcl_native_handle_dev_land_remote(&c.request, &c.reply);
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        ASSERT(strstr(c.reply.error.message, "Not_A_Lane") != NULL);
        ASSERT(strstr(c.reply.error.message, "--lane=<name>") != NULL);
        dlt_end(&c);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "switch", "--quiet", "-") == 0);
        ASSERT(DLT_GIT(NULL, 0, r.sender, "branch", "--quiet", "-D",
                       "Not_A_Lane") == 0);
        PASS();
    }

    TEST("land.send --bundle_out: an existing path refuses SEND_BUNDLE_EXISTS") {
        (void)snprintf(path, sizeof(path), "%s/out.bundle", r.base);
        dlt_send_x(&c, &r, one, path, false);
        ASSERT(dlt_refused(&c, "SEND_BUNDLE_EXISTS"));
        dlt_end(&c);
        ASSERT(access(r.log, F_OK) != 0);
        PASS();
    }

    TEST("land.send: no host and no bundle_out refuses SEND_BAD_ARGUMENT, "
         "and a commit outside the revision characters refuses too") {
        dlt_send_x(&c, &r, NULL, NULL, false);
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_send_x(&c, &r, "abc;def", NULL, true);
        ASSERT(dlt_refused(&c, "SEND_BAD_ARGUMENT"));
        dlt_end(&c);
        ASSERT(access(r.log, F_OK) != 0);
        PASS();
    }

    TEST("land.send --commit: a commit already on origin/main refuses "
         "SEND_NOTHING_AHEAD") {
        ASSERT(DLT_GIT(NULL, 0, r.sender, "push", "--quiet", "origin",
                       "HEAD:refs/heads/landed") == 0);
        ASSERT(DLT_GIT(NULL, 0, r.origin, "update-ref", "refs/heads/main",
                       one) == 0);
        dlt_send_x(&c, &r, one, NULL, true);
        ASSERT(dlt_refused(&c, "SEND_NOTHING_AHEAD"));
        dlt_end(&c);
        PASS();
    }

_test_next:;
    zcl_dev_land_precheck_test_force(false);
    dlt_done(&r);
    return failures;
}

/* dev.land.send's offer manifest and dev.land.check_offer, on a fresh rig. */
static void dlt_check(struct dlt_call *c, const char *cwd, const char *bundle,
                      const char *offer, const char *repo)
{
    dlt_begin(c, "dev.land.check_offer");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "offer", offer);
    if (repo)
        (void)json_push_kv_str(&c->input, "repo", repo);
    dlt_cd(cwd);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

static bool dlt_manifest(const char *path, const char *schema,
                         const char *commit, const char *base,
                         const char *sha, const char *lane)
{
    char body[600];
    (void)snprintf(body, sizeof(body),
                   "{\"schema\":\"%s\",\"commit\":\"%s\",\"base\":\"%s\","
                   "\"bundle_sha256\":\"%s\",\"lane\":\"%s\"}\n",
                   schema, commit, base, sha, lane);
    return dlt_write(path, body, 0644);
}

/* Copies src to dst with the last byte flipped. */
static bool dlt_flip(const char *src, const char *dst)
{
    static unsigned char blob[1 << 16];
    FILE *f = fopen(src, "rb");
    size_t n;
    bool ok;
    if (!f)
        return false;
    n = fread(blob, 1, sizeof(blob), f);
    ok = !ferror(f);
    ok = fclose(f) == 0 && ok && n > 0 && n < sizeof(blob);
    if (!ok)
        return false;
    blob[n - 1] ^= 0xff;
    f = fopen(dst, "wb");
    if (!f)
        return false;
    ok = fwrite(blob, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static int dlt_offer_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char tip[64], b[900], o[900], bad[900], mo[900], bsha[ZSHA256_HEX_LEN];
    char text[1024];
    struct json_value doc;
    if (!dlt_rig(&r, "offer") || !dlt_commit(r.sender, "a.txt", "a\n") ||
        DLT_GIT(tip, sizeof(tip), r.sender, "rev-parse", "HEAD") != 0) {
        printf("rig setup FAILED\n");
        return 1;
    }
    tip[strcspn(tip, "\n")] = '\0';
    (void)snprintf(b, sizeof(b), "%s/o.bundle", r.base);
    (void)snprintf(o, sizeof(o), "%s/o.bundle.offer.json", r.base);
    (void)snprintf(bad, sizeof(bad), "%s/bad.bundle", r.base);
    (void)snprintf(mo, sizeof(mo), "%s/mo.offer.json", r.base);

    TEST("land.send --bundle_out: writes <bundle_out>.offer.json and reports "
         "it as data.offer") {
        dlt_send_x(&c, &r, tip, b, false);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "offer")), o) == 0);
        (void)snprintf(bsha, sizeof(bsha), "%s",
                       json_get_str(json_get(&c.reply.data, "bundle_sha256")));
        dlt_end(&c);
        ASSERT(dlt_slurp(o, text, sizeof(text)));
        json_init(&doc);
        ASSERT(json_read(&doc, text, strlen(text)));
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "schema")),
                      "zcl.dev_land_offer.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "commit")), tip);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "base")), r.base_sha);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "bundle_sha256")), bsha);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "lane")), "mac");
        json_free(&doc);
        PASS();
    }

    TEST("land.check_offer: a sent bundle and its manifest check ok") {
        dlt_check(&c, r.queue, b, o, NULL);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "commit")), tip);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "base")),
                      r.base_sha);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "bundle_sha256")),
                      bsha);
        dlt_end(&c);
        dlt_check(&c, "/", b, o, r.queue);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        PASS();
    }

    TEST("land.check_offer: one flipped bundle byte refuses OFFER_SHA_MISMATCH") {
        ASSERT(dlt_flip(b, bad));
        dlt_check(&c, r.queue, bad, o, NULL);
        ASSERT(dlt_refused(&c, "OFFER_SHA_MISMATCH"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.check_offer: a manifest naming another commit refuses "
         "OFFER_HEAD_MISMATCH") {
        ASSERT(dlt_manifest(mo, "zcl.dev_land_offer.v1", r.base_sha,
                            r.base_sha, bsha, "mac"));
        dlt_check(&c, r.queue, b, mo, NULL);
        ASSERT(dlt_refused(&c, "OFFER_HEAD_MISMATCH"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.check_offer: a manifest naming another base refuses "
         "OFFER_BASE_MISMATCH") {
        ASSERT(dlt_manifest(mo, "zcl.dev_land_offer.v1", tip, tip, bsha,
                            "mac"));
        dlt_check(&c, r.queue, b, mo, NULL);
        ASSERT(dlt_refused(&c, "OFFER_BASE_MISMATCH"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.check_offer: a bad schema or malformed commit refuses "
         "OFFER_BAD_MANIFEST") {
        ASSERT(dlt_manifest(mo, "zcl.other.v1", tip, r.base_sha, bsha, "mac"));
        dlt_check(&c, r.queue, b, mo, NULL);
        ASSERT(dlt_refused(&c, "OFFER_BAD_MANIFEST"));
        dlt_end(&c);
        ASSERT(dlt_manifest(mo, "zcl.dev_land_offer.v1", "xyz", r.base_sha,
                            bsha, "mac"));
        dlt_check(&c, r.queue, b, mo, NULL);
        ASSERT(dlt_refused(&c, "OFFER_BAD_MANIFEST"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.send --bundle_out: the offer base is the commit's parent even "
         "when origin/main has moved past it") {
        char mb[900], mof[900];
        (void)snprintf(mb, sizeof(mb), "%s/m.bundle", r.base);
        (void)snprintf(mof, sizeof(mof), "%s/m.bundle.offer.json", r.base);
        ASSERT(dlt_commit(r.queue, "moved.txt", "moved\n"));
        ASSERT(DLT_GIT(NULL, 0, r.queue, "push", "--quiet", "origin",
                       "main") == 0);
        dlt_send_x(&c, &r, tip, mb, false);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        dlt_check(&c, r.queue, mb, mof, NULL);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "base")),
                      r.base_sha);
        dlt_end(&c);
        PASS();
    }

    TEST("land.send --bundle_out: an existing .offer.json refuses "
         "SEND_OFFER_EXISTS and writes no bundle") {
        char nb[900], no[900];
        (void)snprintf(nb, sizeof(nb), "%s/n.bundle", r.base);
        (void)snprintf(no, sizeof(no), "%s/n.bundle.offer.json", r.base);
        ASSERT(dlt_write(no, "{}\n", 0644));
        dlt_send_x(&c, &r, tip, nb, false);
        ASSERT(dlt_refused(&c, "SEND_OFFER_EXISTS"));
        dlt_end(&c);
        ASSERT(access(nb, F_OK) != 0);
        PASS();
    }

_test_next:;
    dlt_done(&r);
    return failures;
}

/* A prerequisite whose header line is longer than the reader's 511-byte
 * chunk: the continuation chunk starts with '-' and must not count. */
static int dlt_prereq_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char subject[621], base[64], tip[64], caret[72], needle[64];
    char path[900], b[900], mo[900], bsha[ZSHA256_HEX_LEN], blob[4096];
    if (!dlt_rig(&r, "prereq")) {
        printf("rig setup FAILED\n");
        return 1;
    }
    memset(subject, 'x', 620);
    subject[469] = '-';
    subject[620] = '\0';
    (void)snprintf(path, sizeof(path), "%s/long.txt", r.sender);
    ASSERT(dlt_write(path, "long\n", 0644) &&
           DLT_GIT(NULL, 0, r.sender, "add", "-A") == 0 &&
           DLT_GIT(NULL, 0, r.sender, "commit", "--quiet", "--no-verify",
                   "-m", subject) == 0);
    ASSERT(DLT_GIT(base, sizeof(base), r.sender, "rev-parse", "HEAD") == 0);
    base[strcspn(base, "\n")] = '\0';
    ASSERT(dlt_commit(r.sender, "tip.txt", "tip\n"));
    ASSERT(DLT_GIT(tip, sizeof(tip), r.sender, "rev-parse", "HEAD") == 0);
    tip[strcspn(tip, "\n")] = '\0';
    (void)snprintf(caret, sizeof(caret), "^%s", base);
    (void)snprintf(b, sizeof(b), "%s/prereq.bundle", r.base);
    (void)snprintf(mo, sizeof(mo), "%s/prereq.bundle.offer.json", r.base);
    ASSERT(DLT_GIT(NULL, 0, r.sender, "bundle", "create", "--quiet", b,
                   "HEAD", caret) == 0);
    /* The fixture: the prerequisite line is over 600 bytes and the byte
     * after the first 511 is the '-' that used to pass for a header. */
    (void)snprintf(needle, sizeof(needle), "-%s", base);
    ASSERT(dlt_slurp(b, blob, sizeof(blob)));
    ASSERT(strstr(blob, needle) != NULL && strstr(blob, needle)[511] == '-');
    ASSERT(dlt_sha_file(b, bsha));

    TEST("land.check_offer: a prerequisite over 600 bytes with '-' after "
         "the 511-byte read counts as one prerequisite") {
        ASSERT(dlt_manifest(mo, "zcl.dev_land_offer.v1", tip, base, bsha,
                            "mac"));
        dlt_check(&c, r.sender, b, mo, r.sender);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "ok");
        dlt_end(&c);
        PASS();
    }

_test_next:;
    dlt_done(&r);
    return failures;
}

static int dlt_receipt_cases(void)
{
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char tip[64], b[900], o[900], rc[900], t1[900], t2[900], t3[900];
    char bad[900], mo[900], rc2[900], st2[900], bsha[ZSHA256_HEX_LEN];
    if (!dlt_rig(&r, "receipt") || !dlt_commit(r.sender, "a.txt", "a\n") ||
        DLT_GIT(tip, sizeof(tip), r.sender, "rev-parse", "HEAD") != 0) {
        printf("rig setup FAILED\n");
        return 1;
    }
    tip[strcspn(tip, "\n")] = '\0';
    (void)snprintf(b, sizeof(b), "%s/r.bundle", r.base);
    (void)snprintf(o, sizeof(o), "%s/r.bundle.offer.json", r.base);
    (void)snprintf(rc, sizeof(rc), "%s/r.receipt.json", r.base);
    (void)snprintf(t1, sizeof(t1), "%s/t1.receipt.json", r.base);
    (void)snprintf(t2, sizeof(t2), "%s/t2.receipt.json", r.base);
    (void)snprintf(t3, sizeof(t3), "%s/t3.receipt.json", r.base);
    (void)snprintf(bad, sizeof(bad), "%s/bad.bundle", r.base);
    (void)snprintf(mo, sizeof(mo), "%s/mo.offer.json", r.base);
    (void)snprintf(rc2, sizeof(rc2), "%s/other.receipt.json", r.base);
    (void)snprintf(st2, sizeof(st2), "%s/state2", r.base);
    dlt_send_x(&c, &r, tip, b, false);
    (void)snprintf(bsha, sizeof(bsha), "%s",
                   json_get_str(json_get(&c.reply.data, "bundle_sha256")));
    ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    dlt_end(&c);

    TEST("land.attest_offer then verify_offer_receipt: a checked bundle gets "
         "a receipt that verifies ok, with and without --offer") {
        char text[1024];
        dlt_attest(&c, r.queue, b, o, rc);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "receipt")), rc);
        dlt_end(&c);
        ASSERT(dlt_slurp(rc, text, sizeof(text)));
        ASSERT(strstr(text, "zcl.dev_land_offer_receipt.v1") != NULL);
        ASSERT(strstr(text, "bundle_sha256,bundle_verify,head,base") != NULL);
        dlt_vfy(&c, rc, NULL);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "commit")), tip);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "base")),
                      r.base_sha);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "checks")),
                      "bundle_sha256,bundle_verify,head,base");
        ASSERT(strlen(json_get_str(json_get(&c.reply.data, "signer"))) == 64);
        dlt_end(&c);
        dlt_vfy(&c, rc, o);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        PASS();
    }

    TEST("land.attest_offer: an existing receipt_out refuses "
         "OFFER_RECEIPT_EXISTS") {
        dlt_attest(&c, r.queue, b, o, rc);
        ASSERT(dlt_refused(&c, "OFFER_RECEIPT_EXISTS"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.attest_offer: a tampered bundle refuses OFFER_SHA_MISMATCH "
         "and writes no receipt") {
        ASSERT(dlt_flip(b, bad));
        dlt_attest(&c, r.queue, bad, o, t3);
        ASSERT(dlt_refused(&c, "OFFER_SHA_MISMATCH"));
        dlt_end(&c);
        ASSERT(access(t3, F_OK) != 0);
        PASS();
    }

    TEST("land.verify_offer_receipt: one flipped signature digit refuses "
         "RECEIPT_SIGNATURE_INVALID") {
        ASSERT(dlt_tweak(rc, t1, "signature"));
        dlt_vfy(&c, t1, NULL);
        ASSERT(dlt_refused(&c, "RECEIPT_SIGNATURE_INVALID"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.verify_offer_receipt: a changed commit field refuses "
         "RECEIPT_SIGNATURE_INVALID") {
        ASSERT(dlt_tweak(rc, t2, "commit"));
        dlt_vfy(&c, t2, NULL);
        ASSERT(dlt_refused(&c, "RECEIPT_SIGNATURE_INVALID"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.verify_offer_receipt: a receipt that is not v1 refuses "
         "OFFER_RECEIPT_BAD") {
        ASSERT(dlt_write(t3, "{\"schema\":\"zcl.other.v1\"}\n", 0644));
        dlt_vfy(&c, t3, NULL);
        ASSERT(dlt_refused(&c, "OFFER_RECEIPT_BAD"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.verify_offer_receipt: another offer refuses "
         "RECEIPT_OFFER_MISMATCH") {
        ASSERT(dlt_manifest(mo, "zcl.dev_land_offer.v1", r.base_sha, r.base_sha,
                            bsha, "mac"));
        dlt_vfy(&c, rc, mo);
        ASSERT(dlt_refused(&c, "RECEIPT_OFFER_MISMATCH"));
        dlt_end(&c);
        PASS();
    }

    TEST("land.verify_offer_receipt: a receipt signed by a key outside the "
         "allowlist refuses RECEIPT_SIGNER_UNKNOWN") {
        ASSERT(mkdir(st2, 0700) == 0);
        (void)setenv("XDG_STATE_HOME", st2, 1);
        dlt_attest(&c, r.queue, b, o, rc2);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        (void)setenv("XDG_STATE_HOME", r.state, 1);
        dlt_vfy(&c, rc2, NULL);
        ASSERT(dlt_refused(&c, "RECEIPT_SIGNER_UNKNOWN"));
        dlt_end(&c);
        PASS();
    }

_test_next:;
    dlt_done(&r);
    return failures;
}

/* dev.land.reverify_offer: a fixture repo whose commit splits one function
 * (tools/x.c) and deletes its baseline row, and a fake `dev cx check`
 * program (ZCL_LAND_REVERIFY_CX) that logs what it saw and answers pass or,
 * while cx.fail exists, fail. */
#define DLT_RV_BASELINE "tools/lint/cyclomatic_complexity_baseline.txt"
#define DLT_RV_CX                                                            \
    "#!/bin/sh\n"                                                            \
    "d=$(dirname \"$0\")\n"                                                  \
    "wt=${4#--worktree=}\n"                                                  \
    "ch=$(git -C \"$wt\" diff --cached --name-only | tr '\\n' ',')\n"        \
    "if [ -x \"$wt/build/bin/z23-lint\" ]; then l=yes; else l=no; fi\n"      \
    "echo \"$1 $2 $3 $5 $6 lint=$l changed=$ch cwd=$(pwd)\" > \"$d/cx.log\"\n" \
    "if [ -f \"$d/cx.fail\" ]; then\n"                                       \
    "  echo '{\"ok\":false,\"error\":{\"code\":\"CX_STILL_OVER\","            \
    "\"evidence\":\"big is still over 15\"}}'; exit 1\n"                     \
    "fi\n"                                                                   \
    "echo '{\"ok\":true,\"data\":{\"verdict\":\"pass\"}}'\n"

static void dlt_rv(struct dlt_call *c, const struct dlt_rig *r,
                   const char *bundle, const char *offer, const char *receipt)
{
    dlt_begin(c, "dev.land.reverify_offer");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "offer", offer);
    (void)json_push_kv_str(&c->input, "repo", r->queue);
    if (receipt)
        (void)json_push_kv_str(&c->input, "receipt_out", receipt);
    dlt_cd(r->queue);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}

/* No scratch worktree, no refs/z23-reverify ref and an empty temp dir. */
static bool dlt_rv_clean(const struct dlt_rig *r, const char *tmp)
{
    char out[2048];
    struct dirent *e;
    DIR *d;
    int left = 0;
    if (DLT_GIT(out, sizeof(out), r->queue, "worktree", "list") != 0 ||
        (strchr(out, '\n') && strchr(out, '\n')[1]))
        return false;
    if (DLT_GIT(out, sizeof(out), r->queue, "for-each-ref",
                "refs/z23-reverify") != 0 ||
        out[0])
        return false;
    d = opendir(tmp);
    if (!d)
        return false;
    while ((e = readdir(d)) != NULL)
        left += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
    (void)closedir(d);
    return left == 0;
}

/* Commits `body` as `file` on top of the fixture base (a branch of its own),
 * after writing the baseline text, and sends it as bundle+offer. */
static bool dlt_rv_offer(const struct dlt_rig *r, const char *branch,
                         const char *base, const char *const files[2],
                         const char *baseline, const char *bundle)
{
    struct dlt_call c;
    char p[1400], sha[64];
    bool ok;
    (void)snprintf(p, sizeof(p), "%s/" DLT_RV_BASELINE, r->sender);
    ok = DLT_GIT(NULL, 0, r->sender, "checkout", "--quiet", "-b", branch,
                 base) == 0 &&
         dlt_write(p, baseline, 0644);
    (void)snprintf(p, sizeof(p), "%s/%s", r->sender, files[1]);
    ok = ok && (!files[1][0] || dlt_write(p, "int z_changed(void){return 9;}\n",
                                          0644));
    ok = ok && dlt_commit(r->sender, files[0],
                          "int big(void){return 1;}\nint big_a(void){return "
                          "3;}\nint other(void){return 2;}\n") &&
         DLT_GIT(sha, sizeof(sha), r->sender, "rev-parse", "HEAD") == 0;
    if (!ok)
        return false;
    sha[strcspn(sha, "\n")] = '\0';
    dlt_send_x(&c, r, sha, bundle, false);
    ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    dlt_end(&c);
    return ok;
}

static bool dlt_rv_fixture(const struct dlt_rig *r, const char *base_x,
                           const char *baseline)
{
    char p[1400];
    const char *queue_files[][2] = {{"tools/y.c", "int zed(void){return 7;}\n"},
                                    {DLT_RV_BASELINE, baseline}};
    (void)snprintf(p, sizeof(p), "%s/tools/lint", r->queue);
    (void)mkdir(p, 0755);
    for (size_t i = 0; i < 2; i++) {
        (void)snprintf(p, sizeof(p), "%s/%s", r->queue, queue_files[i][0]);
        if (!dlt_write(p, queue_files[i][1], 0644))
            return false;
    }
    if (!dlt_commit(r->queue, "tools/x.c", base_x) ||
        DLT_GIT(NULL, 0, r->queue, "push", "--quiet", "origin", "main") != 0 ||
        DLT_GIT(NULL, 0, r->sender, "pull", "--quiet", "origin", "main") != 0)
        return false;
    /* built after the commit, so the lint copy is not part of the base */
    (void)snprintf(p, sizeof(p), "%s/build", r->queue);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build/bin", r->queue);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build/bin/z23-lint", r->queue);
    return dlt_write(p, "#!/bin/sh\nexit 0\n", 0755);
}

/* --check=verify: a C23 fake of the child launch, installed through
 * zcl_dlr_verify_seam_set() (no shell runner, no build macro). It records the
 * argv and what the scratch worktree holds (commits ahead of the base, files
 * changed, clean tree), then writes agent-verify's verdict file the way the
 * Makefile does, as g_rvf.mode says. The real timeout path is exercised by
 * delegating to the real spawn with a `sleep`. */
enum dlt_rvf_mode { RVF_PASS, RVF_FAIL, RVF_TIMEOUT, RVF_EMPTY, RVF_BASE,
                    RVF_LINTFAIL, RVF_LINTSILENT, RVF_PREPFAIL,
                    RVF_NOVERDICT };
static struct {
    enum dlt_rvf_mode mode;
    int calls;
    char base[64];
    char seen[1500];
    char log[4096]; /* every launch's argv, one line each */
    int first_ms;   /* the first launch's timeout */
} g_rvf;

static void dlt_rvf_verdict(const char *cwd, const char *groups,
                            const char *base, bool fail)
{
    char p[1200];
    FILE *f;
    (void)snprintf(p, sizeof(p), "%s/build", cwd);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build/scratch", cwd);
    (void)mkdir(p, 0755);
    (void)snprintf(p, sizeof(p), "%s/build/scratch/agent-verify.rc", cwd);
    f = fopen(p, "w");
    if (!f)
        return;
    (void)fprintf(f, "agent-verify: selection targeted groups=%s reason=plan "
                     "detail=none base=%s\n",
                  groups, base);
    for (int i = 0; fail && i < 400; i++)
        (void)fprintf(f, "agent-verify: filler-step-%03d rc=0\n", i);
    if (fail)
        (void)fputs("agent-verify: t-fast-exact rc=1\nSUITE VERDICT: FAIL 1 of "
                    "9\nagent-verify: FAILED (t-fast-exact)\n",
                    f);
    else
        (void)fputs("agent-verify: t-fast-exact rc=0\nagent-verify: OK\n", f);
    (void)fclose(f);
}

static bool dlt_rvf_has(const char *const argv[], const char *word)
{
    for (size_t i = 0; argv[i]; i++)
        if (strcmp(argv[i], word) == 0)
            return true;
    return false;
}

/* --check=gate's lint-preparation and lint launches (agent-verify keeps the
 * path below): true with `*rc` and the capture set when argv is one of them. */
static bool dlt_rvf_gate_step(const char *const argv[], char *buf, size_t cap,
                              int *rc)
{
    static const char *const prep[] = {"docs-capability-inventory", "dev-bin",
                                       "install-hooks", "lint-ready"};
    *rc = 0;
    (void)snprintf(buf, cap, "step ok\n");
    for (size_t i = 0; i < sizeof(prep) / sizeof(prep[0]); i++)
        if (dlt_rvf_has(argv, prep[i])) {
            *rc = g_rvf.mode == RVF_PREPFAIL && i == 1 ? 4 : 0;
            return true;
        }
    if (!dlt_rvf_has(argv, "lint"))
        return false;
    if (g_rvf.mode == RVF_LINTFAIL) {
        (void)snprintf(buf, cap, "check-a ok\nFAIL check-no-real-clock-test-"
                                 "deadline: sleep loop in t.c\nmore noise\n");
        *rc = 2;
    } else if (g_rvf.mode != RVF_LINTSILENT) {
        (void)snprintf(buf, cap, "check-a ok\nLINT: all checks passed\n");
    } else {
        (void)snprintf(buf, cap, "check-a ok\nexit-0 but no closing line\n");
    }
    return true;
}

static int dlt_rvf_spawn(const char *const argv[], const char *cwd, char *buf,
                         size_t cap, int timeout_ms, bool *timed_out)
{
    char names[512] = "", count[32] = "", dirty[256] = "", range[200];
    int rc;
    size_t used = 0;
    g_rvf.calls++;
    g_rvf.seen[0] = '\0';
    for (size_t i = 0; argv[i] && used < sizeof(g_rvf.seen) - 80; i++)
        used += (size_t)snprintf(g_rvf.seen + used, sizeof(g_rvf.seen) - used,
                                 "%s ", argv[i]);
    if (g_rvf.calls == 1)
        g_rvf.first_ms = timeout_ms;
    (void)snprintf(g_rvf.log + strlen(g_rvf.log),
                   sizeof(g_rvf.log) - strlen(g_rvf.log), "%s\n", g_rvf.seen);
    if (dlt_rvf_gate_step(argv, buf, cap, &rc)) {
        *timed_out = false;
        return rc;
    }
    (void)snprintf(range, sizeof(range), "%s..HEAD", g_rvf.base);
    (void)DLT_GIT(names, sizeof(names), cwd, "diff", "--name-only",
                  g_rvf.base, "HEAD");
    (void)DLT_GIT(count, sizeof(count), cwd, "rev-list", "--count", range);
    (void)DLT_GIT(dirty, sizeof(dirty), cwd, "status", "--porcelain");
    for (char *c = names; *c; c++)
        if (*c == '\n')
            *c = ',';
    count[strcspn(count, "\n")] = '\0';
    (void)snprintf(g_rvf.seen + used, sizeof(g_rvf.seen) - used,
                   "n=%s changed=%s dirty=%d", count, names,
                   dirty[0] ? 1 : 0);
    if (g_rvf.mode == RVF_TIMEOUT) {
        const char *sl[] = {"sleep", "60", NULL};
        return zcl_spawn_capture_merged_in_dir_observed(sl, cwd, buf, cap,
                                                        timeout_ms, timed_out);
    }
    *timed_out = false;
    /* the head of the capture is noise: only the verdict file has the end */
    (void)snprintf(buf, cap, "CAPTURE-HEAD-NOISE\n");
    switch (g_rvf.mode) {
    case RVF_FAIL:
        dlt_rvf_verdict(cwd, "2", g_rvf.base, true);
        return 3;
    case RVF_EMPTY:
        dlt_rvf_verdict(cwd, "0", g_rvf.base, false);
        return 0;
    case RVF_BASE:
        dlt_rvf_verdict(cwd, "2", "0000000000000000000000000000000000000000",
                        false);
        return 0;
    case RVF_NOVERDICT:
        return 0; /* exit 0 and no verdict file: not a pass */
    default:
        dlt_rvf_verdict(cwd, "2", g_rvf.base, false);
        return 0;
    }
}

/* zcl_dlr_verify_run on a scratch worktree of the sender detached at `base`,
 * given an offered commit that is not one plain commit: shape 0 two commits,
 * 1 a merge commit alone beyond base, 2 an empty commit (it cannot be
 * cherry-picked). True when it refused with `code` and never launched the
 * child. */
static bool dlt_rv_direct_commit(const char *wt, const char *base, int shape,
                                 char *sha, size_t cap)
{
    char tree[64], parent[64], prev[80];
    bool ok = true;
    (void)snprintf(prev, sizeof(prev), "%s~1", base);
    if (shape == 0)
        return dlt_commit(wt, "d1.txt", "1\n") &&
               dlt_commit(wt, "d2.txt", "2\n") &&
               DLT_GIT(sha, cap, wt, "rev-parse", "HEAD") == 0;
    if (shape == 2)
        return DLT_GIT(NULL, 0, wt, "commit", "--quiet", "--no-verify",
                       "--allow-empty", "-m", "empty") == 0 &&
               DLT_GIT(sha, cap, wt, "rev-parse", "HEAD") == 0;
    ok = DLT_GIT(tree, sizeof(tree), wt, "rev-parse", "HEAD^{tree}") == 0 &&
         DLT_GIT(parent, sizeof(parent), wt, "rev-parse", prev) == 0;
    tree[strcspn(tree, "\n")] = '\0';
    parent[strcspn(parent, "\n")] = '\0';
    return ok && DLT_GIT(sha, cap, wt, "commit-tree", tree, "-p", base, "-p",
                         parent, "-m", "merge") == 0;
}

static bool dlt_rv_direct(const struct dlt_rig *r, const char *base, int shape,
                          const char *code)
{
    char wt[900], sha[64] = "";
    struct dlt_call c;
    bool ok;
    (void)snprintf(wt, sizeof(wt), "%s/dwt%d", r->base, shape);
    ok = DLT_GIT(NULL, 0, r->sender, "worktree", "add", "--quiet", "--detach",
                 wt, base) == 0 &&
         dlt_rv_direct_commit(wt, base, shape, sha, sizeof(sha)) &&
         DLT_GIT(NULL, 0, wt, "reset", "--quiet", "--hard", base) == 0;
    sha[strcspn(sha, "\n")] = '\0';
    g_rvf.calls = 0;
    dlt_begin(&c, "dev.land.reverify_offer");
    ok = ok && !zcl_dlr_verify_run(wt, sha, 5, ZCL_DLR_CHECK_VERIFY,
                                   "dev.land.reverify_offer",
                                   &c.reply) &&
         dlt_refused(&c, code) && g_rvf.calls == 0;
    dlt_end(&c);
    (void)DLT_GIT(NULL, 0, r->sender, "worktree", "remove", "--force", wt);
    return ok;
}

static void dlt_rv_mode(struct dlt_call *c, const struct dlt_rig *r,
                        const char *bundle, const char *offer,
                        const char *receipt, const char *check,
                        int timeout_s)
{
    dlt_begin(c, "dev.land.reverify_offer");
    (void)json_push_kv_str(&c->input, "bundle", bundle);
    (void)json_push_kv_str(&c->input, "offer", offer);
    (void)json_push_kv_str(&c->input, "repo", r->queue);
    if (check)
        (void)json_push_kv_str(&c->input, "check", check);
    if (receipt)
        (void)json_push_kv_str(&c->input, "receipt_out", receipt);
    if (timeout_s)
        (void)json_push_kv_int(&c->input, "timeout_s", timeout_s);
    dlt_cd(r->queue);
    zcl_native_handle_dev_land_remote(&c->request, &c->reply);
}


/* One refused verify run: the code, that no receipt was written and that no
 * scratch worktree, ref or temp file is left. `calls` is how many times the
 * child launch ran (0 when the refusal comes before it). */
static bool dlt_rv_refused(struct dlt_call *c, const struct dlt_rig *r,
                           const char *tmp, const char *code, const char *rc,
                           int calls)
{
    bool ok = dlt_refused(c, code) && g_rvf.calls == calls &&
              access(rc, F_OK) != 0 && dlt_rv_clean(r, tmp);
    return ok;
}

/* b2/o2 is a commit touching two .c files: not a split, so --check=cx refuses
 * it and only the general mode takes it. */
static int dlt_rv_verify_cases(const struct dlt_rig *r, const char *tmp,
                               const char *base, const char *b2, const char *o2)
{
    int failures = 0;
    struct dlt_call c;
    char rail[900], absent[900], rc[900], rc2[900];
    char text[2048], want[1200];
    const struct zcl_dlr_verify_seam seam = {rail, dlt_rvf_spawn};
    const struct zcl_dlr_verify_seam norail = {absent, dlt_rvf_spawn};
    (void)snprintf(rail, sizeof(rail), "%s/rail-stub", r->base);
    (void)snprintf(absent, sizeof(absent), "%s/no-such-rail", r->base);
    (void)snprintf(rc, sizeof(rc), "%s/rvv.receipt.json", r->base);
    (void)snprintf(rc2, sizeof(rc2), "%s/rvv2.receipt.json", r->base);
    (void)snprintf(g_rvf.base, sizeof(g_rvf.base), "%s", base);
    if (!dlt_write(rail, "stub\n", 0755)) {
        printf("verify rail stub setup FAILED\n");
        return 1;
    }
    zcl_dlr_verify_seam_set(&seam);
    /* --check=gate: the lint preparation, full lint with the cold per-TU
     * cache, then agent-verify, every launch through the rail with the
     * host's derived -jN. */
    char gjobs[16] = "-j1", pre[900], prefix[1600], lint[400], av[400];
    (void)platform_build_jobs_arg(gjobs);
    (void)snprintf(pre, sizeof(pre), "%s --wait --project z23 make %s", rail,
                   gjobs);
    (void)snprintf(prefix, sizeof(prefix),
                   "%s docs-capability-inventory \n%s dev-bin \n"
                   "%s install-hooks \n%s lint-ready \n",
                   pre, pre, pre, pre);
    (void)snprintf(lint, sizeof(lint),
                   "%s --wait --project z23 env ZCL_LINT_TU_CACHE=0 make %s "
                   "lint \n",
                   rail, gjobs);
    (void)snprintf(av, sizeof(av), "%s agent-verify ONLY=@changed \n", pre);


    TEST("land.reverify_offer --check=verify: a non-split commit through the "
         "rail passes, signs a receipt, and ran as a real clean commit") {
        g_rvf.mode = RVF_PASS;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc, "verify", 0);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "check")), "verify");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "receipt")), rc);
        dlt_end(&c);
        ASSERT(g_rvf.calls == 1);
        ASSERT(dlt_slurp(rc, text, sizeof(text)));
        ASSERT(strstr(text, "bundle_sha256,bundle_verify,head,base,"
                            "agent_verify\"") != NULL);
        /* The child gets the host's parallel job count, as the land
         * qualify build does: serial, a re-verify took 38+ minutes. */
        char jobs[16] = "-j1";
        (void)platform_build_jobs_arg(jobs);
        (void)snprintf(want, sizeof(want),
                       "%s --wait --project z23 make %s agent-verify "
                       "ONLY=@changed n=1 changed=" DLT_RV_BASELINE
                       ",tools/x.c,tools/y.c, dirty=0",
                       rail, jobs);
        ASSERT_STR_EQ(g_rvf.seen, want);
        dlt_vfy(&c, rc, o2);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "checks")),
                      "bundle_sha256,bundle_verify,head,base,agent_verify");
        dlt_end(&c);
        ASSERT(dlt_rv_clean(r, tmp));
        PASS();
    }

    TEST("land.reverify_offer --check=verify: not one plain commit refuses "
         "typed before the child: two commits REVERIFY_NOT_SINGLE, a merge "
         "REVERIFY_MERGE, an empty commit REVERIFY_APPLY") {
        ASSERT(dlt_rv_direct(r, base, 0, "REVERIFY_NOT_SINGLE"));
        ASSERT(dlt_rv_direct(r, base, 1, "REVERIFY_MERGE"));
        ASSERT(dlt_rv_direct(r, base, 2, "REVERIFY_APPLY"));
        PASS();
    }

    TEST("land.reverify_offer --check=verify: no admission rail refuses "
         "REVERIFY_NO_RAIL, runs nothing and leaves nothing") {
        zcl_dlr_verify_seam_set(&norail);
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 0);
        zcl_dlr_verify_seam_set(&seam);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_NO_RAIL", rc2, 0));
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=verify: a run that selected zero "
         "groups refuses REVERIFY_EMPTY_SELECTION, never a pass") {
        g_rvf.mode = RVF_EMPTY;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_EMPTY_SELECTION", rc2, 1));
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=verify: a selection against another "
         "base than the offered one refuses REVERIFY_SELECTION_BASE") {
        g_rvf.mode = RVF_BASE;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_SELECTION_BASE", rc2, 1));
        ASSERT(strstr(c.reply.error.evidence, "0000000000") != NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=verify: exit 0 with no verdict file is "
         "not a pass: REVERIFY_VERIFY_FAILED") {
        g_rvf.mode = RVF_NOVERDICT;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_VERIFY_FAILED", rc2, 1));
        ASSERT(strstr(c.reply.error.evidence, "exit=0") != NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=verify: a failing long run refuses "
         "REVERIFY_VERIFY_FAILED with the exit and the END of the run") {
        g_rvf.mode = RVF_FAIL;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_VERIFY_FAILED", rc2, 1));
        ASSERT(strstr(c.reply.error.evidence, "exit=3") != NULL);
        ASSERT(strstr(c.reply.error.evidence, "SUITE VERDICT: FAIL 1 of 9") !=
               NULL);
        ASSERT(strstr(c.reply.error.evidence,
                      "agent-verify: FAILED (t-fast-exact)") != NULL);
        ASSERT(strstr(c.reply.error.evidence, "CAPTURE-HEAD-NOISE") == NULL);
        ASSERT(strstr(c.reply.error.evidence, "filler-step-000") == NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=verify: a child past timeout_s is "
         "killed and refuses REVERIFY_VERIFY_TIMEOUT, leaving nothing") {
        g_rvf.mode = RVF_TIMEOUT;
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", 1);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_VERIFY_TIMEOUT", rc2, 1));
        ASSERT(strstr(c.reply.error.evidence, "timeout_s=1") != NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=gate: a pass runs exactly the prepare "
         "steps, then cold full lint, then agent-verify, all with the derived "
         "-jN, and signs the lint+agent_verify checks") {
        g_rvf.mode = RVF_PASS;
        g_rvf.calls = 0;
        g_rvf.log[0] = '\0';
        (void)unlink(rc); /* the verify case above signed one here */
        dlt_rv_mode(&c, r, b2, o2, rc, "gate", 0);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "check")), "gate");
        dlt_end(&c);
        ASSERT(g_rvf.calls == 6);
        ASSERT(g_rvf.first_ms == 7200 * 1000); /* the gate's own default */
        (void)snprintf(want, sizeof(want), "%s%s%s", prefix, lint, av);
        ASSERT_STR_EQ(g_rvf.log, want);
        ASSERT(dlt_slurp(rc, text, sizeof(text)));
        ASSERT(strstr(text, "bundle_sha256,bundle_verify,head,base,lint,"
                            "agent_verify\"") != NULL);
        dlt_vfy(&c, rc, o2);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "checks")),
                      "bundle_sha256,bundle_verify,head,base,lint,"
                      "agent_verify");
        dlt_end(&c);
        ASSERT(dlt_rv_clean(r, tmp));
        (void)unlink(rc);
        PASS();
    }

    TEST("land.reverify_offer --check=verify keeps its own default bound and "
         "argv: no prepare, no lint, 3600 s") {
        g_rvf.mode = RVF_PASS;
        g_rvf.calls = 0;
        g_rvf.log[0] = '\0';
        dlt_rv_mode(&c, r, b2, o2, NULL, "verify", 0);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        dlt_end(&c);
        ASSERT(g_rvf.calls == 1);
        ASSERT(g_rvf.first_ms == 3600 * 1000);
        ASSERT_STR_EQ(g_rvf.log, av);
        PASS();
    }

    TEST("land.reverify_offer --check=gate: a lint failure refuses "
         "REVERIFY_LINT_FAILED with the first FAIL line, and agent-verify "
         "never runs") {
        g_rvf.mode = RVF_LINTFAIL;
        g_rvf.calls = 0;
        g_rvf.log[0] = '\0';
        dlt_rv_mode(&c, r, b2, o2, rc2, "gate", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_LINT_FAILED", rc2, 5));
        ASSERT(strstr(c.reply.error.evidence, "exit=2") != NULL);
        ASSERT(strstr(c.reply.error.evidence,
                      "FAIL check-no-real-clock-test-deadline") != NULL);
        ASSERT(strstr(g_rvf.log, "agent-verify") == NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=gate: lint exiting 0 without its "
         "closing line is not a pass: REVERIFY_LINT_FAILED") {
        g_rvf.mode = RVF_LINTSILENT;
        g_rvf.calls = 0;
        g_rvf.log[0] = '\0';
        dlt_rv_mode(&c, r, b2, o2, rc2, "gate", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_LINT_FAILED", rc2, 5));
        ASSERT(strstr(c.reply.error.evidence, "no closing line") != NULL);
        ASSERT(strstr(g_rvf.log, "agent-verify") == NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=gate: a failing prepare step refuses "
         "REVERIFY_PREPARE_FAILED naming it; no later step runs") {
        g_rvf.mode = RVF_PREPFAIL;
        g_rvf.calls = 0;
        g_rvf.log[0] = '\0';
        dlt_rv_mode(&c, r, b2, o2, rc2, "gate", 0);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_PREPARE_FAILED", rc2, 2));
        ASSERT(strstr(c.reply.error.evidence, "step=dev-bin exit=4") != NULL);
        ASSERT(strstr(g_rvf.log, "lint") == NULL);
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer --check=gate: no admission rail refuses "
         "REVERIFY_NO_RAIL before any step") {
        zcl_dlr_verify_seam_set(&norail);
        g_rvf.calls = 0;
        dlt_rv_mode(&c, r, b2, o2, rc2, "gate", 0);
        zcl_dlr_verify_seam_set(&seam);
        ASSERT(dlt_rv_refused(&c, r, tmp, "REVERIFY_NO_RAIL", rc2, 0));
        dlt_end(&c);
        PASS();
    }

    TEST("land.reverify_offer: --check=cx is unchanged and still refuses a "
         "non-split commit; an unknown check or bad timeout_s is refused") {
        dlt_rv_mode(&c, r, b2, o2, rc2, "cx", 0);
        ASSERT(dlt_refused(&c, "REVERIFY_NOT_A_SPLIT"));
        dlt_end(&c);
        dlt_rv_mode(&c, r, b2, o2, rc2, "bogus", 0);
        ASSERT(dlt_refused(&c, "OFFER_BAD_ARGUMENT"));
        dlt_end(&c);
        dlt_rv_mode(&c, r, b2, o2, rc2, "verify", -5);
        ASSERT(dlt_refused(&c, "OFFER_BAD_ARGUMENT"));
        dlt_end(&c);
        ASSERT(dlt_rv_clean(r, tmp));
        PASS();
    }

    TEST("land.reverify_offer: a check that is an integer or an empty string "
         "refuses OFFER_BAD_ARGUMENT naming input.check; it is never cx") {
        dlt_begin(&c, "dev.land.reverify_offer");
        (void)json_push_kv_str(&c.input, "bundle", b2);
        (void)json_push_kv_str(&c.input, "offer", o2);
        (void)json_push_kv_str(&c.input, "repo", r->queue);
        (void)json_push_kv_int(&c.input, "check", 5);
        dlt_cd(r->queue);
        zcl_native_handle_dev_land_remote(&c.request, &c.reply);
        ASSERT(dlt_refused(&c, "OFFER_BAD_ARGUMENT"));
        ASSERT(strstr(c.reply.error.evidence, "input.check") != NULL);
        dlt_end(&c);
        dlt_rv_mode(&c, r, b2, o2, rc2, "", 0);
        ASSERT(dlt_refused(&c, "OFFER_BAD_ARGUMENT"));
        ASSERT(strstr(c.reply.error.evidence, "input.check") != NULL);
        dlt_end(&c);
        ASSERT(dlt_rv_clean(r, tmp));
        PASS();
    }

_test_next:;
    zcl_dlr_verify_seam_set(NULL);
    return failures;
}

static int dlt_reverify_cases(void)
{
    static const char base_rows[] =
        "# baseline\ntools/x.c:big:20\ntools/x.c:other:18\ntools/y.c:zed:17\n";
    static const char split_rows[] =
        "# baseline\ntools/x.c:other:16\ntools/y.c:zed:17\n";
    int failures = 0;
    struct dlt_rig r;
    struct dlt_call c;
    char b1[900], o1[900], b2[900], o2[900], b3[900], o3[900], bad[900];
    char tmp[900], cx[900], fail[900], log[900], rc[900], rc2[900], text[2048];
    char base[64], saved[900] = "";
    const char *old = getenv("TMPDIR");
    const char *split[2] = {"tools/x.c", ""};
    const char *two[2] = {"tools/x.c", "tools/y.c"};
    if (old)
        (void)snprintf(saved, sizeof(saved), "%s", old);
    if (!dlt_rig(&r, "reverify") ||
        !dlt_rv_fixture(&r, "int big(void){return 1;}\nint other(void){return "
                            "2;}\n",
                        base_rows) ||
        DLT_GIT(base, sizeof(base), r.sender, "rev-parse", "HEAD") != 0) {
        printf("rig setup FAILED\n");
        return 1;
    }
    base[strcspn(base, "\n")] = '\0';
    (void)snprintf(tmp, sizeof(tmp), "%s/tmp", r.base);
    (void)snprintf(cx, sizeof(cx), "%s/cx.sh", r.base);
    (void)snprintf(fail, sizeof(fail), "%s/cx.fail", r.base);
    (void)snprintf(log, sizeof(log), "%s/cx.log", r.base);
    (void)snprintf(rc, sizeof(rc), "%s/rv.receipt.json", r.base);
    (void)snprintf(rc2, sizeof(rc2), "%s/rv2.receipt.json", r.base);
    (void)snprintf(bad, sizeof(bad), "%s/rv-bad.bundle", r.base);
    (void)snprintf(b1, sizeof(b1), "%s/rv1.bundle", r.base);
    (void)snprintf(o1, sizeof(o1), "%s/rv1.bundle.offer.json", r.base);
    (void)snprintf(b2, sizeof(b2), "%s/rv2.bundle", r.base);
    (void)snprintf(o2, sizeof(o2), "%s/rv2.bundle.offer.json", r.base);
    (void)snprintf(b3, sizeof(b3), "%s/rv3.bundle", r.base);
    (void)snprintf(o3, sizeof(o3), "%s/rv3.bundle.offer.json", r.base);
    (void)mkdir(tmp, 0700);
    (void)setenv("TMPDIR", tmp, 1);
    (void)setenv("ZCL_LAND_REVERIFY_CX", cx, 1);
    if (!dlt_write(cx, DLT_RV_CX, 0755) ||
        !dlt_rv_offer(&r, "split", base, split, split_rows, b1) ||
        !dlt_rv_offer(&r, "two", base, two, split_rows, b2) ||
        !dlt_rv_offer(&r, "norow", base, split, base_rows, b3)) {
        printf("offer setup FAILED\n");
        return 1;
    }

    TEST("land.reverify_offer: a split commit re-runs dev cx check on its "
         "base and replies ok with the unit; nothing is left behind") {
        dlt_rv(&c, &r, b1, o1, NULL);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "ok");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "file")),
                      "tools/x.c");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "functions")),
                      "big");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "base")), base);
        ASSERT(json_get(&c.reply.data, "receipt") == NULL);
        dlt_end(&c);
        ASSERT(dlt_slurp(log, text, sizeof(text)));
        ASSERT(strstr(text, "dev cx check --file=tools/x.c --functions=big "
                            "lint=yes changed=tools/x.c, cwd=") != NULL);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

    TEST("land.reverify_offer --receipt_out: a pass signs a receipt with the "
         "five checks that verify_offer_receipt accepts") {
        dlt_rv(&c, &r, b1, o1, rc);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "receipt")), rc);
        dlt_end(&c);
        ASSERT(dlt_slurp(rc, text, sizeof(text)));
        ASSERT(strstr(text, "bundle_sha256,bundle_verify,head,base,cx_check") !=
               NULL);
        dlt_vfy(&c, rc, o1);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "checks")),
                      "bundle_sha256,bundle_verify,head,base,cx_check");
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "verdict")), "ok");
        dlt_end(&c);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

    TEST("land.reverify_offer: an existing receipt_out refuses "
         "OFFER_RECEIPT_EXISTS before any worktree is made") {
        dlt_rv(&c, &r, b1, o1, rc);
        ASSERT(dlt_refused(&c, "OFFER_RECEIPT_EXISTS"));
        dlt_end(&c);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

    TEST("land.reverify_offer: a failing dev cx check refuses "
         "REVERIFY_CX_FAILED with the child's code, and writes no receipt") {
        ASSERT(dlt_write(fail, "x\n", 0644));
        dlt_rv(&c, &r, b1, o1, rc2);
        ASSERT(dlt_refused(&c, "REVERIFY_CX_FAILED"));
        ASSERT(strstr(c.reply.error.evidence, "exit=1") != NULL);
        ASSERT(strstr(c.reply.error.evidence, "CX_STILL_OVER") != NULL);
        ASSERT(strstr(c.reply.error.evidence, "big is still over 15") != NULL);
        dlt_end(&c);
        ASSERT(access(rc2, F_OK) != 0);
        ASSERT(dlt_rv_clean(&r, tmp));
        ASSERT(remove(fail) == 0);
        PASS();
    }

    TEST("land.reverify_offer: a commit touching two .c files refuses "
         "REVERIFY_NOT_A_SPLIT") {
        dlt_rv(&c, &r, b2, o2, rc2);
        ASSERT(dlt_refused(&c, "REVERIFY_NOT_A_SPLIT"));
        dlt_end(&c);
        ASSERT(access(rc2, F_OK) != 0);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

    TEST("land.reverify_offer: a .c change that deletes no baseline row "
         "refuses REVERIFY_NOT_A_SPLIT") {
        dlt_rv(&c, &r, b3, o3, NULL);
        ASSERT(dlt_refused(&c, "REVERIFY_NOT_A_SPLIT"));
        dlt_end(&c);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

    TEST("land.reverify_offer: a tampered bundle refuses with check_offer's "
         "OFFER_SHA_MISMATCH, runs no cx check and leaves nothing") {
        ASSERT(remove(log) == 0);
        ASSERT(dlt_flip(b1, bad));
        dlt_rv(&c, &r, bad, o1, rc2);
        ASSERT(dlt_refused(&c, "OFFER_SHA_MISMATCH"));
        dlt_end(&c);
        ASSERT(access(log, F_OK) != 0);
        ASSERT(access(rc2, F_OK) != 0);
        ASSERT(dlt_rv_clean(&r, tmp));
        PASS();
    }

_test_next:;
    failures += dlt_rv_verify_cases(&r, tmp, base, b2, o2);
    if (saved[0])
        (void)setenv("TMPDIR", saved, 1);
    else
        (void)unsetenv("TMPDIR");
    (void)unsetenv("ZCL_LAND_REVERIFY_CX");
    dlt_done(&r);
    return failures;
}

int test_dev_land_remote(void);
int test_dev_land_remote(void)
{
    int failures = dlt_receive_cases() + dlt_send_cases() + dlt_single_cases() +
                   dlt_offer_cases() + dlt_prereq_cases() +
                   dlt_receipt_cases() +
                   dlt_reverify_cases() + dlq_remote_cases();
    if (failures == 0)
        printf("test_dev_land_remote: all passed\n");
    else
        printf("test_dev_land_remote: %d FAILED\n", failures);
    return failures;
}
