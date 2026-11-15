/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_repro_network_policy against fixture Makefiles and the
 *          checkout's repro-verify script. */

#include "test/test_core.h"

#include "repro_network_policy.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char k_block[] =
    "ZCL_NETWORK_DENIED_BUILD_GOALS := ci-reproducible repro-verify\n"
    "ifneq ($(strip $(filter $(ZCL_NETWORK_DENIED_BUILD_GOALS),$(MAKECMDGOALS))),)\n"
    "override ZCL_VENDOR_OFFLINE := 1\n"
    "override ZCL_USE_CCACHE := 0\n"
    "export ZCL_VENDOR_OFFLINE\n"
    "export ZCL_USE_CCACHE\n"
    "endif\n";

static int rnp_put(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(text, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int rnp_mkdir_at(const char *dir, const char *rel)
{
    char path[PATH_MAX];
    size_t n;
    size_t i;
    if (snprintf(path, sizeof path, "%s/%s", dir, rel) >= (int)sizeof path)
        return -1;
    n = strlen(path);
    for (i = 1; i < n; i++) {
        if (path[i] != '/')
            continue;
        path[i] = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return -1;
        path[i] = '/';
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rnp_capture(const char *scratch, const char *repo, char *out, size_t out_cap,
                       char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int saved_out = -1;
    int saved_err = -1;
    int fd_out = -1;
    int fd_err = -1;
    int rc;
    if (snprintf(out_path, sizeof out_path, "%s/stdout.txt", scratch) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/stderr.txt", scratch) >= (int)sizeof err_path)
        return -1;
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (saved_out < 0 || saved_err < 0 || fd_out < 0 || fd_err < 0)
        goto fail;
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_repro_network_policy(repo);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    {
        FILE *fp = fopen(out_path, "r");
        size_t n;
        if (fp == NULL)
            return -1;
        n = fread(out, 1, out_cap - 1, fp);
        fclose(fp);
        out[n] = '\0';
        fp = fopen(err_path, "r");
        if (fp == NULL)
            return -1;
        n = fread(err, 1, err_cap - 1, fp);
        fclose(fp);
        err[n] = '\0';
    }
    return rc;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int rnp_case(const char *root, const char *tag, const char *make, char *dir, size_t cap)
{
    char path[PATH_MAX];
    if (snprintf(dir, cap, "%s/%s", root, tag) >= (int)cap)
        return -1;
    if (mkdir(dir, 0700) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/Makefile", dir) >= (int)sizeof path)
        return -1;
    return rnp_put(path, make);
}

static int test_rnp_repo(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[512];
    char err2[512];
    int rc;
    TEST("a missing repo is refused") {
        ASSERT(rnp_case(root, "repo", "all:\n", dir, sizeof dir) == 0);
        rc = rnp_capture(dir, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, "repro_network_policy_selftest: FAIL: repo is required\n");
        rc = rnp_capture(dir, "", out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_order(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char body[1024];
    char out[64];
    char err[512];
    char err2[512];
    int rc;
    TEST("policy order is refused when cache or the vendor barrier comes first") {
        ASSERT(snprintf(body, sizeof body, "ZCL_USE_CCACHE ?= 1\n%sVENDOR_BOOTSTRAP_MK := build/x\n",
                        k_block) > 0);
        ASSERT(rnp_case(root, "cache", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err,
                      "repro_network_policy_selftest: FAIL: Make hermetic policy is defined "
                      "after compiler-cache selection\n");
        rc = rnp_capture(dir, dir, out, sizeof out, err2, sizeof err2);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err2, err);
        ASSERT(snprintf(body, sizeof body,
                        "VENDOR_BOOTSTRAP_MK := build/x\n%sZCL_USE_CCACHE ?= 1\n", k_block) > 0);
        ASSERT(rnp_case(root, "barrier", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err,
                      "repro_network_policy_selftest: FAIL: Make offline policy is defined "
                      "after the vendor parse barrier\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_caller(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char body[1024];
    char out[64];
    char err[512];
    int rc;
    TEST("a permissive caller value does not survive the parse barrier") {
        ASSERT(snprintf(body, sizeof body,
                        "%s"
                        "ZCL_USE_CCACHE ?= 1\n"
                        "VENDOR_BOOTSTRAP_MK := build/x\n",
                        "ZCL_NETWORK_DENIED_BUILD_GOALS := ci-reproducible repro-verify\n"
                        "ifneq ($(strip $(filter $(ZCL_NETWORK_DENIED_BUILD_GOALS),$(MAKECMDGOALS))),)\n"
                        "export ZCL_VENDOR_OFFLINE\n"
                        "export ZCL_USE_CCACHE\n"
                        "endif\n") > 0);
        ASSERT(rnp_case(root, "caller", body, dir, sizeof dir) == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "did not force offline/no-cache policy: 0 1") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_fixture(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char path[PATH_MAX];
    char body[1024];
    char out[64];
    char err[1024];
    int rc;
    TEST("a failing repro-verify is reported with its output") {
        ASSERT(snprintf(body, sizeof body, "%sZCL_USE_CCACHE ?= 1\nVENDOR_BOOTSTRAP_MK := build/x\n",
                        k_block) > 0);
        ASSERT(rnp_case(root, "fail", body, dir, sizeof dir) == 0);
        ASSERT(rnp_mkdir_at(dir, "tools/scripts") == 0);
        ASSERT(snprintf(path, sizeof path, "%s/tools/scripts/repro-verify.sh", dir) >= 0);
        ASSERT(rnp_put(path, "#!/bin/sh\nprintf 'fixture-blew-up\\n' >&2\nexit 9\n") == 0);
        rc = rnp_capture(dir, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "fixture-blew-up") != NULL);
        ASSERT(strstr(err, "repro-verify fixture failed") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int rnp_run(const char *dir, const char *const *args, char *out, size_t cap)
{
    const char *argv[32] = {"bash", "-c", "cd \"$1\" && shift && \"$@\"", "rnp", dir};
    size_t n = 5;
    for (size_t i = 0; args[i] && n + 1 < sizeof argv / sizeof argv[0]; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_observed(argv, out, cap, 60000, &timed_out);
    return timed_out ? -1 : rc;
}

static int rnp_git(const char *dir, const char *const *args, char *out, size_t cap)
{
    const char *full[24] = {"git", "-C", dir};
    size_t n = 3;
    for (size_t i = 0; args[i] && n + 1 < sizeof full / sizeof full[0]; i++)
        full[n++] = args[i];
    full[n] = NULL;
    int rc = rnp_run(dir, full, out, cap);
    size_t len = strlen(out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    return rc;
}

static int rnp_source_record(const char *dir, char *out, size_t cap)
{
    const char *args[] = {"env", "ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1",
                          "tools/dev/source-identity.sh", "capture-record", NULL};
    return rnp_run(dir, args, out, cap);
}

static size_t rnp_lines(const char *text)
{
    size_t count = text[0] != '\0';
    for (; *text; text++)
        if (*text == '\n')
            count++;
    return count;
}

static bool rnp_gitlink_matches(const char *base, const char *builder,
                                const char *commit, const char *record,
                                size_t expected_objects)
{
    char dir[PATH_MAX], actual[4096], expected[256], snapshot_record[4096];
    if (snprintf(dir, sizeof dir, "%s/%s", base, builder) >= (int)sizeof dir)
        return false;
    const char *list[] = {"ls-files", "--stage", "--", "vendor/tor", NULL};
    if (rnp_git(dir, list, actual, sizeof actual) != 0)
        return false;
    if (snprintf(expected, sizeof expected, "160000 %s 0\tvendor/tor", commit) >=
        (int)sizeof expected)
        return false;
    if (strcmp(actual, expected) != 0) {
        test_note("%s gitlink: got '%s', expected '%s'", builder, actual, expected);
        return false;
    }
    if (rnp_source_record(dir, snapshot_record, sizeof snapshot_record) != 0)
        return false;
    if (strncmp(snapshot_record, record, 64) != 0) {
        test_note("%s source ID: got %.64s, expected %.64s", builder,
                  snapshot_record, record);
        return false;
    }
    char object_dir[PATH_MAX];
    if (snprintf(object_dir, sizeof object_dir, "%s/vendor/tor", dir) >=
        (int)sizeof object_dir)
        return false;
    const char *objects[] = {"cat-file", "--batch-check", "--batch-all-objects", NULL};
    if (rnp_git(object_dir, objects, actual, sizeof actual) != 0)
        return false;
    if (rnp_lines(actual) != expected_objects) {
        test_note("%s object count: got %zu, expected %zu\n%s", builder,
                  rnp_lines(actual), expected_objects, actual);
        return false;
    }
    return true;
}

static int test_rnp_gitlink(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    test_make_tmpdir(root, sizeof root, "repro_gitlink", "root");
    TEST("repro snapshots retain the exact tracked gitlink and source identity") {
        char src[PATH_MAX], sub[PATH_MAX], tmp[PATH_MAX], script[PATH_MAX];
        char payload[PATH_MAX], copy[PATH_MAX], cwd[PATH_MAX];
        char commit[65], record[4096], log[8192], out[4096];
        ASSERT(snprintf(src, sizeof src, "%s/src", root) < (int)sizeof src);
        ASSERT(snprintf(sub, sizeof sub, "%s/sub", root) < (int)sizeof sub);
        ASSERT(snprintf(tmp, sizeof tmp, "%s/tmp", root) < (int)sizeof tmp);
        ASSERT(rnp_mkdir_at(root, "sub") == 0);
        ASSERT(rnp_mkdir_at(root, "src/tools/dev") == 0);
        ASSERT(rnp_mkdir_at(root, "tmp") == 0);
        ASSERT(snprintf(payload, sizeof payload, "%s/payload", sub) < (int)sizeof payload);
        ASSERT(rnp_put(payload, "fixture\n") == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"init", "-q", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"add", "payload", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"-c", "user.name=repro",
                       "-c", "user.email=repro@localhost", "commit", "-q",
                       "-m", "submodule", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"rev-parse", "HEAD", NULL},
                       commit, sizeof commit) == 0);
        ASSERT(rnp_git(src, (const char *const[]){"init", "-q", NULL}, out, sizeof out) == 0);
        ASSERT(snprintf(payload, sizeof payload, "%s/Makefile", src) < (int)sizeof payload);
        ASSERT(rnp_put(payload, ".PHONY: zclassic23\nzclassic23:\n"
                       "\tmkdir -p build/bin\n\tcp payload build/bin/z23\n") == 0);
        ASSERT(snprintf(payload, sizeof payload, "%s/payload", src) < (int)sizeof payload);
        ASSERT(rnp_put(payload, "fixture payload\n") == 0);
        ASSERT(snprintf(payload, sizeof payload, "%s/.gitignore", src) < (int)sizeof payload);
        ASSERT(rnp_put(payload, "/build/\nvendor/tor/\n") == 0);
        ASSERT(getcwd(cwd, sizeof cwd) != NULL);
        ASSERT(snprintf(script, sizeof script, "%s/tools/dev/source-identity.sh", cwd) <
               (int)sizeof script);
        ASSERT(snprintf(copy, sizeof copy, "%s/tools/dev/source-identity.sh", src) <
               (int)sizeof copy);
        ASSERT(rnp_run(src, (const char *const[]){"cp", "-p", script, copy, NULL},
                       out, sizeof out) == 0);
        ASSERT(snprintf(payload, sizeof payload, "%s/payload", sub) < (int)sizeof payload);
        ASSERT(rnp_put(payload, "detached fixture\n") == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"add", "payload", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"-c", "user.name=repro",
                       "-c", "user.email=repro@localhost", "commit", "-q",
                       "-m", "detached submodule", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(sub, (const char *const[]){"rev-parse", "HEAD", NULL},
                       commit, sizeof commit) == 0);
        int submodule_rc = rnp_git(src, (const char *const[]){"-c", "protocol.file.allow=always",
                       "submodule", "add", "--force", "--quiet", sub, "vendor/tor", NULL},
                       out, sizeof out);
        test_note("submodule add rc=%d output=%s", submodule_rc, out);
        ASSERT_EQ(submodule_rc, 0);
        char detached[PATH_MAX];
        ASSERT(snprintf(detached, sizeof detached, "%s/vendor/tor", src) < (int)sizeof detached);
        ASSERT(rnp_git(detached, (const char *const[]){"checkout", "-q", "--detach",
                       commit, NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(detached, (const char *const[]){"update-ref", "-d",
                       "refs/heads/master", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(detached, (const char *const[]){"update-ref", "-d",
                       "refs/remotes/origin/master", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(detached, (const char *const[]){"remote", "set-head", "origin",
                       "-d", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(detached, (const char *const[]){"for-each-ref",
                       "--format=%(refname)", NULL}, out, sizeof out) == 0);
        ASSERT_STR_EQ(out, "");
        ASSERT(rnp_git(src, (const char *const[]){"add", "-A", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_git(src, (const char *const[]){"-c", "user.name=repro",
                       "-c", "user.email=repro@localhost", "commit", "-q", "-m",
                       "fixture", NULL}, out, sizeof out) == 0);
        ASSERT(rnp_source_record(src, record, sizeof record) == 0);
        ASSERT(rnp_git(detached, (const char *const[]){"rev-list", "--objects",
                       "--no-object-names", "--no-walk", commit, NULL},
                       out, sizeof out) == 0);
        size_t expected_objects = rnp_lines(out);
        ASSERT(snprintf(script, sizeof script, "%s/tools/scripts/repro-verify.sh", cwd) <
               (int)sizeof script);
        char tmp_env[PATH_MAX + 16];
        ASSERT(snprintf(tmp_env, sizeof tmp_env, "TMPDIR=%s", tmp) < (int)sizeof tmp_env);
        int repro_rc = rnp_run(src, (const char *const[]){"env", "ZCL_REPRO_JOBS=1",
                       "ZCL_REPRO_KEEP=1", "ZCL_REPRO_REFERENCE_BIN=",
                       "ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1", tmp_env, "bash", script,
                       NULL}, log, sizeof log);
        test_note("repro-verify output:\n%s", log);
        ASSERT_EQ(repro_rc, 0);
        const char *marker = "repro-verify: build trees kept at ";
        char *base = strstr(log, marker);
        ASSERT(base != NULL);
        base += strlen(marker);
        char *end = strchr(base, '\n');
        ASSERT(end != NULL);
        *end = '\0';
        test_note("first source record: %.64s", record);
        ASSERT(rnp_gitlink_matches(base, "a", commit, record, expected_objects));
        ASSERT(rnp_gitlink_matches(base, "builder-two-deliberately-longer-path",
                                   commit, record, expected_objects));
        PASS();
    }
    _test_next:;
    if (root[0] && failures == 0)
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_rnp_pass(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[256];
    char err[4096];
    int rc;
    const char *pass =
        "repro_network_policy_selftest: PASS builds=2 make_parse_offline=true "
        "make_parse_cache=false host_cache=false\n";
    TEST("the checkout forces two hermetic repro-verify builds") {
        ASSERT(rnp_case(root, "pass", "all:\n", dir, sizeof dir) == 0);
        rc = rnp_capture(dir, ".", out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s out=%s", rc, err, out);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, pass);
        ASSERT_STR_EQ(err, "");
        rc = rnp_capture(dir, ".", out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(out, pass);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rnp_locale_source_order(void)
{
    int failures = 0;
    static char c_sources[262144], utf8_sources[262144];
    char cwd[PATH_MAX], locale[64];
    TEST("node source order is independent of locale") {
        ASSERT(getcwd(cwd, sizeof cwd) != NULL);
        int locale_rc = rnp_run(cwd, (const char *const[]){
            "env", "LC_ALL=en_US.UTF-8", "locale", "charmap", NULL}, locale,
            sizeof locale);
        test_note("en_US.UTF-8 locale probe rc=%d output=%s", locale_rc, locale);
        ASSERT_EQ(locale_rc, 0);
        ASSERT_STR_EQ(locale, "UTF-8\n");
        ASSERT_EQ(rnp_run(cwd, (const char *const[]){
            "env", "LC_ALL=C", "make", "-s", "print-node-c23-srcs", NULL},
            c_sources, sizeof c_sources), 0);
        ASSERT_EQ(rnp_run(cwd, (const char *const[]){
            "env", "LC_ALL=en_US.UTF-8", "make", "-s", "print-node-c23-srcs", NULL},
            utf8_sources, sizeof utf8_sources), 0);
        ASSERT(strstr(c_sources, "engine/models/src/database.c\n") != NULL);
        ASSERT(strstr(c_sources, "tools/mind/") != NULL);
        ASSERT(strcmp(c_sources, utf8_sources) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_repro_network_policy(void);
int test_repro_network_policy(void)
{
    char root[PATH_MAX];
    int failures = 0;
    test_make_tmpdir(root, sizeof root, "repro_network_policy", "root");
    failures += test_rnp_repo(root);
    failures += test_rnp_order(root);
    failures += test_rnp_caller(root);
    failures += test_rnp_fixture(root);
    failures += test_rnp_locale_source_order();
    failures += test_rnp_gitlink();
    failures += test_rnp_pass(root);
    if (failures == 0)
        printf("test_repro_network_policy: all passed\n");
    else
        printf("test_repro_network_policy: %d FAILED\n", failures);
    return failures;
}
