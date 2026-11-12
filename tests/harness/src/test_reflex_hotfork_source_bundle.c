/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_reflex_hotfork_source_bundle with a stand-in dev binary. */

#include "test/test_core.h"

#include "reflex_hotfork_source_bundle.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_owner[] =
    "int zsb_paths_disjoint(const char *left, const char *right)\n"
    "{\n"
    "    return strcmp(left, right) != 0 &&\n"
    "        left[0] != right[0];\n"
    "}\n";

static const char k_plain[] = "int zsb_ok(void) { return 1; }\n";

static void rsb_hex(char *dst, char bit)
{
    memset(dst, bit, 64);
    dst[64] = 0;
}

static int rsb_mkdir(const char *path)
{
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rsb_write(const char *path, const char *body, mode_t mode)
{
    FILE *fp;
    size_t n;
    unlink(path);
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    n = strlen(body);
    if (fwrite(body, 1, n, fp) != n || fclose(fp) != 0)
        return -1;
    return chmod(path, mode) == 0 ? 0 : -1;
}

static int rsb_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = 0;
    return 0;
}

static int rsb_count(const char *text, const char *needle)
{
    int count = 0;
    const char *p = text;
    size_t n = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += n;
    }
    return count;
}

static int rsb_write_stub(const char *path, const char *log, const char *src,
                          const char *state)
{
    char obj[65], mod[65], obs_g[65], obs_r[65], story[65], fix[65];
    FILE *fp;
    rsb_hex(obj, 'a');
    rsb_hex(mod, 'b');
    rsb_hex(obs_g, 'c');
    rsb_hex(obs_r, 'd');
    rsb_hex(story, 'e');
    rsb_hex(fix, '1');
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    fputs("#!/bin/sh\n", fp);
    fprintf(fp, "log='%s'\nsrc='%s'\nstate='%s'\n", log, src, state);
    fprintf(fp, "OBJ='%s'\nMOD='%s'\nOBS_G='%s'\nOBS_R='%s'\n", obj, mod, obs_g,
            obs_r);
    fprintf(fp, "SROOT='%s'\nFROOT='%s'\n", story, fix);
    fputs(
        "mode=${RSB_MODE:-ok}\n"
        "printf '%s\\n' \"$*\" >> \"$log\"\n"
        "if [ \"$1 $2\" = \"dev begin\" ]; then\n"
        "  if [ \"$mode\" = begin-fail ]; then exit 4; fi\n"
        "  printf '%s\\n' '{\"ok\":true,\"data\":{\"watcher_id\":7,\"watcher_session\":\"sess-1\",\"epoch\":3}}'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2\" = drive ]; then\n"
        "  if grep -q 'return strcmp(left, right) == 0 &&' \"$src\"; then\n"
        "    printf '%s\\n' kind=red >> \"$log\"\n"
        "    ev=STORY_RED\n"
        "    obs=$OBS_R\n"
        "  elif grep -q 'ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE:' \"$src\"; then\n"
        "    printf '%s\\n' kind=green >> \"$log\"\n"
        "    grep 'ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE:' \"$src\" >> \"$log\"\n"
        "    ev=STORY_GREEN\n"
        "    obs=$OBS_G\n"
        "  else\n"
        "    printf '%s\\n' kind=other >> \"$log\"\n"
        "    ev=STORY_GREEN\n"
        "    obs=$OBS_G\n"
        "  fi\n"
        "  n=3\n"
        "  if [ -f \"$state\" ]; then n=$(cat \"$state\"); fi\n"
        "  n=$((n + 1))\n"
        "  printf '%s\\n' \"$n\" > \"$state\"\n"
        "  if [ \"$mode\" = stall ]; then n=3; fi\n"
        "  class=HOT_FORK\n"
        "  if [ \"$mode\" = bad-class ]; then class=NOPE; fi\n"
        "  printf '{\"ok\":true,\"data\":{\"event\":\"%s\",\"epoch\":%s,\"feedback_class\":\"%s\",\"story_fixture_id\":\"zcode-source-bundle-input-policy.v1\",\"story_adapter\":\"zcode-source-bundle-input-policy.v1\",\"story_timeout_ms\":1000,\"forbidden_effect_mask\":\"git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite\",\"candidate_bytes_executed\":true,\"runtime_published\":false,\"feedback_us\":10,\"candidate_object_root\":\"%s\",\"candidate_module_root\":\"%s\",\"loaded_mapping_root\":\"%s\",\"story_root\":\"%s\",\"story_fixture_root\":\"%s\",\"observation_root\":\"%s\"}}\\n' \\\n"
        "    \"$ev\" \"$n\" \"$class\" \"$OBJ\" \"$MOD\" \"$MOD\" \"$SROOT\" \"$FROOT\" \"$obs\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2 $3\" = \"loop wait\" ]; then\n"
        "  wf=\"$state.waits\"\n"
        "  w=0\n"
        "  if [ -f \"$wf\" ]; then w=$(cat \"$wf\"); fi\n"
        "  w=$((w + 1))\n"
        "  printf '%s\\n' \"$w\" > \"$wf\"\n"
        "  hit=true\n"
        "  root=$OBJ\n"
        "  if [ \"$w\" = 1 ]; then hit=false; root=$OBS_R; fi\n"
        "  if [ \"$mode\" = cache-miss ]; then hit=false; root=$OBJ; fi\n"
        "  printf '{\"ok\":true,\"data\":{\"phase\":\"STORY_GREEN\",\"build_receipt\":{\"artifact_cache_hit\":%s,\"compiler_processes\":0,\"linker_processes\":0},\"candidate_object_root\":\"%s\",\"candidate_module_root\":\"%s\"}}\\n' \\\n"
        "    \"$hit\" \"$root\" \"$MOD\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2 $3\" = \"loop stop\" ]; then\n"
        "  if [ \"$mode\" = stop-fail ]; then exit 5; fi\n"
        "  exit 0\n"
        "fi\n"
        "exit 9\n",
        fp);
    if (fclose(fp) != 0)
        return -1;
    return chmod(path, 0755);
}

struct rsb_saved {
    char root[PATH_MAX];
    char bin[PATH_MAX];
    char output[PATH_MAX];
    char tmp[PATH_MAX];
    char mode[64];
    int has_root, has_bin, has_output, has_tmp, has_mode;
};

static void rsb_keep(char *dst, size_t cap, const char *name, int *has)
{
    const char *v = getenv(name);
    dst[0] = 0;
    *has = v != NULL;
    if (v != NULL && strlen(v) + 1 <= cap)
        memcpy(dst, v, strlen(v) + 1);
}

static void rsb_save(struct rsb_saved *s)
{
    rsb_keep(s->root, sizeof s->root, "ZCL_SOURCE_ROOT", &s->has_root);
    rsb_keep(s->bin, sizeof s->bin, "ZCL_DEV_BIN", &s->has_bin);
    rsb_keep(s->output, sizeof s->output,
             "ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT", &s->has_output);
    rsb_keep(s->tmp, sizeof s->tmp, "TMPDIR", &s->has_tmp);
    rsb_keep(s->mode, sizeof s->mode, "RSB_MODE", &s->has_mode);
}

static void rsb_putenv(const char *name, const char *value, int has)
{
    if (has)
        setenv(name, value, 1);
    else
        unsetenv(name);
}

static void rsb_restore(const struct rsb_saved *s)
{
    rsb_putenv("ZCL_SOURCE_ROOT", s->root, s->has_root);
    rsb_putenv("ZCL_DEV_BIN", s->bin, s->has_bin);
    rsb_putenv("ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT", s->output,
               s->has_output);
    rsb_putenv("TMPDIR", s->tmp, s->has_tmp);
    rsb_putenv("RSB_MODE", s->mode, s->has_mode);
}

static int rsb_capture(char *out, size_t out_cap, char *err, size_t err_cap,
                       int *rc)
{
    char out_path[] = "rsb-out";
    char err_path[] = "rsb-err";
    int fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *fp;
    size_t n;
    if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_reflex_hotfork_source_bundle();
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    fp = fopen(out_path, "r");
    if (fp == NULL)
        return -1;
    n = fread(out, 1, out_cap - 1, fp);
    fclose(fp);
    out[n] = 0;
    fp = fopen(err_path, "r");
    if (fp == NULL)
        return -1;
    n = fread(err, 1, err_cap - 1, fp);
    fclose(fp);
    err[n] = 0;
    unlink(out_path);
    unlink(err_path);
    return 0;
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

static int rsb_tree(const char *root, const char *body)
{
    char path[PATH_MAX];
    if (rsb_mkdir(root) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/tmp", root) >= (int)sizeof path)
        return -1;
    if (rsb_mkdir(path) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/bin", root) >= (int)sizeof path)
        return -1;
    if (rsb_mkdir(path) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/tools", root) >= (int)sizeof path)
        return -1;
    if (rsb_mkdir(path) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/tools/command", root) >= (int)sizeof path)
        return -1;
    if (rsb_mkdir(path) != 0)
        return -1;
    if (snprintf(path, sizeof path,
                 "%s/tools/command/native_zcode_source_bundle_command.c",
                 root) >= (int)sizeof path)
        return -1;
    return rsb_write(path, body, 0640);
}

static int rsb_arm(const char *root, const char *mode, int with_output)
{
    char bin[PATH_MAX], log[PATH_MAX], src[PATH_MAX], state[PATH_MAX];
    char tmp[PATH_MAX], out[PATH_MAX];
    unlink("rsb-log");
    unlink("rsb-state");
    if (snprintf(bin, sizeof bin, "%s/bin/z23-dev", root) >= (int)sizeof bin)
        return -1;
    if (snprintf(log, sizeof log, "%s/rsb-log", root) >= (int)sizeof log)
        return -1;
    if (snprintf(src, sizeof src,
                 "%s/tools/command/native_zcode_source_bundle_command.c",
                 root) >= (int)sizeof src)
        return -1;
    if (snprintf(state, sizeof state, "%s/rsb-state", root) >= (int)sizeof state)
        return -1;
    if (snprintf(tmp, sizeof tmp, "%s/tmp", root) >= (int)sizeof tmp)
        return -1;
    if (snprintf(out, sizeof out, "%s/receipt.json", root) >= (int)sizeof out)
        return -1;
    unlink(log);
    unlink(state);
    unlink(out);
    {
        char waits[PATH_MAX];
        if (snprintf(waits, sizeof waits, "%s.waits", state) > 0)
            unlink(waits);
    }
    if (rsb_write_stub(bin, log, src, state) != 0)
        return -1;
    if (setenv("ZCL_SOURCE_ROOT", root, 1) != 0)
        return -1;
    if (setenv("ZCL_DEV_BIN", bin, 1) != 0)
        return -1;
    if (setenv("TMPDIR", tmp, 1) != 0)
        return -1;
    if (setenv("RSB_MODE", mode, 1) != 0)
        return -1;
    if (with_output)
        return setenv("ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT", out, 1);
    unsetenv("ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT");
    return 0;
}

static int test_rsb_missing(const char *root)
{
    int failures = 0;
    char err1[512], err2[512], out[256];
    char missing[PATH_MAX];
    int rc1 = -1, rc2 = -1;
    TEST("missing dev binary is stable") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(snprintf(missing, sizeof missing, "%s/bin/absent", root) > 0);
        ASSERT(setenv("ZCL_SOURCE_ROOT", root, 1) == 0);
        ASSERT(setenv("ZCL_DEV_BIN", missing, 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err1, sizeof err1, &rc1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err2, sizeof err2, &rc2) == 0);
        ASSERT_EQ(rc1, 2);
        ASSERT_EQ(rc2, 2);
        ASSERT(strcmp(err1, err2) == 0);
        ASSERT(strstr(err1, "reflex-hotfork-source-bundle-acceptance: missing dev binary: ") ==
               err1);
        ASSERT(strstr(err1, missing) != NULL);
        ASSERT(strstr(out, "PASS") == NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_symlink(const char *root)
{
    int failures = 0;
    char err[512], out[256], link_path[PATH_MAX], real_path[PATH_MAX];
    int rc = -1;
    TEST("symlink owner source is refused") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(snprintf(real_path, sizeof real_path, "%s/tools/command/owner-real.c",
                        root) > 0);
        ASSERT(snprintf(link_path, sizeof link_path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_write(real_path, k_owner, 0644) == 0);
        ASSERT(unlink(link_path) == 0);
        ASSERT(symlink("owner-real.c", link_path) == 0);
        ASSERT(rsb_arm(root, "ok", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "owner source is not a regular file: ") != NULL);
        ASSERT(rsb_read(real_path, out, sizeof out) == 0);
        ASSERT(strcmp(out, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_happy(const char *root)
{
    int failures = 0;
    char err[1024], out[2048], again[2048], log[4096], src[8192];
    char path[PATH_MAX];
    char receipt_a[4096], receipt_b[4096];
    struct stat st;
    int rc = -1;
    TEST("green red revert receipt and restored source") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "ok", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(err[0] == '\0');
        ASSERT(snprintf(path, sizeof path, "%s/receipt.json", root) > 0);
        ASSERT(strstr(out, "reflex-hotfork-source-bundle-acceptance: PASS receipt=") == out);
        ASSERT(strstr(out, path) != NULL);
        ASSERT(rsb_read(path, receipt_a, sizeof receipt_a) == 0);
        ASSERT(strstr(receipt_a, "\"schema\": \"zcl.reflex_owner_acceptance.v1\"") != NULL);
        ASSERT(strstr(receipt_a, "\"event\": \"STORY_GREEN\"") != NULL);
        ASSERT(strstr(receipt_a, "\"event\": \"STORY_RED\"") != NULL);
        ASSERT(strstr(receipt_a, "\"compile_valid\": true") != NULL);
        ASSERT(strstr(receipt_a, "\"artifact_cache_hit\": true") != NULL);
        ASSERT(strstr(receipt_a, "\"compiler_processes\": 0") != NULL);
        ASSERT(strstr(receipt_a, "\"linker_processes\": 0") != NULL);
        ASSERT(strstr(receipt_a, "\"same_object\": true") != NULL);
        ASSERT(strstr(receipt_a, "\"same_module\": true") != NULL);
        ASSERT(strstr(receipt_a, "\"runtime_published\": false") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        ASSERT(stat(path, &st) == 0);
        ASSERT_EQ((int)(st.st_mode & 0777), 0640);
        ASSERT(snprintf(path, sizeof path, "%s/rsb-log", root) > 0);
        ASSERT(rsb_read(path, log, sizeof log) == 0);
        ASSERT_EQ(rsb_count(log, "dev begin"), 1);
        ASSERT_EQ(rsb_count(log, "dev drive"), 3);
        ASSERT_EQ(rsb_count(log, "dev loop wait"), 2);
        ASSERT_EQ(rsb_count(log, "dev loop stop"), 1);
        ASSERT_EQ(rsb_count(log, "kind=green"), 2);
        ASSERT_EQ(rsb_count(log, "kind=red"), 1);
        ASSERT_EQ(rsb_count(log, "ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE:"), 2);
        ASSERT(strstr(log, "\"after_epoch\":3,\"wait_for_edit\":true") != NULL);
        ASSERT(strstr(log, "\"after_epoch\":4,\"wait_for_edit\":true") != NULL);
        ASSERT(strstr(log, "\"after_epoch\":5,\"wait_for_edit\":true") != NULL);
        ASSERT(strstr(log, "\"watcher_id\":7,\"watcher_session\":\"sess-1\"") != NULL);
        ASSERT(rsb_arm(root, "ok", 1) == 0);
        ASSERT(rsb_capture(again, sizeof again, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(snprintf(path, sizeof path, "%s/receipt.json", root) > 0);
        ASSERT(rsb_read(path, receipt_b, sizeof receipt_b) == 0);
        ASSERT(strcmp(receipt_a, receipt_b) == 0);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_default_output(const char *root)
{
    int failures = 0;
    char err[256], out[1024], path[PATH_MAX], body[512];
    int rc = -1;
    TEST("default receipt path") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "ok", 0) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 0);
        ASSERT(snprintf(path, sizeof path,
                        "%s/build/dev-loop/reflex-hotfork-source-bundle-acceptance.json",
                        root) > 0);
        ASSERT(strstr(out, path) != NULL);
        ASSERT(rsb_read(path, body, sizeof body) == 0);
        ASSERT(strstr(body, "zcl.reflex_owner_acceptance.v1") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_mutant(const char *root)
{
    int failures = 0;
    char err[512], out[256], src[1024], path[PATH_MAX], log[2048];
    int rc = -1;
    TEST("unstaged semantic mutation restores the owner") {
        ASSERT(rsb_tree(root, k_plain) == 0);
        ASSERT(rsb_arm(root, "ok", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "compile-valid semantic mutation was not staged") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_plain) == 0);
        ASSERT(snprintf(path, sizeof path, "%s/rsb-log", root) > 0);
        ASSERT(rsb_read(path, log, sizeof log) == 0);
        ASSERT_EQ(rsb_count(log, "kind=red"), 0);
        ASSERT(strstr(out, "PASS") == NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_stall(const char *root)
{
    int failures = 0;
    char err[2048], out[256], src[1024], path[PATH_MAX];
    int rc = -1;
    TEST("a stuck event cursor is reported and restored") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "stall", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "event cursor did not advance: ") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_bound(const char *root)
{
    int failures = 0;
    char err[4096], out[256], src[1024], path[PATH_MAX];
    int rc = -1;
    TEST("an unbound story fails closed") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "bad-class", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "candidate did not return bound STORY_GREEN: ") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_cache(const char *root)
{
    int failures = 0;
    char err[512], out[256], src[1024], path[PATH_MAX];
    int rc = -1;
    TEST("a cache miss refuses the revert") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "cache-miss", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "exact revert did not reuse the exact verified capsule cache") !=
               NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_begin_fail(const char *root)
{
    int failures = 0;
    char err[256], out[256], src[1024], path[PATH_MAX];
    int rc = -1;
    TEST("dev begin status is preserved") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "begin-fail", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 4);
        ASSERT(strstr(out, "PASS") == NULL);
        ASSERT(snprintf(path, sizeof path, "%s/receipt.json", root) > 0);
        ASSERT(stat(path, &(struct stat){0}) != 0);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rsb_stop_fail(const char *root)
{
    int failures = 0;
    char err[256], out[256], src[1024], path[PATH_MAX], body[512];
    int rc = -1;
    TEST("a failed stop still restores the owner") {
        ASSERT(rsb_tree(root, k_owner) == 0);
        ASSERT(rsb_arm(root, "stop-fail", 1) == 0);
        ASSERT(rsb_capture(out, sizeof out, err, sizeof err, &rc) == 0);
        ASSERT_EQ(rc, 5);
        ASSERT(strstr(out, "PASS") == NULL);
        ASSERT(snprintf(path, sizeof path, "%s/receipt.json", root) > 0);
        ASSERT(rsb_read(path, body, sizeof body) == 0);
        ASSERT(strstr(body, "zcl.reflex_owner_acceptance.v1") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/tools/command/native_zcode_source_bundle_command.c",
                        root) > 0);
        ASSERT(rsb_read(path, src, sizeof src) == 0);
        ASSERT(strcmp(src, k_owner) == 0);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_reflex_hotfork_source_bundle(void);
int test_reflex_hotfork_source_bundle(void)
{
    char root[PATH_MAX];
    char cwd[PATH_MAX];
    struct rsb_saved saved;
    int failures;
    if (getcwd(cwd, sizeof cwd) == NULL)
        return 1;
    rsb_save(&saved);
    test_make_tmpdir(root, sizeof root, "reflex_source_bundle", "root");
    if (chdir(root) != 0) {
        rsb_restore(&saved);
        return 1;
    }
    failures = test_rsb_missing(root);
    failures += test_rsb_symlink(root);
    failures += test_rsb_happy(root);
    failures += test_rsb_default_output(root);
    failures += test_rsb_mutant(root);
    failures += test_rsb_stall(root);
    failures += test_rsb_bound(root);
    failures += test_rsb_cache(root);
    failures += test_rsb_begin_fail(root);
    failures += test_rsb_stop_fail(root);
    if (chdir(cwd) != 0)
        failures += 1;
    rsb_restore(&saved);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_reflex_hotfork_source_bundle: all passed\n");
    else
        printf("test_reflex_hotfork_source_bundle: %d FAILED\n", failures);
    return failures;
}
