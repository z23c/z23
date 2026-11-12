/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive both shop hotfork acceptance functions with a stand-in
 *          dev binary. */

#include "test/test_core.h"

#include "reflex_hotfork_shop.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_status_body[] =
    "int shop_status(void) { return out.gap_count != 5; }\n";

static const char k_reputation_body[] =
    "int shop_reputation(void) {\n"
    "    return result.row_count != SHOP_REPUTATION_VIEW_ROW_COUNT;\n"
    "}\n";

static const char k_zcode_body[] =
    "int zcode_work(void) {\n"
    "    return have == len && memcmp(at, part, len) == 0;\n"
    "}\n";

static const char k_plain[] = "int shop_plain(void) { return 1; }\n";

static const char k_unrelated[] = "int market_moderation(void) { return 1; }\n";

struct rhs_saved {
    char root[PATH_MAX];
    char bin[PATH_MAX];
    char status_out[PATH_MAX];
    char reputation_out[PATH_MAX];
    char zcode_out[PATH_MAX];
    char tmp[PATH_MAX];
    int has_root, has_bin, has_status, has_reputation, has_zcode, has_tmp;
};

static void rhs_keep(char *dst, size_t cap, const char *name, int *has)
{
    const char *v = getenv(name);
    dst[0] = '\0';
    *has = v != NULL;
    if (v != NULL && strlen(v) + 1 <= cap)
        memcpy(dst, v, strlen(v) + 1);
}

static void rhs_save(struct rhs_saved *s)
{
    rhs_keep(s->root, sizeof s->root, "ZCL_SOURCE_ROOT", &s->has_root);
    rhs_keep(s->bin, sizeof s->bin, "ZCL_DEV_BIN", &s->has_bin);
    rhs_keep(s->status_out, sizeof s->status_out,
             "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT", &s->has_status);
    rhs_keep(s->reputation_out, sizeof s->reputation_out,
             "ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT", &s->has_reputation);
    rhs_keep(s->zcode_out, sizeof s->zcode_out,
             "ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT", &s->has_zcode);
    rhs_keep(s->tmp, sizeof s->tmp, "TMPDIR", &s->has_tmp);
}

static void rhs_putenv(const char *name, const char *value, int has)
{
    if (has)
        setenv(name, value, 1);
    else
        unsetenv(name);
}

static void rhs_restore_env(const struct rhs_saved *s)
{
    rhs_putenv("ZCL_SOURCE_ROOT", s->root, s->has_root);
    rhs_putenv("ZCL_DEV_BIN", s->bin, s->has_bin);
    rhs_putenv("ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT", s->status_out, s->has_status);
    rhs_putenv("ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT", s->reputation_out,
               s->has_reputation);
    rhs_putenv("ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT", s->zcode_out, s->has_zcode);
    rhs_putenv("TMPDIR", s->tmp, s->has_tmp);
}

static int rhs_mkdir(const char *path)
{
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rhs_sub(const char *root, const char *rel)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", root, rel) >= (int)sizeof path)
        return -1;
    return rhs_mkdir(path);
}

static int rhs_write(const char *path, const char *body, mode_t mode)
{
    FILE *fp;
    unlink(path);
    fp = fopen(path, "w");
    size_t n;
    if (fp == NULL)
        return -1;
    n = strlen(body);
    if (fwrite(body, 1, n, fp) != n || fclose(fp) != 0)
        return -1;
    return chmod(path, mode) == 0 ? 0 : -1;
}

static int rhs_read(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static void rhs_hex(char *dst, char bit)
{
    memset(dst, bit, 64);
    dst[64] = '\0';
}

static int rhs_tree(const char *root)
{
    static const char *dirs[] = {
        "tmp", "bin",
        "contexts", "contexts/market", "contexts/market/controllers",
        "contexts/market/controllers/src", "contexts/market/services",
        "contexts/market/services/src", "tools", "tools/command", NULL};
    int i;
    if (rhs_mkdir(root) != 0)
        return -1;
    for (i = 0; dirs[i] != NULL; i++) {
        if (rhs_sub(root, dirs[i]) != 0)
            return -1;
    }
    return 0;
}

static int rhs_stub(const char *path, const char *state)
{
    char obj[65], mod[65], obs_g[65], obs_r[65], story[65], fix[65];
    FILE *fp;
    rhs_hex(obj, 'a');
    rhs_hex(mod, 'b');
    rhs_hex(obs_g, 'c');
    rhs_hex(obs_r, 'd');
    rhs_hex(story, 'e');
    rhs_hex(fix, '1');
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    fputs("#!/bin/sh\n", fp);
    fprintf(fp, "state='%s'\nOBJ='%s'\nMOD='%s'\nOBS_G='%s'\nOBS_R='%s'\n",
            state, obj, mod, obs_g, obs_r);
    fprintf(fp, "SROOT='%s'\nFROOT='%s'\n", story, fix);
    fputs(
        "printf '%s\\n' \"$*\" >> \"$state.log\"\n"
        "if [ \"$1 $2\" = \"dev begin\" ]; then\n"
        "  printf '%s\\n' '{\"ok\":true,\"data\":{\"watcher_id\":7,\"watcher_session\":\"sess-1\",\"epoch\":3}}'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2\" = drive ]; then\n"
        "  n=0\n"
        "  if [ -f \"$state\" ]; then n=$(cat \"$state\"); fi\n"
        "  n=$((n + 1))\n"
        "  printf '%s\\n' \"$n\" > \"$state\"\n"
        "  ev=STORY_GREEN\n"
        "  obs=$OBS_G\n"
        "  detail=ok\n"
        "  sid=shop-other\n"
        "  if [ \"$n\" = 2 ]; then ev=WATCH; fi\n"
        "  if [ \"$n\" = 4 ]; then ev=STORY_RED; obs=$OBS_R; detail=gap; sid=shop-red; fi\n"
        "  epoch=$((3 + n))\n"
        "  printf '{\"ok\":true,\"data\":{\"event\":\"%s\",\"epoch\":%s,\"feedback_class\":\"HOT_FORK\",\"story_fixture_id\":\"%s\",\"story_adapter\":\"%s\",\"story_timeout_ms\":1000,\"forbidden_effect_mask\":\"git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite\",\"candidate_bytes_executed\":true,\"runtime_published\":false,\"feedback_us\":10,\"candidate_object_root\":\"%s\",\"candidate_module_root\":\"%s\",\"loaded_mapping_root\":\"%s\",\"story_root\":\"%s\",\"story_fixture_root\":\"%s\",\"observation_root\":\"%s\",\"story_id\":\"%s\",\"story_detail\":\"%s\"}}\\n' \\\n"
        "    \"$ev\" \"$epoch\" \"$RHS_STORY\" \"$RHS_STORY\" \"$OBJ\" \"$MOD\" \"$MOD\" \"$SROOT\" \"$FROOT\" \"$obs\" \"$sid\" \"$detail\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2 $3\" = \"loop wait\" ]; then\n"
        "  printf '{\"ok\":true,\"data\":{\"artifact_cache_hit\":true,\"compiler_processes\":0,\"linker_processes\":0,\"candidate_object_root\":\"%s\",\"candidate_module_root\":\"%s\"}}\\n' \\\n"
        "    \"$OBJ\" \"$MOD\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$2 $3\" = \"loop stop\" ]; then exit 0; fi\n"
        "exit 9\n",
        fp);
    if (fclose(fp) != 0)
        return -1;
    return chmod(path, 0755);
}

static int rhs_arm(const char *root, const char *owner_rel, const char *owner_body,
                   const char *story, const char *output_env)
{
    char bin[PATH_MAX], state[PATH_MAX], tmp[PATH_MAX], out[PATH_MAX];
    char owner[PATH_MAX], unrelated[PATH_MAX];
    if (snprintf(bin, sizeof bin, "%s/bin/z23-dev", root) >= (int)sizeof bin)
        return -1;
    if (snprintf(state, sizeof state, "%s/state", root) >= (int)sizeof state)
        return -1;
    if (snprintf(tmp, sizeof tmp, "%s/tmp", root) >= (int)sizeof tmp)
        return -1;
    if (snprintf(out, sizeof out, "%s/receipt.json", root) >= (int)sizeof out)
        return -1;
    if (snprintf(owner, sizeof owner, "%s/%s", root, owner_rel) >= (int)sizeof owner)
        return -1;
    if (snprintf(unrelated, sizeof unrelated,
                 "%s/contexts/market/services/src/market_moderation_service.c",
                 root) >= (int)sizeof unrelated)
        return -1;
    unlink(state);
    unlink(out);
    if (rhs_write(owner, owner_body, 0640) != 0)
        return -1;
    if (rhs_write(unrelated, k_unrelated, 0640) != 0)
        return -1;
    if (rhs_stub(bin, state) != 0)
        return -1;
    if (setenv("ZCL_SOURCE_ROOT", root, 1) != 0)
        return -1;
    if (setenv("ZCL_DEV_BIN", bin, 1) != 0)
        return -1;
    if (setenv("TMPDIR", tmp, 1) != 0)
        return -1;
    if (setenv("RHS_STORY", story, 1) != 0)
        return -1;
    if (setenv(output_env, out, 1) != 0)
        return -1;
    return 0;
}

static int rhs_capture(int (*fn)(void), char *out, size_t out_cap, char *err, size_t err_cap)
{
    char out_path[] = "rhs-out";
    char err_path[] = "rhs-err";
    int fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *fp;
    size_t n;
    int rc;
    if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = fn();
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
    out[n] = '\0';
    fp = fopen(err_path, "r");
    if (fp == NULL)
        return -1;
    n = fread(err, 1, err_cap - 1, fp);
    fclose(fp);
    err[n] = '\0';
    unlink(out_path);
    unlink(err_path);
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

static int test_rhs_missing(const char *root)
{
    int failures = 0;
    char err[512], out[256], missing[PATH_MAX];
    int rc;
    TEST("missing dev binary is refused") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_handler.c",
                       k_status_body, "shop-status-view-contract.v1",
                       "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT") == 0);
        ASSERT(snprintf(missing, sizeof missing, "%s/bin/absent", root) > 0);
        ASSERT(setenv("ZCL_DEV_BIN", missing, 1) == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "reflex-hotfork-shop-status-acceptance: missing dev binary: ") == err);
        ASSERT(strstr(err, missing) != NULL);
        ASSERT(strstr(out, "PASS") == NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_link(const char *root)
{
    int failures = 0;
    char err[512], out[256], owner[PATH_MAX], real_path[PATH_MAX];
    int rc;
    TEST("a symlink owner is refused") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(snprintf(real_path, sizeof real_path, "%s/tmp/owner-real.c", root) > 0);
        ASSERT(rhs_write(real_path, k_status_body, 0640) == 0);
        ASSERT(snprintf(owner, sizeof owner,
                        "%s/contexts/market/controllers/src/shop_native_handler.c",
                        root) > 0);
        unlink(owner);
        ASSERT(symlink(real_path, owner) == 0);
        ASSERT(snprintf(owner, sizeof owner, "%s/bin/z23-dev", root) > 0);
        ASSERT(rhs_write(owner, "#!/bin/sh\nexit 0\n", 0755) == 0);
        ASSERT(setenv("ZCL_SOURCE_ROOT", root, 1) == 0);
        ASSERT(setenv("ZCL_DEV_BIN", owner, 1) == 0);
        ASSERT(setenv("TMPDIR", root, 1) == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "owner source is not a regular file: ") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int rhs_same(const char *path, const char *body)
{
    char buf[1024];
    if (rhs_read(path, buf, sizeof buf) != 0)
        return 0;
    return strcmp(buf, body) == 0;
}

static int test_rhs_status(const char *root)
{
    int failures = 0;
    char err[1024], out[1024], receipt[8192];
    char owner[PATH_MAX], unrelated[PATH_MAX], rec_path[PATH_MAX];
    int rc;
    TEST("status acceptance restores both files and writes the receipt") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_handler.c",
                       k_status_body, "shop-status-view-contract.v1",
                       "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT") == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "reflex-hotfork-shop-status-acceptance: PASS receipt=") == out);
        ASSERT_STR_EQ(err, "");
        ASSERT(snprintf(owner, sizeof owner,
                        "%s/contexts/market/controllers/src/shop_native_handler.c",
                        root) > 0);
        ASSERT(snprintf(unrelated, sizeof unrelated,
                        "%s/contexts/market/services/src/market_moderation_service.c",
                        root) > 0);
        ASSERT(rhs_same(owner, k_status_body));
        ASSERT(rhs_same(unrelated, k_unrelated));
        ASSERT(snprintf(rec_path, sizeof rec_path, "%s/receipt.json", root) > 0);
        ASSERT(rhs_read(rec_path, receipt, sizeof receipt) == 0);
        ASSERT(strstr(receipt, "zcl.reflex_owner_acceptance.v1") != NULL);
        ASSERT(strstr(receipt, "contexts/market/controllers/src/shop_native_handler.c") != NULL);
        ASSERT(strstr(receipt, "\"event\": \"STORY_GREEN\"") != NULL);
        ASSERT(strstr(receipt, "\"event\": \"STORY_RED\"") != NULL);
        ASSERT(strstr(receipt, "\"false_owner_attribution\": false") != NULL);
        ASSERT(strstr(receipt, "\"story_detail\": \"gap\"") != NULL);
        ASSERT(strstr(receipt, "\"runtime_published\": false") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_zcode(const char *root)
{
    int failures = 0;
    char err[1024], out[1024], receipt[8192];
    char owner[PATH_MAX], unrelated[PATH_MAX], rec_path[PATH_MAX];
    int rc;
    TEST("zcode work acceptance restores both files and writes the receipt") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "tools/command/native_zcode_work_command.c",
                       k_zcode_body, "zcode-work-input-core.v1",
                       "ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT") == 0);
        rc = rhs_capture(zcl_reflex_hotfork_zcode_work, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "reflex-hotfork-zcode-work-acceptance: PASS receipt=") == out);
        ASSERT_STR_EQ(err, "");
        ASSERT(snprintf(owner, sizeof owner,
                        "%s/tools/command/native_zcode_work_command.c",
                        root) > 0);
        ASSERT(snprintf(unrelated, sizeof unrelated,
                        "%s/contexts/market/services/src/market_moderation_service.c",
                        root) > 0);
        ASSERT(rhs_same(owner, k_zcode_body));
        ASSERT(rhs_same(unrelated, k_unrelated));
        ASSERT(snprintf(rec_path, sizeof rec_path, "%s/receipt.json", root) > 0);
        ASSERT(rhs_read(rec_path, receipt, sizeof receipt) == 0);
        ASSERT(strstr(receipt, "zcl.reflex_owner_acceptance.v1") != NULL);
        ASSERT(strstr(receipt, "tools/command/native_zcode_work_command.c") != NULL);
        ASSERT(strstr(receipt, "\"event\": \"STORY_GREEN\"") != NULL);
        ASSERT(strstr(receipt, "\"event\": \"STORY_RED\"") != NULL);
        ASSERT(strstr(receipt, "\"false_owner_attribution\": false") != NULL);
        ASSERT(strstr(receipt, "\"story_detail\": \"gap\"") != NULL);
        ASSERT(strstr(receipt, "\"runtime_published\": false") != NULL);
        ASSERT(rhs_arm(root, "tools/command/native_zcode_work_command.c",
                       k_zcode_body, "zcode-work-input-core.v1",
                       "ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT") == 0);
        ASSERT(setenv("ZCL_REFLEX_ZCODE_WORK_ACCEPTANCE_OUTPUT", "", 1) == 0);
        rc = rhs_capture(zcl_reflex_hotfork_zcode_work, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "build/dev-loop/reflex-hotfork-zcode-work-acceptance.json") != NULL);
        ASSERT(strstr(out, "/receipt.json") == NULL);
        ASSERT(snprintf(rec_path, sizeof rec_path,
                        "%s/build/dev-loop/reflex-hotfork-zcode-work-acceptance.json",
                        root) > 0);
        ASSERT(rhs_read(rec_path, receipt, sizeof receipt) == 0);
        ASSERT(strstr(receipt, "native_zcode_work_command.c") != NULL);
        ASSERT(rhs_same(owner, k_zcode_body));
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_reputation(const char *root)
{
    int failures = 0;
    char err[1024], out[1024], owner[PATH_MAX];
    int rc;
    TEST("reputation acceptance restores the owner file") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_reputation.c",
                       k_reputation_body, "shop-reputation-view-contract.v1",
                       "ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT") == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_reputation, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "reflex-hotfork-shop-reputation-acceptance: PASS receipt=") == out);
        ASSERT(snprintf(owner, sizeof owner,
                        "%s/contexts/market/controllers/src/shop_native_reputation.c",
                        root) > 0);
        ASSERT(rhs_same(owner, k_reputation_body));
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_stop(const char *root)
{
    int failures = 0;
    char err[1024], out[256], log_path[PATH_MAX], log[4096];
    int rc;
    TEST("a failure after begin still stops the watcher") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_handler.c",
                       k_plain, "shop-status-view-contract.v1",
                       "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT") == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "compile-valid semantic mutation was not staged") != NULL);
        ASSERT(snprintf(log_path, sizeof log_path, "%s/state.log", root) > 0);
        ASSERT(rhs_read(log_path, log, sizeof log) == 0);
        ASSERT(strstr(log, "dev begin") != NULL);
        ASSERT(strstr(log, "loop stop") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_empty_output(const char *root)
{
    int failures = 0;
    char err[1024], out[1024], receipt[8192], path[PATH_MAX];
    int rc;
    TEST("an empty shop output variable uses the default receipt") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_handler.c",
                       k_status_body, "shop-status-view-contract.v1",
                       "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT") == 0);
        ASSERT(setenv("ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT", "", 1) == 0);
        ASSERT(setenv("ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT", "", 1) == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "build/dev-loop/reflex-hotfork-shop-status-acceptance.json") != NULL);
        ASSERT(strstr(out, "/receipt.json") == NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/build/dev-loop/reflex-hotfork-shop-status-acceptance.json",
                        root) > 0);
        ASSERT(rhs_read(path, receipt, sizeof receipt) == 0);
        ASSERT(strstr(receipt, "zcl.reflex_owner_acceptance.v1") != NULL);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_reputation.c",
                       k_reputation_body, "shop-reputation-view-contract.v1",
                       "ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT") == 0);
        ASSERT(setenv("ZCL_REFLEX_SHOP_REPUTATION_ACCEPTANCE_OUTPUT", "", 1) == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_reputation, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "build/dev-loop/reflex-hotfork-shop-reputation-acceptance.json") != NULL);
        ASSERT(snprintf(path, sizeof path,
                        "%s/build/dev-loop/reflex-hotfork-shop-reputation-acceptance.json",
                        root) > 0);
        ASSERT(rhs_read(path, receipt, sizeof receipt) == 0);
        ASSERT(strstr(receipt, "shop_native_reputation.c") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_rhs_nomut(const char *root)
{
    int failures = 0;
    char err[1024], out[256], owner[PATH_MAX];
    int rc;
    TEST("a missing semantic mutation is refused and the owner stays put") {
        ASSERT(rhs_tree(root) == 0);
        ASSERT(rhs_arm(root, "contexts/market/controllers/src/shop_native_handler.c",
                       k_plain, "shop-status-view-contract.v1",
                       "ZCL_REFLEX_SHOP_STATUS_ACCEPTANCE_OUTPUT") == 0);
        rc = rhs_capture(zcl_reflex_hotfork_shop_status, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "compile-valid semantic mutation was not staged") != NULL);
        ASSERT(snprintf(owner, sizeof owner,
                        "%s/contexts/market/controllers/src/shop_native_handler.c",
                        root) > 0);
        ASSERT(rhs_same(owner, k_plain));
        PASS();
    }
    _test_next:;
    return failures;
}

int test_reflex_hotfork_shop(void);
int test_reflex_hotfork_shop(void)
{
    struct rhs_saved saved;
    char root[PATH_MAX];
    int failures = 0;
    rhs_save(&saved);
    test_make_tmpdir(root, sizeof root, "reflex_hotfork_shop", "root");
    failures += test_rhs_missing(root);
    failures += test_rhs_link(root);
    failures += test_rhs_status(root);
    failures += test_rhs_reputation(root);
    failures += test_rhs_zcode(root);
    failures += test_rhs_nomut(root);
    failures += test_rhs_stop(root);
    failures += test_rhs_empty_output(root);
    rhs_restore_env(&saved);
    unsetenv("RHS_STORY");
    if (failures == 0)
        printf("test_reflex_hotfork_shop: all passed\n");
    else
        printf("test_reflex_hotfork_shop: %d FAILED\n", failures);
    return failures;
}
