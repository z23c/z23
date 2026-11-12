/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_agent_clear_stale_reindex against a private dev lane
 *          whose systemctl, date, timeout, and zclassic-cli are stubs. */

#include "test/test_core.h"

#include "agent_clear_stale_reindex.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *k_acr_dirs[] = {"bin", "build", "build/bin", "data", NULL};
static const char *k_acr_links[] = {
    "bin/systemctl", "bin/date", "bin/timeout", "build/bin/zclassic-cli", NULL};

static int acr_spew(const char *path, const char *body, int exec_bit)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(body, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    if (exec_bit && chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int acr_put(const char *dir, const char *leaf, const char *text)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", dir, leaf) >= (int)sizeof path)
        return -1;
    return acr_spew(path, text, 0);
}

static int acr_read(const char *path, char *buf, size_t cap)
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

static int acr_mkdirs(const char *dir)
{
    char path[PATH_MAX];
    int i;
    for (i = 0; k_acr_dirs[i] != NULL; i++) {
        if (snprintf(path, sizeof path, "%s/%s", dir, k_acr_dirs[i]) >=
            (int)sizeof path)
            return -1;
        if (mkdir(path, 0700) != 0)
            return -1;
    }
    return 0;
}

static int acr_script(const char *dir)
{
    char body[4096];
    char path[PATH_MAX];
    int wrote = snprintf(
        body, sizeof body,
        "#!/bin/sh\n"
        "dir='%s'\n"
        "base=${0##*/}\n"
        "{\n"
        "  printf '%%s' \"$base\"\n"
        "  for a in \"$@\"; do printf ' [%%s]' \"$a\"; done\n"
        "  printf '\\n'\n"
        "} >> \"$dir/log\"\n"
        "emit() {\n"
        "  while IFS= read -r line || [ -n \"${line-}\" ]; do\n"
        "    printf '%%s\\n' \"$line\"\n"
        "  done < \"$1\"\n"
        "}\n"
        "case \"$base\" in\n"
        "  date) printf '%%s\\n' '20260101T000000Z' ;;\n"
        "  timeout)\n"
        "    if [ -f \"$dir/data/fail-timeout\" ]; then exit 9; fi\n"
        "    shift\n"
        "    exec \"$@\" ;;\n"
        "  systemctl)\n"
        "    if [ -f \"$dir/data/active\" ]; then emit \"$dir/data/active\"; fi ;;\n"
        "  zclassic-cli)\n"
        "    dd=\n"
        "    cmd=\n"
        "    for a in \"$@\"; do\n"
        "      case \"$a\" in\n"
        "        -datadir=*) dd=${a#-datadir=} ;;\n"
        "        *) cmd=$a ;;\n"
        "      esac\n"
        "    done\n"
        "    leaf=\n"
        "    if [ \"$cmd\" = getblockcount ]; then leaf=height; fi\n"
        "    if [ \"$cmd\" = agent ]; then leaf=agent; fi\n"
        "    if [ -n \"$leaf\" ] && [ -f \"$dd/$leaf\" ]; then emit \"$dd/$leaf\"; fi ;;\n"
        "esac\n"
        "exit 0\n",
        dir);
    if (wrote < 0 || (size_t)wrote >= sizeof body)
        return -1;
    if (snprintf(path, sizeof path, "%s/record.sh", dir) >= (int)sizeof path)
        return -1;
    return acr_spew(path, body, 1);
}

static int acr_link(const char *dir)
{
    char target[PATH_MAX];
    char dest[PATH_MAX];
    int i;
    if (snprintf(target, sizeof target, "%s/record.sh", dir) >= (int)sizeof target)
        return -1;
    for (i = 0; k_acr_links[i] != NULL; i++) {
        if (snprintf(dest, sizeof dest, "%s/%s", dir, k_acr_links[i]) >=
            (int)sizeof dest)
            return -1;
        if (symlink(target, dest) != 0)
            return -1;
    }
    return 0;
}

static int acr_arm(const char *dir)
{
    if (strchr(dir, '\'') != NULL)
        return -1;
    if (acr_mkdirs(dir) != 0)
        return -1;
    if (acr_script(dir) != 0)
        return -1;
    if (acr_link(dir) != 0)
        return -1;
    if (acr_put(dir, "data/active", "active\n") != 0)
        return -1;
    if (acr_put(dir, "data/height", "150\n") != 0)
        return -1;
    if (acr_put(dir, "data/agent",
                "{\"operator_needed\":false,\"validation_pack_ok\":true,"
                "\"agent_work_ready\":true}\n") != 0)
        return -1;
    return 0;
}

static int acr_capture(const char *repo, const char *dir, int argc, char **argv,
                       char *out, size_t out_cap, char *err, size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int fd_out = -1;
    int fd_err = -1;
    int saved_out = -1;
    int saved_err = -1;
    int rc;
    if (snprintf(out_path, sizeof out_path, "%s/cap.out", dir) >= (int)sizeof out_path)
        return -1;
    if (snprintf(err_path, sizeof err_path, "%s/cap.err", dir) >= (int)sizeof err_path)
        return -1;
    fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd_out < 0 || fd_err < 0)
        goto fail;
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    rc = zcl_agent_clear_stale_reindex(repo, argc, argv);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    if (acr_read(out_path, out, out_cap) != 0 || acr_read(err_path, err, err_cap) != 0)
        return -1;
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

static int acr_bind(const char *dir, int dry, char *old_path, size_t cap)
{
    const char *saved = getenv("PATH");
    char next[PATH_MAX];
    char data[PATH_MAX];
    if (saved == NULL)
        saved = "";
    if (strlen(saved) + 1 > cap)
        return -1;
    memcpy(old_path, saved, strlen(saved) + 1);
    if (snprintf(next, sizeof next, "%s/bin", dir) >= (int)sizeof next)
        return -1;
    if (snprintf(data, sizeof data, "%s/data", dir) >= (int)sizeof data)
        return -1;
    if (setenv("PATH", next, 1) != 0)
        return -1;
    if (setenv("ZCL_AGENT_DEV_DATADIR", data, 1) != 0)
        return -1;
    if (setenv("ZCL_AGENT_DEV_RPCPORT", "18252", 1) != 0)
        return -1;
    if (setenv("ZCL_AGENT_DEV_UNIT", "zcl23-dev.service", 1) != 0)
        return -1;
    if (setenv("ZCL_AGENT_CLEAR_STALE_REINDEX_DRY_RUN", dry ? "1" : "0", 1) != 0)
        return -1;
    if (setenv("ZCL_AGENT_CLEAR_STALE_REINDEX_AGENT_TIMEOUT", "10", 1) != 0)
        return -1;
    return 0;
}

static void acr_unbind(const char *old_path)
{
    if (setenv("PATH", old_path, 1) != 0)
        return;
    unsetenv("ZCL_AGENT_DEV_DATADIR");
    unsetenv("ZCL_AGENT_DEV_RPCPORT");
    unsetenv("ZCL_AGENT_DEV_UNIT");
    unsetenv("ZCL_AGENT_CLEAR_STALE_REINDEX_DRY_RUN");
    unsetenv("ZCL_AGENT_CLEAR_STALE_REINDEX_AGENT_TIMEOUT");
}

static int acr_drive(const char *dir, const char *mode, int dry, char *out,
                     size_t out_cap, char *err, size_t err_cap)
{
    char old[8192];
    char *argv[] = {(char *)mode, NULL};
    int argc = mode == NULL ? 0 : 1;
    int rc;
    if (acr_bind(dir, dry, old, sizeof old) != 0)
        return -1;
    rc = acr_capture(dir, dir, argc, argv, out, out_cap, err, err_cap);
    acr_unbind(old);
    return rc;
}

static int acr_case(const char *root, const char *tag, char *dir, size_t cap)
{
    if (snprintf(dir, cap, "%s/%s", root, tag) >= (int)cap)
        return -1;
    if (mkdir(dir, 0700) != 0)
        return -1;
    if (acr_arm(dir) != 0)
        return -1;
    return 0;
}

static int test_acr_repo(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[64];
    char err[256];
    int rc;
    TEST("a missing repo is refused") {
        ASSERT(acr_case(root, "repo", dir, sizeof dir) == 0);
        rc = acr_capture(NULL, dir, 0, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "agent-clear-stale-reindex: repo is required\n");
        ASSERT_STR_EQ(out, "");
        rc = acr_capture("", dir, 0, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(err, "agent-clear-stale-reindex: repo is required\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_acr_absent(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[1024];
    char err[256];
    int rc;
    TEST("an absent marker is a noop in text and json") {
        ASSERT(acr_case(root, "absent", dir, sizeof dir) == 0);
        rc = acr_drive(dir, NULL, 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, "");
        ASSERT_STR_EQ(out,
                      "[agent-clear-stale-reindex] status=noop reason=marker_absent "
                      "height= anchor= count=\n");
        rc = acr_drive(dir, "--json", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "\"schema\": \"zcl.agent_dev_reindex_clear.v1\"") != NULL);
        ASSERT(strstr(out, "\"status\": \"noop\"") != NULL);
        ASSERT(strstr(out, "\"reason\": \"marker_absent\"") != NULL);
        ASSERT(strstr(out, "\"dry_run\": false\n") != NULL);
        ASSERT(strstr(out, "auto_reindex_request") != NULL);
        rc = acr_drive(dir, "sideways", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT_STR_EQ(out, "");
        ASSERT_STR_EQ(err, "usage: tools/dev/agent-clear-stale-reindex.sh [--json]\n");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_acr_marker(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[512];
    char err[256];
    char path[PATH_MAX];
    int rc;
    TEST("marker shape refuses or noops before the lane is asked") {
        ASSERT(acr_case(root, "marker", dir, sizeof dir) == 0);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "[agent-clear-stale-reindex] status=refused reason=marker_read_failed ") == out);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "abc zz\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "[agent-clear-stale-reindex] status=refused reason=marker_malformed height= anchor=abc count=zz\n") ==
               out);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "100 0\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "[agent-clear-stale-reindex] status=noop reason=marker_not_pending height= anchor=100 count=0\n") ==
               out);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "100 -2\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "reason=marker_not_pending") != NULL);
        ASSERT(strstr(out, "count=-2\n") != NULL);
        ASSERT(snprintf(path, sizeof path, "%s/data/auto_reindex_request", dir) > 0);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "100 2\n") == 0);
        ASSERT(chmod(path, 0) == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "[agent-clear-stale-reindex] status=refused reason=marker_unreadable") == out);
        ASSERT(chmod(path, 0600) == 0);
        memset(path, '1', 300);
        path[300] = '\0';
        ASSERT(acr_put(dir, "data/auto_reindex_request", path) == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=marker_read_failed") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_acr_prove(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[512];
    char err[256];
    int rc;
    TEST("the lane proof refuses a short, idle, or unready dev lane") {
        ASSERT(acr_case(root, "prove", dir, sizeof dir) == 0);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "100 2\n") == 0);
        ASSERT(acr_put(dir, "data/active", "inactive\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=service_not_active height= anchor=100 count=2\n") != NULL);
        ASSERT(acr_put(dir, "data/active", "active\n") == 0);
        ASSERT(acr_put(dir, "data/height", "nope\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=rpc_height_unavailable height=nope anchor=100 count=2\n") !=
               NULL);
        ASSERT(acr_put(dir, "data/height", "40\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=marker_anchor_above_served_height height=40 anchor=100 count=2\n") !=
               NULL);
        ASSERT(acr_put(dir, "data/height", "150\n") == 0);
        ASSERT(acr_put(dir, "data/fail-timeout", "1\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=agent_contract_not_ready height=150 anchor=100 count=2\n") !=
               NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_acr_clear(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char out[2048];
    char err[256];
    char log[4096];
    char path[PATH_MAX];
    char body[64];
    int rc;
    TEST("a proved marker is archived, and a dry run leaves it") {
        ASSERT(acr_case(root, "clear", dir, sizeof dir) == 0);
        ASSERT(acr_put(dir, "data/auto_reindex_request", "100 3\n") == 0);
        ASSERT(acr_put(dir, "data/agent", "{\"operator_needed\":true}\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=agent_contract_not_ready") != NULL);
        ASSERT(acr_put(dir, "data/agent", "{\"validation_pack_ok\":false}\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=agent_contract_not_ready") != NULL);
        ASSERT(acr_put(dir, "data/agent", "{\"agent_work_ready\":false}\n") == 0);
        rc = acr_drive(dir, "text", 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(out, "reason=agent_contract_not_ready") != NULL);
        ASSERT(acr_put(dir, "data/agent", "{\"status\":\"ok\"}\n") == 0);
        rc = acr_drive(dir, "json", 1, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(out, "\"status\": \"would_clear\"") != NULL);
        ASSERT(strstr(out, "\"reason\": \"stale_marker_proven\"") != NULL);
        ASSERT(strstr(out, "\"dry_run\": true\n") != NULL);
        ASSERT(strstr(out, ".cleared-20260101T000000Z") != NULL);
        ASSERT(snprintf(path, sizeof path, "%s/data/auto_reindex_request", dir) > 0);
        ASSERT(acr_read(path, body, sizeof body) == 0);
        ASSERT_STR_EQ(body, "100 3\n");
        rc = acr_drive(dir, NULL, 0, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, "");
        ASSERT(strstr(out, "[agent-clear-stale-reindex] status=cleared reason=stale_marker_proven height=150 anchor=100 count=3\n") ==
               out);
        ASSERT(strstr(out, "archived=") != NULL);
        ASSERT(strstr(out, ".cleared-20260101T000000Z\n") != NULL);
        ASSERT(access(path, F_OK) != 0);
        ASSERT(snprintf(path, sizeof path,
                        "%s/data/auto_reindex_request.cleared-20260101T000000Z", dir) > 0);
        ASSERT(acr_read(path, body, sizeof body) == 0);
        ASSERT_STR_EQ(body, "100 3\n");
        ASSERT(snprintf(path, sizeof path, "%s/log", dir) > 0);
        ASSERT(acr_read(path, log, sizeof log) == 0);
        ASSERT(strstr(log, "systemctl [--user] [show] [zcl23-dev.service] [-p] [ActiveState] [--value]") !=
               NULL);
        ASSERT(snprintf(path, sizeof path, "%s/build/bin/zclassic-cli", dir) > 0);
        ASSERT(strstr(log, "[-rpcport=18252] [getblockcount]") != NULL);
        ASSERT(strstr(log, "[-rpcport=18252] [agent]") != NULL);
        ASSERT(strstr(log, "timeout [10] [") != NULL);
        ASSERT(strstr(log, path) != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_acr_home(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char saved[PATH_MAX];
    char out[128];
    char err[256];
    const char *home = getenv("HOME");
    int had = home != NULL && strlen(home) + 1 < sizeof saved;
    int rc;
    if (had)
        memcpy(saved, home, strlen(home) + 1);
    TEST("an unset HOME is refused when the datadir flag is unset") {
        ASSERT(acr_case(root, "home", dir, sizeof dir) == 0);
        unsetenv("ZCL_AGENT_DEV_DATADIR");
        unsetenv("HOME");
        rc = acr_capture(dir, dir, 0, NULL, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 1);
        ASSERT_STR_EQ(err, "agent-clear-stale-reindex: HOME is unset\n");
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    if (had)
        setenv("HOME", saved, 1);
    return failures;
}

int test_agent_clear_stale_reindex(void);
int test_agent_clear_stale_reindex(void)
{
    char root[PATH_MAX];
    int failures;
    test_make_tmpdir(root, sizeof root, "agent_clear_stale_reindex", "root");
    failures = test_acr_repo(root);
    failures += test_acr_home(root);
    failures += test_acr_absent(root);
    failures += test_acr_marker(root);
    failures += test_acr_prove(root);
    failures += test_acr_clear(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_agent_clear_stale_reindex: all passed\n");
    else
        printf("test_agent_clear_stale_reindex: %d FAILED\n", failures);
    return failures;
}
