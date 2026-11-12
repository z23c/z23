/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zcl_watcher_session_stop against the real holder fixture
 *          and a stand-in dev binary. */

#include "test/test_core.h"

#include "watcher_session_stop.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int wss_spew(const char *path, const char *body)
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
    if (chmod(path, 0755) != 0)
        return -1;
    return 0;
}

static int wss_good_stub(const char *dir)
{
    char path[PATH_MAX];
    char body[4096];
    int n;
    if (snprintf(path, sizeof path, "%s/dev-stub", dir) >= (int)sizeof path)
        return -1;
    n = snprintf(
        body, sizeof body,
        "#!/bin/sh\n"
        "log='%s/log'\n"
        "printf '%%s\\n' \"$*\" >> \"$log\"\n"
        "if [ -n \"${ZCL_DEVLOOP_TEST_WATCH_STALL:-}\" ]; then\n"
        "  printf '%%s\\n' '2147483646 2147483646' > \"$ZCL_DEVLOOP_TEST_WATCH_STALL\"\n"
        "  printf '%%s\\n' '{\"code\":\"WATCH_START_FAILED\",\"evidence\":\"/var/not/native-watch.log\"}'\n"
        "  exit 0\n"
        "fi\n"
        "ready=\"${ZCL_DEV_SOURCE_ROOT}/holder.ready\"\n"
        "pid= worker= born= session=\n"
        "if [ -f \"$ready\" ]; then\n"
        "  read -r pid worker born session < \"$ready\"\n"
        "fi\n"
        "case \"$2\" in\n"
        "  begin)\n"
        "    printf '%%s\\n' '{\"status\":\"WATCHER_RETIRING\"}'\n"
        "    ;;\n"
        "  loop)\n"
        "    if [ \"$3\" = status ]; then\n"
        "      printf '{\"pid\":%%s,\"born\":%%s}\\n' \"$pid\" \"$born\"\n"
        "      exit 0\n"
        "    fi\n"
        "    input=$4\n"
        "    case \"$input\" in\n"
        "      *'\"watcher_session\":'*)\n"
        "        kill -KILL \"$pid\" \"$worker\" 2>/dev/null || true\n"
        "        printf '%%s\\n' '{\"stopped\":true,\"session_retired\":\"retired\"}'\n"
        "        ;;\n"
        "      *)\n"
        "        want=$(printf '%%s\\n' \"$input\" | sed -n 's/.*\"watcher_born\":\\([0-9][0-9]*\\).*/\\1/p')\n"
        "        if [ \"$want\" = \"$born\" ]; then\n"
        "          kill -KILL \"$worker\" 2>/dev/null || true\n"
        "          printf '%%s\\n' '{\"session_retired\":\"retired\"}'\n"
        "        else\n"
        "          printf '%%s\\n' '{\"error\":\"WATCHER_ID_MISMATCH\"}'\n"
        "        fi\n"
        "        ;;\n"
        "    esac\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        dir);
    if (n < 0 || (size_t)n >= sizeof body)
        return -1;
    return wss_spew(path, body);
}

static int wss_bad_stub(const char *dir)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/dev-stub", dir) >= (int)sizeof path)
        return -1;
    return wss_spew(path, "#!/bin/sh\nprintf '%s\\n' '{}'\nexit 0\n");
}

static int wss_capture(const char *repo, const char *bin, const char *fixture,
                       const char *dir, char *out, size_t out_cap, char *err,
                       size_t err_cap)
{
    char out_path[PATH_MAX];
    char err_path[PATH_MAX];
    int fd_out = -1;
    int fd_err = -1;
    int saved_out = -1;
    int saved_err = -1;
    int rc;
    FILE *fp;
    size_t n;
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
    rc = zcl_watcher_session_stop(repo, bin, fixture);
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

static int wss_fixture(char *out, size_t cap)
{
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof cwd) == NULL)
        return -1;
    if (snprintf(out, cap, "%s/tools/dev/fixtures/watcher_session_holder.c", cwd) >=
        (int)cap)
        return -1;
    if (access(out, R_OK) != 0)
        return -1;
    return 0;
}

static int test_wss_missing(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bin[PATH_MAX];
    char fix[PATH_MAX];
    char out[256];
    char err[512];
    int rc;
    TEST("a missing dev binary is refused") {
        ASSERT(snprintf(dir, sizeof dir, "%s/missing", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/no-such-dev", dir) > 0);
        ASSERT(wss_fixture(fix, sizeof fix) == 0);
        rc = wss_capture(root, bin, fix, dir, out, sizeof out, err, sizeof err);
        ASSERT_EQ(rc, 2);
        ASSERT(strstr(err, "missing dev binary:") == err);
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_wss_pass(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bin[PATH_MAX];
    char fix[PATH_MAX];
    char log_path[PATH_MAX];
    char log[4096];
    char out[512];
    char err[1024];
    FILE *fp;
    size_t n;
    int rc;
    TEST("the stand-in dev binary is driven through begin, birth, and stop") {
        ASSERT(snprintf(dir, sizeof dir, "%s/pass", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(wss_good_stub(dir) == 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/dev-stub", dir) > 0);
        ASSERT(wss_fixture(fix, sizeof fix) == 0);
        rc = wss_capture(root, bin, fix, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s out=%s", rc, err, out);
        ASSERT_EQ(rc, 0);
        ASSERT_STR_EQ(err, "");
        ASSERT_STR_EQ(out,
                      "watcher session stop: begin refuses beside an orphan; "
                      "orphan retired only by its birth; bound stop leaves no process; "
                      "failed begin leaves no watcher\n");
        ASSERT(snprintf(log_path, sizeof log_path, "%s/log", dir) > 0);
        fp = fopen(log_path, "r");
        ASSERT(fp != NULL);
        n = fread(log, 1, sizeof log - 1, fp);
        fclose(fp);
        log[n] = '\0';
        ASSERT(strstr(log, "dev begin --input=") != NULL);
        ASSERT(strstr(log, "dev loop status") != NULL);
        ASSERT(strstr(log, "dev loop stop --input=") != NULL);
        ASSERT(strstr(log, "\"watcher_session\":") != NULL);
        ASSERT(strstr(log, "\"watcher_born\":") != NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_wss_refuse(const char *root)
{
    int failures = 0;
    char dir[PATH_MAX];
    char bin[PATH_MAX];
    char fix[PATH_MAX];
    char out[256];
    char err[1024];
    int rc;
    TEST("begin without WATCHER_RETIRING fails closed") {
        ASSERT(snprintf(dir, sizeof dir, "%s/refuse", root) > 0);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(wss_bad_stub(dir) == 0);
        ASSERT(snprintf(bin, sizeof bin, "%s/dev-stub", dir) > 0);
        ASSERT(wss_fixture(fix, sizeof fix) == 0);
        rc = wss_capture(root, bin, fix, dir, out, sizeof out, err, sizeof err);
        test_note("rc=%d err=%s", rc, err);
        ASSERT_EQ(rc, 1);
        ASSERT(strstr(err, "watcher session selftest: begin beside an orphan:") == err);
        ASSERT_STR_EQ(out, "");
        PASS();
    }
    _test_next:;
    return failures;
}

int test_watcher_session_stop(void);
int test_watcher_session_stop(void)
{
    char root[PATH_MAX];
    int failures;
    test_make_tmpdir(root, sizeof root, "watcher_session_stop", "root");
    failures = test_wss_missing(root);
    failures += test_wss_pass(root);
    failures += test_wss_refuse(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_watcher_session_stop: all passed\n");
    else
        printf("test_watcher_session_stop: %d FAILED\n", failures);
    return failures;
}
