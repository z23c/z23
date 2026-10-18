/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-fx, proved without a network: the real built binary (build/bin/z23-fx)
 * runs as a subprocess in --print-argv mode, which resolves the fleet config,
 * selects machines and builds the exact ssh argv without starting ssh. The
 * group covers config parsing, HOST/all/@ROLE selection, the verbatim
 * one-argument command, and every refusal path (exit 2, nothing executed).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test/test_core.h"
#include <stdio.h>

#if !defined(_WIN32)
#include "json/json.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FX_BIN "build/bin/z23-fx"
#define FX_XDG "/run/zcl-fx"

static const char *const GOOD_CONFIG =
    "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"alias-one\",\"roles\":[\"dev\"]},"
    "{\"name\":\"r2\",\"ssh\":\"user@example.invalid\",\"roles\":[\"dev\",\"landing\"]},"
    "{\"name\":\"m1\",\"ssh\":\"alias-mac\"}]}";

static int run_fx(const char *xdg, const char *const args[], char *out, size_t cap)
{
    int p[2];
    if (pipe(p) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char *av[16];
        size_t n = 0;
        dup2(p[1], STDOUT_FILENO);
        dup2(p[1], STDERR_FILENO);
        close(p[0]);
        close(p[1]);
        setenv("XDG_RUNTIME_DIR", xdg, 1);
        av[n++] = (char *)FX_BIN;
        for (size_t i = 0; args[i] && n + 1 < 16; i++) av[n++] = (char *)args[i];
        av[n] = NULL;
        execv(av[0], av);
        _exit(127);
    }
    close(p[1]);
    size_t used = 0;
    ssize_t r;
    while (used + 1 < cap && (r = read(p[0], out + used, cap - 1 - used)) != 0) {
        if (r > 0) used += (size_t)r;
        else if (errno != EINTR) break;
    }
    out[used] = '\0';
    close(p[0]);
    int st = 0;
    return waitpid(pid, &st, 0) == pid && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static bool write_config(const char *dir, const char *name, const char *body, char *path, size_t n)
{
    snprintf(path, n, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(body, f) != EOF;
    if (f) ok = fclose(f) == 0 && ok;
    return ok;
}

static size_t count_lines(const char *s)
{
    size_t n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

static const char *config_flag(char *flag, size_t n, const char *cfg)
{
    snprintf(flag, n, "--config=%s", cfg);
    return flag;
}

static int fx_print(const char *cfg, const char *sel, const char *cmd, char *out, size_t cap)
{
    char flag[PATH_MAX + 16];
    const char *args[] = {config_flag(flag, sizeof flag, cfg), "--print-argv", sel, cmd, NULL};
    return run_fx(FX_XDG, args, out, cap);
}

static int test_fx_argv(const char *dir)
{
    int failures = 0;
    TEST("z23-fx: one verbatim ssh argument, batch mode, per-host control socket") {
        char cfg[PATH_MAX], out[8192];
        const char *cmd = "echo \"a b\"; $HOME `id` | cat";
        ASSERT(write_config(dir, "good.json", GOOD_CONFIG, cfg, sizeof cfg));
        ASSERT_EQ(fx_print(cfg, "r1", cmd, out, sizeof out), 0);
        ASSERT_EQ(count_lines(out), (size_t)1);
        struct json_value o;
        json_init(&o);
        ASSERT(json_read(&o, out, strlen(out)));
        const struct json_value *argv = json_get(&o, "argv");
        ASSERT(argv && argv->type == JSON_ARR);
        size_t n = json_size(argv);
        ASSERT_EQ(n, (size_t)18);
        ASSERT_STR_EQ(json_get_str(json_get(&o, "host")), "r1");
        ASSERT_STR_EQ(json_get_str(json_at(argv, 0)), "ssh");
        ASSERT_STR_EQ(json_get_str(json_at(argv, 2)), "BatchMode=yes");
        ASSERT_STR_EQ(json_get_str(json_at(argv, 4)), "ConnectTimeout=8");
        ASSERT_STR_EQ(json_get_str(json_at(argv, n - 4)), "ControlPath=" FX_XDG "/z23-fx-%C");
        ASSERT_STR_EQ(json_get_str(json_at(argv, n - 3)), "--");
        ASSERT_STR_EQ(json_get_str(json_at(argv, n - 2)), "alias-one");
        ASSERT_STR_EQ(json_get_str(json_at(argv, n - 1)), cmd);
        json_free(&o);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fx_selection(const char *dir)
{
    int failures = 0;
    TEST("z23-fx: HOST, all and @ROLE select in config order") {
        char cfg[PATH_MAX], out[8192];
        ASSERT(write_config(dir, "good.json", GOOD_CONFIG, cfg, sizeof cfg));
        ASSERT_EQ(fx_print(cfg, "all", "true", out, sizeof out), 0);
        ASSERT_EQ(count_lines(out), (size_t)3);
        const char *a = strstr(out, "\"r1\""), *b = strstr(out, "\"r2\""), *c = strstr(out, "\"m1\"");
        ASSERT(a && b && c && a < b && b < c);
        ASSERT_EQ(fx_print(cfg, "@dev", "true", out, sizeof out), 0);
        ASSERT_EQ(count_lines(out), (size_t)2);
        ASSERT(strstr(out, "\"m1\"") == NULL);
        ASSERT_EQ(fx_print(cfg, "@landing", "true", out, sizeof out), 0);
        ASSERT(strstr(out, "user@example.invalid") != NULL);
        ASSERT_EQ(count_lines(out), (size_t)1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fx_refuse_selection(const char *dir)
{
    int failures = 0;
    TEST("z23-fx: unknown machine, unknown role, bad usage and --config without = exit 2") {
        char cfg[PATH_MAX], out[8192];
        ASSERT(write_config(dir, "good.json", GOOD_CONFIG, cfg, sizeof cfg));
        ASSERT_EQ(fx_print(cfg, "r9", "true", out, sizeof out), 2);
        ASSERT(strstr(out, "no machine matches") != NULL);
        ASSERT_EQ(fx_print(cfg, "@none", "true", out, sizeof out), 2);
        ASSERT_EQ(fx_print(cfg, "R1", "true", out, sizeof out), 2);
        ASSERT_EQ(fx_print(cfg, "r1", "", out, sizeof out), 2);
        const char *none[] = {NULL};
        ASSERT_EQ(run_fx(FX_XDG, none, out, sizeof out), 2);
        char flag[PATH_MAX + 16];
        config_flag(flag, sizeof flag, cfg);
        const char *nocmd[] = {flag, "r1", NULL};
        ASSERT_EQ(run_fx(FX_XDG, nocmd, out, sizeof out), 2);
        const char *extra[] = {flag, "r1", "echo", "two", NULL};
        ASSERT_EQ(run_fx(FX_XDG, extra, out, sizeof out), 2);
        const char *split[] = {"--config", cfg, "--print-argv", "r1", "true", NULL};
        ASSERT_EQ(run_fx(FX_XDG, split, out, sizeof out), 2);
        const char *empty[] = {"--config=", "--print-argv", "r1", "true", NULL};
        ASSERT_EQ(run_fx(FX_XDG, empty, out, sizeof out), 2);
        const char *help[] = {"--help", NULL};
        ASSERT_EQ(run_fx(FX_XDG, help, out, sizeof out), 0);
        ASSERT(strstr(out, "usage: z23-fx") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fx_refuse_config(const char *dir)
{
    int failures = 0;
    TEST("z23-fx: missing and invalid configs are refused with a pointer to the example") {
        char cfg[PATH_MAX], missing[PATH_MAX], out[8192];
        snprintf(missing, sizeof missing, "%s/absent.json", dir);
        ASSERT_EQ(fx_print(missing, "all", "true", out, sizeof out), 2);
        ASSERT(strstr(out, "docs/fleet-dev/fleet.example.json") != NULL);
        static const char *const bad[] = {
            "{not json",
            "[]",
            "{\"hosts\":[]}",
            "{\"hosts\":{}}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"a\"},{\"name\":\"r1\",\"ssh\":\"b\"}]}",
            "{\"hosts\":[{\"name\":\"all\",\"ssh\":\"a\"}]}",
            "{\"hosts\":[{\"name\":\"-r\",\"ssh\":\"a\"}]}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"-oProxyCommand=x\"}]}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"a b\"}]}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"a;b\"}]}",
            "{\"hosts\":[{\"name\":\"r1\"}]}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"a\",\"roles\":\"dev\"}]}",
            "{\"hosts\":[{\"name\":\"r1\",\"ssh\":\"a\",\"roles\":[\"d v\"]}]}",
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            ASSERT(write_config(dir, "bad.json", bad[i], cfg, sizeof cfg));
            ASSERT_EQ(fx_print(cfg, "all", "true", out, sizeof out), 2);
            ASSERT(strstr(out, "\"argv\"") == NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_fx_refuse_socket_dir(const char *dir)
{
    int failures = 0;
    TEST("z23-fx: a control directory too long for a unix socket is refused") {
        char cfg[PATH_MAX], out[8192];
        ASSERT(write_config(dir, "good.json", GOOD_CONFIG, cfg, sizeof cfg));
        char flag[PATH_MAX + 16];
        const char *args[] = {config_flag(flag, sizeof flag, cfg), "--print-argv", "r1", "true", NULL};
        const char *longdir = "/run/zcl-fx/012345678901234567890123456789012345678901234567890123456789";
        ASSERT_EQ(run_fx(longdir, args, out, sizeof out), 2);
        ASSERT(strstr(out, "control socket") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_z23_fx(void)
{
#if defined(_WIN32)
    printf("z23_fx: UNAVAILABLE on native Windows (POSIX ssh tool)\n");
    return 1;
#else
    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof dir, "z23_fx", "cfg");
    int failures = test_fx_argv(dir) + test_fx_selection(dir) +
                   test_fx_refuse_selection(dir) + test_fx_refuse_config(dir) +
                   test_fx_refuse_socket_dir(dir);
    test_rm_rf_recursive(dir);
    return failures;
#endif
}
