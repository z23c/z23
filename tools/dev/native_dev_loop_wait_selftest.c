/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive zclassic23-dev loop status and wait in a private home.
 *          Starts no watcher and publishes nothing. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "native_dev_loop_wait_selftest.h"
#include "dev_script_dir.h"

#include "base/hex.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_cycle[] =
    "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"selftest\",\"status\":\"passed\","
    "\"action\":\"check\",\"reason\":\"contract_fixture\",\"phase\":\"verified\","
    "\"runtime_published\":false,\"elapsed_ms\":1,\"files\":[\"fixture.c\"]}";

static int ndw_fail(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    return 1;
}

static void ndw_field(struct sha3_256_ctx *ctx, const char *name, const char *value)
{
    unsigned char zero = 0;
    sha3_256_write(ctx, (const unsigned char *)name, strlen(name));
    sha3_256_write(ctx, &zero, 1);
    sha3_256_write(ctx, (const unsigned char *)value, strlen(value));
    sha3_256_write(ctx, &zero, 1);
}

static void ndw_hex(struct sha3_256_ctx *ctx, char out[65])
{
    unsigned char raw[32];
    sha3_256_finalize(ctx, raw);
    zcl_hex_encode(raw, sizeof raw, out);
}

static int ndw_workspace(const char *root, char id[65], char *canon, size_t cap)
{
    struct sha3_256_ctx ctx;
    if (realpath(root, canon) == NULL)
        return -1;
    if (strlen(canon) >= cap)
        return -1;
    sha3_256_init(&ctx);
    ndw_field(&ctx, "domain", "zcl.dev_workspace.v1");
    ndw_field(&ctx, "canonical_root", canon);
    ndw_hex(&ctx, id);
    return 0;
}

static void ndw_cycle_digest(const char *workspace, char out[65])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    ndw_field(&ctx, "domain", "zcl.dev_cycle_record.v1");
    ndw_field(&ctx, "workspace_id", workspace);
    ndw_field(&ctx, "epoch", "1");
    ndw_field(&ctx, "cycle_json", k_cycle);
    ndw_hex(&ctx, out);
}

static int ndw_mkdir(const char *path)
{
    char copy[PATH_MAX];
    char *p;
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof copy)
        return -1;
    memcpy(copy, path, n + 1);
    for (p = copy + 1; *p != '\0'; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(copy, 0700) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(copy, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static void ndw_wipe(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    if (dir == NULL) {
        (void)unlink(path);
        return;
    }
    while ((ent = readdir(dir)) != NULL) {
        char child[PATH_MAX];
        int n;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        n = snprintf(child, sizeof child, "%s/%s", path, ent->d_name);
        if (n > 0 && (size_t)n < sizeof child)
            ndw_wipe(child);
    }
    closedir(dir);
    (void)rmdir(path);
}

static int ndw_sandbox(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    int n;
    if (tmp != NULL && tmp[0] != '\0')
        n = snprintf(out, cap, "%s/zcl-native-loop-wait.XXXXXX", tmp);
    else
        n = snprintf(out, cap, "/tmp/zcl-native-loop-wait.XXXXXX");
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return mkdtemp(out) == NULL ? -1 : 0;
}

static int ndw_slurp(int fd, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    while (n + 1 < cap) {
        ssize_t got = read(fd, out + n, cap - 1 - n);
        if (got == 0) {
            out[n] = '\0';
            return 0;
        }
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
        n += (size_t)got;
    }
    return -1;
}

static int ndw_reap(pid_t pid)
{
    int status = 0;
    pid_t got = waitpid(pid, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(pid, &status, 0);
    if (got != pid)
        return -1;
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static void ndw_child(int wr, int merge, const char *home, const char *xdg,
                      const char *source, char *const argv[])
{
    if (dup2(wr, STDOUT_FILENO) < 0)
        _exit(127);
    if (merge != 0 && dup2(wr, STDERR_FILENO) < 0)
        _exit(127);
    if (wr > STDERR_FILENO)
        close(wr);
    if (setenv("HOME", home, 1) != 0)
        _exit(127);
    if (setenv("ZCL_DEV_SOURCE_ROOT", source, 1) != 0)
        _exit(127);
    if (xdg != NULL && setenv("XDG_STATE_HOME", xdg, 1) != 0)
        _exit(127);
    execvp(argv[0], argv);
    _exit(127);
}

static int ndw_exec(char *const argv[], const char *home, const char *xdg,
                    const char *source, int merge, char *out, size_t cap, int *rc)
{
    int fds[2];
    pid_t pid;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        ndw_child(fds[1], merge, home, xdg, source, argv);
        _exit(127);
    }
    close(fds[1]);
    if (ndw_slurp(fds[0], out, cap) != 0) {
        close(fds[0]);
        (void)ndw_reap(pid);
        return -1;
    }
    close(fds[0]);
    *rc = ndw_reap(pid);
    return *rc < 0 ? -1 : 0;
}

static int ndw_join(char *dst, size_t cap, const char *dir, const char *name)
{
    size_t dir_n = strlen(dir);
    size_t name_n = strlen(name);
    if (dir_n + name_n + 1 >= cap)
        return -1;
    memcpy(dst, dir, dir_n);
    dst[dir_n] = '/';
    memcpy(dst + dir_n + 1, name, name_n + 1);
    return 0;
}

static int ndw_status_dirs(const char *sandbox, char *repo, char *xdg,
                           char *work, char *legacy)
{
    char parent[PATH_MAX];
    if (ndw_join(repo, PATH_MAX, sandbox, "status-repo") != 0)
        return -1;
    if (ndw_join(xdg, PATH_MAX, sandbox, "xdg-state") != 0)
        return -1;
    if (ndw_join(work, PATH_MAX, repo, ".cache/zcl-dev-watch.lock") != 0)
        return -1;
    if (ndw_join(legacy, PATH_MAX, sandbox,
                 ".local/state/zclassic23-dev/native-watch.lock") != 0)
        return -1;
    if (ndw_mkdir(repo) != 0 || ndw_mkdir(xdg) != 0)
        return -1;
    if (ndw_join(parent, sizeof parent, repo, ".cache") != 0 || ndw_mkdir(parent) != 0)
        return -1;
    if (ndw_join(parent, sizeof parent, sandbox, ".local/state/zclassic23-dev") != 0)
        return -1;
    return ndw_mkdir(parent);
}

static int ndw_status(const char *bin, const char *sandbox)
{
    char repo[PATH_MAX];
    char xdg[PATH_MAX];
    char work[PATH_MAX];
    char legacy[PATH_MAX];
    char out[8192];
    char *argv[6];
    int rc = 1;
    if (ndw_status_dirs(sandbox, repo, xdg, work, legacy) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: inactive status failed");
    argv[0] = (char *)bin;
    argv[1] = "dev";
    argv[2] = "loop";
    argv[3] = "status";
    argv[4] = "--view=summary";
    argv[5] = NULL;
    if (ndw_exec(argv, sandbox, xdg, repo, 1, out, sizeof out, &rc) != 0 ||
        rc != 0 || strstr(out, "\"active\":false") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: inactive status failed");
    if (access(work, F_OK) == 0 || access(legacy, F_OK) == 0)
        return ndw_fail("native-dev-loop-wait-selftest: status created a watcher lock");
    return 0;
}

static int ndw_seal(const char *root, const char *sandbox, char *canon, size_t cap)
{
    char id[65];
    char digest[65];
    char state[PATH_MAX];
    char path[PATH_MAX];
    FILE *file;
    int fd;
    if (ndw_workspace(root, id, canon, cap) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    ndw_cycle_digest(id, digest);
    if (snprintf(state, sizeof state,
                 "%s/.local/state/zclassic23-dev/workspaces/%s", sandbox, id) >=
        (int)sizeof state)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    if (ndw_mkdir(state) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    if (snprintf(path, sizeof path, "%s/cycle-state.lock", state) >= (int)sizeof path)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    close(fd);
    if (snprintf(path, sizeof path, "%s/native-cycle.json", state) >= (int)sizeof path)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    file = fopen(path, "w");
    if (file == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    if (fprintf(file,
                "{\"schema\":\"zcl.dev_cycle_record.v1\",\"workspace_id\":\"%s\","
                "\"epoch\":1,\"cycle\":%s,\"cycle_sha3\":\"%s\"}\n",
                id, k_cycle, digest) < 0) {
        fclose(file);
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    }
    if (fclose(file) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    return 0;
}

static int ndw_epoch(const char *text, char *out, size_t cap)
{
    const char *p = text;
    const char *last = NULL;
    size_t n = 0;
    while ((p = strstr(p, "\"epoch\":")) != NULL) {
        const char *digit = p + 8;
        if (digit[0] >= '0' && digit[0] <= '9')
            last = digit;
        p += 8;
    }
    if (last == NULL)
        return -1;
    while (last[n] >= '0' && last[n] <= '9')
        n++;
    if (n == 0 || n >= cap)
        return -1;
    memcpy(out, last, n);
    out[n] = '\0';
    return 0;
}

static int ndw_wait_ok(const char *out)
{
    if (strstr(out, "\"data_schema\":\"zcl.dev_cycle.v1\"") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: declared data schema drifted");
    if (strstr(out, "\"data\":{\"schema\":\"zcl.dev_cycle.v1\"") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: verdict is not the direct data object");
    if (strstr(out, "\"reason\":\"contract_fixture\"") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    if (strstr(out, "\"epoch\":") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: chaining epoch is missing");
    if (strstr(out, "\"latest_verdict\"") != NULL ||
        strstr(out, "zcl.dev_loop_status.v1") != NULL)
        return ndw_fail("native-dev-loop-wait-selftest: wait leaked the loop-status wrapper");
    if (strstr(out, "\"runtime_published\":false") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: fixture lost publication containment");
    return 0;
}

static int ndw_timeout_ok(const char *out, int rc, const char *epoch)
{
    char needle[80];
    if (rc != 3 || strstr(out, "\"code\":\"WAIT_TIMEOUT\"") == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: returned epoch did not chain to a bounded wait");
    if (snprintf(needle, sizeof needle, "current_epoch=%s", epoch) >= (int)sizeof needle)
        return ndw_fail("native-dev-loop-wait-selftest: timeout recovery lost the current epoch");
    if (strstr(out, needle) == NULL)
        return ndw_fail("native-dev-loop-wait-selftest: timeout recovery lost the current epoch");
    if (strstr(out, "\"next\":[{\"command\":\"dev.loop.status\"") == NULL ||
        strstr(out, "\"next\":[{\"command\":\"dev.loop.wait\"") != NULL)
        return ndw_fail("native-dev-loop-wait-selftest: timeout emitted an invalid self-loop");
    return 0;
}

static int ndw_rounds(const char *bin, const char *canon, const char *sandbox)
{
    char out[65536];
    char epoch[32];
    char input[128];
    char *waitv[7];
    char *again[6];
    int rc = 1;
    waitv[0] = (char *)bin;
    waitv[1] = "dev";
    waitv[2] = "loop";
    waitv[3] = "wait";
    waitv[4] = "--input={\"after_epoch\":0,\"timeout_ms\":100}";
    waitv[5] = "--view=summary";
    waitv[6] = NULL;
    if (ndw_exec(waitv, sandbox, NULL, canon, 0, out, sizeof out, &rc) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: durable verdict was not returned");
    if (ndw_wait_ok(out) != 0)
        return 1;
    if (ndw_epoch(out, epoch, sizeof epoch) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: chaining epoch is not an integer");
    if (snprintf(input, sizeof input,
                 "--input={\"after_epoch\":%s,\"timeout_ms\":25}", epoch) >=
        (int)sizeof input)
        return ndw_fail("native-dev-loop-wait-selftest: chaining epoch is not an integer");
    again[0] = (char *)bin;
    again[1] = "dev";
    again[2] = "loop";
    again[3] = "wait";
    again[4] = input;
    again[5] = NULL;
    if (ndw_exec(again, sandbox, NULL, canon, 1, out, sizeof out, &rc) != 0)
        return ndw_fail("native-dev-loop-wait-selftest: returned epoch did not chain to a bounded wait");
    return ndw_timeout_ok(out, rc, epoch);
}

static int ndw_body(const char *bin, const char *root)
{
    char sandbox[PATH_MAX];
    char canon[PATH_MAX];
    mode_t saved = umask(077);
    int rc;
    if (ndw_sandbox(sandbox, sizeof sandbox) != 0) {
        umask(saved);
        return ndw_fail("native-dev-loop-wait-selftest: inactive status failed");
    }
    rc = ndw_status(bin, sandbox);
    if (rc == 0)
        rc = ndw_seal(root, sandbox, canon, sizeof canon);
    if (rc == 0)
        rc = ndw_rounds(bin, canon, sandbox);
    ndw_wipe(sandbox);
    umask(saved);
    if (rc == 0)
        printf("native-dev-loop-wait-selftest: PASS\n");
    return rc;
}

static const char *ndw_bin(const char *bin, const char *root, char *owned, size_t cap)
{
    const char *env;
    int n;
    if (bin != NULL && bin[0] != '\0')
        return bin;
    env = getenv("ZCL_DEV_LOOP_TEST_BIN");
    if (env != NULL && env[0] != '\0')
        return env;
    n = snprintf(owned, cap, "%s/build/bin/zclassic23-dev", root);
    if (n < 0 || (size_t)n >= cap)
        return NULL;
    return owned;
}
#endif

int zcl_native_dev_loop_wait_selftest(const char *bin, const char *root)
{
#if defined(_WIN32)
    (void)bin;
    (void)root;
    fprintf(stderr, "native-dev-loop-wait-selftest: missing dev binary: unavailable\n");
    return 2;
#else
    char checkout[PATH_MAX];
    char owned[PATH_MAX];
    const char *use_root = root;
    const char *use_bin;
    if (use_root == NULL || use_root[0] == '\0') {
        if (zcl_dev_checkout_root(checkout, sizeof checkout) != 0)
            return ndw_fail("native-dev-loop-wait-selftest: missing dev binary: checkout");
        use_root = checkout;
    }
    use_bin = ndw_bin(bin, use_root, owned, sizeof owned);
    if (use_bin == NULL || access(use_bin, X_OK) != 0) {
        fprintf(stderr, "native-dev-loop-wait-selftest: missing dev binary: %s\n",
                use_bin != NULL ? use_bin : "");
        return 2;
    }
    return ndw_body(use_bin, use_root);
#endif
}
