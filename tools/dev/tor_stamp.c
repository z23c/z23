/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read `node -version` for tor: full|stub, refuse a stub with the
 *          shared sentence, and write <node>.tor-stamp plus the SHA-256. */

#include "tor_stamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* THE sentence. Do not reword it: runbooks, gates, and grep look for it. */
static const char k_ts_refusal[] =
    "refusing to package a tor=stub binary: it cannot reach the onion network; rebuild with make tor-full";

static const char *ts_refusal(void)
{
    const char *env = getenv("ZCL_TOR_STUB_REFUSAL");
    if (env != NULL && env[0] != '\0')
        return env;
    return k_ts_refusal;
}

static void ts_say(const char *context, const char *tail)
{
    fprintf(stderr, "%s (%s %s)\n", ts_refusal(), context, tail);
}

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int ts_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static int ts_child(char *const argv[], const char *in_path, int outfd)
{
    int err;
    if (in_path != NULL) {
        int in = open(in_path, O_RDONLY);
        if (in < 0 || dup2(in, STDIN_FILENO) < 0)
            _exit(127);
        close(in);
    }
    if (dup2(outfd, STDOUT_FILENO) < 0)
        _exit(127);
    err = open("/dev/null", O_WRONLY);
    if (err >= 0) {
        if (dup2(err, STDERR_FILENO) < 0)
            _exit(127);
        close(err);
    }
    execvp(argv[0], argv);
    _exit(127);
}

static int ts_capture(char *const argv[], const char *in_path, char *out,
                      size_t cap)
{
    int fds[2];
    pid_t pid;
    size_t used = 0;
    char chunk[1024];
    ssize_t n;
    int status = 0;
    if (out == NULL || cap < 2)
        return -1;
    out[0] = '\0';
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
        ts_child(argv, in_path, fds[1]);
        _exit(127);
    }
    close(fds[1]);
    while ((n = read(fds[0], chunk, sizeof chunk)) > 0) {
        size_t take = (size_t)n;
        if (used + 1 >= cap)
            continue;
        if (used + take >= cap)
            take = cap - 1 - used;
        memcpy(out + used, chunk, take);
        used += take;
        out[used] = '\0';
    }
    close(fds[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    return 0;
}

static int ts_executable(const char *node)
{
    struct stat st;
    if (node == NULL || node[0] == '\0')
        return 0;
    if (stat(node, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return access(node, X_OK) == 0;
}

static int ts_pick(const char *text, char *out, size_t cap)
{
    const char *p = text;
    if (text == NULL || cap < 5)
        return -1;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t n = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (n == 9 && memcmp(p, "tor: full", 9) == 0) {
            memcpy(out, "full", 5);
            return 0;
        }
        if (n == 9 && memcmp(p, "tor: stub", 9) == 0) {
            memcpy(out, "stub", 5);
            return 0;
        }
        if (nl == NULL)
            break;
        p = nl + 1;
    }
    return -1;
}

static int ts_stamp(const char *node, char *out, size_t cap)
{
    char *argv[3];
    char text[4096];
    if (!ts_executable(node))
        return -1;
    argv[0] = (char *)node;
    argv[1] = "-version";
    argv[2] = NULL;
    if (ts_capture(argv, NULL, text, sizeof text) != 0)
        return -1;
    return ts_pick(text, out, cap);
}

static int ts_require(const char *node, const char *context)
{
    char stamp[8];
    const char *who = context;
    int got;
    if (who == NULL || who[0] == '\0')
        who = node != NULL ? node : "";
    got = ts_stamp(node, stamp, sizeof stamp);
    if (got == 0 && strcmp(stamp, "full") == 0)
        return 0;
    if (got == 0 && strcmp(stamp, "stub") == 0) {
        ts_say(who, "reports tor: stub");
        return 1;
    }
    ts_say(who, "printed no tor: stamp, so nothing proves it links real Tor");
    return 1;
}

static int ts_hex64(const char *s)
{
    static const char digits[] = "0123456789abcdef";
    int i;
    if (s == NULL || strlen(s) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        if (strchr(digits, s[i]) == NULL)
            return 0;
    }
    return s[64] == '\0';
}

static int ts_digest(const char *node, char *hex, size_t cap)
{
    char *argv[2];
    char text[256];
    size_t i = 0;
    argv[0] = "sha256sum";
    argv[1] = NULL;
    if (cap < 65)
        return -1;
    if (ts_capture(argv, node, text, sizeof text) != 0)
        return -1;
    while (text[i] != '\0' && text[i] != ' ' && text[i] != '\n' && i < 64) {
        hex[i] = text[i];
        i++;
    }
    hex[i] = '\0';
    return ts_hex64(hex) ? 0 : -1;
}

static int ts_sidecar(const char *node)
{
    char stamp[8];
    char hex[65];
    char path[4096];
    char body[160];
    FILE *fp;
    int n;
    size_t len;
    size_t wrote;
    if (ts_stamp(node, stamp, sizeof stamp) != 0)
        return -1;
    if (ts_digest(node, hex, sizeof hex) != 0)
        return -1;
    n = snprintf(path, sizeof path, "%s.tor-stamp", node);
    if (!ts_fit(n, sizeof path))
        return -1;
    n = snprintf(body, sizeof body, "tor: %s\nbinary_sha256: %s\n", stamp, hex);
    if (!ts_fit(n, sizeof body))
        return -1;
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    len = strlen(body);
    wrote = fwrite(body, 1, len, fp);
    if (fclose(fp) != 0 || wrote != len)
        return -1;
    return 0;
}

#endif /* !_WIN32 */

int zcl_tor_stamp(const char *node, char *out, size_t cap)
{
#if defined(_WIN32)
    (void)node;
    (void)out;
    (void)cap;
    return -1;
#else
    return ts_stamp(node, out, cap);
#endif
}

int zcl_tor_require_full(const char *node, const char *context)
{
#if defined(_WIN32)
    (void)node;
    const char *who = (context != NULL && context[0] != '\0') ? context
                       : (node != NULL ? node : "");
    ts_say(who, "printed no tor: stamp, so nothing proves it links real Tor");
    return 1;
#else
    return ts_require(node, context);
#endif
}

int zcl_tor_write_stamp_sidecar(const char *node)
{
#if defined(_WIN32)
    (void)node;
    return -1;
#else
    return ts_sidecar(node);
#endif
}
