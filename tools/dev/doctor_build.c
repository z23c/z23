/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report which build accelerators this host has, and the
 *          per-iteration cost of each missing one. Read-only. */

#include "doctor_build.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct doc_rep {
    int fd;
    int ok;
    int missing;
};

static void doc_write(int fd, const char *text)
{
    size_t n = strlen(text);
    while (n > 0) {
        ssize_t w = write(fd, text, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        text += w;
        n -= (size_t)w;
    }
}

static void doc_found(struct doc_rep *r, const char *label, const char *where,
                      const char *why)
{
    char line[2048];
    int n = snprintf(line, sizeof line, "  [ok]      %-12s %s — %s\n", label,
                     where, why);
    if (n > 0)
        doc_write(r->fd, line);
    r->ok++;
}

static void doc_absent(struct doc_rep *r, const char *label, const char *lost,
                       const char *cost)
{
    char line[2048];
    int n = snprintf(line, sizeof line, "  [MISSING] %-12s %s\n", label, lost);
    if (n > 0)
        doc_write(r->fd, line);
    n = snprintf(line, sizeof line, "            cost: %s\n", cost);
    if (n > 0)
        doc_write(r->fd, line);
    r->missing++;
}

static int doc_which(const char *name, char *out, size_t cap)
{
    const char *path = getenv("PATH");
    const char *cursor;
    if (!name || !name[0])
        return -1;
    if (!path)
        path = "/usr/bin:/bin";
    cursor = path;
    while (*cursor) {
        const char *colon = strchr(cursor, ':');
        size_t dirlen = colon ? (size_t)(colon - cursor) : strlen(cursor);
        char full[PATH_MAX];
        const char *dir = cursor;
        int nw;
        if (dirlen == 0) {
            dir = ".";
            dirlen = 1;
        }
        nw = snprintf(full, sizeof full, "%.*s/%s", (int)dirlen, dir, name);
        if (nw > 0 && nw < (int)sizeof full && access(full, X_OK) == 0) {
            struct stat st;
            if (stat(full, &st) == 0 && !S_ISDIR(st.st_mode)) {
                if (strlen(full) >= cap)
                    return -1;
                memcpy(out, full, strlen(full) + 1);
                return 0;
            }
        }
        if (!colon)
            break;
        cursor = colon + 1;
    }
    return -1;
}

#if !defined(_WIN32)
static void doc_version_child(const char *bin, int pipefd[2])
{
    int sink = open("/dev/null", O_WRONLY);
    if (dup2(pipefd[1], STDOUT_FILENO) < 0)
        _exit(127);
    if (sink >= 0) {
        (void)dup2(sink, STDERR_FILENO);
        (void)close(sink);
    }
    (void)close(pipefd[0]);
    (void)close(pipefd[1]);
    execl(bin, bin, "--version", (char *)NULL);
    _exit(127);
}
#endif

#if !defined(_WIN32)
static void doc_take_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    if (cap == 0)
        return;
    while (n + 1 < cap) {
        char byte;
        ssize_t got = read(fd, &byte, 1);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (got == 0 || byte == '\n')
            break;
        out[n++] = byte;
    }
    out[n] = '\0';
}
#endif

#if !defined(_WIN32)
static void doc_reap(pid_t pid)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return;
    }
}
#endif

#if !defined(_WIN32)
static void doc_version(const char *bin, char *out, size_t cap)
{
    int pipefd[2];
    pid_t pid;
    out[0] = '\0';
    if (pipe(pipefd) != 0)
        return;
    pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return;
    }
    if (pid == 0)
        doc_version_child(bin, pipefd);
    (void)close(pipefd[1]);
    doc_take_line(pipefd[0], out, cap);
    (void)close(pipefd[0]);
    doc_reap(pid);
}
#else
/* No POSIX child probe on Windows: the probe result stays empty and the
 * report shows the same unknown marker a failed pipe produces. */
static void doc_version(const char *bin, char *out, size_t cap)
{
    (void)bin;
    (void)cap;
    out[0] = '\0';
}
#endif

static void doc_header(struct doc_rep *r)
{
#if !defined(_WIN32)
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
#else
    long cpus = -1; /* no sysconf counter on this platform; report shows "?" */
#endif
    char line[256];
    char num[32];
    const char *shown = "?";
    doc_write(r->fd, "doctor-build: accelerator health for the Z23 inner loop\n");
    if (cpus > 0) {
        (void)snprintf(num, sizeof num, "%ld", cpus);
        shown = num;
    }
    (void)snprintf(line, sizeof line,
                   "  host: %s online CPUs — width for `make -j` build-only / "
                   "test-fast per-TU compiles\n",
                   shown);
    doc_write(r->fd, line);
    doc_write(r->fd, "\n");
}

static const char *doc_cache_why(void)
{
    return "per-TU compile cache around CC (ZCL_USE_CCACHE) — repeat "
           "build-only/test-fast compiles hit the cache instead of rerunning "
           "the front-end";
}

static void doc_cache(struct doc_rep *r)
{
    char path[PATH_MAX];
    char ver[256];
    char where[PATH_MAX + 280];
    if (doc_which("ccache", path, sizeof path) == 0) {
        doc_version(path, ver, sizeof ver);
        (void)snprintf(where, sizeof where, "%s (%s)", path, ver);
        doc_found(r, "ccache", where, doc_cache_why());
        return;
    }
    if (doc_which("sccache", path, sizeof path) == 0) {
        doc_found(r, "sccache", path, doc_cache_why());
        return;
    }
    doc_absent(r, "ccache/sccache",
               "no per-TU compile cache (ZCL_USE_CCACHE=0 leaves CC unwrapped)",
               "every build-only/test-fast/dev-bin epoch reruns the full C "
               "front-end for every recompiled TU (~0.5-2 s per TU x hundreds "
               "on a header edit) instead of ~50-200 ms cache hits");
}

static void doc_linker(struct doc_rep *r)
{
    char path[PATH_MAX];
    char ver[256];
    char where[PATH_MAX + 280];
    if (doc_which("mold", path, sizeof path) == 0) {
        doc_version(path, ver, sizeof ver);
        (void)snprintf(where, sizeof where, "%s (%s)", path, ver);
        doc_found(r, "mold", where,
                  "fast link of the non-LTO dev binary "
                  "(ZCL_DEV_LINKER=-fuse-ld=mold)");
        return;
    }
    if (doc_which("ld.lld", path, sizeof path) == 0) {
        doc_found(r, "ld.lld", path,
                  "faster link of the non-LTO dev binary "
                  "(ZCL_DEV_LINKER=-fuse-ld=lld)");
        return;
    }
    if (doc_which("ld.gold", path, sizeof path) == 0) {
        doc_found(r, "ld.gold", path,
                  "faster link of the non-LTO dev binary "
                  "(ZCL_DEV_LINKER=-fuse-ld=gold)");
        return;
    }
    doc_absent(r, "mold/lld/gold",
               "dev-bin non-LTO link falls back to GNU ld (ZCL_DEV_LINKER "
               "finds none)",
               "the hot dev-reload/dev-bin link over ~1000 objects misses the "
               "fastest installed linker on every edit-link cycle");
}

static void doc_clang(struct doc_rep *r)
{
    char path[PATH_MAX];
    char ver[256];
    char where[PATH_MAX + 280];
    if (doc_which("clang", path, sizeof path) == 0) {
        doc_version(path, ver, sizeof ver);
        (void)snprintf(where, sizeof where, "%s (%s)", path, ver);
        doc_found(r, "clang", where, "libFuzzer+ASan/UBSan fuzz targets (FUZZ_CC)");
        return;
    }
    doc_absent(r, "clang", "fuzz/fuzz-ci targets cannot build (FUZZ_CC)",
               "`make ci` must run with SKIP_FUZZ=1; the fuzz corpus and "
               "sanitizer coverage never execute on this host");
}

static void doc_inotify(struct doc_rep *r)
{
    char path[PATH_MAX];
    if (doc_which("inotifywait", path, sizeof path) == 0) {
        doc_found(r, "inotifywait", path,
                  "event-driven save detection for `make dev-watch` "
                  "(watch-dev-lane.sh:556)");
        return;
    }
    doc_absent(r, "inotifywait",
               "dev watcher falls back to polling (ZCL_DEV_WATCH_BACKEND=auto "
               "-> poll)",
               "save-to-check latency grows by up to ZCL_DEV_WATCH_POLL_MS "
               "(default 500 ms) on every edit, plus a steady polling wake "
               "instead of sleeping on inotify");
}

static void doc_coverage(struct doc_rep *r)
{
    char path[PATH_MAX];
    char ver[256];
    char where[PATH_MAX + 280];
    if (doc_which("lcov", path, sizeof path) == 0) {
        doc_version(path, ver, sizeof ver);
        (void)snprintf(where, sizeof where, "%s (%s)", path, ver);
        doc_found(r, "lcov", where,
                  "coverage report rendering for `make coverage` (coverage "
                  "target)");
        return;
    }
    if (doc_which("gcovr", path, sizeof path) == 0) {
        doc_found(r, "gcovr", path,
                  "coverage report rendering for `make coverage` (lcov absent; "
                  "gcovr fallback path)");
        return;
    }
    doc_absent(r, "lcov/gcovr",
               "no coverage renderer for `make coverage` (coverage target)",
               "the coverage stage in `make ci` cannot render reports — run "
               "with SKIP_COV=1 or lose coverage evidence");
}

static void doc_clangd(struct doc_rep *r)
{
    char path[PATH_MAX];
    if (doc_which("clangd", path, sizeof path) == 0) {
        doc_found(r, "clangd", path,
                  "C23 language server over compile_commands.json (make "
                  "agent-index; ff warns when stale)");
        return;
    }
    doc_absent(r, "clangd", "no language-server indexing of the tree",
               "no iteration-time cost — clangd is optional; "
               "cognition/modules/codeindex + `make agent-index` cover "
               "agent-side navigation. Install only if you want IDE go-to-def");
}

static void doc_footer(const struct doc_rep *r)
{
    char line[160];
    doc_write(r->fd, "\n");
    (void)snprintf(line, sizeof line,
                   "doctor-build: %d present, %d missing (advisory only; the "
                   "tree builds without all of these)\n",
                   r->ok, r->missing);
    doc_write(r->fd, line);
}

int zcl_doctor_build(int out_fd)
{
    struct doc_rep report;
    if (out_fd < 0)
        return 0;
    report.fd = out_fd;
    report.ok = 0;
    report.missing = 0;
    doc_header(&report);
    doc_cache(&report);
    doc_linker(&report);
    doc_clang(&report);
    doc_inotify(&report);
    doc_coverage(&report);
    doc_clangd(&report);
    doc_footer(&report);
    return 0;
}
