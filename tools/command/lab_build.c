/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Toolchain discovery, single-file compile and confined run for the
 * one-file lab. The compile child is confined with Landlock and a seccomp
 * deny-set (no network); the run child additionally has no fork and no
 * writable path outside a fresh private workdir. */
#define _GNU_SOURCE

#include "command/lab.h"

#include "base/safe_alloc.h"
#include "platform/os_proc.h"
#include "util/file_tree_ops.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)

static size_t g_compiles;
static size_t g_runs;

size_t lab_compile_count(void)
{
    return g_compiles;
}

size_t lab_run_count(void)
{
    return g_runs;
}

/* ── state directory ────────────────────────────────────────────────── */

static bool lab_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool lab_base_path(char *out, size_t cap)
{
    const char *over = getenv("Z23_LAB_DIR");
    const char *home = getenv("HOME");
    int n;
    if (over && over[0])
        n = snprintf(out, cap, "%s", over);
    else if (home && home[0])
        n = snprintf(out, cap, "%s/.z23/lab", home);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

enum lab_err lab_dirs_open(struct lab_dirs *d)
{
    memset(d, 0, sizeof(*d));
    if (!lab_base_path(d->base, sizeof(d->base)) ||
        !lab_join(d->cc, sizeof(d->cc), d->base, "cc") ||
        !lab_join(d->run, sizeof(d->run), d->base, "run") ||
        !lab_join(d->receipts, sizeof(d->receipts), d->base, "receipts") ||
        !lab_join(d->zcc, sizeof(d->zcc), d->base, "zcc"))
        return LAB_E_UNSUPPORTED;
    const char *all[] = { d->base, d->cc, d->run, d->receipts, d->zcc };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (!zcl_result_is_ok(zcl_mkdir_p(all[i], 0700)))
            return LAB_E_STATE;
    return LAB_OK;
}

/* ── toolchain ──────────────────────────────────────────────────────── */

static bool lab_is_exec_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           access(path, X_OK) == 0;
}

static bool lab_find_cc(char out[LAB_PATH])
{
    const char *path = getenv("PATH");
    char list[4096], cand[LAB_PATH];
    snprintf(list, sizeof(list), "%s", path && path[0] ? path : "/usr/bin:/bin");
    for (char *save = NULL, *dir = strtok_r(list, ":", &save); dir;
         dir = strtok_r(NULL, ":", &save)) {
        if (dir[0] != '/' || !lab_join(cand, sizeof(cand), dir, "cc"))
            continue;
        if (lab_is_exec_file(cand) && realpath(cand, out))
            return true;
    }
    return false;
}

/* The compile cache ships next to the node binary (build/bin/zcc). */
static void lab_find_zcc(char out[LAB_PATH])
{
    char exe[LAB_PATH], cand[LAB_PATH];
    out[0] = '\0';
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return;
    char *slash = strrchr(exe, '/');
    for (int up = 0; slash && up < 3; up++) {
        *slash = '\0';
        if (lab_join(cand, sizeof(cand), exe, "zcc") && lab_is_exec_file(cand)) {
            snprintf(out, LAB_PATH, "%s", cand);
            return;
        }
        slash = strrchr(exe, '/');
    }
}

static void lab_identity_of(struct lab_hasher *h, const char *tag,
                            const char *path)
{
    struct stat st;
    if (!path[0] || stat(path, &st) != 0) {
        lab_hasher_field(h, tag, "", 0);
        return;
    }
    lab_hasher_field(h, tag, path, strlen(path));
    lab_hasher_u64(h, "size", (uint64_t)st.st_size);
    lab_hasher_u64(h, "mtime_s", (uint64_t)st.st_mtim.tv_sec);
    lab_hasher_u64(h, "mtime_ns", (uint64_t)st.st_mtim.tv_nsec);
}

enum lab_err lab_toolchain_find(struct lab_toolchain *tc)
{
    memset(tc, 0, sizeof(*tc));
    if (!lab_find_cc(tc->cc))
        return LAB_E_NO_COMPILER;
    lab_find_zcc(tc->zcc);
    struct lab_hasher *h = lab_hasher_new("compiler");
    if (!h)
        return LAB_E_STATE;
    lab_identity_of(h, "cc", tc->cc);
    lab_identity_of(h, "zcc", tc->zcc);
    lab_hasher_finish(h, tc->identity);
    return LAB_OK;
}

/* ── source ─────────────────────────────────────────────────────────── */

static void lab_base_name(const char *path, char out[72])
{
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    size_t n = strlen(name), j = 0;
    for (size_t i = 0; i < n && j < 64; i++) {
        unsigned char c = (unsigned char)name[i];
        out[j++] = (isalnum(c) || c == '_' || c == '-' || c == '.') ? (char)c
                                                                    : '_';
    }
    out[j] = '\0';
    if (j < 3 || out[0] == '.' || strcmp(out + j - 2, ".c") != 0)
        snprintf(out, 72, "main.c");
}

static enum lab_err lab_read_fd(int fd, struct lab_source *src)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid())
        return LAB_E_BAD_FILE;
    if (st.st_size > LAB_SRC_MAX)
        return LAB_E_TOO_LARGE;
    src->bytes = zcl_malloc((size_t)st.st_size + 1, "lab.source");
    if (!src->bytes)
        return LAB_E_STATE;
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, src->bytes + got, (size_t)st.st_size - got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    src->len = got;
    src->bytes[got] = '\0';
    return got == (size_t)st.st_size ? LAB_OK : LAB_E_BAD_FILE;
}

enum lab_err lab_source_load(const char *path, struct lab_source *src)
{
    memset(src, 0, sizeof(*src));
    size_t n = path ? strlen(path) : 0;
    if (n < 3 || n >= LAB_PATH || strcmp(path + n - 2, ".c") != 0)
        return LAB_E_BAD_FILE;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? LAB_E_NOT_FOUND : LAB_E_BAD_FILE;
    enum lab_err err = lab_read_fd(fd, src);
    close(fd);
    snprintf(src->path, sizeof(src->path), "%s", path);
    lab_base_name(path, src->base);
    if (err != LAB_OK)
        lab_source_free(src);
    return err;
}

void lab_source_free(struct lab_source *src)
{
    free(src->bytes);
    src->bytes = NULL;
    src->len = 0;
}

/* ── diagnostics ────────────────────────────────────────────────────── */

static bool lab_severity(const char *p, char *sev, const char **rest)
{
    static const struct { const char *text; const char *name; } k[] = {
        { " fatal error: ", "error" }, { " error: ", "error" },
        { " warning: ", "warning" },   { " note: ", "note" },
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        size_t n = strlen(k[i].text);
        if (strncmp(p, k[i].text, n) == 0) {
            snprintf(sev, 8, "%s", k[i].name);
            *rest = p + n;
            return true;
        }
    }
    return false;
}

/* Parse "file:line:col: severity: message" (column optional). */
static bool lab_parse_line(const char *line, size_t len, struct lab_diag *d)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "%.*s", (int)(len < 511 ? len : 511), line);
    const char *p = strchr(buf, ':');
    char *end;
    while (p) {
        long ln = strtol(p + 1, &end, 10);
        if (end == p + 1) {
            p = strchr(p + 1, ':');
            continue;
        }
        long col = 0;
        if (*end == ':' && end[1] >= '0' && end[1] <= '9')
            col = strtol(end + 1, &end, 10);
        const char *msg;
        if (*end == ':' && lab_severity(end + 1, d->severity, &msg)) {
            d->line = (int)ln;
            d->col = (int)col;
            snprintf(d->message, sizeof(d->message), "%s", msg);
            return true;
        }
        p = strchr(p + 1, ':');
    }
    return false;
}

static void lab_parse_diagnostics(const char *text, struct lab_compile *c)
{
    const char *line = text;
    while (*line && c->n_diag < LAB_DIAG_MAX) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (lab_parse_line(line, len, &c->diag[c->n_diag]))
            c->n_diag++;
        line = nl ? nl + 1 : line + len;
    }
}

static void lab_set_tail(const char *text, size_t len, struct lab_compile *c)
{
    size_t from = len > LAB_TAIL_MAX ? len - LAB_TAIL_MAX : 0;
    memcpy(c->tail, text + from, len - from);
    c->tail[len - from] = '\0';
}

/* ── compile ────────────────────────────────────────────────────────── */

static bool lab_write_source(const char *dir, const struct lab_source *src)
{
    char path[LAB_PATH];
    if (!lab_join(path, sizeof(path), dir, src->base))
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t off = 0;
    while (off < src->len) {
        ssize_t n = write(fd, src->bytes + off, src->len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    return close(fd) == 0 && off == src->len;
}

struct lab_cc_args {
    const char *argv[24];
    char binary_rel[96];
};

static void lab_cc_argv(const struct lab_toolchain *tc,
                        const struct lab_source *src, bool sanitize,
                        struct lab_cc_args *a)
{
    size_t n = 0;
    if (tc->zcc[0]) {
        a->argv[n++] = tc->zcc;
        a->argv[n++] = tc->cc;
    } else {
        a->argv[n++] = tc->cc;
    }
    static const char *const flags[] = {
        "-std=c23", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pedantic",
    };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++)
        a->argv[n++] = flags[i];
    if (sanitize) {
        a->argv[n++] = "-fsanitize=address,undefined";
        a->argv[n++] = "-fno-omit-frame-pointer";
    }
    snprintf(a->binary_rel, sizeof(a->binary_rel), "%s.%ld.bin", src->base,
             (long)getpid());
    a->argv[n++] = src->base;
    a->argv[n++] = "-o";
    a->argv[n++] = a->binary_rel;
    a->argv[n++] = "-lm";
    a->argv[n] = NULL;
}

static size_t lab_compile_rules(const struct lab_dirs *d,
                                const struct lab_toolchain *tc, const char *dir,
                                struct os_sandbox_path_rule *r)
{
    size_t n = 0;
    struct stat st;
    r[n++] = (struct os_sandbox_path_rule){ .path = "/usr", .allow_read = true,
                                            .allow_execute = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/lib", .allow_read = true,
                                            .allow_execute = true };
    if (stat("/lib64", &st) == 0)
        r[n++] = (struct os_sandbox_path_rule){ .path = "/lib64",
            .allow_read = true, .allow_execute = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/etc/ld.so.cache",
                                            .allow_read = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/dev/null",
        .allow_read = true, .allow_write = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = dir, .allow_read = true,
        .allow_write = true, .allow_create = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = d->zcc, .allow_read = true,
        .allow_write = true, .allow_create = true };
    if (tc->zcc[0])
        r[n++] = (struct os_sandbox_path_rule){ .path = tc->zcc,
            .allow_read = true, .allow_execute = true };
    return n;
}

static void lab_compile_finish(struct lab_proc *p, struct lab_compile *c,
                               const char *dir, const char *binary_rel)
{
    c->unconfined = p->launch == LAB_LAUNCH_UNCONFINED ||
                    p->launch == LAB_LAUNCH_UNSUPPORTED;
    if (p->launch != LAB_LAUNCHED) {
        snprintf(c->detail, sizeof(c->detail), "%s", p->detail);
        return;
    }
    char text[2 * LAB_CAPTURE_MAX + 2];
    int n = snprintf(text, sizeof(text), "%s%s", p->err, p->out);
    size_t len = n > 0 ? (size_t)n : 0;
    lab_set_tail(text, len, c);
    lab_parse_diagnostics(text, c);
    c->ok = !p->timed_out && p->term_signal == 0 && p->exit_code == 0;
    if (p->timed_out)
        snprintf(c->detail, sizeof(c->detail), "compile exceeded %d ms",
                 LAB_COMPILE_TIMEOUT_MS);
    if (c->ok && !lab_join(c->binary, sizeof(c->binary), dir, binary_rel))
        c->ok = false;
}

static void lab_compile_once(const struct lab_dirs *d,
                             const struct lab_toolchain *tc,
                             const struct lab_source *src, const char *dir,
                             bool sanitize, struct lab_compile *c)
{
    struct os_sandbox_path_rule rules[10];
    struct lab_cc_args args;
    struct lab_proc proc;
    char tmpdir[LAB_PATH + 16], zdir[LAB_PATH + 16];
    snprintf(tmpdir, sizeof(tmpdir), "TMPDIR=%s", dir);
    snprintf(zdir, sizeof(zdir), "ZCC_DIR=%s", d->zcc);
    const char *env[] = { "PATH=/usr/bin:/bin", "LC_ALL=C", tmpdir, zdir,
                          "ZCC_MAX_MB=64", NULL };
    lab_cc_argv(tc, src, sanitize, &args);
    struct lab_spawn spawn = {
        .profile = LAB_PROFILE_COMPILE, .confine = lab_sandbox_available(),
        .argv = args.argv, .env = env,
        .cwd = dir, .rules = rules,
        .n_rules = lab_compile_rules(d, tc, dir, rules),
        .timeout_ms = LAB_COMPILE_TIMEOUT_MS,
        .as_bytes = OS_SANDBOX_RLIMIT_KEEP, .fsize_bytes = 256u << 20,
        .nofile = 256,
    };
    memset(c, 0, sizeof(*c));
    if (!lab_proc_init(&proc)) {
        snprintf(c->detail, sizeof(c->detail), "allocation failed");
        return;
    }
    g_compiles++;
    lab_spawn_run(&spawn, &proc);
    c->wall_us = proc.wall_us;
    lab_compile_finish(&proc, c, dir, args.binary_rel);
    c->sanitized = c->ok && sanitize;
    lab_proc_free(&proc);
}

static bool lab_sanitizer_missing(const struct lab_compile *c)
{
    return strstr(c->tail, "sanitize") || strstr(c->tail, "-lasan") ||
           strstr(c->tail, "-lubsan") || strstr(c->tail, "libasan") ||
           strstr(c->tail, "libubsan");
}

void lab_compile_source(const struct lab_dirs *d, const struct lab_toolchain *tc,
                        const struct lab_source *src, const char *name,
                        bool sanitize, struct lab_compile *out)
{
    char dir[LAB_PATH];
    memset(out, 0, sizeof(*out));
    if (!lab_join(dir, sizeof(dir), d->cc, name) ||
        !zcl_result_is_ok(zcl_mkdir_p(dir, 0700)) || !lab_write_source(dir, src)) {
        snprintf(out->detail, sizeof(out->detail), "compile directory failed");
        return;
    }
    lab_compile_once(d, tc, src, dir, sanitize, out);
    if (sanitize && !out->ok && !out->unconfined && lab_sanitizer_missing(out)) {
        lab_compile_once(d, tc, src, dir, false, out);
        out->sanitizers_unavailable = out->ok;
    }
}

void lab_compile_cleanup(const struct lab_dirs *d, const char *name)
{
    char dir[LAB_PATH];
    if (lab_join(dir, sizeof(dir), d->cc, name))
        (void)zcl_tree_remove(dir);
}

/* ── confined run ───────────────────────────────────────────────────── */

static size_t lab_run_rules(const char *workdir, const char *binary,
                            struct os_sandbox_path_rule *r)
{
    size_t n = 0;
    struct stat st;
    const char *libs[] = { "/lib", "/lib64", "/usr/lib" };
    for (size_t i = 0; i < 3; i++)
        if (stat(libs[i], &st) == 0)
            r[n++] = (struct os_sandbox_path_rule){ .path = libs[i],
                .allow_read = true, .allow_execute = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/etc/ld.so.cache",
                                            .allow_read = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = binary, .allow_read = true,
                                            .allow_execute = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = workdir, .allow_read = true,
        .allow_write = true, .allow_create = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = OS_SANDBOX_PROC_SELF_PATH,
                                            .allow_read = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/dev/null",
        .allow_read = true, .allow_write = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/dev/urandom",
                                            .allow_read = true };
    r[n++] = (struct os_sandbox_path_rule){ .path = "/dev/zero",
                                            .allow_read = true };
    return n;
}

static void lab_run_argv(const char *binary, const struct lab_inputs *in,
                         const char **argv)
{
    size_t n = 0;
    argv[n++] = binary;
    for (size_t i = 0; i < in->n_args && i < LAB_ARGS_MAX; i++)
        argv[n++] = in->args[i];
    argv[n] = NULL;
}

void lab_run_binary(const struct lab_dirs *d, const char *binary,
                    bool sanitized, const struct lab_inputs *in,
                    struct lab_proc *out)
{
    char workdir[LAB_PATH], asan[96];
    const char *argv[LAB_ARGS_MAX + 2];
    struct os_sandbox_path_rule rules[12];
    if (!lab_join(workdir, sizeof(workdir), d->run, "XXXXXX") ||
        !mkdtemp(workdir)) {
        out->launch = LAB_LAUNCH_FAILED;
        snprintf(out->detail, sizeof(out->detail), "workdir could not be made");
        return;
    }
    snprintf(asan, sizeof(asan),
             "ASAN_OPTIONS=detect_leaks=0:symbolize=0:hard_rss_limit_mb=%u",
             (unsigned)in->mem_mb);
    const char *env[] = { "LC_ALL=C", asan,
                          "UBSAN_OPTIONS=symbolize=0:print_stacktrace=0", NULL };
    lab_run_argv(binary, in, argv);
    struct lab_spawn spawn = {
        .profile = LAB_PROFILE_RUN, .confine = true, .argv = argv, .env = env,
        .cwd = workdir,
        .rules = rules, .n_rules = lab_run_rules(workdir, binary, rules),
        .stdin_data = in->stdin_data, .stdin_len = in->stdin_len,
        .timeout_ms = in->timeout_ms,
        .as_bytes = sanitized ? OS_SANDBOX_RLIMIT_KEEP
                              : (uint64_t)in->mem_mb << 20,
        .fsize_bytes = 16u << 20, .nofile = 64, .watch_dir = workdir,
        .watch_max_bytes = LAB_WORKDIR_MAX,
    };
    g_runs++;
    lab_spawn_run(&spawn, out);
    (void)zcl_tree_remove(workdir);
}

#endif /* __linux__ */
