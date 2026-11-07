/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the launchable-app registry behind `z23 app list` / `app open`:
 * compiled-in rows from app_launch_catalog.def, resolved only beside the
 * running binary, plus the operator's own apps.tsv, refused whole unless the
 * file and every executable it names are owner-controlled. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* realpath */
#endif

#include "command/native_app_launch.h"
#include "command/app_selection.h"

#include "platform/os_proc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZCL_APP_ARGV(...) ((const char *const[]){__VA_ARGS__ __VA_OPT__(, ) NULL})

struct app_builtin {
    const char *id;
    const char *aliases;
    const char *executable;
    const char *const *argv;
    const char *ready_marker;
    bool raise_sigusr1;
    const char *build_hint;
    const char *const *preview_argv; /* NULL-terminated; one "%s" capture slot */
    const char *preview_file;        /* capture file in a copy's directory */
};

#define ZCL_APP_RAISE_UNSUPPORTED false
#define ZCL_APP_RAISE_SIGUSR1 true

static const struct app_builtin k_app_builtins[] = {
#define ZCL_APP_LAUNCH(id_, aliases_, exe_, argv_, marker_, raise_, hint_, \
                       preview_argv_, preview_file_) \
    {id_, aliases_, exe_, argv_, marker_, raise_, hint_, preview_argv_, \
     preview_file_},
#include "app_launch_catalog.def"
#undef ZCL_APP_LAUNCH
};

#define APP_TSV_MAX_BYTES 16384u

bool app_launch_kept_entry(const char *name, struct app_launch_entry *out)
{
    if (!out || !app_selection_route_valid(name)) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->id, sizeof(out->id), "%s", name);
    /* No argv, marker or signal declaration may come from the received copy. */
    return true;
}

static bool app_copy(char *dst, size_t cap, const char *src, size_t len)
{
    bool fits = len < cap;

    if (fits) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return fits;
}

/* [a-z0-9-], 1..APP_LAUNCH_ID_MAX bytes, starting with a letter or digit. */
static bool app_name_valid(const char *s, size_t len)
{
    if (len == 0 || len > APP_LAUNCH_ID_MAX || s[0] == '-')
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* ── process environment ──────────────────────────────────────────────── */

/* The directory of the running binary (platform/os_proc.h resolves it; a
 * Linux " (deleted)" suffix after an in-place upgrade is dropped). */
static bool app_self_dir(char *out, size_t cap)
{
    static const char deleted[] = " (deleted)";
    if (!os_proc_exe_path(out, cap)) {
        out[0] = '\0';
        return false;
    }
    size_t len = strlen(out), dl = sizeof(deleted) - 1;
    if (len > dl && strcmp(out + len - dl, deleted) == 0)
        out[len - dl] = '\0';
    char *slash = strrchr(out, '/');
    if (!slash || slash == out)
        return false;
    *slash = '\0';
    return true;
}

static bool app_xdg_path(char *out, size_t cap, const char *xdg_var,
                         const char *home_suffix, const char *leaf)
{
    const char *xdg = getenv(xdg_var);
    const char *home = getenv("HOME");
    int n;
    if (xdg && xdg[0] == '/')
        n = snprintf(out, cap, "%s/z23%s", xdg, leaf);
    else if (home && home[0] == '/')
        n = snprintf(out, cap, "%s/%s/z23%s", home, home_suffix, leaf);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

bool app_launch_env_from_process(struct app_launch_env *env, char *why,
                                 size_t why_size)
{
    memset(env, 0, sizeof(*env));
    env->ready_timeout_ms = APP_LAUNCH_READY_TIMEOUT_MS;
    env->settle_ms = APP_LAUNCH_SETTLE_MS;
    if (!app_self_dir(env->bin_dir, sizeof(env->bin_dir)))
        env->bin_dir[0] = '\0';
    if (!app_xdg_path(env->config_path, sizeof(env->config_path),
                      "XDG_CONFIG_HOME", ".config", "/apps.tsv"))
        env->config_path[0] = '\0';
    if (!app_xdg_path(env->state_dir, sizeof(env->state_dir),
                      "XDG_STATE_HOME", ".local/state", "/apps")) {
        snprintf(why, why_size, "cannot name the app state directory: "
                 "HOME is unset or not absolute");
        return false;
    }
#if defined(__linux__)
    const char *x11 = getenv("DISPLAY");
    const char *wl = getenv("WAYLAND_DISPLAY");
    env->desktop = (x11 && x11[0]) || (wl && wl[0]);
#else
    env->desktop = true;
#endif
    return true;
}

/* ── executable checks ────────────────────────────────────────────────── */

enum app_exe_state { APP_EXE_MISSING, APP_EXE_OK, APP_EXE_UNSAFE };

/* Resolve path to its canonical form and check it is a regular executable
 * file; strict additionally requires it to be owned by this user or root
 * and not group- or world-writable. */
static enum app_exe_state app_exe_check(const char *path, bool strict,
                                        char resolved[APP_LAUNCH_PATH_MAX],
                                        const char **why)
{
#if defined(_WIN32)
    (void)path; (void)strict; (void)resolved;
    *why = "desktop launch is not supported on Windows";
    return APP_EXE_MISSING;
#else
    struct stat st;
    char real[PATH_MAX];
    *why = "";
    if (!realpath(path, real) || stat(real, &st) != 0) {
        *why = "the executable does not exist";
        return errno == ENOENT || errno == ENOTDIR ? APP_EXE_MISSING
                                                    : APP_EXE_UNSAFE;
    }
    if (strlen(real) >= APP_LAUNCH_PATH_MAX) {
        *why = "the executable path is too long";
        return APP_EXE_UNSAFE;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & S_IXUSR) == 0) {
        *why = "is not a regular executable file";
        return APP_EXE_UNSAFE;
    }
    if (strict && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        *why = "is group- or world-writable";
        return APP_EXE_UNSAFE;
    }
    if (strict && st.st_uid != getuid() && st.st_uid != 0) {
        *why = "is owned by another user";
        return APP_EXE_UNSAFE;
    }
    memcpy(resolved, real, strlen(real) + 1);
    return APP_EXE_OK;
#endif
}

/* ── built-in rows ────────────────────────────────────────────────────── */

static bool app_split_aliases(struct app_launch_entry *e, const char *csv)
{
    const char *p = csv;
    while (p && *p) {
        size_t len = strcspn(p, ",");
        if (e->alias_count >= APP_LAUNCH_ALIASES_MAX ||
            !app_name_valid(p, len) ||
            !app_copy(e->aliases[e->alias_count], sizeof(e->aliases[0]), p,
                      len))
            return false;
        e->alias_count++;
        p += len;
        if (*p == ',')
            p++;
    }
    return true;
}

static void app_builtin_load(const struct app_launch_env *env,
                             const struct app_builtin *b,
                             struct app_launch_entry *e)
{
    char path[APP_LAUNCH_PATH_MAX];
    const char *why;
    memset(e, 0, sizeof(*e));
    e->builtin = true;
    (void)app_copy(e->id, sizeof(e->id), b->id, strlen(b->id));
    if (!app_split_aliases(e, b->aliases))
        LOG_ERROR("app-launch", "built-in app %s has an invalid alias list",
                  b->id);
    for (unsigned i = 0; b->argv[i] && i < APP_LAUNCH_ARGS_MAX; i++)
        if (app_copy(e->args[i], sizeof(e->args[0]), b->argv[i],
                     strlen(b->argv[i])))
            e->arg_count = i + 1;
    (void)app_copy(e->ready_marker, sizeof(e->ready_marker), b->ready_marker,
                   strlen(b->ready_marker));
    (void)app_copy(e->build_hint, sizeof(e->build_hint), b->build_hint,
                   strlen(b->build_hint));
    e->raise_sigusr1 = b->raise_sigusr1;
    /* Seam for unit U9: an adopted, built personal copy will resolve here
     * and open through resident_launch, never posix_spawn by path. Today a
     * built-in resolves only beside the running binary. */
    int n = snprintf(path, sizeof(path), "%s/%s", env->bin_dir, b->executable);
    if (!env->bin_dir[0] || n <= 0 || (size_t)n >= sizeof(path)) {
        (void)app_copy(e->executable, sizeof(e->executable), b->executable,
                       strlen(b->executable));
        return;
    }
    (void)app_copy(e->executable, sizeof(e->executable), path, (size_t)n);
    e->installed = app_exe_check(path, false, e->executable, &why) == APP_EXE_OK;
}

/* ── operator apps.tsv ────────────────────────────────────────────────── */

struct app_tsv {
    struct app_launch_registry *reg;
    unsigned line;
    char *error;
    size_t error_size;
};

static bool app_tsv_fail(struct app_tsv *t, const char *what, const char *field)
{
    snprintf(t->error, t->error_size, "apps.tsv line %u: %s%s%s", t->line,
             what, field && field[0] ? ": " : "", field ? field : "");
    return false;
}

static bool app_name_taken(const struct app_launch_registry *reg,
                           const char *name)
{
    return app_launch_registry_find(reg, name) != NULL;
}

static bool app_tsv_names(struct app_tsv *t, struct app_launch_entry *e,
                          const char *id, const char *aliases)
{
    if (!app_name_valid(id, strlen(id)))
        return app_tsv_fail(t, "id must be 1-32 of a-z, 0-9 and -", id);
    (void)app_copy(e->id, sizeof(e->id), id, strlen(id));
    if (strcmp(aliases, "-") != 0 && !app_split_aliases(e, aliases))
        return app_tsv_fail(t, "aliases must be - or up to 4 comma-separated "
                               "names of a-z, 0-9 and -", aliases);
    if (app_name_taken(t->reg, e->id))
        return app_tsv_fail(t, "name already used", e->id);
    for (unsigned i = 0; i < e->alias_count; i++)
        if (app_name_taken(t->reg, e->aliases[i]) ||
            strcmp(e->aliases[i], e->id) == 0)
            return app_tsv_fail(t, "name already used", e->aliases[i]);
    return true;
}

static bool app_tsv_executable(struct app_tsv *t, struct app_launch_entry *e,
                               const char *exe)
{
    const char *why;
    if (exe[0] != '/')
        return app_tsv_fail(t, "executable must be an absolute path", exe);
    if (!app_copy(e->executable, sizeof(e->executable), exe, strlen(exe)))
        return app_tsv_fail(t, "executable path is too long", "");
    switch (app_exe_check(exe, true, e->executable, &why)) {
    case APP_EXE_OK:
        e->installed = true;
        return true;
    case APP_EXE_MISSING:
        return true;
    default:
        snprintf(t->error, t->error_size, "apps.tsv line %u: executable %s %s",
                 t->line, exe, why);
        return false;
    }
}

/* Columns 4 and 5: the ready marker ("-" = alive after the settle time) and
 * the raise declaration ("sigusr1" or "-"). */
static bool app_tsv_options(struct app_tsv *t, struct app_launch_entry *e,
                            const char *marker, const char *raise)
{
    if (strcmp(marker, "-") != 0 &&
        !app_copy(e->ready_marker, sizeof(e->ready_marker), marker,
                  strlen(marker)))
        return app_tsv_fail(t, "ready marker is too long", "");
    if (strcmp(raise, "sigusr1") == 0)
        e->raise_sigusr1 = true;
    else if (strcmp(raise, "-") != 0)
        return app_tsv_fail(t, "raise must be sigusr1 or -", raise);
    return true;
}

#define APP_TSV_FIXED 5u

/* id TAB aliases TAB /abs/executable TAB ready-marker TAB raise [TAB arg]... */
static bool app_tsv_row(struct app_tsv *t, char *line)
{
    char *field[APP_TSV_FIXED + APP_LAUNCH_ARGS_MAX + 1];
    unsigned n = 0;
    for (char *p = line; p && n < sizeof(field) / sizeof(field[0]);) {
        field[n++] = p;
        p = strchr(p, '\t');
        if (p)
            *p++ = '\0';
    }
    if (n < APP_TSV_FIXED)
        return app_tsv_fail(t, "need id, aliases, executable, ready marker and "
                               "raise separated by tabs", "");
    if (n > APP_TSV_FIXED + APP_LAUNCH_ARGS_MAX)
        return app_tsv_fail(t, "more than 8 arguments", "");
    if (t->reg->count >= APP_LAUNCH_ENTRIES_MAX)
        return app_tsv_fail(t, "more than 16 apps", "");
    struct app_launch_entry *e = &t->reg->entries[t->reg->count];
    memset(e, 0, sizeof(*e));
    if (!app_tsv_names(t, e, field[0], field[1]) ||
        !app_tsv_executable(t, e, field[2]) ||
        !app_tsv_options(t, e, field[3], field[4]))
        return false;
    for (unsigned i = APP_TSV_FIXED; i < n; i++)
        if (!app_copy(e->args[e->arg_count++], sizeof(e->args[0]), field[i],
                      strlen(field[i])))
            return app_tsv_fail(t, "argument is too long", "");
    (void)snprintf(e->build_hint, sizeof(e->build_hint),
                   "install it at the path apps.tsv names");
    t->reg->count++;
    return true;
}

static bool app_tsv_parse(struct app_tsv *t, char *text)
{
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        t->line++;
        size_t len = strlen(line);
        if (len && line[len - 1] == '\r')
            line[--len] = '\0';
        if (len == 0 || line[0] == '#')
            continue;
        if (!app_tsv_row(t, line))
            return false;
    }
    return true;
}

#if !defined(_WIN32)
/* Owner-controlled regular file, read whole into buf. */
static bool app_tsv_read(const char *path, char *buf, size_t cap,
                         bool *present, char *why, size_t why_size)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    *present = fd >= 0 || errno != ENOENT;
    if (fd < 0) {
        if (*present)
            snprintf(why, why_size, "%s: cannot open (%s)", path,
                     strerror(errno));
        return false;
    }
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    if (!ok)
        snprintf(why, why_size, "%s is not a regular file", path);
    else if (st.st_uid != getuid() || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        snprintf(why, why_size, "%s must be owned by you and not group- or "
                 "world-writable (chmod 600)", path);
        ok = false;
    } else if ((size_t)st.st_size >= cap) {
        snprintf(why, why_size, "%s is larger than %u bytes", path,
                 APP_TSV_MAX_BYTES);
        ok = false;
    }
    ssize_t got = ok ? read(fd, buf, cap - 1) : -1;
    if (ok && (got < 0 || got != (ssize_t)st.st_size)) {
        snprintf(why, why_size, "%s: short read", path);
        ok = false;
    }
    if (ok)
        buf[got] = '\0';
    (void)close(fd);
    return ok;
}
#endif

static void app_tsv_load(const struct app_launch_env *env,
                         struct app_launch_registry *reg)
{
#if defined(_WIN32)
    (void)env;
    (void)reg;
#else
    static char text[APP_TSV_MAX_BYTES];
    unsigned builtin_count = reg->count;
    if (!env->config_path[0] ||
        !app_tsv_read(env->config_path, text, sizeof(text),
                      &reg->config_present, reg->config_error,
                      sizeof(reg->config_error)))
        return;
    struct app_tsv t = {.reg = reg, .error = reg->config_error,
                        .error_size = sizeof(reg->config_error)};
    if (!app_tsv_parse(&t, text)) {
        reg->count = builtin_count;
        LOG_WARN("app-launch", "refusing operator app list: %s",
                 reg->config_error);
    }
#endif
}

void app_launch_registry_load(const struct app_launch_env *env,
                              struct app_launch_registry *reg)
{
    memset(reg, 0, sizeof(*reg));
    size_t n = sizeof(k_app_builtins) / sizeof(k_app_builtins[0]);
    for (size_t i = 0; i < n && reg->count < APP_LAUNCH_ENTRIES_MAX; i++)
        app_builtin_load(env, &k_app_builtins[i], &reg->entries[reg->count++]);
    app_tsv_load(env, reg);
}

const struct app_launch_entry *
app_launch_registry_find(const struct app_launch_registry *reg,
                         const char *name)
{
    if (!name || !name[0])
        return NULL;
    for (unsigned i = 0; i < reg->count; i++) {
        const struct app_launch_entry *e = &reg->entries[i];
        if (strcmp(e->id, name) == 0)
            return e;
        for (unsigned a = 0; a < e->alias_count; a++)
            if (strcmp(e->aliases[a], name) == 0)
                return e;
    }
    return NULL;
}

bool app_launch_known_names(const struct app_launch_registry *reg, char *out,
                            size_t out_size)
{
    size_t at = 0;
    out[0] = '\0';
    for (unsigned i = 0; i < reg->count; i++) {
        int n = snprintf(out + at, out_size - at, "%s%s", i ? ", " : "",
                         reg->entries[i].id);
        if (n < 0 || (size_t)n >= out_size - at)
            return false;
        at += (size_t)n;
    }
    return true;
}

/* Copy one preview argument; its "%s" (at most one) becomes the capture path. */
static bool app_preview_arg(char *dst, size_t cap, const char *src,
                            const char *path)
{
    const char *slot = strstr(src, "%s");
    int n = slot ? snprintf(dst, cap, "%.*s%s%s", (int)(slot - src), src, path,
                            slot + 2)
                 : snprintf(dst, cap, "%s", src);
    return n > 0 && (size_t)n < cap;
}

/* Fill out->capture_path = <dir>/<file> and every argument of row b. */
static bool app_preview_fill(const struct app_builtin *b, const char *dir,
                             const char *file, struct app_launch_preview *out)
{
    int n = snprintf(out->capture_path, sizeof(out->capture_path), "%s/%s",
                     dir, file);
    if (n <= 0 || (size_t)n >= sizeof(out->capture_path))
        return false;
    for (unsigned a = 0; b->preview_argv[a]; a++) {
        if (a >= APP_LAUNCH_ARGS_MAX ||
            !app_preview_arg(out->args[a], sizeof(out->args[a]),
                             b->preview_argv[a], out->capture_path))
            return false;
        out->arg_count = a + 1;
    }
    return true;
}

/* The compiled-in PREVIEW argv of the built-in app `app_id`, with its "%s"
 * capture slot filled by <dir>/<preview_file>. The path comes from the
 * caller's own copy directory, never from user input. False when the app has
 * no preview row or anything does not fit. */
bool app_launch_preview(const char *app_id, const char *dir,
                        struct app_launch_preview *out)
{
    return app_launch_preview_as(app_id, dir, NULL, out);
}

/* As app_launch_preview, but the capture file is `file` (a plain name, no
 * slash) when given, so one directory can hold a capture per built image. */
bool app_launch_preview_as(const char *app_id, const char *dir,
                           const char *file, struct app_launch_preview *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!app_id || !dir || !dir[0] || (file && (!file[0] || strchr(file, '/'))))
        return false;
    for (size_t i = 0; i < sizeof(k_app_builtins) / sizeof(k_app_builtins[0]);
         i++) {
        const struct app_builtin *b = &k_app_builtins[i];
        if (strcmp(b->id, app_id) != 0 || !b->preview_argv[0] ||
            !b->preview_file[0])
            continue;
        if (!app_preview_fill(b, dir, file ? file : b->preview_file, out)) {
            memset(out, 0, sizeof(*out));
            return false;
        }
        return out->arg_count > 0;
    }
    return false;
}
