/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: bounded, non-authoritative local dispatch CPU observations. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_dev_factory_dispatch.h"
#include "command/native_command.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define FDC_PATH 4096u
#define FDC_ATTEMPTS 20000u
#define FDC_BYTES (8u * 1024u * 1024u)
#define FDC_LINE (65536u)
#define FDC_TOP 5u
#define FDC_SOURCE 512u

struct fdc_profile {
    int64_t rows, known_rows, child_rows, self_rows, child_us, self_us;
};
struct fdc_top {
    int64_t cpu_us, line;
    char source[FDC_SOURCE + 1u];
    bool truncated;
};
struct fdc_report {
    const char *status;
    char attempt[256];
    int64_t rows, malformed, unknown;
    struct fdc_profile profiles[4];
    struct fdc_top top[FDC_TOP];
    size_t top_count;
};

static void fdc_fail(struct zcl_command_reply *reply, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT", "input",
                           false, false, message, "input.dispatch_cpu");
}

#if !defined(_WIN32)
static bool fdc_component(const char *p, size_t n)
{
    return n && n < 256u && !(n == 1 && p[0] == '.') &&
        !(n == 2 && p[0] == '.' && p[1] == '.');
}

/* Open each path component without following links, retaining the directory. */
static int fdc_open_dir(const char *path)
{
    if (!path || !*path) return -1;
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    const char *p = path + (path[0] == '/');
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        char part[256];
        if (!fdc_component(p, n)) { close(fd); errno = EINVAL; return -1; }
        memcpy(part, p, n); part[n] = 0;
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(fd);
        if (next < 0) return -1;
        fd = next;
        if (!slash) break;
        p = slash + 1;
    }
    return fd;
}

static bool fdc_path(char out[FDC_PATH])
{
    const char *override = getenv("ZCL_DEV_FACTORY_ATTEMPTS");
    const char *home = getenv("HOME");
    int n = override && *override ? snprintf(out, FDC_PATH, "%s", override) :
        home && *home ? snprintf(out, FDC_PATH, "%s/.local/state/z23/dev/land/wt/.cache/zcl-dev-proof/attempts", home) : -1;
    return n > 0 && n < (int)FDC_PATH;
}

static int fdc_candidate(int root, const char *name, struct stat *st)
{
    int dir = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return -2;
    int logs = openat(dir, "logs", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(dir);
    if (logs < 0) return errno == ENOENT ? -1 : -2;
    int fd = openat(logs, "dispatch-timing.log", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int saved = errno;
    close(logs);
    if (fd < 0) return saved == ENOENT ? -1 : -2;
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) { close(fd); return -2; }
    return fd;
}

static bool fdc_newer(const struct stat *a, const char *name,
                      const struct stat *b, const char *best)
{
    if (a->st_mtime != b->st_mtime) return a->st_mtime > b->st_mtime;
#if defined(__APPLE__)
    if (a->st_mtimespec.tv_nsec != b->st_mtimespec.tv_nsec) return a->st_mtimespec.tv_nsec > b->st_mtimespec.tv_nsec;
#else
    if (a->st_mtim.tv_nsec != b->st_mtim.tv_nsec) return a->st_mtim.tv_nsec > b->st_mtim.tv_nsec;
#endif
    return strcmp(name, best) > 0;
}

struct fdc_selection {
    int rootfd, best;
    double lower, now;
    struct stat *chosen;
    struct fdc_report *report;
};

static bool fdc_consider(struct fdc_selection *s, const char *name)
{
    struct stat ds, st;
    struct fdc_report *r = s->report;
    if (strlen(name) >= sizeof(r->attempt)) { r->status = "refused_limit"; return false; }
    if (fstatat(s->rootfd, name, &ds, AT_SYMLINK_NOFOLLOW) != 0) { r->status = "read_failure"; return false; }
    if (!S_ISDIR(ds.st_mode)) { r->status = "refused"; return false; }
    int fd = fdc_candidate(s->rootfd, name, &st);
    if (fd == -1) return true;
    if (fd < 0) { r->status = "refused"; return false; }
    if ((double)st.st_mtime < s->lower || (double)st.st_mtime > s->now) { close(fd); return true; }
    if (s->best < 0 || fdc_newer(&st, name, s->chosen, r->attempt)) {
        if (s->best >= 0) close(s->best);
        s->best = fd; *s->chosen = st;
        (void)snprintf(r->attempt, sizeof(r->attempt), "%s", name);
    } else close(fd);
    return true;
}

static void fdc_walk(DIR *dir, struct fdc_selection *s)
{
    size_t count = 0;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) { if (errno) s->report->status = "read_failure"; break; }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (++count > FDC_ATTEMPTS) { s->report->status = "refused_limit"; break; }
        if (!fdc_consider(s, e->d_name)) break;
    }
}

static int fdc_select(const char *root, double lower, double now,
                      struct fdc_report *r, struct stat *chosen)
{
    int rootfd = fdc_open_dir(root);
    if (rootfd < 0) { r->status = errno == ENOENT ? "missing" : "refused"; return -1; }
    int scanfd = dup(rootfd);
    DIR *dir = scanfd < 0 ? NULL : fdopendir(scanfd);
    if (!dir) { if (scanfd >= 0) close(scanfd); close(rootfd); r->status = "read_failure"; return -1; }
    struct fdc_selection s = {rootfd, -1, lower, now, chosen, r};
    fdc_walk(dir, &s);
    if (closedir(dir) != 0 && !r->status) r->status = "read_failure";
    close(rootfd);
    if (r->status) { if (s.best >= 0) close(s.best); return -1; }
    if (s.best < 0) r->status = "missing";
    return s.best;
}

static bool fdc_number(const char *s, int64_t *out, bool *known)
{
    if (!strcmp(s, "unknown")) { *known = false; return true; }
    if (!*s) return false;
    int64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (INT64_MAX - (*s - '0')) / 10) return false;
        n = n * 10 + (*s - '0');
    }
    *out = n; *known = true; return true;
}

static bool fdc_add(int64_t a, int64_t b, int64_t *out)
{
    if (a < 0 || b < 0 || a > INT64_MAX - b) return false;
    *out = a + b; return true;
}

static unsigned fdc_profile(const char *output)
{
    if (!strncmp(output, "build/node-obj/", 15)) return 0;
    if (!strncmp(output, "build/dev-obj/", 14)) return 1;
    if (!strncmp(output, "build/test-obj/", 15)) return 2;
    return 3;
}

static void fdc_top_add(struct fdc_report *r, const char *source, int64_t cpu, int64_t line)
{
    size_t pos = 0;
    while (pos < r->top_count && (r->top[pos].cpu_us > cpu ||
           (r->top[pos].cpu_us == cpu && r->top[pos].line < line))) pos++;
    if (pos >= FDC_TOP) return;
    if (r->top_count < FDC_TOP) r->top_count++;
    for (size_t i = r->top_count - 1; i > pos; i--) r->top[i] = r->top[i - 1];
    struct fdc_top *t = &r->top[pos];
    size_t n = strlen(source); t->truncated = n > FDC_SOURCE;
    if (n > FDC_SOURCE) n = FDC_SOURCE;
    memcpy(t->source, source, n); t->source[n] = 0;
    t->cpu_us = cpu; t->line = line;
}

struct fdc_row { int64_t value[4]; bool known[4]; unsigned seen; };
static int fdc_field_index(const char *s)
{
    static const char *const names[] = {"local_children_user_us", "local_children_system_us", "local_self_user_us", "local_self_system_us"};
    for (int i = 0; i < 4; i++) if (!strcmp(s, names[i])) return i;
    return -1;
}

static bool fdc_fields(char *prefix, struct fdc_row *row)
{
    char *save = NULL;
    for (char *tok = strtok_r(prefix, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq) return false;
        *eq++ = 0;
        int i = fdc_field_index(tok);
        if (i < 0) {
            unsigned bit = !strcmp(tok, "dispatch_wall_ms") ? 16u : !strcmp(tok, "rc") ? 32u : 0u;
            if (bit && ((row->seen & bit) || !*eq)) return false;
            row->seen |= bit;
            continue;
        }
        unsigned bit = 1u << i;
        if (row->seen & bit || !fdc_number(eq, &row->value[i], &row->known[i])) return false;
        row->seen |= bit;
    }
    return (row->seen & 48u) == 48u;
}

static bool fdc_pair(bool known, int64_t first, int64_t second,
                     int64_t previous, int64_t *value, int64_t *sum)
{
    return !known || (fdc_add(first, second, value) && fdc_add(previous, *value, sum));
}

static bool fdc_record(struct fdc_report *r, struct fdc_profile *p,
                       const struct fdc_row *row, const char *src, int64_t line_no)
{
    bool ck = row->known[0] && row->known[1];
    bool sk = row->known[2] && row->known[3];
    int64_t child = 0, self = 0, total = 0, child_sum = p->child_us, self_sum = p->self_us;
    if (!fdc_pair(ck, row->value[0], row->value[1], p->child_us, &child, &child_sum) ||
        !fdc_pair(sk, row->value[2], row->value[3], p->self_us, &self, &self_sum) ||
        (ck && sk && !fdc_add(child, self, &total))) return false;
    p->rows++; r->rows++; p->child_us = child_sum; p->self_us = self_sum;
    if (ck) p->child_rows++;
    if (sk) p->self_rows++;
    if (ck && sk) { p->known_rows++; fdc_top_add(r, src, total, line_no); }
    else r->unknown++;
    return true;
}

static bool fdc_row_add(struct fdc_report *r, char *line, int64_t line_no)
{
    if (line[0] == '#') return true;
    char *src = strstr(line, " source=");
    if (!src) return false;
    *src = 0; src += 8;
    char *output = strstr(src, " output=");
    if (!output || strstr(output + 8, " output=")) return false;
    *output = 0; output += 8;
    if (!*src || !*output) return false;
    struct fdc_row row = {0};
    if (!fdc_fields(line, &row)) return false;
    struct fdc_profile *p = &r->profiles[fdc_profile(output)];
    return fdc_record(r, p, &row, src, line_no);
}

static bool fdc_same_file(const struct stat *a, const struct stat *b)
{
    bool same = a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtime == b->st_mtime && a->st_ctime == b->st_ctime;
#if defined(__APPLE__)
    return same && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return same && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static bool fdc_line_read(struct fdc_report *r, char *line, size_t *bytes, int64_t n)
{
    size_t len = strlen(line); *bytes += len;
    if (*bytes > FDC_BYTES || len > FDC_LINE || !len || line[len - 1] != '\n') {
        r->status = "truncated"; return false;
    }
    line[--len] = 0;
    if (!fdc_row_add(r, line, n)) r->malformed++;
    return true;
}

static void fdc_read(int fd, const struct stat *initial, struct fdc_report *r)
{
    if (initial->st_size < 0 || initial->st_size > (off_t)FDC_BYTES) { r->status = "refused_oversize"; close(fd); return; }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); r->status = "read_failure"; return; }
    char *line = zcl_malloc(FDC_LINE + 2u, "factory_dispatch_line");
    if (!line) { fclose(f); r->status = "read_failure"; return; }
    size_t bytes = 0; int64_t n = 0;
    while (fgets(line, FDC_LINE + 2u, f)) {
        if (!fdc_line_read(r, line, &bytes, ++n)) break;
    }
    struct stat after;
    if (!r->status && (ferror(f) || fstat(fd, &after) != 0 || !fdc_same_file(initial, &after))) r->status = "read_failure";
    free(line);
    if (fclose(f) != 0 && !r->status) r->status = "read_failure";
    if (!r->status) r->status = "ok";
}
#endif

static bool fdc_profiles(const struct fdc_report *r, struct json_value *out)
{
    static const char *const names[] = {"node", "dev", "test", "other"};
    struct json_value all; json_init(&all); json_set_object(&all);
    bool ok = true;
    for (size_t i = 0; i < 4 && ok; i++) {
        const struct fdc_profile *p = &r->profiles[i];
        struct json_value v; json_init(&v); json_set_object(&v);
        ok = json_push_kv_int(&v, "rows", p->rows) && json_push_kv_int(&v, "known_rows", p->known_rows) &&
             json_push_kv_int(&v, "child_known_rows", p->child_rows) && json_push_kv_int(&v, "self_known_rows", p->self_rows) &&
             json_push_kv_int_or_null(&v, "local_child_us", p->child_rows > 0, p->child_us) &&
             json_push_kv_int_or_null(&v, "local_self_us", p->self_rows > 0, p->self_us) && json_push_kv(&all, names[i], &v);
        json_free(&v);
    }
    ok = ok && json_push_kv(out, "profiles", &all); json_free(&all); return ok;
}

static bool fdc_top_report(const struct fdc_report *r, struct json_value *out)
{
    struct json_value list; json_init(&list); json_set_array(&list); bool ok = true;
    for (size_t i = 0; i < r->top_count && ok; i++) {
        const struct fdc_top *t = &r->top[i];
        struct json_value row; json_init(&row); json_set_object(&row);
        ok = json_push_kv_str(&row, "source", t->source) && json_push_kv_bool(&row, "source_truncated", t->truncated) &&
             json_push_kv_int(&row, "line", t->line) && json_push_kv_int(&row, "local_cpu_us", t->cpu_us) && json_push_back(&list, &row);
        json_free(&row);
    }
    ok = ok && json_push_kv(out, "top", &list); json_free(&list); return ok;
}

static bool fdc_totals(const struct fdc_report *r, struct json_value *out)
{
    int64_t child = 0, self = 0, known = 0, child_rows = 0, self_rows = 0;
    for (size_t i = 0; i < 4; i++) {
        const struct fdc_profile *p = &r->profiles[i];
        if (child > INT64_MAX - p->child_us || self > INT64_MAX - p->self_us ||
            known > INT64_MAX - p->known_rows || child_rows > INT64_MAX - p->child_rows ||
            self_rows > INT64_MAX - p->self_rows) return false;
        child += p->child_us; self += p->self_us; known += p->known_rows;
        child_rows += p->child_rows; self_rows += p->self_rows;
    }
    return json_push_kv_int(out, "known_rows", known) &&
        json_push_kv_int(out, "child_known_rows", child_rows) && json_push_kv_int(out, "self_known_rows", self_rows) &&
        json_push_kv_int_or_null(out, "local_child_us", child_rows > 0, child) &&
        json_push_kv_int_or_null(out, "local_self_us", self_rows > 0, self);
}

static bool fdc_metadata(const struct fdc_report *r, struct json_value *out)
{
    return json_push_kv_str(out, "status", r->status) &&
        json_push_kv_bool(out, "sampled_complete", false) &&
        json_push_kv_str(out, "basis", "latest observed attempt log; local only, non-authoritative") &&
        json_push_kv_str(out, "profile_basis", "inferred from output path") &&
        json_push_kv_str(out, "attempt", r->attempt) &&
        json_push_kv_int(out, "rows", r->rows) && json_push_kv_int(out, "malformed_rows", r->malformed) &&
        json_push_kv_int(out, "unknown_rows", r->unknown);
}

static bool fdc_emit(const struct fdc_report *r, struct json_value *data)
{
    struct json_value out; json_init(&out); json_set_object(&out);
    bool ok = fdc_metadata(r, &out) && fdc_totals(r, &out) && fdc_profiles(r, &out) &&
        fdc_top_report(r, &out) && json_push_kv(data, "dispatch_cpu", &out);
    json_free(&out); return ok;
}

bool zcl_dev_factory_dispatch(const struct json_value *input, double now,
                              double window_s, struct zcl_command_reply *reply)
{
    const struct json_value *value = input ? json_get(input, "dispatch_cpu") : NULL;
    if (!value) return true;
    if (value->type != JSON_BOOL) { fdc_fail(reply, "dispatch_cpu must be boolean"); return false; }
    if (!json_get_bool(value)) return true;
    struct fdc_report r = {0};
#if defined(_WIN32)
    (void)now; (void)window_s; r.status = "unavailable";
#else
    char path[FDC_PATH]; struct stat chosen;
    if (!fdc_path(path)) r.status = "unavailable";
    else {
        int fd = fdc_select(path, now - window_s, now, &r, &chosen);
        if (fd >= 0) fdc_read(fd, &chosen, &r);
    }
#endif
    if (fdc_emit(&r, &reply->data)) return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "DISPATCH_REPORT_FAILED", "output", false, false, "cannot build dispatch CPU report", "allocation or numeric overflow");
    return false;
}
