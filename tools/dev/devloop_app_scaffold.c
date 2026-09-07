/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.app.scaffold — materialize the conventional App resource slice.
 *
 * The whole point of the command is that it is safe to run on a checkout you
 * care about, so it is fail-closed in both directions:
 *
 *   PLAN FIRST, WRITE SECOND. Every target is classified in a read-only pass
 *   before any byte is written. If ANY target already exists with different
 *   content, the command refuses with `refused: <path> exists with different
 *   content` and writes nothing at all — never a half-materialised slice.
 *
 *   IDEMPOTENT. A target whose bytes already match is left untouched and
 *   reported unchanged, so a second run of the same command reports
 *   `0 written, N unchanged` and leaves the tree byte-identical.
 *
 *   ATOMIC PER FILE. Each write lands as a temp file in the target's own
 *   directory followed by rename(), so a reader never observes a partial
 *   file and an interrupted run leaves no truncated source behind.
 *
 * The slice itself is never described here: tools/dev/devloop_app_slice.c
 * owns the templates, and this file only decides where the bytes go. No
 * process spawn, no shell.
 */

#include "devloop.h"

#include "base/safe_alloc.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum scaffold_action {
    SCAFFOLD_WRITE = 0,
    SCAFFOLD_APPEND = 1,
    SCAFFOLD_UNCHANGED = 2
};

struct scaffold_plan {
    enum scaffold_action action[ZCL_DEVLOOP_APP_SLICE_MAX_FILES];
    /* Full desired content of an APPEND target (existing bytes + the row). */
    char *merged[ZCL_DEVLOOP_APP_SLICE_MAX_FILES];
    size_t merged_len[ZCL_DEVLOOP_APP_SLICE_MAX_FILES];
    char refusal[ZCL_DEVLOOP_APP_SLICE_PATH_MAX + 96];
    size_t written;
    size_t unchanged;
};

/* Read the whole file at path. Returns NULL when it does not exist or cannot
 * be read; *len_out is the byte count on success. Caller frees. */
static char *scaffold_read(const char *path, size_t *len_out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    for (;;) {
        if (len + 4096u + 1u > cap) {
            size_t next = cap ? cap * 2u : 8192u;
            char *grown = realloc(buf, next);
            if (!grown) {
                free(buf);
                (void)fclose(fp);
                return NULL;
            }
            buf = grown;
            cap = next;
        }
        size_t n = fread(buf + len, 1, 4096u, fp);
        len += n;
        if (n < 4096u)
            break;
    }
    bool bad = ferror(fp) != 0;
    (void)fclose(fp);
    if (bad) {
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    *len_out = len;
    return buf;
}

/* True when haystack contains the exact line `row` (which ends in \n). */
static bool scaffold_has_row(const char *hay, size_t hay_len, const char *row)
{
    size_t row_len = strlen(row);
    if (row_len == 0 || hay_len < row_len)
        return false;
    for (size_t i = 0; i + row_len <= hay_len; i++) {
        if ((i == 0 || hay[i - 1] == '\n') &&
            memcmp(hay + i, row, row_len) == 0)
            return true;
    }
    return false;
}

static void scaffold_refuse(struct scaffold_plan *p, const char *why,
                            const char *path)
{
    if (p->refusal[0])
        return;
    (void)snprintf(p->refusal, sizeof(p->refusal), "refused: %s %s", path, why);
}

/* Classify one CREATE target: absent -> write, byte-identical -> unchanged,
 * present and different -> refusal. */
static void scaffold_classify_create(struct scaffold_plan *p, size_t i,
                                     const struct zcl_devloop_app_slice_file *f,
                                     const char *abs)
{
    size_t have_len = 0;
    char *have = scaffold_read(abs, &have_len);
    if (!have) {
        p->action[i] = SCAFFOLD_WRITE;
        return;
    }
    bool same = have_len == f->body_len &&
                memcmp(have, f->body, f->body_len) == 0;
    free(have);
    if (same) {
        p->action[i] = SCAFFOLD_UNCHANGED;
        return;
    }
    scaffold_refuse(p, "exists with different content", f->path);
}

/* Classify one ROW target: the registry must already exist (the scaffold
 * never invents a registry), and the row is appended only when absent. */
static void scaffold_classify_row(struct scaffold_plan *p, size_t i,
                                  const struct zcl_devloop_app_slice_file *f,
                                  const char *abs)
{
    size_t have_len = 0;
    char *have = scaffold_read(abs, &have_len);
    if (!have) {
        scaffold_refuse(p, "is missing; this registry is not created for you",
                        f->path);
        return;
    }
    if (scaffold_has_row(have, have_len, f->body)) {
        free(have);
        p->action[i] = SCAFFOLD_UNCHANGED;
        return;
    }
    bool needs_nl = have_len > 0 && have[have_len - 1] != '\n';
    size_t total = have_len + (needs_nl ? 1u : 0u) + f->body_len;
    char *merged = zcl_calloc(total + 1u, 1, "dev.app.scaffold registry row");
    if (!merged) {
        free(have);
        scaffold_refuse(p, "could not be staged for append", f->path);
        return;
    }
    memcpy(merged, have, have_len);
    free(have);
    if (needs_nl)
        merged[have_len] = '\n';
    memcpy(merged + have_len + (needs_nl ? 1u : 0u), f->body, f->body_len);
    p->merged[i] = merged;
    p->merged_len[i] = total;
    p->action[i] = SCAFFOLD_APPEND;
}

/* Absolute path of one slice entry inside the resolved checkout root. */
static bool scaffold_abs(const struct zcl_devloop_app_slice *s, size_t i,
                         char *out, size_t out_sz)
{
    int n = snprintf(out, out_sz, "%s/%s", s->root, s->files[i].path);
    return n > 0 && (size_t)n < out_sz;
}

static void scaffold_classify(const struct zcl_devloop_app_slice *s,
                              struct scaffold_plan *p)
{
    for (size_t i = 0; i < s->file_count && !p->refusal[0]; i++) {
        char abs[ZCL_DEVLOOP_PATH_MAX];
        if (!scaffold_abs(s, i, abs, sizeof(abs))) {
            scaffold_refuse(p, "does not fit the checkout path bound",
                            s->files[i].path);
            return;
        }
        if (s->files[i].kind == ZCL_DEVLOOP_APP_SLICE_ROW)
            scaffold_classify_row(p, i, &s->files[i], abs);
        else
            scaffold_classify_create(p, i, &s->files[i], abs);
    }
}

/* Write `len` bytes to `abs` atomically: a temp file in the SAME directory
 * (so rename cannot cross a filesystem), then rename over the target. */
static bool scaffold_write_atomic(const char *abs, const char *bytes,
                                  size_t len)
{
    char tmp[ZCL_DEVLOOP_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.z23scaffold.tmp", abs);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return false;
    FILE *fp = fopen(tmp, "wb");
    if (!fp)
        return false;
    bool ok = len == 0 || fwrite(bytes, 1, len, fp) == len;
    ok = fflush(fp) == 0 && ok;
    ok = fclose(fp) == 0 && ok;
    if (!ok || rename(tmp, abs) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

/* Make sure the target's directory chain exists before the temp file is
 * opened. A conventional slice lands in directories the checkout already
 * has; a brand new App context is the exception this covers. Each component
 * is created in turn — platform_directory_ensure() is one level deep and
 * refuses a symlink, so a planted link cannot redirect the write. */
static bool scaffold_ensure_parent(const char *abs)
{
    char dir[ZCL_DEVLOOP_PATH_MAX];
    size_t n = strnlen(abs, sizeof(dir));
    if (n >= sizeof(dir))
        return false;
    while (n > 0 && abs[n - 1] != '/')
        n--;
    if (n <= 1)
        return true;
    memcpy(dir, abs, n - 1);
    dir[n - 1] = 0;
    /* Walk forward from the checkout root, which already exists, creating
     * each remaining component. Start past the leading '/' so an absolute
     * path's root is never a create target. */
    for (size_t i = 1; dir[i]; i++) {
        if (dir[i] != '/')
            continue;
        dir[i] = 0;
        bool ok = platform_directory_ensure(dir, 0755);
        dir[i] = '/';
        if (!ok)
            return false;
    }
    return platform_directory_ensure(dir, 0755);
}

static bool scaffold_apply(const struct zcl_devloop_app_slice *s,
                           struct scaffold_plan *p)
{
    for (size_t i = 0; i < s->file_count; i++) {
        if (p->action[i] == SCAFFOLD_UNCHANGED) {
            p->unchanged++;
            continue;
        }
        char abs[ZCL_DEVLOOP_PATH_MAX];
        const char *bytes = p->action[i] == SCAFFOLD_APPEND
                                ? p->merged[i] : s->files[i].body;
        size_t len = p->action[i] == SCAFFOLD_APPEND
                         ? p->merged_len[i] : s->files[i].body_len;
        if (!scaffold_abs(s, i, abs, sizeof(abs)) ||
            !scaffold_ensure_parent(abs) ||
            !scaffold_write_atomic(abs, bytes, len)) {
            scaffold_refuse(p, "could not be written", s->files[i].path);
            return false;
        }
        p->written++;
    }
    return true;
}

static void scaffold_plan_free(struct scaffold_plan *p)
{
    for (size_t i = 0; i < ZCL_DEVLOOP_APP_SLICE_MAX_FILES; i++)
        free(p->merged[i]);
}

/* ── JSON reply ────────────────────────────────────────────────────────── */

static const char *scaffold_action_name(enum scaffold_action a)
{
    switch (a) {
    case SCAFFOLD_WRITE:     return "written";
    case SCAFFOLD_APPEND:    return "appended";
    case SCAFFOLD_UNCHANGED: return "unchanged";
    }
    return "unchanged";
}

static size_t scaffold_render(const struct zcl_devloop_app_slice *s,
                              const struct scaffold_plan *p, char *out,
                              size_t out_sz)
{
    size_t len = 0;
    int n = snprintf(out, out_sz,
                     "{\"schema\":\"zcl.dev_app_scaffold.v1\",\"status\":"
                     "\"%s\",\"app_id\":\"%s\",\"resource\":\"%s\","
                     "\"test_group\":\"%s\",\"written\":%zu,\"unchanged\":%zu,"
                     "\"refusal\":\"%s\",\"files\":[",
                     p->refusal[0] ? "refused" : "materialized", s->app_id,
                     s->resource, s->group, p->written, p->unchanged,
                     p->refusal);
    if (n <= 0 || (size_t)n >= out_sz)
        return 0;
    len = (size_t)n;
    for (size_t i = 0; i < s->file_count; i++) {
        n = snprintf(out + len, out_sz - len, "%s{\"path\":\"%s\","
                     "\"action\":\"%s\"}", i ? "," : "", s->files[i].path,
                     p->refusal[0] ? "not_written"
                                   : scaffold_action_name(p->action[i]));
        if (n <= 0 || (size_t)n >= out_sz - len)
            return 0;
        len += (size_t)n;
    }
    n = snprintf(out + len, out_sz - len, "],\"agent_next_action\":\"%s\"}",
                 p->refusal[0]
                     ? "resolve the named file, then run the scaffold again"
                     : "make -s -j8 dev-bin, then make t-fast ONLY=<test_group>");
    if (n <= 0 || (size_t)n >= out_sz - len)
        return 0;
    return len + (size_t)n;
}

size_t zcl_devloop_app_scaffold_json(const char *repo_root, const char *app_id,
                                     const char *resource, char *out,
                                     size_t out_sz)
{
    struct zcl_devloop_app_slice *s =
        zcl_devloop_app_slice_build(repo_root, app_id, resource);
    if (!s)
        return 0;
    struct scaffold_plan p;
    memset(&p, 0, sizeof(p));
    scaffold_classify(s, &p);
    if (!p.refusal[0] && !scaffold_apply(s, &p)) {
        /* A write that fails mid-slice keeps the files it already landed —
         * they are byte-identical to the plan, so re-running finishes the
         * job. The refusal names the file that stopped it. */
        p.written = 0;
    }
    size_t n = scaffold_render(s, &p, out, out_sz);
    scaffold_plan_free(&p);
    zcl_devloop_app_slice_free(s);
    return n;
}

int zcl_devloop_app_scaffold(const char *repo_root, const char *app_id,
                             const char *resource)
{
    char body[8192];
    size_t n = zcl_devloop_app_scaffold_json(repo_root, app_id, resource, body,
                                             sizeof(body));
    if (n == 0) {
        (void)fprintf(stderr,
                      "[devloop] app scaffold: invalid App, resource, or "
                      "checkout root\n");
        return 2;
    }
    (void)printf("%s\n", body);
    return strstr(body, "\"status\":\"materialized\"") ? 0 : 1;
}
