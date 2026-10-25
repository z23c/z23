/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Compiler-API-free binding of a warm semantic-sensor TU to the tree: file digests, include probes, shadow candidates and main-file identity. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "clang_manifest_core.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* A warm session reparses a TU whose preamble (the headers) clang reuses
 * after checking each header's size and modification time only. These
 * checks are what the session trusts instead, all against the last manifest
 * it accepted for the TU: the exact bytes of every file it read (before the
 * reparse), the fresh probes of every include a repo file made (after it),
 * and the shadow candidates of every include no LOOKUPS record covers
 * (before it). Contract: docs/work/SEMANTIC_MANIFEST.md, "Warm session". */

struct cm_host_paths {
    const char *root;
    char resource[PATH_MAX];
    size_t resource_len;
};

struct cm_bind {
    const struct cm_host_paths *paths;
    char *why;
    size_t why_len;
    bool failed;
};

static bool cm_bind_fail(struct cm_bind *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static bool cm_bind_fail(struct cm_bind *b, const char *fmt, ...)
{
    va_list ap;
    if (b->failed)
        return false;
    b->failed = true;
    va_start(ap, fmt);
    (void)vsnprintf(b->why, b->why_len, fmt, ap);
    va_end(ap);
    return false;
}

/* The host path of a manifest path (the inverse of cm_spell_real for what
 * FILES and IDENTITY carry): "." is root, "@sys/x" is "/x", anything else
 * is root-relative. Texts are (pointer, length) as the enumerators give
 * them. False when out is too small. */
static bool cm_resource_suffix(const char *p, size_t n)
{
    if (n == 0)
        return true;
    if (n < 8 || memcmp(p, "/include", 8) != 0 ||
        (n > 8 && p[8] != '/'))
        return false;
    for (size_t at = 1; at < n;) {
        size_t end = at;
        while (end < n && p[end] != '/')
            end++;
        size_t len = end - at;
        if (len == 0 || (len == 1 && p[at] == '.') ||
            (len == 2 && p[at] == '.' && p[at + 1] == '.'))
            return false;
        at = end + 1;
    }
    return p[n - 1] != '/';
}

static bool cm_resource_contained(const struct cm_host_paths *paths,
                                   const char *resolved)
{
    size_t n = strlen(resolved);
    return n > paths->resource_len &&
           memcmp(resolved, paths->resource, paths->resource_len) == 0 &&
           cm_resource_suffix(resolved + paths->resource_len,
                              n - paths->resource_len);
}

/* Resolve each existing component so even a dangling or escaping symlink
 * cannot masquerade as a missing shadow directory. After the first genuinely
 * missing component, the already validated lexical suffix stays missing. */
static bool cm_resource_host(const struct cm_host_paths *paths,
                              const char *suffix, size_t n, char *out, size_t cap)
{
    char current[PATH_MAX], resolved[PATH_MAX];
    if (!paths->resource_len || !cm_resource_suffix(suffix, n))
        return false;
    (void)snprintf(current, sizeof(current), "%s", paths->resource);
    for (size_t at = 0; at < n;) {
        size_t end = at + 1;
        while (end < n && suffix[end] != '/')
            end++;
        size_t used = strlen(current);
        if (used + end - at >= sizeof(current))
            return false;
        memcpy(current + used, suffix + at, end - at);
        current[used + end - at] = '\0';
        struct stat st;
        if (lstat(current, &st) != 0) {
            if (errno != ENOENT)
                return false;
            int w = snprintf(out, cap, "%s%.*s", current, (int)(n - end), suffix + end);
            return w >= 0 && (size_t)w < cap;
        }
        if (realpath(current, resolved) == NULL || !cm_resource_contained(paths, resolved))
            return false;
        (void)snprintf(current, sizeof(current), "%s", resolved);
        at = end;
    }
    int w = snprintf(out, cap, "%s", current);
    return w >= 0 && (size_t)w < cap;
}

static bool cm_ordinary_host(const char *root, const char *p, size_t n,
                             char *out, size_t cap)
{
    int w;
    if (n == 4 && memcmp(p, "@sys", 4) == 0)
        w = snprintf(out, cap, "/");
    else if (n >= 5 && memcmp(p, "@sys/", 5) == 0)
        w = snprintf(out, cap, "/%.*s", (int)(n - 5), p + 5);
    else if (n == 1 && p[0] == '.')
        w = snprintf(out, cap, "%s", root);
    else
        w = snprintf(out, cap, "%s/%.*s", root, (int)n, p);
    return w >= 0 && (size_t)w < cap;
}

static bool cm_host_path(const struct cm_host_paths *paths,
                         const char *p, size_t n, char *out,
                         size_t cap)
{
    static const char resource[] = "@sys/clang-resource";
    const size_t prefix = sizeof(resource) - 1;
    if (n >= PATH_MAX || memchr(p, '\0', n) != NULL)
        return false;
    if (n >= prefix && memcmp(p, resource, prefix) == 0 &&
        (n == prefix || p[prefix] == '/')) {
        return cm_resource_host(paths, p + prefix, n - prefix, out, cap);
    }
    return cm_ordinary_host(paths->root, p, n, out, cap);
}

static bool cm_bind_file_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct cm_bind *b = ctx;
    char path[PATH_MAX * 2];
    uint8_t now[32];
    if (f->ntext < 1 || f->nnum < 1 || f->ndigest < 1)
        return cm_bind_fail(b, "a FILES record is malformed");
    if (f->num[0] == VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return true;
    if (!cm_host_path(b->paths, f->text[0], f->text_len[0], path,
                      sizeof(path)) ||
        !cm_stream_sha3(fopen(path, "rb"), now) ||
        memcmp(now, f->digest[0], 32) != 0)
        return cm_bind_fail(b, "file-changed %.*s", (int)f->text_len[0],
                            f->text[0]);
    return true;
}

/* ---- two manifests' FILES ---------------------------------------------------- */

/* One FILES record, as a view into its manifest's bytes. */
struct cm_fview {
    const char *path;
    size_t len;
    const uint8_t *digest;
    uint64_t origin;
};

struct cm_flist {
    struct cm_fview *v;
    size_t n, cap;
};

static bool cm_flist_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct cm_flist *l = ctx;
    if (f->ntext < 1 || f->nnum < 1 || f->ndigest < 1 ||
        !cm_grow((void **)&l->v, &l->cap, l->n, sizeof(*l->v)))
        return false;
    l->v[l->n++] = (struct cm_fview){.path = f->text[0], .len = f->text_len[0],
                                     .digest = f->digest[0],
                                     .origin = f->num[0]};
    return true;
}

static bool cm_flist(const uint8_t *m, size_t n, struct cm_flist *l)
{
    return vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_FILES,
                                        cm_flist_cb, l);
}

/* The record of `want`'s path in l, or NULL. */
static const struct cm_fview *cm_flist_find(const struct cm_flist *l,
                                            const struct cm_fview *want)
{
    for (size_t k = 0; k < l->n; k++) {
        if (l->v[k].len == want->len &&
            memcmp(l->v[k].path, want->path, want->len) == 0)
            return &l->v[k];
    }
    return NULL;
}

static bool cm_flists_agree(const struct cm_flist *a, const struct cm_flist *b,
                            struct cm_bind *bind)
{
    for (size_t k = 0; k < b->n; k++) {
        const struct cm_fview *hit;
        if (b->v[k].origin == VCS_SEMANTIC_ORIGIN_V1_MAIN)
            continue;
        hit = cm_flist_find(a, &b->v[k]);
        if (hit != NULL && memcmp(hit->digest, b->v[k].digest, 32) != 0)
            return cm_bind_fail(bind, "preamble-file-differs %.*s",
                                (int)b->v[k].len, b->v[k].path);
    }
    return true;
}

bool cm_warm_files_agree(const uint8_t *prev, size_t prev_len,
                         const uint8_t *next, size_t next_len, char *why,
                         size_t why_len)
{
    struct cm_bind bind = {.why = why, .why_len = why_len};
    struct cm_flist a = {0}, b = {0};
    bool ok = cm_flist(prev, prev_len, &a) && cm_flist(next, next_len, &b);
    if (!ok)
        (void)cm_bind_fail(&bind, "a manifest's FILES are unreadable");
    ok = ok && cm_flists_agree(&a, &b, &bind);
    free(a.v);
    free(b.v);
    return ok;
}

struct cm_main_digest {
    uint8_t *out;
    bool found;
};

static bool cm_main_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct cm_main_digest *d = ctx;
    if (f->nnum < 1 || f->ndigest < 1 ||
        f->num[0] != VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return true;
    memcpy(d->out, f->digest[0], 32);
    d->found = true;
    return true;
}

bool cm_warm_main_digest(const uint8_t *m, size_t n, uint8_t out[32])
{
    struct cm_main_digest d = {.out = out};
    return vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_FILES,
                                        cm_main_cb, &d) &&
           d.found;
}

/* ---- lookups: the warm manifest's fresh probes against the accepted ones ---- */

/* One LOOKUPS record body and the length of its key: includer, spelled,
 * form and kind, the leading fields of the record. */
struct cm_lrec {
    const uint8_t *raw;
    size_t len, key_len;
    uint8_t evidence; /* VCS_SEMANTIC_MISS_V1_*: NONE makes no negative claim */
};

struct cm_lset {
    struct cm_lrec *v;
    size_t n, cap;
    bool bad;
};

static bool cm_u32_at(const uint8_t *raw, size_t len, size_t *at, uint32_t *v)
{
    if (len - *at < 4)
        return false;
    *v = zcl_read_u32_le(raw + *at);
    *at += 4;
    return true;
}

/* Step over one length-prefixed text: u32 length, then its bytes. */
static bool cm_text_end(const uint8_t *raw, size_t len, size_t *at)
{
    uint32_t n;
    if (!cm_u32_at(raw, len, at, &n) || len - *at < n)
        return false;
    *at += (size_t)n;
    return true;
}

static bool cm_lset_cb(void *ctx, enum vcs_semantic_section_v1 section,
                       const struct vcs_semantic_fields_v1 *fields,
                       const uint8_t *raw, size_t raw_len)
{
    struct cm_lset *s = ctx;
    size_t at = 0, key;
    (void)fields;
    if (section != VCS_SEMANTIC_SECTION_V1_LOOKUPS)
        return true;
    /* includer, spelled, form, kind | hit, hit_slot, miss_evidence, ... */
    if (!cm_text_end(raw, raw_len, &at) || !cm_text_end(raw, raw_len, &at) ||
        raw_len - at < 2)
        return s->bad = true, false;
    key = at + 2;
    at = key;
    if (!cm_text_end(raw, raw_len, &at) || raw_len - at < 5 ||
        !cm_grow((void **)&s->v, &s->cap, s->n, sizeof(*s->v)))
        return s->bad = true, false;
    s->v[s->n++] = (struct cm_lrec){.raw = raw, .len = raw_len,
                                    .key_len = key, .evidence = raw[at + 4]};
    return true;
}

static bool cm_lset(const uint8_t *m, size_t n, struct cm_lset *s)
{
    return vcs_semantic_manifest_v1_each(m, n, cm_lset_cb, s) && !s->bad;
}

/* The spelled name of a LOOKUPS record, for a reason. */
static void cm_lrec_name(const struct cm_lrec *r, const char **name,
                         int *len)
{
    size_t at = 0, start;
    (void)cm_text_end(r->raw, r->len, &at);
    start = at;
    (void)cm_text_end(r->raw, r->len, &at);
    *name = (const char *)r->raw + start + 4;
    *len = (int)(at - start - 4);
}

/* A warm lookup is stale when the accepted manifest resolved the same
 * directive (same key) and none of its records for that key is this one:
 * the probes moved (a shadowing file now sits in a slot it saw absent, a
 * present slot went away) or the hit did. */
static bool cm_lrec_stale(const struct cm_lset *prev, const struct cm_lrec *r)
{
    bool keyed = false;
    for (size_t k = 0; k < prev->n; k++) {
        const struct cm_lrec *p = &prev->v[k];
        if (p->key_len != r->key_len || memcmp(p->raw, r->raw, r->key_len) != 0)
            continue;
        if (p->len == r->len && memcmp(p->raw, r->raw, r->len) == 0)
            return false;
        keyed = true;
    }
    return keyed;
}

static bool cm_lsets_agree(const struct cm_lset *prev, const struct cm_lset *next,
                           struct cm_bind *b)
{
    for (size_t k = 0; k < next->n; k++) {
        const struct cm_lrec *r = &next->v[k];
        const char *name;
        int len;
        if (!cm_lrec_stale(prev, r))
            continue;
        cm_lrec_name(r, &name, &len);
        return cm_bind_fail(b, "lookup-moved %.*s", len, name);
    }
    return true;
}

bool cm_warm_lookups_agree(const uint8_t *prev, size_t prev_len,
                           const uint8_t *next, size_t next_len, char *why,
                           size_t why_len)
{
    struct cm_bind b = {.why = why, .why_len = why_len};
    struct cm_lset a = {0}, c = {0};
    uint8_t ra[32], rc[32];
    bool ok = vcs_semantic_section_root_v1(prev, prev_len,
                                           VCS_SEMANTIC_SECTION_V1_IDENTITY,
                                           ra) &&
              vcs_semantic_section_root_v1(next, next_len,
                                           VCS_SEMANTIC_SECTION_V1_IDENTITY,
                                           rc);
    if (!ok)
        return cm_bind_fail(&b, "a manifest's IDENTITY is unreadable");
    if (memcmp(ra, rc, 32) != 0)
        return cm_bind_fail(&b, "identity-moved (the search list changed)");
    ok = cm_lset(prev, prev_len, &a) && cm_lset(next, next_len, &c);
    if (!ok)
        (void)cm_bind_fail(&b, "a manifest's LOOKUPS are unreadable");
    ok = ok && cm_lsets_agree(&a, &c, &b);
    free(a.v);
    free(c.v);
    return ok;
}

bool cm_warm_bound(const char *root, const uint8_t *m, size_t n, char *why,
                   size_t why_len)
{
    struct cm_host_paths paths = {.root = root};
    struct cm_bind b = {.paths = &paths, .why = why, .why_len = why_len};
    if (!cm_host_resource_root(paths.resource, &paths.resource_len))
        return cm_bind_fail(&b, "compiler-resource-directory-unavailable");
    struct cm_lset s = {0};
    bool ok = vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_FILES,
                                           cm_bind_file_cb, &b) &&
              cm_lset(m, n, &s);
    if (!ok)
        (void)cm_bind_fail(&b, "the previous manifest is unreadable");
    for (size_t k = 0; ok && k < s.n; k++) {
        const char *name;
        int len;
        if (s.v[k].evidence != VCS_SEMANTIC_MISS_V1_NONE)
            continue;
        cm_lrec_name(&s.v[k], &name, &len);
        ok = cm_bind_fail(&b, "lookup-unbound %.*s", len, name);
    }
    free(s.v);
    return ok;
}

/* ---- shadow candidates: includes no LOOKUPS record covers ------------------- */

/* A preamble keeps the resolution of every include made while it was built,
 * including the ones inside system headers, which LOOKUPS does not record.
 * The front end revalidates the files it read, never the slots it skipped,
 * so a header that appears in an earlier search dir under the same relative
 * name leaves the reparse stale while a cold parse would read the new file.
 * The candidates are: for every non-main file of the manifest, for every
 * search dir (quote, then angled) that holds it, every earlier search dir
 * that now holds the same relative name, or that no longer exists. The list
 * is compared, not judged: a TU is recreated when it differs from the list
 * taken right after the parse that built its preamble. */

struct cm_sdir {
    const char *dir; /* manifest spelling, not NUL-terminated */
    size_t len;
    char host[PATH_MAX];
    char **names; /* its entries, sorted, read on first use */
    size_t nnames, cap;
    int state;    /* 0 unread, 1 read, 2 gone */
    bool listed;  /* its "gone" line is written */
};

struct cm_shadow {
    const struct cm_host_paths *paths;
    struct cm_sdir *dirs;
    size_t ndirs, cap;
    char *out;
    size_t len, outcap;
    bool bad;
};

static bool cm_shadow_bad(struct cm_shadow *s)
{
    s->bad = true;
    return false;
}

/* One IDENTITY dir list: u32 count || text*. keep: record its dirs. */
static bool cm_shadow_list(struct cm_shadow *s, const uint8_t *raw, size_t len,
                           size_t *at, bool keep)
{
    uint32_t count;
    if (!cm_u32_at(raw, len, at, &count))
        return false;
    for (uint32_t k = 0; k < count; k++) {
        size_t start = *at;
        if (!cm_text_end(raw, len, at))
            return false;
        if (!keep)
            continue;
        if (!cm_grow((void **)&s->dirs, &s->cap, s->ndirs, sizeof(*s->dirs)))
            return false;
        s->dirs[s->ndirs++] = (struct cm_sdir){
            .dir = (const char *)raw + start + 4, .len = *at - start - 4};
    }
    return true;
}

/* IDENTITY: compiler, resource dir, target, main file, argv, quote dirs,
 * angled dirs, ignored dirs, env. */
static bool cm_shadow_ident_cb(void *ctx, enum vcs_semantic_section_v1 section,
                               const struct vcs_semantic_fields_v1 *fields,
                               const uint8_t *raw, size_t raw_len)
{
    struct cm_shadow *s = ctx;
    size_t at = 0;
    (void)fields;
    if (section != VCS_SEMANTIC_SECTION_V1_IDENTITY)
        return true;
    for (int k = 0; k < 4; k++)
        if (!cm_text_end(raw, raw_len, &at))
            return cm_shadow_bad(s);
    if (!cm_shadow_list(s, raw, raw_len, &at, false) ||
        !cm_shadow_list(s, raw, raw_len, &at, true) ||
        !cm_shadow_list(s, raw, raw_len, &at, true))
        return cm_shadow_bad(s);
    return true;
}

static int cm_name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static bool cm_sdir_add(struct cm_sdir *d, const char *name)
{
    char *dup;
    if (!cm_grow((void **)&d->names, &d->cap, d->nnames, sizeof(*d->names)))
        return false;
    dup = cm_strdup(name);
    if (dup == NULL)
        return false; /* never store a NULL name: cm_sdir_read qsorts */
    d->names[d->nnames++] = dup;
    return true;
}

static bool cm_sdir_read(struct cm_shadow *s, struct cm_sdir *d)
{
    DIR *dp;
    struct dirent *e;
    bool ok = true;
    if (d->state != 0)
        return true;
    if (!cm_host_path(s->paths, d->dir, d->len, d->host, sizeof(d->host)))
        return false;
    dp = opendir(d->host);
    d->state = dp == NULL ? 2 : 1;
    if (dp == NULL)
        return errno == ENOENT || errno == ENOTDIR;
    errno = 0;
    while (ok && (e = readdir(dp)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            ok = cm_sdir_add(d, e->d_name);
    }
    ok = ok && errno == 0;
    if (closedir(dp) != 0)
        ok = false;
    if (d->nnames > 1)
        qsort(d->names, d->nnames, sizeof(*d->names), cm_name_cmp);
    return ok;
}

static bool cm_shadow_line(struct cm_shadow *s, const char *tag,
                           const struct cm_sdir *d, const char *name,
                           size_t name_len)
{
    size_t need = strlen(tag) + d->len + 1 + name_len + 1;
    while (s->outcap - s->len < need + 1) {
        size_t next = s->outcap ? s->outcap * 2 : 256;
        char *grown = zcl_realloc(s->out, next, "clang_manifest.shadows");
        if (grown == NULL)
            return false;
        s->out = grown;
        s->outcap = next;
    }
    s->len += (size_t)snprintf(s->out + s->len, s->outcap - s->len,
                               "%s%.*s/%.*s\n", tag, (int)d->len, d->dir,
                               (int)name_len, name);
    return true;
}

/* Does search dir d now hold `name` (a relative path)? A present line when
 * it does, a gone line (once) when d itself no longer exists. */
static bool cm_shadow_probe(struct cm_shadow *s, struct cm_sdir *d,
                            const char *name, size_t len)
{
    const char *slash = memchr(name, '/', len);
    size_t first = slash != NULL ? (size_t)(slash - name) : len;
    char key[256], path[PATH_MAX * 2];
    const char *pkey = key;
    struct stat st;
    if (!cm_sdir_read(s, d))
        return false;
    if (d->state == 2) {
        if (d->listed)
            return true;
        d->listed = true;
        return cm_shadow_line(s, "gone ", d, "", 0);
    }
    if (first >= sizeof(key))
        return true;
    memcpy(key, name, first);
    key[first] = '\0';
    if (bsearch(&pkey, d->names, d->nnames, sizeof(*d->names),
                cm_name_cmp) == NULL)
        return true;
    if (slash != NULL) {
        int w = snprintf(path, sizeof(path), "%s/%.*s", d->host, (int)len,
                         name);
        if (w < 0 || (size_t)w >= sizeof(path))
            return false;
        if (stat(path, &st) != 0 && (errno == ENOENT || errno == ENOTDIR))
            return true;
    }
    return cm_shadow_line(s, "", d, name, len);
}

/* Where path lies under search dir d, the offset of its relative name. */
static bool cm_shadow_under(const struct cm_sdir *d, const char *path,
                            size_t len, size_t *off)
{
    if (d->len == 1 && d->dir[0] == '.') {
        *off = 0;
        return !(len >= 4 && memcmp(path, "@sys", 4) == 0);
    }
    if (len <= d->len + 1 || memcmp(path, d->dir, d->len) != 0 ||
        path[d->len] != '/')
        return false;
    *off = d->len + 1;
    return true;
}

static bool cm_shadow_file_cb(void *ctx, const struct vcs_semantic_fields_v1 *f)
{
    struct cm_shadow *s = ctx;
    if (f->ntext < 1 || f->nnum < 1)
        return cm_shadow_bad(s);
    if (f->num[0] == VCS_SEMANTIC_ORIGIN_V1_MAIN)
        return true;
    for (size_t i = 0; i < s->ndirs; i++) {
        size_t off;
        if (!cm_shadow_under(&s->dirs[i], f->text[0], f->text_len[0], &off))
            continue;
        for (size_t j = 0; j < i; j++) {
            if (!cm_shadow_probe(s, &s->dirs[j], f->text[0] + off,
                                 f->text_len[0] - off))
                return cm_shadow_bad(s);
        }
    }
    return true;
}

/* An empty list is still a list: the buffer exists and is NUL-terminated. */
static bool cm_shadow_line_end(struct cm_shadow *s)
{
    if (s->out != NULL)
        return true;
    s->out = zcl_malloc(1, "clang_manifest.shadows");
    if (s->out == NULL)
        return false;
    s->out[0] = '\0';
    s->outcap = 1;
    return true;
}

static void cm_shadow_free(struct cm_shadow *s)
{
    for (size_t k = 0; k < s->ndirs; k++) {
        for (size_t n = 0; n < s->dirs[k].nnames; n++)
            free(s->dirs[k].names[n]);
        free(s->dirs[k].names);
    }
    free(s->dirs);
}

bool cm_warm_shadows(const char *root, const uint8_t *m, size_t n, char **out,
                     size_t *out_len)
{
    struct cm_host_paths paths = {.root = root};
    if (!cm_host_resource_root(paths.resource, &paths.resource_len))
        return false;
    struct cm_shadow s = {.paths = &paths};
    bool ok = vcs_semantic_manifest_v1_each(m, n, cm_shadow_ident_cb, &s) &&
              !s.bad &&
              vcs_semantic_section_v1_each(m, n, VCS_SEMANTIC_SECTION_V1_FILES,
                                           cm_shadow_file_cb, &s) &&
              !s.bad && cm_shadow_line_end(&s);
    cm_shadow_free(&s);
    if (!ok) {
        free(s.out);
        return false;
    }
    *out = s.out;
    *out_len = s.len;
    return true;
}

/* The first line of a (newline-terminated lines) missing from b, or NULL. */
static const char *cm_line_missing(const char *a, size_t an, const char *b,
                                   size_t bn, size_t *len)
{
    for (size_t at = 0; at < an;) {
        const char *nl = memchr(a + at, '\n', an - at);
        size_t n = nl != NULL ? (size_t)(nl - (a + at)) + 1 : an - at;
        bool found = false;
        for (size_t bt = 0; bt < bn && !found;) {
            const char *bl = memchr(b + bt, '\n', bn - bt);
            size_t m = bl != NULL ? (size_t)(bl - (b + bt)) + 1 : bn - bt;
            found = m == n && memcmp(a + at, b + bt, n) == 0;
            bt += m;
        }
        if (!found) {
            *len = n > 0 && a[at + n - 1] == '\n' ? n - 1 : n;
            return a + at;
        }
        at += n;
    }
    return NULL;
}

bool cm_warm_shadows_same(const char *then, size_t then_len, const char *now,
                          size_t now_len, char *why, size_t why_len)
{
    const char *line;
    size_t len = 0;
    if (then_len == now_len && memcmp(then, now, now_len) == 0)
        return true;
    line = cm_line_missing(now, now_len, then, then_len, &len);
    if (line != NULL) {
        (void)snprintf(why, why_len, "include-shadow-appeared %.*s", (int)len,
                       line);
        return false;
    }
    line = cm_line_missing(then, then_len, now, now_len, &len);
    if (line != NULL)
        (void)snprintf(why, why_len, "include-shadow-vanished %.*s",
                       (int)len, line);
    else
        (void)snprintf(why, why_len, "include-shadows-reordered");
    return false;
}
