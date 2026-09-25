/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl.action_preimage.v2 derivation for one real compile. See
 * devloop_action_root.h for the negative-lookup rule. Everything recorded
 * is a canonical token: repo-relative paths, "@sys/..." for system files,
 * "@root" / "@out/..." inside argv. Anything that cannot be spelled that
 * way refuses the derivation instead of leaking a host path into a root.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "devloop_action_root.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/file_metadata.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define AR_DEPFILE_MAX (1024u * 1024u)
#define AR_GENERATED_MAX (1024u * 1024u)
#define AR_TEXT_MAX 4096u
#define AR_MEMO_SLOTS 8192u
#define AR_MEMO_PROBE 16u
/* A file modified this recently may change again within the same mtime
 * tick, so its digest is never memoized ("racily clean"). */
#define AR_MEMO_SETTLE_S 3

static void ar_why(char *why, size_t len, const char *what, const char *arg)
{
    if (why && len && !why[0])
        (void)snprintf(why, len, "%s%s%.180s", what, arg ? ": " : "",
                       arg ? arg : "");
}

/* ---- owned string lists ------------------------------------------------ */

struct ar_list {
    char **v;
    size_t n;
    size_t cap;
};

static bool ar_list_push(struct ar_list *l, const char *s)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        char **grown = zcl_realloc(l->v, cap * sizeof(char *),
                                   "action root string list");
        if (!grown)
            return false;
        l->v = grown;
        l->cap = cap;
    }
    char *copy = zcl_strdup(s, "action root string");
    if (!copy)
        return false;
    l->v[l->n++] = copy;
    return true;
}

static bool ar_list_has(const struct ar_list *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0)
            return true;
    return false;
}

static void ar_list_free(struct ar_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

static int ar_str_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Sort and drop exact duplicates in place. */
static void ar_list_sort_unique(struct ar_list *l)
{
    if (l->n < 2)
        return;
    qsort(l->v, l->n, sizeof(char *), ar_str_cmp);
    size_t w = 1;
    for (size_t i = 1; i < l->n; i++) {
        if (strcmp(l->v[w - 1], l->v[i]) == 0)
            free(l->v[i]);
        else
            l->v[w++] = l->v[i];
    }
    l->n = w;
}

/* ---- path tokens ------------------------------------------------------- */

/* Lexically collapse "", "." and ".." segments. Absolute stays absolute;
 * a ".." that would climb above the start is refused. */
static bool ar_lex_normalize(const char *in, char *out, size_t cap)
{
    bool absolute = in[0] == '/';
    size_t used = 0;
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n == 0 || (n == 1 && p[0] == '.')) {
            p += n;
            continue;
        }
        if (n == 2 && p[0] == '.' && p[1] == '.') {
            if (used == 0) return false;
            while (used > 0 && out[used - 1] != '/') used--;
            if (used > 0) used--;
            p += n;
            continue;
        }
        if (used + n + 2 >= cap) return false;
        if (used > 0 || absolute) out[used++] = '/';
        memcpy(out + used, p, n);
        used += n;
        p += n;
    }
    if (used == 0 && absolute) out[used++] = '/';
    out[used] = '\0';
    return true;
}

/* System locations whose absolute spelling is the same on every host of a
 * toolchain; anything else outside the checkout is refused. */
static bool ar_system_path(const char *abs)
{
    static const char *const prefixes[] = {
        "/usr/", "/opt/", "/lib/", "/lib64/", "/Library/",
        "/Applications/", "/System/", "/nix/store/",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (strncmp(abs, prefixes[i], strlen(prefixes[i])) == 0)
            return true;
    return false;
}

static bool ar_delim(char c)
{
    return c == '\0' || strchr("/=,:; \"'", c) != NULL;
}

struct ar_ctx {
    const struct zcl_action_root_request *req;
    size_t root_len;
    char *why;
    size_t why_len;
};

/* Map a host spelling (absolute, or relative to the root) to its canonical
 * token and the filesystem path to read. */
static bool ar_tokenize(const struct ar_ctx *c, const char *raw,
                        char token[PATH_MAX], char fs[PATH_MAX])
{
    char norm[PATH_MAX];
    const char *root = c->req->root;
    int n = -1;
    if (!raw || !raw[0] || !ar_lex_normalize(raw, norm, sizeof(norm)))
        return false;
    if (norm[0] != '/') {
        (void)snprintf(token, PATH_MAX, "%s", norm[0] ? norm : ".");
        n = snprintf(fs, PATH_MAX, "%s%s%s", root, norm[0] ? "/" : "", norm);
    } else if (strncmp(norm, root, c->root_len) == 0 &&
               (norm[c->root_len] == '\0' || norm[c->root_len] == '/')) {
        const char *rel = norm + c->root_len;
        (void)snprintf(token, PATH_MAX, "%s", rel[0] ? rel + 1 : ".");
        n = snprintf(fs, PATH_MAX, "%s", norm);
    } else if (ar_system_path(norm)) {
        n = snprintf(token, PATH_MAX, "@sys%s", norm);
        if (n > 0 && n < PATH_MAX)
            n = snprintf(fs, PATH_MAX, "%s", norm);
    }
    return n > 0 && n < PATH_MAX &&
           vcs_action_v2_path_canonical(token, true);
}

/* Rewrite host spellings inside one argv/env text: the checkout root
 * becomes "@root", a system prefix gains "@sys". The canonical check that
 * follows refuses whatever absolute spelling is left. */
static bool ar_rewrite(const struct ar_ctx *c, const char *in,
                       char *out, size_t cap)
{
    size_t o = 0;
    const char *root = c->req->root;
    for (size_t i = 0; in[i];) {
        bool at_path = in[i] == '/' && vcs_action_v2_path_boundary(in, i);
        const char *emit = NULL;
        size_t skip = 0;
        if (at_path && strncmp(in + i, root, c->root_len) == 0 &&
            ar_delim(in[i + c->root_len])) {
            emit = "@root";
            skip = c->root_len;
        } else if (at_path && ar_system_path(in + i)) {
            emit = "@sys";
        }
        size_t emit_n = emit ? strlen(emit) : 0;
        if (o + emit_n + 2 > cap)
            return false;
        memcpy(out + o, emit ? emit : "", emit_n);
        o += emit_n;
        if (skip) {
            i += skip;
            continue;
        }
        out[o++] = in[i++];
    }
    out[o] = '\0';
    return true;
}

/* ---- content digests --------------------------------------------------- */

struct ar_memo {
    char *path;
    uint64_t dev, ino, size;
    int64_t mtime_s, mtime_ns, ctime_s, ctime_ns;
    uint8_t sha3[32];
};

static pthread_mutex_t g_memo_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ar_memo g_memo[AR_MEMO_SLOTS];

static void ar_memo_key(const struct stat *st, struct ar_memo *m)
{
    m->dev = (uint64_t)st->st_dev;
    m->ino = (uint64_t)st->st_ino;
    m->size = (uint64_t)st->st_size;
#if defined(_WIN32)
    m->mtime_s = (int64_t)st->st_mtime;
    m->mtime_ns = 0;
    m->ctime_s = (int64_t)st->st_ctime;
    m->ctime_ns = 0;
#elif defined(__APPLE__)
    m->mtime_s = (int64_t)st->st_mtimespec.tv_sec;
    m->mtime_ns = (int64_t)st->st_mtimespec.tv_nsec;
    m->ctime_s = (int64_t)st->st_ctimespec.tv_sec;
    m->ctime_ns = (int64_t)st->st_ctimespec.tv_nsec;
#else
    m->mtime_s = (int64_t)st->st_mtim.tv_sec;
    m->mtime_ns = (int64_t)st->st_mtim.tv_nsec;
    m->ctime_s = (int64_t)st->st_ctim.tv_sec;
    m->ctime_ns = (int64_t)st->st_ctim.tv_nsec;
#endif
}

static bool ar_memo_same(const struct ar_memo *a, const struct ar_memo *b)
{
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
           a->mtime_s == b->mtime_s && a->mtime_ns == b->mtime_ns &&
           a->ctime_s == b->ctime_s && a->ctime_ns == b->ctime_ns;
}

static size_t ar_memo_slot(const char *path)
{
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        h = (h ^ *p) * 1099511628211ULL;
    return (size_t)(h % AR_MEMO_SLOTS);
}

static bool ar_memo_lookup(const char *path, const struct ar_memo *key,
                           uint8_t sha3[32])
{
    size_t base = ar_memo_slot(path);
    bool hit = false;
    pthread_mutex_lock(&g_memo_mu);
    for (size_t k = 0; k < AR_MEMO_PROBE && !hit; k++) {
        const struct ar_memo *m = &g_memo[(base + k) % AR_MEMO_SLOTS];
        hit = m->path && strcmp(m->path, path) == 0 && ar_memo_same(m, key);
        if (hit)
            memcpy(sha3, m->sha3, 32);
    }
    pthread_mutex_unlock(&g_memo_mu);
    return hit;
}

/* Reuse the path's slot, else a free one, else the last probed slot. */
static void ar_memo_store(const char *path, const struct ar_memo *key,
                          const uint8_t sha3[32])
{
    size_t base = ar_memo_slot(path);
    pthread_mutex_lock(&g_memo_mu);
    struct ar_memo *slot = NULL;
    for (size_t k = 0; k < AR_MEMO_PROBE && !slot; k++) {
        struct ar_memo *m = &g_memo[(base + k) % AR_MEMO_SLOTS];
        if (!m->path || strcmp(m->path, path) == 0 || k + 1 == AR_MEMO_PROBE)
            slot = m;
    }
    char *copy = zcl_strdup(path, "action root memo path");
    if (slot && copy) {
        free(slot->path);
        *slot = *key;
        slot->path = copy;
        memcpy(slot->sha3, sha3, 32);
    } else {
        free(copy);
    }
    pthread_mutex_unlock(&g_memo_mu);
}

static bool ar_sha3_stream(FILE *f, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    unsigned char buf[65536];
    size_t n;
    sha3_256_init(&sha);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&sha, buf, n);
    if (ferror(f))
        return false;
    sha3_256_finalize(&sha, out);
    return true;
}

/* SHA3-256 of a regular file's bytes, memoized by (dev, ino, size, mtime,
 * ctime) once the file has settled. */
static bool ar_sha3_file(const char *path, uint8_t out[32])
{
    struct stat before, after;
    struct ar_memo key = {0};
    if (stat(path, &before) != 0 || !S_ISREG(before.st_mode))
        return false;
    ar_memo_key(&before, &key);
    if (ar_memo_lookup(path, &key, out))
        return true;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = ar_sha3_stream(f, out);
    fclose(f);
    struct ar_memo again = {0};
    if (!ok || stat(path, &after) != 0)
        return false;
    ar_memo_key(&after, &again);
    if (!ar_memo_same(&key, &again))
        return false; /* changed while hashing: no stable identity */
    if ((int64_t)time(NULL) - key.mtime_s >= AR_MEMO_SETTLE_S)
        ar_memo_store(path, &key, out);
    return true;
}

static char *ar_read_all(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *text = zcl_malloc(max + 1, "action root file read");
    size_t n = text ? fread(text, 1, max + 1, f) : 0;
    bool ok = text && !ferror(f) && n <= max;
    fclose(f);
    if (!ok) {
        free(text);
        return NULL;
    }
    text[n] = '\0';
    *len = n;
    return text;
}

/* Generated inputs may spell the checkout root (a unity wrapper includes
 * members by absolute path); hash them with the root rewritten to @root so
 * the same generation in another worktree has the same identity. */
static bool ar_sha3_generated(const struct ar_ctx *c, const char *path,
                              uint8_t out[32])
{
    size_t len = 0;
    char *text = ar_read_all(path, AR_GENERATED_MAX, &len);
    if (!text || memchr(text, '\0', len)) {
        free(text);
        return false;
    }
    size_t cap = 2 * len + 64;
    char *norm = zcl_malloc(cap, "action root generated text");
    bool ok = norm && ar_rewrite(c, text, norm, cap);
    if (ok)
        zcl_sha3_256((const unsigned char *)norm, strlen(norm), out);
    free(norm);
    free(text);
    return ok;
}

/* ---- dependency closure ------------------------------------------------ */

struct ar_dep {
    char token[PATH_MAX];
    char fs[PATH_MAX];
    bool generated;
    uint8_t sha3[32];
};

struct ar_state {
    struct ar_ctx c;
    struct ar_dep *deps;
    size_t dep_n;
    struct ar_list search;       /* tokens, compiler order */
    struct ar_list search_fs;
    struct ar_list includers;    /* sorted tokens */
    struct ar_list includers_fs;
    struct vcs_action_probe_v2 *names;
    size_t name_n, name_cap;
    struct vcs_action_present_v2 *present;
    size_t present_n, present_cap;
    struct ar_list argv;
    struct ar_list env;
    uint32_t probes;
};

static bool ar_dep_add(struct ar_state *s, const char *raw)
{
    if (strstr(raw, "build/hotswap-fast/.resident-"))
        return true; /* bounded temporary wrapper, never source authority */
    if (s->dep_n >= ZCL_ACTION_ROOT_MAX_DEPS) {
        ar_why(s->c.why, s->c.why_len, "dependency closure too large", NULL);
        return false;
    }
    struct ar_dep *d = &s->deps[s->dep_n];
    if (!ar_tokenize(&s->c, raw, d->token, d->fs) ||
        strcmp(d->token, ".") == 0) {
        ar_why(s->c.why, s->c.why_len,
               "dependency has no canonical spelling", raw);
        return false;
    }
    d->generated = strncmp(d->token, "build/", 6) == 0;
    bool hashed = d->generated ? ar_sha3_generated(&s->c, d->fs, d->sha3)
                               : ar_sha3_file(d->fs, d->sha3);
    if (!hashed) {
        ar_why(s->c.why, s->c.why_len, "dependency could not be hashed",
               d->token);
        return false;
    }
    s->dep_n++;
    return true;
}

/* Fold "\\\n" continuations, then walk the first rule's prerequisites. */
static bool ar_depfile_load(struct ar_state *s)
{
    size_t len = 0;
    char *text = ar_read_all(s->c.req->depfile, AR_DEPFILE_MAX, &len);
    for (size_t i = 0; text && i + 1 < len; i++)
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    char *colon = text ? strchr(text, ':') : NULL;
    while (colon && colon[1] && !strchr(" \t\r\n", colon[1]))
        colon = strchr(colon + 1, ':');
    if (!colon) {
        free(text);
        ar_why(s->c.why, s->c.why_len, "dependency file absent or malformed",
               NULL);
        return false;
    }
    bool ok = true;
    char *save = NULL;
    for (char *tok = strtok_r(colon + 1, " \t\r\n", &save); ok && tok;
         tok = strtok_r(NULL, " \t\r\n", &save)) {
        size_t n = strlen(tok);
        if (tok[n - 1] == ':' || tok[n - 1] == '\\')
            break; /* a -MP phony rule or an escaped space: end of closure */
        ok = ar_dep_add(s, tok);
    }
    free(text);
    if (ok && s->dep_n == 0) {
        ar_why(s->c.why, s->c.why_len, "dependency closure is empty", NULL);
        ok = false;
    }
    return ok;
}

/* ---- include search order ---------------------------------------------- */

enum { AR_Q_QUOTE, AR_Q_ANGLE, AR_Q_SYSTEM_FLAG, AR_Q_BUILTIN, AR_Q_AFTER,
       AR_Q_COUNT };

static int ar_search_option(const char *arg, const char **value)
{
    static const struct { const char *opt; int cls; } opts[] = {
        { "-idirafter", AR_Q_AFTER }, { "-isystem", AR_Q_SYSTEM_FLAG },
        { "-iquote", AR_Q_QUOTE }, { "-I", AR_Q_ANGLE },
    };
    for (size_t i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
        size_t n = strlen(opts[i].opt);
        if (strncmp(arg, opts[i].opt, n) == 0) {
            *value = arg[n] ? arg + n : NULL;
            return opts[i].cls;
        }
    }
    return -1;
}

/* Flags that move the built-in search list away from what system_dirs
 * describes. Refused rather than approximated. */
static bool ar_search_flag_unsupported(const char *arg)
{
    static const char *const refused[] = {
        "-nostdinc", "--sysroot", "-isysroot", "-iprefix", "-iwithprefix",
        "-imultilib", "-B", "-specs", "--specs",
    };
    if (strcmp(arg, "-I-") == 0)
        return true;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        if (strncmp(arg, refused[i], strlen(refused[i])) == 0)
            return true;
    return false;
}

static bool ar_search_add(struct ar_state *s, const char *raw)
{
    char token[PATH_MAX], fs[PATH_MAX];
    if (!ar_tokenize(&s->c, raw, token, fs)) {
        ar_why(s->c.why, s->c.why_len,
               "include dir has no canonical spelling", raw);
        return false;
    }
    if (ar_list_has(&s->search, token))
        return true; /* the compiler ignores a repeated dir */
    return ar_list_push(&s->search, token) && ar_list_push(&s->search_fs, fs);
}

static bool ar_search_collect(struct ar_state *s, int want)
{
    const struct zcl_action_root_request *req = s->c.req;
    if (want == AR_Q_BUILTIN) {
        for (size_t i = 0; i < req->system_dir_count; i++)
            if (!ar_search_add(s, req->system_dirs[i]))
                return false;
        return true;
    }
    for (size_t i = 0; i < req->argc; i++) {
        const char *value = NULL;
        int cls = ar_search_option(req->argv[i], &value);
        if (cls != want)
            continue;
        if (!value && i + 1 < req->argc)
            value = req->argv[++i];
        if (!value || !ar_search_add(s, value))
            return false;
    }
    return true;
}

static bool ar_search_build(struct ar_state *s)
{
    const struct zcl_action_root_request *req = s->c.req;
    for (size_t i = 0; i < req->argc; i++)
        if (ar_search_flag_unsupported(req->argv[i])) {
            ar_why(s->c.why, s->c.why_len,
                   "argv changes the built-in include search", req->argv[i]);
            return false;
        }
    for (int cls = 0; cls < AR_Q_COUNT; cls++)
        if (!ar_search_collect(s, cls))
            return false;
    return true;
}

/* ---- negative lookups -------------------------------------------------- */

static bool ar_dirname(const char *token, char out[PATH_MAX])
{
    const char *slash = strrchr(token, '/');
    if (!slash) {
        (void)snprintf(out, PATH_MAX, ".");
        return true;
    }
    size_t n = (size_t)(slash - token);
    if (n == 4 && strncmp(token, "@sys", 4) == 0)
        return false;
    (void)snprintf(out, PATH_MAX, "%.*s", (int)n, token);
    return true;
}

/* rel of `token` below `dir`, or NULL. "." holds every checkout path. */
static const char *ar_below(const char *token, const char *dir)
{
    if (strcmp(dir, ".") == 0)
        return token[0] == '@' ? NULL : token;
    size_t n = strlen(dir);
    return strncmp(token, dir, n) == 0 && token[n] == '/' ? token + n + 1
                                                          : NULL;
}

static bool ar_token_fs(const struct ar_ctx *c, const char *token,
                        char fs[PATH_MAX])
{
    int n = strcmp(token, ".") == 0
        ? snprintf(fs, PATH_MAX, "%s", c->req->root)
        : strncmp(token, "@sys/", 5) == 0
            ? snprintf(fs, PATH_MAX, "%s", token + 4)
            : snprintf(fs, PATH_MAX, "%s/%s", c->req->root, token);
    return n > 0 && n < PATH_MAX;
}

static bool ar_includers_build(struct ar_state *s)
{
    for (size_t i = 0; i < s->dep_n; i++) {
        char dir[PATH_MAX];
        if (!ar_dirname(s->deps[i].token, dir) ||
            !ar_list_push(&s->includers, dir)) {
            ar_why(s->c.why, s->c.why_len, "includer dir unavailable",
                   s->deps[i].token);
            return false;
        }
    }
    ar_list_sort_unique(&s->includers);
    for (size_t i = 0; i < s->includers.n; i++) {
        char fs[PATH_MAX];
        if (!ar_token_fs(&s->c, s->includers.v[i], fs) ||
            !ar_list_push(&s->includers_fs, fs))
            return false;
    }
    return true;
}

static bool ar_name_add(struct ar_state *s, const char *name, uint32_t prefix)
{
    if (s->name_n == s->name_cap) {
        size_t cap = s->name_cap ? s->name_cap * 2 : 256;
        struct vcs_action_probe_v2 *grown = zcl_realloc(
            s->names, cap * sizeof(*grown), "action root probe names");
        if (!grown)
            return false;
        s->names = grown;
        s->name_cap = cap;
    }
    char *copy = zcl_strdup(name, "action root probe name");
    if (!copy)
        return false;
    s->names[s->name_n].name = copy;
    s->names[s->name_n].search_prefix = prefix;
    s->name_n++;
    return true;
}

static int ar_name_cmp(const void *a, const void *b)
{
    const struct vcs_action_probe_v2 *x = a, *y = b;
    return strcmp(x->name, y->name);
}

/* Merge repeated names; a name probes every search dir before the LATEST
 * position any dependency was found at under that name. */
static void ar_names_merge(struct ar_state *s)
{
    if (s->name_n < 2)
        return;
    qsort(s->names, s->name_n, sizeof(*s->names), ar_name_cmp);
    size_t w = 1;
    for (size_t i = 1; i < s->name_n; i++) {
        struct vcs_action_probe_v2 *last = &s->names[w - 1];
        if (strcmp(last->name, s->names[i].name) == 0) {
            if (s->names[i].search_prefix > last->search_prefix)
                last->search_prefix = s->names[i].search_prefix;
            free((char *)s->names[i].name);
        } else {
            s->names[w++] = s->names[i];
        }
    }
    s->name_n = w;
}

static bool ar_names_build(struct ar_state *s)
{
    for (size_t i = 0; i < s->dep_n; i++) {
        const char *token = s->deps[i].token;
        for (size_t k = 0; k < s->search.n; k++) {
            const char *rel = ar_below(token, s->search.v[k]);
            if (rel && !ar_name_add(s, rel, (uint32_t)k))
                return false;
        }
        for (size_t k = 0; k < s->includers.n; k++) {
            const char *rel = ar_below(token, s->includers.v[k]);
            if (rel && !ar_name_add(s, rel, 0))
                return false;
        }
    }
    ar_names_merge(s);
    return true;
}

static bool ar_present_add(struct ar_state *s, const char *dir,
                           const char *name, const char *path, bool regular)
{
    if (s->present_n == s->present_cap) {
        size_t cap = s->present_cap ? s->present_cap * 2 : 256;
        struct vcs_action_present_v2 *grown = zcl_realloc(
            s->present, cap * sizeof(*grown), "action root present probes");
        if (!grown)
            return false;
        s->present = grown;
        s->present_cap = cap;
    }
    struct vcs_action_present_v2 *p = &s->present[s->present_n];
    memset(p, 0, sizeof(*p));
    p->dir = dir;
    p->name = name;
    p->kind = regular ? VCS_ACTION_PRESENT_V2_REGULAR
                      : VCS_ACTION_PRESENT_V2_OTHER;
    if (regular && !ar_sha3_file(path, p->sha3)) {
        ar_why(s->c.why, s->c.why_len, "present probe could not be hashed",
               name);
        return false;
    }
    s->present_n++;
    return true;
}

static bool ar_probe(struct ar_state *s, const char *dir, const char *dir_fs,
                     const char *name)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir_fs, name);
    s->probes++;
    if (n <= 0 || n >= (int)sizeof(path)) {
        ar_why(s->c.why, s->c.why_len, "probe path overflow", name);
        return false;
    }
    enum platform_file_shape shape = platform_file_shape_read(path);
    if (shape == PLATFORM_FILE_SHAPE_MISSING)
        return true;
    if (shape == PLATFORM_FILE_SHAPE_UNREADABLE) {
        ar_why(s->c.why, s->c.why_len, "probe location is unreadable", name);
        return false;
    }
    struct stat st;
    bool regular = stat(path, &st) == 0 && S_ISREG(st.st_mode);
    return ar_present_add(s, dir, name, path, regular);
}

static bool ar_includer_has(const struct ar_state *s, const char *dir)
{
    return bsearch(&dir, s->includers.v, s->includers.n, sizeof(char *),
                   ar_str_cmp) != NULL;
}

static int ar_present_cmp(const void *a, const void *b)
{
    const struct vcs_action_present_v2 *x = a, *y = b;
    int c = strcmp(x->dir, y->dir);
    return c ? c : strcmp(x->name, y->name);
}

static bool ar_probes_run(struct ar_state *s)
{
    for (size_t i = 0; i < s->name_n; i++) {
        const struct vcs_action_probe_v2 *p = &s->names[i];
        for (size_t d = 0; d < s->includers.n; d++)
            if (!ar_probe(s, s->includers.v[d], s->includers_fs.v[d],
                          p->name))
                return false;
        for (uint32_t j = 0; j < p->search_prefix; j++) {
            if (ar_includer_has(s, s->search.v[j]))
                continue; /* already probed as an includer dir */
            if (!ar_probe(s, s->search.v[j], s->search_fs.v[j], p->name))
                return false;
        }
    }
    if (s->present_n > 1)
        qsort(s->present, s->present_n, sizeof(*s->present),
              ar_present_cmp);
    return true;
}

/* ---- argv and environment ---------------------------------------------- */

static bool ar_text_add(struct ar_state *s, struct ar_list *l,
                        const char *raw)
{
    char text[AR_TEXT_MAX];
    if (!ar_rewrite(&s->c, raw, text, sizeof(text)) ||
        !vcs_action_v2_text_canonical(text)) {
        ar_why(s->c.why, s->c.why_len, "argument has no canonical spelling",
               raw);
        return false;
    }
    return ar_list_push(l, text);
}

static bool ar_argv_build(struct ar_state *s)
{
    const struct zcl_action_root_request *req = s->c.req;
    for (size_t i = 0; i < req->argc; i++) {
        const char *arg = req->argv[i];
        for (size_t v = 0; v < req->virtual_count; v++)
            if (strcmp(arg, req->virtual_from[v]) == 0)
                arg = req->virtual_to[v];
        if (!ar_text_add(s, &s->argv, arg))
            return false;
    }
    return true;
}

static int ar_env_cmp(const void *a, const void *b)
{
    const char *x = *(char *const *)a, *y = *(char *const *)b;
    size_t xn = strcspn(x, "="), yn = strcspn(y, "=");
    int c = memcmp(x, y, xn < yn ? xn : yn);
    return c ? c : (xn > yn) - (xn < yn);
}

static bool ar_env_seen(const struct ar_list *l, const char *entry,
                        size_t name_len)
{
    for (size_t i = 0; i < l->n; i++)
        if (strncmp(l->v[i], entry, name_len + 1) == 0)
            return true;
    return false;
}

static bool ar_env_build(struct ar_state *s)
{
    const char *const *env = s->c.req->environ;
    for (size_t i = 0; env && env[i]; i++) {
        const char *eq = strchr(env[i], '=');
        size_t name_len = eq ? (size_t)(eq - env[i]) : 0;
        if (!eq || !vcs_action_v2_env_allowlisted(env[i], name_len) ||
            ar_env_seen(&s->env, env[i], name_len))
            continue;
        char entry[AR_TEXT_MAX];
        int n = snprintf(entry, sizeof(entry), "%.*s=", (int)name_len,
                         env[i]);
        if (n <= 0 || !ar_rewrite(&s->c, eq + 1, entry + n,
                                  sizeof(entry) - (size_t)n) ||
            (entry[n] && !vcs_action_v2_text_canonical(entry + n))) {
            ar_why(s->c.why, s->c.why_len,
                   "environment value has no canonical spelling", env[i]);
            return false;
        }
        if (!ar_list_push(&s->env, entry))
            return false;
    }
    if (s->env.n > 1)
        qsort(s->env.v, s->env.n, sizeof(char *), ar_env_cmp);
    return true;
}

/* ---- assembly ---------------------------------------------------------- */

static int ar_input_cmp(const void *a, const void *b)
{
    const struct vcs_action_input_v2 *x = a, *y = b;
    return strcmp(x->path, y->path);
}

/* Split the closure into sorted, de-duplicated source and generated
 * lists (one allocation, sources first). */
static struct vcs_action_input_v2 *ar_inputs(const struct ar_state *s,
                                             size_t *sources,
                                             size_t *generated)
{
    struct vcs_action_input_v2 *v =
        zcl_calloc(s->dep_n ? s->dep_n : 1, sizeof(*v), "action root inputs");
    size_t n[2] = {0, 0};
    for (int pass = 0; v && pass < 2; pass++) {
        struct vcs_action_input_v2 *base = v + (pass ? n[0] : 0);
        for (size_t i = 0; i < s->dep_n; i++) {
            if (s->deps[i].generated != (pass == 1))
                continue;
            base[n[pass]].path = s->deps[i].token;
            memcpy(base[n[pass]].sha3, s->deps[i].sha3, 32);
            n[pass]++;
        }
        qsort(base, n[pass], sizeof(*base), ar_input_cmp);
        size_t w = n[pass] ? 1 : 0;
        for (size_t i = 1; i < n[pass]; i++)
            if (strcmp(base[w - 1].path, base[i].path) != 0)
                base[w++] = base[i];
        n[pass] = w;
    }
    *sources = n[0];
    *generated = n[1];
    return v;
}

static bool ar_encode(struct ar_state *s, struct zcl_action_root_result *out)
{
    const struct zcl_action_root_request *req = s->c.req;
    size_t source_n = 0, generated_n = 0;
    struct vcs_action_input_v2 *inputs = ar_inputs(s, &source_n,
                                                   &generated_n);
    if (!inputs) {
        ar_why(out->why, sizeof(out->why), "input list allocation failed",
               NULL);
        return false;
    }
    struct vcs_action_preimage_v2 p = {
        .stage_kind = req->stage_kind, .stage_version = req->stage_version,
        .sources = inputs, .source_count = source_n,
        .generated = inputs + source_n, .generated_count = generated_n,
        .search_dirs = (const char *const *)s->search.v,
        .search_dir_count = s->search.n,
        .includer_dirs = (const char *const *)s->includers.v,
        .includer_dir_count = s->includers.n,
        .probes = s->names, .probe_count = s->name_n,
        .present = s->present, .present_count = s->present_n,
        .argv = (const char *const *)s->argv.v, .argc = s->argv.n,
        .env = (const char *const *)s->env.v, .env_count = s->env.n,
        .abi = req->abi, .abi_count = req->abi_count,
        .harness = req->harness, .fixtures = req->fixtures,
        .policy = req->policy,
    };
    memcpy(p.toolchain_root, req->toolchain_root, 32);
    bool ok = vcs_action_preimage_v2_encode(&p, &out->preimage,
                                            &out->preimage_len, out->why,
                                            sizeof(out->why)) &&
              vcs_action_root_v2_from_bytes(out->preimage, out->preimage_len,
                                            out->root, out->why,
                                            sizeof(out->why));
    free(inputs);
    if (ok)
        zcl_hex_encode(out->root, 32, out->root_hex);
    out->source_count = (uint32_t)source_n;
    out->generated_count = (uint32_t)generated_n;
    return ok;
}

static void ar_state_free(struct ar_state *s)
{
    free(s->deps);
    ar_list_free(&s->search);
    ar_list_free(&s->search_fs);
    ar_list_free(&s->includers);
    ar_list_free(&s->includers_fs);
    for (size_t i = 0; i < s->name_n; i++)
        free((char *)s->names[i].name);
    free(s->names);
    free(s->present);
    ar_list_free(&s->argv);
    ar_list_free(&s->env);
}

static bool ar_request_valid(const struct zcl_action_root_request *req,
                             char *why, size_t why_len)
{
    char norm[PATH_MAX];
    bool ok = req && req->root && req->root[0] == '/' && req->depfile &&
              req->argv && req->argc > 0 && req->stage_kind &&
              ar_lex_normalize(req->root, norm, sizeof(norm)) &&
              strcmp(norm, req->root) == 0 && strcmp(req->root, "/") != 0;
    if (!ok)
        ar_why(why, why_len, "action root request is incomplete", NULL);
    return ok;
}

bool zcl_action_root_derive(const struct zcl_action_root_request *req,
                            struct zcl_action_root_result *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    int64_t started = platform_time_monotonic_us();
    if (!ar_request_valid(req, out->why, sizeof(out->why)))
        return false;
    struct ar_state s = {
        .c = { req, strlen(req->root), out->why, sizeof(out->why) },
    };
    s.deps = zcl_calloc(ZCL_ACTION_ROOT_MAX_DEPS, sizeof(*s.deps),
                        "action root dependency closure");
    bool ok = s.deps && ar_depfile_load(&s) && ar_search_build(&s) &&
              ar_includers_build(&s) && ar_names_build(&s) &&
              ar_probes_run(&s) && ar_argv_build(&s) && ar_env_build(&s) &&
              ar_encode(&s, out);
    if (!ok)
        ar_why(out->why, sizeof(out->why), "action root derivation failed",
               NULL);
    out->probe_names = (uint32_t)s.name_n;
    out->probes = s.probes;
    out->present = (uint32_t)s.present_n;
    ar_state_free(&s);
    out->derive_us = platform_time_monotonic_us() - started;
    if (ok)
        out->why[0] = '\0';
    else
        zcl_action_root_result_free(out);
    return ok;
}

void zcl_action_root_result_free(struct zcl_action_root_result *out)
{
    if (!out)
        return;
    free(out->preimage);
    out->preimage = NULL;
    out->preimage_len = 0;
}
