/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Confined, bounded access to the checkout's docs/ tree for the
 * discover.wiki and discover.read leaves. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_wiki_priv.h"

#include "platform/os_proc.h"
#include "util/safe_alloc.h"
#include "util/path_util.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

bool wk_is_file(const char *real)
{
    struct stat st;
    return stat(real, &st) == 0 && S_ISREG(st.st_mode);
}

/* A docs root counts only when it is a directory holding README.md. */
static bool wk_docs_try(const char *cand, struct wk_docs *docs)
{
    char readme[WK_PATH_MAX];
    docs->code = false;
    if (!wk_canonicalize(cand, docs->root, sizeof(docs->root)) ||
        !zcl_path_is_dir(docs->root))
        return false;
    return zcl_path_join(readme, sizeof(readme), docs->root, "README.md") &&
           wk_is_file(readme);
}

static bool wk_docs_try_in(struct wk_docs *docs, const char *base,
                           const char *sub)
{
    char cand[WK_PATH_MAX];
    return zcl_path_join(cand, sizeof(cand), base, sub) && wk_docs_try(cand, docs);
}

/* Drops the last path component; false at the root or without a separator. */
static bool wk_dirname(char *path)
{
    size_t n = strlen(path);
    while (n > 1 && path[n - 1] != '/')
        n--;
    if (n <= 1)
        return false;
    path[n - 1] = '\0';
    return true;
}

/* An installed binary: docs/ beside the executable or up to three parents
 * above it (a checkout's build/bin), else share/z23/docs of the install
 * prefix, found up to four parents above the executable directory:
 * <prefix>/bin/z23 and <prefix>/lib/z23/generations/<sha>/z23. */
static bool wk_docs_from_exe(struct wk_docs *docs)
{
    char dir[WK_PATH_MAX], up[WK_PATH_MAX];
    if (!os_proc_exe_path(dir, sizeof(dir)) || !wk_dirname(dir))
        return false;
    memcpy(up, dir, strlen(dir) + 1);
    for (int level = 0; level <= 3; level++) {
        if (wk_docs_try_in(docs, up, "docs"))
            return true;
        if (!wk_dirname(up))
            break;
    }
    for (int level = 1; level <= 4 && wk_dirname(dir); level++)
        if (wk_docs_try_in(docs, dir, "share/z23/docs"))
            return true;
    return false;
}

bool wk_docs_open(const struct zcl_command_request *request,
                  struct wk_docs *docs, struct zcl_command_reply *reply)
{
    const char *over = json_get_str(json_get(request->input, "docsdir"));
    bool found = over && over[0]
                     ? wk_docs_try(over, docs)
                     : wk_docs_try_in(docs, zcl_native_source_root(request), "docs") ||
                           wk_docs_from_exe(docs);
    if (found)
        return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "DOCS_UNAVAILABLE",
                           "resolve", false, false,
                           "no docs directory found; looked at the docsdir "
                           "input, the checkout docs directory, the "
                           "executable's directory and its parents, and the "
                           "share/z23/docs directory of the install prefix",
                           "docsdir");
    return false;
}

static bool wk_segment_ok(const char *s, size_t n)
{
    if (n == 0 || (n == 1 && s[0] == '.') ||
        (n == 2 && s[0] == '.' && s[1] == '.'))
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || s[i] == '\\' || s[i] == 0x7f)
            return false;
    return true;
}

bool wk_rel_normalize(const char *in, char *out, size_t cap)
{
    size_t n = strlen(in);
    while (n > 0 && in[n - 1] == '/')
        n--;
    if (n >= cap || n > WK_REL_MAX || (n > 0 && in[0] == '/'))
        return false;
    size_t start = 0;
    for (size_t i = 0; n > 0 && i <= n; i++) {
        if (i < n && in[i] != '/')
            continue;
        if (!wk_segment_ok(in + start, i - start))
            return false;
        start = i + 1;
    }
    memcpy(out, in, n);
    out[n] = '\0';
    return true;
}

static bool wk_within(const char *root, const char *real)
{
    size_t rl = strlen(root);
    return strncmp(real, root, rl) == 0 && (real[rl] == '\0' || real[rl] == '/');
}

enum wk_status wk_resolve(const struct wk_docs *docs, const char *rel,
                          char *real, size_t cap)
{
    char full[WK_PATH_MAX];
    char res[PATH_MAX];
    int n = rel[0] ? snprintf(full, sizeof(full), "%s/%s", docs->root, rel)
                   : snprintf(full, sizeof(full), "%s", docs->root);
    if (n <= 0 || (size_t)n >= sizeof(full))
        return WK_BAD;
    if (!wk_canonicalize(full, res, sizeof(res)))
        return WK_MISSING;
    if (!wk_within(docs->root, res))
        return WK_ESCAPES;
    if (docs->code && wk_code_denied(wk_code_rel(docs, res)))
        return WK_EXCLUDED;
    if (strlen(res) >= cap)
        return WK_BAD;
    memcpy(real, res, strlen(res) + 1);
    return WK_OK;
}

bool wk_is_topic(const struct wk_docs *docs, const char *real)
{
    char readme[WK_PATH_MAX];
    if (docs->code)
        return wk_code_is_topic(docs, real);
    if (!zcl_path_is_dir(real))
        return false;
    if (strcmp(real, docs->root) == 0)
        return true;
    int n = snprintf(readme, sizeof(readme), "%s/README.md", real);
    return n > 0 && (size_t)n < sizeof(readme) && wk_is_file(readme);
}

void wk_nearest_topic(const struct wk_docs *docs, const char *rel, char *out,
                      size_t cap)
{
    char cur[WK_REL_MAX + 1];
    char real[WK_PATH_MAX];
    snprintf(cur, sizeof(cur), "%s", rel);
    for (;;) {
        char *slash = strrchr(cur, '/');
        if (slash)
            *slash = '\0';
        else
            cur[0] = '\0';
        if (!cur[0] || (wk_resolve(docs, cur, real, sizeof(real)) == WK_OK &&
                        wk_is_topic(docs, real)))
            break;
    }
    snprintf(out, cap, "%s", cur);
}

bool wk_head(const char *real, char *buf, size_t cap, size_t *len)
{
    if (!wk_is_file(real))
        return false;
    FILE *fp = fopen(real, "rb");
    if (!fp)
        return false;
    size_t got = fread(buf, 1, cap - 1, fp);
    bool ok = !ferror(fp);
    fclose(fp);
    buf[ok ? got : 0] = '\0';
    *len = ok ? got : 0;
    return ok;
}

bool wk_read_at(const char *real, int64_t offset, size_t want, char *buf,
                size_t *got, int64_t *size)
{
    struct stat st;
    if (stat(real, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    *size = (int64_t)st.st_size;
    *got = 0;
    if (offset >= *size)
        return true;
    FILE *fp = fopen(real, "rb");
    if (!fp)
        return false;
    bool ok = fseeko(fp, (off_t)offset, SEEK_SET) == 0;
    if (ok) {
        *got = fread(buf, 1, want + 3, fp);
        ok = !ferror(fp);
    }
    fclose(fp);
    return ok;
}

static size_t wk_lead_len(unsigned char c)
{
    if (c < 0x80)
        return 1;
    if (c < 0xC2 || c > 0xF4)
        return 0;
    return c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2;
}

/* Overlong, surrogate and out-of-range encodings share a second-byte rule. */
static bool wk_second_ok(unsigned char lead, unsigned char second)
{
    switch (lead) {
    case 0xE0: return second >= 0xA0;
    case 0xED: return second < 0xA0;
    case 0xF0: return second >= 0x90;
    case 0xF4: return second < 0x90;
    default: return true;
    }
}

/* Length of the valid UTF-8 sequence at p, or 0 when p starts none. */
static size_t wk_seq_len(const unsigned char *p, size_t n)
{
    size_t need = n ? wk_lead_len(p[0]) : 0;
    if (need == 0 || need > n)
        return 0;
    for (size_t i = 1; i < need; i++)
        if ((p[i] & 0xC0) != 0x80)
            return 0;
    return need == 1 || wk_second_ok(p[0], p[1]) ? need : 0;
}

static size_t wk_unit(const char *p, size_t n, bool keep_nl, char *out)
{
    size_t k = wk_seq_len((const unsigned char *)p, n);
    if (k > 1) {
        memcpy(out, p, k);
        return k;
    }
    unsigned char c = (unsigned char)p[0];
    if (k == 0)
        c = '?';
    else if ((c < 0x20 && !(keep_nl && (c == '\n' || c == '\t'))) || c == 0x7f)
        c = ' ';
    out[0] = (char)c;
    return 1;
}

size_t wk_clean(char *dst, size_t max, const char *src, size_t len,
                bool keep_nl, bool force_first)
{
    size_t o = 0;
    while (o < len) {
        char unit[4];
        size_t k = wk_unit(src + o, len - o, keep_nl, unit);
        if (o + k > max && !(force_first && o == 0))
            break;
        memcpy(dst + o, unit, k);
        o += k;
    }
    return o;
}

/* Plain-text rendering of Markdown inline syntax for summaries: links keep
 * their text, emphasis and code marks disappear. Output is a fixed buffer. */

enum { WK_PLAIN_DEPTH = 4 };

struct wk_pw {
    char *d;
    size_t max, o;
    bool full;
};

/* One byte past the delimiter closing the `open` at s[0], or 0. */
static size_t wk_match(const char *s, size_t n, char open, char close)
{
    size_t depth = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == open)
            depth++;
        else if (s[i] == close && --depth == 0)
            return i + 1;
    }
    return 0;
}

/* Bytes of a `[text](target)` link at s[0] (0 when none) and its text. */
static size_t wk_link(const char *s, size_t n, const char **text, size_t *tlen)
{
    size_t t = wk_match(s, n, '[', ']');
    if (t == 0 || t >= n || s[t] != '(')
        return 0;
    size_t u = wk_match(s + t, n - t, '(', ')');
    if (u == 0)
        return 0;
    *text = s + 1;
    *tlen = t - 2;
    return t + u;
}

/* Bytes of an emphasis or code mark at s[0]: `**`, `__` or a backtick. */
static size_t wk_mark(const char *s, size_t n)
{
    if (s[0] == '`')
        return 1;
    return n >= 2 && s[1] == s[0] && (s[0] == '*' || s[0] == '_') ? 2 : 0;
}

/* Emits one character, whole; marks the writer full when it does not fit. */
static size_t wk_put(struct wk_pw *w, const char *s, size_t n)
{
    char unit[4];
    size_t k = wk_unit(s, n, false, unit);
    if (w->o + k > w->max) {
        w->full = true;
        return n;
    }
    memcpy(w->d + w->o, unit, k);
    w->o += k;
    return k;
}

static void wk_pw_run(struct wk_pw *w, const char *s, size_t n, int depth)
{
    size_t i = 0;
    while (i < n && !w->full) {
        const char *text = NULL;
        size_t tlen = 0, used = wk_mark(s + i, n - i);
        if (used == 0 && s[i] == '[' && depth < WK_PLAIN_DEPTH &&
            (used = wk_link(s + i, n - i, &text, &tlen)) != 0)
            wk_pw_run(w, text, tlen, depth + 1);
        else if (used == 0)
            used = wk_put(w, s + i, n - i);
        i += used;
    }
}

size_t wk_plain(char *dst, size_t cap, const char *src, size_t len)
{
    struct wk_pw w = { .d = dst, .max = cap ? cap - 1 : 0 };
    if (cap == 0)
        return 0;
    wk_pw_run(&w, src, len, 0);
    dst[w.o] = '\0';
    return w.o;
}

enum { WK_RAW_MAX = 640 }; /* summary bytes gathered before rendering */

struct wk_scan {
    struct wk_meta *m;
    char raw[WK_RAW_MAX + 1];
    size_t slen;
    bool comment, fence, title, para_done;
};

static bool wk_starts(const char *s, size_t n, const char *lit)
{
    size_t l = strlen(lit);
    return n >= l && memcmp(s, lit, l) == 0;
}

static bool wk_close(const char *s, size_t n)
{
    for (size_t i = 0; i + 3 <= n; i++)
        if (s[i] == '-' && s[i + 1] == '-' && s[i + 2] == '>')
            return true;
    return false;
}

static bool wk_line_markup(struct wk_scan *sc, const char *s, size_t n)
{
    if (sc->comment) {
        sc->comment = !wk_close(s, n);
        return true;
    }
    if (wk_starts(s, n, "<!--")) {
        sc->comment = !wk_close(s + 4, n - 4);
        return true;
    }
    if (wk_starts(s, n, "```") || wk_starts(s, n, "~~~")) {
        sc->fence = !sc->fence;
        sc->para_done = sc->para_done || sc->slen > 0;
        return true;
    }
    return sc->fence;
}

static bool wk_line_noise(const char *s, size_t n)
{
    static const char *const lead[] = {
        "![", "[![", "Copyright", "Commands:", "---", "***", "<", "|",
    };
    for (size_t i = 0; i < sizeof(lead) / sizeof(lead[0]); i++)
        if (wk_starts(s, n, lead[i]))
            return true;
    return false;
}

static void wk_heading(struct wk_scan *sc, const char *s, size_t n)
{
    if (!sc->title && n > 2 && s[1] == ' ') {
        const char *t = s + 2;
        size_t tn = n - 2;
        while (tn && *t == ' ') {
            t++;
            tn--;
        }
        size_t k = wk_clean(sc->m->title, WK_TEXT_MAX, t, tn, false, false);
        sc->m->title[k] = '\0';
        sc->title = true;
        return;
    }
    sc->para_done = sc->para_done || sc->slen > 0;
}

static void wk_append(struct wk_scan *sc, const char *s, size_t n)
{
    char *d = sc->raw;
    size_t room = WK_RAW_MAX - sc->slen;
    if (sc->slen > 0 && room > 0) {
        d[sc->slen++] = ' ';
        room--;
    }
    sc->slen += wk_clean(d + sc->slen, room, s, n, false, false);
}

static void wk_line(struct wk_scan *sc, const char *s, size_t n)
{
    while (n && (s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    while (n && (*s == ' ' || *s == '\t')) {
        s++;
        n--;
    }
    if (wk_line_markup(sc, s, n))
        return;
    if (n == 0) {
        sc->para_done = sc->para_done || sc->slen > 0;
        return;
    }
    if (s[0] == '#')
        wk_heading(sc, s, n);
    else if (!sc->para_done && !wk_line_noise(s, n))
        wk_append(sc, s, n);
}

void wk_meta_scan(const char *buf, size_t len, struct wk_meta *meta)
{
    struct wk_scan sc = { .m = meta };
    meta->title[0] = '\0';
    meta->summary[0] = '\0';
    size_t pos = 0;
    while (pos < len && !(sc.title && sc.para_done)) {
        const char *nl = memchr(buf + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - buf) : len;
        wk_line(&sc, buf + pos, end - pos);
        pos = end + 1;
    }
    while (sc.slen > 0 && sc.raw[sc.slen - 1] == ' ')
        sc.slen--;
    size_t out = wk_plain(meta->summary, sizeof(meta->summary), sc.raw,
                          sc.slen);
    while (out > 0 && meta->summary[out - 1] == ' ')
        out--;
    meta->summary[out] = '\0';
}

static bool wk_name_ok(const char *name)
{
    size_t n = strlen(name);
    char tmp[WK_NAME_MAX];
    if (n == 0 || n >= WK_NAME_MAX || name[0] == '.' || strchr(name, ' '))
        return false;
    return wk_clean(tmp, sizeof(tmp), name, n, false, false) == n &&
           memcmp(tmp, name, n) == 0;
}

static bool wk_ends_md(const char *name)
{
    size_t n = strlen(name);
    return n > 3 && strcmp(name + n - 3, ".md") == 0;
}

/* A directory entry is listed when it resolves inside the root. In docs it is
 * a topic directory or a Markdown page other than README.md; in the source
 * tree, wk_code_classify decides. */
static int wk_classify(const struct wk_docs *docs, const char *dir,
                       const char *name)
{
    char full[WK_PATH_MAX];
    char real[PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(full) ||
        !wk_canonicalize(full, real, sizeof(real)) ||
        !wk_within(docs->root, real))
        return 0;
    if (docs->code)
        return wk_code_classify(docs, real, name);
    if (wk_is_topic(docs, real))
        return 1;
    return wk_is_file(real) && wk_ends_md(name) && strcmp(name, "README.md")
               ? 2 : 0;
}

static int wk_child_cmp(const void *a, const void *b)
{
    return strcmp(((const struct wk_child *)a)->name,
                  ((const struct wk_child *)b)->name);
}

enum wk_status wk_children_list(const struct wk_docs *docs, const char *real,
                                struct wk_children *out)
{
    out->n = 0;
    out->v = zcl_malloc(WK_SCAN_MAX * sizeof(*out->v), "wiki_children");
    if (!out->v)
        return WK_NOMEM;
    DIR *dp = opendir(real);
    struct dirent *e;
    enum wk_status st = WK_OK;
    while (dp && (e = readdir(dp)) != NULL) {
        int kind = wk_name_ok(e->d_name) ? wk_classify(docs, real, e->d_name) : 0;
        if (kind == 0)
            continue;
        if (out->n == WK_SCAN_MAX) {
            st = WK_FULL;
            break;
        }
        memcpy(out->v[out->n].name, e->d_name, strlen(e->d_name) + 1);
        out->v[out->n++].topic = kind == 1;
    }
    if (dp)
        closedir(dp);
    qsort(out->v, out->n, sizeof(*out->v), wk_child_cmp);
    return st;
}

void wk_children_free(struct wk_children *c)
{
    free(c->v);
    c->v = NULL;
    c->n = 0;
}
