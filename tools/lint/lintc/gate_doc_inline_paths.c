/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-doc-inline-paths lint gate of the C23 lint
 * runtime. Replaces tools/lint/check_doc_inline_paths.sh: every backticked
 * source path (prong 1) and every backticked top-level module directory
 * (prong 2) in a tracked Markdown file must resolve against the tracked
 * tree. Violations are checked against a shrink-only baseline and the
 * per-line `doc-path-ok` override. The tracked set is read natively via
 * lint_git_index_foreach and the documents from the worktree; a tree with
 * no .git falls back to a filesystem walk. Never spawns a process.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <fnmatch.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    DA_PATH = 320,          /* one tracked path, doc path or token */
    DA_KEY = 2 * DA_PATH + 32,
    DA_POOL = 8 << 20,      /* interned tracked paths, suffixes, module dirs */
    DA_TAB = 1 << 18,       /* open-addressing slots over the pool */
    DA_DOCS_MAX = 4096,
    DA_FOUND_MAX = 1024,
    DA_WALK_DEPTH = 64
};

enum { DA_K_TRACK = 'T', DA_K_SUFFIX = 'S', DA_K_MODULE = 'M' };

static const char k_msg[] = "check_doc_inline_paths";
static const char k_def_baseline[] = "tools/lint/doc_inline_paths_baseline.txt";
static const char k_def_glob[] = "*.md";
/* Top-level source roots whose two-component children prong 2 resolves. */
static const char *const k_tops[] = {
    "adapters", "app", "application", "apps", "config", "core",
    "docs", "domain", "lib", "ports", "src", "tools"
};
static const char *const k_exts[] = {
    "c", "h", "cc", "def", "inc", "sh", "md", "txt", "tsv", "py", "json"
};
/* Entries the no-.git walk never descends into (the same set the other
 * index-or-walk gates skip). */
static const char *const k_skip[] = { ".git", "build", "vendor", ".claude", "test-tmp" };

struct da_set {
    char pool[DA_POOL];
    size_t used;
    uint32_t tab[DA_TAB];     /* 0 = empty, else pool offset + 1 */
    int n_keys, n_module;
};
struct da_found { char key[DA_KEY]; char line[DA_KEY]; };
struct da_state {
    struct da_set set;
    char docs[DA_DOCS_MAX][DA_PATH];
    int n_docs, n_entries, n_f, n_d;
    struct da_found found[DA_FOUND_MAX];
    int n_found;
    const char *glob;
    int rc;                   /* first error seen inside the index callback */
};

static struct da_state g_da;
static struct lint_base g_base;

/* ── interned string set: (kind, key) with a kind byte ───────────────── */

static uint32_t da_hash(char kind, const char *s)
{
    uint32_t h = 2166136261u;
    h = (h ^ (unsigned char)kind) * 16777619u;
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

/* The slot holding (kind,key), or the first empty slot of its probe run.
 * -1 only when the table is completely full (never in practice; the
 * insert path keeps the load under 3/4). */
static long da_slot(char kind, const char *key)
{
    struct da_set *s = &g_da.set;
    uint32_t h = da_hash(kind, key) & (DA_TAB - 1);
    for (uint32_t probe = 0; probe < DA_TAB; probe++) {
        uint32_t slot = (h + probe) & (DA_TAB - 1);
        if (s->tab[slot] == 0)
            return (long)slot;
        const char *e = &s->pool[s->tab[slot] - 1];
        if (e[0] == kind && strcmp(e + 1, key) == 0)
            return (long)slot;
    }
    return -1;
}

static int da_has(char kind, const char *key)
{
    long slot = da_slot(kind, key);
    return slot >= 0 && g_da.set.tab[slot] != 0;
}

/* Interns (kind,key). Returns 1 when added, 0 when already present, and -1
 * on overflow (the caller fails loud, never drops a key). */
static int da_add(char kind, const char *key)
{
    struct da_set *s = &g_da.set;
    long slot = da_slot(kind, key);
    if (slot < 0)
        return -1;
    if (s->tab[slot])
        return 0;
    size_t len = strlen(key) + 2;
    if (s->used + len > DA_POOL || (size_t)s->n_keys >= DA_TAB / 4 * 3)
        return -1;
    s->pool[s->used] = kind;
    memcpy(s->pool + s->used + 1, key, len - 1);
    s->tab[slot] = (uint32_t)(s->used + 1);
    s->used += len;
    s->n_keys++;
    if (kind == DA_K_MODULE)
        s->n_module++;
    return 1;
}

/* ── tracked-set construction ────────────────────────────────────────── */

/* Every "/"-anchored suffix of a tracked path resolves (prong 1), and the
 * first two components name a module directory (prong 2). */
static int da_add_tracked(const char *path)
{
    size_t n = strlen(path);
    if (n == 0 || n >= DA_PATH)
        return 2;
    if (da_add(DA_K_TRACK, path) < 0)
        return 2;
    for (const char *p = strchr(path, '/'); p; p = strchr(p + 1, '/'))
        if (da_add(DA_K_SUFFIX, p + 1) < 0)
            return 2;
    return 0;
}

static int da_add_module(const char *path)
{
    const char *f1 = strchr(path, '/');
    const char *f2 = f1 ? strchr(f1 + 1, '/') : NULL;
    if (!f2)
        return 0;
    char key[DA_PATH];
    size_t k = (size_t)(f2 - path);
    memcpy(key, path, k);
    key[k] = '\0';
    return da_add(DA_K_MODULE, key) < 0 ? 2 : 0;
}

/* fnmatch against the pathspec the shell gate hands git: a glob with no
 * wildcard names a path or a leading directory; any other glob is matched
 * against the whole tracked path. */
static int da_glob_match(const char *glob, const char *path)
{
    if (!strpbrk(glob, "*?[\\")) {
        size_t n = strlen(glob);
        return strncmp(path, glob, n) == 0 && (path[n] == '\0' || path[n] == '/');
    }
    return fnmatch(glob, path, 0) == 0;
}

static int da_push_doc(struct da_state *S, const char *path)
{
    if (S->n_docs >= DA_DOCS_MAX)
        return 2;
    if (ovf(snprintf(S->docs[S->n_docs], DA_PATH, "%s", path), DA_PATH))
        return 2;
    S->n_docs++;
    return 0;
}

static int da_take(struct da_state *S, const char *path)
{
    if (da_add_tracked(path) || da_add_module(path))
        return 2;
    if (da_glob_match(S->glob, path))
        return da_push_doc(S, path);
    return 0;
}

static int da_idx_cb(const char *path, int stage, void *ctx)
{
    (void)stage;
    struct da_state *S = ctx;
    S->n_entries++;
    S->rc = da_take(S, path);
    return S->rc ? 1 : 0;
}

static int da_skip_name(const char *nm)
{
    for (size_t i = 0; i < sizeof k_skip / sizeof k_skip[0]; i++)
        if (strcmp(nm, k_skip[i]) == 0)
            return 1;
    return 0;
}

static int da_walk_dir(const char *rel, struct da_state *S, int depth);

static int da_walk_one(const char *rel, const char *nm, struct da_state *S, int depth)
{
    char child[DA_PATH];
    if (ovf(snprintf(child, sizeof child, "%s%s%s", rel, rel[0] ? "/" : "", nm), sizeof child))
        return 2;
    struct stat st;
    if (lstat(child, &st) != 0)
        return die("z23-lint: cannot stat %s\n", child);
    if (S_ISDIR(st.st_mode))
        return da_walk_dir(child, S, depth + 1);
    S->n_entries++;
    return S_ISREG(st.st_mode) ? da_take(S, child) : 0;
}

static int da_walk_dir(const char *rel, struct da_state *S, int depth)
{
    if (depth > DA_WALK_DEPTH)
        return 2;
    struct dirent **names = NULL;
    int n = scandir(rel[0] ? rel : ".", &names, NULL, alphasort);
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", rel[0] ? rel : ".");
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") && strcmp(nm, "..") && !da_skip_name(nm))
            rc = da_walk_one(rel, nm, S, depth);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int da_has_git(void)
{
    struct stat st;
    return stat(".git", &st) == 0;
}

/* Tracked set: the git index when present, else a filesystem walk. A
 * mandatory index extension this reader does not interpret is UNPROVEN. */
static int da_collect(struct da_state *S)
{
    if (!da_has_git())
        return da_walk_dir("", S, 0);
    char badext[5] = "";
    int rc = lint_git_index_foreach(da_idx_cb, S, badext);
    if (rc || S->rc || badext[0]) {
        fprintf(stderr,
            "%s: UNPROVEN — the git index is unreadable or carries a mandatory extension\n"
            "  this native reader does not interpret; refusing to grade.\n", k_msg);
        return 2;
    }
    return 0;
}

/* ── path normalisation: the sed "strip ./, collapse SEG/../" pass ──── */

/* True when "SEG/../" starts at c (SEG non-empty); returns the index just
 * past the "/../", or 0. */
static size_t da_dotdot_at(const char *s, size_t c)
{
    size_t e = c;
    while (s[e] && s[e] != '/')
        e++;
    if (e == c || strncmp(s + e, "/../", 4) != 0)
        return 0;
    return e + 4;
}

static int da_collapse_at(char *s, size_t c)
{
    size_t end = da_dotdot_at(s, c);
    if (!end)
        return 0;
    memmove(s + c, s + end, strlen(s + end) + 1);
    return 1;
}

/* One substitution, leftmost first: the match starts at the line start
 * (the "^" branch) or at a "/" (which the replacement keeps). */
static int da_collapse_once(char *s)
{
    size_t len = strlen(s);
    for (size_t p = 0; p <= len; p++) {
        if (p == 0 && da_collapse_at(s, 0))
            return 1;
        if (s[p] == '/' && da_collapse_at(s, p + 1))
            return 1;
    }
    return 0;
}

static int da_norm(const char *in, char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s", in), cap))
        return 2;
    if (out[0] == '.' && out[1] == '/')
        memmove(out, out + 2, strlen(out + 2) + 1);
    while (da_collapse_once(out))
        ;
    return 0;
}

/* ── Markdown link-text stripper: [`x`](http...) never names a path ── */

/* s points at "[`". Returns the length of the external-link match, or 0. */
static size_t da_link_end(const char *s)
{
    const char *q = strchr(s + 2, '`');
    if (!q || strncmp(q, "`](", 3) != 0)
        return 0;
    const char *u = q + 3;
    if (strncmp(u, "https:", 6) == 0)
        u += 6;
    else if (strncmp(u, "http:", 5) == 0)
        u += 5;
    else if (strncmp(u, "mailto:", 7) == 0)
        u += 7;
    else
        return 0;
    const char *cl = strchr(u, ')');
    return cl ? (size_t)(cl - s) + 1 : 0;
}

static void da_strip_links(char *s)
{
    size_t r = 0, w = 0;
    while (s[r]) {
        size_t n = (s[r] == '[' && s[r + 1] == '`') ? da_link_end(s + r) : 0;
        if (n) {
            r += n;
            continue;
        }
        s[w++] = s[r++];
    }
    s[w] = '\0';
}

/* ── tokeniser: backtick-delimited segments, leftmost first ──────────── */

/* The next backtick pair at or after *cur: content is [*open, *close). */
static int da_next_seg(const char *s, size_t *cur, size_t *open, size_t *close)
{
    const char *o = strchr(s + *cur, '`');
    if (!o)
        return 0;
    const char *c = strchr(o + 1, '`');
    if (!c)
        return 0;
    *open = (size_t)(o - s) + 1;
    *close = (size_t)(c - s);
    return 1;
}

static int da_pathch(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
        || c == '_' || c == '.' || c == '/' || c == '-';
}

static int da_all_pathch(const char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!da_pathch((unsigned char)p[i]))
            return 0;
    return 1;
}

/* [0-9]+(-[0-9]+)? spanning [p, end). */
static int da_line_suffix(const char *p, const char *end)
{
    const char *d = p;
    while (d < end && isdigit((unsigned char)*d))
        d++;
    if (d == p)
        return 0;
    if (d == end)
        return 1;
    if (*d != '-' || d + 1 == end)
        return 0;
    for (const char *q = d + 1; q < end; q++)
        if (!isdigit((unsigned char)*q))
            return 0;
    return 1;
}

static int da_ends_in_ext(const char *s, size_t n)
{
    for (size_t k = 0; k < sizeof k_exts / sizeof k_exts[0]; k++) {
        size_t el = strlen(k_exts[k]);
        if (n >= el + 2 && s[n - el - 1] == '.' && memcmp(s + n - el, k_exts[k], el) == 0)
            return 1;
    }
    return 0;
}

/* Prong 1 segment: ^[path]+\.(ext)(:N(-N)?)?$ . Sets *base to the path
 * part, without the optional :LINE suffix. */
static int da_file_seg(const char *seg, size_t n, size_t *base)
{
    const char *colon = memchr(seg, ':', n);
    size_t b = colon ? (size_t)(colon - seg) : n;
    if (colon && !da_line_suffix(colon + 1, seg + n))
        return 0;
    if (!da_all_pathch(seg, b) || !da_ends_in_ext(seg, b))
        return 0;
    *base = b;
    return 1;
}

/* Prong 2 segment: ^[path]+/?$ . Returns 1 when the segment matches the
 * regex (the backtick pair is consumed either way); key receives the
 * "top/second" module directory when the token qualifies, else "". */
static int da_dir_seg(const char *seg, size_t n, char *key, size_t cap)
{
    key[0] = '\0';
    if (n == 0 || !da_all_pathch(seg, n))
        return 0;
    while (n > 0 && seg[n - 1] == '/')
        n--;
    const char *f1 = memchr(seg, '/', n);
    if (!f1)
        return 1;
    size_t top_len = (size_t)(f1 - seg);
    int top_ok = 0;
    for (size_t k = 0; k < sizeof k_tops / sizeof k_tops[0]; k++)
        if (strlen(k_tops[k]) == top_len && memcmp(k_tops[k], seg, top_len) == 0)
            top_ok = 1;
    if (!top_ok)
        return 1;
    const char *f2 = memchr(f1 + 1, '/', (size_t)(seg + n - f1 - 1));
    const char *sec_end = f2 ? f2 : seg + n;
    if (memchr(f1 + 1, '.', (size_t)(sec_end - f1 - 1)))
        return 1;
    size_t k = (size_t)(sec_end - seg);
    if (k >= cap)
        return -1;
    memcpy(key, seg, k);
    key[k] = '\0';
    return 1;
}

/* ── resolution and findings ─────────────────────────────────────────── */

static int da_dirname(const char *file, char *out, size_t cap)
{
    const char *slash = strrchr(file, '/');
    if (!slash)
        return ovf(snprintf(out, cap, "."), cap);
    return ovf(snprintf(out, cap, "%.*s", (int)(slash - file), file), cap);
}

/* A token resolves when it is a tracked path or a "/"-anchored suffix of
 * one, or when it resolves relative to the document's own directory. */
static int da_resolves(const char *tok, const char *dir, int *ok)
{
    *ok = da_has(DA_K_TRACK, tok) || da_has(DA_K_SUFFIX, tok);
    if (*ok)
        return 0;
    char joined[2 * DA_PATH + 4], rel[2 * DA_PATH + 4];
    if (ovf(snprintf(joined, sizeof joined, "%s/%s", dir, tok), sizeof joined))
        return 2;
    if (da_norm(joined, rel, sizeof rel))
        return 2;
    *ok = da_has(DA_K_TRACK, rel);
    return 0;
}

static int da_note_found(struct da_state *S, const char *file, long ln, const char *tok)
{
    if (S->n_found >= DA_FOUND_MAX)
        return 2;
    struct da_found *f = &S->found[S->n_found];
    if (ovf(snprintf(f->key, DA_KEY, "%s -> %s", file, tok), DA_KEY)
        || ovf(snprintf(f->line, DA_KEY, "%s:%ld -> %s", file, ln, tok), DA_KEY))
        return 2;
    S->n_found++;
    return 0;
}

static int da_record_file(struct da_state *S, const char *file, long ln, const char *raw)
{
    char tok[DA_PATH], dir[DA_PATH];
    if (da_norm(raw, tok, sizeof tok))
        return 2;
    if (tok[0] == '/' || strncmp(tok, "build/", 6) == 0
        || strncmp(tok, ".cache/", 7) == 0 || strncmp(tok, "test-tmp/", 9) == 0)
        return 0;
    if (!strchr(tok, '/'))
        return 0;
    if (da_dirname(file, dir, sizeof dir))
        return 2;
    int ok = 0;
    if (da_resolves(tok, dir, &ok))
        return 2;
    return ok ? 0 : da_note_found(S, file, ln, tok);
}

static int da_record_dir(struct da_state *S, const char *file, long ln, const char *key)
{
    if (da_has(DA_K_MODULE, key))
        return 0;
    char tok[DA_PATH];
    if (ovf(snprintf(tok, sizeof tok, "%s/", key), sizeof tok))
        return 2;
    return da_note_found(S, file, ln, tok);
}

/* Prong 1 over one line: F records in order of appearance. */
static int da_file_pass(struct da_state *S, const char *file, long ln, const char *text)
{
    size_t cur = 0, open = 0, close = 0, base = 0;
    while (da_next_seg(text, &cur, &open, &close)) {
        if (!da_file_seg(text + open, close - open, &base)) {
            cur = close;
            continue;
        }
        cur = close + 1;
        if (base >= DA_PATH)
            return 2;
        if (!memchr(text + open, '/', base))
            continue;
        char tok[DA_PATH];
        memcpy(tok, text + open, base);
        tok[base] = '\0';
        S->n_f++;
        if (da_record_file(S, file, ln, tok))
            return 2;
    }
    return 0;
}

/* Prong 2 over one line: D records, after the F records of the same line. */
static int da_dir_pass(struct da_state *S, const char *file, long ln, const char *text)
{
    size_t cur = 0, open = 0, close = 0;
    while (da_next_seg(text, &cur, &open, &close)) {
        char key[DA_PATH];
        int m = da_dir_seg(text + open, close - open, key, sizeof key);
        if (m < 0)
            return 2;
        cur = m ? close + 1 : close;
        if (!m || !key[0])
            continue;
        S->n_d++;
        if (da_record_dir(S, file, ln, key))
            return 2;
    }
    return 0;
}

/* One Markdown line: its text is what follows "file:line:" in git grep. */
static int da_scan_line(struct da_state *S, const char *file, long ln, char *text)
{
    if (strstr(text, "doc-path-ok"))
        return 0;
    da_strip_links(text);
    if (da_file_pass(S, file, ln, text))
        return 2;
    return da_dir_pass(S, file, ln, text);
}

/* A tracked document missing from the worktree has no lines to scan. */
static int da_scan_doc(struct da_state *S, const char *file)
{
    FILE *f = fopen(file, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    long ln = 0;
    int rc = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        ln++;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (strchr(line, '`'))
            rc = da_scan_line(S, file, ln, line);
    }
    return fin(f, line, file, rc);
}

static int da_scan_docs(struct da_state *S)
{
    for (int i = 0; i < S->n_docs; i++)
        if (da_scan_doc(S, S->docs[i]))
            return 2;
    return 0;
}

/* ── report: new findings, shrink-only baseline, verdict ─────────────── */

static int da_cmp_str(const void *a, const void *b)
{
    const char *x = *(const char *const *)a, *y = *(const char *const *)b;
    int r = strcoll(x, y);
    return r ? r : strcmp(x, y);
}

static int da_base_has(const char *key)
{
    for (int i = 0; i < g_base.n; i++)
        if (strcmp(g_base.row[i].key, key) == 0)
            return 1;
    return 0;
}

static int da_in_list(const char *const *list, int n, const char *key)
{
    for (int i = 0; i < n; i++)
        if (strcmp(list[i], key) == 0)
            return 1;
    return 0;
}

/* Sorted, unique found keys; the collation is the locale's, as `sort -u`. */
static int da_current(struct da_state *S, const char **out)
{
    int n = S->n_found;
    for (int i = 0; i < n; i++)
        out[i] = S->found[i].key;
    qsort(out, (size_t)n, sizeof out[0], da_cmp_str);
    int m = 0;
    for (int i = 0; i < n; i++)
        if (m == 0 || strcmp(out[m - 1], out[i]) != 0)
            out[m++] = out[i];
    return m;
}

static void da_print_new_one(const struct da_state *S, const char *key)
{
    const char *arrow = strstr(key, " -> ");
    if (!arrow)
        return;
    char pat[DA_KEY], fpat[DA_PATH + 2];
    if (ovf(snprintf(pat, sizeof pat, "%s", arrow), sizeof pat)
        || ovf(snprintf(fpat, sizeof fpat, "%.*s:", (int)(arrow - key), key), sizeof fpat))
        return;
    for (int i = 0; i < S->n_found; i++)
        if (strstr(S->found[i].line, pat) && strstr(S->found[i].line, fpat))
            fprintf(stderr, "  %s\n", S->found[i].line);
}

static void da_print_new(const struct da_state *S, const char **newk, int n_new)
{
    fprintf(stderr, "%s: FAIL — %d backticked path(s)/director(y|ies) in Markdown do not exist:\n",
            k_msg, n_new);
    for (int i = 0; i < n_new; i++)
        da_print_new_one(S, newk[i]);
    fputs("\n"
          "  Fix the DOC to match the tree (never move code to match a doc).\n"
          "  Find the real path:  z23 code sym --input='{\"name\":\"<symbol>\"}'\n"
          "                       git ls-files | grep '<basename>'\n"
          "  If the path is deliberately absent (a deleted file cited for git\n"
          "  recovery, an upstream project's file in an attribution), add\n"
          "  '<!-- doc-path-ok: <reason> -->' on that line.\n", stderr);
}

static void da_print_fixed(const char *baseline, const char **fixk, int n_fixed)
{
    fprintf(stderr, "%s: FAIL — %d baseline entr(y|ies) now resolve.\n", k_msg, n_fixed);
    fprintf(stderr, "  This baseline is shrink-only. Delete these lines from %s:\n", baseline);
    for (int i = 0; i < n_fixed; i++)
        fprintf(stderr, "  %s\n", fixk[i]);
}

static int da_report(struct da_state *S, const char *baseline)
{
    static const char *cur[DA_FOUND_MAX], *newk[DA_FOUND_MAX];
    static const char *fixk[LB_MAX];
    int n_cur = da_current(S, cur);
    int n_new = 0, still = 0, n_fixed = 0;
    for (int i = 0; i < n_cur; i++) {
        if (da_base_has(cur[i]))
            still++;
        else
            newk[n_new++] = cur[i];
    }
    for (int i = 0; i < g_base.n; i++)
        if (!da_in_list(cur, n_cur, g_base.row[i].key))
            fixk[n_fixed++] = g_base.row[i].key;
    qsort(fixk, (size_t)n_fixed, sizeof fixk[0], da_cmp_str);
    if (n_new)
        da_print_new(S, newk, n_new);
    if (n_fixed)
        da_print_fixed(baseline, fixk, n_fixed);
    if (n_new || n_fixed)
        return 1;
    return printf("%s: PASS (%d docs scanned, %d baselined, 0 new)\n",
                  k_msg, S->n_docs, still) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

/* ── gate entry ──────────────────────────────────────────────────────── */

int check_doc_inline_paths_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    memset(&g_da, 0, sizeof g_da);
    memset(&g_base, 0, sizeof g_base);
    setlocale(LC_COLLATE, "");
    struct da_state *S = &g_da;
    const char *baseline = env_or("ZCL_DOC_INLINE_PATHS_BASELINE", k_def_baseline);
    S->glob = env_or("ZCL_DOC_INLINE_PATHS_GLOB", k_def_glob);
    if (da_collect(S))
        return 2;
    if (gate_require_scanned(S->n_entries, 100, k_msg,
            "git ls-files returned almost nothing — not a repo checkout?"))
        return 2;
    char glob_hint[DA_PATH + 32];
    if (ovf(snprintf(glob_hint, sizeof glob_hint, "no tracked files matched: %s", S->glob),
            sizeof glob_hint))
        return 2;
    if (gate_require_scanned(S->n_docs, 1, k_msg, glob_hint))
        return 2;
    if (gate_require_scanned(S->set.n_module, 20, k_msg,
            "no two-component tracked directories — the module-directory prong would pass on anything"))
        return 2;
    if (da_scan_docs(S))
        return 2;
    if (gate_require_scanned(S->n_f, 200, k_msg,
            "the tokenizer found almost no backticked source paths — regex or corpus broke"))
        return 2;
    if (gate_require_scanned(S->n_d, 100, k_msg,
            "the tokenizer found almost no backticked module directories — regex or corpus broke"))
        return 2;
    if (lint_base_load_set(&g_base, baseline))
        return 2;
    return da_report(S, baseline);
}

/* ── selftest: the pure rules on known inputs ────────────────────────── */

static int da_st_norm(const char *in, const char *want)
{
    char out[DA_PATH];
    if (da_norm(in, out, sizeof out) || strcmp(out, want) != 0) {
        fprintf(stderr, "check_doc_inline_paths selftest: norm(%s) want %s\n", in, want);
        return 1;
    }
    return 0;
}

static int da_st_strip(const char *in, const char *want)
{
    char buf[256];
    if (ovf(snprintf(buf, sizeof buf, "%s", in), sizeof buf))
        return 1;
    da_strip_links(buf);
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "check_doc_inline_paths selftest: strip(%s) want %s\n", in, want);
        return 1;
    }
    return 0;
}

static int da_st_file(const char *seg, int want)
{
    size_t base = 0;
    int got = da_file_seg(seg, strlen(seg), &base);
    if (got != want) {
        fprintf(stderr, "check_doc_inline_paths selftest: file token %s want %d\n", seg, want);
        return 1;
    }
    return 0;
}

int check_doc_inline_paths_selftest(void)
{
    int fails = 0;
    fails += da_st_norm("./a/../b.c", "b.c");
    fails += da_st_norm("x/a/../b/c.h", "x/b/c.h");
    fails += da_st_norm("a/../../b.c", "../b.c");
    fails += da_st_strip("see [`a/b.c`](https://example.com/x) and `c/d.c`",
                         "see  and `c/d.c`");
    fails += da_st_strip("keep [`a/b.c`](./target) here", "keep [`a/b.c`](./target) here");
    fails += da_st_file("lib/x.c:12-14", 1);
    fails += da_st_file("lib/x.c", 1);
    fails += da_st_file("lib/x.cc:7", 1);
    fails += da_st_file(".c", 0);
    fails += da_st_file("lib/x.c:", 0);
    if (fails)
        return 1;
    return printf("[check_doc_inline_paths] SELFTEST PASS (norm collapses ./ and ../; "
                  "external links strip; file tokens classify)\n") < 0
        ? die("z23-lint: write failed\n", "") : 0;
}
