/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Count the C23 lines of one committed tree, exactly, from git objects.
 *
 * code.count answers "how many lines of C23 are in the project" for ONE
 * commit. It reads committed objects only (`git ls-tree -r -l` for the
 * blob ids and sizes, `git grep -c ''` for the blobs it has not counted
 * before), never the working tree, so a stale checkout cannot change the
 * answer. A line count is a pure function of a blob's bytes, so counts are
 * cached per blob id in .codeindex/code_count.v1 (gitignored derived state):
 * a later commit pays only for blobs it has not seen.
 *
 * Counting rule = `git grep -c ''`: one per line, a final unterminated line
 * counts, an empty blob is zero. Symlinks are not files and are not counted.
 * A path that git would quote (tab, newline, quote) is refused, not guessed.
 */

#include "command/native_command.h"
#include "command/native_dev_fleet_internal.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CC_CAPTURE_INITIAL = 1024 * 1024,
    CC_CAPTURE_MAX = 256 * 1024 * 1024,
    CC_CACHE_MAX = 64 * 1024 * 1024,
    CC_PATH_MAX = 512,
    CC_SUBSET_MAX = 6,
    CC_ARG_MAX = 14,
};

struct cc_file {
    char *path;
    unsigned char id[20];
    uint64_t size;
    uint64_t lines;
    bool have;
    bool test;
};

struct cc_row {
    unsigned char id[20];
    uint64_t lines;
};

struct cc_opts {
    const char *at;
    char path[CC_PATH_MAX];
    char exclude[CC_PATH_MAX];
};

struct cc_tree {
    char *text;
    struct cc_file *files;
    size_t count;
};

static const char *cc_input_str(const struct zcl_command_request *request,
                                const char *key, const char *fallback)
{
    const struct json_value *in = request->input;
    const char *s = in && in->type == JSON_OBJ ? json_get_str(json_get(in, key))
                                                : NULL;
    return s && s[0] ? s : fallback;
}

static void cc_refuse(struct zcl_command_reply *reply, enum zcl_command_exit ex,
                      const char *code, const char *phase, const char *why,
                      const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ex, code, phase,
                           false, false, why, evidence ? evidence : "");
}

/* A repo-relative prefix: no glob/pathspec magic, no "..", not absolute. */
static bool cc_prefix_ok(const char *p)
{
    if (p[0] == '/')
        return false;
    for (const char *c = p; *c; c++) {
        unsigned char u = (unsigned char)*c;
        if (u < 0x20 || u == 0x7f || strchr("*?[]\\:\"", *c))
            return false;
        bool start = c == p || c[-1] == '/';
        if (start && c[0] == '.' && (c[1] == '/' || c[1] == '\0' ||
                                     (c[1] == '.' && (c[2] == '/' || !c[2]))))
            return false;
    }
    return true;
}

/* Copy `src` into dst without trailing slashes; false when it does not fit
 * or is not a plain prefix. */
static bool cc_prefix_copy(char *dst, const char *src)
{
    size_t n = strlen(src);
    while (n > 0 && src[n - 1] == '/')
        n--;
    if (n >= CC_PATH_MAX)
        return false;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return cc_prefix_ok(dst);
}

static bool cc_read_opts(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, struct cc_opts *o)
{
    const char *lang = cc_input_str(request, "lang", "c");
    const char *ex = cc_input_str(request, "exclude", "vendor");
    o->at = cc_input_str(request, "at", "HEAD");
    if (strcmp(lang, "c") != 0) {
        cc_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_COUNT_LANG",
                  "validate", "lang must be c (.c and .h)", lang);
        return false;
    }
    if (o->at[0] == '-' || strlen(o->at) > 200 || strpbrk(o->at, "\n\r")) {
        cc_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_COUNT_AT",
                  "validate", "at must be a revision, not an option", o->at);
        return false;
    }
    bool path_ok = cc_prefix_copy(o->path, cc_input_str(request, "path", ""));
    if (!path_ok) {
        cc_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_COUNT_PATH",
                  "validate", "path must be a plain repo-relative prefix", "");
        return false;
    }
    if (strcmp(ex, "none") == 0)
        o->exclude[0] = '\0';
    else if (!cc_prefix_copy(o->exclude, ex)) {
        cc_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_CODE_COUNT_EXCLUDE",
                  "validate", "exclude must be a plain prefix or none", "");
        return false;
    }
    return true;
}

/* Run git and capture stdout, growing until the helper proves it did not
 * truncate. rc 0 is success; rc 1 is also accepted when allow_rc1 (grep with
 * no match). NULL on any other outcome. */
static char *cc_git(const char *root, const char *const args[], bool allow_rc1,
                    size_t initial)
{
    for (size_t cap = initial; cap <= CC_CAPTURE_MAX; cap *= 2) {
        char *out = zcl_malloc(cap, "code_count_git");
        if (!out)
            return NULL;
        bool truncated = false;
        int rc = zcl_dev_fleet_git_capture(root, args, out, cap, &truncated);
        bool ok = rc == 0 || (allow_rc1 && rc == 1);
        if (ok && !truncated)
            return out;
        free(out);
        if (!ok)
            return NULL;
    }
    return NULL;
}

/* 40 lowercase hex characters at s (not necessarily NUL-terminated after). */
static bool cc_hex20(const char *s, unsigned char out[20])
{
    char tmp[41];
    if (strnlen(s, 40) < 40)
        return false;
    memcpy(tmp, s, 40);
    tmp[40] = '\0';
    return zcl_hex_decode_lower(tmp, out, 20);
}

static bool cc_has_suffix(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

static bool cc_under(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    return n > 0 && strncmp(path, prefix, n) == 0 &&
           (path[n] == '/' || path[n] == '\0');
}

enum cc_line_verdict { CC_SKIP, CC_TAKE, CC_BAD };

/* One `git ls-tree -r -l` record: "<mode> blob <40hex> <size>\t<path>". */
static enum cc_line_verdict cc_parse_line(char *line, const struct cc_opts *o,
                                          struct cc_file *f)
{
    char *tab = strchr(line, '\t');
    if (!tab)
        return CC_BAD;
    *tab = '\0';
    f->path = tab + 1;
    if (strncmp(line, "100", 3) != 0 || strncmp(line + 6, " blob ", 6) != 0)
        return CC_SKIP; /* symlink, submodule: no countable bytes */
    if (!cc_has_suffix(f->path, ".c") && !cc_has_suffix(f->path, ".h"))
        return CC_SKIP;
    if (o->exclude[0] && cc_under(f->path, o->exclude))
        return CC_SKIP;
    if (f->path[0] == '"')
        return CC_BAD;
    if (!cc_hex20(line + 12, f->id) || line[52] != ' ')
        return CC_BAD;
    char *end = NULL;
    f->size = strtoull(line + 53, &end, 10);
    if (end == line + 53 || *end != '\0')
        return CC_BAD;
    f->test = strncmp(f->path, "tests/", 6) == 0;
    f->lines = 0;
    f->have = f->size == 0;
    return CC_TAKE;
}

/* A record is one line, so the line count bounds the file array: one
 * allocation, no growth path. */
static bool cc_parse_tree(struct cc_tree *t, const struct cc_opts *o)
{
    size_t lines = 1;
    for (const char *p = t->text; (p = strchr(p, '\n')) != NULL; p++)
        lines++;
    t->files = zcl_malloc(lines * sizeof *t->files, "code_count_files");
    if (!t->files)
        return false;
    for (char *line = t->text; *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        struct cc_file f = {0};
        enum cc_line_verdict v = cc_parse_line(line, o, &f);
        if (v == CC_BAD)
            return false;
        if (v == CC_TAKE)
            t->files[t->count++] = f;
        if (!nl)
            break;
        line = nl + 1;
    }
    return true;
}

static void cc_tree_free(struct cc_tree *t)
{
    free(t->text);
    free(t->files);
}

/* ---- the per-blob cache: lines of "<40hex> <decimal>\n" ---- */

static int cc_row_cmp(const void *a, const void *b)
{
    return memcmp(((const struct cc_row *)a)->id, ((const struct cc_row *)b)->id,
                  20);
}

static bool cc_cache_path(const char *root, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.codeindex/code_count.v1", root);
    return n > 0 && (size_t)n < cap;
}

static bool cc_cache_row(const char *line, size_t len, struct cc_row *row)
{
    if (len < 42 || !cc_hex20(line, row->id) || line[40] != ' ')
        return false;
    uint64_t value = 0;
    for (size_t i = 41; i < len; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c < '0' || c > '9')
            return false;
        unsigned digit = (unsigned)(c - '0');
        if (value > (UINT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    row->lines = value;
    return true;
}

/* Strictly parsed: any malformed or torn line is ignored, never trusted. */
static size_t cc_cache_load(const char *path, struct cc_row **rows)
{
    *rows = NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return 0;
    char *text = zcl_malloc(CC_CACHE_MAX + 1, "code_count_cache");
    size_t len = text ? fread(text, 1, CC_CACHE_MAX, fp) : 0;
    (void)fclose(fp);
    size_t cap = len / 42 + 1, n = 0;
    struct cc_row *out = len ? zcl_malloc(cap * sizeof *out, "code_count_rows")
                             : NULL;
    for (char *line = text; out && line < text + len;) {
        char *nl = memchr(line, '\n', (size_t)(text + len - line));
        if (!nl)
            break; /* torn tail */
        if (n < cap && cc_cache_row(line, (size_t)(nl - line), &out[n]))
            n++;
        line = nl + 1;
    }
    free(text);
    if (n > 1)
        qsort(out, n, sizeof *out, cc_row_cmp);
    *rows = out;
    return n;
}

static size_t cc_apply_cache(struct cc_tree *t, const struct cc_row *rows,
                             size_t nrows)
{
    size_t hits = 0;
    for (size_t i = 0; i < t->count && nrows; i++) {
        struct cc_row key = {0};
        memcpy(key.id, t->files[i].id, 20);
        const struct cc_row *r = bsearch(&key, rows, nrows, sizeof *rows,
                                         cc_row_cmp);
        if (r && !t->files[i].have) {
            t->files[i].lines = r->lines;
            t->files[i].have = true;
            hits++;
        }
    }
    return hits;
}

/* Append the new rows; best effort, reported. A leading newline keeps a torn
 * earlier append from gluing onto the first new record. */
static size_t cc_cache_store(const char *path, const struct cc_tree *t,
                             const bool *fresh)
{
    size_t want = 0;
    for (size_t i = 0; i < t->count; i++)
        want += fresh[i];
    if (want == 0)
        return 0;
    char dir[1100];
    (void)snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (platform_directory_create(dir, 0777) != 0 && errno != EEXIST)
            return 0;
    }
    char *text = zcl_malloc(want * 64 + 2, "code_count_store");
    if (!text)
        return 0;
    size_t len = 0, wrote = 0;
    text[len++] = '\n';
    for (size_t i = 0; i < t->count; i++) {
        if (!fresh[i])
            continue;
        zcl_hex_encode(t->files[i].id, 20, text + len);
        len += 40;
        len += (size_t)snprintf(text + len, 24, " %llu\n",
                                (unsigned long long)t->files[i].lines);
        wrote++;
    }
    FILE *fp = fopen(path, "ab");
    bool ok = fp && fwrite(text, 1, len, fp) == len;
    if (fp && fclose(fp) != 0)
        ok = false;
    free(text);
    return ok ? wrote : 0;
}

/* ---- counting the blobs the cache has not seen ---- */

static int cc_file_path_cmp(const void *a, const void *b)
{
    return strcmp((*(const struct cc_file *const *)a)->path,
                  (*(const struct cc_file *const *)b)->path);
}

static struct cc_file *cc_find(struct cc_file **sorted, size_t n,
                               const char *path)
{
    struct cc_file key = {.path = (char *)path};
    struct cc_file *kp = &key;
    struct cc_file **hit = bsearch(&kp, sorted, n, sizeof *sorted,
                                   cc_file_path_cmp);
    return hit ? *hit : NULL;
}

/* Apply "<commit>:<path>:<count>" lines from git grep -c to the files. */
static bool cc_apply_grep(struct cc_tree *t, char *text, const char *commit)
{
    struct cc_file **sorted = zcl_malloc((t->count + 1) * sizeof *sorted,
                                         "code_count_sorted");
    if (!sorted)
        return false;
    for (size_t i = 0; i < t->count; i++)
        sorted[i] = &t->files[i];
    qsort(sorted, t->count, sizeof *sorted, cc_file_path_cmp);
    size_t plen = strlen(commit) + 1;
    bool ok = true;
    for (char *line = text; *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        char *colon = strrchr(line, ':');
        struct cc_file *f = NULL;
        if (colon && strncmp(line, commit, plen - 1) == 0 && line[plen - 1] == ':' &&
            colon >= line + plen) {
            *colon = '\0';
            f = cc_find(sorted, t->count, line + plen);
            if (f) {
                f->lines = strtoull(colon + 1, NULL, 10);
                f->have = true;
            }
        }
        /* A line for a path this count did not list is not ours; the caller
         * still demands a count for every listed blob. */
        line = nl ? nl + 1 : line + strlen(line);
    }
    free(sorted);
    return ok;
}

/* Spec storage for the pathspec arguments of one git grep. */
struct cc_specs {
    char buf[CC_SUBSET_MAX + 3][CC_PATH_MAX + 32];
    size_t n;
};

static bool cc_spec(struct cc_specs *s, const char *magic, const char *path,
                    const char *tail)
{
    if (s->n >= sizeof s->buf / sizeof s->buf[0])
        return false;
    int w = snprintf(s->buf[s->n], sizeof s->buf[0], ":(%s)%s%s", magic, path,
                     tail);
    if (w < 0 || (size_t)w >= sizeof s->buf[0])
        return false;
    s->n++;
    return true;
}

static bool cc_scope_specs(struct cc_specs *s, const struct cc_opts *o)
{
    if (cc_has_suffix(o->path, ".c") || cc_has_suffix(o->path, ".h"))
        return cc_spec(s, "top", o->path, "");
    const char *sep = o->path[0] ? "/" : "";
    char a[CC_PATH_MAX + 8], b[CC_PATH_MAX + 8];
    (void)snprintf(a, sizeof a, "%s%s*.c", o->path, sep);
    (void)snprintf(b, sizeof b, "%s%s*.h", o->path, sep);
    return cc_spec(s, "top", a, "") && cc_spec(s, "top", b, "");
}

/* Few misses: name them. Many: the scope, minus the exclusion. */
static bool cc_miss_specs(struct cc_specs *s, const struct cc_tree *t,
                          size_t misses, const struct cc_opts *o)
{
    if (misses > CC_SUBSET_MAX) {
        if (!cc_scope_specs(s, o))
            return false;
        return !o->exclude[0] || cc_spec(s, "exclude,top", o->exclude, "");
    }
    for (size_t i = 0; i < t->count; i++)
        if (!t->files[i].have && !cc_spec(s, "top,literal", t->files[i].path, ""))
            return false;
    return true;
}

static bool cc_count_misses(const char *root, const char *commit,
                            struct cc_tree *t, size_t misses,
                            const struct cc_opts *o)
{
    struct cc_specs *specs = zcl_malloc(sizeof *specs, "code_count_specs");
    if (!specs)
        return false;
    specs->n = 0;
    const char *args[CC_ARG_MAX + 1] = {"grep", "-c",       "-e", "",
                                        "--full-name", "--no-color", commit,
                                        "--"};
    size_t n = 8;
    bool ok = cc_miss_specs(specs, t, misses, o) && n + specs->n <= CC_ARG_MAX;
    for (size_t i = 0; ok && i < specs->n; i++)
        args[n++] = specs->buf[i];
    args[n] = NULL;
    char *out = ok ? cc_git(root, args, true, CC_CAPTURE_INITIAL) : NULL;
    ok = out && cc_apply_grep(t, out, commit);
    free(out);
    free(specs);
    return ok;
}

/* ---- resolving the commit and tree ---- */

static bool cc_resolve(const char *root, const char *at, char commit[41],
                       char tree[41])
{
    char rev_c[256], rev_t[256];
    (void)snprintf(rev_c, sizeof rev_c, "%s^{commit}", at);
    const char *args[] = {"rev-parse", "--verify", "-q", rev_c, NULL};
    char *out = cc_git(root, args, false, CC_CAPTURE_INITIAL);
    bool ok = out && strlen(out) >= 40 && cc_hex20(out, (unsigned char[20]){0});
    if (ok) {
        memcpy(commit, out, 40), commit[40] = '\0';
        (void)snprintf(rev_t, sizeof rev_t, "%s^{tree}", commit);
    }
    free(out);
    args[3] = rev_t;
    out = ok ? cc_git(root, args, false, CC_CAPTURE_INITIAL) : NULL;
    ok = out && strlen(out) >= 40;
    if (ok)
        memcpy(tree, out, 40), tree[40] = '\0';
    free(out);
    return ok;
}

struct cc_sum {
    uint64_t files, lines, test_files, test_lines;
};

static struct cc_sum cc_totals(const struct cc_tree *t)
{
    struct cc_sum s = {0};
    for (size_t i = 0; i < t->count; i++) {
        s.files++;
        s.lines += t->files[i].lines;
        s.test_files += t->files[i].test;
        s.test_lines += t->files[i].test ? t->files[i].lines : 0;
    }
    return s;
}

static void cc_push_pair(struct json_value *obj, const char *key,
                         uint64_t files, uint64_t lines)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_int(&o, "files", (int64_t)files);
    (void)json_push_kv_int(&o, "lines", (int64_t)lines);
    (void)json_push_kv(obj, key, &o);
    json_free(&o);
}

static void cc_render(struct zcl_command_reply *reply, const struct cc_opts *o,
                      const char *commit, const char *tree,
                      const struct cc_tree *t, size_t hits, size_t misses,
                      size_t stored)
{
    struct cc_sum s = cc_totals(t);
    char headline[256];
    (void)snprintf(headline, sizeof headline,
                   "%llu lines of C23 in %llu files at %.12s",
                   (unsigned long long)s.lines, (unsigned long long)s.files,
                   commit);
    struct json_value *d = &reply->data;
    (void)json_push_kv_str(d, "headline", headline);
    (void)json_push_kv_str(d, "commit", commit);
    (void)json_push_kv_str(d, "tree", tree);
    (void)json_push_kv_str(d, "at", o->at);
    (void)json_push_kv_str(d, "path", o->path);
    (void)json_push_kv_str(d, "lang", "c");
    (void)json_push_kv_str(d, "exclude", o->exclude[0] ? o->exclude : "none");
    (void)json_push_kv_int(d, "files", (int64_t)s.files);
    (void)json_push_kv_int(d, "lines", (int64_t)s.lines);
    cc_push_pair(d, "tests", s.test_files, s.test_lines);
    cc_push_pair(d, "other", s.files - s.test_files, s.lines - s.test_lines);
    struct json_value cache;
    json_init(&cache);
    json_set_object(&cache);
    (void)json_push_kv_int(&cache, "hits", (int64_t)hits);
    (void)json_push_kv_int(&cache, "counted", (int64_t)misses);
    (void)json_push_kv_int(&cache, "stored", (int64_t)stored);
    (void)json_push_kv(d, "cache", &cache);
    json_free(&cache);
}

struct cc_stats {
    size_t hits, misses, stored;
};

/* Fill every file's count: the cache first, git grep for the rest, then
 * remember what was newly counted. False when any file stays uncounted. */
static bool cc_fill_counts(const char *root, const char *commit,
                           struct cc_tree *t, const struct cc_opts *o,
                           struct cc_stats *st)
{
    char cache_path[1100];
    struct cc_row *rows = NULL;
    bool cached = cc_cache_path(root, cache_path, sizeof cache_path);
    size_t nrows = cached ? cc_cache_load(cache_path, &rows) : 0;
    st->hits = cc_apply_cache(t, rows, nrows);
    free(rows);
    bool *fresh = zcl_malloc(t->count + 1, "code_count_fresh");
    for (size_t i = 0; fresh && i < t->count; i++) {
        fresh[i] = !t->files[i].have;
        st->misses += fresh[i];
    }
    bool ok = fresh && (st->misses == 0 ||
                        cc_count_misses(root, commit, t, st->misses, o));
    for (size_t i = 0; ok && i < t->count; i++)
        ok = t->files[i].have;
    if (ok && cached)
        st->stored = cc_cache_store(cache_path, t, fresh);
    free(fresh);
    return ok;
}

static bool cc_list_tree(const char *root, const char *commit,
                         const struct cc_opts *o, struct cc_tree *t)
{
    const char *args[] = {"ls-tree", "--full-tree", "-r", "-l", commit, "--",
                          o->path, NULL};
    if (!o->path[0])
        args[5] = NULL;
    t->text = cc_git(root, args, false, 2 * CC_CAPTURE_INITIAL);
    return t->text && cc_parse_tree(t, o);
}

void zcl_native_handle_code_count(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    const char *root = zcl_native_source_root(request);
    struct cc_opts o;
    char commit[41], tree[41];
    if (!cc_read_opts(request, reply, &o))
        return;
    if (!cc_resolve(root, o.at, commit, tree)) {
        cc_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "CODE_COUNT_REV", "execute",
                  "revision does not name a commit in this repository", o.at);
        return;
    }
    struct cc_tree t = {0};
    struct cc_stats st = {0};
    if (!cc_list_tree(root, commit, &o, &t))
        cc_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "CODE_COUNT_TREE", "execute",
                  "git ls-tree failed or listed a path git would quote", commit);
    else if (!cc_fill_counts(root, commit, &t, &o, &st))
        cc_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "CODE_COUNT_GREP", "execute",
                  "git grep did not report every non-empty blob", commit);
    else
        cc_render(reply, &o, commit, tree, &t, st.hits, st.misses, st.stored);
    cc_tree_free(&t);
}
