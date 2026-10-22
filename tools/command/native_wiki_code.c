/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Source-tree branch of discover.wiki and discover.read - the
 * repository's directories and source files under the code/ prefix, with the
 * exclusions and summaries that keep the tree navigable. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_wiki_priv.h"

#include "codeindex/codeindex.h"
#include "json/json.h"
#include "util/path_util.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

bool wk_code_sub(const char *rel, size_t *off)
{
    if (strcmp(rel, "code") == 0)
        *off = 4;
    else if (strncmp(rel, "code/", 5) == 0)
        *off = 5;
    else
        return false;
    return true;
}

static bool wk_code_try(const char *cand, struct wk_docs *code)
{
    char marker[WK_PATH_MAX];
    code->code = true;
    if (!wk_canonicalize(cand, code->root, sizeof(code->root)) ||
        !zcl_path_is_dir(code->root))
        return false;
    return zcl_path_join(marker, sizeof(marker), code->root, "AGENTS.md") &&
           wk_is_file(marker);
}

bool wk_code_open(const struct zcl_command_request *request,
                  const struct wk_docs *docs, struct wk_docs *code)
{
    const char *over = json_get_str(json_get(request->input, "codedir"));
    char up[WK_PATH_MAX];
    size_t n = strlen(docs->root);
    if (over && over[0])
        return wk_code_try(over, code);
    if (n < 6 || strcmp(docs->root + n - 5, "/docs") != 0)
        return false;
    memcpy(up, docs->root, n - 5);
    up[n - 5] = '\0';
    return wk_code_try(up, code);
}

const char *wk_code_rel(const struct wk_docs *code, const char *real)
{
    size_t n = strlen(code->root);
    return real[n] == '/' ? real + n + 1 : real + n;
}

static bool wk_seg_is(const char *s, size_t n, const char *lit)
{
    return strlen(lit) == n && memcmp(s, lit, n) == 0;
}

static bool wk_top_denied(const char *s, size_t n)
{
    static const char *const top[] = { "build", "test-tmp", "dist", "docs" };
    for (size_t i = 0; i < sizeof(top) / sizeof(top[0]); i++)
        if (wk_seg_is(s, n, top[i]))
            return true;
    return false;
}

bool wk_code_denied(const char *rel)
{
    size_t depth = 0;
    bool vendor = false;
    for (const char *p = rel; *p; depth++) {
        const char *e = strchr(p, '/');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (p[0] == '.' || (depth == 0 && wk_top_denied(p, n)))
            return true;
        vendor = vendor || (depth == 0 && wk_seg_is(p, n, "vendor"));
        if (!e)
            break;
        p = e + 1;
    }
    return vendor && depth > 1;
}

bool wk_code_is_topic(const struct wk_docs *code, const char *real)
{
    return zcl_path_is_dir(real) && !wk_code_denied(wk_code_rel(code, real));
}

static bool wk_ends_with(const char *name, const char *ext)
{
    size_t n = strlen(name), e = strlen(ext);
    return n > e && strcmp(name + n - e, ext) == 0;
}

bool wk_code_ext_ok(const char *name)
{
    const char *dot = strrchr(name, '.');
    return dot && dot != name &&
           (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0 ||
            strcmp(dot, ".def") == 0 || strcmp(dot, ".sh") == 0 ||
            strcmp(dot, ".md") == 0);
}

/* The repository root lists directories only; a file is listed from the
 * level below it. */
int wk_code_classify(const struct wk_docs *code, const char *real,
                     const char *name)
{
    const char *rel = wk_code_rel(code, real);
    if (wk_code_denied(rel))
        return 0;
    if (zcl_path_is_dir(real))
        return 1;
    return strchr(rel, '/') && wk_is_file(real) && wk_code_ext_ok(name) ? 2 : 0;
}

const char *wk_code_index(const char *dir, char *buf, size_t cap, size_t *len)
{
    static const char *const names[] = { "AGENTS.md", "README.md" };
    char path[WK_PATH_MAX];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        if (n > 0 && (size_t)n < sizeof(path) && wk_head(path, buf, cap, len))
            return names[i];
    }
    return NULL;
}

static void wk_code_count(const char *dir, char *out, size_t cap)
{
    size_t files = 0, seen = 0;
    DIR *dp = opendir(dir);
    struct dirent *e;
    while (dp && (e = readdir(dp)) != NULL && seen++ < WK_SCAN_MAX) {
        char path[WK_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        files += n > 0 && (size_t)n < sizeof(path) && wk_is_file(path);
    }
    if (dp)
        closedir(dp);
    snprintf(out, cap, "%zu file%s", files, files == 1 ? "" : "s");
}

static bool wk_sh_skip(const char *s, size_t n)
{
    static const char *const lead[] = { "Copyright", "SPDX", "Licensed" };
    for (size_t i = 0; i < sizeof(lead) / sizeof(lead[0]); i++)
        if (n >= strlen(lead[i]) && memcmp(s, lead[i], strlen(lead[i])) == 0)
            return true;
    return n == 0;
}

/* First comment line of a shell script after the interpreter line. */
static void wk_sh_purpose(const char *head, size_t len, char *out, size_t cap)
{
    bool shebang = len > 1 && head[0] == '#' && head[1] == '!';
    out[0] = '\0';
    for (size_t i = 0; i < len; ) {
        const char *nl = memchr(head + i, '\n', len - i);
        size_t end = nl ? (size_t)(nl - head) : len;
        const char *s = head + i;
        size_t n = end - i;
        i = end + 1;
        if (shebang) {
            shebang = false;
            continue;
        }
        if (n == 0)
            continue;
        if (s[0] != '#')
            return;
        for (s++, n--; n && *s == ' '; s++, n--)
            ;
        if (!wk_sh_skip(s, n)) {
            snprintf(out, cap, "%.*s", (int)n, s);
            return;
        }
    }
}

void wk_code_purpose(const char *name, const char *head, size_t len,
                     char *out, size_t cap)
{
    char raw[CI_FILE_PURPOSE_MAX];
    if (wk_ends_with(name, ".sh"))
        wk_sh_purpose(head, len, raw, sizeof(raw));
    else
        codeindex_text_purpose(head, len, name, raw);
    size_t k = wk_clean(out, cap - 1, raw, strlen(raw), false, false);
    while (k > 0 && out[k - 1] == ' ')
        k--;
    out[k] = '\0';
}

void wk_code_child_meta(const char *dir, const struct wk_child *c,
                        struct wk_meta *meta)
{
    char path[WK_PATH_MAX], head[WK_HEAD_MAX + 1];
    size_t n = 0;
    int w = snprintf(path, sizeof(path), "%s/%s", dir, c->name);
    meta->title[0] = '\0';
    meta->summary[0] = '\0';
    if (w <= 0 || (size_t)w >= sizeof(path))
        return;
    if (c->topic) {
        if (wk_code_index(path, head, sizeof(head), &n))
            wk_meta_scan(head, n, meta);
        if (!meta->summary[0])
            wk_code_count(path, meta->summary, sizeof(meta->summary));
    } else if (wk_head(path, head, sizeof(head), &n)) {
        if (wk_ends_with(c->name, ".md"))
            wk_meta_scan(head, n, meta);
        else
            wk_code_purpose(c->name, head, n, meta->summary,
                            sizeof(meta->summary));
    }
}
