/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: parsers for check-package-capabilities (gate_package_capabilities.c) —
 * engine/composition/capability_classes.def, the ZCL_MODULE_CAPABILITY rows,
 * the ZCODE_PACKAGE registry rows, a manifest's top-level JSON array fields,
 * and the shipped-source enumeration (files[] honoured exactly, else
 * src+.c and tests+.c). Ported alongside tools/lint/check_package_capabilities.sh
 * and tools/lint/zcode_pkg_sources.sh, which check_package_capabilities.sh
 * sourced.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gate_package_capabilities_priv.h"

int pc_capset_has(const struct pc_capset *s, const char *name)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i], name) == 0)
            return 1;
    return 0;
}
int pc_capset_add(struct pc_capset *s, const char *name)
{
    if (pc_capset_has(s, name))
        return 0;
    if (s->n >= PC_MAXCAPS || strlen(name) >= (size_t)PC_ARRLEN)
        return die("z23-lint: package-capabilities class-set overflow\n", "");
    memcpy(s->v[s->n++], name, strlen(name) + 1);
    return 0;
}

/* ── engine/composition/capability_classes.def ───────────────────────────── */
/* ZCL_CAPABILITY_CLASS(NETWORK, ...) -> "CAP_NETWORK", one per occurrence. */
int pc_load_classes(const char *path, struct sr_set *out, int *n_lines)
{
    *n_lines = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        (void)n;
        const char *m = strstr(line, "ZCL_CAPABILITY_CLASS(");
        if (!m)
            continue;
        const char *p = m + 21;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!isupper((unsigned char)*p))
            continue;
        const char *q = p;
        while (isupper((unsigned char)*q) || isdigit((unsigned char)*q) || *q == '_')
            q++;
        char name[PC_ARRLEN];
        if (ovf(snprintf(name, sizeof name, "CAP_%.*s", (int)(q - p), p), sizeof name)) {
            rc = 2;
            break;
        }
        rc = sr_add(out, name);
        if (rc == 0)
            (*n_lines)++;
    }
    return fin(f, line, path, rc);
}

/* ── engine/composition/module_capabilities*.def ─────────────────────────── */
struct pc_pathcaps *pc_modtable_find(struct pc_modtable *t, const char *path)
{
    for (int i = 0; i < t->n; i++)
        if (strcmp(t->rows[i].path, path) == 0)
            return &t->rows[i];
    return NULL;
}
static struct pc_pathcaps *pc_modtable_touch(struct pc_modtable *t, const char *path)
{
    struct pc_pathcaps *r = pc_modtable_find(t, path);
    if (r)
        return r;
    if (t->n >= PC_MAXPATH || strlen(path) >= (size_t)PC_PATHLEN)
        return NULL;
    r = &t->rows[t->n++];
    memset(r, 0, sizeof *r);
    memcpy(r->path, path, strlen(path) + 1);
    return r;
}
static int pc_extract_first_string(const char *line, char *out, size_t cap,
                                   const char **after)
{
    const char *q1 = strchr(line, '"');
    if (!q1)
        return 1;
    const char *q2 = strchr(q1 + 1, '"');
    if (!q2)
        return 1;
    size_t len = (size_t)(q2 - q1 - 1);
    if (len >= cap)
        return 2;
    memcpy(out, q1 + 1, len);
    out[len] = '\0';
    *after = q2 + 1;
    return 0;
}
static int pc_row_classes(const char *rest, struct pc_capset *toks)
{
    const char *m = strstr(rest, "CAP_");
    if (!m)
        return 0;
    const char *q = m;
    while (*q && (isalnum((unsigned char)*q) || *q == '_' || *q == '|'))
        q++;
    const char *p = m;
    while (p < q) {
        const char *bar = memchr(p, '|', (size_t)(q - p));
        size_t tl = bar ? (size_t)(bar - p) : (size_t)(q - p);
        char tok[PC_ARRLEN];
        if (tl > 0 && tl < sizeof tok) {
            memcpy(tok, p, tl);
            tok[tl] = '\0';
            if (strcmp(tok, "CAP_NONE") != 0 && pc_capset_add(toks, tok))
                return 2;
        }
        p += tl + 1;
    }
    return 0;
}
static int pc_load_module_file(const char *path, struct pc_modtable *out, int *n_rows)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        (void)n;
        if (!strstr(line, "ZCL_MODULE_CAPABILITY("))
            continue;
        char rpath[PC_PATHLEN];
        const char *after = NULL;
        if (pc_extract_first_string(line, rpath, sizeof rpath, &after) != 0)
            continue;
        struct pc_capset toks = { .n = 0 };
        if (pc_row_classes(after, &toks) == 2) {
            rc = 2;
            break;
        }
        struct pc_pathcaps *row = pc_modtable_touch(out, rpath);
        if (!row) {
            rc = die("z23-lint: package-capabilities module-table overflow\n", "");
            break;
        }
        for (int i = 0; i < toks.n; i++)
            if (pc_capset_add(&row->caps, toks.v[i])) {
                rc = 2;
                break;
            }
        (*n_rows)++;
    }
    return fin(f, line, path, rc);
}
int pc_load_module_rows(const char *const *paths, int npaths, struct pc_modtable *out,
                        int *n_rows)
{
    out->n = 0;
    *n_rows = 0;
    for (int i = 0; i < npaths; i++) {
        int rc = pc_load_module_file(paths[i], out, n_rows);
        if (rc == -1)
            continue;
        if (rc)
            return rc;
    }
    return 0;
}

/* ── ZCODE_PACKAGE registry rows: first two quoted strings = name, dir ──── */
static int pc_load_registry_file(const char *path, struct pc_pkg *out, int cap,
                                 int *n_out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t lc = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &lc, f)) >= 0) {
        (void)n;
        if (strncmp(line, "ZCODE_PACKAGE(", 14) != 0)
            continue;
        char name[PC_NAMELEN], dir[PC_DIRLEN];
        const char *after = NULL;
        if (pc_extract_first_string(line, name, sizeof name, &after) != 0)
            continue;
        if (pc_extract_first_string(after, dir, sizeof dir, &after) != 0)
            continue;
        if (*n_out >= cap) {
            rc = die("z23-lint: package-capabilities registry overflow\n", "");
            break;
        }
        memcpy(out[*n_out].name, name, strlen(name) + 1);
        memcpy(out[*n_out].dir, dir, strlen(dir) + 1);
        (*n_out)++;
    }
    return fin(f, line, path, rc);
}
int pc_load_registry(const char *const *paths, int npaths, struct pc_pkg *out, int cap,
                     int *n_out)
{
    *n_out = 0;
    for (int i = 0; i < npaths; i++) {
        int rc = pc_load_registry_file(paths[i], out, cap, n_out);
        if (rc == -1)
            continue;
        if (rc)
            return rc;
    }
    return 0;
}

/* ── manifest JSON: top-level array field <key> ──────────────────────────── */
static void pc_emit_quoted(const char *s, char out[][PC_ARRLEN], int cap, int *n)
{
    const char *p = s;
    while (*p) {
        const char *q1 = strchr(p, '"');
        if (!q1)
            break;
        const char *q2 = strchr(q1 + 1, '"');
        if (!q2)
            break;
        size_t len = (size_t)(q2 - q1 - 1);
        if (*n < cap && len < (size_t)PC_ARRLEN) {
            memcpy(out[*n], q1 + 1, len);
            out[*n][len] = '\0';
            (*n)++;
        }
        p = q2 + 1;
    }
}
int pc_json_array(const char *manifest, const char *key, char out[][PC_ARRLEN], int cap,
                  int *n)
{
    *n = 0;
    FILE *f = fopen(manifest, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", manifest);
    char *line = NULL;
    size_t lc = 0;
    ssize_t rn;
    int inarr = 0, found = 0;
    char needle[PC_ARRLEN + 4];
    if (ovf(snprintf(needle, sizeof needle, "\"%s\"", key), sizeof needle)) {
        fclose(f);
        return 2;
    }
    while ((rn = getline(&line, &lc, f)) >= 0) {
        (void)rn;
        if (inarr) {
            pc_emit_quoted(line, out, cap, n);
            if (strchr(line, ']'))
                inarr = 0;
            continue;
        }
        char *m = strstr(line, needle);
        if (!m)
            continue;
        char *p = m + strlen(needle);
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p != ':')
            continue;
        found = 1;
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        char *b = strchr(p, '[');
        if (!b) {
            inarr = 1;
            continue;
        }
        pc_emit_quoted(b + 1, out, cap, n);
        if (!strchr(b + 1, ']'))
            inarr = 1;
    }
    int bad = ferror(f);
    free(line);
    fclose(f);
    if (bad)
        return die("z23-lint: read failed: %s\n", manifest);
    return found ? 0 : 1;
}
static int pc_has_key(const char *manifest, const char *key)
{
    char out[1][PC_ARRLEN];
    int n = 0;
    return pc_json_array(manifest, key, out, 1, &n) == 0;
}

/* ── shipped sources ──────────────────────────────────────────────────────── */
static int pc_cmp_str(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }
static int pc_glob_dir(const char *base, const char *sub, char out[][PC_SRCLEN],
                       int cap, int *n)
{
    char dirpath[PC_PATHLEN * 2];
    if (ovf(snprintf(dirpath, sizeof dirpath, "%s/%s", base, sub), sizeof dirpath))
        return 2;
    DIR *d = opendir(dirpath);
    if (!d)
        return 0;
    int start = *n;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t nl = strlen(de->d_name);
        if (nl < 3 || strcmp(de->d_name + nl - 2, ".c") != 0)
            continue;
        if (*n >= cap) {
            closedir(d);
            return die("z23-lint: package-capabilities source overflow\n", "");
        }
        if (ovf(snprintf(out[*n], PC_SRCLEN, "%s/%s", dirpath, de->d_name), PC_SRCLEN)) {
            closedir(d);
            return 2;
        }
        (*n)++;
    }
    closedir(d);
    if (*n > start)
        qsort(out[start], (size_t)(*n - start), PC_SRCLEN, pc_cmp_str);
    return 0;
}
int pc_pkg_sources(const char *root, const char *dir, char out[][PC_SRCLEN], int cap,
                  int *n)
{
    *n = 0;
    char manifest[PC_PATHLEN * 2];
    if (ovf(snprintf(manifest, sizeof manifest, "%s/%s/zcode-package.json", root, dir),
            sizeof manifest))
        return 2;
    struct stat st;
    if (stat(manifest, &st) != 0)
        return -1;
    if (pc_has_key(manifest, "files")) {
        char arr[PC_MAXARR][PC_ARRLEN];
        int an = 0;
        int rc = pc_json_array(manifest, "files", arr, PC_MAXARR, &an);
        if (rc == 2)
            return 2;
        for (int i = 0; i < an; i++) {
            size_t l = strlen(arr[i]);
            if (l < 3 || strcmp(arr[i] + l - 2, ".c") != 0)
                continue;
            if (*n >= cap)
                return die("z23-lint: package-capabilities source overflow\n", "");
            if (ovf(snprintf(out[*n], PC_SRCLEN, "%s/%s", dir, arr[i]), PC_SRCLEN))
                return 2;
            (*n)++;
        }
        return 0;
    }
    char full[PC_PATHLEN];
    if (ovf(snprintf(full, sizeof full, "%s/%s", root, dir), sizeof full))
        return 2;
    if (pc_glob_dir(full, "src", out, cap, n))
        return 2;
    /* Rewrite the base-relative names pc_glob_dir wrote (rooted at `full`)
     * to repo-root-relative, prefixed with `dir`. */
    for (int i = 0; i < *n; i++) {
        char tmp[PC_SRCLEN];
        memcpy(tmp, out[i], sizeof tmp);
        const char *rel = tmp + strlen(full) + 1;
        if (ovf(snprintf(out[i], PC_SRCLEN, "%s/%s", dir, rel), PC_SRCLEN))
            return 2;
    }
    int before = *n;
    if (pc_glob_dir(full, "tests", out, cap, n))
        return 2;
    for (int i = before; i < *n; i++) {
        char tmp[PC_SRCLEN];
        memcpy(tmp, out[i], sizeof tmp);
        const char *rel = tmp + strlen(full) + 1;
        if (ovf(snprintf(out[i], PC_SRCLEN, "%s/%s", dir, rel), PC_SRCLEN))
            return 2;
    }
    return 0;
}
