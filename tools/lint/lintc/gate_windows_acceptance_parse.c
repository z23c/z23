/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: catalog, registry and directory parsing for the
 * check-windows-acceptance gate (gate_windows_acceptance.c). These are C
 * ports of the awk passes of the deleted shell script: the active-ID list,
 * the _SOURCES IDs, every .c source of a _SOURCES assignment, the program
 * directories derived from each row's first source line, the
 * ZCL_TEST_GROUP registry names, the EXEMPT table and the on-disk scan of
 * a catalog directory. All state is fixed static; overflow is an error,
 * never a silent truncation.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_windows_acceptance_priv.h"

static const char k_wa_gate[] = "check-windows-acceptance";

int wa_slurp_rel(const char *root, const char *rel, char *buf, size_t cap)
{
    char path[WA_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 1;
    size_t got = 0;
    for (;;) {
        if (got + 1 >= cap) {
            fclose(f);
            return 2;
        }
        size_t r = fread(buf + got, 1, cap - got - 1, f);
        got += r;
        if (r == 0)
            break;
    }
    int bad = ferror(f) != 0;
    fclose(f);
    if (bad)
        return 2;
    buf[got] = '\0';
    return 0;
}

int wa_next_line(const char *buf, size_t *pos, char *out, size_t cap)
{
    size_t p = *pos;
    if (buf[p] == '\0')
        return 0;
    const char *nl = strchr(buf + p, '\n');
    size_t len = nl ? (size_t)(nl - (buf + p)) : strlen(buf + p);
    if (len >= cap)
        return -1;
    memcpy(out, buf + p, len);
    out[len] = '\0';
    *pos = nl ? (size_t)(nl - buf) + 1 : p + len;
    return 1;
}

static int wa_isid(int c)
{
    return isalnum(c) || c == '_';
}

/* Index of the first byte at or after i that is not a space or tab; s is
 * NUL-terminated at its length. */
static size_t wa_skip_blank(const char *s, size_t i)
{
    return i + strspn(s + i, " \t");
}

static int wa_hdr_tests(const char *s, size_t n)
{
    static const char p[] = "ZCL_WINDOWS_ACCEPTANCE_TESTS";
    const size_t pl = sizeof p - 1;
    if (n < pl || memcmp(s, p, pl))
        return 0;
    size_t i = wa_skip_blank(s, pl);
    if (i + 2 > n || s[i] != ':' || s[i + 1] != '=')
        return 0;
    i = wa_skip_blank(s, i + 2);
    if (i >= n || s[i] != '\\')
        return 0;
    i = wa_skip_blank(s, i + 1);
    return i == n;
}

/* Strips a trailing backslash-with-whitespace continuation plus surrounding
 * whitespace in place; returns whether a continuation was present. */
static int wa_strip_cont(char *s, size_t *n)
{
    size_t i = *n;
    while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t'))
        i--;
    int more = i > 0 && s[i - 1] == '\\';
    if (more) {
        i--;
        while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\t'))
            i--;
    }
    size_t j = 0;
    while (j < i && (s[j] == ' ' || s[j] == '\t'))
        j++;
    s[i] = '\0';
    memmove(s, s + j, i - j + 1);
    *n = i - j;
    return more;
}

static int wa_ends_cont(const char *s, size_t n)
{
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    return n > 0 && s[n - 1] == '\\';
}

/* Matches a ZCL_WINDOWS_ACCEPTANCE_<id>_SOURCES := row start; when id is
 * non-NULL the identifier is copied there. */
/* 1 when the text at j reads _SOURCES, blanks, then the := assignment. */
static int wa_row_assign(const char *s, size_t n, size_t j)
{
    if (j + 8 > n || memcmp(s + j, "_SOURCES", 8))
        return 0;
    size_t k = wa_skip_blank(s, j + 8);
    return k + 2 <= n && s[k] == ':' && s[k + 1] == '=';
}

static int wa_row_match(const char *s, size_t n, char *id)
{
    static const char p[] = "ZCL_WINDOWS_ACCEPTANCE_";
    const size_t pl = sizeof p - 1;
    if (n <= pl || memcmp(s, p, pl))
        return 0;
    size_t j = pl;
    while (j < n && wa_isid((unsigned char)s[j]))
        j++;
    if (j < pl + 9 || !wa_row_assign(s, n, j - 8))
        return 0;
    if (!id)
        return 1;
    size_t len = j - 8 - pl;
    if (len >= WA_ID)
        return -1;
    memcpy(id, s + pl, len);
    id[len] = '\0';
    return 1;
}

int wa_catalog_tests(const char *root, struct wa_ids *out)
{
    static char buf[WA_TEXT];
    int rc = wa_slurp_rel(root, WA_CATALOG_REL, buf, sizeof buf);
    if (rc)
        return 2;
    size_t pos = 0;
    char line[WA_LINE];
    int active = 0;
    int r;
    while ((r = wa_next_line(buf, &pos, line, sizeof line)) == 1) {
        size_t n = strlen(line);
        if (!active) {
            if (wa_hdr_tests(line, n))
                active = 1;
            continue;
        }
        int more = wa_strip_cont(line, &n);
        if (n) {
            if (n >= WA_ID || out->n >= WA_IDS) {
                fprintf(stderr, "%s: active ID table exceeds %d\n", k_wa_gate,
                        WA_IDS);
                return 2;
            }
            memcpy(out->v[out->n], line, n + 1);
            out->n++;
        }
        if (!more)
            break;
    }
    if (r < 0) {
        fprintf(stderr, "%s: catalog line exceeds %d\n", k_wa_gate, WA_LINE);
        return 2;
    }
    return 0;
}

int wa_catalog_source_ids(const char *root, struct wa_ids *out)
{
    static char buf[WA_TEXT];
    int rc = wa_slurp_rel(root, WA_CATALOG_REL, buf, sizeof buf);
    if (rc)
        return 2;
    size_t pos = 0;
    char line[WA_LINE], id[WA_ID];
    int m, r;
    while ((r = wa_next_line(buf, &pos, line, sizeof line)) == 1) {
        m = wa_row_match(line, strlen(line), id);
        if (m < 0) {
            fprintf(stderr, "%s: source ID exceeds %d\n", k_wa_gate, WA_ID);
            return 2;
        }
        if (m == 0)
            continue;
        if (out->n >= WA_IDS) {
            fprintf(stderr, "%s: source ID table exceeds %d\n", k_wa_gate,
                    WA_IDS);
            return 2;
        }
        strcpy(out->v[out->n++], id);
    }
    if (r < 0) {
        fprintf(stderr, "%s: catalog line exceeds %d\n", k_wa_gate, WA_LINE);
        return 2;
    }
    wa_ids_sort(out);
    return 0;
}

static int wa_is_c_token(const char *t)
{
    size_t n = strlen(t);
    if (n < 3 || strcmp(t + n - 2, ".c"))
        return 0;
    for (size_t i = 0; i + 2 < n; i++) {
        char c = t[i];
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' ||
              c == '/'))
            return 0;
    }
    return 1;
}

static int wa_emit_tokens(char *s, struct wa_names *out)
{
    for (size_t i = 0; s[i]; i++)
        if (s[i] == '\\')
            s[i] = ' ';
    for (char *t = strtok(s, " \t"); t; t = strtok(NULL, " \t")) {
        if (!wa_is_c_token(t))
            continue;
        if (out->n >= WA_NAMES || strlen(t) >= WA_PATH) {
            fprintf(stderr, "%s: catalog source table exceeds %d\n", k_wa_gate,
                    WA_NAMES);
            return 2;
        }
        strcpy(out->v[out->n++], t);
    }
    return 0;
}

static const char *wa_after_assign(const char *s)
{
    const char *c = strchr(s, ':');
    if (!c || c[1] != '=')
        return NULL;
    c += 2;
    while (*c == ' ' || *c == '\t')
        c++;
    return c;
}

int wa_catalog_sources(const char *root, struct wa_names *out)
{
    static char buf[WA_TEXT];
    int rc = wa_slurp_rel(root, WA_CATALOG_REL, buf, sizeof buf);
    if (rc)
        return 2;
    size_t pos = 0;
    char line[WA_LINE], tmp[WA_LINE];
    int active = 0;
    int r;
    while ((r = wa_next_line(buf, &pos, line, sizeof line)) == 1) {
        size_t n = strlen(line);
        if (wa_row_match(line, n, NULL)) {
            const char *as = wa_after_assign(line);
            if (!as)
                return 2;
            if (ovf(snprintf(tmp, sizeof tmp, "%s", as), sizeof tmp))
                return 2;
            if (wa_emit_tokens(tmp, out))
                return 2;
            active = wa_ends_cont(line, n);
        } else if (active) {
            if (ovf(snprintf(tmp, sizeof tmp, "%s", line), sizeof tmp))
                return 2;
            if (wa_emit_tokens(tmp, out))
                return 2;
            active = wa_ends_cont(line, n);
        }
    }
    if (r < 0) {
        fprintf(stderr, "%s: catalog line exceeds %d\n", k_wa_gate, WA_LINE);
        return 2;
    }
    wa_names_sort_unique(out);
    return 0;
}

/* The directory of the first source line after a row start. */
static int wa_add_progdir(char *s, struct wa_names *out)
{
    size_t n = strlen(s);
    wa_strip_cont(s, &n);
    if (n < 2 || strcmp(s + n - 2, ".c"))
        return 0;
    char *sl = strrchr(s, '/');
    if (sl)
        *sl = '\0';
    if (out->n >= WA_NAMES || strlen(s) >= WA_PATH) {
        fprintf(stderr, "%s: program-dir table exceeds %d\n", k_wa_gate,
                WA_NAMES);
        return 2;
    }
    strcpy(out->v[out->n++], s);
    return 0;
}

int wa_catalog_program_dirs(const char *root, struct wa_names *out)
{
    static char buf[WA_TEXT];
    int rc = wa_slurp_rel(root, WA_CATALOG_REL, buf, sizeof buf);
    if (rc)
        return 2;
    size_t pos = 0;
    char line[WA_LINE], next[WA_LINE];
    int r;
    while ((r = wa_next_line(buf, &pos, line, sizeof line)) == 1) {
        if (!wa_row_match(line, strlen(line), NULL))
            continue;
        if (wa_next_line(buf, &pos, next, sizeof next) != 1)
            break;
        if (wa_add_progdir(next, out))
            return 2;
    }
    if (r < 0) {
        fprintf(stderr, "%s: catalog line exceeds %d\n", k_wa_gate, WA_LINE);
        return 2;
    }
    wa_names_sort_unique(out);
    return 0;
}

static int wa_group_line(const char *s, char *name)
{
    while (*s == ' ' || *s == '\t')
        s++;
    if (strncmp(s, "ZCL_TEST_GROUP(", 15))
        return 0;
    const char *start = s + 15;
    size_t i = 0;
    while (wa_isid((unsigned char)start[i]))
        i++;
    if (i == 0 || start[i] != ')')
        return 0;
    const char *rest = start + i + 1;
    while (*rest == ' ' || *rest == '\t')
        rest++;
    if (*rest)
        return 0;
    if (i >= WA_ID)
        return -1;
    memcpy(name, start, i);
    name[i] = '\0';
    return 1;
}

int wa_registry_groups(const char *root, struct wa_names *out)
{
    static char buf[WA_TEXT];
    int rc = wa_slurp_rel(root, WA_REGISTRY_REL, buf, sizeof buf);
    if (rc)
        return 2;
    size_t pos = 0;
    char line[WA_LINE], name[WA_ID];
    int g, r;
    while ((r = wa_next_line(buf, &pos, line, sizeof line)) == 1) {
        g = wa_group_line(line, name);
        if (g < 0) {
            fprintf(stderr, "%s: group name exceeds %d\n", k_wa_gate, WA_ID);
            return 2;
        }
        if (g == 0)
            continue;
        if (out->n >= WA_NAMES) {
            fprintf(stderr, "%s: group table exceeds %d\n", k_wa_gate,
                    WA_NAMES);
            return 2;
        }
        strcpy(out->v[out->n++], name);
    }
    if (r < 0) {
        fprintf(stderr, "%s: registry line exceeds %d\n", k_wa_gate, WA_LINE);
        return 2;
    }
    wa_names_sort_unique(out);
    return 0;
}

static int wa_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

void wa_ids_sort(struct wa_ids *s)
{
    qsort(s->v, (size_t)s->n, WA_ID, wa_cmp);
}

void wa_names_sort_unique(struct wa_names *s)
{
    qsort(s->v, (size_t)s->n, WA_PATH, wa_cmp);
    int w = 0;
    for (int i = 0; i < s->n; i++)
        if (w == 0 || strcmp(s->v[w - 1], s->v[i]))
            strcpy(s->v[w++], s->v[i]);
    s->n = w;
}

/* Linear membership over a packed table of n fixed-width NUL-terminated rows. */
static int wa_rows_have(const char *rows, int n, size_t width, const char *name)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(rows + (size_t)i * width, name))
            return 1;
    return 0;
}

int wa_has(const struct wa_names *s, const char *name)
{
    return wa_rows_have(s->v[0], s->n, WA_PATH, name);
}

int wa_ids_has(const struct wa_ids *s, const char *name)
{
    return wa_rows_have(s->v[0], s->n, WA_ID, name);
}
int wa_ids_equal(const struct wa_ids *a, const struct wa_ids *b)
{
    if (a->n != b->n)
        return 0;
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->v[i], b->v[i]))
            return 0;
    return 1;
}

int wa_ids_dup(const struct wa_ids *s)
{
    for (int i = 1; i < s->n; i++)
        if (!strcmp(s->v[i - 1], s->v[i]))
            return 1;
    return 0;
}

int wa_file_group(const char *path, const struct wa_names *groups)
{
    regex_t re;
    if (regcomp(&re, "^int[[:space:]]+test_([A-Za-z0-9_]+)[(]void[)]",
                REG_EXTENDED))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        regfree(&re);
        return 0;
    }
    char line[WA_LINE];
    while (fgets(line, sizeof line, f)) {
        regmatch_t m[2];
        if (regexec(&re, line, 2, m, 0))
            continue;
        size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
        char name[WA_ID];
        if (len >= sizeof name)
            continue;
        memcpy(name, line + m[1].rm_so, len);
        name[len] = '\0';
        if (wa_has(groups, name)) {
            fclose(f);
            regfree(&re);
            return 1;
        }
    }
    fclose(f);
    regfree(&re);
    return 0;
}

/* Appends "dir/name" when the entry is a regular file. lstat matches
 * find -type f: a symlink or a directory is not a program on disk. */
static int wa_scan_one(const char *root, const char *dir, const char *name,
                       struct wa_names *out)
{
    char full[WA_PATH];
    struct stat st;
    if (ovf(snprintf(full, sizeof full, "%s/%s/%s", root, dir, name),
            sizeof full))
        return 2;
    if (lstat(full, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (out->n >= WA_NAMES)
        return 2;
    if (ovf(snprintf(out->v[out->n], WA_PATH, "%s/%s", dir, name), WA_PATH))
        return 2;
    out->n++;
    return 0;
}

int wa_scan_dir(const char *root, const char *dir, struct wa_names *out)
{
    char p[WA_PATH];
    size_t dl = strlen(dir);
    int tests_mode = dl >= 6 && !strcmp(dir + dl - 6, "/tests");
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, dir), sizeof p))
        return 2;
    DIR *d = opendir(p);
    if (!d)
        return 2;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        size_t ln = strlen(e->d_name);
        int ok = ln >= 13 && !strcmp(e->d_name + ln - 13, "_acceptance.c");
        if (tests_mode)
            ok = ln >= 2 && !strcmp(e->d_name + ln - 2, ".c");
        if (!ok)
            continue;
        if (wa_scan_one(root, dir, e->d_name, out)) {
            closedir(d);
            return 2;
        }
    }
    closedir(d);
    return 0;
}
