/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family - check-orient-facts of the C23 lint runtime, the
 * replacement for the bash body of build/bin/z23-lint check-orient-facts. Every
 * ZCL_FACT row in engine/composition/facts/ must still be true: its path must
 * exist and its anchor, a literal substring of that file, must still be
 * findable in it.
 *
 * WHY. The fact table exists so an agent stops re-deriving the same map from
 * source. That only holds while the rows are true; a stale row is confidently
 * wrong. The anchor is therefore re-proved on every commit. NEVER weaken an
 * anchor to make a row pass: there is no baseline file and no exemption list.
 *
 * SCAN FLOOR. Zero topic files, zero rows, or an unreadable index is a
 * failure, never a pass.
 *
 *   ZCL_ORIENT_FACTS_DIR=<dir>   scan another facts dir (selftest, tests)
 *   --selftest                   plant broken rows and prove the gate trips
 *
 * Selftest: gate_orient_facts_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_orient_facts_priv.h"
#include "lintc.h"

enum { OF_KEY_MAX = 48, OF_CLAIM_MAX = 160, OF_ANCHOR_MAX = 80, OF_FIELDS = 5 };

static void of_fail(struct of_run *r, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(r->err, fmt, ap);
    va_end(ap);
    fputc('\n', r->err);
    r->rc = 1;
}

static void *of_grow(void *p, size_t n)
{
    void *q = realloc(p, n); // raw-alloc-ok:lint-runtime
    if (!q)
        exit(die("z23-lint: out of memory\n", ""));
    return q;
}

static ssize_t of_getline(FILE *f, char **line, size_t *cap)
{
    ssize_t n = getline(line, cap, f);
    if (n > 0 && (*line)[n - 1] == '\n')
        (*line)[--n] = '\0';
    return n;
}

static size_t of_chars(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        n += ((unsigned char)*s & 0xC0u) != 0x80u;
    return n;
}

static int of_ends_with_paren(const char *s)
{
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        n--;
    return n > 0 && s[n - 1] == ')';
}

/* Text of the quoted string that follows prefix at the start of line, or
 * NULL when the line does not start that way or the quote never closes. */
static char *of_quoted_after(const char *line, const char *prefix)
{
    size_t pl = strlen(prefix);
    if (strncmp(line, prefix, pl) != 0)
        return NULL;
    const char *end = strchr(line + pl, '"');
    if (!end)
        return NULL;
    char *out = of_grow(NULL, (size_t)(end - line - (long)pl) + 1);
    memcpy(out, line + pl, (size_t)(end - line - (long)pl));
    out[end - line - (long)pl] = '\0';
    return out;
}

static void of_index_add(struct of_index *ix, const char *name)
{
    if (name[0])
        ix->any_include = 1;
    const char *p = name;
    while (*p) {
        while (*p && isspace((unsigned char)*p))
            p++;
        const char *s = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        if (p == s)
            continue;
        ix->files = of_grow(ix->files, (ix->nfiles + 1) * sizeof *ix->files);
        ix->files[ix->nfiles] = strndup(s, (size_t)(p - s));
        ix->nfiles++;
    }
}

static void of_topic_add(struct of_index *ix, const char *topic)
{
    size_t add = strlen(topic) + 1;
    ix->topics = of_grow(ix->topics, ix->topics_len + add + 1);
    memcpy(ix->topics + ix->topics_len, topic, add - 1);
    ix->topics[ix->topics_len + add - 1] = ' ';
    ix->topics[ix->topics_len + add] = '\0';
    ix->topics_len += add;
    ix->ntopic_rows++;
}

void of_index_free(struct of_index *ix)
{
    for (size_t i = 0; i < ix->nfiles; i++)
        free(ix->files[i]);
    free(ix->files);
    free(ix->topics);
    memset(ix, 0, sizeof *ix);
}

void of_index_load(struct of_index *ix, const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL, *q;
    size_t cap = 0;
    memset(ix, 0, sizeof *ix);
    if (!f)
        return;
    ix->topics = of_grow(NULL, 1);
    ix->topics[0] = '\0';
    while (of_getline(f, &line, &cap) >= 0) {
        if ((q = of_quoted_after(line, "#include \"")) != NULL)
            of_index_add(ix, q);
        else if ((q = of_quoted_after(line, "ZCL_FACT_TOPIC(\"")) != NULL)
            of_topic_add(ix, q);
        free(q);
    }
    free(line);
    fclose(f);
}

/* Fields split the way `IFS='|' read -r` splits them: the first four at
 * '|', the fifth is the remainder, one trailing '|' dropped from it. */
void of_split_fields(char *line, char *f[OF_FIELDS])
{
    char *p = line;
    for (int i = 0; i < OF_FIELDS - 1; i++) {
        f[i] = p;
        char *bar = p ? strchr(p, '|') : NULL;
        if (bar) {
            *bar = '\0';
            p = bar + 1;
        } else {
            p = NULL;
        }
        if (!f[i])
            f[i] = (char *)"";
    }
    f[OF_FIELDS - 1] = p ? p : (char *)"";
    char *last = strrchr(f[OF_FIELDS - 1], '|');
    if (last && last[1] == '\0' && last == strchr(f[OF_FIELDS - 1], '|'))
        *last = '\0';
}

static int of_contains(const char *hay, size_t hn, const char *needle)
{
    size_t nn = strlen(needle);
    const char *p = hay, *end = hay + hn;
    if (nn == 0)
        return 1;
    while (nn <= (size_t)(end - p)) {
        p = memchr(p, (unsigned char)needle[0], (size_t)(end - p) - nn + 1);
        if (!p)
            return 0;
        if (memcmp(p, needle, nn) == 0)
            return 1;
        p++;
    }
    return 0;
}

int of_anchor_found(const char *path, const char *anchor)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    int found = 0;
    if (fd < 0)
        return 0;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m != MAP_FAILED) {
            found = of_contains(m, (size_t)st.st_size, anchor);
            munmap(m, (size_t)st.st_size);
        }
    }
    close(fd);
    return found;
}

static int of_topic_declared(const struct of_run *r, const char *topic)
{
    size_t n = strlen(topic) + 3;
    char *needle = of_grow(NULL, n + 1);
    char *hay = of_grow(NULL, r->ix->topics_len + 3);
    snprintf(needle, n + 1, " %s ", topic);
    snprintf(hay, r->ix->topics_len + 3, " %s ", r->ix->topics);
    int hit = strstr(hay, needle) != NULL;
    free(needle);
    free(hay);
    return hit;
}

static void of_check_limits(struct of_run *r, const char *id, char *const f[])
{
    if (of_chars(f[1]) > OF_KEY_MAX)
        of_fail(r, "%s: key over %d chars", id, OF_KEY_MAX);
    if (of_chars(f[2]) > OF_CLAIM_MAX)
        of_fail(r, "%s: claim over %d chars", id, OF_CLAIM_MAX);
    if (of_chars(f[4]) > OF_ANCHOR_MAX)
        of_fail(r, "%s: anchor over %d chars", id, OF_ANCHOR_MAX);
}

static void of_check_row(struct of_run *r, const char *rel, char *line)
{
    char *f[OF_FIELDS];
    struct stat st;
    of_split_fields(line, f);
    r->rows++;
    size_t n = strlen(f[0]) + strlen(f[1]) + 2;
    char *id = of_grow(NULL, n);
    snprintf(id, n, "%s.%s", f[0], f[1]);
    if (strcmp(f[0], "MALFORMED") == 0) {
        of_fail(r, "%s: a ZCL_FACT row is not exactly five plain string fields", rel);
        free(id);
        return;
    }
    if (!of_topic_declared(r, f[0]))
        of_fail(r, "%s: topic not declared in %s", id, r->index);
    of_check_limits(r, id, f);
    if (stat(f[3], &st) != 0 || !S_ISREG(st.st_mode))
        of_fail(r, "%s: %s missing", id, f[3]);
    else if (!of_anchor_found(f[3], f[4]))
        of_fail(r, "%s: anchor \"%s\" not found in %s", id, f[4], f[3]);
    free(id);
}

/* The five quoted fields of a joined ZCL_FACT record as one '|' line, or
 * the MALFORMED marker when the record is not exactly five plain strings. */
static char *of_record_line(const char *rec)
{
    size_t quotes = 0, n = strlen(rec);
    for (const char *p = rec; *p; p++)
        quotes += *p == '"';
    char *out = of_grow(NULL, n + 16);
    if (quotes != 10) {
        strcpy(out, "MALFORMED||||");
        return out;
    }
    char *copy = strdup(rec), *save = copy, *o = out;
    for (int i = 0; i < 11; i++) {
        char *q = strchr(copy, '"');
        if (q)
            *q = '\0';
        if (i % 2 == 1)
            o += sprintf(o, "%s%s", i > 1 ? "|" : "", copy);
        copy = q ? q + 1 : copy + strlen(copy);
    }
    free(save);
    return out;
}

static void of_scan_rows(struct of_run *r, const char *rel, FILE *f)
{
    char *line = NULL, *rec = NULL;
    size_t cap = 0, rlen = 0, rcap = 0;
    int open = 0;
    while (of_getline(f, &line, &cap) >= 0) {
        if (strncmp(line, "ZCL_FACT(", 9) == 0) {
            rlen = 0;
            open = 1;
        }
        if (!open)
            continue;
        size_t l = strlen(line);
        if (rlen + l + 1 > rcap)
            rec = of_grow(rec, rcap = (rlen + l + 1) * 2);
        memcpy(rec + rlen, line, l + 1);
        rlen += l;
        if (!of_ends_with_paren(line))
            continue;
        open = 0;
        char *joined = of_record_line(rec);
        of_check_row(r, rel, joined);
        free(joined);
    }
    free(line);
    free(rec);
}

static int of_has_tab(const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[4096];
    size_t n;
    int tab = 0;
    while (f && !tab && (n = fread(buf, 1, sizeof buf, f)) > 0)
        tab = memchr(buf, '\t', n) != NULL;
    if (f)
        fclose(f);
    return tab;
}

static int of_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *of_key_id(const char *line)
{
    const char *q1 = strchr(line, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
    const char *q3 = q2 ? strchr(q2 + 1, '"') : NULL, *q4 = q3 ? strchr(q3 + 1, '"') : NULL;
    if (!q4)
        return NULL;
    size_t a = (size_t)(q2 - q1) - 1, b = (size_t)(q4 - q3) - 1;
    char *id = of_grow(NULL, a + b + 2);
    memcpy(id, q1 + 1, a);
    id[a] = '.';
    memcpy(id + a + 1, q3 + 1, b);
    id[a + b + 1] = '\0';
    return id;
}

static void of_report_dups(struct of_run *r, const char *rel, char **ids, size_t n)
{
    int first = 1;
    qsort(ids, n, sizeof *ids, of_cmp);
    for (size_t i = 1; i < n; i++) {
        if (strcmp(ids[i], ids[i - 1]) != 0 || (i > 1 && !strcmp(ids[i], ids[i - 2])))
            continue;
        if (first)
            fprintf(r->err, "FAIL: duplicate keys in %s: ", rel);
        else
            fputc('\n', r->err);
        fputs(ids[i], r->err);
        first = 0;
    }
    if (!first) {
        fputc('\n', r->err);
        r->rc = 1;
    }
}

static void of_scan_dups(struct of_run *r, const char *rel, FILE *f)
{
    char *line = NULL, **ids = NULL;
    size_t cap = 0, n = 0;
    while (of_getline(f, &line, &cap) >= 0) {
        char *id = strncmp(line, "ZCL_FACT(", 9) == 0 ? of_key_id(line) : NULL;
        if (!id)
            continue;
        ids = of_grow(ids, (n + 1) * sizeof *ids);
        ids[n++] = id;
    }
    of_report_dups(r, rel, ids, n);
    for (size_t i = 0; i < n; i++)
        free(ids[i]);
    free(ids);
    free(line);
}

static void of_scan_topic_file(struct of_run *r, const char *rel)
{
    size_t n = strlen(r->dir) + strlen(rel) + 2;
    char *path = of_grow(NULL, n);
    snprintf(path, n, "%s/%s", r->dir, rel);
    FILE *f = access(path, R_OK) == 0 ? fopen(path, "r") : NULL;
    if (!f) {
        of_fail(r, "FAIL: %s includes unreadable %s", r->index, rel);
        free(path);
        return;
    }
    if (of_has_tab(path))
        of_fail(r, "FAIL: %s contains a tab", rel);
    of_scan_rows(r, rel, f);
    rewind(f);
    of_scan_dups(r, rel, f);
    fclose(f);
    free(path);
}

static size_t of_word_count(const char *s)
{
    size_t words = 0;
    int in = 0;
    for (; *s; s++) {
        int sp = isspace((unsigned char)*s) != 0;
        words += !sp && !in;
        in = !sp;
    }
    return words;
}

int of_scan(const char *dir, FILE *out, FILE *err)
{
    struct of_index ix;
    struct of_run r = { .out = out, .err = err, .dir = dir, .ix = &ix };
    size_t n = strlen(dir) + sizeof "/index.def";
    r.index = of_grow(NULL, n);
    snprintf(r.index, n, "%s/index.def", dir);
    if (access(r.index, R_OK) != 0) {
        fprintf(err, "FAIL: no readable %s\n", r.index);
        free(r.index);
        return 1;
    }
    of_index_load(&ix, r.index);
    int rc = 1;
    if (!ix.any_include)
        fprintf(err, "FAIL: %s includes no topic file\n", r.index);
    else if (ix.ntopic_rows == 0)
        rc = 1;
    else {
        for (size_t i = 0; i < ix.nfiles; i++)
            of_scan_topic_file(&r, ix.files[i]);
        if (r.rows == 0)
            fputs("FAIL: scan floor \xE2\x80\x94 zero fact rows scanned\n", err);
        else if (r.rc == 0) {
            fprintf(out, "orient facts: %ld rows across %zu topics, every path and anchor proved\n",
                    r.rows, of_word_count(ix.topics));
            rc = 0;
        }
    }
    of_index_free(&ix);
    free(r.index);
    return rc;
}

int check_orient_facts_run(int argc, char **argv)
{
    char root[4096];
    (void)argc;
    (void)argv;
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0)
        return die("z23-lint: cannot enter the repository root\n", "");
    const char *dir = getenv("ZCL_ORIENT_FACTS_DIR");
    return of_scan(dir && dir[0] ? dir : "engine/composition/facts", stdout, stderr);
}
