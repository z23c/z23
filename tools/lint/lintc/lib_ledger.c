/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the ledgers of the split C23 lint runtime — the family-size
 * ledger (lint_families_ledger, z23-lint --families), the shared baseline
 * set (lint_base_*) and lint_macro_arg. Split out of lib.c so that file
 * stays under the lint family ceiling; every function is moved verbatim.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "base/serialize_le.h"
#include "lintc.h"

/* z23-lint --families: the family-size ledger. Lists every gate_*.c family
 * file under tools/lint/lintc/ (relative to the caller's cwd, like every
 * gate's scan) with its line count and headroom to LINT_FAMILY_CEILING. A
 * file over the ceiling is named on stderr and fails the command, so the
 * ledger doubles as the refusal the wiring gate enforces. Line counts are
 * newline counts, matching wc -l exactly. */

#define FL_MAX 512
#define FL_NAME 256

static int fl_count(const char *path, long *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    long n = 0;
    int c;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n')
            n++;
    if (ferror(f)) {
        fclose(f);
        return die("z23-lint: read error on %s\n", path);
    }
    fclose(f);
    *out = n;
    return 0;
}

static int fl_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

int lint_families_ledger(void)
{
    static const char k_dir[] = "tools/lint/lintc";
    DIR *d = opendir(k_dir);
    if (!d)
        return die("z23-lint: cannot open %s (run from the repo root)\n",
                   k_dir);
    static char names[FL_MAX][FL_NAME];
    int nf = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        size_t nl = strlen(nm);
        if (strncmp(nm, "gate_", 5) != 0 || nl < 7
            || strcmp(nm + nl - 2, ".c") != 0)
            continue;
        if (nf >= FL_MAX || nl >= FL_NAME) {
            closedir(d);
            char detail[FL_NAME + 96];
            if (nf >= FL_MAX)
                snprintf(detail, sizeof detail,
                        "%s (FL_MAX=%d exceeded; saw at least %d family "
                        "files — raise FL_MAX)", k_dir, FL_MAX, nf);
            else
                snprintf(detail, sizeof detail,
                        "%s (FL_NAME=%d exceeded by filename %s, %zu bytes "
                        "— raise FL_NAME)", k_dir, FL_NAME, nm, nl);
            return die("z23-lint: too many family files under %s\n",
                      detail);
        }
        memcpy(names[nf], nm, nl + 1);
        nf++;
    }
    closedir(d);
    if (nf == 0)
        return die("z23-lint: no family files under %s\n", k_dir);
    qsort(names, (size_t)nf, FL_NAME, fl_cmp);
    int breach = 0;
    for (int i = 0; i < nf; i++) {
        char path[FL_NAME + 64];
        if (ovf(snprintf(path, sizeof path, "%s/%s", k_dir, names[i]),
                sizeof path))
            return 2;
        long lines = 0;
        int rc = fl_count(path, &lines);
        if (rc)
            return rc;
        printf("%s: %ld lines, %ld headroom to %d\n", path, lines,
               LINT_FAMILY_CEILING - lines, LINT_FAMILY_CEILING);
        if (lines > LINT_FAMILY_CEILING) {
            fprintf(stderr, "z23-lint: FAMILY CEILING BREACH — %s has %ld "
                    "lines (ceiling %d)\n", path, lines,
                    LINT_FAMILY_CEILING);
            breach = 1;
        }
    }
    return breach;
}

/* ── shared shrink-only ratchet baseline (contract in lintc.h) ────────── */

static int lb_cmp(const void *a, const void *b)
{
    return strcmp(((const struct lb_row *)a)->key,
                  ((const struct lb_row *)b)->key);
}

/* Parse one baseline line into row r. Returns -1 for a comment/blank line,
 * 0 for a parsed row, 2 for a malformed line (named on err). */
static int lb_parse_line(char *line, struct lb_row *r, FILE *err)
{
    char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '#' || *p == '\n' || *p == '\0')
        return -1;
    char *nl = strchr(p, '\n');
    if (nl)
        *nl = '\0';
    char *colon = strrchr(p, ':');
    if (!colon || colon == p) {
        fprintf(err, "z23-lint: FATAL — malformed baseline line: %s\n", p);
        return 2;
    }
    *colon = '\0';
    char *end = NULL;
    long v = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 100000) {
        fprintf(err, "z23-lint: FATAL — malformed baseline M in line: "
                     "%s:%s\n", p, colon + 1);
        return 2;
    }
    if (strlen(p) >= LB_KEY)
        return die("z23-lint: baseline key too long: %s\n", p);
    memcpy(r->key, p, strlen(p) + 1);
    r->pinned = (int)v;
    r->cur = 0;
    r->seen = 0;
    return 0;
}

int lint_base_load(struct lint_base *b, const char *path, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(err, "z23-lint: FATAL — missing baseline %s (create it, one "
                     "key:M per line, or empty)\n", path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    b->n = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        if (b->n >= LB_MAX) {
            rc = die("z23-lint: baseline overflow: %s\n", path);
            break;
        }
        int pr = lb_parse_line(line, &b->row[b->n], err);
        if (pr < 0)
            continue;
        if (pr) {
            rc = pr;
            break;
        }
        b->n++;
    }
    rc = fin(f, line, path, rc);
    if (rc)
        return rc;
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    for (int i = 1; i < b->n; i++) {
        if (strcmp(b->row[i - 1].key, b->row[i].key) == 0) {
            fprintf(err, "z23-lint: FATAL — duplicate baseline entry %s\n",
                    b->row[i].key);
            return 2;
        }
    }
    return 0;
}

/* Presence-set loader: the gate_load_list_file() semantics the shell
 * allowlist gates used, as a lint_base row set. One plain key per line (no
 * :M); `#` starts a comment ANYWHERE on the line; leading/trailing
 * whitespace is trimmed; blank and comment lines are skipped; duplicate
 * keys collapse silently; a missing or non-regular file yields an empty
 * set, not an error. Rows are stored pinned=1 — membership is
 * lint_base_observe(b, key, 1) >= 0. lint_base_finish does NOT apply: an
 * entry no scan observed is unused, never stale. The set is
 * superset-allowed by contract (contract in lintc.h). */
static char *lb_set_key(char *line)
{
    char *h = strchr(line, '#');
    if (h)
        *h = '\0';
    char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    size_t n = strlen(p);
    while (n && isspace((unsigned char)p[n - 1]))
        p[--n] = '\0';
    return n ? p : NULL;
}

static int lb_set_add(struct lint_base *b, const char *key, const char *path)
{
    size_t n = strlen(key);
    if (b->n >= LB_MAX || n >= LB_KEY)
        return die("z23-lint: baseline overflow: %s\n", path);
    struct lb_row *r = &b->row[b->n++];
    memcpy(r->key, key, n + 1);
    r->pinned = 1;
    r->cur = 0;
    r->seen = 0;
    return 0;
}

static void lb_set_dedup(struct lint_base *b)
{
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    int w = 0;
    for (int i = 0; i < b->n; i++) {
        if (w > 0 && strcmp(b->row[w - 1].key, b->row[i].key) == 0)
            continue;
        if (w != i)
            memcpy(&b->row[w], &b->row[i], sizeof b->row[0]);
        w++;
    }
    b->n = w;
}

int lint_base_load_set(struct lint_base *b, const char *path)
{
    struct stat st;
    b->n = 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *key = lb_set_key(line);
        if (key)
            rc = lb_set_add(b, key, path);
    }
    rc = fin(f, line, path, rc);
    if (rc)
        return rc;
    lb_set_dedup(b);
    return 0;
}

int lint_base_observe(struct lint_base *b, const char *key, int m)
{
    struct lb_row k;
    memset(&k, 0, sizeof k);
    if (strlen(key) >= LB_KEY)
        return -1;
    memcpy(k.key, key, strlen(key) + 1);
    struct lb_row *r = bsearch(&k, b->row, (size_t)b->n, sizeof b->row[0],
                               lb_cmp);
    if (!r)
        return -1;
    r->seen = 1;
    r->cur = m;
    return (int)(r - b->row);
}

/* Verdict for one pinned row: 0 passes, 1 is a violation, -1 a write
 * failure. A shrink that stays over the cap passes and is only noted. */
static int lb_finish_row(const struct lb_row *r, FILE *out, FILE *notes,
                         int cap, const char *hint)
{
    int bad;
    if (!r->seen)
        bad = fprintf(out, "%s is pinned at M=%d but no longer exists — "
                      "stale baseline, delete the line\n",
                      r->key, r->pinned) < 0;
    else if (r->cur > r->pinned)
        bad = fprintf(out, "%s grew M=%d -> M=%d past its baseline pin\n",
                      r->key, r->pinned, r->cur) < 0;
    else if (r->cur <= cap)
        bad = fprintf(out, "%s is pinned at M=%d but is now within the cap "
                      "(M=%d <= %d); delete the baseline line\n",
                      r->key, r->pinned, r->cur, cap) < 0;
    else if (r->cur < r->pinned)
        return fprintf(notes, "%s shrank M=%d -> M=%d; %s lowers the pin\n",
                       r->key, r->pinned, r->cur, hint) < 0 ? -1 : 0;
    else
        return 0;
    return bad ? -1 : 1;
}

int lint_base_finish(const struct lint_base *b, FILE *out, FILE *notes,
                     int cap, const char *hint)
{
    int viol = 0;
    for (int i = 0; i < b->n; i++) {
        int v = lb_finish_row(&b->row[i], out, notes, cap, hint);
        if (v < 0) {
            (void)die("z23-lint: write failed\n", "");
            return -1;
        }
        viol += v;
    }
    return viol;
}

/* Tighten in memory: a row whose function is gone or within the cap is
 * deleted; a row whose function shrank but is still over the cap is lowered
 * to the current M. A row that grew is kept as it is, and no row is added. */
int lint_base_tighten(struct lint_base *b, int cap, int *lowered, int *deleted,
                      int *kept)
{
    int w = 0;
    *lowered = *deleted = *kept = 0;
    for (int i = 0; i < b->n; i++) {
        struct lb_row *r = &b->row[i];
        if (!r->seen || r->cur <= cap) {
            (*deleted)++;
            continue;
        }
        if (r->cur < r->pinned) {
            r->pinned = r->cur;
            (*lowered)++;
        } else {
            (*kept)++;
        }
        if (w != i)
            b->row[w] = b->row[i];
        w++;
    }
    b->n = w;
    return 0;
}

int lint_base_pin(struct lint_base *b, const char *key, int m)
{
    if (b->n >= LB_MAX || strlen(key) >= LB_KEY)
        return die("z23-lint: baseline overflow\n", "");
    struct lb_row *r = &b->row[b->n];
    memcpy(r->key, key, strlen(key) + 1);
    r->pinned = m;
    r->cur = 0;
    r->seen = 0;
    b->n++;
    return 0;
}

int lint_base_write(struct lint_base *b, const char *path, const char *hdr)
{
    qsort(b->row, (size_t)b->n, sizeof b->row[0], lb_cmp);
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    int rc = hdr && fputs(hdr, f) < 0;
    for (int i = 0; !rc && i < b->n; i++)
        rc = fprintf(f, "%s:%d\n", b->row[i].key, b->row[i].pinned) < 0;
    if (fclose(f) != 0 && rc == 0)
        return die("z23-lint: fclose failed: %s\n", path);
    return rc ? die("z23-lint: write failed\n", "") : 0;
}
int lint_macro_arg(const char *s, int want, int *aoff, int *alen)
{
    int depth = 0, instr = 0, esc = 0, argno = 1, start = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i <= n; i++) {
        char c = i < n ? s[i] : ',';
        int flush = i == n;
        if (!flush) {
            if (instr) {
                if (esc)
                    esc = 0;
                else if (c == '\\')
                    esc = 1;
                else if (c == '"')
                    instr = 0;
                continue;
            }
            if (c == '"') {
                instr = 1;
                continue;
            }
            if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
            if (depth != 0 || c != ',')
                continue;
        }
        if (argno == want) {
            *aoff = start;
            *alen = (int)i - start;
        }
        argno++;
        start = (int)i + 1;
    }
    return argno - 1;
}
