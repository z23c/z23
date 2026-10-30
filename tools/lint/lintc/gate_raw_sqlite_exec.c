/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the raw node.db DML half of check-raw-sqlite
 * (gate_raw_sqlite.c). Finds direct exec calls against the node database
 * handle whose first string literal starts with INSERT, DELETE, UPDATE or
 * REPLACE — writes that must go through ar_exec_write_sql or a reviewed
 * helper. The call and its literal may span lines, so each candidate line
 * is grown forward into a chunk (up to 900 chars, like the awk original),
 * the LAST call-shape match in the chunk is taken (the awk sub was
 * greedy), and the first quoted literal after it is judged. Ported from
 * the awk pass of tools/scripts/check_raw_sqlite.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_raw_sqlite_priv.h"

static regex_t g_crs_x_trigger;
static regex_t g_crs_x_call;
static regex_t g_crs_x_ok;

int crs_exec_init(void)
{
    int rc = compile_pat(&g_crs_x_trigger, REG_EXTENDED, "sqlite3_exec",
                         "[[:space:]]*\\(", "", "");
    if (rc)
        return rc;
    rc = compile_pat(&g_crs_x_call, REG_EXTENDED,
                     "sqlite3_exec[[:space:]]*\\([[:space:]]*",
                     "(&[[:space:]]*)?ndb(->|\\.)db[[:space:]]*,", "", "");
    if (rc)
        return rc;
    return compile_pat(&g_crs_x_ok, REG_EXTENDED, "//[[:space:]]*raw-sql-ok:",
                       "[A-Za-z][A-Za-z0-9_-]+", "", "");
}

/* Grow the chunk from the candidate line forward until it holds at least
 * 900 chars or the file ends, exactly the awk accumulation loop. */
static int crs_exec_build(FILE *f, const char *first, char *chunk, size_t cap)
{
    size_t len = strlen(first);
    if (len >= cap)
        return CRS_FATAL;
    memcpy(chunk, first, len + 1);
    char nxt[CRS_LINE];
    while (len < 900 && fgets(nxt, sizeof nxt, f)) {
        if (crs_overlong(nxt))
            return CRS_FATAL;
        crs_chomp(nxt);
        size_t m = strlen(nxt);
        if (len + 1 + m >= cap)
            return CRS_FATAL;
        chunk[len] = '\n';
        memcpy(chunk + len + 1, nxt, m + 1);
        len += 1 + m;
    }
    return 0;
}

/* Uppercase, collapse whitespace runs to single spaces, then report when
 * the statement starts with a DML verb; the verb is the first word. */
static int crs_exec_verdict(const char *path, long ln, const char *sql,
                            struct crs_viol *v)
{
    char up[CRS_LINE];
    size_t o = 0;
    for (size_t i = 0; sql[i] != '\0' && o + 1 < sizeof up; i++) {
        unsigned char c = (unsigned char)sql[i];
        up[o++] = (char)(isspace(c) ? ' ' : toupper(c));
    }
    up[o] = '\0';
    size_t w = 0;
    for (size_t r = 0; r < o; r++) {
        if (up[r] == ' ' && w > 0 && up[w - 1] == ' ')
            continue;
        up[w++] = up[r];
    }
    up[w] = '\0';
    static const char *const verbs[] = { "INSERT ", "DELETE ", "UPDATE ",
                                         "REPLACE " };
    for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
        size_t vl = strlen(verbs[k]);
        if (strncmp(up, verbs[k], vl) != 0)
            continue;
        char verb[16];
        if (ovf(snprintf(verb, sizeof verb, "%.*s", (int)(vl - 1), up),
                sizeof verb))
            return CRS_FATAL;
        crs_viol_add(v, "%s:%ld: raw node.db sqlite3_exec %s; use "
                     "ar_exec_write_sql()/AR_STEP_WRITE or a reviewed helper",
                     path, ln, verb);
        return 0;
    }
    return 0;
}

/* Take the text after the last call-shape match, find the first quoted
 * literal, and judge its first word. */
static int crs_exec_sql(const char *path, long ln, const char *tail,
                        struct crs_viol *v)
{
    const char *p = strchr(tail, '"');
    if (!p)
        return 0;
    p++;
    const char *q = p;
    while (*q != '\0') {
        if (*q == '\\' && q[1] != '\0')
            q += 2;
        else if (*q == '"')
            break;
        else
            q++;
    }
    if (*q != '"')
        return 0;
    size_t n = (size_t)(q - p);
    char sql[CRS_LINE];
    if (n >= sizeof sql)
        return CRS_FATAL;
    memcpy(sql, p, n);
    sql[n] = '\0';
    while (*sql == ' ' || *sql == '\t' || *sql == '\n')
        memmove(sql, sql + 1, strlen(sql));
    return crs_exec_verdict(path, ln, sql, v);
}

/* Next call-shape match in chunk at or after off: 1 with absolute bounds,
 * 0 none, -1 on a regexec failure. */
static int crs_exec_find(const char *chunk, size_t off, size_t *so,
                         size_t *eo)
{
    regmatch_t m;
    int r = crs_rx(&g_crs_x_call, chunk + off, &m, off ? REG_NOTBOL : 0);
    if (r > 0) {
        *so = off + (size_t)m.rm_so;
        *eo = off + (size_t)m.rm_eo;
    }
    return r;
}

/* Judge EVERY call that starts on the candidate line (the awk original
 * judged only the last call in the chunk): the literal after each call is
 * bounded by the start of the next call. One row per line at most. */
static int crs_exec_chunk(const char *path, long ln, char *chunk,
                          size_t first_len, struct crs_viol *v)
{
    size_t len = strlen(chunk), so = 0, eo = 0;
    int r = crs_exec_find(chunk, 0, &so, &eo);
    while (r > 0 && so < first_len) {
        size_t nso = len, neo = 0;
        int r2 = crs_exec_find(chunk, eo, &nso, &neo);
        if (r2 < 0)
            return CRS_FATAL;
        size_t end = r2 > 0 ? nso : len;
        char saved = chunk[end];
        chunk[end] = '\0';
        int before = v->n;
        int rc = crs_exec_sql(path, ln, chunk + eo, v);
        chunk[end] = saved;
        if (rc != 0 || v->n > before)
            return rc;
        r = r2;
        so = nso;
        eo = neo;
    }
    return r < 0 ? CRS_FATAL : 0;
}

/* Candidate line: not tagged raw-sql-ok and holds the call opener.
 * 1 candidate, 0 skip, -1 regexec failure. */
static int crs_exec_candidate(const char *line)
{
    if (!strstr(line, "sqlite3_exec"))
        return 0;
    int ok = crs_rx(&g_crs_x_ok, line, NULL, 0);
    if (ok != 0)
        return ok < 0 ? -1 : 0;
    return crs_rx(&g_crs_x_trigger, line, NULL, 0);
}

/* One candidate line: grow the chunk from here, judge the calls that start
 * on this line, then put the file position back. */
static int crs_exec_line(FILE *f, const char *path, long ln, const char *line,
                         struct crs_viol *v)
{
    static char chunk[CRS_CHUNK];
    fpos_t pos;
    if (fgetpos(f, &pos) != 0)
        return CRS_FATAL;
    int rc = crs_exec_build(f, line, chunk, sizeof chunk);
    if (rc == 0)
        rc = crs_exec_chunk(path, ln, chunk, strlen(line), v);
    if (fsetpos(f, &pos) != 0)
        rc = CRS_FATAL;
    return rc;
}

int crs_exec_file(const char *path, void *ctx)
{
    struct crs_viol *v = ctx;
    if (lint_path_is_excluded(path) || !crs_ends_ch(path))
        return 0;
    if (strcmp(path, "engine/models/include/models/activerecord.h") == 0)
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return CRS_FATAL;
    static char line[CRS_LINE];
    long ln = 0;
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        ln++;
        if (crs_overlong(line)) {
            rc = CRS_FATAL;
            break;
        }
        crs_chomp(line);
        int cand = crs_exec_candidate(line);
        if (cand < 0)
            rc = CRS_FATAL;
        else if (cand > 0)
            rc = crs_exec_line(f, path, ln, line, v);
    }
    if (ferror(f))
        rc = CRS_FATAL;
    fclose(f);
    return rc;
}

int crs_scan_exec(struct crs_viol *v)
{
    for (size_t i = 0;
         i < CRS_PROD_ROOTS; i++) {
        int rc = crs_walk(k_crs_prod_roots[i], 1, crs_exec_file, v);
        if (rc == CRS_FATAL) {
            fprintf(stderr, "check_raw_sqlite: FATAL — exec scan failed "
                    "(rc=2) under %s\n", k_crs_prod_roots[i]);
            return 2;
        }
        if (rc)
            return rc;
    }
    return 0;
}
