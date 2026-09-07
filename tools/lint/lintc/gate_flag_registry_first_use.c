/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-flag-registry
 * Second file of the check-flag-registry family: the first-use pointer
 * check. gate_flag_registry.c parses engine/composition/flags.def and
 * scans the tree for reads of each flag; this file answers a narrower
 * question the parser never asked — does the "first use <path>:<line>"
 * note a row cites actually point at a line that reads that flag's name?
 * Three port lanes cited a stale or wrong line this week and no gate
 * caught any of it, so the pointer itself is now proved, not trusted.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gate_flag_registry_priv.h"
#include "lintc.h"

/* True when tok parses as "<path>:<line>" — a nonempty path, a colon, and
 * one or more digits running to the end of tok. "Makefile deploy:" (no
 * digits after its colon) and a bare "Makefile" (no colon at all) both
 * return 0 here, which is how a prose why_ clause that merely contains
 * the words "first use" without a real pointer stays unaffected. */
static int fru_token_is_pointer(const char *tok, char *path, size_t pathcap,
                                int *line)
{
    const char *colon = strrchr(tok, ':');
    if (!colon || colon == tok)
        return 0;
    const char *d = colon + 1;
    if (!*d)
        return 0;
    for (const char *q = d; *q; q++)
        if (*q < '0' || *q > '9')
            return 0;
    size_t plen = (size_t)(colon - tok);
    if (plen >= pathcap)
        return 0;
    memcpy(path, tok, plen);
    path[plen] = '\0';
    *line = atoi(d);
    return 1;
}

/* Finds "first use " anywhere in why (not just at its start — a row can
 * say "documented at X; first use Y:Z" first) and hands the whitespace-
 * or semicolon-delimited token right after it to fru_token_is_pointer. */
int fru_parse_pointer(const char *why, char *path, size_t pathcap, int *line)
{
    static const char tag[] = "first use ";
    const char *p = strstr(why, tag);
    if (!p)
        return 0;
    p += sizeof tag - 1;
    const char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != ';')
        end++;
    size_t tlen = (size_t)(end - p);
    char tok[300];
    if (tlen == 0 || tlen >= sizeof tok)
        return 0;
    memcpy(tok, p, tlen);
    tok[tlen] = '\0';
    return fru_token_is_pointer(tok, path, pathcap, line);
}

static int fru_ident_char(int c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* True when name appears in line as a whole identifier token — bounded on
 * both sides by a non-identifier byte (or the string's edge) — so a row
 * for ZCL_FOO is never satisfied by a line that reads only ZCL_FOO_BAR. */
static int fru_name_on_line(const char *line, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = line;
    while ((p = strstr(p, name)) != NULL) {
        int before_ok = (p == line) || !fru_ident_char((unsigned char)p[-1]);
        int after_ok = !fru_ident_char((unsigned char)p[nlen]);
        if (before_ok && after_ok)
            return 1;
        p++;
    }
    return 0;
}

/* Opens path (relative to the repo root, same convention as the rest of
 * this gate) and checks whether its cited line reads name. Returns 0 when
 * it does, 1 with reason filled in for a violation the caller reports and
 * keeps scanning past, or -1 when the file exists but can't be read at
 * all — the caller treats that as UNPROVEN and stops immediately rather
 * than guessing. */
static int fru_open_check(const char *path, int line, const char *name,
                          char *reason, size_t rcap)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(reason, rcap, "file missing");
        return 1;
    }
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char *l = NULL;
    size_t cap = 0;
    ssize_t nread;
    int lineno = 0, hit = 0, found = 0;
    while ((nread = getline(&l, &cap, f)) >= 0) {
        lineno++;
        if (lineno == line) {
            hit = 1;
            found = fru_name_on_line(l, name);
            break;
        }
    }
    free(l);
    fclose(f);
    if (!hit) {
        snprintf(reason, rcap, "line past end (%d lines)", lineno);
        return 1;
    }
    if (!found) {
        snprintf(reason, rcap, "name absent");
        return 1;
    }
    return 0;
}

static int fru_check_one(const struct fr_row *row, FILE *out)
{
    char reason[64];
    int rc = fru_open_check(row->fu_path, row->fu_line, row->name, reason,
                            sizeof reason);
    if (rc < 0)
        return die("z23-lint: flag_registry: first-use pointer file "
                   "unreadable: %s\n", row->fu_path);
    if (rc == 0)
        return 0;
    return fprintf(out, "flag_registry: %s first use %s:%d does not read it"
                   " (%s)\n", row->name, row->fu_path, row->fu_line,
                   reason) < 0
        ? die("z23-lint: write failed\n", "") : 1;
}

/* Runs fru_check_one over every row that carries a first-use pointer,
 * counts how many verified clean, and (when any failed) prints one
 * summary line naming the count before returning 1. A -1 from
 * fru_check_one (unreadable cited file) propagates as 2 immediately —
 * die() already told the operator which path. */
int fru_check_rows(const struct fr_row *rows, int n, FILE *out, int *verified)
{
    int violations = 0;
    *verified = 0;
    for (int i = 0; i < n; i++) {
        if (!rows[i].fu_present)
            continue;
        int rc = fru_check_one(&rows[i], out);
        if (rc == 2)
            return 2;
        if (rc == 1)
            violations++;
        else
            (*verified)++;
    }
    if (violations == 0)
        return 0;
    return fprintf(out, "flag_registry: %d first-use pointer(s) do not"
                   " read their flag\n", violations) < 0
        ? die("z23-lint: write failed\n", "") : 1;
}
