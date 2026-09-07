/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the scan half of the check-source-identity-authority family
 * (the 700-line family ceiling split) — the find-mirror directory walk
 * over the scan roots and the awk per-file counter with its six-line
 * "agentbuild nearby" window. The gate body and the list helpers live in
 * gate_source_identity_authority.c, the baseline/evaluate/report in
 * gate_source_identity_authority_ratchet.c, and the planted-violation
 * selftest in gate_source_identity_authority_selftest.c; the files share
 * their internals through gate_source_identity_authority_priv.h. The
 * parity contract for this scan is documented in
 * gate_source_identity_authority.c's header.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_source_identity_authority_priv.h"

static const char k_gate[] = "check_source_identity_authority";
static const char k_rplain[] = "\"source_id_sha256\"[[:space:]]*:";
static const char k_resc[] = "\\\"source_id_sha256\\\"[[:space:]]*:";
static const char k_pkey[] = "\"source_id_sha256\":";

/* ── the scan set: find $SCAN_ROOT -type f -name '*.sh' | grep -vE ────── */

int sia_walk(struct sia_rx *rx, const char *dir, struct sia_list *files)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        size_t nl = strlen(name);
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = sia_walk(rx, path, files);
            else if (S_ISREG(st.st_mode) && nl > 3
                     && memcmp(name + nl - 3, ".sh", 3) == 0
                     && regexec(&rx->excl, path, 0, NULL, 0) != 0)
                rc = sia_add(files, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* ── the awk per-file counter ─────────────────────────────────────────── */

static int sia_reader(struct sia_rx *rx, const char *line)
{
    if (!strstr(line, "source_id_sha256"))
        return 0;
    return regexec(&rx->r1, line, 0, NULL, 0) == 0
        || regexec(&rx->r2, line, 0, NULL, 0) == 0
        || regexec(&rx->r3, line, 0, NULL, 0) == 0;
}

/* Class R: an inline grep/sed extraction of the key's regex source text,
 * or a positional reader call on it, with "agentbuild" inside the window
 * (which holds the current line already). */
static int sia_class_r(struct sia_rx *rx, const char *line,
                       const char recent[SIA_WIN][SIA_LINE])
{
    int needle = strstr(line, k_rplain) || strstr(line, k_resc);
    int tool = strstr(line, "grep") || strstr(line, "sed");
    if (!((needle && tool) || sia_reader(rx, line)))
        return 0;
    for (int i = 0; i < SIA_WIN; i++)
        if (recent[i][0] && strstr(recent[i], "agentbuild"))
            return 1;
    return 0;
}

static int sia_counts_push(struct sia_counts *c, const char *path, long debt)
{
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 32;
        struct sia_count *nv = realloc(c->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        c->v = nv;
        c->cap = nc;
    }
    size_t n = strlen(path);
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, path, n + 1);
    c->v[c->n].path = copy;
    c->v[c->n].debt = debt;
    c->n++;
    return 0;
}

void sia_counts_free(struct sia_counts *c)
{
    for (size_t i = 0; i < c->n; i++)
        free(c->v[i].path);
    free(c->v);
    c->v = NULL;
    c->n = c->cap = 0;
}

/* A pure comment line does not count toward "agentbuild nearby" — an
 * explanatory comment naming agentbuild next to a call this gate must not
 * flag would otherwise self-trigger. An over-long line fails closed. */
static int sia_window_push(char recent[SIA_WIN][SIA_LINE], int ri,
                           const char *line, size_t n)
{
    const char *trimmed = line;
    while (*trimmed == ' ' || *trimmed == '\t')
        trimmed++;
    if (*trimmed == '#') {
        recent[ri % SIA_WIN][0] = '\0';
        return 0;
    }
    if (n >= SIA_LINE)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(recent[ri % SIA_WIN], line, n + 1);
    return 0;
}

static void sia_classify_line(struct sia_rx *rx, const char *line,
                              char recent[SIA_WIN][SIA_LINE],
                              struct sia_acc *a)
{
    if (sia_class_r(rx, line, recent))
        a->count++;
    if (strstr(line, "capture-record"))
        a->has_capture = 1;
    if (strstr(line, k_pkey) && !strstr(line, "grep")
        && !strstr(line, "sed"))
        a->p_count++;
}

int sia_scan_file(struct sia_rx *rx, const char *path,
                  struct sia_counts *counts)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: FATAL — cannot read scanned file: %s\n",
                k_gate, path);
        return 2;
    }
    char recent[SIA_WIN][SIA_LINE];
    memset(recent, 0, sizeof recent);
    struct sia_acc a = { 0 };
    int ri = 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = sia_window_push(recent, ri, line, n);
        if (rc != 0)
            break;
        ri++;
        sia_classify_line(rx, line, recent, &a);
    }
    rc = fin(f, line, path, rc);
    long total = a.count + (a.has_capture ? a.p_count : 0);
    if (rc == 0 && total > 0)
        rc = sia_counts_push(counts, path, total);
    return rc;
}
