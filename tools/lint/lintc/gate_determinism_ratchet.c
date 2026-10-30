/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-determinism-ratchet — the NONDETERMINISTIC set may
 * only shrink. Ported from tools/lint/check_determinism_ratchet.sh
 * (deleted). Selftest: gate_determinism_ratchet_selftest.c.
 *
 * The gate does NOT re-measure determinism (that is `make determinism-scan`,
 * hours of wall clock). It guards the RECORD of that measurement,
 * tools/lint/determinism_baseline.txt, which is cheap and is where the
 * ratchet actually lives:
 *
 *   A. SHRINK-ONLY. Every group in the working-tree baseline must already
 *      be in the baseline at the merge-base with origin/main (or HEAD when
 *      no origin/main exists). A new entry fails; there is no flag that
 *      admits one.
 *   B. EVERY ENTRY NAMES ITS CAUSE. Rows are "<group> <CLASS> <PERTURBATION>
 *      [+<PERTURBATION>...]"; each perturbation must be one the scan tool
 *      actually applies.
 *   C. EVERY ENTRY NAMES A REAL GROUP, from the canonical registry
 *      tools/dev/test_group_catalog.def (ZCL_TEST_GROUP/ZCL_SPEC_GROUP rows,
 *      full id test_x / spec_x).
 *   D. THE DECLARED COUNT MATCHES the "# count: N" header.
 *   E. A MISSING OR UNREADABLE BASELINE, registry, or perturbation source
 *      FAILS CLOSED — a gate that cannot see its input never reports clean.
 *
 * Perturbation vocabulary: build/bin/determinism_scan list-profiles when
 * that tool is built, else the ZCL_DET_P_ enum in the perturbation header.
 * Never a third hand-kept list.
 *
 * Exit: 0 clean, 1 on any violation, 2 on misuse or gate error.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_determinism_ratchet_priv.h"

const char k_dtr_baseline_rel[] = "tools/lint/determinism_baseline.txt";
static const char k_dtr_pert_rel[] =
    "engine/modules/determinism/include/determinism/perturbation.h";
const char k_dtr_catalog_rel[] = "tools/dev/test_group_catalog.def";

enum { DTR_NAME = 160, DTR_GROUPS = 8192, DTR_LIST = 512, DTR_LISTROW = 224,
       DTR_LINE = 4096, DTR_PATH = 1024, DTR_GITOUT = 65536, DTR_SHA = 80 };

struct dtr_names { char v[DTR_GROUPS][DTR_NAME]; int n; };
struct dtr_bad { char v[DTR_LIST][DTR_LISTROW]; int n; };

struct dtr_ctx {
    struct dtr_bad cls, nocause, badgrp, badpert;
    struct dtr_names now;
    long declared;
    int have_declared;
    int rows;
};

static void dtr_over(const char *what, long n)
{
    fprintf(stderr, "check-determinism-ratchet: %s exceeds %ld\n", what, n);
    exit(2);
}

/* Reads one line (newline stripped). 1 got, 0 eof, -1 too long/error. */
static int dtr_getline(FILE *f, char *buf, size_t cap)
{
    int c;
    size_t n = 0;
    while ((c = fgetc(f)) != EOF && c != '\n') {
        if (n + 1 >= cap)
            return -1;
        buf[n++] = (char)c;
    }
    if (c == EOF && n == 0)
        return 0;
    buf[n] = '\0';
    return 1;
}

static int dtr_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int dtr_has(const struct dtr_names *s, const char *name)
{
    size_t n = (size_t)s->n;
    return lfind(name, s->v, &n, DTR_NAME, dtr_cmp) != NULL;
}

static void dtr_add_uniq(struct dtr_names *s, const char *name)
{
    if (dtr_has(s, name))
        return;
    if (s->n >= DTR_GROUPS)
        dtr_over("name set", DTR_GROUPS);
    if (strlen(name) >= DTR_NAME)
        dtr_over("name", DTR_NAME);
    strcpy(s->v[s->n], name);
    s->n++;
}

static void dtr_bad_add(struct dtr_bad *b, const char *g, const char *x)
{
    if (b->n >= DTR_LIST)
        dtr_over("violation rows", DTR_LIST);
    if (x) {
        if (snprintf(b->v[b->n], DTR_LISTROW, "%s -> %s", g, x)
            >= DTR_LISTROW)
            dtr_over("violation row", DTR_LISTROW);
    } else {
        if (strlen(g) >= DTR_LISTROW)
            dtr_over("violation row", DTR_LISTROW);
        strcpy(b->v[b->n], g);
    }
    b->n++;
}

/* ── subprocess runner: fork + execvp, stderr to /dev/null ─────────────── */
int dtr_run(const char *file, char *const argv[], char *out, size_t cap,
            int *st)
{
    int fds[2];
    if (pipe(fds) != 0)
        return 1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return 1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0)
            dup2(nul, 2);
        execvp(file, argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    char b[4096];
    ssize_t r;
    int over = 0;
    while ((r = read(fds[0], b, sizeof b)) > 0) {
        if (n + (size_t)r > cap - 1) {
            over = 1;
            break;
        }
        memcpy(out + n, b, (size_t)r);
        n += (size_t)r;
    }
    close(fds[0]);
    int ws = 0, w;
    do {
        w = waitpid(pid, &ws, 0);
    } while (w < 0 && errno == EINTR);
    if (w < 0)
        return 2;
    *st = WIFEXITED(ws) ? WEXITSTATUS(ws) : 128;
    if (over)
        return 2;
    out[n] = '\0';
    return 0;
}

static int dtr_git(const char *root, const char *a, const char *b,
                   const char *c, const char *d, char *out, size_t cap,
                   int *st)
{
    char *argv[8];
    int n = 0;
    argv[n++] = (char *)"git";
    argv[n++] = (char *)"-C";
    argv[n++] = (char *)root;
    argv[n++] = (char *)a;
    if (b)
        argv[n++] = (char *)b;
    if (c)
        argv[n++] = (char *)c;
    if (d)
        argv[n++] = (char *)d;
    argv[n] = NULL;
    return dtr_run("git", argv, out, cap, st);
}

static int dtr_ref_ok(const char *root, const char *ref, char *buf,
                      size_t cap)
{
    int st;
    if (dtr_git(root, "rev-parse", "--verify", "-q", ref, buf, cap, &st))
        return 0;
    return st == 0;
}

/* ── the registry, from the catalog ─────────────────────────────────────── */
static int dtr_cat_name(const char *line, const char *pfx, const char *pre,
                        char *name, size_t cap)
{
    size_t pl = strlen(pfx);
    if (strncmp(line, pfx, pl) != 0)
        return 1;
    size_t i = pl, j = 0;
    while (isalnum((unsigned char)line[i]) || line[i] == '_') {
        if (j + strlen(pre) + 1 >= cap)
            dtr_over("catalog group name", (long)cap);
        name[j++] = line[i++];
    }
    if (line[i] != ')')
        return 1;
    name[j] = '\0';
    char full[DTR_NAME];
    if (strlen(pre) + j >= sizeof full)
        dtr_over("catalog group name", DTR_NAME);
    snprintf(full, sizeof full, "%s%s", pre, name);
    strcpy(name, full);
    return 0;
}

static int dtr_load_groups(struct dtr_names *g, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* unreadable registry: empty set, caller fails closed */
    char line[DTR_LINE], name[DTR_NAME];
    int r;
    while ((r = dtr_getline(f, line, sizeof line)) == 1) {
        if (dtr_cat_name(line, "ZCL_TEST_GROUP(", "test_", name,
                         sizeof name) == 0
            || dtr_cat_name(line, "ZCL_SPEC_GROUP(", "spec_", name,
                            sizeof name) == 0)
            dtr_add_uniq(g, name);
    }
    fclose(f);
    if (r < 0)
        dtr_over("catalog line", DTR_LINE);
    return 0;
}

/* ── the perturbation vocabulary ────────────────────────────────────────── */
static int dtr_tok_upper(const char *s, size_t n, struct dtr_names *p)
{
    size_t i = 0, j;
    while (i < n && isspace((unsigned char)s[i]))
        i++;
    j = i;
    while (j < n && !isspace((unsigned char)s[j]))
        j++;
    if (j <= i)
        return 0;
    for (size_t k = i; k < j; k++)
        if (!(isupper((unsigned char)s[k]) || s[k] == '_'))
            return 0;
    char name[DTR_NAME];
    if (j - i >= sizeof name)
        return 0;
    memcpy(name, s + i, j - i);
    name[j - i] = '\0';
    dtr_add_uniq(p, name);
    return 0;
}

static int dtr_pert_tool(const char *tool, struct dtr_names *p)
{
    static char out[8192];
    int st;
    char *av[3];
    av[0] = (char *)tool;
    av[1] = (char *)"list-profiles";
    av[2] = NULL;
    int rc = dtr_run(tool, av, out, sizeof out, &st);
    if (rc == 2)
        return 2;
    if (rc != 0 || st != 0)
        return 0;
    const char *q = out;
    while (*q) {
        const char *e = strchr(q, '\n');
        size_t n = e ? (size_t)(e - q) : strlen(q);
        dtr_tok_upper(q, n, p);
        if (!e)
            break;
        q = e + 1;
    }
    return 0;
}

static int dtr_pert_hdr(struct dtr_names *p, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[DTR_LINE], name[DTR_NAME];
    int r;
    while ((r = dtr_getline(f, line, sizeof line)) == 1) {
        size_t i = 0;
        while (isspace((unsigned char)line[i]))
            i++;
        if (strncmp(line + i, "ZCL_DET_P_", 10) != 0)
            continue;
        i += 10;
        size_t j = i;
        while (isupper((unsigned char)line[j]) || line[j] == '_')
            j++;
        size_t nend = j;
        if (line[j] == ',')
            j++;
        int rest_blank = 1;
        for (size_t k = j; line[k]; k++)
            if (!isspace((unsigned char)line[k]))
                rest_blank = 0;
        if (!rest_blank || j == i)
            continue;
        if (nend - i >= sizeof name)
            dtr_over("perturbation name", DTR_NAME);
        memcpy(name, line + i, nend - i);
        name[nend - i] = '\0';
        if (strcmp(name, "_COUNT") == 0)
            continue;
        dtr_add_uniq(p, name);
    }
    fclose(f);
    if (r < 0)
        dtr_over("perturbation header line", DTR_LINE);
    return 0;
}

static int dtr_load_perts(struct dtr_names *p, const char *root)
{
    char tool[DTR_PATH];
    if (ovf(snprintf(tool, sizeof tool, "%s/build/bin/determinism_scan",
                     root), sizeof tool))
        return 2;
    if (access(tool, X_OK) == 0)
        return dtr_pert_tool(tool, p);
    char hdr[DTR_PATH];
    if (ovf(snprintf(hdr, sizeof hdr, "%s/%s", root, k_dtr_pert_rel),
            sizeof hdr))
        return 2;
    return dtr_pert_hdr(p, hdr);
}

/* ── the baseline rows ──────────────────────────────────────────────────── */
/* Each "+"-separated perturbation token must be one the scan tool applies. */
static void dtr_row_causes(struct dtr_ctx *cx, const char *group,
                           const char *cause, const struct dtr_names *p)
{
    char tok[DTR_NAME];
    while (*cause) {
        const char *e = strchr(cause, '+');
        size_t tl = e ? (size_t)(e - cause) : strlen(cause);
        if (tl) {
            if (tl >= sizeof tok)
                dtr_over("perturbation token", DTR_NAME);
            memcpy(tok, cause, tl);
            tok[tl] = '\0';
            if (!dtr_has(p, tok))
                dtr_bad_add(&cx->badpert, group, tok);
        }
        if (!e)
            break;
        cause = e + 1;
    }
}

static int dtr_row(struct dtr_ctx *cx, const char *line, int lower,
                   const struct dtr_names *g, const struct dtr_names *p)
{
    char group[DTR_NAME], cls[DTR_NAME];
    const char *sp = strchr(line, ' ');
    size_t gl = sp ? (size_t)(sp - line) : strlen(line);
    if (gl >= sizeof group)
        dtr_over("baseline group name", DTR_NAME);
    memcpy(group, line, gl);
    group[gl] = '\0';
    if (!sp || sp[1 + strspn(sp + 1, " \t\n\v\f\r")] == '\0') {
        dtr_bad_add(&cx->nocause, group, NULL);
        return 0;
    }
    const char *sp2 = strchr(sp + 1, ' ');
    if (!sp2 || sp2[1 + strspn(sp2 + 1, " \t\n\v\f\r")] == '\0') {
        dtr_bad_add(&cx->nocause, group, NULL);
        return 0;
    }
    if (!dtr_has(g, group))
        dtr_bad_add(&cx->badgrp, group, NULL);
    size_t cl = (size_t)(sp2 - (sp + 1));
    if (cl >= sizeof cls)
        dtr_over("baseline class column", DTR_NAME);
    memcpy(cls, sp + 1, cl);
    cls[cl] = '\0';
    if (strcmp(cls, "NONDETERMINISTIC") != 0
        && strcmp(cls, "TIMING_SENSITIVE") != 0)
        dtr_bad_add(&cx->cls, group, cls);
    dtr_row_causes(cx, group, sp2 + 1, p);
    if (lower)
        dtr_add_uniq(&cx->now, group);
    return 0;
}

static void dtr_count_hdr(struct dtr_ctx *cx, const char *line)
{
    if (strncmp(line, "# count:", 8) != 0)
        return;
    size_t i = 8;
    while (isspace((unsigned char)line[i]))
        i++;
    if (!isdigit((unsigned char)line[i]))
        return;
    long v = 0;
    while (isdigit((unsigned char)line[i])) {
        if (v < 100000000)
            v = v * 10 + (line[i] - '0');
        i++;
    }
    if (!cx->have_declared) {
        cx->declared = v;
        cx->have_declared = 1;
    }
}

static int dtr_scan_baseline(const char *path, struct dtr_ctx *cx,
                             const struct dtr_names *g,
                             const struct dtr_names *p)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "check-determinism-ratchet: cannot read %s\n", path);
        return 2;
    }
    char line[DTR_LINE];
    int r;
    while ((r = dtr_getline(f, line, sizeof line)) == 1) {
        if (line[0] == '\0' || line[0] == '#') {
            dtr_count_hdr(cx, line);
            continue;
        }
        int lower = islower((unsigned char)line[0]) != 0;
        if (lower)
            cx->rows++;
        if (dtr_row(cx, line, lower, g, p)) {
            fclose(f);
            return 2;
        }
    }
    if (ferror(f)) {
        fclose(f);
        return 2;
    }
    fclose(f);
    if (r < 0)
        dtr_over("baseline line", DTR_LINE);
    return 0;
}

static void dtr_dump(const struct dtr_bad *b, FILE *out)
{
    for (int i = 0; i < b->n; i++)
        fprintf(out, "    %s\n", b->v[i]);
}

static int dtr_report_all(const struct dtr_ctx *cx, FILE *out)
{
    int fail = 0;
    if (!cx->have_declared) {
        fail = 1;
        fprintf(out, "FAIL: %s has no '# count: N' header line.\n"
                "  The header is what stops the number in a report from drifting\n"
                "  away from the rows in the file. Add it.\n",
                k_dtr_baseline_rel);
    } else if (cx->declared != cx->rows) {
        fail = 1;
        fprintf(out, "FAIL: %s declares '# count: %ld' but has %d row(s).\n"
                "  Update the header in the same commit as the rows.\n",
                k_dtr_baseline_rel, cx->declared, cx->rows);
    }
    if (cx->cls.n) {
        fail = 1;
        fprintf(out, "FAIL: %s names a class that is not a recorded verdict:\n",
                k_dtr_baseline_rel);
        dtr_dump(&cx->cls, out);
        fprintf(out, "  The second column must be NONDETERMINISTIC or "
                "TIMING_SENSITIVE.\n  A row exists to say WHICH kind of "
                "unreproducibility was measured;\n  a class the classifier "
                "never emits means the row was hand-written.\n");
    }
    if (cx->nocause.n) {
        fail = 1;
        fprintf(out, "FAIL: baseline row(s) that name no splitting "
                "perturbation:\n");
        dtr_dump(&cx->nocause, out);
        fprintf(out, "\n  \"It varies\" is not a finding; \"it varies when CC"
                " is set\" is.\n  Each row is '<group> <CLASS> "
                "<PERTURBATION>[+<PERTURBATION>...]'.\n");
    }
    if (cx->badgrp.n) {
        fail = 1;
        fprintf(out, "FAIL: baseline row(s) naming a group that is not "
                "registered:\n");
        dtr_dump(&cx->badgrp, out);
        fprintf(out, "\n  Stale debt makes the tree look worse than it is and"
                " hides a\n  rename. Delete the row, or fix the name.\n");
    }
    if (cx->badpert.n) {
        fail = 1;
        fprintf(out, "FAIL: baseline row(s) naming an unknown perturbation:\n");
        dtr_dump(&cx->badpert, out);
        fprintf(out, "\n  Valid names come from 'determinism_scan "
                "list-profiles'.\n");
    }
    return fail;
}

/* ── A. shrink-only against the integration point ───────────────────────── */
static void dtr_old_groups(const char *head, struct dtr_names *old)
{
    const char *q = head;
    while (*q) {
        const char *e = strchr(q, '\n');
        size_t n = e ? (size_t)(e - q) : strlen(q);
        if (n && islower((unsigned char)q[0])) {
            size_t j = 0;
            while (j < n && !isspace((unsigned char)q[j]))
                j++;
            char name[DTR_NAME];
            if (j < sizeof name) {
                memcpy(name, q, j);
                name[j] = '\0';
                dtr_add_uniq(old, name);
            }
        }
        if (!e)
            break;
        q = e + 1;
    }
}

static int dtr_shrink(const char *root, const struct dtr_names *now,
                      FILE *out)
{
    static char head[DTR_GITOUT];
    static struct dtr_names old;
    char anchor[DTR_SHA] = "HEAD", scrap[DTR_SHA * 2];
    memset(&old, 0, sizeof old);
    if (dtr_ref_ok(root, "origin/main", scrap, sizeof scrap)) {
        char mb[DTR_SHA];
        int st;
        if (dtr_git(root, "merge-base", "HEAD", "origin/main", NULL, mb,
                    sizeof mb, &st) == 0 && st == 0 && mb[0]) {
            char *nl = strchr(mb, '\n');
            if (nl)
                *nl = '\0';
            snprintf(anchor, sizeof anchor, "%s", mb);
        }
    }
    int have = 0;
    if (dtr_ref_ok(root, anchor, scrap, sizeof scrap)) {
        char ref[DTR_PATH];
        int st;
        if (!ovf(snprintf(ref, sizeof ref, "%s:%s", anchor,
                          k_dtr_baseline_rel), sizeof ref)
            && dtr_git(root, "show", ref, NULL, NULL, head, sizeof head,
                       &st) == 0 && st == 0)
            have = 1;
    }
    if (!have) {
        fprintf(out, "note: no ancestor %s at HEAD — treating this as the\n"
                "      first commit of the record. Every later commit may "
                "only shrink it.\n", k_dtr_baseline_rel);
        return 0;
    }
    dtr_old_groups(head, &old);
    int grew = 0;
    for (int i = 0; i < now->n; i++) {
        if (dtr_has(&old, now->v[i]))
            continue;
        if (!grew) {
            grew = 1;
            fprintf(out, "FAIL: the determinism baseline GREW. New "
                    "non-reproducing group(s):\n");
        }
        fprintf(out, "    %s\n", now->v[i]);
    }
    if (grew)
        fprintf(out, "\n  This baseline is shrink-only. A group appearing "
                "here means a\n  test stopped giving the same answer twice, "
                "and the fix is the\n  test, not the baseline. There is no "
                "flag that admits a new row.\n");
    return grew;
}


int dtr_check_root(const char *root, FILE *out)
{
    static struct dtr_names groups, perts;
    static struct dtr_ctx cx;
    char bpath[DTR_PATH], cpath[DTR_PATH];
    memset(&groups, 0, sizeof groups);
    memset(&perts, 0, sizeof perts);
    memset(&cx, 0, sizeof cx);
    if (ovf(snprintf(bpath, sizeof bpath, "%s/%s", root,
                     k_dtr_baseline_rel), sizeof bpath)
        || ovf(snprintf(cpath, sizeof cpath, "%s/%s", root,
                        k_dtr_catalog_rel), sizeof cpath))
        return 2;
    FILE *bf = fopen(bpath, "r");
    if (!bf) {
        fprintf(out, "FAIL: no readable determinism baseline at %s\n"
                "  A ratchet with no record is not a ratchet. Produce one "
                "with\n  'make determinism-scan' and commit it.\n", bpath);
        return 1;
    }
    fclose(bf);
    int rc = dtr_load_groups(&groups, cpath);
    if (rc)
        return rc;
    if (groups.n == 0) {
        fprintf(out, "FAIL: no registered groups found in %s\n"
                "  This gate cannot validate a baseline against a registry "
                "it\n  cannot read. Fail closed rather than pass vacuously.\n",
                cpath);
        return 1;
    }
    rc = dtr_load_perts(&perts, root);
    if (rc)
        return rc;
    if (perts.n == 0) {
        fprintf(out, "FAIL: no perturbation names found (neither the built\n"
                "      determinism_scan nor engine/modules/determinism/"
                "include/determinism/perturbation.h).\n");
        return 1;
    }
    rc = dtr_scan_baseline(bpath, &cx, &groups, &perts);
    if (rc)
        return rc;
    int fail = dtr_report_all(&cx, out);
    qsort(cx.now.v, (size_t)cx.now.n, DTR_NAME, dtr_cmp);
    rc = dtr_shrink(root, &cx.now, out);
    if (rc == 2)
        return 2;
    fail |= rc;
    if (fail)
        return 1;
    fprintf(out, "OK: determinism baseline is well formed and did not grow — "
            "%d non-reproducing group(s).\n", cx.rows);
    return 0;
}

int check_determinism_ratchet_run(int argc, char **argv)
{
    if (argc >= 1 && strcmp(argv[0], "--selftest") == 0)
        return check_determinism_ratchet_selftest();
    if (argc >= 1) {
        fprintf(stderr, "usage: z23-lint check-determinism-ratchet "
                "[--selftest]\n");
        return 2;
    }
    return dtr_check_root(env_or("ZCL_DETERMINISM_ROOT", "."), stdout);
}
