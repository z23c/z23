/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-doc-counts — machine-checks the numeric claims docs
 * make about code. Ported from tools/scripts/check_doc_counts.sh (deleted).
 * (A) the DOC-COUNTS block of docs/dev/CODEBASE_MAP.md must declare exactly
 * the counts measured from the code (ports, persistence adapters, condition
 * registrations, command bundles and roots, dumpstate subsystems, app shape
 * folders); (B) the prose of every tracked *.md must not cite a count that
 * disagrees with the code or return to a known-stale phrase (the scan is in
 * gate_doc_counts_scan.c); (C) the matchers are proven on a fixture before a
 * clean scan is trusted (gate_doc_counts_selftest.c). `--fix` rewrites the
 * declared values from the measured ones (make fix-doc-counts) and then
 * checks. The code is authoritative. Exit 0 clean, 1 drift, 2 broken.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_doc_counts_priv.h"

enum { DCN_KEYS = 7, DCN_LISTMAX = 512, DCN_DEFS = 128 };

static const char k_dcn_groups_file[] = "tools/dev/test_group_catalog.def";
static const char k_dcn_doc[] = "docs/dev/CODEBASE_MAP.md";
static const char k_dcn_commands[] = "engine/composition/commands";
static const char *const k_dcn_keys[DCN_KEYS] = {
    "port_interfaces", "persistence_adapters", "condition_registrations",
    "command_bundles", "command_roots", "dumpstate_subsystems",
    "app_shape_folders",
};

static char g_dcn_list[DCN_LISTMAX][DCN_PATH];
static int g_dcn_nlist;
static char g_dcn_defs[DCN_DEFS][LINT_DUMPER_PATH];
static char g_dcn_files[DCN_FILES][DCN_PATH];
static struct dcn_viol g_dcn_viol;

/* ── measurement ───────────────────────────────────────────────────── */

static int dcn_name_ends(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);
    return name[0] != '.' && n >= s && strcmp(name + n - s, suffix) == 0;
}

/* Append dir/<name><suffix> for every non-hidden match; an absent dir adds
 * nothing (nullglob). */
static int dcn_add_dir(const char *dir, const char *suffix)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (!dcn_name_ends(e->d_name, suffix))
            continue;
        if (g_dcn_nlist >= DCN_LISTMAX ||
            ovf(snprintf(g_dcn_list[g_dcn_nlist], DCN_PATH, "%s/%s", dir,
                         e->d_name), DCN_PATH)) {
            fprintf(stderr, "check_doc_counts: file list exceeds %d\n",
                    DCN_LISTMAX);
            rc = 2;
        } else {
            g_dcn_nlist++;
        }
    }
    closedir(d);
    return rc;
}

/* <base>/<every non-hidden entry>/<leaf>: add_dir for each. */
static int dcn_add_children(const char *base, const char *leaf,
                            const char *suffix)
{
    DIR *d = opendir(base);
    if (!d)
        return 0;
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        char sub[DCN_PATH];
        if (e->d_name[0] == '.')
            continue;
        if (ovf(snprintf(sub, sizeof sub, "%s/%s%s%s", base, e->d_name,
                         leaf[0] ? "/" : "", leaf), sizeof sub))
            rc = 2;
        else
            rc = dcn_add_dir(sub, suffix);
    }
    closedir(d);
    return rc;
}

struct dcn_lines { const regex_t *re; long n; };

static int dcn_line_matches(void *ctx, const char *line, size_t len)
{
    struct dcn_lines *s = ctx;
    (void)len;
    if (regexec(s->re, line, 0, NULL, 0) == 0)
        s->n++;
    return 0;
}

/* Lines of path matching the ERE (grep -c). */
static int dcn_grep_count(const char *path, const char *ere, long *total)
{
    regex_t re;
    int err = regcomp(&re, ere, REG_EXTENDED);
    if (err)
        return reg_fail(&re, err);
    struct dcn_lines s = { &re, 0 };
    int rc = lc_each_line(path, dcn_line_matches, &s, 0);
    regfree(&re);
    *total += s.n;
    return rc == 2 ? 2 : 0;
}

static int dcn_cond_line(void *ctx, const char *line, size_t len)
{
    struct dcn_lines *s = ctx;
    const char *at = line;
    regmatch_t m;
    (void)len;
    while (*at && regexec(s->re, at, 1, &m, 0) == 0 && m.rm_eo > 0) {
        s->n++;
        at += m.rm_eo;
    }
    return 0;
}

static int dcn_count_conditions(long *total)
{
    regex_t re;
    int err = regcomp(&re, "condition_register[[:space:]]*\\(", REG_EXTENDED);
    if (err)
        return reg_fail(&re, err);
    g_dcn_nlist = 0;
    int rc = dcn_add_dir("engine/conditions/src", ".c");
    rc = rc ? rc : dcn_add_dir("engine/reducer/conditions/src", ".c");
    rc = rc ? rc : dcn_add_children("contexts", "conditions/src", ".c");
    rc = rc ? rc : dcn_add_dir("cognition/conditions/src", ".c");
    struct dcn_lines s = { &re, 0 };
    for (int i = 0; rc == 0 && i < g_dcn_nlist; i++)
        rc = lc_each_line(g_dcn_list[i], dcn_cond_line, &s, 0) == 2 ? 2 : 0;
    regfree(&re);
    *total = s.n;
    return rc;
}

/* A ZCL_COMMAND_BRANCH( row declared with an empty parent: after the last
 * "ZCL_COMMAND_BRANCH(" the awk field $4 split on '"' is empty. */
static int dcn_root_line(void *ctx, const char *line, size_t len)
{
    long *n = ctx;
    const char key[] = "ZCL_COMMAND_BRANCH(";
    const char *last = NULL;
    (void)len;
    for (const char *p = strstr(line, key); p; p = strstr(p + 1, key))
        last = p;
    if (!last)
        return 0;
    const char *q = last + sizeof key - 1;
    for (int i = 0; i < 3 && q; i++) {
        q = strchr(q, '"');
        q = q ? q + 1 : NULL;
    }
    if (!q || *q == '"' || *q == '\n' || *q == '\0')
        (*n)++;
    return 0;
}

static int dcn_count_commands(long *bundles, long *roots)
{
    g_dcn_nlist = 0;
    int rc = dcn_add_dir(k_dcn_commands, ".def");
    rc = rc ? rc : dcn_add_children(k_dcn_commands, "", ".def");
    *bundles = g_dcn_nlist;
    *roots = 0;
    for (int i = 0; rc == 0 && i < g_dcn_nlist; i++)
        rc = lc_each_line(g_dcn_list[i], dcn_root_line, roots, 0) == 2 ? 2 : 0;
    return rc;
}

static int dcn_count_dir(const char *dir, const char *suffix, long *out)
{
    g_dcn_nlist = 0;
    int rc = dcn_add_dir(dir, suffix);
    *out = g_dcn_nlist;
    return rc;
}

static int dcn_count_dumpstate(long *total)
{
    int n = 0;
    if (lint_dumper_def_files(g_dcn_defs, DCN_DEFS, &n)) {
        fputs("FAIL: could not resolve the dumpstate descriptor set (run "
              "from repo root)\n", stderr);
        return 1;
    }
    *total = 0;
    for (int i = 0; i < n; i++)
        if (dcn_grep_count(g_dcn_defs[i], "^[[:space:]]*DIAG_[A-Z]+\\(",
                           total))
            return 2;
    return 0;
}

static int dcn_measure_dirs(struct dcn_counts *c)
{
    int rc = dcn_count_dir("platform/ports/include/ports", ".h", &c->ports);
    rc = rc ? rc : dcn_count_dir("platform/adapters/outbound/persistence/src",
                                 ".c", &c->adapters);
    rc = rc ? rc : dcn_count_conditions(&c->conditions);
    return rc ? rc : dcn_count_commands(&c->bundles, &c->roots);
}

static int dcn_measure(struct dcn_counts *c)
{
    struct stat st;
    int rc = rs_init();
    if (rc)
        return rc;
    if (stat(k_dcn_groups_file, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "FAIL: %s not found (run from repo root)\n",
                k_dcn_groups_file);
        return 1;
    }
    c->groups = 0;
    rc = dcn_count_dumpstate(&c->dumpstate);
    rc = rc ? rc : dcn_grep_count(k_dcn_groups_file,
        "^[[:space:]]*ZCL_(TEST|SPEC)_GROUP\\([a-z_0-9]+\\)[[:space:]]*$",
        &c->groups);
    rc = rc ? rc : dcn_measure_dirs(c);
    c->shapes = g_n_shapes;
    return rc;
}

/* ── the declared block and --fix ──────────────────────────────────── */

static void dcn_values(const struct dcn_counts *c, long out[DCN_KEYS])
{
    out[0] = c->ports;
    out[1] = c->adapters;
    out[2] = c->conditions;
    out[3] = c->bundles;
    out[4] = c->roots;
    out[5] = c->dumpstate;
    out[6] = c->shapes;
}

/* Length of "<ws>key<ws>:" at the start of line (the key anchored after
 * optional whitespace when lead_ws), else 0. */
static size_t dcn_key_prefix(const char *line, const char *key, int lead_ws)
{
    const char *p = line;
    if (lead_ws)
        while (isspace((unsigned char)*p) && *p != '\n')
            p++;
    size_t kl = strlen(key);
    if (strncmp(p, key, kl) != 0)
        return 0;
    p += kl;
    while (isspace((unsigned char)*p) && *p != '\n')
        p++;
    return *p == ':' ? (size_t)(p + 1 - line) : 0;
}

struct dcn_fix { FILE *out; long val[DCN_KEYS]; int bad; };

static int dcn_fix_line(void *ctx, const char *line, size_t len)
{
    struct dcn_fix *f = ctx;
    for (int k = 0; k < DCN_KEYS; k++) {
        size_t pl = dcn_key_prefix(line, k_dcn_keys[k], 0);
        if (!pl)
            continue;
        int nl = len > 0 && line[len - 1] == '\n';
        if (fprintf(f->out, "%.*s %ld%s", (int)pl, line, f->val[k],
                    nl ? "\n" : "") < 0)
            f->bad = 1;
        return f->bad;
    }
    if (fwrite(line, 1, len, f->out) != len)
        f->bad = 1;
    return f->bad;
}

int dcn_rewrite_file(const char *path, const struct dcn_counts *c)
{
    char tmp[DCN_PATH + 16];
    struct stat st;
    if (stat(path, &st) != 0 ||
        ovf(snprintf(tmp, sizeof tmp, "%s.dcn.tmp", path), sizeof tmp))
        return die("check_doc_counts: cannot rewrite %s\n", path);
    struct dcn_fix f = { .out = fopen(tmp, "w") };
    if (!f.out)
        return die("check_doc_counts: cannot write %s\n", tmp);
    dcn_values(c, f.val);
    int rc = lc_each_line(path, dcn_fix_line, &f, 0);
    if (fclose(f.out) != 0)
        rc = 2;
    if (rc == 0 && (chmod(tmp, st.st_mode & 07777) != 0 ||
                    rename(tmp, path) != 0))
        rc = 2;
    if (rc)
        remove(tmp);
    return rc ? 2 : 0;
}

struct dcn_block {
    int in_block, nonspace;
    char val[DCN_KEYS][128];
    int have[DCN_KEYS];
};

static void dcn_take_value(struct dcn_block *b, int k, const char *line)
{
    const char *colon = strrchr(line, ':');
    size_t o = 0;
    for (const char *p = colon + 1; *p; p++)
        if (!isspace((unsigned char)*p) && o + 1 < sizeof b->val[k])
            b->val[k][o++] = *p;
    b->val[k][o] = '\0';
    b->have[k] = 1;
}

static int dcn_block_line(void *ctx, const char *line, size_t len)
{
    struct dcn_block *b = ctx;
    (void)len;
    if (strstr(line, "<!-- DOC-COUNTS-BEGIN -->")) {
        b->in_block = 1;
        return 0;
    }
    if (strstr(line, "<!-- DOC-COUNTS-END -->")) {
        b->in_block = 0;
        return 0;
    }
    if (!b->in_block)
        return 0;
    for (const char *p = line; *p; p++)
        if (!isspace((unsigned char)*p))
            b->nonspace = 1;
    for (int k = 0; k < DCN_KEYS; k++)
        if (!b->have[k] && dcn_key_prefix(line, k_dcn_keys[k], 1))
            dcn_take_value(b, k, line);
    return 0;
}

static int dcn_check_block(const struct dcn_counts *c, struct dcn_viol *v)
{
    static struct dcn_block b;
    memset(&b, 0, sizeof b);
    if (lc_each_line(k_dcn_doc, dcn_block_line, &b, 0) == 2)
        return 2;
    if (!b.nonspace) {
        printf("FAIL: missing or empty <!-- DOC-COUNTS-BEGIN/END --> block "
               "in %s\n      Add port_interfaces / persistence_adapters /\n"
               "      condition_registrations declarations\n      (see the "
               "block format in %s) so the counts can be machine-checked.\n",
               k_dcn_doc, k_dcn_doc);
        return 1;
    }
    long want_v[DCN_KEYS];
    dcn_values(c, want_v);
    for (int k = 0; k < DCN_KEYS; k++) {
        char measured[32];
        if (ovf(snprintf(measured, sizeof measured, "%ld", want_v[k]), sizeof measured))
            return 2;
        int rc = 0;
        if (b.val[k][0] == '\0')
            rc = dcn_viol_add(v, "%s not declared in %s DOC-COUNTS block",
                              k_dcn_keys[k], k_dcn_doc);
        else if (strcmp(b.val[k], measured) != 0)
            rc = dcn_viol_add(v, "%s MISMATCH — code=%s doc-says=%s (update "
                              "the DOC-COUNTS block in %s)", k_dcn_keys[k],
                              measured, b.val[k], k_dcn_doc);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── the tracked *.md set ──────────────────────────────────────────── */

static int dcn_add_file(const char *path, void *ctx)
{
    int *n = ctx;
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (*n >= DCN_FILES || ovf(snprintf(g_dcn_files[*n], DCN_PATH, "%s", path),
                               DCN_PATH)) {
        fprintf(stderr, "check_doc_counts: scan set exceeds %d files\n",
                DCN_FILES);
        return 2;
    }
    (*n)++;
    return 0;
}

static int dcn_scan_set(int *n)
{
    *n = 0;
    if (each_zpath("git ls-files -z -- '*.md' 2>/dev/null", dcn_add_file, n) ==
            2)
        return 2;
    if (*n >= 2)
        return 0;
    *n = 0;
    struct stat st;
    static const char *const roots[] = { "CLAUDE.md", "README.md" };
    for (int i = 0; i < 2; i++)
        if (stat(roots[i], &st) == 0 && S_ISREG(st.st_mode) &&
            dcn_add_file(roots[i], n))
            return 2;
    return each_zpath("find docs -type f -name '*.md' -print0 2>/dev/null",
                      dcn_add_file, n) == 2 ? 2 : 0;
}

/* ── report ────────────────────────────────────────────────────────── */

static void dcn_report_fail(const struct dcn_viol *v)
{
    puts("\nFAIL: doc-count drift detected.");
    for (int i = 0; i < v->n; i++)
        printf("    %s\n", v->t[i]);
    printf("\nFix: the CODE is authoritative.\n"
           "  - For a MISMATCH: update the <!-- DOC-COUNTS --> block in %s\n"
           "    AND any prose (docs/commons/FRAMEWORK.md, CLAUDE.md, docs/dev/BUILD.md, "
           "docs/agent/HANDOFF.md) to match.\n"
           "  - For a stale phrase: delete or correct the prose (the number "
           "is wrong).\n", k_dcn_doc);
}

static void dcn_print_counts(const char *head, const struct dcn_counts *c)
{
    printf("%s test_groups=%ld port_interfaces=%ld persistence_adapters=%ld "
           "condition_registrations=%ld command_bundles=%ld command_roots=%ld "
           "dumpstate_subsystems=%ld app_shape_folders=%ld", head, c->groups,
           c->ports, c->adapters, c->conditions, c->bundles, c->roots,
           c->dumpstate, c->shapes);
}

static int dcn_stage_doc(const struct dcn_counts *c, int fix)
{
    struct stat st;
    if (stat(k_dcn_doc, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "FAIL: %s not found\n", k_dcn_doc);
        return 1;
    }
    if (!fix)
        return 0;
    int rc = dcn_rewrite_file(k_dcn_doc, c);
    if (rc == 0)
        printf("fixed: DOC-COUNTS block in %s rewritten from code-measured "
               "values\n", k_dcn_doc);
    return rc;
}

int check_doc_counts_run(int argc, char **argv)
{
    struct dcn_counts c;
    int rc = dcn_measure(&c);
    if (rc)
        return rc;
    dcn_print_counts("code-measured:", &c);
    putchar('\n');
    rc = dcn_stage_doc(&c, argc > 0 && strcmp(argv[0], "--fix") == 0);
    rc = rc ? rc : dcn_check_block(&c, &g_dcn_viol);
    if (rc == 1 || rc == 2)
        return rc;
    rc = dcn_selfcheck(&c);
    int n = 0;
    rc = rc ? rc : dcn_scan_set(&n);
    rc = rc ? rc : dcn_scan(&c, g_dcn_files, n, &g_dcn_viol);
    if (rc)
        return rc;
    if (g_dcn_viol.n > 0) {
        dcn_report_fail(&g_dcn_viol);
        return 1;
    }
    dcn_print_counts("check_doc_counts: clean —", &c);
    printf("; self-check fired as expected; %d tracked *.md scanned, no "
           "stale count claims\n", n);
    return 0;
}
