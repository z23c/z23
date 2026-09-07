/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — test-registration drift guard of the C23 lint
 * runtime (check-test-registration). Catalog and runners are read
 * natively; tracked files via lint_git_index_foreach.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { TR_MAX = 4096, TR_NAME = 96, TR_LINE = 8192, TR_ORPH = 64 };

struct tr_set { char n[TR_MAX][TR_NAME]; int c; };
struct tr_map { char n[TR_MAX][TR_NAME]; char f[TR_MAX][RS_PATH]; int c; };
struct tr_rows { char r[TR_ORPH][RS_PATH + 64]; int c; };

static const char k_tr_dir[] = "tests/harness/src";
static const char k_tr_par[] = "tests/harness/src/test_parallel.c";
static const char k_tr_ser[] = "tests/harness/src/test.c";
static const char k_tr_cat[] = "tools/dev/test_group_catalog.def";
static const char k_tr_leaf[] = "tools/dev/test_semantic_leaves.def";

static int tr_has(const struct tr_set *s, const char *n)
{
    int i;
    for (i = 0; i < s->c; i++)
        if (strcmp(s->n[i], n) == 0)
            return 1;
    return 0;
}

static int tr_add(struct tr_set *s, const char *n)
{
    size_t k = strlen(n);
    if (tr_has(s, n))
        return 0;
    if (s->c >= TR_MAX || k >= TR_NAME)
        return die("z23-lint: test-registration overflow\n", "");
    memcpy(s->n[s->c++], n, k + 1);
    return 0;
}

static int tr_add_dup(struct tr_set *s, const char *n, int *dups)
{
    if (tr_has(s, n)) {
        (*dups)++;
        return 0;
    }
    return tr_add(s, n);
}

static int tr_macro_line(char *buf, const char *mac, size_t ml,
                         struct tr_set *s, int *dups)
{
    char *p = buf, *e, name[TR_NAME];
    while (*p == ' ' || *p == '\t')
        p++;
    if (strncmp(p, mac, ml) != 0 || p[ml] != '(')
        return 0;
    p += ml + 1;
    e = strchr(p, ')');
    if (!e)
        return 0;
    *e = '\0';
    if (ovf(snprintf(name, sizeof name, "%s", p), sizeof name))
        return 2;
    return tr_add_dup(s, name, dups);
}

static int tr_parse_macro(const char *path, const char *mac, struct tr_set *s)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE];
    int rc = 0, dups = 0;
    size_t ml;
    if (!f) {
        fprintf(stderr, "check_test_registration: FATAL — expected runner "
                        "file missing: %s\n", path);
        fputs("  The test-runner layout drifted; refusing to report "
              "'clean'.\n", stderr);
        return 2;
    }
    ml = strlen(mac);
    s->c = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f))
        rc = tr_macro_line(buf, mac, ml, s, &dups);
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    if (rc)
        return rc;
    if (dups) {
        fprintf(stderr, "FAIL: duplicate test group registration(s) in %s:\n",
                path);
        fputs("  Each parallel test group must have one canonical row.\n",
              stderr);
        return 1;
    }
    return 0;
}

static int tr_uniq_st(void)
{
    struct tr_set s = {0};
    int d = 0, rc;
    rc = tr_add_dup(&s, "alpha", &d) || tr_add_dup(&s, "beta", &d);
    if (rc || d)
        return die("check_test_registration: FATAL — uniqueness selftest "
                   "rejected clean input\n", "");
    s.c = 0;
    d = 0;
    tr_add_dup(&s, "alpha", &d);
    tr_add_dup(&s, "beta", &d);
    tr_add_dup(&s, "alpha", &d);
    if (d != 1)
        return die("check_test_registration: FATAL — uniqueness negative "
                   "control failed\n", "");
    return 0;
}

static int tr_need(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        return 0;
    fprintf(stderr, "check_test_registration: FATAL — expected runner "
                    "file missing: %s\n", path);
    fputs("  The test-runner layout drifted; refusing to report 'clean'.\n",
          stderr);
    return 2;
}

static int tr_serial(struct tr_set *s)
{
    FILE *f = fopen(k_tr_ser, "r");
    char buf[TR_LINE];
    int rc = 0;
    if (!f) {
        fprintf(stderr, "check_test_registration: FATAL — grep over %s "
                        "failed\n", k_tr_ser);
        return 2;
    }
    s->c = 0;
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        char *p = buf;
        while ((p = strstr(p, "test_")) != NULL) {
            char *q = p + 5, name[TR_NAME];
            size_t n = 0;
            while (n + 1 < sizeof name
                   && (isalnum((unsigned char)*q) || *q == '_'))
                name[n++] = *q++;
            name[n] = '\0';
            if (n && q[0] == '(' && q[1] == ')')
                rc = tr_add(s, name);
            p = q;
        }
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", k_tr_ser);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", k_tr_ser);
    return rc;
}

static int tr_is_entry(const char *path, const char *name)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE], want[128];
    int hit = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return -1;
    }
    if (ovf(snprintf(want, sizeof want, "int test_%s(void)", name),
            sizeof want)) {
        fclose(f);
        return -1;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (strcmp(buf, want) == 0) {
            hit = 1;
            break;
        }
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return -1;
    }
    fclose(f);
    return hit;
}

static int tr_is_src(const char *path, const char **base_out)
{
    const char *base;
    size_t n, dl = strlen(k_tr_dir);
    if (strncmp(path, k_tr_dir, dl) != 0 || path[dl] != '/')
        return 0;
    base = path + dl + 1;
    if (strchr(base, '/'))
        return 0;
    n = strlen(base);
    if (n < 3 || strcmp(base + n - 2, ".c") != 0)
        return 0;
    if (strncmp(base, "test_", 5) != 0)
        return 0;
    if (strcmp(base, "test_parallel.c") == 0 || strcmp(base, "test.c") == 0)
        return 0;
    *base_out = base;
    return 1;
}

struct tr_ep_ctx {
    struct tr_set *runs, *seen;
    struct tr_rows *orph;
    int entries;
    int rc;
};

static int tr_note_entry(struct tr_ep_ctx *c, const char *name, const char *path)
{
    if (tr_has(c->seen, name))
        return 0;
    if (tr_add(c->seen, name))
        return 2;
    c->entries++;
    if (tr_has(c->runs, name))
        return 0;
    if (c->orph->c >= TR_ORPH)
        return die("z23-lint: test-registration overflow\n", "");
    if (ovf(snprintf(c->orph->r[c->orph->c], sizeof c->orph->r[0],
                     "%s\t%s", name, path), sizeof c->orph->r[0]))
        return 2;
    c->orph->c++;
    return 0;
}

static int tr_on_test(const char *path, void *ctx)
{
    struct tr_ep_ctx *c = ctx;
    const char *base;
    int hit;
    if (c->rc)
        return c->rc;
    if (!tr_is_src(path, &base))
        return 0;
    {
        char nm[TR_NAME];
        size_t n = strlen(base);
        memcpy(nm, base, n - 2);
        nm[n - 2] = '\0';
        hit = tr_is_entry(path, nm + 5);
        if (hit < 0) {
            c->rc = 2;
            return 2;
        }
        if (!hit)
            return 0;
        c->rc = tr_note_entry(c, nm + 5, path);
    }
    return c->rc;
}

static int tr_index_file(struct tr_map *m, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[TR_LINE];
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        char *p, name[TR_NAME];
        size_t k;
        if (strncmp(buf, "int test_", 9) != 0)
            continue;
        p = buf + 9;
        k = 0;
        while (k + 1 < sizeof name
               && (isalnum((unsigned char)*p) || *p == '_'))
            name[k++] = *p++;
        name[k] = '\0';
        if (strcmp(p, "(void)\n") != 0 && strcmp(p, "(void)") != 0)
            continue;
        if (m->c >= TR_MAX) {
            fclose(f);
            return die("z23-lint: test-registration overflow\n", "");
        }
        memcpy(m->n[m->c], name, k + 1);
        memcpy(m->f[m->c], path, strlen(path) + 1);
        m->c++;
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    fclose(f);
    return 0;
}

static int tr_index_defs(struct tr_map *m)
{
    struct dirent **names = NULL;
    int n = scandir(k_tr_dir, &names, NULL, alphasort);
    int rc = 0, i;
    m->c = 0;
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", k_tr_dir);
    for (i = 0; i < n; i++) {
        size_t kn = strlen(names[i]->d_name);
        if (rc == 0 && kn >= 3 && strcmp(names[i]->d_name + kn - 2, ".c") == 0) {
            char path[4096];
            if (ovf(snprintf(path, sizeof path, "%s/%s", k_tr_dir,
                             names[i]->d_name), sizeof path))
                rc = 2;
            else
                rc = tr_index_file(m, path);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static const char *tr_def_file(const struct tr_map *m, const char *name)
{
    int i;
    for (i = 0; i < m->c; i++)
        if (strcmp(m->n[i], name) == 0)
            return m->f[i];
    return NULL;
}

static int tr_union(struct tr_set *runs, const struct tr_set *cat,
                    const struct tr_set *ser)
{
    int i, rc = 0;
    for (i = 0; rc == 0 && i < cat->c; i++)
        rc = tr_add(runs, cat->n[i]);
    for (i = 0; rc == 0 && i < ser->c; i++)
        rc = tr_add(runs, ser->n[i]);
    return rc;
}

static int tr_walk_src(struct tr_ep_ctx *ep)
{
    struct dirent **names = NULL;
    int n = scandir(k_tr_dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", k_tr_dir);
    for (i = 0; i < n; i++) {
        if (rc == 0) {
            char path[4096];
            if (ovf(snprintf(path, sizeof path, "%s/%s", k_tr_dir,
                             names[i]->d_name), sizeof path))
                rc = 2;
            else
                rc = tr_on_test(path, ep);
        }
        free(names[i]);
    }
    free(names);
    return rc ? rc : ep->rc;
}

static int tr_collect_entries(struct tr_ep_ctx *ep)
{
    int rc;
    if (lint_prod_scan()) {
        rc = lint_git_index_foreach(tr_on_test, ep);
        if (rc)
            return rc;
        return ep->rc;
    }
    return tr_walk_src(ep);
}

static int tr_drift_one(const char *name, const struct tr_set *cat,
                        const struct tr_map *defs, char drift[][RS_PATH + 64],
                        int *ndrift, int *serial_checked)
{
    const char *df, *base, *parent;
    char pn[TR_NAME];
    size_t k;
    if (tr_has(cat, name)) {
        (*serial_checked)++;
        return 0;
    }
    df = tr_def_file(defs, name);
    if (!df)
        return 0;
    (*serial_checked)++;
    base = strrchr(df, '/');
    base = base ? base + 1 : df;
    parent = base + (strncmp(base, "test_", 5) == 0 ? 5 : 0);
    k = strlen(parent);
    if (k >= 2 && strcmp(parent + k - 2, ".c") == 0)
        k -= 2;
    if (k >= sizeof pn)
        return 0;
    memcpy(pn, parent, k);
    pn[k] = '\0';
    if (tr_has(cat, pn))
        return 0;
    if (*ndrift < 64)
        snprintf(drift[(*ndrift)++], sizeof drift[0], "%s\t%s", name, df);
    return 0;
}

static void tr_print_row(const char *row)
{
    const char *tab = strchr(row, '\t');
    if (!tab)
        return;
    printf("    test_%.*s   (%s)\n", (int)(tab - row), row, tab + 1);
}

static int tr_report(int ndrift, char drift[][RS_PATH + 64],
                     const struct tr_rows *orph, int entries, int catc,
                     int serial_checked)
{
    int i;
    if (ndrift) {
        fputs("FAIL: test(s) dispatched ONLY by the legacy serial runner "
              "(test.c) and\n  ABSENT from the canonical registry in "
              "tools/dev/test_group_catalog.def.\n"
              "  `make test-parallel` is the doctrine runner and the\n"
              "  acceptance gate; build/bin/test_zcl is never run. These "
              "therefore\n  execute in NO gate and prove NOTHING:\n\n",
              stdout);
        for (i = 0; i < ndrift; i++)
            tr_print_row(drift[i]);
        fputs("\n  Fix: add ZCL_TEST_GROUP(<name>) to "
              "tools/dev/test_group_catalog.def — and\n"
              "  RUN it (make t-fast ONLY=test_<name>) before assuming it "
              "passes.\n  Do NOT delete the test, and do NOT silence this by "
              "removing the\n  test.c dispatch.\n", stdout);
        return 1;
    }
    if (orph->c) {
        fputs("FAIL: test entry point(s) DEFINED + COMPILED but dispatched "
              "by NEITHER\n  the canonical catalog nor the serial runner\n"
              "  (test.c). They prove NOTHING — green forever, never "
              "executed:\n\n", stdout);
        for (i = 0; i < orph->c; i++)
            tr_print_row(orph->r[i]);
        fputs("\n  Fix: add ZCL_TEST_GROUP(<name>) to "
              "tools/dev/test_group_catalog.def (the doctrine\n"
              "  `make test` runner), or\n"
              "  dispatch it from tests/harness/src/test.c. Do NOT delete "
              "the test to\n  silence this gate.\n", stdout);
        return 1;
    }
    printf("check_test_registration: clean — all %d test entry points are "
           "dispatched\n  (%d registered in the canonical catalog; the rest "
           "covered by the serial runner)\n  canonical-registry drift: 0 of "
           "%d serial-dispatched name(s)\n  run only under the legacy test.c "
           "runner\n", entries, catc, serial_checked);
    return 0;
}

static int tr_eval(struct tr_set *cat)
{
    static struct tr_set ser, runs, seen;
    static struct tr_rows orph;
    static struct tr_map defs;
    struct tr_ep_ctx ep;
    char drift[64][RS_PATH + 64];
    int ndrift = 0, rc, i, serial_checked = 0;
    ser.c = runs.c = seen.c = orph.c = 0;
    defs.c = 0;
    rc = tr_serial(&ser);
    if (rc)
        return rc;
    rc = tr_union(&runs, cat, &ser);
    if (rc)
        return rc;
    ep.runs = &runs;
    ep.orph = &orph;
    ep.seen = &seen;
    ep.entries = 0;
    ep.rc = 0;
    rc = tr_collect_entries(&ep);
    if (rc)
        return rc;
    if (ep.entries < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d "
                        "filename-matching test\n  entry points found under "
                        "%s (expected >=100).\n", ep.entries, k_tr_dir);
        return 2;
    }
    rc = tr_index_defs(&defs);
    if (rc)
        return rc;
    if (defs.c < 100) {
        fprintf(stderr, "check_test_registration: FATAL — indexed only %d "
                        "entry-point\n  definitions under %s (expected "
                        ">=100).\n", defs.c, k_tr_dir);
        return 2;
    }
    for (i = 0; i < ser.c; i++)
        tr_drift_one(ser.n[i], cat, &defs, drift, &ndrift, &serial_checked);
    if (serial_checked < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d "
                        "serial-dispatched\n  names resolved against the "
                        "canonical registry (expected >=100).\n",
                serial_checked);
        return 2;
    }
    return tr_report(ndrift, drift, &orph, ep.entries, cat->c, serial_checked);
}

int check_test_registration_run(int argc, char **argv)
{
    struct tr_set cat = {0};
    int rc;
    (void)argc;
    (void)argv;
    rc = tr_uniq_st();
    if (rc)
        return rc;
    rc = tr_need(k_tr_par) || tr_need(k_tr_ser) || tr_need(k_tr_cat)
        || tr_need(k_tr_leaf);
    if (rc)
        return rc;
    rc = tr_parse_macro(k_tr_cat, "ZCL_TEST_GROUP", &cat);
    if (rc)
        return rc;
    rc = tr_parse_macro(k_tr_leaf, "ZCL_TEST_SEMANTIC_LEAF", &(struct tr_set){0});
    if (rc)
        return rc;
    if (cat.c < 100) {
        fprintf(stderr, "check_test_registration: FATAL — only %d test "
                        "catalog entries parsed\n", cat.c);
        return 2;
    }
    return tr_eval(&cat);
}

static int tr_st_parse(void)
{
    struct tr_set s = {0};
    return tr_parse_macro(k_tr_cat, "ZCL_TEST_GROUP", &s) || s.c < 100;
}

static int tr_st_entry(void)
{
    return tr_is_entry("tests/harness/src/test_hex_codec.c", "hex_codec") != 1;
}

int check_test_registration_selftest(void)
{
    return st_ok(tr_uniq_st() || tr_st_parse() || tr_st_entry(),
                 "check_test_registration selftest: PASS — uniqueness "
                 "controls, catalog parse, and a filename-matching entry "
                 "point are proven\n");
}
