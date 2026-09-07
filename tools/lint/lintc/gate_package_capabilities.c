/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HARD gate — every C23 Commons package's zcode-package.json states
 * the union of capability classes its SHIPPED files can reach, exactly: not
 * a superset, not a subset. Ported from
 * tools/lint/check_package_capabilities.sh, which is now a 3-line exec shim
 * onto this binary. Parsers live in gate_package_capabilities_parse.c;
 * selftest in gate_package_capabilities_selftest.c.
 *
 * PRESENCE: a manifest with no "capabilities" key is a VIOLATION, never
 * "assume empty" — the value of an empty array is that somebody DERIVED it,
 * and a reader who cannot tell "reaches nothing" from "nobody wrote it
 * down" has been handed the second while believing the first.
 *
 * SYMMETRY, both directions: a class a shipped file reaches that the
 * manifest omits (UNDERSTATES), and a class the manifest names that no
 * shipped file reaches (OVERSTATES — a claim nobody re-derived).
 *
 * HOLLOWNESS: zero classes, zero module rows, zero packages parsed, or any
 * package shipping zero C sources exits UNPROVEN (2), never a clean 0 — the
 * same discipline check_zcode_package_standalone.sh applies to its own scan
 * set.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gate_package_capabilities_priv.h"

static const char k_classes_def[] = "engine/composition/capability_classes.def";
static const char *const k_modules_defs[] = {
    "engine/composition/module_capabilities.def",
    "engine/composition/module_capabilities_linux.def",
    "engine/composition/module_capabilities_windows.def",
};
static const char *const k_registry_defs[] = {
    "engine/composition/zcode_package_registry.def",
    "engine/composition/zcode_c23_commons_app.def",
};

int pc_append(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (ovf(k, cap - *used))
        return 2;
    *used += (size_t)k;
    return 0;
}

static int pc_cmp_str(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }
void pc_render(const struct sr_set *s, char *out, size_t cap, int json_style)
{
    static char sorted[SR_ALLOW][SR_NAME];
    int n = s->count;
    for (int i = 0; i < n; i++)
        memcpy(sorted[i], s->n[i], strlen(s->n[i]) + 1);
    qsort(sorted, (size_t)n, SR_NAME, pc_cmp_str);
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        if (i > 0)
            pc_append(out, cap, &used, json_style ? ", " : " ");
        pc_append(out, cap, &used, json_style ? "\"%s\"" : "%s", sorted[i]);
    }
}

static int pc_open_classes(const char *root, struct sr_set *classes, FILE *out)
{
    char path[PC_PATHLEN * 2];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_classes_def), sizeof path))
        return 2;
    int n = 0;
    int rc = pc_load_classes(path, classes, &n);
    if (rc == -1) {
        fprintf(out, "check_package_capabilities: UNPROVEN — cannot read %s\n", path);
        fputs("  That file is the closed list of class names a manifest may use.\n"
             "  Without it every declared name would have to be believed.\n", out);
        return 2;
    }
    if (rc)
        return rc;
    if (n < 1) {
        fprintf(out, "check_package_capabilities: UNPROVEN — parsed 0 classes from\n"
               "  %s. Either it is empty or this script's reader no\n"
               "  longer matches its ZCL_CAPABILITY_CLASS(...) shape. Refusing to\n"
               "  grade declarations against a vocabulary that saw nothing.\n", path);
        return 2;
    }
    return 0;
}

static int pc_open_modules(const char *root, struct pc_modtable *mods, FILE *out,
                           int *n_mod)
{
    char paths[3][PC_PATHLEN * 2];
    const char *present[3];
    int npresent = 0;
    for (int i = 0; i < 3; i++) {
        if (ovf(snprintf(paths[i], sizeof paths[i], "%s/%s", root, k_modules_defs[i]),
                sizeof paths[i]))
            return 2;
        struct stat st;
        if (stat(paths[i], &st) == 0)
            present[npresent++] = paths[i];
    }
    if (npresent == 0) {
        fprintf(out, "check_package_capabilities: UNPROVEN — cannot read %s\n",
               k_modules_defs[0]);
        fputs("  That file is what every package capability set is DERIVED from.\n"
             "  Its absence is a broken precondition, not zero violations.\n", out);
        return 2;
    }
    int rc = pc_load_module_rows(present, npresent, mods, n_mod);
    if (rc)
        return rc;
    if (*n_mod < 1) {
        fprintf(out, "check_package_capabilities: UNPROVEN — parsed 0 rows from\n"
               "  %s. Every package would derive the empty set and\n"
               "  every genuinely inert package would 'pass' off a scan that saw\n"
               "  nothing. That is not a proof of inertness.\n", k_modules_defs[0]);
        return 2;
    }
    return 0;
}

static int pc_open_registry(const char *root, struct pc_pkg *pkgs, int *npkg, FILE *out)
{
    char paths[2][PC_PATHLEN * 2];
    const char *present[2];
    int npresent = 0;
    for (int i = 0; i < 2; i++) {
        if (ovf(snprintf(paths[i], sizeof paths[i], "%s/%s", root, k_registry_defs[i]),
                sizeof paths[i]))
            return 2;
        struct stat st;
        if (stat(paths[i], &st) == 0)
            present[npresent++] = paths[i];
    }
    int rc = pc_load_registry(present, npresent, pkgs, PC_MAXPKG, npkg);
    if (rc)
        return rc;
    if (*npkg == 0) {
        fprintf(out, "check_package_capabilities: UNPROVEN — no ZCODE_PACKAGE rows parsed\n"
               "  from %s %s under %s. Zero packages graded is\n"
               "  a scan that did not happen, never a clean tree.\n",
               k_registry_defs[0], k_registry_defs[1], root);
        return 2;
    }
    return 0;
}

/* vocabulary (2) + canonical ascending order (3), before any set compare —
 * an unknown or misordered name makes the comparison meaningless. */
static int pc_check_vocab_order(const char *name, char (*decl)[PC_ARRLEN], int dn,
                                const struct sr_set *classes, char *rep, size_t cap,
                                size_t *used)
{
    int bad = 0;
    const char *prev = "";
    for (int i = 0; i < dn; i++) {
        if (!sr_has(classes, decl[i])) {
            bad = 1;
            if (pc_append(rep, cap, used,
                         "check_package_capabilities: VIOLATION — %s declares '%s',\n"
                         "  which is not a class in engine/composition/capability_classes.def.\n"
                         "  CAP_NONE is not a class and has no row there; the empty set\n"
                         "  is spelled [].\n", name, decl[i]))
                return -1;
        }
        if (prev[0] && !(strcmp(prev, decl[i]) < 0)) {
            bad = 1;
            if (pc_append(rep, cap, used,
                         "check_package_capabilities: VIOLATION — %s declares '%s'\n"
                         "  after '%s'. capabilities[] must be strictly ascending and\n"
                         "  duplicate-free: a manifest is content-addressed, so two\n"
                         "  spellings of one set are two roots for one package.\n",
                         name, decl[i], prev))
                return -1;
        }
        prev = decl[i];
    }
    return bad;
}

/* Sorted derived classes not in decl[], into missing_toks (caller-owned).
 * Returns the count. */
static int pc_find_missing(const struct sr_set *derived, char (*decl)[PC_ARRLEN], int dn,
                           char missing_toks[][SR_NAME])
{
    static char sorted[SR_ALLOW][SR_NAME];
    int dc = derived->count;
    for (int i = 0; i < dc; i++)
        memcpy(sorted[i], derived->n[i], strlen(derived->n[i]) + 1);
    qsort(sorted, (size_t)dc, SR_NAME, pc_cmp_str);
    int n_missing = 0;
    for (int i = 0; i < dc; i++) {
        int declared = 0;
        for (int j = 0; j < dn; j++)
            if (strcmp(decl[j], sorted[i]) == 0) { declared = 1; break; }
        if (!declared)
            memcpy(missing_toks[n_missing++], sorted[i], strlen(sorted[i]) + 1);
    }
    return n_missing;
}
static int pc_report_missing(const char *name, char missing_toks[][SR_NAME], int n_missing,
                             struct pc_modtable *mods, char (*sources)[PC_SRCLEN], int sn,
                             char *rep, size_t cap, size_t *used)
{
    char names[PC_RENDERBUF] = "";
    size_t nused = 0;
    for (int i = 0; i < n_missing; i++)
        if (pc_append(names, sizeof names, &nused, i ? " %s" : "%s", missing_toks[i]))
            return 2;
    if (pc_append(rep, cap, used,
                 "check_package_capabilities: VIOLATION — %s UNDERSTATES its reach.\n"
                 "  Shipped files declare %s, the manifest does not.\n", name, names))
        return 2;
    for (int i = 0; i < n_missing; i++)
        for (int j = 0; j < sn; j++) {
            struct pc_pathcaps *row = pc_modtable_find(mods, sources[j]);
            if (row && pc_capset_has(&row->caps, missing_toks[i])
                && pc_append(rep, cap, used, "    %s <- %s\n", missing_toks[i], sources[j]))
                return 2;
        }
    return 0;
}
static int pc_report_extra(const char *name, char (*decl)[PC_ARRLEN], int dn,
                           const struct sr_set *derived, char *rep, size_t cap,
                           size_t *used)
{
    char names[PC_RENDERBUF] = "";
    size_t nused = 0;
    int seen = 0;
    for (int i = 0; i < dn; i++) {
        if (sr_has(derived, decl[i]))
            continue;
        if (pc_append(names, sizeof names, &nused, seen ? " %s" : "%s", decl[i]))
            return 2;
        seen = 1;
    }
    return pc_append(rep, cap, used,
                     "check_package_capabilities: VIOLATION — %s OVERSTATES its reach.\n"
                     "  Manifest declares %s, no shipped file reaches it.\n"
                     "  Shrink the declaration; a claim nobody re-derived is not a\n"
                     "  safety margin, it is rot in the other direction.\n", name, names);
}
static int pc_report_summary(const char *name, const struct sr_set *derived, int clean,
                             char *rep, size_t cap, size_t *used)
{
    char buf[PC_RENDERBUF];
    if (clean) {
        pc_render(derived, buf, sizeof buf, 0);
        return pc_append(rep, cap, used, "  %-28s capabilities: [%s]\n", name, buf);
    }
    pc_render(derived, buf, sizeof buf, 1);
    return pc_append(rep, cap, used, "  Derived value for %s:\n"
                     "      \"capabilities\": [%s]\n", name, buf);
}
static int pc_count_extra(char (*decl)[PC_ARRLEN], int dn, const struct sr_set *derived)
{
    int n_extra = 0;
    for (int i = 0; i < dn; i++)
        if (!sr_has(derived, decl[i]))
            n_extra++;
    return n_extra;
}
static int pc_check_symmetry(const char *name, char (*decl)[PC_ARRLEN], int dn,
                             const struct sr_set *derived, struct pc_modtable *mods,
                             char (*sources)[PC_SRCLEN], int sn, char *rep, size_t cap,
                             size_t *used, int *violations)
{
    static char missing_toks[SR_ALLOW][SR_NAME];
    int n_missing = pc_find_missing(derived, decl, dn, missing_toks);
    int n_extra = pc_count_extra(decl, dn, derived);

    if (n_missing > 0) {
        (*violations)++;
        if (pc_report_missing(name, missing_toks, n_missing, mods, sources, sn, rep, cap,
                              used))
            return 2;
    }
    if (n_extra > 0) {
        (*violations)++;
        if (pc_report_extra(name, decl, dn, derived, rep, cap, used))
            return 2;
    }
    return pc_report_summary(name, derived, n_missing == 0 && n_extra == 0, rep, cap, used);
}

/* Returns 0 (handled — violations already updated) or 2 (hollow scan /
 * internal overflow — the caller propagates immediately). */
static int pc_grade_package(const char *root, const struct pc_pkg *pkg,
                            struct pc_modtable *mods, const struct sr_set *classes,
                            char *rep, size_t cap, size_t *used, int *violations,
                            int *n_src_total, FILE *out)
{
    char manifest[PC_PATHLEN * 2];
    if (ovf(snprintf(manifest, sizeof manifest, "%s/%s/zcode-package.json", root,
                     pkg->dir), sizeof manifest))
        return 2;
    struct stat st;
    if (stat(manifest, &st) != 0) {
        (*violations)++;
        return pc_append(rep, cap, used,
                         "check_package_capabilities: VIOLATION — %s has no manifest at\n"
                         "  %s/zcode-package.json, so it can declare nothing at all.\n",
                         pkg->name, pkg->dir);
    }

    static char sources[PC_MAXSRC][PC_SRCLEN];
    int sn = 0;
    if (pc_pkg_sources(root, pkg->dir, sources, PC_MAXSRC, &sn) == 2)
        return 2;
    if (sn == 0) {
        fprintf(out,
               "check_package_capabilities: UNPROVEN — %s (%s) ships zero C\n"
               "  sources. Deriving the empty capability set from an empty file\n"
               "  list would 'prove' the package inert without reading one line\n"
               "  of it. A package this gate cannot see is not a package it can\n"
               "  clear.\n", pkg->name, pkg->dir);
        return 2;
    }
    *n_src_total += sn;

    struct sr_set derived = { .count = 0 };
    for (int i = 0; i < sn; i++) {
        struct pc_pathcaps *row = pc_modtable_find(mods, sources[i]);
        if (!row)
            continue;
        for (int j = 0; j < row->caps.n; j++)
            if (sr_add(&derived, row->caps.v[j]))
                return 2;
    }

    static char decl[PC_MAXARR][PC_ARRLEN];
    int dn = 0;
    int drc = pc_json_array(manifest, "capabilities", decl, PC_MAXARR, &dn);
    if (drc == 2)
        return 2;
    if (drc == 1) {
        (*violations)++;
        char js[PC_RENDERBUF];
        pc_render(&derived, js, sizeof js, 1);
        return pc_append(rep, cap, used,
                         "check_package_capabilities: VIOLATION — %s (%s) has NO\n"
                         "  \"capabilities\" field in its manifest.\n"
                         "  Absent is not empty. A node reading this package cannot tell\n"
                         "  'reaches nothing' from 'nobody wrote it down', and only the\n"
                         "  first of those is worth anything. Add the derived value:\n"
                         "      \"capabilities\": [%s]\n", pkg->name, pkg->dir, js);
    }

    int bad = pc_check_vocab_order(pkg->name, decl, dn, classes, rep, cap, used);
    if (bad < 0)
        return 2;
    if (bad) {
        (*violations)++;
        return 0;
    }
    return pc_check_symmetry(pkg->name, decl, dn, &derived, mods, sources, sn, rep, cap,
                             used, violations);
}

int pc_check_root(const char *root, FILE *out)
{
    struct sr_set classes = { .count = 0 };
    int rc = pc_open_classes(root, &classes, out);
    if (rc)
        return rc;

    static struct pc_modtable mods;
    int n_mod = 0;
    rc = pc_open_modules(root, &mods, out, &n_mod);
    if (rc)
        return rc;

    static struct pc_pkg pkgs[PC_MAXPKG];
    int npkg = 0;
    rc = pc_open_registry(root, pkgs, &npkg, out);
    if (rc)
        return rc;

    static char report[PC_REPORTBUF];
    size_t used = 0;
    int violations = 0, n_src_total = 0;
    for (int i = 0; i < npkg; i++) {
        rc = pc_grade_package(root, &pkgs[i], &mods, &classes, report, sizeof report,
                              &used, &violations, &n_src_total, out);
        if (rc)
            return rc;
    }

    if (used > 0)
        fputs(report, out);
    fprintf(out, "check_package_capabilities: %d package(s), %d shipped\n"
           "  source(s), %d module row(s), %d capability class(es).\n", npkg,
           n_src_total, n_mod, classes.count);
    if (violations > 0) {
        fprintf(out, "check_package_capabilities: FAIL — %d violation(s)\n", violations);
        return 1;
    }
    fputs("check_package_capabilities: OK — every manifest states exactly what its\n"
         "  shipped files can reach\n", out);
    return 0;
}

int check_package_capabilities_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    return pc_check_root(root, stdout);
}
