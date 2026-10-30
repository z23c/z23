/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the prose scan of check-doc-counts. Ported from scan_prose in
 * tools/scripts/check_doc_counts.sh (deleted). Two matchers over a file list:
 * a denylist of historically-wrong fixed phrases, and derived rules whose
 * "<N> <unit>" compound phrases must agree with the code-measured count
 * ("<N>+ <unit>" is an at-least claim and fails only when N exceeds it).
 * A line carrying doc-count-ok is exempt. Output order is rule-major, then
 * file, then line, as in the shell.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_doc_counts_priv.h"

static const char k_dcn_marker[] = "doc-count-ok";

static const char *const k_dcn_deny[] = {
    "1500+ tests", "1500 tests", "15 ports", "28 conditions live",
};

struct dcn_rule { const char *unit; long expected; const char *label; };

/* Everything one file pass needs. */
struct dcn_pass {
    const char *file;
    const char *phrase;      /* denylist pass when non-NULL */
    const regex_t *re;       /* derived pass otherwise */
    const struct dcn_rule *rule;
    struct dcn_viol *v;
    long ln;
};

int dcn_viol_add(struct dcn_viol *v, const char *fmt, ...)
{
    if (v->n >= DCN_VIOL) {
        fprintf(stderr, "check_doc_counts: violations exceed %d\n", DCN_VIOL);
        return 2;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(v->t[v->n], DCN_VSZ, fmt, ap);
    va_end(ap);
    if (ovf(n, DCN_VSZ)) {
        fprintf(stderr, "check_doc_counts: violation text exceeds %d\n",
                DCN_VSZ);
        return 2;
    }
    v->n++;
    return 0;
}

long dcn_claim_number(const char *m, int *plus)
{
    unsigned long long n = 0;
    *plus = 0;
    for (; (*m >= '0' && *m <= '9') || *m == ','; m++)
        if (*m != ',')
            n = n * 10 + (unsigned long long)(*m - '0');
    if (*m == '+')
        *plus = 1;
    return (long)n;
}

static size_t dcn_text_len(const char *line, size_t len)
{
    return len > 0 && line[len - 1] == '\n' ? len - 1 : len;
}

/* One derived-rule match: compare its number to the measured count. */
static int dcn_judge(struct dcn_pass *p, const char *m, size_t ml)
{
    int plus;
    long num = dcn_claim_number(m, &plus);
    long want_n = p->rule->expected;
    if (plus ? num <= want_n : num == want_n)
        return 0;
    return dcn_viol_add(p->v, plus
        ? "count claim \"%.*s\" at %s:%ld claims MORE than the code has — code-measured %s=%ld"
        : "count claim \"%.*s\" at %s:%ld disagrees with the code — code-measured %s=%ld",
        (int)ml, m, p->file, p->ln, p->rule->label, want_n);
}

static int dcn_derived_line(struct dcn_pass *p, const char *line)
{
    const char *at = line;
    int flags = 0;
    regmatch_t m;
    while (*at && regexec(p->re, at, 1, &m, flags) == 0) {
        int rc = dcn_judge(p, at + m.rm_so, (size_t)(m.rm_eo - m.rm_so));
        if (rc)
            return rc;
        if (m.rm_eo == 0)
            break;
        at += m.rm_eo;
        flags = REG_NOTBOL;
    }
    return 0;
}

static int dcn_line(void *ctx, const char *line, size_t len)
{
    struct dcn_pass *p = ctx;
    p->ln++;
    if (memchr(line, '\0', len))
        return 1;
    if (p->phrase ? !strstr(line, p->phrase)
                  : regexec(p->re, line, 0, NULL, 0) != 0)
        return 0;
    if (strstr(line, k_dcn_marker) || strstr(p->file, k_dcn_marker))
        return 0;
    size_t tl = dcn_text_len(line, len);
    if (p->phrase)
        return dcn_viol_add(p->v, "stale phrase \"%s\" → %s:%ld:%.*s  "
                            "(remove or correct the prose)",
                            p->phrase, p->file, p->ln, (int)tl, line);
    return dcn_derived_line(p, line);
}

static int dcn_pass_files(struct dcn_pass *p, char (*files)[DCN_PATH],
                          int nfiles)
{
    for (int i = 0; i < nfiles; i++) {
        p->file = files[i];
        p->ln = 0;
        int rc = lc_each_line(files[i], dcn_line, p, 1);
        if (rc == 2)
            return 2;
    }
    return 0;
}

static int dcn_compile(regex_t *re, const char *unit)
{
    char pat[512];
    if (ovf(snprintf(pat, sizeof pat, "[0-9][0-9,]*\\+?[*_` ]+%s", unit),
            sizeof pat))
        return 2;
    int err = regcomp(re, pat, REG_EXTENDED);
    return err ? reg_fail(re, err) : 0;
}

static int dcn_derived(const struct dcn_rule *rule, char (*files)[DCN_PATH],
                       int nfiles, struct dcn_viol *v)
{
    regex_t re;
    int rc = dcn_compile(&re, rule->unit);
    if (rc)
        return rc;
    struct dcn_pass p = { .re = &re, .rule = rule, .v = v };
    rc = dcn_pass_files(&p, files, nfiles);
    regfree(&re);
    return rc;
}

int dcn_scan(const struct dcn_counts *c, char (*files)[DCN_PATH], int nfiles,
             struct dcn_viol *v)
{
    if (nfiles <= 0)
        return 0;
    for (size_t i = 0; i < sizeof k_dcn_deny / sizeof k_dcn_deny[0]; i++) {
        struct dcn_pass p = { .phrase = k_dcn_deny[i], .v = v };
        int rc = dcn_pass_files(&p, files, nfiles);
        if (rc)
            return rc;
    }
    const struct dcn_rule rules[] = {
        { "((registered|parallel|test)[ -])+groups", c->groups, "test_groups" },
        { "port interfaces", c->ports, "port_interfaces" },
        { "(persistence adapters|sqlite impls)", c->adapters,
          "persistence_adapters" },
        { "(registered conditions|conditions registered)", c->conditions,
          "condition_registrations" },
        { "command bundles", c->bundles, "command_bundles" },
        { "command roots", c->roots, "command_roots" },
        { "dumpstate subsystems", c->dumpstate, "dumpstate_subsystems" },
        { "(app shape folders|shape folders)", c->shapes, "app_shape_folders" },
    };
    for (size_t i = 0; i < sizeof rules / sizeof rules[0]; i++) {
        int rc = dcn_derived(&rules[i], files, nfiles, v);
        if (rc)
            return rc;
    }
    return 0;
}
