/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-clang-portability — SECOND-COMPILER portability gate.
 * Runs a whole-tree -fsyntax-only pass under clang (or ZCL_CC, e.g. gcc)
 * over the same source set the node binary is built from, and ratchets the
 * realized diagnostic sites against a recorded baseline. Includes the
 * per-TU result cache (see gate_clang_portability_cache.c). Ported from
 * tools/lint/check_clang_portability.sh (deleted). Selftest:
 * gate_clang_portability_selftest.c and
 * gate_clang_portability_selftest_cache.c.
 *
 * Modes: default scan+ratchet; ZCL_LINT_MODE=UPDATE re-records the baseline;
 * --sites prints every current diagnostic. SKIP contracts: absent compiler
 * and compiler-version skew both print a loud SKIP and exit 0.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#if defined(__linux__)
#include <sched.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_clang_portability_priv.h"


static const char k_cpr_gate[] = "check-clang-portability";

static regex_t *cpr_crash_re(void)
{
    static regex_t re;
    static int init;
    if (!init) {
        if (cp_regcomp(&re,
                "internal compiler error|cannot execute|CreateProcess|"
                "unable to execute command|frontend command failed|"
                "PLEASE submit a bug report|segmentation fault|stack dump|"
                "out of memory|killed signal|error in backend|LLVM ERROR|"
                "access violation|cc1\\.exe:", REG_EXTENDED | REG_ICASE))
            return NULL;
        init = 1;
    }
    return &re;
}

static regex_t *cpr_err_re(int warn)
{
    static regex_t e, w;
    static int ie, iw;
    if (!warn && !ie) {
        if (cp_regcomp(&e, "^[A-Za-z0-9_./\\\\:-]+\\.[ch]:[0-9]+:[0-9]+: "
                           "(fatal )?error:", REG_EXTENDED))
            return NULL;
        ie = 1;
    }
    if (warn && !iw) {
        if (cp_regcomp(&w, "^[A-Za-z0-9_./\\\\:-]+\\.[ch]:[0-9]+:[0-9]+: "
                           "(fatal )?(error|warning):", REG_EXTENDED))
            return NULL;
        iw = 1;
    }
    return warn ? &w : &e;
}

static int cpr_log_matches(const char *path, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[CP_LINE];
    int hit = 0;
    while (!hit && fgets(line, sizeof line, f))
        if (regexec(re, line, 0, NULL, 0) == 0)
            hit = 1;
    fclose(f);
    return hit;
}

int cp_compiler_result_proven(const char *log, int rc)
{
    regex_t *crash = cpr_crash_re();
    if (!crash || cpr_log_matches(log, crash))
        return 0;
    if (rc == 0)
        return cpr_log_matches(log, cpr_err_re(0)) ? 0 : 1;
    if (rc != 1)
        return 0;
    return cpr_log_matches(log, cpr_err_re(1)) ? 1 : 0;
}

/* ── version skew ────────────────────────────────────────────────────── */

static int cpr_major_of(const char *line)
{
    const char *v = strstr(line, "clang version ");
    if (!v)
        return -1;
    v += 14;
    if (!isdigit((unsigned char)*v))
        return -1;
    int n = 0;
    while (isdigit((unsigned char)*v))
        n = n * 10 + (*v++ - '0');
    return *v == '.' ? n : -1;
}

static int cpr_baseline_major(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[CP_LINE];
    int maj = -1;
    while (maj < 0 && fgets(line, sizeof line, f))
        if (line[0] == '#')
            maj = cpr_major_of(line);
    fclose(f);
    return maj;
}

/* ── grading ─────────────────────────────────────────────────────────── */

#define CPR_REGEN "ZCL_CC=%s ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint " \
                  "check-clang-portability"

struct cpr_report {
    char file[CP_MAXBASE][CP_PATH];
    char line[CP_MAXBASE][CP_PATH];
    int n;
};

static int cpr_rep_add(struct cpr_report *r, const char *file, const char *fmt, ...)
{
    if (r->n >= CP_MAXBASE) {
        fprintf(stderr, "%s: more than %d report rows\n", k_cpr_gate, CP_MAXBASE);
        return 2;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->line[r->n], CP_PATH, fmt, ap);
    va_end(ap);
    snprintf(r->file[r->n], CP_PATH, "%s", file);
    r->n++;
    return 0;
}

struct cpr_kv {
    char key[CP_MAXBASE][CP_PATH];
    int val[CP_MAXBASE];
    int n;
};

static int cpr_kv_find(const struct cpr_kv *kv, const char *k)
{
    for (int i = 0; i < kv->n; i++)
        if (!strcmp(kv->key[i], k))
            return i;
    return -1;
}

static void cpr_kv_load(struct cpr_kv *kv, const char *path)
{
    kv->n = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[CP_PATH + 64];
    while (fgets(line, sizeof line, f) && kv->n < CP_MAXBASE) {
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        char *s = line;
        while (isspace((unsigned char)*s))
            s++;
        char *e = s + strlen(s);
        while (e > s && isspace((unsigned char)e[-1]))
            *--e = '\0';
        if (!*s)
            continue;
        char key[CP_PATH];
        int val = 0;
        if (sscanf(s, "%1023s %d", key, &val) >= 1) {
            snprintf(kv->key[kv->n], CP_PATH, "%s", key);
            kv->val[kv->n] = val;
            kv->n++;
        }
    }
    fclose(f);
}

/* Everything the ratchet compares and reports; static, the tables are MBs. */
struct cpr_grade {
    struct cpr_kv base, scope, cnt;
    struct cpr_report reg, adv, imp;
    int scoped;
};
static struct cpr_grade g_grade;

static int cpr_scope_load(struct cpr_grade *g)
{
    const char *scopef = getenv("ZCL_PORTABILITY_SCOPE");
    struct stat st;
    g->scoped = 0;
    if (!scopef || !*scopef)
        return 0;
    if (stat(scopef, &st) != 0) {
        fprintf(stderr, "%s: FATAL — ZCL_PORTABILITY_SCOPE points at\n"
                "  '%s', which does not exist. Refusing to guess a scope.\n",
                k_cpr_gate, scopef);
        return 2;
    }
    cpr_kv_load(&g->scope, scopef);
    g->scoped = 1;
    printf("  scope: %d changed file(s) must be diagnostic-FREE;"
           "the rest is ratcheted advisory-only (compiler-version skew).\n",
           g->scope.n);
    return 0;
}

/* Classify one file's count: a regression, an advisory excess or an
 * improvement. */
static int cpr_grade_file(struct cpr_grade *g, const char *file, int count)
{
    int bi = cpr_kv_find(&g->base, file);
    int allowed = bi >= 0 ? g->base.val[bi] : 0;
    if (g->scoped && cpr_kv_find(&g->scope, file) >= 0)
        return count > 0
            ? cpr_rep_add(&g->reg, file, "  %s: %d diagnostic(s) in a file "
                          "this change touches", file, count)
            : 0;
    if (count > allowed)
        return cpr_rep_add(g->scoped ? &g->adv : &g->reg, file,
                           "  %s: %d site(s), baseline allows %d", file, count,
                           allowed);
    if (count < allowed)
        return cpr_rep_add(&g->imp, file, "  %s: %d site(s) (baseline %d)",
                           file, count, allowed);
    return 0;
}

static int cpr_grade_all(struct cpr_grade *g)
{
    int rc = 0;
    for (int i = 0; i < g->cnt.n && !rc; i++)
        rc = cpr_grade_file(g, g->cnt.key[i], g->cnt.val[i]);
    for (int i = 0; i < g->base.n && !rc; i++)
        if (cpr_kv_find(&g->cnt, g->base.key[i]) < 0)
            rc = cpr_rep_add(&g->imp, g->base.key[i],
                             "  %s: 0 site(s) (baseline %d)", g->base.key[i],
                             g->base.val[i]);
    return rc;
}

static void cpr_print_diags(const struct cpr_report *reg, char sites[][CP_LINE],
                            int nsites)
{
    fprintf(stderr, "\n  Diagnostics:\n");
    for (int i = 0; i < reg->n; i++) {
        size_t fl = strlen(reg->file[i]);
        for (int k = 0; k < nsites; k++)
            if (!strncmp(sites[k], reg->file[i], fl) && sites[k][fl] == ':')
                fprintf(stderr, "    %s", sites[k]);
    }
}

static int cpr_print_fail(const struct cp_ctx *c, const struct cpr_grade *g,
                          char sites[][CP_LINE], int nsites)
{
    fprintf(stderr, "\nFAIL: %s diagnostic site(s) — this change does not "
                    "compile\n      cleanly under %s.\n\n", c->family, c->cc);
    for (int i = 0; i < g->reg.n; i++)
        fprintf(stderr, "%s\n", g->reg.line[i]);
    cpr_print_diags(&g->reg, sites, nsites);
    fprintf(stderr, "\n  Fix the code. Cross-compiler traps that commonly "
                    "land here:\n"
                    "    * '/* fallthrough */' COMMENTS — GCC honours them, "
                    "clang does\n      not. Use [[fallthrough]]; (C23) instead.\n"
                    "    * a preprocessor directive inside a function-call "
                    "argument list:\n      undefined behaviour, and once "
                    "_FORTIFY_SOURCE turns that call\n      into a macro, "
                    "clang rejects it outright.\n"
                    "    * snprintf into a buffer smaller than the format "
                    "literal.\n"
                    "    * bitwise & / | on bool operands (cast if the "
                    "branchless form is\n      deliberate, e.g. "
                    "constant-time compares).\n"
                    "  Reproduce one file:\n"
                    "    %s -std=c23 -Wall -Wextra -Werror -pedantic "
                    "-Wimplicit-fallthrough -fsyntax-only <the -I set> "
                    "<file.c>\n", c->cc);
    return 1;
}

static void cpr_print_notes(const struct cp_ctx *c, const struct cpr_grade *g)
{
    if (g->adv.n > 0) {
        printf("  NOTE: diagnostics outside this change exceed the recorded "
               "baseline.\n        Expected when this compiler differs in "
               "version from the one\n        the baseline was recorded with. "
               "Not failing the change:\n");
        for (int i = 0; i < g->adv.n; i++)
            printf("%s\n", g->adv.line[i]);
    }
    if (g->imp.n > 0 && !g->scoped) {
        printf("  NOTE: %s diagnostics went DOWN — tighten the ratchet:\n",
               c->family);
        for (int i = 0; i < g->imp.n; i++)
            printf("%s\n", g->imp.line[i]);
        printf("    " CPR_REGEN "\n", c->cc);
    }
}

static int cpr_ratchet(struct cp_ctx *c, char sites[][CP_LINE], int nsites)
{
    struct cpr_grade *g = &g_grade;
    char counts_path[CP_PATH];
    memset(g, 0, sizeof *g);
    cpr_kv_load(&g->base, c->baseline_rel);
    int rc = cpr_scope_load(g);
    if (rc)
        return rc;
    if (cps_snp(counts_path, "%s/counts.txt", c->work))
        return 2;
    cpr_kv_load(&g->cnt, counts_path);
    rc = cpr_grade_all(g);
    if (rc)
        return rc;
    if (g->reg.n > 0)
        return cpr_print_fail(c, g, sites, nsites);
    cpr_print_notes(c, g);
    printf("  OK: %d TU(s) syntax-checked with %s (%s) at %d jobs; ", c->nsrc,
           c->cc, c->family, c->jobs);
    if (g->scoped)
        printf("every changed file is diagnostic-free\n");
    else
        printf("%d known diagnostic site(s), no new ones\n", nsites);
    return 0;
}

/* ── sites / counts ──────────────────────────────────────────────────── */


/* Every compiler diagnostic line of the concatenated log, sorted and unique. */
static int cpr_sites_read(const struct cp_ctx *c, char sites[][CP_LINE], int max,
                          int *n)
{
    regex_t re;
    char logp[CP_PATH], line[CP_LINE];
    if (cp_regcomp(&re, "^[A-Za-z0-9_./-]+\\.[ch]:[0-9]+:[0-9]+: "
                        "(error|warning): .*$", REG_EXTENDED))
        return 2;
    if (cps_snp(logp, "%s/clang.log", c->work)) {
        regfree(&re);
        return 2;
    }
    FILE *f = fopen(logp, "r");
    if (!f) {
        regfree(&re);
        return die("z23-lint: cannot read %s\n", logp);
    }
    int rc = 0;
    *n = 0;
    while (!rc && fgets(line, sizeof line, f)) {
        if (regexec(&re, line, 0, NULL, 0) != 0)
            continue;
        if (*n >= max) {
            fprintf(stderr, "%s: diagnostic sites exceeds %d\n", k_cpr_gate, max);
            rc = 2;
        } else {
            snprintf(sites[(*n)++], CP_LINE, "%s", line);
        }
    }
    fclose(f);
    regfree(&re);
    return rc;
}


static void cpr_count_site(struct cpr_kv *cnt, const char *site)
{
    char file[CP_PATH];
    size_t fl = strcspn(site, ":");
    if (fl >= sizeof file)
        fl = sizeof file - 1;
    memcpy(file, site, fl);
    file[fl] = '\0';
    int ci = cpr_kv_find(cnt, file);
    if (ci < 0 && cnt->n < CP_MAXBASE) {
        ci = cnt->n++;
        snprintf(cnt->key[ci], CP_PATH, "%s", file);
        cnt->val[ci] = 0;
    }
    if (ci >= 0)
        cnt->val[ci]++;
}

static void cpr_kv_sort(struct cpr_kv *cnt)
{
    for (int i = 0; i < cnt->n; i++)
        for (int j = i + 1; j < cnt->n; j++) {
            if (strcmp(cnt->key[i], cnt->key[j]) <= 0)
                continue;
            char t[CP_PATH];
            memcpy(t, cnt->key[i], CP_PATH);
            memcpy(cnt->key[i], cnt->key[j], CP_PATH);
            memcpy(cnt->key[j], t, CP_PATH);
            int tv = cnt->val[i];
            cnt->val[i] = cnt->val[j];
            cnt->val[j] = tv;
        }
}

static int cpr_sites(struct cp_ctx *c, char sites[][CP_LINE], int max, int *n,
                     struct cpr_kv *cnt)
{
    int rc = cpr_sites_read(c, sites, max, n);
    if (rc)
        return rc;
    cp_sort_uniq(sites[0], CP_LINE, n);
    for (int i = 0; i < *n; i++)
        cpr_count_site(cnt, sites[i]);
    cpr_kv_sort(cnt);
    char counts_path[CP_PATH];
    if (cps_snp(counts_path, "%s/counts.txt", c->work))
        return 2;
    FILE *o = fopen(counts_path, "w");
    if (!o)
        return die("z23-lint: cannot write %s\n", counts_path);
    for (int i = 0; i < cnt->n; i++)
        fprintf(o, "%s %d\n", cnt->key[i], cnt->val[i]);
    fclose(o);
    return 0;
}

/* ── infrastructure-failure pass ─────────────────────────────────────── */

/* 0 ok, 1 this TU's result is unproven (written to inf), 2 failure. */
static int cpr_infra_one(const struct cp_ctx *c, const char *src, FILE *inf)
{
    char key[CP_PATH], log[CP_PATH], rcf[CP_PATH], rcstr[32];
    struct stat st;
    cp_key(src, key, sizeof key);
    if (cps_snp(log, "%s/%s.log", c->out_dir, key) ||
        cps_snp(rcf, "%s/%s.rc", c->out_dir, key))
        return 2;
    rcstr[0] = '\0';
    cp_first_line(rcf, rcstr, sizeof rcstr);
    if (!rcstr[0] || strspn(rcstr, "0123456789") != strlen(rcstr)) {
        fprintf(inf, "%s|%s\n", src, rcstr[0] ? rcstr : "missing");
        return 1;
    }
    int rc = atoi(rcstr);
    if (rc == 0 && (stat(log, &st) != 0 || st.st_size == 0))
        return 0;
    if (cp_compiler_result_proven(log, rc))
        return 0;
    fprintf(inf, "%s|%d\n", src, rc);
    return 1;
}

static void cpr_infra_show(const struct cp_ctx *c, char *line)
{
    char key[CP_PATH], log[CP_PATH], ll[CP_LINE];
    char *nl = strchr(line, '\n');
    if (nl)
        *nl = '\0';
    char *sep = strchr(line, '|');
    if (!sep)
        return;
    *sep = '\0';
    fprintf(stderr, "  %s (compiler rc=%s)\n", line, sep + 1);
    cp_key(line, key, sizeof key);
    if (cps_snp(log, "%s/%s.log", c->out_dir, key))
        return;
    FILE *l = fopen(log, "r");
    if (!l)
        return;
    for (int k = 0; k < 80 && fgets(ll, sizeof ll, l); k++)
        fprintf(stderr, "    %s", ll);
    fclose(l);
}

static int cpr_infra(struct cp_ctx *c)
{
    char infrap[CP_PATH];
    if (cps_snp(infrap, "%s/compiler-infrastructure.txt", c->work))
        return 2;
    FILE *inf = fopen(infrap, "w");
    if (!inf)
        return 2;
    int rc = 0;
    for (int i = 0; i < c->nsrc && rc != 2; i++)
        rc = cpr_infra_one(c, c->srcs[i], inf);
    fclose(inf);
    if (rc == 2)
        return 2;
    int n = cp_count_lines(infrap);
    if (n <= 0)
        return 0;
    fprintf(stderr, "%s: UNPROVEN — %d compiler/backend failure(s); "
                    "no baseline can excuse them:\n", k_cpr_gate, n);
    FILE *f = fopen(infrap, "r");
    char line[CP_PATH + 32];
    while (f && fgets(line, sizeof line, f))
        cpr_infra_show(c, line);
    if (f)
        fclose(f);
    return 2;
}

/* ── UPDATE / --sites ────────────────────────────────────────────────── */

static int cpr_update(struct cp_ctx *c, int nfiles, int total_sites)
{
    char capture[CP_PATH], ver[CP_LINE], counts_path[CP_PATH];
    if (cps_snp(capture, "%s/ccver2.txt", c->work) ||
        cps_snp(counts_path, "%s/counts.txt", c->work))
        return 2;
    ver[0] = '\0';
    cp_version_line(c, capture, ver, sizeof ver);
    FILE *o = fopen(c->baseline_rel, "w");
    if (!o)
        return die("z23-lint: cannot write %s\n", c->baseline_rel);
    fprintf(o, "# %s portability ratchet baseline — regenerate with:\n"
               "#   " CPR_REGEN "\n#\n"
               "# One '<path> <count>' line per file that still holds %s\n"
               "# diagnostic sites under the gate's flag set. Every one is a "
               "real\n# second-compiler finding to be driven to zero; a file "
               "absent from\n# this list must produce ZERO diagnostics. Counts "
               "may only go DOWN.\n#\n"
               "# Recorded from %d translation units with:\n#   %s\n"
               "# A different compiler VERSION legitimately reports a "
               "different\n# set; that is why CI scopes its verdict with\n"
               "# ZCL_PORTABILITY_SCOPE instead of trusting this file "
               "verbatim.\n", c->family, c->cc, c->family, c->nsrc, ver);
    FILE *ci = fopen(counts_path, "r");
    char line[CP_LINE];
    while (ci && fgets(line, sizeof line, ci))
        fputs(line, o);
    if (ci)
        fclose(ci);
    fclose(o);
    printf("  UPDATED: %s (%d file(s), %d site(s))\n", c->baseline_rel,
           nfiles, total_sites);
    return 0;
}

/* ── gate body ───────────────────────────────────────────────────────── */

/* What coreutils nproc prints: OMP_NUM_THREADS, else the CPUs this process
 * may run on, then capped by OMP_THREAD_LIMIT. */
static long cp_nproc(void)
{
    const char *e = getenv("OMP_NUM_THREADS");
    long n = e && *e ? strtol(e, NULL, 10) : 0;
#if defined(__linux__)
    cpu_set_t set;
    if (n <= 0 && sched_getaffinity(0, sizeof set, &set) == 0)
        n = CPU_COUNT(&set);
#endif
    if (n <= 0)
        n = sysconf(_SC_NPROCESSORS_ONLN);
    e = getenv("OMP_THREAD_LIMIT");
    long lim = e && *e ? strtol(e, NULL, 10) : 0;
    return lim > 0 && lim < n ? lim : n;
}

static void cp_pick_jobs(struct cp_ctx *c)
{
    const char *j = getenv("ZCL_CC_JOBS");
    long jobs = j && *j ? strtol(j, NULL, 10) : 0;
    if (jobs <= 0)
        jobs = cp_nproc();
    if (jobs < 1)
        jobs = 4;
    if (jobs > 32)
        jobs = 32;
    c->jobs = (int)jobs;
}

static void cpr_append_file(FILE *dst, const char *path)
{
    char buf[8192];
    size_t n;
    FILE *t = fopen(path, "rb");
    if (!t)
        return;
    while ((n = fread(buf, 1, sizeof buf, t)) > 0)
        fwrite(buf, 1, n, dst);
    fclose(t);
}

/* One clang.log from the per-TU logs, in scan order. */
static int cpr_concat_logs(const struct cp_ctx *c)
{
    char logp[CP_PATH], key[CP_PATH], p[CP_PATH];
    if (cps_snp(logp, "%s/clang.log", c->work))
        return 2;
    FILE *lf = fopen(logp, "wb");
    if (!lf)
        return die("z23-lint: cannot write %s\n", logp);
    for (int i = 0; i < c->nsrc; i++) {
        cp_key(c->srcs[i], key, sizeof key);
        if (!cps_snp(p, "%s/%s.log", c->out_dir, key))
            cpr_append_file(lf, p);
    }
    fclose(lf);
    return 0;
}

/* Every TU must have produced both a log and a status file. */
static int cpr_require_results(const struct cp_ctx *c)
{
    int nlog = 0, nrc = 0;
    char key[CP_PATH], p[CP_PATH], hint[128];
    struct stat st;
    for (int i = 0; i < c->nsrc; i++) {
        cp_key(c->srcs[i], key, sizeof key);
        if (!cps_snp(p, "%s/%s.log", c->out_dir, key))
            nlog += stat(p, &st) == 0;
        if (!cps_snp(p, "%s/%s.rc", c->out_dir, key))
            nrc += stat(p, &st) == 0;
    }
    cps_snp(hint, "only %d of %d translation units produced a clang result",
            nlog, c->nsrc);
    int rc = gate_require_scanned(nlog, c->nsrc, k_cpr_gate, hint);
    if (rc)
        return rc;
    cps_snp(hint, "only %d of %d translation units produced a compiler "
                  "status", nrc, c->nsrc);
    return gate_require_scanned(nrc, c->nsrc, k_cpr_gate, hint);
}

/* Compile every TU (cache-aware) and leave the per-TU artifacts in out_dir. */
static int cpr_compile_all(struct cp_ctx *c)
{
    int rc = cp_build_flags(c);
    if (!rc)
        rc = cp_scan_sources(c);
    if (!rc)
        rc = cp_coverage(c);
    if (rc)
        return rc;
    cp_pick_jobs(c);
    if (cps_snp(c->out_dir, "%s/out", c->work))
        return 2;
    if (cp_mkdirs(c->out_dir) != 0)
        return die("z23-lint: cannot create %s\n", c->out_dir);
    rc = cp_cache_setup(c, NULL, ".");
    if (!rc)
        rc = cp_cache_plan(c);
    if (!rc)
        rc = cp_compile_misses(c);
    if (!rc)
        rc = cpr_concat_logs(c);
    if (rc)
        return rc;
    cp_cache_summary(c);
    return cpr_require_results(c);
}

static int cpr_missing_baseline(const struct cp_ctx *c)
{
    fprintf(stderr, "%s: FATAL — baseline '%s' is missing.\n"
            "  Refusing to report 'clean' with nothing to ratchet "
            "against.\n  Regenerate: " CPR_REGEN "\n", k_cpr_gate,
            c->baseline_rel, c->cc);
    return 2;
}

int cp_gate_body(struct cp_ctx *c, int argc, char **argv)
{
    static char sites[CP_MAXSITES][CP_LINE];
    static struct cpr_kv cnt;
    const char *mode = argv && argc > 0 ? argv[0] : NULL;
    const char *lm = getenv("ZCL_LINT_MODE");
    struct stat st;
    int nsites = 0;
    int rc = cpr_compile_all(c);
    if (!rc)
        rc = cpr_infra(c);
    if (!rc)
        rc = cpr_sites(c, sites, CP_MAXSITES, &nsites, &cnt);
    if (rc)
        return rc;
    if (mode && !strcmp(mode, "--sites")) {
        printf("  %d diagnostic site(s) over %d TU(s):\n", nsites, c->nsrc);
        for (int i = 0; i < nsites; i++)
            printf("    %s", sites[i]);
        return 0;
    }
    if (lm && !strcmp(lm, "UPDATE"))
        return cpr_update(c, cnt.n, nsites);
    if (stat(c->baseline_rel, &st) != 0)
        return cpr_missing_baseline(c);
    return cpr_ratchet(c, sites, nsites);
}

/* ── entry ───────────────────────────────────────────────────────────── */

/* Shared by the gate and its selftest: context, banner, compiler presence.
 * 0 ready; 0 with *skip set when the compiler is absent; else a failure. */
int cp_ctx_open(struct cp_ctx *c, int *skip)
{
    const char *e = getenv("ZCL_CC");
    *skip = 0;
    if (!getcwd(c->root, sizeof c->root))
        return die("z23-lint: getcwd failed\n", "");
    cps_snp(c->cc_buf, "%s", e && *e ? e : "clang");
    c->cc = c->cc_buf;
    e = getenv("ZCL_CLANG_PORTABILITY_MAKEFILE");
    cps_snp(c->makefile, "%s", e && *e ? e : "Makefile");
    int rc = cp_shape_init(c);
    if (rc)
        return rc;
    printf("══ LINT: clang portability (second-compiler whole-tree syntax "
           "pass) ══\n");
    if (cp_which(c->cc))
        return 0;
    printf("  check-clang-portability: SKIP — '%s' is not installed.\n"
           "  This gate is a SECOND-compiler cross-check, not a build\n"
           "  requirement: the node builds with GCC and every other gate "
           "still\n  applies. Install clang (apt install clang) to run it, "
           "or set\n  ZCL_CC=<path>. Skipping is not a failure.\n", c->cc);
    *skip = 1;
    return 0;
}

/* A baseline is only meaningful against the clang major it was recorded
 * with: print the loud SKIP and return 1 on skew. */
static int cpr_version_skew(const struct cp_ctx *c)
{
    const char *ic = getenv("ZCL_INTERNAL_CLANG_COVERAGE_SELFTEST");
    char cap[CP_PATH], ver[CP_LINE];
    if (ic && !strcmp(ic, "1"))
        return 0;
    int bmaj = cpr_baseline_major("tools/lint/portability_baseline.clang.txt");
    cps_snp(cap, ".zcl-ccver.tmp");
    ver[0] = '\0';
    cp_version_line(c, cap, ver, sizeof ver);
    unlink(cap);
    int lmaj = ver[0] ? cpr_major_of(ver) : -1;
    if (bmaj <= 0 || lmaj <= 0 || bmaj == lmaj)
        return 0;
    printf("  check-clang-portability: SKIP — compiler version skew.\n"
           "    baseline recorded with: clang %d\n"
           "    installed here:         clang %d\n"
           "  A ratchet baseline is only meaningful against the "
           "version it was\n  recorded with; judging one clang's "
           "output by another clang's\n  baseline measures the "
           "compilers, not the change. To run the gate\n  here, "
           "re-record it and commit the result:\n"
           "    " CPR_REGEN "\n"
           "  Skipping is not a failure.\n", bmaj, lmaj, c->cc);
    return 1;
}

int check_clang_portability_run(int argc, char **argv)
{
    static struct cp_ctx c;
    int skip = 0;
    if (argc > 0 && !strcmp(argv[0], "--stub-cc"))
        return cp_stub_cc_main(argc, argv);
    if (argc > 0 && !strcmp(argv[0], "--self-test"))
        return check_clang_portability_selftest();
    int rc = cp_ctx_open(&c, &skip);
    if (rc || skip || cpr_version_skew(&c))
        return rc;
    rc = cp_mkscratch(c.work, sizeof c.work, "z23-lint-clang-port");
    if (rc)
        return rc;
    rc = cp_gate_body(&c, argc, argv);
    rap_rm_rf(c.work);
    return rc;
}
