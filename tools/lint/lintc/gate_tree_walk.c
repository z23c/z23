/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — filesystem-tree-walking lint gates of the C23 lint
 * runtime (check-sysinit-ordering, check-no-raw-clock-outside-platform,
 * check-no-shellouts, check-command-contract,
 * check-no-writer-below-sealed-frontier, check-proc-self-shim,
 * check-hotswap-dev-only, check-no-new-coin-backfill-caller).
 */

/*
 * Gates: check-sysinit-ordering, check-no-raw-clock-outside-platform, check-no-shellouts, check-command-contract, check-no-writer-below-sealed-frontier, check-proc-self-shim, check-hotswap-dev-only, check-no-new-coin-backfill-caller
 * Default landing spot for a FUTURE gate port: a filesystem-tree-walking
 * gate (walk_src/clock_walk/repo_shape_room_dirs) joins gate_tree_walk.c;
 * a git-tracked-enumeration gate (each_zpath/each_zpath_st) joins whichever
 * of gate_git_scan_a.c/gate_git_scan_b.c is currently smaller by wc -l;
 * a proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c; only once
 * EVERY existing family is within ~200 lines of the ~1500 cap does a new
 * gate warrant a new family file — name it for its own subject the same
 * way the seven above are named for theirs.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"


enum { SI_MAX = 64, SI_NAME = 96, SI_OUT = 8192 };
struct si_rec { int rank, order; char name[SI_NAME]; };
struct si_acc { struct si_rec rec[SI_MAX]; int n, rc; char err[256]; };
static const char k_si_src[] = "engine/composition/src/boot.c";
static const char k_si_gold[] = "tools/lint/sysinit_ordering_golden.txt";

static int si_rank_of(const char *s)
{
    static const char *const nm[] = {
        "INIT", "DATADIR_LOCKED", "CRYPTO_READY", "DB_OPEN", "WALLET_LOADED",
        "BLOCK_INDEX_LOADED", "CHAIN_TIP_RESOLVED", "NETWORK_READY",
        "SERVICES_RUNNING", "READY", "SHUTDOWN_REQUESTED", "SHUTDOWN_COMPLETE"
    };
    for (int i = 0; i < 12; i++)
        if (strcmp(nm[i], s) == 0) return i;
    return -1;
}

static int si_cmp(const void *a, const void *b)
{
    const struct si_rec *x = a, *y = b;
    if (x->rank != y->rank) return (x->rank > y->rank) - (x->rank < y->rank);
    if (x->order != y->order) return (x->order > y->order) - (x->order < y->order);
    return strcmp(x->name, y->name);
}

static int si_cap(const regex_t *re, const char *s, char *dst, size_t cap)
{
    regmatch_t m[2];
    if (regexec(re, s, 2, m, 0) != 0 || m[1].rm_so < 0) return 0;
    size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (n >= cap) n = cap - 1;
    memcpy(dst, s + m[1].rm_so, n);
    dst[n] = '\0';
    return 1;
}

static int si_comp(regex_t *stg, regex_t *ord, regex_t *nam)
{
    int cr = compile_pat(stg, REG_EXTENDED,
                         "\\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_([A-Z_]*)",
                         "", "", "");
    if (cr) return cr;
    cr = pair_comp(ord, REG_EXTENDED,
                   "\\.order[[:space:]]*=[[:space:]]*(-?[0-9]*)", "", "", "",
                   nam, REG_EXTENDED,
                   "\\.name[[:space:]]*=[[:space:]]*\"([^\"]*)\"", "", "", "");
    if (cr) regfree(stg);
    return cr;
}

static int si_die(struct si_acc *a, const char *fmt, const char *arg)
{
    snprintf(a->err, sizeof a->err, fmt, arg);
    a->rc = 2;
    return 2;
}

static int si_feed(struct si_acc *a, const regex_t *stg, const regex_t *ord,
                   const regex_t *nam, const char *line)
{
    char stage[32], order[16], name[SI_NAME];
    if (!si_cap(stg, line, stage, sizeof stage) || !stage[0]) return 0;
    if (!si_cap(ord, line, order, sizeof order) || !order[0]
        || !si_cap(nam, line, name, sizeof name) || !name[0])
        return si_die(a, "check_sysinit_ordering: FATAL — record line missing .order/.name: %s\n",
                      line);
    int rank = si_rank_of(stage);
    if (rank < 0)
        return si_die(a, "check_sysinit_ordering: FATAL — unknown BOOT_STAGE_%s (update STAGE_RANK)\n",
                      stage);
    if (a->n >= SI_MAX)
        return si_die(a, "check_sysinit_ordering: FATAL — too many boundary records\n", "");
    a->rec[a->n].rank = rank;
    a->rec[a->n].order = (int)strtol(order, NULL, 10);
    memcpy(a->rec[a->n].name, name, sizeof name);
    a->n++;
    return 0;
}

static int si_finish(struct si_acc *a, char *out, size_t outsz, int *nrec)
{
    if (a->rc) return 2;
    if (a->n == 0)
        return si_die(a, "check_sysinit_ordering: FATAL — no boundary records found in %s\n",
                      k_si_src);
    qsort(a->rec, (size_t)a->n, sizeof a->rec[0], si_cmp);
    size_t used = 0;
    for (int i = 0; i < a->n; i++) {
        int k = snprintf(out + used, outsz - used, "%02d %06d %s\n",
                         a->rec[i].rank, a->rec[i].order, a->rec[i].name);
        if (k < 0 || (size_t)k >= outsz - used)
            return si_die(a, "z23-lint: derived buffer overflow\n", "");
        used += (size_t)k;
    }
    if (nrec) *nrec = a->n;
    return 0;
}

static int si_from_buf(const char *src, char *out, size_t outsz, int *nrec,
                       char *err, size_t errsz)
{
    regex_t stg, ord, nam;
    int cr = si_comp(&stg, &ord, &nam);
    if (cr) return cr;
    struct si_acc a = { 0 };
    char buf[1024];
    if (snprintf(buf, sizeof buf, "%s", src) >= (int)sizeof buf) {
        drop3(&stg, &ord, &nam);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    for (char *p = buf, *nl; p; p = nl ? nl + 1 : NULL) {
        nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (si_feed(&a, &stg, &ord, &nam, p)) break;
        if (!nl) break;
    }
    drop3(&stg, &ord, &nam);
    int rc = si_finish(&a, out, outsz, nrec);
    if (rc) snprintf(err, errsz, "%s", a.err);
    return rc;
}

static int si_load(struct si_acc *a)
{
    regex_t stg, ord, nam;
    int cr = si_comp(&stg, &ord, &nam);
    if (cr) return cr;
    FILE *f = fopen(k_si_src, "r");
    if (!f) {
        drop3(&stg, &ord, &nam);
        return die("z23-lint: cannot open %s\n", k_si_src);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (si_feed(a, &stg, &ord, &nam, line)) break;
    }
    int fr = fin(f, line, k_si_src, 0);
    drop3(&stg, &ord, &nam);
    if (a->rc) { fputs(a->err, stderr); return 2; }
    return fr;
}

int check_sysinit_ordering_run(int argc, char **argv)
{
    struct si_acc a = { 0 };
    int rc = si_load(&a);
    if (rc) return rc;
    char der[SI_OUT], gold[SI_OUT];
    int nrec = 0;
    if (si_finish(&a, der, sizeof der, &nrec)) { fputs(a.err, stderr); return 2; }
    if (argc >= 1 && strcmp(argv[0], "--update") == 0) {
        FILE *g = fopen(k_si_gold, "w");
        if (!g) return die("z23-lint: cannot open %s\n", k_si_gold);
        size_t dn = strlen(der);
        rc = fwrite(der, 1, dn, g) != dn;
        if (fclose(g) != 0 && rc == 0) return die("z23-lint: fclose failed: %s\n", k_si_gold);
        if (rc) return die("z23-lint: write failed\n", "");
        printf("[check_sysinit_ordering] golden updated (%d records)\n", nrec);
        return 0;
    }
    FILE *g = fopen(k_si_gold, "r");
    if (!g) {
        fputs("check_sysinit_ordering: FATAL — missing golden tools/lint/sysinit_ordering_golden.txt (run --update)\n",
              stderr);
        return 2;
    }
    size_t used = fread(gold, 1, sizeof gold - 1, g);
    rc = ferror(g) ? die("z23-lint: read failed: %s\n", k_si_gold) : 0;
    if (rc == 0 && used == sizeof gold - 1 && !feof(g))
        rc = die("z23-lint: file too large: %s\n", k_si_gold);
    gold[used] = '\0';
    if (fclose(g) != 0 && rc == 0) return die("z23-lint: fclose failed: %s\n", k_si_gold);
    if (rc) return rc;
    if (strcmp(gold, der) != 0) {
        fprintf(stderr, "--- %s\n%s+++ derived\n%s", k_si_gold, gold, der);
        fputs("[check_sysinit_ordering] FAIL — sysinit boundary order drifted from the golden.\n"
              "[check_sysinit_ordering] If intentional: tools/lint/check_sysinit_ordering.sh --update\n",
              stderr);
        return 1;
    }
    int nl = 0;
    for (size_t i = 0; i < used; i++) if (gold[i] == '\n') nl++;
    printf("[check_sysinit_ordering] OK — %d boundary records match the golden\n", nl);
    return 0;
}

static int si_want(const char *src, int want_rc, const char *need)
{
    char out[SI_OUT], err[256];
    int n = 0, rc = si_from_buf(src, out, sizeof out, &n, err, sizeof err);
    int bad = rc != want_rc || (want_rc ? strstr(err, need) == NULL : strcmp(out, need) != 0);
    if (bad)
        fprintf(stderr, "check_sysinit_ordering selftest: want rc %d got %d\n", want_rc, rc);
    return bad;
}

int check_sysinit_ordering_selftest(void)
{
    const char *fwd =
        "{ .stage = BOOT_STAGE_WALLET_LOADED, .order = 10, .name = \"wallet_loaded\" }\n"
        "{ .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 10, .name = \"block_index_loaded\" }\n";
    const char *rev =
        "{ .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 10, .name = \"block_index_loaded\" }\n"
        "{ .stage = BOOT_STAGE_WALLET_LOADED, .order = 10, .name = \"wallet_loaded\" }\n";
    const char *exp = "04 000010 wallet_loaded\n05 000010 block_index_loaded\n";
    int bad = si_want(fwd, 0, exp) | si_want(rev, 0, exp)
            | si_want("{ .stage = BOOT_STAGE_NOPE, .order = 1, .name = \"x\" }\n", 2,
                      "unknown BOOT_STAGE_NOPE (update STAGE_RANK)")
            | si_want("{ .stage=BOOT_STAGE_INIT, .name=\"x\" }\n", 2,
                      "record line missing .order/.name:")
            | si_want("", 2, "no boundary records found in engine/composition/src/boot.c");
    return st_ok(bad, "check_sysinit_ordering selftest: OK\n");
}
static const char k_clock_script[] =
    "tools/lint/check_no_raw_clock_outside_platform.sh";

struct clock_acc { regex_t *re; char *buf; size_t cap, used;
                   int (*keep)(const char *, const char *); int raw; };

static int clock_comp(regex_t *re)
{
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s",
                     "(^|[^[:alnum:]_])clock" "_gettime[[:space:]]*\\(|",
                     "(^|[^[:alnum:]_])get" "timeofday[[:space:]]*\\(|",
                     "(^|[^[:alnum:]_])ti" "me[[:space:]]*\\([[:space:]]*NULL[[:space:]]*\\)|",
                     "(^|[^[:alnum:]_])get" "random[[:space:]]*\\(");
    return ovf(n, sizeof pat) ? 2 : reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int clock_keep(const char *path, const char *text)
{
    size_t sl = sizeof k_clock_script - 1;
    if (lint_path_is_excluded(path)
        || strncmp(path, "platform/modules/platform/", 26) == 0
        || (strncmp(path, k_clock_script, sl) == 0 && (path[sl] == '\0' || path[sl] == ':'))
        || strstr(text, "// platform-ok") != NULL)
        return 0;
    return 1;
}

static int scan_clock(const char *path, void *ctx)
{
    struct clock_acc *a = ctx;
    if (a->keep && !a->keep(path, "")) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0) continue;
        a->raw++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (a->keep && !a->keep(path, line)) continue;
        int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n",
                         path, lineno, line);
        if (ovf(k, a->cap - a->used)) { rc = 2; break; }
        a->used += (size_t)k;
    }
    return fin(f, line, path, rc);
}


static int clock_summary(int v, const char *mode)
{
    return (printf("[check_no_raw_clock_outside_platform] %d violation(s) found (mode: %s)\n",
                   v, mode) < 0
            || puts("[check_no_raw_clock_outside_platform] ratchet now FAIL -- no new raw clock calls allowed") < 0
            || puts("[check_no_raw_clock_outside_platform] use platform.clock/platform.rng or add // platform-ok for a documented exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

static int clock_walk(const char *const *roots, size_t nr, void *ctx)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < nr; i++) rc = walk_src(roots[i], 1, scan_clock, ctx);
    return rc;
}

int check_no_raw_clock_outside_platform_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *mode = clock_mode();
    int rc = rs_init();
    if (rc) return rc;
    regex_t re;
    rc = clock_comp(&re);
    if (rc) return rc;
    char matches[CLK_MATCH];
    matches[0] = '\0';
    struct clock_acc a = {
        .re = &re, .buf = matches, .cap = sizeof matches, .used = 0, .keep = clock_keep
    };
    static const char *const prefix[] = {
        "tools", "engine/composition", "engine/application",
        "platform/adapters", "platform/ports"
    };
    static const char *const suffix[] = {
        "core/consensus", "core/params", "core/math", "core/chainparams"
    };
    rc = clock_walk(prefix, sizeof prefix / sizeof prefix[0], &a);
    char dirs[RS_MAX][RS_PATH];
    int n = 0;
    if (rc == 0) rc = repo_shape_dirs("app", "", dirs, RS_MAX, &n);
    for (int i = 0; rc == 0 && i < n; i++) rc = walk_src(dirs[i], 1, scan_clock, &a);
    n = 0;
    if (rc == 0) rc = repo_shape_dirs("lib", "", dirs, RS_MAX, &n);
    for (int i = 0; rc == 0 && i < n; i++) rc = walk_src(dirs[i], 1, scan_clock, &a);
    if (rc == 0) rc = clock_walk(k_domain, sizeof k_domain / sizeof k_domain[0], &a);
    if (rc == 0) rc = clock_walk(suffix, sizeof suffix / sizeof suffix[0], &a);
    int violations = 0;
    if (rc == 0) rc = gate_count_and_report(matches, &violations);
    if (rc == 0) rc = clock_summary(violations, mode);
    regfree(&re);
    return rc ? rc : clock_grade(violations, mode);
}

static int keep_case(int (*keep)(const char *, const char *), const regex_t *re,
                     const char *path, const char *text,
                     int want_n, int want_rc, const char *mode)
{
    char buf[256] = {0};
    int n = 0;
    if (regexec(re, text, 0, NULL, 0) == 0 && keep(path, text)
        && ovf(snprintf(buf, sizeof buf, "%s:%d:%s\n", path, 1, text), sizeof buf))
        return 1;
    if (gate_count_and_report(buf, &n)) return 1;
    return n != want_n || clock_grade(n, mode) != want_rc;
}

int check_no_raw_clock_outside_platform_selftest(void)
{
    regex_t re;
    int cr = clock_comp(&re);
    if (cr) return cr;
    char hit[80], marked[96];
    if (snprintf(hit, sizeof hit, "    clock" "_gettime(CLOCK_REALTIME, &ts);")
            >= (int)sizeof hit
        || snprintf(marked, sizeof marked, "%s // platform-ok", hit) >= (int)sizeof marked) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    const char *t = "check_no_raw_clock_outside_platform";
    int bad = want(t, &re, "int x = 1;", 0) | want(t, &re, hit, 1)
            | want(t, &re, "my_clock" "_gettime(&ts);", 0)
            | keep_case(clock_keep, &re, "tools/lint/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(clock_keep, &re, "tools/lint/foo.c", hit, 1, 1, "FAIL")
            | keep_case(clock_keep, &re, "platform/modules/platform/src/clock.c", hit, 0, 0, "FAIL")
            | keep_case(clock_keep, &re, "tools/lint/foo.c", marked, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(clock_keep, &re, "tools/lint/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    (void)lint_filter_excluded;
    (void)lint_annotate_stray;
    regfree(&re);
    return st_ok(bad, "check_no_raw_clock_outside_platform selftest: OK\n");
}

static int so_keep(const char *path, const char *text)
{
    const char *t = text;
    while (isspace((unsigned char)*t)) t++;
    return strncmp(path, "tests/", 6) && !strstr(text, "// shellout-ok")
        && *t != '*' && !(t[0] == '/' && (t[1] == '/' || t[1] == '*'));
}

static int so_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, "(^|[^[:alnum:]_])sys" "tem[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])po" "pen[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])exec" "lp[[:space:]]*\\(", "");
}

static int so_summary(int v, const char *mode)
{
    return (printf("[check_no_shellouts] %d violation(s) found (mode: %s)\n", v, mode) < 0
            || puts("[check_no_shellouts] the node must not shell out — use platform/modules/util spawn") < 0
            || puts("[check_no_shellouts] (zcl_spawn_detached/zcl_spawn_capture) or") < 0
            || puts("[check_no_shellouts] platform/modules/util file_tree_ops (zcl_tree_copy/zcl_tree_remove);") < 0
            || puts("[check_no_shellouts] add // shellout-ok for a documented, reviewed exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_shellouts_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    regex_t re;
    int rc = so_comp(&re), v = 0;
    if (rc) return rc;
    char matches[CLK_MATCH] = {0};
    struct clock_acc a = { .re = &re, .buf = matches, .cap = sizeof matches, .keep = so_keep };
    static const char *const roots[] = { "core", "engine", "contexts", "cognition", "platform" };
    rc = clock_walk(roots, sizeof roots / sizeof roots[0], &a);
    if (rc == 0) rc = gate_count_and_report(matches, &v);
    if (rc == 0) rc = so_summary(v, clock_mode());
    regfree(&re);
    return rc ? rc : clock_grade(v, clock_mode());
}

int check_no_shellouts_selftest(void)
{
    regex_t re;
    if (so_comp(&re)) return 2;
    char hit[48], marked[64], commented[56];
    snprintf(hit, sizeof hit, "    sys%s", "tem(\"rm -rf /tmp/x\");");
    snprintf(marked, sizeof marked, "%s // shellout-ok", hit);
    snprintf(commented, sizeof commented, "    // sys%s", "tem(\"x\");");
    int bad = keep_case(so_keep, &re, "engine/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", hit, 1, 1, "FAIL")
            | keep_case(so_keep, &re, "tests/foo.c", hit, 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", marked, 0, 0, "FAIL")
            | keep_case(so_keep, &re, "engine/foo.c", commented, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(so_keep, &re, "engine/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    regfree(&re);
    return st_ok(bad, "check_no_shellouts selftest: OK\n");
}

struct cc_acc { regex_t *leaf, *empty; char *buf; size_t cap, used;
                int n_files, n_leaf, n_empty; };

static int cc_comp(regex_t *leaf, regex_t *empty)
{
    return pair_comp(leaf, REG_EXTENDED,
                     "ZCL_COMMAND_(READY_READ|COMPAT_READ|PLANNED_READ|",
                     "PLANNED_COMMAND|COMPAT_COMMAND|READY_COMMAND|DEV_READ|DEV_COMMAND)\\(",
                     "", "", empty, REG_EXTENDED,
                     "\"[[:space:]]*\"[[:space:]]*,[[:space:]]*(0|[1-9][0-9]*|ZCL_COMMAND_[A-Z_]+)",
                     "", "", "");
}

static int cc_feed(struct cc_acc *a, const char *path, const char *line, int lineno)
{
    for (const char *p = line; ; ) {
        regmatch_t m;
        if (regexec(a->leaf, p, 1, &m, 0) != 0) break;
        a->n_leaf++;
        p += m.rm_eo > 0 ? (size_t)m.rm_eo : 1;
    }
    if (regexec(a->empty, line, 0, NULL, 0) != 0) return 0;
    int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n", path, lineno, line);
    if (ovf(k, a->cap - a->used)) return 2;
    a->used += (size_t)k;
    a->n_empty++;
    return 0;
}

static int scan_cc(const char *path, void *ctx)
{
    struct cc_acc *a = ctx;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    a->n_files++;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if ((rc = cc_feed(a, path, line, ++lineno)) != 0) break;
    }
    return fin(f, line, path, rc);
}

static int cc_msgs(int n_empty, int n_leaf, const char *hits, const char *mode)
{
    if (n_empty > 0) {
        if (fputs(hits, stdout) < 0
            || printf("[check_command_contract] %d leaf(s) with an empty/blank "
                      "semantics argument (mode: %s)\n", n_empty, mode) < 0
            || puts("  Every leaf must supply a specific one-line OUTPUT-interpretation") < 0
            || puts("  semantics (source/freshness/units/completeness) — not \"\" and not") < 0
            || puts("  a restatement of summary. See engine/modules/kernel/include/kernel/") < 0
            || puts("  command_registry.h (struct zcl_command_spec.semantics).") < 0)
            return die("z23-lint: write failed\n", "");
        if (strcmp(mode, "FAIL") == 0) return 1;
    }
    return printf("[check_command_contract] PASS (%d leaves, all with semantics)\n",
                  n_leaf) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

int check_command_contract_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *dir = getenv("ZCL_COMMAND_CONTRACT_DIR");
    if (!dir || !dir[0]) dir = "engine/composition/commands";
    regex_t leaf, empty;
    int cr = cc_comp(&leaf, &empty);
    if (cr) return cr;
    char hits[CLK_MATCH] = {0}, hint[4096];
    struct cc_acc a = { .leaf = &leaf, .empty = &empty, .buf = hits, .cap = sizeof hits };
    int rc = walk_src(dir, 2, scan_cc, &a);
    if (rc == 0 && ovf(snprintf(hint, sizeof hint, "no *.def under: %s", dir), sizeof hint))
        rc = 2;
    if (rc == 0)
        rc = gate_require_scanned(a.n_files, 1, "check_command_contract", hint);
    if (rc == 0)
        rc = gate_require_scanned(a.n_leaf, 125, "check_command_contract",
                                  "leaf-macro population collapsed under floor");
    if (rc == 0) rc = cc_msgs(a.n_empty, a.n_leaf, hits, clock_mode());
    drop2(&leaf, &empty);
    return rc;
}

static int cc_fatal(int count, int floor, const char *hint, const char *need)
{
    int save = dup(STDERR_FILENO);
    FILE *tf = tmpfile();
    char buf[2048] = {0};
    if (save < 0 || !tf) return 1;
    if (dup2(fileno(tf), STDERR_FILENO) < 0) { close(save); fclose(tf); return 1; }
    int rc = gate_require_scanned(count, floor, "check_command_contract", hint);
    fflush(stderr);
    (void)dup2(save, STDERR_FILENO);
    close(save);
    rewind(tf);
    if (fread(buf, 1, sizeof buf - 1, tf) == 0) buf[0] = '\0';
    fclose(tf);
    return rc != 2 || !strstr(buf, "FATAL") || !strstr(buf, need);
}

int check_command_contract_selftest(void)
{
    regex_t leaf, empty;
    if (cc_comp(&leaf, &empty)) return 2;
    char hits[256] = {0};
    struct cc_acc a = { .leaf = &leaf, .empty = &empty, .buf = hits, .cap = sizeof hits };
    const char *okl = "ZCL_COMMAND_READY_READ(\"n\", \"s\", \"height from tip\", 0)";
    const char *badl = "ZCL_COMMAND_READY_READ(\"n\", \"s\", \"\", 0)";
    int bad = cc_feed(&a, "x.def", okl, 1) || a.n_leaf != 1 || a.n_empty != 0;
    a.n_leaf = a.n_empty = 0;
    a.used = 0;
    hits[0] = '\0';
    bad |= cc_feed(&a, "x.def", badl, 1) || a.n_leaf != 1 || a.n_empty != 1
        || clock_grade(a.n_empty, "FAIL") != 1 || clock_grade(a.n_empty, "WARN") != 0;
    drop2(&leaf, &empty);
    bad |= cc_fatal(0, 1, "no *.def under: empty", "no *.def under:")
        | cc_fatal(0, 125, "leaf-macro population collapsed under floor",
                   "leaf-macro population collapsed under floor");
    return st_ok(bad, "check_command_contract selftest: OK\n");
}

static const char *const k_wf_allow[] = {
    "engine/modules/storage/src/chain_segment.c",
    "engine/modules/storage/include/storage/chain_segment.h",
    "engine/services/src/segment_sealer_service.c",
    "engine/controllers/src/chain_segment_controller.c",
    "engine/conditions/src/segment_corruption.c",
};

static int wf_allowed(const char *path)
{
    for (size_t i = 0; i < sizeof k_wf_allow / sizeof k_wf_allow[0]; i++)
        if (strcmp(path, k_wf_allow[i]) == 0) return 1;
    return 0;
}

static int wf_keep(const char *path, const char *text)
{
    const char *t = text;
    while (isspace((unsigned char)*t)) t++;
    return strncmp(path, "tests/", 6) && !strstr(text, "// writer-below-frontier-ok")
        && *t != '*' && !(t[0] == '/' && (t[1] == '/' || t[1] == '*'))
        && (!*t || !wf_allowed(path));
}

static int wf_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "(^|[^[:alnum:]_])chain_segment_seal" "_range[[:space:]]*\\(|",
                       "(^|[^[:alnum:]_])chain_segment_manifest" "_rebuild[[:space:]]*\\(",
                       "", "");
}

static int wf_need_files(void)
{
    for (size_t i = 0; i < sizeof k_wf_allow / sizeof k_wf_allow[0]; i++) {
        struct stat st;
        if (stat(k_wf_allow[i], &st) == 0 && S_ISREG(st.st_mode)) continue;
        fprintf(stderr, "check_no_writer_below_sealed_frontier: FATAL — "
                        "designated writer file '%s' is missing.\n", k_wf_allow[i]);
        fputs("  The sealed-store write surface moved; update this gate's\n"
              "  ALLOWLIST deliberately instead of letting the scan go hollow.\n",
              stderr);
        return 2;
    }
    return 0;
}

static int wf_summary(int raw, int v, const char *mode)
{
    return (printf("[check_no_writer_below_sealed_frontier] scanned %d "
                   "call/declaration site(s); %d violation(s) (mode: %s)\n",
                   raw, v, mode) < 0
            || puts("[check_no_writer_below_sealed_frontier] only the "
                    "sealer/RPC/healer/writer may call") < 0
            || puts("[check_no_writer_below_sealed_frontier] chain_segment_seal"
                    "_range() or chain_segment_manifest" "_rebuild();") < 0
            || puts("[check_no_writer_below_sealed_frontier] add // "
                    "writer-below-frontier-ok for a documented, reviewed exception") < 0)
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_no_writer_below_sealed_frontier_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    int rc = wf_need_files();
    if (rc) return rc;
    regex_t re;
    rc = wf_comp(&re);
    if (rc) return rc;
    char matches[CLK_MATCH] = {0};
    struct clock_acc a = { .re = &re, .buf = matches, .cap = sizeof matches, .keep = wf_keep };
    static const char *const roots[] = { "core", "engine", "contexts", "cognition", "platform" };
    int n_roots = 0;
    for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
        struct stat st;
        if (stat(roots[i], &st) == 0 && S_ISDIR(st.st_mode)) n_roots++;
    }
    rc = gate_require_scanned(n_roots, 5, "check_no_writer_below_sealed_frontier",
                              "expected all five production authorities to exist");
    if (rc == 0) rc = clock_walk(roots, sizeof roots / sizeof roots[0], &a);
    if (rc == 0)
        rc = gate_require_scanned(a.raw, 5, "check_no_writer_below_sealed_frontier",
                                  "chain_segment_seal" "_range/chain_segment_manifest"
                                  "_rebuild appear to have been renamed");
    int v = 0;
    if (rc == 0) rc = gate_count_and_report(matches, &v);
    if (rc == 0) rc = wf_summary(a.raw, v, clock_mode());
    regfree(&re);
    return rc ? rc : clock_grade(v, clock_mode());
}

int check_no_writer_below_sealed_frontier_selftest(void)
{
    regex_t re;
    if (wf_comp(&re)) return 2;
    char hit[48], marked[80], commented[56];
    snprintf(hit, sizeof hit, "    chain_segment_seal%s", "_range(s, 0, 1);");
    snprintf(marked, sizeof marked, "%s // writer-below-frontier-ok", hit);
    snprintf(commented, sizeof commented, "    // chain_segment_seal%s", "_range(s, 0, 1);");
    int bad = keep_case(wf_keep, &re, "engine/foo.c", "int x = 1;", 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", hit, 1, 1, "FAIL")
            | keep_case(wf_keep, &re, k_wf_allow[0], hit, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "tests/foo.c", hit, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", marked, 0, 0, "FAIL")
            | keep_case(wf_keep, &re, "engine/foo.c", commented, 0, 0, "FAIL");
    const char *oldm = getenv("ZCL_LINT_MODE");
    if (setenv("ZCL_LINT_MODE", "WARN", 1) != 0) bad = 1;
    bad |= keep_case(wf_keep, &re, "engine/foo.c", hit, 1, 0, clock_mode());
    if (oldm) (void)setenv("ZCL_LINT_MODE", oldm, 1);
    else (void)unsetenv("ZCL_LINT_MODE");
    regfree(&re);
    return st_ok(bad, "check_no_writer_below_sealed_frontier selftest: OK\n");
}


static int ps_hit_line(const char *s)
{
    return strstr(s, "\"/proc/" "self") || strstr(s, "\"/proc/" "uptime");
}
static int ps_skip(const char *path, const struct sr_set *base)
{
    return lint_path_is_excluded(path)
        || strncmp(path, "platform/modules/platform/", 26) == 0 || sr_has(base, path);
}
struct ps_acc { const struct sr_set *base; char (*hit)[192]; int n, max; };
static int scan_ps(const char *path, void *ctx)
{
    struct ps_acc *a = ctx;
    if (ps_skip(path, a->base)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0, found = 0;
    while (!found && getline(&line, &cap, f) >= 0) found = ps_hit_line(line);
    if (found) {
        size_t n = strlen(path);
        if (a->n >= a->max || n >= 192) rc = die("z23-lint: derived buffer overflow\n", "");
        else memcpy(a->hit[a->n++], path, n + 1);
    }
    return fin(f, line, path, rc);
}

int check_proc_self_shim_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct sr_set base = {0};
    int rc = sr_load(&base, "tools/lint/proc_self_shim_baseline.txt");
    if (rc) return rc;
    char hit[64][192];
    struct ps_acc a = { .base = &base, .hit = hit, .max = 64 };
    static const char *const roots[] = { "app", "config", "lib", "tools" };
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 0, scan_ps, &a);
    if (rc) return rc;
    if (!a.n)
        return puts("check_proc_self_shim: clean — no new raw /proc/self or /proc/uptime reads") < 0
                   ? die("z23-lint: write failed\n", "") : 0;
    char cwd[4096], bpath[4096];
    if (!getcwd(cwd, sizeof cwd)) return die("z23-lint: getcwd failed\n", "");
    if (ovf(snprintf(bpath, sizeof bpath, "%s/tools/lint/proc_self_shim_baseline.txt", cwd),
            sizeof bpath))
        return 2;
    if (fprintf(stderr, "check_proc_self_shim: raw /proc/self or /proc/uptime read(s) "
                        "outside platform/modules/platform/, not in %s:\n", bpath) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < a.n; i++)
        if (fprintf(stderr, "  %s\n", a.hit[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fprintf(stderr, "\nRoute through platform/os_proc.h, or add the file to %s with a "
                        "reason if genuinely exempt (e.g. async-signal-safety, per "
                        "engine/modules/sim/src/postmortem.c:1040).\n", bpath) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_proc_self_shim_selftest(void)
{
    const char *hit = "printf(\"%s\", \"/proc/" "self/exe\");";
    struct sr_set empty = {0}, base = {0};
    int bad = !ps_hit_line(hit) || ps_hit_line("int x;") || ps_hit_line("/proc/" "self");
    bad |= ps_skip("tools/foo.c", &empty) || !ps_skip("platform/modules/platform/os.c", &empty);
    if (sr_add(&base, "tools/foo.c")) return 2;
    bad |= !(ps_hit_line(hit) && !ps_skip("tools/foo.c", &empty));
    bad |= ps_hit_line(hit) && !ps_skip("tools/foo.c", &base);
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0) bad = 1;
    bad |= !lint_path_is_excluded("tools/_xfixture.c") || !ps_skip("tools/_xfixture.c", &empty);
    if (old) (void)setenv("ZCL_LINT_PRODUCTION_SCAN", old, 1);
    else (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    bad |= lint_path_is_excluded("tools/_xfixture.c") || ps_skip("tools/_xfixture.c", &empty);
    return st_ok(bad, "check_proc_self_shim selftest: OK\n");
}

enum { HS_NEST = 64 };
struct hs_st {
    const regex_t *re;
    const char *path;
    char *buf;
    size_t cap, *used;
    int depth, dev_active, lineno;
    int dev_frame[HS_NEST], dev_branch[HS_NEST];
};
static int hs_dl_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED, "(^|[^[:alnum:]_])dl(open|sym|close)",
                       "[[:space:]]*[(]", "", "");
}
static const char *hs_after_hash(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    if (*line != '#') return NULL;
    line++;
    while (*line == ' ' || *line == '\t') line++;
    return line;
}
static int hs_pp(const char *line)
{
    const char *p = hs_after_hash(line);
    if (!p) return 0;
    if (!strncmp(p, "ifdef", 5) && (p[5] == ' ' || p[5] == '\t')) {
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, "ZCL_DEV_BUILD", 13)) return 1;
        return 2;
    }
    if (p[0] == 'i' && p[1] == 'f') return 2;
    if (!strncmp(p, "elif", 4) || !strncmp(p, "else", 4)) return 3;
    if (!strncmp(p, "endif", 5)) return 4;
    return 0;
}
static int hs_feed(struct hs_st *s, const char *line)
{
    s->lineno++;
    int k = hs_pp(line);
    if (k == 1 || k == 2) {
        if (s->depth + 1 >= HS_NEST)
            return die("z23-lint: ifdef nest too deep: %s\n", s->path);
        s->depth++;
        s->dev_frame[s->depth] = (k == 1);
        s->dev_branch[s->depth] = (k == 1);
        if (k == 1) s->dev_active++;
        return 0;
    }
    if (k == 3) {
        if (s->depth > 0 && s->dev_frame[s->depth] && s->dev_branch[s->depth]) {
            s->dev_active--;
            s->dev_branch[s->depth] = 0;
        }
        return 0;
    }
    if (k == 4) {
        if (s->depth > 0) {
            if (s->dev_frame[s->depth] && s->dev_branch[s->depth]) s->dev_active--;
            s->dev_frame[s->depth] = 0;
            s->dev_branch[s->depth] = 0;
            s->depth--;
        }
        return 0;
    }
    if (regexec(s->re, line, 0, NULL, 0) != 0 || s->dev_active >= 1) return 0;
    int n = snprintf(s->buf + *s->used, s->cap - *s->used, "%s:%d: %s\n",
                     s->path, s->lineno, line);
    if (ovf(n, s->cap - *s->used)) return 2;
    *s->used += (size_t)n;
    return 0;
}
static int hs_scan_text(const char *text, const char *path, const regex_t *re,
                        char *buf, size_t cap, size_t *used)
{
    struct hs_st s = {
        .re = re, .path = path, .buf = buf, .cap = cap, .used = used,
        .depth = 0, .dev_active = 0, .lineno = 0
    };
    *used = 0;
    buf[0] = '\0';
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        int rc = hs_feed(&s, line);
        if (rc) return rc;
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}
static int hs_scan_path(const char *path, const regex_t *re, char *buf, size_t cap,
                        size_t *used)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    struct hs_st s = {
        .re = re, .path = path, .buf = buf, .cap = cap, .used = used,
        .depth = 0, .dev_active = 0, .lineno = 0
    };
    *used = 0;
    buf[0] = '\0';
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        rc = hs_feed(&s, line);
        if (rc) break;
    }
    return fin(f, line, path, rc);
}
struct hs_out_acc { const regex_t *re; char *buf; size_t cap, used; };
static int scan_hs_out(const char *path, void *ctx)
{
    struct hs_out_acc *a = ctx;
    if (!strncmp(path, "engine/modules/hotswap/", 23)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0) continue;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        int k = snprintf(a->buf + a->used, a->cap - a->used, "%s:%d:%s\n",
                         path, lineno, line);
        if (ovf(k, a->cap - a->used)) { rc = 2; break; }
        a->used += (size_t)k;
    }
    return fin(f, line, path, rc);
}
static int hs_each_src(const char *dir, const regex_t *re, int *saw)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    char bad[CLK_MATCH];
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISREG(st.st_mode) && nl >= 2 && name[nl - 2] == '.'
                     && name[nl - 1] == 'c') {
                size_t used = 0;
                rc = hs_scan_path(path, re, bad, sizeof bad, &used);
                if (rc == 0 && used) {
                    if (fputs(bad, stdout) < 0
                        || printf("FAIL: dl* call outside a #ifdef ZCL_DEV_BUILD region in %s\n",
                                  path) < 0)
                        rc = die("z23-lint: write failed\n", "");
                    else rc = 1;
                }
                if (saw) (*saw)++;
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

int check_hotswap_dev_only_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    regex_t re;
    int cr = hs_dl_comp(&re);
    if (cr) return cr;
    char hits[CLK_MATCH] = {0};
    struct hs_out_acc a = { .re = &re, .buf = hits, .cap = sizeof hits };
    static const char *const roots[] = {
        "app", "tools", "lib", "config", "src", "domain", "application", "adapters"
    };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof roots / sizeof roots[0]; i++)
        rc = walk_src(roots[i], 0, scan_hs_out, &a);
    if (rc == 0 && a.used) {
        if (fputs(hits, stdout) < 0
            || puts("FAIL: dlopen/dlsym/dlclose outside engine/modules/hotswap/ (release must be static)") < 0)
            rc = die("z23-lint: write failed\n", "");
        else rc = 1;
    }
    if (rc == 0) rc = hs_each_src("engine/modules/hotswap/src", &re, NULL);
    regfree(&re);
    if (rc) return rc;
    return puts("  OK: hot-swap dynamic loading is dev-only") < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int check_hotswap_dev_only_selftest(void)
{
    regex_t re;
    int cr = hs_dl_comp(&re);
    if (cr) return cr;
    char nested[160], elseb[160], inner[160], pfx[160], d1[64], d2[64], d3[48];
    char nbuf[256], ebuf[256], ibuf[256];
    size_t nused = 0, eused = 0, iused = 0;
    if (snprintf(nested, sizeof nested,
                 "#ifdef ZCL_DEV_BUILD\n#if defined(__APPLE__)\ndl%s(\"dev\", 0);\n"
                 "#endif\n#endif\n", "open") >= (int)sizeof nested
        || snprintf(elseb, sizeof elseb,
                    "#ifdef ZCL_DEV_BUILD\ndl%s(\"dev\", 0);\n#else\ndl%s(\"release\", 0);\n"
                    "#endif\n", "open", "open") >= (int)sizeof elseb
        || snprintf(inner, sizeof inner,
                    "#ifdef ZCL_DEV_BUILD\n#if 0\ndl%s(\"inner\", 0);\n#endif\n#endif\n",
                    "open") >= (int)sizeof inner
        || snprintf(pfx, sizeof pfx, "%s\n%s\n%s\n",
                    "static void *vfs_dir_xdlopen(void);",
                    "static void *vfs_dir_xdlsym(void);",
                    "static void vfs_dir_xdlclose(void);") >= (int)sizeof pfx
        || snprintf(d1, sizeof d1, "void *p = dl%s(\"fixture\", 0);", "open") >= (int)sizeof d1
        || snprintf(d2, sizeof d2, "p = dl%s (h, \"fixture\");", "sym") >= (int)sizeof d2
        || snprintf(d3, sizeof d3, "(void)dl%s(h);", "close") >= (int)sizeof d3) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int rc = hs_scan_text(nested, "-", &re, nbuf, sizeof nbuf, &nused);
    if (rc == 0) rc = hs_scan_text(elseb, "-", &re, ebuf, sizeof ebuf, &eused);
    if (rc == 0) rc = hs_scan_text(inner, "-", &re, ibuf, sizeof ibuf, &iused);
    int pfx_hit = 0, direct = 0;
    const char *pl = pfx;
    while (rc == 0 && *pl) {
        const char *nl = strchr(pl, '\n');
        size_t n = nl ? (size_t)(nl - pl) : strlen(pl);
        char line[160];
        if (n >= sizeof line) { rc = 2; break; }
        memcpy(line, pl, n);
        line[n] = '\0';
        if (regexec(&re, line, 0, NULL, 0) == 0) pfx_hit++;
        pl = nl ? nl + 1 : pl + n;
        if (!nl) break;
    }
    if (rc == 0) {
        if (regexec(&re, d1, 0, NULL, 0) == 0) direct++;
        if (regexec(&re, d2, 0, NULL, 0) == 0) direct++;
        if (regexec(&re, d3, 0, NULL, 0) == 0) direct++;
    }
    int bad = rc != 0 || nused != 0 || eused == 0 || iused != 0 || pfx_hit != 0
            || direct != 3;
    if (bad)
        fputs("FAIL: hot-swap dev-region scanner selftest\n", stderr);
    regfree(&re);
    return st_ok(bad, "check_hotswap_dev_only selftest: OK\n");
}

enum { CBF_MAX = 256, CBF_PATH = 256 };
static const char k_cbf_def[] = "engine/jobs/src/stage_repair_coin_backfill.c";
static const char k_cbf_allow[] =
    "engine/reducer/jobs/src/stage_repair_reducer_frontier_coin.c";
static const char *const k_cbf_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};
struct cbf_ent { char path[CBF_PATH]; int count; };
struct cbf_acc { const char *sym; struct cbf_ent *ent; int n; };

static void cbf_sym(char *buf, size_t cap)
{
    (void)snprintf(buf, cap, "%s%s", "stage_repair_coin_backfill_try", "(");
}

static int cbf_cmp(const void *a, const void *b)
{
    return strcmp(((const struct cbf_ent *)a)->path,
                  ((const struct cbf_ent *)b)->path);
}

static int cbf_count(const char *path, const char *sym, int *count)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0, slen = strlen(sym);
    *count = 0;
    while (getline(&line, &cap, f) >= 0) {
        for (char *p = line; slen && (p = strstr(p, sym)) != NULL; p += slen)
            (*count)++;
    }
    return fin(f, line, path, 0);
}

static int cbf_on_file(const char *path, void *ctx)
{
    struct cbf_acc *a = ctx;
    if (strcmp(path, k_cbf_def) == 0 || lint_path_is_excluded(path))
        return 0;
    int n = 0, rc = cbf_count(path, a->sym, &n);
    if (rc)
        return rc;
    if (n <= 0)
        return 0;
    size_t pl = strlen(path);
    if (a->n >= CBF_MAX || pl >= CBF_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a->ent[a->n].path, path, pl + 1);
    a->ent[a->n].count = n;
    a->n++;
    return 0;
}

static int cbf_has_sym(const char *path, const char *sym)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = strstr(line, sym) != NULL;
    (void)fin(f, line, path, 0);
    return found;
}

static int cbf_scan(FILE *out)
{
    char sym[64];
    cbf_sym(sym, sizeof sym);
    if (!cbf_has_sym(k_cbf_def, sym)) {
        if (fprintf(out, "check_no_new_coin_backfill_caller: FATAL — '%s' no longer found in %s.\n",
                    sym, k_cbf_def) < 0
            || fputs("  - If the coin-backfill ladder was deleted, remove this gate and its Makefile wiring.\n",
                     out) < 0
            || fputs("  - If it moved or was renamed, update DEF_FILE/SYMBOL so the ratchet keeps firing.\n",
                     out) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    struct cbf_ent ent[CBF_MAX];
    struct cbf_acc a = { .sym = sym, .ent = ent, .n = 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_cbf_roots / sizeof k_cbf_roots[0]; i++)
        rc = walk_src(k_cbf_roots[i], 0, cbf_on_file, &a);
    if (rc)
        return rc;
    qsort(ent, (size_t)a.n, sizeof ent[0], cbf_cmp);
    int allowed_count = 0, nbad = 0, bad_i[CBF_MAX];
    for (int i = 0; i < a.n; i++) {
        if (strcmp(ent[i].path, k_cbf_allow) == 0)
            allowed_count += ent[i].count;
        else
            bad_i[nbad++] = i;
    }
    if (nbad == 0 && allowed_count == 1)
        return fputs("check_no_new_coin_backfill_caller: clean — one allowed production caller\n",
                     out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (allowed_count != 1
        && fprintf(out, "check_no_new_coin_backfill_caller: expected exactly 1 call in %s, found %d\n",
                   k_cbf_allow, allowed_count) < 0)
        return die("z23-lint: write failed\n", "");
    if (nbad) {
        if (fprintf(out, "check_no_new_coin_backfill_caller: NEW production caller(s) of %s:\n",
                    sym) < 0)
            return die("z23-lint: write failed\n", "");
        for (int i = 0; i < nbad; i++) {
            int j = bad_i[i];
            if (fprintf(out, "  %s:%d\n", ent[j].path, ent[j].count) < 0)
                return die("z23-lint: write failed\n", "");
        }
    }
    if (fputc('\n', out) == EOF
        || fputs("Do NOT add another coin-backfill repair entry caller. Route reducer-frontier\n",
                 out) < 0
        || fputs("repair evidence through the existing dispatcher, or delete/shrink this ladder\n",
                 out) < 0
        || fputs("after the self-verified UTXO anchor rebuild cure (-refold-from-anchor).\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int cbf_with_root(const char *root, FILE *out)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    int rc = cbf_scan(out);
    if (chdir(cwd) != 0 && rc == 0)
        rc = die("z23-lint: getcwd failed\n", "");
    return rc;
}

static const char *cbf_root(int argc, char **argv)
{
    const char *env = getenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    if (env && env[0])
        return env;
    if (argc >= 1 && argv[0] && argv[0][0])
        return argv[0];
    return ".";
}

int check_no_new_coin_backfill_caller_run(int argc, char **argv)
{
    return cbf_with_root(cbf_root(argc, argv), stdout);
}

static int cbf_st_run(FILE *cap, int *rc)
{
    if (psp_st_reset(cap))
        return 1;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0)
        return 1;
    if (dup2(fileno(cap), STDOUT_FILENO) < 0) {
        close(saved);
        return 1;
    }
    *rc = check_no_new_coin_backfill_caller_run(0, NULL);
    fflush(stdout);
    (void)dup2(saved, STDOUT_FILENO);
    close(saved);
    return 0;
}

int check_no_new_coin_backfill_caller_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-cbf-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *cap = tmpfile();
    if (!cap) {
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    const char *old_root = getenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    const char *old_prod = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char oldr[4096], oldp[64];
    int had_root = 0, had_prod = 0, bad = 0, rc = 0;
    if (old_root) {
        if (ovf(snprintf(oldr, sizeof oldr, "%s", old_root), sizeof oldr))
            bad = 1;
        else
            had_root = 1;
    }
    if (old_prod) {
        if (ovf(snprintf(oldp, sizeof oldp, "%s", old_prod), sizeof oldp))
            bad = 1;
        else
            had_prod = 1;
    }
    char sym[64], defp[4096], allp[4096], probep[4096], fx[4096], body[256], ob[8192];
    cbf_sym(sym, sizeof sym);
    if (ovf(snprintf(defp, sizeof defp, "%s/%s", root, k_cbf_def), sizeof defp)
        || ovf(snprintf(allp, sizeof allp, "%s/%s", root, k_cbf_allow), sizeof allp)
        || ovf(snprintf(probep, sizeof probep, "%s/core/probe.c", root), sizeof probep)
        || ovf(snprintf(fx, sizeof fx, "%s/engine/_xfixture.c", root), sizeof fx)
        || ovf(snprintf(body, sizeof body, "void %svoid) {}\n", sym), sizeof body)
        || csr_write(defp, body)
        || ovf(snprintf(body, sizeof body, "void f(void) { %s); }\n", sym), sizeof body)
        || csr_write(allp, body)
        || setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root, 1) != 0)
        bad = 1;

    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_no_new_coin_backfill_caller: clean — one allowed production caller") == NULL;

    if (ovf(snprintf(body, sizeof body, "void f(void) { %s); %s); }\n", sym, sym),
            sizeof body)
        || csr_write(allp, body))
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "expected exactly 1 call in") == NULL
        || strstr(ob, "found 2") == NULL;

    if (ovf(snprintf(body, sizeof body, "void f(void) { %s); }\n", sym), sizeof body)
        || csr_write(allp, body)
        || ovf(snprintf(body, sizeof body, "void g(void) { %s); }\n", sym), sizeof body)
        || csr_write(probep, body))
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "NEW production caller(s)") == NULL
        || strstr(ob, "core/probe.c:1") == NULL;
    (void)unlink(probep);

    (void)unlink(defp);
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 2 || strstr(ob, "FATAL") == NULL;

    if (ovf(snprintf(body, sizeof body, "void %svoid) {}\n", sym), sizeof body)
        || csr_write(defp, body)
        || ovf(snprintf(body, sizeof body, "void x(void) { %s); }\n", sym), sizeof body)
        || csr_write(fx, body)
        || setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
        bad = 1;
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 0
        || strstr(ob, "check_no_new_coin_backfill_caller: clean — one allowed production caller") == NULL;
    (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    if (!bad && cbf_st_run(cap, &rc))
        bad = 1;
    if (csr_slurp(cap, ob, sizeof ob))
        bad = 1;
    bad |= rc != 1
        || strstr(ob, "NEW production caller(s)") == NULL
        || strstr(ob, "engine/_xfixture.c:1") == NULL;

    fclose(cap);
    if (had_root)
        (void)setenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST", oldr, 1);
    else
        (void)unsetenv("ZCL_COIN_BACKFILL_ROOT_FOR_TEST");
    if (had_prod)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", oldp, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_new_coin_backfill_caller selftest\n", stderr);
    return st_ok(bad, "check_no_new_coin_backfill_caller selftest: OK\n");
}
