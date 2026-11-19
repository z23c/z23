/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — pattern-guard scans of the C23 lint runtime
 * (check-rpc-registrar, check-coins-lookup-nullcheck, check-pthread-create,
 * check-silent-error-returns, check-no-gnu-va-args). The rpc/registrar and
 * coins-lookup gates require a risky bare call to be paired with, or
 * replaced by, a specific guard call; the pthread/silent-return/va-args
 * trio shares the two-pattern hit/exclude/prev scanner (struct lg_acc,
 * pt_pair_comp) moved here from gate_pattern_small.c to keep both family
 * files under the 1500-line ceiling.
 */

/*
 * Gates: check-rpc-registrar, check-coins-lookup-nullcheck,
 * check-pthread-create, check-silent-error-returns, check-no-gnu-va-args
 * This family exists because gate_pattern_small.c and gate_ratchet_ports.c
 * are in concurrent flight (other lanes), and the remaining families are
 * each within ~350 lines of the 1500-line cap — too tight for two more
 * consumers. A future guard-pairing pattern scan joins this file while it
 * stays under the cap. Default landing spot otherwise: a filesystem-tree-
 * walking gate joins gate_tree_walk.c; a git-tracked-enumeration gate
 * joins whichever of gate_git_scan_a.c/gate_git_scan_b.c is smaller; a
 * proof/landing/receipt-shaped gate joins gate_landing_proof.c; a
 * build-flag/CI-toggle-shaped gate joins gate_build_config.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lint_narrow_hook.h"

static int pg_pref(const char *path, const char *pref)
{
    return strncmp(path, pref, strlen(pref)) == 0;
}

static int pg_ends(const char *path, const char *suf)
{
    size_t n = strlen(path), m = strlen(suf);
    return n >= m && memcmp(path + n - m, suf, m) == 0;
}

static int pg_is_ch(const char *path)
{
    return pg_ends(path, ".c") || pg_ends(path, ".h");
}

static int pg_copy(FILE *from, FILE *to)
{
    if (fseek(from, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, from)) >= 0) {
        if (fwrite(line, 1, (size_t)n, to) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(from);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int rpc_skip(const char *path)
{
    return strcmp(path, "engine/modules/rpc/src/server.c") == 0
        || strcmp(path, "engine/modules/rpc/include/rpc/server.h") == 0
        || pg_pref(path, "tests/harness/include/test/");
}

static int rpc_keep(const char *path)
{
    if (lint_path_is_excluded(path) || rpc_skip(path) || !pg_is_ch(path))
        return 0;
    return pg_pref(path, "lib/") || pg_pref(path, "app/")
        || pg_pref(path, "tools/") || pg_pref(path, "config/")
        || pg_pref(path, "engine/") || pg_pref(path, "contexts/")
        || pg_pref(path, "cognition/") || pg_pref(path, "platform/");
}

static int rpc_comp(regex_t *re)
{
    return compile_pat(re, REG_EXTENDED,
                       "rpc_table_appe", "nd([^[:alnum:]_]|$)", "", "");
}

struct rpc_acc { regex_t *re; FILE *out; int hits; };

static int rpc_note(struct rpc_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(a->out, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    return fin(f, line, path, rc);
}

static int rpc_on_file(const char *path, void *ctx)
{
    return rpc_keep(path) ? rpc_note(ctx, path) : 0;
}

/* The test harness deliberately omits .git. Choose that filesystem scan
 * before invoking Git; a failed Git producer or callback must stay failed.
 * tools is the current required root; the other legacy filter roots are
 * optional, but errors inspecting them are never evidence of absence. */
static int rpc_scan(struct rpc_acc *a)
{
    struct stat st;
    if (lstat(".git", &st) == 0 || getenv("GIT_INDEX_FILE"))
        return each_zpath(k_ls_all, rpc_on_file, a);
    if (errno != ENOENT)
        return die("z23-lint: cannot stat %s\n", ".git");
    int rc = walk_src_root("check-rpc-registrar", "tools", 1, rpc_on_file, a);
    static const char *const optional[] = {
        "engine", "contexts", "cognition", "platform", "lib", "app", "config"
    };
    for (size_t i = 0; rc == 0 && i < sizeof optional / sizeof optional[0]; i++) {
        if (lstat(optional[i], &st) == 0)
            rc = walk_src_root("check-rpc-registrar", optional[i], 1, rpc_on_file, a);
        else if (errno != ENOENT)
            rc = die("z23-lint: cannot stat %s\n", optional[i]);
    }
    return rc;
}

static int rpc_eval(FILE *out)
{
    regex_t re;
    int rc = rpc_comp(&re);
    if (rc)
        return rc;
    struct rpc_acc a = { .re = &re, .out = out };
    rc = rpc_scan(&a);
    if (rc == 0 && a.hits) {
        if (fputs("\n"
                  "FAIL: rpc_table_appe" "nd() used outside engine/modules/rpc/src/server.c and tests/harness/include/test/.\n"
                  "      Use rpc_table_must_append() in every register_*_rpc_commands()\n"
                  "      callsite. See engine/modules/rpc/include/rpc/server.h for the contract.\n",
                  out) < 0)
            rc = die("z23-lint: write failed\n", "");
        else
            rc = 1;
    } else if (rc == 0) {
        if (fputs("  OK: all RPC registrar callsites use rpc_table_must_append\n",
                  out) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    regfree(&re);
    return rc;
}

int check_rpc_registrar_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return rpc_eval(stdout);
}

static int rpc_st_note(const char *text, int want_hits)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/z23-lint-rpc-note.c", td),
            sizeof path))
        return 1;
    if (csr_write(path, text))
        return 1;
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr) {
        (void)unlink(path);
        return 1;
    }
    FILE *out = tmpfile();
    if (!out) {
        regfree(&re);
        (void)unlink(path);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct rpc_acc a = { .re = &re, .out = out };
    int rc = rpc_note(&a, path);
    int bad = rc != 0 || a.hits != want_hits;
    fclose(out);
    regfree(&re);
    (void)unlink(path);
    return bad;
}

static int rpc_st_skip_scan(void)
{
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr)
        return 1;
    FILE *out = tmpfile();
    if (!out) {
        regfree(&re);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct rpc_acc a = { .re = &re, .out = out };
    int bad = rpc_on_file("engine/modules/rpc/src/server.c", &a) != 0
           || a.hits != 0
           || rpc_on_file("engine/modules/rpc/include/rpc/server.h", &a) != 0
           || a.hits != 0
           || rpc_on_file("tests/harness/include/test/x.h", &a) != 0
           || a.hits != 0;
    fclose(out);
    regfree(&re);
    return bad;
}

static int rpc_st_eval(int want_rc)
{
    FILE *out = tmpfile();
    if (!out)
        return 1;
    int rc = rpc_eval(out);
    char text[4096];
    int bad = csr_slurp(out, text, sizeof text) != 0 || rc != want_rc;
    if (want_rc != 0 && strstr(text, "  OK:"))
        bad = 1;
    if (fclose(out) != 0)
        bad = 1;
    return bad;
}

static int rpc_st_scan_errors(void)
{
    char old[4096], tmp[4096];
    const char *tmpdir = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(tmpdir) || !getcwd(old, sizeof old)
        || ovf(snprintf(tmp, sizeof tmp, "%s/z23-rpc-scan-XXXXXX",
                         tmpdir), sizeof tmp)
        || !mkdtemp(tmp))
        return 1;
    int bad = chdir(tmp) != 0;
    if (!bad) {
        bad |= rpc_st_eval(2); /* Missing required nongit scan root. */
        bad |= mkdir("tools", 0700) != 0;
        bad |= rpc_st_eval(0); /* A successfully scanned empty root is valid. */
        bad |= csr_write("engine/controllers/src/fixture.c",
                         "void f(void) { rpc_table_appe" "nd(0, 0); }\n") != 0;
        bad |= rpc_st_eval(1); /* Current source roots participate in fallback. */
        bad |= csr_write("engine/controllers/src/fixture.c",
                         "void f(void) { rpc_table_must_append(0, 0); }\n") != 0;
        bad |= rpc_st_eval(0);
        bad |= mkdir(".git", 0700) != 0;
        bad |= rpc_st_eval(2); /* Invalid Git metadata must not trigger fallback. */
    }
    if (chdir(old) != 0)
        return die("z23-lint: cannot restore %s\n", old);
    return rap_rm_rf(tmp) != 0 || bad;
}

int check_rpc_registrar_selftest(void)
{
    regex_t re;
    int cr = rpc_comp(&re);
    if (cr)
        return cr;
    const char *t = "check_rpc_registrar";
    int bad = want(t, &re, "    rpc_table_appe" "nd(&t, &c);", 1)
            | want(t, &re, "    rpc_table_must_append(&t, &c);", 0)
            | want(t, &re, "rpc_table_appe" "nd", 1)
            | want(t, &re, "rpc_table_appe" "nd_more(", 0);
    regfree(&re);
    bad |= !rpc_keep("lib/x.c") || !rpc_keep("app/x.h")
        || !rpc_keep("tools/x.c") || !rpc_keep("config/x.h")
        || rpc_keep("engine/modules/rpc/src/server.c")
        || rpc_keep("engine/modules/rpc/include/rpc/server.h")
        || rpc_keep("tests/harness/include/test/x.h")
        || rpc_keep("core/foo.c");
    bad |= rpc_st_skip_scan();
    bad |= rpc_st_note("    rpc_table_appe" "nd(&t, &c);\n", 1);
    bad |= rpc_st_note("    rpc_table_must_append(&t, &c);\n", 0);
    bad |= !rpc_keep("engine/controllers/src/x.c")
        || !rpc_keep("contexts/wallet/x.c")
        || !rpc_keep("cognition/x.c") || !rpc_keep("platform/x.h");
    bad |= rpc_st_scan_errors();
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = rpc_eval(out);
    fclose(out);
    bad |= rc != 0;
    return st_ok(bad, "check_rpc_registrar selftest: OK\n");
}

static int cln_keep(const char *path, int env_mode)
{
    if (lint_path_is_excluded(path) || !pg_ends(path, ".c"))
        return 0;
    return env_mode || pg_pref(path, "engine/controllers/src/");
}

struct cln_acc {
    regex_t *lookup;
    regex_t *guard;
    FILE *miss;
    int nscan;
    int nhit;
    int nmiss;
    int env_mode;
};

static int cln_on_file(const char *path, void *ctx)
{
    struct cln_acc *a = ctx;
    if (!cln_keep(path, a->env_mode))
        return 0;
    a->nscan++;
    int nl = 0, ng = 0;
    int rc = scan_re(path, a->lookup, &nl, 0);
    if (rc)
        return rc;
    if (!nl)
        return 0;
    a->nhit++;
    rc = scan_re(path, a->guard, &ng, 0);
    if (rc)
        return rc;
    if (ng)
        return 0;
    a->nmiss++;
    if (fprintf(a->miss, "%s\n", path) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cln_report(struct cln_acc *a, const char *scan_dir, FILE *out)
{
    const char *dir = scan_dir ? scan_dir : "engine/controllers/src";
    char hint[4096];
    if (ovf(snprintf(hint, sizeof hint,
                     "no controller *.c files under '%s'", dir), sizeof hint))
        return 2;
    int rc = gate_require_scanned(a->nscan, 1, "check_coins_lookup_nullcheck",
                                  hint);
    if (rc)
        return rc;
    if (a->nmiss) {
        if (fputs("check_coins_lookup_nullcheck: missing rpc_require_chainstate_lookup_ready in:\n\n",
                  out) < 0)
            return die("z23-lint: write failed\n", "");
        rc = pg_copy(a->miss, out);
        return rc ? rc : 1;
    }
    rc = gate_require_scanned(a->nhit, 1, "check_coins_lookup_nullcheck",
            "no coins_view_cache_get_coins() call sites found; update this gate deliberately if the lookup API moved");
    if (rc)
        return rc;
    if (fprintf(out,
                "check_coins_lookup_nullcheck: clean — all controller coin lookups guarded (%d files)\n",
                a->nhit) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int cln_eval(const char *scan_dir, FILE *out)
{
    regex_t lookup, guard;
    int rc = pair_comp(&lookup, REG_EXTENDED,
                       "coins_view_cache_get_coins[[:space:]]*\\(", "", "", "",
                       &guard, REG_EXTENDED,
                       "rpc_require_chainstate_lookup_ready[[:space:]]*\\(",
                       "", "", "");
    if (rc)
        return rc;
    FILE *miss = tmpfile();
    if (!miss) {
        drop2(&lookup, &guard);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct cln_acc a = {
        .lookup = &lookup, .guard = &guard, .miss = miss,
        .env_mode = scan_dir != NULL
    };
    if (scan_dir) {
        rc = walk_src(scan_dir, 0, cln_on_file, &a);
    } else {
        struct stat st;
        if (lstat(".git", &st) == 0 || getenv("GIT_INDEX_FILE"))
            rc = each_zpath(k_ls_all, cln_on_file, &a);
        else if (errno != ENOENT)
            rc = die("z23-lint: cannot stat %s\n", ".git");
        else
            rc = walk_src("engine/controllers/src", 0, cln_on_file, &a);
    }
    if (rc == 0)
        rc = cln_report(&a, scan_dir, out);
    fclose(miss);
    drop2(&lookup, &guard);
    return rc;
}

int check_coins_lookup_nullcheck_run(int argc, char **argv)
{
    const char *dir;
    (void)argc;
    (void)argv;
    dir = getenv("ZCL_COINS_LOOKUP_SCAN_DIR");
    return cln_eval((dir && dir[0]) ? dir : NULL, stdout);
}

static int cln_st_case(const char *root, const char *body, int want_rc)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/x.c", root), sizeof path))
        return 1;
    (void)unlink(path);
    if (body && csr_write(path, body))
        return 1;
    FILE *out = tmpfile();
    if (!out)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = cln_eval(root, out);
    fclose(out);
    (void)unlink(path);
    return rc != want_rc;
}

int check_coins_lookup_nullcheck_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-cln.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    int bad = cln_st_case(tmp, NULL, 2);
    bad |= cln_st_case(tmp, "int x(void) { return 0; }\n", 2);
    bad |= cln_st_case(tmp,
                       "void f(void) { coins_view_cache_get_coins(c, id); }\n",
                       1);
    bad |= cln_st_case(tmp,
                       "void f(void) {\n"
                       "    rpc_require_chainstate_lookup_ready();\n"
                       "    coins_view_cache_get_coins(c, id);\n"
                       "}\n",
                       0);
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_coins_lookup_nullcheck selftest: OK\n");
}

struct lg_acc {
    regex_t *hit;
    regex_t *excl;
    regex_t *prev;
    const char *skip_sub;
    const char *skip_eq;
    int hits;
    /* Optional shrink-only-baseline recording: when sym is set, every hit
     * also adds "<path>:<sym>" to *found (once per file). NULL for callers
     * that FAIL on any hit instead of ratcheting a baseline. */
    const char *sym;
    struct bln_set *found;
    int files;
};

static int lg_got(const regex_t *hit, const regex_t *excl, const regex_t *prev,
                  const char *p, const char *s);

/* Baseline-record one hit at `path` (a->sym set) into *a->found, as
 * "<path>:<sym>"; a no-op for callers that FAIL on any hit instead. */
static int lg_record_hit(struct lg_acc *a, const char *path)
{
    if (!a->sym)
        return 0;
    char key[BLN_ROW];
    if (ovf(snprintf(key, sizeof key, "%s:%s", path, a->sym), sizeof key))
        return 2;
    return bln_add(a->found, key);
}

static int lg_scan_at(const char *open_path, const char *logical, struct lg_acc *a)
{
    if ((a->skip_sub && strstr(logical, a->skip_sub) != NULL)
        || (a->skip_eq && strcmp(logical, a->skip_eq) == 0))
        return 0;
    a->files++;
    FILE *f = fopen(open_path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", open_path);
    char *buf[2] = { NULL, NULL };
    size_t cap[2] = { 0, 0 };
    int cur = 0, lineno = 0, rc = 0;
    ssize_t n;
    while ((n = getline(&buf[cur], &cap[cur], f)) >= 0) {
        char *line = buf[cur];
        lineno++;
        const char *prevline = lineno > 1 ? buf[1 - cur] : NULL;
        if (lg_got(a->hit, a->excl, a->prev, prevline, line)) {
            if (n > 0 && line[n - 1] == '\n')
                line[n - 1] = '\0';
            if (fprintf(stdout, "%s:%d:%s\n", logical, lineno, line) < 0) {
                rc = die("z23-lint: write failed\n", "");
                break;
            }
            a->hits++;
            rc = lg_record_hit(a, logical);
            if (rc)
                break;
        }
        cur = 1 - cur;
    }
    rc = fin(f, NULL, open_path, rc);
    free(buf[0]);
    free(buf[1]);
    return rc;
}

static int scan_lg(const char *path, void *ctx)
{
    return lg_scan_at(path, path, ctx);
}

static int lg_got(const regex_t *hit, const regex_t *excl, const regex_t *prev,
                  const char *p, const char *s)
{
    if (regexec(hit, s, 0, NULL, 0) != 0)
        return 0;
    if (regexec(excl, s, 0, NULL, 0) == 0)
        return 0;
    if (p && regexec(prev, p, 0, NULL, 0) == 0)
        return 0;
    return 1;
}

static int lg_want(const char *tag, const regex_t *hit, const regex_t *excl,
                   const regex_t *prev, const char *p, const char *s, int w)
{
    if (lg_got(hit, excl, prev, p, s) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

/* The regex strings of the two-pattern gates, and the one shared compile:
 * a hit pattern, then the exclude/prev pair, freeing the hit regex when
 * the pair fails. The strings live in tables so each gate's comp wrapper
 * stays data, not a duplicated body. */
struct pt_pair_pats {
    const char *hit[4];
    const char *excl[4];
    const char *prev[4];
};

static int pt_pair_comp(regex_t *hit, regex_t *excl, regex_t *prev,
                        const struct pt_pair_pats *pats)
{
    int cr = compile_pat(hit, REG_EXTENDED, pats->hit[0], pats->hit[1],
                         pats->hit[2], pats->hit[3]);
    if (cr)
        return cr;
    cr = pair_comp(excl, REG_EXTENDED, pats->excl[0], pats->excl[1],
                   pats->excl[2], pats->excl[3], prev, REG_EXTENDED,
                   pats->prev[0], pats->prev[1], pats->prev[2],
                   pats->prev[3]);
    if (cr)
        regfree(hit);
    return cr;
}

static const struct pt_pair_pats k_pt_pats = {
    { "pthread_create", "[[:space:]]*\\(", "", "" },
    { "thread_registry_spawn", "|thread_registry_trampoline",
      "|raw-pthread-ok", "" },
    { "raw-pthread-ok", "", "", "" }
};

static int pt_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    return pt_pair_comp(hit, excl, prev, &k_pt_pats);
}

static const char k_pt_baseline[] = "tools/lint/pthread_create_baseline.txt";

/* Production C roots — "lib" and "config" were dead (renamed away); the
 * gate silently scanned only "app" (also dead) and "tools", i.e. nothing
 * of substance, and reported clean. See malloc_baseline.txt for the same
 * root-rename story. */
/* NULL-terminated for the shared lint_narrow_roots_prefix hook; the walk
 * loops use PT_NROOTS, not the sizeof count. */
enum { PT_NROOTS = 6 };
static const char *const k_pt_roots[PT_NROOTS + 1] = {
    "core", "engine", "contexts", "cognition", "platform", "tools", NULL
};

/* Measured 2026-09-06: 2644 .c files under the production roots. */
enum { PT_SCAN_FLOOR = 2400 };

/* pt_path_form/pt_repo/pt_under_roots bodies live in the shared narrowing
 * hooks (lint_narrow_hook.h); the selftest keeps calling the under-roots
 * symbol. */
static const char *pt_path_form(const char *path, const char *repo)
{
    return lint_narrow_repo_form_opt(path, repo);
}

static int pt_repo(const struct lint_changed *ch, char out[4096],
                   const char **repo)
{
    return lint_narrow_repo_opt(ch, out, repo);
}

static int pt_under_roots(const char *path)
{
    return lint_narrow_roots_prefix(path, k_pt_roots);
}

static int pt_selected_file(const char *root, const char *path, struct lg_acc *a)
{
    char full[4096];
    struct stat st;
    if (ovf(snprintf(full, sizeof full, "%s/%s", root, path), sizeof full))
        return die("z23-lint: path too long: %s\n", path);
    if (lstat(full, &st) != 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot stat %s\n", full);
    if (!S_ISREG(st.st_mode))
        return 0;
    return lg_scan_at(full, path, a);
}

static int pt_scan_selected(const char *root, const struct lint_changed *ch,
                            const char *repo, struct lg_acc *a)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < ch->n; i++) {
        const char *path = pt_path_form(ch->path[i], repo);
        size_t n = strlen(path);
        if (n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c' &&
            pt_under_roots(path))
            rc = pt_selected_file(root, path, a);
    }
    return rc;
}

static int pt_base_narrow(struct bln_set *base, const struct lint_changed *ch,
                          const char *repo)
{
    struct bln_set selected = {0};
    for (int i = 0; i < base->count; i++) {
        for (int k = 0; k < ch->n; k++) {
            const char *path = pt_path_form(ch->path[k], repo);
            size_t n = strlen(path);
            if (strncmp(base->n[i], path, n) == 0 && base->n[i][n] == ':') {
                int rc = bln_add(&selected, base->n[i]);
                if (rc)
                    return rc;
                break;
            }
        }
    }
    *base = selected;
    return 0;
}

/* The narrowing-hook descriptor: pt's repo-optional resolver and path
 * form steer the shared lint_narrow_ok baseline compare. */
static const struct lint_narrow_gate k_pt_narrow_gate = {
    "check-pthread-create", NULL, pt_path_form, NULL, pt_repo, NULL, 0
};

static int pt_narrow_ok(const struct lint_changed *ch)
{
    return lint_narrow_ok(ch, k_pt_baseline, &k_pt_narrow_gate);
}

static int pt_scan_report(const char *root, const char *base_path,
                          const struct lint_changed *narrow)
{
    regex_t hit, excl, prev;
    int cr = pt_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    struct bln_set base = {0}, found = {0};
    int rc = bln_load(&base, base_path);
    char repo_buf[4096];
    const char *repo = NULL;
    if (rc == 0 && narrow)
        rc = pt_repo(narrow, repo_buf, &repo);
    if (rc == 0 && narrow)
        rc = pt_base_narrow(&base, narrow, repo);
    struct lg_acc a = {
        .hit = &hit, .excl = &excl, .prev = &prev,
        .skip_sub = "tests/harness/include/test/",
        .skip_eq = "platform/modules/util/src/thread_registry.c",
        .hits = 0, .sym = "pthread_create", .found = &found
    };
    if (rc == 0 && narrow) {
        rc = pt_scan_selected(root, narrow, repo, &a);
        if (rc == 0 && lint_examined_print(a.files, 0) < 0)
            rc = 2;
    }
    for (size_t i = 0; rc == 0 && !narrow && i < (size_t)PT_NROOTS; i++)
        rc = walk_src_root("check-pthread-create", k_pt_roots[i], 0, scan_lg, &a);
    if (rc == 0)
        rc = bln_diff_report(stderr, "check-pthread-create", base_path, &base, &found);
    if (rc == 0)
        fputs("  OK: every raw pthread_create site is pinned in "
              "tools/lint/pthread_create_baseline.txt (shrink-only)\n", stdout);
    drop3(&hit, &excl, &prev);
    return rc;
}

int check_pthread_create_run(int argc, char **argv)
{
    struct lint_changed changed;
    if (lint_changed_bind(&argc, &argv, &changed) != 0)
        return 2;
    const struct lint_changed *narrow = pt_narrow_ok(&changed) ? &changed : NULL;
    int rc = 0;
    if (!narrow) {
        int nfiles = 0;
        rc = walk_count_roots("check-pthread-create", k_pt_roots,
                              (size_t)PT_NROOTS, 0,
                              &nfiles);
        if (rc == 0)
            rc = gate_require_scanned(nfiles, PT_SCAN_FLOOR, "check-pthread-create",
                                      "scanned far fewer .c files than expected "
                                      "under the production roots");
    }
    if (rc == 0)
        rc = pt_scan_report(".", k_pt_baseline, narrow);
    lint_changed_free(&changed);
    return rc;
}

static int pt_st_case(const char *root, const char *path, const char *body,
                      const char *baseline, int want_rc)
{
    char full[4096], base[4096];
    if (ovf(snprintf(base, sizeof base, "%s/baseline.txt", root), sizeof base) ||
        csr_write(base, baseline))
        return 1;
    if (body && (ovf(snprintf(full, sizeof full, "%s/%s", root, path),
                            sizeof full) || csr_write(full, body)))
        return 1;
    char *paths[] = { (char *)path };
    struct lint_changed one = { paths, 1, 1 };
    int rc = pt_scan_report(root, base, &one);
    if (rc != want_rc)
        fprintf(stderr, "pthread narrowed case failed: %s rc=%d want=%d\n",
                path, rc, want_rc);
    return rc != want_rc;
}

static int pt_st_narrow(void)
{
    static const char bad_src[] =
        "int f(void) { pthread_crea" "te(&t, 0, f, 0); return 0; }\n";
    static const char clean_src[] = "int f(void) { return 0; }\n";
    static const struct {
        const char *path, *body, *baseline;
        int want;
    } cases[] = {
        { "docs/README.md", NULL, "", 0 },
        { "engine/x/bad.c", bad_src, "", 2 },
        { "engine/x/bad.c", bad_src, "engine/x/bad.c:pthread_create\n", 0 },
        { "engine/x/bad.c", clean_src, "engine/x/bad.c:pthread_create\n", 2 },
        { "gone.c", NULL, "gone.c:pthread_create\n", 2 },
        { "platform/modules/util/src/thread_registry.c", bad_src, "", 0 },
        { "engine/x/bad.h", bad_src, "", 0 },
        { "engine/missing.c", NULL, "", 0 },
    };
    char root[4096];
    if (lint_mkdtemp(root, sizeof root, "pt-narrow") != 0)
        return 1;
    int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        bad |= pt_st_case(root, cases[i].path, cases[i].body,
                          cases[i].baseline, cases[i].want);
    char *baseline_path[] = { (char *)k_pt_baseline };
    struct lint_changed baseline = { baseline_path, 1, 1 };
    struct lint_changed empty = { NULL, 0, 1 };
    bad |= pt_narrow_ok(&baseline) || !pt_narrow_ok(&empty);
    bad |= rap_rm_rf(root);
    return bad;
}

int check_pthread_create_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = pt_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    const char *t = "check_pthread_create";
    int bad = lg_want(t, &hit, &excl, &prev, NULL,
                      "    pthread_crea" "te(&t, 0, f, 0);", 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    thread_registry_spawn(...)", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    pthread_crea" "te(&t, 0, f, 0); // raw-pthread-ok: x", 0)
            | lg_want(t, &hit, &excl, &prev, "// raw-pthread-ok: startup",
                      "pthread_crea" "te(", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "my_pthread_create_wrapper(", 0);
    bad |= require_scan_root("check-pthread-create", "lib") == 0;
    bad |= pt_st_narrow();
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_pthread_create selftest: OK\n");
}

static const struct pt_pair_pats k_ser_pats = {
    { "return -1;", "", "", "" },
    { "LOG_ERR|LOG_FAIL|LOG_RETURN|log_json",
      "|(//|/\\*) raw-return-ok:[A-Za-z][A-Za-z0-9_-]+", "", "" },
    { "LOG_ERR|LOG_FAIL|LOG_RETURN|", "log_json.*error", "", "" }
};

static int ser_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    return pt_pair_comp(hit, excl, prev, &k_ser_pats);
}

int check_silent_error_returns_run(int argc, char **argv)
{
    if (argc < 4)
        return die("usage: check_silent_error_returns.sh <scan-dir> <fail-label> <ok-label> <fix-hint>\n",
                   "");
    regex_t hit, excl, prev;
    int cr = ser_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    struct lg_acc a = {
        .hit = &hit, .excl = &excl, .prev = &prev,
        .skip_sub = NULL, .skip_eq = NULL, .hits = 0
    };
    int rc = walk_src(argv[0], 0, scan_lg, &a);
    if (rc == 0 && a.hits) {
        printf("FAIL: silent error returns found in %s (%s)\n", argv[1], argv[3]);
        rc = 1;
    } else if (rc == 0) {
        printf("  OK: all %s error returns logged\n", argv[2]);
    }
    drop3(&hit, &excl, &prev);
    return rc;
}

int check_silent_error_returns_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = ser_comp(&hit, &excl, &prev);
    if (cr)
        return cr;
    const char *t = "check_silent_error_returns";
    int bad = lg_want(t, &hit, &excl, &prev, NULL, "    return -1;", 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    LOG_ERR(\"x\"); return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, "    LOG_FAIL(\"bad\");",
                      "    return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    return -1; // raw-return-ok:reason_1", 0)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    return -1; // raw-return-ok:", 1)
            | lg_want(t, &hit, &excl, &prev, "    log_json(\"error\", ...)",
                      "    return -1;", 0)
            | lg_want(t, &hit, &excl, &prev, "    log_json(\"info\", ...)",
                      "    return -1;", 1);
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_silent_error_returns selftest: OK\n");
}

static const struct pt_pair_pats k_va_pats = {
    { ",[[:space:]]*##", "[[:space:]]*", "__VA", "_ARGS__" },
    { "gnu-va-args-ok", "", "", "" },
    { "gnu-va-args-ok", "", "", "" }
};

static int va_comp(regex_t *hit, regex_t *excl, regex_t *prev)
{
    return pt_pair_comp(hit, excl, prev, &k_va_pats);
}

static const char k_va_baseline[] = "tools/lint/gnu_va_args_baseline.txt";

/* Production C roots — this gate used to walk two engine/platform
 * sub-directories plus four dead tokens (app config lib domain src) and
 * missed engine/{composition,controllers,entry,models,services,supervisors,
 * conditions,jobs,modules,...} and most of contexts/cognition/platform
 * entirely. Re-rooted onto the full production tree. */
static const char *const k_va_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

/* Measured 2026-09-06 under the production roots (.c+.h): 4337 files. */
enum { VA_SCAN_FLOOR = 4000 };

int check_no_gnu_va_args_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    int nfiles = 0;
    int rc = walk_count_roots("check-no-gnu-va-args", k_va_roots,
                              sizeof k_va_roots / sizeof k_va_roots[0], 1,
                              &nfiles);
    if (rc == 0)
        rc = gate_require_scanned(nfiles, VA_SCAN_FLOOR, "check-no-gnu-va-args",
                                  "scanned far fewer .c/.h files than expected "
                                  "under the production roots");
    if (rc) return rc;
    regex_t hit, excl, prev;
    int cr = va_comp(&hit, &excl, &prev);
    if (cr) return cr;
    struct bln_set base = {0}, found = {0};
    rc = bln_load(&base, k_va_baseline);
    if (rc) {
        drop3(&hit, &excl, &prev);
        return rc;
    }
    struct lg_acc a = {
        .hit = &hit, .excl = &excl, .prev = &prev, .hits = 0,
        .sym = "gnu-va-args", .found = &found
    };
    for (size_t i = 0; rc == 0 && i < sizeof k_va_roots / sizeof k_va_roots[0]; i++)
        rc = walk_src_root("check-no-gnu-va-args", k_va_roots[i], 1, scan_lg, &a);
    if (rc == 0)
        rc = bln_diff_report(stderr, "check-no-gnu-va-args", k_va_baseline, &base, &found);
    if (rc == 0)
        fputs("  OK: every GNU comma-swallowing __VA_ARGS__ site is pinned in "
              "tools/lint/gnu_va_args_baseline.txt (shrink-only)\n", stdout);
    drop3(&hit, &excl, &prev);
    return rc;
}

int check_no_gnu_va_args_selftest(void)
{
    regex_t hit, excl, prev;
    int cr = va_comp(&hit, &excl, &prev);
    if (cr) return cr;
    const char *t = "check_no_gnu_va_args";
    char h[72], m[88];
    if (snprintf(h, sizeof h, "    fprintf(stderr, fmt, ##%s", "__VA_ARGS__);")
            >= (int)sizeof h
        || snprintf(m, sizeof m, "%s // gnu-va-args-ok: legacy", h) >= (int)sizeof m) {
        drop3(&hit, &excl, &prev);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = lg_want(t, &hit, &excl, &prev, NULL, h, 1)
            | lg_want(t, &hit, &excl, &prev, NULL,
                      "    LOG_ERR(fmt __VA_OPT__(,) __VA_ARGS__);", 0)
            | lg_want(t, &hit, &excl, &prev, NULL, m, 0)
            | lg_want(t, &hit, &excl, &prev, "// gnu-va-args-ok: legacy", h, 0)
            | lg_want(t, &hit, &excl, &prev, NULL, "    x = a ## b;", 0);
    bad |= require_scan_root("check-no-gnu-va-args", "domain") == 0;
    drop3(&hit, &excl, &prev);
    return st_ok(bad, "check_no_gnu_va_args selftest: OK\n");
}

