/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-supervisor-domain
 * Second file of the check-supervisor-domain family (the 700-line family
 * ceiling split): the boot background-worker lock-in half of the gate, and
 * the gate's --selftest probes. The domain-registration scan, the coverage
 * check, and the port's parity notes live in gate_supervisor_domain.c.
 */

/* ── the boot-worker lock-in ─────────────────────────────────────────────
 * Byte-parity port of the second half of tools/lint/
 * check_supervisor_domain.sh: any spawn — a raw pthread_create /
 * thread_registry_spawn, OR a call to the shared boot_start_thread_service(
 * wrapper — in a scanned worker file must be paired with a
 * supervisor_register_in_domain( / boot_register_worker_supervisor( call in
 * the same file, or the file must appear in
 * tools/scripts/supervisor_baseline.txt.
 *
 * - ZCL_SUPERVISOR_WORKER_FILES (default the two boot worker TUs) is
 *   IFS-split AND glob-expanded like the unquoted `for f in $WORKER_FILES`
 *   (glob(3) GLOB_NOCHECK, bash's default no-nullglob/no-failglob; an
 *   expansion error leaves the word literal, as bash does).
 * - `[ -f ]` is stat+S_ISREG. The spawn and registration probes are ERE
 *   matchers with [[:space:]] for grep's \s; a grep open failure reproduces
 *   grep's "grep: <f>: <strerror>" diagnostic, and the shell's funnels are
 *   kept exactly: the spawn probe's `! grep -q` skips the file on ANY
 *   nonzero grep exit (no-match and error alike), while the registration
 *   probe and the baseline grandfather fail closed toward "violation".
 *
 * Baseline: NOT a lint_base_load / lint_base_load_set client. The shell's
 * grandfather test is `grep -qxF "$f" tools/scripts/supervisor_baseline.txt`
 * — exact FULL-LINE byte equality, with NO `#` comment stripping and NO
 * whitespace trimming, and a missing file simply never matches.
 * lint_base_load_set would wrongly comment-strip and trim (a baseline line
 * "path  # note" or "path " matches under the set helper but not under
 * grep -qxF), and lint_base_load's key:M ratchet is a different contract.
 * sdw_in_baseline keeps the shell's true exact-line semantics.
 *
 * ── --selftest ────────────────────────────────────────────────────────────
 * The shell gate's --selftest proves the COVERAGE check (three answers, not
 * two): a full scan clears its independent expectation (exit 0), a scan
 * short one declared root is UNPROVEN (exit 2), and an allowance above the
 * true shortfall is a stale-ratchet (exit 1). Each cov_case re-invokes the
 * gate for real with env assignments; here that is setenv + cic_invoke, with
 * the four relevant ZCL_* vars snapshotted at entry and restored before
 * each case, so every inner run sees exactly what `env VAR=VAL... "$self"`
 * would have seen, including operator-set leftovers the case doesn't
 * override. The inner run's merged output is discarded (>/dev/null 2>&1);
 * only its exit code is graded.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <glob.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* IFS-split helper shared with gate_supervisor_domain.c. */
int sd_split_words(const char *s, char *buf, size_t cap,
                   const char **vec, int max, int *out_n);

static const char k_sdw_name[] = "check_supervisor_domain";
static const char k_sdw_gate[] = "check-supervisor-domain";
static const char k_sdw_default[] =
    "engine/composition/src/boot_background_workers.c "
    "engine/composition/src/boot_snapshot_offer.c";
static const char k_sdw_baseline[] = "tools/scripts/supervisor_baseline.txt";

enum { SDW_NFILES = 512, SDW_SINK = 65536 };
static char g_sdw_files[SDW_NFILES][4096];
static int g_sdw_nfiles;

/* grep -qE over one file. Returns 1 match, 0 clean no-match, 2 on an open
 * failure — with grep's own diagnostic reproduced. The shell funnels:
 * `if ! grep -qE <spawn>; then continue` skips the file on ANY nonzero
 * grep exit (no-match AND error alike), while `if grep -qE <register>`
 * and the baseline `grep -qxF` skip only on a clean match — an error
 * there fails closed toward "violation". */
static int sdw_probe(const char *path, const regex_t *re)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = regexec(re, line, 0, NULL, 0) == 0;
    free(line);
    fclose(f);
    return found;
}

/* grep -qxF "$f" "$BASELINE": exact full-line byte equality, no comment
 * stripping, no trimming; a missing baseline never matches. */
static int sdw_in_baseline(const char *f)
{
    struct stat st;
    if (stat(k_sdw_baseline, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *fp = fopen(k_sdw_baseline, "r");
    if (!fp) {
        fprintf(stderr, "grep: %s: %s\n", k_sdw_baseline, strerror(errno));
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&line, &cap, fp)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        found = strcmp(line, f) == 0;
    }
    free(line);
    fclose(fp);
    return found;
}

static int sdw_add(const char *path)
{
    if (g_sdw_nfiles >= SDW_NFILES
        || ovf(snprintf(g_sdw_files[g_sdw_nfiles], 4096, "%s", path), 4096))
        return die("z23-lint: scan-set overflow\n", "");
    g_sdw_nfiles++;
    return 0;
}

/* `for f in $WORKER_FILES` — IFS split, then pathname expansion per word
 * (GLOB_NOCHECK = bash's default: an unmatched pattern stays literal; an
 * expansion error also leaves the word in place). */
static int sdw_expand(void)
{
    const char *spec = env_or("ZCL_SUPERVISOR_WORKER_FILES", k_sdw_default);
    static char buf[8192];
    const char *words[SDW_NFILES];
    int nw = 0;
    int rc = sd_split_words(spec, buf, sizeof buf, words, SDW_NFILES, &nw);
    g_sdw_nfiles = 0;
    for (int i = 0; rc == 0 && i < nw; i++) {
        glob_t g;
        int gr = glob(words[i], GLOB_NOCHECK, NULL, &g);
        if (gr == GLOB_NOSPACE)
            rc = die("z23-lint: out of memory\n", "");
        for (size_t k = 0; rc == 0 && gr == 0 && k < g.gl_pathc; k++)
            rc = sdw_add(g.gl_pathv[k]);
        if (rc == 0 && gr != 0 && gr != GLOB_NOSPACE)
            rc = sdw_add(words[i]);
        if (gr == 0)
            globfree(&g);
    }
    return rc;
}

static int sdw_comp(regex_t *spawn, regex_t *reg)
{
    int cr = compile_pat(spawn, REG_EXTENDED, "pthread_crea",
                         "te[[:space:]]*\\(|thread_registry_spawn",
                         "|boot_start_thread_service[[:space:]]*\\(", "");
    if (cr)
        return cr;
    cr = compile_pat(reg, REG_EXTENDED,
                     "supervisor_register_in_domain[[:space:]]*\\(",
                     "|boot_register_worker_supervisor[[:space:]]*\\(",
                     "", "");
    if (cr)
        regfree(spawn);
    return cr;
}

int supervisor_domain_workers_run(const char *mode)
{
    int rc = sdw_expand();
    if (rc)
        return rc;
    regex_t spawn, reg;
    rc = sdw_comp(&spawn, &reg);
    int bad[SDW_NFILES];
    int nbad = 0;
    for (int i = 0; rc == 0 && i < g_sdw_nfiles; i++) {
        const char *f = g_sdw_files[i];
        struct stat st;
        if (stat(f, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (sdw_probe(f, &spawn) != 1)
            continue;
        if (sdw_probe(f, &reg) == 1)
            continue;
        if (sdw_in_baseline(f))
            continue;
        bad[nbad++] = i;
    }
    drop2(&spawn, &reg);
    if (rc)
        return rc;
    if (nbad > 0) {
        for (int i = 0; i < nbad; i++)
            printf("%s\n", g_sdw_files[bad[i]]);
        printf("[%s] %d background worker file(s) spawn threads without "
               "supervisor_register_in_domain (mode: %s)\n", k_sdw_name,
               nbad, mode);
        fputs("  Fix: in each boot_start_*_service, init a static "
              "liveness_contract\n  and call "
              "supervisor_register_in_domain(g_op_sup|g_chain_sup, &c).\n"
              "  See engine/services/src/disk_monitor.c "
              "(dm_register_supervisor).\n", stdout);
        if (strcmp(mode, "FAIL") == 0)
            return 1;
    }
    return 0;
}

/* ── selftest: the three cov_case coverage probes ──────────────────────── */

struct sdw_snap { char val[4096]; int set; };
static struct sdw_snap g_sdw_snap[4];
static const char *const k_sdw_vars[] = {
    "ZCL_LINT_PRODUCTION_SCAN", "ZCL_SUPDOM_COVERAGE_ONLY",
    "ZCL_SUPDOM_SCAN_ROOTS", "ZCL_SUPDOM_COVERAGE_ALLOWANCE",
};

static int sdw_snap_save(void)
{
    for (int i = 0; i < 4; i++) {
        const char *e = getenv(k_sdw_vars[i]);
        g_sdw_snap[i].set = e != NULL;
        if (e && ovf(snprintf(g_sdw_snap[i].val, sizeof g_sdw_snap[i].val,
                              "%s", e), sizeof g_sdw_snap[i].val))
            return 2;
    }
    return 0;
}

static int sdw_snap_restore(void)
{
    for (int i = 0; i < 4; i++) {
        int rc = g_sdw_snap[i].set
            ? setenv(k_sdw_vars[i], g_sdw_snap[i].val, 1)
            : unsetenv(k_sdw_vars[i]);
        if (rc != 0)
            return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

static int sdw_apply(const char *const *assigns)
{
    for (; *assigns; assigns++) {
        char buf[4096];
        if (ovf(snprintf(buf, sizeof buf, "%s", *assigns), sizeof buf))
            return 2;
        char *eq = strchr(buf, '=');
        if (!eq)
            return die("z23-lint: setenv failed\n", "");
        *eq = '\0';
        if (setenv(buf, eq + 1, 1) != 0)
            return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

/* cov_case: restore the entry snapshot, apply this case's assignments, run
 * the gate for real, grade only the exit code. */
static int sdw_cov_case(int want, const char *msg, const char *const *assigns)
{
    int rc = sdw_snap_restore();
    if (rc == 0)
        rc = sdw_apply(assigns);
    if (rc)
        return rc;
    static char sink[SDW_SINK];
    int code = 0;
    rc = cic_invoke(k_sdw_gate, 1, sink, sizeof sink, &code);
    if (rc)
        return rc;
    if (code != want) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s (wanted exit %d, got %d)\n",
                k_sdw_name, msg, want, code);
        return 2;
    }
    return 0;
}

int check_supervisor_domain_selftest(void)
{
    static const char *const case1[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_SUPDOM_COVERAGE_ONLY=1", NULL
    };
    static const char *const case2[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_SUPDOM_COVERAGE_ONLY=1",
        "ZCL_SUPDOM_SCAN_ROOTS=app lib", NULL
    };
    static const char *const case3[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_SUPDOM_COVERAGE_ONLY=1",
        "ZCL_SUPDOM_COVERAGE_ALLOWANCE=1", NULL
    };
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = sdw_snap_save();
    if (rc == 0)
        rc = sdw_cov_case(0, "the complete scan did not pass its coverage "
                             "expectation", case1);
    if (rc == 0)
        rc = sdw_cov_case(2, "a scan missing a whole declared root was not "
                             "UNPROVEN", case2);
    if (rc == 0)
        rc = sdw_cov_case(1, "an allowance above the true shortfall was "
                             "silently tolerated", case3);
    if (rc == 0)
        fputs("[check_supervisor_domain] SELFTEST PASS (a full scan passes "
              "coverage, a scan short one declared root is UNPROVEN exit 2, "
              "and an allowance above the true shortfall is a stale-ratchet "
              "exit 1)\n", stdout);
    return rc;
}
