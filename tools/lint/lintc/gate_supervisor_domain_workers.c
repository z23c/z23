/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-supervisor-domain
 * Second file of the check-supervisor-domain family (the 700-line family
 * ceiling split): the boot background-worker lock-in half of the gate, and
 * the gate's --selftest probes. The find mirror, the coverage check, and
 * the port's parity notes live in gate_supervisor_domain.c; the native
 * main scan lives in gate_supervisor_domain_scan.c.
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
 *   matchers with [[:space:]] standing in for grep's whitespace escape; an
 *   open failure reproduces grep's "grep: <f>: <strerror>" diagnostic, and
 *   the shell's funnels are
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
 * only its exit code is graded. A fourth, native-only block then probes the
 * index reader's extension walk (sdw_ext_probes: a synthetic 'link'
 * extension is refused and named, a 'TREE' extension changes nothing), so
 * the SELFTEST PASS line carries one more clause than the shell original's
 * — a deliberate, verifier-directed divergence.
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

/* ── index-reader probes: mandatory vs optional extensions ──────────────
 * Library-level, but this gate is the reader's consumer that surfaces a
 * refusal, so the verifier-ruled probes live in its --selftest: a
 * synthetic one-entry index carrying a mandatory 'link' extension must be
 * refused and named; the same index carrying an optional 'TREE' extension
 * must enumerate byte-identically to no extension at all. The synthetics
 * are built from scratch — DIRC v2 header, one zeroed-stat entry named
 * t.c, a 4-byte extension payload, a 20-byte trailer (the reader's
 * trailer check is structural, not cryptographic). */

enum { SDW_IDXCAP = 128 };

/* DIRC v2, one entry "t.c" (zeroed stat + object id, namelen 3, stage 0,
 * the 72-byte padded entry), then the optional extension record (4-byte
 * signature, big-endian size, 4 zero payload bytes), then the zeroed
 * 20-byte trailer. Returns the byte count. */
static size_t sdw_idx_build(unsigned char *buf, const char *sig)
{
    memset(buf, 0, SDW_IDXCAP);
    memcpy(buf, "DIRC", 4);
    buf[7] = 2;                     /* version 2 */
    buf[11] = 1;                    /* one entry */
    buf[12 + 61] = 3;               /* entry flags: namelen of "t.c" */
    memcpy(buf + 12 + 62, "t.c", 3);
    size_t n = 12 + 72;
    if (sig) {
        memcpy(buf + n, sig, 4);
        buf[n + 7] = 4;             /* payload size */
        n += 12;
    }
    return n + 20;
}

struct sdw_idxacc { char *list; size_t cap, used; };

static int sdw_idxacc_add(const char *path, int stage, void *ctx)
{
    (void)stage;
    struct sdw_idxacc *a = ctx;
    int k = snprintf(a->list + a->used, a->cap - a->used, "%s\n", path);
    if (k < 0 || a->used + (size_t)k + 1 > a->cap)
        return die("z23-lint: derived buffer overflow\n", "");
    a->used += (size_t)k;
    return 0;
}

/* GIT_INDEX_FILE snapshot around the probes (the operator may have it
 * set; the four-var selftest snapshot does not cover it). */
static char g_sdw_gif[4096];
static int g_sdw_gif_had;

static int sdw_gif_save(void)
{
    const char *e = getenv("GIT_INDEX_FILE");
    g_sdw_gif_had = e != NULL;
    if (e && ovf(snprintf(g_sdw_gif, sizeof g_sdw_gif, "%s", e),
                 sizeof g_sdw_gif))
        return 2;
    return 0;
}

static int sdw_gif_restore(void)
{
    int rc = g_sdw_gif_had ? setenv("GIT_INDEX_FILE", g_sdw_gif, 1)
                           : unsetenv("GIT_INDEX_FILE");
    return rc ? die("z23-lint: setenv failed\n", "") : 0;
}

/* Build the synthetic index (sig = the extension to append, or NULL),
 * point GIT_INDEX_FILE at it, and enumerate it into list. Returns the
 * reader's rc; badext receives a refused mandatory extension's name. */
static int sdw_ext_probe_one(const char *sig, char *list, size_t cap,
                             char *badext)
{
    unsigned char buf[SDW_IDXCAP];
    size_t n = sdw_idx_build(buf, sig);
    char path[64];
    memcpy(path, "test-tmp/sd_idxext_XXXXXX", 26);
    int fd = mkstemp(path);
    if (fd < 0)
        return die("z23-lint: mktemp failed\n", "");
    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(path);
        return die("z23-lint: write failed\n", "");
    }
    int bad = fwrite(buf, 1, n, f) != n;
    if (fclose(f) != 0)
        bad = 1;
    struct sdw_idxacc a = { .list = list, .cap = cap, .used = 0 };
    int rc = 2;
    if (!bad && setenv("GIT_INDEX_FILE", path, 1) == 0) {
        list[0] = '\0';
        rc = lint_git_index_foreach(sdw_idxacc_add, &a, badext);
    }
    if (unlink(path) != 0)
        return die("z23-lint: unlink failed: %s\n", path);
    return bad ? die("z23-lint: write failed\n", "") : rc;
}

/* Baseline: the bare synthetic enumerates exactly its one entry. */
static int sdw_ext_base(char *list0)
{
    char badext[5] = "";
    int rc = sdw_ext_probe_one(NULL, list0, 256, badext);
    if (rc == 0 && (badext[0] || strcmp(list0, "t.c\n") != 0))
        rc = 2;
    return rc;
}

/* A mandatory 'link' extension: refused, and the refusal names it. */
static int sdw_ext_link(void)
{
    char list[256], badext[5] = "";
    int rc = sdw_ext_probe_one("link", list, sizeof list, badext);
    return rc == 2 && strcmp(badext, "link") == 0 ? 0 : 2;
}

/* An optional 'TREE' extension: the entry list is byte-identical. */
static int sdw_ext_tree(const char *list0)
{
    char list[256], badext[5] = "";
    int rc = sdw_ext_probe_one("TREE", list, sizeof list, badext);
    if (rc == 0 && (badext[0] || strcmp(list, list0) != 0))
        rc = 2;
    return rc;
}

static int sdw_ext_probes(void)
{
    int rc = csr_mkdirs("test-tmp");
    if (rc == 0)
        rc = sdw_gif_save();
    char list0[256];
    if (rc == 0)
        rc = sdw_ext_base(list0);
    if (rc == 0)
        rc = sdw_ext_link();
    if (rc == 0)
        rc = sdw_ext_tree(list0);
    int rr = sdw_gif_restore();
    if (rc == 0)
        rc = rr;
    if (rc)
        fprintf(stderr, "%s: SELFTEST FAILED — the native index reader's "
                "extension handling is wrong\n", k_sdw_name);
    return rc;
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
        rc = sdw_ext_probes();
    if (rc == 0)
        fputs("[check_supervisor_domain] SELFTEST PASS (a full scan passes "
              "coverage, a scan short one declared root is UNPROVEN exit 2, "
              "an allowance above the true shortfall is a stale-ratchet "
              "exit 1, and a mandatory index extension is refused while an "
              "optional one changes nothing)\n", stdout);
    return rc;
}
