/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-capability-inventory-generated — prove the capability
 * inventory is complete, internally consistent output of the C23 source
 * scanner. Ported from tools/lint/check_capability_inventory_generated.sh
 * (deleted). With no argument the gate runs the generator binary at
 * <ZCL_LINT_BIN_DIR or build/bin>/gen_capability_inventory (run_lint.sh
 * exports ZCL_LINT_BIN_DIR from --bin-dir; make lint builds it first); an
 * explicit path may be given as argv[0]. Its absence is a FATAL, exit 2,
 * exactly as in the script. The gate runs that binary to produce
 * build/gen/CAPABILITY_INVENTORY.jsonl, then verifies: the census floor
 * (>=1000 capabilities, >=500 registered roots), the public-header census
 * against the tracked headers (git ls-files, compared as unique sorted
 * sets), every summary count against the rows actually emitted, and the
 * generated-artifact header claims. There is no stored copy to diff
 * against: the report is evidence, never authored prose. Exit 0 = pass,
 * 1 = violation, 2 = usage/internal error. Fail closed: an unreadable file
 * is an error, never a skip. Relative paths are resolved by chdir to the
 * repository root (cic_repo_root), as the script's cd "$ROOT" did.
 * Selftest: gate_capability_inventory_generated_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

extern char **environ;

static const char k_cig_gate[] = "check_capability_inventory_generated";
static const char k_cig_doc[] = "build/gen/CAPABILITY_INVENTORY.jsonl";
static const char k_cig_catalog[] = "tools/dev/test_group_catalog.def";

static const char *const k_cig_claims[] = {
    "\"generated_artifact_schema\":\"zcl.generated_artifact.v1\"",
    "\"artifact_id\":\"zcl.code_capability_inventory.v1\"",
    "\"generated_by\":\"tools/gen_capability_inventory.c\"",
    "\"regenerate\":\"make docs-capability-inventory\"",
    "\"artifact_id\":\"zcl.arm_symbol_single_baseline.v1\"",
};

static const char *const k_cig_records[] = {
    "capability", "duplicate", "untested_invariant",
    "test_root_gap", "multi_arm_symbol", "definition_arm",
};
enum { CIG_NREC = 6 };

enum { CIG_PATH = 1024, CIG_LINE = 16384, CIG_HDR = 512,
       CIG_NHDR = 4096, CIG_DIFF_MAX = 60 };

static char g_cig_trk[CIG_NHDR][CIG_HDR];
static char g_cig_rep[CIG_NHDR][CIG_HDR];
static size_t g_cig_ntrk, g_cig_nrep;

/* ---------------------------------------------------------------- spawn */

/* Runs argv[0] with posix_spawnp, stdout to out_path and stderr to err_path.
 * *code receives the exit status (or 128+signal). 0 ok, -1 internal. */
static int cig_spawn(char **argv, const char *out_path, const char *err_path,
                     int *code)
{
    int od = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int ed = open(err_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (od < 0 || ed < 0) {
        if (od >= 0) close(od);
        if (ed >= 0) close(ed);
        return -1;
    }
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(od); close(ed);
        return -1;
    }
    posix_spawn_file_actions_adddup2(&fa, od, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, ed, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fa, od);
    posix_spawn_file_actions_addclose(&fa, ed);
    pid_t pid;
    int rc = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(od); close(ed);
    if (rc != 0)
        return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    if (WIFEXITED(st))
        *code = WEXITSTATUS(st);
    else if (WIFSIGNALED(st))
        *code = 128 + WTERMSIG(st);
    else
        *code = 128;
    return 0;
}

static void cig_dump_indented(FILE *err, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[CIG_LINE];
    while (fgets(line, sizeof line, f))
        fprintf(err, "    %s", line);
    fclose(f);
}

/* ---------------------------------------------------------------- scratch */

/* mkdtemp scratch under $HOME/.local/state/zclassic23/scratch (never /tmp). */
static int cig_scratch_mk(char *out, size_t cap, const char *tag)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place gate scratch\n", "");
    char base[CIG_PATH];
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/%s.XXXXXX", base, tag), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for gate scratch\n", "");
    return 0;
}

/* Default generator binary: <ZCL_LINT_BIN_DIR or build/bin>/gen_... */
int cig_default_gen(char *out, size_t cap)
{
    const char *dir = env_or("ZCL_LINT_BIN_DIR", "build/bin");
    if (ovf(snprintf(out, cap, "%s/gen_capability_inventory", dir), cap))
        return 2;
    return 0;
}

/* The gate works on repo-relative paths; chdir to the root as the script's
 * cd "$ROOT" did. */
static int cig_chdir_root(void)
{
    char root[CIG_PATH];
    if (cic_repo_root(root, sizeof root) != 0)
        return die("z23-lint: cannot locate repository root\n", "");
    if (chdir(root) != 0)
        return die("z23-lint: cannot chdir to repository root\n", "");
    return 0;
}

/* ---------------------------------------------------------------- pipeline */

/* Runs the generator binary at gen to produce the report at
 * build/gen/CAPABILITY_INVENTORY.jsonl. scratch_out receives the scratch dir
 * (caller removes it); doc_out the report path. 0 ok, 2 internal (message
 * already on err). */
int cig_pipeline(const char *gen, char *scratch_out, size_t scap,
                 char *doc_out, size_t dcap, FILE *err)
{
    if (!gen)
        return die("z23-lint: generator path missing\n", "");
    if (access(gen, X_OK) != 0) {
        fprintf(err, "%s: FATAL — generator absent: %s\n", k_cig_gate, gen);
        return 2;
    }
    int rc = cig_scratch_mk(scratch_out, scap, "cap-inventory");
    if (rc)
        return rc;
    char genlog[CIG_PATH];
    if (ovf(snprintf(genlog, sizeof genlog, "%s/gen.log", scratch_out),
            sizeof genlog))
        return 2;
    if (csr_mkdirs("build/gen"))
        return 2;
    char *gargv[4] = { (char *)gen, (char *)k_cig_doc, (char *)".", NULL };
    int code = 0;
    if (cig_spawn(gargv, "/dev/null", genlog, &code) != 0 || code != 0) {
        fprintf(err, "%s: FATAL — derivation failed\n", k_cig_gate);
        cig_dump_indented(err, genlog);
        return 2;
    }
    if (ovf(snprintf(doc_out, dcap, "%s", k_cig_doc), dcap))
        return 2;
    return 0;
}

/* ---------------------------------------------------------------- sets */

static int cig_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Sorts v then drops adjacent duplicates, sort -u style, so the header
 * census compares sets, not multisets. */
static void cig_sort_uniq(char v[][CIG_HDR], size_t *n)
{
    qsort(v, *n, CIG_HDR, cig_cmp);
    size_t w = 0;
    for (size_t i = 0; i < *n; i++) {
        size_t len = strlen(v[i]);
        if (w == 0 || strcmp(v[w - 1], v[i]) != 0) {
            memcpy(v[w], v[i], len + 1);
            w++;
        }
    }
    *n = w;
}

static int cig_set_add(char v[][CIG_HDR], size_t *n, const char *name)
{
    if (*n >= CIG_NHDR)
        return die("z23-lint: header census exceeds %d entries\n",
                   k_cig_gate);
    size_t len = strlen(name);
    if (len >= CIG_HDR)
        return die("z23-lint: header path too long: %s\n", name);
    memcpy(v[*n], name, len + 1);
    (*n)++;
    return 0;
}

/* git ls-files core engine contexts cognition platform — headers only. */
static int cig_tracked_load(const char *lsfile)
{
    static const char *const pfx[] = { "core/", "engine/", "contexts/",
                                       "cognition/", "platform/" };
    FILE *f = fopen(lsfile, "r");
    if (!f)
        return die("z23-lint: cannot read git ls-files output\n", lsfile);
    char line[CIG_LINE];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        if (n < 3 || strcmp(line + n - 2, ".h") != 0)
            continue;
        if (!strstr(line, "/include/"))
            continue;
        if (strncmp(line, "lib/test/", 9) == 0)
            continue;
        int hit = 0;
        for (size_t i = 0; i < sizeof pfx / sizeof pfx[0]; i++)
            if (strncmp(line, pfx[i], strlen(pfx[i])) == 0)
                hit = 1;
        if (!hit)
            continue;
        if (cig_set_add(g_cig_trk, &g_cig_ntrk, line)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    cig_sort_uniq(g_cig_trk, &g_cig_ntrk);
    return 0;
}

static int cig_tracked(FILE *err)
{
    char scratch[CIG_PATH], lsfile[CIG_PATH];
    int rc = cig_scratch_mk(scratch, sizeof scratch, "cap-inv-ls");
    if (rc)
        return rc;
    if (ovf(snprintf(lsfile, sizeof lsfile, "%s/ls", scratch), sizeof lsfile))
        return 2;
    char *argv[9] = { (char *)"git", (char *)"ls-files", (char *)"core",
                      (char *)"engine", (char *)"contexts",
                      (char *)"cognition", (char *)"platform",
                      (char *)"contexts/commons/packages", NULL };
    int code = 0;
    if (cig_spawn(argv, lsfile, "/dev/null", &code) != 0 || code != 0) {
        rap_rm_rf(scratch);
        fprintf(err, "%s: FATAL — git ls-files failed\n", k_cig_gate);
        return 2;
    }
    rc = cig_tracked_load(lsfile);
    rap_rm_rf(scratch);
    return rc;
}

/* ---------------------------------------------------------------- meta */

/* The LAST "name":<digits> in the line, as the shell's greedy
 * sed 's/.*"name":\([0-9][0-9]*\).*' read it: the meta line names some
 * fields twice (an object first, the count later). -1 when none. */
static long cig_field(const char *meta, const char *name)
{
    char pat[128];
    if (ovf(snprintf(pat, sizeof pat, "\"%s\":", name), sizeof pat))
        return -1;
    long v = -1;
    for (const char *p = strstr(meta, pat); p; p = strstr(p + 1, pat)) {
        const char *d = p + strlen(pat);
        if (*d < '0' || *d > '9')
            continue;
        v = 0;
        while (*d >= '0' && *d <= '9')
            v = v * 10 + (*d++ - '0');
    }
    return v;
}

/* Counts ZCL_TEST_GROUP/ZCL_SPEC_GROUP lines in the catalog; -1 on error. */
static int cig_catalog_regexes(regex_t *a, regex_t *b)
{
    if (regcomp(a, "^[[:space:]]*ZCL_TEST_GROUP\\([[:alnum:]_]+\\)"
                   "[[:space:]]*$", REG_EXTENDED | REG_NOSUB) != 0)
        return -1;
    if (regcomp(b, "^[[:space:]]*ZCL_SPEC_GROUP\\([[:alnum:]_]+\\)"
                   "[[:space:]]*$", REG_EXTENDED | REG_NOSUB) != 0) {
        regfree(a);
        return -1;
    }
    return 0;
}

static long cig_catalog_groups(void)
{
    regex_t a, b;
    if (cig_catalog_regexes(&a, &b) != 0)
        return -1;
    FILE *f = fopen(k_cig_catalog, "r");
    if (!f) {
        drop2(&a, &b);
        return -1;
    }
    long n = 0;
    char line[CIG_LINE];
    while (fgets(line, sizeof line, f))
        if (regexec(&a, line, 0, NULL, 0) == 0 ||
            regexec(&b, line, 0, NULL, 0) == 0)
            n++;
    fclose(f);
    drop2(&a, &b);
    return n;
}

/* ---------------------------------------------------------------- scan */

static const char *cig_cap_header(const char *line)
{
    static const char pfx[] = "{\"record\":\"capability\",\"header\":\"";
    if (strncmp(line, pfx, sizeof pfx - 1) != 0)
        return NULL;
    const char *h = line + sizeof pfx - 1;
    const char *e = strchr(h, '"');
    if (!e || (size_t)(e - h) >= CIG_HDR)
        return NULL;
    return h;
}

static int cig_record_is(const char *line, const char *rec)
{
    char pfx[96];
    if (ovf(snprintf(pfx, sizeof pfx, "{\"record\":\"%s\"", rec), sizeof pfx))
        return 0;
    return strncmp(line, pfx, strlen(pfx)) == 0;
}

static void cig_cap_store(const char *h, size_t len)
{
    if (g_cig_nrep >= CIG_NHDR)
        return;
    memcpy(g_cig_rep[g_cig_nrep], h, len);
    g_cig_rep[g_cig_nrep][len] = '\0';
    g_cig_nrep++;
}

static int cig_scan_body(FILE *f, const char *path, long *rows, FILE *err)
{
    char line[CIG_LINE];
    while (fgets(line, sizeof line, f)) {
        for (int i = 0; i < CIG_NREC; i++)
            if (cig_record_is(line, k_cig_records[i]))
                rows[i]++;
        const char *h = cig_cap_header(line);
        if (h) {
            const char *e = strchr(h, '"');
            if (!e) {
                fclose(f);
                fprintf(err, "%s: FATAL — malformed capability row: %s\n",
                        k_cig_gate, path);
                return 2;
            }
            cig_cap_store(h, (size_t)(e - h));
        }
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(err, "%s: FATAL — read error on %s\n", k_cig_gate, path);
        return 2;
    }
    fclose(f);
    return 0;
}

/* One pass over the report: first line is meta; the rest are counted and
 * capability rows feed the public-header census. */
static int cig_scan_doc(const char *path, char *meta, size_t metacap,
                        long *rows, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(err, "%s: FATAL — cannot read report: %s\n", k_cig_gate, path);
        return 2;
    }
    if (!fgets(meta, (int)metacap, f)) {
        fprintf(err, "%s: FATAL — report has no header record: %s\n",
                k_cig_gate, path);
        fclose(f);
        return 2;
    }
    size_t n = strlen(meta);
    if (n && meta[n - 1] == '\n')
        meta[n - 1] = '\0';
    int rc = cig_scan_body(f, path, rows, err);
    if (rc)
        return rc;
    if (g_cig_nrep >= CIG_NHDR) {
        fprintf(err, "%s: FATAL — report header census exceeds %d entries\n",
                k_cig_gate, CIG_NHDR);
        return 2;
    }
    cig_sort_uniq(g_cig_rep, &g_cig_nrep);
    return 0;
}

/* ---------------------------------------------------------------- verify */

/* Prints the census diff (unified-style +/-, first 60 lines). Returns 1. */
static int cig_census_fail(FILE *err)
{
    fprintf(err, "%s: FAIL — public-header census is not exact\n", k_cig_gate);
    size_t i = 0, j = 0;
    int shown = 0;
    while ((i < g_cig_ntrk || j < g_cig_nrep) && shown < CIG_DIFF_MAX) {
        int c = i < g_cig_ntrk && j < g_cig_nrep
                    ? strcmp(g_cig_trk[i], g_cig_rep[j])
                    : (i < g_cig_ntrk ? -1 : 1);
        if (c == 0) {
            i++; j++;
        } else if (c < 0) {
            fprintf(err, "    - %s\n", g_cig_trk[i]);
            i++; shown++;
        } else {
            fprintf(err, "    + %s\n", g_cig_rep[j]);
            j++; shown++;
        }
    }
    return 1;
}

/* 1 when the two sorted unique header sets are identical, else 0. */
static int cig_census_equal(void)
{
    size_t i = 0, j = 0;
    if (g_cig_ntrk != g_cig_nrep)
        return 0;
    while (i < g_cig_ntrk) {
        if (strcmp(g_cig_trk[i], g_cig_rep[j]) != 0)
            return 0;
        i++; j++;
    }
    return 1;
}

/* Summary fields, in meta order of use. */
struct cig_meta_fields {
    long capabilities, duplicates, invariants, groups;
    long roots_found, roots_missing, roots_amb, root_gaps;
    long multi, arms;
};

static void cig_meta_read(struct cig_meta_fields *m, const char *meta)
{
    m->capabilities = cig_field(meta, "capabilities");
    m->duplicates = cig_field(meta, "duplicates");
    m->invariants = cig_field(meta, "untested_invariants");
    m->groups = cig_field(meta, "registered_test_groups");
    m->roots_found = cig_field(meta, "registered_test_roots_found");
    m->roots_missing = cig_field(meta, "registered_test_roots_missing");
    m->roots_amb = cig_field(meta, "ambiguous_registered_test_roots");
    m->root_gaps = cig_field(meta, "test_root_gaps");
    m->multi = cig_field(meta, "multi_arm_symbols");
    m->arms = cig_field(meta, "definition_arms");
}

/* "missing" for an absent field, else the decimal value, like the shell's
 * ${capabilities:-missing}. */
static void cig_num(char *buf, size_t cap, long v)
{
    if (v < 0) {
        snprintf(buf, cap, "missing");
        return;
    }
    snprintf(buf, cap, "%ld", v);
}

/* Census floor: 2 and message on err when not met, else 0. */
static int cig_floor_check(const struct cig_meta_fields *m, FILE *err)
{
    if (m->capabilities < 1000 || m->roots_found < 500) {
        char cbuf[32], rbuf[32];
        cig_num(cbuf, sizeof cbuf, m->capabilities);
        cig_num(rbuf, sizeof rbuf, m->roots_found);
        fprintf(err, "%s: FATAL — census floor failed\n", k_cig_gate);
        fprintf(err, "  capabilities=%s roots_found=%s\n", cbuf, rbuf);
        return 2;
    }
    return 0;
}

/* 1 when every summary count matches the rows and the catalog, else 0. */
static int cig_account_ok(const struct cig_meta_fields *m, const long *rows,
                          long catalog)
{
    if (m->capabilities != rows[0] || m->duplicates != rows[1])
        return 0;
    if (m->invariants != rows[2] || m->groups != catalog)
        return 0;
    if (m->multi != rows[4] || m->arms != rows[5])
        return 0;
    if (m->roots_found + m->roots_missing + m->roots_amb != m->groups)
        return 0;
    if (m->root_gaps != rows[3] || rows[3] != m->roots_missing + m->roots_amb)
        return 0;
    return 1;
}

static int cig_account_fail(const struct cig_meta_fields *m, const long *rows,
                            long catalog, FILE *err)
{
    fprintf(err, "%s: FAIL — report accounting is inconsistent\n",
            k_cig_gate);
    fprintf(err, "  capabilities=%ld/%ld duplicates=%ld/%ld "
            "invariants=%ld/%ld\n", m->capabilities, rows[0], m->duplicates,
            rows[1], m->invariants, rows[2]);
    fprintf(err, "  multi_arm_symbols=%ld/%ld definition_arms=%ld/%ld\n",
            m->multi, rows[4], m->arms, rows[5]);
    fprintf(err, "  groups=%ld/%ld roots=%ld+%ld+%ld gaps=%ld/%ld\n",
            m->groups, catalog, m->roots_found, m->roots_missing, m->roots_amb,
            m->root_gaps, rows[3]);
    return 1;
}

static int cig_claims_check(const char *meta, FILE *err)
{
    for (size_t i = 0; i < sizeof k_cig_claims / sizeof k_cig_claims[0]; i++)
        if (!strstr(meta, k_cig_claims[i])) {
            fprintf(err, "%s: FAIL — generated artifact header lacks %s\n",
                    k_cig_gate, k_cig_claims[i]);
            return 1;
        }
    return 0;
}

/* Verifies a generated report file. 0 pass, 1 violation, 2 internal.
 * The OK line goes to out; FATAL/FAIL lines go to err. */
int cig_verify_file(const char *path, FILE *out, FILE *err)
{
    char meta[CIG_LINE];
    long rows[CIG_NREC] = { 0 };
    struct cig_meta_fields m;
    g_cig_ntrk = 0;
    g_cig_nrep = 0;
    int rc = cig_scan_doc(path, meta, sizeof meta, rows, err);
    if (rc)
        return rc;
    cig_meta_read(&m, meta);
    rc = cig_floor_check(&m, err);
    if (rc)
        return rc;
    if (cig_tracked(err))
        return 2;
    if (!cig_census_equal())
        return cig_census_fail(err);
    long catalog = cig_catalog_groups();
    if (catalog < 0) {
        fprintf(err, "%s: FATAL — cannot read %s\n", k_cig_gate,
                k_cig_catalog);
        return 2;
    }
    if (!cig_account_ok(&m, rows, catalog))
        return cig_account_fail(&m, rows, catalog, err);
    rc = cig_claims_check(meta, err);
    if (rc)
        return rc;
    fprintf(out, "%s: clean — %ld capabilities; %ld registered roots "
            "resolved\n", k_cig_gate, m.capabilities, m.roots_found);
    return 0;
}

int cig_selftest_with(const char *gen); /* the selftest file */

int check_capability_inventory_generated_run(int argc, char **argv)
{
    if (cig_chdir_root())
        return 2;
    if (argc >= 1 && strcmp(argv[0], "--selftest") == 0)
        return cig_selftest_with(argc >= 2 ? argv[1] : NULL);
    char gen[CIG_PATH];
    if (argc >= 1) {
        if (ovf(snprintf(gen, sizeof gen, "%s", argv[0]), sizeof gen))
            return 2;
    } else if (cig_default_gen(gen, sizeof gen)) {
        return 2;
    }
    char scratch[CIG_PATH] = "", doc[CIG_PATH];
    int rc = cig_pipeline(gen, scratch, sizeof scratch, doc, sizeof doc,
                          stderr);
    if (rc) {
        if (scratch[0] != '\0')
            rap_rm_rf(scratch);
        return rc;
    }
    rc = cig_verify_file(doc, stdout, stderr);
    if (scratch[0] != '\0')
        rap_rm_rf(scratch);
    return rc;
}
