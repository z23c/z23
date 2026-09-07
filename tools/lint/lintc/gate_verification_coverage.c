/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-verification-coverage of the C23 lint
 * runtime, the replacement for tools/lint/check_verification_coverage.sh.
 * Holds .github/verification-coverage.txt to .github/workflows/build.yml
 * both directions (every required item declared, every hosted=yes item's
 * job_key real, every real job claimed, the workflow points readers at the
 * manifest, and the hosted test job is cold and semantically verified) and
 * names the not-hosted items in its own output. The one subprocess this
 * gate spawns — tools/lint/check_hosted_suite_verdict.sh --self-test — is
 * the same input producer the original script ran, invoked through the
 * capture_cmd() seam; its stdout is replayed verbatim and its stderr flows
 * straight through the inherited descriptor, untouched. No file-scope
 * mutable data. Selftest: gate_verification_coverage_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum {
    VC_ROWS = 64, VC_FIELD = 320, VC_JOBS = 128, VC_JOBNAME = 96,
    VC_WFBUF = 262144, VC_MANBUF = 16384, VC_CAPBUF = 16384, VC_LINEBUF = 8192
};

static const char k_vc_manifest[] = ".github/verification-coverage.txt";
static const char k_vc_workflow[] = ".github/workflows/build.yml";
static const char k_vc_verifier[] = "tools/lint/check_hosted_suite_verdict.sh";
static const char k_vc_gate[] = "check-verification-coverage";
static const char *const k_vc_required[] = { "gcc", "clang", "lint", "tests",
                                             "fuzz-replay" };

struct vc_row {
    char item[64], hosted[4], job[VC_FIELD], display[VC_FIELD], attest[VC_FIELD];
};
struct vc_strset { char v[VC_JOBS][VC_JOBNAME]; int n; };

static int vc_set_has(const struct vc_strset *s, const char *name)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i], name) == 0) return 1;
    return 0;
}
static int vc_set_add(struct vc_strset *s, const char *name)
{
    if (s->n >= VC_JOBS) return die("z23-lint: verification-coverage job overflow\n", "");
    if (ovf((int)strlen(name), VC_JOBNAME)) return 2;
    memcpy(s->v[s->n], name, strlen(name) + 1);
    s->n++;
    return 0;
}

static int vc_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) return die("z23-lint: read failed: %s\n", path);
    out[n] = '\0';
    return 0;
}

static int vc_readable(const char *path)
{
    if (access(path, R_OK) == 0) return 0;
    return errno == EACCES ? -2 : -1;
}

/* ── .github/workflows/build.yml job-key extraction ──────────────────── */

static int vc_is_jobs_line(const char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    return n == 5 && strncmp(line, "jobs:", 5) == 0;
}
static int vc_ends_jobs(const char *line)
{ return line[0] != '\0' && line[0] != ' ' && line[0] != '\t' && line[0] != '#'; }

static int vc_job_key(const char *line, char *out, size_t cap)
{
    if (line[0] != ' ' || line[1] != ' ' || line[2] == ' ' || line[2] == '\t')
        return 0;
    const char *p = line + 2;
    if (!(*p >= 'a' && *p <= 'z')) return 0;
    const char *start = p;
    while (isalnum((unsigned char)*p) || *p == '_' || *p == '-') p++;
    if (*p != ':') return 0;
    const char *rest = p + 1;
    while (*rest == ' ' || *rest == '\t') rest++;
    if (*rest != '\0') return 0;
    size_t n = (size_t)(p - start);
    if (n >= cap) return 0;
    memcpy(out, start, n);
    out[n] = '\0';
    return 1;
}

static int vc_parse_jobs(const char *text, struct vc_strset *jobs)
{
    int injobs = 0;
    for (const char *p = text; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[VC_LINEBUF];
        if (n >= sizeof line) return die("z23-lint: workflow line too long\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (vc_is_jobs_line(line)) {
            injobs = 1;
        } else {
            if (injobs && vc_ends_jobs(line)) injobs = 0;
            char key[VC_JOBNAME];
            if (injobs && vc_job_key(line, key, sizeof key) && vc_set_add(jobs, key))
                return 2;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* ── manifest row parsing ─────────────────────────────────────────────── */

static int vc_append(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (ovf(k, cap - *used)) return 2;
    *used += (size_t)k;
    return 0;
}

static int vc_item_shape_ok(const char *s)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || isdigit((unsigned char)*p) || *p == '-'))
            return 0;
    return 1;
}
static int vc_job_shape_ok(const char *s)
{
    if (!*s || strcmp(s, "-") == 0) return 0;
    for (const char *p = s; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-')) return 0;
    return 1;
}
static const char *vc_trim(const char *s, char *buf, size_t cap)
{
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) n--;
    if (n >= cap) n = cap - 1;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return buf;
}

static int vc_split_fields(char *line, char *f[5])
{
    f[0] = line;
    for (int i = 0; i < 4; i++) {
        char *bar = strchr(f[i], '|');
        if (!bar) return -1;
        *bar = '\0';
        f[i + 1] = bar + 1;
    }
    return strchr(f[4], '|') ? -1 : 0;
}

static int vc_find_row(const struct vc_row *rows, int n, const char *item)
{
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].item, item) == 0) return i;
    return -1;
}

static int vc_row_hosted(const char *item, char *fields[5], struct vc_row *r,
                         struct vc_strset *claimed, int lineno, char *out,
                         size_t cap, size_t *used)
{
    (void)item;
    int rc;
    if (!vc_job_shape_ok(fields[2])) {
        rc = vc_append(out, cap, used,
                       "FAIL: %s line %d item '%s' is hosted=yes so job_key must be "
                       "a real\n      workflow job key, got '%s'\n", k_vc_manifest,
                       lineno, r->item, fields[2]);
        return rc ? rc : 1;
    }
    if (strcmp(fields[4], "-") != 0) {
        rc = vc_append(out, cap, used,
                       "FAIL: %s line %d item '%s' is hosted=yes so attested_by must "
                       "be '-'\n      (the hosted job IS the attestation), got '%s'\n",
                       k_vc_manifest, lineno, r->item, fields[4]);
        return rc ? rc : 1;
    }
    memcpy(r->job, fields[2], strlen(fields[2]) + 1);
    memcpy(r->attest, "-", 2);
    return vc_set_has(claimed, r->job) ? 0 : (vc_set_add(claimed, r->job) ? 2 : 0);
}

static int vc_row_not_hosted(struct vc_row *r, char *fields[5], int lineno,
                             char *out, size_t cap, size_t *used)
{
    int rc;
    if (strcmp(fields[2], "-") != 0) {
        rc = vc_append(out, cap, used,
                       "FAIL: %s line %d item '%s' is hosted=no so job_key must be "
                       "'-', got '%s'\n", k_vc_manifest, lineno, r->item, fields[2]);
        return rc ? rc : 1;
    }
    char trimmed[VC_FIELD];
    vc_trim(fields[4], trimmed, sizeof trimmed);
    if (trimmed[0] == '\0' || strcmp(trimmed, "-") == 0) {
        rc = vc_append(out, cap, used,
                       "FAIL: %s line %d item '%s' is hosted=no and names no "
                       "attestor.\n      An item that hosted CI does not check must "
                       "say where its verdict comes\n      from. Leaving it blank "
                       "turns an admitted gap into a silent one.\n", k_vc_manifest,
                       lineno, r->item);
        return rc ? rc : 1;
    }
    memcpy(r->job, "-", 2);
    memcpy(r->attest, fields[4], strlen(fields[4]) + 1);
    return 0;
}

static int vc_parse_line(char *line, int lineno, struct vc_row *rows, int *rn,
                         struct vc_strset *claimed, char *out, size_t cap,
                         size_t *used, int *fail)
{
    if (line[0] == '\0' || line[0] == '#') return 0;
    char *bar_scan = line;
    int seps = 0;
    for (; *bar_scan; bar_scan++) if (*bar_scan == '|') seps++;
    if (seps != 4) {
        *fail = 1;
        return vc_append(out, cap, used,
                         "FAIL: %s line %d has %d '|' separator(s), needs exactly 4\n"
                         "      expected: item|hosted|job_key|display_name|attested_by\n"
                         "      got:      %s\n", k_vc_manifest, lineno, seps, line);
    }
    char *f[5];
    vc_split_fields(line, f);
    if (!vc_item_shape_ok(f[0])) {
        *fail = 1;
        return vc_append(out, cap, used,
                         "FAIL: %s line %d item '%s' must be non-empty lowercase "
                         "[a-z0-9-]\n", k_vc_manifest, lineno, f[0]);
    }
    if (vc_find_row(rows, *rn, f[0]) >= 0) {
        *fail = 1;
        return vc_append(out, cap, used,
                         "FAIL: %s line %d declares item '%s' twice — one row per "
                         "item\n", k_vc_manifest, lineno, f[0]);
    }
    if (strcmp(f[1], "yes") != 0 && strcmp(f[1], "no") != 0) {
        *fail = 1;
        return vc_append(out, cap, used,
                         "FAIL: %s line %d hosted='%s' — must be exactly 'yes' or "
                         "'no'\n", k_vc_manifest, lineno, f[1]);
    }
    if (f[3][0] == '\0') {
        *fail = 1;
        return vc_append(out, cap, used, "FAIL: %s line %d display_name is empty\n",
                         k_vc_manifest, lineno);
    }
    if (*rn >= VC_ROWS) return die("z23-lint: verification-coverage row overflow\n", "");
    struct vc_row *r = &rows[*rn];
    memcpy(r->item, f[0], strlen(f[0]) + 1);
    memcpy(r->hosted, f[1], strlen(f[1]) + 1);
    memcpy(r->display, f[3], strlen(f[3]) + 1);
    int rc = strcmp(f[1], "yes") == 0
        ? vc_row_hosted(f[0], f, r, claimed, lineno, out, cap, used)
        : vc_row_not_hosted(r, f, lineno, out, cap, used);
    if (rc == 1) { *fail = 1; return 0; }
    if (rc) return rc;
    (*rn)++;
    return 0;
}

static int vc_parse_manifest(char *text, struct vc_row *rows, int *rn,
                             struct vc_strset *claimed, char *out, size_t cap,
                             size_t *used, int *fail)
{
    int lineno = 0;
    char *p = text;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        lineno++;
        if (vc_parse_line(p, lineno, rows, rn, claimed, out, cap, used, fail))
            return 2;
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* ── prongs 2-6 ────────────────────────────────────────────────────────── */

static int vc_prong2(const struct vc_row *rows, int rn, char *out, size_t cap,
                     size_t *used, int *fail)
{
    for (size_t i = 0; i < sizeof k_vc_required / sizeof k_vc_required[0]; i++) {
        if (vc_find_row(rows, rn, k_vc_required[i]) >= 0) continue;
        *fail = 1;
        if (vc_append(out, cap, used,
                     "FAIL: %s does not declare required verification item '%s'.\n"
                     "      The required list lives in this gate, not in the "
                     "manifest, so a coverage\n      gap cannot be closed by deleting "
                     "its row. Declare '%s' — as hosted=no\n      with an attestor if "
                     "nothing hosted checks it.\n", k_vc_manifest, k_vc_required[i],
                     k_vc_required[i]))
            return 2;
    }
    return 0;
}

static int vc_jobs_present_list(const struct vc_strset *jobs, char *out, size_t cap)
{
    size_t used = 0;
    for (int i = 0; i < jobs->n; i++)
        if (vc_append(out, cap, &used, "%s ", jobs->v[i])) return 2;
    return 0;
}

static int vc_prong3(const struct vc_row *rows, int rn, const struct vc_strset *jobs,
                     char *out, size_t cap, size_t *used, int *fail)
{
    static char present[VC_CAPBUF];
    if (vc_jobs_present_list(jobs, present, sizeof present)) return 2;
    for (int i = 0; i < rn; i++) {
        if (strcmp(rows[i].hosted, "yes") != 0) continue;
        if (vc_set_has(jobs, rows[i].job)) continue;
        *fail = 1;
        if (vc_append(out, cap, used,
                     "FAIL: %s claims item '%s' is verified by workflow job '%s',\n"
                     "      but %s has no such job. It was renamed or removed, and "
                     "the\n      item it used to cover is now unverified while still "
                     "claiming to be\n      hosted. Jobs present: %s\n", k_vc_manifest,
                     rows[i].item, rows[i].job, k_vc_workflow, present))
            return 2;
    }
    return 0;
}

static int vc_prong4(const struct vc_strset *jobs, const struct vc_strset *claimed,
                     char *out, size_t cap, size_t *used, int *fail)
{
    for (int i = 0; i < jobs->n; i++) {
        if (vc_set_has(claimed, jobs->v[i])) continue;
        *fail = 1;
        if (vc_append(out, cap, used,
                     "FAIL: %s defines job '%s' that no item in %s claims.\n"
                     "      Every hosted job must declare which verification item it "
                     "provides, or\n      the manifest stops being a statement about "
                     "what green means.\n", k_vc_workflow, jobs->v[i], k_vc_manifest))
            return 2;
    }
    return 0;
}

static int vc_prong5(const char *workflow_text, char *out, size_t cap, size_t *used,
                     int *fail)
{
    if (strstr(workflow_text, "verification-coverage.txt")) return 0;
    *fail = 1;
    return vc_append(out, cap, used,
                     "FAIL: %s does not mention %s.\n"
                     "      A reader of the workflow must be sent to the coverage "
                     "statement rather\n      than counting jobs and guessing what "
                     "green covers. Reference it in a\n      comment next to the job "
                     "list.\n", k_vc_workflow, k_vc_manifest);
}

static int vc_prong6_verifier(char *out, size_t cap, size_t *used, int *fail)
{
    if (access(k_vc_verifier, X_OK) != 0) {
        *fail = 1;
        return vc_append(out, cap, used,
                         "FAIL: hosted suite verifier is missing or not executable: "
                         "%s\n", k_vc_verifier);
    }
    char cmd[256];
    if (ovf(snprintf(cmd, sizeof cmd, "%s --self-test", k_vc_verifier), sizeof cmd))
        return 2;
    static char captured[VC_CAPBUF];
    int code = 0;
    if (capture_cmd(cmd, captured, sizeof captured, &code)) return 2;
    if (captured[0] && vc_append(out, cap, used, "%s\n", captured)) return 2;
    if (code == 0) return 0;
    *fail = 1;
    return vc_append(out, cap, used,
                     "FAIL: hosted suite verifier did not reject its adversarial "
                     "fixtures\n");
}

static int vc_prong6(const char *workflow_text, char *out, size_t cap, size_t *used,
                     int *fail)
{
    if (vc_prong6_verifier(out, cap, used, fail)) return 2;
    if (!strstr(workflow_text, "TEST_PARALLEL_ARGS=--no-cache")) {
        *fail = 1;
        if (vc_append(out, cap, used,
                     "FAIL: hosted tests do not force TEST_PARALLEL_ARGS=--no-cache\n"))
            return 2;
    }
    if (!strstr(workflow_text, "check_hosted_suite_verdict.sh /tmp/suite.log")) {
        *fail = 1;
        if (vc_append(out, cap, used,
                     "FAIL: hosted tests do not semantically verify the full captured "
                     "suite log\n"))
            return 2;
    }
    return 0;
}

/* ── prong 7 and the top-level run ────────────────────────────────────── */

static int vc_prong7(const struct vc_row *rows, int rn, int workflow_job_count,
                     char *out, size_t cap, size_t *used)
{
    if (vc_append(out, cap, used,
                 "  ok: %d declared item(s); %d workflow job key(s), all claimed\n",
                 rn, workflow_job_count))
        return 2;
    const char *not_hosted[8];
    int nn = 0;
    for (size_t i = 0; i < sizeof k_vc_required / sizeof k_vc_required[0]; i++) {
        int idx = vc_find_row(rows, rn, k_vc_required[i]);
        if (idx >= 0 && strcmp(rows[idx].hosted, "no") == 0)
            not_hosted[nn++] = k_vc_required[i];
    }
    if (nn == 0)
        return vc_append(out, cap, used,
                         "  ok: every required verification item is covered by a "
                         "hosted job\n");
    if (vc_append(out, cap, used, "  NOT HOSTED — hosted CI does NOT check:"))
        return 2;
    for (int i = 0; i < nn; i++)
        if (vc_append(out, cap, used, " %s", not_hosted[i])) return 2;
    if (vc_append(out, cap, used, "\n")) return 2;
    for (int i = 0; i < nn; i++) {
        int idx = vc_find_row(rows, rn, not_hosted[i]);
        if (vc_append(out, cap, used, "      %s: %s\n", not_hosted[i],
                     rows[idx].attest))
            return 2;
    }
    return vc_append(out, cap, used,
                     "      A green commit on GitHub therefore does NOT mean the "
                     "above passed on\n      that source. Do not read the hosted "
                     "checks as covering them.\n");
}

static int vc_report_missing_manifest(void)
{
    printf("FAIL: %s is missing.\n"
          "      Hosted CI publishes five green checks per commit and the test suite "
          "is\n      not among them. Without a declared coverage manifest, a reader "
          "on GitHub\n      cannot tell which of gcc/clang/lint/tests/fuzz-replay a "
          "green commit\n      actually passed, and the workflow's prose is free to "
          "rot unchecked.\n", k_vc_manifest);
    return 1;
}
static int vc_report_missing_workflow(void)
{
    printf("FAIL: %s is missing — there is nothing to hold the manifest to.\n",
          k_vc_workflow);
    return 1;
}
static int vc_report_unreadable(const char *path)
{
    fprintf(stderr, "check-verification-coverage: UNPROVEN — %s exists but is not "
           "readable; refusing to report a clean scan\n", path);
    return 2;
}

int check_verification_coverage_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0)
        return die("z23-lint: cannot chdir to repo root\n", "");

    int mrc = vc_readable(k_vc_manifest);
    if (mrc == -1) return vc_report_missing_manifest();
    if (mrc == -2) return vc_report_unreadable(k_vc_manifest);
    int wrc = vc_readable(k_vc_workflow);
    if (wrc == -1) return vc_report_missing_workflow();
    if (wrc == -2) return vc_report_unreadable(k_vc_workflow);

    static char workflow_text[VC_WFBUF];
    if (vc_slurp(k_vc_workflow, workflow_text, sizeof workflow_text)) return 2;
    static struct vc_strset jobs = { .n = 0 };
    if (vc_parse_jobs(workflow_text, &jobs)) return 2;
    char jhint[128];
    if (ovf(snprintf(jhint, sizeof jhint,
                     "no job keys parsed out of %s — the awk job-level indent match "
                     "broke", k_vc_workflow), sizeof jhint))
        return 2;
    if (gate_require_scanned(jobs.n, 2, k_vc_gate, jhint)) return 2;

    static char manifest_text[VC_MANBUF];
    if (vc_slurp(k_vc_manifest, manifest_text, sizeof manifest_text)) return 2;
    static struct vc_row rows[VC_ROWS];
    static struct vc_strset claimed = { .n = 0 };
    int rn = 0, fail = 0;
    static char faults[VC_CAPBUF * 2];
    size_t used = 0;
    if (vc_parse_manifest(manifest_text, rows, &rn, &claimed, faults, sizeof faults,
                          &used, &fail))
        return 2;
    char rhint[128];
    if (ovf(snprintf(rhint, sizeof rhint,
                     "only %d row(s) parsed from %s — the parse broke or the file was "
                     "emptied", rn, k_vc_manifest), sizeof rhint))
        return 2;
    if (gate_require_scanned(rn, (int)(sizeof k_vc_required / sizeof k_vc_required[0]),
                             k_vc_gate, rhint))
        return 2;

    if (vc_prong2(rows, rn, faults, sizeof faults, &used, &fail)) return 2;
    if (vc_prong3(rows, rn, &jobs, faults, sizeof faults, &used, &fail)) return 2;
    if (vc_prong4(&jobs, &claimed, faults, sizeof faults, &used, &fail)) return 2;
    if (vc_prong5(workflow_text, faults, sizeof faults, &used, &fail)) return 2;
    if (vc_prong6(workflow_text, faults, sizeof faults, &used, &fail)) return 2;

    fputs(faults, stdout);
    if (fail) return 1;
    size_t used2 = 0;
    static char summary[VC_CAPBUF];
    if (vc_prong7(rows, rn, jobs.n, summary, sizeof summary, &used2)) return 2;
    fputs(summary, stdout);
    printf("check_verification_coverage: clean — declared coverage matches %s\n",
          k_vc_workflow);
    return 0;
}

/* ── selftest: drives the in-memory parsers/prongs directly, touching no
 * file or subprocess (the pattern gate_include_direction_fences.c's
 * check_core_include_boundary_selftest uses for its text-based checks). */

static int vc_st_jobs(void)
{
    struct vc_strset jobs = { .n = 0 };
    const char *wf = "on:\n  push:\njobs:\n  compile-check:\n  build:\n"
                     "  lint:\n# comment\n";
    if (vc_parse_jobs(wf, &jobs) || jobs.n != 3) {
        fprintf(stderr, "check-verification-coverage selftest: job parse "
               "want 3 got %d\n", jobs.n);
        return 1;
    }
    return 0;
}

static int vc_st_row(const char *label, char *text, int want_fail, int want_rn)
{
    static struct vc_row rows[8];
    struct vc_strset claimed = { .n = 0 };
    int rn = 0, fail = 0;
    char out[1024];
    size_t used = 0;
    if (vc_parse_manifest(text, rows, &rn, &claimed, out, sizeof out, &used, &fail))
        return 1;
    if ((fail != 0) != (want_fail != 0) || rn != want_rn) {
        fprintf(stderr, "check-verification-coverage selftest: %s (fail=%d "
               "rn=%d)\n", label, fail, rn);
        return 1;
    }
    return 0;
}

static int vc_st_manifest(void)
{
    char good[] = "gcc|yes|compile-check|compile-check (gcc)|-\n";
    char bad_seps[] = "gcc|yes|compile-check\n";
    char bad_dup[] = "gcc|yes|compile-check|c|-\ngcc|yes|compile-check|c|-\n";
    char bad_job[] = "gcc|yes|not a job!|c|-\n";
    char bad_attest[] = "gcc|no|-|c| \n";
    int rc = vc_st_row("a clean hosted=yes row parses", good, 0, 1);
    rc |= vc_st_row("a row with too few separators fails", bad_seps, 1, 0);
    rc |= vc_st_row("a duplicated item fails", bad_dup, 1, 1);
    rc |= vc_st_row("a malformed job_key fails", bad_job, 1, 0);
    rc |= vc_st_row("a blank attestor on hosted=no fails", bad_attest, 1, 0);
    return rc;
}

static int vc_st_prongs(void)
{
    static struct vc_row rows[2];
    memcpy(rows[0].item, "gcc", 4);
    memcpy(rows[0].hosted, "yes", 4);
    memcpy(rows[0].job, "ghost-job", 10);
    struct vc_strset jobs = { .n = 0 };
    if (vc_set_add(&jobs, "compile-check")) return 1;
    struct vc_strset claimed = { .n = 0 };
    char out[1024];
    size_t used = 0;
    int fail = 0;
    if (vc_prong3(rows, 1, &jobs, out, sizeof out, &used, &fail)) return 1;
    if (!fail) {
        fprintf(stderr, "check-verification-coverage selftest: prong3 missed "
               "a job that does not exist\n");
        return 1;
    }
    fail = 0; used = 0; out[0] = '\0';
    if (vc_prong4(&jobs, &claimed, out, sizeof out, &used, &fail)) return 1;
    if (!fail) {
        fprintf(stderr, "check-verification-coverage selftest: prong4 missed "
               "an unclaimed workflow job\n");
        return 1;
    }
    fail = 0; used = 0; out[0] = '\0';
    if (vc_prong5("no mention here", out, sizeof out, &used, &fail)) return 1;
    if (!fail) {
        fprintf(stderr, "check-verification-coverage selftest: prong5 missed "
               "a workflow with no manifest reference\n");
        return 1;
    }
    fail = 0; used = 0;
    if (vc_prong5("see .github/verification-coverage.txt", out, sizeof out,
                 &used, &fail))
        return 1;
    if (fail) {
        fprintf(stderr, "check-verification-coverage selftest: prong5 false "
               "positive on a present reference\n");
        return 1;
    }
    return 0;
}

int check_verification_coverage_selftest(void)
{
    int rc = vc_st_jobs() | vc_st_manifest() | vc_st_prongs();
    return st_ok(rc,
                 "check-verification-coverage selftest: PASS (job-key "
                 "extraction, the five row-shape checks, and prongs 3-5 all "
                 "catch their planted defect)\n");
}
