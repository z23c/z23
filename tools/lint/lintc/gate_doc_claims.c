/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-doc-claims — BOUND DOC CLAIMS (doc-freshness, HARD).
 * Ported from tools/lint/check_doc_claims.sh (deleted). A markdown
 * annotation of the form "<!-- claim: PREDICATE args... -->" binds one
 * prose assertion to one machine-checkable predicate; the gate fails when
 * the predicate stops holding. Predicates: file-present, file-absent,
 * symbol-present, symbol-absent, gate-passes, gate-fails. Also rejects
 * positive-reliance phrases in the durable entry documents. Modes:
 * plain (all), --global (oracle claims only), --doc=PATH (the rest),
 * --list, --selftest, and --scan DIR (external documents, predicates
 * still resolve against this repository). Selftest lives in
 * gate_doc_claims_selftest.c; the pre-scan self-check in
 * gate_doc_claims_selfcheck.c.
 *
 * Exit: 0 clean, 1 stale/malformed claim, 2 hollow scan set or broken
 * matcher. No heap: fixed static arrays; on overflow print
 * "check_doc_claims: <what> exceeds <N>" and return 2.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_doc_claims_priv.h"

char dc_root[DC_PATH] = ".";
int dc_mode = DC_M_SCAN;
int dc_claim_part = DC_PART_ALL;
int dc_claims_parsed = 0;
int dc_claims_left = 0;
int dc_reliance_scanned = 0;
char dc_viol[DC_VIOL][DC_VIOL_SZ];
int dc_viol_n = 0;
char dc_scan_files[DC_FILES][DC_FILE];
int dc_scan_n = 0;
int dc_external = 0;
int dc_gate_timeout = 180;
int dc_table_override = 0;
char dc_table_path[DC_PATH];

static char dc_extra[DC_ARGS][DC_FILE];
static int dc_extra_n = 0;
static char dc_doc_args[DC_ARGS][DC_FILE];
static int dc_doc_n = 0;

static const char *k_dc_entry_docs[DC_ENTRY_DOCS] = {
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "docs/README.md",
    "docs/dev/DEVELOPING.md",
    "docs/agent/HANDOFF.md",
    "docs/work/FORWARD_PLAN.md",
    ".claude/skills/z23-dev/SKILL.md",
};

void dc_state_reset(void)
{
    dc_viol_n = 0;
    dc_claims_parsed = 0;
    dc_claims_left = 0;
    dc_reliance_scanned = 0;
}

int dc_viol_add(const char *fmt, ...)
{
    if (dc_viol_n >= DC_VIOL) {
        fprintf(stderr, "check_doc_claims: violations exceed %d\n", DC_VIOL);
        return 2;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dc_viol[dc_viol_n], DC_VIOL_SZ, fmt, ap);
    va_end(ap);
    if (ovf(n, DC_VIOL_SZ)) {
        fprintf(stderr, "check_doc_claims: violation text exceeds %d\n",
                DC_VIOL_SZ);
        return 2;
    }
    dc_viol_n++;
    return 0;
}

const char *dc_ltrim(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/* ── argument handling ─────────────────────────────────────────────── */

static const char *dc_mode_name(int m)
{
    switch (m) {
    case DC_M_SELFTEST: return "selftest";
    case DC_M_LIST: return "list";
    case DC_M_GLOBAL: return "global";
    case DC_M_DOC: return "doc";
    default: return "scan";
    }
}

static int dc_set_mode(int m)
{
    if (dc_mode != DC_M_SCAN && dc_mode != m) {
        fprintf(stderr, "check_doc_claims: --%s and --%s cannot be combined\n",
                dc_mode_name(dc_mode), dc_mode_name(m));
        return 2;
    }
    dc_mode = m;
    return 0;
}

static int dc_record(char arr[][DC_FILE], int *n, const char *v)
{
    if (*n >= DC_ARGS) {
        fprintf(stderr, "check_doc_claims: arguments exceed %d\n", DC_ARGS);
        return 2;
    }
    if (strlen(v) >= DC_FILE) {
        fprintf(stderr, "check_doc_claims: argument exceeds %d bytes: %s\n",
                DC_FILE, v);
        return 2;
    }
    strcpy(arr[(*n)++], v);
    return 0;
}

/* The mode flags. Returns 0 ok, 2 error, -1 when a is not a mode flag. */
static int dc_parse_mode(const char *a)
{
    if (!strcmp(a, "--selftest"))
        return dc_set_mode(DC_M_SELFTEST) ? 2 : 0;
    if (!strcmp(a, "--list"))
        return dc_set_mode(DC_M_LIST) ? 2 : 0;
    if (!strcmp(a, "--global"))
        return dc_set_mode(DC_M_GLOBAL) ? 2 : 0;
    if (!strncmp(a, "--doc=", 6)) {
        if (dc_set_mode(DC_M_DOC))
            return 2;
        return dc_record(dc_doc_args, &dc_doc_n, a + 6) ? 2 : 0;
    }
    return -1;
}

/* One argument. Returns 0 ok, 1 help requested, 2 error, 3 consumed the
 * next argv slot (--scan PATH form). */
static int dc_parse_one(const char *a, char **argv, int argc, int *next)
{
    int m = dc_parse_mode(a);
    if (m >= 0)
        return m;
    if (!strcmp(a, "--scan")) {
        if (*next + 1 >= argc) {
            fprintf(stderr, "check_doc_claims: --scan needs a PATH\n");
            return 2;
        }
        if (dc_record(dc_extra, &dc_extra_n, argv[*next + 1]))
            return 2;
        (*next)++;
        return 3;
    }
    if (!strncmp(a, "--scan=", 7))
        return dc_record(dc_extra, &dc_extra_n, a + 7) ? 2 : 0;
    if (!strcmp(a, "--help") || !strcmp(a, "-h"))
        return 1;
    if (!strcmp(a, "."))
        return 0;
    fprintf(stderr, "check_doc_claims: unknown argument '%s'\n", a);
    return 2;
}

static int dc_parse_args(int argc, char **argv)
{
    int i = 0;
    while (i < argc) {
        int r = dc_parse_one(argv[i], argv, argc, &i);
        if (r == 1 || r == 2)
            return r;
        i++;
    }
    if ((dc_mode == DC_M_GLOBAL || dc_mode == DC_M_DOC) && dc_extra_n > 0) {
        fprintf(stderr, "check_doc_claims: --%s covers tracked documents "
                "only; it does not combine with --scan\n",
                dc_mode_name(dc_mode));
        return 2;
    }
    return 0;
}

/* ── scan set ──────────────────────────────────────────────────────── */

static int dc_add_scan(const char *p)
{
    if (dc_scan_n >= DC_FILES) {
        fprintf(stderr, "check_doc_claims: scan set exceeds %d documents\n",
                DC_FILES);
        return 2;
    }
    if (strlen(p) >= DC_FILE) {
        fprintf(stderr, "check_doc_claims: scan path exceeds %d bytes: %s\n",
                DC_FILE, p);
        return 2;
    }
    strcpy(dc_scan_files[dc_scan_n++], p);
    return 0;
}

static int dc_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int dc_expand_home(const char *p, char *out, size_t cap)
{
    if (p[0] != '~')
        return ovf(snprintf(out, cap, "%s", p), cap) ? 2 : 0;
    return ovf(snprintf(out, cap, "%s%s", env_or("HOME", ""), p + 1), cap)
               ? 2
               : 0;
}

static int dc_find_md(const char *dir)
{
    static char out[DC_OUT];
    char *av[] = { "find", (char *)dir, "-type", "f", "-name", "*.md", NULL };
    size_t len;
    int rc;
    if (dc_run_capture(av, out, sizeof out, &len, &rc)) {
        fprintf(stderr, "check_doc_claims: find output exceeds %d bytes\n",
                DC_OUT);
        return 2;
    }
    int first = dc_scan_n;
    char *p = out;
    while (p < out + len) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = 0;
        if (*p && dc_add_scan(p))
            return 2;
        if (!nl)
            break;
        p = nl + 1;
    }
    qsort(dc_scan_files + first, (size_t)(dc_scan_n - first), DC_FILE, dc_cmp);
    return 0;
}

static int dc_add_external(const char *p0)
{
    char p[DC_PATH];
    if (dc_expand_home(p0, p, sizeof p))
        return 2;
    struct stat st;
    if (stat(p, &st) == 0) {
        if (S_ISREG(st.st_mode))
            return dc_add_scan(p);
        if (S_ISDIR(st.st_mode))
            return dc_find_md(p);
    }
    fprintf(stderr,
            "check_doc_claims: FATAL — --scan path does not exist: %s\n", p0);
    return 2;
}

static int dc_trackable(const char *p)
{
    struct stat st, lst;
    if (stat(p, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (lstat(p, &lst) == 0 && S_ISLNK(lst.st_mode))
        return 0;
    return 1;
}

static int dc_git_scan_set(void)
{
    static char out[DC_OUT];
    char *av[] = { "git", "ls-files", "--", "*.md", NULL };
    size_t len;
    int rc;
    if (dc_run_capture(av, out, sizeof out, &len, &rc)) {
        fprintf(stderr, "check_doc_claims: git ls-files output exceeds %d "
                "bytes\n", DC_OUT);
        return 2;
    }
    char *p = out;
    while (p < out + len) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = 0;
        if (*p && dc_trackable(p) && dc_add_scan(p))
            return 2;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int dc_build_scan_set(void)
{
    if (dc_extra_n > 0) {
        dc_external = 1;
        for (int i = 0; i < dc_extra_n; i++)
            if (dc_add_external(dc_extra[i]))
                return 2;
        return 0;
    }
    return dc_git_scan_set();
}

/* ── report ────────────────────────────────────────────────────────── */

static void dc_report_violations(void)
{
    printf("\nFAIL: %d document claim(s) no longer hold.\n", dc_viol_n);
    for (int i = 0; i < dc_viol_n; i++)
        printf("  %s\n", dc_viol[i]);
    printf("\nFix: the CODE is authoritative.\n");
    printf("  - STALE: correct the prose, then re-bind the annotation to "
           "what is now true.\n");
    printf("    A 'gate-passes'/'gate-fails' oracle that flipped means the "
           "work the item\n");
    printf("    describes finished (or regressed) — say so, do not "
           "re-dispatch it.\n");
    printf("  - MALFORMED: fix the annotation. Syntax:\n");
    printf("      <!-- claim: file-present|file-absent <path> -->\n");
    printf("      <!-- claim: symbol-present|symbol-absent <symbol> "
           "<git-pathspec> -->\n");
    printf("      <!-- claim: gate-passes|gate-fails <check-*-gate> -->\n");
    printf("    (documented in docs/DEFENSIVE_CODING.md under "
           "check-doc-claims)\n");
}

/* ── the per-document part (--doc=PATH...) ──────────────────────────── */

static int dc_in_scan_set(const char *f)
{
    for (int i = 0; i < dc_scan_n; i++)
        if (!strcmp(dc_scan_files[i], f))
            return 1;
    return 0;
}

static int dc_doc_main(void)
{
    for (int i = 0; i < dc_doc_n; i++) {
        if (!dc_doc_args[i][0] || !dc_in_scan_set(dc_doc_args[i])) {
            fprintf(stderr, "check_doc_claims: REFUSE: '%s' is not a tracked,"
                    " regular *.md document of the scan set\n",
                    dc_doc_args[i]);
            return 2;
        }
    }
    dc_claim_part = DC_PART_DOC;
    for (int i = 0; i < dc_doc_n; i++) {
        int rc = dc_scan_claim_file(dc_doc_args[i], dc_doc_args[i]);
        if (rc)
            return rc;
    }
    if (dc_viol_n) {
        dc_report_violations();
        return 1;
    }
    printf("check_doc_claims: docs PASS — %d bound claim(s) across %d "
           "document(s) hold; %d oracle claim(s) there belong to --global\n",
           dc_claims_parsed - dc_claims_left, dc_doc_n, dc_claims_left);
    return 0;
}

/* ── entry-document positive-reliance scan ──────────────────────────── */

static int dc_entry_scan(void)
{
    for (int i = 0; i < DC_ENTRY_DOCS; i++) {
        struct stat st;
        if (stat(k_dc_entry_docs[i], &st) != 0) {
            fprintf(stderr, "check_doc_claims: FATAL — entry document "
                    "missing: %s\n", k_dc_entry_docs[i]);
            return 2;
        }
        int rc = dc_scan_positive_reliance(k_dc_entry_docs[i],
                                           k_dc_entry_docs[i]);
        if (rc)
            return rc;
    }
    if (gate_require_scanned(dc_reliance_scanned, DC_ENTRY_DOCS,
                             "check_doc_claims positive-reliance scan",
                             "The durable entry-document scan set was "
                             "incomplete."))
        return 2;
    return 0;
}

/* ── main scan tail ─────────────────────────────────────────────────── */

static int dc_select_claim_docs(int idx[], int *nidx)
{
    *nidx = 0;
    for (int i = 0; i < dc_scan_n; i++) {
        if (dc_mode != DC_M_GLOBAL) {
            idx[(*nidx)++] = i;
            continue;
        }
        int h = dc_doc_has_claim(dc_scan_files[i]);
        if (h < 0) {
            fprintf(stderr, "check_doc_claims: FATAL — cannot search the "
                    "scan set for annotations\n");
            return 2;
        }
        if (h)
            idx[(*nidx)++] = i;
    }
    return 0;
}

static int dc_report_tail(int nidx)
{
    if (dc_viol_n) {
        dc_report_violations();
        return 1;
    }
    if (dc_mode == DC_M_GLOBAL) {
        printf("check_doc_claims: global PASS — %d oracle claim(s) hold; %d "
               "bound claim(s) across %d of %d document(s) meet the floor; "
               "%d entry document(s) reject positive-reliance claims; "
               "self-check fired as expected\n",
               dc_claims_parsed - dc_claims_left, dc_claims_parsed, nidx,
               dc_scan_n, dc_reliance_scanned);
        return 0;
    }
    printf("check_doc_claims: clean — %d bound claim(s) across %d document(s)"
           " all hold; %d entry document(s) reject positive-reliance claims;"
           " self-check fired as expected\n",
           dc_claims_parsed, dc_scan_n, dc_reliance_scanned);
    if (dc_external && dc_claims_parsed == 0) {
        printf("  ZERO COVERAGE, not a clean bill of health: none of the\n");
        printf("  %d scanned document(s) carries a claim annotation, so this"
               " pass\n", dc_scan_n);
        printf("  examined nothing. An out-of-repo plan is only checked once"
               " its author\n");
        printf("  binds an open item to a predicate, e.g. under a PENDING"
               " deletion:\n");
        printf("      <!-- claim: gate-fails check-no-utxo-projection -->\n");
    }
    if (!dc_external) {
        printf("  NOTE: tracked *.md only. Documents outside the repository"
               " (notably\n");
        printf("  ~/.claude/plans/*.md, where the motivating failure occurred)"
               " are NOT\n");
        printf("  covered by `make lint` and must be checked on demand:\n");
        printf("      z23-lint check-doc-claims --scan"
               " ~/.claude/plans\n");
    }
    return 0;
}

static int dc_run_tail(void)
{
    if (dc_external) {
        if (gate_require_scanned(dc_scan_n, 1, "check_doc_claims",
                                 "--scan was given a path with no *.md "
                                 "files under it."))
            return 2;
    } else if (gate_require_scanned(dc_scan_n, MD_SCAN_FLOOR,
                                    "check_doc_claims",
                                    "`git ls-files -- '*.md'` returned almost"
                                    " nothing; run from a real checkout.")) {
        return 2;
    }
    if (dc_mode == DC_M_GLOBAL)
        dc_claim_part = DC_PART_GATE;
    static int idx[DC_FILES];
    int nidx = 0;
    if (dc_select_claim_docs(idx, &nidx))
        return 2;
    for (int i = 0; i < nidx; i++) {
        int rc = dc_scan_claim_file(dc_scan_files[idx[i]],
                                    dc_scan_files[idx[i]]);
        if (rc)
            return rc;
    }
    if (dc_mode == DC_M_LIST) {
        extern int dc_list_mode(void);
        return dc_list_mode();
    }
    if (!dc_external && dc_entry_scan())
        return 2;
    if (!dc_external &&
        gate_require_scanned(dc_claims_parsed, CLAIM_FLOOR, "check_doc_claims",
                             "No <!-- claim: ... --> annotation remains in "
                             "the tracked docs; the gate would pass "
                             "vacuously."))
        return 2;
    return dc_report_tail(nidx);
}

/* ── entry ─────────────────────────────────────────────────────────── */

static void dc_print_help(void)
{
    puts("Lint gate - BOUND DOC CLAIMS (doc-freshness, HARD).");
    puts("");
    puts("  <!-- claim: <predicate> <arg> [<arg>] [# free-text note] -->");
    puts("");
    puts("Predicates: file-present, file-absent, symbol-present,");
    puts("symbol-absent, gate-passes, gate-fails. The gate fails when a");
    puts("predicate stops holding.");
    puts("");
    puts("Usage: z23-lint check-doc-claims [--global | --doc=PATH |");
    puts("       --list | --selftest | --scan DIR | --help]");
}

int check_doc_claims_run(int argc, char **argv)
{
    dc_gate_timeout = atoi(env_or("ZCL_DOC_CLAIMS_GATE_TIMEOUT", "180"));
    if (dc_gate_timeout <= 0)
        dc_gate_timeout = 180;
    int prc = dc_parse_args(argc, argv);
    if (prc == 1) {
        dc_print_help();
        return 0;
    }
    if (prc)
        return prc;
    char dc_top[DC_PATH];
    if (cic_repo_root(dc_top, sizeof dc_top) || chdir(dc_top) != 0) {
        fprintf(stderr, "check_doc_claims: cannot locate the repository root\n");
        return 2;
    }
    if (dc_build_scan_set())
        return 2;
    if (dc_mode == DC_M_DOC)
        return dc_doc_main();
    if (dc_selfcheck())
        return 2;
    if (dc_mode == DC_M_SELFTEST) {
        printf("check_doc_claims: selftest PASS — evaluator fires in both "
               "directions\n");
        return 0;
    }
    return dc_run_tail();
}
