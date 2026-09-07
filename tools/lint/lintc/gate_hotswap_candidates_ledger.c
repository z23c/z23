/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-hotswap-candidates-ledger
 * The agent-facing hot-swap advisory ledger gate of the C23 lint runtime: the
 * gate that holds tools/dev/hotswap-candidates.sh to the counts the hot-swap
 * gates publish, to the leaf denylist, and to the surviving `make hotswap`
 * refusal. Families do not share helpers cross-file (lintc.h declares only
 * lib.c helpers and gate entry points), so the column-1 paren-depth manifest
 * walker this gate needs is duplicated here from gate_hotswap_manifests.c
 * rather than imported.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

#define HL_NUM 32
#define HL_PATH 4096
#define HL_SPEC 8192
#define HL_MAX_LEAVES 512
#define HL_MANIFEST_CAP (1u << 20)
#define HL_CAPTURE_CAP (1u << 20)
#define HL_RECIPE_CAP 65536

/* awk '{ buf = buf $0 "\n" }': the whole file, with a newline appended after
 * every record — including a final line that lacks one. Same walk as
 * gate_hotswap_manifests.c's hss_slurp. */
static int hl_slurp(const char *path, char *buf, size_t cap, size_t *out_n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t n = fread(buf, 1, cap - 1, f);
    int rc = 0;
    if (ferror(f))
        rc = die("z23-lint: cannot read %s\n", path);
    else if (!feof(f))
        rc = die("z23-lint: manifest too large: %s\n", path);
    fclose(f);
    if (rc)
        return rc;
    if (n > 0 && buf[n - 1] != '\n')
        buf[n++] = '\n';
    buf[n] = '\0';
    *out_n = n;
    return 0;
}

/* Paren-depth scan of one invocation body starting just past tok's open
 * paren: copies the raw argument text into spec and reports the index one
 * past the closing paren. Parens inside strings do not count; backslash
 * escapes only shield the depth counter. Same walk as the inner loop of
 * gate_hotswap_manifests.c's hss_collect. */
static int hl_scan_args(const char *buf, size_t n, size_t j, char *spec,
                        size_t cap, size_t *out_j)
{
    int depth = 1, in_str = 0, esc = 0;
    size_t sl = 0;
    while (j < n && depth > 0) {
        char c = buf[j];
        if (in_str) {
            if (esc)
                esc = 0;
            else if (c == '\\')
                esc = 1;
            else if (c == '"')
                in_str = 0;
        } else {
            if (c == '"')
                in_str = 1;
            else if (c == '(')
                depth++;
            else if (c == ')')
                depth--;
        }
        if (depth > 0) {
            if (sl + 1 >= cap)
                return die("z23-lint: hotswap manifest arg overflow\n", "");
            spec[sl++] = c;
        }
        j++;
    }
    spec[sl] = '\0';
    *out_j = j;
    return 0;
}

/* The naive "..." pair: the first string literal's raw content, exactly like
 * the awk original's match(spec, /"[^"]*"/). */
static int hl_store_first_literal(const char *spec, char out[][HL_PATH],
                                  int *nout)
{
    const char *a = strchr(spec, '"');
    const char *b = a ? strchr(a + 1, '"') : NULL;
    if (!b)
        return 0;
    size_t len = (size_t)(b - a - 1);
    if (len >= HL_PATH || *nout >= HL_MAX_LEAVES)
        return die("z23-lint: hotswap manifest path overflow\n", "");
    memcpy(out[*nout], a + 1, len);
    out[*nout][len] = '\0';
    (*nout)++;
    return 0;
}

/* Column-1 walk: every invocation of tok (which includes its open paren)
 * starting at column 1 contributes its FIRST string literal's raw content.
 * Same walk as gate_hotswap_manifests.c's hss_collect with second=0. */
static int hl_collect(const char *buf, size_t n, const char *tok,
                      char out[][HL_PATH], int *nout)
{
    size_t L = strlen(tok);
    size_t i = 0;
    while (i < n) {
        if (i + L > n || memcmp(buf + i, tok, L) != 0
            || (i > 0 && buf[i - 1] != '\n')) {
            i++;
            continue;
        }
        char spec[HL_SPEC];
        size_t j = i + L;
        if (hl_scan_args(buf, n, j, spec, sizeof spec, &j)
            || hl_store_first_literal(spec, out, nout))
            return 2;
        i = j;
    }
    return 0;
}

/* check-hotswap-candidates-ledger — port of
 * tools/lint/check_hotswap_candidates_ledger.sh (now a shim). The agent-facing
 * advisory tool tools/dev/hotswap-candidates.sh re-parses the same .def
 * manifests the gates parse with its OWN awk walkers; a drifted walk does not
 * crash, it under-reports, and an agent believes it and pays the ~4m45s
 * relink for a file that swaps in ~9s. Three fail-closed assertions:
 *   A. COUNT PARITY — run check_hotswap_swappable_shape.sh (still a shell
 *      gate; nonzero exit is FATAL 2), lift the four counts off its OK line,
 *      run the tool's --summary, lift the same four counts, FAIL on drift.
 *   B. THE DENYLIST HOLDS IN THE ADVICE — every HOTSWAP_DENIED_LEAF row of
 *      engine/composition/hotswap_denied_leaves.def, asked of the tool with
 *      --leaf, must come back exit 2 + "VERDICT: BLOCKED". Parsed with the
 *      own column-1 paren-depth walk (hl_collect above) — the same awk state
 *      machine the original embedded.
 *   C. THE REFUSAL SURVIVES — the Makefile `hotswap:` recipe block must still
 *      contain REFUSING, `exit 3`, and the FILES=/PROBE= guards.
 * The tool path and Makefile path are overridable per-invocation via
 * ZCL_HOTSWAP_CANDIDATES_TOOL / ZCL_HOTSWAP_CANDIDATES_MAKEFILE (resolved
 * inside the run, like the shell's run_check) so the selftest can point at
 * seeded fixtures.
 * Parity notes / sanctioned divergences from the shell original:
 *   - the ══ LINT banner is owned by the Make recipe (@echo), as with the
 *     other ported gates; the gate body is byte-identical to the original's
 *     output with that one banner line stripped;
 *   - count extraction is one REG_NEWLINE leftmost-longest regexec over the
 *     whole capture, equivalent to the original's per-line `sed -n s///p |
 *     head -1` for these anchored patterns;
 *   - captures (1 MiB), the recipe block (64 KiB) and count fields (31
 *     digits) are bounded; past the bound the runtime dies with exit 2 where
 *     the shell was unbounded;
 *   - a subprocess killed by a signal reports exit 127 (capture_cmd's
 *     mapping) where the shell's $? would be 128+SIG. */


static const char k_hl_shape_gate[] = "tools/lint/check_hotswap_swappable_shape.sh";
static const char k_hl_denied_def[] = "engine/composition/hotswap_denied_leaves.def";
static const char k_hl_denied_tok[] = "HOTSWAP_" "DENIED_LEAF(";

enum { HL_FILES, HL_LEAVES, HL_ISLAND, HL_READY };
struct hl_counts { char f[4][HL_NUM]; };

struct hl_re { regex_t g[4], s[4]; };

static void hl_free(struct hl_re *r, int n)
{
    for (int i = 0; i < n && i < 4; i++) {
        regfree(&r->g[i]);
        regfree(&r->s[i]);
    }
}

static int hl_compile(struct hl_re *r)
{
    /* Field order is {files, leaves, island, ready} on both sides. */
    static const char *const gpat[] = {
        ".*OK: ([0-9]+) swappable file\\(s\\).*",
        ".*swappable file\\(s\\), ([0-9]+) READY read-only leaf.*",
        ".*leaf/leaves, ([0-9]+) stateless island member.*",
        ".*cross-checked against ([0-9]+) ZCL_COMMAND_READY_READ.*",
    };
    static const char *const spat[] = {
        ".*\\| TUs ([0-9]+)/[0-9]+.*",
        "^SUMMARY: leaves ([0-9]+)/[0-9]+.*",
        ".*\\+ ([0-9]+) island member\\(s\\).*",
        "^SUMMARY: leaves [0-9]+/([0-9]+).*",
    };
    for (int i = 0; i < 4; i++) {
        int err = regcomp(&r->g[i], gpat[i], REG_EXTENDED | REG_NEWLINE);
        if (!err)
            err = regcomp(&r->s[i], spat[i], REG_EXTENDED | REG_NEWLINE);
        if (err) {
            hl_free(r, i);
            return reg_fail(&r->g[i], err);
        }
    }
    return 0;
}

/* sed 's/^/    /' over printf '%s\n' of a trailing-newline-stripped capture:
 * every line indented four spaces; an empty capture is one blank indent. */
static int hl_indent(FILE *out, const char *text)
{
    if (!text[0])
        return fputs("    \n", out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    const char *p = text;
    while (1) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (fputs("    ", out) < 0 || fwrite(p, 1, n, out) != n
            || fputc('\n', out) == EOF)
            return die("z23-lint: write failed\n", "");
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

/* First match of each anchored pattern anywhere in the capture yields the
 * field's digits; a missing pattern leaves the field empty. */
static int hl_counts_from(const regex_t *re4, const char *text,
                          struct hl_counts *c)
{
    for (int i = 0; i < 4; i++) {
        regmatch_t m[2];
        c->f[i][0] = '\0';
        if (regexec(&re4[i], text, 2, m, 0) != 0)
            continue;
        size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
        if (len >= HL_NUM)
            return die("z23-lint: hotswap ledger count overflow\n", "");
        memcpy(c->f[i], text + m[1].rm_so, len);
        c->f[i][len] = '\0';
    }
    return 0;
}

static int hl_counts_ok(const struct hl_counts *c)
{
    return c->f[0][0] && c->f[1][0] && c->f[2][0] && c->f[3][0];
}

/* Section A, first half: the shape gate's own published counts. Its failure
 * or an unparsable OK line is FATAL (2) — parity cannot be measured. */
static int hl_shape_counts(const struct hl_re *re, struct hl_counts *g,
                           FILE *err)
{
    char q[8192], cmd[16384];
    if (sh_single_quote(k_hl_shape_gate, q, sizeof q)
        || ovf(snprintf(cmd, sizeof cmd, "bash %s 2>&1", q), sizeof cmd))
        return 2;
    static char shape_out[HL_CAPTURE_CAP];
    int code = 0;
    if (capture_cmd(cmd, shape_out, sizeof shape_out, &code))
        return 2;
    if (code != 0) {
        fprintf(err, "check_hotswap_candidates_ledger: FATAL — %s itself "
                "failed (exit %d).\n", k_hl_shape_gate, code);
        fputs("  The reference numbers are not trustworthy; fix that gate "
              "first.\n", err);
        hl_indent(err, shape_out);
        return 2;
    }
    if (hl_counts_from(re->g, shape_out, g))
        return 2;
    if (!hl_counts_ok(g)) {
        fputs("check_hotswap_candidates_ledger: FATAL — could not read the "
              "reference counts\n", err);
        fprintf(err, "  out of %s's OK line. Its output shape changed; this "
                "gate\n", k_hl_shape_gate);
        fputs("  refuses to certify parity it cannot measure.\n", err);
        hl_indent(err, shape_out);
        return 2;
    }
    return 0;
}

static void hl_report_mismatch(const char *tool, const struct hl_counts *g,
                               const struct hl_counts *t, FILE *out)
{
    fprintf(out, "FAIL: %s disagrees with %s about what the manifests say.\n",
            tool, k_hl_shape_gate);
    if (strcmp(t->f[HL_FILES], g->f[HL_FILES]) != 0)
        fprintf(out, "    swappable TU count:  tool=%s  gate=%s\n",
                t->f[HL_FILES], g->f[HL_FILES]);
    if (strcmp(t->f[HL_LEAVES], g->f[HL_LEAVES]) != 0)
        fprintf(out, "    swappable leaf count: tool=%s  gate=%s\n",
                t->f[HL_LEAVES], g->f[HL_LEAVES]);
    if (strcmp(t->f[HL_ISLAND], g->f[HL_ISLAND]) != 0)
        fprintf(out, "    island member count: tool=%s  gate=%s\n",
                t->f[HL_ISLAND], g->f[HL_ISLAND]);
    if (strcmp(t->f[HL_READY], g->f[HL_READY]) != 0)
        fprintf(out, "    READY_READ population: tool=%s  gate=%s\n",
                t->f[HL_READY], g->f[HL_READY]);
    fputs("  Two independent parsers of one manifest set have drifted. The "
          "tool\n"
          "  advises agents which loop to use; a tool that under-reports "
          "coverage\n"
          "  sends them to the 4m45s rebuild for a file that swaps in 9 "
          "seconds.\n", out);
}

/* Section A, second half: the tool's --summary counts against the gate's.
 * Returns 1 when run_check bails out immediately (unparsable summary). */
static int hl_summary_parity(const char *tool, const struct hl_re *re,
                             const struct hl_counts *g, FILE *out, int *fail)
{
    char qtool[8192], cmd[16384];
    if (sh_single_quote(tool, qtool, sizeof qtool)
        || ovf(snprintf(cmd, sizeof cmd, "bash %s --summary 2>&1", qtool),
               sizeof cmd))
        return 2;
    static char summary[HL_CAPTURE_CAP];
    int code = 0;
    if (capture_cmd(cmd, summary, sizeof summary, &code))
        return 2;
    if (code != 0) {
        fprintf(out, "FAIL: '%s --summary' exited %d.\n", tool, code);
        if (hl_indent(out, summary))
            return 2;
        *fail = 1;
    }
    struct hl_counts t;
    if (hl_counts_from(re->s, summary, &t))
        return 2;
    if (!hl_counts_ok(&t)) {
        fprintf(out, "FAIL: could not parse the coverage numbers out of "
                "'%s --summary'.\n", tool);
        fputs("      Expected a line shaped:\n"
              "        SUMMARY: leaves <n>/<n> READY_READ covered (..%) | "
              "TUs <n>/<n> ... + <n> island member(s) | ...\n", out);
        if (hl_indent(out, summary))
            return 2;
        return 1;
    }
    if (strcmp(t.f[HL_FILES], g->f[HL_FILES]) != 0
        || strcmp(t.f[HL_LEAVES], g->f[HL_LEAVES]) != 0
        || strcmp(t.f[HL_ISLAND], g->f[HL_ISLAND]) != 0
        || strcmp(t.f[HL_READY], g->f[HL_READY]) != 0) {
        hl_report_mismatch(tool, g, &t, out);
        *fail = 1;
    }
    return 0;
}

static int hl_leaf_check(const char *tool, const char *qtool,
                         const char *leaf, FILE *out, int *fail)
{
    char qleaf[8192], cmd[16384];
    if (sh_single_quote(leaf, qleaf, sizeof qleaf)
        || ovf(snprintf(cmd, sizeof cmd, "bash %s --leaf %s 2>&1", qtool,
                        qleaf), sizeof cmd))
        return 2;
    static char captured[HL_CAPTURE_CAP];
    int code = 0;
    if (capture_cmd(cmd, captured, sizeof captured, &code))
        return 2;
    if (code == 2 && strstr(captured, "VERDICT: BLOCKED") != NULL)
        return 0;
    fprintf(out, "FAIL: '%s --leaf %s' did not report BLOCKED (exit %d).\n",
            tool, leaf, code);
    fprintf(out, "      That leaf is on %s. The tool must never advise a\n",
            k_hl_denied_def);
    fputs("      swap of a denied leaf, whatever the mechanical rules say.\n",
          out);
    if (hl_indent(out, captured))
        return 2;
    *fail = 1;
    return 0;
}

/* Section B: every denied leaf must come back BLOCKED from the tool. */
static int hl_denied_advice(const char *tool, FILE *out, int *fail,
                            int *denied_n)
{
    static char buf[HL_MANIFEST_CAP];
    size_t n = 0;
    if (hl_slurp(k_hl_denied_def, buf, sizeof buf, &n))
        return 2;
    static char leaves[HL_MAX_LEAVES][HL_PATH];
    int nl = 0;
    if (hl_collect(buf, n, k_hl_denied_tok, leaves, &nl))
        return 2;
    char qtool[8192];
    if (sh_single_quote(tool, qtool, sizeof qtool))
        return 2;
    int cnt = 0;
    for (int i = 0; i < nl; i++) {
        if (!leaves[i][0])
            continue;
        cnt++;
        if (hl_leaf_check(tool, qtool, leaves[i], out, fail))
            return 2;
    }
    *denied_n = cnt;
    char hint[512];
    if (ovf(snprintf(hint, sizeof hint, "no HOTSWAP_" "DENIED_LEAF rows "
                     "parsed from %s — the denylist fails CLOSED",
                     k_hl_denied_def), sizeof hint))
        return 2;
    if (fflush(out) != 0)
        return die("z23-lint: write failed\n", "");
    return gate_require_scanned(cnt, 1, "check_hotswap_candidates_ledger",
                                hint);
}

/* awk '/^hotswap:/ { inb = 1; next } inb { if ($0 ~ /^[^\t ]/ && $0 !~ /^#/)
 * exit; print }' — the recipe block after the first hotswap: line, up to the
 * first outdented non-# line; $(...) strips the trailing newlines. */
static int hl_recipe_extract(FILE *f, const char *path, char *buf, size_t cap)
{
    char *line = NULL;
    size_t lcap = 0, used = 0;
    ssize_t n;
    int inb = 0, rc = 0;
    while ((n = getline(&line, &lcap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (!inb) {
            inb = strncmp(line, "hotswap:", 8) == 0;
            continue;
        }
        if (n > 0 && line[0] != '\t' && line[0] != ' ' && line[0] != '#')
            break;
        if (used + (size_t)n + 2 > cap) {
            rc = die("z23-lint: hotswap ledger recipe overflow\n", "");
            break;
        }
        memcpy(buf + used, line, (size_t)n + 1);
        used += (size_t)n;
        buf[used++] = '\n';
    }
    while (used && buf[used - 1] == '\n')
        buf[--used] = '\0';
    return fin(f, line, path, rc);
}

static const char *const k_hl_needle[4] = { "REFUSING", "exit 3", "FILES",
                                            "PROBE" };
static const char *const k_hl_what[4] = { " the refusal message", ", 'exit 3'",
                                          ", the FILES= guard",
                                          ", the PROBE= guard" };

static int hl_recipe_missing(const char *recipe, char *missing, size_t cap)
{
    size_t used = 0;
    missing[0] = '\0';
    for (int i = 0; i < 4; i++) {
        if (strstr(recipe, k_hl_needle[i]) != NULL)
            continue;
        size_t l = strlen(k_hl_what[i]);
        if (used + l + 1 > cap)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(missing + used, k_hl_what[i], l + 1);
        used += l;
    }
    return missing[0] != '\0';
}

/* Section C: the runtime-publication refusal must survive in the recipe. */
static int hl_recipe_refusal(const char *makefile, FILE *out, int *fail)
{
    FILE *f = fopen(makefile, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", makefile);
    static char recipe[HL_RECIPE_CAP];
    int rc = hl_recipe_extract(f, makefile, recipe, sizeof recipe);
    if (rc)
        return rc;
    int blank = 1;
    for (const char *p = recipe; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            blank = 0;
            break;
        }
    }
    if (blank) {
        fprintf(out, "FAIL: no 'hotswap:' recipe found in %s.\n", makefile);
        fputs("      This gate exists to prove that recipe still refuses "
              "runtime\n"
              "      publication; it cannot certify a recipe it cannot "
              "read.\n", out);
        *fail = 1;
        return 0;
    }
    char missing[256];
    if (!hl_recipe_missing(recipe, missing, sizeof missing))
        return 0;
    fputs("FAIL: the 'hotswap:' recipe no longer refuses runtime "
          "publication.\n", out);
    fprintf(out, "      Missing:%s\n", missing);
    fputs("      `make hotswap FILES=... [PROBE=...]` is the RUNTIME "
          "PUBLICATION\n"
          "      form — build a generation .so and hand it to the resident\n"
          "      dev_hotswap RPC for in-process publication and resident "
          "probing.\n"
          "      Widening the bare goal into a read-only ledger must never "
          "make\n"
          "      that form reachable. Restore the guarded refusal + exit 3.\n",
          out);
    *fail = 1;
    return 0;
}

static int hl_run_impl(FILE *out, FILE *err)
{
    /* Resolved per invocation, like the shell's run_check locals: the
     * selftest re-runs this with the env knobs pointed at seeded fixtures. */
    const char *tool = env_or("ZCL_HOTSWAP_CANDIDATES_TOOL",
                              "tools/dev/hotswap-candidates.sh");
    const char *makefile = env_or("ZCL_HOTSWAP_CANDIDATES_MAKEFILE",
                                  "Makefile");
    const char *const inputs[4] = { tool, k_hl_shape_gate, k_hl_denied_def,
                                    makefile };
    for (int i = 0; i < 4; i++) {
        if (access(inputs[i], R_OK) == 0)
            continue;
        fprintf(err, "check_hotswap_candidates_ledger: FATAL — '%s' "
                "missing/unreadable.\n", inputs[i]);
        fputs("  Refusing to certify an advisory tool off an unreadable "
              "input.\n", err);
        return 2;
    }
    struct hl_re re;
    int rc = hl_compile(&re);
    if (rc)
        return rc;
    struct hl_counts g;
    int fail = 0, denied_n = 0;
    rc = hl_shape_counts(&re, &g, err);
    if (rc == 0)
        rc = gate_require_scanned(atoi(g.f[HL_LEAVES]), 1,
                "check_hotswap_candidates_ledger",
                "tools/lint/check_hotswap_swappable_shape.sh reported zero "
                "swappable leaves");
    if (rc == 0)
        rc = hl_summary_parity(tool, &re, &g, out, &fail);
    if (rc == 0)
        rc = hl_denied_advice(tool, out, &fail, &denied_n);
    if (rc == 0)
        rc = hl_recipe_refusal(makefile, out, &fail);
    hl_free(&re, 4);
    if (rc)
        return rc;
    if (fail)
        return 1;
    fprintf(out, "  OK: ledger agrees with %s (%s TU(s), %s leaf/leaves,\n",
            k_hl_shape_gate, g.f[HL_FILES], g.f[HL_LEAVES]);
    fprintf(out, "      %s island member(s), %s READY_READ leaves); %d "
            "denied\n", g.f[HL_ISLAND], g.f[HL_READY], denied_n);
    fputs("      leaf/leaves refused by the tool; 'make hotswap' still "
          "refuses FILES=/PROBE=.\n", out);
    return 0;
}

int check_hotswap_candidates_ledger_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return hl_run_impl(stdout, stderr);
}

/* ── selftest: prove each class fires before trusting the gate ──────────── */

static const char k_hl_stub_tool[] =
    "#!/usr/bin/env bash\n"
    "# Seeded violation: reports coverage numbers that do not match the "
    "manifests.\n"
    "if [ \"${1:-}\" = \"--summary\" ]; then\n"
    "  echo \"SUMMARY: leaves 1/1 READY_READ covered (100.0%) | TUs 1/1 "
    "app/controllers TUs registered (100.0%) + 1 island member(s) | "
    "eligible-not-registered 0 TU(s)/0 leaf/leaves | blocked 0 TU(s) | 0 "
    "leaf/leaves owned by a registered TU but unlisted and unexplained\"\n"
    "  exit 0\n"
    "fi\n"
    "if [ \"${1:-}\" = \"--leaf\" ]; then echo \"VERDICT: BLOCKED\"; exit 2; "
    "fi\n"
    "exit 0\n";

static const char k_hl_seeded_makefile[] =
    "hotswap:\n"
    "\t@tools/dev/hotswap-candidates.sh --all\n"
    "\n";

struct hl_st_env { const char *name; char old[4096]; int was_set; };

static int hl_st_env_set(struct hl_st_env *sv, const char *name,
                         const char *val)
{
    const char *e = getenv(name);
    sv->name = name;
    sv->was_set = e != NULL;
    if (e && ovf(snprintf(sv->old, sizeof sv->old, "%s", e), sizeof sv->old))
        return 2;
    if (!e)
        sv->old[0] = '\0';
    return setenv(name, val, 1) != 0 ? die("z23-lint: setenv failed\n", "")
                                     : 0;
}

static int hl_st_env_restore(const struct hl_st_env *sv)
{
    if (!sv->was_set) {
        unsetenv(sv->name);
        return 0;
    }
    return setenv(sv->name, sv->old, 1) != 0
               ? die("z23-lint: setenv failed\n", "") : 0;
}

/* One seeded-violation case: point the knob at the fixture, run the gate
 * with its output sunk, require a nonzero exit. */
static int hl_st_run(const char *header, const char *fail_msg,
                     const char *env_name, const char *env_val)
{
    fputs(header, stdout);
    struct hl_st_env sv;
    if (hl_st_env_set(&sv, env_name, env_val))
        return 1;
    FILE *out = tmpfile();
    FILE *errf = tmpfile();
    int rc = (out && errf) ? hl_run_impl(out, errf) : 2;
    if (out)
        fclose(out);
    if (errf)
        fclose(errf);
    if (hl_st_env_restore(&sv))
        return 1;
    if (rc == 0) {
        fputs(fail_msg, stderr);
        return 1;
    }
    fprintf(stdout, "  ok (exit %d)\n", rc);
    return 0;
}

int check_hotswap_candidates_ledger_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl,
                     "%s/zcl-hotswap-ledger-selftest.XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *tmp = mkdtemp(tmpl);
    if (!tmp)
        return die("z23-lint: mkdir failed: %s\n", td);
    char stub[4096], mk[4096];
    int bad = 0;
    if (ovf(snprintf(stub, sizeof stub, "%s/stub-tool.sh", tmp), sizeof stub)
        || ovf(snprintf(mk, sizeof mk, "%s/Makefile.seeded", tmp), sizeof mk)
        || csr_write(stub, k_hl_stub_tool)
        || chmod(stub, 0755) != 0
        || csr_write(mk, k_hl_seeded_makefile))
        bad = 1;
    if (!bad)
        bad |= hl_st_run(
            "── selftest 1/2: a tool that under-reports coverage must FAIL "
            "──\n",
            "  SELFTEST FAIL: the gate passed a tool whose counts disagree "
            "with the manifests.\n",
            "ZCL_HOTSWAP_CANDIDATES_TOOL", stub);
    if (!bad)
        bad |= hl_st_run(
            "── selftest 2/2: a hotswap: recipe with the refusal removed "
            "must FAIL ──\n",
            "  SELFTEST FAIL: the gate passed a recipe that no longer "
            "refuses FILES=/PROBE=.\n",
            "ZCL_HOTSWAP_CANDIDATES_MAKEFILE", mk);
    (void)rap_rm_rf(tmp);
    if (bad) {
        fputs("SELFTEST FAILED — this gate cannot be trusted.\n", stderr);
        return 1;
    }
    fputs("  selftest OK: both seeded violations were caught.\n", stdout);
    return 0;
}
