/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate — the lint umbrella's three files must agree by NAME
 * (Makefile LINT_GATES/LINT_FAST_GATES, run_lint.sh's gate_command() case
 * table, and the docs/DEFENSIVE_CODING.md LINT-GATES doc block), plus the
 * lintc family-file line ceiling. Ported from
 * tools/lint/check_lint_gate_wiring.sh, which is now a 3-line exec shim
 * onto this binary. Selftest: gate_lint_gate_wiring_selftest.c.
 *
 * Sources of truth this gate never re-parses by hand: the Makefile's
 * backslash-continued LINT_GATES/LINT_FAST_GATES blocks (read directly,
 * same shape tools/scripts/check_doc_accuracy.sh and
 * tools/dev/agent-baseline.sh already assume), and run_lint.sh's own
 * `--list` / `--print-command <gate>` outputs (spawned via capture_cmd,
 * the same producer the shell original invoked — this gate never
 * re-implements gate_command()'s case table).
 *
 * Checks (all fail-closed, all run and all reported before returning):
 *   A. every LINT_GATES/LINT_FAST_GATES member has a gate_command() entry.
 *   B. every gate_command() entry belongs to one of those two lists.
 *   C. every listed gate has a real `check-<name>:` Makefile target.
 *   D. every table entry's script path (each whitespace-split, non-'$',
 *      *.sh token) exists under the scanned root.
 *   E. no tools/lint/lintc/gate_*.c file exceeds LINT_FAMILY_CEILING,
 *      read out of lintc.h's own #define (never the compiled-in value —
 *      a fixture root can carry a different lintc.h than this binary's).
 *   F. every LINT_GATES/LINT_FAST_GATES member is named inside the
 *      <!-- LINT-GATES-BEGIN/END --> block of docs/DEFENSIVE_CODING.md.
 *   G. every check-* token in that doc block belongs to LINT_GATES or
 *      LINT_FAST_GATES (no doc-only phantom gate).
 *
 * Adding a lint gate is a THREE-file operation: Makefile LINT_GATES,
 * run_lint.sh gate_command(), and the DEFENSIVE_CODING.md doc block. F/G
 * catch the third file the same way A/B catch the second — by NAME, not
 * just by count, so a doc block that swaps one gate for another (same
 * count, wrong names) still fails. The doc-block extraction mirrors the
 * awk block scan in tools/scripts/check_doc_accuracy.sh (not literally
 * shared — that script is bash, this gate is C — but same markers, same
 * shape: everything between LINT-GATES-BEGIN and LINT-GATES-END, check-*
 * tokens only).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_lint_gate_wiring_priv.h"

enum { LGW_BUF = 1 << 20, LGW_LINE = 8192 };

/* ── gate-name token scan: "check-[a-z0-9-]+" wherever it occurs ────────── */
static int lgw_scan_tokens(const char *line, struct sr_set *out)
{
    const char *p = line;
    while ((p = strstr(p, "check-")) != NULL) {
        const char *start = p, *q = p + 6;
        while (*q && (islower((unsigned char)*q) || isdigit((unsigned char)*q)
                     || *q == '-'))
            q++;
        size_t len = (size_t)(q - start);
        char buf[SR_NAME];
        if (len >= sizeof buf)
            return die("z23-lint: gate-name token too long\n", "");
        memcpy(buf, start, len);
        buf[len] = '\0';
        int rc = sr_add(out, buf);
        if (rc)
            return rc;
        p = q;
    }
    return 0;
}

/* ── extract_gate_list: the "VAR := \" backslash-continued block idiom ── */
static int lgw_is_var_start(const char *line, const char *var)
{
    size_t vlen = strlen(var);
    if (strncmp(line, var, vlen) != 0)
        return 0;
    const char *p = line + vlen;
    while (*p == ' ' || *p == '\t')
        p++;
    return p[0] == ':' && p[1] == '=';
}
static int lgw_line_continues(const char *line)
{
    size_t n = strlen(line);
    while (n && isspace((unsigned char)line[n - 1]))
        n--;
    return n > 0 && line[n - 1] == '\\';
}
static int lgw_extract_var(const char *makefile, const char *var, struct sr_set *out)
{
    FILE *f = fopen(makefile, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", makefile);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int collecting = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (!collecting) {
            if (!lgw_is_var_start(line, var))
                continue;
            collecting = 1;
        }
        rc = lgw_scan_tokens(line, out);
        if (rc == 0 && !lgw_line_continues(line))
            break;
    }
    return fin(f, line, makefile, rc);
}

/* ── doc block: <!-- LINT-GATES-BEGIN --> ... <!-- LINT-GATES-END --> ──── */
static int lgw_extract_doc_block(const char *doc, struct sr_set *out)
{
    FILE *f = fopen(doc, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", doc);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int inb = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (strstr(line, "<!-- LINT-GATES-BEGIN -->")) {
            inb = 1;
            continue;
        }
        if (strstr(line, "<!-- LINT-GATES-END -->")) {
            inb = 0;
            continue;
        }
        if (inb)
            rc = lgw_scan_tokens(line, out);
    }
    return fin(f, line, doc, rc);
}

/* ── the driver's own outputs (never re-parsed as text elsewhere) ──────── */
static int lgw_driver_list(const char *driver, struct sr_set *out)
{
    char q[8192], cmd[8192], buf[LGW_BUF];
    int code = 0;
    if (sh_single_quote(driver, q, sizeof q)
        || ovf(snprintf(cmd, sizeof cmd, "%s --list 2>/dev/null", q), sizeof cmd))
        return 2;
    int rc = capture_cmd(cmd, buf, sizeof buf, &code);
    if (rc)
        return rc;
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (strncmp(ln, "check-", 6) == 0 && sr_add(out, ln))
            return 2;
    }
    return 0;
}
static int lgw_print_command(const char *driver, const char *gate, char *out, size_t cap)
{
    char qd[8192], qg[SR_NAME + 8], cmd[8192];
    int code = 0;
    if (sh_single_quote(driver, qd, sizeof qd) || sh_single_quote(gate, qg, sizeof qg)
        || ovf(snprintf(cmd, sizeof cmd, "%s --print-command %s 2>/dev/null", qd, qg),
              sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, &code);
}

/* ── set arithmetic + report accumulation ───────────────────────────────── */
static int lgw_append(char *out, size_t cap, size_t *used, const char *s)
{
    size_t n = strlen(s);
    if (*used + n >= cap)
        return die("z23-lint: report buffer overflow\n", "");
    memcpy(out + *used, s, n + 1);
    *used += n;
    return 0;
}
int lgw_appendf_pub(char *out, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (ovf(k, cap - *used))
        return 2;
    *used += (size_t)k;
    return 0;
}

static int lgw_check_a(const struct sr_set *listed, const struct sr_set *table,
                       char *out, size_t cap, size_t *used, int *fail)
{
    int any = 0;
    for (int i = 0; i < listed->count; i++)
        if (!sr_has(table, listed->n[i]))
            any = 1;
    if (!any)
        return 0;
    *fail = 1;
    if (lgw_append(out, cap, used,
                   "FAIL: gate(s) in LINT_GATES/LINT_FAST_GATES with NO gate_command() entry:\n"))
        return 2;
    for (int i = 0; i < listed->count; i++) {
        if (sr_has(table, listed->n[i]))
            continue;
        if (lgw_appendf_pub(out, cap, used, "    %s\n", listed->n[i]))
            return 2;
    }
    return lgw_append(out, cap, used,
                      "\n  Adding a lint gate is a THREE-FILE operation. You did the Makefile part.\n"
                      "  Add the run_lint.sh part to gate_command() in tools/lint/run_lint.sh, one\n"
                      "  line per gate, reproducing the Make recipe EXACTLY (script path, args, any\n"
                      "  ZCL_LINT_MODE prefix). A recipe with two steps is joined with &&:\n\n"
                      "        <gate>)   echo './tools/lint/<script>.sh --selftest && ./tools/lint/<script>.sh' ;;\n\n"
                      "  Without it 'make lint' exits 2 for everyone and reports NO gate results.\n"
                      "  (The doc part — docs/DEFENSIVE_CODING.md's LINT-GATES block — is checked\n"
                      "  separately below.)\n");
}

static int lgw_check_b(const struct sr_set *listed, const struct sr_set *table,
                       char *out, size_t cap, size_t *used, int *fail)
{
    int any = 0;
    for (int i = 0; i < table->count; i++)
        if (!sr_has(listed, table->n[i]))
            any = 1;
    if (!any)
        return 0;
    *fail = 1;
    if (lgw_append(out, cap, used,
                   "FAIL: gate_command() entries that NO gate list names (dead wiring):\n"))
        return 2;
    for (int i = 0; i < table->count; i++) {
        if (sr_has(listed, table->n[i]))
            continue;
        if (lgw_appendf_pub(out, cap, used, "    %s\n", table->n[i]))
            return 2;
    }
    return lgw_append(out, cap, used,
                      "\n  Nothing runs these. Either add them to LINT_GATES (or LINT_FAST_GATES)\n"
                      "  in Makefile, or delete the table entry. A gate that never runs is a\n"
                      "  gate that is not protecting anything.\n");
}

static int lgw_check_f(const struct sr_set *listed, const struct sr_set *doc,
                       const char *doc_path, char *out, size_t cap, size_t *used, int *fail)
{
    int any = 0;
    for (int i = 0; i < listed->count; i++)
        if (!sr_has(doc, listed->n[i]))
            any = 1;
    if (!any)
        return 0;
    *fail = 1;
    if (lgw_appendf_pub(out, cap, used,
                    "FAIL: gate(s) in LINT_GATES/LINT_FAST_GATES missing from %s:\n",
                    doc_path))
        return 2;
    for (int i = 0; i < listed->count; i++) {
        if (sr_has(doc, listed->n[i]))
            continue;
        if (lgw_appendf_pub(out, cap, used, "    %s\n", listed->n[i]))
            return 2;
    }
    return lgw_appendf_pub(out, cap, used,
                      "\n  Adding a lint gate is a THREE-file operation. You wired the Makefile\n"
                      "  and run_lint.sh; add the gate name to the <!-- LINT-GATES-BEGIN/END -->\n"
                      "  block in %s too.\n", doc_path);
}
static int lgw_check_g(const struct sr_set *listed, const struct sr_set *doc,
                       const char *doc_path, char *out, size_t cap, size_t *used, int *fail)
{
    int any = 0;
    for (int i = 0; i < doc->count; i++)
        if (!sr_has(listed, doc->n[i]))
            any = 1;
    if (!any)
        return 0;
    *fail = 1;
    if (lgw_appendf_pub(out, cap, used,
                    "FAIL: gate(s) documented in %s but NOT in Makefile LINT_GATES/LINT_FAST_GATES:\n",
                    doc_path))
        return 2;
    for (int i = 0; i < doc->count; i++) {
        if (sr_has(listed, doc->n[i]))
            continue;
        if (lgw_appendf_pub(out, cap, used, "    %s\n", doc->n[i]))
            return 2;
    }
    return lgw_appendf_pub(out, cap, used,
                      "\n  %s documents a gate the Makefile does not list. Either add it to\n"
                      "  LINT_GATES (or LINT_FAST_GATES), or remove it from the doc block.\n",
                      doc_path);
}

static int lgw_makefile_has_target(const char *makefile, const char *gate)
{
    FILE *f = fopen(makefile, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", makefile);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    size_t glen = strlen(gate);
    int found = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if ((size_t)n > glen && strncmp(line, gate, glen) == 0 && line[glen] == ':') {
            found = 1;
            break;
        }
    }
    int rc = fin(f, line, makefile, 0);
    return rc ? rc : found;
}

static int lgw_check_c(const char *makefile, const struct sr_set *listed,
                       char *out, size_t cap, size_t *used, int *fail)
{
    int any = 0;
    for (int i = 0; i < listed->count; i++) {
        int r = lgw_makefile_has_target(makefile, listed->n[i]);
        if (r < 0)
            return r;
        if (!r)
            any = 1;
    }
    if (!any)
        return 0;
    *fail = 1;
    if (lgw_appendf_pub(out, cap, used,
                    "FAIL: listed gate(s) with no 'check-...:' target in %s:\n", makefile))
        return 2;
    for (int i = 0; i < listed->count; i++) {
        int r = lgw_makefile_has_target(makefile, listed->n[i]);
        if (r < 0)
            return r;
        if (!r && lgw_appendf_pub(out, cap, used, "    %s\n", listed->n[i]))
            return 2;
    }
    return lgw_append(out, cap, used,
                      "\n  ZCL_LINT_SERIAL=1 runs the gate list as Make prerequisites. A listed\n"
                      "  name with no rule makes that fallback fail with 'No rule to make target'\n"
                      "  while the parallel path stays green — check a typo in the list first.\n");
}

/* Whitespace-split like unquoted `for tok in $cmd`; every non-'$' token
 * ending in ".sh" must exist under root. */
static int lgw_check_one_command(const char *root, const char *gate, const char *cmd,
                                 char *out, size_t cap, size_t *used, int *fail)
{
    char buf[8192];
    if (ovf(snprintf(buf, sizeof buf, "%s", cmd), sizeof buf))
        return 2;
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t\n", &save); tok; tok = strtok_r(NULL, " \t\n", &save)) {
        if (strchr(tok, '$'))
            continue;
        size_t tl = strlen(tok);
        if (tl < 3 || strcmp(tok + tl - 3, ".sh") != 0)
            continue;
        const char *rel = (tok[0] == '.' && tok[1] == '/') ? tok + 2 : tok;
        char path[8192];
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
            return 2;
        struct stat st;
        if (stat(path, &st) == 0)
            continue;
        *fail = 1;
        if (lgw_appendf_pub(out, cap, used, "    %s -> %s\n", gate, rel))
            return 2;
    }
    return 0;
}
static int lgw_check_d(const char *root, const char *driver, const struct sr_set *table,
                       char *out, size_t cap, size_t *used, int *fail)
{
    static char body[LGW_BUF];
    size_t bused = 0;
    for (int i = 0; i < table->count; i++) {
        char cmd[LGW_BUF];
        if (lgw_print_command(driver, table->n[i], cmd, sizeof cmd))
            return 2;
        if (cmd[0] == '\0')
            continue;
        int local_fail = 0;
        if (lgw_check_one_command(root, table->n[i], cmd, body, sizeof body, &bused,
                                  &local_fail))
            return 2;
    }
    if (bused == 0)
        return 0;
    *fail = 1;
    if (lgw_append(out, cap, used,
                   "FAIL: gate_command() entries naming a script that does not exist:\n"))
        return 2;
    if (lgw_appendf_pub(out, cap, used, "%s", body))
        return 2;
    return lgw_append(out, cap, used,
                      "\n  The case table is a string table — nothing type-checks these paths.\n"
                      "  Fix the path, or add the script.\n");
}

/* ── E: lintc family-file line ceiling ───────────────────────────────────── */
static int lgw_count_lines(const char *path, long *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    long n = 0;
    int c;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n')
            n++;
    int bad = ferror(f);
    fclose(f);
    if (bad)
        return die("z23-lint: read error on %s\n", path);
    *out = n;
    return 0;
}
static int lgw_read_ceiling(const char *lintc_h, long *out)
{
    FILE *f = fopen(lintc_h, "r");
    if (!f)
        return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    long found = -1;
    while (found < 0 && (n = getline(&line, &cap, f)) >= 0) {
        (void)n;
        const char *p = line;
        if (strncmp(p, "#define", 7) != 0)
            continue;
        p += 7;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, "LINT_FAMILY_CEILING", 19) != 0)
            continue;
        p += 19;
        while (*p == ' ' || *p == '\t')
            p++;
        if (isdigit((unsigned char)*p))
            found = atol(p);
    }
    int bad = ferror(f);
    free(line);
    fclose(f);
    if (bad)
        return die("z23-lint: read error on %s\n", lintc_h);
    *out = found;
    return found < 0 ? -2 : 0;
}
/* Appends "    <path> has <lines> lines (ceiling <ceiling>)\n" to `over`
 * for every tools/lint/lintc/gate_*.c file over `ceiling`. */
static int lgw_scan_family_files(const char *lintc_dir, long ceiling, char *over,
                                 size_t cap, size_t *used)
{
    DIR *d = opendir(lintc_dir);
    if (!d)
        return die("z23-lint: cannot open %s\n", lintc_dir);
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        const char *nm = de->d_name;
        size_t nl = strlen(nm);
        if (strncmp(nm, "gate_", 5) != 0 || nl < 3 || strcmp(nm + nl - 2, ".c") != 0)
            continue;
        char path[4096];
        if (ovf(snprintf(path, sizeof path, "%s/%s", lintc_dir, nm), sizeof path)) {
            rc = 2;
            break;
        }
        long lines = 0;
        rc = lgw_count_lines(path, &lines);
        if (rc)
            break;
        if (lines > ceiling)
            rc = lgw_appendf_pub(over, cap, used, "    %s has %ld lines (ceiling %ld)\n",
                                 path, lines, ceiling);
    }
    closedir(d);
    return rc;
}

static int lgw_check_e(const char *root, char *out, size_t cap, size_t *used, int *fail)
{
    char lintc_dir[4096], lintc_h[4160];
    if (ovf(snprintf(lintc_dir, sizeof lintc_dir, "%s/tools/lint/lintc", root),
            sizeof lintc_dir))
        return 2;
    struct stat st;
    if (stat(lintc_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    if (ovf(snprintf(lintc_h, sizeof lintc_h, "%s/lintc.h", lintc_dir), sizeof lintc_h))
        return 2;
    long ceiling = 0;
    int rc = lgw_read_ceiling(lintc_h, &ceiling);
    if (rc == -2) {
        *fail = 1;
        return lgw_appendf_pub(out, cap, used,
                           "FAIL: %s does not define LINT_FAMILY_CEILING.\n"
                           "      The family-file line budget exists exactly once, in that header;\n"
                           "      a tree where it cannot be read is a tree whose budget cannot be\n"
                           "      verified. Restore the definition.\n", lintc_h);
    }
    if (rc)
        return rc;
    static char over[LGW_BUF];
    size_t oused = 0;
    rc = lgw_scan_family_files(lintc_dir, ceiling, over, sizeof over, &oused);
    if (rc)
        return rc;
    if (oused == 0)
        return 0;
    *fail = 1;
    if (lgw_appendf_pub(out, cap, used,
                    "FAIL: lint-runtime family file(s) over the %ld-line ceiling:\n", ceiling))
        return 2;
    if (lgw_appendf_pub(out, cap, used, "%s", over))
        return 2;
    return lgw_append(out, cap, used,
                      "\n  'z23-lint --families' prints every family's headroom. Split the\n"
                      "  family or move the new gate to a family with room — the ceiling\n"
                      "  is what keeps each family file reviewable in one sitting.\n");
}

/* ── orchestration ───────────────────────────────────────────────────────── */
/* Existence of the three source files, plus 1 if any is missing (message
 * already printed to `out`). */
static int lgw_paths_exist(const char *makefile, const char *driver, const char *doc,
                           FILE *out)
{
    struct stat st;
    if (stat(makefile, &st) != 0) {
        fprintf(out, "FAIL: no Makefile at %s\n", makefile);
        return 1;
    }
    if (stat(driver, &st) != 0) {
        fprintf(out, "FAIL: no run_lint.sh at %s\n", driver);
        return 1;
    }
    if (stat(doc, &st) != 0) {
        fprintf(out, "FAIL: no %s\n", doc);
        return 1;
    }
    return 0;
}

/* Loads `doc` (the check-* tokens inside the DEFENSIVE_CODING.md
 * LINT-GATES block). Returns 0 ok, 1 rejected (message already printed),
 * 2 die()'d. */
static int lgw_load_doc_set(const char *doc, FILE *out, struct sr_set *docset)
{
    docset->count = 0;
    int rc = lgw_extract_doc_block(doc, docset);
    if (rc)
        return rc;
    if (docset->count == 0) {
        fprintf(out, "FAIL: missing or empty <!-- LINT-GATES-BEGIN/END --> block in %s\n",
               doc);
        fputs("      Add the canonical gate list so this gate can verify three-way\n"
             "      parity between the Makefile, run_lint.sh, and the doc.\n", out);
        return 1;
    }
    return 0;
}

/* Builds `listed` (LINT_GATES ∪ LINT_FAST_GATES) and `table` (the driver's
 * --list). Returns 0 ok, 1 rejected (message already printed), 2 die()'d. */
static int lgw_load_sets(const char *makefile, const char *driver, FILE *out,
                         struct sr_set *listed, struct sr_set *table)
{
    struct sr_set umbrella = { .count = 0 }, fastg = { .count = 0 };
    int rc = lgw_extract_var(makefile, "LINT_GATES", &umbrella);
    if (rc == 0)
        rc = lgw_extract_var(makefile, "LINT_FAST_GATES", &fastg);
    if (rc)
        return rc;
    if (umbrella.count == 0) {
        fprintf(out, "FAIL: LINT_GATES is empty or unparseable in %s\n", makefile);
        fputs("      This gate cannot verify wiring it cannot read. Fix the list shape\n"
             "      (a 'LINT_GATES := \\' block of backslash-continued check-* names).\n",
             out);
        return 1;
    }
    listed->count = 0;
    for (int i = 0; i < umbrella.count && rc == 0; i++)
        rc = sr_add(listed, umbrella.n[i]);
    for (int i = 0; i < fastg.count && rc == 0; i++)
        rc = sr_add(listed, fastg.n[i]);
    if (rc)
        return rc;
    table->count = 0;
    rc = lgw_driver_list(driver, table);
    if (rc)
        return rc;
    if (table->count == 0) {
        fprintf(out, "FAIL: '%s --list' produced no gate names.\n", driver);
        fputs("      Either the driver is broken or its --list self-grep no longer\n"
             "      matches its case labels. Both are worse than a missing entry.\n",
             out);
        return 1;
    }
    return 0;
}

static int lgw_run_checks(const char *root, const char *makefile, const char *driver,
                          const char *doc, const struct sr_set *listed,
                          const struct sr_set *table, const struct sr_set *docset,
                          char *faults, size_t cap, size_t *used, int *fail)
{
    if (lgw_check_a(listed, table, faults, cap, used, fail)) return 2;
    if (lgw_check_b(listed, table, faults, cap, used, fail)) return 2;
    if (lgw_check_c(makefile, listed, faults, cap, used, fail)) return 2;
    if (lgw_check_d(root, driver, table, faults, cap, used, fail)) return 2;
    if (lgw_check_e(root, faults, cap, used, fail)) return 2;
    if (lgw_check_f(listed, docset, doc, faults, cap, used, fail)) return 2;
    return lgw_check_g(listed, docset, doc, faults, cap, used, fail);
}

int lgw_check_root(const char *root, FILE *out)
{
    char makefile[4096], driver[4096], doc[4096];
    if (ovf(snprintf(makefile, sizeof makefile, "%s/Makefile", root), sizeof makefile)
        || ovf(snprintf(driver, sizeof driver, "%s/tools/lint/run_lint.sh", root),
              sizeof driver)
        || ovf(snprintf(doc, sizeof doc, "%s/docs/DEFENSIVE_CODING.md", root), sizeof doc))
        return 2;
    int rc = lgw_paths_exist(makefile, driver, doc, out);
    if (rc)
        return rc;

    struct sr_set listed, table, docset;
    rc = lgw_load_sets(makefile, driver, out, &listed, &table);
    if (rc == 0)
        rc = lgw_load_doc_set(doc, out, &docset);
    if (rc)
        return rc;

    static char faults[LGW_BUF];
    size_t used = 0;
    int fail = 0;
    rc = lgw_run_checks(root, makefile, driver, doc, &listed, &table, &docset, faults,
                        sizeof faults, &used, &fail);
    if (rc)
        return rc;

    if (used > 0)
        fputs(faults, out);
    if (fail)
        return 1;
    fprintf(out,
           "OK: lint gate wiring is complete \xe2\x80\x94 %d listed gate(s), %d table entry(ies), "
           "%d documented, exact parity.\n",
           listed.count, table.count, docset.count);
    return 0;
}

static int lgw_resolve_root(char *out, size_t cap)
{
    const char *ov = env_or("ZCL_GATE_WIRING_ROOT", "");
    if (ov[0])
        return ovf(snprintf(out, cap, "%s", ov), cap);
    return cic_repo_root(out, cap);
}

int check_lint_gate_wiring_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    if (lgw_resolve_root(root, sizeof root))
        return 2;
    return lgw_check_root(root, stdout);
}
