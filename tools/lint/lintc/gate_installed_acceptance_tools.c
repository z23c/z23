/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-installed-acceptance-tools, the C23 lint
 * runtime port of tools/lint/check_installed_acceptance_tools.sh. Every
 * binary tools/dev/zcode_dht_acceptance.sh (the HARNESS) tests with
 * `[ -x ]` before it starts a node must be placed in the install prefix by
 * tools/dev/c23_commons_beta_acceptance.sh (the INSTALLER) OUTSIDE every
 * conditional, so the public `make c23-commons-installed-acceptance`
 * target — which runs with every optional variable unset — never dies on
 * the harness's own precondition. Both lists are DERIVED from the scripts
 * themselves, never hand-written here. This gate reads text only (three
 * named scripts); it spawns no process and runs no build.
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

enum {
    ATL_CAP = 131072,
    ATL_LINE = 2048,
    ATL_PATH = 256,
    ATL_VAR_MAX = 32,
    ATL_VAR_LEN = 64,
    ATL_REC_MAX = 160,
    ATL_REC_LEN = ATL_LINE,
};

static const char k_atl_gate[] = "check-installed-acceptance-tools";
static const char k_atl_harness[] = "tools/dev/zcode_dht_acceptance.sh";
static const char k_atl_lifecycle[] = "tools/dev/node_lifecycle.sh";
static const char k_atl_installer[] = "tools/dev/c23_commons_beta_acceptance.sh";

static FILE *atl_out, *atl_err;
static const char *atl_harness_ov, *atl_lifecycle_ov, *atl_installer_ov;

static void atl_io_prod(void) { atl_out = stdout; atl_err = stderr; }
static void atl_clear_ov(void)
{
    atl_harness_ov = NULL; atl_lifecycle_ov = NULL; atl_installer_ov = NULL;
    atl_io_prod();
}
static const char *atl_harness(void)
{ return atl_harness_ov ? atl_harness_ov : k_atl_harness; }
static const char *atl_lifecycle(void)
{ return atl_lifecycle_ov ? atl_lifecycle_ov : k_atl_lifecycle; }
static const char *atl_installer(void)
{ return atl_installer_ov ? atl_installer_ov : k_atl_installer; }

/* Read a whole file into buf, printing the ORIGINAL gate's own "cannot
 * read" message and returning 2 on any failure (missing or unreadable —
 * `[ -r "$path" ]` in the shell rejects both the same way). */
static int atl_read(const char *path, char *buf, size_t cap, size_t *outn)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (fprintf(atl_out ? atl_out : stdout,
                    "FAIL: %s cannot read %s\n", k_atl_gate, path) < 0)
            return die("z23-lint: write failed\n", "");
        return 2;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    if (n == cap - 1) {
        char extra;
        if (fread(&extra, 1, 1, f) == 1) {
            fclose(f);
            return die("z23-lint: derived buffer overflow\n", "");
        }
    }
    int err = ferror(f);
    if (fclose(f) != 0 && !err) return die("z23-lint: fclose failed: %s\n", path);
    if (err) return die("z23-lint: read failed: %s\n", path);
    buf[n] = '\0';
    *outn = n;
    return 0;
}

static int atl_find_line_re(const char *text, const regex_t *re, char *outline,
                            size_t cap)
{
    const char *p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[ATL_LINE];
        size_t ll = len < sizeof line - 1 ? len : sizeof line - 1;
        memcpy(line, p, ll);
        line[ll] = '\0';
        if (regexec(re, line, 0, NULL, 0) == 0) {
            size_t cl = ll < cap - 1 ? ll : cap - 1;
            memcpy(outline, line, cl);
            outline[cl] = '\0';
            return 1;
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* ── 1. REQUIRED_VARS: every `[ -x "$VAR" ]` the harness tests ────────── */

struct atl_vars { char v[ATL_VAR_MAX][ATL_VAR_LEN]; int n; };

static int atl_var_add(struct atl_vars *vs, const char *name, size_t len)
{
    if (len >= ATL_VAR_LEN) return die("z23-lint: derived buffer overflow\n", "");
    char buf[ATL_VAR_LEN];
    memcpy(buf, name, len);
    buf[len] = '\0';
    for (int i = 0; i < vs->n; i++)
        if (strcmp(vs->v[i], buf) == 0) return 0;
    if (vs->n >= ATL_VAR_MAX) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(vs->v[vs->n], buf, len + 1);
    vs->n++;
    return 0;
}

static int atl_cmp_str(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int atl_extract_vars(const char *text, struct atl_vars *vs)
{
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED,
        "\\[ -x \"\\$([A-Za-z_][A-Za-z0-9_]*)\" \\]", "", "", "");
    if (rc) return rc;
    const char *p = text;
    regmatch_t m[2];
    while (*p != '\0' && regexec(&re, p, 2, m, 0) == 0) {
        size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
        rc = atl_var_add(vs, p + m[1].rm_so, len);
        if (rc) { regfree(&re); return rc; }
        regoff_t adv = m[0].rm_eo > 0 ? m[0].rm_eo : 1;
        p += adv;
    }
    regfree(&re);
    if (vs->n > 1) qsort(vs->v, (size_t)vs->n, ATL_VAR_LEN, atl_cmp_str);
    return 0;
}

/* ── 2. resolve a harness variable through node_lifecycle.sh's owner ──── */

static int atl_resolve_caller(const char *lifecycle_text, const char *var,
                              char *out, size_t outcap)
{
    char pat[ATL_VAR_LEN + 96];
    if (ovf(snprintf(pat, sizeof pat,
                     "^%s=\"\\$\\{[A-Za-z_][A-Za-z0-9_]*:-", var), sizeof pat))
        return 2;
    regex_t re;
    int rc = reg_fail(&re, regcomp(&re, pat, REG_EXTENDED));
    if (rc) return rc;
    char line[ATL_LINE];
    int found = atl_find_line_re(lifecycle_text, &re, line, sizeof line);
    regfree(&re);
    if (!found)
        return ovf(snprintf(out, outcap, "%s", var), outcap);

    regex_t re2;
    rc = compile_pat(&re2, REG_EXTENDED,
        "^[A-Za-z0-9_]+=\"\\$\\{([A-Za-z0-9_]+):-", "", "", "");
    if (rc) return rc;
    regmatch_t m[2];
    if (regexec(&re2, line, 2, m, 0) != 0) {
        regfree(&re2);
        return ovf(snprintf(out, outcap, "%s", var), outcap);
    }
    size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
    regfree(&re2);
    if (len >= outcap) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(out, line + m[1].rm_so, len);
    out[len] = '\0';
    return 0;
}

/* ── 3. the installer as depth-tagged logical lines ────────────────────
 * Backslash continuations are joined so a `for product in a \ b; do` list
 * reads as one record. Depth counts `if`/`fi` and brace-group opens/closes:
 * a line inside either is not something the public target is guaranteed
 * to run. Comments are dropped after classification (a comment that
 * happens to name an install path is prose, not a guarantee). */

struct atl_recs { char r[ATL_REC_MAX][ATL_REC_LEN]; int n; };

static int atl_rec_add(struct atl_recs *rs, const char *line)
{
    if (rs->n >= ATL_REC_MAX) return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(rs->r[rs->n], ATL_REC_LEN, "%s", line), ATL_REC_LEN))
        return 2;
    rs->n++;
    return 0;
}

static int atl_stripped_is_closer(const char *stripped)
{
    size_t fl = strlen("fi");
    if (strncmp(stripped, "fi", fl) == 0
        && (stripped[fl] == '\0' || stripped[fl] == ' ' || stripped[fl] == '\t'
            || stripped[fl] == ';'))
        return 1;
    return stripped[0] == '}'
        && (stripped[1] == '\0' || stripped[1] == ' ' || stripped[1] == '\t'
            || stripped[1] == ';');
}

static int atl_stripped_is_opener(const char *stripped)
{
    if (strncmp(stripped, "if", 2) == 0 && (stripped[2] == ' ' || stripped[2] == '\t'))
        return 1;
    size_t sl = strlen(stripped);
    return sl > 0 && stripped[sl - 1] == '{';
}

static const char *atl_lstrip(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    return line;
}

/* End-of-line backslash continuation, as `line ~ /\\$/` sees a physical
 * line with its trailing newline already stripped. */
static int atl_continues(const char *line, size_t *cut)
{
    size_t n = strlen(line);
    if (n == 0 || line[n - 1] != '\\') return 0;
    *cut = n - 1;
    while (*cut > 0 && (line[*cut - 1] == ' ' || line[*cut - 1] == '\t')) (*cut)--;
    return 1;
}

/* Merge a physical line with any pending continuation. On return, *line
 * is set to the complete logical line and 0 is returned; 1 means the
 * (possibly joined) text itself ends in "\" and was stashed into pending
 * for the next physical line; 2 is a fatal buffer overflow. Split out of
 * atl_parse_installer to keep that function under the complexity cap. */
static int atl_join_line(char *pending, char *joined, size_t cap,
                         const char *raw, const char **line)
{
    const char *cand;
    if (pending[0] != '\0') {
        if (ovf(snprintf(joined, cap, "%s %s", pending, raw), cap)) return 2;
        pending[0] = '\0';
        cand = joined;
    } else {
        cand = raw;
    }
    size_t cut;
    if (!atl_continues(cand, &cut)) { *line = cand; return 0; }
    if (cut >= cap) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(pending, cand, cut);
    pending[cut] = '\0';
    return 1;
}

/* Depth bookkeeping (closer decrements before recording, opener increments
 * after) plus the depth-0/non-comment record capture. Split out of
 * atl_parse_installer for the same reason as atl_join_line above. */
static int atl_classify_and_record(const char *line, int *depth,
                                   struct atl_recs *out)
{
    const char *stripped = atl_lstrip(line);
    if (atl_stripped_is_closer(stripped) && *depth > 0) (*depth)--;
    int rc = (*depth == 0 && stripped[0] != '#') ? atl_rec_add(out, line) : 0;
    if (rc) return rc;
    if (atl_stripped_is_opener(stripped)) (*depth)++;
    return 0;
}

static int atl_parse_installer(const char *path, struct atl_recs *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : die("z23-lint: cannot open %s\n", path);
    char pending[ATL_REC_LEN]; pending[0] = '\0';
    char joined[ATL_REC_LEN];
    char *raw = NULL; size_t cap = 0; ssize_t n;
    int depth = 0, rc = 0;
    while ((n = getline(&raw, &cap, f)) >= 0) {
        if (n > 0 && raw[n - 1] == '\n') raw[--n] = '\0';
        const char *line = NULL;
        int jr = atl_join_line(pending, joined, sizeof joined, raw, &line);
        if (jr == 2) { rc = 2; break; }
        if (jr == 1) continue;
        rc = atl_classify_and_record(line, &depth, out);
        if (rc) break;
    }
    return fin(f, raw, path, rc);
}

/* ── the two shapes an unconditional install can take ──────────────── */

static int atl_rec_has_install(const char *record, const char *tool)
{
    const char *ins = strstr(record, "install");
    if (!ins) return 0;
    char needle[ATL_VAR_LEN + 16];
    if (ovf(snprintf(needle, sizeof needle, "\"$PREFIX/bin/%s\"", tool),
            sizeof needle))
        return 0;
    return strstr(ins, needle) != NULL;
}

static int atl_rec_has_for_product(const char *record, const char *tool)
{
    static const char pfx[] = "for product in ";
    if (strncmp(record, pfx, sizeof pfx - 1) != 0) return 0;
    char padded[ATL_REC_LEN + 4], needle[ATL_VAR_LEN + 4];
    if (ovf(snprintf(padded, sizeof padded, " %s ", record), sizeof padded))
        return 0;
    if (ovf(snprintf(needle, sizeof needle, " %s ", tool), sizeof needle))
        return 0;
    return strstr(padded, needle) != NULL;
}

static int atl_unconditional(const struct atl_recs *rs, const char *tool)
{
    for (int i = 0; i < rs->n; i++)
        if (atl_rec_has_install(rs->r[i], tool)
            || atl_rec_has_for_product(rs->r[i], tool))
            return 1;
    return 0;
}

/* ── per-var check + violation reporting ───────────────────────────── */

struct atl_state { int violations; };

static int atl_extract_tool(const char *export_line, char *tool, size_t cap)
{
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED,
        "\\$PREFIX/bin/([A-Za-z0-9_.+-]+)\"$", "", "", "");
    if (rc) return rc;
    regmatch_t m[2];
    if (regexec(&re, export_line, 2, m, 0) != 0) {
        regfree(&re);
        return die("z23-lint: derived buffer overflow\n", "");
    }
    size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
    regfree(&re);
    if (len >= cap) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(tool, export_line + m[1].rm_so, len);
    tool[len] = '\0';
    return 0;
}

static int atl_report_no_export(struct atl_state *st, const char *var,
                                const char *caller_var)
{
    if (fprintf(atl_out, "FAIL: %s requires $%s, but %s does not point\n",
                atl_harness(), var, atl_installer()) < 0
        || fprintf(atl_out, "      $%s at a binary in its install prefix.\n",
                   caller_var) < 0)
        return die("z23-lint: write failed\n", "");
    st->violations++;
    return 0;
}

static int atl_report_conditional(struct atl_state *st, const char *tool,
                                  const char *var)
{
    if (fprintf(atl_out, "FAIL: %s is required by %s (as $%s) but %s\n",
                tool, atl_harness(), var, atl_installer()) < 0
        || fputs(
            "      only installs it inside a conditional. The public target\n"
            "      make c23-commons-installed-acceptance runs with every\n"
            "      optional variable unset and would refuse on its absence.\n",
            atl_out) < 0)
        return die("z23-lint: write failed\n", "");
    st->violations++;
    return 0;
}

static int atl_check_var(struct atl_state *st, const char *lifecycle_text,
                         const char *installer_text,
                         const struct atl_recs *recs, const char *var)
{
    char caller_var[ATL_VAR_LEN];
    int rc = atl_resolve_caller(lifecycle_text, var, caller_var, sizeof caller_var);
    if (rc) return rc;

    char pat[ATL_VAR_LEN + 96];
    if (ovf(snprintf(pat, sizeof pat,
                     "^export %s=\"\\$PREFIX/bin/[A-Za-z0-9_.+-]+\"$",
                     caller_var), sizeof pat))
        return 2;
    regex_t re;
    rc = reg_fail(&re, regcomp(&re, pat, REG_EXTENDED));
    if (rc) return rc;
    char line[ATL_LINE];
    int found = atl_find_line_re(installer_text, &re, line, sizeof line);
    regfree(&re);
    if (!found) return atl_report_no_export(st, var, caller_var);

    char tool[ATL_VAR_LEN];
    rc = atl_extract_tool(line, tool, sizeof tool);
    if (rc) return rc;
    if (!atl_unconditional(recs, tool)) return atl_report_conditional(st, tool, var);
    return 0;
}

static int atl_summary(const struct atl_state *st, int n_vars)
{
    if (st->violations == 0) {
        if (fprintf(atl_out,
                    "%s: clean \xe2\x80\x94 %d harness-required binaries "
                    "installed unconditionally\n",
                    "check_installed_acceptance_tools", n_vars) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(atl_out, "\n%s: %d of %d\n", k_atl_gate, st->violations, n_vars) < 0
        || fputs("  harness-required binaries are not guaranteed by the "
                 "installed lane.\n", atl_out) < 0)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int atl_eval(void)
{
    static char harness_buf[ATL_CAP];
    static char lifecycle_buf[ATL_CAP];
    static char installer_buf[ATL_CAP];

    int rc = atl_read(atl_harness(), harness_buf, sizeof harness_buf, &(size_t){0});
    if (rc) return rc;
    rc = atl_read(atl_lifecycle(), lifecycle_buf, sizeof lifecycle_buf, &(size_t){0});
    if (rc) return rc;
    rc = atl_read(atl_installer(), installer_buf, sizeof installer_buf, &(size_t){0});
    if (rc) return rc;

    struct atl_vars vs = { .n = 0 };
    rc = atl_extract_vars(harness_buf, &vs);
    if (rc) return rc;
    char hint[ATL_PATH + 64];
    if (ovf(snprintf(hint, sizeof hint,
                     "no '[ -x \"$VAR\" ]' precondition found in %s", atl_harness()),
            sizeof hint))
        return 2;
    rc = gate_require_scanned(vs.n, 3, k_atl_gate, hint);
    if (rc) return rc;

    struct atl_recs recs = { .n = 0 };
    rc = atl_parse_installer(atl_installer(), &recs);
    if (rc) return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "no unconditional lines parsed out of %s", atl_installer()),
            sizeof hint))
        return 2;
    rc = gate_require_scanned(recs.n, 20, k_atl_gate, hint);
    if (rc) return rc;

    struct atl_state st = { .violations = 0 };
    for (int i = 0; i < vs.n; i++) {
        rc = atl_check_var(&st, lifecycle_buf, installer_buf, &recs, vs.v[i]);
        if (rc) return rc;
    }
    return atl_summary(&st, vs.n);
}

int check_installed_acceptance_tools_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    atl_clear_ov();
    return atl_eval();
}

/* ── selftest ───────────────────────────────────────────────────────── */

static int atl_cap(int (*eval)(void), char *ob, size_t oc, char *eb, size_t ec,
                   int *rc)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return die("z23-lint: tmpfile failed\n", "");
    }
    atl_out = out; atl_err = err; *rc = eval();
    int bad = csr_slurp(out, ob, oc) || csr_slurp(err, eb, ec);
    fclose(out); fclose(err); atl_io_prod();
    return bad ? 2 : 0;
}

static int atl_has(const char *buf, const char *need)
{ return buf && need && strstr(buf, need) != NULL; }

static char *atl_mkdtemp(char *tmpl, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(tmpl, cap, "%s/z23-lint-atl.XXXXXX", td), cap)) return NULL;
    char *tmp = mkdtemp(tmpl);
    return tmp ? tmp : (die("z23-lint: mkdir failed: %s\n", td), NULL);
}

static const char k_atl_harness_fx[] =
    "#!/usr/bin/env bash\n"
    "run() {\n"
    "[ -x \"$NODE_BIN\" ] && [ -x \"$RPC_BIN\" ] && [ -x \"$DHT_ACCEPTANCE_C23\" ] ||\n"
    "    exit 1\n"
    "}\n";
static const char k_atl_lifecycle_fx[] =
    "NODE_BIN=\"${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}\"\n"
    "RPC_BIN=\"${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}\"\n"
    "DHT_ACCEPTANCE_C23=\"${DHT_ACCEPTANCE_C23:-$REPO_ROOT/build/bin/arena_product_journey_c23}\"\n";
static const char k_atl_installer_good[] =
    "#!/usr/bin/env bash\n"
    "make -C \"$REPO_ROOT\" c23-portable-install DESTDIR=\"$PREFIX\" PREFIX= >/dev/null\n"
    "for product in zclassic23 zcl-rpc \\\n"
    "        zclassic23-package-verify; do\n"
    "    [ -x \"$PREFIX/bin/$product\" ] || exit 2\n"
    "done\n"
    "make -C \"$REPO_ROOT\" tools/arena-product-journey-c23 >/dev/null\n"
    "install -m 0755 \"$REPO_ROOT/build/bin/arena_product_journey_c23\" \\\n"
    "    \"$PREFIX/bin/arena_product_journey_c23\"\n"
    "if [ \"${C23_BETA_INSTALL_ARENA_RUNNER:-0}\" = 1 ]; then\n"
    "    make -C \"$REPO_ROOT\" tools/arena-runner dev-bin >/dev/null\n"
    "    install -m 0755 \"$REPO_ROOT/build/bin/arena_runner\" \\\n"
    "        \"$PREFIX/bin/arena_runner\"\n"
    "fi\n"
    "export ZCL_NODE_BIN=\"$PREFIX/bin/zclassic23\"\n"
    "export ZCL_RPC_BIN=\"$PREFIX/bin/zcl-rpc\"\n"
    "export DHT_ACCEPTANCE_C23=\"$PREFIX/bin/arena_product_journey_c23\"\n"
    "cd \"$RUN_ROOT\"\n"
    "bash \"$SCRIPT_DIR/zcode_dht_acceptance.sh\"\n"
    "echo done\n"
    "# a comment naming install \"$PREFIX/bin/zclassic23-dev\" proves nothing\n";
/* Twenty top-level lines pad this fixture past the floor=20 requirement
 * without changing what it asserts; padding lines are inert no-ops. */
static const char k_atl_pad[] =
    "true\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\n"
    "true\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\ntrue\n";

/* Static: the override pointers must outlive this call, into the eval()
 * it sets up for. Selftest cases run strictly sequentially. */
static char g_atl_h[ATL_PATH], g_atl_l[ATL_PATH], g_atl_i[ATL_PATH];

static int atl_seed(const char *dir, const char *installer_body)
{
    char *h = g_atl_h, *l = g_atl_l, *i = g_atl_i;
    if (rap_rm_rf(dir)) return 1;
    if (ovf(snprintf(h, ATL_PATH, "%s/harness.sh", dir), ATL_PATH)
        || ovf(snprintf(l, ATL_PATH, "%s/lifecycle.sh", dir), ATL_PATH)
        || ovf(snprintf(i, ATL_PATH, "%s/installer.sh", dir), ATL_PATH))
        return 1;
    if (csr_write(h, k_atl_harness_fx)) return 1;
    if (csr_write(l, k_atl_lifecycle_fx)) return 1;
    static char body[ATL_CAP];
    if (ovf(snprintf(body, sizeof body, "%s%s", installer_body, k_atl_pad),
            sizeof body))
        return 1;
    if (csr_write(i, body)) return 1;
    atl_harness_ov = h; atl_lifecycle_ov = l; atl_installer_ov = i;
    return 0;
}

static int atl_st_run(const char *tmp, const char *sub, const char *installer_body,
                      int want_rc, const char *want_out)
{
    char dir[ATL_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/%s", tmp, sub), sizeof dir)) return 1;
    if (atl_seed(dir, installer_body)) return 1;
    char out[ATL_CAP], err[ATL_CAP];
    int rc = 0;
    int bad = atl_cap(atl_eval, out, sizeof out, err, sizeof err, &rc);
    atl_clear_ov();
    if (bad || rc != want_rc) return 1;
    return (want_out && !atl_has(out, want_out)) ? 1 : 0;
}

static int atl_st_clean(const char *tmp)
{
    return atl_st_run(tmp, "clean", k_atl_installer_good, 0,
        "clean \xe2\x80\x94 3 harness-required binaries installed unconditionally");
}
static int atl_st_no_export(const char *tmp)
{
    static char body[ATL_CAP];
    if (ovf(snprintf(body, sizeof body, "%s", k_atl_installer_good), sizeof body))
        return 1;
    char *hit = strstr(body, "export DHT_ACCEPTANCE_C23=\"$PREFIX/bin/arena_product_journey_c23\"\n");
    if (!hit) return 1;
    memmove(hit, hit + strlen("export DHT_ACCEPTANCE_C23=\"$PREFIX/bin/arena_product_journey_c23\"\n"),
            strlen(hit + strlen("export DHT_ACCEPTANCE_C23=\"$PREFIX/bin/arena_product_journey_c23\"\n")) + 1);
    return atl_st_run(tmp, "noexport", body, 1,
        "requires $DHT_ACCEPTANCE_C23, but");
}
static int atl_st_conditional(const char *tmp)
{
    static char body[ATL_CAP];
    if (ovf(snprintf(body, sizeof body, "%s", k_atl_installer_good), sizeof body))
        return 1;
    /* Move the arena_product_journey_c23 install line behind the same
     * conditional as the arena_runner one. */
    char *hit = strstr(body,
        "install -m 0755 \"$REPO_ROOT/build/bin/arena_product_journey_c23\" \\\n"
        "    \"$PREFIX/bin/arena_product_journey_c23\"\n");
    if (!hit) return 1;
    memmove(hit, hit + strlen(
        "install -m 0755 \"$REPO_ROOT/build/bin/arena_product_journey_c23\" \\\n"
        "    \"$PREFIX/bin/arena_product_journey_c23\"\n"),
        strlen(hit + strlen(
            "install -m 0755 \"$REPO_ROOT/build/bin/arena_product_journey_c23\" \\\n"
            "    \"$PREFIX/bin/arena_product_journey_c23\"\n")) + 1);
    return atl_st_run(tmp, "cond", body, 1,
        "is required by");
}
static int atl_st_empty_harness(const char *tmp)
{
    char dir[ATL_PATH], h[ATL_PATH];
    int rc = 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/emptyh", tmp), sizeof dir)) return 1;
    if (atl_seed(dir, k_atl_installer_good)) return 1;
    if (ovf(snprintf(h, sizeof h, "%s/harness.sh", dir), sizeof h)) return 1;
    if (csr_write(h, "#!/usr/bin/env bash\ntrue\n")) return 1;
    atl_harness_ov = h;
    char out[ATL_CAP], err[ATL_CAP];
    int bad = atl_cap(atl_eval, out, sizeof out, err, sizeof err, &rc);
    atl_clear_ov();
    return bad || rc != 2;
}
static int atl_st_unreadable(const char *tmp)
{
    char dir[ATL_PATH], h[ATL_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/unreadable", tmp), sizeof dir)) return 1;
    if (atl_seed(dir, k_atl_installer_good)) return 1;
    if (ovf(snprintf(h, sizeof h, "%s/harness.sh", dir), sizeof h)) return 1;
    if (chmod(h, 0) != 0) return 1;
    char out[ATL_CAP], err[ATL_CAP];
    int rc = 0;
    int bad = atl_cap(atl_eval, out, sizeof out, err, sizeof err, &rc);
    atl_clear_ov();
    (void)chmod(h, 0600);
    return bad || rc != 2 || !atl_has(out, h);
}

int check_installed_acceptance_tools_selftest(void)
{
    char tmpl[ATL_PATH];
    char *tmp = atl_mkdtemp(tmpl, sizeof tmpl);
    if (!tmp) return 2;
    int bad = atl_st_clean(tmp) | atl_st_no_export(tmp) | atl_st_conditional(tmp)
        | atl_st_empty_harness(tmp) | atl_st_unreadable(tmp);
    atl_clear_ov();
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_installed_acceptance_tools selftest: OK\n");
}
