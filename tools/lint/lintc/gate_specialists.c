/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-specialists lint gate of the C23 lint
 * runtime. Replaces tools/lint/check_specialists.sh: every SPECIALIST(...)
 * row in engine/composition/specialists.def must carry five strings (name,
 * territory, gates, test_groups, fact_kinds); every territory token must
 * match a tracked file, every gate token must be a real Makefile lint gate,
 * and every test-group token must resolve in
 * tools/dev/test_group_catalog.def. Production scan probes for a .git
 * directory and reads it natively via lint_git_index_foreach; a sandbox or
 * archive tree without .git (git archive HEAD, or the make_lint_gates
 * fixture) falls back to a plain filesystem walk instead.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    SPC_PATH = 768, SPC_LIT = 512, SPC_RAW = 8192, SPC_ROWS = 128,
    SPC_MAXLIT = 8, SPC_FAULT_CAP = 65536, SPC_FAULT_LINE = 640,
    SPC_CAT_BUF = 131072
};

struct spc_row { char lit[5][SPC_LIT]; int malformed; };
struct spc_rows { struct spc_row row[SPC_ROWS]; int n; };

/* ── small text utilities (local to this family; nothing shared) ────── */

static int spc_is_file(const char *path)
{ struct stat st; return stat(path, &st) == 0 && S_ISREG(st.st_mode); }

static int spc_gate_char(char c)
{ return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; }

static int spc_add_fault(char *faults, size_t cap, size_t *used, int *n,
                         const char *line)
{
    int k = snprintf(faults + *used, cap - *used, "%s%s", *used ? "\n" : "", line);
    if (ovf(k, cap - *used)) return 2;
    *used += (size_t)k;
    (*n)++;
    return 0;
}

/* ── SPECIALIST(...) parser: mirrors the awk collector in the original
 * script — collect physical lines from "SPECIALIST(" to a line ending in
 * ")" (trailing whitespace allowed), then peel off double-quoted string
 * literals in order. A block that does not carry exactly five is
 * MALFORMED, same as upstream. ────────────────────────────────────────── */

static int spc_take_lit(const char **rest, char *dst, size_t cap)
{
    const char *p = *rest;
    while (*p && *p != '"') p++;
    if (*p != '"') return 0;
    p++;
    size_t n = 0;
    while (*p) {
        if (*p == '\\' && p[1]) {
            if (n + 2 >= cap) return -1;
            dst[n++] = *p++;
            dst[n++] = *p++;
            continue;
        }
        if (*p == '"') { dst[n] = '\0'; *rest = p + 1; return 1; }
        if (n + 1 >= cap) return -1;
        dst[n++] = *p++;
    }
    return -1;
}

static int spc_close_row(const char *call, struct spc_rows *out)
{
    if (out->n >= SPC_ROWS)
        return die("z23-lint: derived buffer overflow\n", "");
    struct spc_row *row = &out->row[out->n];
    char tmp[SPC_MAXLIT][SPC_LIT];
    const char *r = call;
    int n_lit = 0;
    for (; n_lit < SPC_MAXLIT; n_lit++) {
        int k = spc_take_lit(&r, tmp[n_lit], SPC_LIT);
        if (k == 0) break;
        if (k < 0) return die("z23-lint: derived buffer overflow\n", "");
    }
    row->malformed = (n_lit != 5);
    if (!row->malformed)
        for (int i = 0; i < 5; i++)
            memcpy(row->lit[i], tmp[i], SPC_LIT);
    out->n++;
    return 0;
}

static int spc_parse_rows(const char *text, struct spc_rows *out)
{
    static const char prefix[] = "SPECIALIST(";
    size_t plen = sizeof prefix - 1;
    out->n = 0;
    int collecting = 0;
    char call[SPC_RAW];
    size_t used = 0;
    const char *p = text;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n') eol++;
        size_t linelen = (size_t)(eol - p);
        size_t trim = linelen;
        while (trim && isspace((unsigned char)p[trim - 1])) trim--;
        int closes = trim && p[trim - 1] == ')';
        if (!collecting && linelen >= plen && memcmp(p, prefix, plen) == 0) {
            collecting = 1;
            used = 0;
        }
        if (collecting) {
            if (used + linelen >= sizeof call)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(call + used, p, linelen);
            used += linelen;
            call[used] = '\0';
            if (closes) {
                collecting = 0;
                if (spc_close_row(call, out)) return 2;
            }
        }
        p = *eol == '\n' ? eol + 1 : eol;
    }
    return 0;
}

/* ── Makefile gate-name set: LINT_GATES / LINT_FAST_GATES variable
 * blocks plus every `check-*:` target — streamed line by line so a
 * multi-thousand-line Makefile never needs slurping. ─────────────────── */

static int spc_opens_var(const char *line, const char *var)
{
    size_t vlen = strlen(var);
    if (strncmp(line, var, vlen) != 0) return 0;
    const char *p = line + vlen;
    while (*p == ' ' || *p == '\t') p++;
    return p[0] == ':' && p[1] == '=';
}

static int spc_continues(const char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    return n > 0 && line[n - 1] == '\\';
}

static int spc_target_len(const char *line)
{
    if (strncmp(line, "check-", 6) != 0) return 0;
    size_t n = 6;
    while (spc_gate_char(line[n])) n++;
    return (n > 6 && line[n] == ':') ? (int)n : 0;
}

static int spc_extract_tokens(const char *line, struct sr_set *out)
{
    const char *p = line;
    while ((p = strstr(p, "check-")) != NULL) {
        size_t n = 6;
        while (spc_gate_char(p[n])) n++;
        if (n > 6) {
            char tok[SR_NAME];
            if (n >= sizeof tok) return die("z23-lint: derived buffer overflow\n", "");
            memcpy(tok, p, n);
            tok[n] = '\0';
            if (sr_add(out, tok)) return 2;
        }
        p += n;
    }
    return 0;
}

static int spc_load_makefile_gates(const char *path, struct sr_set *out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[check_specialists] UNPROVEN — cannot open %s\n", path);
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int rc = 0, in_var = 0;
    while (rc == 0 && (len = getline(&line, &cap, f)) >= 0) {
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (!in_var && (spc_opens_var(line, "LINT_GATES")
                         || spc_opens_var(line, "LINT_FAST_GATES")))
            in_var = 1;
        if (in_var) {
            rc = spc_extract_tokens(line, out);
            if (rc == 0 && !spc_continues(line)) in_var = 0;
        } else {
            int tlen = spc_target_len(line);
            if (tlen) {
                char tok[SR_NAME];
                if ((size_t)tlen >= sizeof tok)
                    rc = die("z23-lint: derived buffer overflow\n", "");
                else {
                    memcpy(tok, line, (size_t)tlen);
                    tok[tlen] = '\0';
                    rc = sr_add(out, tok);
                }
            }
        }
    }
    return fin(f, line, path, rc);
}

/* ── territory resolution: a token with no glob metachar matches a
 * tracked/walked path equal to it or beneath it; a glob token is matched
 * with fnmatch(). Production reads .git/index natively; a tree with no
 * .git (archive or sandbox) is walked directly instead — never spawns a
 * process either way. ─────────────────────────────────────────────────── */

struct spc_match { const char *tok; int is_glob, found; };
static int spc_walk(const char *root, const char *rel, struct spc_match *m);

static int spc_path_matches(const char *path, const struct spc_match *m)
{
    if (m->is_glob) return fnmatch(m->tok, path, 0) == 0;
    size_t n = strlen(m->tok);
    if (strncmp(path, m->tok, n) != 0) return 0;
    return path[n] == '\0' || path[n] == '/';
}

static int spc_idx_cb(const char *path, int stage, void *ctxp)
{
    if (stage != 0) return 0;
    struct spc_match *m = ctxp;
    if (!spc_path_matches(path, m)) return 0;
    m->found = 1;
    return 1;
}

static int spc_skip_dir(const char *name)
{
    return !strcmp(name, ".git") || !strcmp(name, "build")
        || !strcmp(name, "vendor") || !strcmp(name, ".claude")
        || !strcmp(name, "test-tmp");
}

static int spc_walk_entry(const char *root, const char *dir, const char *rel,
                          const char *nm, struct spc_match *m)
{
    char relpath[SPC_PATH], abspath[4096];
    int k1 = snprintf(relpath, sizeof relpath, "%s%s%s", rel, rel[0] ? "/" : "", nm);
    int k2 = snprintf(abspath, sizeof abspath, "%s/%s", dir, nm);
    if (ovf(k1, sizeof relpath) || ovf(k2, sizeof abspath)) return 2;
    struct stat st;
    if (lstat(abspath, &st) != 0)
        return die("z23-lint: cannot stat %s\n", abspath);
    if (S_ISDIR(st.st_mode))
        return spc_walk(root, relpath, m);
    if (S_ISREG(st.st_mode) && spc_path_matches(relpath, m))
        m->found = 1;
    return 0;
}

static int spc_walk(const char *root, const char *rel, struct spc_match *m)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s%s%s", root, rel[0] ? "/" : "", rel),
            sizeof dir))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        if (rc == 0 && !m->found) {
            const char *nm = names[i]->d_name;
            if (strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0
                && !spc_skip_dir(nm))
                rc = spc_walk_entry(root, dir, rel, nm, m);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int spc_has_git(const char *root)
{
    char p[SPC_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/.git", root), sizeof p)) return 0;
    struct stat st;
    return stat(p, &st) == 0;
}

static int spc_territory_matches(const char *root, int has_git,
                                 const char *tok, int *matched)
{
    struct spc_match m = { tok, strpbrk(tok, "*?[") != NULL, 0 };
    if (has_git) {
        char badext[5] = "";
        int rc = lint_git_index_foreach(spc_idx_cb, &m, badext);
        if (rc == 2 || badext[0]) {
            fprintf(stderr,
                "[check_specialists] UNPROVEN — the git index carries a\n"
                "  mandatory extension this native reader does not\n"
                "  interpret; refusing to grade.\n");
            return 2;
        }
    } else {
        int rc = spc_walk(root, "", &m);
        if (rc == 2) return 2;
    }
    *matched = m.found;
    return 0;
}

/* ── group-catalog resolution: same regex the shell gate used, run over
 * the slurped catalog text with REG_NEWLINE so ^/$ anchor per line. ───── */

static int spc_group_resolves(const char *tok, const char *cat_text)
{
    char pat[SR_NAME + 40];
    if (ovf(snprintf(pat, sizeof pat, "^ZCL_(TEST|SPEC)_GROUP\\(%s\\)", tok),
            sizeof pat))
        return -1;
    regex_t re;
    if (regcomp(&re, pat, REG_EXTENDED | REG_NEWLINE) != 0) return -1;
    int hit = regexec(&re, cat_text, 0, NULL, 0) == 0;
    regfree(&re);
    return hit;
}

/* ── row-by-row fault assembly, in the same order the shell scan()
 * emitted them: malformed, duplicate name, empty territory, territory
 * tokens, gate tokens, group tokens, empty fact_kinds. ─────────────────── */

static int spc_check_territory(const char *root, int has_git, const char *name,
                               const char *terr, char *faults, size_t cap,
                               size_t *used, int *nf)
{
    char buf[SPC_LIT];
    memcpy(buf, terr, SPC_LIT);
    char *save = NULL;
    for (char *tok = strtok_r(buf, "|", &save); tok; tok = strtok_r(NULL, "|", &save)) {
        int matched = 0;
        if (spc_territory_matches(root, has_git, tok, &matched)) return 2;
        if (!matched) {
            char line[SPC_FAULT_LINE];
            if (ovf(snprintf(line, sizeof line,
                             "  %s: territory '%s' matches no tracked file", name, tok),
                    sizeof line)
                || spc_add_fault(faults, cap, used, nf, line))
                return 2;
        }
    }
    return 0;
}

static int spc_check_gates(const char *name, const char *gates,
                           const struct sr_set *gate_set, char *faults,
                           size_t cap, size_t *used, int *nf)
{
    char buf[SPC_LIT];
    memcpy(buf, gates, SPC_LIT);
    char *save = NULL;
    for (char *tok = strtok_r(buf, "|", &save); tok; tok = strtok_r(NULL, "|", &save)) {
        if (!sr_has(gate_set, tok)) {
            char line[SPC_FAULT_LINE];
            if (ovf(snprintf(line, sizeof line,
                             "  %s: gate '%s' is not a Makefile lint gate", name, tok),
                    sizeof line)
                || spc_add_fault(faults, cap, used, nf, line))
                return 2;
        }
    }
    return 0;
}

static int spc_check_groups(const char *name, const char *groups,
                            const char *cat_text, char *faults, size_t cap,
                            size_t *used, int *nf)
{
    char buf[SPC_LIT];
    memcpy(buf, groups, SPC_LIT);
    char *save = NULL;
    for (char *tok = strtok_r(buf, "|", &save); tok; tok = strtok_r(NULL, "|", &save)) {
        int hit = spc_group_resolves(tok, cat_text);
        if (hit < 0) return die("z23-lint: derived buffer overflow\n", "");
        if (!hit) {
            char line[SPC_FAULT_LINE];
            if (ovf(snprintf(line, sizeof line,
                             "  %s: test group '%s' is not in test_group_catalog.def",
                             name, tok), sizeof line)
                || spc_add_fault(faults, cap, used, nf, line))
                return 2;
        }
    }
    return 0;
}

static int spc_scan_row(const char *root, int has_git, const struct spc_row *row,
                        const struct sr_set *gate_set, const char *cat_text,
                        struct sr_set *seen, char *faults, size_t cap,
                        size_t *used, int *nf)
{
    if (row->malformed)
        return spc_add_fault(faults, cap, used, nf,
                             "  a SPECIALIST row does not carry five strings");
    const char *name = row->lit[0], *terr = row->lit[1], *gates = row->lit[2],
              *groups = row->lit[3], *facts = row->lit[4];
    if (!name[0]) return 0;
    if (sr_has(seen, name)) {
        char line[SPC_FAULT_LINE];
        if (ovf(snprintf(line, sizeof line,
                         "  %s: a second row for a specialist that already has one",
                         name), sizeof line)
            || spc_add_fault(faults, cap, used, nf, line))
            return 2;
    }
    if (sr_add(seen, name)) return 2;
    if (!terr[0]) {
        char line[SPC_FAULT_LINE];
        return ovf(snprintf(line, sizeof line, "  %s: empty territory", name), sizeof line)
            || spc_add_fault(faults, cap, used, nf, line);
    }
    if (spc_check_territory(root, has_git, name, terr, faults, cap, used, nf)) return 2;
    if (spc_check_gates(name, gates, gate_set, faults, cap, used, nf)) return 2;
    if (spc_check_groups(name, groups, cat_text, faults, cap, used, nf)) return 2;
    if (!facts[0]) {
        char line[SPC_FAULT_LINE];
        if (ovf(snprintf(line, sizeof line, "  %s: empty fact_kinds", name), sizeof line)
            || spc_add_fault(faults, cap, used, nf, line))
            return 2;
    }
    return 0;
}

static int spc_scan(const char *root, int has_git, const struct spc_rows *rows,
                    const struct sr_set *gate_set, const char *cat_text,
                    char *faults, size_t cap, int *nf)
{
    *nf = 0;
    faults[0] = '\0';
    size_t used = 0;
    struct sr_set seen = {0};
    for (int i = 0; i < rows->n; i++)
        if (spc_scan_row(root, has_git, &rows->row[i], gate_set, cat_text,
                         &seen, faults, cap, &used, nf))
            return 2;
    return 0;
}

/* ── entry point ──────────────────────────────────────────────────────── */

static int spc_slurp_checked(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[check_specialists] UNPROVEN — cannot open %s\n", path);
        return 2;
    }
    int rc = csr_slurp(f, buf, cap);
    return fin(f, NULL, path, rc);
}

static int spc_require_inputs(const char *def_path, const char *cat_path, const char *mk_path)
{
    if (!spc_is_file(def_path)) {
        fprintf(stderr, "[check_specialists] FATAL — %s is missing; "
                        "refusing to report a clean scan\n", def_path);
        return 2;
    }
    if (!spc_is_file(cat_path)) {
        fprintf(stderr, "[check_specialists] FATAL — %s is missing\n", cat_path);
        return 2;
    }
    if (!spc_is_file(mk_path)) {
        fprintf(stderr, "[check_specialists] FATAL — %s is missing\n", mk_path);
        return 2;
    }
    return 0;
}

static int spc_report(int nf, int row_count, const char *faults)
{
    if (nf > 0) {
        if (printf("[check_specialists] FAIL — specialist catalog has false rows:\n%s\n",
                   faults) < 0)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (printf("[check_specialists] OK — %d specialists; "
              "every territory, gate and test group resolves\n", row_count) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_specialists_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *root = env_or("ZCL_SPECIALISTS_ROOT", ".");
    const char *def_rel = env_or("ZCL_SPECIALISTS_DEF", "engine/composition/specialists.def");
    int floor_v = atoi(env_or("ZCL_SPECIALISTS_FLOOR", "10"));
    char def_path[SPC_PATH], cat_path[SPC_PATH], mk_path[SPC_PATH];
    if (ovf(snprintf(def_path, sizeof def_path, "%s/%s", root, def_rel), sizeof def_path)
        || ovf(snprintf(cat_path, sizeof cat_path, "%s/tools/dev/test_group_catalog.def",
                        root), sizeof cat_path)
        || ovf(snprintf(mk_path, sizeof mk_path, "%s/Makefile", root), sizeof mk_path))
        return 2;

    if (spc_require_inputs(def_path, cat_path, mk_path)) return 2;

    static char def_text[65536];
    if (spc_slurp_checked(def_path, def_text, sizeof def_text)) return 2;

    struct spc_rows rows;
    if (spc_parse_rows(def_text, &rows)) return 2;

    if (rows.n < floor_v) {
        fprintf(stderr,
            "[check_specialists] FATAL — %d specialist rows is below the floor of %d\n"
            "        A catalog that stopped parsing must never read as clean.\n",
            rows.n, floor_v);
        return 2;
    }

    struct sr_set gate_set = {0};
    if (spc_load_makefile_gates(mk_path, &gate_set)) return 2;

    static char cat_text[SPC_CAT_BUF];
    if (spc_slurp_checked(cat_path, cat_text, sizeof cat_text)) return 2;

    int has_git = spc_has_git(root);
    static char faults[SPC_FAULT_CAP];
    int nf = 0;
    if (spc_scan(root, has_git, &rows, &gate_set, cat_text, faults, sizeof faults, &nf))
        return 2;

    return spc_report(nf, rows.n, faults);
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static int spc_hush_run(void)
{
    fflush(stdout);
    fflush(stderr);
    int n = open("/dev/null", O_WRONLY), o = dup(1), e = dup(2);
    if (n < 0 || o < 0 || e < 0) return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(n, 1) >= 0 && dup2(n, 2) >= 0) rc = check_specialists_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    (void)dup2(o, 1); (void)dup2(e, 2);
    close(n); close(o); close(e);
    return rc;
}

static int spc_run_stub(const char *root, int floor_v)
{
    char fb[16];
    if (ovf(snprintf(fb, sizeof fb, "%d", floor_v), sizeof fb)) return 2;
    if (setenv("ZCL_SPECIALISTS_ROOT", root, 1) != 0
        || setenv("ZCL_SPECIALISTS_FLOOR", fb, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    int rc = spc_hush_run();
    (void)unsetenv("ZCL_SPECIALISTS_ROOT");
    (void)unsetenv("ZCL_SPECIALISTS_FLOOR");
    (void)unsetenv("ZCL_SPECIALISTS_DEF");
    return rc;
}

static int spc_write(const char *path, const char *text)
{ return csr_write(path, text); }

static int spc_selftest_case(const char *stub, const char *def_body, int want_ok,
                             const char *label, int *fails)
{
    char def_path[SPC_PATH];
    if (ovf(snprintf(def_path, sizeof def_path, "%s/engine/composition/specialists.def",
                     stub), sizeof def_path))
        return 2;
    if (spc_write(def_path, def_body)) return 2;
    int rc = spc_run_stub(stub, 1);
    int ok = (rc == 0);
    if (ok != want_ok) {
        fprintf(stderr, "check_specialists: SELFTEST FAILED — %s\n", label);
        (*fails)++;
    } else if (printf("  selftest ok: %s\n", label) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int spc_selftest_fixture(const char *stub)
{
    char d1[4096], d2[4096], d3[4096];
    if (ovf(snprintf(d1, sizeof d1, "%s/core/consensus", stub), sizeof d1)
        || ovf(snprintf(d2, sizeof d2, "%s/tools/dev", stub), sizeof d2)
        || ovf(snprintf(d3, sizeof d3, "%s/engine/composition", stub), sizeof d3)
        || csr_mkdirs(d1) || csr_mkdirs(d2) || csr_mkdirs(d3))
        return 1;

    char consensus_c[4096], mk[4096], cat[4096];
    if (ovf(snprintf(consensus_c, sizeof consensus_c, "%s/x.c", d1), sizeof consensus_c)
        || spc_write(consensus_c, "int x;\n")
        || ovf(snprintf(mk, sizeof mk, "%s/Makefile", stub), sizeof mk)
        || spc_write(mk, "LINT_GATES := \\\n    check-consensus-parity\n"
                        "check-consensus-parity:\n\t@true\n")
        || ovf(snprintf(cat, sizeof cat, "%s/test_group_catalog.def", d2), sizeof cat)
        || spc_write(cat, "ZCL_TEST_GROUP(consensus)\n"))
        return 1;
    return 0;
}

static void spc_selftest_bad_rows(const char *stub, int *fails)
{
    spc_selftest_case(stub,
        "SPECIALIST(\"consensus\",\"core/consensus\",\"check-consensus-parity\","
        "\"consensus\",\"consensus\")\n",
        1, "a row whose territory, gate and group exist", fails);
    spc_selftest_case(stub,
        "SPECIALIST(\"consensus\",\"core/nope\",\"check-consensus-parity\","
        "\"consensus\",\"consensus\")\n",
        0, "a territory that matches nothing", fails);
    spc_selftest_case(stub,
        "SPECIALIST(\"consensus\",\"core/consensus\",\"check-not-a-gate\","
        "\"consensus\",\"consensus\")\n",
        0, "a gate the Makefile does not declare", fails);
    spc_selftest_case(stub,
        "SPECIALIST(\"consensus\",\"core/consensus\",\"check-consensus-parity\","
        "\"no_such_group\",\"consensus\")\n",
        0, "a test group the catalog does not declare", fails);
}

static int spc_selftest_missing_def(const char *stub, int *fails)
{
    if (setenv("ZCL_SPECIALISTS_ROOT", stub, 1) != 0
        || setenv("ZCL_SPECIALISTS_DEF", "missing.def", 1) != 0
        || setenv("ZCL_SPECIALISTS_FLOOR", "1", 1) != 0)
        return 1;
    int rc = spc_hush_run();
    (void)unsetenv("ZCL_SPECIALISTS_ROOT");
    (void)unsetenv("ZCL_SPECIALISTS_DEF");
    (void)unsetenv("ZCL_SPECIALISTS_FLOOR");
    if (rc != 2) {
        fprintf(stderr, "check_specialists: SELFTEST FAILED — a missing .def did not exit 2 (rc=%d)\n", rc);
        (*fails)++;
        return 0;
    }
    return printf("  selftest ok: a missing .def exits 2\n") < 0 ? -1 : 0;
}

int check_specialists_selftest(void)
{
    char tmpl[4096];
    (void)csr_mkdirs("test-tmp");
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-spc.XXXXXX", env_or("TMPDIR", "test-tmp")),
            sizeof tmpl))
        return 1;
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed\n", "");
    char stub[4096];
    if (ovf(snprintf(stub, sizeof stub, "%s/repo", tmp), sizeof stub)) { rap_rm_rf(tmp); return 1; }
    if (spc_selftest_fixture(stub)) { rap_rm_rf(tmp); return 1; }

    int fails = 0;
    spc_selftest_bad_rows(stub, &fails);

    int mrc = spc_selftest_missing_def(stub, &fails);
    if (mrc < 0) { rap_rm_rf(tmp); return die("z23-lint: write failed\n", ""); }

    rap_rm_rf(tmp);
    if (fails) return 1;
    return printf("[check_specialists] SELFTEST PASS (unknown territory, unknown gate, "
                  "unknown group fail; a resolving row passes; a missing .def exits 2)\n") < 0
        ? die("z23-lint: write failed\n", "") : 0;
}
