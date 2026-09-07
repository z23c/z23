/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-windows-acceptance-guard of the C23 lint
 * runtime, the replacement for tools/lint/check_windows_acceptance_guard.sh.
 * Every tests/harness/src/NAME_windows_acceptance.c TU, and every tests/-rooted
 * source a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES catalog row names, must either
 * define no main() or wrap it in the full
 *   #if defined(_WIN32) ... #else typedef int <name>_not_built; #endif
 * idiom, or a Linux test binary that links the harness sources collides at
 * link time (commit b562857bc). No file-scope mutable state — every helper
 * takes its context as an explicit parameter. Selftest lives in the sibling
 * gate_windows_acceptance_guard_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_windows_acceptance_guard_priv.h"

static const char k_wag_gate[] = "check-windows-acceptance-guard";
const char k_wag_catalog_rel[] =
    "platform/modules/platform/tests/windows_acceptance.mk";
const char k_wag_harness_dir_rel[] = "tests/harness/src";
enum { WAG_SCAN_FLOOR = 8, WAG_LINE = 8192, WAG_TOK = 512,
       WAG_ROWS = WAG_ROWS_PRIV };

static int wag_paths_add(struct wag_paths *s, const char *p)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i], p) == 0) return 0;
    if (s->n >= WAG_ROWS || strlen(p) >= RS_PATH)
        return die("z23-lint: windows-acceptance-guard path-set overflow\n", "");
    if (ovf(snprintf(s->v[s->n], RS_PATH, "%s", p), RS_PATH)) return 2;
    s->n++;
    return 0;
}

static int wag_paths_cmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int wag_paths_sort(struct wag_paths *s)
{ qsort(s->v, (size_t)s->n, RS_PATH, wag_paths_cmp); return 0; }

/* ── catalog row parsing (Makefile continuation-aware) ─────────────────── */

/* True when trimming trailing spaces/tabs off `line` (n bytes) leaves a
 * final backslash — the Makefile line-continuation marker. */
static int wag_continues(const char *line, size_t n)
{
    while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    return n > 0 && line[n - 1] == '\\';
}

/* gsub(/\\/, " ", s): replace every backslash with a space in place. */
static void wag_unbackslash(char *s)
{
    for (; *s; s++) if (*s == '\\') *s = ' ';
}

/* Splits `s` on runs of whitespace; each token matching ^tests/[path].c$ is
 * added to out. tok_re is the compiled ^tests/[-A-Za-z0-9_./]+\.c$ regex. */
static int wag_emit_tokens(char *s, const regex_t *tok_re, struct wag_paths *out)
{
    wag_unbackslash(s);
    char *save = NULL;
    for (char *t = strtok_r(s, " \t\r\n", &save); t;
         t = strtok_r(NULL, " \t\r\n", &save)) {
        if (regexec(tok_re, t, 0, NULL, 0) == 0) {
            int rc = wag_paths_add(out, t);
            if (rc) return rc;
        }
    }
    return 0;
}

struct wag_catalog_scan {
    const regex_t *row_re; /* ^ZCL_WINDOWS_ACCEPTANCE_[A-Za-z_0-9]+_SOURCES[[:space:]]*:= */
    const regex_t *tok_re;
    int active;
};

/* Everything after the FIRST ":=" on the row-start line. */
static char *wag_after_assign(char *line)
{
    char *p = strstr(line, ":=");
    return p ? p + 2 : line + strlen(line);
}

static int wag_catalog_line(struct wag_catalog_scan *st, char *line,
                            struct wag_paths *out)
{
    size_t n = strlen(line);
    if (!st->active) {
        if (regexec(st->row_re, line, 0, NULL, 0) != 0)
            return 0;
        int more = wag_continues(line, n);
        int rc = wag_emit_tokens(wag_after_assign(line), st->tok_re, out);
        st->active = more;
        return rc;
    }
    int more = wag_continues(line, n);
    int rc = wag_emit_tokens(line, st->tok_re, out);
    st->active = more;
    return rc;
}

/* Not static: gate_windows_acceptance_guard_selftest.c reads the real
 * catalog to build its "every declared TU correctly guarded" fixture. */
int wag_catalog_sources(const char *path, struct wag_paths *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? 0
             : die("z23-lint: cannot open %s\n", path);
    regex_t row_re, tok_re;
    int rc = pair_comp(&row_re, REG_EXTENDED,
                       "^ZCL_WINDOWS_ACCEPTANCE_[A-Za-z_0-9]+_SOURCES[[:space:]]*:=",
                       "", "", "",
                       &tok_re, REG_EXTENDED,
                       "^tests/[-A-Za-z0-9_./]+[.]c$", "", "", "");
    if (rc) { fclose(f); return rc; }
    struct wag_catalog_scan st = { .row_re = &row_re, .tok_re = &tok_re,
                                   .active = 0 };
    char *raw = NULL;
    size_t cap = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&raw, &cap, f)) >= 0) {
        if (n > 0 && raw[n - 1] == '\n') raw[--n] = '\0';
        rc = wag_catalog_line(&st, raw, out);
    }
    rc = fin(f, raw, path, rc);
    drop2(&row_re, &tok_re);
    return rc;
}

/* ── per-file verdict ────────────────────────────────────────────────────
 * Reads path with comments stripped and reports (via the reason and
 * outline out-params) whether the file defines main() outside the
 * required guard idiom. */

/* Copies one "..." or '...' literal body VERBATIM (escapes included), from
 * line[*i] (the opening quote) through its close or end of line. */
static void wag_copy_literal(const char *line, size_t n, char *out,
                             size_t cap, size_t *i, size_t *o)
{
    char q = line[*i];
    out[(*o)++] = line[(*i)++];
    while (*i < n && *o + 1 < cap) {
        if (line[*i] == '\\' && *i + 1 < n && *o + 2 < cap) {
            out[(*o)++] = line[*i];
            out[(*o)++] = line[*i + 1];
            *i += 2;
            continue;
        }
        out[(*o)++] = line[*i];
        if (line[*i] == q) { (*i)++; break; }
        (*i)++;
    }
}

/* Advances one step of an already-open block comment, blanking it; clears
 * *in_block on its closing "*" "/" pair. Returns 1 (handled — caller must
 * `continue`) whenever a block comment was open on entry, 0 otherwise. */
static int wag_advance_block(const char *line, size_t n, char *out,
                             size_t cap, size_t *i, size_t *o, int *in_block)
{
    if (!*in_block)
        return 0;
    if (line[*i] == '*' && *i + 1 < n && line[*i + 1] == '/') {
        *in_block = 0;
        *i += 2;
        if (*o + 1 < cap) out[(*o)++] = ' ';
    } else {
        (*i)++;
    }
    return 1;
}

static void wag_strip_line(int *in_block, const char *line, char *out, size_t cap)
{
    size_t i = 0, o = 0, n = strlen(line);
    while (i < n && o + 1 < cap) {
        if (wag_advance_block(line, n, out, cap, &i, &o, in_block))
            continue;
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '*') {
            *in_block = 1; i += 2; out[o++] = ' '; continue;
        }
        if (line[i] == '/' && i + 1 < n && line[i + 1] == '/') {
            out[o++] = ' '; break;
        }
        if (line[i] == '"' || line[i] == '\'') {
            wag_copy_literal(line, n, out, cap, &i, &o);
            continue;
        }
        out[o++] = line[i++];
    }
    out[o] = '\0';
}

static void wag_trim(char *s)
{
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

struct wag_marks {
    char first[512], last[512];
    long firstln, lastln, mainln, elsln, tbln, endifln;
};

static int wag_is_main(const regex_t *re, const char *s)
{ return regexec(re, s, 0, NULL, 0) == 0; }

static void wag_note_marks(struct wag_marks *m, const char *s, long nr,
                           const regex_t *main_re, const regex_t *td_re)
{
    if (m->firstln == 0) {
        snprintf(m->first, sizeof m->first, "%s", s);
        m->firstln = nr;
    }
    snprintf(m->last, sizeof m->last, "%s", s);
    m->lastln = nr;
    if (m->mainln == 0 && wag_is_main(main_re, s)) m->mainln = nr;
    if (m->elsln == 0 && strncmp(s, "#else", 5) == 0) m->elsln = nr;
    if (m->tbln == 0 && regexec(td_re, s, 0, NULL, 0) == 0) m->tbln = nr;
    if (strncmp(s, "#endif", 6) == 0) m->endifln = nr;
}

static int wag_scan_marks(const char *path, const regex_t *main_re,
                          const regex_t *td_re, struct wag_marks *m)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == EACCES ? -1 : die("z23-lint: cannot open %s\n", path);
    char *raw = NULL;
    size_t cap = 0;
    ssize_t n;
    int in_block = 0, rc = 0;
    long nr = 0;
    while (rc == 0 && (n = getline(&raw, &cap, f)) >= 0) {
        nr++;
        if (n > 0 && raw[n - 1] == '\n') raw[--n] = '\0';
        char stripped[WAG_LINE];
        wag_strip_line(&in_block, raw, stripped, sizeof stripped);
        wag_trim(stripped);
        if (stripped[0] == '\0') continue;
        wag_note_marks(m, stripped, nr, main_re, td_re);
    }
    rc = fin(f, raw, path, rc);
    return rc;
}

/* Builds the one-line offender reason. Returns 0 clean, 1 with *reason/
 * *outline filled, or a die()'d >=2. */
static int wag_verdict(const struct wag_marks *m, char *reason, size_t rcap,
                       long *outline)
{
    if (m->mainln == 0) return 0;
    if (strcmp(m->first, "#if defined(_WIN32)") != 0) {
        *outline = m->firstln;
        return ovf(snprintf(reason, rcap,
                            "defines main() but the first non-comment line "
                            "is not '#if defined(_WIN32)' (it is: %s)",
                            m->first), rcap) ? 2 : 1;
    }
    if (strcmp(m->last, "#endif") != 0) {
        *outline = m->lastln;
        return ovf(snprintf(reason, rcap,
                            "guarded but the last non-comment line is not "
                            "'#endif' (it is: %s)", m->last), rcap) ? 2 : 1;
    }
    if (m->elsln == 0 || m->elsln > m->endifln) {
        *outline = m->endifln;
        return ovf(snprintf(reason, rcap,
                            "guarded but no '#else' arm before the final "
                            "'#endif'"), rcap) ? 2 : 1;
    }
    if (m->tbln == 0 || m->tbln < m->elsln || m->tbln > m->endifln) {
        *outline = m->endifln;
        return ovf(snprintf(reason, rcap,
                            "'#else' arm lacks a 'typedef int ..._not_built;' "
                            "placeholder (an empty TU trips -Werror=pedantic)"),
                   rcap) ? 2 : 1;
    }
    return 0;
}

static int wag_inspect(const char *path, const regex_t *main_re,
                       const regex_t *td_re, char *reason, size_t rcap,
                       long *outline)
{
    struct wag_marks m = {0};
    int rc = wag_scan_marks(path, main_re, td_re, &m);
    if (rc) return rc;
    return wag_verdict(&m, reason, rcap, outline);
}

/* ── scan set ─────────────────────────────────────────────────────────── */

static int wag_glob_harness(const char *root, struct wag_paths *out)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s/%s", root, k_wag_harness_dir_rel),
            sizeof dir))
        return 2;
    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? 0 : die("z23-lint: cannot open %s\n", dir);
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        static const char suf[] = "_windows_acceptance.c";
        size_t sl = sizeof suf - 1;
        if (l <= sl || strcmp(de->d_name + l - sl, suf) != 0) continue;
        char rel[RS_PATH];
        if (ovf(snprintf(rel, sizeof rel, "%s/%s", k_wag_harness_dir_rel,
                         de->d_name), sizeof rel)) { closedir(d); return 2; }
        rc = wag_paths_add(out, rel);
    }
    closedir(d);
    return rc;
}

static int wag_missing_declared(const char *root, const struct wag_paths *d,
                                char *out, size_t cap)
{
    size_t used = 0;
    for (int i = 0; i < d->n; i++) {
        char full[4096];
        if (ovf(snprintf(full, sizeof full, "%s/%s", root, d->v[i]),
                sizeof full))
            return 2;
        struct stat st;
        if (stat(full, &st) == 0) continue;
        int k = snprintf(out + used, cap - used, "    %s\n", d->v[i]);
        if (ovf(k, cap - used)) return 2;
        used += (size_t)k;
    }
    return 0;
}

static int wag_report_fail(const struct wag_paths *scan, const regex_t *main_re,
                           const regex_t *td_re, const char *root, FILE *out)
{
    char faults[65536];
    size_t used = 0;
    faults[0] = '\0';
    int any = 0, rc = 0;
    for (int i = 0; rc == 0 && i < scan->n; i++) {
        char full[4096], reason[512];
        long line = 0;
        if (ovf(snprintf(full, sizeof full, "%s/%s", root, scan->v[i]),
                sizeof full))
            return 2;
        int vr = wag_inspect(full, main_re, td_re, reason, sizeof reason,
                             &line);
        if (vr < 0) {
            fprintf(stderr, "%s: UNPROVEN — %s exists but is not readable; "
                   "refusing to report a clean scan\n", k_wag_gate,
                   scan->v[i]);
            return 2;
        }
        if (vr == 0) continue;
        if (vr != 1) return vr;
        any = 1;
        int k = snprintf(faults + used, sizeof faults - used,
                         "    %s:%ld: %s\n", scan->v[i], line, reason);
        if (ovf(k, sizeof faults - used)) return 2;
        used += (size_t)k;
    }
    if (!any) return 0;
    fprintf(out, "%s: FAIL — Windows acceptance TU(s) that define main() "
           "without the full off-Windows guard:\n", k_wag_gate);
    fputs(faults, out);
    fputs("\n"
         "  A tests/-rooted acceptance TU is linked into every Linux test\n"
         "  binary; an unguarded main() collides with the suite runner and\n"
         "  NO test group can link. Wrap the whole body:\n"
         "      #if defined(_WIN32)\n"
         "      ...existing body...\n"
         "      #else\n"
         "      typedef int <name>_not_built;\n"
         "      #endif\n", out);
    return 1;
}

/* Not static: gate_windows_acceptance_guard_selftest.c drives the scan
 * against fixture roots directly, the same entry point production uses. */
int wag_scan_root(const char *root, FILE *out)
{
    char catalog[4096];
    if (ovf(snprintf(catalog, sizeof catalog, "%s/%s", root, k_wag_catalog_rel),
            sizeof catalog))
        return 2;
    struct stat st;
    if (stat(catalog, &st) != 0) {
        fprintf(stderr, "%s: UNPROVEN — no acceptance catalog at %s.\n",
               k_wag_gate, k_wag_catalog_rel);
        fputs("  The scan set is derived from it; without the catalog this\n"
             "  gate would grade only the glob and call that clean.\n",
             stderr);
        return 2;
    }
    static struct wag_paths declared;
    declared.n = 0;
    int rc = wag_catalog_sources(catalog, &declared);
    if (rc) return rc;
    if (declared.n == 0) {
        fprintf(stderr, "%s: UNPROVEN — %s named no sources under tests/.\n",
               k_wag_gate, k_wag_catalog_rel);
        fputs("  The row shape this gate parses may have changed; a scan "
             "over\n  the glob alone must not stand in for the catalog.\n",
             stderr);
        return 2;
    }
    char missing[16384];
    rc = wag_missing_declared(root, &declared, missing, sizeof missing);
    if (rc) return rc;
    if (missing[0]) {
        fprintf(stderr, "%s: UNPROVEN — catalog rows naming files not on "
               "disk:\n%s", k_wag_gate, missing);
        return 2;
    }
    static struct wag_paths scan;
    scan.n = 0;
    rc = wag_glob_harness(root, &scan);
    if (rc) return rc;
    for (int i = 0; rc == 0 && i < declared.n; i++)
        rc = wag_paths_add(&scan, declared.v[i]);
    if (rc) return rc;
    wag_paths_sort(&scan);
    rc = gate_require_scanned(scan.n, WAG_SCAN_FLOOR, k_wag_gate,
                              "The union of the tests/harness/src glob and "
                              "the catalog's tests/ rows came back below "
                              "the floor.");
    if (rc) return rc;

    regex_t main_re, td_re;
    rc = pair_comp(&main_re, REG_EXTENDED, "^(int|void)[[:space:]]+main[[:space:]]*\\(",
                  "", "", "",
                  &td_re, REG_EXTENDED,
                  "^typedef[[:space:]]+int[[:space:]]+[A-Za-z0-9_]+_not_built"
                  "[[:space:]]*;", "", "", "");
    if (rc) return rc;
    rc = wag_report_fail(&scan, &main_re, &td_re, root, out);
    drop2(&main_re, &td_re);
    if (rc) return rc;

    return fprintf(out, "%s: clean — %d file(s) scanned; every "
                  "tests/-rooted Windows acceptance TU opens with '#if "
                  "defined(_WIN32)' and closes with an '#else ... "
                  "_not_built; #endif' tail, or defines no main()\n",
                  k_wag_gate, scan.n) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

int check_windows_acceptance_guard_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    const char *ov = env_or("ZCL_WINDOWS_ACCEPTANCE_GUARD_ROOT", "");
    if (ov[0]) {
        if (ovf(snprintf(root, sizeof root, "%s", ov), sizeof root)) return 2;
    } else if (cic_repo_root(root, sizeof root)) {
        return 2;
    }
    return wag_scan_root(root, stdout);
}
