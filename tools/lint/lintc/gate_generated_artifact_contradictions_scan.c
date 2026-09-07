/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-generated-artifact-contradictions
 * Second file of the check-generated-artifact-contradictions family (the
 * 700-line family ceiling split): the native scanners — the git grep -l
 * discovery file test, the sed line-1 reads and BRE extractions, the
 * arm-baseline row set, and the capability-inventory record parse. The
 * gate body (discovery, the verdict chain, the entry) and the family's
 * parity notes live in gate_generated_artifact_contradictions.c; the
 * --selftest probes live in
 * gate_generated_artifact_contradictions_workers.c. Shared structs and
 * prototypes: gate_generated_artifact_contradictions.h.
 */

/* ── the native scanners ─────────────────────────────────────────────────
 * Every external-tool read in the original shell gate is reproduced in C;
 * no subprocess runs anywhere in this family (the standing lint-gate
 * ruling). All patterns are BRE, exactly as grep/sed resolved them without
 * -E: the same leftmost-longest subexpression rules decide every capture,
 * so the greedy leading .* takes the LAST admissible literal occurrence,
 * as sed did.
 *
 * - git grep -l '"artifact_id":"zcl.code_capability_inventory.v1"' -- is
 *   gacs_file_listed over the native git-index enumeration
 *   (lint_git_index_foreach — index order, byte-sorted by path then
 *   ascending stage, exactly the order git grep reports tracked worktree
 *   files). The pattern is a BRE, so its dots match any byte, here as
 *   there. A file is listed when at least one line matches; git matches
 *   on raw line bytes, so a NUL-bearing line is tested segment by segment
 *   (the pattern holds no NUL, making segment-wise matching exact). An
 *   unreadable, missing, or non-regular index entry is skipped silently —
 *   the shell sent git's diagnostics to /dev/null and ignored the exit
 *   status, so such an entry simply never became a candidate. A
 *   repository submodule gitlink is a directory in the worktree and is
 *   skipped on both sides.
 * - sed -n '1p' is gacs_first_line: the first line without its newline,
 *   an empty string for an empty file. In the DISCOVERY loop the shell's
 *   read ran inside a process-substitution subshell whose failure could
 *   not reach the parent, so a vanished candidate reads as
 *   not-a-candidate here too; in the later meta/consumes reads an open
 *   failure is sed's "can't read" environment class (set -e exit 2 with
 *   sed's own text) and maps to die() — an environment defect, never a
 *   gate verdict.
 * - The line-1 consumes extraction and the two record extractions keep
 *   the original BREs byte-for-byte, including the absent trailing anchor
 *   on the multi/arm row patterns (trailing content is allowed) and the
 *   adjacent `","verdict":"` in the arm pattern.
 * - The baseline build `awk -F '\t' 'NF == 2 && $0 !~ /^#/ { print $1
 *   "\t" $2 }' | LC_ALL=C sort -u`: with exactly one tab the printed row
 *   IS the original line, so the set is the lines with exactly one tab
 *   whose first byte is not '#', qsort/strcmp byte-ordered with
 *   exact-duplicate collapse. Byte order is the deliberate, deterministic
 *   replacement for the shell's locale-dependent sort — identical under
 *   LC_ALL=C, the A/B fixture locale on both sides. awk reads a final
 *   line with no newline terminator as a record; so does the getline
 *   loop.
 * - grep -Fqx membership is an exact full-line string compare against the
 *   deduped set; grep -Fq claims are fixed-string substring tests
 *   (strstr); the untested-invariant record grep is one BRE per line.
 * - A field value containing a tab would be split further by the shell's
 *   awk -F '\t' re-parse of its own TSV, truncating the comparison keys;
 *   the port compares the full extracted values. No generated artifact
 *   value contains a tab. A NUL inside a compared header line is read as
 *   a C string terminator here where grep -Fqx compared raw bytes; no
 *   artifact line contains a NUL. Both are latent-edge notes, not
 *   observed behavior.
 * - The shell was unbounded; the fixed pools (row arrays, string pool)
 *   fail closed with die().
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "gate_generated_artifact_contradictions.h"

enum { GACS_MAXROW = 8192, GACS_POOL = 1 << 20, GACS_FIRST = 1 << 16 };

enum { RE_GG, RE_CONS, RE_MULTI, RE_ARM, RE_UN, RE_DPATH, RE_SYM, RE_N };

struct gac_arm {
    const char *h, *p, *s, *ev, *sc, *ve;
};
struct gac_triple {
    const char *h, *p, *s, *key;
};

static regex_t g_gacs_re[RE_N];
static char g_gacs_pool[GACS_POOL]; /* every extracted string */
static size_t g_gacs_used;
static char g_gacs_first[GACS_FIRST]; /* the sed -n '1p' result */
static const char *g_gacs_base[GACS_MAXROW]; /* the sorted-unique rows */
static int g_gacs_nbase;
static struct gac_multi g_gacs_multi[GACS_MAXROW];
static int g_gacs_nmulti;
static struct gac_arm g_gacs_arms[GACS_MAXROW];
static int g_gacs_narms;
static struct gac_untested g_gacs_un[GACS_MAXROW];
static int g_gacs_nun;
static struct gac_triple g_gacs_tri[GACS_MAXROW];
static int g_gacs_ntri;

static const char k_gacs_schema[] =
    "\"generated_artifact_schema\":\"zcl.generated_artifact.v1\"";
static const char k_gacs_artid[] =
    "\"artifact_id\":\"zcl.code_capability_inventory.v1\"";
static const char k_gacs_scope_pair[] =
    "\"multi_arm_definition\":true,"
    "\"definition_scope\":\"preprocessor_arm_UNPROVEN\"";
static const char k_gacs_verdict[] = "\"verdict\":\"UNPROVEN\"";

/* ── small buffer utilities ────────────────────────────────────────────── */

static int gacs_pool_n(const char *s, size_t n, const char **out)
{
    if (g_gacs_used + n + 1 > sizeof g_gacs_pool)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = g_gacs_pool + g_gacs_used;
    memcpy(dst, s, n);
    dst[n] = '\0';
    g_gacs_used += n + 1;
    *out = dst;
    return 0;
}

static int gacs_span(const char *line, regmatch_t m, const char **out)
{
    if (m.rm_so < 0) {
        *out = "";
        return 0;
    }
    return gacs_pool_n(line + m.rm_so, (size_t)(m.rm_eo - m.rm_so), out);
}

/* The single-group sed substitution shape (a greedy leading .* , one
 * [^"] group, no trailing anchor requirement on the group): the first
 * group's bytes when the BRE matches, else the empty string (sed printed
 * nothing). */
static int gacs_span1(int re, const char *line, const char **out)
{
    regmatch_t m[2];
    *out = "";
    if (regexec(&g_gacs_re[re], line, 2, m, 0) != 0)
        return 0;
    return gacs_span(line, m[1], out);
}

static int gacs_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ── git grep -l, per file ─────────────────────────────────────────────── */

static int gacs_file_listed(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (memchr(line, '\0', (size_t)n)) {
            const char *end = line + n;
            for (const char *seg = line; !found && seg < end;
                 seg += strlen(seg) + 1)
                found = regexec(&g_gacs_re[RE_GG], seg, 0, NULL, 0) == 0;
        } else {
            found = regexec(&g_gacs_re[RE_GG], line, 0, NULL, 0) == 0;
        }
    }
    free(line);
    (void)fclose(f);
    return found;
}

/* ── sed -n '1p' ───────────────────────────────────────────────────────── */

static int gacs_first_line(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, f);
    int rc = 0;
    if (n < 0) {
        g_gacs_first[0] = '\0';
        if (ferror(f))
            rc = die("z23-lint: read failed: %s\n", path);
    } else {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if ((size_t)n >= sizeof g_gacs_first)
            rc = die("z23-lint: derived buffer overflow\n", "");
        else
            memcpy(g_gacs_first, line, (size_t)n + 1);
    }
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

/* Discovery candidate: listed by the git grep, then both fixed strings on
 * its first line. A first-line read failure is swallowed (the shell's
 * read lived in a process-substitution subshell whose status was lost). */
int gacs_discover_ok(const char *path)
{
    if (!gacs_file_listed(path))
        return 0;
    if (gacs_first_line(path) != 0)
        return 0;
    return strstr(g_gacs_first, k_gacs_schema) != NULL
        && strstr(g_gacs_first, k_gacs_artid) != NULL;
}

/* The line-1 consumes substitution (greedy leading .* , the [^"] capture
 * after "consumes":[{"path":" , trailing content allowed): the captured
 * path, or the empty string when line 1 has no such edge. */
int gacs_consumes_path(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    int rc = gacs_first_line(path);
    regmatch_t m[2];
    if (rc == 0
        && regexec(&g_gacs_re[RE_CONS], g_gacs_first, 2, m, 0) == 0
        && m[1].rm_so >= 0) {
        size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
        if (n >= cap)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out, g_gacs_first + m[1].rm_so, n);
        out[n] = '\0';
    }
    return rc;
}

/* meta="$(sed -n '1p' "$CAP")" then the grep -Fq claim loop: the first
 * absent claim, in declaration order. */
int gacs_meta_check(const char *path, const char *const *claims, int n,
                    const char **miss)
{
    *miss = NULL;
    int rc = gacs_first_line(path);
    for (int i = 0; rc == 0 && i < n; i++) {
        if (!strstr(g_gacs_first, claims[i])) {
            *miss = claims[i];
            return 0;
        }
    }
    return rc;
}

/* grep -Fqx: an exact full-line membership test. */
int gacs_file_has_line(const char *path, const char *line, int *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *l = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&l, &cap, f)) >= 0) {
        if (n > 0 && l[n - 1] == '\n')
            l[--n] = '\0';
        found = strcmp(l, line) == 0;
    }
    *out = found;
    return fin(f, l, path, 0);
}

/* ── the arm baseline row set ──────────────────────────────────────────── */

/* awk -F '\t' 'NF == 2 && $0 !~ /^#/': exactly one tab, first byte not
 * '#'; the printed $1 "\t" $2 is then the original line. */
static int gacs_base_row(const char *line, size_t n)
{
    int tabs = 0;
    for (size_t i = 0; i < n; i++)
        tabs += line[i] == '\t';
    if (tabs != 1 || line[0] == '#')
        return 0;
    if (g_gacs_nbase >= GACS_MAXROW)
        return die("z23-lint: scan-set overflow\n", "");
    return gacs_pool_n(line, n, &g_gacs_base[g_gacs_nbase++]);
}

int gacs_load_baseline(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    g_gacs_nbase = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            n--;
        rc = gacs_base_row(line, (size_t)n);
    }
    qsort(g_gacs_base, (size_t)g_gacs_nbase, sizeof g_gacs_base[0],
          gacs_ptr_cmp);
    int w = 0;
    for (int i = 0; i < g_gacs_nbase; i++) {
        if (w > 0 && strcmp(g_gacs_base[w - 1], g_gacs_base[i]) == 0)
            continue;
        g_gacs_base[w++] = g_gacs_base[i];
    }
    g_gacs_nbase = w;
    return fin(f, line, path, rc);
}

int gacs_baseline_n(void)
{
    return g_gacs_nbase;
}

/* grep -Fqx "$path\t$symbol" baseline.tsv: full-line membership in the
 * sorted-unique set. */
int gacs_baseline_has(const char *key)
{
    return bsearch(&key, g_gacs_base, (size_t)g_gacs_nbase,
                   sizeof g_gacs_base[0], gacs_ptr_cmp) != NULL;
}

/* ── the capability-inventory parse ────────────────────────────────────── */

static int gacs_multi_add(const char *line, const regmatch_t *m)
{
    if (g_gacs_nmulti >= GACS_MAXROW)
        return die("z23-lint: scan-set overflow\n", "");
    struct gac_multi *r = &g_gacs_multi[g_gacs_nmulti];
    int rc = gacs_span(line, m[1], &r->h);
    if (rc == 0)
        rc = gacs_span(line, m[3], &r->p);
    if (rc == 0)
        rc = gacs_span(line, m[2], &r->s);
    if (rc == 0)
        rc = gacs_span(line, m[4], &r->claimed);
    if (rc == 0)
        rc = gacs_span(line, m[5], &r->agdef);
    if (rc == 0)
        rc = gacs_span(line, m[6], &r->agcon);
    if (rc == 0)
        g_gacs_nmulti++;
    return rc;
}

static int gacs_arm_add(const char *line, const regmatch_t *m)
{
    if (g_gacs_narms >= GACS_MAXROW)
        return die("z23-lint: scan-set overflow\n", "");
    struct gac_arm *r = &g_gacs_arms[g_gacs_narms];
    int rc = gacs_span(line, m[1], &r->h);
    if (rc == 0)
        rc = gacs_span(line, m[3], &r->p);
    if (rc == 0)
        rc = gacs_span(line, m[2], &r->s);
    if (rc == 0)
        rc = gacs_span(line, m[4], &r->ev);
    if (rc == 0)
        rc = gacs_span(line, m[5], &r->sc);
    if (rc == 0)
        rc = gacs_span(line, m[6], &r->ve);
    if (rc == 0)
        g_gacs_narms++;
    return rc;
}

static int gacs_un_add(const char *line)
{
    if (g_gacs_nun >= GACS_MAXROW)
        return die("z23-lint: scan-set overflow\n", "");
    struct gac_untested *u = &g_gacs_un[g_gacs_nun];
    int rc = gacs_span1(RE_DPATH, line, &u->p);
    if (rc == 0)
        rc = gacs_span1(RE_SYM, line, &u->s);
    if (rc)
        return rc;
    u->scope_ok = strstr(line, k_gacs_scope_pair) != NULL;
    u->verdict_ok = strstr(line, k_gacs_verdict) != NULL;
    g_gacs_nun++;
    return 0;
}

/* One pass over the inventory: the two record extractions and the
 * untested-invariant match, each in file order within its class — the
 * shell's two seds and its trailing grep each saw the same file order. */
static int gacs_cap_line(const char *line)
{
    regmatch_t m[7];
    int rc = 0;
    if (regexec(&g_gacs_re[RE_MULTI], line, 7, m, 0) == 0)
        rc = gacs_multi_add(line, m);
    if (rc == 0 && regexec(&g_gacs_re[RE_ARM], line, 7, m, 0) == 0)
        rc = gacs_arm_add(line, m);
    if (rc == 0 && regexec(&g_gacs_re[RE_UN], line, 0, NULL, 0) == 0)
        rc = gacs_un_add(line);
    return rc;
}

int gacs_parse_cap(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    g_gacs_nmulti = 0;
    g_gacs_narms = 0;
    g_gacs_nun = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = gacs_cap_line(line);
    }
    return fin(f, line, path, rc);
}

int gacs_multi_n(void)
{
    return g_gacs_nmulti;
}

const struct gac_multi *gacs_multi_at(int i)
{
    return &g_gacs_multi[i];
}

static int gacs_arm_eq(const struct gac_arm *a, const char *h,
                       const char *p, const char *s)
{
    return strcmp(a->h, h) == 0 && strcmp(a->p, p) == 0
        && strcmp(a->s, s) == 0;
}

/* awk '$1 == h && $2 == p && $3 == s { n++ } END { print n + 0 }'. */
int gacs_arm_count(const char *h, const char *p, const char *s)
{
    int n = 0;
    for (int i = 0; i < g_gacs_narms; i++)
        n += gacs_arm_eq(&g_gacs_arms[i], h, p, s);
    return n;
}

static int gacs_arm_clean1(const struct gac_arm *a)
{
    int ev = strcmp(a->ev, "parsed_definition_body") == 0
        || strcmp(a->ev, "body_binding_UNPROVEN") == 0;
    return ev && strcmp(a->sc, "preprocessor_arm_UNPROVEN") == 0
        && strcmp(a->ve, "UNPROVEN") == 0;
}

/* The awk ceiling probe: matching rows whose evidence, scope, and verdict
 * all sit at their explicit UNPROVEN ceiling. */
int gacs_arm_clean(const char *h, const char *p, const char *s)
{
    int n = 0;
    for (int i = 0; i < g_gacs_narms; i++)
        n += gacs_arm_eq(&g_gacs_arms[i], h, p, s)
            && gacs_arm_clean1(&g_gacs_arms[i]);
    return n;
}

/* ── the definition-arm triples ────────────────────────────────────────── */

static int gacs_tri_add(const struct gac_arm *a)
{
    if (g_gacs_ntri >= GACS_MAXROW)
        return die("z23-lint: scan-set overflow\n", "");
    struct gac_triple *t = &g_gacs_tri[g_gacs_ntri];
    char key[12288];
    int k = snprintf(key, sizeof key, "%s\t%s\t%s", a->h, a->p, a->s);
    if (ovf(k, sizeof key))
        return 2;
    t->h = a->h;
    t->p = a->p;
    t->s = a->s;
    int rc = gacs_pool_n(key, (size_t)k, &t->key);
    if (rc == 0)
        g_gacs_ntri++;
    return rc;
}

static int gacs_tri_cmp(const void *a, const void *b)
{
    return strcmp(((const struct gac_triple *)a)->key,
                  ((const struct gac_triple *)b)->key);
}

/* awk '{ print $1 "\t" $2 "\t" $3 }' arms.tsv | LC_ALL=C sort -u: the
 * distinct (header, path, symbol) triples, strcmp byte order with
 * exact-duplicate collapse. */
int gacs_build_triples(void)
{
    g_gacs_ntri = 0;
    int rc = 0;
    for (int i = 0; rc == 0 && i < g_gacs_narms; i++)
        rc = gacs_tri_add(&g_gacs_arms[i]);
    if (rc)
        return rc;
    qsort(g_gacs_tri, (size_t)g_gacs_ntri, sizeof g_gacs_tri[0],
          gacs_tri_cmp);
    int w = 0;
    for (int i = 0; i < g_gacs_ntri; i++) {
        if (w > 0 && strcmp(g_gacs_tri[w - 1].key, g_gacs_tri[i].key) == 0)
            continue;
        g_gacs_tri[w++] = g_gacs_tri[i];
    }
    g_gacs_ntri = w;
    return 0;
}

int gacs_ntriples(void)
{
    return g_gacs_ntri;
}

const char *gacs_triple_key(int i)
{
    return g_gacs_tri[i].key;
}

/* awk over multi.tsv: a row with exactly these header/path/symbol fields. */
int gacs_multi_has(const char *h, const char *p, const char *s)
{
    for (int i = 0; i < g_gacs_nmulti; i++) {
        const struct gac_multi *r = &g_gacs_multi[i];
        if (strcmp(r->h, h) == 0 && strcmp(r->p, p) == 0
            && strcmp(r->s, s) == 0)
            return 1;
    }
    return 0;
}

int gacs_untested_n(void)
{
    return g_gacs_nun;
}

const struct gac_untested *gacs_untested_at(int i)
{
    return &g_gacs_un[i];
}

/* ── pattern lifecycle ─────────────────────────────────────────────────── */

int gacs_comp(void)
{
    static const char *const pats[RE_N] = {
        "\"artifact_id\":\"zcl.code_capability_inventory.v1\"",
        ".*\"consumes\":\\[{\"path\":\"\\([^\"]*\\)\".*",
        "^{\"record\":\"multi_arm_symbol\",\"header\":\"\\([^\"]*\\)\","
        "\"symbol\":\"\\([^\"]*\\)\",\"source_path\":\"\\([^\"]*\\)\","
        "\"definition_arm_count\":\\([0-9][0-9]*\\),"
        "\"aggregate_definition\":\"\\([^\"]*\\)\","
        "\"aggregate_constant_return\":\"\\([^\"]*\\)\".*",
        "^{\"record\":\"definition_arm\",\"header\":\"\\([^\"]*\\)\","
        "\"symbol\":\"\\([^\"]*\\)\".*\"path\":\"\\([^\"]*\\)\".*"
        "\"constant_return_evidence\":\"\\([^\"]*\\)\".*"
        "\"definition_scope\":\"\\([^\"]*\\)\",\"verdict\":\"\\([^\"]*\\)\".*",
        "^{\"record\":\"untested_invariant\".*\"constant_return_body\":true",
        ".*\"definition\":{\"path\":\"\\([^\"]*\\)\".*",
        ".*\"symbol\":\"\\([^\"]*\\)\".*",
    };
    int i = 0, rc = 0;
    for (; rc == 0 && i < RE_N; i++)
        rc = reg_fail(&g_gacs_re[i], regcomp(&g_gacs_re[i], pats[i], 0));
    if (rc) {
        while (--i >= 0)
            regfree(&g_gacs_re[i]);
    }
    return rc;
}

void gacs_drop(void)
{
    for (int i = 0; i < RE_N; i++)
        regfree(&g_gacs_re[i]);
}
