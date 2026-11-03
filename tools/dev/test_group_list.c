/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Print and resolve the REGISTERED test-group names without
 *          building: the C form of the former tools/dev/test-group-list.sh.
 *
 * The registry is read from tools/dev/test_group_catalog.def at run time (the
 * same file the C planner and the runner include), never from a compiled-in
 * copy, so a fixture registry named by ZCL_TEST_REGISTRY_SRC still works and a
 * Make parse needs no build of the runner. Output is catalog order, which is
 * g_groups[] order, the order the runner reports in. Names carry the prefix
 * the X-macro stamps: test_ on ZCL_TEST_GROUP rows, spec_ on ZCL_SPEC_GROUP.
 *
 * Modes (all read-only, no network):
 *   (none) | list      every registered group name, one per line
 *   --count            the number of registered groups
 *   --match S          groups a `--only=S` run selects (substring of the FULL
 *                      name); exit 1, no output, when nothing matches
 *   --resolve-exact ID...   proof-plan IDs to canonical full names; the full
 *                      or legacy prefixless name, never a substring; exit 1
 *                      when absent or ambiguous
 *   --resolve-proof ID...   every plan ID must have one canonical exact group;
 *                      a legacy prefixless ID keeps its substring union; a
 *                      complete shard set drops its umbrella
 *   --resolve-exact-set CSV  canonicalize/validate a comma-separated set
 *   --check-impact-rules [FILE]  fail when a declared proof-plan ID is not exact
 *   --suggest S        nearest candidates for an S that matched nothing
 *   --params-gated     the groups group_is_params_heavy() leaves out of a
 *                      default full run
 *   --report           registered vs executed (test_group_list_report.c)
 * Exit codes: 0 ok, 1 no match or a refusal, 2 a missing proof source or
 * bad usage. */

#include "test_group_list_int.h"

#include "base/safe_alloc.h"

#include "platform/glob_match.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TGL_NAME_LIMIT 100
#define TGL_SUGGEST_MAX 8
#define TGL_FILE_CAP (32u * 1024u * 1024u)

/* ── small helpers ─────────────────────────────────────────────────────── */

bool tgl_ident_char(int c)
{
    return isalnum((unsigned char)c) || c == '_';
}

const char *tgl_skip_space(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

bool tgl_blank(const char *s)
{
    return *tgl_skip_space(s) == '\0';
}

bool tgl_strs_push(struct tgl_strs *s, const char *str, size_t len)
{
    char *copy;
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 64;
        char **v = zcl_realloc(s->v, cap * sizeof(*v), "tgl_strs");
        if (!v)
            return false;
        s->v = v;
        s->cap = cap;
    }
    copy = zcl_malloc(len + 1, "tgl_str");
    if (!copy)
        return false;
    memcpy(copy, str, len);
    copy[len] = '\0';
    s->v[s->n++] = copy;
    return true;
}

void tgl_strs_free(struct tgl_strs *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

bool tgl_strs_has(const struct tgl_strs *s, const char *str)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], str) == 0)
            return true;
    return false;
}

char *tgl_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t used = 0, cap = 65536;
    char *buf = f ? zcl_malloc(cap, "tgl_file") : NULL;
    while (buf && !feof(f)) {
        size_t got;
        if (used + 1 >= cap) {
            char *bigger = cap < TGL_FILE_CAP ? zcl_realloc(buf, cap * 2, "tgl_file") : NULL;
            if (!bigger) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = bigger;
            cap *= 2;
        }
        got = fread(buf + used, 1, cap - used - 1, f);
        used += got;
        if (got == 0)
            break;
    }
    if (f)
        fclose(f);
    if (buf) {
        buf[used] = '\0';
        if (len)
            *len = used;
    }
    return buf;
}

size_t tgl_split_lines(char *text, char ***lines)
{
    size_t n = 0, cap = 256;
    char **v = zcl_malloc(cap * sizeof(*v), "tgl_lines");
    char *p = text;
    *lines = v;
    while (v && *p) {
        char *nl = strchr(p, '\n');
        if (n == cap) {
            char **bigger = zcl_realloc(v, cap * 2 * sizeof(*v), "tgl_lines");
            if (!bigger)
                break;
            v = *lines = bigger;
            cap *= 2;
        }
        v[n++] = p;
        if (!nl)
            break;
        *nl = '\0';
        p = nl + 1;
    }
    return n;
}

FILE *tgl_errf(const struct tgl_ctx *c)
{
    fflush(c->out);
    return c->err;
}

bool tgl_words(const char *text, struct tgl_strs *out)
{
    const char *p = text;
    while (*(p = tgl_skip_space(p))) {
        const char *b = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        if (!tgl_strs_push(out, b, (size_t)(p - b)))
            return false;
    }
    return true;
}

/* ── registry ──────────────────────────────────────────────────────────── */

/* One `MACRO(identifier)` row, alone on its line. */
static bool row_name(const char *line, const char *macro, const char **name,
                     size_t *len)
{
    const char *p = tgl_skip_space(line);
    size_t m = strlen(macro);
    const char *b;
    if (strncmp(p, macro, m) != 0 || p[m] != '(')
        return false;
    b = p += m + 1;
    while (tgl_ident_char((unsigned char)*p))
        p++;
    if (p == b || *p != ')' || !tgl_blank(p + 1))
        return false;
    *name = b;
    *len = (size_t)(p - b);
    return true;
}

static bool push_prefixed(struct tgl_strs *s, const char *prefix,
                          const char *name, size_t len)
{
    char buf[TGL_NAME_LIMIT * 4];
    size_t pl = strlen(prefix);
    if (pl + len >= sizeof(buf))
        return false;
    memcpy(buf, prefix, pl);
    memcpy(buf + pl, name, len);
    return tgl_strs_push(s, buf, pl + len);
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static bool registry_rows(struct tgl_ctx *c, char **lines, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const char *name;
        size_t len;
        if (row_name(lines[i], "ZCL_TEST_GROUP", &name, &len)) {
            if (!push_prefixed(&c->reg, "test_", name, len))
                return false;
        } else if (row_name(lines[i], "ZCL_SPEC_GROUP", &name, &len)) {
            if (!push_prefixed(&c->reg, "spec_", name, len))
                return false;
        }
    }
    return true;
}

bool tgl_load_registry(struct tgl_ctx *c)
{
    char *text = tgl_read_file(c->src->registry, NULL);
    char **lines = NULL;
    size_t n;
    bool ok;
    if (!text)
        return false;
    n = tgl_split_lines(text, &lines);
    ok = lines && registry_rows(c, lines, n);
    free(lines);
    free(text);
    if (!ok)
        return false;
    c->sorted = zcl_malloc((c->reg.n + 1) * sizeof(*c->sorted), "tgl_sorted");
    if (!c->sorted)
        return false;
    for (size_t i = 0; i < c->reg.n; i++)
        c->sorted[i] = c->reg.v[i];
    qsort(c->sorted, c->reg.n, sizeof(*c->sorted), name_cmp);
    return true;
}

void tgl_ctx_free(struct tgl_ctx *c)
{
    tgl_strs_free(&c->reg);
    free(c->sorted);
    for (size_t i = 0; i < c->nfam; i++) {
        free(c->fam[i].token);
        free(c->fam[i].glob);
    }
    free(c->fam);
}

const char *tgl_find(const struct tgl_ctx *c, const char *name)
{
    const char *const *hit;
    if (!name || !name[0] || c->reg.n == 0)
        return NULL;
    hit = bsearch(&name, c->sorted, c->reg.n, sizeof(*c->sorted), name_cmp);
    return hit ? *hit : NULL;
}

bool tgl_is_registered(const struct tgl_ctx *c, const char *name)
{
    return tgl_find(c, name) != NULL;
}

bool tgl_resolve_exact(const struct tgl_ctx *c, const char *needle,
                       const char **hit)
{
    static const char *const prefix[] = {"", "test_", "spec_"};
    const char *found = NULL;
    int count = 0;
    char cand[TGL_NAME_LIMIT * 2];
    if (!needle[0] || strlen(needle) >= TGL_NAME_LIMIT)
        return false;
    for (const char *p = needle; *p; p++)
        if (!tgl_ident_char((unsigned char)*p))
            return false;
    for (size_t i = 0; i < 3; i++) {
        const char *r;
        (void)snprintf(cand, sizeof(cand), "%s%s", prefix[i], needle);
        r = tgl_find(c, cand);
        if (r) {
            found = r;
            count++;
        }
    }
    if (count != 1)
        return false;
    if (hit)
        *hit = found;
    return true;
}

/* ── declared proof families ───────────────────────────────────────────── */

/* The text of the pair-th quoted string of a line (awk -F'"' $2 and $4). */
char *tgl_quoted_field(const char *line, int pair)
{
    const char *p = line, *e;
    for (int i = 0; i < pair * 2 + 1; i++) {
        p = strchr(p, '"');
        if (!p)
            return NULL;
        p++;
    }
    e = strchr(p, '"');
    return e ? strndup(p, (size_t)(e - p)) : NULL;
}

static bool family_row(struct tgl_ctx *c, const char *line)
{
    char *token, *glob;
    struct tgl_family *bigger;
    if (strncmp(tgl_skip_space(line), "ZCL_TEST_PROOF_FAMILY(", 22) != 0)
        return true;
    token = tgl_quoted_field(line, 0);
    glob = tgl_quoted_field(line, 1);
    if (!token || !glob || !token[0] || !glob[0]) {
        free(token);
        free(glob);
        return true;
    }
    bigger = zcl_realloc(c->fam, (c->nfam + 1) * sizeof(*c->fam), "tgl_family");
    if (!bigger) {
        free(token);
        free(glob);
        return false;
    }
    c->fam = bigger;
    c->fam[c->nfam].token = token;
    c->fam[c->nfam].glob = glob;
    c->nfam++;
    return true;
}

bool tgl_load_families(struct tgl_ctx *c)
{
    char *text, **lines = NULL;
    size_t n;
    bool ok = true;
    if (c->fam_loaded)
        return true;
    text = tgl_read_file(c->src->families, NULL);
    if (!text)
        return false;
    n = tgl_split_lines(text, &lines);
    for (size_t i = 0; lines && ok && i < n; i++)
        ok = family_row(c, lines[i]);
    free(lines);
    free(text);
    c->fam_loaded = ok;
    return ok;
}

/* proof_plan_token_selects_full: an exact registered token selects only
 * itself; otherwise the legacy substring rule, then a declared family. */
bool tgl_token_selects(struct tgl_ctx *c, const char *token, const char *full)
{
    if (tgl_is_registered(c, token))
        return strcmp(token, full) == 0;
    if (strstr(full, token))
        return true;
    if (!tgl_load_families(c))
        return false;
    for (size_t i = 0; i < c->nfam; i++)
        if (strcmp(token, c->fam[i].token) == 0 &&
            platform_glob_match(c->fam[i].glob, full, false))
            return true;
    return false;
}

/* ── params-gated policy, read from the function that enforces it ──────── */

/* Every strcmp(name, "ident") on `line`, appended as test_ident. */
static bool gated_line(struct tgl_strs *out, const char *line)
{
    const char *rest = line, *at;
    while ((at = strstr(rest, "strcmp(name,")) != NULL) {
        const char *p = tgl_skip_space(at + 12), *b;
        rest = at + 1;
        if (*p != '"')
            continue;
        b = ++p;
        while (tgl_ident_char((unsigned char)*p))
            p++;
        if (p == b || *p != '"' || p[1] != ')')
            continue;
        if (!push_prefixed(out, "test_", b, (size_t)(p - b)))
            return false;
        rest = p + 2;
    }
    return true;
}

bool tgl_params_gated(const struct tgl_ctx *c, struct tgl_strs *out)
{
    char *text = tgl_read_file(c->src->runner, NULL), **lines = NULL;
    size_t n;
    bool inside = false, ok = text != NULL;
    if (!ok)
        return false;
    n = tgl_split_lines(text, &lines);
    for (size_t i = 0; lines && ok && i < n; i++) {
        const char *l = lines[i];
        if (strncmp(l, "static bool group_is_params_heavy", 33) == 0) {
            inside = true;
            continue;
        }
        if (inside && l[0] == '}')
            inside = false;
        if (inside)
            ok = gated_line(out, l);
    }
    free(lines);
    free(text);
    return ok;
}

/* ── modes ─────────────────────────────────────────────────────────────── */

static int mode_list(struct tgl_ctx *c)
{
    for (size_t i = 0; i < c->reg.n; i++)
        fprintf(c->out, "%s\n", c->reg.v[i]);
    return 0;
}

static int mode_count(struct tgl_ctx *c)
{
    fprintf(c->out, "%zu\n", c->reg.n);
    return 0;
}

static int mode_match(struct tgl_ctx *c, int argc, const char *const *argv)
{
    const char *needle = argc > 1 ? argv[1] : "";
    bool found = false;
    if (!needle[0]) {
        fprintf(tgl_errf(c), "test-group-list: --match needs a substring\n");
        return 2;
    }
    for (size_t i = 0; i < c->reg.n; i++) {
        if (strstr(c->reg.v[i], needle)) {
            fprintf(c->out, "%s\n", c->reg.v[i]);
            found = true;
        }
    }
    return found ? 0 : 1;
}

static int mode_resolve_exact(struct tgl_ctx *c, int argc,
                              const char *const *argv)
{
    if (argc < 2) {
        fprintf(tgl_errf(c), "test-group-list: --resolve-exact needs one or "
                             "more group ids\n");
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        const char *hit;
        if (!tgl_resolve_exact(c, argv[i], &hit))
            return 1;
        fprintf(c->out, "%s\n", hit);
    }
    return 0;
}

static int mode_resolve_proof(struct tgl_ctx *c, int argc,
                              const char *const *argv)
{
    struct tgl_strs ids = {0};
    int rc;
    if (argc < 2) {
        fprintf(tgl_errf(c), "test-group-list: --resolve-proof needs one or "
                             "more plan ids\n");
        return 2;
    }
    for (int i = 1; i < argc; i++)
        if (!tgl_strs_push(&ids, argv[i], strlen(argv[i]))) {
            tgl_strs_free(&ids);
            return 1;
        }
    rc = tgl_resolve_proof(c, &ids);
    tgl_strs_free(&ids);
    return rc;
}

static void exact_set_help(struct tgl_ctx *c)
{
    fprintf(tgl_errf(c), "test-group-list: use comma-separated exact groups "
            "(not spaces), e.g. ONLY=dev_land,impact_composition; full "
            "test_/spec_ names are also accepted.\n");
}

static size_t edit_distance(const char *a, const char *b, size_t *row)
{
    size_t la = strlen(a), lb = strlen(b);
    for (size_t j = 0; j <= lb; j++)
        row[j] = j;
    for (size_t i = 1; i <= la; i++) {
        size_t diag = row[0];
        row[0] = i;
        for (size_t j = 1; j <= lb; j++) {
            size_t old = row[j], x = row[j] + 1, y = row[j - 1] + 1;
            size_t z = diag + (a[i - 1] != b[j - 1]);
            if (y < x)
                x = y;
            if (z < x)
                x = z;
            row[j] = x;
            diag = old;
        }
    }
    return row[lb];
}

struct ranked {
    size_t dist;
    const char *name;
};

static int ranked_cmp(const void *a, const void *b)
{
    const struct ranked *x = a, *y = b;
    if (x->dist != y->dist)
        return x->dist < y->dist ? -1 : 1;
    return strcmp(x->name, y->name);
}

/* The three registered names (whole or without prefix) nearest `token`. */
static void closest_names(struct tgl_ctx *c, const char *token)
{
    struct ranked *r = zcl_malloc((c->reg.n + 1) * sizeof(*r), "tgl_ranked");
    size_t *row = zcl_malloc((strlen(token) + TGL_NAME_LIMIT * 4) * sizeof(*row), "tgl_row");
    size_t shown = c->reg.n < 3 ? c->reg.n : 3;
    if (!r || !row) {
        free(r);
        free(row);
        return;
    }
    for (size_t i = 0; i < c->reg.n; i++) {
        const char *full = c->reg.v[i], *alias = full;
        size_t d, e;
        if (strncmp(full, "test_", 5) == 0 || strncmp(full, "spec_", 5) == 0)
            alias = full + 5;
        d = edit_distance(token, full, row);
        e = edit_distance(token, alias, row);
        r[i].dist = e < d ? e : d;
        r[i].name = full;
    }
    qsort(r, c->reg.n, sizeof(*r), ranked_cmp);
    for (size_t i = 0; i < shown; i++)
        fprintf(c->err, "  %s\n", r[i].name);
    free(r);
    free(row);
}

static void exact_set_unknown(struct tgl_ctx *c, const char *token)
{
    static const char *const prefix[] = {"", "test_", "spec_"};
    const char *kind = "unknown";
    char cand[TGL_NAME_LIMIT * 4 + 8];
    for (size_t i = 0; i < 3; i++) {
        (void)snprintf(cand, sizeof(cand), "%s%s", prefix[i], token);
        if (tgl_is_registered(c, cand))
            kind = "ambiguous";
    }
    fprintf(tgl_errf(c), "test-group-list: %s exact group '%s'\n", kind, token);
    fprintf(c->err, "closest registered names:\n");
    closest_names(c, token);
}

static bool csv_has_empty_token(const char *csv)
{
    size_t n = strlen(csv);
    return csv[0] == ',' || (n > 0 && csv[n - 1] == ',') ||
           strstr(csv, ",,") != NULL;
}

/* One non-empty token: canonical and deduplicated into `out`, or reported. */
static bool exact_set_token(struct tgl_ctx *c, const char *tok, size_t len,
                            struct tgl_strs *out)
{
    char word[TGL_NAME_LIMIT * 4];
    const char *hit;
    if (len >= sizeof(word))
        len = sizeof(word) - 1;
    memcpy(word, tok, len);
    word[len] = '\0';
    if (!tgl_resolve_exact(c, word, &hit)) {
        exact_set_unknown(c, word);
        return false;
    }
    if (!tgl_strs_has(out, hit))
        (void)tgl_strs_push(out, hit, strlen(hit));
    return true;
}

static int resolve_exact_set(struct tgl_ctx *c, const char *arg)
{
    struct tgl_strs out = {0};
    size_t nl = strcspn(arg, "\n");
    char *csv = strndup(arg, nl);
    const char *p;
    bool invalid = false;
    if (!csv)
        return 1;
    if (csv_has_empty_token(csv)) {
        fprintf(tgl_errf(c), "test-group-list: empty exact group token\n");
        invalid = true;
    }
    for (p = csv; *p || p == csv;) {
        size_t len = strcspn(p, ",");
        if (len > 0 && !exact_set_token(c, p, len, &out))
            invalid = true;
        p += len;
        if (*p == ',')
            p++;
        else
            break;
    }
    free(csv);
    if (invalid)
        exact_set_help(c);
    if (invalid || out.n == 0) {
        tgl_strs_free(&out);
        return 1;
    }
    for (size_t i = 0; i < out.n; i++)
        fprintf(c->out, "%s%s", i ? "," : "", out.v[i]);
    fprintf(c->out, "\n");
    tgl_strs_free(&out);
    return 0;
}

static int mode_exact_set(struct tgl_ctx *c, int argc, const char *const *argv)
{
    const char *arg = argc > 1 ? argv[1] : "";
    if (!arg[0]) {
        fprintf(tgl_errf(c), "test-group-list: empty exact group selection\n");
        exact_set_help(c);
        return 2;
    }
    return resolve_exact_set(c, arg);
}

/* The registered names containing `probe`, at most eight; true on a hit. */
static bool suggest_probe(struct tgl_ctx *c, const char *probe)
{
    size_t hits = 0;
    for (size_t i = 0; i < c->reg.n && hits < TGL_SUGGEST_MAX; i++) {
        if (strstr(c->reg.v[i], probe)) {
            fprintf(c->out, "%s\n", c->reg.v[i]);
            hits++;
        }
    }
    return hits > 0;
}

/* Tokens of >= 3 identifier bytes, longest first (ties: byte order,
 * descending, as sort -rn orders equal keys). */
static int token_cmp(const void *a, const void *b)
{
    const char *x = *(const char *const *)a, *y = *(const char *const *)b;
    size_t lx = strlen(x), ly = strlen(y);
    if (lx != ly)
        return lx > ly ? -1 : 1;
    return strcmp(y, x);
}

static bool suggest_tokens(const char *needle, struct tgl_strs *toks)
{
    const char *p = needle;
    while (*p) {
        const char *b;
        while (*p && !tgl_ident_char((unsigned char)*p))
            p++;
        b = p;
        while (tgl_ident_char((unsigned char)*p))
            p++;
        if (p - b >= 3 && !tgl_strs_push(toks, b, (size_t)(p - b)))
            return false;
    }
    qsort(toks->v, toks->n, sizeof(*toks->v), token_cmp);
    return true;
}

static void suggest_shrink(struct tgl_ctx *c, const char *longest)
{
    char *probe = strdup(longest);
    size_t len = probe ? strlen(probe) : 0;
    while (len >= 3 && !suggest_probe(c, probe))
        probe[--len] = '\0';
    free(probe);
}

static int mode_suggest(struct tgl_ctx *c, int argc, const char *const *argv)
{
    struct tgl_strs toks = {0};
    const char *needle = argc > 1 ? argv[1] : "";
    if (!needle[0] || !suggest_tokens(needle, &toks)) {
        tgl_strs_free(&toks);
        return 0;
    }
    for (size_t i = 0; i < toks.n; i++) {
        if (suggest_probe(c, toks.v[i])) {
            tgl_strs_free(&toks);
            return 0;
        }
    }
    if (toks.n > 0)
        suggest_shrink(c, toks.v[0]);
    tgl_strs_free(&toks);
    return 0;
}

static int mode_params_gated(struct tgl_ctx *c)
{
    struct tgl_strs gated = {0};
    if (!tgl_gated_or_refuse(c, &gated)) {
        tgl_strs_free(&gated);
        return 2;
    }
    for (size_t i = 0; i < gated.n; i++)
        fprintf(c->out, "%s\n", gated.v[i]);
    tgl_strs_free(&gated);
    return 0;
}

static int mode_impact_rules(struct tgl_ctx *c, int argc,
                             const char *const *argv)
{
    return tgl_check_impact_rules(c, argc > 1 ? argv[1] : TGL_DEFAULT_RULES);
}

static int usage(struct tgl_ctx *c)
{
    fprintf(tgl_errf(c), "usage: test-group-list [--count | --match SUBSTR | "
            "--resolve-exact ID... | --resolve-proof ID... | "
            "--resolve-exact-set CSV | --check-impact-rules [FILE] | "
            "--suggest SUBSTR | --params-gated | --report]\n");
    return 2;
}

static int dispatch(struct tgl_ctx *c, int argc, const char *const *argv)
{
    const char *m = argc > 0 ? argv[0] : "list";
    if (strcmp(m, "list") == 0)
        return mode_list(c);
    if (strcmp(m, "--count") == 0)
        return mode_count(c);
    if (strcmp(m, "--match") == 0)
        return mode_match(c, argc, argv);
    if (strcmp(m, "--resolve-exact") == 0)
        return mode_resolve_exact(c, argc, argv);
    if (strcmp(m, "--resolve-proof") == 0)
        return mode_resolve_proof(c, argc, argv);
    if (strcmp(m, "--resolve-exact-set") == 0)
        return mode_exact_set(c, argc, argv);
    if (strcmp(m, "--check-impact-rules") == 0)
        return mode_impact_rules(c, argc, argv);
    if (strcmp(m, "--suggest") == 0)
        return mode_suggest(c, argc, argv);
    if (strcmp(m, "--params-gated") == 0)
        return mode_params_gated(c);
    if (strcmp(m, "--report") == 0)
        return tgl_report(c);
    return usage(c);
}

static const char *or_default(const char *v, const char *fallback)
{
    return v ? v : fallback;
}

void tgl_sources_from_env(struct tgl_sources *s)
{
    s->registry = or_default(getenv("ZCL_TEST_REGISTRY_SRC"), TGL_DEFAULT_REGISTRY);
    s->runner = or_default(getenv("ZCL_TEST_RUNNER_SRC"), TGL_DEFAULT_RUNNER);
    s->families = or_default(getenv("ZCL_TEST_PROOF_FAMILIES_SRC"),
                             TGL_DEFAULT_FAMILIES);
    s->umbrellas = or_default(getenv("ZCL_TEST_UMBRELLAS_SRC"),
                              TGL_DEFAULT_UMBRELLAS);
    s->timing = or_default(getenv("ZCL_TEST_TIMING_JSON"), TGL_DEFAULT_TIMING);
}

static bool sources_present(const struct tgl_ctx *c)
{
    const char *need[] = {c->src->registry, c->src->runner, c->src->families};
    for (size_t i = 0; i < 3; i++) {
        FILE *f = fopen(need[i], "rb");
        if (!f) {
            fprintf(c->err, "test-group-list: FATAL \xe2\x80\x94 missing "
                    "proof source %s\n", need[i]);
            return false;
        }
        fclose(f);
    }
    return true;
}

int tgl_run(const struct tgl_sources *s, int argc, const char *const *argv,
            FILE *out, FILE *err)
{
    struct tgl_ctx c;
    int rc;
    memset(&c, 0, sizeof(c));
    c.src = s;
    c.out = out;
    c.err = err;
    if (!sources_present(&c))
        return 2;
    if (!tgl_load_registry(&c)) {
        tgl_ctx_free(&c);
        fprintf(err, "test-group-list: cannot read the registry\n");
        return 2;
    }
    rc = dispatch(&c, argc, argv);
    fflush(out);
    tgl_ctx_free(&c);
    return rc;
}
