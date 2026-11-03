/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: --report of the test-group list: reconcile the REGISTERED groups
 *          against the groups a run actually EXECUTED (the runner's own
 *          .cache/test-timing/last-run.json) and name every group in the
 *          gap. A registered group that never runs protects nothing.
 *
 * EXECUTED is read from the runner's artifact, never re-derived from the
 * runner's gating rules. The only modelled column is the reason, taken from
 * group_is_params_heavy() itself and used only to explain a gap the evidence
 * already established. Exit 0 when every gap has a reason; exit 1 when a
 * group is UNEXPLAINED, when the artifact is from a different registry, or
 * when the runner executed a name the registry does not know. */

#include "test_group_list_int.h"

#include "base/safe_alloc.h"

#include <ctype.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define REASON_GATED "params-heavy gate (group_is_params_heavy) \xe2\x80\x94 " \
                     "opt in with ZCL_PARAMS_TESTS=1 or --only="
#define RULE_RECON "── test registry reconciliation ────────────────────────────────────"
#define RULE_MISSING "── REGISTERED but NOT EXECUTED ─────────────────────────────────────"
#define RULE_EXTRA "── EXECUTED but NOT REGISTERED ─────────────────────────────────────"

static int loc_cmp(const void *a, const void *b)
{
    const char *x = *(const char *const *)a, *y = *(const char *const *)b;
    int r = strcoll(x, y);
    return r ? r : strcmp(x, y);
}

/* The value after `"key":` on the first line that carries one; sed's
 * greedy prefix means the LAST occurrence on a line wins. */
static bool field_on_line(const char *line, const char *key, bool numeric,
                          char *out, size_t cap)
{
    char pat[96];
    const char *at[64];
    size_t found = 0;
    const char *p = line;
    (void)snprintf(pat, sizeof(pat), "\"%s\"", key);
    while (found < 64 && (p = strstr(p, pat)) != NULL)
        at[found++] = p++;
    while (found-- > 0) {
        const char *v = tgl_skip_space(at[found] + strlen(pat));
        size_t len = 0;
        if (*v != ':')
            continue;
        v = tgl_skip_space(v + 1);
        if (numeric && (isdigit((unsigned char)*v) || *v == '-')) {
            len = 1 + strspn(v + 1, "0123456789");
        } else if (!numeric && *v == '"') {
            v++;
            len = strcspn(v, "\"");
            if (v[len] != '"')
                continue;
        } else {
            continue;
        }
        (void)snprintf(out, cap, "%.*s", (int)len, v);
        return true;
    }
    return false;
}

static void artifact_field(char **lines, size_t n, const char *key,
                           bool numeric, char *out, size_t cap)
{
    out[0] = '\0';
    for (size_t i = 0; i < n; i++)
        if (field_on_line(lines[i], key, numeric, out, cap))
            return;
}

/* Every "name":"ident" in the artifact, in byte-stream order. */
static bool name_in_line(const char *line, struct tgl_strs *out)
{
    static const char key[] = "\"name\":\"";
    const char *p = line;
    while ((p = strstr(p, key)) != NULL) {
        const char *b = p + sizeof(key) - 1, *e = b;
        while (tgl_ident_char((unsigned char)*e))
            e++;
        if (e > b && *e == '"' && !tgl_strs_push(out, b, (size_t)(e - b)))
            return false;
        p = b;
    }
    return true;
}

/* Every "name":"ident" of the artifact, sorted as sort(1) would. */
static bool executed_names(char **lines, size_t n, struct tgl_strs *out)
{
    for (size_t i = 0; i < n; i++)
        if (!name_in_line(lines[i], out))
            return false;
    qsort(out->v, out->n, sizeof(*out->v), loc_cmp);
    return true;
}

static int no_artifact(struct tgl_ctx *c, const struct tgl_strs *gated)
{
    FILE *o = c->out;
    fprintf(o, "executed_groups=UNKNOWN\nrun_artifact=MISSING (%s)\n\n",
            c->src->timing);
    fputs("No run artifact. EXECUTED cannot be established without one.\n"
          "Produce it with a full run (make test-parallel), or point this at an\n"
          "existing one:  ZCL_TEST_TIMING_JSON=<path> make test-registry-report\n\n"
          "For reference, the policy that gates groups out of a default run\n"
          "(group_is_params_heavy(), tests/harness/src/test_parallel.c) currently names:\n",
          o);
    for (size_t i = 0; i < gated->n; i++)
        fprintf(o, "  %s\n", gated->v[i]);
    return 0;
}

struct art {
    char total[32], ran[32], cached[32], skipped[32];
};

static void print_header(struct tgl_ctx *c, char **lines, size_t nl,
                         size_t exec_count, struct art *a)
{
    char stamp[96], mode[96];
    artifact_field(lines, nl, "group_count", true, a->total, sizeof(a->total));
    artifact_field(lines, nl, "groups_ran", true, a->ran, sizeof(a->ran));
    artifact_field(lines, nl, "groups_cached", true, a->cached,
                   sizeof(a->cached));
    artifact_field(lines, nl, "skipped_count", true, a->skipped,
                   sizeof(a->skipped));
    artifact_field(lines, nl, "generated_at_utc", false, stamp, sizeof(stamp));
    artifact_field(lines, nl, "mode", false, mode, sizeof(mode));
    fprintf(c->out, "executed_groups=%zu\nrun_artifact=%s\n"
            "run_generated_at_utc=%s\nrun_mode=%s\nrun_group_count=%s\n"
            "run_groups_ran=%s\nrun_groups_cached=%s\nrun_skipped_count=%s\n",
            exec_count, c->src->timing, stamp, mode, a->total, a->ran,
            a->cached, a->skipped);
}

/* comm -23 (only in A) and comm -13 (only in B) of two sorted lists. */
static void comm_split(const char *const *a, size_t na, const char *const *b,
                       size_t nb, struct tgl_strs *only_a,
                       struct tgl_strs *only_b)
{
    size_t i = 0, j = 0;
    while (i < na || j < nb) {
        int r = i >= na ? 1 : (j >= nb ? -1 : loc_cmp(&a[i], &b[j]));
        if (r < 0) {
            (void)tgl_strs_push(only_a, a[i], strlen(a[i]));
            i++;
        } else if (r > 0) {
            (void)tgl_strs_push(only_b, b[j], strlen(b[j]));
            j++;
        } else {
            i++;
            j++;
        }
    }
}

static bool missing_section(struct tgl_ctx *c, const struct tgl_strs *missing,
                            const struct tgl_strs *gated)
{
    bool clean = true;
    fputc('\n', c->out);
    fputs(RULE_MISSING "\n", c->out);
    if (missing->n == 0)
        fputs("(none)\n", c->out);
    for (size_t i = 0; i < missing->n; i++) {
        const char *g = missing->v[i];
        if (tgl_strs_has(gated, g)) {
            fprintf(c->out, "  %-42s %s%s\n", g, REASON_GATED, g);
        } else {
            fprintf(c->out, "  %-42s UNEXPLAINED\n", g);
            clean = false;
        }
    }
    return clean;
}

static bool extra_section(struct tgl_ctx *c, const struct tgl_strs *extra)
{
    fputc('\n', c->out);
    fputs(RULE_EXTRA "\n", c->out);
    if (extra->n == 0) {
        fputs("(none)\n", c->out);
        return true;
    }
    for (size_t i = 0; i < extra->n; i++)
        fprintf(c->out, "  %s\n", extra->v[i]);
    fputs("  ^ the registry parse disagrees with the runner; every count "
          "above is suspect\n", c->out);
    return false;
}

static int reconcile(struct tgl_ctx *c, const struct tgl_strs *gated,
                     char *text)
{
    struct tgl_strs exec = {0}, missing = {0}, extra = {0};
    char **lines = NULL, count[32];
    struct art a;
    size_t nl = tgl_split_lines(text, &lines);
    const char **regsorted = zcl_malloc((c->reg.n + 1) * sizeof(*regsorted), "tgl_regsorted");
    bool ok = lines && regsorted && executed_names(lines, nl, &exec);
    if (ok) {
        for (size_t i = 0; i < c->reg.n; i++)
            regsorted[i] = c->reg.v[i];
        qsort(regsorted, c->reg.n, sizeof(*regsorted), loc_cmp);
        print_header(c, lines, nl, exec.n, &a);
        (void)snprintf(count, sizeof(count), "%zu", c->reg.n);
        if (a.total[0] && strcmp(a.total, count) != 0)
            fprintf(c->out, "\nSTALE ARTIFACT: the run recorded %s registered "
                    "groups, this\n  source tree has %s. The by-name "
                    "difference below mixes\n  registry drift with gating and "
                    "should not be read as gating.\n", a.total, count);
        comm_split(regsorted, c->reg.n, (const char *const *)exec.v, exec.n,
                   &missing, &extra);
        ok = (!a.total[0] || strcmp(a.total, count) == 0);
        ok = missing_section(c, &missing, gated) && ok;
        ok = extra_section(c, &extra) && ok;
        fputs(ok ? "\nVERDICT: every registered group is accounted for.\n"
                 : "\nVERDICT: unaccounted-for groups above \xe2\x80\x94 a "
                   "registered group that never\n  runs is a test protecting "
                   "nothing.\n", c->out);
    }
    free(lines);
    free(regsorted);
    tgl_strs_free(&exec);
    tgl_strs_free(&missing);
    tgl_strs_free(&extra);
    return ok ? 0 : 1;
}

bool tgl_gated_or_refuse(struct tgl_ctx *c, struct tgl_strs *gated)
{
    if (tgl_params_gated(c, gated) && gated->n > 0)
        return true;
    fprintf(tgl_errf(c), "test-group-list: FATAL \xe2\x80\x94 "
            "group_is_params_heavy() in %s yielded no names; its shape "
            "changed and this parse is stale\n", c->src->registry);
    return false;
}

int tgl_report(struct tgl_ctx *c)
{
    struct tgl_strs gated = {0};
    struct stat sb;
    char *text;
    int rc;
    (void)setlocale(LC_COLLATE, "");
    if (!tgl_gated_or_refuse(c, &gated))
        return 2;
    fputs(RULE_RECON "\n", c->out);
    fprintf(c->out, "registry_source=tests/harness/src/test_parallel.c\n"
            "registered_groups=%zu\n", c->reg.n);
    if (stat(c->src->timing, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        rc = no_artifact(c, &gated);
    } else if (!(text = tgl_read_file(c->src->timing, NULL))) {
        rc = 1;
    } else {
        rc = reconcile(c, &gated, text);
        free(text);
    }
    tgl_strs_free(&gated);
    return rc;
}
