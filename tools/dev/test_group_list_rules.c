/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: --check-impact-rules of the test-group list: every proof-plan ID a
 *          rule row declares must be exact, and the union of the plans of the
 *          rows that match a registered test source must select that
 *          source's own group. Rules compose by union, so each source is
 *          checked against every row that matches it. */

#include "test_group_list_int.h"

#include "base/safe_alloc.h"

#include "platform/glob_match.h"
#include "util/spawn.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TGL_GIT_TIMEOUT_MS (60 * 1000)
#define TGL_GIT_OUT_MAX (8u * 1024u * 1024u)
#define TGL_TEST_PREFIX "tests/harness/src/test_"

struct rules_state {
    struct tgl_strs tests; /* tracked and unignored test sources, git order */
    char **plans;          /* plan text per test, each plan then a blank */
    bool bad;
};

static bool list_test_sources(struct rules_state *st)
{
    const char *const argv[] = {"git", "ls-files", "--cached", "--others",
                                "--exclude-standard", "--",
                                "tests/harness/src/test_*.c", NULL};
    struct zcl_spawn_binary_observation obs;
    char *buf = zcl_malloc(TGL_GIT_OUT_MAX + 1, "tgl_git_out");
    bool ok;
    if (!buf)
        return false;
    ok = zcl_spawn_capture_binary(argv, buf, TGL_GIT_OUT_MAX, TGL_GIT_TIMEOUT_MS,
                                  &obs).ok;
    if (ok) {
        char *p = buf;
        buf[obs.output_len] = '\0';
        while (*p) {
            size_t len = strcspn(p, "\n");
            if (len > 0 && !tgl_strs_push(&st->tests, p, len))
                ok = false;
            p += len + (p[len] ? 1 : 0);
        }
    }
    free(buf);
    st->plans = zcl_calloc(st->tests.n + 1, sizeof(*st->plans), "tgl_plans");
    return ok && st->plans;
}

static void rules_free(struct rules_state *st)
{
    for (size_t i = 0; i < st->tests.n; i++)
        free(st->plans ? st->plans[i] : NULL);
    free(st->plans);
    tgl_strs_free(&st->tests);
}

static bool plan_append(struct rules_state *st, size_t idx, const char *plan)
{
    size_t old = st->plans[idx] ? strlen(st->plans[idx]) : 0;
    char *bigger = zcl_realloc(st->plans[idx], old + strlen(plan) + 2, "tgl_plan");
    if (!bigger)
        return false;
    st->plans[idx] = bigger;
    (void)snprintf(bigger + old, strlen(plan) + 2, "%s ", plan);
    return true;
}

static bool is_test_source_pattern(const char *pat, size_t len)
{
    size_t pre = strlen(TGL_TEST_PREFIX);
    return len >= pre + 2 && strncmp(pat, TGL_TEST_PREFIX, pre) == 0 &&
           strcmp(pat + len - 2, ".c") == 0;
}

static bool file_exists(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0;
}

/* The tracked sources one pattern names (compgen -G over the tree). */
static bool pattern_plans(struct rules_state *st, const char *pat,
                          const char *plan)
{
    bool literal = strpbrk(pat, "*?[\\") == NULL;
    for (size_t i = 0; i < st->tests.n; i++) {
        const char *t = st->tests.v[i];
        bool hit = literal ? strcmp(t, pat) == 0
                           : platform_glob_match(pat, t, true);
        if (hit && file_exists(t) && !plan_append(st, i, plan))
            return false;
    }
    return true;
}

static bool rule_patterns(struct rules_state *st, const char *patterns,
                          const char *plan)
{
    const char *p = patterns;
    for (;;) {
        size_t len = strcspn(p, "|");
        char *one = strndup(p, len);
        bool ok = one != NULL;
        if (ok && is_test_source_pattern(one, len))
            ok = pattern_plans(st, one, plan);
        free(one);
        if (!ok)
            return false;
        if (!p[len])
            return true;
        p += len + 1;
    }
}

static bool plan_ids_exact(struct tgl_ctx *c, struct rules_state *st,
                           const char *plan)
{
    struct tgl_strs ids = {0};
    bool ok = tgl_words(plan, &ids);
    for (size_t i = 0; ok && i < ids.n; i++) {
        if (!tgl_resolve_exact(c, ids.v[i], NULL)) {
            fprintf(tgl_errf(c), "test-group-list: non-exact impact proof "
                    "id: %s\n", ids.v[i]);
            st->bad = true;
        }
    }
    tgl_strs_free(&ids);
    return ok;
}

/* One AGENT_IMPACT_RULE row. False only on resource failure. */
static bool rule_row(struct tgl_ctx *c, struct rules_state *st,
                     const char *rules, size_t lineno, const char *line)
{
    char *patterns, *plan;
    bool ok = true;
    if (strncmp(tgl_skip_space(line), "AGENT_IMPACT_RULE(", 18) != 0)
        return true;
    patterns = tgl_quoted_field(line, 0);
    plan = tgl_quoted_field(line, 1);
    if (!patterns || tgl_blank(patterns)) {
        fprintf(tgl_errf(c), "test-group-list: empty impact pattern at "
                "%s:%zu\n", rules, lineno);
        st->bad = true;
    } else if (!plan || tgl_blank(plan)) {
        fprintf(tgl_errf(c), "test-group-list: empty impact proof plan at "
                "%s:%zu\n", rules, lineno);
        st->bad = true;
    } else {
        ok = plan_ids_exact(c, st, plan) && rule_patterns(st, patterns, plan);
    }
    free(patterns);
    free(plan);
    return ok;
}

static bool plan_selects(struct tgl_ctx *c, const char *plan, const char *group)
{
    struct tgl_strs ids = {0};
    bool selected = false;
    if (!tgl_words(plan, &ids))
        return true;
    for (size_t i = 0; !selected && i < ids.n; i++)
        selected = tgl_token_selects(c, ids.v[i], group);
    tgl_strs_free(&ids);
    return selected;
}

/* Each registered test source against the union of the rows matching it. */
static void union_check(struct tgl_ctx *c, struct rules_state *st)
{
    for (size_t i = 0; i < st->tests.n; i++) {
        const char *file = st->tests.v[i], *base = strrchr(file, '/');
        char group[256];
        size_t len;
        if (!st->plans[i])
            continue;
        base = base ? base + 1 : file;
        len = strlen(base);
        if (len < 2 || len >= sizeof(group))
            continue;
        memcpy(group, base, len - 2);
        group[len - 2] = '\0';
        if (!tgl_is_registered(c, group) || plan_selects(c, st->plans[i], group))
            continue;
        fprintf(tgl_errf(c), "test-group-list: impact rules match %s but "
                "their union omits its registered group %s (plans: %s)\n",
                file, group, st->plans[i]);
        st->bad = true;
    }
}

int tgl_check_impact_rules(struct tgl_ctx *c, const char *rules)
{
    struct rules_state st;
    char *text = tgl_read_file(rules, NULL), **lines = NULL;
    size_t n = 0;
    bool ok;
    if (!text) {
        fprintf(tgl_errf(c), "test-group-list: impact rules missing: %s\n",
                rules);
        return 2;
    }
    memset(&st, 0, sizeof(st));
    ok = list_test_sources(&st);
    n = ok ? tgl_split_lines(text, &lines) : 0;
    for (size_t i = 0; ok && lines && i < n; i++)
        ok = rule_row(c, &st, rules, i + 1, lines[i]);
    if (ok)
        union_check(c, &st);
    if (!ok)
        fprintf(tgl_errf(c), "test-group-list: cannot read the impact rules\n");
    free(lines);
    free(text);
    rules_free(&st);
    return ok && !st.bad ? 0 : 1;
}
