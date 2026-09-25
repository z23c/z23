/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Evaluation half of the action-root reuse study: compare two
 * snapshots action by action, attribute each invalidation to the inputs that
 * moved, ask the existing content-keyed test cache which groups it would
 * still reuse, and write the per-pair and aggregate report rows.
 */

#include "action_root_reuse_study.h"

#include "base/safe_alloc.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- aggregation ------------------------------------------------------- */

void st_reason_add(struct st_reasons *r, const char *name)
{
    for (size_t i = 0; i < r->n; i++)
        if (strcmp(r->name[i], name) == 0) {
            r->count[i]++;
            return;
        }
    size_t at = r->n < ST_REASON_MAX ? r->n++ : ST_REASON_MAX - 1;
    (void)snprintf(r->name[at], sizeof(r->name[at]), "%s",
                   at == ST_REASON_MAX - 1 ? "other" : name);
    r->count[at]++;
}

static size_t st_cause_slot(struct st_causes *k, const char *path)
{
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        h = (h ^ *p) * 1099511628211ULL;
    for (size_t probe = 0; probe < ST_CAUSE_SLOTS; probe++) {
        size_t at = (size_t)((h + probe) % ST_CAUSE_SLOTS);
        if (!k->path[at]) {
            k->path[at] = zcl_strdup(path, "study cause path");
            return k->path[at] ? at : ST_CAUSE_SLOTS;
        }
        if (strcmp(k->path[at], path) == 0)
            return at;
    }
    return ST_CAUSE_SLOTS;
}

void st_cause_add(struct st_causes *k, const char *path,
                         uint32_t pair)
{
    size_t at = st_cause_slot(k, path);
    if (at == ST_CAUSE_SLOTS)
        return;
    k->tus[at]++;
    if (k->last_pair[at] != pair) {
        k->last_pair[at] = pair;
        k->pairs[at]++;
    }
}

static int st_input_cmp(const struct vcs_action_input_v2 *a,
                        const struct vcs_action_input_v2 *b)
{
    return strcmp(a->path, b->path);
}

/* Every source input that differs between two preimages (content, or
 * present on one side only) is one cause of this invalidation. */
static void st_cause_sources(struct st_causes *k,
                             const struct vcs_action_preimage_v2 *p,
                             const struct vcs_action_preimage_v2 *q,
                             uint32_t pair)
{
    size_t i = 0, j = 0;
    while (i < p->source_count || j < q->source_count) {
        int cmp = i >= p->source_count ? 1
                : j >= q->source_count ? -1
                : st_input_cmp(&p->sources[i], &q->sources[j]);
        if (cmp < 0) {
            st_cause_add(k, p->sources[i++].path, pair);
        } else if (cmp > 0) {
            st_cause_add(k, q->sources[j++].path, pair);
        } else {
            if (memcmp(p->sources[i].sha3, q->sources[j].sha3, 32) != 0)
                st_cause_add(k, p->sources[i].path, pair);
            i++;
            j++;
        }
    }
}

static void st_cause_record(struct st_causes *k, const struct st_tu *p,
                            const struct st_tu *q, uint32_t pair)
{
    enum vcs_action_field_v2 f = VCS_ACTION_FIELD_V2_NONE;
    if (!p->pre || !q->pre ||
        !vcs_action_preimage_v2_first_diff(p->pre, p->pre_len, q->pre,
                                           q->pre_len, &f))
        return;
    if (f < VCS_ACTION_FIELD_V2_COUNT)
        k->field[f]++;
    if (f != VCS_ACTION_FIELD_V2_SOURCE)
        return;
    struct vcs_action_preimage_v2_decoded dp = {0}, dq = {0};
    char why[128];
    if (vcs_action_preimage_v2_decode(p->pre, p->pre_len, &dp, why,
                                      sizeof(why)) &&
        vcs_action_preimage_v2_decode(q->pre, q->pre_len, &dq, why,
                                      sizeof(why)))
        st_cause_sources(k, &dp.view, &dq.view, pair);
    vcs_action_preimage_v2_decoded_free(&dp);
    vcs_action_preimage_v2_decoded_free(&dq);
}

const struct st_tu *st_find_tu(const struct st_snap *s,
                                      const char *src, size_t hint)
{
    if (hint < s->n && strcmp(s->tu[hint].src, src) == 0)
        return &s->tu[hint];
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->tu[i].src, src) == 0)
            return &s->tu[i];
    return NULL;
}

enum st_verdict st_compare(const struct st_outcome *p,
                                  const struct st_outcome *q,
                                  bool have_parent, const char **reason)
{
    *reason = NULL;
    if (!have_parent)
        return ST_V_ADDED;
    if (q->state != ST_ROOT) {
        *reason = q->reason;
        return ST_V_MISS;
    }
    if (p->state != ST_ROOT) {
        *reason = p->reason;
        return ST_V_MISS;
    }
    return memcmp(p->root, q->root, 32) == 0 ? ST_V_REUSE : ST_V_CHANGED;
}

static void st_tally_add(struct st_tally *t, enum st_verdict v,
                         const char *reason, bool parent_side)
{
    t->total++;
    if (v == ST_V_REUSE)
        t->reuse++;
    else if (v == ST_V_CHANGED)
        t->changed++;
    else if (v == ST_V_ADDED)
        t->added++;
    if (v != ST_V_MISS)
        return;
    t->miss++;
    char name[128];
    (void)snprintf(name, sizeof(name), "%s%s", parent_side ? "parent:" : "",
                   reason ? reason : "unknown");
    st_reason_add(&t->miss_reasons, name);
}

static void st_pair_one(const struct st_tu *p, const struct st_tu *q,
                        struct st_pair_result *r, struct st_causes *k,
                        uint32_t pair)
{
    const char *why = NULL;
    enum st_verdict va = st_compare(p ? &p->a : NULL, &q->a, p != NULL,
                                    &why);
    st_tally_add(&r->a, va, why,
                 va == ST_V_MISS && q->a.state == ST_ROOT);
    enum st_verdict vb = st_compare(p ? &p->b : NULL, &q->b, p != NULL,
                                    &why);
    st_tally_add(&r->b, vb, why,
                 vb == ST_V_MISS && q->b.state == ST_ROOT);
    if (vb == ST_V_CHANGED && k)
        st_cause_record(k, p, q, pair);
    if (q->a.state == ST_ROOT && q->b.state == ST_ROOT &&
        memcmp(q->a.root, q->b.root, 32) != 0)
        r->ab_violations++;
}

void st_pair_compare(const struct st_snap *parent,
                            const struct st_snap *child,
                            struct st_pair_result *r, struct st_causes *k,
                            uint32_t pair)
{
    memset(r, 0, sizeof(*r));
    for (size_t i = 0; i < child->n; i++) {
        const struct st_tu *q = &child->tu[i];
        st_pair_one(st_find_tu(parent, q->src, i), q, r, k, pair);
    }
}

/* ---- the existing content-keyed test cache ----------------------------- */

static bool st_probe_line(char *line, char **group, char **label)
{
    if (strncmp(line, "PROBE ", 6) != 0)
        return false;
    char *save = NULL;
    (void)strtok_r(line, " ", &save);
    *group = strtok_r(NULL, " ", &save);
    (void)strtok_r(NULL, " ", &save);
    *label = strtok_r(NULL, " ", &save);
    return *group && *label;
}

static bool st_probe_run(const struct st_ctx *c, const char *const *changed,
                         size_t n, struct st_list *groups,
                         struct st_list *labels, int64_t *us)
{
    const char *argv[ST_BATCH + 12];
    char args[ST_BATCH][PATH_MAX + 32];
    size_t k = 0;
    argv[k++] = "env";
    argv[k++] = "-C";
    argv[k++] = c->repo;
    argv[k++] = "-u";
    argv[k++] = "ZCL_HOTSWAP_TEST_MODULE";
    argv[k++] = c->test_bin;
    argv[k++] = "--cache";
    if (n)
        argv[k++] = "--cache-snapshot";
    for (size_t i = 0; i < n && i < ST_BATCH; i++) {
        (void)snprintf(args[i], sizeof(args[i]), "--changed-source=%s",
                       changed[i]);
        argv[k++] = args[i];
    }
    argv[k++] = "--cache-probe-only";
    argv[k] = NULL;
    int64_t t0 = platform_time_monotonic_us();
    struct st_proc p;
    bool ok = st_run(argv, ST_PROBE_CAP, &p);
    *us += platform_time_monotonic_us() - t0;
    char *save = NULL;
    for (char *line = ok ? strtok_r(p.out, "\n", &save) : NULL;
         ok && line; line = strtok_r(NULL, "\n", &save)) {
        char *g = NULL, *l = NULL;
        if (st_probe_line(line, &g, &l))
            ok = st_list_push(groups, g) && st_list_push(labels, l);
    }
    if (!ok)
        fprintf(c->log, "probe run failed exit=%d: %.300s\n", p.exit_code,
                p.out ? p.out : "");
    st_proc_free(&p);
    return ok && groups->n > 0;
}

static void st_harness_files(const struct st_ctx *c, struct st_list *out)
{
    static const char *const units[] = {
        "tests/harness/src/test_parallel", "tests/harness/src/testcache",
    };
    for (size_t u = 0; u < sizeof(units) / sizeof(units[0]); u++) {
        char dep[PATH_MAX];
        (void)snprintf(dep, sizeof(dep), "%s/%s.d", c->test_obj, units[u]);
        struct st_list l = {0};
        if (st_depfile_list(dep, &l))
            for (size_t i = 0; i < l.n; i++)
                if (!st_list_has(out, l.v[i]))
                    (void)st_list_push(out, l.v[i]);
        st_list_free(&l);
    }
}

void st_groups_baseline(const struct st_ctx *c, struct st_groups *g)
{
    int64_t us = 0;
    memset(g, 0, sizeof(*g));
    g->ok = st_probe_run(c, NULL, 0, &g->name, &g->label, &us);
    for (size_t i = 0; g->ok && i < g->label.n; i++)
        g->cacheable += strcmp(g->label.v[i], "cacheable") == 0;
    st_harness_files(c, &g->harness);
    fprintf(c->log, "test baseline ok=%d groups=%zu cacheable=%zu "
            "harness_files=%zu probe_us=%lld\n", g->ok, g->name.n,
            g->cacheable, g->harness.n, (long long)us);
}

static bool st_changed_paths(const struct st_ctx *c, const char *parent,
                             const char *child, struct st_list *out)
{
    const char *argv[] = { "git", "-C", c->repo, "diff", "--name-only",
                           "--no-renames", parent, child, NULL };
    struct st_proc p;
    bool ok = st_run(argv, ST_PROBE_CAP, &p);
    char *save = NULL;
    for (char *line = ok ? strtok_r(p.out, "\n", &save) : NULL;
         ok && line; line = strtok_r(NULL, "\n", &save))
        if (line[0] && !strstr(line, ".."))
            ok = st_list_push(out, line);
    st_proc_free(&p);
    return ok;
}

static void st_mark_invalidated(const struct st_list *groups,
                                const struct st_list *labels,
                                const struct st_groups *base, bool *hit)
{
    for (size_t i = 0; i < groups->n; i++) {
        if (strcmp(labels->v[i], "changed-input-runs-fresh") != 0)
            continue;
        for (size_t b = 0; b < base->name.n; b++)
            if (strcmp(base->name.v[b], groups->v[i]) == 0)
                hit[b] = true;
    }
}

static void st_groups_count(const struct st_groups *base, const bool *hit,
                            bool all, struct st_group_result *r)
{
    r->total = base->name.n;
    for (size_t b = 0; b < base->name.n; b++) {
        if (strcmp(base->label.v[b], "cacheable") != 0) {
            r->uncacheable++;
            continue;
        }
        r->cacheable++;
        if (all || hit[b])
            r->invalidated++;
        else
            r->unchanged++;
    }
}

void st_groups_pair(const struct st_ctx *c, const struct st_groups *g,
                           const struct st_snap *parent,
                           const struct st_snap *child,
                           struct st_group_result *r)
{
    memset(r, 0, sizeof(*r));
    struct st_list changed = {0};
    bool *hit = g->ok ? zcl_calloc(g->name.n + 1, sizeof(bool),
                                   "study group hits") : NULL;
    r->ok = hit && st_changed_paths(c, parent->sha, child->sha, &changed);
    r->changed_paths = changed.n;
    r->toolkey_changed = parent->test_flags && child->test_flags &&
                         strcmp(parent->test_flags, child->test_flags) != 0;
    for (size_t i = 0; r->ok && i < changed.n; i++)
        r->harness_changed |= st_list_has(&g->harness, changed.v[i]);
    for (size_t at = 0; r->ok && at < changed.n; at += ST_BATCH) {
        struct st_list groups = {0}, labels = {0};
        size_t n = changed.n - at < ST_BATCH ? changed.n - at : ST_BATCH;
        r->ok = st_probe_run(c, (const char *const *)changed.v + at, n,
                             &groups, &labels, &r->probe_us);
        r->probe_runs++;
        if (r->ok)
            st_mark_invalidated(&groups, &labels, g, hit);
        st_list_free(&groups);
        st_list_free(&labels);
    }
    if (r->ok)
        st_groups_count(g, hit,
                        r->toolkey_changed || r->harness_changed, r);
    free(hit);
    st_list_free(&changed);
}

/* ---- corpus ------------------------------------------------------------ */

bool st_rev_parse(const struct st_ctx *c, const char *rev,
                         char out[64])
{
    const char *argv[] = { "git", "-C", c->repo, "rev-parse", "--verify",
                           "--quiet", rev, NULL };
    return st_run_line(argv, out, 64) && strlen(out) == 40;
}

/* Oldest-first first-parent chain: corpus+1 commits give corpus pairs. */
bool st_corpus_chain(const struct st_ctx *c, struct st_list *chain)
{
    char count[32];
    (void)snprintf(count, sizeof(count), "%u", c->corpus + 1);
    const char *argv[] = { "git", "-C", c->repo, "rev-list", "--first-parent",
                           "--reverse", "-n", count, c->main_sha, NULL };
    struct st_proc p;
    bool ok = st_run(argv, ST_SMALL_CAP, &p);
    char *save = NULL;
    for (char *line = ok ? strtok_r(p.out, "\n", &save) : NULL;
         ok && line; line = strtok_r(NULL, "\n", &save))
        ok = st_list_push(chain, line);
    st_proc_free(&p);
    return ok && chain->n == c->corpus + 1;
}

/* Hand-picked edits: each --pick=LABEL=REV; the parent is REV^1. */
size_t st_picked_load(const struct st_ctx *c, struct st_pair *out,
                      size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < c->picks.n && n < cap; i++) {
        const char *pick = c->picks.v[i];
        const char *eq = strchr(pick, '=');
        char parent_rev[128];
        struct st_pair *p = &out[n];
        if (!eq || eq == pick || (size_t)(eq - pick) >= sizeof(p->label) ||
            snprintf(parent_rev, sizeof(parent_rev), "%s^1", eq + 1) >=
                (int)sizeof(parent_rev)) {
            fprintf(c->log, "pick %s is not LABEL=REV\n", pick);
            continue;
        }
        (void)snprintf(p->label, sizeof(p->label), "%.*s",
                       (int)(eq - pick), pick);
        if (st_rev_parse(c, eq + 1, p->child) &&
            st_rev_parse(c, parent_rev, p->parent))
            n++;
        else
            fprintf(c->log, "pick %s unresolved\n", pick);
    }
    return n;
}

/* ---- report output ----------------------------------------------------- */

void st_tally_merge(struct st_tally *into, const struct st_tally *t)
{
    into->total += t->total;
    into->reuse += t->reuse;
    into->changed += t->changed;
    into->miss += t->miss;
    into->added += t->added;
    for (size_t i = 0; i < t->miss_reasons.n; i++)
        for (uint64_t k = 0; k < t->miss_reasons.count[i]; k++)
            st_reason_add(&into->miss_reasons, t->miss_reasons.name[i]);
}

void st_group_merge(struct st_group_result *into,
                           const struct st_group_result *g)
{
    into->total += g->total;
    into->cacheable += g->cacheable;
    into->unchanged += g->unchanged;
    into->invalidated += g->invalidated;
    into->uncacheable += g->uncacheable;
    into->probe_runs += g->probe_runs;
    into->probe_us += g->probe_us;
    into->pairs_ok += g->ok;
    into->pairs_failed += !g->ok;
}

/* Per-snapshot coverage: every action has a root or an explicit MISS. */
void st_snap_account(struct st_totals *t, const struct st_snap *s,
                            FILE *out)
{
    uint64_t ra = 0, rb = 0;
    for (size_t i = 0; i < s->n; i++) {
        const struct st_tu *u = &s->tu[i];
        ra += u->a.state == ST_ROOT;
        rb += u->b.state == ST_ROOT;
        if (u->a.state == ST_ROOT)
            st_sample(&t->us_a, u->a.us);
        else
            st_reason_add(&t->miss_snap_a, u->a.reason);
        if (u->b.state == ST_ROOT)
            st_sample(&t->us_b, u->b.us);
        else
            st_reason_add(&t->miss_snap_b, u->b.reason);
        if (u->pp_us)
            st_sample(&t->us_pp, u->pp_us);
    }
    t->snaps++;
    t->snaps_immutable += s->immutable;
    t->actions += s->n;
    t->rooted_a += ra;
    t->rooted_b += rb;
    t->miss_a += s->n - ra;
    t->miss_b += s->n - rb;
    fprintf(out, "%s\t%s\t%d\t%zu\t%llu\t%llu\t%llu\t%llu\t%lld\t%lld\n",
            s->label, s->sha, s->immutable, s->n, (unsigned long long)ra,
            (unsigned long long)(s->n - ra), (unsigned long long)rb,
            (unsigned long long)(s->n - rb), (long long)s->archive_us,
            (long long)s->parse_us);
}

double st_share(uint64_t part, uint64_t whole)
{
    return whole ? 100.0 * (double)part / (double)whole : 0.0;
}

void st_pair_row(FILE *out, const char *set, const struct st_pair *p,
                        const struct st_pair_result *r,
                        const struct st_group_result *g)
{
    fprintf(out, "%s\t%s\t%.12s\t%.12s\t%llu\t%llu\t%llu\t%llu\t%llu\t"
            "%llu\t%llu\t%llu\t%llu\t%d\t%zu\t%d\t%d\t%llu\t%llu\t%llu\t"
            "%llu\n",
            set, p->label, p->parent, p->child,
            (unsigned long long)r->b.total, (unsigned long long)r->a.reuse,
            (unsigned long long)r->a.changed, (unsigned long long)r->a.miss,
            (unsigned long long)r->a.added, (unsigned long long)r->b.reuse,
            (unsigned long long)r->b.changed, (unsigned long long)r->b.miss,
            (unsigned long long)r->b.added, g->ok, g->changed_paths,
            g->toolkey_changed, g->harness_changed,
            (unsigned long long)g->cacheable,
            (unsigned long long)g->unchanged,
            (unsigned long long)g->invalidated,
            (unsigned long long)g->uncacheable);
    fflush(out);
}

static void st_print_reasons(FILE *out, const char *title,
                             const struct st_reasons *r)
{
    for (size_t i = 0; i < r->n; i++)
        fprintf(out, "%s\t%s\t%llu\n", title, r->name[i],
                (unsigned long long)r->count[i]);
}

static void st_print_tally(FILE *out, const char *name,
                           const struct st_tally *t)
{
    fprintf(out, "%s actions=%llu reuse=%llu (%.2f%%) changed=%llu "
            "(%.2f%%) miss=%llu (%.2f%%) added=%llu (%.2f%%)\n", name,
            (unsigned long long)t->total, (unsigned long long)t->reuse,
            st_share(t->reuse, t->total), (unsigned long long)t->changed,
            st_share(t->changed, t->total), (unsigned long long)t->miss,
            st_share(t->miss, t->total), (unsigned long long)t->added,
            st_share(t->added, t->total));
}

/* Ranked view of a path counter: most counted first, then by path. */
static int st_rank_cmp(const void *a, const void *b)
{
    const struct st_rank *x = a, *y = b;
    if (x->n != y->n)
        return x->n < y->n ? 1 : -1;
    return strcmp(x->path, y->path);
}

size_t st_rank_build(const struct st_causes *k, struct st_rank **out)
{
    size_t n = 0;
    for (size_t i = 0; i < ST_CAUSE_SLOTS; i++)
        n += k->path[i] != NULL;
    *out = zcl_calloc(n + 1, sizeof(**out), "study rank");
    if (!*out)
        return 0;
    size_t w = 0;
    for (size_t i = 0; i < ST_CAUSE_SLOTS; i++)
        if (k->path[i])
            (*out)[w++] = (struct st_rank){ k->path[i], k->tus[i],
                                            k->pairs[i] };
    qsort(*out, w, sizeof(**out), st_rank_cmp);
    return w;
}

void st_causes_free(struct st_causes *k)
{
    for (size_t i = 0; k && i < ST_CAUSE_SLOTS; i++)
        free(k->path[i]);
}

void st_summary_totals(FILE *s, const char *set, struct st_totals *t)
{
    char name[64];
    fprintf(s, "== %s ==\n", set);
    (void)snprintf(name, sizeof(name), "%s A(build-depfile)", set);
    st_print_tally(s, name, &t->a);
    (void)snprintf(name, sizeof(name), "%s B(snapshot-depfile)", set);
    st_print_tally(s, name, &t->b);
    st_print_reasons(s, "pair-miss-A", &t->a.miss_reasons);
    st_print_reasons(s, "pair-miss-B", &t->b.miss_reasons);
    fprintf(s, "%s a_b_root_disagreements=%llu\n", set,
            (unsigned long long)t->ab_violations);
    fprintf(s, "%s tests pairs_probed=%llu pairs_failed=%llu groups=%llu "
            "cacheable=%llu unchanged=%llu (%.2f%% "
            "of cacheable) invalidated=%llu uncacheable=%llu probe_runs=%zu "
            "probe_us=%lld\n", set, (unsigned long long)t->g.pairs_ok,
            (unsigned long long)t->g.pairs_failed,
            (unsigned long long)t->g.total,
            (unsigned long long)t->g.cacheable,
            (unsigned long long)t->g.unchanged,
            st_share(t->g.unchanged, t->g.cacheable),
            (unsigned long long)t->g.invalidated,
            (unsigned long long)t->g.uncacheable, t->g.probe_runs,
            (long long)t->g.probe_us);
    fprintf(s, "%s snapshots=%llu immutable=%llu actions=%llu "
            "rooted_A=%llu (%.2f%%) miss_A=%llu rooted_B=%llu (%.2f%%) "
            "miss_B=%llu\n", set, (unsigned long long)t->snaps,
            (unsigned long long)t->snaps_immutable,
            (unsigned long long)t->actions,
            (unsigned long long)t->rooted_a, st_share(t->rooted_a, t->actions),
            (unsigned long long)t->miss_a, (unsigned long long)t->rooted_b,
            st_share(t->rooted_b, t->actions),
            (unsigned long long)t->miss_b);
    st_print_reasons(s, "snapshot-miss-A", &t->miss_snap_a);
    st_print_reasons(s, "snapshot-miss-B", &t->miss_snap_b);
    fprintf(s, "%s derive_us A total=%lld n=%zu p50=%lld p95=%lld | B "
            "total=%lld n=%zu p50=%lld p95=%lld | preprocess total=%lld "
            "p50=%lld p95=%lld\n", set, (long long)st_sum(&t->us_a),
            t->us_a.n, (long long)st_pct(&t->us_a, 50),
            (long long)st_pct(&t->us_a, 95), (long long)st_sum(&t->us_b),
            t->us_b.n, (long long)st_pct(&t->us_b, 50),
            (long long)st_pct(&t->us_b, 95), (long long)st_sum(&t->us_pp),
            (long long)st_pct(&t->us_pp, 50), (long long)st_pct(&t->us_pp, 95));
}


void st_summary_causes(FILE *s, const struct st_causes *k)
{
    for (size_t f = 0; f < VCS_ACTION_FIELD_V2_COUNT; f++)
        if (k->field[f])
            fprintf(s, "first_diff_field\t%s\t%llu\n",
                    vcs_action_field_v2_name(f)
                        ? vcs_action_field_v2_name(f) : "none",
                    (unsigned long long)k->field[f]);
    struct st_rank *rank = NULL;
    size_t n = st_rank_build(k, &rank);
    for (size_t i = 0; i < n && i < 40; i++)
        fprintf(s, "cause\t%zu\t%s\t%llu\t%llu\n", i + 1, rank[i].path,
                (unsigned long long)rank[i].n,
                (unsigned long long)rank[i].pairs);
    free(rank);
}

void st_totals_free(struct st_totals *t)
{
    free(t->us_a.v);
    free(t->us_b.v);
    free(t->us_pp.v);
    memset(t, 0, sizeof(*t));
}

void st_groups_free(struct st_groups *g)
{
    st_list_free(&g->name);
    st_list_free(&g->label);
    st_list_free(&g->harness);
}
