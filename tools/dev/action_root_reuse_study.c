/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Offline study of how many compile actions keep an exact v2 action
 * root across real first-parent commits, measured from immutable snapshots.
 * `make action-root-reuse-study` drives it; see
 * docs/experiments/2026-09-25-action-root-reuse.md for a recorded run.
 *
 * Every snapshot is `git archive` bytes extracted into scratch. Its own
 * Makefile names the exact compile argv of every dev-profile translation
 * unit (a dry-run parse; nothing is compiled). Each action gets a v2 root,
 * or an explicit MISS with its reason, under two closures (see
 * action_root_reuse_study_snap.c). Consecutive snapshots are compared
 * action by action: equal roots are reusable evidence, different roots and
 * MISS are not.
 *
 * The study also asks the existing content-keyed test cache which groups it
 * would still reuse for each commit, checks commit invariance by applying a
 * commit's diff to its parent uncommitted, and seeds adversarial edits that
 * must never be counted as reuse.
 */

#include "action_root_reuse_study.h"

#include "base/safe_alloc.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the study run ----------------------------------------------------- */

static void st_run_pair(struct st_run *r, const char *set,
                        const struct st_pair *p, const struct st_snap *ps,
                        const struct st_snap *cs, struct st_totals *t)
{
    struct st_pair_result pr;
    struct st_group_result g;
    r->pair_seq++;
    st_pair_compare(ps, cs, &pr, strcmp(set, "corpus") == 0 ? r->causes
                                                            : NULL,
                    r->pair_seq);
    st_groups_pair(r->c, &r->groups, ps, cs, &g);
    st_pair_row(r->pairs, set, p, &pr, &g);
    st_tally_merge(&t->a, &pr.a);
    st_tally_merge(&t->b, &pr.b);
    t->ab_violations += pr.ab_violations;
    st_group_merge(&t->g, &g);
}

/* ---- commit invariance ------------------------------------------------- */

struct st_patch_arg {
    const char *patch;
};

static bool st_apply_patch(const struct st_ctx *c, struct st_snap *s,
                           void *arg)
{
    (void)c;
    const struct st_patch_arg *a = arg;
    const char *argv[] = { "env", "-C", s->dir, "git", "apply", "--binary",
                           "--whitespace=nowarn", a->patch, NULL };
    return st_run_quiet(argv);
}

static bool st_write_diff(const struct st_ctx *c, const char *parent,
                          const char *child, const char *path)
{
    const char *argv[] = { "git", "-C", c->repo, "diff", "--binary",
                           "--no-renames", parent, child, NULL };
    struct st_proc p;
    bool ok = st_run(argv, ST_MAKE_CAP, &p);
    FILE *f = ok ? fopen(path, "wb") : NULL;
    ok = f && fwrite(p.out, 1, p.len, f) == p.len;
    if (f)
        ok = fclose(f) == 0 && ok;
    st_proc_free(&p);
    return ok;
}

static void st_invariance(struct st_run *r, const struct st_pair *p,
                          const struct st_snap *child, FILE *out)
{
    char patch[PATH_MAX];
    (void)snprintf(patch, sizeof(patch), "%s/inv-%.12s.patch", r->c->scratch,
                   p->child);
    struct st_snap v;
    char label[96];
    (void)snprintf(label, sizeof(label), "inv-%.12s", p->child);
    st_snap_init(&v, label, p->parent);
    struct st_patch_arg arg = { patch };
    bool ok = st_write_diff(r->c, p->parent, p->child, patch) &&
              st_snap_load(r->c, &v, st_apply_patch, &arg, false, false);
    uint64_t rooted = 0, equal = 0, differ = 0, missing = 0;
    for (size_t i = 0; ok && i < child->n; i++) {
        const struct st_tu *q = &child->tu[i];
        const struct st_tu *u = st_find_tu(&v, q->src, i);
        if (q->b.state != ST_ROOT)
            continue;
        rooted++;
        if (!u || u->b.state != ST_ROOT)
            missing++;
        else if (memcmp(u->b.root, q->b.root, 32) == 0)
            equal++;
        else
            differ++;
    }
    fprintf(out, "%.12s\t%d\t%zu\t%zu\t%llu\t%llu\t%llu\t%llu\n", p->child,
            ok, child->n, v.n, (unsigned long long)rooted,
            (unsigned long long)equal, (unsigned long long)differ,
            (unsigned long long)missing);
    fflush(out);
    st_snap_drop(&v);
    st_snap_free(&v);
    (void)st_rm_rf(patch);
}

/* ---- seeded adversarial edits ------------------------------------------ */

enum st_seed { ST_SEED_FLAG, ST_SEED_HEADER, ST_SEED_GENERATED,
               ST_SEED_DELETE, ST_SEED_SHADOW, ST_SEED_COUNT };

struct st_seed_arg {
    enum st_seed kind;
    char target[PATH_MAX];   /* repo-relative file the seed touches */
    char shadow[PATH_MAX];   /* repo-relative shadow location */
    char affected[PATH_MAX]; /* dependency that marks an affected action */
};

static bool st_append(const char *path, const char *text)
{
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool st_copy_with(const char *from, const char *to, const char *head)
{
    size_t len = 0;
    char *body = st_read_file(from, 64u * 1024u * 1024u, &len);
    FILE *f = body ? fopen(to, "wb") : NULL;
    bool ok = f && fputs(head, f) >= 0 && fwrite(body, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    free(body);
    return ok;
}

static bool st_seed_flag(struct st_snap *s)
{
    const char *argv[] = {
        "env", "-C", s->dir, "sed", "-i",
        "/^DEV_HOT_CFLAGS = /i DEV_CFLAGS += -DZCL_ACTION_ROOT_STUDY_SEED=1",
        "Makefile", NULL,
    };
    const char *check[] = { "grep", "-c", "ZCL_ACTION_ROOT_STUDY_SEED",
                            NULL, NULL };
    char makefile[PATH_MAX + 16];
    (void)snprintf(makefile, sizeof(makefile), "%s/Makefile", s->dir);
    check[3] = makefile;
    char line[64] = {0};
    return st_run_quiet(argv) && st_run_line(check, line, sizeof(line)) &&
           strcmp(line, "1") == 0;
}

static bool st_seed_mutate(const struct st_ctx *c, struct st_snap *s,
                           void *arg)
{
    (void)c;
    const struct st_seed_arg *a = arg;
    char path[PATH_MAX * 2], shadow[PATH_MAX * 2];
    (void)snprintf(path, sizeof(path), "%s/%s", s->dir, a->target);
    (void)snprintf(shadow, sizeof(shadow), "%s/%s", s->dir, a->shadow);
    switch (a->kind) {
    case ST_SEED_FLAG:
        return st_seed_flag(s);
    case ST_SEED_HEADER:
        return st_append(path, "/* action-root study: seeded edit */\n");
    case ST_SEED_GENERATED:
        /* A rule, not a comment: the generator minifies comments away,
         * and an edit that leaves the header byte-identical may reuse. */
        return st_append(path, "\n.zcl-action-root-study-seed{color:red}\n");
    case ST_SEED_DELETE: {
        const char *argv[] = { "rm", "--", path, NULL };
        return st_run_quiet(argv);
    }
    case ST_SEED_SHADOW: {
        char dir[PATH_MAX * 2];
        (void)snprintf(dir, sizeof(dir), "%s", shadow);
        char *slash = strrchr(dir, '/');
        if (slash)
            *slash = '\0';
        return st_mkdir_p(dir) &&
               st_copy_with(path, shadow,
                            "/* action-root study: shadowing header */\n");
    }
    default:
        return false;
    }
}

static const char *st_seed_name(enum st_seed k)
{
    static const char *const names[] = {
        "flag: -D added to DEV_CFLAGS in the Makefile",
        "header: widely included header edited",
        "generated: view source edited, header regenerated",
        "incomplete closure: included header deleted",
        "shadow: same-named header in an earlier -I dir",
    };
    return k < ST_SEED_COUNT ? names[k] : "?";
}

static bool st_tu_affected(const struct st_seed_arg *a, const struct st_tu *t)
{
    if (a->kind == ST_SEED_FLAG)
        return true;
    return st_list_has(&t->deps, a->affected);
}

struct st_seed_tally {
    uint64_t affected, changed, miss, reuse;       /* protocol B */
    uint64_t f_changed, f_miss, f_reuse;           /* build depfile, forced */
    uint64_t unaffected, unaffected_reuse;
    uint64_t field[VCS_ACTION_FIELD_V2_COUNT];
};

static void st_seed_one(const struct st_tu *base, const struct st_tu *v,
                        bool affected, struct st_seed_tally *t)
{
    const char *why = NULL;
    enum st_verdict vb = st_compare(&base->b, &v->b, true, &why);
    if (!affected) {
        t->unaffected++;
        t->unaffected_reuse += vb == ST_V_REUSE;
        return;
    }
    t->affected++;
    t->reuse += vb == ST_V_REUSE;
    t->changed += vb == ST_V_CHANGED;
    t->miss += vb == ST_V_MISS;
    enum st_verdict vf = st_compare(&base->b, &v->forced, true, &why);
    t->f_reuse += vf == ST_V_REUSE;
    t->f_changed += vf == ST_V_CHANGED;
    t->f_miss += vf == ST_V_MISS;
    enum vcs_action_field_v2 f = VCS_ACTION_FIELD_V2_NONE;
    if (vb == ST_V_CHANGED && base->pre && v->pre &&
        vcs_action_preimage_v2_first_diff(base->pre, base->pre_len, v->pre,
                                          v->pre_len, &f) &&
        f < VCS_ACTION_FIELD_V2_COUNT)
        t->field[f]++;
}

static void st_seed_report(FILE *out, const struct st_seed_arg *a,
                           const struct st_seed_tally *t, bool ok)
{
    char fields[256] = {0};
    size_t o = 0;
    for (size_t f = 0; f < VCS_ACTION_FIELD_V2_COUNT; f++)
        if (t->field[f] && o < sizeof(fields))
            o += (size_t)snprintf(fields + o, sizeof(fields) - o, "%s=%llu ",
                                  vcs_action_field_v2_name(f)
                                      ? vcs_action_field_v2_name(f) : "none",
                                  (unsigned long long)t->field[f]);
    fprintf(out, "%s\t%s\t%d\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t"
            "%llu\t%llu\t%s\t%s\n", st_seed_name(a->kind), a->target, ok,
            (unsigned long long)t->affected,
            (unsigned long long)t->changed, (unsigned long long)t->miss,
            (unsigned long long)t->reuse, (unsigned long long)t->f_changed,
            (unsigned long long)t->f_miss, (unsigned long long)t->f_reuse,
            (unsigned long long)t->unaffected,
            (unsigned long long)t->unaffected_reuse,
            t->affected && !t->reuse && !t->f_reuse ? "PASS" : "FAIL",
            fields);
    fflush(out);
}

static void st_seed_run(struct st_run *r, const struct st_snap *base,
                        const struct st_seed_arg *a, FILE *out)
{
    struct st_snap v;
    char label[96];
    (void)snprintf(label, sizeof(label), "seed-%d", (int)a->kind);
    st_snap_init(&v, label, base->sha);
    (void)snprintf(v.tar, sizeof(v.tar), "%s", base->tar);
    bool ok = st_snap_load(r->c, &v, st_seed_mutate, (void *)a, true, false);
    struct st_seed_tally t = {0};
    for (size_t i = 0; ok && i < base->n; i++) {
        const struct st_tu *b = &base->tu[i];
        const struct st_tu *u = st_find_tu(&v, b->src, i);
        if (u)
            st_seed_one(b, u, st_tu_affected(a, b), &t);
    }
    st_seed_report(out, a, &t, ok);
    st_snap_drop(&v);
    st_snap_free(&v);
}


static bool st_is_header(const char *p)
{
    size_t n = strlen(p);
    return n > 2 && strcmp(p + n - 2, ".h") == 0;
}

/* The -I dir a header is reached through, by the first action including
 * it; the shadow goes into search dir 0 when that dir comes later. */
static bool st_shadow_target(const struct st_snap *s, const char *header,
                             char shadow[PATH_MAX])
{
    const struct st_tu *t = NULL;
    for (size_t i = 0; i < s->n && !t; i++)
        if (st_list_has(&s->tu[i].deps, header))
            t = &s->tu[i];
    const char *first = NULL;
    for (size_t i = t ? t->flag_lo : 0; t && i < t->flag_hi; i++) {
        const char *a = t->argv.v[i];
        if (strncmp(a, "-I", 2) != 0 || !a[2])
            continue;
        size_t n = strlen(a + 2);
        if (!first) {
            first = a + 2;
            continue;
        }
        if (strncmp(header, a + 2, n) == 0 && header[n] == '/') {
            (void)snprintf(shadow, PATH_MAX, "%s/%s", first, header + n + 1);
            return true;
        }
    }
    return false;
}

/* Headers of the base snapshot ranked by how many actions include them. */
struct st_headers {
    struct st_rank *rank;
    size_t n;
    struct st_causes *count;
};

static bool st_headers_build(const struct st_snap *s, struct st_headers *h)
{
    memset(h, 0, sizeof(*h));
    h->count = zcl_calloc(1, sizeof(*h->count), "study fan-in");
    for (size_t i = 0; h->count && i < s->n; i++)
        for (size_t d = 0; d < s->tu[i].deps.n; d++)
            if (st_is_header(s->tu[i].deps.v[d]))
                st_cause_add(h->count, s->tu[i].deps.v[d], (uint32_t)i + 1);
    h->n = h->count ? st_rank_build(h->count, &h->rank) : 0;
    return h->n > 0;
}

static void st_headers_free(struct st_headers *h)
{
    st_causes_free(h->count);
    free(h->count);
    free(h->rank);
}

static void st_seed_targets(const struct st_snap *base,
                            const struct st_headers *h,
                            struct st_seed_arg seeds[ST_SEED_COUNT])
{
    const char *site = "contexts/explorer/views/include/views/site_css.h";
    for (size_t k = 0; k < ST_SEED_COUNT; k++)
        seeds[k] = (struct st_seed_arg){ .kind = (enum st_seed)k };
    (void)snprintf(seeds[ST_SEED_FLAG].target, PATH_MAX, "Makefile");
    (void)snprintf(seeds[ST_SEED_HEADER].target, PATH_MAX, "%s",
                   h->rank[0].path);
    (void)snprintf(seeds[ST_SEED_GENERATED].target, PATH_MAX,
                   "contexts/explorer/views/src/site.css");
    (void)snprintf(seeds[ST_SEED_GENERATED].affected, PATH_MAX, "%s", site);
    (void)snprintf(seeds[ST_SEED_DELETE].target, PATH_MAX, "%s",
                   h->n > 1 ? h->rank[1].path : "");
    for (size_t i = 0; i < h->n; i++)
        if (st_shadow_target(base, h->rank[i].path,
                             seeds[ST_SEED_SHADOW].shadow)) {
            (void)snprintf(seeds[ST_SEED_SHADOW].target, PATH_MAX, "%s",
                           h->rank[i].path);
            break;
        }
    for (size_t k = ST_SEED_HEADER; k < ST_SEED_COUNT; k++)
        if (!seeds[k].affected[0])
            (void)snprintf(seeds[k].affected, PATH_MAX, "%s",
                           seeds[k].target);
}

void st_adversarial(struct st_run *r, const struct st_snap *base, FILE *out,
                    FILE *summary)
{
    struct st_headers h;
    if (!st_headers_build(base, &h)) {
        fprintf(summary, "adversarial: base snapshot has no header fan-in\n");
        st_headers_free(&h);
        return;
    }
    for (size_t k = 0; k < 10 && k < h.n; k++)
        fprintf(summary, "fanin\t%zu\t%s\t%llu\t%.2f%%\n", k + 1,
                h.rank[k].path, (unsigned long long)h.rank[k].n,
                st_share(h.rank[k].n, base->n));
    struct st_seed_arg seeds[ST_SEED_COUNT];
    st_seed_targets(base, &h, seeds);
    for (size_t k = 0; k < ST_SEED_COUNT; k++) {
        fprintf(summary, "seed\t%s\ttarget=%s\tshadow=%s\n",
                st_seed_name((enum st_seed)k), seeds[k].target,
                seeds[k].shadow);
        if (seeds[k].target[0])
            st_seed_run(r, base, &seeds[k], out);
    }
    st_headers_free(&h);
}

/* ---- orchestration ----------------------------------------------------- */

static FILE *st_open_out(const struct st_ctx *c, const char *name,
                         const char *header)
{
    char path[PATH_MAX * 2];
    (void)snprintf(path, sizeof(path), "%s/%s", c->out, name);
    FILE *f = fopen(path, "w");
    if (f && header)
        fputs(header, f);
    return f;
}

static void st_run_corpus(struct st_run *r, const struct st_list *chain,
                          FILE *inv, struct st_snap *tip)
{
    struct st_snap prev, cur;
    char label[96];
    (void)snprintf(label, sizeof(label), "c%02u", 0u);
    st_snap_init(&prev, label, chain->v[0]);
    if (st_snap_load(r->c, &prev, NULL, NULL, false, false))
        st_snap_account(&r->corpus, &prev, r->snaps);
    unsigned inv_left = r->c->invariance;
    for (size_t i = 1; i < chain->n; i++) {
        (void)snprintf(label, sizeof(label), "c%02zu", i);
        st_snap_init(&cur, label, chain->v[i]);
        bool last = i + 1 == chain->n;
        if (st_snap_load(r->c, &cur, NULL, NULL, last, last))
            st_snap_account(&r->corpus, &cur, r->snaps);
        struct st_pair p;
        (void)snprintf(p.label, sizeof(p.label), "%s", label);
        (void)snprintf(p.parent, sizeof(p.parent), "%s", prev.sha);
        (void)snprintf(p.child, sizeof(p.child), "%s", cur.sha);
        st_run_pair(r, "corpus", &p, &prev, &cur, &r->corpus);
        if (inv_left && prev.ok && cur.ok) {
            st_invariance(r, &p, &cur, inv);
            inv_left--;
        }
        st_snap_drop(&prev);
        (void)st_rm_rf(prev.tar);
        st_snap_free(&prev);
        prev = cur;
    }
    st_snap_drop(&prev);
    *tip = prev; /* keeps its actions, deps and tar for the seeded edits */
}

static void st_run_picked(struct st_run *r)
{
    struct st_pair *picked = zcl_calloc(ST_MAX_PICKED, sizeof(*picked),
                                        "study picked");
    size_t n = picked && r->c->picks.n
        ? st_picked_load(r->c, picked, ST_MAX_PICKED) : 0;
    for (size_t i = 0; i < n; i++) {
        struct st_snap ps, cs;
        char label[128];
        (void)snprintf(label, sizeof(label), "%s-parent", picked[i].label);
        st_snap_init(&ps, label, picked[i].parent);
        (void)snprintf(label, sizeof(label), "%s-child", picked[i].label);
        st_snap_init(&cs, label, picked[i].child);
        if (st_snap_load(r->c, &ps, NULL, NULL, false, false))
            st_snap_account(&r->picked, &ps, r->snaps);
        if (st_snap_load(r->c, &cs, NULL, NULL, false, false))
            st_snap_account(&r->picked, &cs, r->snaps);
        st_run_pair(r, "picked", &picked[i], &ps, &cs, &r->picked);
        st_snap_drop(&ps);
        st_snap_drop(&cs);
        (void)st_rm_rf(ps.tar);
        (void)st_rm_rf(cs.tar);
        st_snap_free(&ps);
        st_snap_free(&cs);
    }
    free(picked);
}

static bool st_study(struct st_ctx *c)
{
    struct st_run r = { .c = c };
    r.causes = zcl_calloc(1, sizeof(*r.causes), "study causes");
    struct st_list chain = {0};
    if (!r.causes || !st_rev_parse(c, c->main_ref, c->main_sha) ||
        !st_corpus_chain(c, &chain)) {
        fprintf(stderr, "study: corpus unavailable for %s\n", c->main_ref);
        free(r.causes);
        return false;
    }
    r.pairs = st_open_out(c, "pairs.tsv",
        "set\tlabel\tparent\tchild\tactions\tA_reuse\tA_changed\tA_miss\t"
        "A_added\tB_reuse\tB_changed\tB_miss\tB_added\ttests_ok\t"
        "changed_paths\ttoolkey_changed\tharness_changed\tcacheable\t"
        "unchanged\tinvalidated\tuncacheable\n");
    r.snaps = st_open_out(c, "snapshots.tsv",
        "label\tsha\timmutable\tactions\tA_rooted\tA_miss\tB_rooted\t"
        "B_miss\tarchive_us\tparse_us\n");
    FILE *inv = st_open_out(c, "invariance.tsv",
        "child\tok\tcommitted_actions\tapplied_actions\trooted\tequal\t"
        "differ\tmissing\n");
    FILE *adv = st_open_out(c, "adversarial.tsv",
        "seed\ttarget\tok\taffected\tB_changed\tB_miss\tB_reuse\t"
        "forced_changed\tforced_miss\tforced_reuse\tunaffected\t"
        "unaffected_reuse\tverdict\tfirst_diff_fields\n");
    FILE *sum = st_open_out(c, "summary.txt", NULL);
    bool ok = r.pairs && r.snaps && inv && adv && sum;
    if (ok) {
        fprintf(sum, "main_ref=%s main_sha=%s corpus_pairs=%u jobs=%u\n",
                c->main_ref, c->main_sha, c->corpus, c->jobs);
        st_groups_baseline(c, &r.groups);
        struct st_snap tip;
        st_run_corpus(&r, &chain, inv, &tip);
        st_run_picked(&r);
        st_summary_totals(sum, "corpus", &r.corpus);
        st_summary_totals(sum, "picked", &r.picked);
        st_summary_causes(sum, r.causes);
        if (tip.ok)
            st_adversarial(&r, &tip, adv, sum);
        (void)st_rm_rf(tip.tar);
        st_snap_free(&tip);
    }
    FILE *files[] = { r.pairs, r.snaps, inv, adv, sum };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        if (files[i])
            ok = fclose(files[i]) == 0 && ok;
    st_list_free(&chain);
    st_groups_free(&r.groups);
    st_totals_free(&r.corpus);
    st_totals_free(&r.picked);
    st_causes_free(r.causes);
    free(r.causes);
    return ok;
}

/* ---- command line ------------------------------------------------------ */

static bool st_opt(const char *arg, const char *name, char *out, size_t cap)
{
    size_t n = strlen(name);
    if (strncmp(arg, name, n) != 0 || arg[n] != '=')
        return false;
    (void)snprintf(out, cap, "%s", arg + n + 1);
    return true;
}

static bool st_opt_num(const char *arg, const char *name, unsigned *out)
{
    char num[32];
    if (!st_opt(arg, name, num, sizeof(num)))
        return false;
    *out = (unsigned)strtoul(num, NULL, 10);
    return true;
}

static bool st_opt_path(const char *a, struct st_ctx *c)
{
    return st_opt(a, "--repo", c->repo, sizeof(c->repo)) ||
           st_opt(a, "--scratch", c->scratch, sizeof(c->scratch)) ||
           st_opt(a, "--out", c->out, sizeof(c->out)) ||
           st_opt(a, "--build-obj", c->build_obj, sizeof(c->build_obj)) ||
           st_opt(a, "--test-obj", c->test_obj, sizeof(c->test_obj)) ||
           st_opt(a, "--test-bin", c->test_bin, sizeof(c->test_bin)) ||
           st_opt(a, "--main-ref", c->main_ref, sizeof(c->main_ref));
}

static bool st_parse_args(int argc, char **argv, struct st_ctx *c)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        bool hit = st_opt_path(a, c) ||
                   st_opt_num(a, "--corpus", &c->corpus) ||
                   st_opt_num(a, "--jobs", &c->jobs) ||
                   st_opt_num(a, "--invariance", &c->invariance) ||
                   st_opt_num(a, "--max-actions", &c->max_actions);
        if (!hit && strncmp(a, "--pick=", 7) == 0)
            hit = st_list_push(&c->picks, a + 7);
        if (!hit) {
            fprintf(stderr, "study: unknown argument %s\n", a);
            return false;
        }
    }
    return c->repo[0] == '/' && c->scratch[0] == '/' && c->out[0] &&
           c->build_obj[0] && c->test_obj[0] && c->test_bin[0] &&
           c->main_ref[0] && c->corpus > 0 && c->jobs > 0;
}

int main(int argc, char **argv)
{
    static struct st_ctx c;
    c.jobs = 8;
    c.invariance = 5;
    if (!st_parse_args(argc, argv, &c)) {
        fprintf(stderr,
                "usage: %s --repo=ABS --scratch=ABS --out=DIR "
                "--build-obj=DIR --test-obj=DIR --test-bin=PATH "
                "--main-ref=REV --corpus=N [--pick=LABEL=REV]... [--jobs=N] "
                "[--invariance=N]\n", argv[0]);
        return 2;
    }
    char log[PATH_MAX * 2];
    (void)snprintf(log, sizeof(log), "%s/study.log", c.out);
    if (!st_mkdir_p(c.out) || !st_mkdir_p(c.scratch) ||
        !(c.log = fopen(log, "w")) || !st_toolchain_capture(&c.tc))
        return 1;
    int64_t t0 = platform_time_monotonic_us();
    bool ok = st_study(&c);
    fprintf(c.log, "study wall_us=%lld ok=%d\n",
            (long long)(platform_time_monotonic_us() - t0), ok);
    fclose(c.log);
    printf("action-root-reuse-study: %s (results in %s)\n",
           ok ? "done" : "FAILED", c.out);
    return ok ? 0 : 1;
}
