/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Test obligations of the facts consumer: seeds from the functions a changed id reaches, the checks that refuse a seed the name walk cannot bound, and the narrowed or file-seeded closure. */
#include "devloop_facts_consumer.h"

#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FXC_READERS_MAX 4096

void fxc_refuse(struct fxc *c, const char *reason, const char *what,
                const char *path)
{
    if (c->seed_reason != NULL)
        return;
    c->seed_reason = reason;
    (void)snprintf(c->seed_detail, sizeof(c->seed_detail), "%s: %s", what,
                   path);
}

/* The readers of one header that declares an external seed: each must
 * have its manifest here, or its address may be taken where no manifest
 * can say. */
static void fxc_check_header(struct fxc *c, const char *id, const char *header)
{
    char(*readers)[256];
    int n;
    if (fxc_strs_has(&c->checked, header))
        return;
    if (!fxc_strs_add(&c->checked, header)) {
        fxc_refuse(c, "out-of-memory", id, header);
        return;
    }
    readers = zcl_calloc(FXC_READERS_MAX, 256, "facts_obligations.readers");
    n = readers != NULL ? fxc_readers(c, header, readers, FXC_READERS_MAX) : -1;
    if (n < 0) /* no graph: a reader may take its address unseen */
        fxc_refuse(c, "indirect-unknown", id, header);
    for (int k = 0; k < n; k++) {
        size_t len = strlen(readers[k]);
        if (len < 2 || strcmp(readers[k] + len - 2, ".c") != 0 ||
            fxc_strs_has(&c->cand, readers[k]))
            continue;
        fxc_refuse(c, "indirect-unknown", id, readers[k]);
        break;
    }
    free(readers);
}

void fxc_check_decl(struct fxc *c, const struct fxi *x, size_t e)
{
    const char *main = fxi_main(x);
    /* An internal id (a header's static inline) is each reader's own copy:
     * a reader with facts seeds its copy itself, and a reader without a
     * manifest is affected "facts-missing" through the depfile graph, so no
     * reader outside the candidates can reach it unseen. */
    if (!fxi_external(x, e))
        return;
    for (size_t k = 0; c->seed_reason == NULL && k < fxi_nrows(x, e); k++) {
        char header[ZCL_DEVLOOP_PATH_MAX];
        const char *p;
        size_t n;
        if (!fxi_row_path_at(x, e, k, &p, &n) || n >= sizeof(header) ||
            (strlen(main) == n && memcmp(p, main, n) == 0))
            continue;
        memcpy(header, p, n);
        header[n] = '\0';
        fxc_check_header(c, fxi_id(x, e), header);
    }
}

bool fxc_seed_add(struct fxc *c, const struct fxi *x, size_t e)
{
    const char *id = fxi_id(x, e), *name = fxi_bare(x, e);
    struct zcl_devloop_facts_seed *s;
    for (size_t k = 0; k < c->nseeds; k++)
        if (strcmp(c->seeds[k].id, id) == 0)
            return true;
    if (c->nseeds == c->capseeds) {
        size_t next = c->capseeds ? c->capseeds * 2 : 64;
        struct zcl_devloop_facts_seed *g =
            zcl_realloc(c->seeds, next * sizeof(*g), "facts_obligations.seeds");
        if (g == NULL)
            return false;
        c->seeds = g;
        c->capseeds = next;
    }
    s = &c->seeds[c->nseeds++];
    memset(s, 0, sizeof(*s));
    if (strlen(name) >= sizeof(s->name))
        fxc_refuse(c, "seed-unresolved", "a seed name is too long", id);
    (void)snprintf(s->name, sizeof(s->name), "%s", name);
    if (strlen(id) < sizeof(s->id))
        memcpy(s->id, id, strlen(id) + 1);
    fxc_check_decl(c, x, e);
    return true;
}

void fxc_check_addresses(struct fxc *c,
                         const struct zcl_devloop_facts_seed *seeds, size_t n)
{
    for (size_t k = 0; c->seed_reason == NULL && k < n; k++) {
        if (seeds[k].id[0] == '\0')
            fxc_refuse(c, "indirect-unknown", "a seed has no canonical id",
                       seeds[k].name);
        else if (fxc_strs_has(&c->address, seeds[k].id))
            fxc_refuse(c, "address-taken", "a manifest takes the address of",
                       seeds[k].id);
    }
}

/* ---- the plans ------------------------------------------------------------------- */

static bool fxc_plain(struct fxc *c, const struct zcl_devloop_plan *given,
                      struct zcl_devloop_plan *plan,
                      struct zcl_devloop_facts_verdict *v, const char *reason,
                      const char *detail)
{
    memcpy(plan, given, sizeof(*plan));
    v->narrowed = false;
    v->reason = reason;
    (void)snprintf(v->detail, sizeof(v->detail), "%s", detail);
    v->seeds_len = v->seeds_total = 0;
    return zcl_devloop_plan_add_closure(c->root, c->files, c->nfiles, plan);
}

/* A failed narrowed/merge attempt can have hit a bound before the plain
 * replan replaces its output. Retain that first observation across the reset. */
static bool fxc_plain_after_attempt(struct fxc *c,
                                    const struct zcl_devloop_plan *given,
                                    struct zcl_devloop_plan *plan,
                                    struct zcl_devloop_facts_verdict *v,
                                    const char *reason, const char *detail)
{
    const char *origin = plan->capacity_origin;
    const char *cause = plan->capacity_cause;
    char input[sizeof(plan->capacity_input)];
    memcpy(input, plan->capacity_input, sizeof(input));
    bool ok = fxc_plain(c, given, plan, v, reason, detail);
    if (origin) {
        plan->capacity_origin = origin;
        plan->capacity_cause = cause;
        memcpy(plan->capacity_input, input, sizeof(input));
    }
    return ok;
}

static bool fxc_broadened(struct fxc *c, const struct zcl_devloop_plan *given,
                          struct zcl_devloop_plan *plan, bool c_path);

/* After a search-dir change a TU that read no changed file can be affected
 * without making the change universal: its file-seeded closure joins the
 * plan, and when the groups overflow, every group is in scope. */
bool fxc_fallback(struct fxc *c, const struct zcl_devloop_plan *given,
                  struct zcl_devloop_plan *plan,
                  struct zcl_devloop_facts_verdict *v)
{
    const struct zcl_devloop_facts_report *r = c->report;
    if (!fxc_plain(c, given, plan, v, r->reason, r->detail))
        return false;
    plan->closure_universal |= c->universal;
    if (c->sdir && !c->universal && !fxc_broadened(c, given, plan, false))
        plan->closure_universal = true;
    return true;
}

static bool fxc_has_group(const struct zcl_devloop_plan *p, const char *g)
{
    for (size_t k = 0; k < p->path_groups_len; k++)
        if (strcmp(p->path_groups[k], g) == 0)
            return true;
    for (size_t k = 0; k < p->closure_groups_len; k++)
        if (strcmp(p->closure_groups[k], g) == 0)
            return true;
    return false;
}

static bool fxc_merge_group(struct fxc *c, struct zcl_devloop_plan *plan,
                            const char *g)
{
    if (fxc_has_group(plan, g))
        return true;
    if (plan->closure_groups_len >= ZCL_DEVLOOP_MAX_PLAN_GROUPS) {
        zcl_devloop_capacity_note(plan, "facts", "group-cap", "unknown");
        return false;
    }
    (void)snprintf(plan->closure_groups[plan->closure_groups_len],
                   ZCL_DEVLOOP_GROUP_MAX, "%s", g);
    c->report->group_reason[plan->closure_groups_len++] = "tu-broadened";
    return true;
}

static size_t fxc_broadened_paths(const struct fxc *c, const char **paths,
                                  bool c_path)
{
    const struct zcl_devloop_facts_report *r = c->report;
    size_t n = 0;
    for (size_t k = 0; k < r->ntus; k++)
        if (r->tus[k].affected && r->tus[k].broadened &&
            !(c_path && fxc_is_changed(c, r->tus[k].path)))
            paths[n++] = r->tus[k].path;
    return n;
}

/* The file-seeded closure of every broadened TU, added to the plan; on the
 * .c path (c_path), not of a changed file's own TU, which its rule chain
 * decided. */
static bool fxc_broadened(struct fxc *c, const struct zcl_devloop_plan *given,
                          struct zcl_devloop_plan *plan, bool c_path)
{
    const struct zcl_devloop_facts_report *r = c->report;
    const char **paths = zcl_calloc(r->ntus + 1, sizeof(*paths), "facts.bpaths");
    struct zcl_devloop_plan *tmp = zcl_malloc(sizeof(*tmp), "facts.bplan");
    size_t n = 0;
    bool ok = paths != NULL && tmp != NULL;
    if (ok)
        n = fxc_broadened_paths(c, paths, c_path);
    if (ok && n > 0) {
        memcpy(tmp, given, sizeof(*tmp));
        ok = zcl_devloop_plan_files(paths, n, tmp) &&
             zcl_devloop_plan_add_closure(c->root, paths, n, tmp);
        if (ok && tmp->closure_universal && tmp->capacity_origin)
            zcl_devloop_capacity_note(plan, tmp->capacity_origin,
                                      tmp->capacity_cause, tmp->capacity_input);
        for (size_t k = 0; ok && k < tmp->path_groups_len; k++)
            ok = fxc_merge_group(c, plan, tmp->path_groups[k]);
        for (size_t k = 0; ok && k < tmp->closure_groups_len; k++)
            ok = fxc_merge_group(c, plan, tmp->closure_groups[k]);
        plan->closure_universal |= ok && tmp->closure_universal;
    }
    free(paths);
    free(tmp);
    return ok;
}

/* Changed files and every affected TU are reached by construction; a TU
 * in the compile set only (a debug position moved) adds no obligation. */
static const char **fxc_fold_list(const struct fxc *c, size_t *n)
{
    const struct zcl_devloop_facts_report *r = c->report;
    const char **fold = zcl_calloc(c->nfiles + r->ntus + 1, sizeof(*fold),
                                   "facts.fold");
    *n = 0;
    if (fold == NULL)
        return NULL;
    for (size_t k = 0; k < c->nfiles; k++)
        fold[(*n)++] = c->files[k];
    for (size_t k = 0; k < r->ntus; k++)
        if (r->tus[k].affected && !r->tus[k].compile_only)
            fold[(*n)++] = r->tus[k].path;
    return fold;
}

static void fxc_verdict_seeds(const struct fxc *c,
                              struct zcl_devloop_facts_verdict *v)
{
    v->seeds_len = 0;
    for (size_t k = 0; k < c->nseeds && k < ZCL_DEVLOOP_FACTS_MAX_SEEDS; k++) {
        (void)snprintf(v->seeds[k], sizeof(v->seeds[k]), "%s", c->seeds[k].name);
        (void)snprintf(v->seed_ids[k], sizeof(v->seed_ids[k]), "%s",
                       c->seeds[k].id);
        v->seeds_len++;
    }
    v->seeds_total = c->nseeds;
}

bool fxc_obligations(struct fxc *c, const struct zcl_devloop_plan *given,
                     struct zcl_devloop_plan *plan,
                     struct zcl_devloop_facts_verdict *v)
{
    const struct zcl_devloop_facts_report *r = c->report;
    const char **fold;
    size_t nfold;
    bool ok;
    if (!r->complete)
        return fxc_fallback(c, given, plan, v);
    fxc_check_addresses(c, c->seeds, c->nseeds);
    if (c->seed_reason != NULL)
        return fxc_plain(c, given, plan, v, c->seed_reason, c->seed_detail);
    fold = fxc_fold_list(c, &nfold);
    if (fold == NULL)
        return false;
    memcpy(plan, given, sizeof(*plan));
    fxc_verdict_seeds(c, v);
    ok = zcl_devloop_facts_narrow(c->root, c->facts_dir, fold, nfold, c->seeds,
                                  c->nseeds, plan, v);
    free(fold);
    if (!ok) {
        const char *why = v->reason && v->reason[0] ? v->reason : "closure-error";
        memset(c->report->group_reason, 0, sizeof(c->report->group_reason));
        return fxc_plain_after_attempt(c, given, plan, v, why, "the narrowed walk");
    }
    if (!fxc_broadened(c, given, plan, false)) {
        memset(c->report->group_reason, 0, sizeof(c->report->group_reason));
        return fxc_plain_after_attempt(c, given, plan, v, "group-cap", "broadened TUs");
    }
    v->narrowed = true;
    v->reason = "";
    return true;
}

bool fxc_plain_count(struct fxc *c, const struct zcl_devloop_plan *given)
{
    struct zcl_devloop_plan *tmp = zcl_malloc(sizeof(*tmp), "facts.plain");
    bool ok = tmp != NULL;
    if (ok) {
        memcpy(tmp, given, sizeof(*tmp));
        ok = zcl_devloop_plan_add_closure(c->root, c->files, c->nfiles, tmp);
        c->report->plain_groups = tmp->path_groups_len + tmp->closure_groups_len;
        c->report->plain_universal = tmp->closure_universal;
    }
    free(tmp);
    return ok;
}

/* ---- the .c path's members ------------------------------------------------------ */

static bool fxc_seed_in(const struct zcl_devloop_facts_seed *s, size_t n,
                        const char *id)
{
    for (size_t k = 0; k < n; k++)
        if (strcmp(s[k].id, id) == 0)
            return true;
    return false;
}

/* An affected TU that is not a changed file: the rule chain's walk, which
 * started from the changed files, never reached it. */
static bool fxc_foreign_affected(const struct fxc *c)
{
    const struct zcl_devloop_facts_report *r = c->report;
    for (size_t k = 0; k < r->ntus; k++)
        if (r->tus[k].affected && !r->tus[k].compile_only &&
            !fxc_is_changed(c, r->tus[k].path))
            return true;
    return false;
}

/* The walk again, from the rule chain's seeds and the members' together,
 * folding every changed file and affected TU. */
static bool fxc_c_rewalk(struct fxc *c, const struct zcl_devloop_plan *given,
                         struct zcl_devloop_plan *plan,
                         struct zcl_devloop_facts_verdict *v,
                         const struct zcl_devloop_facts_seed *all, size_t n)
{
    size_t nfold;
    const char **fold = fxc_fold_list(c, &nfold);
    bool ok;
    if (fold == NULL)
        return false;
    memcpy(plan, given, sizeof(*plan));
    ok = zcl_devloop_facts_narrow(c->root, c->facts_dir, fold, nfold, all, n,
                                  plan, v);
    free(fold);
    if (!ok) {
        const char *why = v->reason && v->reason[0] ? v->reason : "closure-error";
        return fxc_plain_after_attempt(c, given, plan, v, why, "the narrowed walk");
    }
    v->seeds_len = 0;
    for (size_t k = 0; k < n && k < ZCL_DEVLOOP_FACTS_MAX_SEEDS; k++) {
        (void)snprintf(v->seeds[k], sizeof(v->seeds[k]), "%s", all[k].name);
        (void)snprintf(v->seed_ids[k], sizeof(v->seed_ids[k]), "%s", all[k].id);
        v->seeds_len++;
    }
    v->seeds_total = n;
    return true;
}

bool fxc_c_members(struct fxc *c, const struct zcl_devloop_plan *given,
                   struct zcl_devloop_plan *plan,
                   struct zcl_devloop_facts_verdict *v)
{
    struct zcl_devloop_facts_seed *all =
        zcl_calloc(v->seeds_len + c->nseeds + 1, sizeof(*all), "facts.cseeds");
    size_t n = 0;
    bool ok = all != NULL;
    for (size_t k = 0; ok && k < v->seeds_len; k++) {
        (void)snprintf(all[n].name, sizeof(all[n].name), "%s", v->seeds[k]);
        (void)snprintf(all[n].id, sizeof(all[n].id), "%s", v->seed_ids[k]);
        n++;
    }
    for (size_t k = 0; ok && k < c->nseeds; k++)
        if (!fxc_seed_in(all, n, c->seeds[k].id))
            all[n++] = c->seeds[k];
    if (ok)
        fxc_check_addresses(c, all, n);
    if (ok && c->seed_reason != NULL)
        ok = fxc_plain(c, given, plan, v, c->seed_reason, c->seed_detail);
    else if (ok && (n > v->seeds_len || fxc_foreign_affected(c)))
        ok = fxc_c_rewalk(c, given, plan, v, all, n);
    if (ok && v->narrowed && !fxc_broadened(c, given, plan, true))
        ok = fxc_plain_after_attempt(c, given, plan, v, "group-cap", "broadened TUs");
    free(all);
    return ok;
}
