/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The semantic-facts fuzz oracle: plan one change set in process from its facts directory, then hold the plan to the objects (an unaffected TU's object is byte-identical; a function or data object with new bytes or new addressed content is a seed or covered). */
#include "semantic_fuzz_case_priv.h"

#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "vcs/semantic_manifest.h"

#include "devloop_facts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The dev.change.plan document reads each changed .c's pair and its two
 * source texts itself; so does this. */
#define SFZ_SOURCE_MAX (16u * 1024u * 1024u)

struct sfz_plan {
    struct zcl_devloop_plan plan;
    struct zcl_devloop_facts_verdict v;
    struct zcl_devloop_facts_report report;
    struct zcl_devloop_facts_tu tus[64];
};

static bool load_pair(const char *root, const char *file,
                      struct zcl_devloop_facts_tu *tu)
{
    uint8_t *b = NULL, *a = NULL, *bs = NULL, *as = NULL;
    bool ok = zcl_devloop_facts_read(root, "facts", file, ".before.zsm",
                                     VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &b,
                                     &tu->before_len) &&
              zcl_devloop_facts_read(root, "facts", file, ".after.zsm",
                                     VCS_SEMANTIC_MANIFEST_V1_MAX_BYTES, &a,
                                     &tu->after_len) &&
              zcl_devloop_facts_read(root, "facts", file, ".before",
                                     SFZ_SOURCE_MAX, &bs, &tu->before_src_len) &&
              zcl_devloop_facts_read(root, NULL, file, "", SFZ_SOURCE_MAX, &as,
                                     &tu->after_src_len);
    if (!ok) {
        /* a partial pair is dropped whole: the caller passes the file
         * without its evidence */
        free(b);
        free(a);
        free(bs);
        free(as);
        memset(tu, 0, sizeof(*tu));
        return false;
    }
    tu->source = file;
    tu->before = b;
    tu->after = a;
    tu->before_src = bs;
    tu->after_src = as;
    return true;
}

static void unload_pairs(struct sfz_plan *p, size_t n)
{
    for (size_t k = 0; k < n; k++) {
        free((void *)p->tus[k].before);
        free((void *)p->tus[k].after);
        free((void *)p->tus[k].before_src);
        free((void *)p->tus[k].after_src);
    }
}

/* Plan r->changed as dev.change.plan with {"facts":"facts"} does: a change
 * set of .c files passes their pairs (a file without its full evidence is
 * passed without it and falls back as "no-manifest"), any other goes to the
 * declaration-identity consumer. */
static bool plan(struct sfz_run *r, struct sfz_plan *p)
{
    const char *const *files = (const char *const *)r->changed.v;
    size_t n = r->changed.n;
    bool all_c = !r->header_changed && n <= sizeof(p->tus) / sizeof(p->tus[0]);
    bool ok;
    int64_t t0 = clock_now_monotonic_ns();
    if (!zcl_devloop_plan_files(files, n, &p->plan))
        return false;
    for (size_t k = 0; all_c && k < n; k++)
        (void)load_pair(r->tree, files[k], &p->tus[k]);
    ok = zcl_devloop_facts_consume(r->tree, files, n, "facts",
                                   all_c ? p->tus : NULL, &p->plan, &p->v,
                                   &p->report);
    if (all_c)
        unload_pairs(p, n);
    r->out->plan_s = (double)(clock_now_monotonic_ns() - t0) / 1e9;
    return ok;
}

static const struct zcl_devloop_facts_tu_verdict *
tu_of(const struct sfz_plan *p, const char *path)
{
    for (size_t k = 0; k < p->report.ntus; k++)
        if (strcmp(p->report.tus[k].path, path) == 0)
            return &p->report.tus[k];
    return NULL;
}

static bool is_c_path(const char *path, size_t len)
{
    return len > 2 && path[len - 2] == '.' && path[len - 1] == 'c';
}

/* True when canonical id `id` names the first `len` bytes of `name` in TU
 * `tu` as kind `kind` ('f' a function, 'v' a variable): "<kind>:<name>" an
 * external symbol, "<kind>:<path>:<name>" a local one that tu itself
 * defines (path is tu) or that a header defines static (path is no .c
 * file). `any` accepts either binding: a local clone
 * ("t0_e1.constprop.0") runs its external function's code, and a
 * function's static ("t0_kk.a") belongs to that function. A seed without a
 * canonical id names nothing. */
static bool id_names(const char *id, char kind, const char *name, size_t len,
                     bool local, bool any, const char *tu)
{
    const char *colon, *bare;
    size_t plen;
    if (id[0] != kind || id[1] != ':')
        return false;
    id += 2;
    colon = strrchr(id, ':');
    bare = colon != NULL ? colon + 1 : id;
    if (strlen(bare) != len || strncmp(bare, name, len) != 0)
        return false;
    if (colon == NULL)
        return !local || any;
    if (!local && !any)
        return false;
    plen = (size_t)(colon - id);
    return (strlen(tu) == plen && strncmp(id, tu, plen) == 0) ||
           !is_c_path(id, plen);
}

/* A seed of TU tu's symbol s by canonical id, so a same-name static of
 * another file is no seed. A data object needs a variable seed (v:...).
 * With `bare` a suffix after the first '.' is set aside:
 * "t0_s1.constprop.0" is t0_s1's code, and the object "t0_kk.a" (the
 * static `a` inside t0_kk) is covered by t0_kk's seed. */
static bool is_seed(const struct sfz_plan *p, const char *tu,
                    const struct sfz_sym *s, bool bare)
{
    size_t len = bare ? strcspn(s->name, ".") : strlen(s->name);
    bool dotted = s->name[len] != '\0';
    char kind = s->object && !dotted ? 'v' : 'f';
    for (size_t k = 0; k < p->v.seeds_len; k++)
        if (id_names(p->v.seed_ids[k], kind, s->name, len, s->local, dotted, tu))
            return true;
    return false;
}

/* One TU with a changed object: how its plan covers it. */
struct tu_judge {
    const char *tu;
    bool predicted, broadened;
    struct sfz_syms before, after;
};

/* New bytes or new addressed content: a symbol on one side only, or one
 * whose raw or resolved digest differs. */
static bool sym_changed(const struct tu_judge *j, const char *name, size_t k)
{
    const struct sfz_sym *a = sfz_sym_find(&j->before, name, k);
    const struct sfz_sym *b = sfz_sym_find(&j->after, name, k);
    return a == NULL || b == NULL || memcmp(a->raw, b->raw, 32) != 0 ||
           memcmp(a->resolved, b->resolved, 32) != 0;
}

/* Only a relocation's target symbol or addend changed, and every changed
 * relocation still resolves to the same content. */
static bool reloc_only(const struct tu_judge *j, const char *name, size_t k)
{
    const struct sfz_sym *a = sfz_sym_find(&j->before, name, k);
    const struct sfz_sym *b = sfz_sym_find(&j->after, name, k);
    return a != NULL && b != NULL && memcmp(a->resolved, b->resolved, 32) == 0;
}

/* Every other symbol at f's address in the after object is f's new
 * bytes: each must be a seed too. */
static void judge_aliases(struct sfz_run *r, const struct sfz_plan *p,
                          const struct tu_judge *j, const struct sfz_sym *f)
{
    for (size_t q = 0; f != NULL && q < j->after.n; q++) {
        const struct sfz_sym *o = &j->after.v[q];
        if (o == f || o->shndx != f->shndx || o->value != f->value ||
            strcmp(o->name, f->name) == 0 || is_seed(p, j->tu, o, false))
            continue;
        r->out->notcov++;
        sfz_why(r->out, "  %s %s alias-of-%s ALIAS-NOT-COVERED\n", j->tu,
                o->name, f->name);
    }
}

static void judge_sym(struct sfz_run *r, const struct sfz_plan *p,
                      const struct tu_judge *j, const struct sfz_sym *s,
                      size_t k)
{
    struct sfz_outcome *o = r->out;
    const char *name = s->name, *what = s->object ? " (object)" : "";
    if (s->object)
        o->cobj++;
    else
        o->cfun++;
    if (!p->v.narrowed) {
        o->covered_other++; /* covered-fallback: the file-seeded plan */
        return;
    }
    if (!j->predicted) {
        o->notcov++;
        sfz_why(o, "  %s %s%s tu-missed\n", j->tu, name, what);
        return;
    }
    if (r->header_changed && j->broadened) {
        o->covered_other++; /* covered-tu-broadened: its whole file */
        return;
    }
    if (is_seed(p, j->tu, s, true))
        o->covered_seed++;
    else if (reloc_only(j, name, k)) {
        o->reloc++;
        return;
    } else {
        o->notcov++;
        sfz_why(o, "  %s %s%s NOT-COVERED%s\n", j->tu, name, what,
                p->v.seeds_total > p->v.seeds_len ? " (seed list truncated)" : "");
    }
    judge_aliases(r, p, j, sfz_sym_find(&j->after, name, k));
}

/* The k-th occurrence index of v[i]'s name among v[0..i). */
static size_t ordinal(const struct sfz_syms *f, size_t i)
{
    size_t k = 0;
    for (size_t q = 0; q < i; q++)
        k += strcmp(f->v[q].name, f->v[i].name) == 0;
    return k;
}

static void judge_side(struct sfz_run *r, const struct sfz_plan *p,
                       const struct tu_judge *j, const struct sfz_syms *side,
                       bool before)
{
    for (size_t i = 0; i < side->n; i++) {
        size_t k = ordinal(side, i);
        /* a symbol on both sides is judged once, from the after side */
        if (before && sfz_sym_find(&j->after, side->v[i].name, k) != NULL)
            continue;
        if (sym_changed(j, side->v[i].name, k))
            judge_sym(r, p, j, &side->v[i], k);
    }
}

static bool read_syms(struct sfz_run *r, const char *dir, const char *tu,
                      struct sfz_syms *out)
{
    char path[PATH_MAX] = "", err[128] = "";
    uint8_t *img = NULL;
    size_t n = 0;
    bool ok;
    ok = sfz_object(path, sizeof(path), dir, tu) && sfz_slurp(path, &img, &n) &&
         sfz_elf_syms(img, n, out, err, sizeof(err));
    if (!ok)
        sfz_why(r->out, "cannot read the symbols of %s: %s\n", path, err);
    free(img);
    return ok;
}

static bool judge_syms(struct sfz_run *r, const struct sfz_plan *p,
                       struct tu_judge *j)
{
    bool ok = read_syms(r, r->ob, j->tu, &j->before) &&
              read_syms(r, r->oa, j->tu, &j->after);
    if (ok) {
        judge_side(r, p, j, &j->after, false);
        judge_side(r, p, j, &j->before, true);
    }
    sfz_syms_free(&j->before);
    sfz_syms_free(&j->after);
    return ok;
}

static bool same_object(const struct sfz_run *r, const char *tu, bool *same)
{
    char a[PATH_MAX], b[PATH_MAX];
    uint8_t *x = NULL, *y = NULL;
    size_t xn = 0, yn = 0;
    bool ok = sfz_object(a, sizeof(a), r->ob, tu) && sfz_object(b, sizeof(b), r->oa, tu) &&
              sfz_slurp(a, &x, &xn) && sfz_slurp(b, &y, &yn);
    *same = ok && xn == yn && memcmp(x, y, xn) == 0;
    free(x);
    free(y);
    return ok;
}

static bool judge_tu(struct sfz_run *r, const struct sfz_plan *p, const char *tu)
{
    const struct zcl_devloop_facts_tu_verdict *t = tu_of(p, tu);
    struct tu_judge j = {.tu = tu, .predicted = t != NULL && t->affected,
                         .broadened = t != NULL && t->broadened};
    struct sfz_outcome *o = r->out;
    bool same = false;
    if (!same_object(r, tu, &same)) {
        sfz_why(o, "cannot compare objects for %s\n", tu);
        return false;
    }
    o->tus++;
    o->predicted += j.predicted;
    o->changed += !same;
    o->over += same && j.predicted;
    if (!same && !j.predicted) {
        o->missed++;
        sfz_why(o, "  %s object changed, planned unaffected (%s)\n", tu,
                t != NULL ? t->reason : "not in the universe");
    }
    return same || judge_syms(r, p, &j);
}

bool sfz_plan_and_judge(struct sfz_run *r)
{
    struct sfz_plan *p = zcl_calloc(1, sizeof(*p), "sfz.plan");
    struct sfz_outcome *o = r->out;
    bool ok = p != NULL && plan(r, p);
    if (ok) {
        o->narrowed = p->v.narrowed;
        (void)snprintf(o->vreason, sizeof(o->vreason), "%s",
                       p->v.narrowed ? "" : p->v.reason);
        o->seeds = p->v.seeds_total;
    }
    for (size_t k = 0; ok && k < r->tus.n; k++)
        ok = judge_tu(r, p, r->tus.v[k]);
    if (ok)
        o->status = o->missed == 0 && o->notcov == 0 ? SFZ_PASS : SFZ_FAIL;
    if (p != NULL)
        zcl_devloop_facts_report_free(&p->report);
    free(p);
    return ok;
}
