/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_select — decide, with no human input, which functions are
 * fingerprintable, and record for every one that is not exactly why.
 *
 * The verdicts form a PARTITION of every function definition the scan found,
 * which is what makes the coverage number an accounting rather than an
 * estimate: candidates plus every exclusion bucket equals the definition
 * count, always. The order of the tests is therefore load-bearing, because a
 * function that fails several tests is attributed to the first one:
 *
 *   1. the fingerprint tool's own code, which must never fingerprint itself;
 *   2. linkage — a `static` function cannot be called from a generated
 *      harness at all, so nothing else about it matters;
 *   3. PURITY, before shape. Asking "is it pure?" first means the breakdown
 *      answers the more interesting question — how much of this tree is
 *      reproducible at all — rather than hiding impure functions inside a
 *      "bad parameter type" bucket;
 *   4. a header prototype to #include, without which the harness cannot
 *      declare the call;
 *   5. shape — can its inputs be synthesised and its outputs observed.
 */

#include "fp_priv.h"

#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* The tool must not fingerprint itself: its own helpers are pure and would
 * show up as candidates, and its generated probes would then be measuring
 * the measuring apparatus. */
static bool fp_is_self(const char *path)
{
    return strncmp(path, "lib/fingerprint/", 16) == 0 ||
           strncmp(path, "tools/fingerprint_", 18) == 0 ||
           strstr(path, "/fp_probes_") != NULL;
}

/* A prototype in a HEADER, which is what the generated harness includes. A
 * prototype that exists only in a .c is useless here: the harness would have
 * to re-declare it by hand, and a hand-written declaration that disagreed
 * with the definition would silently produce a wrong call. */
static int fp_header_proto(const struct fp_index *ix, const char *name)
{
    uint64_t h = fp_hash_str(name);
    int i;
    for (i = ix->bucket[h % ix->nbuckets]; i >= 0; i = ix->syms[i].next) {
        const struct fp_sym *s = &ix->syms[i];
        if (s->kind != (unsigned char)FP_SYM_PROTO)
            continue;
        if (strcmp(s->name, name) != 0)
            continue;
        if (ix->files[s->file].is_header)
            return i;
    }
    return -1;
}

/* Record WHY, by name. An exclusion bucket with 4000 functions in it is a
 * number; the same bucket with "the top three unresolved call targets are
 * these" is a work item. */
static void fp_tally_cause(struct fp_index *ix, enum fp_verdict v,
                           const char *name)
{
    size_t i;
    if (name == NULL || name[0] == '\0')
        return;
    for (i = 0; i < ix->ncauses; i++)
        if (ix->causes[i].verdict == (unsigned char)v &&
            strcmp(ix->causes[i].name, name) == 0) {
            ix->causes[i].count++;
            return;
        }
    if (ix->ncauses == ix->causes_cap) {
        size_t ncap = ix->causes_cap ? ix->causes_cap * 2u : 1024u;
        struct fp_cause *grown = (struct fp_cause *)zcl_realloc(
            ix->causes, ncap * sizeof *grown, "fp.causes");
        if (grown == NULL)
            return;
        ix->causes = grown;
        ix->causes_cap = ncap;
    }
    snprintf(ix->causes[ix->ncauses].name,
             sizeof ix->causes[ix->ncauses].name, "%s", name);
    ix->causes[ix->ncauses].verdict = (unsigned char)v;
    ix->causes[ix->ncauses].count = 1u;
    ix->ncauses++;
}

static int fp_cmp_cause(const void *a, const void *b)
{
    const struct fp_cause *x = (const struct fp_cause *)a;
    const struct fp_cause *y = (const struct fp_cause *)b;
    if (x->count != y->count)
        return x->count < y->count ? 1 : -1;
    return strcmp(x->name, y->name);
}

int fp_index_top_causes(struct fp_index *ix, enum fp_verdict v,
                        char (*name)[FP_MAX_NAME], size_t *count, int cap)
{
    size_t i;
    int n = 0;
    if (ix->ncauses > 1)
        qsort(ix->causes, ix->ncauses, sizeof *ix->causes, fp_cmp_cause);
    for (i = 0; i < ix->ncauses && n < cap; i++) {
        if (ix->causes[i].verdict != (unsigned char)v)
            continue;
        snprintf(name[n], FP_MAX_NAME, "%s", ix->causes[i].name);
        count[n] = ix->causes[i].count;
        n++;
    }
    return n;
}

static int fp_cmp_cand(const void *a, const void *b)
{
    const struct fp_candidate *x = (const struct fp_candidate *)a;
    const struct fp_candidate *y = (const struct fp_candidate *)b;
    int c = strcmp(x->group, y->group);
    if (c != 0) return c;
    c = strcmp(x->include, y->include);
    if (c != 0) return c;
    c = strcmp(x->def_path, y->def_path);
    if (c != 0) return c;
    return strcmp(x->name, y->name);
}

long fp_index_select(struct fp_index *ix, struct fp_candidate *out, size_t cap,
                     size_t *tally)
{
    size_t i;
    size_t n = 0;

    for (i = 0; i < (size_t)FP_V_COUNT; i++)
        tally[i] = 0;

    for (i = 0; i < ix->nsyms; i++) {
        struct fp_sym *s = &ix->syms[i];
        const struct fp_file *f;
        enum fp_verdict v;
        struct fp_candidate cand;
        int proto;

        if (s->kind != (unsigned char)FP_SYM_FUNC)
            continue;
        f = &ix->files[s->file];

        if (fp_is_self(f->path)) { tally[FP_V_SELF_EXCLUDED]++; continue; }
        if (s->is_static)        { tally[FP_V_STATIC_LINKAGE]++; continue; }

        ix->cause[0] = '\0';
        v = fp_purity_of(ix, (int)i);
        if (v != FP_V_CANDIDATE) {
            tally[v]++;
            fp_tally_cause(ix, v, ix->cause);
            continue;
        }

        proto = fp_header_proto(ix, s->name);
        if (proto < 0) { tally[FP_V_NO_PROTOTYPE]++; continue; }

        v = fp_signature_of(ix, (int)i, &cand);
        if (v != FP_V_CANDIDATE) { tally[v]++; continue; }

        snprintf(cand.include, sizeof cand.include, "%s",
                 ix->files[ix->syms[proto].file].include);
        tally[FP_V_CANDIDATE]++;
        if (n < cap)
            out[n++] = cand;
    }

    if (n > 1)
        qsort(out, n, sizeof *out, fp_cmp_cand);
    return (long)n;
}
