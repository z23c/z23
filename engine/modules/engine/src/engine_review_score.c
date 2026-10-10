/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The review-scoring rule. See engine/engine_review_score.h for the rule.
 * Pure: reads its arguments, writes only `out`.
 */

#include "engine/engine_review_score.h"

#include <string.h>

static bool ers_discard(const struct ers_finding *f)
{
    return !f->file || !f->file[0] || f->line <= 0 ||
           (f->kind != ERS_KIND_CHANGE && f->kind != ERS_KIND_CLAIM);
}

static bool ers_kind_matches(enum ers_locus locus, enum ers_kind kind)
{
    if (locus == ERS_LOCUS_CODE)
        return kind == ERS_KIND_CHANGE;
    return kind == ERS_KIND_CLAIM;
}

static bool ers_range_hits(const struct ers_case *c, const struct ers_range *r,
                           const struct ers_finding *f)
{
    if (strcmp(r->file, f->file) != 0)
        return false;
    return f->line >= r->line_lo - c->tolerance &&
           f->line <= r->line_hi + c->tolerance;
}

static bool ers_finding_hits(const struct ers_case *c,
                             const struct ers_finding *f)
{
    if (!ers_kind_matches(c->locus, f->kind))
        return false;
    for (size_t i = 0; i < c->nranges; i++) {
        if (ers_range_hits(c, &c->ranges[i], f))
            return true;
    }
    return false;
}

void ers_score_review(const struct ers_case *c,
                      const struct ers_finding *findings, size_t n,
                      struct ers_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!c)
        return;
    bool hit = false;
    out->findings = n;
    for (size_t i = 0; i < n; i++) {
        const struct ers_finding *f = &findings[i];
        if (ers_discard(f)) {
            out->discarded++;
            continue;
        }
        if (f->kind == ERS_KIND_CHANGE)
            out->surviving_change++;
        else
            out->surviving_claim++;
        if (c->label == ERS_LABEL_DEFECT && ers_finding_hits(c, f))
            hit = true;
    }
    if (c->label == ERS_LABEL_SOUND) {
        out->rejected_change = out->surviving_change > 0;
        out->rejected_claim = out->surviving_claim > 0;
        out->rejected = out->rejected_change || out->rejected_claim;
        return;
    }
    out->caught = hit;
    out->accepted = !hit;
}
