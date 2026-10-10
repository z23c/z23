/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_review_score — score ONE review's findings against ONE known-answer
 * case. A pure function: no I/O, no allocation, no clock. It is the measurement
 * behind milestone D3 (docs/work/DEVELOPMENT_MVP.md): do reviews agree with the
 * truth, in both directions.
 *
 * THE RULE
 *
 *   A finding with no file, an empty file, a non-positive line, or a kind other
 *   than CHANGE/CLAIM is DISCARDED and counted; it never scores.
 *
 *   A surviving finding HITS a defect case when its file equals a defect
 *   range's file (exact, case-sensitive), its line is in
 *   [line_lo - tolerance, line_hi + tolerance], and its kind matches the locus
 *   (CHANGE with code, CLAIM with claim).
 *
 *   A review of a SOUND case REJECTS it when it has at least one surviving
 *   finding; the result also records the change side and the claim side.
 *
 *   A review of a DEFECT case ACCEPTS it (a miss) when no finding hits.
 */

#ifndef ZCL_ENGINE_REVIEW_SCORE_H
#define ZCL_ENGINE_REVIEW_SCORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ERS_TOLERANCE_DEFAULT 2
#define ERS_TOLERANCE_MAX 50
#define ERS_RANGES_MAX 16
#define ERS_ID_MAX 96    /* buffer size, terminator included */
#define ERS_CLASS_MAX 48
#define ERS_FILE_MAX 256

enum ers_label {
    ERS_LABEL_SOUND = 0,
    ERS_LABEL_DEFECT
};

enum ers_locus {
    ERS_LOCUS_CODE = 0,   /* the defect is in the change: CHANGE findings hit */
    ERS_LOCUS_CLAIM       /* the defect is in the claim: CLAIM findings hit */
};

enum ers_kind {
    ERS_KIND_INVALID = 0, /* any other spelling: discarded */
    ERS_KIND_CHANGE,
    ERS_KIND_CLAIM
};

struct ers_range {
    char    file[ERS_FILE_MAX];
    int64_t line_lo;
    int64_t line_hi;
};

/* The caller owns `ranges` (nranges entries); the rule only reads it. */
struct ers_case {
    char                     id[ERS_ID_MAX];
    char                     cls[ERS_CLASS_MAX];
    enum ers_label           label;
    enum ers_locus           locus;
    int                      tolerance;
    const struct ers_range  *ranges;
    size_t                   nranges;
};

/* `file` may be NULL (a finding that named none). */
struct ers_finding {
    enum ers_kind kind;
    const char   *file;
    int64_t       line;
};

struct ers_result {
    size_t findings;          /* findings presented */
    size_t discarded;         /* of those, discarded */
    size_t surviving_change;
    size_t surviving_claim;
    bool   rejected;          /* sound case: >= 1 surviving finding */
    bool   rejected_change;   /* sound case: >= 1 surviving CHANGE finding */
    bool   rejected_claim;    /* sound case: >= 1 surviving CLAIM finding */
    bool   caught;            /* defect case: some finding hit */
    bool   accepted;          /* defect case: no finding hit (a miss) */
};

void ers_score_review(const struct ers_case *c,
                      const struct ers_finding *findings, size_t n,
                      struct ers_result *out);

#endif /* ZCL_ENGINE_REVIEW_SCORE_H */
