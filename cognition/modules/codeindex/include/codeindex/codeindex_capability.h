/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_capability — "does this checkout ALREADY DO X?"
 *
 * ── The question this exists to answer ──
 * codeindex_find() and codeindex_search_text() search NAMES. That answers
 * "where is the thing called X", which is a different question from the one an
 * agent actually has before it writes code: "is there already something here
 * that does X?" The gap is not academic. This tree already had a 970-line
 * ActiveRecord layer with sixteen validation macros used by most of its
 * models, and an agent asked to add validation could not find it by searching
 * for "validation" — the macros are called `validates_*`, and only a name
 * search for the literal string `validates` reached them. It imported a
 * 12,474-line ORM instead.
 *
 * ── What it searches ──
 * Concepts, via cheap morphology, not embeddings. The query is lowercased,
 * split, stripped of stopwords, and suffix-stemmed ("validation" → "valid",
 * "hashing" → "hash", "records" → "record"), then each stem is matched as a
 * case-insensitive SUBSTRING against five kinds of recorded text:
 *   symbol names, symbol doc comments, symbol signatures,
 *   file purposes (the leading block comment's first substantive line),
 *   and repo paths / group names.
 * That is the whole trick. It carries a surprising amount of the value
 * because this tree documents itself; it carries NONE of the value where the
 * tree does not. See "What this cannot find" at the bottom.
 *
 * ── What it returns ──
 * Capabilities, anchored on the FILE that owns the API (a header when one
 * declares the symbols, else the defining .c), each carrying the evidence that
 * put it there. The load-bearing field is `used_by_files`: a capability with
 * sixty callers is a live part of this system, and a capability with zero is
 * something somebody left behind. That single number is what would have
 * stopped the ActiveRecord mistake.
 *
 * ── The verdict is DERIVED ──
 * codeindex_capability_verdict() reads ONLY the fields on the records it is
 * handed — the same fields the caller renders. It therefore cannot disagree
 * with the evidence on the page. This is deliberate and is the whole safety
 * property: a confident ALREADY EXISTS that the counts do not support would
 * send the next agent down exactly the wrong path, which is the failure this
 * file exists to prevent.
 *
 * ── What this cannot find ──
 *   * A capability whose header carries no comment and whose symbols are named
 *     opaquely. There is no text to match, so only its literal name reaches it.
 *   * A capability expressed purely as data (a `.def` registry's rows are
 *     macro data and are never scanned for symbols).
 *   * Usage through function pointers, dispatch tables, or dlopen — those
 *     edges are invisible to the ref index, so `used_by_files` UNDERCOUNTS
 *     them. It never overcounts: a comment that merely mentions a name is not
 *     a reference.
 * A NOT_FOUND from this query means "the recorded text does not say so",
 * never "this tree cannot do that".
 */

#ifndef ZCL_CODEINDEX_CAPABILITY_H
#define ZCL_CODEINDEX_CAPABILITY_H

#include "codeindex/codeindex.h"

#include <stdbool.h>
#include <stddef.h>

struct codeindex;

/* Query stems kept. A longer query is truncated to these, reported through
 * `terms_dropped` rather than silently narrowed. */
#define CI_CAPABILITY_TERM_CAP 6
/* Stems are short by construction; this bounds one stem's stored text. */
#define CI_CAPABILITY_TERM_MAX 48
/* Symbol names rendered per capability. `symbol_count` is the true total. */
#define CI_CAPABILITY_SYMBOL_CAP 8

/* How `used_by_files` was counted. Emitted verbatim so the number is never
 * presented without saying what it is a count OF. */
#define CI_CAPABILITY_BASIS_MATCHED "callers-of-matched-symbols"
#define CI_CAPABILITY_BASIS_FILE    "callers-of-file-symbols"

/* One candidate capability plus the evidence that selected it. */
struct ci_capability {
    /* A short label derived from the anchor: its file stem plus, when the
     * matched symbols share one, their common name prefix. Never invented. */
    char what[192];
    /* The file that owns the API — a header when one declares the symbols. */
    char header[256];
    char group[64];
    /* The anchor's recorded one-line purpose ("" when the file has none). */
    char purpose[CI_FILE_PURPOSE_MAX];
    /* Matched symbol names, sorted, first CI_CAPABILITY_SYMBOL_CAP only. */
    char symbols[CI_CAPABILITY_SYMBOL_CAP][128];
    int  symbols_listed;
    /* Symbols of this anchor whose NAME matched a query stem. Doc-only and
     * purpose-only matches raise `score` but never enter this set, so the
     * count stays checkable by hand from the emitted names. */
    int  symbol_count;
    /* Distinct files holding a recorded call site of this capability's
     * symbols, excluding the anchor itself. See `count_basis`. */
    int  used_by_files;
    char count_basis[32];
    /* Lowest-sorting such file, "" when there are none. */
    char example_caller[256];
    /* Deterministic ranking convenience; not a probability. */
    int  score;
    /* How many of the query's stems this candidate matched anywhere. */
    int  terms_matched;
};

/* What the search actually did, so a NOT_FOUND can say what was looked at
 * instead of just being empty. */
struct ci_capability_query {
    char stems[CI_CAPABILITY_TERM_CAP][CI_CAPABILITY_TERM_MAX];
    int  term_count;
    int  terms_dropped;      /* query terms past CI_CAPABILITY_TERM_CAP */
    int  symbol_rows;        /* symbol rows that matched at least one stem */
    int  file_rows;          /* file rows that matched at least one stem */
    int  candidates;         /* distinct anchors considered */
    bool relaxed;            /* true when the all-terms pass found nothing and
                              * the n-1 pass was used; caps confidence at
                              * PARTIAL */
    bool truncated;          /* candidate table overflowed its bound */
};

enum ci_capability_verdict {
    CI_CAPABILITY_NOT_FOUND = 0,
    CI_CAPABILITY_PARTIAL,
    CI_CAPABILITY_ALREADY_EXISTS
};

/* Rank capabilities for `text`, best first. Fills up to `cap` records and
 * returns the count (>=0), -1 on a hard error. `q` (required) receives what
 * the search did.
 *
 * Admission is deliberately strict: a candidate must match EVERY query stem.
 * Only when that yields nothing is the bar dropped to n-1 stems (and only for
 * a query of two or more), with `q->relaxed` set. A candidate that matches one
 * stem out of three is not returned at all, because a weak match dressed as an
 * answer teaches the caller to stop trusting this query — which costs more
 * than returning nothing. */
int codeindex_capabilities(struct codeindex *ci, const char *text,
                           struct ci_capability *out, int cap,
                           struct ci_capability_query *q);

/* The verdict for a result set. Reads ONLY `caps` and `q->term_count` /
 * `q->relaxed` — never re-derives anything from the index — so it can never
 * claim more than the rendered evidence supports. `n <= 0` is NOT_FOUND. */
enum ci_capability_verdict codeindex_capability_verdict(
    const struct ci_capability *caps, int n,
    const struct ci_capability_query *q);

/* Per-candidate confidence, on the same evidence and the same thresholds the
 * verdict uses: "high", "medium", or "low". */
const char *codeindex_capability_confidence(const struct ci_capability *c,
                                            const struct ci_capability_query *q);

/* "ALREADY EXISTS" / "PARTIAL" / "NOT FOUND". */
const char *codeindex_capability_verdict_label(enum ci_capability_verdict v);

/* Reduce one word to its search stem, in place. Exposed for the test that
 * pins the morphology; callers use codeindex_capabilities(). */
void ci_capability_stem(char *word);

#endif /* ZCL_CODEINDEX_CAPABILITY_H */
