/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * retrieval — BM25 ranked retrieval over an in-memory document corpus.
 *
 * WHY THIS EXISTS
 * ---------------
 * `code have` answers "does the tree already do this?" by weighted substring
 * matching against a hand-rolled stemmer. Substring matching cannot rank: it
 * has no notion of how rare a term is, so a query mentioning a word that
 * appears in nine hundred records scores that word exactly as loudly as the
 * one word that appears twice. The result is an answer list whose order
 * carries no information, which is the same as having no answer.
 *
 * BM25 is the honest fix and it is not new code here: this is a port of
 * `modules/fact_db/src/fact_db.c` from the owner's own qedc tree, 244 lines
 * of C23, no dependency added.
 *
 *   score(q, d) = SUM over t in q of
 *                 IDF(t) * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl/avgdl))
 *
 * with k1 = 1.5, b = 0.75 and IDF(t) = log((N - n + 0.5) / (n + 0.5) + 1),
 * where N is the corpus size and n the number of documents holding t.
 *
 * WHAT THE PORT CHANGED, AND WHY
 * ------------------------------
 * Three things, each because this corpus is meant to be quotable by one node
 * to another rather than printed once on a developer's terminal:
 *
 *  1. THE RANKING IS TOTAL. The original compares two documents by score and
 *     nothing else, so documents that tie come back in whatever order qsort
 *     happens to leave them — implementation-defined, and free to differ
 *     between two honest nodes running the same query over the same corpus.
 *     Ties here break on ascending document id, which is insertion order.
 *  2. EVERY ALLOCATION IS CHECKED. The original checks none.
 *  3. THE AVERAGE DOCUMENT LENGTH IS A SUM DIVIDED BY A COUNT, not a rolling
 *     update. The rolling form accumulates rounding error and makes avgdl a
 *     function of insertion order even when the corpus is identical.
 *
 * FAIL-CLOSED
 * -----------
 * An insertion is all-or-nothing: a document that cannot be indexed in full
 * is not counted, not named and not returned. What it can leave behind is
 * postings pointing at an id no document ever took, and a query run over
 * those would answer confidently and wrongly. So an index that has ever
 * failed an insertion refuses to answer at all: zcl_retrieval_ok() goes
 * false and zcl_retrieval_query() returns 0 from then on. There is no way to
 * clear it short of destroying the index, which is the point — a retrieval
 * index that degrades quietly is worse than one that stops.
 *
 * NOT PERSISTENT. The corpus is rebuilt from its source on each run; there is
 * no on-disk index format and no staleness key to get wrong.
 */

#ifndef ZCL_RETRIEVAL_H
#define ZCL_RETRIEVAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* BM25 parameters. Standard values; named so a test can quote them rather
 * than re-typing the constants and agreeing with itself. */
#define ZCL_RETRIEVAL_K1 1.5
#define ZCL_RETRIEVAL_B  0.75

/* A token longer than this is indexed as consecutive chunks of this length
 * rather than truncated, so no text is silently dropped. */
#define ZCL_RETRIEVAL_TOKEN_MAX 127u

struct zcl_retrieval;

/* One ranked answer. `doc` is the id returned by zcl_retrieval_add. */
struct zcl_retrieval_hit {
    uint32_t doc;
    double   score;
};

/* Create an empty index. Returns NULL on allocation failure. */
struct zcl_retrieval *zcl_retrieval_create(void);
void zcl_retrieval_destroy(struct zcl_retrieval *r);

/* Index one document. Returns its id, or 0 on refusal — a NULL argument, or
 * an allocation failure, which also poisons the index. Ids start at 1; 0 is
 * never a valid document. */
uint32_t zcl_retrieval_add(struct zcl_retrieval *r, const char *name,
                           const char *text);

/* Top-`cap` documents for `query`, best first, ties broken by ascending id.
 * Writes at most `cap` hits and returns how many were written. Documents
 * scoring zero are never written: a hit list padded with non-answers is
 * worse than a short one. Returns 0 if the index is poisoned. */
size_t zcl_retrieval_query(const struct zcl_retrieval *r, const char *query,
                           struct zcl_retrieval_hit *out, size_t cap);

/* Checked form for callers that must distinguish an observed zero-hit result
 * from an unobserved ranking caused by invalid input, a poisoned index, or a
 * scoring allocation failure. On every failure *out_count is set to zero.
 * The legacy count-returning API above remains for callers where zero is a
 * sufficient refusal value. */
bool zcl_retrieval_query_checked(const struct zcl_retrieval *r,
                                 const char *query,
                                 struct zcl_retrieval_hit *out, size_t cap,
                                 size_t *out_count);

/* Stored fields. NULL for an unknown id. */
const char *zcl_retrieval_name(const struct zcl_retrieval *r, uint32_t doc);
const char *zcl_retrieval_text(const struct zcl_retrieval *r, uint32_t doc);

/* Corpus shape — enough for a test to check the index directly instead of
 * only through the ranking it produces. */
size_t   zcl_retrieval_count(const struct zcl_retrieval *r);
size_t   zcl_retrieval_tokens(const struct zcl_retrieval *r);
double   zcl_retrieval_avgdl(const struct zcl_retrieval *r);
uint32_t zcl_retrieval_doc_len(const struct zcl_retrieval *r, uint32_t doc);

/* Document frequency: how many documents hold `token`. The token is matched
 * after the same lowercasing the indexer applies, so a caller may pass it in
 * any case. 0 for an unknown token. */
size_t zcl_retrieval_df(const struct zcl_retrieval *r, const char *token);

/* False once any insertion has failed. A poisoned index answers nothing. */
bool zcl_retrieval_ok(const struct zcl_retrieval *r);

/* Truthful file-level evaluation for a reviewed task corpus. Ranked symbol
 * results must be projected to files before use; duplicate paths are ignored
 * at their later positions so one file cannot inflate recall or rank. */
#define ZCL_RETRIEVAL_EVAL_RANK_MAX 128u
#define ZCL_RETRIEVAL_EVAL_BASIS_POINTS 10000u

struct zcl_retrieval_ranked_file {
    const char *path;
    uint64_t context_bytes;
    bool in_scope;
    bool in_scope_available;
};

struct zcl_retrieval_gold_task {
    const char *task_id;
    const char *query;
    const char *const *relevant_paths;
    size_t relevant_count;
    const struct zcl_retrieval_ranked_file *ranked;
    size_t ranked_count;
    bool ranking_complete;
};

struct zcl_retrieval_eval_metrics {
    uint32_t tasks;
    uint32_t recall_at_5_bp;
    uint32_t recall_at_20_bp;
    uint32_t mrr_bp;
    bool recall_at_5_available;
    bool recall_at_20_available;
    bool mrr_available;
    uint64_t unique_files_at_5;
    uint64_t context_bytes_at_5;
    uint64_t approximate_tokens_at_5;
    uint64_t wrong_scope_files_at_5;
    uint32_t wrong_scope_at_5_bp;
    bool wrong_scope_at_5_available;
};

/* Evaluate macro Recall@5/20 and MRR in integer basis points. A metric is
 * unavailable when any task's ranking is truncated before the required depth
 * and the needed answer has not already been observed. Context tokens use the
 * declared byte/4 approximation and are never presented as tokenizer output.
 * File and context totals sum each task's unique observed selections up to
 * rank five; they are not global-unique corpus counts. Wrong-scope is available
 * only when at least one file was selected and every selected row has an
 * explicit scope classification. */
bool zcl_retrieval_evaluate(
    const struct zcl_retrieval_gold_task *tasks, size_t task_count,
    struct zcl_retrieval_eval_metrics *out);

#endif /* ZCL_RETRIEVAL_H */
