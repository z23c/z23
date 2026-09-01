/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_retrieval — the cognition/modules/retrieval gate.
 *
 * A ranking is only worth quoting if it has properties, and "it returned
 * some documents" is not one. These are the ones that make a ranked answer
 * something one node can hand another:
 *
 *  1. THE ANSWERS ARE THE KNOWN ANSWERS. A five-document corpus is written
 *     out here in full, and every expected order below was worked out from
 *     the BM25 formula by hand against those exact texts, not read off a
 *     run. Assertions are on ORDER and on integer document frequencies, not
 *     on float equality: a score that agrees to the last bit at -O2 and not
 *     at -O0 would fail a test that proves nothing anyone needs.
 *
 *  2. RARITY OUTRANKS PRESENCE. A term in one document out of five must beat
 *     a term in two, at equal length and equal frequency. This is the whole
 *     reason to leave substring matching behind, so it is asserted directly.
 *
 *  3. LENGTH IS NORMALISED. Same term, same count, shorter document wins.
 *
 *  4. THE ORDER IS TOTAL. Two documents that score identically come back in
 *     ascending id, every time. The corpus below contains a deliberate exact
 *     tie for this. Without it the answer depends on qsort's behaviour on
 *     equal elements, which is free to differ between two honest nodes.
 *
 *  5. A POISONED INDEX ANSWERS NOTHING. An insertion is failed on purpose
 *     through the allocation fault hook; from there the index must refuse
 *     every query rather than answer from a corpus with a hole in it. A
 *     retrieval index that degrades quietly is worse than one that stops.
 *
 *  6. TOKENIZING IS NOT LOCALE-SHAPED. Case folds, punctuation and
 *     underscores separate, bytes outside ASCII separate rather than joining
 *     words, and a run longer than the token limit is chunked rather than
 *     truncated — no input silently loses text.
 */

#include "test/test_core.h"

#include <base/safe_alloc.h>
#include <retrieval/retrieval.h>

#include <stdio.h>
#include <string.h>

#define RT_CHECK(name, expr)                                        \
    do {                                                            \
        const bool rt_ok_ = (expr);                                 \
        if (!rt_ok_) failures++;                                    \
        printf("retrieval: %s %s\n", rt_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* ── the corpus ────────────────────────────────────────────────────────
 *
 * Token counts, counted by hand and asserted below:
 *   1 net      10    2 sync     10    3 crypto  10
 *   4 receipt  13    5 test     13          total 56, avgdl 11.2
 *
 * "receipt" appears in documents 4 and 5, both of length 13, once each — an
 * exact scoring tie, which is what proves the tie-break. Document 3 holds
 * "receipts", a different token; that is deliberate, and it is also why this
 * index is a retrieval aid and not a search engine. */
static const char *const k_names[] = { "net", "sync", "crypto", "receipt",
                                       "test" };
static const char *const k_texts[] = {
    "reachability and speed are different properties refuse to collapse them",
    "the node must always sync fast from a cold start",
    "sha3 hashing is the only hash we trust for receipts",
    "a receipt is a claim another node can check and refuse to believe",
    "a test group that emits no per check vector is refused a receipt",
};
#define CORPUS_N (sizeof k_texts / sizeof k_texts[0])

struct token_capture {
    char values[4][ZCL_RETRIEVAL_TOKEN_MAX + 1u];
    size_t count;
    size_t accept;
};

static bool token_capture_emit(const char *token, void *opaque)
{
    struct token_capture *capture = opaque;
    if (capture->count >= capture->accept || capture->count >= 4u)
        return false;
    (void)snprintf(capture->values[capture->count],
                   sizeof(capture->values[0]), "%s", token);
    capture->count++;
    return true;
}

static struct zcl_retrieval *corpus_build(void)
{
    struct zcl_retrieval *r = zcl_retrieval_create();
    if (!r)
        return NULL;
    for (size_t i = 0; i < CORPUS_N; i++) {
        if (zcl_retrieval_add(r, k_names[i], k_texts[i]) != (uint32_t)(i + 1)) {
            zcl_retrieval_destroy(r);
            return NULL;
        }
    }
    return r;
}

/* Name of the nth hit, or "" when there is no nth hit. Comparing names
 * rather than ids keeps the expectations readable. */
static const char *hit_name(const struct zcl_retrieval *r,
                            const struct zcl_retrieval_hit *h, size_t n,
                            size_t count)
{
    if (n >= count)
        return "";
    const char *s = zcl_retrieval_name(r, h[n].doc);
    return s ? s : "";
}

/* ── 1. shape of the index ─────────────────────────────────────────── */

static int case_shape(void)
{
    int failures = 0;
    struct zcl_retrieval *r = corpus_build();
    RT_CHECK("the corpus builds", r != NULL);
    if (!r)
        return failures;

    RT_CHECK("it holds five documents", zcl_retrieval_count(r) == CORPUS_N);
    RT_CHECK("the index is healthy", zcl_retrieval_ok(r));
    RT_CHECK("document 1 is ten tokens", zcl_retrieval_doc_len(r, 1) == 10);
    RT_CHECK("document 2 is ten tokens", zcl_retrieval_doc_len(r, 2) == 10);
    RT_CHECK("document 3 is ten tokens", zcl_retrieval_doc_len(r, 3) == 10);
    RT_CHECK("document 4 is thirteen tokens",
             zcl_retrieval_doc_len(r, 4) == 13);
    RT_CHECK("document 5 is thirteen tokens",
             zcl_retrieval_doc_len(r, 5) == 13);
    RT_CHECK("the average length is 56/5", zcl_retrieval_avgdl(r) == 11.2);
    RT_CHECK("stored names come back",
             strcmp(zcl_retrieval_name(r, 3), "crypto") == 0);
    RT_CHECK("stored text comes back",
             strcmp(zcl_retrieval_text(r, 3), k_texts[2]) == 0);
    RT_CHECK("id 0 is not a document", zcl_retrieval_name(r, 0) == NULL);
    RT_CHECK("one past the end is not a document",
             zcl_retrieval_name(r, 6) == NULL);

    /* Document frequencies are integers counted by eye from the texts. */
    RT_CHECK("df(receipt) is 2", zcl_retrieval_df(r, "receipt") == 2);
    RT_CHECK("df(receipts) is 1 and is a different token",
             zcl_retrieval_df(r, "receipts") == 1);
    RT_CHECK("df(sha3) is 1", zcl_retrieval_df(r, "sha3") == 1);
    RT_CHECK("df(node) is 2", zcl_retrieval_df(r, "node") == 2);
    RT_CHECK("df(check) is 2", zcl_retrieval_df(r, "check") == 2);
    RT_CHECK("df(refuse) is 2 and refused is not refuse",
             zcl_retrieval_df(r, "refuse") == 2 &&
                 zcl_retrieval_df(r, "refused") == 1);
    RT_CHECK("df(a) is 3 documents, not 5 occurrences",
             zcl_retrieval_df(r, "a") == 3);
    RT_CHECK("df of an absent term is 0",
             zcl_retrieval_df(r, "unicorn") == 0);
    RT_CHECK("df of a phrase is refused, not guessed",
             zcl_retrieval_df(r, "sha3 receipts") == 0);
    RT_CHECK("df is case-insensitive like the indexer",
             zcl_retrieval_df(r, "SHA3") == 1);

    zcl_retrieval_destroy(r);
    return failures;
}

/* ── 2. the fixed query set ────────────────────────────────────────── */

static int case_known_answers(void)
{
    int failures = 0;
    struct zcl_retrieval *r = corpus_build();
    RT_CHECK("the corpus builds", r != NULL);
    if (!r)
        return failures;

    struct zcl_retrieval_hit h[8];
    size_t n;

    /* Only document 3 holds "sha3". */
    n = zcl_retrieval_query(r, "sha3", h, 8);
    RT_CHECK("a term in one document returns exactly that one", n == 1);
    RT_CHECK("and it is the crypto document",
             strcmp(hit_name(r, h, 0, n), "crypto") == 0);

    /* Nothing holds "unicorn": a zero-scoring document is never padding. */
    n = zcl_retrieval_query(r, "unicorn", h, 8);
    RT_CHECK("an absent term returns nothing at all", n == 0);

    /* A query with no tokens at all is not a match-everything query. */
    n = zcl_retrieval_query(r, "!!! ...", h, 8);
    RT_CHECK("a query with no tokens returns nothing", n == 0);

    /* RARITY. idf(sha3)=log(4)=1.386 over one document; idf(node)=log(2.4)
     * =0.876 over two. Documents 2 and 3 are both ten tokens, so the length
     * factor is identical and only rarity separates them. Document 4 holds
     * "node" too but is thirteen tokens, so it comes last. */
    n = zcl_retrieval_query(r, "node sha3", h, 8);
    RT_CHECK("three documents answer 'node sha3'", n == 3);
    RT_CHECK("the rare term wins outright",
             strcmp(hit_name(r, h, 0, n), "crypto") == 0);
    RT_CHECK("then the shorter of the two 'node' documents",
             strcmp(hit_name(r, h, 1, n), "sync") == 0);
    RT_CHECK("then the longer one",
             strcmp(hit_name(r, h, 2, n), "receipt") == 0);
    RT_CHECK("and the scores fall in that order",
             h[0].score > h[1].score && h[1].score > h[2].score);

    /* THE TIE. Documents 4 and 5 hold "receipt" once each and are both
     * thirteen tokens: the scores are equal by construction, so the answer
     * is decided entirely by the tie-break. */
    n = zcl_retrieval_query(r, "receipt", h, 8);
    RT_CHECK("two documents hold the term", n == 2);
    RT_CHECK("the tie really is a tie", n == 2 && h[0].score == h[1].score);
    RT_CHECK("the lower id comes first", n == 2 && h[0].doc < h[1].doc);
    RT_CHECK("which is the receipt document",
             strcmp(hit_name(r, h, 0, n), "receipt") == 0);

    /* Case folding: the query is tokenized exactly as the corpus was. */
    struct zcl_retrieval_hit u[8];
    size_t nu = zcl_retrieval_query(r, "RECEIPT", u, 8);
    RT_CHECK("an upper-case query gives the identical list",
             nu == n && u[0].doc == h[0].doc && u[1].doc == h[1].doc);

    /* A cap truncates the list; it does not reorder or refuse it. */
    n = zcl_retrieval_query(r, "node sha3", h, 1);
    RT_CHECK("a cap of one returns one", n == 1);
    RT_CHECK("and it is still the best answer",
             strcmp(hit_name(r, h, 0, n), "crypto") == 0);

    zcl_retrieval_destroy(r);
    return failures;
}

/* ── 3. same corpus, same list ─────────────────────────────────────── */

static int case_reproducible(void)
{
    int failures = 0;
    struct zcl_retrieval *a = corpus_build();
    struct zcl_retrieval *b = corpus_build();
    RT_CHECK("two indexes build", a != NULL && b != NULL);
    if (!a || !b) {
        zcl_retrieval_destroy(a);
        zcl_retrieval_destroy(b);
        return failures;
    }

    RT_CHECK("they agree on size",
             zcl_retrieval_count(a) == zcl_retrieval_count(b));
    RT_CHECK("they agree on the average length",
             zcl_retrieval_avgdl(a) == zcl_retrieval_avgdl(b));
    RT_CHECK("they agree on the distinct token count",
             zcl_retrieval_tokens(a) == zcl_retrieval_tokens(b));

    static const char *const k_queries[] = {
        "receipt", "node sha3", "refuse", "a", "check vector", "sync fast",
    };
    bool same = true;
    for (size_t q = 0; q < sizeof k_queries / sizeof k_queries[0]; q++) {
        struct zcl_retrieval_hit ha[8], hb[8];
        size_t na = zcl_retrieval_query(a, k_queries[q], ha, 8);
        size_t nb = zcl_retrieval_query(b, k_queries[q], hb, 8);
        if (na != nb) {
            same = false;
            break;
        }
        for (size_t i = 0; i < na; i++) {
            if (ha[i].doc != hb[i].doc || ha[i].score != hb[i].score) {
                same = false;
                break;
            }
        }
    }
    RT_CHECK("six queries give identical lists on both, ties included", same);

    /* Querying twice on ONE index must also agree — the accumulator is
     * allocated per query, and a query that left state behind would show up
     * here as a second answer that differs from the first. */
    struct zcl_retrieval_hit h1[8], h2[8];
    size_t n1 = zcl_retrieval_query(a, "node sha3", h1, 8);
    size_t n2 = zcl_retrieval_query(a, "node sha3", h2, 8);
    RT_CHECK("a repeated query on one index agrees with itself",
             n1 == n2 && n1 == 3 && h1[0].doc == h2[0].doc &&
                 h1[0].score == h2[0].score && h1[2].doc == h2[2].doc);

    zcl_retrieval_destroy(a);
    zcl_retrieval_destroy(b);
    return failures;
}

/* ── 4. the tokenizer ──────────────────────────────────────────────── */

static int case_tokenizer(void)
{
    int failures = 0;
    struct token_capture capture = {.accept = 4};
    RT_CHECK("the public tokenizer exposes the engine's exact ASCII atoms",
             zcl_retrieval_tokenize("Alpha_beta99 GAMMA", token_capture_emit,
                                    &capture) &&
             capture.count == 3 &&
             strcmp(capture.values[0], "alpha") == 0 &&
             strcmp(capture.values[1], "beta99") == 0 &&
             strcmp(capture.values[2], "gamma") == 0);
    capture = (struct token_capture){.accept = 1};
    RT_CHECK("the public tokenizer propagates callback refusal",
             !zcl_retrieval_tokenize("one two", token_capture_emit,
                                     &capture) && capture.count == 1);
    RT_CHECK("the public tokenizer refuses NULL inputs",
             !zcl_retrieval_tokenize(NULL, token_capture_emit, &capture) &&
             !zcl_retrieval_tokenize("one", NULL, &capture));
    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK("an index is created", r != NULL);
    if (!r)
        return failures;

    RT_CHECK("mixed case and punctuation index as three tokens",
             zcl_retrieval_add(r, "punct", "Alpha, BETA; gamma!") == 1 &&
                 zcl_retrieval_doc_len(r, 1) == 3);
    RT_CHECK("case is folded", zcl_retrieval_df(r, "beta") == 1);

    /* An identifier separates on underscores. This is the original's rule
     * and it is the useful one here: a query naming a function finds the
     * record even when the record spells the name a little differently. */
    RT_CHECK("an identifier splits on underscores",
             zcl_retrieval_add(r, "ident", "zcl_receipt_encode") == 2 &&
                 zcl_retrieval_doc_len(r, 2) == 3);
    RT_CHECK("and its parts are indexed",
             zcl_retrieval_df(r, "encode") == 1);

    /* Bytes outside ASCII separate. They must not join two words into one
     * token, and they must not be folded by anything locale-dependent. */
    RT_CHECK("a non-ASCII byte separates rather than joins",
             zcl_retrieval_add(r, "utf8", "caf\xc3\xa9 noir") == 3 &&
                 zcl_retrieval_doc_len(r, 3) == 2 &&
                 zcl_retrieval_df(r, "caf") == 1 &&
                 zcl_retrieval_df(r, "noir") == 1);

    /* A run longer than the token limit is chunked, not truncated: 300
     * characters is 127 + 127 + 46. Truncating would silently drop text a
     * caller had every reason to think was indexed. */
    char longrun[301];
    memset(longrun, 'x', 300);
    longrun[300] = '\0';
    RT_CHECK("a 300-character run becomes three tokens",
             zcl_retrieval_add(r, "long", longrun) == 4 &&
                 zcl_retrieval_doc_len(r, 4) == 3);

    /* An empty document is legal and contributes no tokens. */
    RT_CHECK("an empty document indexes as zero tokens",
             zcl_retrieval_add(r, "empty", "") == 5 &&
                 zcl_retrieval_doc_len(r, 5) == 0);

    /* Repeats coalesce into one posting with a frequency, so the same term
     * three times is still one document. */
    RT_CHECK("a repeated term is one document, not three",
             zcl_retrieval_add(r, "rep", "beta beta beta") == 6 &&
                 zcl_retrieval_df(r, "beta") == 2 &&
                 zcl_retrieval_doc_len(r, 6) == 3);

    zcl_retrieval_destroy(r);
    return failures;
}

/* ── 5. fail-closed ────────────────────────────────────────────────── */

static int case_poisoned(void)
{
    int failures = 0;
    struct zcl_retrieval *r = corpus_build();
    RT_CHECK("the corpus builds", r != NULL);
    if (!r)
        return failures;

    struct zcl_retrieval_hit h[8];
    RT_CHECK("it answers before the failure",
             zcl_retrieval_query(r, "sha3", h, 8) == 1);

    /* Fail the first posting list this insertion has to grow. "a" is already
     * in the corpus and its list has room, so the failure lands on the NEXT
     * token — part-way through the document, which is the case that matters:
     * some of it is in the index and the rest never will be. */
    zcl_alloc_fault_fail_next("retrieval_postings");
    RT_CHECK("an insertion that cannot allocate returns no id",
             zcl_retrieval_add(r, "sixth", "a document that never lands") == 0);
    zcl_alloc_fault_clear();

    RT_CHECK("the index reports itself unhealthy", !zcl_retrieval_ok(r));
    RT_CHECK("and refuses to answer from here on",
             zcl_retrieval_query(r, "sha3", h, 8) == 0);
    RT_CHECK("and refuses further insertions",
             zcl_retrieval_add(r, "seventh", "sha3 again") == 0);
    RT_CHECK("the corpus size did not grow",
             zcl_retrieval_count(r) == CORPUS_N);

    zcl_retrieval_destroy(r);
    return failures;
}

/* ── 6. the surface refuses nonsense ───────────────────────────────── */

static int case_surface(void)
{
    int failures = 0;
    struct zcl_retrieval_hit h[4];

    RT_CHECK("a NULL index has no documents", zcl_retrieval_count(NULL) == 0);
    RT_CHECK("a NULL index has no tokens", zcl_retrieval_tokens(NULL) == 0);
    RT_CHECK("a NULL index has no average length",
             zcl_retrieval_avgdl(NULL) == 0.0);
    RT_CHECK("a NULL index has no lengths",
             zcl_retrieval_doc_len(NULL, 1) == 0);
    RT_CHECK("a NULL index has no names", zcl_retrieval_name(NULL, 1) == NULL);
    RT_CHECK("a NULL index has no text", zcl_retrieval_text(NULL, 1) == NULL);
    RT_CHECK("a NULL index has no frequencies",
             zcl_retrieval_df(NULL, "a") == 0);
    RT_CHECK("a NULL index is not healthy", !zcl_retrieval_ok(NULL));
    RT_CHECK("a NULL index answers nothing",
             zcl_retrieval_query(NULL, "a", h, 4) == 0);
    RT_CHECK("adding to a NULL index refuses",
             zcl_retrieval_add(NULL, "n", "t") == 0);
    zcl_retrieval_destroy(NULL); /* must not crash */

    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK("an empty index is created", r != NULL);
    if (!r)
        return failures;
    RT_CHECK("an empty index has no documents", zcl_retrieval_count(r) == 0);
    RT_CHECK("an empty index has no average length",
             zcl_retrieval_avgdl(r) == 0.0);
    RT_CHECK("an empty index answers nothing",
             zcl_retrieval_query(r, "anything", h, 4) == 0);
    size_t checked_count = 99;
    RT_CHECK("checked empty query is an observed zero-hit result",
             zcl_retrieval_query_checked(r, "anything", h, 4,
                                         &checked_count) &&
             checked_count == 0);
    RT_CHECK("a NULL name refuses", zcl_retrieval_add(r, NULL, "t") == 0);
    RT_CHECK("a NULL text refuses", zcl_retrieval_add(r, "n", NULL) == 0);
    RT_CHECK("a refused insertion did not poison the index",
             zcl_retrieval_ok(r) && zcl_retrieval_count(r) == 0);

    RT_CHECK("one document indexes", zcl_retrieval_add(r, "one", "solo") == 1);
    RT_CHECK("a NULL query refuses", zcl_retrieval_query(r, NULL, h, 4) == 0);
    RT_CHECK("a NULL output refuses",
             zcl_retrieval_query(r, "solo", NULL, 4) == 0);
    RT_CHECK("a zero cap refuses", zcl_retrieval_query(r, "solo", h, 0) == 0);
    RT_CHECK("a single-document corpus still scores above zero",
             zcl_retrieval_query(r, "solo", h, 4) == 1 && h[0].score > 0.0);
    checked_count = 99;
    zcl_alloc_fault_fail_next("retrieval_scores");
    RT_CHECK("checked query exposes scoring allocation failure",
             !zcl_retrieval_query_checked(r, "solo", h, 4,
                                          &checked_count) &&
             checked_count == 0);
    zcl_alloc_fault_clear();
    RT_CHECK("legacy query keeps its zero-on-refusal contract",
             zcl_retrieval_query(r, "solo", h, 4) == 1);

    zcl_retrieval_destroy(r);
    return failures;
}

static int case_gold_metrics(void)
{
    int failures = 0;
    static const char *const relevant_a[] = {"a.c", "b.c"};
    static const char *const relevant_b[] = {"c.c"};
    static const struct zcl_retrieval_ranked_file ranked_a[] = {
        {"x.c", 10, true, true}, {"a.c", 10, true, true},
        {"y.c", 10, false, true}, {"b.c", 10, true, true},
        {"z.c", 10, true, true},
    };
    static const struct zcl_retrieval_ranked_file ranked_b[] = {
        {"p01.c", 20, true, true}, {"p02.c", 20, true, true},
        {"p03.c", 20, true, true}, {"p04.c", 20, true, true},
        {"p05.c", 20, true, true}, {"p06.c", 20, true, true},
        {"p07.c", 20, true, true}, {"p08.c", 20, true, true},
        {"p09.c", 20, true, true}, {"p10.c", 20, true, true},
        {"p11.c", 20, true, true}, {"p12.c", 20, true, true},
        {"p13.c", 20, true, true}, {"p14.c", 20, true, true},
        {"p15.c", 20, true, true}, {"p16.c", 20, true, true},
        {"p17.c", 20, true, true}, {"c.c", 20, true, true},
        {"p19.c", 20, true, true}, {"p20.c", 20, true, true},
        {"p21.c", 20, true, true},
    };
    struct zcl_retrieval_gold_task tasks[] = {
        {"task-a", "find a and b", relevant_a, 2,
         ranked_a, sizeof(ranked_a) / sizeof(ranked_a[0]), true},
        {"task-b", "find c", relevant_b, 1,
         ranked_b, sizeof(ranked_b) / sizeof(ranked_b[0]), true},
    };
    struct zcl_retrieval_eval_metrics m = {0};
    RT_CHECK("gold metrics score two reviewed tasks",
             zcl_retrieval_evaluate(tasks, 2, &m));
    RT_CHECK("macro Recall@5 is one half",
             m.recall_at_5_available && m.recall_at_5_bp == 5000);
    RT_CHECK("macro Recall@20 is complete",
             m.recall_at_20_available && m.recall_at_20_bp == 10000);
    RT_CHECK("MRR preserves the rank-2 and rank-18 answers",
             m.mrr_available && m.mrr_bp == 2777);
    RT_CHECK("top-five file and context costs are explicit",
             m.unique_files_at_5 == 10 && m.context_bytes_at_5 == 150 &&
             m.approximate_tokens_at_5 == 38);
    RT_CHECK("wrong-scope rate is one of ten selected files",
             m.wrong_scope_files_at_5 == 1 &&
             m.wrong_scope_at_5_available &&
             m.wrong_scope_at_5_bp == 1000);

    tasks[1].ranked_count = 16;
    tasks[1].ranking_complete = false;
    RT_CHECK("a truncated top-16 ranking still evaluates honestly",
             zcl_retrieval_evaluate(tasks, 2, &m));
    RT_CHECK("Recall@5 remains observable at depth sixteen",
             m.recall_at_5_available && m.recall_at_5_bp == 5000);
    RT_CHECK("Recall@20 is unavailable, never counted as a miss",
             !m.recall_at_20_available && m.recall_at_20_bp == 0);
    RT_CHECK("MRR is unavailable when the first answer may be below the cap",
             !m.mrr_available && m.mrr_bp == 0);

    struct zcl_retrieval_ranked_file rank21[21];
    memcpy(rank21, ranked_b, sizeof(rank21));
    struct zcl_retrieval_ranked_file swap = rank21[17];
    rank21[17] = rank21[20];
    rank21[20] = swap;
    tasks[1].ranked = rank21;
    tasks[1].ranked_count = 21;
    tasks[1].ranking_complete = true;
    RT_CHECK("moving the answer to rank 21 is a measured Recall@20 miss",
             zcl_retrieval_evaluate(tasks, 2, &m) &&
             m.recall_at_20_available && m.recall_at_20_bp == 5000);

    static const struct zcl_retrieval_ranked_file duplicated[] = {
        {"x.c", 1, true, true}, {"a.c", 1, true, true},
        {"a.c", 999, false, true}, {"y.c", 1, true, true},
        {"b.c", 1, true, true},
    };
    tasks[0].ranked = duplicated;
    tasks[0].ranked_count = sizeof(duplicated) / sizeof(duplicated[0]);
    RT_CHECK("a duplicate path cannot improve rank, recall, or context cost",
             zcl_retrieval_evaluate(tasks, 1, &m) &&
             m.recall_at_5_bp == 10000 && m.mrr_bp == 5000 &&
             m.unique_files_at_5 == 4 && m.context_bytes_at_5 == 4 &&
             m.wrong_scope_files_at_5 == 0);

    struct zcl_retrieval_ranked_file unscoped[] = {
        {"x.c", 1, false, true}, {"a.c", 1, false, false},
    };
    tasks[0].ranked = unscoped;
    tasks[0].ranked_count = sizeof(unscoped) / sizeof(unscoped[0]);
    tasks[0].ranking_complete = true;
    RT_CHECK("one unclassified top-five file makes wrong-scope unavailable",
             zcl_retrieval_evaluate(tasks, 1, &m) &&
             !m.wrong_scope_at_5_available &&
             m.wrong_scope_files_at_5 == 0 &&
             m.wrong_scope_at_5_bp == 0);

    tasks[0].ranked_count = 0;
    RT_CHECK("zero selected files leave wrong-scope unavailable",
             zcl_retrieval_evaluate(tasks, 1, &m) &&
             !m.wrong_scope_at_5_available &&
             m.wrong_scope_files_at_5 == 0 &&
             m.wrong_scope_at_5_bp == 0);

    tasks[0].relevant_count = 0;
    RT_CHECK("an empty relevance judgement refuses instead of scoring",
             !zcl_retrieval_evaluate(tasks, 1, &m) && m.tasks == 0);
    RT_CHECK("an empty corpus refuses instead of reporting perfect zeroes",
             !zcl_retrieval_evaluate(NULL, 0, &m));

    struct zcl_retrieval_gold_task zero = {
        .task_id = "zero",
        .query = "a real query with no hits",
        .relevant_paths = relevant_a,
        .relevant_count = 1,
        .ranked = NULL,
        .ranked_count = 0,
        .ranking_complete = true,
    };
    RT_CHECK("a complete zero-hit ranking is a measured zero",
             zcl_retrieval_evaluate(&zero, 1, &m) &&
             m.recall_at_5_available && m.recall_at_5_bp == 0 &&
             m.recall_at_20_available && m.recall_at_20_bp == 0 &&
             m.mrr_available && m.mrr_bp == 0 &&
             m.unique_files_at_5 == 0 && m.context_bytes_at_5 == 0);
    zero.ranking_complete = false;
    RT_CHECK("an incomplete zero-hit ranking is valid but unavailable",
             zcl_retrieval_evaluate(&zero, 1, &m) &&
             !m.recall_at_5_available && !m.recall_at_20_available &&
             !m.mrr_available && m.recall_at_5_bp == 0 &&
             m.recall_at_20_bp == 0 && m.mrr_bp == 0);
    return failures;
}

int test_retrieval(void);
int test_retrieval(void)
{
    int failures = 0;
    failures += case_shape();
    failures += case_known_answers();
    failures += case_reproducible();
    failures += case_tokenizer();
    failures += case_poisoned();
    failures += case_surface();
    failures += case_gold_metrics();
    printf("retrieval: %d failure(s)\n", failures);
    return failures;
}
