/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_retrieval — the cognition/modules/retrieval gate.
 *
 * Ranking properties, on a five-document corpus with expected orders worked
 * out by hand from the BM25 formula. Assertions are on ORDER and integer
 * document frequencies, not float equality.
 *
 *  1. The answers are the known answers.
 *  2. Rarity outranks presence: a term in one document beats a term in two
 *     at equal length and frequency.
 *  3. Length is normalised: same term and count, shorter document wins.
 *  4. The order is total: equal scores come back in ascending id (the corpus
 *     holds an exact tie).
 *  5. A poisoned index answers nothing: after an injected allocation failure
 *     every query is refused.
 *  6. Tokenizing is not locale-shaped: case folds, punctuation and
 *     underscores separate, non-ASCII bytes separate, and a run longer than
 *     the token limit is chunked rather than truncated.
 *  7. Reusing a token does not grow a half-full token table or poison the
 *     index on an allocation that the insertion did not need. */

#include "test/test_core.h"

#include <base/safe_alloc.h>
#include <base/log_level.h>
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
 * Token counts: 1 net 10, 2 sync 10, 3 crypto 10, 4 receipt 13, 5 test 13;
 * total 56, avgdl 11.2.
 *
 * "receipt" appears once each in documents 4 and 5 (both length 13): an exact
 * scoring tie. Document 3 holds "receipts", a different token. */
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

/* Name of the nth hit, or "" when there is none. */
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

    /* RARITY. idf(sha3)=log(4)=1.386 over one document; idf(node)=log(2.4)=0.876 over two. Documents 2 and 3 have equal length, so only rarity separates them; document 4 has thirteen tokens and comes last. */
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

    /* THE TIE. Documents 4 and 5 score equal by construction; the tie-break decides. */
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

    /* Querying twice on one index agrees: the accumulator is per query. */
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

/* A half-full token table must not grow merely to reuse a token. */
static int case_existing_token_growth(void)
{
    int failures = 0;
    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK("the token-growth corpus builds", r != NULL);
    if (!r)
        return failures;
    const char *seed =
        "t00 t01 t02 t03 t04 t05 t06 t07 "
        "t08 t09 t10 t11 t12 t13 t14 t15 "
        "t16 t17 t18 t19 t20 t21 t22 t23 "
        "t24 t25 t26 t27 t28 t29 t30 t31";
    const bool seeded = zcl_retrieval_add(r, "seed", seed) == 1 &&
                        zcl_retrieval_tokens(r) == 32;
    RT_CHECK("32 distinct tokens fill half of the initial table", seeded);
    if (!seeded) {
        zcl_retrieval_destroy(r);
        return failures;
    }

    zcl_alloc_fault_fail_next("retrieval_toks_grow");
    const uint32_t repeated = zcl_retrieval_add(r, "repeat", "t00 t00");
    const bool growth_pending = zcl_alloc_fault_armed_label() != NULL;
    zcl_alloc_fault_clear();
    struct zcl_retrieval_hit hits[2] = {0};
    RT_CHECK("reusing tokens needs no token-table allocation",
             repeated == 2 && growth_pending && zcl_retrieval_ok(r) &&
             zcl_retrieval_tokens(r) == 32 &&
             zcl_retrieval_doc_len(r, 2) == 2 &&
             zcl_retrieval_df(r, "t00") == 2 &&
             zcl_retrieval_query(r, "t00", hits, 2) == 2);
    zcl_retrieval_destroy(r);
    return failures;
}

static int case_tokenizer_public_api(void)
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
    return failures;
}

/* ── 4. the tokenizer ──────────────────────────────────────────────── */

static int case_tokenizer(void)
{
    int failures = 0;
    failures += case_tokenizer_public_api();
    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK("an index is created", r != NULL);
    if (!r)
        return failures;

    RT_CHECK("mixed case and punctuation index as three tokens",
             zcl_retrieval_add(r, "punct", "Alpha, BETA; gamma!") == 1 &&
                 zcl_retrieval_doc_len(r, 1) == 3);
    RT_CHECK("case is folded", zcl_retrieval_df(r, "beta") == 1);

    /* An identifier separates on underscores. */
    RT_CHECK("an identifier splits on underscores",
             zcl_retrieval_add(r, "ident", "zcl_receipt_encode") == 2 &&
                 zcl_retrieval_doc_len(r, 2) == 3);
    RT_CHECK("and its parts are indexed",
             zcl_retrieval_df(r, "encode") == 1);

    /* Bytes outside ASCII separate words and are not locale-folded. */
    RT_CHECK("a non-ASCII byte separates rather than joins",
             zcl_retrieval_add(r, "utf8", "caf\xc3\xa9 noir") == 3 &&
                 zcl_retrieval_doc_len(r, 3) == 2 &&
                 zcl_retrieval_df(r, "caf") == 1 &&
                 zcl_retrieval_df(r, "noir") == 1);

    /* A run longer than the token limit is chunked, not truncated: 300 characters is 127 + 127 + 46. */
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

    /* Repeats coalesce into one posting with a frequency. */
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
    RT_CHECK("committed documents determine frequency before the failure",
             zcl_retrieval_df(r, "a") == 3);

    /* Fail the first posting list the insertion must grow ("a" already has room), so the failure lands part-way through the document. */
    zcl_alloc_fault_fail_next("retrieval_postings");
    RT_CHECK("an insertion that cannot allocate returns no id",
             zcl_retrieval_add(r, "sixth", "a document that never lands") == 0);
    zcl_alloc_fault_clear();

    RT_CHECK("the index reports itself unhealthy", !zcl_retrieval_ok(r));
    RT_CHECK("it refuses frequency from abandoned postings",
             zcl_retrieval_df(r, "a") == 0);
    RT_CHECK("it refuses frequency from committed postings too",
             zcl_retrieval_df(r, "sha3") == 0);
    RT_CHECK("and refuses to answer from here on",
             zcl_retrieval_query(r, "sha3", h, 8) == 0);
    memset(h, 0x5a, sizeof(h));
    struct zcl_retrieval_hit sentinel[8];
    memcpy(sentinel, h, sizeof(h));
    size_t count = 99;
    RT_CHECK("checked poisoned query refuses with zero count and no hits",
             !zcl_retrieval_query_checked(r, "sha3", h, 8, &count) &&
             count == 0 && memcmp(h, sentinel, sizeof(h)) == 0);
    RT_CHECK("and refuses further insertions",
             zcl_retrieval_add(r, "seventh", "sha3 again") == 0);
    RT_CHECK("the corpus size did not grow",
             zcl_retrieval_count(r) == CORPUS_N);

    zcl_retrieval_destroy(r);
    return failures;
}

/* ── 6. the surface refuses nonsense ───────────────────────────────── */

static int allocation_refused_state(struct zcl_retrieval *r, size_t count)
{
    int failures = 0;
    struct zcl_retrieval_hit hit = {.doc = 99, .score = -1.0};
    size_t hits = 99;
    RT_CHECK("failed insertion preserves committed count",
             zcl_retrieval_count(r) == count);
    RT_CHECK("failed insertion publishes no name",
             zcl_retrieval_name(r, (uint32_t)(count + 1)) == NULL);
    RT_CHECK("failed insertion publishes no text",
             zcl_retrieval_text(r, (uint32_t)(count + 1)) == NULL);
    RT_CHECK("failed insertion poisons the index", !zcl_retrieval_ok(r));
    RT_CHECK("checked query refuses a poisoned index",
             !zcl_retrieval_query_checked(r, "seed", &hit, 1, &hits));
    RT_CHECK("refused checked query resets the count", hits == 0);
    RT_CHECK("poison survives a later insertion",
             zcl_retrieval_add(r, "later", "seed") == 0);
    return failures;
}

static int allocation_insert_row(const char *label, size_t docs,
                                 const char *seed)
{
    int failures = 0;
    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK(label, r != NULL);
    if (!r)
        return failures;
    for (size_t i = 0; i < docs; i++)
        RT_CHECK(label, zcl_retrieval_add(r, "kept", seed) == i + 1);
    RT_CHECK("seed index is healthy", zcl_retrieval_ok(r));
    struct zcl_retrieval_hit hit;
    RT_CHECK("seed index answers before refusal",
             zcl_retrieval_query(r, "seed", &hit, 1) == 1);
    zcl_alloc_fault_fail_next(label);
    uint32_t id = zcl_retrieval_add(r, "abandoned", "novel seed");
    RT_CHECK(label, zcl_alloc_fault_armed_label() == NULL);
    zcl_alloc_fault_clear();
    RT_CHECK(label, id == 0);
    failures += allocation_refused_state(r, docs);
    RT_CHECK("committed name survives refusal",
             zcl_retrieval_name(r, 1) != NULL);
    RT_CHECK("committed text survives refusal",
             zcl_retrieval_text(r, 1) != NULL);
    if (zcl_retrieval_name(r, 1) && zcl_retrieval_text(r, 1)) {
        RT_CHECK("committed name is unchanged",
                 strcmp(zcl_retrieval_name(r, 1), "kept") == 0);
        RT_CHECK("committed text is unchanged",
                 strcmp(zcl_retrieval_text(r, 1), seed) == 0);
    }
    zcl_retrieval_destroy(r);
    return failures;
}

static int case_allocation_failures(void)
{
    int failures = 0;
    static const char *const create_tags[] = {
        "retrieval_index", "retrieval_docs", "retrieval_toks"
    };
    for (size_t i = 0; i < sizeof(create_tags) / sizeof(create_tags[0]); i++) {
        zcl_alloc_fault_fail_next(create_tags[i]);
        struct zcl_retrieval *r = zcl_retrieval_create();
        RT_CHECK(create_tags[i], zcl_alloc_fault_armed_label() == NULL);
        zcl_alloc_fault_clear();
        RT_CHECK(create_tags[i], r == NULL);
        zcl_retrieval_destroy(r);
    }
    failures += allocation_insert_row("retrieval_docs_grow", 7, "seed");
    /* Exactly 32 distinct terms: the next insertion crosses half of 64. */
    failures += allocation_insert_row("retrieval_toks_grow", 1,
        "seed t01 t02 t03 t04 t05 t06 t07 t08 t09 t10 t11 t12 t13 t14 t15 "
        "t16 t17 t18 t19 t20 t21 t22 t23 t24 t25 t26 t27 t28 t29 t30 t31");
    failures += allocation_insert_row("retrieval_token", 1, "seed");
    failures += allocation_insert_row("retrieval_doc_name", 1, "seed");
    failures += allocation_insert_row("retrieval_doc_text", 1, "seed");
    return failures;
}

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

static int case_checked_refusals(void)
{
    int failures = 0;
    struct zcl_retrieval *r = zcl_retrieval_create();
    RT_CHECK("checked refusal fixture creates an index", r != NULL);
    if (!r)
        return failures;
    RT_CHECK("checked refusal fixture indexes one document",
             zcl_retrieval_add(r, "one", "solo") == 1);

    struct zcl_retrieval_hit h[4], sentinel[4];
    size_t count = 99;
    const struct {
        const char *label;
        const struct zcl_retrieval *index;
        const char *query;
        struct zcl_retrieval_hit *out;
        size_t cap;
        size_t *out_count;
    } invalid[] = {
        {"checked NULL index refuses", NULL, "solo", h, 4, &count},
        {"checked NULL query refuses", r, NULL, h, 4, &count},
        {"checked NULL output refuses", r, "solo", NULL, 4, &count},
        {"checked zero capacity refuses", r, "solo", h, 0, &count},
        {"checked NULL count refuses", r, "solo", h, 4, NULL},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        count = 99;
        memset(h, 0x5a, sizeof(h));
        memcpy(sentinel, h, sizeof(h));
        RT_CHECK(invalid[i].label,
                 !zcl_retrieval_query_checked(invalid[i].index,
                     invalid[i].query, invalid[i].out, invalid[i].cap,
                     invalid[i].out_count));
        RT_CHECK("checked refusal resets a supplied count and leaves hits alone",
                 count == (invalid[i].out_count ? 0u : 99u) &&
                 memcmp(h, sentinel, sizeof(h)) == 0);
    }
    RT_CHECK("invalid checked arguments leave the document healthy",
             zcl_retrieval_ok(r) && zcl_retrieval_count(r) == 1);
    RT_CHECK("checked valid query still observes the matching document",
             zcl_retrieval_query_checked(r, "solo", h, 4, &count) &&
             count == 1 && h[0].doc == 1 && h[0].score > 0.0);
    RT_CHECK("unknown document IDs have no stored text",
             zcl_retrieval_text(r, 0) == NULL &&
             zcl_retrieval_text(r, 2) == NULL);
    RT_CHECK("unknown document IDs have no length",
             zcl_retrieval_doc_len(r, 0) == 0 &&
             zcl_retrieval_doc_len(r, 2) == 0);
    RT_CHECK("a NULL token has no document frequency",
             zcl_retrieval_df(r, NULL) == 0);
    zcl_retrieval_destroy(r);
    return failures;
}

static int case_gold_metrics_ranking(struct zcl_retrieval_gold_task *tasks,
                                     const struct zcl_retrieval_ranked_file
                                         *ranked_b,
                                     struct zcl_retrieval_eval_metrics *m)
{
    int failures = 0;
    RT_CHECK("gold metrics score two reviewed tasks",
             zcl_retrieval_evaluate(tasks, 2, m));
    RT_CHECK("macro Recall@5 is one half",
             m->recall_at_5_available && m->recall_at_5_bp == 5000);
    RT_CHECK("macro Recall@20 is complete",
             m->recall_at_20_available && m->recall_at_20_bp == 10000);
    RT_CHECK("MRR preserves the rank-2 and rank-18 answers",
             m->mrr_available && m->mrr_bp == 2777);
    RT_CHECK("top-five file and context costs are explicit",
             m->unique_files_at_5 == 10 && m->context_bytes_at_5 == 150 &&
             m->approximate_tokens_at_5 == 38);
    RT_CHECK("wrong-scope rate is one of ten selected files",
             m->wrong_scope_files_at_5 == 1 &&
             m->wrong_scope_at_5_available &&
             m->wrong_scope_at_5_bp == 1000);

    tasks[1].ranked_count = 16;
    tasks[1].ranking_complete = false;
    RT_CHECK("a truncated top-16 ranking still evaluates honestly",
             zcl_retrieval_evaluate(tasks, 2, m));
    RT_CHECK("Recall@5 remains observable at depth sixteen",
             m->recall_at_5_available && m->recall_at_5_bp == 5000);
    RT_CHECK("Recall@20 is unavailable, never counted as a miss",
             !m->recall_at_20_available && m->recall_at_20_bp == 0);
    RT_CHECK("MRR is unavailable when the first answer may be below the cap",
             !m->mrr_available && m->mrr_bp == 0);

    struct zcl_retrieval_ranked_file rank21[21];
    memcpy(rank21, ranked_b, sizeof(rank21));
    struct zcl_retrieval_ranked_file swap = rank21[17];
    rank21[17] = rank21[20];
    rank21[20] = swap;
    tasks[1].ranked = rank21;
    tasks[1].ranked_count = 21;
    tasks[1].ranking_complete = true;
    RT_CHECK("moving the answer to rank 21 is a measured Recall@20 miss",
             zcl_retrieval_evaluate(tasks, 2, m) &&
             m->recall_at_20_available && m->recall_at_20_bp == 5000);
    return failures;
}

static int case_gold_metrics_selection(struct zcl_retrieval_gold_task *tasks,
                                       struct zcl_retrieval_eval_metrics *m)
{
    int failures = 0;
    static const struct zcl_retrieval_ranked_file duplicated[] = {
        {"x.c", 1, true, true}, {"a.c", 1, true, true},
        {"a.c", 999, false, true}, {"y.c", 1, true, true},
        {"b.c", 1, true, true},
    };
    tasks[0].ranked = duplicated;
    tasks[0].ranked_count = sizeof(duplicated) / sizeof(duplicated[0]);
    RT_CHECK("a duplicate path cannot improve rank, recall, or context cost",
             zcl_retrieval_evaluate(tasks, 1, m) &&
             m->recall_at_5_bp == 10000 && m->mrr_bp == 5000 &&
             m->unique_files_at_5 == 4 && m->context_bytes_at_5 == 4 &&
             m->wrong_scope_files_at_5 == 0);

    struct zcl_retrieval_ranked_file unscoped[] = {
        {"x.c", 1, false, true}, {"a.c", 1, false, false},
    };
    tasks[0].ranked = unscoped;
    tasks[0].ranked_count = sizeof(unscoped) / sizeof(unscoped[0]);
    tasks[0].ranking_complete = true;
    RT_CHECK("one unclassified top-five file makes wrong-scope unavailable",
             zcl_retrieval_evaluate(tasks, 1, m) &&
             !m->wrong_scope_at_5_available &&
             m->wrong_scope_files_at_5 == 0 &&
             m->wrong_scope_at_5_bp == 0);

    tasks[0].ranked_count = 0;
    RT_CHECK("zero selected files leave wrong-scope unavailable",
             zcl_retrieval_evaluate(tasks, 1, m) &&
             !m->wrong_scope_at_5_available &&
             m->wrong_scope_files_at_5 == 0 &&
             m->wrong_scope_at_5_bp == 0);

    tasks[0].relevant_count = 0;
    RT_CHECK("an empty relevance judgement refuses instead of scoring",
             !zcl_retrieval_evaluate(tasks, 1, m) && m->tasks == 0);
    RT_CHECK("an empty corpus refuses instead of reporting perfect zeroes",
             !zcl_retrieval_evaluate(NULL, 0, m));
    return failures;
}

static int case_gold_metrics_zero_complete(struct zcl_retrieval_gold_task *zero,
                                           struct zcl_retrieval_eval_metrics *m)
{
    int failures = 0;
    RT_CHECK("a complete zero-hit ranking is a measured zero",
             zcl_retrieval_evaluate(zero, 1, m) &&
             m->recall_at_5_available && m->recall_at_5_bp == 0 &&
             m->recall_at_20_available && m->recall_at_20_bp == 0 &&
             m->mrr_available && m->mrr_bp == 0 &&
             m->unique_files_at_5 == 0 && m->context_bytes_at_5 == 0);
    return failures;
}

static int case_gold_metrics_zero_incomplete(struct zcl_retrieval_gold_task *zero,
                                             struct zcl_retrieval_eval_metrics *m)
{
    int failures = 0;
    zero->ranking_complete = false;
    RT_CHECK("an incomplete zero-hit ranking is valid but unavailable",
             zcl_retrieval_evaluate(zero, 1, m) &&
             !m->recall_at_5_available && !m->recall_at_20_available &&
             !m->mrr_available && m->recall_at_5_bp == 0 &&
             m->recall_at_20_bp == 0 && m->mrr_bp == 0);
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
    failures += case_gold_metrics_ranking(tasks, ranked_b, &m);
    failures += case_gold_metrics_selection(tasks, &m);
    struct zcl_retrieval_gold_task zero = {
        .task_id = "zero",
        .query = "a real query with no hits",
        .relevant_paths = relevant_a,
        .relevant_count = 1,
        .ranked = NULL,
        .ranked_count = 0,
        .ranking_complete = true,
    };
    failures += case_gold_metrics_zero_complete(&zero, &m);
    failures += case_gold_metrics_zero_incomplete(&zero, &m);
    return failures;
}

static bool gold_capture_restore(int saved)
{
    bool ok = fflush(stderr) == 0;
    if (dup2(saved, STDERR_FILENO) < 0) ok = false;
    if (close(saved) != 0) ok = false;
    return ok;
}

static bool gold_capture_read(FILE *capture, const char *expected, bool ok)
{
    char text[4096] = {0};
    if (fseek(capture, 0, SEEK_SET) != 0) ok = false;
    size_t n = fread(text, 1, sizeof(text) - 1, capture);
    if (ferror(capture) || n == sizeof(text) - 1) ok = false;
    if (fclose(capture) != 0) ok = false;
    return ok && strstr(text, expected) != NULL && strstr(text, "private-") == NULL;
}

static FILE *gold_capture_open(void)
{
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "retrieval_log");
    if (fd < 0) return NULL;
    bool removed = unlink(path) == 0;
    FILE *capture = fdopen(fd, "w+");
    if (!capture) {
        (void)close(fd);
        return NULL;
    }
    if (!removed) {
        (void)fclose(capture);
        return NULL;
    }
    return capture;
}

static bool gold_diagnostic(const struct zcl_retrieval_gold_task *invalid,
                            const char *expected)
{
    const char *paths[] = {"a.c"};
    const struct zcl_retrieval_ranked_file ranked[] = {{"a.c", 4, true, true}};
    struct zcl_retrieval_gold_task tasks[] = {
        {"first", "find a", paths, 1, ranked, 1, true}, *invalid,
    };
    FILE *capture = gold_capture_open();
    if (!capture) return false;
    int saved = dup(STDERR_FILENO);
    bool ok = saved >= 0;
    enum zcl_log_level level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ERROR);
    if (fflush(stderr) != 0) ok = false;
    if (ok && dup2(fileno(capture), STDERR_FILENO) < 0) ok = false;
    if (ok) {
        struct zcl_retrieval_eval_metrics metrics;
        ok = !zcl_retrieval_evaluate(tasks, 2, &metrics);
        ok = ok && metrics.tasks == 0 && metrics.unique_files_at_5 == 1 &&
            metrics.context_bytes_at_5 == 4;
    }
    if (saved >= 0 && !gold_capture_restore(saved)) ok = false;
    zcl_log_level_set(level);
    return gold_capture_read(capture, expected, ok);
}

static int case_gold_diagnostics(void)
{
    int failures = 0;
    const char *paths[] = {"a.c"};
    const char *empty[] = {""};
    const char *null_path[] = {NULL};
    const char *duplicate[] = {"private-path", "private-path"};
    const struct zcl_retrieval_ranked_file empty_rank[] = {{"", 0, true, true}};
    const struct zcl_retrieval_ranked_file null_rank[] = {{NULL, 0, true, true}};
    const struct {
        struct zcl_retrieval_gold_task task;
        const char *expected;
    } cases[] = {
        {{"private-id", "", paths, 1, NULL, 0, true},
         "task=1 field=query reason=invalid-field"},
        {{"first", "private-query", paths, 1, NULL, 0, true},
         "task=1 field=task_id reason=duplicate-id"},
        {{"private-id", NULL, paths, 1, NULL, 0, true},
         "task=1 field=query reason=invalid-field"},
        {{NULL, "private-query", paths, 1, NULL, 0, true},
         "task=1 field=task_id reason=invalid-field"},
        {{"", "private-query", paths, 1, NULL, 0, true},
         "task=1 field=task_id reason=invalid-field"},
        {{"private-id", "private-query", NULL, 1, NULL, 0, true},
         "task=1 field=relevant_paths reason=invalid-field"},
        {{"private-id", "private-query", paths, 0, NULL, 0, true},
         "task=1 field=relevant_paths reason=invalid-field"},
        {{"private-id", "private-query", empty, 1, NULL, 0, true},
         "task=1 field=relevant_path reason=invalid-field"},
        {{"private-id", "private-query", null_path, 1, NULL, 0, true},
         "task=1 field=relevant_path reason=invalid-field"},
        {{"private-id", "private-query", duplicate, 2, NULL, 0, true},
         "task=1 field=relevant_path reason=invalid-field"},
        {{"private-id", "private-query", paths, 1, NULL, 1, true},
         "task=1 field=ranked reason=invalid-field"},
        {{"private-id", "private-query", paths, 1, empty_rank,
          ZCL_RETRIEVAL_EVAL_RANK_MAX + 1u, true},
         "task=1 field=ranked reason=invalid-field"},
        {{"private-id", "private-query", paths, 1, empty_rank, 1, true},
         "task=1 field=ranked_path reason=invalid-field"},
        {{"private-id", "private-query", paths, 1, null_rank, 1, true},
         "task=1 field=ranked_path reason=invalid-field"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        RT_CHECK(cases[i].expected, gold_diagnostic(&cases[i].task, cases[i].expected));
    return failures;
}

int test_retrieval(void);
int test_retrieval(void)
{
    int failures = 0;
    failures += case_shape();
    failures += case_known_answers();
    failures += case_reproducible();
    failures += case_existing_token_growth();
    failures += case_tokenizer();
    failures += case_poisoned();
    failures += case_allocation_failures();
    failures += case_surface();
    failures += case_checked_refusals();
    failures += case_gold_metrics();
    failures += case_gold_diagnostics();
    printf("retrieval: %d failure(s)\n", failures);
    return failures;
}
