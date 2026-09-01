/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BM25 ranked retrieval. See retrieval/retrieval.h for the formula, the
 * provenance (a port of qedc's modules/fact_db) and the three things this
 * port changed.
 *
 * Structure, unchanged from the original:
 *   docs[]   documents, ids 1..count-1; index 0 reserved for "no document"
 *   toks[]   open-addressed hash of token -> posting list
 *   posting  (doc id, term frequency), appended in insertion order, so each
 *            list is already sorted by doc id and needs no sort
 *
 * A FOURTH DIFFERENCE, not in the header because it is about this file's
 * choice of primitives rather than the design: tokenizing uses ASCII tests
 * written out here instead of <ctype.h>. isalnum() and tolower() answer
 * according to the process locale, so the same corpus indexed on two machines
 * with different LC_CTYPE can produce different tokens, different document
 * frequencies and therefore a different ranking. An index another node is
 * expected to reproduce cannot depend on an environment variable.
 */

#include <retrieval/retrieval.h>

#include <base/log_macros.h>
#include <base/safe_alloc.h>

#include <math.h>
#include <stdlib.h>
#include <string.h>

struct posting {
    uint32_t doc;
    uint32_t tf;
};

struct posting_list {
    struct posting *data;
    size_t          n;
    size_t          cap;
};

struct document {
    char    *name;
    char    *text;
    uint32_t len; /* token count, including repeats */
};

struct token_entry {
    char               *token; /* owned, lowercased; NULL means empty slot */
    struct posting_list plist;
};

struct zcl_retrieval {
    struct document *docs;
    size_t           count;     /* docs in use INCLUDING the reserved 0 */
    size_t           cap_docs;

    struct token_entry *toks;
    size_t              n_toks;
    size_t              cap_toks;

    uint64_t total_len; /* sum of every document's token count */
    bool     poisoned;
};

/* ── ASCII, deliberately not <ctype.h> ─────────────────────────────── */

static bool ascii_alnum(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

static char ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* ── lifecycle ─────────────────────────────────────────────────────── */

struct zcl_retrieval *zcl_retrieval_create(void)
{
    struct zcl_retrieval *r =
        zcl_calloc(1, sizeof *r, "retrieval_index");
    if (!r)
        return NULL;

    r->cap_docs = 8;
    r->docs = zcl_calloc(r->cap_docs, sizeof *r->docs, "retrieval_docs");
    r->cap_toks = 64;
    r->toks = zcl_calloc(r->cap_toks, sizeof *r->toks, "retrieval_toks");
    if (!r->docs || !r->toks) {
        free(r->docs);
        free(r->toks);
        free(r);
        return NULL;
    }
    r->count = 1; /* id 0 is reserved and never returned */
    return r;
}

void zcl_retrieval_destroy(struct zcl_retrieval *r)
{
    if (!r)
        return;
    for (size_t i = 1; i < r->count; i++) {
        free(r->docs[i].name);
        free(r->docs[i].text);
    }
    free(r->docs);
    for (size_t i = 0; i < r->cap_toks; i++) {
        if (r->toks[i].token) {
            free(r->toks[i].token);
            free(r->toks[i].plist.data);
        }
    }
    free(r->toks);
    free(r);
}

/* ── token table ───────────────────────────────────────────────────── */

static size_t str_hash(const char *s)
{
    /* FNV-1a over the bytes as given; callers hash lowercased tokens. */
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return (size_t)h;
}

static bool toks_grow(struct zcl_retrieval *r)
{
    if (r->cap_toks > SIZE_MAX / (2 * sizeof(struct token_entry)))
        LOG_FAIL("retrieval", "token table too large to grow: %zu", r->cap_toks);

    size_t nc = r->cap_toks * 2;
    struct token_entry *nt =
        zcl_calloc(nc, sizeof *nt, "retrieval_toks_grow");
    if (!nt)
        LOG_FAIL("retrieval", "token table grow to %zu failed", nc);

    for (size_t i = 0; i < r->cap_toks; i++) {
        if (!r->toks[i].token)
            continue;
        size_t idx = str_hash(r->toks[i].token) % nc;
        while (nt[idx].token)
            idx = (idx + 1) % nc;
        nt[idx] = r->toks[i];
    }
    free(r->toks);
    r->toks = nt;
    r->cap_toks = nc;
    return true;
}

/* Find `token`, inserting it if absent. NULL on allocation failure. */
static struct token_entry *tok_slot(struct zcl_retrieval *r, const char *token)
{
    if ((r->n_toks + 1) * 2 > r->cap_toks && !toks_grow(r))
        return NULL;

    size_t idx = str_hash(token) % r->cap_toks;
    while (r->toks[idx].token) {
        if (strcmp(r->toks[idx].token, token) == 0)
            return &r->toks[idx];
        idx = (idx + 1) % r->cap_toks;
    }
    r->toks[idx].token = zcl_strdup(token, "retrieval_token");
    if (!r->toks[idx].token)
        LOG_NULL("retrieval", "token '%s' could not be stored", token);
    r->n_toks++;
    return &r->toks[idx];
}

/* Read-only lookup: NULL when the token was never indexed. */
static const struct token_entry *tok_find(const struct zcl_retrieval *r,
                                          const char *token)
{
    if (r->cap_toks == 0)
        return NULL;
    size_t idx = str_hash(token) % r->cap_toks;
    while (r->toks[idx].token) {
        if (strcmp(r->toks[idx].token, token) == 0)
            return &r->toks[idx];
        idx = (idx + 1) % r->cap_toks;
    }
    return NULL;
}

static bool posting_push(struct posting_list *pl, uint32_t doc, uint32_t tf)
{
    if (pl->n == pl->cap) {
        if (pl->cap > SIZE_MAX / (2 * sizeof(struct posting)))
            LOG_FAIL("retrieval", "posting list too large: %zu", pl->cap);
        size_t nc = pl->cap ? pl->cap * 2 : 4;
        struct posting *nd =
            zcl_realloc(pl->data, nc * sizeof *nd, "retrieval_postings");
        if (!nd)
            LOG_FAIL("retrieval", "posting list grow to %zu failed", nc);
        pl->data = nd;
        pl->cap = nc;
    }
    pl->data[pl->n].doc = doc;
    pl->data[pl->n].tf = tf;
    pl->n++;
    return true;
}

/* ── tokenizer ─────────────────────────────────────────────────────── */

/* Calls `emit` once per lowercased token. Stops early, returning false, the
 * first time `emit` refuses. A run of alphanumerics longer than
 * ZCL_RETRIEVAL_TOKEN_MAX is emitted as consecutive full-length chunks. */
bool zcl_retrieval_tokenize(const char *text, zcl_retrieval_token_fn emit,
                            void *ctx)
{
    if (!text || !emit) return false;
    char buf[ZCL_RETRIEVAL_TOKEN_MAX + 1];
    for (const char *p = text; *p;) {
        while (*p && !ascii_alnum(*p))
            p++;
        size_t k = 0;
        while (*p && ascii_alnum(*p) && k + 1 < sizeof buf)
            buf[k++] = ascii_lower(*p++);
        buf[k] = '\0';
        if (k > 0 && !emit(buf, ctx))
            return false;
    }
    return true;
}

/* ── add ───────────────────────────────────────────────────────────── */

struct add_ctx {
    struct zcl_retrieval *r;
    uint32_t              doc;
    uint32_t              len;
};

static bool add_emit(const char *tok, void *vctx)
{
    struct add_ctx *c = vctx;
    struct token_entry *te = tok_slot(c->r, tok);
    if (!te)
        return false;

    /* Every posting for this document is appended consecutively, so a repeat
     * of the same token is always the list's last entry. */
    struct posting_list *pl = &te->plist;
    if (pl->n > 0 && pl->data[pl->n - 1].doc == c->doc) {
        if (pl->data[pl->n - 1].tf == UINT32_MAX)
            LOG_FAIL("retrieval", "term frequency overflow in doc %u", c->doc);
        pl->data[pl->n - 1].tf++;
    } else if (!posting_push(pl, c->doc, 1)) {
        return false;
    }

    if (c->len == UINT32_MAX)
        LOG_FAIL("retrieval", "document %u exceeds the token limit", c->doc);
    c->len++;
    return true;
}

static bool docs_reserve(struct zcl_retrieval *r)
{
    if (r->count != r->cap_docs)
        return true;
    if (r->cap_docs > SIZE_MAX / (2 * sizeof(struct document)))
        LOG_FAIL("retrieval", "document table too large: %zu", r->cap_docs);

    size_t nc = r->cap_docs * 2;
    struct document *nd =
        zcl_realloc(r->docs, nc * sizeof *nd, "retrieval_docs_grow");
    if (!nd)
        LOG_FAIL("retrieval", "document table grow to %zu failed", nc);
    memset(nd + r->count, 0, (nc - r->count) * sizeof *nd);
    r->docs = nd;
    r->cap_docs = nc;
    return true;
}

uint32_t zcl_retrieval_add(struct zcl_retrieval *r, const char *name,
                           const char *text)
{
    if (!r || !name || !text)
        return 0;
    if (r->poisoned)
        LOG_RETURN(0, "retrieval", "index poisoned; refusing to add '%s'", name);
    if (r->count > UINT32_MAX - 1) {
        r->poisoned = true;
        LOG_RETURN(0, "retrieval", "document id space exhausted");
    }
    if (!docs_reserve(r)) {
        r->poisoned = true;
        return 0;
    }

    /* Nothing is committed until the whole document is indexed. The id is
     * chosen but r->count is not advanced, so a failure part-way through
     * leaves the corpus exactly the size it was, and no caller can ever see
     * a document that is only half in the index. Postings already written
     * against the abandoned id do stay behind, and they are unreachable: the
     * index is poisoned in the same breath and answers nothing from then on.
     * That is the whole reason the poison flag exists — dropping the stray
     * postings instead would mean walking every posting list on a failure
     * path that has just been told it cannot allocate. */
    uint32_t id = (uint32_t)r->count;
    char *dup_name = zcl_strdup(name, "retrieval_doc_name");
    char *dup_text = zcl_strdup(text, "retrieval_doc_text");
    struct add_ctx ctx = { .r = r, .doc = id, .len = 0 };
    if (!dup_name || !dup_text ||
        !zcl_retrieval_tokenize(text, add_emit, &ctx)) {
        free(dup_name);
        free(dup_text);
        r->poisoned = true;
        LOG_RETURN(0, "retrieval", "document '%s' was not fully indexed", name);
    }

    r->docs[id].name = dup_name;
    r->docs[id].text = dup_text;
    r->docs[id].len = ctx.len;
    r->total_len += ctx.len;
    r->count++;
    return id;
}

/* ── query ─────────────────────────────────────────────────────────── */

struct query_ctx {
    const struct zcl_retrieval *r;
    struct zcl_retrieval_hit   *acc; /* indexed by doc id */
};

static bool query_emit(const char *tok, void *vctx)
{
    struct query_ctx *c = vctx;
    const struct token_entry *te = tok_find(c->r, tok);
    if (!te)
        return true; /* a query term the corpus does not hold scores nothing */

    const struct posting_list *pl = &te->plist;
    double n = (double)pl->n;
    double n_docs = (double)(c->r->count - 1);
    double idf = log((n_docs - n + 0.5) / (n + 0.5) + 1.0);
    double avgdl = zcl_retrieval_avgdl(c->r);
    if (avgdl <= 0.0)
        avgdl = 1.0;

    for (size_t i = 0; i < pl->n; i++) {
        double tf = (double)pl->data[i].tf;
        double dl = (double)c->r->docs[pl->data[i].doc].len;
        double denom =
            tf + ZCL_RETRIEVAL_K1 * (1.0 - ZCL_RETRIEVAL_B +
                                     ZCL_RETRIEVAL_B * dl / avgdl);
        if (denom == 0.0)
            denom = 1.0;
        c->acc[pl->data[i].doc].score +=
            idf * (tf * (ZCL_RETRIEVAL_K1 + 1.0)) / denom;
    }
    return true;
}

/* Best score first; ties by ascending document id, so the order is total and
 * two nodes with the same corpus produce the same list. */
static int cmp_hit(const void *va, const void *vb)
{
    const struct zcl_retrieval_hit *a = va;
    const struct zcl_retrieval_hit *b = vb;
    if (a->score > b->score)
        return -1;
    if (a->score < b->score)
        return 1;
    if (a->doc < b->doc)
        return -1;
    if (a->doc > b->doc)
        return 1;
    return 0;
}

bool zcl_retrieval_query_checked(const struct zcl_retrieval *r,
                                 const char *query,
                                 struct zcl_retrieval_hit *out, size_t cap,
                                 size_t *out_count)
{
    if (!out_count)
        return false;
    *out_count = 0;
    if (!r || !query || !out || cap == 0)
        return false;
    if (r->poisoned)
        LOG_FAIL("retrieval", "index poisoned; refusing to answer");
    if (r->count <= 1)
        return true;

    struct zcl_retrieval_hit *acc =
        zcl_calloc(r->count, sizeof *acc, "retrieval_scores");
    if (!acc)
        LOG_FAIL("retrieval", "scoring %zu documents failed", r->count);
    for (size_t i = 0; i < r->count; i++)
        acc[i].doc = (uint32_t)i;

    struct query_ctx ctx = { .r = r, .acc = acc };
    (void)zcl_retrieval_tokenize(query, query_emit, &ctx);
    /* query_emit never refuses */

    qsort(acc, r->count, sizeof *acc, cmp_hit);

    size_t n = 0;
    for (size_t i = 0; i < r->count && n < cap; i++) {
        if (acc[i].doc != 0 && acc[i].score > 0.0)
            out[n++] = acc[i];
    }
    free(acc);
    *out_count = n;
    return true;
}

size_t zcl_retrieval_query(const struct zcl_retrieval *r, const char *query,
                           struct zcl_retrieval_hit *out, size_t cap)
{
    size_t count = 0;
    return zcl_retrieval_query_checked(r, query, out, cap, &count) ? count : 0;
}

/* ── accessors ─────────────────────────────────────────────────────── */

const char *zcl_retrieval_name(const struct zcl_retrieval *r, uint32_t doc)
{
    if (!r || doc == 0 || (size_t)doc >= r->count)
        return NULL;
    return r->docs[doc].name;
}

const char *zcl_retrieval_text(const struct zcl_retrieval *r, uint32_t doc)
{
    if (!r || doc == 0 || (size_t)doc >= r->count)
        return NULL;
    return r->docs[doc].text;
}

size_t zcl_retrieval_count(const struct zcl_retrieval *r)
{
    return r ? r->count - 1 : 0;
}

size_t zcl_retrieval_tokens(const struct zcl_retrieval *r)
{
    return r ? r->n_toks : 0;
}

double zcl_retrieval_avgdl(const struct zcl_retrieval *r)
{
    if (!r || r->count <= 1)
        return 0.0;
    return (double)r->total_len / (double)(r->count - 1);
}

uint32_t zcl_retrieval_doc_len(const struct zcl_retrieval *r, uint32_t doc)
{
    if (!r || doc == 0 || (size_t)doc >= r->count)
        return 0;
    return r->docs[doc].len;
}

struct df_ctx {
    const struct zcl_retrieval *r;
    size_t                      df;
    unsigned                    seen;
};

static bool df_emit(const char *tok, void *vctx)
{
    struct df_ctx *c = vctx;
    if (c->seen++ > 0)
        return false; /* one token only: a phrase has no single frequency */
    const struct token_entry *te = tok_find(c->r, tok);
    c->df = te ? te->plist.n : 0;
    return true;
}

size_t zcl_retrieval_df(const struct zcl_retrieval *r, const char *token)
{
    if (!r || !token)
        return 0;
    struct df_ctx c = { .r = r, .df = 0, .seen = 0 };
    (void)zcl_retrieval_tokenize(token, df_emit, &c);
    return c.seen == 1 ? c.df : 0;
}

bool zcl_retrieval_ok(const struct zcl_retrieval *r)
{
    return r && !r->poisoned;
}
