/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shadow-mode proof selection. Proves the corpus is the frozen
 * bytes, the compositional reuse rule refuses every missing condition, the
 * fallback classifier never answers "none" for a false-hit witness, and
 * prints the per-entry shadow report against the live selector. */
#include "test/test_core.h"

#include "dev_shadow_select.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SS_FIXTURE_DIR "tools/dev/fixtures/shadow_select"
#define SS_FILE_MAX (4u * 1024u * 1024u)

static struct zcl_shadow_corpus ss_corpus;
static struct zcl_shadow_result ss_rows[ZCL_SHADOW_MAX_ENTRIES];

static char *ss_slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = zcl_malloc(SS_FILE_MAX, "ss_slurp");
    size_t n = buf ? fread(buf, 1, SS_FILE_MAX - 1, f) : 0;
    bool ok = buf && !ferror(f) && n < SS_FILE_MAX - 1;
    fclose(f);
    if (!ok) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

static bool ss_load_corpus(void)
{
    size_t len = 0;
    char why[128] = "";
    char *text = ss_slurp(SS_FIXTURE_DIR "/corpus.tsv", &len);
    bool ok = text && zcl_shadow_corpus_parse(text, len, &ss_corpus, why,
                                              sizeof(why));
    if (!ok) printf("corpus: %s\n", why);
    free(text);
    return ok;
}

static bool ss_load_weights(struct zcl_shadow_weights *w)
{
    size_t len = 0;
    char why[128] = "";
    char *text = ss_slurp(SS_FIXTURE_DIR "/weights.tsv", &len);
    bool ok = text && zcl_shadow_weights_parse(text, len, w, why, sizeof(why));
    if (!ok) printf("weights: %s\n", why);
    free(text);
    return ok;
}

static const struct zcl_shadow_entry *ss_entry(const char *id)
{
    for (size_t i = 0; i < ss_corpus.count; i++)
        if (strcmp(ss_corpus.entries[i].id, id) == 0)
            return &ss_corpus.entries[i];
    return NULL;
}

static bool ss_patch_facts(const char *id, struct zcl_shadow_patch_facts *out,
                           bool *sha_ok)
{
    const struct zcl_shadow_entry *e = ss_entry(id);
    char path[256];
    size_t len = 0;
    if (!e) return false;
    (void)snprintf(path, sizeof(path), SS_FIXTURE_DIR "/%s.patch", id);
    char *bytes = ss_slurp(path, &len);
    if (!bytes) return false;
    uint8_t digest[32];
    zcl_sha3_256((const unsigned char *)bytes, len, digest);
    *sha_ok = memcmp(digest, e->patch_sha3, 32) == 0;
    char why[64];
    bool ok = zcl_shadow_patch_analyze(e->component, (const uint8_t *)bytes,
                                       len, out, why, sizeof(why));
    free(bytes);
    return ok;
}

static int ss_test_corpus_frozen(void)
{
    int failures = 0;
    TEST("shadow select: corpus holds 20 real rows and every adversarial kind") {
        ASSERT(ss_load_corpus());
        size_t real = 0;
        bool kinds[ZCL_SHADOW_KIND__COUNT] = {false};
        for (size_t i = 0; i < ss_corpus.count; i++) {
            kinds[ss_corpus.entries[i].kind] = true;
            real += ss_corpus.entries[i].kind == ZCL_SHADOW_KIND_REAL;
            ASSERT(ss_corpus.entries[i].file_count >= 1 &&
                   ss_corpus.entries[i].file_count <= 3);
        }
        ASSERT_EQ(real, (size_t)20);
        for (unsigned k = 0; k < ZCL_SHADOW_KIND__COUNT; k++) ASSERT(kinds[k]);
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_weights(void)
{
    int failures = 0;
    struct zcl_shadow_weights w = {0};
    TEST("shadow select: cost weights are sorted and cover the 213 lint gates") {
        ASSERT(ss_load_weights(&w));
        ASSERT_EQ(zcl_shadow_weights_count(&w, ZCL_SHADOW_OBLIGATION_LINT_GATE),
                  (size_t)213);
        uint32_t ms = 0;
        ASSERT(zcl_shadow_weight_ms(&w, ZCL_SHADOW_OBLIGATION_TEST_GROUP,
                                    "test_codec_cursor", &ms));
        ASSERT(!zcl_shadow_weight_ms(&w, ZCL_SHADOW_OBLIGATION_LINT_GATE,
                                     "test_codec_cursor", &ms));
        ASSERT(zcl_shadow_weights_median(&w, ZCL_SHADOW_OBLIGATION_LINT_GATE) >
               0);
        const char unsorted[] = "test_group\tb\t1\t1\ntest_group\ta\t1\t1\n";
        struct zcl_shadow_weights bad = {0};
        char why[64];
        ASSERT(!zcl_shadow_weights_parse(unsorted, sizeof(unsorted) - 1, &bad,
                                         why, sizeof(why)));
        PASS();
    } _test_next:;
    zcl_shadow_weights_free(&w);
    return failures;
}

/* Each synthetic patch is the frozen bytes and says what it claims. */
static int ss_test_synthetic_facts(void)
{
    int failures = 0;
    TEST("shadow select: synthetic patches match their SHA3 and their kind") {
        struct zcl_shadow_patch_facts p;
        bool sha = false;
        ASSERT(ss_patch_facts("syn-private-impl", &p, &sha) && sha);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_NONE);
        ASSERT(memcmp(p.contract_before, p.contract_after, 32) == 0);
        ASSERT(ss_patch_facts("syn-contract", &p, &sha) && sha);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_MOVED);
        ASSERT(memcmp(p.contract_before, p.contract_after, 32) != 0);
        ASSERT(ss_patch_facts("syn-header-decl", &p, &sha) && sha);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_MOVED);
        ASSERT(ss_patch_facts("syn-abi", &p, &sha) && sha);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_MOVED);
        ASSERT(ss_patch_facts("syn-negative-lookup", &p, &sha) && sha);
        ASSERT(p.file_count == 1 && p.created[0]);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_NONE);
        ASSERT(ss_patch_facts("syn-flag", &p, &sha) && sha);
        ASSERT(zcl_shadow_path_is_build_graph(p.files[0]));
        ASSERT(ss_patch_facts("syn-generated-input", &p, &sha) && sha);
        ASSERT(zcl_shadow_path_is_generator_input(p.files[0]));
        PASS();
    } _test_next:;
    return failures;
}

static bool ss_analyze_text(const char *patch, struct zcl_shadow_patch_facts *p)
{
    char why[64];
    return zcl_shadow_patch_analyze("platform/modules/codec",
                                    (const uint8_t *)patch, strlen(patch), p,
                                    why, sizeof(why));
}

static int ss_test_contract_tokens(void)
{
    int failures = 0;
    TEST("shadow select: contract roots ignore comments, see additions and rewrites") {
        struct zcl_shadow_patch_facts p;
        const char *comment_only =
            "diff --git a/platform/modules/codec/include/codec/cursor.h "
            "b/platform/modules/codec/include/codec/cursor.h\n"
            "--- a/platform/modules/codec/include/codec/cursor.h\n"
            "+++ b/platform/modules/codec/include/codec/cursor.h\n"
            "@@ -1,2 +1,2 @@\n"
            "-/* old words */ int a;\n"
            "+/* new words */  int   a;\n";
        ASSERT(ss_analyze_text(comment_only, &p));
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_NONE);
        ASSERT(memcmp(p.contract_before, p.contract_after, 32) == 0);
        const char *additive =
            "diff --git a/platform/modules/codec/include/codec/cursor.h "
            "b/platform/modules/codec/include/codec/cursor.h\n"
            "@@ -1,1 +1,2 @@\n"
            " int a;\n"
            "+int b;\n";
        ASSERT(ss_analyze_text(additive, &p));
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_ADDITIVE);
        const char *private_only =
            "diff --git a/platform/modules/codec/src/cursor.c "
            "b/platform/modules/codec/src/cursor.c\n"
            "@@ -1,1 +1,1 @@\n"
            "-return 1;\n"
            "+return 2;\n";
        ASSERT(ss_analyze_text(private_only, &p));
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_NONE);
        ASSERT(p.contract_hunks == 0 && p.hunks == 1);
        ASSERT(!ss_analyze_text("not a patch\n", &p));
        PASS();
    } _test_next:;
    return failures;
}

static void ss_claim_ok(struct zcl_shadow_reuse_claim *c,
                        const enum zcl_shadow_premise *premises, size_t n)
{
    memset(c, 0, sizeof(*c));
    memset(c->contract_before, 0x11, 32);
    memset(c->contract_after, 0x11, 32);
    memset(c->callee_impl_after, 0x22, 32);
    memset(c->contract_run_impl, 0x22, 32);
    c->contract_verdict = ZCL_SHADOW_VERDICT_PASS;
    c->contract_basis = ZCL_SHADOW_BASIS_EXECUTED;
    c->contract_obligations = 3;
    c->caller_premises = premises;
    c->caller_premise_count = n;
}

/* The rule admits exactly one shape and names every other one. */
static int ss_test_reuse_rule(void)
{
    int failures = 0;
    TEST("shadow select: reuse rule refuses each missing condition") {
        static const enum zcl_shadow_premise contract[] = {
            ZCL_SHADOW_PREMISE_CONTRACT, ZCL_SHADOW_PREMISE_CONTRACT};
        static const enum zcl_shadow_premise symbol[] = {
            ZCL_SHADOW_PREMISE_CONTRACT, ZCL_SHADOW_PREMISE_PRIVATE_SYMBOL};
        static const enum zcl_shadow_premise layout[] = {
            ZCL_SHADOW_PREMISE_PRIVATE_LAYOUT};
        static const enum zcl_shadow_premise header[] = {
            ZCL_SHADOW_PREMISE_PRIVATE_HEADER};
        struct zcl_shadow_reuse_claim c;
        ss_claim_ok(&c, contract, 2);
        ASSERT(zcl_shadow_reuse_admit(&c) == ZCL_SHADOW_REUSE_ADMIT);
        /* 1: contract root moved */
        c.contract_after[31] ^= 1;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED);
        /* 2: not freshly executed -- reused, never run, or zero obligations */
        ss_claim_ok(&c, contract, 2);
        c.contract_basis = ZCL_SHADOW_BASIS_REUSED;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED);
        ss_claim_ok(&c, contract, 2);
        c.contract_verdict = ZCL_SHADOW_VERDICT_NOT_RUN;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED);
        ss_claim_ok(&c, contract, 2);
        c.contract_obligations = 0;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED);
        /* 2: executed but failed */
        ss_claim_ok(&c, contract, 2);
        c.contract_verdict = ZCL_SHADOW_VERDICT_FAIL;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_FAILED);
        /* 2: an old PASS -- executed on another implementation root */
        ss_claim_ok(&c, contract, 2);
        c.contract_run_impl[0] ^= 1;
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL);
        /* 3: any premise outside the contract, or none stated */
        ss_claim_ok(&c, symbol, 2);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE);
        ss_claim_ok(&c, layout, 1);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE);
        ss_claim_ok(&c, header, 1);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE);
        ss_claim_ok(&c, contract, 0);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE);
        /* malformed: zero roots, missing premise array, NULL */
        ss_claim_ok(&c, contract, 2);
        memset(c.callee_impl_after, 0, 32);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_MALFORMED);
        ss_claim_ok(&c, NULL, 2);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_MALFORMED);
        ASSERT(zcl_shadow_reuse_admit(NULL) ==
               ZCL_SHADOW_REUSE_REFUSE_MALFORMED);
        PASS();
    } _test_next:;
    return failures;
}

/* An unchanged ABI and signature plus an old PASS is the exact shape of the
 * syn-contract witness. It must not be enough: the contract test rewrite
 * moves contract_root, and without a fresh run the claim is refused anyway. */
static int ss_test_unchanged_abi_is_not_enough(void)
{
    int failures = 0;
    TEST("shadow select: unchanged ABI with an old PASS never admits reuse") {
        static const enum zcl_shadow_premise contract[] = {
            ZCL_SHADOW_PREMISE_CONTRACT};
        struct zcl_shadow_patch_facts p;
        bool sha = false;
        ASSERT(ss_patch_facts("syn-contract", &p, &sha) && sha);
        struct zcl_shadow_reuse_claim c;
        ss_claim_ok(&c, contract, 1);
        memcpy(c.contract_before, p.contract_before, 32);
        memcpy(c.contract_after, p.contract_after, 32);
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED);
        memcpy(c.contract_after, p.contract_before, 32);
        c.contract_run_impl[5] ^= 0x40; /* the PASS predates the new impl */
        ASSERT(zcl_shadow_reuse_admit(&c) ==
               ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL);
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_classifier(void)
{
    int failures = 0;
    TEST("shadow select: fallback precedence is conflict, policy, dependency, scope") {
        struct zcl_shadow_scope_facts f = {0};
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_NONE);
        f.closure_universal = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE);
        f.closure_universal = false;
        f.negative_lookup = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE);
        f.generated_input = true;
        ASSERT(zcl_shadow_classify(&f) ==
               ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE);
        f.generated_input = false;
        f.build_graph_input = true;
        ASSERT(zcl_shadow_classify(&f) ==
               ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE);
        f.consensus_policy = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_POLICY);
        f.bytes_mismatch = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_CONFLICT);
        ASSERT(zcl_shadow_classify(NULL) == ZCL_SHADOW_FALLBACK_CONFLICT);
        ASSERT_STR_EQ(zcl_shadow_fallback_name(
                          ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE),
                      "dependency-change");
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_corpus_refusals(void)
{
    int failures = 0;
    TEST("shadow select: malformed corpus rows are refused, not repaired") {
        static struct zcl_shadow_corpus c;
        char why[64];
        const char *sha = "0000000000000000000000000000000000000000000000000000000000000000";
        const char *commit = "7a9f354f3f7996383c0e7c858346ac29a5ad8957";
        char row[512];
        (void)snprintf(row, sizeof(row), "a\treal\tx\t%s\t%s\tx.c\n", commit,
                       sha);
        ASSERT(zcl_shadow_corpus_parse(row, strlen(row), &c, why, sizeof(why)));
        (void)snprintf(row, sizeof(row), "a\tbogus\tx\t%s\t%s\tx.c\n", commit,
                       sha);
        ASSERT(!zcl_shadow_corpus_parse(row, strlen(row), &c, why,
                                        sizeof(why)));
        (void)snprintf(row, sizeof(row), "a\treal\tx\t%.39s\t%s\tx.c\n",
                       commit, sha);
        ASSERT(!zcl_shadow_corpus_parse(row, strlen(row), &c, why,
                                        sizeof(why)));
        (void)snprintf(row, sizeof(row), "a\treal\tx\t%s\t%.62s\tx.c\n",
                       commit, sha);
        ASSERT(!zcl_shadow_corpus_parse(row, strlen(row), &c, why,
                                        sizeof(why)));
        (void)snprintf(row, sizeof(row),
                       "a\treal\tx\t%s\t%s\tx.c\na\treal\tx\t%s\t%s\ty.c\n",
                       commit, sha, commit, sha);
        ASSERT(!zcl_shadow_corpus_parse(row, strlen(row), &c, why,
                                        sizeof(why)));
        (void)snprintf(row, sizeof(row), "a\treal\tx\t%s\t%s\ta,b,c,d,e\n",
                       commit, sha);
        ASSERT(!zcl_shadow_corpus_parse(row, strlen(row), &c, why,
                                        sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static bool ss_row_consistent(const struct zcl_shadow_result *r)
{
    return r->bytes_verified && r->groups_reference > 0 &&
           r->lint_reference == 213 && r->lint_selected == r->lint_reference &&
           r->fresh_cost_ms <= r->reference_cost_ms &&
           r->rule_cost_ms <= r->fresh_cost_ms &&
           r->build_invalidated <= r->build_total &&
           r->edges_selected <= r->groups_selected &&
           r->premise_groups <= r->groups_reference &&
           (unsigned)r->fallback < ZCL_SHADOW_FALLBACK__COUNT;
}

static const struct zcl_shadow_result *ss_row(size_t n, const char *id)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(ss_rows[i].id, id) == 0) return &ss_rows[i];
    return NULL;
}

/* Regressions for the false-hit witnesses in
 * docs/experiments/2026-09-25-shadow-obligation-selector.md: a shadow policy
 * must never answer "none" for these, and the rule must keep no caller. */
static bool ss_witness_guarded(size_t n)
{
    static const char *const witnesses[] = {
        "syn-flag", "syn-generated-input", "syn-negative-lookup",
    };
    for (size_t i = 0; i < sizeof(witnesses) / sizeof(witnesses[0]); i++) {
        const struct zcl_shadow_result *r = ss_row(n, witnesses[i]);
        if (!r || r->fallback == ZCL_SHADOW_FALLBACK_NONE ||
            r->rule_reusable != 0)
            return false;
    }
    const struct zcl_shadow_result *c = ss_row(n, "syn-contract");
    return c && c->rule_reusable == 0 &&
           c->patch.contract_change == ZCL_SHADOW_CONTRACT_MOVED;
}

static bool ss_evaluate_all(size_t *count)
{
    struct zcl_shadow_weights w = {0};
    if (!ss_load_weights(&w)) return false;
    struct zcl_shadow_eval_ctx ctx = {
        ".", SS_FIXTURE_DIR, &w, zcl_shadow_validation_ns_per_obligation()};
    bool ok = ctx.validation_ns > 0;
    *count = 0;
    for (size_t i = 0; ok && i < ss_corpus.count; i++) {
        char why[160] = "";
        ok = zcl_shadow_evaluate(&ctx, &ss_corpus.entries[i], &ss_rows[i],
                                 why, sizeof(why));
        if (!ok) printf("evaluate %s: %s\n", ss_corpus.entries[i].id, why);
        ok = ok && zcl_shadow_render_entry(stdout, &ss_rows[i]);
        *count += ok ? 1u : 0u;
    }
    ok = ok && zcl_shadow_render_totals(stdout, ss_rows, *count);
    zcl_shadow_weights_free(&w);
    return ok;
}

static int ss_test_live_report(void)
{
    int failures = 0;
    TEST("shadow select: report every corpus entry against the live selector") {
        ASSERT(ss_load_corpus());
        size_t n = 0;
        printf("\n");
        ASSERT(ss_evaluate_all(&n));
        ASSERT_EQ(n, ss_corpus.count);
        for (size_t i = 0; i < n; i++) {
            if (!ss_row_consistent(&ss_rows[i]))
                printf("inconsistent row %s\n", ss_rows[i].id);
            ASSERT(ss_row_consistent(&ss_rows[i]));
        }
        ASSERT(ss_witness_guarded(n));
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_shadow_select(void)
{
    int failures = 0;
    failures += ss_test_corpus_frozen();
    failures += ss_test_weights();
    failures += ss_test_synthetic_facts();
    failures += ss_test_contract_tokens();
    failures += ss_test_reuse_rule();
    failures += ss_test_unchanged_abi_is_not_enough();
    failures += ss_test_classifier();
    failures += ss_test_corpus_refusals();
    failures += ss_test_live_report();
    return failures;
}
