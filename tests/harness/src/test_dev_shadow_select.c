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
        ASSERT(ss_patch_facts("syn-macro", &p, &sha) && sha);
        ASSERT(p.contract_change == ZCL_SHADOW_CONTRACT_MOVED);
        ASSERT(p.contract_hunks == 1);
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
        f.plan_refused = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE);
        f.plan_refused = false;
        f.contract_moved = true;
        ASSERT(zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE);
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

static bool ss_row_costs_consistent(const struct zcl_shadow_result *r)
{
    bool fallback = r->predict_mode == ZCL_SHADOW_PREDICT_ALL;
    return r->fresh_cost_ms <= r->reference_cost_ms &&
           r->rule_cost_ms <= r->reference_cost_ms &&
           (fallback || r->rule_cost_ms <= r->fresh_cost_ms) &&
           (!fallback || r->predicted_groups == r->groups_reference) &&
           fallback == (r->fallback != ZCL_SHADOW_FALLBACK_NONE ||
                        r->selector_universal) &&
           r->lint_cost_ms <= r->rule_cost_ms &&
           r->critical_rule_ms <= r->critical_reference_ms;
}

static bool ss_row_graph_consistent(const struct zcl_shadow_result *r)
{
    const struct zcl_shadow_proof_graph *g = &r->graph;
    uint32_t layered = g->nodes[ZCL_SHADOW_LAYER_CONTRACT] +
                       g->nodes[ZCL_SHADOW_LAYER_CALLER] +
                       g->nodes[ZCL_SHADOW_LAYER_INTEGRATION];
    return layered == r->groups_selected &&
           g->collision_groups <= r->groups_selected &&
           r->build_invalidated <= r->build_total &&
           r->edges_selected <= r->groups_selected &&
           r->premise_groups <= r->groups_reference;
}

/* The class split adds up to the rule's bill, an ALL prediction is all
 * fallback, and the lint premise variant differs from the rule only in how
 * lint gates are priced: every corpus entry carries rows for exactly the
 * SS_LINT_PREMISE_GATES gates that declare a premise in
 * tools/lint/lintc/selection_gates.def. */
enum { SS_LINT_PREMISE_GATES = 7 };

static bool ss_row_classes_consistent(const struct zcl_shadow_result *r)
{
    uint64_t ms = 0;
    uint32_t n = 0;
    for (unsigned c = 0; c < ZCL_SHADOW_CLASS__COUNT; c++) {
        ms += r->class_ms[c];
        n += r->class_n[c];
    }
    bool all = r->predict_mode == ZCL_SHADOW_PREDICT_ALL;
    return ms == r->rule_cost_ms &&
           n == r->predicted_groups + r->lint_selected &&
           r->class_ms[ZCL_SHADOW_CLASS_LINT] == r->lint_cost_ms &&
           (!all || r->class_n[ZCL_SHADOW_CLASS_FALLBACK] ==
                        r->predicted_groups) &&
           (all || r->class_n[ZCL_SHADOW_CLASS_FALLBACK] == 0) &&
           r->lint_premise_gates == SS_LINT_PREMISE_GATES &&
           r->lint_units_fresh <= r->lint_units_total &&
           r->premise_rule_cost_ms ==
               r->rule_cost_ms - r->lint_cost_ms + r->lint_premise_ms;
}

/* eligible_groups == 0 is the fail-closed guard: the only prior verdicts a
 * host offers are its own uid's, and those never stand in for a run. */
static bool ss_row_consistent(const struct zcl_shadow_result *r)
{
    return r->bytes_verified && r->groups_reference > 0 &&
           ss_row_classes_consistent(r) &&
           r->lint_reference == 213 && r->lint_selected == r->lint_reference &&
           r->eligible_groups == 0 &&
           r->eligible_cost_ms == r->reference_cost_ms &&
           r->carried_groups + r->predicted_groups >= r->groups_reference &&
           (unsigned)r->fallback < ZCL_SHADOW_FALLBACK__COUNT &&
           ss_row_costs_consistent(r) && ss_row_graph_consistent(r);
}

static const struct zcl_shadow_result *ss_row(size_t n, const char *id)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(ss_rows[i].id, id) == 0) return &ss_rows[i];
    return NULL;
}

/* Regressions for the false-hit witnesses in
 * docs/experiments/2026-09-25-shadow-obligation-selector.md: a changed
 * build graph, generator input or shadowing header must expand the
 * prediction to the reference, and so must a moved contract (declaration,
 * layout, macro, assertion): syn-contract showed the caller closure missing
 * test_zcode_recipe behind a proof-owner file. */
static bool ss_witness_guarded(size_t n)
{
    static const char *const expand[] = {
        "syn-flag", "syn-generated-input", "syn-negative-lookup",
    };
    static const char *const moved[] = {
        "syn-contract", "syn-header-decl", "syn-abi", "syn-macro",
    };
    for (size_t i = 0; i < sizeof(expand) / sizeof(expand[0]); i++) {
        const struct zcl_shadow_result *r = ss_row(n, expand[i]);
        if (!r || r->fallback == ZCL_SHADOW_FALLBACK_NONE ||
            r->predict_mode != ZCL_SHADOW_PREDICT_ALL || r->rule_reusable != 0)
            return false;
    }
    for (size_t i = 0; i < sizeof(moved) / sizeof(moved[0]); i++) {
        const struct zcl_shadow_result *r = ss_row(n, moved[i]);
        if (!r || r->rule_reusable != 0 ||
            r->predict_mode != ZCL_SHADOW_PREDICT_ALL ||
            r->patch.contract_change != ZCL_SHADOW_CONTRACT_MOVED)
            return false;
    }
    /* The created header flips the premise path set, so the lint premise
     * selection inherits no unit of any declared gate. */
    const struct zcl_shadow_result *neg = ss_row(n, "syn-negative-lookup");
    return neg && neg->lint_units_total > 0 &&
           neg->lint_units_fresh == neg->lint_units_total;
}

static bool ss_load_lint_premises(struct zcl_shadow_lint_premises *p)
{
    size_t len = 0;
    char why[128] = "";
    char *text = ss_slurp(SS_FIXTURE_DIR "/lint_premise.tsv", &len);
    bool ok = text && zcl_shadow_lint_premises_parse(text, len, p, why,
                                                     sizeof(why));
    if (!ok) printf("lint premises: %s\n", text ? why : "lint_premise.tsv absent");
    free(text);
    return ok;
}

/* Real entries feed the top-obligation tally; synthetic ones do not. */
static bool ss_evaluate_rows(struct zcl_shadow_eval_ctx *ctx,
                             struct zcl_shadow_tally *tally, size_t *count)
{
    bool ok = ctx->validation_ns > 0;
    *count = 0;
    for (size_t i = 0; ok && i < ss_corpus.count; i++) {
        char why[160] = "";
        bool real = ss_corpus.entries[i].kind == ZCL_SHADOW_KIND_REAL;
        ctx->tally = real ? tally : NULL;
        ok = zcl_shadow_evaluate(ctx, &ss_corpus.entries[i], &ss_rows[i],
                                 why, sizeof(why));
        if (!ok) printf("evaluate %s: %s\n", ss_corpus.entries[i].id, why);
        ok = ok && zcl_shadow_render_entry(stdout, &ss_rows[i]);
        *count += ok ? 1u : 0u;
    }
    return ok;
}

static bool ss_evaluate_all(size_t *count)
{
    struct zcl_shadow_weights w = {0};
    struct zcl_shadow_lint_premises lp = {0};
    struct zcl_shadow_tally tally = {0};
    *count = 0;
    bool ok = ss_load_weights(&w) && ss_load_lint_premises(&lp) &&
              zcl_shadow_tally_init(&tally, &w);
    struct zcl_shadow_eval_ctx ctx = {
        ".", SS_FIXTURE_DIR, &w, ok ? zcl_shadow_validation_ns_per_obligation()
                                    : 0,
        &lp, NULL};
    ok = ok && ss_evaluate_rows(&ctx, &tally, count);
    ok = ok && zcl_shadow_render_totals(stdout, ss_rows, *count) &&
         zcl_shadow_render_top(stdout, &tally, 15);
    zcl_shadow_tally_free(&tally);
    zcl_shadow_lint_premises_free(&lp);
    zcl_shadow_weights_free(&w);
    return ok;
}

/* The live prediction rows, in the exact predicted.tsv format, so the frozen
 * file can be regenerated from this output and compared with it. */
static bool ss_print_predictions(size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (fputs("SHADOW-PREDICT\t", stdout) < 0 ||
            !zcl_shadow_render_prediction(stdout, &ss_rows[i]))
            return false;
    }
    return true;
}

static bool ss_load_predictions(struct zcl_shadow_predictions *p)
{
    size_t len = 0;
    char why[128] = "";
    char *text = ss_slurp(SS_FIXTURE_DIR "/predicted.tsv", &len);
    bool ok = text && zcl_shadow_predictions_parse(text, len, p, why,
                                                   sizeof(why));
    if (!ok) printf("predictions: %s\n", text ? why : "predicted.tsv absent");
    if (ok) {
        uint8_t digest[32];
        char hex[65];
        zcl_sha3_256((const uint8_t *)text, len, digest);
        for (size_t i = 0; i < 32; i++)
            (void)snprintf(hex + 2 * i, 3, "%02x", digest[i]);
        printf("SHADOW-PREDICT-FILE rows=%zu sha3=%s\n", p->count, hex);
    }
    free(text);
    return ok;
}

static bool ss_load_observations(struct zcl_shadow_observations *o)
{
    size_t len = 0;
    char why[128] = "";
    char *text = ss_slurp(SS_FIXTURE_DIR "/observed.tsv", &len);
    bool ok = text && zcl_shadow_observations_parse(text, len, o, why,
                                                    sizeof(why));
    if (!ok) printf("observations: %s\n", text ? why : "observed.tsv absent");
    free(text);
    return ok;
}

/* Frozen prediction against the reference run: any required obligation the
 * rule prediction did not name is RED. The live prediction is held to the
 * same observations, so a selector change that drops a witness fails here. */
/* RED tallies. `frozen_*` compare the committed predicted.tsv (written
 * before any reference run) with observed.tsv, so they never move; `live_*`
 * hold today's code to the same observations. */
struct ss_red {
    uint32_t frozen_rule;
    uint32_t frozen_selector;
    uint32_t live_rule;
    uint32_t live_selector;
    char frozen_rule_first[ZCL_SHADOW_ID_MAX + ZCL_SHADOW_NAME_MAX + 2];
};

static void ss_live_prediction(const struct zcl_shadow_result *live,
                               struct zcl_shadow_prediction *now)
{
    memset(now, 0, sizeof(*now));
    (void)snprintf(now->id, sizeof(now->id), "%s", live->id);
    now->selector_mode = live->selector_universal ? ZCL_SHADOW_PREDICT_ALL
                                                  : ZCL_SHADOW_PREDICT_EXACT;
    now->rule_mode = live->predict_mode;
    (void)snprintf(now->selector_names, sizeof(now->selector_names), "%s",
                   live->selected_names);
    (void)snprintf(now->rule_names, sizeof(now->rule_names), "%s",
                   live->predicted_names);
}

static bool ss_compare_one(const struct zcl_shadow_prediction *frozen,
                           const struct zcl_shadow_result *live,
                           const struct zcl_shadow_observations *obs,
                           struct ss_red *red)
{
    struct zcl_shadow_comparison c;
    if (!zcl_shadow_compare(frozen, obs, &c) ||
        !zcl_shadow_render_comparison(stdout, frozen->id, &c))
        return false;
    if (c.red_rule && red->frozen_rule == 0)
        (void)snprintf(red->frozen_rule_first,
                       sizeof(red->frozen_rule_first), "%s:%s", frozen->id,
                       c.first_red_rule);
    red->frozen_rule += c.red_rule;
    red->frozen_selector += c.red_selector;
    static struct zcl_shadow_prediction now;
    ss_live_prediction(live, &now);
    if (now.rule_mode != frozen->rule_mode ||
        strcmp(now.rule_names, frozen->rule_names) != 0)
        printf("SHADOW-PREDICT-DRIFT id=%s rule_mode=%s\n", live->id,
               now.rule_mode == ZCL_SHADOW_PREDICT_ALL ? "all" : "exact");
    if (!zcl_shadow_compare(&now, obs, &c)) return false;
    printf("SHADOW-LIVE-COMPARE id=%s required=%u red_selector=%u "
           "red_rule=%u first_red_selector=%s first_red_rule=%s\n",
           live->id, c.required, c.red_selector, c.red_rule,
           c.first_red_selector[0] ? c.first_red_selector : "-",
           c.first_red_rule[0] ? c.first_red_rule : "-");
    red->live_rule += c.red_rule;
    red->live_selector += c.red_selector;
    return true;
}

static bool ss_compare_all(size_t n, struct ss_red *red)
{
    struct zcl_shadow_predictions p = {0};
    struct zcl_shadow_observations o = {0};
    bool ok = ss_load_predictions(&p) && ss_load_observations(&o);
    memset(red, 0, sizeof(*red));
    for (size_t i = 0; ok && i < n; i++) {
        const struct zcl_shadow_prediction *frozen =
            zcl_shadow_prediction_find(&p, ss_rows[i].id);
        if (!frozen) printf("prediction missing for %s\n", ss_rows[i].id);
        ok = frozen && ss_compare_one(frozen, &ss_rows[i], &o, red);
    }
    printf("SHADOW-RED frozen_rule=%u frozen_selector=%u live_rule=%u "
           "live_selector=%u frozen_rule_first=%s\n",
           red->frozen_rule, red->frozen_selector, red->live_rule,
           red->live_selector,
           red->frozen_rule_first[0] ? red->frozen_rule_first : "-");
    zcl_shadow_predictions_free(&p);
    zcl_shadow_observations_free(&o);
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
        ASSERT(ss_print_predictions(n));
        struct ss_red red;
        ASSERT(ss_compare_all(n, &red));
        /* Today's prediction misses no required obligation. */
        ASSERT_EQ(red.live_rule, (uint32_t)0);
        /* The frozen record keeps its one RED: a moved contract predicted
         * as the selector's own set missed test_zcode_recipe, whose
         * decoder reaches the callee through a proof-owner file the caller
         * closure stops at. The landing selector missed five. */
        ASSERT_EQ(red.frozen_rule, (uint32_t)1);
        ASSERT_STR_EQ(red.frozen_rule_first,
                      "syn-contract:test_zcode_recipe");
        ASSERT_EQ(red.frozen_selector, (uint32_t)5);
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_compare(void)
{
    int failures = 0;
    TEST("shadow select: a required obligation outside a prediction is RED") {
        ASSERT(zcl_shadow_names_contain("test_a,test_ab", "test_ab"));
        ASSERT(zcl_shadow_names_contain("test_a,test_ab", "test_a"));
        ASSERT(!zcl_shadow_names_contain("test_ab,test_abc", "test_a"));
        ASSERT(!zcl_shadow_names_contain("", "test_a"));
        struct zcl_shadow_observation o = {"x", "test_a",
                                           ZCL_SHADOW_VERDICT_PASS,
                                           ZCL_SHADOW_VERDICT_PASS};
        ASSERT(!zcl_shadow_obligation_required(&o));
        o.patched = ZCL_SHADOW_VERDICT_FAIL;
        ASSERT(zcl_shadow_obligation_required(&o));
        o.base = ZCL_SHADOW_VERDICT_FAIL;
        o.patched = ZCL_SHADOW_VERDICT_PASS;
        ASSERT(zcl_shadow_obligation_required(&o));
        o.patched = ZCL_SHADOW_VERDICT_NOT_RUN;
        ASSERT(!zcl_shadow_obligation_required(&o));

        const char *obs_text =
            "# id group base patched evidence\n"
            "x\ttest_a\tpass\tfail\tlog-a\n"
            "x\ttest_b\tpass\tpass\tlog-b\n"
            "y\ttest_a\tpass\tfail\tlog-c\n";
        struct zcl_shadow_observations obs = {0};
        char why[96];
        ASSERT(zcl_shadow_observations_parse(obs_text, strlen(obs_text), &obs,
                                             why, sizeof(why)));
        ASSERT_EQ(obs.count, (size_t)3);
        static struct zcl_shadow_predictions p;
        const char *pred_text = "x\texact\ttest_b\tall\t-\n"
                                "y\tall\t-\texact\ttest_b,test_c\n";
        ASSERT(zcl_shadow_predictions_parse(pred_text, strlen(pred_text), &p,
                                            why, sizeof(why)));
        struct zcl_shadow_comparison c;
        ASSERT(zcl_shadow_compare(zcl_shadow_prediction_find(&p, "x"), &obs,
                                  &c));
        ASSERT(c.observed == 2 && c.required == 1);
        ASSERT(c.red_selector == 1 && c.red_rule == 0);
        ASSERT_STR_EQ(c.first_red_selector, "test_a");
        ASSERT(zcl_shadow_compare(zcl_shadow_prediction_find(&p, "y"), &obs,
                                  &c));
        ASSERT(c.red_selector == 0 && c.red_rule == 1);
        zcl_shadow_predictions_free(&p);
        zcl_shadow_observations_free(&obs);
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_compare_refusals(void)
{
    int failures = 0;
    TEST("shadow select: predictions and observations are refused, never repaired") {
        static struct zcl_shadow_predictions p;
        struct zcl_shadow_observations o = {0};
        char why[96];
        static const char *const bad_predictions[] = {
            "x\tall\ttest_a\texact\t-\n",         /* all carries a list */
            "x\tsome\t-\texact\t-\n",             /* unknown mode */
            "x\texact\ttest_a,...\texact\t-\n",   /* truncated list */
            "x\texact\t-\texact\t-\nx\texact\t-\texact\t-\n", /* duplicate */
            "x\texact\t-\texact\n",               /* short row */
        };
        for (size_t i = 0; i < sizeof(bad_predictions) / sizeof(char *); i++)
            ASSERT(!zcl_shadow_predictions_parse(bad_predictions[i],
                                                 strlen(bad_predictions[i]),
                                                 &p, why, sizeof(why)));
        static const char *const bad_observations[] = {
            "x\ttest_a\tpass\tmaybe\tlog\n",
            "x\ttest_a\tpass\tfail\tlog\nx\ttest_a\tpass\tpass\tlog\n",
            "x\ttest_a\tpass\tfail\n",
        };
        for (size_t i = 0; i < sizeof(bad_observations) / sizeof(char *); i++)
            ASSERT(!zcl_shadow_observations_parse(bad_observations[i],
                                                  strlen(bad_observations[i]),
                                                  &o, why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_eligibility(void)
{
    int failures = 0;
    TEST("shadow select: reuse needs image sensitivity, the rule, a full key and an independent verdict") {
        struct zcl_shadow_eligibility_claim c = {
            .sensitivity = ZCL_SHADOW_SENSITIVITY_IMAGE,
            .source_changed = false,
            .rule = ZCL_SHADOW_REUSE_ADMIT,
            .missing_key_fields = 0,
            .inputs_match = true,
            .source = ZCL_SHADOW_SOURCE_SIGNED_INDEPENDENT,
        };
        ASSERT(zcl_shadow_reuse_eligible(&c) == ZCL_SHADOW_ELIGIBLE);
        struct zcl_shadow_eligibility_claim x = c;
        x.sensitivity = ZCL_SHADOW_SENSITIVITY_SOURCE;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_SOURCE_SENSITIVE);
        x = c;
        x.source_changed = true;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_SOURCE_SENSITIVE);
        x = c;
        x.rule = ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL;
        ASSERT(zcl_shadow_reuse_eligible(&x) == ZCL_SHADOW_INELIGIBLE_RULE);
        x = c;
        x.missing_key_fields = 1u << ZCL_SHADOW_FIELD_UNIT_ID;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_INPUTS_INCOMPLETE);
        x = c;
        x.inputs_match = false;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_INPUTS_DIFFER);
        x = c;
        x.source = ZCL_SHADOW_SOURCE_LOCAL_SAME_UID;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_SAME_UID);
        x.source = ZCL_SHADOW_SOURCE_LOCAL_OTHER_UID;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_NOT_INDEPENDENT);
        x.source = ZCL_SHADOW_SOURCE_NONE;
        ASSERT(zcl_shadow_reuse_eligible(&x) ==
               ZCL_SHADOW_INELIGIBLE_NO_VERDICT);
        ASSERT(zcl_shadow_reuse_eligible(NULL) != ZCL_SHADOW_ELIGIBLE);
        /* A lint gate is source-sensitive whatever else holds. */
        ASSERT(zcl_shadow_obligation_sensitivity(
                   ZCL_SHADOW_OBLIGATION_LINT_GATE) ==
               ZCL_SHADOW_SENSITIVITY_SOURCE);
        ASSERT(zcl_shadow_obligation_sensitivity(
                   ZCL_SHADOW_OBLIGATION_TEST_GROUP) ==
               ZCL_SHADOW_SENSITIVITY_IMAGE);
        PASS();
    } _test_next:;
    return failures;
}

static int ss_test_lint_premise(void)
{
    int failures = 0;
    TEST("shadow select: lint premise rows are refused, never repaired, and price only fresh units") {
        static struct zcl_shadow_lint_premises p;
        char why[96];
        static const char *const bad[] = {
            "x\tg\t10\t11\tenabled\t5\t0\n",        /* more fresh than units */
            "x\tg\t0\t0\tenabled\t5\t0\n",          /* no units */
            "x\tg\t10\t1\tmaybe\t5\t0\n",           /* unknown selection */
            "x\tg\t10\t1\tenabled\t5\n",            /* short row */
            "x\tg\t10\t1\tenabled\t5\t0\nx\tg\t10\t1\tenabled\t5\t0\n",
            "x\tg\t10\t-1\tenabled\t5\t0\n",        /* not a count */
            "x\tg\t10\t1\tenabled\t5\t0\t0\n",      /* long row */
            "x\tg\t10\t1\tenabled\t5\tall\n",       /* always part not a count */
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
            ASSERT(!zcl_shadow_lint_premises_parse(bad[i], strlen(bad[i]), &p,
                                                   why, sizeof(why)));
        const char *good = "# c\nx\tg\t1000\t2\tenabled\t7000\t0\n"
                           "x\th\t1000\t0\tdisabled\t7000\t0\n"
                           "x\tk\t10\t10\tenabled\t7000\t0\n"
                           "x\ta\t72\t4\tenabled\t9000\t18000\n";
        ASSERT(zcl_shadow_lint_premises_parse(good, strlen(good), &p, why,
                                              sizeof(why)));
        ASSERT_EQ(p.count, (size_t)4);
        bool priced = true;
        /* No row, or selection disabled: the whole gate. */
        ASSERT_EQ(zcl_shadow_lint_gate_ms(NULL, 120000, &priced),
                  (uint64_t)120000);
        ASSERT(!priced);
        ASSERT_EQ(zcl_shadow_lint_gate_ms(zcl_shadow_lint_premise_find(
                                              &p, "x", "h"),
                                          120000, &priced),
                  (uint64_t)120000);
        ASSERT(!priced);
        ASSERT(!zcl_shadow_lint_premise_find(&p, "y", "g"));
        /* Enabled: the select run plus each fresh unit at the floor. */
        const struct zcl_shadow_lint_premise *g =
            zcl_shadow_lint_premise_find(&p, "x", "g");
        ASSERT_EQ(zcl_shadow_lint_gate_ms(g, 120000, &priced),
                  (uint64_t)(7000 + 2 * ZCL_SHADOW_LINT_UNIT_FLOOR_MS));
        ASSERT(priced);
        /* A heavy gate's mean share outranks the floor. */
        ASSERT_EQ(zcl_shadow_lint_gate_ms(g, 5000000, &priced),
                  (uint64_t)(7000 + 2 * 5000));
        /* Every unit fresh: the select run was paid, then the whole gate
         * runs, never ten single-unit charges above its weight. */
        ASSERT_EQ(zcl_shadow_lint_gate_ms(zcl_shadow_lint_premise_find(
                                              &p, "x", "k"),
                                          3000, &priced),
                  (uint64_t)(7000 + 3000));
        ASSERT(priced);
        /* An always-run part is paid whole, and only the rest of the
         * weight is shared among the units: ceil(97700 / 72) = 1357. */
        const struct zcl_shadow_lint_premise *a =
            zcl_shadow_lint_premise_find(&p, "x", "a");
        ASSERT_EQ(zcl_shadow_lint_gate_ms(a, 115700, &priced),
                  (uint64_t)(9000 + 18000 + 4 * 1357));
        ASSERT(priced);
        /* The always-run part never exceeds the gate: select plus gate. */
        ASSERT_EQ(zcl_shadow_lint_gate_ms(a, 10000, &priced),
                  (uint64_t)(9000 + 10000));
        zcl_shadow_lint_premises_free(&p);
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_shadow_select(void)
{
    int failures = 0;
    failures += ss_test_lint_premise();
    failures += ss_test_corpus_frozen();
    failures += ss_test_weights();
    failures += ss_test_synthetic_facts();
    failures += ss_test_contract_tokens();
    failures += ss_test_reuse_rule();
    failures += ss_test_unchanged_abi_is_not_enough();
    failures += ss_test_classifier();
    failures += ss_test_corpus_refusals();
    failures += ss_test_compare();
    failures += ss_test_compare_refusals();
    failures += ss_test_eligibility();
    failures += ss_test_live_report();
    return failures;
}
