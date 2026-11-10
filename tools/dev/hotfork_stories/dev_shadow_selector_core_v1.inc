/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: HOT_FORK story adapter dev-shadow-selector-core.v1 for the
 * shadow selector core: tools/dev/dev_shadow_rule.c with its sibling TUs
 * dev_shadow_corpus.c, dev_shadow_lint.c, dev_shadow_render.c and
 * dev_shadow_compare.c. Compiled only inside the capsule unity rendered by
 * tools/dev/hotfork_unity.h: phase 1 precedes the owner TU set, phase 2
 * follows it. check-hotfork-stories compiles every unity with the frozen
 * dev flags, so an owner API change cannot silently disable this story.
 *
 * The known answers are the frozen ones of
 * tests/harness/src/test_dev_shadow_select.c, restated over caller-owned
 * text and heap buffers only: no fixture file, no clock, no process, no
 * index. dev_shadow_eval.c and dev_shadow_graph.c read the code index and
 * spawn processes, so they stay outside the capsule and outside the story.
 */
#if !defined(ZCL_HOTFORK_STORY_PHASE)
#error "HOT_FORK stories are included only by the generated capsule unity"
#elif ZCL_HOTFORK_STORY_PHASE == 1
#define _GNU_SOURCE
#include "hotswap/hotfork_capsule.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#elif ZCL_HOTFORK_STORY_PHASE == 2
/* The capsule links without --no-undefined and is mapped RTLD_LAZY, so a
 * core function the candidate no longer defines (removed or renamed while
 * the header still declares it) silently binds to the RESIDENT binary's
 * old copy, and every check below would observe stale bytes. Each core
 * entry point the story exercises must live in the same object as the
 * story itself; anything else is a refusal, never a green. */
static bool hf_shadow_home(const void *fn, const Dl_info *story)
{
    Dl_info info;
    return fn && dladdr(fn, &info) != 0 && info.dli_fbase == story->dli_fbase;
}

#define HF_SHADOW_HOME(fn) \
    do { \
        typeof(&(fn)) f_ = &(fn); \
        const void *p_ = NULL; \
        static_assert(sizeof(f_) == sizeof(p_), "code pointer width"); \
        memcpy(&p_, &f_, sizeof(p_)); \
        home = home && hf_shadow_home(p_, &story); \
    } while (0)

static bool hf_shadow_home_rule(const Dl_info *story_info)
{
    Dl_info story = *story_info;
    bool home = true;
    HF_SHADOW_HOME(zcl_shadow_classify);
    HF_SHADOW_HOME(zcl_shadow_fallback_name);
    HF_SHADOW_HOME(zcl_shadow_reuse_admit);
    HF_SHADOW_HOME(zcl_shadow_reuse_name);
    HF_SHADOW_HOME(zcl_shadow_reuse_eligible);
    HF_SHADOW_HOME(zcl_shadow_obligation_sensitivity);
    HF_SHADOW_HOME(zcl_shadow_kind_parse);
    HF_SHADOW_HOME(zcl_shadow_kind_name);
    HF_SHADOW_HOME(zcl_shadow_eligibility_name);
    HF_SHADOW_HOME(zcl_shadow_field_name);
    HF_SHADOW_HOME(zcl_shadow_component_input_key_gaps);
    HF_SHADOW_HOME(zcl_shadow_path_is_contract);
    HF_SHADOW_HOME(zcl_shadow_path_is_generator_input);
    HF_SHADOW_HOME(zcl_shadow_path_is_build_graph);
    return home;
}

static bool hf_shadow_home_siblings(const Dl_info *story_info)
{
    Dl_info story = *story_info;
    bool home = true;
    HF_SHADOW_HOME(zcl_shadow_patch_analyze);
    HF_SHADOW_HOME(zcl_shadow_corpus_parse);
    HF_SHADOW_HOME(zcl_shadow_weights_parse);
    HF_SHADOW_HOME(zcl_shadow_weights_free);
    HF_SHADOW_HOME(zcl_shadow_lint_premises_parse);
    HF_SHADOW_HOME(zcl_shadow_lint_premises_free);
    HF_SHADOW_HOME(zcl_shadow_lint_premise_find);
    HF_SHADOW_HOME(zcl_shadow_lint_gate_ms);
    HF_SHADOW_HOME(zcl_shadow_class_name);
    HF_SHADOW_HOME(zcl_shadow_names_contain);
    HF_SHADOW_HOME(zcl_shadow_obligation_required);
    HF_SHADOW_HOME(zcl_shadow_observations_parse);
    HF_SHADOW_HOME(zcl_shadow_observations_free);
    HF_SHADOW_HOME(zcl_shadow_predictions_parse);
    HF_SHADOW_HOME(zcl_shadow_predictions_free);
    HF_SHADOW_HOME(zcl_shadow_prediction_find);
    HF_SHADOW_HOME(zcl_shadow_compare);
    HF_SHADOW_HOME(zcl_shadow_render_comparison);
    HF_SHADOW_HOME(zcl_shadow_render_entry);
    return home;
}
#undef HF_SHADOW_HOME

static bool hf_shadow_bound_in_capsule(void)
{
    Dl_info story;
    bool (*self)(void) = hf_shadow_bound_in_capsule;
    const void *p = NULL;
    memcpy(&p, &self, sizeof(p));
    return dladdr(p, &story) != 0 && story.dli_fbase &&
           hf_shadow_home_rule(&story) && hf_shadow_home_siblings(&story);
}


/* Fallback precedence: conflict, policy, dependency, scope. */
static bool hf_shadow_classify(void)
{
    struct zcl_shadow_scope_facts f = {0};
    bool ok = zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_NONE;
    f.closure_universal = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE;
    f.closure_universal = false;
    f.plan_refused = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE;
    f.plan_refused = false;
    f.contract_moved = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE;
    f.negative_lookup = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE;
    f.generated_input = true;
    ok = ok &&
         zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE;
    f.generated_input = false;
    f.build_graph_input = true;
    ok = ok &&
         zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE;
    f.consensus_policy = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_POLICY;
    f.bytes_mismatch = true;
    ok = ok && zcl_shadow_classify(&f) == ZCL_SHADOW_FALLBACK_CONFLICT;
    return ok && zcl_shadow_classify(NULL) == ZCL_SHADOW_FALLBACK_CONFLICT &&
           strcmp(zcl_shadow_fallback_name(
                      ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE),
                  "dependency-change") == 0;
}

static void hf_shadow_claim(struct zcl_shadow_reuse_claim *c,
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

/* The compositional reuse rule admits one shape and names every other. */
static bool hf_shadow_reuse(void)
{
    static const enum zcl_shadow_premise contract[] = {
        ZCL_SHADOW_PREMISE_CONTRACT, ZCL_SHADOW_PREMISE_CONTRACT};
    static const enum zcl_shadow_premise layout[] = {
        ZCL_SHADOW_PREMISE_PRIVATE_LAYOUT};
    struct zcl_shadow_reuse_claim c;
    hf_shadow_claim(&c, contract, 2);
    bool ok = zcl_shadow_reuse_admit(&c) == ZCL_SHADOW_REUSE_ADMIT;
    c.contract_after[31] ^= 1;
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED;
    hf_shadow_claim(&c, contract, 2);
    c.contract_basis = ZCL_SHADOW_BASIS_REUSED;
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED;
    hf_shadow_claim(&c, contract, 2);
    c.contract_obligations = 0;
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED;
    hf_shadow_claim(&c, contract, 2);
    c.contract_verdict = ZCL_SHADOW_VERDICT_FAIL;
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_CONTRACT_FAILED;
    hf_shadow_claim(&c, contract, 2);
    c.contract_run_impl[0] ^= 1;
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL;
    hf_shadow_claim(&c, layout, 1);
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE;
    hf_shadow_claim(&c, contract, 0);
    ok = ok && zcl_shadow_reuse_admit(&c) ==
                   ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE;
    hf_shadow_claim(&c, NULL, 2);
    ok = ok && zcl_shadow_reuse_admit(&c) == ZCL_SHADOW_REUSE_REFUSE_MALFORMED;
    return ok && zcl_shadow_reuse_admit(NULL) ==
                     ZCL_SHADOW_REUSE_REFUSE_MALFORMED &&
           strcmp(zcl_shadow_reuse_name(
                      ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL),
                  "contract_ran_on_other_implementation") == 0;
}

static bool hf_shadow_paths(void)
{
    return zcl_shadow_path_is_contract("platform/modules/codec", "platform/modules/codec/include/codec/cursor.h") &&
        zcl_shadow_path_is_contract("platform/modules/codec", "tests/harness/src/test_codec_cursor.c") &&
        !zcl_shadow_path_is_contract("platform/modules/codec", "platform/modules/codec/src/cursor.c") &&
        zcl_shadow_path_is_generator_input("contexts/explorer/views/src/site.css") &&
        zcl_shadow_path_is_build_graph("tools/build/rules.mk") &&
        !zcl_shadow_path_is_build_graph("Makefile.am");
}
/* Reuse eligibility, obligation sensitivity, names and path predicates. */
static bool hf_shadow_eligibility(void)
{
    struct zcl_shadow_eligibility_claim c = {
        .sensitivity = ZCL_SHADOW_SENSITIVITY_IMAGE,
        .rule = ZCL_SHADOW_REUSE_ADMIT,
        .inputs_match = true,
        .source = ZCL_SHADOW_SOURCE_SIGNED_INDEPENDENT,
    };
    bool ok = zcl_shadow_reuse_eligible(&c) == ZCL_SHADOW_ELIGIBLE;
    struct zcl_shadow_eligibility_claim x = c;
    x.source_changed = true;
    ok = ok && zcl_shadow_reuse_eligible(&x) ==
                   ZCL_SHADOW_INELIGIBLE_SOURCE_SENSITIVE;
    x = c;
    x.missing_key_fields = 1u << ZCL_SHADOW_FIELD_UNIT_ID;
    ok = ok && zcl_shadow_reuse_eligible(&x) ==
                   ZCL_SHADOW_INELIGIBLE_INPUTS_INCOMPLETE;
    x = c;
    x.source = ZCL_SHADOW_SOURCE_LOCAL_SAME_UID;
    ok = ok && zcl_shadow_reuse_eligible(&x) == ZCL_SHADOW_INELIGIBLE_SAME_UID;
    x.source = ZCL_SHADOW_SOURCE_NONE;
    ok = ok &&
         zcl_shadow_reuse_eligible(&x) == ZCL_SHADOW_INELIGIBLE_NO_VERDICT &&
         zcl_shadow_reuse_eligible(NULL) != ZCL_SHADOW_ELIGIBLE;
    ok = ok &&
         zcl_shadow_obligation_sensitivity(ZCL_SHADOW_OBLIGATION_LINT_GATE) ==
             ZCL_SHADOW_SENSITIVITY_SOURCE &&
         zcl_shadow_obligation_sensitivity(ZCL_SHADOW_OBLIGATION_TEST_GROUP) ==
             ZCL_SHADOW_SENSITIVITY_IMAGE;
    enum zcl_shadow_kind kind = ZCL_SHADOW_KIND_REAL;
    ok = ok && zcl_shadow_kind_parse("macro", &kind) &&
         strcmp(zcl_shadow_kind_name(kind), "macro") == 0 &&
         !zcl_shadow_kind_parse("bogus", &kind) &&
         strcmp(zcl_shadow_eligibility_name(ZCL_SHADOW_INELIGIBLE_SAME_UID),
                "same_uid_local_verdict") == 0 &&
         strcmp(zcl_shadow_field_name(ZCL_SHADOW_FIELD_UNIT_ID), "unit_id") ==
             0 &&
         __builtin_popcount(zcl_shadow_component_input_key_gaps()) == 8;
    return ok && hf_shadow_paths();
}

static bool hf_shadow_analyze(const char *patch,
                              struct zcl_shadow_patch_facts *p)
{
    char why[64];
    return zcl_shadow_patch_analyze("platform/modules/codec",
                                    (const uint8_t *)patch, strlen(patch), p,
                                    why, sizeof(why));
}

static bool hf_shadow_corpus_row(struct zcl_shadow_corpus *c,
                                 const char *kind, const char *commit,
                                 const char *files)
{
    static const char sha[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char row[512], why[64];
    int n = snprintf(row, sizeof(row), "a\t%s\tx\t%s\t%s\t%s\n", kind,
                     commit, sha, files);
    return n > 0 && (size_t)n < sizeof(row) &&
           zcl_shadow_corpus_parse(row, (size_t)n, c, why, sizeof(why));
}

/* Contract tokens ignore comments and see additions; corpus and weight
 * rows are refused, never repaired. */
static bool hf_shadow_corpus_rows(struct zcl_shadow_corpus *c, const char *commit)
{
    return c && hf_shadow_corpus_row(c, "real", commit, "x.c") &&
         c->count == 1 && !hf_shadow_corpus_row(c, "bogus", commit, "x.c") &&
         !hf_shadow_corpus_row(c, "real", "7a9f354f", "x.c") &&
         !hf_shadow_corpus_row(c, "real", commit, "a,b,c,d,e");
}
static bool hf_shadow_corpus(void)
{
    struct zcl_shadow_patch_facts p;
    bool ok = hf_shadow_analyze(
                  "diff --git a/platform/modules/codec/include/codec/cursor.h "
                  "b/platform/modules/codec/include/codec/cursor.h\n"
                  "@@ -1,2 +1,2 @@\n"
                  "-/* old words */ int a;\n"
                  "+/* new words */  int   a;\n",
                  &p) &&
              p.contract_change == ZCL_SHADOW_CONTRACT_NONE &&
              memcmp(p.contract_before, p.contract_after, 32) == 0;
    ok = ok &&
         hf_shadow_analyze(
             "diff --git a/platform/modules/codec/include/codec/cursor.h "
             "b/platform/modules/codec/include/codec/cursor.h\n"
             "@@ -1,1 +1,2 @@\n int a;\n+int b;\n",
             &p) &&
         p.contract_change == ZCL_SHADOW_CONTRACT_ADDITIVE;
    ok = ok &&
         hf_shadow_analyze("diff --git a/platform/modules/codec/src/cursor.c "
                           "b/platform/modules/codec/src/cursor.c\n"
                           "@@ -1,1 +1,1 @@\n-return 1;\n+return 2;\n",
                           &p) &&
         p.contract_change == ZCL_SHADOW_CONTRACT_NONE &&
         p.contract_hunks == 0 && p.hunks == 1 &&
         !hf_shadow_analyze("not a patch\n", &p);
    struct zcl_shadow_corpus *c = zcl_calloc(1, sizeof(*c), "hf corpus");
    static const char commit[] = "7a9f354f3f7996383c0e7c858346ac29a5ad8957";
    ok = ok && hf_shadow_corpus_rows(c, commit);
    free(c);
    const char unsorted[] = "test_group\tb\t1\t1\ntest_group\ta\t1\t1\n";
    struct zcl_shadow_weights w = {0};
    char why[64];
    ok = ok && !zcl_shadow_weights_parse(unsorted, sizeof(unsorted) - 1, &w,
                                         why, sizeof(why));
    zcl_shadow_weights_free(&w);
    return ok;
}

/* Lint premise rows price only fresh units; the always-run part is paid
 * whole and the rest is shared (ceil(97700 / 72) = 1357). */
static bool hf_shadow_lint_prices(const struct zcl_shadow_lint_premises *p,
    const struct zcl_shadow_lint_premise *g, const struct zcl_shadow_lint_premise *k,
    const struct zcl_shadow_lint_premise *a, bool *priced)
{
    return zcl_shadow_lint_gate_ms(NULL, 120000, priced) == 120000 && !*priced &&
         zcl_shadow_lint_gate_ms(zcl_shadow_lint_premise_find(p, "x", "h"), 120000, priced) == 120000 &&
         !zcl_shadow_lint_premise_find(p, "y", "g") &&
         zcl_shadow_lint_gate_ms(g, 120000, priced) == 7000 + 2 * ZCL_SHADOW_LINT_UNIT_FLOOR_MS &&
         *priced && zcl_shadow_lint_gate_ms(g, 5000000, priced) == 17000 &&
         zcl_shadow_lint_gate_ms(k, 3000, priced) == 10000 &&
         zcl_shadow_lint_gate_ms(a, 115700, priced) == 9000 + 18000 + 4 * 1357 &&
         zcl_shadow_lint_gate_ms(a, 10000, priced) == 19000 &&
         strcmp(zcl_shadow_class_name(ZCL_SHADOW_CLASS_FALLBACK), "fallback") == 0;
}
static bool hf_shadow_lint(void)
{
    struct zcl_shadow_lint_premises p = {0};
    char why[96];
    static const char bad[] = "x\tg\t10\t11\tenabled\t5\t0\n";
    bool ok = !zcl_shadow_lint_premises_parse(bad, sizeof(bad) - 1, &p, why,
                                              sizeof(why));
    zcl_shadow_lint_premises_free(&p);
    static const char good[] = "# c\nx\tg\t1000\t2\tenabled\t7000\t0\n"
                               "x\th\t1000\t0\tdisabled\t7000\t0\n"
                               "x\tk\t10\t10\tenabled\t7000\t0\n"
                               "x\ta\t72\t4\tenabled\t9000\t18000\n";
    ok = ok && zcl_shadow_lint_premises_parse(good, sizeof(good) - 1, &p, why,
                                              sizeof(why)) &&
         p.count == 4;
    bool priced = true;
    const struct zcl_shadow_lint_premise *g =
        ok ? zcl_shadow_lint_premise_find(&p, "x", "g") : NULL;
    const struct zcl_shadow_lint_premise *k =
        ok ? zcl_shadow_lint_premise_find(&p, "x", "k") : NULL;
    const struct zcl_shadow_lint_premise *a =
        ok ? zcl_shadow_lint_premise_find(&p, "x", "a") : NULL;
    ok = ok && g && k && a && hf_shadow_lint_prices(&p, g, k, a, &priced);
    zcl_shadow_lint_premises_free(&p);
    return ok;
}

static bool hf_shadow_render_text(char **text, size_t *len,
                                  const struct zcl_shadow_comparison *c,
                                  const struct zcl_shadow_result *r)
{
    FILE *out = open_memstream(text, len);
    if (!out) return false;
    bool ok = (!c || zcl_shadow_render_comparison(out, "x", c)) &&
              (!r || zcl_shadow_render_entry(out, r));
    return fclose(out) == 0 && ok && *text;
}

/* A required obligation outside a prediction is RED, and the rendered
 * comparison line says so. */
static bool hf_shadow_compare_parsed(struct zcl_shadow_observations *obs,
    struct zcl_shadow_predictions *p, struct zcl_shadow_comparison *c)
{
    return zcl_shadow_compare(zcl_shadow_prediction_find(p, "y"), obs, c) &&
        c->red_selector == 0 && c->red_rule == 1 &&
        zcl_shadow_compare(zcl_shadow_prediction_find(p, "x"), obs, c) &&
        c->observed == 2 && c->required == 1 && c->red_selector == 1 &&
        c->red_rule == 0 && strcmp(c->first_red_selector, "test_a") == 0;
}
static bool hf_shadow_compare(void)
{
    struct zcl_shadow_observation o = {"x", "test_a", ZCL_SHADOW_VERDICT_PASS,
                                       ZCL_SHADOW_VERDICT_PASS};
    bool ok = zcl_shadow_names_contain("test_a,test_ab", "test_ab") &&
              !zcl_shadow_names_contain("test_ab,test_abc", "test_a") &&
              !zcl_shadow_obligation_required(&o);
    o.base = ZCL_SHADOW_VERDICT_FAIL;
    ok = ok && zcl_shadow_obligation_required(&o);
    static const char obs_text[] = "# id group base patched evidence\n"
                                   "x\ttest_a\tpass\tfail\tlog-a\n"
                                   "x\ttest_b\tpass\tpass\tlog-b\n"
                                   "y\ttest_a\tpass\tfail\tlog-c\n";
    static const char pred_text[] = "x\texact\ttest_b\tall\t-\n"
                                    "y\tall\t-\texact\ttest_b,test_c\n";
    struct zcl_shadow_observations obs = {0};
    struct zcl_shadow_predictions *p = zcl_calloc(1, sizeof(*p), "hf pred");
    struct zcl_shadow_comparison c;
    char why[96];
    ok = ok && p &&
         zcl_shadow_observations_parse(obs_text, sizeof(obs_text) - 1, &obs,
                                       why, sizeof(why)) &&
         obs.count == 3 &&
         zcl_shadow_predictions_parse(pred_text, sizeof(pred_text) - 1, p,
                                      why, sizeof(why)) &&
         hf_shadow_compare_parsed(&obs, p, &c);
    char *text = NULL;
    size_t len = 0;
    ok = ok && hf_shadow_render_text(&text, &len, &c, NULL) &&
         strcmp(text,
                "SHADOW-COMPARE id=x observed=2 required=1 red_selector=1 "
                "red_rule=0 first_red_selector=test_a first_red_rule=- "
                "verdict=GREEN\n") == 0;
    free(text);
    if (p) zcl_shadow_predictions_free(p);
    free(p);
    zcl_shadow_observations_free(&obs);
    return ok;
}

/* One synthetic entry renders its kind, fallback, savings, premise fields
 * and divergence. */
static bool hf_shadow_render(void)
{
    struct zcl_shadow_result *r = zcl_calloc(1, sizeof(*r), "hf result");
    if (!r) return false;
    (void)snprintf(r->id, sizeof(r->id), "kat");
    (void)snprintf(r->component, sizeof(r->component), "tools/dev");
    r->kind = ZCL_SHADOW_KIND_ABI;
    r->fallback = ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE;
    r->reference_cost_ms = 4000;
    r->rule_cost_ms = 1000;
    r->premise_fields = (1u << ZCL_SHADOW_FIELD_FLAGS) |
                        (1u << ZCL_SHADOW_FIELD_HARNESS);
    char *text = NULL;
    size_t len = 0;
    bool ok = hf_shadow_render_text(&text, &len, NULL, r) &&
              strstr(text, "SHADOW id=kat kind=abi component=tools/dev ") &&
              strstr(text, " savings_pct=75.0 ") &&
              strstr(text, " fallback_reason=dependency-change ") &&
              strstr(text, " premise_fields=flags,harness ") &&
              strstr(text, " divergence=global ");
    free(text);
    free(r);
    return ok;
}

__attribute__((visibility("hidden"))) bool
zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
    unsigned failed = 0;
#define HF_CHECK(x) \
    do { \
        unsigned n = out->checks_run++; \
        if (x) \
            out->checks_passed++; \
        else \
            failed |= 1u << n; \
    } while (0)
    HF_CHECK(hf_shadow_bound_in_capsule());
    HF_CHECK(hf_shadow_classify());
    HF_CHECK(hf_shadow_reuse());
    HF_CHECK(hf_shadow_eligibility());
    HF_CHECK(hf_shadow_corpus());
    HF_CHECK(hf_shadow_lint());
    HF_CHECK(hf_shadow_compare());
    HF_CHECK(hf_shadow_render());
#undef HF_CHECK
    snprintf(out->exercised_surface, sizeof(out->exercised_surface),
             ZCL_HOTFORK_EXERCISED_SURFACE);
    snprintf(out->detail, sizeof(out->detail), "checks=%u/%u;failed_mask=0x%x",
             out->checks_passed, out->checks_run, failed);
    return out->checks_run == 8 && out->checks_passed == 8;
}
#else
#error "unknown HOT_FORK story phase"
#endif
