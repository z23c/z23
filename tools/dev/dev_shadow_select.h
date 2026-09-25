/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shadow-mode evaluation of the proof obligation selector against
 * the conservative landing reference. It reports; it never admits. */

#ifndef ZCL_TOOLS_DEV_SHADOW_SELECT_H
#define ZCL_TOOLS_DEV_SHADOW_SELECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Nothing in this file grants reuse, acceptance or publication. The landing
 * proof keeps running every lint gate and every group its own selector names;
 * these functions only say what a narrower selector WOULD have skipped, what
 * that would have cost, and which of those skips a checked rule could defend.
 */

#define ZCL_SHADOW_ID_MAX 32u
#define ZCL_SHADOW_PATH_MAX 192u
#define ZCL_SHADOW_MAX_FILES 4u
#define ZCL_SHADOW_MAX_ENTRIES 48u
#define ZCL_SHADOW_NAME_MAX 96u
#define ZCL_SHADOW_ROOT_BYTES 32u

enum zcl_shadow_kind {
    ZCL_SHADOW_KIND_REAL = 0,
    ZCL_SHADOW_KIND_HEADER_DECL,
    ZCL_SHADOW_KIND_ABI,
    ZCL_SHADOW_KIND_FLAG,
    ZCL_SHADOW_KIND_CONTRACT,
    ZCL_SHADOW_KIND_PRIVATE_IMPL,
    ZCL_SHADOW_KIND_GENERATED_INPUT,
    ZCL_SHADOW_KIND_NEGATIVE_LOOKUP,
    ZCL_SHADOW_KIND_MACRO,
    ZCL_SHADOW_KIND__COUNT
};

/* Why a reuse-enabled selector must answer this change with the reference
 * path instead of its own narrower set. NONE means no such reason was found;
 * it is not a claim that the narrower set is sufficient. */
enum zcl_shadow_fallback {
    ZCL_SHADOW_FALLBACK_NONE = 0,
    ZCL_SHADOW_FALLBACK_UNKNOWN_SCOPE,
    ZCL_SHADOW_FALLBACK_POLICY,
    ZCL_SHADOW_FALLBACK_CONFLICT,
    ZCL_SHADOW_FALLBACK_DEPENDENCY_CHANGE,
    ZCL_SHADOW_FALLBACK__COUNT
};

/* How the exported interface moved: NONE (normalized tokens equal), ADDITIVE
 * (only new tokens), MOVED (an existing token sequence was removed or
 * rewritten). The interface is the component's public headers PLUS its
 * contract tests: rewriting an assertion is a contract change even when no
 * header byte moves. */
enum zcl_shadow_contract_change {
    ZCL_SHADOW_CONTRACT_NONE = 0,
    ZCL_SHADOW_CONTRACT_ADDITIVE,
    ZCL_SHADOW_CONTRACT_MOVED,
};

const char *zcl_shadow_kind_name(enum zcl_shadow_kind kind);
bool zcl_shadow_kind_parse(const char *text, enum zcl_shadow_kind *out);
const char *zcl_shadow_fallback_name(enum zcl_shadow_fallback reason);
const char *
zcl_shadow_contract_change_name(enum zcl_shadow_contract_change change);

/* ── Frozen corpus ────────────────────────────────────────────────────────
 *
 * One tab-separated row per entry; '#' lines are comments:
 *   id  kind  component  commit  patch_sha3  file[,file...]
 * `commit` is the landed commit (kind real) or the base the synthetic patch
 * applies to. `patch_sha3` is SHA3-256 of the exact patch bytes: for a real
 * row the output of zcl_shadow_real_patch_argv(), for a synthetic row the
 * bytes of <fixture dir>/<id>.patch. Rows are refused, never repaired. */
struct zcl_shadow_entry {
    char id[ZCL_SHADOW_ID_MAX];
    enum zcl_shadow_kind kind;
    char component[ZCL_SHADOW_PATH_MAX];
    char commit[41];
    uint8_t patch_sha3[ZCL_SHADOW_ROOT_BYTES];
    char files[ZCL_SHADOW_MAX_FILES][ZCL_SHADOW_PATH_MAX];
    size_t file_count;
};

struct zcl_shadow_corpus {
    struct zcl_shadow_entry entries[ZCL_SHADOW_MAX_ENTRIES];
    size_t count;
};

bool zcl_shadow_corpus_parse(const char *text, size_t len,
                             struct zcl_shadow_corpus *out, char *why,
                             size_t why_len);

/* argv that reproduces a real row's patch bytes from the object store of the
 * repository at `root`: git diff-tree of <commit>^ .. <commit> with every
 * presentation knob pinned. `root` and `commit` must outlive argv; the
 * parent spelling lives in static storage, so this is single-threaded.
 * Returns false on a short argv or a commit that is not 40 hex bytes. */
bool zcl_shadow_real_patch_argv(const char *root, const char *commit,
                                const char **argv, size_t argv_cap);

/* ── Cost weights ─────────────────────────────────────────────────────────
 *
 * Rows: kind(lint_gate|test_group)  name  mean_ms  samples, strictly
 * ascending by (kind, name) so lookups are a binary search. */
enum zcl_shadow_obligation {
    ZCL_SHADOW_OBLIGATION_LINT_GATE = 0,
    ZCL_SHADOW_OBLIGATION_TEST_GROUP,
};

struct zcl_shadow_weight {
    char name[ZCL_SHADOW_NAME_MAX];
    enum zcl_shadow_obligation kind;
    uint32_t mean_ms;
    uint32_t samples;
};

struct zcl_shadow_weights {
    struct zcl_shadow_weight *rows;
    size_t count;
};

bool zcl_shadow_weights_parse(const char *text, size_t len,
                              struct zcl_shadow_weights *out, char *why,
                              size_t why_len);
void zcl_shadow_weights_free(struct zcl_shadow_weights *weights);
bool zcl_shadow_weight_ms(const struct zcl_shadow_weights *weights,
                          enum zcl_shadow_obligation kind, const char *name,
                          uint32_t *out_ms);
size_t zcl_shadow_weights_count(const struct zcl_shadow_weights *weights,
                                enum zcl_shadow_obligation kind);
/* Median of one kind's means; the fallback weight for an unmeasured name. */
uint32_t zcl_shadow_weights_median(const struct zcl_shadow_weights *weights,
                                   enum zcl_shadow_obligation kind);

/* ── Patch facts ──────────────────────────────────────────────────────────
 *
 * Parsed from unified-diff bytes, not from the working tree, so the answer is
 * a function of the frozen corpus alone. The contract roots are over the
 * NORMALIZED token stream (comments dropped, whitespace collapsed) of every
 * hunk in a public header (<module>/include/...h) or a contract test
 * (tests/harness/src/test_*.c, <module>/tests/...) of the entry's component:
 * `before` folds the context and removed lines, `after` the context and
 * added lines. Equal roots mean no exported token moved. */
struct zcl_shadow_patch_facts {
    char files[ZCL_SHADOW_MAX_FILES][ZCL_SHADOW_PATH_MAX];
    bool created[ZCL_SHADOW_MAX_FILES];
    size_t file_count;
    size_t hunks;
    size_t contract_hunks;
    enum zcl_shadow_contract_change contract_change;
    uint8_t contract_before[ZCL_SHADOW_ROOT_BYTES];
    uint8_t contract_after[ZCL_SHADOW_ROOT_BYTES];
};

bool zcl_shadow_patch_analyze(const char *component, const uint8_t *bytes,
                              size_t len, struct zcl_shadow_patch_facts *out,
                              char *why, size_t why_len);

/* Does this path belong to the component's exported contract surface? */
bool zcl_shadow_path_is_contract(const char *component, const char *path);
/* Generator inputs the Makefile turns into compiled headers. */
bool zcl_shadow_path_is_generator_input(const char *path);
/* Inputs that rewrite the build graph or its flags for every action. */
bool zcl_shadow_path_is_build_graph(const char *path);

/* ── Fallback classification ──────────────────────────────────────────── */
struct zcl_shadow_scope_facts {
    bool bytes_mismatch;    /* frozen patch SHA3 differs from the bytes */
    bool plan_refused;      /* plan builder refused or plan inadmissible:
                             * the selector could not name the scope */
    bool consensus_policy;  /* consensus surface or sealed core */
    bool build_graph_input; /* Makefile / *.mk: flags and graph moved */
    bool generated_input;   /* a generator input: output bytes unindexed */
    bool negative_lookup;   /* a created header can satisfy an old miss */
    bool closure_universal; /* selector could not enumerate the closure */
};

enum zcl_shadow_fallback
zcl_shadow_classify(const struct zcl_shadow_scope_facts *facts);

/* ── Compositional reuse rule ─────────────────────────────────────────────
 *
 * A caller's proof may be carried across a changed callee implementation
 * ONLY IF all three hold:
 *   1. the callee's contract_root is unchanged;
 *   2. the callee's own contract obligations were freshly EXECUTED and
 *      PASSED on exactly the new implementation root;
 *   3. the caller's premises reference only the callee's contract: no
 *      private symbol, no private header, no layout outside the contract.
 * An unchanged ABI, an unchanged signature, or an old PASS is not a fourth
 * way in: none of them is an input here. */
enum zcl_shadow_verdict {
    ZCL_SHADOW_VERDICT_NOT_RUN = 0,
    ZCL_SHADOW_VERDICT_PASS,
    ZCL_SHADOW_VERDICT_FAIL,
};

enum zcl_shadow_basis {
    ZCL_SHADOW_BASIS_NONE = 0,
    ZCL_SHADOW_BASIS_EXECUTED,
    ZCL_SHADOW_BASIS_REUSED,
};

enum zcl_shadow_premise {
    ZCL_SHADOW_PREMISE_CONTRACT = 0,
    ZCL_SHADOW_PREMISE_PRIVATE_SYMBOL,
    ZCL_SHADOW_PREMISE_PRIVATE_LAYOUT,
    ZCL_SHADOW_PREMISE_PRIVATE_HEADER,
};

struct zcl_shadow_reuse_claim {
    uint8_t contract_before[ZCL_SHADOW_ROOT_BYTES];
    uint8_t contract_after[ZCL_SHADOW_ROOT_BYTES];
    uint8_t callee_impl_after[ZCL_SHADOW_ROOT_BYTES];
    /* the implementation root the contract obligations actually executed */
    uint8_t contract_run_impl[ZCL_SHADOW_ROOT_BYTES];
    enum zcl_shadow_verdict contract_verdict;
    enum zcl_shadow_basis contract_basis;
    size_t contract_obligations; /* how many ran; zero proves nothing */
    const enum zcl_shadow_premise *caller_premises;
    size_t caller_premise_count;
};

enum zcl_shadow_reuse {
    ZCL_SHADOW_REUSE_ADMIT = 0,
    ZCL_SHADOW_REUSE_REFUSE_MALFORMED,
    ZCL_SHADOW_REUSE_REFUSE_CONTRACT_CHANGED,
    ZCL_SHADOW_REUSE_REFUSE_CONTRACT_NOT_EXECUTED,
    ZCL_SHADOW_REUSE_REFUSE_CONTRACT_FAILED,
    ZCL_SHADOW_REUSE_REFUSE_CONTRACT_STALE_IMPL,
    ZCL_SHADOW_REUSE_REFUSE_PRIVATE_PREMISE,
};

const char *zcl_shadow_reuse_name(enum zcl_shadow_reuse decision);
enum zcl_shadow_reuse
zcl_shadow_reuse_admit(const struct zcl_shadow_reuse_claim *claim);

/* ── Proof dependency graph ───────────────────────────────────────────────
 *
 * Kept apart from the build graph (which TUs recompile). A selected group
 * sits on exactly one layer:
 *   CONTRACT     the changed unit's own contract and invariant obligations:
 *                the groups its changed files name through the impact rules;
 *   CALLER       groups reached through the reverse-caller or reverse-include
 *                closure from a file inside the changed component, or through
 *                an opaque rule;
 *   INTEGRATION  groups reached through a file of another component: the
 *                obligations that bind this contract to a consumer.
 * Contract invalidates callers, callers invalidate integration; the rule
 * below decides how far an edit actually propagates. */
enum zcl_shadow_layer {
    ZCL_SHADOW_LAYER_CONTRACT = 0,
    ZCL_SHADOW_LAYER_CALLER,
    ZCL_SHADOW_LAYER_INTEGRATION,
    ZCL_SHADOW_LAYER__COUNT
};

const char *zcl_shadow_layer_name(enum zcl_shadow_layer layer);

struct zcl_shadow_proof_graph {
    uint32_t nodes[ZCL_SHADOW_LAYER__COUNT];   /* selected groups per layer */
    uint64_t ms[ZCL_SHADOW_LAYER__COUNT];
    uint32_t predicted[ZCL_SHADOW_LAYER__COUNT]; /* predicted fresh per layer */
    /* Over-approximation named, not fixed: groups the selector reached ONLY
     * through a reverse-caller hop whose file includes no header of any
     * component the walk legitimately reached. codeindex_callers() matches
     * callees by bare name, so a file-local `static` of the same name in an
     * unrelated TU widens the closure. */
    uint32_t collision_groups;
    uint64_t collision_ms;
    uint32_t caller_hops;                      /* SEMANTIC via files examined */
    uint32_t collision_hops;                   /* of those, unexplained */
};

/* What the reuse-enabled selector PREDICTS must run fresh, written before any
 * reference run. ALL means the reference itself (a fallback fired). */
enum zcl_shadow_predict_mode {
    ZCL_SHADOW_PREDICT_EXACT = 0,
    ZCL_SHADOW_PREDICT_ALL,
};

#define ZCL_SHADOW_NAMES_MAX 32768u

/* ── Evaluation against the live selector ─────────────────────────────── */
struct zcl_shadow_result {
    char id[ZCL_SHADOW_ID_MAX];
    enum zcl_shadow_kind kind;
    char component[ZCL_SHADOW_PATH_MAX];
    struct zcl_shadow_patch_facts patch;
    enum zcl_shadow_fallback fallback;
    bool selector_universal;
    bool bytes_verified;
    uint32_t build_invalidated;     /* TUs the change makes recompile */
    uint32_t build_total;           /* TUs with a compiler depfile */
    bool build_known;               /* the include graph answered */
    uint32_t private_readers;       /* TUs reading a changed private file */
    uint32_t groups_selected;
    uint32_t groups_reference;
    uint32_t lint_selected;
    uint32_t lint_reference;
    uint32_t floor_groups;          /* the changed component's own proofs */
    uint32_t edges_selected;        /* cross-component groups rerun */
    uint32_t edges_reference;
    uint32_t rule_reusable;         /* selected callers the rule could keep */
    uint32_t premise_groups;        /* groups whose premises actually moved */
    uint32_t unweighted;
    uint64_t fresh_cost_ms;
    uint64_t reference_cost_ms;
    uint64_t rule_cost_ms;          /* fresh cost if the rule were applied */
    uint64_t validation_cost_us;
    uint32_t premise_fields;        /* bit per zcl_shadow_field */
    uint32_t key_gap_fields;        /* premise fields the lookup key lacks */
    /* Exact plans only: the selected groups, comma-separated, so a skipped
     * obligation can be re-run by name. Empty for a universal selection;
     * ends in "..." when it did not fit. */
    char selected_names[ZCL_SHADOW_NAMES_MAX];
    char selector_reason[96];       /* why the plan was refused, or "" */
    uint64_t lint_cost_ms;          /* the lint share of every bill above */
    struct zcl_shadow_proof_graph graph;
    /* The rule-enabled prediction: ALL, or exactly these groups plus every
     * lint gate. predicted_cost_ms == rule_cost_ms. */
    enum zcl_shadow_predict_mode predict_mode;
    uint32_t predicted_groups;
    char predicted_names[ZCL_SHADOW_NAMES_MAX];
};

/* Premise fields, named after zcl.component_proof_key.v1. */
enum zcl_shadow_field {
    ZCL_SHADOW_FIELD_SOURCE_CLOSURE = 0,
    ZCL_SHADOW_FIELD_DEPENDENCY_CLOSURE,
    ZCL_SHADOW_FIELD_NEGATIVE_LOOKUPS,
    ZCL_SHADOW_FIELD_GENERATED_INPUTS,
    ZCL_SHADOW_FIELD_FLAGS,
    ZCL_SHADOW_FIELD_ABI_GENERATION,
    ZCL_SHADOW_FIELD_BUILD_GRAPH,
    ZCL_SHADOW_FIELD_HARNESS,
    ZCL_SHADOW_FIELD_FIXTURES,
    ZCL_SHADOW_FIELD_INVARIANTS,
    ZCL_SHADOW_FIELD_INTEGRATION_EDGES,
    ZCL_SHADOW_FIELD_UNIT_ID,
    ZCL_SHADOW_FIELD__COUNT
};

const char *zcl_shadow_field_name(enum zcl_shadow_field field);
/* Bit set of the premise fields zcl.zcode.component_input_key.v1 does not
 * bind as a separate input (it folds the whole candidate source tree into
 * one root and names no callee contract, lookup miss or generator). */
uint32_t zcl_shadow_component_input_key_gaps(void);

/* Measured per-obligation validation cost: deriving one 19-root proof key
 * and verifying one signed ticket (SHA3 + Ed25519). Microseconds x1000. */
uint64_t zcl_shadow_validation_ns_per_obligation(void);

struct zcl_shadow_eval_ctx {
    const char *root;                 /* tree the selector runs against */
    const char *fixture_dir;          /* holds <id>.patch */
    const struct zcl_shadow_weights *weights;
    uint64_t validation_ns;           /* from the call above */
};

bool zcl_shadow_evaluate(const struct zcl_shadow_eval_ctx *ctx,
                         const struct zcl_shadow_entry *entry,
                         struct zcl_shadow_result *out, char *why,
                         size_t why_len);

/* A module's directory: everything before its src/, include/ or tests/, else
 * the file's directory. */
void zcl_shadow_component_of(const char *path, char *out, size_t cap);

/* For each plan selection, whether the include graph explains it. Only
 * reverse-caller (SEMANTIC) hops can be unexplained: one whose TU reads no
 * header of the changed component, nor of a component an explained hop
 * already reached, came from a bare-name caller match. With no include
 * graph, every selection is explained (unknown is never waste). `explained`
 * holds plan->selections_len entries. */
struct zcl_devloop_plan;
bool zcl_shadow_explained_selections(const char *root,
                                     const struct zcl_shadow_entry *e,
                                     const struct zcl_devloop_plan *plan,
                                     bool *explained, uint32_t *hops_out,
                                     uint32_t *collisions_out);

/* One `SHADOW` line per entry, one `SHADOW-PREMISE` line, and the totals and
 * key-gap lines from zcl_shadow_render_totals(). */
bool zcl_shadow_render_entry(FILE *out, const struct zcl_shadow_result *r);
bool zcl_shadow_render_totals(FILE *out, const struct zcl_shadow_result *rows,
                              size_t count);
/* One `SHADOW-GRAPH` line: the proof dependency graph, per layer. */
bool zcl_shadow_render_graph(FILE *out, const struct zcl_shadow_result *r);

/* ── Prediction before proof, then comparison ─────────────────────────────
 *
 * predicted.tsv is written from the live selector BEFORE any reference run
 * and committed; its SHA3 is quoted in the experiment record. One row:
 *   id  selector_mode  selector_groups  rule_mode  rule_groups
 * mode is `all` or `exact`; groups are comma-separated full names, or `-`.
 * `selector` is what the landing selector runs today; `rule` is what the
 * reuse-enabled selector would run. Lint gates are never skipped by either.
 *
 * observed.tsv records the conservative reference run under each patch:
 *   id  group  base  patched  evidence
 * base and patched are pass|fail|not-run; evidence names the log. */
struct zcl_shadow_prediction {
    char id[ZCL_SHADOW_ID_MAX];
    enum zcl_shadow_predict_mode selector_mode;
    enum zcl_shadow_predict_mode rule_mode;
    char selector_names[ZCL_SHADOW_NAMES_MAX];
    char rule_names[ZCL_SHADOW_NAMES_MAX];
};

struct zcl_shadow_predictions {
    struct zcl_shadow_prediction *rows;
    size_t count;
};

/* Writes exactly the row zcl_shadow_predictions_parse() reads back. Refuses
 * a result whose name lists did not fit, so no prediction is ever recorded
 * narrower than the selector's answer. */
bool zcl_shadow_render_prediction(FILE *out, const struct zcl_shadow_result *r);
bool zcl_shadow_predictions_parse(const char *text, size_t len,
                                  struct zcl_shadow_predictions *out,
                                  char *why, size_t why_len);
void zcl_shadow_predictions_free(struct zcl_shadow_predictions *p);
const struct zcl_shadow_prediction *
zcl_shadow_prediction_find(const struct zcl_shadow_predictions *p,
                           const char *id);

struct zcl_shadow_observation {
    char id[ZCL_SHADOW_ID_MAX];
    char group[ZCL_SHADOW_NAME_MAX];
    enum zcl_shadow_verdict base;
    enum zcl_shadow_verdict patched;
};

struct zcl_shadow_observations {
    struct zcl_shadow_observation *rows;
    size_t count;
};

bool zcl_shadow_observations_parse(const char *text, size_t len,
                                   struct zcl_shadow_observations *out,
                                   char *why, size_t why_len);
void zcl_shadow_observations_free(struct zcl_shadow_observations *o);

/* An obligation the change made REQUIRED: it fails under the patch, or its
 * verdict differs from the base. A group that was not run is not evidence. */
bool zcl_shadow_obligation_required(const struct zcl_shadow_observation *o);
/* Exact membership in a comma-separated name list. */
bool zcl_shadow_names_contain(const char *names, const char *group);

struct zcl_shadow_comparison {
    uint32_t observed;          /* reference groups run for this entry */
    uint32_t required;
    uint32_t red_selector;      /* required but outside the landing selector */
    uint32_t red_rule;          /* required but outside the rule prediction */
    char first_red_selector[ZCL_SHADOW_NAME_MAX];
    char first_red_rule[ZCL_SHADOW_NAME_MAX];
};

/* RED is any required obligation a prediction did not name. `all` covers
 * everything. False on a NULL argument only. */
bool zcl_shadow_compare(const struct zcl_shadow_prediction *p,
                        const struct zcl_shadow_observations *obs,
                        struct zcl_shadow_comparison *out);
bool zcl_shadow_render_comparison(FILE *out, const char *id,
                                  const struct zcl_shadow_comparison *c);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_DEV_SHADOW_SELECT_H */
