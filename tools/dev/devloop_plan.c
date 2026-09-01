/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "devloop.h"

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "controllers/agent_impact_rules.h"
#include "crypto/sha3.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_service.h"
#include "platform/file_watch_compat.h"
#include "services/dev_reflex_policy_service.h"
#include "test_group_catalog.h"
#include "util/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct hotswap_eligible_entry {
    const char *path;
    const char *probe;
};

static const struct hotswap_eligible_entry g_hotswap_eligible[] = {
#define HOTSWAP_ELIGIBLE(path_) { .path = path_, .probe =
#define HOTSWAP_PROBE(probe_) probe_ },
#include "../../engine/composition/hotswap_eligible.def"
#undef HOTSWAP_PROBE
#undef HOTSWAP_ELIGIBLE
};

static const struct hotswap_eligible_entry g_hotswap_services[] = {
#define HOTSWAP_SERVICE(id_, source_, headers_, contract_headers_, imports_, abi_, schema_, wire_, kat_, probe_) \
    { .path = source_, .probe = probe_ },
#include "../../engine/composition/hotswap_services.def"
#undef HOTSWAP_SERVICE
};

const char *zcl_devloop_progress_phase(const char *status,
                                       const char *detail)
{
    const struct dev_reflex_policy_service_v1 *service =
        dev_reflex_policy_service_builtin();
    return service->progress_phase(status, detail);
}

static bool path_is_safe(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || strstr(path, ".."))
        return false;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        if (*p < 0x20 || *p == '\\')
            return false;
    }
    return true;
}

static const struct hotswap_eligible_entry *hotswap_entry(const char *path)
{
    const char *owner = hotswap_island_owner_for_path(path);
    if (!owner) {
        owner = zcl_hotswap_service_source_for_path(path);
        for (size_t i = 0; owner && i < sizeof(g_hotswap_services) /
                                      sizeof(g_hotswap_services[0]); i++)
            if (strcmp(owner, g_hotswap_services[i].path) == 0)
                return &g_hotswap_services[i];
    }
    if (!owner)
        return NULL;
    for (size_t i = 0; i < sizeof(g_hotswap_eligible) /
                            sizeof(g_hotswap_eligible[0]); i++) {
        if (strcmp(owner, g_hotswap_eligible[i].path) == 0)
            return &g_hotswap_eligible[i];
    }
    return NULL;
}

static bool has_suffix(const char *path, const char *suffix)
{
    size_t plen = path ? strlen(path) : 0;
    size_t slen = suffix ? strlen(suffix) : 0;
    return plen >= slen && memcmp(path + plen - slen, suffix, slen) == 0;
}

bool zcl_devloop_restart_source_set_add(
    struct zcl_devloop_restart_source_set *set,
    const char *const *paths, size_t path_count)
{
    if (!set || !paths || path_count == 0 || set->overflow)
        return false;
    for (size_t i = 0; i < path_count; i++) {
        const char *source = zcl_hotswap_service_source_for_path(paths[i]);
        if (!source && has_suffix(paths[i], ".c"))
            source = paths[i];
        if (!source)
            continue;
        size_t source_len = strlen(source);
        if (source_len == 0 || source_len >= ZCL_DEVLOOP_PATH_MAX) {
            set->overflow = true;
            return false;
        }
        bool present = false;
        for (size_t j = 0; j < set->count; j++)
            if (strcmp(set->sources[j], source) == 0) {
                present = true;
                break;
            }
        if (present)
            continue;
        if (set->count >= ZCL_DEVLOOP_RESTART_SOURCE_MAX) {
            set->overflow = true;
            return false;
        }
        (void)snprintf(set->sources[set->count],
                       sizeof(set->sources[set->count]), "%s", source);
        set->count++;
    }
    return true;
}

static bool path_is_docs(const char *path)
{
    return path &&
        (strncmp(path, "docs/", 5) == 0 ||
         strcmp(path, "README.md") == 0 ||
         strcmp(path, "AGENTS.md") == 0 ||
         has_suffix(path, ".md"));
}

/* The SEALED consensus core: the exact surface `core/MANIFEST.sha3` pins
 * (`git ls-files core/`). This is intentionally the whole `core/` tree —
 * broader than path_is_consensus_risk()'s prefix list, which predates the
 * core-split absorption and does not name core/math. Keeping this a single
 * "core/" prefix keeps the fast-loop refusal aligned with the seal manifest
 * by construction (there is no second list to drift). */
bool zcl_devloop_path_is_sealed_core(const char *path)
{
    return path && strncmp(path, "core/", 5) == 0;
}

bool zcl_devloop_path_is_relevant(const char *path)
{
    if (!path || !path[0])
        return false;
    size_t len = strlen(path);
    if (path[len - 1] == '~' || strstr(path, ".swp") ||
        strstr(path, ".tmp") || strstr(path, "/build/") ||
        strncmp(path, "build/", 6) == 0 ||
        strncmp(path, ".git/", 5) == 0)
        return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    /* Transient lint/shape-gate fixtures: test_make_lint_gates.c writes
     * `_*fixture*` .c files under app/, lib/, and domain/ to exercise the
     * path gates, then deletes them. A leading-underscore basename that
     * mentions "fixture" is never a real edit; reacting to it fires a phantom
     * reload cycle on every test-suite run (the file is already gone by the
     * time the cycle rebuilds). No tracked source matches this shape — the
     * real fixture sources under tests/harness/fixtures/ have no leading '_'. */
    if (base[0] == '_' && strstr(base, "fixture"))
        return false;
    if (strcmp(base, "Makefile") == 0)
        return true;
    const char *dot = strrchr(base, '.');
    return dot &&
        (strcmp(dot, ".c") == 0 || strcmp(dot, ".h") == 0 ||
         strcmp(dot, ".def") == 0 || strcmp(dot, ".md") == 0 ||
         strcmp(dot, ".mk") == 0 || strcmp(dot, ".service") == 0);
}

bool zcl_devloop_watch_event_is_mutation(uint32_t inotify_mask)
{
    return (inotify_mask &
            (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM |
             IN_CREATE | IN_DELETE)) != 0;
}

bool zcl_devloop_watch_dir_is_ignored(const char *name)
{
    return !name || !name[0] || name[0] == '.' ||
           strcmp(name, "build") == 0 || strcmp(name, "vendor") == 0 ||
           strcmp(name, "target") == 0 || strcmp(name, "node_modules") == 0 ||
           strcmp(name, "test-tmp") == 0;
}

/* ── the three dimensions (C3) ─────────────────────────────────────────── */

const char *zcl_devloop_dim_name(enum zcl_devloop_dim dim)
{
    switch (dim) {
    case ZCL_DEVLOOP_DIM_OPAQUE:   return "opaque";
    case ZCL_DEVLOOP_DIM_SEMANTIC: return "semantic";
    case ZCL_DEVLOOP_DIM_INCLUDE:  return "include";
    case ZCL_DEVLOOP_DIM__COUNT:   break;
    }
    return "unknown";
}

const char *zcl_devloop_dim_status_name(enum zcl_devloop_dim_status status)
{
    switch (status) {
    case ZCL_DEVLOOP_DIM_COMPLETE:       return "complete";
    case ZCL_DEVLOOP_DIM_INCOMPLETE:     return "incomplete";
    case ZCL_DEVLOOP_DIM_UNAVAILABLE:    return "unavailable";
    case ZCL_DEVLOOP_DIM_NOT_APPLICABLE: return "not_applicable";
    }
    return "unknown";
}

/* An artifact NO graph can reach: the compiler never reads it, so neither the
 * call graph nor the include graph has anything to say about it, and the only
 * thing that can map it to a proof is a hand-authored rule in
 * agent_impact_rules.def. That is what makes such a rule OPAQUE rather than
 * redundant — it is not a cache of something derivable.
 *
 * Kept a pure suffix test on purpose: it must agree with what the compiler
 * does and does not open, and every extension here is one no translation unit
 * can `#include`. `.def` is deliberately ABSENT — a registry IS compiled (it
 * is `#include`d), so it belongs to the include dimension, not to this one. */
static bool path_is_opaque_class(const char *path)
{
    static const char *const suffixes[] = {
        ".sh", ".md", ".txt", ".service", ".timer", ".mk", ".yml", ".yaml",
        ".json", ".sha3",
    };
    if (!path || !path[0])
        return false;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strcmp(base, "Makefile") == 0)
        return true;
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        if (has_suffix(path, suffixes[i]))
            return true;
    }
    return false;
}

/* Graph dimensions are properties of a source shape, not mandatory rituals.
 * A .c file cannot be reverse-included; a .def registry has no callable
 * symbols; opaque assets enter neither compiler graph. Dedicated registered
 * test translation units are proof leaves: their exact owning group is the
 * path floor, while the runner's dispatch reference is harness plumbing, not
 * production blast radius. Only translation units in the mechanically audited
 * semantic-leaf registry get that exemption; ordinary registered tests still
 * query the semantic graph. This avoids expensive empty queries and the
 * historic test_parallel fanout false alarm without hiding helper impacts. */
static bool path_semantic_applies(const char *path)
{
    if (!path || agent_impact_path_is_direct_development_contract(path) ||
        path_is_opaque_class(path) || has_suffix(path, ".def"))
        return false;
    if (has_suffix(path, ".h"))
        return true;
    if (!has_suffix(path, ".c"))
        return false;
    return !zcl_test_group_source_is_semantic_leaf(path);
}

static bool path_include_applies(const char *path)
{
    return path &&
           !agent_impact_path_is_direct_development_contract(path) &&
           !path_is_opaque_class(path) &&
           (has_suffix(path, ".h") || has_suffix(path, ".def"));
}

static bool plan_semantic_leaf_group(
    const char *path, char full[ZCL_TEST_GROUP_FULL_MAX])
{
    static const char prefix[] = "tests/harness/src/";
    size_t path_len = path ? strlen(path) : 0;
    size_t prefix_len = sizeof(prefix) - 1;
    if (!full || !zcl_test_group_source_is_semantic_leaf(path) ||
        path_len <= prefix_len + 2 ||
        strncmp(path, prefix, prefix_len) != 0 ||
        strcmp(path + path_len - 2, ".c") != 0)
        return false;
    size_t group_len = path_len - prefix_len - 2;
    if (group_len == 0 || group_len >= ZCL_TEST_GROUP_FULL_MAX)
        return false;
    memcpy(full, path + prefix_len, group_len);
    full[group_len] = 0;
    return zcl_test_group_catalog_contains(full);
}

/* Severity ordering for combining one dimension's verdict across several
 * changed files. NOT_APPLICABLE is the most benign (there was nothing to find),
 * COMPLETE beats it only in the sense that something WAS found; the two
 * refusing states outrank both, and UNAVAILABLE outranks INCOMPLETE because a
 * dimension that never ran tells us strictly less than one that ran partway. */
static int plan_dim_severity(enum zcl_devloop_dim_status status)
{
    switch (status) {
    case ZCL_DEVLOOP_DIM_NOT_APPLICABLE: return 0;
    case ZCL_DEVLOOP_DIM_COMPLETE:       return 1;
    case ZCL_DEVLOOP_DIM_INCOMPLETE:     return 2;
    case ZCL_DEVLOOP_DIM_UNAVAILABLE:    return 3;
    }
    return 3;
}

static void plan_dim_set(struct zcl_devloop_plan *plan, enum zcl_devloop_dim dim,
                         enum zcl_devloop_dim_status status, const char *reason)
{
    if (!plan || (int)dim < 0 || dim >= ZCL_DEVLOOP_DIM__COUNT)
        return;
    /* Worst verdict wins: a dimension that was UNAVAILABLE for one changed
     * file does not become COMPLETE because the next file was fine. */
    if (plan_dim_severity(status) <= plan_dim_severity(plan->dims[dim].status))
        return;
    plan->dims[dim].status = status;
    plan->dims[dim].reason = reason ? reason : "";
}

/* Record WHY a group is in the plan (C5). Deduped on (group, dim): the first
 * dimension to name a group owns the explanation, which keeps the ledger
 * bounded and the attribution stable. */
static void plan_note_selection(struct zcl_devloop_plan *plan,
                                const char *group, enum zcl_devloop_dim dim,
                                const char *via)
{
    if (!plan || !group || !group[0])
        return;
    for (size_t i = 0; i < plan->selections_len; i++) {
        if (strcmp(plan->selections[i].group, group) == 0)
            return;
    }
    if (plan->selections_len >= ZCL_DEVLOOP_MAX_PLAN_SELECTIONS) {
        /* The ledger itself overflowed: some selected group is now unexplained,
         * which is precisely the state C5 exists to make visible. */
        plan->selections_truncated = true;
        return;
    }
    struct zcl_devloop_selection *s = &plan->selections[plan->selections_len];
    snprintf(s->group, sizeof(s->group), "%s", group);
    snprintf(s->via, sizeof(s->via), "%s", (via && via[0]) ? via : "(unknown)");
    s->dim = dim;
    plan->selections_len++;
}

static bool plan_group_ids_valid(const struct zcl_devloop_plan *plan)
{
    if (!plan)
        return false;
    char full[ZCL_TEST_GROUP_FULL_MAX];
    for (size_t i = 0; i < plan->path_groups_len; i++)
        if (!zcl_test_group_resolve_exact(plan->path_groups[i], full))
            return false;
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        if (!zcl_test_group_resolve_exact(plan->closure_groups[i], full))
            return false;
    return true;
}

static bool plan_selects_full_group(const struct zcl_devloop_plan *plan,
                                    const char *full_id)
{
    for (size_t i = 0; i < plan->path_groups_len; i++)
        if (zcl_test_group_plan_selects(plan->path_groups[i], full_id))
            return true;
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        if (zcl_test_group_plan_selects(plan->closure_groups[i], full_id))
            return true;
    return false;
}

bool zcl_devloop_plan_proof_admissible(const struct zcl_devloop_plan *plan,
                                       const char **out_reason)
{
    if (out_reason) *out_reason = "";
    if (!plan) {
        if (out_reason) *out_reason = "no-plan";
        return false;
    }
    if (plan->file_count > 0 && !plan->docs_only &&
        plan->path_groups_len == 0) {
        if (out_reason) *out_reason = "unmapped-code-change";
        return false;
    }
    if (!plan_group_ids_valid(plan)) {
        if (out_reason) *out_reason = "unknown-test-group";
        return false;
    }
    for (int d = 0; d < ZCL_DEVLOOP_DIM__COUNT; d++) {
        enum zcl_devloop_dim_status st = plan->dims[d].status;
        if (st == ZCL_DEVLOOP_DIM_COMPLETE ||
            st == ZCL_DEVLOOP_DIM_NOT_APPLICABLE)
            continue;
        if (out_reason)
            *out_reason = plan->dims[d].reason ? plan->dims[d].reason
                                               : "incomplete";
        return false;
    }
    /* A group in the plan that the ledger could not explain is itself an
     * unproven claim: the plan cannot say what covers what. */
    if (plan->selections_truncated) {
        if (out_reason) *out_reason = "selection-ledger-truncated";
        return false;
    }
    return true;
}

static bool path_is_consensus_risk(const char *path)
{
    static const char *const prefixes[] = {
        "core/consensus/", "core/params/", "core/chainparams/",
        "core/modules/validation/", "core/modules/chain/", "core/modules/primitives/", "core/modules/crypto/",
        "platform/modules/sha3/",
        "core/modules/sapling/", "engine/jobs/",
    };
    if (!path)
        return false;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0)
            return true;
    }
    return false;
}

static bool plan_add_path_group(struct zcl_devloop_plan *plan,
                                const char *group)
{
    for (size_t i = 0; i < plan->path_groups_len; i++)
        if (strcmp(plan->path_groups[i], group) == 0)
            return true;
    if (plan->path_groups_len >= ZCL_DEVLOOP_MAX_PLAN_GROUPS)
        return false;
    snprintf(plan->path_groups[plan->path_groups_len],
             sizeof(plan->path_groups[0]), "%s", group);
    plan->path_groups_len++;
    return true;
}

bool zcl_devloop_plan_files(const char *const *files, size_t file_count,
                            struct zcl_devloop_plan *out)
{
    if (!out || (file_count > 0 && !files) ||
        file_count > ZCL_DEVLOOP_MAX_FILES)
        return false;

    memset(out, 0, sizeof(*out));
    out->action = ZCL_DEVLOOP_CHECK;
    out->action_name = "check";
    out->reason = "no_changes";
    out->proof_group = "";
    out->probe_tool = "";
    out->file_count = file_count;
    /* The two GRAPH dimensions start UNAVAILABLE and stay that way unless
     * zcl_devloop_plan_add_closure() actually runs them. A path-only plan has
     * asked the index nothing, and must not read as proof that it did. */
    out->dims[ZCL_DEVLOOP_DIM_OPAQUE].status = ZCL_DEVLOOP_DIM_COMPLETE;
    out->dims[ZCL_DEVLOOP_DIM_OPAQUE].reason = "";
    out->dims[ZCL_DEVLOOP_DIM_SEMANTIC].status = ZCL_DEVLOOP_DIM_UNAVAILABLE;
    out->dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason = "closure-not-attempted";
    out->dims[ZCL_DEVLOOP_DIM_INCLUDE].status = ZCL_DEVLOOP_DIM_UNAVAILABLE;
    out->dims[ZCL_DEVLOOP_DIM_INCLUDE].reason = "closure-not-attempted";
    if (file_count == 0)
        return true;

    bool all_docs = true;
    bool all_hotswap = true;
    const struct hotswap_eligible_entry *batch_hotswap = NULL;
    bool one_hotswap_owner = true;
    const char *consensus_via = NULL;
    for (size_t i = 0; i < file_count; i++) {
        if (!path_is_safe(files[i]))
            return false;
        all_docs = all_docs && path_is_docs(files[i]);
        const struct hotswap_eligible_entry *entry = hotswap_entry(files[i]);
        all_hotswap = all_hotswap && entry != NULL;
        if (i == 0)
            batch_hotswap = entry;
        else if (entry != batch_hotswap)
            one_hotswap_owner = false;
        bool sealed = zcl_devloop_path_is_sealed_core(files[i]);
        out->sealed_core = out->sealed_core || sealed;
        /* A sealed-core file is always heaviest-proof: even core/math (not in
         * the legacy consensus_risk prefix list) decides block/tx validity. */
        bool crisk = sealed || path_is_consensus_risk(files[i]);
        if (crisk && !consensus_via)
            consensus_via = files[i];
        out->consensus_risk = out->consensus_risk || crisk;
        /* An audited test translation unit is its own exact path floor. Its
         * runner and helper dependencies do not make the test source itself
         * an owner of every broad rule that happens to match its contents. */
        char leaf_group[ZCL_TEST_GROUP_FULL_MAX];
        if (plan_semantic_leaf_group(files[i], leaf_group)) {
            plan_note_selection(out, leaf_group, ZCL_DEVLOOP_DIM_OPAQUE,
                                files[i]);
            if (!plan_add_path_group(out, leaf_group))
                plan_dim_set(out, ZCL_DEVLOOP_DIM_OPAQUE,
                             ZCL_DEVLOOP_DIM_INCOMPLETE, "path-group-cap");
            continue;
        }
        /* Each rule is evaluated in its original bounded accumulator, then
         * unioned directly into the graph-plan envelope. A multi-file plan is
         * not constrained by the smaller per-path result shape. */
        struct agent_impact_acc per_file = {0};
        (void)agent_impact_apply_shared_rules(files[i], &per_file);
        enum zcl_devloop_dim dim =
            (path_is_opaque_class(files[i]) ||
             (!path_semantic_applies(files[i]) &&
              !path_include_applies(files[i])))
                ? ZCL_DEVLOOP_DIM_OPAQUE
                : ZCL_DEVLOOP_DIM_SEMANTIC;
        for (size_t g = 0; g < per_file.groups_len; g++) {
            plan_note_selection(out, per_file.groups[g], dim, files[i]);
            if (!plan_add_path_group(out, per_file.groups[g]))
                plan_dim_set(out, ZCL_DEVLOOP_DIM_OPAQUE,
                             ZCL_DEVLOOP_DIM_INCOMPLETE, "path-group-cap");
        }
    }
    out->docs_only = all_docs;

    /* The consensus-surface route is a hardcoded prefix list — an explicit,
     * hand-authored, non-derivable mapping, exactly like the .def rules. It
     * already drives foreground_proof, but it named no group in any array, so
     * a reader saw "0 test groups" for a change to consensus crypto. Name it. */
    if (out->consensus_risk) {
        plan_note_selection(out, "consensus_parity", ZCL_DEVLOOP_DIM_OPAQUE,
                            consensus_via ? consensus_via : files[0]);
        if (!plan_add_path_group(out, "consensus_parity"))
            plan_dim_set(out, ZCL_DEVLOOP_DIM_OPAQUE,
                         ZCL_DEVLOOP_DIM_INCOMPLETE, "path-group-cap");
    }

    if (all_docs) {
        out->reason = "documentation_only";
        return true;
    }
    if (all_hotswap && one_hotswap_owner && batch_hotswap) {
        out->action = ZCL_DEVLOOP_HOTSWAP;
        out->action_name = "hotswap";
        out->reason = file_count == 1
            ? "single_stateless_provider"
            : (zcl_hotswap_service_source_for_path(files[0])
                ? "single_service_island_batch"
                : "single_stateless_island_batch");
        /* A frozen fail-fast story is the direct behavioral owner. Generic
         * islands retain the loader/simnet owner, but this service must never
         * make an agent infer its story from a broad hot-swap suite. */
        out->proof_group = strcmp(batch_hotswap->probe, "dev.test.story") == 0
            ? "transaction_intent" : "hotswap_simnet";
        out->probe_tool = batch_hotswap->probe;
        return true;
    }

    out->action = ZCL_DEVLOOP_RELOAD;
    out->action_name = "reload";
    snprintf(out->proof_group_storage, sizeof(out->proof_group_storage), "%s",
             out->consensus_risk
                ? "consensus_parity"
                : (out->path_groups_len > 0
                    ? out->path_groups[0]
                    : "make_lint_gates"));
    out->proof_group = out->proof_group_storage;
    out->reason = out->consensus_risk
        ? "consensus_or_chain_state_is_never_swappable"
        : (all_hotswap
            ? "multi_provider_generation_not_yet_admitted"
            : "state_or_abi_contract_requires_process_reload");
    return true;
}

/* Hard ceiling on impacted files pulled from a single dimension's walk.
 * Hitting it marks that dimension INCOMPLETE; it never discards what the walk
 * already found. Deliberately unchanged: a cap firing is a reporting problem
 * (C1/C4), not a reason to buy a bigger number. */
#define ZCL_DEVLOOP_CLOSURE_FILE_CAP 2048

static bool plan_group_present(const struct zcl_devloop_plan *plan,
                               const char *group)
{
    for (size_t i = 0; i < plan->path_groups_len; i++)
        if (strcmp(plan->path_groups[i], group) == 0)
            return true;
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        if (strcmp(plan->closure_groups[i], group) == 0)
            return true;
    return false;
}

/* Fold one reached file's rule matches into closure_groups, attributing each
 * new group to `dim` through `reached`. Returns false iff the group array
 * filled — the caller marks the dimension INCOMPLETE and KEEPS what fit. */
static bool plan_fold_reached_file(struct zcl_devloop_plan *plan,
                                   const char *reached,
                                   enum zcl_devloop_dim dim)
{
    char leaf_group[ZCL_TEST_GROUP_FULL_MAX];
    if (plan_semantic_leaf_group(reached, leaf_group)) {
        if (plan_group_present(plan, leaf_group))
            return true;
        if (plan->closure_groups_len >= ZCL_DEVLOOP_MAX_PLAN_GROUPS)
            return false;
        snprintf(plan->closure_groups[plan->closure_groups_len],
                 sizeof(plan->closure_groups[0]), "%s", leaf_group);
        plan->closure_groups_len++;
        plan_note_selection(plan, leaf_group, dim, reached);
        return true;
    }
    struct agent_impact_acc acc = {0};
    (void)agent_impact_apply_shared_rules(reached, &acc);
    for (size_t g = 0; g < acc.groups_len; g++) {
        if (plan_group_present(plan, acc.groups[g]))
            continue;
        if (plan->closure_groups_len >= ZCL_DEVLOOP_MAX_PLAN_GROUPS)
            return false;
        snprintf(plan->closure_groups[plan->closure_groups_len],
                 sizeof(plan->closure_groups[0]), "%s", acc.groups[g]);
        plan->closure_groups_len++;
        plan_note_selection(plan, acc.groups[g], dim, reached);
    }
    return true;
}

static bool plan_reached_proof_owner(const char *path, void *user)
{
    (void)user;
    if (zcl_test_group_source_is_semantic_leaf(path))
        return true;
    struct agent_impact_acc impact = {0};
    (void)agent_impact_apply_shared_rules(path, &impact);
    return impact.shared_rule_hits > 0;
}

static bool plan_add_closure(const char *repo_root,
                             const char *const *files, size_t file_count,
                             struct zcl_devloop_plan *plan, bool snapshot)
{
    if (!plan || (file_count > 0 && !files) ||
        file_count > ZCL_DEVLOOP_MAX_FILES)
        return false;

    plan->closure_attempted = true;
    plan->closure_snapshot = false;
    plan->closure_groups_len = 0;
    /* This call OWNS the two graph dimensions; reset them and let the walks
     * below escalate. The OPAQUE dimension belongs to the path floor and is
     * left exactly as zcl_devloop_plan_files() decided it. */
    plan->dims[ZCL_DEVLOOP_DIM_SEMANTIC].status =
        ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    plan->dims[ZCL_DEVLOOP_DIM_SEMANTIC].reason = "";
    plan->dims[ZCL_DEVLOOP_DIM_INCLUDE].status =
        ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    plan->dims[ZCL_DEVLOOP_DIM_INCLUDE].reason = "";
    if (file_count == 0) {
        plan->closure_truncated = false;
        return true;
    }

    size_t semantic_count = 0;
    size_t include_count = 0;
    for (size_t i = 0; i < file_count; i++) {
        semantic_count += path_semantic_applies(files[i]) ? 1u : 0u;
        include_count += path_include_applies(files[i]) ? 1u : 0u;
    }
    if (semantic_count == 0 && include_count == 0) {
        plan->closure_truncated = false;
        return true;
    }

    const char *root = (repo_root && repo_root[0]) ? repo_root : ".";
    struct codeindex *ci = snapshot ? codeindex_open_existing(root) : NULL;
    if (snapshot && ci)
        plan->closure_snapshot = true;
    if (!ci)
        ci = codeindex_open(root);
    if (!ci) {
        /* No index: the path floor still stands and its tests still run, but
         * neither graph dimension was consulted. Say UNAVAILABLE — the old
         * code returned here silently, which read as "asked, found nothing". */
        if (semantic_count > 0)
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_SEMANTIC,
                         ZCL_DEVLOOP_DIM_UNAVAILABLE, "no-code-index");
        if (include_count > 0)
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                         ZCL_DEVLOOP_DIM_UNAVAILABLE, "no-code-index");
        plan->closure_truncated = true;
        return true;
    }

    bool ok = true;
    char (*changed)[256] = semantic_count > 0
        ? zcl_malloc(sizeof(*changed) * semantic_count, "closure_changed")
        : NULL;
    char (*impacted)[256] = zcl_malloc(
        sizeof(*impacted) * ZCL_DEVLOOP_CLOSURE_FILE_CAP, "closure_impacted");
    if ((semantic_count > 0 && !changed) || !impacted) {
        ok = false;
        goto out;
    }
    size_t semantic_index = 0;
    for (size_t i = 0; i < file_count; i++)
        if (path_semantic_applies(files[i]))
            snprintf(changed[semantic_index++], 256, "%s", files[i]);

    /* ── dimension SEMANTIC: the reverse-caller blast radius ── */
    if (semantic_count > 0) {
        plan_dim_set(plan, ZCL_DEVLOOP_DIM_SEMANTIC,
                     ZCL_DEVLOOP_DIM_COMPLETE, "");
        bool truncated = false;
        /* A reached file with an explicit proof-owner rule is the terminal
         * evidence layer. Record it below, but do not walk back through its
         * generic caller/dispatcher and select unrelated proof families. An
         * unowned caller is never a boundary and the graph keeps climbing. */
        int n = plan->closure_snapshot
            ? codeindex_impact_closure_overlay_with_terminal(
                ci, root, changed, (int)semantic_count, 0,
                plan_reached_proof_owner, NULL, impacted,
                ZCL_DEVLOOP_CLOSURE_FILE_CAP, &truncated)
            : codeindex_impact_closure_with_terminal(
                ci, changed, (int)semantic_count, 0,
                plan_reached_proof_owner, NULL, impacted,
                ZCL_DEVLOOP_CLOSURE_FILE_CAP, &truncated);
        if (n < 0) {
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_SEMANTIC,
                         ZCL_DEVLOOP_DIM_UNAVAILABLE, "closure-query-error");
            ok = false;
            goto out;
        }
        if (truncated) {
        /* C1: the walk is INCOMPLETE, not empty. Everything it reached below
         * is still folded in — a partial closure is real evidence, and the
         * caller learns it is partial from dims[SEMANTIC], not by receiving
         * an empty array that looks like "nothing to run". */
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_SEMANTIC,
                         ZCL_DEVLOOP_DIM_INCOMPLETE, "closure-truncated");
        }
        for (int i = 0; i < n; i++) {
            if (!plan_fold_reached_file(plan, impacted[i],
                                        ZCL_DEVLOOP_DIM_SEMANTIC)) {
                plan_dim_set(plan, ZCL_DEVLOOP_DIM_SEMANTIC,
                             ZCL_DEVLOOP_DIM_INCOMPLETE, "plan-group-cap");
                break;
            }
        }
    }

    /* ── dimension INCLUDE: every TU the compiler read a changed file for ──
     * The call graph above cannot see this edge at all: a macro-only header,
     * an enum, a typedef, and an X-macro registry define no callable symbol,
     * so they have an empty reverse-caller closure while every file that
     * includes them recompiles. */
    if (include_count > 0)
        plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                     ZCL_DEVLOOP_DIM_COMPLETE, "");
    for (size_t i = 0; i < file_count; i++) {
        if (!path_include_applies(files[i]))
            continue;
        enum codeindex_include_dim idim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
        int nd = codeindex_reverse_includes(ci, files[i], impacted,
                                            ZCL_DEVLOOP_CLOSURE_FILE_CAP,
                                            &idim);
        if (nd < 0) {
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                         ZCL_DEVLOOP_DIM_UNAVAILABLE, "closure-query-error");
            ok = false;
            goto out;
        }
        if (idim == CODEINDEX_INCLUDE_DIM_UNAVAILABLE) {
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                         ZCL_DEVLOOP_DIM_UNAVAILABLE,
                         codeindex_include_dim_label(idim));
        } else if (idim == CODEINDEX_INCLUDE_DIM_TRUNCATED) {
            plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                         ZCL_DEVLOOP_DIM_INCOMPLETE,
                         codeindex_include_dim_label(idim));
        }
        for (int d = 0; d < nd; d++) {
            if (!plan_fold_reached_file(plan, impacted[d],
                                        ZCL_DEVLOOP_DIM_INCLUDE)) {
                plan_dim_set(plan, ZCL_DEVLOOP_DIM_INCLUDE,
                             ZCL_DEVLOOP_DIM_INCOMPLETE, "plan-group-cap");
                break;
            }
        }
    }

out:
    /* Back-compat: the single boolean older readers still parse. It now means
     * "at least one applicable graph dimension is refusing", and it no longer
     * implies closure_groups is empty. NOT_APPLICABLE is complete evidence. */
    enum zcl_devloop_dim_status semantic_status =
        plan->dims[ZCL_DEVLOOP_DIM_SEMANTIC].status;
    enum zcl_devloop_dim_status include_status =
        plan->dims[ZCL_DEVLOOP_DIM_INCLUDE].status;
    plan->closure_truncated =
        semantic_status == ZCL_DEVLOOP_DIM_INCOMPLETE ||
        semantic_status == ZCL_DEVLOOP_DIM_UNAVAILABLE ||
        include_status == ZCL_DEVLOOP_DIM_INCOMPLETE ||
        include_status == ZCL_DEVLOOP_DIM_UNAVAILABLE;
    free(changed);
    free(impacted);
    codeindex_close(ci);
    return ok;
}

bool zcl_devloop_plan_add_closure(const char *repo_root,
                                  const char *const *files, size_t file_count,
                                  struct zcl_devloop_plan *plan)
{
    return plan_add_closure(repo_root, files, file_count, plan, false);
}

bool zcl_devloop_plan_add_closure_snapshot(
    const char *repo_root, const char *const *files, size_t file_count,
    struct zcl_devloop_plan *plan)
{
    return plan_add_closure(repo_root, files, file_count, plan, true);
}

static bool appendf(char *out, size_t out_sz, size_t *pos,
                    const char *fmt, ...)
{
    if (!out || !pos || *pos >= out_sz)
        return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *pos, out_sz - *pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= out_sz - *pos)
        return false;
    *pos += (size_t)n;
    return true;
}

static bool append_json_string(char *out, size_t out_sz, size_t *pos,
                               const char *value)
{
    if (!appendf(out, out_sz, pos, "\""))
        return false;
    for (const unsigned char *p = (const unsigned char *)(value ? value : "");
         *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (!appendf(out, out_sz, pos, "\\%c", *p))
                return false;
        } else if (*p < 0x20) {
            if (!appendf(out, out_sz, pos, "\\u%04x", *p))
                return false;
        } else if (!appendf(out, out_sz, pos, "%c", *p)) {
            return false;
        }
    }
    return appendf(out, out_sz, pos, "\"");
}

/* Bytes held back while rendering the (droppable) selection ledger so the
 * per-dimension completeness verdict and the document tail always fit. The
 * verdict is what a proof consumer reads; it must never be the thing that
 * falls off the end. */
#define PLAN_TAIL_RESERVE 1536
#define PLAN_GROUPS_LIST_MAX 48
#define PLAN_FILES_LIST_MAX 16

/* Emit a bounded view plus a root over the complete fixed-stride group set. */
static bool append_group_array(char *out, size_t out_sz, size_t *pos,
                               const char *name,
                               const char (*groups)[ZCL_DEVLOOP_GROUP_MAX],
                               size_t len)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)name, strlen(name));
    const unsigned char separator = '\0';
    sha3_256_write(&ctx, &separator, 1);
    for (size_t i = 0; i < len; i++) {
        sha3_256_write(&ctx, (const unsigned char *)groups[i],
                       strlen(groups[i]));
        const unsigned char newline = '\n';
        sha3_256_write(&ctx, &newline, 1);
    }
    unsigned char digest[32];
    char digest_string[65];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_string);
    if (!appendf(out, out_sz, pos, ",\"%s\":[", name))
        return false;
    size_t listed = len < PLAN_GROUPS_LIST_MAX ? len : PLAN_GROUPS_LIST_MAX;
    for (size_t i = 0; i < listed; i++) {
        if ((i && !appendf(out, out_sz, pos, ",")) ||
            !append_json_string(out, out_sz, pos, groups[i]))
            return false;
    }
    return appendf(out, out_sz, pos,
                   "],\"%s_listed\":%zu,\"%s_total\":%zu,"
                   "\"%s_abridged\":%s,\"%s_sha3\":\"%s\"",
                   name, listed, name, len, name,
                   listed < len ? "true" : "false", name, digest_string);
}

/* Materialize the C-owned proof plan as canonical full IDs. The catalog is
 * already deterministic and unique, so iterating it gives stable order and
 * deduplication without a second registry or a large scratch array. The SHA3
 * commits the COMPLETE set even when the bounded JSON view is abridged. */
static bool append_execution_set(const struct zcl_devloop_plan *plan,
                                 char *out, size_t out_sz, size_t *pos)
{
    static const unsigned char domain[] = "zcl.dev_execution_set.v1\0";
    bool valid = plan_group_ids_valid(plan);
    size_t total = 0;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain) - 1);
    if (valid) {
        for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
            const char *full = zcl_test_group_catalog_at(i);
            if (!plan_selects_full_group(plan, full))
                continue;
            sha3_256_write(&ctx, (const unsigned char *)full, strlen(full));
            const unsigned char newline = '\n';
            sha3_256_write(&ctx, &newline, 1);
            total++;
        }
    }
    unsigned char digest[32];
    char digest_string[65];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), digest_string);

    if (!appendf(out, out_sz, pos,
                 ",\"execution_selector\":\"exact\","
                 "\"execution_groups\":["))
        return false;
    size_t listed = 0;
    bool abridged = false;
    if (valid) {
        for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
            const char *full = zcl_test_group_catalog_at(i);
            if (!plan_selects_full_group(plan, full))
                continue;
            size_t saved = *pos;
            if (out_sz - *pos < PLAN_TAIL_RESERVE ||
                (listed > 0 && !appendf(out, out_sz, pos, ",")) ||
                !append_json_string(out, out_sz, pos, full)) {
                *pos = saved;
                out[*pos] = '\0';
                abridged = true;
                break;
            }
            listed++;
        }
    }
    return appendf(out, out_sz, pos,
                   "],\"execution_groups_listed\":%zu,"
                   "\"execution_groups_total\":%zu,"
                   "\"execution_groups_abridged\":%s,"
                   "\"execution_set_valid\":%s,"
                   "\"execution_set_sha3\":\"%s\"",
                   listed, total, abridged ? "true" : "false",
                   valid ? "true" : "false", digest_string);
}

static const char *plan_first_non_live_path(const struct zcl_devloop_plan *plan,
                                            const char *const *files,
                                            size_t file_count)
{
    if (!plan || !files || file_count == 0)
        return "";
    if (plan->consensus_risk) {
        for (size_t i = 0; i < file_count; i++)
            if (zcl_devloop_path_is_sealed_core(files[i]) ||
                path_is_consensus_risk(files[i]))
                return files[i];
    }
    const struct hotswap_eligible_entry *owner = hotswap_entry(files[0]);
    for (size_t i = 0; i < file_count; i++) {
        const struct hotswap_eligible_entry *entry = hotswap_entry(files[i]);
        if (!entry || (owner && entry != owner))
            return files[i];
    }
    /* Proof-closure refusal is a property of the exact batch rather than one
     * classifier path. `files` already carries that whole batch; choose its
     * first stable member as the diagnostic anchor. */
    return files[0];
}

/* Shared serializer for a fully-computed plan. When `include_closure` is set,
 * the closure_groups + closure_truncated fields are emitted too; path_groups is
 * always emitted (additive; existing readers ignore unknown keys). */
static size_t plan_json_body(const struct zcl_devloop_plan *plan,
                             const char *const *files, size_t file_count,
                             bool include_closure, char *out, size_t out_sz)
{
    size_t pos = 0;
    bool proof_admissible = true;
    const char *proof_why = "";
    /* Render against the SMALLER of the caller's buffer and the wire ceiling
     * the serving leaf declares (ZCL_DEVLOOP_PLAN_WIRE_MAX). The native
     * dev.test.plan handler hands us a 16 KB stack buffer, but the command
     * registry hard-fails any reply over the leaf's declared budget — it does
     * not truncate — so a document that fits the buffer and busts the budget
     * reaches the caller as an EMPTY error, losing the plan entirely. Clamping
     * here turns that cliff into an abridged explanation list. */
    if (out_sz > ZCL_DEVLOOP_PLAN_WIRE_MAX)
        out_sz = ZCL_DEVLOOP_PLAN_WIRE_MAX;
    if (!appendf(out, out_sz, &pos,
                 "{\"schema\":\"zcl.dev_plan.v1\",\"action\":") ||
        !append_json_string(out, out_sz, &pos, plan->action_name) ||
        !appendf(out, out_sz, &pos, ",\"reason\":") ||
        !append_json_string(out, out_sz, &pos, plan->reason) ||
        !appendf(out, out_sz, &pos,
                 ",\"consensus_risk\":%s,\"sealed_core\":%s,\"docs_only\":%s,"
                 "\"files\":[",
                 plan->consensus_risk ? "true" : "false",
                 plan->sealed_core ? "true" : "false",
                 plan->docs_only ? "true" : "false"))
        return 0;

    size_t files_listed = file_count < PLAN_FILES_LIST_MAX
        ? file_count : PLAN_FILES_LIST_MAX;
    for (size_t i = 0; i < files_listed; i++) {
        if ((i && !appendf(out, out_sz, &pos, ",")) ||
            !append_json_string(out, out_sz, &pos, files[i]))
            return 0;
    }
    if (!appendf(out, out_sz, &pos,
                 "],\"files_listed\":%zu,\"files_total\":%zu,"
                 "\"files_abridged\":%s,\"foreground_proof\":",
                 files_listed, file_count,
                 files_listed < file_count ? "true" : "false") ||
        !append_json_string(out, out_sz, &pos, plan->proof_group) ||
        !appendf(out, out_sz, &pos, ",\"probe\":") ||
        !append_json_string(out, out_sz, &pos, plan->probe_tool) ||
        !append_group_array(out, out_sz, &pos, "path_groups",
                            plan->path_groups, plan->path_groups_len))
        return 0;
    if (include_closure) {
        if (!append_group_array(out, out_sz, &pos, "closure_groups",
                                plan->closure_groups,
                                plan->closure_groups_len) ||
            !appendf(out, out_sz, &pos,
                     ",\"closure_truncated\":%s,\"closure_snapshot\":%s",
                     plan->closure_truncated ? "true" : "false",
                     plan->closure_snapshot ? "true" : "false"))
            return 0;

        /* C5: why each selected group is here. A reader answers "why is THIS
         * test in my plan" without opening a source file.
         *
         * Two different failures are reported separately here, because they
         * mean different things and only one of them is a soundness problem:
         *
         *   selections_truncated  the LEDGER overflowed — more groups were
         *                         selected than the plan can explain, so some
         *                         group in the arrays above has no recorded
         *                         reason at all. That is a real gap and it
         *                         refuses proof admission below.
         *   selections_abridged   the DOCUMENT ran out of wire budget — every
         *                         selection is recorded in the plan, this
         *                         rendering just stopped listing them. The
         *                         counts say how many exist and how many were
         *                         listed. Not a coverage gap, so it does not
         *                         refuse proof admission.
         *
         * PLAN_TAIL_RESERVE keeps enough room after the list for the
         * per-dimension completeness verdict, which is the part a proof
         * consumer actually reads; it must never be the thing that falls off
         * the end. */
        bool sel_abridged = false;
        size_t sel_listed = 0;
        if (!appendf(out, out_sz, &pos, ",\"selections\":["))
            return 0;
        for (size_t i = 0; i < plan->selections_len; i++) {
            const struct zcl_devloop_selection *s = &plan->selections[i];
            size_t saved = pos;
            if (out_sz - pos < PLAN_TAIL_RESERVE ||
                (i && !appendf(out, out_sz, &pos, ",")) ||
                !appendf(out, out_sz, &pos, "{\"group\":") ||
                !append_json_string(out, out_sz, &pos, s->group) ||
                !appendf(out, out_sz, &pos, ",\"dimension\":") ||
                !append_json_string(out, out_sz, &pos,
                                    zcl_devloop_dim_name(s->dim)) ||
                !appendf(out, out_sz, &pos, ",\"via\":") ||
                !append_json_string(out, out_sz, &pos, s->via) ||
                !appendf(out, out_sz, &pos, "}")) {
                pos = saved;
                out[pos] = '\0';
                sel_abridged = true;
                break;
            }
            sel_listed++;
        }
        if (!appendf(out, out_sz, &pos,
                     "],\"selections_listed\":%zu,\"selections_total\":%zu,"
                     "\"selections_abridged\":%s,\"selections_truncated\":%s,"
                     "\"dimensions\":[",
                     sel_listed, plan->selections_len,
                     sel_abridged ? "true" : "false",
                     plan->selections_truncated ? "true" : "false"))
            return 0;
        /* C5: and what might be MISSING — one row per dimension, each naming
         * its own completeness and the reason it is not complete. */
        for (int d = 0; d < ZCL_DEVLOOP_DIM__COUNT; d++) {
            const struct zcl_devloop_dim_state *st = &plan->dims[d];
            if ((d && !appendf(out, out_sz, &pos, ",")) ||
                !appendf(out, out_sz, &pos, "{\"name\":") ||
                !append_json_string(out, out_sz, &pos,
                                    zcl_devloop_dim_name(
                                        (enum zcl_devloop_dim)d)) ||
                !appendf(out, out_sz, &pos, ",\"status\":") ||
                !append_json_string(out, out_sz, &pos,
                                    zcl_devloop_dim_status_name(st->status)) ||
                !appendf(out, out_sz, &pos, ",\"reason\":") ||
                !append_json_string(out, out_sz, &pos,
                                    st->reason ? st->reason : "") ||
                !appendf(out, out_sz, &pos, "}"))
                return 0;
        }
        /* C4: the one field a caller that needs PROOF must read. False means
         * the groups listed above still RUN, but they are not evidence that
         * the change is covered. */
        proof_admissible = zcl_devloop_plan_proof_admissible(plan,
                                                              &proof_why);
        if (!appendf(out, out_sz, &pos, "],\"proof_admissible\":%s,"
                     "\"proof_refusal\":",
                     proof_admissible ? "true" : "false") ||
            !append_json_string(out, out_sz, &pos, proof_why))
            return 0;
    }
    /* Render this bounded, abridgable list after all mandatory closure and
     * completeness fields. Its reserve now protects only the fixed document
     * tail, so a valid multi-file plan cannot disappear merely because an
     * earlier optional execution listing consumed space needed by closure. */
    if (!append_execution_set(plan, out, out_sz, &pos))
        return 0;

    /* Make the classification actionable without asking a new agent to infer
     * whether `action=hotswap` was later refused by proof admission. A
     * path-only document reports classification eligibility; the native
     * acting path always requests closure and therefore also binds this bit to
     * proof_admissible. Every refusal carries its stable code plus the exact
     * first changed path (the complete batch remains in `files`). */
    bool live_eligible = plan->action == ZCL_DEVLOOP_HOTSWAP &&
                         (!include_closure || proof_admissible);
    const char *why_not_live = live_eligible
        ? ""
        : (plan->action == ZCL_DEVLOOP_HOTSWAP && include_closure
            ? proof_why
            : plan->reason);
    const char *why_not_live_path = live_eligible
        ? ""
        : plan_first_non_live_path(plan, files, file_count);
    const char *next_action = file_count == 0
        ? "edit one C23 file"
        : (plan->docs_only
            ? "make lint"
            : "z23-dev dev begin");
    if (!appendf(out, out_sz, &pos, ",\"live_eligible\":%s,\"why_not_live\":",
                 live_eligible ? "true" : "false") ||
        !append_json_string(out, out_sz, &pos, why_not_live) ||
        !appendf(out, out_sz, &pos, ",\"why_not_live_path\":") ||
        !append_json_string(out, out_sz, &pos, why_not_live_path) ||
        !appendf(out, out_sz, &pos, ",\"agent_next_action\":") ||
        !append_json_string(out, out_sz, &pos, next_action) ||
        !appendf(out, out_sz, &pos, "}"))
        return 0;
    return pos;
}

size_t zcl_devloop_plan_json(const char *const *files, size_t file_count,
                             char *out, size_t out_sz)
{
    struct zcl_devloop_plan plan;
    if (!out || out_sz == 0 ||
        !zcl_devloop_plan_files(files, file_count, &plan))
        return 0;
    return plan_json_body(&plan, files, file_count, false, out, out_sz);
}

size_t zcl_devloop_plan_json_closure(const char *repo_root,
                                     const char *const *files,
                                     size_t file_count, char *out,
                                     size_t out_sz)
{
    struct zcl_devloop_plan plan;
    if (!out || out_sz == 0 ||
        !zcl_devloop_plan_files(files, file_count, &plan))
        return 0;
    /* Closure is best-effort: a failure/unavailable index leaves the path
     * floor intact, so we still emit a valid plan (closure_groups empty). */
    (void)zcl_devloop_plan_add_closure(repo_root, files, file_count, &plan);
    return plan_json_body(&plan, files, file_count, true, out, out_sz);
}

bool zcl_devloop_unseal_token_present(const char *repo_root)
{
    /* READ-ONLY presence check of <repo_root>/.core-unseal-token — the
     * one-shot token `make core-unseal REASON=…` mints. We deliberately do
     * NOT open, mint, or unlink it: `make core-seal` is the sole consumer, so
     * one unseal authorizes exactly one landed commit (which may span several
     * iterative dev-cycles while the author converges the sealed edit), never
     * one dev-cycle. Path traversal is a non-issue: repo_root is the native
     * source root, not attacker input. */
    const char *root = (repo_root && repo_root[0]) ? repo_root : ".";
    char path[ZCL_DEVLOOP_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.core-unseal-token", root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    return access(path, F_OK) == 0;
}

size_t zcl_devloop_refusal_json(const char *const *files, size_t file_count,
                                char *out, size_t out_sz)
{
    size_t pos = 0;
    if (!out || out_sz == 0 || (file_count > 0 && !files))
        return 0;

    /* A zcl.dev_cycle.v1 verdict whose status is the new "refused" — the
     * structured envelope the fast loop emits (stdout + persisted verdict)
     * when a changed-file set touches the sealed consensus core with no valid
     * unseal token. "Sealed != frozen": the envelope always names the
     * elevated procedure, so it never dead-ends. */
    if (!appendf(out, out_sz, &pos,
                 "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"native\","
                 "\"status\":\"refused\",\"reason\":\"sealed_consensus_core\","
                 "\"paths\":["))
        return 0;

    /* Only the sealed members that actually triggered the refusal. */
    bool first = true;
    for (size_t i = 0; i < file_count; i++) {
        if (!zcl_devloop_path_is_sealed_core(files[i]))
            continue;
        if ((!first && !appendf(out, out_sz, &pos, ",")) ||
            !append_json_string(out, out_sz, &pos, files[i]))
            return 0;
        first = false;
    }

    if (!appendf(out, out_sz, &pos,
                 "],\"manifest\":\"core/MANIFEST.sha3\","
                 "\"law\":\"docs/CONSENSUS_PARITY_DOCTRINE.md\","
                 "\"unseal\":\"make core-unseal REASON=... "
                 "(owner-gated; see core/UNSEAL.md)\","
                 "\"elevated_procedure\":\"full make ci + copy-prove + "
                 "owner-gated deploy\","
                 "\"why_not_live\":\"sealed consensus core requires the "
                 "owner-gated unseal and elevated proof procedure\","
                 "\"agent_next_action\":\"edit outside core/, or run the "
                 "owner-gated unseal ritual (make core-unseal) for a "
                 "consensus-parity fix\"}"))
        return 0;
    return pos;
}
