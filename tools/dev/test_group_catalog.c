/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve canonical test IDs and exact proof execution sets. */

#include "test_group_catalog.h"
#include "platform/glob_match.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const g_test_groups[] = {
#define ZCL_TEST_GROUP(name) "test_" #name,
#define ZCL_SPEC_GROUP(name) "spec_" #name,
#include "test_group_catalog.def"
#undef ZCL_SPEC_GROUP
#undef ZCL_TEST_GROUP
};

static const char *const g_semantic_leaf_sources[] = {
#define ZCL_TEST_SEMANTIC_LEAF(name) "tests/harness/src/test_" #name ".c",
#include "test_semantic_leaves.def"
#undef ZCL_TEST_SEMANTIC_LEAF
    NULL, /* Zero declared leaves is the safe, valid state. */
};

struct proof_family {
    const char *plan_id;
    const char *full_id_glob;
};

static const struct proof_family g_proof_families[] = {
#define ZCL_TEST_PROOF_FAMILY(plan_id_, glob_) {plan_id_, glob_},
#include "test_proof_families.def"
#undef ZCL_TEST_PROOF_FAMILY
};

static const char *const g_integration_only[] = {
#define ZCL_TEST_INTEGRATION_ONLY(full_id_) full_id_,
#include "test_integration_only.def"
#undef ZCL_TEST_INTEGRATION_ONLY
    NULL,
};

struct proof_contract_row {
    const char *full_id;
    enum zcl_test_proof_contract contract;
};

static const struct proof_contract_row g_proof_contracts[] = {
#define ZCL_TEST_PROOF_CONTRACT(full_id_, contract_) {full_id_, contract_},
#include "test_proof_contracts.def"
#undef ZCL_TEST_PROOF_CONTRACT
};

size_t zcl_test_group_catalog_count(void)
{
    return sizeof(g_test_groups) / sizeof(g_test_groups[0]);
}

const char *zcl_test_group_catalog_at(size_t index)
{
    return index < zcl_test_group_catalog_count() ? g_test_groups[index] : NULL;
}

/* Plan selection asks "is this id in the catalog" and "which catalog row does
 * this id name" once per (catalog row x plan group) pair. A linear strcmp scan
 * per question made one plan ~3e9 instructions (1178 rows). The catalog is
 * immutable, so sort row pointers once and answer by binary search. */
#define CATALOG_ROWS (sizeof(g_test_groups) / sizeof(g_test_groups[0]))
static const char *g_sorted_groups[CATALOG_ROWS];
static pthread_once_t g_sorted_once = PTHREAD_ONCE_INIT;

static int catalog_row_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void catalog_sort_once(void)
{
    for (size_t i = 0; i < CATALOG_ROWS; i++)
        g_sorted_groups[i] = g_test_groups[i];
    qsort(g_sorted_groups, CATALOG_ROWS, sizeof(g_sorted_groups[0]),
          catalog_row_cmp);
}

/* Rows equal to `id`, so a duplicated catalog row still reads as ambiguous. */
static size_t catalog_matches(const char *id, const char **hit)
{
    pthread_once(&g_sorted_once, catalog_sort_once);
    size_t lo = 0, hi = CATALOG_ROWS;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(g_sorted_groups[mid], id) < 0) lo = mid + 1;
        else hi = mid;
    }
    size_t n = 0;
    while (lo + n < CATALOG_ROWS && strcmp(g_sorted_groups[lo + n], id) == 0)
        n++;
    if (n > 0 && hit)
        *hit = g_sorted_groups[lo];
    return n;
}

bool zcl_test_group_catalog_contains(const char *full_id)
{
    if (!full_id || !full_id[0])
        return false;
    return catalog_matches(full_id, NULL) > 0;
}

bool zcl_test_group_requires_exclusive_run(const char *full_id)
{
    if (!full_id || !zcl_test_group_catalog_contains(full_id))
        return false;
    return strcmp(full_id, "test_command_registry_latency") == 0 ||
           strcmp(full_id, "test_sapling_crypto") == 0 ||
           strcmp(full_id, "test_vcs_core") == 0 ||
           strcmp(full_id, "test_golden_dev_cycle") == 0 ||
           strcmp(full_id, "test_kill9_recovery") == 0 ||
           strcmp(full_id, "test_validate_parallel_determinism") == 0 ||
           strcmp(full_id, "test_simnet_perf") == 0 ||
           strcmp(full_id, "test_replay_canary_verdict") == 0 ||
           strcmp(full_id, "test_test_group_selector") == 0;
}

enum zcl_test_proof_contract
zcl_test_group_proof_contract(const char *full_id)
{
    if (!full_id || !zcl_test_group_catalog_contains(full_id))
        return ZCL_TEST_PROOF_NONE;
    for (size_t i = 0; i < sizeof(g_proof_contracts) /
                            sizeof(g_proof_contracts[0]); i++)
        if (strcmp(g_proof_contracts[i].full_id, full_id) == 0)
            return g_proof_contracts[i].contract;
    return ZCL_TEST_PROOF_NONE;
}

bool zcl_test_proof_contract_environment(
    enum zcl_test_proof_contract contract,
    const char **env_name, const char **env_value)
{
    if (env_name)
        *env_name = NULL;
    if (env_value)
        *env_value = NULL;
    if (!env_name || !env_value) {
        fprintf(stderr,
                "test_group_catalog: proof contract environment output missing\n");
        return false;
    }
    switch (contract) {
    case ZCL_TEST_PROOF_NONE:
        return true;
    case ZCL_TEST_PROOF_STRESS:
        *env_name = "ZCL_STRESS_TESTS";
        break;
    case ZCL_TEST_PROOF_EVENT_LOG_KILL9:
        *env_name = "ZCL_EVENT_LOG_KILL9_FUZZ";
        break;
    case ZCL_TEST_PROOF_EVENT_LOG_BENCH:
        /* The bounded push proof is distinct from the full standalone
         * ZCL_EVENT_LOG_BENCH=1 measurement. */
        *env_name = "ZCL_EVENT_LOG_BENCH_PROOF";
        break;
    case ZCL_TEST_PROOF_GOLDEN_TIMING:
        *env_name = "ZCL_GOLDEN_TIMING_STRICT";
        break;
    default:
        fprintf(stderr,
                "test_group_catalog: unknown proof contract value=%d\n",
                (int)contract);
        return false;
    }
    *env_value = "1";
    return true;
}

bool zcl_test_group_proof_contracts_valid(void)
{
    for (size_t i = 0; i < sizeof(g_proof_contracts) /
                            sizeof(g_proof_contracts[0]); i++) {
        const char *env_name = NULL;
        const char *env_value = NULL;
        if (!zcl_test_group_catalog_contains(g_proof_contracts[i].full_id) ||
            g_proof_contracts[i].contract <= ZCL_TEST_PROOF_NONE ||
            g_proof_contracts[i].contract > ZCL_TEST_PROOF_GOLDEN_TIMING ||
            !zcl_test_proof_contract_environment(
                g_proof_contracts[i].contract, &env_name, &env_value) ||
            !env_name || !env_value)
            return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(g_proof_contracts[i].full_id,
                       g_proof_contracts[j].full_id) == 0)
                return false;
    }
    return true;
}

bool zcl_test_group_source_is_semantic_leaf(const char *path)
{
    if (!path || !path[0])
        return false;
    for (size_t i = 0; g_semantic_leaf_sources[i] != NULL; i++)
        if (strcmp(g_semantic_leaf_sources[i], path) == 0)
            return true;
    return false;
}

bool zcl_test_group_resolve_exact(
    const char *id, char out[ZCL_TEST_GROUP_FULL_MAX])
{
    if (!id || !id[0] || !out)
        return false;
    const char *hit = NULL;
    size_t hits = 0;
    char test_id[ZCL_TEST_GROUP_FULL_MAX];
    char spec_id[ZCL_TEST_GROUP_FULL_MAX];
    int tn = snprintf(test_id, sizeof(test_id), "test_%s", id);
    int sn = snprintf(spec_id, sizeof(spec_id), "spec_%s", id);
    hits += catalog_matches(id, &hit);
    if (tn > 0 && (size_t)tn < sizeof(test_id) && strcmp(test_id, id) != 0)
        hits += catalog_matches(test_id, &hit);
    if (sn > 0 && (size_t)sn < sizeof(spec_id) && strcmp(spec_id, id) != 0)
        hits += catalog_matches(spec_id, &hit);
    if (hits != 1 || strlen(hit) >= ZCL_TEST_GROUP_FULL_MAX)
        return false;
    snprintf(out, ZCL_TEST_GROUP_FULL_MAX, "%s", hit);
    return true;
}

static bool declared_family_selects(const char *plan_id, const char *full_id)
{
    for (size_t i = 0; i < sizeof(g_proof_families) /
                            sizeof(g_proof_families[0]); i++) {
        if (strcmp(g_proof_families[i].plan_id, plan_id) == 0 &&
            platform_glob_match(g_proof_families[i].full_id_glob,
                                full_id, false))
            return true;
    }
    return false;
}

bool zcl_test_group_plan_selects(const char *plan_id, const char *full_id)
{
    char primary[ZCL_TEST_GROUP_FULL_MAX];
    if (!plan_id || !full_id ||
        !zcl_test_group_resolve_exact(plan_id, primary) ||
        !zcl_test_group_catalog_contains(full_id))
        return false;
    if (strcmp(plan_id, primary) == 0)
        return strcmp(full_id, primary) == 0;
    return strstr(full_id, plan_id) != NULL ||
           declared_family_selects(plan_id, full_id);
}

bool zcl_test_group_family_expand(const char *plan_id,
                                  zcl_test_group_visit_fn visit, void *ctx)
{
    char primary[ZCL_TEST_GROUP_FULL_MAX];
    if (!zcl_test_group_resolve_exact(plan_id, primary))
        return false;
    if (visit && !visit(primary, ctx))
        return false;
    for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
        const char *full = g_test_groups[i];
        if (strcmp(full, primary) == 0 ||
            !declared_family_selects(plan_id, full))
            continue;
        if (visit && !visit(full, ctx))
            return false;
    }
    return true;
}

bool zcl_test_group_is_integration_only(const char *full_id)
{
    if (!zcl_test_group_catalog_contains(full_id))
        return false;
    for (size_t i = 0; g_integration_only[i] != NULL; i++)
        if (strcmp(g_integration_only[i], full_id) == 0)
            return true;
    return false;
}

bool zcl_test_group_integration_policy_valid(void)
{
    for (size_t i = 0; g_integration_only[i] != NULL; i++) {
        if (!zcl_test_group_catalog_contains(g_integration_only[i]))
            return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(g_integration_only[i], g_integration_only[j]) == 0)
                return false;
    }
    return true;
}

static size_t expand_plan(
    const char *const *plan_ids, size_t plan_count,
    char (*out)[ZCL_TEST_GROUP_FULL_MAX], size_t cap, bool *truncated,
    bool immediate_only)
{
    if (truncated)
        *truncated = false;
    if ((!plan_ids && plan_count > 0) || (!out && cap > 0) || !truncated ||
        (immediate_only && !zcl_test_group_integration_policy_valid()))
        return SIZE_MAX;
    for (size_t p = 0; p < plan_count; p++) {
        char primary[ZCL_TEST_GROUP_FULL_MAX];
        if (!zcl_test_group_resolve_exact(plan_ids[p], primary))
            return SIZE_MAX;
    }
    size_t total = 0;
    for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
        bool selected = false;
        for (size_t p = 0; p < plan_count; p++) {
            if (zcl_test_group_plan_selects(plan_ids[p], g_test_groups[i])) {
                selected = true;
                break;
            }
        }
        if (!selected)
            continue;
        if (immediate_only &&
            zcl_test_group_is_integration_only(g_test_groups[i]))
            continue;
        if (total < cap)
            snprintf(out[total], ZCL_TEST_GROUP_FULL_MAX, "%s", g_test_groups[i]);
        total++;
    }
    *truncated = total > cap;
    return total;
}

size_t zcl_test_group_expand_plan(
    const char *const *plan_ids, size_t plan_count,
    char (*out)[ZCL_TEST_GROUP_FULL_MAX], size_t cap, bool *truncated)
{
    return expand_plan(plan_ids, plan_count, out, cap, truncated, false);
}

size_t zcl_test_group_expand_plan_immediate(
    const char *const *plan_ids, size_t plan_count,
    char (*out)[ZCL_TEST_GROUP_FULL_MAX], size_t cap, bool *truncated)
{
    return expand_plan(plan_ids, plan_count, out, cap, truncated, true);
}
