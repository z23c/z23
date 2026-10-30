/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_dev_proof_observation_index — regressions for the box-level
 * receiver index of signed observation leaves (tools/dev/
 * dev_proof_observation_index.c, canonical lifecycle item 3 in
 * docs/work/FORWARD_PLAN.md).
 *
 * Reuse of unchanged unit evidence across candidates is permitted only
 * when the exact input closure and the receiver's policy permit it. The
 * receiver's half of that contract is a durable, verified basis of the
 * observations this box has seen. Explicit callers fold a pair's durable
 * observation CAS into that index; these cases
 * pin the merge, the self-verifying row format, the named refusals, and
 * the classification parity with the receiver-side lookup. */

#include "test/test_core.h"

#include "dev_proof_observation.h"
#include "dev_proof_observation_index.h"
#include "dev_proof_observation_lookup.h"
#include "dev_proof_signer.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include "platform/directory_compat.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define DPOI_STATE_ENV "ZCL_STATE_ROOT"
#else
#define DPOI_STATE_ENV "XDG_STATE_HOME"
#endif

static char g_dpoi_state[4096];
static char g_dpoi_saved_state[4096];
static bool g_dpoi_had_state;

static bool dpoi_isolate(const char *tag)
{
    char base[4096 - 64];
    test_make_tmpdir(base, sizeof(base), "dev_proof_obs_index", tag);
    (void)snprintf(g_dpoi_state, sizeof(g_dpoi_state), "%s/state", base);
    if (!g_dpoi_had_state && getenv(DPOI_STATE_ENV)) {
        g_dpoi_had_state = true;
        (void)snprintf(g_dpoi_saved_state, sizeof(g_dpoi_saved_state), "%s",
                       getenv(DPOI_STATE_ENV));
    }
    if (!platform_directory_ensure(g_dpoi_state, 0700)) return false;
    return setenv(DPOI_STATE_ENV, g_dpoi_state, 1) == 0;
}

static void dpoi_restore(void)
{
    if (g_dpoi_had_state)
        setenv(DPOI_STATE_ENV, g_dpoi_saved_state, 1);
    else
        unsetenv(DPOI_STATE_ENV);
}

static void dpoi_key(uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], uint8_t seed)
{
    for (size_t i = 0; i < ZCL_DEV_VERDICT_LEAF_KEY_BYTES; i++)
        key[i] = (uint8_t)(seed * 29u + (uint8_t)i);
}

static bool dpoi_record_verdict(const char *store, uint8_t seed,
    const char *group, enum zcl_dev_verdict_leaf_verdict verdict,
    uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    dpoi_key(key, seed);
    char why[96] = {0};
    return zcl_dev_observation_record(store, key, group, verdict, seed, root,
                                      why, sizeof(why)) &&
           why[0] == '\0';
}

static bool dpoi_record(const char *store, uint8_t seed, const char *group,
                        uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    return dpoi_record_verdict(store, seed, group, ZCL_DEV_VERDICT_LEAF_PASS,
                               root);
}

/* Three leaves in one store, returned roots in group order. */
static bool dpoi_store3(const char *store, uint8_t roots[3][32])
{
    static const char *const groups[3] = {
        "test_obs_index_alpha", "test_obs_index_beta", "test_obs_index_gamma"};
    if (!platform_directory_ensure(store, 0700)) return false;
    for (size_t i = 0; i < 3; i++)
        if (!dpoi_record(store, (uint8_t)(i + 1), groups[i], roots[i]))
            return false;
    return true;
}

static bool dpoi_sorted_unique(const struct zcl_dev_observation_leaf *leaves,
                               size_t count)
{
    for (size_t i = 1; i < count; i++)
        if (memcmp(leaves[i - 1].root, leaves[i].root, 32) >= 0)
            return false;
    return true;
}

static int dpoi_row_cmp(const void *a, const void *b)
{
    return memcmp(a, b, ZCL_DEV_PROOF_ROOT_BYTES);
}

/* Preserve one real leaf and fill the remaining bounded index with distinct,
 * byte-bound but signature-ineligible observations. Eligibility is separate
 * from the union: these rows must remain present rather than be discarded. */
static bool dpoi_full_index(const char *path,
    const struct zcl_dev_verdict_leaf_v1 *first)
{
    const size_t count = ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS;
    const size_t bytes = count * ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
    uint8_t *rows = zcl_malloc(bytes, "observation-index-cap-fixture");
    if (!rows) return false;
    char why[128] = {0};
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        struct zcl_dev_verdict_leaf_v1 leaf = *first;
        leaf.elapsed_ms += i;
        uint8_t *row = rows + i * ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES;
        ok = zcl_dev_verdict_leaf_root(&leaf, row, why, sizeof(why)) &&
             zcl_dev_verdict_leaf_serialize(&leaf,
                 row + ZCL_DEV_PROOF_ROOT_BYTES, why, sizeof(why));
    }
    if (ok)
        qsort(rows, count, ZCL_DEV_OBSERVATION_INDEX_ROW_BYTES, dpoi_row_cmp);
    uint8_t header[ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES] = {0};
    memcpy(header, "Z23OIDX", 7);
    zcl_write_u32_le(header + 8, 1);
    zcl_write_u32_le(header + 12, (uint32_t)count);
    FILE *f = ok ? fopen(path, "wb") : NULL;
    if (!f) ok = false;
    if (f) {
        ok = fwrite(header, 1, sizeof(header), f) == sizeof(header) &&
             fwrite(rows, 1, bytes, f) == bytes;
        if (fclose(f) != 0) ok = false;
    }
    free(rows);
    return ok;
}

static int test_dpoi_union_at_cap(void)
{
    int failures = 0;
    char root[4096], store[4096], novel[4096], index_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_obs_index", "cap");
    if (!dpoi_isolate("cap")) return 1;
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(novel, sizeof(novel), "%s/novel", root);
    (void)snprintf(index_path, sizeof(index_path), "%s/index", root);
    struct zcl_dev_observation_leaf *leaves = NULL;
    size_t count = 0;
    bool present = false;
    char why[128] = {0};
    TEST_CASE("dev_proof_obs_index: duplicates at capacity merge; new roots refuse") {
        uint8_t emitted[32];
        ASSERT(platform_directory_ensure(store, 0700));
        ASSERT(dpoi_record(store, 1, "test_obs_index_cap", emitted));
        ASSERT(zcl_dev_observation_enumerate(store, &leaves, &count,
                                             &present, why, sizeof(why)));
        ASSERT(present && count == 1);
        ASSERT(dpoi_full_index(index_path, &leaves[0].leaf));
        zcl_dev_observation_release(leaves);
        leaves = NULL;
        /* Both unchanged merges are no-ops despite the full index. */
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        ASSERT(platform_directory_ensure(novel, 0700));
        ASSERT(dpoi_record(novel, 2, "test_obs_index_novel", emitted));
        ASSERT(!zcl_dev_observation_index_merge(index_path, novel,
                                                why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_OBSERVATION_INDEX_WHY_TOO_MANY) == 0);
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why, sizeof(why)));
        ASSERT(present && count == ZCL_DEV_OBSERVATION_INDEX_MAX_ROWS);
        ASSERT(dpoi_sorted_unique(leaves, count));
    }
    TEST_END
    zcl_dev_observation_release(leaves);
    dpoi_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoi_merge_and_load(void)
{
    int failures = 0;
    char root[4096], store[4096], index_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_obs_index", "merge");
    if (!dpoi_isolate("merge")) return 1;
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(index_path, sizeof(index_path), "%s/index", root);
    uint8_t emitted[3][32];
    TEST_CASE("dev_proof_obs_index: merge folds a pair store into verified rows") {
        ASSERT(dpoi_store3(store, emitted));
        char why[128] = {0};
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        ASSERT(why[0] == '\0');
        struct zcl_dev_observation_leaf *leaves = NULL;
        size_t count = 0;
        bool present = false;
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why,
                                              sizeof(why)));
        ASSERT(present);
        ASSERT(count == 3);
        ASSERT(dpoi_sorted_unique(leaves, count));
        for (size_t i = 0; i < count; i++) {
            ASSERT(leaves[i].eligible);
            uint8_t derived[32];
            ASSERT(zcl_dev_verdict_leaf_root(&leaves[i].leaf, derived,
                                             why, sizeof(why)));
            ASSERT(memcmp(derived, leaves[i].root, 32) == 0);
        }
        zcl_dev_observation_release(leaves);

        /* Re-merging the same store is an exact no-op (union by root). */
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why,
                                              sizeof(why)));
        ASSERT(present && count == 3);
        zcl_dev_observation_release(leaves);

        /* A second pair's store unions in, still sorted and unique. */
        char store_b[4096];
        (void)snprintf(store_b, sizeof(store_b), "%s/store_b", root);
        ASSERT(platform_directory_ensure(store_b, 0700));
        uint8_t root_b1[32], root_b2[32];
        /* Seed 9 includes LF and Ctrl-Z in the exact serialized key. */
        ASSERT(dpoi_record(store_b, 9, "test_obs_index_delta", root_b1));
        ASSERT(dpoi_record(store_b, 8, "test_obs_index_epsilon", root_b2));
        ASSERT(zcl_dev_observation_index_merge(index_path, store_b,
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why,
                                              sizeof(why)));
        ASSERT(present && count == 5);
        ASSERT(dpoi_sorted_unique(leaves, count));
        uint8_t expected_key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
        dpoi_key(expected_key, 9);
        bool found_binary_key = false;
        for (size_t i = 0; i < count; i++) {
            if (memcmp(leaves[i].root, root_b1, 32) == 0) {
                ASSERT(memcmp(leaves[i].leaf.key, expected_key,
                              sizeof(expected_key)) == 0);
                found_binary_key = true;
            }
        }
        ASSERT(found_binary_key);
        zcl_dev_observation_release(leaves);

        /* Merging an absent store changes nothing. */
        ASSERT(zcl_dev_observation_index_merge(index_path, "/nonexistent",
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why,
                                              sizeof(why)));
        ASSERT(present && count == 5);
        zcl_dev_observation_release(leaves);
        ASSERT(zcl_dev_observation_index_merge(index_path, store_b,
                                               why, sizeof(why)));
    }
    TEST_END
    dpoi_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoi_refusals(void)
{
    int failures = 0;
    char root[4096], store[4096], index_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_obs_index", "refuse");
    if (!dpoi_isolate("refuse")) return 1;
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(index_path, sizeof(index_path), "%s/index", root);
    uint8_t emitted[3][32];
    TEST_CASE("dev_proof_obs_index: corrupt bytes refuse by name, never re-derived") {
        ASSERT(dpoi_store3(store, emitted));
        char why[128] = {0};
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        /* Corrupt one root byte: the row no longer binds to its wire. */
        FILE *f = fopen(index_path, "r+b");
        ASSERT(f != NULL);
        ASSERT(fseek(f, (long)ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES, SEEK_SET) == 0);
        int ch = fgetc(f);
        ASSERT(ch != EOF);
        ASSERT(fseek(f, (long)ZCL_DEV_OBSERVATION_INDEX_WIRE_BYTES, SEEK_SET) == 0);
        ASSERT(fputc(ch ^ 0xff, f) != EOF);
        (void)fclose(f);

        struct zcl_dev_observation_leaf *leaves = NULL;
        size_t count = 0;
        bool present = false;
        ASSERT(!zcl_dev_observation_index_load(index_path, &leaves, &count,
                                               &present, why,
                                               sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID) == 0);
        ASSERT(leaves == NULL);
        why[0] = 0;
        ASSERT(!zcl_dev_observation_index_merge(index_path, store,
                                                why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_OBSERVATION_INDEX_WHY_INVALID) == 0);
        /* A refused merge must release its lock for the next writer. */
        ASSERT(remove(index_path) == 0);
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
    }
    TEST_END
    dpoi_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoi_lookup_parity(void)
{
    int failures = 0;
    char root[4096], store[4096], index_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_obs_index", "lookup");
    if (!dpoi_isolate("lookup")) return 1;
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(index_path, sizeof(index_path), "%s/index", root);
    uint8_t emitted[3][32];
    TEST_CASE("dev_proof_obs_index: the index classifies like the pair store") {
        ASSERT(dpoi_store3(store, emitted));
        char why[128] = {0};
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        struct zcl_dev_observation_leaf *leaves = NULL;
        size_t count = 0;
        bool present = false;
        ASSERT(zcl_dev_observation_index_load(index_path, &leaves, &count,
                                              &present, why,
                                              sizeof(why)));
        ASSERT(present && count == 3);

        struct zcl_dev_observation_object objects[4];
        uint8_t wires[4][ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
        for (size_t i = 0; i < count; i++) {
            ASSERT(zcl_dev_verdict_leaf_serialize(&leaves[i].leaf, wires[i],
                                                  why, sizeof(why)));
            (void)memcpy(objects[i].root, leaves[i].root,
                         ZCL_DEV_PROOF_ROOT_BYTES);
            objects[i].wire = wires[i];
            objects[i].wire_len = ZCL_DEV_VERDICT_LEAF_WIRE_BYTES;
        }
        uint8_t own[ZCL_DEV_PROOF_PUBKEY_BYTES];
        bool have_key = false;
        const char *signer_why = NULL;
        ASSERT(zcl_dev_proof_signer_public(own, &have_key, &signer_why) &&
               have_key);
        struct zcl_dev_observation_domain domain = {0};
        (void)memcpy(domain.producer_pubkey, own, sizeof(own));
        memset(domain.domain_root, 0x5c, sizeof(domain.domain_root));

        struct zcl_dev_observation_query query = {0};
        dpoi_key(query.key, 2);
        query.group = "test_obs_index_beta";
        query.now_unix = (uint64_t)platform_time_wall_unix();
        query.max_age_seconds = 3600;
        query.max_future_seconds = 600;
        query.required_independent_domains = 1;
        struct zcl_dev_observation_result_detail detail = {0};
        zcl_dev_observation_lookup(&query, objects, count, true, &domain, 1,
                                   &detail);
        ASSERT(detail.result == ZCL_DEV_OBSERVATION_PASS_EVIDENCE);
        ASSERT(detail.pass_count == 1);

        /* A receiver that demands two independent domains does not have
         * them from one key, even listed twice: the reuse gate stays
         * named instead of counting one signer twice. */
        struct zcl_dev_observation_domain two_same[2];
        two_same[0] = domain;
        two_same[1] = domain;
        query.required_independent_domains = 2;
        memset(&detail, 0, sizeof(detail));
        zcl_dev_observation_lookup(&query, objects, count, true, two_same, 2,
                                   &detail);
        ASSERT(detail.result == ZCL_DEV_OBSERVATION_INSUFFICIENT_DOMAINS);

        /* An input closure the index never saw is a miss, not evidence. */
        query.required_independent_domains = 1;
        dpoi_key(query.key, 99);
        memset(&detail, 0, sizeof(detail));
        zcl_dev_observation_lookup(&query, objects, count, true, &domain, 1,
                                   &detail);
        ASSERT(detail.result == ZCL_DEV_OBSERVATION_MISS);

        zcl_dev_observation_release(leaves);
    }
    TEST_END
    dpoi_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpoi_query(void)
{
    int failures = 0;
    char root[4096], store[4096], index_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_obs_index", "query");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(index_path, sizeof(index_path), "%s/index", root);
    uint8_t emitted[3][32];
    TEST_CASE("dev_proof_obs_index: box-level query over empty, full and conflicting indexes") {
        ASSERT(dpoi_isolate("query"));
        char why[128] = {0};
        struct zcl_dev_observation_query_report report = {0};

        /* An absent index is an honest empty answer. */
        ASSERT(zcl_dev_observation_index_query(index_path, NULL, &report,
                                               why, sizeof(why)));
        ASSERT(report.total == 0 && report.groups_named == 0);
        ASSERT(!report.truncated && report.conflicted_groups == 0);

        ASSERT(dpoi_store3(store, emitted));
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_query(index_path, NULL, &report,
                                               why, sizeof(why)));
        ASSERT(report.total == 3 && report.eligible == 3);
        ASSERT(report.ineligible == 0);
        ASSERT(report.oldest_observed_unix != 0);
        ASSERT(report.newest_observed_unix >= report.oldest_observed_unix);
        ASSERT(report.groups_named == 3);
        ASSERT(!report.truncated);
        /* Deterministic order: sorted by group name. */
        ASSERT(strcmp(report.groups[0].group, "test_obs_index_alpha") == 0);
        ASSERT(strcmp(report.groups[1].group, "test_obs_index_beta") == 0);
        ASSERT(strcmp(report.groups[2].group, "test_obs_index_gamma") == 0);
        for (uint32_t i = 0; i < report.groups_named; i++) {
            ASSERT(report.groups[i].verdict == ZCL_DEV_VERDICT_LEAF_PASS);
            ASSERT(report.groups[i].observations == 1);
            ASSERT(!report.groups[i].conflict);
        }

        /* A preserved contradiction is named, never collapsed. */
        uint8_t fail_root[32];
        ASSERT(dpoi_record_verdict(store, 1, "test_obs_index_alpha",
                                   ZCL_DEV_VERDICT_LEAF_FAIL, fail_root));
        ASSERT(zcl_dev_observation_index_merge(index_path, store,
                                               why, sizeof(why)));
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_observation_index_query(index_path, NULL, &report,
                                               why, sizeof(why)));
        ASSERT(report.total == 4 && report.eligible == 4);
        ASSERT(report.conflicted_groups == 1);
        ASSERT(strcmp(report.groups[0].group, "test_obs_index_alpha") == 0);
        ASSERT(report.groups[0].conflict);
        ASSERT(report.groups[0].observations == 2);
        ASSERT(report.groups[1].observations == 1);

        /* The group filter scopes every count to one exact group. */
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_observation_index_query(index_path,
                                               "test_obs_index_beta",
                                               &report, why, sizeof(why)));
        ASSERT(report.total == 1 && report.eligible == 1);
        ASSERT(report.groups_named == 1);
        ASSERT(strcmp(report.groups[0].group, "test_obs_index_beta") == 0);
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_observation_index_query(index_path,
                                               "test_obs_index_absent",
                                               &report, why, sizeof(why)));
        ASSERT(report.total == 0 && report.groups_named == 0);

        /* The named-group cap truncates honestly. */
        char wide[4096];
        (void)snprintf(wide, sizeof(wide), "%s/wide", root);
        ASSERT(platform_directory_ensure(wide, 0700));
        for (size_t i = 0; i < 40; i++) {
            char name[64];
            (void)snprintf(name, sizeof(name), "test_obs_wide_%02zu", i);
            uint8_t discard[32];
            ASSERT(dpoi_record(wide, (uint8_t)(i + 20), name, discard));
        }
        ASSERT(zcl_dev_observation_index_merge(index_path, wide,
                                               why, sizeof(why)));
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_observation_index_query(index_path, NULL, &report,
                                               why, sizeof(why)));
        ASSERT(report.total == 44);
        ASSERT(report.groups_named == ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS);
        ASSERT(report.truncated);

        /* A conflict after the display cap still contributes to the total. */
        uint8_t hidden_fail_root[32];
        ASSERT(dpoi_record_verdict(wide, 59, "test_obs_wide_39",
                                   ZCL_DEV_VERDICT_LEAF_FAIL,
                                   hidden_fail_root));
        ASSERT(zcl_dev_observation_index_merge(index_path, wide,
                                               why, sizeof(why)));
        ASSERT(zcl_dev_observation_index_query(index_path, NULL, &report,
                                               why, sizeof(why)));
        ASSERT(report.total == 45 && report.eligible == 45);
        ASSERT(report.groups_named == ZCL_DEV_OBSERVATION_QUERY_MAX_GROUPS);
        ASSERT(report.truncated);
        ASSERT(report.conflicted_groups == 2);
        ASSERT(strcmp(report.groups[report.groups_named - 1].group,
                      "test_obs_wide_39") != 0);

        ASSERT(zcl_dev_observation_index_query(index_path, "test_obs_wide_39",
                                               &report, why, sizeof(why)));
        ASSERT(report.total == 2 && report.groups_named == 1);
        ASSERT(report.conflicted_groups == 1 && report.groups[0].conflict);
        ASSERT(report.groups[0].observations == 2 && !report.truncated);
        ASSERT(zcl_dev_observation_index_query(index_path, "test_obs_wide_38",
                                               &report, why, sizeof(why)));
        ASSERT(report.total == 1 && report.groups_named == 1);
        ASSERT(report.conflicted_groups == 0 && !report.groups[0].conflict);
    }
    TEST_END
    dpoi_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

int test_dev_proof_observation_index(void)
{
    int failures = 0;
    failures += test_dpoi_merge_and_load();
    failures += test_dpoi_union_at_cap();
    failures += test_dpoi_refusals();
    failures += test_dpoi_lookup_parity();
    failures += test_dpoi_query();
    return failures;
}
