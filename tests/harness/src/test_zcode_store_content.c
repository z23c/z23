/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_store scenario checks: the blob surface (vcs/blob_store.h) —
 * the FROZEN golden root vector, root purity across independent
 * constructions, length commitment, put/get round-trip, idempotent
 * re-put, the size ceiling, absent-root and small-buffer failures,
 * and a corrupted CAS object failing verification on read; zcode work
 * output; and the exact-cache restore path (build fabric cache).
 *
 * Split out of test_zcode_store.c (which keeps the includes, the
 * fixture helpers shared across siblings, the dump_state scenarios,
 * and the group entry point) so no family member crosses the
 * 1,500-line ceiling. */

#include "test/test_core.h"

#include "models/build_fabric.h"
#include "services/build_fabric_cache.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/package_store.h"

#include "vcs/blob_store.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_possession_scheduler.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_swarm_status.h"
#include "vcs/zcode_work_output.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include "config/boot_zcode_swarm_receipt.h"
#include "controllers/diagnostics_internal.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "util/util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_zcode_store_priv.h"


/* ── 12: content-addressed blob surface (vcs/blob_store.h) ────────── */

/* FROZEN GOLDEN VECTOR. The blob root is a wire contract: the SAME bytes
 * must yield the SAME 32-byte root on every node, forever. This pins the
 * whole derivation — the "blob" path, mode 0100644, the size/chunk_count
 * fields, the SHA3-256 chunk hash, and the zcl.package_manifest.v1 root
 * domain. If this ever changes, every already-published blob root breaks;
 * a failure here is a CONSENSUS-OF-CONTENT regression, not a test nit. */
#define ZS_BLOB_GOLDEN_INPUT "zcl.blob.golden.v1"
#define ZS_BLOB_GOLDEN_ROOT \
    "a407592f33b1ac781c69ac5bb0bf7f7635c320b17d2e5382bf93b5567af686e7"

static int store_case_blob_pure_root(uint8_t a[256], uint8_t root_a[32])
{
    int failures = 0;
    /* ---- pure root: determinism across independent constructions ---- */
    uint8_t b[256];
    for (size_t i = 0; i < 256; i++)
        a[i] = (uint8_t)(i * 7u + 11u);
    memset(b, 0, sizeof(b));
    for (size_t i = 0; i < sizeof(b); i++)
        b[i] = (uint8_t)((i * 7u + 11u) & 0xffu);
    uint8_t root_b[32];
    bool ok_a = vcs_blob_root(a, 256, root_a);
    bool ok_b = vcs_blob_root(b, sizeof(b), root_b);
    ZS_CHECK("blob: root is a pure function of the bytes",
             ok_a && ok_b && memcmp(root_a, root_b, 32) == 0);

    /* Different bytes -> different root; same prefix, shorter -> different
     * root (the length is committed, so truncation is not a collision). */
    uint8_t c[256];
    memcpy(c, a, sizeof(c));
    c[100] ^= 0x01;
    uint8_t root_c[32], root_short[32];
    ZS_CHECK("blob: one flipped byte changes the root",
             vcs_blob_root(c, sizeof(c), root_c) &&
             memcmp(root_a, root_c, 32) != 0);
    ZS_CHECK("blob: length is committed (prefix != whole)",
             vcs_blob_root(a, 256 - 1u, root_short) &&
             memcmp(root_a, root_short, 32) != 0);
    return failures;
}

static int store_case_blob_golden_vector(void)
{
    int failures = 0;
    /* ---- the frozen golden vector ---- */
    uint8_t golden[32];
    const char *gin = ZS_BLOB_GOLDEN_INPUT;
    bool gok = vcs_blob_root((const uint8_t *)gin, strlen(gin), golden);
    char ghex[65];
    zs_hex32(golden, ghex);
    printf("  zcode_store: blob golden root = %s\n", ghex);
    ZS_CHECK("blob: FROZEN golden root vector holds",
             gok && strcmp(ghex, ZS_BLOB_GOLDEN_ROOT) == 0);
    return failures;
}

static int store_case_blob_hostile_and_ceiling(struct vcs_package_store *s,
                                                uint8_t a[256])
{
    int failures = 0;
    /* ---- hostile input, refused by name, before anything is stored ---- */
    uint8_t junk_root[32];
    ZS_CHECK("blob: null bytes refused",
             vcs_blob_root_of(NULL, 10, junk_root) == VCS_BLOB_ERR_NULL);
    ZS_CHECK("blob: empty blob refused",
             vcs_blob_root_of(a, 0, junk_root) == VCS_BLOB_ERR_EMPTY);
    ZS_CHECK("blob: null store refused",
             vcs_blob_put_to(NULL, a, 256, junk_root) ==
                 VCS_BLOB_ERR_NO_STORE);

    static uint8_t big[VCS_BLOB_MAX_BYTES + 64u];
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)(i ^ 0x5au);
    ZS_CHECK("blob: over the ceiling refused by name (root)",
             vcs_blob_root_of(big, VCS_BLOB_MAX_BYTES + 1u, junk_root) ==
                 VCS_BLOB_ERR_TOO_LARGE);
    ZS_CHECK("blob: over the ceiling refused by name (put)",
             vcs_blob_put_to(s, big, VCS_BLOB_MAX_BYTES + 1u, junk_root) ==
                 VCS_BLOB_ERR_TOO_LARGE);
    ZS_CHECK("blob: refused oversize stored nothing",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 0 &&
             vcs_package_store_pool_usage(s,
                                          VCS_PACKAGE_STORE_POOL_STAGING) ==
                 0);
    /* Exactly at the ceiling is admitted: the bound is a ceiling, not a
     * fencepost bug. */
    uint8_t edge_root[32];
    ZS_CHECK("blob: exactly at the ceiling is accepted",
             vcs_blob_put_to(s, big, VCS_BLOB_MAX_BYTES, edge_root) ==
                 VCS_BLOB_OK);
    ZS_CHECK("blob: ceiling blob is one chunk (never split)",
             vcs_package_store_chunk_present(s, edge_root, 0, 0) &&
             !vcs_package_store_chunk_present(s, edge_root, 0, 1) &&
             !vcs_package_store_chunk_present(s, edge_root, 1, 0));
    return failures;
}

static int store_case_blob_put_get_roundtrip(struct vcs_package_store *s,
                                              uint8_t a[256],
                                              uint8_t root_a[32],
                                              uint8_t out_root[32])
{
    int failures = 0;
    /* ---- put / get round trip ---- */
    ZS_CHECK("blob: put admits manifest + chunk",
             vcs_blob_put_to(s, a, 256, out_root) == VCS_BLOB_OK);
    ZS_CHECK("blob: put root equals the pure root",
             memcmp(out_root, root_a, 32) == 0);
    struct vcs_package_store_status st;
    ZS_CHECK("blob: stored package is complete and one-file",
             vcs_package_store_package_status(s, out_root, &st) &&
             st.complete && st.total_chunks == 1 && st.total_bytes == 256);

    uint8_t out[512];
    size_t out_len = 0;
    memset(out, 0, sizeof(out));
    ZS_CHECK("blob: get round-trips the exact bytes",
             vcs_blob_get_from(s, out_root, out, sizeof(out), &out_len) ==
                 VCS_BLOB_OK &&
             out_len == 256 && memcmp(out, a, 256) == 0);

    /* Idempotent re-put of identical bytes. */
    uint8_t root2[32];
    ZS_CHECK("blob: re-put of identical bytes is idempotent",
             vcs_blob_put_to(s, a, 256, root2) == VCS_BLOB_OK &&
             memcmp(out_root, root2, 32) == 0);
    return failures;
}

static int store_case_blob_absent_and_bad_args(struct vcs_package_store *s,
                                                const uint8_t root[32])
{
    int failures = 0;
    uint8_t out[512];
    size_t out_len = 0;
    /* ---- absent root fails cleanly (no crash, no partial write) ---- */
    uint8_t absent[32];
    memcpy(absent, root, 32);
    absent[0] ^= 0xff;
    ZS_CHECK("blob: get of an absent root fails cleanly",
             vcs_blob_get_from(s, absent, out, sizeof(out), &out_len) ==
                 VCS_BLOB_ERR_ABSENT && out_len == 0);
    ZS_CHECK("blob: get with a null buffer refused",
             vcs_blob_get_from(s, root, NULL, 16, &out_len) ==
                 VCS_BLOB_ERR_NULL);
    ZS_CHECK("blob: buffer smaller than the blob refused",
             vcs_blob_get_from(s, root, out, 256 - 1u, &out_len) ==
                 VCS_BLOB_ERR_CAPACITY);
    return failures;
}

static int store_case_blob_corrupted_cas(struct vcs_package_store *s,
                                          const char *dd, uint8_t a[256],
                                          const uint8_t root[32])
{
    int failures = 0;
    /* ---- a corrupted CAS object must FAIL verification, not be served -- */
    uint8_t chunk_hash[32];
    ZS_CHECK("blob: chunk hash computes",
             vcs_package_chunk_hash(a, 256, chunk_hash));
    char hex[65];
    zs_hex32(chunk_hash, hex);
    char suffix[160];
    char cas_path[1400];
    snprintf(suffix, sizeof(suffix), "cas/sha3/%.2s/%s", hex, hex);
    zs_store_path(cas_path, sizeof(cas_path), dd, suffix);
    ZS_CHECK("blob: CAS object exists under its hash",
             zs_path_exists(cas_path));
    uint8_t tampered[256];
    memcpy(tampered, a, sizeof(tampered));
    tampered[7] ^= 0xff;
    FILE *f = fopen(cas_path, "wb");
    bool wrote = f && fwrite(tampered, 1, sizeof(tampered), f) ==
                          sizeof(tampered);
    if (f)
        fclose(f);
    ZS_CHECK("blob: CAS object tampered on disk", wrote);
    uint8_t out[512];
    size_t out_len = 0;
    ZS_CHECK("blob: corrupted chunk fails verification on read",
             vcs_blob_get_from(s, root, out, sizeof(out), &out_len) ==
                 VCS_BLOB_ERR_CORRUPT && out_len == 0);
    return failures;
}

static int store_case_blob_named_results(void)
{
    int failures = 0;
    /* ---- named results ---- */
    ZS_CHECK("blob: result strings are named",
             strcmp(vcs_blob_result_string(VCS_BLOB_OK), "ok") == 0 &&
             strcmp(vcs_blob_result_string(VCS_BLOB_ERR_TOO_LARGE),
                    "blob-too-large") == 0 &&
             strcmp(vcs_blob_result_string(VCS_BLOB_ERR_CORRUPT),
                    "blob-bytes-corrupt") == 0 &&
             strcmp(vcs_blob_result_string((enum vcs_blob_result)999),
                    "unknown") == 0);
    return failures;
}

static int store_case_blob_global_accessors(uint8_t a[256],
                                             const uint8_t root[32])
{
    int failures = 0;
    uint8_t out[512];
    uint8_t junk_root[32];
    /* ---- global accessors refuse cleanly with no global store open ---- */
    ZS_CHECK("blob: global put refuses with no global store",
             vcs_package_store_global() == NULL &&
             !vcs_blob_put(a, 256, junk_root));
    ZS_CHECK("blob: global get refuses with no global store",
             vcs_blob_get(root, out, sizeof(out)) == -1);
    ZS_CHECK("blob: fetch refuses with no engine",
             vcs_blob_fetch_via(NULL, root, 20500, 1) ==
                 VCS_BLOB_ERR_NO_ENGINE &&
             vcs_blob_announce_via(NULL) == 0);
    return failures;
}

int t_store_blob(void)
{
    int failures = 0;
    char dd[1024];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "blob", VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("blob: store opens", s != NULL);
    if (!s)
        return failures + 1;

    uint8_t a[256];
    uint8_t root_a[32];
    failures += store_case_blob_pure_root(a, root_a);
    failures += store_case_blob_golden_vector();
    failures += store_case_blob_hostile_and_ceiling(s, a);

    uint8_t root[32];
    failures += store_case_blob_put_get_roundtrip(s, a, root_a, root);
    failures += store_case_blob_absent_and_bad_args(s, root);
    failures += store_case_blob_corrupted_cas(s, dd, a, root);
    failures += store_case_blob_named_results();
    failures += store_case_blob_global_accessors(a, root);

    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── action-bound work output carrier ─────────────────────────────── */
int t_store_work_output(void)
{
    int failures = 0;
    char dd[1024];
    struct vcs_package_store *s = zs_open(
        dd, sizeof(dd), "work_output", VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("work output: store opens", s != NULL);
    if (!s) return failures + 1;
    uint8_t action_a[32], action_b[32];
    memset(action_a, 0x31, sizeof(action_a));
    memset(action_b, 0x32, sizeof(action_b));
    size_t bytes_len = VCS_PACKAGE_CHUNK_BYTES + 17u;
    uint8_t *bytes = malloc(bytes_len);
    ZS_CHECK("work output: fixture allocates", bytes != NULL);
    if (!bytes) {
        vcs_package_store_close(s); test_rm_rf_recursive(dd);
        return failures + 1;
    }
    for (size_t i = 0; i < bytes_len; i++)
        bytes[i] = (uint8_t)(i * 13u + 7u);
    uint8_t root_a[32], root_again[32], root_b[32];
    ZS_CHECK("work output: action plus multi-chunk bytes publish",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, bytes_len, root_a) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    uint8_t *out = NULL; size_t out_len = 0;
    ZS_CHECK("work output: exact action reconstructs exact bytes",
             vcs_zcode_work_output_get(
                 s, root_a, action_a, &out, &out_len) ==
                 VCS_ZCODE_WORK_OUTPUT_OK && out_len == bytes_len &&
             memcmp(out, bytes, bytes_len) == 0);
    free(out); out = NULL; out_len = 0;
    ZS_CHECK("work output: wrong action fails closed",
             vcs_zcode_work_output_get(
                 s, root_a, action_b, &out, &out_len) ==
                 VCS_ZCODE_WORK_OUTPUT_CORRUPT && out == NULL && out_len == 0);
    ZS_CHECK("work output: exact re-put is idempotent",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, bytes_len, root_again) ==
                 VCS_ZCODE_WORK_OUTPUT_OK &&
             memcmp(root_a, root_again, 32) == 0);
    ZS_CHECK("work output: different action cannot alias",
             vcs_zcode_work_output_put(
                 s, action_b, bytes, bytes_len, root_b) ==
                 VCS_ZCODE_WORK_OUTPUT_OK && memcmp(root_a, root_b, 32) != 0);
    ZS_CHECK("work output: empty output refused by name",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, 0, root_b) ==
                 VCS_ZCODE_WORK_OUTPUT_EMPTY);
    free(bytes);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

static bool zs_cache_plan_write_source(const char *workspace,
                                       uint8_t source_sha[32],
                                       uint8_t source_root[32])
{
    char source_dir[1200], source_c[1240], source_i[1240];
    (void)snprintf(source_dir, sizeof(source_dir), "%s/cache-source", workspace);
    (void)snprintf(source_c, sizeof(source_c), "%s/unit.c", source_dir);
    (void)snprintf(source_i, sizeof(source_i), "%s/unit.i", source_dir);
    if (mkdir(source_dir, 0700) != 0) return false;
    static const uint8_t payload[] = "int cache_fixture(void){return 23;}\n";
    FILE *file = fopen(source_c, "wb");
    bool files_ok = file && fwrite(payload, 1, sizeof(payload) - 1u, file) ==
                                  sizeof(payload) - 1u;
    if (file) files_ok = fclose(file) == 0 && files_ok;
    file = files_ok ? fopen(source_i, "wb") : NULL;
    files_ok = file && fwrite(payload, 1, sizeof(payload) - 1u, file) ==
                              sizeof(payload) - 1u;
    if (file) files_ok = fclose(file) == 0 && files_ok;
    if (!files_ok || vcs_tree_capture_into(source_dir, workspace, source_root) !=
                         VCS_OK)
        return false;
    uint8_t *source_wire = NULL;
    size_t source_wire_len = 0;
    if (vcs_object_load_raw(
            workspace, source_root, &source_wire, &source_wire_len) != 0)
        return false;
    vcs_source_manifest_id(source_wire, source_wire_len, source_sha);
    free(source_wire);
    return true;
}

static bool zs_cache_plan_write_authority(const char *workspace,
                                          const uint8_t source_root[32],
                                          uint8_t lock_root[32],
                                          uint8_t recipe_root[32])
{
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    lock.count = 1;
    memcpy(lock.nodes[0].root, source_root, 32);
    (void)snprintf(lock.nodes[0].name, sizeof(lock.nodes[0].name),
                   "publisher/cache-fixture");
    (void)snprintf(lock.nodes[0].semver, sizeof(lock.nodes[0].semver), "1.0.0");
    uint8_t *lock_wire = NULL;
    size_t lock_len = 0;
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error recipe_error;
    bool authority_ok = vcs_package_lock_serialize(
            &lock, &lock_wire, &lock_len) == VCS_PACKAGE_DEPS_OK &&
        vcs_package_recipe_add_source(&recipe, "unit.c", &recipe_error);
    vcs_package_recipe_set_test_limits(
        &recipe, 0, 30, UINT64_C(64) * 1024u * 1024u);
    uint8_t *recipe_wire = NULL;
    size_t recipe_len = 0;
    authority_ok = authority_ok && vcs_package_recipe_serialize(
            &recipe, &recipe_wire, &recipe_len) == VCS_PACKAGE_RECIPE_OK &&
        vcs_zcode_task_authority_store(
            workspace, lock_wire, lock_len, recipe_wire, recipe_len,
            lock_root, recipe_root) == VCS_ZCODE_TASK_AUTHORITY_OK;
    vcs_package_recipe_free(&recipe);
    free(recipe_wire); free(lock_wire);
    return authority_ok;
}

static bool zs_cache_plan_write_task(const char *workspace,
                                     const uint8_t source_root[32],
                                     const uint8_t lock_root[32],
                                     const uint8_t recipe_root[32],
                                     const uint8_t toolchain[32],
                                     const uint8_t policy[32],
                                     struct vcs_zcode_task_v1 *task,
                                     uint8_t task_root[32])
{
    *task = (struct vcs_zcode_task_v1){
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .capabilities = VCS_ZCODE_TASK_CAP_V1_MASK,
        .max_changed_files = 4,
        .max_patch_bytes = 1024u,
        .max_context_bytes = 1024u * 1024u,
        .max_cpu_seconds = 30,
        .max_memory_bytes = UINT64_C(64) * 1024u * 1024u,
        .max_output_bytes = UINT64_C(16) * 1024u * 1024u,
        .expires_unix = 200,
    };
    memcpy(task->source_root, source_root, 32);
    memcpy(task->dependency_lock_root, lock_root, 32);
    memcpy(task->acceptance_tests_root, recipe_root, 32);
    memcpy(task->toolchain_capsule_root, toolchain, 32);
    memcpy(task->proof_policy_root, policy, 32);
    memset(task->write_scope_root, 0x91, 32);
    memset(task->model_policy_root, 0x92, 32);
    memset(task->goal_root, 0x93, 32);
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    return vcs_zcode_task_root(task, task_root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_serialize(task, task_wire) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, task_root, task_wire,
                                 sizeof(task_wire));
}

static bool zs_cache_plan_write_candidate(
    const char *workspace, const uint8_t task_root[32],
    const uint8_t source_root[32], const struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate, uint8_t candidate_root[32])
{
    *candidate = (struct vcs_zcode_candidate_v1){
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .sequence = 1,
        .created_unix = 100,
    };
    memcpy(candidate->task_root, task_root, 32);
    memcpy(candidate->base_source_root, source_root, 32);
    memcpy(candidate->candidate_source_root, source_root, 32);
    memset(candidate->patch_root, 0xa1, 32);
    memset(candidate->adapter_policy_root, 0xa2, 32);
    memset(candidate->author_pubkey, 0xa3, 32);
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_candidate_validate_for_task(
               task, candidate, candidate->created_unix) ==
               VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(candidate, candidate_root) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_serialize(candidate, candidate_wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, candidate_root, candidate_wire,
                                 sizeof(candidate_wire));
}

static bool zs_cache_plan_write_input(
    const char *workspace, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, uint8_t input_root[32])
{
    struct vcs_zcode_action_input_v1 input;
    enum vcs_zcode_action_input_result input_result =
        vcs_zcode_action_input_derive_cas(
            workspace, task_root, candidate_root, task, candidate,
            VCS_ZCODE_WORK_BUILD, "unit.i", &input);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool stored = input_result == VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_zcode_action_input_root(&input, input_root) ==
            VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_zcode_action_input_serialize(&input, &wire, &wire_len) ==
            VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_object_put_addressed(workspace, input_root, wire, wire_len);
    free(wire);
    vcs_zcode_action_input_free(&input);
    return stored;
}

static bool zs_cache_plan_fill_job_action(
    struct db_build_job *job, struct db_build_action *action,
    const uint8_t source_sha[32], const uint8_t source_root[32],
    const uint8_t toolchain[32], const uint8_t policy[32],
    const uint8_t input_root[32], const uint8_t task_root[32],
    const uint8_t candidate_root[32])
{
    memset(job, 0, sizeof(*job));
    memset(action, 0, sizeof(*action));
    zcl_hex_encode(source_sha, 32, job->source_sha256);
    zcl_hex_encode(source_root, 32, job->source_cas_sha3);
    zcl_hex_encode(toolchain, 32, job->toolchain_sha3);
    (void)snprintf(job->profile, sizeof(job->profile), "dev");
    (void)snprintf(job->state, sizeof(job->state), "ACCEPTED");
    (void)snprintf(job->outcome, sizeof(job->outcome), "ACCEPTED");
    job->created_at = job->updated_at = 100;
    (void)snprintf(action->kind, sizeof(action->kind), "%s",
                   VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(action->state, sizeof(action->state), "ACCEPTED");
    (void)snprintf(action->outcome, sizeof(action->outcome), "ACCEPTED");
    zcl_hex_encode(input_root, 32, action->input_root_sha3);
    zcl_hex_encode(task_root, 32, action->task_root_sha3);
    zcl_hex_encode(candidate_root, 32, action->candidate_root_sha3);
    zcl_hex_encode(policy, 32, action->proof_policy_root_sha3);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    vcs_build_action_v1_fixed_flags_root(flags);
    vcs_build_action_v1_fixed_environment_root(environment);
    zcl_hex_encode(flags, 32, action->flags_sha3);
    zcl_hex_encode(environment, 32, action->environment_sha3);
    (void)snprintf(action->virtual_workdir,
                   sizeof(action->virtual_workdir), "%s",
                   VCS_BUILD_VIRTUAL_ROOT_V1);
    (void)snprintf(action->declared_outputs,
                   sizeof(action->declared_outputs), "%s",
                   VCS_BUILD_OUTPUT_V1);
    (void)snprintf(action->resource_policy,
                   sizeof(action->resource_policy), "%s",
                   VCS_BUILD_RESOURCE_POLICY_V1);
    action->created_at = action->updated_at = 100;
    return build_fabric_action_id(job, action, action->action_id).ok &&
        build_fabric_job_id(job, action->action_id, job->job_id).ok &&
        snprintf(action->job_id, sizeof(action->job_id), "%s", job->job_id) > 0;
}

static bool zs_cache_plan(const char *workspace, struct db_build_job *job,
                          struct db_build_action *action)
{
    uint8_t source_sha[32], source_root[32], toolchain[32], policy[32];
    memset(toolchain, 0x33, sizeof(toolchain));
    memset(policy, 0x66, sizeof(policy));

    if (!zs_cache_plan_write_source(workspace, source_sha, source_root))
        return false;

    uint8_t lock_root[32], recipe_root[32];
    if (!zs_cache_plan_write_authority(workspace, source_root, lock_root,
                                       recipe_root))
        return false;

    struct vcs_zcode_task_v1 task;
    uint8_t task_root[32];
    if (!zs_cache_plan_write_task(workspace, source_root, lock_root,
                                  recipe_root, toolchain, policy, &task,
                                  task_root))
        return false;

    struct vcs_zcode_candidate_v1 candidate;
    uint8_t candidate_root[32];
    if (!zs_cache_plan_write_candidate(workspace, task_root, source_root,
                                       &task, &candidate, candidate_root))
        return false;

    uint8_t input_root[32];
    if (!zs_cache_plan_write_input(workspace, task_root, candidate_root,
                                   &task, &candidate, input_root))
        return false;

    return zs_cache_plan_fill_job_action(job, action, source_sha,
                                         source_root, toolchain, policy,
                                         input_root, task_root,
                                         candidate_root);
}

static bool zs_file_equals(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *file = fopen(path, "rb");
    uint8_t *actual = malloc(len ? len : 1u);
    bool ok = file && actual && fread(actual, 1, len, file) == len &&
              fgetc(file) == EOF && memcmp(actual, bytes, len) == 0;
    free(actual);
    if (file) ok = fclose(file) == 0 && ok;
    return ok;
}

static bool zs_addressed_path(const char *workspace, const uint8_t root[32],
                              char *out, size_t out_cap)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    int n = snprintf(out, out_cap, "%s/.zvcs/objects/%.2s/%s",
                     workspace, hex, hex + 2);
    return n > 0 && (size_t)n < out_cap;
}

static void zs_cache_worker_id(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

static bool zs_cache_observation(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t output_root[32],
    const uint8_t *output, size_t output_len, char root_hex[65])
{
    struct vcs_build_execution_observation_v1 observation = {
        .schema_version = VCS_BUILD_EXECUTION_OBSERVATION_VERSION,
        .flags = VCS_BUILD_OBS_REQUIRED_FLAGS,
        .cpu_seconds_limit = 1,
        .memory_bytes_limit = 1,
        .process_limit = 1,
        .file_limit = 1,
        .file_bytes_limit = output_len,
        .output_bytes_limit = output_len,
        .wall_millis_limit = 1,
    };
    if (!zcl_hex_decode_lower(action->action_id, observation.action_root, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3,
                              observation.action_input_root, 32) ||
        !zcl_hex_decode_lower(job->toolchain_sha3,
                              observation.toolchain_root, 32) ||
        !zcl_hex_decode_lower(action->flags_sha3,
                              observation.flags_root, 32) ||
        !zcl_hex_decode_lower(action->environment_sha3,
                              observation.environment_root, 32))
        return false;
    memcpy(observation.artifact_root, output_root, 32);
    sha3_256(output, output_len, observation.output_bytes_root);
    memcpy(observation.observed_input_bytes_root,
           observation.action_input_root, 32);
    vcs_build_execution_read_set_root(
        observation.action_input_root, observation.observed_input_bytes_root,
        observation.toolchain_root, observation.declared_reads_root);
    memcpy(observation.observed_reads_root,
           observation.declared_reads_root, 32);
    vcs_build_execution_declared_write_set_root(
        VCS_BUILD_OUTPUT_V1, observation.declared_writes_root);
    vcs_build_execution_observed_write_set_root(
        VCS_BUILD_OUTPUT_V1, observation.output_bytes_root,
        observation.observed_writes_root);
    uint8_t wire[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES], root[32];
    if (!vcs_build_execution_observation_v1_serialize(&observation, wire) ||
        !vcs_build_execution_observation_v1_root(&observation, root) ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))
        return false;
    zcl_hex_encode(root, 32, root_hex);
    return true;
}

static bool zs_cache_accept(
    struct node_db *ndb, const char *workspace, struct db_build_job *job,
    struct db_build_action *action, const uint8_t output_root[32],
    const uint8_t *output, size_t output_len)
{
    uint8_t seed[32], pubkey[32], secret[32];
    memset(seed, 0x5a, sizeof(seed));
    ed25519_keypair(pubkey, secret, seed);
    struct db_build_worker worker = {
        .approved = 1,
        .approved_at = 100,
        .last_seen_at = 100,
    };
    zs_cache_worker_id(pubkey, worker.worker_id);
    zcl_hex_encode(pubkey, 32, worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities),
                   "linux,c23,%s", VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(job->state, sizeof(job->state), "RUNNING");
    job->outcome[0] = '\0';
    (void)snprintf(action->state, sizeof(action->state), "VERIFYING");
    action->outcome[0] = '\0';
    action->output_root_sha3[0] = '\0';
    (void)snprintf(action->worker_id, sizeof(action->worker_id), "%s",
                   worker.worker_id);
    memset(seed, 0x6b, sizeof(seed));
    zcl_hex_encode(seed, 32, action->lease_id);
    action->lease_expires_at = 190;
    if (!db_build_worker_save(ndb, &worker) ||
        !db_build_job_save(ndb, job) || !db_build_action_save(ndb, action))
        return false;
    struct db_build_receipt receipt = { .created_at = 150 };
    (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                   action->action_id);
    (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                   action->action_id);
    (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s", job->job_id);
    (void)snprintf(receipt.worker_id, sizeof(receipt.worker_id), "%s",
                   worker.worker_id);
    (void)snprintf(receipt.lease_id, sizeof(receipt.lease_id), "%s",
                   action->lease_id);
    zcl_hex_encode(output_root, 32, receipt.output_sha3);
    if (!zs_cache_observation(
            workspace, job, action, output_root, output, output_len,
            receipt.observation_sha3))
        return false;
    (void)snprintf(receipt.confinement, sizeof(receipt.confinement),
                   "fixture:isolation=complete,network=0");
    (void)snprintf(receipt.trust_state, sizeof(receipt.trust_state),
                   "REMOTE_OBSERVED");
    if (!build_fabric_receipt_id(&receipt, receipt.receipt_id).ok)
        return false;
    uint8_t receipt_id[32], signature[64];
    if (!zcl_hex_decode_lower(receipt.receipt_id, receipt_id, 32)) return false;
    ed25519_sign(signature, receipt_id, 32, secret, pubkey);
    zcl_hex_encode(signature, 64, receipt.signature);
    return build_fabric_receipt_quarantine(ndb, &receipt, 150).ok &&
        build_fabric_receipt_admit(
            ndb, workspace, receipt.receipt_id, 151).ok &&
        db_build_job_find(ndb, job->job_id, job) &&
        db_build_action_find(ndb, action->action_id, action);
}

static bool zs_cache_rekey(struct db_build_job *job,
                           struct db_build_action *action)
{
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    if (!build_fabric_action_id(job, action, action_id).ok ||
        !build_fabric_job_id(job, action_id, job_id).ok)
        return false;
    (void)snprintf(action->action_id, sizeof(action->action_id), "%s",
                   action_id);
    (void)snprintf(action->job_id, sizeof(action->job_id), "%s", job_id);
    (void)snprintf(job->job_id, sizeof(job->job_id), "%s", job_id);
    return true;
}

struct exact_cache_ctx {
    struct node_db *ndb;
    const char *dd;
    struct vcs_package_store *store;
    struct db_build_job *job;
    struct db_build_action *action;
    char *output;
};

static int store_case_exact_cache_setup(struct exact_cache_ctx *ctx,
                                         const uint8_t *object,
                                         size_t object_len,
                                         uint8_t output_root[32])
{
    int failures = 0;
    ZS_CHECK("exact cache: canonical closure and action derive",
             zs_cache_plan(ctx->dd, ctx->job, ctx->action));
    uint8_t action_root[32];
    ZS_CHECK("exact cache: action id decodes",
             zcl_hex_decode_lower(ctx->action->action_id, action_root, 32));
    ZS_CHECK("exact cache: action-bound output stores",
             vcs_zcode_work_output_put(ctx->store, action_root, object,
                                       object_len, output_root) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    (void)snprintf(ctx->output, 1200, "%s/restored.o", ctx->dd);
    zcl_hex_encode(output_root, 32, ctx->action->output_root_sha3);
    ZS_CHECK("exact cache: hollow accepted row persists for refusal",
             db_build_job_save(ctx->ndb, ctx->job) &&
             db_build_action_save(ctx->ndb, ctx->action));
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: accepted row without receipt is corrupt",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(ctx->output, F_OK) != 0);
    return failures;
}

static int store_case_exact_cache_accept_and_restore(
    struct exact_cache_ctx *ctx, const uint8_t *object, size_t object_len,
    const uint8_t output_root[32])
{
    int failures = 0;
    ZS_CHECK("exact cache: canonical local receipt admits expired task output",
             zs_cache_accept(ctx->ndb, ctx->dd, ctx->job, ctx->action,
                             output_root, object, object_len) &&
             strcmp(ctx->job->state, "ACCEPTED") == 0 &&
             strcmp(ctx->action->state, "ACCEPTED") == 0);
    struct db_build_job wrong_source_job = *ctx->job;
    struct db_build_action wrong_source_action = *ctx->action;
    wrong_source_job.source_sha256[0] =
        wrong_source_job.source_sha256[0] == '0' ? '1' : '0';
    ZS_CHECK("exact cache: mismatched source identity plan rekeys",
             zs_cache_rekey(&wrong_source_job, &wrong_source_action));
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, &wrong_source_job,
        &wrong_source_action, ctx->output, &report);
    ZS_CHECK("exact cache: source id must match exact candidate manifest",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(ctx->output, F_OK) != 0);
    restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: historical accepted action restores after expiry",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_HIT &&
             report.restored_bytes == object_len &&
             zs_file_equals(ctx->output, object, object_len));
    return failures;
}

static int store_case_exact_cache_stable_identity(
    struct exact_cache_ctx *ctx)
{
    int failures = 0;
    struct build_fabric_cache_report report;
    struct stat stable_before, stable_after;
    ZS_CHECK("exact cache: materialized object identity captures",
             stat(ctx->output, &stable_before) == 0);
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: identical hit does not rewrite artifact",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_HIT &&
             stat(ctx->output, &stable_after) == 0 &&
             stable_after.st_dev == stable_before.st_dev &&
             stable_after.st_ino == stable_before.st_ino &&
             stable_after.st_mtime == stable_before.st_mtime);
    return failures;
}

static int store_case_exact_cache_missing_source_blob(
    struct exact_cache_ctx *ctx)
{
    int failures = 0;
    uint8_t source_root[32], *source_wire = NULL, *source_blob = NULL;
    size_t source_wire_len = 0, source_blob_len = 0;
    struct vcs_manifest source_manifest = {0};
    char source_blob_path[1400] = {0};
    bool source_fixture_ok =
        zcl_hex_decode_lower(ctx->job->source_cas_sha3, source_root, 32) &&
        vcs_object_load_raw(ctx->dd, source_root, &source_wire,
                            &source_wire_len) == 0 &&
        vcs_manifest_parse(source_wire, source_wire_len,
                           &source_manifest) &&
        source_manifest.count > 0 &&
        vcs_object_get(ctx->dd, source_manifest.entries[0].blob,
                       VCS_TAG_BLOB, &source_blob,
                       &source_blob_len) == 0 &&
        zs_addressed_path(ctx->dd, source_manifest.entries[0].blob,
                          source_blob_path, sizeof(source_blob_path));
    ZS_CHECK("exact cache: source closure blob resolves", source_fixture_ok);
    if (source_fixture_ok) {
        ZS_CHECK("exact cache: source closure missing-blob fixture removes",
                 unlink(source_blob_path) == 0);
        struct build_fabric_cache_report report;
        struct zcl_result restored = build_fabric_cache_restore(
            ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action,
            ctx->output, &report);
        ZS_CHECK("exact cache: missing source closure blob refuses restore",
                 !restored.ok &&
                 report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
        uint8_t restored_blob_root[32];
        ZS_CHECK("exact cache: source closure blob restores exactly",
                 vcs_object_put(ctx->dd, source_blob, source_blob_len,
                                VCS_TAG_BLOB, restored_blob_root) &&
                 memcmp(restored_blob_root,
                        source_manifest.entries[0].blob,
                        sizeof(restored_blob_root)) == 0);
    }
    free(source_blob);
    free(source_wire);
    vcs_manifest_free(&source_manifest);
    return failures;
}

static int store_case_exact_cache_miss_and_repair(
    struct exact_cache_ctx *ctx, const uint8_t *object, size_t object_len)
{
    int failures = 0;
    struct db_build_receipt receipts[1];
    struct db_build_action unchanged;
    ZS_CHECK("exact cache: hit mints no receipt or lifecycle transition",
             db_build_job_receipts(ctx->ndb, ctx->job->job_id, receipts,
                                   1) == 1 &&
             db_build_action_find(ctx->ndb, ctx->action->action_id,
                                  &unchanged) &&
             strcmp(unchanged.state, "ACCEPTED") == 0 &&
             strcmp(unchanged.output_root_sha3,
                    ctx->action->output_root_sha3) == 0);

    struct db_build_action pending = *ctx->action;
    (void)snprintf(pending.state, sizeof(pending.state), "SNAPSHOTTED");
    pending.outcome[0] = '\0';
    pending.output_root_sha3[0] = '\0';
    ZS_CHECK("exact cache: unaccepted exact action is a miss",
             db_build_action_save(ctx->ndb, &pending));
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: miss returns without changing output",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_MISS &&
             zs_file_equals(ctx->output, object, object_len));
    ZS_CHECK("exact cache: accepted plan restores after miss",
             db_build_action_save(ctx->ndb, ctx->action));
    return failures;
}

static int store_case_exact_cache_wrong_carrier(
    struct exact_cache_ctx *ctx, const uint8_t *object, size_t object_len)
{
    int failures = 0;
    uint8_t other_action[32], wrong_root[32];
    memset(other_action, 0xa5, sizeof(other_action));
    ZS_CHECK("exact cache: mismatched action carrier stores",
             vcs_zcode_work_output_put(ctx->store, other_action, object,
                                       object_len, wrong_root) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    struct db_build_action wrong_output = *ctx->action;
    zcl_hex_encode(wrong_root, 32, wrong_output.output_root_sha3);
    ZS_CHECK("exact cache: poisoned output reference persists for refusal",
             db_build_action_save(ctx->ndb, &wrong_output));
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: wrong action-bound carrier is corrupt",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
    ZS_CHECK("exact cache: accepted output reference repairs",
             db_build_action_save(ctx->ndb, ctx->action));
    return failures;
}

static int store_case_exact_cache_symlink_dest(struct exact_cache_ctx *ctx)
{
    int failures = 0;
#if !defined(_WIN32)
    (void)unlink(ctx->output);
    ZS_CHECK("exact cache: symlink destination fixture creates",
             symlink("/dev/null", ctx->output) == 0);
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: symlink destination refuses closed",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
    (void)unlink(ctx->output);
#else
    (void)ctx;
#endif
    return failures;
}

static int store_case_exact_cache_invalid_input_closure(
    struct exact_cache_ctx *ctx)
{
    int failures = 0;
    uint8_t input_root[32], *input_wire = NULL;
    size_t input_len = 0;
    char addressed[1400];
    ZS_CHECK("exact cache: input closure loads for corruption fixture",
             zcl_hex_decode_lower(ctx->action->input_root_sha3, input_root,
                                  32) &&
             vcs_object_load_raw(ctx->dd, input_root, &input_wire,
                                 &input_len) == 0 &&
             zs_addressed_path(ctx->dd, input_root, addressed,
                               sizeof(addressed)));
    FILE *poison = fopen(addressed, "wb");
    bool poison_written = poison && fwrite("bad", 1, 3, poison) == 3;
    if (poison) poison_written = fclose(poison) == 0 && poison_written;
    ZS_CHECK("exact cache: invalid action input fixture writes",
             poison_written);
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: invalid input closure refuses before restore",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(ctx->output, F_OK) != 0);
    bool repaired = false;
    ZS_CHECK("exact cache: input closure repairs from canonical bytes",
             vcs_object_put_addressed_repair(
                 ctx->dd, input_root, input_wire, input_len, &repaired) &&
             repaired);
    free(input_wire);
    return failures;
}

static int store_case_exact_cache_invalid_candidate(
    struct exact_cache_ctx *ctx)
{
    int failures = 0;
    uint8_t candidate_root[32];
    char addressed[1400];
    ZS_CHECK("exact cache: candidate closure address resolves",
             zcl_hex_decode_lower(ctx->action->candidate_root_sha3,
                                  candidate_root, 32) &&
             zs_addressed_path(ctx->dd, candidate_root, addressed,
                               sizeof(addressed)));
    FILE *poison = fopen(addressed, "wb");
    bool poison_written = poison && fwrite("bad", 1, 3, poison) == 3;
    if (poison)
        poison_written = fclose(poison) == 0 && poison_written;
    ZS_CHECK("exact cache: invalid candidate fixture writes",
             poison_written);
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        ctx->ndb, ctx->dd, ctx->store, ctx->job, ctx->action, ctx->output,
        &report);
    ZS_CHECK("exact cache: invalid candidate refuses before restore",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(ctx->output, F_OK) != 0);
    return failures;
}

int t_store_exact_cache_restore(void)
{
    int failures = 0;
    char dd[1024], output[1200];
    struct vcs_package_store *store = zs_open(
        dd, sizeof(dd), "exact_cache_restore",
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("exact cache: package store opens", store != NULL);
    if (!store) return failures + 1;
    struct node_db ndb = {0};
    ZS_CHECK("exact cache: ledger opens", node_db_open(&ndb, ":memory:"));
    ZS_CHECK("exact cache: ZVCS input store opens",
             vcs_object_store_init(dd));
    struct db_build_job job;
    struct db_build_action action;
    static const uint8_t object[] = {
        0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 62, 0, 'z', '2', '3', '\n'
    };
    struct exact_cache_ctx ctx = {
        .ndb = &ndb, .dd = dd, .store = store, .job = &job,
        .action = &action, .output = output,
    };

    uint8_t output_root[32];
    failures += store_case_exact_cache_setup(&ctx, object, sizeof(object),
                                              output_root);
    failures += store_case_exact_cache_accept_and_restore(
        &ctx, object, sizeof(object), output_root);
    failures += store_case_exact_cache_stable_identity(&ctx);
    failures += store_case_exact_cache_missing_source_blob(&ctx);
    failures += store_case_exact_cache_miss_and_repair(&ctx, object,
                                                        sizeof(object));
    failures += store_case_exact_cache_wrong_carrier(&ctx, object,
                                                      sizeof(object));
    failures += store_case_exact_cache_symlink_dest(&ctx);
    failures += store_case_exact_cache_invalid_input_closure(&ctx);
    failures += store_case_exact_cache_invalid_candidate(&ctx);

    node_db_close(&ndb);
    vcs_package_store_close(store);
    test_rm_rf_recursive(dd);
    return failures;
}

