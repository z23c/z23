/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ZCODE dev-loop publish staging — reload and re-verify the signed
 * lane receipt (Ed25519 signature, cross-object task/candidate/policy
 * roots, the evaluated proof set) that is the sole acceptance authority for
 * a publish, stage the rederivable ordinary content.v2 package into a
 * private transactional staging directory, and project publisher lineage
 * (parent release, sequence) from the persisted release index. Shared by
 * native_zcode_dev_publish.c, which owns the zcode.publish.plan and
 * zcode.publish.commit orchestration on top of these primitives. */

#include "command/native_command.h"
#include "command/native_zcode_dev_priv.h"
#include "command/native_zcode_dev_publish_priv.h"

#include "controllers/rpc_client.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "config/runtime.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_agent_context_service.h"
#include "services/zcode_lane_service.h"
#include "services/zcode_lane_view_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/package_manifest.h"
#include "vcs/package_mapping.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_task_index.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

void zpub_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.publish");
}

static bool zpub_load_wire(const char *workspace, const char *hex,
                           uint8_t **wire, size_t *wire_len, uint8_t root[32])
{
    return zcl_hex_decode_lower(hex, root, 32) &&
           vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static bool zpub_load_task(const char *workspace, const char *hex,
                           struct vcs_zcode_task_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_task_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool zpub_load_candidate(const char *workspace, const char *hex,
                                struct vcs_zcode_candidate_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_candidate_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool zpub_load_policy(const char *workspace, const char *hex,
                             struct vcs_zcode_proof_policy_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_proof_policy_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

/* Load the signed lane receipt, re-derive its id, and verify its Ed25519
 * signature against the candidate's pinned work-authority signer. Keeps the
 * exact CAS wire: it is published as the canonical authority file. */
static bool zpub_load_lane_receipt(
    const char *workspace, const char *hex,
    struct vcs_zcode_lane_receipt_v1 *out,
    const uint8_t expected_signer[32],
    uint8_t wire_out[VCS_ZCODE_LANE_WIRE_BYTES])
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        len == VCS_ZCODE_LANE_WIRE_BYTES &&
        vcs_zcode_lane_receipt_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_lane_receipt_verify(out, expected_signer) ==
            VCS_ZCODE_DEV_OK;
    if (ok)
        memcpy(wire_out, wire, len);
    free(wire);
    return ok;
}

/* The accepted proof set must re-derive its bound root from CAS bytes. */
static bool zpub_proof_set_valid(
    const char *workspace, const char *hex,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0, count = 0;
    uint8_t (*roots)[32] =
        zcl_malloc(sizeof(*roots) * VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
                   "zcode.publish.proof_set");
    bool ok = roots != NULL;
    if (ok)
        ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
            vcs_zcode_proof_set_parse(
                wire, len, roots, VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
                &count) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_proof_set_root(
                (const uint8_t (*)[32])roots, count,
                checked) == VCS_ZCODE_DEV_OK &&
            memcmp(root, checked, 32) == 0;
    for (size_t i = 0; ok && i < count; i++) {
        uint8_t *receipt_wire = NULL;
        size_t receipt_len = 0;
        struct vcs_zcode_work_receipt_v1 receipt;
        uint8_t receipt_id[32];
        ok = vcs_object_load_raw(workspace, roots[i], &receipt_wire,
                                 &receipt_len) == 0 &&
            vcs_zcode_work_receipt_parse(receipt_wire, receipt_len,
                                         &receipt) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_validate(&receipt) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_id(&receipt, receipt_id) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(receipt_id, roots[i], 32) == 0 &&
            vcs_zcode_work_receipt_verify(&receipt,
                                          receipt.signer_pubkey) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_validate_for_candidate(
                task, candidate, &receipt, receipt.finished_unix) ==
                VCS_ZCODE_DEV_OK;
        free(receipt_wire);
    }
    free(roots);
    free(wire);
    return ok;
}

#if defined(_WIN32)
/* Descend the relative path's directory components under root (creating
 * each as needed) and write the leaf file, closing every transaction this
 * function opened (root stays owned by, and closed by, the caller). */
static bool zpub_stage_file_windows_write(
    struct platform_directory_transaction *root, char *relative,
    const uint8_t *bytes, size_t len)
{
    struct platform_directory_transaction current, next;
    struct platform_directory_transaction *active = root;
    platform_directory_transaction_init(&current);
    platform_directory_transaction_init(&next);
    char *leaf = relative;
    for (char *slash = strchr(leaf, '/'); slash; slash = strchr(leaf, '/')) {
        *slash = '\0';
        enum platform_directory_result opened =
            platform_directory_transaction_open_child(active, leaf, true, &next);
        if (opened != PLATFORM_DIRECTORY_OK) {
            platform_directory_transaction_close(&next);
            platform_directory_transaction_close(&current);
            return false;
        }
        if (active == &current) platform_directory_transaction_close(&current);
        current = next;
        platform_directory_transaction_init(&next);
        active = &current;
        leaf = slash + 1;
    }
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool ok = leaf[0] && platform_directory_child_create(active, leaf, &file) &&
        platform_directory_child_write_exact(&file, bytes, len, 0) &&
        platform_directory_child_flush(&file) &&
        platform_directory_transaction_flush(active);
    platform_directory_child_close(&file);
    platform_directory_transaction_close(&next);
    platform_directory_transaction_close(&current);
    return ok;
}

static bool zpub_stage_file_windows(
    const char *dir, const char *relpath, const uint8_t *bytes, size_t len)
{
    char relative[ZPUB_PATH_MAX];
    if (!dir || !relpath || strlen(relpath) >= sizeof(relative)) return false;
    (void)snprintf(relative, sizeof(relative), "%s", relpath);
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    if (!platform_directory_transaction_open(&root, dir)) return false;
    bool ok = zpub_stage_file_windows_write(&root, relative, bytes, len);
    platform_directory_transaction_close(&root);
    return ok;
}
#else
static bool zpub_stage_file_posix(
    const char *dir, const char *relpath, const uint8_t *bytes, size_t len)
{
    char path[ZPUB_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, relpath);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    for (char *p = path + strlen(dir) + 1u; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        bool made = mkdir(path, 0700) == 0 || errno == EEXIST;
        *p = '/';
        if (!made)
            return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}
#endif

/* Write one staged file beneath dir, creating intermediate directories. The
 * relative path is already grammar-validated (canonical, no traversal). */
static bool zpub_stage_file(const char *dir, const char *relpath,
                            const uint8_t *bytes, size_t len)
{
#if defined(_WIN32)
    return zpub_stage_file_windows(dir, relpath, bytes, len);
#else
    return zpub_stage_file_posix(dir, relpath, bytes, len);
#endif
}

bool zpub_stage_transport(
    const char *dir, const struct vcs_source_package_transport *transport)
{
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &path, &bytes, &len) ||
            !zpub_stage_file(dir, path, bytes, len))
            return false;
    }
    return true;
}

#if defined(_WIN32)
static void zpub_stage_cleanup_windows(
    const char *dir, const struct vcs_source_package_transport *transport)
{
    char path[ZPUB_PATH_MAX];
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL; const uint8_t *bytes = NULL; size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len)) continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n > 0 && (size_t)n < sizeof(path))
            (void)platform_private_file_unlink_missing_ok(path);
    }
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL; const uint8_t *bytes = NULL; size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len)) continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n <= 0 || (size_t)n >= sizeof(path)) continue;
        for (char *p = strrchr(path, '/'); p && p > path + strlen(dir);
             p = strrchr(path, '/')) {
            *p = '\0';
            (void)platform_private_directory_remove_empty(path);
        }
    }
    (void)platform_private_directory_remove_empty(dir);
}
#else
static void zpub_stage_cleanup_posix(
    const char *dir, const struct vcs_source_package_transport *transport)
{
    char path[ZPUB_PATH_MAX];
    size_t count = vcs_source_package_transport_file_count(transport);
    size_t base = strlen(dir);
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len))
            continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        (void)unlink(path);
    }
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len))
            continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n <= 0 || (size_t)n >= sizeof(path)) continue;
        for (char *p = strrchr(path, '/'); p && (size_t)(p - path) > base;
             p = strrchr(path, '/')) {
            *p = '\0';
            (void)rmdir(path);
        }
    }
    (void)rmdir(dir);
}
#endif

void zpub_stage_cleanup(
    const char *dir, const struct vcs_source_package_transport *transport)
{
#if defined(_WIN32)
    zpub_stage_cleanup_windows(dir, transport);
#else
    zpub_stage_cleanup_posix(dir, transport);
#endif
}

bool zpub_stage_create(const char *datadir,
                              char out[ZPUB_PATH_MAX])
{
#if defined(_WIN32)
    uint8_t nonce[16];
    char hex[33];
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        if (!rng_fill(nonce, sizeof(nonce))) return false;
        zcl_hex_encode(nonce, sizeof(nonce), hex);
        int n = snprintf(out, ZPUB_PATH_MAX, "%s/.accept-publish-%s",
                         datadir, hex);
        if (n <= 0 || n >= ZPUB_PATH_MAX) return false;
        if (platform_private_directory_create(out)) return true;
    }
    return false;
#else
    int n = snprintf(out, ZPUB_PATH_MAX, "%s/.accept-publish-XXXXXX",
                     datadir);
    return n > 0 && n < ZPUB_PATH_MAX && mkdtemp(out) != NULL;
#endif
}

/* Publisher lineage from the persisted releases (rebuildable projection):
 * parent = this key's latest release id, sequence = its sequence + 1. A key
 * with no persisted release is a root release (no parent, sequence 1). */
bool zpub_lineage(const char *zcode_dir, const char *publisher_hex,
                         bool *has_parent, uint8_t parent_root[32],
                         uint64_t *sequence)
{
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        LOG_FAIL("zcode.publish", "package index build failed for %s",
                 zcode_dir);
    uint64_t max_seq = 0;
    char latest_id[65] = "";
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *e =
            vcs_package_index_at(index, i);
        if (strcmp(e->publisher_hex, publisher_hex) == 0 &&
            e->publisher_sequence >= max_seq) {
            max_seq = e->publisher_sequence;
            (void)snprintf(latest_id, sizeof(latest_id), "%s",
                           e->release_id_hex);
        }
    }
    vcs_package_index_free(index);
    if (max_seq == UINT64_MAX)
        return false;
    *has_parent = max_seq > 0;
    *sequence = max_seq + 1u;
    return !*has_parent || zcl_hex_decode_lower(latest_id, parent_root, 32);
}

void zpub_bundle_free(struct zpub_accepted_bundle *bundle)
{
    if (!bundle) return;
    vcs_source_package_transport_free(&bundle->transport);
    vcs_package_mapping_set_free(&bundle->mapping);
    memset(bundle, 0, sizeof(*bundle));
    vcs_package_mapping_set_init(&bundle->mapping);
}

bool zpub_push_hex(struct json_value *out, const char *key,
                          const uint8_t *bytes, size_t len)
{
    if (!out || !key || (!bytes && len > 0) ||
        len > (SIZE_MAX - 1u) / 2u)
        return false;
    char *hex = zcl_malloc(len * 2u + 1u, "zcode.publish.hex");
    if (!hex) return false;
    zcl_hex_encode(bytes, len, hex);
    bool ok = json_push_kv_str(out, key, hex);
    free(hex);
    return ok;
}

bool zpub_decode_hex(const char *hex, size_t max_bytes,
                            uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 ||
        hex_len > max_bytes * 2u)
        return false;
    size_t len = hex_len / 2u;
    uint8_t *bytes = zcl_malloc(len, "zcode.publish.input");
    if (!bytes || !zcl_hex_decode_lower(hex, bytes, len)) {
        free(bytes);
        return false;
    }
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

bool zpub_copy_field(char *out, size_t cap, const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (!out || cap == 0 || len >= cap)
        return false;
    memcpy(out, value ? value : "", len + 1u);
    return true;
}

bool zpub_normalize(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    memset(bundle, 0, sizeof(*bundle));
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *datadir_arg = zdev_str(request->input, "datadir");
    const char *acceptance_datadir_arg =
        zdev_str(request->input, "acceptance_datadir");
    const char *source_root_arg = zdev_str(request->input, "source_root");
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, bundle->workspace, sizeof(bundle->workspace)) ||
        !datadir_arg || !platform_directory_canonical_real(
            datadir_arg, bundle->datadir, sizeof(bundle->datadir)) ||
        !platform_directory_canonical_real(
            acceptance_datadir_arg && acceptance_datadir_arg[0]
                ? acceptance_datadir_arg : datadir_arg,
            bundle->acceptance_datadir, sizeof(bundle->acceptance_datadir)) ||
        !source_root_arg ||
        !zcl_hex_decode_lower(source_root_arg, bundle->source_root, 32)) {
        zpub_fail(reply, "BAD_PUBLISH_INPUT",
                  "workspace, datadir, and optional acceptance_datadir must "
                  "resolve to existing directories and source_root must be "
                  "64 lowercase hex");
        return false;
    }
    const char *mapping_arg = zdev_str(
        request->input, "package_mapping_root");
    if (mapping_arg && mapping_arg[0]) {
        bundle->have_mapping =
            zcl_hex_decode_lower(mapping_arg, bundle->mapping_root, 32) &&
            vcs_package_mapping_set_load(
                bundle->workspace, bundle->mapping_root, &bundle->mapping) &&
            memcmp(bundle->mapping.source_tree_root,
                   bundle->source_root, 32) == 0;
        if (!bundle->have_mapping) {
            zpub_bundle_free(bundle);
            zpub_fail(reply, "PACKAGE_MAPPING_INVALID",
                      "package_mapping_root must be one complete immutable "
                      "mapping set for the exact accepted source tree");
            return false;
        }
    }
    return true;
}

static bool zpub_lane_acceptable(
    struct zcl_command_reply *reply, struct zpub_accepted_bundle *bundle,
    struct zcl_result found)
{
    if (!found.ok) {
        zpub_fail(reply, "LANE_NOT_ACCEPTED", found.message);
        return false;
    }
    if (bundle->lane.lane != VCS_ZCODE_LANE_PROVEN) {
        zpub_fail(reply, "LANE_NOT_ACCEPTED",
                  "publication requires the exact PROVEN root produced by "
                  "zcode work accept; FRONTIER and CANDIDATE are not human acceptance");
        return false;
    }
    return true;
}

bool zpub_find_lane_readonly(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    sqlite3 *db = NULL;
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(bundle->acceptance_datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (!owned && !zcl_native_node_db_require_readonly(
            bundle->acceptance_datadir, reply, "the ZCODE lane ledger",
            &db, ndb))
        return false;
    struct zcode_accepted_work_status accepted;
    struct zcl_result found = zcode_accepted_work_find(
        ndb, bundle->workspace, zdev_str(request->input, "source_root"),
        (int64_t)platform_time_wall_unix(), false, &accepted);
    if (found.ok)
        found = zcode_lane_find(
            ndb, bundle->workspace,
            zdev_str(request->input, "source_root"), &bundle->lane);
    if (!owned) zcl_native_node_db_close_readonly(&db, ndb);
    return zpub_lane_acceptable(reply, bundle, found);
}

bool zpub_find_lane_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(bundle->acceptance_datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (!owned && !zdev_open_db(bundle->acceptance_datadir, ndb)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "DATABASE_OPEN_FAILED",
                               "accept", true, false,
                               "the ZBuild ledger could not be opened",
                               "zcode.publish");
        return false;
    }
    struct zcode_accepted_work_status accepted;
    struct zcl_result found = zcode_accepted_work_find(
        ndb, bundle->workspace, zdev_str(request->input, "source_root"),
        (int64_t)platform_time_wall_unix(), true, &accepted);
    if (found.ok)
        found = zcode_lane_find(
            ndb, bundle->workspace,
            zdev_str(request->input, "source_root"), &bundle->lane);
    if (!owned) node_db_close(ndb);
    return zpub_lane_acceptable(reply, bundle, found);
}

/* Reload and re-verify the exact task/candidate/policy/receipt/proof-set
 * chain the accepted lane names, never trusting caller claims. */
static bool zpub_verify_acceptance(
    struct zpub_accepted_bundle *bundle, struct zcl_command_reply *reply)
{
    struct vcs_zcode_lane_receipt_v1 receipt;
    uint8_t proof_set_root[32];
    bool accepted =
        zpub_load_task(bundle->workspace, bundle->lane.task_root_sha3,
                       &bundle->task) &&
        zpub_load_candidate(bundle->workspace,
                            bundle->lane.candidate_root_sha3,
                            &bundle->candidate) &&
        zpub_load_policy(bundle->workspace,
                         bundle->lane.proof_policy_root_sha3,
                         &bundle->policy) &&
        zpub_load_lane_receipt(bundle->workspace,
                               bundle->lane.receipt_root_sha3, &receipt,
                               bundle->candidate.author_pubkey,
                               bundle->receipt_wire) &&
        zcl_hex_decode_lower(bundle->lane.proof_set_root_sha3,
                             proof_set_root, 32) &&
        vcs_zcode_lane_receipt_validate_for_candidate(
            &receipt, &bundle->task, &bundle->candidate,
            &bundle->policy) == VCS_ZCODE_DEV_OK &&
        memcmp(receipt.proof_set_root, proof_set_root, 32) == 0 &&
        memcmp(bundle->candidate.candidate_source_root,
               bundle->source_root, 32) == 0 &&
        memcmp(receipt.source_root, bundle->source_root, 32) == 0;
    if (!accepted) {
        zpub_fail(reply, "LANE_ACCEPTANCE_INVALID",
                  "the lane receipt, signature, proof-set root, task, "
                  "candidate, policy, or source binding failed CAS "
                  "reverification");
        return false;
    }
    if (!zpub_proof_set_valid(bundle->workspace,
                              bundle->lane.proof_set_root_sha3,
                              &bundle->task, &bundle->candidate)) {
        zpub_fail(reply, "PROOF_SET_INVALID",
                  "the accepted proof set or one of its signed work receipts "
                  "does not rederive and bind to this task and candidate");
        return false;
    }
    return true;
}

static bool zpub_verify_claimed_bindings(
    const struct zcl_command_request *request, struct zpub_accepted_bundle *bundle,
    struct zcl_command_reply *reply)
{
    const char *claimed_task = zdev_str(request->input, "task_root");
    const char *claimed_receipt =
        zdev_str(request->input, "lane_receipt_root");
    if ((claimed_task && claimed_task[0] &&
         strcmp(claimed_task, bundle->lane.task_root_sha3) != 0) ||
        (claimed_receipt && claimed_receipt[0] &&
         strcmp(claimed_receipt, bundle->lane.receipt_root_sha3) != 0)) {
        zpub_fail(reply, "CLAIMED_BINDING_MISMATCH",
                  "task_root or lane_receipt_root does not match the "
                  "verified acceptance");
        return false;
    }
    return true;
}

static bool zpub_verify_mapping_binding(
    struct zpub_accepted_bundle *bundle, struct zcl_command_reply *reply)
{
    uint8_t lane_receipt_root[32];
    if (!zcl_hex_decode_lower(bundle->lane.receipt_root_sha3,
                              lane_receipt_root, 32)) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "LANE_ACCEPTANCE_INVALID",
                  "the verified PROVEN accepted-work root is not canonical");
        return false;
    }
    if (bundle->have_mapping &&
        memcmp(bundle->mapping.lane_receipt_root,
               lane_receipt_root, 32) != 0) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "PACKAGE_MAPPING_LANE_MISMATCH",
                  "package_mapping_root does not bind the verified PROVEN accepted work");
        return false;
    }
    return true;
}

static bool zpub_build_transport_and_recipe(
    struct zpub_accepted_bundle *bundle, struct zcl_command_reply *reply)
{
    uint8_t lane_receipt_root[32];
    (void)zcl_hex_decode_lower(bundle->lane.receipt_root_sha3,
                               lane_receipt_root, 32);
    if (!vcs_source_package_transport_build_accepted(
            bundle->workspace, bundle->source_root,
            lane_receipt_root, (int64_t)platform_time_wall_unix(),
            &bundle->transport)) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "SOURCE_PACKAGE_FAILED",
                  "the exact accepted ZVCS tree, LICENSE, complete accepted "
                  "work authority, or compressed source carrier could not "
                  "be rederived as one "
                  "bounded canonical content.v2 package");
        return false;
    }

    uint8_t *acceptance_recipe_wire = NULL;
    size_t acceptance_recipe_wire_len = 0;
    uint8_t recipe_checked[32];
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    bool recipe_ok =
        vcs_object_load_raw(bundle->workspace,
                            bundle->task.acceptance_tests_root,
                            &acceptance_recipe_wire,
                            &acceptance_recipe_wire_len) == 0 &&
        acceptance_recipe_wire_len <= VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES &&
        vcs_package_recipe_parse(acceptance_recipe_wire,
                                 acceptance_recipe_wire_len,
                                 &recipe) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(&recipe, recipe_checked) ==
            VCS_PACKAGE_RECIPE_OK &&
        memcmp(recipe_checked, bundle->task.acceptance_tests_root, 32) == 0;
    vcs_package_recipe_free(&recipe);
    free(acceptance_recipe_wire);
    if (!recipe_ok) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "RECIPE_CAS_INVALID",
                  "the task acceptance recipe is absent, corrupt, or does "
                  "not rederive its CAS root");
        return false;
    }
    return true;
}

bool zpub_prepare_accepted_objects(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    if (!zpub_verify_acceptance(bundle, reply))
        return false;
    if (!zpub_verify_claimed_bindings(request, bundle, reply))
        return false;
    if (!zpub_verify_mapping_binding(bundle, reply))
        return false;
    return zpub_build_transport_and_recipe(bundle, reply);
}

bool zpub_release_body(
    const struct vcs_package_release *release, uint8_t **body_out,
    size_t *body_len_out, uint8_t digest[32])
{
    *body_out = NULL;
    *body_len_out = 0;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_release_error err =
        vcs_package_release_id(release, digest);
    if (err == VCS_PACKAGE_RELEASE_OK)
        err = vcs_package_release_serialize(release, &wire, &wire_len);
    if (err != VCS_PACKAGE_RELEASE_OK ||
        wire_len <= VCS_PACKAGE_RELEASE_SIGNATURE_BYTES) {
        free(wire);
        return false;
    }
    size_t body_len = wire_len - VCS_PACKAGE_RELEASE_SIGNATURE_BYTES;
    uint8_t *body = zcl_malloc(body_len, "zcode.publish.release_body");
    if (!body) {
        free(wire);
        return false;
    }
    memcpy(body, wire, body_len);
    free(wire);
    *body_out = body;
    *body_len_out = body_len;
    return true;
}

bool zpub_lineage_claims_match(
    const struct json_value *input, bool has_parent,
    const uint8_t parent_root[32], uint64_t sequence)
{
    int64_t seq_claim = zdev_int(input, "publisher_sequence", 0);
    if (seq_claim > 0 && (uint64_t)seq_claim != sequence)
        return false;
    const char *parent_claim = zdev_str(input, "parent_release_root");
    if (!parent_claim || !parent_claim[0])
        return true;
    uint8_t checked[32];
    return has_parent &&
        zcl_hex_decode_lower(parent_claim, checked, 32) &&
        memcmp(checked, parent_root, 32) == 0;
}

bool zpub_release_lineage_valid(
    const char *zcode_dir, const struct vcs_package_release *release,
    const uint8_t release_id[32])
{
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        LOG_FAIL("zcode.publish", "package index build failed for %s",
                 zcode_dir);
    char publisher_hex[2 * VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 1u];
    char release_id_hex[65];
    zcl_hex_encode(release->publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, publisher_hex);
    zcl_hex_encode(release_id, 32, release_id_hex);
    uint64_t max_seq = 0;
    char latest_id[65] = "";
    bool duplicate = false;
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *entry =
            vcs_package_index_at(index, i);
        if (strcmp(entry->publisher_hex, publisher_hex) != 0)
            continue;
        if (strcmp(entry->release_id_hex, release_id_hex) == 0)
            duplicate = true;
        if (entry->publisher_sequence > max_seq) {
            max_seq = entry->publisher_sequence;
            (void)snprintf(latest_id, sizeof(latest_id), "%s",
                           entry->release_id_hex);
        }
    }
    vcs_package_index_free(index);
    if (duplicate)
        return true;
    if (max_seq == UINT64_MAX)
        return false;
    if (release->publisher_sequence != max_seq + 1u ||
        release->has_parent != (max_seq > 0))
        return false;
    uint8_t latest_root[32];
    return max_seq == 0 ||
        (zcl_hex_decode_lower(latest_id, latest_root, 32) &&
         memcmp(release->parent_root, latest_root, 32) == 0);
}

void zpub_common_output(
    struct json_value *out, const struct zpub_accepted_bundle *bundle)
{
    zdev_push_root(out, "source_root", bundle->source_root);
    zdev_push_root(out, "recipe_root", bundle->transport.recipe_root);
    zdev_push_root(out, "acceptance_recipe_root",
                   bundle->task.acceptance_tests_root);
    (void)json_push_kv_str(out, "lane", bundle->lane.lane_name);
    (void)json_push_kv_str(out, "lane_receipt_root",
                           bundle->lane.receipt_root_sha3);
    (void)json_push_kv_str(out, "proof_set_root",
                           bundle->lane.proof_set_root_sha3);
    (void)json_push_kv_str(out, "task_root",
                           bundle->lane.task_root_sha3);
    (void)json_push_kv_str(out, "candidate_root",
                           bundle->lane.candidate_root_sha3);
    (void)json_push_kv_str(
        out, "authority", "SIGNED_LANE_RECEIPT_AND_RELEASE_ENVELOPE");
    (void)json_push_kv_str(out, "source_transport",
                           "vcs_source_bundle.v2");
    (void)json_push_kv_int(out, "source_bundle_bytes",
                           (int64_t)bundle->transport.source_transport_bytes);
    (void)json_push_kv_int(
        out, "source_bytes",
        (int64_t)bundle->transport.bundle_metrics.source_bytes);
    (void)json_push_kv_int(out, "source_files",
                           bundle->transport.bundle_metrics.file_count);
    (void)json_push_kv_int(out, "source_shards",
                           bundle->transport.source.shard_count);
    (void)json_push_kv_int(out, "offline_input_bytes",
                           (int64_t)bundle->transport.offline_input_bytes);
    (void)json_push_kv_int(out, "offline_input_files",
                           bundle->transport.offline_input_count);
    (void)json_push_kv_int(
        out, "carrier_files",
        vcs_source_package_transport_file_count(&bundle->transport));
}
