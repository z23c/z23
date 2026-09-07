/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the canonical evidence readers behind `zcode work status` — the
 * goal blob, the latest patch and its exact line deltas, the proof policy,
 * the read-only proof-ledger snapshot and the acceptance-plan identity —
 * split out of native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. Every reader re-verifies the bytes it loads and
 * stores nothing. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "base/hex.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "services/build_fabric_service.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/package_recipe.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_task_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *zwork_load_goal(const char *workspace, const char *root_hex)
{
    uint8_t root[32], check[32], *bytes = NULL;
    size_t len = 0;
    if (!zcl_hex_decode_lower(root_hex, root, 32) ||
        vcs_object_load_raw(workspace, root, &bytes, &len) != 0 ||
        len == 0 || len > 4096 || memchr(bytes, '\0', len)) {
        free(bytes); return NULL;
    }
    sha3_256(bytes, len, check);
    if (memcmp(root, check, 32) != 0) { free(bytes); return NULL; }
    char *goal = zcl_malloc(len + 1u, "zcode.work.goal");
    if (!goal) { free(bytes); return NULL; }
    memcpy(goal, bytes, len); goal[len] = '\0'; free(bytes);
    return goal;
}

static int zwork_line_hash_compare(const void *left, const void *right)
{
    return memcmp(left, right, 32);
}

/* Lines are the newline-terminated runs plus one final unterminated run. */
static size_t zwork_line_count(const uint8_t *bytes, size_t len)
{
    size_t count = 0;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] == '\n') count++;
    if (len > 0 && bytes[len - 1u] != '\n') count++;
    return count;
}

static size_t zwork_line_hash_fill(const uint8_t *bytes, size_t len,
                                   uint8_t *hashes)
{
    size_t start = 0, at = 0;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] != '\n') continue;
        sha3_256(bytes + start, i + 1u - start, hashes + at++ * 32u);
        start = i + 1u;
    }
    if (start < len)
        sha3_256(bytes + start, len - start, hashes + at++ * 32u);
    return at;
}

static bool zwork_line_hashes(const uint8_t *bytes, size_t len,
                              uint8_t **out, size_t *count_out,
                              bool *text_out)
{
    *out = NULL; *count_out = 0; *text_out = false;
    if (len > 0 && (!bytes || memchr(bytes, '\0', len))) return true;
    size_t count = zwork_line_count(bytes, len);
    if (count > ZWORK_LINE_COUNT_MAX) return true;
    uint8_t *hashes = count > 0
        ? zcl_malloc(count * 32u, "zcode.work.line_hashes") : NULL;
    if (count > 0 && !hashes) return false;
    if (zwork_line_hash_fill(bytes, len, hashes) != count) {
        free(hashes); return false;
    }
    if (count > 1)
        qsort(hashes, count, 32u, zwork_line_hash_compare);
    *out = hashes; *count_out = count; *text_out = true;
    return true;
}

static bool zwork_blob(const char *workspace, const uint8_t root[32],
                       uint8_t **bytes, size_t *len)
{
    return vcs_object_get(workspace, root, VCS_TAG_BLOB, bytes, len) == 0;
}

/* Two sorted line-hash multisets share exactly their merge intersection. */
static size_t zwork_line_common(const uint8_t *old_hashes, size_t old_count,
                                const uint8_t *new_hashes, size_t new_count)
{
    size_t oi = 0, ni = 0, common = 0;
    while (oi < old_count && ni < new_count) {
        int cmp = memcmp(old_hashes + oi * 32u, new_hashes + ni * 32u, 32u);
        if (cmp < 0) oi++;
        else if (cmp > 0) ni++;
        else { common++; oi++; ni++; }
    }
    return common;
}

static bool zwork_line_delta(const char *workspace,
                             const struct vcs_zcode_patch_change_v1 *change,
                             uint64_t *added, uint64_t *deleted,
                             bool *exact)
{
    uint8_t *old_bytes = NULL, *new_bytes = NULL;
    size_t old_len = 0, new_len = 0;
    bool have_old = change->kind != VCS_DIFF_ADDED;
    bool have_new = change->kind != VCS_DIFF_REMOVED;
    if ((have_old && !zwork_blob(workspace, change->old_blob,
                                 &old_bytes, &old_len)) ||
        (have_new && !zwork_blob(workspace, change->new_blob,
                                 &new_bytes, &new_len))) {
        free(new_bytes); free(old_bytes); return false;
    }
    uint8_t *old_hashes = NULL, *new_hashes = NULL;
    size_t old_count = 0, new_count = 0;
    bool old_text = true, new_text = true;
    bool ok = (!have_old || zwork_line_hashes(
                   old_bytes, old_len, &old_hashes, &old_count, &old_text)) &&
        (!have_new || zwork_line_hashes(
                   new_bytes, new_len, &new_hashes, &new_count, &new_text));
    free(new_bytes); free(old_bytes);
    if (!ok) { free(new_hashes); free(old_hashes); return false; }
    if (!old_text || !new_text) {
        *exact = false; free(new_hashes); free(old_hashes); return true;
    }
    size_t common = zwork_line_common(old_hashes, old_count,
                                      new_hashes, new_count);
    *deleted += old_count - common;
    *added += new_count - common;
    free(new_hashes); free(old_hashes); return true;
}

static bool zwork_recipe_load(const char *workspace, const char *root_hex,
                              struct vcs_package_recipe *recipe)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(root_hex, root, sizeof(root)) &&
        vcs_object_load_raw_bounded(workspace, root,
                                    VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                                    &wire, &len) == 0 &&
        vcs_package_recipe_parse(wire, len, recipe) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(recipe, checked) == VCS_PACKAGE_RECIPE_OK &&
        memcmp(root, checked, sizeof(root)) == 0;
    free(wire); return ok;
}

static bool zwork_is_public_header(const struct vcs_package_recipe *recipe,
                                   const char *path)
{
    for (size_t i = 0; i < recipe->public_headers.count; i++)
        if (strcmp(recipe->public_headers.items[i], path) == 0) return true;
    return false;
}

static bool zwork_patch_object_load(const char *workspace,
                                    const char *root_hex,
                                    struct vcs_zcode_patch_v1 *patch)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(root_hex, root, sizeof(root)) &&
        vcs_object_load_raw_bounded(workspace, root,
                                    VCS_ZCODE_TASK_MAX_PATCH_BYTES,
                                    &wire, &len) == 0 &&
        vcs_zcode_patch_parse(wire, len, patch) == VCS_ZCODE_PATCH_OK &&
        vcs_zcode_patch_root(patch, checked) == VCS_ZCODE_PATCH_OK &&
        memcmp(root, checked, sizeof(root)) == 0;
    free(wire);
    return ok;
}

static bool zwork_patch_changes_measure(const char *workspace,
                                        const struct vcs_package_recipe *recipe,
                                        struct zwork_patch_summary *out)
{
    bool ok = true;
    for (size_t i = 0; i < out->patch.count && ok; i++) {
        const struct vcs_zcode_patch_change_v1 *change =
            &out->patch.changes[i];
        ok = zwork_line_delta(workspace, change, &out->added_lines,
                              &out->deleted_lines,
                              &out->line_counts_exact);
        if (zwork_is_public_header(recipe, change->path))
            out->public_api_changes++;
    }
    return ok;
}

bool zwork_patch_summary_load(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    struct zwork_patch_summary *out)
{
    memset(out, 0, sizeof(*out));
    vcs_zcode_patch_init(&out->patch);
    out->line_counts_exact = true;
    if (!entry->latest_patch_root_hex[0]) return true;
    bool ok = zwork_patch_object_load(
        workspace, entry->latest_patch_root_hex, &out->patch);
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    ok = ok && zwork_recipe_load(workspace, entry->acceptance_tests_root_hex,
                                 &recipe);
    if (!ok) {
        vcs_package_recipe_free(&recipe);
        vcs_zcode_patch_free(&out->patch);
        return false;
    }
    ok = zwork_patch_changes_measure(workspace, &recipe, out);
    vcs_package_recipe_free(&recipe);
    if (!ok) vcs_zcode_patch_free(&out->patch);
    return ok;
}

bool zwork_policy_load(
    const char *workspace, const char *root_hex,
    struct vcs_zcode_proof_policy_v1 *policy)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    bool ok = policy && zcl_hex_decode_lower(root_hex, root, 32) &&
        vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(policy, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, sizeof(root)) == 0;
    free(wire);
    return ok;
}

/* An explicit datadir names another node's ledger; otherwise the ledger is
 * the closed task-local scratch ZBuild. Only an existing file is opened. */
static bool zwork_proof_ledger_path(const char *task_root,
                                    const char *proof_datadir,
                                    char db_path[ZWORK_PATH_MAX],
                                    bool *explicit_out)
{
    char resolved_datadir[ZWORK_PATH_MAX];
    *explicit_out = proof_datadir && proof_datadir[0];
    int n = *explicit_out
        ? (platform_directory_canonical_real(
               proof_datadir, resolved_datadir, sizeof(resolved_datadir))
            ? snprintf(db_path, ZWORK_PATH_MAX, "%s/node.db",
                       resolved_datadir) : -1)
        : (zwork_task_path(resolved_datadir, task_root, "/zbuild")
            ? snprintf(db_path, ZWORK_PATH_MAX, "%s/node.db",
                       resolved_datadir) : -1);
    struct platform_positioned_file db_file;
    platform_positioned_file_init(&db_file);
    bool present = n > 0 && (size_t)n < ZWORK_PATH_MAX &&
        platform_positioned_file_open(&db_file, db_path);
    platform_positioned_file_close(&db_file);
    return present;
}

static const struct db_build_proof_event *zwork_proof_latest_event(
    const struct db_build_proof_event *events, int event_count,
    const char *candidate_root, bool candidate_known, bool *outstanding_out)
{
    const struct db_build_proof_event *latest = NULL;
    *outstanding_out = false;
    for (int i = 0; i < event_count; i++) {
        if (candidate_known &&
            strcmp(events[i].candidate_root_sha3, candidate_root) != 0)
            continue;
        if (!events[i].state[0])
            continue;
        latest = &events[i];
        if (strcmp(events[i].state, "SUPERSEDED") != 0)
            *outstanding_out = true;
    }
    return latest;
}

/* A later independently signed display receipt may name an action that
 * is not in this operator's ledger. It stays visible in the task index,
 * but cannot redirect the proof snapshot away from the durable proof
 * event chain. */
static bool zwork_proof_recover_action(
    struct node_db *ndb, const char *workspace,
    const struct db_build_proof_event *events, int event_count,
    const char *candidate_root, bool candidate_known, int64_t now,
    char action[BUILD_PROOF_EVENT_ROOT_HEX + 1],
    struct build_fabric_proof_evaluation *facts)
{
    for (int i = event_count - 1; i >= 0; i--) {
        if (candidate_known && strcmp(
                events[i].candidate_root_sha3, candidate_root) != 0)
            continue;
        struct build_fabric_proof_evaluation candidate_facts = {0};
        if (!build_fabric_proof_evaluate_readonly(
                ndb, workspace, events[i].action_id, now,
                &candidate_facts).ok ||
            !candidate_facts.policy_satisfied)
            continue;
        (void)snprintf(action, BUILD_PROOF_EVENT_ROOT_HEX + 1, "%s",
                       events[i].action_id);
        *facts = candidate_facts;
        return true;
    }
    return false;
}

/* A task the index cannot name by action still has a candidate root; one of
 * the two identities must be present before any ledger is opened. */
static bool zwork_proof_inputs_valid(const char *workspace,
                                     const char *task_root,
                                     bool action_known, bool candidate_known)
{
    return workspace && task_root && strlen(task_root) == 64u &&
           (action_known || candidate_known);
}

/* The resident node's own handle when the path is its datadir, otherwise a
 * lightweight read-only reopen this reader closes again. */
static struct node_db *zwork_proof_open_ledger(const char *db_path,
                                               struct node_db *local,
                                               bool *owned_out)
{
    struct node_db *ndb = zwork_runtime_ledger(db_path);
    *owned_out = ndb != NULL;
    if (ndb) return ndb;
    return node_db_open_existing_runtime(local, db_path,
                                         "zcode.work.status.proof")
        ? local : NULL;
}

static void zwork_proof_apply_latest(
    const struct db_build_proof_event *latest, bool outstanding,
    char action[BUILD_PROOF_EVENT_ROOT_HEX + 1],
    struct zwork_proof_snapshot *out)
{
    if (!latest) return;
    (void)snprintf(out->async_proof_state,
                   sizeof(out->async_proof_state), "%s", latest->state);
    out->async_proof_outstanding = outstanding;
    if (!action[0] && outstanding)
        (void)snprintf(action, BUILD_PROOF_EVENT_ROOT_HEX + 1, "%s",
                       latest->action_id);
}

/* Human status is a projection only. Re-evaluate the exact action and receipt
 * bytes without storing a proof set or promoting receipt trust. Before the
 * first receipt exists the task index cannot name the action, so the durable
 * proof chain (keyed by task and candidate roots) supplies both the action
 * identity and the in-flight reading of CANDIDATE_ADMITTED — the same fact
 * zcode.work.run classifies. */
void zwork_proof_snapshot_read(
    const char *workspace, const char *task_root, const char *action_id,
    const char *candidate_root, const char *proof_datadir, int64_t now,
    struct zwork_proof_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    bool action_known = action_id && strlen(action_id) == 64u;
    bool candidate_known = candidate_root && strlen(candidate_root) == 64u;
    if (!zwork_proof_inputs_valid(workspace, task_root, action_known,
                                  candidate_known))
        return;
    char db_path[ZWORK_PATH_MAX];
    bool explicit_datadir = false;
    if (!zwork_proof_ledger_path(task_root, proof_datadir, db_path,
                                 &explicit_datadir))
        return;
    struct node_db local_ndb = {0};
    bool owned = false;
    struct node_db *ndb = zwork_proof_open_ledger(db_path, &local_ndb,
                                                  &owned);
    if (!ndb) return;
    char action[BUILD_PROOF_EVENT_ROOT_HEX + 1] = {0};
    if (action_known)
        (void)snprintf(action, sizeof(action), "%s", action_id);
    struct db_build_proof_event events[64];
    int event_count = db_build_proof_events_for_task(
        ndb, task_root, events, sizeof(events) / sizeof(events[0]));
    bool outstanding = false;
    const struct db_build_proof_event *latest = zwork_proof_latest_event(
        events, event_count, candidate_root, candidate_known, &outstanding);
    zwork_proof_apply_latest(latest, outstanding, action, out);
    out->ledger_supervised = explicit_datadir || owned;
    struct zcl_result result = action[0]
        ? build_fabric_proof_evaluate_readonly(ndb, workspace, action, now,
                                               &out->facts)
        : ZCL_ERR(-1, "no action identity is bound to this task yet");
    bool recovered = (!result.ok || !out->facts.policy_satisfied) &&
        zwork_proof_recover_action(ndb, workspace, events, event_count,
                                   candidate_root, candidate_known, now,
                                   action, &out->facts);
    if (action[0])
        (void)snprintf(out->action_root, sizeof(out->action_root), "%s",
                       action);
    if (!owned) node_db_close(ndb);
    out->available = result.ok || recovered;
}

bool zwork_proof_required(
    const struct vcs_zcode_proof_policy_v1 *policy, uint32_t kind,
    uint16_t minimum)
{
    return (policy->required_proofs & kind) != 0 || minimum > 0;
}

bool zwork_confirmation_identity(
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_proof_snapshot *proof, char identity[65])
{
    identity[0] = '\0';
    if (!entry || !proof || !proof->available ||
        !proof->facts.policy_satisfied ||
        !proof->facts.proof_set_root_sha3[0])
        return false;
    uint8_t task[32], candidate[32], policy[32], proof_set[32], plan[32];
    if (!zcl_hex_decode_lower(entry->task_root_hex, task, sizeof(task)) ||
        !zcl_hex_decode_lower(entry->latest_candidate_root_hex, candidate,
                              sizeof(candidate)) ||
        !zcl_hex_decode_lower(entry->proof_policy_root_hex, policy,
                              sizeof(policy)) ||
        !zcl_hex_decode_lower(proof->facts.proof_set_root_sha3, proof_set,
                              sizeof(proof_set)) ||
        vcs_zcode_acceptance_plan_root(task, candidate, policy, proof_set,
                                       plan) != VCS_ZCODE_DEV_OK)
        return false;
    zcl_hex_encode(plan, sizeof(plan), identity);
    return true;
}

/* Load the exact, already-canonical proof-set members; a corrupt or missing
 * object leaves the set unavailable rather than reconstructing it. */
static bool zwork_proof_set_roots_load(
    const char *workspace, const uint8_t expected[32],
    uint8_t (*roots)[32], size_t *count_out)
{
    uint8_t *wire = NULL, checked[32];
    size_t wire_len = 0;
    *count_out = 0;
    bool exact = vcs_object_load_raw(
            workspace, expected, &wire, &wire_len) == 0 &&
        vcs_zcode_proof_set_parse(
            wire, wire_len, roots, VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
            count_out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])roots, *count_out, checked) ==
            VCS_ZCODE_DEV_OK &&
        memcmp(expected, checked, 32) == 0;
    free(wire);
    return exact;
}

/* Project the exact, already-canonical proof-set members. Missing or corrupt
 * CAS bytes stay unavailable; this reader never reconstructs or stores a
 * substitute authority. */
bool zwork_proof_receipt_roots(
    const char *workspace, const char *proof_set_hex,
    struct json_value *roots_json, bool *available)
{
    if (!roots_json || !available) return false;
    json_init(roots_json);
    json_set_array(roots_json);
    *available = false;
    uint8_t expected[32];
    if (!workspace || !proof_set_hex ||
        !zcl_hex_decode_lower(proof_set_hex, expected, 32))
        return true;
    uint8_t (*roots)[32] = zcl_malloc(
        sizeof(*roots) * VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
        "zcode.work.proof_receipt_roots");
    if (!roots) return false;
    size_t count = 0;
    bool exact = zwork_proof_set_roots_load(workspace, expected, roots,
                                            &count);
    bool ok = true;
    for (size_t i = 0; exact && ok && i < count; i++) {
        char hex[65];
        struct json_value value;
        zcl_hex_encode(roots[i], 32, hex);
        json_init(&value);
        json_set_str(&value, hex);
        ok = json_push_back(roots_json, &value);
        json_free(&value);
    }
    free(roots);
    if (exact && ok) *available = true;
    return ok;
}
