/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private declarations shared between the native `zcode work`
 * command siblings (native_zcode_work_command.c,
 * native_zcode_work_reuse.c, native_zcode_work_reuse_plan.c,
 * native_zcode_work_start.c, native_zcode_work_evidence.c,
 * native_zcode_work_status.c, native_zcode_work_accept.c,
 * native_zcode_work_review.c and native_zcode_work_publish.c).
 * Nothing here is a public API: every symbol is a static-linkage-turned-
 * internal-linkage helper reused across exactly these sibling translation
 * units, never included elsewhere. */
#ifndef ZCL_NATIVE_ZCODE_WORK_PRIV_H
#define ZCL_NATIVE_ZCODE_WORK_PRIV_H

#include "command/native_command.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "services/build_fabric_service.h"
#include "services/package_lifecycle.h"
#include "vcs/package_index.h"
#include "vcs/package_prepare.h"
#include "vcs/package_recipe.h"
#include "vcs/package_reuse.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_task_index.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZWORK_PATH_MAX 4400
#define ZWORK_LINE_COUNT_MAX 65536u
#define ZWORK_REUSE_API_TEXT_MAX 256u
#define ZWORK_REUSE_HEADER_BYTES_MAX (64u * 1024u)
#define ZWORK_LOG "zcode.work"

struct zwork_patch_summary {
    struct vcs_zcode_patch_v1 patch;
    uint64_t added_lines;
    uint64_t deleted_lines;
    size_t public_api_changes;
    bool line_counts_exact;
};

struct zwork_proof_snapshot {
    bool available;
    struct build_fabric_proof_evaluation facts;
    /* Latest async proof chain event the read ledger holds for the action
     * ("" when it holds none).  Outstanding means the chain is not
     * superseded; ledger_supervised means a named or resident node datadir
     * whose supervisor consumes outstanding chains, as opposed to the closed
     * scratch ledger.  Together they decide whether CANDIDATE_ADMITTED is a
     * real wait for independent reproduction or an incomplete execution —
     * the same fact zcode.work.run classifies. */
    char async_proof_state[BUILD_PROOF_EVENT_STATE_MAX + 1];
    bool async_proof_outstanding;
    bool ledger_supervised;
    /* Action identity recovered from the durable proof chain when no receipt
     * can name it yet ("" while nothing is bound). */
    char action_root[BUILD_PROOF_EVENT_ROOT_HEX + 1];
};

struct zwork_reuse_candidate {
    struct vcs_package_reuse_input input;
    char api_text[VCS_PACKAGE_REUSE_MAX_APIS][ZWORK_REUSE_API_TEXT_MAX];
    struct vcs_package_build_receipt receipt;
    bool receipt_verified;
    bool installed_invalid;
};

struct zwork_peer_inventory {
    bool live;
    bool truncated;
    bool pointer_board_available;
    bool pointer_board_truncated;
    size_t roots_seen;
    size_t pointer_records_seen;
    size_t roots_matched;
};

/* Shared plumbing (native_zcode_work_command.c): the task-local workspace
 * path, the bounded JSON accessors of the HOT_FORK input core, the two
 * build-ledger openers, the compact failure reply, the canonical task
 * resolver and the bounded continuation writer. */
bool zwork_task_path(char out[ZWORK_PATH_MAX], const char *task,
                     const char *suffix);
const char *zwork_str(const struct json_value *input, const char *key);
bool zwork_bool(const struct json_value *input, const char *key);
int64_t zwork_int(const struct json_value *input, const char *key,
                  int64_t fallback);
bool zwork_open_build_ledger(struct node_db *ndb, const char *path,
                             const char *reason, bool allow_create);
struct node_db *zwork_runtime_ledger(const char *db_path);
void zwork_fail(struct zcl_command_reply *reply, const char *code,
                const char *phase, const char *detail, bool retryable,
                bool mutated);
bool zwork_coordination_handoff(const struct zcl_command_reply *inner,
                                const char *expected_workspace,
                                struct zcl_command_reply *reply);
char *zwork_hex_alloc(const uint8_t *bytes, size_t len, const char *label);
bool zwork_scopes(const struct vcs_package_prepared *prepared,
                  bool include_package_metadata, char out[1024]);
uint64_t zwork_source_bytes(const struct vcs_package_prepared *prepared);
bool zwork_regular_package_config(const char *workspace);
bool zwork_prepare(const char *workspace,
                   struct vcs_package_prepared *prepared,
                   char *detail, size_t detail_cap);
bool zwork_read_bounded_regular(const char *path, size_t maximum,
                                uint8_t **out, size_t *out_len);
const struct vcs_zcode_task_index_entry *zwork_resolve(
    const struct vcs_zcode_task_index *index, const char *work,
    bool *ambiguous);
bool zwork_add_next(struct zcl_command_reply *reply, const char *command,
                    const struct json_value *input, const char *reason);

/* Reusable-package facts (native_zcode_work_reuse.c): index rows that the
 * package lifecycle would resolve again, their verified installed receipts,
 * the composed dependency lock and the signed peer inventory. */
bool zwork_lock_has_root(const struct vcs_package_lock *lock,
                         const char *root_hex);
bool zwork_reuse_load_facts(const char *zcode_dir,
                            const struct vcs_package_index_entry *entry,
                            struct vcs_package_recipe *recipe);
bool zwork_reuse_api_add(struct zwork_reuse_candidate *candidate,
                         const char *api, size_t len);
void zwork_reuse_installed(const char *datadir, const char *zcode_dir,
                           const struct vcs_package_index_entry *entry,
                           struct zwork_reuse_candidate *candidate);
bool zwork_reuse_is_lifecycle_release(
    const struct vcs_package_index *index,
    const struct vcs_package_index_entry *candidate);
void zwork_peer_inventory_apply(struct zwork_reuse_candidate *candidates,
                                size_t candidate_count,
                                struct zwork_peer_inventory *inventory);
bool zwork_compose_selected_lock(struct vcs_package_prepared *prepared,
                                 const struct vcs_package_index *index,
                                 const struct zwork_reuse_candidate *candidates,
                                 const struct vcs_package_reuse_plan *reuse,
                                 size_t *added_out);

/* Reuse projection (native_zcode_work_reuse_plan.c): the human reuse plan
 * and its expert companion, plus the exact zcode.use continuation. */
const char *zwork_reuse_datadir(const struct zcl_command_request *request);
bool zwork_use_next_input(const struct zcl_command_request *request,
                          const char *package_ref,
                          struct json_value *next_input);
bool zwork_reuse_render(
    const struct zcl_command_request *request, const char *goal,
    const char *license,
    struct vcs_package_prepared *prepared, struct json_value *plan_json,
    struct json_value *expert_json, bool *complete_out, bool *composed_out,
    bool *filter_truncated_out, bool *filter_incomplete_out,
    size_t *indexed_out, size_t *matched_out, size_t *skipped_out,
    char selected_root[65],
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u]);

/* Canonical evidence readers (native_zcode_work_evidence.c): the goal blob,
 * the latest patch and its exact line deltas, the proof policy, the
 * read-only proof-ledger snapshot and the acceptance-plan identity. */
char *zwork_load_goal(const char *workspace, const char *root_hex);
bool zwork_patch_summary_load(const char *workspace,
                              const struct vcs_zcode_task_index_entry *entry,
                              struct zwork_patch_summary *out);
bool zwork_policy_load(const char *workspace, const char *root_hex,
                       struct vcs_zcode_proof_policy_v1 *policy);
void zwork_proof_snapshot_read(const char *workspace, const char *task_root,
                               const char *action_id,
                               const char *candidate_root,
                               const char *proof_datadir, int64_t now,
                               struct zwork_proof_snapshot *out);
bool zwork_proof_required(const struct vcs_zcode_proof_policy_v1 *policy,
                          uint32_t kind, uint16_t minimum);
bool zwork_confirmation_identity(
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_proof_snapshot *proof, char identity[65]);
bool zwork_proof_receipt_roots(const char *workspace,
                               const char *proof_set_hex,
                               struct json_value *roots_json,
                               bool *available);

/* Acceptance (native_zcode_work_accept.c): the inner lane, evidence and
 * promotion calls plus the accepted-candidate publication binding, reused by
 * the acceptance handler alone. */
bool zwork_bind_accepted_publication(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *accepted_reply,
    char candidate_workspace[ZWORK_PATH_MAX],
    struct vcs_devloop_accepted_candidate_result *publication);

#endif /* ZCL_NATIVE_ZCODE_WORK_PRIV_H */
