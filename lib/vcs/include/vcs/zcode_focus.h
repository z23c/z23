/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical shared-focus, claim, report, and handoff objects. */
#ifndef ZCL_VCS_ZCODE_FOCUS_H
#define ZCL_VCS_ZCODE_FOCUS_H

#include "ontology/ontology.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_work_swarm.h"
#include "vcs/zcode_write_scope.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_FOCUS_VERSION 1u
#define VCS_ZCODE_FOCUS_DOMAIN "zcl.focus.v1"
#define VCS_ZCODE_FOCUS_SITUATION_DOMAIN "zcl.focus_situation.v1"
#define VCS_ZCODE_FOCUS_CLAIM_DOMAIN "zcl.focus_claim.v1"
#define VCS_ZCODE_FOCUS_CLAIM_SET_DOMAIN "zcl.focus_claim_set.v1"
#define VCS_ZCODE_SPECIALIST_REPORT_DOMAIN "zcl.specialist_report.v1"
#define VCS_ZCODE_FOCUS_HANDOFF_DOMAIN "zcl.focus_handoff.v1"

#define VCS_ZCODE_FOCUS_WIRE_BYTES 320u
#define VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES 192u
#define VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES 272u
#define VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES 240u
#define VCS_ZCODE_FOCUS_MAX_CLAIMS 16u
#define VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES 12u
#define VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX \
    (VCS_ZCODE_FOCUS_CLAIM_SET_HEADER_BYTES + \
     VCS_ZCODE_FOCUS_MAX_CLAIMS * 32u)

enum vcs_zcode_focus_error {
    VCS_ZCODE_FOCUS_OK = 0,
    VCS_ZCODE_FOCUS_NULL,
    VCS_ZCODE_FOCUS_VERSION_ERROR,
    VCS_ZCODE_FOCUS_SHAPE,
    VCS_ZCODE_FOCUS_ROOT_ZERO,
    VCS_ZCODE_FOCUS_LIMIT,
    VCS_ZCODE_FOCUS_ORDER,
    VCS_ZCODE_FOCUS_DUPLICATE,
    VCS_ZCODE_FOCUS_BINDING,
    VCS_ZCODE_FOCUS_EXPIRED,
    VCS_ZCODE_FOCUS_ALLOC,
    VCS_ZCODE_FOCUS_INCOMPLETE,
};

enum vcs_zcode_specialist_role {
    VCS_ZCODE_SPECIALIST_RETRIEVAL = 1,
    VCS_ZCODE_SPECIALIST_CODE = 2,
    VCS_ZCODE_SPECIALIST_PROOF = 3,
    VCS_ZCODE_SPECIALIST_PLATFORM = 4,
    VCS_ZCODE_SPECIALIST_INTEGRATION = 5,
};

enum vcs_zcode_focus_flag {
    VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED = 1u << 0,
};

struct vcs_zcode_focus_v1 {
    uint16_t schema_version;
    uint8_t status;
    uint8_t flags;
    uint16_t claim_count;
    uint16_t reserved;
    uint32_t capabilities;
    uint32_t max_changed_files;
    uint64_t max_patch_bytes;
    uint64_t max_context_bytes;
    uint32_t max_cpu_seconds;
    uint32_t reserved_budget;
    uint64_t max_memory_bytes;
    uint64_t max_output_bytes;
    uint8_t task_root[32];
    uint8_t goal_root[32];
    uint8_t source_universe_root[32];
    uint8_t context_root[32];
    uint8_t story_graph_root[32];
    uint8_t claim_set_root[32];
    uint8_t required_evidence_root[32];
    uint8_t authority_limits_root[32];
};

struct vcs_zcode_focus_claim_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t reserved;
    int64_t created_unix;
    int64_t expires_unix;
    uint8_t situation_root[32];
    uint8_t claimant_root[32];
    uint8_t write_scope_root[32];
    uint8_t intent_root[32];
    uint8_t evidence_plan_root[32];
};

struct vcs_zcode_specialist_report_v1 {
    uint16_t schema_version;
    uint8_t role;
    uint8_t status;
    uint16_t flags;
    uint16_t reserved;
    uint64_t context_bytes;
    uint64_t latency_us;
    uint32_t files_opened;
    uint32_t tool_calls;
    uint32_t duplicate_actions;
    uint32_t proof_reuse_count;
    uint8_t focus_root[32];
    uint8_t claim_root[32];
    uint8_t specialist_root[32];
    uint8_t evidence_root[32];
    uint8_t result_root[32];
    uint8_t next_experiment_root[32];
    uint8_t evaluator_root[32];
};

struct vcs_zcode_focus_handoff_v1 {
    uint16_t schema_version;
    uint8_t status;
    uint8_t flags;
    uint32_t reserved;
    uint8_t focus_root[32];
    uint8_t report_root[32];
    uint8_t from_claim_root[32];
    uint8_t to_specialist_root[32];
    uint8_t next_claim_root[32];
    uint8_t required_evidence_root[32];
    uint8_t continuation_root[32];
};

const char *vcs_zcode_focus_error_string(enum vcs_zcode_focus_error error);

enum vcs_zcode_focus_error vcs_zcode_focus_compose(
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const uint8_t context_root[32], const uint8_t story_graph_root[32],
    enum zcl_ontology_status status, uint8_t flags,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    struct vcs_zcode_focus_v1 *out);
enum vcs_zcode_focus_error vcs_zcode_focus_validate(
    const struct vcs_zcode_focus_v1 *focus);
enum vcs_zcode_focus_error vcs_zcode_focus_serialize(
    const struct vcs_zcode_focus_v1 *focus,
    uint8_t out[VCS_ZCODE_FOCUS_WIRE_BYTES]);
enum vcs_zcode_focus_error vcs_zcode_focus_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_focus_v1 *out);
enum vcs_zcode_focus_error vcs_zcode_focus_situation_root(
    const struct vcs_zcode_focus_v1 *focus, uint8_t out[32]);
enum vcs_zcode_focus_error vcs_zcode_focus_root(
    const struct vcs_zcode_focus_v1 *focus, uint8_t out[32]);
enum vcs_zcode_focus_error vcs_zcode_focus_validate_for_context(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    bool require_complete);

enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_serialize(
    const uint8_t (*claim_roots)[32], size_t claim_count,
    uint8_t **wire, size_t *wire_len);
enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_parse(
    const uint8_t *wire, size_t wire_len,
    uint8_t (*claim_roots)[32], size_t capacity, size_t *claim_count);
enum vcs_zcode_focus_error vcs_zcode_focus_claim_set_root(
    const uint8_t (*claim_roots)[32], size_t claim_count, uint8_t out[32]);

enum vcs_zcode_focus_error vcs_zcode_focus_claim_validate_at(
    const struct vcs_zcode_focus_claim_v1 *claim, int64_t now_unix);
enum vcs_zcode_focus_error vcs_zcode_focus_claim_serialize(
    const struct vcs_zcode_focus_claim_v1 *claim,
    uint8_t out[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES]);
enum vcs_zcode_focus_error vcs_zcode_focus_claim_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_focus_claim_v1 *out);
enum vcs_zcode_focus_error vcs_zcode_focus_claim_root(
    const struct vcs_zcode_focus_claim_v1 *claim, uint8_t out[32]);
enum zcl_ontology_status vcs_zcode_focus_claim_disjoint_status(
    const struct vcs_zcode_focus_claim_v1 *a,
    const struct vcs_zcode_write_scope_v1 *scope_a,
    const struct vcs_zcode_focus_claim_v1 *b,
    const struct vcs_zcode_write_scope_v1 *scope_b, int64_t now_unix);
enum zcl_ontology_status vcs_zcode_focus_claim_authority_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const struct vcs_zcode_write_scope_v1 *claim_scope, int64_t now_unix);
enum zcl_ontology_status vcs_zcode_focus_claim_set_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *claims,
    const struct vcs_zcode_write_scope_v1 *scopes,
    size_t claim_count, int64_t now_unix);
enum zcl_ontology_status vcs_zcode_focus_claim_membership_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const uint8_t (*claim_roots)[32], size_t claim_count);
enum zcl_ontology_status vcs_zcode_focus_claim_work_status(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const struct vcs_zcode_write_scope_v1 *claim_scope,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_admission_v1 *admission,
    int64_t now_unix);

enum vcs_zcode_focus_error vcs_zcode_specialist_report_validate(
    const struct vcs_zcode_specialist_report_v1 *report);
enum vcs_zcode_focus_error vcs_zcode_specialist_report_serialize(
    const struct vcs_zcode_specialist_report_v1 *report,
    uint8_t out[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES]);
enum vcs_zcode_focus_error vcs_zcode_specialist_report_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_specialist_report_v1 *out);
enum vcs_zcode_focus_error vcs_zcode_specialist_report_root(
    const struct vcs_zcode_specialist_report_v1 *report, uint8_t out[32]);
enum vcs_zcode_focus_error vcs_zcode_specialist_report_validate_for_work(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *claim,
    const uint8_t (*claim_roots)[32], size_t claim_count,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_receipt_v1 *receipt,
    const struct vcs_zcode_specialist_report_v1 *report);

enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate(
    const struct vcs_zcode_focus_handoff_v1 *handoff);
enum vcs_zcode_focus_error vcs_zcode_focus_handoff_serialize(
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    uint8_t out[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES]);
enum vcs_zcode_focus_error vcs_zcode_focus_handoff_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_focus_handoff_v1 *out);
enum vcs_zcode_focus_error vcs_zcode_focus_handoff_root(
    const struct vcs_zcode_focus_handoff_v1 *handoff, uint8_t out[32]);
enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate_chain(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_focus_claim_v1 *from_claim,
    const struct vcs_zcode_specialist_report_v1 *report,
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    const struct vcs_zcode_focus_claim_v1 *next_claim);

/* Receiver-side resume gate for admitted work. Unlike the structural chain
 * check above, this requires the complete canonical claim snapshot, proves
 * every scope was simultaneously active, disjoint, and within task authority,
 * proves the source claim/admission at its signed receipt completion time,
 * proves the successor claim/admission at now_unix, and binds the source
 * report to that receipt. Expired historical authority never becomes current
 * authority. No object is accepted, executed, or deployed. */
enum vcs_zcode_focus_error vcs_zcode_focus_handoff_validate_for_work(
    const struct vcs_zcode_focus_v1 *focus,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_write_scope_v1 *task_scope,
    const struct vcs_zcode_focus_claim_v1 *claims,
    const struct vcs_zcode_write_scope_v1 *scopes,
    size_t claim_count, size_t from_index, size_t next_index,
    const struct vcs_zcode_work_request_v1 *from_request,
    const struct vcs_zcode_work_admission_v1 *from_admission,
    const struct vcs_zcode_work_request_v1 *next_request,
    const struct vcs_zcode_work_admission_v1 *next_admission,
    const struct vcs_zcode_work_receipt_v1 *from_receipt,
    const struct vcs_zcode_specialist_report_v1 *report,
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    int64_t now_unix);

#endif /* ZCL_VCS_ZCODE_FOCUS_H */
