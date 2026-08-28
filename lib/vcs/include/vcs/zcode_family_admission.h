/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed Family admissions, immutable projections and access seam. */
#ifndef ZCL_VCS_ZCODE_FAMILY_ADMISSION_H
#define ZCL_VCS_ZCODE_FAMILY_ADMISSION_H

#include "vcs/zcode_commons.h"
#include "vcs/zcode_sovereignty_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES 380u
#define VCS_ZCODE_FAMILY_ADMISSION_MAX_SOURCES 4096u
#define VCS_ZCODE_FAMILY_INTAKE_MAX_BYTES \
    (UINT64_C(64) * 1024u * 1024u)
#define VCS_ZCODE_FAMILY_CONTROL_MAX_BYTES 4096u
#define VCS_ZCODE_FAMILY_PROJECTION_V1_DOMAIN \
    "zcl.zcode.family_admission_projection.v1"

enum vcs_zcode_family_admission_error {
    VCS_ZCODE_FAMILY_ADMISSION_OK = 0,
    VCS_ZCODE_FAMILY_ADMISSION_NULL,
    VCS_ZCODE_FAMILY_ADMISSION_SIZE,
    VCS_ZCODE_FAMILY_ADMISSION_MAGIC,
    VCS_ZCODE_FAMILY_ADMISSION_VERSION,
    VCS_ZCODE_FAMILY_ADMISSION_FLAGS,
    VCS_ZCODE_FAMILY_ADMISSION_ENUM,
    VCS_ZCODE_FAMILY_ADMISSION_ROOT,
    VCS_ZCODE_FAMILY_ADMISSION_TIME,
    VCS_ZCODE_FAMILY_ADMISSION_SIGNATURE,
    VCS_ZCODE_FAMILY_ADMISSION_ORDER,
    VCS_ZCODE_FAMILY_ADMISSION_CHAIN,
    VCS_ZCODE_FAMILY_ADMISSION_LIMIT,
    VCS_ZCODE_FAMILY_ADMISSION_NOMEM,
    VCS_ZCODE_FAMILY_ADMISSION_OVERFLOW,
};

struct vcs_zcode_commons_admission_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t state;
    uint16_t tier;
    uint8_t coverage_complete;
    uint8_t closure_complete;
    uint16_t reserved;
    uint64_t sequence;
    uint64_t decided_height;
    int64_t decided_mtp;
    uint64_t expires_height;
    int64_t expires_mtp;
    uint8_t content_root[32];
    uint8_t dependency_closure_root[32];
    uint8_t family_policy_root[32];
    uint8_t moderation_set_root[32];
    uint8_t panel_root[32];
    uint8_t evidence_root[32];
    uint8_t predecessor_admission_root[32];
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

struct vcs_zcode_family_admission_source_v1 {
    uint8_t object_root[32];
    struct vcs_zcode_commons_admission_v1 admission;
};

struct vcs_zcode_family_projection_config_v1 {
    uint8_t family_policy_root[32];
    uint8_t moderation_set_root[32];
    uint8_t chain_tip_root[32];
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    enum vcs_zcode_moderation_tier_v1 required_tier;
    bool chain_current;
};

struct vcs_zcode_family_admission_projection_entry_v1 {
    uint8_t content_root[32];
    uint8_t dependency_closure_root[32];
    uint8_t admission_root[32];
    uint64_t sequence;
    enum vcs_zcode_commons_admission_state_v1 state;
    enum vcs_zcode_moderation_tier_v1 tier;
    bool coverage_complete;
    bool closure_complete;
    bool chain_complete;
    bool current;
    bool family_public;
};

struct vcs_zcode_family_admission_projection;

const char *vcs_zcode_family_admission_error_string(
    enum vcs_zcode_family_admission_error error);
enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_sign(
    struct vcs_zcode_commons_admission_v1 *admission,
    const uint8_t signer_seed[32]);
enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_validate(
    const struct vcs_zcode_commons_admission_v1 *admission);
enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_encode(
    const struct vcs_zcode_commons_admission_v1 *admission,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_decode(
    struct vcs_zcode_commons_admission_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_root(
    const struct vcs_zcode_commons_admission_v1 *admission,
    uint8_t out[32]);

enum vcs_zcode_family_admission_error
vcs_zcode_family_admission_projection_build_v1(
    const struct vcs_zcode_family_projection_config_v1 *config,
    const struct vcs_zcode_family_admission_source_v1 *sources,
    size_t source_count,
    struct vcs_zcode_family_admission_projection **out);
void vcs_zcode_family_admission_projection_free_v1(
    struct vcs_zcode_family_admission_projection *projection);
size_t vcs_zcode_family_admission_projection_count_v1(
    const struct vcs_zcode_family_admission_projection *projection);
const struct vcs_zcode_family_admission_projection_entry_v1 *
vcs_zcode_family_admission_projection_at_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    size_t index);
const struct vcs_zcode_family_admission_projection_entry_v1 *
vcs_zcode_family_admission_projection_find_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    const uint8_t content_root[32], const uint8_t closure_root[32]);
void vcs_zcode_family_admission_projection_root_v1(
    const struct vcs_zcode_family_admission_projection *projection,
    uint8_t out[32]);

enum vcs_zcode_family_access_intent_v1 {
    VCS_ZCODE_FAMILY_INTENT_FAMILY_PUBLIC = 1,
    VCS_ZCODE_FAMILY_INTENT_MODERATION_INTAKE = 2,
    VCS_ZCODE_FAMILY_INTENT_EXACT_ROOT_DIAGNOSTIC = 3,
    VCS_ZCODE_FAMILY_INTENT_PROTOCOL_CONTROL = 4,
};

enum vcs_zcode_family_access_action_v1 {
    VCS_ZCODE_FAMILY_ACTION_DISCOVER = 0,
    VCS_ZCODE_FAMILY_ACTION_INDEX,
    VCS_ZCODE_FAMILY_ACTION_SEARCH,
    VCS_ZCODE_FAMILY_ACTION_SHOW,
    VCS_ZCODE_FAMILY_ACTION_REST,
    VCS_ZCODE_FAMILY_ACTION_PREVIEW,
    VCS_ZCODE_FAMILY_ACTION_DHT_ADVERTISE,
    VCS_ZCODE_FAMILY_ACTION_DHT_FORWARD,
    VCS_ZCODE_FAMILY_ACTION_PROVIDER_RENEW,
    VCS_ZCODE_FAMILY_ACTION_FETCH,
    VCS_ZCODE_FAMILY_ACTION_STORE,
    VCS_ZCODE_FAMILY_ACTION_REPLICATE,
    VCS_ZCODE_FAMILY_ACTION_SERVE,
    VCS_ZCODE_FAMILY_ACTION_DOWNLOAD,
    VCS_ZCODE_FAMILY_ACTION_STORAGE_ACK,
    VCS_ZCODE_FAMILY_ACTION_INSTALL,
    VCS_ZCODE_FAMILY_ACTION_BUILD,
    VCS_ZCODE_FAMILY_ACTION_RUN,
    VCS_ZCODE_FAMILY_ACTION_EXECUTE,
    VCS_ZCODE_FAMILY_ACTION_PROTOCOL_FRAME,
    VCS_ZCODE_FAMILY_ACTION_COUNT,
};

enum vcs_zcode_family_control_kind_v1 {
    VCS_ZCODE_FAMILY_CONTROL_DHT_QUERY = 1,
    VCS_ZCODE_FAMILY_CONTROL_DHT_RESPONSE = 2,
    VCS_ZCODE_FAMILY_CONTROL_PROVIDER_HEARTBEAT = 3,
    VCS_ZCODE_FAMILY_CONTROL_MODERATION_DISCOVERY = 4,
};

struct vcs_zcode_family_access_request_v1 {
    enum vcs_zcode_family_access_action_v1 action;
    enum vcs_zcode_family_access_intent_v1 intent;
    struct vcs_zcode_sovereignty_subject subject;
    uint8_t content_root[32];
    uint8_t dependency_closure_root[32];
    uint8_t provider_root[32];
    uint64_t expected_bytes;
    uint64_t byte_budget;
    uint64_t expires_height;
    int64_t expires_mtp;
    uint64_t current_height;
    int64_t current_mtp;
    uint32_t control_bytes;
    uint16_t control_kind;
    bool operator_authorized;
    bool redacted;
};

enum vcs_zcode_family_access_reason_v1 {
    VCS_ZCODE_FAMILY_ACCESS_INVALID = 0,
    VCS_ZCODE_FAMILY_ACCESS_LOCAL_BLOCK,
    VCS_ZCODE_FAMILY_ACCESS_INACTIVE,
    VCS_ZCODE_FAMILY_ACCESS_NO_PROJECTION,
    VCS_ZCODE_FAMILY_ACCESS_NOT_ADMITTED,
    VCS_ZCODE_FAMILY_ACCESS_FAMILY_PUBLIC,
    VCS_ZCODE_FAMILY_ACCESS_MODERATION_INTAKE,
    VCS_ZCODE_FAMILY_ACCESS_EXACT_ROOT_DIAGNOSTIC,
    VCS_ZCODE_FAMILY_ACCESS_PROTOCOL_CONTROL,
};

struct vcs_zcode_family_access_decision_v1 {
    bool allow;
    bool enforcement_active;
    bool generation_changed;
    enum vcs_zcode_family_access_reason_v1 reason;
    uint64_t admission_generation;
    uint8_t projection_root[32];
    uint8_t admission_root[32];
};

struct vcs_zcode_family_access_binding_v1 {
    uint64_t admission_generation;
    enum vcs_zcode_family_access_action_v1 action;
    enum vcs_zcode_family_access_intent_v1 intent;
    uint8_t projection_root[32];
    uint8_t content_root[32];
    uint8_t dependency_closure_root[32];
};

struct vcs_zcode_family_access_service;

struct vcs_zcode_family_access_service *vcs_zcode_family_access_service_create(
    void);
void vcs_zcode_family_access_service_free(
    struct vcs_zcode_family_access_service *service);
enum vcs_zcode_family_admission_error
vcs_zcode_family_access_service_publish(
    struct vcs_zcode_family_access_service *service,
    const struct vcs_zcode_family_admission_projection *projection);
enum vcs_zcode_family_admission_error
vcs_zcode_family_access_service_set_active(
    struct vcs_zcode_family_access_service *service, bool active);
uint64_t vcs_zcode_family_access_service_generation(
    const struct vcs_zcode_family_access_service *service);
bool vcs_zcode_family_access_service_active(
    const struct vcs_zcode_family_access_service *service);
struct vcs_zcode_family_access_decision_v1 vcs_zcode_family_access_decide_v1(
    struct vcs_zcode_family_access_service *service,
    vcs_zcode_sovereignty_decide_fn local_decide, void *local_ctx,
    const struct vcs_zcode_family_access_request_v1 *request);
bool vcs_zcode_family_access_bind_v1(
    const struct vcs_zcode_family_access_request_v1 *request,
    const struct vcs_zcode_family_access_decision_v1 *decision,
    struct vcs_zcode_family_access_binding_v1 *out);
struct vcs_zcode_family_access_decision_v1 vcs_zcode_family_access_recheck_v1(
    struct vcs_zcode_family_access_service *service,
    vcs_zcode_sovereignty_decide_fn local_decide, void *local_ctx,
    const struct vcs_zcode_family_access_request_v1 *request,
    const struct vcs_zcode_family_access_binding_v1 *binding);

#endif /* ZCL_VCS_ZCODE_FAMILY_ADMISSION_H */
