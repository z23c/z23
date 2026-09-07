/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal wiring shared only by the two ZCODE dev-loop publish translation
 * units: native_zcode_dev_publish_stage.c (accepted-lane reload/verify,
 * staging-directory transactions, and publisher-lineage projection) and
 * native_zcode_dev_publish.c (the zcode.publish.plan and zcode.publish.commit
 * orchestration on top of them). Not a public surface and not included by
 * any of the other zcode-dev sibling files. */
#ifndef ZCL_TOOLS_NATIVE_ZCODE_DEV_PUBLISH_PRIV_H
#define ZCL_TOOLS_NATIVE_ZCODE_DEV_PUBLISH_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "command/native_zcode_dev_priv.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/package_mapping.h"
#include "vcs/source_package_transport.h"
#include "services/zcode_lane_service.h"

struct json_value;
struct zcl_command_reply;
struct zcl_command_request;
struct vcs_package_release;

#define ZPUB_PATH_MAX 4400

struct zpub_accepted_bundle {
    char workspace[ZDEV_PATH_MAX];
    char datadir[ZPUB_PATH_MAX];
    char acceptance_datadir[ZPUB_PATH_MAX];
    uint8_t source_root[32];
    struct zcode_lane_status lane;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t receipt_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    struct vcs_source_package_transport transport;
    bool have_mapping;
    uint8_t mapping_root[32];
    struct vcs_package_mapping_set mapping;
};

/* ── native_zcode_dev_publish_stage.c: reply/reload/staging/lineage ─────── */
void zpub_fail(struct zcl_command_reply *reply, const char *code,
              const char *detail);
void zpub_bundle_free(struct zpub_accepted_bundle *bundle);
bool zpub_push_hex(struct json_value *out, const char *key,
                   const uint8_t *bytes, size_t len);
bool zpub_decode_hex(const char *hex, size_t max_bytes,
                     uint8_t **out, size_t *out_len);
bool zpub_copy_field(char *out, size_t cap, const char *value);
bool zpub_normalize(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle);
bool zpub_find_lane_readonly(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle);
bool zpub_find_lane_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle);
bool zpub_prepare_accepted_objects(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle);
bool zpub_release_body(
    const struct vcs_package_release *release, uint8_t **out, size_t *out_len,
    uint8_t digest[32]);
bool zpub_lineage(const char *zcode_dir, const char *publisher_hex,
                  bool *has_parent, uint8_t parent_root[32],
                  uint64_t *sequence_out);
bool zpub_lineage_claims_match(
    const struct json_value *input, bool has_parent,
    const uint8_t parent_root[32], uint64_t sequence);
bool zpub_release_lineage_valid(
    const char *zcode_dir, const struct vcs_package_release *release,
    const uint8_t release_id[32]);
void zpub_common_output(
    struct json_value *out, const struct zpub_accepted_bundle *bundle);
bool zpub_stage_create(const char *datadir, char out[ZPUB_PATH_MAX]);
bool zpub_stage_transport(
    const char *dir, const struct vcs_source_package_transport *transport);
void zpub_stage_cleanup(
    const char *dir, const struct vcs_source_package_transport *transport);

#endif /* ZCL_TOOLS_NATIVE_ZCODE_DEV_PUBLISH_PRIV_H */
