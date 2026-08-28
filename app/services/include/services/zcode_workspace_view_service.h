/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure calculation ABI for Passport-bound workspace entry views. */

#ifndef ZCL_SERVICES_ZCODE_WORKSPACE_VIEW_SERVICE_H
#define ZCL_SERVICES_ZCODE_WORKSPACE_VIEW_SERVICE_H

#include "vcs/zcode_commons.h"

#include <stdbool.h>
#include <stdint.h>

#define ZCODE_WORKSPACE_VIEW_SERVICE_ID "zcode.workspace.view.v1"
#define ZCODE_WORKSPACE_VIEW_ABI_FINGERPRINT \
    "zcode.workspace.view.abi.v2:manifest-render"
#define ZCODE_WORKSPACE_VIEW_SCHEMA_FINGERPRINT \
    "zcl.zcode_workspace_status.v1+plan.v1+verify.v1+manifest-plan.v1+manifest-commit.v1"
#define ZCODE_WORKSPACE_VIEW_WIRE_FINGERPRINT \
    "module-passport+workspace-entry-binding+manifest-unsigned.v1"
#define ZCODE_WORKSPACE_VIEW_KAT_FINGERPRINT \
    "a027432310c2e02e8460b2757159fc0d40a24c176d6935fffd1de2d2b765e84b"

enum zcode_workspace_manifest_view_mode_v1 {
    ZCODE_WORKSPACE_MANIFEST_VIEW_PLAN = 1,
    ZCODE_WORKSPACE_MANIFEST_VIEW_COMMIT = 2,
};

struct zcode_workspace_binding_input_v1 {
    struct vcs_zcode_module_passport_v1 passport;
    uint8_t module_release_root[32];
    uint8_t predecessor_release_root[32];
    uint64_t sequence;
};

struct zcode_workspace_binding_result_v1 {
    bool valid;
    struct vcs_zcode_workspace_entry_v1 entry;
    uint8_t binding_root[32];
};

struct zcode_workspace_view_result_v1 {
    bool valid;
    char kind[32];
    char capability[128];
    char next_action[128];
};

struct zcode_workspace_view_service_v1 {
    bool (*derive_binding)(
        const struct zcode_workspace_binding_input_v1 *input,
        struct zcode_workspace_binding_result_v1 *out);
    bool (*render_binding)(bool verified,
                           struct zcode_workspace_view_result_v1 *out);
    bool (*render_status)(struct zcode_workspace_view_result_v1 *out);
    bool (*render_manifest)(enum zcode_workspace_manifest_view_mode_v1 mode,
                            struct zcode_workspace_view_result_v1 *out);
};

const struct zcode_workspace_view_service_v1 *
zcode_workspace_view_service_builtin(void);

struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_zcode_workspace_view_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_WORKSPACE_VIEW_SERVICE_H */
