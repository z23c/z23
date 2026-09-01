/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure workspace binding calculation over caller-owned buffers. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_workspace_view_service.h"

#include "base/bytes.h"
#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static bool derive_binding(
    const struct zcode_workspace_binding_input_v1 *input,
    struct zcode_workspace_binding_result_v1 *out)
{
    if (!input || !out || input->sequence == 0 ||
        (input->sequence == 1 && zcl_bytes_any_set(input->predecessor_release_root, 32)) ||
        (input->sequence > 1 && !zcl_bytes_any_set(input->predecessor_release_root, 32)))
        return false;
    memset(out, 0, sizeof(*out));
    out->entry.sequence = input->sequence;
    memcpy(out->entry.module_release_root, input->module_release_root, 32);
    memcpy(out->entry.predecessor_release_root,
           input->predecessor_release_root, 32);
    memcpy(out->entry.semantic_fingerprint_root,
           input->passport.semantic_fingerprint_root, 32);
    memcpy(out->entry.source_assignment_root,
           input->passport.source_assignment_root, 32);
    if (vcs_zcode_module_passport_v1_root(
            &input->passport, out->entry.module_passport_root) !=
            VCS_ZCODE_COMMONS_OK ||
        vcs_zcode_workspace_entry_v1_root(
            &out->entry, out->binding_root) != VCS_ZCODE_COMMONS_OK)
        return false;
    out->valid = true;
    return true;
}

static bool render_binding(bool verified,
                           struct zcode_workspace_view_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->kind, sizeof(out->kind), "%s", "workspace_entry.v1");
    (void)snprintf(out->capability, sizeof(out->capability), "%s",
                   "verified Passport roots are bound to one release lineage entry");
    (void)snprintf(
        out->next_action, sizeof(out->next_action), "%s",
        verified ? "include this exact entry in a signed workspace manifest"
                 : "zcode workspace verify --input='<plan input plus binding_root>'");
    out->valid = true;
    return true;
}

static bool render_status(struct zcode_workspace_view_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->kind, sizeof(out->kind), "%s", "workspace_entry.v1");
    (void)snprintf(out->capability, sizeof(out->capability), "%s",
                   "Passport-bound workspace entry plan, show and verify are ready");
    (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                   "zcode workspace plan");
    out->valid = true;
    return true;
}

static bool render_manifest(enum zcode_workspace_manifest_view_mode_v1 mode,
                            struct zcode_workspace_view_result_v1 *out)
{
    if (!out || (mode != ZCODE_WORKSPACE_MANIFEST_VIEW_PLAN &&
                 mode != ZCODE_WORKSPACE_MANIFEST_VIEW_COMMIT))
        return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->kind, sizeof(out->kind), "%s",
                   "workspace_manifest.v1");
    if (mode == ZCODE_WORKSPACE_MANIFEST_VIEW_PLAN) {
        (void)snprintf(out->capability, sizeof(out->capability), "%s",
                       "exact manifest commitment is ready for offline signature");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "offline-sign payload, then zcode workspace manifest commit");
    } else {
        (void)snprintf(out->capability, sizeof(out->capability), "%s",
                       "external signature verifies the exact workspace manifest");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "retain manifest root; human publication stays separate");
    }
    out->valid = true;
    return true;
}

static const struct zcode_workspace_view_service_v1 k_builtin = {
    .derive_binding = derive_binding,
    .render_binding = render_binding,
    .render_status = render_status,
    .render_manifest = render_manifest,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_WORKSPACE_VIEW_SERVICE_ID, k_builtin,
    ZCODE_WORKSPACE_VIEW_ABI_FINGERPRINT,
    ZCODE_WORKSPACE_VIEW_SCHEMA_FINGERPRINT,
    ZCODE_WORKSPACE_VIEW_WIRE_FINGERPRINT,
    ZCODE_WORKSPACE_VIEW_KAT_FINGERPRINT)

const struct zcode_workspace_view_service_v1 *
zcode_workspace_view_service_builtin(void)
{
    return &k_builtin;
}
