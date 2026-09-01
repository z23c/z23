/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure package-index presentation over caller-owned input and output. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/zcode_package_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

#define COPY_FIELD(dst_, src_) \
    (void)snprintf((dst_), sizeof(dst_), "%s", (src_))

static bool render_entry(const struct vcs_package_index_entry *entry,
                         struct zcode_package_view_entry_v1 *out)
{
    if (!entry || !out) return false;
    memset(out, 0, sizeof(*out));
    COPY_FIELD(out->release_id, entry->release_id_hex);
    COPY_FIELD(out->package_root, entry->package_root_hex);
    COPY_FIELD(out->name, entry->name);
    COPY_FIELD(out->semver, entry->semver);
    COPY_FIELD(out->license, entry->license);
    COPY_FIELD(out->publisher, entry->publisher_hex);
    COPY_FIELD(out->chain_id, entry->chain_id);
    COPY_FIELD(out->reward_address, entry->reward_address);
    COPY_FIELD(out->parent_root, entry->parent_root_hex);
    COPY_FIELD(out->znam, entry->znam);
    out->publisher_sequence = entry->publisher_sequence;
    out->has_parent = entry->has_parent;
    out->has_znam = entry->has_znam;
    out->manifest_present = entry->manifest_present;
    out->file_count = entry->file_count;
    out->total_bytes = entry->total_bytes;
    out->chunk_total = entry->chunk_total;
    out->license_present = entry->license_present;
    out->executable_count = entry->executable_count;
    out->valid = out->release_id[0] != '\0' && out->package_root[0] != '\0' &&
                 out->name[0] != '\0';
    return true;
}

static bool render_guide(struct zcode_package_guide_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->cas_authority_static = true;
    out->index_reads_static = true;
    out->publication_static = true;
    out->execution_static = true;
    (void)snprintf(out->live_surface, sizeof(out->live_surface), "%s",
                   "bounded package search, release metadata, publication readiness and workflow text");
    (void)snprintf(out->static_boundary, sizeof(out->static_boundary), "%s",
                   "CAS/index reads, signatures, publication, fetch, install, build, execution, storage and network effects");
    (void)snprintf(out->next_command, sizeof(out->next_command), "%s",
                   "z23 zcode network status");
    return true;
}

static bool render_publish_plan(
    const struct zcode_package_publish_plan_input_v1 *input,
    struct zcode_package_publish_plan_result_v1 *out)
{
    if (!input || !out || !input->validation_complete) return false;
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->stage, sizeof(out->stage), "%s", "plan");
    out->valid = input->failure_count == 0;
    out->ready_to_commit = out->valid && input->chunks_checked;
    if (!out->valid) {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       "blocked");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "fix the first reported failure, then rerun zcode package publish plan");
    } else if (!input->chunks_checked) {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       "needs_chunk_source");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "rerun zcode package publish plan with dir");
    } else {
        (void)snprintf(out->readiness, sizeof(out->readiness), "%s",
                       "ready_to_commit");
        (void)snprintf(out->next_action, sizeof(out->next_action), "%s",
                       "zcode package publish commit");
    }
    return true;
}

static const struct zcode_package_view_service_v1 k_builtin = {
    .render_entry = render_entry,
    .render_guide = render_guide,
    .render_publish_plan = render_publish_plan,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    ZCODE_PACKAGE_VIEW_SERVICE_ID, k_builtin,
    ZCODE_PACKAGE_VIEW_ABI_FINGERPRINT,
    ZCODE_PACKAGE_VIEW_SCHEMA_FINGERPRINT,
    ZCODE_PACKAGE_VIEW_WIRE_FINGERPRINT,
    ZCODE_PACKAGE_VIEW_KAT_FINGERPRINT)

const struct zcode_package_view_service_v1 *
zcode_package_view_service_builtin(void)
{
    return &k_builtin;
}
