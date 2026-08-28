/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refuse consensus snapshot export on unqualified Windows paths. */
#if defined(_WIN32)

#include "consensus_state_snapshot_export_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

bool consensus_export_fail(struct consensus_state_export_result *result,
                           enum consensus_state_export_status status,
                           const char *fmt, ...)
{
    char reason[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = status;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    return false;
}

void consensus_export_output_init(struct consensus_export_output_binding *output)
{
    if (!output) return;
    memset(output, 0, sizeof(*output));
    output->dirfd = -1;
    output->temp_fd = -1;
}

void consensus_export_output_close(struct consensus_export_output_binding *output)
{
    if (!output) return;
    output->dirfd = -1;
    output->temp_fd = -1;
    output->vfs_registered = false;
}

static bool export_windows_refused(struct consensus_state_export_result *result)
{
    return consensus_export_fail(
        result, CONSENSUS_EXPORT_REFUSED,
        "consensus-state export is unavailable on Windows until a retained "
        "native directory capability and identity-bound publication are "
        "qualified");
}

bool consensus_export_output_open(
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_export_result *result)
{
    (void)request;
    consensus_export_output_init(output);
    return export_windows_refused(result);
}

bool consensus_export_open_temp(struct consensus_export_output_binding *output,
                                sqlite3 **destination,
                                struct consensus_state_export_result *result)
{
    (void)output;
    if (destination) *destination = NULL;
    return export_windows_refused(result);
}

bool consensus_export_finalize_temp(
    struct consensus_export_output_binding *output,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    (void)output;
    (void)manifest;
    return export_windows_refused(result);
}

bool consensus_export_prove_write(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    (void)source;
    (void)request;
    (void)output;
    (void)manifest;
    return export_windows_refused(result);
}

void consensus_export_run_after_bind_hook(void) { }

#ifdef ZCL_TESTING
void consensus_state_snapshot_export_test_set_after_output_bind_hook(
    void (*hook)(void *), void *ctx)
{
    (void)hook;
    (void)ctx;
}
void consensus_state_snapshot_export_test_set_after_staging_create_hook(
    void (*hook)(void *, int), void *ctx)
{
    (void)hook;
    (void)ctx;
}
#endif

bool consensus_export_digest_nonzero(const uint8_t digest[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= digest[i];
    return any != 0;
}

void consensus_export_fill_success(
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    if (!manifest || !result) return;
    result->status = CONSENSUS_EXPORT_EXPORTED;
    result->history_complete = true;
    result->source_clean = manifest->source_clean;
    result->validation_profile = manifest->validation_profile;
    result->height = manifest->height;
    result->utxo_count = manifest->utxo_count;
    result->anchor_count = manifest->anchor_count;
    result->nullifier_count = manifest->nullifier_count;
    memcpy(result->artifact_digest, manifest->artifact_digest, 32);
}

bool consensus_state_snapshot_export(
    sqlite3 *progress_db,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    (void)progress_db;
    (void)request;
    if (result) memset(result, 0, sizeof(*result));
    return export_windows_refused(result);
}

#else
typedef int consensus_state_snapshot_export_windows_not_built;
#endif
