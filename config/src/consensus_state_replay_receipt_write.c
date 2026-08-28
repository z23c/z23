/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Publish replay receipts with a handle-bound durable replacement. */
#include "config/consensus_state_replay_receipt_write.h"

#include "config/consensus_state_replay_receipt.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
char *realpath(const char *restrict path, char *restrict resolved_path);
#endif

#define RR_WRITE_SUBSYS "consensus_replay_receipt"

static _Atomic uint64_t g_staging_nonce;

static bool receipt_path(const char *datadir, char *out, size_t cap)
{
    char resolved_datadir[PATH_MAX];
#ifdef _WIN32
    if (!_fullpath(resolved_datadir, datadir, sizeof(resolved_datadir)))
        return false;
#else
    if (!realpath(datadir, resolved_datadir))
        return false;
#endif
    int n = snprintf(out, cap, "%s/%s", resolved_datadir,
                     CONSENSUS_STATE_REPLAY_RECEIPT_NAME);
    return n > 0 && (size_t)n < cap;
}

static bool persist(struct platform_private_file *staging,
                    const uint8_t *payload, size_t payload_size,
                    const char *temporary, const char *resolved,
                    const char *parent)
{
    bool ok = platform_private_file_write_at(staging, payload, payload_size, 0);
    const char *stage = "write";
    if (ok) {
        stage = "file flush";
        ok = platform_private_file_flush(staging);
    }
    if (ok) {
        stage = "atomic replace";
        ok = platform_private_file_replace(staging, temporary, resolved);
    }
    if (ok) {
        stage = "parent flush";
        ok = platform_private_parent_flush(parent);
    }
    if (!ok)
        LOG_WARN(RR_WRITE_SUBSYS, "receipt persistence failed at %s path=%s",
                 stage, resolved);
    return ok;
}

bool consensus_state_replay_receipt_write(const char *datadir,
                                          const uint8_t *payload,
                                          size_t payload_size,
                                          char *final_out,
                                          size_t final_cap)
{
    char final_path[PATH_MAX], temporary[PATH_MAX];
    if (!datadir || !payload || !payload_size ||
        !platform_private_directory_ensure(datadir) ||
        !receipt_path(datadir, final_path, sizeof(final_path)) ||
        (final_out && strlen(final_path) >= final_cap))
        return false;
    char resolved[PATH_MAX], parent[PATH_MAX];
    if (!platform_private_path_resolve(final_path, resolved, sizeof(resolved),
                                       parent, sizeof(parent)))
        return false;
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned attempt = 0; attempt < 64 && !created; ++attempt) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_staging_nonce, 1, memory_order_relaxed);
        int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%016llx",
                         resolved, (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= sizeof(temporary))
            return false;
        created = platform_private_file_create(temporary, &staging);
    }
    if (!created)
        return false;
    bool ok = persist(&staging, payload, payload_size, temporary, resolved,
                      parent);
    platform_private_file_close(&staging);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(temporary);
        return false;
    }
    if (final_out)
        memcpy(final_out, final_path, strlen(final_path) + 1u);
    return true;
}
