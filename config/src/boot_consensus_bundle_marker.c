/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_consensus_bundle_marker.c — the durable "a sovereign consensus bundle is
 * installed in this datadir" marker. Written by boot_install_consensus_bundle
 * after a successful atomic activation; read by boot_snapshot_failure_memory to
 * refuse re-loading a borrowed starter-pack seed over the installed state.
 *
 * Contract in config/boot_consensus_bundle_marker.h. */

#include "config/boot_consensus_bundle_marker.h"

#include "platform/file_metadata.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

static bool marker_path(char *out, size_t cap, const char *datadir)
{
    if (!out || cap == 0 || !datadir || !datadir[0])
        return false;
    int n = snprintf(out, cap,
#if defined(_WIN32)
                     "%s\\%s",
#else
                     "%s/%s",
#endif
                     datadir,
                     BOOT_CONSENSUS_BUNDLE_MARKER_NAME);
    return n > 0 && (size_t)n < cap;
}

static _Atomic uint64_t g_marker_staging_sequence;

bool boot_consensus_bundle_marker_write(const char *datadir, int32_t height,
                                        const uint8_t artifact_digest[32])
{
    if (!datadir || !datadir[0] || !artifact_digest)
        LOG_FAIL("install_consensus_bundle",
                 "marker write: missing datadir or artifact digest");

    char final_path[1200];
    char resolved_path[1200];
    char parent[1200];
    char tmp_path[1280];
    if (!marker_path(final_path, sizeof(final_path), datadir))
        LOG_FAIL("install_consensus_bundle",
                 "marker write: datadir path too long (%s)", datadir);
    if (!platform_private_path_resolve(final_path, resolved_path,
                                       sizeof(resolved_path), parent,
                                       sizeof(parent)))
        LOG_FAIL("install_consensus_bundle",
                 "marker write: unsafe/non-canonical datadir path (%s)",
                 datadir);

    char digest_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(digest_hex + i * 2, 3, "%02x", artifact_digest[i]);

    char body[256];
    int body_len = snprintf(body, sizeof(body),
                            "zclassic23-consensus-bundle-installed v1\n"
                            "height=%d\n"
                            "artifact_digest=%s\n"
                            "installed_unix=%lld\n",
                            height, digest_hex,
                            (long long)time(NULL)); // platform-ok: human-facing install timestamp, not consensus timing
    if (body_len <= 0 || (size_t)body_len >= sizeof(body))
        LOG_FAIL("install_consensus_bundle",
                 "marker write: body encoding failed");

    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned attempt = 0; attempt < 16 && !created; ++attempt) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &g_marker_staging_sequence, 1, memory_order_relaxed);
        int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%lld.%llu",
                          resolved_path,
                          (long long)platform_time_realtime_us(),
                          (unsigned long long)sequence);
        if (tn <= 0 || (size_t)tn >= sizeof(tmp_path)) break;
        created = platform_private_file_create(tmp_path, &staging);
    }
    if (!created)
        LOG_FAIL("install_consensus_bundle",
                 "marker write: unique private staging failed: %s",
                 strerror(errno));

    if (!platform_private_file_write_at(&staging, body, (size_t)body_len, 0) ||
        !platform_private_file_flush(&staging) ||
        !platform_private_file_replace(&staging, tmp_path, resolved_path)) {
        (void)platform_private_file_retire(&staging, tmp_path);
        platform_private_file_close(&staging);
        LOG_FAIL("install_consensus_bundle",
                 "marker write: durable replace failed: %s", strerror(errno));
    }
    if (!platform_private_parent_flush(parent))
        LOG_FAIL("install_consensus_bundle",
                 "marker write: parent durability failed: %s", strerror(errno));
    LOG_INFO("install_consensus_bundle",
             "consensus-bundle-installed marker written: %s (height=%d "
             "artifact_digest=%s)", resolved_path, height, digest_hex);
    return true;
}

bool boot_consensus_bundle_marker_exists(const char *datadir)
{
    char path[1200];
    if (!marker_path(path, sizeof(path), datadir))
        return false;
    struct platform_file_metadata metadata;
    return platform_file_metadata_read(path, &metadata) ==
           PLATFORM_FILE_METADATA_OK;
}
