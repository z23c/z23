/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Backward-compatible package-swarm download-record persistence. */

#include "package_swarm_record.h"

#include "package_store_priv.h"
#include "vcs/package_manifest.h"
#include "vcs/package_swarm_node.h"
#include "vcs_priv.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SWARM_RECORD_LOG "vcs.swarm.record"
#define SWARM_RECORD_VERSION 3u
#define SWARM_RECORD_VERSION_LEGACY 2u
#define SWARM_RECORD_WIRE_BYTES_LEGACY 51u

static const uint8_t record_magic[8] = {'Z', 'S', 'W', 'D', 'L', 'R',
                                        0x0d, 0x0a};

bool vcs_swarm_manifest_within_bound(
    const struct vcs_package_manifest *manifest, uint64_t maximum_bytes)
{
    if (!manifest || maximum_bytes == 0)
        return manifest != NULL;
    uint64_t total = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        uint64_t size = manifest->files[i].size;
        if (size > maximum_bytes - total)
            return false;
        total += size;
    }
    return true;
}

static void record_path(const char *zcode_dir, const char *root_hex,
                        char *out, size_t out_size)
{
    snprintf(out, out_size, "%s/downloads/%s", zcode_dir, root_hex);
}

bool vcs_swarm_record_persist(const char *zcode_dir, const char *root_hex,
                              const struct vcs_swarm_record *record)
{
    if (!zcode_dir || !root_hex || !record)
        LOG_FAIL(SWARM_RECORD_LOG, "download record input invalid");
    uint8_t wire[VCS_SWARM_RECORD_WIRE_BYTES];
    memcpy(wire, record_magic, sizeof(record_magic));
    vcs_wr_u16le(wire + 8, SWARM_RECORD_VERSION);
    memcpy(wire + 10, record->root, 32);
    vcs_wr_u64le(wire + 42, (uint64_t)record->created_day);
    wire[50] = record->provider_restricted ? 1u : 0u;
    vcs_wr_u64le(wire + 51, record->maximum_package_bytes);
    char dir[STORE_PATH_MAX], path[STORE_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/downloads", zcode_dir);
    record_path(zcode_dir, root_hex, path, sizeof(path));
    if (!store_mkdir_p(dir) || !store_atomic_write(path, wire, sizeof(wire)))
        LOG_FAIL(SWARM_RECORD_LOG, "download record persist failed for %.16s",
                 root_hex);
    return true;
}

bool vcs_swarm_record_load(const char *path, struct vcs_swarm_record *out)
{
    uint8_t wire[VCS_SWARM_RECORD_WIRE_BYTES];
    FILE *f = path ? fopen(path, "rb") : NULL;
    struct stat st;
    bool sized = f && fstat(fileno(f), &st) == 0 && st.st_size >= 0 &&
                 (size_t)st.st_size <= sizeof(wire);
    size_t wire_len = sized ? (size_t)st.st_size : 0;
    bool read_ok = sized && fread(wire, 1, wire_len, f) == wire_len &&
                   fgetc(f) == EOF;
    if (f)
        fclose(f);
    uint16_t version = read_ok && wire_len >= 10u
                           ? vcs_rd_u16le(wire + 8) : 0;
    bool supported =
        (version == SWARM_RECORD_VERSION &&
         wire_len == VCS_SWARM_RECORD_WIRE_BYTES) ||
        (version == SWARM_RECORD_VERSION_LEGACY &&
         wire_len == SWARM_RECORD_WIRE_BYTES_LEGACY);
    if (!out || !read_ok || !supported ||
        memcmp(wire, record_magic, sizeof(record_magic)) != 0)
        return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->root, wire + 10, 32);
    out->created_day = (int64_t)vcs_rd_u64le(wire + 42);
    out->provider_restricted = wire[50] == 1u;
    out->maximum_package_bytes = version == SWARM_RECORD_VERSION
                                     ? vcs_rd_u64le(wire + 51) : 0;
    return true;
}

void vcs_swarm_record_delete(const char *zcode_dir, const char *root_hex)
{
    if (!zcode_dir || !root_hex)
        return;
    char path[STORE_PATH_MAX];
    record_path(zcode_dir, root_hex, path, sizeof(path));
    if (unlink(path) != 0)
        LOG_WARN(SWARM_RECORD_LOG, "download record delete failed for %.16s",
                 root_hex);
}
