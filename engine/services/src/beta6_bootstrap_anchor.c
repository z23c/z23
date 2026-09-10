/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: beta6 compiled fast-sync anchors and the serve-directory sidecars.
 *
 * The anchor table is a verbatim port of zclassicd v2.1.2-beta6's
 * chainparams.cpp:205-219. It is NOT a z23 consensus constant: it is the set
 * of commitments a beta6 CLIENT compiled in, so a manifest this node serves is
 * only accepted by that client when it reproduces one of these exactly. A
 * served copy names which anchor it belongs to in a sibling ".anchor" file;
 * anything not in this table is refused by name rather than served blind.
 */
#include "services/beta6_bootstrap.h"

#include "platform/directory_compat.h"
#include "platform/positioned_file.h"

#include <stdio.h>
#include <string.h>

/* chainparams.cpp:205-219 — mainnet primary anchor. vFastSyncAnchors lists the
 * accepted set newest first; beta6 ships exactly this one entry. */
static const struct {
    int32_t height;
    const char *hash_block;
    const char *hash_anchor_sha256;
    const char *hash_anchor_sha3;
    const char *hash_chainstate;
} k_beta6_anchor_text[] = {
    { 3126937,
      "0x00000663e40f1fe0bc32a7e7282fac25de5fe8ecefd9c627e2fd948d388f7053",
      "0x376d6d5e6f7d02459b89ae0988f5c51bb1deaf2a3e4b3a1de745e4f2e3bb279d",
      "0x0f7d542e5c662c9652b93eef8eb98e386e8bdbd2f848eba0e99c6451eb2ef0bd",
      "0x4efb67005d842e9d5bab21831fef8905a7fcb89e7264e43bd1aa00623f5a585f" },
};

#define BETA6_ANCHOR_COUNT \
    (sizeof(k_beta6_anchor_text) / sizeof(k_beta6_anchor_text[0]))

static struct beta6_bs_anchor g_anchors[BETA6_ANCHOR_COUNT];
static bool g_anchors_ready;

static void anchors_build_once(void)
{
    if (g_anchors_ready)
        return;
    for (size_t i = 0; i < BETA6_ANCHOR_COUNT; i++) {
        g_anchors[i].height = k_beta6_anchor_text[i].height;
        uint256_set_hex(&g_anchors[i].hash_block, k_beta6_anchor_text[i].hash_block);
        uint256_set_hex(&g_anchors[i].hash_anchor_sha256,
                        k_beta6_anchor_text[i].hash_anchor_sha256);
        uint256_set_hex(&g_anchors[i].hash_anchor_sha3,
                        k_beta6_anchor_text[i].hash_anchor_sha3);
        uint256_set_hex(&g_anchors[i].hash_chainstate,
                        k_beta6_anchor_text[i].hash_chainstate);
    }
    g_anchors_ready = true;
}

const struct beta6_bs_anchor *beta6_bs_anchors(size_t *count)
{
    anchors_build_once();
    if (count)
        *count = BETA6_ANCHOR_COUNT;
    return g_anchors;
}

const struct beta6_bs_anchor *beta6_bs_find_anchor(int32_t height,
                                                   const struct uint256 *hash_block)
{
    if (!hash_block)
        return NULL;
    anchors_build_once();
    for (size_t i = 0; i < BETA6_ANCHOR_COUNT; i++) {
        if (g_anchors[i].height == height &&
            uint256_eq(&g_anchors[i].hash_block, hash_block))
            return &g_anchors[i];
    }
    return NULL;
}

bool beta6_bs_sidecar_path(const char *source_dir, const char *suffix, char *out,
                           size_t out_size)
{
    if (!source_dir || !suffix || !out || out_size == 0)
        return false;
    int written = snprintf(out, out_size, "%s%s", source_dir, suffix);
    return written > 0 && (size_t)written < out_size;
}

/* Read the first line of a sidecar into `line`. The sidecars are tiny
 * operator-written records; anything longer than the buffer is malformed. */
static bool sidecar_read_line(const char *sidecar_path, char *line, size_t line_size)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, sidecar_path))
        return false;
    int64_t got = platform_positioned_file_read(&file, line, line_size - 1, 0);
    platform_positioned_file_close(&file);
    if (got <= 0)
        return false;
    line[got] = '\0';
    return true;
}

/* A 64-char lowercase-or-uppercase hex block hash, exactly as the C++ writes
 * it with uint256::ToString(). Refusing anything else keeps a malformed
 * sidecar from silently arming a partially-parsed anchor. */
static bool parse_block_hash(const char *hex, struct uint256 *out)
{
    size_t len = strlen(hex);
    if (len != 64)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F');
        if (!is_hex)
            return false;
    }
    uint256_set_hex(out, hex);
    return true;
}

bool beta6_bs_read_height_hash_sidecar(const char *sidecar_path, int32_t *height,
                                       struct uint256 *hash_block)
{
    if (!sidecar_path || !height || !hash_block)
        return false;
    char line[256];
    if (!sidecar_read_line(sidecar_path, line, sizeof(line)))
        return false;
    int parsed_height = -1;
    char hash_hex[160] = { 0 };
    if (sscanf(line, "%d %159s", &parsed_height, hash_hex) != 2)
        return false;
    if (parsed_height < 0 || !parse_block_hash(hash_hex, hash_block))
        return false;
    *height = parsed_height;
    return true;
}

bool beta6_bs_read_meta_sidecar(const char *sidecar_path, int32_t *height,
                                struct uint256 *hash_block,
                                struct uint256 *hash_chainstate)
{
    if (!sidecar_path || !height || !hash_block || !hash_chainstate)
        return false;
    char line[256];
    if (!sidecar_read_line(sidecar_path, line, sizeof(line)))
        return false;
    int parsed_height = -1;
    char hash_hex[128] = { 0 };
    char commitment_hex[128] = { 0 };
    if (sscanf(line, "%d %127s %127s", &parsed_height, hash_hex, commitment_hex) != 3)
        return false;
    if (parsed_height < 0 || !parse_block_hash(hash_hex, hash_block) ||
        !parse_block_hash(commitment_hex, hash_chainstate))
        return false;
    if (uint256_is_null(hash_chainstate))
        return false;
    *height = parsed_height;
    return true;
}

static bool dir_exists(const char *parent, const char *child)
{
    char path[4096];
    int written = snprintf(path, sizeof(path), "%s/%s", parent, child);
    if (written <= 0 || (size_t)written >= sizeof(path))
        return false;
    return platform_directory_probe_real(path) == PLATFORM_DIRECTORY_PROBE_OK;
}

bool beta6_bs_source_paths_exist(const char *source_dir)
{
    if (!source_dir || source_dir[0] == '\0')
        return false;
    return dir_exists(source_dir, "blocks") && dir_exists(source_dir, "blocks/index") &&
           dir_exists(source_dir, "chainstate");
}

/* Every "/"-separated component is non-empty and is neither "." nor ".."
 * (IsSafeBootstrapSnapshotPath, bootstrap.cpp:3374-3387). */
static bool components_are_safe(const char *relative_path)
{
    const char *segment = relative_path;
    while (*segment) {
        const char *end = strchr(segment, '/');
        size_t len = end ? (size_t)(end - segment) : strlen(segment);
        if (len == 0)
            return false;
        if ((len == 1 && segment[0] == '.') ||
            (len == 2 && segment[0] == '.' && segment[1] == '.'))
            return false;
        if (!end)
            break;
        segment = end + 1;
    }
    return true;
}

bool beta6_bs_is_data_path(const char *relative_path)
{
    if (!relative_path || relative_path[0] == '\0' || relative_path[0] == '/')
        return false;
    if (strlen(relative_path) >= BETA6_BS_MAX_PATH_LEN)
        return false;
    if (strchr(relative_path, '\\'))
        return false;
    if (!components_are_safe(relative_path))
        return false;

    /* First component must be blocks or chainstate. */
    return strncmp(relative_path, "blocks/", 7) == 0 ||
           strncmp(relative_path, "chainstate/", 11) == 0;
}
