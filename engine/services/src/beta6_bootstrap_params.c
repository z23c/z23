/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Serve the Zcash zk-SNARK parameter files over the beta6 bootstrap wire.
 *
 * Port of GetZcashParamManifest + ReadZcashParamChunk (bootstrap.cpp:3842-3961,
 * 3964-4031). A fresh beta6 node fetches the proving/verifying parameters from
 * its bootstrap peer rather than an external download; because the expected
 * SHA-256 of every file is compiled into the CLIENT, the serving peer is
 * untrusted and only content matching a compiled hash is installed. The server
 * therefore advertises the compiled hash, not a recomputed one, and advertises
 * a file only when its on-disk size matches the compiled size exactly.
 *
 * The manifest is v1-shaped: no height, no anchor hashes — the client's param
 * path never runs it through the snapshot anchor validator.
 */
#include "services/beta6_bootstrap.h"

#include "base/safe_alloc.h"
#include "platform/positioned_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bootstrap.cpp:3828-3835 — the authoritative table, in the order the manifest
 * advertises and serves them. */
static const struct {
    const char *name;
    const char *sha256_hex;
    uint64_t size;
} k_param_specs[] = {
    { "sapling-output.params",
      "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4", 3592860ULL },
    { "sapling-spend.params",
      "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13", 47958396ULL },
    { "sprout-groth16.params",
      "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50", 725523612ULL },
    { "sprout-proving.key",
      "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7", 910173851ULL },
    { "sprout-verifying.key",
      "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82", 1449ULL },
};

#define BETA6_PARAM_COUNT (sizeof(k_param_specs) / sizeof(k_param_specs[0]))

static void set_msg(char *err, size_t err_size, const char *message)
{
    if (err && err_size)
        snprintf(err, err_size, "%s", message);
}

/* Present with the compiled size, opened without following a link. Fills the
 * manifest entry (including the handle-bound mtime the chunk read re-proves).
 * A file that is absent or the wrong size is simply not advertised, exactly as
 * the C++ `continue`s past it. */
static bool describe_param(const char *params_dir, size_t index,
                           struct beta6_bs_file *out)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, params_dir, k_param_specs[index].name))
        return false;
    struct platform_positioned_file_snapshot stamp;
    uint64_t size = 0;
    bool ok = platform_positioned_file_size(&file, &size) &&
              platform_positioned_file_snapshot(&file, &stamp);
    platform_positioned_file_close(&file);
    if (!ok || size != k_param_specs[index].size)
        return false;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", k_param_specs[index].name);
    out->size = size;
    out->mtime_seconds = stamp.modified_seconds;
    uint256_set_hex(&out->sha256, k_param_specs[index].sha256_hex);
    return true;
}

bool beta6_bs_param_manifest(const char *params_dir, const char *network,
                             struct beta6_bs_manifest *manifest, char *err,
                             size_t err_size)
{
    if (!params_dir || !network || !manifest)
        return false;
    beta6_bs_manifest_init(manifest);
    snprintf(manifest->network, sizeof(manifest->network), "%s", network);
    manifest->chunk_size = BETA6_BS_CHUNK_SIZE;

    struct beta6_bs_file *files =
        zcl_calloc(BETA6_PARAM_COUNT, sizeof(*files), "beta6 zcash param manifest");
    if (!files) {
        set_msg(err, err_size, "out of memory building the beta6 zcash param manifest");
        return false;
    }
    size_t count = 0;
    uint64_t total = 0;
    for (size_t i = 0; i < BETA6_PARAM_COUNT; i++) {
        if (!describe_param(params_dir, i, &files[count]))
            continue;
        total += files[count].size;
        count++;
    }
    if (count == 0) {
        free(files);
        set_msg(err, err_size, "no zcash parameters available to serve");
        return false;
    }
    manifest->files = files;
    manifest->file_count = count;
    manifest->snapshot_bytes = total;
    return true;
}

bool beta6_bs_read_param_chunk(const char *params_dir, const char *network,
                               const struct beta6_bs_chunk_request *request,
                               unsigned char *out, size_t out_capacity, char *err,
                               size_t err_size)
{
    if (!params_dir || !request || !out)
        return false;
    if (request->length == 0 || request->length > BETA6_BS_CHUNK_SIZE) {
        set_msg(err, err_size, "invalid zcash param chunk length");
        return false;
    }

    struct beta6_bs_manifest manifest;
    if (!beta6_bs_param_manifest(params_dir, network, &manifest, err, err_size))
        return false;
    bool ok = false;
    if (request->file_index >= manifest.file_count) {
        set_msg(err, err_size, "zcash param chunk file index out of range");
    } else {
        /* Param paths are bare compiled file names, not blocks/ or chainstate/
         * data paths, so they use the same bounded reader with the manifest's
         * own path rather than beta6_bs_is_data_path. */
        ok = beta6_bs_read_file_chunk(params_dir, &manifest.files[request->file_index],
                                      request, "zcash param", out, out_capacity, err,
                                      err_size);
    }
    beta6_bs_manifest_free(&manifest);
    return ok;
}
