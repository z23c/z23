/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Serve chunks from a retained immutable history generation. */
#include "net/file_service_generation.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fs_history_generation_init(struct fs_history_generation *g)
{
    if (!g) return;
    memset(g, 0, sizeof(*g));
    platform_directory_transaction_init(&g->root);
    platform_directory_transaction_init(&g->blocks);
}
static bool generation_valid(const struct file_manifest *m, int32_t height)
{
    if (!m || height < 0 || m->chain_height != height || m->num_chunks == 0 || m->num_chunks > FILE_MAX_CHUNKS)
        return false;
    uint64_t total = 0;
    struct sha3_256_ctx ctx;
    uint8_t root[32];
    sha3_256_init(&ctx);
    for (uint32_t i = 0; i < m->num_chunks; i++) {
        const struct file_chunk *c = &m->chunks[i];
        if (c->file_index > 253 || !c->size || c->size > FILE_CHUNK_SIZE ||
            c->offset > UINT64_MAX - c->size || total > UINT64_MAX - c->size)
            return false;
        total += c->size;
        sha3_256_write(&ctx, c->sha3, 32);
    }
    sha3_256_finalize(&ctx, root);
    return total == m->total_bytes && memcmp(root, m->root_hash, 32) == 0;
}
static bool generation_chunk_valid(const struct file_chunk *c);
static bool generation_extents_valid(struct platform_directory_transaction *root,
    struct platform_directory_transaction *blocks, const struct file_manifest *m)
{
    uint64_t extents[254] = {0};
    for (uint32_t i = 0; i < m->num_chunks; i++) {
        const struct file_chunk *chunk = &m->chunks[i];
        char leaf[16];
        struct platform_directory_transaction *dir = chunk->file_index == 253 ? root : blocks;
        if (!generation_chunk_valid(chunk)) return false;
        if (chunk->file_index == 253) memcpy(leaf, "block_index.bin", 16);
        else if (snprintf(leaf, sizeof(leaf), "blk%05u.dat", chunk->file_index) != 12) return false;
        struct platform_directory_child file;
        struct platform_directory_child_info info;
        platform_directory_child_init(&file);
        bool ok = platform_directory_child_open(dir, leaf, &file) &&
            platform_directory_child_info(&file, &info) && info.link_count == 1 &&
            chunk->offset == extents[chunk->file_index] &&
            chunk->offset <= info.size && chunk->size <= info.size - chunk->offset;
        platform_directory_child_close(&file);
        if (!ok) return false;
        extents[chunk->file_index] += chunk->size;
    }
    return true;
}

bool fs_history_generation_take(struct fs_history_generation *g,
    struct platform_directory_transaction *root, const struct file_manifest *m,
    const uint8_t snapshot_digest[32], int32_t height, const uint8_t hash[32])
{
    if (!g || !root || root == &g->root || root == &g->blocks || !snapshot_digest || !hash || g->ready ||
        root->native == UINTPTR_MAX || !generation_valid(m, height)) return false;
    struct platform_directory_transaction blocks;
    platform_directory_transaction_init(&blocks);
    if (platform_directory_transaction_open_child(root, "blocks", false, &blocks)
        != PLATFORM_DIRECTORY_OK) return false;
    if (!generation_extents_valid(root, &blocks, m)) {
        platform_directory_transaction_close(&blocks);
        return false;
    }
    g->root = *root;
    platform_directory_transaction_init(root);
    g->blocks = blocks;
    g->manifest = *m;
    memcpy(g->snapshot_digest, snapshot_digest, 32);
    memcpy(g->endpoint_hash, hash, 32);
    g->endpoint_height = height;
    g->ready = true;
    return true;
}
static bool generation_chunk_valid(const struct file_chunk *c)
{
    return c->file_index <= 253 && c->size > 0 && c->size <= FILE_CHUNK_SIZE &&
        c->offset <= UINT64_MAX - c->size;
}
static bool generation_open_file(const struct fs_history_generation *g,
    const struct file_chunk *c, struct platform_directory_child *file)
{
    char leaf[16];
    struct platform_directory_transaction *dir = (struct platform_directory_transaction *)
        (c->file_index == 253 ? &g->root : &g->blocks);
    if (c->file_index == 253) memcpy(leaf, "block_index.bin", 16);
    else if (snprintf(leaf, sizeof(leaf), "blk%05u.dat", c->file_index) != 12)
        return false;
    return platform_directory_child_open(dir, leaf, file);
}
static uint8_t *generation_read_file(struct platform_directory_child *file,
                                    const struct file_chunk *c)
{
    struct platform_directory_child_info info;
    if (!platform_directory_child_info(file, &info) || info.link_count != 1 ||
        c->offset > info.size || c->size > info.size - c->offset) return NULL;
    uint8_t *data = zcl_malloc(c->size, "history generation chunk");
    if (!data) return NULL;
    if (!platform_directory_child_read_exact(file, data, c->size, c->offset)) {
        free(data); return NULL;
    }
    return data;
}
bool fs_history_generation_read(const struct fs_history_generation *g,
    uint32_t index, uint8_t **out, uint32_t *size)
{
    if (out) *out = NULL;
    if (size) *size = 0;
    if (!g || !g->ready || !out || !size ||
        g->manifest.num_chunks > FILE_MAX_CHUNKS || index >= FILE_MAX_CHUNKS ||
        index >= g->manifest.num_chunks) return false;
    const struct file_chunk *c = &g->manifest.chunks[index];
    if (!generation_chunk_valid(c)) return false;
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    if (!generation_open_file(g, c, &file)) return false;
    uint8_t *data = generation_read_file(&file, c);
    platform_directory_child_close(&file);
    if (!data) return false;
    uint8_t digest[32];
    sha3_256(data, c->size, digest);
    if (memcmp(digest, c->sha3, 32) != 0) { free(data); return false; }
    *out = data; *size = c->size;
    return true;
}
void fs_history_generation_close(struct fs_history_generation *g)
{
    if (!g) return;
    platform_directory_transaction_close(&g->blocks);
    platform_directory_transaction_close(&g->root);
    fs_history_generation_init(g);
}
