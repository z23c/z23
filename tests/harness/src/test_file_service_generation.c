/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Check retained history generation identity, refusal and chunk reads. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "net/file_service_generation.h"
#include "crypto/sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/stat.h>
#include <unistd.h>
static bool write_one(const char *p, const char *s)
{
    FILE *f = fopen(p, "wb");
    if (!f) return false;
    bool ok = fwrite(s, 1, strlen(s), f) == strlen(s);
    if (fclose(f) != 0) ok = false;
    return ok && chmod(p, 0600) == 0;
}
static bool make_root(const char *p, const char *data)
{
    char b[512], f[512], i[512];
    if (snprintf(b, sizeof(b), "%s/blocks", p) >= (int)sizeof(b) ||
        snprintf(f, sizeof(f), "%s/blocks/blk00000.dat", p) >= (int)sizeof(f) ||
        snprintf(i, sizeof(i), "%s/block_index.bin", p) >= (int)sizeof(i)) return false;
    return mkdir(p, 0700) == 0 && mkdir(b, 0700) == 0 &&
        write_one(f, data) && write_one(i, "i");
}
static void manifest_root(struct file_manifest *m)
{
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (uint32_t i = 0; i < m->num_chunks; i++)
        sha3_256_write(&hash, m->chunks[i].sha3, 32);
    sha3_256_finalize(&hash, m->root_hash);
}
static void manifest(struct file_manifest *m)
{
    memset(m, 0, sizeof(*m)); m->num_chunks = 1; m->total_bytes = 3; m->chain_height = 1;
    m->chunks[0].size = 3;
    sha3_256((const uint8_t *)"abc", 3, m->chunks[0].sha3);
    manifest_root(m);
}
static bool generation_layout_refusals(struct fs_history_generation *g,
    struct platform_directory_transaction *root, struct file_manifest *m, const uint8_t binding[32])
{
    m->chunks[0].offset = 1; m->chunks[0].size = 2; m->total_bytes = 2;
    bool gap = !fs_history_generation_take(g, root, m, binding, 1, binding);
    manifest(m);
    m->num_chunks = 2; m->total_bytes = 6; m->chunks[1] = m->chunks[0]; manifest_root(m);
    bool overlap = !fs_history_generation_take(g, root, m, binding, 1, binding);
    printf("generation layout: gap=%d overlap=%d\n", gap, overlap);
    manifest(m);
    return gap && overlap;
}
static bool generation_refusals(struct fs_history_generation *g,
    struct platform_directory_transaction *root, struct platform_directory_transaction *symlink_root,
    struct file_manifest *m, const uint8_t binding[32])
{
    bool symlink_refused = !fs_history_generation_take(g, symlink_root, m, binding, 1, binding) &&
        symlink_root->native != UINTPTR_MAX;
    m->chain_height = 2;
    bool height_refused = !fs_history_generation_take(g, root, m, binding, 1, binding) &&
        root->native != UINTPTR_MAX;
    m->chain_height = 1; m->chunks[0].size = 4;
    bool extent_refused = !fs_history_generation_take(g, root, m, binding, 1, binding) &&
        root->native != UINTPTR_MAX;
    manifest(m);
    bool layout_refused = generation_layout_refusals(g, root, m, binding);
    printf("generation refusals: symlink=%d height=%d extent=%d layout=%d\n",
           symlink_refused, height_refused, extent_refused, layout_refused);
    return symlink_refused && height_refused && extent_refused && layout_refused;
}
static bool generation_read_cases(struct fs_history_generation *g)
{
    uint8_t *data = NULL; uint32_t size = 0;
    bool ok = fs_history_generation_read(g, 0, &data, &size) && size == 3 && memcmp(data, "abc", 3) == 0;
    free(data); data = NULL;
    ok = ok && !fs_history_generation_read(g, 1, &data, &size);
    g->manifest.num_chunks = FILE_MAX_CHUNKS + 1;
    ok = ok && !fs_history_generation_read(g, FILE_MAX_CHUNKS, &data, &size);
    g->manifest.num_chunks = 1; g->manifest.chunks[0].offset = UINT64_MAX;
    ok = ok && !fs_history_generation_read(g, 0, &data, &size);
    g->manifest.chunks[0].offset = 0; g->manifest.chunks[0].size = FILE_CHUNK_SIZE + 1;
    ok = ok && !fs_history_generation_read(g, 0, &data, &size);
    g->manifest.chunks[0].size = 3; g->manifest.chunks[0].file_index = 254;
    ok = ok && !fs_history_generation_read(g, 0, &data, &size);
    g->manifest.chunks[0].file_index = 0; g->manifest.chunks[0].sha3[0] ^= 1;
    return ok && !fs_history_generation_read(g, 0, &data, &size);
}

static bool generation_fixture_run(const char *tmp)
{
    char a[512], moved[512], bad[512];
    snprintf(a, sizeof(a), "%s/a", tmp);
    snprintf(moved, sizeof(moved), "%s/moved", tmp);
    snprintf(bad, sizeof(bad), "%s/bad", tmp);
    if (!make_root(a, "abc") || mkdir(bad, 0700) != 0) return false;
    char link[512]; snprintf(link, sizeof(link), "%s/bad/blocks", tmp);
    if (symlink("../a/blocks", link) != 0) return false;
    struct platform_directory_transaction root, symlink_root;
    platform_directory_transaction_init(&root); platform_directory_transaction_init(&symlink_root);
    if (!platform_directory_transaction_open(&root, a) ||
        !platform_directory_transaction_open(&symlink_root, bad)) {
        platform_directory_transaction_close(&root);
        platform_directory_transaction_close(&symlink_root);
        return false;
    }
    struct fs_history_generation g; fs_history_generation_init(&g);
    struct file_manifest m; manifest(&m); uint8_t binding[32] = {1};
    bool refusals = generation_refusals(&g, &root, &symlink_root, &m, binding);
    bool taken = refusals && fs_history_generation_take(&g, &root, &m, binding, 1, binding) &&
        root.native == UINTPTR_MAX;
    bool renamed = taken && rename(a, moved) == 0 && make_root(a, "xyz");
    bool reads = renamed && generation_read_cases(&g);
    printf("generation lifecycle: refusals=%d taken=%d renamed=%d reads=%d\n",
           refusals, taken, renamed, reads);
    bool ok = refusals && taken && renamed && reads;
    fs_history_generation_close(&g);
    platform_directory_transaction_close(&root);
    platform_directory_transaction_close(&symlink_root);
    return ok;
}
static bool generation_fixture(void)
{
    char tmp[512];
    if (!test_mkdtemp(tmp, sizeof(tmp), "file_service_generation")) return false;
    bool ok = generation_fixture_run(tmp);
    return test_rm_rf_recursive(tmp) == 0 && ok;
}
int test_file_service_generation(void) { return generation_fixture() ? 0 : 1; }
#else
int test_file_service_generation(void) { printf("SKIP (Linux-only generation fixture)\n"); return 0; }
#endif
