/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocks_mmap_reader.c — see header.
 *
 * Layout of each block inside a blk*.dat file:
 *
 *     [magic(4) | size(4) | payload(size bytes)]
 *
 * `nDataPos` (stored in the block-index record) points to the start of
 * the payload, NOT the magic. To validate, we peek 8 bytes back.
 *
 * Accepted magic values:
 *   0x24e92764 — zcash / zclassic mainnet
 *   0xfa1af9bf — testnet
 *   0xaae83f5f — regtest
 *
 * mmap regions are MAP_PRIVATE | PROT_READ — kernel page-cache backed,
 * zero-copy, safe under concurrent readers.
 */

#include "storage/blocks_mmap_reader.h"

#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BMR_LRU_SIZE 8

struct bmr_slot {
    int32_t nFile;            /* -1 when slot empty */
    const uint8_t *base;
    size_t size;
    uint64_t last_used;
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
};

struct blocks_mmap {
    char *blocks_dir;
    struct bmr_slot lru[BMR_LRU_SIZE];
    uint64_t clock;
};

bool bmr_open(const char *blocks_dir, struct blocks_mmap **out)
{
    if (!blocks_dir || !out)
        return false;
    *out = NULL;

    if (platform_directory_probe_real(blocks_dir) !=
        PLATFORM_DIRECTORY_PROBE_OK) {
        fprintf(stderr, "[bmr] not a directory: %s\n", blocks_dir);
        return false;
    }

    struct blocks_mmap *m = zcl_malloc(sizeof(*m), "bmr");
    if (!m) return false;
    memset(m, 0, sizeof(*m));
    m->blocks_dir = strdup(blocks_dir);
    if (!m->blocks_dir) {
        free(m);
        return false;
    }
    for (int i = 0; i < BMR_LRU_SIZE; i++)
        m->lru[i].nFile = -1;

    *out = m;
    return true;
}

static void bmr_evict_slot(struct bmr_slot *s)
{
    if (s->base) {
        platform_read_mapping_close(&s->mapping);
        platform_positioned_file_close(&s->file);
        s->base = NULL;
        s->size = 0;
    }
    s->nFile = -1;
}

void bmr_close(struct blocks_mmap *m)
{
    if (!m) return;
    for (int i = 0; i < BMR_LRU_SIZE; i++)
        bmr_evict_slot(&m->lru[i]);
    free(m->blocks_dir);
    free(m);
}

/* Find an LRU slot for nFile. If already mapped, return it. If not,
 * find or evict a slot and mmap. Returns NULL on failure. */
static struct bmr_slot *bmr_ensure_slot(struct blocks_mmap *m, int32_t nFile)
{
    /* Hit? */
    for (int i = 0; i < BMR_LRU_SIZE; i++) {
        if (m->lru[i].nFile == nFile) {
            m->lru[i].last_used = ++m->clock;
            return &m->lru[i];
        }
    }

    /* Find a free slot, else evict the least-recently-used. */
    int victim = -1;
    uint64_t oldest = UINT64_MAX;
    for (int i = 0; i < BMR_LRU_SIZE; i++) {
        if (m->lru[i].nFile < 0) { victim = i; break; }
        if (m->lru[i].last_used < oldest) {
            oldest = m->lru[i].last_used;
            victim = i;
        }
    }
    if (victim < 0) return NULL;
    bmr_evict_slot(&m->lru[victim]);

    char path[1024];
    int path_len = snprintf(path, sizeof(path), "blk%05d.dat", nFile);
    if (path_len < 0 || (size_t)path_len >= sizeof(path))
        return NULL;
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    platform_positioned_file_init(&file);
    platform_read_mapping_init(&mapping);
    if (!platform_positioned_file_open_beneath(&file, m->blocks_dir, path)) {
        fprintf(stderr, "[bmr] open failed: %s/%s\n", m->blocks_dir, path);
        return NULL;
    }
    uint64_t file_size = 0;
    if (!platform_positioned_file_size(&file, &file_size) ||
        file_size == 0 || file_size > SIZE_MAX) {
        platform_positioned_file_close(&file);
        fprintf(stderr, "[bmr] invalid file size: %s/%s\n", m->blocks_dir,
                path);
        return NULL;
    }
    if (!platform_read_mapping_open_positioned(&mapping, &file,
                                               (size_t)file_size)) {
        platform_positioned_file_close(&file);
        fprintf(stderr, "[bmr] mapping failed: %s/%s\n", m->blocks_dir,
                path);
        return NULL;
    }

    /* Advise sequential — we walk height-ordered, but per-file the
     * blocks are mostly in receive-order which IS sequential within
     * the file. */
    platform_read_mapping_advise_sequential(&mapping);

    m->lru[victim].nFile = nFile;
    m->lru[victim].file = file;
    m->lru[victim].mapping = mapping;
    m->lru[victim].base  = mapping.data;
    m->lru[victim].size  = mapping.size;
    m->lru[victim].last_used = ++m->clock;
    return &m->lru[victim];
}

const uint8_t *bmr_get_payload(struct blocks_mmap *m,
                               int32_t nFile, uint32_t nDataPos,
                               size_t *out_len)
{
    if (!m || !out_len) return NULL;
    *out_len = 0;
    if (nFile < 0 || nDataPos < 8) return NULL;

    struct bmr_slot *s = bmr_ensure_slot(m, nFile);
    if (!s) return NULL;
    if ((size_t)nDataPos > s->size) {
        fprintf(stderr, "[bmr] nDataPos %u beyond file size %zu (nFile=%d)\n",
                nDataPos, s->size, nFile);
        return NULL;
    }

    const uint8_t *hdr = s->base + (nDataPos - 8u);
    bool magic_ok = (hdr[0] == 0x24 && hdr[1] == 0xe9 &&
                     hdr[2] == 0x27 && hdr[3] == 0x64) ||
                    (hdr[0] == 0xfa && hdr[1] == 0x1a &&
                     hdr[2] == 0xf9 && hdr[3] == 0xbf) ||
                    (hdr[0] == 0xaa && hdr[1] == 0xe8 &&
                     hdr[2] == 0x3f && hdr[3] == 0x5f);
    if (!magic_ok) {
        fprintf(stderr, "[bmr] bad magic at nFile=%d nDataPos=%u: %02x%02x%02x%02x\n",
                nFile, nDataPos, hdr[0], hdr[1], hdr[2], hdr[3]);
        return NULL;
    }
    uint32_t blk_size = 0;
    memcpy(&blk_size, hdr + 4, 4);
    if (blk_size == 0 || blk_size > 2000000u) {
        fprintf(stderr, "[bmr] invalid block size %u at nFile=%d nDataPos=%u\n",
                blk_size, nFile, nDataPos);
        return NULL;
    }
    if ((size_t)nDataPos + blk_size > s->size) {
        fprintf(stderr, "[bmr] payload runs off end (nFile=%d nDataPos=%u size=%u file_size=%zu)\n",
                nFile, nDataPos, blk_size, s->size);
        return NULL;
    }

    *out_len = blk_size;
    return s->base + nDataPos;
}
