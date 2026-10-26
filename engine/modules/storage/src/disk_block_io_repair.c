/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: blk*.dat frame decoding and hash-targeted position repair — the
 * layer that understands the on-disk 8-byte magic+size record header, plus
 * the rescan that relocates a block by hash when its stored position has
 * gone stale.
 *
 * Split out of disk_block_io.c along the file-size ceiling seam: that file
 * keeps the write path, the handle caches, the deferred fdatasync
 * bookkeeping and the pread read paths. The one symbol that crosses back
 * (disk_block_locate_payload) is declared in disk_block_io_internal.h.
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#include "disk_block_io_internal.h"

#include "storage/disk_block_io.h"
#include "core/serialize.h"
#include "core/hash.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"
#include "platform/positioned_file.h"
#include "platform/positioned_io.h"
#include "platform/read_mapping.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/mman.h>
#endif

/* The accepted frame magic bytes, in the order the header check tests
 * them. */
static const uint8_t disk_block_frame_magics[3][4] = {
    {0x24, 0xe9, 0x27, 0x64},
    {0xfa, 0x1a, 0xf9, 0xbf},
    {0xaa, 0xe8, 0x3f, 0x5f},
};

/* True when hdr[0..3] holds one of the accepted frame magics. */
static bool disk_block_frame_magic_matches(const uint8_t hdr[4])
{
    for (size_t i = 0; i < 3; i++) {
        if (memcmp(hdr, disk_block_frame_magics[i], 4) == 0)
            return true;
    }
    return false;
}

static bool disk_block_frame_header_valid(const uint8_t hdr[8],
                                          uint32_t *out_size)
{
    bool magic_ok = disk_block_frame_magic_matches(hdr);
    uint32_t block_size = 0;
    memcpy(&block_size, hdr + 4, 4);
    if (!magic_ok || block_size == 0 || block_size > 2000000u)
        return false;
    if (out_size)
        *out_size = block_size;
    return true;
}

/* True when an 8-byte magic+size frame header sits at `off`. */
static bool disk_block_frame_at(int fd, uint64_t off, uint32_t *out_size)
{
    uint8_t hdr[8];
    return platform_positioned_read(fd, hdr, sizeof(hdr), off) ==
               (int64_t)sizeof(hdr) &&
           disk_block_frame_header_valid(hdr, out_size);
}

/* Resolve (payload offset, size), or REFUSE an unframed position — see the
 * FRAMED POSITIONS ONLY contract in storage/disk_block_io.h. */
bool disk_block_locate_payload(int fd,
                               const struct disk_block_pos *pos,
                               uint32_t *out_payload_pos,
                               size_t *out_size)
{
    if (!pos || !out_payload_pos || !out_size)
        return false;
    uint32_t block_size = 0;
    /* Canonical block indexes store the PAYLOAD offset: frame sits at pos-8. */
    if (pos->nPos >= 8 &&
        disk_block_frame_at(fd, (uint64_t)pos->nPos - 8, &block_size)) {
        *out_payload_pos = pos->nPos;
        *out_size = block_size;
        return true;
    }
    /* Some recovery/import paths hand the FRAME offset instead. Accept it. */
    if (pos->nPos <= UINT32_MAX - 8u &&
        disk_block_frame_at(fd, pos->nPos, &block_size)) {
        *out_payload_pos = pos->nPos + 8u;
        *out_size = block_size;
        return true;
    }

    return false;
}

/* ── Hash-targeted position repair ─────────────────────────────
 * See storage/disk_block_io.h. Motivation (2026-08 producer-fold wedge):
 * blk*.dat files hardlinked into a live zclassicd datadir are rewritten
 * under us (zd's rebuilt index appends below physical EOF), so a position
 * that was hash-valid when stored can dangle while a DUPLICATE copy of the
 * same block still exists elsewhere in the blk files. A hash-targeted
 * rescan finds that copy and re-stores through the verified path above. */

/* Enough of a record to cover the full ZClassic header (140 fixed bytes
 * plus the compactsize-prefixed Equihash solution — the block hash commits
 * to all of it). Same bound chain_restore_disk_repair uses. */
#define REPAIR_HDR_READ_SIZE \
    (4 + 32 + 32 + 32 + 4 + 4 + 32 + 9 + MAX_SOLUTION_SIZE)

/* Open `path` and map it whole for a repair scan. Returns 0 with
 * *out_file, *out_mapping and *out_file_size filled on success (the caller
 * closes both handles), -1 when the open fails, -2 when the size is
 * unusable and -3 when the map fails; anything already opened on a
 * failure is closed again before returning. */
static int repair_scan_open_mapped(const char *path,
                                   struct platform_positioned_file *out_file,
                                   struct platform_read_mapping *out_mapping,
                                   uint64_t *out_file_size)
{
    platform_positioned_file_init(out_file);
    platform_read_mapping_init(out_mapping);
    if (!platform_positioned_file_open(out_file, path))
        return -1;
    if (!platform_positioned_file_size(out_file, out_file_size) ||
        *out_file_size == 0 || *out_file_size > LONG_MAX ||
        *out_file_size > SIZE_MAX) {
        platform_positioned_file_close(out_file);
        return -2;
    }
    if (!platform_read_mapping_open_positioned(out_mapping, out_file,
                                               (size_t)*out_file_size)) {
        platform_positioned_file_close(out_file);
        return -3;
    }
    return 0;
}

/* First offset at or after `from` where a valid frame header sits, or -1
 * when none is left before the 140-byte floor. */
static long repair_scan_next_frame_offset(const uint8_t *data, long from,
                                          long fsize)
{
    for (long p = from; p + 8 + 140 <= fsize; p++) {
        uint32_t sz = 0;
        if (disk_block_frame_header_valid(data + p, &sz))
            return p;
    }
    return -1;
}

/* Decode the header of the framed record at `pos` and compare its hash
 * against `target`: 1 = the hashes match, 0 = decoded but different,
 * -1 = the record header does not decode. */
static int repair_scan_record_hash_matches(const uint8_t *data, long pos,
                                           uint32_t blk_size,
                                           const struct uint256 *target)
{
    size_t want = (size_t)blk_size < (size_t)REPAIR_HDR_READ_SIZE
                      ? (size_t)blk_size : (size_t)REPAIR_HDR_READ_SIZE;
    struct block_header bhdr;
    block_header_init(&bhdr);
    struct byte_stream bs;
    stream_init_from_data(&bs, data + pos + 8, want);
    bool parsed = block_header_deserialize(&bhdr, &bs);
    stream_free(&bs);
    if (!parsed)
        return -1;
    struct uint256 h;
    block_header_get_hash(&bhdr, &h);
    return uint256_cmp(&h, target) == 0;
}

/* Walk one blk*.dat record-by-record looking for the block whose hash
 * equals `target`; on a hit *pos_out takes the canonical nDataPos (record
 * start + 8). Garbage gaps are skipped by resyncing to the next frame
 * header — the same policy as the boot blk-file scan. */
static bool repair_scan_one_file(const char *path,
                                 const struct uint256 *target,
                                 unsigned int *pos_out)
{
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    uint64_t file_size = 0;
    if (repair_scan_open_mapped(path, &file, &mapping, &file_size) != 0)
        return false;
    long fsize = (long)file_size;
    const uint8_t *data = mapping.data;

    bool found = false;
    long pos = 0;
    while (!found && pos + 8 + 140 <= fsize) {
        uint32_t blk_size = 0;
        if (!disk_block_frame_header_valid(data + pos, &blk_size) ||
            blk_size < 140 || pos + 8 + (long)blk_size > fsize) {
            long next = repair_scan_next_frame_offset(data, pos + 1, fsize);
            if (next < 0)
                break;
            pos = next;
            continue;
        }

        if (repair_scan_record_hash_matches(data, pos, blk_size,
                                            target) == 1) {
            *pos_out = (unsigned int)(pos + 8);
            found = true;
        }
        pos += 8 + (long)blk_size;
    }

    platform_read_mapping_close(&mapping);
    platform_positioned_file_close(&file);
    return found;
}

/* Scan only the blk*.dat that `pos` names — repair pass 1. Returns that
 * file number on a hit, -1 on a miss. */
static int repair_scan_current_blk_file(const char *datadir,
                                        const struct disk_block_pos *pos,
                                        const struct uint256 *target,
                                        unsigned int *pos_out)
{
    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, pos, "blk");
    if (repair_scan_one_file(path, target, pos_out))
        return pos->nFile;
    return -1;
}

/* True when a full blk-set scan already ran within the last 60 seconds. */
static bool repair_full_scan_throttled(int64_t now, int64_t last)
{
    /* last==0 doubles as "never ran" (a frozen/mocked clock reads 0),
     * so the first full sweep always runs. */
    return last != 0 && now - last < 60;
}

/* Scan every blk*.dat except `skip_file` — repair pass 2 — stopping after
 * 3 consecutive missing/empty files (the boot scan's gap policy). Returns
 * the file number holding `target`, or -1 when none does. */
static int repair_scan_blk_file_set(const char *datadir, int skip_file,
                                    const struct uint256 *target,
                                    unsigned int *pos_out)
{
    int found_file = -1;
    int misses = 0;
    for (int i = 0; i <= 9999 && found_file < 0; i++) {
        if (i == skip_file)
            continue;
        char path[512];
        struct disk_block_pos probe = { .nFile = i, .nPos = 0 };
        get_block_pos_filename(path, sizeof(path), datadir, &probe, "blk");
        struct stat st;
        if (stat(path, &st) != 0 || st.st_size <= 0) {
            if (++misses >= 3)
                break;
            continue;
        }
        misses = 0;
        if (repair_scan_one_file(path, target, pos_out))
            found_file = i;
    }
    return found_file;
}

bool block_index_repair_pos_from_disk(struct block_index *pindex,
                                      const char *datadir,
                                      bool scan_all_files)
{
    if (!pindex || !datadir || !datadir[0])
        LOG_FAIL("disk_block_io",
                 "repair_pos_from_disk: invalid argument (pindex=%p datadir=%p)",
                 (void *)pindex, (const void *)datadir);
    if (!pindex->phashBlock)
        LOG_FAIL("disk_block_io",
                 "repair_pos_from_disk: missing block hash at h=%d",
                 pindex->nHeight);

    struct disk_block_pos cur;
    disk_block_pos_init(&cur);
    (void)block_index_disk_pos_snapshot(pindex, &cur, NULL);

    unsigned int found_pos = 0;
    int found_file = -1;

    /* Pass 1: the file the entry currently points at — the usual case is a
     * stale offset inside the SAME blk file (a duplicate copy survives
     * there), so it is both cheapest and most likely. */
    if (cur.nFile >= 0)
        found_file = repair_scan_current_blk_file(datadir, &cur,
                                                  pindex->phashBlock,
                                                  &found_pos);

    /* Pass 2: every other blk*.dat, stopping after 3 consecutive misses
     * (the boot scan's gap policy). A full sweep hashes every header in the
     * blk set — throttle it so a mass-missing-bodies episode (blocks-less
     * bundle) degrades to the clear-and-refetch fallback instead of a full
     * walk per failure. Pass-1 hits (the common stale-tail case) are never
     * throttled. */
    static int64_t g_last_full_scan_unix = 0;
    if (found_file < 0 && scan_all_files) {
        int64_t now = platform_time_wall_unix();
        int64_t last = __atomic_load_n(&g_last_full_scan_unix, __ATOMIC_RELAXED);
        if (repair_full_scan_throttled(now, last)) {
            LOG_WARN("disk_block_io",
                     "repair_pos_from_disk: h=%d same-file miss, full blk-set "
                     "scan throttled (%llds since last) — falling back",
                     pindex->nHeight, (long long)(now - last));
            return false;
        }
        __atomic_store_n(&g_last_full_scan_unix, now, __ATOMIC_RELAXED);
        found_file = repair_scan_blk_file_set(datadir, cur.nFile,
                                              pindex->phashBlock, &found_pos);
    }

    char want_hex[65];
    uint256_get_hex(pindex->phashBlock, want_hex);
    if (found_file < 0) {
        LOG_WARN("disk_block_io",
                 "repair_pos_from_disk: h=%d hash=%.16s has no copy in any "
                 "blk file — caller falls back to clear-and-refetch",
                 pindex->nHeight, want_hex);
        return false;
    }

    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    pos.nFile = found_file;
    pos.nPos = found_pos;
    if (!block_index_set_have_data_verified(pindex, &pos, datadir))
        return false; /* verified store already logged the mismatch */

    LOG_WARN("disk_block_io",
             "repair_pos_from_disk: h=%d repositioned file=%d pos=%u -> "
             "file=%d pos=%u (hash=%.16s verified on read-back)",
             pindex->nHeight, cur.nFile, cur.nPos, found_file, found_pos,
             want_hex);
    return true;
}
