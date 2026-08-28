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
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

static bool disk_block_frame_header_valid(const uint8_t hdr[8],
                                          uint32_t *out_size)
{
    bool magic_ok = (hdr[0] == 0x24 && hdr[1] == 0xe9 &&
                     hdr[2] == 0x27 && hdr[3] == 0x64) ||
                    (hdr[0] == 0xfa && hdr[1] == 0x1a &&
                     hdr[2] == 0xf9 && hdr[3] == 0xbf) ||
                    (hdr[0] == 0xaa && hdr[1] == 0xe8 &&
                     hdr[2] == 0x3f && hdr[3] == 0x5f);
    uint32_t block_size = 0;
    memcpy(&block_size, hdr + 4, 4);
    if (!magic_ok || block_size == 0 || block_size > 2000000u)
        return false;
    if (out_size)
        *out_size = block_size;
    return true;
}

/* True when an 8-byte magic+size frame header sits at `off`. */
static bool disk_block_frame_at(int fd, off_t off, uint32_t *out_size)
{
    uint8_t hdr[8];
    return pread(fd, hdr, sizeof(hdr), off) == (ssize_t)sizeof(hdr) &&
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
        disk_block_frame_at(fd, (off_t)(pos->nPos - 8), &block_size)) {
        *out_payload_pos = pos->nPos;
        *out_size = block_size;
        return true;
    }
    /* Some recovery/import paths hand the FRAME offset instead. Accept it. */
    if (pos->nPos <= UINT32_MAX - 8u &&
        disk_block_frame_at(fd, (off_t)pos->nPos, &block_size)) {
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

/* Walk one blk*.dat record-by-record looking for the block whose hash
 * equals `target`; on a hit *pos_out takes the canonical nDataPos (record
 * start + 8). Garbage gaps are skipped by resyncing to the next frame
 * header — the same policy as the boot blk-file scan. */
static bool repair_scan_one_file(const char *path,
                                 const struct uint256 *target,
                                 unsigned int *pos_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return false;
    }
    long fsize = (long)st.st_size;
    uint8_t *data = mmap(NULL, (size_t)fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED)
        return false;

    bool found = false;
    long pos = 0;
    while (!found && pos + 8 + 140 <= fsize) {
        uint32_t blk_size = 0;
        if (!disk_block_frame_header_valid(data + pos, &blk_size) ||
            blk_size < 140 || pos + 8 + (long)blk_size > fsize) {
            long next = -1;
            for (long p = pos + 1; p + 8 + 140 <= fsize; p++) {
                uint32_t sz = 0;
                if (disk_block_frame_header_valid(data + p, &sz)) {
                    next = p;
                    break;
                }
            }
            if (next < 0)
                break;
            pos = next;
            continue;
        }

        size_t want = (size_t)blk_size < (size_t)REPAIR_HDR_READ_SIZE
                          ? (size_t)blk_size : (size_t)REPAIR_HDR_READ_SIZE;
        struct block_header bhdr;
        block_header_init(&bhdr);
        struct byte_stream bs;
        stream_init_from_data(&bs, data + pos + 8, want);
        bool parsed = block_header_deserialize(&bhdr, &bs);
        stream_free(&bs);
        if (parsed) {
            struct uint256 h;
            block_header_get_hash(&bhdr, &h);
            if (uint256_cmp(&h, target) == 0) {
                *pos_out = (unsigned int)(pos + 8);
                found = true;
            }
        }
        pos += 8 + (long)blk_size;
    }

    munmap(data, (size_t)fsize);
    return found;
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
    if (cur.nFile >= 0) {
        char path[512];
        get_block_pos_filename(path, sizeof(path), datadir, &cur, "blk");
        if (repair_scan_one_file(path, pindex->phashBlock, &found_pos))
            found_file = cur.nFile;
    }

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
        /* last==0 doubles as "never ran" (a frozen/mocked clock reads 0),
         * so the first full sweep always runs. */
        if (last != 0 && now - last < 60) {
            LOG_WARN("disk_block_io",
                     "repair_pos_from_disk: h=%d same-file miss, full blk-set "
                     "scan throttled (%llds since last) — falling back",
                     pindex->nHeight, (long long)(now - last));
            return false;
        }
        __atomic_store_n(&g_last_full_scan_unix, now, __ATOMIC_RELAXED);
        int misses = 0;
        for (int i = 0; i <= 9999 && found_file < 0; i++) {
            if (i == cur.nFile)
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
            if (repair_scan_one_file(path, pindex->phashBlock, &found_pos))
                found_file = i;
        }
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
