/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The mechanism. The format, and why a CRC is not enough, are in
 * chainlog/chainlog.h.
 *
 * All file access goes through platform/private_file.h rather than raw
 * POSIX: it is the seam that already carries exclusive locking, positioned
 * reads and writes, truncation and fsync on both hosts. The exclusive lock
 * is not incidental — a chain has exactly one writer by construction, and
 * two appenders racing would produce two frames claiming the same sequence
 * number and the same previous hash.
 */

#include "chainlog/chainlog.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/private_file.h"
#include "sha3/sha3.h"

#include <string.h>

#define HDR   ZCL_CHAINLOG_HEADER_BYTES
#define PRE   ZCL_CHAINLOG_PREFIX_BYTES
#define HASH  ZCL_CHAINLOG_HASH_BYTES
#define SENT  ZCL_CHAINLOG_SENTINEL_BYTES

struct zcl_chainlog {
    struct platform_private_file file;
    uint8_t  stream[ZCL_CHAINLOG_STREAM_BYTES];
    uint8_t  seed[HASH]; /* chain value before frame 1 */
    uint8_t  head[HASH];
    uint64_t count;
    uint64_t size;    /* committed bytes, i.e. where the next frame starts */
    uint64_t *offset; /* offset[i] is the start of frame i+1 */
    size_t   offset_cap;
    uint8_t *scratch; /* ZCL_CHAINLOG_PAYLOAD_MAX bytes */
};

const char *zcl_chainlog_status_label(enum zcl_chainlog_status s)
{
    switch (s) {
    case ZCL_CHAINLOG_OK:               return "OK";
    case ZCL_CHAINLOG_ARGUMENT:         return "ARGUMENT";
    case ZCL_CHAINLOG_IO:               return "IO";
    case ZCL_CHAINLOG_FORMAT:           return "FORMAT";
    case ZCL_CHAINLOG_STREAM_MISMATCH:  return "STREAM_MISMATCH";
    case ZCL_CHAINLOG_BROKEN_CHAIN:     return "BROKEN_CHAIN";
    case ZCL_CHAINLOG_SEQUENCE:         return "SEQUENCE";
    case ZCL_CHAINLOG_UNCOMMITTED_GAP:  return "UNCOMMITTED_GAP";
    case ZCL_CHAINLOG_NOT_FOUND:        return "NOT_FOUND";
    case ZCL_CHAINLOG_TRUNCATED:        return "TRUNCATED";
    }
    return "UNKNOWN_STATUS";
}

/* ── header ────────────────────────────────────────────────────────── */

static void sha3_of(const uint8_t *data, size_t len, uint8_t out[HASH])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)data, len);
    sha3_256_finalize(&c, (unsigned char *)out);
}

static void header_build(uint8_t out[HDR], const uint8_t stream[32])
{
    memset(out, 0, HDR);
    memcpy(out, ZCL_CHAINLOG_MAGIC, 8);
    zcl_write_u32_be(out + 8, ZCL_CHAINLOG_VERSION);
    zcl_write_u32_be(out + 12, 0u);
    memcpy(out + 16, stream, ZCL_CHAINLOG_STREAM_BYTES);
    uint8_t d[HASH];
    sha3_of(out, 48, d);
    memcpy(out + 48, d, 16);
}

/* The reserved word is CHECKED, not skipped: a field nobody validates is a
 * field a later writer can smuggle meaning into. */
static enum zcl_chainlog_status header_check(const uint8_t in[HDR],
                                             const uint8_t stream[32])
{
    if (memcmp(in, ZCL_CHAINLOG_MAGIC, 8) != 0)
        return ZCL_CHAINLOG_FORMAT;
    if (zcl_read_u32_be(in + 8) != ZCL_CHAINLOG_VERSION)
        return ZCL_CHAINLOG_FORMAT;
    if (zcl_read_u32_be(in + 12) != 0u)
        return ZCL_CHAINLOG_FORMAT;
    uint8_t d[HASH];
    sha3_of(in, 48, d);
    if (memcmp(in + 48, d, 16) != 0)
        return ZCL_CHAINLOG_FORMAT;
    if (memcmp(in + 16, stream, ZCL_CHAINLOG_STREAM_BYTES) != 0)
        return ZCL_CHAINLOG_STREAM_MISMATCH;
    return ZCL_CHAINLOG_OK;
}

/* chain_n = SHA3-256(chain_{n-1} || prefix || payload) */
static void frame_hash(const uint8_t prev[HASH], const uint8_t prefix[PRE],
                       const uint8_t *payload, size_t len, uint8_t out[HASH])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)prev, HASH);
    sha3_256_write(&c, (const unsigned char *)prefix, PRE);
    if (len)
        sha3_256_write(&c, (const unsigned char *)payload, len);
    sha3_256_finalize(&c, (unsigned char *)out);
}

static void sentinel_build(uint8_t out[SENT], uint64_t start)
{
    memset(out, 0, SENT);
    memcpy(out, ZCL_CHAINLOG_SENTINEL_MAGIC, 7);
    zcl_write_u64_be(out + 8, start);
}

static bool sentinel_ok(const uint8_t in[SENT], uint64_t start)
{
    return memcmp(in, ZCL_CHAINLOG_SENTINEL_MAGIC, 7) == 0 && in[7] == 0 &&
           zcl_read_u64_be(in + 8) == start;
}

/* ── the scan ──────────────────────────────────────────────────────── */

static bool offsets_reserve(uint64_t **arr, size_t *cap, size_t need)
{
    if (need <= *cap)
        return true;
    size_t nc = *cap ? *cap * 2 : 64;
    while (nc < need) {
        if (nc > SIZE_MAX / 2)
            LOG_FAIL("chainlog", "offset table too large: %zu", nc);
        nc *= 2;
    }
    uint64_t *na = zcl_realloc(*arr, nc * sizeof *na, "chainlog_offsets");
    if (!na)
        LOG_FAIL("chainlog", "offset table grow to %zu failed", nc);
    *arr = na;
    *cap = nc;
    return true;
}

/* Walk every frame from `seed`, filling `rep`. Never writes. `rep->torn_bytes`
 * reports an uncommitted tail; deciding what to do about it belongs to the
 * caller, because only open-for-append is allowed to remove it. */
static enum zcl_chainlog_status scan(struct platform_private_file *f,
                                     uint64_t size, const uint8_t seed[HASH],
                                     uint8_t *scratch,
                                     struct zcl_chainlog_report *rep,
                                     uint64_t **offset, size_t *offset_cap)
{
    uint8_t chain[HASH];
    memcpy(chain, seed, HASH);
    memcpy(rep->head, seed, HASH);

    uint64_t at = HDR;
    while (at < size) {
        uint64_t left = size - at;
        uint8_t prefix[PRE];
        if (left < PRE) {
            rep->torn_bytes = left;
            break;
        }
        if (!platform_private_file_read_at(f, prefix, PRE, at))
            return ZCL_CHAINLOG_IO;

        uint32_t kind = zcl_read_u32_be(prefix);
        uint64_t seq = zcl_read_u64_be(prefix + 4);
        uint32_t len = zcl_read_u32_be(prefix + 12);
        (void)kind;

        /* An impossible length REFUSES; it is never treated as a torn tail.
         * The prefix is written by one 16-byte write, so a length this wrong
         * is far more likely an edit than an interrupted append — and the
         * two are indistinguishable from here. Discarding the rest of the
         * file on that guess would destroy the evidence. */
        if (len > ZCL_CHAINLOG_PAYLOAD_MAX) {
            rep->first_bad_seq = seq;
            return ZCL_CHAINLOG_FORMAT;
        }
        uint64_t need = (uint64_t)PRE + len + HASH + SENT;
        if (left < need) {
            rep->torn_bytes = left;
            break;
        }

        if (len && !platform_private_file_read_at(f, scratch, len, at + PRE))
            return ZCL_CHAINLOG_IO;
        uint8_t stored[HASH], sent[SENT];
        if (!platform_private_file_read_at(f, stored, HASH, at + PRE + len))
            return ZCL_CHAINLOG_IO;
        if (!platform_private_file_read_at(f, sent, SENT,
                                           at + PRE + len + HASH))
            return ZCL_CHAINLOG_IO;

        if (!sentinel_ok(sent, at)) {
            /* Uncommitted. Only the LAST frame can be: a crash cannot commit
             * a frame after failing to commit an earlier one, so anything
             * else means the file was cut or spliced. */
            if (at + need != size) {
                rep->first_bad_seq = seq;
                return ZCL_CHAINLOG_UNCOMMITTED_GAP;
            }
            rep->torn_bytes = left;
            break;
        }

        uint8_t want[HASH];
        frame_hash(chain, prefix, scratch, len, want);
        if (memcmp(want, stored, HASH) != 0) {
            rep->first_bad_seq = seq;
            return ZCL_CHAINLOG_BROKEN_CHAIN;
        }
        if (seq != rep->records + 1) {
            rep->first_bad_seq = seq;
            return ZCL_CHAINLOG_SEQUENCE;
        }

        if (offset) {
            if (!offsets_reserve(offset, offset_cap, (size_t)rep->records + 1))
                return ZCL_CHAINLOG_IO;
            (*offset)[rep->records] = at;
        }
        memcpy(chain, stored, HASH);
        memcpy(rep->head, stored, HASH);
        rep->records++;
        at += need;
    }
    return ZCL_CHAINLOG_OK;
}

/* ── open / close ──────────────────────────────────────────────────── */

static void report_reset(struct zcl_chainlog_report *rep)
{
    memset(rep, 0, sizeof *rep);
}

struct zcl_chainlog *zcl_chainlog_open(const char *path,
                                       const uint8_t stream[32],
                                       struct zcl_chainlog_report *report)
{
    if (!report)
        return NULL;
    report_reset(report);
    if (!path || !stream) {
        report->status = ZCL_CHAINLOG_ARGUMENT;
        return NULL;
    }

    struct zcl_chainlog *log = zcl_calloc(1, sizeof *log, "chainlog");
    if (!log) {
        report->status = ZCL_CHAINLOG_IO;
        return NULL;
    }
    log->scratch = zcl_malloc(ZCL_CHAINLOG_PAYLOAD_MAX, "chainlog_scratch");
    if (!log->scratch) {
        free(log);
        report->status = ZCL_CHAINLOG_IO;
        return NULL;
    }
    platform_private_file_init(&log->file);
    memcpy(log->stream, stream, ZCL_CHAINLOG_STREAM_BYTES);

    if (!platform_private_file_open_locked_create_wait(path, &log->file)) {
        report->status = ZCL_CHAINLOG_IO;
        goto fail;
    }

    uint64_t size = 0;
    if (!platform_private_file_size(&log->file, &size)) {
        report->status = ZCL_CHAINLOG_IO;
        goto fail;
    }

    uint8_t hdr[HDR];
    if (size == 0) {
        header_build(hdr, stream);
        if (!platform_private_file_write_at(&log->file, hdr, HDR, 0) ||
            !platform_private_file_flush(&log->file)) {
            report->status = ZCL_CHAINLOG_IO;
            goto fail;
        }
        size = HDR;
    } else if (size < HDR) {
        report->status = ZCL_CHAINLOG_FORMAT;
        goto fail;
    } else if (!platform_private_file_read_at(&log->file, hdr, HDR, 0)) {
        report->status = ZCL_CHAINLOG_IO;
        goto fail;
    }

    enum zcl_chainlog_status st = header_check(hdr, stream);
    if (st != ZCL_CHAINLOG_OK) {
        report->status = st;
        goto fail;
    }
    sha3_of(hdr, HDR, log->seed);

    st = scan(&log->file, size, log->seed, log->scratch, report, &log->offset,
              &log->offset_cap);
    if (st != ZCL_CHAINLOG_OK) {
        report->status = st;
        goto fail;
    }

    /* The one place a chainlog ever shrinks, and it may only drop bytes no
     * sentinel ever committed. */
    if (report->torn_bytes) {
        uint64_t keep = size - report->torn_bytes;
        if (!platform_private_file_truncate(&log->file, keep) ||
            !platform_private_file_flush(&log->file)) {
            report->status = ZCL_CHAINLOG_IO;
            goto fail;
        }
        LOG_WARN("chainlog", "%s: discarded %llu uncommitted byte(s) after "
                             "%llu record(s)", path,
                 (unsigned long long)report->torn_bytes,
                 (unsigned long long)report->records);
        size = keep;
    }

    log->count = report->records;
    log->size = size;
    memcpy(log->head, report->head, HASH);
    report->status = ZCL_CHAINLOG_OK;
    return log;

fail:
    platform_private_file_close(&log->file);
    free(log->offset);
    free(log->scratch);
    free(log);
    return NULL;
}

void zcl_chainlog_close(struct zcl_chainlog *log)
{
    if (!log)
        return;
    platform_private_file_close(&log->file);
    free(log->offset);
    free(log->scratch);
    free(log);
}

/* ── append ────────────────────────────────────────────────────────── */

enum zcl_chainlog_status zcl_chainlog_append(struct zcl_chainlog *log,
                                             uint32_t kind,
                                             const void *payload, size_t len,
                                             uint64_t *out_seq,
                                             uint8_t out_chain[32])
{
    if (!log || (len && !payload) || len > ZCL_CHAINLOG_PAYLOAD_MAX)
        return ZCL_CHAINLOG_ARGUMENT;

    uint64_t seq = log->count + 1;
    uint8_t prefix[PRE];
    zcl_write_u32_be(prefix, kind);
    zcl_write_u64_be(prefix + 4, seq);
    zcl_write_u32_be(prefix + 12, (uint32_t)len);

    uint8_t chain[HASH];
    frame_hash(log->head, prefix, (const uint8_t *)payload, len, chain);

    if (!offsets_reserve(&log->offset, &log->offset_cap, (size_t)seq))
        return ZCL_CHAINLOG_IO;

    /* Phase 1: the frame, then fsync. Until the sentinel lands these bytes
     * are not history and a reopen will discard them. */
    uint64_t at = log->size;
    if (!platform_private_file_write_at(&log->file, prefix, PRE, at))
        return ZCL_CHAINLOG_IO;
    if (len &&
        !platform_private_file_write_at(&log->file, payload, len, at + PRE))
        return ZCL_CHAINLOG_IO;
    if (!platform_private_file_write_at(&log->file, chain, HASH, at + PRE + len))
        return ZCL_CHAINLOG_IO;
    if (!platform_private_file_flush(&log->file))
        return ZCL_CHAINLOG_IO;

    /* Phase 2: the commit sentinel, then fsync. */
    uint8_t sent[SENT];
    sentinel_build(sent, at);
    if (!platform_private_file_write_at(&log->file, sent, SENT,
                                        at + PRE + len + HASH))
        return ZCL_CHAINLOG_IO;
    if (!platform_private_file_flush(&log->file))
        return ZCL_CHAINLOG_IO;

    log->offset[seq - 1] = at;
    log->size = at + PRE + len + HASH + SENT;
    log->count = seq;
    memcpy(log->head, chain, HASH);
    if (out_seq)
        *out_seq = seq;
    if (out_chain)
        memcpy(out_chain, chain, HASH);
    return ZCL_CHAINLOG_OK;
}

/* ── read ──────────────────────────────────────────────────────────── */

enum zcl_chainlog_status zcl_chainlog_read(struct zcl_chainlog *log,
                                           uint64_t seq, uint32_t *kind,
                                           void *buf, size_t cap, size_t *len)
{
    if (!log || seq == 0 || !len)
        return ZCL_CHAINLOG_ARGUMENT;
    if (seq > log->count)
        return ZCL_CHAINLOG_NOT_FOUND;

    struct platform_private_file *f = &log->file;
    uint64_t at = log->offset[seq - 1];
    uint8_t prefix[PRE];
    if (!platform_private_file_read_at(f, prefix, PRE, at))
        return ZCL_CHAINLOG_IO;
    uint32_t plen = zcl_read_u32_be(prefix + 12);
    if (plen > ZCL_CHAINLOG_PAYLOAD_MAX)
        return ZCL_CHAINLOG_FORMAT;
    *len = plen;
    if (kind)
        *kind = zcl_read_u32_be(prefix);

    /* Re-verify on the way out. A reader that trusts the offset table it
     * built at open time cannot notice a file edited since. */
    uint8_t prev[HASH];
    if (seq == 1) {
        memcpy(prev, log->seed, HASH);
    } else if (!platform_private_file_read_at(
                   f, prev, HASH,
                   log->offset[seq - 1] - HASH - SENT)) {
        return ZCL_CHAINLOG_IO;
    }
    if (plen && !platform_private_file_read_at(f, log->scratch, plen, at + PRE))
        return ZCL_CHAINLOG_IO;
    uint8_t stored[HASH], want[HASH];
    if (!platform_private_file_read_at(f, stored, HASH, at + PRE + plen))
        return ZCL_CHAINLOG_IO;
    frame_hash(prev, prefix, log->scratch, plen, want);
    if (memcmp(want, stored, HASH) != 0)
        return ZCL_CHAINLOG_BROKEN_CHAIN;

    if (cap < plen)
        return ZCL_CHAINLOG_TRUNCATED;
    if (plen && buf)
        memcpy(buf, log->scratch, plen);
    return ZCL_CHAINLOG_OK;
}

uint64_t zcl_chainlog_count(const struct zcl_chainlog *log)
{
    return log ? log->count : 0;
}

bool zcl_chainlog_head(const struct zcl_chainlog *log, uint8_t out[32])
{
    if (!log || !out)
        return false;
    memcpy(out, log->head, HASH);
    return true;
}

/* ── verify ────────────────────────────────────────────────────────── */

enum zcl_chainlog_status zcl_chainlog_verify(const char *path,
                                             const uint8_t stream[32],
                                             struct zcl_chainlog_report *report)
{
    if (!report)
        return ZCL_CHAINLOG_ARGUMENT;
    report_reset(report);
    if (!path || !stream) {
        report->status = ZCL_CHAINLOG_ARGUMENT;
        return report->status;
    }

    uint8_t *scratch = zcl_malloc(ZCL_CHAINLOG_PAYLOAD_MAX, "chainlog_verify");
    if (!scratch) {
        report->status = ZCL_CHAINLOG_IO;
        return report->status;
    }
    struct platform_private_file f;
    platform_private_file_init(&f);
    if (!platform_private_file_open_locked_wait(path, &f)) {
        free(scratch);
        report->status = ZCL_CHAINLOG_IO;
        return report->status;
    }

    uint64_t size = 0;
    uint8_t hdr[HDR];
    if (!platform_private_file_size(&f, &size)) {
        report->status = ZCL_CHAINLOG_IO;
    } else if (size < HDR) {
        report->status = ZCL_CHAINLOG_FORMAT;
    } else if (!platform_private_file_read_at(&f, hdr, HDR, 0)) {
        report->status = ZCL_CHAINLOG_IO;
    } else {
        report->status = header_check(hdr, stream);
        if (report->status == ZCL_CHAINLOG_OK) {
            uint8_t seed[HASH];
            sha3_of(hdr, HDR, seed);
            report->status = scan(&f, size, seed, scratch, report, NULL, NULL);
        }
    }

    platform_private_file_close(&f);
    free(scratch);
    return report->status;
}
