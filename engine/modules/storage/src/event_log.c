/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * event_log — append-only event log implementation.
 *
 * See storage/event_log.h for the wire format, threading model, and
 * recovery contract.
 *
 * - Pure pwrite + fsync. The on-disk format is frozen, and the recovery
 *   scan is what keeps any future append backend safe.
 * - The CRC is Castagnoli (CRC-32C, polynomial 0x1EDC6F41), reflected
 *   form, init 0xFFFFFFFF, final xor 0xFFFFFFFF. The software table is
 *   the reference implementation; x86 hosts with SSE4.2 use hardware
 *   CRC32C after a startup self-check matches reference output.
 * - On open() the file is scanned from the tail to detect partial
 *   trailing writes (crash between header-fsync and sentinel-fsync, or
 *   sentinel write torn). Any partial event is TRUNCATED so the file
 *   only contains complete, durable events.
 *
 * - Mutex around append serializes writers; readers use pread and are
 *   safe under one appender + many readers because all writes are
 *   strictly append-only and durable before the offset is published. */

#include "storage/event_log.h"
#include "storage/event_log_pending.h"

#include "platform/private_file.h"
#include "platform/time_compat.h"   /* platform_time_monotonic_us */
#include "util/crc32c.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "crypto/sha3.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── on-disk constants ─────────────────────────────────────────────── */

#define EVT_HDR_LEN       16u    /* 4 + 4 + 4 + 4 */
#define EVT_SENTINEL_LEN  16u    /* 8 magic + 8 offset */

/* ── crc32c (Castagnoli) ────────────────────────────────────────────
 *
 * The implementation lives in platform/modules/util/src/crc32c.c so the event log and
 * the C23 LevelDB reader share one set of bytes. This file keeps only the
 * thin names it already used. */

#define crc32c(data, len)    zcl_crc32c((data), (len))
#define crc32c_sw(data, len) zcl_crc32c_sw((data), (len))

#ifdef ZCL_TESTING
const char *event_log_crc32c_impl(void)
{
    return zcl_crc32c_impl_name();
}

uint32_t event_log_crc32c_test_sw(const void *data, size_t len)
{
    return crc32c_sw(data, len);
}

uint32_t event_log_crc32c_test_active(const void *data, size_t len)
{
    return crc32c(data, len);
}

bool event_log_crc32c_hw_available(void)
{
    return zcl_crc32c_hw_available();
}
#endif

/* ── little-endian byte helpers ─────────────────────────────────────── */

static void put_u32_le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v        & 0xFF);
    dst[1] = (uint8_t)((v >> 8) & 0xFF);
    dst[2] = (uint8_t)((v >> 16) & 0xFF);
    dst[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t get_u32_le(const uint8_t *src)
{
    return (uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

static void put_u64_le(uint8_t *dst, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}

static uint64_t get_u64_le(const uint8_t *src)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)src[i] << (i * 8);
    return v;
}

/* ── struct ─────────────────────────────────────────────────────────── */

struct event_log {
    struct platform_private_file file;
    pthread_mutex_t lock;
    char path[1024];
    /* Byte offset for the next append (== file size); cached so append
     * doesn't have to fstat() each time. */
    uint64_t end_offset;
    /* Deferred durability: when set, event_log_append() skips its two
     * per-append fsync()s and only marks `dirty`; event_log_flush()
     * fdatasync()s once. Both under `lock`. See event_log.h. */
    bool deferred_sync;
    bool dirty;
    /* Deferred records are assembled here and published to readers only when
     * the complete span has been written at a batch boundary. */
    struct event_log_pending pending;
    /* Verified-prefix receipt bookkeeping (see "verified-prefix receipt"
     * below). `records`/`last_start`/`last_crc` describe the log up to and
     * including everything appended through this handle, buffered or not;
     * they are only published after a clean flush at close. `open_prefix_end`
     * is the prefix a receipt vouched for at open (0 after a full walk), the
     * span event_log_audit_prefix() re-proves. `receipt_poisoned` stops close
     * from re-vouching for a prefix an audit found damaged. */
    uint64_t records;
    uint64_t last_start;
    uint32_t last_crc;
    uint64_t open_prefix_end;
    _Atomic bool receipt_poisoned;
};

/* Append-path attribution (see event_log.h "Which append path did the fold
 * actually take?"). Process-wide, not per handle: the node opens exactly one
 * log and the question is about the process's fold, and a per-handle copy would
 * have to be read under the handle's own lock — which the append path holds
 * while it fsync()s, so an observer asking "how many barriers so far" would
 * block behind the very barrier it is measuring. Relaxed adds off the barrier
 * itself: three atomics next to two ext4 journal commits is noise. */
static _Atomic uint64_t g_barrier_appends;
static _Atomic uint64_t g_deferred_appends;
static _Atomic uint64_t g_barrier_us_total;

void event_log_append_stats(uint64_t *barrier_appends,
                            uint64_t *deferred_appends,
                            uint64_t *barrier_us_total)
{
    if (barrier_appends)
        *barrier_appends = atomic_load_explicit(&g_barrier_appends,
                                                memory_order_relaxed);
    if (deferred_appends)
        *deferred_appends = atomic_load_explicit(&g_deferred_appends,
                                                 memory_order_relaxed);
    if (barrier_us_total)
        *barrier_us_total = atomic_load_explicit(&g_barrier_us_total,
                                                 memory_order_relaxed);
}

/* Test override for the kill switch: -1 = consult env, 0 = off, 1 = forced.
 * Lets the unit test drive both branches deterministically (the env read is
 * cached below). Not touched by production code. */
static _Atomic int g_force_per_append_override = -1;

#ifdef ZCL_TESTING
/* Test seam: a nested fixture process that only proves runner plumbing can
 * skip the disk barriers so a saturated host disk cannot decide its verdict.
 * Off unless a test turns it on; production never touches it. */
static _Atomic int g_skip_barrier_for_test;
#endif

/* Kill switch: ZCL_EVENTLOG_SYNC_PER_APPEND=1 forces the per-append fsync even
 * while deferred mode is on (restores the pre-batch behavior for A/B). Read
 * once and cached — the env cannot change under a running process. */
static bool event_log_force_per_append_sync(void)
{
    int ov = atomic_load_explicit(&g_force_per_append_override,
                                  memory_order_relaxed);
    if (ov >= 0)
        return ov == 1;
    static _Atomic int cached = -1;
    int v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v < 0) {
        const char *e = getenv("ZCL_EVENTLOG_SYNC_PER_APPEND");
        v = (e && e[0] && e[0] != '0') ? 1 : 0;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    return v == 1;
}

/* ── pread/pwrite wrappers that retry short ops ─────────────────────── */

static int full_pread(struct platform_private_file *file, void *buf, size_t n,
                      uint64_t off)
{
    return platform_private_file_read_at(file, buf, n, off) ? 0 : -1;
}

static int full_pwrite(struct platform_private_file *file, const void *buf,
                       size_t n, uint64_t off)
{
    return platform_private_file_write_at(file, buf, n, off) ? 0 : -1;
}

/* ── recovery: validate the tail event, truncate if partial ─────────── */

/* One payload buffer shared by every record a walk verifies (the walk used to
 * malloc and free per event: 3.5M times on a production log). Grown on demand
 * to the largest payload seen, released once at the end of the walk. */
struct walk_scratch {
    uint8_t *buf;
    size_t   cap;
};

static bool walk_scratch_reserve(struct walk_scratch *s, size_t need)
{
    if (need <= s->cap)
        return true;
    size_t ncap = s->cap ? s->cap : 65536u;
    while (ncap < need)
        ncap *= 2;               /* need <= EVENT_LOG_MAX_PAYLOAD: no wrap */
    uint8_t *nbuf = (uint8_t *)zcl_realloc(s->buf, ncap, "event_log/recover");
    if (!nbuf)
        return false;
    s->buf = nbuf;
    s->cap = ncap;
    return true;
}

/* Verify the record framed at `cursor` inside [0, size): bounded length,
 * complete frame, sentinel magic plus its own start offset, payload CRC. The
 * checks and their order are the original recovery walk's, so the walked
 * region truncates at exactly the same point. On success *need_out is the
 * whole frame length and *crc_out the payload CRC. */
static bool verify_record_at(struct platform_private_file *file,
                             uint64_t cursor, uint64_t size,
                             struct walk_scratch *scratch,
                             uint64_t *need_out, uint32_t *crc_out)
{
    uint8_t hdr[EVT_HDR_LEN];
    if (full_pread(file, hdr, EVT_HDR_LEN, cursor) < 0)
        return false;
    uint32_t plen = get_u32_le(hdr + 0);

    /* Defensive bound — anything pathological → truncate. */
    if (plen > EVENT_LOG_MAX_PAYLOAD)
        return false;

    uint64_t need = (uint64_t)EVT_HDR_LEN + plen + EVT_SENTINEL_LEN;
    if (cursor + need > size)
        return false;

    /* Validate sentinel. */
    uint8_t sent[EVT_SENTINEL_LEN];
    if (full_pread(file, sent, EVT_SENTINEL_LEN,
                   cursor + EVT_HDR_LEN + plen) < 0)
        return false;
    if (get_u64_le(sent + 0) != EVENT_LOG_SENTINEL_MAGIC ||
        get_u64_le(sent + 8) != cursor)
        return false;

    /* Validate CRC over the payload. */
    uint32_t crc_disk = get_u32_le(hdr + 12);
    const uint8_t *payload = NULL;
    if (plen > 0) {
        if (!walk_scratch_reserve(scratch, plen))
            return false;
        if (full_pread(file, scratch->buf, plen, cursor + EVT_HDR_LEN) < 0)
            return false;
        payload = scratch->buf;
    }
    if (crc_disk != crc32c(payload, plen))
        return false;

    *need_out = need;
    *crc_out  = crc_disk;
    return true;
}

/* ── verified-prefix receipt ────────────────────────────────────────────
 *
 * The walk above is O(file): 20 s on a 1.4 GB log, paid on every boot. A clean
 * close therefore leaves a sidecar `<log>.verified` that vouches for the
 * prefix [0, verified_end); the next open re-verifies only the one record that
 * ends at verified_end and walks from there. The receipt is an optimisation of
 * WHERE the walk starts, never a different judgement of the bytes after it.
 *
 * Fixed 96-byte little-endian layout:
 *    0  magic "ZCLEVRCP"      8  version (1)      12  reserved (0)
 *   16  verified_end          24  records         32  st_dev
 *   40  st_ino                48  last_start      56  last_crc  60 reserved
 *   64  SHA3-256 over bytes [0,64)
 *
 * Safety rules, enforced below:
 *   - written only at a clean close, after a durability barrier, so it never
 *     names bytes that are not on disk; tmp + fsync + rename + dir fsync;
 *   - unlinked (and the directory fsynced) before ANY truncate, so no crash
 *     window can leave a receipt claiming bytes the file no longer has;
 *   - any mismatch (checksum, identity, size, last record) falls back to the
 *     full walk and drops the stale sidecar.
 * The prefix itself is re-proved off the boot path by event_log_audit_prefix(). */
#define RCPT_LEN      96u
#define RCPT_BODY_LEN 64u
#define RCPT_VERSION  1u
#define RCPT_SUFFIX   ".verified"
#define RCPT_TMP_SUFFIX ".verified.tmp"

struct receipt {
    uint64_t verified_end;
    uint64_t records;
    uint64_t dev;
    uint64_t ino;
    uint64_t last_start;
    uint32_t last_crc;
};

static bool receipt_path(const char *log_path, const char *suffix,
                         char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s", log_path, suffix);
    return n > 0 && (size_t)n < cap;
}

static void receipt_encode(const struct receipt *r, uint8_t out[RCPT_LEN])
{
    memset(out, 0, RCPT_LEN);
    memcpy(out, "ZCLEVRCP", 8);
    put_u32_le(out + 8, RCPT_VERSION);
    put_u64_le(out + 16, r->verified_end);
    put_u64_le(out + 24, r->records);
    put_u64_le(out + 32, r->dev);
    put_u64_le(out + 40, r->ino);
    put_u64_le(out + 48, r->last_start);
    put_u32_le(out + 56, r->last_crc);
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, out, RCPT_BODY_LEN);
    sha3_256_finalize(&h, out + RCPT_BODY_LEN);
}

static bool receipt_decode(const uint8_t in[RCPT_LEN], struct receipt *r)
{
    if (memcmp(in, "ZCLEVRCP", 8) != 0 || get_u32_le(in + 8) != RCPT_VERSION)
        return false;
    uint8_t want[32];
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, in, RCPT_BODY_LEN);
    sha3_256_finalize(&h, want);
    if (memcmp(want, in + RCPT_BODY_LEN, sizeof(want)) != 0)
        return false;
    r->verified_end = get_u64_le(in + 16);
    r->records      = get_u64_le(in + 24);
    r->dev          = get_u64_le(in + 32);
    r->ino          = get_u64_le(in + 40);
    r->last_start   = get_u64_le(in + 48);
    r->last_crc     = get_u32_le(in + 56);
    return true;
}

/* fsync the directory that holds `log_path` so a rename or unlink of a
 * sidecar next to it is itself durable. */
static bool receipt_parent_flush(const char *log_path)
{
    char dir[1100];
    int n = snprintf(dir, sizeof(dir), "%s", log_path);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return false;
    char *slash = strrchr(dir, '/');
    if (!slash)
        snprintf(dir, sizeof(dir), ".");
    else if (slash == dir)
        slash[1] = '\0';
    else
        *slash = '\0';
    return platform_private_parent_flush(dir);
}

/* Drop the sidecar durably. True when it is gone (or never existed). */
static bool receipt_remove(const char *log_path)
{
    char side[1100];
    if (!receipt_path(log_path, RCPT_SUFFIX, side, sizeof(side)))
        return false;
    if (platform_private_path_absent(side))
        return true;
    if (!platform_private_file_unlink_missing_ok(side)) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] unlink(%s) failed: %s\n", side, strerror(errno));
        return false;
    }
    if (!receipt_parent_flush(log_path)) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] fsync of directory holding %s failed: %s\n",
                side, strerror(errno));
        return false;
    }
    return true;
}

static bool receipt_read(const char *side, struct receipt *r)
{
    struct platform_private_file f;
    platform_private_file_init(&f);
    if (!platform_private_file_open_observation(side, &f))
        return false;
    uint64_t sz = 0;
    uint8_t raw[RCPT_LEN];
    bool ok = platform_private_file_size(&f, &sz) && sz == RCPT_LEN &&
              full_pread(&f, raw, RCPT_LEN, 0) == 0 &&
              receipt_decode(raw, r);
    platform_private_file_close(&f);
    return ok;
}

/* Does the receipt still describe `file`? Identity, size, and a fresh
 * re-verification of the one record that ends exactly at verified_end. */
static bool receipt_matches(struct platform_private_file *file, uint64_t size,
                            const struct receipt *r,
                            struct walk_scratch *scratch)
{
    struct platform_private_file_identity id;
    if (!platform_private_file_identity(file, &id) ||
        id.volume != r->dev || id.file != r->ino)
        return false;
    if (r->records == 0 || r->verified_end > size ||
        r->verified_end < (uint64_t)EVT_HDR_LEN + EVT_SENTINEL_LEN ||
        r->last_start >= r->verified_end)
        return false;
    uint64_t need = 0;
    uint32_t crc = 0;
    if (!verify_record_at(file, r->last_start, r->verified_end, scratch,
                          &need, &crc))
        return false;
    return r->last_start + need == r->verified_end && crc == r->last_crc;
}

/* Load and validate the sidecar for `log_path`. A sidecar that exists but does
 * not validate is removed so it cannot match a recycled inode later. */
static bool receipt_try(struct platform_private_file *file, const char *log_path,
                        uint64_t size, struct walk_scratch *scratch,
                        struct receipt *r)
{
    char side[1100];
    if (!receipt_path(log_path, RCPT_SUFFIX, side, sizeof(side)) ||
        platform_private_path_absent(side))
        return false;
    if (receipt_read(side, r) && receipt_matches(file, size, r, scratch))
        return true;
    fprintf(stderr,  // obs-ok:event-log-lifecycle
            "[event_log] stale or invalid receipt %s: full recovery walk\n",
            side);
    (void)receipt_remove(log_path);
    return false;
}

/* Publish the receipt: tmp + fsync + rename + dir fsync. Best effort — a
 * failure leaves the previous receipt (still a true statement about an older
 * prefix of the same file) or none, and the next open walks. */
static void receipt_publish(event_log_t *log)
{
    struct platform_private_file_identity id;
    char side[1100], tmp[1100];
    if (!receipt_path(log->path, RCPT_SUFFIX, side, sizeof(side)) ||
        !receipt_path(log->path, RCPT_TMP_SUFFIX, tmp, sizeof(tmp)) ||
        !platform_private_file_identity(&log->file, &id))
        return;
    struct receipt r = {
        .verified_end = log->end_offset, .records = log->records,
        .dev = id.volume, .ino = id.file,
        .last_start = log->last_start, .last_crc = log->last_crc,
    };
    uint8_t raw[RCPT_LEN];
    receipt_encode(&r, raw);

    (void)platform_private_file_unlink_missing_ok(tmp);
    struct platform_private_file f;
    platform_private_file_init(&f);
    if (!platform_private_file_create(tmp, &f)) {
        fprintf(stderr,  // obs-ok:event-log-lifecycle
                "[event_log] receipt create(%s) failed: %s\n",
                tmp, strerror(errno));
        return;
    }
    if (full_pwrite(&f, raw, RCPT_LEN, 0) < 0 ||
        !platform_private_file_flush(&f) ||
        !platform_private_file_replace(&f, tmp, side) ||
        !receipt_parent_flush(log->path)) {
        fprintf(stderr,  // obs-ok:event-log-lifecycle
                "[event_log] receipt publish(%s) failed: %s\n",
                side, strerror(errno));
        platform_private_file_close(&f);
        (void)platform_private_file_unlink_missing_ok(tmp);
    }
}

/* What the last event_log_open() did, for tests and the boot log: how many
 * bytes the recovery walk actually covered and whether a receipt was used. */
static _Atomic uint64_t g_last_open_walked = 0;
static _Atomic int      g_last_open_receipt = 0;

struct recover_out {
    uint64_t end;
    uint64_t records;
    uint64_t last_start;
    uint32_t last_crc;
    uint64_t prefix_end;   /* receipt-vouched prefix, 0 after a full walk */
};

/* Walk forward from the start (or from a validated receipt), tracking the last
 * KNOWN-good end offset; anything past that is partial and gets truncated.
 * Returns false on a hard error. */
static bool recover_truncate_partial(struct platform_private_file *file,
                                     const char *path,
                                     struct recover_out *out)
{
    uint64_t size = 0;
    if (!platform_private_file_size(file, &size) || size > INT64_MAX) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] fstat(%s) failed: %s\n",
                path, strerror(errno));
        return false;
    }

    struct walk_scratch scratch = {0};
    uint64_t cursor = 0;
    uint64_t last_good_end = 0;
    memset(out, 0, sizeof(*out));

    struct receipt r;
    if (receipt_try(file, path, size, &scratch, &r)) {
        cursor = last_good_end = r.verified_end;
        out->records    = r.records;
        out->last_start = r.last_start;
        out->last_crc   = r.last_crc;
        out->prefix_end = r.verified_end;
    }
    const uint64_t walk_from = cursor;

    while (cursor + EVT_HDR_LEN + EVT_SENTINEL_LEN <= size) {
        uint64_t need = 0;
        uint32_t crc = 0;
        if (!verify_record_at(file, cursor, size, &scratch, &need, &crc))
            break;

        /* Event is well-formed and durable. */
        out->last_start = cursor;
        out->last_crc   = crc;
        out->records++;
        cursor       += need;
        last_good_end = cursor;
    }
    free(scratch.buf);

    atomic_store_explicit(&g_last_open_walked, cursor - walk_from,
                          memory_order_relaxed);
    atomic_store_explicit(&g_last_open_receipt, out->prefix_end != 0,
                          memory_order_relaxed);
    if (out->prefix_end) {
        fprintf(stderr,  // obs-ok:event-log-lifecycle
                "[event_log] receipt accepted: skipped %llu verified bytes, "
                "walked %llu (%s)\n",
                (unsigned long long)out->prefix_end,
                (unsigned long long)(cursor - walk_from), path);
    }

    if (last_good_end < size) {
        fprintf(stderr,  // obs-ok:event-log-lifecycle
                "[event_log] truncating partial tail: %llu -> %llu (%s)\n",
                (unsigned long long)size,
                (unsigned long long)last_good_end, path);
        /* The receipt must never outlive the bytes it vouches for: drop it,
         * durably, BEFORE the file shrinks. Fail closed if it cannot go. */
        if (!receipt_remove(path)) {
            fprintf(stderr,  // obs-ok:event-log-open-failure
                    "[event_log] refusing to truncate %s: receipt not removed\n",
                    path);
            return false;
        }
        if (!platform_private_file_truncate(file, last_good_end)) {
            fprintf(stderr,  // obs-ok:event-log-open-failure
                    "[event_log] ftruncate(%s) failed: %s\n",
                    path, strerror(errno));
            return false;
        }
        /* Make the truncation durable before publishing the handle. */
        if (!platform_private_file_flush(file)) {
            fprintf(stderr,  // obs-ok:event-log-open-failure
                    "[event_log] fsync after truncate(%s) failed: %s\n",
                    path, strerror(errno));
            return false;
        }
    }
    out->end = last_good_end;
    return true;
}

/* ── public API ─────────────────────────────────────────────────────── */

event_log_t *event_log_open(const char *path)
{
    if (!path || !path[0])
        LOG_NULL("event_log", "open: empty path");

    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked_create(path, &file)) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] open(%s) failed: %s\n",
                path, strerror(errno));
        return NULL;
    }

    struct recover_out rec;
    if (!recover_truncate_partial(&file, path, &rec)) {
        platform_private_file_close(&file);
        return NULL;
    }
    int64_t end = (int64_t)rec.end;

    event_log_t *log = (event_log_t *)zcl_malloc(sizeof(*log),
                                                  "event_log/handle");
    if (!log) {
        platform_private_file_close(&file);
        return NULL;
    }
    log->file = file;
    pthread_mutex_init(&log->lock, NULL);
    snprintf(log->path, sizeof(log->path), "%s", path);
    log->end_offset = (uint64_t)end;
    log->deferred_sync = false;
    log->dirty = false;
    log->pending = (struct event_log_pending){0};
    log->records = rec.records;
    log->last_start = rec.last_start;
    log->last_crc = rec.last_crc;
    log->open_prefix_end = rec.prefix_end;
    atomic_init(&log->receipt_poisoned, false);

    fprintf(stderr,  // obs-ok:event-log-lifecycle
            "[event_log] opened %s (size=%llu)\n",
            path, (unsigned long long)log->end_offset);
    return log;
}

void event_log_close(event_log_t *log)
{
    if (!log) return;
    /* Best-effort flush also publishes any deferred in-memory span. */
    bool flushed = event_log_flush(log);
    if (atomic_load_explicit(&log->receipt_poisoned, memory_order_relaxed)) {
        /* An audit found the vouched prefix damaged: never vouch again. */
        (void)receipt_remove(log->path);
    } else if (flushed && !log->dirty && log->pending.len == 0 &&
               log->records > 0 && log->end_offset > 0) {
        /* The receipt may only name bytes that are on disk. event_log_flush()
         * is a no-op when nothing is dirty, but bytes this handle inherited at
         * open (a previous process killed before its own fsync) were never
         * barriered by us, so take one explicit barrier first. */
        if (platform_private_file_flush(&log->file))
            receipt_publish(log);
    }
    platform_private_file_close(&log->file);
    event_log_pending_destroy(&log->pending);
    pthread_mutex_destroy(&log->lock);
    free(log);
}

/* One durability barrier, timed. The clock pair is the whole point: this is the
 * syscall the fold parks in (jbd2_log_wait_commit), and without a number here
 * the per-call-site totals cannot separate barrier wait from anything else.
 * Returns fsync()'s own result unchanged — the time is accumulated on the
 * failure path too, since a barrier that failed still cost its wait. */
static int event_log_barrier(struct platform_private_file *file)
{
#ifdef ZCL_TESTING
    if (atomic_load_explicit(&g_skip_barrier_for_test, memory_order_relaxed))
        return 0;
#endif
    int64_t t0 = platform_time_monotonic_us();
    int rc = platform_private_file_flush(file) ? 0 : -1;
    int64_t dt = platform_time_monotonic_us() - t0;
    atomic_fetch_add_explicit(&g_barrier_us_total,
                              dt > 0 ? (uint64_t)dt : 0u,
                              memory_order_relaxed);
    return rc;
}

static bool event_log_write_pending_locked(event_log_t *log)
{
    return log && event_log_pending_write(&log->pending, &log->file,
                                           &log->end_offset);
}

uint64_t event_log_append(event_log_t *log,
                          enum event_log_type type,
                          const void *payload, size_t payload_len)
{
    if (!log) return UINT64_MAX;
    if (payload_len > 0 && !payload) return UINT64_MAX;
    if (payload_len > EVENT_LOG_MAX_PAYLOAD) {
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] append rejected: payload_len=%zu > max=%zu\n",
                payload_len, EVENT_LOG_MAX_PAYLOAD);
        return UINT64_MAX;
    }

    pthread_mutex_lock(&log->lock);
    uint64_t start = log->end_offset + (uint64_t)log->pending.len;
    /* Deferred mode skips BOTH per-append fsync()s (batched to a later
     * event_log_flush()), unless the kill switch forces per-append sync. */
    bool defer = log->deferred_sync && !event_log_force_per_append_sync();

    /* Build header. */
    uint8_t hdr[EVT_HDR_LEN];
    put_u32_le(hdr + 0,  (uint32_t)payload_len);
    put_u32_le(hdr + 4,  (uint32_t)type);
    put_u32_le(hdr + 8,  0u);
    uint32_t crc = crc32c(payload, payload_len);
    put_u32_le(hdr + 12, crc);

    uint8_t sent[EVT_SENTINEL_LEN];
    put_u64_le(sent + 0, EVENT_LOG_SENTINEL_MAGIC);
    put_u64_le(sent + 8, start);

    if (defer) {
        size_t event_len = EVT_HDR_LEN + payload_len + EVT_SENTINEL_LEN;
        if (!event_log_pending_prepare(&log->pending, event_len, &log->file,
                                       &log->end_offset)) {
            pthread_mutex_unlock(&log->lock);
            return UINT64_MAX;
        }
        uint8_t *dst = log->pending.data + log->pending.len;
        memcpy(dst, hdr, EVT_HDR_LEN);
        if (payload_len > 0)
            memcpy(dst + EVT_HDR_LEN, payload, payload_len);
        memcpy(dst + EVT_HDR_LEN + payload_len, sent, EVT_SENTINEL_LEN);
        log->pending.len += event_len;
        log->records++;
        log->last_start = start;
        log->last_crc = crc;
        log->dirty = true;
        pthread_mutex_unlock(&log->lock);
        atomic_fetch_add_explicit(&g_deferred_appends, 1u,
                                  memory_order_relaxed);
        return start;
    }
    /* From here the append pays the two-barrier price. Counted BEFORE the
     * first pwrite so an append that dies inside a barrier still shows up as
     * one that took this path — an uncounted failure would understate exactly
     * the cost being attributed. */
    atomic_fetch_add_explicit(&g_barrier_appends, 1u, memory_order_relaxed);

    /* A caller that disabled deferred mode without flushing cannot overtake
     * older buffered records. The immediate fsyncs below cover both spans. */
    if (!event_log_write_pending_locked(log)) {
        pthread_mutex_unlock(&log->lock);
        return UINT64_MAX;
    }
    start = log->end_offset;
    put_u64_le(sent + 8, start);

    /* Durable body write: header + payload. */
    if (full_pwrite(&log->file, hdr, EVT_HDR_LEN, start) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] pwrite(hdr) failed at off=%llu: %s\n",
                (unsigned long long)start, strerror(errno));
        return UINT64_MAX;
    }
    if (payload_len > 0) {
        if (full_pwrite(&log->file, payload, payload_len,
                        start + EVT_HDR_LEN) < 0) {
            pthread_mutex_unlock(&log->lock);
            fprintf(stderr,  // obs-ok:event-log-append-failure
                    "[event_log] pwrite(payload) failed at off=%llu: %s\n",
                    (unsigned long long)(start + EVT_HDR_LEN),
                    strerror(errno));
            return UINT64_MAX;
        }
    }
    if (event_log_barrier(&log->file) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] fsync(hdr+payload) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }

    /* Durable completion marker: sentinel. */
    if (full_pwrite(&log->file, sent, EVT_SENTINEL_LEN,
                    start + EVT_HDR_LEN + payload_len) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] pwrite(sentinel) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }
    if (event_log_barrier(&log->file) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] fsync(sentinel) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }

    log->end_offset = start + EVT_HDR_LEN + payload_len + EVT_SENTINEL_LEN;
    log->records++;
    log->last_start = start;
    log->last_crc = crc;
    pthread_mutex_unlock(&log->lock);
    return start;
}

void event_log_set_deferred_sync(event_log_t *log, bool enabled)
{
    if (!log) return;
    pthread_mutex_lock(&log->lock);
    log->deferred_sync = enabled;
    pthread_mutex_unlock(&log->lock);
}

bool event_log_deferred_sync_enabled(event_log_t *log)
{
    if (!log) return false;
    pthread_mutex_lock(&log->lock);
    bool v = log->deferred_sync;
    pthread_mutex_unlock(&log->lock);
    return v;
}

bool event_log_flush(event_log_t *log)
{
    if (!log) return true;
    pthread_mutex_lock(&log->lock);
    if (!log->dirty) {
        pthread_mutex_unlock(&log->lock);
        return true;
    }
    if (!event_log_write_pending_locked(log)) {
        pthread_mutex_unlock(&log->lock);
        LOG_FAIL("event_log", "flush: pwrite(%s) failed: %s",
                 log->path, strerror(errno));
    }
    if (!platform_private_file_flush(&log->file)) {
        /* Keep `dirty` set so a retry re-attempts the fdatasync; the caller
         * (the stage pre-commit hook) must veto the commit on this false. */
        pthread_mutex_unlock(&log->lock);
        LOG_FAIL("event_log", "flush: fdatasync(%s) failed: %s",
                 log->path, strerror(errno));
    }
    log->dirty = false;
    pthread_mutex_unlock(&log->lock);
    return true;
}

int event_log_read(event_log_t *log, uint64_t offset,
                   enum event_log_type *type_out,
                   void *buf, size_t buf_cap, size_t *out_len)
{
    if (!log) return -1;
    /* Atomically snapshot the current end_offset for bounds checks. */
    pthread_mutex_lock(&log->lock);
    uint64_t end = log->end_offset;
    pthread_mutex_unlock(&log->lock);

    if (offset + EVT_HDR_LEN > end) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: offset %llu past end %llu\n",
                (unsigned long long)offset, (unsigned long long)end);
        return -1;
    }
    uint8_t hdr[EVT_HDR_LEN];
    if (full_pread(&log->file, hdr, EVT_HDR_LEN, offset) < 0) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: pread(hdr) at off=%llu: %s\n",
                (unsigned long long)offset, strerror(errno));
        return -1;
    }
    uint32_t plen  = get_u32_le(hdr + 0);
    uint32_t type  = get_u32_le(hdr + 4);
    uint32_t crc_d = get_u32_le(hdr + 12);
    if (plen > EVENT_LOG_MAX_PAYLOAD) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: corrupt plen=%u at off=%llu\n",
                plen, (unsigned long long)offset);
        return -1;
    }
    if (offset + EVT_HDR_LEN + plen + EVT_SENTINEL_LEN > end) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: event extends past end at off=%llu\n",
                (unsigned long long)offset);
        return -1;
    }

    if (out_len) *out_len = plen;
    if (type_out) *type_out = (enum event_log_type)type;

    if (plen > 0) {
        /* Read into caller buf if it fits; otherwise fail (caller must
         * pre-size). Use a temp buffer so we can always validate CRC. */
        uint8_t *tmp = (uint8_t *)zcl_malloc(plen, "event_log/read");
        if (!tmp) return -1;
        if (full_pread(&log->file, tmp, plen, offset + EVT_HDR_LEN) < 0) {
            free(tmp);
            return -1;
        }
        uint32_t crc_c = crc32c(tmp, plen);
        if (crc_c != crc_d) {
            free(tmp);
            fprintf(stderr,  // obs-ok:event-log-read-failure
                    "[event_log] read: CRC mismatch at off=%llu\n",
                    (unsigned long long)offset);
            return -1;
        }
        if (buf_cap < plen) {
            free(tmp);
            return -1;
        }
        if (buf) memcpy(buf, tmp, plen);
        free(tmp);
    } else {
        /* Empty-payload event — still validate sentinel below. */
    }

    /* Validate sentinel. */
    uint8_t sent[EVT_SENTINEL_LEN];
    if (full_pread(&log->file, sent, EVT_SENTINEL_LEN,
                   offset + EVT_HDR_LEN + plen) < 0) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: sentinel pread at off=%llu\n",
                (unsigned long long)offset);
        return -1;
    }
    uint64_t magic = get_u64_le(sent + 0);
    uint64_t soff  = get_u64_le(sent + 8);
    if (magic != EVENT_LOG_SENTINEL_MAGIC || soff != offset) {
        fprintf(stderr,  // obs-ok:event-log-read-failure
                "[event_log] read: bad sentinel at off=%llu\n",
                (unsigned long long)offset);
        return -1;
    }
    return 0;
}

int event_log_stream(event_log_t *log, uint64_t start_offset,
                     event_log_cb cb, void *user)
{
    if (!log || !cb) return -1;
    pthread_mutex_lock(&log->lock);
    uint64_t end = log->end_offset;
    pthread_mutex_unlock(&log->lock);

    uint64_t cursor = start_offset;
    /* Use a growable scratch buffer to avoid re-allocing per event. */
    size_t cap = 4096;
    uint8_t *buf = (uint8_t *)zcl_malloc(cap, "event_log/stream");
    if (!buf) return -1;

    while (cursor + EVT_HDR_LEN + EVT_SENTINEL_LEN <= end) {
        uint8_t hdr[EVT_HDR_LEN];
        if (full_pread(&log->file, hdr, EVT_HDR_LEN, cursor) < 0) {
            free(buf);
            return -1;
        }
        uint32_t plen = get_u32_le(hdr + 0);
        uint32_t type = get_u32_le(hdr + 4);
        uint32_t crcd = get_u32_le(hdr + 12);
        if (plen > EVENT_LOG_MAX_PAYLOAD) {
            free(buf);
            return -1;
        }
        if (cursor + EVT_HDR_LEN + plen + EVT_SENTINEL_LEN > end) {
            free(buf);
            return -1;
        }

        if (plen > cap) {
            size_t ncap = cap;
            while (ncap < plen) ncap *= 2;
            uint8_t *nbuf = (uint8_t *)realloc(buf, ncap);  // raw-alloc-ok:event-log-scratch-grow
            if (!nbuf) {
                free(buf);
                return -1;
            }
            buf = nbuf;
            cap = ncap;
        }
        if (plen > 0) {
            if (full_pread(&log->file, buf, plen,
                           cursor + EVT_HDR_LEN) < 0) {
                free(buf);
                return -1;
            }
            uint32_t crcc = crc32c(buf, plen);
            if (crcc != crcd) {
                free(buf);
                return -1;
            }
        }
        /* Sentinel validation (cheap, catches in-flight corruption). */
        uint8_t sent[EVT_SENTINEL_LEN];
        if (full_pread(&log->file, sent, EVT_SENTINEL_LEN,
                       cursor + EVT_HDR_LEN + plen) < 0) {
            free(buf);
            return -1;
        }
        if (get_u64_le(sent + 0) != EVENT_LOG_SENTINEL_MAGIC ||
            get_u64_le(sent + 8) != cursor) {
            free(buf);
            return -1;
        }

        bool keep = cb(cursor, (enum event_log_type)type,
                       plen > 0 ? buf : NULL, plen, user);
        cursor += EVT_HDR_LEN + plen + EVT_SENTINEL_LEN;
        if (!keep) break;
    }
    free(buf);
    return 0;
}

struct fp_ctx { struct sha3_256_ctx h; };

static bool fp_cb(uint64_t offset, enum event_log_type type,
                  const void *payload, size_t len, void *user)
{
    (void)offset; (void)type;
    struct fp_ctx *c = (struct fp_ctx *)user;
    if (len > 0 && payload)
        sha3_256_write(&c->h, (const unsigned char *)payload, len);
    return true;
}

int event_log_fingerprint(event_log_t *log, uint8_t out[32])
{
    if (!log || !out) return -1;
    struct fp_ctx c;
    sha3_256_init(&c.h);
    if (event_log_stream(log, 0, fp_cb, &c) < 0) return -1;
    sha3_256_finalize(&c.h, out);
    return 0;
}

uint64_t event_log_size(event_log_t *log)
{
    if (!log) return 0;
    pthread_mutex_lock(&log->lock);
    uint64_t s = log->end_offset;
    pthread_mutex_unlock(&log->lock);
    return s;
}

/* Records between should_stop polls: ~4096 frames is a few MiB of log, so a
 * shutdown request is honoured within milliseconds. */
#define AUDIT_POLL_RECORDS 4096u

int event_log_audit_prefix(event_log_t *log, bool (*should_stop)(void),
                           uint64_t *audited_bytes)
{
    if (audited_bytes)
        *audited_bytes = 0;
    if (!log)
        return -1;
    /* Immutable after open, so no lock: appends never touch [0, end). */
    const uint64_t end = log->open_prefix_end;
    if (end == 0)
        return 0;   /* open walked everything itself: nothing was skipped */

    struct walk_scratch scratch = {0};
    uint64_t cursor = 0;
    uint64_t n = 0;
    int rc = 0;
    while (cursor < end) {
        uint64_t need = 0;
        uint32_t crc = 0;
        /* Reads only: the handle's descriptor is used for pread, never
         * written, and nothing here can truncate. */
        if (!verify_record_at(&log->file, cursor, end, &scratch, &need, &crc)) {
            fprintf(stderr,  // obs-ok:event-log-audit-failure
                    "[event_log] AUDIT FAILED: record at off=%llu inside the "
                    "receipt-vouched prefix [0,%llu) is damaged (%s); dropping "
                    "the receipt so the next boot does the full walk\n",
                    (unsigned long long)cursor, (unsigned long long)end,
                    log->path);
            rc = -1;
            break;
        }
        cursor += need;
        if ((++n % AUDIT_POLL_RECORDS) == 0 && should_stop && should_stop()) {
            rc = 1;
            break;
        }
    }
    free(scratch.buf);
    if (audited_bytes)
        *audited_bytes = cursor;
    if (rc == 0 && cursor != end) {
        fprintf(stderr,  // obs-ok:event-log-audit-failure
                "[event_log] AUDIT FAILED: records end at %llu, receipt "
                "claimed %llu (%s)\n", (unsigned long long)cursor,
                (unsigned long long)end, log->path);
        rc = -1;
    }
    if (rc < 0) {
        atomic_store_explicit(&log->receipt_poisoned, true,
                              memory_order_relaxed);
        (void)receipt_remove(log->path);
    }
    return rc;
}

#ifdef ZCL_TESTING
uint64_t event_log_test_last_open_walked_bytes(void)
{
    return atomic_load_explicit(&g_last_open_walked, memory_order_relaxed);
}

bool event_log_test_last_open_used_receipt(void)
{
    return atomic_load_explicit(&g_last_open_receipt, memory_order_relaxed) != 0;
}
#endif

#ifdef ZCL_TESTING
/* Deferred-mode test hooks. Defined here (after `struct event_log` and
 * g_force_per_append_override are complete) so they can touch the fields. */
bool event_log_test_dirty(event_log_t *log)
{
    if (!log) return false;
    pthread_mutex_lock(&log->lock);
    bool v = log->dirty;
    pthread_mutex_unlock(&log->lock);
    return v;
}

void event_log_test_reset_append_stats(void)
{
    atomic_store_explicit(&g_barrier_appends, 0u, memory_order_relaxed);
    atomic_store_explicit(&g_deferred_appends, 0u, memory_order_relaxed);
    atomic_store_explicit(&g_barrier_us_total, 0u, memory_order_relaxed);
}

void event_log_skip_barriers_for_test(bool skip)
{
    atomic_store_explicit(&g_skip_barrier_for_test, skip ? 1 : 0,
                          memory_order_relaxed);
}

void event_log_test_set_force_per_append(int v)
{
    atomic_store_explicit(&g_force_per_append_override, v,
                          memory_order_relaxed);
}

int event_log_test_fd(event_log_t *log)
{
#ifdef _WIN32
    (void)log;
    return -1;
#else
    return log ? (int)log->file.native : -1;
#endif
}

void event_log_test_set_fd(event_log_t *log, int fd)
{
#ifdef _WIN32
    (void)log;
    (void)fd;
#else
    if (log) log->file.native = (uintptr_t)fd;
#endif
}
#endif
