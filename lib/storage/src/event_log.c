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

#include "platform/time_compat.h"   /* platform_time_monotonic_us */
#include "platform/file_sync.h"
#include "util/crc32c.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "crypto/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── on-disk constants ─────────────────────────────────────────────── */

#define EVT_HDR_LEN       16u    /* 4 + 4 + 4 + 4 */
#define EVT_SENTINEL_LEN  16u    /* 8 magic + 8 offset */

/* ── crc32c (Castagnoli) ────────────────────────────────────────────
 *
 * The implementation lives in lib/util/src/crc32c.c so the event log and
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
    int fd;
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

static int full_pread(int fd, void *buf, size_t n, off_t off)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = pread(fd, p, n, off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;  /* short read at EOF */
        p += (size_t)r;
        off += r;
        n   -= (size_t)r;
    }
    return 0;
}

static int full_pwrite(int fd, const void *buf, size_t n, off_t off)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = pwrite(fd, p, n, off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += (size_t)w;
        off += w;
        n   -= (size_t)w;
    }
    return 0;
}

/* ── recovery: validate the tail event, truncate if partial ─────────── */

/* Returns the post-recovery file size (>= 0) or -1 on hard error. */
static int64_t recover_truncate_partial(int fd, const char *path)
{
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] fstat(%s) failed: %s\n",
                path, strerror(errno));
        return -1;
    }
    uint64_t size = (uint64_t)st.st_size;

    /* Walk from the start (cheap because typical logs are small at
     * boot and we only re-walk on open). We track the last KNOWN-good
     * end offset; anything past that is partial and gets truncated. */
    uint64_t cursor = 0;
    uint64_t last_good_end = 0;

    while (cursor + EVT_HDR_LEN + EVT_SENTINEL_LEN <= size) {
        uint8_t hdr[EVT_HDR_LEN];
        if (full_pread(fd, hdr, EVT_HDR_LEN, (off_t)cursor) < 0) break;
        uint32_t plen   = get_u32_le(hdr + 0);
        /* type/flags/crc parsed below if we proceed */

        /* Defensive bound — anything pathological → truncate. */
        if (plen > EVENT_LOG_MAX_PAYLOAD) break;

        uint64_t need = (uint64_t)EVT_HDR_LEN + plen + EVT_SENTINEL_LEN;
        if (cursor + need > size) break;

        /* Validate sentinel. */
        uint8_t sent[EVT_SENTINEL_LEN];
        if (full_pread(fd, sent, EVT_SENTINEL_LEN,
                       (off_t)(cursor + EVT_HDR_LEN + plen)) < 0)
            break;
        uint64_t magic  = get_u64_le(sent + 0);
        uint64_t offset = get_u64_le(sent + 8);
        if (magic != EVENT_LOG_SENTINEL_MAGIC || offset != cursor)
            break;

        /* Validate CRC over the payload. */
        uint32_t crc_disk = get_u32_le(hdr + 12);
        uint8_t *payload = NULL;
        if (plen > 0) {
            payload = (uint8_t *)zcl_malloc(plen, "event_log/recover");
            if (!payload) break;
            if (full_pread(fd, payload, plen,
                           (off_t)(cursor + EVT_HDR_LEN)) < 0) {
                free(payload);
                break;
            }
        }
        uint32_t crc_calc = crc32c(payload, plen);
        free(payload);
        if (crc_disk != crc_calc) break;

        /* Event is well-formed and durable. */
        cursor       += need;
        last_good_end = cursor;
    }

    if (last_good_end < size) {
        fprintf(stderr,  // obs-ok:event-log-lifecycle
                "[event_log] truncating partial tail: %llu -> %llu (%s)\n",
                (unsigned long long)size,
                (unsigned long long)last_good_end, path);
        if (ftruncate(fd, (off_t)last_good_end) < 0) {
            fprintf(stderr,  // obs-ok:event-log-open-failure
                    "[event_log] ftruncate(%s) failed: %s\n",
                    path, strerror(errno));
            return -1;
        }
        /* Make the truncation durable before publishing the handle. */
        if (fsync(fd) < 0) {
            fprintf(stderr,  // obs-ok:event-log-open-failure
                    "[event_log] fsync after truncate(%s) failed: %s\n",
                    path, strerror(errno));
            return -1;
        }
    }
    return (int64_t)last_good_end;
}

/* ── public API ─────────────────────────────────────────────────────── */

event_log_t *event_log_open(const char *path)
{
    if (!path || !path[0])
        LOG_NULL("event_log", "open: empty path");

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        fprintf(stderr,  // obs-ok:event-log-open-failure
                "[event_log] open(%s) failed: %s\n",
                path, strerror(errno));
        return NULL;
    }

    int64_t end = recover_truncate_partial(fd, path);
    if (end < 0) {
        close(fd);
        return NULL;
    }

    event_log_t *log = (event_log_t *)zcl_malloc(sizeof(*log),
                                                  "event_log/handle");
    if (!log) {
        close(fd);
        return NULL;
    }
    log->fd = fd;
    pthread_mutex_init(&log->lock, NULL);
    snprintf(log->path, sizeof(log->path), "%s", path);
    log->end_offset = (uint64_t)end;
    log->deferred_sync = false;
    log->dirty = false;
    log->pending = (struct event_log_pending){0};

    fprintf(stderr,  // obs-ok:event-log-lifecycle
            "[event_log] opened %s (size=%llu)\n",
            path, (unsigned long long)log->end_offset);
    return log;
}

void event_log_close(event_log_t *log)
{
    if (!log) return;
    /* Best-effort flush also publishes any deferred in-memory span. */
    if (log->fd >= 0) {
        (void)event_log_flush(log);
        close(log->fd);
        log->fd = -1;
    }
    event_log_pending_destroy(&log->pending);
    pthread_mutex_destroy(&log->lock);
    free(log);
}

/* One durability barrier, timed. The clock pair is the whole point: this is the
 * syscall the fold parks in (jbd2_log_wait_commit), and without a number here
 * the per-call-site totals cannot separate barrier wait from anything else.
 * Returns fsync()'s own result unchanged — the time is accumulated on the
 * failure path too, since a barrier that failed still cost its wait. */
static int event_log_barrier(int fd)
{
    int64_t t0 = platform_time_monotonic_us();
    int rc = fsync(fd);
    int64_t dt = platform_time_monotonic_us() - t0;
    atomic_fetch_add_explicit(&g_barrier_us_total,
                              dt > 0 ? (uint64_t)dt : 0u,
                              memory_order_relaxed);
    return rc;
}

static bool event_log_write_pending_locked(event_log_t *log)
{
    return log && event_log_pending_write(&log->pending, log->fd,
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
        if (!event_log_pending_prepare(&log->pending, event_len, log->fd,
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
    if (full_pwrite(log->fd, hdr, EVT_HDR_LEN, (off_t)start) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] pwrite(hdr) failed at off=%llu: %s\n",
                (unsigned long long)start, strerror(errno));
        return UINT64_MAX;
    }
    if (payload_len > 0) {
        if (full_pwrite(log->fd, payload, payload_len,
                        (off_t)(start + EVT_HDR_LEN)) < 0) {
            pthread_mutex_unlock(&log->lock);
            fprintf(stderr,  // obs-ok:event-log-append-failure
                    "[event_log] pwrite(payload) failed at off=%llu: %s\n",
                    (unsigned long long)(start + EVT_HDR_LEN),
                    strerror(errno));
            return UINT64_MAX;
        }
    }
    if (event_log_barrier(log->fd) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] fsync(hdr+payload) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }

    /* Durable completion marker: sentinel. */
    if (full_pwrite(log->fd, sent, EVT_SENTINEL_LEN,
                    (off_t)(start + EVT_HDR_LEN + payload_len)) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] pwrite(sentinel) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }
    if (event_log_barrier(log->fd) < 0) {
        pthread_mutex_unlock(&log->lock);
        fprintf(stderr,  // obs-ok:event-log-append-failure
                "[event_log] fsync(sentinel) failed: %s\n",
                strerror(errno));
        return UINT64_MAX;
    }

    log->end_offset = start + EVT_HDR_LEN + payload_len + EVT_SENTINEL_LEN;
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
    if (platform_data_sync(log->fd) < 0) {
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
    if (full_pread(log->fd, hdr, EVT_HDR_LEN, (off_t)offset) < 0) {
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
        if (full_pread(log->fd, tmp, plen,
                       (off_t)(offset + EVT_HDR_LEN)) < 0) {
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
    if (full_pread(log->fd, sent, EVT_SENTINEL_LEN,
                   (off_t)(offset + EVT_HDR_LEN + plen)) < 0) {
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
        if (full_pread(log->fd, hdr, EVT_HDR_LEN, (off_t)cursor) < 0) {
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
            if (full_pread(log->fd, buf, plen,
                           (off_t)(cursor + EVT_HDR_LEN)) < 0) {
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
        if (full_pread(log->fd, sent, EVT_SENTINEL_LEN,
                       (off_t)(cursor + EVT_HDR_LEN + plen)) < 0) {
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

void event_log_test_set_force_per_append(int v)
{
    atomic_store_explicit(&g_force_per_append_override, v,
                          memory_order_relaxed);
}

int event_log_test_fd(event_log_t *log)
{
    return log ? log->fd : -1;
}

void event_log_test_set_fd(event_log_t *log, int fd)
{
    if (log) log->fd = fd;
}
#endif
