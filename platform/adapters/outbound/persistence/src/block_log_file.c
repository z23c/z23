/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton */

#define _POSIX_C_SOURCE 200809L

#include "adapters/outbound/persistence/block_log_file.h"
#include "platform/directory_compat.h"
#include "platform/file_sync.h"
#include "platform/positioned_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* On-disk constants. */
static const char BLK_MAGIC[4] = {'Z', 'B', 'L', 'K'};
#define LOG_HEADER_BYTES   (4 + 32 + 4)   /* magic + hash + len */
#define IDX_RECORD_BYTES   (4 + 32 + 8)   /* height + hash + offset */

struct idx_entry {
    uint32_t height;
    struct block_hash hash;
    uint64_t offset;
};

struct block_log_file {
    char *dir;
    int log_fd;
    int idx_fd;

    /* In-memory snapshot of the index, in append order. */
    struct idx_entry *entries;
    size_t count;
    size_t capacity;

    /* Single owned read buffer returned by read_by_hash / read_at_height.
     * The port contract says the buffer is valid until the next port
     * call — so a single owned buffer per handle suffices. */
    uint8_t *read_buf;
    size_t read_cap;
    size_t read_len;
};

/* ---- low-level helpers ------------------------------------------ */

static struct zcl_result write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return ZCL_ERR(BLOCK_LOG_ERR_IO,
                           "write_all: errno=%d (%s)", errno, strerror(errno));
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return ZCL_OK;
}

static struct zcl_result read_exact(int fd, off_t off, void *buf, size_t n)
{
    if (off < 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "positioned read: negative offset");
    uint8_t *p = buf;
    while (n > 0) {
        size_t chunk = n > UINT32_MAX ? UINT32_MAX : n;
        int64_t r = platform_positioned_read(fd, p, chunk, (uint64_t)off);
        if (r < 0) {
            return ZCL_ERR(BLOCK_LOG_ERR_IO,
                           "positioned read: errno=%d (%s)", errno,
                           strerror(errno));
        }
        if (r == 0)
            return ZCL_ERR(BLOCK_LOG_ERR_CORRUPT,
                           "positioned read: unexpected EOF at offset %lld",
                           (long long)off);
        p += (size_t)r;
        off += r;
        n -= (size_t)r;
    }
    return ZCL_OK;
}

static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void put_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

static uint32_t get_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static struct zcl_result entries_reserve(struct block_log_file *h,
                                         size_t need)
{
    if (need <= h->capacity) return ZCL_OK;
    size_t cap = h->capacity ? h->capacity : 16;
    while (cap < need) cap *= 2;
    struct idx_entry *p = realloc(h->entries, cap * sizeof(*p));
    if (!p)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "entries_reserve: realloc failed (cap=%zu)", cap);
    h->entries = p;
    h->capacity = cap;
    return ZCL_OK;
}

static struct zcl_result read_buf_reserve(struct block_log_file *h,
                                          size_t need)
{
    if (need <= h->read_cap) return ZCL_OK;
    size_t cap = h->read_cap ? h->read_cap : 4096;
    while (cap < need) cap *= 2;
    uint8_t *p = realloc(h->read_buf, cap);
    if (!p)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "read_buf_reserve: realloc failed (cap=%zu)", cap);
    h->read_buf = p;
    h->read_cap = cap;
    return ZCL_OK;
}

/* Read a log record header at offset; populate hash, payload_len, and
 * the offset of the payload bytes. Returns BLOCK_LOG_ERR_CORRUPT if
 * the magic is wrong or the file is too short. */
static struct zcl_result read_log_record_header(struct block_log_file *h,
                                                off_t off,
                                                struct block_hash *hash_out,
                                                uint32_t *len_out)
{
    uint8_t hdr[LOG_HEADER_BYTES];
    struct zcl_result r = read_exact(h->log_fd, off, hdr, sizeof hdr);
    if (!r.ok) return r;
    if (memcmp(hdr, BLK_MAGIC, 4) != 0)
        return ZCL_ERR(BLOCK_LOG_ERR_CORRUPT,
                       "log record magic mismatch at offset %lld",
                       (long long)off);
    memcpy(hash_out->bytes, hdr + 4, 32);
    *len_out = get_u32_le(hdr + 4 + 32);
    return ZCL_OK;
}

/* Append an index entry (in memory + on disk) and fsync the index. */
static struct zcl_result idx_append_and_fsync(struct block_log_file *h,
                                              uint32_t height,
                                              const struct block_hash *hash,
                                              uint64_t offset)
{
    struct zcl_result r = entries_reserve(h, h->count + 1);
    if (!r.ok) return r;

    uint8_t rec[IDX_RECORD_BYTES];
    put_u32_le(rec, height);
    memcpy(rec + 4, hash->bytes, 32);
    put_u64_le(rec + 4 + 32, offset);

    /* The idx fd is opened with O_APPEND so the write atomically goes
     * to end-of-file. */
    r = write_all(h->idx_fd, rec, sizeof rec);
    if (!r.ok) return r;
    if (platform_file_sync(h->idx_fd) != 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "fsync idx: errno=%d (%s)", errno, strerror(errno));

    h->entries[h->count++] = (struct idx_entry){
        .height = height, .hash = *hash, .offset = offset,
    };
    return ZCL_OK;
}

/* ---- port-impl callbacks ---------------------------------------- */

static const struct idx_entry *find_by_hash(const struct block_log_file *h,
                                            const struct block_hash *hash)
{
    /* Linear scan. The blocks.idx is small (one record per block); for
     * a 3M-block chain that's ~131 MB and ~3M entries. Until this is
     * a hotspot, the scan is acceptable; a 2026-vintage CPU walks 3M
     * 44-byte structs in well under a second. A later commit can drop
     * a hashmap in front of this with no API change. */
    for (size_t i = h->count; i > 0; i--) {
        if (memcmp(h->entries[i - 1].hash.bytes, hash->bytes, 32) == 0)
            return &h->entries[i - 1];
    }
    return NULL;
}

static struct zcl_result blf_append(void *self_v,
                                    uint32_t height,
                                    const struct block_hash *hash,
                                    const uint8_t *bytes,
                                    size_t len)
{
    struct block_log_file *h = self_v;
    if (!h || !hash || (len > 0 && !bytes))
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "blf_append: null arg(s)");
    if (len > UINT32_MAX)
        return ZCL_ERR(BLOCK_LOG_ERR_TOO_LARGE,
                       "blf_append: len=%zu exceeds u32", len);

    /* Idempotency: hash collision check. */
    const struct idx_entry *existing = find_by_hash(h, hash);
    if (existing) {
        uint32_t stored_len;
        struct block_hash stored_hash;
        struct zcl_result r = read_log_record_header(
                h, (off_t)existing->offset, &stored_hash, &stored_len);
        if (!r.ok) return r;
        if (stored_len != len)
            return ZCL_ERR(BLOCK_LOG_ERR_CORRUPT,
                           "blf_append: idempotency violated — same hash, "
                           "stored len=%u, new len=%zu", stored_len, len);
        if (len > 0) {
            r = read_buf_reserve(h, len);
            if (!r.ok) return r;
            r = read_exact(h->log_fd,
                           (off_t)(existing->offset + LOG_HEADER_BYTES),
                           h->read_buf, len);
            if (!r.ok) return r;
            if (memcmp(h->read_buf, bytes, len) != 0)
                return ZCL_ERR(BLOCK_LOG_ERR_CORRUPT,
                               "blf_append: idempotency violated — same "
                               "hash, different bytes");
        }
        return ZCL_OK;
    }

    /* Append a fresh record. */
    off_t end = lseek(h->log_fd, 0, SEEK_END);
    if (end < 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "lseek log: errno=%d", errno);

    uint8_t hdr[LOG_HEADER_BYTES];
    memcpy(hdr, BLK_MAGIC, 4);
    memcpy(hdr + 4, hash->bytes, 32);
    put_u32_le(hdr + 4 + 32, (uint32_t)len);

    struct zcl_result r = write_all(h->log_fd, hdr, sizeof hdr);
    if (!r.ok) return r;
    if (len > 0) {
        r = write_all(h->log_fd, bytes, len);
        if (!r.ok) return r;
    }
    if (platform_file_sync(h->log_fd) != 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "fsync log: errno=%d (%s)", errno, strerror(errno));

    /* Now publish via the index. If we crash between the two fsyncs,
     * the open()-time recovery scan picks up the orphan log record. */
    return idx_append_and_fsync(h, height, hash, (uint64_t)end);
}

static struct zcl_result blf_read_by_hash(void *self_v,
                                          const struct block_hash *hash,
                                          const uint8_t **bytes_out,
                                          size_t *len_out)
{
    struct block_log_file *h = self_v;
    if (!h || !hash || !bytes_out || !len_out)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "blf_read_by_hash: null arg(s)");
    const struct idx_entry *e = find_by_hash(h, hash);
    if (!e)
        return ZCL_ERR(BLOCK_LOG_ERR_NOT_FOUND, "blf_read_by_hash: miss");

    uint32_t len;
    struct block_hash stored_hash;
    struct zcl_result r = read_log_record_header(
            h, (off_t)e->offset, &stored_hash, &len);
    if (!r.ok) return r;

    r = read_buf_reserve(h, len ? len : 1);
    if (!r.ok) return r;
    if (len > 0) {
        r = read_exact(h->log_fd, (off_t)(e->offset + LOG_HEADER_BYTES),
                       h->read_buf, len);
        if (!r.ok) return r;
    }
    h->read_len = len;
    *bytes_out = h->read_buf;
    *len_out = len;
    return ZCL_OK;
}

static struct zcl_result blf_read_at_height(void *self_v,
                                            uint32_t height,
                                            const uint8_t **bytes_out,
                                            size_t *len_out)
{
    struct block_log_file *h = self_v;
    if (!h || !bytes_out || !len_out)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "blf_read_at_height: null arg(s)");
    /* Latest entry wins at a given height — supports reorgs in the
     * append stream. Walk back to front. */
    for (size_t i = h->count; i > 0; i--) {
        if (h->entries[i - 1].height != height) continue;
        return blf_read_by_hash(h, &h->entries[i - 1].hash, bytes_out, len_out);
    }
    return ZCL_ERR(BLOCK_LOG_ERR_NOT_FOUND,
                   "blf_read_at_height: no record at height=%u", height);
}

static uint32_t blf_tip_height(void *self_v)
{
    struct block_log_file *h = self_v;
    if (!h || h->count == 0) return UINT32_MAX;
    uint32_t hi = 0;
    bool any = false;
    for (size_t i = 0; i < h->count; i++) {
        if (!any || h->entries[i].height > hi) {
            hi = h->entries[i].height;
            any = true;
        }
    }
    return any ? hi : UINT32_MAX;
}

static struct zcl_result blf_iter_from(void *self_v,
                                       uint32_t start_height,
                                       block_log_iter_fn cb,
                                       void *user_data)
{
    struct block_log_file *h = self_v;
    if (!h || !cb)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "blf_iter_from: null arg(s)");
    /* Append-order traversal: skip below start_height, deliver the rest. */
    for (size_t i = 0; i < h->count; i++) {
        if (h->entries[i].height < start_height) continue;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        struct zcl_result r = blf_read_by_hash(
                h, &h->entries[i].hash, &bytes, &len);
        if (!r.ok) return r;
        if (!cb(h->entries[i].height, &h->entries[i].hash, bytes, len, user_data))
            break;
    }
    return ZCL_OK;
}

/* ---- open / recovery / close ------------------------------------ */

static struct zcl_result load_existing_index(struct block_log_file *h)
{
    off_t end = lseek(h->idx_fd, 0, SEEK_END);
    if (end < 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "lseek idx: errno=%d", errno);

    /* Truncate a torn final record, if any. */
    off_t whole = end - (end % IDX_RECORD_BYTES);
    if (whole != end) {
        if (ftruncate(h->idx_fd, whole) != 0)
            return ZCL_ERR(BLOCK_LOG_ERR_IO,
                           "ftruncate idx tail: errno=%d", errno);
        end = whole;
    }
    size_t records = (size_t)(end / IDX_RECORD_BYTES);
    struct zcl_result r = entries_reserve(h, records);
    if (!r.ok) return r;

    for (size_t i = 0; i < records; i++) {
        uint8_t rec[IDX_RECORD_BYTES];
        r = read_exact(h->idx_fd, (off_t)(i * IDX_RECORD_BYTES),
                       rec, sizeof rec);
        if (!r.ok) return r;
        h->entries[i].height = get_u32_le(rec);
        memcpy(h->entries[i].hash.bytes, rec + 4, 32);
        h->entries[i].offset = get_u64_le(rec + 4 + 32);
    }
    h->count = records;
    return ZCL_OK;
}

/* Scan blocks.log past the highest indexed offset; rebuild missing
 * index entries. Also truncates a torn final log record. Heights for
 * recovered records default to UINT32_MAX since we cannot know them
 * — the next normal append rewrites with the correct height, and
 * read-by-hash still works either way. (This is the conservative
 * choice; a header parser could extract block height, but that
 * would couple this adapter to primitives/block.h, which we want to
 * keep clean.) */
static struct zcl_result scan_log_tail(struct block_log_file *h)
{
    off_t log_end = lseek(h->log_fd, 0, SEEK_END);
    if (log_end < 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "lseek log: errno=%d", errno);

    off_t cursor = 0;
    if (h->count > 0) {
        const struct idx_entry *last = &h->entries[h->count - 1];
        uint32_t len;
        struct block_hash hash;
        struct zcl_result r = read_log_record_header(
                h, (off_t)last->offset, &hash, &len);
        if (!r.ok) return r;
        cursor = (off_t)(last->offset + LOG_HEADER_BYTES + len);
    }

    while (cursor < log_end) {
        if (log_end - cursor < (off_t)LOG_HEADER_BYTES) {
            /* Torn header — truncate. */
            if (ftruncate(h->log_fd, cursor) != 0)
                return ZCL_ERR(BLOCK_LOG_ERR_IO,
                               "ftruncate log torn header: errno=%d", errno);
            break;
        }
        struct block_hash hash;
        uint32_t len;
        struct zcl_result r = read_log_record_header(h, cursor, &hash, &len);
        if (!r.ok) return r;

        off_t need_end = cursor + (off_t)LOG_HEADER_BYTES + (off_t)len;
        if (need_end > log_end) {
            /* Torn payload — truncate to start of this record. */
            if (ftruncate(h->log_fd, cursor) != 0)
                return ZCL_ERR(BLOCK_LOG_ERR_IO,
                               "ftruncate log torn payload: errno=%d", errno);
            break;
        }

        r = idx_append_and_fsync(h, UINT32_MAX, &hash, (uint64_t)cursor);
        if (!r.ok) return r;
        cursor = need_end;
    }
    return ZCL_OK;
}

static int ensure_dir(const char *path)
{
    return platform_directory_ensure(path, 0755) ? 0 : -1;
}

struct zcl_result block_log_file_open(const char *dir,
                                      struct block_log_file **out_handle,
                                      struct block_log_port *out_port)
{
    if (!dir || !out_handle || !out_port)
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "block_log_file_open: null arg(s)");

    if (ensure_dir(dir) != 0)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: mkdir(%s): errno=%d (%s)",
                       dir, errno, strerror(errno));

    struct block_log_file *h = calloc(1, sizeof *h);
    if (!h)
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: calloc handle");
    h->log_fd = -1;
    h->idx_fd = -1;

    size_t dir_n = strlen(dir);
    h->dir = malloc(dir_n + 1);
    if (!h->dir) {
        block_log_file_close(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO, "block_log_file_open: dup dir");
    }
    memcpy(h->dir, dir, dir_n + 1);

    char path[4096];
    int n = snprintf(path, sizeof path, "%s/blocks.log", dir);
    if (n < 0 || (size_t)n >= sizeof path) {
        block_log_file_close(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: dir path too long");
    }
    h->log_fd = open(path, O_RDWR | O_CREAT, 0644);
    if (h->log_fd < 0) {
        block_log_file_close(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: open(%s): errno=%d (%s)",
                       path, errno, strerror(errno));
    }

    n = snprintf(path, sizeof path, "%s/blocks.idx", dir);
    if (n < 0 || (size_t)n >= sizeof path) {
        block_log_file_close(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: dir path too long (idx)");
    }
    h->idx_fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (h->idx_fd < 0) {
        block_log_file_close(h);
        return ZCL_ERR(BLOCK_LOG_ERR_IO,
                       "block_log_file_open: open(%s): errno=%d (%s)",
                       path, errno, strerror(errno));
    }

    {
        struct zcl_result r = load_existing_index(h);
        if (!r.ok) { block_log_file_close(h); return r; }
    }
    {
        struct zcl_result r = scan_log_tail(h);
        if (!r.ok) { block_log_file_close(h); return r; }
    }

    out_port->self = h;
    out_port->append = blf_append;
    out_port->read_by_hash = blf_read_by_hash;
    out_port->read_at_height = blf_read_at_height;
    out_port->tip_height = blf_tip_height;
    out_port->iter_from = blf_iter_from;

    *out_handle = h;
    return ZCL_OK;
}

void block_log_file_close(struct block_log_file *h)
{
    if (!h) return;
    if (h->log_fd >= 0) close(h->log_fd);
    if (h->idx_fd >= 0) close(h->idx_fd);
    free(h->entries);
    free(h->read_buf);
    free(h->dir);
    free(h);
}
