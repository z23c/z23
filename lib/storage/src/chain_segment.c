/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_segment — implementation. See storage/chain_segment.h for the format.
 */

#include "storage/chain_segment.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/file_sync.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t SEG_MAGIC[8] = { 'Z','C','L','S','E','G','0','1' };
static const uint8_t MAN_MAGIC[8] = { 'Z','C','L','M','A','N','0','1' };

const char *cseg_status_str(enum cseg_status s)
{
    switch (s) {
    case CSEG_OK:                return "ok";
    case CSEG_ERR_ARG:           return "bad_argument";
    case CSEG_ERR_EMPTY_RANGE:   return "empty_range";
    case CSEG_ERR_BODY_MISSING:  return "body_missing";
    case CSEG_ERR_IO:            return "io_error";
    case CSEG_ERR_FORMAT:        return "bad_format";
    case CSEG_ERR_SEGMENT_DIGEST:return "segment_digest_mismatch";
    case CSEG_ERR_BLOCK_DIGEST:  return "block_digest_mismatch";
    case CSEG_ERR_NOT_FOUND:     return "height_not_found";
    case CSEG_ERR_MANIFEST:      return "manifest_error";
    }
    return "unknown";
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    if (!err || errlen == 0) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* ── Little-endian scalar helpers ────────────────────────────────────── */
static void put_u32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8*i));
}
static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8*i);
    return v;
}

static void seg_path(char *buf, size_t buflen, const char *dir,
                     uint32_t first_height, uint32_t count)
{
    snprintf(buf, buflen, "%s/seg-%u-%u.dat", dir, first_height, count);
}
static void manifest_path(char *buf, size_t buflen, const char *dir)
{
    snprintf(buf, buflen, "%s/manifest.dat", dir);
}

/* Atomic publish of immutable bytes: unique stage -> fsync -> rename ->
 * chmod 0444. Staging names are issued once per attempt — pid plus a
 * process-lifetime counter shared by every caller in this address space
 * (the HTTP repair pool and the segment sealer thread race on the same
 * destinations) — because a single "<path>.tmp" let whichever opener won
 * O_TRUNC silently rewrite the other's staging file mid-write, and the
 * final rename could then publish a spliced body under one digest. With a
 * private stage name, EEXIST is not contention; it is tampering with our
 * staging area, and fails closed. A stage left behind by a crash carries
 * a name parse_seg_name() ignores, so scans never mistake it for data. */
static _Atomic uint32_t g_stage_seq;
static pthread_mutex_t g_publish_mutex = PTHREAD_MUTEX_INITIALIZER;

static enum cseg_status chain_segment_manifest_rebuild_unlocked(
    const char *dir, char *err, size_t errlen);

static enum cseg_status atomic_write_ro(const char *path,
                                        const uint8_t *buf, size_t len,
                                        char *err, size_t errlen)
{
    char tmp[4096];
    int fd;
    for (;;) {
        int n = snprintf(tmp, sizeof(tmp), "%s.%ld-%u.tmp", path,
                         (long)getpid(),
                         (unsigned)atomic_fetch_add(&g_stage_seq, 1));
        if (n < 0 || (size_t)n >= sizeof(tmp)) {
            set_err(err, errlen, "staging name too long: %s", path);
            return CSEG_ERR_IO;
        }
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0644);
        if (fd >= 0)
            break;
        if (errno == EEXIST) {
            set_err(err, errlen, "stage name already exists: %s", tmp);
            return CSEG_ERR_IO;
        }
        if (errno != EINTR) {
            set_err(err, errlen, "open(%s): %s", tmp, strerror(errno));
            return CSEG_ERR_IO;
        }
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            set_err(err, errlen, "write(%s): %s", tmp, strerror(errno));
            close(fd); unlink(tmp);
            return CSEG_ERR_IO;
        }
        off += (size_t)w;
    }
    if (platform_data_sync(fd) != 0) {
        set_err(err, errlen, "fdatasync(%s): %s", tmp, strerror(errno));
        close(fd); unlink(tmp);
        return CSEG_ERR_IO;
    }
    if (close(fd) != 0) {
        set_err(err, errlen, "close(%s): %s", tmp, strerror(errno));
        unlink(tmp);
        return CSEG_ERR_IO;
    }
    if (rename(tmp, path) != 0) {
        set_err(err, errlen, "rename(%s -> %s): %s", tmp, path, strerror(errno));
        unlink(tmp);
        return CSEG_ERR_IO;
    }
    /* Seal read-only: finalized history is never rewritten. */
    (void)chmod(path, 0444);
    return CSEG_OK;
}

/* ── Writer ──────────────────────────────────────────────────────────── */

/* Build one segment covering [first_height, first_height+count) in memory,
 * then publish it atomically. Records the segment digest into `digest_out`. */
static enum cseg_status seal_one(const char *dir,
                                 chain_segment_body_fn body, void *user,
                                 uint32_t first_height, uint32_t count,
                                 uint8_t digest_out[32],
                                 char *err, size_t errlen)
{
    uint8_t **bodies = zcl_malloc(count * sizeof(*bodies), "chain_segment/bodies");
    size_t  *lens    = zcl_malloc(count * sizeof(*lens),   "chain_segment/lens");
    if (!bodies || !lens) {
        free(bodies); free(lens);
        set_err(err, errlen, "alloc bodies[%u]", count);
        return CSEG_ERR_IO;
    }
    memset(bodies, 0, count * sizeof(*bodies));

    uint64_t data_bytes = 0;
    enum cseg_status st = CSEG_OK;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t h = first_height + i;
        if (!body(user, h, &bodies[i], &lens[i]) || !bodies[i] || lens[i] == 0) {
            set_err(err, errlen, "seg-%u-%u: body missing at height %u",
                    first_height, count, h);
            st = CSEG_ERR_BODY_MISSING;
            goto done;
        }
        data_bytes += lens[i];
    }

    uint64_t index_bytes = (uint64_t)count * CHAIN_SEGMENT_INDEX_ENTRY_SIZE;
    uint64_t data_offset = CHAIN_SEGMENT_HEADER_SIZE + index_bytes;
    uint64_t body_offset = data_offset + data_bytes; /* == trailer offset */
    uint64_t total = body_offset + CHAIN_SEGMENT_TRAILER_SIZE;

    uint8_t *buf = zcl_malloc(total, "chain_segment/seal_buf");
    if (!buf) {
        set_err(err, errlen, "alloc segment buf %llu", (unsigned long long)total);
        st = CSEG_ERR_IO;
        goto done;
    }
    memset(buf, 0, CHAIN_SEGMENT_HEADER_SIZE);
    memcpy(buf, SEG_MAGIC, 8);
    put_u32(buf + 8,  CHAIN_SEGMENT_FORMAT_VERSION);
    put_u32(buf + 12, first_height);
    put_u32(buf + 16, count);
    put_u32(buf + 20, CHAIN_SEGMENT_INDEX_ENTRY_SIZE);
    put_u64(buf + 24, data_offset);

    uint64_t cursor = data_offset;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *e = buf + CHAIN_SEGMENT_HEADER_SIZE + (uint64_t)i * CHAIN_SEGMENT_INDEX_ENTRY_SIZE;
        put_u32(e + 0, first_height + i);
        put_u32(e + 4, (uint32_t)lens[i]);
        put_u64(e + 8, cursor);
        sha3_256(bodies[i], lens[i], e + 16);
        memcpy(buf + cursor, bodies[i], lens[i]);
        cursor += lens[i];
    }

    sha3_256(buf, body_offset, buf + body_offset);
    memcpy(digest_out, buf + body_offset, 32);

    char path[4096];
    seg_path(path, sizeof(path), dir, first_height, count);
    st = atomic_write_ro(path, buf, total, err, errlen);
    free(buf);

done:
    for (uint32_t i = 0; i < count; i++) free(bodies[i]);
    free(bodies); free(lens);
    return st;
}

enum cseg_status chain_segment_seal_range(const char *dir,
                                          chain_segment_body_fn body,
                                          void *user,
                                          uint32_t first_height,
                                          uint32_t count,
                                          char *err, size_t errlen)
{
    if (!dir || !body) { set_err(err, errlen, "null dir/body"); return CSEG_ERR_ARG; }
    if (count == 0) {
        set_err(err, errlen, "empty range at height %u", first_height);
        return CSEG_ERR_EMPTY_RANGE;
    }

    int lock_rc = pthread_mutex_lock(&g_publish_mutex);
    if (lock_rc != 0) {
        set_err(err, errlen, "segment publish lock: %s", strerror(lock_rc));
        return CSEG_ERR_IO;
    }

    enum cseg_status result = CSEG_OK;
    uint32_t done = 0;
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > CHAIN_SEGMENT_BLOCKS_PER_SEG) chunk = CHAIN_SEGMENT_BLOCKS_PER_SEG;
        uint8_t digest[32];
        enum cseg_status st = seal_one(dir, body, user, first_height + done,
                                       chunk, digest, err, errlen);
        if (st != CSEG_OK) {
            result = st;
            goto unlock;
        }
        done += chunk;
    }
    result = chain_segment_manifest_rebuild_unlocked(dir, err, errlen);

unlock:
    pthread_mutex_unlock(&g_publish_mutex);
    return result;
}

/* ── Reader ──────────────────────────────────────────────────────────── */

struct chain_segment {
    uint8_t *base;      /* mmap base */
    size_t   size;      /* file size */
    uint32_t first_height;
    uint32_t count;
    uint64_t data_offset;
    const uint8_t *index;   /* base + header */
    uint8_t  digest[32];
};

/* Parse + validate the header and geometry of a mapped segment. */
static enum cseg_status parse_segment(struct chain_segment *seg,
                                      const char *path,
                                      char *err, size_t errlen)
{
    if (seg->size < CHAIN_SEGMENT_HEADER_SIZE + CHAIN_SEGMENT_TRAILER_SIZE) {
        set_err(err, errlen, "%s: truncated (%zu bytes)", path, seg->size);
        return CSEG_ERR_FORMAT;
    }
    if (memcmp(seg->base, SEG_MAGIC, 8) != 0) {
        set_err(err, errlen, "%s: bad magic", path);
        return CSEG_ERR_FORMAT;
    }
    uint32_t ver = get_u32(seg->base + 8);
    if (ver != CHAIN_SEGMENT_FORMAT_VERSION) {
        set_err(err, errlen, "%s: format version %u != %u", path, ver,
                CHAIN_SEGMENT_FORMAT_VERSION);
        return CSEG_ERR_FORMAT;
    }
    seg->first_height = get_u32(seg->base + 12);
    seg->count        = get_u32(seg->base + 16);
    uint32_t entsz    = get_u32(seg->base + 20);
    seg->data_offset  = get_u64(seg->base + 24);
    if (entsz != CHAIN_SEGMENT_INDEX_ENTRY_SIZE || seg->count == 0) {
        set_err(err, errlen, "%s: bad index geometry (entsz=%u count=%u)",
                path, entsz, seg->count);
        return CSEG_ERR_FORMAT;
    }
    uint64_t index_bytes = (uint64_t)seg->count * CHAIN_SEGMENT_INDEX_ENTRY_SIZE;
    if (seg->data_offset != CHAIN_SEGMENT_HEADER_SIZE + index_bytes) {
        set_err(err, errlen, "%s: data_offset %llu inconsistent with count %u",
                path, (unsigned long long)seg->data_offset, seg->count);
        return CSEG_ERR_FORMAT;
    }
    if (seg->data_offset + CHAIN_SEGMENT_TRAILER_SIZE > seg->size) {
        set_err(err, errlen, "%s: index overruns file", path);
        return CSEG_ERR_FORMAT;
    }
    seg->index = seg->base + CHAIN_SEGMENT_HEADER_SIZE;

    uint64_t trailer_off = seg->size - CHAIN_SEGMENT_TRAILER_SIZE;
    /* Every index entry must land inside [data_offset, trailer_off). */
    for (uint32_t i = 0; i < seg->count; i++) {
        const uint8_t *e = seg->index + (uint64_t)i * CHAIN_SEGMENT_INDEX_ENTRY_SIZE;
        uint32_t len = get_u32(e + 4);
        uint64_t off = get_u64(e + 8);
        if (len == 0 || off < seg->data_offset ||
            off + len > trailer_off) {
            set_err(err, errlen, "%s: index[%u] out of range (off=%llu len=%u)",
                    path, i, (unsigned long long)off, len);
            return CSEG_ERR_FORMAT;
        }
    }

    /* Whole-segment digest over [0, trailer_off). */
    uint8_t got[32];
    sha3_256(seg->base, trailer_off, got);
    if (memcmp(got, seg->base + trailer_off, 32) != 0) {
        set_err(err, errlen, "%s: segment digest mismatch", path);
        return CSEG_ERR_SEGMENT_DIGEST;
    }
    memcpy(seg->digest, got, 32);
    return CSEG_OK;
}

enum cseg_status chain_segment_open(const char *path,
                                    struct chain_segment **out,
                                    char *err, size_t errlen)
{
    if (!path || !out) { set_err(err, errlen, "null path/out"); return CSEG_ERR_ARG; }
    *out = NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_err(err, errlen, "open(%s): %s", path, strerror(errno));
        return CSEG_ERR_IO;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) {
        set_err(err, errlen, "fstat(%s): %s", path, strerror(errno));
        close(fd);
        return CSEG_ERR_IO;
    }
    void *base = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        set_err(err, errlen, "mmap(%s): %s", path, strerror(errno));
        return CSEG_ERR_IO;
    }

    struct chain_segment *seg = zcl_malloc(sizeof(*seg), "chain_segment/open");
    if (!seg) {
        munmap(base, (size_t)sb.st_size);
        set_err(err, errlen, "alloc chain_segment");
        return CSEG_ERR_IO;
    }
    memset(seg, 0, sizeof(*seg));
    seg->base = base;
    seg->size = (size_t)sb.st_size;

    enum cseg_status st = parse_segment(seg, path, err, errlen);
    if (st != CSEG_OK) {
        munmap(seg->base, seg->size);
        free(seg);
        return st;
    }
    *out = seg;
    return CSEG_OK;
}

void chain_segment_close(struct chain_segment *seg)
{
    if (!seg) return;
    if (seg->base) munmap(seg->base, seg->size);
    free(seg);
}

uint32_t chain_segment_first_height(const struct chain_segment *seg)
{
    return seg ? seg->first_height : 0;
}
uint32_t chain_segment_count(const struct chain_segment *seg)
{
    return seg ? seg->count : 0;
}
void chain_segment_digest(const struct chain_segment *seg, uint8_t out[32])
{
    if (seg) memcpy(out, seg->digest, 32); else memset(out, 0, 32);
}

enum cseg_status chain_segment_get_block(struct chain_segment *seg,
                                         uint32_t height,
                                         uint8_t **bytes, size_t *len,
                                         char *err, size_t errlen)
{
    if (!seg || !bytes || !len) { set_err(err, errlen, "null arg"); return CSEG_ERR_ARG; }
    *bytes = NULL; *len = 0;

    if (height < seg->first_height || height >= seg->first_height + seg->count) {
        set_err(err, errlen, "seg-%u-%u: height %u out of range",
                seg->first_height, seg->count, height);
        return CSEG_ERR_NOT_FOUND;
    }
    uint32_t i = height - seg->first_height;
    const uint8_t *e = seg->index + (uint64_t)i * CHAIN_SEGMENT_INDEX_ENTRY_SIZE;
    /* The index is height-ordered and contiguous from first_height, so entry i
     * is the block at `height`; guard against a corrupt height field. */
    if (get_u32(e + 0) != height) {
        set_err(err, errlen, "seg-%u-%u: index[%u] height %u != %u",
                seg->first_height, seg->count, i, get_u32(e + 0), height);
        return CSEG_ERR_FORMAT;
    }
    uint32_t blen = get_u32(e + 4);
    uint64_t off  = get_u64(e + 8);

    uint8_t got[32];
    sha3_256(seg->base + off, blen, got);
    if (memcmp(got, e + 16, 32) != 0) {
        set_err(err, errlen, "seg-%u-%u: block digest mismatch at height %u",
                seg->first_height, seg->count, height);
        return CSEG_ERR_BLOCK_DIGEST;
    }

    uint8_t *copy = zcl_malloc(blen, "chain_segment/get_block");
    if (!copy) {
        set_err(err, errlen, "alloc block %u bytes", blen);
        return CSEG_ERR_IO;
    }
    memcpy(copy, seg->base + off, blen);
    *bytes = copy;
    *len = blen;
    return CSEG_OK;
}

/* ── Manifest + store view ───────────────────────────────────────────── */

struct seg_entry {
    uint32_t first_height;
    uint32_t count;
    uint8_t  digest[32];
};

static int seg_entry_cmp(const void *a, const void *b)
{
    uint32_t x = ((const struct seg_entry *)a)->first_height;
    uint32_t y = ((const struct seg_entry *)b)->first_height;
    return (x > y) - (x < y);
}

/* Match "seg-<first>-<count>.dat"; returns true and fills fh, cnt on match. */
static bool parse_seg_name(const char *name, uint32_t *fh, uint32_t *cnt)
{
    unsigned f = 0, c = 0;
    char tail = 0;
    if (sscanf(name, "seg-%u-%u.da%c", &f, &c, &tail) == 3 && tail == 't' &&
        name[strlen(name) - 1] == 't') {
        *fh = f; *cnt = c;
        return true;
    }
    return false;
}

/* Collect + digest-verify every seg-*.dat in `dir`, sorted by first_height.
 * On success returns a malloc'd array (*out_entries, caller frees) of length
 * *out_n. Any segment that fails to open/verify aborts with a typed status. */
static enum cseg_status collect_segments(const char *dir,
                                         struct seg_entry **out_entries,
                                         uint32_t *out_n,
                                         char *err, size_t errlen)
{
    *out_entries = NULL; *out_n = 0;
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT) return CSEG_OK; /* no store yet */
        set_err(err, errlen, "opendir(%s): %s", dir, strerror(errno));
        return CSEG_ERR_IO;
    }
    size_t cap = 16, n = 0;
    struct seg_entry *ents = zcl_malloc(cap * sizeof(*ents), "chain_segment/collect");
    if (!ents) { closedir(d); set_err(err, errlen, "alloc"); return CSEG_ERR_IO; }

    enum cseg_status st = CSEG_OK;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        uint32_t fh, cnt;
        if (!parse_seg_name(de->d_name, &fh, &cnt)) continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct chain_segment *seg = NULL;
        st = chain_segment_open(path, &seg, err, errlen);
        if (st != CSEG_OK) break;
        if (n == cap) {
            cap *= 2;
            struct seg_entry *grown = realloc(ents, cap * sizeof(*ents)); // raw-alloc-ok:local-array-grow
            if (!grown) { chain_segment_close(seg); st = CSEG_ERR_IO;
                          set_err(err, errlen, "grow entries"); break; }
            ents = grown;
        }
        ents[n].first_height = chain_segment_first_height(seg);
        ents[n].count = chain_segment_count(seg);
        chain_segment_digest(seg, ents[n].digest);
        n++;
        chain_segment_close(seg);
    }
    closedir(d);
    if (st != CSEG_OK) { free(ents); return st; }

    qsort(ents, n, sizeof(*ents), seg_entry_cmp);
    *out_entries = ents;
    *out_n = (uint32_t)n;
    return CSEG_OK;
}

static enum cseg_status chain_segment_manifest_rebuild_unlocked(
    const char *dir, char *err, size_t errlen)
{
    if (!dir) { set_err(err, errlen, "null dir"); return CSEG_ERR_ARG; }

    struct seg_entry *ents = NULL;
    uint32_t n = 0;
    enum cseg_status st = collect_segments(dir, &ents, &n, err, errlen);
    if (st != CSEG_OK) return st;

    uint64_t body = CHAIN_MANIFEST_HEADER_SIZE + (uint64_t)n * CHAIN_MANIFEST_ENTRY_SIZE;
    uint64_t total = body + CHAIN_MANIFEST_TRAILER_SIZE;
    uint8_t *buf = zcl_malloc(total, "chain_segment/manifest");
    if (!buf) { free(ents); set_err(err, errlen, "alloc manifest"); return CSEG_ERR_IO; }

    memset(buf, 0, CHAIN_MANIFEST_HEADER_SIZE);
    memcpy(buf, MAN_MAGIC, 8);
    put_u32(buf + 8, CHAIN_MANIFEST_FORMAT_VERSION);
    put_u32(buf + 12, n);
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *e = buf + CHAIN_MANIFEST_HEADER_SIZE + (uint64_t)i * CHAIN_MANIFEST_ENTRY_SIZE;
        put_u32(e + 0, ents[i].first_height);
        put_u32(e + 4, ents[i].count);
        memcpy(e + 8, ents[i].digest, 32);
    }
    sha3_256(buf, body, buf + body);
    free(ents);

    char path[4096];
    manifest_path(path, sizeof(path), dir);
    st = atomic_write_ro(path, buf, total, err, errlen);
    free(buf);
    return st;
}

enum cseg_status chain_segment_manifest_rebuild(const char *dir,
                                                char *err, size_t errlen)
{
    int lock_rc = pthread_mutex_lock(&g_publish_mutex);
    if (lock_rc != 0) {
        set_err(err, errlen, "manifest publish lock: %s", strerror(lock_rc));
        return CSEG_ERR_IO;
    }
    enum cseg_status st =
        chain_segment_manifest_rebuild_unlocked(dir, err, errlen);
    pthread_mutex_unlock(&g_publish_mutex);
    return st;
}

/* Load + validate manifest.dat into a malloc'd entry array. An absent manifest
 * yields *out_n = 0 and CSEG_OK. */
static enum cseg_status load_manifest(const char *dir,
                                      struct seg_entry **out_entries,
                                      uint32_t *out_n, uint8_t root[32],
                                      char *err, size_t errlen)
{
    *out_entries = NULL; *out_n = 0; memset(root, 0, 32);
    char path[4096];
    manifest_path(path, sizeof(path), dir);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return CSEG_OK;
        set_err(err, errlen, "open(%s): %s", path, strerror(errno));
        return CSEG_ERR_IO;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        set_err(err, errlen, "fstat(%s): %s", path, strerror(errno));
        close(fd);
        return CSEG_ERR_IO;
    }
    if ((uint64_t)sb.st_size < CHAIN_MANIFEST_HEADER_SIZE + CHAIN_MANIFEST_TRAILER_SIZE) {
        close(fd);
        set_err(err, errlen, "%s: truncated", path);
        return CSEG_ERR_MANIFEST;
    }
    uint8_t *buf = zcl_malloc((size_t)sb.st_size, "chain_segment/load_manifest");
    if (!buf) { close(fd); set_err(err, errlen, "alloc"); return CSEG_ERR_IO; }
    ssize_t got = read(fd, buf, (size_t)sb.st_size);
    close(fd);
    if (got != sb.st_size) {
        free(buf);
        set_err(err, errlen, "%s: short read", path);
        return CSEG_ERR_IO;
    }
    if (memcmp(buf, MAN_MAGIC, 8) != 0 ||
        get_u32(buf + 8) != CHAIN_MANIFEST_FORMAT_VERSION) {
        free(buf); set_err(err, errlen, "%s: bad header", path);
        return CSEG_ERR_MANIFEST;
    }
    uint32_t n = get_u32(buf + 12);
    uint64_t body = CHAIN_MANIFEST_HEADER_SIZE + (uint64_t)n * CHAIN_MANIFEST_ENTRY_SIZE;
    if (body + CHAIN_MANIFEST_TRAILER_SIZE != (uint64_t)sb.st_size) {
        free(buf); set_err(err, errlen, "%s: size inconsistent with count %u", path, n);
        return CSEG_ERR_MANIFEST;
    }
    uint8_t calc[32];
    sha3_256(buf, body, calc);
    if (memcmp(calc, buf + body, 32) != 0) {
        free(buf); set_err(err, errlen, "%s: manifest root mismatch", path);
        return CSEG_ERR_MANIFEST;
    }
    memcpy(root, calc, 32);

    struct seg_entry *ents = NULL;
    if (n > 0) {
        ents = zcl_malloc((size_t)n * sizeof(*ents), "chain_segment/manifest_entries");
        if (!ents) { free(buf); set_err(err, errlen, "alloc"); return CSEG_ERR_IO; }
        for (uint32_t i = 0; i < n; i++) {
            const uint8_t *e = buf + CHAIN_MANIFEST_HEADER_SIZE + (uint64_t)i * CHAIN_MANIFEST_ENTRY_SIZE;
            ents[i].first_height = get_u32(e + 0);
            ents[i].count = get_u32(e + 4);
            memcpy(ents[i].digest, e + 8, 32);
        }
    }
    free(buf);
    *out_entries = ents;
    *out_n = n;
    return CSEG_OK;
}

enum cseg_status chain_segment_store_stat(const char *dir,
                                          bool full_verify,
                                          struct chain_segment_stat *out,
                                          char *err, size_t errlen)
{
    if (!dir || !out) { set_err(err, errlen, "null arg"); return CSEG_ERR_ARG; }
    memset(out, 0, sizeof(*out));
    out->full_verify = full_verify;

    struct seg_entry *ents = NULL;
    uint32_t n = 0;
    enum cseg_status st = load_manifest(dir, &ents, &n, out->manifest_root, err, errlen);
    if (st != CSEG_OK) return st;

    out->segment_count = n;
    if (n == 0) { free(ents); return CSEG_OK; }

    out->have_range = true;
    out->min_height = ents[0].first_height;
    out->max_height = ents[n - 1].first_height + ents[n - 1].count - 1;

    for (uint32_t i = 0; i < n; i++) {
        char path[4096];
        seg_path(path, sizeof(path), dir, ents[i].first_height, ents[i].count);
        if (full_verify) {
            struct chain_segment *seg = NULL;
            st = chain_segment_open(path, &seg, err, errlen);
            if (st != CSEG_OK) { free(ents); return st; }
            uint8_t d[32];
            chain_segment_digest(seg, d);
            chain_segment_close(seg);
            if (memcmp(d, ents[i].digest, 32) != 0) {
                set_err(err, errlen, "seg-%u-%u: digest disagrees with manifest",
                        ents[i].first_height, ents[i].count);
                free(ents);
                return CSEG_ERR_MANIFEST;
            }
            out->verified_count++;
        } else {
            struct stat sb;
            if (stat(path, &sb) == 0 && S_ISREG(sb.st_mode))
                out->verified_count++;
        }
    }
    free(ents);
    return CSEG_OK;
}
