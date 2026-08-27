/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM download resume journal — see net/rom_journal.h.
 *
 * The durable sidecar that makes a per-chunk ROM fetch kill-9-safe. On disk:
 * an 88-byte ROMJRNL1 header pinning the manifest identity, followed by a
 * ceil(num_chunks/8)-byte chunk bitmap. A set bit means "this chunk's data is
 * durably present in the .part AND was digest-verified before the bit was set"
 * — the caller (rom_fetch.c) guarantees the pwrite→fdatasync(.part) happened
 * before rom_journal_mark(), and mark() itself does set-bit→fdatasync(journal).
 *
 * On open, a header that does not byte-match the caller's current manifest
 * (chunk_root / whole_sha3 / chunk_size / num_chunks) discards the journal and
 * starts fresh — no partial trust ("recompute, never repair"). The .part is the
 * caller's to discard on that signal (a fresh journal reports count_done == 0).
 *
 * One open fd + an in-memory bitmap per handle. An internal mutex makes
 * is_done/mark/count self-safe so a parallel fetch's workers can share one
 * handle. The header uses host byte order: this is a local resume artifact,
 * never on the wire and never shared between machines. */

#include "net/rom_journal.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/file_sync.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RJ_SUBSYS "rom_journal"

/* Defensive upper bound on num_chunks so a corrupt/hostile value cannot force
 * a huge bitmap allocation. Far above the ROM protocol's real cap
 * (ROM_SEED_MAX_CHUNKS == 4096) but bounded regardless of the caller. A 16 M
 * cap is a 2 MB bitmap. */
#define RJ_MAX_NUM_CHUNKS  (1u << 24)

struct rom_journal {
    int             fd;
    uint32_t        num_chunks;
    uint32_t        bitmap_bytes;   /* ceil(num_chunks / 8)                 */
    uint8_t        *bitmap;         /* in-memory mirror of the on-disk map  */
    uint32_t        done;           /* cached popcount of set bits          */
    pthread_mutex_t lock;           /* makes mark/is_done/count self-safe   */
};

/* On-disk offset of the chunk bitmap (immediately after the fixed header). */
#define RJ_BITMAP_OFFSET  ((off_t)sizeof(struct rom_journal_header))

static uint32_t rj_popcount_bitmap(const uint8_t *bm, uint32_t nbytes,
                                   uint32_t num_chunks)
{
    uint32_t c = 0;
    for (uint32_t i = 0; i < num_chunks; i++)
        if (bm[i >> 3] & (uint8_t)(1u << (i & 7u)))
            c++;
    (void)nbytes;
    return c;
}

/* True iff any bit beyond [0, num_chunks) is set in the last byte — a sign the
 * bitmap on disk is inconsistent with the pinned num_chunks. */
static bool rj_has_stray_bits(const uint8_t *bm, uint32_t bitmap_bytes,
                              uint32_t num_chunks)
{
    uint32_t full_bytes = num_chunks >> 3;
    uint32_t tail_bits = num_chunks & 7u;
    if (tail_bits && full_bytes < bitmap_bytes) {
        uint8_t mask = (uint8_t)(0xFFu << tail_bits); /* bits >= tail_bits */
        if (bm[full_bytes] & mask)
            return true;
    }
    return false;
}

/* Fill `h` for the manifest identity (caller-owned buffer). */
static void rj_fill_header(struct rom_journal_header *h,
                           const uint8_t chunk_root[32],
                           const uint8_t whole_sha3[32],
                           uint32_t chunk_size, uint32_t num_chunks)
{
    memset(h, 0, sizeof(*h));
    memcpy(h->magic, ROM_JOURNAL_MAGIC, ROM_JOURNAL_MAGIC_LEN);
    h->version = ROM_JOURNAL_VERSION;
    h->chunk_size = chunk_size;
    h->num_chunks = num_chunks;
    h->reserved = 0;
    memcpy(h->chunk_root, chunk_root, 32);
    memcpy(h->whole_sha3, whole_sha3, 32);
}

/* Allocate + zero-init a handle wrapping `fd`. Returns NULL on OOM (fd left
 * open for the caller to close). */
static struct rom_journal *rj_alloc(int fd, uint32_t num_chunks,
                                    uint32_t bitmap_bytes)
{
    struct rom_journal *j = zcl_malloc(sizeof(*j), "rom_journal_handle");
    if (!j)
        return NULL;
    j->bitmap = zcl_malloc(bitmap_bytes, "rom_journal_bitmap");
    if (!j->bitmap) {
        free(j);
        return NULL;
    }
    memset(j->bitmap, 0, bitmap_bytes);
    j->fd = fd;
    j->num_chunks = num_chunks;
    j->bitmap_bytes = bitmap_bytes;
    j->done = 0;
    pthread_mutex_init(&j->lock, NULL);
    return j;
}

/* Truncate + (re)write a fresh header and zeroed bitmap onto `fd`, then
 * fdatasync. Returns the handle, or NULL on IO failure (fd closed on error). */
static struct rom_journal *rj_create_fresh(int fd,
                                           const uint8_t chunk_root[32],
                                           const uint8_t whole_sha3[32],
                                           uint32_t chunk_size,
                                           uint32_t num_chunks,
                                           uint32_t bitmap_bytes)
{
    if (ftruncate(fd, 0) != 0) {
        close(fd);
        LOG_NULL(RJ_SUBSYS, "create: ftruncate failed errno=%d", errno);
    }
    struct rom_journal_header h;
    rj_fill_header(&h, chunk_root, whole_sha3, chunk_size, num_chunks);
    if (pwrite(fd, &h, sizeof(h), 0) != (ssize_t)sizeof(h)) {
        close(fd);
        LOG_NULL(RJ_SUBSYS, "create: header pwrite failed errno=%d", errno);
    }

    struct rom_journal *j = rj_alloc(fd, num_chunks, bitmap_bytes);
    if (!j) {
        close(fd);
        LOG_NULL(RJ_SUBSYS, "create: handle alloc failed");
    }
    /* bitmap is already zeroed in rj_alloc; persist the zeroed region. */
    if (pwrite(fd, j->bitmap, bitmap_bytes, RJ_BITMAP_OFFSET) !=
        (ssize_t)bitmap_bytes) {
        rom_journal_close(j);
        LOG_NULL(RJ_SUBSYS, "create: bitmap pwrite failed errno=%d", errno);
    }
    if (platform_data_sync(fd) != 0) {
        rom_journal_close(j);
        LOG_NULL(RJ_SUBSYS, "create: fdatasync failed errno=%d", errno);
    }
    return j;
}

struct rom_journal *rom_journal_open(const char *journal_path,
                                     const uint8_t chunk_root[32],
                                     const uint8_t whole_sha3[32],
                                     uint32_t chunk_size, uint32_t num_chunks)
{
    if (!journal_path || !chunk_root || !whole_sha3)
        LOG_NULL(RJ_SUBSYS, "open: NULL arg");
    if (num_chunks == 0 || num_chunks > RJ_MAX_NUM_CHUNKS)
        LOG_NULL(RJ_SUBSYS, "open: num_chunks %u out of range", num_chunks);
    if (chunk_size == 0)
        LOG_NULL(RJ_SUBSYS, "open: chunk_size 0");

    uint32_t bitmap_bytes = (num_chunks + 7u) / 8u;

    /* Try to resume an existing journal. */
    int fd = open(journal_path, O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        struct rom_journal_header disk;
        struct rom_journal_header want;
        rj_fill_header(&want, chunk_root, whole_sha3, chunk_size, num_chunks);

        bool header_ok = (pread(fd, &disk, sizeof(disk), 0) ==
                          (ssize_t)sizeof(disk)) &&
                         memcmp(&disk, &want, sizeof(disk)) == 0;
        if (header_ok) {
            struct rom_journal *j = rj_alloc(fd, num_chunks, bitmap_bytes);
            if (!j) {
                close(fd);
                LOG_NULL(RJ_SUBSYS, "open: resume handle alloc failed");
            }
            ssize_t br = pread(fd, j->bitmap, bitmap_bytes, RJ_BITMAP_OFFSET);
            if (br != (ssize_t)bitmap_bytes ||
                rj_has_stray_bits(j->bitmap, bitmap_bytes, num_chunks)) {
                /* Short/garbage bitmap → do not partially trust; rewrite
                 * fresh onto the same fd. rj_alloc's mutex/bitmap are freed
                 * here; rj_create_fresh makes its own. */
                int reuse_fd = j->fd;
                j->fd = -1;             /* keep fd open across close()        */
                rom_journal_close(j);
                LOG_WARN(RJ_SUBSYS, "open: '%s' bitmap unreadable/inconsistent"
                         " — discarding, starting fresh", journal_path);
                return rj_create_fresh(reuse_fd, chunk_root, whole_sha3,
                                       chunk_size, num_chunks, bitmap_bytes);
            }
            j->done = rj_popcount_bitmap(j->bitmap, bitmap_bytes, num_chunks);
            LOG_INFO(RJ_SUBSYS, "open: resuming '%s' (%u/%u chunks already "
                     "verified)", journal_path, j->done, num_chunks);
            return j;
        }

        /* Header mismatch (different artifact / stale journal): discard and
         * start fresh on the same fd. */
        LOG_WARN(RJ_SUBSYS, "open: '%s' header mismatch — discarding stale "
                 "journal, starting fresh", journal_path);
        return rj_create_fresh(fd, chunk_root, whole_sha3, chunk_size,
                               num_chunks, bitmap_bytes);
    }

    if (errno != ENOENT)
        LOG_NULL(RJ_SUBSYS, "open: open('%s') failed errno=%d",
                 journal_path, errno);

    /* No journal yet: create one. */
    fd = open(journal_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        LOG_NULL(RJ_SUBSYS, "open: create('%s') failed errno=%d",
                 journal_path, errno);
    return rj_create_fresh(fd, chunk_root, whole_sha3, chunk_size, num_chunks,
                           bitmap_bytes);
}

bool rom_journal_is_done(const struct rom_journal *j, uint32_t idx)
{
    if (!j || idx >= j->num_chunks)
        return false; /* raw-return-ok: out-of-range / NULL is "not done" */
    struct rom_journal *m = (struct rom_journal *)j; /* mutex is logically mutable */
    pthread_mutex_lock(&m->lock);
    bool set = (j->bitmap[idx >> 3] & (uint8_t)(1u << (idx & 7u))) != 0;
    pthread_mutex_unlock(&m->lock);
    return set;
}

bool rom_journal_mark(struct rom_journal *j, uint32_t idx)
{
    if (!j)
        LOG_FAIL(RJ_SUBSYS, "mark: NULL journal handle");
    if (idx >= j->num_chunks)
        LOG_FAIL(RJ_SUBSYS, "mark: idx %u >= num_chunks %u", idx, j->num_chunks);

    pthread_mutex_lock(&j->lock);
    uint32_t byte = idx >> 3;
    uint8_t bit = (uint8_t)(1u << (idx & 7u));
    if (j->bitmap[byte] & bit) {
        pthread_mutex_unlock(&j->lock);
        return true; /* idempotent: already durably recorded */
    }
    j->bitmap[byte] |= bit;
    /* Persist the single changed byte, then fdatasync so a set bit always
     * implies durable data (the caller fdatasync'd the .part first). */
    bool ok = pwrite(j->fd, &j->bitmap[byte], 1,
                     RJ_BITMAP_OFFSET + (off_t)byte) == 1 &&
              platform_data_sync(j->fd) == 0;
    if (!ok) {
        j->bitmap[byte] &= (uint8_t)~bit; /* roll back the in-memory bit */
        pthread_mutex_unlock(&j->lock);
        LOG_FAIL(RJ_SUBSYS, "mark: persist idx %u failed errno=%d", idx, errno);
    }
    j->done++;
    pthread_mutex_unlock(&j->lock);
    return true;
}

uint32_t rom_journal_count_done(const struct rom_journal *j)
{
    if (!j)
        return 0u; /* raw-return-ok: pure accessor, 0 when absent */
    struct rom_journal *m = (struct rom_journal *)j;
    pthread_mutex_lock(&m->lock);
    uint32_t d = j->done;
    pthread_mutex_unlock(&m->lock);
    return d;
}

void rom_journal_close(struct rom_journal *j)
{
    if (!j)
        return;
    if (j->fd >= 0)
        (void)close(j->fd);
    pthread_mutex_destroy(&j->lock);
    free(j->bitmap);
    free(j);
}

bool rom_journal_discard(const char *journal_path)
{
    if (!journal_path)
        LOG_FAIL(RJ_SUBSYS, "discard: NULL journal_path");
    if (unlink(journal_path) != 0 && errno != ENOENT)
        LOG_FAIL(RJ_SUBSYS, "discard: unlink(%s) failed errno=%d",
                 journal_path, errno);
    return true;
}
