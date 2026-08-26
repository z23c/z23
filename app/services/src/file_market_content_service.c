/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Seller-side paid content registration and verified chunk loading. */

#include "services/file_market_content_service.h"

#include "crypto/sha3.h"
#include "models/file_offer.h"
#include "net/file_market.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum market_content_error {
    MARKET_CONTENT_ERR_ARGS = -1,
    MARKET_CONTENT_ERR_OFFER = -2,
    MARKET_CONTENT_ERR_OPEN = -3,
    MARKET_CONTENT_ERR_TYPE = -4,
    MARKET_CONTENT_ERR_SIZE = -5,
    MARKET_CONTENT_ERR_LIMIT = -6,
    MARKET_CONTENT_ERR_IO = -7,
    MARKET_CONTENT_ERR_ROOT = -8,
    MARKET_CONTENT_ERR_SAVE = -9,
};

static bool market_content_read_exact(int fd, uint8_t *out, size_t size,
                                      uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t got = pread(fd, out + done, size - done,
                            (off_t)(offset + done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            LOG_FAIL("market", "private content exact read failed");
        done += (size_t)got;
    }
    return true;
}

static bool market_content_manifest(int fd, uint64_t size_bytes,
                                    uint32_t num_chunks, uint8_t *hashes,
                                    uint8_t root[32])
{
    size_t buffer_size = size_bytes < FILE_MARKET_CHUNK_SIZE
        ? (size_t)size_bytes : (size_t)FILE_MARKET_CHUNK_SIZE;
    uint8_t *buffer = zcl_malloc(buffer_size, "market content hash buffer");
    if (!buffer)
        LOG_FAIL("market", "private content hash buffer allocation failed");
    bool ok = true;
    for (uint32_t i = 0; i < num_chunks; i++) {
        uint64_t offset = (uint64_t)i * FILE_MARKET_CHUNK_SIZE;
        uint64_t remain = size_bytes - offset;
        size_t want = remain < FILE_MARKET_CHUNK_SIZE
            ? (size_t)remain : (size_t)FILE_MARKET_CHUNK_SIZE;
        if (!market_content_read_exact(fd, buffer, want, offset)) {
            ok = false;
            break;
        }
        sha3_256(buffer, want, hashes + (size_t)i * 32u);
    }
    free(buffer);
    if (!ok)
        return false;
    sha3_256(hashes, (size_t)num_chunks * 32u, root);
    return true;
}

struct zcl_result file_market_content_manifest_build(
    const char *content_path, char canonical_out[MARKET_CONTENT_PATH_MAX],
    uint8_t **hashes_out, uint64_t *size_out, uint32_t *chunks_out,
    uint8_t root_out[32])
{
    if (!content_path || !content_path[0] || !canonical_out || !size_out ||
        !chunks_out || !root_out)
        return ZCL_ERR(MARKET_CONTENT_ERR_ARGS,
                       "content reference and manifest outputs are required");

    int source_fd = open(content_path,
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source_fd < 0)
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "content reference is unavailable or is a symbolic link");
    struct stat source_stat;
    if (fstat(source_fd, &source_stat) != 0 ||
        !S_ISREG(source_stat.st_mode) || source_stat.st_size <= 0) {
        close(source_fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_TYPE,
                       "content reference must be a non-empty regular file");
    }

    char canonical[MARKET_CONTENT_PATH_MAX];
    if (!realpath(content_path, canonical)) {
        close(source_fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "content reference could not be canonicalized");
    }
    int fd = open(canonical,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat canonical_stat;
    if (fd < 0 || fstat(fd, &canonical_stat) != 0 ||
        !S_ISREG(canonical_stat.st_mode) ||
        canonical_stat.st_dev != source_stat.st_dev ||
        canonical_stat.st_ino != source_stat.st_ino) {
        if (fd >= 0) close(fd);
        close(source_fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "content reference changed during canonicalization");
    }
    close(source_fd);

    uint64_t size_bytes = (uint64_t)canonical_stat.st_size;
    uint32_t num_chunks = 0;
    if (!file_market_num_chunks_for_size(size_bytes, &num_chunks)) {
        close(fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_SIZE,
                       "content size overflows the chunk manifest");
    }
    if (num_chunks > MARKET_CONTENT_MAX_CHUNKS) {
        close(fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_LIMIT,
                       "content manifest exceeds the local registration limit");
    }

    size_t hashes_len = (size_t)num_chunks * 32u;
    uint8_t *hashes = zcl_malloc(hashes_len, "market content manifest");
    if (!hashes) {
        close(fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_LIMIT,
                       "content manifest allocation failed");
    }
    uint8_t root[32];
    bool hashed = market_content_manifest(fd, size_bytes, num_chunks,
                                          hashes, root);
    struct stat after_stat;
    bool stable = fstat(fd, &after_stat) == 0 &&
        after_stat.st_dev == canonical_stat.st_dev &&
        after_stat.st_ino == canonical_stat.st_ino &&
        after_stat.st_size == canonical_stat.st_size;
    close(fd);
    if (!hashed || !stable) {
        free(hashes);
        return ZCL_ERR(MARKET_CONTENT_ERR_IO,
                       "content changed or became unreadable while hashing");
    }

    snprintf(canonical_out, MARKET_CONTENT_PATH_MAX, "%s", canonical);
    *size_out = size_bytes;
    *chunks_out = num_chunks;
    memcpy(root_out, root, 32);
    if (hashes_out)
        *hashes_out = hashes;
    else
        free(hashes);
    return ZCL_OK;
}

struct zcl_result file_market_content_register(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    int64_t now_unix, struct market_content_public_record *out)
{
    if (!ndb || !ndb->open || !offer_id || !content_path ||
        !content_path[0] || !out || now_unix <= 0)
        return ZCL_ERR(MARKET_CONTENT_ERR_ARGS,
                       "database, offer id, content reference, time, and output are required");
    memset(out, 0, sizeof(*out));

    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, offer_id, &offer))
        return ZCL_ERR(MARKET_CONTENT_ERR_OFFER,
                       "authenticated current paid offer not found");

    char canonical[MARKET_CONTENT_PATH_MAX];
    uint8_t *hashes = NULL;
    uint64_t size_bytes = 0;
    uint32_t num_chunks = 0;
    uint8_t root[32];
    struct zcl_result manifest = file_market_content_manifest_build(
        content_path, canonical, &hashes, &size_bytes, &num_chunks, root);
    if (!manifest.ok)
        return manifest;
    size_t hashes_len = (size_t)num_chunks * 32u;
    if (size_bytes != offer.size_bytes || num_chunks != offer.num_chunks) {
        free(hashes);
        return ZCL_ERR(MARKET_CONTENT_ERR_SIZE,
                       "content size does not match the signed offer");
    }
    if (memcmp(root, offer.root_hash, 32) != 0) {
        free(hashes);
        return ZCL_ERR(MARKET_CONTENT_ERR_ROOT,
                       "content manifest root does not match the signed offer");
    }

    struct market_content_record record;
    memset(&record, 0, sizeof(record));
    memcpy(record.offer_id, offer.offer_id, 32);
    memcpy(record.root_hash, root, 32);
    snprintf(record.private_path, sizeof(record.private_path), "%s",
             canonical);
    record.size_bytes = size_bytes;
    record.num_chunks = num_chunks;
    record.chunk_hashes = hashes;
    record.chunk_hashes_len = hashes_len;
    record.registered_at = now_unix;
    bool saved = db_market_content_save(ndb, &record);
    free(hashes);
    if (!saved)
        return ZCL_ERR(MARKET_CONTENT_ERR_SAVE,
                       "private content registration could not be persisted");

    memcpy(out->offer_id, record.offer_id, 32);
    memcpy(out->root_hash, record.root_hash, 32);
    out->size_bytes = record.size_bytes;
    out->num_chunks = record.num_chunks;
    out->registered_at = record.registered_at;
    return ZCL_OK;
}

/* Slice-serving runs one GET per <=60 KiB slice, and each call used to
 * re-hash the whole chunk (up to FILE_MARKET_CHUNK_SIZE = 50 MiB) only to
 * compare against the same immutable record.chunk_sha3. The digest table
 * below caches ONLY that computed digest, keyed on everything the chunk
 * read already proved about the backing inode (identity, size, mtime) and
 * the registered record it must match. The full read and pre/post
 * stability checks stay on every path, and the key includes st_ctim:
 * mtime alone can be restored with futimens(2) after an in-place rewrite,
 * but no userspace call sets ctime backwards — any rewrite of the backing
 * bytes therefore forces a full re-hash here against the actual bytes, so
 * a stale digest can never pass for changed content. This is a
 * derived projection of verification already performed, not a second
 * source of truth: entries are replaced by exact key match and never
 * trusted past the next full read. */
struct market_content_digest_entry {
    bool used;
    uint8_t offer_id[32];
    uint32_t chunk_index;
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtim;
    struct timespec ctim;
    uint8_t sha3[32];
};

#define MARKET_CONTENT_DIGEST_SLOTS 4
static struct market_content_digest_entry
    g_content_digests[MARKET_CONTENT_DIGEST_SLOTS];
static pthread_mutex_t g_content_digests_mutex = PTHREAD_MUTEX_INITIALIZER;

static void content_digest_slot_stage(struct market_content_digest_entry *staged,
                                      const uint8_t offer_id[32],
                                      uint32_t chunk_index,
                                      const struct stat *st,
                                      const uint8_t sha3[32])
{
    memset(staged, 0, sizeof(*staged));
    staged->used = true;
    memcpy(staged->offer_id, offer_id, 32);
    staged->chunk_index = chunk_index;
    staged->dev = st->st_dev;
    staged->ino = st->st_ino;
    staged->size = st->st_size;
    staged->mtim = st->st_mtim;
    staged->ctim = st->st_ctim;
    memcpy(staged->sha3, sha3, 32);
}

static bool content_digest_lookup(const uint8_t offer_id[32],
                                  uint32_t chunk_index,
                                  uint32_t want,
                                  const struct stat *st,
                                  const uint8_t chunk_sha3[32],
                                  uint8_t digest_out[32])
{
    /* The key must pin both the exact bytes observed this call and the
     * registration the digest will be compared against; anything less
     * reruns the hash. */
    if ((uint64_t)st->st_size != (uint64_t)want)
        return false;
    pthread_mutex_lock(&g_content_digests_mutex);
    for (size_t i = 0; i < MARKET_CONTENT_DIGEST_SLOTS; i++) {
        struct market_content_digest_entry *e = &g_content_digests[i];
        if (!e->used || e->dev != st->st_dev || e->ino != st->st_ino ||
            e->mtim.tv_sec != st->st_mtim.tv_sec ||
            e->mtim.tv_nsec != st->st_mtim.tv_nsec ||
            e->ctim.tv_sec != st->st_ctim.tv_sec ||
            e->ctim.tv_nsec != st->st_ctim.tv_nsec ||
            memcmp(e->offer_id, offer_id, 32) != 0 ||
            e->chunk_index != chunk_index ||
            memcmp(e->sha3, chunk_sha3, 32) != 0)
            continue;
        memcpy(digest_out, e->sha3, 32);
        pthread_mutex_unlock(&g_content_digests_mutex);
        return true;
    }
    pthread_mutex_unlock(&g_content_digests_mutex);
    return false;
}

static void content_digest_store(const uint8_t offer_id[32],
                                 uint32_t chunk_index,
                                 uint32_t want,
                                 const struct stat *st,
                                 const uint8_t digest[32])
{
    if ((uint64_t)st->st_size != (uint64_t)want)
        return;
    struct market_content_digest_entry staged;
    content_digest_slot_stage(&staged, offer_id, chunk_index, st, digest);
    pthread_mutex_lock(&g_content_digests_mutex);
    struct market_content_digest_entry *chosen = &g_content_digests[0];
    for (size_t i = 0; i < MARKET_CONTENT_DIGEST_SLOTS; i++) {
        struct market_content_digest_entry *e = &g_content_digests[i];
        if (!e->used) {
            chosen = e; /* prefer a genuinely free slot */
            break;
        }
        if (e->dev == st->st_dev && e->ino == st->st_ino &&
            memcmp(e->offer_id, offer_id, 32) == 0 &&
            e->chunk_index == chunk_index) {
            chosen = e; /* same identity, stats moved: replace in place */
            break;
        }
    }
    *chosen = staged;
    pthread_mutex_unlock(&g_content_digests_mutex);
}

struct zcl_result file_market_content_load_chunk(
    struct node_db *ndb, const uint8_t offer_id[32], uint32_t chunk_index,
    struct file_market_delivery_chunk *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !offer_id || !out)
        return ZCL_ERR(MARKET_CONTENT_ERR_ARGS,
                       "private content load requires complete inputs");

    struct market_content_chunk_record record;
    if (!db_market_content_find_chunk(ndb, offer_id, chunk_index, &record))
        return ZCL_ERR(MARKET_CONTENT_ERR_OFFER,
                       "private content chunk is not registered");
    int fd = open(record.private_path,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size != record.content.size_bytes) {
        if (fd >= 0) close(fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "registered private content is unavailable or changed");
    }

    uint64_t offset = (uint64_t)chunk_index * FILE_MARKET_CHUNK_SIZE;
    uint64_t remain = record.content.size_bytes - offset;
    uint32_t want = remain < FILE_MARKET_CHUNK_SIZE
        ? (uint32_t)remain : (uint32_t)FILE_MARKET_CHUNK_SIZE;
    uint8_t *data = zcl_malloc(want, "market paid content chunk");
    if (!data) {
        close(fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_LIMIT,
                       "private content chunk allocation failed");
    }
    bool read_ok = market_content_read_exact(fd, data, want, offset);
    struct stat after;
    bool stable = fstat(fd, &after) == 0 && after.st_dev == st.st_dev &&
        after.st_ino == st.st_ino && after.st_size == st.st_size;
    close(fd);
    uint8_t digest[32];
    if (!read_ok || !stable) {
        free(data);
        return ZCL_ERR(MARKET_CONTENT_ERR_IO,
                       "registered private content read was not stable");
    }
    if (!content_digest_lookup(offer_id, chunk_index, want, &after,
                               record.chunk_sha3, digest)) {
        sha3_256(data, want, digest);
        content_digest_store(offer_id, chunk_index, want, &after, digest);
    }
    if (memcmp(digest, record.chunk_sha3, 32) != 0) {
        free(data);
        return ZCL_ERR(MARKET_CONTENT_ERR_ROOT,
                       "registered private content chunk digest mismatch");
    }
    out->data = data;
    out->size = want;
    memcpy(out->sha3, digest, 32);
    return ZCL_OK;
}
