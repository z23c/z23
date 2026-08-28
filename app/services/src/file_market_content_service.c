/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Seller-side paid content registration and verified chunk loading. */

#include "services/file_market_content_service.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "models/file_offer.h"
#include "net/file_market.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/file_compat.h"
#include "platform/path_compat.h"

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
    MARKET_CONTENT_ERR_STALE = -10,
    MARKET_CONTENT_ERR_TXN = -11,
    MARKET_CONTENT_ERR_STATE = -12,
};

static pthread_mutex_t g_content_registration_mutex =
    PTHREAD_MUTEX_INITIALIZER;

#ifdef ZCL_TESTING
static file_market_content_precommit_test_hook_fn g_precommit_test_hook;
static void *g_precommit_test_hook_ctx;

void file_market_content_set_precommit_test_hook(
    file_market_content_precommit_test_hook_fn hook, void *ctx)
{
    g_precommit_test_hook = hook;
    g_precommit_test_hook_ctx = ctx;
}
#endif

static bool market_content_read_exact(int fd, uint8_t *out, size_t size,
                                      uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t got = platform_file_pread(fd, out + done, size - done,
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

    int source_fd = platform_file_open_nofollow(
        content_path, O_RDONLY | O_CLOEXEC, 0);
    if (source_fd < 0)
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "content reference is unavailable or is a symbolic link");
    struct stat source_stat;
    struct platform_file_identity source_identity;
    if (fstat(source_fd, &source_stat) != 0 ||
        !S_ISREG(source_stat.st_mode) || source_stat.st_size <= 0 ||
        !platform_file_identity_read(source_fd, &source_identity)) {
        close(source_fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_TYPE,
                       "content reference must be a non-empty regular file");
    }

    char canonical[MARKET_CONTENT_PATH_MAX];
#if defined(_WIN32)
    if (!platform_path_resolve(canonical, sizeof(canonical), content_path)) {
#else
    if (!realpath(content_path, canonical)) {
#endif
        close(source_fd);
        return ZCL_ERR(MARKET_CONTENT_ERR_OPEN,
                       "content reference could not be canonicalized");
    }
    int fd = platform_file_open_nofollow(canonical, O_RDONLY | O_CLOEXEC, 0);
    struct stat canonical_stat;
    struct platform_file_identity canonical_identity;
    if (fd < 0 || fstat(fd, &canonical_stat) != 0 ||
        !S_ISREG(canonical_stat.st_mode) ||
        !platform_file_identity_read(fd, &canonical_identity) ||
        memcmp(&source_identity, &canonical_identity,
               sizeof(source_identity)) != 0) {
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
    struct platform_file_identity after_identity;
    bool stable = fstat(fd, &after_stat) == 0 &&
        platform_file_identity_read(fd, &after_identity) &&
        memcmp(&canonical_identity, &after_identity,
               sizeof(canonical_identity)) == 0 &&
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

static struct zcl_result market_content_plan_snapshot(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    uint8_t token_out[32],
    char state_out[MARKET_CONTENT_REGISTRATION_STATE_MAX],
    struct file_offer *offer_out)
{
    if (!ndb || !ndb->open || !offer_id || !content_path ||
        !content_path[0] ||
        strnlen(content_path, MARKET_CONTENT_PATH_MAX) >=
            MARKET_CONTENT_PATH_MAX ||
        !token_out || !state_out)
        return ZCL_ERR(MARKET_CONTENT_ERR_ARGS,
                       "registration plan inputs are required");
    memset(token_out, 0, 32);
    state_out[0] = '\0';

    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, offer_id, &offer))
        return ZCL_ERR(MARKET_CONTENT_ERR_OFFER,
                       "authenticated current paid offer not found");
    uint8_t offer_wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t offer_wire_len = 0;
    if (file_offer_auth_encode_into(&offer, offer_wire, sizeof(offer_wire),
                                    &offer_wire_len) != FILE_OFFER_AUTH_OK ||
        offer_wire_len == 0)
        return ZCL_ERR(MARKET_CONTENT_ERR_OFFER,
                       "authenticated offer has no canonical wire");

    uint8_t identity[32];
    enum market_content_state_result state =
        db_market_content_registration_identity(ndb, offer_id, identity);
    if (state == MARKET_CONTENT_STATE_ERROR)
        return ZCL_ERR(MARKET_CONTENT_ERR_STATE,
                       "content registration state could not be read");
    if (state == MARKET_CONTENT_STATE_PRESENT) {
        char identity_hex[65];
        zcl_hex_encode(identity, 32, identity_hex);
        snprintf(state_out, MARKET_CONTENT_REGISTRATION_STATE_MAX,
                 "registered@%s", identity_hex);
    } else {
        snprintf(state_out, MARKET_CONTENT_REGISTRATION_STATE_MAX,
                 "unregistered");
    }

    static const char domain[] = "zcl.market.content.plan.v2";
    uint8_t encoded[8];
    uint8_t state_byte = (uint8_t)state;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    zcl_write_u64_le(encoded, offer_wire_len);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, offer_wire, offer_wire_len);
    sha3_256_write(&sha, &state_byte, 1);
    if (state == MARKET_CONTENT_STATE_PRESENT)
        sha3_256_write(&sha, identity, sizeof(identity));
    size_t path_len = strlen(content_path);
    zcl_write_u64_le(encoded, path_len);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    sha3_256_write(&sha, (const uint8_t *)content_path, path_len);
    sha3_256_finalize(&sha, token_out);
    if (offer_out)
        *offer_out = offer;
    return ZCL_OK;
}

struct zcl_result file_market_content_registration_plan(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    uint8_t token_out[32],
    char state_out[MARKET_CONTENT_REGISTRATION_STATE_MAX])
{
    return market_content_plan_snapshot(ndb, offer_id, content_path,
                                        token_out, state_out, NULL);
}

static void market_content_record_fill(
    struct market_content_record *record, const struct file_offer *offer,
    const char *canonical, const uint8_t root[32], uint64_t size_bytes,
    uint32_t num_chunks, const uint8_t *hashes, int64_t now_unix)
{
    memset(record, 0, sizeof(*record));
    memcpy(record->offer_id, offer->offer_id, 32);
    memcpy(record->root_hash, root, 32);
    snprintf(record->private_path, sizeof(record->private_path), "%s",
             canonical);
    record->size_bytes = size_bytes;
    record->num_chunks = num_chunks;
    record->chunk_hashes = hashes;
    record->chunk_hashes_len = (size_t)num_chunks * 32u;
    record->registered_at = now_unix;
}

static void market_content_public_fill(
    struct market_content_public_record *out,
    const struct market_content_record *record)
{
    memcpy(out->offer_id, record->offer_id, 32);
    memcpy(out->root_hash, record->root_hash, 32);
    out->size_bytes = record->size_bytes;
    out->num_chunks = record->num_chunks;
    out->registered_at = record->registered_at;
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
    market_content_record_fill(&record, &offer, canonical, root, size_bytes,
                               num_chunks, hashes, now_unix);
    pthread_mutex_lock(&g_content_registration_mutex);
    bool saved = db_market_content_save(ndb, &record);
    pthread_mutex_unlock(&g_content_registration_mutex);
    free(hashes);
    if (!saved)
        return ZCL_ERR(MARKET_CONTENT_ERR_SAVE,
                       "private content registration could not be persisted");

    market_content_public_fill(out, &record);
    return ZCL_OK;
}

struct zcl_result file_market_content_register_planned(
    struct node_db *ndb, const uint8_t offer_id[32], const char *content_path,
    const uint8_t plan_token[32], int64_t now_unix,
    struct market_content_public_record *out)
{
    if (!ndb || !ndb->open || !offer_id || !content_path ||
        !content_path[0] || !plan_token || !out || now_unix <= 0)
        return ZCL_ERR(MARKET_CONTENT_ERR_ARGS,
                       "database, offer id, content reference, plan token, time, and output are required");
    memset(out, 0, sizeof(*out));

    char canonical[MARKET_CONTENT_PATH_MAX];
    uint8_t *hashes = NULL;
    uint64_t size_bytes = 0;
    uint32_t num_chunks = 0;
    uint8_t root[32];
    struct zcl_result manifest = file_market_content_manifest_build(
        content_path, canonical, &hashes, &size_bytes, &num_chunks, root);
    if (!manifest.ok)
        return manifest;

#ifdef ZCL_TESTING
    if (g_precommit_test_hook)
        g_precommit_test_hook(g_precommit_test_hook_ctx);
#endif

    struct zcl_result result = ZCL_ERR(
        MARKET_CONTENT_ERR_TXN,
        "content registration transaction could not be started");
    pthread_mutex_lock(&g_content_registration_mutex);
    if (!node_db_begin_immediate(ndb))
        goto done;

    uint8_t current_token[32];
    char current_state[MARKET_CONTENT_REGISTRATION_STATE_MAX];
    struct file_offer current_offer;
    struct zcl_result snapshot = market_content_plan_snapshot(
        ndb, offer_id, content_path, current_token, current_state,
        &current_offer);
    if (!snapshot.ok) {
        result = snapshot;
        goto rollback;
    }
    uint8_t difference = 0;
    for (size_t i = 0; i < 32; i++)
        difference |= current_token[i] ^ plan_token[i];
    if (difference) {
        result = ZCL_ERR(
            MARKET_CONTENT_ERR_STALE,
            "STALE_PLAN: the signed offer, registration, or target path moved after planning");
        goto rollback;
    }
    if (size_bytes != current_offer.size_bytes ||
        num_chunks != current_offer.num_chunks) {
        result = ZCL_ERR(MARKET_CONTENT_ERR_SIZE,
                         "content size does not match the signed offer");
        goto rollback;
    }
    if (memcmp(root, current_offer.root_hash, 32) != 0) {
        result = ZCL_ERR(MARKET_CONTENT_ERR_ROOT,
                         "content manifest root does not match the signed offer");
        goto rollback;
    }

    struct market_content_record record;
    market_content_record_fill(&record, &current_offer, canonical, root,
                               size_bytes, num_chunks, hashes, now_unix);
    if (!db_market_content_save(ndb, &record)) {
        result = ZCL_ERR(
            MARKET_CONTENT_ERR_SAVE,
            "private content registration could not be persisted");
        goto rollback;
    }
    if (!node_db_commit(ndb)) {
        result = ZCL_ERR(MARKET_CONTENT_ERR_TXN,
                         "content registration transaction could not commit");
        goto rollback;
    }
    market_content_public_fill(out, &record);
    result = ZCL_OK;
    goto done;

rollback:
    if (!node_db_rollback(ndb))
        LOG_ERROR("market", "content registration rollback failed");
done:
    pthread_mutex_unlock(&g_content_registration_mutex);
    free(hashes);
    return result;
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
#if !defined(_WIN32)
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtim;
    struct timespec ctim;
#endif
    uint8_t sha3[32];
};

#define MARKET_CONTENT_DIGEST_SLOTS 4
#if !defined(_WIN32)
static struct market_content_digest_entry
    g_content_digests[MARKET_CONTENT_DIGEST_SLOTS];
static pthread_mutex_t g_content_digests_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#if !defined(_WIN32)
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
#endif

static bool content_digest_lookup(const uint8_t offer_id[32],
                                  uint32_t chunk_index,
                                  uint32_t want,
                                  const struct stat *st,
                                  const uint8_t chunk_sha3[32],
                                  uint8_t digest_out[32])
{
#if defined(_WIN32)
    (void)offer_id; (void)chunk_index; (void)want; (void)st;
    (void)chunk_sha3; (void)digest_out;
    return false;
#else
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
#endif
}

static void content_digest_store(const uint8_t offer_id[32],
                                 uint32_t chunk_index,
                                 uint32_t want,
                                 const struct stat *st,
                                 const uint8_t digest[32])
{
#if defined(_WIN32)
    (void)offer_id; (void)chunk_index; (void)want; (void)st; (void)digest;
    return;
#else
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
#endif
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
    int fd = platform_file_open_nofollow(record.private_path,
                                         O_RDONLY | O_CLOEXEC, 0);
    struct stat st;
    struct platform_file_identity before_identity;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size != record.content.size_bytes ||
        !platform_file_identity_read(fd, &before_identity)) {
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
    struct platform_file_identity after_identity;
    bool stable = fstat(fd, &after) == 0 &&
        platform_file_identity_read(fd, &after_identity) &&
        memcmp(&before_identity, &after_identity,
               sizeof(before_identity)) == 0 &&
        after.st_size == st.st_size;
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
