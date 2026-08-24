/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: restart-safe authenticated buyer retrieval and publication. */

#include "services/file_market_purchase_service.h"
#include "services/file_market_purchase_internal.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/market_download.h"
#include "models/vault_intent.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum file_market_delivery_status market_purchase_fetch_endpoint(
    void *ctx, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk)
{
    (void)ctx;
    return file_market_delivery_fetch_endpoint_until(
        peer_ip, peer_port, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, deadline_ms, out_chunk);
}

enum file_market_delivery_status market_purchase_fetch_onion_endpoint(
    void *ctx, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk)
{
    (void)ctx;
    return file_market_delivery_fetch_onion_endpoint_until(
        seller_onion_pubkey, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, deadline_ms, out_chunk);
}

static bool mp_private_paths(const uint8_t plan_id[32],
                             const char *destination,
                             char canonical[MARKET_DOWNLOAD_PATH_MAX],
                             char staging[MARKET_DOWNLOAD_PATH_MAX],
                             char parent[MARKET_DOWNLOAD_PATH_MAX])
{
    if (!plan_id || !destination || destination[0] != '/' ||
        strnlen(destination, MARKET_DOWNLOAD_PATH_MAX) >=
            MARKET_DOWNLOAD_PATH_MAX)
        return false; // raw-return-ok:pure bounded path parser
    const char *slash = strrchr(destination, '/');
    const char *base = slash ? slash + 1 : NULL;
    if (!slash || !base || !base[0] || strcmp(base, ".") == 0 ||
        strcmp(base, "..") == 0)
        return false; // raw-return-ok:pure bounded path parser
    char parent_input[MARKET_DOWNLOAD_PATH_MAX];
    size_t parent_len = (size_t)(slash - destination);
    if (parent_len == 0) parent_len = 1;
    if (parent_len >= sizeof(parent_input))
        return false; // raw-return-ok:pure bounded path parser
    memcpy(parent_input, destination, parent_len);
    parent_input[parent_len] = '\0';
    if (!realpath(parent_input, parent))
        return false; // raw-return-ok:caller returns private-path-safe error
    int n = snprintf(canonical, MARKET_DOWNLOAD_PATH_MAX, "%s/%s",
                     strcmp(parent, "/") == 0 ? "" : parent, base);
    char plan_hex[65];
    zcl_hex_encode(plan_id, 32, plan_hex);
    int s = snprintf(staging, MARKET_DOWNLOAD_PATH_MAX,
                     "%s/.zclassic23-market-%s.part",
                     strcmp(parent, "/") == 0 ? "" : parent, plan_hex);
    return n > 0 && n < (int)MARKET_DOWNLOAD_PATH_MAX &&
           s > 0 && s < (int)MARKET_DOWNLOAD_PATH_MAX;
}

static bool mp_read_exact_at(int fd, uint8_t *out, size_t size,
                             uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t got = pread(fd, out + done, size - done,
                            (off_t)(offset + done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false; // raw-return-ok:caller reports bounded IO failure
        done += (size_t)got;
    }
    return true;
}

static bool mp_write_exact_at(int fd, const uint8_t *data, size_t size,
                              uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t wrote = pwrite(fd, data + done, size - done,
                               (off_t)(offset + done));
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return false; // raw-return-ok:caller reports bounded IO failure
        done += (size_t)wrote;
    }
    return true;
}

static uint32_t mp_chunk_size(const struct file_offer *offer, uint32_t index)
{
    uint64_t offset = (uint64_t)index * FILE_MARKET_CHUNK_SIZE;
    uint64_t remain = offer->size_bytes - offset;
    return remain < FILE_MARKET_CHUNK_SIZE
        ? (uint32_t)remain : (uint32_t)FILE_MARKET_CHUNK_SIZE;
}

static void mp_chunk_discard(struct file_market_delivery_chunk *chunk)
{
    if (!chunk)
        return;
    if (chunk->data && chunk->size > 0)
        memory_cleanse(chunk->data, chunk->size);
    free(chunk->data);
    memset(chunk, 0, sizeof(*chunk));
}

static bool mp_deadline_active(int64_t deadline_ms)
{
    int64_t now_ms = platform_time_monotonic_ms();
    return now_ms > 0 && now_ms < deadline_ms;
}

static bool mp_verify_staged(struct node_db *ndb,
                             const struct market_download_record *download,
                             int fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
        return false; // raw-return-ok:caller names staging verification error
    if ((uint64_t)st.st_size > download->bytes_received &&
        ftruncate(fd, (off_t)download->bytes_received) != 0)
        return false; // raw-return-ok:caller names staging verification error
    if ((uint64_t)st.st_size < download->bytes_received ||
        db_market_download_chunk_count(ndb, download->plan_id) !=
            (int)download->chunks_received)
        return false; // raw-return-ok:caller names staging verification error
    uint64_t offset = 0;
    for (uint32_t i = 0; i < download->chunks_received; i++) {
        struct market_download_chunk_record chunk;
        if (!db_market_download_chunk_find(ndb, download->plan_id, i,
                                            &chunk) ||
            chunk.size_bytes == 0 || offset > download->bytes_received ||
            chunk.size_bytes > download->bytes_received - offset)
            return false; // raw-return-ok:caller names staging verification error
        uint8_t *buffer = zcl_malloc(chunk.size_bytes,
                                     "market download resume buffer");
        if (!buffer)
            return false; // raw-return-ok:caller names bounded allocation error
        bool read_ok = mp_read_exact_at(fd, buffer, chunk.size_bytes, offset);
        uint8_t digest[32];
        if (read_ok) sha3_256(buffer, chunk.size_bytes, digest);
        memory_cleanse(buffer, chunk.size_bytes);
        free(buffer);
        bool digest_ok = read_ok &&
            memcmp(digest, chunk.chunk_sha3, 32) == 0;
        memory_cleanse(digest, sizeof(digest));
        if (!digest_ok)
            return false; // raw-return-ok:caller names staging verification error
        offset += chunk.size_bytes;
    }
    return offset == download->bytes_received;
}

static bool mp_manifest_root(struct node_db *ndb,
                             const struct market_download_record *download,
                             uint8_t root[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    for (uint32_t i = 0; i < download->num_chunks; i++) {
        struct market_download_chunk_record chunk;
        if (!db_market_download_chunk_find(ndb, download->plan_id, i,
                                            &chunk))
            return false; // raw-return-ok:caller names incomplete manifest
        sha3_256_write(&sha, chunk.chunk_sha3, 32);
    }
    sha3_256_finalize(&sha, root);
    return true;
}

static bool mp_fsync_parent(const char *parent)
{
    int fd = open(parent, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0)
        return false; // raw-return-ok:caller reports atomic publish failure
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static struct zcl_result mp_download_initialize(
    const struct market_purchase_runtime *rt,
    const struct vault_intent_row *row, const struct file_offer *offer,
    const char *destination, struct market_download_record *download,
    char parent[MARKET_DOWNLOAD_PATH_MAX])
{
    char canonical[MARKET_DOWNLOAD_PATH_MAX];
    char staging[MARKET_DOWNLOAD_PATH_MAX];
    if (!mp_private_paths(row->plan_id, destination, canonical, staging,
                          parent))
        return ZCL_ERR(-60, "destination must name a file in an existing absolute directory");
    if (db_market_download_find(rt->node_db, row->plan_id, download)) {
        if (strcmp(download->private_destination, canonical) != 0 ||
            strcmp(download->private_staging, staging) != 0 ||
            memcmp(download->offer_id, offer->offer_id, 32) != 0 ||
            memcmp(download->root_hash, offer->root_hash, 32) != 0 ||
            download->size_bytes != offer->size_bytes ||
            download->num_chunks != offer->num_chunks)
            return ZCL_ERR(-61, "purchase download is already bound to different immutable terms");
        return ZCL_OK;
    }
    struct stat existing;
    if (lstat(canonical, &existing) == 0 || errno != ENOENT)
        return ZCL_ERR(-62, "destination already exists or cannot be inspected");
    int fd = open(staging, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
                           O_NOFOLLOW, 0600);
    if (fd < 0)
        return ZCL_ERR(-63, "private staging file could not be created");
    close(fd);
    memset(download, 0, sizeof(*download));
    memcpy(download->plan_id, row->plan_id, 32);
    memcpy(download->offer_id, offer->offer_id, 32);
    memcpy(download->root_hash, offer->root_hash, 32);
    snprintf(download->private_destination,
             sizeof(download->private_destination), "%s", canonical);
    snprintf(download->private_staging,
             sizeof(download->private_staging), "%s", staging);
    download->size_bytes = offer->size_bytes;
    download->num_chunks = offer->num_chunks;
    download->state = MARKET_DOWNLOAD_FETCHING;
    download->created_at = rt->now_unix;
    download->updated_at = rt->now_unix;
    if (!db_market_download_save(rt->node_db, download)) {
        (void)unlink(staging);
        return ZCL_ERR(-64, "durable download could not be initialized");
    }
    return ZCL_OK;
}

static struct zcl_result mp_download_record_chunk(
    const struct market_purchase_runtime *rt,
    struct market_download_record *download, uint32_t index,
    const struct file_market_delivery_chunk *chunk)
{
    struct market_download_chunk_record record;
    memset(&record, 0, sizeof(record));
    memcpy(record.plan_id, download->plan_id, 32);
    record.chunk_index = index;
    record.size_bytes = chunk->size;
    memcpy(record.chunk_sha3, chunk->sha3, 32);
    record.created_at = rt->now_unix;
    if (!node_db_begin(rt->node_db))
        return ZCL_ERR(-65, "download progress transaction could not begin");
    bool saved = db_market_download_chunk_save(rt->node_db, &record);
    if (saved) {
        download->chunks_received++;
        download->bytes_received += chunk->size;
        download->updated_at = rt->now_unix;
        saved = db_market_download_save(rt->node_db, download);
    }
    if (!saved || !node_db_commit(rt->node_db)) {
        (void)node_db_rollback(rt->node_db);
        return ZCL_ERR(-66, "download progress could not be committed atomically");
    }
    return ZCL_OK;
}

static struct zcl_result mp_publish_download(
    const struct market_purchase_runtime *rt,
    struct market_download_record *download, int fd, const char *parent)
{
    uint8_t root[32];
    if (download->chunks_received != download->num_chunks ||
        download->bytes_received != download->size_bytes ||
        !mp_manifest_root(rt->node_db, download, root) ||
        memcmp(root, download->root_hash, 32) != 0 ||
        ftruncate(fd, (off_t)download->size_bytes) != 0 || fsync(fd) != 0)
        return ZCL_ERR(-67, "complete downloaded manifest failed verification");

    struct stat staging_stat, destination_stat;
    if (fstat(fd, &staging_stat) != 0)
        return ZCL_ERR(-68, "private staging identity is unavailable");
    bool linked = link(download->private_staging,
                       download->private_destination) == 0;
    if (!linked) {
        if (errno != EEXIST ||
            lstat(download->private_destination, &destination_stat) != 0 ||
            destination_stat.st_dev != staging_stat.st_dev ||
            destination_stat.st_ino != staging_stat.st_ino)
            return ZCL_ERR(-69, "destination publication conflicted");
    }
    if (!mp_fsync_parent(parent))
        return ZCL_ERR(-70, "destination directory durability failed");
    download->state = MARKET_DOWNLOAD_COMPLETE;
    download->updated_at = rt->now_unix;
    if (!db_market_download_save(rt->node_db, download))
        return ZCL_ERR(-71, "published destination state could not be persisted");
    if (unlink(download->private_staging) != 0 && errno != ENOENT)
        return ZCL_ERR(-72, "published staging reference could not be retired");
    if (!mp_fsync_parent(parent))
        return ZCL_ERR(-73, "published directory cleanup was not durable");
    return ZCL_OK;
}

struct zcl_result market_purchase_retrieve(
    const struct market_purchase_runtime *rt, const uint8_t plan_id[32],
    const char *destination_path, struct market_purchase_view *out)
{
    ZCL_CHECK(market_purchase_runtime_validate(rt, false, false));
    int64_t retrieve_started_ms = platform_time_monotonic_ms();
    if (!plan_id || !destination_path || !destination_path[0] || !out ||
        !rt->fetch)
        return ZCL_ERR(-58, "plan id, private destination, output, and fetch transport are required");
    struct vault_intent_row row;
    if (!vault_intent_find(rt->node_db, plan_id, &row) ||
        strcmp(row.application_kind, MARKET_PURCHASE_APPLICATION) != 0 ||
        !row.has_txid || row.state < VAULT_INTENT_MEMPOOL_ACCEPTED ||
        row.state > VAULT_INTENT_REORGED)
        return ZCL_ERR(-59, "purchase payment is absent or not committed");
    uint8_t plain[MARKET_PURCHASE_PAYLOAD_MAX]; size_t plain_len = 0;
    struct market_purchase_private_payload payload;
    struct zcl_result decrypted = market_purchase_payload_decrypt(rt, &row, &payload,
                                              plain, &plain_len);
    if (!decrypted.ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return decrypted;
    }
    struct file_offer offer;
    uint8_t recomputed_offer_id[32];
    int64_t exact_amount = 0;
    bool offer_ok = db_file_offer_find_by_id(rt->node_db, payload.offer_id,
                                             &offer) &&
        file_offer_auth_verify_signature(&offer) == FILE_OFFER_AUTH_OK &&
        file_offer_auth_offer_id(&offer, recomputed_offer_id) ==
            FILE_OFFER_AUTH_OK &&
        memcmp(recomputed_offer_id, payload.offer_id, 32) == 0 &&
        memcmp(offer.network_genesis, payload.network_genesis, 32) == 0 &&
        payload.chunk_start == 0 && payload.chunks_paid == offer.num_chunks &&
        file_market_offer_total_zat(&offer, &exact_amount) &&
        exact_amount == payload.amount_zat &&
        exact_amount == row.recipient_value_zat;
    if (!offer_ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-74, "only an exact full-file signed purchase can be retrieved");
    }
    struct market_download_record download;
    char parent[MARKET_DOWNLOAD_PATH_MAX];
    struct zcl_result initialized = mp_download_initialize(
        rt, &row, &offer, destination_path, &download, parent);
    if (!initialized.ok) {
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return initialized;
    }
    market_purchase_view_from_row(&row, &payload, out);
    if (download.state == MARKET_DOWNLOAD_COMPLETE) {
        market_purchase_view_add_download(&download, out);
        out->idempotent_replay = true;
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_OK;
    }
    int fd = open(download.private_staging,
                  O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 ||
        !mp_verify_staged(rt->node_db, &download, fd)) {
        if (fd >= 0) close(fd);
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-75, "durable staging bytes failed restart verification");
    }

    struct zcl_result result = ZCL_OK;
    /* The signed offer picks the delivery transport. An onion endpoint
     * requires a running embedded Tor and refuses outright — there is
     * never an automatic clearnet fallback against a signed onion offer. */
    bool onion_endpoint =
        offer.endpoint_type == FILE_MARKET_ENDPOINT_ONION;
    if (onion_endpoint && offer.num_chunks > download.chunks_received &&
        (!rt->onion_transport_ready || !rt->fetch_onion)) {
        close(fd);
        memory_cleanse(plain, sizeof(plain));
        memory_cleanse(&payload, sizeof(payload));
        return ZCL_ERR(-78, "signed offer names an onion endpoint but the embedded Tor client is not running (start the node with -tor)");
    }
    int64_t retrieve_deadline_ms = INT64_MAX;
    if (offer.num_chunks > download.chunks_received) {
        if (retrieve_started_ms <= 0 ||
            retrieve_started_ms >
                INT64_MAX - MARKET_PURCHASE_RETRIEVE_BUDGET_MS) {
            close(fd);
            memory_cleanse(plain, sizeof(plain));
            memory_cleanse(&payload, sizeof(payload));
            return ZCL_ERR(-76, "seller delivery is %s",
                file_market_delivery_status_string(
                    FILE_MARKET_DELIVERY_RESOURCE_LIMIT));
        }
        retrieve_deadline_ms =
            retrieve_started_ms + MARKET_PURCHASE_RETRIEVE_BUDGET_MS;
    }
    for (uint32_t i = download.chunks_received; i < offer.num_chunks; i++) {
        struct file_market_delivery_chunk chunk;
        memset(&chunk, 0, sizeof(chunk));
        if (!mp_deadline_active(retrieve_deadline_ms)) {
            result = ZCL_ERR(-76, "seller delivery is %s",
                file_market_delivery_status_string(
                    FILE_MARKET_DELIVERY_RESOURCE_LIMIT));
            break;
        }
        enum file_market_delivery_status status = onion_endpoint
            ? rt->fetch_onion(
                rt->fetch_onion_ctx, offer.onion_pubkey,
                offer.network_genesis, offer.offer_id, i,
                payload.buyer_pubkey, payload.buyer_seed,
                retrieve_deadline_ms, &chunk)
            : rt->fetch(
                rt->fetch_ctx, offer.peer_ip, offer.peer_port,
                offer.network_genesis, offer.offer_id, i,
                payload.buyer_pubkey, payload.buyer_seed,
                retrieve_deadline_ms, &chunk);
        if (!mp_deadline_active(retrieve_deadline_ms)) {
            mp_chunk_discard(&chunk);
            result = ZCL_ERR(-76, "seller delivery is %s",
                file_market_delivery_status_string(
                    FILE_MARKET_DELIVERY_RESOURCE_LIMIT));
            break;
        }
        uint32_t expected = mp_chunk_size(&offer, i);
        uint8_t actual[32];
        bool exact = status == FILE_MARKET_DELIVERY_READY && chunk.data &&
            chunk.size == expected;
        if (exact) {
            sha3_256(chunk.data, chunk.size, actual);
            exact = memcmp(actual, chunk.sha3, 32) == 0;
        }
        if (!exact) {
            mp_chunk_discard(&chunk);
            result = ZCL_ERR(-76, "seller delivery is %s",
                file_market_delivery_status_string(status));
            break;
        }
        uint64_t offset = (uint64_t)i * FILE_MARKET_CHUNK_SIZE;
        if (!mp_write_exact_at(fd, chunk.data, chunk.size, offset) ||
            fsync(fd) != 0) {
            mp_chunk_discard(&chunk);
            result = ZCL_ERR(-77, "downloaded chunk could not be durably staged");
            break;
        }
        if (!mp_deadline_active(retrieve_deadline_ms)) {
            mp_chunk_discard(&chunk);
            result = ZCL_ERR(-76, "seller delivery is %s",
                file_market_delivery_status_string(
                    FILE_MARKET_DELIVERY_RESOURCE_LIMIT));
            break;
        }
        struct zcl_result recorded = mp_download_record_chunk(
            rt, &download, i, &chunk);
        mp_chunk_discard(&chunk);
        if (!recorded.ok) {
            result = recorded;
            break;
        }
    }
    if (result.ok)
        result = mp_publish_download(rt, &download, fd, parent);
    close(fd);
    market_purchase_view_add_download(&download, out);
    memory_cleanse(plain, sizeof(plain));
    memory_cleanse(&payload, sizeof(payload));
    return result;
}
