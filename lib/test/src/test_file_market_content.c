/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-private paid-content registration, restart, and tamper tests. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "controllers/file_market_controller.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/file_offer.h"
#include "models/market_content.h"
#include "net/file_market.h"
#include "platform/time_compat.h"
#include "sapling/sapling.h"
#include "services/file_market_content_service.h"
#include "services/market_moderation_service.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONTENT_CHECK(label, condition) do {                         \
    printf("file_market content: %s... ", (label));                 \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static bool content_write_file(const char *path, const uint8_t *data,
                               size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t done = 0;
    while (done < size) {
        ssize_t wrote = write(fd, data + done, size - done);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0) {
            close(fd);
            return false;
        }
        done += (size_t)wrote;
    }
    return close(fd) == 0;
}

static void content_one_chunk_root(const uint8_t *data, size_t size,
                                   uint8_t chunk[32], uint8_t root[32])
{
    sha3_256(data, size, chunk);
    sha3_256(chunk, 32, root);
}

static bool content_signed_offer(struct file_offer *offer,
                                 const uint8_t root[32], uint64_t size,
                                 uint64_t nonce, int64_t now_unix)
{
    const struct chain_params *params = chain_params_get();
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    if (!params)
        return false;
    memset(offer, 0, sizeof(*offer));
    memset(seed, 0x63, sizeof(seed));
    memcpy(offer->root_hash, root, 32);
    memcpy(offer->network_genesis,
           params->consensus.hashGenesisBlock.data, 32);
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "paid-content.bin");
    offer->size_bytes = size;
    if (!file_market_num_chunks_for_size(size, &offer->num_chunks))
        return false;
    offer->price_per_mb = 1200;
    for (uint8_t d = 1; ; d++) {
        memset(offer->z_addr, 0, sizeof(offer->z_addr));
        offer->z_addr[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, offer->z_addr))
            break;
        if (d == UINT8_MAX)
            return false;
    }
    jub_to_bytes(offer->z_addr + 11, &payment_key);
    offer->peer_ip[15] = 1;
    offer->peer_port = 18034;
    offer->last_seen = now_unix;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = nonce;
    offer->issued_unix = now_unix - 60;
    offer->expires_unix = now_unix + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

int file_market_content_tests(void)
{
    int failures = 0;
    enum { PAYLOAD_SIZE = 8193 };
    uint8_t payload[PAYLOAD_SIZE];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 17u + 3u);
    uint8_t chunk_sha3[32], root[32];
    content_one_chunk_root(payload, sizeof(payload), chunk_sha3, root);

    char dir[256], dbpath[512], filepath[512], symlink_path[512];
    char fifo_path[512], wrong_path[512];
    snprintf(dir, sizeof(dir), "./test-tmp/market_content_%d", (int)getpid());
    (void)mkdir("./test-tmp", 0700);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        CONTENT_CHECK("create fixture directory", false);
        return failures;
    }
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(filepath, sizeof(filepath), "%s/content.bin", dir);
    snprintf(symlink_path, sizeof(symlink_path), "%s/content-link", dir);
    snprintf(fifo_path, sizeof(fifo_path), "%s/content-fifo", dir);
    snprintf(wrong_path, sizeof(wrong_path), "%s/wrong.bin", dir);
    bool files_ready = content_write_file(filepath, payload, sizeof(payload)) &&
        symlink(filepath, symlink_path) == 0 && mkfifo(fifo_path, 0600) == 0 &&
        content_write_file(wrong_path, payload, sizeof(payload) - 1);
    CONTENT_CHECK("regular, symlink, fifo, and mismatch fixtures", files_ready);

    int64_t now_unix = (int64_t)platform_time_wall_time_t();
    struct file_offer offer;
    bool signed_offer = content_signed_offer(
        &offer, root, sizeof(payload), 7301, now_unix);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = signed_offer && node_db_open(&ndb, dbpath) &&
                  db_file_offer_save(&ndb, &offer);
    CONTENT_CHECK("authenticated offer database fixture", opened);
    if (!opened) {
        if (ndb.open) node_db_close(&ndb);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct market_content_public_record registered;
    struct zcl_result result = file_market_content_register(
        &ndb, offer.offer_id, filepath, now_unix, &registered);
    CONTENT_CHECK("exact bytes register against signed manifest",
        result.ok && registered.size_bytes == sizeof(payload) &&
        registered.num_chunks == 1 &&
        memcmp(registered.root_hash, root, 32) == 0);

    struct market_content_public_record listed[2];
    int listed_count = db_market_content_list(&ndb, listed, 2);
    CONTENT_CHECK("path-free model projection lists one binding",
        listed_count == 1 &&
        memcmp(listed[0].offer_id, offer.offer_id, 32) == 0);

    struct file_market_delivery_chunk loaded;
    struct zcl_result load_result = file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded);
    bool load_ok = load_result.ok;
    CONTENT_CHECK("verified reader returns exact registered chunk",
        load_ok && loaded.size == sizeof(payload) &&
        memcmp(loaded.data, payload, sizeof(payload)) == 0 &&
        memcmp(loaded.sha3, chunk_sha3, 32) == 0);
    free(loaded.data);

    result = file_market_content_register(
        &ndb, offer.offer_id, symlink_path, now_unix + 1, &registered);
    CONTENT_CHECK("symbolic-link registration fails closed", !result.ok);
    result = file_market_content_register(
        &ndb, offer.offer_id, fifo_path, now_unix + 1, &registered);
    CONTENT_CHECK("nonblocking FIFO registration fails closed", !result.ok);
    result = file_market_content_register(
        &ndb, offer.offer_id, wrong_path, now_unix + 1, &registered);
    CONTENT_CHECK("signed size mismatch fails before persistence", !result.ok);

    struct file_offer wrong_root_offer;
    uint8_t wrong_root[32];
    memset(wrong_root, 0x92, sizeof(wrong_root));
    bool wrong_offer_ready = content_signed_offer(
        &wrong_root_offer, wrong_root, sizeof(payload), 7302, now_unix) &&
        db_file_offer_save(&ndb, &wrong_root_offer);
    result = wrong_offer_ready ? file_market_content_register(
        &ndb, wrong_root_offer.offer_id, filepath, now_unix + 1,
        &registered) : ZCL_ERR(-1, "wrong offer fixture failed");
    CONTENT_CHECK("signed root mismatch fails before persistence",
                  wrong_offer_ready && !result.ok);

    rpc_market_set_state(&ndb);
    /* The registered-content index is a serving surface: it names what
     * this node holds bytes for. Under the boot-default profile a node
     * has not signed off on anything yet, so the index lists nothing and
     * says how much it withheld — it never lists a row the chunk-delivery
     * gate would then refuse. */
    struct json_value hidden_index;
    json_init(&hidden_index);
    bool hidden_indexed = api_market_content_list(&hidden_index);
    char hidden_rendered[4096];
    size_t hidden_len = json_write(&hidden_index, hidden_rendered,
                                   sizeof(hidden_rendered));
    const struct json_value *hidden_count =
        json_get(&hidden_index, "hidden_by_profile");
    CONTENT_CHECK("unreviewed content is withheld and counted, not listed",
        hidden_indexed && hidden_len > 0 &&
        !strstr(hidden_rendered, "offer_id") &&
        hidden_count && hidden_count->type == JSON_INT &&
        json_get_int(hidden_count) >= 1);
    json_free(&hidden_index);

    /* After this node signs off on its own content the row appears — and
     * the private filesystem path is still never returned. */
    struct zcl_result signed_off = market_moderation_set_review_state(
        offer.offer_id, MARKET_REVIEW_REVIEWED_OK);
    struct json_value public_index;
    json_init(&public_index);
    bool indexed = api_market_content_list(&public_index);
    char rendered[4096];
    size_t rendered_len = json_write(&public_index, rendered,
                                     sizeof(rendered));
    CONTENT_CHECK("private REST index omits filesystem references",
        signed_off.ok && indexed && rendered_len > 0 &&
        strstr(rendered, "offer_id") &&
        !strstr(rendered, "private_path") && !strstr(rendered, filepath));
    json_free(&public_index);

    node_db_close(&ndb);
    bool reopened = node_db_open(&ndb, dbpath);
    load_result = reopened ? file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded)
        : ZCL_ERR(-1, "database reopen failed");
    load_ok = load_result.ok;
    CONTENT_CHECK("restart reconstructs verified content reader",
        load_ok && loaded.size == sizeof(payload) &&
        memcmp(loaded.data, payload, sizeof(payload)) == 0);
    free(loaded.data);

    int mutate_fd = open(filepath, O_WRONLY | O_CLOEXEC);
    uint8_t changed = (uint8_t)(payload[0] ^ 0xffu);
    bool mutated = mutate_fd >= 0 && pwrite(mutate_fd, &changed, 1, 0) == 1;
    if (mutate_fd >= 0) close(mutate_fd);
    load_result = file_market_content_load_chunk(
        &ndb, offer.offer_id, 0, &loaded);
    load_ok = load_result.ok;
    CONTENT_CHECK("post-registration content tamper revokes delivery",
                  mutated && !load_ok && loaded.data == NULL);

    rpc_market_set_state(NULL);
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}
