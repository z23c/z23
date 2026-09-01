/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Seller offer plan/commit, idempotency, custody, and wire-roundtrip tests. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/market_content.h"
#include "models/market_seller_key.h"
#include "net/file_market.h"
#include "platform/time_compat.h"
#include "sapling/sapling.h"
#include "services/file_market_content_service.h"
#include "services/file_market_offer_service.h"
#include "wallet/wallet_lock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OFFER_CHECK(label, condition) do {                          \
    printf("file_market offer: %s... ", (label));                   \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

struct offer_fixture {
    bool endpoint_ok;
    bool payee_ok;
    bool announce_ok;
    bool onion_ok;
    int announcements;
    uint8_t onion_pubkey[32];
    uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t wire_len;
};

static bool offer_write_file(const char *path, const uint8_t *data,
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

static struct zcl_result offer_endpoint(void *opaque, uint8_t peer_ip[16],
                                        uint16_t *peer_port)
{
    struct offer_fixture *f = opaque;
    if (!f || !f->endpoint_ok)
        return ZCL_ERR(-1, "fixture endpoint unavailable");
    memset(peer_ip, 0, 16);
    peer_ip[15] = 1;
    *peer_port = 18034;
    return ZCL_OK;
}

static struct zcl_result offer_payee(void *opaque, uint8_t z_addr_out[43])
{
    struct offer_fixture *f = opaque;
    struct jub_point payment_key;
    if (!f || !f->payee_ok)
        return ZCL_ERR(-1, "fixture payee unavailable");
    for (uint8_t d = 1; ; d++) {
        memset(z_addr_out, 0, 43);
        z_addr_out[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, z_addr_out))
            break;
        if (d == UINT8_MAX)
            return ZCL_ERR(-2, "fixture diversifier exhausted");
    }
    jub_to_bytes(z_addr_out + 11, &payment_key);
    return ZCL_OK;
}

static struct zcl_result offer_onion_endpoint(void *opaque,
                                              uint8_t onion_pubkey_out[32])
{
    struct offer_fixture *f = opaque;
    if (!f || !f->onion_ok)
        return ZCL_ERR(-1, "fixture onion endpoint unavailable");
    memcpy(onion_pubkey_out, f->onion_pubkey, 32);
    return ZCL_OK;
}

static bool offer_announce(void *opaque, const uint8_t *wire, size_t wire_len)
{
    struct offer_fixture *f = opaque;
    if (!f || !f->announce_ok || wire_len > sizeof(f->wire))
        return false;
    memcpy(f->wire, wire, wire_len);
    f->wire_len = wire_len;
    f->announcements++;
    return true;
}

static void offer_runtime(struct market_offer_runtime *rt,
                          struct node_db *ndb, struct offer_fixture *f,
                          const uint8_t genesis[32], int64_t now_unix)
{
    memset(rt, 0, sizeof(*rt));
    rt->node_db = ndb;
    rt->endpoint = offer_endpoint;
    rt->endpoint_ctx = f;
    rt->payee = offer_payee;
    rt->payee_ctx = f;
    rt->announce = offer_announce;
    rt->announce_ctx = f;
    rt->onion_endpoint = offer_onion_endpoint;
    rt->onion_endpoint_ctx = f;
    rt->prefer_onion = false;
    memcpy(rt->network_genesis, genesis, 32);
    rt->now_unix = now_unix;
}

int file_market_offer_tests(void)
{
    int failures = 0;
    enum { PAYLOAD_SIZE = 9001 };
    uint8_t payload[PAYLOAD_SIZE];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 31u + 7u);

    char dir[256], dbpath[320], filepath[320], second_path[320];
    test_make_tmpdir(dir, sizeof(dir), "file_market_offer", "origin");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(filepath, sizeof(filepath), "%s/offer.bin", dir);
    snprintf(second_path, sizeof(second_path), "%s/second.bin", dir);
    bool files_ready = offer_write_file(filepath, payload, sizeof(payload)) &&
        offer_write_file(second_path, payload, sizeof(payload) - 1);
    OFFER_CHECK("private content fixtures written", files_ready);

    const struct chain_params *params = chain_params_get();
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    bool ready = files_ready && params && node_db_open(&ndb, dbpath) &&
        wallet_lock_unlock(NULL, NULL, "market-offer-test").ok;
    OFFER_CHECK("database and encrypted wallet fixture", ready);
    if (!ready) {
        if (ndb.open) node_db_close(&ndb);
        wallet_lock_reset_for_test();
        test_cleanup_tmpdir(dir);
        return failures;
    }

    const uint8_t *genesis = params->consensus.hashGenesisBlock.data;
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct offer_fixture fixture;
    memset(&fixture, 0, sizeof(fixture));
    fixture.endpoint_ok = true;
    fixture.payee_ok = true;
    fixture.announce_ok = true;
    struct market_offer_runtime rt;
    offer_runtime(&rt, &ndb, &fixture, genesis, now);
    struct market_offer_request request;
    memset(&request, 0, sizeof(request));
    request.filepath = filepath;
    request.price_per_mb_zat = 1200;

    struct market_offer_view plan;
    struct zcl_result r = file_market_offer_plan(&rt, &request, &plan);
    uint8_t expected_root[32], chunk[32];
    sha3_256(payload, sizeof(payload), chunk);
    sha3_256(chunk, 32, expected_root);
    OFFER_CHECK("plan hashes and prices without an offer identity",
        r.ok && memcmp(plan.root_hash, expected_root, 32) == 0 &&
        plan.size_bytes == sizeof(payload) && plan.num_chunks == 1 &&
        plan.price_per_mb == 1200 && plan.total_zat > 0 &&
        strcmp(plan.filename, "offer.bin") == 0 &&
        plan.expires_unix == now + FILE_MARKET_OFFER_MAX_LIFETIME_SECS &&
        !plan.idempotent_replay && !plan.announced &&
        fixture.announcements == 0);

    struct market_offer_request bad = request;
    bad.filepath = "no-such-file.bin";
    r = file_market_offer_plan(&rt, &bad, &plan);
    OFFER_CHECK("missing file refused with named code",
        !r.ok && r.code == -2 /* CONTENT_UNAVAILABLE */);
    bad = request;
    bad.price_per_mb_zat = 0;
    r = file_market_offer_plan(&rt, &bad, &plan);
    OFFER_CHECK("zero price refused with named code",
        !r.ok && r.code == -6 /* PRICE_INVALID */);

    struct market_offer_view committed;
    r = file_market_offer_commit(&rt, &request, &committed);
    struct file_offer persisted;
    bool persisted_ok = r.ok &&
        db_file_offer_find_by_id(&ndb, committed.offer_id, &persisted) &&
        file_offer_auth_verify_at(&persisted, genesis, now) ==
            FILE_OFFER_AUTH_OK &&
        memcmp(persisted.root_hash, expected_root, 32) == 0 &&
        persisted.price_per_mb == 1200;
    OFFER_CHECK("commit seals, persists, binds, and announces",
        persisted_ok && committed.announced && !committed.idempotent_replay &&
        fixture.announcements == 1 &&
        fixture.wire_len == FILE_MARKET_OFFER_WIRE_BYTES);
    if (!persisted_ok)
        goto cleanup;

    struct file_market_delivery_chunk served;
    struct zcl_result load = file_market_content_load_chunk(
        &ndb, committed.offer_id, 0, &served);
    OFFER_CHECK("committed content binding serves exact bytes",
        load.ok && served.size == sizeof(payload) &&
        memcmp(served.data, payload, sizeof(payload)) == 0);
    free(served.data);

    struct file_offer decoded;
    enum file_offer_auth_error decoded_err =
        file_offer_auth_decode(fixture.wire, fixture.wire_len, &decoded);
    struct file_offer ingested;
    enum file_market_offer_ingest ingest = file_market_ingest_offer_wire(
        fixture.wire, fixture.wire_len, genesis, 99, now, &ingested);
    OFFER_CHECK("announced wire round-trips through decode and ingest",
        decoded_err == FILE_OFFER_AUTH_OK &&
        memcmp(decoded.offer_id, committed.offer_id, 32) == 0 &&
        decoded.price_per_mb == 1200 &&
        strcmp(decoded.filename, "offer.bin") == 0 &&
        (ingest == FILE_MARKET_INGEST_NEW ||
         ingest == FILE_MARKET_INGEST_DEDUP) &&
        memcmp(ingested.offer_id, committed.offer_id, 32) == 0);

    struct market_offer_view replayed;
    r = file_market_offer_commit(&rt, &request, &replayed);
    OFFER_CHECK("re-commit of the same live offer replays idempotently",
        r.ok && replayed.idempotent_replay && !replayed.announced &&
        memcmp(replayed.offer_id, committed.offer_id, 32) == 0 &&
        fixture.announcements == 1);

    node_db_close(&ndb);
    memset(&ndb, 0, sizeof(ndb));
    bool reopened = node_db_open(&ndb, dbpath);
    offer_runtime(&rt, &ndb, &fixture, genesis, now);
    struct market_offer_request second = request;
    second.filepath = second_path;
    struct market_offer_view second_view;
    r = reopened ? file_market_offer_commit(&rt, &second, &second_view)
                 : ZCL_ERR(-1, "database reopen failed");
    OFFER_CHECK("restart reuses the owner seller key for a new offer",
        r.ok && !second_view.idempotent_replay &&
        memcmp(second_view.seller_pubkey, committed.seller_pubkey, 32) == 0 &&
        memcmp(second_view.offer_id, committed.offer_id, 32) != 0);

    fixture.endpoint_ok = false;
    struct market_offer_view refused;
    struct market_offer_request third = second;
    third.price_per_mb_zat = 42;
    r = file_market_offer_commit(&rt, &third, &refused);
    OFFER_CHECK("unknown own endpoint refuses before signing",
        !r.ok && r.code == -7 /* ENDPOINT_UNKNOWN */);
    fixture.endpoint_ok = true;
    fixture.payee_ok = false;
    r = file_market_offer_commit(&rt, &third, &refused);
    OFFER_CHECK("missing wallet payee refuses before signing",
        !r.ok && r.code == -8 /* PAYEE_UNAVAILABLE */);
    fixture.payee_ok = true;

    wallet_lock_reset_for_test();
    r = file_market_offer_commit(&rt, &third, &refused);
    OFFER_CHECK("locked wallet refuses at the seller-key custody gate",
        !r.ok && r.code == -9 /* SELLER_KEY_UNAVAILABLE */);
    wallet_lock_note_encrypted_at_rest();
    ZCL_IGNORE_RESULT(wallet_lock_unlock(NULL, NULL, "market-offer-test"),
        "post-custody-gate re-unlock; a failure surfaces in the next use");

    /* ── v2 onion-endpoint offers ─────────────────────────────── */
    OFFER_CHECK("clearnet commit reports the clearnet endpoint kind",
        committed.endpoint_type == FILE_MARKET_ENDPOINT_CLEARNET);

    memset(fixture.onion_pubkey, 0xAB, sizeof(fixture.onion_pubkey));
    fixture.onion_ok = true;
    rt.prefer_onion = true;
    struct market_offer_view onion_view;
    r = file_market_offer_commit(&rt, &request, &onion_view);
    OFFER_CHECK("onion-preferred commit signs a fresh v2 onion-endpoint offer",
        r.ok && !onion_view.idempotent_replay &&
        onion_view.endpoint_type == FILE_MARKET_ENDPOINT_ONION &&
        memcmp(onion_view.offer_id, committed.offer_id, 32) != 0 &&
        fixture.wire_len == FILE_MARKET_OFFER_WIRE_BYTES_V2);
    if (!r.ok)
        goto cleanup;

    struct file_offer v2_decoded;
    OFFER_CHECK("v2 wire round-trips with the onion endpoint committed",
        file_offer_auth_decode(fixture.wire, fixture.wire_len,
                               &v2_decoded) == FILE_OFFER_AUTH_OK &&
        v2_decoded.auth_version == FILE_MARKET_OFFER_VERSION_V2 &&
        v2_decoded.endpoint_type == FILE_MARKET_ENDPOINT_ONION &&
        memcmp(v2_decoded.onion_pubkey, fixture.onion_pubkey, 32) == 0 &&
        v2_decoded.peer_port == 0 &&
        memcmp(v2_decoded.offer_id, onion_view.offer_id, 32) == 0 &&
        file_offer_auth_verify_at(&v2_decoded, genesis, now) ==
            FILE_OFFER_AUTH_OK);

    struct file_offer v2_persisted;
    OFFER_CHECK("v2 offer persists and reloads by offer_id",
        db_file_offer_find_by_id(&ndb, onion_view.offer_id,
                                 &v2_persisted) &&
        v2_persisted.auth_version == FILE_MARKET_OFFER_VERSION_V2 &&
        v2_persisted.endpoint_type == FILE_MARKET_ENDPOINT_ONION &&
        memcmp(v2_persisted.onion_pubkey, fixture.onion_pubkey, 32) == 0);

    uint8_t v1_wire[FILE_MARKET_OFFER_WIRE_BYTES];
    struct file_offer v1_roundtrip;
    OFFER_CHECK("v1 wires keep decoding beside v2 (dual decode)",
        file_offer_auth_encode(&persisted, v1_wire) ==
            FILE_OFFER_AUTH_OK &&
        file_offer_auth_decode(v1_wire, sizeof(v1_wire), &v1_roundtrip) ==
            FILE_OFFER_AUTH_OK &&
        v1_roundtrip.auth_version == FILE_MARKET_OFFER_VERSION &&
        v1_roundtrip.endpoint_type == FILE_MARKET_ENDPOINT_CLEARNET &&
        memcmp(v1_roundtrip.offer_id, persisted.offer_id, 32) == 0);

    uint8_t v3_wire[FILE_MARKET_OFFER_WIRE_BYTES_V2];
    memcpy(v3_wire, fixture.wire, sizeof(v3_wire));
    v3_wire[8] = 3; /* auth_version LE at offset 8 */
    struct file_offer dropped;
    OFFER_CHECK("unknown offer version drops with the named version error",
        file_offer_auth_decode(v3_wire, sizeof(v3_wire), &dropped) ==
            FILE_OFFER_AUTH_ERR_VERSION);
    OFFER_CHECK("old nodes drop the longer v2 wire by size",
        file_offer_auth_decode(fixture.wire, FILE_MARKET_OFFER_WIRE_BYTES,
                               &dropped) == FILE_OFFER_AUTH_ERR_WIRE_SIZE);

    struct file_offer v2_ingested;
    enum file_market_offer_ingest v2_ingest = file_market_ingest_offer_wire(
        fixture.wire, fixture.wire_len, genesis, 100, now, &v2_ingested);
    OFFER_CHECK("v2 wire ingests from gossip with its identity intact",
        (v2_ingest == FILE_MARKET_INGEST_NEW ||
         v2_ingest == FILE_MARKET_INGEST_DEDUP) &&
        memcmp(v2_ingested.offer_id, onion_view.offer_id, 32) == 0);

    struct market_offer_view onion_replay;
    r = file_market_offer_commit(&rt, &request, &onion_replay);
    OFFER_CHECK("re-commit of the live onion offer replays idempotently",
        r.ok && onion_replay.idempotent_replay &&
        memcmp(onion_replay.offer_id, onion_view.offer_id, 32) == 0);

    struct market_offer_view clearnet_again;
    rt.prefer_onion = false;
    r = file_market_offer_commit(&rt, &request, &clearnet_again);
    OFFER_CHECK("flipping back to clearnet never replays the onion offer",
        r.ok && !clearnet_again.idempotent_replay &&
        clearnet_again.endpoint_type == FILE_MARKET_ENDPOINT_CLEARNET &&
        memcmp(clearnet_again.offer_id, onion_view.offer_id, 32) != 0 &&
        fixture.wire_len == FILE_MARKET_OFFER_WIRE_BYTES);

    rt.prefer_onion = true;
    fixture.onion_ok = false;
    int announcements_before = fixture.announcements;
    struct market_offer_view onion_refused;
    r = file_market_offer_commit(&rt, &request, &onion_refused);
    OFFER_CHECK("onion endpoint outage refuses by name, never downgrades",
        !r.ok && r.code == -14 /* ONION_ENDPOINT_UNAVAILABLE */ &&
        fixture.announcements == announcements_before);
    fixture.onion_ok = true;
    rt.prefer_onion = false;

cleanup:
    node_db_close(&ndb);
    wallet_lock_reset_for_test();
    test_cleanup_tmpdir(dir);
    return failures;
}
