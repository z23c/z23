/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for ZCL Market — file sharing serialization, cache, and DB. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "controllers/file_market_controller.h"
#include "encoding/utilstrencodings.h"
#include "net/file_market.h"
#include "core/serialize.h"
#include "models/database.h"
#include "crypto/ed25519.h"
#include "sapling/sapling.h"
#include <stdint.h>

static bool market_test_signed_offer(struct file_offer *offer,
                                     uint8_t root_byte, uint64_t nonce,
                                     int64_t now_unix)
{
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    memset(offer, 0, sizeof(*offer));
    memset(seed, (int)(root_byte ^ 0x5a), sizeof(seed));
    memset(offer->root_hash, root_byte, sizeof(offer->root_hash));
    memset(offer->network_genesis, 0x42, sizeof(offer->network_genesis));
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "paid-%02x.dat",
             root_byte);
    offer->size_bytes = FILE_MARKET_CHUNK_SIZE + 1u;
    offer->num_chunks = 2;
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
    memset(offer->peer_ip, 0, sizeof(offer->peer_ip));
    offer->peer_ip[15] = root_byte ? root_byte : 1;
    offer->peer_port = 18034;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->last_seen = now_unix;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = nonce;
    offer->issued_unix = now_unix;
    offer->expires_unix = now_unix + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

int test_file_market(void)
{
    int failures = 0;

    printf("\n=== File Market Tests ===\n");

    /* ── File offer serialize/deserialize roundtrip ────────────── */

    printf("file_offer serialize+deserialize roundtrip... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0xAA, 32);
        snprintf(offer.filename, sizeof(offer.filename), "test-file.dat");
        offer.size_bytes = 104857600;  /* 100 MB */
        offer.num_chunks = 2;
        offer.price_per_mb = 10000;
        memset(offer.z_addr, 0xBB, 43);
        memset(offer.peer_ip, 0, 16);
        offer.peer_ip[12] = 192; offer.peer_ip[13] = 168;
        offer.peer_ip[14] = 1;  offer.peer_ip[15] = 1;
        offer.peer_port = 8033;
        offer.ttl = 3;

        struct byte_stream ws;
        stream_init(&ws, 512);
        bool ser = file_offer_serialize(&offer, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_offer got = {0};
        bool des = file_offer_deserialize(&got, &rs);

        if (ser && des &&
            memcmp(got.root_hash, offer.root_hash, 32) == 0 &&
            strcmp(got.filename, "test-file.dat") == 0 &&
            got.size_bytes == 104857600 &&
            got.num_chunks == 2 &&
            got.price_per_mb == 10000 &&
            memcmp(got.z_addr, offer.z_addr, 43) == 0 &&
            got.peer_port == 8033 &&
            got.ttl == 3) {
            printf("OK\n");
        } else {
            printf("FAIL (ser=%d des=%d)\n", ser, des);
            failures++;
        }
        stream_free(&ws);
    }

    /* ── File challenge serialize/deserialize roundtrip ────────── */

    printf("signed paid offer: exact wire roundtrip and verification... ");
    {
        struct file_offer offer, got;
        uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES];
        bool made = market_test_signed_offer(&offer, 0x31, 101, 1000);
        enum file_offer_auth_error enc = file_offer_auth_encode(&offer, wire);
        enum file_offer_auth_error dec = file_offer_auth_decode(
            wire, sizeof(wire), &got);
        enum file_offer_auth_error verified = file_offer_auth_verify_at(
            &got, offer.network_genesis, 1001);
        if (made && enc == FILE_OFFER_AUTH_OK &&
            dec == FILE_OFFER_AUTH_OK && verified == FILE_OFFER_AUTH_OK &&
            memcmp(got.offer_id, offer.offer_id, 32) == 0 &&
            strcmp(got.filename, offer.filename) == 0)
            printf("OK\n");
        else {
            printf("FAIL (made=%d enc=%s dec=%s verify=%s)\n", made,
                   file_offer_auth_error_string(enc),
                   file_offer_auth_error_string(dec),
                   file_offer_auth_error_string(verified));
            failures++;
        }
    }

    printf("signed paid offer: exact integer total and money cap... ");
    {
        struct file_offer offer;
        int64_t total = 0;
        bool made = market_test_signed_offer(&offer, 0x30, 100, 900);
        bool exact = file_market_offer_total_zat(&offer, &total) &&
                     total == 60001;
        offer.price_per_mb = INT64_MAX;
        bool capped = !file_market_offer_total_zat(&offer, &total);
        if (made && exact && capped) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("signed paid offer: tamper, wrong network, and expiry rejected... ");
    {
        struct file_offer offer, got;
        uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES], wrong_net[32];
        bool made = market_test_signed_offer(&offer, 0x32, 102, 2000);
        bool encoded = file_offer_auth_encode(&offer, wire) ==
                       FILE_OFFER_AUTH_OK;
        /* price_per_mb begins at body offset 130. Keep it positive while
         * changing the signed statement. */
        wire[130] ^= 1;
        bool decoded = file_offer_auth_decode(wire, sizeof(wire), &got) ==
                       FILE_OFFER_AUTH_OK;
        bool tamper_rejected = decoded &&
            file_offer_auth_verify_at(&got, offer.network_genesis, 2001) ==
                FILE_OFFER_AUTH_ERR_SIGNATURE;
        memset(wrong_net, 0x43, sizeof(wrong_net));
        bool wrong_rejected = file_offer_auth_verify_at(
            &offer, wrong_net, 2001) == FILE_OFFER_AUTH_ERR_NETWORK_MISMATCH;
        bool expired = file_offer_auth_verify_at(
            &offer, offer.network_genesis, offer.expires_unix) ==
                FILE_OFFER_AUTH_ERR_EXPIRED;
        if (made && encoded && tamper_rejected && wrong_rejected && expired)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("signed paid offer ingress: verify, dedup, and cross-network drop... ");
    {
        struct file_offer offer, accepted;
        uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES], wrong_net[32];
        bool made = market_test_signed_offer(&offer, 0x33, 103, 3000);
        bool encoded = file_offer_auth_encode(&offer, wire) ==
                       FILE_OFFER_AUTH_OK;
        enum file_market_offer_ingest first = file_market_ingest_offer_wire(
            wire, sizeof(wire), offer.network_genesis, 77, 3001, &accepted);
        enum file_market_offer_ingest duplicate = file_market_ingest_offer_wire(
            wire, sizeof(wire), offer.network_genesis, 77, 3002, &accepted);
        memset(wrong_net, 0x44, sizeof(wrong_net));
        enum file_market_offer_ingest wrong = file_market_ingest_offer_wire(
            wire, sizeof(wire), wrong_net, 78, 3003, NULL);
        if (made && encoded && first == FILE_MARKET_INGEST_NEW &&
            duplicate == FILE_MARKET_INGEST_DEDUP &&
            wrong == FILE_MARKET_INGEST_INVALID &&
            memcmp(accepted.offer_id, offer.offer_id, 32) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("signed paid offer ingress: newer contract replaces same content... ");
    {
        struct file_offer first_offer, refreshed, found;
        uint8_t first_wire[FILE_MARKET_OFFER_WIRE_BYTES];
        uint8_t refresh_wire[FILE_MARKET_OFFER_WIRE_BYTES];
        bool made_first = market_test_signed_offer(
            &first_offer, 0x35, 105, 4000);
        bool made_refresh = market_test_signed_offer(
            &refreshed, 0x35, 106, 4001);
        bool encoded =
            file_offer_auth_encode(&first_offer, first_wire) ==
                FILE_OFFER_AUTH_OK &&
            file_offer_auth_encode(&refreshed, refresh_wire) ==
                FILE_OFFER_AUTH_OK;
        enum file_market_offer_ingest first = file_market_ingest_offer_wire(
            first_wire, sizeof(first_wire), first_offer.network_genesis,
            88, 4002, NULL);
        enum file_market_offer_ingest refresh = file_market_ingest_offer_wire(
            refresh_wire, sizeof(refresh_wire), refreshed.network_genesis,
            88, 4003, NULL);
        bool current = file_market_find_offer(refreshed.root_hash, &found) &&
            memcmp(found.offer_id, refreshed.offer_id, 32) == 0;
        if (made_first && made_refresh && encoded &&
            first == FILE_MARKET_INGEST_NEW &&
            refresh == FILE_MARKET_INGEST_NEW && current)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("signed paid offer ingress: bounded fresh offers per peer... ");
    {
        bool ok = true;
        for (unsigned i = 0; i <= FILE_MARKET_PEER_WINDOW_MAX_OFFERS; i++) {
            struct file_offer offer;
            uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES];
            ok = ok && market_test_signed_offer(
                &offer, (uint8_t)(0x40 + i), 200 + i, 5000);
            ok = ok && file_offer_auth_encode(&offer, wire) ==
                FILE_OFFER_AUTH_OK;
            enum file_market_offer_ingest got = file_market_ingest_offer_wire(
                wire, sizeof(wire), offer.network_genesis, 900, 5001, NULL);
            enum file_market_offer_ingest expected =
                i < FILE_MARKET_PEER_WINDOW_MAX_OFFERS
                    ? FILE_MARKET_INGEST_NEW
                    : FILE_MARKET_INGEST_RATE_LIMITED;
            ok = ok && got == expected;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("signed paid offer ingress: invalid attempts are CPU-bounded... ");
    {
        bool ok = true;
        uint8_t invalid_wire = 0;
        uint8_t expected_network[32];
        memset(expected_network, 0x42, sizeof(expected_network));
        for (unsigned i = 0;
             i <= FILE_MARKET_PEER_WINDOW_MAX_ATTEMPTS; i++) {
            enum file_market_offer_ingest got = file_market_ingest_offer_wire(
                &invalid_wire, sizeof(invalid_wire), expected_network,
                901, 5100, NULL);
            enum file_market_offer_ingest expected =
                i < FILE_MARKET_PEER_WINDOW_MAX_ATTEMPTS
                    ? FILE_MARKET_INGEST_INVALID
                    : FILE_MARKET_INGEST_RATE_LIMITED;
            ok = ok && got == expected;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("legacy market writes: fail closed without cache or session mutation... ");
    {
        struct rpc_table table;
        struct json_value offer_params = {0}, buy_params = {0};
        struct json_value value = {0}, result = {0};
        uint8_t known_root[32];
        struct file_download download;
        int offers_before = file_market_count();
        rpc_table_init(&table);
        register_market_rpc_commands(&table);

        json_set_array(&offer_params);
        json_set_str(&value, "/tmp/not-read-by-contained-market-rpc");
        bool assembled = json_push_back(&offer_params, &value);
        json_set_int(&value, 1000);
        assembled = assembled && json_push_back(&offer_params, &value);
        const struct rpc_command *offer_cmd = rpc_table_find(
            &table, "zmarket_offer");
        bool offer_refused = offer_cmd &&
            !offer_cmd->actor(&offer_params, false, &result) &&
            strstr(json_get_str(&result), "contained") != NULL &&
            file_market_count() == offers_before;
        json_free(&result);
        json_init(&result);

        memset(known_root, 0x33, sizeof(known_root));
        char root_hex[65];
        HexStr(known_root, sizeof(known_root), false,
               root_hex, sizeof(root_hex));
        json_set_array(&buy_params);
        json_set_str(&value, root_hex);
        assembled = assembled && json_push_back(&buy_params, &value);
        const struct rpc_command *buy_cmd = rpc_table_find(
            &table, "zmarket_buy");
        bool buy_refused = buy_cmd &&
            !buy_cmd->actor(&buy_params, false, &result) &&
            strstr(json_get_str(&result), "contained") != NULL &&
            !file_market_get_download(known_root, &download);

        json_free(&value);
        json_free(&offer_params);
        json_free(&buy_params);
        json_free(&result);
        if (assembled && offer_refused && buy_refused) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("legacy unsigned paid offer is rejected from the cache... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0x34, 32);
        snprintf(offer.filename, sizeof(offer.filename), "unsigned.dat");
        offer.size_bytes = 1;
        offer.num_chunks = 1;
        offer.price_per_mb = 1;
        offer.ttl = 1;
        if (!file_market_add_offer(&offer)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── File challenge serialize/deserialize roundtrip ────────── */

    printf("file_challenge serialize+deserialize roundtrip... ");
    {
        struct file_challenge chal = {0};
        memset(chal.root_hash, 0xCC, 32);
        chal.chunk_index = 42;

        struct byte_stream ws;
        stream_init(&ws, 128);
        bool ser = file_challenge_serialize(&chal, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_challenge got = {0};
        bool des = file_challenge_deserialize(&got, &rs);

        if (ser && des &&
            memcmp(got.root_hash, chal.root_hash, 32) == 0 &&
            got.chunk_index == 42) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    /* ── File proof serialize/deserialize roundtrip ────────────── */

    printf("file_proof serialize+deserialize roundtrip... ");
    {
        struct file_proof proof = {0};
        memset(proof.root_hash, 0xDD, 32);
        proof.chunk_index = 7;
        memset(proof.chunk_hash, 0xEE, 32);

        struct byte_stream ws;
        stream_init(&ws, 128);
        bool ser = file_proof_serialize(&proof, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_proof got = {0};
        bool des = file_proof_deserialize(&got, &rs);

        if (ser && des &&
            memcmp(got.root_hash, proof.root_hash, 32) == 0 &&
            got.chunk_index == 7 &&
            memcmp(got.chunk_hash, proof.chunk_hash, 32) == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    /* ── File payment serialize/deserialize roundtrip ──────────── */

    printf("file_payment serialize+deserialize roundtrip... ");
    {
        struct file_payment pay = {0};
        uint8_t buyer_seed[32], buyer_secret[32];
        memset(buyer_seed, 0x19, sizeof(buyer_seed));
        pay.version = FILE_MARKET_PAYMENT_VERSION;
        memset(pay.network_genesis, 0x11, 32);
        memset(pay.offer_id, 0x33, 32);
        memset(pay.txid, 0x22, 32);
        pay.chunks_paid = 10;
        pay.chunk_start = 5;
        pay.amount_zat = 500000;
        ed25519_keypair(pay.buyer_pubkey, buyer_secret, buyer_seed);
        bool sealed = file_payment_auth_seal(&pay, buyer_seed) ==
                      FILE_PAYMENT_AUTH_OK;

        struct byte_stream ws;
        stream_init(&ws, FILE_MARKET_PAYMENT_WIRE_BYTES);
        bool ser = file_payment_serialize(&pay, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_payment got = {0};
        bool des = file_payment_deserialize(&got, &rs);

        if (sealed && ser && des &&
            ws.size == FILE_MARKET_PAYMENT_WIRE_BYTES &&
            memcmp(got.network_genesis, pay.network_genesis, 32) == 0 &&
            memcmp(got.offer_id, pay.offer_id, 32) == 0 &&
            memcmp(got.txid, pay.txid, 32) == 0 &&
            got.chunks_paid == 10 &&
            got.chunk_start == 5 && got.amount_zat == pay.amount_zat &&
            memcmp(got.claim_id, pay.claim_id, 32) == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    /* ── Offer with long filename ─────────────────────────────── */

    printf("file_offer: long filename truncated to 255... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0xFF, 32);
        memset(offer.filename, 'x', 255);
        offer.filename[255] = '\0';
        offer.size_bytes = 1000;
        offer.num_chunks = 1;
        offer.price_per_mb = 100;
        offer.ttl = 1;

        struct byte_stream ws;
        stream_init(&ws, 512);
        bool ser = file_offer_serialize(&offer, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_offer got = {0};
        bool des = file_offer_deserialize(&got, &rs);

        if (ser && des && strlen(got.filename) == 255)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    /* ── Offer with empty filename ────────────────────────────── */

    printf("file_offer: empty filename... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0x77, 32);
        offer.filename[0] = '\0';
        offer.size_bytes = 1000;
        offer.num_chunks = 1;
        offer.price_per_mb = 0;
        offer.ttl = 2;

        struct byte_stream ws;
        stream_init(&ws, 256);
        bool ser = file_offer_serialize(&offer, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct file_offer got = {0};
        bool des = file_offer_deserialize(&got, &rs);

        if (ser && des && got.filename[0] == '\0')
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&ws);
    }

    /* ── In-memory offer cache ────────────────────────────────── */

    printf("file_market_add_offer: add new offer... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0x01, 32);
        snprintf(offer.filename, sizeof(offer.filename), "cached.dat");
        offer.num_chunks = 1;
        offer.ttl = 2;

        bool is_new = file_market_add_offer(&offer);
        if (is_new) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_add_offer: reject null... ");
    {
        if (!file_market_add_offer(NULL)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_add_offer: reject zero ttl... ");
    {
        struct file_offer offer = {0};
        offer.ttl = 0;
        offer.num_chunks = 1;
        if (!file_market_add_offer(&offer)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_add_offer: reject zero chunks... ");
    {
        struct file_offer offer = {0};
        offer.ttl = 1;
        offer.num_chunks = 0;
        if (!file_market_add_offer(&offer)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_find_offer: find by root_hash... ");
    {
        uint8_t hash[32];
        memset(hash, 0x01, 32);
        struct file_offer found;
        bool ok = file_market_find_offer(hash, &found);
        if (ok && strcmp(found.filename, "cached.dat") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_find_offer: miss on unknown hash... ");
    {
        uint8_t hash[32];
        memset(hash, 0xFE, 32);
        struct file_offer found;
        if (!file_market_find_offer(hash, &found)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_get_offers: returns count... ");
    {
        struct file_offer out[10];
        int count = file_market_get_offers(out, 10);
        if (count >= 1) printf("OK (count=%d)\n", count);
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_count: returns count... ");
    {
        int count = file_market_count();
        if (count >= 1) printf("OK (count=%d)\n", count);
        else { printf("FAIL\n"); failures++; }
    }

    printf("file_market_add_offer: update existing (same hash)... ");
    {
        struct file_offer offer = {0};
        memset(offer.root_hash, 0x01, 32);
        snprintf(offer.filename, sizeof(offer.filename), "updated.dat");
        offer.num_chunks = 1;
        offer.ttl = 3;

        bool is_new = file_market_add_offer(&offer);
        if (!is_new) {
            struct file_offer found;
            uint8_t hash[32];
            memset(hash, 0x01, 32);
            file_market_find_offer(hash, &found);
            if (strcmp(found.filename, "updated.dat") == 0)
                printf("OK\n");
            else { printf("FAIL (not updated)\n"); failures++; }
        } else { printf("FAIL (should not be new)\n"); failures++; }
    }

    printf("file_market_prune: removes old offers... ");
    {
        int pruned = file_market_prune(0);
        if (pruned >= 0) printf("OK (pruned=%d)\n", pruned);
        else { printf("FAIL\n"); failures++; }
    }

    /* ── num_chunks overflow guard ──────────────────────── */

    printf("num_chunks: 0 bytes -> 0 chunks... ");
    {
        uint32_t n = 99;
        bool ok = file_market_num_chunks_for_size(0, &n);
        if (ok && n == 0) printf("OK\n");
        else { printf("FAIL (ok=%d n=%u)\n", ok, n); failures++; }
    }

    printf("num_chunks: 1 byte -> 1 chunk... ");
    {
        uint32_t n = 0;
        bool ok = file_market_num_chunks_for_size(1, &n);
        if (ok && n == 1) printf("OK\n");
        else { printf("FAIL (ok=%d n=%u)\n", ok, n); failures++; }
    }

    printf("num_chunks: exactly CHUNK_SIZE -> 1 chunk... ");
    {
        uint32_t n = 0;
        bool ok = file_market_num_chunks_for_size(
            (uint64_t)FILE_MARKET_CHUNK_SIZE, &n);
        if (ok && n == 1) printf("OK\n");
        else { printf("FAIL (ok=%d n=%u)\n", ok, n); failures++; }
    }

    printf("num_chunks: CHUNK_SIZE + 1 -> 2 chunks... ");
    {
        uint32_t n = 0;
        bool ok = file_market_num_chunks_for_size(
            (uint64_t)FILE_MARKET_CHUNK_SIZE + 1, &n);
        if (ok && n == 2) printf("OK\n");
        else { printf("FAIL (ok=%d n=%u)\n", ok, n); failures++; }
    }

    printf("num_chunks: UINT32_MAX * CHUNK_SIZE accepted (at cap)... ");
    {
        uint32_t n = 0;
        uint64_t max_ok =
            (uint64_t)UINT32_MAX * (uint64_t)FILE_MARKET_CHUNK_SIZE;
        bool ok = file_market_num_chunks_for_size(max_ok, &n);
        if (ok && n == UINT32_MAX) printf("OK\n");
        else { printf("FAIL (ok=%d n=%u)\n", ok, n); failures++; }
    }

    printf("num_chunks: UINT32_MAX * CHUNK_SIZE + 1 rejected "
           "(pre-fix wrapped to 0)... ");
    {
        uint32_t n = 99;
        uint64_t over =
            (uint64_t)UINT32_MAX * (uint64_t)FILE_MARKET_CHUNK_SIZE + 1;
        bool ok = file_market_num_chunks_for_size(over, &n);
        if (!ok) printf("OK\n");
        else { printf("FAIL (accepted n=%u for 225 PB file)\n", n); failures++; }
    }

    printf("num_chunks: silent-truncation shape rejected "
           "(225 PB + 5*CHUNK -> would report 4)... ");
    {
        /* The pre-fix expression wraps UINT32_MAX + 5 to 4 — the
         * exact attack shape where a malformed huge file reports a
         * plausible small chunk count instead of the add_offer
         * guard's num_chunks==0 reject. */
        uint32_t n = 99;
        uint64_t shape =
            (uint64_t)UINT32_MAX * (uint64_t)FILE_MARKET_CHUNK_SIZE +
            5 * (uint64_t)FILE_MARKET_CHUNK_SIZE;
        bool ok = file_market_num_chunks_for_size(shape, &n);
        if (!ok) printf("OK\n");
        else { printf("FAIL (accepted n=%u for truncation shape)\n", n); failures++; }
    }

    printf("num_chunks: UINT64_MAX rejected... ");
    {
        uint32_t n = 99;
        bool ok = file_market_num_chunks_for_size(UINT64_MAX, &n);
        if (!ok) printf("OK\n");
        else { printf("FAIL (accepted UINT64_MAX)\n"); failures++; }
    }

    printf("num_chunks: NULL out_chunks rejected... ");
    {
        bool ok = file_market_num_chunks_for_size(1000, NULL);
        if (!ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── SQLite persistence ───────────────────────────────────── */

    printf("file_market DB save+find+list+prune roundtrip... ");
    {
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        if (rc != SQLITE_OK) { printf("FAIL (open)\n"); failures++; }
        else {
            sqlite3_exec(db,
                "CREATE TABLE file_offers("
                "root_hash BLOB PRIMARY KEY, filename TEXT,"
                "size_bytes INTEGER, num_chunks INTEGER,"
                "price_per_mb INTEGER, z_addr BLOB,"
                "peer_ip BLOB, peer_port INTEGER,"
                "last_seen INTEGER, ttl INTEGER, auth_version INTEGER,"
                "network_genesis BLOB, seller_pubkey BLOB, nonce INTEGER,"
                "issued_unix INTEGER, expires_unix INTEGER,"
                "seller_signature BLOB, offer_id BLOB,"
                "endpoint_type INTEGER, onion_pubkey BLOB)",
                NULL, NULL, NULL);

            struct node_db ndb = { .db = db, .open = true };

            struct file_offer offer;
            int64_t now = (int64_t)platform_time_wall_time_t();
            bool made = market_test_signed_offer(&offer, 0xAA, 404, now);

            bool save = db_file_offer_save(&ndb, &offer);
            struct file_offer found = {0};
            bool find = db_file_offer_find(&ndb, offer.root_hash, &found);
            struct file_offer list[10];
            int count = db_file_offer_list(&ndb, list, 10);

            if (made && save && find &&
                strcmp(found.filename, offer.filename) == 0 &&
                memcmp(found.offer_id, offer.offer_id, 32) == 0 &&
                count == 1) {
                printf("OK\n");
            } else {
                printf("FAIL (save=%d find=%d count=%d)\n", save, find, count);
                failures++;
            }

            printf("file_market DB signed listing refuses cross-seller takeover... ");
            struct file_offer honest, attacker;
            uint8_t rogue_seed[32], rogue_secret[32];
            memset(rogue_seed, 0x77, sizeof(rogue_seed));
            bool pair_made = market_test_signed_offer(&honest, 0xC1, 501, now) &&
                market_test_signed_offer(&attacker, 0xC2, 502, now) &&
                db_file_offer_save(&ndb, &honest);
            /* Same content root, attacker's own signature and payment
             * address: a perfectly valid offer that must not re-key a root
             * an accepted listing already owns. */
            memcpy(attacker.root_hash, honest.root_hash, 32);
            snprintf(attacker.filename, sizeof(attacker.filename), "%s",
                     honest.filename);
            ed25519_keypair(attacker.seller_pubkey, rogue_secret, rogue_seed);
            bool attack_refused = pair_made &&
                file_offer_auth_seal(&attacker, rogue_seed) ==
                    FILE_OFFER_AUTH_OK &&
                !db_file_offer_save(&ndb, &attacker);
            struct file_offer listing = {0};
            bool listing_intact = attack_refused &&
                db_file_offer_find(&ndb, honest.root_hash, &listing) &&
                memcmp(listing.seller_pubkey, honest.seller_pubkey,
                       32) == 0 &&
                memcmp(listing.offer_id, honest.offer_id, 32) == 0;
            if (attack_refused && listing_intact) {
                printf("OK\n");
            } else {
                printf("FAIL (refused=%d intact=%d)\n", attack_refused,
                       listing_intact);
                failures++;
            }

            printf("file_market DB unsigned rows take only byte-identical refreshes... ");
            struct file_offer free_row;
            memset(&free_row, 0, sizeof(free_row));
            memset(free_row.root_hash, 0xE1, sizeof(free_row.root_hash));
            snprintf(free_row.filename, sizeof(free_row.filename),
                     "free.dat");
            free_row.size_bytes = 101;
            free_row.num_chunks = 1;
            free_row.ttl = FILE_MARKET_MAX_TTL;
            free_row.last_seen = now;
            bool free_saved = db_file_offer_save(&ndb, &free_row);
            struct file_offer free_poison = free_row;
            snprintf(free_poison.filename,
                     sizeof(free_poison.filename), "evil.dat");
            bool poison_refused = free_saved &&
                !db_file_offer_save(&ndb, &free_poison);
            struct file_offer free_refresh = free_row;
            free_refresh.last_seen = now + 5;
            free_refresh.peer_port = 19001;
            bool refresh_allowed = poison_refused &&
                db_file_offer_save(&ndb, &free_refresh);
            if (poison_refused && refresh_allowed) {
                printf("OK\n");
            } else {
                printf("FAIL (poison=%d refresh=%d)\n", poison_refused,
                       refresh_allowed);
                failures++;
            }

            /* Prune old entries */
            printf("file_market DB prune... ");
            offer.last_seen = 1;  /* very old */
            db_file_offer_save(&ndb, &offer);
            int pruned = db_file_offer_prune(&ndb, 60);
            if (pruned >= 0) printf("OK (pruned=%d)\n", pruned);
            else { printf("FAIL\n"); failures++; }

            sqlite3_close(db);
        }
    }

    failures += file_market_payment_tests();
    failures += file_market_delivery_tests();
    failures += file_market_content_tests();
    failures += file_market_purchase_tests();
    failures += file_market_offer_tests();
    printf("\n%d file_market test(s) failed\n", failures);
    return failures;
}
