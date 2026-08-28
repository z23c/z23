/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact zfilepay.v1 contract + authoritative confirmation/reorg tests. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "crypto/ed25519.h"
#include "models/file_offer.h"
#include "models/market_payment_claim.h"
#include "models/wallet_tx.h"
#include "net/file_market.h"
#include "platform/time_compat.h"
#include "sapling/sapling.h"
#include "services/file_market_payment_service.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PAYMENT_CHECK(label, condition) do {                         \
    printf("file_market payment: %s... ", (label));                 \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static bool payment_test_offer(struct file_offer *offer, int64_t now_unix)
{
    const struct chain_params *params = chain_params_get();
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    if (!params)
        return false;
    memset(offer, 0, sizeof(*offer));
    memset(seed, 0x51, sizeof(seed));
    memset(offer->root_hash, 0x71, sizeof(offer->root_hash));
    memcpy(offer->network_genesis,
           params->consensus.hashGenesisBlock.data, 32);
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "payment-fixture.bin");
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
    offer->peer_ip[15] = 1;
    offer->peer_port = 18034;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->last_seen = now_unix;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = 9001;
    offer->issued_unix = now_unix - 60;
    offer->expires_unix = now_unix + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

/* Each claim mints a fresh buyer keypair: claim_id is content-bound over the
 * whole wire, so the keypair is what makes two claims of one offer distinct. */
static bool payment_test_claim_seeded(struct file_payment *payment,
                                      const struct file_offer *offer,
                                      uint8_t seed_byte, uint8_t txid_byte)
{
    uint8_t seed[32], secret[32];
    memset(payment, 0, sizeof(*payment));
    memset(seed, seed_byte, sizeof(seed));
    payment->version = FILE_MARKET_PAYMENT_VERSION;
    memcpy(payment->network_genesis, offer->network_genesis, 32);
    memcpy(payment->offer_id, offer->offer_id, 32);
    memset(payment->txid, txid_byte, sizeof(payment->txid));
    payment->chunk_start = 1;
    payment->chunks_paid = 1;
    if (!file_market_offer_range_zat(offer, payment->chunk_start,
                                     payment->chunks_paid,
                                     &payment->amount_zat))
        return false;
    ed25519_keypair(payment->buyer_pubkey, secret, seed);
    return file_payment_auth_seal(payment, seed) == FILE_PAYMENT_AUTH_OK;
}

static bool payment_test_claim(struct file_payment *payment,
                               const struct file_offer *offer)
{
    return payment_test_claim_seeded(payment, offer, 0x29, 0x91);
}

static bool payment_test_insert_block(struct node_db *ndb,
                                      const uint8_t hash[32], int height,
                                      int64_t block_time, int status)
{
    static const uint8_t zero32[32] = {0};
    sqlite3_stmt *s = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO blocks("
        "hash,height,prev_hash,version,merkle_root,time,bits,nonce,solution,"
        "chain_work,status,num_tx) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, 4);
    sqlite3_bind_blob(s, 5, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 6, block_time);
    sqlite3_bind_int(s, 7, 1);
    sqlite3_bind_blob(s, 8, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 9, zero32, 1, SQLITE_STATIC);
    sqlite3_bind_blob(s, 10, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 11, status);
    sqlite3_bind_int(s, 12, 1);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool payment_test_insert_transaction(
    struct node_db *ndb, const uint8_t txid[32],
    const uint8_t block_hash[32], int block_height)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO transactions("
            "txid,block_hash,block_height,tx_index,file_num,file_pos,is_coinbase)"
            " VALUES(?,?,?,0,0,0,0)", -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, block_hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 3, block_height);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool payment_test_insert_note(
    struct node_db *ndb, const struct file_payment *payment,
    const struct file_offer *offer, int block_height)
{
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    memcpy(note.txid, payment->txid, 32);
    note.output_index = 0;
    note.value = payment->amount_zat;
    memset(note.rcm, 0x11, sizeof(note.rcm));
    if (file_payment_memo_encode(payment, note.memo) !=
        FILE_PAYMENT_AUTH_OK)
        return false;
    note.memo_len = FILE_MARKET_PAYMENT_MEMO_BYTES;
    memset(note.ivk, 0x22, sizeof(note.ivk));
    memcpy(note.diversifier, offer->z_addr, 11);
    memcpy(note.pk_d, offer->z_addr + 11, 32);
    memset(note.cm, 0x33, sizeof(note.cm));
    memset(note.nullifier, 0x44, sizeof(note.nullifier));
    note.block_height = block_height;
    snprintf(note.source, sizeof(note.source), "%s",
             DB_SAPLING_NOTE_SOURCE_LOCAL);
    return db_sapling_note_save(ndb, &note);
}

static bool payment_test_set_block_status(struct node_db *ndb,
                                          const uint8_t hash[32], int status)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "UPDATE blocks SET status=? WHERE hash=?", -1, &s, NULL) !=
        SQLITE_OK)
        return false;
    sqlite3_bind_int(s, 1, status);
    sqlite3_bind_blob(s, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(ndb->db) == 1;
    sqlite3_finalize(s);
    return ok;
}

int file_market_payment_tests(void)
{
    int failures = 0;
    int64_t now_unix = (int64_t)platform_time_wall_time_t();
    struct file_offer offer;
    struct file_payment payment;
    bool made = payment_test_offer(&offer, now_unix) &&
                payment_test_claim(&payment, &offer);
    PAYMENT_CHECK("signed offer + exact buyer claim fixture", made);
    if (!made)
        return failures;

    int64_t first_zat = 0, last_zat = 0, total_zat = 0;
    bool priced = file_market_offer_range_zat(&offer, 0, 1, &first_zat) &&
                  file_market_offer_range_zat(&offer, 1, 1, &last_zat) &&
                  file_market_offer_total_zat(&offer, &total_zat);
    PAYMENT_CHECK("exact full and final-partial chunk pricing",
                  priced && first_zat == 60000 && last_zat == 1 &&
                  total_zat == 60001);

    uint8_t wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
    struct file_payment decoded = {0};
    bool codec = file_payment_auth_encode(&payment, wire) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_auth_decode(wire, sizeof(wire), &decoded) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_auth_verify_for_offer(&decoded, &offer) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_memo_encode(&decoded, memo) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_memo_verify(&decoded, memo, sizeof(memo)) ==
                     FILE_PAYMENT_AUTH_OK;
    PAYMENT_CHECK("fixed claim wire + exact 512-byte memo", codec);

    struct file_payment tampered = decoded;
    tampered.amount_zat++;
    PAYMENT_CHECK("changed amount fails signed-offer verification",
        file_payment_auth_verify_for_offer(&tampered, &offer) !=
            FILE_PAYMENT_AUTH_OK);
    tampered = decoded;
    tampered.buyer_signature[0] ^= 1;
    PAYMENT_CHECK("changed buyer signature fails verification",
        file_payment_auth_verify_for_offer(&tampered, &offer) ==
            FILE_PAYMENT_AUTH_ERR_SIGNATURE);
    memo[FILE_MARKET_PAYMENT_MEMO_BYTES - 1] = 1;
    PAYMENT_CHECK("noncanonical memo padding fails closed",
        file_payment_memo_verify(&decoded, memo, sizeof(memo)) ==
            FILE_PAYMENT_AUTH_ERR_MEMO);
    struct byte_stream legacy;
    uint8_t old_wire[72] = {0};
    stream_init_from_data(&legacy, old_wire, sizeof(old_wire));
    PAYMENT_CHECK("legacy mempool-only payment wire is rejected",
                  !file_payment_deserialize(&tampered, &legacy));

    char dir[256], dbpath[512];
    snprintf(dir, sizeof(dir), "./test-tmp/market_payment_%d", (int)getpid());
    (void)mkdir("./test-tmp", 0700);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        PAYMENT_CHECK("create payment fixture directory", false);
        return failures;
    }
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    struct main_state main_state;
    struct block_index tip;
    uint8_t payment_block_hash[32], tip_hash[32];
    memset(&tip, 0, sizeof(tip));
    memset(payment_block_hash, 0xa0, sizeof(payment_block_hash));
    memset(tip_hash, 0xa1, sizeof(tip_hash));
    tip.nHeight = 101;
    memcpy(tip.hashBlock.data, tip_hash, 32);
    tip.phashBlock = &tip.hashBlock;
    main_state_init(&main_state);
    bool opened = node_db_open(&ndb, dbpath) &&
                  active_chain_install_tip_slot(&main_state.chain_active,
                                                &tip) &&
                  db_file_offer_save(&ndb, &offer);
    PAYMENT_CHECK("durable offer/payment database fixture", opened);
    if (!opened) {
        if (ndb.open) node_db_close(&ndb);
        main_state_free(&main_state);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct market_payment_claim_record record;
    struct zcl_result result = market_payment_claim_ingest(
        &ndb, &main_state, false, -1, &payment, now_unix, &record);
    PAYMENT_CHECK("stale chain/wallet state records UNKNOWN, never zero",
                  result.ok && strcmp(record.status, "UNKNOWN") == 0);

    result = market_payment_claim_reconcile(
        &ndb, &main_state, true, 100, payment.claim_id,
        now_unix + 1, &record);
    PAYMENT_CHECK("wallet projection behind tip remains UNKNOWN",
                  result.ok && strcmp(record.status, "UNKNOWN") == 0);

    bool chain_ready = payment_test_insert_block(
                           &ndb, payment_block_hash, 100, now_unix, 3) &&
                       payment_test_insert_block(
                           &ndb, tip_hash, 101, now_unix + 1, 3) &&
                       payment_test_insert_transaction(
                           &ndb, payment.txid, payment_block_hash, 100) &&
                       payment_test_insert_note(
                           &ndb, &payment, &offer, 100);
    PAYMENT_CHECK("canonical transaction + decrypted seller note fixture",
                  chain_ready);

    result = market_payment_claim_reconcile(
        &ndb, &main_state, true, 101, payment.claim_id,
        now_unix + 2, &record);
    PAYMENT_CHECK("exact canonical Sapling output confirms payment",
                  result.ok && strcmp(record.status, "CONFIRMED") == 0 &&
                  record.block_height == 100 && record.confirmations == 2);

    struct market_payment_authorization authorization;
    result = market_payment_authorize_chunk(
        &ndb, &main_state, true, 101, offer.offer_id,
        payment.buyer_pubkey, 1, now_unix + 3, &authorization);
    PAYMENT_CHECK("confirmed range authorizes its exact chunk",
                  result.ok && authorization.authorized &&
                  strcmp(authorization.status, "CONFIRMED") == 0);
    result = market_payment_authorize_chunk(
        &ndb, &main_state, true, 101, offer.offer_id,
        payment.buyer_pubkey, 0, now_unix + 3, &authorization);
    PAYMENT_CHECK("confirmed range does not authorize another chunk",
                  result.ok && !authorization.authorized);

    node_db_close(&ndb);
    bool reopened = node_db_open(&ndb, dbpath);
    result = reopened ? market_payment_claim_reconcile(
        &ndb, &main_state, true, 101, payment.claim_id,
        now_unix + 4, &record) : ZCL_ERR(-1, "reopen failed");
    PAYMENT_CHECK("restart reconstructs confirmed payment authority",
                  reopened && result.ok &&
                  strcmp(record.status, "CONFIRMED") == 0);

    bool detached = payment_test_set_block_status(
        &ndb, payment_block_hash, 2);
    result = market_payment_claim_reconcile(
        &ndb, &main_state, true, 101, payment.claim_id,
        now_unix + 5, &record);
    PAYMENT_CHECK("reorg revokes a previously confirmed authorization",
                  detached && result.ok &&
                  strcmp(record.status, "CONFLICTED") == 0);
    result = market_payment_authorize_chunk(
        &ndb, &main_state, true, 101, offer.offer_id,
        payment.buyer_pubkey, 1, now_unix + 5, &authorization);
    PAYMENT_CHECK("reorged payment cannot unlock its chunk",
                  result.ok && !authorization.authorized &&
                  strcmp(authorization.status, "CONFLICTED") == 0);

    bool restored = payment_test_set_block_status(
        &ndb, payment_block_hash, 3);
    result = market_payment_claim_reconcile(
        &ndb, &main_state, true, 101, payment.claim_id,
        now_unix + 6, &record);
    PAYMENT_CHECK("reconfirmation restores authorization after reorg",
                  restored && result.ok &&
                  strcmp(record.status, "CONFIRMED") == 0);

    /* Regression: a claim against a v2 (onion-endpoint) signed offer
     * carries the 568-byte v2 offer wire (FILE_MARKET_OFFER_WIRE_BYTES_V2).
     * The v56 market_payment_claims schema pinned
     * CHECK(length(offer_wire)=535) — the v1 wire — so every onion-offer
     * claim INSERT failed the CHECK, the seller never persisted the claim,
     * and per-chunk authorization sat at PENDING forever (no candidates).
     * v64 widens the CHECK to IN (535,568); this saves through the real
     * ingest path on a freshly migrated database. */
    struct file_offer onion_offer = offer;
    uint8_t seller_seed[32];
    memset(seller_seed, 0x51, sizeof(seller_seed));
    memset(onion_offer.root_hash, 0x72, sizeof(onion_offer.root_hash));
    onion_offer.auth_version = FILE_MARKET_OFFER_VERSION_V2;
    onion_offer.endpoint_type = FILE_MARKET_ENDPOINT_ONION;
    memset(onion_offer.onion_pubkey, 0x66, sizeof(onion_offer.onion_pubkey));
    /* The v2 onion contract forbids a usable clearnet endpoint
     * (file_offer_auth_validate): peer_ip must be all-zero, peer_port 0. */
    memset(onion_offer.peer_ip, 0, sizeof(onion_offer.peer_ip));
    onion_offer.peer_port = 0;
    onion_offer.nonce = 9002;
    struct file_payment onion_payment;
    bool onion_fixture =
        file_offer_auth_seal(&onion_offer, seller_seed) ==
            FILE_OFFER_AUTH_OK &&
        db_file_offer_save(&ndb, &onion_offer) &&
        payment_test_claim(&onion_payment, &onion_offer);
    PAYMENT_CHECK("v2 onion-endpoint offer + claim fixture", onion_fixture);
    result = onion_fixture
        ? market_payment_claim_ingest(&ndb, &main_state, false, -1,
                                      &onion_payment, now_unix, &record)
        : ZCL_ERR(-1, "fixture failed");
    PAYMENT_CHECK("v2 onion-endpoint claim persists (568-byte offer wire)",
                  onion_fixture && result.ok &&
                  strcmp(record.status, "UNKNOWN") == 0);
    struct market_payment_claim_record found;
    PAYMENT_CHECK("v2 onion claim survives durable readback",
        onion_fixture &&
        db_market_payment_claim_find(&ndb, onion_payment.claim_id, &found) &&
        found.offer.endpoint_type == FILE_MARKET_ENDPOINT_ONION);

    /* Claim cap: claim_id is content-bound, so fresh buyer keypairs mint
     * unlimited self-consistent claims against one live offer. The ingest
     * must refuse beyond MARKET_PAYMENT_CLAIM_OFFER_MAX without evicting the
     * earlier claims — refusal, not eviction, keeps an honest early claim. */
    struct file_offer capped_offer = offer;
    memset(capped_offer.root_hash, 0x73, sizeof(capped_offer.root_hash));
    capped_offer.nonce = 9003;
    bool capped_ready = file_offer_auth_seal(&capped_offer, seller_seed) ==
                            FILE_OFFER_AUTH_OK &&
                        db_file_offer_save(&ndb, &capped_offer);
    bool cap_enforced = capped_ready;
    struct file_payment flood;
    struct zcl_result flood_result = ZCL_OK;
    for (int i = 0; cap_enforced && i <= MARKET_PAYMENT_CLAIM_OFFER_MAX; i++) {
        if (!payment_test_claim_seeded(&flood, &capped_offer,
                                       (uint8_t)(0x30 + i), 0x91)) {
            cap_enforced = false;
            break;
        }
        flood_result = market_payment_claim_ingest(
            &ndb, &main_state, false, -1, &flood, now_unix, &record);
        cap_enforced = flood_result.ok == (i < MARKET_PAYMENT_CLAIM_OFFER_MAX);
    }
    PAYMENT_CHECK("per-offer cap refuses the (cap+1)th distinct valid claim",
                  cap_enforced && !flood_result.ok && flood_result.code == -9 &&
                  strstr(flood_result.message, "cap") != NULL &&
                  db_market_payment_claim_count_for_offer(
                      &ndb, capped_offer.offer_id) ==
                      MARKET_PAYMENT_CLAIM_OFFER_MAX);

    /* Prune: an expired offer's non-CONFIRMED claims are dropped by the next
     * ingest touching that offer, while a CONFIRMED row always survives as
     * settlement evidence. Time is injected through the ingest's now_unix —
     * the test never waits on the wall clock. */
    struct file_offer expiring_offer = offer;
    memset(expiring_offer.root_hash, 0x74, sizeof(expiring_offer.root_hash));
    expiring_offer.nonce = 9004;
    expiring_offer.expires_unix = now_unix + 120;
    bool expiring_ready = file_offer_auth_seal(&expiring_offer, seller_seed) ==
                              FILE_OFFER_AUTH_OK &&
                          db_file_offer_save(&ndb, &expiring_offer);
    struct file_payment settled, stale, late;
    bool expiry_fixture = expiring_ready &&
        payment_test_claim_seeded(&settled, &expiring_offer, 0x61, 0x93) &&
        payment_test_insert_transaction(&ndb, settled.txid,
                                        payment_block_hash, 100) &&
        payment_test_insert_note(&ndb, &settled, &expiring_offer, 100) &&
        payment_test_claim_seeded(&stale, &expiring_offer, 0x62, 0x92);
    result = expiry_fixture
        ? market_payment_claim_ingest(&ndb, &main_state, true, 101, &settled,
                                      now_unix, &record)
        : ZCL_ERR(-1, "fixture failed");
    expiry_fixture = expiry_fixture && result.ok &&
                     strcmp(record.status, "CONFIRMED") == 0;
    result = expiry_fixture
        ? market_payment_claim_ingest(&ndb, &main_state, true, 101, &stale,
                                      now_unix, &record)
        : ZCL_ERR(-1, "fixture failed");
    expiry_fixture = expiry_fixture && result.ok &&
                     strcmp(record.status, "PENDING") == 0;
    PAYMENT_CHECK("expired-offer fixture stores confirmed and pending claims",
                  expiry_fixture);

    bool late_ready = payment_test_claim_seeded(&late, &expiring_offer, 0x63,
                                                0x94);
    result = late_ready
        ? market_payment_claim_ingest(&ndb, &main_state, true, 101, &late,
                                      expiring_offer.expires_unix + 1, &record)
        : ZCL_ERR(-1, "fixture failed");
    bool settlement_kept =
        db_market_payment_claim_find(&ndb, settled.claim_id, &found) &&
        strcmp(found.status, "CONFIRMED") == 0;
    bool pending_dropped =
        !db_market_payment_claim_find(&ndb, stale.claim_id, &found);
    PAYMENT_CHECK("expired offer prunes pending claims, keeps settlement",
                  result.code == -7 && settlement_kept && pending_dropped &&
                  db_market_payment_claim_count_for_offer(
                      &ndb, expiring_offer.offer_id) == 1);

    node_db_close(&ndb);
    main_state_free(&main_state);
    test_cleanup_tmpdir(dir);
    return failures;
}
