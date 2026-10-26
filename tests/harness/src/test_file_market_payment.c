/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact zfilepay.v1 contract + authoritative confirmation/reorg tests. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/boot_internal.h"
#include "config/boot_msg_callbacks.h"
#include "crypto/ed25519.h"
#include "models/file_offer.h"
#include "models/market_payment_claim.h"
#include "models/wallet_tx.h"
#include "net/file_market.h"
#include "platform/time_compat.h"
#include "sapling/sapling.h"
#include "services/file_market_payment_service.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Walk the sync FSM along legal edges to AT_TIP so the composition adapter
 * treats the chain as current; the scan cursor is then the only variable. */
static bool payment_test_sync_at_tip(void)
{
    if (sync_get_state() == SYNC_AT_TIP)
        return true;
    if (sync_get_state() != SYNC_IDLE)
        (void)sync_set_state(SYNC_IDLE, "market payment coverage test");
    return sync_set_state(SYNC_HEADERS_DOWNLOAD,
                          "market payment coverage test") &&
           sync_set_state(SYNC_AT_TIP, "market payment coverage test");
}

/* The payment adapters must judge a claim against the height the wallet READ
 * through, not its stop height. A boot catch-up that could not read block 100
 * leaves best_block_height at the tip (101) with scan_retry.from == 100:
 * a claim whose paying transaction sits in block 100 is not knowable yet, so
 * the answer is UNKNOWN — never PENDING, CONFLICTED, or an unlock. */
static int payment_test_scan_coverage(struct node_db *ndb,
                                      struct main_state *main_state,
                                      const struct file_offer *base_offer,
                                      const uint8_t seller_seed[32],
                                      const uint8_t payment_block_hash[32],
                                      int64_t now_unix)
{
    int failures = 0;
    struct file_offer offer = *base_offer;
    memset(offer.root_hash, 0x75, sizeof(offer.root_hash));
    offer.nonce = 9005;
    struct file_payment unread_paid, unread_absent;
    struct wallet *w = zcl_calloc(1, sizeof(*w), "market payment wallet");
    bool fixture = w && file_offer_auth_seal(&offer, seller_seed) ==
                            FILE_OFFER_AUTH_OK &&
                   db_file_offer_save(ndb, &offer) &&
                   payment_test_claim_seeded(&unread_paid, &offer, 0x64,
                                             0x95) &&
                   payment_test_claim_seeded(&unread_absent, &offer, 0x65,
                                             0x96) &&
                   payment_test_insert_transaction(ndb, unread_paid.txid,
                                                   payment_block_hash, 100) &&
                   payment_test_sync_at_tip();
    PAYMENT_CHECK("scan-coverage fixture: wallet stopped at tip, block 100 "
                  "unread", fixture);
    if (!fixture) {
        free(w);
        return failures;
    }
    wallet_init(w);
    w->best_block_height = 101;
    w->scan_retry.pending = true;
    w->scan_retry.from = 100;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker),
             "RESCAN_NO_BLOCK_DATA");
    struct boot_svc_ctx svc;
    memset(&svc, 0, sizeof(svc));
    svc.node_db = ndb;
    svc.state = main_state;
    svc.wallet = w;

    struct market_payment_claim_record found;
    int verdict = boot_ingest_file_payment(&unread_paid, 0, now_unix, &svc);
    PAYMENT_CHECK("incomplete scan: paying tx in the unread block is UNKNOWN",
                  verdict == FILE_PAYMENT_INGEST_UNKNOWN &&
                  db_market_payment_claim_find(ndb, unread_paid.claim_id,
                                               &found) &&
                  strcmp(found.status, "UNKNOWN") == 0);
    verdict = boot_ingest_file_payment(&unread_absent, 0, now_unix, &svc);
    PAYMENT_CHECK("incomplete scan: a claim with no visible tx is UNKNOWN, "
                  "not PENDING",
                  verdict == FILE_PAYMENT_INGEST_UNKNOWN);
    struct market_payment_authorization authorization;
    struct zcl_result result = market_payment_authorize_chunk(
        ndb, main_state, true, wallet_read_scanned_through_height(w),
        offer.offer_id, unread_paid.buyer_pubkey, 1, now_unix,
        &authorization);
    PAYMENT_CHECK("incomplete scan: the paid chunk is not served",
                  result.ok && !authorization.authorized &&
                  strcmp(authorization.status, "UNKNOWN") == 0);

    /* The catch-up reads block 100 and clears the marker: today's
     * full-scan answers return unchanged. */
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    bool read = payment_test_insert_note(ndb, &unread_paid, &offer, 100);
    verdict = boot_ingest_file_payment(&unread_paid, 0, now_unix + 1, &svc);
    PAYMENT_CHECK("full scan: the paid tx in a read block is CONFIRMED",
                  read && verdict == FILE_PAYMENT_INGEST_CONFIRMED);
    result = market_payment_authorize_chunk(
        ndb, main_state, true, wallet_read_scanned_through_height(w),
        offer.offer_id, unread_paid.buyer_pubkey, 1, now_unix + 1,
        &authorization);
    PAYMENT_CHECK("full scan: the confirmed chunk is served",
                  result.ok && authorization.authorized &&
                  strcmp(authorization.status, "CONFIRMED") == 0);
    verdict = boot_ingest_file_payment(&unread_absent, 0, now_unix + 1, &svc);
    PAYMENT_CHECK("full scan: an unpaid claim is PENDING as before",
                  verdict == FILE_PAYMENT_INGEST_PENDING);

    (void)sync_set_state(SYNC_IDLE, "market payment coverage test");
    wallet_free(w);
    free(w);
    return failures;
}


static int payment_test_check_signed_fixture(struct file_offer *offer,
                                             struct file_payment *payment,
                                             int64_t now_unix, bool *stop)
{
    int failures = 0;
    bool made = payment_test_offer(offer, now_unix) &&
                payment_test_claim(payment, offer);
    PAYMENT_CHECK("signed offer + exact buyer claim fixture", made);
    *stop = !made;
    return failures;
}

static int payment_test_check_chunk_pricing(const struct file_offer *offer)
{
    int failures = 0;
    int64_t first_zat = 0, last_zat = 0, total_zat = 0;
    bool priced = file_market_offer_range_zat(offer, 0, 1, &first_zat) &&
                  file_market_offer_range_zat(offer, 1, 1, &last_zat) &&
                  file_market_offer_total_zat(offer, &total_zat);
    PAYMENT_CHECK("exact full and final-partial chunk pricing",
                  priced && first_zat == 60000 && last_zat == 1 &&
                  total_zat == 60001);
    return failures;
}

static int payment_test_check_claim_codec(const struct file_payment *payment,
                                          const struct file_offer *offer)
{
    int failures = 0;
    uint8_t wire[FILE_MARKET_PAYMENT_WIRE_BYTES];
    uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
    struct file_payment decoded = {0};
    bool codec = file_payment_auth_encode(payment, wire) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_auth_decode(wire, sizeof(wire), &decoded) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_auth_verify_for_offer(&decoded, offer) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_memo_encode(&decoded, memo) ==
                     FILE_PAYMENT_AUTH_OK &&
                 file_payment_memo_verify(&decoded, memo, sizeof(memo)) ==
                     FILE_PAYMENT_AUTH_OK;
    PAYMENT_CHECK("fixed claim wire + exact 512-byte memo", codec);

    struct file_payment tampered = decoded;
    tampered.amount_zat++;
    PAYMENT_CHECK("changed amount fails signed-offer verification",
        file_payment_auth_verify_for_offer(&tampered, offer) !=
            FILE_PAYMENT_AUTH_OK);
    tampered = decoded;
    tampered.buyer_signature[0] ^= 1;
    PAYMENT_CHECK("changed buyer signature fails verification",
        file_payment_auth_verify_for_offer(&tampered, offer) ==
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
    return failures;
}

static int payment_test_make_fixture_dir(char *dir, size_t dir_len,
                                         char *dbpath, size_t dbpath_len,
                                         bool *stop)
{
    int failures = 0;
    snprintf(dir, dir_len, "./test-tmp/market_payment_%d", (int)getpid());
    (void)mkdir("./test-tmp", 0700);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        PAYMENT_CHECK("create payment fixture directory", false);
        *stop = true;
        return failures;
    }
    snprintf(dbpath, dbpath_len, "%s/node.db", dir);
    *stop = false;
    return failures;
}

/* `tip` stays with the caller: active_chain_install_tip_slot stores the
 * pointer in the chain window for the rest of the test. */
static int payment_test_open_offer_db(struct node_db *ndb,
                                      struct main_state *main_state,
                                      const char *dbpath, const char *dir,
                                      struct block_index *tip,
                                      const struct file_offer *offer,
                                      bool *stop)
{
    int failures = 0;
    main_state_init(main_state);
    bool opened = node_db_open(ndb, dbpath) &&
                  active_chain_install_tip_slot(&main_state->chain_active,
                                                tip) &&
                  db_file_offer_save(ndb, offer);
    PAYMENT_CHECK("durable offer/payment database fixture", opened);
    if (!opened) {
        if (ndb->open) node_db_close(ndb);
        main_state_free(main_state);
        test_cleanup_tmpdir(dir);
        *stop = true;
        return failures;
    }
    *stop = false;
    return failures;
}

static int payment_test_check_stale_unknown(struct node_db *ndb,
                                            struct main_state *main_state,
                                            const struct file_payment *payment,
                                            int64_t now_unix)
{
    int failures = 0;
    struct market_payment_claim_record record;
    struct zcl_result result = market_payment_claim_ingest(
        ndb, main_state, false, -1, payment, now_unix, &record);
    PAYMENT_CHECK("stale chain/wallet state records UNKNOWN, never zero",
                  result.ok && strcmp(record.status, "UNKNOWN") == 0);

    result = market_payment_claim_reconcile(
        ndb, main_state, true, 100, payment->claim_id,
        now_unix + 1, &record);
    PAYMENT_CHECK("wallet projection behind tip remains UNKNOWN",
                  result.ok && strcmp(record.status, "UNKNOWN") == 0);
    return failures;
}

static int payment_test_check_canonical_confirm(
    struct node_db *ndb, struct main_state *main_state,
    const struct file_payment *payment, const struct file_offer *offer,
    const uint8_t payment_block_hash[32], const uint8_t tip_hash[32],
    int64_t now_unix)
{
    int failures = 0;
    bool chain_ready = payment_test_insert_block(
                           ndb, payment_block_hash, 100, now_unix, 3) &&
                       payment_test_insert_block(
                           ndb, tip_hash, 101, now_unix + 1, 3) &&
                       payment_test_insert_transaction(
                           ndb, payment->txid, payment_block_hash, 100) &&
                       payment_test_insert_note(
                           ndb, payment, offer, 100);
    PAYMENT_CHECK("canonical transaction + decrypted seller note fixture",
                  chain_ready);

    struct market_payment_claim_record record;
    struct zcl_result result = market_payment_claim_reconcile(
        ndb, main_state, true, 101, payment->claim_id,
        now_unix + 2, &record);
    PAYMENT_CHECK("exact canonical Sapling output confirms payment",
                  result.ok && strcmp(record.status, "CONFIRMED") == 0 &&
                  record.block_height == 100 && record.confirmations == 2);

    struct market_payment_authorization authorization;
    result = market_payment_authorize_chunk(
        ndb, main_state, true, 101, offer->offer_id,
        payment->buyer_pubkey, 1, now_unix + 3, &authorization);
    PAYMENT_CHECK("confirmed range authorizes its exact chunk",
                  result.ok && authorization.authorized &&
                  strcmp(authorization.status, "CONFIRMED") == 0);
    result = market_payment_authorize_chunk(
        ndb, main_state, true, 101, offer->offer_id,
        payment->buyer_pubkey, 0, now_unix + 3, &authorization);
    PAYMENT_CHECK("confirmed range does not authorize another chunk",
                  result.ok && !authorization.authorized);
    return failures;
}

static int payment_test_check_restart_and_reorg(
    struct node_db *ndb, struct main_state *main_state, const char *dbpath,
    const struct file_payment *payment, const struct file_offer *offer,
    const uint8_t payment_block_hash[32], int64_t now_unix)
{
    int failures = 0;
    struct market_payment_claim_record record;
    struct market_payment_authorization authorization;
    node_db_close(ndb);
    bool reopened = node_db_open(ndb, dbpath);
    struct zcl_result result = reopened ? market_payment_claim_reconcile(
        ndb, main_state, true, 101, payment->claim_id,
        now_unix + 4, &record) : ZCL_ERR(-1, "reopen failed");
    PAYMENT_CHECK("restart reconstructs confirmed payment authority",
                  reopened && result.ok &&
                  strcmp(record.status, "CONFIRMED") == 0);

    bool detached = payment_test_set_block_status(
        ndb, payment_block_hash, 2);
    result = market_payment_claim_reconcile(
        ndb, main_state, true, 101, payment->claim_id,
        now_unix + 5, &record);
    PAYMENT_CHECK("reorg revokes a previously confirmed authorization",
                  detached && result.ok &&
                  strcmp(record.status, "CONFLICTED") == 0);
    result = market_payment_authorize_chunk(
        ndb, main_state, true, 101, offer->offer_id,
        payment->buyer_pubkey, 1, now_unix + 5, &authorization);
    PAYMENT_CHECK("reorged payment cannot unlock its chunk",
                  result.ok && !authorization.authorized &&
                  strcmp(authorization.status, "CONFLICTED") == 0);

    bool restored = payment_test_set_block_status(
        ndb, payment_block_hash, 3);
    result = market_payment_claim_reconcile(
        ndb, main_state, true, 101, payment->claim_id,
        now_unix + 6, &record);
    PAYMENT_CHECK("reconfirmation restores authorization after reorg",
                  restored && result.ok &&
                  strcmp(record.status, "CONFIRMED") == 0);
    return failures;
}

static int payment_test_check_onion_claim(struct node_db *ndb,
                                          struct main_state *main_state,
                                          const struct file_offer *offer,
                                          uint8_t *seller_seed,
                                          size_t seed_len, int64_t now_unix)
{
    int failures = 0;
    /* Regression: a claim against a v2 (onion-endpoint) signed offer
     * carries the 568-byte v2 offer wire (FILE_MARKET_OFFER_WIRE_BYTES_V2).
     * The v56 market_payment_claims schema pinned
     * CHECK(length(offer_wire)=535) — the v1 wire — so every onion-offer
     * claim INSERT failed the CHECK, the seller never persisted the claim,
     * and per-chunk authorization sat at PENDING forever (no candidates).
     * v64 widens the CHECK to IN (535,568); this saves through the real
     * ingest path on a freshly migrated database. */
    struct file_offer onion_offer = *offer;
    memset(seller_seed, 0x51, seed_len);
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
        db_file_offer_save(ndb, &onion_offer) &&
        payment_test_claim(&onion_payment, &onion_offer);
    PAYMENT_CHECK("v2 onion-endpoint offer + claim fixture", onion_fixture);
    struct market_payment_claim_record record;
    struct zcl_result result = onion_fixture
        ? market_payment_claim_ingest(ndb, main_state, false, -1,
                                      &onion_payment, now_unix, &record)
        : ZCL_ERR(-1, "fixture failed");
    PAYMENT_CHECK("v2 onion-endpoint claim persists (568-byte offer wire)",
                  onion_fixture && result.ok &&
                  strcmp(record.status, "UNKNOWN") == 0);
    struct market_payment_claim_record found;
    PAYMENT_CHECK("v2 onion claim survives durable readback",
        onion_fixture &&
        db_market_payment_claim_find(ndb, onion_payment.claim_id, &found) &&
        found.offer.endpoint_type == FILE_MARKET_ENDPOINT_ONION);
    return failures;
}

static int payment_test_check_claim_cap(struct node_db *ndb,
                                        struct main_state *main_state,
                                        const struct file_offer *offer,
                                        const uint8_t *seller_seed,
                                        int64_t now_unix)
{
    int failures = 0;
    /* Claim cap: claim_id is content-bound, so fresh buyer keypairs mint
     * unlimited self-consistent claims against one live offer. The ingest
     * must refuse beyond MARKET_PAYMENT_CLAIM_OFFER_MAX without evicting the
     * earlier claims — refusal, not eviction, keeps an honest early claim. */
    struct file_offer capped_offer = *offer;
    memset(capped_offer.root_hash, 0x73, sizeof(capped_offer.root_hash));
    capped_offer.nonce = 9003;
    bool capped_ready = file_offer_auth_seal(&capped_offer, seller_seed) ==
                            FILE_OFFER_AUTH_OK &&
                        db_file_offer_save(ndb, &capped_offer);
    bool cap_enforced = capped_ready;
    struct file_payment flood;
    struct market_payment_claim_record record;
    struct zcl_result flood_result = ZCL_OK;
    for (int i = 0; cap_enforced && i <= MARKET_PAYMENT_CLAIM_OFFER_MAX; i++) {
        if (!payment_test_claim_seeded(&flood, &capped_offer,
                                       (uint8_t)(0x30 + i), 0x91)) {
            cap_enforced = false;
            break;
        }
        flood_result = market_payment_claim_ingest(
            ndb, main_state, false, -1, &flood, now_unix, &record);
        cap_enforced = flood_result.ok == (i < MARKET_PAYMENT_CLAIM_OFFER_MAX);
    }
    PAYMENT_CHECK("per-offer cap refuses the (cap+1)th distinct valid claim",
                  cap_enforced && !flood_result.ok && flood_result.code == -9 &&
                  strstr(flood_result.message, "cap") != NULL &&
                  db_market_payment_claim_count_for_offer(
                      ndb, capped_offer.offer_id) ==
                      MARKET_PAYMENT_CLAIM_OFFER_MAX);
    return failures;
}

static bool payment_test_expiring_claims_ready(
    struct node_db *ndb, struct file_offer *expiring_offer,
    const uint8_t *seller_seed, const uint8_t *payment_block_hash,
    struct file_payment *settled, struct file_payment *stale)
{
    bool expiring_ready = file_offer_auth_seal(expiring_offer, seller_seed) ==
                              FILE_OFFER_AUTH_OK &&
                          db_file_offer_save(ndb, expiring_offer);
    return expiring_ready &&
        payment_test_claim_seeded(settled, expiring_offer, 0x61, 0x93) &&
        payment_test_insert_transaction(ndb, settled->txid,
                                        payment_block_hash, 100) &&
        payment_test_insert_note(ndb, settled, expiring_offer, 100) &&
        payment_test_claim_seeded(stale, expiring_offer, 0x62, 0x92);
}

static bool payment_test_ingested_claim_status(
    bool ready, struct node_db *ndb, struct main_state *main_state,
    const struct file_payment *payment, int64_t now_unix, const char *status)
{
    struct market_payment_claim_record record;
    struct zcl_result result = ready
        ? market_payment_claim_ingest(ndb, main_state, true, 101, payment,
                                      now_unix, &record)
        : ZCL_ERR(-1, "fixture failed");
    return ready && result.ok && strcmp(record.status, status) == 0;
}

static int payment_test_check_offer_expiry(
    struct node_db *ndb, struct main_state *main_state,
    const struct file_offer *offer, const uint8_t *seller_seed,
    const uint8_t *payment_block_hash, int64_t now_unix)
{
    int failures = 0;
    /* Prune: an expired offer's non-CONFIRMED claims are dropped by the next
     * ingest touching that offer, while a CONFIRMED row always survives as
     * settlement evidence. Time is injected through the ingest's now_unix —
     * the test never waits on the wall clock. */
    struct file_offer expiring_offer = *offer;
    memset(expiring_offer.root_hash, 0x74, sizeof(expiring_offer.root_hash));
    expiring_offer.nonce = 9004;
    expiring_offer.expires_unix = now_unix + 120;
    struct file_payment settled, stale, late;
    bool expiry_fixture = payment_test_expiring_claims_ready(
        ndb, &expiring_offer, seller_seed, payment_block_hash,
        &settled, &stale);
    expiry_fixture = payment_test_ingested_claim_status(
        expiry_fixture, ndb, main_state, &settled, now_unix, "CONFIRMED");
    expiry_fixture = payment_test_ingested_claim_status(
        expiry_fixture, ndb, main_state, &stale, now_unix, "PENDING");
    PAYMENT_CHECK("expired-offer fixture stores confirmed and pending claims",
                  expiry_fixture);

    bool late_ready = payment_test_claim_seeded(&late, &expiring_offer, 0x63,
                                                0x94);
    struct market_payment_claim_record record;
    struct zcl_result result = late_ready
        ? market_payment_claim_ingest(ndb, main_state, true, 101, &late,
                                      expiring_offer.expires_unix + 1, &record)
        : ZCL_ERR(-1, "fixture failed");
    struct market_payment_claim_record found;
    bool settlement_kept =
        db_market_payment_claim_find(ndb, settled.claim_id, &found) &&
        strcmp(found.status, "CONFIRMED") == 0;
    bool pending_dropped =
        !db_market_payment_claim_find(ndb, stale.claim_id, &found);
    PAYMENT_CHECK("expired offer prunes pending claims, keeps settlement",
                  result.code == -7 && settlement_kept && pending_dropped &&
                  db_market_payment_claim_count_for_offer(
                      ndb, expiring_offer.offer_id) == 1);
    return failures;
}

int file_market_payment_tests(void)
{
    int failures = 0;
    int64_t now_unix = (int64_t)platform_time_wall_time_t();
    struct file_offer offer;
    struct file_payment payment;
    bool stop = false;
    failures += payment_test_check_signed_fixture(&offer, &payment, now_unix,
                                                  &stop);
    if (stop)
        return failures;

    failures += payment_test_check_chunk_pricing(&offer);
    failures += payment_test_check_claim_codec(&payment, &offer);

    char dir[256], dbpath[512];
    failures += payment_test_make_fixture_dir(dir, sizeof(dir), dbpath,
                                              sizeof(dbpath), &stop);
    if (stop)
        return failures;

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
    failures += payment_test_open_offer_db(&ndb, &main_state, dbpath, dir,
                                           &tip, &offer, &stop);
    if (stop)
        return failures;

    failures += payment_test_check_stale_unknown(&ndb, &main_state, &payment,
                                                 now_unix);
    failures += payment_test_check_canonical_confirm(
        &ndb, &main_state, &payment, &offer, payment_block_hash, tip_hash,
        now_unix);
    failures += payment_test_check_restart_and_reorg(
        &ndb, &main_state, dbpath, &payment, &offer, payment_block_hash,
        now_unix);

    uint8_t seller_seed[32];
    failures += payment_test_check_onion_claim(
        &ndb, &main_state, &offer, seller_seed, sizeof(seller_seed), now_unix);
    failures += payment_test_check_claim_cap(&ndb, &main_state, &offer,
                                             seller_seed, now_unix);
    failures += payment_test_check_offer_expiry(
        &ndb, &main_state, &offer, seller_seed, payment_block_hash, now_unix);
    failures += payment_test_scan_coverage(&ndb, &main_state, &offer,
                                           seller_seed, payment_block_hash,
                                           now_unix);
    node_db_close(&ndb);
    main_state_free(&main_state);
    test_cleanup_tmpdir(dir);
    return failures;
}
