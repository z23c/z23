/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for snapshot sync service policy helpers. */

#include "test/test_core.h"
#include "models/database.h"
#include "net/snapshot_sync_contract.h"
#include "services/snapshot_manifest.h"
#include "config/db_service.h"
#include "config/boot_snapshot_offer.h"
#include "config/runtime.h"
#include "services/sync_trust_policy.h"
#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "chain/checkpoints.h"
#include "jobs/stage_helpers.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/main_state.h"
#include <string.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>

static void build_snapshot_chunk(struct byte_stream *s)
{
    const uint8_t txid[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    const uint8_t script[] = {
        0x76, 0xa9, 0x14,
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x88, 0xac
    };

    stream_init(s, 128);
    stream_write_u32_le(s, 1);
    stream_write_bytes(s, txid, sizeof(txid));
    stream_write_u32_le(s, 2);
    stream_write_u64_le(s, 5000000000ULL);
    stream_write_u32_le(s, 345678);
    stream_write_u8(s, 0);
    stream_write_u8(s, (uint8_t)sizeof(script));
    stream_write_bytes(s, script, sizeof(script));
}

static int test_snapshot_offer_trust_policy(void)
{
    int failures = 0;
    TEST("snapshot offer trust policy permits only complete sovereign state") {
        ASSERT(boot_snapshot_offer_trust_policy(
            true, true, true, 0, true, 0, true, 0));
        ASSERT(!boot_snapshot_offer_trust_policy(
            false, true, true, 0, true, 0, true, 0));
        ASSERT(!boot_snapshot_offer_trust_policy(
            true, false, true, 0, true, 0, true, 0));
        ASSERT(!boot_snapshot_offer_trust_policy(
            true, true, true, 1, true, 0, true, 0));
        ASSERT(!boot_snapshot_offer_trust_policy(
            true, true, true, 0, true, 1, true, 0));
        ASSERT(!boot_snapshot_offer_trust_policy(
            true, true, true, 0, true, 0, true, 1));
        ASSERT(!boot_snapshot_offer_trust_policy(
            true, true, false, 0, true, 0, true, 0));
        char reason[96] = {0};
        boot_snapshot_offer_test_set_trust_override(1);
        boot_snapshot_offer_test_set_publication_override(-1);
        ASSERT(!boot_snapshot_offer_state_is_sovereign(reason,
                                                        sizeof(reason)));
        ASSERT(strcmp(reason,
                      "snapshot_payload_authority_binding_incomplete") == 0);
        boot_snapshot_offer_test_set_trust_override(-1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_boot_publish_block_swarm(void)
{
    int failures = 0;
    TEST("block swarm publishes for caught-up z23 peers, not IBD") {
        ASSERT(!boot_publish_block_swarm(0, 0, 64));
        ASSERT(!boot_publish_block_swarm(64, 64, 64));
        ASSERT(boot_publish_block_swarm(65, 65, 64));
        ASSERT(boot_publish_block_swarm(3000000, 3000000, 64));
        ASSERT(boot_publish_block_swarm(3000000, 3001024, 64));
        ASSERT(!boot_publish_block_swarm(3000000, 3001025, 64));
        ASSERT(!boot_publish_block_swarm(3000000, 2999999, 64));
        ASSERT(!boot_publish_block_swarm(65, 65, 0));
        PASS();
    } _test_next:;
    return failures;
}

/* config/src/boot_snapshot_offer.c routes the offer-advertisement trust bit
 * through sync_trust_cap_allowed(sync_trust_derive(...), SYNC_CAP_SEED_BUNDLE)
 * instead of reading the raw self_derived predicate directly. By
 * construction SYNC_CAP_SEED_BUNDLE is granted iff self_derived holds
 * (ARTIFACT_VERIFIED and SOVEREIGN both carry it, no other trust state
 * does), so the centralized expression must equal the raw self_derived bit
 * for every (proven, refold, self_derived) combination — this is the
 * equivalence the routing change relies on. */
static int test_snapshot_offer_seed_cap_matches_self_derived(void)
{
    int failures = 0;
    TEST("offer seed-bundle cap equals raw self_derived for all combos") {
        for (int p = 0; p < 2; p++) {
            for (int r = 0; r < 2; r++) {
                for (int s = 0; s < 2; s++) {
                    bool proven = p != 0;
                    bool refold = r != 0;
                    bool self_derived = s != 0;
                    enum sync_trust_state st =
                        sync_trust_derive(proven, refold, self_derived);
                    bool seed_allowed =
                        sync_trust_cap_allowed(st, SYNC_CAP_SEED_BUNDLE);
                    ASSERT(seed_allowed == self_derived);
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static void build_truncated_snapshot_chunk(struct byte_stream *s)
{
    build_snapshot_chunk(s);
    if (s->size > 0)
        s->size--;
}

static void fill_v2_offer_params(struct snapshot_offer_params *params,
                                 int32_t height,
                                 int32_t our_height,
                                 uint32_t peer_id)
{
    memset(params, 0, sizeof(*params));
    params->height = height;
    params->our_height = our_height;
    params->num_utxos = 1234;
    params->total_bytes = 12345;
    params->peer_id = peer_id;
    params->protocol_version = FAST_SYNC_PROTOCOL_VERSION;
    params->snapshot_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;
    params->peer_tip_height = height + 10;
    memset(params->utxo_root, 0x11, 32);
    memset(params->mmr_root, 0x22, 32);
    memset(params->mmb_root, 0x33, 32);
    memset(params->block_hash, 0x44, 32);
    memset(params->chain_work, 0x55, 32);
}

static int64_t count_table_rows(sqlite3 *db, const char *table)
{
    sqlite3_stmt *st = NULL;
    char sql[128];
    int64_t count = -1;

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return count;
}

static bool snapshot_table_has_outpoint(sqlite3 *db, const char *table,
                                        const uint8_t txid[32], int vout)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    bool found = false;

    if (!db || !table || !txid)
        return false;
    int n = snprintf(sql, sizeof(sql),
                     "SELECT 1 FROM %s WHERE txid=? AND vout=? LIMIT 1",
                     table);
    if (n <= 0 || (size_t)n >= sizeof(sql) ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_int(st, 2, vout) == SQLITE_OK)
        found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static bool snapshot_meta_is(sqlite3 *db, const char *key, const char *want)
{
    char buf[24] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

static bool build_fc_chain(struct mmb *mmb,
                          struct mmb_leaf *leaves,
                          uint8_t (*leaf_hashes)[32],
                          uint32_t count,
                          uint32_t nbits)
{
    mmb_init(mmb);
    for (uint32_t i = 0; i < count; i++) {
        memset(&leaves[i], 0, sizeof(*leaves));
        memset(leaf_hashes[i], 0, 32);
        leaves[i].height = i;
        leaves[i].timestamp = 1000000 + i;
        leaves[i].nBits = nbits;
        memset(leaves[i].sapling_root, (uint8_t)(i + 1), 32);
        memset(leaves[i].chain_work, (uint8_t)(i + 2), 32);
        if (mmb_append(mmb, &leaves[i]) < 0)
            return false;
        mmb_hash_leaf(&leaves[i], leaf_hashes[i]);
    }
    return true;
}

static int test_snapshot_sync_service_followups(void)
{
    int failures = 0;

    TEST("snapshot sync service followup action tracks verification state") {
        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));

        svc.fc_verified = false;
        ASSERT(snapsync_offer_followup_action(&svc) ==
               SNAPSYNC_FOLLOWUP_SEND_FC_CHALLENGE);

        svc.fc_verified = true;
        ASSERT(snapsync_offer_followup_action(&svc) ==
               SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ);

        ASSERT(snapsync_verify_followup_action(false) ==
               SNAPSYNC_FOLLOWUP_NONE);
        ASSERT(snapsync_verify_followup_action(true) ==
               SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_handle_offer_requires_v2(void)
{
    int failures = 0;

    TEST("snapshot sync service rejects non-v2 snapshot offers") {
        struct snapshot_sync_service svc;
        struct snapshot_offer_params params;

        memset(&svc, 0, sizeof(svc));
        svc.state = SNAPSYNC_IDLE;
        svc.ndb = NULL;

        fill_v2_offer_params(&params, 10000, 10, 4);
        params.protocol_version = 0;

        ASSERT(snapsync_handle_offer(&svc, &params) ==
               SNAPSYNC_OFFER_REJECTED_STALE_SCHEMA);
        fill_v2_offer_params(&params, 10000, 10, 4);
        memset(params.chain_work, 0, sizeof(params.chain_work));
        ASSERT(snapsync_handle_offer(&svc, &params) ==
               SNAPSYNC_OFFER_REJECTED_WEAK_WORK);
        fill_v2_offer_params(&params, 10000, 10, 4);
        params.peer_tip_height = 10009;
        ASSERT(snapsync_handle_offer(&svc, &params) ==
               SNAPSYNC_OFFER_REJECTED_UNFINAL);
        ASSERT(svc.state == SNAPSYNC_IDLE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_verify_flyclient_begin_failure(void)
{
    int failures = 0;

    TEST("snapshot sync service keeps fc unverified when begin fails after FlyClient proof") {
        struct snapshot_sync_service svc;
        struct mmb m;
        struct mmb_leaf leaves[MMB_MAX_MOUNTAINS];
        uint8_t leaf_hashes[MMB_MAX_MOUNTAINS][32];
        uint8_t expected_root[32];
        struct fc_challenge challenge;
        struct fc_response resp;

        memset(&svc, 0, sizeof(svc));
        memset(&m, 0, sizeof(m));
        memset(&challenge, 0, sizeof(challenge));
        memset(&resp, 0, sizeof(resp));

        ASSERT(build_fc_chain(&m, leaves, leaf_hashes, 16, 0x1d00ffff));

        mmb_root(&m, expected_root);
        memset(&svc.fc_challenge, 0, sizeof(svc.fc_challenge));
        memset(challenge.seed, 0x33, sizeof(challenge.seed));
        challenge.chain_length = 16;
        memcpy(challenge.mmb_root, expected_root, 32);

        svc.state = SNAPSYNC_NEGOTIATING;
        svc.ndb = NULL;
        svc.fc_challenge = challenge;
        memset(svc.offered_chain_work, 0xFF, sizeof(svc.offered_chain_work));

        ASSERT(fc_build_response(&challenge, &m, leaves,
                                (const uint8_t (*)[32])leaf_hashes,
                                &resp));
        ASSERT(resp.num_samples > 0);
        ASSERT(!snapsync_verify_flyclient(&svc, &resp).ok);
        ASSERT(!svc.fc_verified);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING);
        PASS();
    } _test_next:;

    return failures;
}

struct offer_churn_ctx {
    struct snapshot_sync_service *svc;
    atomic_int accepted;
    int rounds;
    int peer_base;
};

static void *offer_churn_worker(void *arg)
{
    struct offer_churn_ctx *ctx = (struct offer_churn_ctx *)arg;
    struct snapshot_offer_params params;
    uint8_t mmr_root[32];
    uint8_t mmb_root[32];
    uint8_t utxo_root[32];
    uint8_t block_hash[32];

    memset(mmr_root, 1, sizeof(mmr_root));
    memset(mmb_root, 1, sizeof(mmb_root));
    memset(utxo_root, 0x11, sizeof(utxo_root));
    memset(block_hash, 0x22, sizeof(block_hash));

    for (int i = 0; i < ctx->rounds; i++) {
        fill_v2_offer_params(&params, 10000 + i, 1000,
                             (uint32_t)(ctx->peer_base + i));
        params.num_utxos = (uint64_t)(1000 + i);
        params.total_bytes = 65536;
        memcpy(params.utxo_root, utxo_root, 32);
        memcpy(params.mmr_root, mmr_root, 32);
        memcpy(params.mmb_root, mmb_root, 32);
        params.block_hash[0] = (uint8_t)i;

        if (snapsync_handle_offer(ctx->svc, &params) ==
            SNAPSYNC_OFFER_ACCEPTED) {
            atomic_fetch_add(&ctx->accepted, 1);
        }

        if ((i % 10) == 0)
            snapsync_reset(ctx->svc);
    }

    return NULL;
}

static int test_snapshot_sync_service_offer_churn(void)
{
    int failures = 0;
    /* enum, not `const int`: a const-qualified object is not a constant
     * expression in C, so `pthread_t tids[threads]` below would be a VLA. */
    enum { threads = 4 };
    const int rounds = 120;
    struct snapshot_sync_service svc;
    pthread_t tids[threads];
    struct offer_churn_ctx ctx[threads];

    memset(&svc, 0, sizeof(svc));
    snapsync_init(&svc, NULL);

    TEST("snapshot sync service handles concurrent offer churn safely") {
        atomic_init(&ctx[0].accepted, 0);
        for (int i = 0; i < threads; i++) {
            ctx[i].svc = &svc;
            ctx[i].rounds = rounds;
            ctx[i].peer_base = 3000 + i * 100;
            atomic_init(&ctx[i].accepted, 0);
            pthread_create(&tids[i], NULL, offer_churn_worker, &ctx[i]);
        }

        for (int i = 0; i < threads; i++) {
            pthread_join(tids[i], NULL);
        }

        int accepted_total = atomic_load(&ctx[0].accepted) +
                            atomic_load(&ctx[1].accepted) +
                            atomic_load(&ctx[2].accepted) +
                            atomic_load(&ctx[3].accepted);
        ASSERT(accepted_total > 0);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING ||
               svc.state == SNAPSYNC_IDLE);
        snapsync_reset(&svc);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_handle_offer_null_inputs(void)
{
    int failures = 0;

    TEST("snapshot sync service rejects null offer input") {
        struct snapshot_sync_service svc;

        memset(&svc, 0, sizeof(svc));
        ASSERT(snapsync_handle_offer(NULL, NULL) ==
               SNAPSYNC_OFFER_REJECTED_PARSE);
        ASSERT(snapsync_handle_offer(&svc, NULL) ==
               SNAPSYNC_OFFER_REJECTED_PARSE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_builds_pow(void)
{
    int failures = 0;

    TEST("snapshot sync service builds valid request pow from peer ip") {
        uint8_t ip[16] = {0};
        struct fast_sync_pow pow;

        ip[15] = 1;
        ASSERT(snapsync_build_request_pow(ip, &pow).ok);
        ASSERT(fast_sync_verify_pow(&pow));
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_stream_helpers(void)
{
    int failures = 0;

    TEST("snapshot sync service parses offers and writes request/challenge payloads") {
        struct snapshot_offer_params params;
        struct snapshot_sync_service svc;
        struct byte_stream offer;
        struct byte_stream request;
        struct byte_stream challenge;
        uint8_t ip[16] = {0};

        memset(&svc, 0, sizeof(svc));
        memset(&params, 0, sizeof(params));
        memset(svc.fc_challenge.seed, 0x11, sizeof(svc.fc_challenge.seed));
        memset(svc.fc_challenge.mmb_root, 0x22, sizeof(svc.fc_challenge.mmb_root));
        svc.fc_challenge.chain_length = 12345;
        ip[15] = 7;

        stream_init(&offer, 160);
        stream_write_i32_le(&offer, 99);
        for (int i = 0; i < 32; i++) stream_write_u8(&offer, (uint8_t)i);
        for (int i = 0; i < 32; i++) stream_write_u8(&offer, (uint8_t)(i + 1));
        for (int i = 0; i < 32; i++) stream_write_u8(&offer, (uint8_t)(i + 2));
        stream_write_u64_le(&offer, 1234);
        stream_write_u64_le(&offer, 5678);
        for (int i = 0; i < 32; i++) stream_write_u8(&offer, (uint8_t)(i + 3));
        stream_write_u32_le(&offer, FAST_SYNC_PROTOCOL_VERSION);
        stream_write_u32_le(&offer, FAST_SYNC_SNAPSHOT_SCHEMA_VERSION);
        stream_write_i32_le(&offer, 109);
        for (int i = 0; i < 32; i++) stream_write_u8(&offer, (uint8_t)(i + 4));

        ASSERT(snapsync_parse_offer_params(&params, &offer).ok);
        ASSERT(params.height == 99);
        ASSERT(params.num_utxos == 1234);
        ASSERT(params.total_bytes == 5678);
        ASSERT(params.block_hash[0] == 0);
        ASSERT(params.utxo_root[0] == 1);
        ASSERT(params.mmr_root[0] == 2);
        ASSERT(params.mmb_root[0] == 3);
        ASSERT(params.protocol_version == FAST_SYNC_PROTOCOL_VERSION);
        ASSERT(params.snapshot_schema_version == FAST_SYNC_SNAPSHOT_SCHEMA_VERSION);
        ASSERT(params.peer_tip_height == 109);
        ASSERT(params.chain_work[0] == 4);

        stream_init(&challenge, 72);
        ASSERT(snapsync_write_fc_challenge(&svc, &challenge).ok);
        ASSERT(challenge.size == 72);

        stream_init(&request, 52);
        ASSERT(snapsync_write_snapshot_request(&request, 88, ip).ok);
        ASSERT(request.size == 52);

        stream_free(&offer);
        stream_free(&challenge);
        stream_free(&request);
        PASS();
    } _test_next:;

    return failures;
}

static void write_valid_snapshot_manifest(struct byte_stream *offer,
                                             int32_t height,
                                             int32_t peer_tip_height)
{
    stream_write_i32_le(offer, height);
    for (int i = 0; i < 32; i++) stream_write_u8(offer, (uint8_t)i);
    for (int i = 0; i < 32; i++) stream_write_u8(offer, (uint8_t)(i + 1));
    for (int i = 0; i < 32; i++) stream_write_u8(offer, (uint8_t)(i + 2));
    stream_write_u64_le(offer, 1234);
    stream_write_u64_le(offer, 5678);
    for (int i = 0; i < 32; i++) stream_write_u8(offer, (uint8_t)(i + 3));
    stream_write_u32_le(offer, FAST_SYNC_PROTOCOL_VERSION);
    stream_write_u32_le(offer, FAST_SYNC_SNAPSHOT_SCHEMA_VERSION);
    stream_write_i32_le(offer, peer_tip_height);
    for (int i = 0; i < 32; i++) stream_write_u8(offer, (uint8_t)(i + 4));
}

static int test_snapshot_manifest_contract(void)
{
    int failures = 0;

    TEST("snapshot manifest v2 rejects malformed or incomplete contracts") {
        struct byte_stream offer;
        struct snapshot_manifest manifest;
        enum snapshot_manifest_result result;

        stream_init(&offer, 192);
        write_valid_snapshot_manifest(&offer, 10000, 10010);

        ASSERT(snapshot_manifest_parse(&manifest, &offer, &result).ok);
        ASSERT(result == SNAPSHOT_MANIFEST_OK);
        ASSERT(manifest.height == 10000);
        ASSERT(manifest.peer_tip_height == 10010);
        ASSERT(snapshot_manifest_validate_offer(&manifest, 0) ==
               SNAPSHOT_MANIFEST_OK);

        offer.read_pos = 0;
        stream_write_u8(&offer, 0xff);
        ASSERT(!snapshot_manifest_parse(&manifest, &offer, &result).ok);
        ASSERT(result == SNAPSHOT_MANIFEST_TRAILING_BYTES);
        stream_free(&offer);

        stream_init(&offer, 192);
        write_valid_snapshot_manifest(&offer, 10000, 10009);
        ASSERT(snapshot_manifest_parse(&manifest, &offer, &result).ok);
        ASSERT(snapshot_manifest_validate_offer(&manifest, 0) ==
               SNAPSHOT_MANIFEST_UNFINAL);

        manifest.peer_tip_height = manifest.height;
        ASSERT(snapshot_manifest_validate_offer(&manifest, 0) ==
               SNAPSHOT_MANIFEST_OK);

        manifest.peer_tip_height = manifest.height + 10;
        memset(manifest.chain_work, 0, sizeof(manifest.chain_work));
        ASSERT(snapshot_manifest_validate_offer(&manifest, 0) ==
               SNAPSHOT_MANIFEST_WEAK_WORK);
        stream_free(&offer);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_manifest_recovery_contract(void)
{
    int failures = 0;

    TEST("snapshot manifest recovery keeps verification gates but relaxes distance") {
        struct byte_stream offer;
        struct snapshot_manifest manifest;
        enum snapshot_manifest_result result;

        stream_init(&offer, 192);
        write_valid_snapshot_manifest(&offer, 10000, 10010);

        ASSERT(snapshot_manifest_parse(&manifest, &offer, &result).ok);
        ASSERT(result == SNAPSHOT_MANIFEST_OK);
        ASSERT(snapshot_manifest_validate_offer(&manifest, 9500) ==
               SNAPSHOT_MANIFEST_NOT_AHEAD);
        ASSERT(snapshot_manifest_validate_recovery(&manifest, 9999) ==
               SNAPSHOT_MANIFEST_OK);
        ASSERT(snapshot_manifest_validate_recovery(&manifest, 10001) ==
               SNAPSHOT_MANIFEST_NOT_AHEAD);

        memset(manifest.chain_work, 0, sizeof(manifest.chain_work));
        ASSERT(snapshot_manifest_validate_recovery(&manifest, 9999) ==
               SNAPSHOT_MANIFEST_WEAK_WORK);

        stream_free(&offer);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_fc_roundtrip(void)
{
    int failures = 0;

    TEST("snapshot sync service serializes and parses FlyClient responses") {
        struct fc_response resp;
        struct fc_response parsed;
        struct byte_stream s;

        memset(&resp, 0, sizeof(resp));
        resp.num_samples = 1;
        resp.samples[0].leaf.height = 42;
        resp.samples[0].leaf.timestamp = 123;
        resp.samples[0].leaf.nBits = 0x1d00ffffU;
        resp.samples[0].proof.leaf_index = 7;
        resp.samples[0].proof.num_siblings = 1;
        resp.samples[0].proof.num_peaks = 1;
        resp.samples[0].proof.mmb_size = 99;
        memset(resp.samples[0].leaf.block_hash, 0x41, 32);
        memset(resp.samples[0].leaf.sapling_root, 0x42, 32);
        memset(resp.samples[0].leaf.chain_work, 0x43, 32);
        memset(resp.samples[0].proof.leaf_hash, 0x44, 32);
        memset(resp.samples[0].proof.siblings[0], 0x45, 32);
        memset(resp.samples[0].proof.peaks[0], 0x46, 32);

        stream_init(&s, 512);
        ASSERT(snapsync_write_fc_response(&s, &resp).ok);
        s.read_pos = 0;
        ASSERT(snapsync_parse_fc_response(&parsed, &s).ok);
        ASSERT(parsed.num_samples == 1);
        ASSERT(parsed.samples[0].leaf.height == 42);
        ASSERT(parsed.samples[0].proof.leaf_index == 7);
        ASSERT(parsed.samples[0].proof.num_siblings == 1);
        ASSERT(parsed.samples[0].proof.num_peaks == 1);
        ASSERT(parsed.samples[0].proof.mmb_size == 99);
        ASSERT(parsed.samples[0].leaf.block_hash[0] == 0x41);
        ASSERT(parsed.samples[0].proof.siblings[0][0] == 0x45);
        stream_free(&s);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_contains_tip_activation(void)
{
    int failures = 0;

    TEST("snapshot sync contains verified snapshot tip activation") {
        struct snapshot_sync_service svc;
        struct main_state ms;
        struct block_index genesis, snap;
        struct uint256 h0 = {0}, h1 = {0};

        memset(&svc, 0, sizeof(svc));
        memset(&genesis, 0, sizeof(genesis));
        memset(&snap, 0, sizeof(snap));
        main_state_init(&ms);
        block_index_init(&genesis);
        block_index_init(&snap);

        h0.data[0] = 1;
        h1.data[0] = 2;
        genesis.phashBlock = &h0;
        genesis.nHeight = 0;
        snap.phashBlock = &h1;
        snap.nHeight = 1;
        snap.pprev = &genesis;

        block_map_insert(&ms.map_block_index, &h0, &genesis);
        block_map_insert(&ms.map_block_index, &h1, &snap);
        memcpy(svc.offered_block_hash, h1.data, 32);
        svc.offered_height = 1;
        svc.offered_peer_tip_height = 11;

        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        ASSERT(snapsync_activate_verified_tip(&svc, &ms) ==
               SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(active_chain_tip(&ms.chain_active) == NULL);
        ASSERT(ms.pindex_best_header == NULL);
        ASSERT(!blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        main_state_free(&ms);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_contains_fallback_tip(void)
{
    int failures = 0;

    TEST("snapshot sync containment creates no fallback anchor") {
        struct snapshot_sync_service svc;
        struct main_state ms;
        struct block_index genesis, indexed, unindexed, too_high;
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0}, h3 = {0}, missing = {0};

        memset(&svc, 0, sizeof(svc));
        memset(&genesis, 0, sizeof(genesis));
        memset(&indexed, 0, sizeof(indexed));
        memset(&unindexed, 0, sizeof(unindexed));
        memset(&too_high, 0, sizeof(too_high));
        main_state_init(&ms);
        block_index_init(&genesis);
        block_index_init(&indexed);
        block_index_init(&unindexed);
        block_index_init(&too_high);

        h0.data[0] = 1;
        h1.data[0] = 2;
        h2.data[0] = 3;
        h3.data[0] = 4;
        missing.data[0] = 9;

        genesis.phashBlock = &h0;
        genesis.nHeight = 0;
        genesis.nStatus = BLOCK_HAVE_DATA;
        genesis.nChainTx = 1;

        indexed.phashBlock = &h1;
        indexed.nHeight = 1000;
        indexed.nStatus = BLOCK_HAVE_DATA;
        indexed.nChainTx = 1;
        indexed.pprev = &genesis;

        unindexed.phashBlock = &h2;
        unindexed.nHeight = 1500;
        unindexed.nChainTx = 1;
        unindexed.pprev = &indexed;

        too_high.phashBlock = &h3;
        too_high.nHeight = 2500;
        too_high.nStatus = BLOCK_HAVE_DATA;
        too_high.nChainTx = 1;
        too_high.pprev = &indexed;

        block_map_insert(&ms.map_block_index, &h0, &genesis);
        block_map_insert(&ms.map_block_index, &h1, &indexed);
        block_map_insert(&ms.map_block_index, &h2, &unindexed);
        block_map_insert(&ms.map_block_index, &h3, &too_high);

        memcpy(svc.offered_block_hash, missing.data, 32);
        svc.offered_height = 2000;
        svc.offered_peer_tip_height = 2010;

        snapsync_set_anchor(NULL);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        ASSERT(snapsync_activate_verified_tip(&svc, &ms) ==
               SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(block_map_find(&ms.map_block_index, &missing) == NULL);
        ASSERT(snapsync_get_anchor() == NULL);
        ASSERT(active_chain_tip(&ms.chain_active) == NULL);
        ASSERT(ms.pindex_best_header == NULL);
        ASSERT(!blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        main_state_free(&ms);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_reset_clears_non_owned_anchor(void)
{
    int failures = 0;

    TEST("snapshot sync reset clears non-owned anchor slot") {
        struct snapshot_sync_service svc;
        struct block_index anchor;

        memset(&svc, 0, sizeof(svc));
        memset(&anchor, 0, sizeof(anchor));
        block_index_init(&anchor);
        anchor.nHeight = 12345;

        snapsync_set_anchor(&anchor);
        ASSERT(snapsync_get_anchor() == &anchor);

        snapsync_reset(&svc);
        ASSERT(snapsync_get_anchor() == NULL);
        ASSERT(anchor.nHeight == 12345);

        PASS();
    } _test_next:;

    snapsync_set_anchor(NULL);
    return failures;
}

static int test_snapshot_sync_service_prepare_serve_step(void)
{
    int failures = 0;

    TEST("snapshot sync service prepares serving chunk and end marker") {
        struct p2p_node node;
        struct snapsync_serve_step step;
        uint8_t buf[128];
        size_t pos = 0;

        memset(&node, 0, sizeof(node));
        memset(buf, 0, sizeof(buf));
        node.zsync_total = 2;

        buf[pos++] = 1;
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 0;
        pos += 32; /* txid */
        pos += 4;  /* vout */
        pos += 8;  /* value */
        pos += 4;  /* height */
        buf[pos++] = 0; /* is_coinbase */
        buf[pos++] = 1; /* script len */
        buf[pos++] = 0x51; /* script */

        ASSERT(snapsync_prepare_serve_step(&step, &node, buf, (int64_t)pos).ok);
        ASSERT(step.action == SNAPSYNC_SERVE_ACTION_SEND_CHUNK);
        ASSERT(step.entries == 1);
        ASSERT(step.chunk_offset == 0);
        ASSERT(step.chunk_len == pos);
        ASSERT(node.zsync_offset == 1);
        ASSERT(node.zsync_sent == 1);
        ASSERT(node.zsync_file_offset == (int64_t)pos);

        ASSERT(snapsync_prepare_serve_step(&step, &node, buf, (int64_t)pos).ok);
        ASSERT(step.action == SNAPSYNC_SERVE_ACTION_SEND_END);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_prepare_serve_step_bad_input(void)
{
    int failures = 0;

    TEST("snapshot sync serve step returns a non-ok result on bad input") {
        struct p2p_node node;
        struct snapsync_serve_step step;
        uint8_t buf[8];

        memset(&node, 0, sizeof(node));
        memset(buf, 0, sizeof(buf));

        /* NULL step / node / buf and non-positive size are all invalid args. */
        ASSERT(!snapsync_prepare_serve_step(NULL, &node, buf, 4).ok);
        ASSERT(!snapsync_prepare_serve_step(&step, &node, buf, 0).ok);

        /* entry count 0 is rejected (bad entry count). buf[0..3] == 0. */
        node.zsync_file_offset = 0;
        ASSERT(!snapsync_prepare_serve_step(&step, &node, buf,
                                            (int64_t)sizeof(buf)).ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_transition_results(void)
{
    int failures = 0;

    TEST("snapshot sync service exposes router transition results for accept and verify") {
        struct snapsync_offer_acceptance accepted;
        struct snapsync_end_result end_result;
        struct snapsync_serve_start serve_start;
        struct snapsync_offer_followup followup;
        struct snapsync_verify_result verify_result;
        struct snapsync_serve_complete serve_complete;
        struct snapshot_sync_service svc;

        memset(&accepted, 0, sizeof(accepted));
        memset(&end_result, 0, sizeof(end_result));
        memset(&serve_start, 0, sizeof(serve_start));
        memset(&followup, 0, sizeof(followup));
        memset(&verify_result, 0, sizeof(verify_result));
        memset(&serve_complete, 0, sizeof(serve_complete));
        memset(&svc, 0, sizeof(svc));

        snapsync_build_offer_acceptance(&accepted);
        ASSERT(accepted.should_begin_receive);
        ASSERT(accepted.should_store_offer_details);
        ASSERT(accepted.should_reset_offset);
        ASSERT(accepted.should_update_peer_state);
        ASSERT(accepted.peer_state == PEER_SNAPSHOT_RECEIVING);
        ASSERT(accepted.should_set_sync_state);
        ASSERT(accepted.sync_state == SYNC_SNAPSHOT_RECEIVE);

        snapsync_build_serve_start(&serve_start, 1234);
        ASSERT(serve_start.should_begin_serving);
        ASSERT(serve_start.should_reset_progress);
        ASSERT(serve_start.should_reset_cursor);
        ASSERT(serve_start.should_update_peer_state);
        ASSERT(serve_start.peer_state == PEER_SNAPSHOT_SERVING);
        ASSERT(serve_start.total_utxos == 1234);

        svc.fc_verified = false;
        snapsync_build_offer_followup(&followup, &svc);
        ASSERT(followup.should_send);
        ASSERT(followup.action == SNAPSYNC_FOLLOWUP_SEND_FC_CHALLENGE);

        svc.fc_verified = true;
        snapsync_build_offer_followup(&followup, &svc);
        ASSERT(followup.should_send);
        ASSERT(followup.action == SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ);

        snapsync_build_verify_result(&verify_result, true);
        ASSERT(verify_result.verified);
        ASSERT(verify_result.should_send);
        ASSERT(verify_result.action == SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ);

        snapsync_build_verify_result(&verify_result, false);
        ASSERT(!verify_result.verified);
        ASSERT(!verify_result.should_send);
        ASSERT(verify_result.action == SNAPSYNC_FOLLOWUP_NONE);

        snapsync_build_end_result(&end_result, true);
        ASSERT(end_result.verified);
        ASSERT(end_result.should_resume_header_sync);
        ASSERT(end_result.should_update_peer_state);
        ASSERT(end_result.peer_state == PEER_ACTIVE);
        ASSERT(end_result.should_activate_tip);
        ASSERT(end_result.should_set_sync_state);
        ASSERT(end_result.sync_state == SYNC_HEADERS_DOWNLOAD);

        snapsync_build_end_result(&end_result, false);
        ASSERT(!end_result.verified);
        ASSERT(!end_result.should_resume_header_sync);

        snapsync_build_serve_complete(&serve_complete);
        ASSERT(serve_complete.should_finish_serving);
        ASSERT(serve_complete.should_update_peer_state);
        ASSERT(serve_complete.peer_state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_db_service_runtime(void)
{
    int failures = 0;

    TEST("snapshot sync service uses runtime db service for begin/reset") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct node_db_status st;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));

        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;
        ASSERT(snapsync_begin_receive(&svc).ok);
        ASSERT(svc.state == SNAPSYNC_RECEIVING);
        ASSERT(svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(st.turbo_mode);
        ASSERT(st.tx_open);

        snapsync_reset(&svc);
        ASSERT(svc.state == SNAPSYNC_IDLE);
        ASSERT(!svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);

        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_runtime_accessor(void)
{
    int failures = 0;

    TEST("snapshot sync service uses runtime-owned instance when present") {
        struct snapshot_sync_service runtime_svc;
        struct app_runtime_context runtime = {0};

        memset(&runtime_svc, 0, sizeof(runtime_svc));
        runtime_svc.state = SNAPSYNC_RECEIVING;
        runtime.snapshot_sync = &runtime_svc;

        app_runtime_set_current(&runtime);
        ASSERT(app_runtime_snapshot_sync() == &runtime_svc);
        ASSERT(snapsync_is_active());
        app_runtime_set_current(NULL);
        if (snapsync_get_state() != SNAPSYNC_IDLE)
            ASSERT(snapsync_set_state(SNAPSYNC_IDLE, "test reset"));
        ASSERT(snapsync_set_state(SNAPSYNC_NEGOTIATING, "test active guard"));
        ASSERT(snapsync_is_active());
        ASSERT(snapsync_set_state(SNAPSYNC_IDLE, "test reset"));
        ASSERT(!snapsync_is_active());
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_db_service_chunk_contained(void)
{
    int failures = 0;

    TEST("snapshot sync verifies chunks but contains runtime activation") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct node_db_status st;
        struct byte_stream chunk;
        uint8_t root[32];
        uint8_t coins_best_block[32];
        uint8_t cec_snapshot_evidence[256];
        size_t best_block_len = 0;
        size_t cec_snapshot_evidence_len = 0;
        uint64_t count = 0;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        memset(root, 0, sizeof(root));
        memset(coins_best_block, 0, sizeof(coins_best_block));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));

        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.start_time_us = 1;
        svc.offered_count = 1;
        svc.fc_verified = true;
        svc.serving_peer_id = 9;
        svc.offered_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;
        memset(svc.offered_block_hash, 0x44, sizeof(svc.offered_block_hash));
        memset(svc.offered_mmb_root, 0x55, sizeof(svc.offered_mmb_root));
        memset(svc.offered_chain_work, 0x66, sizeof(svc.offered_chain_work));

        ASSERT(snapsync_begin_receive(&svc).ok);
        build_snapshot_chunk(&chunk);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 1);
        ASSERT(svc.received_utxos == 1);

        ASSERT(db_service_commit_write(&dbsvc));
        utxo_commitment_sha3_compute_table(ndb.db, "snapshot_staging_utxos",
                                           root, &count);
        ASSERT(count == 1);
        memcpy(svc.offered_utxo_root, root, sizeof(root));
        ASSERT(db_service_begin_write(&dbsvc));

        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        struct zcl_result finalized = snapsync_finalize(&svc);
        ASSERT(!finalized.ok);
        ASSERT(finalized.code == SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(strstr(finalized.message,
                      SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID) != NULL);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(!svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);
        ASSERT(!node_db_state_get(&ndb, "coins_best_block",
                                  coins_best_block,
                                  sizeof(coins_best_block),
                                  &best_block_len));
        /* wave 2: the write-only 'snapshot_pending_coins_best_*' key family
         * was deleted — finalize must no longer write it. */
        ASSERT(!node_db_state_get(&ndb, "snapshot_pending_coins_best_block",
                                  coins_best_block,
                                  sizeof(coins_best_block),
                                  &best_block_len));
        ASSERT(!node_db_state_get(&ndb, "cec.snapshot_evidence",
                                  cec_snapshot_evidence,
                                  sizeof(cec_snapshot_evidence),
                                  &cec_snapshot_evidence_len));
        ASSERT(count_table_rows(ndb.db, "utxos") == 0);
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        /* A failed discard must retain FAILED + blocker + staged data. */
        ASSERT(db_service_exec_write(
            &dbsvc,
            "CREATE TRIGGER snapsync_test_reject_discard "
            "BEFORE DELETE ON snapshot_staging_utxos "
            "BEGIN SELECT RAISE(ABORT, 'injected discard failure'); END"));
        snapsync_reset(&svc);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);

        /* The blocker must not poison serving health after a fully successful
         * deterministic fallback to normal P2P/full-history sync. */
        ASSERT(db_service_exec_write(
            &dbsvc, "DROP TRIGGER snapsync_test_reject_discard"));
        snapsync_reset(&svc);
        ASSERT(svc.state == SNAPSYNC_IDLE);
        ASSERT(!blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 0);

        stream_free(&chunk);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_containment_preserves_canonical_state(void)
{
    int failures = 0;

    TEST("snapshot containment preserves node db coins shielded state and tip") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct byte_stream chunk;
        uint8_t root[32];
        uint64_t count = 0;
        uint8_t active_txid[32] = {0xa1};
        uint8_t coin_txid[32] = {0xc1};
        uint8_t stale_nf[32] = {0x5a};
        bool old_nf_found = false;
        int64_t old_nf_height = -1;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));

        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.start_time_us = 1;
        svc.offered_count = 1;
        svc.fc_verified = true;
        svc.serving_peer_id = 15;
        svc.offered_height = 30;
        memset(svc.offered_block_hash, 0x44, sizeof(svc.offered_block_hash));

        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);
        ASSERT(node_db_exec(&ndb,
            "INSERT INTO utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES(X'A100000000000000000000000000000000000000000000000000000000000000',"
            "7,777,X'51',0,4,0)"));
        ASSERT(count_table_rows(ndb.db, "utxos") == 1);
        ASSERT(test_complete_genesis_shielded_replay(pdb));
        ASSERT(nullifier_kv_add(pdb, stale_nf, NULLIFIER_POOL_SAPLING, 1));
        ASSERT(coins_kv_ensure_schema(pdb));
        ASSERT(coins_kv_add(pdb, coin_txid, 9, 999, 5, false,
                            (const uint8_t *)"\x51", 1));
        int64_t coins_before = coins_kv_count(pdb);
        uint64_t tip_cursor_before =
            stage_cursor_persisted(pdb, "tip_finalize",
                                   "snapshot_containment_test");

        ASSERT(snapsync_begin_receive(&svc).ok);
        build_snapshot_chunk(&chunk);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 1);
        ASSERT(db_service_commit_write(&dbsvc));

        ASSERT(count_table_rows(ndb.db, "utxos") == 1);
        ASSERT(snapshot_table_has_outpoint(ndb.db, "utxos", active_txid, 7));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        utxo_commitment_sha3_compute_table(ndb.db, "snapshot_staging_utxos",
                                           root, &count);
        ASSERT(count == 1);
        memcpy(svc.offered_utxo_root, root, sizeof(root));
        ASSERT(db_service_begin_write(&dbsvc));

        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        struct zcl_result finalized = snapsync_finalize(&svc);
        ASSERT(!finalized.ok);
        ASSERT(finalized.code == SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(count_table_rows(ndb.db, "utxos") == 1);
        ASSERT(snapshot_table_has_outpoint(ndb.db, "utxos", active_txid, 7));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        int64_t sprout_cursor = -1, sapling_cursor = -1;
        bool sprout_found = false, sapling_found = false;
        ASSERT(anchor_kv_activation_cursor(
                   pdb, ANCHOR_POOL_SPROUT, &sprout_cursor, &sprout_found));
        ASSERT(anchor_kv_activation_cursor(
                   pdb, ANCHOR_POOL_SAPLING, &sapling_cursor, &sapling_found));
        ASSERT(sprout_found && sapling_found &&
               sprout_cursor == 0 && sapling_cursor == 0);
        ASSERT(snapshot_meta_is(pdb, "nullifier_kv.activation_cursor", "0"));
        ASSERT(nullifier_kv_get(pdb, stale_nf, NULLIFIER_POOL_SAPLING,
                                &old_nf_found, &old_nf_height));
        ASSERT(old_nf_found && old_nf_height == 1);
        ASSERT(coins_kv_count(pdb) == coins_before);
        int64_t coin_value = 0;
        size_t coin_script_len = 0;
        uint8_t coin_script[4] = {0};
        ASSERT(coins_kv_get(pdb, coin_txid, 9, &coin_value,
                            coin_script, sizeof(coin_script),
                            &coin_script_len));
        ASSERT(coin_value == 999 && coin_script_len == 1 &&
               coin_script[0] == 0x51);
        ASSERT(stage_cursor_persisted(pdb, "tip_finalize",
                                      "snapshot_containment_test") ==
               tip_cursor_before);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        stream_free(&chunk);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_boot_discards_staging(void)
{
    int failures = 0;

    TEST("snapshot sync boot cleanup discards incomplete staging rows") {
        struct node_db ndb;
        char dbpath[256];
        uint8_t phase[32] = {0};
        size_t phase_len = 0;

        mkdir("./test-tmp", 0755);
        snprintf(dbpath, sizeof(dbpath), "./test-tmp/snapsync_stage_%d.db",
                 (int)getpid());
        unlink(dbpath);

        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT(node_db_exec(&ndb,
            "INSERT INTO snapshot_staging_utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase)"
            " VALUES(X'4200000000000000000000000000000000000000000000000000000000000000',0,1,X'51',0,1,0)"));
        ASSERT(node_db_state_set(&ndb, "snapshot_staging_phase",
                                 "chunk_receive", strlen("chunk_receive")));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        node_db_close(&ndb);

        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 0);
        ASSERT(!node_db_state_get(&ndb, "snapshot_staging_phase",
                                  phase, sizeof(phase), &phase_len));
        node_db_close(&ndb);
        unlink(dbpath);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_finalize_mismatch(void)
{
    int failures = 0;

    TEST("snapshot sync service finalize SHA3 mismatch clears turbo and fails") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct node_db_status st;
        struct byte_stream chunk;
        uint8_t actual_root[32];
        uint8_t bad_root[32];
        uint64_t count = 0;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        memset(actual_root, 0, sizeof(actual_root));
        memset(bad_root, 0xAA, sizeof(bad_root));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));

        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.start_time_us = 1;
        svc.offered_count = 1;
        svc.fc_verified = true;
        svc.serving_peer_id = 12;
        memset(svc.offered_block_hash, 0x44, sizeof(svc.offered_block_hash));

        ASSERT(snapsync_begin_receive(&svc).ok);
        build_snapshot_chunk(&chunk);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 1);

        ASSERT(db_service_commit_write(&dbsvc));
        utxo_commitment_sha3_compute_table(ndb.db, "snapshot_staging_utxos",
                                           actual_root, &count);
        ASSERT(count == 1);
        memcpy(svc.offered_utxo_root, bad_root, sizeof(bad_root));
        memcpy(bad_root, actual_root, sizeof(bad_root));
        if (bad_root[0] == 0xFF) {
            bad_root[0] = 0xFE;
        } else {
            bad_root[0] ^= 0xFF;
        }
        memcpy(svc.offered_utxo_root, bad_root, sizeof(bad_root));

        ASSERT(!snapsync_finalize(&svc).ok);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(!svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);

        stream_free(&chunk);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_sync_service_chunk_apply_failure_fails_closed(void)
{
    int failures = 0;

    TEST("snapshot sync service fails closed on malformed chunk apply") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct node_db_status st;
        struct byte_stream chunk;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));

        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;
        svc.start_time_us = 1;
        svc.offered_count = 2;
        svc.serving_peer_id = 7;

        ASSERT(snapsync_begin_receive(&svc).ok);
        build_truncated_snapshot_chunk(&chunk);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) < 0);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(!svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);

        stream_free(&chunk);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_accept_offer_with_few_utxos(void)
{
    int failures = 0;

    TEST("snapshot accept_offer allows offer when UTXO count is low") {
        /* Simulates the bug: a partial block connect from genesis sets
         * coins_best_block but produces very few UTXOs (<100K).  The
         * old code rejected all offers because coins_best_block was
         * non-null.  The fix checks UTXO count instead. */
        struct snapshot_sync_service svc;
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        /* Set coins_best_block to a non-null value (simulating partial connect) */
        uint8_t fake_best[32];
        memset(fake_best, 0x11, 32);
        node_db_state_set(&ndb, "coins_best_block", fake_best, 32);

        /* UTXOs table exists but has 0 rows — should NOT block offer */
        uint8_t utxo_root[32], mmb_root[32], block_hash[32];
        memset(utxo_root, 0x22, 32);
        memset(mmb_root, 0x33, 32);
        memset(block_hash, 0x44, 32);

        bool accepted = snapsync_accept_offer(&svc, 3000000, 1350000,
                                               utxo_root, mmb_root,
                                               block_hash, 42).ok;
        ASSERT(accepted);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING);

        snapsync_reset(&svc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_accept_offer_with_real_utxos(void)
{
    int failures = 0;

    TEST("snapshot accept_offer rejects offer when UTXO count is high") {
        /* If we already have 100K+ UTXOs, we should NOT accept another
         * snapshot — we already have a real UTXO set. */
        struct snapshot_sync_service svc;
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        /* Insert >100K fake UTXOs to simulate a real import */
        node_db_exec(&ndb, "BEGIN");
        sqlite3_stmt *ins = NULL;
        sqlite3_prepare_v2(ndb.db,
            "INSERT INTO utxos (txid,vout,value,script,script_type,height) "
            "VALUES (?,0,100,X'00',0,1)", -1, &ins, NULL);
        for (int i = 0; i < 100001; i++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            memcpy(txid, &i, sizeof(i));
            sqlite3_reset(ins);
            sqlite3_bind_blob(ins, 1, txid, 32, SQLITE_STATIC);
            sqlite3_step(ins);
        }
        sqlite3_finalize(ins);
        node_db_exec(&ndb, "COMMIT");

        uint8_t utxo_root[32], mmb_root[32], block_hash[32];
        memset(utxo_root, 0x22, 32);
        memset(mmb_root, 0x33, 32);
        memset(block_hash, 0x44, 32);

        bool accepted = snapsync_accept_offer(&svc, 3000000, 1350000,
                                               utxo_root, mmb_root,
                                               block_hash, 42).ok;
        ASSERT(!accepted);
        ASSERT(svc.state == SNAPSYNC_IDLE);

        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_recovery_request_allows_populated_utxos(void)
{
    int failures = 0;

    TEST("snapshot recovery request accepts verified manifest over populated UTXOs") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct snapshot_offer_params params;

        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        node_db_exec(&ndb, "BEGIN");
        sqlite3_stmt *ins = NULL;
        sqlite3_prepare_v2(ndb.db,
            "INSERT INTO utxos (txid,vout,value,script,script_type,height) "
            "VALUES (?,0,100,X'00',0,1)", -1, &ins, NULL);
        for (int i = 0; i < 100001; i++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            memcpy(txid, &i, sizeof(i));
            sqlite3_reset(ins);
            sqlite3_bind_blob(ins, 1, txid, 32, SQLITE_STATIC);
            sqlite3_step(ins);
        }
        sqlite3_finalize(ins);
        node_db_exec(&ndb, "COMMIT");

        fill_v2_offer_params(&params, 3000000, 2999000, 0);
        params.num_utxos = 1350000;
        params.total_bytes = 200000000;
        params.peer_tip_height = params.height + 10;

        ASSERT(snapsync_handle_offer(&svc, &params) ==
               SNAPSYNC_OFFER_REJECTED_NOT_AHEAD);
        ASSERT(svc.state == SNAPSYNC_IDLE);

        ASSERT(snapsync_request_recovery(&svc, 2999500, &params).ok);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING);
        ASSERT(svc.offered_height == params.height);
        ASSERT(svc.offered_count == params.num_utxos);
        ASSERT(svc.offered_peer_tip_height == params.peer_tip_height);
        ASSERT(svc.fc_challenge.chain_length == (uint64_t)params.height + 1);
        ASSERT(!svc.fc_verified);

        snapsync_reset(&svc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_recovery_request_rejects_unverified_manifest(void)
{
    int failures = 0;

    TEST("snapshot recovery request rejects weak or too-low manifests") {
        struct snapshot_sync_service svc;
        struct snapshot_offer_params params;

        memset(&svc, 0, sizeof(svc));
        svc.state = SNAPSYNC_IDLE;

        fill_v2_offer_params(&params, 3000000, 2999000, 0);
        params.peer_tip_height = params.height + 10;

        ASSERT(!snapsync_request_recovery(&svc, 3000001, &params).ok);
        ASSERT(svc.state == SNAPSYNC_IDLE);

        memset(params.chain_work, 0, sizeof(params.chain_work));
        ASSERT(!snapsync_request_recovery(&svc, 2999500, &params).ok);
        ASSERT(svc.state == SNAPSYNC_IDLE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_recovery_requires_flyclient_and_sha3(void)
{
    int failures = 0;

    TEST("snapshot recovery request still gates promotion on FlyClient and SHA3") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct snapshot_offer_params params;
        struct byte_stream chunk;
        uint8_t staged_root[32];
        uint64_t staged_count = 0;

        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        ASSERT(node_db_exec(&ndb,
            "INSERT INTO utxos "
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES (X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',"
            "0,100,X'51',0,1,0)"));

        fill_v2_offer_params(&params, 3000000, 2999000, 0);
        params.num_utxos = 1;
        params.total_bytes = 128;
        params.peer_tip_height = params.height + 10;

        ASSERT(snapsync_request_recovery(&svc, 2999500, &params).ok);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING);
        ASSERT(!svc.fc_verified);

        build_snapshot_chunk(&chunk);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 0);
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 0);
        ASSERT(!snapsync_handle_end(&svc, params.peer_id).ok);
        ASSERT(svc.state == SNAPSYNC_NEGOTIATING);

        ASSERT(snapsync_begin_receive(&svc).ok);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 1);
        ASSERT(!snapsync_handle_end(&svc, params.peer_id).ok);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(count_table_rows(ndb.db, "utxos") == 1);
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 0);

        snapsync_reset(&svc);
        ASSERT(snapsync_request_recovery(&svc, 2999500, &params).ok);
        ASSERT(snapsync_begin_receive(&svc).ok);
        ASSERT(snapsync_apply_chunk(&svc, chunk.data, chunk.size) == 1);
        ASSERT(node_db_commit(&ndb));
        utxo_commitment_sha3_compute_table(ndb.db, "snapshot_staging_utxos",
                                           staged_root, &staged_count);
        ASSERT(staged_count == 1);
        memcpy(svc.offered_utxo_root, staged_root, sizeof(staged_root));
        ASSERT(node_db_begin(&ndb));
        svc.fc_verified = true;
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        struct zcl_result contained =
            snapsync_handle_end(&svc, params.peer_id);
        ASSERT(!contained.ok);
        ASSERT(contained.code == SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(count_table_rows(ndb.db, "utxos") == 1);
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        stream_free(&chunk);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static void persist_test_roots(struct node_db *ndb,
                               const uint8_t block_hash[32],
                               const uint8_t chain_work[32])
{
    struct mmr mmr;
    struct mmb mmb;
    struct mmb_leaf leaf;
    uint8_t buf[MMB_SERIALIZED_MAX];
    size_t len;

    mmr_init(&mmr);
    mmr_append(&mmr, block_hash);
    len = mmr_serialize(&mmr, buf, sizeof(buf));
    node_db_state_set(ndb, "mmr_state", buf, len);

    mmb_init(&mmb);
    mmb_leaf_from_block(&leaf, block_hash, 1, 1234567890, 0x1d00ffff,
                        block_hash, chain_work, NULL);
    mmb_append(&mmb, &leaf);
    len = mmb_serialize(&mmb, buf, sizeof(buf));
    node_db_state_set(ndb, "mmb_state", buf, len);
}

static int test_snapshot_local_recovery_manifest_builder(void)
{
    int failures = 0;

    TEST("snapshot local recovery manifest binds runtime db roots") {
        struct node_db ndb;
        struct snapshot_offer_params params;
        struct snapshot_manifest manifest;
        uint8_t block_hash[32];
        uint8_t prev_hash[32];
        uint8_t merkle_root[32];
        uint8_t nonce[32];
        uint8_t solution[1] = {0};
        uint8_t chain_work[32];
        uint8_t expected_root[32];
        uint64_t expected_count = 0;

        memset(block_hash, 0x41, sizeof(block_hash));
        memset(prev_hash, 0x40, sizeof(prev_hash));
        memset(merkle_root, 0x42, sizeof(merkle_root));
        memset(nonce, 0x43, sizeof(nonce));
        memset(chain_work, 0x55, sizeof(chain_work));

        ASSERT(node_db_open(&ndb, ":memory:"));
        ASSERT(node_db_state_set_int(&ndb, "tip_height", 1));
        ASSERT(node_db_state_set(&ndb, "tip_hash", block_hash, 32));

        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "INSERT INTO blocks "
            "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
            "solution,chain_work,status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,3)",
            -1, &st, NULL) == SQLITE_OK);
        sqlite3_bind_blob(st, 1, block_hash, 32, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, 1);
        sqlite3_bind_blob(st, 3, prev_hash, 32, SQLITE_STATIC);
        sqlite3_bind_int(st, 4, 4);
        sqlite3_bind_blob(st, 5, merkle_root, 32, SQLITE_STATIC);
        sqlite3_bind_int(st, 6, 1234567890);
        sqlite3_bind_int(st, 7, 0x1d00ffff);
        sqlite3_bind_blob(st, 8, nonce, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 9, solution, sizeof(solution), SQLITE_STATIC);
        sqlite3_bind_blob(st, 10, chain_work, 32, SQLITE_STATIC);
        ASSERT(sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);

        ASSERT(node_db_exec(&ndb,
            "INSERT INTO utxos "
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES (X'0102030405060708090A0B0C0D0E0F101112131415161718"
            "191A1B1C1D1E1F20',0,5000,X'51',0,1,0)"));

        ASSERT(!snapsync_build_local_recovery_manifest(&ndb, &params, 0).ok);
        persist_test_roots(&ndb, block_hash, chain_work);
        ASSERT(snapsync_build_local_recovery_manifest(&ndb, &params, 0).ok);

        utxo_commitment_sha3_compute(ndb.db, expected_root, &expected_count);
        ASSERT(params.height == 1);
        ASSERT(params.peer_tip_height == 1);
        ASSERT(params.num_utxos == expected_count);
        ASSERT(memcmp(params.utxo_root, expected_root, 32) == 0);
        ASSERT(memcmp(params.block_hash, block_hash, 32) == 0);
        ASSERT(memcmp(params.chain_work, chain_work, 32) == 0);

        memset(&manifest, 0, sizeof(manifest));
        manifest.height = params.height;
        memcpy(manifest.block_hash, params.block_hash, 32);
        memcpy(manifest.utxo_root, params.utxo_root, 32);
        memcpy(manifest.mmr_root, params.mmr_root, 32);
        memcpy(manifest.mmb_root, params.mmb_root, 32);
        memcpy(manifest.chain_work, params.chain_work, 32);
        manifest.num_utxos = params.num_utxos;
        manifest.total_bytes = params.total_bytes;
        manifest.protocol_version = params.protocol_version;
        manifest.snapshot_schema_version = params.snapshot_schema_version;
        manifest.peer_tip_height = params.peer_tip_height;
        ASSERT(snapshot_manifest_validate_recovery(&manifest, 1) ==
               SNAPSHOT_MANIFEST_OK);

        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

/* Stage one UTXO chunk, commit it, and return the locally-computed SHA3
 * commitment over the staging table — the same procedure that derives the
 * in-binary checkpoint root, scaled to one coin. Leaves a write txn open so
 * the caller can immediately finalize. */
static bool stage_one_and_hash(struct snapshot_sync_service *svc,
                               struct node_db *ndb,
                               struct db_service *dbsvc,
                               struct byte_stream *chunk,
                               uint8_t local_root[32],
                               uint64_t *local_count)
{
    snapsync_init(svc, ndb);
    svc->state = SNAPSYNC_NEGOTIATING;
    svc->start_time_us = 1;
    svc->offered_count = 1;
    svc->fc_verified = true;
    svc->serving_peer_id = 21;
    memset(svc->offered_block_hash, 0x44, sizeof(svc->offered_block_hash));

    if (!snapsync_begin_receive(svc).ok)
        return false;
    build_snapshot_chunk(chunk);
    if (snapsync_apply_chunk(svc, chunk->data, chunk->size) != 1)
        return false;
    if (!db_service_commit_write(dbsvc))
        return false;
    utxo_commitment_sha3_compute_table(ndb->db, "snapshot_staging_utxos",
                                       local_root, local_count);
    if (*local_count != 1)
        return false;
    return db_service_begin_write(dbsvc);
}

/* POSITIVE verification, contained activation.
 * At the anchor height, a genuine set whose locally-computed commitment IS the
 * compiled checkpoint root must pass validation and reach the containment gate.
 * We install a test checkpoint
 * whose sha3_hash equals the local_root of the staged set — i.e. the genuine
 * anchor set by construction — and prove it is retained but not promoted. */
static int test_snapshot_anchor_bind_validates_then_contains_genuine_root(void)
{
    int failures = 0;

    TEST("snapshot anchor bind validates genuine root then contains activation") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct byte_stream chunk;
        struct sha3_utxo_checkpoint test_cp;
        uint8_t local_root[32];
        uint64_t local_count = 0;
        const int32_t anchor_h = 3056758;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        ASSERT(stage_one_and_hash(&svc, &ndb, &dbsvc, &chunk,
                                  local_root, &local_count));

        /* The genuine anchor set hashes to the compiled root by construction:
         * install a checkpoint at the anchor height whose root == local_root. */
        memset(&test_cp, 0, sizeof(test_cp));
        test_cp.height = anchor_h;
        memcpy(test_cp.sha3_hash, local_root, 32);
        test_cp.utxo_count = local_count;
        checkpoints_set_sha3_override_for_test(&test_cp);

        /* Offer is at the anchor height; offered root is self-consistent. */
        svc.offered_height = anchor_h;
        memcpy(svc.offered_utxo_root, local_root, sizeof(local_root));

        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        struct zcl_result contained = snapsync_finalize(&svc);
        ASSERT(!contained.ok);
        ASSERT(contained.code == SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(count_table_rows(ndb.db, "utxos") == 0);
        ASSERT(count_table_rows(ndb.db, "snapshot_staging_utxos") == 1);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));

        checkpoints_reset_sha3_override_for_test();
        stream_free(&chunk);
        blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

/* NEGATIVE — no false-accept.
 * At the anchor height, a FABRICATED set (local_root != compiled checkpoint
 * root) must be REJECTED — even though it is self-consistent with the peer's
 * offered root, which the OLD bare memcmp gate would have ACCEPTED. We prove
 * both: (a) offered_utxo_root == local_root, so the legacy self-consistency
 * check passes; (b) the compiled checkpoint root differs, so the anchor bind
 * fires and the snapshot is rejected. */
static int test_snapshot_anchor_bind_rejects_fabricated_root(void)
{
    int failures = 0;

    TEST("snapshot anchor bind rejects a fabricated set the old memcmp accepted") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct node_db_status st;
        struct byte_stream chunk;
        struct sha3_utxo_checkpoint test_cp;
        uint8_t local_root[32];
        uint8_t compiled_root[32];
        uint64_t local_count = 0;
        const int32_t anchor_h = 3056758;

        memset(&svc, 0, sizeof(svc));
        memset(&runtime, 0, sizeof(runtime));
        ASSERT(node_db_open(&ndb, ":memory:"));
        db_service_init(&dbsvc);
        ASSERT(db_service_attach(&dbsvc, &ndb));
        ASSERT(db_service_start(&dbsvc));
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        ASSERT(stage_one_and_hash(&svc, &ndb, &dbsvc, &chunk,
                                  local_root, &local_count));

        /* The compiled checkpoint root differs from the staged set's root: this
         * staged set is fabricated relative to the genuine anchor. */
        memcpy(compiled_root, local_root, sizeof(compiled_root));
        compiled_root[0] ^= 0xFF;
        ASSERT(memcmp(compiled_root, local_root, 32) != 0);

        memset(&test_cp, 0, sizeof(test_cp));
        test_cp.height = anchor_h;
        memcpy(test_cp.sha3_hash, compiled_root, 32);
        test_cp.utxo_count = local_count;
        checkpoints_set_sha3_override_for_test(&test_cp);

        /* Offered root == local_root: the LEGACY self-consistency memcmp passes,
         * so the old gate alone would have ACCEPTED this set. */
        svc.offered_height = anchor_h;
        memcpy(svc.offered_utxo_root, local_root, sizeof(local_root));
        ASSERT(memcmp(svc.offered_utxo_root, local_root, 32) == 0);

        /* Anchor bind fires: local_root != compiled checkpoint root -> REJECT. */
        ASSERT(!snapsync_finalize(&svc).ok);
        ASSERT(svc.state == SNAPSYNC_FAILED);
        ASSERT(!svc.turbo_active);
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);
        /* Staged set was NOT promoted to active. */
        ASSERT(count_table_rows(ndb.db, "utxos") == 0);

        checkpoints_reset_sha3_override_for_test();
        stream_free(&chunk);
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
        node_db_close(&ndb);
        PASS();
    } _test_next:;

    return failures;
}

static int test_snapshot_blacklist_add_query(void)
{
    int failures = 0;
    TEST("snapshot blacklist_peer adds and queries correctly") {
        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.state = SNAPSYNC_IDLE;

        ASSERT(!snapsync_is_peer_blacklisted(&svc, 42));
        snapsync_blacklist_peer(&svc, 42);
        ASSERT(snapsync_is_peer_blacklisted(&svc, 42));
        ASSERT(!snapsync_is_peer_blacklisted(&svc, 99));
        ASSERT(svc.blacklist_count == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_blacklist_zero_peer(void)
{
    int failures = 0;
    TEST("snapshot blacklist rejects zero peer_id") {
        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));

        snapsync_blacklist_peer(&svc, 0);
        ASSERT(svc.blacklist_count == 0);
        ASSERT(!snapsync_is_peer_blacklisted(&svc, 0));
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_blacklist_refresh(void)
{
    int failures = 0;
    TEST("snapshot blacklist refreshes timestamp on re-add") {
        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));

        snapsync_blacklist_peer(&svc, 42);
        ASSERT(svc.blacklist_count == 1);
        int64_t first_ts = svc.blacklist[0].blacklisted_at_us;

        snapsync_blacklist_peer(&svc, 42);
        ASSERT(svc.blacklist_count == 1);
        ASSERT(svc.blacklist[0].blacklisted_at_us >= first_ts);
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_blacklist_multiple(void)
{
    int failures = 0;
    TEST("snapshot blacklist multiple peers") {
        struct snapshot_sync_service svc;
        memset(&svc, 0, sizeof(svc));

        snapsync_blacklist_peer(&svc, 10);
        snapsync_blacklist_peer(&svc, 20);
        snapsync_blacklist_peer(&svc, 30);
        ASSERT(svc.blacklist_count == 3);
        ASSERT(snapsync_is_peer_blacklisted(&svc, 10));
        ASSERT(snapsync_is_peer_blacklisted(&svc, 20));
        ASSERT(snapsync_is_peer_blacklisted(&svc, 30));
        ASSERT(!snapsync_is_peer_blacklisted(&svc, 40));
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_blacklist_rejects_offer(void)
{
    int failures = 0;
    TEST("snapshot handle_offer rejects blacklisted peer") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        snapsync_blacklist_peer(&svc, 5);

        struct snapshot_offer_params params;
        fill_v2_offer_params(&params, 3000000, 0, 5);
        params.num_utxos = 1350000;
        params.total_bytes = 200000000;

        enum snapsync_offer_result result = snapsync_handle_offer(&svc, &params);
        ASSERT(result == SNAPSYNC_OFFER_REJECTED_BLACKLISTED);

        params.peer_id = 7;
        result = snapsync_handle_offer(&svc, &params);
        ASSERT(result == SNAPSYNC_OFFER_ACCEPTED);

        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

static int test_snapshot_blacklist_survives_reset(void)
{
    int failures = 0;
    TEST("snapshot reset preserves blacklist") {
        struct snapshot_sync_service svc;
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, ":memory:"));
        snapsync_init(&svc, &ndb);

        snapsync_blacklist_peer(&svc, 42);
        ASSERT(svc.blacklist_count == 1);

        snapsync_reset(&svc);
        ASSERT(svc.state == SNAPSYNC_IDLE);
        ASSERT(svc.blacklist_count == 1);
        ASSERT(snapsync_is_peer_blacklisted(&svc, 42));

        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

int test_snapshot_sync_service(void)
{
    int failures = 0;
    char progress_dir[256];
    test_make_tmpdir(progress_dir, sizeof(progress_dir),
                     "snapshot_sync_service", "progress");
    progress_store_close();
    if (!progress_store_open(progress_dir)) {
        fprintf(stderr, "snapshot_sync_service: progress store open failed\n");
        test_cleanup_tmpdir(progress_dir);
        return 1;
    }
    failures += test_snapshot_sync_service_followups();
    failures += test_snapshot_offer_trust_policy();
    failures += test_boot_publish_block_swarm();
    failures += test_snapshot_offer_seed_cap_matches_self_derived();
    failures += test_snapshot_sync_service_builds_pow();
    failures += test_snapshot_sync_service_stream_helpers();
    failures += test_snapshot_manifest_contract();
    failures += test_snapshot_manifest_recovery_contract();
    failures += test_snapshot_sync_service_fc_roundtrip();
    failures += test_snapshot_sync_service_contains_tip_activation();
    failures += test_snapshot_sync_service_contains_fallback_tip();
    failures += test_snapshot_reset_clears_non_owned_anchor();
    failures += test_snapshot_sync_service_prepare_serve_step();
    failures += test_snapshot_sync_service_prepare_serve_step_bad_input();
    failures += test_snapshot_sync_service_transition_results();
    failures += test_snapshot_sync_service_handle_offer_requires_v2();
    failures += test_snapshot_sync_service_handle_offer_null_inputs();
    failures += test_snapshot_sync_service_verify_flyclient_begin_failure();
    failures += test_snapshot_sync_service_offer_churn();
    failures += test_snapshot_sync_service_db_service_runtime();
    failures += test_snapshot_sync_service_runtime_accessor();
    failures += test_snapshot_sync_service_db_service_chunk_contained();
    failures += test_snapshot_sync_service_containment_preserves_canonical_state();
    failures += test_snapshot_sync_service_boot_discards_staging();
    failures += test_snapshot_sync_service_finalize_mismatch();
    failures += test_snapshot_sync_service_chunk_apply_failure_fails_closed();
    failures += test_snapshot_accept_offer_with_few_utxos();
    failures += test_snapshot_accept_offer_with_real_utxos();
    failures += test_snapshot_recovery_request_allows_populated_utxos();
    failures += test_snapshot_recovery_request_rejects_unverified_manifest();
    failures += test_snapshot_recovery_requires_flyclient_and_sha3();
    failures += test_snapshot_local_recovery_manifest_builder();
    failures += test_snapshot_anchor_bind_validates_then_contains_genuine_root();
    failures += test_snapshot_anchor_bind_rejects_fabricated_root();
    failures += test_snapshot_blacklist_add_query();
    failures += test_snapshot_blacklist_zero_peer();
    failures += test_snapshot_blacklist_refresh();
    failures += test_snapshot_blacklist_multiple();
    failures += test_snapshot_blacklist_rejects_offer();
    failures += test_snapshot_blacklist_survives_reset();
    progress_store_close();
    test_cleanup_tmpdir(progress_dir);
    return failures;
}
