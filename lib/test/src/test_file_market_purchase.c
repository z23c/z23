/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable buyer plan/commit, idempotency, and fail-closed restart tests. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/market_download.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "net/file_market.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "sapling/fr.h"
#include "sapling/sapling.h"
#include "script/sighashtype.h"
#include "sim/simnet.h"
#include "sim/simnet_sapling.h"
#include "services/file_market_purchase_service.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"
#include "validation/sighash.h"
#include "wallet/wallet_lock.h"
#include "wallet/sapling_keys.h"

#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PURCHASE_CHECK(label, condition) do {                       \
    printf("file_market purchase: %s... ", (label));                \
    if (condition) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

struct purchase_fixture {
    struct node_db *ndb;
    struct wallet_identity_row identity;
    uint8_t initial_root[32];
    uint8_t reserved_root[32];
    int32_t tip_height;
    uint8_t tip_hash[32];
    int money_reads;
    int sends;
    int notifications;
    int fetches;
    int onion_fetches;
    int64_t onion_deadline_ms;
    int64_t deadline_wall_unix;
    _Atomic int deadline_clock_reads;
    bool money_current;
    bool source_owned;
    bool fetch_ready;
    int64_t expected_amount;
    uint8_t expected_memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
    struct simnet sim;
    bool sim_ready;
    struct uint256 funding_txid;
    int payment_height;
    bool chain_confirmed;
    size_t sapling_tree_size;
};

static const uint8_t k_purchase_content[] =
    "verified paid market content\n";

static int64_t purchase_deadline_monotonic_us(void *opaque)
{
    struct purchase_fixture *fixture = opaque;
    int read = atomic_fetch_add_explicit(&fixture->deadline_clock_reads, 1,
                                         memory_order_relaxed);
    return read < 4 ? 1000000 : 242000000;
}

static int64_t purchase_deadline_wall_unix(void *opaque)
{
    struct purchase_fixture *fixture = opaque;
    return fixture->deadline_wall_unix;
}

static void purchase_zero_chunk_sha3(uint8_t out[32])
{
    uint8_t zeros[4096] = {0};
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    for (size_t done = 0; done < FILE_MARKET_CHUNK_SIZE;
         done += sizeof(zeros))
        sha3_256_write(&sha, zeros, sizeof(zeros));
    sha3_256_finalize(&sha, out);
}

static struct zcl_result purchase_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct purchase_fixture *f = opaque;
    if (!f || !out || strcmp(scope, "dev") != 0)
        return ZCL_ERR(-1, "fixture scope mismatch");
    memset(out, 0, sizeof(*out));
    out->identity = f->identity;
    snprintf(out->wallet_scope, sizeof(out->wallet_scope), "dev");
    snprintf(out->status, sizeof(out->status), "%s",
             f->money_current ? "CURRENT" : "UNKNOWN");
    snprintf(out->reason, sizeof(out->reason), "%s",
             f->money_current ? "fixture current" : "fixture reader unavailable");
    out->complete = f->money_current;
    out->confirmed_zat = 30000000;
    out->agent_available_zat = 5000000;
    out->intent_reserved_zat = vault_intent_reserved_total(
        f->ndb, "dev", f->identity.wallet_instance_id);
    out->tip_height = f->tip_height;
    memcpy(out->tip_hash, f->tip_hash, 32);
    memcpy(out->snapshot_root,
           f->money_reads++ == 0 ? f->initial_root : f->reserved_root, 32);
    return ZCL_OK;
}

static struct zcl_result purchase_source(void *opaque, const char *source)
{
    struct purchase_fixture *f = opaque;
    return f && f->source_owned && source &&
               strcmp(source, "fixture-owned-source") == 0
        ? ZCL_OK : ZCL_ERR(-1, "source is not owned");
}

static bool purchase_binding_sig(const uint8_t output_rcv[32],
                                 const uint8_t sighash[32],
                                 uint8_t signature[64])
{
    struct fs rcv, neg, bsk;
    fs_zero(&bsk);
    if (!fs_from_bytes(&rcv, output_rcv))
        return false;
    fs_neg(&neg, &rcv);
    fs_add(&bsk, &bsk, &neg);
    uint8_t bsk_bytes[32];
    fs_to_bytes(bsk_bytes, &bsk);
    bool ok = sapling_create_binding_sig(bsk_bytes, sighash, signature);
    memory_cleanse(bsk_bytes, sizeof(bsk_bytes));
    memory_cleanse(&bsk, sizeof(bsk));
    return ok;
}

static struct zcl_result purchase_send(
    void *opaque, const char *source, const char *seller, int64_t amount,
    const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES], uint8_t txid[32])
{
    struct purchase_fixture *f = opaque;
    if (!f || strcmp(source, "fixture-owned-source") != 0 ||
        !seller || seller[0] == '\0' || amount != f->expected_amount ||
        memcmp(memo, f->expected_memo, FILE_MARKET_PAYMENT_MEMO_BYTES) != 0)
        return ZCL_ERR(-2, "exact send contract changed");
    uint8_t d[11], pk_d[32];
    if (!f->sim_ready || !sapling_decode_payment_address(seller, d, pk_d))
        return ZCL_ERR(-3, "isolated seller address cannot be decoded");

    struct transaction tx;
    transaction_init(&tx);
    tx.overwintered = true;
    tx.version = SAPLING_TX_VERSION;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    if (!transaction_alloc(&tx, 1, 0))
        return ZCL_ERR(-4, "isolated payment input allocation failed");
    tx.vin[0].prevout.hash = f->funding_txid;
    tx.vin[0].prevout.n = 0;
    tx.vin[0].sequence = UINT32_MAX;
    {
        static const uint8_t placeholder_sig[] = {0x00, 0x00};
        script_set(&tx.vin[0].script_sig, placeholder_sig,
                   sizeof(placeholder_sig));
    }
    tx.value_balance = -amount;
    tx.v_shielded_output = zcl_calloc(
        1, sizeof(struct output_description), "market purchase output");
    if (!tx.v_shielded_output) {
        transaction_free(&tx);
        return ZCL_ERR(-5, "isolated payment output allocation failed");
    }
    tx.num_shielded_output = 1;
    struct output_description *od = tx.v_shielded_output;
    uint8_t ovk[32], output_rcv[32];
    memset(ovk, 0x6d, sizeof(ovk));
    bool built = sapling_build_output_description(
        ovk, d, pk_d, (uint64_t)amount, memo, od->cv.data, od->cm.data,
        od->ephemeral_key.data, od->enc_ciphertext, od->out_ciphertext,
        od->zkproof, output_rcv);
    if (built) {
        uint32_t branch = consensus_current_epoch_branch_id(
            simnet_tip_height(&f->sim) + 1, &f->sim.params.consensus);
        struct precomputed_tx_data txdata;
        precompute_tx_data(&tx, &txdata);
        struct script empty;
        script_init(&empty);
        struct sighash_type hash_type = {.raw = SIGHASH_ALL};
        struct uint256 sighash;
        built = signature_hash(&empty, &tx, NOT_AN_INPUT, hash_type, 0,
                               branch, &txdata, &sighash) &&
                purchase_binding_sig(output_rcv, sighash.data,
                                     tx.binding_sig);
    }
    if (!built) {
        transaction_free(&tx);
        return ZCL_ERR(-6, "isolated market payment could not be built");
    }
    transaction_compute_hash(&tx);
    struct uint256 payment_txid = tx.hash;
    struct output_description *shielded_owned = tx.v_shielded_output;
    bool mined = simnet_mint_txs(&f->sim, &tx, 1);
    free(shielded_owned);
    if (!mined)
        return ZCL_ERR(-7, "isolated market payment was not mined");

    memcpy(txid, payment_txid.data, 32);
    f->sends++;
    f->payment_height = simnet_tip_height(&f->sim);
    f->chain_confirmed =
        simnet_sapling_tree_size(&f->sim) == f->sapling_tree_size + 1 &&
        !simnet_coin_value(&f->sim, &f->funding_txid, 0, NULL);
    if (f->chain_confirmed)
        f->sapling_tree_size = simnet_sapling_tree_size(&f->sim);
    return f->chain_confirmed
        ? ZCL_OK : ZCL_ERR(-8, "isolated payment chain state is incomplete");
}

static bool purchase_notify(void *opaque, const struct file_payment *payment)
{
    struct purchase_fixture *f = opaque;
    if (!f || !payment || payment->amount_zat != f->expected_amount ||
        file_payment_auth_verify(payment, payment->network_genesis) !=
            FILE_PAYMENT_AUTH_OK)
        return false;
    f->notifications++;
    return true;
}

static enum file_market_delivery_status purchase_fetch(
    void *opaque, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out)
{
    struct purchase_fixture *f = opaque;
    uint8_t derived[32], secret[32];
    if (!f || !peer_ip || peer_ip[15] != 1 || peer_port != 18034 ||
        !network_genesis || !offer_id || chunk_index > 1 ||
        !buyer_pubkey || !buyer_seed || !out)
        return FILE_MARKET_DELIVERY_MALFORMED;
    ed25519_keypair(derived, secret, buyer_seed);
    if (memcmp(derived, buyer_pubkey, 32) != 0)
        return FILE_MARKET_DELIVERY_UNAUTHENTICATED;
    f->fetches++;
    if (!f->fetch_ready)
        return FILE_MARKET_DELIVERY_PAYMENT_PENDING;
    if (deadline_ms <= 0)
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    size_t size = chunk_index == 0
        ? FILE_MARKET_CHUNK_SIZE : sizeof(k_purchase_content);
    out->data = zcl_calloc(1, size,
                           "purchase fetched fixture");
    if (!out->data)
        return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
    if (chunk_index == 1)
        memcpy(out->data, k_purchase_content, sizeof(k_purchase_content));
    out->size = (uint32_t)size;
    sha3_256(out->data, out->size, out->sha3);
    return FILE_MARKET_DELIVERY_READY;
}

static enum file_market_delivery_status purchase_fetch_onion_limited(
    void *opaque, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out)
{
    struct purchase_fixture *fixture = opaque;
    if (!fixture || !seller_onion_pubkey || !network_genesis || !offer_id ||
        !buyer_pubkey || !buyer_seed || !out || chunk_index != 0)
        return FILE_MARKET_DELIVERY_MALFORMED;
    memset(out, 0, sizeof(*out));
    fixture->onion_fetches++;
    fixture->onion_deadline_ms = deadline_ms;
    return FILE_MARKET_DELIVERY_RESOURCE_LIMIT;
}

static bool purchase_offer(struct file_offer *offer, int64_t now)
{
    const struct chain_params *params = chain_params_get();
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    if (!params) return false;
    memset(offer, 0, sizeof(*offer));
    memset(seed, 0x57, sizeof(seed));
    uint8_t chunk_hashes[64];
    purchase_zero_chunk_sha3(chunk_hashes);
    sha3_256(k_purchase_content, sizeof(k_purchase_content),
             chunk_hashes + 32);
    sha3_256(chunk_hashes, sizeof(chunk_hashes), offer->root_hash);
    memcpy(offer->network_genesis,
           params->consensus.hashGenesisBlock.data, 32);
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "purchase.bin");
    offer->size_bytes = FILE_MARKET_CHUNK_SIZE + sizeof(k_purchase_content);
    offer->num_chunks = 2;
    offer->price_per_mb = 1200;
    for (uint8_t d = 1; ; d++) {
        memset(offer->z_addr, 0, sizeof(offer->z_addr));
        offer->z_addr[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, offer->z_addr)) break;
        if (d == UINT8_MAX) return false;
    }
    jub_to_bytes(offer->z_addr + 11, &payment_key);
    offer->peer_ip[15] = 1;
    offer->peer_port = 18034;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->last_seen = now;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = 9901;
    offer->issued_unix = now - 60;
    offer->expires_unix = now + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

int file_market_purchase_tests(void)
{
    int failures = 0;
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "file_market_purchase", "intent");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb; memset(&ndb, 0, sizeof(ndb));
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct file_offer offer;
    bool ready = node_db_open(&ndb, path) && purchase_offer(&offer, now) &&
                 db_file_offer_save(&ndb, &offer);
    const struct chain_params *params = chain_params_get();
    struct purchase_fixture fixture; memset(&fixture, 0, sizeof(fixture));
    fixture.ndb = &ndb;
    memset(fixture.initial_root, 0x31, 32);
    memset(fixture.reserved_root, 0x32, 32);
    fixture.tip_height = 420;
    fixture.deadline_wall_unix = now;
    memset(fixture.tip_hash, 0x44, 32);
    fixture.money_current = true;
    fixture.source_owned = true;
    ready = ready && params && wallet_identity_ensure(
        &ndb, params->consensus.hashGenesisBlock.data, "dev",
        &fixture.identity);
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    ready = ready && wallet_lock_unlock(NULL, NULL, "market-purchase-test").ok;
    PURCHASE_CHECK("authenticated offer, identity, and encrypted fixture", ready);
    if (!ready) goto cleanup;

    struct market_purchase_runtime runtime; memset(&runtime, 0, sizeof(runtime));
    runtime.node_db = &ndb;
    runtime.read_money = purchase_money;
    runtime.money_ctx = &fixture;
    runtime.check_source = purchase_source;
    runtime.source_ctx = &fixture;
    runtime.send = purchase_send;
    runtime.send_ctx = &fixture;
    runtime.notify = purchase_notify;
    runtime.notify_ctx = &fixture;
    runtime.fetch = purchase_fetch;
    runtime.fetch_ctx = &fixture;
    runtime.tip_height = fixture.tip_height;
    memcpy(runtime.tip_hash, fixture.tip_hash, 32);
    runtime.maximum_fee_zat = 10000;
    runtime.now_unix = now;
    struct market_purchase_request request; memset(&request, 0, sizeof(request));
    snprintf(request.wallet_scope, sizeof(request.wallet_scope), "dev");
    memcpy(request.offer_id, offer.offer_id, 32);
    snprintf(request.source_address, sizeof(request.source_address),
             "fixture-owned-source");
    request.chunk_start = 0;
    request.chunks_paid = offer.num_chunks;
    snprintf(request.idempotency_key, sizeof(request.idempotency_key),
             "purchase-1");
    file_market_offer_range_zat(&offer, 0, request.chunks_paid,
                                &fixture.expected_amount);

    if (ready) {
        enum { PURCHASE_SAPLING_HEIGHT = 100 };
        ready = simnet_init(&fixture.sim);
        fixture.sim_ready = ready;
        if (ready) {
            simnet_activate_sapling_at(&fixture.sim,
                                       PURCHASE_SAPLING_HEIGHT);
            ready = simnet_enable_sapling_tree(&fixture.sim);
            simnet_enable_contextual_check(&fixture.sim, false);
        }
        if (ready) {
            struct script funding_script;
            script_init(&funding_script);
            static const uint8_t funding_prefix[] = {0x76, 0xa9, 0x14};
            script_set(&funding_script, funding_prefix,
                       sizeof(funding_prefix));
            int funding_height = simnet_tip_height(&fixture.sim) + 1;
            ready = simnet_mint_coinbase_to(
                &fixture.sim, &funding_script,
                fixture.expected_amount + runtime.maximum_fee_zat,
                &fixture.funding_txid) &&
                simnet_mint_to_height(
                    &fixture.sim, funding_height + COINBASE_MATURITY);
        }
    }
    PURCHASE_CHECK("isolated payment funding is mature", ready);
    if (!ready) goto cleanup;

    struct market_purchase_view plan, replay, committed;
    struct zcl_result planned = market_purchase_plan(&runtime, &request, &plan);
    struct file_payment memo_contract; memset(&memo_contract, 0,
                                               sizeof(memo_contract));
    memo_contract.version = FILE_MARKET_PAYMENT_VERSION;
    memcpy(memo_contract.network_genesis, offer.network_genesis, 32);
    memcpy(memo_contract.offer_id, offer.offer_id, 32);
    memcpy(memo_contract.txid, plan.plan_id, 32);
    memo_contract.chunk_start = request.chunk_start;
    memo_contract.chunks_paid = request.chunks_paid;
    memo_contract.amount_zat = fixture.expected_amount;
    memcpy(memo_contract.buyer_pubkey, plan.buyer_pubkey, 32);
    bool memo_ready = file_payment_memo_encode(
        &memo_contract, fixture.expected_memo) == FILE_PAYMENT_AUTH_OK;
    PURCHASE_CHECK("plan reserves exact range value plus maximum fee",
        planned.ok && memo_ready && plan.amount_zat == fixture.expected_amount &&
        plan.reserved_zat == fixture.expected_amount + 10000 &&
        vault_intent_reserved_total(
            &ndb, "dev", fixture.identity.wallet_instance_id) ==
                plan.reserved_zat);

    struct zcl_result replayed = market_purchase_plan(
        &runtime, &request, &replay);
    PURCHASE_CHECK("same idempotency key returns the same durable plan",
        replayed.ok && replay.idempotent_replay &&
        memcmp(replay.plan_id, plan.plan_id, 32) == 0);
    struct market_purchase_request changed = request;
    changed.chunk_start = 1;
    PURCHASE_CHECK("changed request under same idempotency key conflicts",
        !market_purchase_plan(&runtime, &changed, &replay).ok);

    struct zcl_result committed_result = market_purchase_commit(
        &runtime, "dev", plan.plan_id, &committed);
    PURCHASE_CHECK("commit sends exact memo and seals a buyer payment claim",
        committed_result.ok && fixture.sends == 1 &&
        fixture.chain_confirmed && fixture.payment_height > 0 &&
        fixture.notifications == 1 && committed.has_txid &&
        committed.has_claim && committed.payment_notification_queued);
    struct zcl_result committed_replay = market_purchase_commit(
        &runtime, "dev", plan.plan_id, &replay);
    PURCHASE_CHECK("commit replay never broadcasts a second transaction",
        committed_replay.ok && replay.idempotent_replay && fixture.sends == 1 &&
        fixture.notifications == 2 &&
        memcmp(replay.txid, committed.txid, 32) == 0);

    node_db_close(&ndb);
    PURCHASE_CHECK("restart reopens durable purchase intent",
                   node_db_open(&ndb, path));
    fixture.ndb = &ndb;
    struct market_purchase_view restarted;
    PURCHASE_CHECK("restart reconstructs claim without buyer key disclosure",
        market_purchase_status(&runtime, plan.plan_id, &restarted).ok &&
        restarted.has_claim &&
        memcmp(restarted.claim_id, committed.claim_id, 32) == 0);

    char absolute_dir[MARKET_DOWNLOAD_PATH_MAX];
    char destination[MARKET_DOWNLOAD_PATH_MAX];
    bool destination_ready = platform_directory_canonical_real(
        dir, absolute_dir, sizeof(absolute_dir));
    snprintf(destination, sizeof(destination), "%s/purchased.bin",
             destination_ready ? absolute_dir : "");
    struct market_purchase_view downloaded;
    fixture.fetch_ready = false;
    struct zcl_result pending_download = market_purchase_retrieve(
        &runtime, plan.plan_id, destination, &downloaded);
    if (pending_download.ok == false)
        printf("file_market purchase: pending retrieve reason=%s\n",
               pending_download.message);
    struct market_download_record durable_download;
    PURCHASE_CHECK("pending seller keeps a path-private restartable download",
        destination_ready && !pending_download.ok && fixture.fetches == 1 &&
        db_market_download_find(&ndb, plan.plan_id, &durable_download) &&
        durable_download.state == MARKET_DOWNLOAD_FETCHING &&
        durable_download.chunks_received == 0 &&
        access(destination, F_OK) != 0);

    node_db_close(&ndb);
    PURCHASE_CHECK("download progress survives database restart",
                   node_db_open(&ndb, path));
    fixture.ndb = &ndb;
    fixture.fetch_ready = true;
    int fetches_before_budget = fixture.fetches;
    atomic_init(&fixture.deadline_clock_reads, 0);
    struct platform_clock_source budget_source = {
        .monotonic_us = purchase_deadline_monotonic_us,
        .wall_unix = purchase_deadline_wall_unix,
        .user = &fixture,
    };
    platform_clock_set_source(&budget_source);
    struct zcl_result budget_limited = market_purchase_retrieve(
        &runtime, plan.plan_id, destination, &downloaded);
    platform_clock_clear_source();
    struct market_download_record bounded_progress;
    bool bounded_found = db_market_download_find(
        &ndb, plan.plan_id, &bounded_progress);
    int bounded_chunk_count = db_market_download_chunk_count(
        &ndb, plan.plan_id);
    bool bounded_exact =
        !budget_limited.ok && budget_limited.code == -76 &&
        fixture.fetches == fetches_before_budget + 1 &&
        bounded_found &&
        bounded_progress.state == MARKET_DOWNLOAD_FETCHING &&
        bounded_progress.chunks_received == 1 &&
        bounded_progress.bytes_received == FILE_MARKET_CHUNK_SIZE &&
        bounded_chunk_count == 1 && !downloaded.destination_published &&
        access(destination, F_OK) != 0;
    if (!bounded_exact)
        printf("file_market purchase: clearnet budget detail ok=%d code=%d "
               "fetch=%d/%d clock=%d found=%d state=%d chunks=%u bytes=%llu "
               "rows=%d published=%d exists=%d\n",
               budget_limited.ok, budget_limited.code, fixture.fetches,
               fetches_before_budget, atomic_load(&fixture.deadline_clock_reads),
               bounded_found,
               bounded_found ? (int)bounded_progress.state : -1,
               bounded_found ? bounded_progress.chunks_received : 0,
               (unsigned long long)(bounded_found
                   ? bounded_progress.bytes_received : 0),
               bounded_chunk_count, downloaded.destination_published,
               access(destination, F_OK) == 0);
    PURCHASE_CHECK("clearnet budget persists one chunk and starts no next fetch",
                   bounded_exact);
    node_db_close(&ndb);
    PURCHASE_CHECK("budgeted clearnet prefix survives database restart",
                   node_db_open(&ndb, path));
    fixture.ndb = &ndb;
    struct zcl_result retrieved = market_purchase_retrieve(
        &runtime, plan.plan_id, destination, &downloaded);
    if (!retrieved.ok)
        printf("file_market purchase: retrieve reason=%s\n",
               retrieved.message);
    uint8_t disk[sizeof(k_purchase_content)];
    FILE *published = fopen(destination, "rb");
    bool tail_seek = published &&
        fseeko(published, (off_t)FILE_MARKET_CHUNK_SIZE, SEEK_SET) == 0;
    size_t disk_len = tail_seek ? fread(disk, 1, sizeof(disk), published) : 0;
    if (published) fclose(published);
    PURCHASE_CHECK("verified manifest is atomically published after restart",
        retrieved.ok && downloaded.destination_published &&
        downloaded.chunks_received == 2 && downloaded.num_chunks == 2 &&
        disk_len == sizeof(k_purchase_content) &&
        memcmp(disk, k_purchase_content, sizeof(disk)) == 0);
    int fetches_after_publish = fixture.fetches;
    PURCHASE_CHECK("retrieve replay never downloads or republishes twice",
        market_purchase_retrieve(&runtime, plan.plan_id, destination,
                                 &downloaded).ok &&
        downloaded.idempotent_replay &&
        fixture.fetches == fetches_after_publish);

    request.idempotency_key[9] = '2';
    fixture.money_reads = 1;
    struct market_purchase_view uncertain;
    struct zcl_result planned_uncertain = market_purchase_plan(
        &runtime, &request, &uncertain);
    bool claimed = planned_uncertain.ok && vault_intent_claim_commit(
        &ndb, uncertain.plan_id, now);
    int before = fixture.sends;
    struct zcl_result refused = market_purchase_commit(
        &runtime, "dev", uncertain.plan_id, &replay);
    PURCHASE_CHECK("restart-uncertain proving state fails closed without resend",
        claimed && !refused.ok && fixture.sends == before);

    request.idempotency_key[9] = '3';
    fixture.money_reads = 1;
    struct market_purchase_view stale;
    struct zcl_result planned_stale = market_purchase_plan(
        &runtime, &request, &stale);
    runtime.tip_hash[0] ^= 1;
    before = fixture.sends;
    struct zcl_result stale_commit = market_purchase_commit(
        &runtime, "dev", stale.plan_id, &replay);
    PURCHASE_CHECK("changed tip-bound state conflicts before wallet mutation",
        planned_stale.ok && !stale_commit.ok && fixture.sends == before);

    runtime.tip_hash[0] ^= 1;
    request.idempotency_key[9] = '4';
    fixture.money_reads = 1;
    struct market_purchase_view fee_bound;
    struct zcl_result planned_fee = market_purchase_plan(
        &runtime, &request, &fee_bound);
    runtime.maximum_fee_zat++;
    before = fixture.sends;
    struct zcl_result changed_fee = market_purchase_commit(
        &runtime, "dev", fee_bound.plan_id, &replay);
    PURCHASE_CHECK("changed maximum fee conflicts before wallet mutation",
        planned_fee.ok && !changed_fee.ok && fixture.sends == before);
    runtime.maximum_fee_zat--;

    request.idempotency_key[9] = '5';
    fixture.money_reads = 1;
    struct market_purchase_view source_bound;
    struct zcl_result planned_source = market_purchase_plan(
        &runtime, &request, &source_bound);
    fixture.source_owned = false;
    before = fixture.sends;
    struct zcl_result unowned = market_purchase_commit(
        &runtime, "dev", source_bound.plan_id, &replay);
    PURCHASE_CHECK("unowned source refuses before wallet mutation",
        planned_source.ok && !unowned.ok && fixture.sends == before);
    fixture.source_owned = true;

    request.idempotency_key[9] = '6';
    fixture.money_reads = 1;
    fixture.identity.network_genesis[0] ^= 1;
    PURCHASE_CHECK("wrong-network signed offer refuses without reservation",
        !market_purchase_plan(&runtime, &request, &replay).ok);
    fixture.identity.network_genesis[0] ^= 1;

    request.idempotency_key[9] = '7';
    fixture.money_reads = 1;
    fixture.money_current = false;
    PURCHASE_CHECK("unknown money reader never collapses to a zero-balance plan",
        !market_purchase_plan(&runtime, &request, &replay).ok);
    fixture.money_current = true;

    /* ── Phase B5: an onion-endpoint signed offer refuses delivery outright
     * when no embedded Tor client is running — never a clearnet fallback. ── */
    struct file_offer onion_offer;
    bool onion_ready = purchase_offer(&onion_offer, now);
    if (onion_ready) {
        uint8_t onion_seed[32];
        memset(onion_seed, 0x57, sizeof(onion_seed));
        memset(onion_offer.peer_ip, 0, sizeof(onion_offer.peer_ip));
        onion_offer.peer_port = 0;
        onion_offer.auth_version = FILE_MARKET_OFFER_VERSION_V2;
        onion_offer.endpoint_type = FILE_MARKET_ENDPOINT_ONION;
        onion_offer.nonce++;
        memset(onion_offer.onion_pubkey, 0xab,
               sizeof(onion_offer.onion_pubkey));
        onion_ready = file_offer_auth_seal(&onion_offer, onion_seed) ==
            FILE_OFFER_AUTH_OK && db_file_offer_save(&ndb, &onion_offer);
    }
    if (onion_ready) {
        struct script onion_funding_script;
        script_init(&onion_funding_script);
        static const uint8_t onion_funding_prefix[] = {0x76, 0xa9, 0x14};
        script_set(&onion_funding_script, onion_funding_prefix,
                   sizeof(onion_funding_prefix));
        int onion_funding_height = simnet_tip_height(&fixture.sim) + 1;
        onion_ready = simnet_mint_coinbase_to(
            &fixture.sim, &onion_funding_script,
            fixture.expected_amount + runtime.maximum_fee_zat,
            &fixture.funding_txid) &&
            simnet_mint_to_height(
                &fixture.sim, onion_funding_height + COINBASE_MATURITY);
    }
    struct market_purchase_view onion_plan, onion_committed;
    struct zcl_result onion_planned = ZCL_OK, onion_commit = ZCL_OK;
    if (onion_ready) {
        memcpy(request.offer_id, onion_offer.offer_id, 32);
        request.idempotency_key[9] = '8';
        fixture.money_reads = 1;
        onion_planned = market_purchase_plan(&runtime, &request,
                                             &onion_plan);
        struct file_payment onion_memo;
        memset(&onion_memo, 0, sizeof(onion_memo));
        onion_memo.version = FILE_MARKET_PAYMENT_VERSION;
        memcpy(onion_memo.network_genesis, onion_offer.network_genesis, 32);
        memcpy(onion_memo.offer_id, onion_offer.offer_id, 32);
        memcpy(onion_memo.txid, onion_plan.plan_id, 32);
        onion_memo.chunk_start = request.chunk_start;
        onion_memo.chunks_paid = request.chunks_paid;
        onion_memo.amount_zat = fixture.expected_amount;
        memcpy(onion_memo.buyer_pubkey, onion_plan.buyer_pubkey, 32);
        onion_ready = onion_planned.ok && file_payment_memo_encode(
            &onion_memo, fixture.expected_memo) == FILE_PAYMENT_AUTH_OK;
    }
    if (onion_ready)
        onion_commit = market_purchase_commit(
            &runtime, "dev", onion_plan.plan_id, &onion_committed);
    char onion_destination[MARKET_DOWNLOAD_PATH_MAX];
    snprintf(onion_destination, sizeof(onion_destination),
             "%s/onion-purchased.bin", absolute_dir);
    int fetches_before_onion = fixture.fetches;
    struct market_purchase_view onion_download;
    struct zcl_result onion_retrieved = onion_ready
        ? market_purchase_retrieve(&runtime, onion_plan.plan_id,
                                   onion_destination, &onion_download)
        : ZCL_ERR(-1, "onion fixture could not be built");
    if (!(onion_planned.ok && onion_commit.ok && !onion_retrieved.ok &&
          onion_retrieved.code == -78 &&
          fixture.fetches == fetches_before_onion))
        printf("file_market purchase: onion detail planned=%d(%d %s) "
               "commit=%d(%d %s) retrieve=%d code=%d msg=%s fetches=%d/%d\n",
               onion_planned.ok, onion_planned.code, onion_planned.message,
               onion_commit.ok, onion_commit.code, onion_commit.message,
               onion_retrieved.ok, onion_retrieved.code,
               onion_retrieved.message, fixture.fetches,
               fetches_before_onion);
    PURCHASE_CHECK("onion-endpoint offer refuses delivery without a Tor client",
        onion_planned.ok && onion_commit.ok && !onion_retrieved.ok &&
        onion_retrieved.code == -78 &&
        fixture.fetches == fetches_before_onion);
    runtime.fetch_onion = purchase_fetch_onion_limited;
    runtime.fetch_onion_ctx = &fixture;
    runtime.onion_transport_ready = true;
    struct market_purchase_view onion_limited_view;
    memset(&onion_limited_view, 0, sizeof(onion_limited_view));
    struct zcl_result onion_limited = onion_ready
        ? market_purchase_retrieve(&runtime, onion_plan.plan_id,
                                   onion_destination, &onion_limited_view)
        : ZCL_ERR(-1, "onion fixture could not be built");
    struct market_download_record onion_progress;
    int64_t observed_now_ms = platform_time_monotonic_ms();
    PURCHASE_CHECK("onion retrieval budget leaves only durable progress",
        !onion_limited.ok && onion_limited.code == -76 &&
        fixture.onion_fetches == 1 &&
        fixture.onion_deadline_ms > observed_now_ms &&
        fixture.onion_deadline_ms - observed_now_ms <=
            MARKET_PURCHASE_RETRIEVE_BUDGET_MS &&
        db_market_download_find(&ndb, onion_plan.plan_id, &onion_progress) &&
        onion_progress.state == MARKET_DOWNLOAD_FETCHING &&
        onion_progress.chunks_received == 0 &&
        onion_progress.bytes_received == 0 &&
        db_market_download_chunk_count(&ndb, onion_plan.plan_id) == 0 &&
        !onion_limited_view.destination_published &&
        access(onion_destination, F_OK) != 0);

cleanup:
    if (ndb.open) node_db_close(&ndb);
    if (fixture.sim_ready) simnet_free(&fixture.sim);
    wallet_lock_reset_for_test();
    test_rm_rf(dir);
    return failures;
}
