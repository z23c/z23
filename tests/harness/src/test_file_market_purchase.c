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
    int invalid_ready;
    int64_t expected_amount;
    uint8_t expected_memo[FILE_MARKET_PAYMENT_MEMO_BYTES];
    struct simnet sim;
    bool sim_ready;
    struct uint256 funding_txid;
    int payment_height;
    bool chain_confirmed;
    size_t sapling_tree_size;
};

struct purchase_test_run {
    struct node_db ndb;
    struct purchase_fixture fixture;
    struct market_purchase_runtime runtime;
    struct market_purchase_request request;
    struct file_offer offer;
    struct file_offer onion_offer;
    struct market_purchase_view plan;
    struct market_purchase_view replay;
    struct market_purchase_view committed;
    struct market_purchase_view downloaded;
    struct market_purchase_view onion_plan;
    struct market_purchase_view onion_committed;
    struct zcl_result onion_planned;
    struct zcl_result onion_commit;
    char dir[256];
    char path[320];
    char absolute_dir[MARKET_DOWNLOAD_PATH_MAX];
    char destination[MARKET_DOWNLOAD_PATH_MAX];
    char onion_destination[MARKET_DOWNLOAD_PATH_MAX];
    int64_t now;
    bool onion_ready;
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

static bool purchase_send_contract_violated(
    struct purchase_fixture *f, const char *source, const char *seller,
    int64_t amount, const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES])
{
    return !f || strcmp(source, "fixture-owned-source") != 0 ||
        !seller || seller[0] == '\0' || amount != f->expected_amount ||
        memcmp(memo, f->expected_memo, FILE_MARKET_PAYMENT_MEMO_BYTES) != 0;
}

static int purchase_payment_tx_build(
    struct purchase_fixture *f, uint8_t d[11], uint8_t pk_d[32],
    int64_t amount, const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES],
    struct transaction *tx)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    if (!transaction_alloc(tx, 1, 0))
        return -4;
    tx->vin[0].prevout.hash = f->funding_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    {
        static const uint8_t placeholder_sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, placeholder_sig,
                   sizeof(placeholder_sig));
    }
    tx->value_balance = -amount;
    tx->v_shielded_output = zcl_calloc(
        1, sizeof(struct output_description), "market purchase output");
    if (!tx->v_shielded_output) {
        transaction_free(tx);
        return -5;
    }
    tx->num_shielded_output = 1;
    struct output_description *od = tx->v_shielded_output;
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
        precompute_tx_data(tx, &txdata);
        struct script empty;
        script_init(&empty);
        struct sighash_type hash_type = {.raw = SIGHASH_ALL};
        struct uint256 sighash;
        built = signature_hash(&empty, tx, NOT_AN_INPUT, hash_type, 0,
                               branch, &txdata, &sighash) &&
                purchase_binding_sig(output_rcv, sighash.data,
                                     tx->binding_sig);
    }
    if (!built) {
        transaction_free(tx);
        return -6;
    }
    return 0;
}

static bool purchase_send_mint_payment(struct purchase_fixture *f,
                                       struct transaction *tx,
                                       struct uint256 *payment_txid)
{
    transaction_compute_hash(tx);
    *payment_txid = tx->hash;
    struct output_description *shielded_owned = tx->v_shielded_output;
    bool mined = simnet_mint_txs(&f->sim, tx, 1);
    free(shielded_owned);
    return mined;
}

static void purchase_send_record_chain_state(struct purchase_fixture *f)
{
    f->payment_height = simnet_tip_height(&f->sim);
    f->chain_confirmed =
        simnet_sapling_tree_size(&f->sim) == f->sapling_tree_size + 1 &&
        !simnet_coin_value(&f->sim, &f->funding_txid, 0, NULL);
    if (f->chain_confirmed)
        f->sapling_tree_size = simnet_sapling_tree_size(&f->sim);
}

static struct zcl_result purchase_send(
    void *opaque, const char *source, const char *seller, int64_t amount,
    const uint8_t memo[FILE_MARKET_PAYMENT_MEMO_BYTES], uint8_t txid[32])
{
    struct purchase_fixture *f = opaque;
    if (purchase_send_contract_violated(f, source, seller, amount, memo))
        return ZCL_ERR(-2, "exact send contract changed");
    uint8_t d[11], pk_d[32];
    if (!f->sim_ready || !sapling_decode_payment_address(seller, d, pk_d))
        return ZCL_ERR(-3, "isolated seller address cannot be decoded");

    struct transaction tx;
    int build_code = purchase_payment_tx_build(f, d, pk_d, amount, memo,
                                               &tx);
    if (build_code == -4)
        return ZCL_ERR(-4, "isolated payment input allocation failed");
    if (build_code == -5)
        return ZCL_ERR(-5, "isolated payment output allocation failed");
    if (build_code == -6)
        return ZCL_ERR(-6, "isolated market payment could not be built");
    struct uint256 payment_txid;
    if (!purchase_send_mint_payment(f, &tx, &payment_txid))
        return ZCL_ERR(-7, "isolated market payment was not mined");

    memcpy(txid, payment_txid.data, 32);
    f->sends++;
    purchase_send_record_chain_state(f);
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

static bool purchase_fetch_args_malformed(
    struct purchase_fixture *f, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    const struct file_market_delivery_chunk *out)
{
    return !f || !peer_ip || peer_ip[15] != 1 || peer_port != 18034 ||
        !network_genesis || !offer_id || chunk_index > 1 ||
        !buyer_pubkey || !buyer_seed || !out;
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
    if (purchase_fetch_args_malformed(f, peer_ip, peer_port, network_genesis,
                                      offer_id, chunk_index, buyer_pubkey,
                                      buyer_seed, out))
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

static enum file_market_delivery_status purchase_fetch_invalid_ready(
    void *opaque, const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out)
{
    struct purchase_fixture *f = opaque;
    if (f->invalid_ready == 1) {
        f->fetches++;
        memset(out, 0, sizeof(*out));
        out->size = FILE_MARKET_CHUNK_SIZE;
        return FILE_MARKET_DELIVERY_READY;
    }
    enum file_market_delivery_status status = purchase_fetch(
        opaque, peer_ip, peer_port, network_genesis, offer_id, chunk_index,
        buyer_pubkey, buyer_seed, deadline_ms, out);
    if (status == FILE_MARKET_DELIVERY_READY) {
        if (f->invalid_ready == 2) out->size--;
        else out->sha3[0] ^= 1;
    }
    return status;
}

static int purchase_invalid_ready_tests(
    struct market_purchase_runtime *runtime, struct purchase_fixture *fixture,
    const uint8_t plan_id[32], const char *destination)
{
    int failures = 0;
    const char *causes[] = {"data", "size", "hash"};
    runtime->fetch = purchase_fetch_invalid_ready;
    fixture->fetch_ready = true;
    for (int mode = 1; mode <= 3; mode++) {
        fixture->invalid_ready = mode;
        struct market_purchase_view view = {0};
        int before = fixture->fetches;
        struct zcl_result result = market_purchase_retrieve(
            runtime, plan_id, destination, &view);
        PURCHASE_CHECK(causes[mode - 1],
            !result.ok && result.code == -76 &&
            fixture->fetches == before + 1 &&
            db_market_download_chunk_count(fixture->ndb, plan_id) == 0 &&
            !view.destination_published && access(destination, F_OK) != 0);
        PURCHASE_CHECK("invalid READY names chunk, cause, and safe recovery",
            strstr(result.message, "chunk=0") &&
            strstr(result.message, causes[mode - 1]) &&
            strstr(result.message, "retry") && strstr(result.message, "provider") &&
            !strstr(result.message, "seller delivery is"));
    }
    fixture->invalid_ready = 0;
    runtime->fetch = purchase_fetch;
    return failures;
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

static bool purchase_test_fixture_ready(struct purchase_test_run *run)
{
    test_make_tmpdir(run->dir, sizeof(run->dir), "file_market_purchase",
                     "intent");
    snprintf(run->path, sizeof(run->path), "%s/node.db", run->dir);
    memset(&run->ndb, 0, sizeof(run->ndb));
    run->now = (int64_t)platform_time_wall_time_t();
    bool ready = node_db_open(&run->ndb, run->path) &&
                 purchase_offer(&run->offer, run->now) &&
                 db_file_offer_save(&run->ndb, &run->offer);
    const struct chain_params *params = chain_params_get();
    memset(&run->fixture, 0, sizeof(run->fixture));
    run->fixture.ndb = &run->ndb;
    memset(run->fixture.initial_root, 0x31, 32);
    memset(run->fixture.reserved_root, 0x32, 32);
    run->fixture.tip_height = 420;
    run->fixture.deadline_wall_unix = run->now;
    memset(run->fixture.tip_hash, 0x44, 32);
    run->fixture.money_current = true;
    run->fixture.source_owned = true;
    ready = ready && params && wallet_identity_ensure(
        &run->ndb, params->consensus.hashGenesisBlock.data, "dev",
        &run->fixture.identity);
    wallet_lock_reset_for_test();
    wallet_lock_note_encrypted_at_rest();
    ready = ready && wallet_lock_unlock(NULL, NULL, "market-purchase-test").ok;
    return ready;
}

static void purchase_test_runtime_init(struct purchase_test_run *run)
{
    struct market_purchase_runtime *runtime = &run->runtime;
    memset(runtime, 0, sizeof(*runtime));
    runtime->node_db = &run->ndb;
    runtime->read_money = purchase_money;
    runtime->money_ctx = &run->fixture;
    runtime->check_source = purchase_source;
    runtime->source_ctx = &run->fixture;
    runtime->send = purchase_send;
    runtime->send_ctx = &run->fixture;
    runtime->notify = purchase_notify;
    runtime->notify_ctx = &run->fixture;
    runtime->fetch = purchase_fetch;
    runtime->fetch_ctx = &run->fixture;
    runtime->tip_height = run->fixture.tip_height;
    memcpy(runtime->tip_hash, run->fixture.tip_hash, 32);
    runtime->maximum_fee_zat = 10000;
    runtime->now_unix = run->now;
    struct market_purchase_request *request = &run->request;
    memset(request, 0, sizeof(*request));
    snprintf(request->wallet_scope, sizeof(request->wallet_scope), "dev");
    memcpy(request->offer_id, run->offer.offer_id, 32);
    snprintf(request->source_address, sizeof(request->source_address),
             "fixture-owned-source");
    request->chunk_start = 0;
    request->chunks_paid = run->offer.num_chunks;
    snprintf(request->idempotency_key, sizeof(request->idempotency_key),
             "purchase-1");
    file_market_offer_range_zat(&run->offer, 0, request->chunks_paid,
                                &run->fixture.expected_amount);
}

static bool purchase_test_funding_ready(struct purchase_test_run *run)
{
    enum { PURCHASE_SAPLING_HEIGHT = 100 };
    bool ready = simnet_init(&run->fixture.sim);
    run->fixture.sim_ready = ready;
    if (ready) {
        simnet_activate_sapling_at(&run->fixture.sim,
                                   PURCHASE_SAPLING_HEIGHT);
        ready = simnet_enable_sapling_tree(&run->fixture.sim);
        simnet_enable_contextual_check(&run->fixture.sim, false);
    }
    if (ready) {
        struct script funding_script;
        script_init(&funding_script);
        static const uint8_t funding_prefix[] = {0x76, 0xa9, 0x14};
        script_set(&funding_script, funding_prefix,
                   sizeof(funding_prefix));
        int funding_height = simnet_tip_height(&run->fixture.sim) + 1;
        ready = simnet_mint_coinbase_to(
            &run->fixture.sim, &funding_script,
            run->fixture.expected_amount + run->runtime.maximum_fee_zat,
            &run->fixture.funding_txid) &&
            simnet_mint_to_height(
                &run->fixture.sim, funding_height + COINBASE_MATURITY);
    }
    return ready;
}

static int purchase_test_plan_checks(struct purchase_test_run *run)
{
    int failures = 0;
    struct zcl_result planned = market_purchase_plan(
        &run->runtime, &run->request, &run->plan);
    struct file_payment memo_contract; memset(&memo_contract, 0,
                                               sizeof(memo_contract));
    memo_contract.version = FILE_MARKET_PAYMENT_VERSION;
    memcpy(memo_contract.network_genesis, run->offer.network_genesis, 32);
    memcpy(memo_contract.offer_id, run->offer.offer_id, 32);
    memcpy(memo_contract.txid, run->plan.plan_id, 32);
    memo_contract.chunk_start = run->request.chunk_start;
    memo_contract.chunks_paid = run->request.chunks_paid;
    memo_contract.amount_zat = run->fixture.expected_amount;
    memcpy(memo_contract.buyer_pubkey, run->plan.buyer_pubkey, 32);
    bool memo_ready = file_payment_memo_encode(
        &memo_contract, run->fixture.expected_memo) == FILE_PAYMENT_AUTH_OK;
    PURCHASE_CHECK("plan reserves exact range value plus maximum fee",
        planned.ok && memo_ready &&
        run->plan.amount_zat == run->fixture.expected_amount &&
        run->plan.reserved_zat == run->fixture.expected_amount + 10000 &&
        vault_intent_reserved_total(
            &run->ndb, "dev", run->fixture.identity.wallet_instance_id) ==
                run->plan.reserved_zat);
    return failures;
}

static int purchase_test_plan_replay_checks(struct purchase_test_run *run)
{
    int failures = 0;
    struct zcl_result replayed = market_purchase_plan(
        &run->runtime, &run->request, &run->replay);
    PURCHASE_CHECK("same idempotency key returns the same durable plan",
        replayed.ok && run->replay.idempotent_replay &&
        memcmp(run->replay.plan_id, run->plan.plan_id, 32) == 0);
    struct market_purchase_request changed = run->request;
    changed.chunk_start = 1;
    PURCHASE_CHECK("changed request under same idempotency key conflicts",
        !market_purchase_plan(&run->runtime, &changed, &run->replay).ok);
    return failures;
}

static int purchase_test_commit_check(struct purchase_test_run *run)
{
    int failures = 0;
    struct zcl_result committed_result = market_purchase_commit(
        &run->runtime, "dev", run->plan.plan_id, &run->committed);
    PURCHASE_CHECK("commit sends exact memo and seals a buyer payment claim",
        committed_result.ok && run->fixture.sends == 1 &&
        run->fixture.chain_confirmed && run->fixture.payment_height > 0 &&
        run->fixture.notifications == 1 && run->committed.has_txid &&
        run->committed.has_claim && run->committed.payment_notification_queued);
    return failures;
}

static int purchase_test_commit_replay_check(struct purchase_test_run *run)
{
    int failures = 0;
    struct zcl_result committed_replay = market_purchase_commit(
        &run->runtime, "dev", run->plan.plan_id, &run->replay);
    PURCHASE_CHECK("commit replay never broadcasts a second transaction",
        committed_replay.ok && run->replay.idempotent_replay &&
        run->fixture.sends == 1 &&
        run->fixture.notifications == 2 &&
        memcmp(run->replay.txid, run->committed.txid, 32) == 0);
    return failures;
}

static int purchase_test_restart_claim_checks(struct purchase_test_run *run)
{
    int failures = 0;
    node_db_close(&run->ndb);
    PURCHASE_CHECK("restart reopens durable purchase intent",
                   node_db_open(&run->ndb, run->path));
    run->fixture.ndb = &run->ndb;
    struct market_purchase_view restarted;
    PURCHASE_CHECK("restart reconstructs claim without buyer key disclosure",
        market_purchase_status(
            &run->runtime, run->plan.plan_id, &restarted).ok &&
        restarted.has_claim &&
        memcmp(restarted.claim_id, run->committed.claim_id, 32) == 0);
    return failures;
}

static int purchase_test_pending_download_checks(
    struct purchase_test_run *run)
{
    int failures = 0;
    bool destination_ready = platform_directory_canonical_real(
        run->dir, run->absolute_dir, sizeof(run->absolute_dir));
    snprintf(run->destination, sizeof(run->destination), "%s/purchased.bin",
             destination_ready ? run->absolute_dir : "");
    run->fixture.fetch_ready = false;
    struct zcl_result pending_download = market_purchase_retrieve(
        &run->runtime, run->plan.plan_id, run->destination, &run->downloaded);
    if (pending_download.ok == false)
        printf("file_market purchase: pending retrieve reason=%s\n",
               pending_download.message);
    struct market_download_record durable_download;
    PURCHASE_CHECK("pending seller keeps a path-private restartable download",
        destination_ready && !pending_download.ok &&
        run->fixture.fetches == 1 &&
        db_market_download_find(
            &run->ndb, run->plan.plan_id, &durable_download) &&
        durable_download.state == MARKET_DOWNLOAD_FETCHING &&
        durable_download.chunks_received == 0 &&
        access(run->destination, F_OK) != 0);
    return failures;
}

static bool purchase_test_budget_progress_exact(
    struct purchase_test_run *run, const struct zcl_result *budget_limited,
    const struct market_download_record *bounded_progress, bool bounded_found,
    int bounded_chunk_count, int fetches_before_budget)
{
    return !budget_limited->ok && budget_limited->code == -76 &&
        run->fixture.fetches == fetches_before_budget + 1 &&
        bounded_found &&
        bounded_progress->state == MARKET_DOWNLOAD_FETCHING &&
        bounded_progress->chunks_received == 1 &&
        bounded_progress->bytes_received == FILE_MARKET_CHUNK_SIZE &&
        bounded_chunk_count == 1 &&
        !run->downloaded.destination_published &&
        access(run->destination, F_OK) != 0;
}

static int purchase_test_budget_checks(struct purchase_test_run *run)
{
    int failures = 0;
    node_db_close(&run->ndb);
    PURCHASE_CHECK("download progress survives database restart",
                   node_db_open(&run->ndb, run->path));
    run->fixture.ndb = &run->ndb;
    run->fixture.fetch_ready = true;
    failures += purchase_invalid_ready_tests(
        &run->runtime, &run->fixture, run->plan.plan_id, run->destination);
    int fetches_before_budget = run->fixture.fetches;
    atomic_init(&run->fixture.deadline_clock_reads, 0);
    struct platform_clock_source budget_source = {
        .monotonic_us = purchase_deadline_monotonic_us,
        .wall_unix = purchase_deadline_wall_unix,
        .user = &run->fixture,
    };
    platform_clock_set_source(&budget_source);
    struct zcl_result budget_limited = market_purchase_retrieve(
        &run->runtime, run->plan.plan_id, run->destination, &run->downloaded);
    platform_clock_clear_source();
    struct market_download_record bounded_progress;
    bool bounded_found = db_market_download_find(
        &run->ndb, run->plan.plan_id, &bounded_progress);
    int bounded_chunk_count = db_market_download_chunk_count(
        &run->ndb, run->plan.plan_id);
    bool bounded_exact = purchase_test_budget_progress_exact(
        run, &budget_limited, &bounded_progress, bounded_found,
        bounded_chunk_count, fetches_before_budget);
    if (!bounded_exact)
        printf("file_market purchase: clearnet budget detail ok=%d code=%d "
               "fetch=%d/%d clock=%d found=%d state=%d chunks=%u bytes=%llu "
               "rows=%d published=%d exists=%d\n",
               budget_limited.ok, budget_limited.code, run->fixture.fetches,
               fetches_before_budget,
               atomic_load(&run->fixture.deadline_clock_reads),
               bounded_found,
               bounded_found ? (int)bounded_progress.state : -1,
               bounded_found ? bounded_progress.chunks_received : 0,
               (unsigned long long)(bounded_found
                   ? bounded_progress.bytes_received : 0),
               bounded_chunk_count, run->downloaded.destination_published,
               access(run->destination, F_OK) == 0);
    PURCHASE_CHECK("clearnet budget persists one chunk and starts no next fetch",
                   bounded_exact);
    return failures;
}

static size_t purchase_test_read_published_tail(const char *destination,
                                                uint8_t *disk,
                                                size_t disk_size)
{
    FILE *published = fopen(destination, "rb");
    bool tail_seek = published &&
        fseeko(published, (off_t)FILE_MARKET_CHUNK_SIZE, SEEK_SET) == 0;
    size_t disk_len = tail_seek ? fread(disk, 1, disk_size, published) : 0;
    if (published) fclose(published);
    return disk_len;
}

static int purchase_test_publish_checks(struct purchase_test_run *run)
{
    int failures = 0;
    node_db_close(&run->ndb);
    PURCHASE_CHECK("budgeted clearnet prefix survives database restart",
                   node_db_open(&run->ndb, run->path));
    run->fixture.ndb = &run->ndb;
    struct zcl_result retrieved = market_purchase_retrieve(
        &run->runtime, run->plan.plan_id, run->destination, &run->downloaded);
    if (!retrieved.ok)
        printf("file_market purchase: retrieve reason=%s\n",
               retrieved.message);
    uint8_t disk[sizeof(k_purchase_content)];
    size_t disk_len = purchase_test_read_published_tail(
        run->destination, disk, sizeof(disk));
    PURCHASE_CHECK("verified manifest is atomically published after restart",
        retrieved.ok && run->downloaded.destination_published &&
        run->downloaded.chunks_received == 2 &&
        run->downloaded.num_chunks == 2 &&
        disk_len == sizeof(k_purchase_content) &&
        memcmp(disk, k_purchase_content, sizeof(disk)) == 0);
    return failures;
}

static int purchase_test_replay_retrieve_check(struct purchase_test_run *run)
{
    int failures = 0;
    int fetches_after_publish = run->fixture.fetches;
    PURCHASE_CHECK("retrieve replay never downloads or republishes twice",
        market_purchase_retrieve(&run->runtime, run->plan.plan_id,
                                 run->destination, &run->downloaded).ok &&
        run->downloaded.idempotent_replay &&
        run->fixture.fetches == fetches_after_publish);
    return failures;
}

static int purchase_test_state_conflict_refusals(struct purchase_test_run *run)
{
    int failures = 0;
    run->request.idempotency_key[9] = '2';
    run->fixture.money_reads = 1;
    struct market_purchase_view uncertain;
    struct zcl_result planned_uncertain = market_purchase_plan(
        &run->runtime, &run->request, &uncertain);
    bool claimed = planned_uncertain.ok && vault_intent_claim_commit(
        &run->ndb, uncertain.plan_id, run->now);
    int before = run->fixture.sends;
    struct zcl_result refused = market_purchase_commit(
        &run->runtime, "dev", uncertain.plan_id, &run->replay);
    PURCHASE_CHECK("restart-uncertain proving state fails closed without resend",
        claimed && !refused.ok && run->fixture.sends == before);

    run->request.idempotency_key[9] = '3';
    run->fixture.money_reads = 1;
    struct market_purchase_view stale;
    struct zcl_result planned_stale = market_purchase_plan(
        &run->runtime, &run->request, &stale);
    run->runtime.tip_hash[0] ^= 1;
    before = run->fixture.sends;
    struct zcl_result stale_commit = market_purchase_commit(
        &run->runtime, "dev", stale.plan_id, &run->replay);
    PURCHASE_CHECK("changed tip-bound state conflicts before wallet mutation",
        planned_stale.ok && !stale_commit.ok &&
        run->fixture.sends == before);
    return failures;
}

static int purchase_test_policy_conflict_refusals(struct purchase_test_run *run)
{
    int failures = 0;
    run->runtime.tip_hash[0] ^= 1;
    run->request.idempotency_key[9] = '4';
    run->fixture.money_reads = 1;
    struct market_purchase_view fee_bound;
    struct zcl_result planned_fee = market_purchase_plan(
        &run->runtime, &run->request, &fee_bound);
    run->runtime.maximum_fee_zat++;
    int before = run->fixture.sends;
    struct zcl_result changed_fee = market_purchase_commit(
        &run->runtime, "dev", fee_bound.plan_id, &run->replay);
    PURCHASE_CHECK("changed maximum fee conflicts before wallet mutation",
        planned_fee.ok && !changed_fee.ok && run->fixture.sends == before);
    run->runtime.maximum_fee_zat--;

    run->request.idempotency_key[9] = '5';
    run->fixture.money_reads = 1;
    struct market_purchase_view source_bound;
    struct zcl_result planned_source = market_purchase_plan(
        &run->runtime, &run->request, &source_bound);
    run->fixture.source_owned = false;
    before = run->fixture.sends;
    struct zcl_result unowned = market_purchase_commit(
        &run->runtime, "dev", source_bound.plan_id, &run->replay);
    PURCHASE_CHECK("unowned source refuses before wallet mutation",
        planned_source.ok && !unowned.ok && run->fixture.sends == before);
    run->fixture.source_owned = true;
    return failures;
}

static int purchase_test_plan_refusals(struct purchase_test_run *run)
{
    int failures = 0;
    run->request.idempotency_key[9] = '6';
    run->fixture.money_reads = 1;
    run->fixture.identity.network_genesis[0] ^= 1;
    PURCHASE_CHECK("wrong-network signed offer refuses without reservation",
        !market_purchase_plan(&run->runtime, &run->request,
                              &run->replay).ok);
    run->fixture.identity.network_genesis[0] ^= 1;

    run->request.idempotency_key[9] = '7';
    run->fixture.money_reads = 1;
    run->fixture.money_current = false;
    PURCHASE_CHECK("unknown money reader never collapses to a zero-balance plan",
        !market_purchase_plan(&run->runtime, &run->request,
                              &run->replay).ok);
    run->fixture.money_current = true;
    return failures;
}

static void purchase_test_onion_fixture_prepare(struct purchase_test_run *run)
{
    bool onion_ready = purchase_offer(&run->onion_offer, run->now);
    if (onion_ready) {
        uint8_t onion_seed[32];
        memset(onion_seed, 0x57, sizeof(onion_seed));
        memset(run->onion_offer.peer_ip, 0, sizeof(run->onion_offer.peer_ip));
        run->onion_offer.peer_port = 0;
        run->onion_offer.auth_version = FILE_MARKET_OFFER_VERSION_V2;
        run->onion_offer.endpoint_type = FILE_MARKET_ENDPOINT_ONION;
        run->onion_offer.nonce++;
        memset(run->onion_offer.onion_pubkey, 0xab,
               sizeof(run->onion_offer.onion_pubkey));
        onion_ready = file_offer_auth_seal(&run->onion_offer, onion_seed) ==
            FILE_OFFER_AUTH_OK &&
            db_file_offer_save(&run->ndb, &run->onion_offer);
    }
    if (onion_ready) {
        struct script onion_funding_script;
        script_init(&onion_funding_script);
        static const uint8_t onion_funding_prefix[] = {0x76, 0xa9, 0x14};
        script_set(&onion_funding_script, onion_funding_prefix,
                   sizeof(onion_funding_prefix));
        int onion_funding_height = simnet_tip_height(&run->fixture.sim) + 1;
        onion_ready = simnet_mint_coinbase_to(
            &run->fixture.sim, &onion_funding_script,
            run->fixture.expected_amount + run->runtime.maximum_fee_zat,
            &run->fixture.funding_txid) &&
            simnet_mint_to_height(
                &run->fixture.sim, onion_funding_height + COINBASE_MATURITY);
    }
    run->onion_ready = onion_ready;
}

static void purchase_test_onion_plan_prepare(struct purchase_test_run *run)
{
    run->onion_planned = ZCL_OK;
    run->onion_commit = ZCL_OK;
    if (run->onion_ready) {
        memcpy(run->request.offer_id, run->onion_offer.offer_id, 32);
        run->request.idempotency_key[9] = '8';
        run->fixture.money_reads = 1;
        run->onion_planned = market_purchase_plan(&run->runtime,
                                                  &run->request,
                                                  &run->onion_plan);
        struct file_payment onion_memo;
        memset(&onion_memo, 0, sizeof(onion_memo));
        onion_memo.version = FILE_MARKET_PAYMENT_VERSION;
        memcpy(onion_memo.network_genesis, run->onion_offer.network_genesis,
               32);
        memcpy(onion_memo.offer_id, run->onion_offer.offer_id, 32);
        memcpy(onion_memo.txid, run->onion_plan.plan_id, 32);
        onion_memo.chunk_start = run->request.chunk_start;
        onion_memo.chunks_paid = run->request.chunks_paid;
        onion_memo.amount_zat = run->fixture.expected_amount;
        memcpy(onion_memo.buyer_pubkey, run->onion_plan.buyer_pubkey, 32);
        run->onion_ready = run->onion_planned.ok && file_payment_memo_encode(
            &onion_memo, run->fixture.expected_memo) == FILE_PAYMENT_AUTH_OK;
    }
    if (run->onion_ready)
        run->onion_commit = market_purchase_commit(
            &run->runtime, "dev", run->onion_plan.plan_id,
            &run->onion_committed);
}

static bool purchase_test_onion_refusal_exact(
    struct purchase_test_run *run, const struct zcl_result *onion_retrieved,
    int fetches_before_onion)
{
    return run->onion_planned.ok && run->onion_commit.ok &&
        !onion_retrieved->ok && onion_retrieved->code == -78 &&
        run->fixture.fetches == fetches_before_onion;
}

static int purchase_test_onion_refusal_checks(struct purchase_test_run *run)
{
    int failures = 0;
    snprintf(run->onion_destination, sizeof(run->onion_destination),
             "%s/onion-purchased.bin", run->absolute_dir);
    int fetches_before_onion = run->fixture.fetches;
    struct market_purchase_view onion_download;
    struct zcl_result onion_retrieved = run->onion_ready
        ? market_purchase_retrieve(&run->runtime, run->onion_plan.plan_id,
                                   run->onion_destination, &onion_download)
        : ZCL_ERR(-1, "onion fixture could not be built");
    if (!purchase_test_onion_refusal_exact(
            run, &onion_retrieved, fetches_before_onion))
        printf("file_market purchase: onion detail planned=%d(%d %s) "
               "commit=%d(%d %s) retrieve=%d code=%d msg=%s fetches=%d/%d\n",
               run->onion_planned.ok, run->onion_planned.code,
               run->onion_planned.message,
               run->onion_commit.ok, run->onion_commit.code,
               run->onion_commit.message,
               onion_retrieved.ok, onion_retrieved.code,
               onion_retrieved.message, run->fixture.fetches,
               fetches_before_onion);
    PURCHASE_CHECK("onion-endpoint offer refuses delivery without a Tor client",
        purchase_test_onion_refusal_exact(
            run, &onion_retrieved, fetches_before_onion));
    return failures;
}

static bool purchase_test_onion_progress_durable(
    struct purchase_test_run *run,
    struct market_download_record *onion_progress)
{
    return db_market_download_find(
               &run->ndb, run->onion_plan.plan_id, onion_progress) &&
        onion_progress->state == MARKET_DOWNLOAD_FETCHING &&
        onion_progress->chunks_received == 0 &&
        onion_progress->bytes_received == 0 &&
        db_market_download_chunk_count(
            &run->ndb, run->onion_plan.plan_id) == 0;
}

static bool purchase_test_onion_budget_exact(
    struct purchase_test_run *run, const struct zcl_result *onion_limited,
    const struct market_purchase_view *onion_limited_view,
    struct market_download_record *onion_progress, int64_t observed_now_ms)
{
    return !onion_limited->ok && onion_limited->code == -76 &&
        run->fixture.onion_fetches == 1 &&
        run->fixture.onion_deadline_ms > observed_now_ms &&
        run->fixture.onion_deadline_ms - observed_now_ms <=
            MARKET_PURCHASE_RETRIEVE_BUDGET_MS &&
        purchase_test_onion_progress_durable(run, onion_progress) &&
        !onion_limited_view->destination_published &&
        access(run->onion_destination, F_OK) != 0;
}

static int purchase_test_onion_budget_check(struct purchase_test_run *run)
{
    int failures = 0;
    run->runtime.fetch_onion = purchase_fetch_onion_limited;
    run->runtime.fetch_onion_ctx = &run->fixture;
    run->runtime.onion_transport_ready = true;
    struct market_purchase_view onion_limited_view;
    memset(&onion_limited_view, 0, sizeof(onion_limited_view));
    struct zcl_result onion_limited = run->onion_ready
        ? market_purchase_retrieve(&run->runtime, run->onion_plan.plan_id,
                                   run->onion_destination, &onion_limited_view)
        : ZCL_ERR(-1, "onion fixture could not be built");
    struct market_download_record onion_progress;
    int64_t observed_now_ms = platform_time_monotonic_ms();
    PURCHASE_CHECK("onion retrieval budget leaves only durable progress",
        purchase_test_onion_budget_exact(
            run, &onion_limited, &onion_limited_view, &onion_progress,
            observed_now_ms));
    return failures;
}

int file_market_purchase_tests(void)
{
    int failures = 0;
    struct purchase_test_run run;
    memset(&run, 0, sizeof(run));
    bool ready = purchase_test_fixture_ready(&run);
    PURCHASE_CHECK("authenticated offer, identity, and encrypted fixture", ready);
    if (!ready) goto cleanup;

    purchase_test_runtime_init(&run);
    ready = purchase_test_funding_ready(&run);
    PURCHASE_CHECK("isolated payment funding is mature", ready);
    if (!ready) goto cleanup;

    failures += purchase_test_plan_checks(&run);
    failures += purchase_test_plan_replay_checks(&run);
    failures += purchase_test_commit_check(&run);
    failures += purchase_test_commit_replay_check(&run);
    failures += purchase_test_restart_claim_checks(&run);
    failures += purchase_test_pending_download_checks(&run);
    failures += purchase_test_budget_checks(&run);
    failures += purchase_test_publish_checks(&run);
    failures += purchase_test_replay_retrieve_check(&run);
    failures += purchase_test_state_conflict_refusals(&run);
    failures += purchase_test_policy_conflict_refusals(&run);
    failures += purchase_test_plan_refusals(&run);

    /* ── Phase B5: an onion-endpoint signed offer refuses delivery outright
     * when no embedded Tor client is running — never a clearnet fallback. ── */
    purchase_test_onion_fixture_prepare(&run);
    purchase_test_onion_plan_prepare(&run);
    failures += purchase_test_onion_refusal_checks(&run);
    failures += purchase_test_onion_budget_check(&run);

cleanup:
    if (run.ndb.open) node_db_close(&run.ndb);
    if (run.fixture.sim_ready) simnet_free(&run.fixture.sim);
    wallet_lock_reset_for_test();
    test_rm_rf(run.dir);
    return failures;
}
