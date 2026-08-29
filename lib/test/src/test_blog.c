/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "coins/undo.h"
#include "controllers/blog_controller.h"
#include "controllers/blog_post_controller.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "views/blog_post_view.h"
#include "services/blog_publication_service.h"
#include "models/app_event.h"
#include "models/block.h"
#include "models/db_txn.h"
#include "models/explorer_index.h"
#include "models/onion_announcement.h"
#include "models/tx_index.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "models/znam.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "keys/key_io.h"
#include "keys/key.h"
#include "script/standard.h"
#include "rpc/server.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include <unistd.h>

/* db_service owns two background pthreads (zcl_db_worker, zcl_db_ckpt) that
 * run for as long as the service is started. ASSERT()'s goto _test_next
 * (test/test_core.h) can leave the block that started the service on ANY
 * failing check between db_service_start() and the matching stop — and
 * test_blog_publication_slice keeps the service live across ~20 ASSERTs. A
 * skipped db_service_stop() leaves both threads running against a
 * stack-local struct db_service whose frame is about to be reused by the
 * rest of this test group's own execution (ecc_verify_destroy/ecc_stop and
 * process teardown all run on the SAME thread stack before _exit()). The
 * checkpoint thread wakes once a second and dereferences that freed memory
 * — usually harmless in isolation (the process exits before the 1 Hz timer
 * fires), but a fatal stack-use-after-return under full-suite parallel load,
 * where scheduling delays give the timer time to land mid-teardown. Attach
 * this as __attribute__((cleanup(...))) on the db_service local so EVERY
 * exit path — the normal one and any early ASSERT bailout — is guaranteed
 * to retire both threads before the frame is reused. Idempotent: a no-op
 * on the normal path, which already stops the service explicitly before
 * closing the node_db it wraps. See db_txn_auto_rollback (db_txn.h) for the
 * same pattern already used by this file's sibling, blog_publication.c. */
static void test_blog_db_service_cleanup(struct db_service *svc)
{
    app_runtime_set_current(NULL);
    db_service_stop(svc);
}

/* safe_path is static in blog_controller.c, so we replicate
 * the exact logic here for testing the validation rules. */
static bool test_safe_path(const char *path)
{
    if (!path || path[0] == '\0') return false;
    if (strstr(path, "..")) return false;
    if (path[0] == '/' && path[1] == '/') return false;
    return true;
}

static bool blog_test_address(const struct key_id *key_id,
                              char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params || !key_id || !out)
        return false;
    struct tx_destination destination;
    memset(&destination, 0, sizeof(destination));
    destination.type = DEST_KEY_ID;
    destination.id.key = *key_id;
    size_t pub_len = 0, script_len = 0;
    const unsigned char *pub = chain_params_base58_prefix(
        params, B58_PUBKEY_ADDRESS, &pub_len);
    const unsigned char *script = chain_params_base58_prefix(
        params, B58_SCRIPT_ADDRESS, &script_len);
    return encode_destination(&destination, pub, pub_len, script, script_len,
                              out, out_size);
}

static bool blog_test_save_name_marker(struct node_db *ndb, const char *owner,
                                       uint8_t marker)
{
    struct znam_entry name;
    memset(&name, 0, sizeof(name));
    snprintf(name.name, sizeof(name.name), "alice");
    snprintf(name.owner_address, sizeof(name.owner_address), "%s", owner);
    name.target_type = ZNAM_TYPE_TADDR;
    snprintf(name.target_value, sizeof(name.target_value), "%s", owner);
    memset(name.reg_txid, marker, sizeof(name.reg_txid));
    name.reg_height = 100;
    memset(name.last_update_txid, (uint8_t)(marker + 1),
           sizeof(name.last_update_txid));
    name.expiry_height = name.reg_height + ZNAM_REGISTRATION_TERM_BLOCKS;
    return db_znam_save(ndb, &name);
}

static bool blog_test_save_name(struct node_db *ndb, const char *owner)
{
    return blog_test_save_name_marker(ndb, owner, 0x31);
}

struct blog_anchor_fixture {
    struct node_db *ndb;
    struct wallet_identity_row identity;
    uint8_t initial_root[32];
    uint8_t reserved_root[32];
    uint8_t tip_hash[32];
    int32_t tip_height;
    int money_reads;
    int prepares;
    int publishes;
};

static struct zcl_result blog_anchor_fixture_money(
    void *opaque, const char *scope, struct wallet_money_snapshot *out)
{
    struct blog_anchor_fixture *fixture = opaque;
    if (!fixture || !out || strcmp(scope, "dev") != 0)
        return ZCL_ERR(-1, "Blog anchor fixture scope mismatch");
    memset(out, 0, sizeof(*out));
    out->identity = fixture->identity;
    snprintf(out->wallet_scope, sizeof(out->wallet_scope), "dev");
    snprintf(out->status, sizeof(out->status), "CURRENT");
    snprintf(out->reason, sizeof(out->reason), "fixture current");
    out->complete = true;
    out->confirmed_zat = 30000000;
    out->agent_available_zat = 5000000;
    out->intent_reserved_zat = vault_intent_reserved_total(
        fixture->ndb, "dev", fixture->identity.wallet_instance_id);
    out->tip_height = fixture->tip_height;
    memcpy(out->tip_hash, fixture->tip_hash, 32);
    memcpy(out->snapshot_root,
           fixture->money_reads++ == 0 ? fixture->initial_root
                                       : fixture->reserved_root, 32);
    return ZCL_OK;
}

static struct zcl_result blog_anchor_fixture_prepare(
    void *opaque, const uint8_t *script, size_t script_len,
    int64_t maximum_fee_zat, uint8_t *raw, size_t raw_capacity,
    size_t *raw_len, uint8_t txid[32], int64_t *actual_fee_zat)
{
    struct blog_anchor_fixture *fixture = opaque;
    if (!fixture || !script || script_len == 0 || raw_capacity < 8 ||
        maximum_fee_zat != 10000 || !raw || !raw_len || !txid ||
        !actual_fee_zat)
        return ZCL_ERR(-1, "Blog anchor fixture prepare mismatch");
    fixture->prepares++;
    memcpy(raw, "ZBLGTX1", 7);
    raw[7] = (uint8_t)script_len;
    *raw_len = 8;
    memset(txid, 0x61, 32);
    *actual_fee_zat = 1000;
    return ZCL_OK;
}

static struct zcl_result blog_anchor_fixture_publish(
    void *opaque, const uint8_t *raw, size_t raw_len,
    const uint8_t expected_txid[32])
{
    struct blog_anchor_fixture *fixture = opaque;
    uint8_t expected[32];
    memset(expected, 0x61, sizeof(expected));
    if (!fixture || !raw || raw_len != 8 ||
        memcmp(raw, "ZBLGTX1", 7) != 0 ||
        memcmp(expected_txid, expected, 32) != 0)
        return ZCL_ERR(-1, "Blog anchor fixture publish mismatch");
    fixture->publishes++;
    return ZCL_OK;
}

static struct db_block blog_test_block(uint8_t marker, int height,
                                       uint8_t solution[3])
{
    struct db_block block;
    memset(&block, 0, sizeof(block));
    memset(block.hash, marker, sizeof(block.hash));
    block.height = height;
    memset(block.prev_hash, marker - 1, sizeof(block.prev_hash));
    block.version = 4;
    memset(block.merkle_root, marker + 1, sizeof(block.merkle_root));
    block.time = 1700000000u + (uint32_t)height;
    block.bits = 0x1d00ffff;
    memset(block.nonce, marker + 2, sizeof(block.nonce));
    solution[0] = marker;
    solution[1] = marker + 1;
    solution[2] = marker + 2;
    block.solution = solution;
    block.solution_len = 3;
    memset(block.chain_work, marker + 3, sizeof(block.chain_work));
    block.status = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    block.file_num = 1;
    block.data_pos = height * 10;
    block.undo_pos = height * 10 + 1;
    block.num_tx = 1;
    return block;
}

static int test_blog_validation_contracts(void)
{
    int failures = 0;
    TEST("blog: canonical field validation rejects ambiguous content") {
        static const char valid_utf8[] = "Sovereign caf\xc3\xa9";
        static const char malformed_utf8[] = "bad\xc0\xaf";
        static const char bidi_override[] = "bad\xe2\x80\xaehtml";
        static const char delete_control[] = { 'b', 'a', 'd', 0x7f, 0 };
        char max_body[BLOG_BODY_MAX + 1];
        char oversized_body[BLOG_BODY_MAX + 2];
        memset(max_body, 'x', BLOG_BODY_MAX);
        max_body[BLOG_BODY_MAX] = 0;
        memset(oversized_body, 'x', sizeof(oversized_body));
        oversized_body[sizeof(oversized_body) - 1] = 0;
        uint8_t zero[32] = {0};
        uint8_t previous[32] = {0};
        previous[0] = 1;
        ASSERT(db_blog_slug_valid("c23-and-cryptography"));
        ASSERT(!db_blog_slug_valid("C23-and-cryptography"));
        ASSERT(!db_blog_slug_valid("leading-"));
        ASSERT(db_blog_title_valid(valid_utf8));
        ASSERT(!db_blog_title_valid("line\nbreak"));
        ASSERT(!db_blog_title_valid(malformed_utf8));
        ASSERT(!db_blog_title_valid(bidi_override));
        ASSERT(!db_blog_title_valid(delete_control));
        ASSERT(db_blog_body_valid("line one\nline two\tindented"));
        ASSERT(!db_blog_body_valid("carriage\rreturn"));
        ASSERT(db_blog_body_valid(max_body));
        ASSERT(!db_blog_body_valid(oversized_body));
        ASSERT(db_blog_sequence_shape_valid(1, zero));
        ASSERT(!db_blog_sequence_shape_valid(1, previous));
        ASSERT(db_blog_sequence_shape_valid(2, previous));
        ASSERT(!db_blog_sequence_shape_valid(2, zero));
        PASS();
    } _test_next:;
    return failures;
}

static int test_blog_publication_slice(void)
{
    int failures = 0;
    TEST("blog: MVC/ActiveRecord signed publication survives relay and reorg") {
        chain_params_select(CHAIN_MAIN);
        struct node_db publisher;
        struct node_db reader;
        memset(&publisher, 0, sizeof(publisher));
        memset(&reader, 0, sizeof(reader));
        ASSERT(node_db_open(&publisher, ":memory:"));
        ASSERT(node_db_open(&reader, ":memory:"));
        ASSERT(node_db_schema_version(&publisher) == NODE_DB_SCHEMA_LATEST);

        struct privkey key;
        privkey_init(&key);
        key.vch[31] = 1;
        key.fValid = true;
        key.fCompressed = true;
        struct pubkey pubkey;
        ASSERT(privkey_get_pubkey(&key, &pubkey));
        struct key_id key_id = pubkey_get_id(&pubkey);
        char owner[BLOG_AUTHOR_ADDRESS_MAX + 1];
        ASSERT(blog_test_address(&key_id, owner, sizeof(owner)));
        ASSERT(blog_test_save_name(&publisher, owner));
        ASSERT(blog_test_save_name(&reader, owner));

        /* struct wallet is megabytes (MAX_WALLET_TX=65536 wallet_tx entries
         * plus the key pool and spent set) — on the heap, per convention
         * used by every other wallet test (see test_wallet.c), not the
         * stack: a stack instance overflows the default 8 MiB ulimit -s. */
        struct wallet *wallet = zcl_calloc(1, sizeof(struct wallet),
                                           "test_blog_wallet");
        ASSERT(wallet != NULL);
        wallet_init(wallet);
        ASSERT(wallet_import_key(wallet, &key));
        size_t wallet_tx_count = wallet->num_wallet_tx;
        size_t wallet_spent_count = wallet->num_spent;

        struct zcl_app_event_scope_v1 scope;
        ASSERT(blog_publication_scope(&scope).ok);
        struct zcl_app_event_binding_test_spec_v1 spec;
        memset(&spec, 0, sizeof(spec));
        spec.struct_size = sizeof(spec);
        spec.operation = ZCL_APP_WALLET_OP_SIGN_EVENT_V1;
        spec.app_generation = 1;
        spec.grant_revision = 1;
        memset(spec.grant_id, 0x41, sizeof(spec.grant_id));
        memset(spec.manifest_digest, 0x42, sizeof(spec.manifest_digest));
        spec.scope = scope;
        memcpy(spec.author_key_id, key_id.id.data, sizeof(spec.author_key_id));
        spec.grant_active = true;
        struct zcl_app_event_signing_binding_v1 *binding = NULL;
        char why[256];
        ASSERT(zcl_app_event_signing_binding_v1_test_create(
            &spec, &binding, why, sizeof(why)));

        struct blog_publish_request request = {
            .blog_name = "alice",
            .slug = "first-post",
            .title = "Hello <script>alert(1)</script>",
            .body = "A sovereign post with <b>portable</b> content.",
            .sequence = 1,
            .created_at = UINT64_C(1700001234),
        };
        struct zcl_result result = blog_publication_validate_request(
            &publisher, &request);
        ASSERT(result.ok);
        struct blog_publish_request invalid_request = request;
        invalid_request.slug = "Not-Canonical";
        ASSERT(!blog_publication_validate_request(
            &publisher, &invalid_request).ok);
        invalid_request = request;
        invalid_request.body = "bad\rbody";
        ASSERT(!blog_publication_validate_request(
            &publisher, &invalid_request).ok);
        invalid_request = request;
        invalid_request.created_at = UINT64_MAX;
        ASSERT(!blog_publication_validate_request(
            &publisher, &invalid_request).ok);
        invalid_request = request;
        invalid_request.sequence = 2;
        ASSERT(!blog_publication_validate_request(
            &publisher, &invalid_request).ok);
        struct blog_publish_result published;
        result = blog_post_controller_create(
            &publisher, wallet, binding, &request, &published);
        ASSERT(result.ok);
        ASSERT(db_blog_post_count(&publisher, "alice") == 1);
        ASSERT(db_app_event_count(
            &publisher, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 1);
        ASSERT(wallet->num_wallet_tx == wallet_tx_count);
        ASSERT(wallet->num_spent == wallet_spent_count);

        char anchor_name[BLOG_NAME_MAX + 1];
        uint8_t anchor_event_id[32];
        ASSERT(blog_anchor_script_parse(published.anchor_script,
                                        published.anchor_script_len,
                                        anchor_name, anchor_event_id).ok);
        ASSERT(strcmp(anchor_name, "alice") == 0);
        ASSERT(memcmp(anchor_event_id, published.post.event_id, 32) == 0);

        /* A real plan is identity-bound and reserves the maximum fee before
         * returning. The service sees only signed transaction bytes through
         * ports; the wallet key never crosses this boundary. */
        struct blog_anchor_fixture anchor_fixture;
        memset(&anchor_fixture, 0, sizeof(anchor_fixture));
        anchor_fixture.ndb = &publisher;
        anchor_fixture.tip_height = 420;
        memset(anchor_fixture.tip_hash, 0x44,
               sizeof(anchor_fixture.tip_hash));
        memset(anchor_fixture.initial_root, 0x31,
               sizeof(anchor_fixture.initial_root));
        memset(anchor_fixture.reserved_root, 0x32,
               sizeof(anchor_fixture.reserved_root));
        const struct chain_params *params = chain_params_get();
        ASSERT(params != NULL);
        ASSERT(wallet_identity_ensure(
            &publisher, params->consensus.hashGenesisBlock.data, "dev",
            &anchor_fixture.identity));
        wallet_lock_reset_for_test();
        wallet_lock_note_encrypted_at_rest();
        ASSERT(wallet_lock_unlock(NULL, NULL, "blog-anchor-test").ok);
        struct blog_anchor_runtime anchor_runtime;
        memset(&anchor_runtime, 0, sizeof(anchor_runtime));
        anchor_runtime.node_db = &publisher;
        anchor_runtime.read_money = blog_anchor_fixture_money;
        anchor_runtime.money_ctx = &anchor_fixture;
        anchor_runtime.prepare = blog_anchor_fixture_prepare;
        anchor_runtime.prepare_ctx = &anchor_fixture;
        anchor_runtime.publish = blog_anchor_fixture_publish;
        anchor_runtime.publish_ctx = &anchor_fixture;
        anchor_runtime.tip_height = anchor_fixture.tip_height;
        memcpy(anchor_runtime.tip_hash, anchor_fixture.tip_hash, 32);
        anchor_runtime.maximum_fee_zat = 10000;
        anchor_runtime.now_unix = 1700002000;
        struct blog_anchor_request anchor_request;
        memset(&anchor_request, 0, sizeof(anchor_request));
        snprintf(anchor_request.wallet_scope,
                 sizeof(anchor_request.wallet_scope), "dev");
        snprintf(anchor_request.blog_name, sizeof(anchor_request.blog_name),
                 "alice");
        memcpy(anchor_request.event_id, published.post.event_id, 32);
        snprintf(anchor_request.idempotency_key,
                 sizeof(anchor_request.idempotency_key), "alice-post-1");
        struct blog_anchor_transaction_result anchor_plan;
        result = blog_publication_anchor_plan(
            &anchor_runtime, &anchor_request, &anchor_plan);
        ASSERT(result.ok && anchor_plan.event_verified &&
               !anchor_plan.broadcast &&
               strcmp(anchor_plan.wallet_scope, "dev") == 0);
        ASSERT(anchor_plan.maximum_fee_zat == 10000 &&
               anchor_plan.reserved_zat == 10000 &&
               anchor_plan.actual_fee_zat == 1000);
        ASSERT(anchor_plan.anchor_script_len == published.anchor_script_len);
        ASSERT(memcmp(anchor_plan.anchor_script, published.anchor_script,
                      published.anchor_script_len) == 0);
        ASSERT(anchor_fixture.prepares == 1 &&
               vault_intent_reserved_total(
                   &publisher, "dev",
                   anchor_fixture.identity.wallet_instance_id) == 10000);
        struct blog_anchor_transaction_result anchor_replay;
        ASSERT(blog_publication_anchor_plan(
            &anchor_runtime, &anchor_request, &anchor_replay).ok);
        ASSERT(anchor_replay.idempotent_replay &&
               memcmp(anchor_replay.plan_id, anchor_plan.plan_id, 32) == 0 &&
               anchor_fixture.prepares == 1);
        result = blog_publication_anchor_commit(
            &anchor_runtime, "prod", anchor_plan.plan_id, &anchor_replay);
        ASSERT(!result.ok && anchor_fixture.publishes == 0);
        result = blog_publication_anchor_commit(
            &anchor_runtime, "dev", anchor_plan.plan_id, &anchor_replay);
        ASSERT(result.ok && anchor_replay.broadcast &&
               anchor_fixture.publishes == 1);
        ASSERT(blog_publication_anchor_commit(
            &anchor_runtime, "dev", anchor_plan.plan_id, &anchor_replay).ok);
        ASSERT(anchor_replay.idempotent_replay &&
               anchor_fixture.publishes == 1);

        uint8_t trailing[BLOG_ANCHOR_SCRIPT_MAX + 1];
        memcpy(trailing, published.anchor_script, published.anchor_script_len);
        trailing[published.anchor_script_len] = 0;
        ASSERT(!blog_anchor_script_parse(trailing,
                                         published.anchor_script_len + 1,
                                         anchor_name, anchor_event_id).ok);
        uint8_t nonminimal[BLOG_ANCHOR_SCRIPT_MAX + 1];
        nonminimal[0] = 0x6a;
        nonminimal[1] = 0x4c; /* PUSHDATA1 for a four-byte field is nonminimal. */
        nonminimal[2] = 4;
        memcpy(nonminimal + 3, published.anchor_script + 2,
               published.anchor_script_len - 2);
        ASSERT(!blog_anchor_script_parse(nonminimal,
                                         published.anchor_script_len + 1,
                                         anchor_name, anchor_event_id).ok);

        uint8_t payload[BLOG_BODY_MAX + BLOG_TITLE_MAX + BLOG_NAME_MAX +
                        BLOG_SLUG_MAX + 32];
        struct zcl_app_signed_event_v1 exported;
        result = blog_publication_export_event(
            &published.post, payload, sizeof(payload), &exported);
        ASSERT(result.ok);

        /* The generic model never trusts scope carried by the event itself. */
        struct node_db scoped_reader;
        ASSERT(node_db_open(&scoped_reader, ":memory:"));
        struct db_app_event scoped_event;
        memset(&scoped_event, 0, sizeof(scoped_event));
        scoped_event.event = exported;
        scoped_event.received_at = INT64_C(1700001235);
        struct zcl_app_event_scope_v1 wrong_scope = scope;
        snprintf(wrong_scope.topic, sizeof(wrong_scope.topic), "%s",
                 "wrong.topic.v1");
        ASSERT(!db_app_event_save(
            &scoped_reader, &scoped_event, &wrong_scope));
        ASSERT(db_app_event_count(
            &scoped_reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 0);
        node_db_close(&scoped_reader);

        /* Import owns one exclusive transaction. It must never join an
         * unrelated caller merely because the connection's tx bit is set. */
        struct node_db nested_reader;
        ASSERT(node_db_open(&nested_reader, ":memory:"));
        ASSERT(blog_test_save_name(&nested_reader, owner));
        struct db_txn *outer = db_txn_begin(&nested_reader, "blog.test.outer");
        ASSERT(outer != NULL);
        struct db_blog_post nested_post;
        ASSERT(!blog_post_controller_import(
            &nested_reader, &exported, &nested_post).ok);
        ASSERT(db_blog_post_count(&nested_reader, "alice") == 0);
        ASSERT(db_app_event_count(
            &nested_reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 0);
        db_txn_rollback(outer);
        db_txn_auto_rollback(&outer);
        node_db_close(&nested_reader);

        struct db_blog_post oversized_signature = published.post;
        oversized_signature.signature_len = BLOG_SIGNATURE_MAX + 1;
        struct zcl_app_signed_event_v1 cleared_event;
        memset(&cleared_event, 0xa5, sizeof(cleared_event));
        result = blog_publication_export_event(
            &oversized_signature, payload, sizeof(payload), &cleared_event);
        ASSERT(!result.ok);
        ASSERT(cleared_event.signature_len == 0);
        ASSERT(cleared_event.event_id[0] == 0);
        struct db_blog_post imported;
        result = blog_post_controller_import(&reader, &exported, &imported);
        ASSERT(result.ok);
        ASSERT(memcmp(imported.event_id, published.post.event_id, 32) == 0);
        ASSERT(strcmp(imported.body, request.body) == 0);
        ASSERT(db_app_event_count(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 1);
        uint8_t stored_payload[sizeof(payload)];
        struct db_app_event stored_event;
        ASSERT(db_app_event_find(
            &reader, exported.event_id, &scope, &stored_event,
            stored_payload, sizeof(stored_payload)));
        ASSERT(stored_event.receive_cursor > 0);
        ASSERT(stored_event.received_at > 0);
        ASSERT(stored_event.event.payload.len == exported.payload.len);
        ASSERT(memcmp(stored_event.event.payload.data,
                      exported.payload.data, exported.payload.len) == 0);
        ASSERT(memcmp(stored_event.event.signature,
                      exported.signature, exported.signature_len) == 0);
        uint8_t short_payload[1];
        struct db_app_event short_event;
        ASSERT(!db_app_event_find(
            &reader, exported.event_id, &scope, &short_event,
            short_payload, sizeof(short_payload)));
        struct db_blog_post replayed;
        ASSERT(blog_post_controller_import(
            &reader, &exported, &replayed).ok);
        ASSERT(db_app_event_count(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 1);

        struct zcl_app_signed_event_v1 tampered = exported;
        uint8_t tampered_payload[sizeof(payload)];
        memcpy(tampered_payload, payload, exported.payload.len);
        tampered_payload[exported.payload.len - 1] ^= 1;
        tampered.payload.data = tampered_payload;
        struct db_blog_post rejected;
        result = blog_post_controller_import(&reader, &tampered, &rejected);
        ASSERT(!result.ok);
        ASSERT(db_blog_post_count(&reader, "alice") == 1);
        ASSERT(db_app_event_count(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 1);

        /* Valid equivocations are retained by event_id, not discarded by
         * arrival order. The slug route deterministically selects the lowest
         * event ID while the explicit previous-post relationship remains
         * queryable for every fork. */
        struct blog_publish_request fork_request = {
            .blog_name = "alice",
            .slug = "second-post",
            .title = "A deterministic fork",
            .body = "Variant A",
            .sequence = 2,
            .created_at = UINT64_C(1700002234),
        };
        memcpy(fork_request.previous_event_id, published.post.event_id, 32);
        struct blog_publish_result fork_a, fork_b;
        result = blog_post_controller_create(
            &publisher, wallet, binding, &fork_request, &fork_a);
        ASSERT(result.ok);
        fork_request.body = "Variant B";
        fork_request.created_at++;
        result = blog_post_controller_create(
            &publisher, wallet, binding, &fork_request, &fork_b);
        ASSERT(result.ok);
        ASSERT(memcmp(fork_a.post.event_id, fork_b.post.event_id, 32) != 0);

        uint8_t fork_payload_a[sizeof(payload)], fork_payload_b[sizeof(payload)];
        struct zcl_app_signed_event_v1 fork_event_a, fork_event_b;
        ASSERT(blog_publication_export_event(
            &fork_a.post, fork_payload_a, sizeof(fork_payload_a),
            &fork_event_a).ok);
        ASSERT(blog_publication_export_event(
            &fork_b.post, fork_payload_b, sizeof(fork_payload_b),
            &fork_event_b).ok);
        struct db_blog_post imported_fork_a, imported_fork_b;
        ASSERT(blog_post_controller_import(
            &reader, &fork_event_a, &imported_fork_a).ok);
        ASSERT(blog_post_controller_import(
            &reader, &fork_event_b, &imported_fork_b).ok);
        struct db_blog_post previous;
        ASSERT(db_blog_post_previous(&reader, &imported_fork_a, &previous));
        ASSERT(memcmp(previous.event_id, imported.event_id, 32) == 0);
        ASSERT(db_app_event_count(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC) == 3);
        uint8_t stored_fork_payload[sizeof(payload)];
        struct db_app_event stored_fork;
        ASSERT(db_app_event_find(
            &reader, fork_event_a.event_id, &scope, &stored_fork,
            stored_fork_payload, sizeof(stored_fork_payload)));
        uint8_t stored_previous_payload[sizeof(payload)];
        struct db_app_event stored_previous;
        ASSERT(db_app_event_previous(
            &reader, &stored_fork, &scope, &stored_previous,
            stored_previous_payload, sizeof(stored_previous_payload)));
        ASSERT(memcmp(stored_previous.event.event_id,
                      exported.event_id, 32) == 0);
        struct db_app_event_ref successors[4];
        ASSERT(db_app_event_successors(
            &reader, &stored_previous, &scope, successors, 4) == 2);
        ASSERT(memcmp(successors[0].event_id,
                      successors[1].event_id, 32) < 0);
        struct db_app_event_ref inventory[4];
        ASSERT(db_app_event_topic_after(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC, 0,
            inventory, 4) == 3);
        ASSERT(inventory[0].receive_cursor < inventory[1].receive_cursor);
        ASSERT(db_app_event_topic_after(
            &reader, BLOG_APP_ID, BLOG_EVENT_TOPIC,
            inventory[1].receive_cursor, inventory, 4) == 1);

        struct node_db reverse_reader;
        memset(&reverse_reader, 0, sizeof(reverse_reader));
        ASSERT(node_db_open(&reverse_reader, ":memory:"));
        ASSERT(blog_test_save_name(&reverse_reader, owner));
        struct db_blog_post reverse_import;
        ASSERT(blog_post_controller_import(
            &reverse_reader, &exported, &reverse_import).ok);
        ASSERT(blog_post_controller_import(
            &reverse_reader, &fork_event_b, &reverse_import).ok);
        ASSERT(blog_post_controller_import(
            &reverse_reader, &fork_event_a, &reverse_import).ok);
        struct db_blog_post selected_forward, selected_reverse;
        ASSERT(db_blog_post_find_by_slug(
            &reader, "alice", "second-post", &selected_forward));
        ASSERT(db_blog_post_find_by_slug(
            &reverse_reader, "alice", "second-post", &selected_reverse));
        ASSERT(memcmp(selected_forward.event_id,
                      selected_reverse.event_id, 32) == 0);
        struct db_blog_post all_forks[4];
        ASSERT(db_blog_post_list(&reader, "alice", all_forks, 4) == 3);
        ASSERT(db_blog_post_list(
            &reverse_reader, "alice", all_forks, 4) == 3);
        node_db_close(&reverse_reader);

        struct blog_projection_observation observation;
        result = blog_publication_observe_projection(
            &reader, imported.event_id, &observation);
        ASSERT(result.ok && !observation.observed);
        ASSERT(observation.projection_only);
        ASSERT(!observation.served_frontier_proven);

        uint8_t solution_a[3];
        struct db_block block_a = blog_test_block(0x51, 500, solution_a);
        ASSERT(db_block_save_canonical(&reader, &block_a));
        struct db_tx_index anchor_tx;
        memset(&anchor_tx, 0, sizeof(anchor_tx));
        memset(anchor_tx.txid, 0x71, sizeof(anchor_tx.txid));
        memcpy(anchor_tx.block_hash, block_a.hash, 32);
        anchor_tx.block_height = block_a.height;
        anchor_tx.tx_index = 0;
        anchor_tx.file_num = block_a.file_num;
        anchor_tx.file_pos = block_a.data_pos;
        ASSERT(db_tx_save(&reader, &anchor_tx));
        ASSERT(db_op_return_save(&reader, anchor_tx.txid,
                                 anchor_tx.block_height,
                                 published.anchor_script,
                                 published.anchor_script_len, false));
        result = blog_publication_observe_projection(
            &reader, imported.event_id, &observation);
        ASSERT(result.ok && observation.observed);
        ASSERT(observation.receipt.status == BLOG_PUBLICATION_CONFIRMED);
        ASSERT(!observation.served_frontier_proven);
        struct db_blog_publication_receipt receipts[2];
        ASSERT(db_blog_post_publication_receipts(
            &reader, imported.event_id, receipts, 2) == 1);
        struct db_blog_post receipt_parent;
        ASSERT(db_blog_publication_receipt_post(
            &reader, &receipts[0], &receipt_parent));
        ASSERT(memcmp(receipt_parent.event_id, imported.event_id, 32) == 0);
        struct db_blog_publication_receipt drifted_receipt = receipts[0];
        drifted_receipt.author_key_id[0] ^= 1;
        ASSERT(!db_blog_publication_receipt_save(
            &reader, &drifted_receipt));

        struct blog_post_page page;
        int show_changes_before = sqlite3_total_changes(reader.db);
        result = blog_post_controller_show(
            &reader, "alice", "first-post", &page);
        ASSERT(result.ok && page.has_receipt && page.content_available);
        ASSERT(sqlite3_total_changes(reader.db) == show_changes_before);
        uint8_t html[65536];
        size_t html_len = blog_post_view_render(&page, html, sizeof(html));
        ASSERT(html_len > 0);
        ASSERT(strstr((char *)html, "&lt;script&gt;") != NULL);
        ASSERT(strstr((char *)html, "<script>") == NULL);
        ASSERT(strstr((char *)html, "projection-confirmed") != NULL);
        ASSERT(strstr((char *)html, "served-frontier proof: pending") != NULL);
        ASSERT(strstr((char *)html, "Historical owner-epoch") != NULL);
        struct blog_post_page max_page = page;
        memset(max_page.post.body, 'x', BLOG_BODY_MAX);
        max_page.post.body[BLOG_BODY_MAX] = 0;
        ASSERT(blog_post_view_render(
            &max_page, html, sizeof(html)) > BLOG_BODY_MAX);

        struct db_service db_service
            __attribute__((cleanup(test_blog_db_service_cleanup)));
        struct app_runtime_context runtime;
        memset(&runtime, 0, sizeof(runtime));
        db_service_init(&db_service);
        ASSERT(db_service_attach(&db_service, &reader));
        ASSERT(db_service_start(&db_service));
        runtime.db_service = &db_service;
        app_runtime_set_current(&runtime);
        uint8_t site[131072];
        int public_read_changes_before = sqlite3_total_changes(reader.db);
        memset(site, 0, sizeof(site));
        size_t site_len = blog_site_handle_request(
            "GET", "/blog", NULL, 0, site, sizeof(site));
        ASSERT(site_len > 0 && strstr((char *)site, "200 OK") != NULL);
        ASSERT(strstr((char *)site, "/blog/alice/first-post") != NULL);
        site_len = blog_site_handle_request(
            "GET", "/blog/alice/first-post", NULL, 0,
            site, sizeof(site));
        ASSERT(site_len > 0 && strstr((char *)site, "200 OK") != NULL);
        ASSERT(strstr((char *)site, "&lt;script&gt;") != NULL);
        memset(site, 0, sizeof(site));
        site_len = blog_site_handle_request(
            "HEAD", "/blog/alice/first-post", NULL, 0,
            site, sizeof(site));
        ASSERT(site_len > 0 && strstr((char *)site, "200 OK") != NULL);
        ASSERT(strstr((char *)site, "<!doctype html>") == NULL);
        site_len = blog_site_handle_request(
            "POST", "/blog", NULL, 0, site, sizeof(site));
        ASSERT(site_len > 0 && strstr((char *)site, "405 Method Not Allowed") != NULL);
        site_len = blog_site_handle_request(
            "GET", "/blogger", NULL, 0, site, sizeof(site));
        ASSERT(site_len > 0 && strstr((char *)site, "404 Not Found") != NULL);
        ASSERT(sqlite3_total_changes(reader.db) == public_read_changes_before);
        app_runtime_set_current(NULL);
        db_service_stop(&db_service);

        /* A transfer must not be mislabeled as current ownership. Existing
         * receipt identity remains frozen, while the UI explicitly keeps the
         * historical owner-epoch proof pending. */
        struct privkey successor_key;
        privkey_init(&successor_key);
        successor_key.vch[31] = 2;
        successor_key.fValid = true;
        successor_key.fCompressed = true;
        struct pubkey successor_pubkey;
        ASSERT(privkey_get_pubkey(&successor_key, &successor_pubkey));
        struct key_id successor_id = pubkey_get_id(&successor_pubkey);
        char successor_owner[BLOG_AUTHOR_ADDRESS_MAX + 1];
        ASSERT(blog_test_address(
            &successor_id, successor_owner, sizeof(successor_owner)));
        ASSERT(blog_test_save_name_marker(
            &reader, successor_owner, 0x81));

        uint8_t solution_b[3];
        struct db_block block_b = blog_test_block(0x52, 500, solution_b);
        ASSERT(db_block_save_canonical(&reader, &block_b));
        result = blog_publication_observe_projection(
            &reader, imported.event_id, &observation);
        ASSERT(result.ok && observation.observed);
        ASSERT(observation.receipt.status == BLOG_PUBLICATION_ORPHANED);
        show_changes_before = sqlite3_total_changes(reader.db);
        result = blog_post_controller_show(
            &reader, "alice", "first-post", &page);
        ASSERT(result.ok && page.has_receipt);
        ASSERT(page.receipt.status == BLOG_PUBLICATION_ORPHANED);
        ASSERT(sqlite3_total_changes(reader.db) == show_changes_before);

        struct db_blog_post invalid = imported;
        snprintf(invalid.slug, sizeof(invalid.slug), "Not-Canonical");
        struct ar_errors errors;
        ASSERT(!db_blog_post_validate(&invalid, &errors));

        zcl_app_event_signing_binding_v1_test_destroy(binding);
        wallet_free(wallet);
        free(wallet);
        node_db_close(&reader);
        node_db_close(&publisher);
        PASS();
    } _test_next:;
    return failures;
}

int test_blog(void)
{
    int failures = 0;

    printf("blog: safe_path rejects .. traversal... ");
    {
        bool ok = !test_safe_path("../etc/passwd");
        ok = ok && !test_safe_path("foo/../bar");
        ok = ok && !test_safe_path("..hidden");
        ok = ok && !test_safe_path("..");
        ok = ok && !test_safe_path("a/b/../../c");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: safe_path rejects // prefix... ");
    {
        bool ok = !test_safe_path("//etc/passwd");
        ok = ok && !test_safe_path("//");
        ok = ok && !test_safe_path("///foo");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: safe_path accepts valid paths... ");
    {
        bool ok = test_safe_path("index.html");
        ok = ok && test_safe_path("/about");
        ok = ok && test_safe_path("posts/hello.html");
        ok = ok && test_safe_path("a/b/c.css");
        ok = ok && test_safe_path("style.css");
        /* Empty and NULL must be rejected */
        ok = ok && !test_safe_path("");
        ok = ok && !test_safe_path(NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: discover_onion_peers with empty/missing data... ");
    {
        struct onion_peer peers[10];
        bool ok = true;
        /* Every datadir handed to production code is a per-run scratch dir
         * under ./test-tmp, never "." — see the block comment below. */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_disc", "peers");
        /* NULL checks */
        int found = blog_discover_onion_peers(NULL, peers, 10);
        ok = ok && (found == 0);
        found = blog_discover_onion_peers(dir, NULL, 10);
        ok = ok && (found == 0);
        found = blog_discover_onion_peers(dir, peers, 0);
        ok = ok && (found == 0);
        /* A missing database is inert: discovery returns no peers and must
         * not create node.db or run the boot/schema ceremony.
         * test-tmp/-namespaced + pid-tagged (test_make_tmpdir), not a
         * bare literal in the repo working tree: a raw mkdtemp() template
         * rooted at "." drops its directory directly into the checkout
         * root, where a crash mid-test (or any exit path that skips
         * test_cleanup_tmpdir) leaves debris that pollutes `git status`
         * and the source-identity inventory for every other concurrent
         * consumer of this checkout. */
        found = blog_discover_onion_peers(dir, peers, 10);
        ok = ok && (found == 0);
        char db_path[512];
        int db_path_len = snprintf(db_path, sizeof(db_path), "%s/node.db",
                                   dir);
        ok = ok && db_path_len > 0 && (size_t)db_path_len < sizeof(db_path) &&
             access(db_path, F_OK) != 0;
        if (ok) {
            int wal_len = snprintf(db_path, sizeof(db_path), "%s/node.db-wal",
                                   dir);
            ok = wal_len > 0 && (size_t)wal_len < sizeof(db_path) &&
                 access(db_path, F_OK) != 0;
        }
        if (ok) {
            int shm_len = snprintf(db_path, sizeof(db_path), "%s/node.db-shm",
                                   dir);
            ok = shm_len > 0 && (size_t)shm_len < sizeof(db_path) &&
                 access(db_path, F_OK) != 0;
        }
        test_cleanup_tmpdir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: serve returns 404 for missing files... ");
    {
        /* Use a temp directory with no blog/ subdirectory */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_serve", "404");
        bool ok = true;
        {
            char out[4096];
            memset(out, 0, sizeof(out));
            size_t len = blog_serve(dir, "/nonexistent_page", out, sizeof(out));
            if (len < sizeof(out)) out[len] = '\0';
            ok = ok && (len > 0);
            ok = ok && (strstr(out, "404") != NULL);
            ok = ok && (strstr(out, "Not Found") != NULL);

            /* Also test with a deeper path */
            memset(out, 0, sizeof(out));
            len = blog_serve(dir, "/deep/nested/path.html", out, sizeof(out));
            if (len < sizeof(out)) out[len] = '\0';
            ok = ok && (len > 0);
            ok = ok && (strstr(out, "404") != NULL);

            test_cleanup_tmpdir(dir);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: serve returns 403 for path traversal... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_serve", "403");
        bool ok = true;
        {
            char out[4096];
            memset(out, 0, sizeof(out));
            size_t len = blog_serve(dir, "/../../../etc/passwd",
                                    out, sizeof(out));
            if (len < sizeof(out)) out[len] = '\0';
            ok = ok && (len > 0);
            ok = ok && (strstr(out, "403") != NULL);
            test_cleanup_tmpdir(dir);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: serve handles NULL/empty inputs... ");
    {
        char out[4096];
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_serve", "nullin");
        /* NULL path */
        size_t len = blog_serve(dir, NULL, out, sizeof(out));
        bool ok = (len == 0);
        /* NULL output buffer */
        len = blog_serve(dir, "/index.html", NULL, sizeof(out));
        ok = ok && (len == 0);
        /* Buffer too small */
        len = blog_serve(dir, "/index.html", out, 100);
        ok = ok && (len == 0);
        test_cleanup_tmpdir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: node registry genesis builds valid output... ");
    {
        uint8_t buf[256];
        size_t len = blog_build_node_registry_genesis(buf, sizeof(buf));
        /* Should produce non-empty OP_RETURN script */
        bool ok = (len > 0 && len < sizeof(buf));
        if (ok) printf("OK (%zu bytes)\n", len);
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("blog: auto_announce_onion rejects invalid input... ");
    {
        /* "no_suffix" clears the argument guards, so the call reaches
         * node_db_open("<datadir>/node.db") — which CREATES the file —
         * before the .onion-suffix check rejects it. A per-run scratch
         * datadir keeps that side effect inside ./test-tmp. */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_ann", "reject");
        bool ok = !blog_auto_announce_onion(NULL, "test.onion");
        ok = ok && !blog_auto_announce_onion(dir, NULL);
        ok = ok && !blog_auto_announce_onion(dir, "");
        ok = ok && !blog_auto_announce_onion(dir, "no_suffix");
        test_cleanup_tmpdir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("blog: auto_announce_onion announces new address... ");
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "blog_ann", "onion");
        bool ok = true;
        {
            const char *addr1 =
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
            ok = ok && blog_auto_announce_onion(dir, addr1);

            /* Second call with same address returns false (no re-announce) */
            ok = ok && !blog_auto_announce_onion(dir, addr1);

            /* Different address announces successfully */
            const char *addr2 =
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion";
            ok = ok && blog_auto_announce_onion(dir, addr2);

            char db_path[1024];
            snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
            struct node_db ndb;
            memset(&ndb, 0, sizeof(ndb));
            ok = ok && node_db_open(&ndb, db_path);
            if (ok) {
                struct db_onion_announcement rows[4];
                memset(rows, 0, sizeof(rows));
                int count = db_onion_announcement_recent(&ndb, rows, 4);
                ok = ok && (count >= 2);
                ok = ok && db_onion_announcement_exists(&ndb, addr2);
                ok = ok && rows[0].script_hex[0] != '\0';
                node_db_close(&ndb);
            }

            /* Clean up: remove node.db and tmpdir */
            test_cleanup_tmpdir(dir);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    failures += test_blog_validation_contracts();
    failures += test_blog_publication_slice();
    return failures;
}
