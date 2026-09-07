/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_event_sync — a dapp's signed AppEvent rows crossing from one node
 * to another, and every way that crossing is refused.
 *
 * Two independent node databases, driven through the REAL pull wire in wire
 * order, the same standard test_fleet_board_two_nodes holds itself to: node
 * A never hands node B a struct. B asks with bytes it encoded, A answers
 * with bytes it encoded out of its own table, and every field B ends up
 * holding, B decoded and verified.
 *
 * What is pinned here:
 *   - three signed events cross, and what B stores is BYTE-IDENTICAL to
 *     what A signed (compared as canonical signed frames, not field by
 *     field, so an encoder that lost a field would still fail);
 *   - a second pull carries nothing and stores nothing;
 *   - one tampered byte refuses by name, at the row it was in, and nothing
 *     after that row is stored — a tampered FIRST row leaves the frontier
 *     exactly where it was;
 *   - an event from another topic in an otherwise good answer is refused as
 *     out of scope before any signature work is spent on it;
 *   - the batch bound stops an answer at ZCL_APP_SYNC_BATCH_MAX rows and
 *     the next pull continues from there;
 *   - no peer and no session both refuse, and neither stores anything.
 *
 * Clocks are injected. `received_at` is a fixed number this file chooses,
 * because arrival order is local evidence and no assertion here may depend
 * on when the test happened to run.
 */

#include "test/test_core.h"

#include "appsync/app_event_sync.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include "models/app_event.h"
#include "models/database.h"
#include "services/app_event_sync_service.h"
#include "wallet/wallet.h"

#include <stdlib.h>
#include <string.h>

/* The fixed arrival time every save in this file is stamped with. */
#define SYNC_TEST_RECEIVED_AT INT64_C(1700009999)

/* A chain id that is not any live network's, so a row from this file could
 * never be mistaken for one that belongs on a chain. */
static const uint8_t g_sync_chain_id[32] = {
    0x5a, 0x43, 0x4c, 0x53, 0x59, 0x4e, 0x43, 0x01,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static struct zcl_app_event_scope_v1 sync_test_scope(const char *topic)
{
    struct zcl_app_event_scope_v1 scope;
    memset(&scope, 0, sizeof(scope));
    scope.struct_size = sizeof(scope);
    (void)snprintf(scope.app_id, sizeof(scope.app_id), "%s", "social");
    (void)snprintf(scope.topic, sizeof(scope.topic), "%s", topic);
    memcpy(scope.chain_id, g_sync_chain_id, sizeof(scope.chain_id));
    scope.max_event_bytes = 65536;
    return scope;
}

/* One wallet holding one key, plus a signing binding for one scope. The
 * binding constructor is the test-only stand-in for the future Core wallet
 * broker; there is deliberately no production constructor. */
struct sync_test_signer {
    struct wallet *wallet;
    struct zcl_app_event_signing_binding_v1 *binding;
    struct key_id key_id;
};

static bool sync_test_signer_open(struct sync_test_signer *out,
                                  const struct zcl_app_event_scope_v1 *scope,
                                  uint8_t key_byte)
{
    memset(out, 0, sizeof(*out));
    struct privkey key;
    privkey_init(&key);
    key.vch[31] = key_byte;
    key.fValid = true;
    key.fCompressed = true;
    struct pubkey pubkey;
    if (!privkey_get_pubkey(&key, &pubkey))
        return false;
    out->key_id = pubkey_get_id(&pubkey);
    out->wallet = zcl_calloc(1, sizeof(struct wallet), "sync_test_wallet");
    if (!out->wallet)
        return false;
    wallet_init(out->wallet);
    if (!wallet_import_key(out->wallet, &key))
        return false;

    struct zcl_app_event_binding_test_spec_v1 spec;
    memset(&spec, 0, sizeof(spec));
    spec.struct_size = sizeof(spec);
    spec.operation = ZCL_APP_WALLET_OP_SIGN_EVENT_V1;
    spec.app_generation = 1;
    spec.grant_revision = 1;
    memset(spec.grant_id, 0x31, sizeof(spec.grant_id));
    memset(spec.manifest_digest, 0x32, sizeof(spec.manifest_digest));
    spec.scope = *scope;
    memcpy(spec.author_key_id, out->key_id.id.data,
           sizeof(spec.author_key_id));
    spec.grant_active = true;
    char why[256];
    return zcl_app_event_signing_binding_v1_test_create(&spec, &out->binding,
                                                        why, sizeof(why));
}

static void sync_test_signer_close(struct sync_test_signer *s)
{
    if (s->binding)
        zcl_app_event_signing_binding_v1_test_destroy(s->binding);
    s->binding = NULL;
    free(s->wallet);
    s->wallet = NULL;
}

/* One chained event. `payload` must outlive `out`: the signed event borrows
 * it, which is the same ownership rule the model and the wire both use. */
static bool sync_test_sign(struct sync_test_signer *s, uint64_t sequence,
                           const uint8_t previous_event_id[32],
                           const uint8_t *payload, size_t payload_len,
                           struct zcl_app_signed_event_v1 *out)
{
    struct zcl_app_event_intent_v1 intent;
    memset(&intent, 0, sizeof(intent));
    intent.struct_size = sizeof(intent);
    intent.kind = 1;
    intent.sequence = sequence;
    intent.created_at = UINT64_C(1700000000) + sequence;
    if (previous_event_id)
        memcpy(intent.previous_event_id, previous_event_id, 32);
    intent.payload.data = payload;
    intent.payload.len = payload_len;
    char why[256];
    return zcl_app_signed_event_v1_sign_wallet(&intent, s->binding, s->wallet,
                                               out, why, sizeof(why));
}

static bool sync_test_store(struct node_db *ndb,
                            const struct zcl_app_event_scope_v1 *scope,
                            const struct zcl_app_signed_event_v1 *event)
{
    struct db_app_event record;
    memset(&record, 0, sizeof(record));
    record.event = *event;
    record.received_at = SYNC_TEST_RECEIVED_AT;
    return db_app_event_save(ndb, &record, scope);
}

/* The canonical signed frame of one event: the unsigned bytes, the
 * little-endian signature length, and the signature. Byte identity across
 * two nodes is compared on THIS, because it is exactly what was signed. */
static size_t sync_test_frame(const struct zcl_app_signed_event_v1 *event,
                              uint8_t *out, size_t cap)
{
    char why[256];
    size_t len = 0;
    if (!zcl_app_signed_event_v1_canonical_unsigned(event, out, cap, &len,
                                                    why, sizeof(why)))
        return 0;
    if (cap - len < 2u + event->signature_len)
        return 0;
    out[len] = (uint8_t)event->signature_len;
    out[len + 1] = (uint8_t)(event->signature_len >> 8);
    memcpy(out + len + 2, event->signature, event->signature_len);
    return len + 2 + event->signature_len;
}

/* ── the loopback peer ───────────────────────────────────────────────── */

/* A peer that is one other node's SERVE, reached with the same bytes a
 * session would have carried. `answer_bytes`/`answer_rows` record what the
 * last answer held so a test can assert on the bound rather than on how
 * many rows happened to be stored afterwards. `tamper_at` flips one byte
 * inside one row's payload, which is how a relay that altered a row in
 * flight is simulated without giving the test a private encoder. */
struct sync_test_peer_ctx {
    struct node_db *serving;
    struct zcl_app_event_scope_v1 scope;
    size_t answer_bytes;
    size_t answer_rows;
    bool tamper;
    size_t tamper_row;
    enum zcl_app_sync_status last_serve;
};

static uint8_t *sync_test_row_at(uint8_t *answer, size_t len, size_t index,
                                 size_t *row_len)
{
    size_t offset = 0;
    for (size_t i = 0; offset + ZCL_APP_SYNC_ROW_HEAD_BYTES <= len; i++) {
        size_t n = ((size_t)answer[offset] << 24) |
            ((size_t)answer[offset + 1] << 16) |
            ((size_t)answer[offset + 2] << 8) | (size_t)answer[offset + 3];
        if (n == 0 || offset + ZCL_APP_SYNC_ROW_HEAD_BYTES + n > len)
            return NULL;
        if (i == index) {
            *row_len = n;
            return answer + offset + ZCL_APP_SYNC_ROW_HEAD_BYTES;
        }
        offset += ZCL_APP_SYNC_ROW_HEAD_BYTES + n;
    }
    return NULL;
}

static bool sync_test_ask(void *ctx, const uint8_t *request,
                          size_t request_len, uint8_t *answer,
                          size_t answer_cap, size_t *answer_len)
{
    struct sync_test_peer_ctx *peer = ctx;
    struct zcl_app_sync_pull pull;
    if (zcl_app_sync_pull_decode(request, request_len, &pull) !=
        ZCL_APP_SYNC_OK)
        return false;
    size_t rows = 0;
    peer->last_serve = zcl_app_event_sync_serve(
        peer->serving, &peer->scope, &pull, answer, answer_cap, answer_len,
        &rows);
    if (peer->last_serve != ZCL_APP_SYNC_OK)
        return false;
    peer->answer_bytes = *answer_len;
    peer->answer_rows = rows;
    if (peer->tamper) {
        size_t row_len = 0;
        uint8_t *row = sync_test_row_at(answer, *answer_len, peer->tamper_row,
                                        &row_len);
        if (!row)
            return false;
        /* Inside the payload, well past the header, so what breaks is the
         * signature over the content and not the frame's shape. */
        row[row_len / 2] = (uint8_t)(row[row_len / 2] ^ 0x40);
    }
    return true;
}

/* ── the wire on its own ─────────────────────────────────────────────── */

static int test_app_sync_pull_codec(void)
{
    int failures = 0;
    TEST("app sync: a pull request round-trips and refuses by name") {
        struct zcl_app_sync_pull pull;
        memset(&pull, 0, sizeof(pull));
        memset(pull.since_event_id, 0xa7, sizeof(pull.since_event_id));
        (void)snprintf(pull.app_id, sizeof(pull.app_id), "%s", "social");
        (void)snprintf(pull.topic, sizeof(pull.topic), "%s",
                       "social.events.v1");
        uint8_t frame[ZCL_APP_SYNC_PULL_MAX_BYTES];
        size_t len = 0;
        ASSERT_EQ(zcl_app_sync_pull_encode(&pull, frame, sizeof(frame), &len),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(len, ZCL_APP_SYNC_PULL_HEAD_BYTES + 6u + 16u);

        struct zcl_app_sync_pull back;
        ASSERT_EQ(zcl_app_sync_pull_decode(frame, len, &back),
                  ZCL_APP_SYNC_OK);
        ASSERT(memcmp(back.since_event_id, pull.since_event_id, 32) == 0);
        ASSERT(strcmp(back.app_id, pull.app_id) == 0);
        ASSERT(strcmp(back.topic, pull.topic) == 0);

        /* A version this build does not speak is its own refusal, never a
         * malformed frame: the answer is a newer build, not a bad peer. */
        uint8_t bad[ZCL_APP_SYNC_PULL_MAX_BYTES];
        memcpy(bad, frame, len);
        bad[1] = (uint8_t)(ZCL_APP_SYNC_WIRE_VERSION + 1u);
        ASSERT_EQ(zcl_app_sync_pull_decode(bad, len, &back),
                  ZCL_APP_SYNC_VERSION);
        memcpy(bad, frame, len);
        bad[0] = 9;
        ASSERT_EQ(zcl_app_sync_pull_decode(bad, len, &back),
                  ZCL_APP_SYNC_MALFORMED);
        /* Short, and long: a trailing byte is not slack, it is a frame
         * this build did not write. */
        ASSERT_EQ(zcl_app_sync_pull_decode(frame, len - 1, &back),
                  ZCL_APP_SYNC_MALFORMED);
        memcpy(bad, frame, len);
        bad[len] = 0;
        ASSERT_EQ(zcl_app_sync_pull_decode(bad, len + 1, &back),
                  ZCL_APP_SYNC_MALFORMED);
        ASSERT_EQ(zcl_app_sync_pull_decode(frame, 4, &back),
                  ZCL_APP_SYNC_MALFORMED);

        /* An empty topic names no topic; a buffer that cannot hold the
         * request refuses rather than truncating one. */
        struct zcl_app_sync_pull empty = pull;
        empty.topic[0] = 0;
        ASSERT_EQ(zcl_app_sync_pull_encode(&empty, frame, sizeof(frame),
                                           &len),
                  ZCL_APP_SYNC_ARGUMENT);
        ASSERT_EQ(zcl_app_sync_pull_encode(&pull, frame, 8, &len),
                  ZCL_APP_SYNC_ARGUMENT);
        ASSERT_EQ(len, 0u);

        ASSERT(strcmp(zcl_app_sync_status_label(ZCL_APP_SYNC_OK), "ok") == 0);
        ASSERT(strcmp(zcl_app_sync_status_label(ZCL_APP_SYNC_SIG_INVALID),
                      "appsync_sig_invalid") == 0);
        ASSERT(strcmp(zcl_app_sync_status_label(ZCL_APP_SYNC_NO_PEER),
                      "appsync_no_peer") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── two nodes ───────────────────────────────────────────────────────── */

static int test_app_sync_two_nodes(void)
{
    int failures = 0;
    struct sync_test_signer signer;
    memset(&signer, 0, sizeof(signer));
    TEST("app sync: three signed events cross to another node and verify") {
        struct zcl_app_event_scope_v1 scope =
            sync_test_scope("social.events.v1");
        struct node_db a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&a, ":memory:"));
        ASSERT(node_db_open(&b, ":memory:"));
        ASSERT(sync_test_signer_open(&signer, &scope, 1));

        static const uint8_t payloads[3][24] = {
            "the first thing said",
            "the second thing sai",
            "the third thing said",
        };
        struct zcl_app_signed_event_v1 events[3];
        uint8_t previous[32];
        memset(previous, 0, sizeof(previous));
        for (uint64_t i = 0; i < 3; i++) {
            ASSERT(sync_test_sign(&signer, i + 1,
                                  i == 0 ? NULL : previous,
                                  payloads[i], sizeof(payloads[i]) - 1,
                                  &events[i]));
            ASSERT(sync_test_store(&a, &scope, &events[i]));
            memcpy(previous, events[i].event_id, 32);
        }
        ASSERT_EQ(db_app_event_count(&a, "social", "social.events.v1"), 3);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 0);

        struct sync_test_peer_ctx peer_ctx;
        memset(&peer_ctx, 0, sizeof(peer_ctx));
        peer_ctx.serving = &a;
        peer_ctx.scope = scope;
        struct zcl_app_sync_peer peer = {
            .name = "node-a", .ask = sync_test_ask, .ctx = &peer_ctx,
        };

        struct zcl_app_sync_report report;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(report.pulled, 3u);
        ASSERT_EQ(report.verified, 3u);
        ASSERT_EQ(report.stored, 3u);
        ASSERT_EQ(report.refused, 0u);
        ASSERT(report.frontier.have);
        ASSERT_EQ(report.frontier.rows, 3);
        ASSERT(memcmp(report.frontier.event_id, events[2].event_id, 32) == 0);

        /* Byte identity: what B holds re-encodes to the exact frame A
         * signed, signature and all. */
        for (size_t i = 0; i < 3; i++) {
            struct db_app_event held;
            uint8_t held_payload[256];
            ASSERT(db_app_event_find(&b, events[i].event_id, &scope, &held,
                                     held_payload, sizeof(held_payload)));
            uint8_t mine[512], theirs[512];
            size_t mine_len = sync_test_frame(&events[i], mine, sizeof(mine));
            size_t theirs_len = sync_test_frame(&held.event, theirs,
                                                sizeof(theirs));
            ASSERT(mine_len > 0);
            ASSERT_EQ(theirs_len, mine_len);
            ASSERT(memcmp(mine, theirs, mine_len) == 0);
        }
        /* B ends up with A's events under its OWN arrival order: the
         * cursors are B's, and nothing about A's ordering crossed. */
        ASSERT(report.frontier.cursor > 0);

        /* A second pull asks from the new frontier, is answered with
         * nothing, and stores nothing. */
        struct zcl_app_sync_report again;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &again),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(again.pulled, 0u);
        ASSERT_EQ(again.stored, 0u);
        ASSERT_EQ(peer_ctx.answer_rows, 0u);
        ASSERT_EQ(peer_ctx.answer_bytes, 0u);
        ASSERT_EQ(again.frontier.cursor, report.frontier.cursor);
        ASSERT(memcmp(again.frontier.event_id, report.frontier.event_id,
                      32) == 0);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 3);

        node_db_close(&a);
        node_db_close(&b);
        PASS();
    } _test_next:;
    sync_test_signer_close(&signer);
    return failures;
}

static int test_app_sync_tampered_row(void)
{
    int failures = 0;
    struct sync_test_signer signer;
    memset(&signer, 0, sizeof(signer));
    TEST("app sync: one tampered byte refuses by name and stores nothing after") {
        struct zcl_app_event_scope_v1 scope =
            sync_test_scope("social.events.v1");
        struct node_db a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&a, ":memory:"));
        ASSERT(node_db_open(&b, ":memory:"));
        ASSERT(sync_test_signer_open(&signer, &scope, 2));

        static const uint8_t payloads[3][24] = {
            "alpha payload contents",
            "bravo payload contents",
            "delta payload contents",
        };
        struct zcl_app_signed_event_v1 events[3];
        uint8_t previous[32];
        memset(previous, 0, sizeof(previous));
        for (uint64_t i = 0; i < 3; i++) {
            ASSERT(sync_test_sign(&signer, i + 1, i == 0 ? NULL : previous,
                                  payloads[i], sizeof(payloads[i]) - 1,
                                  &events[i]));
            ASSERT(sync_test_store(&a, &scope, &events[i]));
            memcpy(previous, events[i].event_id, 32);
        }

        struct sync_test_peer_ctx peer_ctx;
        memset(&peer_ctx, 0, sizeof(peer_ctx));
        peer_ctx.serving = &a;
        peer_ctx.scope = scope;
        peer_ctx.tamper = true;
        peer_ctx.tamper_row = 0;
        struct zcl_app_sync_peer peer = {
            .name = "a-relay", .ask = sync_test_ask, .ctx = &peer_ctx,
        };

        /* The FIRST row is altered, so the walk refuses before anything is
         * stored and the frontier is exactly where it was. */
        struct zcl_app_sync_report report;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_SIG_INVALID);
        ASSERT_EQ(report.pulled, 0u);
        ASSERT_EQ(report.verified, 0u);
        ASSERT_EQ(report.stored, 0u);
        ASSERT_EQ(report.refused, 1u);
        ASSERT_EQ(report.bad_row, 0u);
        ASSERT(!report.frontier.have);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 0);
        ASSERT(strcmp(report.peer, "a-relay") == 0);

        /* The SECOND row is altered: the walk stops there, the row before
         * it is held (it verified, and that stays true), and neither the
         * bad row nor the row after it is stored. */
        peer_ctx.tamper_row = 1;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_SIG_INVALID);
        ASSERT_EQ(report.pulled, 1u);
        ASSERT_EQ(report.verified, 1u);
        ASSERT_EQ(report.stored, 1u);
        ASSERT_EQ(report.bad_row, 1u);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 1);
        ASSERT(memcmp(report.frontier.event_id, events[0].event_id, 32) == 0);

        /* Once the relay stops altering rows, the same pull completes. */
        peer_ctx.tamper = false;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(report.pulled, 2u);
        ASSERT_EQ(report.stored, 2u);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 3);

        node_db_close(&a);
        node_db_close(&b);
        PASS();
    } _test_next:;
    sync_test_signer_close(&signer);
    return failures;
}

static int test_app_sync_out_of_scope_row(void)
{
    int failures = 0;
    struct sync_test_signer signer;
    memset(&signer, 0, sizeof(signer));
    TEST("app sync: an event from another topic is refused as out of scope") {
        struct zcl_app_event_scope_v1 wanted =
            sync_test_scope("social.events.v1");
        struct zcl_app_event_scope_v1 other =
            sync_test_scope("social.other.v1");
        struct node_db b;
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&b, ":memory:"));
        ASSERT(sync_test_signer_open(&signer, &other, 3));

        static const uint8_t payload[] = "a post in a topic nobody asked for";
        struct zcl_app_signed_event_v1 stranger;
        ASSERT(sync_test_sign(&signer, 1, NULL, payload,
                              sizeof(payload) - 1, &stranger));

        uint8_t answer[1024];
        struct zcl_app_sync_writer writer;
        zcl_app_sync_writer_init(&writer, answer, sizeof(answer));
        ASSERT_EQ(zcl_app_sync_writer_append(&writer, &stranger),
                  ZCL_APP_SYNC_OK);

        struct zcl_app_sync_report report;
        memset(&report, 0, sizeof(report));
        ASSERT_EQ(zcl_app_event_sync_apply(&b, &wanted, answer, writer.len,
                                           SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_SCOPE);
        ASSERT_EQ(report.verified, 0u);
        ASSERT_EQ(report.stored, 0u);
        ASSERT_EQ(report.refused, 1u);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 0);

        /* A truncated answer is a refusal, never a short read taken for the
         * end of the batch. */
        memset(&report, 0, sizeof(report));
        ASSERT_EQ(zcl_app_event_sync_apply(&b, &other, answer,
                                           writer.len - 1,
                                           SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_MALFORMED);
        ASSERT_EQ(report.stored, 0u);

        /* A row_len claiming more than any answer could ever carry is
         * refused as too large, never treated as a huge-but-honest count. */
        uint8_t huge_row_len[1024];
        memcpy(huge_row_len, answer, writer.len);
        huge_row_len[0] = 0xff;
        huge_row_len[1] = 0xff;
        huge_row_len[2] = 0xff;
        huge_row_len[3] = 0xff;
        memset(&report, 0, sizeof(report));
        ASSERT_EQ(zcl_app_event_sync_apply(&b, &other, huge_row_len,
                                           writer.len,
                                           SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_ROW_TOO_LARGE);
        ASSERT_EQ(report.stored, 0u);

        /* A row_len one byte longer than the bytes actually present is a
         * malformed answer, never a read past the end of the buffer. */
        uint8_t row_len_plus_one[1024];
        memcpy(row_len_plus_one, answer, writer.len);
        uint32_t declared = (uint32_t)(writer.len - ZCL_APP_SYNC_ROW_HEAD_BYTES) + 1u;
        row_len_plus_one[0] = (uint8_t)(declared >> 24);
        row_len_plus_one[1] = (uint8_t)(declared >> 16);
        row_len_plus_one[2] = (uint8_t)(declared >> 8);
        row_len_plus_one[3] = (uint8_t)declared;
        memset(&report, 0, sizeof(report));
        ASSERT_EQ(zcl_app_event_sync_apply(&b, &other, row_len_plus_one,
                                           writer.len,
                                           SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_MALFORMED);
        ASSERT_EQ(report.stored, 0u);

        node_db_close(&b);
        PASS();
    } _test_next:;
    sync_test_signer_close(&signer);
    return failures;
}

static int test_app_sync_batch_bound(void)
{
    int failures = 0;
    struct sync_test_signer signer;
    memset(&signer, 0, sizeof(signer));
    TEST("app sync: one answer stops at the batch bound and the next continues") {
        struct zcl_app_event_scope_v1 scope =
            sync_test_scope("social.events.v1");
        struct node_db a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&a, ":memory:"));
        ASSERT(node_db_open(&b, ":memory:"));
        ASSERT(sync_test_signer_open(&signer, &scope, 4));

        const size_t total = ZCL_APP_SYNC_BATCH_MAX + 3u;
        static uint8_t payloads[ZCL_APP_SYNC_BATCH_MAX + 3u][32];
        struct zcl_app_signed_event_v1 event;
        uint8_t previous[32];
        memset(previous, 0, sizeof(previous));
        for (size_t i = 0; i < total; i++) {
            (void)snprintf((char *)payloads[i], sizeof(payloads[i]),
                           "event number %zu", i);
            ASSERT(sync_test_sign(&signer, (uint64_t)i + 1,
                                  i == 0 ? NULL : previous, payloads[i],
                                  strlen((const char *)payloads[i]), &event));
            ASSERT(sync_test_store(&a, &scope, &event));
            memcpy(previous, event.event_id, 32);
        }
        ASSERT_EQ(db_app_event_count(&a, "social", "social.events.v1"),
                  (int)total);

        struct sync_test_peer_ctx peer_ctx;
        memset(&peer_ctx, 0, sizeof(peer_ctx));
        peer_ctx.serving = &a;
        peer_ctx.scope = scope;
        struct zcl_app_sync_peer peer = {
            .name = "node-a", .ask = sync_test_ask, .ctx = &peer_ctx,
        };

        struct zcl_app_sync_report first;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &first),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(peer_ctx.answer_rows, (size_t)ZCL_APP_SYNC_BATCH_MAX);
        ASSERT_EQ(first.pulled, (size_t)ZCL_APP_SYNC_BATCH_MAX);
        ASSERT_EQ(first.stored, (size_t)ZCL_APP_SYNC_BATCH_MAX);

        struct zcl_app_sync_report second;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &peer,
                                          SYNC_TEST_RECEIVED_AT, &second),
                  ZCL_APP_SYNC_OK);
        ASSERT_EQ(second.pulled, 3u);
        ASSERT_EQ(second.stored, 3u);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"),
                  (int)total);

        /* The byte bound is a refusal too: a writer with room for one row
         * refuses the second rather than writing a partial one. */
        uint8_t narrow[64];
        struct zcl_app_sync_writer writer;
        zcl_app_sync_writer_init(&writer, narrow, sizeof(narrow));
        ASSERT_EQ(zcl_app_sync_writer_append(&writer, &event),
                  ZCL_APP_SYNC_BATCH_FULL);
        ASSERT_EQ(writer.len, 0u);
        ASSERT_EQ(writer.rows, 0u);

        node_db_close(&a);
        node_db_close(&b);
        PASS();
    } _test_next:;
    sync_test_signer_close(&signer);
    return failures;
}

static int test_app_sync_no_peer(void)
{
    int failures = 0;
    TEST("app sync: no peer and no session both refuse and store nothing") {
        struct zcl_app_event_scope_v1 scope =
            sync_test_scope("social.events.v1");
        struct node_db b;
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&b, ":memory:"));

        struct zcl_app_sync_report report;
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, NULL,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_NO_PEER);
        ASSERT_EQ(report.pulled, 0u);
        ASSERT_EQ(report.stored, 0u);

        /* A peer that is named but has no session to ask over is the same
         * refusal: a name is not a link. */
        struct zcl_app_sync_peer unreachable = {
            .name = "node-far", .ask = NULL, .ctx = NULL,
        };
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &unreachable,
                                          SYNC_TEST_RECEIVED_AT, &report),
                  ZCL_APP_SYNC_NO_PEER);
        ASSERT(strcmp(report.peer, "node-far") == 0);
        ASSERT_EQ(report.stored, 0u);
        ASSERT_EQ(db_app_event_count(&b, "social", "social.events.v1"), 0);

        /* An arrival time is required: nothing here reads a clock, so a
         * caller that supplies none is refused rather than given one. */
        ASSERT_EQ(zcl_app_event_replicate(&b, &scope, &unreachable, 0,
                                          &report),
                  ZCL_APP_SYNC_ARGUMENT);

        node_db_close(&b);
        PASS();
    } _test_next:;
    return failures;
}

int test_app_event_sync(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    failures += test_app_sync_pull_codec();
    failures += test_app_sync_two_nodes();
    failures += test_app_sync_tampered_row();
    failures += test_app_sync_out_of_scope_row();
    failures += test_app_sync_batch_bound();
    failures += test_app_sync_no_peer();
    return failures;
}
