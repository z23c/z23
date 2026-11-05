/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The fleet AI message board and wiki: codec, signature, caps, store, and the
 * two-node gossip path.
 *
 * The gossip proof drives two independent node databases through the real
 * frame codec: A posts and announces, B GETs, A serves a POST frame, B
 * ingests and verifies. The socket underneath is not covered. */

#include "test/test_core.h"

#include "config/boot_fleet_board.h"
#include "config/args.h"
#include "config/boot.h"
#include "config/boot_fleet_roster.h"
#include "fleet_enrol.h"
#include "models/zid_identity.h"
#include "util/fleet_roster_check.h"
#include "config/command_catalog.h"
#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "controllers/fleet_status_controller.h"
#include "controllers/fleet_tip.h"
#include "platform/clock.h"
#include "net/connman.h"
#include "net/tor_integration.h"
#include "util/fleet_role_check.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "command/native_command.h"
#include "command/native_fleet.h"
#include "controllers/rpc_client.h"
#include "session/fleet_board_proto.h"
#include "session/fleet_wiki_entry.h"
#include "chain/chainparams.h"
#include "net/fast_sync.h"
#include "rpc/server.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "platform/time_compat.h"
#include "platform/clock.h"
#include "platform/environment_compat.h"
#include "platform/private_directory.h"
#include "util/thread_registry.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/mesh_term_fixture.h"
#include "models/mesh_pairing.h"
#include "net/noise_transport.h"
#include "net/onion_v3_address.h"
#include "../../../engine/composition/src/boot_fleet_board_roster_internal.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Two distinct, deterministic host identities. A board post is only as
 * meaningful as the key that signed it, so the tests never share one. */
static void fb_test_identity(uint8_t which, uint8_t seed[32], uint8_t pk[32])
{
    uint8_t sk[32];
    memset(seed, 0, 32);
    seed[0] = which;
    seed[31] = (uint8_t)(0xa0 + which);
    ed25519_keypair(pk, sk, seed);
    memcpy(seed, sk, 32);
}

static void fb_test_compose(struct fleet_board_post *post, uint8_t kind,
                            const char *agent, const char *text,
                            uint64_t created_at, uint32_t ttl)
{
    memset(post, 0, sizeof(*post));
    post->kind = kind;
    post->created_at = created_at;
    post->ttl = ttl;
    (void)snprintf(post->agent, sizeof(post->agent), "%s", agent ? agent : "");
    size_t n = strlen(text);
    memcpy(post->text, text, n);
    post->text[n] = '\0';
    post->text_len = (uint32_t)n;
}

static int test_fleet_board_codec(void)
{
    int failures = 0;
    TEST("fleet board: the id is the bytes, and the signature is the id") {
        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);

        struct fleet_board_post post;
        fb_test_compose(&post, FLEET_BOARD_KIND_PROBLEM, "lane-a",
                        "regtest group wedges on a slow disk", 1000, 3600);
        ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_verify(&post), FLEET_BOARD_OK);

        /* Canonical encoding is deterministic and total. */
        uint8_t body_a[FLEET_BOARD_BODY_MAX], body_b[FLEET_BOARD_BODY_MAX];
        size_t len_a = 0, len_b = 0;
        ASSERT_EQ(fleet_board_post_canonical(&post, body_a, sizeof(body_a),
                                             &len_a), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_canonical(&post, body_b, sizeof(body_b),
                                             &len_b), FLEET_BOARD_OK);
        ASSERT_EQ(len_a, len_b);
        ASSERT(memcmp(body_a, body_b, len_a) == 0);

        /* A short buffer reports the size it needed and writes no id. */
        uint8_t tiny[8];
        size_t needed = 0;
        ASSERT_EQ(fleet_board_post_canonical(&post, tiny, sizeof(tiny),
                                             &needed),
                  FLEET_BOARD_ERR_CAPACITY);
        ASSERT_EQ(needed, len_a);

        /* Changing ONE signed byte changes the id, so the stated id no
         * longer matches and the post is refused before any curve work. */
        struct fleet_board_post tampered = post;
        tampered.text[0] = (char)(tampered.text[0] ^ 0x01);
        ASSERT_EQ(fleet_board_post_verify(&tampered), FLEET_BOARD_ERR_ID);

        /* Keeping the id but breaking the signature is the other half. */
        struct fleet_board_post forged = post;
        forged.signature[0] = (uint8_t)(forged.signature[0] ^ 0x01);
        ASSERT_EQ(fleet_board_post_verify(&forged), FLEET_BOARD_ERR_SIGNATURE);

        /* A different host cannot claim this post's bytes. */
        uint8_t seed_b[32], pk_b[32];
        fb_test_identity(2, seed_b, pk_b);
        struct fleet_board_post impostor = post;
        memcpy(impostor.host_pubkey, pk_b, 32);
        ASSERT_EQ(fleet_board_post_verify(&impostor), FLEET_BOARD_ERR_ID);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_bounds(void)
{
    int failures = 0;
    TEST("fleet board: every bound refuses rather than truncates") {
        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);
        struct fleet_board_post post;

        /* Empty text is not a post. */
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", "", 1000, 60);
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_ERR_TEXT);

        /* An ordinary post is capped well below a wiki page. */
        static char long_text[FLEET_BOARD_WIKI_TEXT_MAX + 1];
        memset(long_text, 'x', FLEET_BOARD_TEXT_MAX + 1);
        long_text[FLEET_BOARD_TEXT_MAX + 1] = '\0';
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", long_text, 1000, 60);
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_ERR_TEXT);

        /* The same bytes are a legal WIKI body, which is the whole point of
         * giving the wiki its own limit. */
        post.kind = FLEET_BOARD_KIND_WIKI;
        (void)snprintf(post.slug, sizeof(post.slug), "%s", "push-gate");
        (void)snprintf(post.title, sizeof(post.title), "%s", "The push gate");
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_OK);

        /* Slug rules. */
        ASSERT(fleet_board_slug_valid("push-gate"));
        ASSERT(fleet_board_slug_valid("a"));
        ASSERT(!fleet_board_slug_valid(""));
        ASSERT(!fleet_board_slug_valid("-lead"));
        ASSERT(!fleet_board_slug_valid("trail-"));
        ASSERT(!fleet_board_slug_valid("Upper"));
        ASSERT(!fleet_board_slug_valid("has space"));

        /* A non-wiki post carrying wiki fields is refused: those fields are
         * signed, so accepting them would sign a claim the kind cannot make. */
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", "hi", 1000, 60);
        (void)snprintf(post.slug, sizeof(post.slug), "%s", "sneaky");
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_ERR_SLUG);

        /* ttl bounds. */
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", "hi", 1000, 0);
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_ERR_TTL);
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", "hi", 1000,
                        FLEET_BOARD_TTL_MAX + 1);
        ASSERT_EQ(fleet_board_post_validate(&post), FLEET_BOARD_ERR_TTL);

        /* Clock checks are separate from shape and from cryptography. */
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "a", "hi", 1000, 100);
        ASSERT_EQ(fleet_board_post_check_time(&post, 1050), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_check_time(&post, 1100),
                  FLEET_BOARD_ERR_EXPIRED);
        ASSERT_EQ(fleet_board_post_check_time(&post, 500),
                  FLEET_BOARD_ERR_FUTURE);
        /* Inside the tolerated skew a slightly fast peer is still accepted. */
        ASSERT_EQ(fleet_board_post_check_time(&post, 1000 -
                                              FLEET_BOARD_FUTURE_SKEW_MAX),
                  FLEET_BOARD_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_frames(void)
{
    int failures = 0;
    TEST("fleet board: frames round-trip and refuse trailing bytes") {
        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);
        struct fleet_board_post post;
        fb_test_compose(&post, FLEET_BOARD_KIND_OFFER, "host-3",
                        "offer-cpu cores=32 free_slots=4 load=1.2 takes=build",
                        2000, 3600);
        ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);

        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t frame_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_post(&post, frame, sizeof(frame),
                                                &frame_len), FLEET_BOARD_OK);
        ASSERT(fleet_board_frame_is_board(frame, frame_len));
        ASSERT_EQ(fleet_board_frame_type(frame, frame_len),
                  FLEET_BOARD_FRAME_POST);

        struct fleet_board_post decoded;
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len, &decoded),
                  FLEET_BOARD_OK);
        ASSERT(memcmp(decoded.id, post.id, 32) == 0);
        ASSERT(strcmp(decoded.text, post.text) == 0);
        ASSERT(strcmp(decoded.agent, post.agent) == 0);

        /* One appended byte is a refusal, not a shrug: a relay must not be
         * able to staple attacker bytes onto a post it forwards. */
        frame[frame_len] = 0x00;
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len + 1, &decoded),
                  FLEET_BOARD_ERR_TRAILING);
        /* A truncated frame is refused and leaves nothing behind. */
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len - 1, &decoded),
                  FLEET_BOARD_ERR_TRUNCATED);
        ASSERT_EQ(decoded.kind, 0);

        /* Id-list frames. */
        uint8_t ids[3][32];
        for (size_t i = 0; i < 3; i++)
            memset(ids[i], (int)(i + 1), 32);
        uint8_t inv[FLEET_BOARD_FRAME_MAX];
        size_t inv_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids, 3,
                                               inv, sizeof(inv), &inv_len),
                  FLEET_BOARD_OK);
        uint8_t out_ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        uint8_t type = 0;
        size_t count = 0;
        ASSERT_EQ(fleet_board_frame_decode_ids(inv, inv_len, &type, out_ids,
                                               FLEET_BOARD_FRAME_IDS_MAX,
                                               &count), FLEET_BOARD_OK);
        ASSERT_EQ(type, FLEET_BOARD_FRAME_INV);
        ASSERT_EQ(count, 3u);
        ASSERT(memcmp(out_ids[2], ids[2], 32) == 0);

        /* A frame claiming more ids than it carries is refused. */
        inv[FLEET_BOARD_FRAME_MAGIC_BYTES + 1] = 0x7f;
        ASSERT_EQ(fleet_board_frame_decode_ids(inv, inv_len, &type, out_ids,
                                               FLEET_BOARD_FRAME_IDS_MAX,
                                               &count),
                  FLEET_BOARD_ERR_TRUNCATED);

        /* Somebody else's swarm frame is not ours. */
        ASSERT(!fleet_board_frame_is_board((const uint8_t *)"ZCWS...", 7));

        /* The local chain step is a pure function of (previous, id). */
        uint8_t zero[32] = {0}, c1[32], c1b[32], c2[32];
        fleet_board_chain_step(zero, post.id, c1);
        fleet_board_chain_step(zero, post.id, c1b);
        ASSERT(memcmp(c1, c1b, 32) == 0);
        fleet_board_chain_step(c1, post.id, c2);
        ASSERT(memcmp(c1, c2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_store(void)
{
    int failures = 0;
    TEST("fleet board: the store appends, chains, and closes open questions") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(node_db_schema_version(&db), NODE_DB_SCHEMA_LATEST);

        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);
        const int64_t now = 100000;

        struct fleet_board_post problem;
        fb_test_compose(&problem, FLEET_BOARD_KIND_PROBLEM, "lane-a",
                        "the params gate blows its 60s budget under -j32",
                        (uint64_t)now, 3600);
        ASSERT_EQ(fleet_board_post_sign(&problem, seed, pk), FLEET_BOARD_OK);
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &problem, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);
        ASSERT(db_fleet_board_have(&db, problem.id));

        /* Idempotent: the id IS the bytes, so a re-delivery is a no-op and
         * must not append a second row or a second chain link. */
        stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &problem, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(!stored);

        /* A tampered copy never enters the ledger. */
        struct fleet_board_post tampered = problem;
        tampered.text[0] = 'X';
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &tampered, now, NULL),
                  FLEET_BOARD_ERR_ID);
        /* Nor does an expired one. */
        struct fleet_board_post stale;
        fb_test_compose(&stale, FLEET_BOARD_KIND_NOTE, "lane-a", "old news",
                        (uint64_t)(now - 7200), 3600);
        ASSERT_EQ(fleet_board_post_sign(&stale, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &stale, now, NULL),
                  FLEET_BOARD_ERR_EXPIRED);
        /* Nor an unsigned one. */
        struct fleet_board_post unsigned_post;
        fb_test_compose(&unsigned_post, FLEET_BOARD_KIND_NOTE, "nobody",
                        "trust me", (uint64_t)now, 600);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &unsigned_post, now, NULL),
                  FLEET_BOARD_ERR_ID);

        /* The question is open until something references it. */
        struct fleet_board_filter open_filter;
        memset(&open_filter, 0, sizeof(open_filter));
        open_filter.open_only = true;
        struct db_fleet_board_post rows[8];
        ASSERT_EQ(db_fleet_board_list(&db, &open_filter, now, rows, 8), 1);
        ASSERT(memcmp(rows[0].post.id, problem.id, 32) == 0);

        /* A claim carrying the dispatcher's receipt fields references it. */
        struct fleet_board_post claim;
        fb_test_compose(&claim, FLEET_BOARD_KIND_CLAIM, "lane-b",
                        "taking it: reproducing on a 7200rpm box",
                        (uint64_t)now + 1, 3600);
        memcpy(claim.ref, problem.id, 32);
        (void)snprintf(claim.receipt, sizeof(claim.receipt), "%s",
                       "unit=u-17 engine=glm gate=pending tokens=0");
        ASSERT_EQ(fleet_board_post_sign(&claim, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &claim, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_list(&db, &open_filter, now, rows, 8), 0);

        /* A result closes it just as a claim does, and carries the verdict
         * pointer the dispatcher will later ride on. */
        struct fleet_board_post result;
        fb_test_compose(&result, FLEET_BOARD_KIND_RESULT, "lane-b",
                        "fixed: the params pass needs its own -j1 lane",
                        (uint64_t)now + 2, 3600);
        memcpy(result.ref, problem.id, 32);
        (void)snprintf(result.receipt, sizeof(result.receipt), "%s",
                       "unit=u-17 engine=glm gate=pass tokens=48210 "
                       "commit=fba3a5d23");
        ASSERT_EQ(fleet_board_post_sign(&result, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &result, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_list(&db, &open_filter, now, rows, 8), 0);

        struct db_fleet_board_post fetched;
        ASSERT(db_fleet_board_post_find(&db, result.id, &fetched));
        ASSERT(strcmp(fetched.post.receipt, result.receipt) == 0);

        /* Kind and host filters. */
        struct fleet_board_filter kind_filter;
        memset(&kind_filter, 0, sizeof(kind_filter));
        kind_filter.kind = FLEET_BOARD_KIND_RESULT;
        ASSERT_EQ(db_fleet_board_list(&db, &kind_filter, now, rows, 8), 1);
        memset(&kind_filter, 0, sizeof(kind_filter));
        memset(kind_filter.host_pubkey, 0xee, 32);
        kind_filter.host_set = true;
        ASSERT_EQ(db_fleet_board_list(&db, &kind_filter, now, rows, 8), 0);

        /* The local chain links every stored post in arrival order. */
        int64_t checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 3);

        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, now, &status));
        ASSERT_EQ(status.posts, 3);
        ASSERT(status.bytes > 0);
        ASSERT_EQ(status.open_questions, 0);
        ASSERT(status.head_chain_set);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_agents_kind(void)
{
    int failures = 0;
    TEST("fleet board: an `agents` post signs, stores, and lists by kind") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(4, seed, pk);
        const int64_t now = 200000;

        struct fleet_board_post dash;
        fb_test_compose(&dash, FLEET_BOARD_KIND_AGENTS, "node1",
                        "v1|host=node1|now=200000\nR|lane-a|lane|abc|0|1\n",
                        (uint64_t)now, 3600);
        dash.scope = FLEET_BOARD_SCOPE_FLEET;
        ASSERT_EQ(fleet_board_post_sign(&dash, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_verify(&dash), FLEET_BOARD_OK);
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &dash, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);

        struct fleet_board_filter filter;
        memset(&filter, 0, sizeof(filter));
        filter.kind = FLEET_BOARD_KIND_AGENTS;
        filter.scope_set = true;
        filter.scope = FLEET_BOARD_SCOPE_FLEET;
        struct db_fleet_board_post rows[4];
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 4), 1);
        ASSERT(strcmp(rows[0].post.text, dash.text) == 0);
        ASSERT_STR_EQ(fleet_board_kind_name(rows[0].post.kind), "agents");

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_kind_ceiling_refuses_unknown(void)
{
    int failures = 0;
    TEST("fleet board: a kind past the known enum is refused, not admitted") {
        /* The SQL CHECK admits kind 1..64; the C layer is the gate: any kind
         * >= FLEET_BOARD_KIND__COUNT never reaches storage or a signed RPC. */
        uint8_t seed[32], pk[32];
        fb_test_identity(5, seed, pk);
        const int64_t now = 200000;

        struct fleet_board_post bogus;
        fb_test_compose(&bogus, FLEET_BOARD_KIND_AGENTS, "node1",
                        "v1|host=node1|now=200000\n", (uint64_t)now, 3600);
        bogus.kind = (uint8_t)(FLEET_BOARD_KIND__COUNT);
        ASSERT_EQ(fleet_board_post_validate(&bogus), FLEET_BOARD_ERR_KIND);

        /* Signing does not launder an unknown kind either: validate runs
         * before storage regardless of whether the caller ever signs. */
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &bogus, now, &stored),
                  FLEET_BOARD_ERR_KIND);
        ASSERT(!stored);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_transaction_busy(void)
{
    int failures = 0;
    TEST("fleet board: transaction contention is distinct from exhausted capacity") {
        struct node_db db = {0};
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], key[32];
        fb_test_identity(7, seed, key);
        struct fleet_board_post post;
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "lane-a", "busy witness", 100, 1000);
        ASSERT_EQ(fleet_board_post_sign(&post, seed, key), FLEET_BOARD_OK);
        ASSERT(node_db_begin(&db));
        int changes = sqlite3_total_changes(db.db);
        bool stored = true;
        enum fleet_board_result result = db_fleet_board_post_ingest(&db, &post, 100, &stored);
        bool absent = !db_fleet_board_have(&db, post.id);
        bool unchanged = sqlite3_total_changes(db.db) == changes;
        struct node_db_status status;
        node_db_get_status(&db, &status);
        bool rolled_back = node_db_rollback(&db);
        ASSERT(rolled_back);
        ASSERT_STR_EQ(fleet_board_result_string(result), "board database transaction is busy");
        ASSERT(!stored && absent && unchanged && status.tx_open);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &post, 100, &stored), FLEET_BOARD_OK);
        ASSERT(stored && db_fleet_board_have(&db, post.id));
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_store_boundaries(void)
{
    int failures = 0;
    TEST("fleet board: capacity refuses before append and preserves wiki heads") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_store_limits(2, 1024 * 1024);

        uint8_t seed[32], pk[32];
        fb_test_identity(7, seed, pk);
        struct fleet_board_post wiki, live, refused;
        fb_test_compose(&wiki, FLEET_BOARD_KIND_WIKI, "lane-a", "keep me",
                        100, 10);
        (void)snprintf(wiki.slug, sizeof(wiki.slug), "%s", "protected-head");
        (void)snprintf(wiki.title, sizeof(wiki.title), "%s", "Protected head");
        ASSERT_EQ(fleet_board_post_sign(&wiki, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &wiki, 100, NULL),
                  FLEET_BOARD_OK);
        fb_test_compose(&live, FLEET_BOARD_KIND_NOTE, "lane-a", "still live",
                        100, 1000);
        ASSERT_EQ(fleet_board_post_sign(&live, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &live, 100, NULL),
                  FLEET_BOARD_OK);

        fb_test_compose(&refused, FLEET_BOARD_KIND_NOTE, "lane-b", "no room",
                        200, 1000);
        ASSERT_EQ(fleet_board_post_sign(&refused, seed, pk), FLEET_BOARD_OK);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &refused, 200, &stored),
                  FLEET_BOARD_ERR_CAPACITY);
        ASSERT(!stored);
        ASSERT(!db_fleet_board_have(&db, refused.id));
        ASSERT(db_fleet_board_have(&db, wiki.id));
        ASSERT(db_fleet_board_have(&db, live.id));
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, 200, &status));
        ASSERT_EQ(status.posts, 2);
        int64_t checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 2);

        node_db_close(&db);
        db_fleet_board_test_set_store_limits(0, 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_store_limits(0, 0);
    return failures;
}

static int test_fleet_board_byte_boundary(void)
{
    int failures = 0;
    TEST("fleet board: byte capacity refuses a live append") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(8, seed, pk);
        struct fleet_board_post first, second;
        fb_test_compose(&first, FLEET_BOARD_KIND_NOTE, "a", "first", 300, 1000);
        fb_test_compose(&second, FLEET_BOARD_KIND_NOTE, "b", "second", 301, 1000);
        ASSERT_EQ(fleet_board_post_sign(&first, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&second, seed, pk), FLEET_BOARD_OK);
        size_t first_bytes = 0, second_bytes = 0;
        ASSERT_EQ(fleet_board_post_canonical(&first, NULL, 0, &first_bytes),
                  FLEET_BOARD_ERR_CAPACITY);
        ASSERT_EQ(fleet_board_post_canonical(&second, NULL, 0, &second_bytes),
                  FLEET_BOARD_ERR_CAPACITY);
        db_fleet_board_test_set_store_limits(
            10, (int64_t)(first_bytes + second_bytes - 1));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &first, 300, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &second, 301, NULL),
                  FLEET_BOARD_ERR_CAPACITY);
        ASSERT(!db_fleet_board_have(&db, second.id));
        node_db_close(&db);
        db_fleet_board_test_set_store_limits(0, 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_store_limits(0, 0);

    return failures;
}

static int test_fleet_board_corrupt_reads(void)
{
    int failures = 0;
    TEST("fleet board: corrupted body id and signature all fail closed on read") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(10, seed, pk);
        struct fleet_board_post posts[3];
        const char *agents[] = {"body", "identifier", "signature"};
        for (size_t i = 0; i < 3; i++) {
            fb_test_compose(&posts[i], FLEET_BOARD_KIND_NOTE, agents[i],
                            "verified before storage", 600 + i, 1000);
            ASSERT_EQ(fleet_board_post_sign(&posts[i], seed, pk), FLEET_BOARD_OK);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &posts[i], 600, NULL),
                      FLEET_BOARD_OK);
        }
        ASSERT(node_db_exec(&db,
            "UPDATE fleet_board_posts SET text='altered' WHERE agent='body'"));
        ASSERT(node_db_exec(&db,
            "UPDATE fleet_board_posts SET id=zeroblob(32) WHERE agent='identifier'"));
        ASSERT(node_db_exec(&db,
            "UPDATE fleet_board_posts SET signature=zeroblob(64) "
            "WHERE agent='signature'"));

        struct db_fleet_board_post row;
        for (size_t i = 0; i < 3; i++)
            ASSERT(!db_fleet_board_post_find(&db, posts[i].id, &row));
        struct db_fleet_board_post rows[4];
        ASSERT_EQ(db_fleet_board_list(&db, NULL, 600, rows, 4), 0);
        int64_t checked = 0;
        ASSERT(!db_fleet_board_chain_verify(&db, &checked));
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

extern void (*db_fleet_board_inventory_row_for_testing)(sqlite3_stmt *, int);
static bool fb_inventory_excess;
static int fb_inventory_injected;
static int fb_inventory_injection_rc;

static void fb_inventory_interrupt(sqlite3_stmt *s, int count)
{
    if (fb_inventory_injected || count != (fb_inventory_excess ? 0 : 1))
        return;
    fb_inventory_injected++;
    fb_inventory_injection_rc = sqlite3_reset(s);
    if (fb_inventory_injection_rc == SQLITE_OK)
        fb_inventory_injection_rc = sqlite3_bind_int(
            s, sqlite3_bind_parameter_count(s), fb_inventory_excess ? 3 : 1);
}

/* Larger physical backing makes the old bug fail safely at the canaries. */
static bool fb_inventory_interrupted_page(struct node_db *db, bool excess)
{
    uint8_t ids[4][32];
    memset(ids, 0xa5, sizeof(ids));
    int64_t cursor = 999;
    fb_inventory_excess = excess;
    fb_inventory_injected = 0;
    fb_inventory_injection_rc = SQLITE_ERROR;
    db_fleet_board_inventory_row_for_testing = fb_inventory_interrupt;
    int result = db_fleet_board_ids_before(db, 800, 0, true, ids, 2, &cursor);
    db_fleet_board_inventory_row_for_testing = NULL;
    uint8_t cleared[2][32] = {{0}};
    uint8_t guard[2][32];
    memset(guard, 0xa5, sizeof(guard));
    return result == -1 && cursor == 0 && fb_inventory_injected == 1 &&
           fb_inventory_injection_rc == SQLITE_OK &&
           memcmp(ids, cleared, sizeof(cleared)) == 0 &&
           memcmp(ids + 2, guard, sizeof(guard)) == 0;
}

static int test_fleet_board_inventory_pages(void)
{
    int failures = 0;
    TEST("fleet board: inventory cursor reaches rows older than one frame") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(11, seed, pk);
        struct fleet_board_post post;
        uint8_t oldest[2][32];
        for (size_t i = 0; i < FLEET_BOARD_FRAME_IDS_MAX + 2; i++) {
            fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "pager", "page row",
                            700 + i, 1000);
            ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &post, 800, NULL),
                      FLEET_BOARD_OK);
            if (i < 2)
                memcpy(oldest[i], post.id, 32);
        }

        ASSERT(fb_inventory_interrupted_page(&db, false));
        ASSERT(fb_inventory_interrupted_page(&db, true));

        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        int64_t cursor = 0;
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, 0, true, ids, FLEET_BOARD_FRAME_IDS_MAX,
                      &cursor),
                  FLEET_BOARD_FRAME_IDS_MAX);
        ASSERT_EQ(cursor, 3);
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, cursor, true, ids, FLEET_BOARD_FRAME_IDS_MAX,
                      &cursor),
                  2);
        ASSERT_EQ(cursor, 1);
        ASSERT(memcmp(ids[0], oldest[1], 32) == 0);
        ASSERT(memcmp(ids[1], oldest[0], 32) == 0);
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, cursor, true, ids, FLEET_BOARD_FRAME_IDS_MAX,
                      &cursor),
                  0);
        ASSERT_EQ(cursor, 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* The fixed peer table is a cap, not a churn-resettable cache. */
static int test_fleet_board_peer_churn_limits(void)
{
    int failures = 0;
    TEST("fleet board: peer churn cannot reset receive or announce budgets") {
        const int64_t now = 100;
        boot_fleet_board_wire(NULL);
        for (int64_t peer = 1; peer <= FLEET_BOARD_PEER_SLOTS; peer++) {
            ASSERT(boot_fleet_board_admit_for_testing(peer, now));
            ASSERT(boot_fleet_board_announce_due_for_testing(peer, now));
        }
        for (unsigned frame = 1;
             frame < FLEET_BOARD_PEER_FRAMES_PER_WINDOW; frame++)
            for (int64_t peer = 1; peer <= FLEET_BOARD_PEER_SLOTS; peer++)
                ASSERT(boot_fleet_board_admit_for_testing(peer, now));
        ASSERT(!boot_fleet_board_admit_for_testing(1, now));
        ASSERT(!boot_fleet_board_announce_due_for_testing(1, now));
        for (int64_t peer = FLEET_BOARD_PEER_SLOTS + 1;
             peer <= FLEET_BOARD_PEER_SLOTS * 3; peer++) {
            ASSERT(!boot_fleet_board_admit_for_testing(peer, now));
            ASSERT(!boot_fleet_board_announce_due_for_testing(peer, now));
        }
        ASSERT(boot_fleet_board_admit_for_testing(
            1, now + FLEET_BOARD_PEER_WINDOW_SECONDS));
        ASSERT(!boot_fleet_board_admit_for_testing(
            FLEET_BOARD_PEER_SLOTS + 1,
            now + FLEET_BOARD_PEER_WINDOW_SECONDS));
        ASSERT(boot_fleet_board_admit_for_testing(
            FLEET_BOARD_PEER_SLOTS + 1,
            now + FLEET_BOARD_SLOT_PROTECT_SECONDS));
        ASSERT(boot_fleet_board_announce_due_for_testing(
            FLEET_BOARD_PEER_SLOTS + 1,
            now + FLEET_BOARD_SLOT_PROTECT_SECONDS));
        ASSERT(boot_fleet_board_announce_due_for_testing(
            1, now + FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS));
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    return failures;
}

static int test_fleet_board_peer_inventory_cursor(void)
{
    int failures = 0;
    TEST("fleet board: a sent inventory page advances one peer cursor") {
        boot_fleet_board_wire(NULL);
        ASSERT(boot_fleet_board_announce_due_for_testing(7, 100));
        ASSERT_EQ(boot_fleet_board_inventory_cursor_for_testing(7), 0);
        ASSERT(boot_fleet_board_inventory_cursor_commit_for_testing(
            7, 0, 129, false));
        ASSERT_EQ(boot_fleet_board_inventory_cursor_for_testing(7), 129);
        ASSERT(!boot_fleet_board_inventory_cursor_commit_for_testing(
            7, 0, 1, false));
        ASSERT_EQ(boot_fleet_board_inventory_cursor_for_testing(7), 129);
        ASSERT(boot_fleet_board_inventory_cursor_commit_for_testing(
            7, 129, 0, true));
        ASSERT_EQ(boot_fleet_board_inventory_cursor_for_testing(7), 0);
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    return failures;
}

static int test_fleet_board_wiki(void)
{
    int failures = 0;
    TEST("fleet board: a wiki page revises without losing its history") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));

        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);
        const int64_t now = 200000;

        struct fleet_board_post v1;
        fb_test_compose(&v1, FLEET_BOARD_KIND_WIKI, "lane-a",
                        "The push gate runs the full lint, not lint-fast.",
                        (uint64_t)now, 86400);
        (void)snprintf(v1.slug, sizeof(v1.slug), "%s", "push-gate");
        (void)snprintf(v1.title, sizeof(v1.title), "%s", "The push gate");
        ASSERT_EQ(fleet_board_post_sign(&v1, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &v1, now, NULL),
                  FLEET_BOARD_OK);

        struct db_fleet_board_post page;
        ASSERT(db_fleet_board_wiki_read(&db, "push-gate", &page));
        ASSERT(memcmp(page.post.id, v1.id, 32) == 0);

        /* A revision supersedes; it does not edit. */
        struct fleet_board_post v2;
        fb_test_compose(&v2, FLEET_BOARD_KIND_WIKI, "lane-b",
                        "The push gate runs the full lint AND waits on a "
                        "native proof receipt; budget 15 minutes per pair.",
                        (uint64_t)now + 60, 86400);
        (void)snprintf(v2.slug, sizeof(v2.slug), "%s", "push-gate");
        (void)snprintf(v2.title, sizeof(v2.title), "%s", "The push gate");
        memcpy(v2.supersedes, v1.id, 32);
        ASSERT_EQ(fleet_board_post_sign(&v2, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &v2, now, NULL),
                  FLEET_BOARD_OK);

        ASSERT(db_fleet_board_wiki_read(&db, "push-gate", &page));
        ASSERT(memcmp(page.post.id, v2.id, 32) == 0);
        ASSERT(memcmp(page.post.supersedes, v1.id, 32) == 0);

        /* Both revisions remain readable, newest first. */
        struct db_fleet_board_post history[8];
        ASSERT_EQ(db_fleet_board_wiki_history(&db, "push-gate", history, 8), 2);
        ASSERT(memcmp(history[0].post.id, v2.id, 32) == 0);
        ASSERT(memcmp(history[1].post.id, v1.id, 32) == 0);

        /* A second page shows up as its own row, once. */
        struct fleet_board_post other;
        fb_test_compose(&other, FLEET_BOARD_KIND_WIKI, "lane-a",
                        "Worktrees do not inherit submodules; run "
                        "make worktree-prime before building.",
                        (uint64_t)now + 5, 86400);
        (void)snprintf(other.slug, sizeof(other.slug), "%s", "worktrees");
        (void)snprintf(other.title, sizeof(other.title), "%s",
                       "Worktree gotchas");
        ASSERT_EQ(fleet_board_post_sign(&other, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &other, now, NULL),
                  FLEET_BOARD_OK);

        struct db_fleet_board_post pages[8];
        ASSERT_EQ(db_fleet_board_wiki_list(&db, pages, 8), 2);

        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, now, &status));
        ASSERT_EQ(status.wiki_pages, 2);

        /* An unknown slug is absent, not an error with a page in it. */
        ASSERT(!db_fleet_board_wiki_read(&db, "no-such-page", &page));

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Two independent node databases, driven through the real frame codec in wire
 * order. Node A never hands node B a struct: every byte B sees, B decoded. */
static int test_fleet_board_two_nodes(void)
{
    int failures = 0;
    TEST("fleet board: a post crosses from one node to another and verifies") {
        struct node_db a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        ASSERT(node_db_open(&a, ":memory:"));
        ASSERT(node_db_open(&b, ":memory:"));

        uint8_t seed_a[32], pk_a[32];
        fb_test_identity(1, seed_a, pk_a);
        const int64_t now = 300000;

        /* A posts a problem. */
        struct fleet_board_post problem;
        fb_test_compose(&problem, FLEET_BOARD_KIND_PROBLEM, "lane-a",
                        "who has a spare 32-core box for a params pass?",
                        (uint64_t)now, 3600);
        ASSERT_EQ(fleet_board_post_sign(&problem, seed_a, pk_a),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&a, &problem, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&b, problem.id));

        /* A announces its public inventory. */
        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        int n = db_fleet_board_recent_ids(&a, now, true, ids,
                                          FLEET_BOARD_FRAME_IDS_MAX);
        ASSERT_EQ(n, 1);
        uint8_t inv[FLEET_BOARD_FRAME_MAX];
        size_t inv_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids,
                                               (size_t)n, inv, sizeof(inv),
                                               &inv_len), FLEET_BOARD_OK);

        /* B decodes the inventory and asks only for what it lacks. */
        uint8_t heard[FLEET_BOARD_FRAME_IDS_MAX][32];
        uint8_t type = 0;
        size_t heard_n = 0;
        ASSERT_EQ(fleet_board_frame_decode_ids(inv, inv_len, &type, heard,
                                               FLEET_BOARD_FRAME_IDS_MAX,
                                               &heard_n), FLEET_BOARD_OK);
        ASSERT_EQ(type, FLEET_BOARD_FRAME_INV);
        uint8_t wanted[FLEET_BOARD_FRAME_IDS_MAX][32];
        size_t wanted_n = 0;
        for (size_t i = 0; i < heard_n; i++)
            if (!db_fleet_board_have(&b, heard[i]))
                memcpy(wanted[wanted_n++], heard[i], 32);
        ASSERT_EQ(wanted_n, 1u);
        uint8_t get[FLEET_BOARD_FRAME_MAX];
        size_t get_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_GET, wanted,
                                               wanted_n, get, sizeof(get),
                                               &get_len), FLEET_BOARD_OK);

        /* A serves the request. */
        size_t asked_n = 0;
        ASSERT_EQ(fleet_board_frame_decode_ids(get, get_len, &type, heard,
                                               FLEET_BOARD_FRAME_IDS_MAX,
                                               &asked_n), FLEET_BOARD_OK);
        ASSERT_EQ(type, FLEET_BOARD_FRAME_GET);
        ASSERT_EQ(asked_n, 1u);
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_post_find(&a, heard[0], &row));
        static uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                             FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t frame_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_post(&row.post, frame,
                                                sizeof(frame), &frame_len),
                  FLEET_BOARD_OK);

        /* B ingests what crossed. */
        struct fleet_board_post received;
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len, &received),
                  FLEET_BOARD_OK);
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&b, &received, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);
        ASSERT(db_fleet_board_have(&b, problem.id));

        struct db_fleet_board_post on_b;
        ASSERT(db_fleet_board_post_find(&b, problem.id, &on_b));
        ASSERT(strcmp(on_b.post.text, problem.text) == 0);
        ASSERT(memcmp(on_b.post.host_pubkey, pk_a, 32) == 0);
        /* B ends up with A's post but its OWN arrival order and chain — the
         * ledger is local evidence, never a shared ordering. */
        ASSERT_EQ(on_b.seq, 1);

        /* A tampered relay of the same post is refused by B. */
        frame[frame_len - 1] = (uint8_t)(frame[frame_len - 1] ^ 0x01);
        struct fleet_board_post bad;
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len, &bad),
                  FLEET_BOARD_ERR_SIGNATURE);

        /* B's --open view now shows A's question, and closes when B answers. */
        struct fleet_board_filter open_filter;
        memset(&open_filter, 0, sizeof(open_filter));
        open_filter.open_only = true;
        struct db_fleet_board_post rows[4];
        ASSERT_EQ(db_fleet_board_list(&b, &open_filter, now, rows, 4), 1);

        uint8_t seed_b[32], pk_b[32];
        fb_test_identity(2, seed_b, pk_b);
        struct fleet_board_post answer;
        fb_test_compose(&answer, FLEET_BOARD_KIND_RESULT, "lane-b",
                        "took it; gate green, receipt in the unit ledger",
                        (uint64_t)now + 10, 3600);
        memcpy(answer.ref, problem.id, 32);
        (void)snprintf(answer.receipt, sizeof(answer.receipt), "%s",
                       "unit=u-42 engine=grok gate=pass tokens=91004");
        ASSERT_EQ(fleet_board_post_sign(&answer, seed_b, pk_b),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&b, &answer, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_list(&b, &open_filter, now, rows, 4), 0);

        /* Both nodes' local chains still verify independently. */
        int64_t checked_a = 0, checked_b = 0;
        ASSERT(db_fleet_board_chain_verify(&a, &checked_a));
        ASSERT(db_fleet_board_chain_verify(&b, &checked_b));
        ASSERT_EQ(checked_a, 1);
        ASSERT_EQ(checked_b, 2);

        node_db_close(&a);
        node_db_close(&b);
        PASS();
    } _test_next:;
    return failures;
}

static bool fb_review_compose(struct fleet_board_post *post, uint8_t who,
    const uint8_t target[32], const uint8_t *parent, const char *verdict,
    const char *rationale, uint64_t now)
{
    char id[65], body[4096];
    fleet_board_id_to_hex(target, id);
    int written = snprintf(body, sizeof(body),
        "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
        "\"verdict\":\"%s\",\"rating\":%u,\"rationale\":\"%s\"}",
        id, verdict, !strcmp(verdict, "approve") ? 5u : 1u, rationale);
    if (written < 0 || (size_t)written >= sizeof(body)) return false;
    fb_test_compose(post, FLEET_BOARD_KIND_WIKI, "descriptive-agent", body, now, 60);
    post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    (void)snprintf(post->room, sizeof(post->room), "%s", FLEET_BOARD_ROOM_DEFAULT);
    (void)snprintf(post->slug, sizeof(post->slug), "peer-reviewed-page");
    (void)snprintf(post->title, sizeof(post->title), "Exact revision review");
    memcpy(post->ref, target, 32);
    if (parent) memcpy(post->supersedes, parent, 32);
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    return fleet_board_post_sign(post, seed, pk) == FLEET_BOARD_OK;
}

/* The receiver decodes INV, sends GET, then verifies decoded POST bytes.
 * Replay the same POST once more to qualify duplicate import idempotence. */
static bool fb_review_exchange_id(const uint8_t id[32], uint8_t heard[1][32])
{
    uint8_t ids[1][32], frame[FLEET_BOARD_FRAME_MAX], type;
    size_t len = 0, count = 0;
    memcpy(ids[0], id, 32);
    if (fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids, 1, frame,
            sizeof(frame), &len) != FLEET_BOARD_OK ||
        fleet_board_frame_decode_ids(frame, len, &type, heard, 1, &count) != FLEET_BOARD_OK ||
        type != FLEET_BOARD_FRAME_INV || count != 1 ||
        fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_GET, heard, count, frame,
            sizeof(frame), &len) != FLEET_BOARD_OK ||
        fleet_board_frame_decode_ids(frame, len, &type, heard, 1, &count) != FLEET_BOARD_OK ||
        type != FLEET_BOARD_FRAME_GET || count != 1) return false;
    return true;
}

static bool fb_review_converged_views(struct node_db *db,
    const struct fleet_board_post *root, const struct fleet_board_post *left,
    const struct fleet_board_post *right, const struct fleet_board_post *opposite)
{
    struct fleet_wiki_review_state state;
    if (!db_fleet_board_review_state(db, root, &state)) return false;
    bool ok = state.resolved;
    ok &= state.complete;
    ok &= !state.current;
    ok &= state.fork;
    const struct fleet_board_post *leaves[] = {left, right, opposite};
    for (size_t i = 0; i < 3; i++) {
        if (!db_fleet_board_review_state(db, leaves[i], &state)) return false;
        ok &= state.resolved;
        ok &= state.lineage_valid;
        ok &= state.complete;
        ok &= state.current;
        ok &= state.fork == (i < 2);
    }
    return ok;
}


static bool fb_review_transfer(struct node_db *from, struct node_db *to,
    const uint8_t id[32], int64_t now)
{
    uint8_t heard[1][32], frame[FLEET_BOARD_FRAME_MAX];
    size_t len = 0;
    if (!fb_review_exchange_id(id, heard)) return false;
    struct db_fleet_board_post row;
    if (!db_fleet_board_post_find(from, heard[0], &row) ||
        fleet_board_frame_encode_post(&row.post, frame, sizeof(frame), &len) != FLEET_BOARD_OK)
        return false;
    bool already = db_fleet_board_have(to, id);
    for (unsigned replay = 0; replay < 2; replay++) {
        struct fleet_board_post decoded;
        bool stored = false;
        if (fleet_board_frame_decode_post(frame, len, &decoded) != FLEET_BOARD_OK ||
            memcmp(decoded.id, id, 32) ||
            db_fleet_board_post_ingest(to, &decoded, now, &stored) != FLEET_BOARD_OK ||
            stored != (!already && replay == 0)) return false;
    }
    return true;
}

static int test_fleet_wiki_review_convergence(void)
{
    int failures = 0;
    struct node_db a = {0}, b = {0};
    TEST("fleet wiki reviews: reordered signed peer objects converge without hiding opposing opinions or forks") {
        ASSERT(node_db_open(&a, ":memory:")); ASSERT(node_db_open(&b, ":memory:"));
        const int64_t now = 900000;
        uint8_t seed[32], pk[32]; fb_test_identity(30, seed, pk);
        struct fleet_board_post target, root, left, right, opposite;
        fb_test_compose(&target, FLEET_BOARD_KIND_WIKI, "author", "immutable target", now, 60);
        target.scope = FLEET_BOARD_SCOPE_PUBLIC;
        (void)snprintf(target.room, sizeof(target.room), "%s", FLEET_BOARD_ROOM_DEFAULT);
        (void)snprintf(target.slug, sizeof(target.slug), "peer-reviewed-page");
        (void)snprintf(target.title, sizeof(target.title), "Reviewed page");
        ASSERT_EQ(fleet_board_post_sign(&target, seed, pk), FLEET_BOARD_OK);
        ASSERT(fb_review_compose(&root, 31, target.id, NULL, "approve", "initial", now + 1));
        ASSERT(fb_review_compose(&left, 31, target.id, root.id, "approve", "left branch", now + 3));
        ASSERT(fb_review_compose(&right, 31, target.id, root.id, "request-changes", "right branch", now + 2));
        ASSERT(fb_review_compose(&opposite, 32, target.id, NULL, "request-changes", "independent reviewer", now + 4));
        ASSERT_EQ(db_fleet_board_post_ingest(&a, &target, now + 4, NULL), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&a, &root, now + 4, NULL), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&a, &left, now + 4, NULL), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&b, &right, now + 4, NULL), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&b, &opposite, now + 4, NULL), FLEET_BOARD_OK);
        struct fleet_wiki_review_state state;
        ASSERT(db_fleet_board_review_state(&b, &right, &state));
        ASSERT(!state.resolved && !state.lineage_valid && !state.current);
        ASSERT(fb_review_transfer(&b, &a, right.id, now + 4));
        ASSERT(fb_review_transfer(&a, &b, left.id, now + 4));
        ASSERT(fb_review_transfer(&b, &a, opposite.id, now + 4));
        ASSERT(fb_review_transfer(&a, &b, target.id, now + 4));
        ASSERT(db_fleet_board_review_state(&b, &right, &state));
        ASSERT(state.resolved && !state.lineage_valid && !state.current);
        ASSERT(fb_review_transfer(&a, &b, root.id, now + 4));
        struct fleet_board_post *objects[] = {&target, &root, &left, &right, &opposite};
        for (size_t i = 0; i < 5; i++) {
            struct db_fleet_board_post on_a, on_b;
            ASSERT(db_fleet_board_post_find(&a, objects[i]->id, &on_a));
            ASSERT(db_fleet_board_post_find(&b, objects[i]->id, &on_b));
            uint8_t wire_a[FLEET_BOARD_FRAME_MAX], wire_b[FLEET_BOARD_FRAME_MAX];
            size_t len_a = 0, len_b = 0;
            ASSERT_EQ(fleet_board_frame_encode_post(&on_a.post, wire_a, sizeof(wire_a), &len_a), FLEET_BOARD_OK);
            ASSERT_EQ(fleet_board_frame_encode_post(&on_b.post, wire_b, sizeof(wire_b), &len_b), FLEET_BOARD_OK);
            ASSERT_EQ(len_a, len_b); ASSERT(memcmp(wire_a, wire_b, len_a) == 0);
        }
        struct node_db *nodes[] = {&a, &b};
        for (size_t i = 0; i < 2; i++) {
            ASSERT(fb_review_converged_views(nodes[i], &root, &left, &right, &opposite));
            int64_t checked = 0;
            ASSERT(db_fleet_board_chain_verify(nodes[i], &checked)); ASSERT_EQ(checked, 5);
        }
        uint8_t after[32] = {0}, cursor[32]; size_t count_a, count_b; bool more_a, more_b;
        struct db_fleet_board_post rows_a[4], rows_b[4];
        ASSERT(db_fleet_board_wiki_reviews(&a, target.id, after, rows_a, 4, &count_a, cursor, &more_a));
        ASSERT(db_fleet_board_wiki_reviews(&b, target.id, after, rows_b, 4, &count_b, cursor, &more_b));
        ASSERT_EQ(count_a, 4); ASSERT_EQ(count_b, 4); ASSERT(!more_a && !more_b);
        for (size_t i = 0; i < count_a; i++) ASSERT(memcmp(rows_a[i].post.id, rows_b[i].post.id, 32) == 0);
        PASS();
    } _test_next:;
    if (a.open) node_db_close(&a);
    if (b.open) node_db_close(&b);
    return failures;
}


static bool fb_test_busy_frame(struct node_db *db, struct msg_processor *mp,
    struct p2p_node *node, const uint8_t *frame, size_t frame_len,
    const uint8_t post_id[32])
{
    if (!node_db_begin(db)) return false;
    int changes = sqlite3_total_changes(db->db);
    int score = atomic_load(&node->misbehavior);
    bool handled = boot_fleet_board_frame(mp, node, frame, frame_len, NULL);
    bool absent = !db_fleet_board_have(db, post_id);
    bool unchanged = changes == sqlite3_total_changes(db->db);
    bool unpenalized = score == atomic_load(&node->misbehavior);
    bool restored = node_db_rollback(db);
    return restored && handled && absent && unchanged && unpenalized;
}

/* Write-lock contention: one connection holds the write lock, and the
 * other's append meets SQLITE_BUSY inside the insert. */
static int test_fleet_board_busy_append_names_contention(void)
{
    int failures = 0;
    TEST("fleet board: a write-locked database is contention, not a bad argument") {
        char dbdir[256];
        char dbpath[320];
        struct node_db writer, board;
        memset(&writer, 0, sizeof(writer));
        memset(&board, 0, sizeof(board));
        test_make_tmpdir(dbdir, sizeof(dbdir), "fleet_board_busy", "zcl");
        (void)snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        ASSERT(node_db_open(&board, dbpath));
        ASSERT(node_db_open(&writer, dbpath));
        /* Fail fast rather than spend the production 10 s busy timeout. */
        (void)sqlite3_busy_timeout(board.db, 0);
        db_fleet_board_test_clear_quarantine();

        uint8_t seed[32], pk[32];
        fb_test_identity(9, seed, pk);
        struct fleet_board_post post;
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "lane-busy",
                        "append meets a locked database", 100, 1000);
        ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);

        /* The OTHER connection holds the write lock. This board connection
         * has no transaction of its own, so it reaches the append. */
        ASSERT(node_db_begin_immediate(&writer));
        struct node_db_status status;
        node_db_get_status(&board, &status);
        ASSERT(!status.tx_open);

        bool stored = true;
        enum fleet_board_result r =
            db_fleet_board_post_ingest(&board, &post, 100, &stored);
        ASSERT_STR_EQ(fleet_board_result_string(r),
                      "board database transaction is busy");
        ASSERT(!stored && !db_fleet_board_have(&board, post.id));

        /* Contention is never quarantined: once the lock clears, the very
         * same post appends, so the board recovers with no restart. */
        ASSERT(node_db_rollback(&writer));
        ASSERT_EQ(db_fleet_board_post_ingest(&board, &post, 100, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored && db_fleet_board_have(&board, post.id));

        node_db_close(&writer);
        node_db_close(&board);
        PASS();
    } _test_next:;
    return failures;
}

/* An append the store refuses every round must not be retried forever nor
 * block the posts behind it. */
static int test_fleet_board_permanent_refusal_quarantines(void)
{
    int failures = 0;
    TEST("fleet board: a permanently rejected post is quarantined, others keep landing") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_clear_quarantine();

        uint8_t seed[32], pk[32];
        fb_test_identity(13, seed, pk);
        struct fleet_board_post first, poison, other;
        fb_test_compose(&first, FLEET_BOARD_KIND_NOTE, "lane-poison",
                        "first post by this agent", 100, 1000);
        ASSERT_EQ(fleet_board_post_sign(&first, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &first, 100, NULL),
                  FLEET_BOARD_OK);

        /* A constraint this post can never satisfy, so the append fails
         * identically every time gossip re-offers the id. */
        ASSERT(node_db_exec(&db,
            "CREATE UNIQUE INDEX fb_one_post_per_agent "
            "ON fleet_board_posts(agent)"));

        fb_test_compose(&poison, FLEET_BOARD_KIND_NOTE, "lane-poison",
                        "second post by the same agent", 101, 1000);
        ASSERT_EQ(fleet_board_post_sign(&poison, seed, pk), FLEET_BOARD_OK);
        bool stored = true;
        enum fleet_board_result r =
            db_fleet_board_post_ingest(&db, &poison, 101, &stored);
        /* A well-formed, signed, admissible post is never reported as a
         * missing argument. */
        ASSERT(strcmp(fleet_board_result_string(r), "missing argument") != 0);
        ASSERT_EQ(r, FLEET_BOARD_ERR_STORAGE);
        ASSERT(!stored && !db_fleet_board_have(&db, poison.id));

        /* Quarantined: the refusal stands even once the constraint is gone,
         * so gossip cannot spend every round re-failing one id. */
        ASSERT(node_db_exec(&db, "DROP INDEX fb_one_post_per_agent"));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &poison, 102, &stored),
                  FLEET_BOARD_ERR_STORAGE);

        /* And the board never wedged: an unrelated post still appends. */
        fb_test_compose(&other, FLEET_BOARD_KIND_NOTE, "lane-clean",
                        "an unrelated post still lands", 103, 1000);
        ASSERT_EQ(fleet_board_post_sign(&other, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &other, 103, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored && db_fleet_board_have(&db, other.id));

        db_fleet_board_test_clear_quarantine();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_local_capacity_does_not_score_peer(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db;
    memset(&db, 0, sizeof(db));
    TEST("fleet board: local capacity is a drop, future payload is an offence") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t seed[32], pk[32];
        struct fleet_board_post resident, capacity, future;
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t frame_len = 0;
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        struct boot_svc_ctx svc;

        peer_scoring_init();
        memset(&nm, 0, sizeof(nm));
        memset(&mp, 0, sizeof(mp));
        memset(&svc, 0, sizeof(svc));
        mp.net_mgr = &nm;
        svc.node_db = &db;
        svc.msg_processor = &mp;
        memset(&node, 0, sizeof(node));
        node.id = 41;
        (void)snprintf(node.addr_name, sizeof(node.addr_name), "%s", "board-fixture");
        node.addr.svc.addr.ip[10] = 0xff;
        node.addr.svc.addr.ip[11] = 0xff;
        node.addr.svc.addr.ip[12] = 198;
        node.addr.svc.addr.ip[13] = 51;
        node.addr.svc.addr.ip[14] = 100;
        node.addr.svc.addr.ip[15] = 7;

        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        db_fleet_board_test_set_store_limits(1, 1024 * 1024);
        boot_fleet_board_wire(&svc);

        fb_test_identity(11, seed, pk);
        fb_test_compose(&resident, FLEET_BOARD_KIND_NOTE, "score-fixture",
                        "resident fills the local store", now, 3600);
        ASSERT_EQ(fleet_board_post_sign(&resident, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &resident, now, NULL),
                  FLEET_BOARD_OK);

        fb_test_compose(&capacity, FLEET_BOARD_KIND_NOTE, "score-fixture",
                        "valid post meets local capacity", now, 3600);
        ASSERT_EQ(fleet_board_post_sign(&capacity, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_frame_encode_post(&capacity, frame, sizeof(frame),
                                                &frame_len), FLEET_BOARD_OK);
        int score_before = atomic_load(&node.misbehavior);
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, frame_len, NULL));
        ASSERT_EQ(atomic_load(&node.misbehavior), score_before);
        ASSERT(!db_fleet_board_have(&db, capacity.id));

        db_fleet_board_test_set_store_limits(10, 1024 * 1024);
        ASSERT(fb_test_busy_frame(&db, &mp, &node, frame, frame_len, capacity.id));

        fb_test_compose(&future, FLEET_BOARD_KIND_NOTE, "score-fixture",
                        "signed future post remains sender fault",
                        now + FLEET_BOARD_FUTURE_SKEW_MAX + 60, 3600);
        ASSERT_EQ(fleet_board_post_sign(&future, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_frame_encode_post(&future, frame, sizeof(frame),
                                                &frame_len), FLEET_BOARD_OK);
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, frame_len, NULL));
        ASSERT_EQ(atomic_load(&node.misbehavior),
                  score_before + peer_offence_weight(PEER_OFFENCE_INVALID_PAYLOAD));
        ASSERT(!node.disconnect);
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    db_fleet_board_test_set_store_limits(0, 0);
    return failures;
}

static int test_fleet_board_waits_for_peer_handshake(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db = {0};
    struct net_manager nm;
    struct p2p_node *node = NULL;
    net_manager_init(&nm);
    TEST("fleet board: inventory waits for an eligible completed handshake") {
        const struct chain_params *params = chain_params_get();
        const int64_t now = (int64_t)platform_time_wall_time_t();
        struct msg_processor mp = {.params = params, .net_mgr = &nm};
        struct boot_svc_ctx svc = {.node_db = &db, .msg_processor = &mp,
                                   .params = params};
        struct net_address addr;
        uint8_t seed[32], pk[32];
        struct fleet_board_post post;

        ASSERT(params != NULL);
        net_address_init(&addr);
        uint8_t ip4[4] = {192, 0, 2, 44};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8233;
        node = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr,
                               "board-handshake", false);
        ASSERT(node != NULL);
        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&svc);

        fb_test_identity(15, seed, pk);
        fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "handshake-fixture",
                        "announce only after version and verack", now, 3600);
        ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &post, now, NULL),
                  FLEET_BOARD_OK);
        node->services = NODE_NETWORK | NODE_ZCL23;
        ASSERT(peer_set_state_checked((uint32_t)node->id, &node->state,
                                      PEER_CONNECTED, "fixture connected"));
        ASSERT(peer_set_state_checked((uint32_t)node->id, &node->state,
                                      PEER_VERSION_SENT, "fixture version"));
        boot_fleet_board_tick(&mp, node, &svc);
        ASSERT_EQ(node->send_size, 0u);

        ASSERT(peer_set_state_checked((uint32_t)node->id, &node->state,
                                      PEER_HANDSHAKE_COMPLETE,
                                      "fixture verack"));
        node->services = NODE_NETWORK;
        boot_fleet_board_tick(&mp, node, &svc);
        ASSERT_EQ(node->send_size, 0u);
        node->services |= NODE_ZCL23;
        boot_fleet_board_tick(&mp, node, &svc);
        ASSERT(node->send_size > 0);

        size_t sent = node->send_size;
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&svc);
        atomic_store(&node->disconnect, true);
        boot_fleet_board_tick(&mp, node, &svc);
        ASSERT_EQ(node->send_size, sent);
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    if (node)
        p2p_node_free(node);
    net_manager_free(&nm);
    return failures;
}

static int test_fleet_board_durable_wiki(void)
{
    int failures = 0;
    TEST("fleet board: a fresh peer recovers exact wiki history after TTL") {
        struct node_db publisher = {0}, receiver = {0};
        ASSERT(node_db_open(&publisher, ":memory:"));
        ASSERT(node_db_open(&receiver, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(12, seed, pk);
        struct fleet_board_post wiki, discussion;
        fb_test_compose(&wiki, FLEET_BOARD_KIND_WIKI, "historian",
                        "Decisions remain reproducible after their author leaves.", 100, 60);
        (void)snprintf(wiki.slug, sizeof(wiki.slug), "%s", "development-decisions");
        (void)snprintf(wiki.title, sizeof(wiki.title), "%s", "Development decisions");
        ASSERT_EQ(fleet_board_post_sign(&wiki, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&publisher, &wiki, 100, NULL), FLEET_BOARD_OK);
        const int64_t later = 100 + FLEET_BOARD_TTL_MAX + 1;
        uint8_t ids[1][32];
        ASSERT_EQ(db_fleet_board_recent_ids(&publisher, later, true, ids, 1), 1);
        ASSERT(memcmp(ids[0], wiki.id, 32) == 0);
        uint8_t frame[FLEET_BOARD_FRAME_MAX];
        size_t frame_len = 0;
        ASSERT_EQ(fleet_board_frame_encode_post(&wiki, frame, sizeof(frame),
                                               &frame_len), FLEET_BOARD_OK);
        node_db_close(&publisher);
        struct fleet_board_post received;
        ASSERT_EQ(fleet_board_frame_decode_post(frame, frame_len, &received), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&receiver, &received, later, NULL), FLEET_BOARD_OK);
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_wiki_read(&receiver, wiki.slug, &row));
        ASSERT_EQ(fleet_board_post_verify(&row.post), FLEET_BOARD_OK);
        ASSERT(memcmp(row.post.id, wiki.id, 32) == 0);
        ASSERT(memcmp(row.post.signature, wiki.signature, 64) == 0);
        fb_test_compose(&discussion, FLEET_BOARD_KIND_NOTE, "historian",
                        "Ordinary discussion still expires.", 100, 60);
        ASSERT_EQ(fleet_board_post_sign(&discussion, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&receiver, &discussion, later, NULL),
                  FLEET_BOARD_ERR_EXPIRED);
        node_db_close(&receiver);
        PASS();
    } _test_next:;
    return failures;
}

static bool fb_rpc_show_request(bool ok, struct rpc_table *table,
                                const char *id, struct json_value *params,
                                struct json_value *input,
                                struct json_value *result)
{
    return ok && json_push_kv_str(input, "op", "show") &&
           json_push_kv_str(input, "id", id) &&
           json_push_back(params, input) &&
           rpc_table_execute(table, "fleet_board", params, result) &&
           json_get_bool(json_get(result, "ok"));
}

static bool fb_rpc_check_show_reply(bool ok, struct json_value *result,
                                    const struct fleet_board_post *post,
                                    struct fleet_board_post *reconstructed)
{
    const char *agent = json_get_str(json_get(result, "agent"));
    const char *body = json_get_str(json_get(result, "text"));
    const char *slug = json_get_str(json_get(result, "slug"));
    const char *title = json_get_str(json_get(result, "title"));
    ok = ok && agent && body && slug && title;
    if (ok) {
        fb_test_compose(reconstructed, FLEET_BOARD_KIND_WIKI, agent, body,
            (uint64_t)json_get_int(json_get(result, "created_at")),
            (uint32_t)json_get_int(json_get(result, "ttl")));
        (void)snprintf(reconstructed->slug, sizeof(reconstructed->slug),
                       "%s", slug);
        (void)snprintf(reconstructed->title, sizeof(reconstructed->title),
                       "%s", title);
        ok = fleet_board_kind_from_name(
                 json_get_str(json_get(result, "kind")),
                 &reconstructed->kind) &&
             zcl_hex_decode(json_get_str(json_get(result, "id")),
                            reconstructed->id, 32) &&
             zcl_hex_decode(json_get_str(json_get(result, "host")),
                            reconstructed->host_pubkey, 32) &&
             zcl_hex_decode(json_get_str(json_get(result, "ref")),
                            reconstructed->ref, 32) &&
             zcl_hex_decode(json_get_str(json_get(result, "supersedes")),
                            reconstructed->supersedes, 32) &&
             zcl_hex_decode(json_get_str(json_get(result, "signature")),
                            reconstructed->signature, 64) &&
             json_get_int(json_get(result, "text_len")) ==
                 reconstructed->text_len &&
             fleet_board_post_verify(reconstructed) == FLEET_BOARD_OK &&
             memcmp(reconstructed->id, post->id, 32) == 0;
    }
    return ok;
}

static int test_fleet_board_rpc_verification(void)
{
    int failures = 0;
    TEST("fleet board: RPC exposes verifiable signatures and status creates no key") {
        struct node_db db = {0};
        ASSERT(node_db_open(&db, ":memory:"));
        char dir[256], key_path[320];
        test_make_tmpdir(dir, sizeof(dir), "fleetboard", "rpc");
        (void)snprintf(key_path, sizeof(key_path), "%s/zcode/dht-online.key", dir);
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        struct boot_svc_ctx svc = {.node_db = &db, .datadir = dir};
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        struct rpc_table table;
        rpc_table_init(&table);
        boot_fleet_board_register_rpc(&table);
        char warmup_status[256];
        bool was_warming_up = rpc_is_in_warmup(warmup_status, sizeof(warmup_status));
        set_rpc_warmup_finished();
        struct json_value params, input, result;
        json_init(&params); json_init(&input); json_init(&result);
        json_set_array(&params); json_set_object(&input);
        bool ok = access(key_path, F_OK) != 0 &&
                  json_push_kv_str(&input, "op", "status") &&
                  json_push_back(&params, &input) &&
                  rpc_table_execute(&table, "fleet_board", &params, &result) &&
                  json_get_bool(json_get(&result, "ok")) &&
                  access(key_path, F_OK) != 0;
        uint8_t public_key[32];
        ok = ok && !boot_fleet_board_public_identity(public_key);
        if (!ok) {
            char diagnostic[1024];
            json_write(&result, diagnostic, sizeof(diagnostic));
            fprintf(stderr, "fleet board: read-only RPC status failed: %s\n", diagnostic);
        }
        json_free(&params); json_free(&input); json_free(&result);
        json_init(&params); json_init(&input); json_init(&result);

        uint8_t seed[32], pk[32];
        fb_test_identity(3, seed, pk);
        int64_t now = (int64_t)platform_time_wall_time_t();
        struct fleet_board_post post;
        fb_test_compose(&post, FLEET_BOARD_KIND_WIKI, "verifier",
                        "Verify machine access in both directions.\n", now, 3600);
        (void)snprintf(post.slug, sizeof(post.slug), "%s", "machine-access");
        (void)snprintf(post.title, sizeof(post.title), "%s", "Machine access");
        post.ref[0] = 5;
        post.supersedes[0] = 7;
        ok = ok && fleet_board_post_sign(&post, seed, pk) == FLEET_BOARD_OK &&
             db_fleet_board_post_ingest(&db, &post, now, NULL) == FLEET_BOARD_OK;
        if (!ok)
            fprintf(stderr, "fleet board: RPC fixture post was not admitted\n");
        char id[65];
        fleet_board_id_to_hex(post.id, id);
        json_set_array(&params); json_set_object(&input);
        ok = fb_rpc_show_request(ok, &table, id, &params, &input, &result);
        struct fleet_board_post reconstructed = {0};
        if (!ok) {
            char diagnostic[1024];
            json_write(&result, diagnostic, sizeof(diagnostic));
            fprintf(stderr, "fleet board: show RPC failed: %s\n", diagnostic);
        }
        ok = fb_rpc_check_show_reply(ok, &result, &post, &reconstructed);
        json_free(&params); json_free(&input); json_free(&result);
        app_runtime_set_current(NULL);
        if (was_warming_up)
            set_rpc_warmup_started(warmup_status);
        boot_fleet_board_shutdown();
        node_db_close(&db);
        test_rm_rf(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

struct fb_rpc_reader {
    const struct rpc_table *table;
    const char *agent;
    char host[65];
    atomic_int *ready;
    atomic_bool *go;
    bool ok;
};

static bool fb_rpc_verify_item_post(const struct json_value *item,
                                    const char *agent, const char *text,
                                    const char *kind, const char *host,
                                    const char *id, const char *ref,
                                    const char *signature)
{
    struct fleet_board_post post;
    memset(&post, 0, sizeof(post));
    size_t text_len = strlen(text);
    if (text_len > FLEET_BOARD_WIKI_TEXT_MAX ||
        !fleet_board_kind_from_name(kind, &post.kind) ||
        !zcl_hex_decode(id, post.id, sizeof(post.id)) ||
        !zcl_hex_decode(host, post.host_pubkey, sizeof(post.host_pubkey)) ||
        !zcl_hex_decode(ref, post.ref, sizeof(post.ref)) ||
        !zcl_hex_decode(signature, post.signature, sizeof(post.signature)))
        return false;
    post.created_at = (uint64_t)json_get_int(json_get(item, "created_at"));
    post.ttl = (uint32_t)json_get_int(json_get(item, "ttl"));
    post.text_len = (uint32_t)text_len;
    memcpy(post.text, text, text_len + 1);
    (void)snprintf(post.agent, sizeof(post.agent), "%s", agent);
    return json_get_int(json_get(item, "text_len")) == (int64_t)text_len &&
           fleet_board_post_verify(&post) == FLEET_BOARD_OK;
}

static bool fb_rpc_verify_item(const struct json_value *item,
                               const struct fb_rpc_reader *reader)
{
    const char *agent = json_get_str(json_get(item, "agent"));
    const char *text = json_get_str(json_get(item, "text"));
    const char *kind = json_get_str(json_get(item, "kind"));
    const char *host = json_get_str(json_get(item, "host"));
    const char *id = json_get_str(json_get(item, "id"));
    const char *ref = json_get_str(json_get(item, "ref"));
    const char *signature = json_get_str(json_get(item, "signature"));
    if (!agent || !text || !kind || !host || !id || !ref || !signature ||
        strcmp(agent, reader->agent) != 0 || strcmp(host, reader->host) != 0)
        return false;

    return fb_rpc_verify_item_post(item, agent, text, kind, host, id, ref,
                                   signature);
}

static void *fb_rpc_reader_main(void *opaque)
{
    struct fb_rpc_reader *reader = opaque;
    struct json_value params, input;
    json_init(&params);
    json_init(&input);
    json_set_array(&params);
    json_set_object(&input);
    reader->ok = json_push_kv_str(&input, "op", "list") &&
                 json_push_kv_str(&input, "host", reader->host) &&
                 json_push_kv_int(&input, "limit", 128) &&
                 json_push_back(&params, &input);
    atomic_fetch_add_explicit(reader->ready, 1, memory_order_release);
    while (!atomic_load_explicit(reader->go, memory_order_acquire))
        platform_sleep_ms(1);

    for (int pass = 0; reader->ok && pass < 32; pass++) {
        struct json_value result;
        json_init(&result);
        reader->ok = rpc_table_execute(reader->table, "fleet_board", &params,
                                       &result);
        const struct json_value *posts = json_get(&result, "posts");
        reader->ok = reader->ok && posts && json_size(posts) == 128;
        for (size_t i = 0; reader->ok && i < json_size(posts); i++)
            reader->ok = fb_rpc_verify_item(json_at(posts, i), reader);
        json_free(&result);
    }
    json_free(&params);
    json_free(&input);
    return NULL;
}

static int test_fleet_board_rpc_concurrency(void)
{
    int failures = 0;
    TEST("fleet board: concurrent registered RPC lists own verified snapshots") {
        struct node_db db = {0};
        ASSERT(node_db_open(&db, ":memory:"));
        int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t seeds[2][32], keys[2][32];
        const char *agents[2] = {"reader-a", "reader-b"};
        for (size_t lane = 0; lane < 2; lane++) {
            fb_test_identity((uint8_t)(20 + lane), seeds[lane], keys[lane]);
            for (size_t i = 0; i < 128; i++) {
                struct fleet_board_post post;
                char text[64];
                (void)snprintf(text, sizeof(text), "lane=%zu row=%zu", lane, i);
                fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, agents[lane],
                                text, (uint64_t)(now - (int64_t)i), 3600);
                ASSERT_EQ(fleet_board_post_sign(&post, seeds[lane], keys[lane]),
                          FLEET_BOARD_OK);
                ASSERT_EQ(db_fleet_board_post_ingest(&db, &post, now, NULL),
                          FLEET_BOARD_OK);
            }
        }

        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);
        struct rpc_table table;
        rpc_table_init(&table);
        boot_fleet_board_register_rpc(&table);
        char warmup_status[256];
        bool was_warming_up =
            rpc_is_in_warmup(warmup_status, sizeof(warmup_status));
        set_rpc_warmup_finished();

        /* Machine capacity is private unless an operator writes public post
         * text; the removed shortcut stays unavailable and appends nothing. */
        struct fleet_board_status before, after;
        ASSERT(db_fleet_board_status(&db, now, &before));
        struct json_value offer_params, offer_input, offer_result;
        json_init(&offer_params);
        json_init(&offer_input);
        json_init(&offer_result);
        json_set_array(&offer_params);
        json_set_object(&offer_input);
        ASSERT(json_push_kv_str(&offer_input, "op", "offer_cpu"));
        ASSERT(json_push_kv_int(&offer_input, "cores", 64));
        ASSERT(json_push_kv_int(&offer_input, "free_slots", 8));
        ASSERT(json_push_back(&offer_params, &offer_input));
        ASSERT(rpc_table_execute(&table, "fleet_board", &offer_params,
                                 &offer_result));
        ASSERT(!json_get_bool(json_get(&offer_result, "ok")));
        ASSERT(strcmp(json_get_str(json_get(&offer_result, "code")),
                      "UNKNOWN_OP") == 0);
        ASSERT(db_fleet_board_status(&db, now, &after));
        ASSERT_EQ(after.posts, before.posts);
        json_free(&offer_params);
        json_free(&offer_input);
        json_free(&offer_result);

        atomic_int ready = 0;
        atomic_bool go = false;
        struct fb_rpc_reader readers[2] = {
            {.table = &table, .agent = agents[0], .ready = &ready, .go = &go},
            {.table = &table, .agent = agents[1], .ready = &ready, .go = &go},
        };
        fleet_board_id_to_hex(keys[0], readers[0].host);
        fleet_board_id_to_hex(keys[1], readers[1].host);
        pthread_t threads[2];
        int spawned = 0;
        for (; spawned < 2; spawned++) {
            if (thread_registry_spawn("fb_rpc_reader", fb_rpc_reader_main,
                                      &readers[spawned], &threads[spawned]) != 0)
                break;
        }
        while (atomic_load_explicit(&ready, memory_order_acquire) < spawned)
            platform_sleep_ms(1);
        atomic_store_explicit(&go, true, memory_order_release);
        for (int i = 0; i < spawned; i++)
            pthread_join(threads[i], NULL);
        bool ok = spawned == 2 && readers[0].ok && readers[1].ok;

        app_runtime_set_current(NULL);
        if (was_warming_up)
            set_rpc_warmup_started(warmup_status);
        node_db_close(&db);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

struct fb_rpc_fixture {
    struct node_db db;
    struct db_service service;
    struct app_runtime_context runtime;
    struct boot_svc_ctx svc;
    struct rpc_table table;
    char dir[256];
    char warmup_status[256];
    bool was_warming_up;
};

static bool fb_rpc_fixture_open(struct fb_rpc_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), "fleetboard", tag);
    f->service.node_db = &f->db;
    f->service.started = true;
    f->runtime.db_service = &f->service;
    f->svc.node_db = &f->db;
    f->svc.datadir = f->dir;
    if (!node_db_open(&f->db, ":memory:")) return false;
    boot_fleet_board_shutdown();
    boot_fleet_board_wire(&f->svc);
    app_runtime_set_current(&f->runtime);
    rpc_table_init(&f->table);
    boot_fleet_board_register_rpc(&f->table);
    f->was_warming_up =
        rpc_is_in_warmup(f->warmup_status, sizeof(f->warmup_status));
    set_rpc_warmup_finished();
    return true;
}

static void fb_rpc_fixture_close(struct fb_rpc_fixture *f)
{
    app_runtime_set_current(NULL);
    if (f->was_warming_up)
        set_rpc_warmup_started(f->warmup_status);
    boot_fleet_board_shutdown();
    node_db_close(&f->db);
}

static bool fb_rpc_call(struct fb_rpc_fixture *f, struct json_value *input,
                        struct json_value *result)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    bool ok = json_push_back(&params, input) &&
              rpc_table_execute(&f->table, "fleet_board", &params, result);
    json_free(&params);
    return ok;
}

static bool fb_rpc_post(struct fb_rpc_fixture *f, const char *kind,
                        const char *text, const char *agent,
                        const char *scope, struct json_value *result)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "op", "post") &&
              json_push_kv_str(&input, "kind", kind) &&
              json_push_kv_str(&input, "text", text);
    if (ok && agent) ok = json_push_kv_str(&input, "agent", agent);
    if (ok && scope) ok = json_push_kv_str(&input, "scope", scope);
    if (ok) ok = fb_rpc_call(f, &input, result);
    json_free(&input);
    return ok;
}

static const struct rpc_table *fb_native_test_table;
static const char *fb_native_projection_fault;
static unsigned fb_native_projection_nth;
static const char *fb_native_receipt_tamper;
static bool fb_native_receipt_copy_fault;
static unsigned fb_native_receipt_copy_nth;
static unsigned fb_native_rpc_calls;

static void fb_native_tamper_receipt(struct json_value *output)
{
    if (!fb_native_receipt_tamper) return;
    for (size_t i = 0; i < output->num_children; i++) {
        if (output->keys && !strcmp(output->keys[i], fb_native_receipt_tamper)) {
            json_set_str(&output->children[i], "wrong-receipt");
            break;
        }
    }
}

/* A node that predates bounded slug reads: it answers a slug read with the
 * whole page because it never sees the budget fields. */
static bool fb_native_legacy_slug_reads;
static size_t fb_native_wire_max = 8192;
static bool fb_native_legacy_list_paging;

static bool fb_native_strip_budgets(const struct json_value *params,
                                    struct json_value *stripped)
{
    const struct json_value *first = json_size(params) ? json_at(params, 0) : NULL;
    json_init(stripped);
    if (!first || first->type != JSON_OBJ || json_get(first, "id") ||
        strcmp(json_get_str(json_get(first, "op")), "wiki_read") != 0)
        return false;
    struct json_value object;
    json_init(&object); json_set_object(&object); json_set_array(stripped);
    for (size_t i = 0; i < first->num_children; i++) {
        const char *key = first->keys[i];
        if (key && strcmp(key, "response_budget") && strcmp(key, "data_budget") &&
            strcmp(key, "continuation_bytes"))
            (void)json_push_kv(&object, key, &first->children[i]);
    }
    (void)json_push_back(stripped, &object);
    json_free(&object);
    return true;
}

/* An old node's wiki_list answer: no more, no after_slug. */
static void fb_native_strip_list_paging(struct json_value *output)
{
    struct json_value kept;
    json_init(&kept);
    json_set_object(&kept);
    for (size_t i = 0; i < output->num_children; i++)
        if (output->keys && strcmp(output->keys[i], "more") && strcmp(output->keys[i], "after_slug"))
            (void)json_push_kv(&kept, output->keys[i], &output->children[i]);
    json_free(output);
    *output = kept;
}

static bool fb_native_rpc_run(const char *method, const struct json_value *input,
    struct json_value *output)
{
    fb_native_rpc_calls++;
    if (fb_native_projection_fault)
        zcl_alloc_fault_fail_nth(fb_native_projection_fault, fb_native_projection_nth);
    struct json_value legacy;
    json_init(&legacy);
    bool strip = fb_native_legacy_slug_reads && fb_native_strip_budgets(input, &legacy);
    bool ok = rpc_table_execute(fb_native_test_table, method, strip ? &legacy : input, output);
    json_free(&legacy);
    if (ok) fb_native_tamper_receipt(output);
    if (ok && fb_native_legacy_list_paging && !strcmp(method, "fleet_board") && json_get(output, "more"))
        fb_native_strip_list_paging(output);
    if (ok && fb_native_receipt_copy_fault)
        zcl_alloc_fault_fail_nth("json_copy_str", fb_native_receipt_copy_nth ? fb_native_receipt_copy_nth : 1);
    return ok;
}

static char *fb_native_rpc(const char *method, const char *params)
{
    struct json_value input, output;
    json_init(&input); json_init(&output);
    char *wire = NULL;
    if (fb_native_test_table && json_read(&input, params, strlen(params)) &&
        fb_native_rpc_run(method, &input, &output)) {
        size_t length = json_write(&output, NULL, 0);
        if (length < (fb_native_legacy_slug_reads ? 65536u : fb_native_wire_max)) {
            wire = malloc(length + 1);
            if (wire) (void)json_write(&output, wire, length + 1);
        }
    }
    json_free(&input); json_free(&output);
    return wire;
}

static int test_fleet_board_native_busy(void)
{
    int failures = 0;
    struct fb_rpc_fixture fixture;
    bool opened = false;
    TEST("fleet board: native busy refusal is transient and retries after rollback") {
        ASSERT(fb_rpc_fixture_open(&fixture, "native-busy"));
        opened = true;
        struct json_value setup;
        json_init(&setup);
        ASSERT(fb_rpc_post(&fixture, "note", "identity setup", "fixture", NULL, &setup));
        ASSERT(json_get_bool(json_get(&setup, "ok")));
        json_free(&setup);
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "kind", "note"));
        ASSERT(json_push_kv_str(&input, "text", "native transaction witness"));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.fleet_board_post.v1");
        fb_native_test_table = &fixture.table;
        node_rpc_client_set_test_hook(fb_native_rpc);
        ASSERT(node_db_begin(&fixture.db));
        int changes = sqlite3_total_changes(fixture.db.db);
        zcl_native_handle_fleet_board_post(&request, &reply);
        bool unchanged = changes == sqlite3_total_changes(fixture.db.db);
        bool restored = node_db_rollback(&fixture.db);
        ASSERT(restored && unchanged);
        ASSERT_STR_EQ(reply.error.code, "BOARD_BUSY");
        ASSERT(reply.error.retryable && !reply.error.mutated);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_TRANSIENT);
        zcl_command_reply_free(&reply);
        zcl_command_reply_init(&reply, "zcl.fleet_board_post.v1");
        zcl_native_handle_fleet_board_post(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    fb_native_test_table = NULL;
    if (opened) fb_rpc_fixture_close(&fixture);
    return failures;
}

static struct node_db *s_wait_writer;

static void fb_wait_release_writer(void)
{
    db_fleet_board_test_set_wait_hook(NULL);
    (void)node_db_rollback(s_wait_writer);
}

static int test_fleet_board_ingest_wait_bounded(void)
{
    int failures = 0;
    struct node_db writer, board;
    bool opened = false;
    memset(&writer, 0, sizeof(writer));
    memset(&board, 0, sizeof(board));
    TEST("fleet board: a local write waits out a short lock and gives up on a long one") {
        char dbdir[256];
        char dbpath[320];
        test_make_tmpdir(dbdir, sizeof(dbdir), "fleet_board_wait", "zcl");
        (void)snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        ASSERT(node_db_open(&board, dbpath));
        opened = true;
        ASSERT(node_db_open(&writer, dbpath));
        (void)sqlite3_busy_timeout(board.db, 0);
        db_fleet_board_test_clear_quarantine();

        uint8_t seed[32], pk[32];
        fb_test_identity(11, seed, pk);
        struct fleet_board_post released, held;
        fb_test_compose(&released, FLEET_BOARD_KIND_NOTE, "lane-wait",
                        "lock released inside the bound", 100, 1000);
        fb_test_compose(&held, FLEET_BOARD_KIND_NOTE, "lane-wait",
                        "lock outlives the bound", 100, 1000);
        ASSERT_EQ(fleet_board_post_sign(&released, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&held, seed, pk), FLEET_BOARD_OK);

        /* The second connection holds the write lock. The hook releases it
         * on the first retry, far inside the 100 ms bound. */
        ASSERT(node_db_begin_immediate(&writer));
        s_wait_writer = &writer;
        db_fleet_board_test_set_wait_hook(fb_wait_release_writer);
        bool stored = false;
        enum fleet_board_result r = db_fleet_board_post_ingest_wait(
            &board, &released, 100, 100, &stored);
        db_fleet_board_test_set_wait_hook(NULL);
        ASSERT_EQ(r, FLEET_BOARD_OK);
        ASSERT(stored && db_fleet_board_have(&board, released.id));

        /* The lock outlives a 30 ms bound: the refusal stays BUSY, nothing is
         * stored, and the call really waited for the bound. */
        ASSERT(node_db_begin_immediate(&writer));
        stored = true;
        int64_t t0 = platform_time_monotonic_ms();
        r = db_fleet_board_post_ingest_wait(&board, &held, 100, 30, &stored);
        int64_t waited_ms = platform_time_monotonic_ms() - t0;
        ASSERT_EQ(r, FLEET_BOARD_ERR_BUSY);
        ASSERT(!stored && !db_fleet_board_have(&board, held.id) && waited_ms >= 30);
        ASSERT(node_db_rollback(&writer));
        ASSERT_EQ(db_fleet_board_post_ingest_wait(&board, &held, 100, 30, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);
        PASS();
    } _test_next:;
    if (opened) node_db_close(&board);
    node_db_close(&writer);
    return failures;
}

static int64_t fb_room_boundary_mono_ns(void *self)
{
    (void)self;
    return INT64_C(1000000000);
}

static int64_t fb_room_boundary_wall_ms(void *self)
{
    (void)self;
    return INT64_C(1700000000000);
}

static bool fb_rpc_room_post(struct fb_rpc_fixture *f, const char *room,
                             struct json_value *out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "op", "post") &&
              json_push_kv_str(&input, "kind", "note") &&
              json_push_kv_str(&input, "scope", "public") &&
              json_push_kv_str(&input, "room", room) &&
              json_push_kv_str(&input, "text", "x") &&
              fb_rpc_call(f, &input, out);
    json_free(&input);
    return ok;
}

static int fb_rpc_room_refusal(struct fb_rpc_fixture *f, const char *room)
{
    int failures = 0;
    struct json_value out;
    json_init(&out);
    {
        struct fleet_board_status before, after;
        ASSERT(db_fleet_board_status(&f->db, INT64_C(1700000000), &before));
        int changes = sqlite3_total_changes(f->db.db);
        ASSERT(fb_rpc_room_post(f, room, &out));
        ASSERT(!json_get_bool(json_get(&out, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_ROOM");
        ASSERT_EQ(sqlite3_total_changes(f->db.db), changes);
        ASSERT(db_fleet_board_status(&f->db, INT64_C(1700000000), &after));
        ASSERT_EQ(after.posts, before.posts);
    } _test_next:;
    json_free(&out);
    return failures;
}

static int fb_rpc_room_acceptance(struct fb_rpc_fixture *f, const char *room)
{
    int failures = 0;
    struct json_value out;
    json_init(&out);
    {
        struct fleet_board_status before, after;
        ASSERT(db_fleet_board_status(&f->db, INT64_C(1700000000), &before));
        ASSERT(fb_rpc_room_post(f, room, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        uint8_t id[32];
        ASSERT(fleet_board_id_from_hex(json_get_str(json_get(&out, "id")), id));
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_post_find(&f->db, id, &row));
        ASSERT_STR_EQ(row.post.room, room);
        ASSERT(db_fleet_board_status(&f->db, INT64_C(1700000000), &after));
        ASSERT_EQ(after.posts, before.posts + INT64_C(1));
    } _test_next:;
    json_free(&out);
    return failures;
}

static int test_fleet_board_rpc_room_boundary(void)
{
    int failures = 0;
    static const clock_iface_t clock = {
        .now_monotonic_ns = fb_room_boundary_mono_ns,
        .now_wall_ms = fb_room_boundary_wall_ms,
    };
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&clock);
    struct fb_rpc_fixture f;
    bool opened = fb_rpc_fixture_open(&f, "rpc-room-boundary");
    TEST("fleet board: RPC refuses room33 without writes and preserves room32") {
        ASSERT(opened);
        char room[FLEET_BOARD_ROOM_MAX + 2];
        memset(room, 'a', sizeof(room) - 1);
        room[sizeof(room) - 1] = '\0';
        ASSERT_EQ(fb_rpc_room_refusal(&f, room), 0);
        room[FLEET_BOARD_ROOM_MAX] = '\0';
        ASSERT_EQ(fb_rpc_room_acceptance(&f, room), 0);
        PASS();
    } _test_next:;
    if (opened) fb_rpc_fixture_close(&f);
    if (test_rm_rf_recursive(f.dir) != 0) {
        fprintf(stderr, "fleet board: room-boundary cleanup failed\n");
        failures++;
    }
    clock_set_default(saved_clock);
    return failures;
}

static int test_fleet_board_rpc_scope_default(void)
{
    int failures = 0;
    TEST("fleet board: RPC post without scope signs the public default room") {
        struct fb_rpc_fixture f;
        ASSERT(fb_rpc_fixture_open(&f, "rpc-scope"));
        struct json_value out;
        json_init(&out);
        bool posted = fb_rpc_post(&f, "note", "scope default acceptance",
                                  "scope-probe", NULL, &out);
        if (!posted || !json_get_bool(json_get(&out, "ok"))) {
            const char *code = json_get_str(json_get(&out, "code"));
            fprintf(stderr, "fleet board: scope-default post refused: %s\n",
                    code[0] ? code : "(no code)");
        }
        ASSERT(json_get_bool(json_get(&out, "ok")));
        const char *id = json_get_str(json_get(&out, "id"));
        ASSERT(strlen(id) == 64);
        char post_id[65];
        (void)snprintf(post_id, sizeof(post_id), "%s", id);
        json_free(&out);

        json_init(&out);
        json_set_object(&out);
        struct json_value show;
        json_init(&show);
        json_set_object(&show);
        bool shown = json_push_kv_str(&show, "op", "show") &&
                     json_push_kv_str(&show, "id", post_id) &&
                     fb_rpc_call(&f, &show, &out);
        json_free(&show);
        ASSERT(shown && json_get_bool(json_get(&out, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "scope")), "public");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "room")),
                      FLEET_BOARD_ROOM_DEFAULT);
        json_free(&out);

        /* An unrecognized scope stays a typed refusal, never a default. */
        json_init(&out);
        ASSERT(fb_rpc_post(&f, "note", "scope refusal acceptance", NULL,
                           "bogus", &out));
        ASSERT(!json_get_bool(json_get(&out, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_SCOPE");
        json_free(&out);

        fb_rpc_fixture_close(&f);
        ASSERT(test_rm_rf_recursive(f.dir) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* One fleet-scoped note with an explicit signed created_at and ttl. */
static bool fb_rpc_post_at(struct fb_rpc_fixture *f, const char *text,
                           int64_t created_at, int64_t ttl,
                           struct json_value *result)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "op", "post") &&
              json_push_kv_str(&input, "kind", "note") &&
              json_push_kv_str(&input, "scope", "fleet") &&
              json_push_kv_str(&input, "text", text) &&
              json_push_kv_int(&input, "created_at", created_at) &&
              json_push_kv_int(&input, "ttl", ttl) &&
              fb_rpc_call(f, &input, result);
    json_free(&input);
    return ok;
}

static int test_fleet_board_rpc_created_at(void)
{
    int failures = 0;
    static const clock_iface_t clock = {
        .now_monotonic_ns = fb_room_boundary_mono_ns,
        .now_wall_ms = fb_room_boundary_wall_ms,
    };
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&clock);
    TEST("fleet board: an RPC retry with the same content and created_at is "
         "the same post, and created_at is bounded both ways") {
        struct fb_rpc_fixture f;
        ASSERT(fb_rpc_fixture_open(&f, "rpc-created-at"));
        const int64_t now = INT64_C(1700000000);
        struct json_value first, retry, refused;
        json_init(&first);
        json_init(&retry);
        ASSERT(fb_rpc_post_at(&f, "deliver row 7", now - 100, 3600, &first));
        ASSERT(json_get_bool(json_get(&first, "ok")));
        ASSERT_EQ(json_get_int(json_get(&first, "created_at")), now - 100);
        /* The retry signs the same bytes, so it IS the first post: the same
         * id, and the store still holds one post. */
        ASSERT(fb_rpc_post_at(&f, "deliver row 7", now - 100, 3600, &retry));
        ASSERT(json_get_bool(json_get(&retry, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&retry, "id")),
                      json_get_str(json_get(&first, "id")));
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&f.db, now, &status));
        ASSERT_EQ(status.posts, INT64_C(1));
        json_free(&first);
        json_free(&retry);

        /* Further ahead than a peer would accept: refused, nothing signed. */
        json_init(&refused);
        ASSERT(fb_rpc_post_at(&f, "from the future", now + 3600, 3600,
                              &refused));
        ASSERT(!json_get_bool(json_get(&refused, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&refused, "code")),
                      "BAD_CREATED_AT");
        json_free(&refused);

        /* Older than its own ttl: it would be expired before it was sent. */
        json_init(&refused);
        ASSERT(fb_rpc_post_at(&f, "long gone", now - 7200, 3600, &refused));
        ASSERT(!json_get_bool(json_get(&refused, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&refused, "code")),
                      "CREATED_AT_EXPIRED");
        json_free(&refused);
        ASSERT(db_fleet_board_status(&f.db, now, &status));
        ASSERT_EQ(status.posts, INT64_C(1));

        fb_rpc_fixture_close(&f);
        ASSERT(test_rm_rf_recursive(f.dir) == 0);
        PASS();
    } _test_next:;
    clock_set_default(saved_clock);
    return failures;
}

static bool fb_rpc_fleet_page(struct fb_rpc_fixture *f, int64_t after,
                              struct json_value *result)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "op", "fleet_page") &&
              json_push_kv_int(&input, "after", after) &&
              fb_rpc_call(f, &input, result);
    json_free(&input);
    return ok;
}

static int test_fleet_board_rpc_fleet_page(void)
{
    int failures = 0;
    static const clock_iface_t clock = {
        .now_monotonic_ns = fb_room_boundary_mono_ns,
        .now_wall_ms = fb_room_boundary_wall_ms,
    };
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&clock);
    TEST("fleet board: fleet_page pages fleet posts by arrival, not by "
         "signed time, under one process epoch") {
        struct fb_rpc_fixture f;
        ASSERT(fb_rpc_fixture_open(&f, "rpc-fleet-page"));
        const int64_t now = INT64_C(1700000000);
        struct json_value out, page;
        json_init(&out);
        ASSERT(fb_rpc_post_at(&f, "arrives first", now - 100, 3600, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);
        /* Signed EARLIER but arriving later: a created_at cursor would
         * pass it over; the arrival page must not. */
        json_init(&out);
        ASSERT(fb_rpc_post_at(&f, "arrives second", now - 500, 3600, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);
        json_init(&out);
        ASSERT(fb_rpc_post(&f, "note", "public, never paged", NULL, NULL,
                           &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);

        json_init(&page);
        ASSERT(fb_rpc_fleet_page(&f, 0, &page));
        ASSERT(json_get_bool(json_get(&page, "ok")));
        ASSERT_EQ(json_get_int(json_get(&page, "returned")), 2);
        const struct json_value *posts = json_get(&page, "posts");
        ASSERT(posts && json_size(posts) == 2);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(posts, 0), "text")),
                      "arrives first");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(posts, 1), "text")),
                      "arrives second");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(posts, 1), "scope")),
                      "fleet");
        int64_t scanned = json_get_int(json_get(&page, "scanned"));
        ASSERT_EQ(scanned,
                  json_get_int(json_get(json_at(posts, 1), "arrival")));
        char epoch[64];
        (void)snprintf(epoch, sizeof(epoch), "%s",
                       json_get_str(json_get(&page, "epoch")));
        ASSERT(strlen(epoch) == 32);
        json_free(&page);

        /* Resuming at the returned number hands back nothing new, under
         * the same epoch. */
        json_init(&page);
        ASSERT(fb_rpc_fleet_page(&f, scanned, &page));
        ASSERT(json_get_bool(json_get(&page, "ok")));
        ASSERT_EQ(json_get_int(json_get(&page, "returned")), 0);
        ASSERT_EQ(json_get_int(json_get(&page, "scanned")), scanned);
        ASSERT_STR_EQ(json_get_str(json_get(&page, "epoch")), epoch);
        json_free(&page);

        json_init(&page);
        ASSERT(fb_rpc_fleet_page(&f, -1, &page));
        ASSERT(!json_get_bool(json_get(&page, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&page, "code")), "BAD_AFTER");
        json_free(&page);

        fb_rpc_fixture_close(&f);
        ASSERT(test_rm_rf_recursive(f.dir) == 0);
        PASS();
    } _test_next:;
    clock_set_default(saved_clock);
    return failures;
}

static void fb_test_scope(struct fleet_board_post *post, uint8_t scope,
                          const char *room)
{
    post->scope = scope;
    (void)snprintf(post->room, sizeof(post->room), "%s", room ? room : "");
}

static int test_fleet_board_scope_codec(void)
{
    int failures = 0;
    TEST("fleet board: the scope is signed, and v1 posts still verify") {
        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);

        /* A public post signs its room: encode/decode round-trips the scope
         * fields and still verifies end to end. */
        struct fleet_board_post pub;
        fb_test_compose(&pub, FLEET_BOARD_KIND_NOTE, "lane-a",
                        "ops room is open", 1000, 3600);
        fb_test_scope(&pub, FLEET_BOARD_SCOPE_PUBLIC, "ops");
        ASSERT_EQ(fleet_board_post_sign(&pub, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_verify(&pub), FLEET_BOARD_OK);
        uint8_t wire[FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(fleet_board_post_encode(&pub, wire, sizeof(wire),
                                          &wire_len), FLEET_BOARD_OK);
        struct fleet_board_post decoded;
        ASSERT_EQ(fleet_board_post_decode(wire, wire_len, &decoded),
                  FLEET_BOARD_OK);
        ASSERT_EQ(decoded.scope, FLEET_BOARD_SCOPE_PUBLIC);
        ASSERT(strcmp(decoded.room, "ops") == 0);
        ASSERT(memcmp(decoded.id, pub.id, 32) == 0);

        /* Moving the post to another room, or out of the public scope
         * entirely, breaks the id — a relay cannot re-address a post. */
        struct fleet_board_post moved = pub;
        moved.room[0] = 'x';
        ASSERT_EQ(fleet_board_post_verify(&moved), FLEET_BOARD_ERR_ID);
        struct fleet_board_post hidden = pub;
        hidden.scope = FLEET_BOARD_SCOPE_FLEET;
        hidden.room[0] = '\0';
        ASSERT_EQ(fleet_board_post_verify(&hidden), FLEET_BOARD_ERR_ID);

        /* A legacy post decodes as legacy-public and re-encodes to the exact
         * bytes it was signed over, so its id and signature survive scopes. */
        struct fleet_board_post legacy;
        fb_test_compose(&legacy, FLEET_BOARD_KIND_PROBLEM, "lane-b",
                        "signed before rooms existed", 1000, 3600);
        ASSERT_EQ(fleet_board_post_sign(&legacy, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_encode(&legacy, wire, sizeof(wire),
                                          &wire_len), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_decode(wire, wire_len, &decoded),
                  FLEET_BOARD_OK);
        ASSERT_EQ(decoded.scope, FLEET_BOARD_SCOPE_LEGACY_PUBLIC);
        ASSERT(decoded.room[0] == '\0');
        ASSERT(memcmp(decoded.id, legacy.id, 32) == 0);
        ASSERT(strcmp(fleet_board_room_name(&decoded), "general") == 0);
        uint8_t rewire[FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t rewire_len = 0;
        ASSERT_EQ(fleet_board_post_encode(&decoded, rewire, sizeof(rewire),
                                          &rewire_len), FLEET_BOARD_OK);
        ASSERT_EQ(rewire_len, wire_len);
        ASSERT(memcmp(rewire, wire, wire_len) == 0);

        /* Scope and room shape refusals. */
        struct fleet_board_post bad;
        fb_test_compose(&bad, FLEET_BOARD_KIND_NOTE, "a", "hi", 1000, 60);
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_PUBLIC, "");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_ERR_ROOM);
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_PUBLIC, "Bad Room");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_ERR_ROOM);
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_FLEET, "ops");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_ERR_ROOM);
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_LEGACY_PUBLIC, "ops");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_ERR_ROOM);
        fb_test_scope(&bad, 9, "");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_ERR_SCOPE);

        /* A fleet post with no room is a legal shape. */
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_validate(&bad), FLEET_BOARD_OK);

        /* The names agents type. */
        ASSERT(strcmp(fleet_board_scope_name(FLEET_BOARD_SCOPE_PUBLIC),
                      "public") == 0);
        ASSERT(strcmp(fleet_board_scope_name(FLEET_BOARD_SCOPE_LEGACY_PUBLIC),
                      "public") == 0);
        ASSERT(strcmp(fleet_board_scope_name(FLEET_BOARD_SCOPE_FLEET),
                      "fleet") == 0);
        ASSERT(strcmp(fleet_board_scope_name(9), "unknown") == 0);
        uint8_t parsed = 0;
        ASSERT(fleet_board_scope_from_name("public", &parsed));
        ASSERT_EQ(parsed, FLEET_BOARD_SCOPE_PUBLIC);
        ASSERT(fleet_board_scope_from_name("fleet", &parsed));
        ASSERT_EQ(parsed, FLEET_BOARD_SCOPE_FLEET);
        ASSERT(!fleet_board_scope_from_name("nope", &parsed));

        ASSERT(fleet_board_room_valid("ops"));
        ASSERT(fleet_board_room_valid("a"));
        ASSERT(!fleet_board_room_valid(""));
        ASSERT(!fleet_board_room_valid("-lead"));
        ASSERT(!fleet_board_room_valid("trail-"));
        ASSERT(!fleet_board_room_valid("Upper"));
        ASSERT(!fleet_board_room_valid(
            "this-room-name-is-far-too-long-to-sign"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_scope_store(void)
{
    int failures = 0;
    TEST("fleet board: the store filters by signed scope and room") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        ASSERT_EQ(node_db_schema_version(&db), NODE_DB_SCHEMA_LATEST);

        uint8_t seed[32], pk[32];
        fb_test_identity(1, seed, pk);
        const int64_t now = 100000;

        /* One post per scope situation: a pre-scope legacy row, a named
         * public room, the default public room, and a fleet-private row. */
        struct fleet_board_post legacy, ops, general, fleet;
        fb_test_compose(&legacy, FLEET_BOARD_KIND_NOTE, "lane-a",
                        "from before scopes", (uint64_t)now, 3600);
        fb_test_compose(&ops, FLEET_BOARD_KIND_NOTE, "lane-a",
                        "ops only", (uint64_t)now + 1, 3600);
        fb_test_scope(&ops, FLEET_BOARD_SCOPE_PUBLIC, "ops");
        fb_test_compose(&general, FLEET_BOARD_KIND_NOTE, "lane-a",
                        "default room", (uint64_t)now + 2, 3600);
        fb_test_scope(&general, FLEET_BOARD_SCOPE_PUBLIC, "general");
        fb_test_compose(&fleet, FLEET_BOARD_KIND_NOTE, "lane-a",
                        "fleet eyes only", (uint64_t)now + 3, 3600);
        fb_test_scope(&fleet, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_sign(&legacy, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&ops, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&general, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&fleet, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &legacy, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &ops, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &general, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &fleet, now, NULL),
                  FLEET_BOARD_OK);

        struct db_fleet_board_post rows[8];
        struct fleet_board_filter filter;

        /* No filter sees all four. */
        memset(&filter, 0, sizeof(filter));
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 4);

        /* A named room sees only its own posts. */
        memset(&filter, 0, sizeof(filter));
        (void)snprintf(filter.room, sizeof(filter.room), "%s", "ops");
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 1);
        ASSERT(memcmp(rows[0].post.id, ops.id, 32) == 0);

        /* The default room also returns legacy rows: their empty signed room
         * IS the default room, or the pre-scope board would vanish. */
        memset(&filter, 0, sizeof(filter));
        (void)snprintf(filter.room, sizeof(filter.room), "%s", "general");
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 2);

        /* Scope filters. */
        memset(&filter, 0, sizeof(filter));
        filter.scope_set = true;
        filter.scope = FLEET_BOARD_SCOPE_PUBLIC;
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 2);
        filter.scope = FLEET_BOARD_SCOPE_FLEET;
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 1);
        ASSERT(memcmp(rows[0].post.id, fleet.id, 32) == 0);
        filter.scope = FLEET_BOARD_SCOPE_LEGACY_PUBLIC;
        ASSERT_EQ(db_fleet_board_list(&db, &filter, now, rows, 8), 1);
        ASSERT(memcmp(rows[0].post.id, legacy.id, 32) == 0);

        /* A stored row re-verifies with its scope intact. */
        struct db_fleet_board_post fetched;
        ASSERT(db_fleet_board_post_find(&db, ops.id, &fetched));
        ASSERT_EQ(fetched.post.scope, FLEET_BOARD_SCOPE_PUBLIC);
        ASSERT(strcmp(fetched.post.room, "ops") == 0);
        ASSERT(db_fleet_board_post_find(&db, legacy.id, &fetched));
        ASSERT_EQ(fetched.post.scope, FLEET_BOARD_SCOPE_LEGACY_PUBLIC);
        ASSERT(strcmp(fleet_board_room_name(&fetched.post), "general") == 0);

        /* The public gossip inventory carries public rows only; announcing a
         * fleet post's id would reveal it exists. */
        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        ASSERT_EQ(db_fleet_board_recent_ids(&db, now, false, ids,
                                            FLEET_BOARD_FRAME_IDS_MAX),
                  4);
        ASSERT_EQ(db_fleet_board_recent_ids(&db, now, true, ids,
                                            FLEET_BOARD_FRAME_IDS_MAX),
                  3);
        for (int i = 0; i < 3; i++)
            ASSERT(memcmp(ids[i], fleet.id, 32) != 0);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* PUBLIC scope needs no operator grant: a never-granted key may post to a
 * public room but stays refused elsewhere, and a flood past the per-key quota
 * is refused without touching the store. Runs with the REAL role gate. */
static int test_fleet_board_public_grant_free(void)
{
    int failures = 0;
    TEST("fleet board: a never-granted key posts to a public room and is "
        "stored, but is refused the moment it tries a fleet room") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(9, seed, pk);
        const int64_t now = 500000;

        struct fleet_board_post pub;
        fb_test_compose(&pub, FLEET_BOARD_KIND_NOTE, "stranger",
                        "hello from a box nobody granted anything to",
                        (uint64_t)now, 3600);
        fb_test_scope(&pub, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&pub, seed, pk), FLEET_BOARD_OK);
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &pub, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);

        struct fleet_board_post priv;
        fb_test_compose(&priv, FLEET_BOARD_KIND_NOTE, "stranger",
                        "the same key tries a fleet room", (uint64_t)now,
                        3600);
        fb_test_scope(&priv, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_sign(&priv, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &priv, now, NULL),
                  FLEET_BOARD_ERR_ROLE);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_public_unknown_scope(void)
{
    int failures = 0;
    TEST("fleet board: an unknown scope value is refused through the real "
        "ingest path, quota or no quota") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(10, seed, pk);
        const int64_t now = 500000;

        /* Scope validation runs before verification, so an illegal scope set
         * after signing is refused on its own terms. */
        struct fleet_board_post bad;
        fb_test_compose(&bad, FLEET_BOARD_KIND_NOTE, "stranger",
                        "an unknown scope value", (uint64_t)now, 3600);
        fb_test_scope(&bad, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_sign(&bad, seed, pk), FLEET_BOARD_OK);
        bad.scope = (uint8_t)FLEET_BOARD_SCOPE__COUNT;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &bad, now, NULL),
                  FLEET_BOARD_ERR_SCOPE);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_public_quota(void)
{
    int failures = 0;
    TEST("fleet board: the post past the per-key public quota is refused "
        "and the stored count for that key never moves") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(11, seed, pk);
        const int64_t now = 500000;

        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            struct fleet_board_post p;
            char text[64];
            (void)snprintf(text, sizeof(text), "post number %d", i);
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "flooder", text,
                            (uint64_t)now + (uint64_t)i, 3600);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            bool stored = false;
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, &stored),
                      FLEET_BOARD_OK);
            ASSERT(stored);
        }

        struct fleet_board_filter filter;
        memset(&filter, 0, sizeof(filter));
        filter.host_set = true;
        memcpy(filter.host_pubkey, pk, 32);
        struct db_fleet_board_post rows[FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX +
                                        4];
        int before = db_fleet_board_list(&db, &filter, now, rows,
            sizeof(rows) / sizeof(rows[0]));
        ASSERT_EQ(before, FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX);

        struct fleet_board_post one_too_many;
        fb_test_compose(&one_too_many, FLEET_BOARD_KIND_NOTE, "flooder",
                        "one post past the window quota",
                        (uint64_t)now +
                            (uint64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX,
                        3600);
        fb_test_scope(&one_too_many, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&one_too_many, seed, pk),
                  FLEET_BOARD_OK);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &one_too_many, now,
                                             &stored),
                  FLEET_BOARD_ERR_QUOTA);
        ASSERT(!stored);

        int after = db_fleet_board_list(&db, &filter, now, rows,
            sizeof(rows) / sizeof(rows[0]));
        ASSERT_EQ(after, before);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Sign one PUBLIC post of `kind` for the seeded key; wiki posts get a slug. */
static void fb_test_public_post(struct fleet_board_post *p, uint8_t kind,
                                int n, const uint8_t seed[32],
                                const uint8_t pk[32], int64_t now)
{
    char text[64];
    (void)snprintf(text, sizeof(text), "budget post %d", n);
    fb_test_compose(p, kind, "budget", text, (uint64_t)now, 3600);
    fb_test_scope(p, FLEET_BOARD_SCOPE_PUBLIC, "general");
    if (kind == FLEET_BOARD_KIND_WIKI) {
        (void)snprintf(p->slug, sizeof(p->slug), "page-%d", n % 5);
        (void)snprintf(p->title, sizeof(p->title), "Page %d", n);
    }
    (void)fleet_board_post_sign(p, seed, pk);
}

static int test_fleet_board_wiki_budget_is_separate(void)
{
    int failures = 0;
    TEST("fleet board: a key that spent its message window can still write "
        "wiki, and a spent wiki window never blocks messages") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(21, seed, pk);
        const int64_t now = 600000;
        struct fleet_board_post p;
        int n = 0;

        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, n++, seed, pk, now);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                      FLEET_BOARD_OK);
        }
        fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, n++, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                  FLEET_BOARD_ERR_QUOTA);

        for (int i = 0; i < FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX; i++) {
            fb_test_public_post(&p, FLEET_BOARD_KIND_WIKI, n++, seed, pk, now);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                      FLEET_BOARD_OK);
        }
        fb_test_public_post(&p, FLEET_BOARD_KIND_WIKI, n++, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                  FLEET_BOARD_ERR_WIKI_QUOTA);
        ASSERT(strstr(fleet_board_result_string(FLEET_BOARD_ERR_WIKI_QUOTA),
                      "wiki") != NULL);

        /* Messages stay refused by their own budget, not the wiki's. */
        fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, n++, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                  FLEET_BOARD_ERR_QUOTA);

        /* A second key spends only wiki; its messages are untouched. */
        uint8_t seed2[32], pk2[32];
        fb_test_identity(22, seed2, pk2);
        for (int i = 0; i < FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX; i++) {
            fb_test_public_post(&p, FLEET_BOARD_KIND_WIKI, n++, seed2, pk2,
                                now);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                      FLEET_BOARD_OK);
        }
        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, n++, seed2, pk2,
                                now);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                      FLEET_BOARD_OK);
        }
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Sign one PUBLIC wiki revision of `slug` for the seeded key. */
static void fb_test_wiki_rev(struct fleet_board_post *p, const char *slug,
                             int n, const uint8_t seed[32],
                             const uint8_t pk[32], int64_t now)
{
    char text[64];
    (void)snprintf(text, sizeof(text), "revision %d of %s", n, slug);
    fb_test_compose(p, FLEET_BOARD_KIND_WIKI, "budget", text, (uint64_t)now,
                    3600);
    fb_test_scope(p, FLEET_BOARD_SCOPE_PUBLIC, "general");
    (void)snprintf(p->slug, sizeof(p->slug), "%s", slug);
    (void)snprintf(p->title, sizeof(p->title), "Page %s", slug);
    (void)fleet_board_post_sign(p, seed, pk);
}

static enum fleet_board_result fb_test_put_rev(struct node_db *db,
                                               const char *slug, int n,
                                               uint8_t who, int64_t now,
                                               struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_wiki_rev(out, slug, n, seed, pk, now);
    return db_fleet_board_post_ingest(db, out, now, NULL);
}

/* fb_test_put_rev with a day-long ttl, for fixtures whose ingest clock runs
 * past an hour: the rows must stay unexpired. */
static enum fleet_board_result fb_test_put_rev_day(struct node_db *db,
                                                   const char *slug, int n,
                                                   uint8_t who, int64_t now,
                                                   struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_wiki_rev(out, slug, n, seed, pk, now);
    out->ttl = 86400;
    if (fleet_board_post_sign(out, seed, pk) != FLEET_BOARD_OK)
        return FLEET_BOARD_ERR_SIGNATURE;
    return db_fleet_board_post_ingest(db, out, now, NULL);
}

static int test_fleet_board_wiki_stored_ceiling(void)
{
    int failures = 0;
    TEST("fleet board: a key at its stored wiki ceiling replaces its own "
        "oldest superseded revision and touches no other key's rows") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post other[3], first, second, last, p;
        int64_t now = 700000;
        for (int i = 0; i < 3; i++)
            ASSERT_EQ(fb_test_put_rev(&db, "one", i, 24, now, &other[i]),
                      FLEET_BOARD_OK);
        for (int i = 0; i < FLEET_BOARD_WIKI_QUOTA_STORED_MAX; i++) {
            now += 31;
            struct fleet_board_post *slot = i == 0 ? &first
                                          : i == 1 ? &second : &p;
            ASSERT_EQ(fb_test_put_rev(&db, "one", 10 + i, 23, now, slot),
                      FLEET_BOARD_OK);
        }
        now += 31;
        bool stored = false;
        uint8_t seed[32], pk[32];
        fb_test_identity(23, seed, pk);
        fb_test_wiki_rev(&last, "one", 9999, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &last, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);
        ASSERT(!db_fleet_board_have(&db, first.id));
        ASSERT(db_fleet_board_have(&db, second.id));
        ASSERT(db_fleet_board_have(&db, last.id));
        for (int i = 0; i < 3; i++)
            ASSERT(db_fleet_board_have(&db, other[i].id));
        int64_t checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        struct db_fleet_board_post page;
        ASSERT(db_fleet_board_wiki_read(&db, "one", &page));
        ASSERT(memcmp(page.post.id, last.id, 32) == 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_wiki_all_newest_refuses(void)
{
    int failures = 0;
    TEST("fleet board: 200 distinct pages leave nothing to replace, the "
        "201st page is refused for good, a revision of a held page is "
        "taken, and ordinary posts are unaffected") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post p, s0;
        int64_t now = 800000;
        for (int i = 0; i < FLEET_BOARD_WIKI_QUOTA_STORED_MAX; i++) {
            char slug[16];
            (void)snprintf(slug, sizeof(slug), "s-%d", i);
            now += 31;
            ASSERT_EQ(fb_test_put_rev_day(&db, slug, i, 25, now,
                                      i == 0 ? &s0 : &p),
                      FLEET_BOARD_OK);
        }
        now += 31;
        ASSERT_EQ(fb_test_put_rev(&db, "brand-new", 1, 25, now, &p),
                  FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(!db_fleet_board_have(&db, p.id));
        uint8_t seed[32], pk[32];
        fb_test_identity(25, seed, pk);
        fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, 7, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                  FLEET_BOARD_OK);
        now += 31;
        ASSERT_EQ(fb_test_put_rev(&db, "s-0", 2, 25, now, &p), FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, s0.id));
        ASSERT(db_fleet_board_have(&db, p.id));
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_wiki_half_store_bound(void)
{
    int failures = 0;
    TEST("fleet board: wiki rows together stop at half the store's byte "
        "cap with the capacity reason, and ordinary posts still fit") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_store_limits(0, 4000);
        db_fleet_board_test_set_wiki_limits(1000, 0);
        struct fleet_board_post p;
        int stored = 0;
        enum fleet_board_result r = FLEET_BOARD_OK;
        for (int i = 0; i < 40 && r == FLEET_BOARD_OK; i++) {
            char slug[16];
            (void)snprintf(slug, sizeof(slug), "w-%d", i);
            r = fb_test_put_rev(&db, slug, i, 26, 900000 + i, &p);
            stored += r == FLEET_BOARD_OK;
        }
        ASSERT_EQ(r, FLEET_BOARD_ERR_CAPACITY);
        ASSERT(stored > 2);
        uint8_t seed[32], pk[32];
        fb_test_identity(26, seed, pk);
        fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, 1, seed, pk, 900100);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, 900100, NULL),
                  FLEET_BOARD_OK);
        db_fleet_board_test_set_store_limits(0, 0);
        db_fleet_board_test_set_wiki_limits(0, 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_store_limits(0, 0);
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

/* One wiki revision of `slug` by `who` in `scope`, created at `created_at`,
 * with a body text of `text_len` bytes made distinct by `tag`. */
static enum fleet_board_result fb_put_wiki(struct node_db *db, uint8_t who,
                                           uint8_t scope, const char *slug,
                                           int64_t created_at,
                                           size_t text_len, int tag,
                                           int64_t now,
                                           struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    char text[256];
    memset(text, 'x', sizeof(text));
    text_len = text_len < sizeof(text) ? text_len : sizeof(text) - 1;
    text[text_len] = '\0';
    char tagged[16];
    size_t tag_len = (size_t)snprintf(tagged, sizeof(tagged), "t%d", tag);
    memcpy(text, tagged, tag_len < text_len ? tag_len : text_len);
    /* `created_at` is an offset inside the post's live hour. */
    fb_test_compose(out, FLEET_BOARD_KIND_WIKI, "budget", text,
                    (uint64_t)(now - 3000 + created_at), 3600);
    fb_test_scope(out, scope,
                  scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    (void)snprintf(out->slug, sizeof(out->slug), "%s", slug);
    (void)snprintf(out->title, sizeof(out->title), "%s", slug);
    if (fleet_board_post_sign(out, seed, pk) != FLEET_BOARD_OK)
        return FLEET_BOARD_ERR_SIGNATURE;
    return db_fleet_board_post_ingest(db, out, now, NULL);
}

#define FB_PUB FLEET_BOARD_SCOPE_PUBLIC

static bool fb_chain_ok(struct node_db *db)
{
    int64_t checked = 0;
    return db_fleet_board_chain_verify(db, &checked);
}

static int test_fleet_board_wiki_replacement_rules(void)
{
    int failures = 0;
    TEST("fleet board: at the ceiling, id decides a created_at tie, an "
        "older incoming revision is refused for good, another key's newer "
        "revision does not make a row evictable, and the other scope is "
        "untouched") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        zcl_fleet_role_checker_install_permissive_for_testing();
        db_fleet_board_test_set_wiki_limits(1000, 3);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post z, t1, t2, w, other, fleet_row, in;
        const int64_t now = 2000000;

        /* A created_at tie: the larger id is the later revision. */
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "zed", 50, 20, 1, now, &z),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "tie", 100, 20, 2, now, &t1),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "tie", 100, 20, 3, now, &t2),
                  FLEET_BOARD_OK);
        const struct fleet_board_post *lo =
            memcmp(t1.id, t2.id, 32) < 0 ? &t1 : &t2;
        const struct fleet_board_post *hi = lo == &t1 ? &t2 : &t1;
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "new", 300, 20, 4, now, &w),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, lo->id));
        ASSERT(db_fleet_board_have(&db, hi->id));
        ASSERT(db_fleet_board_have(&db, z.id));
        ASSERT(fb_chain_ok(&db));

        /* Older than a stored revision of its page: refused, final. */
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "new", 200, 20, 5, now, &in),
                  FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(!db_fleet_board_have(&db, in.id));
        ASSERT(db_fleet_board_have(&db, w.id));

        /* Another key's newer revision of the same slug is no reason to
         * replace this key's newest revision of it. */
        ASSERT_EQ(fb_put_wiki(&db, 42, FB_PUB, "zed", 900, 20, 6, now,
                              &other),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "fresh", 400, 20, 7, now, &in),
                  FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(db_fleet_board_have(&db, z.id));
        ASSERT(db_fleet_board_have(&db, other.id));
        node_db_close(&db);

        /* The same key's other scope is never read or removed. */
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post a1, a2, b1, a3;
        ASSERT_EQ(fb_put_wiki(&db, 41, FLEET_BOARD_SCOPE_FLEET, "a", 10, 20, 8,
                              now, &fleet_row), FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "a", 100, 20, 9, now, &a1),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "a", 200, 20, 10, now, &a2),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "b", 300, 20, 11, now, &b1),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 41, FB_PUB, "a", 400, 20, 12, now, &a3),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, a1.id));
        ASSERT(db_fleet_board_have(&db, fleet_row.id));
        ASSERT(fb_chain_ok(&db));
        node_db_close(&db);
        zcl_fleet_role_checker_install_permissive_for_testing();
        db_fleet_board_test_set_wiki_limits(0, 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

/* fb_put_wiki with an explicit ttl: `created_at` is an offset inside the
 * post's live window, so the row is created at now - 3000 + created_at. */
static enum fleet_board_result fb_put_wiki_ttl(struct node_db *db, uint8_t who,
                                               const char *slug,
                                               int64_t created_at,
                                               uint32_t ttl, int tag,
                                               int64_t now,
                                               struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    char text[32];
    (void)snprintf(text, sizeof(text), "t%d body", tag);
    fb_test_compose(out, FLEET_BOARD_KIND_WIKI, "budget", text,
                    (uint64_t)(now - 3000 + created_at), ttl);
    fb_test_scope(out, FB_PUB, "general");
    (void)snprintf(out->slug, sizeof(out->slug), "%s", slug);
    (void)snprintf(out->title, sizeof(out->title), "%s", slug);
    if (fleet_board_post_sign(out, seed, pk) != FLEET_BOARD_OK)
        return FLEET_BOARD_ERR_SIGNATURE;
    return db_fleet_board_post_ingest(db, out, now, NULL);
}

static int test_fleet_board_wiki_expired_evict(void)
{
    int failures = 0;
    TEST("fleet board: at the ceiling a key with no superseded revision "
        "replaces its oldest expired plain revision, keeps unexpired and "
        "review rows, and still prefers a superseded revision") {
        struct node_db db;
        struct fleet_board_post a, b, c, d, in;
        const int64_t n0 = 3000000;
        zcl_fleet_role_checker_install_permissive_for_testing();
        db_fleet_board_test_set_wiki_limits(1000, 3);

        /* a: three short-lived pages; A and B have outlived their ttl. */
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_reset_wiki_evictions();
        ASSERT_EQ(fb_put_wiki_ttl(&db, 51, "pa", 2900, 120, 1, n0, &a),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 51, "pb", 2950, 120, 2, n0, &b),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 51, "pc", 3000, 120, 3, n0, &c),
                  FLEET_BOARD_OK);
        /* b: nothing has expired yet, so the ceiling still refuses. */
        ASSERT_EQ(fb_put_wiki_ttl(&db, 51, "pd", 3000, 3600, 4, n0 + 10, &d),
                  FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(!db_fleet_board_have(&db, d.id));
        ASSERT(db_fleet_board_have(&db, a.id));
        /* a: A and B expired, C not; the oldest expired row makes room. */
        ASSERT_EQ(fb_put_wiki_ttl(&db, 51, "pd", 3000, 3600, 4, n0 + 100, &d),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, a.id));
        ASSERT(db_fleet_board_have(&db, b.id));
        ASSERT(db_fleet_board_have(&db, c.id));
        ASSERT(db_fleet_board_have(&db, d.id));
        ASSERT(fb_chain_ok(&db));
        node_db_close(&db);

        /* d: a superseded revision wins over an older expired page. */
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post s1, s2;
        ASSERT_EQ(fb_put_wiki_ttl(&db, 52, "old", 2900, 120, 5, n0, &a),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 52, "s", 2950, 120, 6, n0, &s1),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 52, "s", 3000, 120, 7, n0, &s2),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 52, "new", 3000, 3600, 8, n0 + 130,
                                  &in), FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, s1.id));
        ASSERT(db_fleet_board_have(&db, a.id));
        ASSERT(db_fleet_board_have(&db, s2.id));
        node_db_close(&db);

        /* c: an expired review row is lineage evidence, never a victim. */
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post target, review, other;
        ASSERT_EQ(fb_put_wiki_ttl(&db, 53, "tgt", 3000, 3600, 9, n0, &target),
                  FLEET_BOARD_OK);
        ASSERT(fb_review_compose(&review, 53, target.id, NULL, "approve",
                                 "ok", (uint64_t)n0));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &review, n0, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 53, "oth", 3000, 3600, 10, n0,
                                  &other), FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki_ttl(&db, 53, "nxt", 3000, 3600, 11, n0 + 1000,
                                  &in), FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(db_fleet_board_have(&db, review.id));
        ASSERT(db_fleet_board_have(&db, target.id));
        ASSERT(db_fleet_board_have(&db, other.id));
        node_db_close(&db);
        db_fleet_board_test_set_wiki_limits(0, 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static int test_fleet_board_wiki_replacement_chain(void)
{
    int failures = 0;
    TEST("fleet board: a replacement relinks only the rows after the "
        "victim, whether the victim is in the middle or at the tail") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 3);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post head, x1, x2, y, in;
        const int64_t now = 2100000;
        ASSERT_EQ(fb_put_wiki(&db, 43, FB_PUB, "head", 10, 20, 1, now, &head),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 44, FB_PUB, "x", 100, 20, 2, now, &x1),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 44, FB_PUB, "x", 200, 20, 3, now, &x2),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 44, FB_PUB, "y", 300, 20, 4, now, &y),
                  FLEET_BOARD_OK);
        struct db_fleet_board_post before, after;
        ASSERT(db_fleet_board_post_find(&db, head.id, &before));
        /* Middle: seq 2 of 4, two rows after it. */
        ASSERT_EQ(fb_put_wiki(&db, 44, FB_PUB, "w", 400, 20, 5, now, &in),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, x1.id));
        ASSERT(fb_chain_ok(&db));
        ASSERT(db_fleet_board_post_find(&db, head.id, &after));
        ASSERT_EQ(after.seq, before.seq);
        ASSERT(memcmp(after.chain_hash, before.chain_hash, 32) == 0);

        /* Tail: the superseded row is the last one stored. */
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post late;
        ASSERT_EQ(fb_put_wiki(&db, 45, FB_PUB, "q", 500, 20, 6, now, &late),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 45, FB_PUB, "r", 600, 20, 7, now, &late),
                  FLEET_BOARD_OK);
        struct fleet_board_post old_tail;
        ASSERT_EQ(fb_put_wiki(&db, 45, FB_PUB, "q", 450, 20, 8, now,
                              &old_tail), FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 45, FB_PUB, "s", 700, 20, 9, now, &in),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, old_tail.id));
        ASSERT(fb_chain_ok(&db));
        node_db_close(&db);
        db_fleet_board_test_set_wiki_limits(0, 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static int test_fleet_board_wiki_replacement_rolls_back(void)
{
    int failures = 0;
    TEST("fleet board: a replacement that cannot be appended near the "
        "half-store bound leaves the victim stored and the chain intact, and "
        "a slightly larger one that fits is taken") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 3);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post a1, a2, b, big, bigger;
        const int64_t now = 2200000;
        ASSERT_EQ(fb_put_wiki(&db, 46, FB_PUB, "a", 100, 100, 1, now, &a1),
                  FLEET_BOARD_OK);
        size_t body = 0;
        (void)fleet_board_post_canonical(&a1, NULL, 0, &body);
        /* Wiki rows may use half the byte cap: leave room for three rows
         * of this size and 20 bytes more. */
        db_fleet_board_test_set_store_limits(0, 2 * (3 * (int64_t)body + 20));
        ASSERT_EQ(fb_put_wiki(&db, 46, FB_PUB, "a", 200, 100, 2, now, &a2),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 46, FB_PUB, "b", 300, 100, 3, now, &b),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fb_put_wiki(&db, 46, FB_PUB, "a", 400, 110, 4, now, &big),
                  FLEET_BOARD_OK);
        ASSERT(!db_fleet_board_have(&db, a1.id));
        ASSERT(fb_chain_ok(&db));

        /* Too large once the victim's bytes are freed: refused after the
         * delete, so the delete must be undone. */
        ASSERT_EQ(fb_put_wiki(&db, 46, FB_PUB, "a", 500, 160, 5, now,
                              &bigger), FLEET_BOARD_ERR_CAPACITY);
        ASSERT(db_fleet_board_have(&db, a2.id));
        ASSERT(!db_fleet_board_have(&db, bigger.id));
        ASSERT(fb_chain_ok(&db));
        db_fleet_board_test_set_store_limits(0, 0);
        db_fleet_board_test_set_wiki_limits(0, 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_store_limits(0, 0);
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static int test_fleet_board_wiki_replacement_node_cap(void)
{
    int failures = 0;
    TEST("fleet board: replacements are capped node-wide per minute across "
        "keys, with the retryable window reason beyond the cap") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 2);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post p;
        int64_t now = 2300000;
        int tag = 0;
        for (uint8_t who = 47; who <= 48; who++)
            for (int i = 0; i < 2; i++)
                ASSERT_EQ(fb_put_wiki(&db, who, FB_PUB, "a", 100 + i, 20,
                                      tag++, now, &p), FLEET_BOARD_OK);
        for (int i = 0; i < FLEET_BOARD_WIKI_EVICT_MAX; i++) {
            ASSERT_EQ(fb_put_wiki(&db, (uint8_t)(47 + i % 2), FB_PUB, "a",
                                  1000 + i, 20, tag++, now + i, &p),
                      FLEET_BOARD_OK);
        }
        ASSERT_EQ(fb_put_wiki(&db, 47, FB_PUB, "a", 2000, 20, tag++, now + 10,
                              &p), FLEET_BOARD_ERR_WIKI_QUOTA);
        ASSERT(!db_fleet_board_have(&db, p.id));
        ASSERT_EQ(fb_put_wiki(&db, 47, FB_PUB, "a", 2001, 20, tag++, now + 61,
                              &p), FLEET_BOARD_OK);
        ASSERT(fb_chain_ok(&db));
        db_fleet_board_test_reset_wiki_evictions();
        db_fleet_board_test_set_wiki_limits(0, 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static int test_fleet_board_stored_ceilings_are_separate(void)
{
    int failures = 0;
    TEST("fleet board: the ordinary stored ceiling ignores wiki rows, and "
        "a held revision is answered before any quota is asked") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 0);
        uint8_t seed[32], pk[32];
        fb_test_identity(27, seed, pk);
        struct fleet_board_post p, held;
        int64_t now = 1000000;
        for (int i = 0; i < 150; i++) {
            char slug[16];
            (void)snprintf(slug, sizeof(slug), "k-%d", i);
            now += 31;
            ASSERT_EQ(fb_test_put_rev(&db, slug, i, 27, now,
                                      i == 0 ? &held : &p),
                      FLEET_BOARD_OK);
        }
        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX; i++) {
            now += 31;
            fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, i, seed, pk, now);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                      FLEET_BOARD_OK);
        }
        now += 31;
        fb_test_public_post(&p, FLEET_BOARD_KIND_NOTE, 5000, seed, pk, now);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, NULL),
                  FLEET_BOARD_ERR_QUOTA);
        /* The same revision again is settled, not charged to any quota,
         * even with the wiki window spent. */
        db_fleet_board_test_set_wiki_limits(1, 0);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &held, now, &stored),
                  FLEET_BOARD_OK);
        ASSERT(!stored);
        db_fleet_board_test_set_wiki_limits(0, 0);
        node_db_close(&db);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static const char FB_ENTRY_OK[] =
    "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"push-gate\","
    "\"summary\":\"The push gate runs the full lint.\","
    "\"lessons\":[{\"rule\":\"Run the full lint before pushing.\","
    "\"why\":\"lint-fast skips whole-tree gates.\","
    "\"evidence\":\"docs/dev/DEVELOPING.md\"}],"
    "\"applies_to\":[\"Git\",\"landing\"],"
    "\"updated\":\"2026-10-12T09:00:00Z\"}";

static int test_fleet_wiki_entry_validation(void)
{
    int failures = 0;
    TEST("fleet wiki: an entry is accepted only when it matches the schema") {
        struct json_value entry;
        const char *why = NULL;
        ASSERT(fleet_wiki_entry_parse(FB_ENTRY_OK, strlen(FB_ENTRY_OK),
                                      &entry, &why));
        ASSERT(fleet_wiki_entry_matches(&entry, "git"));
        ASSERT(fleet_wiki_entry_matches(&entry, "full lint"));
        ASSERT(fleet_wiki_entry_matches(&entry, "push-g"));
        ASSERT(!fleet_wiki_entry_matches(&entry, "nothing-here"));
        /* Several words: each in some field, not necessarily the same one;
         * one missing word fails the entry, and field names never match. */
        ASSERT(fleet_wiki_entry_matches(&entry, "landing whole-tree"));
        ASSERT(fleet_wiki_entry_matches(&entry, " GIT\tlint-fast "));
        ASSERT(!fleet_wiki_entry_matches(&entry, "landing nothing-here"));
        ASSERT(!fleet_wiki_entry_matches(&entry, "landing applies_to"));
        ASSERT(!fleet_wiki_entry_matches(&entry, "  "));
        {
            const char *fields[FLEET_WIKI_MATCH_FIELDS];
            ASSERT_EQ(fleet_wiki_entry_matched_fields(&entry, "rollback-drill",
                          "rollback whole-tree", fields), 2);
            ASSERT_STR_EQ(fields[0], "slug");
            ASSERT_STR_EQ(fields[1], "why");
            const char *pf[3];
            ASSERT_EQ(fleet_wiki_page_matched_fields("ops-notes", "Deploy",
                          "Restart one host", "deploy host", pf), 2);
            ASSERT_STR_EQ(pf[0], "title");
            ASSERT_STR_EQ(pf[1], "summary");
            ASSERT_EQ(fleet_wiki_page_matched_fields("ops-notes", "Deploy",
                          "Restart one host", "deploy nowhere", pf), 0);
        }
        {
            struct fleet_wiki_entry_query sq = {.q = "rollback",
                .slug = "rollback-drill"};
            ASSERT(fleet_wiki_entry_query_matches(&entry, &sq));
            sq.slug = NULL;
            ASSERT(!fleet_wiki_entry_query_matches(&entry, &sq));
            sq.slug = "rollback-drill";
            sq.topic = "other";
            ASSERT(!fleet_wiki_entry_query_matches(&entry, &sq));
            sq.topic = NULL;
            sq.q = "ROLLBACK";
            ASSERT(fleet_wiki_entry_query_matches(&entry, &sq));
        }
        json_free(&entry);

        const char *bad[] = {
            "plain prose, not an entry",
            "{\"schema\":\"zcl.fleet_wiki_entry.v2\"}",
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"Bad Topic\","
            "\"summary\":\"s\",\"lessons\":[{\"rule\":\"r\",\"why\":\"\","
            "\"evidence\":\"\"}],\"applies_to\":[],"
            "\"updated\":\"2026-10-12T09:00:00Z\"}",
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
            "\"summary\":\"s\",\"lessons\":[],\"applies_to\":[],"
            "\"updated\":\"2026-10-12T09:00:00Z\"}",
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
            "\"summary\":\"s\",\"lessons\":[{\"rule\":\"r\",\"why\":\"\","
            "\"evidence\":\"\"}],\"applies_to\":[],"
            "\"updated\":\"2026-10-12 09:00:00\"}",
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
            "\"summary\":\"s\",\"lessons\":[{\"rule\":\"r\",\"why\":\"\","
            "\"evidence\":\"\"}],\"applies_to\":[],"
            "\"updated\":\"2026-10-12T09:00:00Z\",\"extra\":1}",
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            why = NULL;
            ASSERT(!fleet_wiki_entry_parse(bad[i], strlen(bad[i]), &entry,
                                           &why));
            ASSERT(why != NULL);
        }

        char big[512];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        char text[1400];
        (void)snprintf(text, sizeof(text),
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
            "\"summary\":\"%.201s\",\"lessons\":[{\"rule\":\"r\",\"why\":\"\","
            "\"evidence\":\"\"}],\"applies_to\":[],"
            "\"updated\":\"2026-10-12T09:00:00Z\"}", big);
        ASSERT(!fleet_wiki_entry_parse(text, strlen(text), &entry, &why));
        PASS();
    } _test_next:;
    return failures;
}

/* One RPC call against the board; `input` is consumed by the caller. */
static bool fb_test_rpc(const struct rpc_table *table, struct json_value *input,
                        struct json_value *result)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    bool ok = json_push_back(&params, input) &&
              rpc_table_execute(table, "fleet_board", &params, result);
    json_free(&params);
    return ok;
}

static bool fb_test_ingest_page(struct node_db *db, const char *slug,
                                const char *text, int n, int64_t now)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(31, seed, pk);
    struct fleet_board_post p;
    fb_test_compose(&p, FLEET_BOARD_KIND_WIKI, "scribe", text,
                    (uint64_t)now, 3600);
    fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
    (void)snprintf(p.slug, sizeof(p.slug), "%s", slug);
    (void)snprintf(p.title, sizeof(p.title), "Page %d", n);
    return fleet_board_post_sign(&p, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(db, &p, now, NULL) == FLEET_BOARD_OK;
}

static unsigned fb_wiki_backend_variant;
static char *fb_wiki_backend_rpc(const char *method, const char *params)
{
    (void)params;
    if (strcmp(method, "fleet_board")) return NULL;
    static const char *const ENTRIES[] = {
        "[]",
        "[{\"slug\":\"kernel\",\"summary\":\"old backend\"}]",
        "[{\"id\":\"bad\",\"host\":\"bad\",\"created_at\":1,\"expires_at\":2}]",
        "[{\"id\":\"1111111111111111111111111111111111111111111111111111111111111111\","
        "\"host\":\"2222222222222222222222222222222222222222222222222222222222222222\","
        "\"created_at\":\"1\",\"expires_at\":2}]",
        "[{\"id\":\"1111111111111111111111111111111111111111111111111111111111111111\","
        "\"host\":\"2222222222222222222222222222222222222222222222222222222222222222\","
        "\"created_at\":2,\"expires_at\":1}]",
        "[]"
    };
    if (fb_wiki_backend_variant >= sizeof(ENTRIES) / sizeof(ENTRIES[0])) return NULL;
    char wire[1024];
    const char *marker = fb_wiki_backend_variant < 2 ? "" :
        "\"identity_schema\":\"" FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA "\",";
    int n = snprintf(wire, sizeof(wire),
        "{\"ok\":true,%s\"entries\":%s,\"returned\":%u,\"scanned\":256,\"truncated\":false}",
        marker, ENTRIES[fb_wiki_backend_variant],
        fb_wiki_backend_variant == 0 || fb_wiki_backend_variant == 5 ? 0u : 1u);
    if (n < 0 || (size_t)n >= sizeof(wire)) return NULL;
    char *copy = malloc((size_t)n + 1);
    if (copy) memcpy(copy, wire, (size_t)n + 1);
    return copy;
}
static bool fb_wiki_backend_case(unsigned variant)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_wiki_find.v1");
    fb_wiki_backend_variant = variant;
    node_rpc_client_set_test_hook(fb_wiki_backend_rpc);
    bool ok = json_push_kv_str(&input, "q", "kernel");
    if (ok) zcl_native_handle_fleet_steer_wiki_find(&request, &reply);
    if (variant == 5)
        ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED;
    else
        ok = ok && reply.status == ZCL_COMMAND_STATUS_FAILED &&
            !strcmp(reply.error.code, "WIKI_CAPABILITY_UNAVAILABLE") &&
            !json_get(&reply.data, "exact_read") && !json_get(&reply.data, "discovery");
    node_rpc_client_set_test_hook(NULL);
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}
static int test_fleet_wiki_backend_capability(void)
{
    int failures = 0;
    TEST("fleet wiki: old empty and populated backends or invalid identities refuse pinned discovery") {
        for (unsigned variant = 0; variant < 6; variant++)
            ASSERT(fb_wiki_backend_case(variant));
        struct json_value envelope;
        json_init(&envelope);
        static const char MAX_ENVELOPE[] =
            "{\"ok\":true,\"identity_schema\":\"" FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA "\","
            "\"entries\":[],\"returned\":8,\"scanned\":256,\"truncated\":false}";
        bool parsed = json_read(&envelope, MAX_ENVELOPE, sizeof(MAX_ENVELOPE) - 1);
        size_t size = parsed ? json_write(&envelope, NULL, 0) : 0;
        json_free(&envelope);
        ASSERT(parsed); ASSERT(size > 0 && size <= 192);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static bool fb_wiki_native_find(struct zcl_command_request *request, const char *id)
{
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_wiki_find.v1");
    zcl_native_handle_fleet_steer_wiki_find(request, &reply);
    const struct json_value *discovery = json_get(&reply.data, "discovery");
    const char *found = json_get_str(json_get(json_at(json_get(discovery, "entries"), 0), "id"));
    const char *selection = json_get_str(json_get(&reply.data, "selection"));
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
        json_get_bool(json_get(&reply.data, "untrusted")) &&
        selection && !strcmp(selection, "latest-held") &&
        json_get_int(json_get(&reply.data, "observed_at")) > 0 &&
        json_get_int(json_get(discovery, "returned")) == 1 && found && !strcmp(found, id);
    zcl_command_reply_free(&reply);
    return ok;
}
/* Inject sibling responses, rather than modifying the held mail store. This
 * exercises completion and paging independently of the native pull fixtures. */
static unsigned fb_mail_fault, fb_mail_pages;
static bool fb_mail_inputs_ok;
static bool fb_mail_fixture_input(const struct zcl_command_request *request)
{
    const struct json_value *since = json_get(request->input, "since");
    const char *ref = json_get_str(json_get(request->input, "ref"));
    char expected[80];
    (void)snprintf(expected, sizeof(expected), "v1:outbox=%u;inbox.receiver=%u", fb_mail_pages * 64, fb_mail_pages);
    return ref && !strcmp(ref, "read-fixture") &&
        !json_get(request->input, "from") && !json_get(request->input, "to") &&
        !json_get(request->input, "kind") && !json_get(request->input, "agent") &&
        since && (fb_mail_pages ? since->type == JSON_STR &&
            !strcmp(json_get_str(since), expected) :
            since->type == JSON_INT && json_get_int(since) == 0);
}
static void fb_mail_fixture_row(struct json_value *row, bool more, unsigned i)
{
    json_set_object(row);
    (void)json_push_kv_str(row, "ref", "read-fixture");
    (void)json_push_kv_str(row, "body", more ? "earlier" : "last reply");
    (void)json_push_kv_str(row, "from", more ? "sender" : "receiver");
    (void)json_push_kv_str(row, "to", more ? "receiver" : "sender");
    (void)json_push_kv_str(row, "kind", more ? "directive" : "result");
    (void)json_push_kv_str(row, "ts", more ? "2026-10-14T01:00:00Z" : "2026-10-13T01:00:00Z");
    (void)json_push_kv_int(row, "seq", i + 1);
}
static void fb_mail_fixture_scalar_fault(struct json_value *data)
{
    static const char *const keys[] = {"rows", "truncated", "next_since", "sources"};
    if (fb_mail_fault < 7 || fb_mail_fault > 10) return;
    struct json_value *value = (struct json_value *)json_get(data, keys[fb_mail_fault - 7]);
    if (value) json_set_int(value, 1);
}
static void fb_mail_pull_fixture(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    fb_mail_inputs_ok = fb_mail_inputs_ok && fb_mail_fixture_input(request);
    fb_mail_pages++;
    bool more = fb_mail_fault == 0 && fb_mail_pages < 3;
    struct json_value rows, sources, row;
    json_init(&rows); json_init(&sources); json_init(&row);
    json_set_array(&rows); json_set_array(&sources);
    for (unsigned i = 0; i < 64 && fb_mail_fault == 0; i++) {
        fb_mail_fixture_row(&row, more, i);
        (void)json_push_back(&rows, &row);
    }
    json_set_object(&row);
    (void)json_push_kv_bool(&row, "complete", fb_mail_fault != 6);
    (void)json_push_back(&sources, &row);
    if (fb_mail_fault != 2) (void)json_push_kv(&reply->data, "rows", &rows);
    if (fb_mail_fault != 3) (void)json_push_kv_bool(&reply->data, "truncated", more);
    (void)json_push_kv_int(&reply->data, "cursor", fb_mail_fault == 4 ? -1 : 99);
    char token[80];
    (void)snprintf(token, sizeof(token), "v1:outbox=%u;inbox.receiver=%u", fb_mail_pages * 64, fb_mail_pages);
    if (fb_mail_fault != 5) (void)json_push_kv_str(&reply->data, "next_since", token);
    (void)json_push_kv(&reply->data, "sources", &sources);
    fb_mail_fixture_scalar_fault(&reply->data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    json_free(&row); json_free(&sources); json_free(&rows);
}

static int test_fleet_evidence_completion(void)
{
    int failures = 0;
    TEST("fleet evidence: drains filtered pages and refuses unproven absence") {
        for (unsigned mode = 0; mode < 11; mode++) {
            struct json_value input;
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "type", "mail"));
            ASSERT(json_push_kv_str(&input, "ref", "read-fixture"));
            struct zcl_command_request request = {.input = &input};
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.fleet_steer_evidence.v1");
            fb_mail_fault = mode; fb_mail_pages = 0; fb_mail_inputs_ok = true;
            zcl_fleet_steer_test_set_mail_pull(fb_mail_pull_fixture);
            zcl_native_handle_fleet_steer_evidence(&request, &reply);
            zcl_fleet_steer_test_set_mail_pull(NULL);
            bool ok = fb_mail_inputs_ok;
            if (!mode) ok = ok && fb_mail_pages == 3 &&
                reply.status == ZCL_COMMAND_STATUS_PASSED &&
                !strcmp(json_get_str(json_get(json_get(&reply.data, "object"), "body")), "last reply");
            else {
                const char *code = reply.error.code;
                ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && code &&
                    !strcmp(code, mode == 1 ? "EVIDENCE_NOT_FOUND" : "EVIDENCE_UNAVAILABLE");
            }
            zcl_command_reply_free(&reply); json_free(&input);
            ASSERT(ok);
        }
        PASS();
    } _test_next:;
    zcl_fleet_steer_test_set_mail_pull(NULL);
    return failures;
}

static bool fb_wiki_native_exact(struct zcl_command_request *request, const char *id)
{
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_evidence.v1");
    zcl_native_handle_fleet_steer_evidence(request, &reply);
    const char *found = json_get_str(json_get(json_get(&reply.data, "object"), "id"));
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && found && !strcmp(found, id);
    zcl_command_reply_free(&reply);
    return ok;
}
static bool fb_wiki_native_roundtrip(const struct rpc_table *table,
    struct node_db *db, const char *id)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    struct zcl_command_request request = {.input = &input};
    int changes = sqlite3_total_changes(db->db);
    fb_native_test_table = table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    bool ok = json_push_kv_str(&input, "q", "FULL LINT") && fb_wiki_native_find(&request, id);
    json_free(&input); json_init(&input); json_set_object(&input);
    ok = ok && json_push_kv_str(&input, "type", "board") &&
        json_push_kv_str(&input, "ref", id) && fb_wiki_native_exact(&request, id) &&
        sqlite3_total_changes(db->db) == changes;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    json_free(&input);
    return ok;
}

static int test_fleet_wiki_find_and_read(void)
{
    int failures = 0;
    TEST("fleet wiki: read returns the parsed entry, find returns at most 8 "
        "matching results with rules, and malformed pages are skipped") {
        struct node_db db = {0};
        ASSERT(node_db_open(&db, ":memory:"));
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        struct boot_svc_ctx svc = {.node_db = &db};
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        struct rpc_table table;
        rpc_table_init(&table);
        boot_fleet_board_register_rpc(&table);
        char warmup_status[256];
        bool was_warming_up = rpc_is_in_warmup(warmup_status,
                                               sizeof(warmup_status));
        set_rpc_warmup_finished();
        const int64_t now = (int64_t)platform_time_wall_time_t();

        ASSERT(fb_test_ingest_page(&db, "push-gate", FB_ENTRY_OK, 0, now));
        ASSERT(fb_test_ingest_page(&db, "plain-page",
                                   "prose that mentions git", 1, now));
        for (int i = 0; i < 10; i++) {
            char slug[32], text[600];
            (void)snprintf(slug, sizeof(slug), "topic-%02d", i);
            (void)snprintf(text, sizeof(text),
                "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"%s\","
                "\"summary\":\"bulk entry %d\",\"lessons\":[{\"rule\":\"rule "
                "%d\",\"why\":\"w\",\"evidence\":\"e\"}],"
                "\"applies_to\":[\"bulk\"],"
                "\"updated\":\"2026-10-12T09:00:00Z\"}", slug, i, i);
            ASSERT(fb_test_ingest_page(&db, slug, text, 2 + i, now));
        }

        struct json_value in, result;
        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "wiki_read") &&
               json_push_kv_str(&in, "slug", "push-gate"));
        ASSERT(fb_test_rpc(&table, &in, &result));
        const struct json_value *entry = json_get(&result, "entry");
        ASSERT(entry != NULL);
        ASSERT(strcmp(json_get_str(json_get(entry, "topic")), "push-gate") == 0);
        json_free(&in); json_free(&result);

        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "wiki_read") &&
               json_push_kv_str(&in, "slug", "plain-page"));
        ASSERT(fb_test_rpc(&table, &in, &result));
        ASSERT(json_get(&result, "entry") == NULL);
        json_free(&in); json_free(&result);

        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "wiki_find") &&
               json_push_kv_str(&in, "q", "GIT"));
        ASSERT(fb_test_rpc(&table, &in, &result));
        ASSERT_EQ(json_get_int(json_get(&result, "returned")), 2);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&result, "entries"), 0), "kind")), "page");
        const struct json_value *hit =
            json_at(json_get(&result, "entries"), 1);
        struct db_fleet_board_post exact;
        char exact_id[65], exact_host[65];
        ASSERT(db_fleet_board_wiki_read(&db, "push-gate", &exact));
        fleet_board_id_to_hex(exact.post.id, exact_id);
        fleet_board_id_to_hex(exact.post.host_pubkey, exact_host);
        ASSERT_STR_EQ(json_get_str(json_get(hit, "id")), exact_id);
        ASSERT_STR_EQ(json_get_str(json_get(hit, "host")), exact_host);
        ASSERT_EQ(json_get_int(json_get(hit, "created_at")), (int64_t)exact.post.created_at);
        ASSERT_EQ(json_get_int(json_get(hit, "expires_at")), exact.expires_at);
        ASSERT(json_write(&result, NULL, 0) <= 16 * 1024);
        ASSERT(fb_wiki_native_roundtrip(&table, &db, exact_id));
        ASSERT(strcmp(json_get_str(json_get(hit, "slug")), "push-gate") == 0);
        ASSERT(strcmp(json_get_str(json_at(json_get(hit, "rules"), 0)),
                      "Run the full lint before pushing.") == 0);
        json_free(&in); json_free(&result);

        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "wiki_find") &&
               json_push_kv_str(&in, "q", "bulk") &&
               json_push_kv_int(&in, "response_budget", 8192));
        ASSERT(fb_test_rpc(&table, &in, &result));
        ASSERT_EQ(json_get_int(json_get(&result, "returned")), 8);
        ASSERT(json_get_bool(json_get(&result, "truncated")));
        json_free(&in); json_free(&result);

        ASSERT(fb_test_ingest_page(&db, "rollback-drill",
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"drills\","
            "\"summary\":\"A drill note.\","
            "\"lessons\":[{\"rule\":\"Practise the revert.\",\"why\":\"w\","
            "\"evidence\":\"e\"}],\"applies_to\":[\"ops\"],"
            "\"updated\":\"2026-10-12T09:00:00Z\"}", 12, now));
        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "wiki_find") &&
               json_push_kv_str(&in, "q", "rollback"));
        ASSERT(fb_test_rpc(&table, &in, &result));
        ASSERT_EQ(json_get_int(json_get(&result, "returned")), 1);
        ASSERT(strcmp(json_get_str(json_get(json_at(json_get(&result, "entries"), 0), "slug")),
                      "rollback-drill") == 0);
        json_free(&in); json_free(&result);

        json_init(&in); json_init(&result);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "post") &&
               json_push_kv_str(&in, "kind", "wiki") &&
               json_push_kv_str(&in, "slug", "bad-entry") &&
               json_push_kv_str(&in, "title", "Bad") &&
               json_push_kv_str(&in, "text", "not json") &&
               json_push_kv_str(&in, "format", "entry"));
        ASSERT(fb_test_rpc(&table, &in, &result));
        ASSERT(!json_get_bool(json_get(&result, "ok")));
        ASSERT(strcmp(json_get_str(json_get(&result, "code")), "BAD_ENTRY") == 0);
        json_free(&in); json_free(&result);

        app_runtime_set_current(NULL);
        if (was_warming_up)
            set_rpc_warmup_started(warmup_status);
        boot_fleet_board_shutdown();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* An entry with one lesson built from the given pieces; `applies` and
 * `lessons` are raw JSON array bodies. */
static void fb_entry_json(char *out, size_t cap, const char *summary,
                          const char *lessons, const char *applies)
{
    (void)snprintf(out, cap,
        "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
        "\"summary\":\"%s\",\"lessons\":[%s],\"applies_to\":[%s],"
        "\"updated\":\"2026-10-12T09:00:00Z\"}", summary, lessons, applies);
}

#define FB_ONE_LESSON "{\"rule\":\"r\",\"why\":\"w\",\"evidence\":\"e\"}"

static int test_fleet_wiki_entry_rejections(void)
{
    int failures = 0;
    TEST("fleet wiki: duplicate keys, invalid UTF-8, too many lessons and an "
        "over-long applies_to item are all refused") {
        static char text[8192], lessons[4096], applies[256];
        struct json_value entry;
        const char *why = NULL;
        const char *dup_root =
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"t\","
            "\"topic\":\"u\",\"summary\":\"s\",\"lessons\":[" FB_ONE_LESSON
            "],\"applies_to\":[],\"updated\":\"2026-10-12T09:00:00Z\"}";
        ASSERT(!fleet_wiki_entry_parse(dup_root, strlen(dup_root), &entry,
                                       &why));
        fb_entry_json(text, sizeof(text), "s",
                      "{\"rule\":\"a\",\"rule\":\"b\",\"why\":\"w\","
                      "\"evidence\":\"e\"}", "");
        ASSERT(!fleet_wiki_entry_parse(text, strlen(text), &entry, &why));

        /* Overlong, surrogate and stray-continuation byte sequences. */
        const char *bad_utf8[] = { "\xC0" "\xAF", "\xED" "\xA0" "\x80",
                                   "\xE0" "\x80" "\x80", "\x80", "\xF5" "ab" };
        for (size_t i = 0; i < sizeof(bad_utf8) / sizeof(bad_utf8[0]); i++) {
            fb_entry_json(text, sizeof(text), bad_utf8[i], FB_ONE_LESSON, "");
            ASSERT(!fleet_wiki_entry_parse(text, strlen(text), &entry, &why));
        }
        fb_entry_json(text, sizeof(text), "caf" "\xC3" "\xA9", FB_ONE_LESSON,
                      "\"na" "\xC3" "\xAF" "ve\"");
        ASSERT(fleet_wiki_entry_parse(text, strlen(text), &entry, &why));
        json_free(&entry);

        lessons[0] = '\0';
        for (int i = 0; i < FLEET_WIKI_ENTRY_LESSONS_MAX + 1; i++) {
            if (i)
                (void)strcat(lessons, ",");
            (void)strcat(lessons, FB_ONE_LESSON);
            if (i == FLEET_WIKI_ENTRY_LESSONS_MAX - 1) {
                fb_entry_json(text, sizeof(text), "s", lessons, "");
                ASSERT(fleet_wiki_entry_parse(text, strlen(text), &entry,
                                              &why));
                json_free(&entry);
            }
        }
        fb_entry_json(text, sizeof(text), "s", lessons, "");
        ASSERT(!fleet_wiki_entry_parse(text, strlen(text), &entry, &why));

        applies[0] = '"';
        memset(applies + 1, 'a', FLEET_WIKI_ENTRY_APPLIES_LEN_MAX + 1);
        applies[FLEET_WIKI_ENTRY_APPLIES_LEN_MAX + 2] = '"';
        applies[FLEET_WIKI_ENTRY_APPLIES_LEN_MAX + 3] = '\0';
        fb_entry_json(text, sizeof(text), "s", FB_ONE_LESSON, applies);
        ASSERT(!fleet_wiki_entry_parse(text, strlen(text), &entry, &why));
        applies[FLEET_WIKI_ENTRY_APPLIES_LEN_MAX + 1] = '"';
        applies[FLEET_WIKI_ENTRY_APPLIES_LEN_MAX + 2] = '\0';
        fb_entry_json(text, sizeof(text), "s", FB_ONE_LESSON, applies);
        ASSERT(fleet_wiki_entry_parse(text, strlen(text), &entry, &why));
        json_free(&entry);
        PASS();
    } _test_next:;
    return failures;
}

struct fb_rpc_env {
    struct node_db db;
    struct db_service service;
    struct app_runtime_context runtime;
    struct boot_svc_ctx svc;
    struct rpc_table table;
    char warmup_status[256];
    bool was_warming_up;
};

static bool fb_rpc_env_open(struct fb_rpc_env *e)
{
    memset(e, 0, sizeof(*e));
    if (!node_db_open(&e->db, ":memory:"))
        return false;
    e->service = (struct db_service){.node_db = &e->db, .started = true};
    e->runtime = (struct app_runtime_context){.db_service = &e->service};
    e->svc = (struct boot_svc_ctx){.node_db = &e->db};
    boot_fleet_board_shutdown();
    boot_fleet_board_wire(&e->svc);
    app_runtime_set_current(&e->runtime);
    rpc_table_init(&e->table);
    boot_fleet_board_register_rpc(&e->table);
    e->was_warming_up = rpc_is_in_warmup(e->warmup_status,
                                         sizeof(e->warmup_status));
    set_rpc_warmup_finished();
    return true;
}

static void fb_rpc_env_close(struct fb_rpc_env *e)
{
    app_runtime_set_current(NULL);
    if (e->was_warming_up)
        set_rpc_warmup_started(e->warmup_status);
    boot_fleet_board_shutdown();
    node_db_close(&e->db);
}

/* Run one board op with up to two string arguments; `result` is the caller's
 * to free. */
static bool fb_rpc_op(struct fb_rpc_env *e, const char *op, const char *k1,
                      const char *v1, const char *k2, const char *v2,
                      struct json_value *result)
{
    struct json_value in;
    json_init(&in);
    json_init(result);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", op) &&
              (!k1 || json_push_kv_str(&in, k1, v1)) &&
              (!k2 || json_push_kv_str(&in, k2, v2)) &&
              fb_test_rpc(&e->table, &in, result);
    json_free(&in);
    return ok;
}

static void fb_max_entry(char *out, size_t cap, const char *topic)
{
    char rule[FLEET_WIKI_ENTRY_RULE_MAX + 1], why[301], ev[301];
    memset(rule, 'r', FLEET_WIKI_ENTRY_RULE_MAX);
    rule[FLEET_WIKI_ENTRY_RULE_MAX] = '\0';
    memset(why, 'w', 300);
    why[300] = '\0';
    memset(ev, 'e', 300);
    ev[300] = '\0';
    char summary[FLEET_WIKI_ENTRY_SUMMARY_MAX + 1];
    memset(summary, 's', FLEET_WIKI_ENTRY_SUMMARY_MAX);
    summary[FLEET_WIKI_ENTRY_SUMMARY_MAX] = '\0';
    size_t off = (size_t)snprintf(out, cap,
        "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"%s\","
        "\"summary\":\"%s\",\"lessons\":[", topic, summary);
    for (int i = 0; i < FLEET_WIKI_ENTRY_LESSONS_MAX; i++)
        off += (size_t)snprintf(out + off, cap - off,
            "%s{\"rule\":\"%s\",\"why\":\"%s\",\"evidence\":\"%s\"}",
            i ? "," : "", rule, why, ev);
    (void)snprintf(out + off, cap - off,
        "],\"applies_to\":[\"budget\"],\"updated\":\"2026-10-12T09:00:00Z\"}");
}

static bool fb_chunk_envelope_as(struct fb_rpc_env *e, const char *id,
                              int64_t offset, struct json_value *envelope, bool wrapper, size_t budget, bool fleet)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id", id);
    (void)json_push_kv_int(&input, "offset", offset);
    if (fleet && !wrapper) (void)json_push_kv_str(&input, "scope", "fleet");
    (void)json_push_kv_int(&input, "bytes", 1024);
    const char *path = wrapper ? "fleet.steer.wiki-read" : "fleet.wiki.read";
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg,
        path, NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    char wire[8193];
    enum zcl_command_exit rc;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, path, "full", budget, 0, NULL, wire, sizeof(wire), &rc);
    node_rpc_client_set_test_hook(NULL);
    fb_native_test_table = NULL;
    json_free(&input);
    json_init(envelope);
    return rc == ZCL_COMMAND_EXIT_OK && n <= budget &&
        json_read(envelope, wire, strlen(wire));
}

static bool fb_chunk_envelope(struct fb_rpc_env *e, const char *id,
                              int64_t offset, struct json_value *envelope)
{
    return fb_chunk_envelope_as(e, id, offset, envelope, false, 4096, false);
}

static bool fb_chunk_metadata(const struct json_value *data,
                              struct fleet_board_post *post)
{
    post->kind = FLEET_BOARD_KIND_WIKI;
    post->created_at = (uint64_t)json_get_int(json_get(data, "created_at"));
    post->ttl = (uint32_t)json_get_int(json_get(data, "ttl"));
    post->text_len = (uint32_t)json_get_int(json_get(data, "text_len"));
    post->scope = (uint8_t)json_get_int(json_get(data, "signed_scope"));
    (void)snprintf(post->room, sizeof(post->room), "%s", json_get_str(json_get(data, "signed_room")));
    (void)snprintf(post->agent, sizeof(post->agent), "%s", json_get_str(json_get(data, "agent")));
    (void)snprintf(post->slug, sizeof(post->slug), "%s", json_get_str(json_get(data, "slug")));
    (void)snprintf(post->title, sizeof(post->title), "%s", json_get_str(json_get(data, "title")));
    (void)snprintf(post->receipt, sizeof(post->receipt), "%s", json_get_str(json_get(data, "receipt")));
    return zcl_hex_decode(json_get_str(json_get(data, "id")), post->id, 32) &&
        zcl_hex_decode(json_get_str(json_get(data, "host")), post->host_pubkey, 32) &&
        zcl_hex_decode(json_get_str(json_get(data, "ref")), post->ref, 32) &&
        zcl_hex_decode(json_get_str(json_get(data, "supersedes")), post->supersedes, 32) &&
        zcl_hex_decode(json_get_str(json_get(data, "signature")), post->signature, 64);
}

static bool fb_chunk_reassemble_as(struct fb_rpc_env *e, const char *id,
                                const struct fleet_board_post *expected, bool wrapper, size_t budget)
{
    struct fleet_board_post recovered = {0};
    memset(recovered.text, 0, sizeof(recovered.text));
    int64_t offset = 0;
    while ((uint64_t)offset < expected->text_len) {
        struct json_value envelope;
        if (!fb_chunk_envelope_as(e, id, offset, &envelope, wrapper, budget, expected->scope == FLEET_BOARD_SCOPE_FLEET)) {
            json_free(&envelope);
            return false;
        }
        const struct json_value *data = json_get(&envelope, "data");
        if (wrapper) data = json_get(data, "revision");
        int64_t next = json_get_int(json_get(data, "next_offset"));
        bool ok = next > offset && (uint64_t)next <= expected->text_len &&
            !strcmp(json_get_str(json_get(data, "id")), id) &&
            !json_get(data, "text") && !json_get(data, "entry");
        if (ok) ok = fb_chunk_metadata(data, &recovered);
        if (ok) ok = zcl_hex_decode(json_get_str(json_get(data, "data_hex")),
            (uint8_t *)recovered.text + offset, (size_t)(next - offset));
        json_free(&envelope);
        if (!ok) return false;
        offset = next;
    }
    return !memcmp(recovered.text, expected->text, expected->text_len) &&
        fleet_board_post_verify(&recovered) == FLEET_BOARD_OK &&
        !memcmp(recovered.id, expected->id, 32);
}

static bool fb_chunk_reassemble(struct fb_rpc_env *e, const char *id,
                                const struct fleet_board_post *expected)
{
    return fb_chunk_reassemble_as(e, id, expected, false, 4096);
}

static bool fb_chunk_refused(struct fb_rpc_env *e, const char *id,
                             int64_t offset, int64_t bytes, const char *code)
{
    struct json_value input, result;
    json_init(&input); json_init(&result); json_set_object(&input);
    (void)json_push_kv_str(&input, "op", "wiki_read");
    (void)json_push_kv_str(&input, "id", id);
    (void)json_push_kv_int(&input, "offset", offset);
    (void)json_push_kv_int(&input, "bytes", bytes);
    bool ok = fb_test_rpc(&e->table, &input, &result) &&
        !json_get_bool(json_get(&result, "ok")) &&
        !strcmp(json_get_str(json_get(&result, "code")), code);
    json_free(&input); json_free(&result);
    return ok;
}

static bool fb_chunk_wrapper_refused(struct fb_rpc_env *e, const char *id)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id", id);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_wiki_read.v1");
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    zcl_native_handle_fleet_steer_wiki_read(&request, &reply);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    const char *code = reply.error.code;
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED && code &&
        !strcmp(code, "WIKI_READ_UNAVAILABLE") && !json_get(&reply.data, "revision");
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static bool fb_chunk_copy_fault(struct fb_rpc_env *e, const char *id,
    const char *label, unsigned nth, bool *hit)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id", id);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_wiki_read.v1");
    fb_native_test_table = &e->table;
    fb_native_projection_fault = label; fb_native_projection_nth = nth;
    node_rpc_client_set_test_hook(fb_native_rpc);
    zcl_native_handle_fleet_steer_wiki_read(&request, &reply);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    *hit = zcl_alloc_fault_armed_label() == NULL;
    fb_native_projection_fault = NULL;
    zcl_alloc_fault_clear();
    bool passed = reply.status == ZCL_COMMAND_STATUS_PASSED;
    bool ok = *hit ? !passed && reply.error.code[0] : passed;
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static bool fb_chunk_copy_faults(struct fb_rpc_env *e, const char *id)
{
    const char *labels[] = {"json_set_str", "json_copy_str", "json_copy_key",
        "json_copy_children", "json_copy_keys"};
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        bool hit = true;
        unsigned hits = 0;
        for (unsigned nth = 1; hit && nth < 128; nth++) {
            if (!fb_chunk_copy_fault(e, id, labels[i], nth, &hit)) return false;
            hits += hit;
        }
        if (hit || !hits) return false;
    }
    return true;
}

static bool fb_chunk_typed_refusal(void)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id",
        "0000000000000000000000000000000000000000000000000000000000000000");
    (void)json_push_kv_str(&input, "bytes", "1024junk");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg,
        "fleet.wiki.read", NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[4097];
    enum zcl_command_exit rc;
    (void)zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.wiki.read", "full", 4096, 0, NULL, wire, sizeof(wire), &rc);
    json_free(&input);
    return rc == ZCL_COMMAND_EXIT_INVALID;
}
static bool fb_chunk_wrapper_input_refused(const char *key, int64_t value, size_t budget)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id", "0000000000000000000000000000000000000000000000000000000000000000");
    (void)json_push_kv_int(&input, key, value);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-read", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    enum zcl_command_exit rc;
    char wire[8193];
    (void)zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.steer.wiki-read", "full", budget, 0, NULL, wire, sizeof(wire), &rc);
    json_free(&input);
    if (budget >= 3072) return rc == ZCL_COMMAND_EXIT_INVALID;
    struct json_value envelope;
    json_init(&envelope);
    bool parsed = json_read(&envelope, wire, strlen(wire));
    const char *code = json_get_str(json_get(json_get(&envelope, "error"), "code"));
    bool ok = parsed && rc == ZCL_COMMAND_EXIT_FAILED && code && !strcmp(code, "WIKI_BUDGET");
    json_free(&envelope);
    return ok;
}

static bool fb_chunk_grant_action(const char *action, const char *value, char id[33])
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "action", action);
    (void)json_push_kv_str(&input, !strcmp(action, "mint") ? "scopes" : "id", value);
    if (!strcmp(action, "mint")) (void)json_push_kv_str(&input, "label", "wiki-author");
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_grant.v1");
    zcl_native_handle_fleet_steer_grant(&request, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok && !strcmp(action, "mint")) {
        const char *found = json_get_str(json_get(&reply.data, "id"));
        ok = found && strlen(found) == 32;
        if (ok) (void)snprintf(id, 33, "%s", found);
    }
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static bool fb_chunk_grant_denied(const char *grant, const char *expected)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "id", "0000000000000000000000000000000000000000000000000000000000000000");
    (void)json_push_kv_str(&input, "grant", grant);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_wiki_read.v1");
    zcl_native_handle_fleet_steer_wiki_read(&request, &reply);
    const char *code = reply.error.code;
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED && code && !strcmp(code, expected) &&
        !json_get(&reply.data, "revision");
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static void fb_wiki_write_call(struct fb_rpc_env *e, const char *grant,
    const char *key, const char *parent, const char *slug, const char *text,
    struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    if (grant) (void)json_push_kv_str(&input, "grant", grant);
    (void)json_push_kv_str(&input, "request_key", key);
    (void)json_push_kv_str(&input, "expected", parent);
    (void)json_push_kv_str(&input, "slug", slug);
    (void)json_push_kv_str(&input, "title", "Inline payload");
    (void)json_push_kv_str(&input, "text", text);
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.steer.wiki-write", NULL);
    struct zcl_command_request request = {.input = &input, .spec = spec, .budget_bytes = 4096};
    zcl_command_reply_init(reply, "zcl.fleet_steer_wiki_write.v1");
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    zcl_native_handle_fleet_steer_wiki_write(&request, reply);
    node_rpc_client_set_test_hook(NULL);
    fb_native_test_table = NULL;
    json_free(&input);
}

static bool fb_wiki_write_denied(struct fb_rpc_env *e, const char *grant,
    const char *key, const char *code)
{
    struct fleet_board_status before, after;
    if (!db_fleet_board_status(&e->db, 1, &before)) return false;
    struct zcl_command_reply reply;
    fb_wiki_write_call(e, grant, key, "absent", "write-page", "@literal/path", &reply);
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, code) && !json_get(&reply.data, "revision") &&
        db_fleet_board_status(&e->db, 1, &after) && before.posts == after.posts;
    zcl_command_reply_free(&reply);
    return ok;
}

static bool fb_wiki_write_success(struct fb_rpc_env *e, const char *grant,
    const char *slug, char id[65], char binding[33])
{
    struct zcl_command_reply reply;
    fb_wiki_write_call(e, grant, "same-request", "absent", slug, "@literal/path", &reply);
    const struct json_value *revision = json_get(&reply.data, "revision");
    const char *found = json_get_str(json_get(revision, "id"));
    const char *bound = json_get_str(json_get(&reply.data, "caller_binding"));
    uint8_t decoded[32];
    struct db_fleet_board_post row;
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && found && bound &&
        fleet_board_id_from_hex(found, decoded) && db_fleet_board_post_find(&e->db, decoded, &row) &&
        fleet_board_post_verify(&row.post) == FLEET_BOARD_OK &&
        !strcmp(row.post.text, "@literal/path") && !strcmp(row.post.agent, bound) &&
        json_get_int(json_get(revision, "text_len")) == 13 &&
        json_get_bool(json_get(revision, "partial"));
    if (ok) { (void)snprintf(id, 65, "%s", found); (void)snprintf(binding, 33, "%s", bound); }
    zcl_command_reply_free(&reply);
    return ok;
}

static bool fb_write_grant_mint(const char *scopes, const char *peer, int64_t ttl, char id[33])
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "action", "mint");
    (void)json_push_kv_str(&input, "scopes", scopes);
    (void)json_push_kv_str(&input, "label", "wiki-author");
    (void)json_push_kv_int(&input, "ttl_seconds", ttl);
    if (peer) (void)json_push_kv_str(&input, "peer", peer);
    struct zcl_command_request req = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_steer_grant.v1");
    zcl_native_handle_fleet_steer_grant(&req, &reply);
    const char *found = json_get_str(json_get(&reply.data, "id"));
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && found && strlen(found) == 32;
    if (ok) (void)snprintf(id, 33, "%s", found);
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static int64_t fb_write_wall_ms;
static int64_t fb_write_clock_wall(void *self) { (void)self; return fb_write_wall_ms; }

static bool fb_wiki_write_revise(struct fb_rpc_env *e, const char *grant, const char *id)
{
    struct zcl_command_reply reply;
    fb_write_wall_ms += 1000;
    fb_wiki_write_call(e, grant, "revision-key", id, "write-page", "replacement", &reply);
    const struct json_value *revision = json_get(&reply.data, "revision");
    const char *parent = json_get_str(json_get(revision, "supersedes"));
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && parent && !strcmp(parent, id);
    zcl_command_reply_free(&reply);
    fb_wiki_write_call(e, grant, "same-request", "absent", "write-page", "changed", &reply);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "WIKI_REQUEST_COLLISION");
    zcl_command_reply_free(&reply);
    return ok;
}

static bool fb_wiki_write_receipt_faults(struct fb_rpc_env *e, const char *grant)
{
    static const char *const fields[] = {"body_sha3_256", "agent", "receipt", "supersedes", "slug", "title", "representation",
        "id", "host", "signature", "ref", "signed_scope", "signed_room", "created_at", "ttl", "kind"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct zcl_command_reply reply;
        fb_native_receipt_tamper = fields[i];
        fb_wiki_write_call(e, grant, "same-request", "absent", "write-page", "@literal/path", &reply);
        fb_native_receipt_tamper = NULL;
        ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED &&
            !strcmp(reply.error.code, "WIKI_OUTCOME_UNKNOWN") && !json_get(&reply.data, "revision") &&
            !reply.error.mutated && !reply.error.retryable && !strcmp(reply.error.current_state, "outcome_unknown");
        zcl_command_reply_free(&reply);
    }
    return ok;
}

static bool fb_wiki_write_stored_body(struct fb_rpc_env *e,
    const struct json_value *envelope, const char *text)
{
    const struct json_value *revision = json_get(json_get(envelope, "data"), "revision");
    uint8_t id[32]; struct db_fleet_board_post row;
    return fleet_board_id_from_hex(json_get_str(json_get(revision, "id")), id) &&
        db_fleet_board_post_find(&e->db, id, &row) && row.post.text_len == FLEET_BOARD_WIKI_TEXT_MAX &&
        !memcmp(row.post.text, text, FLEET_BOARD_WIKI_TEXT_MAX + 1) &&
        fleet_board_post_verify(&row.post) == FLEET_BOARD_OK;
}

static bool fb_wiki_write_envelope(struct fb_rpc_env *e, const char *grant, size_t budget)
{
    static char text[FLEET_BOARD_WIKI_TEXT_MAX + 1];
    for (size_t i = 0; i < sizeof(text) - 1; i++) text[i] = i % 2 ? '\\' : '"';
    text[sizeof(text) - 1] = '\0';
    char title[FLEET_BOARD_TITLE_MAX + 1];
    memset(title, '"', sizeof(title) - 1); title[sizeof(title) - 1] = '\0';
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input); json_init(&envelope);
    bool prepared = json_push_kv_str(&input, "grant", grant) &&
        json_push_kv_str(&input, "request_key", "envelope-key") &&
        json_push_kv_str(&input, "expected", "absent") &&
        json_push_kv_str(&input, "slug", "escaped-envelope") &&
        json_push_kv_str(&input, "title", title) && json_push_kv_str(&input, "text", text);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[8193]; enum zcl_command_exit rc = ZCL_COMMAND_EXIT_FAILED;
    fb_native_test_table = &e->table; node_rpc_client_set_test_hook(fb_native_rpc);
    size_t size = prepared ? zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.steer.wiki-write", "full", budget, 0, NULL, wire, sizeof(wire), &rc) : 0;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool ok = rc == ZCL_COMMAND_EXIT_OK && size <= budget &&
        json_read(&envelope, wire, strlen(wire));
    if (!ok) fprintf(stderr, "wiki write envelope rc=%d bytes=%zu budget=%zu wire=%.512s\n",
        (int)rc, size, budget, size ? wire : "<empty>");
    ok = ok && fb_wiki_write_stored_body(e, &envelope, text);
    json_free(&input); json_free(&envelope);
    return ok;
}

static bool fb_wiki_write_overlimit_refused(struct fb_rpc_env *e, const char *grant,
    struct json_value *input, const char *text)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    unsigned calls = fb_native_rpc_calls;
    char wire[8193]; enum zcl_command_exit rc;
    fb_native_test_table = &e->table; node_rpc_client_set_test_hook(fb_native_rpc);
    (void)zcl_command_registry_execute_json(reg, spec, &ctx, input, false,
        "fleet.steer.wiki-write", "full", 4096, 0, NULL, wire, sizeof(wire), &rc);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool ok = rc == ZCL_COMMAND_EXIT_INVALID && fb_native_rpc_calls == calls;
    struct zcl_command_reply reply;
    fb_wiki_write_call(e, grant, "boundary-key", "absent", "boundary-page", text, &reply);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "BAD_INPUT") && fb_native_rpc_calls == calls;
    zcl_command_reply_free(&reply);
    return ok;
}

static bool fb_wiki_write_input_boundaries(struct fb_rpc_env *e, const char *grant)
{
    char text[FLEET_BOARD_WIKI_TEXT_MAX + 2];
    for (size_t i = 0; i < FLEET_BOARD_WIKI_TEXT_MAX; i++) text[i] = i % 2 ? (char)0xa9 : (char)0xc3;
    text[FLEET_BOARD_WIKI_TEXT_MAX] = '\0';
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "grant", grant) &&
        json_push_kv_str(&input, "request_key", "boundary-key") &&
        json_push_kv_str(&input, "expected", "absent") &&
        json_push_kv_str(&input, "slug", "boundary-page") &&
        json_push_kv_str(&input, "title", "Byte boundary") &&
        json_push_kv_str(&input, "text", text);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    char why[256];
    ok = ok && zcl_command_registry_input_validate(spec, &input, why, sizeof(why)) &&
        zcl_command_registry_input_str_max("text") == 4096;
    if (!ok) { json_free(&input); return false; }
    memset(text, 1, FLEET_BOARD_WIKI_TEXT_MAX);
    json_set_str(&input.children[5], text);
    ok = zcl_command_registry_input_validate(spec, &input, why, sizeof(why)) &&
        json_write(&input, NULL, 0) + 32 <= zcl_command_registry_input_budget_bytes(spec);
    for (size_t i = 0; i < FLEET_BOARD_WIKI_TEXT_MAX; i++) text[i] = i % 2 ? (char)0xa9 : (char)0xc3;
    text[FLEET_BOARD_WIKI_TEXT_MAX] = 'x'; text[FLEET_BOARD_WIKI_TEXT_MAX + 1] = '\0';
    json_set_str(&input.children[5], text);
    ok = ok && fb_wiki_write_overlimit_refused(e, grant, &input, text);
    json_free(&input);
    return ok;
}

static bool fb_wiki_write_searchable(struct fb_rpc_env *e, const char *grant)
{
    char text[2048], id[65];
    fb_entry_json(text, sizeof(text), "saved lesson", FB_ONE_LESSON, "\"z23\"");
    struct zcl_command_reply reply;
    fb_wiki_write_call(e, grant, "structured-key", "absent", "structured-page", text, &reply);
    const char *found = json_get_str(json_get(json_get(&reply.data, "revision"), "id"));
    bool saved = reply.status == ZCL_COMMAND_STATUS_PASSED && found && strlen(found) == 64;
    if (saved) (void)snprintf(id, sizeof(id), "%s", found);
    zcl_command_reply_free(&reply);
    if (!saved) return false;
    struct json_value input, result;
    json_init(&input); json_set_object(&input); json_init(&result);
    (void)json_push_kv_str(&input, "op", "wiki_find");
    (void)json_push_kv_str(&input, "q", "saved lesson");
    (void)json_push_kv_str(&input, "topic", "t");
    (void)json_push_kv_str(&input, "applies_to", "z23");
    bool ok = fb_test_rpc(&e->table, &input, &result);
    const struct json_value *entries = json_get(&result, "entries");
    const char *match = json_get_str(json_get(json_at(entries, 0), "id"));
    ok = ok && json_get_int(json_get(&result, "returned")) == 1 && match && !strcmp(match, id);
    json_free(&input); json_free(&result);
    uint8_t decoded[32]; struct db_fleet_board_post row;
    return ok && fleet_board_id_from_hex(id, decoded) && db_fleet_board_post_find(&e->db, decoded, &row) &&
        fb_chunk_reassemble(e, id, &row.post);
}

static bool fb_wiki_write_unknown_recovery(struct fb_rpc_env *e, const char *grant)
{
    struct fleet_board_status before, after;
    if (!db_fleet_board_status(&e->db, 1, &before)) return false;
    struct zcl_command_reply reply;
    fb_native_receipt_copy_fault = true;
    fb_wiki_write_call(e, grant, "unknown-key", "absent", "unknown-page", "stored despite lost receipt", &reply);
    fb_native_receipt_copy_fault = false;
    bool hit = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    bool refused = reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "WIKI_OUTCOME_UNKNOWN") && hit && reply.error.mutated &&
        !strcmp(reply.error.current_state, "committed_receipt_unavailable") && !reply.error.retryable;
    zcl_command_reply_free(&reply);
    fb_wiki_write_call(e, grant, "unknown-key", "absent", "unknown-page", "stored despite lost receipt", &reply);
    bool replay = reply.status == ZCL_COMMAND_STATUS_PASSED &&
        json_get_bool(json_get(json_get(&reply.data, "revision"), "replayed")) &&
        !reply.error.mutated && !strcmp(reply.error.current_state, "retained_replay");
    zcl_command_reply_free(&reply);
    return refused && replay && db_fleet_board_status(&e->db, 1, &after) && after.posts == before.posts + 1;
}

static bool fb_wiki_signed_unknown_wire(struct fb_rpc_env *e, const char *grant)
{
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input); json_init(&envelope);
    bool prepared = json_push_kv_str(&input, "grant", grant) &&
        json_push_kv_str(&input, "request_key", "signed-unknown-key") &&
        json_push_kv_str(&input, "expected", "absent") &&
        json_push_kv_str(&input, "slug", "signed-unknown-page") &&
        json_push_kv_str(&input, "title", "Inline payload") &&
        json_push_kv_str(&input, "text", "retained signed text");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = UINT64_MAX,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[8193]; enum zcl_command_exit rc;
    fb_native_test_table = &e->table; node_rpc_client_set_test_hook(fb_native_rpc);
    fb_native_receipt_tamper = "body_sha3_256";
    size_t size = prepared ? zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, spec->path, "full", 8192, 0, NULL, wire, sizeof(wire), &rc) : 0;
    fb_native_receipt_tamper = NULL;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool ok = size > 0 && rc != ZCL_COMMAND_EXIT_OK && json_read(&envelope, wire, size);
    const struct json_value *error = json_get(&envelope, "error");
    const char *effect = json_get_str(json_get(error, "effect_outcome"));
    const char *action = json_get_str(json_get(error, "next_action"));
    ok = ok && effect && !strcmp(effect, "unknown") && action && strstr(action, "same request_key") &&
        json_get_bool(json_get(error, "mutated")) && !json_get_bool(json_get(error, "retryable"));
    json_free(&input); json_free(&envelope);
    return ok;
}

static bool fb_wiki_signed_unknown_reconcile(struct fb_rpc_env *e, const char *grant)
{
    struct fleet_board_status before, after;
    if (!db_fleet_board_status(&e->db, 1, &before) || !fb_wiki_signed_unknown_wire(e, grant)) return false;
    struct zcl_command_reply replay;
    fb_wiki_write_call(e, grant, "signed-unknown-key", "absent", "signed-unknown-page", "retained signed text", &replay);
    const struct json_value *revision = json_get(&replay.data, "revision");
    uint8_t id[32]; struct db_fleet_board_post stored;
    bool ok = replay.status == ZCL_COMMAND_STATUS_PASSED && !replay.error.mutated &&
        !strcmp(replay.error.current_state, "retained_replay") && json_get_bool(json_get(revision, "replayed")) &&
        fleet_board_id_from_hex(json_get_str(json_get(revision, "id")), id) &&
        db_fleet_board_post_find(&e->db, id, &stored) && fleet_board_post_verify(&stored.post) == FLEET_BOARD_OK &&
        !strcmp(stored.post.text, "retained signed text");
    zcl_command_reply_free(&replay);
    return ok && db_fleet_board_status(&e->db, 1, &after) && after.posts == before.posts + 1;
}

static bool fb_wiki_final_fault_result(const struct json_value *envelope,
    enum zcl_command_exit rc, bool hit, bool *final_hit)
{
    const struct json_value *error = json_get(envelope, "error");
    const char *code = json_get_str(json_get(error, "code"));
    *final_hit = code && !strcmp(code, "RESPONSE_BUDGET_EXCEEDED");
    if (!hit) return rc == ZCL_COMMAND_EXIT_OK;
    const char *effect = json_get_str(json_get(error, "effect_outcome"));
    const char *action = json_get_str(json_get(error, "next_action"));
    return rc != ZCL_COMMAND_EXIT_OK && json_get_bool(json_get(error, "mutated")) &&
        !json_get_bool(json_get(error, "retryable")) && effect &&
        (!strcmp(effect, "committed") || !strcmp(effect, "unknown")) &&
        action && strstr(action, "same request_key");
}

static bool fb_wiki_final_fault_replay(struct fb_rpc_env *e, const char *grant,
    const char *key, unsigned nth, int64_t before_posts, bool ok)
{
    struct fleet_board_status after;
    struct zcl_command_reply replay;
    fb_wiki_write_call(e, grant, key, "absent", key, "committed inline body", &replay);
    ok = ok && replay.status == ZCL_COMMAND_STATUS_PASSED && !replay.error.mutated &&
        json_get_bool(json_get(json_get(&replay.data, "revision"), "replayed")) &&
        !strcmp(replay.error.current_state, "retained_replay");
    if (!ok) fprintf(stderr, "wiki final fault replay nth=%u status=%d code=%s\n",
        nth, (int)replay.status, replay.error.code);
    zcl_command_reply_free(&replay);
    return ok && db_fleet_board_status(&e->db, 1, &after) && after.posts == before_posts + 1;
}

static bool fb_wiki_final_fault_one(struct fb_rpc_env *e, const char *grant,
    unsigned nth, bool *hit, bool *final_hit)
{
    struct fleet_board_status before;
    if (!db_fleet_board_status(&e->db, 1, &before)) return false;
    char key[48], wire[8193];
    (void)snprintf(key, sizeof(key), "final-receipt-%u", nth);
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input); json_init(&envelope);
    bool ready = json_push_kv_str(&input, "grant", grant) &&
        json_push_kv_str(&input, "request_key", key) && json_push_kv_str(&input, "expected", "absent") &&
        json_push_kv_str(&input, "slug", key) && json_push_kv_str(&input, "title", "Inline payload") &&
        json_push_kv_str(&input, "text", "committed inline body");
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    enum zcl_command_exit rc = ZCL_COMMAND_EXIT_FAILED;
    fb_native_test_table = &e->table; node_rpc_client_set_test_hook(fb_native_rpc);
    fb_native_receipt_copy_fault = true; fb_native_receipt_copy_nth = nth;
    size_t size = ready ? zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.steer.wiki-write", "full", 4096, 0, NULL, wire, sizeof(wire), &rc) : 0;
    *hit = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear(); fb_native_receipt_copy_fault = false; fb_native_receipt_copy_nth = 0;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool ok = size && size <= 4096 && json_read(&envelope, wire, strlen(wire));
    ok = ok && fb_wiki_final_fault_result(&envelope, rc, *hit, final_hit);
    if (!ok) fprintf(stderr, "wiki final fault nth=%u hit=%d size=%zu rc=%d wire=%.*s\n",
        nth, *hit, size, (int)rc, (int)size, wire);
    json_free(&input); json_free(&envelope);
    return fb_wiki_final_fault_replay(e, grant, key, nth, before.posts, ok);
}

static bool fb_wiki_final_faults(struct fb_rpc_env *e, const char *grant)
{
    unsigned hits = 0, final_hits = 0;
    for (unsigned nth = 1; nth <= 128; nth++) {
        /* Each case must reach a new committed write, not the independent
         * per-key wiki burst refusal. Advance the fixture clock past the
         * unchanged production quota window; these fixture grants do not expire. */
        fb_write_wall_ms += ((int64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS + 1) * 1000;
        bool hit = false, final_hit = false;
        if (!fb_wiki_final_fault_one(e, grant, nth, &hit, &final_hit)) return false;
        if (!hit) {
            fprintf(stderr, "wiki final fault sweep hits=%u final_hits=%u exhausted_at=%u\n",
                hits, final_hits, nth);
            return hits > 0 && final_hits > 0;
        }
        hits++; final_hits += final_hit;
    }
    return false;
}

static int test_fleet_wiki_write_grants(void)
{
    int failures = 0;
#ifdef _WIN32
    const char *env = "ZCL_STATE_ROOT";
#else
    const char *env = "XDG_STATE_HOME";
#endif
    const char *prior = getenv(env);
    char saved[4096], dir[512], first[33], second[33], narrow[33], peer[33], expiring[33], id[65], other[65], a[33], b[33];
    bool changed = false, opened = false;
    struct fb_rpc_env e;
    if (prior && strlen(prior) >= sizeof(saved)) return 1;
    (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
    static const clock_iface_t clock = {.now_monotonic_ns = fb_room_boundary_mono_ns,
        .now_wall_ms = fb_write_clock_wall};
    const clock_iface_t *saved_clock = clock_default();
    fb_write_wall_ms = INT64_C(1700000000000);
    clock_set_default(&clock);
    TEST("wiki write: explicit scoped grant binds attribution and replay; denied calls never mutate") {
        test_make_tmpdir(dir, sizeof(dir), "fleet_wiki", "write");
        ASSERT(platform_environment_set(env, dir, 1) == 0); changed = true;
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        e.svc.datadir = dir;
        ASSERT(fb_wiki_write_denied(&e, NULL, "missing", "GRANT_REQUIRED"));
        ASSERT(fb_wiki_write_denied(&e, "00000000000000000000000000000000", "forged", "STEER_GRANT_UNKNOWN"));
        ASSERT(fb_chunk_grant_action("mint", "brief,send,evidence", narrow));
        ASSERT(fb_wiki_write_denied(&e, narrow, "narrow", "STEER_GRANT_SCOPE"));
        ASSERT(fb_chunk_grant_action("mint", "wiki-write", first));
        ASSERT(fb_chunk_grant_action("mint", "wiki-write", second));
        ASSERT(fb_write_grant_mint("send,wiki-write", "peer-box", 0, peer));
        ASSERT(fb_wiki_write_denied(&e, peer, "peer-key", "STEER_GRANT_PEER_ONLY"));
        ASSERT(fb_write_grant_mint("wiki-write", NULL, 1, expiring));
        fb_write_wall_ms += 2000;
        ASSERT(fb_wiki_write_denied(&e, expiring, "expired-key", "STEER_GRANT_EXPIRED"));
        ASSERT(fb_wiki_write_success(&e, first, "write-page", id, a));
        ASSERT(fb_wiki_write_success(&e, second, "other-page", other, b));
        ASSERT(strcmp(a, b) != 0);
        ASSERT(fb_wiki_write_input_boundaries(&e, second));
        ASSERT(fb_wiki_write_envelope(&e, second, 3072));
        ASSERT(fb_wiki_write_envelope(&e, second, 4096));
        ASSERT(fb_wiki_write_envelope(&e, second, 8192));
        ASSERT(fb_wiki_write_searchable(&e, second));
        ASSERT(fb_wiki_write_unknown_recovery(&e, second));
        ASSERT(fb_wiki_signed_unknown_reconcile(&e, second));
        ASSERT(fb_wiki_final_faults(&e, second));
        ASSERT(fb_wiki_write_receipt_faults(&e, first));
        struct zcl_command_reply reply;
        fb_wiki_write_call(&e, first, "same-request", "absent", "write-page", "@literal/path", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(json_get(&reply.data, "revision"), "replayed")));
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&reply.data, "revision"), "id")), id);
        zcl_command_reply_free(&reply);
        ASSERT(fb_wiki_write_revise(&e, first, id));
        ASSERT(fb_chunk_grant_action("revoke", first, first));
        ASSERT(fb_wiki_write_denied(&e, first, "same-request", "STEER_GRANT_REVOKED"));
        PASS();
    } _test_next:;
    if (opened) fb_rpc_env_close(&e);
    fb_native_receipt_tamper = NULL;
    fb_native_receipt_copy_fault = false;
    zcl_alloc_fault_clear();
    clock_set_default(saved_clock);
    if (changed) {
#ifdef _WIN32
        if (platform_environment_set(env, saved, 1)) failures++;
#else
        if (prior ? platform_environment_set(env, saved, 1) : unsetenv(env)) failures++;
#endif
    }
    return failures;
}

/* Hermetic lifecycle qualification of the wiki MCP tools' native leaves
 * (fleet.steer.wiki-write / wiki-read / wiki-find) behind the gateway. The
 * gateway test fixture has no working wiki backend (wiki_* only reaches
 * WIKI_UNAVAILABLE there), so these run at the registry + RPC layer. */
static bool fb_lc_write(struct fb_rpc_env *e, const char *grant, const char *key,
    const char *parent, const char *slug, const char *text, char id[65],
    bool *replayed, const char *refusal)
{
    struct fleet_board_status before, after;
    if (!db_fleet_board_status(&e->db, 1, &before)) return false;
    fb_write_wall_ms += ((int64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS + 1) * 1000;
    struct zcl_command_reply reply;
    fb_wiki_write_call(e, grant, key, parent, slug, text, &reply);
    bool ok = db_fleet_board_status(&e->db, 1, &after);
    if (refusal) {
        ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED &&
            !strcmp(reply.error.code, refusal) && !json_get(&reply.data, "revision") &&
            after.posts == before.posts;
    } else {
        const struct json_value *rev = json_get(&reply.data, "revision");
        const char *found = json_get_str(json_get(rev, "id"));
        ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED && found && strlen(found) == 64;
        if (ok) {
            if (id) (void)snprintf(id, 65, "%s", found);
            if (replayed) *replayed = json_get_bool(json_get(rev, "replayed"));
            ok = after.posts == before.posts + (json_get_bool(json_get(rev, "replayed")) ? 0 : 1);
        }
    }
    if (!ok) fprintf(stderr, "wiki lifecycle write key=%s status=%d code=%s\n",
        key, (int)reply.status, reply.error.code);
    zcl_command_reply_free(&reply);
    return ok;
}

static bool fb_lc_mixed_text(char *text, bool over)
{
    /* '"' + '\n' + U+1F600 repeated: 2730 units * 6 bytes + one 4-byte char
     * is exactly the 16384-byte limit; over adds a single byte. */
    size_t n = 0;
    for (int i = 0; i < 2730; i++) {
        text[n++] = '"'; text[n++] = '\n';
        memcpy(text + n, "\xF0\x9F\x98\x80", 4); n += 4;
    }
    memcpy(text + n, "\xF0\x9F\x98\x80", 4); n += 4;
    if (over) text[n++] = 'x';
    text[n] = '\0';
    return n == FLEET_BOARD_WIKI_TEXT_MAX + (over ? 1u : 0u);
}

static bool fb_lc_execute(struct fb_rpc_env *e, const char *grant, const char *key,
    const char *text, char *wire, size_t wire_cap, enum zcl_command_exit *rc, unsigned *calls)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ready = json_push_kv_str(&input, "grant", grant) &&
        json_push_kv_str(&input, "request_key", key) &&
        json_push_kv_str(&input, "expected", "absent") &&
        json_push_kv_str(&input, "slug", key) &&
        json_push_kv_str(&input, "title", "Mixed escapes") &&
        json_push_kv_str(&input, "text", text);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.steer.wiki-write", NULL);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    *rc = ZCL_COMMAND_EXIT_FAILED; *calls = fb_native_rpc_calls;
    fb_native_test_table = &e->table; node_rpc_client_set_test_hook(fb_native_rpc);
    fb_write_wall_ms += ((int64_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS + 1) * 1000;
    wire[0] = '\0';
    if (ready) (void)zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
        "fleet.steer.wiki-write", "full", 8192, 0, NULL, wire, wire_cap, rc);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    json_free(&input);
    *calls = fb_native_rpc_calls - *calls;
    return ready;
}

static bool fb_lc_accepts_limit(struct fb_rpc_env *e, const char *grant)
{
    static char text[FLEET_BOARD_WIKI_TEXT_MAX + 8];
    static char wire[8193];
    enum zcl_command_exit rc;
    unsigned calls;
    if (!fb_lc_mixed_text(text, false)) return false;
    bool ok = fb_lc_execute(e, grant, "mixed-ok", text, wire, sizeof(wire), &rc, &calls) &&
        rc == ZCL_COMMAND_EXIT_OK && calls > 0;
    struct json_value envelope; json_init(&envelope);
    ok = ok && json_read(&envelope, wire, strlen(wire)) && fb_wiki_write_stored_body(e, &envelope, text);
    const char *id = json_get_str(json_get(json_get(json_get(&envelope, "data"), "revision"), "id"));
    uint8_t raw[32]; struct db_fleet_board_post row;
    ok = ok && id && fleet_board_id_from_hex(id, raw) && db_fleet_board_post_find(&e->db, raw, &row) &&
        fb_chunk_reassemble(e, id, &row.post);
    json_free(&envelope);
    return ok;
}

static bool fb_lc_refuses_over(struct fb_rpc_env *e, const char *grant)
{
    static char text[FLEET_BOARD_WIKI_TEXT_MAX + 8];
    static char wire[8193];
    enum zcl_command_exit rc;
    unsigned calls;
    if (!fb_lc_mixed_text(text, true)) return false;
    bool ok = fb_lc_execute(e, grant, "mixed-over", text, wire, sizeof(wire), &rc, &calls) &&
        rc == ZCL_COMMAND_EXIT_INVALID && calls == 0 &&
        strstr(wire, "inline wiki text must be a nonempty UTF-8 string of at most 16384 bytes") &&
        !strstr(wire, "4096");
    if (!ok) fprintf(stderr, "wiki lifecycle over-limit rc=%d calls=%u wire=%.400s\n", (int)rc, calls, wire);
    return ok;
}

static bool fb_lc_admission(struct fb_rpc_env *e, const char *grant)
{
    return fb_lc_accepts_limit(e, grant) && fb_lc_refuses_over(e, grant);
}

static bool fb_lc_conflicts(struct fb_rpc_env *e, const char *grant)
{
    char v1[65], v2[65], again[65];
    bool replayed = false;
    if (!fb_lc_write(e, grant, "lc-k1", "absent", "lc-page", "first body", v1, &replayed, NULL) || replayed)
        return false;
    /* Same key, same payload: the original revision, no new post. */
    if (!fb_lc_write(e, grant, "lc-k1", "absent", "lc-page", "first body", again, &replayed, NULL) ||
        !replayed || strcmp(again, v1)) return false;
    /* Same key, changed payload: collision, nothing written. */
    if (!fb_lc_write(e, grant, "lc-k1", "absent", "lc-page", "other body", NULL, NULL,
                     "WIKI_REQUEST_COLLISION")) return false;
    /* expected=absent on an existing page refuses. */
    if (!fb_lc_write(e, grant, "lc-k2", "absent", "lc-page", "second body", NULL, NULL, "WIKI_CONFLICT"))
        return false;
    if (!fb_lc_write(e, grant, "lc-k3", v1, "lc-page", "second body", v2, &replayed, NULL) || replayed ||
        !strcmp(v1, v2)) return false;
    /* A stale parent refuses once the head moved on. */
    return fb_lc_write(e, grant, "lc-k4", v1, "lc-page", "third body", NULL, NULL, "WIKI_CONFLICT") &&
        fb_lc_write(e, grant, "lc-k5", v2, "lc-page", "third body", NULL, NULL, NULL);
}

enum { FB_LC_PAGES = 19 };

static bool fb_lc_write_pages(struct fb_rpc_env *e, const char *grant)
{
    char text[512], id[65];
    for (int i = 0; i < FB_LC_PAGES; i++) {
        char slug[16], key[16];
        (void)snprintf(slug, sizeof(slug), "pg-%02d", i);
        (void)snprintf(key, sizeof(key), "pgk-%02d", i);
        fb_entry_json(text, sizeof(text), "paginated lifecycle", FB_ONE_LESSON, "\"z23\"");
        if (!fb_lc_write(e, grant, key, "absent", slug, text, id, NULL, NULL)) return false;
    }
    return true;
}

/* Entries must continue the ascending pg-NN run exactly where the previous
 * page stopped: no gap and no duplicate. */
static bool fb_lc_page_entries(const struct json_value *r, int *total)
{
    const struct json_value *entries = json_get(r, "entries");
    int returned = (int)json_get_int(json_get(r, "returned"));
    if (returned < 0 || returned > 8) return false;
    for (int i = 0; i < returned; i++) {
        char want[16];
        const char *slug = json_get_str(json_get(json_at(entries, (size_t)i), "slug"));
        (void)snprintf(want, sizeof(want), "pg-%02d", (*total)++);
        if (!slug || strcmp(slug, want) != 0) return false;
    }
    return returned > 0 || !json_get_bool(json_get(r, "incomplete"));
}

static bool fb_lc_find_pages(struct fb_rpc_env *e, const char *grant)
{
    if (!fb_lc_write_pages(e, grant)) return false;
    int total = 0, pages = 0;
    char after[65] = "";
    for (;;) {
        struct json_value r;
        if (!fb_rpc_op(e, "wiki_find", "q", "paginated", after[0] ? "after_slug" : NULL, after, &r))
            return false;
        bool incomplete = json_get_bool(json_get(&r, "incomplete"));
        const char *next = json_get_str(json_get(&r, "after_slug"));
        bool ok = ++pages <= 8 && fb_lc_page_entries(&r, &total) &&
            (!incomplete || (next && next[0] && strcmp(next, after) != 0));
        if (ok && incomplete) (void)snprintf(after, sizeof(after), "%s", next);
        json_free(&r);
        if (!ok) return false;
        if (!incomplete) break;
    }
    return total == FB_LC_PAGES && pages >= 3;
}

static int test_fleet_wiki_write_lifecycle(void)
{
    int failures = 0;
#ifdef _WIN32
    const char *env = "ZCL_STATE_ROOT";
#else
    const char *env = "XDG_STATE_HOME";
#endif
    const char *prior = getenv(env);
    char saved[4096], dir[512], grant[33];
    bool changed = false, opened = false;
    static struct fb_rpc_env e;
    if (prior && strlen(prior) >= sizeof(saved)) return 1;
    (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
    static const clock_iface_t clock = {.now_monotonic_ns = fb_room_boundary_mono_ns,
        .now_wall_ms = fb_write_clock_wall};
    const clock_iface_t *saved_clock = clock_default();
    fb_write_wall_ms = INT64_C(1700000000000);
    clock_set_default(&clock);
    TEST("wiki lifecycle: retry-safe writes, CAS conflicts, mixed-escape admission at 16384 and paged find") {
        test_make_tmpdir(dir, sizeof(dir), "fleet_wiki", "lifecycle");
        ASSERT(platform_environment_set(env, dir, 1) == 0); changed = true;
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        e.svc.datadir = dir;
        ASSERT(fb_chunk_grant_action("mint", "wiki-write", grant));
        ASSERT(fb_lc_conflicts(&e, grant));
        ASSERT(fb_lc_admission(&e, grant));
        ASSERT(fb_lc_find_pages(&e, grant));
        PASS();
    } _test_next:;
    if (opened) fb_rpc_env_close(&e);
    clock_set_default(saved_clock);
    if (changed) {
#ifdef _WIN32
        if (platform_environment_set(env, saved, 1)) failures++;
#else
        if (prior ? platform_environment_set(env, saved, 1) : unsetenv(env)) failures++;
#endif
    }
    return failures;
}

static int test_fleet_wiki_chunk_grants(void)
{
    int failures = 0;
#ifdef _WIN32
    const char *key = "ZCL_STATE_ROOT";
#else
    const char *key = "XDG_STATE_HOME";
#endif
    const char *prior = getenv(key);
    char saved[4096], dir[512], narrow[33], evidence[33];
    bool changed = false;
    if (prior && strlen(prior) >= sizeof(saved)) return 1;
    (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
    TEST("fleet wiki chunks: scope and revocation deny before revision lookup") {
        test_make_tmpdir(dir, sizeof(dir), "fleet_wiki", "grants");
        ASSERT(platform_private_directory_ensure(dir));
        ASSERT(platform_environment_set(key, dir, 1) == 0); changed = true;
        ASSERT(fb_chunk_grant_action("mint", "brief", narrow));
        ASSERT(fb_chunk_grant_denied(narrow, "STEER_GRANT_SCOPE"));
        ASSERT(fb_chunk_grant_action("mint", "evidence", evidence));
        ASSERT(fb_chunk_grant_action("revoke", evidence, evidence));
        ASSERT(fb_chunk_grant_denied(evidence, "STEER_GRANT_REVOKED"));
        PASS();
    } _test_next:;
    if (changed) {
#ifdef _WIN32
        if (platform_environment_set(key, saved, 1) != 0) failures++;
#else
        if ((prior ? platform_environment_set(key, saved, 1) : unsetenv(key)) != 0) failures++;
#endif
    }
    return failures;
}

static bool fb_chunk_scope_roundtrip(struct fb_rpc_env *e, uint8_t scope,
                                     int64_t now)
{
    uint8_t seed[32], pk[32];
    fb_test_identity((uint8_t)(40 + scope), seed, pk);
    struct fleet_board_post post;
    fb_test_compose(&post, FLEET_BOARD_KIND_WIKI, "scribe", "signed scope bytes",
        (uint64_t)now, 3600);
    (void)snprintf(post.slug, sizeof(post.slug), "scope-%u", scope);
    (void)snprintf(post.title, sizeof(post.title), "scope title");
    if (scope != FLEET_BOARD_SCOPE_LEGACY_PUBLIC)
        fb_test_scope(&post, scope, scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    if (fleet_board_post_sign(&post, seed, pk) != FLEET_BOARD_OK ||
        db_fleet_board_post_ingest(&e->db, &post, now, NULL) != FLEET_BOARD_OK)
        return false;
    char id[65]; fleet_board_id_to_hex(post.id, id);
    if (scope != FLEET_BOARD_SCOPE_FLEET)
        return fb_chunk_reassemble(e, id, &post) &&
            fb_chunk_reassemble_as(e, id, &post, true, 4096);
    /* A fleet revision reads in chunks only with scope=fleet named; an id
     * read with no scope is public and the steer wrapper (no scope option)
     * is refused. */
    struct fleet_board_post publicly = post;
    publicly.scope = FLEET_BOARD_SCOPE_PUBLIC;
    return fb_chunk_reassemble(e, id, &post) &&
        !fb_chunk_reassemble(e, id, &publicly) &&
        !fb_chunk_reassemble_as(e, id, &post, true, 4096);
}

/* Read a page by slug through the registry path the CLI uses. */
static bool fb_slug_envelope_as(struct fb_rpc_env *e, const char *slug,
                             size_t budget, bool expect_ok, struct json_value *envelope)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "slug", slug);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg,
        "fleet.wiki.read", NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    char wire[8193];
    enum zcl_command_exit rc;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.wiki.read", "full", budget, 0, NULL, wire, sizeof(wire), &rc);
    node_rpc_client_set_test_hook(NULL);
    fb_native_test_table = NULL;
    json_free(&input);
    json_init(envelope);
    return (rc == ZCL_COMMAND_EXIT_OK) == expect_ok && n <= budget &&
        json_read(envelope, wire, strlen(wire));
}

static bool fb_slug_envelope(struct fb_rpc_env *e, const char *slug,
                             size_t budget, struct json_value *envelope)
{
    return fb_slug_envelope_as(e, slug, budget, true, envelope);
}

/* Append the hex chunks from `offset` to the end of the body. */
static bool fb_chunks_append(struct fb_rpc_env *e, const char *id,
                             int64_t offset, char *out, size_t cap)
{
    size_t len = (size_t)offset;
    for (;;) {
        struct json_value env;
        if (!fb_chunk_envelope(e, id, (int64_t)len, &env)) {
            json_free(&env);
            return false;
        }
        const struct json_value *d = json_get(&env, "data");
        const char *hex = json_get_str(json_get(d, "data_hex"));
        if (!hex) { json_free(&env); return false; }
        size_t n = strlen(hex) / 2;
        bool done = json_get_bool(json_get(d, "complete"));
        bool ok = len + n < cap && zcl_hex_decode(hex, (uint8_t *)out + len, n);
        json_free(&env);
        if (!ok) return false;
        len += n;
        if (done) break;
        if (!n) return false;
    }
    out[len] = '\0';
    return true;
}

/* A partial slug body resumes exactly on its UTF-8 byte boundary. */
static bool fb_slug_continuation(const struct json_value *d,
                                  const char *text, const char *id)
{
    const char *got = json_get_str(json_get(d, "text"));
    size_t n = strlen(got);
    const struct json_value *hint = json_get(d, "continue");
    const struct json_value *in = json_get(hint, "input");
    const char *command = json_get_str(json_get(hint, "command"));
    const char *hint_id = json_get_str(json_get(in, "id"));
    return command && hint_id && n > 0 && n < strlen(text) && !memcmp(got, text, n) &&
        ((uint8_t)text[n] & 0xC0) != 0x80 &&
        json_get_int(json_get(d, "next_offset")) == (int64_t)n &&
        !strcmp(command, "fleet.wiki.read") && !strcmp(hint_id, id) &&
        json_get_int(json_get(in, "offset")) == (int64_t)n;
}

static bool fb_slug_reconstruct(struct fb_rpc_env *e, const struct json_value *d,
                                 const char *text, const char *id)
{
    if (!fb_slug_continuation(d, text, id))
        return false;
    static char full[FLEET_BOARD_WIKI_TEXT_MAX + 1];
    const char *got = json_get_str(json_get(d, "text"));
    size_t n = strlen(got);
    memcpy(full, got, n);
    return fb_chunks_append(e, id, (int64_t)n, full, sizeof(full)) && !strcmp(full, text);
}

/* ok:true, exact revision identity and complete or reconstructible body. */
static bool fb_slug_read_check(struct fb_rpc_env *e, const char *slug,
                               const char *text, const char *id, size_t budget)
{
    struct json_value env;
    if (!fb_slug_envelope(e, slug, budget, &env)) {
        json_free(&env);
        return false;
    }
    const struct json_value *d = json_get(&env, "data");
    const char *got = json_get_str(json_get(d, "text"));
    const char *got_id = json_get_str(json_get(d, "id"));
    bool ok = got && got_id && json_get_bool(json_get(&env, "ok")) &&
        !strcmp(got_id, id) &&
        json_get_int(json_get(d, "text_len")) == (int64_t)strlen(text);
    if (ok)
        ok = json_get_bool(json_get(d, "truncated"))
            ? fb_slug_reconstruct(e, d, text, id) : !strcmp(got, text);
    json_free(&env);
    return ok;
}

static bool fb_slug_read_sizes(struct fb_rpc_env *e, int64_t now)
{
    static const size_t sizes[] = {6000, 7900};
    static char text[8000];
    for (size_t s = 0; s < 2; s++) {
        char slug[24];
        (void)snprintf(slug, sizeof(slug), "big-page-%zu", sizes[s]);
        for (size_t i = 0; i < sizes[s]; i++)
            text[i] = "\303\251\"\\\n"[i % 5];
        text[sizes[s]] = '\0';
        struct db_fleet_board_post row;
        if (!fb_test_ingest_page(&e->db, slug, text, (int)s, now) ||
            !db_fleet_board_wiki_read(&e->db, slug, &row))
            return false;
        char id[65]; fleet_board_id_to_hex(row.post.id, id);
        if (!fb_slug_read_check(e, slug, text, id, 8192) ||
            !fb_slug_read_check(e, slug, text, id, 4096) ||
            !fb_slug_read_check(e, slug, text, id, 2048))
            return false;
    }
    return true;
}

/* Full structured reads retain both established representations. */
static bool fb_slug_full_fit_text(char *text, size_t cap)
{
    /* The complete structured response fits 8192 bytes, although its RPC
     * body exceeds 8192 - 1536. Preserve both representations at that edge. */
    char rule[201], why[401], evidence[401], lesson[1100], lessons[3400];
    memset(rule, 'r', sizeof(rule) - 1); rule[sizeof(rule) - 1] = '\0';
    memset(why, 'w', sizeof(why) - 1); why[sizeof(why) - 1] = '\0';
    memset(evidence, 'e', sizeof(evidence) - 1);
    evidence[sizeof(evidence) - 1] = '\0';
    int n = snprintf(lesson, sizeof(lesson),
        "{\"rule\":\"%s\",\"why\":\"%s\",\"evidence\":\"%s\"}",
        rule, why, evidence);
    if (n < 0 || (size_t)n >= sizeof(lesson))
        return false;
    n = snprintf(lessons, sizeof(lessons), "%s,%s,%s", lesson, lesson, lesson);
    if (n < 0 || (size_t)n >= sizeof(lessons))
        return false;
    fb_entry_json(text, cap, "budget compatibility", lessons, "\"kernel\"");
    return strlen(text) == 3255;
}

static bool fb_slug_structured_full(struct fb_rpc_env *e, const char *slug,
                                    const char *text)
{
    struct json_value env;
    bool ok = fb_slug_envelope(e, slug, 8192, &env);
    const struct json_value *data = json_get(&env, "data");
    const char *raw = json_get_str(json_get(data, "text"));
    const struct json_value *entry = json_get(data, "entry");
    ok = ok && raw && !strcmp(raw, text) && entry && entry->type == JSON_OBJ &&
        !json_get_bool(json_get(data, "truncated")) && json_write(&env, NULL, 0) <= 8192;
    json_free(&env);
    return ok;
}

/* A structured page whose parsed entry and raw text cannot share one
 * response still reads back whole: a bounded prefix, then exact chunks. */
static bool fb_slug_structured_large(struct fb_rpc_env *e, int64_t now)
{
    char rule[101], why[181], evidence[61], lesson[400], lessons[3600], text[4096];
    memset(rule, 'r', sizeof(rule) - 1); rule[sizeof(rule) - 1] = '\0';
    memset(why, 'w', sizeof(why) - 1); why[sizeof(why) - 1] = '\0';
    memset(evidence, 'e', sizeof(evidence) - 1); evidence[sizeof(evidence) - 1] = '\0';
    int n = snprintf(lesson, sizeof(lesson),
        "{\"rule\":\"%s\",\"why\":\"%s\",\"evidence\":\"%s\"}", rule, why, evidence);
    if (n < 0 || (size_t)n >= sizeof(lesson))
        return false;
    lessons[0] = '\0';
    for (int i = 0; i < 9; i++) {
        size_t used = strlen(lessons);
        (void)snprintf(lessons + used, sizeof(lessons) - used, "%s%s", i ? "," : "", lesson);
    }
    fb_entry_json(text, sizeof(text), "large structured page", lessons, "\"kernel\"");
    if (strlen(text) < 3400 || !fb_test_ingest_page(&e->db, "budget-structured-large", text, 11, now))
        return false;
    struct db_fleet_board_post row;
    if (!db_fleet_board_wiki_read(&e->db, "budget-structured-large", &row))
        return false;
    char id[65]; fleet_board_id_to_hex(row.post.id, id);
    static const size_t budgets[] = {8192, 4096, 2048};
    for (int legacy = 0; legacy < 2; legacy++) {
        fb_native_legacy_slug_reads = legacy;
        for (size_t i = 0; i < 3; i++)
            if (!fb_slug_read_check(e, "budget-structured-large", text, id, budgets[i])) {
                fb_native_legacy_slug_reads = false;
                return false;
            }
    }
    fb_native_legacy_slug_reads = false;
    return true;
}

static bool fb_slug_structured_compat(struct fb_rpc_env *e, int64_t now)
{
    char text[4096];
    fb_entry_json(text, sizeof(text), "budget compatibility", FB_ONE_LESSON,
                   "\"kernel\"");
    if (!fb_test_ingest_page(&e->db, "budget-structured", text, 9, now) ||
        !fb_slug_structured_full(e, "budget-structured", text))
        return false;
    if (!fb_slug_full_fit_text(text, sizeof(text)) ||
        !fb_test_ingest_page(&e->db, "budget-structured-full-fit", text, 10, now))
        return false;
    if (!fb_slug_structured_full(e, "budget-structured-full-fit", text))
        return false;
    return fb_slug_structured_large(e, now);
}

static bool fb_review_envelope(struct fb_rpc_env *e, const char *target,
    size_t budget, bool expect_ok, struct json_value *envelope)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool prepared = json_push_kv_str(&input, "target", target);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg,
        "fleet.wiki.history", NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    char wire[8193];
    enum zcl_command_exit rc = ZCL_COMMAND_EXIT_FAILED;
    size_t n = prepared ? zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, "fleet.wiki.history", "full", budget, 0, NULL,
        wire, sizeof(wire), &rc) : 0;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    json_free(&input); json_init(envelope);
    return prepared && n > 0 && n <= budget &&
        (rc == ZCL_COMMAND_EXIT_OK) == expect_ok &&
        json_read(envelope, wire, strlen(wire));
}

static int test_fleet_wiki_review_budget(void)
{
    int failures = 0;
    struct fb_rpc_env e;
    bool opened = false;
    TEST("fleet wiki reviews: complete registry envelopes honor escaped-body budgets without cursor advancement") {
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        const int64_t now = (int64_t)platform_time_wall_time_t();
        struct fleet_board_post target, review;
        uint8_t seed[32], pk[32]; fb_test_identity(40, seed, pk);
        fb_test_compose(&target, FLEET_BOARD_KIND_WIKI, "author", "budget target", (uint64_t)now, 60);
        target.scope = FLEET_BOARD_SCOPE_PUBLIC;
        (void)snprintf(target.room, sizeof(target.room), "%s", FLEET_BOARD_ROOM_DEFAULT);
        (void)snprintf(target.slug, sizeof(target.slug), "review-budget-target");
        (void)snprintf(target.title, sizeof(target.title), "Budget target");
        ASSERT_EQ(fleet_board_post_sign(&target, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&e.db, &target, now, NULL), FLEET_BOARD_OK);
        char escaped[2001];
        for (size_t i = 0; i < 1000; i++) { escaped[2 * i] = 0x5c; escaped[2 * i + 1] = '"'; }
        escaped[2000] = 0;
        ASSERT(fb_review_compose(&review, 41, target.id, NULL, "approve", escaped, (uint64_t)now));
        ASSERT_EQ(db_fleet_board_post_ingest(&e.db, &review, now, NULL), FLEET_BOARD_OK);
        char id[65]; fleet_board_id_to_hex(target.id, id);
        struct json_value env;
        ASSERT(fb_review_envelope(&e, id, 8192, true, &env));
        ASSERT(json_get_bool(json_get(&env, "ok")));
        ASSERT(json_write(&env, NULL, 0) <= 8192);
        const struct json_value *data = json_get(&env, "data");
        ASSERT_EQ(json_size(json_get(data, "posts")), 1);
        const struct json_value *item = json_at(json_get(data, "posts"), 0);
        ASSERT(strcmp(json_get_str(json_get(item, "text")), review.text) == 0);
        ASSERT(strlen(json_get_str(json_get(json_get(item, "review"), "rationale"))) == 1000);
        json_free(&env);
        ASSERT(fb_review_envelope(&e, id, 4096, false, &env));
        ASSERT(!json_get_bool(json_get(&env, "ok")));
        ASSERT(json_write(&env, NULL, 0) <= 4096);
        ASSERT(strcmp(json_get_str(json_get(json_get(&env, "error"), "code")), "REVIEW_BUDGET") == 0);
        ASSERT(!json_get(json_get(&env, "data"), "posts"));
        ASSERT(!json_get(json_get(&env, "data"), "after_id"));
        json_free(&env);
        /* Exercise the actual registry boundary, including policy/status/schema
         * overhead. One byte below its smallest complete envelope must refuse. */
        size_t low = 4097, high = 8192;
        while (low < high) {
            size_t mid = low + (high - low) / 2;
            /* Probe either outcome, then inspect the returned envelope. */
            bool success = fb_review_envelope(&e, id, mid, true, &env);
            if (!success) {
                json_free(&env);
                ASSERT(fb_review_envelope(&e, id, mid, false, &env));
            }
            bool accepted = json_get_bool(json_get(&env, "ok"));
            json_free(&env);
            if (accepted) high = mid; else low = mid + 1;
        }
        ASSERT(fb_review_envelope(&e, id, low, true, &env)); json_free(&env);
        ASSERT(fb_review_envelope(&e, id, low - 1, false, &env)); json_free(&env);
        PASS();
    } _test_next:;
    if (opened) fb_rpc_env_close(&e);
    return failures;
}


/* Faults are armed at the RPC boundary, after request construction. */
static bool fb_slug_projection_fault(struct fb_rpc_env *e, const char *slug,
    const char *label, unsigned nth)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "slug", slug);
    struct zcl_command_request request = {.input = &input, .budget_bytes = 4096};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_wiki_read.v1");
    size_t before = json_test_live_blocks();
    fb_native_test_table = &e->table;
    fb_native_projection_fault = label; fb_native_projection_nth = nth;
    node_rpc_client_set_test_hook(fb_native_rpc);
    zcl_native_handle_fleet_wiki_read(&request, &reply);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool hit = zcl_alloc_fault_armed_label() == NULL;
    fb_native_projection_fault = NULL;
    zcl_alloc_fault_clear();
    bool ok = hit && reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.code[0];
    zcl_command_reply_free(&reply);
    ok = ok && json_test_live_blocks() == before;
    json_free(&input);
    return ok;
}

static bool fb_slug_prepare_fault(struct fb_rpc_env *e, const char *label,
                                   unsigned nth, bool allowance)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "slug", "big-page-6000");
    struct zcl_command_request request = {.input = &input, .budget_bytes = 4096,
        .success_data_budget_provided = allowance, .success_data_budget = 3000};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_wiki_read.v1");
    size_t before = json_test_live_blocks();
    fb_native_test_table = &e->table; fb_native_rpc_calls = 0;
    node_rpc_client_set_test_hook(fb_native_rpc);
    zcl_alloc_fault_fail_nth(label, nth);
    zcl_native_handle_fleet_wiki_read(&request, &reply);
    bool hit = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    bool ok = hit && fb_native_rpc_calls == 0 &&
        reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "BOARD_PROJECTION_FAILED");
    zcl_command_reply_free(&reply);
    ok = ok && json_test_live_blocks() == before;
    json_free(&input);
    return ok;
}

static bool fb_slug_projection_checks(struct fb_rpc_env *e)
{
    if (!fb_slug_prepare_fault(e, "json_set_str", 2, false) ||
        !fb_slug_prepare_fault(e, "json_push_kv_key", 3, false) ||
        !fb_slug_prepare_fault(e, "json_copy_children", 1, true) ||
        !fb_slug_projection_fault(e, "budget-structured", "json_string", 1)) return false;
    const char *labels[] = {"fleet_board.rpc.wiki_prefix", "json_copy_children",
        "json_copy_keys", "json_copy_key", "json_copy_str", "json_set_str"};
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
        if (!fb_slug_projection_fault(e, "big-page-6000", labels[i], 1)) return false;
    size_t before = json_test_live_blocks();
    for (unsigned i = 0; i < 8; i++) {
        struct json_value env;
        bool ok = fb_slug_envelope(e, i % 2 ? "budget-structured" : "big-page-6000",
            4096, &env);
        json_free(&env);
        if (!ok || json_test_live_blocks() != before) return false;
    }
    return true;
}

/* Older/direct callers have no measured registry envelope allowance. */
static bool fb_slug_direct_fallback(struct fb_rpc_env *e, const char *slug,
                                     bool partial)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "slug", slug);
    struct zcl_command_request request = {.input = &input, .budget_bytes = 4096};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_wiki_read.v1");
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    if (ok) zcl_native_handle_fleet_wiki_read(&request, &reply);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    const char *text = json_get_str(json_get(&reply.data, "text"));
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED && text && text[0] &&
        json_get_bool(json_get(&reply.data, "truncated")) == partial &&
        json_write(&reply.data, NULL, 0) <= 4096;
    if (ok && !partial) {
        const struct json_value *entry = json_get(&reply.data, "entry");
        ok = entry && entry->type == JSON_OBJ;
    }
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static bool fb_slug_rpc_limits(struct fb_rpc_env *e)
{
    static const char *const cases[] = {
        "\"data_budget\":\"bad\",\"continuation_bytes\":0",
        "\"data_budget\":1000,\"continuation_bytes\":\"bad\"",
        "\"data_budget\":-1,\"continuation_bytes\":0",
        "\"data_budget\":8193,\"continuation_bytes\":0",
        "\"data_budget\":1000,\"continuation_bytes\":-1",
        "\"data_budget\":1000,\"continuation_bytes\":1001",
        "\"data_budget\":1000",
        "\"data_budget\":0,\"continuation_bytes\":0"
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char text[256];
        (void)snprintf(text, sizeof(text),
            "{\"op\":\"wiki_read\",\"slug\":\"budget-structured\",\"response_budget\":8192,%s}", cases[i]);
        struct json_value input, result;
        json_init(&input); json_init(&result);
        bool ok = json_read(&input, text, strlen(text)) && fb_test_rpc(&e->table, &input, &result);
        const char *code = json_get_str(json_get(&result, "code"));
        ok = ok && !json_get_bool(json_get(&result, "ok")) && code &&
            !strcmp(code, "READ_BUDGET");
        json_free(&input); json_free(&result);
        if (!ok) return false;
    }
    return true;
}

static int test_fleet_wiki_slug_budget(void)
{
    int failures = 0;
    static struct fb_rpc_env e;
    bool opened = false;
    TEST("fleet wiki: bounded slug reads preserve compatible full bodies or "
        "resume a nonempty shorter prefix; insufficient budgets refuse") {
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        ASSERT(fb_slug_read_sizes(&e, (int64_t)platform_time_wall_time_t()));
        ASSERT(fb_slug_structured_compat(&e, (int64_t)platform_time_wall_time_t()));
        ASSERT(fb_slug_projection_checks(&e));
        ASSERT(fb_slug_rpc_limits(&e));
        ASSERT(fb_slug_direct_fallback(&e, "budget-structured", false));
        ASSERT(fb_slug_direct_fallback(&e, "big-page-6000", true));
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    if (opened) fb_rpc_env_close(&e);
    return failures;
}

static int test_fleet_wiki_chunks(void)
{
    int failures = 0;
    struct fb_rpc_env e;
    bool opened = false;
    TEST("fleet wiki: exact chunks reconstruct maximum escaped body within command envelope") {
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        ASSERT(fb_chunk_typed_refusal());
        ASSERT(fb_chunk_wrapper_input_refused("offset", -1, 4096));
        ASSERT(fb_chunk_wrapper_input_refused("bytes", 1025, 4096));
        ASSERT(fb_chunk_wrapper_input_refused("bytes", 1024, 2048));
        char text[FLEET_BOARD_WIKI_TEXT_MAX + 1];
        for (size_t i = 0; i < sizeof(text) - 1; i++)
            text[i] = i % 2 ? '\\' : '"';
        text[sizeof(text) - 1] = '\0';
        int64_t now = (int64_t)platform_time_wall_time_t();
        ASSERT(fb_chunk_scope_roundtrip(&e, FLEET_BOARD_SCOPE_LEGACY_PUBLIC, now));
        ASSERT(fb_chunk_scope_roundtrip(&e, FLEET_BOARD_SCOPE_PUBLIC, now));
        ASSERT(fb_chunk_scope_roundtrip(&e, FLEET_BOARD_SCOPE_FLEET, now));
        ASSERT(fb_test_ingest_page(&e.db, "chunk-page", text, 1, now));
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_wiki_read(&e.db, "chunk-page", &row));
        char id[65]; fleet_board_id_to_hex(row.post.id, id);
        ASSERT(fb_test_ingest_page(&e.db, "chunk-page", "replacement", 2, now + 1));
        ASSERT(fb_chunk_reassemble(&e, id, &row.post));
        ASSERT(fb_chunk_reassemble_as(&e, id, &row.post, true, 3072));
        ASSERT(fb_chunk_reassemble_as(&e, id, &row.post, true, 4096));
        ASSERT(fb_chunk_reassemble_as(&e, id, &row.post, true, 8192));
        ASSERT(fb_chunk_copy_faults(&e, id));
        ASSERT(fb_chunk_refused(&e, id, -1, 1024, "BAD_CHUNK"));
        ASSERT(fb_chunk_refused(&e, id, 0, 1025, "BAD_CHUNK"));
        ASSERT(fb_chunk_refused(&e, id, 16385, 1024, "BAD_OFFSET"));
        ASSERT(fb_chunk_refused(&e,
            "0000000000000000000000000000000000000000000000000000000000000000",
            0, 1024, "NOT_FOUND"));
        ASSERT(fb_chunk_wrapper_refused(&e,
            "0000000000000000000000000000000000000000000000000000000000000000"));
        struct json_value end;
        ASSERT(fb_chunk_envelope(&e, id, row.post.text_len, &end));
        ASSERT(json_get_bool(json_get(json_get(&end, "data"), "complete")));
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&end, "data"), "data_hex")), "");
        json_free(&end);
        ASSERT(node_db_exec(&e.db, "UPDATE fleet_board_posts SET text='corrupted' WHERE slug='chunk-page'"));
        ASSERT(fb_chunk_refused(&e, id, 0, 1024, "NOT_FOUND"));
        ASSERT(fb_chunk_wrapper_refused(&e, id));
        uint8_t seed[32], pk[32];
        fb_test_identity(32, seed, pk);
        struct fleet_board_post note;
        fb_test_compose(&note, FLEET_BOARD_KIND_NOTE, "tester", "a note",
            (uint64_t)now, 3600);
        fb_test_scope(&note, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT(fleet_board_post_sign(&note, seed, pk) == FLEET_BOARD_OK);
        ASSERT(db_fleet_board_post_ingest(&e.db, &note, now, NULL) == FLEET_BOARD_OK);
        fleet_board_id_to_hex(note.id, id);
        ASSERT(fb_chunk_refused(&e, id, 0, 1024, "NOT_WIKI"));
        ASSERT(fb_chunk_wrapper_refused(&e, id));
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    if (opened) fb_rpc_env_close(&e);
    return failures;
}

static int test_fleet_wiki_find_edges(void)
{
    int failures = 0;
    TEST("fleet wiki: find skips malformed and superseded revisions, folds "
        "ASCII case only, refuses a long q, honours its byte budget, and "
        "format is refused on other kinds") {
        static struct fb_rpc_env e;
        static char big[FLEET_BOARD_WIKI_TEXT_MAX + 1];
        struct json_value r;
        ASSERT(fb_rpc_env_open(&e));
        db_fleet_board_test_set_wiki_limits(1000, 0);
        const int64_t now = INT64_C(5000000);

        ASSERT(fb_test_ingest_page(&e.db, "broken", "{\"schema\":", 0, now));
        ASSERT(fb_rpc_op(&e, "wiki_read", "slug", "broken", NULL, NULL, &r));
        ASSERT(json_get(&r, "entry") == NULL);
        json_free(&r);

        fb_entry_json(big, sizeof(big), "hidden entry", FB_ONE_LESSON,
                      "\"older\"");
        ASSERT(fb_test_ingest_page(&e.db, "hidden", big, 1, now - 100));
        ASSERT(fb_test_ingest_page(&e.db, "hidden", "plain prose now", 2, now));
        ASSERT(fb_rpc_op(&e, "wiki_read", "slug", "hidden", NULL, NULL, &r));
        ASSERT(json_get(&r, "entry") == NULL);
        json_free(&r);
        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "older", NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 0);
        json_free(&r);

        fb_entry_json(big, sizeof(big), "accent entry", FB_ONE_LESSON,
                      "\"caf" "\xC3" "\xA9" "\"");
        ASSERT(fb_test_ingest_page(&e.db, "accent", big, 3, now));
        fb_entry_json(big, sizeof(big), "plain entry", FB_ONE_LESSON,
                      "\"cafe\"");
        ASSERT(fb_test_ingest_page(&e.db, "unaccented", big, 4, now));
        const char *qs[] = { "caf" "\xC3" "\xA9", "CAF" "\xC3" "\x89", "CAF" };
        const int expect[] = { 1, 0, 2 };
        for (int i = 0; i < 3; i++) {
            ASSERT(fb_rpc_op(&e, "wiki_find", "q", qs[i], NULL, NULL, &r));
            ASSERT_EQ(json_get_int(json_get(&r, "returned")), expect[i]);
            json_free(&r);
        }

        char longq[130];
        memset(longq, 'a', 129);
        longq[129] = '\0';
        ASSERT(fb_rpc_op(&e, "wiki_find", "q", longq, NULL, NULL, &r));
        ASSERT(strcmp(json_get_str(json_get(&r, "code")), "Q_TOO_LONG") == 0);
        json_free(&r);

        ASSERT(fb_rpc_op(&e, "post", "text", "hello", "format", "entry", &r));
        ASSERT(strcmp(json_get_str(json_get(&r, "code")),
                      "FORMAT_NOT_WIKI") == 0);
        json_free(&r);

        for (int i = 0; i < 8; i++) {
            char topic[16];
            (void)snprintf(topic, sizeof(topic), "budget-%d", i);
            fb_max_entry(big, sizeof(big), topic);
            ASSERT(fb_test_ingest_page(&e.db, topic, big, 10 + i, now));
        }
        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "budget", NULL, NULL, &r));
        int64_t returned = json_get_int(json_get(&r, "returned"));
        ASSERT(returned >= 1 && returned < 8);
        ASSERT(json_get_bool(json_get(&r, "truncated")));
        ASSERT(json_write(&r, NULL, 0) <= 4096 - 768);
        json_free(&r);

        db_fleet_board_test_set_wiki_limits(0, 0);
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static int test_fleet_wiki_find_page_cap(void)
{
    int failures = 0;
    TEST("fleet wiki: bounded pages reach late-alphabet matches with unchanged filters") {
        static struct fb_rpc_env e;
        struct json_value r;
        ASSERT(fb_rpc_env_open(&e));
        db_fleet_board_test_set_wiki_limits(1000, 1000);
        const int64_t now = INT64_C(5000000);
        for (int i = 0; i < FLEET_BOARD_LIST_MAX + 1; i++) {
            char slug[16], text[256];
            (void)snprintf(slug, sizeof(slug), "page-%03d", i);
            fb_entry_json(text, sizeof(text), i == FLEET_BOARD_LIST_MAX
                ? "last-match" : "earlier entry", FB_ONE_LESSON, "");
            ASSERT(fb_test_ingest_page(&e.db, slug, text, i, now));
        }
        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "last-match", NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "scanned")), FLEET_BOARD_LIST_MAX);
        ASSERT(json_get_bool(json_get(&r, "incomplete")));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 0);
        char after[65];
        (void)snprintf(after, sizeof(after), "%s", json_get_str(json_get(&r, "after_slug")));
        ASSERT_STR_EQ(after, "page-255");
        json_free(&r);
        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "last-match", "after_slug", after, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&r, "entries"), 0), "slug")), "page-256");
        ASSERT(!json_get_bool(json_get(&r, "incomplete")));
        json_free(&r);
        db_fleet_board_test_set_wiki_limits(0, 0);
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

static void fb_matched_join(const struct json_value *r, char *out, size_t cap)
{
    const struct json_value *m = json_get(json_at(json_get(r, "entries"), 0), "matched");
    out[0] = 0;
    for (size_t i = 0; m && i < json_size(m); i++)
        (void)snprintf(out + strlen(out), cap - strlen(out), "%s%s",
                       i ? "," : "", json_get_str(json_at(m, i)));
}

static bool fb_find_matched(struct fb_rpc_env *e, const char *q, size_t *returned,
                            char *joined, size_t cap)
{
    struct json_value r;
    if (!fb_rpc_op(e, "wiki_find", "q", q, NULL, NULL, &r)) return false;
    *returned = (size_t)json_get_int(json_get(&r, "returned"));
    fb_matched_join(&r, joined, cap);
    json_free(&r);
    return true;
}

static int test_fleet_wiki_find_matched_fields(void)
{
    int failures = 0;
    TEST("fleet wiki: find searches lesson rule and why, not evidence, and "
         "names matched fields in fixed order") {
        static struct fb_rpc_env e;
        char joined[96];
        size_t returned = 99;
        ASSERT(fb_rpc_env_open(&e));
        const int64_t now = INT64_C(5000000);
        char text[512];
        fb_entry_json(text, sizeof(text), "s", "{\"rule\":\"Quokka first.\","
            "\"why\":\"w\",\"evidence\":\"e\"}", "");
        ASSERT(fb_test_ingest_page(&e.db, "p-rule", text, 0, now));
        fb_entry_json(text, sizeof(text), "s", "{\"rule\":\"r\","
            "\"why\":\"Because wombat.\",\"evidence\":\"e\"}", "");
        ASSERT(fb_test_ingest_page(&e.db, "p-why", text, 1, now));
        fb_entry_json(text, sizeof(text), "s", "{\"rule\":\"r\",\"why\":\"w\","
            "\"evidence\":\"see numbat.md\"}", "");
        ASSERT(fb_test_ingest_page(&e.db, "p-evidence", text, 2, now));
        fb_entry_json(text, sizeof(text), "emu summary", "{\"rule\":\"emu rule\","
            "\"why\":\"emu why\",\"evidence\":\"e\"}", "\"emu\"");
        ASSERT(fb_test_ingest_page(&e.db, "emu-page", text, 3, now));

        ASSERT(fb_find_matched(&e, "QUOKKA", &returned, joined, sizeof(joined)));
        ASSERT_EQ((int64_t)returned, 1);
        ASSERT_STR_EQ(joined, "rule");
        ASSERT(fb_find_matched(&e, "wombat", &returned, joined, sizeof(joined)));
        ASSERT_EQ((int64_t)returned, 1);
        ASSERT_STR_EQ(joined, "why");
        ASSERT(fb_find_matched(&e, "numbat", &returned, joined, sizeof(joined)));
        ASSERT_EQ((int64_t)returned, 0);
        ASSERT(fb_find_matched(&e, "emu", &returned, joined, sizeof(joined)));
        ASSERT_EQ((int64_t)returned, 1);
        ASSERT_STR_EQ(joined, "slug,summary,applies_to,rule,why");
        ASSERT(fb_find_matched(&e, "", &returned, joined, sizeof(joined)));
        ASSERT_EQ((int64_t)returned, 4);
        ASSERT_STR_EQ(joined, "");
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    return failures;
}

static const struct json_value *fb_index_row(const struct json_value *r, const char *slug)
{
    const struct json_value *posts = json_get(r, "posts");
    for (size_t i = 0; posts && i < json_size(posts); i++)
        if (!strcmp(json_get_str(json_get(json_at(posts, i), "slug")), slug))
            return json_at(posts, i);
    return NULL;
}

static int test_fleet_wiki_list_is_an_index(void)
{
    int failures = 0;
    TEST("fleet wiki: list is an index of slug, title, topic and summary without page text") {
        static struct fb_rpc_env e;
        struct json_value r;
        ASSERT(fb_rpc_env_open(&e));
        const int64_t now = INT64_C(5000000);
        char text[512], plain[400] = "a";
        fb_entry_json(text, sizeof(text), "entry summary", FB_ONE_LESSON, "");
        ASSERT(fb_test_ingest_page(&e.db, "entry-page", text, 0, now));
        for (int i = 0; i < 60; i++) strcat(plain, "\xC3\xA9");
        strcat(plain, "\nsecond line");
        ASSERT(fb_test_ingest_page(&e.db, "plain-page", plain, 1, now));
        char longline[161];
        memset(longline, 'x', 160);
        longline[160] = 0;
        ASSERT(fb_test_ingest_page(&e.db, "plain-long", longline, 2, now));
        ASSERT(fb_rpc_op(&e, "wiki_list", NULL, NULL, NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 3);
        const struct json_value *entry = fb_index_row(&r, "entry-page");
        const struct json_value *flat = fb_index_row(&r, "plain-page");
        ASSERT(entry != NULL && flat != NULL);
        ASSERT(json_get(entry, "text") == NULL && json_get(flat, "text") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(entry, "topic")), "t");
        ASSERT_STR_EQ(json_get_str(json_get(entry, "summary")), "entry summary");
        ASSERT(json_get(flat, "topic") == NULL);
        ASSERT_EQ((int64_t)strlen(json_get_str(json_get(flat, "summary"))), 119);
        const struct json_value *lng = fb_index_row(&r, "plain-long");
        ASSERT(lng != NULL);
        ASSERT_EQ((int64_t)strlen(json_get_str(json_get(lng, "summary"))), 120);
        ASSERT(json_get(entry, "id") && json_get(entry, "host") && json_get(entry, "agent") &&
               json_get(entry, "created_at") && json_get(entry, "title"));
        json_free(&r);
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_wiki_find_plain_pages(void)
{
    int failures = 0;
    TEST("fleet wiki: find returns plain pages by slug, title or first line, never under a topic filter") {
        static struct fb_rpc_env e;
        struct json_value r;
        ASSERT(fb_rpc_env_open(&e));
        const int64_t now = INT64_C(5000000);
        char text[512];
        fb_entry_json(text, sizeof(text), "alpha summary", FB_ONE_LESSON, "");
        ASSERT(fb_test_ingest_page(&e.db, "aaa-entry", text, 1, now));
        ASSERT(fb_test_ingest_page(&e.db, "bbb-plain", "Some prose\nsecond line", 7, now));
        ASSERT(fb_test_ingest_page(&e.db, "ccc-plain", "Alpha prose", 8, now));

        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "PAGE 7", NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 1);
        const struct json_value *hit = json_at(json_get(&r, "entries"), 0);
        ASSERT_STR_EQ(json_get_str(json_get(hit, "kind")), "page");
        ASSERT_STR_EQ(json_get_str(json_get(hit, "slug")), "bbb-plain");
        ASSERT_STR_EQ(json_get_str(json_get(hit, "title")), "Page 7");
        ASSERT_STR_EQ(json_get_str(json_get(hit, "summary")), "Some prose");
        ASSERT_EQ((int64_t)json_size(json_get(hit, "matched")), 1);
        ASSERT_STR_EQ(json_get_str(json_at(json_get(hit, "matched"), 0)), "title");
        json_free(&r);

        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "page 7", "topic", "t", &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 0);
        json_free(&r);

        ASSERT(fb_rpc_op(&e, "wiki_find", "q", "alpha", NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 2);
        const struct json_value *items = json_get(&r, "entries");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 0), "slug")), "aaa-entry");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 0), "kind")), "entry");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 1), "slug")), "ccc-plain");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(items, 1), "kind")), "page");
        ASSERT_STR_EQ(json_get_str(json_at(json_get(json_at(items, 1), "matched"), 0)), "summary");
        json_free(&r);
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    return failures;
}

struct fb_query_vm { uint64_t steps, statements; };
static int fb_query_vm_trace(unsigned type, void *context, void *statement, void *unused)
{
    (void)unused;
    if (type == SQLITE_TRACE_PROFILE) {
        struct fb_query_vm *vm = context;
        vm->steps += (uint64_t)sqlite3_stmt_status(statement, SQLITE_STMTSTATUS_VM_STEP, 0);
        vm->statements++;
    }
    return 0;
}
static enum fleet_wiki_visit_result fb_query_count(void *context,
    const struct db_fleet_board_post *row)
{
    (void)row;
    unsigned *count = context;
    (*count)++;
    return FLEET_WIKI_VISIT_CONTINUE;
}
struct fb_query_compare_rows {
    const struct db_fleet_board_post *rows;
    unsigned count;
};
static enum fleet_wiki_visit_result fb_query_compare(void *context,
    const struct db_fleet_board_post *row)
{
    struct fb_query_compare_rows *expected = context;
    if (expected->count >= 3 ||
        memcmp(expected->rows[expected->count].post.id, row->post.id, 32))
        return FLEET_WIKI_VISIT_FAILED;
    expected->count++;
    return FLEET_WIKI_VISIT_CONTINUE;
}

static enum fleet_wiki_visit_result fb_query_fail(void *context,
    const struct db_fleet_board_post *row)
{
    (void)context; (void)row;
    return FLEET_WIKI_VISIT_FAILED;
}
static int fb_query_abort_step(void *context)
{
    (void)context;
    return 1;
}
static bool fb_query_index_plan(struct node_db *db)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "EXPLAIN QUERY PLAN SELECT slug FROM fleet_board_posts "
        "WHERE kind=?1 AND slug>?2 ORDER BY slug LIMIT 1";
    if (sqlite3_prepare_v2(db->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int(s, 1, FLEET_BOARD_KIND_WIKI) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, "a", -1, SQLITE_STATIC) == SQLITE_OK;
    bool index = false;
    while (ok && sqlite3_step(s) == SQLITE_ROW) {
        const char *detail = (const char *)sqlite3_column_text(s, 3);
        if (detail && strstr(detail, "idx_fleet_board_wiki_latest")) index = true;
        if (detail && strstr(detail, "TEMP B-TREE")) ok = false;
    }
    sqlite3_finalize(s);
    return ok && index;
}

static bool fb_query_execute(struct fb_rpc_env *e, bool wrapper,
    const struct json_value *input, size_t budget, struct json_value *envelope,
    enum zcl_command_exit *exit_code)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const char *path = wrapper ? "fleet.steer.wiki-find" : "fleet.wiki.find";
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, path, NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    fb_native_test_table = &e->table;
    node_rpc_client_set_test_hook(fb_native_rpc);
    char wire[8193];
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input,
        false, path, "full", budget, 0, NULL, wire, sizeof(wire), exit_code);
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    json_init(envelope);
    return n > 0 && n <= budget && json_read(envelope, wire, strlen(wire));
}

static bool fb_query_filtered_envelope(struct fb_rpc_env *e, bool wrapper, size_t budget)
{
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "q", "indexed") &&
        json_push_kv_str(&input, "topic", "t") &&
        json_push_kv_str(&input, "applies_to", "kernel") &&
        json_push_kv_str(&input, "after_slug", "a-before");
    enum zcl_command_exit rc;
    if (ok) ok = fb_query_execute(e, wrapper, &input, budget, &envelope, &rc);
    else json_init(&envelope);
    if (ok) ok = rc == ZCL_COMMAND_EXIT_OK;
    const struct json_value *data = json_get(&envelope, "data");
    if (wrapper) data = json_get(data, "discovery");
    if (ok) ok = json_get_int(json_get(data, "returned")) == 1 &&
        !strcmp(json_get_str(json_get(json_at(json_get(data, "entries"), 0), "slug")), "b-match");
    json_free(&input); json_free(&envelope);
    return ok;
}

static bool fb_query_escaped_fields(struct json_value *entry,
    const struct json_value *lessons, const struct json_value *applies, const char *rule)
{
    return json_push_kv_str(entry, "schema", FLEET_WIKI_ENTRY_SCHEMA) &&
        json_push_kv_str(entry, "topic", "large") &&
        json_push_kv_str(entry, "summary", rule) &&
        json_push_kv(entry, "lessons", lessons) &&
        json_push_kv(entry, "applies_to", applies) &&
        json_push_kv_str(entry, "updated", "2026-10-12T09:00:00Z");
}

static bool fb_query_escaped_body(char *text, size_t capacity)
{
    char rule[201], detail[257];
    for (size_t i = 0; i < sizeof(rule) - 1; i++) rule[i] = i % 2 ? '\\' : '"';
    rule[200] = '\0';
    memset(detail, 'x', 256); detail[256] = '\0';
    struct json_value entry, lessons, lesson, applies;
    json_init(&entry); json_set_object(&entry);
    json_init(&lessons); json_set_array(&lessons);
    json_init(&lesson); json_set_object(&lesson);
    json_init(&applies); json_set_array(&applies);
    bool ok = json_push_kv_str(&lesson, "rule", rule) &&
        json_push_kv_str(&lesson, "why", detail) && json_push_kv_str(&lesson, "evidence", detail);
    for (size_t i = 0; ok && i < 16; i++) ok = json_push_back(&lessons, &lesson);
    if (ok) ok = fb_query_escaped_fields(&entry, &lessons, &applies, rule);
    if (ok) ok = json_write(&entry, text, capacity) < capacity;
    json_free(&entry); json_free(&lessons); json_free(&lesson); json_free(&applies);
    return ok;
}
static bool fb_query_large_envelope(struct fb_rpc_env *e, size_t budget)
{
    struct json_value input, envelope;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "q", "large");
    enum zcl_command_exit rc;
    if (ok) ok = fb_query_execute(e, false, &input, budget, &envelope, &rc);
    else json_init(&envelope);
    if (ok) ok = rc == ZCL_COMMAND_EXIT_OK;
    const struct json_value *data = json_get(&envelope, "data");
    const struct json_value *hit = json_at(json_get(data, "entries"), 0);
    if (ok) ok = json_get_int(json_get(data, "returned")) == 1 &&
        json_get_bool(json_get(hit, "rules_omitted")) &&
        !strcmp(json_get_str(json_get(data, "after_slug")), "z-large");
    json_free(&input); json_free(&envelope);
    return ok;
}

static int test_fleet_wiki_query_envelopes(void)
{
    int failures = 0;
    static struct fb_rpc_env e;
    bool opened = false;
    TEST("fleet wiki: AND filters and cursor survive native and evidence wrapper budgets") {
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        const int64_t now = INT64_C(5000000);
        char text[512];
        fb_entry_json(text, sizeof(text), "indexed knowledge", FB_ONE_LESSON, "\"kernel\"");
        ASSERT(fb_test_ingest_page(&e.db, "a-before", text, 1, now));
        ASSERT(fb_test_ingest_page(&e.db, "b-match", text, 2, now));
        fb_entry_json(text, sizeof(text), "indexed knowledge", FB_ONE_LESSON, "\"other\"");
        ASSERT(fb_test_ingest_page(&e.db, "c-wrong-applies", text, 3, now));
        ASSERT(fb_test_ingest_page(&e.db, "d-plaintext", "indexed kernel", 4, now));
        (void)snprintf(text, sizeof(text),
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"u\","
            "\"summary\":\"indexed knowledge\",\"lessons\":[" FB_ONE_LESSON
            "],\"applies_to\":[\"kernel\"],\"updated\":\"2026-10-12T09:00:00Z\"}");
        ASSERT(fb_test_ingest_page(&e.db, "e-wrong-topic", text, 5, now));
        ASSERT(fb_query_filtered_envelope(&e, false, 2048));
        ASSERT(fb_query_filtered_envelope(&e, false, 4096));
        ASSERT(fb_query_filtered_envelope(&e, false, 8192));
        ASSERT(fb_query_filtered_envelope(&e, true, 4096));
        ASSERT(fb_query_filtered_envelope(&e, true, 8192));
        static char escaped[FLEET_BOARD_WIKI_TEXT_MAX + 1];
        ASSERT(fb_query_escaped_body(escaped, sizeof(escaped)));
        ASSERT(fb_test_ingest_page(&e.db, "z-large", escaped, 6, now));
        ASSERT(fb_query_large_envelope(&e, 2048));
        ASSERT(fb_query_large_envelope(&e, 4096));
        ASSERT(fb_query_large_envelope(&e, 8192));

        struct json_value input, envelope;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "q", "indexed"));
        enum zcl_command_exit rc;
        ASSERT(fb_query_execute(&e, true, &input, 2048, &envelope, &rc));
        ASSERT(rc != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&envelope, "error"), "code")), "QUERY_BUDGET");
        json_free(&envelope); json_free(&input);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
    if (opened) fb_rpc_env_close(&e);
    return failures;
}

/* The scan the indexed seeks replaced: every revision row in slug order is
 * stepped until max distinct slugs are seen, then each slug is resolved. */
static int fb_query_naive_list(struct node_db *db, struct db_fleet_board_post *out,
                               size_t max)
{
    char slugs[8][FLEET_BOARD_SLUG_MAX + 1], sql[128];
    size_t n = 0;
    sqlite3_stmt *s = NULL;
    (void)snprintf(sql, sizeof(sql), "SELECT slug FROM fleet_board_posts "
        "WHERE kind=%d ORDER BY slug", (int)FLEET_BOARD_KIND_WIKI);
    if (max > 8 || sqlite3_prepare_v2(db->db, sql, -1, &s, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(s) == SQLITE_ROW && n < max) {
        const char *slug = (const char *)sqlite3_column_text(s, 0);
        if (n && !strcmp(slugs[n - 1], slug)) continue;
        (void)snprintf(slugs[n++], sizeof(slugs[0]), "%s", slug);
    }
    sqlite3_finalize(s);
    int written = 0;
    for (size_t i = 0; i < n; i++)
        if (db_fleet_board_wiki_read(db, slugs[i], &out[written])) written++;
    return written;
}

static int test_fleet_wiki_query_cost(void)
{
    int failures = 0;
    static struct fb_rpc_env e;
    bool opened = false;
    TEST("fleet wiki: indexed distinct seeks skip duplicate history with measured VM work") {
        ASSERT(fb_rpc_env_open(&e)); opened = true;
        db_fleet_board_test_set_wiki_limits(1000, 1000);
        const int64_t now = INT64_C(5000000);
        for (int i = 0; i < 400; i++)
            ASSERT(fb_test_ingest_page(&e.db, "a-history", "prose", i, now + i));
        ASSERT(fb_test_ingest_page(&e.db, "a-history", "tied newest", 400, now + 399));
        ASSERT(fb_test_ingest_page(&e.db, "b-next", "prose", 401, now));
        ASSERT(fb_test_ingest_page(&e.db, "z-last", "prose", 402, now));
        ASSERT(fb_query_index_plan(&e.db));
        struct fb_query_vm old = {0}, indexed = {0};
        static struct db_fleet_board_post rows[3];
        ASSERT(sqlite3_trace_v2(e.db.db, SQLITE_TRACE_PROFILE, fb_query_vm_trace, &old) == SQLITE_OK);
        ASSERT_EQ(fb_query_naive_list(&e.db, rows, 3), 3);
        ASSERT(sqlite3_trace_v2(e.db.db, SQLITE_TRACE_PROFILE, fb_query_vm_trace, &indexed) == SQLITE_OK);
        struct fleet_wiki_query_progress progress;
        unsigned count = 0;
        ASSERT(db_fleet_board_wiki_query(&e.db, "", fb_query_count, &count, &progress));
        ASSERT(sqlite3_trace_v2(e.db.db, 0, NULL, NULL) == SQLITE_OK);
        ASSERT_EQ(count, 3);
        ASSERT_EQ(progress.status, FLEET_WIKI_QUERY_DONE);
        ASSERT_EQ(progress.verified, 3);
        ASSERT(indexed.steps < old.steps / 2);
        struct fb_query_vm listed = {0};
        static struct db_fleet_board_post list_rows[3];
        ASSERT(sqlite3_trace_v2(e.db.db, SQLITE_TRACE_PROFILE, fb_query_vm_trace, &listed) == SQLITE_OK);
        ASSERT_EQ(db_fleet_board_wiki_list_after(&e.db, "", list_rows, 3, NULL, NULL), 3);
        ASSERT(sqlite3_trace_v2(e.db.db, 0, NULL, NULL) == SQLITE_OK);
        ASSERT(listed.steps < old.steps / 2);
        struct fb_query_compare_rows expected = {.rows = rows};
        ASSERT(db_fleet_board_wiki_query(&e.db, "", fb_query_compare, &expected, &progress));
        ASSERT_EQ(expected.count, 3);
        ASSERT(node_db_exec(&e.db, "UPDATE fleet_board_posts SET text='corrupt newest' "
            "WHERE id=(SELECT id FROM fleet_board_posts WHERE slug='a-history' "
            "ORDER BY created_at DESC,id DESC LIMIT 1)"));
        ASSERT(db_fleet_board_wiki_read(&e.db, "a-history", &rows[0]));
        expected.count = 0;
        ASSERT(db_fleet_board_wiki_query(&e.db, "", fb_query_compare, &expected, &progress));
        ASSERT_EQ(expected.count, 3);
        printf("wiki query VM: baseline=%llu indexed=%llu statements=%llu/%llu\n",
            (unsigned long long)old.steps, (unsigned long long)indexed.steps,
            (unsigned long long)old.statements, (unsigned long long)indexed.statements);
        ASSERT(!db_fleet_board_wiki_query(&e.db, "", fb_query_fail, NULL, &progress));
        ASSERT_EQ(progress.status, FLEET_WIKI_QUERY_VISITOR_FAILED);
        ASSERT_STR_EQ(progress.after_slug, "");
        sqlite3_progress_handler(e.db.db, 1, fb_query_abort_step, NULL);
        bool queried = db_fleet_board_wiki_query(&e.db, "", fb_query_count, &count, &progress);
        sqlite3_progress_handler(e.db.db, 0, NULL, NULL);
        ASSERT(!queried);
        ASSERT_EQ(progress.status, FLEET_WIKI_QUERY_STORAGE);
        ASSERT(node_db_exec(&e.db, "UPDATE fleet_board_posts SET text='corrupt' WHERE slug='a-history'"));
        ASSERT(db_fleet_board_wiki_query(&e.db, "", fb_query_count, &count, &progress));
        ASSERT_EQ(progress.status, FLEET_WIKI_QUERY_VERIFY_BUDGET);
        ASSERT_EQ(progress.verified, FLEET_BOARD_LIST_MAX);
        ASSERT_STR_EQ(progress.after_slug, "");
        ASSERT_STR_EQ(progress.blocked_slug, "a-history");
        struct json_value input, envelope;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "q", "prose"));
        enum zcl_command_exit rc;
        ASSERT(fb_query_execute(&e, false, &input, 2048, &envelope, &rc));
        ASSERT_EQ(rc, ZCL_COMMAND_EXIT_OK);
        const struct json_value *data = json_get(&envelope, "data");
        ASSERT(json_get_bool(json_get(data, "incomplete")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "blocked_slug")), "a-history");
        ASSERT(strstr(json_get_str(json_get(data, "reason")), "verification_budget") != NULL);
        json_free(&input); json_free(&envelope);
        PASS();
    } _test_next:;
    if (opened) {
        sqlite3_progress_handler(e.db.db, 0, NULL, NULL);
        (void)sqlite3_trace_v2(e.db.db, 0, NULL, NULL);
        fb_rpc_env_close(&e);
    }
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

/* Two wiki revisions of distinct pages are held, then a third distinct page
 * arrives from a relay. With `window_max` 2 the refusal is the window leg
 * and with `stored_max` 2 it is the final stored leg; either way the relay
 * is neither scored nor disconnected and the post is not stored. */
static bool fb_wiki_relay_unscored(uint8_t who, int64_t window_max,
                                   int64_t stored_max)
{
    const int64_t now = (int64_t)platform_time_wall_time_t();
    struct node_db db;
    memset(&db, 0, sizeof(db));
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node node;
    struct boot_svc_ctx svc;
    struct fleet_board_post post;
    uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 + FLEET_BOARD_BODY_MAX +
                  FLEET_BOARD_SIG_BYTES];
    size_t frame_len = 0;

    peer_scoring_init();
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    mp.net_mgr = &nm;
    svc.node_db = &db;
    svc.msg_processor = &mp;
    memset(&node, 0, sizeof(node));
    node.id = 43;
    (void)snprintf(node.addr_name, sizeof(node.addr_name), "%s", "wiki-relay");
    node.addr.svc.addr.ip[10] = 0xff;
    node.addr.svc.addr.ip[11] = 0xff;
    node.addr.svc.addr.ip[12] = 198;
    node.addr.svc.addr.ip[13] = 51;
    node.addr.svc.addr.ip[14] = 100;
    node.addr.svc.addr.ip[15] = 9;
    if (!node_db_open(&db, ":memory:"))
        return false;
    boot_fleet_board_wire(&svc);
    db_fleet_board_test_set_wiki_limits(window_max, stored_max);
    bool ok = fb_test_put_rev(&db, "relay-a", 1, who, now, &post) ==
                  FLEET_BOARD_OK &&
              fb_test_put_rev(&db, "relay-b", 1, who, now, &post) ==
                  FLEET_BOARD_OK;
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_wiki_rev(&post, "relay-c", 1, seed, pk, now);
    ok = ok && fleet_board_frame_encode_post(&post, frame, sizeof(frame),
                                             &frame_len) == FLEET_BOARD_OK;
    int before = atomic_load(&node.misbehavior);
    ok = ok && boot_fleet_board_frame(&mp, &node, frame, frame_len, NULL) &&
         atomic_load(&node.misbehavior) == before && !node.disconnect &&
         !db_fleet_board_have(&db, post.id);
    boot_fleet_board_shutdown();
    db_fleet_board_test_set_wiki_limits(0, 0);
    node_db_close(&db);
    return ok;
}

static int test_fleet_board_wiki_refusals_do_not_score_relay(void)
{
    int failures = 0;
    TEST("fleet board: a relayed wiki revision past the author's wiki window "
        "or stored ceiling is dropped without scoring the relay") {
        ASSERT(fb_wiki_relay_unscored(28, 2, 0));
        ASSERT(fb_wiki_relay_unscored(29, 1000, 2));
        PASS();
    } _test_next:;
    return failures;
}

/* The public-post quota counts one AUTHOR key on this node's store; the
 * relaying peer is usually not that author and must not be scored for it. */
static int test_fleet_board_quota_does_not_score_relay(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db;
    memset(&db, 0, sizeof(db));
    TEST("fleet board: a relayed post past the author's quota is dropped "
        "without scoring the relay") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t seed[32], pk[32];
        struct fleet_board_post post;
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t frame_len = 0;
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        struct boot_svc_ctx svc;

        peer_scoring_init();
        memset(&nm, 0, sizeof(nm));
        memset(&mp, 0, sizeof(mp));
        memset(&svc, 0, sizeof(svc));
        mp.net_mgr = &nm;
        svc.node_db = &db;
        svc.msg_processor = &mp;
        memset(&node, 0, sizeof(node));
        node.id = 42;
        (void)snprintf(node.addr_name, sizeof(node.addr_name), "%s",
                       "board-relay");
        node.addr.svc.addr.ip[10] = 0xff;
        node.addr.svc.addr.ip[11] = 0xff;
        node.addr.svc.addr.ip[12] = 198;
        node.addr.svc.addr.ip[13] = 51;
        node.addr.svc.addr.ip[14] = 100;
        node.addr.svc.addr.ip[15] = 8;

        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        boot_fleet_board_wire(&svc);

        fb_test_identity(12, seed, pk);
        for (int i = 0; i <= FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            char text[64];
            (void)snprintf(text, sizeof(text), "relayed post %d", i);
            fb_test_compose(&post, FLEET_BOARD_KIND_NOTE, "author", text,
                            (uint64_t)now, 3600);
            fb_test_scope(&post, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&post, seed, pk), FLEET_BOARD_OK);
            if (i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX)
                ASSERT_EQ(db_fleet_board_post_ingest(&db, &post, now, NULL),
                          FLEET_BOARD_OK);
        }
        ASSERT_EQ(fleet_board_frame_encode_post(&post, frame, sizeof(frame),
                                                &frame_len), FLEET_BOARD_OK);
        int score_before = atomic_load(&node.misbehavior);
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, frame_len, NULL));
        ASSERT_EQ(atomic_load(&node.misbehavior), score_before);
        ASSERT(!db_fleet_board_have(&db, post.id));
        ASSERT(!node.disconnect);
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    return failures;
}


/* T1 + T2: the resident leg. FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX rows
 * admitted 11 s apart with maximum TTL; the next post is refused (T2). After
 * the TTL passes the key is still refused (T1) because expired rows still
 * count until the reclaim removes them. */
static int test_fleet_board_public_quota_counts_stored(void)
{
    int failures = 0;
    TEST("fleet board: the per-key resident ceiling counts STORED rows — "
        "expiry alone does not hand a slot back, the reclaim does") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(12, seed, pk);
        const int64_t base = 1000000;
        /* 11 s apart keeps a 600 s window under its 60-arrival limit, so only
         * the resident leg is exercised. */
        const int64_t step = 11;
        const uint32_t ttl = FLEET_BOARD_TTL_MAX;
        int64_t last = base;

        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX; i++) {
            struct fleet_board_post p;
            char text[64];
            (void)snprintf(text, sizeof(text), "resident post %d", i);
            last = base + (int64_t)i * step;
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "steady", text,
                            (uint64_t)last, ttl);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            bool stored = false;
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, last, &stored),
                      FLEET_BOARD_OK);
            ASSERT(stored);
        }

        /* T2: all of them are live, so the ceiling refuses the next one. */
        struct fleet_board_post one_too_many;
        fb_test_compose(&one_too_many, FLEET_BOARD_KIND_NOTE, "steady",
                        "one post past the resident ceiling",
                        (uint64_t)last + 1, ttl);
        fb_test_scope(&one_too_many, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&one_too_many, seed, pk),
                  FLEET_BOARD_OK);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &one_too_many, last + 1,
                                             &stored),
                  FLEET_BOARD_ERR_QUOTA);
        ASSERT(!stored);

        /* T1: TTL expired but rows still on disk, so the key is still
         * refused. */
        int64_t later = last + (int64_t)ttl + 1;
        struct fleet_board_post after_expiry;
        fb_test_compose(&after_expiry, FLEET_BOARD_KIND_NOTE, "steady",
                        "the first post after the whole batch expired",
                        (uint64_t)later, 3600);
        fb_test_scope(&after_expiry, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&after_expiry, seed, pk),
                  FLEET_BOARD_OK);
        stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &after_expiry, later,
                                             &stored),
                  FLEET_BOARD_ERR_QUOTA);
        ASSERT(!stored);

        /* The reclaim is what makes the bytes go, and only then does the
         * slot come back. */
        int64_t removed = 0;
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, later, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT_EQ(removed, FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX);
        stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &after_expiry, later,
                                             &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* T5: the reclaim cannot lift the burst ceiling. The window leg counts
 * arrivals, so rows still inside their window survive the pass and the 61st
 * post in 600 s is refused whether or not maintenance ran. */
static int test_fleet_board_reclaim_keeps_burst_bound(void)
{
    int failures = 0;
    TEST("fleet board: a reclaim inside an open burst window does not hand "
        "the key its window back") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(15, seed, pk);
        const int64_t now = 1500000;
        const uint32_t ttl = 1;

        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            struct fleet_board_post p;
            char text[64];
            (void)snprintf(text, sizeof(text), "one-second note %d", i);
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "burster", text,
                            (uint64_t)now, ttl);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            bool stored = false;
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, &stored),
                      FLEET_BOARD_OK);
            ASSERT(stored);
        }

        /* Every one of them is expired a minute later; the window they
         * arrived in has 540 s left to run. The pass takes nothing. */
        int64_t inside = now + 60;
        int64_t removed = 99;
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, inside, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT_EQ(removed, 0);

        struct fleet_board_post next;
        fb_test_compose(&next, FLEET_BOARD_KIND_NOTE, "burster",
                        "the 61st arrival in the same window",
                        (uint64_t)inside, 3600);
        fb_test_scope(&next, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&next, seed, pk), FLEET_BOARD_OK);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &next, inside, &stored),
                  FLEET_BOARD_ERR_QUOTA);
        ASSERT(!stored);

        /* Once their window closes the pass reclaims them all and the key
         * may post again. */
        int64_t outside =
            now + FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS + 1;
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, outside, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT_EQ(removed, FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX);
        stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &next, outside, &stored),
                  FLEET_BOARD_OK);
        ASSERT(stored);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* T3: the window leg is not live-aware: a burst of short-TTL posts still
 * counts after they expire. */
static int test_fleet_board_public_quota_window_counts_expired(void)
{
    int failures = 0;
    TEST("fleet board: the rolling window counts every arrival, including "
        "posts whose TTL has already run out") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(13, seed, pk);
        const int64_t now = 700000;
        const uint32_t ttl = 60;

        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            struct fleet_board_post p;
            char text[64];
            (void)snprintf(text, sizeof(text), "burst post %d", i);
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "burster", text,
                            (uint64_t)now, ttl);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            bool stored = false;
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, &stored),
                      FLEET_BOARD_OK);
            ASSERT(stored);
        }

        /* Past every one of those TTLs, still inside the same 600 s window
         * of arrivals this node recorded. */
        int64_t later = now + (int64_t)ttl * 2;
        struct fleet_board_filter filter;
        memset(&filter, 0, sizeof(filter));
        filter.host_set = true;
        memcpy(filter.host_pubkey, pk, 32);
        struct db_fleet_board_post rows[4];
        ASSERT_EQ(db_fleet_board_list(&db, &filter, later, rows, 4), 0);

        struct fleet_board_post next;
        fb_test_compose(&next, FLEET_BOARD_KIND_NOTE, "burster",
                        "one more inside the same window", (uint64_t)later,
                        3600);
        fb_test_scope(&next, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&next, seed, pk), FLEET_BOARD_OK);
        bool stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &next, later, &stored),
                  FLEET_BOARD_ERR_QUOTA);
        ASSERT(!stored);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* T4: the reclaim deletes expired discussion rows, keeps durable wiki
 * revisions, leaves a chain the unchanged verifier walks (survivors re-seq'd
 * 1..n), and refuses to run inside another transaction. */
static int test_fleet_board_reclaim_expired(void)
{
    int failures = 0;
    TEST("fleet board: the maintenance reclaim takes back expired posts, "
        "keeps the wiki, and leaves a chain that still verifies") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(14, seed, pk);
        const int64_t now = 900000;

        /* Survivors are not a suffix of the chain, so the relink is real. */
        uint8_t doomed[3][32];
        uint8_t kept[2][32];
        int n_doomed = 0;
        int n_kept = 0;
        for (int i = 0; i < 5; i++) {
            struct fleet_board_post p;
            char text[64];
            bool durable = (i == 1 || i == 3);
            (void)snprintf(text, sizeof(text), "%s post %d",
                           durable ? "long-lived" : "short-lived", i);
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "mixed", text,
                            (uint64_t)now + (uint64_t)i,
                            durable ? FLEET_BOARD_TTL_MAX : 100);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now + i, NULL),
                      FLEET_BOARD_OK);
            if (durable)
                memcpy(kept[n_kept++], p.id, 32);
            else
                memcpy(doomed[n_doomed++], p.id, 32);
        }

        /* One wiki revision with a TTL that runs out: durable history is
         * not discussion, and the reclaim must not take it. */
        struct fleet_board_post page;
        fb_test_compose(&page, FLEET_BOARD_KIND_WIKI, "mixed",
                        "A wiki revision outlives its own ttl.",
                        (uint64_t)now + 5, 100);
        (void)snprintf(page.slug, sizeof(page.slug), "%s", "durable");
        (void)snprintf(page.title, sizeof(page.title), "%s", "Durable page");
        ASSERT_EQ(fleet_board_post_sign(&page, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &page, now + 5, NULL),
                  FLEET_BOARD_OK);

        int64_t checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 6);

        /* Inside another transaction the reclaim steps aside, changes
         * nothing and reports DEFERRED. */
        int64_t after_ttl = now + 1000;
        int64_t removed = 99;
        ASSERT(node_db_begin(&db));
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, after_ttl, &removed),
                  FLEET_BOARD_RECLAIM_DEFERRED);
        ASSERT_EQ(removed, 0);
        ASSERT(node_db_rollback(&db));
        ASSERT(db_fleet_board_have(&db, doomed[0]));

        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, after_ttl, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT_EQ(removed, 3);
        for (int i = 0; i < 3; i++)
            ASSERT(!db_fleet_board_have(&db, doomed[i]));
        for (int i = 0; i < 2; i++)
            ASSERT(db_fleet_board_have(&db, kept[i]));
        ASSERT(db_fleet_board_have(&db, page.id));

        /* The chain the verifier walks is unchanged in kind: genesis, then
         * every stored row, re-seq'd 1..n in the order they arrived. */
        checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 3);
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_post_find(&db, kept[0], &row));
        ASSERT_EQ(row.seq, 1);
        ASSERT(db_fleet_board_post_find(&db, kept[1], &row));
        ASSERT_EQ(row.seq, 2);
        ASSERT(db_fleet_board_post_find(&db, page.id, &row));
        ASSERT_EQ(row.seq, 3);

        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, after_ttl, &status));
        ASSERT_EQ(status.posts, 3);

        /* A second pass with nothing expired is a no-op that says so. */
        removed = 99;
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, after_ttl, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT_EQ(removed, 0);

        /* And the board keeps appending: the next post chains onto the
         * rebuilt head, not onto the one the deleted rows left behind. */
        struct fleet_board_post fresh;
        fb_test_compose(&fresh, FLEET_BOARD_KIND_NOTE, "mixed",
                        "the first post after a reclaim", (uint64_t)after_ttl,
                        3600);
        fb_test_scope(&fresh, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&fresh, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &fresh, after_ttl, NULL),
                  FLEET_BOARD_OK);
        checked = 0;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 4);
        ASSERT(db_fleet_board_post_find(&db, fresh.id, &row));
        ASSERT_EQ(row.seq, 4);

        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}
/* ── FLEET-scope carriage over the paired mesh stream ────────────────────
 * The "board" stream service through the production callbacks over the
 * loopback wire; only the socket, DHT delegation lookup and clock are stood
 * in for. The asker accepted the link; the answerer dialled it. */

/* Inside the fixture delegations' signed window (1000..4000). */
#define FBW_NOW INT64_C(2500)
#define FBW_PAIRED_AT INT64_C(1)
#define FBW_PAIRING_EXPIRES INT64_C(4102444800)
#define FBW_POSTS 40

struct fbw {
    char dir[256];
    struct mesh_term_fixture f;
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *asker;    /* accepted the link: the pulling box */
    struct p2p_node *answerer; /* dialled the link: the box behind NAT */
    struct p2p_node *nodes[2];
    struct send_segment *ask_q;
    struct send_segment *answer_q;
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    struct node_db a; /* the answering box's board store */
    struct node_db b; /* the asking box's board store */
    uint8_t box_a[32];
    uint8_t box_b[32];
    bool fixture_open;
    bool nodes_inited;
    bool registered;
};

static bool g_fbw_deny_read;
static bool g_fbw_deny_post;
static uint8_t g_fbw_deny_post_key[32];

/* Role gate for this group: every key may do everything, except fleet reads
 * can be switched off and one author can be refused. */
static bool fbw_role_check(const uint8_t key[32], const char *leaf,
                           const char *kind, char *why, size_t why_cap,
                           void *ctx)
{
    (void)kind;
    (void)ctx;
    bool deny = (g_fbw_deny_read &&
                 strcmp(leaf, FLEET_BOARD_FLEET_READ_LEAF) == 0) ||
                (g_fbw_deny_post &&
                 strcmp(leaf, ZCL_FLEET_LEAF_BOARD_POST) == 0 &&
                 memcmp(key, g_fbw_deny_post_key, 32) == 0);
    if (deny && why && why_cap)
        (void)snprintf(why, why_cap, "role_refused: test denies %s", leaf);
    return !deny;
}

static bool fbw_nodes_open(struct fbw *w)
{
    zcl_mutex_init(&w->nm.cs_nodes);
    zcl_mutex_init(&w->nm.cs_last_node_id);
    w->nodes_inited = true;
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    addr.svc.port = 18035;
    w->asker = p2p_node_create(&w->nm, ZCL_INVALID_SOCKET, &addr,
                               "board-ask", true);
    w->answerer = p2p_node_create(&w->nm, ZCL_INVALID_SOCKET, &addr,
                                  "board-answer", false);
    if (!w->asker || !w->answerer)
        return false;
    w->asker->transport = w->f.term_peer.ini;
    w->answerer->transport = w->f.res_term;
    w->asker->state = PEER_HANDSHAKE_COMPLETE;
    w->answerer->state = PEER_HANDSHAKE_COMPLETE;
    w->nodes[0] = w->asker;
    w->nodes[1] = w->answerer;
    w->nm.nodes = w->nodes;
    w->nm.num_nodes = 2;
    w->ask_q = mesh_loop_sentinel(w->asker);
    w->answer_q = mesh_loop_sentinel(w->answerer);
    return w->ask_q && w->answer_q;
}

static bool fbw_open(struct fbw *w)
{
    memset(w, 0, sizeof(*w));
    test_make_tmpdir(w->dir, sizeof(w->dir), "fleet_board", "carriage");
    w->fixture_open = mesh_term_fixture_open(&w->f, w->dir);
    if (!w->fixture_open || !fbw_nodes_open(w))
        return false;
    w->mp.net_mgr = &w->nm;
    w->mp.params = chain_params_get();
    w->svc.msg_processor = &w->mp;
    w->dbsvc.node_db = &w->f.ndb; /* the pairing authority */
    w->dbsvc.started = true;
    w->runtime.db_service = &w->dbsvc;
    app_runtime_set_current(&w->runtime);
    mesh_stream_test_bind(&w->svc);
    mesh_stream_test_reset();
    w->registered = boot_fleet_board_fleet_register_service();
    memset(w->box_a, 0xA1, 32);
    memset(w->box_b, 0xB2, 32);
    return w->mp.params && w->registered && node_db_open(&w->a, ":memory:") &&
           node_db_open(&w->b, ":memory:");
}

static void fbw_close(struct fbw *w)
{
    boot_fleet_board_fleet_test_bind_authority(NULL, NULL, 0);
    mesh_stream_test_reset();
    boot_fleet_board_fleet_test_bind(NULL);
    mesh_stream_service_unregister(FLEET_BOARD_FLEET_SERVICE_NAME);
    mesh_stream_service_unregister(FLEET_BOARD_ROSTER_SERVICE_NAME);
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    mesh_loop_free_queue(w->asker, w->ask_q);
    mesh_loop_free_queue(w->answerer, w->answer_q);
    p2p_node_free(w->asker);
    p2p_node_free(w->answerer);
    free(w->ask_q);
    free(w->answer_q);
    if (w->nodes_inited) {
        zcl_mutex_destroy(&w->nm.cs_nodes);
        zcl_mutex_destroy(&w->nm.cs_last_node_id);
    }
    if (w->a.open)
        node_db_close(&w->a);
    if (w->b.open)
        node_db_close(&w->b);
    if (w->fixture_open)
        mesh_term_fixture_close(&w->f);
    test_rm_rf_recursive(w->dir);
}

/* Sign and store one post in `db` as if it arrived at `received_at`. */
static bool fbw_post(struct node_db *db, uint8_t who, uint8_t scope,
                     const char *text, int64_t created_at, uint32_t ttl,
                     int64_t received_at, struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(out, FLEET_BOARD_KIND_NOTE, "carrier", text,
                    (uint64_t)created_at, ttl);
    fb_test_scope(out, scope,
                  scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(db, out, received_at, NULL) ==
               FLEET_BOARD_OK;
}

/* One whole pull toward the answering box as `peer_box`: the OPEN, the
 * answer, the close, and the commit into `into`. Returns the posts newly
 * stored; `frames` receives how many frames the answering box sent. */
static size_t fbw_pull(struct fbw *w, const uint8_t peer_box[32],
                       struct node_db *into, size_t *frames)
{
    *frames = 0;
    mesh_loop_discard(w->asker, w->ask_q, w->f.res_term);
    mesh_loop_discard(w->answerer, w->answer_q, w->f.term_peer.ini);
    mesh_stream_test_reset();
    if (!boot_fleet_board_fleet_test_pull(w->f.resp_noise_pub, peer_box) ||
        mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return SIZE_MAX;
    boot_fleet_board_fleet_test_serve(); /* the answer, when there is one */
    boot_fleet_board_fleet_test_serve(); /* nothing left: close */
    *frames = mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini,
                             &w->mp, w->asker);
    return boot_fleet_board_fleet_test_drain_into(into);
}

/* The verdict a raw OPEN from the asking node gets, read off the wire. */
static uint8_t fbw_raw_open_verdict(struct fbw *w, uint64_t stream_id)
{
    uint8_t pull[FLEET_BOARD_FLEET_PULL_BYTES];
    memset(pull, 0, sizeof(pull));
    pull[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_PULL;
    pull[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    uint8_t frame[MESH_LOOP_WIRE_MAX];
    size_t frame_len = mesh_stream_test_open_frame(
        stream_id, 4096u, FLEET_BOARD_FLEET_SERVICE_NAME, pull, sizeof(pull),
        frame, sizeof(frame));
    uint8_t answer[MESH_LOOP_WIRE_MAX];
    uint8_t kind = 0;
    bool more = false;
    if (frame_len == 0 ||
        !mesh_stream_frame(&w->mp, w->answerer, frame, frame_len, NULL))
        return 0xFFu;
    size_t answer_len = mesh_loop_take(w->answerer, w->answer_q,
                                       w->f.term_peer.ini, answer,
                                       sizeof(answer), &more);
    if (!mesh_stream_test_read_header(answer, answer_len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_CLOSE)
        return 0xFEu;
    return answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u];
}

/* Every fleet post in `posts` is held by `db`. */
static bool fbw_holds_all(struct node_db *db,
                          const struct fleet_board_post *posts, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!db_fleet_board_have(db, posts[i].id))
            return false;
    return true;
}

/* Deliver independently composed frames through the real encrypted P2P queue. */
static bool fbw_deliver(struct fbw *w, const uint8_t *frame, size_t len)
{
    if (!len || !p2p_node_begin_message(w->asker, "zpkgswm",
                                       w->mp.params->pchMessageStart))
        return false;
    p2p_node_write_message_data(w->asker, frame, len);
    return p2p_node_end_message(w->asker) &&
           mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                           w->answerer) == 1;
}

static bool fbw_exact_answer(const uint8_t *frame, size_t len,
                              const struct fleet_board_post *post)
{
    uint8_t wire[MESH_LOOP_WIRE_MAX];
    size_t wire_len = 0;
    const size_t offset = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 2u +
                          FLEET_BOARD_FLEET_ANSWER_HEAD +
                          FLEET_BOARD_FLEET_RECORD_HEAD;
    return fleet_board_post_encode(post, wire, sizeof(wire), &wire_len) ==
               FLEET_BOARD_OK && len == offset + wire_len &&
           memcmp(frame + offset, wire, wire_len) == 0;
}

/* Each authority change gets a fresh independently paired Noise fixture. */
static int test_fleet_board_delayed_authority(unsigned change)
{
    int failures = 0;
    static struct fbw w;
    struct fleet_board_post post;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-delayed-authority" };
    const char *names[] = {
        "fleet board delayed page: authorized WINDOW sends exact signed post",
        "fleet board delayed page: pairing revoke prevents cached DATA",
        "fleet board delayed page: read role withdrawal prevents cached DATA",
        "fleet board delayed page: delegation expiry prevents cached DATA" };
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);
    TEST(names[change]) {
        ASSERT(opened);
        ASSERT(fbw_post(&w.a, 7, FLEET_BOARD_SCOPE_FLEET, "private delayed page",
                        2000, 3600, 2100, &post));
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind(&w.a);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        uint8_t pull[FLEET_BOARD_FLEET_PULL_BYTES] = {0};
        pull[0] = FLEET_BOARD_FLEET_MSG_PULL;
        pull[1] = FLEET_BOARD_FLEET_VERSION;
        uint8_t frame[MESH_LOOP_WIRE_MAX], answer[MESH_LOOP_WIRE_MAX];
        size_t len = mesh_stream_test_open_frame(
            1, 1, FLEET_BOARD_FLEET_SERVICE_NAME, pull, sizeof(pull),
            frame, sizeof(frame));
        ASSERT(fbw_deliver(&w, frame, len));
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_BOARD_FLEET_SERVICE_NAME),
                  (size_t)1);
        boot_fleet_board_fleet_test_serve();
        bool more = false;
        ASSERT_EQ(mesh_loop_take(w.answerer, w.answer_q, w.f.term_peer.ini,
                                 answer, sizeof(answer), &more), (size_t)0);
        ASSERT(!more); /* The actual credit window held the cached page. */
        if (change == 1)
            ASSERT(db_mesh_pairing_revoke(&w.f.ndb,
                                          w.f.term_peer.pairing.pairing_id,
                                          FBW_NOW));
        else if (change == 2)
            g_fbw_deny_read = true;
        else if (change == 3)
            boot_fleet_board_fleet_test_bind_authority(
                &w.f.term_peer.delegation, w.f.genesis, 4001);
        len = mesh_stream_test_window_frame(1, 4096, frame, sizeof(frame));
        ASSERT(fbw_deliver(&w, frame, len));
        boot_fleet_board_fleet_test_serve();
        len = mesh_loop_take(w.answerer, w.answer_q, w.f.term_peer.ini,
                              answer, sizeof(answer), &more);
        uint8_t kind = 0;
        ASSERT(more && mesh_stream_test_read_header(answer, len, &kind, NULL));
        ASSERT_EQ(kind, change ? MESH_STREAM_KIND_CLOSE : MESH_STREAM_KIND_DATA);
        if (change) {
            ASSERT(len > MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u);
            ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                      MESH_STREAM_REFUSED_PEER_UNPAIRED);
        } else
            ASSERT(fbw_exact_answer(answer, len, &post));
        boot_fleet_board_fleet_test_serve();
        if (change) {
            ASSERT_EQ(mesh_loop_take(w.answerer, w.answer_q,
                                     w.f.term_peer.ini, answer, sizeof(answer),
                                     &more), (size_t)0);
            ASSERT(!more);
        } else
            mesh_loop_discard(w.answerer, w.answer_q, w.f.term_peer.ini);
        PASS();
    }
    _test_next:
    fbw_close(&w);
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

static int test_fleet_board_fleet_carriage(void)
{
    int failures = 0;
    static struct fbw w;
    static struct fleet_board_post fleet[FBW_POSTS];
    struct fleet_board_post expired, public_post, from_b;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-carriage-test" };
    struct boot_fleet_board_fleet_counts before, after;
    size_t frames = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: an unpaired peer, and a paired peer without "
         "the read role, never receive a fleet post") {
        ASSERT(opened);
        /* The answering box holds a live fleet post, a live public post,
         * and a fleet post whose TTL ran out long before anyone asks. */
        ASSERT(fbw_post(&w.a, 7, FLEET_BOARD_SCOPE_FLEET, "gone by now",
                        1000, 60, 1000, &expired));
        ASSERT(fbw_post(&w.a, 7, FLEET_BOARD_SCOPE_PUBLIC, "for everyone",
                        2000, 3600, 2000, &public_post));
        for (int i = 0; i < FBW_POSTS; i++) {
            char text[48];
            (void)snprintf(text, sizeof(text), "fleet note %d", i);
            ASSERT(fbw_post(&w.a, 7, FLEET_BOARD_SCOPE_FLEET, text,
                            2000 + i, 3600, 2100, &fleet[i]));
        }
        boot_fleet_board_fleet_test_bind(&w.a);

        /* No pairing row: the OPEN is refused by name. The accepting node
         * mints odd stream ids. */
        ASSERT_EQ(fbw_raw_open_verdict(&w, 1), MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_BOARD_FLEET_SERVICE_NAME),
                  (size_t)0);

        /* Paired and current, but the peer's key holds no role that reads
         * the fleet board here: refused by the service, before a row is
         * read, and counted. */
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        g_fbw_deny_read = true;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        ASSERT_EQ(frames, (size_t)1); /* the refusal alone */
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.role_refused, before.role_refused + 1);
        ASSERT(!db_fleet_board_have(&w.b, fleet[0].id));
        g_fbw_deny_read = false;
        PASS();
    }

    TEST("fleet board carriage: a paired peer pulls fleet posts in bounded "
         "pages, never an expired or public one, and a re-pull is a no-op") {
        /* 40 live fleet posts, 32 to a page. */
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)(FBW_POSTS - FLEET_BOARD_FLEET_ANSWER_POSTS_MAX));
        ASSERT(fbw_holds_all(&w.b, fleet, FBW_POSTS));
        ASSERT(!db_fleet_board_have(&w.b, expired.id));
        ASSERT(!db_fleet_board_have(&w.b, public_post.id));

        /* Everything is held: asking again moves nothing, and the answer
         * is its head alone — one DATA frame with no record — then the
         * CLOSE. */
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        ASSERT_EQ(frames, (size_t)2);
        struct db_fleet_board_post row;
        ASSERT(db_fleet_board_post_find(&w.b, fleet[0].id, &row));
        ASSERT_EQ(row.post.scope, FLEET_BOARD_SCOPE_FLEET);
        PASS();
    }

    TEST("fleet board carriage: two paired stores converge") {
        /* The other box posts and answers: it pages everything it holds in
         * arrival order, the 40 already pulled, then the one new post. */
        ASSERT(fbw_post(&w.b, 8, FLEET_BOARD_SCOPE_FLEET, "from the other box",
                        2200, 3600, 2200, &from_b));
        boot_fleet_board_fleet_test_bind(&w.b);
        ASSERT_EQ(fbw_pull(&w, w.box_b, &w.a, &frames), (size_t)0);
        ASSERT_EQ(fbw_pull(&w, w.box_b, &w.a, &frames), (size_t)1);
        ASSERT_EQ(fbw_pull(&w, w.box_b, &w.a, &frames), (size_t)0);
        ASSERT_EQ(frames, (size_t)2);
        ASSERT(db_fleet_board_have(&w.a, from_b.id));
        ASSERT(fbw_holds_all(&w.a, fleet, FBW_POSTS));
        ASSERT(fbw_holds_all(&w.b, fleet, FBW_POSTS));
        ASSERT(db_fleet_board_have(&w.b, from_b.id));
        PASS();
    }
    _test_next:
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* Store posts from `who` in `db`, all arriving in the same second, until
 * the batch holds an id below AND an id above `pivot`. Returns how many it
 * stored, or 0 when no such pair turned up in the bound. */
static size_t fbw_post_straddling(struct node_db *db, uint8_t who,
                                  const uint8_t pivot[32], int64_t second,
                                  struct fleet_board_post *out, size_t cap)
{
    bool below = false, above = false;
    size_t n = 0;
    while (n < cap && !(below && above)) {
        char text[48];
        (void)snprintf(text, sizeof(text), "same second %zu", n);
        if (!fbw_post(db, who, FLEET_BOARD_SCOPE_FLEET, text, second, 3600,
                      second, &out[n]))
            return 0;
        int order = memcmp(out[n].id, pivot, 32);
        below = below || order < 0;
        above = above || order > 0;
        n++;
    }
    return below && above ? n : 0;
}

/* Pull `times` whole answers; returns the posts newly stored in all. */
static size_t fbw_pull_n(struct fbw *w, const uint8_t peer_box[32],
                         struct node_db *into, int times)
{
    size_t stored = 0, frames = 0;
    for (int i = 0; i < times; i++) {
        size_t got = fbw_pull(w, peer_box, into, &frames);
        if (got == SIZE_MAX)
            return SIZE_MAX;
        stored += got;
    }
    return stored;
}

#define FBW_BATCH 16

/* The cursor must never pass over a row: same-second arrivals, a refusal
 * that clears later, a reclaim between pulls, and a restart. */
static int test_fleet_board_fleet_carriage_gap_free(void)
{
    int failures = 0;
    static struct fbw w;
    static struct fleet_board_post first[FBW_BATCH], later[FBW_BATCH];
    static struct fleet_board_post live[FBW_POSTS], late[3];
    struct fleet_board_post refused, beside, behind, dead, restarted;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-gap-test" };
    struct boot_fleet_board_fleet_counts before, after;
    size_t frames = 0;
    g_fbw_deny_read = false;
    g_fbw_deny_post = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: posts arriving in the same second as the "
         "last one pulled, with ids on both sides of it, all arrive") {
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        ASSERT(fbw_post(&w.a, 20, FLEET_BOARD_SCOPE_FLEET, "first in 2300",
                        2300, 3600, 2300, &first[0]));
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        /* More posts in that very second, some sorting below the id just
         * pulled and some above it. */
        size_t n = fbw_post_straddling(&w.a, 21, first[0].id, 2300, later,
                                       FBW_BATCH);
        ASSERT(n >= 2);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), n);
        ASSERT(fbw_holds_all(&w.b, later, n));
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        PASS();
    }

    TEST("fleet board carriage: a post refused for a reason that clears is "
         "delivered once it clears, and never holds back the posts after "
         "it") {
        ASSERT(fbw_post(&w.a, 22, FLEET_BOARD_SCOPE_FLEET, "not granted yet",
                        2310, 3600, 2310, &refused));
        ASSERT(fbw_post(&w.a, 23, FLEET_BOARD_SCOPE_FLEET, "right beside it",
                        2310, 3600, 2310, &beside));
        /* This box does not let key 22 post here yet. */
        uint8_t seed[32];
        fb_test_identity(22, seed, g_fbw_deny_post_key);
        g_fbw_deny_post = true;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.deferred, before.deferred + 1);
        ASSERT(!db_fleet_board_have(&w.b, refused.id));
        ASSERT(db_fleet_board_have(&w.b, beside.id));
        /* Still refused: the next forward page carries the next post, and
         * the sweep after it offers the refused one again, in vain. */
        ASSERT(fbw_post(&w.a, 23, FLEET_BOARD_SCOPE_FLEET, "behind it",
                        2320, 3600, 2320, &behind));
        ASSERT_EQ(fbw_pull_n(&w, w.box_a, &w.b, 2), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, behind.id));
        ASSERT(!db_fleet_board_have(&w.b, refused.id));
        /* The grant arrives. A forward page, then the sweep delivers it. */
        g_fbw_deny_post = false;
        ASSERT_EQ(fbw_pull_n(&w, w.box_a, &w.b, 2), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, refused.id));
        ASSERT_EQ(fbw_pull_n(&w, w.box_a, &w.b, 3), (size_t)0);
        PASS();
    }

    TEST("fleet board carriage: a reclaim on the answering box between two "
         "pulls skips nothing") {
        /* Forty live posts with long-dead ones among them; the dead ones
         * are never served, and are what the reclaim takes back. */
        for (int i = 0; i < FBW_POSTS; i++) {
            char text[48];
            (void)snprintf(text, sizeof(text), "reclaim survivor %d", i);
            ASSERT(fbw_post(&w.a, 24, FLEET_BOARD_SCOPE_FLEET, text, 2400,
                            3600, 2400, &live[i]));
            if (i % 4 == 0) {
                (void)snprintf(text, sizeof(text), "long dead %d", i);
                ASSERT(fbw_post(&w.a, 25, FLEET_BOARD_SCOPE_FLEET, text,
                                1800, 60, 1800, &dead));
            }
        }
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        int64_t removed = 0;
        ASSERT_EQ(db_fleet_board_reclaim_expired(&w.a, FBW_NOW, &removed),
                  FLEET_BOARD_RECLAIM_DONE);
        ASSERT(removed >= FBW_POSTS / 4);
        for (int i = 0; i < 3; i++) {
            char text[48];
            (void)snprintf(text, sizeof(text), "after the reclaim %d", i);
            ASSERT(fbw_post(&w.a, 24, FLEET_BOARD_SCOPE_FLEET, text, 2450,
                            3600, 2450, &late[i]));
        }
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)(FBW_POSTS - FLEET_BOARD_FLEET_ANSWER_POSTS_MAX +
                           3));
        ASSERT(fbw_holds_all(&w.b, live, FBW_POSTS));
        ASSERT(fbw_holds_all(&w.b, late, 3));
        ASSERT(!db_fleet_board_have(&w.b, dead.id));
        PASS();
    }

    TEST("fleet board carriage: an answer from a restarted process sends the "
         "asking box back to the beginning") {
        boot_fleet_board_fleet_test_new_epoch();
        ASSERT(fbw_post(&w.a, 26, FLEET_BOARD_SCOPE_FLEET, "after a restart",
                        2460, 3600, 2460, &restarted));
        /* The first answer is in numbers the cursor cannot trust: nothing
         * from it is taken, and the cursor goes back to 0. */
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        ASSERT(!db_fleet_board_have(&w.b, restarted.id));
        /* From the beginning: every page is dedupe until the new post. */
        size_t got = fbw_pull_n(&w, w.box_a, &w.b, 4);
        ASSERT_EQ(got, (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, restarted.id));
        PASS();
    }
    _test_next:
    g_fbw_deny_post = false;
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* A wiki revision by `who` at `created_at`, stored in `db` as if it arrived
 * at `received_at`; fleet scope, as the paired pull carries. */
static bool fbw_wiki(struct node_db *db, uint8_t who, const char *slug,
                     int64_t created_at, int64_t received_at,
                     struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(out, FLEET_BOARD_KIND_WIKI, "carrier", slug,
                    (uint64_t)created_at, 3600);
    fb_test_scope(out, FLEET_BOARD_SCOPE_FLEET, "");
    (void)snprintf(out->slug, sizeof(out->slug), "%s", slug);
    (void)snprintf(out->title, sizeof(out->title), "%s", slug);
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(db, out, received_at, NULL) ==
               FLEET_BOARD_OK;
}

/* The stored wiki leg is final: a pull whose revision is refused for it
 * must not set the carry, so no sweep ever offers it again. */
static int test_fleet_board_fleet_wiki_full_is_final(void)
{
    int failures = 0;
    static struct fbw w;
    struct fleet_board_post held[2], third;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-wiki-full-test" };
    struct boot_fleet_board_fleet_counts before, after;
    g_fbw_deny_read = false;
    g_fbw_deny_post = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: a wiki revision refused for the stored "
         "ceiling is not offered again, while one refused for the window is") {
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        db_fleet_board_test_set_wiki_limits(1000, 2);
        ASSERT(fbw_wiki(&w.b, 40, "held-one", 2300, 2300, &held[0]));
        ASSERT(fbw_wiki(&w.b, 40, "held-two", 2301, 2301, &held[1]));
        ASSERT(fbw_wiki(&w.a, 40, "third-page", 2400, 2400, &third));
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(fbw_pull_n(&w, w.box_a, &w.b, 4), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT(!db_fleet_board_have(&w.b, third.id));
        ASSERT_EQ(after.deferred, before.deferred);

        /* Control: the same shape refused for the window leg is retryable
         * and counted as deferred. */
        struct fleet_board_post fourth;
        db_fleet_board_test_set_wiki_limits(2, 1000);
        ASSERT(fbw_wiki(&w.a, 40, "fourth-page", 2450, 2450, &fourth));
        boot_fleet_board_fleet_counts(&before);
        (void)fbw_pull_n(&w, w.box_a, &w.b, 2);
        boot_fleet_board_fleet_counts(&after);
        ASSERT(after.deferred > before.deferred);
        PASS();
    }
    _test_next:
    db_fleet_board_test_set_wiki_limits(0, 0);
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* A fleet-scope wiki page travels only the paired channel: an unpaired peer
 * is refused by name, a paired peer without the read role is refused before a
 * row is read, and a paired one receives the fleet page but never a public
 * one (public pages are flooded, not pulled). Once held, the page is visible
 * to the fleet view of the receiver and to no public read. */
static int test_fleet_board_fleet_wiki_carriage(void)
{
    int failures = 0;
    static struct fbw w;
    struct fleet_board_post fleet_page, public_page;
    struct db_fleet_board_post row;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-wiki-carriage-test" };
    struct boot_fleet_board_fleet_counts before, after;
    size_t frames = 0;
    g_fbw_deny_read = false;
    g_fbw_deny_post = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: a fleet wiki page is refused to an unpaired "
         "peer and to a peer without the read role, and a paired peer gets "
         "only the fleet page, visible only in the fleet view") {
        ASSERT(opened);
        ASSERT(fbw_wiki(&w.a, 7, "fleet-only-page", 2000, 2000, &fleet_page));
        /* A public wiki page on the same store, same author. */
        uint8_t seed[32], pk[32];
        fb_test_identity(7, seed, pk);
        fb_test_compose(&public_page, FLEET_BOARD_KIND_WIKI, "carrier",
                        "public-page", 2001, 3600);
        fb_test_scope(&public_page, FLEET_BOARD_SCOPE_PUBLIC, "general");
        (void)snprintf(public_page.slug, sizeof(public_page.slug), "public-page");
        (void)snprintf(public_page.title, sizeof(public_page.title), "public-page");
        ASSERT_EQ(fleet_board_post_sign(&public_page, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&w.a, &public_page, 2001, NULL),
                  FLEET_BOARD_OK);
        boot_fleet_board_fleet_test_bind(&w.a);

        /* No pairing row: refused by name, nothing opened. */
        ASSERT_EQ(fbw_raw_open_verdict(&w, 1), MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_BOARD_FLEET_SERVICE_NAME),
                  (size_t)0);

        /* Paired, but the key holds no read role: refused and counted. */
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        g_fbw_deny_read = true;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.role_refused, before.role_refused + 1);
        ASSERT(!db_fleet_board_have(&w.b, fleet_page.id));
        g_fbw_deny_read = false;

        /* Paired with the role: the fleet page, and only it. */
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, fleet_page.id));
        ASSERT(!db_fleet_board_have(&w.b, public_page.id));
        ASSERT(db_fleet_board_wiki_read_in(&w.b, FLEET_WIKI_VIEW_FLEET,
                                           "fleet-only-page", &row));
        ASSERT(!db_fleet_board_wiki_read_in(&w.b, FLEET_WIKI_VIEW_PUBLIC,
                                            "fleet-only-page", &row));
        PASS();
    }
    _test_next:
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* A role grant lets a key write fleet posts here; it does not let that key
 * fill the store every other key shares. */
static int test_fleet_board_fleet_quota(void)
{
    int failures = 0;
    TEST("fleet board: a fleet-scope key past the per-key quota is refused") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        fb_test_identity(31, seed, pk);
        const int64_t now = 500000;
        for (int i = 0; i <= FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            struct fleet_board_post p;
            char text[64];
            (void)snprintf(text, sizeof(text), "fleet post number %d", i);
            fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "flooder", text,
                            (uint64_t)now, 3600);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_FLEET, "");
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            bool stored = false;
            enum fleet_board_result want =
                i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX ? FLEET_BOARD_OK
                                                        : FLEET_BOARD_ERR_QUOTA;
            ASSERT_EQ(db_fleet_board_post_ingest(&db, &p, now, &stored), want);
            ASSERT_EQ(stored, want == FLEET_BOARD_OK);
        }
        /* The key's public budget is its own: a public post still lands. */
        struct fleet_board_post pub;
        fb_test_compose(&pub, FLEET_BOARD_KIND_NOTE, "flooder",
                        "public is counted apart", (uint64_t)now, 3600);
        fb_test_scope(&pub, FLEET_BOARD_SCOPE_PUBLIC, "general");
        ASSERT_EQ(fleet_board_post_sign(&pub, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &pub, now, NULL),
                  FLEET_BOARD_OK);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static bool fb_refusal_wiki_post(struct fb_rpc_fixture *e, const char *slug,
                                 const char *text, const char *scope,
                                 struct json_value *result)
{
    struct json_value in;
    json_init(&in); json_init(result); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", "post") &&
        json_push_kv_str(&in, "kind", "wiki") &&
        json_push_kv_str(&in, "slug", slug) &&
        json_push_kv_str(&in, "title", "Refusal probe") &&
        json_push_kv_str(&in, "text", text) &&
        (!scope || json_push_kv_str(&in, "scope", scope)) &&
        fb_test_rpc(&e->table, &in, result);
    json_free(&in);
    return ok;
}

static bool fb_refusal_is(const struct json_value *r, const char *needle)
{
    const char *code = json_get_str(json_get(r, "code"));
    const char *message = json_get_str(json_get(r, "message"));
    return !json_get_bool(json_get(r, "ok")) && !strcmp(code, "BOARD_REFUSED") &&
        strstr(message, needle) != NULL;
}

static bool fb_role_denied(const uint8_t key[32], const char *leaf,
                           const char *kind, char *why, size_t why_cap, void *ctx)
{
    (void)key; (void)kind; (void)ctx;
    if (why && why_cap)
        (void)snprintf(why, why_cap, "role_refused: test grants no %s", leaf);
    return false;
}

static int test_fleet_board_write_refusal_reasons(void)
{
    int failures = 0;
    TEST("fleet board: a refused local wiki write names the exact reason and the command that clears it") {
        static struct fb_rpc_fixture e;
        struct json_value r;
        ASSERT(fb_rpc_fixture_open(&e, "write-refusal"));
        /* Carriage returns are refused, and the reason says so. */
        ASSERT(fb_refusal_wiki_post(&e, "crlf-page", "line one\r\nline two", NULL, &r));
        ASSERT(fb_refusal_is(&r, "control character"));
        json_free(&r);
        /* A fleet-scoped write by a key with no role names the grant command. */
        const struct zcl_fleet_role_checker deny = {.allow = fb_role_denied, .name = "write-refusal-test"};
        zcl_fleet_role_checker_install(&deny);
        ASSERT(fb_refusal_wiki_post(&e, "fleet-page", "body", "fleet", &r));
        ASSERT(fb_refusal_is(&r, "z23 fleet roles grant"));
        zcl_fleet_role_checker_install(NULL);
        json_free(&r);
        /* The wiki window: the second revision inside it is refused with the limit. */
        db_fleet_board_test_set_wiki_limits(1, 0);
        ASSERT(fb_refusal_wiki_post(&e, "window-a", "first", NULL, &r));
        ASSERT(json_get_bool(json_get(&r, "ok")));
        json_free(&r);
        ASSERT(fb_refusal_wiki_post(&e, "window-b", "second", NULL, &r));
        ASSERT(fb_refusal_is(&r, "wiki revisions per 600 seconds"));
        json_free(&r);
        db_fleet_board_test_set_wiki_limits(0, 0);
        /* The stored ceiling: a new page is refused and a revision is the way out. */
        db_fleet_board_test_set_wiki_limits(1000, 1);
        ASSERT(fb_refusal_wiki_post(&e, "full-a", "first", NULL, &r));
        ASSERT(fb_refusal_is(&r, "revise an existing page"));
        json_free(&r);
        db_fleet_board_test_set_wiki_limits(0, 0);
        fb_rpc_fixture_close(&e);
        ASSERT(test_rm_rf_recursive(e.dir) == 0);
        PASS();
    } _test_next:;
    db_fleet_board_test_set_wiki_limits(0, 0);
    return failures;
}

/* Walk fleet.wiki.list through its own cursor and collect every slug. */
static char g_fb_list_error[64];

static bool fb_list_last_error_is(const char *code)
{
    return !strcmp(g_fb_list_error, code);
}

void zcl_native_fleet_wiki_list_test_set_calls_max(int max);

static size_t fb_list_walk(struct fb_rpc_env *e, char slugs[][FLEET_BOARD_SLUG_MAX + 1],
                           size_t cap, size_t *calls)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "fleet.wiki.list", NULL);
    struct zcl_command_context ctx = {.registry = reg,
        .granted_capabilities = ~(uint64_t)0, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    size_t total = 0;
    char cursor[24] = "";
    *calls = 0;
    for (;;) {
        struct json_value input, env;
        json_init(&input); json_set_object(&input);
        char wire[8193];
        enum zcl_command_exit rc;
        fb_native_test_table = &e->table;
        node_rpc_client_set_test_hook(fb_native_rpc);
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
            "fleet.wiki.list", "normal", 8192, 0, cursor[0] ? cursor : NULL,
            wire, sizeof(wire), &rc);
        node_rpc_client_set_test_hook(NULL); fb_native_test_table = NULL;
        json_free(&input);
        json_init(&env);
        g_fb_list_error[0] = '\0';
        if (n && json_read(&env, wire, strlen(wire)))
            (void)snprintf(g_fb_list_error, sizeof(g_fb_list_error), "%s",
                           json_get_str(json_get(json_get(&env, "error"), "code")));
        if (!n || rc != ZCL_COMMAND_EXIT_OK || ++*calls > 2000) { json_free(&env); return SIZE_MAX; }
        const struct json_value *data = json_get(&env, "data");
        const struct json_value *posts = json_get(data, "posts");
        for (size_t i = 0; i < json_size(posts); i++) {
            if (total == cap) { json_free(&env); return SIZE_MAX; }
            (void)snprintf(slugs[total++], FLEET_BOARD_SLUG_MAX + 1, "%s",
                           json_get_str(json_get(json_at(posts, i), "slug")));
        }
        const struct json_value *page = json_get(data, "_page");
        bool more = json_get_bool(json_get(page, "truncated"));
        if (json_get(page, "skipped_oversize_index")) { json_free(&env); return SIZE_MAX; }
        (void)snprintf(cursor, sizeof(cursor), "%lld", (long long)json_get_int(json_get(page, "next_cursor")));
        json_free(&env);
        if (!more) return total;
    }
}

static int test_fleet_wiki_list_reaches_every_page(void)
{
    int failures = 0;
    TEST("fleet wiki: list reaches every page past the per-call batch, in slug order, none skipped") {
        static struct fb_rpc_env e;
        static char slugs[400][FLEET_BOARD_SLUG_MAX + 1];
        const int pages = 300;
        const int64_t now = INT64_C(5000000);
        ASSERT(fb_rpc_env_open(&e));
        for (int i = 0; i < pages; i++) {
            uint8_t seed[32], pk[32];
            struct fleet_board_post p;
            fb_test_identity((uint8_t)(40 + i / 10), seed, pk);
            fb_test_compose(&p, FLEET_BOARD_KIND_WIKI, "scribe", "page body", (uint64_t)now, 3600);
            fb_test_scope(&p, FLEET_BOARD_SCOPE_PUBLIC, "general");
            (void)snprintf(p.slug, sizeof(p.slug), "page-%04d", i);
            (void)snprintf(p.title, sizeof(p.title), "Page %d", i);
            ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
            ASSERT_EQ(db_fleet_board_post_ingest(&e.db, &p, now, NULL), FLEET_BOARD_OK);
        }
        /* The node serves 256 slugs per call and says where to resume. */
        struct json_value r;
        ASSERT(fb_rpc_op(&e, "wiki_list", NULL, NULL, NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 256);
        ASSERT(json_get_bool(json_get(&r, "more")));
        ASSERT_STR_EQ(json_get_str(json_get(&r, "after_slug")), "page-0255");
        json_free(&r);
        ASSERT(fb_rpc_op(&e, "wiki_list", "after_slug", "page-0255", NULL, NULL, &r));
        ASSERT_EQ(json_get_int(json_get(&r, "returned")), 44);
        ASSERT(!json_get_bool(json_get(&r, "more")));
        json_free(&r);
        ASSERT(fb_rpc_op(&e, "wiki_list", "after_slug", "Bad Slug", NULL, NULL, &r));
        ASSERT_STR_EQ(json_get_str(json_get(&r, "code")), "BAD_AFTER");
        json_free(&r);
        /* The command's own cursor reaches all of them. */
        size_t calls;
        fb_native_wire_max = 1u << 20;
        size_t total = fb_list_walk(&e, slugs, 400, &calls);
        ASSERT_EQ((int64_t)total, pages);
        for (size_t j = 1; j < total; j++)
            ASSERT(strcmp(slugs[j - 1], slugs[j]) < 0);
        for (int i = 0; i < pages; i++) {
            char want[16];
            (void)snprintf(want, sizeof(want), "page-%04d", i);
            ASSERT_STR_EQ(slugs[i], want);
        }
        ASSERT(calls > 1);

        /* A node that reports no paging is refused by name, never listed short. */
        fb_native_legacy_list_paging = true;
        ASSERT(fb_list_walk(&e, slugs, 400, &calls) == SIZE_MAX);
        ASSERT(fb_list_last_error_is("NODE_VERSION_SKEW"));
        fb_native_legacy_list_paging = false;

        /* A list needing more node calls than the cap fails by name. */
        zcl_native_fleet_wiki_list_test_set_calls_max(1);
        ASSERT(fb_list_walk(&e, slugs, 400, &calls) == SIZE_MAX);
        ASSERT(fb_list_last_error_is("WIKI_INDEX_TOO_LARGE"));
        zcl_native_fleet_wiki_list_test_set_calls_max(0);
        fb_native_wire_max = 8192;
        fb_rpc_env_close(&e);
        PASS();
    } _test_next:;
    fb_native_wire_max = 8192;
    fb_native_legacy_list_paging = false;
    zcl_native_fleet_wiki_list_test_set_calls_max(0);
    return failures;
}

/* Run the PUBLIC-scope tests with the real gate installed, then restore the
 * permissive stub. */
static int test_fleet_board_public_no_grant_needed(void)
{
    int failures = 0;
    zcl_fleet_role_checker_install(NULL);
    failures += test_fleet_board_public_grant_free();
    failures += test_fleet_board_public_unknown_scope();
    failures += test_fleet_board_public_quota();
    failures += test_fleet_board_wiki_budget_is_separate();
    failures += test_fleet_board_wiki_stored_ceiling();
    failures += test_fleet_board_wiki_all_newest_refuses();
    failures += test_fleet_board_wiki_half_store_bound();
    failures += test_fleet_board_wiki_replacement_rules();
    failures += test_fleet_board_wiki_replacement_chain();
    failures += test_fleet_board_wiki_expired_evict();
    failures += test_fleet_board_wiki_replacement_rolls_back();
    failures += test_fleet_board_wiki_replacement_node_cap();
    failures += test_fleet_board_stored_ceilings_are_separate();
    failures += test_fleet_board_wiki_refusals_do_not_score_relay();
    failures += test_fleet_wiki_entry_validation();
    failures += test_fleet_wiki_backend_capability();
    failures += test_fleet_wiki_find_and_read();
    failures += test_fleet_wiki_entry_rejections();
    failures += test_fleet_wiki_chunks();
    failures += test_fleet_wiki_slug_budget();
    failures += test_fleet_wiki_chunk_grants();
    failures += test_fleet_wiki_write_grants();
    failures += test_fleet_wiki_write_lifecycle();
    failures += test_fleet_evidence_completion();
    failures += test_fleet_wiki_find_edges();
    failures += test_fleet_wiki_find_page_cap();
    failures += test_fleet_wiki_find_matched_fields();
    failures += test_fleet_wiki_list_is_an_index();
    failures += test_fleet_wiki_list_reaches_every_page();
    failures += test_fleet_board_write_refusal_reasons();
    failures += test_fleet_wiki_find_plain_pages();
    failures += test_fleet_wiki_query_cost();
    failures += test_fleet_wiki_query_envelopes();
    failures += test_fleet_board_quota_does_not_score_relay();
    failures += test_fleet_board_public_quota_counts_stored();
    failures += test_fleet_board_public_quota_window_counts_expired();
    failures += test_fleet_board_reclaim_keeps_burst_bound();
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* The paired pull's resume point is a file: after a simulated restart the
 * next pull asks where the file says, not from arrival 0. */
static int test_fleet_board_fleet_cursor_resumes(void)
{
    int failures = 0;
    static struct fbw w;
    static struct fleet_board_post posts[FBW_POSTS];
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-cursor-test" };
    char dir[512];
    size_t frames = 0;
    int64_t resumed = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    test_make_tmpdir(dir, sizeof(dir), "fleet_board", "cursor");
    boot_fleet_board_fleet_test_cursor_dir(dir);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: a restart resumes the paired pull from the "
         "saved cursor") {
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        for (int i = 0; i < FBW_POSTS; i++) {
            char text[48];
            (void)snprintf(text, sizeof(text), "resume note %d", i);
            ASSERT(fbw_post(&w.a, 11, FLEET_BOARD_SCOPE_FLEET, text,
                            2000 + i, 3600, 2100, &posts[i]));
        }
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        ASSERT_EQ(boot_fleet_board_fleet_test_last_after(), (int64_t)0);
        boot_fleet_board_fleet_test_restart_cursors();
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)(FBW_POSTS - FLEET_BOARD_FLEET_ANSWER_POSTS_MAX));
        resumed = boot_fleet_board_fleet_test_last_after();
        ASSERT(resumed > 0);
        ASSERT(fbw_holds_all(&w.b, posts, FBW_POSTS));
        PASS();
    }
    _test_next:
    boot_fleet_board_fleet_test_cursor_dir(NULL);
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* Post FBW_POSTS signed notes into the answering box's store. */
static bool fbw_seed_answerer(struct fbw *w, struct fleet_board_post *posts,
                              const char *tag)
{
    for (int i = 0; i < FBW_POSTS; i++) {
        char text[48];
        (void)snprintf(text, sizeof(text), "%s note %d", tag, i);
        if (!fbw_post(&w->a, 11, FLEET_BOARD_SCOPE_FLEET, text, 2000 + i,
                      3600, 2100, &posts[i]))
            return false;
    }
    return true;
}

/* A power cut keeps the fsynced cursor file but can roll back rows the WAL
 * store had committed. The next process must pull the lost rows again. */
static int test_fleet_board_fleet_cursor_heals_lost_rows(void)
{
    int failures = 0;
    static struct fbw w;
    static struct fleet_board_post posts[FBW_POSTS];
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-heal-test" };
    char dir[512];
    size_t frames = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    test_make_tmpdir(dir, sizeof(dir), "fleet_board", "heal");
    boot_fleet_board_fleet_test_cursor_dir(dir);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: rows lost behind a kept cursor are pulled "
         "again after a restart") {
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        ASSERT(fbw_seed_answerer(&w, posts, "heal"));
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames),
                  (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        /* The rollback: some stored rows vanish, the cursor file stays. */
        ASSERT(node_db_exec(&w.b, "DELETE FROM fleet_board_posts WHERE rowid "
                                  "IN (SELECT rowid FROM fleet_board_posts "
                                  "ORDER BY rowid LIMIT 5)"));
        ASSERT(!fbw_holds_all(&w.b, posts, FBW_POSTS));
        boot_fleet_board_fleet_test_restart_cursors();
        ASSERT(fbw_pull_n(&w, w.box_a, &w.b, 3) != SIZE_MAX);
        ASSERT(fbw_holds_all(&w.b, posts, FBW_POSTS));
        PASS();
    }
    _test_next:
    boot_fleet_board_fleet_test_cursor_dir(NULL);
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* Once every cursor slot is taken, a peer never seen before must still make
 * progress past its first page. */
static int test_fleet_board_fleet_cursor_table_full(void)
{
    int failures = 0;
    static struct fbw w;
    static struct fleet_board_post posts[FBW_POSTS];
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-full-test" };
    uint8_t newcomer[32];
    size_t frames = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);

    TEST("fleet board carriage: a new peer makes progress when all cursor "
         "slots are taken") {
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        for (unsigned i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX; i++) {
            uint8_t other[32];
            memset(other, (int)(i + 1u), sizeof other);
            ASSERT_EQ(fbw_pull(&w, other, &w.b, &frames), (size_t)0);
        }
        ASSERT(fbw_seed_answerer(&w, posts, "full"));
        memset(newcomer, 0xC3, sizeof newcomer);
        ASSERT(fbw_pull_n(&w, newcomer, &w.b, 2) != SIZE_MAX);
        ASSERT(fbw_holds_all(&w.b, posts, FBW_POSTS));
        PASS();
    }
    _test_next:
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* ── ZRC 0012 step 2: the fleet roster and its relay gate ────────────────
 *
 * The roster rows here are REAL operator-sealed machine lines (the codec
 * `fleet admit` writes), minted with real keys; the provider under test is
 * the production one. The one test double is in fbr_verify: the paired-peer
 * fixture's delegation carries an online key (0x44 bytes) nobody holds a
 * seed for, and a roster line must be signed by the key it names. So the
 * fixture stands the real test identity FBR_PEER in for that delegation key
 * AFTER the production verifier has checked the seal. */

#define FBR_ROOT 0x71          /* fleet root: a seed byte */
#define FBR_OTHER_ROOT 0x72    /* a different operator */
#define FBR_MEMBER 5           /* a member's board identity */
#define FBR_STRANGER 7         /* nobody's board identity */
#define FBR_PEER 9             /* stands for the paired peer's online key */
#define FBR_LINE_NOW INT64_C(1000000)

struct fbr_ctx {
    bool present;
    bool root_fail;
    bool manager;
    uint8_t root_pub[32];
    char lines[8][ZCL_FLEET_ROSTER_LINE_MAX];
    size_t n_lines;
    bool remap;
    uint8_t remap_from[32];
    uint8_t remap_to[32];
    struct zcl_fleet_head head; /* the test double's roster head */
};
static struct fbr_ctx g_fbr;

static void fbr_root_pub(uint8_t id, uint8_t seed[32], uint8_t pub[32])
{
    uint8_t secret[32];
    memset(seed, id, 32);
    ed25519_keypair(pub, secret, seed);
    memset(secret, 0, sizeof secret);
}

static bool fbr_root_cb(uint8_t root[32], bool *present, bool *manager,
                        void *ctx)
{
    (void)ctx;
    if (g_fbr.root_fail)
        return false;
    *present = g_fbr.present;
    *manager = g_fbr.manager;
    memcpy(root, g_fbr.root_pub, 32);
    return true;
}

static bool fbr_verify_cb(const char *line, const uint8_t root[32],
                          enum zcl_fleet_root_state state, bool require,
                          uint8_t signer[32], uint8_t box[32], bool *sealed,
                          const char **why,
                          void *ctx)
{
    (void)ctx;
    const struct zcl_fleet_roster_provider *real = zcl_fleet_roster_gate_provider();
    bool ok = real->verify(line, root, state, require, signer, box, sealed, why,
                           real->ctx);
    if (ok && g_fbr.remap && memcmp(signer, g_fbr.remap_from, 32) == 0)
        memcpy(signer, g_fbr.remap_to, 32);
    return ok;
}

static void fbr_head_cb(const uint8_t root[32], struct zcl_fleet_head *out,
                        void *ctx)
{
    (void)root;
    (void)ctx;
    *out = g_fbr.head;
}

static bool fbr_each_cb(void (*visit)(const char *line, void *user),
                        void *user, void *ctx)
{
    (void)ctx;
    for (size_t i = 0; i < g_fbr.n_lines; i++)
        visit(g_fbr.lines[i], user);
    return true;
}

static void fbr_install(uint8_t root_id, bool manager)
{
    uint8_t seed[32];
    static const struct zcl_fleet_roster_provider provider = {
        .root = fbr_root_cb, .verify = fbr_verify_cb, .head = fbr_head_cb,
        .each_line = fbr_each_cb, .ctx = NULL, .name = "fleet-board-test" };
    memset(&g_fbr, 0, sizeof g_fbr);
    g_fbr.present = true;
    g_fbr.manager = manager;
    fbr_root_pub(root_id, seed, g_fbr.root_pub);
    memset(seed, 0, sizeof seed);
    zcl_fleet_roster_provider_install(&provider);
    boot_fleet_roster_test_reset();
}

static void fbr_uninstall(void)
{
    zcl_fleet_roster_provider_install(NULL);
    memset(&g_fbr, 0, sizeof g_fbr);
    boot_fleet_roster_test_reset();
}

/* One sealed machine line: `root_id` seals a receipt for `name` whose board
 * signing key is test identity `signer_id`. */
static bool fbr_line(uint8_t root_id, const char *name, uint8_t signer_id,
                     char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts;
    struct fleet_signing_key signer;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    memset(&facts, 0, sizeof facts);
    (void)snprintf(facts.hostname, sizeof facts.hostname, "%s", name);
    fbr_root_pub(root_id, op_seed, op_pub);
    fbr_root_pub((uint8_t)(0x80 + signer_id), box_seed, box_pub);
    fb_test_identity(signer_id, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, 24, "", op_seed, op_pub, FBR_LINE_NOW,
                             token, sizeof token, &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof invite_wire,
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                              box_seed, box_pub, &signer, receipt,
                              sizeof receipt, &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof receipt_wire, &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FBR_LINE_NOW,
                              FLEET_ENROL_PORT_FIRST, op_seed, op_pub, out,
                              cap, &why);
}

/* Store one roster-shaped row (a fleet-scope note) in `db` straight through
 * the store's own ingest, as if it had been accepted earlier, authored by
 * test identity `author` and living `ttl` seconds. `id` (optional) receives
 * the row id. This deliberately skips the roster screen: the screen is what
 * the ingress tests prove, and these rows are how they plant junk. */
static bool fbr_store_row_id(struct node_db *db, uint8_t author,
                             const char *line, int64_t now, uint32_t ttl,
                             uint8_t id[32])
{
    uint8_t seed[32], pk[32];
    struct fleet_board_post p;
    fb_test_identity(author, seed, pk);
    fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_AGENT, line,
                    (uint64_t)now, ttl);
    fb_test_scope(&p, FLEET_BOARD_SCOPE_FLEET, "");
    bool ok = fleet_board_post_sign(&p, seed, pk) == FLEET_BOARD_OK &&
              db_fleet_board_post_ingest(db, &p, now, NULL) == FLEET_BOARD_OK;
    if (ok && id)
        memcpy(id, p.id, 32);
    boot_fleet_roster_invalidate();
    return ok;
}

static bool fbr_store_row(struct node_db *db, uint8_t author,
                          const char *line, int64_t now, uint32_t ttl)
{
    return fbr_store_row_id(db, author, line, now, ttl, NULL);
}

static bool fbr_member_row(struct node_db *db, uint8_t root_id,
                           const char *name, uint8_t signer_id, int64_t now)
{
    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
    return fbr_line(root_id, name, signer_id, line, sizeof line) &&
           fbr_store_row(db, 1, line, now, 3600);
}

static void fbr_key(uint8_t id, uint8_t pub[32])
{
    uint8_t seed[32];
    fb_test_identity(id, seed, pub);
    memset(seed, 0, sizeof seed);
}

static bool fbr_anchor(struct node_db *db, uint8_t root_id, const char *status)
{
    uint8_t seed[32];
    struct zid_identity identity;
    memset(&identity, 0, sizeof identity);
    fbr_root_pub(root_id, seed, identity.master_pubkey);
    memset(identity.anchor_txid, 0x77, 32);
    identity.anchor_height = 10;
    identity.updated_height = 10;
    if (strcmp(status, ZID_IDENTITY_STATUS_ROTATED) == 0) {
        identity.has_successor = true;
        memset(identity.successor_pubkey, 0x55, 32);
    }
    (void)snprintf(identity.status, sizeof identity.status, "%s", status);
    (void)snprintf(identity.source, sizeof identity.source, "%s",
                   ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    boot_fleet_roster_invalidate();
    return db_zid_identity_save(db, &identity);
}

static int test_fleet_board_roster_membership(void)
{
    int failures = 0;
    TEST("fleet roster: a row sealed by the fleet root names a member; a "
         "row sealed by any other key names nobody and does not arm the "
         "gate") {
        struct node_db db;
        uint8_t member[32], stranger[32];
        const int64_t now = 700000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_STRANGER, stranger);
        /* Nothing published: unarmed, so nothing is gated. */
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        /* A row sealed by ANOTHER operator: dropped, counted, arms nothing. */
        ASSERT(fbr_member_row(&db, FBR_OTHER_ROOT, "forged", FBR_STRANGER,
                              now));
        ASSERT_EQ(boot_fleet_roster_check(&db, stranger, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        struct boot_fleet_roster_counts counts;
        boot_fleet_roster_counts(&counts);
        ASSERT(counts.bad_rows >= 1);
        /* The fleet root's own row arms the gate and names its member. */
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&db, stranger, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        /* The all-zero key is never a member. */
        uint8_t zero[32] = {0};
        ASSERT_EQ(boot_fleet_roster_check(&db, zero, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        /* A later junk roster note cannot shadow the member: every stored
         * roster note is read. */
        ASSERT(fbr_store_row(&db, FBR_STRANGER, "not a sealed line", now + 5,
                             3600));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 5),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* A stranger who may post a note adds nobody by writing a
         * roster-looking row under their own key. */
        ASSERT(fbr_store_row(&db, FBR_STRANGER, "ZmFrZQ", now + 6, 3600));
        ASSERT_EQ(boot_fleet_roster_check(&db, stranger, now + 6),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* The operator-signed roster head: a revoked BOX key is dropped from the
 * roster the relay gate reads, a non-revoked box still is admitted, and a
 * head that cannot be trusted admits nobody. The revoked set names BOX keys
 * (the machine the operator admitted), while the roster holds each box's
 * board SIGNING key; the line ties the two, so revocation has to be applied
 * where the line is judged. */
static int test_fleet_board_roster_revoked_box(void)
{
    int failures = 0;
    TEST("fleet roster: a box the roster head revokes is not admitted, a "
         "box it does not revoke still is, and an untrusted head admits "
         "nobody") {
        struct node_db db;
        static struct fleet_status status;
        static struct fleet_board_post note;
        uint8_t revoked_signer[32], kept_signer[32], seed[32], held_id[32];
        const int64_t now = 900000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, revoked_signer);
        fbr_key(FBR_PEER, kept_signer);
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m9", FBR_PEER, now));
        /* No head: nothing is revoked, both are members (the old
         * behaviour), and the verified lines are now memoised. */
        ASSERT(boot_fleet_roster_admits_peer(&db, revoked_signer, now));
        ASSERT(boot_fleet_roster_admits_peer(&db, kept_signer, now));
        /* Armed: fleet status says the gate is deciding, and the flag that
         * turns it off says so too. */
        fleet_status_collect(&db, now, &status);
        ASSERT(status.roster_enforcing);
        ASSERT_EQ(status.roster_gate, BOOT_FLEET_ROSTER_GATE_DEFAULT);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        fleet_status_collect(&db, now, &status);
        ASSERT(!status.roster_enforcing);
        ASSERT_EQ(status.roster_gate, BOOT_FLEET_ROSTER_GATE_OFF);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        /* Something m5 wrote before it is revoked. */
        ASSERT(fbr_store_row_id(&db, FBR_MEMBER, "before the revocation", now,
                                3600, held_id));

        /* The head revokes m5's BOX key (fbr_line derives it from the
         * signer id). The memo must not carry m5 past it. */
        g_fbr.head.state = ZCL_FLEET_HEAD_OK;
        g_fbr.head.count = 1;
        fbr_root_pub((uint8_t)(0x80 + FBR_MEMBER), seed,
                     g_fbr.head.revoked[0]);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, revoked_signer, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        ASSERT(!boot_fleet_roster_admits_peer(&db, revoked_signer, now));
        ASSERT(boot_fleet_roster_admits_peer(&db, kept_signer, now));
        /* What m5 wrote stays; what it writes next does not get in. */
        ASSERT(db_fleet_board_have(&db, held_id));
        memset(&note, 0, sizeof note);
        note.kind = FLEET_BOARD_KIND_NOTE;
        note.scope = FLEET_BOARD_SCOPE_FLEET;
        memcpy(note.host_pubkey, revoked_signer, 32);
        ASSERT_EQ(boot_fleet_roster_screen_post(&db, &note, now),
                  FLEET_BOARD_ERR_ROLE);

        /* A head that exists and cannot be trusted is not "nothing
         * revoked": nobody is admitted. */
        g_fbr.head.state = ZCL_FLEET_HEAD_FAILED;
        g_fbr.head.count = 0;
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, kept_signer, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        ASSERT(!boot_fleet_roster_admits_peer(&db, kept_signer, now));
        ASSERT(!boot_fleet_roster_admits_peer(&db, revoked_signer, now));

        /* Repaired or removed: both are members again. */
        memset(&g_fbr.head, 0, sizeof g_fbr.head);
        boot_fleet_roster_invalidate();
        ASSERT(boot_fleet_roster_admits_peer(&db, revoked_signer, now));
        ASSERT(boot_fleet_roster_admits_peer(&db, kept_signer, now));
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_roster_root_standing(void)
{
    int failures = 0;
    TEST("fleet roster: a revoked or rotated root invalidates the roster "
         "(no fleet relay at all); an active or never-anchored root does "
         "not") {
        struct node_db db;
        uint8_t member[32];
        const int64_t now = 800000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        /* Never anchored: tolerated, as step 1 tolerates it. */
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_ACTIVE));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* Rotated away: the seal is genuine and the roster is still dead. */
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_ROTATED));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        ASSERT(!boot_fleet_roster_admits_peer(&db, member, now));
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_REVOKED));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        struct boot_fleet_roster_counts counts;
        boot_fleet_roster_counts(&counts);
        ASSERT(counts.unverifiable >= 1);
        /* A recorded root that cannot be read closes the gate: no fleet
         * relay, and no pretence that the roster is simply absent. */
        g_fbr.root_fail = true;
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        g_fbr.root_fail = false;
        boot_fleet_roster_invalidate();
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_ACTIVE));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Corrupt a saved anchor's status to a value the reader does not know, so the
 * real read path maps it to UNREADABLE. The status column is TEXT NOT NULL
 * with no CHECK constraint, so the raw UPDATE is accepted. */
static bool fbr_corrupt_status(struct node_db *db, uint8_t root_id)
{
    uint8_t seed[32], pub[32];
    char sql[192];
    fbr_root_pub(root_id, seed, pub);
    memset(seed, 0, sizeof seed);
    size_t off = (size_t)snprintf(sql, sizeof sql, "%s",
        "UPDATE zid_identities SET status='bogus' WHERE master_pubkey=X'");
    for (int i = 0; i < 32; i++)
        off += (size_t)snprintf(sql + off, sizeof sql - off, "%02x", pub[i]);
    (void)snprintf(sql + off, sizeof sql - off, "'");
    boot_fleet_roster_invalidate();
    return node_db_exec(db, sql);
}

/* A root rotated, revoked or unreadable on chain refuses fleet-scope relay
 * even when no roster note is live: an empty roster and a roster whose only
 * note has expired are both refused, never UNARMED. An active root with an
 * empty roster stays unarmed, and public scope is never consulted here. */
static int test_fleet_board_roster_refused_root_no_notes(void)
{
    int failures = 0;
    TEST("fleet roster: a rotated, revoked or unreadable root refuses fleet "
         "relay with no live roster note (empty, or only expired); an active "
         "root with no notes stays unarmed; public scope is admitted") {
        struct node_db db;
        uint8_t member[32];
        const int64_t now = 900000;
        /* Index 2 is saved ACTIVE and then corrupted to an unknown status:
         * UNREADABLE. */
        static const char *const bad[] = {
            ZID_IDENTITY_STATUS_REVOKED, ZID_IDENTITY_STATUS_ROTATED,
            ZID_IDENTITY_STATUS_ACTIVE };
        fbr_key(FBR_MEMBER, member);
        for (int s = 0; s < 3; s++) {
            for (int expired = 0; expired < 2; expired++) {
                memset(&db, 0, sizeof db);
                ASSERT(node_db_open(&db, ":memory:"));
                fbr_install(FBR_ROOT, false);
                if (expired) {
                    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
                    ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line,
                                    sizeof line));
                    ASSERT(fbr_store_row(&db, 1, line, now, 60));
                }
                ASSERT(fbr_anchor(&db, FBR_ROOT, bad[s]));
                if (s == 2)
                    ASSERT(fbr_corrupt_status(&db, FBR_ROOT));
                struct boot_fleet_roster_counts before, after;
                boot_fleet_roster_counts(&before);
                ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 600),
                          BOOT_FLEET_ROSTER_UNVERIFIABLE);
                ASSERT(!boot_fleet_roster_admits_peer(&db, member, now + 600));
                boot_fleet_roster_counts(&after);
                ASSERT(after.unverifiable > before.unverifiable);
                fbr_uninstall();
                node_db_close(&db);
            }
        }
        /* An active root with no notes is still unarmed, and admits. */
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_ACTIVE));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        ASSERT(boot_fleet_roster_admits_peer(&db, member, now));
        /* Public scope never reaches the roster: a revoked root still admits
         * a public post. */
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_REVOKED));
        struct fleet_board_post pub;
        memset(&pub, 0, sizeof pub);
        pub.scope = FLEET_BOARD_SCOPE_PUBLIC;
        ASSERT(boot_fleet_roster_admits_post(&db, &pub, now));
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_roster_lifetime(void)
{
    int failures = 0;
    TEST("fleet roster: a roster note keeps its member through the reclaim "
         "for its whole life, then the roster lapses to unarmed (today's "
         "gate), never to a wider one") {
        struct node_db db;
        uint8_t member[32];
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        const int64_t now = 1000000;
        const int64_t later = now + 3 * 86400;
        const int64_t gone = now + (int64_t)FLEET_BOARD_TTL_MAX + 4000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        ASSERT(fbr_store_row(&db, 1, line, now, FLEET_BOARD_TTL_MAX));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, later),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* The maintenance reclaim takes expired discussion posts back; a
         * live roster note is not one. */
        ASSERT_EQ(db_fleet_board_reclaim_expired(&db, later, NULL),
                  FLEET_BOARD_RECLAIM_DONE);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, later),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* Nobody republished it: past its TTL the roster is gone and the
         * gate is UNARMED, which is the pairing-plus-role behaviour. */
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, gone),
                  BOOT_FLEET_ROSTER_UNARMED);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Revocation is persistent: it does not depend on a live roster note. When
 * every note has expired the gate falls back to UNARMED (today's pairing
 * behaviour), and a key the trusted head revokes is still refused there. */
static int test_fleet_board_roster_revoked_after_lapse(void)
{
    int failures = 0;
    TEST("fleet roster: after the roster notes expire, a key the trusted "
         "head revokes is still refused in the UNARMED fallback and any "
         "other key behaves as before") {
        struct node_db db;
        uint8_t member[32], other[32], box[32], seed[32];
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        const int64_t now = 1000000;
        const int64_t gone = now + (int64_t)FLEET_BOARD_TTL_MAX + 4000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_PEER, other);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        ASSERT(fbr_store_row(&db, 1, line, now, FLEET_BOARD_TTL_MAX));
        /* What the real mint produces for a revoked box: the BOX key and the
         * SIGNER key its roster row binds to it. Callers present the signer. */
        fbr_root_pub((uint8_t)(0x80 + FBR_MEMBER), seed, box);
        g_fbr.head.state = ZCL_FLEET_HEAD_OK;
        g_fbr.head.count = 1;
        memcpy(g_fbr.head.revoked[0], member, 32); /* signer only, live row */
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        g_fbr.head.count = 2;
        memcpy(g_fbr.head.revoked[1], box, 32);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, gone),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, other, gone),
                  BOOT_FLEET_ROSTER_UNARMED);
        /* A restart with every note lapsed rebuilds from stored state only;
         * the head still refuses the signer. */
        boot_fleet_roster_test_reset();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, gone),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&db, other, gone),
                  BOOT_FLEET_ROSTER_UNARMED);
        /* A head naming only the box (no signer counterpart) still refuses
         * its live row, so the signer is not a member. */
        g_fbr.head.count = 1;
        memcpy(g_fbr.head.revoked[0], box, 32);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fleet_board_roster_bounds(void)
{
    int failures = 0;
    TEST("fleet roster: the roster size and the row size are bounded") {
        struct node_db db;
        uint8_t seed[32], sink[32];
        const int64_t now = 900000;
        char huge[ZCL_FLEET_ROSTER_LINE_MAX + 8];
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        /* A note past the board's text bound cannot carry a roster row at
         * all; one that fits but is not sealed is counted bad and arms
         * nothing. */
        memset(huge, 'A', sizeof huge);
        huge[FLEET_BOARD_TEXT_MAX + 1] = '\0';
        {
            struct fleet_board_post too_long;
            fb_test_compose(&too_long, FLEET_BOARD_KIND_NOTE,
                            BOOT_FLEET_ROSTER_AGENT, "x", 1000, 3600);
            ASSERT(strlen(huge) > FLEET_BOARD_TEXT_MAX);
            memcpy(too_long.text, huge, strlen(huge) + 1u);
            too_long.text_len = (uint32_t)strlen(huge);
            fb_test_scope(&too_long, FLEET_BOARD_SCOPE_FLEET, "");
            ASSERT_EQ(fleet_board_post_validate(&too_long),
                      FLEET_BOARD_ERR_TEXT);
        }
        huge[FLEET_BOARD_TEXT_MAX - 8] = '\0';
        ASSERT(fbr_store_row(&db, 1, huge, now, 3600));
        fbr_key(FBR_MEMBER, sink);
        ASSERT_EQ(boot_fleet_roster_check(&db, sink, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        /* More members than the roster holds: the first
         * BOOT_FLEET_ROSTER_MAX keys are kept, the rest are not admitted. */
        for (int i = 0; i < BOOT_FLEET_ROSTER_MAX + 2; i++) {
            char name[16], line[FLEET_ENROL_MACHINE_TEXT_MAX];
            (void)snprintf(name, sizeof name, "box-%d", i);
            /* Test identities 100.. are distinct board keys. */
            ASSERT(fbr_line(FBR_ROOT, name, (uint8_t)(100 + i), line,
                            sizeof line));
            ASSERT(fbr_store_row(&db, (uint8_t)(30 + i / 10), line, now + i,
                                 3600));
        }
        size_t admitted = 0;
        for (int i = 0; i < BOOT_FLEET_ROSTER_MAX + 2; i++) {
            uint8_t pub[32];
            fb_test_identity((uint8_t)(100 + i), seed, pub);
            if (boot_fleet_roster_check(&db, pub, now + 200) ==
                BOOT_FLEET_ROSTER_MEMBER)
                admitted++;
        }
        ASSERT_EQ(admitted, (size_t)BOOT_FLEET_ROSTER_MAX);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* A raw P2P POST frame from `who`. */
static bool fbr_post_frame(struct fleet_board_post *p, uint8_t who,
                           uint8_t scope, const char *text, int64_t now,
                           uint8_t *frame, size_t cap, size_t *len)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(p, FLEET_BOARD_KIND_NOTE, "roster-fixture", text,
                    (uint64_t)now, 3600);
    fb_test_scope(p, scope, scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    return fleet_board_post_sign(p, seed, pk) == FLEET_BOARD_OK &&
           fleet_board_frame_encode_post(p, frame, cap, len) ==
               FLEET_BOARD_OK;
}

static int test_fleet_board_roster_p2p_ingress(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db;
    memset(&db, 0, sizeof db);
    TEST("fleet roster: with an armed roster a non-member's fleet post is "
         "not accepted and costs the relay nothing; a member's, a public "
         "one and a pre-scope one all are") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t len = 0;
        struct fleet_board_post from_stranger, from_member, public_post, legacy;
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        struct boot_svc_ctx svc;
        peer_scoring_init();
        memset(&nm, 0, sizeof nm);
        memset(&mp, 0, sizeof mp);
        memset(&svc, 0, sizeof svc);
        memset(&node, 0, sizeof node);
        mp.net_mgr = &nm;
        svc.node_db = &db;
        svc.msg_processor = &mp;
        node.id = 52;
        (void)snprintf(node.addr_name, sizeof node.addr_name, "%s", "roster-fx");
        node.addr.svc.addr.ip[10] = 0xff;
        node.addr.svc.addr.ip[11] = 0xff;
        node.addr.svc.addr.ip[12] = 198;
        node.addr.svc.addr.ip[13] = 51;
        node.addr.svc.addr.ip[14] = 100;
        node.addr.svc.addr.ip[15] = 9;
        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        boot_fleet_board_wire(&svc);
        fbr_install(FBR_ROOT, false);

        /* Unarmed: the stranger's fleet post lands, exactly as before. */
        ASSERT(fbr_post_frame(&from_stranger, FBR_STRANGER,
                              FLEET_BOARD_SCOPE_FLEET, "before the roster",
                              now, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, from_stranger.id));

        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        int score = atomic_load(&node.misbehavior);

        ASSERT(fbr_post_frame(&from_stranger, FBR_STRANGER,
                              FLEET_BOARD_SCOPE_FLEET, "after the roster",
                              now + 1, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(!db_fleet_board_have(&db, from_stranger.id));
        ASSERT_EQ(atomic_load(&node.misbehavior), score);

        ASSERT(fbr_post_frame(&from_member, FBR_MEMBER,
                              FLEET_BOARD_SCOPE_FLEET, "from a member",
                              now + 1, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, from_member.id));

        /* Public scope is untouched by the roster, even from a stranger. */
        ASSERT(fbr_post_frame(&public_post, FBR_STRANGER,
                              FLEET_BOARD_SCOPE_PUBLIC, "public as ever",
                              now + 1, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, public_post.id));

        /* An old-format (pre-scope, v1) row is still accepted. */
        ASSERT(fbr_post_frame(&legacy, FBR_STRANGER,
                              FLEET_BOARD_SCOPE_LEGACY_PUBLIC, "pre-scope",
                              now + 1, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, legacy.id));
        ASSERT_EQ(atomic_load(&node.misbehavior), score);

        /* Fail closed: once the root is revoked even a member's fleet post
         * is not accepted, and public scope still is. */
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_REVOKED));
        ASSERT(fbr_post_frame(&from_member, FBR_MEMBER,
                              FLEET_BOARD_SCOPE_FLEET, "after revocation",
                              now + 2, frame, sizeof frame, &len));
        ASSERT(boot_fleet_board_frame(&mp, &node, frame, len, NULL));
        ASSERT(!db_fleet_board_have(&db, from_member.id));
        PASS();
    } _test_next:;
    fbr_uninstall();
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    return failures;
}

/* A roster row is an ordinary signed fleet note: the unchanged v2
 * codec round-trips and verifies it, so a node that predates the roster
 * stores it as the note it is. */
static int test_fleet_board_roster_row_is_an_old_row(void)
{
    int failures = 0;
    TEST("fleet roster: a roster row is an ordinary fleet note "
         "the unchanged codec verifies") {
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t seed[32], pk[32], wire[FLEET_BOARD_BODY_MAX + 128];
        struct fleet_board_post p, decoded;
        size_t wire_len = 0;
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        ASSERT(strlen(line) < ZCL_FLEET_ROSTER_LINE_MAX);
        fb_test_identity(1, seed, pk);
        fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_AGENT,
                        line, 1000, 3600);
        fb_test_scope(&p, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_sign(&p, seed, pk), FLEET_BOARD_OK);
        ASSERT(boot_fleet_roster_is_row(&p));
        ASSERT_EQ(fleet_board_post_encode(&p, wire, sizeof wire, &wire_len),
                  FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_decode(wire, wire_len, &decoded),
                  FLEET_BOARD_OK);
        ASSERT_EQ(decoded.kind, FLEET_BOARD_KIND_NOTE);
        ASSERT_EQ(decoded.scope, FLEET_BOARD_SCOPE_FLEET);
        PASS();
    } _test_next:;
    return failures;
}

/* The manager publishes its own sealed roster onto the board, once. */
static int test_fleet_board_roster_publish(void)
{
    int failures = 0;
    struct fb_rpc_env env;
    bool open = false;
    char dir[256] = {0};
    TEST("fleet roster: the manager publishes each sealed line once, "
         "re-publishes only a changed one, and a non-manager publishes "
         "nothing") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t member[32];
        open = fb_rpc_env_open(&env);
        ASSERT(open);
        test_make_tmpdir(dir, sizeof dir, "fleet_board", "roster");
        env.svc.datadir = dir;
        fbr_install(FBR_ROOT, true);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        fbr_key(FBR_MEMBER, member);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, g_fbr.lines[0],
                        sizeof g_fbr.lines[0]));
        ASSERT(fbr_line(FBR_OTHER_ROOT, "alien", FBR_STRANGER, g_fbr.lines[1],
                        sizeof g_fbr.lines[1]));
        g_fbr.n_lines = 2;
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)1);
        ASSERT_EQ(boot_fleet_roster_check(&env.db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* Nothing changed: nothing written. */
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now + 60), (size_t)0);
        /* The same machine re-admitted under a changed line: one new note. */
        ASSERT(fbr_line(FBR_ROOT, "m5-renamed", FBR_MEMBER, g_fbr.lines[0],
                        sizeof g_fbr.lines[0]));
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now + 90), (size_t)1);
        /* A young live copy is left alone; an old one is written again
         * before it can lapse. */
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now + 120), (size_t)0);
        ASSERT_EQ(boot_fleet_roster_publish(
                      &env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 100),
                  (size_t)1);
        /* A box that is not the root's own box publishes nothing. */
        g_fbr.manager = false;
        ASSERT(fbr_line(FBR_ROOT, "m6", FBR_STRANGER, g_fbr.lines[2],
                        sizeof g_fbr.lines[2]));
        g_fbr.n_lines = 3;
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 200), (size_t)0);
        /* The local RPC is an ingest path too: a roster-shaped note that the
         * root did not seal is refused and not stored. */
        {
            struct fleet_board_post junk;
            fb_test_compose(&junk, FLEET_BOARD_KIND_NOTE,
                            BOOT_FLEET_ROSTER_AGENT, "not a sealed line",
                            (uint64_t)now, 3600);
            fb_test_scope(&junk, FLEET_BOARD_SCOPE_FLEET, "");
            ASSERT_EQ(boot_fleet_board_publish(&junk, now),
                      FLEET_BOARD_ERR_SIGNATURE);
            ASSERT(!db_fleet_board_have(&env.db, junk.id));
        }
        PASS();
    } _test_next:;
    fbr_uninstall();
    if (open)
        fb_rpc_env_close(&env);
    if (dir[0])
        test_rm_rf_recursive(dir);
    return failures;
}

/* A one-peer P2P ingress rig over `db`. */
struct fbr_p2p {
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node node;
    struct boot_svc_ctx svc;
};

static void fbr_p2p_init(struct fbr_p2p *x, struct node_db *db, int64_t id)
{
    peer_scoring_init();
    memset(x, 0, sizeof *x);
    x->mp.net_mgr = &x->nm;
    x->svc.node_db = db;
    x->svc.msg_processor = &x->mp;
    x->node.id = id;
    (void)snprintf(x->node.addr_name, sizeof x->node.addr_name, "%s",
                   "roster-fx");
    x->node.addr.svc.addr.ip[10] = 0xff;
    x->node.addr.svc.addr.ip[11] = 0xff;
    x->node.addr.svc.addr.ip[12] = 198;
    x->node.addr.svc.addr.ip[13] = 51;
    x->node.addr.svc.addr.ip[14] = 100;
    x->node.addr.svc.addr.ip[15] = (uint8_t)id;
}

enum fb_review_ingress_object {
    FB_REVIEW_TARGET, FB_REVIEW_ROOT, FB_REVIEW_LEFT, FB_REVIEW_RIGHT,
    FB_REVIEW_OPPOSITE, FB_REVIEW_OBJECTS
};

static bool fb_review_ingress_sign(struct fleet_board_post *post, uint8_t who)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    post->ttl = 3600;
    return fleet_board_post_sign(post, seed, pk) == FLEET_BOARD_OK;
}

static bool fb_review_ingress_compose(struct fleet_board_post *p, uint64_t now)
{
    fb_test_compose(&p[FB_REVIEW_TARGET], FLEET_BOARD_KIND_WIKI, "author",
                    "immutable ingress target", now - 4, 3600);
    p[FB_REVIEW_TARGET].scope = FLEET_BOARD_SCOPE_PUBLIC;
    (void)snprintf(p[FB_REVIEW_TARGET].room, sizeof(p[FB_REVIEW_TARGET].room),
                   "%s", FLEET_BOARD_ROOM_DEFAULT);
    (void)snprintf(p[FB_REVIEW_TARGET].slug, sizeof(p[FB_REVIEW_TARGET].slug),
                   "peer-reviewed-page");
    (void)snprintf(p[FB_REVIEW_TARGET].title, sizeof(p[FB_REVIEW_TARGET].title),
                   "Reviewed ingress bytes");
    if (!fb_review_ingress_sign(&p[FB_REVIEW_TARGET], 30)) return false;
    return fb_review_compose(&p[FB_REVIEW_ROOT], 31, p[FB_REVIEW_TARGET].id,
               NULL, "approve", "initial", now - 3) &&
           fb_review_ingress_sign(&p[FB_REVIEW_ROOT], 31) &&
           fb_review_compose(&p[FB_REVIEW_LEFT], 31, p[FB_REVIEW_TARGET].id,
               p[FB_REVIEW_ROOT].id, "approve", "left branch", now - 1) &&
           fb_review_ingress_sign(&p[FB_REVIEW_LEFT], 31) &&
           fb_review_compose(&p[FB_REVIEW_RIGHT], 31, p[FB_REVIEW_TARGET].id,
               p[FB_REVIEW_ROOT].id, "request-changes", "right branch", now - 2) &&
           fb_review_ingress_sign(&p[FB_REVIEW_RIGHT], 31) &&
           fb_review_compose(&p[FB_REVIEW_OPPOSITE], 32, p[FB_REVIEW_TARGET].id,
               NULL, "request-changes", "independent reviewer", now) &&
           fb_review_ingress_sign(&p[FB_REVIEW_OPPOSITE], 32);
}

static bool fb_review_ingress_stored(struct node_db *db,
    const struct fleet_board_post *post, const uint8_t *frame, size_t frame_len,
    int64_t expected_rows)
{
    struct db_fleet_board_post row;
    uint8_t stored_frame[FLEET_BOARD_FRAME_MAX];
    size_t stored_len = 0;
    int64_t checked = 0;
    return db_fleet_board_post_find(db, post->id, &row) &&
           fleet_board_frame_encode_post(&row.post, stored_frame,
               sizeof(stored_frame), &stored_len) == FLEET_BOARD_OK &&
           stored_len == frame_len && !memcmp(stored_frame, frame, frame_len) &&
           db_fleet_board_chain_verify(db, &checked) && checked == expected_rows;
}

/* This fixture crosses the production POST handler, not a direct DB import.
 * Wire one receiver at a time because the board's service pointer is global. */
static bool fb_review_ingress_post(struct fbr_p2p *peer,
    const struct fleet_board_post *post, int64_t expected_rows)
{
    uint8_t frame[FLEET_BOARD_FRAME_MAX];
    size_t frame_len = 0;
    if (fleet_board_frame_encode_post(post, frame, sizeof(frame), &frame_len) !=
        FLEET_BOARD_OK) return false;
    int score = atomic_load(&peer->node.misbehavior);
    boot_fleet_board_wire(&peer->svc);
    bool ok = true;
    for (unsigned replay = 0; replay < 2 && ok; replay++)
        ok = boot_fleet_board_frame(&peer->mp, &peer->node, frame, frame_len,
                                    NULL) &&
             fb_review_ingress_stored(peer->svc.node_db, post, frame, frame_len,
                                       expected_rows);
    boot_fleet_board_shutdown();
    return ok && atomic_load(&peer->node.misbehavior) == score &&
           !peer->node.disconnect;
}

static bool fb_review_ingress_state(struct node_db *db,
    const struct fleet_board_post *post,
    const struct fleet_wiki_review_state *expected)
{
    struct fleet_wiki_review_state state;
    return db_fleet_board_review_state(db, post, &state) &&
           state.resolved == expected->resolved &&
           state.lineage_valid == expected->lineage_valid &&
           state.current == expected->current &&
           state.complete == expected->complete && state.fork == expected->fork;
}

static bool fb_review_ingress_children(struct fbr_p2p *peer,
    const struct fleet_board_post *posts, const unsigned order[3])
{
    for (size_t i = 0; i < 3; i++)
        if (!fb_review_ingress_post(peer, &posts[order[i]], (int64_t)i + 1))
            return false;
    const struct fleet_wiki_review_state missing_target_and_parent = {0};
    return fb_review_ingress_state(peer->svc.node_db, &posts[FB_REVIEW_LEFT],
                                   &missing_target_and_parent);
}

static bool fb_review_ingress_equal(struct node_db *a, struct node_db *b,
    const struct fleet_board_post *posts)
{
    for (size_t i = 0; i < FB_REVIEW_OBJECTS; i++) {
        uint8_t frame[FLEET_BOARD_FRAME_MAX];
        size_t frame_len = 0;
        if (fleet_board_frame_encode_post(&posts[i], frame, sizeof(frame),
                &frame_len) != FLEET_BOARD_OK ||
            !fb_review_ingress_stored(a, &posts[i], frame, frame_len,
                                       FB_REVIEW_OBJECTS) ||
            !fb_review_ingress_stored(b, &posts[i], frame, frame_len,
                                       FB_REVIEW_OBJECTS)) return false;
    }
    return true;
}

static int test_fleet_wiki_review_post_ingress_convergence(void)
{
    int failures = 0;
    struct node_db a = {0}, b = {0};
    static struct fbr_p2p peers[2];
    struct fleet_board_post posts[FB_REVIEW_OBJECTS];
    TEST("fleet wiki reviews: production POST ingress retains late targets, "
         "parents, opposing opinions and forks exactly once") {
        ASSERT(node_db_open(&a, ":memory:"));
        ASSERT(node_db_open(&b, ":memory:"));
        uint64_t now = (uint64_t)platform_time_wall_time_t();
        ASSERT(now > 4);
        ASSERT(fb_review_ingress_compose(posts, now));
        fbr_p2p_init(&peers[0], &a, 61);
        fbr_p2p_init(&peers[1], &b, 62);
        const unsigned order_a[] = {
            FB_REVIEW_LEFT, FB_REVIEW_OPPOSITE, FB_REVIEW_RIGHT};
        const unsigned order_b[] = {
            FB_REVIEW_RIGHT, FB_REVIEW_LEFT, FB_REVIEW_OPPOSITE};
        ASSERT(fb_review_ingress_children(&peers[0], posts, order_a));
        ASSERT(fb_review_ingress_children(&peers[1], posts, order_b));
        ASSERT(fb_review_ingress_post(&peers[0], &posts[FB_REVIEW_TARGET], 4));
        const struct fleet_wiki_review_state missing_parent = {
            .resolved = true, .lineage_valid = false, .current = false,
            .complete = false, .fork = false};
        ASSERT(fb_review_ingress_state(&a, &posts[FB_REVIEW_LEFT],
                                       &missing_parent));
        ASSERT(fb_review_ingress_post(&peers[1], &posts[FB_REVIEW_ROOT], 4));
        const struct fleet_wiki_review_state missing_target = {
            .resolved = false, .lineage_valid = true, .current = true,
            .complete = true, .fork = true};
        ASSERT(fb_review_ingress_state(&b, &posts[FB_REVIEW_LEFT],
                                       &missing_target));
        ASSERT(fb_review_ingress_post(&peers[0], &posts[FB_REVIEW_ROOT], 5));
        ASSERT(fb_review_ingress_post(&peers[1], &posts[FB_REVIEW_TARGET], 5));
        ASSERT(fb_review_converged_views(&a, &posts[FB_REVIEW_ROOT],
            &posts[FB_REVIEW_LEFT], &posts[FB_REVIEW_RIGHT],
            &posts[FB_REVIEW_OPPOSITE]));
        ASSERT(fb_review_converged_views(&b, &posts[FB_REVIEW_ROOT],
            &posts[FB_REVIEW_LEFT], &posts[FB_REVIEW_RIGHT],
            &posts[FB_REVIEW_OPPOSITE]));
        ASSERT(fb_review_ingress_equal(&a, &b, posts));
        PASS();
    } _test_next:;
    boot_fleet_board_shutdown();
    if (a.open) node_db_close(&a);
    if (b.open) node_db_close(&b);
    return failures;
}

/* A raw P2P POST frame carrying a roster-shaped note from `who`. */
static bool fbr_row_frame(struct fleet_board_post *p, uint8_t who,
                          const char *text, int64_t now, uint8_t *frame,
                          size_t cap, size_t *len)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_AGENT, text,
                    (uint64_t)now, 3600);
    fb_test_scope(p, FLEET_BOARD_SCOPE_FLEET, "");
    return fleet_board_post_sign(p, seed, pk) == FLEET_BOARD_OK &&
           fleet_board_frame_encode_post(p, frame, cap, len) ==
               FLEET_BOARD_OK;
}

/* A roster row is stored only if its seal verifies: a junk or foreign-sealed
 * one is refused on the P2P path, whoever posts it, and costs the cache
 * nothing. */
static int test_fleet_board_roster_ingress_seal(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db;
    static struct fbr_p2p x;
    memset(&db, 0, sizeof db);
    TEST("fleet roster ingress: a junk or foreign-sealed roster row posted "
         "by a member or a non-member is refused and not stored, leaves the "
         "cached roster alone, and a sealed row is stored and verified once") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t len = 0;
        struct fleet_board_post p;
        char foreign[FLEET_ENROL_MACHINE_TEXT_MAX];
        char genuine[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t member[32], newcomer[32];
        struct boot_fleet_roster_counts c0, c1;
        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        fbr_p2p_init(&x, &db, 53);
        boot_fleet_board_wire(&x.svc);
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c0);
        int score = atomic_load(&x.node.misbehavior);
        ASSERT(fbr_line(FBR_OTHER_ROOT, "alien", FBR_STRANGER, foreign,
                        sizeof foreign));
        const char *junk[] = { "not a sealed line", "ZmFrZQ", foreign };
        const uint8_t who[] = { FBR_STRANGER, FBR_MEMBER };
        int sent = 0;
        for (size_t w = 0; w < 2; w++)
            for (size_t j = 0; j < 3; j++) {
                ASSERT(fbr_row_frame(&p, who[w], junk[j], now + sent++, frame,
                                     sizeof frame, &len));
                ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len,
                                              NULL));
                ASSERT(!db_fleet_board_have(&db, p.id));
            }
        ASSERT_EQ(atomic_load(&x.node.misbehavior), score);
        /* Not one of them dropped the cache. */
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.rebuilds, c0.rebuilds);
        ASSERT_EQ(c1.bad_rows, c0.bad_rows + 6);
        /* Six refusals, one log line: the rest are counted. */
        uint64_t skipped = 0;
        ASSERT(boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_POST_DROPPED,
                                         now + 1000, &skipped));
        ASSERT_EQ(skipped, (uint64_t)5);

        /* A genuinely sealed row is stored, whoever carries it, and the
         * cache is dropped once. */
        fbr_key(11, newcomer);
        ASSERT(fbr_line(FBR_ROOT, "m11", 11, genuine, sizeof genuine));
        ASSERT(fbr_row_frame(&p, FBR_STRANGER, genuine, now + 20, frame,
                             sizeof frame, &len));
        boot_fleet_roster_counts(&c0);
        ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, p.id));
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies + 1);
        ASSERT_EQ(boot_fleet_roster_check(&db, newcomer, now + 20),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* The same frame again costs no second verify. */
        boot_fleet_roster_counts(&c0);
        ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies);
        PASS();
    } _test_next:;
    fbr_uninstall();
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    return failures;
}

/* `n` rows holding `text`, each newer than the last, stored straight as colluding
 * keys or a store from before the ingest rule would hold them. Several authors,
 * so the per-key window is not what limits the page. */
static bool fbr_flood(struct node_db *db, const char *text, int64_t from, int n)
{
    for (int i = 0; i < n; i++)
        if (!fbr_store_row(db, (uint8_t)(40 + i / 50), text, from + i,
                           FLEET_BOARD_TTL_MAX))
            return false;
    return true;
}

/* One roster row on the way in: the screen every path runs, then the store. */
static enum fleet_board_result fbr_offer(struct node_db *db, uint8_t author,
                                         const char *text, int64_t at,
                                         struct fleet_board_post *p)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(author, seed, pk);
    fb_test_compose(p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_AGENT, text,
                    (uint64_t)at, FLEET_BOARD_TTL_MAX);
    fb_test_scope(p, FLEET_BOARD_SCOPE_FLEET, "");
    enum fleet_board_result r = fleet_board_post_sign(p, seed, pk);
    if (r == FLEET_BOARD_OK)
        r = boot_fleet_roster_screen_post(db, p, at);
    if (r == FLEET_BOARD_OK)
        r = db_fleet_board_post_ingest(db, p, at, NULL);
    return r;
}

/* Copies of a genuine line, however many there are, leave every older line in
 * the scan: this is the page the flood used to fill. */
static int test_fleet_board_roster_flood_scan(void)
{
    int failures = 0;
    TEST("fleet roster flood: a page of newer sealed copies displaces no "
         "member, and the copies cost one verify") {
        struct node_db db;
        uint8_t member[32], peer[32], flooder[32];
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct boot_fleet_roster_counts c0, c1;
        const int64_t now = 1300000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_PEER, peer);
        fbr_key(FBR_STRANGER, flooder);
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m9", FBR_PEER, now));
        ASSERT(fbr_line(FBR_ROOT, "m7", FBR_STRANGER, line, sizeof line));
        ASSERT(fbr_flood(&db, line, now + 100, BOOT_FLEET_ROSTER_SCAN_ROWS + 44));
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 1000),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&db, peer, now + 1000),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&db, flooder, now + 1000),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies + 3);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* The way in: one key gets a small fixed number of rows per line, a refused
 * copy costs no verify and drops no cache, and a republish after the interval
 * still lands, off the real P2P frame path. */
static int test_fleet_board_roster_flood_ingest(void)
{
    int failures = 0;
    bool db_open = false;
    struct node_db db;
    static struct fbr_p2p x;
    memset(&db, 0, sizeof db);
    TEST("fleet roster flood: a further copy from the same key is refused "
         "at no cost, a republish after the interval and another carrier are "
         "not") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                      FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t len = 0;
        struct fleet_board_post p;
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t member[32];
        struct boot_fleet_roster_counts c0, c1;
        ASSERT(node_db_open(&db, ":memory:"));
        db_open = true;
        fbr_p2p_init(&x, &db, 54);
        boot_fleet_board_wire(&x.svc);
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        ASSERT(fbr_store_row(&db, FBR_STRANGER, line,
                             now - BOOT_FLEET_ROSTER_REPUBLISH_S - 100,
                             FLEET_BOARD_TTL_MAX));

        /* A copy past the interval is a republish, and lands. */
        ASSERT(fbr_row_frame(&p, FBR_STRANGER, line, now, frame, sizeof frame,
                             &len));
        ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, p.id));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);

        /* Newer or back-dated, inside the interval: refused, not stored, no
         * Ed25519 check, and the cached roster stands. */
        boot_fleet_roster_counts(&c0);
        const int64_t dated[] = { now + 1, now - 1000 };
        for (size_t i = 0; i < 2; i++) {
            ASSERT(fbr_row_frame(&p, FBR_STRANGER, line, dated[i], frame,
                                 sizeof frame, &len));
            ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
            ASSERT(!db_fleet_board_have(&db, p.id));
        }
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.rebuilds, c0.rebuilds);
        ASSERT_EQ(c1.verifies, c0.verifies);

        /* The same line from another key is that key's first copy: a roster
         * row is stored whoever carries it. */
        ASSERT(fbr_row_frame(&p, FBR_PEER, line, now + 2, frame, sizeof frame,
                             &len));
        ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
        ASSERT(db_fleet_board_have(&db, p.id));
        PASS();
    } _test_next:;
    fbr_uninstall();
    boot_fleet_board_shutdown();
    if (db_open)
        node_db_close(&db);
    return failures;
}

/* Every three hours for a whole note lifetime, one key offering one line. */
static int test_fleet_board_roster_flood_bound(void)
{
    int failures = 0;
    TEST("fleet roster flood: one key holds a small fixed number of copies of "
         "one line over a whole note lifetime") {
        struct node_db db;
        struct fleet_board_post p;
        struct fleet_board_filter filter;
        struct db_fleet_board_post *rows = NULL;
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t seed[32];
        const int64_t base = 1400000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        for (int i = 0; i < 240; i++) {
            enum fleet_board_result r = fbr_offer(&db, FBR_STRANGER, line,
                                                  base + i * INT64_C(10800), &p);
            ASSERT(r == FLEET_BOARD_OK || r == FLEET_BOARD_ERR_EXPIRED);
        }
        memset(&filter, 0, sizeof filter);
        filter.host_set = true;
        fb_test_identity(FBR_STRANGER, seed, filter.host_pubkey);
        rows = zcl_calloc(16, sizeof *rows, "fbr_flood_bound");
        ASSERT(rows);
        int held = db_fleet_board_list(&db, &filter, base + 1, rows, 16);
        free(rows);
        ASSERT(held >= 3 && held <= 4);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Junk a box took before it had a root cannot crowd the scan once it has one. */
static int test_fleet_board_roster_flood_no_root(void)
{
    int failures = 0;
    TEST("fleet roster flood: junk stored with no root hides no genuine line "
         "once a root appears, and a page of it never reads as unarmed") {
        struct node_db db;
        struct fleet_board_post p;
        uint8_t member[32], peer[32];
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct boot_fleet_roster_counts c0, c1;
        enum boot_fleet_roster_verdict v;
        const int64_t now = 1500000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        g_fbr.present = false;
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_PEER, peer);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        ASSERT_EQ(fbr_offer(&db, 1, line, now, &p), FLEET_BOARD_OK);
        for (int i = 0; i < BOOT_FLEET_ROSTER_SCAN_ROWS + 44; i++) {
            char junk[32];
            (void)snprintf(junk, sizeof junk, "junk-%d", i);
            ASSERT_EQ(fbr_offer(&db, (uint8_t)(40 + i / 50), junk, now + 100 + i,
                                &p), FLEET_BOARD_OK);
        }
        g_fbr.present = true;
        boot_fleet_roster_invalidate();
        boot_fleet_roster_counts(&c0);
        v = boot_fleet_roster_check(&db, member, now + 1000);
        boot_fleet_roster_counts(&c1);
        ASSERT(v != BOOT_FLEET_ROSTER_UNARMED);
        ASSERT(c1.verifies - c0.verifies <= BOOT_FLEET_ROSTER_SCAN_ROWS);
        for (int i = 0; i < 3 && v != BOOT_FLEET_ROSTER_MEMBER; i++) {
            boot_fleet_roster_invalidate();
            v = boot_fleet_roster_check(&db, member, now + 1000);
        }
        ASSERT_EQ(v, BOOT_FLEET_ROSTER_MEMBER);
        /* Proven once, it stays proven while the junk is still there. */
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 1000),
                  BOOT_FLEET_ROSTER_MEMBER);
        /* A line that arrives now is judged ahead of all of it. */
        ASSERT(fbr_line(FBR_ROOT, "m9", FBR_PEER, line, sizeof line));
        ASSERT_EQ(fbr_offer(&db, 1, line, now + 1000, &p), FLEET_BOARD_OK);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, peer, now + 1000),
                  BOOT_FLEET_ROSTER_MEMBER);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* The manager writes a line again by its OWN copies alone: another key's copy
 * must not stand in for it (only the manager's copy reaches every member) and
 * other keys' rows must not hide its own from it. */
static int test_fleet_board_roster_flood_publish(void)
{
    int failures = 0;
    struct fb_rpc_env env;
    bool open = false;
    char dir[256] = {0};
    TEST("fleet roster flood: another key's copies neither stop the manager "
         "republishing a line nor make it write one it holds") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        const int64_t later = now + BOOT_FLEET_ROSTER_REPUBLISH_S;
        char other[FLEET_ENROL_MACHINE_TEXT_MAX];
        open = fb_rpc_env_open(&env);
        ASSERT(open);
        test_make_tmpdir(dir, sizeof dir, "fleet_board", "roster_flood");
        env.svc.datadir = dir;
        fbr_install(FBR_ROOT, true);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, g_fbr.lines[0],
                        sizeof g_fbr.lines[0]));
        g_fbr.n_lines = 1;
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)1);
        /* Young, another key's, and carried nowhere the manager's is. */
        ASSERT(fbr_store_row(&env.db, FBR_STRANGER, g_fbr.lines[0], later,
                             FLEET_BOARD_TTL_MAX));
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, later + 100), (size_t)1);
        /* A page of copies of some other line leaves its own young copy in
         * view: nothing to write. */
        ASSERT(fbr_line(FBR_ROOT, "m7", FBR_STRANGER, other, sizeof other));
        ASSERT(fbr_flood(&env.db, other, later + 200,
                         BOOT_FLEET_ROSTER_SCAN_ROWS + 44));
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, later + 1000), (size_t)0);
        PASS();
    } _test_next:;
    fbr_uninstall();
    if (open)
        fb_rpc_env_close(&env);
    if (dir[0])
        test_rm_rf_recursive(dir);
    return failures;
}

/* The opt-in, the announcement of each change of state, the local switch-off
 * and the manager that publishes nothing by default. */
static int test_fleet_board_roster_arming(void)
{
    int failures = 0;
    struct fb_rpc_env env;
    bool open = false;
    char dir[256] = {0};
    TEST("fleet roster arming: nothing is published without the opt-in; "
         "arming and each way back down are announced once; "
         "-fleetrostergate=0 disarms the box") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        const int64_t gone = now + (int64_t)FLEET_BOARD_TTL_MAX + 4000;
        uint8_t member[32], stranger[32];
        struct boot_fleet_roster_counts c;
        open = fb_rpc_env_open(&env);
        ASSERT(open);
        test_make_tmpdir(dir, sizeof dir, "fleet_board", "arming");
        env.svc.datadir = dir;
        fbr_install(FBR_ROOT, true);
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_STRANGER, stranger);
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, g_fbr.lines[0],
                        sizeof g_fbr.lines[0]));
        g_fbr.n_lines = 1;

        /* Default: a manager with sealed lines still writes nothing, and
         * nobody is gated. */
        ASSERT_EQ(boot_fleet_roster_gate(), BOOT_FLEET_ROSTER_GATE_DEFAULT);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)0);
        ASSERT_EQ(boot_fleet_roster_check(&env.db, member, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)0);

        /* The opt-in publishes and arms, announced once. */
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)1);
        ASSERT_EQ(boot_fleet_roster_check(&env.db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&env.db, stranger, now + 1),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        boot_fleet_roster_counts(&c);
        ASSERT_EQ(c.armed_events, (uint64_t)1);
        ASSERT_EQ(c.lapse_events, (uint64_t)0);

        /* The escape hatch: this box stops enforcing, and says so once. */
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        ASSERT_EQ(boot_fleet_roster_check(&env.db, stranger, now + 2),
                  BOOT_FLEET_ROSTER_UNARMED);
        ASSERT(boot_fleet_roster_admits_peer(&env.db, stranger, now + 2));
        boot_fleet_roster_counts(&c);
        ASSERT_EQ(c.lapse_events, (uint64_t)1);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        ASSERT_EQ(boot_fleet_roster_check(&env.db, stranger, now + 3),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        boot_fleet_roster_counts(&c);
        ASSERT_EQ(c.armed_events, (uint64_t)2);

        /* Nobody republished it: past its TTL the roster lapses, loudly. */
        ASSERT_EQ(boot_fleet_roster_check(&env.db, stranger, gone),
                  BOOT_FLEET_ROSTER_UNARMED);
        boot_fleet_roster_counts(&c);
        ASSERT_EQ(c.lapse_events, (uint64_t)2);
        PASS();
    } _test_next:;
    fbr_uninstall();
    if (open)
        fb_rpc_env_close(&env);
    if (dir[0])
        test_rm_rf_recursive(dir);
    return failures;
}

/* A flag on the node's command line is what arms the manager. */
static int test_fleet_board_roster_gate_flag(void)
{
    int failures = 0;
    TEST("fleet roster: -fleetrostergate arms the manager, "
         "-fleetrostergate=0 switches the box off, and the default is "
         "neither") {
        struct app_context ctx;
        bool show = false;
        char *none[] = { "zclassic23" };
        char *on[] = { "zclassic23", "-fleetrostergate" };
        char *on1[] = { "zclassic23", "-fleetrostergate=1" };
        char *off[] = { "zclassic23", "-fleetrostergate=0" };
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        memset(&ctx, 0, sizeof ctx);
        ASSERT_EQ(args_parse_node_options(1, none, &ctx, &show), -1);
        ASSERT_EQ(boot_fleet_roster_gate(), BOOT_FLEET_ROSTER_GATE_DEFAULT);
        memset(&ctx, 0, sizeof ctx);
        ASSERT_EQ(args_parse_node_options(2, on, &ctx, &show), -1);
        ASSERT_EQ(boot_fleet_roster_gate(), BOOT_FLEET_ROSTER_GATE_ON);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        memset(&ctx, 0, sizeof ctx);
        ASSERT_EQ(args_parse_node_options(2, on1, &ctx, &show), -1);
        ASSERT_EQ(boot_fleet_roster_gate(), BOOT_FLEET_ROSTER_GATE_ON);
        memset(&ctx, 0, sizeof ctx);
        ASSERT_EQ(args_parse_node_options(2, off, &ctx, &show), -1);
        ASSERT_EQ(boot_fleet_roster_gate(), BOOT_FLEET_ROSTER_GATE_OFF);
        PASS();
    } _test_next:;
    boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
    boot_fleet_roster_test_reset();
    return failures;
}

/* A read that fails is "cannot tell", never "no roster". */
static int test_fleet_board_roster_read_failure(void)
{
    int failures = 0;
    TEST("fleet roster: a roster that cannot be read from the store is "
         "unverifiable (no fleet relay), not unarmed") {
        struct node_db db;
        uint8_t member[32];
        struct db_fleet_board_post rows[4];
        struct boot_fleet_roster_counts c;
        bool complete = false;
        const int64_t now = 1100000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        /* A healthy empty store is unarmed, and says it read completely. */
        (void)db_fleet_board_list_checked(&db, NULL, now, rows, 4, &complete);
        ASSERT(complete);
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNARMED);
        ASSERT(fbr_member_row(&db, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);

        /* The table cannot be read: the same store, a failed prepare. There
         * is no fault-injection seam on the board store, so the table is
         * taken away, which fails the query for the same reason an I/O error
         * would. */
        ASSERT(node_db_exec(&db, "ALTER TABLE fleet_board_posts RENAME TO "
                                 "fleet_board_posts_gone"));
        (void)db_fleet_board_list_checked(&db, NULL, now, rows, 4, &complete);
        ASSERT(!complete);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        ASSERT(!boot_fleet_roster_admits_peer(&db, member, now));
        boot_fleet_roster_counts(&c);
        ASSERT(c.unverifiable >= 1);
        ASSERT(node_db_exec(&db, "ALTER TABLE fleet_board_posts_gone RENAME "
                                 "TO fleet_board_posts"));
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_MEMBER);

        /* A stored roster row that no longer decodes may be the very row
         * that names a member: also "cannot tell". */
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='altered' "
                                 "WHERE agent='fleet-roster'"));
        (void)db_fleet_board_list_checked(&db, NULL, now, rows, 4, &complete);
        ASSERT(!complete);
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

struct fbr_hammer {
    struct node_db *db;
    const uint8_t *key;
    int64_t now;
    atomic_int wrong;
};

static void *fbr_hammer_run(void *arg)
{
    struct fbr_hammer *h = arg;
    for (int i = 0; i < 200; i++)
        if (boot_fleet_roster_check(h->db, h->key, h->now) !=
            BOOT_FLEET_ROSTER_MEMBER)
            atomic_fetch_add(&h->wrong, 1);
    return NULL;
}

/* One rebuild at a time, one verify per distinct line, none per post. */
static int test_fleet_board_roster_cost(void)
{
    int failures = 0;
    TEST("fleet roster cost: republished copies are verified once, a post "
         "on the cached path costs no verify, and concurrent askers share "
         "one rebuild") {
        enum { LINES = 40, THREADS = 8 };
        struct node_db db;
        uint8_t member[32], stranger[32], seed[32];
        struct boot_fleet_roster_counts c0, c1;
        struct fleet_board_post p;
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        const int64_t now = 1200000;
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        fbr_key(FBR_STRANGER, stranger);
        /* Four copies of one line (a republish every 10 days leaves up to
         * three live) plus LINES - 1 other members. */
        ASSERT(fbr_line(FBR_ROOT, "m5", FBR_MEMBER, line, sizeof line));
        for (int i = 0; i < 4; i++)
            ASSERT(fbr_store_row(&db, 1, line, now + i, 3600));
        for (int i = 1; i < LINES; i++) {
            char name[16];
            (void)snprintf(name, sizeof name, "box-%d", i);
            ASSERT(fbr_line(FBR_ROOT, name, (uint8_t)(100 + i), line,
                            sizeof line));
            ASSERT(fbr_store_row(&db, (uint8_t)(30 + i % 8), line, now + 10 + i,
                                 3600));
        }
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 100),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.rebuilds, c0.rebuilds + 1);
        ASSERT_EQ(c1.verifies, c0.verifies + LINES); /* not LINES + 3 */

        /* The cached path: a thousand fleet posts, from a member and from a
         * stranger, cost no verify and no rebuild. */
        fb_test_identity(FBR_MEMBER, seed, member);
        fb_test_compose(&p, FLEET_BOARD_KIND_NOTE, "carrier", "hot", 1, 3600);
        fb_test_scope(&p, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(fleet_board_post_sign(&p, seed, member), FLEET_BOARD_OK);
        boot_fleet_roster_counts(&c0);
        for (int i = 0; i < 1000; i++)
            ASSERT(boot_fleet_roster_admits_post(&db, &p, now + 100));
        fb_test_identity(FBR_STRANGER, seed, stranger);
        ASSERT_EQ(fleet_board_post_sign(&p, seed, stranger), FLEET_BOARD_OK);
        for (int i = 0; i < 1000; i++)
            ASSERT(!boot_fleet_roster_admits_post(&db, &p, now + 100));
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies);
        ASSERT_EQ(c1.rebuilds, c0.rebuilds);

        /* A rebuild that finds the same lines again does not verify them
         * again; a change of the root's chain state does, and refuses them. */
        boot_fleet_roster_invalidate();
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 101),
                  BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.rebuilds, c0.rebuilds + 1);
        ASSERT_EQ(c1.verifies, c0.verifies);
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_REVOKED));
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 102),
                  BOOT_FLEET_ROSTER_UNVERIFIABLE);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies + LINES);
        ASSERT(fbr_anchor(&db, FBR_ROOT, ZID_IDENTITY_STATUS_ACTIVE));
        ASSERT_EQ(boot_fleet_roster_check(&db, member, now + 103),
                  BOOT_FLEET_ROSTER_MEMBER);

        /* Single flight: after the roster changes, and again from a cold
         * start, many threads asking at once cause one rebuild. */
        for (int phase = 0; phase < 2; phase++) {
            pthread_t t[THREADS];
            struct fbr_hammer h = { .db = &db, .key = member,
                                    .now = now + 200 };
            atomic_init(&h.wrong, 0);
            if (phase == 0)
                boot_fleet_roster_invalidate();
            else
                boot_fleet_roster_test_reset();
            boot_fleet_roster_test_build_delay_ms(60); /* askers arrive mid-build */
            boot_fleet_roster_counts(&c0);
            for (int i = 0; i < THREADS; i++)
                ASSERT_EQ(pthread_create(&t[i], NULL, fbr_hammer_run, &h), 0);
            for (int i = 0; i < THREADS; i++)
                ASSERT_EQ(pthread_join(t[i], NULL), 0);
            boot_fleet_roster_test_build_delay_ms(0);
            boot_fleet_roster_counts(&c1);
            ASSERT_EQ(atomic_load(&h.wrong), 0);
            ASSERT_EQ(c1.rebuilds, c0.rebuilds + 1);
        }
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* The relay gate on the paired board stream: a member peer is served, a
 * non-member is not, an unverifiable roster serves nobody, and an author
 * who is not a member is not accepted off the stream. */
static int test_fleet_board_roster_relay(void)
{
    int failures = 0;
    static struct fbw w;
    struct fleet_board_post a_member, after_revoke, after_member, after_stranger;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-roster-test" };
    struct boot_fleet_roster_counts rb, ra;
    size_t frames = 0;
    uint8_t member[32];
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w);
    TEST("fleet roster relay: a roster member peer is served fleet posts, a "
         "non-member peer is not, a revoked root serves nobody, and a "
         "non-member author is not accepted") {
        const int64_t now = FBW_NOW;
        ASSERT(opened);
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, FBW_NOW);
        boot_fleet_board_fleet_test_bind(&w.a);
        fbr_install(FBR_ROOT, false);
        fbr_key(FBR_MEMBER, member);
        /* The fixture's delegation carries an online key nobody holds a
         * seed for; the verifier stands FBR_PEER in for it (see top). */
        g_fbr.remap = true;
        fbr_key(FBR_PEER, g_fbr.remap_from);
        memcpy(g_fbr.remap_to, w.f.term_peer.delegation.online_pubkey, 32);

        /* UNARMED: fleet carriage is what it was before this step. */
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "unarmed note", 2000, 3600, 2000, &a_member));
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, a_member.id));

        /* ARMED, peer not on the roster: the pull is refused before a row
         * is read; nothing is served, and it is counted. */
        ASSERT(fbr_member_row(&w.a, FBR_ROOT, "m5", FBR_MEMBER, now));
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "for members only", 2100, 3600, 2100, &after_member));
        boot_fleet_roster_counts(&rb);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        ASSERT_EQ(frames, (size_t)1); /* the refusal alone */
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.non_member, rb.non_member + 1);
        ASSERT(!db_fleet_board_have(&w.b, after_member.id));

        /* The asking half asks the roster too, before it opens a stream:
         * board_peer_due refuses a peer that is not on it. (The fixture's
         * paired row names a noise key no node is connected as, so the
         * stream itself cannot be watched; the roster's own refusal count
         * is what the call leaves behind.) */
        boot_fleet_roster_counts(&rb);
        boot_fleet_board_fleet_test_pull_paired(now);
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.non_member, rb.non_member + 1);

        /* The peer joins the roster: served within the next pull. */
        ASSERT(fbr_member_row(&w.a, FBR_ROOT, "peerbox", FBR_PEER, now + 1));
        ASSERT(fbw_pull(&w, w.box_a, &w.b, &frames) >= (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, after_member.id));
        /* On the roster, the same call is not refused: so the refusal above
         * was the roster's and nothing else's. */
        boot_fleet_roster_counts(&rb);
        boot_fleet_board_fleet_test_pull_paired(now);
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.non_member, rb.non_member);
        ASSERT_EQ(ra.unverifiable, rb.unverifiable);

        /* The root is revoked on chain: the roster is unverifiable and the
         * answering box serves nobody, member or not. */
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "after revocation", 2200, 3600, 2200, &after_revoke));
        ASSERT(fbr_anchor(&w.a, FBR_ROOT, ZID_IDENTITY_STATUS_REVOKED));
        boot_fleet_roster_counts(&rb);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.unverifiable, rb.unverifiable + 1);
        ASSERT(!db_fleet_board_have(&w.b, after_revoke.id));
        PASS();
    }
    TEST("fleet roster relay: an armed asking box does not accept a "
         "non-member author off the stream, and takes a member's") {
        /* A fresh answering store with no roster of its own, so it serves
         * everything; the asking store is the armed one. */
        struct node_db fresh;
        uint8_t junk_id[32];
        memset(&fresh, 0, sizeof fresh);
        ASSERT(node_db_open(&fresh, ":memory:"));
        boot_fleet_board_fleet_test_new_epoch(); /* a different store answers */
        boot_fleet_board_fleet_test_bind(&fresh);
        ASSERT(fbw_post(&fresh, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "by a member", 2300, 3600, 2300, &after_member));
        ASSERT(fbw_post(&fresh, FBR_STRANGER, FLEET_BOARD_SCOPE_FLEET,
                        "by a stranger", 2300, 3600, 2300, &after_stranger));
        /* A roster-shaped note nobody sealed rides the same stream and is
         * refused at the asking box, whoever authored it. */
        ASSERT(fbr_store_row_id(&fresh, FBR_MEMBER, "not a sealed line", 2300,
                                3600, junk_id));
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, after_member.id));
        ASSERT(!db_fleet_board_have(&w.b, after_stranger.id));
        ASSERT(!db_fleet_board_have(&w.b, junk_id));
        node_db_close(&fresh);
        PASS();
    }
    TEST("fleet roster relay: a box with no fleet root pulls a roster row "
         "from an armed manager, stores it as the ordinary note it was "
         "before this step, and defers nothing") {
        struct node_db fresh;
        struct boot_fleet_board_fleet_counts fb, fa;
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t row_id[32];
        memset(&fresh, 0, sizeof fresh);
        ASSERT(node_db_open(&fresh, ":memory:"));
        boot_fleet_board_fleet_test_new_epoch();
        boot_fleet_board_fleet_test_bind(&fresh);
        ASSERT(fbr_line(FBR_ROOT, "m77", 77, line, sizeof line));
        ASSERT(fbr_store_row_id(&fresh, FBR_MEMBER, line, 2400, 3600, row_id));
        g_fbr.present = false; /* this box has no fleet root */
        boot_fleet_roster_invalidate();
        boot_fleet_board_fleet_counts(&fb);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)1);
        boot_fleet_board_fleet_counts(&fa);
        ASSERT(db_fleet_board_have(&w.b, row_id));
        ASSERT_EQ(fa.deferred, fb.deferred);
        /* The cursor moved on: the next pull has nothing to offer again. */
        ASSERT_EQ(fbw_pull(&w, w.box_a, &w.b, &frames), (size_t)0);
        boot_fleet_board_fleet_counts(&fb);
        ASSERT_EQ(fb.deferred, fa.deferred);
        g_fbr.present = true;
        node_db_close(&fresh);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    fbw_close(&w);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

#define FBD_ONION_A "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
#define FBD_ONION_B "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxa.onion"
#define FBD_ONION_C "cdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxab.onion"
#define FBD_ONION_D "defghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxabc.onion"
#define FBD_NOW INT64_C(2500)

static struct {
    char host[8][80];
    int port[8];
    size_t n;
} g_fbd;

static char g_fbd_self = 'B';

static void fbd_dial(const char *host, int port)
{
    if (g_fbd.n < 8) {
        (void)snprintf(g_fbd.host[g_fbd.n], sizeof g_fbd.host[0], "%s", host);
        g_fbd.port[g_fbd.n] = port;
    }
    g_fbd.n++;
}

static bool fbd_verify_cb(const char *line, const uint8_t root[32],
                          enum zcl_fleet_root_state state, bool require,
                          uint8_t signer[32], uint8_t box[32], bool *sealed,
                          const char **why, void *ctx)
{
    (void)root; (void)state; (void)require; (void)ctx;
    *sealed = line[0] != 'D';
    *why = "fleetboard.roster_signature_invalid";
    if (line[0] == 'D')
        return false;
    memset(signer, 0, 32);
    memset(box, 0, 32);
    signer[0] = (uint8_t)(0x80 | line[0]);
    box[0] = (uint8_t)line[0];
    return true;
}

/* The onion a stub line claims by its first character; a second character
 * of - makes the same box claim none (the pre-onion row of a machine). */
static bool fbd_endpoint_cb(const char *line, const uint8_t root[32],
                            char *onion, size_t cap, bool *self, void *ctx)
{
    const char *claim = NULL;
    (void)root; (void)ctx;
    *self = line[0] == g_fbd_self;
    switch (line[0]) {
    case 'A': claim = FBD_ONION_A; break;
    case 'B': claim = FBD_ONION_B; break;
    case 'C': claim = FBD_ONION_C; break;
    case 'D': claim = FBD_ONION_D; break;
    case 'E': claim = ""; break;
    default: return false;
    }
    (void)snprintf(onion, cap, "%s", line[1] == '-' ? "" : claim);
    return true;
}

static bool fbd_each_cb(void (*visit)(const char *line, void *user),
                        void *user, void *ctx)
{
    static const char *const lines[] = { "A", "B", "C", "D", "E", "A" };
    (void)ctx;
    for (size_t i = 0; i < sizeof lines / sizeof lines[0]; i++)
        visit(lines[i], user);
    return true;
}

static int test_fleet_board_roster_dial(void)
{
    int failures = 0;
    TEST("fleet roster dial: only a verified, unrevoked, other machine with "
         "an onion is dialled, once per call, and nobody without a root or "
         "with a head that cannot be trusted") {
        struct node_db db;
        static const struct zcl_fleet_roster_provider provider = {
            .root = fbr_root_cb, .verify = fbd_verify_cb,
            .head = fbr_head_cb, .each_line = fbd_each_cb,
            .endpoint = fbd_endpoint_cb, .ctx = NULL,
            .name = "fleet-dial-test" };
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        zcl_fleet_roster_provider_install(&provider);
        g_fbr.head.state = ZCL_FLEET_HEAD_OK;
        g_fbr.head.count = 1;
        g_fbr.head.revoked[0][0] = 'C';
        memset(&g_fbd, 0, sizeof g_fbd);
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT_EQ(g_fbd.n, 1);
        ASSERT_STR_EQ(g_fbd.host[0], FBD_ONION_A);
        ASSERT_EQ(g_fbd.port[0], 0);
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT_EQ(g_fbd.n, 2);
        g_fbr.head.state = ZCL_FLEET_HEAD_FAILED;
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 0);
        g_fbr.head.state = ZCL_FLEET_HEAD_OK;
        g_fbr.present = false;
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 0);
        g_fbr.present = true;
        fbr_uninstall();
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 0);
        ASSERT_EQ(g_fbd.n, 2);
        node_db_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static bool fbd_has(const char *onion)
{
    for (size_t i = 0; i < g_fbd.n && i < 8; i++)
        if (strcmp(g_fbd.host[i], onion) == 0)
            return true;
    return false;
}

static int test_fleet_board_roster_dial_board(void)
{
    int failures = 0;
    TEST("fleet roster dial: every member of a fleet whose roster lives only "
         "on the board dials the other members onions and never its own") {
        struct node_db db;
        static const struct zcl_fleet_roster_provider provider = {
            .root = fbr_root_cb, .verify = fbd_verify_cb,
            .head = fbr_head_cb, .each_line = NULL,
            .endpoint = fbd_endpoint_cb, .ctx = NULL,
            .name = "fleet-dial-board-test" };
        static const char members[] = "ABC";
        const char *onions[] = { FBD_ONION_A, FBD_ONION_B, FBD_ONION_C };
        memset(&db, 0, sizeof db);
        ASSERT(node_db_open(&db, ":memory:"));
        fbr_install(FBR_ROOT, false);
        zcl_fleet_roster_provider_install(&provider);
        for (size_t i = 0; i < 3; i++) {
            char line[2] = { members[i], 0 };
            ASSERT(fbr_store_row(&db, 1, line, 2400, 3600));
        }
        for (size_t self = 0; self < 3; self++) {
            g_fbd_self = members[self];
            memset(&g_fbd, 0, sizeof g_fbd);
            ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 2);
            ASSERT_EQ(g_fbd.n, 2);
            for (size_t m = 0; m < 3; m++)
                ASSERT_EQ(fbd_has(onions[m]), m != self);
        }
        g_fbd_self = 'B';
        fbr_uninstall();
        node_db_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static const struct zcl_fleet_roster_provider g_fbd_board_provider = {
    .root = fbr_root_cb, .verify = fbd_verify_cb, .head = fbr_head_cb,
    .each_line = NULL, .endpoint = fbd_endpoint_cb, .ctx = NULL,
    .name = "fleet-dial-guard-test" };

/* A board-only roster of `rows` (each stored as a fleet-scope note), this
 * box being no listed member, with the given box or signing key revoked. */
static bool fbd_guard_open(struct node_db *db, const char *const *rows,
                           size_t n, uint8_t revoked_box, uint8_t revoked_signer)
{
    memset(db, 0, sizeof *db);
    if (!node_db_open(db, ":memory:"))
        return false;
    fbr_install(FBR_ROOT, false);
    zcl_fleet_roster_provider_install(&g_fbd_board_provider);
    g_fbd_self = 'Z';
    g_fbr.head.state = ZCL_FLEET_HEAD_OK;
    g_fbr.head.count = revoked_box || revoked_signer;
    memset(g_fbr.head.revoked, 0, sizeof g_fbr.head.revoked);
    g_fbr.head.revoked[0][0] = revoked_box ? revoked_box : revoked_signer;
    memset(&g_fbd, 0, sizeof g_fbd);
    for (size_t i = 0; i < n; i++)
        if (!fbr_store_row(db, 1, rows[i], 2400, 3600))
            return false;
    return true;
}

static void fbd_guard_close(struct node_db *db)
{
    g_fbd_self = 'B';
    fbr_uninstall();
    node_db_close(db);
}

static int test_fleet_board_roster_dial_flood(void)
{
    int failures = 0;
    TEST("fleet roster dial: a page of newer copies of one line hides no other "
         "machine from the dialler") {
        struct node_db db;
        const char *const rows[] = { "A" };
        ASSERT(fbd_guard_open(&db, rows, 1, 0, 0));
        ASSERT(fbr_flood(&db, "C", 2401, BOOT_FLEET_ROSTER_SCAN_ROWS + 44));
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 2);
        ASSERT(fbd_has(FBD_ONION_A));
        ASSERT(fbd_has(FBD_ONION_C));
        fbd_guard_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_board_roster_dial_junk(void)
{
    int failures = 0;
    TEST("fleet roster dial: a page of lines that do not verify hides no "
         "machine from the dialler once the scan has reached it") {
        struct node_db db;
        const char *const rows[] = { "A" };
        ASSERT(fbd_guard_open(&db, rows, 1, 0, 0));
        for (int i = 0; i < BOOT_FLEET_ROSTER_SCAN_ROWS + 44; i++) {
            char junk[16];
            (void)snprintf(junk, sizeof junk, "D%d", i);
            ASSERT(fbr_store_row(&db, (uint8_t)(40 + i / 50), junk, 2401 + i,
                                 FLEET_BOARD_TTL_MAX));
        }
        for (int pass = 0; pass < 3 && !fbd_has(FBD_ONION_A); pass++) {
            boot_fleet_roster_invalidate();
            (void)boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial);
        }
        ASSERT(fbd_has(FBD_ONION_A));
        ASSERT(!fbd_has(FBD_ONION_D));
        fbd_guard_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_board_roster_dial_guards(void)
{
    int failures = 0;
    struct node_db db;
    TEST("fleet roster dial: a board row that fails root verification is "
         "never dialled") {
        const char *rows[] = { "A", "D" }; /* the stub refuses D */
        ASSERT(fbd_guard_open(&db, rows, 2, 0, 0));
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT(fbd_has(FBD_ONION_A));
        ASSERT(!fbd_has(FBD_ONION_D));
        fbd_guard_close(&db);
        PASS();
    }
    TEST("fleet roster dial: a board row whose box key is revoked is never "
         "dialled") {
        const char *rows[] = { "A", "C" };
        ASSERT(fbd_guard_open(&db, rows, 2, 'C', 0)); /* box[0] = line[0] */
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT(fbd_has(FBD_ONION_A));
        ASSERT(!fbd_has(FBD_ONION_C));
        fbd_guard_close(&db);
        PASS();
    }
    TEST("fleet roster dial: a board row whose signing key is revoked is "
         "never dialled") {
        const char *rows[] = { "A", "C" };
        ASSERT(fbd_guard_open(&db, rows, 2, 0, 0x80 | 'C')); /* signer[0] */
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT(fbd_has(FBD_ONION_A));
        ASSERT(!fbd_has(FBD_ONION_C));
        fbd_guard_close(&db);
        PASS();
    }
    TEST("fleet roster dial: a machine re-admitted with an onion beside its "
         "old empty-onion row is dialled once and the empty row adds nothing") {
        const char *rows[] = { "A-", "A" }; /* same box key, two rows */
        ASSERT(fbd_guard_open(&db, rows, 2, 0, 0));
        ASSERT_EQ(boot_fleet_roster_dial(&db, FBD_NOW, fbd_dial), 1);
        ASSERT_EQ(g_fbd.n, 1);
        ASSERT_STR_EQ(g_fbd.host[0], FBD_ONION_A);
        fbd_guard_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

/* The own-key cases of the roster gate's endpoint. While this box's key is
 * readable its own sealed line is recognised as this box (self, with its
 * onion) and another box's line is not. While the key is absent or unreadable
 * any valid line is refused, because the box cannot prove the line is not its
 * own, so the dialler must skip it. The key leaf is tools/dev/fleet_enrol_key.c
 * FLEET_KEY_LEAF. */
#define FBK_KEY_LEAF "box.ed25519"
#define FBK_OWN_ONION FBD_ONION_A
#define FBK_OTHER_ONION FBD_ONION_B

static bool fbk_isolate(const char *env, const char *tag, char *dir,
                        size_t cap)
{
    test_make_tmpdir(dir, cap, "fleet_board_own_key", tag);
    return platform_environment_set(env, dir, 1) == 0;
}

/* Truncate the key file so it still opens but is not a 32-byte key. */
static bool fbk_break_key(void)
{
    char path[PATH_MAX];
    FILE *f = NULL;
    if (!fleet_enrol_state_path(FBK_KEY_LEAF, path, sizeof path))
        return false;
    f = fopen(path, "wb");
    if (!f)
        return false;
    bool wrote = fwrite("short", 1, 5, f) == 5;
    return fclose(f) == 0 && wrote;
}

/* Create this isolate's own key and return its seed and public half. */
static bool fbk_make_key(uint8_t seed[FLEET_ENROL_SEED_BYTES],
                         uint8_t pub[FLEET_ENROL_PUBKEY_BYTES])
{
    const char *why = NULL;
    bool present = false;
    return fleet_enrol_key_load(seed, pub, true, &present, &why) && present;
}

/* One sealed machine line for the box whose key is box_seed/box_pub, with
 * the receipt claiming `onion`; the same chain fbr_line builds. */
static bool fbk_line(const uint8_t box_seed[32], const uint8_t box_pub[32],
                     const char *onion, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts;
    struct fleet_signing_key signer;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    memset(&facts, 0, sizeof facts);
    (void)snprintf(facts.hostname, sizeof facts.hostname, "fbk-box");
    fbr_root_pub(FBR_ROOT, op_seed, op_pub);
    fb_test_identity(2, signer.seed, signer.pubkey);
    return fleet_invite_mint("fbk-box", 24, "", op_seed, op_pub, FBR_LINE_NOW,
                             token, sizeof token, &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof invite_wire,
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, onion, &facts, "",
                              box_seed, box_pub, &signer, receipt,
                              sizeof receipt, &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof receipt_wire, &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FBR_LINE_NOW,
                              FLEET_ENROL_PORT_FIRST, op_seed, op_pub, out,
                              cap, &why);
}

static int test_fleet_board_roster_dial_own_key(void)
{
    int failures = 0;
#ifdef _WIN32
    const char *env = "ZCL_STATE_ROOT";
#else
    const char *env = "XDG_STATE_HOME";
#endif
    const char *prior = getenv(env);
    char saved[4096], dir[512], own_line[FLEET_ENROL_MACHINE_TEXT_MAX];
    char other_line[FLEET_ENROL_MACHINE_TEXT_MAX], onion[96];
    uint8_t root[32], own_seed[FLEET_ENROL_SEED_BYTES];
    uint8_t own_pub[FLEET_ENROL_PUBKEY_BYTES], other_seed[32], other_pub[32];
    bool changed = false, self = false;
    const struct zcl_fleet_roster_provider *real =
        zcl_fleet_roster_gate_provider();
    if (prior && strlen(prior) >= sizeof(saved)) return 1;
    (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
    TEST("fleet roster dial: with a readable key this box's own line is "
         "recognised as self and another box's line is not; with the key "
         "absent or unreadable the own line is refused") {
        ASSERT(real && real->endpoint);
        fbr_root_pub(FBR_ROOT, other_seed, root);
        fbr_root_pub(0x82, other_seed, other_pub);
        ASSERT(fbk_line(other_seed, other_pub, FBK_OTHER_ONION, other_line,
                        sizeof other_line));

        /* Readable key: the own line is this box, the other line is not. */
        ASSERT(fbk_isolate(env, "readable", dir, sizeof dir)); changed = true;
        ASSERT(fbk_make_key(own_seed, own_pub));
        ASSERT(fbk_line(own_seed, own_pub, FBK_OWN_ONION, own_line,
                        sizeof own_line));
        ASSERT(real->endpoint(own_line, root, onion, sizeof onion, &self,
                              real->ctx));
        ASSERT(self);
        ASSERT_STR_EQ(onion, FBK_OWN_ONION);
        ASSERT(real->endpoint(other_line, root, onion, sizeof onion, &self,
                              real->ctx));
        ASSERT(!self);
        ASSERT_STR_EQ(onion, FBK_OTHER_ONION);

        /* Absent key: the own line (made under a key that is then removed by
         * switching to an empty state root) is refused. */
        ASSERT(fbk_isolate(env, "absent-src", dir, sizeof dir));
        ASSERT(fbk_make_key(own_seed, own_pub));
        ASSERT(fbk_line(own_seed, own_pub, FBK_OWN_ONION, own_line,
                        sizeof own_line));
        ASSERT(fbk_isolate(env, "absent", dir, sizeof dir));
        ASSERT(!real->endpoint(own_line, root, onion, sizeof onion, &self,
                               real->ctx));

        /* Unreadable key: the same own line is refused. */
        ASSERT(fbk_isolate(env, "unreadable", dir, sizeof dir));
        ASSERT(fbk_make_key(own_seed, own_pub));
        ASSERT(fbk_line(own_seed, own_pub, FBK_OWN_ONION, own_line,
                        sizeof own_line));
        ASSERT(fbk_break_key());
        ASSERT(!real->endpoint(own_line, root, onion, sizeof onion, &self,
                               real->ctx));
        PASS();
    } _test_next:;
    if (changed) {
        if (prior ? platform_environment_set(env, saved, 1) : unsetenv(env))
            failures++;
    }
    return failures;
}

/* ── core.wallet.fleet.status ─────────────────────────────────────────── */

#define FST_ALPHA FBD_ONION_A
#define FST_ALPHA2 "aefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxabc.onion"
#define FST_BRAVO FBD_ONION_B
#define FST_CHARLIE FBD_ONION_C
#define FST_SELF FBD_ONION_D
#define FST_FORGED "eefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxabc.onion"
#define FST_LOCAL 5000
#define FST_NOW 10000

static uint8_t g_fst_self_box[32];

/* One real sealed line whose receipt names `onion`, enrolled at `at`; the box
 * key is test identity 0x80+signer_id, so a test knows it without parsing. */
static bool fst_line(uint8_t root_id, const char *name, uint8_t signer_id,
                     const char *onion, int64_t at, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts;
    struct fleet_signing_key signer;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    memset(&facts, 0, sizeof facts);
    (void)snprintf(facts.hostname, sizeof facts.hostname, "%s", name);
    fbr_root_pub(root_id, op_seed, op_pub);
    fbr_root_pub((uint8_t)(0x80 + signer_id), box_seed, box_pub);
    fb_test_identity(signer_id, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, 24, "", op_seed, op_pub, FBR_LINE_NOW,
                             token, sizeof token, &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof invite_wire,
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, onion, &facts, "",
                              box_seed, box_pub, &signer, receipt,
                              sizeof receipt, &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof receipt_wire, &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, at,
                              FLEET_ENROL_PORT_FIRST, op_seed, op_pub, out,
                              cap, &why);
}

/* The endpoint of a real line: its receipt's onion, and self when its box is
 * the box this test plays. */
static bool fst_endpoint_cb(const char *line, const uint8_t root[32],
                            char *onion, size_t cap, bool *self, void *ctx)
{
    struct fleet_machine m;
    const char *why = NULL;
    (void)ctx;
    memset(&m, 0, sizeof m);
    if (!fleet_machine_parse(line, root, &m, &why) ||
        strlen(m.receipt.onion) >= cap)
        return false;
    (void)snprintf(onion, cap, "%s", m.receipt.onion);
    *self = memcmp(m.receipt.box_pubkey, g_fst_self_box, 32) == 0;
    return true;
}

static bool fst_name_cb(const char *line, const uint8_t root[32], char *out,
                        size_t cap, void *ctx)
{
    const struct zcl_fleet_roster_provider *real =
        zcl_fleet_roster_gate_provider();
    (void)ctx;
    return real->machine_name(line, root, out, cap, real->ctx);
}

static bool fst_enrolled_cb(const char *line, const uint8_t root[32],
                            int64_t *out, void *ctx)
{
    const struct zcl_fleet_roster_provider *real =
        zcl_fleet_roster_gate_provider();
    (void)ctx;
    return real->enrolled_at(line, root, out, real->ctx);
}

static const struct zcl_fleet_roster_provider g_fst_provider = {
    .root = fbr_root_cb, .verify = fbr_verify_cb, .head = fbr_head_cb,
    .each_line = fbr_each_cb, .endpoint = fst_endpoint_cb,
    .machine_name = fst_name_cb, .enrolled_at = fst_enrolled_cb,
    .ctx = NULL, .name = "fleet-status-test" };

static struct fleet_status g_fst;
/* The database the open fixture stores standing refusals in. */
static struct node_db *g_fst_db;

/* A chain whose block at height h has a hash only this node holds, and a
 * forked chain that differs at every height. */
static void fst_hash(int64_t h, bool forked, char hex[65])
{
    (void)snprintf(hex, 65, "%064llx",
                   (unsigned long long)(h * 7919 + (forked ? 2 : 1)));
}

static bool fst_hash_at(int64_t h, char hex[65], void *ctx)
{
    (void)ctx;
    if (h < FST_LOCAL - 100 || h > FST_LOCAL)
        return false;
    fst_hash(h, false, hex);
    return true;
}

static const struct fleet_status_local g_fst_local = {
    .tip = FST_LOCAL, .hash_at = fst_hash_at };

/* The box key of the roster machine at `onion` in the collected status. */
static bool fst_box_of(const char *onion, uint8_t box[32])
{
    char want[BOOT_FLEET_ROSTER_ONION_MAX], have[BOOT_FLEET_ROSTER_ONION_MAX];
    if (!fleet_status_onion_key(onion, want, sizeof want))
        return false;
    for (size_t i = 0; i < g_fst.machine_count; i++)
        if (fleet_status_onion_key(g_fst.machines[i].onion, have,
                                   sizeof have) &&
            strcmp(want, have) == 0) {
            memcpy(box, g_fst.machines[i].box, 32);
            return true;
        }
    return false;
}

/* The standing refusal the cache holds for the machine at `onion`: its
 * refused height, 0 when none. */
static int64_t fst_refusal_of(const char *onion)
{
    static const char digits[] = "0123456789abcdef";
    char key[FLEET_TIP_REFUSAL_KEY_MAX];
    uint8_t box[32];
    if (!fst_box_of(onion, box))
        return -1;
    for (size_t i = 0; i < 32; i++) {
        key[2 * i] = digits[box[i] >> 4];
        key[2 * i + 1] = digits[box[i] & 15];
    }
    key[64] = '\0';
    return fleet_tip_cache_refusal(key);
}

/* A check of `onion` made at time `at` on the fleet_tip_now_secs() clock,
 * stored and settled as the background step does. `at_forked` is the block a
 * machine above our tip names at our tip height: ours, or a fork's. */
static void fst_check_above(const char *onion, int64_t h, bool forked,
                            bool has_at, bool at_forked, int64_t at)
{
    char key[BOOT_FLEET_ROSTER_ONION_MAX];
    uint8_t box[32];
    struct fleet_tip t;
    memset(&t, 0, sizeof t);
    t.height = h;
    fst_hash(h, forked, t.hash);
    t.has_at = has_at;
    t.at_height = FST_LOCAL;
    fst_hash(FST_LOCAL, at_forked, t.at_hash);
    t.fetched_at = at;
    if (!fleet_status_onion_key(onion, key, sizeof key) ||
        !fst_box_of(onion, box))
        return;
    fleet_tip_cache_put(key, &t);
    fleet_status_note_check(g_fst_db, box, &t, &g_fst_local);
}

static void fst_check(const char *onion, int64_t h, bool forked, int64_t at)
{
    fst_check_above(onion, h, forked, false, false, at);
}

static void fst_peer(struct fleet_status_peer *p, const char *host,
                     bool inbound)
{
    memset(p, 0, sizeof *p);
    (void)snprintf(p->host, sizeof p->host, "%s", host);
    p->inbound = inbound;
}

static void fst_apply(const struct fleet_status_peer *peers, size_t n)
{
    fleet_status_apply(&g_fst, peers, n, &g_fst_local, FST_NOW);
}

enum fst_readmit { FST_ONCE = 0, FST_READMIT_LAST, FST_READMIT_FIRST };

/* Append `line` to the roster at `first` or last. */
static void fst_add_line(const char *line, bool first)
{
    if (first) {
        memmove(g_fbr.lines[1], g_fbr.lines[0],
                g_fbr.n_lines * sizeof g_fbr.lines[0]);
        (void)snprintf(g_fbr.lines[0], sizeof g_fbr.lines[0], "%s", line);
        g_fbr.n_lines++;
        return;
    }
    (void)snprintf(g_fbr.lines[g_fbr.n_lines++], sizeof g_fbr.lines[0], "%s",
                   line);
}

/* A verified roster of alpha, bravo, charlie, this box, and one line sealed
 * by a root nobody trusts. bravo's box key is revoked when `revoke_bravo`.
 * With a readmit, alpha is admitted again later under a new onion, and that
 * row sits last or first in the roster. */
static bool fst_open(struct node_db *db, bool revoke_bravo,
                     enum fst_readmit readmit)
{
    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
    uint8_t seed[32];
    const char *const names[] = { "alpha", "bravo", "charlie", "mallory",
                                  "studio" };
    const char *const onions[] = { FST_ALPHA, FST_BRAVO, FST_CHARLIE,
                                   FST_FORGED, FST_SELF };
    memset(db, 0, sizeof *db);
    if (!node_db_open(db, ":memory:"))
        return false;
    g_fst_db = db;
    fleet_tip_cache_reset();
    fbr_install(FBR_ROOT, false);
    zcl_fleet_roster_provider_install(&g_fst_provider);
    fbr_root_pub((uint8_t)(0x80 + 15), seed, g_fst_self_box);
    for (uint8_t i = 0; i < 5; i++) {
        /* mallory (index 3) is sealed by a root this box does not trust. */
        uint8_t root = i == 3 ? (uint8_t)(FBR_ROOT + 1) : FBR_ROOT;
        if (!fst_line(root, names[i], (uint8_t)(11 + i), onions[i],
                      FBR_LINE_NOW, line, sizeof line))
            return false;
        fst_add_line(line, false);
    }
    if (readmit != FST_ONCE) {
        if (!fst_line(FBR_ROOT, "alpha", 11, FST_ALPHA2, FBR_LINE_NOW + 3600,
                      line, sizeof line))
            return false;
        fst_add_line(line, readmit == FST_READMIT_FIRST);
    }
    if (revoke_bravo) {
        g_fbr.head.state = ZCL_FLEET_HEAD_OK;
        g_fbr.head.count = 1;
        fbr_root_pub((uint8_t)(0x80 + 12), seed, g_fbr.head.revoked[0]);
    }
    return true;
}

static void fst_close(struct node_db *db)
{
    g_fst_db = NULL;
    fbr_uninstall();
    fleet_tip_cache_reset();
    node_db_close(db);
}

static bool fst_listed(const char *name)
{
    for (size_t i = 0; i < g_fst.machine_count; i++)
        if (strcmp(g_fst.machines[i].name, name) == 0)
            return true;
    return false;
}

static const struct fleet_status_machine *fst_machine(const char *name)
{
    for (size_t i = 0; i < g_fst.machine_count; i++)
        if (strcmp(g_fst.machines[i].name, name) == 0)
            return &g_fst.machines[i];
    return NULL;
}

static int test_fleet_status_roster(void)
{
    int failures = 0;
    struct node_db db;
    TEST("fleet status: the roster lists only verified, unrevoked, other "
         "machines, and a line sealed by another root is refused") {
        ASSERT(fst_open(&db, true, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        ASSERT(g_fst.member);
        ASSERT_EQ(g_fst.machine_count, (size_t)2);
        ASSERT(fst_listed("alpha"));
        ASSERT(fst_listed("charlie"));
        ASSERT(!fst_listed("bravo"));   /* revoked */
        ASSERT(!fst_listed("mallory")); /* forged */
        ASSERT(!fst_listed("studio"));  /* this box */
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a box admitted again counts under its newest onion, "
         "whichever row comes first, and the retired onion names nobody") {
        const enum fst_readmit modes[] = { FST_READMIT_LAST,
                                           FST_READMIT_FIRST };
        struct fleet_status_peer peers[1];
        for (size_t m = 0; m < 2; m++) {
            ASSERT(fst_open(&db, false, modes[m]));
            fleet_status_collect(&db, FBD_NOW, &g_fst);
            ASSERT_EQ(g_fst.machine_count, (size_t)3);
            ASSERT_STR_EQ(fst_machine("alpha")->onion, FST_ALPHA2);
            ASSERT_EQ(fst_machine("alpha")->enrolled_at,
                      FBR_LINE_NOW + 3600);
            fst_peer(&peers[0], FST_ALPHA, false); /* the retired onion */
            fst_apply(peers, 1);
            ASSERT_EQ(g_fst.connected_count, (size_t)0);
            ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_ALPHA, false));
            fst_peer(&peers[0], FST_ALPHA2 ":8033", false);
            fst_apply(peers, 1);
            ASSERT_EQ(g_fst.connected_count, (size_t)1);
            ASSERT(fst_machine("alpha")->connected);
            ASSERT(fleet_status_peer_on_roster(&g_fst, FST_ALPHA2, false));
            fst_close(&db);
        }
        PASS();
    }
    TEST("fleet status: a node with no fleet root is not a member and "
         "returns no machines") {
        struct fleet_status_peer peers[1];
        ASSERT(fst_open(&db, false, FST_ONCE));
        g_fbr.present = false;
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_apply(peers, 1);
        ASSERT(!g_fst.member);
        ASSERT_EQ(g_fst.machine_count, (size_t)0);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_NOT_MEMBER);
        ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_ALPHA, false));
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_connections(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[4];
    TEST("fleet status: a clearnet or inbound connection from a roster "
         "machine is not an onion connection") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], "203.0.113.9:8033", false);
        fst_peer(&peers[1], FST_ALPHA, true); /* inbound */
        fst_apply(peers, 2);
        ASSERT_EQ(g_fst.connected_count, (size_t)0);
        ASSERT(!fst_machine("alpha")->connected);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_NONE_CONNECTED);
        ASSERT(!fleet_status_peer_on_roster(&g_fst, "203.0.113.9:8033", false));
        ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_ALPHA, true));
        ASSERT(fleet_status_peer_on_roster(&g_fst, FST_ALPHA ":8033", false));
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a revoked, forged or own onion is not on the "
         "roster") {
        ASSERT(fst_open(&db, true, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_BRAVO, false);
        fst_peer(&peers[1], FST_FORGED, false);
        fst_peer(&peers[2], FST_SELF, false);
        fst_apply(peers, 3);
        ASSERT_EQ(g_fst.connected_count, (size_t)0);
        ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_BRAVO, false));
        ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_FORGED, false));
        ASSERT(!fleet_status_peer_on_roster(&g_fst, FST_SELF, false));
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_agreement(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[4];
    TEST("fleet status: a machine whose hash is our block at the tip agrees, "
         "one above the tip is the phone behind, one below on our chain is "
         "the machine behind, and none of them disagree") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_ALPHA, FST_LOCAL, false, FST_NOW - 5);
        fst_check_above(FST_BRAVO, FST_LOCAL + 40, false, true, false,
                        FST_NOW - 5);
        fst_check(FST_CHARLIE, FST_LOCAL - 3, false, FST_NOW - 5);
        fst_peer(&peers[0], FST_ALPHA ":8033", false);
        fst_peer(&peers[1], FST_BRAVO, false);
        fst_peer(&peers[2], FST_CHARLIE ":8033", false);
        fst_apply(peers, 3);
        ASSERT_EQ(g_fst.connected_count, (size_t)3);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_AGREES);
        ASSERT_EQ(fst_machine("bravo")->agreement, FLEET_STATUS_PHONE_BEHIND);
        ASSERT_EQ(fst_machine("charlie")->agreement,
                  FLEET_STATUS_MACHINE_BEHIND);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        ASSERT(!g_fst.refuses_send);
        /* A machine ahead of us alone settles nothing. */
        fst_apply(&peers[1], 1);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: the same height with a different hash disagrees and "
         "holds a send back, but a lower machine on a fork does not") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        fst_check(FST_CHARLIE, FST_LOCAL - 3, true, FST_NOW - 5);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_peer(&peers[1], FST_CHARLIE, false);
        fst_apply(peers, 2);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        /* alpha's refusal stands with alpha gone; charlie alone, on a fork
         * below our tip, refuses nothing. */
        fst_apply(&peers[1], 1);
        ASSERT(g_fst.refuses_send);
        fst_close(&db);
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_CHARLIE, FST_LOCAL - 3, true, FST_NOW - 5);
        fst_apply(&peers[1], 1);
        ASSERT_EQ(fst_machine("charlie")->agreement, FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(!g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a connected machine with no check, or a check older "
         "than the maximum age, is unknown and never agreement") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_apply(peers, 1); /* connected, never checked */
        ASSERT(fst_machine("alpha")->connected);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_UNKNOWN);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        ASSERT(!g_fst.refuses_send);
        fst_check(FST_ALPHA, FST_LOCAL, false,
                  FST_NOW - FLEET_TIP_MAX_AGE_SECS - 1);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_UNKNOWN);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        fst_check(FST_ALPHA, FST_LOCAL, false,
                  FST_NOW - FLEET_TIP_MAX_AGE_SECS);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_AGREES);
        /* A fork seen long ago still names another block: the refusal it
         * raised stands, because failing to learn is not agreement. */
        fst_check(FST_ALPHA, FST_LOCAL, true,
                  FST_NOW - FLEET_TIP_MAX_AGE_SECS - 1);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

/* Four connections on a fixture connection manager: alpha handshaked, bravo
 * handshaked but disconnecting, charlie still mid-handshake, and this box's
 * own onion inbound. */
static bool fst_fleet_nodes(struct connman *cm, struct p2p_node *nodes[4])
{
    const char *const hosts[] = { FST_ALPHA, FST_BRAVO, FST_CHARLIE,
                                  FST_SELF };
    struct net_address addr;
    memset(cm, 0, sizeof *cm);
    net_manager_init(&cm->manager);
    net_address_init(&addr);
    cm->manager.nodes = zcl_calloc(4, sizeof *cm->manager.nodes, "fst_nodes");
    if (!cm->manager.nodes)
        return false;
    for (size_t i = 0; i < 4; i++) {
        nodes[i] = p2p_node_create(&cm->manager, ZCL_INVALID_SOCKET, &addr,
                                   hosts[i], i == 3);
        if (!nodes[i])
            return false;
        nodes[i]->state = PEER_HANDSHAKE_COMPLETE;
        cm->manager.nodes[cm->manager.num_nodes++] = nodes[i];
    }
    atomic_store(&nodes[1]->disconnect, true);
    nodes[2]->state = PEER_VERSION_SENT;
    return true;
}

static void fst_free_nodes(struct connman *cm, struct p2p_node *nodes[4])
{
    for (size_t i = 0; i < 4; i++)
        if (nodes[i])
            p2p_node_free(nodes[i]);
    free(cm->manager.nodes);
    cm->manager.nodes = NULL;
    cm->manager.num_nodes = 0;
    net_manager_free(&cm->manager);
}

static int test_fleet_status_snapshot(void)
{
    int failures = 0;
    struct node_db db;
    struct connman cm;
    struct p2p_node *nodes[4] = { NULL, NULL, NULL, NULL };
    TEST("fleet status: only handshaken connections that are not "
         "disconnecting count as connected, the filter connman uses") {
        struct fleet_status_peer peers[4];
        ASSERT(fst_open(&db, false, FST_ONCE));
        ASSERT(fst_fleet_nodes(&cm, nodes));
        ASSERT_EQ(fleet_status_peers_snapshot(&cm, peers, 4), (size_t)2);
        ASSERT_STR_EQ(peers[0].host, FST_ALPHA);
        ASSERT(!peers[0].inbound);
        ASSERT(peers[1].inbound);
        ASSERT_EQ(fleet_status_peers_snapshot(NULL, peers, 4), (size_t)0);
        fst_check(FST_ALPHA, FST_LOCAL, false, FST_NOW - 5);
        fst_check(FST_BRAVO, FST_LOCAL, false, FST_NOW - 5);
        fst_check(FST_CHARLIE, FST_LOCAL, false, FST_NOW - 5);
        ASSERT(fleet_status_build(&db, &cm, &g_fst_local, FBD_NOW, FST_NOW,
                                  &g_fst));
        ASSERT_EQ(g_fst.machine_count, (size_t)3);
        ASSERT_EQ(g_fst.connected_count, (size_t)1);
        ASSERT(fst_machine("alpha")->connected);
        ASSERT(!fst_machine("bravo")->connected); /* disconnecting */
        ASSERT(!fst_machine("charlie")->connected); /* mid-handshake */
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        PASS();
    }
    _test_next:;
    fst_free_nodes(&cm, nodes);
    fst_close(&db);
    return failures;
}

static int g_fst_asked;
static char g_fst_asked_key[4][BOOT_FLEET_ROSTER_ONION_MAX];
static bool g_fst_answer;

static bool fst_fetch(const char *onion, int64_t ask_height,
                      struct fleet_tip *out)
{
    if (g_fst_asked < 4)
        (void)snprintf(g_fst_asked_key[g_fst_asked], BOOT_FLEET_ROSTER_ONION_MAX,
                       "%s", onion);
    g_fst_asked++;
    (void)ask_height;
    out->height = FST_LOCAL;
    fst_hash(FST_LOCAL, false, out->hash);
    return g_fst_answer;
}

static int test_fleet_status_schedule(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[3];
    TEST("fleet status: the background step asks one connected machine at "
         "a time, each at most once a minute, and nobody while paused") {
        char key[BOOT_FLEET_ROSTER_ONION_MAX];
        struct fleet_tip t;
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_peer(&peers[1], FST_CHARLIE, false);
        fst_apply(peers, 2); /* bravo is not connected */
        g_fst_asked = 0;
        g_fst_answer = true;
        ASSERT(!fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW, true, fst_fetch));
        ASSERT_EQ(g_fst_asked, 0);
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW, false, fst_fetch));
        ASSERT_EQ(g_fst_asked, 1);
        ASSERT_STR_EQ(g_fst_asked_key[0], FST_ALPHA);
        ASSERT(fleet_status_onion_key(FST_ALPHA, key, sizeof key));
        ASSERT(fleet_tip_cache_get(key, &t));
        ASSERT_EQ(t.height, (int64_t)FST_LOCAL);
        ASSERT_EQ(t.fetched_at, (int64_t)FST_NOW);
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW + 1, false, fst_fetch));
        ASSERT_STR_EQ(g_fst_asked_key[1], FST_CHARLIE);
        ASSERT(!fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW + 2, false, fst_fetch));
        ASSERT(!fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db,
                                    FST_NOW + FLEET_TIP_REFRESH_SECS - 1,
                                    false, fst_fetch));
        ASSERT_EQ(g_fst_asked, 2);
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW + FLEET_TIP_REFRESH_SECS,
                                   false, fst_fetch));
        ASSERT_STR_EQ(g_fst_asked_key[2], FST_ALPHA);
        /* A failed ask is still a try: the machine asked longest ago goes
         * first, so a dead machine is not asked again ahead of the others. */
        g_fst_answer = false;
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db,
                                   FST_NOW + 2 * FLEET_TIP_REFRESH_SECS,
                                   false, fst_fetch));
        ASSERT_STR_EQ(g_fst_asked_key[3], FST_CHARLIE);
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db,
                                   FST_NOW + 2 * FLEET_TIP_REFRESH_SECS + 1,
                                   false, fst_fetch));
        ASSERT_EQ(g_fst_asked, 5);
        ASSERT(!fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db,
                                    FST_NOW + 2 * FLEET_TIP_REFRESH_SECS + 2,
                                    false, fst_fetch));
        ASSERT_EQ(g_fst_asked, 5);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a tip reply must be an object with a height and a "
         "64-digit hash, and an at-block counts only for the height asked") {
        struct fleet_tip t;
        const char *const good =
            "{\"schema\":\"zcl.tip.v1\",\"height\":7,\"hash\":\""
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            "\",\"at\":{\"height\":5,\"hash\":\""
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "\"}}";
        const char *const bad[] = {
            "{\"height\":7,\"hash\":\"abc\"}",
            "{\"height\":-1,\"hash\":\"0000000000000000000000000000000000000000"
            "000000000000000000000000\"}",
            "{\"height\":\"7\",\"hash\":\"00000000000000000000000000000000000000"
            "00000000000000000000000000\"}",
            "{\"height\":7,\"hash\":\"zz00000000000000000000000000000000"
            "000000000000000000000000000000\"}",
            "{\"height\":7,\"hash\":\"0000000000000000000000000000000000000000"
            "000000000000000000000000\",\"at\":{\"height\":5,\"hash\":\"x\"}}",
            "[7]", "" };
        ASSERT(fleet_tip_parse((const uint8_t *)good, strlen(good), 5, &t));
        ASSERT_EQ(t.height, (int64_t)7);
        ASSERT_STR_EQ(t.hash, "abcdef0123456789abcdef0123456789abcdef01234567"
                              "89abcdef0123456789");
        ASSERT(t.has_at);
        ASSERT_EQ(t.at_height, (int64_t)5);
        ASSERT(fleet_tip_parse((const uint8_t *)good, strlen(good), 6, &t));
        ASSERT(!t.has_at); /* it answered a height nobody asked */
        ASSERT(fleet_tip_parse((const uint8_t *)good, strlen(good), 0, &t));
        ASSERT(!t.has_at);
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
            ASSERT(!fleet_tip_parse((const uint8_t *)bad[i], strlen(bad[i]),
                                    5, &t));
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

/* The node's chain as the route sees it. */
static bool fst_hash_at_any(int64_t h, char hex[65], void *ctx)
{
    (void)ctx;
    if (h < 0 || h > 4242)
        return false;
    fst_hash(h, false, hex);
    return true;
}

static const struct fleet_status_local g_fst_chain = {
    .tip = 4242, .hash_at = fst_hash_at_any };

static const char *fst_body(const uint8_t *page)
{
    const char *body = strstr((const char *)page, "\r\n\r\n");
    return body ? body + 4 : "";
}

static int test_fleet_tip_route(void)
{
    int failures = 0;
    TEST("fleet tip: the route answers the tip, the block at an asked "
         "height at or below it, and nothing for a bad height") {
        uint8_t page[512];
        char want[65];
        struct fleet_tip t;
        size_t n = fleet_tip_respond(&g_fst_chain, NULL, page, sizeof page);
        ASSERT(n > 0 && n < sizeof page);
        page[n] = 0;
        ASSERT(strncmp((const char *)page, "HTTP/1.1 200 OK\r\n", 17) == 0);
        ASSERT(fleet_tip_parse((const uint8_t *)fst_body(page),
                               strlen(fst_body(page)), 0, &t));
        fst_hash(4242, false, want);
        ASSERT_EQ(t.height, (int64_t)4242);
        ASSERT_STR_EQ(t.hash, want);
        ASSERT(!t.has_at);
        n = fleet_tip_respond(&g_fst_chain, "4000", page, sizeof page);
        ASSERT(n > 0 && n < sizeof page);
        page[n] = 0;
        ASSERT(fleet_tip_parse((const uint8_t *)fst_body(page),
                               strlen(fst_body(page)), 4000, &t));
        fst_hash(4000, false, want);
        ASSERT(t.has_at);
        ASSERT_STR_EQ(t.at_hash, want);
        n = fleet_tip_respond(&g_fst_chain, "9999", page, sizeof page);
        page[n] = 0;
        ASSERT(fleet_tip_parse((const uint8_t *)fst_body(page),
                               strlen(fst_body(page)), 9999, &t));
        ASSERT(!t.has_at); /* above our tip: nothing to name */
        ASSERT_EQ(fleet_tip_respond(&g_fst_chain, "40x0", page, sizeof page),
                  (size_t)0);
        ASSERT_EQ(fleet_tip_respond(&g_fst_chain, "", page, sizeof page),
                  (size_t)0);
        ASSERT_EQ(fleet_tip_respond(&g_fst_chain, "12345678901", page,
                                    sizeof page), (size_t)0);
        ASSERT_EQ(fleet_tip_respond(NULL, NULL, page, sizeof page), (size_t)0);
        ASSERT_EQ(fleet_tip_respond(&g_fst_chain, NULL, page, 40), (size_t)0);
        PASS();
    }
    TEST("fleet tip: a node with no chain answers nothing, so the caller "
         "returns 404") {
        uint8_t page[512];
        ASSERT_EQ(fleet_tip_serve(page, sizeof page), (size_t)0);
        ASSERT_EQ(fleet_tip_serve_at("100", page, sizeof page), (size_t)0);
        PASS();
    }
    _test_next:;
    return failures;
}

static int g_fst_wire_calls;
static char g_fst_wire_path[64];
static int g_fst_wire_status;
static const char *g_fst_wire_body;
static int g_fst_wire_rc;

static int fst_wire(const char *onion, const char *path,
                    struct onion_fetch_result *res, int timeout_secs)
{
    (void)onion;
    (void)timeout_secs;
    g_fst_wire_calls++;
    (void)snprintf(g_fst_wire_path, sizeof g_fst_wire_path, "%s", path);
    res->status = g_fst_wire_status;
    if (g_fst_wire_body) {
        res->body_len = strlen(g_fst_wire_body);
        res->body = malloc(res->body_len);
        if (!res->body)
            return -1;
        memcpy(res->body, g_fst_wire_body, res->body_len);
    }
    return g_fst_wire_rc;
}

static int test_fleet_tip_fetch(void)
{
    int failures = 0;
    char reply[512];
    TEST("fleet tip: a fetch names the tip height it asks about and takes "
         "only a 200 with a well-formed tip") {
        struct fleet_tip t;
        char h[65], at[65];
        fst_hash(5001, false, h);
        fst_hash(5000, true, at);
        (void)snprintf(reply, sizeof reply,
                       "{\"schema\":\"zcl.tip.v1\",\"height\":5001,"
                       "\"hash\":\"%s\",\"at\":{\"height\":5000,"
                       "\"hash\":\"%s\"}}", h, at);
        fleet_tip_set_transport(fst_wire);
        g_fst_wire_calls = 0;
        g_fst_wire_status = 200;
        g_fst_wire_body = reply;
        g_fst_wire_rc = 0;
        ASSERT(fleet_tip_fetch(FST_ALPHA, 5000, &t));
        ASSERT_STR_EQ(g_fst_wire_path, "/explorer/tip/5000");
        ASSERT_EQ(t.height, (int64_t)5001);
        ASSERT(t.has_at);
        ASSERT_STR_EQ(t.at_hash, at);
        ASSERT(fleet_tip_fetch(FST_ALPHA, 0, &t));
        ASSERT_STR_EQ(g_fst_wire_path, "/explorer/tip");
        ASSERT(!t.has_at);
        g_fst_wire_status = 404;
        ASSERT(!fleet_tip_fetch(FST_ALPHA, 5000, &t));
        g_fst_wire_status = 200;
        g_fst_wire_rc = -1;
        ASSERT(!fleet_tip_fetch(FST_ALPHA, 5000, &t));
        g_fst_wire_rc = 0;
        g_fst_wire_body = "{\"height\":1}";
        ASSERT(!fleet_tip_fetch(FST_ALPHA, 5000, &t));
        g_fst_wire_body = NULL;
        ASSERT(!fleet_tip_fetch(FST_ALPHA, 5000, &t));
        ASSERT(!fleet_tip_fetch(NULL, 5000, &t));
        fleet_tip_set_transport(NULL);
        PASS();
    }
    TEST("fleet tip: the main-loop tick asks nobody while Tor is not ready") {
        fleet_tip_set_transport(fst_wire);
        g_fst_wire_calls = 0;
        fleet_tip_poll_tick();
        fleet_tip_poll_tick();
        ASSERT_EQ(g_fst_wire_calls, 0);
        fleet_tip_set_transport(NULL);
        PASS();
    }
    _test_next:;
    fleet_tip_set_transport(NULL);
    return failures;
}

static int test_fleet_status_ahead(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[3];
    TEST("fleet status: a machine above the tip is asked which block it "
         "holds at our tip height, and another block there disagrees and "
         "holds a send back") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check_above(FST_ALPHA, FST_LOCAL + 1, true, true, true,
                        FST_NOW - 5);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a machine above the tip that names our block there "
         "is only the phone behind, and one that names nothing is unknown") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check_above(FST_ALPHA, FST_LOCAL + 1, true, true, false,
                        FST_NOW - 5);
        fst_check_above(FST_BRAVO, FST_LOCAL + 2, false, false, false,
                        FST_NOW - 5);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_peer(&peers[1], FST_BRAVO, false);
        fst_apply(peers, 2);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_PHONE_BEHIND);
        ASSERT_EQ(fst_machine("bravo")->agreement, FLEET_STATUS_UNKNOWN);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        ASSERT(!g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

/* The node restarts: the cache is gone, node_state stays. */
static void fst_restart(struct node_db *db)
{
    fleet_tip_cache_reset();
    fleet_status_collect(db, FBD_NOW, &g_fst);
    fleet_status_load_refusals(db, &g_fst);
}

static bool fst_hash_none(int64_t h, char hex[65], void *ctx)
{
    (void)h;
    (void)hex;
    (void)ctx;
    return false;
}

/* A chain that forks from ours at height *fork_from: the block at h is ours
 * below that height and a fork's at or above it. */
static bool fst_hash_fork_at(int64_t h, char hex[65], void *ctx)
{
    const int64_t *fork_from = ctx;
    if (h < FST_LOCAL - 100 || h > FST_LOCAL)
        return false;
    fst_hash(h, h >= *fork_from, hex);
    return true;
}

/* A check of the machine with box key `box` naming block h on the chain of
 * `forked`, settled against `local` as the background step does. */
static void fst_settle(struct node_db *db, const uint8_t box[32], int64_t h,
                       bool forked, const struct fleet_status_local *local)
{
    struct fleet_tip t;
    memset(&t, 0, sizeof t);
    t.height = h;
    fst_hash(h, forked, t.hash);
    fleet_status_note_check(db, box, &t, local);
}

static int test_fleet_status_refusal_keeps_highest(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_local local;
    int64_t fork_from = FST_LOCAL + 1;
    uint8_t box[32];
    TEST("fleet status: a refusal keeps the highest height it was raised at, "
         "so a machine back below it on our chain lifts nothing") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        ASSERT(fst_box_of(FST_ALPHA, box));
        local.tip = FST_LOCAL - 10;
        local.hash_at = fst_hash_fork_at;
        local.ctx = &fork_from;
        /* alpha names a fork's block at 100 and is refused at 100. */
        fst_settle(&db, box, FST_LOCAL - 10, true, &local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)(FST_LOCAL - 10));
        /* The phone moves onto a fork from 108 and reaches 110. Alpha returns
         * and names another block at 110: the refusal rises to 110. */
        fork_from = FST_LOCAL - 2;
        local.tip = FST_LOCAL;
        fst_settle(&db, box, FST_LOCAL, false, &local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        /* Alpha resyncs to 105 on the phone's chain: machine_behind, but
         * below the refused 110, so nothing lifts. */
        fst_settle(&db, box, FST_LOCAL - 5, false, &local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        /* A check that reaches 110 on the phone's chain lifts it. */
        fst_settle(&db, box, FST_LOCAL, true, &local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)0);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_standing_refusal(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[2];
    TEST("fleet status: a refusal outlives its check's age and a failed "
         "ask, and lifts only when a later check lands on our chain") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        fst_apply(peers, 1);
        ASSERT(g_fst.refuses_send);
        /* The machine's onion is flooded: every ask fails for an hour. */
        g_fst_answer = false;
        g_fst_asked = 0;
        for (int64_t at = FST_NOW; at <= FST_NOW + 3600; at += 60)
            (void)fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, at, false,
                                      fst_fetch);
        ASSERT(g_fst_asked > 50);
        fleet_status_apply(&g_fst, peers, 1, &g_fst_local, FST_NOW + 3600);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        /* The link drops, as when the phone changes network: the refusal
         * stands, because no check has agreed. */
        fleet_status_apply(&g_fst, peers, 0, &g_fst_local, FST_NOW + 3600);
        ASSERT(!fst_machine("alpha")->connected);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        /* A check on a fork below our tip is no agreement. */
        fst_check(FST_ALPHA, FST_LOCAL - 3, true, FST_NOW + 3600);
        fleet_status_apply(&g_fst, peers, 1, &g_fst_local, FST_NOW + 3601);
        ASSERT(g_fst.refuses_send);
        /* Nor is a check that stops below the refused height, on our chain
         * or not: it says nothing of the block that was refused. */
        fst_check(FST_ALPHA, FST_LOCAL - 3, false, FST_NOW + 3600);
        fleet_status_apply(&g_fst, peers, 1, &g_fst_local, FST_NOW + 3601);
        ASSERT(g_fst.refuses_send);
        /* A later check that lands on our chain lifts it. */
        g_fst_answer = true;
        ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db, FST_NOW + 3700,
                                   false, fst_fetch));
        fleet_status_apply(&g_fst, peers, 1, &g_fst_local, FST_NOW + 3701);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_AGREES);
        ASSERT(!g_fst.refuses_send);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a refusal survives a restart of the node and its "
         "lifting is stored too") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        /* Android kills the node: memory is gone, node_state is kept, and
         * every ask of the machine fails after the restart. */
        fst_restart(&db);
        fst_apply(peers, 1);
        ASSERT(fst_machine("alpha")->connected);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        fst_apply(peers, 0);
        ASSERT(g_fst.refuses_send);
        /* An agreeing check at the refused height lifts it for good. */
        fst_check(FST_ALPHA, FST_LOCAL, false, FST_NOW - 5);
        fst_apply(peers, 1);
        ASSERT(!g_fst.refuses_send);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        fst_restart(&db);
        fst_apply(peers, 1);
        ASSERT(!g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a refusal follows a box admitted again under another "
         "onion") {
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        ASSERT(fst_line(FBR_ROOT, "alpha", 11, FST_ALPHA2,
                        FBR_LINE_NOW + 3600, line, sizeof line));
        fst_add_line(line, false);
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        ASSERT_STR_EQ(fst_machine("alpha")->onion, FST_ALPHA2);
        fst_peer(&peers[0], FST_ALPHA2, false);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_DISAGREES);
        ASSERT(g_fst.refuses_send);
        fst_restart(&db);
        fst_apply(peers, 1);
        ASSERT(g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: an unreadable fleet root is unverifiable, holds a "
         "send back and never reads as no fleet") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        g_fbr.root_fail = true;
        ASSERT(fleet_status_build(&db, NULL, &g_fst_local, FBD_NOW, FST_NOW,
                                  &g_fst));
        ASSERT(g_fst.unverifiable);
        ASSERT(g_fst.member);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        ASSERT(g_fst.refuses_send);
        g_fbr.root_fail = false;
        ASSERT(fleet_status_build(&db, NULL, &g_fst_local, FBD_NOW, FST_NOW,
                                  &g_fst));
        ASSERT(!g_fst.unverifiable);
        ASSERT(!g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: the status build of the running node reloads a "
         "stored refusal after a restart") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        fleet_tip_cache_reset(); /* the node restarts; node_state is kept */
        ASSERT(fleet_status_build(&db, NULL, &g_fst_local, FBD_NOW, FST_NOW,
                                  &g_fst));
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_DISAGREE);
        ASSERT(g_fst.refuses_send);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a refusal whose first save failed is saved again by "
         "the next status build") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        g_fst_db = NULL; /* no database: the save cannot happen */
        fst_check(FST_ALPHA, FST_LOCAL, true, FST_NOW - 5);
        g_fst_db = &db;
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        fleet_status_load_refusals(&db, &g_fst);
        fleet_tip_cache_reset();
        fleet_status_load_refusals(&db, &g_fst);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        fst_close(&db);
        PASS();
    }
    TEST("fleet status: a check judged against no chain, no tip, no block "
         "or a block above the tip neither raises nor lifts a refusal") {
        uint8_t box[32];
        struct fleet_tip fork, same, above;
        const struct fleet_status_local notip = {
            .tip = 0, .hash_at = fst_hash_at };
        const struct fleet_status_local noblock = {
            .tip = FST_LOCAL, .hash_at = fst_hash_none };
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        ASSERT(fst_box_of(FST_ALPHA, box));
        memset(&fork, 0, sizeof fork);
        fork.height = FST_LOCAL;
        fst_hash(FST_LOCAL, true, fork.hash);
        same = fork;
        fst_hash(FST_LOCAL, false, same.hash);
        memset(&above, 0, sizeof above);
        above.height = FST_LOCAL + 1;
        fst_hash(above.height, true, above.hash);
        above.has_at = true;
        above.at_height = FST_LOCAL + 5; /* a height this node does not hold */
        fst_hash(above.at_height, true, above.at_hash);
        fleet_status_note_check(&db, box, &fork, NULL);
        fleet_status_note_check(&db, box, &fork, &notip);
        fleet_status_note_check(&db, box, &fork, &noblock);
        fleet_status_note_check(&db, box, &above, &g_fst_local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)0);
        fleet_status_note_check(&db, box, &fork, &g_fst_local);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        fleet_status_note_check(&db, box, &same, NULL);
        fleet_status_note_check(&db, box, &same, &notip);
        fleet_status_note_check(&db, box, &same, &noblock);
        ASSERT_EQ(fst_refusal_of(FST_ALPHA), (int64_t)FST_LOCAL);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_depth(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[3];
    TEST("fleet status: a machine behind by more than the depth bound does "
         "not count toward agreement") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_peer(&peers[1], FST_BRAVO, false);
        fst_check(FST_ALPHA, FST_LOCAL - FLEET_STATUS_AGREE_DEPTH - 1, false,
                  FST_NOW - 5);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement, FLEET_STATUS_UNKNOWN);
        ASSERT_EQ(fst_machine("alpha")->depth,
                  (int64_t)FLEET_STATUS_AGREE_DEPTH + 1);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_UNCHECKED);
        fst_check(FST_ALPHA, FST_LOCAL - FLEET_STATUS_AGREE_DEPTH, false,
                  FST_NOW - 5);
        fst_apply(peers, 1);
        ASSERT_EQ(fst_machine("alpha")->agreement,
                  FLEET_STATUS_MACHINE_BEHIND);
        ASSERT_EQ(fst_machine("alpha")->depth,
                  (int64_t)FLEET_STATUS_AGREE_DEPTH);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        fst_check(FST_ALPHA, FST_LOCAL - 40, false, FST_NOW - 5);
        fst_check(FST_BRAVO, FST_LOCAL, false, FST_NOW - 5);
        fst_apply(peers, 2);
        ASSERT_EQ(g_fst.verdict, FLEET_STATUS_AGREE);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_fairness(void)
{
    int failures = 0;
    struct node_db db;
    struct fleet_status_peer peers[3];
    TEST("fleet status: the machine asked longest ago is asked next, so a "
         "fast ask never starves the last machine") {
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_peer(&peers[1], FST_BRAVO, false);
        fst_peer(&peers[2], FST_CHARLIE, false);
        fst_apply(peers, 3);
        g_fst_asked = 0;
        g_fst_answer = true;
        for (int i = 0; i < 4; i++)
            ASSERT(fleet_tip_poll_step(&g_fst, &g_fst_local, g_fst_db,
                                       FST_NOW + i * FLEET_TIP_REFRESH_SECS,
                                       false, fst_fetch));
        ASSERT_STR_EQ(g_fst_asked_key[0], FST_ALPHA);
        ASSERT_STR_EQ(g_fst_asked_key[1], FST_BRAVO);
        ASSERT_STR_EQ(g_fst_asked_key[2], FST_CHARLIE);
        ASSERT_STR_EQ(g_fst_asked_key[3], FST_ALPHA);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

#ifdef __linux__
extern int unshare(int flags);
enum { FST_CLONE_NEWUSER = 0x10000000, FST_CLONE_NEWTIME = 0x00000080 };

enum {
    FST_SKEW_SEEN = 0,    /* the age clock shows the shift */
    FST_SKEW_MISSED = 1,  /* it does not */
    FST_SKEW_BROKEN = 6   /* the observer itself failed */
};

/* Exit status of `pid`, or FST_SKEW_BROKEN when it did not exit normally. */
static int fst_exit_of(pid_t pid)
{
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st))
        return FST_SKEW_BROKEN;
    return WEXITSTATUS(st);
}

/* In a child with CLOCK_BOOTTIME shifted six hours ahead of CLOCK_MONOTONIC,
 * as after a suspend, the age clock must show the shift. Returns an
 * FST_SKEW_* value; only FST_SKEW_SEEN observed it. */
static int fst_suspend_child(void)
{
    char map[64];
    int fd;
    pid_t pid;
    unsigned uid = (unsigned)getuid(); /* unshare turns it into the overflow id */
    if (unshare(FST_CLONE_NEWUSER | FST_CLONE_NEWTIME) != 0)
        return 3;
    (void)snprintf(map, sizeof map, "0 %u 1", uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, strlen(map)) < 0)
        return 4;
    close(fd);
    fd = open("/proc/self/timens_offsets", O_WRONLY);
    if (fd < 0 || write(fd, "boottime 21600 0\n", 17) < 0)
        return 5;
    close(fd);
    pid = fork();
    if (pid < 0)
        return FST_SKEW_BROKEN;
    if (pid == 0) {
        int64_t skew = fleet_tip_now_secs() - clock_now_monotonic_ns() / 1000000000;
        _exit(skew >= 21600 - 2 ? FST_SKEW_SEEN : FST_SKEW_MISSED);
    }
    return fst_exit_of(pid);
}
#endif

static int test_fleet_status_clock(void)
{
    int failures = 0;
    TEST("fleet status: cache ages are read on a clock that counts time "
         "spent suspended") {
        ASSERT(fleet_tip_now_secs() > 0);
#ifdef __linux__
        pid_t pid = fork();
        int got;
        ASSERT(pid >= 0);
        if (pid == 0)
            _exit(fst_suspend_child());
        got = fst_exit_of(pid);
        ASSERT(got != FST_SKEW_MISSED);
        ASSERT(got != FST_SKEW_BROKEN);
        if (got != FST_SKEW_SEEN) {
            /* Not observed: reported through the runner's skip channel and
             * never as a pass. */
            printf("SKIP (suspend skew not observed: time namespace setup "
                   "stage %d refused)\n", got);
            goto _test_next;
        }
#else
        printf("SKIP (suspend skew not observed: no time namespaces on "
               "this platform)\n");
        goto _test_next;
#endif
        PASS();
    }
    _test_next:;
    return failures;
}

static int test_fleet_status_rpc_reply(void)
{
    int failures = 0;
    struct node_db db;
    TEST("fleet status: the fleetstatus RPC answers help, and a call reads "
         "the roster and the cache without waiting on a peer") {
        struct json_value out;
        ASSERT(fst_open(&db, false, FST_ONCE));
        json_init(&out);
        ASSERT(fleet_status_rpc(NULL, true, &out));
        json_free(&out);
        json_init(&out);
        ASSERT(fleet_status_rpc(NULL, false, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "schema")),
                      "zcl.fleet_status.v1");
        ASSERT(json_get_bool(json_get(&out, "member")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "verdict")),
                      "none_connected");
        ASSERT(!json_get_bool(json_get(&out, "refuses_send")));
        json_free(&out);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status_reply(void)
{
    int failures = 0;
    struct node_db db;
    TEST("fleet status: the reply names only membership, counts, the "
         "verdict, the send refusal, the roster gate, and per machine a name, "
         "connection and agreement") {
        struct fleet_status_peer peers[1];
        struct json_value out;
        ASSERT(fst_open(&db, false, FST_ONCE));
        fleet_status_collect(&db, FBD_NOW, &g_fst);
        fst_check(FST_ALPHA, FST_LOCAL, false, FST_NOW - 5);
        fst_peer(&peers[0], FST_ALPHA, false);
        fst_apply(peers, 1);
        json_init(&out);
        fleet_status_render(&g_fst, &out);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "verdict")), "agree");
        ASSERT(!json_get_bool(json_get(&out, "refuses_send")));
        ASSERT_EQ(json_get_int(json_get(&out, "machines_total")), 3);
        ASSERT_EQ(json_get_int(json_get(&out, "machines_connected")), 1);
        ASSERT_EQ(json_get_int(json_get(&out, "local_tip")), FST_LOCAL);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "roster_gate")), "default");
        ASSERT(json_get(&out, "roster_enforcing") != NULL);
        ASSERT_EQ(out.num_children, (size_t)10);
        const struct json_value *rows = json_get(&out, "machines");
        ASSERT_EQ(json_size(rows), (size_t)3);
        for (size_t i = 0; i < json_size(rows); i++)
            ASSERT_EQ(json_at(rows, i)->num_children, (size_t)4);
        json_free(&out);
        fst_close(&db);
        PASS();
    }
    _test_next:;
    fbr_uninstall();
    return failures;
}

static int test_fleet_status(void)
{
    int failures = 0;
    failures += test_fleet_status_roster();
    failures += test_fleet_status_connections();
    failures += test_fleet_status_agreement();
    failures += test_fleet_status_snapshot();
    failures += test_fleet_status_schedule();
    failures += test_fleet_tip_route();
    failures += test_fleet_tip_fetch();
    failures += test_fleet_status_ahead();
    failures += test_fleet_status_standing_refusal();
    failures += test_fleet_status_refusal_keeps_highest();
    failures += test_fleet_status_depth();
    failures += test_fleet_status_fairness();
    failures += test_fleet_status_clock();
    failures += test_fleet_status_rpc_reply();
    failures += test_fleet_status_reply();
    return failures;
}

/* ── carriage between roster machines, with no pairing row ──────────────── */

#define FBC_REVOKED 11 /* a member whose box the head comes to revoke */
#define FBC_TTL 3600u

static char g_fbc_onion[80];

static void fbc_sign_as(enum fleet_board_roster_side side, uint8_t id)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(id, seed, pk);
    boot_fleet_board_fleet_test_roster_identity((int)side, seed, pk);
    memset(seed, 0, sizeof seed);
}

/* Each side signs as the box it stands in for. */
static void fbc_boxes(uint8_t asking, uint8_t answering)
{
    fbc_sign_as(FLEET_BOARD_ROSTER_SIDE_ASK, asking);
    fbc_sign_as(FLEET_BOARD_ROSTER_SIDE_ANSWER, answering);
}

/* A key that claims one identity and signs with another's seed. */
static void fbc_forge(enum fleet_board_roster_side side, uint8_t claims,
                      uint8_t signs)
{
    uint8_t seed[32], pk[32], claimed[32];
    fb_test_identity(signs, seed, pk);
    fbr_key(claims, claimed);
    boot_fleet_board_fleet_test_roster_identity((int)side, seed, claimed);
    memset(seed, 0, sizeof seed);
}

static void fbc_ask_begin(struct fbw *w)
{
    mesh_loop_discard(w->asker, w->ask_q, w->f.res_term);
    mesh_loop_discard(w->answerer, w->answer_q, w->f.term_peer.ini);
    mesh_stream_test_reset();
}

/* The OPEN reaches the answering box, it answers, and the answer is committed
 * into `into`. */
static size_t fbc_finish(struct fbw *w, struct node_db *into, size_t *frames)
{
    *frames = 0;
    if (mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return SIZE_MAX;
    boot_fleet_board_fleet_test_serve(); /* the answer, when there is one */
    boot_fleet_board_fleet_test_serve(); /* nothing left: close */
    *frames = mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini,
                             &w->mp, w->asker);
    return boot_fleet_board_fleet_test_drain_into(into);
}

/* One whole roster pull over the real encrypted stream path. */
static size_t fbc_pull(struct fbw *w, struct node_db *into, size_t *frames)
{
    fbc_ask_begin(w);
    if (!boot_fleet_board_fleet_test_pull_roster(&w->svc, w->f.resp_noise_pub))
        return SIZE_MAX;
    return fbc_finish(w, into, frames);
}

/* Refused before a row was read: the CLOSE alone came back, nothing stored. */
static bool fbc_refused(struct fbw *w, struct node_db *into)
{
    size_t frames = 0;
    return fbc_pull(w, into, &frames) == 0 && frames == 1;
}

/* The verdict a raw OPEN on `service` gets, read off the wire. */
static uint8_t fbc_raw_open(struct fbw *w, const char *service,
                            const uint8_t *payload, size_t len)
{
    uint8_t frame[MESH_LOOP_WIRE_MAX], answer[MESH_LOOP_WIRE_MAX];
    uint8_t kind = 0;
    bool more = false;
    fbc_ask_begin(w);
    size_t frame_len = mesh_stream_test_open_frame(1, 4096u, service, payload,
                                                   len, frame, sizeof frame);
    if (frame_len == 0 ||
        !mesh_stream_frame(&w->mp, w->answerer, frame, frame_len, NULL))
        return 0xFFu;
    size_t answer_len = mesh_loop_take(w->answerer, w->answer_q,
                                       w->f.term_peer.ini, answer,
                                       sizeof answer, &more);
    if (!mesh_stream_test_read_header(answer, answer_len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_CLOSE)
        return 0xFEu;
    return answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u];
}

/* One sealed line, byte-identical in `a` and (when named) in `b`. */
static bool fbc_plant(struct node_db *a, struct node_db *b, const char *name,
                      uint8_t signer, int64_t now)
{
    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
    return fbr_line(FBR_ROOT, name, signer, line, sizeof line) &&
           fbr_store_row(a, 1, line, now, FBC_TTL) &&
           (!b || fbr_store_row(b, 1, line, now, FBC_TTL));
}

static void fbc_revoke(uint8_t id)
{
    g_fbr.head.state = ZCL_FLEET_HEAD_OK;
    g_fbr.head.count = 1;
    fbr_key(id, g_fbr.head.revoked[0]);
    boot_fleet_roster_invalidate();
}

/* What `fleet roster revoke` writes: the line's box key, not its signing key. */
static void fbc_revoke_box(uint8_t id)
{
    uint8_t seed[32];
    g_fbr.head.state = ZCL_FLEET_HEAD_OK;
    g_fbr.head.count = 1;
    fbr_root_pub((uint8_t)(0x80 + id), seed, g_fbr.head.revoked[0]);
    memset(seed, 0, sizeof seed);
    boot_fleet_roster_invalidate();
}

static void fbc_unrevoke(void)
{
    memset(&g_fbr.head, 0, sizeof g_fbr.head);
    boot_fleet_roster_invalidate();
}

static int test_fleet_board_roster_carriage_proof(void)
{
    int failures = 0;
    TEST("fleet roster carriage: a proof holds only for its side, network, "
         "session and cursor") {
        struct fleet_board_roster_bind bind, other;
        uint8_t proof[FLEET_BOARD_ROSTER_PROOF_BYTES];
        memset(&bind, 0, sizeof bind);
        memset(bind.network_genesis, 0x11, 32);
        memset(bind.transcript_hash, 0x22, 32);
        bind.connection_generation = 7;
        bind.after = 9;
        fbc_sign_as(FLEET_BOARD_ROSTER_SIDE_ASK, FBR_PEER);
        ASSERT(fleet_board_roster_proof_make(FLEET_BOARD_ROSTER_SIDE_ASK, &bind,
                                             proof));
        ASSERT(fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                              &bind, proof));
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ANSWER,
                                               &bind, proof));
        other = bind;
        memset(other.network_genesis, 0x12, 32);
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                               &other, proof));
        other = bind;
        memset(other.transcript_hash, 0x23, 32);
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                               &other, proof));
        other = bind;
        other.connection_generation = 8;
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                               &other, proof));
        other = bind;
        other.after = 10;
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                               &other, proof));
        /* Another key cannot claim the signature. */
        fbr_key(FBR_MEMBER, proof);
        ASSERT(!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_ASK,
                                               &bind, proof));
        PASS();
    }
    _test_next:;
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    return failures;
}

static int test_fleet_board_roster_carriage(void)
{
    int failures = 0;
    static struct fbw w;
    static struct node_db dest, empty, junk, joined;
    struct fleet_board_post from_a, from_b, pub, late, note;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-carriage-test" };
    struct boot_fleet_board_fleet_counts cb, ca;
    struct boot_fleet_roster_counts rb, ra;
    size_t frames = 0;
    const int64_t now = FBW_NOW;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w) && node_db_open(&dest, ":memory:") &&
                  node_db_open(&empty, ":memory:") &&
                  node_db_open(&junk, ":memory:") &&
                  node_db_open(&joined, ":memory:");
    TEST("fleet roster carriage: two isolated boxes on the owner's roster "
         "exchange a fleet row both ways with no pairing row, and no public "
         "row rides along") {
        ASSERT(opened);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        boot_fleet_board_fleet_test_bind(&w.a);
        fbr_install(FBR_ROOT, false);
        ASSERT(fbc_plant(&w.a, &w.b, "answerbox", FBR_MEMBER, now));
        ASSERT(fbc_plant(&w.a, &w.b, "askbox", FBR_PEER, now));
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "over the roster", 2000, FBC_TTL, 2000, &from_a));
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_PUBLIC, "public",
                        2000, FBC_TTL, 2000, &pub));
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, from_a.id));
        ASSERT(!db_fleet_board_have(&w.b, pub.id));

        boot_fleet_board_fleet_test_new_epoch();
        boot_fleet_board_fleet_test_bind(&w.b);
        ASSERT(fbw_post(&w.b, FBR_PEER, FLEET_BOARD_SCOPE_FLEET,
                        "and back again", 2100, FBC_TTL, 2100, &from_b));
        fbc_boxes(FBR_MEMBER, FBR_PEER);
        ASSERT_EQ(fbc_pull(&w, &w.a, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.a, from_b.id));
        PASS();
    }
    TEST("fleet roster carriage: a joined box holding no row yet arms from "
         "sealed rows alone, then takes the fleet row it set aside") {
        boot_fleet_board_fleet_test_new_epoch();
        boot_fleet_board_fleet_test_bind(&w.a);
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbc_pull(&w, &joined, &frames), (size_t)2);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT(!db_fleet_board_have(&joined, from_a.id));
        ASSERT(ca.deferred > cb.deferred);
        for (int i = 0; i < 6 && !db_fleet_board_have(&joined, from_a.id); i++)
            ASSERT(fbc_pull(&w, &joined, &frames) != SIZE_MAX);
        ASSERT(db_fleet_board_have(&joined, from_a.id));
        ASSERT(db_fleet_board_have(&joined, from_b.id));
        PASS();
    }
    TEST("fleet roster carriage: no root, no sealed row, a row nobody sealed, "
         "a gate switched off and an expired roster all admit nothing") {
        boot_fleet_board_fleet_test_bind(&w.a);
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        /* The positive control: this store does admit this peer. */
        ASSERT_EQ(fbc_pull(&w, &dest, &frames), (size_t)2);
        ASSERT(!fbc_refused(&w, &dest));

        g_fbr.present = false;
        boot_fleet_roster_invalidate();
        ASSERT(fbc_refused(&w, &dest));
        g_fbr.present = true;
        boot_fleet_roster_invalidate();

        boot_fleet_board_fleet_test_bind(&empty);
        ASSERT(fbw_post(&empty, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "no roster here", 2000, FBC_TTL, 2000, &note));
        ASSERT(fbc_refused(&w, &dest));

        boot_fleet_board_fleet_test_bind(&junk);
        ASSERT(fbr_store_row(&junk, 1, "not a sealed line", now, FBC_TTL));
        ASSERT(fbr_member_row(&junk, FBR_OTHER_ROOT, "foreign", FBR_PEER, now));
        ASSERT(fbc_refused(&w, &dest));

        boot_fleet_board_fleet_test_bind(&w.a);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);

        boot_fleet_board_fleet_test_bind_authority(
            &w.f.term_peer.delegation, w.f.genesis, now + FBC_TTL + 1);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        PASS();
    }
    TEST("fleet roster carriage: a peer off the roster, a revoked member, a "
         "forged proof, another network's proof and a peer without the read "
         "role get no fleet row") {
        uint8_t other_genesis[32];
        boot_fleet_board_fleet_test_bind(&w.a);

        fbc_boxes(FBR_STRANGER, FBR_MEMBER);
        boot_fleet_roster_counts(&rb);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.non_member, rb.non_member + 1);

        fbc_boxes(FBR_PEER, FBR_MEMBER);
        fbc_revoke(FBR_PEER);
        ASSERT(fbc_refused(&w, &dest));
        fbc_revoke_box(FBR_PEER);
        ASSERT(fbc_refused(&w, &dest));
        fbc_unrevoke();

        fbc_forge(FLEET_BOARD_ROSTER_SIDE_ASK, FBR_PEER, FBR_STRANGER);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.roster_refused, cb.roster_refused + 1);

        /* Signed under another network's genesis, judged under this one. */
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        memset(other_genesis, 0x77, 32);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   other_genesis, now);
        fbc_ask_begin(&w);
        ASSERT(boot_fleet_board_fleet_test_pull_roster(&w.svc,
                                                       w.f.resp_noise_pub));
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbc_finish(&w, &dest, &frames), (size_t)0);
        ASSERT_EQ(frames, (size_t)1);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.roster_refused, cb.roster_refused + 1);

        g_fbw_deny_read = true;
        boot_fleet_board_fleet_counts(&cb);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.role_refused, cb.role_refused + 1);
        g_fbw_deny_read = false;
        PASS();
    }
    TEST("fleet roster carriage: the plain board service still refuses an "
         "unpaired peer, and the roster service refuses a pull with no proof") {
        uint8_t pull[FLEET_BOARD_FLEET_PULL_BYTES];
        memset(pull, 0, sizeof pull);
        pull[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_PULL;
        pull[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
        boot_fleet_board_fleet_test_bind(&w.a);
        ASSERT_EQ(fbc_raw_open(&w, FLEET_BOARD_FLEET_SERVICE_NAME, pull,
                               sizeof pull),
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(fbc_raw_open(&w, FLEET_BOARD_ROSTER_SERVICE_NAME, pull,
                               sizeof pull),
                  MESH_STREAM_REFUSED_MALFORMED);
        PASS();
    }
    TEST("fleet roster carriage: an armed asking box drops a whole answer from "
         "a box off its roster or with a forged proof, and moves no cursor") {
        boot_fleet_board_fleet_test_bind(&w.a);
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "for members", 2200, FBC_TTL, 2200, &late));
        fbc_boxes(FBR_PEER, FBR_STRANGER);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)0);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.answer_refused, cb.answer_refused + 1);
        ASSERT(!db_fleet_board_have(&w.b, late.id));

        fbc_boxes(FBR_PEER, FBR_MEMBER);
        fbc_forge(FLEET_BOARD_ROSTER_SIDE_ANSWER, FBR_MEMBER, FBR_STRANGER);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)0);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.answer_refused, cb.answer_refused + 1);
        ASSERT(!db_fleet_board_have(&w.b, late.id));

        fbc_boxes(FBR_PEER, FBR_MEMBER);
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, late.id));
        PASS();
    }
    TEST("fleet roster carriage: a row a member wrote before revocation "
         "arrives, a row it writes after is refused from any carrier") {
        boot_fleet_board_fleet_test_bind(&w.a);
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        ASSERT(fbc_plant(&w.a, &w.b, "goner", FBC_REVOKED, now));
        ASSERT(fbw_post(&w.a, FBC_REVOKED, FLEET_BOARD_SCOPE_FLEET,
                        "before revocation", 2300, FBC_TTL, 2300, &note));
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, note.id));

        fbc_revoke_box(FBC_REVOKED);
        ASSERT(fbw_post(&w.a, FBC_REVOKED, FLEET_BOARD_SCOPE_FLEET,
                        "after revocation", 2400, FBC_TTL, 2400, &late));
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbc_pull(&w, &w.b, &frames), (size_t)0);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT(ca.deferred > cb.deferred);
        ASSERT(!db_fleet_board_have(&w.b, late.id));
        fbc_unrevoke();
        PASS();
    }
    _test_next:;
    g_fbw_deny_read = false;
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity(2, NULL, NULL);
    fbr_uninstall();
    fbw_close(&w);
    if (dest.open)
        node_db_close(&dest);
    if (empty.open)
        node_db_close(&empty);
    if (junk.open)
        node_db_close(&junk);
    if (joined.open)
        node_db_close(&joined);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* The onion every stub line claims. A box is never its own peer here. */
static bool fbc_endpoint_cb(const char *line, const uint8_t root[32],
                            char *onion, size_t cap, bool *self, void *ctx)
{
    (void)line;
    (void)root;
    (void)ctx;
    (void)snprintf(onion, cap, "%s", g_fbc_onion);
    *self = false;
    return true;
}

static const struct zcl_fleet_roster_provider g_fbc_provider = {
    .root = fbr_root_cb, .verify = fbr_verify_cb, .head = fbr_head_cb,
    .each_line = fbr_each_cb, .endpoint = fbc_endpoint_cb, .ctx = NULL,
    .name = "fleet-board-carriage-test" };

static int test_fleet_board_roster_carriage_lane(void)
{
    int failures = 0;
    static struct fbw w;
    static struct node_db dest, joined;
    struct fleet_board_post note, paired;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-carriage-lane-test" };
    struct boot_fleet_board_fleet_counts cb, ca;
    uint8_t onion_pub[32];
    size_t frames = 0;
    const int64_t now = FBW_NOW;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    bool opened = fbw_open(&w) && node_db_open(&dest, ":memory:") &&
                  node_db_open(&joined, ":memory:");
    TEST("fleet roster carriage lane: the real lane asks the session at a "
         "sealed line's onion, and nobody when the address, the gate or the "
         "root says otherwise") {
        ASSERT(opened);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        boot_fleet_board_fleet_test_bind(&w.a);
        fbr_install(FBR_ROOT, false);
        zcl_fleet_roster_provider_install(&g_fbc_provider);
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        fbr_key(FBR_MEMBER, onion_pub);
        ASSERT(onion_v3_address_from_pubkey(onion_pub, g_fbc_onion));
        ASSERT(fbc_plant(&w.a, NULL, "answerbox", FBR_MEMBER, now));
        ASSERT(fbc_plant(&w.a, NULL, "askbox", FBR_PEER, now));
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET, "by the lane",
                        2000, FBC_TTL, 2000, &note));
        /* The joined box holds the answering machine's line, as `fleet import`
         * leaves it, and no roster row. */
        ASSERT(fbr_line(FBR_ROOT, "answerbox", FBR_MEMBER, g_fbr.lines[0],
                        sizeof g_fbr.lines[0]));
        g_fbr.n_lines = 1;

        /* No session is at that onion: nothing is sent to anybody. */
        fbc_ask_begin(&w);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &joined,
                                                               now),
                  (size_t)0);
        ASSERT_EQ(mesh_stream_test_live_count(FLEET_BOARD_ROSTER_SERVICE_NAME),
                  (size_t)0);

        /* The asking node's peer is at that onion. The lane's onions are read
         * again once the bind forgets them. */
        ASSERT(net_addr_from_onion(g_fbc_onion, &w.asker->addr.svc.addr));
        boot_fleet_board_fleet_test_bind(&w.a);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &joined,
                                                               now),
                  (size_t)0);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        g_fbr.present = false;
        boot_fleet_roster_invalidate();
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &joined,
                                                               now),
                  (size_t)0);
        g_fbr.present = true;
        boot_fleet_roster_invalidate();

        fbc_ask_begin(&w);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &joined,
                                                               now),
                  (size_t)1);
        /* A pull under way is not asked twice. */
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &joined,
                                                               now),
                  (size_t)0);
        ASSERT_EQ(fbc_finish(&w, &joined, &frames), (size_t)2);
        /* Both boxes share this process, so the answering half's learned peer
         * would now answer the lane too: the rest goes straight at the peer. */
        for (int i = 0; i < 6 && !db_fleet_board_have(&joined, note.id); i++)
            ASSERT(fbc_pull(&w, &joined, &frames) != SIZE_MAX);
        ASSERT(db_fleet_board_have(&joined, note.id));
        PASS();
    }
    TEST("fleet roster carriage lane: a session that proved a member key is "
         "asked back, until the key is revoked") {
        memset(&w.asker->addr.svc.addr, 0, sizeof w.asker->addr.svc.addr);
        boot_fleet_board_fleet_test_bind(&w.a);
        fbc_ask_begin(&w);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &w.a,
                                                               now),
                  (size_t)0);
        ASSERT(fbc_pull(&w, &dest, &frames) != SIZE_MAX);
        fbc_ask_begin(&w);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &w.a,
                                                               now),
                  (size_t)1);
        fbc_ask_begin(&w);
        fbc_revoke(FBR_PEER);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &w.a,
                                                               now),
                  (size_t)0);
        fbc_unrevoke();
        PASS();
    }
    TEST("fleet roster carriage lane: a pairing row keeps a peer on the "
         "pairing path, which goes on working exactly as before") {
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        fbc_ask_begin(&w);
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &w.a,
                                                               now),
                  (size_t)0);
        boot_fleet_board_fleet_counts(&cb);
        ASSERT(fbc_refused(&w, &dest));
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.roster_refused, cb.roster_refused + 1);

        /* The same peer over the plain service, roster gate unarmed. */
        ASSERT(fbw_post(&w.a, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET, "as paired",
                        2100, FBC_TTL, 2100, &paired));
        g_fbr.present = false;
        boot_fleet_roster_invalidate();
        boot_fleet_board_fleet_test_new_epoch();
        boot_fleet_board_fleet_test_bind(&w.a);
        ASSERT(fbw_pull(&w, w.box_a, &dest, &frames) >= (size_t)1);
        ASSERT(db_fleet_board_have(&dest, paired.id));
        PASS();
    }
    _test_next:;
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity(2, NULL, NULL);
    fbr_uninstall();
    fbw_close(&w);
    if (dest.open)
        node_db_close(&dest);
    if (joined.open)
        node_db_close(&joined);
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* ── revocation carried as a sealed head row ────────────────────────────── */

/* Each box holds its head where a real box does: the fleet state files under
 * its own XDG_STATE_HOME, switched before that box acts. The head callbacks
 * are the real provider's, so the row goes through the one store path. */
enum { FBH_OWNER = 0, FBH_MEMBER, FBH_JOINER, FBH_WITHHELD, FBH_LONG, FBH_LATE,
       FBH_PAIRED, FBH_BOXES };
static char g_fbh_base[256];
static char g_fbh_saved_xdg[512];
static bool g_fbh_had_xdg;
static char g_fbh_text[FLEET_ENROL_HEAD_TEXT_MAX];

static void fbh_box(int box)
{
    char path[320];
    (void)snprintf(path, sizeof path, "%s/box%d", g_fbh_base, box);
    (void)setenv("XDG_STATE_HOME", path, 1);
    boot_fleet_roster_invalidate();
}

static void fbh_open(void)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    g_fbh_had_xdg = xdg != NULL;
    (void)snprintf(g_fbh_saved_xdg, sizeof g_fbh_saved_xdg, "%s",
                   xdg ? xdg : "");
    test_make_tmpdir(g_fbh_base, sizeof g_fbh_base, "fleet_board", "head");
    fbh_box(FBH_OWNER);
}

static void fbh_close(void)
{
    if (g_fbh_had_xdg)
        (void)setenv("XDG_STATE_HOME", g_fbh_saved_xdg, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
    if (g_fbh_base[0])
        (void)test_rm_rf_recursive(g_fbh_base);
    g_fbh_base[0] = '\0';
}

static void fbh_install(void)
{
    static struct zcl_fleet_roster_provider provider;
    provider = *zcl_fleet_roster_gate_provider();
    provider.root = fbr_root_cb;
    provider.verify = fbr_verify_cb;
    provider.each_line = fbr_each_cb;
    provider.endpoint = NULL;
    provider.name = "fleet-board-head-test";
    fbr_install(FBR_ROOT, false);
    zcl_fleet_roster_provider_install(&provider);
}

/* A head sealed by `root_id` at `seq`, revoking each id's box and signing key,
 * which is what `fleet roster revoke` writes. Left in g_fbh_text. */
static bool fbh_mint(uint8_t root_id, uint64_t seq, const uint8_t *ids,
                     size_t n)
{
    uint8_t keys[64][32], seed[32], pub[32];
    const char *why = NULL;
    if (n * 2 > 64)
        return false;
    for (size_t i = 0; i < n; i++) {
        fbr_root_pub((uint8_t)(0x80 + ids[i]), seed, keys[i * 2]);
        fbr_key(ids[i], keys[i * 2 + 1]);
    }
    fbr_root_pub(root_id, seed, pub);
    bool ok = fleet_head_mint(seq, FBW_NOW, &keys[0][0], n * 2, seed, pub,
                              g_fbh_text, sizeof g_fbh_text, &why);
    memset(seed, 0, sizeof seed);
    return ok;
}

/* What `fleet roster revoke` leaves on the owner's box. */
static bool fbh_owner_revokes(uint64_t seq, const uint8_t *ids, size_t n)
{
    static struct fleet_head head;
    uint8_t seed[32], pub[32];
    const char *why = NULL;
    bool replaced = false;
    fbr_root_pub(FBR_ROOT, seed, pub);
    memset(seed, 0, sizeof seed);
    fbh_box(FBH_OWNER);
    return fbh_mint(FBR_ROOT, seq, ids, n) &&
           fleet_head_import(g_fbh_text, pub, false, &head, &replaced, &why) &&
           replaced;
}

static void fbh_compose(struct fleet_board_post *p, uint8_t who,
                        const char *text, int64_t created_at)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(p, FLEET_BOARD_KIND_NOTE, BOOT_FLEET_ROSTER_HEAD_AGENT, text,
                    (uint64_t)created_at, FBC_TTL);
    fb_test_scope(p, FLEET_BOARD_SCOPE_FLEET, "");
    (void)fleet_board_post_sign(p, seed, pk);
}

/* A head row planted straight in a store, as a carrier would hold it. */
static bool fbh_plant(struct node_db *db, const char *text, int64_t created_at,
                      struct fleet_board_post *p)
{
    fbh_compose(p, 1, text, created_at);
    return db_fleet_board_post_ingest(db, p, created_at, NULL) == FLEET_BOARD_OK;
}

/* The sequence of the head `box` holds: 0 for none, -1 for a head it cannot
 * trust. */
static int64_t fbh_seq(int box)
{
    static struct fleet_head head;
    uint8_t seed[32], pub[32];
    fbr_root_pub(FBR_ROOT, seed, pub);
    memset(seed, 0, sizeof seed);
    fbh_box(box);
    enum fleet_head_state state = fleet_head_load(pub, &head, NULL);
    if (state == FLEET_HEAD_ABSENT)
        return 0;
    return state == FLEET_HEAD_OK ? (int64_t)head.seq : -1;
}

/* Which store answers. The lane's tick finds the head row to lead with; here
 * each pull stands in for that tick. */
static struct node_db *g_fbh_serving;

static void fbh_serve(struct node_db *db)
{
    g_fbh_serving = db;
    boot_fleet_board_fleet_test_bind(db);
}

/* One whole roster pull with each half on its own box's state. */
static size_t fbh_pull(struct fbw *w, struct node_db *into, int answering,
                       int asking)
{
    fleet_board_roster_pin_refresh(g_fbh_serving, FBW_NOW);
    fbc_ask_begin(w);
    if (!boot_fleet_board_fleet_test_pull_roster(&w->svc, w->f.resp_noise_pub))
        return SIZE_MAX;
    fbh_box(answering);
    if (mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return SIZE_MAX;
    boot_fleet_board_fleet_test_serve();
    boot_fleet_board_fleet_test_serve();
    (void)mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini, &w->mp,
                         w->asker);
    fbh_box(asking);
    return boot_fleet_board_fleet_test_drain_into(into);
}

/* The answering store changes: a new answering process, read from the start. */
static void fbh_answer_from(struct node_db *db)
{
    boot_fleet_board_fleet_test_new_epoch();
    fbh_serve(db);
    fbc_boxes(FBR_PEER, FBR_MEMBER);
}

static int test_fleet_board_head_row_carriage(void)
{
    int failures = 0;
    static struct fbw w;
    static struct node_db dest;
    struct fleet_board_post post, late;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-head-test" };
    struct boot_fleet_roster_counts rb, ra;
    struct boot_fleet_board_fleet_counts cb, ca;
    uint8_t goner[32], peer[32];
    const uint8_t revoked[] = { FBC_REVOKED };
    const int64_t now = FBW_NOW;
    char dir[256] = {0};
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    fbh_open();
    bool opened = fbw_open(&w) && node_db_open(&dest, ":memory:");
    fbr_key(FBC_REVOKED, goner);
    fbr_key(FBR_PEER, peer);
    TEST("fleet head row: the owner revokes member C once, and the head reaches "
         "member B with no file import; C gets no fleet row from B, and rows C "
         "writes afterward are refused at B") {
        ASSERT(opened);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        fbh_serve(&w.a);
        fbh_install();
        ASSERT(fbc_plant(&w.a, &w.b, "answerbox", FBR_MEMBER, now));
        ASSERT(fbc_plant(&w.a, &w.b, "askbox", FBR_PEER, now));
        ASSERT(fbc_plant(&w.a, &w.b, "goner", FBC_REVOKED, now));
        fbh_box(FBH_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&w.b, goner, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 0);

        /* The owner's box: revoke, then its node's publish pass writes the row
         * through the real local publish. */
        ASSERT(fbh_owner_revokes(1, revoked, 1));
        test_make_tmpdir(dir, sizeof dir, "fleet_board", "headowner");
        w.svc.node_db = &w.a;
        w.svc.datadir = dir;
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&w.svc);
        g_fbr.manager = true;
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        ASSERT_EQ(boot_fleet_roster_publish(&w.a, now), (size_t)1);
        ASSERT_EQ(boot_fleet_roster_publish(&w.a, now + 60), (size_t)0);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        g_fbr.manager = false;

        fbc_boxes(FBR_PEER, FBR_MEMBER);
        boot_fleet_roster_counts(&rb);
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)1);
        boot_fleet_roster_counts(&ra);
        ASSERT_EQ(ra.heads_installed, rb.heads_installed + 1);
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 1);
        ASSERT_EQ(boot_fleet_roster_check(&w.b, goner, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&w.b, peer, now),
                  BOOT_FLEET_ROSTER_MEMBER);

        /* B now refuses C, and still answers a member. */
        fbh_serve(&w.b);
        fbc_boxes(FBC_REVOKED, FBR_PEER);
        ASSERT(fbc_refused(&w, &dest));
        fbc_boxes(FBR_MEMBER, FBR_PEER);
        ASSERT(!fbc_refused(&w, &dest));

        /* A row C writes now, carried by an honest box, stops at B. */
        fbh_answer_from(&w.a);
        ASSERT(fbw_post(&w.a, FBC_REVOKED, FLEET_BOARD_SCOPE_FLEET,
                        "after revocation", 2400, FBC_TTL, 2400, &late));
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)0);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT(ca.deferred > cb.deferred);
        ASSERT(!db_fleet_board_have(&w.b, late.id));
        PASS();
    }
    TEST("fleet head row: a replayed older head and a second head at the same "
         "sequence are refused, the row is not kept, and the newer head stays") {
        char older[FLEET_ENROL_HEAD_TEXT_MAX];
        const uint8_t two[] = { FBC_REVOKED, FBR_STRANGER };
        ASSERT(fbh_mint(FBR_ROOT, 1, revoked, 1));
        (void)snprintf(older, sizeof older, "%s", g_fbh_text);
        ASSERT(fbh_owner_revokes(2, two, 2));
        ASSERT(fbh_plant(&w.a, g_fbh_text, 2410, &post));
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)1);
        ASSERT(db_fleet_board_have(&w.b, post.id));
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);

        ASSERT(fbh_plant(&w.a, older, 2411, &post));
        boot_fleet_roster_counts(&rb);
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)0);
        boot_fleet_roster_counts(&ra);
        ASSERT(ra.heads_refused > rb.heads_refused);
        ASSERT_EQ(ra.heads_installed, rb.heads_installed);
        ASSERT(!db_fleet_board_have(&w.b, post.id));
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);

        ASSERT(fbh_mint(FBR_ROOT, 2, revoked, 1));
        ASSERT(fbh_plant(&w.a, g_fbh_text, 2412, &post));
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)0);
        ASSERT(!db_fleet_board_have(&w.b, post.id));
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);
        PASS();
    }
    TEST("fleet head row: a head under another root and a corrupt head are "
         "refused, the row is not kept, and the held head is intact") {
        ASSERT(fbh_mint(FBR_OTHER_ROOT, 9, revoked, 1));
        ASSERT(fbh_plant(&w.a, g_fbh_text, 2420, &post));
        boot_fleet_roster_counts(&rb);
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)0);
        boot_fleet_roster_counts(&ra);
        ASSERT(ra.heads_refused > rb.heads_refused);
        ASSERT(!db_fleet_board_have(&w.b, post.id));
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);

        /* Flipped bytes at the highest sequence yet, and plain junk. */
        ASSERT(fbh_mint(FBR_ROOT, 40, revoked, 1));
        g_fbh_text[sizeof(FLEET_HEAD_PREFIX) + 10] ^= 1;
        const char *corrupt[] = { g_fbh_text, FLEET_HEAD_PREFIX, "not a head" };
        for (size_t i = 0; i < sizeof corrupt / sizeof corrupt[0]; i++) {
            ASSERT(fbh_plant(&w.a, corrupt[i], 2421 + (int64_t)i, &post));
            ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)0);
            ASSERT(!db_fleet_board_have(&w.b, post.id));
            ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);
            /* The gate still reads a good head, not a failed one. */
            ASSERT_EQ(boot_fleet_roster_check(&w.b, goner, now),
                      BOOT_FLEET_ROSTER_NOT_MEMBER);
            ASSERT_EQ(boot_fleet_roster_check(&w.b, peer, now),
                      BOOT_FLEET_ROSTER_MEMBER);
        }
        PASS();
    }
    TEST("fleet head row: a box with no root, or with its gate off, takes "
         "nothing and keeps no row; a root it cannot read defers; and the P2P "
         "frame path takes no head row at all") {
        struct fbr_p2p x;
        static uint8_t frame[FLEET_BOARD_FRAME_MAGIC_BYTES + 1 +
                             FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES];
        size_t len = 0;
        ASSERT(fbh_mint(FBR_ROOT, 3, revoked, 1));
        fbh_compose(&post, 1, g_fbh_text, 2430);
        fbh_box(FBH_MEMBER);
        g_fbr.present = false;
        ASSERT_EQ(boot_fleet_roster_screen_post(&w.b, &post, now),
                  FLEET_BOARD_ERR_SCOPE);
        g_fbr.present = true;
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_OFF);
        ASSERT_EQ(boot_fleet_roster_screen_post(&w.b, &post, now),
                  FLEET_BOARD_ERR_SCOPE);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        g_fbr.root_fail = true;
        ASSERT_EQ(boot_fleet_roster_screen_post(&w.b, &post, now),
                  FLEET_BOARD_ERR_ROLE);
        g_fbr.root_fail = false;
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);

        /* A good head at the next sequence, off the flood: not taken. */
        fbr_p2p_init(&x, &w.b, 54);
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&x.svc);
        ASSERT_EQ(fleet_board_frame_encode_post(&post, frame, sizeof frame, &len),
                  FLEET_BOARD_OK);
        ASSERT(boot_fleet_board_frame(&x.mp, &x.node, frame, len, NULL));
        ASSERT(!db_fleet_board_have(&w.b, post.id));
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 2);
        boot_fleet_board_shutdown();

        /* The same row over carriage is taken, so only the path refused it. */
        ASSERT(db_fleet_board_post_ingest(&w.a, &post, 2430, NULL) ==
               FLEET_BOARD_OK);
        ASSERT_EQ(fbh_pull(&w, &w.b, FBH_OWNER, FBH_MEMBER), (size_t)1);
        ASSERT_EQ(fbh_seq(FBH_MEMBER), 3);
        PASS();
    }
    _test_next:;
    g_fbw_deny_read = false;
    boot_fleet_board_shutdown();
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity(2, NULL, NULL);
    fbr_uninstall();
    fbw_close(&w);
    if (dest.open)
        node_db_close(&dest);
    if (dir[0])
        (void)test_rm_rf_recursive(dir);
    fbh_close();
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* Sealed lines for the owner, a member and the machine that gets revoked. */
static bool fbh_plant_roster(struct node_db *a, struct node_db *b, int64_t now)
{
    return fbc_plant(a, b, "answerbox", FBR_MEMBER, now) &&
           fbc_plant(a, b, "askbox", FBR_PEER, now) &&
           fbc_plant(a, b, "goner", FBC_REVOKED, now);
}

static int test_fleet_board_head_row_bootstrap(void)
{
    int failures = 0;
    static struct fbw w;
    static struct node_db joined, withheld, thin, longb, paged, late, late_src,
        paired_src, paired_dest;
    struct fleet_board_post post, note;
    struct zcl_fleet_role_checker checker = {
        .allow = fbw_role_check, .name = "fleet-board-head-boot-test" };
    uint8_t goner[32], peer[32];
    const uint8_t revoked[] = { FBC_REVOKED };
    const int64_t now = FBW_NOW;
    size_t frames = 0;
    g_fbw_deny_read = false;
    zcl_fleet_role_checker_install(&checker);
    fbh_open();
    bool opened = fbw_open(&w) && node_db_open(&joined, ":memory:") &&
                  node_db_open(&withheld, ":memory:") &&
                  node_db_open(&thin, ":memory:") &&
                  node_db_open(&longb, ":memory:") &&
                  node_db_open(&paged, ":memory:") &&
                  node_db_open(&late, ":memory:") &&
                  node_db_open(&late_src, ":memory:") &&
                  node_db_open(&paired_src, ":memory:") &&
                  node_db_open(&paired_dest, ":memory:");
    fbr_key(FBC_REVOKED, goner);
    fbr_key(FBR_PEER, peer);
    TEST("fleet head row: a box bootstrapping from an answer holding an old "
         "roster row and the head never lists the revoked key") {
        ASSERT(opened);
        boot_fleet_board_fleet_test_bind_authority(&w.f.term_peer.delegation,
                                                   w.f.genesis, now);
        fbh_install();
        fbh_serve(&w.a);
        fbc_boxes(FBR_PEER, FBR_MEMBER);
        ASSERT(fbh_plant_roster(&w.a, NULL, now));
        ASSERT(fbh_owner_revokes(1, revoked, 1));
        ASSERT(fbh_plant(&w.a, g_fbh_text, 2401, &post));
        ASSERT_EQ(fbh_seq(FBH_JOINER), 0);
        ASSERT_EQ(fbh_pull(&w, &joined, FBH_OWNER, FBH_JOINER), (size_t)4);
        ASSERT_EQ(fbh_seq(FBH_JOINER), 1);
        ASSERT_EQ(boot_fleet_roster_check(&joined, goner, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&joined, peer, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        PASS();
    }
    TEST("fleet head row: the real lane's tick finds the row an answer leads "
         "with, and a pull past that row pays nothing") {
        static struct db_fleet_board_post row;
        fbh_box(FBH_OWNER);
        fbh_serve(&w.a);
        ASSERT(!fleet_board_roster_pinned_head(&w.a, 0, &row));
        ASSERT_EQ(boot_fleet_board_fleet_test_pull_roster_lane(&w.svc, &w.a, now),
                  (size_t)0);
        ASSERT(fleet_board_roster_pinned_head(&w.a, 0, &row));
        ASSERT(boot_fleet_roster_is_head_row(&row.post));
        ASSERT(!fleet_board_roster_pinned_head(&w.a, row.arrival, &row));
        PASS();
    }
    TEST("fleet head row: a hostile answer that withholds the head arms a fresh "
         "box with the revoked key, and the next honest answer overrides it "
         "within one pull") {
        ASSERT(fbh_plant_roster(&thin, NULL, now));
        boot_fleet_board_fleet_test_new_epoch();
        fbh_serve(&thin);
        fbc_boxes(FBR_PEER, FBC_REVOKED);
        /* The answering box holds no head of its own here. */
        ASSERT_EQ(fbh_pull(&w, &withheld, FBH_WITHHELD, FBH_WITHHELD), (size_t)3);
        ASSERT_EQ(fbh_seq(FBH_WITHHELD), 0);
        ASSERT_EQ(boot_fleet_roster_check(&withheld, goner, now),
                  BOOT_FLEET_ROSTER_MEMBER);

        fbh_answer_from(&w.a);
        ASSERT(fbh_pull(&w, &withheld, FBH_OWNER, FBH_WITHHELD) != SIZE_MAX);
        ASSERT_EQ(fbh_seq(FBH_WITHHELD), 1);
        ASSERT_EQ(boot_fleet_roster_check(&withheld, goner, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        /* And that revoked box's next answer is dropped whole. */
        boot_fleet_board_fleet_test_new_epoch();
        fbh_serve(&thin);
        fbc_boxes(FBR_PEER, FBC_REVOKED);
        struct boot_fleet_board_fleet_counts cb, ca;
        boot_fleet_board_fleet_counts(&cb);
        ASSERT_EQ(fbh_pull(&w, &withheld, FBH_WITHHELD, FBH_WITHHELD), (size_t)0);
        boot_fleet_board_fleet_counts(&ca);
        ASSERT_EQ(ca.answer_refused, cb.answer_refused + 1);
        PASS();
    }
    TEST("fleet head row: on a board longer than one page the head still comes "
         "first, ahead of the rows that arm the box") {
        char text[64];
        ASSERT(fbh_plant_roster(&longb, NULL, now));
        for (int i = 0; i < (int)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX + 4; i++) {
            (void)snprintf(text, sizeof text, "filler %d", i);
            ASSERT(fbw_post(&longb, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET, text,
                            2000 + i, FBC_TTL, 2000 + i, &note));
        }
        ASSERT(fbh_mint(FBR_ROOT, 1, revoked, 1));
        ASSERT(fbh_plant(&longb, g_fbh_text, 2401, &post));
        fbh_answer_from(&longb);
        ASSERT(fbh_pull(&w, &paged, FBH_OWNER, FBH_LONG) != SIZE_MAX);
        ASSERT_EQ(fbh_seq(FBH_LONG), 1);
        ASSERT_EQ(boot_fleet_roster_check(&paged, goner, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        ASSERT_EQ(boot_fleet_roster_check(&paged, peer, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        PASS();
    }
    TEST("fleet head row: a member that never received the head still works, "
         "and picks it up on the next pull") {
        ASSERT(fbh_plant_roster(&late_src, &late, now));
        ASSERT(fbw_post(&late_src, FBR_MEMBER, FLEET_BOARD_SCOPE_FLEET,
                        "before the head", 2300, FBC_TTL, 2300, &note));
        fbh_answer_from(&late_src);
        ASSERT_EQ(fbh_pull(&w, &late, FBH_OWNER, FBH_LATE), (size_t)1);
        ASSERT(db_fleet_board_have(&late, note.id));
        ASSERT_EQ(fbh_seq(FBH_LATE), 0);
        ASSERT_EQ(boot_fleet_roster_check(&late, goner, now),
                  BOOT_FLEET_ROSTER_MEMBER);
        ASSERT(fbh_plant(&late_src, g_fbh_text, 2401, &post));
        ASSERT_EQ(fbh_pull(&w, &late, FBH_OWNER, FBH_LATE), (size_t)1);
        ASSERT(db_fleet_board_have(&late, post.id));
        ASSERT_EQ(fbh_seq(FBH_LATE), 1);
        ASSERT_EQ(boot_fleet_roster_check(&late, goner, now),
                  BOOT_FLEET_ROSTER_NOT_MEMBER);
        PASS();
    }
    TEST("fleet head row: on the pairing lane, where nothing leads the answer, a "
         "post by the revoked key numbered ahead of the head is judged under it") {
        /* One state for both halves: the answering box holds no head file. */
        ASSERT(mesh_term_pair_row(&w.f, &w.f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                  FBW_PAIRING_EXPIRES));
        g_fbr.remap = true;
        fbr_key(FBR_PEER, g_fbr.remap_from);
        memcpy(g_fbr.remap_to, w.f.term_peer.delegation.online_pubkey, 32);
        ASSERT(fbh_plant_roster(&paired_src, &paired_dest, now));
        ASSERT(fbw_post(&paired_src, FBC_REVOKED, FLEET_BOARD_SCOPE_FLEET,
                        "numbered first", 2390, FBC_TTL, 2390, &note));
        ASSERT(fbh_plant(&paired_src, g_fbh_text, 2401, &post));
        fbh_box(FBH_PAIRED);
        boot_fleet_board_fleet_test_new_epoch();
        boot_fleet_board_fleet_test_bind(&paired_src);
        ASSERT_EQ(fbw_pull(&w, w.box_a, &paired_dest, &frames), (size_t)1);
        ASSERT(db_fleet_board_have(&paired_dest, post.id));
        ASSERT_EQ(fbh_seq(FBH_PAIRED), 1);
        ASSERT(!db_fleet_board_have(&paired_dest, note.id));
        PASS();
    }
    _test_next:;
    g_fbw_deny_read = false;
    boot_fleet_board_fleet_test_roster_identity(1, NULL, NULL);
    boot_fleet_board_fleet_test_roster_identity(2, NULL, NULL);
    fbr_uninstall();
    fbw_close(&w);
    struct node_db *dbs[] = { &joined, &withheld, &thin, &longb, &paged, &late,
                              &late_src, &paired_src, &paired_dest };
    for (size_t i = 0; i < sizeof dbs / sizeof dbs[0]; i++)
        if (dbs[i]->open)
            node_db_close(dbs[i]);
    fbh_close();
    zcl_fleet_role_checker_install_permissive_for_testing();
    return failures;
}

/* The owner's publish pass: once per new head and once per republish period; a
 * box that is not the owner's, or a head over one row, writes nothing. */
static int test_fleet_board_head_row_publish(void)
{
    int failures = 0;
    struct fb_rpc_env env;
    bool open = false;
    char dir[256] = {0};
    const uint8_t one[] = { FBC_REVOKED };
    uint8_t many[24]; /* 48 keys: past the 44 one row holds */
    fbh_open();
    TEST("fleet head row: the manager publishes its head once, again only for a "
         "new head or a republish, not over one row, and never a bad line") {
        const int64_t now = (int64_t)platform_time_wall_time_t();
        struct fleet_board_post junk;
        struct db_fleet_board_post newest;
        open = fb_rpc_env_open(&env);
        ASSERT(open);
        test_make_tmpdir(dir, sizeof dir, "fleet_board", "headpub");
        env.svc.datadir = dir;
        fbh_install();

        /* No head: nothing to publish, and no opt-in: nothing at all. */
        g_fbr.manager = true;
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)0);
        ASSERT(fbh_owner_revokes(1, one, 1));
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)0);
        boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_ON);

        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now), (size_t)1);
        ASSERT(boot_fleet_roster_newest_head_row(&env.db, now, &newest));
        ASSERT_STR_EQ(newest.post.text, g_fbh_text);
        ASSERT_EQ(boot_fleet_roster_publish(&env.db, now + 60), (size_t)0);

        /* A member box publishes nothing. */
        g_fbr.manager = false;
        ASSERT_EQ(boot_fleet_roster_publish(
                      &env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 100),
                  (size_t)0);
        g_fbr.manager = true;
        ASSERT_EQ(boot_fleet_roster_publish(
                      &env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 100),
                  (size_t)1);

        /* A new head does not wait for the republish. */
        const uint8_t two[] = { FBC_REVOKED, FBR_STRANGER };
        ASSERT(fbh_owner_revokes(2, two, 2));
        ASSERT_EQ(boot_fleet_roster_publish(
                      &env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 160),
                  (size_t)1);

        /* Over the note bound: still a good head here, and not on the board. */
        for (size_t i = 0; i < sizeof many; i++)
            many[i] = (uint8_t)(0x20 + i);
        ASSERT(fbh_owner_revokes(3, many, sizeof many));
        ASSERT(strlen(g_fbh_text) >= ZCL_FLEET_HEAD_LINE_MAX);
        ASSERT_EQ(fbh_seq(FBH_OWNER), 3);
        ASSERT_EQ(boot_fleet_roster_publish(
                      &env.db, now + BOOT_FLEET_ROSTER_REPUBLISH_S + 220),
                  (size_t)0);

        /* The local RPC is an ingest path too. */
        fb_test_compose(&junk, FLEET_BOARD_KIND_NOTE,
                        BOOT_FLEET_ROSTER_HEAD_AGENT, "not a head",
                        (uint64_t)now, 3600);
        fb_test_scope(&junk, FLEET_BOARD_SCOPE_FLEET, "");
        ASSERT_EQ(boot_fleet_board_publish(&junk, now),
                  FLEET_BOARD_ERR_SIGNATURE);
        ASSERT(!db_fleet_board_have(&env.db, junk.id));
        PASS();
    } _test_next:;
    boot_fleet_roster_set_gate(BOOT_FLEET_ROSTER_GATE_DEFAULT);
    fbr_uninstall();
    if (open)
        fb_rpc_env_close(&env);
    if (dir[0])
        test_rm_rf_recursive(dir);
    fbh_close();
    return failures;
}

int test_fleet_board(void)
{
    int failures = 0;
    /* The role gate is held open here; the gate itself is proven in
     * test_fleet_board_public_no_grant_needed() and fleet_roles. */
    zcl_fleet_role_checker_install_permissive_for_testing();
    failures += test_fleet_board_codec();
    failures += test_fleet_board_bounds();
    failures += test_fleet_board_frames();
    failures += test_fleet_board_store();
    failures += test_fleet_board_agents_kind();
    failures += test_fleet_board_kind_ceiling_refuses_unknown();
    failures += test_fleet_board_transaction_busy();
    failures += test_fleet_board_busy_append_names_contention();
    failures += test_fleet_board_permanent_refusal_quarantines();
    failures += test_fleet_board_store_boundaries();
    failures += test_fleet_board_byte_boundary();
    failures += test_fleet_board_corrupt_reads();
    failures += test_fleet_board_inventory_pages();
    failures += test_fleet_board_wiki();
    failures += test_fleet_board_two_nodes();
    failures += test_fleet_wiki_review_convergence();
    failures += test_fleet_wiki_review_post_ingress_convergence();
    failures += test_fleet_wiki_review_budget();
    failures += test_fleet_board_waits_for_peer_handshake();
    failures += test_fleet_board_peer_churn_limits();
    failures += test_fleet_board_rpc_verification();
    failures += test_fleet_board_rpc_concurrency();
    failures += test_fleet_board_rpc_scope_default();
    failures += test_fleet_board_rpc_room_boundary();
    failures += test_fleet_board_rpc_created_at();
    failures += test_fleet_board_rpc_fleet_page();
    failures += test_fleet_board_native_busy();
    failures += test_fleet_board_ingest_wait_bounded();
    failures += test_fleet_board_durable_wiki();
    failures += test_fleet_board_local_capacity_does_not_score_peer();
    failures += test_fleet_board_peer_inventory_cursor();
    failures += test_fleet_board_scope_codec();
    failures += test_fleet_board_scope_store();
    failures += test_fleet_board_reclaim_expired();
    failures += test_fleet_board_fleet_carriage();
    for (unsigned change = 0; change < 4; change++)
        failures += test_fleet_board_delayed_authority(change);
    failures += test_fleet_board_fleet_cursor_resumes();
    failures += test_fleet_board_fleet_cursor_heals_lost_rows();
    failures += test_fleet_board_fleet_cursor_table_full();
    failures += test_fleet_board_fleet_carriage_gap_free();
    failures += test_fleet_board_fleet_wiki_full_is_final();
    failures += test_fleet_board_fleet_wiki_carriage();
    failures += test_fleet_board_fleet_quota();
    failures += test_fleet_board_roster_membership();
    failures += test_fleet_board_roster_revoked_box();
    failures += test_fleet_board_roster_root_standing();
    failures += test_fleet_board_roster_refused_root_no_notes();
    failures += test_fleet_board_roster_lifetime();
    failures += test_fleet_board_roster_revoked_after_lapse();
    failures += test_fleet_board_roster_bounds();
    failures += test_fleet_board_roster_row_is_an_old_row();
    failures += test_fleet_board_roster_p2p_ingress();
    failures += test_fleet_board_roster_ingress_seal();
    failures += test_fleet_board_roster_flood_scan();
    failures += test_fleet_board_roster_flood_ingest();
    failures += test_fleet_board_roster_flood_bound();
    failures += test_fleet_board_roster_flood_no_root();
    failures += test_fleet_board_roster_flood_publish();
    failures += test_fleet_board_roster_arming();
    failures += test_fleet_board_roster_gate_flag();
    failures += test_fleet_board_roster_read_failure();
    failures += test_fleet_board_roster_cost();
    failures += test_fleet_board_roster_publish();
    failures += test_fleet_board_roster_relay();
    failures += test_fleet_board_roster_dial();
    failures += test_fleet_board_roster_dial_board();
    failures += test_fleet_board_roster_dial_flood();
    failures += test_fleet_board_roster_dial_junk();
    failures += test_fleet_board_roster_dial_guards();
    failures += test_fleet_board_roster_dial_own_key();
    failures += test_fleet_board_roster_carriage_proof();
    failures += test_fleet_board_roster_carriage();
    failures += test_fleet_board_roster_carriage_lane();
    failures += test_fleet_board_head_row_carriage();
    failures += test_fleet_board_head_row_bootstrap();
    failures += test_fleet_board_head_row_publish();
    failures += test_fleet_status();
    failures += test_fleet_board_public_no_grant_needed();
    /* Leave the process as this group found it: the next group in the same
     * binary must not inherit an open gate. */
    zcl_fleet_role_checker_install(NULL);
    return failures;
}
