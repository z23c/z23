/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The fleet AI message board and wiki: codec, signature, caps, store, and the
 * two-node gossip path.
 *
 * The gossip proof drives TWO independent node databases through the REAL
 * frame codec, in the order the wire uses them: A posts, A announces an
 * inventory frame, B decides what it is missing, B sends a GET, A serves a
 * POST frame, B ingests and verifies. Every byte that crosses is the byte the
 * wire would carry. What this does NOT prove is the socket underneath it —
 * see the group's closing note. */

#include "test/test_core.h"

#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "session/fleet_board_proto.h"
#include "chain/chainparams.h"
#include "net/fast_sync.h"
#include "rpc/server.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "platform/time_compat.h"
#include "util/thread_registry.h"

#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
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

        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        int64_t cursor = 0;
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, 0, ids, FLEET_BOARD_FRAME_IDS_MAX, &cursor),
                  FLEET_BOARD_FRAME_IDS_MAX);
        ASSERT_EQ(cursor, 3);
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, cursor, ids, FLEET_BOARD_FRAME_IDS_MAX, &cursor),
                  2);
        ASSERT_EQ(cursor, 1);
        ASSERT(memcmp(ids[0], oldest[1], 32) == 0);
        ASSERT(memcmp(ids[1], oldest[0], 32) == 0);
        ASSERT_EQ(db_fleet_board_ids_before(
                      &db, 800, cursor, ids, FLEET_BOARD_FRAME_IDS_MAX, &cursor),
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

        /* A announces its inventory. */
        uint8_t ids[FLEET_BOARD_FRAME_IDS_MAX][32];
        int n = db_fleet_board_recent_ids(&a, now, ids,
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
        ASSERT_EQ(db_fleet_board_recent_ids(&publisher, later, ids, 1), 1);
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
        ok = ok && json_push_kv_str(&input, "op", "show") &&
             json_push_kv_str(&input, "id", id) &&
             json_push_back(&params, &input) &&
             rpc_table_execute(&table, "fleet_board", &params, &result) &&
             json_get_bool(json_get(&result, "ok"));
        struct fleet_board_post reconstructed = {0};
        if (!ok) {
            char diagnostic[1024];
            json_write(&result, diagnostic, sizeof(diagnostic));
            fprintf(stderr, "fleet board: show RPC failed: %s\n", diagnostic);
        }
        const char *agent = json_get_str(json_get(&result, "agent"));
        const char *body = json_get_str(json_get(&result, "text"));
        const char *slug = json_get_str(json_get(&result, "slug"));
        const char *title = json_get_str(json_get(&result, "title"));
        ok = ok && agent && body && slug && title;
        if (ok) {
            fb_test_compose(&reconstructed, FLEET_BOARD_KIND_WIKI, agent, body,
                (uint64_t)json_get_int(json_get(&result, "created_at")),
                (uint32_t)json_get_int(json_get(&result, "ttl")));
            (void)snprintf(reconstructed.slug, sizeof(reconstructed.slug), "%s", slug);
            (void)snprintf(reconstructed.title, sizeof(reconstructed.title), "%s", title);
            ok = fleet_board_kind_from_name(json_get_str(json_get(&result, "kind")),
                    &reconstructed.kind) &&
                 zcl_hex_decode(json_get_str(json_get(&result, "id")), reconstructed.id, 32) &&
                 zcl_hex_decode(json_get_str(json_get(&result, "host")), reconstructed.host_pubkey, 32) &&
                 zcl_hex_decode(json_get_str(json_get(&result, "ref")), reconstructed.ref, 32) &&
                 zcl_hex_decode(json_get_str(json_get(&result, "supersedes")), reconstructed.supersedes, 32) &&
                 zcl_hex_decode(json_get_str(json_get(&result, "signature")), reconstructed.signature, 64) &&
                 json_get_int(json_get(&result, "text_len")) == reconstructed.text_len &&
                 fleet_board_post_verify(&reconstructed) == FLEET_BOARD_OK &&
                 memcmp(reconstructed.id, post.id, 32) == 0;
        }
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

        /* Machine capacity is private unless an operator deliberately writes
         * public post text. The removed shortcut must remain unavailable and
         * must not append anything as a side effect. */
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

int test_fleet_board(void)
{
    int failures = 0;
    failures += test_fleet_board_codec();
    failures += test_fleet_board_bounds();
    failures += test_fleet_board_frames();
    failures += test_fleet_board_store();
    failures += test_fleet_board_store_boundaries();
    failures += test_fleet_board_byte_boundary();
    failures += test_fleet_board_corrupt_reads();
    failures += test_fleet_board_inventory_pages();
    failures += test_fleet_board_wiki();
    failures += test_fleet_board_two_nodes();
    failures += test_fleet_board_waits_for_peer_handshake();
    failures += test_fleet_board_peer_churn_limits();
    failures += test_fleet_board_rpc_verification();
    failures += test_fleet_board_rpc_concurrency();
    failures += test_fleet_board_durable_wiki();
    failures += test_fleet_board_local_capacity_does_not_score_peer();
    failures += test_fleet_board_peer_inventory_cursor();
    return failures;
}
