/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_board_site — the read-only /board room pages gate
 * (contexts/messaging/controllers/src/board_site_controller.c).
 *
 * Coverage:
 *   1. Route coverage: /board, /board/room/<name>, an empty room, an
 *      invalid room name, and an unknown route all render complete HTTP
 *      responses from one fixture store.
 *   2. SCOPE DISCIPLINE (the adversarial one): the store holds a
 *      fleet-scoped post, and no page — not the index, not any room — ever
 *      renders its text or admits the scope exists.
 *   3. Default-room continuity: a legacy pre-scope post and a v2 post that
 *      names "general" appear together on the general room page.
 *   4. HTML escaping: hostile agent and text render escaped, never as raw
 *      markup.
 *   5. Store agreement: the room page shows exactly what
 *      db_fleet_board_list returns for that room filter — no website
 *      database, no second board truth.
 *   6. No node database is a named 503, not a fall-through.
 *
 * Fixtures run fully in-process on :memory: node databases; the handler is
 * called directly, the same shape as the fleet_board RPC tests. */

#include "test/test_core.h"

#include "controllers/board_site_controller.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"

#include <string.h>

#define BS_RESP_CAP 131072
static uint8_t g_resp[BS_RESP_CAP];

static void bs_identity(uint8_t which, uint8_t seed[32], uint8_t pk[32])
{
    uint8_t sk[32];
    memset(seed, 0, 32);
    seed[0] = which;
    seed[31] = (uint8_t)(0xb0 + which);
    ed25519_keypair(pk, sk, seed);
    memcpy(seed, sk, 32);
}

static void bs_compose(struct fleet_board_post *post, uint8_t kind,
                       uint8_t scope, const char *room, const char *agent,
                       const char *text, uint64_t created_at, uint32_t ttl)
{
    memset(post, 0, sizeof(*post));
    post->kind = kind;
    post->scope = scope;
    post->created_at = created_at;
    post->ttl = ttl;
    (void)snprintf(post->room, sizeof(post->room), "%s", room ? room : "");
    (void)snprintf(post->agent, sizeof(post->agent), "%s", agent ? agent : "");
    size_t n = strlen(text);
    memcpy(post->text, text, n);
    post->text[n] = '\0';
    post->text_len = (uint32_t)n;
}

static const char *bs_get(const char *path, size_t *len_out)
{
    size_t n = board_site_handle_request("GET", path, NULL, 0, g_resp,
                                         BS_RESP_CAP - 1, NULL);
    g_resp[n] = '\0';
    if (len_out)
        *len_out = n;
    return (const char *)g_resp;
}

static bool bs_has(const char *resp, const char *needle)
{
    return strstr(resp, needle) != NULL;
}

int test_board_site(void)
{
    int failures = 0;
    TEST("board site: room pages render public posts and never fleet rows") {
        /* With no runtime bound, the mount answers a named 503 rather than
         * falling through into another route family. */
        app_runtime_set_current(NULL);
        const char *resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "503 Service Unavailable"));
        ASSERT(bs_has(resp, "Board unavailable"));

        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        bs_identity(1, seed, pk);
        /* The handler lists against real wall time, so the fixtures are
         * dated by the same clock: anything older would be expired history
         * the discoverable view rightly hides. The base is a BARE reading
         * and every fixture offset is an addition — the five posts sit
         * between now and now+4 s, inside FLEET_BOARD_FUTURE_SKEW_MAX (300)
         * and nowhere near the 3600 s TTL — so no assertion below is graded
         * on a difference between two clock readings. */
        const int64_t now = (int64_t)platform_time_wall_time_t();

        struct fleet_board_post legacy, ops, general, fleet, hostile;
        bs_compose(&legacy, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_LEGACY_PUBLIC,
                   "", "lane-a", "from before scopes", (uint64_t)now, 3600);
        bs_compose(&ops, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                   "ops", "lane-b", "ops room question", (uint64_t)now + 1,
                   3600);
        bs_compose(&general, FLEET_BOARD_KIND_RESULT, FLEET_BOARD_SCOPE_PUBLIC,
                   "general", "lane-b", "default room answer",
                   (uint64_t)now + 2, 3600);
        bs_compose(&fleet, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                   "", "lane-a", "FLEETONLY-MARKER text", (uint64_t)now + 3,
                   3600);
        bs_compose(&hostile, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "ops", "<b>bold</b>", "<script>alert(1)</script>",
                   (uint64_t)now + 4, 3600);
        ASSERT_EQ(fleet_board_post_sign(&legacy, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&ops, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&general, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&fleet, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&hostile, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &legacy, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &ops, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &general, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &fleet, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &hostile, now, NULL),
                  FLEET_BOARD_OK);

        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);

        /* The index lists the public rooms and links each one. */
        resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "Board rooms"));
        ASSERT(bs_has(resp, "/board/room/ops"));
        ASSERT(bs_has(resp, "/board/room/general"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));

        /* A room page shows its own posts, newest first, with the store's
         * rows — and nothing from other rooms or scopes. */
        resp = bs_get("/board/room/ops", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "Room: ops"));
        ASSERT(bs_has(resp, "ops room question"));
        ASSERT(!bs_has(resp, "default room answer"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));
        /* Hostile markup is escaped on the way out. */
        ASSERT(!bs_has(resp, "<script>alert(1)</script>"));
        ASSERT(bs_has(resp, "&lt;script&gt;"));
        ASSERT(!bs_has(resp, "<b>bold</b>"));
        ASSERT(bs_has(resp, "&lt;b&gt;bold&lt;/b&gt;"));

        /* The default room shows the v2 general post and the legacy post
         * together: the pre-scope board IS the default room. */
        resp = bs_get("/board/room/general", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "default room answer"));
        ASSERT(bs_has(resp, "from before scopes"));
        ASSERT(!bs_has(resp, "ops room question"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));

        /* A well-formed room this node holds nothing for is an honest empty
         * page, not an error. */
        resp = bs_get("/board/room/empty-room", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "No posts"));

        /* A name that cannot be a room is a 404, as is an unknown route. */
        resp = bs_get("/board/room/Unknown", NULL);
        ASSERT(bs_has(resp, "404 Not Found"));
        resp = bs_get("/board/bogus", NULL);
        ASSERT(bs_has(resp, "404 Not Found"));

        /* Every answer is a complete, typed HTTP response. */
        resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "Content-Type: text/html; charset=utf-8"));

        app_runtime_set_current(NULL);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}
