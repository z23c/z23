/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API messaging routes: the /api/messages inbox index object. The inbox
 * serves a bounded newest-first window; before the object result the
 * response was a bare array, so an inbox that outgrew the window was
 * reported as if it were the whole inbox. Pinned here:
 *   - the result is {messages, shown, total};
 *   - shown counts the window's rows and total counts the same store
 *     under the same filter, so shown < total is a truthful window
 *     disclosure, never a mismatch between two stores;
 *   - an inbox that fits renders no discrepancy to disclose;
 *   - the unread filter arrives through the RPC surface and the totals
 *     follow it;
 *   - with no node.db wired, the in-memory store answers and counts its
 *     own rows (the established fallback, now with honest counts);
 *   - a store that cannot be counted drops the total instead of guessing.
 */

#include "test/api_test_fixtures.h"
#include "controllers/messaging_controller.h"
#include "models/database.h"
#include "models/zmsg.h"
#include "net/zmsg.h"

/* Seed one inbound inbox row. Fields satisfy db_zmsg_validate; ids are
 * unique per index (zmsg_compute_id would also do — the store dedups on
 * them either way). */
static bool seed_inbox_row(struct node_db *ndb, int i, bool read)
{
    struct zmsg_message m;
    memset(&m, 0, sizeof(m));
    m.direction = ZMSG_INBOUND;
    m.channel = ZMSG_CHANNEL_P2P;
    m.timestamp = 1700000000 + i;
    snprintf(m.sender, sizeof(m.sender), "peer%03d", i);
    snprintf(m.recipient, sizeof(m.recipient), "self");
    snprintf(m.body, sizeof(m.body), "inbox probe %03d", i);
    memset(m.msg_id, (uint8_t)(i + 1), sizeof(m.msg_id));
    m.read = read;
    return db_zmsg_save(ndb, &m);
}

/* Fault seam payload: the count step dies, the list step does not. */
static int zmsg_count_step_interrupted(void *stmt)
{
    (void)stmt;
    return SQLITE_INTERRUPT;
}

/* Call the registered exact-window inbox RPC with one bool arg. */
static bool call_msg_inbox_index(bool unread_only, struct json_value *result)
{
    struct rpc_table t;
    rpc_table_init(&t);
    register_msg_rpc_commands(&t);
    const struct rpc_command *cmd = rpc_table_find(&t, "msg_inbox_index");
    if (!cmd)
        return false;
    struct json_value params = {0}, arg = {0};
    json_set_array(&params);
    if (unread_only) {
        json_set_int(&arg, 1);
        json_push_back(&params, &arg);
    }
    json_free(&arg);
    bool ok = cmd->actor(&params, false, result);
    json_free(&params);
    return ok;
}

/* Read messages/shown/total out of an inbox result. */
static bool inbox_counts(const struct json_value *root, int *shown,
                         int *total, size_t *rows)
{
    const struct json_value *messages = json_get(root, "messages");
    if (!messages || messages->type != JSON_ARR)
        return false;
    *rows = json_size(messages);
    const struct json_value *shown_v = json_get(root, "shown");
    const struct json_value *total_v = json_get(root, "total");
    *shown = shown_v ? (int)json_get_int(shown_v) : -1;
    *total = total_v ? (int)json_get_int(total_v) : -1;
    return true;
}

int api_msg_routes_focused_tests(void)
{
    int failures = 0;

    /* ── Fitting inbox: the window holds everything ──────────────── */
    printf("api: /api/messages/index returns the inbox index object... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = node_db_open(&ndb, ":memory:") && ndb.open;
        struct zmsg_message model_rows[2];
        size_t model_shown = 99;
        int64_t model_total = -1;
        ok = ok && db_zmsg_inbox_window(
            &ndb, model_rows, 2, false, &model_shown, &model_total) &&
            model_shown == 0 && model_total == 0;
        for (int i = 0; ok && i < 3; i++)
            ok = seed_inbox_row(&ndb, i, false);
        ok = ok && db_zmsg_count(&ndb, false) == 3;
        ok = ok && db_zmsg_inbox_window(
            &ndb, model_rows, 2, false, &model_shown, &model_total) &&
            model_shown == 2 && model_total == 3 &&
            strcmp(model_rows[0].sender, "peer002") == 0 &&
            strcmp(model_rows[1].sender, "peer001") == 0;
        ok = ok && db_zmsg_inbox_window(
            &ndb, NULL, 0, false, &model_shown, &model_total) &&
            model_shown == 0 && model_total == 3;

        rpc_msg_set_state(&ndb, NULL);
        uint8_t resp[16384];
        size_t n = ok ? api_handle_request("GET", "/api/messages/index", NULL, 0,
                                           resp, sizeof(resp)) : 0;
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 &&
             strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
             body && json_read(&root, body, strlen(body));
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = ok && inbox_counts(&root, &shown, &total, &rows);
        ok = ok && rows == 3 && shown == 3 && total == 3;
        json_free(&root);

        /* The established v1 route remains a bare array for callers that
         * predate the exact-window index contract. */
        n = ok ? api_handle_request("GET", "/api/messages", NULL, 0,
                                    resp, sizeof(resp)) : 0;
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body &&
             json_read(&root, body, strlen(body)) &&
             root.type == JSON_ARR && json_size(&root) == 3;
        json_free(&root);
        rpc_msg_set_state(NULL, NULL);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu rows=%zu shown=%d total=%d)\n",
                      n, rows, shown, total); failures++; }
    }

    /* ── Over-window: shown names the window, total names the inbox ── */
    printf("api: truncated inbox discloses shown vs total... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = node_db_open(&ndb, ":memory:") && ndb.open;
        /* Two more rows than the controller's 50-row window. */
        for (int i = 0; ok && i < 52; i++)
            ok = seed_inbox_row(&ndb, i, false);

        rpc_msg_set_state(&ndb, NULL);
        struct json_value root = {0};
        bool called = ok && call_msg_inbox_index(false, &root);
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = called && inbox_counts(&root, &shown, &total, &rows);
        /* Newest first: the window keeps the tail of the seed range. */
        ok = ok && rows == 50 && shown == 50 && total == 52;
        const struct json_value *messages =
            ok ? json_get(&root, "messages") : NULL;
        const struct json_value *newest =
            messages ? json_at(messages, 0) : NULL;
        ok = ok && newest &&
             strcmp(json_get_str(json_get(newest, "sender")),
                    "peer051") == 0;
        json_free(&root);
        rpc_msg_set_state(NULL, NULL);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL (rows=%zu shown=%d total=%d)\n",
                      rows, shown, total); failures++; }
    }

    /* ── Unread filter: totals follow the filter, not the window ──── */
    printf("api: msg_inbox_index totals track the unread filter... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = node_db_open(&ndb, ":memory:") && ndb.open;
        for (int i = 0; ok && i < 5; i++)
            ok = seed_inbox_row(&ndb, i, i >= 3);   /* last two read */

        struct zmsg_message unread_rows[5];
        size_t unread_shown = 0;
        int64_t unread_total = 0;
        ok = ok && db_zmsg_inbox_window(
            &ndb, unread_rows, 5, true, &unread_shown, &unread_total) &&
            unread_shown == 3 && unread_total == 3 &&
            strcmp(unread_rows[0].sender, "peer002") == 0;

        rpc_msg_set_state(&ndb, NULL);
        struct json_value root = {0};
        bool called = ok && call_msg_inbox_index(true, &root);
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = called && inbox_counts(&root, &shown, &total, &rows);
        ok = ok && rows == 3 && shown == 3 && total == 3;
        json_free(&root);

        root = (struct json_value){0};
        called = ok && call_msg_inbox_index(false, &root);
        ok = called && inbox_counts(&root, &shown, &total, &rows);
        ok = ok && rows == 5 && shown == 5 && total == 5;
        json_free(&root);
        rpc_msg_set_state(NULL, NULL);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL (rows=%zu shown=%d total=%d)\n",
                      rows, shown, total); failures++; }
    }

    /* ── No db: the in-memory store answers and counts its own ────── */
    printf("api: store fallback counts the rows it serves... ");
    {
        rpc_msg_set_state(NULL, NULL);
        int before_all = zmsg_store_count();
        int before_unread = zmsg_store_count_unread();

        struct zmsg_message m;
        memset(&m, 0, sizeof(m));
        m.direction = ZMSG_INBOUND;
        m.channel = ZMSG_CHANNEL_P2P;
        m.timestamp = 1700000100;
        snprintf(m.sender, sizeof(m.sender), "fallbackA");
        snprintf(m.recipient, sizeof(m.recipient), "self");
        snprintf(m.body, sizeof(m.body), "fallback probe A");
        memset(m.msg_id, 0x71, sizeof(m.msg_id));
        bool ok = zmsg_store_add(&m);
        memset(m.msg_id, 0x72, sizeof(m.msg_id));
        snprintf(m.sender, sizeof(m.sender), "fallbackB");
        snprintf(m.body, sizeof(m.body), "fallback probe B");
        ok = ok && zmsg_store_add(&m);

        struct json_value root = {0};
        bool called = ok && api_msg_inbox_index(&root);
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = called && inbox_counts(&root, &shown, &total, &rows);
        ok = ok && total == before_all + 2 &&
             rows == (size_t)(50 < before_all + 2 ? 50 : before_all + 2) &&
             (int)rows == shown;
        json_free(&root);

        /* The unread view's total is the store's own unread count. */
        root = (struct json_value){0};
        called = ok && call_msg_inbox_index(true, &root);
        ok = called && inbox_counts(&root, &shown, &total, &rows);
        ok = ok && total == before_unread + 2;
        json_free(&root);
        if (ok) printf("OK\n");
        else { printf("FAIL (rows=%zu shown=%d total=%d)\n",
                      rows, shown, total); failures++; }
    }

    /* ── Fail closed: an unreadable snapshot is never partial ────── */
    printf("api: unreadable inbox snapshot fails closed... ");
    {
        int no_db = db_zmsg_count(NULL, false);
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ndb.db = NULL;
        ndb.open = false;
        int closed = db_zmsg_count(&ndb, false);
        bool ok = no_db == -1 && closed == -1;

        /* End to end: the index refuses a statement fault instead of
         * returning rows with an invented or separately sampled total. */
        struct node_db seeded;
        memset(&seeded, 0, sizeof(seeded));
        ok = ok && node_db_open(&seeded, ":memory:") && seeded.open;
        for (int i = 0; ok && i < 3; i++)
            ok = seed_inbox_row(&seeded, i, false);
        if (ok) {
            rpc_msg_set_state(&seeded, NULL);
            db_zmsg_test_set_window_step(zmsg_count_step_interrupted);
            struct json_value root = {0};
            bool called = api_msg_inbox_index(&root);
            db_zmsg_test_set_window_step(NULL);
            ok = !called && root.type == JSON_STR &&
                 strstr(json_get_str(&root), "unavailable") != NULL;
            json_free(&root);
            rpc_msg_set_state(NULL, NULL);

            /* The atomic model API never returns partial rows or stale
             * counters when its one statement is interrupted. */
            struct zmsg_message window[2];
            memset(window, 0xA5, sizeof(window));
            struct zmsg_message zero_window[2] = {0};
            size_t window_rows = 7;
            int64_t window_total = 7;
            db_zmsg_test_set_window_step(zmsg_count_step_interrupted);
            bool window_ok = db_zmsg_inbox_window(
                &seeded, window, 2, false, &window_rows, &window_total);
            db_zmsg_test_set_window_step(NULL);
            ok = !window_ok && window_rows == 0 && window_total == 0 &&
                 memcmp(window, zero_window, sizeof(window)) == 0;
        }
        node_db_close(&seeded);
        if (ok) printf("OK\n");
        else { printf("FAIL (no_db=%d closed=%d)\n", no_db, closed);
               failures++; }
    }

    return failures;
}
