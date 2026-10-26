/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API messaging routes: the /api/messages inbox index object. The inbox
 * serves a bounded newest-first window, so the result is an object rather than
 * a bare array (which would report a truncated inbox as the whole inbox).
 * Pinned here:
 *   - the result is {messages, shown, total};
 *   - shown counts the window's rows and total counts the same store
 *     under the same filter, so shown < total is a truthful window
 *     disclosure, never a mismatch between two stores;
 *   - an inbox that fits renders no discrepancy to disclose;
 *   - the unread filter arrives through the RPC surface and the totals
 *     follow it;
 *   - with no node.db wired, the in-memory store answers and counts its
 *   - with no node.db wired, the in-memory store answers and counts its
 *     own rows;
 */

#include "test/api_test_fixtures.h"
#include "controllers/messaging_controller.h"
#include "models/database.h"
#include "models/zmsg.h"
#include "net/zmsg.h"
#include "chain/chainparams.h"

static int64_t msg_size_clock(void *self)
{
    (void)self;
    return 1700000300000LL;
}

static bool msg_send_size_accepted(bool called, const struct json_value *result,
                                   struct node_db *ndb, const char *body,
                                   size_t length, int stored, int memory)
{
    struct zmsg_message rows[4] = {0};
    bool ok = called && result->type == JSON_OBJ;
    ok &= db_zmsg_count(ndb, false) == stored + 1;
    int count = db_zmsg_list(ndb, rows, 4, false);
    bool exact = false;
    for (int i = 0; i < count; i++)
        exact |= memcmp(rows[i].body, body, length + 1) == 0;
    ok &= exact && zmsg_store_count() == memory + 1;
    return ok;
}

/* Size refusal takes precedence even without a network or name database. */
static bool msg_send_size_unwired(const struct rpc_command *cmd,
                                  const struct json_value *params)
{
    rpc_msg_set_state(NULL, NULL);
    struct json_value result = {0};
    bool called = cmd->actor(params, false, &result);
    bool ok = !called && result.type == JSON_STR &&
              strstr(json_get_str(&result), "too long") != NULL;
    json_free(&result);
    return ok;
}

static bool msg_send_size_case(const struct rpc_command *cmd, bool named,
                               struct node_db *ndb, struct p2p_node *peer,
                               size_t length, bool multibyte)
{
    char body[sizeof(((struct zmsg_message *)0)->body) + 2];
    /* Distinct bytes prevent ID collisions across actors and cases. */
    memset(body, named ? 'n' : 'p', length);
    body[0] = multibyte ? 'm' : 'a';
    if (multibyte) {
        body[length - 2] = (char)0xc3;
        body[length - 1] = (char)0xa9;
    }
    body[length] = '\0';
    struct json_value params = {0}, arg = {0}, result = {0};
    json_set_array(&params);
    if (named) json_set_str(&arg, "sizeprobe");
    else json_set_int(&arg, 7);
    json_push_back(&params, &arg);
    json_set_str(&arg, body);
    json_push_back(&params, &arg);
    if (!named) {
        json_set_str(&arg, "p2p");
        json_push_back(&params, &arg);
    }
    json_free(&arg);
    int stored = db_zmsg_count(ndb, false), memory = zmsg_store_count();
    size_t sent = peer->send_size;
    bool disconnected = peer->disconnect;
    bool called = cmd->actor(&params, false, &result);
    bool ok;
    if (length >= sizeof(((struct zmsg_message *)0)->body)) {
        ok = !called && result.type == JSON_STR &&
             strstr(json_get_str(&result), "too long") != NULL;
        ok &= db_zmsg_count(ndb, false) == stored;
        ok &= zmsg_store_count() == memory && peer->send_size == sent;
        ok &= peer->disconnect == disconnected;
        ok &= msg_send_size_unwired(cmd, &params);
    } else {
        ok = msg_send_size_accepted(called, &result, ndb, body, length,
                                    stored, memory);
        ok &= named || peer->send_size > sent;
    }
    json_free(&params);
    json_free(&result);
    return ok;
}

/* Each case gets a fresh peer: sending on the inert socket disconnects it. */
static bool msg_send_size_fixture(const struct rpc_command *cmd, bool named,
                                  size_t length, bool multibyte)
{
    struct node_db ndb = {0};
    struct connman cm = {0};
    struct net_address addr;
    struct p2p_node *peer = NULL;
    struct znam_entry entry = {0};
    snprintf(entry.name, sizeof(entry.name), "sizeprobe");
    snprintf(entry.owner_address, sizeof(entry.owner_address), "owner");
    snprintf(entry.target_value, sizeof(entry.target_value), "recipient");
    entry.target_type = ZNAM_TYPE_CONTENT;
    memset(entry.reg_txid, 0x63, sizeof(entry.reg_txid));
    bool ok = node_db_open(&ndb, ":memory:") && db_znam_save(&ndb, &entry);
    bool network = api_test_init_connman_peer(&cm, &addr, &peer, 0);
    cm.params = chain_params_get();
    ok &= network && cm.params != NULL;
    rpc_msg_set_state(&ndb, &cm);
    if (ok) {
        peer->id = 7;
        ok = msg_send_size_case(cmd, named, &ndb, peer, length, multibyte);
    }
    rpc_msg_set_state(NULL, NULL);
    rpc_net_set_connman(NULL);
    net_manager_free(&cm.manager);
    node_db_close(&ndb);
    return ok;
}

int api_msg_send_size_focused_tests(void)
{
    static const clock_iface_t clock = {
        .now_monotonic_ns = msg_size_clock, .now_wall_ms = msg_size_clock
    };
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&clock);
    struct rpc_table table;
    rpc_table_init(&table);
    register_msg_rpc_commands(&table);
    const char *names[] = {"msg_send", "msg_send_named"};
    size_t cap = sizeof(((struct zmsg_message *)0)->body);
    const size_t lengths[] = {cap - 1, cap, cap + 1, cap, cap - 1};
    bool ok = true;
    for (size_t actor = 0; actor < 2; actor++) {
        const struct rpc_command *cmd = rpc_table_find(&table, names[actor]);
        if (!cmd) { ok = false; break; }
        for (size_t i = 0; i < 5; i++) {
            bool passed = msg_send_size_fixture(cmd, actor == 1,
                                                lengths[i], i >= 3);
            printf("api: %s body bytes=%zu multibyte=%d... %s\n",
                   names[actor], lengths[i], i >= 3, passed ? "OK" : "FAIL");
            ok &= passed;
        }
    }
    clock_set_default(saved_clock);
    return ok ? 0 : 1;
}

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

static bool named_message_queued(struct node_db *ndb,
                                  const struct json_value *result, int before)
{
    const char *status = json_get_str(json_get(result, "status"));
    struct zmsg_message row = {0};
    return status && strcmp(status, "queued") == 0 &&
           zmsg_store_count() == before + 1 && db_zmsg_count(ndb, false) == 1 &&
           db_zmsg_list(ndb, &row, 1, false) == 1 &&
           strcmp(row.body, "hello") == 0 &&
           strcmp(row.recipient, "alice (fixture-target)") == 0;
}

static bool named_message_save_test(bool query_only)
{
    struct node_db ndb = {0};
    struct znam_entry entry = {0};
    struct json_value params = {0}, arg = {0}, result = {0};
    struct rpc_table table;
    rpc_table_init(&table);
    register_msg_rpc_commands(&table);
    const struct rpc_command *cmd = rpc_table_find(&table, "msg_send_named");
    snprintf(entry.name, sizeof(entry.name), "alice");
    snprintf(entry.owner_address, sizeof(entry.owner_address), "fixture-owner");
    entry.target_type = ZNAM_TYPE_CONTENT;
    snprintf(entry.target_value, sizeof(entry.target_value), "fixture-target");
    memset(entry.reg_txid, 0x43, sizeof(entry.reg_txid));
    entry.reg_height = 1;
    bool ready = node_db_open(&ndb, ":memory:") && db_znam_save(&ndb, &entry);
    json_set_array(&params);
    json_set_str(&arg, "alice");
    ready = ready && json_push_back(&params, &arg);
    json_set_str(&arg, "hello");
    ready = ready && json_push_back(&params, &arg);
    if (ready && query_only)
        ready = sqlite3_exec(ndb.db, "PRAGMA query_only=ON", NULL, NULL,
                             NULL) == SQLITE_OK;
    int before = zmsg_store_count();
    rpc_msg_set_state(&ndb, NULL);
    bool called = ready && cmd && cmd->actor(&params, false, &result);
    bool ok = false;
    if (query_only) {
        const char *error = json_get_str(&result);
        ok = ready && cmd && !called;
        ok &= result.type == JSON_STR && error &&
              strstr(error, "Local message save failed");
        ok &= zmsg_store_count() == before;
        ok &= db_zmsg_count(&ndb, false) == 0;
    } else {
        ok = called && named_message_queued(&ndb, &result, before);
    }
    json_free(&result);
    json_free(&arg);
    json_free(&params);
    rpc_msg_set_state(NULL, NULL);
    node_db_close(&ndb);
    return ok;
}

static int named_message_save_report(bool query_only)
{
    printf("api: named message %s... ", query_only ?
           "refuses failed local save" : "queues one durable local copy");
    bool ok = named_message_save_test(query_only);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool message_read_result(bool called, const struct json_value *result,
                                const char *hex, bool query_only)
{
    if (query_only) {
        const char *error = json_get_str(result);
        return !called && result->type == JSON_STR && error &&
               strstr(error, hex) && strstr(error, "persistent read mark failed") &&
               strstr(error, "restore a writable message store before retrying") &&
               json_get(result, "status") == NULL;
    }
    const char *id = json_get_str(json_get(result, "msg_id"));
    const char *status = json_get_str(json_get(result, "status"));
    return called && result->type == JSON_OBJ && id && status &&
           strcmp(id, hex) == 0 && strcmp(status, "read") == 0;
}

static int message_read_report(bool query_only)
{
    const char *hex =
        "4242424242424242424242424242424242424242424242424242424242424242";
    struct node_db ndb = {0};
    struct rpc_table table;
    struct json_value params = {0}, arg = {0}, result = {0};
    rpc_table_init(&table);
    register_msg_rpc_commands(&table);
    const struct rpc_command *cmd = rpc_table_find(&table, "msg_read");
    /* Index 65 seeds an unread row whose 32 ID bytes are all 0x42. */
    bool ready = node_db_open(&ndb, ":memory:") && seed_inbox_row(&ndb, 65, false);
    json_set_array(&params);
    json_set_str(&arg, hex);
    ready = ready && json_push_back(&params, &arg);
    if (ready && query_only)
        ready = sqlite3_exec(ndb.db, "PRAGMA query_only=ON", NULL, NULL,
                             NULL) == SQLITE_OK;
    rpc_msg_set_state(&ndb, NULL);
    bool called = ready && cmd && cmd->actor(&params, false, &result);
    bool ok = ready && cmd;
    ok &= message_read_result(called, &result, hex, query_only);
    struct zmsg_message row = {0};
    ok &= db_zmsg_list(&ndb, &row, 1, false) == 1;
    ok &= row.read == !query_only;
    uint8_t expected_id[32];
    memset(expected_id, 0x42, sizeof(expected_id));
    ok &= memcmp(row.msg_id, expected_id, sizeof(expected_id)) == 0;
    json_free(&result);
    json_free(&arg);
    json_free(&params);
    rpc_msg_set_state(NULL, NULL);
    node_db_close(&ndb);
    printf("api: message read %s... %s\n", query_only ?
           "refuses failed persistent mark" : "marks durable row read",
           ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static size_t inbox_route_response(bool ok, const char *path,
                                   uint8_t *resp, size_t cap,
                                   const char **body)
{
    size_t n = ok ? api_handle_request("GET", path, NULL, 0, resp, cap) : 0;
    resp[n < cap ? n : cap - 1] = '\0';
    *body = api_test_body(resp, n, cap);
    return n;
}

static bool fitting_inbox_empty_window(struct node_db *ndb,
                                       struct zmsg_message *model_rows,
                                       size_t *model_shown,
                                       int64_t *model_total)
{
    bool ok = node_db_open(ndb, ":memory:") && ndb->open;
    ok = ok && db_zmsg_inbox_window(
        ndb, model_rows, 2, false, model_shown, model_total) &&
        *model_shown == 0 && *model_total == 0;
    return ok;
}

static bool fitting_inbox_newest_senders(bool ok,
                                         const struct zmsg_message *rows)
{
    return ok &&
           strcmp(rows[0].sender, "peer002") == 0 &&
           strcmp(rows[1].sender, "peer001") == 0;
}

static bool fitting_inbox_seeded_window(bool ok, struct node_db *ndb,
                                        struct zmsg_message *model_rows,
                                        size_t *model_shown,
                                        int64_t *model_total)
{
    for (int i = 0; ok && i < 3; i++)
        ok = seed_inbox_row(ndb, i, false);
    ok = ok && db_zmsg_count(ndb, false) == 3;
    ok = ok && db_zmsg_inbox_window(
        ndb, model_rows, 2, false, model_shown, model_total) &&
        *model_shown == 2 && *model_total == 3;
    ok = fitting_inbox_newest_senders(ok, model_rows);
    ok = ok && db_zmsg_inbox_window(
        ndb, NULL, 0, false, model_shown, model_total) &&
        *model_shown == 0 && *model_total == 3;
    return ok;
}

static bool fitting_inbox_index_http(bool ok, uint8_t *resp, size_t cap,
                                     struct json_value *root,
                                     int *shown, int *total, size_t *rows)
{
    const char *body = NULL;
    size_t n = inbox_route_response(ok, "/api/messages/index", resp, cap,
                                    &body);
    json_init(root);
    ok = ok && n > 0 &&
         strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
         body && json_read(root, body, strlen(body));
    *shown = -1;
    *total = -1;
    *rows = 0;
    ok = ok && inbox_counts(root, shown, total, rows);
    ok = ok && *rows == 3 && *shown == 3 && *total == 3;
    json_free(root);
    return ok;
}

static size_t fitting_inbox_v1_array(bool *ok, uint8_t *resp, size_t cap,
                                     struct json_value *root)
{
    const char *body = NULL;
    size_t n = inbox_route_response(*ok, "/api/messages", resp, cap, &body);
    json_init(root);
    *ok = *ok && n > 0 && body &&
          json_read(root, body, strlen(body)) &&
          root->type == JSON_ARR && json_size(root) == 3;
    json_free(root);
    return n;
}

static bool truncated_inbox_seed(struct node_db *ndb)
{
    bool ok = node_db_open(ndb, ":memory:") && ndb->open;
    /* Two more rows than the controller's 50-row window. */
    for (int i = 0; ok && i < 52; i++)
        ok = seed_inbox_row(ndb, i, false);
    return ok;
}

static bool truncated_inbox_window(bool ok, struct json_value *root,
                                   size_t *rows, int *shown, int *total)
{
    bool called = ok && call_msg_inbox_index(false, root);
    *shown = -1;
    *total = -1;
    *rows = 0;
    ok = called && inbox_counts(root, shown, total, rows);
    /* Newest first: the window keeps the tail of the seed range. */
    ok = ok && *rows == 50 && *shown == 50 && *total == 52;
    const struct json_value *messages =
        ok ? json_get(root, "messages") : NULL;
    const struct json_value *newest =
        messages ? json_at(messages, 0) : NULL;
    ok = ok && newest &&
         strcmp(json_get_str(json_get(newest, "sender")),
                "peer051") == 0;
    return ok;
}

static bool unread_filter_model(struct node_db *ndb)
{
    bool ok = node_db_open(ndb, ":memory:") && ndb->open;
    for (int i = 0; ok && i < 5; i++)
        ok = seed_inbox_row(ndb, i, i >= 3);   /* last two read */
    struct zmsg_message unread_rows[5];
    size_t unread_shown = 0;
    int64_t unread_total = 0;
    ok = ok && db_zmsg_inbox_window(
        ndb, unread_rows, 5, true, &unread_shown, &unread_total) &&
        unread_shown == 3 && unread_total == 3 &&
        strcmp(unread_rows[0].sender, "peer002") == 0;
    return ok;
}

static bool inbox_index_matches(bool ok, bool unread_only,
                                struct json_value *root,
                                size_t *rows, int *shown, int *total,
                                size_t want_rows, int want_shown,
                                int want_total)
{
    bool called = ok && call_msg_inbox_index(unread_only, root);
    ok = called && inbox_counts(root, shown, total, rows);
    ok = ok && *rows == want_rows && *shown == want_shown &&
         *total == want_total;
    json_free(root);
    return ok;
}

static bool unread_filter_rpc(bool ok, struct json_value *root,
                              size_t *rows, int *shown, int *total)
{
    *shown = -1;
    *total = -1;
    *rows = 0;
    ok = inbox_index_matches(ok, true, root, rows, shown, total, 3, 3, 3);
    *root = (struct json_value){0};
    return inbox_index_matches(ok, false, root, rows, shown, total, 5, 5, 5);
}

static bool store_fallback_served_rows(size_t *rows, int *shown, int *total,
                                       int *before_unread)
{
    rpc_msg_set_state(NULL, NULL);
    int before_all = zmsg_store_count();
    *before_unread = zmsg_store_count_unread();

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
    *shown = -1;
    *total = -1;
    *rows = 0;
    ok = called && inbox_counts(&root, shown, total, rows);
    ok = ok && *total == before_all + 2 &&
         *rows == (size_t)(50 < before_all + 2 ? 50 : before_all + 2) &&
         (int)*rows == *shown;
    json_free(&root);
    return ok;
}

static bool unreadable_snapshot_seed(struct node_db *seeded,
                                     int no_db, int closed)
{
    bool ok = no_db == -1 && closed == -1;
    ok = ok && node_db_open(seeded, ":memory:") && seeded->open;
    for (int i = 0; ok && i < 3; i++)
        ok = seed_inbox_row(seeded, i, false);
    return ok;
}

static bool unreadable_snapshot_fault(struct node_db *seeded)
{
    rpc_msg_set_state(seeded, NULL);
    db_zmsg_test_set_window_step(zmsg_count_step_interrupted);
    struct json_value root = {0};
    bool called = api_msg_inbox_index(&root);
    db_zmsg_test_set_window_step(NULL);
    bool ok = !called && root.type == JSON_STR &&
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
        seeded, window, 2, false, &window_rows, &window_total);
    db_zmsg_test_set_window_step(NULL);
    ok = !window_ok && window_rows == 0 && window_total == 0 &&
         memcmp(window, zero_window, sizeof(window)) == 0;
    return ok;
}

int api_msg_routes_focused_tests(void)
{
    int failures = 0;

    failures += named_message_save_report(true);
    failures += named_message_save_report(false);
    failures += message_read_report(true);
    failures += message_read_report(false);

    /* ── Fitting inbox: the window holds everything ──────────────── */
    printf("api: /api/messages/index returns the inbox index object... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        struct zmsg_message model_rows[2];
        size_t model_shown = 99;
        int64_t model_total = -1;
        bool ok = fitting_inbox_empty_window(&ndb, model_rows, &model_shown,
                                             &model_total);
        ok = fitting_inbox_seeded_window(ok, &ndb, model_rows, &model_shown,
                                         &model_total);

        rpc_msg_set_state(&ndb, NULL);
        uint8_t resp[16384];
        struct json_value root;
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = fitting_inbox_index_http(ok, resp, sizeof(resp), &root,
                                      &shown, &total, &rows);
        /* The established v1 route remains a bare array for callers that
         * predate the exact-window index contract. */
        size_t n = fitting_inbox_v1_array(&ok, resp, sizeof(resp), &root);
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
        bool ok = truncated_inbox_seed(&ndb);
        rpc_msg_set_state(&ndb, NULL);
        struct json_value root = {0};
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = truncated_inbox_window(ok, &root, &rows, &shown, &total);
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
        bool ok = unread_filter_model(&ndb);
        rpc_msg_set_state(&ndb, NULL);
        struct json_value root = {0};
        int shown = -1, total = -1;
        size_t rows = 0;
        ok = unread_filter_rpc(ok, &root, &rows, &shown, &total);
        rpc_msg_set_state(NULL, NULL);
        node_db_close(&ndb);
        if (ok) printf("OK\n");
        else { printf("FAIL (rows=%zu shown=%d total=%d)\n",
                      rows, shown, total); failures++; }
    }

    /* ── No db: the in-memory store answers and counts its own ────── */
    printf("api: store fallback counts the rows it serves... ");
    {
        int shown = -1, total = -1;
        size_t rows = 0;
        int before_unread = 0;
        bool ok = store_fallback_served_rows(&rows, &shown, &total,
                                             &before_unread);
        /* The unread view's total is the store's own unread count. */
        struct json_value root = {0};
        bool called = ok && call_msg_inbox_index(true, &root);
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
        /* End to end: the index refuses a statement fault instead of
         * returning rows with an invented or separately sampled total. */
        struct node_db seeded;
        memset(&seeded, 0, sizeof(seeded));
        bool ok = unreadable_snapshot_seed(&seeded, no_db, closed);
        if (ok)
            ok = unreadable_snapshot_fault(&seeded);
        node_db_close(&seeded);
        if (ok) printf("OK\n");
        else { printf("FAIL (no_db=%d closed=%d)\n", no_db, closed);
               failures++; }
    }

    return failures;
}
