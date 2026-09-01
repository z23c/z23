/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/small_projections.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SP_CHECK(label, cond) do { \
    bool _ok = (cond); \
    printf("small_projections: %s... %s\n", (label), _ok ? "OK" : "FAIL"); \
    if (!_ok) failures++; \
} while (0)

static int t_payload_ids(void)
{
    int failures = 0;
    SP_CHECK("contact set id", EV_CONTACT_SET == 20);
    SP_CHECK("contact touched id", EV_CONTACT_TOUCHED == 21);
    SP_CHECK("contact delete id", EV_CONTACT_DELETE == 22);
    SP_CHECK("onion announcement id", EV_ONION_ANNOUNCEMENT == 23);
    SP_CHECK("hodl snapshot id", EV_HODL_SNAPSHOT == 24);
    return failures;
}

static int t_contact_payload_roundtrip(void)
{
    int failures = 0;

    {
        const char *address = "t1TaskOneContactAddressFixture";
        const char *name = "Alice Ops";
        struct ev_contact_set in = {
            .address_len = (uint8_t)strlen(address),
            .name_len = (uint8_t)strlen(name),
            .address = address,
            .name = name,
        };
        struct ev_contact_set out;
        uint8_t buf[128];
        size_t len = 0;
        SP_CHECK("contact set serialize",
                 ev_contact_set_serialize(&in, buf, sizeof(buf), &len));
        SP_CHECK("contact set len",
                 len == EV_CONTACT_SET_FIXED_LEN + strlen(address) +
                        strlen(name));
        SP_CHECK("contact set parse",
                 ev_contact_set_parse(buf, len, &out));
        SP_CHECK("contact set roundtrip",
                 out.address_len == in.address_len &&
                 out.name_len == in.name_len &&
                 memcmp(out.address, address, in.address_len) == 0 &&
                 memcmp(out.name, name, in.name_len) == 0);
    }

    {
        const char *address = "t1TaskOneContactTouchFixture";
        struct ev_contact_touched in = {
            .address_len = (uint8_t)strlen(address),
            .last_used_unix = 1777777777u,
            .address = address,
        };
        struct ev_contact_touched out;
        uint8_t buf[128];
        size_t len = 0;
        SP_CHECK("contact touched serialize",
                 ev_contact_touched_serialize(&in, buf, sizeof(buf), &len));
        SP_CHECK("contact touched parse",
                 ev_contact_touched_parse(buf, len, &out));
        SP_CHECK("contact touched roundtrip",
                 out.address_len == in.address_len &&
                 out.last_used_unix == in.last_used_unix &&
                 memcmp(out.address, address, in.address_len) == 0);
    }

    {
        const char *address = "t1TaskOneContactDeleteFixture";
        struct ev_contact_delete in = {
            .address_len = (uint8_t)strlen(address),
            .address = address,
        };
        struct ev_contact_delete out;
        uint8_t buf[128];
        size_t len = 0;
        SP_CHECK("contact delete serialize",
                 ev_contact_delete_serialize(&in, buf, sizeof(buf), &len));
        SP_CHECK("contact delete parse",
                 ev_contact_delete_parse(buf, len, &out));
        SP_CHECK("contact delete roundtrip",
                 out.address_len == in.address_len &&
                 memcmp(out.address, address, in.address_len) == 0);
    }

    return failures;
}

static int t_onion_payload_roundtrip(void)
{
    int failures = 0;
    const char *onion =
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef.onion";
    const char *script = "6a045a434c23010474657374";
    struct ev_onion_announcement in = {
        .announced_at_unix = 1765432100u,
        .onion_addr_len = (uint8_t)strlen(onion),
        .script_hex_len = (uint8_t)strlen(script),
        .onion_address = onion,
        .script_hex = script,
    };
    struct ev_onion_announcement out;
    uint8_t buf[256];
    size_t len = 0;

    SP_CHECK("onion announcement serialize",
             ev_onion_announcement_serialize(&in, buf, sizeof(buf), &len));
    SP_CHECK("onion announcement parse",
             ev_onion_announcement_parse(buf, len, &out));
    SP_CHECK("onion announcement roundtrip",
             out.announced_at_unix == in.announced_at_unix &&
             out.onion_addr_len == in.onion_addr_len &&
             out.script_hex_len == in.script_hex_len &&
             memcmp(out.onion_address, onion, in.onion_addr_len) == 0 &&
             memcmp(out.script_hex, script, in.script_hex_len) == 0);
    return failures;
}

static int t_hodl_payload_roundtrip(void)
{
    int failures = 0;
    struct ev_hodl_snapshot in = {
        .height = 1234567,
        .time_unix = 1760000000u,
        .total_zat = 99887766554433LL,
        .older_1y_zat = 5544332211LL,
        .older_1y_pct = 42.625,
    };
    struct ev_hodl_snapshot out;
    uint8_t buf[EV_HODL_SNAPSHOT_LEN];

    SP_CHECK("hodl snapshot serialize", ev_hodl_snapshot_serialize(&in, buf));
    SP_CHECK("hodl snapshot parse",
             ev_hodl_snapshot_parse(buf, sizeof(buf), &out));
    SP_CHECK("hodl snapshot roundtrip",
             out.height == in.height &&
             out.time_unix == in.time_unix &&
             out.total_zat == in.total_zat &&
             out.older_1y_zat == in.older_1y_zat &&
             out.older_1y_pct == in.older_1y_pct);
    return failures;
}

static bool index_exists(const char *db_path, const char *name)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    bool found = false;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
            -1, &s, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(s) == SQLITE_ROW;
done:
    if (s) sqlite3_finalize(s);
    if (db) sqlite3_close(db);
    return found;
}

static int64_t dump_int(struct json_value *dump, const char *key)
{
    const struct json_value *v = json_get(dump, key);
    return v ? json_get_int(v) : INT64_MIN;
}

static bool exec_test_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "small_projections SQL failed: %s\n",
                err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool test_query_i64(sqlite3 *db, const char *sql, int64_t *out)
{
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (!db || !sql || !out)
        return false;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_step(s) == SQLITE_ROW) {
        *out = sqlite3_column_int64(s, 0);
        ok = true;
    }
    sqlite3_finalize(s);
    return ok;
}

static const char *test_stmt_key(sqlite3_stmt *s, char *buf, size_t n)
{
    if (!s || !buf || n == 0)
        return "";
    int type = sqlite3_column_type(s, 0);
    if (type == SQLITE_INTEGER)
        snprintf(buf, n, "%lld", (long long)sqlite3_column_int64(s, 0));
    else if (type == SQLITE_FLOAT)
        snprintf(buf, n, "%.17g", sqlite3_column_double(s, 0));
    else {
        const char *text = (const char *)sqlite3_column_text(s, 0);
        snprintf(buf, n, "%s", text ? text : "");
    }
    return buf;
}

static bool test_column_equal(sqlite3_stmt *a, sqlite3_stmt *b, int col)
{
    int at = sqlite3_column_type(a, col);
    int bt = sqlite3_column_type(b, col);
    if (at == SQLITE_NULL || bt == SQLITE_NULL)
        return at == bt;
    if (at == SQLITE_INTEGER && bt == SQLITE_INTEGER)
        return sqlite3_column_int64(a, col) == sqlite3_column_int64(b, col);
    if (at == SQLITE_FLOAT || bt == SQLITE_FLOAT)
        return sqlite3_column_double(a, col) == sqlite3_column_double(b, col);
    if (at == SQLITE_BLOB || bt == SQLITE_BLOB) {
        int an = sqlite3_column_bytes(a, col);
        int bn = sqlite3_column_bytes(b, col);
        return an == bn &&
               memcmp(sqlite3_column_blob(a, col),
                      sqlite3_column_blob(b, col), (size_t)an) == 0;
    }
    const char *av = (const char *)sqlite3_column_text(a, col);
    const char *bv = (const char *)sqlite3_column_text(b, col);
    return strcmp(av ? av : "", bv ? bv : "") == 0;
}

static bool test_projection_db_matches_legacy(
    const char *projection_path,
    sqlite3 *legacy_db,
    const char *count_sql,
    const char *row_sql,
    int columns,
    int64_t *projection_count,
    int64_t *legacy_count,
    char *first_diff,
    size_t first_diff_len)
{
    sqlite3 *projection_db = NULL;
    sqlite3_stmt *ps = NULL;
    sqlite3_stmt *ls = NULL;
    bool ok = false;
    if (!projection_path || !legacy_db || !count_sql || !row_sql ||
        columns <= 0 || !projection_count || !legacy_count ||
        !first_diff || first_diff_len == 0)
        return false;
    first_diff[0] = '\0';
    if (sqlite3_open_v2(projection_path, &projection_db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    if (!test_query_i64(projection_db, count_sql, projection_count) ||
        !test_query_i64(legacy_db, count_sql, legacy_count))
        goto done;
    if (sqlite3_prepare_v2(projection_db, row_sql, -1, &ps, NULL) !=
        SQLITE_OK ||
        sqlite3_prepare_v2(legacy_db, row_sql, -1, &ls, NULL) != SQLITE_OK)
        goto done;
    ok = true;
    for (;;) {
        int prc = sqlite3_step(ps);
        int lrc = sqlite3_step(ls);
        if (prc == SQLITE_DONE && lrc == SQLITE_DONE)
            break;
        if (prc != SQLITE_ROW || lrc != SQLITE_ROW) {
            char key[128];
            sqlite3_stmt *source = prc == SQLITE_ROW ? ps : ls;
            snprintf(first_diff, first_diff_len, "%s",
                     test_stmt_key(source, key, sizeof(key)));
            break;
        }
        for (int i = 0; i < columns; i++) {
            if (!test_column_equal(ps, ls, i)) {
                char key[128];
                snprintf(first_diff, first_diff_len, "%s",
                         test_stmt_key(ps, key, sizeof(key)));
                goto done_compare;
            }
        }
    }
done_compare:
done:
    if (ps) sqlite3_finalize(ps);
    if (ls) sqlite3_finalize(ls);
    if (projection_db) sqlite3_close(projection_db);
    return ok;
}

static int t_projection_skeletons_fresh(void)
{
    int failures = 0;
    char dir[256];
    char elog_path[320];
    char contacts_path[320];
    char onion_path[320];
    char hodl_path[320];
    test_make_tmpdir(dir, sizeof(dir), "small_projections", "fresh");
    snprintf(elog_path, sizeof(elog_path), "%s/event_log.dat", dir);
    snprintf(contacts_path, sizeof(contacts_path), "%s/contacts.db", dir);
    snprintf(onion_path, sizeof(onion_path), "%s/onion_announcements.db",
             dir);
    snprintf(hodl_path, sizeof(hodl_path), "%s/hodl_history.db", dir);

    event_log_t *log = event_log_open(elog_path);
    SP_CHECK("event log open", log != NULL);
    if (!log) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    contacts_projection_t *contacts =
        contacts_projection_open(contacts_path, log);
    onion_ann_projection_t *onion =
        onion_ann_projection_open(onion_path, log);
    hodl_history_projection_t *hodl =
        hodl_history_projection_open(hodl_path, log);
    SP_CHECK("contacts open", contacts != NULL);
    SP_CHECK("onion announcements open", onion != NULL);
    SP_CHECK("hodl history open", hodl != NULL);
    SP_CHECK("contacts current", contacts_projection_current() == contacts);
    SP_CHECK("onion current", onion_ann_projection_current() == onion);
    SP_CHECK("hodl current", hodl_history_projection_current() == hodl);
    SP_CHECK("contacts fresh count",
             contacts && contacts_projection_count(contacts) == 0);
    SP_CHECK("onion fresh count",
             onion && onion_ann_projection_count(onion) == 0);
    SP_CHECK("hodl fresh count",
             hodl && hodl_history_projection_count(hodl) == 0);
    SP_CHECK("onion announced index exists",
             index_exists(onion_path, "idx_onion_announced_at"));
    SP_CHECK("hodl time index exists",
             index_exists(hodl_path, "idx_hodl_history_time"));
    SP_CHECK("contacts fresh catchup",
             contacts && contacts_projection_catch_up(contacts) == 0);
    SP_CHECK("onion fresh catchup",
             onion && onion_ann_projection_catch_up(onion) == 0);
    SP_CHECK("hodl fresh catchup",
             hodl && hodl_history_projection_catch_up(hodl) == 0);

    contacts_projection_close(contacts);
    onion_ann_projection_close(onion);
    hodl_history_projection_close(hodl);
    SP_CHECK("contacts current cleared", contacts_projection_current() == NULL);
    SP_CHECK("onion current cleared", onion_ann_projection_current() == NULL);
    SP_CHECK("hodl current cleared", hodl_history_projection_current() == NULL);

    contacts = contacts_projection_open(contacts_path, log);
    onion = onion_ann_projection_open(onion_path, log);
    hodl = hodl_history_projection_open(hodl_path, log);
    SP_CHECK("contacts reopen", contacts != NULL);
    SP_CHECK("onion reopen", onion != NULL);
    SP_CHECK("hodl reopen", hodl != NULL);
    SP_CHECK("contacts reopen count",
             contacts && contacts_projection_count(contacts) == 0);
    SP_CHECK("onion reopen count",
             onion && onion_ann_projection_count(onion) == 0);
    SP_CHECK("hodl reopen count",
             hodl && hodl_history_projection_count(hodl) == 0);
    SP_CHECK("contacts offset preserved",
             contacts && contacts_projection_catch_up(contacts) == 0);
    SP_CHECK("onion offset preserved",
             onion && onion_ann_projection_catch_up(onion) == 0);
    SP_CHECK("hodl offset preserved",
             hodl && hodl_history_projection_catch_up(hodl) == 0);

    contacts_projection_close(contacts);
    onion_ann_projection_close(onion);
    hodl_history_projection_close(hodl);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static bool append_contact_set_event(event_log_t *log,
                                     const char *address,
                                     const char *name)
{
    struct ev_contact_set ev = {
        .address_len = (uint8_t)strlen(address),
        .name_len = (uint8_t)strlen(name),
        .address = address,
        .name = name,
    };
    uint8_t payload[256];
    size_t len = 0;
    if (!ev_contact_set_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_CONTACT_SET, payload, len) != UINT64_MAX;
}

static bool append_contact_touched_event(event_log_t *log,
                                         const char *address,
                                         uint32_t last_used)
{
    struct ev_contact_touched ev = {
        .address_len = (uint8_t)strlen(address),
        .last_used_unix = last_used,
        .address = address,
    };
    uint8_t payload[128];
    size_t len = 0;
    if (!ev_contact_touched_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_CONTACT_TOUCHED, payload, len) != UINT64_MAX;
}

static bool append_contact_delete_event(event_log_t *log,
                                        const char *address)
{
    struct ev_contact_delete ev = {
        .address_len = (uint8_t)strlen(address),
        .address = address,
    };
    uint8_t payload[128];
    size_t len = 0;
    if (!ev_contact_delete_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_CONTACT_DELETE, payload, len) != UINT64_MAX;
}

static bool append_onion_announcement_event(event_log_t *log,
                                            const char *onion,
                                            const char *script,
                                            uint32_t announced_at)
{
    struct ev_onion_announcement ev = {
        .announced_at_unix = announced_at,
        .onion_addr_len = (uint8_t)strlen(onion),
        .script_hex_len = (uint8_t)strlen(script),
        .onion_address = onion,
        .script_hex = script,
    };
    uint8_t payload[256];
    size_t len = 0;
    if (!ev_onion_announcement_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ONION_ANNOUNCEMENT, payload, len) !=
           UINT64_MAX;
}

static bool append_hodl_snapshot_event(event_log_t *log, int32_t height)
{
    struct ev_hodl_snapshot ev = {
        .height = height,
        .time_unix = 1760000000u + (uint32_t)height,
        .total_zat = 1000000000LL + height,
        .older_1y_zat = 500000000LL + height,
        .older_1y_pct = 50.0,
    };
    uint8_t payload[EV_HODL_SNAPSHOT_LEN];
    if (!ev_hodl_snapshot_serialize(&ev, payload))
        return false;
    return event_log_append(log, EV_HODL_SNAPSHOT, payload, sizeof(payload)) !=
           UINT64_MAX;
}

static int t_projection_catchup_mixed(void)
{
    int failures = 0;
    char dir[256];
    char elog_path[320];
    char contacts_path[320];
    char onion_path[320];
    char hodl_path[320];
    test_make_tmpdir(dir, sizeof(dir), "small_projections", "mixed");
    snprintf(elog_path, sizeof(elog_path), "%s/event_log.dat", dir);
    snprintf(contacts_path, sizeof(contacts_path), "%s/contacts.db", dir);
    snprintf(onion_path, sizeof(onion_path), "%s/onion_announcements.db",
             dir);
    snprintf(hodl_path, sizeof(hodl_path), "%s/hodl_history.db", dir);

    event_log_t *log = event_log_open(elog_path);
    SP_CHECK("mixed event log open", log != NULL);
    if (!log) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    const uint8_t unrelated[] = {1, 2, 3, 4};
    const char *onion =
        "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg.onion";
    bool appended =
        append_contact_set_event(log, "t1MixedAlice", "Alice") &&
        event_log_append(log, EV_BLOCK_BODY, unrelated, sizeof(unrelated)) !=
            UINT64_MAX &&
        append_onion_announcement_event(log, onion, "6a045a434c23",
                                        1761234567u) &&
        append_contact_set_event(log, "t1MixedBob", "Bob") &&
        append_contact_touched_event(log, "t1MixedAlice", 1762222222u) &&
        append_hodl_snapshot_event(log, 100) &&
        append_contact_delete_event(log, "t1MixedBob") &&
        append_hodl_snapshot_event(log, 101);
    SP_CHECK("mixed append events", appended);

    contacts_projection_t *contacts =
        contacts_projection_open(contacts_path, log);
    onion_ann_projection_t *onion_p =
        onion_ann_projection_open(onion_path, log);
    hodl_history_projection_t *hodl =
        hodl_history_projection_open(hodl_path, log);
    SP_CHECK("mixed contacts open", contacts != NULL);
    SP_CHECK("mixed onion open", onion_p != NULL);
    SP_CHECK("mixed hodl open", hodl != NULL);

    uint64_t end_offset = event_log_size(log);
    SP_CHECK("contacts catchup mixed",
             contacts && contacts_projection_catch_up(contacts) == end_offset);
    SP_CHECK("onion catchup mixed",
             onion_p && onion_ann_projection_catch_up(onion_p) == end_offset);
    SP_CHECK("hodl catchup mixed",
             hodl && hodl_history_projection_catch_up(hodl) == end_offset);
    SP_CHECK("contacts mixed count",
             contacts && contacts_projection_count(contacts) == 1);
    SP_CHECK("onion mixed count",
             onion_p && onion_ann_projection_count(onion_p) == 1);
    SP_CHECK("hodl mixed count",
             hodl && hodl_history_projection_count(hodl) == 2);

    {
        struct json_value dump = {0};
        SP_CHECK("contacts dump",
                 contacts_projection_dump_state_json(&dump, NULL));
        SP_CHECK("contacts dump count",
                 json_get_int(json_get(&dump, "count")) == 1);
        SP_CHECK("contacts dump table count",
                 json_get_int(json_get(&dump, "contacts_count")) == 1);
        SP_CHECK("contacts dump consumed",
                 json_get_int(json_get(&dump, "events_consumed_total")) == 4);
        SP_CHECK("contacts dump set events",
                 json_get_int(json_get(&dump, "contact_set_total")) == 2);
        SP_CHECK("contacts dump touch events",
                 json_get_int(json_get(&dump, "contact_touched_total")) == 1);
        SP_CHECK("contacts dump delete events",
                 json_get_int(json_get(&dump, "contact_delete_total")) == 1);
        json_free(&dump);

        memset(&dump, 0, sizeof(dump));
        SP_CHECK("onion dump",
                 onion_ann_projection_dump_state_json(&dump, NULL));
        SP_CHECK("onion dump count",
                 json_get_int(json_get(&dump, "count")) == 1);
        SP_CHECK("onion dump table count",
                 json_get_int(json_get(&dump, "onion_announcements_count")) == 1);
        SP_CHECK("onion dump consumed",
                 json_get_int(json_get(&dump, "events_consumed_total")) == 1);
        SP_CHECK("onion dump announcement events",
                 json_get_int(json_get(&dump, "announcement_total")) == 1);
        json_free(&dump);

        memset(&dump, 0, sizeof(dump));
        SP_CHECK("hodl dump",
                 hodl_history_projection_dump_state_json(&dump, NULL));
        SP_CHECK("hodl dump count",
                 json_get_int(json_get(&dump, "count")) == 2);
        SP_CHECK("hodl dump table count",
                 json_get_int(json_get(&dump, "hodl_history_count")) == 2);
        SP_CHECK("hodl dump consumed",
                 json_get_int(json_get(&dump, "events_consumed_total")) == 2);
        SP_CHECK("hodl dump snapshot events",
                 json_get_int(json_get(&dump, "snapshot_total")) == 2);
        json_free(&dump);
    }

    contacts_projection_close(contacts);
    onion_ann_projection_close(onion_p);
    hodl_history_projection_close(hodl);

    contacts = contacts_projection_open(contacts_path, log);
    onion_p = onion_ann_projection_open(onion_path, log);
    hodl = hodl_history_projection_open(hodl_path, log);
    SP_CHECK("contacts mixed offset persisted",
             contacts && contacts_projection_catch_up(contacts) == end_offset);
    SP_CHECK("onion mixed offset persisted",
             onion_p && onion_ann_projection_catch_up(onion_p) == end_offset);
    SP_CHECK("hodl mixed offset persisted",
             hodl && hodl_history_projection_catch_up(hodl) == end_offset);
    SP_CHECK("contacts mixed reopen count",
             contacts && contacts_projection_count(contacts) == 1);
    SP_CHECK("onion mixed reopen count",
             onion_p && onion_ann_projection_count(onion_p) == 1);
    SP_CHECK("hodl mixed reopen count",
             hodl && hodl_history_projection_count(hodl) == 2);

    contacts_projection_close(contacts);
    onion_ann_projection_close(onion_p);
    hodl_history_projection_close(hodl);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_projection_rollback_restores_cached_offsets(void)
{
    int failures = 0;
    char dir[256];
    char elog_path[320];
    char onion_path[320];
    char hodl_path[320];
    test_make_tmpdir(dir, sizeof(dir), "small_projections", "rollback");
    snprintf(elog_path, sizeof(elog_path), "%s/event_log.dat", dir);
    snprintf(onion_path, sizeof(onion_path), "%s/onion_announcements.db",
             dir);
    snprintf(hodl_path, sizeof(hodl_path), "%s/hodl_history.db", dir);

    event_log_t *log = event_log_open(elog_path);
    const uint8_t malformed[] = {0x01};
    const char *onion =
        "defghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi.onion";
    SP_CHECK("rollback append onion valid",
             append_onion_announcement_event(log, onion, "6a045a434c23",
                                             1764444444u));
    SP_CHECK("rollback append onion malformed",
             event_log_append(log, EV_ONION_ANNOUNCEMENT, malformed,
                              sizeof(malformed)) != UINT64_MAX);
    SP_CHECK("rollback append hodl valid",
             append_hodl_snapshot_event(log, 300));
    SP_CHECK("rollback append hodl malformed",
             event_log_append(log, EV_HODL_SNAPSHOT, malformed,
                              sizeof(malformed)) != UINT64_MAX);

    onion_ann_projection_t *onion_p =
        onion_ann_projection_open(onion_path, log);
    hodl_history_projection_t *hodl =
        hodl_history_projection_open(hodl_path, log);

    SP_CHECK("rollback onion catch up fails",
             onion_p &&
             onion_ann_projection_catch_up(onion_p) == UINT64_MAX);
    SP_CHECK("rollback onion table empty",
             onion_p && onion_ann_projection_count(onion_p) == 0);
    struct json_value dump = {0};
    SP_CHECK("rollback onion dump",
             onion_ann_projection_dump_state_json(&dump, NULL));
    SP_CHECK("rollback onion cached offset restored",
             dump_int(&dump, "last_consumed_offset") == 0);
    json_free(&dump);

    memset(&dump, 0, sizeof(dump));
    SP_CHECK("rollback hodl catch up fails",
             hodl &&
             hodl_history_projection_catch_up(hodl) == UINT64_MAX);
    SP_CHECK("rollback hodl table empty",
             hodl && hodl_history_projection_count(hodl) == 0);
    SP_CHECK("rollback hodl dump",
             hodl_history_projection_dump_state_json(&dump, NULL));
    SP_CHECK("rollback hodl cached offset restored",
             dump_int(&dump, "last_consumed_offset") == 0);
    json_free(&dump);

    onion_ann_projection_close(onion_p);
    hodl_history_projection_close(hodl);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_projection_emit_helpers(void)
{
    int failures = 0;
    char dir[256];
    char elog_path[320];
    char contacts_path[320];
    char onion_path[320];
    char hodl_path[320];
    char legacy_path[320];
    test_make_tmpdir(dir, sizeof(dir), "small_projections", "emit");
    snprintf(elog_path, sizeof(elog_path), "%s/event_log.dat", dir);
    snprintf(contacts_path, sizeof(contacts_path), "%s/contacts.db", dir);
    snprintf(onion_path, sizeof(onion_path), "%s/onion_announcements.db",
             dir);
    snprintf(hodl_path, sizeof(hodl_path), "%s/hodl_history.db", dir);
    snprintf(legacy_path, sizeof(legacy_path), "%s/legacy.db", dir);

    event_log_t *log = event_log_open(elog_path);
    SP_CHECK("emit event log open", log != NULL);
    if (!log) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    contacts_projection_set_event_log(log);
    onion_ann_projection_set_event_log(log);
    hodl_history_projection_set_event_log(log);

    struct json_value contacts_before = {0};
    struct json_value onion_before = {0};
    struct json_value hodl_before = {0};
    contacts_projection_dump_state_json(&contacts_before, NULL);
    onion_ann_projection_dump_state_json(&onion_before, NULL);
    hodl_history_projection_dump_state_json(&hodl_before, NULL);

    const char *onion_addr =
        "cdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh.onion";
    SP_CHECK("emit contact set",
             contacts_projection_emit_set("t1EmitAlice", "Alice"));
    SP_CHECK("emit contact touched",
             contacts_projection_emit_touched("t1EmitAlice", 1763333333u));
    SP_CHECK("emit onion",
             onion_ann_projection_emit(onion_addr, 1763333334u,
                                       "6a045a434c2301"));
    SP_CHECK("emit hodl",
             hodl_history_projection_emit_snapshot(
                 200, 1763333335u, 123456789LL, 12345LL, 0.01));

    struct json_value contacts_after = {0};
    struct json_value onion_after = {0};
    struct json_value hodl_after = {0};
    contacts_projection_dump_state_json(&contacts_after, NULL);
    onion_ann_projection_dump_state_json(&onion_after, NULL);
    hodl_history_projection_dump_state_json(&hodl_after, NULL);
    SP_CHECK("emit contact set counter",
             dump_int(&contacts_after, "emit_set_total") ==
             dump_int(&contacts_before, "emit_set_total") + 1);
    SP_CHECK("emit contact touched counter",
             dump_int(&contacts_after, "emit_touched_total") ==
             dump_int(&contacts_before, "emit_touched_total") + 1);
    SP_CHECK("emit onion counter",
             dump_int(&onion_after, "emit_announcement_total") ==
             dump_int(&onion_before, "emit_announcement_total") + 1);
    SP_CHECK("emit hodl counter",
             dump_int(&hodl_after, "emit_snapshot_total") ==
             dump_int(&hodl_before, "emit_snapshot_total") + 1);
    json_free(&contacts_before);
    json_free(&onion_before);
    json_free(&hodl_before);
    json_free(&contacts_after);
    json_free(&onion_after);
    json_free(&hodl_after);

    contacts_projection_t *contacts =
        contacts_projection_open(contacts_path, log);
    onion_ann_projection_t *onion =
        onion_ann_projection_open(onion_path, log);
    hodl_history_projection_t *hodl =
        hodl_history_projection_open(hodl_path, log);
    uint64_t end_offset = event_log_size(log);
    SP_CHECK("emit contacts catchup",
             contacts && contacts_projection_catch_up(contacts) == end_offset);
    SP_CHECK("emit onion catchup",
             onion && onion_ann_projection_catch_up(onion) == end_offset);
    SP_CHECK("emit hodl catchup",
             hodl && hodl_history_projection_catch_up(hodl) == end_offset);
    SP_CHECK("emit contacts count",
             contacts && contacts_projection_count(contacts) == 1);
    SP_CHECK("emit onion count",
             onion && onion_ann_projection_count(onion) == 1);
    SP_CHECK("emit hodl count",
             hodl && hodl_history_projection_count(hodl) == 1);

    sqlite3 *legacy = NULL;
    SP_CHECK("emit legacy db open",
             sqlite3_open(legacy_path, &legacy) == SQLITE_OK && legacy);
    if (legacy) {
        bool ok =
            exec_test_sql(legacy,
                "CREATE TABLE contacts(address TEXT PRIMARY KEY,"
                "name TEXT NOT NULL,last_used INTEGER NOT NULL)") &&
            exec_test_sql(legacy,
                "INSERT INTO contacts VALUES"
                "('t1EmitAlice','Alice',1763333333)") &&
            exec_test_sql(legacy,
                "CREATE TABLE onion_announcements("
                "onion_address TEXT PRIMARY KEY,"
                "announced_at INTEGER NOT NULL,"
                "script_hex TEXT NOT NULL DEFAULT '')") &&
            exec_test_sql(legacy,
                "INSERT INTO onion_announcements VALUES"
                "('cdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh.onion',"
                "1763333334,'6a045a434c2301')") &&
            exec_test_sql(legacy,
                "CREATE TABLE hodl_history(height INTEGER PRIMARY KEY,"
                "time INTEGER NOT NULL,total_zat INTEGER NOT NULL,"
                "older_1y_zat INTEGER NOT NULL,older_1y_pct REAL NOT NULL)") &&
            exec_test_sql(legacy,
                "INSERT INTO hodl_history VALUES"
                "(200,1763333335,123456789,12345,0.01)");
        SP_CHECK("emit legacy seed", ok);

        int64_t pc = 0;
        int64_t lc = 0;
        char first_diff[256] = {0};
        SP_CHECK("emit contacts table match",
                 test_projection_db_matches_legacy(
                     contacts_path, legacy,
                     "SELECT COUNT(*) FROM contacts",
                     "SELECT address,name,last_used "
                     "FROM contacts ORDER BY address ASC",
                     3, &pc, &lc, first_diff, sizeof(first_diff)) &&
                 pc == 1 && lc == 1 && first_diff[0] == '\0');
        SP_CHECK("emit onion table match",
                 test_projection_db_matches_legacy(
                     onion_path, legacy,
                     "SELECT COUNT(*) FROM onion_announcements",
                     "SELECT onion_address,announced_at,script_hex "
                     "FROM onion_announcements ORDER BY onion_address ASC",
                     3, &pc, &lc, first_diff, sizeof(first_diff)) &&
                 pc == 1 && lc == 1 && first_diff[0] == '\0');
        SP_CHECK("emit hodl table match",
                 test_projection_db_matches_legacy(
                     hodl_path, legacy,
                     "SELECT COUNT(*) FROM hodl_history",
                     "SELECT height,time,total_zat,older_1y_zat,"
                     "older_1y_pct FROM hodl_history ORDER BY height ASC",
                     5, &pc, &lc, first_diff, sizeof(first_diff)) &&
                 pc == 1 && lc == 1 && first_diff[0] == '\0');
        SP_CHECK("emit contacts first diff",
                 exec_test_sql(legacy,
                     "UPDATE contacts SET name='Alicia' "
                     "WHERE address='t1EmitAlice'") &&
                 test_projection_db_matches_legacy(
                     contacts_path, legacy,
                     "SELECT COUNT(*) FROM contacts",
                     "SELECT address,name,last_used "
                     "FROM contacts ORDER BY address ASC",
                     3, &pc, &lc, first_diff, sizeof(first_diff)) &&
                 strcmp(first_diff, "t1EmitAlice") == 0);
        sqlite3_close(legacy);
    }

    contacts_projection_close(contacts);
    onion_ann_projection_close(onion);
    hodl_history_projection_close(hodl);
    contacts_projection_set_event_log(NULL);
    onion_ann_projection_set_event_log(NULL);
    hodl_history_projection_set_event_log(NULL);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_small_projections(void)
{
    int failures = 0;
    printf("\n=== small_projections tests ===\n");
    failures += t_payload_ids();
    failures += t_contact_payload_roundtrip();
    failures += t_onion_payload_roundtrip();
    failures += t_hodl_payload_roundtrip();
    failures += t_projection_skeletons_fresh();
    failures += t_projection_catchup_mixed();
    failures += t_projection_rollback_restores_cached_offsets();
    failures += t_projection_emit_helpers();
    printf("small_projections: %d failures\n", failures);
    return failures;
}
