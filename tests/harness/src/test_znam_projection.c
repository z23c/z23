/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "json/json.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/znam_projection.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZP_CHECK(label, cond) do { \
    bool _ok = (cond); \
    printf("znam_projection: %s... %s\n", (label), _ok ? "OK" : "FAIL"); \
    if (!_ok) failures++; \
} while (0)


static void fill_txid(uint8_t txid[32], uint8_t tail)
{
    memset(txid, 0xAA, 32);
    txid[31] = tail;
}

static bool append_register(event_log_t *log, const char *name,
                            const char *owner, uint8_t type,
                            const char *value, uint8_t txid_tail,
                            int32_t reg_height, int32_t expiry)
{
    struct ev_znam_register ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.owner_len = (uint8_t)strlen(owner);
    memcpy(ev.owner_address, owner, ev.owner_len);
    ev.target_type = type;
    ev.target_value_len = (uint8_t)strlen(value);
    memcpy(ev.target_value, value, ev.target_value_len);
    fill_txid(ev.reg_txid, txid_tail);
    ev.reg_height = reg_height;
    ev.registered_unix = 1700000000u;
    ev.expiry_height = expiry;
    if (!ev_znam_register_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_REGISTER, payload, len) != UINT64_MAX;
}

static bool append_update_text(event_log_t *log, const char *name,
                               const char *key, const char *value,
                               uint8_t txid_tail)
{
    struct ev_znam_update ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.action_type = EV_ZNAM_UPDATE_ACTION_TEXT;
    ev.key_len = (uint8_t)strlen(key);
    memcpy(ev.key, key, ev.key_len);
    ev.value_len = (uint8_t)strlen(value);
    memcpy(ev.value, value, ev.value_len);
    fill_txid(ev.update_txid, txid_tail);
    if (!ev_znam_update_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_UPDATE, payload, len) != UINT64_MAX;
}

static bool append_update_addr(event_log_t *log, const char *name,
                               uint8_t coin_type, const char *address,
                               uint8_t txid_tail)
{
    struct ev_znam_update ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.action_type = EV_ZNAM_UPDATE_ACTION_ADDR;
    ev.key_or_coin_type = coin_type;
    ev.value_len = (uint8_t)strlen(address);
    memcpy(ev.value, address, ev.value_len);
    fill_txid(ev.update_txid, txid_tail);
    if (!ev_znam_update_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_UPDATE, payload, len) != UINT64_MAX;
}

static bool append_transfer(event_log_t *log, const char *name,
                            const char *new_owner, uint8_t txid_tail)
{
    struct ev_znam_transfer ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.new_owner_len = (uint8_t)strlen(new_owner);
    memcpy(ev.new_owner, new_owner, ev.new_owner_len);
    fill_txid(ev.update_txid, txid_tail);
    if (!ev_znam_transfer_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_TRANSFER, payload, len) != UINT64_MAX;
}

static bool append_renew(event_log_t *log, const char *name,
                         int32_t new_expiry, uint8_t txid_tail)
{
    struct ev_znam_renew ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.new_expiry_height = new_expiry;
    fill_txid(ev.update_txid, txid_tail);
    if (!ev_znam_renew_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_RENEW, payload, len) != UINT64_MAX;
}

static bool append_expire(event_log_t *log, const char *name,
                          int32_t expired_at)
{
    struct ev_znam_expire ev;
    uint8_t payload[512];
    size_t len = 0;
    memset(&ev, 0, sizeof(ev));
    ev.name_len = (uint8_t)strlen(name);
    memcpy(ev.name, name, ev.name_len);
    ev.expired_at_height = expired_at;
    if (!ev_znam_expire_serialize(&ev, payload, sizeof(payload), &len))
        return false;
    return event_log_append(log, EV_ZNAM_EXPIRE, payload, len) != UINT64_MAX;
}

static int64_t znam_dump_int(struct json_value *dump, const char *key)
{
    const struct json_value *v = json_get(dump, key);
    return v ? json_get_int(v) : -1;
}

static int t_payload_roundtrip(void)
{
    int failures = 0;

    /* REGISTER */
    {
        struct ev_znam_register in, out;
        uint8_t buf[512];
        size_t len = 0;
        memset(&in, 0, sizeof(in));
        in.name_len = 5; memcpy(in.name, "alice", 5);
        in.owner_len = 7; memcpy(in.owner_address, "t1Owner", 7);
        in.target_type = 1;
        in.target_value_len = 11; memcpy(in.target_value, "abcde.onion", 11);
        fill_txid(in.reg_txid, 9);
        in.reg_height = 100; in.registered_unix = 1700000000u;
        in.expiry_height = 50000;
        ZP_CHECK("register serialize",
                 ev_znam_register_serialize(&in, buf, sizeof(buf), &len));
        ZP_CHECK("register parse",
                 ev_znam_register_parse(buf, len, &out));
        ZP_CHECK("register roundtrip",
                 out.name_len == in.name_len &&
                 memcmp(out.name, in.name, in.name_len) == 0 &&
                 out.owner_len == in.owner_len &&
                 memcmp(out.owner_address, in.owner_address, in.owner_len) == 0 &&
                 out.target_type == in.target_type &&
                 out.target_value_len == in.target_value_len &&
                 memcmp(out.target_value, in.target_value,
                        in.target_value_len) == 0 &&
                 memcmp(out.reg_txid, in.reg_txid, 32) == 0 &&
                 out.reg_height == in.reg_height &&
                 out.registered_unix == in.registered_unix &&
                 out.expiry_height == in.expiry_height);
    }

    /* UPDATE (text) */
    {
        struct ev_znam_update in, out;
        uint8_t buf[512];
        size_t len = 0;
        memset(&in, 0, sizeof(in));
        in.name_len = 5; memcpy(in.name, "alice", 5);
        in.action_type = EV_ZNAM_UPDATE_ACTION_TEXT;
        in.key_len = 5; memcpy(in.key, "email", 5);
        in.value_len = 13; memcpy(in.value, "a@example.com", 13);
        fill_txid(in.update_txid, 11);
        ZP_CHECK("update serialize",
                 ev_znam_update_serialize(&in, buf, sizeof(buf), &len));
        ZP_CHECK("update parse",
                 ev_znam_update_parse(buf, len, &out));
        ZP_CHECK("update roundtrip",
                 out.action_type == in.action_type &&
                 out.key_len == in.key_len &&
                 memcmp(out.key, in.key, in.key_len) == 0 &&
                 out.value_len == in.value_len &&
                 memcmp(out.value, in.value, in.value_len) == 0);
    }

    /* TRANSFER */
    {
        struct ev_znam_transfer in, out;
        uint8_t buf[256];
        size_t len = 0;
        memset(&in, 0, sizeof(in));
        in.name_len = 5; memcpy(in.name, "alice", 5);
        in.new_owner_len = 5; memcpy(in.new_owner, "t1Bob", 5);
        fill_txid(in.update_txid, 12);
        ZP_CHECK("transfer serialize",
                 ev_znam_transfer_serialize(&in, buf, sizeof(buf), &len));
        ZP_CHECK("transfer parse",
                 ev_znam_transfer_parse(buf, len, &out));
        ZP_CHECK("transfer roundtrip",
                 out.new_owner_len == in.new_owner_len &&
                 memcmp(out.new_owner, in.new_owner, in.new_owner_len) == 0);
    }

    /* RENEW */
    {
        struct ev_znam_renew in, out;
        uint8_t buf[128];
        size_t len = 0;
        memset(&in, 0, sizeof(in));
        in.name_len = 5; memcpy(in.name, "alice", 5);
        in.new_expiry_height = 99999;
        fill_txid(in.update_txid, 13);
        ZP_CHECK("renew serialize",
                 ev_znam_renew_serialize(&in, buf, sizeof(buf), &len));
        ZP_CHECK("renew parse",
                 ev_znam_renew_parse(buf, len, &out));
        ZP_CHECK("renew roundtrip",
                 out.new_expiry_height == in.new_expiry_height);
    }

    /* EXPIRE */
    {
        struct ev_znam_expire in, out;
        uint8_t buf[128];
        size_t len = 0;
        memset(&in, 0, sizeof(in));
        in.name_len = 5; memcpy(in.name, "alice", 5);
        in.expired_at_height = 12345;
        ZP_CHECK("expire serialize",
                 ev_znam_expire_serialize(&in, buf, sizeof(buf), &len));
        ZP_CHECK("expire parse",
                 ev_znam_expire_parse(buf, len, &out));
        ZP_CHECK("expire roundtrip",
                 out.expired_at_height == in.expired_at_height);
    }

    return failures;
}

static int t_open_close_clean(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "open");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);
    ZP_CHECK("open handles", log && p);
    ZP_CHECK("empty name count", znam_projection_name_count(p) == 0);
    znam_projection_close(p);
    event_log_close(log);
    log = event_log_open(elog_path);
    p = znam_projection_open(proj_path, log);
    ZP_CHECK("reopen handles", log && p);
    ZP_CHECK("reopen empty count", znam_projection_name_count(p) == 0);
    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_register_replay(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "register");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);

    ZP_CHECK("append register",
             append_register(log, "alice", "t1OwnerAlice", 1,
                             "alice.onion", 1, 100, 50000));
    ZP_CHECK("catch up", znam_projection_catch_up(p) != UINT64_MAX);
    ZP_CHECK("count one", znam_projection_name_count(p) == 1);

    char owner[65], value[129];
    uint8_t type = 0;
    int32_t reg_h = 0, exp_h = 0;
    ZP_CHECK("find alice",
             znam_projection_find(p, "alice", owner, sizeof(owner),
                                  &type, value, sizeof(value),
                                  &reg_h, &exp_h));
    ZP_CHECK("alice owner",  strcmp(owner, "t1OwnerAlice") == 0);
    ZP_CHECK("alice type",   type == 1);
    ZP_CHECK("alice value",  strcmp(value, "alice.onion") == 0);
    ZP_CHECK("alice height", reg_h == 100);
    ZP_CHECK("alice expiry", exp_h == 50000);

    ZP_CHECK("idempotent catch up",
             znam_projection_catch_up(p) != UINT64_MAX);
    ZP_CHECK("count still one", znam_projection_name_count(p) == 1);

    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_update_addr_and_text(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "update");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);

    append_register(log, "bob", "t1OwnerBob", 1, "bob.onion", 2, 200, 60000);
    append_update_addr(log, "bob", 4, "bc1qbtcaddr", 3);  /* BTC */
    append_update_addr(log, "bob", 5, "Ltcaddress", 4);   /* LTC */
    append_update_text(log, "bob", "email", "bob@example.com", 5);
    append_update_text(log, "bob", "url", "https://bob.example", 6);

    ZP_CHECK("catch up", znam_projection_catch_up(p) != UINT64_MAX);
    ZP_CHECK("addr count 2", znam_projection_addr_count(p) == 2);
    ZP_CHECK("text count 2", znam_projection_text_count(p) == 2);

    char buf[256];
    ZP_CHECK("addr get btc",
             znam_projection_addr_get(p, "bob", 4, buf, sizeof(buf)) &&
             strcmp(buf, "bc1qbtcaddr") == 0);
    ZP_CHECK("addr get ltc",
             znam_projection_addr_get(p, "bob", 5, buf, sizeof(buf)) &&
             strcmp(buf, "Ltcaddress") == 0);
    ZP_CHECK("text get email",
             znam_projection_text_get(p, "bob", "email", buf, sizeof(buf)) &&
             strcmp(buf, "bob@example.com") == 0);
    ZP_CHECK("text get url",
             znam_projection_text_get(p, "bob", "url", buf, sizeof(buf)) &&
             strcmp(buf, "https://bob.example") == 0);

    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_transfer_renew_expire(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "lifecycle");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);

    append_register(log, "carol", "t1OwnerOriginal", 1, "carol.onion",
                    7, 300, 70000);
    append_update_addr(log, "carol", 4, "bc1qcarol", 8);
    append_transfer(log, "carol", "t1OwnerNew", 9);
    append_renew(log, "carol", 80000, 10);

    ZP_CHECK("catch up after transfer+renew",
             znam_projection_catch_up(p) != UINT64_MAX);
    char owner[65], value[129];
    int32_t reg_h = 0, exp_h = 0;
    uint8_t type = 0;
    ZP_CHECK("carol found",
             znam_projection_find(p, "carol", owner, sizeof(owner),
                                  &type, value, sizeof(value),
                                  &reg_h, &exp_h));
    ZP_CHECK("owner updated", strcmp(owner, "t1OwnerNew") == 0);
    ZP_CHECK("expiry renewed", exp_h == 80000);

    /* Addr record still present after transfer/renew */
    char buf[128];
    ZP_CHECK("addr survives transfer",
             znam_projection_addr_get(p, "carol", 4, buf, sizeof(buf)) &&
             strcmp(buf, "bc1qcarol") == 0);

    /* Expire wipes everything */
    append_expire(log, "carol", 90000);
    ZP_CHECK("catch up after expire",
             znam_projection_catch_up(p) != UINT64_MAX);
    ZP_CHECK("carol gone after expire",
             !znam_projection_find(p, "carol", owner, sizeof(owner),
                                   &type, value, sizeof(value),
                                   &reg_h, &exp_h));
    ZP_CHECK("addr gone after expire",
             !znam_projection_addr_get(p, "carol", 4, buf, sizeof(buf)));
    ZP_CHECK("name count zero", znam_projection_name_count(p) == 0);

    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_persists_across_reopen(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "persist");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));

    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);
    append_register(log, "dave", "t1OwnerDave", 1, "dave.onion", 14, 400, 70000);
    append_update_text(log, "dave", "email", "dave@example.com", 15);
    ZP_CHECK("initial catch up",
             znam_projection_catch_up(p) != UINT64_MAX);
    ZP_CHECK("initial counts",
             znam_projection_name_count(p) == 1 &&
             znam_projection_text_count(p) == 1);
    znam_projection_close(p);
    event_log_close(log);

    log = event_log_open(elog_path);
    p = znam_projection_open(proj_path, log);
    ZP_CHECK("reopen finds dave",
             znam_projection_name_count(p) == 1);
    ZP_CHECK("reopen finds email",
             znam_projection_text_count(p) == 1);
    /* Idempotent catch_up should be a no-op (no new events). */
    ZP_CHECK("idempotent catch up across reopen",
             znam_projection_catch_up(p) != UINT64_MAX);
    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_rollback_restores_cached_offset(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "znam_projection", "rollback");
    test_projection_paths(dir, "znam", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));

    event_log_t *log = event_log_open(elog_path);
    znam_projection_t *p = znam_projection_open(proj_path, log);
    const uint8_t malformed[] = {0x01};
    ZP_CHECK("rollback append valid",
             append_register(log, "erin", "t1OwnerErin", 1,
                             "erin.onion", 21, 500, 80000));
    ZP_CHECK("rollback append malformed",
             event_log_append(log, EV_ZNAM_UPDATE, malformed,
                              sizeof(malformed)) != UINT64_MAX);
    ZP_CHECK("rollback catch up fails",
             znam_projection_catch_up(p) == UINT64_MAX);
    ZP_CHECK("rollback table empty", znam_projection_name_count(p) == 0);

    struct json_value dump = {0};
    ZP_CHECK("rollback dump", znam_projection_dump_state_json(&dump, NULL));
    ZP_CHECK("rollback cached offset restored",
             znam_dump_int(&dump, "last_consumed_offset") == 0);
    json_free(&dump);

    znam_projection_close(p);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_znam_projection(void)
{
    int failures = 0;
    printf("\n=== znam_projection tests ===\n");
    failures += t_payload_roundtrip();
    failures += t_open_close_clean();
    failures += t_register_replay();
    failures += t_update_addr_and_text();
    failures += t_transfer_renew_expire();
    failures += t_persists_across_reopen();
    failures += t_rollback_restores_cached_offset();
    printf("znam_projection: %d failures\n", failures);
    return failures;
}
