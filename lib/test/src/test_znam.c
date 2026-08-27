/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for ZCL Names (ZNAM) — parser, builder, validator, DB persistence,
 * and the name_update/name_transfer/name_renew/name_set_record/
 * name_set_text RPC write surface (app/controllers/src/name_controller.c). */

#include "test/test_core.h"
#include "models/database.h"
#include "models/znam.h"
#include "controllers/name_controller.h"
#include "rpc/server.h"
#include "json/json.h"
#include "wallet/wallet.h"
#include "services/zslp_command_service.h"
#include "script/standard.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "validation/txmempool.h"
#include "validation/main_state.h"
#include "coins/coins_view.h"
#include <inttypes.h>
#include <string.h>

static int znam_count_step_interrupted(void *stmt)
{
    (void)stmt;
    return SQLITE_INTERRUPT;
}

/* ── Test helpers for the RPC write surface ────────────────────────
 *
 * Mirrors the fixture test_api.c already uses for name_list/name_register
 * (in-memory sqlite + rpc_table_init/register_name_rpc_commands/
 * rpc_table_find), factored here since the new commands need it five
 * times over for positive + negative coverage. */

static bool open_test_names_db(sqlite3 **db_out, struct node_db *ndb_out)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    sqlite3_exec(db,
        "CREATE TABLE znam_names("
        "name TEXT PRIMARY KEY, owner_address TEXT,"
        "target_type INTEGER, target_value TEXT,"
        "reg_txid BLOB, reg_height INTEGER,"
        "last_update_txid BLOB,"
        "expiry_height INTEGER NOT NULL DEFAULT 0)",
        NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE znam_text_records("
        "name TEXT, key TEXT, value TEXT,"
        "PRIMARY KEY(name,key))", NULL, NULL, NULL);
    sqlite3_exec(db,
        "CREATE TABLE znam_addr_records("
        "name TEXT, coin_type INTEGER, address TEXT,"
        "PRIMARY KEY(name,coin_type))", NULL, NULL, NULL);
    *db_out = db;
    ndb_out->db = db;
    ndb_out->open = true;
    return true;
}

/* Call a registered name_* RPC with 0-3 string args. has_a2 distinguishes
 * "no 3rd arg" from "3rd arg is an explicit empty string" (name_set_text's
 * optional value). Frees params; leaves *result for the caller to inspect
 * and free. */
static bool call_name_rpc(struct rpc_table *t, const char *method,
                          const char *a0, const char *a1,
                          bool has_a2, const char *a2,
                          struct json_value *result)
{
    const struct rpc_command *cmd = rpc_table_find(t, method);
    if (!cmd) return false;
    struct json_value params = {0}, v = {0};
    json_set_array(&params);
    /* json_set_str() internally json_free()s v's PREVIOUS contents before
     * overwriting (lib/json/src/json.c) — an extra manual json_free(&v)
     * between pushes double-frees v.val.s on the next json_set_str call.
     * One json_free(&v) after the last json_set_str is correct and
     * sufficient; json_push_back() deep-copies into params so v's storage
     * is independent of the array from that point on. */
    if (a0) { json_set_str(&v, a0); json_push_back(&params, &v); }
    if (a1) { json_set_str(&v, a1); json_push_back(&params, &v); }
    if (has_a2) { json_set_str(&v, a2 ? a2 : ""); json_push_back(&params, &v); }
    json_free(&v);
    bool ok = cmd->actor(&params, false, result);
    json_free(&params);
    return ok;
}

/* Fund a wallet-owned P2PKH coin so wallet_available_coins()/
 * zslp_command_build_owner_base_tx() can select it (confirms>=1, not
 * coinbase — see wallet_available_coins in lib/wallet/src/wallet.c). */

/* wallet_get_new_address() on a plain (non-HD) wallet_init()'d wallet
 * refuses every key with "no persisted keypool entry available" — the
 * legacy key-pool path only hands out entries a durability flush has
 * marked persisted (see wallet_key_pool_mark_persisted_through, which a
 * bare unit test never calls). An HD wallet has no such gate — an
 * address is always re-derivable from the seed — so seed it instead;
 * distinct seed_byte values give distinct wallets provably different
 * addresses, as the "not the owner" tests below require. */
static void init_hd_wallet(struct wallet *w, uint8_t seed_byte)
{
    uint8_t seed[32];
    memset(seed, seed_byte, sizeof(seed));
    wallet_init(w);
    wallet_init_hd(w, seed, sizeof(seed));
}

static bool fund_wallet_key(struct wallet *w, const struct key_id *kid,
                            int64_t value)
{
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    transaction_init(&wtx.tx);
    if (!transaction_alloc(&wtx.tx, 0, 1)) return false;
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    dest.id.key = *kid;
    script_for_destination(&wtx.tx.vout[0].script_pub_key, &dest);
    wtx.tx.vout[0].value = value;
    transaction_compute_hash(&wtx.tx);
    wtx.confirms = 10;
    bool ok = wallet_add_to_wallet(w, &wtx);
    transaction_free(&wtx.tx);
    return ok;
}

/* ── Wallet-wide name sweep ────────────────────────────────────────────
 *
 * db_znam_list_by_owner answers for ONE owner address the caller already
 * knows. The wallet-wide sweep answers "which names does this node own" by
 * deriving that owner set from the wallet itself — wallet_keys encoded as
 * this chain's P2PKH addresses plus wallet_watch_only's stored text. The
 * cases that matter: a keyless wallet (empty, not an error), a name owned
 * by a wallet key, a name owned by a stranger (excluded), a name owned by
 * a watch-only address, and the same address reachable twice (listed once). */

static void znam_test_p2pkh(const uint8_t hash160[20], char out[64])
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, hash160, 20);
    out[0] = 0;
    (void)encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, out, 64);
}

static void znam_test_ins_key(struct node_db *ndb, const uint8_t hash160[20])
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO wallet_keys"
        "(pubkey_hash,pubkey,privkey,compressed,created_at)"
        " VALUES(?,zeroblob(33),zeroblob(32),1,0)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash160, 20, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void znam_test_ins_watch(struct node_db *ndb, const uint8_t hash160[20],
                                const char *address)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO wallet_watch_only"
        "(address_hash,address,created_at) VALUES(?,?,0)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash160, 20, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, address, -1, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static bool znam_test_register(struct node_db *ndb, const char *name,
                               const char *owner, int32_t reg_height)
{
    struct znam_entry e;
    memset(&e, 0, sizeof(e));
    snprintf(e.name, sizeof(e.name), "%s", name);
    snprintf(e.owner_address, sizeof(e.owner_address), "%s", owner);
    e.target_type = ZNAM_TYPE_ONION;
    snprintf(e.target_value, sizeof(e.target_value), "%s.onion", name);
    memset(e.reg_txid, 0x5A, sizeof(e.reg_txid));
    memset(e.last_update_txid, 0x5A, sizeof(e.last_update_txid));
    e.reg_height = reg_height;
    e.expiry_height = reg_height + 1000;
    return db_znam_save(ndb, &e);
}

static int test_znam_wallet_sweep(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("znam wallet: open in-memory node.db... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    uint8_t mine[20], watched[20], stranger[20];
    memset(mine, 0xC1, sizeof(mine));
    memset(watched, 0xC2, sizeof(watched));
    memset(stranger, 0xC3, sizeof(stranger));

    char mine_addr[64], watched_addr[64], stranger_addr[64];
    znam_test_p2pkh(mine, mine_addr);
    znam_test_p2pkh(watched, watched_addr);
    znam_test_p2pkh(stranger, stranger_addr);

    bool seeded = znam_test_register(&ndb, "mine", mine_addr, 100) &&
                  znam_test_register(&ndb, "watched", watched_addr, 200) &&
                  znam_test_register(&ndb, "notmine", stranger_addr, 300);
    printf("znam wallet: seeded three registered names... ");
    if (seeded) printf("OK\n"); else { printf("FAIL\n"); failures++; }

    struct znam_entry owned[8];

    printf("znam wallet: a wallet with no keys owns 0 names "
           "(empty, not an error)... ");
    { int n = db_znam_list_wallet_owned(&ndb, owned, 8);
      int a = db_znam_wallet_address_count(&ndb);
      int all = db_znam_list(&ndb, owned, 8);
      if (n == 0 && a == 0 && all == 3) printf("OK\n");
      else { printf("FAIL (owned=%d addrs=%d registry=%d)\n", n, a, all);
             failures++; } }

    znam_test_ins_key(&ndb, mine);

    printf("znam wallet: a wallet key claims its own name and not the "
           "stranger's... ");
    { int n = db_znam_list_wallet_owned(&ndb, owned, 8);
      if (n == 1 && strcmp(owned[0].name, "mine") == 0 &&
          strcmp(owned[0].owner_address, mine_addr) == 0 &&
          owned[0].reg_height == 100 && owned[0].expiry_height == 1100)
          printf("OK\n");
      else { printf("FAIL (n=%d name=%s expiry=%d)\n", n,
                    n > 0 ? owned[0].name : "-",
                    n > 0 ? owned[0].expiry_height : -1); failures++; } }

    printf("znam wallet: the wallet-wide answer matches the per-owner one... ");
    { struct znam_entry by_owner[8];
      int a = db_znam_list_wallet_owned(&ndb, owned, 8);
      int b = db_znam_list_by_owner(&ndb, mine_addr, by_owner, 8);
      if (a == b && a == 1 && strcmp(owned[0].name, by_owner[0].name) == 0)
          printf("OK\n");
      else { printf("FAIL (wallet=%d owner=%d)\n", a, b); failures++; } }

    znam_test_ins_watch(&ndb, watched, watched_addr);

    printf("znam wallet: a watch-only address adds its name (2 owned, "
           "stranger still excluded)... ");
    { int n = db_znam_list_wallet_owned(&ndb, owned, 8);
      int a = db_znam_wallet_address_count(&ndb);
      bool saw_stranger = false;
      for (int i = 0; i < n; i++)
          if (strcmp(owned[i].name, "notmine") == 0) saw_stranger = true;
      if (n == 2 && a == 2 && !saw_stranger) printf("OK\n");
      else { printf("FAIL (owned=%d addrs=%d stranger=%d)\n", n, a,
                    (int)saw_stranger); failures++; } }

    /* Importing your own key as watch-only is the ordinary way one address
     * becomes reachable twice; the name must still be listed once. */
    znam_test_ins_watch(&ndb, mine, mine_addr);

    printf("znam wallet: an address reachable through both tables is folded "
           "once... ");
    { int n = db_znam_list_wallet_owned(&ndb, owned, 8);
      int a = db_znam_wallet_address_count(&ndb);
      if (n == 2 && a == 2) printf("OK\n");
      else { printf("FAIL (owned=%d addrs=%d)\n", n, a); failures++; } }

    printf("znam wallet: a zero-capacity sweep writes nothing and "
           "returns 0... ");
    { int n = db_znam_list_wallet_owned(&ndb, owned, 0);
      if (n == 0) printf("OK\n"); else { printf("FAIL (%d)\n", n); failures++; } }

    node_db_close(&ndb);
    return failures;
}

int test_znam(void)
{
    int failures = 0;

    /* ── Name validation ──────────────────────────────────────── */

    printf("\n=== ZNAM Tests ===\n");

    printf("znam_validate_name: valid lowercase alpha... ");
    if (znam_validate_name("alice")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: valid alphanumeric... ");
    if (znam_validate_name("node42")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: valid with hyphens... ");
    if (znam_validate_name("my-node-1")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject NULL... ");
    if (!znam_validate_name(NULL)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject empty... ");
    if (!znam_validate_name("")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject uppercase... ");
    if (!znam_validate_name("Alice")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject leading hyphen... ");
    if (!znam_validate_name("-alice")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject trailing hyphen... ");
    if (!znam_validate_name("alice-")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject special chars... ");
    if (!znam_validate_name("alice@bob")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject spaces... ");
    if (!znam_validate_name("alice bob")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: single char... ");
    if (znam_validate_name("a")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: max length (63 chars)... ");
    {
        char name64[64];
        memset(name64, 'a', 63);
        name64[63] = '\0';
        if (znam_validate_name(name64)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_validate_name: too long (64 chars)... ");
    {
        char name65[65];
        memset(name65, 'a', 64);
        name65[64] = '\0';
        if (!znam_validate_name(name65)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_validate_name: reject dots... ");
    if (!znam_validate_name("alice.bob")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: reject underscore... ");
    if (!znam_validate_name("alice_bob")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("znam_validate_name: all digits... ");
    if (znam_validate_name("12345")) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* ── Build + Parse roundtrip: REGISTER ────────────────────── */

    printf("znam build+parse REGISTER roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "mynode", ZNAM_TYPE_TADDR,
                                         "t1abc123");
        if (len == 0) { printf("FAIL (build)\n"); failures++; }
        else {
            struct znam_message msg;
            bool ok = znam_parse(buf, len, &msg);
            if (ok && msg.command == ZNAM_CMD_REGISTER &&
                strcmp(msg.name, "mynode") == 0 &&
                msg.target_type == ZNAM_TYPE_TADDR &&
                strcmp(msg.target_value, "t1abc123") == 0) {
                printf("OK\n");
            } else {
                printf("FAIL (parse: ok=%d cmd=%d name=%s type=%d val=%s)\n",
                       ok, msg.command, msg.name, msg.target_type,
                       msg.target_value);
                failures++;
            }
        }
    }

    /* ── Build + Parse roundtrip: UPDATE ──────────────────────── */

    printf("znam build+parse UPDATE roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_update(buf, sizeof(buf),
                                       "mynode", ZNAM_TYPE_ONION,
                                       "abc123.onion");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        if (ok && msg.command == ZNAM_CMD_UPDATE &&
            strcmp(msg.name, "mynode") == 0 &&
            msg.target_type == ZNAM_TYPE_ONION &&
            strcmp(msg.target_value, "abc123.onion") == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── Build + Parse roundtrip: TRANSFER ────────────────────── */

    printf("znam build+parse TRANSFER roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_transfer(buf, sizeof(buf),
                                         "mynode", "t1newowner");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        if (ok && msg.command == ZNAM_CMD_TRANSFER &&
            strcmp(msg.name, "mynode") == 0 &&
            strcmp(msg.new_owner, "t1newowner") == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── Build + Parse roundtrip: RENEW ───────────────────────── */

    printf("znam build+parse RENEW roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_renew(buf, sizeof(buf), "mynode");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        if (ok && msg.command == ZNAM_CMD_RENEW &&
            strcmp(msg.name, "mynode") == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── Build + Parse roundtrip: SET_RECORD ──────────────────── */

    printf("znam build+parse SET_RECORD roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_set_record(buf, sizeof(buf),
                                           "mynode", ZNAM_TYPE_BTC,
                                           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        if (ok && msg.command == ZNAM_CMD_SET_RECORD &&
            strcmp(msg.name, "mynode") == 0 &&
            msg.target_type == ZNAM_TYPE_BTC &&
            strcmp(msg.target_value, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── Build + Parse roundtrip: SET_TEXT ─────────────────────── */

    printf("znam build+parse SET_TEXT roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_set_text(buf, sizeof(buf),
                                         "mynode", "email",
                                         "user@example.com");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        if (ok && msg.command == ZNAM_CMD_SET_TEXT &&
            strcmp(msg.name, "mynode") == 0 &&
            strcmp(msg.text_key, "email") == 0 &&
            strcmp(msg.text_value, "user@example.com") == 0) {
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── SET_TEXT with empty value ─────────────────────────────── */

    printf("znam build+parse SET_TEXT empty value roundtrip... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_set_text(buf, sizeof(buf),
                                         "mynode", "avatar", "");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg);
        ok = ok && msg.command == ZNAM_CMD_SET_TEXT;
        ok = ok && strcmp(msg.name, "mynode") == 0;
        ok = ok && strcmp(msg.text_key, "avatar") == 0;
        ok = ok && msg.text_value[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Parser edge cases ────────────────────────────────────── */

    printf("znam_parse: reject empty script... ");
    {
        struct znam_message msg;
        if (!znam_parse(NULL, 0, &msg)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_parse: reject null output message... ");
    {
        uint8_t script[] = {0x6a};
        if (!znam_parse(script, sizeof(script), NULL)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_parse: reject non-OP_RETURN... ");
    {
        uint8_t bad[] = {0x76, 0x04, 'Z', 'N', 'A', 'M'};
        struct znam_message msg;
        if (!znam_parse(bad, sizeof(bad), &msg)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_parse: reject wrong lokad ID... ");
    {
        uint8_t bad[] = {0x6a, 0x04, 'Z', 'S', 'L', 'P', 0x01, 0x01, 0x01, 0x01, 0x05, 'h', 'e', 'l', 'l', 'o'};
        struct znam_message msg;
        if (!znam_parse(bad, sizeof(bad), &msg)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Builder validation ───────────────────────────────────── */

    printf("znam_build_register: reject invalid name... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "INVALID", ZNAM_TYPE_TADDR, "t1abc");
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_build_register: reject invalid target_type... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "valid", 0, "t1abc");
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── REGISTER/UPDATE accept multi-coin types (parser parity) ── */

    printf("znam_build_register: accepts ZNAM_TYPE_BTC... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "alice", ZNAM_TYPE_BTC,
                                         "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg) &&
                  msg.command == ZNAM_CMD_REGISTER &&
                  msg.target_type == ZNAM_TYPE_BTC;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam_build_register: accepts ZNAM_TYPE_LTC... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "bob", ZNAM_TYPE_LTC,
                                         "LcHKJaR1U8nzzcRhMqg9PbM9Nqv9UJbJKV");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg) &&
                  msg.target_type == ZNAM_TYPE_LTC;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam_build_register: accepts ZNAM_TYPE_DOGE... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "carol", ZNAM_TYPE_DOGE,
                                         "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg) &&
                  msg.target_type == ZNAM_TYPE_DOGE;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam_build_register: accepts ZNAM_TYPE_CONTENT... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "dave", ZNAM_TYPE_CONTENT,
                                         "a1b2c3d4e5f6");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg) &&
                  msg.target_type == ZNAM_TYPE_CONTENT;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam_build_update: accepts ZNAM_TYPE_BTC... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_update(buf, sizeof(buf),
                                       "alice", ZNAM_TYPE_BTC,
                                       "1NewAddress");
        struct znam_message msg;
        bool ok = len > 0 && znam_parse(buf, len, &msg) &&
                  msg.command == ZNAM_CMD_UPDATE &&
                  msg.target_type == ZNAM_TYPE_BTC;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam_build_register: rejects type > ZNAM_TYPE_CONTENT... ");
    {
        uint8_t buf[256];
        /* 8 is above ZNAM_TYPE_CONTENT (7) — still out of spec. */
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "eve", 8, "value");
        if (len == 0) printf("OK\n");
        else { printf("FAIL (accepted type=8)\n"); failures++; }
    }

    printf("znam_build_update: rejects type > ZNAM_TYPE_CONTENT... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_update(buf, sizeof(buf),
                                       "eve", 255, "value");
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_build_register: reject null value... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_register(buf, sizeof(buf),
                                         "valid", ZNAM_TYPE_TADDR, NULL);
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("znam_build_set_text: reject empty key... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_set_text(buf, sizeof(buf),
                                         "valid", "", "val");
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Standard-relay cap (MAX_OP_RETURN_RELAY) ──────────────────
     *
     * A builder that emits more than 223 bytes has produced a NON-STANDARD
     * OP_RETURN that will not relay, i.e. a transaction that can never
     * confirm. SET_TEXT is the reachable case: 63-char name + 32-char key +
     * 128-char value encodes to 237 bytes. It must return 0, not a script. */

    printf("znam_build_set_text: max-length record refused (over 223 cap)... ");
    {
        char name[ZNAM_NAME_MAX + 1];
        char key[ZNAM_TEXT_KEY_MAX + 1];
        char val[ZNAM_TEXT_VAL_MAX + 1];
        memset(name, 'a', ZNAM_NAME_MAX); name[ZNAM_NAME_MAX] = '\0';
        memset(key, 'k', ZNAM_TEXT_KEY_MAX); key[ZNAM_TEXT_KEY_MAX] = '\0';
        memset(val, 'v', ZNAM_TEXT_VAL_MAX); val[ZNAM_TEXT_VAL_MAX] = '\0';

        uint8_t buf[512];
        size_t len = znam_build_set_text(buf, sizeof(buf), name, key, val);
        if (len == 0) printf("OK\n");
        else { printf("FAIL (emitted %zu bytes)\n", len); failures++; }
    }

    printf("znam_build_set_text: shortened record still builds at/under cap... ");
    {
        char name[ZNAM_NAME_MAX + 1];
        char key[ZNAM_TEXT_KEY_MAX + 1];
        char val[ZNAM_TEXT_VAL_MAX + 1];
        memset(name, 'a', 32); name[32] = '\0';
        memset(key, 'k', 16); key[16] = '\0';
        memset(val, 'v', 100); val[100] = '\0';

        uint8_t buf[512];
        struct znam_message msg;
        size_t len = znam_build_set_text(buf, sizeof(buf), name, key, val);
        if (len > 0 && len <= MAX_OP_RETURN_RELAY &&
            znam_parse(buf, len, &msg) && msg.command == ZNAM_CMD_SET_TEXT)
            printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("znam builders: every emitted script fits the 223-byte cap... ");
    {
        char name[ZNAM_NAME_MAX + 1];
        char val[ZNAM_VALUE_MAX + 1];
        char owner[64];
        memset(name, 'a', ZNAM_NAME_MAX); name[ZNAM_NAME_MAX] = '\0';
        memset(val, 'v', ZNAM_VALUE_MAX); val[ZNAM_VALUE_MAX] = '\0';
        memset(owner, 'o', 63); owner[63] = '\0';

        uint8_t buf[512];
        size_t lens[4];
        lens[0] = znam_build_register(buf, sizeof(buf), name,
                                      ZNAM_TYPE_TADDR, val);
        lens[1] = znam_build_update(buf, sizeof(buf), name,
                                    ZNAM_TYPE_TADDR, val);
        lens[2] = znam_build_transfer(buf, sizeof(buf), name, owner);
        lens[3] = znam_build_renew(buf, sizeof(buf), name);

        bool all_ok = true;
        for (int i = 0; i < 4; i++)
            if (lens[i] == 0 || lens[i] > MAX_OP_RETURN_RELAY) all_ok = false;
        if (all_ok) printf("OK\n");
        else {
            printf("FAIL (%zu %zu %zu %zu)\n",
                   lens[0], lens[1], lens[2], lens[3]);
            failures++;
        }
    }

    printf("znam_build_transfer: reject null new_owner... ");
    {
        uint8_t buf[256];
        size_t len = znam_build_transfer(buf, sizeof(buf),
                                         "valid", NULL);
        if (len == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── SET_RECORD with all target types ─────────────────────── */

    printf("znam SET_RECORD all target types roundtrip... ");
    {
        bool all_ok = true;
        for (uint8_t t = 1; t <= ZNAM_TYPE_CONTENT; t++) {
            uint8_t buf[256];
            size_t len = znam_build_set_record(buf, sizeof(buf),
                                               "multi", t, "someaddr");
            struct znam_message msg;
            if (!znam_parse(buf, len, &msg) || msg.target_type != t) {
                all_ok = false;
                break;
            }
        }
        if (all_ok) printf("OK (types 1-%d)\n", ZNAM_TYPE_CONTENT);
        else { printf("FAIL\n"); failures++; }
    }

    /* ── SQLite persistence ───────────────────────────────────── */

    printf("znam DB save+find+list roundtrip... ");
    {
        sqlite3 *db = NULL;
        int rc = sqlite3_open(":memory:", &db);
        if (rc != SQLITE_OK) { printf("FAIL (open)\n"); failures++; }
        else {
            /* Create tables */
            sqlite3_exec(db,
                "CREATE TABLE znam_names("
                "name TEXT PRIMARY KEY, owner_address TEXT,"
                "target_type INTEGER, target_value TEXT,"
                "reg_txid BLOB, reg_height INTEGER,"
                "last_update_txid BLOB,"
                "expiry_height INTEGER NOT NULL DEFAULT 0)",
                NULL, NULL, NULL);
            sqlite3_exec(db,
                "CREATE TABLE znam_text_records("
                "name TEXT, key TEXT, value TEXT,"
                "PRIMARY KEY(name,key))", NULL, NULL, NULL);
            sqlite3_exec(db,
                "CREATE TABLE znam_addr_records("
                "name TEXT, coin_type INTEGER, address TEXT,"
                "PRIMARY KEY(name,coin_type))", NULL, NULL, NULL);

            struct node_db ndb = { .db = db, .open = true };

            struct znam_entry entry = {0};
            snprintf(entry.name, sizeof(entry.name), "alice");
            snprintf(entry.owner_address, sizeof(entry.owner_address), "t1owner");
            entry.target_type = ZNAM_TYPE_TADDR;
            snprintf(entry.target_value, sizeof(entry.target_value), "t1target");
            memset(entry.reg_txid, 0xAA, 32);
            entry.reg_height = 12345;
            memset(entry.last_update_txid, 0xBB, 32);
            entry.expiry_height = 12345 + ZNAM_REGISTRATION_TERM_BLOCKS;

            bool save_ok = db_znam_save(&ndb, &entry);
            struct znam_entry found = {0};
            bool find_ok = db_znam_find(&ndb, "alice", &found);

            struct znam_entry list[10];
            int count = db_znam_list(&ndb, list, 10);

            if (save_ok && find_ok &&
                strcmp(found.name, "alice") == 0 &&
                strcmp(found.owner_address, "t1owner") == 0 &&
                found.target_type == ZNAM_TYPE_TADDR &&
                strcmp(found.target_value, "t1target") == 0 &&
                found.reg_height == 12345 &&
                found.expiry_height == 12345 + ZNAM_REGISTRATION_TERM_BLOCKS &&
                count == 1) {
                printf("OK\n");
            } else {
                printf("FAIL (save=%d find=%d count=%d)\n",
                       save_ok, find_ok, count);
                failures++;
            }

            /* Text records */
            printf("znam DB text records save+get+list... ");
            bool t_save = db_znam_text_save(&ndb, "alice", "email", "a@b.com");
            bool t_save2 = db_znam_text_save(&ndb, "alice", "url", "https://x.com");
            char val[256] = {0};
            bool t_get = db_znam_text_get(&ndb, "alice", "email", val, sizeof(val));
            struct znam_text_record texts[10];
            int t_count = db_znam_text_list(&ndb, "alice", texts, 10);
            /* The uncapped total behind the window — equal here because
             * nothing was truncated, and zero for a name that has none. */
            int t_total = db_znam_text_count(&ndb, "alice");
            int t_total_missing =
                db_znam_text_count(&ndb, "nobody-here");

            if (t_save && t_save2 && t_get &&
                strcmp(val, "a@b.com") == 0 && t_count == 2 &&
                t_total == 2 && t_total_missing == 0) {
                printf("OK\n");
            } else {
                printf("FAIL (save=%d get=%d val=%s count=%d total=%d"
                       " missing=%d)\n",
                       t_save && t_save2, t_get, val, t_count, t_total,
                       t_total_missing);
                failures++;
            }

            /* Address records */
            printf("znam DB addr records save+get+list... ");
            bool a_save = db_znam_addr_save(&ndb, "alice", ZNAM_TYPE_BTC, "1abc");
            bool a_save2 = db_znam_addr_save(&ndb, "alice", ZNAM_TYPE_LTC, "Labc");
            char addr[256] = {0};
            bool a_get = db_znam_addr_get(&ndb, "alice", ZNAM_TYPE_BTC, addr, sizeof(addr));
            struct znam_addr_record addrs[10];
            int a_count = db_znam_addr_list(&ndb, "alice", addrs, 10);
            int a_total = db_znam_addr_count(&ndb, "alice");
            if (a_save && a_save2 && a_get && strcmp(addr, "1abc") == 0 &&
                a_count == 2 && a_total == 2 &&
                addrs[0].coin_type == ZNAM_TYPE_BTC &&
                addrs[1].coin_type == ZNAM_TYPE_LTC &&
                strcmp(addrs[1].address, "Labc") == 0) {
                printf("OK\n");
            } else {
                printf("FAIL (save=%d get=%d count=%d total=%d)\n",
                       a_save && a_save2, a_get, a_count, a_total);
                failures++;
            }

            /* A non-row count step is a store failure, never an empty
             * record set. Inject SQLITE_INTERRUPT at the exact seam shared
             * by both helpers, then restore the production reader. */
            printf("znam DB record counts fail closed on interrupt... ");
            db_znam_test_set_count_step(znam_count_step_interrupted);
            int t_interrupted = db_znam_text_count(&ndb, "alice");
            int a_interrupted = db_znam_addr_count(&ndb, "alice");
            db_znam_test_set_count_step(NULL);
            if (t_interrupted == -1 && a_interrupted == -1) {
                printf("OK\n");
            } else {
                printf("FAIL (text=%d addr=%d)\n",
                       t_interrupted, a_interrupted);
                failures++;
            }

            /* List by owner */
            printf("znam DB list_by_owner... ");
            struct znam_entry by_owner[10];
            int owner_count = db_znam_list_by_owner(&ndb, "t1owner", by_owner, 10);
            if (owner_count == 1 && strcmp(by_owner[0].name, "alice") == 0) {
                printf("OK\n");
            } else {
                printf("FAIL (count=%d)\n", owner_count); failures++;
            }

            /* Find non-existent */
            printf("znam DB find non-existent... ");
            struct znam_entry none;
            bool found_none = db_znam_find(&ndb, "nonexistent", &none);
            if (!found_none) printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            /* Null DB guard */
            printf("znam DB null guard... ");
            if (!db_znam_save(NULL, &entry) &&
                !db_znam_find(NULL, "x", &none)) {
                printf("OK\n");
            } else { printf("FAIL\n"); failures++; }

            sqlite3_close(db);
        }
    }

    /* ── RPC write surface: name_update / name_transfer / name_renew /
     * name_set_record / name_set_text ─────────────────────────────
     *
     * No wallet is wired for this section (rpc_name_set_wallet is never
     * called), so every command takes the same "no wallet loaded" hex
     * fallback branch rpc_name_register already has — this exercises
     * arg validation, existence checks, and the OP_RETURN builders'
     * size limits without needing a funded wallet. */

    printf("\n=== ZNAM RPC write surface (no wallet) ===\n");
    {
        sqlite3 *db = NULL;
        struct node_db ndb = {0};
        bool opened = open_test_names_db(&db, &ndb);
        if (!opened) {
            printf("znam RPC fixture: FAIL (could not open in-memory db)\n");
            failures++;
        } else {
            rpc_name_set_state(&ndb);

            struct znam_entry alice = {0};
            snprintf(alice.name, sizeof(alice.name), "alice");
            snprintf(alice.owner_address, sizeof(alice.owner_address), "t1owner");
            alice.target_type = ZNAM_TYPE_TADDR;
            snprintf(alice.target_value, sizeof(alice.target_value), "t1original");
            memset(alice.reg_txid, 0xCC, 32);
            alice.reg_height = 500;
            alice.expiry_height = 500 + ZNAM_REGISTRATION_TERM_BLOCKS;
            db_znam_save(&ndb, &alice);

            struct rpc_table t;
            rpc_table_init(&t);
            register_name_rpc_commands(&t);

            char oversize_value[ZNAM_VALUE_MAX + 32];
            memset(oversize_value, 'x', sizeof(oversize_value) - 1);
            oversize_value[sizeof(oversize_value) - 1] = '\0';
            char oversize_owner[ZNAM_NAME_MAX + 32];
            memset(oversize_owner, 'y', sizeof(oversize_owner) - 1);
            oversize_owner[sizeof(oversize_owner) - 1] = '\0';
            char oversize_key[ZNAM_TEXT_KEY_MAX + 8];
            memset(oversize_key, 'k', sizeof(oversize_key) - 1);
            oversize_key[sizeof(oversize_key) - 1] = '\0';

            /* name_update */
            {
                struct json_value r = {0};
                /* Fewer than 3 args hits the same "< 3" branch as an
                 * explicit help request (matches rpc_name_register's own
                 * shape) — usage text back, not a hard rejection. */
                printf("name_update: too few args returns usage text... ");
                bool ok = call_name_rpc(&t, "name_update", "alice", "taddr", false, NULL, &r);
                if (ok && strstr(json_get_str(&r), "name_update") != NULL) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_update: unknown name rejected... ");
                bool ok = call_name_rpc(&t, "name_update", "nosuchname", "taddr", true, "t1x", &r);
                if (!ok && strcmp(json_get_str(&r), "Name not found") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_update: oversize value rejected... ");
                bool ok = call_name_rpc(&t, "name_update", "alice", "taddr", true, oversize_value, &r);
                if (!ok && strcmp(json_get_str(&r), "Value too long (max 128 chars)") == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_update: valid update (no wallet) returns ready hex... ");
                bool ok = call_name_rpc(&t, "name_update", "alice", "btc", true, "1NewBtcAddr", &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "name")), "alice") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0 &&
                    json_get(&r, "op_return_hex") != NULL;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }

            /* name_transfer */
            {
                struct json_value r = {0};
                printf("name_transfer: too few args returns usage text... ");
                bool ok = call_name_rpc(&t, "name_transfer", "alice", NULL, false, NULL, &r);
                if (ok && strstr(json_get_str(&r), "name_transfer") != NULL) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_transfer: oversize new_owner rejected... ");
                bool ok = call_name_rpc(&t, "name_transfer", "alice", oversize_owner, false, NULL, &r);
                if (!ok && strcmp(json_get_str(&r), "Invalid new_owner (1-63 chars)") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_transfer: unknown name rejected... ");
                bool ok = call_name_rpc(&t, "name_transfer", "nosuchname", "t1newowner", false, NULL, &r);
                if (!ok && strcmp(json_get_str(&r), "Name not found") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_transfer: valid transfer (no wallet) returns ready hex... ");
                bool ok = call_name_rpc(&t, "name_transfer", "alice", "t1newowner", false, NULL, &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "new_owner")), "t1newowner") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }

            /* name_renew */
            {
                struct json_value r = {0};
                printf("name_renew: unknown name rejected... ");
                bool ok = call_name_rpc(&t, "name_renew", "nosuchname", NULL, false, NULL, &r);
                if (!ok && strcmp(json_get_str(&r), "Name not found") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_renew: invalid name rejected... ");
                bool ok = call_name_rpc(&t, "name_renew", "INVALID", NULL, false, NULL, &r);
                if (!ok) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_renew: valid renew (no wallet) returns ready hex... ");
                bool ok = call_name_rpc(&t, "name_renew", "alice", NULL, false, NULL, &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "name")), "alice") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }

            /* name_set_record */
            {
                struct json_value r = {0};
                printf("name_set_record: unknown name rejected... ");
                bool ok = call_name_rpc(&t, "name_set_record", "nosuchname", "btc", true, "1abc", &r);
                if (!ok && strcmp(json_get_str(&r), "Name not found") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_record: invalid type rejected... ");
                bool ok = call_name_rpc(&t, "name_set_record", "alice", "notacoin", true, "1abc", &r);
                if (!ok) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_record: oversize value rejected... ");
                bool ok = call_name_rpc(&t, "name_set_record", "alice", "btc", true, oversize_value, &r);
                if (!ok && strcmp(json_get_str(&r), "Value too long (max 128 chars)") == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_record: valid record (no wallet) returns ready hex... ");
                bool ok = call_name_rpc(&t, "name_set_record", "alice", "btc",
                                       true, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "type")), "bitcoin") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }

            /* name_set_text */
            {
                struct json_value r = {0};
                printf("name_set_text: too few args returns usage text... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", NULL, false, NULL, &r);
                if (ok && strstr(json_get_str(&r), "name_set_text") != NULL) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: unknown name rejected... ");
                bool ok = call_name_rpc(&t, "name_set_text", "nosuchname", "email", true, "a@b.com", &r);
                if (!ok && strcmp(json_get_str(&r), "Name not found") == 0) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: oversize key rejected... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", oversize_key, true, "v", &r);
                if (!ok) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: oversize value rejected... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", "bio", true, oversize_value, &r);
                if (!ok) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: valid with omitted value clears the key... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", "avatar", false, NULL, &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "key")), "avatar") == 0 &&
                    strcmp(json_get_str(json_get(&r, "value")), "") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: valid with value (no wallet) returns ready hex... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", "email", true, "a@b.com", &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "value")), "a@b.com") == 0 &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&r);
            }

            rpc_name_set_state(NULL);
            sqlite3_close(db);
        }
    }

    /* ── Owner-authorization gate ────────────────────────────────────
     *
     * Exercises zslp_command_build_owner_base_tx directly (the new
     * coin-selection helper the 4 owner-restricted RPCs above use) and
     * the RPC-level "non-owner rejected" path, without needing a full
     * mempool/coins_tip/main_state chain fixture — the ownership check
     * fails (or the coin-selection loop finds nothing) strictly before
     * that plumbing is ever touched. Section 7 of test_simnet.c already
     * proves the consensus-side projection independently re-derives and
     * enforces ownership from the confirmed tx; this section proves the
     * RPC/wallet-layer fail-fast gate in front of it. */

    printf("\n=== ZNAM owner-authorization gate ===\n");

    printf("build_owner_base_tx: rejects an address that isn't P2PKH... ");
    {
        static struct wallet w;
        wallet_init(&w);
        struct wallet_tx wtx = {0};
        int64_t fee = 0;
        const char *err = NULL;
        struct zcl_result r = zslp_command_build_owner_base_tx(
            &w, "not-a-valid-address", &wtx, &fee, &err);
        if (!r.ok && err && strstr(err, "not a spendable P2PKH") != NULL)
            printf("OK\n");
        else { printf("FAIL (ok=%d err=%s)\n", r.ok, err ? err : "(null)"); failures++; }
    }

    printf("build_owner_base_tx: rejects a wallet that lacks the owner's key... ");
    {
        static struct wallet owner_w, other_w;
        init_hd_wallet(&owner_w, 0x11);
        init_hd_wallet(&other_w, 0x22);
        char owner_addr[128] = {0};
        bool got_addr = wallet_get_new_address(&owner_w, owner_addr, sizeof(owner_addr));
        struct wallet_tx wtx = {0};
        int64_t fee = 0;
        const char *err = NULL;
        struct zcl_result r = { .ok = false };
        if (got_addr)
            r = zslp_command_build_owner_base_tx(&other_w, owner_addr, &wtx, &fee, &err);
        if (got_addr && !r.ok && err && strstr(err, "does not control") != NULL)
            printf("OK\n");
        else {
            printf("FAIL (got_addr=%d ok=%d err=%s)\n", got_addr, r.ok, err ? err : "(null)");
            failures++;
        }
    }

    printf("build_owner_base_tx: rejects owner key held but no funded coin... ");
    {
        static struct wallet w;
        init_hd_wallet(&w, 0x33);
        char addr[128] = {0};
        bool got_addr = wallet_get_new_address(&w, addr, sizeof(addr));
        struct wallet_tx wtx = {0};
        int64_t fee = 0;
        const char *err = NULL;
        struct zcl_result r = { .ok = false };
        if (got_addr)
            r = zslp_command_build_owner_base_tx(&w, addr, &wtx, &fee, &err);
        if (got_addr && !r.ok && err && strstr(err, "no spendable coin") != NULL)
            printf("OK\n");
        else {
            printf("FAIL (got_addr=%d ok=%d err=%s)\n", got_addr, r.ok, err ? err : "(null)");
            failures++;
        }
    }

    printf("build_owner_base_tx: prepares exact signed OP_RETURN bytes without broadcast... ");
    {
        static struct wallet w;
        init_hd_wallet(&w, 0x44);
        char addr[128] = {0};
        struct key_id kid;
        bool got_addr = wallet_get_new_address_with_key_id(&w, addr, sizeof(addr), &kid);
        bool funded = got_addr && fund_wallet_key(&w, &kid, 20000);
        struct wallet_tx wtx = {0};
        int64_t fee = 0;
        const char *err = NULL;
        struct zcl_result r = { .ok = false };
        if (funded)
            r = zslp_command_build_owner_base_tx(&w, addr, &wtx, &fee, &err);
        bool base_ok = funded && r.ok && wtx.tx.num_vin == 1 &&
            wtx.tx.num_vout == 2 &&
            wtx.tx.vout[0].value == 546 &&
            wtx.tx.vout[1].value == (20000 - 546 - fee) &&
            fee == w.default_fee;
        uint8_t script[512];
        size_t script_len = base_ok
            ? znam_build_renew(script, sizeof(script), "alice") : 0;
        struct zcl_result prepared = { .ok = false };
        if (script_len > 0)
            prepared = zslp_command_prepare_with_op_return(
                &w, &wtx, script, script_len);
        bool pass = base_ok && prepared.ok && wtx.tx.num_vout == 3 &&
            wtx.tx.vout[0].value == 0 &&
            wtx.tx.vout[0].script_pub_key.size == script_len &&
            memcmp(wtx.tx.vout[0].script_pub_key.data, script, script_len) == 0 &&
            wtx.tx.vout[1].value == 546 &&
            wtx.tx.vout[2].value == (20000 - 546 - fee) &&
            wtx.tx.vin[0].script_sig.size > 0 &&
            !uint256_is_null(&wtx.tx.hash) &&
            wallet_get_tx(&w, &wtx.tx.hash) == NULL;
        if (pass) printf("OK\n");
        else {
            printf("FAIL (got_addr=%d funded=%d base=%d prepared=%d vin=%zu vout=%zu fee=%" PRId64 ")\n",
                   got_addr, funded, base_ok, prepared.ok,
                   wtx.tx.num_vin, wtx.tx.num_vout, fee);
            failures++;
        }
        if (r.ok) transaction_free(&wtx.tx);
    }

    /* RPC-level: a wallet that does not hold the current owner's key is
     * refused a clean error for every owner-restricted command, instead
     * of silently broadcasting a tx the projection will just ignore. */
    printf("\n=== ZNAM RPC write surface: non-owner rejected ===\n");
    {
        sqlite3 *db = NULL;
        struct node_db ndb = {0};
        bool opened = open_test_names_db(&db, &ndb);
        static struct wallet owner_w, attacker_w;
        static struct tx_mempool dummy_mp;
        static struct main_state dummy_ms;
        static struct coins_view_cache dummy_cv;
        memset(&dummy_mp, 0, sizeof(dummy_mp));
        memset(&dummy_ms, 0, sizeof(dummy_ms));
        memset(&dummy_cv, 0, sizeof(dummy_cv));
        init_hd_wallet(&owner_w, 0x55);
        init_hd_wallet(&attacker_w, 0x66);

        char owner_addr[128] = {0};
        bool got_addr = opened && wallet_get_new_address(&owner_w, owner_addr, sizeof(owner_addr));

        if (!got_addr) {
            printf("znam non-owner RPC fixture: FAIL (setup)\n");
            failures++;
        } else {
            struct znam_entry alice = {0};
            snprintf(alice.name, sizeof(alice.name), "alice");
            snprintf(alice.owner_address, sizeof(alice.owner_address), "%s", owner_addr);
            alice.target_type = ZNAM_TYPE_TADDR;
            snprintf(alice.target_value, sizeof(alice.target_value), "t1original");
            memset(alice.reg_txid, 0xDD, 32);
            alice.reg_height = 700;
            alice.expiry_height = 700 + ZNAM_REGISTRATION_TERM_BLOCKS;
            db_znam_save(&ndb, &alice);

            rpc_name_set_state(&ndb);
            /* attacker_w does NOT hold owner_w's key — the only wallet the
             * controller has to sign with. mempool/main_state/coins_tip are
             * unused placeholders: build_owner_base_tx fails (and the RPC
             * returns) before commit_with_op_return ever touches them. */
            rpc_name_set_wallet(&attacker_w, &dummy_mp, &dummy_ms, &dummy_cv);

            struct rpc_table t;
            rpc_table_init(&t);
            register_name_rpc_commands(&t);
            const char *want = "wallet does not control the name owner's private key";

            {
                struct json_value r = {0};
                printf("name_update: non-owner rejected... ");
                bool ok = call_name_rpc(&t, "name_update", "alice", "btc", true, "1x", &r);
                if (!ok && strcmp(json_get_str(&r), want) == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_transfer: non-owner rejected... ");
                bool ok = call_name_rpc(&t, "name_transfer", "alice", "t1attacker", false, NULL, &r);
                if (!ok && strcmp(json_get_str(&r), want) == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_record: non-owner rejected... ");
                bool ok = call_name_rpc(&t, "name_set_record", "alice", "btc", true, "1x", &r);
                if (!ok && strcmp(json_get_str(&r), want) == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }
            {
                struct json_value r = {0};
                printf("name_set_text: non-owner rejected... ");
                bool ok = call_name_rpc(&t, "name_set_text", "alice", "email", true, "a@b.com", &r);
                if (!ok && strcmp(json_get_str(&r), want) == 0) printf("OK\n");
                else { printf("FAIL (ok=%d msg=%s)\n", ok, json_get_str(&r)); failures++; }
                json_free(&r);
            }

            /* Reset the module-global wallet/state BEFORE any other test
             * in this process runs — g_name_wallet etc. are statics in
             * name_controller.c that every other name_* RPC test (in
             * test_api.c) relies on being NULL ("no wallet" branch). */
            rpc_name_set_wallet(NULL, NULL, NULL, NULL);
            rpc_name_set_state(NULL);
        }
        if (opened) sqlite3_close(db);
    }

    failures += test_znam_wallet_sweep();

    printf("\n%d ZNAM test(s) failed\n", failures);
    return failures;
}
