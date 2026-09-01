/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the `core identity` native leaves
 * (tools/command/native_identity_command.c) and for the chain-rooted
 * `--anchored` mode of `zcode release verify`
 * (tools/command/native_zcode_release_command.c).
 *
 * Every case builds a REAL on-disk fixture datadir with a real node.db,
 * seeds the zid_identities projection through the model's own write API,
 * and calls the handler function directly — the
 * test_offline_datadir_query.c harness shape, because the handlers under
 * test open real files at a caller-supplied path.
 *
 * NO NODE, NO BROADCAST. node_rpc_call is stubbed with sanitized durable
 * plan/commit receipts. The isolated lifecycle fixture builds the same ZID
 * codec bytes used by the intent controller and wraps them in RAM-only
 * transactions; nothing broadcasts or touches the network.
 *
 * The un-fakeable cases are (6) and the exact chain lifecycle: each native
 * write proves explicit custody plus two-phase intent handling, while exact
 * ANCHOR / ROTATE / REVOKE codec bytes are owner-funded, admitted through
 * connect_block(), and folded through the production explorer indexer.
 *
 * Case (9) is the point of the whole surface — it pins that "the
 * signature is valid" and "the key is anchored on-chain" are two
 * SEPARATE reported facts that never collapse into one: a tampered doc
 * signed under an anchored key still fails BAD_SIGNATURE, and a valid
 * doc under an unanchored key still fails KEY_NOT_ANCHORED. */

#include "test/test_core.h"
#include "test/transaction_lab_simnet.h"

#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/zid_identity.h"
#include "zid/zid.h"
#include "zid/zid_anchor.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define IDC_CHECK(name, expr) do {                                    \
    printf("identity_command: %s... ", (name));                       \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

/* ── fixture ──────────────────────────────────────────────────────── */

static int g_idc_plan_calls;
static int g_idc_commit_calls;

/* No live node for the whole file: the RPC seam returns public-safe intent
 * receipts and deliberately never includes keys, owners, addresses, or raw
 * transaction bytes. */
static char *idc_rpc_hook(const char *method, const char *params_json)
{
    if (!method || strcmp(method, "zid_intent") != 0)
        return NULL;
    bool commit = params_json && strstr(params_json, "\"confirm\":true");
    if (commit) {
        g_idc_commit_calls++;
        return strdup(
            "{\"schema\":\"zcl.core_identity_anchor.v2\","
            "\"wallet_scope\":\"dev\",\"operation\":\"anchor\","
            "\"plan_id\":\"11111111111111111111111111111111"
            "11111111111111111111111111111111\","
            "\"snapshot_status\":\"CURRENT\",\"status\":\"broadcast\","
            "\"state\":\"mempool_accepted\",\"actual_fee_zat\":500,"
            "\"txid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    }
    g_idc_plan_calls++;
    return strdup(
        "{\"schema\":\"zcl.core_identity_anchor.v2\","
        "\"wallet_scope\":\"dev\",\"operation\":\"anchor\","
        "\"plan_id\":\"11111111111111111111111111111111"
        "11111111111111111111111111111111\","
        "\"plan_digest\":\"22222222222222222222222222222222"
        "22222222222222222222222222222222\","
        "\"snapshot_root\":\"33333333333333333333333333333333"
        "33333333333333333333333333333333\","
        "\"snapshot_status\":\"CURRENT\",\"status\":\"planned\","
        "\"state\":\"planned\",\"actual_fee_zat\":500,"
        "\"maximum_fee_zat\":1000,\"reserved_zat\":1000,"
        "\"pubkey\":\"fixture-secret\",\"owner_address\":\"fixture-owner\","
        "\"raw_tx\":\"fixture-raw\"}");
}

static void idc_mk_key(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
}

static void idc_hex32(const uint8_t b[32], char out[65])
{
    HexStr(b, 32, false, out, 65);
}

/* Build <dir>/node.db (schema comes from node_db_open) and stash one row
 * per caller request. Returns false on any failure. */
static bool idc_save_row(const char *dir, const struct zid_identity *row)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open(&ndb, path))
        return false;
    bool ok = db_zid_identity_save(&ndb, row);
    node_db_close(&ndb);
    return ok;
}

/* Create the fixture datadir and its node.db. */
static bool idc_mk_datadir(char *dir, size_t dir_size, const char *tag)
{
    test_fmt_tmpdir(dir, dir_size, "identity_command", tag);
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open(&ndb, path))
        return false;
    node_db_close(&ndb);
    return true;
}

static void idc_fill(struct zid_identity *r, const uint8_t key[32],
                     int32_t height, const char *status, const char *source,
                     const char *name, const char *owner)
{
    memset(r, 0, sizeof(*r));
    memcpy(r->master_pubkey, key, 32);
    memset(r->anchor_txid, 0x5a, 32);
    r->anchor_height = height;
    r->updated_height = height;
    snprintf(r->status, sizeof(r->status), "%s", status);
    snprintf(r->source, sizeof(r->source), "%s", source);
    if (name) snprintf(r->name, sizeof(r->name), "%s", name);
    if (owner) snprintf(r->owner_address, sizeof(r->owner_address), "%s",
                        owner);
}

/* Run one handler against {datadir, ...} and hand the reply back. The
 * caller owns `reply` (zcl_command_reply_free) and `input` (json_free). */
static void idc_call(void (*fn)(const struct zcl_command_request *,
                                struct zcl_command_reply *),
                     struct json_value *input,
                     struct zcl_command_reply *reply, const char *schema)
{
    static const struct zcl_command_spec anchor_spec = {
        .path = "core.identity.anchor"
    };
    static const struct zcl_command_spec rotate_spec = {
        .path = "core.identity.rotate"
    };
    static const struct zcl_command_spec revoke_spec = {
        .path = "core.identity.revoke"
    };
    const struct zcl_command_spec *spec = NULL;
    if (fn == zcl_native_handle_core_identity_anchor) spec = &anchor_spec;
    if (fn == zcl_native_handle_core_identity_rotate) spec = &rotate_spec;
    if (fn == zcl_native_handle_core_identity_revoke) spec = &revoke_spec;
    struct zcl_command_request request = { .spec = spec, .input = input };
    zcl_command_reply_init(reply, schema);
    fn(&request, reply);
}

static void idc_input_open(struct json_value *input, const char *dir)
{
    json_init(input);
    json_set_object(input);
    if (dir)
        (void)json_push_kv_str(input, "datadir", dir);
}

static const char *idc_str(const struct zcl_command_reply *reply,
                           const char *key)
{
    const char *s = json_get_str(json_get(&reply->data, key));
    return s ? s : "";
}

/* ── (1)+(2)+(3)+(4) resolve ──────────────────────────────────────── */

static int t_resolve(void)
{
    int failures = 0;
    char dir[256];
    IDC_CHECK("resolve fixture: datadir",
              idc_mk_datadir(dir, sizeof(dir), "resolve"));

    uint8_t key_a[32], key_b[32], key_missing[32];
    idc_mk_key(key_a, 0x11);
    idc_mk_key(key_b, 0x40);
    idc_mk_key(key_missing, 0x90);
    char hex_a[65], hex_b[65], hex_missing[65];
    idc_hex32(key_a, hex_a);
    idc_hex32(key_b, hex_b);
    idc_hex32(key_missing, hex_missing);

    struct zid_identity row;
    /* key_a: rotated toward key_b, anchored via the ZNAM text convention. */
    idc_fill(&row, key_a, 1000, ZID_IDENTITY_STATUS_ROTATED,
             ZID_IDENTITY_SOURCE_ZNAM_TEXT, "alice", "t1owner");
    memcpy(row.successor_pubkey, key_b, 32);
    row.has_successor = true;
    row.updated_height = 1200;
    IDC_CHECK("resolve fixture: rotated row", idc_save_row(dir, &row));
    /* key_b: the live successor, anchored via the ZID overlay. */
    idc_fill(&row, key_b, 1200, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
    IDC_CHECK("resolve fixture: active row", idc_save_row(dir, &row));

    /* by pubkey */
    struct json_value input;
    struct zcl_command_reply reply;
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_a);
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve by pubkey: exit OK",
              reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("resolve by pubkey: pubkey echoed",
              strcmp(idc_str(&reply, "pubkey"), hex_a) == 0);
    IDC_CHECK("resolve by pubkey: name",
              strcmp(idc_str(&reply, "name"), "alice") == 0);
    IDC_CHECK("resolve by pubkey: status rotated",
              strcmp(idc_str(&reply, "status"), "rotated") == 0);
    IDC_CHECK("resolve by pubkey: successor is key_b",
              strcmp(idc_str(&reply, "successor"), hex_b) == 0);
    IDC_CHECK("resolve by pubkey: source znam_text",
              strcmp(idc_str(&reply, "source"), "znam_text") == 0);
    IDC_CHECK("resolve by pubkey: anchor_height",
              json_get_int(json_get(&reply.data, "anchor_height")) == 1000);
    IDC_CHECK("resolve by pubkey: updated_height",
              json_get_int(json_get(&reply.data, "updated_height")) == 1200);
    IDC_CHECK("resolve by pubkey: anchor_txid is 64 hex",
              strlen(idc_str(&reply, "anchor_txid")) == 64);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* by name */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "alice");
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve by name: exit OK",
              reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("resolve by name: same row as by pubkey",
              strcmp(idc_str(&reply, "pubkey"), hex_a) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* unknown key -> KEY_NOT_ANCHORED */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_missing);
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve unknown key: FAILED",
              reply.status == ZCL_COMMAND_STATUS_FAILED);
    IDC_CHECK("resolve unknown key: KEY_NOT_ANCHORED",
              strcmp(reply.error.code, "KEY_NOT_ANCHORED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* unknown name -> NAME_NOT_FOUND */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "name", "nobody");
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve unknown name: NAME_NOT_FOUND",
              strcmp(reply.error.code, "NAME_NOT_FOUND") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* no selector -> MISSING_SELECTOR */
    idc_input_open(&input, dir);
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve no selector: MISSING_SELECTOR",
              strcmp(reply.error.code, "MISSING_SELECTOR") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* both selectors -> AMBIGUOUS_SELECTOR */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_a);
    (void)json_push_kv_str(&input, "name", "alice");
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve both selectors: AMBIGUOUS_SELECTOR",
              strcmp(reply.error.code, "AMBIGUOUS_SELECTOR") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* malformed pubkey -> BAD_PUBKEY_HEX (short, non-hex, all-zero) */
    static const char *const bad[] = {
        "deadbeef",
        "zz11111111111111111111111111111111111111111111111111111111111111",
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        idc_input_open(&input, dir);
        (void)json_push_kv_str(&input, "pubkey", bad[i]);
        idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
                 "zcl.core_identity_resolve.v1");
        IDC_CHECK("resolve malformed pubkey: BAD_PUBKEY_HEX",
                  strcmp(reply.error.code, "BAD_PUBKEY_HEX") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* no datadir at all -> MISSING_DATADIR, never a crash */
    idc_input_open(&input, NULL);
    (void)json_push_kv_str(&input, "pubkey", hex_a);
    idc_call(zcl_native_handle_core_identity_resolve, &input, &reply,
             "zcl.core_identity_resolve.v1");
    IDC_CHECK("resolve no datadir: named error, no crash",
              reply.status == ZCL_COMMAND_STATUS_FAILED &&
              reply.error.code[0] != '\0');
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

/* ── (5) list paging ──────────────────────────────────────────────── */

static int t_list(void)
{
    int failures = 0;
    char dir[256];
    IDC_CHECK("list fixture: datadir",
              idc_mk_datadir(dir, sizeof(dir), "list"));

    bool seeded = true;
    for (int i = 0; i < 5; i++) {
        uint8_t k[32];
        idc_mk_key(k, (uint8_t)(0x20 + i));
        struct zid_identity row;
        idc_fill(&row, k, 100 + i, i == 4 ? ZID_IDENTITY_STATUS_REVOKED
                                          : ZID_IDENTITY_STATUS_ACTIVE,
                 ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
        seeded = seeded && idc_save_row(dir, &row);
    }
    IDC_CHECK("list fixture: five rows", seeded);

    struct json_value input;
    struct zcl_command_reply reply;
    idc_input_open(&input, dir);
    (void)json_push_kv_int(&input, "limit", 2);
    idc_call(zcl_native_handle_core_identity_list, &input, &reply,
             "zcl.core_identity_index.v1");
    IDC_CHECK("list: exit OK", reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("list: total is 5",
              json_get_int(json_get(&reply.data, "total")) == 5);
    IDC_CHECK("list: active is 4",
              json_get_int(json_get(&reply.data, "active")) == 4);
    IDC_CHECK("list: revoked is 1",
              json_get_int(json_get(&reply.data, "revoked")) == 1);
    IDC_CHECK("list: limit caps the page",
              json_get_int(json_get(&reply.data, "count")) == 2);
    const struct json_value *arr = json_get(&reply.data, "identities");
    IDC_CHECK("list: two identities returned",
              arr && arr->type == JSON_ARR && arr->num_children == 2);
    /* newest anchor first: heights 104 then 103 */
    IDC_CHECK("list: newest anchor first",
              arr && arr->num_children == 2 &&
              json_get_int(json_get(json_at(arr, 0), "anchor_height")) == 104 &&
              json_get_int(json_get(json_at(arr, 1), "anchor_height")) == 103);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* offset walks the page */
    idc_input_open(&input, dir);
    (void)json_push_kv_int(&input, "limit", 2);
    (void)json_push_kv_int(&input, "offset", 2);
    idc_call(zcl_native_handle_core_identity_list, &input, &reply,
             "zcl.core_identity_index.v1");
    arr = json_get(&reply.data, "identities");
    IDC_CHECK("list: offset walks to height 102",
              arr && arr->num_children == 2 &&
              json_get_int(json_get(json_at(arr, 0), "anchor_height")) == 102);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* an absurd limit is clamped, never honoured */
    idc_input_open(&input, dir);
    (void)json_push_kv_int(&input, "limit", 100000);
    idc_call(zcl_native_handle_core_identity_list, &input, &reply,
             "zcl.core_identity_index.v1");
    IDC_CHECK("list: limit clamped to the cap",
              json_get_int(json_get(&reply.data, "limit")) == 100);
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

/* ── (6)+(7) custody-bound native plan/commit ────────────────────── */

static void idc_add_plan_fields(struct json_value *input,
                                const char *idempotency_key)
{
    (void)json_push_kv_str(input, "wallet_scope", "dev");
    (void)json_push_kv_str(input, "idempotency_key", idempotency_key);
}

static int t_write_intents(void)
{
    int failures = 0;
    char dir[256];
    IDC_CHECK("write fixture: datadir",
              idc_mk_datadir(dir, sizeof(dir), "write"));

    uint8_t key_a[32], key_b[32];
    idc_mk_key(key_a, 0x11);
    idc_mk_key(key_b, 0x40);
    char hex_a[65], hex_b[65];
    idc_hex32(key_a, hex_a);
    idc_hex32(key_b, hex_b);

    struct zid_identity row;
    idc_fill(&row, key_a, 500, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
    IDC_CHECK("write fixture: active row", idc_save_row(dir, &row));

    struct json_value input;
    struct zcl_command_reply reply;
    g_idc_plan_calls = 0;
    g_idc_commit_calls = 0;

    /* Anchor: a scoped request creates a durable reservation, never raw
     * bytes or identity fields in the public receipt. */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_b);
    idc_add_plan_fields(&input, "identity-anchor-fixture");
    idc_call(zcl_native_handle_core_identity_anchor, &input, &reply,
             "zcl.core_identity_anchor.v2");
    IDC_CHECK("anchor plan: exit OK",
              reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("anchor plan: durable plan stage",
              strcmp(idc_str(&reply, "stage"), "plan") == 0 &&
              strlen(idc_str(&reply, "plan_id")) == 64 &&
              strstr(idc_str(&reply, "commit_input"), "confirm") != NULL);
    IDC_CHECK("anchor plan: public receipt excludes identity and raw bytes",
              json_get(&reply.data, "pubkey") == NULL &&
              json_get(&reply.data, "owner_address") == NULL &&
              json_get(&reply.data, "raw_tx") == NULL &&
              json_get(&reply.data, "op_return_hex") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Rotate and revoke traverse the same scoped plan surface after their
     * projection ownership/refusal preflights. */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_a);
    (void)json_push_kv_str(&input, "new_pubkey", hex_b);
    idc_add_plan_fields(&input, "identity-rotate-fixture");
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v2");
    IDC_CHECK("rotate plan: durable and sanitized",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(idc_str(&reply, "stage"), "plan") == 0 &&
              json_get(&reply.data, "pubkey") == NULL &&
              json_get(&reply.data, "owner_address") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_a);
    idc_add_plan_fields(&input, "identity-revoke-fixture");
    idc_call(zcl_native_handle_core_identity_revoke, &input, &reply,
             "zcl.core_identity_anchor.v2");
    IDC_CHECK("revoke plan: durable and sanitized",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(idc_str(&reply, "stage"), "plan") == 0 &&
              json_get(&reply.data, "pubkey") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "wallet_scope", "dev");
    (void)json_push_kv_str(&input, "plan_id",
        "1111111111111111111111111111111111111111111111111111111111111111");
    (void)json_push_kv_bool(&input, "confirm", true);
    idc_call(zcl_native_handle_core_identity_anchor, &input, &reply,
             "zcl.core_identity_anchor.v2");
    IDC_CHECK("commit omits operation fields and publishes once",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(idc_str(&reply, "stage"), "committed") == 0 &&
              g_idc_plan_calls == 3 && g_idc_commit_calls == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

/* ── exact public-command bytes through consensus + projection ───── */

static int t_exact_chain_lifecycle(void)
{
    int failures = 0;
    char dir[256];
    bool fixture_ok = idc_mk_datadir(dir, sizeof(dir), "chain");
    IDC_CHECK("chain fixture: datadir", fixture_ok);
    if (!fixture_ok)
        return failures;

    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool db_open = node_db_open(&ndb, dbpath) && ndb.open;
    IDC_CHECK("chain fixture: projection database", db_open);
    if (!db_open)
        return failures;

    uint8_t key_a[32], key_b[32], owner20[20];
    idc_mk_key(key_a, 0x61);
    idc_mk_key(key_b, 0x91);
    memset(owner20, 0x4d, sizeof(owner20));
    char hex_a[65], hex_b[65];
    idc_hex32(key_a, hex_a);
    idc_hex32(key_b, hex_b);

    struct zid_anchor_message message;
    uint8_t script[ZID_ANCHOR_SCRIPT_MAX];
    size_t script_len;
    struct transaction_lab_simnet_receipt anchor_mined;
    struct transaction_lab_simnet_receipt rotate_mined;
    struct transaction_lab_simnet_receipt revoke_mined;
    bool anchor_mined_ok = false;
    bool rotate_mined_ok = false;
    bool revoke_mined_ok = false;

    script_len = zid_anchor_build_anchor(script, sizeof(script), key_a);
    bool anchor_command_ok =
        script_len > 0 && zid_anchor_parse(script, script_len, &message) &&
        message.command == ZID_ANCHOR_CMD_ANCHOR &&
        memcmp(message.pubkey, key_a, sizeof(key_a)) == 0;
    IDC_CHECK("chain anchor: production codec emits exact ANCHOR bytes",
              anchor_command_ok);

    anchor_mined_ok = anchor_command_ok &&
        transaction_lab_simnet_mine_owned_op_return_at(
            script, script_len, owner20, 500, &anchor_mined);
    IDC_CHECK("chain anchor: exact command bytes pass connect_block",
              anchor_mined_ok && anchor_mined.mined_height == 500 &&
              anchor_mined.change_zat == 800000 &&
              anchor_mined.transaction.vout[0].script_pub_key.size ==
                  script_len &&
              memcmp(anchor_mined.transaction.vout[0].script_pub_key.data,
                     script, script_len) == 0);
    bool anchor_projected = anchor_mined_ok &&
        transaction_lab_simnet_project(&ndb, &anchor_mined);
    struct zid_identity anchored;
    memset(&anchored, 0, sizeof(anchored));
    bool anchor_found = anchor_projected &&
        db_zid_identity_find(&ndb, key_a, &anchored);
    IDC_CHECK("chain anchor: mined bytes project the active owner-bound key",
              anchor_found &&
              strcmp(anchored.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
              anchored.anchor_height == 500 && anchored.updated_height == 500 &&
              anchored.owner_address[0] != '\0' &&
              memcmp(anchored.anchor_txid, anchor_mined.txid.data, 32) == 0);
    char owner_address[64] = {0};
    if (anchor_found)
        snprintf(owner_address, sizeof(owner_address), "%s",
                 anchored.owner_address);

    script_len = zid_anchor_build_rotate(
        script, sizeof(script), key_a, key_b);
    bool rotate_command_ok = anchor_found &&
        script_len > 0 &&
        zid_anchor_parse(script, script_len, &message) &&
        message.command == ZID_ANCHOR_CMD_ROTATE && message.has_old_pubkey &&
        memcmp(message.old_pubkey, key_a, sizeof(key_a)) == 0 &&
        memcmp(message.pubkey, key_b, sizeof(key_b)) == 0;
    IDC_CHECK("chain rotate: production codec emits exact ROTATE bytes",
              rotate_command_ok);

    rotate_mined_ok = rotate_command_ok &&
        transaction_lab_simnet_mine_owned_op_return_at(
            script, script_len, owner20, 700, &rotate_mined);
    IDC_CHECK("chain rotate: exact command bytes pass connect_block",
              rotate_mined_ok && rotate_mined.mined_height == 700 &&
              rotate_mined.change_zat == 800000);
    bool rotate_projected = rotate_mined_ok &&
        transaction_lab_simnet_project(&ndb, &rotate_mined);
    struct zid_identity rotated, successor;
    memset(&rotated, 0, sizeof(rotated));
    memset(&successor, 0, sizeof(successor));
    bool rotate_found = rotate_projected &&
        db_zid_identity_find(&ndb, key_a, &rotated) &&
        db_zid_identity_find(&ndb, key_b, &successor);
    IDC_CHECK("chain rotate: projection preserves lineage and owner",
              rotate_found &&
              strcmp(rotated.status, ZID_IDENTITY_STATUS_ROTATED) == 0 &&
              rotated.has_successor &&
              memcmp(rotated.successor_pubkey, key_b, sizeof(key_b)) == 0 &&
              rotated.anchor_height == 500 && rotated.updated_height == 700 &&
              strcmp(successor.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
              successor.anchor_height == 700 &&
              strcmp(successor.owner_address, owner_address) == 0 &&
              memcmp(successor.anchor_txid, rotate_mined.txid.data, 32) == 0);

    script_len = zid_anchor_build_revoke(script, sizeof(script), key_b);
    bool revoke_command_ok = rotate_found &&
        script_len > 0 &&
        zid_anchor_parse(script, script_len, &message) &&
        message.command == ZID_ANCHOR_CMD_REVOKE &&
        memcmp(message.pubkey, key_b, sizeof(key_b)) == 0;
    IDC_CHECK("chain revoke: production codec emits exact REVOKE bytes",
              revoke_command_ok);

    revoke_mined_ok = revoke_command_ok &&
        transaction_lab_simnet_mine_owned_op_return_at(
            script, script_len, owner20, 900, &revoke_mined);
    IDC_CHECK("chain revoke: exact command bytes pass connect_block",
              revoke_mined_ok && revoke_mined.mined_height == 900 &&
              revoke_mined.change_zat == 800000);
    bool revoke_projected = revoke_mined_ok &&
        transaction_lab_simnet_project(&ndb, &revoke_mined);
    struct zid_identity revoked;
    memset(&revoked, 0, sizeof(revoked));
    bool revoke_found = revoke_projected &&
        db_zid_identity_find(&ndb, key_b, &revoked);
    IDC_CHECK("chain revoke: projection retires the successor in place",
              revoke_found &&
              strcmp(revoked.status, ZID_IDENTITY_STATUS_REVOKED) == 0 &&
              !revoked.has_successor && revoked.anchor_height == 700 &&
              revoked.updated_height == 900 &&
              strcmp(revoked.owner_address, owner_address) == 0 &&
              memcmp(revoked.anchor_txid, rotate_mined.txid.data, 32) == 0);

    if (anchor_mined_ok)
        transaction_lab_simnet_receipt_free(&anchor_mined);
    if (rotate_mined_ok)
        transaction_lab_simnet_receipt_free(&rotate_mined);
    if (revoke_mined_ok)
        transaction_lab_simnet_receipt_free(&revoke_mined);
    node_db_close(&ndb);
    return failures;
}

/* ── (8) the named refusals ───────────────────────────────────────── */

static int t_write_refusals(void)
{
    int failures = 0;
    char dir[256];
    IDC_CHECK("refusal fixture: datadir",
              idc_mk_datadir(dir, sizeof(dir), "refuse"));

    uint8_t key_live[32], key_dead[32], key_absent[32], key_orphan[32];
    idc_mk_key(key_live, 0x11);
    idc_mk_key(key_dead, 0x33);
    idc_mk_key(key_absent, 0x77);
    idc_mk_key(key_orphan, 0x99);
    char hex_live[65], hex_dead[65], hex_absent[65], hex_orphan[65];
    idc_hex32(key_live, hex_live);
    idc_hex32(key_dead, hex_dead);
    idc_hex32(key_absent, hex_absent);
    idc_hex32(key_orphan, hex_orphan);

    struct zid_identity row;
    idc_fill(&row, key_live, 500, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
    IDC_CHECK("refusal fixture: live row", idc_save_row(dir, &row));
    idc_fill(&row, key_dead, 501, ZID_IDENTITY_STATUS_REVOKED,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
    IDC_CHECK("refusal fixture: revoked row", idc_save_row(dir, &row));
    /* an anchor published from a non-P2PKH input records no owner */
    idc_fill(&row, key_orphan, 502, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, NULL);
    IDC_CHECK("refusal fixture: ownerless row", idc_save_row(dir, &row));

    struct json_value input;
    struct zcl_command_reply reply;

    /* rotate to itself */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_live);
    (void)json_push_kv_str(&input, "new_pubkey", hex_live);
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("rotate self: SELF_ROTATE",
              strcmp(reply.error.code, "SELF_ROTATE") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* rotate an absent key */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_absent);
    (void)json_push_kv_str(&input, "new_pubkey", hex_live);
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("rotate absent key: KEY_NOT_ANCHORED",
              strcmp(reply.error.code, "KEY_NOT_ANCHORED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* rotate a revoked key */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_dead);
    (void)json_push_kv_str(&input, "new_pubkey", hex_live);
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("rotate revoked key: ALREADY_REVOKED",
              strcmp(reply.error.code, "ALREADY_REVOKED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* rotate an ownerless row — nobody can ever prove ownership */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_orphan);
    (void)json_push_kv_str(&input, "new_pubkey", hex_absent);
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("rotate ownerless row: NOT_OWNER",
              strcmp(reply.error.code, "NOT_OWNER") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* revoke an absent key / a revoked key */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_absent);
    idc_call(zcl_native_handle_core_identity_revoke, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("revoke absent key: KEY_NOT_ANCHORED",
              strcmp(reply.error.code, "KEY_NOT_ANCHORED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_dead);
    idc_call(zcl_native_handle_core_identity_revoke, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("revoke revoked key: ALREADY_REVOKED",
              strcmp(reply.error.code, "ALREADY_REVOKED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* re-anchoring a dead key */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_dead);
    idc_call(zcl_native_handle_core_identity_anchor, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("anchor revoked key: ALREADY_REVOKED",
              strcmp(reply.error.code, "ALREADY_REVOKED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* every write with no pubkey at all names its own refusal */
    idc_input_open(&input, dir);
    idc_call(zcl_native_handle_core_identity_anchor, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("anchor no pubkey: MISSING_PUBKEY",
              strcmp(reply.error.code, "MISSING_PUBKEY") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "pubkey", hex_live);
    idc_call(zcl_native_handle_core_identity_rotate, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("rotate no new_pubkey: MISSING_NEW_PUBKEY",
              strcmp(reply.error.code, "MISSING_NEW_PUBKEY") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    idc_input_open(&input, dir);
    idc_call(zcl_native_handle_core_identity_revoke, &input, &reply,
             "zcl.core_identity_anchor.v1");
    IDC_CHECK("revoke no pubkey: MISSING_PUBKEY",
              strcmp(reply.error.code, "MISSING_PUBKEY") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

/* ── (9) zcode release verify --anchored ──────────────────────────── */

/* Sign a release doc under `seed` and hand back its canonical wire hex
 * plus the master pubkey the signature commits to. */
static bool idc_sign_release(const uint8_t seed[32], const char *name,
                             const char *version, char *hex_out,
                             size_t hex_size, uint8_t pubkey_out[32])
{
    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "%s", name);
    snprintf(rel.version, sizeof(rel.version), "%s", version);
    memset(rel.manifest_root, 0x7c, 32);

    struct zid_doc doc;
    memset(&doc, 0, sizeof(doc));
    /* An expiry far past any plausible test clock: the case under test is
     * anchor status, and an expired doc would fail for the wrong reason. */
    if (!zid_release_sign(&doc, &rel, 1, 4102444800ull, seed))
        return false;
    uint8_t wire[ZID_DOC_MAX];
    size_t n = zid_doc_encode(wire, sizeof(wire), &doc);
    if (n == 0 || n * 2 + 1 > hex_size)
        return false;
    HexStr(wire, n, false, hex_out, hex_size);
    memcpy(pubkey_out, doc.master_pubkey, 32);
    return true;
}

static int t_verify_anchored(void)
{
    int failures = 0;
    char dir[256];
    IDC_CHECK("anchored fixture: datadir",
              idc_mk_datadir(dir, sizeof(dir), "anchored"));

    uint8_t seed_live[32], seed_dead[32], seed_loose[32];
    idc_mk_key(seed_live, 0x01);
    idc_mk_key(seed_dead, 0x02);
    idc_mk_key(seed_loose, 0x03);

    char doc_live[ZID_DOC_MAX * 2 + 2];
    char doc_dead[ZID_DOC_MAX * 2 + 2];
    char doc_loose[ZID_DOC_MAX * 2 + 2];
    uint8_t pub_live[32], pub_dead[32], pub_loose[32];
    IDC_CHECK("anchored fixture: sign live doc",
              idc_sign_release(seed_live, "demo", "1.0", doc_live,
                               sizeof(doc_live), pub_live));
    IDC_CHECK("anchored fixture: sign revoked-key doc",
              idc_sign_release(seed_dead, "demo", "0.9", doc_dead,
                               sizeof(doc_dead), pub_dead));
    IDC_CHECK("anchored fixture: sign unanchored-key doc",
              idc_sign_release(seed_loose, "demo", "0.1", doc_loose,
                               sizeof(doc_loose), pub_loose));

    struct zid_identity row;
    idc_fill(&row, pub_live, 2222, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZNAM_TEXT, "demo-publisher", "t1owner");
    IDC_CHECK("anchored fixture: anchored publisher key",
              idc_save_row(dir, &row));
    idc_fill(&row, pub_dead, 1111, ZID_IDENTITY_STATUS_REVOKED,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL, "t1owner");
    IDC_CHECK("anchored fixture: revoked publisher key",
              idc_save_row(dir, &row));

    struct json_value input;
    struct zcl_command_reply reply;

    /* the honest happy path: valid signature AND an anchored, live key */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "doc", doc_live);
    (void)json_push_kv_bool(&input, "anchored", true);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify --anchored: exit OK",
              reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("verify --anchored: signature still reported valid",
              json_get_bool(json_get(&reply.data, "valid")));
    IDC_CHECK("verify --anchored: anchored true",
              json_get_bool(json_get(&reply.data, "anchored")));
    IDC_CHECK("verify --anchored: anchor_height",
              json_get_int(json_get(&reply.data, "anchor_height")) == 2222);
    IDC_CHECK("verify --anchored: anchor_name",
              strcmp(idc_str(&reply, "anchor_name"), "demo-publisher") == 0);
    IDC_CHECK("verify --anchored: anchor_status active",
              strcmp(idc_str(&reply, "anchor_status"), "active") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* without --anchored the handler is unchanged: no anchor fact at all */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "doc", doc_loose);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify without --anchored: still passes",
              reply.exit_code == ZCL_COMMAND_EXIT_OK);
    IDC_CHECK("verify without --anchored: reports no anchor fact",
              json_get(&reply.data, "anchored") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* a valid signature by a key nobody anchored is NOT trust */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "doc", doc_loose);
    (void)json_push_kv_bool(&input, "anchored", true);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify --anchored unanchored key: KEY_NOT_ANCHORED",
              strcmp(reply.error.code, "KEY_NOT_ANCHORED") == 0);
    IDC_CHECK("verify --anchored unanchored key: signature was still valid",
              json_get_bool(json_get(&reply.data, "valid")));
    IDC_CHECK("verify --anchored unanchored key: anchored false",
              !json_get_bool(json_get(&reply.data, "anchored")));
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* a valid signature by a revoked key is NOT trust either */
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "doc", doc_dead);
    (void)json_push_kv_bool(&input, "anchored", true);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify --anchored revoked key: KEY_REVOKED",
              strcmp(reply.error.code, "KEY_REVOKED") == 0);
    IDC_CHECK("verify --anchored revoked key: anchored is still true",
              json_get_bool(json_get(&reply.data, "anchored")));
    IDC_CHECK("verify --anchored revoked key: anchor_status revoked",
              strcmp(idc_str(&reply, "anchor_status"), "revoked") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* THE separation: an anchored key does not rescue a tampered doc */
    char tampered[ZID_DOC_MAX * 2 + 2];
    snprintf(tampered, sizeof(tampered), "%s", doc_live);
    size_t tlen = strlen(tampered);
    /* flip one nibble deep inside the signed body, not in the signature */
    size_t at = tlen / 2;
    tampered[at] = (tampered[at] == 'a') ? 'b' : 'a';
    idc_input_open(&input, dir);
    (void)json_push_kv_str(&input, "doc", tampered);
    (void)json_push_kv_bool(&input, "anchored", true);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify --anchored tampered doc: still BAD_SIGNATURE",
              strcmp(reply.error.code, "BAD_SIGNATURE") == 0);
    IDC_CHECK("verify --anchored tampered doc: no anchor fact reported",
              json_get(&reply.data, "anchored") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* --anchored with no datadir names its own refusal */
    idc_input_open(&input, NULL);
    (void)json_push_kv_str(&input, "doc", doc_live);
    (void)json_push_kv_bool(&input, "anchored", true);
    idc_call(zcl_native_handle_zcode_release_verify, &input, &reply,
             "zcl.zcode_release_verify.v1");
    IDC_CHECK("verify --anchored no datadir: named error, no crash",
              reply.status != ZCL_COMMAND_STATUS_PASSED &&
              reply.error.code[0] != '\0');
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

int test_identity_command(void)
{
    printf("\n=== core identity command tests ===\n");
    int failures = 0;

    node_rpc_client_set_test_hook(idc_rpc_hook);

    failures += t_resolve();
    failures += t_list();
    failures += t_write_intents();
    failures += t_exact_chain_lifecycle();
    failures += t_write_refusals();
    failures += t_verify_anchored();

    node_rpc_client_set_test_hook(NULL);
    return failures;
}
