/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ZDIR WRITE PATH — the half zdir/zdir.h used to say did not
 * exist. The codec and the onion_directory fold were always wired; nothing
 * composed, funded, signed or broadcast a record, so on a network where no
 * other tool writes ZDIR records the projection read empty forever.
 *
 * The surfaces under test:
 *   tools/command/native_zdir_command.c  — `core zdir register/deregister`
 *   contexts/naming/controllers/src/zdir_controller.c — the zdir_* RPCs
 *   engine/services/.../zslp_command_build_owner_base_tx — the ownership proof
 *
 * NO NODE, NO BROADCAST. node_rpc_call returns sanitized durable-intent
 * receipts. The legacy RPC controller is separately driven with no wallet,
 * and the isolated fixture wraps production codec bytes in RAM-only
 * transactions; nothing broadcasts or touches the network.
 *
 * The un-fakeable case is (1) THE FULL LOOP: native writes prove scoped
 * plan/commit handling, then production codec bytes are spent from the
 * owner's coin, admitted through connect_block(), and folded by the SAME
 * indexer a node runs on live block data.
 *
 * Case (2) pins the ownership proof itself: the base tx for a mutation
 * spends EXACTLY the recorded owner's coin, never some other coin the same
 * wallet happens to hold — that first input is the only thing
 * explorer_index_apply_zdir_overlay accepts as ownership.
 *
 * Case (4) pins that TRANSFER stays refused. Command byte 3 is reserved and
 * zdir_parse rejects it on purpose, because a parsed-but-unhandled command
 * would be a silent stub. No write path may ever emit it; handing a
 * hostname over is deregister-then-register.
 *
 * NOT PROVEN HERE, and deliberately so: "nothing fires on a timer" is a
 * property of who CALLS these functions, which a unit test cannot observe.
 * It is held by the shape of the code instead — the RPCs are reachable only
 * from the rpc_table, the native leaves only from the command registry, and
 * neither is registered with the supervisor or any tick runner. */

#include "test/test_core.h"
#include "test/transaction_lab_simnet.h"

#include "chain/chainparams.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "controllers/zdir_controller.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/onion_directory.h"
#include "net/onion_peer_merge.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "services/zslp_command_service.h"
#include "wallet/wallet.h"
#include "zdir/zdir.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define ZWP_CHECK(name, expr) do {                                    \
    printf("zdir_write_path: %s... ", (name));                        \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

/* ── fixture ──────────────────────────────────────────────────────── */

static int g_zwp_plan_calls;

/* No live node for the whole file: this seam returns a public-safe plan and
 * never exposes hostnames, keys, owner addresses, or raw transaction bytes. */
static char *zwp_rpc_hook(const char *method, const char *params_json)
{
    (void)params_json;
    if (!method || strcmp(method, "zdir_intent") != 0)
        return NULL;
    g_zwp_plan_calls++;
    return strdup(
        "{\"schema\":\"zcl.core_zdir_register.v2\","
        "\"wallet_scope\":\"dev\",\"operation\":\"register\","
        "\"plan_id\":\"11111111111111111111111111111111"
        "11111111111111111111111111111111\","
        "\"plan_digest\":\"22222222222222222222222222222222"
        "22222222222222222222222222222222\","
        "\"snapshot_root\":\"33333333333333333333333333333333"
        "33333333333333333333333333333333\","
        "\"snapshot_status\":\"CURRENT\",\"status\":\"planned\","
        "\"state\":\"planned\",\"actual_fee_zat\":500,"
        "\"maximum_fee_zat\":1000,\"reserved_zat\":1000,"
        "\"hostname\":\"fixture-host\",\"pubkey\":\"fixture-key\","
        "\"owner_address\":\"fixture-owner\",\"raw_tx\":\"fixture-raw\"}");
}

/* A v3 onion hostname: 56 base32 characters + ".onion". */
static void zwp_mk_host(char *out, size_t n, char c)
{
    char body[57];
    memset(body, c, 56);
    body[56] = '\0';
    snprintf(out, n, "%s.onion", body);
}

/* Encode a 20-byte hash160 as this chain's P2PKH t-address — the same
 * encoding explorer_index_owner_address produces from a spent prevout. */
static void zwp_p2pkh(const uint8_t hash160[20], char *out, size_t n)
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
    out[0] = '\0';
    (void)encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, out, n);
}

/* Create the fixture datadir and its node.db, and hand back an OPEN handle
 * — the native commands re-open the same file READONLY on their own. */
static bool zwp_mk_datadir(char *dir, size_t dir_size, const char *tag,
                           struct node_db *ndb)
{
    test_fmt_tmpdir(dir, dir_size, "zdir_write_path", tag);
    mkdir("./test-tmp", 0700);
    mkdir(dir, 0700);
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    (void)remove(path);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path) && ndb->open;
}

/* Seed a spendable tx_output owned by `addr20` at outpoint (prevbyte×32, 0),
 * so a later tx spending it resolves that address as its signer. */
static void zwp_seed_owner_utxo(struct node_db *ndb, uint8_t prevbyte,
                                const uint8_t addr20[20], int height)
{
    uint8_t txid[32];
    memset(txid, prevbyte, 32);
    db_tx_output_save(ndb, txid, 0, 500000000, 0, addr20, height);
}

/* Build a one-tx block spending outpoint (prevbyte×32, 0) whose sole output
 * carries `script`, and run the per-block indexer at `height` — the SAME
 * entry point a node runs over live block data. */
static bool zwp_fold(struct node_db *ndb, const uint8_t *script, size_t slen,
                     uint8_t prevbyte, int height)
{
    struct transaction tx;
    transaction_init(&tx);
    if (!transaction_alloc(&tx, 1, 1))
        return false;
    memset(tx.vin[0].prevout.hash.data, prevbyte, 32);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;
    tx.vout[0].value = 0;
    memcpy(tx.vout[0].script_pub_key.data, script, slen);
    tx.vout[0].script_pub_key.size = slen;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)height;

    struct uint256 bhash;
    memset(bhash.data, 0x70, 32);
    bhash.data[0] = (uint8_t)height;
    bhash.data[1] = (uint8_t)(height >> 8);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

/* Run one native handler against {datadir, ...}. The caller owns `reply`
 * (zcl_command_reply_free) and `input` (json_free). */
static void zwp_call(void (*fn)(const struct zcl_command_request *,
                                struct zcl_command_reply *),
                     struct json_value *input,
                     struct zcl_command_reply *reply, const char *schema)
{
    static const struct zcl_command_spec register_spec = {
        .path = "core.zdir.register"
    };
    static const struct zcl_command_spec deregister_spec = {
        .path = "core.zdir.deregister"
    };
    const struct zcl_command_spec *spec =
        fn == zcl_native_handle_core_zdir_register ? &register_spec :
        fn == zcl_native_handle_core_zdir_deregister ? &deregister_spec : NULL;
    struct zcl_command_request request = { .spec = spec, .input = input };
    zcl_command_reply_init(reply, schema);
    fn(&request, reply);
}

static void zwp_input_open(struct json_value *input, const char *dir)
{
    json_init(input);
    json_set_object(input);
    if (dir)
        (void)json_push_kv_str(input, "datadir", dir);
}

static const char *zwp_str(const struct zcl_command_reply *reply,
                           const char *key)
{
    const char *s = json_get_str(json_get(&reply->data, key));
    return s ? s : "";
}

static void zwp_add_plan_fields(struct json_value *input, const char *idem)
{
    (void)json_push_kv_str(input, "wallet_scope", "dev");
    (void)json_push_kv_str(input, "idempotency_key", idem);
}

/* ── (1) compose -> fold -> deregister -> fold, on real bytes ─────── */

static int t_full_loop(void)
{
    int failures = 0;
    char dir[256];
    struct node_db ndb;
    ZWP_CHECK("loop fixture: datadir + node.db",
              zwp_mk_datadir(dir, sizeof(dir), "loop", &ndb));

    uint8_t owner20[20];
    memset(owner20, 0x41, sizeof(owner20));
    char owner_addr[96];
    zwp_p2pkh(owner20, owner_addr, sizeof(owner_addr));
    ZWP_CHECK("loop fixture: owner encodes as a t-address",
              owner_addr[0] != '\0');
    /* The later projection-only re-register still uses a synthetic previous
     * output; the initial register/deregister receipts seed their own exact
     * block-connected funding outputs. */
    zwp_seed_owner_utxo(&ndb, 0xA2, owner20, 10);

    char host[64];
    zwp_mk_host(host, sizeof(host), 'k');
    uint8_t key[ZDIR_PUBKEY_LEN];
    memset(key, 0x33, sizeof(key));
    char key_hex[65];
    HexStr(key, ZDIR_PUBKEY_LEN, false, key_hex, sizeof(key_hex));

    struct json_value input;
    struct zcl_command_reply reply;
    uint8_t script[ZDIR_SCRIPT_MAX];
    size_t slen = 0;
    struct zdir_message msg;
    struct transaction_lab_simnet_receipt register_mined;
    struct transaction_lab_simnet_receipt deregister_mined;
    bool register_mined_ok = false;
    bool deregister_mined_ok = false;
    g_zwp_plan_calls = 0;

    /* REGISTER: native command creates a scoped reservation and returns a
     * sanitized receipt. Production codec bytes are proven independently
     * below because raw signed bytes never belong in public output. */
    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", host);
    (void)json_push_kv_str(&input, "pubkey", key_hex);
    zwp_add_plan_fields(&input, "zdir-register-fixture");
    zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
             "zcl.core_zdir_register.v2");
    ZWP_CHECK("register plan: durable and scoped",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(zwp_str(&reply, "stage"), "plan") == 0 &&
              strlen(zwp_str(&reply, "plan_id")) == 64);
    ZWP_CHECK("register plan: receipt hides hostname, key, owner, raw bytes",
              json_get(&reply.data, "hostname") == NULL &&
              json_get(&reply.data, "pubkey") == NULL &&
              json_get(&reply.data, "owner_address") == NULL &&
              json_get(&reply.data, "raw_tx") == NULL &&
              json_get(&reply.data, "op_return_hex") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    slen = zdir_build_register(script, sizeof(script), host, key);
    ZWP_CHECK("register codec: exact bytes round-trip",
              slen > 0 && zdir_parse(script, slen, &msg) &&
              msg.command == ZDIR_CMD_REGISTER &&
              strcmp(msg.hostname, host) == 0 && msg.has_pubkey &&
              memcmp(msg.pubkey, key, sizeof(key)) == 0);

    /* Mine and project those exact bytes, spent from the owner's coin. */
    register_mined_ok = slen > 0 &&
        transaction_lab_simnet_mine_owned_op_return_at(
            script, slen, owner20, 500, &register_mined);
    ZWP_CHECK("register: exact command bytes pass connect_block",
              register_mined_ok && register_mined.mined_height == 500 &&
              register_mined.transaction.num_vout == 2 &&
              register_mined.change_zat == 800000);
    ZWP_CHECK("register: block-connected bytes fold through the indexer",
              register_mined_ok &&
              transaction_lab_simnet_project(&ndb, &register_mined));

    struct db_onion_directory row;
    memset(&row, 0, sizeof(row));
    bool landed = db_onion_directory_find(&ndb, host, &row);
    ZWP_CHECK("register: the projection now has the row", landed);
    ZWP_CHECK("register: the row is active",
              landed && strcmp(row.status,
                               ONION_DIRECTORY_STATUS_ACTIVE) == 0);
    ZWP_CHECK("register: the row records the paying owner",
              landed && strcmp(row.owner_address, owner_addr) == 0);
    ZWP_CHECK("register: seniority is the registering height",
              landed && row.height == 500 && row.updated_height == 500);
    ZWP_CHECK("register: the key binding reached the projection",
              landed && row.has_pubkey &&
              memcmp(row.master_pubkey, key, 32) == 0);
    struct db_onion_directory page[4];
    ZWP_CHECK("register: the hostname is now a dial candidate",
              db_onion_directory_list_active(&ndb, page, 4, 0) == 1);

    /* DEREGISTER: preflight reads the row this loop just wrote, then creates
     * a second sanitized durable reservation. */
    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", host);
    zwp_add_plan_fields(&input, "zdir-deregister-fixture");
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v2");
    ZWP_CHECK("deregister plan: durable and sanitized",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(zwp_str(&reply, "stage"), "plan") == 0 &&
              json_get(&reply.data, "hostname") == NULL &&
              json_get(&reply.data, "owner_address") == NULL);
    zcl_command_reply_free(&reply);
    json_free(&input);

    slen = zdir_build_deregister(script, sizeof(script), host);
    ZWP_CHECK("deregister codec: exact bytes round-trip without key",
              slen > 0 && zdir_parse(script, slen, &msg) &&
              msg.command == ZDIR_CMD_DEREGISTER && !msg.has_pubkey);

    deregister_mined_ok = slen > 0 &&
        transaction_lab_simnet_mine_owned_op_return_at(
            script, slen, owner20, 700, &deregister_mined);
    ZWP_CHECK("deregister: exact command bytes pass connect_block",
              deregister_mined_ok && deregister_mined.mined_height == 700 &&
              deregister_mined.transaction.num_vout == 2 &&
              deregister_mined.change_zat == 800000);
    ZWP_CHECK("deregister: block-connected bytes fold through the indexer",
              deregister_mined_ok &&
              transaction_lab_simnet_project(&ndb, &deregister_mined));

    memset(&row, 0, sizeof(row));
    bool retired = db_onion_directory_find(&ndb, host, &row);
    ZWP_CHECK("deregister: the row is retired", retired &&
              strcmp(row.status, ONION_DIRECTORY_STATUS_RETIRED) == 0);
    ZWP_CHECK("deregister: seniority and history survive retirement",
              retired && row.height == 500 && row.updated_height == 700);
    ZWP_CHECK("deregister: the hostname stops being a dial candidate",
              db_onion_directory_list_active(&ndb, page, 4, 0) == 0);

    /* And the command now refuses to spend a fee saying it again. */
    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", host);
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("deregister twice: ALREADY_RETIRED",
              strcmp(reply.error.code, "ALREADY_RETIRED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* A production unbound re-register revives the row without resetting
     * seniority. The native mutation path was already proved above. */
    slen = zdir_build_register(script, sizeof(script), host, NULL);
    ZWP_CHECK("re-register: folds and revives the row",
              slen > 0 && zwp_fold(&ndb, script, slen, 0xA2, 900));
    memset(&row, 0, sizeof(row));
    bool revived = db_onion_directory_find(&ndb, host, &row);
    ZWP_CHECK("re-register: active again, seniority unchanged",
              revived && row.height == 500 && row.updated_height == 900 &&
              strcmp(row.status, ONION_DIRECTORY_STATUS_ACTIVE) == 0);
    ZWP_CHECK("re-register: the unbound form clears the key binding",
              revived && !row.has_pubkey);
    ZWP_CHECK("native writes reached exactly two plan RPCs",
              g_zwp_plan_calls == 2);

    if (register_mined_ok)
        transaction_lab_simnet_receipt_free(&register_mined);
    if (deregister_mined_ok)
        transaction_lab_simnet_receipt_free(&deregister_mined);
    node_db_close(&ndb);
    return failures;
}

/* ── (2) the ownership proof: exactly the owner's input ──────────── */

/* Fund a wallet-controlled P2PKH coin and hand back the funding txid, so
 * the caller can assert WHICH coin the base tx selected. */
static bool zwp_fund(struct wallet *w, const struct key_id *kid,
                     int64_t value, uint8_t txid_out[32])
{
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    transaction_init(&wtx.tx);
    if (!transaction_alloc(&wtx.tx, 0, 1))
        return false;
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    dest.id.key = *kid;
    script_for_destination(&wtx.tx.vout[0].script_pub_key, &dest);
    wtx.tx.vout[0].value = value;
    transaction_compute_hash(&wtx.tx);
    wtx.confirms = 10;
    memcpy(txid_out, wtx.tx.hash.data, 32);
    bool ok = wallet_add_to_wallet(w, &wtx);
    transaction_free(&wtx.tx);
    return ok;
}

static int t_owner_proof(void)
{
    int failures = 0;

    static struct wallet w;
    uint8_t seed[32];
    memset(seed, 0x71, sizeof(seed));
    wallet_init(&w);
    wallet_init_hd(&w, seed, sizeof(seed));

    /* Two addresses in ONE wallet. The base tx must reach for the owner's
     * coin specifically — picking either coin would "work" as a wallet
     * operation and be silently refused by every node folding the record. */
    char owner_addr[128] = {0}, other_addr[128] = {0};
    struct key_id owner_kid, other_kid;
    bool got = wallet_get_new_address_with_key_id(&w, other_addr,
                                                  sizeof(other_addr),
                                                  &other_kid) &&
               wallet_get_new_address_with_key_id(&w, owner_addr,
                                                  sizeof(owner_addr),
                                                  &owner_kid);
    ZWP_CHECK("owner proof: two distinct wallet addresses",
              got && strcmp(owner_addr, other_addr) != 0);

    uint8_t other_txid[32], owner_txid[32];
    /* The decoy is funded FIRST and more richly, so a builder that simply
     * took the best available coin would take the wrong one. */
    bool funded = got && zwp_fund(&w, &other_kid, 900000, other_txid) &&
                  zwp_fund(&w, &owner_kid, 20000, owner_txid);
    ZWP_CHECK("owner proof: both addresses funded", funded);

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    int64_t fee = 0;
    const char *err = NULL;
    struct zcl_result r = { .ok = false };
    if (funded)
        r = zslp_command_build_owner_base_tx(&w, owner_addr, &wtx, &fee, &err);
    ZWP_CHECK("owner proof: the base tx builds", r.ok);
    ZWP_CHECK("owner proof: it spends exactly ONE input",
              r.ok && wtx.tx.num_vin == 1);
    ZWP_CHECK("owner proof: that input is the OWNER's coin, not the decoy",
              r.ok && wtx.tx.num_vin == 1 &&
              memcmp(wtx.tx.vin[0].prevout.hash.data, owner_txid, 32) == 0);
    ZWP_CHECK("owner proof: it is not the richer decoy coin",
              r.ok && wtx.tx.num_vin == 1 &&
              memcmp(wtx.tx.vin[0].prevout.hash.data, other_txid, 32) != 0);
    ZWP_CHECK("owner proof: output 0 pays dust back to the owner",
              r.ok && wtx.tx.num_vout == 2 && wtx.tx.vout[0].value == 546);
    ZWP_CHECK("owner proof: the remainder is change, not a burn",
              r.ok && wtx.tx.num_vout == 2 &&
              wtx.tx.vout[1].value == 20000 - 546 - fee);
    if (r.ok)
        transaction_free(&wtx.tx);

    /* An address the wallet cannot spend under fails CLOSED — it never
     * broadcasts a tx the projection would refuse. */
    uint8_t stranger20[20];
    memset(stranger20, 0x5e, sizeof(stranger20));
    char stranger_addr[96];
    zwp_p2pkh(stranger20, stranger_addr, sizeof(stranger_addr));
    memset(&wtx, 0, sizeof(wtx));
    err = NULL;
    struct zcl_result bad =
        zslp_command_build_owner_base_tx(&w, stranger_addr, &wtx, &fee, &err);
    ZWP_CHECK("owner proof: a non-owner address is refused, not composed",
              !bad.ok && err != NULL);

    return failures;
}

/* ── (3) the named refusals, before any fee is spent ─────────────── */

static int t_refusals(void)
{
    int failures = 0;
    char dir[256];
    struct node_db ndb;
    ZWP_CHECK("refusal fixture: datadir + node.db",
              zwp_mk_datadir(dir, sizeof(dir), "refuse", &ndb));

    /* A row registered from a non-P2PKH first input records no owner and is
     * permanently immutable — the fail-closed choice onion_directory.h
     * names. Both write commands must refuse it up front. */
    char orphan_host[64];
    zwp_mk_host(orphan_host, sizeof(orphan_host), 'm');
    struct db_onion_directory orphan;
    memset(&orphan, 0, sizeof(orphan));
    snprintf(orphan.hostname, sizeof(orphan.hostname), "%s", orphan_host);
    memset(orphan.txid, 0x5a, 32);
    orphan.height = 42;
    orphan.updated_height = 42;
    snprintf(orphan.status, sizeof(orphan.status), "%s",
             ONION_DIRECTORY_STATUS_ACTIVE);
    ZWP_CHECK("refusal fixture: ownerless row",
              db_onion_directory_save(&ndb, &orphan));
    node_db_close(&ndb);

    char good_host[64];
    zwp_mk_host(good_host, sizeof(good_host), 'n');

    struct json_value input;
    struct zcl_command_reply reply;

    /* no hostname at all */
    zwp_input_open(&input, dir);
    zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("register no hostname: MISSING_HOSTNAME",
              strcmp(reply.error.code, "MISSING_HOSTNAME") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    zwp_input_open(&input, dir);
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("deregister no hostname: MISSING_HOSTNAME",
              strcmp(reply.error.code, "MISSING_HOSTNAME") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* anything that is not a v3 onion */
    static const char *const bad_hosts[] = {
        "example.com",
        "aaaaaaaaaaaaaaaa.onion",                  /* v2 length */
        "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",  /* no suffix */
        "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK.onion",
        "11111111111111111111111111111111111111111111111111111111.onion",
    };
    for (size_t i = 0; i < sizeof(bad_hosts) / sizeof(bad_hosts[0]); i++) {
        zwp_input_open(&input, dir);
        (void)json_push_kv_str(&input, "hostname", bad_hosts[i]);
        zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
                 "zcl.core_zdir_register.v1");
        ZWP_CHECK("register non-v3 hostname: BAD_HOSTNAME",
                  strcmp(reply.error.code, "BAD_HOSTNAME") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* a malformed key binding is named, never silently dropped */
    static const char *const bad_keys[] = {
        "deadbeef",
        "zz11111111111111111111111111111111111111111111111111111111111111",
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); i++) {
        zwp_input_open(&input, dir);
        (void)json_push_kv_str(&input, "hostname", good_host);
        (void)json_push_kv_str(&input, "pubkey", bad_keys[i]);
        zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
                 "zcl.core_zdir_register.v1");
        ZWP_CHECK("register malformed pubkey: BAD_PUBKEY_HEX",
                  strcmp(reply.error.code, "BAD_PUBKEY_HEX") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* deregistering something nobody registered */
    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", good_host);
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("deregister unknown hostname: NOT_REGISTERED",
              strcmp(reply.error.code, "NOT_REGISTERED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* the permanently-immutable row, from both sides */
    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", orphan_host);
    zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("re-register an ownerless row: NOT_OWNER",
              strcmp(reply.error.code, "NOT_OWNER") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    zwp_input_open(&input, dir);
    (void)json_push_kv_str(&input, "hostname", orphan_host);
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("deregister an ownerless row: NOT_OWNER",
              strcmp(reply.error.code, "NOT_OWNER") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* deregister with no datadir cannot guess an owner, and says so */
    zwp_input_open(&input, NULL);
    (void)json_push_kv_str(&input, "hostname", good_host);
    zwp_call(zcl_native_handle_core_zdir_deregister, &input, &reply,
             "zcl.core_zdir_register.v1");
    ZWP_CHECK("deregister no datadir: named error, no crash",
              reply.status != ZCL_COMMAND_STATUS_PASSED &&
              reply.error.code[0] != '\0');
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* A first registration needs no local projection, but still requires
     * explicit custody and creates a durable plan through the node API. */
    zwp_input_open(&input, NULL);
    (void)json_push_kv_str(&input, "hostname", good_host);
    zwp_add_plan_fields(&input, "zdir-no-projection-fixture");
    zwp_call(zcl_native_handle_core_zdir_register, &input, &reply,
             "zcl.core_zdir_register.v2");
    ZWP_CHECK("register with no datadir: scoped plan still succeeds",
              reply.exit_code == ZCL_COMMAND_EXIT_OK &&
              strcmp(zwp_str(&reply, "stage"), "plan") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    return failures;
}

/* ── (4) TRANSFER stays refused ──────────────────────────────────── */

static int t_no_transfer(void)
{
    int failures = 0;

    ZWP_CHECK("transfer: byte 3 is not a handled command",
              !zdir_command_valid(3));
    ZWP_CHECK("transfer: byte 3 has no human name",
              strcmp(zdir_command_name(3), "unknown") == 0);

    /* Hand-forge a byte-3 record with an otherwise perfect body: the parser
     * must still reject it, so no fold can ever half-apply it. */
    char host[64];
    zwp_mk_host(host, sizeof(host), 'p');
    uint8_t script[ZDIR_SCRIPT_MAX];
    size_t slen = zdir_build_register(script, sizeof(script), host, NULL);
    ZWP_CHECK("transfer: a REGISTER fixture builds", slen > 0);
    struct zdir_message msg;
    ZWP_CHECK("transfer: the fixture parses before tampering",
              slen > 0 && zdir_parse(script, slen, &msg));

    /* The command byte is the only single-byte push whose value is 1 here;
     * find it by re-parsing after each candidate flip rather than assuming
     * an offset. */
    bool forged_rejected = true;
    bool forged_found = false;
    for (size_t i = 0; i < slen; i++) {
        if (script[i] != ZDIR_CMD_REGISTER)
            continue;
        uint8_t saved = script[i];
        script[i] = 3;
        struct zdir_message m;
        if (zdir_parse(script, slen, &m)) {
            /* A flip that still parses did not hit the command byte, unless
             * it somehow yielded command 3 — which must be impossible. */
            if (m.command == 3)
                forged_rejected = false;
        } else {
            forged_found = true;
        }
        script[i] = saved;
    }
    ZWP_CHECK("transfer: flipping the command byte to 3 makes it unparseable",
              forged_found);
    ZWP_CHECK("transfer: no forged byte-3 record ever parses",
              forged_rejected);

    /* And no builder can be talked into emitting it. */
    uint8_t out[ZDIR_SCRIPT_MAX];
    size_t reg = zdir_build_register(out, sizeof(out), host, NULL);
    struct zdir_message rm;
    ZWP_CHECK("transfer: register only ever emits command 1",
              reg > 0 && zdir_parse(out, reg, &rm) &&
              rm.command == ZDIR_CMD_REGISTER);
    size_t der = zdir_build_deregister(out, sizeof(out), host);
    ZWP_CHECK("transfer: deregister only ever emits command 2",
              der > 0 && zdir_parse(out, der, &rm) &&
              rm.command == ZDIR_CMD_DEREGISTER);

    return failures;
}

/* ── (5) the RPC surface with NO wallet: ready, never broadcast ──── */

static bool zwp_call_rpc(struct rpc_table *t, const char *method,
                         const char *hostname, const char *pubkey,
                         struct json_value *result)
{
    const struct rpc_command *cmd = rpc_table_find(t, method);
    if (!cmd)
        return false;
    struct json_value params = {0}, obj = {0};
    json_set_array(&params);
    json_set_object(&obj);
    if (hostname)
        (void)json_push_kv_str(&obj, "hostname", hostname);
    if (pubkey)
        (void)json_push_kv_str(&obj, "pubkey", pubkey);
    json_push_back(&params, &obj);
    json_free(&obj);
    bool ok = cmd->actor(&params, false, result);
    json_free(&params);
    return ok;
}

static int t_rpc_surface(void)
{
    int failures = 0;

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    ZWP_CHECK("rpc fixture: in-memory node.db",
              node_db_open(&ndb, ":memory:") && ndb.open);

    struct rpc_table t;
    memset(&t, 0, sizeof(t));
    rpc_table_init(&t);
    /* NO wallet and no mempool: the branch that cannot broadcast by
     * construction, whatever the caller asks for. */
    register_zdir_rpc_commands(&t, &ndb, NULL, NULL, NULL, NULL);

    ZWP_CHECK("rpc: zdir_register is registered",
              rpc_table_find(&t, "zdir_register") != NULL);
    ZWP_CHECK("rpc: zdir_deregister is registered",
              rpc_table_find(&t, "zdir_deregister") != NULL);
    ZWP_CHECK("rpc: custody-bound zdir_intent is registered",
              rpc_table_find(&t, "zdir_intent") != NULL);
    ZWP_CHECK("rpc: there is no zdir_transfer to call",
              rpc_table_find(&t, "zdir_transfer") == NULL);

    char host[64];
    zwp_mk_host(host, sizeof(host), 'q');

    struct json_value r = {0};
    bool ok = zwp_call_rpc(&t, "zdir_register", host, NULL, &r);
    ZWP_CHECK("rpc register (no wallet): succeeds", ok);
    ZWP_CHECK("rpc register (no wallet): status is ready, NOT broadcast",
              ok && strcmp(json_get_str(json_get(&r, "status")),
                           "ready") == 0);
    ZWP_CHECK("rpc register (no wallet): no txid is claimed",
              json_get(&r, "txid") == NULL);
    {
        const char *hex = json_get_str(json_get(&r, "op_return_hex"));
        uint8_t script[ZDIR_SCRIPT_MAX];
        int n = (hex && IsHex(hex)) ? ParseHex(hex, script, sizeof(script)) : 0;
        struct zdir_message m;
        ZWP_CHECK("rpc register (no wallet): the hex is a real ZDIR record",
                  n > 0 && zdir_parse(script, (size_t)n, &m) &&
                  m.command == ZDIR_CMD_REGISTER &&
                  strcmp(m.hostname, host) == 0);
    }
    json_free(&r);

    /* Refusals hold on the RPC side too. */
    memset(&r, 0, sizeof(r));
    ok = zwp_call_rpc(&t, "zdir_register", "not-an-onion", NULL, &r);
    ZWP_CHECK("rpc register: a non-v3 hostname is refused", !ok);
    json_free(&r);

    memset(&r, 0, sizeof(r));
    ok = zwp_call_rpc(&t, "zdir_deregister", host, NULL, &r);
    ZWP_CHECK("rpc deregister: an unregistered hostname is refused", !ok);
    json_free(&r);

    /* Drop the context before the db handle dies, so no later group can
     * reach a freed node_db through the controller's file statics. */
    struct rpc_table scratch;
    memset(&scratch, 0, sizeof(scratch));
    rpc_table_init(&scratch);
    register_zdir_rpc_commands(&scratch, NULL, NULL, NULL, NULL, NULL);
    node_db_close(&ndb);
    return failures;
}

int test_zdir_write_path(void)
{
    printf("\n=== ZDIR write path (announce/retire a node on-chain) ===\n");
    int failures = 0;

    node_rpc_client_set_test_hook(zwp_rpc_hook);

    failures += t_full_loop();
    failures += t_owner_proof();
    failures += t_refusals();
    failures += t_no_transfer();
    failures += t_rpc_surface();

    node_rpc_client_set_test_hook(NULL);
    return failures;
}
