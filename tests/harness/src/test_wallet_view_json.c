/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * wallet_view JSON builders, called directly with fixture values: the
 * diagnostic controllers are the only production callers, so this is the
 * only place the exact field set and values of each builder is pinned.
 * Hermetic: no DB, no wallet, no network. */

#include "test/test_core.h"
#include "test/test_wallet_view_priv.h"
#include "views/wallet_view.h"
#include "models/wallet_key.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

static int wvj_fail(const char *what)
{
    printf("wallet_view json: %s... FAIL\n", what);
    return 1;
}

static bool wvj_int(const struct json_value *o, const char *k, int64_t want)
{
    const struct json_value *v = json_get(o, k);
    return v && v->type == JSON_INT && json_get_int(v) == want;
}

static bool wvj_real(const struct json_value *o, const char *k, double want)
{
    const struct json_value *v = json_get(o, k);
    return v && v->type == JSON_REAL && json_get_real(v) == want;
}

static bool wvj_str(const struct json_value *o, const char *k, const char *want)
{
    const struct json_value *v = json_get(o, k);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static bool wvj_bool(const struct json_value *o, const char *k, bool want)
{
    const struct json_value *v = json_get(o, k);
    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}

static int wvj_key_entry(void)
{
    int failures = 0;
    struct db_wallet_key key;
    memset(&key, 0, sizeof(key));
    for (int i = 0; i < 20; i++)
        key.pubkey_hash[i] = (uint8_t)(0x01 + i);
    memset(key.privkey, 0xA5, sizeof(key.privkey));
    memset(key.pubkey, 0x5A, sizeof(key.pubkey));
    key.pubkey_len = 33;

    struct json_value out;
    memset(&out, 0, sizeof(out));
    wallet_view_key_entry(&out, &key, "t1Example", 3, 150000000);
    if (out.type != JSON_OBJ || json_size(&out) != 4)
        failures += wvj_fail("key entry is an object of exactly 4 fields");
    if (!wvj_str(&out, "address", "t1Example"))
        failures += wvj_fail("key entry address");
    /* Full 40 hex chars, in byte order (not reversed, not truncated). */
    if (!wvj_str(&out, "pubkey_hash",
                 "0102030405060708090a0b0c0d0e0f1011121314"))
        failures += wvj_fail("key entry pubkey_hash is 20 bytes in order");
    if (!wvj_int(&out, "unspent_count", 3))
        failures += wvj_fail("key entry unspent_count");
    if (!wvj_real(&out, "balance", 1.5))
        failures += wvj_fail("key entry balance");

    /* A key view must carry no secret: no private key bytes, no seed. */
    char buf[1024];
    json_write(&out, buf, sizeof(buf));
    if (strstr(buf, "a5a5a5a5") || strstr(buf, "A5A5A5A5") ||
        strstr(buf, "5a5a5a5a") || strstr(buf, "priv") ||
        strstr(buf, "seed") || strstr(buf, "secret"))
        failures += wvj_fail("key entry carries no secret");
    json_free(&out);
    if (!failures)
        printf("wallet_view json: key entry... OK\n");
    return failures;
}

static bool wvj_trace_with_spender_ok(const struct json_value *o)
{
    return o->type == JSON_OBJ && json_size(o) == 8 &&
           wvj_str(o, "txid", "ab12") && wvj_int(o, "vout", 7) &&
           wvj_str(o, "status", "unspent") && wvj_real(o, "value", 0.25) &&
           wvj_int(o, "height", 321) && wvj_str(o, "spent_by", "cd34") &&
           wvj_bool(o, "in_wallet", true) &&
           wvj_bool(o, "in_chainstate", false);
}

static int wvj_utxo_trace(void)
{
    int failures = 0;
    struct json_value out;
    memset(&out, 0, sizeof(out));
    wallet_view_utxo_trace(&out, "ab12", 7, "unspent", 25000000, 321,
                           "cd34", true, false);
    if (!wvj_trace_with_spender_ok(&out))
        failures += wvj_fail("utxo trace with spender");
    json_free(&out);

    memset(&out, 0, sizeof(out));
    wallet_view_utxo_trace(&out, "ab12", 0, "spent", 100000000, 5, NULL,
                           false, true);
    if (json_size(&out) != 7 || json_get(&out, "spent_by") ||
        !wvj_bool(&out, "in_wallet", false) ||
        !wvj_bool(&out, "in_chainstate", true))
        failures += wvj_fail("utxo trace without spender omits spent_by");
    json_free(&out);
    if (!failures)
        printf("wallet_view json: utxo trace... OK\n");
    return failures;
}

static int wvj_flow_entry(void)
{
    int failures = 0;
    struct json_value out;
    memset(&out, 0, sizeof(out));
    wallet_view_flow_entry(&out, "ef56", "send", -200000000, 1, 9,
                           50000000);
    if (out.type != JSON_OBJ || json_size(&out) != 6 ||
        !wvj_str(&out, "txid", "ef56") || !wvj_str(&out, "category", "send") ||
        !wvj_real(&out, "amount", -2.0) ||
        !wvj_real(&out, "fee", -0.00000001) || !wvj_int(&out, "height", 9) ||
        !wvj_real(&out, "running_balance", 0.5))
        failures += wvj_fail("flow entry with a 1-zatoshi fee");
    json_free(&out);

    memset(&out, 0, sizeof(out));
    wallet_view_flow_entry(&out, "ef56", "receive", 100000000, 0, 10,
                           100000000);
    if (json_size(&out) != 5 || json_get(&out, "fee") ||
        !wvj_real(&out, "amount", 1.0))
        failures += wvj_fail("flow entry with zero fee omits fee");
    json_free(&out);
    if (!failures)
        printf("wallet_view json: flow entry... OK\n");
    return failures;
}

static bool wvj_reconcile_ok(void)
{
    struct json_value o;
    memset(&o, 0, sizeof(o));
    wallet_view_reconcile_summary(&o, 1, 2, 3, 4, 5, 100000000, 250000000);
    bool ok = o.type == JSON_OBJ && json_size(&o) == 7 &&
              wvj_int(&o, "verified", 1) && wvj_int(&o, "phantom", 2) &&
              wvj_int(&o, "spent_on_chain", 3) &&
              wvj_int(&o, "value_mismatch", 4) && wvj_int(&o, "fixed", 5) &&
              wvj_real(&o, "balance_before", 1.0) &&
              wvj_real(&o, "balance_after", 2.5);
    json_free(&o);
    return ok;
}

static bool wvj_purge_ok(void)
{
    struct json_value o;
    memset(&o, 0, sizeof(o));
    wallet_view_purge_summary(&o, 6, 7, 300000000, 400000000, 25000000);
    bool ok = o.type == JSON_OBJ && json_size(&o) == 5 &&
              wvj_int(&o, "utxos_deleted", 6) &&
              wvj_int(&o, "txs_deleted", 7) &&
              wvj_real(&o, "amount_purged", 3.0) &&
              wvj_real(&o, "balance_before", 4.0) &&
              wvj_real(&o, "balance_after", 0.25);
    json_free(&o);
    return ok;
}

static bool wvj_replay_ok(void)
{
    struct json_value o;
    memset(&o, 0, sizeof(o));
    wallet_view_replay_summary(&o, 8, 9, 500000000, 50000000);
    bool ok = o.type == JSON_OBJ && json_size(&o) == 4 &&
              wvj_int(&o, "utxos_found", 8) && wvj_int(&o, "txs_found", 9) &&
              wvj_real(&o, "new_balance", 5.0) &&
              wvj_real(&o, "old_balance", 0.5);
    json_free(&o);
    return ok;
}

static bool wvj_sync_ok(void)
{
    struct json_value o;
    memset(&o, 0, sizeof(o));
    wallet_view_sync_summary(&o, 10, 11, 12, 600000000, 75000000);
    bool ok = o.type == JSON_OBJ && json_size(&o) == 5 &&
              wvj_int(&o, "utxos_unmarked_spent", 10) &&
              wvj_int(&o, "already_correct", 11) &&
              wvj_int(&o, "marked_spent", 12) &&
              wvj_real(&o, "balance_before", 6.0) &&
              wvj_real(&o, "balance_after", 0.75);
    json_free(&o);
    return ok;
}

static int wvj_summaries(void)
{
    int failures = 0;
    if (!wvj_reconcile_ok()) failures += wvj_fail("reconcile summary");
    if (!wvj_purge_ok()) failures += wvj_fail("purge summary");
    if (!wvj_replay_ok()) failures += wvj_fail("replay summary");
    if (!wvj_sync_ok()) failures += wvj_fail("sync summary");
    if (!failures)
        printf("wallet_view json: summaries... OK\n");
    return failures;
}

static int wvj_chain_coin(void)
{
    int failures = 0;
    struct json_value out;
    memset(&out, 0, sizeof(out));
    wallet_view_chain_coin(&out, 2, 125000000, true, "t1Addr", true);
    if (out.type != JSON_OBJ || json_size(&out) != 5 ||
        !wvj_int(&out, "vout", 2) || !wvj_real(&out, "value", 1.25) ||
        !wvj_str(&out, "status", "unspent") ||
        !wvj_str(&out, "address", "t1Addr") ||
        !wvj_bool(&out, "in_wallet", true))
        failures += wvj_fail("chain coin unspent with address");
    json_free(&out);

    memset(&out, 0, sizeof(out));
    wallet_view_chain_coin(&out, 0, 0, false, NULL, false);
    if (json_size(&out) != 4 || json_get(&out, "address") ||
        !wvj_str(&out, "status", "spent") ||
        !wvj_real(&out, "value", 0.0) ||
        !wvj_bool(&out, "in_wallet", false))
        failures += wvj_fail("chain coin spent without address");
    json_free(&out);
    if (!failures)
        printf("wallet_view json: chain coin... OK\n");
    return failures;
}

int check_wallet_view_json_builders(void)
{
    int failures = wvj_key_entry();
    failures += wvj_utxo_trace();
    failures += wvj_flow_entry();
    failures += wvj_summaries();
    failures += wvj_chain_coin();
    return failures;
}
