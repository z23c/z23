/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view sync helpers: zclassicd RPC calls and the JSON mini-parser used
 * by wallet pages. */

#include "platform/time_compat.h"
#include "controllers/wallet_view_internal.h"
/* CSS is now in app/views/css/wallet.ccss, compiled as CSS_WALLET */
#include "models/contact.h"
#include "models/shared_validators.h"
#include "models/wallet_tx.h"
#include "crypto/sha256.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* Wallet sync from zclassicd plus its JSON mini-parser. */

/* ── JSON mini-parser (internal) ───────────────────────────── */

static bool json_next_str(const char **pos, const char *key,
                           const char **val, size_t *vlen) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(*pos, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return false;
    p++;
    const char *end = p;
    while (*end && !(*end == '"' && (end == p || *(end-1) != '\\'))) end++;
    if (!*end) return false;
    *val = p;
    *vlen = (size_t)(end - p);
    *pos = end + 1;
    return true;
}

static bool json_next_num(const char **pos, const char *key, double *out) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(*pos, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':') p++;
    char *endptr = NULL;
    *out = strtod(p, &endptr);
    *pos = endptr ? endptr : p + 1;
    return true;
}

static bool json_next_int(const char **pos, const char *key, int *out) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(*pos, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':') p++;
    char *endptr = NULL;
    *out = (int)strtol(p, &endptr, 10);
    *pos = endptr ? endptr : p + 1;
    return true;
}

static bool json_rpc_result_is_array(const char *json)
{
    const char *p;

    if (!json)
        return false;
    p = strstr(json, "\"result\"");
    if (!p)
        return false;
    p += strlen("\"result\"");
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != ':')
        return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return *p == '[';
}

static void wv_sapling_placeholder_fields(const uint8_t txid_bin[32],
                                          int outindex,
                                          uint8_t rcm[32],
                                          uint8_t ivk[32],
                                          uint8_t div_full[32],
                                          uint8_t pkd[32],
                                          uint8_t cm[32],
                                          uint8_t nf[32])
{
    uint8_t seed[36];

    memcpy(seed, txid_bin, 32);
    seed[32] = (uint8_t)(outindex & 0xFF);
    seed[33] = (uint8_t)((outindex >> 8) & 0xFF);
    seed[34] = 0;
    seed[35] = 0;

    #define HASH_FIELD(tag, taglen, out) do { \
        struct sha256_ctx _hc; \
        sha256_init(&_hc); \
        sha256_write(&_hc, (const unsigned char *)(tag), (taglen)); \
        sha256_write(&_hc, seed, 36); \
        sha256_finalize(&_hc, (out)); \
    } while (0)

    HASH_FIELD("nf", 2, nf);
    HASH_FIELD("cm", 2, cm);
    HASH_FIELD("rcm", 3, rcm);
    HASH_FIELD("ivk", 3, ivk);
    HASH_FIELD("pkd", 3, pkd);
    HASH_FIELD("div", 3, div_full);

    #undef HASH_FIELD
}

#ifdef ZCL_TESTING
void wv_sapling_placeholder_fields_for_test(const uint8_t txid_bin[32],
                                            int outindex,
                                            uint8_t rcm[32],
                                            uint8_t ivk[32],
                                            uint8_t div_full[32],
                                            uint8_t pkd[32],
                                            uint8_t cm[32],
                                            uint8_t nf[32])
{
    wv_sapling_placeholder_fields(txid_bin, outindex, rcm, ivk, div_full,
                                  pkd, cm, nf);
}
#endif

/* ── Sync wallet from zclassicd ────────────────────────────── */

void wv_sync_wallet_from_zclassicd(void) {
    if (!g_wv_datadir) return;
    char dbpath[1024];
    struct node_db ndb;
    struct db_wallet_utxo *utxos = NULL;
    struct db_sapling_note *notes = NULL;
    size_t utxo_count = 0;
    size_t utxo_cap = 0;
    size_t note_count = 0;
    size_t note_cap = 0;

    snprintf(dbpath, sizeof(dbpath), "%s/node.db", g_wv_datadir);
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, dbpath, "wallet_view.legacy_sync"))
        return;

    /* Fetch transparent UTXOs from zclassicd */
    char lu[65536] = "";
    int lu_rc = wv_rpc_call("listunspent", "[0]", lu, sizeof(lu));
    if (lu_rc <= 0) { node_db_close(&ndb); return; }

    /* Fetch shielded notes from zclassicd.
     * z_listunspent can be large (~1.3KB per note with memo fields).
     * 256KB handles ~200 notes safely. */
    char zlu[262144] = "";
    int zlu_rc = wv_rpc_call("z_listunspent", "[0]", zlu, sizeof(zlu));
    if (zlu_rc <= 0) { node_db_close(&ndb); return; }

    /* Sanity: mirror only array-shaped successful RPC results. Empty arrays
     * are valid and must clear stale mirror rows; result:null error bodies
     * must not wipe the DB. */
    if (!json_rpc_result_is_array(lu) || !json_rpc_result_is_array(zlu)) {
        node_db_close(&ndb); return;
    }

    {
        int chain_tip = db_wallet_chain_tip_height(&ndb);
        const char *p = lu;
        const char *txid_s;
        size_t txid_l;

        while (json_next_str(&p, "txid", &txid_s, &txid_l)) {
            struct db_wallet_utxo row;
            int vout = 0;
            int confs = 0;
            int height = 0;
            double amt = 0;
            int64_t val = 0;
            const char *script_s;
            size_t script_l = 0;
            const char *scan = p;
            uint8_t script_bin[64];
            size_t script_bin_len = 0;

            if (txid_l != 64)
                continue;
            memset(&row, 0, sizeof(row));
            if (ParseHex(txid_s, row.txid, 32) != 32)
                continue;
            json_next_int(&scan, "vout", &vout);
            scan = p;
            json_next_num(&scan, "amount", &amt);
            scan = p;
            json_next_int(&scan, "confirmations", &confs);
            val = (int64_t)(amt * 1e8 + 0.5);
            height = (chain_tip > 0 && confs > 0) ? (chain_tip - confs + 1) : 0;

            row.vout = (uint32_t)vout;
            row.value = val;
            row.height = height;

            scan = p;
            if (json_next_str(&scan, "scriptPubKey", &script_s, &script_l)) {
                script_bin_len = ParseHex(script_s, script_bin,
                                          sizeof(script_bin));
                if (script_bin_len == 25 && script_bin[0] == 0x76 &&
                    script_bin[1] == 0xa9 && script_bin[2] == 0x14) {
                    memcpy(row.address_hash, script_bin + 3, 20);
                }
            }
            if (script_bin_len > 0) {
                row.script = zcl_malloc(script_bin_len, "utxo script");
                if (!row.script)
                    goto cleanup;
                memcpy(row.script, script_bin, script_bin_len);
                row.script_len = script_bin_len;
            }

            if (utxo_count == utxo_cap) {
                size_t new_cap = utxo_cap == 0 ? 64 : utxo_cap * 2;
                struct db_wallet_utxo *new_rows =
                    zcl_realloc(utxos, new_cap * sizeof(*utxos), "utxo list grow");
                if (!new_rows) {
                    db_wallet_utxo_free(&row);
                    goto cleanup;
                }
                utxos = new_rows;
                utxo_cap = new_cap;
            }
            utxos[utxo_count++] = row;
        }
    }

    {
        int chain_tip = db_wallet_chain_tip_height(&ndb);
        const char *p = zlu;
        const char *txid_s;
        size_t txid_l;

        while (json_next_str(&p, "txid", &txid_s, &txid_l)) {
            struct db_sapling_note row;
            int outindex = 0;
            int confs = 0;
            int note_height = 0;
            double amt = 0;
            int64_t val = 0;
            const char *addr_s;
            size_t addr_l = 0;
            const char *scan = p;
            uint8_t div_full[32];

            if (txid_l != 64)
                continue;
            memset(&row, 0, sizeof(row));
            if (ParseHex(txid_s, row.txid, 32) != 32)
                continue;
            json_next_int(&scan, "outindex", &outindex);
            scan = p;
            json_next_num(&scan, "amount", &amt);
            scan = p;
            json_next_int(&scan, "confirmations", &confs);
            val = (int64_t)(amt * 1e8 + 0.5);
            note_height = (chain_tip > 0 && confs > 0)
                ? (chain_tip - confs + 1) : 0;

            row.output_index = (uint32_t)outindex;
            row.value = val;
            row.block_height = note_height;
            scan = p;
            if (json_next_str(&scan, "address", &addr_s, &addr_l) &&
                addr_l < sizeof(row.address)) {
                memcpy(row.address, addr_s, addr_l);
                row.address[addr_l] = '\0';
            }

            wv_sapling_placeholder_fields(row.txid, outindex, row.rcm, row.ivk,
                                          div_full, row.pk_d, row.cm,
                                          row.nullifier);
            memcpy(row.diversifier, div_full, sizeof(row.diversifier));
            snprintf(row.source, sizeof(row.source), "%s",
                     DB_SAPLING_NOTE_SOURCE_VIEW);

            if (note_count == note_cap) {
                size_t new_cap = note_cap == 0 ? 64 : note_cap * 2;
                struct db_sapling_note *new_rows =
                    zcl_realloc(notes, new_cap * sizeof(*notes), "sapling notes grow");
                if (!new_rows)
                    goto cleanup;
                notes = new_rows;
                note_cap = new_cap;
            }
            notes[note_count++] = row;
        }
    }

    if (!db_wallet_utxo_replace_all(&ndb, utxos, utxo_count))
        goto cleanup;
    if (!db_sapling_note_replace_view_rows(&ndb, notes, note_count))
        goto cleanup;

    /* Update wallet_transactions: fill in block_height for confirmed txs.
     * Query zclassicd gettransaction for each tx with height=0. */
    {
        struct db_wallet_txid_ref txids[50];
        int tx_count = db_wallet_tx_list_unconfirmed(&ndb, txids,
                                                     sizeof(txids) / sizeof(txids[0]));
        int updated = 0;
        int chain_tip = db_wallet_chain_tip_height(&ndb);
        for (int i = 0; i < tx_count; i++) {
            char txid_hex[65];
            for (int j = 0; j < 32; j++)
                snprintf(txid_hex + 2*j, 3, "%02x",
                         txids[i].txid[j]);

            char params[256];
            snprintf(params, sizeof(params), "[\"%s\"]", txid_hex);
            char gtx[4096] = "";
            if (wv_rpc_call("gettransaction", params, gtx, sizeof(gtx)) > 0) {
                int confs = 0;
                const char *scan = gtx;
                json_next_int(&scan, "confirmations", &confs);
                if (confs > 0 && chain_tip > 0) {
                    int tx_height = chain_tip - confs + 1;
                    if (db_wallet_tx_update_block_height(&ndb, txids[i].txid,
                                                         tx_height))
                        updated++;
                }
            }
            /* Limit RPC calls to avoid slowdown on first sync */
            if (updated >= 50)
                break;
        }
    }

    node_db_close(&ndb);
    for (size_t i = 0; i < utxo_count; i++)
        db_wallet_utxo_free(&utxos[i]);
    free(utxos);
    free(notes);
    g_balance_dirty = 1;
    return;

cleanup:
    node_db_close(&ndb);
    for (size_t i = 0; i < utxo_count; i++)
        db_wallet_utxo_free(&utxos[i]);
    free(utxos);
    free(notes);
}
