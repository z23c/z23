/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The repair-utxos run-and-exit mode (repair_utxos_mode and its local helpers).
 * Moved out of engine/entry/main_cli_modes.c unchanged to fit the file-size cap;
 * behaviour is identical. */
#if !defined(ZCL_TESTING) || !defined(ZCL_RPC_COMPOSER_TEST)
#include "main_cli_modes.h"
#include "rpc/client.h"
#include "base/safe_alloc.h"
#include "util/ar_step_readonly.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int repair_utxos_local_tip(sqlite3 *db)
{
    int tip = 0;
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(db, "SELECT MAX(height) FROM blocks", -1, &s, NULL);
    if (s && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) tip = sqlite3_column_int(s, 0);
    if (s) sqlite3_finalize(s);
    return tip;
}
static int repair_utxos_remote_tip(int port, const char *creds)
{
    char rbuf[4096];
    if (rpc_call_local(port, creds, "getblockcount", "[]", rbuf, sizeof(rbuf)) <= 0)
        return 0;
    const char *body = rpc_http_body(rbuf);
    const char *rp = body ? strstr(body, "\"result\":") : NULL;
    return rp ? (int)strtol(rp + 9, NULL, 10) : 0;
}
static bool repair_utxos_block_hash(int port, const char *creds, int h, char bhash[65])
{
    char params[64];
    snprintf(params, sizeof(params), "[%d]", h);
    char hbuf[256];
    if (rpc_call_local(port, creds, "getblockhash", params, hbuf, sizeof(hbuf)) <= 0) return false;
    const char *hbody = rpc_http_body(hbuf);
    if (!hbody) return false;
    const char *hp = strstr(hbody, "\"result\":\"");
    if (!hp) return false;
    { const char *s = hp + 10; int i = 0;
      while (*s && *s != '"' && i < 64) bhash[i++] = *s++;
      bhash[i] = '\0'; }
    return true;
}
static int repair_utxos_tx_height(int port, const char *creds, const char *txbody)
{
    const char *bhp = strstr(txbody, "\"blockhash\"");
    if (!bhp) return 0;
    /* Get height from block header */
    const char *bhs = strchr(bhp + 11, '"');
    if (!bhs) return 0;
    bhs++;
    char bhhex[65] = "";
    const char *bhe = strchr(bhs, '"');
    if (!bhe || bhe - bhs != 64) return 0;
    memcpy(bhhex, bhs, 64);
    char bhp2[128];
    snprintf(bhp2, sizeof(bhp2), "[\"%s\"]", bhhex);
    char bhbuf[4096];
    if (rpc_call_local(port, creds, "getblockheader", bhp2, bhbuf, sizeof(bhbuf)) <= 0)
        return 0;
    const char *bhb = rpc_http_body(bhbuf);
    const char *hhp = bhb ? strstr(bhb, "\"height\":") : NULL;
    return hhp ? (int)strtol(hhp + 9, NULL, 10) : 0;
}
static int repair_utxos_output_script(const char *entry, uint8_t script[520],
                                      int *stype, uint8_t addr_hash[20])
{
    /* Find scriptPubKey hex */
    const char *sp = strstr(entry, "\"hex\":\"");
    const char *se = sp ? strchr(sp + 7, '"') : NULL;
    int script_len = 0;
    if (se) {
        sp += 7;
        script_len = (int)(se - sp) / 2;
        if (script_len > 520) script_len = 520;
        for (int si = 0; si < script_len; si++) {
            char h2[3] = { sp[si*2], sp[si*2+1], 0 };
            script[si] = (uint8_t)strtol(h2, NULL, 16);
        }
    }
    *stype = 0;
    if (script_len == 25 && script[0] == 0x76) {
        memcpy(addr_hash, script + 3, 20);
    } else if (script_len == 23 && script[0] == 0xa9) {
        memcpy(addr_hash, script + 2, 20);
        *stype = 1;
    }
    return script_len;
}
static bool repair_utxos_insert_missing(sqlite3_stmt *ins, int port, const char *creds,
        const char *txid_hex, const uint8_t txid_bin[32], int vout, int tip)
{
    /* Fetch from zclassicd */
    char txp[128];
    snprintf(txp, sizeof(txp), "[\"%s\",1]", txid_hex);
    char txbuf[65536];
    if (rpc_call_local(port, creds, "getrawtransaction", txp, txbuf,
                       sizeof(txbuf)) <= 0) return false;
    const char *txbody = rpc_http_body(txbuf);
    if (!txbody) return false;
    /* Find the output at vout index */
    /* Find "vout":[...{...value...scriptPubKey...}...] */
    const char *entry = strstr(txbody, "\"vout\"");
    /* Skip to the vout-th entry */
    for (int vi = 0; entry && vi <= vout; vi++)
        entry = strstr(entry + 1, "\"value\"");
    if (!entry) return false;
    int64_t val_sat = (int64_t)(strtod(entry + 8, NULL) * 1e8 + 0.5);
    uint8_t script[520] = {0};
    int stype = 0;
    uint8_t addr_hash[20] = {0};
    int script_len = repair_utxos_output_script(entry, script, &stype, addr_hash);
    /* Get block height */
    int txht = repair_utxos_tx_height(port, creds, txbody);
    /* Only insert UTXOs created at or below
     * our tip. UTXOs from blocks above the
     * tip will be created by connect_block
     * when those blocks are connected.
     * Inserting them early causes BIP30
     * violations (duplicate txid). */
    if (txht <= 0 || txht > tip) return false;
    sqlite3_reset(ins);
    sqlite3_bind_blob(ins, 1, txid_bin, 32, SQLITE_STATIC);
    sqlite3_bind_int(ins, 2, vout);
    sqlite3_bind_int64(ins, 3, val_sat);
    sqlite3_bind_blob(ins, 4, script, script_len, SQLITE_STATIC);
    sqlite3_bind_int(ins, 5, stype);
    sqlite3_bind_blob(ins, 6, addr_hash, 20, SQLITE_STATIC);
    sqlite3_bind_int(ins, 7, txht);
    AR_STEP_WRITE(ins);
    return true;
}
static bool repair_utxos_vin_entry(sqlite3 *db, sqlite3_stmt *ins, int port,
        const char *creds, const char **pp, int tip, int *checked, int *fixed)
{
    const char *p = *pp + 6;
    const char *q = strchr(p, '"');
    if (!q) { *pp = p; return false; }
    q++;
    const char *end = strchr(q, '"');
    if (!end || end - q != 64) { *pp = end ? end : q; return true; }
    char txid_hex[65] = {0};
    memcpy(txid_hex, q, 64);
    /* Get vout */
    const char *vp = strstr(end, "\"vout\"");
    if (!vp) { *pp = p; return false; }
    int vout = (int)strtol(vp + 7, NULL, 10);
    (*checked)++;
    /* Reverse txid for internal byte order */
    uint8_t txid_bin[32];
    for (int i = 0; i < 32; i++) {
        char hex2[3] = { txid_hex[62-2*i], txid_hex[63-2*i], 0 };
        txid_bin[i] = (uint8_t)strtol(hex2, NULL, 16);
    }
    /* Check if exists */
    sqlite3_stmt *chk = NULL;
    sqlite3_prepare_v2(db, "SELECT 1 FROM utxos WHERE txid=? AND vout=?", -1, &chk, NULL);
    sqlite3_bind_blob(chk, 1, txid_bin, 32, SQLITE_STATIC);
    sqlite3_bind_int(chk, 2, vout);
    bool exists = (AR_STEP_ROW_READONLY(chk) == SQLITE_ROW);
    sqlite3_finalize(chk);
    if (!exists && repair_utxos_insert_missing(ins, port, creds, txid_hex,
                                               txid_bin, vout, tip))
        (*fixed)++;
    *pp = end + 1;
    return true;
}
static bool repair_utxos_scan_height(sqlite3 *db, sqlite3_stmt *ins, int port,
        const char *creds, int h, int tip, int *checked, int *fixed)
{
    /* Get block hash */
    char bhash[65] = "";
    if (!repair_utxos_block_hash(port, creds, h, bhash)) return false;
    /* Get block with full tx data */
    char bparams[128];
    snprintf(bparams, sizeof(bparams), "[\"%s\",2]", bhash);
    char *bbuf = zcl_malloc(2*1024*1024, "repair_utxos_block"); /* 2MB for block data */
    if (!bbuf) return false;
    int brc = rpc_call_local(port, creds, "getblock", bparams, bbuf, 2*1024*1024);
    if (brc <= 0) { free(bbuf); return false; }
    const char *bbody = rpc_http_body(bbuf);
    if (!bbody) { free(bbuf); return false; }
    /* Parse inputs: find each "vin":[{"txid":"...","vout":N}] */
    const char *p = bbody;
    while ((p = strstr(p, "\"vin\"")) != NULL) {
        p += 5;
        /* Walk through vin array entries */
        while ((p = strstr(p, "\"txid\"")) != NULL) {
            if (!repair_utxos_vin_entry(db, ins, port, creds, &p, tip,
                                        checked, fixed)) break;
        }
        break; /* only process first vin array per tx */
    }
    free(bbuf);
    return true;
}
static void repair_utxos_reset_best_block(sqlite3 *db)
{
    sqlite3_stmt *tip_s = NULL;
    sqlite3_prepare_v2(db, "SELECT hash FROM blocks WHERE height = "
        "(SELECT MAX(height) FROM blocks)", -1, &tip_s, NULL);
    const void *tip_hash = NULL;
    if (tip_s && AR_STEP_ROW_READONLY(tip_s) == SQLITE_ROW)
        tip_hash = sqlite3_column_blob(tip_s, 0);
    int tip_len = tip_hash ? sqlite3_column_bytes(tip_s, 0) : 0;
    sqlite3_stmt *up = NULL;
    if (tip_hash && tip_len >= 32)
        sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO node_state(key,value)"
            " VALUES('coins_best_block',?)", -1, &up, NULL);
    if (up) {
        sqlite3_bind_blob(up, 1, tip_hash, tip_len, SQLITE_STATIC);
        AR_STEP_WRITE(up);
        sqlite3_finalize(up);
        printf("Reset coins_best_block to tip\n");
    }
    if (tip_s) sqlite3_finalize(tip_s);
}
int repair_utxos_mode(int argc, char **argv)
{
    if (argc <= 4) {
        fprintf(stderr,
            "repair-utxos requires the node's RPC credentials\n"
            "usage: repair-utxos [num_blocks] [port] <user:password>\n\n"
            "Take user:password from rpcuser/rpcpassword in\n"
            "zclassic.conf, or from the first line of the node's\n"
            ".cookie file when conf credentials are not set.\n");
        return 1;
    }
    int num_blocks = argc > 2 ? atoi(argv[2]) : 5000;
    int port = argc > 3 ? atoi(argv[3]) : 8232;
    const char *creds = argv[4];
    const char *home = getenv("HOME");
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/.zclassic-c23/node.db",
             home ? home : ".");

    printf("=== UTXO Repair ===\n");
    printf("DB:     %s\n", db_path);
    printf("Source: zclassicd on port %d\n", port);
    printf("Scan:   %d blocks ahead\n\n", num_blocks);

    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open %s\n", db_path);
        return 1;
    }

    /* Get current tip */
    int tip = repair_utxos_local_tip(db);
    printf("Current tip: %d\n", tip);

    /* Get zclassicd tip */
    int ztip = repair_utxos_remote_tip(port, creds);
    if (ztip == 0) {
        fprintf(stderr, "Cannot reach zclassicd on port %d\n", port);
        sqlite3_close(db);
        return 1;
    }
    int scan_end = tip + num_blocks;
    if (scan_end > ztip) scan_end = ztip;
    printf("zclassicd tip: %d\nScan range: %d → %d\n\n", ztip, tip+1, scan_end);

    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    sqlite3_stmt *ins = NULL;
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO utxos"
        "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
        " VALUES(?,?,?,?,?,?,?,0)", -1, &ins, NULL);

    int fixed = 0, checked = 0;

    for (int h = tip + 1; h <= scan_end; h++) {
        if (!repair_utxos_scan_height(db, ins, port, creds, h, tip,
                                      &checked, &fixed)) break;
        if (h % 200 == 0) {
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            printf("  h=%d  checked=%d  fixed=%d\n", h, checked, fixed);
            fflush(stdout);
        }
    }

    if (ins) sqlite3_finalize(ins);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    /* OFFLINE CACHE RESET: 'coins_best_block' is a
     * projection key — authority = reducer_frontier_derive_coins_best
     * over coins_kv. The --repair modified the utxos mirror directly,
     * so refresh its cached anchor to match; the derivation is
     * unaffected. */
    if (fixed > 0)
        repair_utxos_reset_best_block(db);

    sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);
    sqlite3_close(db);

    printf("\nDone: checked %d inputs, fixed %d UTXOs\n", checked, fixed);
    printf("Restart the node to apply.\n");
    return 0;
}
#endif /* ZCL_RPC_COMPOSER_TEST */
