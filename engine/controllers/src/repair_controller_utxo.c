/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * repairutxos RPC and UTXO refetch/insert helpers. */

#include "controllers/repair_controller_internal.h"

/* Parse a scriptPubKey hex run starting at `sph` (just past the "hex"
 * key) into script/script_len. `*hex_bytes` always receives the decoded
 * byte count so the caller can report it; `*script_len` is written only
 * when the run fits the caller's 10000-byte buffer. */
static bool repair_parse_script_hex(const char *sph, uint8_t *script,
                                    size_t *script_len, size_t *hex_bytes)
{
    while (*sph == ' ' || *sph == ':' || *sph == '"') sph++;
    const char *sp = sph;
    size_t slen = 0;
    while (*sp && *sp != '"') { slen++; sp++; }
    slen /= 2;
    *hex_bytes = slen;
    if (slen > 10000) return false;
    for (size_t i = 0; i < slen; i++) {
        char hx[3] = { sph[i*2], sph[i*2+1], '\0' };
        script[i] = (uint8_t)strtoul(hx, NULL, 16);
    }
    *script_len = slen;
    return true;
}

/* Compute the UTXO height from "confirmations" and the remote tip. */
static void repair_height_from_confirmations(int port, const char *creds,
                                             const char *res, int *height)
{
    int64_t confs = repair_json_int(res, "confirmations");
    char resp2[4096];
    int rc2 = rpc_call_local(port, creds, "getblockcount", "[]",
                              resp2, sizeof(resp2));
    if (rc2 > 0) {
        const char *b2 = rpc_http_body(resp2);
        const char *r2 = strstr(b2, "\"result\"");
        if (r2) {
            r2 += 8;
            while (*r2 == ' ' || *r2 == ':') r2++;
            *height = (int)(strtoll(r2, NULL, 10) - confs + 1);
        }
    }
}

static bool fetch_utxo_gettxout(int port, const char *creds,
                                 const char *txid_hex, uint32_t vout,
                                 int64_t *value, uint8_t *script,
                                 size_t *script_len, int *height,
                                 bool *coinbase)
{
    char params[256];
    snprintf(params, sizeof(params), "[\"%s\", %u, false]", txid_hex, vout);

    char resp[65536];
    int rc = rpc_call_local(port, creds, "gettxout", params,
                             resp, sizeof(resp));
    if (rc <= 0) LOG_FAIL("repair", "gettxout RPC failed for %s:%u", txid_hex, vout);

    const char *body = rpc_http_body(resp);
    const char *res = strstr(body, "\"result\"");
    if (!res) LOG_FAIL("repair", "gettxout response missing \"result\" for %s:%u", txid_hex, vout);
    res += 8;
    while (*res == ' ' || *res == ':') res++;
    if (*res == 'n') return false; /* null = already spent — expected, not an error */

    /* Extract value (ZCL → zatoshi) */
    const char *vp = strstr(res, "\"value\"");
    if (!vp) LOG_FAIL("repair", "gettxout missing \"value\" field for %s:%u", txid_hex, vout);
    vp += 7;
    while (*vp == ' ' || *vp == ':') vp++;
    *value = (int64_t)(strtod(vp, NULL) * 100000000.0 + 0.5);

    /* Extract scriptPubKey hex */
    const char *sph = strstr(res, "\"hex\"");
    if (!sph) LOG_FAIL("repair", "gettxout missing scriptPubKey hex for %s:%u", txid_hex, vout);
    sph += 5;
    size_t hex_bytes = 0;
    if (!repair_parse_script_hex(sph, script, script_len, &hex_bytes))
        LOG_FAIL("repair",
                 "gettxout script too large (%zu bytes) for %s:%u",
                 hex_bytes, txid_hex, vout);

    *coinbase = (strstr(res, "\"coinbase\":true") != NULL ||
                 strstr(res, "\"coinbase\": true") != NULL);

    /* Compute UTXO height from confirmations */
    repair_height_from_confirmations(port, creds, res, height);
    return true;
}

/* Locate the opening '{' of the vout object whose "n" is `vout`.
 * Returns NULL when no such entry exists; on success `*ventry_out`
 * receives the "n" key match the caller's window checks are relative
 * to. */
static const char *repair_rawtx_find_vout_obj(const char *vout_arr,
                                              uint32_t vout,
                                              const char **ventry_out)
{
    char n_pat[64];
    snprintf(n_pat, sizeof(n_pat), "\"n\": %u", vout);
    const char *ventry = strstr(vout_arr, n_pat);
    if (!ventry) {
        snprintf(n_pat, sizeof(n_pat), "\"n\":%u", vout);
        ventry = strstr(vout_arr, n_pat);
    }
    if (!ventry) return NULL;
    *ventry_out = ventry;

    /* Find opening { of this vout object */
    const char *obj = ventry;
    int depth = 0;
    while (obj > vout_arr) {
        obj--;
        if (*obj == '}') depth++;
        if (*obj == '{') { if (depth == 0) break; depth--; }
    }
    return obj;
}

enum repair_rawtx_output_status {
    REPAIR_RAWTX_OUTPUT_OK = 0,
    REPAIR_RAWTX_OUTPUT_NO_VALUE = 1,
    REPAIR_RAWTX_OUTPUT_NO_HEX = 2,
    REPAIR_RAWTX_OUTPUT_SCRIPT_TOO_LARGE = 3
};

/* Extract value + scriptPubKey from one getrawtransaction vout object,
 * keeping the original's proximity windows relative to `ventry`. */
static enum repair_rawtx_output_status repair_rawtx_extract_output(
    const char *obj, const char *ventry, int64_t *value, uint8_t *script,
    size_t *script_len, size_t *hex_bytes)
{
    /* Extract value */
    const char *vp = strstr(obj, "\"value\"");
    if (!vp || vp > ventry + 200) return REPAIR_RAWTX_OUTPUT_NO_VALUE;
    vp += 7;
    while (*vp == ' ' || *vp == ':') vp++;
    *value = (int64_t)(strtod(vp, NULL) * 100000000.0 + 0.5);

    /* Extract scriptPubKey hex */
    const char *sph = strstr(obj, "\"hex\"");
    if (!sph || sph > ventry + 2000) return REPAIR_RAWTX_OUTPUT_NO_HEX;
    sph += 5;
    if (!repair_parse_script_hex(sph, script, script_len, hex_bytes))
        return REPAIR_RAWTX_OUTPUT_SCRIPT_TOO_LARGE;
    return REPAIR_RAWTX_OUTPUT_OK;
}

/* Height + coinbase flags for a getrawtransaction result body. */
static void repair_rawtx_height_and_coinbase(const char *res, int *height,
                                             bool *coinbase)
{
    *height = 0;
    int64_t bh = repair_json_int(res, "height");
    if (bh > 0) *height = (int)bh;

    *coinbase = (strstr(res, "\"coinbase\"") != NULL &&
                 strstr(res, "\"vin\"") != NULL &&
                 strstr(strstr(res, "\"vin\""), "\"coinbase\"") != NULL);
}

/* Fetch via getrawtransaction (works for spent UTXOs if txindex=1) */
static bool fetch_utxo_rawtx(int port, const char *creds,
                               const char *txid_hex, uint32_t vout,
                               int64_t *value, uint8_t *script,
                               size_t *script_len, int *height,
                               bool *coinbase)
{
    char params[256];
    snprintf(params, sizeof(params), "[\"%s\", 1]", txid_hex);

    char *resp = zcl_malloc(1024 * 1024, "repair_rawtx_buf");
    if (!resp) LOG_FAIL("repair", "malloc failed for getrawtransaction response buffer");

    int rc = rpc_call_local(port, creds, "getrawtransaction", params,
                             resp, 1024 * 1024);
    if (rc <= 0) { free(resp); LOG_FAIL("repair", "getrawtransaction RPC failed for %s", txid_hex); }

    const char *body = rpc_http_body(resp);
    const char *res = strstr(body, "\"result\"");
    if (!res) { free(resp); LOG_FAIL("repair", "getrawtransaction missing \"result\" for %s", txid_hex); }
    res += 8;
    while (*res == ' ' || *res == ':') res++;
    if (*res == 'n') { free(resp); LOG_FAIL("repair", "getrawtransaction returned null for %s", txid_hex); }

    /* Find matching vout entry */
    const char *vout_arr = strstr(res, "\"vout\"");
    if (!vout_arr) { free(resp); LOG_FAIL("repair", "getrawtransaction missing \"vout\" array for %s", txid_hex); }

    const char *ventry = NULL;
    const char *obj = repair_rawtx_find_vout_obj(vout_arr, vout, &ventry);
    if (!obj) {
        free(resp);
        LOG_FAIL("repair",
                 "getrawtransaction vout %u not found for %s",
                 vout, txid_hex);
    }

    size_t hex_bytes = 0;
    enum repair_rawtx_output_status st = repair_rawtx_extract_output(
        obj, ventry, value, script, script_len, &hex_bytes);
    if (st == REPAIR_RAWTX_OUTPUT_NO_VALUE) {
        free(resp);
        LOG_FAIL("repair",
                 "getrawtransaction missing \"value\" for %s:%u",
                 txid_hex, vout);
    }
    if (st == REPAIR_RAWTX_OUTPUT_NO_HEX) {
        free(resp);
        LOG_FAIL("repair",
                 "getrawtransaction missing scriptPubKey hex for %s:%u",
                 txid_hex, vout);
    }
    if (st == REPAIR_RAWTX_OUTPUT_SCRIPT_TOO_LARGE) {
        free(resp);
        LOG_FAIL("repair",
                 "getrawtransaction script too large (%zu bytes) "
                 "for %s:%u",
                 hex_bytes, txid_hex, vout);
    }

    repair_rawtx_height_and_coinbase(res, height, coinbase);

    free(resp);
    return true;
}

/* Insert a repaired UTXO into coins cache + SQLite */
static void insert_repaired_utxo(const uint8_t txid_bytes[32], uint32_t vout,
                                  int64_t value, const uint8_t *script_data,
                                  size_t script_len, int height, bool is_coinbase)
{
    struct repair_context *ctx = repair_ctx();
    /* Insert into coins cache (for connect_block) */
    if (ctx->coins_tip) {
        struct uint256 ptxid;
        memcpy(ptxid.data, txid_bytes, 32);
        struct coins_cache_entry *entry =
            coins_view_cache_modify_new(ctx->coins_tip, &ptxid);
        if (entry) {
            if (entry->coins.num_vout <= vout) {
                size_t old_size = entry->coins.num_vout;
                size_t new_size = vout + 1;
                struct tx_out *nv = zcl_realloc(entry->coins.vout,
                    new_size * sizeof(struct tx_out), "repair_coin_vout");
                if (nv) {
                    for (size_t k = entry->coins.num_vout; k < new_size; k++)
                        tx_out_set_null(&nv[k]);
                    entry->coins.vout = nv;
                    entry->coins.num_vout = new_size;
                    coins_view_cache_account_vout_resize(
                        ctx->coins_tip, old_size, new_size);
                }
            }
            if (vout < entry->coins.num_vout) {
                entry->coins.vout[vout].value = value;
                script_init(&entry->coins.vout[vout].script_pub_key);
                script_set(&entry->coins.vout[vout].script_pub_key,
                           script_data, script_len);
            }
            if (entry->coins.height == 0) entry->coins.height = height;
            if (is_coinbase) entry->coins.is_coinbase = true;
            entry->flags |= COINS_CACHE_DIRTY;
        }
    }

    /* Insert into SQLite */
    uint8_t addr_hash[20];
    bool has_addr = false;
    enum script_type stype = utxo_classify_script(
        script_data, script_len, addr_hash, &has_addr);

    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid_bytes, 32);
    u.vout = vout;
    u.value = value;
    u.script = zcl_malloc(script_len, "repair_utxo_script");
    if (u.script) memcpy(u.script, script_data, script_len);
    u.script_len = script_len;
    u.script_type = stype;
    u.has_address = has_addr;
    if (has_addr) memcpy(u.address_hash, addr_hash, 20);
    u.height = height;
    u.is_coinbase = is_coinbase;
    db_utxo_save(ctx->node_db, &u);
    free(u.script);
}

/* ── RPC handler ───────────────────────────────────────────────── */

enum { REPAIRUTXOS_SCAN_ERROR_LEN = 160 };

/* Progress counters threaded through the scan, all reported in the
 * final JSON result and gating the activation-pause clear. */
struct repairutxos_counters {
    int blocks_scanned;
    int inputs_checked;
    int missing_found;
    int repaired_gettxout;
    int repaired_rawtx;
    int repair_failed;
};

enum repairutxos_vin_step {
    REPAIRUTXOS_VIN_DONE = 0,
    REPAIRUTXOS_VIN_SKIP = 1,
    REPAIRUTXOS_VIN_PREVOUT = 2
};

/* Readiness + argument validation, in the original first-error-wins
 * order. `*creds` points into the caller's params JSON tree, which
 * outlives this call. */
static bool repairutxos_validate_params(struct repair_context *ctx,
                                        const struct json_value *params,
                                        struct json_value *result,
                                        int *port, const char **creds,
                                        int *num_blocks)
{
    if (!ctx->main_state) {
        json_set_str(result, "Node not fully initialized");
        return false;
    }
    if (!ctx->node_db || !ctx->node_db->open) {
        json_set_str(result, "Database not available");
        return false;
    }
    if (ctx->coins_tip && !rpc_require_chainstate_lookup_ready(
            ctx->main_state, result, "repairutxos",
            "Chainstate lookup"))
        return false;

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 3);

    *port = (int)rpc_permit_int(&p, 0, "port",
                                ZCLASSICD_RPC_DEFAULT_PORT);
    /* Credentials are never invented here: absence is refused by name
     * below, not filled with a guessable development default. */
    *creds = rpc_permit_str(&p, 1, "creds", "");
    *num_blocks = (int)rpc_permit_int(&p, 2, "num_blocks",
                                      REPAIRUTXOS_DEFAULT_SCAN_BLOCKS);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }
    if (*port <= 0 || *port > 65535) {
        json_set_str(result, "port must be between 1 and 65535");
        return false;
    }
    if (!*creds || (*creds)[0] == '\0' ||
        strlen(*creds) > REPAIRUTXOS_MAX_CREDS_LEN) {
        json_set_str(result,
                     "creds must be a non-empty user:password string");
        return false;
    }
    if (*num_blocks <= 0 || *num_blocks > REPAIRUTXOS_MAX_SCAN_BLOCKS) {
        json_set_str(result,
                     "num_blocks must be between 1 and 50000");
        return false;
    }
    return true;
}

/* Clamp the requested scan window to zclassicd's own chain height. */
static bool repairutxos_compute_scan_range(int port, const char *creds,
                                           int tip_height, int num_blocks,
                                           int *scan_end,
                                           struct json_value *result)
{
    if (tip_height < 0 || tip_height > INT_MAX - num_blocks) {
        json_set_str(result, "active tip height is invalid for repair scan");
        return false;
    }
    *scan_end = tip_height + num_blocks;

    /* Get zclassicd's chain height as scan limit */
    char resp[4096];
    int rc = rpc_call_local(port, creds, "getblockcount", "[]",
                             resp, sizeof(resp));
    if (rc > 0) {
        const char *body = rpc_http_body(resp);
        const char *rp = strstr(body, "\"result\"");
        if (rp) {
            rp += 8;
            while (*rp == ' ' || *rp == ':') rp++;
            int remote_tip = (int)strtol(rp, NULL, 10);
            if (remote_tip > 0 && *scan_end > remote_tip)
                *scan_end = remote_tip;
        }
    } else {
        json_set_str(result, "Cannot connect to zclassicd — is it running?");
        return false;
    }
    return true;
}

/* getblockhash + getblock(2) for one height. Returns the block body, or
 * NULL with scan_error filled. Only the two RPC-call failures print,
 * exactly as before. */
static const char *repairutxos_fetch_block_body(
    int port, const char *creds, int h, char *blk_buf, size_t blk_buf_size,
    char scan_error[REPAIRUTXOS_SCAN_ERROR_LEN])
{
    /* getblockhash */
    char hash_params[64];
    snprintf(hash_params, sizeof(hash_params), "[%d]", h);
    char hash_resp[4096];
    int rc = rpc_call_local(port, creds, "getblockhash", hash_params,
                             hash_resp, sizeof(hash_resp));
    if (rc <= 0) {
        snprintf(scan_error, REPAIRUTXOS_SCAN_ERROR_LEN,
                 "getblockhash(%d) failed", h);
        printf("repairutxos: %s\n", scan_error);
        return NULL;
    }

    const char *hbody = rpc_http_body(hash_resp);
    const char *hr = strstr(hbody, "\"result\"");
    if (!hr) {
        snprintf(scan_error, REPAIRUTXOS_SCAN_ERROR_LEN,
                 "getblockhash(%d) missing result", h);
        return NULL;
    }
    hr += 8;
    while (*hr == ' ' || *hr == ':') hr++;
    if (*hr != '"') {
        snprintf(scan_error, REPAIRUTXOS_SCAN_ERROR_LEN,
                 "getblockhash(%d) result was not a string", h);
        return NULL;
    }
    hr++;
    char block_hash[65];
    size_t bhi = 0;
    while (*hr && *hr != '"' && bhi < 64) block_hash[bhi++] = *hr++;
    block_hash[bhi] = '\0';
    if (bhi != 64 || *hr != '"') {
        snprintf(scan_error, REPAIRUTXOS_SCAN_ERROR_LEN,
                 "getblockhash(%d) returned malformed hash", h);
        return NULL;
    }

    /* getblock hash 2 */
    char blk_params[256];
    snprintf(blk_params, sizeof(blk_params), "[\"%s\", 2]", block_hash);
    rc = rpc_call_local(port, creds, "getblock", blk_params,
                         blk_buf, blk_buf_size);
    if (rc <= 0) {
        snprintf(scan_error, REPAIRUTXOS_SCAN_ERROR_LEN,
                 "getblock(%d) failed", h);
        printf("repairutxos: %s\n", scan_error);
        return NULL;
    }

    return rpc_http_body(blk_buf);
}

/* Read the JSON string value of a "txid" key at `tid`. Returns the
 * resume pointer the original used for its `vp = tid` skips; `*quoted`
 * is false when the value was not a string. */
static const char *repairutxos_read_txid(const char *tid, char hex[65],
                                         size_t *len, bool *quoted)
{
    tid += 6;
    while (*tid == ' ' || *tid == ':') tid++;
    if (*tid != '"') { *quoted = false; *len = 0; return tid; }
    tid++;
    size_t ti2 = 0;
    while (*tid && *tid != '"' && ti2 < 64) hex[ti2++] = *tid++;
    hex[ti2] = '\0';
    *quoted = true;
    *len = ti2;
    return tid;
}

/* True when a "coinbase" key precedes this input's txid inside the
 * same vin array. */
static bool repairutxos_vin_is_coinbase(const char *vp, const char *arr_end,
                                        const char *tid)
{
    const char *cb = strstr(vp, "\"coinbase\"");
    return cb && (!arr_end || cb < arr_end) && cb < tid;
}

/* Advance one input inside a vin array. On SKIP/PREVOUT `*next_vp` is
 * the original's `vp = tid` resume point. */
static enum repairutxos_vin_step repairutxos_next_prevout(
    const char *vp, const char **next_vp, char prev_txid_hex[65],
    uint32_t *prev_vout)
{
    const char *tid = strstr(vp, "\"txid\"");
    if (!tid) return REPAIRUTXOS_VIN_DONE;
    const char *arr_end = strchr(vp, ']');
    if (arr_end && tid > arr_end) return REPAIRUTXOS_VIN_DONE;

    /* Extract prevout txid */
    size_t ti2 = 0;
    bool quoted = false;
    tid = repairutxos_read_txid(tid, prev_txid_hex, &ti2, &quoted);
    *next_vp = tid;
    if (!quoted) return REPAIRUTXOS_VIN_SKIP;

    /* Extract prevout vout */
    const char *vn = strstr(tid, "\"vout\"");
    if (!vn || (arr_end && vn > arr_end)) return REPAIRUTXOS_VIN_SKIP;
    vn += 6;
    while (*vn == ' ' || *vn == ':') vn++;
    *prev_vout = (uint32_t)strtoul(vn, NULL, 10);

    /* Skip coinbase inputs (ti2==0) and reject malformed
     * txids whose length != 64 hex chars — a short txid
     * would otherwise feed uninitialized stack bytes into
     * the hex->byte loop below (prev_txid_hex[bi*2] past
     * the '\0'). Defensive only: valid 64-char txids are
     * unaffected. */
    if (ti2 == 0 || ti2 != 64) return REPAIRUTXOS_VIN_SKIP;
    if (repairutxos_vin_is_coinbase(vp, arr_end, tid))
        return REPAIRUTXOS_VIN_SKIP;
    return REPAIRUTXOS_VIN_PREVOUT;
}

/* Coins cache first, then SQLite — the original's lookup order. */
static bool repairutxos_prevout_exists(struct repair_context *ctx,
                                       const uint8_t prev_txid_bytes[32],
                                       uint32_t prev_vout)
{
    /* Check coins cache */
    bool exists = false;
    if (ctx->coins_tip) {
        struct uint256 ptxid;
        memcpy(ptxid.data, prev_txid_bytes, 32);
        struct coins c;
        coins_init(&c);
        bool have = coins_view_cache_get_coins(
            ctx->coins_tip, &ptxid, &c);
        if (have && prev_vout < c.num_vout &&
            !tx_out_is_null(&c.vout[prev_vout]))
            exists = true;
        coins_free(&c);
    }
    /* Check SQLite */
    if (!exists)
        exists = db_utxo_exists(ctx->node_db,
            prev_txid_bytes, prev_vout);
    return exists;
}

/* Missing! Fetch from zclassicd. insert_repaired_utxo keeps writing
 * through ctx->coins_tip and db_utxo_save directly, outside the caller's
 * node_db transaction, exactly as before. */
static void repairutxos_repair_missing_utxo(
    int port, const char *creds, const char *prev_txid_hex,
    const uint8_t prev_txid_bytes[32], uint32_t prev_vout, int h,
    struct repairutxos_counters *cnt)
{
    cnt->missing_found++;
    if (cnt->missing_found <= 20 || cnt->missing_found % 100 == 0)
        printf("repairutxos: missing %s:%u (block %d)\n",
               prev_txid_hex, prev_vout, h);

    int64_t value = 0;
    uint8_t script[10001];
    size_t script_len = 0;
    int utxo_height = 0;
    bool is_coinbase = false;

    bool fetched = fetch_utxo_gettxout(
        port, creds, prev_txid_hex, prev_vout,
        &value, script, &script_len, &utxo_height, &is_coinbase);

    if (!fetched) {
        fetched = fetch_utxo_rawtx(
            port, creds, prev_txid_hex, prev_vout,
            &value, script, &script_len, &utxo_height,
            &is_coinbase);
        if (fetched) cnt->repaired_rawtx++;
    } else {
        cnt->repaired_gettxout++;
    }

    if (!fetched) {
        cnt->repair_failed++;
        printf("repairutxos: FAILED to fetch %s:%u\n",
               prev_txid_hex, prev_vout);
        return;
    }

    insert_repaired_utxo(prev_txid_bytes, prev_vout, value,
                          script, script_len, utxo_height,
                          is_coinbase);
}

/* Parse vin arrays for prevout references */
static void repairutxos_scan_block_vins(const char *bbody,
                                        struct repair_context *ctx,
                                        int port, const char *creds, int h,
                                        struct repairutxos_counters *cnt)
{
    const char *tx_start = bbody;
    while ((tx_start = strstr(tx_start, "\"vin\"")) != NULL) {
        const char *arr = strchr(tx_start, '[');
        if (!arr) break;
        tx_start = arr + 1;

        const char *vp = tx_start;
        while (*vp) {
            char prev_txid_hex[65];
            uint32_t prev_vout = 0;
            const char *next_vp = vp;
            enum repairutxos_vin_step step = repairutxos_next_prevout(
                vp, &next_vp, prev_txid_hex, &prev_vout);
            if (step == REPAIRUTXOS_VIN_DONE) break;
            vp = next_vp;
            if (step == REPAIRUTXOS_VIN_SKIP) continue;

            cnt->inputs_checked++;

            /* Convert hex txid to internal byte order (reversed) */
            uint8_t prev_txid_bytes[32];
            for (int bi = 0; bi < 32; bi++) {
                char hx[3] = { prev_txid_hex[bi*2],
                               prev_txid_hex[bi*2+1], '\0' };
                prev_txid_bytes[31 - bi] = (uint8_t)strtoul(hx, NULL, 16);
            }

            if (repairutxos_prevout_exists(ctx, prev_txid_bytes, prev_vout))
                continue;

            repairutxos_repair_missing_utxo(port, creds, prev_txid_hex,
                                            prev_txid_bytes, prev_vout, h,
                                            cnt);
        }
    }
}

/* Final console summary + JSON result, in the original field order. */
static void repairutxos_report_result(
    struct json_value *result, const struct repairutxos_counters *cnt,
    bool scan_complete, const char *scan_error, int tip_height,
    int scan_end, int64_t elapsed)
{
    printf("repairutxos: done in %llds — %d blocks, %d inputs, "
           "%d missing, %d repaired (%d gettxout, %d rawtx), %d failed, "
           "complete=%s\n",
           (long long)elapsed, cnt->blocks_scanned, cnt->inputs_checked,
           cnt->missing_found, cnt->repaired_gettxout + cnt->repaired_rawtx,
           cnt->repaired_gettxout, cnt->repaired_rawtx, cnt->repair_failed,
           scan_complete ? "true" : "false");
    fflush(stdout);

    json_set_object(result);
    json_push_kv_int(result, "blocks_scanned", cnt->blocks_scanned);
    json_push_kv_int(result, "inputs_checked", cnt->inputs_checked);
    json_push_kv_int(result, "missing_found", cnt->missing_found);
    json_push_kv_int(result, "repaired_gettxout", cnt->repaired_gettxout);
    json_push_kv_int(result, "repaired_rawtx", cnt->repaired_rawtx);
    json_push_kv_int(result, "repair_failed", cnt->repair_failed);
    json_push_kv_bool(result, "scan_complete", scan_complete);
    if (!scan_complete)
        json_push_kv_str(result, "scan_error", scan_error);
    json_push_kv_int(result, "scan_start", tip_height + 1);
    json_push_kv_int(result, "scan_end", scan_end);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
}

bool rpc_repairutxos(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct repair_context *ctx = repair_ctx();
    RPC_HELP(help, result,
        "repairutxos ( zclassicd_port zclassicd_creds num_blocks )\n"
        "\nScans forward through blocks on zclassicd, finds inputs whose\n"
        "UTXOs are missing locally, and fetches them via RPC.\n"
        "\nArguments:\n"
        "1. zclassicd_port   (number, optional, default=8232)\n"
        "2. zclassicd_creds  (string, required — the node's\n"
        "                    rpcuser:rpcpassword from zclassic.conf or its\n"
        "                    .cookie; never a built-in pair)\n"
        "3. num_blocks       (number, optional, default=10000, max=50000)\n"
        "\nRequires zclassicd running on localhost with RPC enabled.\n"
        "For spent UTXOs, zclassicd needs txindex=1.\n");

    int port = 0;
    const char *creds = NULL;
    int num_blocks = 0;
    if (!repairutxos_validate_params(ctx, params, result, &port, &creds,
                                     &num_blocks))
        return false;

    int tip_height = active_chain_height(&ctx->main_state->chain_active);
    int scan_end = 0;
    if (!repairutxos_compute_scan_range(port, creds, tip_height, num_blocks,
                                        &scan_end, result))
        return false;

    printf("repairutxos: scanning blocks %d -> %d (%d blocks)\n",
           tip_height + 1, scan_end, scan_end - tip_height);
    printf("repairutxos: using zclassicd on port %d "
           "(max_scan=%d, current_tip=%d)\n",
           port, REPAIRUTXOS_MAX_SCAN_BLOCKS, tip_height);
    fflush(stdout);

    int64_t t_start = (int64_t)platform_time_wall_time_t();
    struct repairutxos_counters cnt = {0};

    /* Repaired UTXOs persist through db_utxo_save(); coins_tip is only the
     * current-process read cache and must not flush to the projection. */
    if (!node_db_begin(ctx->node_db)) {
        LOG_WARN("repairutxos",
                 "repairutxos: database BEGIN failed");
        json_set_str(result,
                     "Database transaction begin failed");
        /* node_db_begin already logged database context. */
        return false;
    }

    size_t blk_buf_size = 4 * 1024 * 1024;
    char *blk_buf = zcl_malloc(blk_buf_size, "repair_blk_buf");
    if (!blk_buf) {
        node_db_rollback(ctx->node_db);
        json_set_str(result, "Out of memory");
        return false;
    }

    bool scan_complete = true;
    char scan_error[REPAIRUTXOS_SCAN_ERROR_LEN] = {0};
    for (int h = tip_height + 1; h <= scan_end; h++) {
        const char *bbody = repairutxos_fetch_block_body(
            port, creds, h, blk_buf, blk_buf_size, scan_error);
        if (!bbody) {
            scan_complete = false;
            break;
        }

        repairutxos_scan_block_vins(bbody, ctx, port, creds, h, &cnt);

        cnt.blocks_scanned++;
        if (cnt.blocks_scanned % 100 == 0) {
            printf("repairutxos: scanned %d/%d blocks, %d missing, %d repaired\n",
                   cnt.blocks_scanned, scan_end - tip_height,
                   cnt.missing_found,
                   cnt.repaired_gettxout + cnt.repaired_rawtx);
            fflush(stdout);
        }
    }

    free(blk_buf);
    if (!node_db_commit(ctx->node_db)) {
        LOG_WARN("repairutxos",
                 "repairutxos: database COMMIT failed");
        json_set_str(result,
                     "Database transaction commit failed");
        /* node_db_commit already logged database context. */
        return false;
    }

    if (scan_complete && cnt.repair_failed == 0 &&
        (cnt.repaired_gettxout + cnt.repaired_rawtx) > 0)
        process_block_clear_utxo_activation_pause_range(tip_height + 1,
                                                        scan_end);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;

    repairutxos_report_result(result, &cnt, scan_complete, scan_error,
                              tip_height, scan_end, elapsed);
    return true;
}

/* ── repairheights: fix height=0 UTXOs from transaction index ──── */
