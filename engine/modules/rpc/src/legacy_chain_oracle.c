/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "rpc/legacy_chain_oracle.h"

#include "chain/mmb.h"
#include "chain/mmr.h"                  /* MMR_COMMITMENT_INTERVAL boundary */
#include "core/uint256.h"
#include "json/json.h"
#include "rpc/legacy_rpc_client.h"
#include "storage/coins_kv.h"           /* boundary utxo_root read */
#include "storage/progress_store.h"     /* progress_store_db() handle */
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool lco_rpc_result_obj(const char *raw, struct json_value *root,
                               const struct json_value **result)
{
    const char *body = legacy_rpc_http_body(raw);

    if (!body || !root || !result)
        return false;
    json_init(root);
    if (!json_read(root, body, strlen(body))) {
        json_free(root);
        return false;
    }
    *result = json_get(root, "result");
    return *result && (*result)->type == JSON_OBJ;
}

bool legacy_chain_rpc_get_block_hash_hex(int height, char out_hex[65])
{
    char err[256];
    char req[256];
    char *resp = NULL;
    bool ok;

    if (!out_hex || height < 0)
        return false;
    out_hex[0] = '\0';

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl23-chain\","
             "\"method\":\"getblockhash\",\"params\":[%d]}", height);
    if (!legacy_rpc_authenticated_call(req, &resp, err, sizeof(err)))
        return false;

    ok = legacy_rpc_parse_result_string(resp, out_hex, 65, err, sizeof(err)) && strlen(out_hex) == 64;
    free(resp);
    return ok;
}

bool legacy_chain_rpc_get_mmb_leaf(int height, struct mmb_leaf *leaf)
{
    char err[256];
    char req[512], hash_hex[65];
    char *resp = NULL;
    bool ok;

    if (!leaf || height < 0)
        return false;
    if (!legacy_chain_rpc_get_block_hash_hex(height, hash_hex))
        return false;

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl23-chain\","
             "\"method\":\"getblockheader\",\"params\":[\"%s\",true]}",
             hash_hex);
    if (!legacy_rpc_authenticated_call(req, &resp, err, sizeof(err)))
        return false;

    struct json_value root = {0};
    const struct json_value *obj = NULL;
    ok = lco_rpc_result_obj(resp, &root, &obj);
    if (ok) {
        const struct json_value *jh = json_get(obj, "hash");
        const struct json_value *jheight = json_get(obj, "height");
        const struct json_value *jtime = json_get(obj, "time");
        const struct json_value *jbits = json_get(obj, "bits");
        const struct json_value *jsapling = json_get(obj, "finalsaplingroot");
        const struct json_value *jchainwork = json_get(obj, "chainwork");
        struct uint256 bh = {0}, sapling = {0}, chainwork = {0};

        if (!jh || jh->type != JSON_STR ||
            !jheight || jheight->type != JSON_INT ||
            !jtime || jtime->type != JSON_INT ||
            !jbits || jbits->type != JSON_STR ||
            !jchainwork || jchainwork->type != JSON_STR) {
            ok = false;
        } else {
            uint256_set_hex(&bh, json_get_str(jh));
            if (jsapling && jsapling->type == JSON_STR)
                uint256_set_hex(&sapling, json_get_str(jsapling));
            uint256_set_hex(&chainwork, json_get_str(jchainwork));
            /* zclassicd does not carry the MMB utxo_root (it never speaks the
             * MMB). At a boundary height, reconstruct the same leaf hash the
             * live path produced by reading the persisted boundary root;
             * otherwise the zero sentinel. */
            int32_t bheight = (int32_t)json_get_int(jheight);
            uint8_t utxo_root[32] = {0};
            if (bheight > 0 && bheight % MMR_COMMITMENT_INTERVAL == 0) {
                sqlite3 *pdb = progress_store_db();
                bool found = false;
                if (pdb)
                    coins_kv_boundary_root_get(pdb, bheight, utxo_root, &found);
                if (!found) memset(utxo_root, 0, 32);
            }
            mmb_leaf_from_block(leaf, bh.data,
                                (uint32_t)bheight,
                                (uint32_t)json_get_int(jtime),
                                (uint32_t)strtoul(json_get_str(jbits), NULL, 16),
                                sapling.data, chainwork.data, utxo_root);
        }
    }
    json_free(&root);
    free(resp);
    return ok;
}

bool legacy_chain_rpc_get_chainwork(const uint8_t block_hash[32],
                                    uint8_t chain_work[32])
{
    struct uint256 hash = {0};
    struct uint256 work = {0};
    char err[256];
    char req[512], hash_hex[65];
    char *resp = NULL;
    bool ok;

    if (!block_hash || !chain_work)
        return false;

    memcpy(hash.data, block_hash, 32);
    uint256_get_hex(&hash, hash_hex);
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl23-chain\","
             "\"method\":\"getblockheader\",\"params\":[\"%s\",true]}",
             hash_hex);
    if (!legacy_rpc_authenticated_call(req, &resp, err, sizeof(err)))
        return false;

    struct json_value root = {0};
    const struct json_value *obj = NULL;
    ok = lco_rpc_result_obj(resp, &root, &obj);
    if (ok) {
        const struct json_value *jchainwork = json_get(obj, "chainwork");
        if (!jchainwork || jchainwork->type != JSON_STR) {
            ok = false;
        } else {
            uint256_set_hex(&work, json_get_str(jchainwork));
            memcpy(chain_work, work.data, 32);
        }
    }
    json_free(&root);
    free(resp);
    return ok && !zcl_chainwork_is_zero(chain_work);
}

bool legacy_chain_rpc_get_block_count(int *out_height)
{
    char err[256];
    char req[256];
    char *resp = NULL;
    int64_t h = 0;
    bool ok;

    if (!out_height)
        return false;
    *out_height = 0;

    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl23-chain\","
             "\"method\":\"getblockcount\",\"params\":[]}");
    if (!legacy_rpc_authenticated_call(req, &resp, err, sizeof(err)))
        return false;

    ok = legacy_rpc_parse_result_int(resp, &h, err, sizeof(err)) &&
         h >= 0 && h <= INT32_MAX;
    free(resp);
    if (ok)
        *out_height = (int)h;
    return ok;
}

bool legacy_chain_rpc_get_block_hex(int height, char *out_hex,
                                    size_t out_hex_sz)
{
    char err[256];
    char req[256], hash_hex[65];
    char *resp = NULL;
    bool ok;

    if (!out_hex || out_hex_sz == 0 || height < 0)
        return false;
    out_hex[0] = '\0';
    if (!legacy_chain_rpc_get_block_hash_hex(height, hash_hex))
        return false;

    /* verbose=0 → result is the serialized block as a hex string. */
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"1.0\",\"id\":\"zcl23-chain\","
             "\"method\":\"getblock\",\"params\":[\"%s\",0]}", hash_hex);
    if (!legacy_rpc_authenticated_call(req, &resp, err, sizeof(err)))
        return false;

    ok = legacy_rpc_parse_result_string(resp, out_hex, out_hex_sz,
                                        err, sizeof(err));
    /* A valid block hex is non-empty and even-length. */
    if (ok) {
        size_t n = strlen(out_hex);
        ok = (n > 0) && (n % 2 == 0);
    }
    free(resp);
    return ok;
}
