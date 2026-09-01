/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/transaction_controller_internal.h"
#include "models/tx_index.h"
#include "services/txindex_projection_service.h"

struct rawtx_context g_rawtx_ctx = {0};

void rpc_rawtx_set_state(struct main_state *ms, struct tx_mempool *mp,
                          struct coins_view_cache *coins_tip,
                          const char *datadir)
{
    struct rawtx_context *ctx = rawtx_ctx();
    ctx->main_state = ms;
    ctx->mempool = mp;
    ctx->coins_tip = coins_tip;
    if (datadir && datadir[0]) {
        (void)snprintf(ctx->datadir_storage, sizeof(ctx->datadir_storage),
                       "%s", datadir);
        ctx->datadir = ctx->datadir_storage;
    } else {
        ctx->datadir_storage[0] = '\0';
        ctx->datadir = NULL;
    }
}

void rpc_rawtx_set_keystore(struct basic_keystore *ks)
{
    rawtx_ctx()->keystore = ks;
}

void rpc_rawtx_set_connman(struct connman *cm)
{
    rawtx_ctx()->connman = cm;
}

/* The canonical node database already records every transaction's active-
 * chain height and index while a block is finalized.  Treat that row only as
 * a locator: the block hash, body position, and transaction hash are all
 * checked against the active chain before bytes are returned.  This makes a
 * confirmed shielded-only transaction findable even when the optional legacy
 * txindex is disabled and no transparent coin exists to locate it. */
static bool rawtx_find_in_node_db(struct rawtx_context *ctx,
                                  const struct uint256 *hash,
                                  struct transaction *tx,
                                  struct uint256 *hash_block)
{
    struct node_db *ndb = rawtx_node_db();
    struct db_tx_index row;
    if (!ctx || !hash || !tx || !hash_block || !ctx->main_state ||
        !ctx->datadir || !ndb || !ndb->open ||
        !db_tx_find(ndb, hash->data, &row))
        return false;

    if (row.block_height < 0 || row.tx_index < 0) {
        LOG_WARN("rawtx", "node-db locator rejected negative position "
                 "(height=%d tx_index=%d)", row.block_height, row.tx_index);
        return false;
    }

    struct block_index *bi = active_chain_at(
        &ctx->main_state->chain_active, row.block_height);
    if (!bi || !bi->phashBlock ||
        memcmp(row.block_hash, bi->phashBlock->data,
               sizeof(row.block_hash)) != 0) {
        LOG_WARN("rawtx", "node-db locator is not on the active chain "
                 "(height=%d tx_index=%d)", row.block_height, row.tx_index);
        return false;
    }

    struct block blk;
    block_init(&blk);
    bool found = false;
    if (read_block_from_disk_index(&blk, bi, ctx->datadir) &&
        (size_t)row.tx_index < blk.num_vtx &&
        uint256_cmp(&blk.vtx[row.tx_index].hash, hash) == 0) {
        struct uint256 body_hash;
        block_header_get_hash(&blk.header, &body_hash);
        if (uint256_cmp(&body_hash, bi->phashBlock) == 0) {
            transaction_free(tx);
            transaction_init(tx);
            transaction_copy(tx, &blk.vtx[row.tx_index]);
            *hash_block = body_hash;
            found = true;
        } else {
            LOG_WARN("rawtx", "node-db locator body hash mismatch "
                     "(height=%d tx_index=%d)", row.block_height,
                     row.tx_index);
        }
    }
    block_free(&blk);
    return found;
}

static bool rpc_getrawtransaction(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    struct rawtx_context *ctx = rawtx_ctx();
    RPC_HELP(help, result,
        "getrawtransaction \"txid\" ( verbose )\n"
        "Return the raw transaction data.\n"
        "Arguments:\n"
        "1. \"txid\"    (string, required) The transaction id\n"
        "2. verbose   (numeric, optional, default=0) "
        "If 0, return hex; if 1, return JSON object");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *txid_str = rpc_require_str(&p, 0, "txid");
    int verbose = (int)rpc_permit_int(&p, 1, "verbose", 0);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct uint256 hash;
    if (!parse_hash_str(txid_str, &hash)) {
        json_set_str(result, "Invalid txid format");
        return false;
    }

    struct transaction tx;
    transaction_init(&tx);
    struct uint256 hash_block;
    uint256_set_null(&hash_block);
    bool found = false;

    /* 1. Check mempool */
    if (ctx->mempool && tx_mempool_lookup(ctx->mempool, &hash, &tx)) {
        found = true;
    }

    /* 1a. The canonical finalized-block projection is the normal confirmed
     * lookup path.  The independent indexes below remain useful fallbacks,
     * but a snapshot-seeded node need not rebuild from genesis before it can
     * answer for a transaction already present in its verified chain. */
    if (!found)
        found = rawtx_find_in_node_db(ctx, &hash, &tx, &hash_block);

    /* Wallet-owned transactions are projected synchronously from the exact
     * finalized body before the global transaction index is guaranteed to
     * catch up. */
    if (!found)
        found = rawtx_find_in_wallet_db(ctx, &hash, &tx, &hash_block);

    if (!found)
        found = rawtx_find_by_wallet_note(ctx, &hash, &tx, &hash_block);

    if (!found)
        found = rawtx_find_in_wallet(ctx, &hash, &tx, &hash_block);

    /* 1b. Check the txindex projection when present (first-class, integrity-
     * tagged). A hit locates (height, tx_n) directly; a behind/absent/busy
     * result never asserts "not found" here — it falls through to the paths
     * below, so a lagging projection is never silently wrong. */
    if (!found && ctx->main_state && ctx->datadir) {
        int64_t pi_height = -1, pi_tx_n = -1, pi_cursor = -1;
        uint8_t pi_block_hash[32];
        enum txindex_read_status pst = txindex_projection_read_locate(
            hash.data, &pi_height, pi_block_hash, &pi_tx_n, &pi_cursor);
        if (pst == TXINDEX_READ_FOUND && pi_height >= 0 && pi_tx_n >= 0) {
            struct block_index *bi = active_chain_at(
                &ctx->main_state->chain_active, (int)pi_height);
            if (bi) {
                struct block blk;
                block_init(&blk);
                if (read_block_from_disk_index(&blk, bi, ctx->datadir) &&
                    (size_t)pi_tx_n < blk.num_vtx &&
                    uint256_cmp(&blk.vtx[pi_tx_n].hash, &hash) == 0) {
                    transaction_free(&tx);
                    transaction_init(&tx);
                    transaction_copy(&tx, &blk.vtx[pi_tx_n]);
                    block_header_get_hash(&blk.header, &hash_block);
                    found = true;
                }
                block_free(&blk);
            }
        }
    }

    /* 2. Check txindex for O(1) disk lookup */
    extern struct block_tree_db *g_active_block_tree;
    if (!found && g_active_block_tree && ctx->main_state &&
        ctx->main_state->fTxIndex) {
        struct disk_tx_pos pos;
        if (block_tree_db_read_tx_index(g_active_block_tree, &hash, &pos)) {
            /* pread-based reads: no shared FILE* cache, no lock, and no
             * silently-unchecked fseek — each read names its absolute
             * position. */
            unsigned char hdr_buf[256];
            ssize_t hdr_read = disk_block_pread(ctx->datadir, &pos.block_pos,
                                                "blk", hdr_buf,
                                                sizeof(hdr_buf));
            if (hdr_read > 0) {
                struct byte_stream hs;
                stream_init_from_data(&hs, hdr_buf, (size_t)hdr_read);
                struct block_header bh;
                block_header_deserialize(&bh, &hs);
                block_header_get_hash(&bh, &hash_block);
            }
            struct disk_block_pos tx_pos = pos.block_pos;
            if (pos.nTxOffset <= UINT32_MAX - tx_pos.nPos) {
                tx_pos.nPos += pos.nTxOffset;
                const size_t tx_cap = 2 * 1024 * 1024;
                unsigned char *tx_buf = zcl_malloc(tx_cap, "rawtx disk read");
                if (tx_buf) {
                    ssize_t tx_read = disk_block_pread(ctx->datadir, &tx_pos,
                                                       "blk", tx_buf, tx_cap);
                    if (tx_read > 0) {
                        struct byte_stream ts;
                        stream_init_from_data(&ts, tx_buf, (size_t)tx_read);
                        transaction_free(&tx);
                        transaction_init(&tx);
                        if (transaction_deserialize(&tx, &ts))
                            found = true;
                    }
                    free(tx_buf);
                }
            } else {
                LOG_WARN("rawtx", "txindex offset overflow (nPos=%u nTxOffset=%u)",
                         pos.block_pos.nPos, pos.nTxOffset);
            }
        }
    }

    /* Index projections are derived and can briefly lag the authoritative
     * reducer. Keep newly confirmed transactions queryable during that gap. */
    if (!found)
        found = rawtx_find_in_recent_chain(ctx, &hash, &tx, &hash_block);

    /* 3. Fallback: use coins DB to find block, then scan block */
    if (!found && ctx->coins_tip && ctx->main_state && ctx->datadir) {
        if (!rpc_require_chainstate_lookup_ready(ctx->main_state, result,
                "getrawtransaction", "Chainstate lookup"))
            return false;
        struct coins entry;
        coins_init(&entry);
        if (coins_view_cache_get_coins(ctx->coins_tip, &hash, &entry)) {
            if (entry.height > 0) {
                struct block_index *bi = active_chain_at(
                    &ctx->main_state->chain_active, entry.height);
                if (bi) {
                    struct block blk;
                    block_init(&blk);
                    if (read_block_from_disk_index(&blk, bi, ctx->datadir)) {
                        for (size_t i = 0; i < blk.num_vtx; i++) {
                            if (uint256_cmp(&blk.vtx[i].hash, &hash) == 0) {
                                transaction_free(&tx);
                                transaction_init(&tx);
                                transaction_copy(&tx, &blk.vtx[i]);
                                block_header_get_hash(&blk.header,
                                                      &hash_block);
                                found = true;
                                break;
                            }
                        }
                    }
                    block_free(&blk);
                }
            }
            coins_free(&entry);
        }
    }

    if (!found) {
        transaction_free(&tx);
        json_set_str(result, "Transaction not found");
        return false;
    }

    if (verbose == 0) {
        char *hex = zcl_malloc(2 * 1024 * 1024, "tx_hex_buf");
        if (!hex) {
            transaction_free(&tx);
            json_set_str(result, "Out of memory");
            LOG_FAIL("tx", "getrawtransaction: malloc failed for hex buffer");
            return false;
        }
        size_t hex_len = encode_hex_tx(&tx, hex, 2 * 1024 * 1024);
        hex[hex_len] = '\0';
        json_set_str(result, hex);
        free(hex);
    } else {
        tx_to_json(&tx, &hash_block, result);
        json_push_kv_int(result, "confirmations",
                         rawtx_confirmations(ctx, &hash_block));
    }

    transaction_free(&tx);
    return true;
}

static bool rpc_decoderawtransaction(const struct json_value *params, bool help,
                                      struct json_value *result)
{
    RPC_HELP(help, result,
        "decoderawtransaction \"hexstring\"\n"
        "Return a JSON object representing the serialized transaction.\n"
        "Arguments:\n"
        "1. \"hexstring\" (string, required) The transaction hex string");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *hex_str = rpc_require_str(&p, 0, "hexstring");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct transaction tx;
    transaction_init(&tx);
    if (!decode_hex_tx(&tx, hex_str)) {
        transaction_free(&tx);
        json_set_str(result, "TX decode failed");
        return false;
    }

    struct uint256 null_hash;
    uint256_set_null(&null_hash);
    tx_to_json(&tx, &null_hash, result);
    transaction_free(&tx);
    return true;
}

static bool rpc_sendrawtransaction(const struct json_value *params, bool help,
                                    struct json_value *result)
{
    struct rawtx_context *ctx = rawtx_ctx();
    RPC_HELP(help, result,
        "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
        "Submits raw transaction to local node and network.\n"
        "Arguments:\n"
        "1. \"hexstring\" (string, required) The hex string of the raw tx\n"
        "2. allowhighfees (boolean, optional, default=false)");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 2);
    const char *hex_str = rpc_require_str(&p, 0, "hexstring");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct transaction tx;
    transaction_init(&tx);
    if (!decode_hex_tx(&tx, hex_str)) {
        transaction_free(&tx);
        json_set_str(result, "TX decode failed");
        return false;
    }

    transaction_compute_hash(&tx);
    struct uint256 hash = tx.hash;

    if (ctx->mempool && tx_mempool_exists(ctx->mempool, &hash)) {
        /* Already in mempool — re-relay to peers */
        if (ctx->connman)
            connman_relay_transaction(ctx->connman, &hash);
        char hex[65];
        uint256_get_hex(&hash, hex);
        json_set_str(result, hex);
        transaction_free(&tx);
        return true;
    }

    /* Full mempool-acceptance gate (structural + shielded-proof +
     * per-input scriptSig verification + inputs-exist + fee policy)
     * via the ONE shared helper that the P2P `tx` path also uses. This
     * is what stops sendrawtransaction from relaying a tx with a bad
     * signature, a forged shielded proof, or missing inputs. */
    if (ctx->mempool) {
        enum mempool_accept_result r = accept_to_mempool(
            ctx->mempool, ctx->coins_tip, ctx->main_state,
            chain_params_get(), &tx);

        if (r != MEMPOOL_ACCEPT_OK) {
            const char *msg;
            switch (r) {
            case MEMPOOL_ACCEPT_INVALID:
                msg = "TX rejected: failed verification "
                      "(bad signature, proof, or structure)"; break;
            case MEMPOOL_ACCEPT_DUPLICATE:
                msg = "TX already in mempool"; break;
            case MEMPOOL_ACCEPT_CONFLICT:
                msg = "TX rejected: conflicts with mempool (double-spend)";
                break;
            case MEMPOOL_ACCEPT_BELOW_FEE:
                msg = "TX rejected: insufficient fee"; break;
            case MEMPOOL_ACCEPT_MISSING_INPUTS:
                msg = "TX rejected: inputs missing or already spent"; break;
            case MEMPOOL_ACCEPT_NONFINAL:
                msg = "TX rejected: non-final lock time"; break;
            case MEMPOOL_ACCEPT_EXPIRING_SOON:
                msg = "TX rejected: expiry height is too close"; break;
            case MEMPOOL_ACCEPT_UNVERIFIABLE:
                /* Say what actually happened. Reporting this as "bad
                 * signature, proof, or structure" would send an operator
                 * hunting a defect in a transaction that is probably fine. */
                msg = "TX not accepted: shielded proof verification is "
                      "unavailable right now (verifying keys still loading). "
                      "The transaction was not judged invalid — retry shortly";
                break;
            default:
                msg = "TX rejected: failed to add to mempool"; break;
            }
            json_set_str(result, msg);
            transaction_free(&tx);
            return false;
        }
    }

    /* Relay to peers (only after the gate above accepted it). */
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &hash);

    char hex[65];
    uint256_get_hex(&hash, hex);
    json_set_str(result, hex);
    transaction_free(&tx);
    return true;
}

static bool rpc_createrawtransaction(const struct json_value *params, bool help,
                                      struct json_value *result)
{
    struct rawtx_context *ctx = rawtx_ctx();
    RPC_HELP(help, result,
        "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] "
        "{\"address\":amount,...} ( \"op_return_hex\" )\n"
        "Create a transaction spending the given inputs.\n"
        "Arguments:\n"
        "1. \"inputs\"  (array, required) JSON array of inputs\n"
        "2. \"outputs\" (object, required) JSON object of outputs\n"
        "3. \"op_return_hex\" (string, optional) exact standard-relay "
        "OP_RETURN script");

    if (json_size(params) < 2) {
        json_set_str(result, "Missing required parameters: inputs and outputs");
        return false;
    }
    if (json_size(params) > 3) {
        json_set_str(result, "Too many parameters (maximum 3)");
        return false;
    }

    const struct json_value *inputs = json_at(params, 0);
    const struct json_value *outputs = json_at(params, 1);

    if (!inputs || inputs->type != JSON_ARR ||
        !outputs || outputs->type != JSON_OBJ) {
        json_set_str(result, "Invalid parameters");
        return false;
    }

    struct transaction tx;
    transaction_init(&tx);

    int tip_height = ctx->main_state ?
        active_chain_height(&ctx->main_state->chain_active) : 0;
    const struct consensus_params *cp = &chain_params_get()->consensus;
    int epoch = consensus_current_epoch(tip_height + 1, cp);

    if (epoch >= (int)UPGRADE_SAPLING) {
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = (uint32_t)(tip_height + 500);
    } else if (epoch >= (int)UPGRADE_OVERWINTER) {
        tx.overwintered = true;
        tx.version = OVERWINTER_TX_VERSION;
        tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        tx.expiry_height = (uint32_t)(tip_height + 500);
    } else {
        tx.version = 1;
    }

    for (size_t i = 0; i < json_size(inputs); i++) {
        const struct json_value *inp = json_at(inputs, i);
        if (!inp || inp->type != JSON_OBJ) continue;

        const struct json_value *txid_v = json_get(inp, "txid");
        const struct json_value *vout_v = json_get(inp, "vout");
        if (!txid_v || !vout_v) continue;

        struct tx_in vin;
        tx_in_init(&vin);
        if (!parse_hash_str(json_get_str(txid_v), &vin.prevout.hash)) {
            transaction_free(&tx);
            json_set_str(result, "Invalid txid format in inputs");
            LOG_FAIL("tx", "createrawtransaction: invalid txid at input %zu", i);
        }
        vin.prevout.n = (uint32_t)json_get_int(vout_v);

        const struct json_value *seq_v = json_get(inp, "sequence");
        if (seq_v) vin.sequence = (uint32_t)json_get_int(seq_v);

        size_t new_count = tx.num_vin + 1;
        struct tx_in *new_vin = zcl_realloc(tx.vin, new_count * sizeof(struct tx_in), "tx_vin");
        if (!new_vin) { transaction_free(&tx); json_set_str(result, "Out of memory"); LOG_FAIL("tx", "createrawtransaction: realloc vin failed at input %zu", i); }
        tx.vin = new_vin;
        tx.vin[tx.num_vin] = vin;
        tx.num_vin = new_count;
    }

    for (size_t i = 0; i < json_size(outputs); i++) {
        if (!outputs->keys || !outputs->keys[i]) continue;
        const char *addr = outputs->keys[i];
        const struct json_value *amt_v = &outputs->children[i];

        struct tx_out vout;
        tx_out_set_null(&vout);

        int64_t amount = 0;
        if (amt_v->type == JSON_REAL) {
            double d = json_get_real(amt_v);
            if (d < 0 || d > 21000000.0) {
                json_set_str(result, "Amount out of range");
                transaction_free(&tx);
                return false;
            }
            amount = (int64_t)(d * (double)ZATOSHI_PER_ZCL);
        } else if (amt_v->type == JSON_INT) {
            int64_t v = json_get_int(amt_v);
            if (v < 0 || v > 21000000) {
                json_set_str(result, "Amount out of range");
                transaction_free(&tx);
                return false;
            }
            amount = v * ZATOSHI_PER_ZCL;
        }
        vout.value = amount;

        const struct chain_params *cp2 = chain_params_get();
        size_t pk_len, sc_len;
        const unsigned char *pk_pfx = chain_params_base58_prefix(
            cp2, B58_PUBKEY_ADDRESS, &pk_len);
        const unsigned char *sc_pfx = chain_params_base58_prefix(
            cp2, B58_SCRIPT_ADDRESS, &sc_len);
        struct tx_destination dest;
        if (decode_destination(addr, pk_pfx, pk_len, sc_pfx, sc_len, &dest)) {
            script_for_destination(&vout.script_pub_key, &dest);
        }

        size_t new_count = tx.num_vout + 1;
        struct tx_out *new_vout = zcl_realloc(tx.vout,
                                          new_count * sizeof(struct tx_out), "tx_vout");
        if (!new_vout) { transaction_free(&tx); json_set_str(result, "Out of memory"); LOG_FAIL("tx", "createrawtransaction: realloc vout failed at output %zu", i); }
        tx.vout = new_vout;
        tx.vout[tx.num_vout] = vout;
        tx.num_vout = new_count;
    }

    const struct json_value *op_return_v = json_at(params, 2);
    if (op_return_v) {
        const char *op_return_hex = json_get_str(op_return_v);
        uint8_t script[MAX_OP_RETURN_RELAY];
        const size_t hex_len = op_return_hex ? strlen(op_return_hex) : 0;
        const size_t script_len =
            op_return_hex && IsHex(op_return_hex) && (hex_len & 1U) == 0 &&
                    hex_len <= sizeof(script) * 2
                ? ParseHex(op_return_hex, script, sizeof(script))
                : 0;
        if (script_len == 0 || script[0] != OP_RETURN) {
            json_set_str(result,
                "Invalid op_return_hex (need one exact OP_RETURN script "
                "within the 223-byte relay cap)");
            transaction_free(&tx);
            return false;
        }
        struct tx_out vout;
        tx_out_set_null(&vout);
        vout.value = 0;
        script_set(&vout.script_pub_key, script, script_len);
        const size_t new_count = tx.num_vout + 1;
        struct tx_out *new_vout = zcl_realloc(
            tx.vout, new_count * sizeof(struct tx_out), "tx_op_return_vout");
        if (!new_vout) {
            transaction_free(&tx);
            json_set_str(result, "Out of memory");
            LOG_FAIL("tx", "createrawtransaction: realloc OP_RETURN vout failed");
        }
        tx.vout = new_vout;
        tx.vout[tx.num_vout] = vout;
        tx.num_vout = new_count;
    }

    char *hex = zcl_malloc(2 * 1024 * 1024, "tx_hex_buf");
    if (!hex) { transaction_free(&tx); json_set_str(result, "Out of memory"); LOG_FAIL("tx", "createrawtransaction: malloc failed for hex buffer"); }
    size_t hex_len = encode_hex_tx(&tx, hex, 2 * 1024 * 1024);
    hex[hex_len] = '\0';
    json_set_str(result, hex);
    free(hex);
    transaction_free(&tx);
    return true;
}


void register_rawtransaction_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "rawtransactions", "getrawtransaction",
          rpc_getrawtransaction, true },
        { "rawtransactions", "decoderawtransaction",
          rpc_decoderawtransaction, true },
        { "rawtransactions", "sendrawtransaction",
          rpc_sendrawtransaction, false },
        { "rawtransactions", "createrawtransaction",
          rpc_createrawtransaction, false },
        { "rawtransactions", "signrawtransaction",
          rpc_signrawtransaction, false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
