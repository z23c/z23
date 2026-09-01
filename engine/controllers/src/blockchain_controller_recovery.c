/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Recovery RPCs: invalidateblock / reconsiderblock.
 *
 * The operator lever to drop a stale fork (mark BLOCK_FAILED_VALID +
 * disconnect-and-reorg to the next-best valid chain) and its inverse.
 * Mirrors Bitcoin Core semantics. The consensus-safe machinery lives in
 * core/modules/validation/src/process_block_invalidate.c — these handlers only
 * parse the hash, dispatch, and shape the JSON result. */

#include "platform/time_compat.h"
#include "controllers/blockchain_controller.h"
#include "blockchain_controller_internal.h"
#include "controllers/strong_params.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block_invalidate.h"
#include "util/log_macros.h"

#include <stdbool.h>

bool rpc_invalidateblock(const struct json_value *params, bool help,
                         struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    RPC_HELP(help, result,
             "invalidateblock \"hash\"\n"
             "\nPermanently marks a block as invalid, as if it violated a\n"
             "consensus rule. The active chain disconnects back below the\n"
             "block (if it is on the active chain) and reorgs to the\n"
             "next-best fully-valid chain. Every reconnected block is\n"
             "fully re-validated. Use reconsiderblock to undo.\n"
             "\nArguments:\n"
             "  1. \"hash\"  (string, required) the block hash to invalidate\n"
             "\nResult:\n"
             "  {\n"
             "    \"hash\": \"...\",         (string) the invalidated hash\n"
             "    \"result\": \"ok\",        (string) outcome name\n"
             "    \"tip_before\": n,       (numeric) tip height before\n"
             "    \"tip_after\": n         (numeric) tip height after\n"
             "  }\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *hash_str = rpc_require_str(&p, 0, "hash");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "invalidateblock: invalid params");
    }
    if (!ctx->main_state) {
        json_set_str(result, "Not initialized");
        LOG_FAIL("blockchain", "invalidateblock: main_state not initialized");
    }

    struct uint256 hash;
    uint256_set_hex(&hash, hash_str);

    int tip_before = active_chain_height(&ctx->main_state->chain_active);

    struct uint256 out_hash;
    enum invalidate_result r =
        process_block_invalidate(ctx->main_state, &hash, &out_hash);

    if (r != INVALIDATE_OK) {
        char body[160];
        snprintf(body, sizeof(body),
                 "invalidateblock failed: %s", invalidate_result_name(r));
        json_set_str(result, body);
        LOG_FAIL("blockchain", "invalidateblock %s: %s",
                 hash_str, invalidate_result_name(r));
    }

    int tip_after = active_chain_height(&ctx->main_state->chain_active);

    char out_hex[65];
    uint256_get_hex(&out_hash, out_hex);

    json_set_object(result);
    json_push_kv_str(result, "hash", out_hex);
    json_push_kv_str(result, "result", invalidate_result_name(r));
    json_push_kv_int(result, "tip_before", tip_before);
    json_push_kv_int(result, "tip_after", tip_after);
    return true;
}

bool rpc_reconsiderblock(const struct json_value *params, bool help,
                         struct json_value *result)
{
    struct blockchain_context *ctx = blockchain_ctx();
    RPC_HELP(help, result,
             "reconsiderblock \"hash\"\n"
             "\nRemoves invalidity status from a block and its descendants,\n"
             "re-adding them to chain selection. If the reconsidered chain\n"
             "has the most work it is re-validated and reconnected. The\n"
             "inverse of invalidateblock.\n"
             "\nArguments:\n"
             "  1. \"hash\"  (string, required) the block hash to reconsider\n"
             "\nResult:\n"
             "  {\n"
             "    \"hash\": \"...\",         (string) the reconsidered hash\n"
             "    \"result\": \"ok\",        (string) outcome name\n"
             "    \"tip\": n                (numeric) tip height after\n"
             "  }\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 1, 1);
    const char *hash_str = rpc_require_str(&p, 0, "hash");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("blockchain", "reconsiderblock: invalid params");
    }
    if (!ctx->main_state) {
        json_set_str(result, "Not initialized");
        LOG_FAIL("blockchain", "reconsiderblock: main_state not initialized");
    }

    struct uint256 hash;
    uint256_set_hex(&hash, hash_str);

    struct uint256 out_hash;
    enum reconsider_result r =
        process_block_reconsider(ctx->main_state, &hash, &out_hash);

    /* RECONSIDER_NO_FAILURE is a benign no-op (nothing was marked) — report
     * it as a successful result with the name, not an error. */
    if (r != RECONSIDER_OK && r != RECONSIDER_NO_FAILURE) {
        char body[160];
        snprintf(body, sizeof(body),
                 "reconsiderblock failed: %s", reconsider_result_name(r));
        json_set_str(result, body);
        LOG_FAIL("blockchain", "reconsiderblock %s: %s",
                 hash_str, reconsider_result_name(r));
    }

    int tip = active_chain_height(&ctx->main_state->chain_active);

    char out_hex[65];
    uint256_get_hex(&out_hash, out_hex);

    json_set_object(result);
    json_push_kv_str(result, "hash", out_hex);
    json_push_kv_str(result, "result", reconsider_result_name(r));
    json_push_kv_int(result, "tip", tip);
    return true;
}
