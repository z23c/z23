/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Probe controller — the `probezclassicd` primitive.
 *
 * Synchronously probe the co-located zclassicd (independent ZClassic
 * implementation) for the block hash at a given height and compare it
 * against our block_index. Used as a drift oracle during sync.
 */

#include "controllers/diagnostics_internal.h"

#include "json/json.h"
#include "rpc/server.h"
#include "controllers/strong_params.h"
#include "services/zclassicd_oracle_service.h"
#include "util/log_macros.h"

#include <stdlib.h>

bool diag_rpc_probezclassicd(const struct json_value *params, bool help,
                             struct json_value *result)
{
    RPC_HELP(help, result,
        "probezclassicd <height>\n"
        "\nProbe the local zclassicd (independent ZClassic impl) for the\n"
        "block hash at <height> and compare to our block_index.\n"
        "\nResult: { height, our_hash, their_hash, match, our_have_block,\n"
        "         error, error_msg }");

    const struct json_value *h_val = json_at(params, 0);
    int height = -1;
    if (h_val) {
        if (h_val->type == JSON_INT)
            height = (int)json_get_int(h_val);
        else if (h_val->type == JSON_STR)
            height = atoi(json_get_str(h_val));
    }
    if (height < 0) {
        LOG_FAIL("diag", "probezclassicd: bad/missing height");
    }

    struct zclassicd_oracle_probe_result r;
    struct zcl_result probe_r = zclassicd_oracle_probe(height, &r);

    json_set_object(result);
    json_push_kv_int (result, "height",         r.height);
    json_push_kv_str (result, "our_hash",       r.our_hash);
    json_push_kv_str (result, "their_hash",     r.their_hash);
    json_push_kv_bool(result, "match",          r.match);
    json_push_kv_bool(result, "our_have_block", r.our_have_block);
    json_push_kv_bool(result, "error",          r.error);
    json_push_kv_str (result, "error_msg",      r.error_msg);
    return probe_r.ok;
}
