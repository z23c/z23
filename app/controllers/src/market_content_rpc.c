/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The owner's private paid-content registry, as RPC.
 *
 * Split out of file_market_controller.c so the registration confirm gate
 * lives beside the RPC it guards: this is the owner-registration surface
 * (what bytes this node vouches for and serves), while the rest of that
 * controller lists offers, sells files, and moves money. They share the
 * node_db through rpc_market_state and nothing else.
 *
 * REGISTRATION IS A TWO-STEP COMMAND, like the moderation setters. The
 * write re-keys an offer's serving bytes, so mode "plan" mints a plan
 * token bound to the canonical signed-offer wire, target path, and complete
 * durable registration-row identity. Commit rechecks it inside the same
 * reserved write transaction that saves the row, after hashing the file.
 *
 * Nothing here deletes, re-signs an offer, or reaches block or transaction
 * acceptance; the signed offer still commits the content root. */

#include "controllers/file_market_controller.h"

#include "base/hex.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/market_content.h"
#include "net/file_market.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/file_market_content_service.h"
#include "services/market_moderation_service.h"

#include <stdio.h>
#include <string.h>

/* The registered-content index is a serving surface — it tells a caller,
 * including a remote one over GET /api/market-contents, which content
 * this node holds bytes for and will hand out, under the same profile the
 * chunk-delivery gate asks. The remote REST response reveals only servable
 * rows. Local RPC may additionally report private window diagnostics. */
static bool market_content_index_json(struct json_value *result,
                                      bool local_details)
{
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.market_contents.index.v1");
    json_push_kv_str(result, "profile",
                     market_moderation_profile_string(
                         market_moderation_active_profile()));
    int64_t hidden = 0; int count = 0, total = -1;
    struct json_value rows = {0};
    json_set_array(&rows);
    if (rpc_market_state() && rpc_market_state()->open) {
        struct node_db *ndb = rpc_market_state();
        struct market_content_public_record content[FILE_MARKET_MAX_OFFERS];
        count = db_market_content_list_snapshot(
            ndb, content, FILE_MARKET_MAX_OFFERS, &total);
        if (count < 0) {
            json_free(&rows);
            json_set_str(result,
                         "market content registry could not be read");
            return false;
        }
        for (int i = 0; i < count; i++) {
            if (!market_moderation_may_serve_root(content[i].root_hash)) {
                hidden++;
                continue;
            }
            struct json_value row = {0};
            json_set_object(&row);
            char offer_hex[65], root_hex[65];
            HexStr(content[i].offer_id, 32, false,
                   offer_hex, sizeof(offer_hex));
            HexStr(content[i].root_hash, 32, false,
                   root_hex, sizeof(root_hex));
            json_push_kv_str(&row, "offer_id", offer_hex);
            json_push_kv_str(&row, "root_hash", root_hex);
            json_push_kv_int(&row, "size_bytes",
                             (int64_t)content[i].size_bytes);
            json_push_kv_int(&row, "num_chunks", content[i].num_chunks);
            json_push_kv_int(&row, "registered_at",
                             content[i].registered_at);
            json_push_back(&rows, &row);
            json_free(&row);
        }
    }
    json_push_kv(result, "contents", &rows);
    json_free(&rows);
    json_push_kv_int(result, "shown", count - (int)hidden);
    if (local_details) {
        json_push_kv_int(result, "hidden_by_profile", hidden);
        if (total >= 0)
            json_push_kv_int(result, "total", total);
    }
    return true;
}

static bool rpc_zmarket_content_list(const struct json_value *params,
                                     bool help,
                                     struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "zmarket_content_list\n\nList owner-registered paid content "
            "without revealing private filesystem paths.\n");
        return true;
    }
    (void)params;
    return market_content_index_json(result, true);
}

bool api_market_content_list(struct json_value *result)
{
    return market_content_index_json(result, false);
}

static bool rpc_zmarket_content_register(const struct json_value *params,
                                         bool help,
                                         struct json_value *result)
{
    if (help || !params || json_size(params) < 3) {
        json_set_str(result,
            "zmarket_content_register \"offer_id\" \"content_path\" "
            "\"mode\" [\"plan_token\"]\n"
            "\nBind exact local bytes to an authenticated paid offer. The\n"
            "private path is never returned. Exact two-step: mode \"plan\"\n"
            "mints a plan_token bound to the offer, the target path, and\n"
            "the offer's registration as it stands; mode \"commit\" requires\n"
            "that token (STALE_PLAN if any of the three moved in between)\n"
            "and only then hashes and records the bytes.\n"
            "\nArguments:\n"
            "1. offer_id     (string, required) 64-hex authenticated offer id\n"
            "2. content_path (string, required) private path to the exact bytes\n"
            "3. mode         (string, required) \"plan\" or \"commit\"\n"
            "4. plan_token   (string, required for commit) 64-hex plan token\n");
        return true;
    }
    const char *offer_hex = json_get_str(json_at(params, 0));
    const char *content_path = json_get_str(json_at(params, 1));
    const struct json_value *arg2 = json_at(params, 2);
    const char *mode =
        arg2 && arg2->type == JSON_STR ? json_get_str(arg2) : NULL;
    uint8_t offer_id[32];
    if (!offer_hex || strlen(offer_hex) != 64 || !IsHex(offer_hex) ||
        ParseHex(offer_hex, offer_id, sizeof(offer_id)) != 32 ||
        !content_path || !content_path[0]) {
        json_set_str(result,
                     "offer_id must be 64 hex characters and content_path is required");
        return false;
    }
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        json_set_str(result, "mode must be \"plan\" or \"commit\"");
        return false;
    }
    struct node_db *ndb = rpc_market_state();
    if (!ndb || !ndb->open) {
        json_set_str(result, "market database is unavailable");
        return false;
    }

    char state_name[MARKET_CONTENT_REGISTRATION_STATE_MAX];
    uint8_t token[32];
    struct zcl_result planned = file_market_content_registration_plan(
        ndb, offer_id, content_path, token, state_name);
    if (!planned.ok) {
        json_set_str(result, planned.message);
        return false;
    }

    bool committed = false;
    uint8_t supplied[32] = {0};
    if (strcmp(mode, "commit") == 0) {
        const struct json_value *arg3 = json_at(params, 3);
        const char *hex =
            arg3 && arg3->type == JSON_STR ? json_get_str(arg3) : NULL;
        uint8_t difference = 0;
        if (!hex || strlen(hex) != 64 ||
            !zcl_hex_decode_lower(hex, supplied, 32)) {
            json_set_str(result,
                "INVALID_PLAN_TOKEN: commit requires the canonical 64-hex "
                "plan_token minted by mode \"plan\"");
            return false;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            json_set_str(result,
                "STALE_PLAN: the offer's registration or target path moved "
                "after the plan was minted — re-plan and commit again");
            return false;
        }
        committed = true;
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.market_content.v1");
    json_push_kv_str(result, "mode", mode);
    json_push_kv_bool(result, "committed", committed);
    char token_hex[65];
    zcl_hex_encode(token, 32, token_hex);
    json_push_kv_str(result, "plan_token", token_hex);
    json_push_kv_str(result, "offer_id", offer_hex);
    json_push_kv_str(result, "registration_state", state_name);

    if (!committed) {
        json_push_kv_str(result, "status", "planned");
        return true;
    }

    struct market_content_public_record registered;
    struct zcl_result saved = file_market_content_register_planned(
        ndb, offer_id, content_path, supplied,
        (int64_t)platform_time_wall_time_t(), &registered);
    if (!saved.ok) {
        json_set_str(result, saved.message);
        return false;
    }
    char root_hex[65];
    HexStr(registered.root_hash, 32, false, root_hex, sizeof(root_hex));
    json_push_kv_str(result, "status", "registered");
    json_push_kv_str(result, "root_hash", root_hex);
    json_push_kv_int(result, "size_bytes", (int64_t)registered.size_bytes);
    json_push_kv_int(result, "num_chunks", registered.num_chunks);
    json_push_kv_int(result, "registered_at", registered.registered_at);
    return true;
}

void register_market_content_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "market", "zmarket_content_list",
          rpc_zmarket_content_list, true },
        { "market", "zmarket_content_register",
          rpc_zmarket_content_register, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
