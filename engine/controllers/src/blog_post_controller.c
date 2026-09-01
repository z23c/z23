/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: expose the Blog MVC resource and its read-only public HTTP routes. */

#include "controllers/blog_post_controller.h"
#include "controllers/native_handler_body.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"

#include "chain/chain.h"
#include "config/runtime.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "services/wallet_money_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "views/blog_post_view.h"
#include "znam/znam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOG_ANCHOR_WALLET_COINS_MAX 4096u

static struct zcl_result blog_anchor_read_money(
    void *opaque, const char *wallet_scope,
    struct wallet_money_snapshot *out)
{
    struct wallet_rpc_context *ctx = opaque;
    return wallet_money_snapshot_build(ctx ? ctx->node_db : NULL,
                                       ctx ? ctx->main_state : NULL,
                                       wallet_scope, out);
}

static struct zcl_result blog_anchor_prepare_wallet(
    void *opaque, const uint8_t *anchor_script, size_t anchor_script_len,
    int64_t maximum_fee_zat, uint8_t *raw_tx, size_t raw_capacity,
    size_t *raw_tx_len, uint8_t txid_out[32], int64_t *actual_fee_zat)
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !anchor_script || anchor_script_len == 0 ||
        anchor_script_len > MAX_SCRIPT_SIZE || maximum_fee_zat <= 0 ||
        !raw_tx || !raw_tx_len || !txid_out || !actual_fee_zat)
        return ZCL_ERR(-1, "Blog anchor wallet prepare context is incomplete");
    int64_t wallet_fee = wallet_default_fee(ctx->wallet);
    if (wallet_fee <= 0 || wallet_fee > maximum_fee_zat)
        return ZCL_ERR(-2, "wallet fee exceeds Blog anchor maximum fee");
    struct coin_entry *available = zcl_malloc(
        BLOG_ANCHOR_WALLET_COINS_MAX * sizeof(*available),
        "blog_anchor_available_coins");
    struct coin_entry *selected = zcl_malloc(
        BLOG_ANCHOR_WALLET_COINS_MAX * sizeof(*selected),
        "blog_anchor_selected_coins");
    if (!available || !selected) {
        free(available);
        free(selected);
        return ZCL_ERR(-3, "Blog anchor coin inventory allocation failed");
    }
    size_t available_len = 0, selected_len = 0;
    int64_t selected_value = 0;
    wallet_available_coins(ctx->wallet, available, &available_len,
                           BLOG_ANCHOR_WALLET_COINS_MAX, true, false);
    bool funded = wallet_select_coins(
        ctx->wallet, available, available_len, wallet_fee, selected,
        &selected_len, BLOG_ANCHOR_WALLET_COINS_MAX, &selected_value);
    free(available);
    if (!funded || selected_len == 0 || selected_value <= wallet_fee) {
        free(selected);
        return ZCL_ERR(-4,
                       "confirmed transparent funds cannot cover the Blog anchor fee");
    }
    struct pubkey change_key;
    if (!wallet_get_key_from_pool(ctx->wallet, &change_key)) {
        free(selected);
        return ZCL_ERR(-5, "Blog anchor change key is unavailable");
    }
    struct tx_destination change = {
        .type = DEST_KEY_ID, .id.key = pubkey_get_id(&change_key),
    };
    struct tx_out outputs[2];
    memset(outputs, 0, sizeof(outputs));
    outputs[0].value = 0;
    outputs[0].script_pub_key.size = anchor_script_len;
    memcpy(outputs[0].script_pub_key.data, anchor_script, anchor_script_len);
    outputs[1].value = selected_value - wallet_fee;
    script_for_destination(&outputs[1].script_pub_key, &change);
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    const char *why = NULL;
    int64_t fee = 0;
    bool built = wallet_create_transaction_selected(
        ctx->wallet, selected, selected_len, outputs, 2, &wtx, &fee, &why);
    free(selected);
    if (!built || fee != wallet_fee) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-6, "Blog anchor exact transaction build failed: %s",
                       why ? why : "fee changed");
    }
    struct zcl_result flushed = wallet_flush_from_context(ctx);
    if (!flushed.ok) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-7, "Blog anchor change-key persistence failed: %s",
                       flushed.message);
    }
    struct byte_stream stream;
    stream_init(&stream, 1024);
    bool serialized = transaction_serialize(&wtx.tx, &stream) &&
        stream.size <= raw_capacity;
    if (serialized) {
        memcpy(raw_tx, stream.data, stream.size);
        *raw_tx_len = stream.size;
        memcpy(txid_out, wtx.tx.hash.data, 32);
        *actual_fee_zat = fee;
    }
    stream_free(&stream);
    transaction_free(&wtx.tx);
    return serialized
        ? ZCL_OK
        : ZCL_ERR(-8, "Blog anchor prepared transaction is too large");
}

static struct zcl_result blog_anchor_publish_wallet(
    void *opaque, const uint8_t *raw_tx, size_t raw_tx_len,
    const uint8_t expected_txid[32])
{
    struct wallet_rpc_context *ctx = opaque;
    if (!ctx || !ctx->wallet || !ctx->mempool || !ctx->main_state ||
        !ctx->coins_tip || !raw_tx || raw_tx_len == 0 || !expected_txid)
        return ZCL_ERR(-1, "Blog anchor wallet publish context is incomplete");
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    struct byte_stream stream;
    stream_init_from_data(&stream, raw_tx, raw_tx_len);
    bool decoded = transaction_deserialize(&wtx.tx, &stream) &&
        stream_remaining(&stream) == 0;
    stream_free(&stream);
    if (!decoded) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-2, "prepared Blog transaction failed to decode");
    }
    transaction_compute_hash(&wtx.tx);
    if (memcmp(wtx.tx.hash.data, expected_txid, 32) != 0) {
        transaction_free(&wtx.tx);
        return ZCL_ERR(-3, "prepared Blog transaction identity changed");
    }
    wtx.time_received = (int64_t)platform_time_wall_time_t();
    wtx.from_me = true;
    wtx.used = true;
    if (!wallet_get_tx(ctx->wallet, &wtx.tx.hash)) {
        struct zcl_result committed = wallet_commit_from_context(ctx, &wtx);
        if (!committed.ok) {
            transaction_free(&wtx.tx);
            return committed;
        }
        struct zcl_result persisted =
            wallet_persist_commit_before_relay(ctx, &wtx);
        if (!persisted.ok) {
            transaction_free(&wtx.tx);
            return persisted;
        }
        if (wallet_ctx_db_ready(ctx))
            node_db_sync_wallet_tx(ctx->node_db, &wtx.tx, ctx->wallet, 0);
    }
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &wtx.tx.hash);
    transaction_free(&wtx.tx);
    return ZCL_OK;
}

static struct zcl_result blog_anchor_runtime(
    struct blog_anchor_runtime *out)
{
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    if (!out || !ctx || !ctx->node_db || !ctx->wallet || !ctx->mempool ||
        !ctx->main_state || !ctx->coins_tip)
        return ZCL_ERR(-1, "Blog anchor wallet RPC context is incomplete");
    struct block_index *tip = ctx->main_state
        ? active_chain_tip(&ctx->main_state->chain_active) : NULL;
    if (!tip)
        return ZCL_ERR(-2, "Blog anchor active chain tip is unavailable");
    memset(out, 0, sizeof(*out));
    out->node_db = ctx->node_db;
    out->read_money = blog_anchor_read_money;
    out->money_ctx = ctx;
    out->prepare = blog_anchor_prepare_wallet;
    out->prepare_ctx = ctx;
    out->publish = blog_anchor_publish_wallet;
    out->publish_ctx = ctx;
    out->tip_height = tip->nHeight;
    memcpy(out->tip_hash, tip->hashBlock.data, 32);
    out->maximum_fee_zat = wallet_default_fee(ctx->wallet);
    out->now_unix = (int64_t)platform_time_wall_time_t();
    return ZCL_OK;
}

static const char *blog_anchor_arg(const struct json_value *params,
                                   size_t positional, const char *key)
{
    if (!params)
        return NULL;
    const struct json_value *first = json_size(params) ? json_at(params, 0)
                                                       : NULL;
    if (first && first->type == JSON_OBJ) {
        const struct json_value *value = json_get(first, key);
        return value && value->type == JSON_STR ? json_get_str(value) : NULL;
    }
    const struct json_value *value =
        json_size(params) > positional ? json_at(params, positional) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool blog_anchor_bool_arg(const struct json_value *params,
                                 size_t positional, const char *key)
{
    if (!params)
        return false;
    const struct json_value *first = json_size(params) ? json_at(params, 0)
                                                       : NULL;
    if (first && first->type == JSON_OBJ)
        return json_get_bool_or(first, key, false);
    const struct json_value *value =
        json_size(params) > positional ? json_at(params, positional) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static void blog_anchor_render(
    const struct blog_anchor_transaction_result *anchored,
    struct json_value *result)
{
    char plan_hex[65], event_hex[65], txid_hex[65];
    HexStr(anchored->plan_id, sizeof(anchored->plan_id), false,
           plan_hex, sizeof(plan_hex));
    HexStr(anchored->event_id, sizeof(anchored->event_id), false,
           event_hex, sizeof(event_hex));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.app_blog_anchor.v1");
    json_push_kv_str(result, "wallet_scope", anchored->wallet_scope);
    json_push_kv_str(result, "plan_id", plan_hex);
    json_push_kv_str(result, "blog_name", anchored->blog_name);
    json_push_kv_str(result, "event_id", event_hex);
    json_push_kv_bool(result, "event_verified", anchored->event_verified);
    char script_hex[BLOG_ANCHOR_SCRIPT_MAX * 2 + 1];
    HexStr(anchored->anchor_script, anchored->anchor_script_len, false,
           script_hex, sizeof(script_hex));
    json_push_kv_str(result, "op_return_hex", script_hex);
    json_push_kv_int(result, "op_return_size",
                     (int64_t)anchored->anchor_script_len);
    json_push_kv_str(result, "state", anchored->state);
    json_push_kv_str(result, "status",
                     anchored->broadcast ? "broadcast" : "planned");
    json_push_kv_int(result, "actual_fee_zat", anchored->actual_fee_zat);
    json_push_kv_int(result, "maximum_fee_zat", anchored->maximum_fee_zat);
    json_push_kv_int(result, "reserved_zat", anchored->reserved_zat);
    json_push_kv_int(result, "expires_at", anchored->expires_at);
    json_push_kv_bool(result, "idempotent_replay",
                      anchored->idempotent_replay);
    if (anchored->has_txid) {
        struct uint256 txid;
        memcpy(txid.data, anchored->txid, 32);
        uint256_get_hex(&txid, txid_hex);
        json_push_kv_str(result, "txid", txid_hex);
    }
}

static bool rpc_blog_anchor(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "blog_anchor plan {wallet_scope,name,event_id,idempotency_key}\n"
            "blog_anchor commit {wallet_scope,plan_id,confirm:true}\n"
            "\nThe plan verifies the signed event and current ZNAM owner, "
            "prepares exact signed transaction bytes, and atomically reserves "
            "the maximum fee. Commit rechecks wallet identity, genesis, tip, "
            "money snapshot, event ownership, and the exact prepared tx.\n");
        return true;
    }
    const char *scope = blog_anchor_arg(params, 0, "wallet_scope");
    const char *name = blog_anchor_arg(params, 1, "name");
    const char *event_hex = blog_anchor_arg(params, 2, "event_id");
    const char *idempotency = blog_anchor_arg(params, 3, "idempotency_key");
    const char *plan_hex = blog_anchor_arg(params, 4, "plan_id");
    bool confirm = blog_anchor_bool_arg(params, 5, "confirm");
    if (!scope || (strcmp(scope, "dev") != 0 && strcmp(scope, "prod") != 0)) {
        json_set_str(result, "blog_anchor requires wallet_scope=dev|prod");
        return false;
    }
    struct blog_anchor_runtime runtime;
    struct zcl_result ready = blog_anchor_runtime(&runtime);
    if (!ready.ok) {
        json_set_str(result, ready.message);
        LOG_FAIL("blog.anchor", "runtime refused: %s", ready.message);
    }
    struct blog_anchor_transaction_result anchored;
    struct zcl_result outcome;
    if (confirm) {
        uint8_t plan_id[32];
        if (!plan_hex || strlen(plan_hex) != 64 || !IsHex(plan_hex) ||
            ParseHex(plan_hex, plan_id, sizeof(plan_id)) != 32) {
            json_set_str(result,
                         "blog_anchor commit requires a 64-hex plan_id");
            return false;
        }
        outcome = blog_publication_anchor_commit(
            &runtime, scope, plan_id, &anchored);
    } else {
        uint8_t event_id[32];
        if (!name || !event_hex || !idempotency ||
            strlen(event_hex) != 64 || !IsHex(event_hex) ||
            ParseHex(event_hex, event_id, sizeof(event_id)) != 32) {
            json_set_str(result,
                "blog_anchor plan requires name, 64-hex event_id, and idempotency_key");
            return false;
        }
        struct blog_anchor_request request;
        memset(&request, 0, sizeof(request));
        if (strlen(scope) >= sizeof(request.wallet_scope) ||
            strlen(name) >= sizeof(request.blog_name) ||
            strlen(idempotency) >= sizeof(request.idempotency_key)) {
            json_set_str(result, "blog_anchor plan input exceeds bounds");
            return false;
        }
        (void)snprintf(request.wallet_scope, sizeof(request.wallet_scope),
                       "%s", scope);
        (void)snprintf(request.blog_name, sizeof(request.blog_name), "%s",
                       name);
        (void)snprintf(request.idempotency_key,
                       sizeof(request.idempotency_key), "%s", idempotency);
        memcpy(request.event_id, event_id, 32);
        outcome = blog_publication_anchor_plan(
            &runtime, &request, &anchored);
    }
    if (!outcome.ok) {
        json_set_str(result, outcome.message);
        LOG_FAIL("blog.anchor", "blog_anchor refused: %s", outcome.message);
    }
    blog_anchor_render(&anchored, result);
    return true;
}

void register_blog_post_rpc_commands(struct rpc_table *table)
{
    struct rpc_command command = {
        "blog", "blog_anchor", rpc_blog_anchor, true,
    };
    rpc_table_must_append(table, &command);
}

struct zcl_result blog_post_controller_create(
    struct node_db *ndb, struct wallet *wallet,
    const struct zcl_app_event_signing_binding_v1 *binding,
    const struct blog_publish_request *request,
    struct blog_publish_result *out)
{
    if (!request || !request->blog_name || !request->slug ||
        !request->title || !request->body)
        return ZCL_ERR(-1, "BlogPost#create requires name, slug, title, and body");
    return blog_publication_create(ndb, wallet, binding, request, out);
}

struct zcl_result blog_post_controller_import(
    struct node_db *ndb, const struct zcl_app_signed_event_v1 *event,
    struct db_blog_post *out)
{
    return blog_publication_import_event(ndb, event, out);
}

struct zcl_result blog_post_controller_show(
    struct node_db *ndb, const char *blog_name, const char *slug,
    struct blog_post_page *out)
{
    if (!ndb || !ndb->open || !blog_name || !slug || !out)
        return ZCL_ERR(-1, "BlogPost#show requires db, name, slug, and output");
    memset(out, 0, sizeof(*out));
    if (!db_blog_post_find_by_slug(ndb, blog_name, slug, &out->post))
        return ZCL_ERR(-2, "BlogPost#show did not find the resource");
    uint8_t payload[BLOG_BODY_MAX + BLOG_TITLE_MAX + BLOG_NAME_MAX +
                    BLOG_SLUG_MAX + 32];
    struct zcl_app_signed_event_v1 verified_event;
    struct zcl_result verified = blog_publication_export_event(
        &out->post, payload, sizeof(payload), &verified_event);
    if (!verified.ok)
        return verified;
    out->content_available = true;
    /* Public GET/HEAD is strictly read-only.  Chain observation persists a
     * projection receipt and therefore belongs to the owned publication/job
     * lane, never an unauthenticated request path. */
    if (db_blog_publication_receipt_find_by_event(
            ndb, out->post.event_id, &out->receipt)) {
        out->has_receipt = true;
    }
    /* Receipts in v28 are node.db projection evidence only. The future live
     * verifier sets this after H* + active-slot/body proof. */
    out->served_frontier_proven = false;
    return ZCL_OK;
}

struct zcl_result blog_post_controller_index(
    struct node_db *ndb, const char *blog_name_or_null,
    struct blog_post_index_page *out)
{
    if (!ndb || !ndb->open || !out)
        return ZCL_ERR(-1, "BlogPost#index requires an open db and output");
    if (blog_name_or_null && blog_name_or_null[0] &&
        !znam_validate_name(blog_name_or_null))
        return ZCL_ERR(-2, "BlogPost#index name is not canonical");
    memset(out, 0, sizeof(*out));
    if (blog_name_or_null && blog_name_or_null[0])
        (void)snprintf(out->blog_name, sizeof(out->blog_name), "%s",
                       blog_name_or_null);
    out->count = blog_publication_recent_verified_summaries(
        ndb, blog_name_or_null, out->posts, BLOG_POST_INDEX_MAX);
    return ZCL_OK;
}

static size_t blog_http_response(const char *status,
                                 const uint8_t *body, size_t body_len,
                                 bool head_only,
                                 uint8_t *response, size_t response_max)
{
    if (!status || !body || !response)
        return 0;
    int header_len = snprintf((char *)response, response_max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, body_len);
    if (header_len < 0 || (size_t)header_len >= response_max)
        return 0;
    if (head_only)
        return (size_t)header_len;
    if (body_len > response_max - (size_t)header_len)
        return 0;
    memcpy(response + header_len, body, body_len);
    return (size_t)header_len + body_len;
}

static bool blog_path_segments(const char *path,
                               char name[BLOG_NAME_MAX + 1],
                               char slug[BLOG_SLUG_MAX + 1],
                               bool *has_name, bool *has_slug)
{
    *has_name = false;
    *has_slug = false;
    name[0] = 0;
    slug[0] = 0;
    if (!path || strncmp(path, "/blog", 5) != 0 ||
        (path[5] != 0 && path[5] != '/'))
        return false;
    const char *p = path + 5;
    if (*p == '/')
        p++;
    if (*p == 0)
        return true;
    const char *slash = strchr(p, '/');
    size_t name_len = slash ? (size_t)(slash - p) : strlen(p);
    if (name_len == 0 || name_len > BLOG_NAME_MAX)
        return false;
    memcpy(name, p, name_len);
    name[name_len] = 0;
    *has_name = true;
    if (!slash)
        return true;
    p = slash + 1;
    if (!*p || strchr(p, '/'))
        return false;
    size_t slug_len = strlen(p);
    if (slug_len == 0 || slug_len > BLOG_SLUG_MAX)
        return false;
    memcpy(slug, p, slug_len + 1);
    *has_slug = true;
    return true;
}

size_t blog_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max)
{
    (void)body;
    (void)body_len;
    if (!method || !path || !response || response_max < 512)
        return 0;
    bool head_only = strcmp(method, "HEAD") == 0;
    if (strcmp(method, "GET") != 0 && !head_only) {
        static const uint8_t denied[] =
            "<!doctype html><h1>405 Method Not Allowed</h1>";
        return blog_http_response("405 Method Not Allowed", denied,
                                  sizeof(denied) - 1, false,
                                  response, response_max);
    }
    const char *query = strchr(path, '?');
    size_t path_len = query ? (size_t)(query - path) : strlen(path);
    char clean_path[256];
    if (path_len == 0 || path_len >= sizeof(clean_path)) {
        static const uint8_t bad[] = "<!doctype html><h1>400 Bad Request</h1>";
        return blog_http_response("400 Bad Request", bad, sizeof(bad) - 1,
                                  head_only, response, response_max);
    }
    memcpy(clean_path, path, path_len);
    clean_path[path_len] = 0;
    char name[BLOG_NAME_MAX + 1], slug[BLOG_SLUG_MAX + 1];
    bool has_name = false, has_slug = false;
    if (!blog_path_segments(clean_path, name, slug, &has_name, &has_slug) ||
        (has_name && !znam_validate_name(name))) {
        static const uint8_t missing[] = "<!doctype html><h1>404 Not Found</h1>";
        return blog_http_response("404 Not Found", missing,
                                  sizeof(missing) - 1, head_only,
                                  response, response_max);
    }
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        LOG_WARN("blog", "public Blog requested while node.db is unavailable");
        return 0; /* caller may use the legacy static fallback */
    }
    size_t body_capacity = response_max < 262144 ? response_max : 262144;
    uint8_t *rendered = zcl_malloc(body_capacity, "blog site response body");
    if (!rendered) {
        LOG_WARN("blog", "public Blog response allocation failed");
        return 0;
    }
    size_t rendered_len = 0;
    struct zcl_result result;
    if (has_slug) {
        struct blog_post_page page;
        result = blog_post_controller_show(ndb, name, slug, &page);
        if (result.ok)
            rendered_len = blog_post_view_render(
                &page, rendered, body_capacity);
    } else {
        struct blog_post_index_page page;
        result = blog_post_controller_index(
            ndb, has_name ? name : NULL, &page);
        if (result.ok)
            rendered_len = blog_post_index_view_render(
                &page, rendered, body_capacity);
    }
    size_t response_len = 0;
    if (result.ok && rendered_len > 0) {
        response_len = blog_http_response("200 OK", rendered, rendered_len,
                                          head_only, response, response_max);
    } else {
        static const uint8_t missing[] = "<!doctype html><h1>404 Not Found</h1>";
        response_len = blog_http_response("404 Not Found", missing,
                                          sizeof(missing) - 1, head_only,
                                          response, response_max);
    }
    free(rendered);
    return response_len;
}
