/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: sign, verify, import, export, and observe anchored Blog events. */

#include "services/blog_publication_service.h"

#include "base/bytes.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "models/app_event.h"
#include "models/db_txn.h"
#include "models/shared_validators.h"
#include "models/znam.h"
#include "platform/time_compat.h"
#include "script/op_return_push.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <string.h>

static const uint8_t k_blog_payload_magic[4] = { 'Z', 'B', 'L', 'G' };
static const uint8_t k_blog_anchor_lokad[4] = { 'Z', 'B', 'L', 'G' };

enum blog_publication_error {
    BLOG_ERR_ARGS = -1,
    BLOG_ERR_SCOPE = -2,
    BLOG_ERR_CODEC = -3,
    BLOG_ERR_SIGN = -4,
    BLOG_ERR_VERIFY = -5,
    BLOG_ERR_NAME = -6,
    BLOG_ERR_SAVE = -7,
    BLOG_ERR_CHAIN = -8,
    BLOG_ERR_VALIDATION = -9,
    BLOG_ERR_TX = -10,
};

static void write_u16_le(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}

static void write_u32_le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static uint16_t read_u16_le(const uint8_t in[2])
{
    return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

static uint32_t read_u32_le(const uint8_t in[4])
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static bool payload_field_size(const char *value, size_t max, size_t *len_out)
{
    if (!value || !len_out)
        return false;
    const char *end = memchr(value, 0, max + 1);
    if (!end || end == value)
        return false;
    *len_out = (size_t)(end - value);
    return true;
}

static bool blog_payload_build(const struct blog_publish_request *request,
                               uint8_t *out, size_t capacity,
                               size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!request || !out || !out_len)
        return false;
    size_t name_len = 0, slug_len = 0, title_len = 0, body_len = 0;
    if (!payload_field_size(request->blog_name, BLOG_NAME_MAX, &name_len) ||
        !payload_field_size(request->slug, BLOG_SLUG_MAX, &slug_len) ||
        !payload_field_size(request->title, BLOG_TITLE_MAX, &title_len) ||
        !payload_field_size(request->body, BLOG_BODY_MAX, &body_len) ||
        name_len > UINT8_MAX || slug_len > UINT8_MAX ||
        title_len > UINT16_MAX || body_len > UINT32_MAX)
        return false;
    size_t required = sizeof(k_blog_payload_magic) + 1 + 1 + name_len +
        1 + slug_len + 2 + title_len + 4 + body_len;
    *out_len = required;
    if (required > capacity)
        return false;

    size_t off = 0;
    memcpy(out + off, k_blog_payload_magic, sizeof(k_blog_payload_magic));
    off += sizeof(k_blog_payload_magic);
    out[off++] = 1;
    out[off++] = (uint8_t)name_len;
    memcpy(out + off, request->blog_name, name_len);
    off += name_len;
    out[off++] = (uint8_t)slug_len;
    memcpy(out + off, request->slug, slug_len);
    off += slug_len;
    write_u16_le(out + off, (uint16_t)title_len);
    off += 2;
    memcpy(out + off, request->title, title_len);
    off += title_len;
    write_u32_le(out + off, (uint32_t)body_len);
    off += 4;
    memcpy(out + off, request->body, body_len);
    off += body_len;
    return off == required;
}

static bool take_payload_field(const uint8_t **cursor, const uint8_t *end,
                               size_t len, char *out, size_t out_size)
{
    if (!cursor || !*cursor || !end || !out || *cursor > end || len == 0 ||
        len >= out_size || (size_t)(end - *cursor) < len ||
        memchr(*cursor, 0, len))
        return false;
    memcpy(out, *cursor, len);
    out[len] = 0;
    *cursor += len;
    return true;
}

static bool blog_payload_parse(const uint8_t *payload, size_t payload_len,
                               struct db_blog_post *out)
{
    if (!payload || !out || payload_len < 13)
        return false;
    const uint8_t *p = payload;
    const uint8_t *end = payload + payload_len;
    if (memcmp(p, k_blog_payload_magic, sizeof(k_blog_payload_magic)) != 0)
        return false;
    p += sizeof(k_blog_payload_magic);
    if (p >= end || *p++ != 1)
        return false;
    if (p >= end)
        return false;
    size_t name_len = *p++;
    if (!take_payload_field(&p, end, name_len, out->blog_name,
                            sizeof(out->blog_name)) || p >= end)
        return false;
    size_t slug_len = *p++;
    if (!take_payload_field(&p, end, slug_len, out->slug,
                            sizeof(out->slug)) || (size_t)(end - p) < 2)
        return false;
    size_t title_len = read_u16_le(p);
    p += 2;
    if (!take_payload_field(&p, end, title_len, out->title,
                            sizeof(out->title)) || (size_t)(end - p) < 4)
        return false;
    size_t body_len = read_u32_le(p);
    p += 4;
    if (!take_payload_field(&p, end, body_len, out->body,
                            sizeof(out->body)))
        return false;
    return p == end;
}

struct zcl_result blog_publication_scope(struct zcl_app_event_scope_v1 *out)
{
    if (!out)
        return ZCL_ERR(BLOG_ERR_ARGS, "Blog scope output is required");
    const struct chain_params *params = chain_params_get();
    if (!params)
        return ZCL_ERR(BLOG_ERR_SCOPE, "selected chain parameters unavailable");
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    memcpy(out->app_id, BLOG_APP_ID, sizeof(BLOG_APP_ID));
    memcpy(out->topic, BLOG_EVENT_TOPIC, sizeof(BLOG_EVENT_TOPIC));
    memcpy(out->chain_id, params->consensus.hashGenesisBlock.data,
           sizeof(out->chain_id));
    out->max_event_bytes = BLOG_EVENT_MAX_BYTES;
    return ZCL_OK;
}

static bool author_address(const uint8_t key_id_bytes[20],
                           char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params || !key_id_bytes || !out)
        return false;
    struct tx_destination destination;
    memset(&destination, 0, sizeof(destination));
    destination.type = DEST_KEY_ID;
    memcpy(destination.id.key.id.data, key_id_bytes, 20);
    size_t pub_len = 0, script_len = 0;
    const unsigned char *pub = chain_params_base58_prefix(
        params, B58_PUBKEY_ADDRESS, &pub_len);
    const unsigned char *script = chain_params_base58_prefix(
        params, B58_SCRIPT_ADDRESS, &script_len);
    return encode_destination(&destination, pub, pub_len, script, script_len,
                              out, out_size);
}

struct zcl_result blog_publication_validate_request(
    struct node_db *ndb, const struct blog_publish_request *request)
{
    if (!ndb || !ndb->open || !request || !request->blog_name ||
        !request->slug || !request->title || !request->body)
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "Blog publish requires an open db and all fields");
    if (!znam_validate_name(request->blog_name))
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog name is not a canonical ZNAM identity");
    if (!db_blog_slug_valid(request->slug))
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog slug must be lowercase words and hyphens");
    if (!db_blog_title_valid(request->title))
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog title is empty, oversized, or unsafe UTF-8");
    if (!db_blog_body_valid(request->body))
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog body is empty, oversized, or unsafe UTF-8");
    if (!db_blog_sequence_shape_valid(request->sequence,
                                      request->previous_event_id))
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog sequence and previous event do not form a link");
    if (request->sequence > 1) {
        struct db_blog_post previous;
        if (!db_blog_post_find(ndb, request->previous_event_id, &previous) ||
            strcmp(previous.blog_name, request->blog_name) != 0 ||
            previous.sequence == UINT64_MAX ||
            request->sequence != previous.sequence + 1)
            return ZCL_ERR(BLOG_ERR_VALIDATION,
                           "Blog predecessor is missing or not sequence-1");
    }
    time_t now = platform_time_wall_time_t();
    if (request->created_at == 0 || request->created_at > INT64_MAX ||
        now < 0 || request->created_at > (uint64_t)now +
                                        BLOG_MAX_FUTURE_SKEW_SECONDS)
        return ZCL_ERR(BLOG_ERR_VALIDATION,
                       "Blog timestamp is invalid or too far in the future");
    struct znam_entry name;
    if (!db_znam_find(ndb, request->blog_name, &name))
        return ZCL_ERR(BLOG_ERR_NAME, "Blog ZNAM identity is not registered");
    if (!zcl_validate_zcl_address(name.owner_address))
        return ZCL_ERR(BLOG_ERR_NAME,
                       "Blog ZNAM owner is not a valid ZClassic address");
    return ZCL_OK;
}

struct zcl_result blog_publication_import_event(
    struct node_db *ndb, const struct zcl_app_signed_event_v1 *event,
    struct db_blog_post *out)
{
    if (!ndb || !ndb->open || !event || !out)
        return ZCL_ERR(BLOG_ERR_ARGS, "blog import requires db, event, and output");
    memset(out, 0, sizeof(*out));
    struct zcl_app_event_scope_v1 scope;
    struct zcl_result scope_result = blog_publication_scope(&scope);
    if (!scope_result.ok)
        return scope_result;
    char why[256];
    if (event->kind != BLOG_EVENT_KIND_PUBLISH ||
        !zcl_app_signed_event_v1_verify(event, &scope, why, sizeof(why)))
        return ZCL_ERR(BLOG_ERR_VERIFY, "Blog event verification failed: %s",
                       event->kind == BLOG_EVENT_KIND_PUBLISH ? why
                                                              : "wrong kind");

    struct db_blog_post post;
    memset(&post, 0, sizeof(post));
    if (!blog_payload_parse(event->payload.data, event->payload.len, &post))
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog payload is malformed or trailing");
    if (!author_address(event->author_key_id, post.author_address,
                        sizeof(post.author_address)))
        return ZCL_ERR(BLOG_ERR_NAME, "Blog author address encoding failed");

    struct znam_entry name;
    if (!db_znam_find(ndb, post.blog_name, &name))
        return ZCL_ERR(BLOG_ERR_NAME, "ZNAM name '%s' is not registered",
                       post.blog_name);
    if (strcmp(name.owner_address, post.author_address) != 0)
        return ZCL_ERR(BLOG_ERR_NAME,
                       "ZNAM owner does not match the Blog event signer");

    memcpy(post.event_id, event->event_id, 32);
    memcpy(post.author_key_id, event->author_key_id, 20);
    memcpy(post.author_pubkey, event->author_pubkey, 33);
    memcpy(post.chain_id, event->chain_id, 32);
    post.sequence = event->sequence;
    memcpy(post.previous_event_id, event->previous_event_id, 32);
    post.event_created_at = (int64_t)event->created_at;
    memcpy(post.signature, event->signature, event->signature_len);
    post.signature_len = event->signature_len;
    post.stored_at = (int64_t)platform_time_wall_time_t();

    /* One verified envelope store feeds Blog today and Social/Chat later.
     * Keep the generic immutable event and the typed Blog projection atomic.
     * This service must own the transaction: inferring ownership from a bare
     * tx_open bit could accidentally join another thread or sync batch and
     * report success for work that its real owner later rolls back. */
    struct db_app_event app_event;
    memset(&app_event, 0, sizeof(app_event));
    app_event.event = *event;
    app_event.received_at = post.stored_at;
    __attribute__((cleanup(db_txn_auto_rollback)))
    struct db_txn *txn = db_txn_begin(ndb, "blog.import_event");
    if (!txn)
        return ZCL_ERR(BLOG_ERR_SAVE,
                       "Blog import requires an exclusive transaction");
    if (!db_app_event_save(ndb, &app_event, &scope))
        return ZCL_ERR(BLOG_ERR_SAVE,
                       "Blog event failed shared AppEvent save");
    if (!db_blog_post_save(ndb, &post))
        return ZCL_ERR(BLOG_ERR_SAVE, "Blog post failed ActiveRecord save");
    if (!db_txn_commit(txn))
        return ZCL_ERR(BLOG_ERR_SAVE,
                       "Blog AppEvent transaction failed to commit");
    if (!db_blog_post_find(ndb, post.event_id, out))
        return ZCL_ERR(BLOG_ERR_SAVE,
                       "Blog post conflicted with slug or author sequence");
    return ZCL_OK;
}

struct zcl_result blog_publication_create(
    struct node_db *ndb, struct wallet *wallet,
    const struct zcl_app_event_signing_binding_v1 *binding,
    const struct blog_publish_request *request,
    struct blog_publish_result *out)
{
    if (!ndb || !wallet || !binding || !request || !out)
        return ZCL_ERR(BLOG_ERR_ARGS, "blog create requires all arguments");
    memset(out, 0, sizeof(*out));
    struct zcl_result validated = blog_publication_validate_request(
        ndb, request);
    if (!validated.ok)
        return validated;
    uint8_t payload[BLOG_BODY_MAX + BLOG_TITLE_MAX + BLOG_NAME_MAX +
                    BLOG_SLUG_MAX + 32];
    size_t payload_len = 0;
    if (!blog_payload_build(request, payload, sizeof(payload), &payload_len))
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog fields exceed canonical limits");

    struct zcl_app_event_intent_v1 intent;
    memset(&intent, 0, sizeof(intent));
    intent.struct_size = sizeof(intent);
    intent.kind = BLOG_EVENT_KIND_PUBLISH;
    intent.sequence = request->sequence;
    intent.created_at = request->created_at;
    memcpy(intent.previous_event_id, request->previous_event_id, 32);
    intent.payload.data = payload;
    intent.payload.len = payload_len;
    struct zcl_app_signed_event_v1 event;
    char why[256];
    if (!zcl_app_signed_event_v1_sign_wallet(
            &intent, binding, wallet, &event, why, sizeof(why)))
        return ZCL_ERR(BLOG_ERR_SIGN, "Blog wallet signing refused: %s", why);

    struct zcl_result imported = blog_publication_import_event(
        ndb, &event, &out->post);
    if (!imported.ok)
        return imported;
    struct zcl_result anchor_result = blog_anchor_script_build(
        out->post.blog_name, out->post.event_id, out->anchor_script,
        sizeof(out->anchor_script), &out->anchor_script_len);
    if (!anchor_result.ok)
        return anchor_result;
    return ZCL_OK;
}

struct zcl_result blog_publication_export_event(
    const struct db_blog_post *post,
    uint8_t *payload, size_t payload_capacity,
    struct zcl_app_signed_event_v1 *out_event)
{
    if (!post || !payload || !out_event)
        return ZCL_ERR(BLOG_ERR_ARGS, "blog export requires all arguments");
    memset(out_event, 0, sizeof(*out_event));
    struct ar_errors errors;
    if (!db_blog_post_validate(post, &errors))
        return ZCL_ERR(BLOG_ERR_VERIFY,
                       "stored Blog row failed ActiveRecord validation");
    struct blog_publish_request request = {
        .blog_name = post->blog_name,
        .slug = post->slug,
        .title = post->title,
        .body = post->body,
        .sequence = post->sequence,
        .created_at = (uint64_t)post->event_created_at,
    };
    memcpy(request.previous_event_id, post->previous_event_id, 32);
    size_t payload_len = 0;
    if (!blog_payload_build(&request, payload, payload_capacity, &payload_len))
        return ZCL_ERR(BLOG_ERR_CODEC, "stored Blog payload cannot be rebuilt");
    out_event->struct_size = sizeof(*out_event);
    out_event->version = ZCL_APP_SIGNED_EVENT_V1;
    memcpy(out_event->app_id, BLOG_APP_ID, sizeof(BLOG_APP_ID));
    memcpy(out_event->topic, BLOG_EVENT_TOPIC, sizeof(BLOG_EVENT_TOPIC));
    out_event->kind = BLOG_EVENT_KIND_PUBLISH;
    out_event->sequence = post->sequence;
    out_event->created_at = (uint64_t)post->event_created_at;
    memcpy(out_event->chain_id, post->chain_id, 32);
    memcpy(out_event->previous_event_id, post->previous_event_id, 32);
    memcpy(out_event->author_key_id, post->author_key_id, 20);
    memcpy(out_event->author_pubkey, post->author_pubkey, 33);
    out_event->payload.data = payload;
    out_event->payload.len = payload_len;
    /* db_blog_post_validate() establishes this bound before either fixed-size
     * signature array is touched. Keep the check at this public boundary even
     * though database reads also clamp corrupt lengths. */
    memcpy(out_event->signature, post->signature, post->signature_len);
    out_event->signature_len = post->signature_len;
    memcpy(out_event->event_id, post->event_id, 32);
    struct zcl_app_event_scope_v1 scope;
    char why[256] = {0};
    struct zcl_result scope_result = blog_publication_scope(&scope);
    if (!scope_result.ok)
        return scope_result;
    if (!zcl_app_signed_event_v1_verify(out_event, &scope, why, sizeof(why)))
        return ZCL_ERR(BLOG_ERR_VERIFY, "stored Blog event is invalid: %s",
                       why[0] ? why : "scope unavailable");
    return ZCL_OK;
}

int blog_publication_recent_verified_summaries(
    struct node_db *ndb, const char *blog_name_or_null,
    struct db_blog_post_summary *out, size_t max)
{
    enum { BLOG_VERIFY_BATCH_MAX = 64 };
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    if (max > BLOG_VERIFY_BATCH_MAX)
        max = BLOG_VERIFY_BATCH_MAX;
    struct db_blog_post_summary candidates[BLOG_VERIFY_BATCH_MAX];
    int count = db_blog_post_recent_summaries(
        ndb, blog_name_or_null, candidates, max);
    int accepted = 0;
    for (int i = 0; i < count; i++) {
        struct db_blog_post post;
        if (!db_blog_post_find(ndb, candidates[i].event_id, &post))
            continue;
        uint8_t payload[BLOG_BODY_MAX + BLOG_TITLE_MAX + BLOG_NAME_MAX +
                        BLOG_SLUG_MAX + 32];
        struct zcl_app_signed_event_v1 event;
        struct zcl_result verified = blog_publication_export_event(
            &post, payload, sizeof(payload), &event);
        if (!verified.ok)
            continue;
        out[accepted++] = candidates[i];
    }
    return accepted;
}

struct zcl_result blog_anchor_script_build(
    const char *blog_name, const uint8_t event_id[32],
    uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    size_t name_len = 0;
    if (!blog_name || !event_id || !out || !out_len || out_capacity == 0 ||
        !zcl_bytes_any_set(event_id, 32) ||
        !payload_field_size(blog_name, BLOG_NAME_MAX, &name_len))
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "Blog anchor requires canonical name, event ID, and output");
    uint8_t version = 1;
    size_t off = 0;
    out[off++] = 0x6a;
    bool ok = push_data_checked(out, &off, out_capacity,
                                k_blog_anchor_lokad,
                                sizeof(k_blog_anchor_lokad)) &&
        push_data_checked(out, &off, out_capacity, &version, 1) &&
        push_data_checked(out, &off, out_capacity,
                          (const uint8_t *)blog_name, name_len) &&
        push_data_checked(out, &off, out_capacity, event_id, 32);
    if (!ok || off > MAX_OP_RETURN_RELAY)
        return ZCL_ERR(BLOG_ERR_CODEC,
                       "Blog anchor exceeds canonical relay policy");
    *out_len = off;
    return ZCL_OK;
}

struct zcl_result blog_anchor_script_parse(
    const uint8_t *script, size_t script_len,
    char blog_name[BLOG_NAME_MAX + 1], uint8_t event_id[32])
{
    if (!blog_name || !event_id)
        return ZCL_ERR(BLOG_ERR_ARGS, "Blog anchor parse outputs are required");
    blog_name[0] = 0;
    memset(event_id, 0, 32);
    if (!script || script_len < 1 || script_len > MAX_OP_RETURN_RELAY ||
        script[0] != 0x6a)
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog anchor framing is invalid");
    const uint8_t *p = script + 1;
    const uint8_t *end = script + script_len;
    const uint8_t *data = NULL;
    size_t len = 0;
    p = read_push(p, end, &data, &len);
    if (!p || len != sizeof(k_blog_anchor_lokad) ||
        memcmp(data, k_blog_anchor_lokad, len) != 0)
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog anchor lokad ID is invalid");
    p = read_push(p, end, &data, &len);
    if (!p || len != 1 || data[0] != 1)
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog anchor version is unsupported");
    p = read_push(p, end, &data, &len);
    if (!p || len == 0 || len > BLOG_NAME_MAX || memchr(data, 0, len))
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog anchor ZNAM field is invalid");
    memcpy(blog_name, data, len);
    blog_name[len] = 0;
    if (!znam_validate_name(blog_name))
        return ZCL_ERR(BLOG_ERR_CODEC, "Blog anchor ZNAM name is noncanonical");
    p = read_push(p, end, &data, &len);
    if (!p || len != 32 || p != end)
        return ZCL_ERR(BLOG_ERR_CODEC,
                       "Blog anchor event ID is missing or has trailing data");
    memcpy(event_id, data, 32);
    uint8_t canonical[BLOG_ANCHOR_SCRIPT_MAX];
    size_t canonical_len = 0;
    struct zcl_result rebuilt = blog_anchor_script_build(
        blog_name, event_id, canonical, sizeof(canonical), &canonical_len);
    if (!rebuilt.ok ||
        canonical_len != script_len ||
        memcmp(canonical, script, script_len) != 0)
        return ZCL_ERR(BLOG_ERR_CODEC,
                       "Blog anchor uses a nonminimal encoding");
    return ZCL_OK;
}


struct zcl_result blog_publication_observe_projection(
    struct node_db *ndb, const uint8_t event_id[32],
    struct blog_projection_observation *out)
{
    if (!ndb || !ndb->open || !event_id || !out)
        return ZCL_ERR(BLOG_ERR_ARGS,
                       "blog anchor observation requires valid arguments");
    memset(out, 0, sizeof(*out));
    out->projection_only = true;
    out->served_frontier_proven = false;
    out->receipt.status = BLOG_PUBLICATION_UNRESOLVED;
    out->receipt.block_height = -1;

    struct db_blog_post post;
    if (!db_blog_post_find(ndb, event_id, &post))
        return ZCL_ERR(BLOG_ERR_SAVE, "Blog event is not stored locally");
    uint8_t script[BLOG_ANCHOR_SCRIPT_MAX];
    size_t script_len = 0;
    struct zcl_result built = blog_anchor_script_build(
        post.blog_name, post.event_id, script, sizeof(script), &script_len);
    if (!built.ok)
        return built;
    struct db_blog_chain_anchor anchor;
    if (!db_blog_chain_anchor_find(ndb, script, script_len, &anchor))
        return ZCL_OK; /* lossy projection: unresolved, never global absence */

    struct db_blog_publication_receipt existing;
    bool has_existing = db_blog_publication_receipt_find_by_event(
        ndb, post.event_id, &existing) &&
        strcmp(existing.blog_name, post.blog_name) == 0 &&
        memcmp(existing.author_key_id, post.author_key_id, 20) == 0;
    struct znam_entry name;
    bool current_name_matches = db_znam_find(ndb, post.blog_name, &name) &&
        strcmp(name.owner_address, post.author_address) == 0;
    if (!current_name_matches && !has_existing)
        return ZCL_ERR(BLOG_ERR_NAME,
                       "ZNAM owner epoch is unavailable for this anchor");

    out->observed = true;
    memcpy(out->receipt.txid, anchor.txid, 32);
    memcpy(out->receipt.event_id, post.event_id, 32);
    (void)snprintf(out->receipt.blog_name, sizeof(out->receipt.blog_name),
                   "%s", post.blog_name);
    memcpy(out->receipt.author_key_id, post.author_key_id, 20);
    memcpy(out->receipt.znam_reg_txid,
           current_name_matches ? name.reg_txid : existing.znam_reg_txid, 32);
    out->receipt.block_height = anchor.has_transaction
        ? anchor.transaction_block_height : anchor.op_return_height;
    if (anchor.has_transaction)
        memcpy(out->receipt.block_hash, anchor.transaction_block_hash, 32);
    out->receipt.status = BLOG_PUBLICATION_UNRESOLVED;
    if (anchor.has_transaction && anchor.has_canonical_block &&
        anchor.op_return_height == anchor.transaction_block_height) {
        out->receipt.status = memcmp(anchor.transaction_block_hash,
                                     anchor.canonical_block_hash, 32) == 0
            ? BLOG_PUBLICATION_CONFIRMED : BLOG_PUBLICATION_ORPHANED;
    }
    out->receipt.observed_at = (int64_t)platform_time_wall_time_t();
    if (!db_blog_publication_receipt_save(ndb, &out->receipt))
        return ZCL_ERR(BLOG_ERR_CHAIN,
                       "Blog projection receipt failed ActiveRecord save");
    return ZCL_OK;
}
