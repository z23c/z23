/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/app_platform.h"

#include "base/bytes.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const uint8_t g_event_id_domain[] = "zcl.app.event.id.v1";
static const uint8_t g_event_sig_domain[] = "zcl.app.event.sig.v1";

#define ZCL_APP_EVENT_BINDING_MAGIC UINT64_C(0x5a434c42494e4431)

/* Deliberately private. The future Core wallet broker will be the only
 * production constructor and will resolve active manifest + local grant
 * records before filling this binding. */
struct zcl_app_event_signing_binding_v1 {
    uint32_t struct_size;
    uint32_t operation;
    uint64_t app_generation;
    uint64_t grant_revision;
    uint8_t grant_id[32];
    uint8_t manifest_digest[32];
    struct zcl_app_event_scope_v1 scope;
    uint8_t author_key_id[ZCL_APP_EVENT_KEY_ID_SIZE];
    uint64_t magic;
};

static bool reject(char *why, size_t why_sz, const char *fmt, ...)
{
    if (why && why_sz > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(why, why_sz, fmt, ap);
        va_end(ap);
    }
    return false;
}

static bool valid_token_char(unsigned char c, bool allow_slash)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_' || c == '-' || c == '.' ||
           (allow_slash && c == '/');
}

static bool valid_token(const char *value, size_t max_len,
                        bool allow_slash)
{
    if (!value || !value[0])
        return false;
    size_t len = strlen(value);
    if (len > max_len)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (valid_token_char(c, allow_slash))
            continue;
        return false;
    }
    return true;
}

static bool valid_sha256(const char *hex)
{
    if (!hex || strlen(hex) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

static bool event_token_len(const char *value, size_t max_len,
                            size_t *len_out)
{
    if (!value || !len_out)
        return false;
    const char *end = memchr(value, 0, max_len + 1);
    if (!end || end == value)
        return false;
    size_t len = (size_t)(end - value);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (valid_token_char(c, false))
            continue;
        return false;
    }
    *len_out = len;
    return true;
}

static bool event_content_validate(const struct zcl_app_signed_event_v1 *event,
                                   size_t *app_len, size_t *topic_len,
                                   char *why, size_t why_sz)
{
    size_t alen = 0, tlen = 0;
    if (!event)
        return reject(why, why_sz, "signed event is null");
    if (event->struct_size < sizeof(*event) ||
        event->version != ZCL_APP_SIGNED_EVENT_V1)
        return reject(why, why_sz, "signed event version mismatch");
    if (!event_token_len(event->app_id, ZCL_APP_ID_MAX, &alen) ||
        !event_token_len(event->topic, ZCL_APP_TOPIC_MAX, &tlen))
        return reject(why, why_sz, "invalid signed event app or topic");
    if (event->kind == 0 || event->sequence == 0 || event->created_at == 0)
        return reject(why, why_sz, "invalid event kind, sequence, or time");
    if (!zcl_bytes_any_set(event->chain_id, sizeof(event->chain_id)))
        return reject(why, why_sz, "event chain id is empty");
    bool has_previous = zcl_bytes_any_set(event->previous_event_id,
                                      sizeof(event->previous_event_id));
    if ((event->sequence == 1 && has_previous) ||
        (event->sequence > 1 && !has_previous))
        return reject(why, why_sz, "event sequence and previous id disagree");
    if (event->payload.len > ZCL_APP_EVENT_PAYLOAD_MAX ||
        (event->payload.len > 0 && !event->payload.data))
        return reject(why, why_sz, "event payload is invalid or oversized");
    if (app_len)
        *app_len = alen;
    if (topic_len)
        *topic_len = tlen;
    return true;
}

static bool event_base_validate(const struct zcl_app_signed_event_v1 *event,
                                size_t *app_len, size_t *topic_len,
                                char *why, size_t why_sz)
{
    if (!event_content_validate(event, app_len, topic_len, why, why_sz))
        return false;
    if ((event->author_pubkey[0] != 0x02 &&
         event->author_pubkey[0] != 0x03) ||
        !zcl_bytes_any_set(event->author_key_id,
                       sizeof(event->author_key_id)))
        return reject(why, why_sz, "event author is not a compressed key");
    return true;
}

static size_t event_unsigned_size(
    const struct zcl_app_signed_event_v1 *event,
    size_t app_len, size_t topic_len)
{
    return 4 + ZCL_APP_EVENT_CHAIN_ID_SIZE + 2 + app_len +
        2 + topic_len + 4 + ZCL_APP_EVENT_KEY_ID_SIZE +
        ZCL_APP_EVENT_PUBKEY_SIZE + 8 + 8 + 32 + 4 + event->payload.len;
}

static bool event_scope_validate(const struct zcl_app_signed_event_v1 *event,
                                 const struct zcl_app_event_scope_v1 *scope,
                                 size_t framed_signature_len,
                                 char *why, size_t why_sz)
{
    size_t event_app_len = 0, event_topic_len = 0;
    size_t scope_app_len = 0, scope_topic_len = 0;
    if (!scope || scope->struct_size < sizeof(*scope) ||
        scope->max_event_bytes == 0 ||
        framed_signature_len == 0 ||
        framed_signature_len > ZCL_APP_EVENT_SIGNATURE_MAX ||
        !event_token_len(scope->app_id, ZCL_APP_ID_MAX, &scope_app_len) ||
        !event_token_len(scope->topic, ZCL_APP_TOPIC_MAX, &scope_topic_len) ||
        !zcl_bytes_any_set(scope->chain_id, sizeof(scope->chain_id)) ||
        !event_token_len(event->app_id, ZCL_APP_ID_MAX, &event_app_len) ||
        !event_token_len(event->topic, ZCL_APP_TOPIC_MAX, &event_topic_len))
        return reject(why, why_sz, "event scope is invalid");
    if (event_app_len != scope_app_len ||
        event_topic_len != scope_topic_len ||
        memcmp(event->app_id, scope->app_id, event_app_len) != 0 ||
        memcmp(event->topic, scope->topic, event_topic_len) != 0 ||
        memcmp(event->chain_id, scope->chain_id,
               ZCL_APP_EVENT_CHAIN_ID_SIZE) != 0)
        return reject(why, why_sz, "event is outside its app scope");
    size_t framed_size = event_unsigned_size(
        event, event_app_len, event_topic_len) + 2 + framed_signature_len;
    if (framed_size > scope->max_event_bytes)
        return reject(why, why_sz, "event exceeds topic byte limit");
    return true;
}

static bool event_binding_validate(
    const struct zcl_app_event_signing_binding_v1 *binding,
    char *why, size_t why_sz)
{
    size_t app_len = 0, topic_len = 0;
    if (!binding || binding->struct_size != sizeof(*binding) ||
        binding->magic != ZCL_APP_EVENT_BINDING_MAGIC ||
        binding->operation != ZCL_APP_WALLET_OP_SIGN_EVENT_V1 ||
        binding->app_generation == 0 || binding->grant_revision == 0 ||
        !zcl_bytes_any_set(binding->grant_id, sizeof(binding->grant_id)) ||
        !zcl_bytes_any_set(binding->manifest_digest,
                       sizeof(binding->manifest_digest)) ||
        !zcl_bytes_any_set(binding->author_key_id,
                       sizeof(binding->author_key_id)) ||
        binding->scope.struct_size < sizeof(binding->scope) ||
        binding->scope.max_event_bytes == 0 ||
        !event_token_len(binding->scope.app_id, ZCL_APP_ID_MAX, &app_len) ||
        !event_token_len(binding->scope.topic, ZCL_APP_TOPIC_MAX, &topic_len) ||
        !zcl_bytes_any_set(binding->scope.chain_id,
                       sizeof(binding->scope.chain_id)))
        return reject(why, why_sz,
                      "event signing binding is absent, stale, or invalid");
    return true;
}

#ifdef ZCL_TESTING
bool zcl_app_event_signing_binding_v1_test_create(
    const struct zcl_app_event_binding_test_spec_v1 *spec,
    struct zcl_app_event_signing_binding_v1 **out_binding,
    char *why, size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    if (!out_binding)
        return reject(why, why_sz, "binding output is null");
    *out_binding = NULL;
    if (!spec || spec->struct_size < sizeof(*spec) ||
        !spec->grant_active ||
        spec->operation != ZCL_APP_WALLET_OP_SIGN_EVENT_V1)
        return reject(why, why_sz, "test signing grant is inactive or invalid");

    struct zcl_app_event_signing_binding_v1 candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.struct_size = sizeof(candidate);
    candidate.operation = spec->operation;
    candidate.app_generation = spec->app_generation;
    candidate.grant_revision = spec->grant_revision;
    memcpy(candidate.grant_id, spec->grant_id, sizeof(candidate.grant_id));
    memcpy(candidate.manifest_digest, spec->manifest_digest,
           sizeof(candidate.manifest_digest));
    candidate.scope = spec->scope;
    memcpy(candidate.author_key_id, spec->author_key_id,
           sizeof(candidate.author_key_id));
    candidate.magic = ZCL_APP_EVENT_BINDING_MAGIC;
    if (!event_binding_validate(&candidate, why, why_sz))
        return false;

    struct zcl_app_event_signing_binding_v1 *created =
        zcl_calloc(1, sizeof(*created), "test app signing binding");
    if (!created)
        return reject(why, why_sz, "test signing binding allocation failed");
    *created = candidate;
    *out_binding = created;
    return true;
}

void zcl_app_event_signing_binding_v1_test_destroy(
    struct zcl_app_event_signing_binding_v1 *binding)
{
    if (!binding)
        return;
    memory_cleanse(binding, sizeof(*binding));
    free(binding);
}
#endif

typedef bool (*event_emit_fn)(void *ctx, const uint8_t *data, size_t len);

static bool emit_u16(event_emit_fn emit, void *ctx, uint16_t value)
{
    uint8_t bytes[2] = { (uint8_t)value, (uint8_t)(value >> 8) };
    return emit(ctx, bytes, sizeof(bytes));
}

static bool emit_u32(event_emit_fn emit, void *ctx, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)value, (uint8_t)(value >> 8),
        (uint8_t)(value >> 16), (uint8_t)(value >> 24)
    };
    return emit(ctx, bytes, sizeof(bytes));
}

static bool emit_u64(event_emit_fn emit, void *ctx, uint64_t value)
{
    uint8_t bytes[8];
    for (size_t i = 0; i < sizeof(bytes); i++)
        bytes[i] = (uint8_t)(value >> (8 * i));
    return emit(ctx, bytes, sizeof(bytes));
}

static bool event_emit_unsigned(const struct zcl_app_signed_event_v1 *event,
                                size_t app_len, size_t topic_len,
                                event_emit_fn emit, void *ctx)
{
    return emit_u32(emit, ctx, event->version) &&
        emit(ctx, event->chain_id, sizeof(event->chain_id)) &&
        emit_u16(emit, ctx, (uint16_t)app_len) &&
        emit(ctx, (const uint8_t *)event->app_id, app_len) &&
        emit_u16(emit, ctx, (uint16_t)topic_len) &&
        emit(ctx, (const uint8_t *)event->topic, topic_len) &&
        emit_u32(emit, ctx, event->kind) &&
        emit(ctx, event->author_key_id, sizeof(event->author_key_id)) &&
        emit(ctx, event->author_pubkey, sizeof(event->author_pubkey)) &&
        emit_u64(emit, ctx, event->sequence) &&
        emit_u64(emit, ctx, event->created_at) &&
        emit(ctx, event->previous_event_id,
             sizeof(event->previous_event_id)) &&
        emit_u32(emit, ctx, (uint32_t)event->payload.len) &&
        emit(ctx, event->payload.data, event->payload.len);
}

struct event_encode_sink {
    uint8_t *out;
    size_t capacity;
    size_t used;
};

static bool event_encode_emit(void *ctx, const uint8_t *data, size_t len)
{
    struct event_encode_sink *sink = ctx;
    if (len > sink->capacity - sink->used)
        return false;
    if (len > 0)
        memcpy(sink->out + sink->used, data, len);
    sink->used += len;
    return true;
}

static bool event_hash_emit(void *ctx, const uint8_t *data, size_t len)
{
    sha3_256_write(ctx, data, len);
    return true;
}

bool zcl_app_signed_event_v1_canonical_unsigned(
    const struct zcl_app_signed_event_v1 *event,
    uint8_t *out, size_t out_capacity, size_t *out_len,
    char *why, size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    if (!out_len)
        return reject(why, why_sz, "canonical event length output is null");
    *out_len = 0;
    size_t app_len = 0, topic_len = 0;
    if (!event_base_validate(event, &app_len, &topic_len, why, why_sz))
        return false;
    size_t required = event_unsigned_size(event, app_len, topic_len);
    *out_len = required;
    if (!out || out_capacity < required)
        return reject(why, why_sz, "canonical event output needs %zu bytes",
                      required);
    struct event_encode_sink sink = {
        .out = out,
        .capacity = out_capacity,
        .used = 0,
    };
    if (!event_emit_unsigned(event, app_len, topic_len,
                             event_encode_emit, &sink))
        return reject(why, why_sz, "canonical event encoding overflow");
    return true;
}

bool zcl_app_signed_event_v1_id(
    const struct zcl_app_signed_event_v1 *event,
    uint8_t out_event_id[32], char *why, size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    if (!out_event_id)
        return reject(why, why_sz, "event id output is null");
    memset(out_event_id, 0, 32);
    size_t app_len = 0, topic_len = 0;
    if (!event_base_validate(event, &app_len, &topic_len, why, why_sz))
        return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, g_event_id_domain, sizeof(g_event_id_domain));
    if (!event_emit_unsigned(event, app_len, topic_len,
                             event_hash_emit, &hash))
        return reject(why, why_sz, "event id canonicalization failed");
    sha3_256_finalize(&hash, out_event_id);
    return true;
}

static void event_signing_digest(const uint8_t event_id[32],
                                 struct uint256 *digest)
{
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, g_event_sig_domain, sizeof(g_event_sig_domain));
    sha3_256_write(&hash, event_id, 32);
    sha3_256_finalize(&hash, digest->data);
}

static bool event_signature_is_canonical(const uint8_t *sig, size_t len)
{
    static const uint8_t half_order[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    };
    if (!sig || len < 8 || len > ZCL_APP_EVENT_SIGNATURE_MAX ||
        sig[0] != 0x30 || sig[1] != len - 2 || sig[2] != 0x02)
        return false;
    size_t len_r = sig[3];
    if (len_r == 0 || len_r > 33 || len_r > len - 7 ||
        (sig[4] & 0x80) != 0 ||
        (len_r > 1 && sig[4] == 0 && (sig[5] & 0x80) == 0))
        return false;
    size_t start_s = 4 + len_r;
    if (sig[start_s] != 0x02)
        return false;
    size_t len_s = sig[start_s + 1];
    if (len_s == 0 || len_s > 33 || start_s + 2 + len_s != len ||
        (sig[start_s + 2] & 0x80) != 0 ||
        (len_s > 1 && sig[start_s + 2] == 0 &&
         (sig[start_s + 3] & 0x80) == 0))
        return false;
    const uint8_t *s = sig + start_s + 2;
    if (len_s == 33) {
        if (s[0] != 0)
            return false;
        s++;
        len_s--;
    }
    uint8_t s_value[32] = {0};
    memcpy(s_value + sizeof(s_value) - len_s, s, len_s);
    return memcmp(s_value, half_order, sizeof(s_value)) <= 0;
}

bool zcl_app_signed_event_v1_sign_wallet(
    const struct zcl_app_event_intent_v1 *intent,
    const struct zcl_app_event_signing_binding_v1 *binding,
    struct wallet *wallet,
    struct zcl_app_signed_event_v1 *out_event,
    char *why, size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    if (!out_event)
        return reject(why, why_sz, "event signer output is null");
    memset(out_event, 0, sizeof(*out_event));
    if (!intent || !wallet || intent->struct_size < sizeof(*intent))
        return reject(why, why_sz, "event signer input is null");
    if (!event_binding_validate(binding, why, why_sz))
        return false;

    struct zcl_app_signed_event_v1 candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.struct_size = sizeof(candidate);
    candidate.version = ZCL_APP_SIGNED_EVENT_V1;
    memcpy(candidate.app_id, binding->scope.app_id,
           sizeof(candidate.app_id));
    memcpy(candidate.topic, binding->scope.topic,
           sizeof(candidate.topic));
    candidate.kind = intent->kind;
    candidate.sequence = intent->sequence;
    candidate.created_at = intent->created_at;
    memcpy(candidate.chain_id, binding->scope.chain_id,
           sizeof(candidate.chain_id));
    memcpy(candidate.previous_event_id, intent->previous_event_id,
           sizeof(candidate.previous_event_id));
    candidate.payload = intent->payload;
    size_t app_len = 0, topic_len = 0;
    if (!event_content_validate(&candidate, &app_len, &topic_len,
                                why, why_sz) ||
        !event_scope_validate(&candidate, &binding->scope, 1, why, why_sz))
        return false;

    struct key_id requested_key_id;
    memcpy(requested_key_id.id.data, binding->author_key_id,
           sizeof(binding->author_key_id));
    struct privkey key;
    privkey_init(&key);
    zcl_mutex_lock(&wallet->cs);
    bool have_key = keystore_get_key(&wallet->keystore,
                                     &requested_key_id, &key);
    zcl_mutex_unlock(&wallet->cs);
    if (!have_key) {
        memory_cleanse(&key, sizeof(key));
        return reject(why, why_sz, "publishing key is not wallet-owned");
    }

    bool ok = false;
    struct pubkey pubkey;
    if (!privkey_is_valid(&key) || !privkey_is_compressed(&key) ||
        !privkey_get_pubkey(&key, &pubkey) ||
        pubkey.size != ZCL_APP_EVENT_PUBKEY_SIZE) {
        reject(why, why_sz, "publishing key must be valid and compressed");
        goto out;
    }
    memcpy(candidate.author_pubkey, pubkey.vch,
           sizeof(candidate.author_pubkey));
    struct key_id key_id = pubkey_get_id(&pubkey);
    if (memcmp(key_id.id.data, binding->author_key_id,
               sizeof(binding->author_key_id)) != 0) {
        reject(why, why_sz, "publishing key principal mismatch");
        goto out;
    }
    memcpy(candidate.author_key_id, key_id.id.data,
           sizeof(candidate.author_key_id));

    if (!event_base_validate(&candidate, &app_len, &topic_len, why, why_sz))
        goto out;
    if (!zcl_app_signed_event_v1_id(&candidate, candidate.event_id,
                                    why, why_sz))
        goto out;
    struct uint256 digest;
    event_signing_digest(candidate.event_id, &digest);
    size_t signature_len = sizeof(candidate.signature);
    if (!privkey_sign(&key, &digest, candidate.signature, &signature_len) ||
        !event_signature_is_canonical(candidate.signature, signature_len)) {
        reject(why, why_sz, "event signature failed canonical validation");
        goto out;
    }
    candidate.signature_len = (uint32_t)signature_len;
    if (!event_scope_validate(&candidate, &binding->scope, signature_len,
                              why, why_sz))
        goto out;
    *out_event = candidate;
    ok = true;

out:
    memory_cleanse(&key, sizeof(key));
    if (!ok)
        memset(out_event, 0, sizeof(*out_event));
    return ok;
}

bool zcl_app_signed_event_v1_verify(
    const struct zcl_app_signed_event_v1 *event,
    const struct zcl_app_event_scope_v1 *scope,
    char *why, size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    size_t app_len = 0, topic_len = 0;
    if (!event_base_validate(event, &app_len, &topic_len, why, why_sz))
        return false;
    if (event->signature_len == 0 ||
        event->signature_len > sizeof(event->signature))
        return reject(why, why_sz, "event signature length is invalid");
    if (!event_signature_is_canonical(event->signature,
                                      event->signature_len))
        return reject(why, why_sz, "event signature encoding is noncanonical");
    if (!event_scope_validate(event, scope, event->signature_len,
                              why, why_sz))
        return false;

    struct pubkey pubkey;
    pubkey_set(&pubkey, event->author_pubkey,
               ZCL_APP_EVENT_PUBKEY_SIZE);
    struct key_id key_id = pubkey_get_id(&pubkey);
    if (memcmp(key_id.id.data, event->author_key_id,
               sizeof(event->author_key_id)) != 0)
        return reject(why, why_sz, "event author key id mismatch");

    uint8_t event_id[32];
    if (!zcl_app_signed_event_v1_id(event, event_id, why, why_sz))
        return false;
    if (memcmp(event_id, event->event_id, sizeof(event_id)) != 0)
        return reject(why, why_sz, "event id mismatch");

    struct uint256 digest;
    event_signing_digest(event_id, &digest);
    if (!pubkey_verify(&pubkey, &digest, event->signature,
                       event->signature_len))
        return reject(why, why_sz, "event signature is invalid");
    return true;
}

const char *zcl_app_capability_name(uint64_t cap)
{
    switch (cap) {
    case ZCL_APP_CAP_CHAIN_READ: return "chain_read";
    case ZCL_APP_CAP_SIGNED_EVENTS: return "signed_events";
    case ZCL_APP_CAP_RESIDENT_STATE: return "resident_state";
    case ZCL_APP_CAP_WEB_ROUTES: return "web_routes";
    case ZCL_APP_CAP_ONION_BINDING: return "onion_binding";
    case ZCL_APP_CAP_ZNAM_BINDING: return "znam_binding";
    case ZCL_APP_CAP_P2P_TOPICS: return "p2p_topics";
    case ZCL_APP_CAP_WALLET_REQUESTS: return "wallet_requests";
    case ZCL_APP_CAP_SCHEDULED_JOBS: return "scheduled_jobs";
    case ZCL_APP_CAP_CLOCK: return "clock";
    case ZCL_APP_CAP_RANDOM: return "random";
    default: return NULL;
    }
}

bool zcl_app_manifest_v1_validate(const struct zcl_app_manifest_v1 *m,
                                  uint64_t host_caps,
                                  const char *expected_build,
                                  char *why,
                                  size_t why_sz)
{
    if (why && why_sz > 0)
        why[0] = 0;
    if (!m)
        return reject(why, why_sz, "manifest is null");
    if (m->struct_size < sizeof(*m) ||
        m->manifest_version != ZCL_APP_MANIFEST_V1 ||
        m->required_host_abi != ZCL_APP_HOST_ABI_V1)
        return reject(why, why_sz, "app or host ABI mismatch");
    if (!valid_token(m->app_id, ZCL_APP_ID_MAX, false))
        return reject(why, why_sz, "invalid app_id");
    if (!m->display_name || !m->display_name[0] ||
        !valid_token(m->app_version, 31, false))
        return reject(why, why_sz, "invalid display name or version");
    if (!m->build_identity || !expected_build ||
        strcmp(m->build_identity, expected_build) != 0)
        return reject(why, why_sz, "build identity mismatch");
    if (!valid_sha256(m->content_sha256))
        return reject(why, why_sz, "invalid content sha256");
    if ((m->required_capabilities & ~host_caps) != 0)
        return reject(why, why_sz, "required host capability is unavailable");
    if (m->route_count > 0 && !m->routes)
        return reject(why, why_sz, "route table missing");
    if (m->topic_count > 0 && !m->topics)
        return reject(why, why_sz, "topic table missing");
    if (!m->self_test || !m->quiesce)
        return reject(why, why_sz, "self-test or quiescence hook missing");

    for (size_t i = 0; i < m->route_count; i++) {
        const struct zcl_app_route_v1 *route = &m->routes[i];
        if (route->struct_size < sizeof(*route) || !route->handler ||
            !valid_token(route->method, 16, false) ||
            !valid_token(route->path, ZCL_APP_ROUTE_MAX, true) ||
            route->path[0] != '/')
            return reject(why, why_sz, "invalid app route at index %zu", i);
        for (size_t j = 0; j < i; j++) {
            if (strcmp(route->method, m->routes[j].method) == 0 &&
                strcmp(route->path, m->routes[j].path) == 0)
                return reject(why, why_sz, "duplicate app route at index %zu", i);
        }
    }
    for (size_t i = 0; i < m->topic_count; i++) {
        const struct zcl_app_topic_v1 *topic = &m->topics[i];
        if (topic->struct_size < sizeof(*topic) ||
            !valid_token(topic->name, ZCL_APP_TOPIC_MAX, false) ||
            topic->wire_version == 0 || topic->max_event_bytes == 0)
            return reject(why, why_sz, "invalid app topic at index %zu", i);
        for (size_t j = 0; j < i; j++) {
            if (strcmp(topic->name, m->topics[j].name) == 0)
                return reject(why, why_sz,
                              "duplicate app topic at index %zu", i);
        }
    }
    if (m->state_schema_version > 0) {
        if (!(m->required_capabilities & ZCL_APP_CAP_RESIDENT_STATE))
            return reject(why, why_sz, "state schema lacks resident_state capability");
        if (!m->migration || m->migration->struct_size < sizeof(*m->migration) ||
            !m->migration->prepare || !m->migration->commit ||
            !m->migration->abort)
            return reject(why, why_sz, "stateful app lacks transactional migration hooks");
    }
    return true;
}
