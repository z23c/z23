/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "session/zses.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

const char *zses_refuse_name(enum zses_refuse code)
{
    switch (code) {
    case ZSES_OK: return "ok";
    case ZSES_REFUSE_UNSIGNED: return "unsigned";
    case ZSES_REFUSE_WRONG_KEY: return "wrong_key";
    case ZSES_REFUSE_TAMPERED: return "tampered";
    case ZSES_REFUSE_EXPIRED: return "expired";
    case ZSES_REFUSE_MALFORMED: return "malformed";
    case ZSES_REFUSE_BAD_ENDPOINT: return "bad_endpoint";
    case ZSES_REFUSE_CLEARNET_FORBIDDEN: return "clearnet_forbidden";
    case ZSES_REFUSE_NO_ONION: return "no_onion";
    }
    return "malformed";
}

bool zses_looks_onion(const char *endpoint)
{
    return endpoint && strstr(endpoint, ".onion") != NULL;
}

bool zses_looks_clearnet(const char *endpoint)
{
    if (!endpoint || !endpoint[0])
        return false;
    if (zses_looks_onion(endpoint))
        return false;
    if (endpoint[0] == '[')
        return true; /* IPv6 */
    return endpoint[0] >= '0' && endpoint[0] <= '9';
}

bool zses_pick_endpoint(const char *posture, const char *onion,
                        const char *clearnet, char *out, size_t out_cap,
                        enum zses_refuse *refuse)
{
    if (!out || out_cap < 2)
        LOG_FAIL("zses", "pick_endpoint: out buffer missing");
    out[0] = '\0';
    if (refuse)
        *refuse = ZSES_OK;
    const char *p = (posture && posture[0]) ? posture : "onion";
    if (strcmp(p, "none") == 0) {
        if (refuse)
            *refuse = ZSES_REFUSE_NO_ONION;
        LOG_FAIL("zses", "pick_endpoint: posture=none publishes nothing");
    }
    if (strcmp(p, "clearnet") == 0) {
        const char *ep = (clearnet && clearnet[0]) ? clearnet : onion;
        if (!ep || !ep[0]) {
            if (refuse)
                *refuse = ZSES_REFUSE_NO_ONION;
            LOG_FAIL("zses", "pick_endpoint: clearnet posture has no endpoint");
        }
        if (strlen(ep) >= out_cap) {
            if (refuse)
                *refuse = ZSES_REFUSE_BAD_ENDPOINT;
            LOG_FAIL("zses", "pick_endpoint: endpoint too long");
        }
        memcpy(out, ep, strlen(ep) + 1);
        return true;
    }
    /* Default onion: never emit a numeric IP. */
    if (!onion || !onion[0] || !zses_looks_onion(onion)) {
        if (refuse)
            *refuse = ZSES_REFUSE_NO_ONION;
        LOG_FAIL("zses", "pick_endpoint: onion posture needs an onion endpoint");
    }
    if (zses_looks_clearnet(onion)) {
        if (refuse)
            *refuse = ZSES_REFUSE_CLEARNET_FORBIDDEN;
        LOG_FAIL("zses", "pick_endpoint: refused clearnet under onion posture");
    }
    if (strlen(onion) >= out_cap) {
        if (refuse)
            *refuse = ZSES_REFUSE_BAD_ENDPOINT;
        LOG_FAIL("zses", "pick_endpoint: onion endpoint too long");
    }
    memcpy(out, onion, strlen(onion) + 1);
    return true;
}

static bool zses_canonical(const struct zses_invite *inv, char *buf, size_t cap)
{
    if (!inv || !buf)
        return false;
    int n = snprintf(buf, cap,
                     "zses:v1\nendpoint=%s\nexpires=%lld\ncapability-tag=%s\n",
                     inv->endpoint, (long long)inv->expires,
                     inv->capability_tag);
    return n > 0 && (size_t)n < cap;
}

static void zses_body_hash(const struct zses_invite *inv, struct uint256 *out)
{
    char canon[512];
    unsigned char digest[SHA256_OUTPUT_SIZE];
    memset(out, 0, sizeof(*out));
    if (!zses_canonical(inv, canon, sizeof(canon)))
        return;
    hash256((const unsigned char *)canon, strlen(canon), digest);
    memcpy(out->data, digest, 32);
}

bool zses_invite_sign(struct zses_invite *inv, const struct privkey *k)
{
    if (!inv || !k)
        LOG_FAIL("zses", "invite_sign: null invite or key");
    if (!ecc_start_once() || !ecc_verify_init_once())
        LOG_FAIL("zses", "invite_sign: secp256k1 context init failed");
    if (!inv->endpoint[0])
        LOG_FAIL("zses", "invite_sign: empty endpoint");
    if (inv->expires <= 0)
        LOG_FAIL("zses", "invite_sign: expires must be positive");
    if (!inv->capability_tag[0])
        memcpy(inv->capability_tag, "session", 8);
    struct pubkey pk;
    if (!privkey_get_pubkey(k, &pk) || pk.size != ZSES_PUBKEY_LEN)
        LOG_FAIL("zses", "invite_sign: could not derive compressed pubkey");
    memcpy(inv->pubkey, pk.vch, ZSES_PUBKEY_LEN);
    inv->has_pubkey = true;
    struct uint256 hash;
    zses_body_hash(inv, &hash);
    if (!privkey_sign_compact(k, &hash, inv->signature))
        LOG_FAIL("zses", "invite_sign: secp256k1 compact sign failed");
    inv->has_signature = true;
    return true;
}

enum zses_refuse zses_invite_verify(const struct zses_invite *inv, int64_t now)
{
    if (!inv) {
        LOG_ERROR("zses", "invite_verify: null invite");
        return ZSES_REFUSE_MALFORMED;
    }
    if (!ecc_start_once() || !ecc_verify_init_once()) {
        LOG_ERROR("zses", "invite_verify: secp256k1 context init failed");
        return ZSES_REFUSE_MALFORMED;
    }
    if (!inv->endpoint[0] || inv->expires <= 0 || !inv->capability_tag[0]) {
        LOG_ERROR("zses", "invite_verify: missing body fields");
        return ZSES_REFUSE_MALFORMED;
    }
    if (!inv->has_signature) {
        LOG_ERROR("zses", "invite_verify: unsigned");
        return ZSES_REFUSE_UNSIGNED;
    }
    if (!inv->has_pubkey) {
        LOG_ERROR("zses", "invite_verify: missing pubkey");
        return ZSES_REFUSE_MALFORMED;
    }
    struct uint256 hash;
    zses_body_hash(inv, &hash);
    struct pubkey recovered;
    if (!pubkey_recover_compact(&recovered, &hash, inv->signature)) {
        LOG_ERROR("zses", "invite_verify: signature did not recover (tampered)");
        return ZSES_REFUSE_TAMPERED;
    }
    if (recovered.size != ZSES_PUBKEY_LEN ||
        memcmp(recovered.vch, inv->pubkey, ZSES_PUBKEY_LEN) != 0) {
        LOG_ERROR("zses", "invite_verify: recovered pubkey != stated (wrong_key)");
        return ZSES_REFUSE_WRONG_KEY;
    }
    if (now > inv->expires) {
        LOG_ERROR("zses", "invite_verify: expired now=%lld expires=%lld",
                  (long long)now, (long long)inv->expires);
        return ZSES_REFUSE_EXPIRED;
    }
    return ZSES_OK;
}

bool zses_invite_encode_json(const struct zses_invite *inv, char *out,
                             size_t out_cap)
{
    if (!inv || !out || out_cap < 8)
        LOG_FAIL("zses", "invite_encode_json: bad args");
    if (!inv->has_signature || !inv->has_pubkey)
        LOG_FAIL("zses", "invite_encode_json: unsigned invite");
    char pub_hex[ZSES_PUBKEY_LEN * 2 + 1];
    char sig_hex[COMPACT_SIGNATURE_SIZE * 2 + 1];
    zcl_hex_encode(inv->pubkey, ZSES_PUBKEY_LEN, pub_hex);
    zcl_hex_encode(inv->signature, COMPACT_SIGNATURE_SIZE, sig_hex);
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    (void)json_push_kv_str(&obj, "schema", ZSES_SCHEMA);
    (void)json_push_kv_str(&obj, "endpoint", inv->endpoint);
    (void)json_push_kv_int(&obj, "expires", inv->expires);
    (void)json_push_kv_str(&obj, "capability_tag", inv->capability_tag);
    (void)json_push_kv_str(&obj, "pubkey", pub_hex);
    (void)json_push_kv_str(&obj, "signature", sig_hex);
    size_t n = json_write(&obj, out, out_cap);
    json_free(&obj);
    if (n >= out_cap)
        LOG_FAIL("zses", "invite_encode_json: output truncated");
    return true;
}

bool zses_invite_decode_json(const char *json, struct zses_invite *inv)
{
    if (!json || !inv)
        LOG_FAIL("zses", "invite_decode_json: bad args");
    memset(inv, 0, sizeof(*inv));
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, json, strlen(json)) || v.type != JSON_OBJ) {
        json_free(&v);
        LOG_FAIL("zses", "invite_decode_json: not a JSON object");
    }
    const char *schema = json_get_str(json_get(&v, "schema"));
    const char *endpoint = json_get_str(json_get(&v, "endpoint"));
    const char *tag = json_get_str(json_get(&v, "capability_tag"));
    if (!tag[0])
        tag = json_get_str(json_get(&v, "capability-tag"));
    const char *pub_hex = json_get_str(json_get(&v, "pubkey"));
    const char *sig_hex = json_get_str(json_get(&v, "signature"));
    const struct json_value *exp = json_get(&v, "expires");
    int64_t expires = exp ? json_get_int(exp) : 0;
    bool ok = schema && strcmp(schema, ZSES_SCHEMA) == 0 &&
              endpoint && endpoint[0] && tag && tag[0] && expires > 0;
    if (ok && strlen(endpoint) <= ZSES_ENDPOINT_MAX &&
        strlen(tag) <= ZSES_TAG_MAX) {
        memcpy(inv->endpoint, endpoint, strlen(endpoint) + 1);
        memcpy(inv->capability_tag, tag, strlen(tag) + 1);
        inv->expires = expires;
    } else {
        ok = false;
    }
    if (ok && pub_hex && zcl_hex_decode(pub_hex, inv->pubkey, ZSES_PUBKEY_LEN))
        inv->has_pubkey = true;
    if (ok && sig_hex &&
        zcl_hex_decode(sig_hex, inv->signature, COMPACT_SIGNATURE_SIZE))
        inv->has_signature = true;
    json_free(&v);
    if (!ok)
        LOG_FAIL("zses", "invite_decode_json: missing/invalid zses:v1 fields");
    return true;
}
