/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zses:v1 — signed session invite. Body is {endpoint, expires,
 * capability-tag}. Signatures use the existing secp256k1 compact
 * recoverable scheme (privkey_sign_compact / pubkey_recover_compact).
 * No new crypto. Verify is fail-closed. */

#ifndef ZCL_SESSION_ZSES_H
#define ZCL_SESSION_ZSES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keys/key.h"
#include "keys/pubkey.h"

#define ZSES_SCHEMA "zses:v1"
#define ZSES_ENDPOINT_MAX 127
#define ZSES_TAG_MAX 63
#define ZSES_JSON_MAX 2048
#define ZSES_PUBKEY_LEN 33

enum zses_refuse {
    ZSES_OK = 0,
    ZSES_REFUSE_UNSIGNED,
    ZSES_REFUSE_WRONG_KEY,
    ZSES_REFUSE_TAMPERED,
    ZSES_REFUSE_EXPIRED,
    ZSES_REFUSE_MALFORMED,
    ZSES_REFUSE_BAD_ENDPOINT,
    ZSES_REFUSE_CLEARNET_FORBIDDEN,
    ZSES_REFUSE_NO_ONION
};

struct zses_invite {
    char endpoint[ZSES_ENDPOINT_MAX + 1];
    int64_t expires;
    char capability_tag[ZSES_TAG_MAX + 1];
    unsigned char pubkey[ZSES_PUBKEY_LEN];
    unsigned char signature[COMPACT_SIGNATURE_SIZE];
    bool has_pubkey;
    bool has_signature;
};

const char *zses_refuse_name(enum zses_refuse code);

/* Onion-default disclosure: never returns a clearnet (numeric IP) endpoint
 * unless posture is exactly "clearnet". posture NULL/"onion" requires onion.
 * Writes a named refuse and returns false on refusal. */
bool zses_pick_endpoint(const char *posture, const char *onion,
                        const char *clearnet, char *out, size_t out_cap,
                        enum zses_refuse *refuse);

bool zses_looks_clearnet(const char *endpoint);
bool zses_looks_onion(const char *endpoint);

/* Sign invite in place using k. Fills pubkey + signature. */
bool zses_invite_sign(struct zses_invite *inv, const struct privkey *k);

/* Verify fail-closed. `now` is unix seconds supplied by the caller so tests
 * do not depend on the wall clock. */
enum zses_refuse zses_invite_verify(const struct zses_invite *inv, int64_t now);

bool zses_invite_encode_json(const struct zses_invite *inv, char *out,
                             size_t out_cap);
bool zses_invite_decode_json(const char *json, struct zses_invite *inv);

#endif /* ZCL_SESSION_ZSES_H */
