/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives the shipped zses:v1 encode/sign/verify path. Valid invites
 * round-trip; unsigned, wrong-key, tampered, and expired inputs refuse. */

#include "test/test_core.h"

#include "session/zses.h"

#include "keys/key.h"
#include "keys/pubkey.h"

#include <string.h>

static void zses_fill_body(struct zses_invite *inv, const char *endpoint,
                           int64_t expires, const char *tag)
{
    memset(inv, 0, sizeof(*inv));
    memcpy(inv->endpoint, endpoint, strlen(endpoint) + 1);
    inv->expires = expires;
    memcpy(inv->capability_tag, tag, strlen(tag) + 1);
}

int test_zses(void)
{
    int failures = 0;

    TEST("onion posture never emits a numeric IP") {
        char out[ZSES_ENDPOINT_MAX + 1];
        enum zses_refuse r = ZSES_OK;
        ASSERT(zses_pick_endpoint("onion",
                                  "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                                  "203.0.113.9:8033", out, sizeof(out), &r));
        ASSERT_EQ(r, ZSES_OK);
        ASSERT(zses_looks_onion(out));
        ASSERT(!zses_looks_clearnet(out));
        ASSERT(!zses_pick_endpoint(NULL, NULL, "203.0.113.9:8033", out,
                                   sizeof(out), &r));
        ASSERT_EQ(r, ZSES_REFUSE_NO_ONION);
        PASS();
    }

    TEST("clearnet posture requires an explicit act") {
        char out[ZSES_ENDPOINT_MAX + 1];
        enum zses_refuse r = ZSES_OK;
        ASSERT(zses_pick_endpoint("clearnet",
                                  "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                                  "203.0.113.9:8033", out, sizeof(out), &r));
        ASSERT(zses_looks_clearnet(out));
        PASS();
    }

    TEST("signed invite round-trips through the shipped codec") {
        struct privkey k;
        privkey_make_new(&k, true);
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       2000000000, "session");
        ASSERT(zses_invite_sign(&inv, &k));
        ASSERT_EQ(zses_invite_verify(&inv, 1900000000), ZSES_OK);
        char json[ZSES_JSON_MAX];
        ASSERT(zses_invite_encode_json(&inv, json, sizeof(json)));
        struct zses_invite decoded;
        ASSERT(zses_invite_decode_json(json, &decoded));
        ASSERT_EQ(zses_invite_verify(&decoded, 1900000000), ZSES_OK);
        ASSERT(strcmp(decoded.endpoint, inv.endpoint) == 0);
        ASSERT_EQ(decoded.expires, inv.expires);
        ASSERT(strcmp(decoded.capability_tag, "session") == 0);
        PASS();
    }

    TEST("unsigned invite is refused") {
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       2000000000, "session");
        ASSERT_EQ(zses_invite_verify(&inv, 1900000000), ZSES_REFUSE_UNSIGNED);
        struct privkey k;
        privkey_make_new(&k, true);
        ASSERT(zses_invite_sign(&inv, &k));
        inv.has_signature = false;
        ASSERT_EQ(zses_invite_verify(&inv, 1900000000), ZSES_REFUSE_UNSIGNED);
        PASS();
    }

    TEST("wrong-key invite is refused") {
        struct privkey k1, k2;
        privkey_make_new(&k1, true);
        privkey_make_new(&k2, true);
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       2000000000, "session");
        ASSERT(zses_invite_sign(&inv, &k1));
        struct pubkey pk2;
        ASSERT(privkey_get_pubkey(&k2, &pk2));
        memcpy(inv.pubkey, pk2.vch, ZSES_PUBKEY_LEN);
        ASSERT_EQ(zses_invite_verify(&inv, 1900000000), ZSES_REFUSE_WRONG_KEY);
        PASS();
    }

    TEST("tampered signature is refused") {
        struct privkey k;
        privkey_make_new(&k, true);
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       2000000000, "session");
        ASSERT(zses_invite_sign(&inv, &k));
        inv.signature[1] ^= 0xff;
        inv.signature[32] ^= 0xff;
        inv.signature[64] ^= 0xff;
        enum zses_refuse r = zses_invite_verify(&inv, 1900000000);
        ASSERT(r == ZSES_REFUSE_TAMPERED || r == ZSES_REFUSE_WRONG_KEY);
        PASS();
    }

    TEST("expired invite is refused") {
        struct privkey k;
        privkey_make_new(&k, true);
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       100, "session");
        ASSERT(zses_invite_sign(&inv, &k));
        ASSERT_EQ(zses_invite_verify(&inv, 200), ZSES_REFUSE_EXPIRED);
        ASSERT_EQ(zses_invite_verify(&inv, 100), ZSES_OK);
        PASS();
    }

    TEST("body tamper is refused as wrong_key") {
        struct privkey k;
        privkey_make_new(&k, true);
        struct zses_invite inv;
        zses_fill_body(&inv,
                       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcd.onion:8055",
                       2000000000, "session");
        ASSERT(zses_invite_sign(&inv, &k));
        inv.endpoint[0] = 'x';
        ASSERT_EQ(zses_invite_verify(&inv, 1900000000), ZSES_REFUSE_WRONG_KEY);
        PASS();
    }

_test_next:;
    return failures;
}
