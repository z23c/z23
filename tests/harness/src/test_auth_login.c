/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auth login service tests: the full challenge/response round trip
 * (sign -> recover -> address match over the canonical domain-tagged message),
 * plus the negative paths — single-use nonce, expired nonce, wrong server id,
 * and a tampered message — all fail closed. */

#include "test/test_core.h"

#include "models/database.h"
#include "models/principal.h"
#include "models/auth_challenge.h"
#include "services/auth_login_service.h"
#include "models/authz_policy.h"

#include "chain/chainparams.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>

static bool addr_from_pubkey(const struct pubkey *pk, char *out, size_t n)
{
    struct key_id kid = pubkey_get_id(pk);
    struct tx_destination d;
    memset(&d, 0, sizeof(d));
    d.type = DEST_KEY_ID;
    d.id.key = kid;
    const struct chain_params *cp = chain_params_get();
    size_t pl = 0, sl = 0;
    const unsigned char *pp = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pl);
    const unsigned char *sp = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sl);
    return encode_destination(&d, pp, pl, sp, sl, out, n);
}

static int test_roundtrip_and_single_use(void)
{
    int failures = 0;
    struct node_db ndb;
    struct privkey k;
    struct pubkey pk;
    char address[128] = {0};
    TEST("secp256k1 round-trip: sign the canonical message, recover, match, session") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        privkey_make_new(&k, true);
        ASSERT(privkey_get_pubkey(&k, &pk));
        ASSERT(addr_from_pubkey(&pk, address, sizeof(address)));

        struct auth_challenge_issued issued;
        ASSERT(auth_login_challenge(&ndb, "srv", address, &issued).ok);

        struct uint256 h;
        ASSERT(auth_login_signable_hash(issued.message, &h));
        unsigned char sig[COMPACT_SIGNATURE_SIZE];
        ASSERT(privkey_sign_compact(&k, &h, sig));

        struct auth_session sess;
        struct zcl_result vr = auth_login_verify(&ndb, "srv", address,
                                                 issued.nonce_hex, sig,
                                                 sizeof(sig), NULL, &sess);
        ASSERT(vr.ok);
        ASSERT_STR_EQ(sess.account, address);
        ASSERT_EQ((int)sess.role, PRINCIPAL_ROLE_GUEST);
        ASSERT_EQ(sess.granted_capabilities,
                  authz_caps_for_role(PRINCIPAL_ROLE_GUEST));
        ASSERT(sess.newly_registered);

        struct db_principal got;
        ASSERT(db_principal_find(&ndb, address, &got));

        /* Single-use: replaying the same nonce+signature is denied. */
        struct auth_session sess2;
        ASSERT(!auth_login_verify(&ndb, "srv", address, issued.nonce_hex, sig,
                                  sizeof(sig), NULL, &sess2).ok);
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

static int test_wrong_server_and_tamper(void)
{
    int failures = 0;
    struct node_db ndb;
    struct privkey k;
    struct pubkey pk;
    char address[128] = {0};
    TEST("wrong server id and a tampered message both fail closed") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        privkey_make_new(&k, true);
        ASSERT(privkey_get_pubkey(&k, &pk));
        ASSERT(addr_from_pubkey(&pk, address, sizeof(address)));

        struct auth_challenge_issued issued;
        ASSERT(auth_login_challenge(&ndb, "srv", address, &issued).ok);
        struct uint256 h;
        ASSERT(auth_login_signable_hash(issued.message, &h));
        unsigned char sig[COMPACT_SIGNATURE_SIZE];
        ASSERT(privkey_sign_compact(&k, &h, sig));
        struct auth_session sess;
        ASSERT(!auth_login_verify(&ndb, "attacker", address, issued.nonce_hex,
                                  sig, sizeof(sig), NULL, &sess).ok);

        struct auth_challenge_issued issued2;
        ASSERT(auth_login_challenge(&ndb, "srv", address, &issued2).ok);
        char tampered[AUTH_MESSAGE_MAX];
        snprintf(tampered, sizeof(tampered), "%sEXTRA", issued2.message);
        struct uint256 th;
        ASSERT(auth_login_signable_hash(tampered, &th));
        unsigned char tsig[COMPACT_SIGNATURE_SIZE];
        ASSERT(privkey_sign_compact(&k, &th, tsig));
        struct auth_session tsess;
        ASSERT(!auth_login_verify(&ndb, "srv", address, issued2.nonce_hex,
                                  tsig, sizeof(tsig), NULL, &tsess).ok);
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nonce_single_use_and_expiry(void)
{
    int failures = 0;
    struct node_db ndb;
    TEST("nonce store enforces single-use, expiry, and address binding") {
        ASSERT(node_db_open(&ndb, ":memory:"));
        int64_t now = (int64_t)platform_time_wall_time_t();

        struct db_auth_challenge fut;
        memset(&fut, 0, sizeof(fut));
        snprintf(fut.nonce_hex, sizeof(fut.nonce_hex), "%064x", 1u);
        snprintf(fut.address, sizeof(fut.address), "t1nonceaddr0000000000000000000000");
        fut.issued_at = now;
        fut.expires_at = now + 300;
        ASSERT(db_auth_challenge_save(&ndb, &fut));
        ASSERT(db_auth_challenge_consume(&ndb, fut.nonce_hex, fut.address, now));
        ASSERT(!db_auth_challenge_consume(&ndb, fut.nonce_hex, fut.address, now));

        struct db_auth_challenge past;
        memset(&past, 0, sizeof(past));
        snprintf(past.nonce_hex, sizeof(past.nonce_hex), "%064x", 2u);
        snprintf(past.address, sizeof(past.address), "t1nonceaddr0000000000000000000000");
        past.issued_at = now - 1000;
        past.expires_at = now - 500;
        ASSERT(db_auth_challenge_save(&ndb, &past));
        ASSERT(!db_auth_challenge_consume(&ndb, past.nonce_hex, past.address, now));

        struct db_auth_challenge other;
        memset(&other, 0, sizeof(other));
        snprintf(other.nonce_hex, sizeof(other.nonce_hex), "%064x", 3u);
        snprintf(other.address, sizeof(other.address), "t1nonceaddr0000000000000000000000");
        other.issued_at = now;
        other.expires_at = now + 300;
        ASSERT(db_auth_challenge_save(&ndb, &other));
        ASSERT(!db_auth_challenge_consume(&ndb, other.nonce_hex, "t1other", now));
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    return failures;
}

int test_auth_login(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    failures += test_roundtrip_and_single_use();
    failures += test_wrong_server_and_tamper();
    failures += test_nonce_single_use_and_expiry();
    printf("=== auth_login: %d failures ===\n", failures);
    return failures;
}
