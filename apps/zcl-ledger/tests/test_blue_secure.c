/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_secure.h"

#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) abort(); } while (0)

int main(void) {
    EVP_PKEY *alice = blue_key_generate();
    EVP_PKEY *bob = blue_key_generate();
    CHECK(alice && bob);
    uint8_t alice_public[65], bob_public[65], alice_secret[32], bob_secret[32];
    CHECK(blue_key_public(alice, alice_public) == 0);
    CHECK(blue_key_public(bob, bob_public) == 0);
    CHECK(blue_ecdh(alice, bob_public, alice_secret) == 0);
    CHECK(blue_ecdh(bob, alice_public, bob_secret) == 0);
    CHECK(memcmp(alice_secret, bob_secret, 32) == 0);
    const uint8_t message[] = "ledger-blue-c23";
    uint8_t signature[80];
    size_t signature_length = sizeof signature;
    CHECK(blue_sign(alice, message, sizeof message, signature,
                    &signature_length) == 0);
    CHECK(blue_verify(alice_public, message, sizeof message, signature,
                      signature_length) == 0);
    CHECK(blue_verify(bob_public, message, sizeof message, signature,
                      signature_length) < 0);
    blue_secure_channel tx, rx;
    CHECK(blue_secure_init(&tx, alice_secret) == 0);
    CHECK(blue_secure_init(&rx, bob_secret) == 0);
    uint8_t wrapped[256], plain[256];
    size_t wrapped_length = 0, plain_length = 0;
    CHECK(blue_secure_wrap(&tx, message, sizeof message, wrapped,
                           sizeof wrapped, &wrapped_length) == 0);
    CHECK(blue_secure_unwrap(&rx, wrapped, wrapped_length, plain,
                             sizeof plain, &plain_length) == 0);
    CHECK(plain_length == sizeof message);
    CHECK(memcmp(plain, message, plain_length) == 0);
    wrapped[wrapped_length - 1] ^= 1;
    CHECK(blue_secure_unwrap(&rx, wrapped, wrapped_length, plain,
                             sizeof plain, &plain_length) < 0);
    EVP_PKEY_free(bob);
    EVP_PKEY_free(alice);
    return 0;
}
