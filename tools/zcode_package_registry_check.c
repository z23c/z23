/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rederive and verify the checked-in ZCODE package root projection. */

#include "base/hex.h"
#include "vcs/package_prepare.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <stdio.h>
#include <string.h>

struct registry_row {
    const char *name, *dir;
    uint64_t sequence;
    const char *content, *release, *recipe, *lock, *capsule, *publisher;
    const char *signature;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature},
static const struct registry_row rows[] = {
#include "../config/zcode_package_registry.def"
#include "../config/zcode_c23_commons_app.def"
};
#undef ZCODE_PACKAGE

static bool root_equal(const uint8_t root[32], const char *expected)
{
    uint8_t decoded[32];
    return zcl_hex_decode_lower(expected, decoded, sizeof(decoded)) &&
           memcmp(root, decoded, sizeof(decoded)) == 0;
}

static void print_derived_roots(const struct vcs_package_prepared *prepared)
{
    char content[65], release[65], recipe[65], lock[65], capsule[65];
    zcl_hex_encode(prepared->package_root, 32, content);
    zcl_hex_encode(prepared->signing_digest, 32, release);
    zcl_hex_encode(prepared->recipe_root, 32, recipe);
    zcl_hex_encode(prepared->lock_root, 32, lock);
    zcl_hex_encode(prepared->capsule_root, 32, capsule);
    fprintf(stderr,
            "  derived content=%s release=%s recipe=%s lock=%s capsule=%s\n",
            content, release, recipe, lock, capsule);
}

/* This key is the public alpha fixture identity already embedded in the
 * checked projection. It has no owner, wallet, or stable-release authority. */
static bool derive_fixture_signature(const uint8_t digest[32], char out[129])
{
    uint8_t secret[32], compact[64];
    memset(secret, 0x47, sizeof(secret));
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_recoverable_signature signature;
    int recovery_id = -1;
    bool ok = ctx && secp256k1_ec_seckey_verify(ctx, secret) == 1 &&
        secp256k1_ecdsa_sign_recoverable(ctx, &signature, digest, secret,
            secp256k1_nonce_function_rfc6979, NULL) == 1 &&
        secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, compact, &recovery_id, &signature) == 1 && recovery_id >= 0;
    if (ctx)
        secp256k1_context_destroy(ctx);
    memset(secret, 0, sizeof(secret));
    if (!ok)
        return false;
    zcl_hex_encode(compact, sizeof(compact), out);
    memset(compact, 0, sizeof(compact));
    return true;
}

static bool derive_fixture_public(uint8_t out[33])
{
    uint8_t secret[32];
    memset(secret, 0x47, sizeof(secret));
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey public_key;
    size_t out_len = 33;
    bool ok = ctx && secp256k1_ec_pubkey_create(ctx, &public_key, secret) == 1 &&
        secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &public_key,
                                     SECP256K1_EC_COMPRESSED) == 1 &&
        out_len == 33;
    if (ctx)
        secp256k1_context_destroy(ctx);
    memset(secret, 0, sizeof(secret));
    return ok;
}

static bool print_derived_row(const struct registry_row *row,
                              const struct vcs_package_prepared *prepared)
{
    char content[65], release[65], recipe[65], lock[65], capsule[65];
    char publisher[67], signature[129];
    zcl_hex_encode(prepared->package_root, 32, content);
    zcl_hex_encode(prepared->signing_digest, 32, release);
    zcl_hex_encode(prepared->recipe_root, 32, recipe);
    zcl_hex_encode(prepared->lock_root, 32, lock);
    zcl_hex_encode(prepared->capsule_root, 32, capsule);
    zcl_hex_encode(prepared->release.publisher_pubkey, 33, publisher);
    if (!derive_fixture_signature(prepared->signing_digest, signature))
        return false;
    printf("%s content=%s release=%s recipe=%s lock=%s capsule=%s "
           "publisher=%s signature=%s\n", row->name, content, release,
           recipe, lock, capsule, publisher, signature);
    return true;
}

int main(int argc, char **argv)
{
    bool derive = argc == 3 && strcmp(argv[1], "--derive") == 0;
    const char *derive_name = derive ? argv[2] : NULL;
    if (argc != 1 && !derive) {
        fprintf(stderr,
                "usage: zcode-package-registry-check [--derive NAME]\n");
        return 2;
    }
    if (sizeof(rows) / sizeof(rows[0]) < 8)
        return 1;
    bool derived = false;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if (derive && strcmp(rows[i].name, derive_name) != 0)
            continue;
        uint8_t pubkey[33];
        if (derive ? !derive_fixture_public(pubkey) :
                     !zcl_hex_decode_lower(rows[i].publisher, pubkey,
                                           sizeof(pubkey)))
            return 1;
        struct vcs_package_prepare_options options = {
            .dir = rows[i].dir, .publisher_sequence = rows[i].sequence,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pubkey, sizeof(pubkey));
        struct vcs_package_prepared prepared; char detail[256] = {0};
        enum vcs_package_prepare_error err = vcs_package_prepare(
            &options, &prepared, detail, sizeof(detail));
        bool ok = err == VCS_PACKAGE_PREPARE_OK &&
            strcmp(prepared.release.name, rows[i].name) == 0 &&
            root_equal(prepared.package_root, rows[i].content) &&
            root_equal(prepared.signing_digest, rows[i].release) &&
            root_equal(prepared.recipe_root, rows[i].recipe) &&
            root_equal(prepared.lock_root, rows[i].lock) &&
            root_equal(prepared.capsule_root, rows[i].capsule) &&
            zcl_hex_decode_lower(rows[i].signature,
                prepared.release.signature,
                sizeof(prepared.release.signature)) &&
            vcs_package_release_verify(&prepared.release) ==
                VCS_PACKAGE_RELEASE_OK;
        if (ok) {
            ok = prepared.lock.count >= 1 &&
                 prepared.lock.nodes[prepared.lock.count - 1u].depth == 0 &&
                 prepared.lock.nodes[prepared.lock.count - 1u].direct_deps ==
                     prepared.lock.count - 1u;
            for (size_t d = 0; ok && d + 1u < prepared.lock.count; d++) {
                bool found = false;
                for (size_t p = 0; p < i; p++)
                    found = found || root_equal(
                        prepared.lock.nodes[d].root, rows[p].content);
                ok = found && prepared.lock.nodes[d].depth == 1;
            }
        }
        if (derive && err == VCS_PACKAGE_PREPARE_OK) {
            derived = print_derived_row(&rows[i], &prepared);
        }
        if (!ok && !derive) {
            fprintf(stderr, "zcode registry mismatch: %s (%s: %s)\n",
                    rows[i].name, vcs_package_prepare_error_string(err),
                    detail);
            if (err == VCS_PACKAGE_PREPARE_OK)
                print_derived_roots(&prepared);
            vcs_package_prepared_free(&prepared);
            return 1;
        }
        vcs_package_prepared_free(&prepared);
    }
    if (derive)
        return derived ? 0 : 1;
    printf("zcode package registry: %zu roots and exact dependency DAG rederived\n",
           sizeof(rows) / sizeof(rows[0]));
    return 0;
}
