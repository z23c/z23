/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * metaverse_tour_fixture — hermetic fixture builder for
 * tools/dev/metaverse_tour.sh. Compiled at script runtime (the same
 * pattern as tools/zcode_dht_acceptance_peer.c); never installed.
 *
 *   metaverse-tour-fixture pubkey <64-lower-hex-seed>
 *       Print the Ed25519 public key (64 hex) for a ZID master seed, so
 *       the tour can `core identity anchor` it before delegating.
 *
 *   metaverse-tour-fixture fixture <pkgdir> <name> <license> <key-seed-byte-hex> <seq>
 *       Write a tiny three-file package (LICENSE + include/ring.h +
 *       src/ring.c) under <pkgdir>, then print ONE JSON line:
 *       {"release_hex":"..","manifest_hex":"..","recipe_hex":"..","package_root":"<64hex>"}
 *       The release is the canonical signed secp256k1 envelope the
 *       `zcode package publish plan|commit` input schema expects, bound
 *       to CHAIN_MAIN exactly the way the publish CLI validates it
 *       (the CLI pins CHAIN_MAIN for its acceptance replay regardless
 *       of the node's own chain).
 *
 * The fixture construction mirrors tests/harness/src/test_zcode_publish.c's
 * zp_* builders so the tour exercises the same happy-path shape the
 * unit gate proves.
 */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "support/cleanse.h"
#include "vcs/package_accept.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char *mtf_hex(const uint8_t *data, size_t len)
{
    char *out = zcl_malloc(2 * len + 1, "mtf_hex");
    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++)
        snprintf(out + 2 * i, 3, "%02x", data[i]);
    return out;
}

static int mtf_pubkey(const char *seed_hex)
{
    uint8_t seed[32], pubkey[32], secret_copy[32];
    if (strlen(seed_hex) != 64 ||
        !zcl_hex_decode_lower(seed_hex, seed, sizeof(seed))) {
        memory_cleanse(seed, sizeof(seed));
        fprintf(stderr, "seed must be exactly 64 lowercase hex characters\n");
        return 2;
    }
    zcl_ed25519_keypair(pubkey, secret_copy, seed);
    memory_cleanse(secret_copy, sizeof(secret_copy));
    memory_cleanse(seed, sizeof(seed));
    char hex[65];
    zcl_hex_encode(pubkey, sizeof(pubkey), hex);
    puts(hex);
    memory_cleanse(pubkey, sizeof(pubkey));
    memory_cleanse(hex, sizeof(hex));
    return 0;
}

static bool mtf_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool mtf_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool mtf_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0, script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x33, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, out, out_size);
}

static bool mtf_write_file(const char *dir, const char *path,
                           const char *content)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, path);
    const char *slash = strrchr(path, '/');
    if (slash) {
        char parent[1024];
        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        (void)mkdir(parent, 0700); /* EEXIST is fine */
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t len = strlen(content);
    bool wrote = fwrite(content, 1, len, f) == len;
    fclose(f);
    return wrote;
}

static bool mtf_add_file(struct vcs_package_manifest *m, const char *dir,
                         const char *path, const char *content)
{
    if (!mtf_write_file(dir, path, content))
        return false;
    uint8_t hash[32];
    size_t len = strlen(content);
    if (!vcs_package_chunk_hash((const uint8_t *)content, len, hash))
        return false;
    return vcs_package_manifest_add(m, path, VCS_PACKAGE_MODE_FILE, len,
                                    hash, 1);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "pubkey") == 0)
        return mtf_pubkey(argv[2]);
    if (argc != 7 || strcmp(argv[1], "fixture") != 0) {
        fprintf(stderr,
                "usage: %s pubkey <64-lower-hex-seed>\n"
                "       %s fixture <pkgdir> <name> <license> "
                "<key-seed-byte-hex> <seq>\n",
                argv[0], argv[0]);
        return 2;
    }
    const char *dir = argv[2];
    const char *name = argv[3];
    const char *license = argv[4];
    uint8_t key_seed = 0;
    if (strlen(argv[5]) != 2 ||
        !zcl_hex_decode_lower(argv[5], &key_seed, 1)) {
        fprintf(stderr, "key seed must be one lowercase hex byte\n");
        return 2;
    }
    char *end = NULL;
    unsigned long seq = strtoul(argv[6], &end, 10);
    if (!end || *end || seq == 0) {
        fprintf(stderr, "seq must be a positive integer\n");
        return 2;
    }

    /* The publish CLI pins CHAIN_MAIN for its acceptance replay; the
     * fixture must commit the same chain id and a mainnet t1 reward
     * address no matter which chain the tour node runs. */
    chain_params_select(CHAIN_MAIN);
    /* Offline one-shot process: create the secp256k1 signing context the
     * node's boot wiring would otherwise own. */
    if (!ecc_start_once()) {
        fprintf(stderr, "secp256k1 context init failed\n");
        return 2;
    }

    (void)mkdir(dir, 0700);
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    if (!mtf_add_file(&manifest, dir, "LICENSE",
                      "MIT License\n\nPermission is hereby granted.\n") ||
        !mtf_add_file(&manifest, dir, "include/ring.h",
                      "#pragma once\nstruct ring { unsigned head, tail; };\n") ||
        !mtf_add_file(&manifest, dir, "src/ring.c",
                      "#include \"ring.h\"\nint ring_push(void) { return 0; }\n")) {
        fprintf(stderr, "package fixture files failed\n");
        vcs_package_manifest_free(&manifest);
        return 2;
    }
    uint8_t *manifest_wire = NULL;
    size_t manifest_wire_len = 0;
    uint8_t package_root[32];
    if (!vcs_package_manifest_serialize(&manifest, &manifest_wire,
                                        &manifest_wire_len) ||
        !vcs_package_manifest_root(&manifest, package_root)) {
        fprintf(stderr, "manifest serialize/root failed\n");
        vcs_package_manifest_free(&manifest);
        return 2;
    }

    /* Declarative recipe: every .h a public header (parent an include
     * dir), every .c a source; one define, libc only, exit 0, 60 s,
     * 64 MiB — the same shape test_zcode_publish proves. */
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    bool ok = true;
    for (size_t i = 0; ok && i < manifest.count; i++) {
        const char *path = manifest.files[i].path;
        size_t len = strlen(path);
        if (len > 2 && strcmp(path + len - 2, ".h") == 0) {
            ok = vcs_package_recipe_add_header(&recipe, path, NULL);
            const char *slash = strrchr(path, '/');
            if (ok && slash) {
                char idir[1024];
                snprintf(idir, sizeof(idir), "%.*s", (int)(slash - path),
                         path);
                enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
                if (!vcs_package_recipe_add_include_dir(&recipe, idir,
                                                        &rerr) &&
                    rerr != VCS_PACKAGE_RECIPE_ERR_LIST_ORDER)
                    ok = false;
            }
        } else if (len > 2 && strcmp(path + len - 2, ".c") == 0) {
            ok = vcs_package_recipe_add_source(&recipe, path, NULL);
        }
    }
    if (ok)
        ok = vcs_package_recipe_add_define(&recipe, "ZCL_FIXTURE=1", NULL) &&
             vcs_package_recipe_add_library(&recipe,
                                            VCS_PACKAGE_RECIPE_LIB_LIBC,
                                            NULL);
    vcs_package_recipe_set_test_limits(&recipe, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t recipe_root[32];
    uint8_t *recipe_wire = NULL;
    size_t recipe_wire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&recipe, recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&recipe, &recipe_wire,
                                          &recipe_wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&recipe);
    if (!ok) {
        fprintf(stderr, "recipe build failed\n");
        vcs_package_manifest_free(&manifest);
        free(manifest_wire);
        return 2;
    }

    struct vcs_package_release release;
    memset(&release, 0, sizeof(release));
    struct privkey sk;
    struct pubkey pk;
    ok = mtf_keypair(key_seed, &sk, &pk);
    if (ok) {
        release.schema_version = VCS_PACKAGE_RELEASE_VERSION;
        snprintf(release.name, sizeof(release.name), "%s", name);
        snprintf(release.semver, sizeof(release.semver), "1.0.0");
        memcpy(release.package_root, package_root, 32);
        release.has_parent = false;
        memcpy(release.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
        release.publisher_sequence = (uint64_t)seq;
        ok = mtf_t1_reward(release.reward_address,
                           sizeof(release.reward_address));
    }
    if (ok) {
        snprintf(release.license, sizeof(release.license), "%s", license);
        memcpy(release.recipe_root, recipe_root, 32);
        release.has_znam = false;
        ok = vcs_package_accept_chain_id(release.chain_id,
                                         sizeof(release.chain_id));
    }
    if (ok)
        ok = mtf_sign(&release, &sk);
    memory_cleanse(&sk, sizeof(sk));
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    if (ok)
        ok = vcs_package_release_serialize(&release, &release_wire,
                                           &release_wire_len) ==
                 VCS_PACKAGE_RELEASE_OK;
    if (!ok) {
        fprintf(stderr, "release build/sign failed\n");
        vcs_package_manifest_free(&manifest);
        free(manifest_wire);
        free(recipe_wire);
        return 2;
    }

    char *release_hex = mtf_hex(release_wire, release_wire_len);
    char *manifest_hex = mtf_hex(manifest_wire, manifest_wire_len);
    char *recipe_hex = mtf_hex(recipe_wire, recipe_wire_len);
    char root_hex[65];
    zcl_hex_encode(package_root, 32, root_hex);
    ok = release_hex && manifest_hex && recipe_hex;
    if (ok)
        printf("{\"release_hex\":\"%s\",\"manifest_hex\":\"%s\","
               "\"recipe_hex\":\"%s\",\"package_root\":\"%s\"}\n",
               release_hex, manifest_hex, recipe_hex, root_hex);
    free(release_hex);
    free(manifest_hex);
    free(recipe_hex);
    free(release_wire);
    free(manifest_wire);
    free(recipe_wire);
    vcs_package_manifest_free(&manifest);
    if (!ok) {
        fprintf(stderr, "hex encode failed\n");
        return 2;
    }
    return 0;
}
