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

enum mtf_command {
    MTF_COMMAND_FIXTURE,
    MTF_COMMAND_PUBKEY,
    MTF_COMMAND_USAGE,
};

static enum mtf_command mtf_parse_command(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "pubkey") == 0)
        return MTF_COMMAND_PUBKEY;
    if (argc != 7 || strcmp(argv[1], "fixture") != 0)
        return MTF_COMMAND_USAGE;
    return MTF_COMMAND_FIXTURE;
}

/* Returns 0 when argv[5]/argv[6] parse, 1 for a bad key seed byte,
 * 2 for a bad seq; the caller reports the message. */
static int mtf_parse_fixture_args(char **argv, uint8_t *key_seed,
                                  unsigned long *seq)
{
    if (strlen(argv[5]) != 2 ||
        !zcl_hex_decode_lower(argv[5], key_seed, 1))
        return 1;
    char *end = NULL;
    *seq = strtoul(argv[6], &end, 10);
    if (!end || *end || *seq == 0)
        return 2;
    return 0;
}

static bool mtf_add_package_files(struct vcs_package_manifest *m,
                                  const char *dir)
{
    return mtf_add_file(m, dir, "LICENSE",
                        "MIT License\n\nPermission is hereby granted.\n") &&
           mtf_add_file(m, dir, "include/ring.h",
                        "#pragma once\nstruct ring { unsigned head, tail; };\n") &&
           mtf_add_file(m, dir, "src/ring.c",
                        "#include \"ring.h\"\nint ring_push(void) { return 0; }\n");
}

static bool mtf_serialize_manifest(struct vcs_package_manifest *m,
                                   uint8_t **wire, size_t *wire_len,
                                   uint8_t *root)
{
    return vcs_package_manifest_serialize(m, wire, wire_len) &&
           vcs_package_manifest_root(m, root);
}

static bool mtf_recipe_add_public_header(struct vcs_package_recipe *recipe,
                                         const char *path)
{
    bool ok = vcs_package_recipe_add_header(recipe, path, NULL);
    const char *slash = strrchr(path, '/');
    if (ok && slash) {
        char idir[1024];
        snprintf(idir, sizeof(idir), "%.*s", (int)(slash - path), path);
        enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
        ok = vcs_package_recipe_add_include_dir(recipe, idir, &rerr) ||
             rerr == VCS_PACKAGE_RECIPE_ERR_LIST_ORDER;
    }
    return ok;
}

static bool mtf_recipe_add_file(struct vcs_package_recipe *recipe,
                                const char *path)
{
    size_t len = strlen(path);
    if (len > 2 && strcmp(path + len - 2, ".h") == 0)
        return mtf_recipe_add_public_header(recipe, path);
    if (len > 2 && strcmp(path + len - 2, ".c") == 0)
        return vcs_package_recipe_add_source(recipe, path, NULL);
    return true;
}

static bool mtf_build_recipe(struct vcs_package_manifest *manifest,
                             struct vcs_package_recipe *recipe,
                             uint8_t *recipe_root, uint8_t **recipe_wire,
                             size_t *recipe_wire_len)
{
    bool ok = true;
    for (size_t i = 0; ok && i < manifest->count; i++) {
        ok = mtf_recipe_add_file(recipe, manifest->files[i].path);
    }
    if (ok)
        ok = vcs_package_recipe_add_define(recipe, "ZCL_FIXTURE=1", NULL) &&
             vcs_package_recipe_add_library(recipe,
                                            VCS_PACKAGE_RECIPE_LIB_LIBC,
                                            NULL);
    vcs_package_recipe_set_test_limits(recipe, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    if (ok)
        ok = vcs_package_recipe_root(recipe, recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(recipe, recipe_wire,
                                          recipe_wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    return ok;
}

static bool mtf_build_release(struct vcs_package_release *release,
                              uint8_t key_seed, const char *name,
                              const char *license, uint64_t seq,
                              const uint8_t *package_root,
                              const uint8_t *recipe_root,
                              uint8_t **release_wire,
                              size_t *release_wire_len)
{
    struct privkey sk;
    struct pubkey pk;
    bool ok = mtf_keypair(key_seed, &sk, &pk);
    if (ok) {
        release->schema_version = VCS_PACKAGE_RELEASE_VERSION;
        snprintf(release->name, sizeof(release->name), "%s", name);
        snprintf(release->semver, sizeof(release->semver), "1.0.0");
        memcpy(release->package_root, package_root, 32);
        release->has_parent = false;
        memcpy(release->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
        release->publisher_sequence = seq;
        ok = mtf_t1_reward(release->reward_address,
                           sizeof(release->reward_address));
    }
    if (ok) {
        snprintf(release->license, sizeof(release->license), "%s", license);
        memcpy(release->recipe_root, recipe_root, 32);
        release->has_znam = false;
        ok = vcs_package_accept_chain_id(release->chain_id,
                                         sizeof(release->chain_id));
    }
    if (ok)
        ok = mtf_sign(release, &sk);
    memory_cleanse(&sk, sizeof(sk));
    if (ok)
        ok = vcs_package_release_serialize(release, release_wire,
                                           release_wire_len) ==
                 VCS_PACKAGE_RELEASE_OK;
    return ok;
}

static bool mtf_print_fixture_json(uint8_t *release_wire,
                                   size_t release_wire_len,
                                   uint8_t *manifest_wire,
                                   size_t manifest_wire_len,
                                   uint8_t *recipe_wire,
                                   size_t recipe_wire_len,
                                   const uint8_t *package_root)
{
    char *release_hex = mtf_hex(release_wire, release_wire_len);
    char *manifest_hex = mtf_hex(manifest_wire, manifest_wire_len);
    char *recipe_hex = mtf_hex(recipe_wire, recipe_wire_len);
    char root_hex[65];
    zcl_hex_encode(package_root, 32, root_hex);
    bool ok = release_hex && manifest_hex && recipe_hex;
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
    return ok;
}

int main(int argc, char **argv)
{
    enum mtf_command cmd = mtf_parse_command(argc, argv);
    if (cmd == MTF_COMMAND_PUBKEY)
        return mtf_pubkey(argv[2]);
    if (cmd == MTF_COMMAND_USAGE) {
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
    unsigned long seq = 0;
    int argerr = mtf_parse_fixture_args(argv, &key_seed, &seq);
    if (argerr == 1) {
        fprintf(stderr, "key seed must be one lowercase hex byte\n");
        return 2;
    }
    if (argerr == 2) {
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
    if (!mtf_add_package_files(&manifest, dir)) {
        fprintf(stderr, "package fixture files failed\n");
        vcs_package_manifest_free(&manifest);
        return 2;
    }
    uint8_t *manifest_wire = NULL;
    size_t manifest_wire_len = 0;
    uint8_t package_root[32];
    if (!mtf_serialize_manifest(&manifest, &manifest_wire,
                                &manifest_wire_len, package_root)) {
        fprintf(stderr, "manifest serialize/root failed\n");
        vcs_package_manifest_free(&manifest);
        return 2;
    }

    /* Declarative recipe: every .h a public header (parent an include
     * dir), every .c a source; one define, libc only, exit 0, 60 s,
     * 64 MiB — the same shape test_zcode_publish proves. */
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    uint8_t recipe_root[32];
    uint8_t *recipe_wire = NULL;
    size_t recipe_wire_len = 0;
    bool ok = mtf_build_recipe(&manifest, &recipe, recipe_root, &recipe_wire,
                               &recipe_wire_len);
    vcs_package_recipe_free(&recipe);
    if (!ok) {
        fprintf(stderr, "recipe build failed\n");
        vcs_package_manifest_free(&manifest);
        free(manifest_wire);
        return 2;
    }

    struct vcs_package_release release;
    memset(&release, 0, sizeof(release));
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    ok = mtf_build_release(&release, key_seed, name, license, (uint64_t)seq,
                           package_root, recipe_root, &release_wire,
                           &release_wire_len);
    if (!ok) {
        fprintf(stderr, "release build/sign failed\n");
        vcs_package_manifest_free(&manifest);
        free(manifest_wire);
        free(recipe_wire);
        return 2;
    }

    ok = mtf_print_fixture_json(release_wire, release_wire_len, manifest_wire,
                                manifest_wire_len, recipe_wire,
                                recipe_wire_len, package_root);
    vcs_package_manifest_free(&manifest);
    if (!ok) {
        fprintf(stderr, "hex encode failed\n");
        return 2;
    }
    return 0;
}
