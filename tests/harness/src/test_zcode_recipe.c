/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_recipe — the declarative C23 build recipe gate (slice 5:
 * contexts/commons/modules/vcs/package_recipe.*, the recipe rules in contexts/commons/modules/vcs/package_publish.*,
 * recipe persistence in contexts/commons/modules/vcs/package_store.*, and the zcode package
 * recipe handler in tools/command/native_zcode_command.c).
 *
 * Coverage:
 *   1. Codec roundtrip + root stability: build -> validate -> serialize ->
 *      parse -> identical fields and identical root; a frozen KAT root hex
 *      guards the canonical encoding against drift.
 *   1b. Schema 2, the declared program list: roundtrip and its own frozen
 *      KAT root (the schema-1 KAT must never move when schema 2 changes),
 *      the `app/<stem>.c` grammar, install-output naming, and the four
 *      illegal encodings — version 2 with no list, version 1 with one,
 *      version 2 with an empty one, and a non-program entry on the wire.
 *   2. Every bound enforced: oversized lists/strings, unsorted/duplicate
 *      entries, wrong extensions, bad define grammar, a library outside
 *      {libc, libm, pthread}, empty sources, out-of-range seconds/memory,
 *      unknown wire version/magic/trailing bytes (closed grammar), and
 *      hostile paths (absolute/traversal/backslash) inside recipe fields.
 *   3. Publish integration: missing recipe (recipe-missing), non-canonical
 *      wire (recipe-wire-not-canonical), root != envelope recipe_root
 *      (recipe-root-mismatch, plan failure AND commit error code), and a
 *      recipe referencing a file the manifest does not carry
 *      (recipe-path-not-in-manifest).
 *   4. zcode package recipe: happy decode (fields, libs, scalars, source
 *      label, execution note), bounded list rendering with the truncated
 *      flag, RECIPE_NOT_HOSTED when the wire is absent, UNKNOWN_PACKAGE
 *      and BAD_ROOT rejections.
 *
 * Handlers run in-process on ./test-tmp datadirs; CHAIN_MAIN is pinned.
 * Nothing here or in the code under test compiles or executes anything —
 * the recipe is declarative; compilation belongs to the external verifier
 * (slice 6). */

#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZR_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_recipe: %s... OK\n", (name)); }       \
    else { printf("  zcode_recipe: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── fixtures (test_zcode_publish.c pattern) ────────────────────────── */

static char *zr_hex(const uint8_t *data, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *out = malloc(2 * len + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[data[i] & 0xf];
    }
    out[2 * len] = '\0';
    return out;
}

static void zr_hex32(const uint8_t in[32], char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

static bool zr_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zr_sign(struct vcs_package_release *r, struct privkey *sk)
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

static bool zr_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0;
    size_t script_len = 0;
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

/* The canonical fixture recipe: one header + one source + one test source
 * + one include dir + one define + libc/libm/pthread + limits. */
static bool zr_recipe(struct vcs_package_recipe *r)
{
    vcs_package_recipe_init(r);
    bool ok =
        vcs_package_recipe_add_header(r, "include/ring.h", NULL) &&
        vcs_package_recipe_add_source(r, "src/ring.c", NULL) &&
        vcs_package_recipe_add_test_source(r, "tests/ring_test.c", NULL) &&
        vcs_package_recipe_add_include_dir(r, "include", NULL) &&
        vcs_package_recipe_add_define(r, "RING_CAP=64", NULL) &&
        vcs_package_recipe_add_library(r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                       NULL) &&
        vcs_package_recipe_add_library(r, VCS_PACKAGE_RECIPE_LIB_LIBM,
                                       NULL) &&
        vcs_package_recipe_add_library(r, VCS_PACKAGE_RECIPE_LIB_PTHREAD,
                                       NULL);
    vcs_package_recipe_set_test_limits(r, 0, 120,
                                       UINT64_C(1024) * 1024u * 1024u);
    return ok;
}

/* Serialize + hex + root for a recipe; frees nothing on *r. */
static char *zr_recipe_hex(const struct vcs_package_recipe *r,
                           uint8_t root_out[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_recipe_root(r, root_out) != VCS_PACKAGE_RECIPE_OK ||
        vcs_package_recipe_serialize(r, &wire, &wire_len) !=
            VCS_PACKAGE_RECIPE_OK)
        return NULL;
    char *hex = zr_hex(wire, wire_len);
    free(wire);
    return hex;
}

/* A signed release committing recipe_root. */
static bool zr_release(struct vcs_package_release *r, uint8_t key_seed,
                       uint64_t sequence, const char *name,
                       const uint8_t package_root[32],
                       const uint8_t recipe_root[32])
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zr_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zr_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    memcpy(r->recipe_root, recipe_root, 32);
    r->has_znam = false;
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zr_sign(r, &sk);
}

static char *zr_release_hex(const struct vcs_package_release *r)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(r, &wire, &wire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return NULL;
    char *hex = zr_hex(wire, wire_len);
    free(wire);
    return hex;
}

/* ── the fixture package: LICENSE + include/ring.h + src/ring.c +
 * tests/ring_test.c on disk, manifest with real chunk hashes ────────── */

struct zr_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
};

static void zr_pkg_free(struct zr_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

static bool zr_add_file(struct zr_pkg *p, const char *dir, const char *path,
                        const char *content)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, path);
    const char *slash = strrchr(path, '/');
    if (slash) {
        char parent[1024];
        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        if (mkdir(parent, 0700) != 0) {
            /* EEXIST is fine. */
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t len = strlen(content);
    bool wrote = fwrite(content, 1, len, f) == len;
    fclose(f);
    if (!wrote)
        return false;
    uint8_t hash[32];
    if (!vcs_package_chunk_hash((const uint8_t *)content, len, hash))
        return false;
    return vcs_package_manifest_add(&p->manifest, path,
                                    VCS_PACKAGE_MODE_FILE, len, hash, 1);
}

static bool zr_make_package(struct zr_pkg *p, const char *dir)
{
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    mkdir(dir, 0700);
    if (!zr_add_file(p, dir, "LICENSE",
                     "MIT License\n\nPermission is hereby granted.\n") ||
        !zr_add_file(p, dir, "include/ring.h",
                     "#pragma once\nstruct ring { unsigned head, tail; };\n") ||
        !zr_add_file(p, dir, "src/ring.c",
                     "#include \"ring.h\"\nint ring_push(void) { return 0; }\n") ||
        !zr_add_file(p, dir, "tests/ring_test.c",
                     "int main(void) { return 0; }\n"))
        return false;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    zr_hex32(p->root, p->root_hex);
    return true;
}

/* ── in-process command runner ──────────────────────────────────────── */

struct zr_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zr_cmd_init(struct zr_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_recipe_test.v1");
}

static void zr_cmd_free(struct zr_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const char *zr_failure_rule(const struct zcl_command_reply *reply,
                                   size_t i)
{
    const struct json_value *fails = json_get(&reply->data, "failures");
    if (!fails)
        return NULL;
    const struct json_value *f = json_at(fails, i);
    if (!f)
        return NULL;
    return json_get_str(json_get(f, "rule"));
}

/* ── 1: codec roundtrip + root stability ────────────────────────────── */
static int t_codec(void)
{
    int failures = 0;
    struct vcs_package_recipe r;
    ZR_CHECK("codec: fixture recipe builds", zr_recipe(&r));
    ZR_CHECK("codec: fixture recipe validates",
             vcs_package_recipe_validate(&r) == VCS_PACKAGE_RECIPE_OK);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZR_CHECK("codec: serializes",
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK && wire && wire_len > 0);
    struct vcs_package_recipe back;
    ZR_CHECK("codec: parses back",
             vcs_package_recipe_parse(wire, wire_len, &back) ==
                 VCS_PACKAGE_RECIPE_OK);
    bool same =
        back.public_headers.count == 1 && back.sources.count == 1 &&
        back.test_sources.count == 1 && back.include_dirs.count == 1 &&
        back.defines.count == 1 && back.library_count == 3 &&
        back.expected_test_exit_code == 0 &&
        back.maximum_test_seconds == 120 &&
        back.maximum_memory_bytes == UINT64_C(1024) * 1024u * 1024u;
    if (same)
        same = strcmp(back.public_headers.items[0], "include/ring.h") == 0 &&
               strcmp(back.sources.items[0], "src/ring.c") == 0 &&
               strcmp(back.test_sources.items[0], "tests/ring_test.c") == 0 &&
               strcmp(back.include_dirs.items[0], "include") == 0 &&
               strcmp(back.defines.items[0], "RING_CAP=64") == 0 &&
               back.libraries[0] == VCS_PACKAGE_RECIPE_LIB_LIBC &&
               back.libraries[1] == VCS_PACKAGE_RECIPE_LIB_LIBM &&
               back.libraries[2] == VCS_PACKAGE_RECIPE_LIB_PTHREAD;
    ZR_CHECK("codec: roundtrip field for field", same);

    uint8_t root_a[32];
    uint8_t root_b[32];
    ZR_CHECK("codec: roots compute",
             vcs_package_recipe_root(&r, root_a) == VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_root(&back, root_b) ==
                 VCS_PACKAGE_RECIPE_OK);
    ZR_CHECK("codec: root stable across the roundtrip",
             memcmp(root_a, root_b, 32) == 0);

    /* Frozen KAT: the fixture recipe's root pins the canonical encoding
     * (magic, field order, widths, the domain string). Any drift in the
     * wire format moves this hash — that is a deliberate, reviewable
     * break, never a silent one. */
    char root_hex[65];
    zr_hex32(root_a, root_hex);
    ZR_CHECK("codec: KAT root pins the encoding",
             strcmp(root_hex,
                    "6cf44ed4a51741fecc967207acd88ba1198220bc6013149be475de"
                    "dbef263053") == 0);

    vcs_package_recipe_free(&back);
    vcs_package_recipe_free(&r);
    free(wire);
    return failures;
}

#define ZR_SCHEMA2_KAT \
    "3c6d7e680ed247c482b6d35f11feefbc2db4bcacc2a590c47d45daf3afb9c7c2"

/* ── 1b: schema 2 — the declared programs list ──────────────────────── */

/* A hand-made wire: the canonical schema-1 encoding with the version field
 * (the two bytes after the 8-byte magic) overwritten and arbitrary bytes
 * appended. Nothing else about the encoding is assumed. */
static uint8_t *zr_wire_variant(const uint8_t *base, size_t base_len,
                                uint16_t version, const uint8_t *extra,
                                size_t extra_len, size_t *out_len)
{
    uint8_t *w = malloc(base_len + extra_len + 1u);
    if (!w)
        return NULL;
    memcpy(w, base, base_len);
    w[VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES] = (uint8_t)(version & 0xffu);
    w[VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES + 1u] = (uint8_t)(version >> 8);
    if (extra_len > 0)
        memcpy(w + base_len, extra, extra_len);
    *out_len = base_len + extra_len;
    return w;
}

/* [2 count][2 len][path] — one program list holding exactly one entry. */
static size_t zr_program_list(uint8_t *out, const char *path)
{
    size_t len = strlen(path);
    out[0] = 1; out[1] = 0;
    out[2] = (uint8_t)(len & 0xffu);
    out[3] = (uint8_t)(len >> 8);
    memcpy(out + 4, path, len);
    return 4u + len;
}

/* The fixture recipe plus the four files zr_recipe names, so the programs
 * list is the only thing membership can fail on. */
static bool zr_manifest_without_app(struct vcs_package_manifest *m)
{
    static const char *const paths[] = {
        "include/ring.h", "src/ring.c", "tests/ring_test.c",
    };
    vcs_package_manifest_init(m);
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        uint8_t hash[32];
        const char *body = "x\n";
        if (!vcs_package_chunk_hash((const uint8_t *)body, strlen(body),
                                    hash) ||
            !vcs_package_manifest_add(m, paths[i], VCS_PACKAGE_MODE_FILE,
                                      strlen(body), hash, 1))
            return false;
    }
    return true;
}

static int t_programs(void)
{
    int failures = 0;
    enum vcs_package_recipe_error err = VCS_PACKAGE_RECIPE_OK;

    /* Roundtrip: the fixture recipe plus two programs. */
    struct vcs_package_recipe r;
    ZR_CHECK("programs: schema-2 fixture builds",
             zr_recipe(&r) &&
             vcs_package_recipe_add_program(&r, "app/main.c", NULL) &&
             vcs_package_recipe_add_program(&r, "app/tool.c", NULL));
    ZR_CHECK("programs: a program raises the recipe to schema 2",
             r.schema_version == VCS_PACKAGE_RECIPE_VERSION_PROGRAMS);
    ZR_CHECK("programs: schema-2 fixture validates",
             vcs_package_recipe_validate(&r) == VCS_PACKAGE_RECIPE_OK);

    uint8_t *wire2 = NULL;
    size_t wire2_len = 0;
    ZR_CHECK("programs: schema-2 recipe serializes",
             vcs_package_recipe_serialize(&r, &wire2, &wire2_len) ==
                 VCS_PACKAGE_RECIPE_OK && wire2 && wire2_len > 0);
    struct vcs_package_recipe back;
    ZR_CHECK("programs: schema-2 wire parses back",
             vcs_package_recipe_parse(wire2, wire2_len, &back) ==
                 VCS_PACKAGE_RECIPE_OK);
    ZR_CHECK("programs: roundtrip field for field",
             back.schema_version == VCS_PACKAGE_RECIPE_VERSION_PROGRAMS &&
             back.programs.count == 2 &&
             strcmp(back.programs.items[0], "app/main.c") == 0 &&
             strcmp(back.programs.items[1], "app/tool.c") == 0 &&
             back.public_headers.count == 1 && back.sources.count == 1 &&
             back.test_sources.count == 1 && back.include_dirs.count == 1 &&
             back.defines.count == 1 && back.library_count == 3);
    uint8_t root_a[32], root_b[32];
    ZR_CHECK("programs: schema-2 roots compute",
             vcs_package_recipe_root(&r, root_a) == VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_root(&back, root_b) ==
                 VCS_PACKAGE_RECIPE_OK);
    ZR_CHECK("programs: schema-2 root stable across the roundtrip",
             memcmp(root_a, root_b, 32) == 0);

    /* Frozen KAT: this pins the schema-2 encoding — the trailing program
     * list's position, count width, entry framing and order — exactly as
     * the schema-1 KAT in t_codec pins the encoding a recipe without
     * programs still has. The two KATs are independent on purpose: the
     * schema-1 value must never move when schema 2 changes. */
    char root_hex[65];
    zr_hex32(root_a, root_hex);
    ZR_CHECK("programs: schema-2 KAT root pins the encoding",
             strcmp(root_hex, ZR_SCHEMA2_KAT) == 0);
    vcs_package_recipe_free(&back);

    /* Builder rejections: the program grammar is exactly `app/<stem>.c`. */
    static const char *const not_programs[] = {
        "src/x.c", "app/a/b.c", "app/x.h", "app/.c", "tests/t.c",
    };
    for (size_t i = 0; i < sizeof(not_programs) / sizeof(not_programs[0]);
         i++) {
        struct vcs_package_recipe bad;
        vcs_package_recipe_init(&bad);
        err = VCS_PACKAGE_RECIPE_OK;
        bool rejected =
            !vcs_package_recipe_add_program(&bad, not_programs[i], &err) &&
            err == VCS_PACKAGE_RECIPE_ERR_PATH &&
            bad.schema_version == VCS_PACKAGE_RECIPE_VERSION;
        char name[96];
        snprintf(name, sizeof(name), "programs: %s is not a program",
                 not_programs[i]);
        ZR_CHECK(name, rejected);
        vcs_package_recipe_free(&bad);
    }
    err = VCS_PACKAGE_RECIPE_OK;
    ZR_CHECK("programs: a repeated program names the order rule",
             !vcs_package_recipe_add_program(&r, "app/main.c", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_LIST_ORDER);

    /* A schema-1 struct carrying a program has no legal encoding. */
    struct vcs_package_recipe forged;
    ZR_CHECK("programs: schema-1 struct with a program builds",
             zr_recipe(&forged) &&
             vcs_package_recipe_add_program(&forged, "app/main.c", NULL));
    forged.schema_version = VCS_PACKAGE_RECIPE_VERSION;
    ZR_CHECK("programs: schema 1 with a program is a PROGRAM rejection",
             vcs_package_recipe_validate(&forged) ==
                 VCS_PACKAGE_RECIPE_ERR_PROGRAM);
    vcs_package_recipe_free(&forged);

    /* Hand-built wires. The schema-1 encoding of the same recipe is the
     * base; every variant below differs from it only in the version field
     * and the trailing bytes. */
    struct vcs_package_recipe plain;
    (void)zr_recipe(&plain);
    uint8_t *wire1 = NULL;
    size_t wire1_len = 0;
    ZR_CHECK("programs: schema-1 base wire serializes",
             vcs_package_recipe_serialize(&plain, &wire1, &wire1_len) ==
                 VCS_PACKAGE_RECIPE_OK);

    struct vcs_package_recipe out;
    size_t forged_len = 0;
    uint8_t *forged_wire = zr_wire_variant(
        wire1, wire1_len, VCS_PACKAGE_RECIPE_VERSION_PROGRAMS, NULL, 0,
        &forged_len);
    /* Version 2 with no trailing list: the parser reaches the program
     * count and runs off the end, so the codec returns WIRE_TRUNCATED — it
     * never gets far enough to call the mismatch a PROGRAM rejection. */
    ZR_CHECK("programs: version 2 without a list is truncated",
             forged_wire &&
             vcs_package_recipe_parse(forged_wire, forged_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED);
    free(forged_wire);

    uint8_t list[64];
    size_t list_len = zr_program_list(list, "app/main.c");
    forged_wire = zr_wire_variant(wire1, wire1_len,
                                  VCS_PACKAGE_RECIPE_VERSION, list, list_len,
                                  &forged_len);
    ZR_CHECK("programs: version 1 with a list is trailing bytes",
             forged_wire &&
             vcs_package_recipe_parse(forged_wire, forged_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING);
    free(forged_wire);

    uint8_t empty_list[2] = { 0, 0 };
    forged_wire = zr_wire_variant(wire1, wire1_len,
                                  VCS_PACKAGE_RECIPE_VERSION_PROGRAMS,
                                  empty_list, sizeof(empty_list),
                                  &forged_len);
    ZR_CHECK("programs: version 2 with an empty list names the rule",
             forged_wire &&
             vcs_package_recipe_parse(forged_wire, forged_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_PROGRAM);
    free(forged_wire);

    list_len = zr_program_list(list, "src/x.c");
    forged_wire = zr_wire_variant(wire1, wire1_len,
                                  VCS_PACKAGE_RECIPE_VERSION_PROGRAMS, list,
                                  list_len, &forged_len);
    ZR_CHECK("programs: a non-program entry on the wire names the path rule",
             forged_wire &&
             vcs_package_recipe_parse(forged_wire, forged_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_PATH);
    free(forged_wire);
    free(wire1);
    vcs_package_recipe_free(&plain);

    /* Install outputs: app/main.c carries the package's name, every other
     * stem carries its own. */
    char output[VCS_PACKAGE_PATH_MAX];
    ZR_CHECK("programs: app/main.c installs under the package short name",
             vcs_package_recipe_program_output("app/main.c", "wordcount",
                                               output, sizeof(output)) &&
             strcmp(output, "bin/wordcount") == 0);
    ZR_CHECK("programs: app/tool.c installs under its own stem",
             vcs_package_recipe_program_output("app/tool.c", "wordcount",
                                               output, sizeof(output)) &&
             strcmp(output, "bin/tool") == 0);
    ZR_CHECK("programs: an empty short name has no output",
             !vcs_package_recipe_program_output("app/main.c", "", output,
                                                sizeof(output)) &&
             output[0] == '\0');
    ZR_CHECK("programs: a non-program has no output",
             !vcs_package_recipe_program_output("src/main.c", "x", output,
                                                sizeof(output)) &&
             output[0] == '\0');
    ZR_CHECK("programs: an output that does not fit is refused empty",
             !vcs_package_recipe_program_output("app/main.c", "wordcount",
                                                output, 8u) &&
             output[0] == '\0');

    /* Publication membership: a declared program must be a package file. */
    struct vcs_package_manifest m;
    char detail[160] = {0};
    ZR_CHECK("programs: membership manifest builds",
             zr_manifest_without_app(&m));
    ZR_CHECK("programs: a program absent from the manifest is named",
             !vcs_package_recipe_files_in_manifest(&r, &m, detail,
                                                   sizeof(detail)) &&
             strncmp(detail, "programs: app/main.c",
                     strlen("programs: app/main.c")) == 0);
    vcs_package_manifest_free(&m);

    vcs_package_recipe_free(&r);
    free(wire2);
    return failures;
}
/* ── 2: bounds + closed grammar ─────────────────────────────────────── */
static int t_bounds(void)
{
    int failures = 0;
    enum vcs_package_recipe_error err = VCS_PACKAGE_RECIPE_OK;

    /* List count bound: 257 sources. */
    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    bool ok = true;
    for (int i = 0; ok && i < 256; i++) {
        char path[32];
        snprintf(path, sizeof(path), "src/f%03d.c", i);
        ok = vcs_package_recipe_add_source(&r, path, NULL);
    }
    ZR_CHECK("bounds: 256 sources accepted", ok && r.sources.count == 256);
    err = VCS_PACKAGE_RECIPE_OK;
    ZR_CHECK("bounds: 257th source names the count bound",
             !vcs_package_recipe_add_source(&r, "src/f256.c", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND);
    vcs_package_recipe_free(&r);

    /* String bound: a 1025-char path fails the path grammar. */
    vcs_package_recipe_init(&r);
    char long_path[1100];
    memset(long_path, 'a', sizeof(long_path) - 3);
    memcpy(long_path + sizeof(long_path) - 3, ".c", 3);
    err = VCS_PACKAGE_RECIPE_OK;
    ZR_CHECK("bounds: overlong path rejected",
             !vcs_package_recipe_add_source(&r, long_path, &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_PATH);
    vcs_package_recipe_free(&r);

    /* Extensions: a header must end .h, a source must end .c. */
    vcs_package_recipe_init(&r);
    ZR_CHECK("bounds: header extension enforced",
             !vcs_package_recipe_add_header(&r, "include/ring.txt", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_PATH &&
             !vcs_package_recipe_add_source(&r, "src/ring.h", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_PATH);
    vcs_package_recipe_free(&r);

    /* Define grammar: leading digit, embedded space, overlong. */
    vcs_package_recipe_init(&r);
    ZR_CHECK("bounds: define grammar enforced",
             !vcs_package_recipe_add_define(&r, "1BAD", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_DEFINE &&
             !vcs_package_recipe_add_define(&r, "HAS SPACE=1", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_DEFINE &&
             vcs_package_recipe_add_define(&r, "OK_NAME=1", NULL));
    vcs_package_recipe_free(&r);

    /* Library allowlist: unknown name/id rejected; duplicates rejected. */
    ZR_CHECK("bounds: libssl is not on the allowlist",
             vcs_package_recipe_library_id("libssl") == 0);
    vcs_package_recipe_init(&r);
    ZR_CHECK("bounds: unknown library id rejected",
             !vcs_package_recipe_add_library(&r, 9, &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_LIBRARY &&
             vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBM,
                                            NULL) &&
             !vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBM,
                                             &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_LIST_ORDER);
    vcs_package_recipe_free(&r);

    /* Duplicate + unsorted list entries. */
    vcs_package_recipe_init(&r);
    ZR_CHECK("bounds: duplicate entry rejected",
             vcs_package_recipe_add_source(&r, "src/a.c", NULL) &&
             !vcs_package_recipe_add_source(&r, "src/a.c", &err) &&
             err == VCS_PACKAGE_RECIPE_ERR_LIST_ORDER);
    vcs_package_recipe_free(&r);

    /* Hostile paths inside recipe fields. */
    static const char *const hostile[] = {
        "/etc/passwd.c", "../evil.c", "src/../evil.c", "src\\win.c",
        "src//evil.c", "./evil.c",
    };
    for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
        vcs_package_recipe_init(&r);
        err = VCS_PACKAGE_RECIPE_OK;
        bool rejected = !vcs_package_recipe_add_source(&r, hostile[i],
                                                       &err) &&
                        err == VCS_PACKAGE_RECIPE_ERR_PATH;
        char name[96];
        snprintf(name, sizeof(name), "bounds: hostile path %s", hostile[i]);
        ZR_CHECK(name, rejected);
        vcs_package_recipe_free(&r);
    }

    /* Scalar bounds through validate: seconds 0 / 3601, memory low/high,
     * empty sources. */
    vcs_package_recipe_init(&r);
    (void)vcs_package_recipe_add_source(&r, "src/a.c", NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 0,
                                       UINT64_C(64) * 1024u * 1024u);
    ZR_CHECK("bounds: zero seconds rejected",
             vcs_package_recipe_validate(&r) ==
                 VCS_PACKAGE_RECIPE_ERR_TEST_SECONDS);
    vcs_package_recipe_set_test_limits(&r, 0, 3601,
                                       UINT64_C(64) * 1024u * 1024u);
    ZR_CHECK("bounds: 3601 seconds rejected",
             vcs_package_recipe_validate(&r) ==
                 VCS_PACKAGE_RECIPE_ERR_TEST_SECONDS);
    vcs_package_recipe_set_test_limits(&r, 0, 60, 1024);
    ZR_CHECK("bounds: sub-1MiB memory rejected",
             vcs_package_recipe_validate(&r) ==
                 VCS_PACKAGE_RECIPE_ERR_MEMORY_BYTES);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(17) * 1024u * 1024u * 1024u);
    ZR_CHECK("bounds: over-16GiB memory rejected",
             vcs_package_recipe_validate(&r) ==
                 VCS_PACKAGE_RECIPE_ERR_MEMORY_BYTES);
    vcs_package_recipe_free(&r);
    vcs_package_recipe_init(&r);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    ZR_CHECK("bounds: empty sources rejected",
             vcs_package_recipe_validate(&r) ==
                 VCS_PACKAGE_RECIPE_ERR_SOURCES_EMPTY);
    vcs_package_recipe_free(&r);

    /* Closed grammar on the wire: bad magic, unknown version, trailing
     * bytes, unknown library id, unsorted wire list, truncated wire. */
    struct vcs_package_recipe good;
    (void)zr_recipe(&good);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ZR_CHECK("bounds: good wire serializes",
             vcs_package_recipe_serialize(&good, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK);
    struct vcs_package_recipe out;
    uint8_t saved = wire[0];
    wire[0] = 'X';
    ZR_CHECK("bounds: bad magic rejected",
             vcs_package_recipe_parse(wire, wire_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_MAGIC);
    wire[0] = saved;
    saved = wire[9];
    wire[9] = 9; /* version high byte */
    ZR_CHECK("bounds: unknown version rejected",
             vcs_package_recipe_parse(wire, wire_len, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_SCHEMA_VERSION);
    wire[9] = saved;
    ZR_CHECK("bounds: trailing byte rejected",
             vcs_package_recipe_parse(wire, wire_len + 1, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING);
    ZR_CHECK("bounds: truncated wire rejected",
             vcs_package_recipe_parse(wire, wire_len - 1, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING ||
             vcs_package_recipe_parse(wire, wire_len - 1, &out) ==
                 VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED);
    free(wire);
    vcs_package_recipe_free(&good);
    return failures;
}

/* ── 3: publish integration ─────────────────────────────────────────── */
static int t_publish(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_recipe", "publish");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zr_pkg p;
    ZR_CHECK("publish: package fixture builds", zr_make_package(&p, pkgdir));
    struct vcs_package_recipe r;
    ZR_CHECK("publish: recipe fixture builds", zr_recipe(&r));
    uint8_t recipe_root[32];
    char *recipe_hex = zr_recipe_hex(&r, recipe_root);
    ZR_CHECK("publish: recipe encodes", recipe_hex != NULL);
    struct vcs_package_release rel;
    ZR_CHECK("publish: release signs",
             zr_release(&rel, 0x11, 1u, "rhett/ring-buffer", p.root,
                        recipe_root));
    char *release_hex = zr_release_hex(&rel);
    char *manifest_hex = zr_hex(p.wire, p.wire_len);

    /* Happy path: plan valid + recipe summary present. */
    struct zr_cmd c;
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    const struct json_value *rcp = json_get(&c.reply.data, "recipe");
    const char *rc_root =
        rcp ? json_get_str(json_get(rcp, "recipe_root")) : NULL;
    char expect_root[65];
    zr_hex32(recipe_root, expect_root);
    ZR_CHECK("publish: valid candidate passes with the recipe summary",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "valid")) &&
             zr_failure_rule(&c.reply, 0) == NULL && rcp &&
             json_get_bool(json_get(rcp, "valid")) && rc_root &&
             strcmp(rc_root, expect_root) == 0 &&
             json_get_int(json_get(rcp, "sources")) == 1 &&
             json_get_int(json_get(rcp, "test_sources")) == 1 &&
             json_get_int(json_get(rcp, "maximum_test_seconds")) == 120);
    zr_cmd_free(&c);

    /* Missing recipe: plan failure names recipe-missing; commit fails with
     * the same code. */
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZR_CHECK("publish: missing recipe rejected naming the rule",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zr_failure_rule(&c.reply, 0) &&
             strcmp(zr_failure_rule(&c.reply, 0), "recipe-missing") == 0);
    zr_cmd_free(&c);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZR_CHECK("publish: commit without recipe names the rule",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "recipe-missing") == 0);
    zr_cmd_free(&c);

    /* Non-canonical recipe wire. */
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", "deadbeef");
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZR_CHECK("publish: bad recipe wire rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zr_failure_rule(&c.reply, 0) &&
             strcmp(zr_failure_rule(&c.reply, 0),
                    "recipe-wire-not-canonical") == 0);
    zr_cmd_free(&c);

    /* Root mismatch: a valid recipe whose root the envelope does NOT
     * commit (the envelope names the fixture recipe's root). */
    struct vcs_package_recipe other;
    vcs_package_recipe_init(&other);
    ZR_CHECK("publish: foreign recipe builds",
             vcs_package_recipe_add_source(&other, "src/ring.c", NULL));
    vcs_package_recipe_set_test_limits(&other, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t other_root[32];
    char *other_hex = zr_recipe_hex(&other, other_root);
    ZR_CHECK("publish: foreign recipe encodes",
             other_hex && memcmp(other_root, recipe_root, 32) != 0);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", other_hex);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZR_CHECK("publish: root mismatch rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zr_failure_rule(&c.reply, 0) &&
             strcmp(zr_failure_rule(&c.reply, 0),
                    "recipe-root-mismatch") == 0);
    zr_cmd_free(&c);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", other_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZR_CHECK("publish: commit of a mismatched recipe names the rule",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "recipe-root-mismatch") == 0);
    zr_cmd_free(&c);
    free(other_hex);
    vcs_package_recipe_free(&other);

    /* Path not in the manifest: the envelope commits THIS recipe's root,
     * so the release must be re-signed over the ghost recipe's root. */
    struct vcs_package_recipe ghost;
    vcs_package_recipe_init(&ghost);
    ZR_CHECK("publish: ghost recipe builds",
             vcs_package_recipe_add_source(&ghost, "src/ghost.c", NULL));
    vcs_package_recipe_set_test_limits(&ghost, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t ghost_root[32];
    char *ghost_hex = zr_recipe_hex(&ghost, ghost_root);
    struct vcs_package_release rel2;
    ZR_CHECK("publish: ghost release signs",
             ghost_hex &&
             zr_release(&rel2, 0x11, 1u, "rhett/ring-buffer", p.root,
                        ghost_root));
    char *release2_hex = zr_release_hex(&rel2);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release2_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", ghost_hex);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    const struct json_value *f0 =
        json_at(json_get(&c.reply.data, "failures"), 0);
    const char *f0_detail = f0 ? json_get_str(json_get(f0, "detail")) : NULL;
    ZR_CHECK("publish: recipe path outside the manifest rejected",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zr_failure_rule(&c.reply, 0) &&
             strcmp(zr_failure_rule(&c.reply, 0),
                    "recipe-path-not-in-manifest") == 0 && f0_detail &&
             strstr(f0_detail, "src/ghost.c") != NULL);
    zr_cmd_free(&c);
    free(ghost_hex);
    free(release2_hex);
    vcs_package_recipe_free(&ghost);

    free(recipe_hex);
    free(release_hex);
    free(manifest_hex);
    vcs_package_recipe_free(&r);
    zr_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4: zcode package recipe command ────────────────────────────────── */
static int t_command(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_recipe", "command");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zr_pkg p;
    ZR_CHECK("command: package fixture builds", zr_make_package(&p, pkgdir));
    struct vcs_package_recipe r;
    ZR_CHECK("command: recipe fixture builds", zr_recipe(&r));
    uint8_t recipe_root[32];
    char *recipe_hex = zr_recipe_hex(&r, recipe_root);
    struct vcs_package_release rel;
    ZR_CHECK("command: release signs",
             recipe_hex &&
             zr_release(&rel, 0x11, 1u, "rhett/ring-buffer", p.root,
                        recipe_root));
    char *release_hex = zr_release_hex(&rel);
    char *manifest_hex = zr_hex(p.wire, p.wire_len);

    struct zr_cmd c;
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZR_CHECK("command: package with recipe commits locally",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_str(json_get(&c.reply.data, "result")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "result")),
                    "committed") == 0);
    zr_cmd_free(&c);
    char recipe_root_hex[65];
    zr_hex32(recipe_root, recipe_root_hex);
    char path[512];
    snprintf(path, sizeof(path), "%s/zcode/recipes/%s", dd,
             recipe_root_hex);
    struct stat st;
    ZR_CHECK("command: recipe wire persisted", stat(path, &st) == 0);

    /* Decode it back through the command. */
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_recipe(&c.request, &c.reply);
    const struct json_value *rcp = json_get(&c.reply.data, "recipe");
    const struct json_value *srcs = rcp ? json_get(rcp, "sources") : NULL;
    const struct json_value *libs =
        rcp ? json_get(rcp, "allowed_system_libraries") : NULL;
    const char *src0 =
        srcs ? json_get_str(json_at(srcs, 0)) : NULL;
    const char *lib2 = libs ? json_get_str(json_at(libs, 2)) : NULL;
    ZR_CHECK("command: recipe decodes from the canonical wire",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && rcp && src0 &&
             strcmp(src0, "src/ring.c") == 0 && libs &&
             json_size(libs) == 3 && lib2 && strcmp(lib2, "pthread") == 0 &&
             json_get_int(json_get(rcp, "expected_test_exit_code")) == 0 &&
             json_get_int(json_get(rcp, "maximum_test_seconds")) == 120 &&
             json_get_int(json_get(rcp, "maximum_memory_bytes")) ==
                 (int64_t)(UINT64_C(1024) * 1024u * 1024u));
    const char *nm = json_get_str(json_get(&c.reply.data, "name"));
    const char *rr = json_get_str(json_get(&c.reply.data, "recipe_root"));
    const char *src = json_get_str(json_get(&c.reply.data, "source"));
    ZR_CHECK("command: identity from the signed envelope",
             nm && strcmp(nm, "rhett/ring-buffer") == 0 && rr &&
             strcmp(rr, recipe_root_hex) == 0 && src &&
             strcmp(src, "canonical-recipe-wire") == 0 &&
             json_get_str(json_get(&c.reply.data, "execution_note")));
    ZR_CHECK("command: short lists not flagged truncated",
             !json_get_bool(json_get(rcp, "sources_truncated")));
    zr_cmd_free(&c);

    /* The wire vanishes -> RECIPE_NOT_HOSTED (the store never invents a
     * recipe). */
    ZR_CHECK("command: recipe wire removed", remove(path) == 0);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_recipe(&c.request, &c.reply);
    ZR_CHECK("command: absent recipe wire named",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "RECIPE_NOT_HOSTED") == 0);
    zr_cmd_free(&c);

    /* Unknown root / malformed root. */
    char unknown[65];
    memset(unknown, '9', 64);
    unknown[64] = '\0';
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", unknown);
    zcl_native_handle_zcode_package_recipe(&c.request, &c.reply);
    ZR_CHECK("command: unknown root rejected",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "UNKNOWN_PACKAGE") == 0);
    zr_cmd_free(&c);
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", "xyz");
    zcl_native_handle_zcode_package_recipe(&c.request, &c.reply);
    ZR_CHECK("command: bad root hex rejected",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "BAD_ROOT") == 0);
    zr_cmd_free(&c);

    free(recipe_hex);
    free(release_hex);
    free(manifest_hex);
    vcs_package_recipe_free(&r);
    zr_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 5: bounded command output ──────────────────────────────────────── */
static int t_bounded(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_recipe", "bounded");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);

    /* A package with 40 sources: the command renders at most 32 and flags
     * the rest. */
    struct zr_pkg p;
    memset(&p, 0, sizeof(p));
    vcs_package_manifest_init(&p.manifest);
    mkdir(pkgdir, 0700);
    char srcdir[512];
    snprintf(srcdir, sizeof(srcdir), "%s/src", pkgdir);
    mkdir(srcdir, 0700);
    bool ok = zr_add_file(&p, pkgdir, "LICENSE", "MIT\n");
    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    for (int i = 0; ok && i < 40; i++) {
        char rel[32];
        snprintf(rel, sizeof(rel), "src/f%02d.c", i);
        ok = zr_add_file(&p, pkgdir, rel, "int x;\n") &&
             vcs_package_recipe_add_source(&r, rel, NULL);
    }
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    if (ok)
        ok = vcs_package_manifest_serialize(&p.manifest, &p.wire,
                                            &p.wire_len) &&
             vcs_package_manifest_root(&p.manifest, p.root);
    if (ok)
        zr_hex32(p.root, p.root_hex);
    ZR_CHECK("bounded: 40-source package builds", ok);
    uint8_t recipe_root[32];
    char *recipe_hex = ok ? zr_recipe_hex(&r, recipe_root) : NULL;
    struct vcs_package_release rel;
    ZR_CHECK("bounded: release signs",
             recipe_hex &&
             zr_release(&rel, 0x11, 1u, "rhett/many-sources", p.root,
                        recipe_root));
    char *release_hex = zr_release_hex(&rel);
    char *manifest_hex = zr_hex(p.wire, p.wire_len);

    struct zr_cmd c;
    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZR_CHECK("bounded: package publishes",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zr_cmd_free(&c);

    zr_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_recipe(&c.request, &c.reply);
    const struct json_value *rcp = json_get(&c.reply.data, "recipe");
    const struct json_value *srcs = rcp ? json_get(rcp, "sources") : NULL;
    ZR_CHECK("bounded: source list capped and flagged",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && srcs &&
             json_size(srcs) == 32 &&
             json_get_bool(json_get(rcp, "sources_truncated")));
    zr_cmd_free(&c);

    free(recipe_hex);
    free(release_hex);
    free(manifest_hex);
    vcs_package_recipe_free(&r);
    zr_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

int test_zcode_recipe(void)
{
    printf("\n=== zcode_recipe: declarative C23 build recipe ===\n");
    int failures = 0;
    failures += t_codec();
    failures += t_programs();
    failures += t_bounds();
    failures += t_publish();
    failures += t_command();
    failures += t_bounded();
    printf("=== zcode_recipe complete: %d failure(s) ===\n", failures);
    return failures;
}
