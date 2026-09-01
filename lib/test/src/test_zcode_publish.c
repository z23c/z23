/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_publish — the ZCODE publication + local search gate
 * (lib/vcs/package_publish.*, lib/vcs/package_index.*, and the
 * zcode.package.* native handlers in tools/command/native_zcode_command.c).
 *
 * Coverage:
 *   1. publish plan happy path (with and without a chunk source dir) and
 *      the plan-token == release-id correlation.
 *   2. License policy: unknown/missing(compound) SPDX ids rejected at the
 *      envelope layer naming "spdx-license"; a manifest without a LICENSE
 *      file rejected naming "license-text-missing".
 *   3. Package structure: traversal path, symlink mode, duplicate canonical
 *      paths, oversized wire (manifest grammar); hidden executable payload;
 *      over-64MiB package; release/manifest root mismatch.
 *   4. Chunk checks: source missing, size mismatch, hash mismatch — each
 *      names its rule and coordinates.
 *   5. publish commit: roundtrip persists manifest + chunks + release;
 *      idempotent recommit reports "duplicate"; commit of a release that
 *      fails plan names the failed rule.
 *   6. Acceptance replay: equivocation, stale sequence, namespace conflict
 *      against persisted releases; a higher sequence commits.
 *   7. search: publisher/name-prefix/license/keyword filters, miss,
 *      bounds (limit + items_truncated), empty store.
 *   8. library: complete tracked store catalog (empty store, name from
 *      the index, complete/pinned/counts/public_serveable, next_command
 *      on empty and non-empty shelves). Fetch by that local name after
 *      a published complete package; name+root mismatch fails closed.
 *  8b. library reproduction evidence: every row carries the local
 *      receipts scan (the publish-gate predicate) or an unevaluable
 *      error object (transport-carrier packages — no persisted release —
 *      are the production unnamed case); the reply censuses
 *      evaluated/reproduced rows; evidence never fails the view.
 *   9. show: full record + manifest summary + bounded file page;
 *      UNKNOWN_PACKAGE and BAD_ROOT rejections.
 *  10. Index rebuild: a fresh build from the persisted CAS bytes equals the
 *      pre-"crash" build entry for entry (the index holds no truth).
 *  11. THE CLI PATH (t_registry_path): the same publication driven through
 *      the catalog the way `z23 zcode package publish ...` drives it
 *      — zcl_command_registry_input_validate() first, then the handler the
 *      leaf BINDS. Cases 1-9 call the handler symbol directly, which skips
 *      input_validate entirely; that blind spot shipped a plan leaf that
 *      REQUIRED recipe_hex and never declared it, so passing the key was
 *      INVALID_INPUT and omitting it was RECIPE_MISSING and the command was
 *      uncallable in every build. Direct-handler coverage cannot see that,
 *      by construction: this case exists to cross the layer that rejected it.
 *
 * Handlers run in-process on ./test-tmp datadirs; CHAIN_MAIN is pinned so
 * the chain-id and reward rules are deterministic. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "presentation/model.h"
#include "vcs/package_index.h"
#include "vcs/package_build.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZP_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_publish: %s... OK\n", (name)); }      \
    else { printf("  zcode_publish: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── fixtures ───────────────────────────────────────────────────────── */

static void zp_hex32(const uint8_t in[32], char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

/* malloc'd hex of arbitrary bytes (release/manifest wires). */
static char *zp_hex(const uint8_t *data, size_t len)
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

static bool zp_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zp_pubkey_hex(uint8_t seed, char out[67])
{
    static const char hexd[] = "0123456789abcdef";
    struct privkey sk;
    struct pubkey pk;
    if (!zp_keypair(seed, &sk, &pk))
        return false;
    for (size_t i = 0; i < pk.size; i++) {
        out[2 * i]     = hexd[(pk.vch[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[pk.vch[i] & 0xf];
    }
    out[2 * pk.size] = '\0';
    return true;
}

static bool zp_sign(struct vcs_package_release *r, struct privkey *sk)
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

static bool zp_t1_reward(char *out, size_t out_size)
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

/* ── declarative build recipe fixture (slice 5) ───────────────────────
 * Every publish input must now carry a recipe whose root the envelope
 * commits. zp_use_recipe derives the fixture recipe from a package's
 * manifest: every .h a public header (its parent dir an include dir),
 * every .c a source; one define, libc only, exit 0, 60 s, 64 MiB. The
 * globals feed zp_release (the committed recipe_root) and
 * zp_publish_input (the recipe wire hex). */
static char *g_zp_recipe_hex;
static uint8_t g_zp_recipe_root[32];

static bool zp_use_recipe(const struct vcs_package_manifest *m)
{
    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    bool ok = true;
    for (size_t i = 0; ok && i < m->count; i++) {
        const char *path = m->files[i].path;
        size_t len = strlen(path);
        if (len > 2 && strcmp(path + len - 2, ".h") == 0) {
            ok = vcs_package_recipe_add_header(&r, path, NULL);
            const char *slash = strrchr(path, '/');
            if (ok && slash) {
                char dir[1024];
                snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path),
                         path);
                /* A repeat dir (second header) is fine. */
                enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
                if (!vcs_package_recipe_add_include_dir(&r, dir, &rerr) &&
                    rerr != VCS_PACKAGE_RECIPE_ERR_LIST_ORDER)
                    ok = false;
            }
        } else if (len > 2 && strcmp(path + len - 2, ".c") == 0) {
            ok = vcs_package_recipe_add_source(&r, path, NULL);
        }
    }
    if (ok)
        ok = vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
             vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                            NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, g_zp_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok) {
        free(wire);
        return false;
    }
    free(g_zp_recipe_hex);
    g_zp_recipe_hex = zp_hex(wire, wire_len);
    free(wire);
    return g_zp_recipe_hex != NULL;
}

/* A valid, signed release naming package_root. */
static bool zp_release(struct vcs_package_release *r, uint8_t key_seed,
                       uint64_t sequence, const char *name,
                       const char *license, const uint8_t package_root[32])
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zp_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zp_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "%s", license);
    memcpy(r->recipe_root, g_zp_recipe_root, 32);
    r->has_znam = false;
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zp_sign(r, &sk);
}

/* malloc'd canonical wire + hex for a release. */
static char *zp_release_hex(const struct vcs_package_release *r,
                            uint8_t **wire_out, size_t *wire_len_out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(r, &wire, &wire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return NULL;
    char *hex = zp_hex(wire, wire_len);
    if (!hex) {
        free(wire);
        return NULL;
    }
    if (wire_out)
        *wire_out = wire;
    else
        free(wire);
    if (wire_len_out)
        *wire_len_out = wire_len;
    return hex;
}

/* File a build receipt under <dd>/zcode/receipts/<receipt-id-hex> — the
 * exact location and name vcs_package_reproduce_scan enumerates. */
static bool zp_file_receipt(const char *dd,
                            const struct vcs_package_build_receipt *r)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t id[32];
    if (vcs_package_build_serialize(r, &wire, &wire_len) !=
            VCS_PACKAGE_BUILD_OK ||
        vcs_package_build_id(r, id) != VCS_PACKAGE_BUILD_OK) {
        free(wire);
        return false;
    }
    char id_hex[65];
    zp_hex32(id, id_hex);
    char dir[600], path[700];
    snprintf(dir, sizeof(dir), "%s/zcode/receipts", dd);
    if (mkdir(dir, 0700) != 0) {
        /* EEXIST is fine (a second receipt under the same datadir). */
    }
    snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    FILE *f = fopen(path, "wb");
    bool wrote = f && fwrite(wire, 1, wire_len, f) == wire_len;
    if (f)
        fclose(f);
    free(wire);
    return wrote;
}

struct zp_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
};

static void zp_pkg_free(struct zp_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* Write <dir>/<path> (creating the single parent directory when the path
 * has one), then add the file to the manifest with its real chunk hash. */
static bool zp_add_file(struct zp_pkg *p, const char *dir, const char *path,
                        const char *content, uint32_t mode)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, path);
    const char *slash = strrchr(path, '/');
    if (slash) {
        char parent[1024];
        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        if (mkdir(parent, 0700) != 0) {
            /* EEXIST is fine (a second file under the same parent). */
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
    return vcs_package_manifest_add(&p->manifest, path, mode, len, hash, 1);
}

/* The happy-path package: LICENSE + include/ring.h + src/ring.c. */
static bool zp_make_package(struct zp_pkg *p, const char *dir)
{
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    mkdir(dir, 0700);
    if (!zp_add_file(p, dir, "LICENSE",
                     "MIT License\n\nPermission is hereby granted.\n",
                     VCS_PACKAGE_MODE_FILE) ||
        !zp_add_file(p, dir, "include/ring.h",
                     "#pragma once\nstruct ring { unsigned head, tail; };\n",
                     VCS_PACKAGE_MODE_FILE) ||
        !zp_add_file(p, dir, "src/ring.c",
                     "#include \"ring.h\"\nint ring_push(void) { return 0; }\n",
                     VCS_PACKAGE_MODE_FILE))
        return false;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    zp_hex32(p->root, p->root_hex);
    return true;
}

/* Hand-encode a one- or two-file manifest wire with caller-chosen paths and
 * modes — the only way to get a traversal path, a hostile mode, or a
 * duplicate path past the builder. */
static size_t zp_raw_wire(uint8_t *out, const char *path1, uint32_t mode1,
                          const char *path2, uint32_t mode2)
{
    size_t n = 0;
    memcpy(out + n, "ZCLPKG\r\n", 8); n += 8;
    out[n++] = 1; out[n++] = 0;                          /* version */
    out[n++] = 0; out[n++] = 0; out[n++] = 16; out[n++] = 0; /* 1 MiB */
    uint32_t files = path2 ? 2u : 1u;
    out[n++] = (uint8_t)files; out[n++] = 0; out[n++] = 0; out[n++] = 0;
    for (uint32_t i = 0; i < files; i++) {
        const char *path = i == 0 ? path1 : path2;
        uint32_t mode = i == 0 ? mode1 : mode2;
        uint16_t plen = (uint16_t)strlen(path);
        out[n++] = (uint8_t)plen; out[n++] = (uint8_t)(plen >> 8);
        memcpy(out + n, path, plen); n += plen;
        out[n++] = (uint8_t)mode; out[n++] = (uint8_t)(mode >> 8);
        out[n++] = (uint8_t)(mode >> 16); out[n++] = (uint8_t)(mode >> 24);
        memset(out + n, 0, 8); n += 8;                   /* size = 0 */
        memset(out + n, 0, 4); n += 4;                   /* chunks = 0 */
    }
    return n;
}

/* ── in-process command runner ──────────────────────────────────────── */

struct zp_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zp_cmd_init(struct zp_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_test.v1");
}

static void zp_cmd_free(struct zp_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Standard publish input: release hex + manifest hex + recipe hex +
 * datadir (+dir). The recipe hex is the last zp_use_recipe() build — a
 * candidate without one now fails plan naming recipe-missing. The `day`
 * input advances one ISO week per call: the slice-11 publish-frequency
 * checkpoint (new user: 1 publication/week per publisher key) counts
 * same-week commits, and these tests exercise validation, search, and
 * acceptance — never the frequency gate — so each commit lands in its
 * own week (plan ignores the key). */
static void zp_publish_input(struct zp_cmd *c, const char *dd,
                             const char *release_hex,
                             const char *manifest_hex, const char *dir)
{
    static unsigned zp_week_seq = 0;
    zp_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "release_hex", release_hex);
    (void)json_push_kv_str(&c->input, "manifest_hex", manifest_hex);
    if (g_zp_recipe_hex)
        (void)json_push_kv_str(&c->input, "recipe_hex", g_zp_recipe_hex);
    if (dir)
        (void)json_push_kv_str(&c->input, "dir", dir);
    (void)json_push_kv_int(&c->input, "day",
                           20000 + 7 * (int64_t)zp_week_seq++);
}

/* Rule string of failure i in a plan reply, or NULL. */
static const char *zp_failure_rule(const struct zcl_command_reply *reply,
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

static const char *zp_failure_detail(const struct zcl_command_reply *reply,
                                     size_t i)
{
    const struct json_value *fails = json_get(&reply->data, "failures");
    if (!fails)
        return NULL;
    const struct json_value *f = json_at(fails, i);
    if (!f)
        return NULL;
    return json_get_str(json_get(f, "detail"));
}

/* The byte offset of the license field inside a canonical release wire
 * (for the same-length tamper that keeps the wire decodable-length while
 * breaking the license rule). */
static size_t zp_license_offset(const uint8_t *wire)
{
    size_t off = 8 + 2;                          /* magic + schema */
    uint16_t name_len = (uint16_t)(wire[off] | (wire[off + 1] << 8));
    off += 2 + name_len;
    uint16_t semver_len = (uint16_t)(wire[off] | (wire[off + 1] << 8));
    off += 2 + semver_len + 32;                  /* + package_root */
    bool parent = wire[off++] != 0;
    if (parent)
        off += 32;
    off += 33 + 8;                               /* pubkey + sequence */
    uint16_t reward_len = (uint16_t)(wire[off] | (wire[off + 1] << 8));
    off += 2 + reward_len;
    return off + 2;                              /* skip license_len */
}

/* ── 1: plan happy path ─────────────────────────────────────────────── */
static int t_plan_happy(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "plan");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);

    struct zp_pkg p;
    ZP_CHECK("plan: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("plan: recipe fixture builds", zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("plan: release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT", p.root));
    char *release_hex = zp_release_hex(&r, NULL, NULL);
    char *manifest_hex = zp_hex(p.wire, p.wire_len);
    ZP_CHECK("plan: inputs encode", release_hex && manifest_hex);

    struct zp_cmd c;
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("plan: valid candidate passes",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "valid")));
    ZP_CHECK("plan: verified chunks are ready for one commit action",
             json_get_bool(json_get(&c.reply.data, "ready_to_commit")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "readiness")),
                    "ready_to_commit") == 0 &&
             strcmp(json_get_str(json_get(&c.reply.data, "next_action")),
                    "zcode package publish commit") == 0);
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZP_CHECK("plan: release id computes",
             vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK);
    char id_hex[65];
    zp_hex32(id, id_hex);
    ZP_CHECK("plan: plan token is the release id",
             json_get_str(json_get(&c.reply.data, "plan_token")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "plan_token")),
                    id_hex) == 0);
    const struct json_value *pkg = json_get(&c.reply.data, "package");
    ZP_CHECK("plan: all chunks verified",
             pkg && json_get_bool(json_get(pkg, "chunks_checked")) &&
             json_get_int(json_get(pkg, "chunks_verified")) == 3);
    const struct json_value *rel = json_get(&c.reply.data, "release");
    ZP_CHECK("plan: acceptance accepted, nothing replayed",
             rel &&
             strcmp(json_get_str(json_get(rel, "acceptance")),
                    "accepted") == 0 &&
             json_get_int(json_get(rel, "replayed_releases")) == 0);
    ZP_CHECK("plan: no failures",
             zp_failure_rule(&c.reply, 0) == NULL);
    struct zcl_present_model_v1 confirmation;
    char confirmation_error[192];
    ZP_CHECK("plan: exact output feeds the native confirmation instrument",
             zcl_native_presentation_publication_confirm_model_from_plan(
                 &c.reply.data, &confirmation, confirmation_error,
                 sizeof(confirmation_error)) &&
             confirmation.kind == ZCL_PRESENT_MODEL_CONFIRMATION &&
             strcmp(confirmation.exact_root, id_hex) == 0 &&
             confirmation.action_count == 2);
    zp_cmd_free(&c);

    /* Without dir the chunk check is honestly skipped, not failed. */
    zp_publish_input(&c, dd, release_hex, manifest_hex, NULL);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    pkg = json_get(&c.reply.data, "package");
    ZP_CHECK("plan: no dir skips chunk verification",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "valid")) &&
             pkg && !json_get_bool(json_get(pkg, "chunks_checked")));
    ZP_CHECK("plan: no dir names the one missing-source action",
             !json_get_bool(json_get(&c.reply.data, "ready_to_commit")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "readiness")),
                    "needs_chunk_source") == 0 &&
             strcmp(json_get_str(json_get(&c.reply.data, "next_action")),
                    "rerun zcode package publish plan with dir") == 0);
    ZP_CHECK("plan: unchecked chunks cannot produce confirmation chrome",
             !zcl_native_presentation_publication_confirm_model_from_plan(
                 &c.reply.data, &confirmation, confirmation_error,
                 sizeof(confirmation_error)));
    zp_cmd_free(&c);

    free(release_hex);
    free(manifest_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 2: license policy ──────────────────────────────────────────────── */
static int t_license_rules(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "license");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("license: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("license: recipe fixture builds", zp_use_recipe(&p.manifest));
    char *manifest_hex = zp_hex(p.wire, p.wire_len);

    /* Unknown SPDX id: tamper the wire's license bytes in place (same
     * length), so the wire reaches the parser and the parser names the
     * license rule. "Apache-2.0" -> "Apache-2.9" is not on the allowlist. */
    struct vcs_package_release r;
    ZP_CHECK("license: release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "Apache-2.0",
                        p.root));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    char *release_hex = zp_release_hex(&r, &wire, &wire_len);
    ZP_CHECK("license: wire encodes", release_hex && wire);
    size_t loff = zp_license_offset(wire);
    ZP_CHECK("license: tamper target located",
             loff + 10 <= wire_len &&
             memcmp(wire + loff, "Apache-2.0", 10) == 0);
    wire[loff + 9] = '9';
    char *bad_hex = zp_hex(wire, wire_len);
    struct zp_cmd c;
    zp_publish_input(&c, dd, bad_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("license: unknown SPDX id rejected naming the license rule",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "release-wire-not-canonical") == 0 &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0), "spdx-license") == 0);
    ZP_CHECK("license: blocked plan names one repair action",
             !json_get_bool(json_get(&c.reply.data, "ready_to_commit")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "readiness")),
                    "blocked") == 0 &&
             strcmp(json_get_str(json_get(&c.reply.data, "next_action")),
                    "fix the first reported failure, then rerun zcode package publish plan") ==
                 0);
    zp_cmd_free(&c);
    free(bad_hex);

    /* Compound license: "Apache-2.0" -> "MIT OR ISC" (10 bytes) — the
     * allowlist takes exactly one id, never an expression. */
    memcpy(wire + loff, "MIT OR ISC", 10);
    bad_hex = zp_hex(wire, wire_len);
    zp_publish_input(&c, dd, bad_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("license: compound id rejected naming the license rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0), "spdx-license") == 0);
    zp_cmd_free(&c);
    free(bad_hex);
    free(wire);
    free(release_hex);

    /* Missing license: blanked id -> same named rule. */
    ZP_CHECK("license: blank release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT", p.root));
    wire = NULL;
    release_hex = zp_release_hex(&r, &wire, &wire_len);
    loff = zp_license_offset(wire);
    memcpy(wire + loff, "   ", 3);
    bad_hex = zp_hex(wire, wire_len);
    zp_publish_input(&c, dd, bad_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("license: blank id rejected naming the license rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0), "spdx-license") == 0);
    zp_cmd_free(&c);
    free(bad_hex);
    free(wire);
    free(release_hex);

    /* License text absent: a manifest with no LICENSE file. */
    char noldir[512];
    snprintf(noldir, sizeof(noldir), "%s/nolicense", dd);
    mkdir(noldir, 0700);
    struct zp_pkg p2;
    memset(&p2, 0, sizeof(p2));
    vcs_package_manifest_init(&p2.manifest);
    ZP_CHECK("license: no-LICENSE package builds",
             zp_add_file(&p2, noldir, "src/only.c", "int x;\n",
                         VCS_PACKAGE_MODE_FILE) &&
             vcs_package_manifest_serialize(&p2.manifest, &p2.wire,
                                            &p2.wire_len) &&
             vcs_package_manifest_root(&p2.manifest, p2.root));
    ZP_CHECK("license: no-LICENSE release signs",
             zp_use_recipe(&p2.manifest) &&
             zp_release(&r, 0x11, 1u, "rhett/no-license", "MIT", p2.root));
    release_hex = zp_release_hex(&r, NULL, NULL);
    char *manifest2_hex = zp_hex(p2.wire, p2.wire_len);
    zp_publish_input(&c, dd, release_hex, manifest2_hex, noldir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("license: missing LICENSE file rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "license-text-missing") == 0);
    zp_cmd_free(&c);

    free(release_hex);
    free(manifest2_hex);
    free(manifest_hex);
    zp_pkg_free(&p2);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 3: package structure rules ─────────────────────────────────────── */
static int t_structure_rules(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "structure");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("structure: package fixture builds",
             zp_make_package(&p, pkgdir) && zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("structure: release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT", p.root));
    char *release_hex = zp_release_hex(&r, NULL, NULL);
    struct zp_cmd c;

    /* The grammar-level hostile wires all name the one manifest-grammar
     * rule (the parse is the exact check; detail says why). */
    struct {
        const char *label;
        const char *path1;
        uint32_t mode1;
        const char *path2;
        uint32_t mode2;
    } cases[] = {
        { "traversal path", "../evil", VCS_PACKAGE_MODE_FILE, NULL, 0 },
        { "absolute path", "/etc/passwd", VCS_PACKAGE_MODE_FILE, NULL, 0 },
        { "symlink mode", "x", 0120777, NULL, 0 },
        { "device mode", "x", 060666, NULL, 0 },
        { "socket mode", "x", 0140777, NULL, 0 },
        { "unknown mode", "x", 0600, NULL, 0 },
        { "duplicate canonical paths", "src/a.c", VCS_PACKAGE_MODE_FILE,
          "src/a.c", VCS_PACKAGE_MODE_FILE },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t raw[2048];
        size_t raw_len = zp_raw_wire(raw, cases[i].path1, cases[i].mode1,
                                     cases[i].path2, cases[i].mode2);
        char *raw_hex = zp_hex(raw, raw_len);
        zp_publish_input(&c, dd, release_hex, raw_hex, NULL);
        zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
        char name[96];
        snprintf(name, sizeof(name), "structure: %s rejected", cases[i].label);
        ZP_CHECK(name,
                 !json_get_bool(json_get(&c.reply.data, "valid")) &&
                 zp_failure_rule(&c.reply, 0) &&
                 strcmp(zp_failure_rule(&c.reply, 0),
                        "manifest-grammar") == 0);
        zp_cmd_free(&c);
        free(raw_hex);
    }

    /* Oversized manifest wire: over the 1 MiB wire bound. */
    size_t big_len = 2 * (VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES + 1) + 1;
    char *big = malloc(big_len);
    ZP_CHECK("structure: oversized hex allocates", big != NULL);
    if (big) {
        memset(big, 'a', big_len - 1);
        big[big_len - 1] = '\0';
        zp_publish_input(&c, dd, release_hex, big, NULL);
        zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
        ZP_CHECK("structure: oversized manifest rejected",
                 !json_get_bool(json_get(&c.reply.data, "valid")) &&
                 zp_failure_rule(&c.reply, 0) &&
                 strcmp(zp_failure_rule(&c.reply, 0),
                        "manifest-grammar") == 0);
        zp_cmd_free(&c);
        free(big);
    }

    /* Hidden executable payload: a canonical path under a dot segment with
     * the executable mode — the grammar allows it, publication forbids it. */
    struct zp_pkg hp;
    memset(&hp, 0, sizeof(hp));
    vcs_package_manifest_init(&hp.manifest);
    uint8_t h1[32];
    uint8_t h2[32];
    ZP_CHECK("structure: hidden-exec hashes compute",
             vcs_package_chunk_hash((const uint8_t *)"x", 1, h1) &&
             vcs_package_chunk_hash((const uint8_t *)"y", 1, h2));
    ZP_CHECK("structure: hidden-exec manifest builds",
             vcs_package_manifest_add(&hp.manifest, "LICENSE",
                                      VCS_PACKAGE_MODE_FILE, 1, h1, 1) &&
             vcs_package_manifest_add(&hp.manifest, ".git/hooks/evil",
                                      VCS_PACKAGE_MODE_EXECUTABLE, 1, h2,
                                      1) &&
             vcs_package_manifest_serialize(&hp.manifest, &hp.wire,
                                            &hp.wire_len) &&
             vcs_package_manifest_root(&hp.manifest, hp.root));
    ZP_CHECK("structure: hidden-exec release signs",
             zp_release(&r, 0x11, 1u, "rhett/hidden-exec", "MIT", hp.root));
    char *hr_hex = zp_release_hex(&r, NULL, NULL);
    char *hm_hex = zp_hex(hp.wire, hp.wire_len);
    zp_publish_input(&c, dd, hr_hex, hm_hex, NULL);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("structure: hidden executable payload rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "hidden-executable-payload") == 0 &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0),
                    ".git/hooks/evil") == 0);
    zp_cmd_free(&c);
    free(hr_hex);
    free(hm_hex);
    zp_pkg_free(&hp);

    /* Over-64MiB package (sizes are manifest facts; no bytes needed). */
    struct zp_pkg bp;
    memset(&bp, 0, sizeof(bp));
    vcs_package_manifest_init(&bp.manifest);
    uint8_t fake[65 * 32];
    memset(fake, 0x5a, sizeof(fake));
    ZP_CHECK("structure: over-cap manifest builds",
             vcs_package_manifest_add(&bp.manifest, "LICENSE",
                                      VCS_PACKAGE_MODE_FILE, 1, h1, 1) &&
             vcs_package_manifest_add(&bp.manifest, "big.bin",
                                      VCS_PACKAGE_MODE_FILE,
                                      VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES + 1,
                                      fake, 65) &&
             vcs_package_manifest_serialize(&bp.manifest, &bp.wire,
                                            &bp.wire_len) &&
             vcs_package_manifest_root(&bp.manifest, bp.root));
    ZP_CHECK("structure: over-cap release signs",
             zp_release(&r, 0x11, 1u, "rhett/too-big", "MIT", bp.root));
    hr_hex = zp_release_hex(&r, NULL, NULL);
    hm_hex = zp_hex(bp.wire, bp.wire_len);
    zp_publish_input(&c, dd, hr_hex, hm_hex, NULL);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("structure: over-64MiB package rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "package-exceeds-64mib-cap") == 0);
    zp_cmd_free(&c);
    free(hr_hex);
    free(hm_hex);
    zp_pkg_free(&bp);

    /* Release root != manifest root. */
    uint8_t other_root[32];
    memset(other_root, 0x77, 32);
    ZP_CHECK("structure: mismatched release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT",
                        other_root));
    hr_hex = zp_release_hex(&r, NULL, NULL);
    hm_hex = zp_hex(p.wire, p.wire_len);
    zp_publish_input(&c, dd, hr_hex, hm_hex, NULL);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("structure: root mismatch rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "release-root-mismatch") == 0);
    zp_cmd_free(&c);
    free(hr_hex);
    free(hm_hex);

    free(release_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4: chunk checks ────────────────────────────────────────────────── */
static int t_chunk_rules(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "chunks");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("chunks: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("chunks: recipe fixture builds", zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("chunks: release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT", p.root));
    char *release_hex = zp_release_hex(&r, NULL, NULL);
    char *manifest_hex = zp_hex(p.wire, p.wire_len);
    struct zp_cmd c;

    /* Corrupt one source file (same length -> hash mismatch). */
    char victim[512];
    snprintf(victim, sizeof(victim), "%s/src/ring.c", pkgdir);
    FILE *f = fopen(victim, "r+b");
    ZP_CHECK("chunks: victim opens", f != NULL);
    if (f) {
        (void)fwrite("X", 1, 1, f);
        fclose(f);
    }
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("chunks: hash mismatch names rule + coordinates",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "chunk-hash-mismatch") == 0 &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0), "src/ring.c#0") == 0);
    zp_cmd_free(&c);

    /* Truncate it (size mismatch). */
    f = fopen(victim, "wb");
    ZP_CHECK("chunks: victim truncates", f != NULL);
    if (f)
        fclose(f);
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("chunks: size mismatch names the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "chunk-source-size-mismatch") == 0);
    zp_cmd_free(&c);

    /* Delete it (missing). */
    ZP_CHECK("chunks: victim unlinks", remove(victim) == 0);
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("chunks: missing source names the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "chunk-source-missing") == 0);
    zp_cmd_free(&c);

    free(release_hex);
    free(manifest_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 5: commit roundtrip + idempotence + failed-plan commit ─────────── */
static int t_commit_roundtrip(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "commit");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("commit: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("commit: recipe fixture builds", zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("commit: release signs",
             zp_release(&r, 0x11, 1u, "rhett/ring-buffer", "MIT", p.root));
    char *release_hex = zp_release_hex(&r, NULL, NULL);
    char *manifest_hex = zp_hex(p.wire, p.wire_len);
    struct zp_cmd c;

    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("commit: valid candidate commits locally",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_str(json_get(&c.reply.data, "result")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "result")),
                    "committed") == 0 &&
             json_get_bool(json_get(&c.reply.data,
                                    "local_commit_complete")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "pointer_publication_observed")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "provider_publication_observed")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "peer_discovery_observed")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "exact_fetch_observed")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "network_publication_performed")) &&
             c.reply.error.mutated);
    ZP_CHECK("commit: all chunks admitted",
             json_get_int(json_get(&c.reply.data, "chunks_stored")) == 3);
    {
        const char *pkg =
            json_get_str(json_get(&c.reply.data, "package_root"));
        const char *tr =
            json_get_str(json_get(&c.reply.data, "transport_root"));
        const char *next =
            json_get_str(json_get(&c.reply.data, "next_command"));
        ZP_CHECK("commit: next_command is a filled pointer publish plan",
                 pkg && tr && next && strstr(next, pkg) && strstr(next, tr) &&
                     strstr(next, "zcode network publish") &&
                     strstr(next, "\"kind\":\"pointer\"") &&
                     strstr(next, "zclassic23.package"));
        ZP_CHECK("commit: next_kind is pointer",
                 json_get_str(json_get(&c.reply.data, "next_kind")) &&
                     strcmp(json_get_str(json_get(&c.reply.data, "next_kind")),
                            "pointer") == 0);
    }
    zp_cmd_free(&c);

    /* On-disk truth: manifest, release envelope, and the CAS chunk. */
    char path[512];
    snprintf(path, sizeof(path), "%s/zcode/manifests/%s", dd, p.root_hex);
    struct stat st;
    ZP_CHECK("commit: manifest persisted", stat(path, &st) == 0);
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZP_CHECK("commit: release id computes",
             vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK);
    char id_hex[65];
    zp_hex32(id, id_hex);
    snprintf(path, sizeof(path), "%s/zcode/releases/%s", dd, id_hex);
    ZP_CHECK("commit: release persisted", stat(path, &st) == 0);
    char rc_hex[65];
    zp_hex32(g_zp_recipe_root, rc_hex);
    snprintf(path, sizeof(path), "%s/zcode/recipes/%s", dd, rc_hex);
    ZP_CHECK("commit: recipe persisted", stat(path, &st) == 0);

    /* A reopened store sees the package complete (CAS-derived). */
    struct vcs_package_store *s = vcs_package_store_open(dd, 1000000u);
    ZP_CHECK("commit: store reopens", s != NULL);
    if (s) {
        struct vcs_package_store_status pst;
        ZP_CHECK("commit: package complete after reopen",
                 vcs_package_store_package_status(s, p.root, &pst) &&
                 pst.complete && pst.present_chunks == 3);
        vcs_package_store_close(s);
    }

    /* Idempotent recommit: duplicate, not error, nothing mutated. */
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("commit: recommit reports duplicate",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_str(json_get(&c.reply.data, "result")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "result")),
                    "duplicate") == 0 &&
             !c.reply.error.mutated);
    zp_cmd_free(&c);

    /* Plan after commit classifies as a duplicate, still valid. */
    zp_publish_input(&c, dd, release_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    const struct json_value *rel = json_get(&c.reply.data, "release");
    ZP_CHECK("commit: post-commit plan sees the replayed duplicate",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "valid")) && rel &&
             strcmp(json_get_str(json_get(rel, "acceptance")),
                    "duplicate-release") == 0 &&
             json_get_int(json_get(rel, "replayed_releases")) == 1);
    zp_cmd_free(&c);

    /* Commit of a release that fails plan names the failed rule. */
    char nodir[512];
    snprintf(nodir, sizeof(nodir), "%s/nolicense", dd);
    mkdir(nodir, 0700);
    struct zp_pkg p2;
    memset(&p2, 0, sizeof(p2));
    vcs_package_manifest_init(&p2.manifest);
    ZP_CHECK("commit: no-LICENSE package builds",
             zp_add_file(&p2, nodir, "src/only.c", "int x;\n",
                         VCS_PACKAGE_MODE_FILE) &&
             vcs_package_manifest_serialize(&p2.manifest, &p2.wire,
                                            &p2.wire_len) &&
             vcs_package_manifest_root(&p2.manifest, p2.root));
    struct vcs_package_release r2;
    ZP_CHECK("commit: no-LICENSE release signs",
             zp_use_recipe(&p2.manifest) &&
             zp_release(&r2, 0x22, 1u, "bob/no-license", "ISC", p2.root));
    char *r2_hex = zp_release_hex(&r2, NULL, NULL);
    char *m2_hex = zp_hex(p2.wire, p2.wire_len);
    zp_publish_input(&c, dd, r2_hex, m2_hex, nodir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("commit: plan of the bad candidate fails first",
             !json_get_bool(json_get(&c.reply.data, "valid")));
    zp_cmd_free(&c);
    zp_publish_input(&c, dd, r2_hex, m2_hex, nodir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("commit: failed-plan commit names the rule",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "license-text-missing") == 0 &&
             c.reply.error.evidence[0] != '\0');
    zp_cmd_free(&c);
    free(r2_hex);
    free(m2_hex);
    zp_pkg_free(&p2);

    free(release_hex);
    free(manifest_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 6: acceptance replay (sequence + namespace) ────────────────────── */
static int t_acceptance_replay(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "accept");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("accept: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("accept: recipe fixture builds", zp_use_recipe(&p.manifest));
    char *manifest_hex = zp_hex(p.wire, p.wire_len);
    struct vcs_package_release r;
    struct zp_cmd c;

    /* Commit seq 1 from key A. */
    ZP_CHECK("accept: seq1 signs",
             zp_release(&r, 0xaa, 1u, "rhett/pkg-one", "MIT", p.root));
    char *r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("accept: seq1 commits",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);
    free(r_hex);

    /* Equivocation: same key, same sequence, different content. */
    ZP_CHECK("accept: equivocation signs",
             zp_release(&r, 0xaa, 1u, "rhett/pkg-one-fork", "MIT", p.root));
    r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("accept: equivocation rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0),
                    "release-acceptance-failed") == 0 &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0),
                    "publisher-equivocation") == 0);
    zp_cmd_free(&c);
    free(r_hex);

    /* Stale: advance the cursor to 2, then a different seq-1 release. */
    ZP_CHECK("accept: seq2 signs",
             zp_release(&r, 0xaa, 2u, "rhett/pkg-two", "MIT", p.root));
    r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("accept: seq2 commits (cursor advances)",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);
    free(r_hex);
    ZP_CHECK("accept: stale signs",
             zp_release(&r, 0xaa, 1u, "rhett/pkg-one-fork", "MIT", p.root));
    r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("accept: stale sequence rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0),
                    "stale-publisher-sequence") == 0);
    zp_cmd_free(&c);
    free(r_hex);

    /* Namespace: another key cannot publish under "rhett/". */
    ZP_CHECK("accept: namespace squatter signs",
             zp_release(&r, 0xbb, 1u, "rhett/pkg-squat", "MIT", p.root));
    r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_plan(&c.request, &c.reply);
    ZP_CHECK("accept: namespace conflict rejected naming the rule",
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_detail(&c.reply, 0) &&
             strcmp(zp_failure_detail(&c.reply, 0),
                    "publisher-namespace-conflict") == 0);
    zp_cmd_free(&c);
    free(r_hex);

    /* The same other key under its OWN namespace commits fine. */
    ZP_CHECK("accept: other-namespace release signs",
             zp_release(&r, 0xbb, 1u, "bob/pkg-squat", "Zlib", p.root));
    r_hex = zp_release_hex(&r, NULL, NULL);
    zp_publish_input(&c, dd, r_hex, manifest_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("accept: own-namespace commit passes",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);
    free(r_hex);

    free(manifest_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 7: search ──────────────────────────────────────────────────────── */

/* Commit one small package under the given key/name/license/sequence. The
 * LICENSE text carries content_seed so every package root is distinct. */
static bool zp_scratch_path(char *out, size_t out_cap, const char *dd,
                            const char *name)
{
    if (!out || out_cap == 0 || !dd || !name)
        return false;
    int wrote = snprintf(out, out_cap, "%s/src-", dd);
    if (wrote < 0 || (size_t)wrote >= out_cap)
        return false;
    size_t used = (size_t)wrote;
    for (const char *p = name; *p; p++) {
        if (used + 1u >= out_cap)
            return false;
        out[used++] = *p == '/' ? '_' : *p;
    }
    out[used] = '\0';
    return true;
}

static bool zp_commit_one_observed(const char *dd, uint8_t key_seed,
                                   uint64_t seq, const char *name,
                                   const char *license, int content_seed,
                                   char *observed_path,
                                   size_t observed_path_cap)
{
    char pkgdir[512];
    if (!zp_scratch_path(pkgdir, sizeof(pkgdir), dd, name))
        return false;
    if (observed_path) {
        size_t path_len = strlen(pkgdir);
        if (observed_path_cap == 0 || path_len >= observed_path_cap)
            return false;
        memcpy(observed_path, pkgdir, path_len + 1u);
    } else if (observed_path_cap != 0) {
        return false;
    }
    if (mkdir(pkgdir, 0700) != 0)
        return false;
    struct zp_pkg p;
    memset(&p, 0, sizeof(p));
    vcs_package_manifest_init(&p.manifest);
    char license_text[96];
    snprintf(license_text, sizeof(license_text),
             "%s\nsee the LICENSE file, variant %d\n", license,
             content_seed);
    char source[64];
    snprintf(source, sizeof(source), "int x_%d;\n", content_seed);
    if (!zp_add_file(&p, pkgdir, "LICENSE", license_text,
                     VCS_PACKAGE_MODE_FILE) ||
        !zp_add_file(&p, pkgdir, "src/x.c", source,
                     VCS_PACKAGE_MODE_FILE) ||
        !vcs_package_manifest_serialize(&p.manifest, &p.wire,
                                        &p.wire_len) ||
        !vcs_package_manifest_root(&p.manifest, p.root)) {
        zp_pkg_free(&p);
        test_rm_rf_recursive(pkgdir);
        return false;
    }
    struct vcs_package_release r;
    if (!zp_use_recipe(&p.manifest) ||
        !zp_release(&r, key_seed, seq, name, license, p.root)) {
        zp_pkg_free(&p);
        test_rm_rf_recursive(pkgdir);
        return false;
    }
    char *r_hex = zp_release_hex(&r, NULL, NULL);
    char *m_hex = zp_hex(p.wire, p.wire_len);
    struct zp_cmd c;
    zp_publish_input(&c, dd, r_hex, m_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    bool ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    zp_cmd_free(&c);
    free(r_hex);
    free(m_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(pkgdir);
    return ok;
}

static bool zp_commit_one(const char *dd, uint8_t key_seed, uint64_t seq,
                          const char *name, const char *license,
                          int content_seed)
{
    return zp_commit_one_observed(dd, key_seed, seq, name, license,
                                  content_seed, NULL, 0);
}

static void zp_search_input(struct zp_cmd *c, const char *dd,
                            const char *key, const char *value)
{
    zp_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    if (key && value)
        (void)json_push_kv_str(&c->input, key, value);
}

static int t_search(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "search");
    struct zp_cmd c;

    char scratch[512] = {0};
    char prefix_tiny[8];
    char name_tiny[512];
    size_t dd_len = strlen(dd);
    size_t name_tiny_cap = dd_len + strlen("/src-") + 3u;
    ZP_CHECK("search: truncated scratch prefix fails closed",
             !zp_scratch_path(prefix_tiny, sizeof(prefix_tiny), dd,
                              "alice/ring-buffer"));
    ZP_CHECK("search: truncated scratch name fails closed",
             name_tiny_cap <= sizeof(name_tiny) &&
             !zp_scratch_path(name_tiny, name_tiny_cap, dd,
                              "alice/ring-buffer"));
    char observed_tiny[8];
    ZP_CHECK("search: truncated observed path fails before mkdir",
             !zp_commit_one_observed(dd, 0xaa, 1u,
                                     "alice/ring-buffer", "MIT", 0,
                                     observed_tiny,
                                     sizeof(observed_tiny)));

    /* Empty store: a PASSED empty result, not an error. */
    zp_search_input(&c, dd, NULL, NULL);
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: empty store passes with zero rows",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "total_matches")) == 0 &&
             json_get_int(json_get(&c.reply.data, "packages_scanned")) == 0);
    zp_cmd_free(&c);

    bool observed_commit = zp_commit_one_observed(
        dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 1, scratch,
        sizeof(scratch));
    ZP_CHECK("search: three packages commit",
             observed_commit &&
             zp_commit_one(dd, 0xaa, 2u, "rhett/json-lite", "Apache-2.0",
                           2) &&
             zp_commit_one(dd, 0xbb, 1u, "bob/ring-zlib", "Zlib", 3));
    struct stat scratch_st;
    errno = 0;
    int scratch_stat = observed_commit ? stat(scratch, &scratch_st) : 0;
    int scratch_errno = errno;
    ZP_CHECK("search: package scratch stays below root and is removed",
             observed_commit && strncmp(scratch, dd, dd_len) == 0 &&
             scratch[dd_len] == '/' &&
             scratch_stat == -1 && scratch_errno == ENOENT);

    zp_search_input(&c, dd, NULL, NULL);
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: unfiltered finds all three, sorted by name",
             json_get_int(json_get(&c.reply.data, "total_matches")) == 3 &&
             json_get_int(json_get(&c.reply.data, "packages_scanned")) == 3);
    const struct json_value *rows = json_get(&c.reply.data, "results");
    const struct json_value *row0 = rows ? json_at(rows, 0) : NULL;
    ZP_CHECK("search: first row is bob/ring-zlib (name order)",
             row0 &&
             strcmp(json_get_str(json_get(row0, "name")),
                    "bob/ring-zlib") == 0 &&
             json_get_bool(json_get(row0, "manifest_present")));
    zp_cmd_free(&c);

    zp_search_input(&c, dd, "keyword", "ring");
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: keyword narrows to two",
             json_get_int(json_get(&c.reply.data, "total_matches")) == 2);
    zp_cmd_free(&c);

    zp_search_input(&c, dd, "keyword", "no-such-thing");
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: miss is a passed empty result",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "total_matches")) == 0);
    zp_cmd_free(&c);

    zp_search_input(&c, dd, "license", "MIT");
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: license filter",
             json_get_int(json_get(&c.reply.data, "total_matches")) == 1);
    zp_cmd_free(&c);

    zp_search_input(&c, dd, "name_prefix", "rhett/");
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: name prefix filter",
             json_get_int(json_get(&c.reply.data, "total_matches")) == 2);
    zp_cmd_free(&c);

    char pub[67];
    ZP_CHECK("search: publisher hex computes", zp_pubkey_hex(0xbb, pub));
    pub[10] = '\0'; /* prefix match on the pubkey hex */
    zp_search_input(&c, dd, "publisher", pub);
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: publisher prefix filter",
             json_get_int(json_get(&c.reply.data, "total_matches")) == 1);
    rows = json_get(&c.reply.data, "results");
    row0 = rows ? json_at(rows, 0) : NULL;
    ZP_CHECK("search: publisher row fields",
             row0 &&
             strcmp(json_get_str(json_get(row0, "name")),
                    "bob/ring-zlib") == 0 &&
             strcmp(json_get_str(json_get(row0, "license")), "Zlib") == 0 &&
             json_get_int(json_get(row0, "files")) == 2);
    zp_cmd_free(&c);

    /* Bounds: limit 1 renders one row and flags the rest. */
    zp_search_input(&c, dd, "limit", NULL);
    (void)json_push_kv_int(&c.input, "limit", 1);
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    ZP_CHECK("search: limit bounds rows and flags truncation",
             json_get_int(json_get(&c.reply.data, "rendered")) == 1 &&
             json_get_int(json_get(&c.reply.data, "total_matches")) == 3 &&
             json_get_bool(json_get(&c.reply.data, "items_truncated")));
    zp_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 8: library ─────────────────────────────────────────────────────── */
static int t_library(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "library");
    struct zp_cmd c;

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_zcode_package_library(&c.request, &c.reply);
    const char *empty_next =
        json_get_str(json_get(&c.reply.data, "next_command"));
    ZP_CHECK("library: empty store passes with zero rows",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "count")) == 0 &&
             json_get_int(json_get(&c.reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&c.reply.data, "evaluated_count")) == 0 &&
             json_get_int(json_get(&c.reply.data, "reproduced_count")) == 0 &&
             !json_get_bool(json_get(&c.reply.data, "items_truncated")));
    ZP_CHECK("library: empty shelf names an obvious fetch next command",
             empty_next && strstr(empty_next, "zcode package fetch") != NULL);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    zcl_native_handle_zcode_package_library(&c.request, &c.reply);
    ZP_CHECK("library: missing datadir names MISSING_DATADIR",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "MISSING_DATADIR") == 0);
    zp_cmd_free(&c);

    ZP_CHECK("library: two packages commit",
             zp_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 21) &&
             zp_commit_one(dd, 0xbb, 1u, "bob/json-lite", "Apache-2.0", 22));

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_zcode_package_library(&c.request, &c.reply);
    const struct json_value *rows = json_get(&c.reply.data, "packages");
    int64_t listed = json_get_int(json_get(&c.reply.data, "count"));
    bool named_ring = false;
    bool named_json = false;
    const struct json_value *named_row = NULL;
    size_t n_rows = rows ? rows->num_children : 0;
    for (size_t i = 0; i < n_rows; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *name = row ? json_get_str(json_get(row, "name")) : NULL;
        if (name && strcmp(name, "rhett/ring-buffer") == 0) {
            named_ring = true;
            named_row = row;
        }
        if (name && strcmp(name, "bob/json-lite") == 0)
            named_json = true;
    }
    ZP_CHECK("library: lists both complete packages with index names",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             listed >= 2 &&
             json_get_int(json_get(&c.reply.data, "rendered")) == listed &&
             named_ring && named_json);
    ZP_CHECK("library: named row is a complete unpinned seedable package",
             named_row &&
             json_get_str(json_get(named_row, "package_root")) &&
             strlen(json_get_str(json_get(named_row, "package_root"))) == 64 &&
             json_get_bool(json_get(named_row, "complete")) &&
             !json_get_bool(json_get(named_row, "pinned")) &&
             json_get_int(json_get(named_row, "file_count")) == 2 &&
             json_get_int(json_get(named_row, "total_bytes")) > 0 &&
             json_get_int(json_get(named_row, "total_chunks")) == 2 &&
             json_get(named_row, "public_serveable") &&
             json_get(named_row, "public_serveable")->type == JSON_BOOL);
    const char *listed_root =
        named_row ? json_get_str(json_get(named_row, "package_root")) : NULL;
    const char *shelf_next =
        json_get_str(json_get(&c.reply.data, "next_command"));
    ZP_CHECK("library: non-empty shelf points at fetch of a listed title",
             shelf_next && strstr(shelf_next, "zcode package fetch") != NULL &&
             (strstr(shelf_next, "rhett/ring-buffer") != NULL ||
              strstr(shelf_next, "bob/json-lite") != NULL ||
              (listed_root && strstr(shelf_next, listed_root) != NULL)));
    char ring_root[65];
    ring_root[0] = '\0';
    if (listed_root)
        (void)snprintf(ring_root, sizeof(ring_root), "%s", listed_root);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "name", "rhett/ring-buffer");
    zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
    ZP_CHECK("library: fetch by local name after a published complete package",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "already_complete")) &&
             json_get_str(json_get(&c.reply.data, "package_root")) &&
             ring_root[0] &&
             strcmp(json_get_str(json_get(&c.reply.data, "package_root")),
                    ring_root) == 0);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "name", "rhett/ring-buffer");
    (void)json_push_kv_str(&c.input, "root", ring_root);
    zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
    ZP_CHECK("library: matching name+root still fetches the same identity",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "already_complete")));
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", ring_root);
    zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
    ZP_CHECK("library: fetch by root still works",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "already_complete")) &&
             json_get_str(json_get(&c.reply.data, "package_root")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "package_root")),
                    ring_root) == 0);
    zp_cmd_free(&c);

    char other_root[65];
    memset(other_root, 'a', 64);
    other_root[64] = '\0';
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "name", "rhett/ring-buffer");
    (void)json_push_kv_str(&c.input, "root", other_root);
    zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
    ZP_CHECK("library: name+root mismatch fails closed",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "NAME_ROOT_MISMATCH") == 0 &&
             c.reply.error.message[0] != '\0');
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_int(&c.input, "limit", 1);
    zcl_native_handle_zcode_package_library(&c.request, &c.reply);
    ZP_CHECK("library: limit bounds rows and flags truncation",
             json_get_int(json_get(&c.reply.data, "rendered")) == 1 &&
             json_get_int(json_get(&c.reply.data, "count")) == 1 &&
             json_get_bool(json_get(&c.reply.data, "items_truncated")));
    zp_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 8b: library reproduction evidence ────────────────────────────────
 * Every shelf row carries the local receipts scan for its package+recipe —
 * the exact predicate the pointer publish gate applies — and the reply
 * censuses evaluated/reproduced rows. Evidence never fails the view: a
 * complete package with no persisted release reads an error object. */
static int t_library_reproduction(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "library_repro");
    struct zp_cmd c;

    /* Package A: committed, then two distinct, mutually matching receipts
     * filed under <dd>/zcode/receipts (different flags strings, different
     * pinned toolchain capsules — distinct build events, distinct ids). */
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg-a", dd);
    struct zp_pkg pa;
    ZP_CHECK("library repro: package A builds", zp_make_package(&pa, pkgdir));
    ZP_CHECK("library repro: recipe A builds", zp_use_recipe(&pa.manifest));
    struct vcs_package_release rel_a;
    ZP_CHECK("library repro: release A signs",
             zp_release(&rel_a, 0xaa, 1u, "rhett/repro-ok", "MIT", pa.root));
    char *ra_hex = zp_release_hex(&rel_a, NULL, NULL);
    char *ma_hex = zp_hex(pa.wire, pa.wire_len);
    zp_publish_input(&c, dd, ra_hex, ma_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("library repro: package A commits",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);
    free(ra_hex);
    free(ma_hex);

    struct vcs_package_build_receipt rca, rcb;
    vcs_package_build_receipt_init(&rca);
    vcs_package_build_receipt_init(&rcb);
    struct vcs_package_build_receipt *rcpts[2] = {&rca, &rcb};
    static const char *const rcpt_flags[2] = {"shelf-quick",
                                              "shelf-standard"};
    bool rcpts_ok = true;
    uint8_t out_sha[32];
    memset(out_sha, 0x5a, sizeof(out_sha));
    for (size_t i = 0; i < 2 && rcpts_ok; i++) {
        struct vcs_package_build_receipt *rr = rcpts[i];
        memcpy(rr->package_root, pa.root, 32);
        memcpy(rr->recipe_root, g_zp_recipe_root, 32);
        memcpy(rr->lock_root, pa.root, 32);
        snprintf(rr->compiler_id, sizeof(rr->compiler_id), "gcc");
        snprintf(rr->compiler_version, sizeof(rr->compiler_version),
                 "14.2.0");
        snprintf(rr->flags, sizeof(rr->flags), "%s", rcpt_flags[i]);
        rr->isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
        rr->test_ran = false;
        rr->result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
        uint8_t cap[32];
        memset(cap, i == 0 ? 0xd1 : 0xd2, sizeof(cap));
        rcpts_ok = vcs_package_build_add_output(rr, "lib/repro-ok.a",
                                                out_sha, 123) ==
                       VCS_PACKAGE_BUILD_OK &&
                   vcs_package_build_set_toolchain_capsule(rr, cap) ==
                       VCS_PACKAGE_BUILD_OK &&
                   zp_file_receipt(dd, rr);
    }
    ZP_CHECK("library repro: two distinct matching receipts filed",
             rcpts_ok);

    /* Package B: committed, no receipts of its own — evaluated, not
     * reproduced. */
    ZP_CHECK("library repro: package B commits",
             zp_commit_one(dd, 0xbb, 1u, "bob/repro-none", "ISC", 31));

    /* Package C: committed, then its envelope moved OUT of releases/ (the
     * index loader keys on content, so the bytes must leave the dir).
     * Manifest and chunks keep it complete, but no persisted release names
     * the root — the row is unevaluable, never a failure. The fixture
     * content must differ from package A's (zp_make_package is
     * fixed-content: identical bytes would mean the SAME package root). */
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg-c", dd);
    struct zp_pkg pc;
    memset(&pc, 0, sizeof(pc));
    vcs_package_manifest_init(&pc.manifest);
    mkdir(pkgdir, 0700);
    bool c_built =
        zp_add_file(&pc, pkgdir, "LICENSE",
                    "ISC\nsee the LICENSE file, variant 31\n",
                    VCS_PACKAGE_MODE_FILE) &&
        zp_add_file(&pc, pkgdir, "src/y.c", "int y_31;\n",
                    VCS_PACKAGE_MODE_FILE) &&
        vcs_package_manifest_serialize(&pc.manifest, &pc.wire,
                                       &pc.wire_len) &&
        vcs_package_manifest_root(&pc.manifest, pc.root) &&
        memcmp(pc.root, pa.root, 32) != 0;
    if (c_built)
        zp_hex32(pc.root, pc.root_hex);
    ZP_CHECK("library repro: package C builds (distinct root)", c_built);
    ZP_CHECK("library repro: recipe C builds", zp_use_recipe(&pc.manifest));
    struct vcs_package_release rel_c;
    ZP_CHECK("library repro: release C signs",
             zp_release(&rel_c, 0xcc, 1u, "carol/repro-unreleased", "ISC",
                        pc.root));
    char *rc_hex = zp_release_hex(&rel_c, NULL, NULL);
    char *mc_hex = zp_hex(pc.wire, pc.wire_len);
    zp_publish_input(&c, dd, rc_hex, mc_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("library repro: package C commits",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);
    free(rc_hex);
    free(mc_hex);
    uint8_t id_c[32];
    char id_c_hex[65];
    bool id_c_ok =
        vcs_package_release_id(&rel_c, id_c) == VCS_PACKAGE_RELEASE_OK;
    if (id_c_ok)
        zp_hex32(id_c, id_c_hex);
    char envelope[600], envelope_off[600];
    snprintf(envelope, sizeof(envelope), "%s/zcode/releases/%s", dd,
             id_c_hex);
    snprintf(envelope_off, sizeof(envelope_off), "%s/envelope-c", dd);
    ZP_CHECK("library repro: C's envelope leaves the releases dir",
             id_c_ok && rename(envelope, envelope_off) == 0);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_zcode_package_library(&c.request, &c.reply);
    const struct json_value *rows = json_get(&c.reply.data, "packages");
    const struct json_value *row_a = NULL, *row_b = NULL, *row_c = NULL;
    size_t n_rows = rows ? rows->num_children : 0;
    for (size_t i = 0; i < n_rows; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *name = row ? json_get_str(json_get(row, "name")) : NULL;
        if (name && strcmp(name, "rhett/repro-ok") == 0)
            row_a = row;
        if (name && strcmp(name, "bob/repro-none") == 0)
            row_b = row;
        const char *root_hex =
            row ? json_get_str(json_get(row, "package_root")) : NULL;
        if (root_hex && strcmp(root_hex, pc.root_hex) == 0)
            row_c = row;
    }
    const struct json_value *repro_a =
        row_a ? json_get(row_a, "reproduction") : NULL;
    ZP_CHECK("library repro: row A proves the gate predicate",
             row_a && repro_a &&
             json_get_int(json_get(repro_a, "receipts_scanned")) == 2 &&
             json_get_int(json_get(repro_a, "receipts_matching")) == 2 &&
             json_get_bool(json_get(repro_a, "reproduced")) &&
             json_get_bool(json_get(repro_a, "publishable")) &&
             json_get_int(json_get(repro_a, "distinct_toolchains")) == 2 &&
             json_get_bool(json_get(repro_a, "cross_toolchain")) &&
             !json_get_bool(json_get(repro_a, "rows_truncated")));
    const struct json_value *repro_b =
        row_b ? json_get(row_b, "reproduction") : NULL;
    ZP_CHECK("library repro: row B is evaluated with no matching receipts",
             row_b && repro_b &&
             !json_get_bool(json_get(repro_b, "reproduced")) &&
             !json_get_bool(json_get(repro_b, "publishable")) &&
             json_get_int(json_get(repro_b, "receipts_matching")) == 0 &&
             json_get(repro_b, "error") == NULL);
    const struct json_value *repro_c =
        row_c ? json_get(row_c, "reproduction") : NULL;
    const char *err_c = repro_c ? json_get_str(json_get(repro_c, "error"))
                                : NULL;
    ZP_CHECK("library repro: row C is complete, unnamed, unevaluable",
             row_c && json_get_bool(json_get(row_c, "complete")) &&
             err_c &&
             strcmp(err_c, "no persisted release names this root") == 0);
    /* The shelf also carries the transport-carrier packages commit
     * persists alongside each release — complete tracked packages no
     * persisted release names. They are the production unnamed-row case:
     * each must read the same unevaluable error object as C. */
    size_t unevaluable = 0;
    for (size_t i = 0; i < n_rows; i++) {
        const struct json_value *row = json_at(rows, i);
        const struct json_value *repro =
            row ? json_get(row, "reproduction") : NULL;
        if (repro && json_get(repro, "error"))
            unevaluable++;
    }
    ZP_CHECK("library repro: census counts agree with the rows",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "count")) == 6 &&
             unevaluable == 4 &&
             json_get_int(json_get(&c.reply.data, "evaluated_count")) == 2 &&
             json_get_int(json_get(&c.reply.data, "reproduced_count")) == 1);
    zp_cmd_free(&c);

    zp_pkg_free(&pa);
    zp_pkg_free(&pc);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 9: show ────────────────────────────────────────────────────────── */
static int t_show(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "show");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    struct zp_pkg p;
    ZP_CHECK("show: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("show: recipe fixture builds", zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("show: release signs",
             zp_release(&r, 0xaa, 7u, "rhett/ring-buffer", "MIT", p.root));
    char *r_hex = zp_release_hex(&r, NULL, NULL);
    char *m_hex = zp_hex(p.wire, p.wire_len);
    struct zp_cmd c;
    zp_publish_input(&c, dd, r_hex, m_hex, pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ZP_CHECK("show: package commits",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    const struct json_value *rel = json_get(&c.reply.data, "release");
    ZP_CHECK("show: full release record",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && rel &&
             strcmp(json_get_str(json_get(rel, "name")),
                    "rhett/ring-buffer") == 0 &&
             strcmp(json_get_str(json_get(rel, "license")), "MIT") == 0 &&
             json_get_int(json_get(rel, "publisher_sequence")) == 7 &&
             json_get_str(json_get(rel, "reward_address")) != NULL &&
             json_get_str(json_get(rel, "publisher")) != NULL &&
             json_get_str(json_get(rel, "chain_id")) != NULL);
    ZP_CHECK("show: manifest summary",
             json_get_bool(json_get(&c.reply.data, "manifest_present")) &&
             json_get_int(json_get(&c.reply.data, "files")) == 3 &&
             json_get_bool(json_get(&c.reply.data, "license_present")) &&
             json_get_int(json_get(&c.reply.data, "bytes")) > 0 &&
             json_get_int(json_get(&c.reply.data, "chunks")) == 3);
    const struct json_value *page =
        json_get(&c.reply.data, "files_page");
    const struct json_value *f0 = page ? json_at(page, 0) : NULL;
    ZP_CHECK("show: bounded file page, sorted paths",
             f0 &&
             strcmp(json_get_str(json_get(f0, "path")), "LICENSE") == 0 &&
             !json_get_bool(json_get(&c.reply.data, "files_truncated")));
    /* No receipts filed yet: reproduction reads as an honest empty
     * report — not reproduced, and the publish gate would refuse. */
    const struct json_value *repro =
        json_get(&c.reply.data, "reproduction");
    ZP_CHECK("show: zero receipts report not-reproduced, not publishable",
             repro &&
             json_get_int(json_get(repro, "receipts_scanned")) == 0 &&
             json_get_int(json_get(repro, "receipts_matching")) == 0 &&
             !json_get_bool(json_get(repro, "reproduced")) &&
             !json_get_bool(json_get(repro, "publishable")) &&
             json_get_int(json_get(repro, "distinct_toolchains")) == 0 &&
             !json_get_bool(json_get(repro, "cross_toolchain")) &&
             !json_get_bool(json_get(repro, "rows_truncated")));
    char release_id[65];
    const char *rid = rel ? json_get_str(json_get(rel, "release_id")) : NULL;
    snprintf(release_id, sizeof(release_id), "%s", rid ? rid : "");
    ZP_CHECK("show: the release names its own id", rid != NULL);
    zp_cmd_free(&c);

    /* File two distinct, mutually matching installable receipts (the same
     * package+recipe roots, the same output set, different flags strings —
     * distinct build events, distinct receipt ids): the gate's exact local
     * predicate must now read true. The two receipts pin DIFFERENT
     * toolchain capsules, so the strong diversity claim must read too. */
    struct vcs_package_build_receipt ra, rb;
    vcs_package_build_receipt_init(&ra);
    vcs_package_build_receipt_init(&rb);
    struct vcs_package_build_receipt *rcpts[2] = {&ra, &rb};
    static const char *const rcpt_flags[2] = {"fixture-quick",
                                              "fixture-standard"};
    bool rcpts_ok = true;
    uint8_t out_sha[32];
    memset(out_sha, 0x5a, sizeof(out_sha));
    for (size_t i = 0; i < 2 && rcpts_ok; i++) {
        struct vcs_package_build_receipt *rr = rcpts[i];
        memcpy(rr->package_root, p.root, 32);
        memcpy(rr->recipe_root, g_zp_recipe_root, 32);
        memcpy(rr->lock_root, p.root, 32);
        snprintf(rr->compiler_id, sizeof(rr->compiler_id), "gcc");
        snprintf(rr->compiler_version, sizeof(rr->compiler_version), "14.2.0");
        snprintf(rr->flags, sizeof(rr->flags), "%s", rcpt_flags[i]);
        rr->isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
        rr->test_ran = false;
        rr->result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
        uint8_t cap[32];
        memset(cap, i == 0 ? 0xc1 : 0xc2, sizeof(cap));
        rcpts_ok = vcs_package_build_add_output(rr, "lib/ring-buffer.a",
                                                out_sha, 123) ==
                       VCS_PACKAGE_BUILD_OK &&
                   vcs_package_build_set_toolchain_capsule(rr, cap) ==
                       VCS_PACKAGE_BUILD_OK &&
                   zp_file_receipt(dd, rr);
    }
    uint8_t id_a[32], id_b[32];
    bool ids_ok = rcpts_ok &&
        vcs_package_build_id(&ra, id_a) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rb, id_b) == VCS_PACKAGE_BUILD_OK &&
        memcmp(id_a, id_b, 32) != 0;
    ZP_CHECK("show: two distinct matching receipts filed", ids_ok);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    repro = json_get(&c.reply.data, "reproduction");
    ZP_CHECK("show: two agreeing receipts report reproduced + publishable",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED && repro &&
             json_get_int(json_get(repro, "receipts_matching")) == 2 &&
             json_get_bool(json_get(repro, "reproduced")) &&
             json_get_bool(json_get(repro, "publishable")) &&
             json_get_int(json_get(repro, "distinct_toolchains")) == 2 &&
             json_get_bool(json_get(repro, "cross_toolchain")) &&
             !json_get_bool(json_get(repro, "rows_truncated")));
    /* Capture this cross-toolchain package's verdict so it can be
     * compared, below, against a SOLO single-toolchain package's verdict
     * on an entirely separate package root. */
    bool cross_publishable =
        repro && json_get_bool(json_get(repro, "publishable"));
    int cross_distinct =
        repro ? (int)json_get_int(json_get(repro, "distinct_toolchains"))
              : -1;
    bool cross_flag = repro && json_get_bool(json_get(repro, "cross_toolchain"));
    zp_cmd_free(&c);

    /* ── owner directive pin (2026-08-25): cross-toolchain diversity is
     * EVIDENCE, NEVER A GATE. The owner ruled: "RECORD cross-toolchain
     * diversity as evidence whenever it is observed, but NEVER GATE
     * PUBLICATION ON IT. A two-toolchain requirement locks out every
     * solo publisher working on one machine, which betrays runs-anywhere.
     * Diversity accumulates from witnesses over time. It is a STRENGTH
     * SCORE, NOT A DOOR." Prove it end to end on the real show/publish
     * path: a SEPARATE package whose two agreeing receipts pin the SAME
     * toolchain capsule (one publisher, one machine, rebuilt twice) must
     * still read publishable — and the diversity fields must still be
     * honestly reported, because recording never stops just because it
     * doesn't gate. */
    char pkgdir2[512];
    snprintf(pkgdir2, sizeof(pkgdir2), "%s/pkg-solo", dd);
    struct zp_pkg p2;
    memset(&p2, 0, sizeof(p2));
    vcs_package_manifest_init(&p2.manifest);
    mkdir(pkgdir2, 0700);
    /* zp_make_package() always writes the SAME fixed file content
     * (manifest content is what the package root hashes over, not the
     * directory path) — reusing it here would collide p2's root with
     * p's and pollute p's already-filed receipts. Distinct content, a
     * distinct root, an isolated receipts bucket. */
    bool p2_built =
        zp_add_file(&p2, pkgdir2, "LICENSE",
                    "MIT License\n\nsolo publisher, one machine.\n",
                    VCS_PACKAGE_MODE_FILE) &&
        zp_add_file(&p2, pkgdir2, "src/solo.c",
                    "int solo_build(void) { return 9; }\n",
                    VCS_PACKAGE_MODE_FILE) &&
        vcs_package_manifest_serialize(&p2.manifest, &p2.wire,
                                       &p2.wire_len) &&
        vcs_package_manifest_root(&p2.manifest, p2.root) &&
        memcmp(p2.root, p.root, 32) != 0;
    if (p2_built)
        zp_hex32(p2.root, p2.root_hex);
    ZP_CHECK("owner directive fixture: solo-toolchain package builds "
             "(distinct root)",
             p2_built);
    ZP_CHECK("owner directive fixture: solo-toolchain recipe builds",
             zp_use_recipe(&p2.manifest));
    struct vcs_package_release r2;
    ZP_CHECK("owner directive fixture: solo-toolchain release signs",
             zp_release(&r2, 0xdd, 1u, "solo/one-machine", "MIT", p2.root));
    char *r2_hex = zp_release_hex(&r2, NULL, NULL);
    char *m2_hex = zp_hex(p2.wire, p2.wire_len);
    struct zp_cmd c2;
    zp_publish_input(&c2, dd, r2_hex, m2_hex, pkgdir2);
    zcl_native_handle_zcode_package_publish_commit(&c2.request, &c2.reply);
    ZP_CHECK("owner directive fixture: solo-toolchain package commits",
             c2.reply.status == ZCL_COMMAND_STATUS_PASSED);
    zp_cmd_free(&c2);

    struct vcs_package_build_receipt sa, sb;
    vcs_package_build_receipt_init(&sa);
    vcs_package_build_receipt_init(&sb);
    struct vcs_package_build_receipt *srcpts[2] = {&sa, &sb};
    static const char *const srcpt_flags[2] = {"fixture-quick",
                                               "fixture-standard"};
    bool srcpts_ok = true;
    uint8_t sout_sha[32];
    memset(sout_sha, 0x5b, sizeof(sout_sha));
    uint8_t solo_cap[32];
    memset(solo_cap, 0xc9, sizeof(solo_cap));
    for (size_t i = 0; i < 2 && srcpts_ok; i++) {
        struct vcs_package_build_receipt *rr = srcpts[i];
        memcpy(rr->package_root, p2.root, 32);
        memcpy(rr->recipe_root, g_zp_recipe_root, 32);
        memcpy(rr->lock_root, p2.root, 32);
        snprintf(rr->compiler_id, sizeof(rr->compiler_id), "gcc");
        snprintf(rr->compiler_version, sizeof(rr->compiler_version),
                 "14.2.0");
        snprintf(rr->flags, sizeof(rr->flags), "%s", srcpt_flags[i]);
        rr->isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
        rr->test_ran = false;
        rr->result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_BUILD_PASS;
        /* SAME capsule on both receipts, deliberately: one publisher, one
         * machine, rebuilt twice — the exact case the owner ruled must
         * still pass. */
        srcpts_ok = vcs_package_build_add_output(rr, "lib/ring-buffer.a",
                                                 sout_sha, 123) ==
                        VCS_PACKAGE_BUILD_OK &&
                    vcs_package_build_set_toolchain_capsule(rr, solo_cap) ==
                        VCS_PACKAGE_BUILD_OK &&
                    zp_file_receipt(dd, rr);
    }
    uint8_t sid_a[32], sid_b[32];
    bool sids_ok = srcpts_ok &&
        vcs_package_build_id(&sa, sid_a) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&sb, sid_b) == VCS_PACKAGE_BUILD_OK &&
        memcmp(sid_a, sid_b, 32) != 0;
    ZP_CHECK("owner directive fixture: two same-capsule receipts filed",
             sids_ok);

    zp_cmd_init(&c2);
    (void)json_push_kv_str(&c2.input, "datadir", dd);
    (void)json_push_kv_str(&c2.input, "root", p2.root_hex);
    zcl_native_handle_zcode_package_show(&c2.request, &c2.reply);
    const struct json_value *repro2 =
        json_get(&c2.reply.data, "reproduction");
    ZP_CHECK("owner directive: a single-toolchain package still PASSES "
             "publication (cross-toolchain diversity must be evidence, "
             "never a publication gate — owner directive)",
             c2.reply.status == ZCL_COMMAND_STATUS_PASSED && repro2 &&
             json_get_int(json_get(repro2, "receipts_matching")) == 2 &&
             json_get_bool(json_get(repro2, "reproduced")) &&
             json_get_bool(json_get(repro2, "publishable")));
    ZP_CHECK("owner directive: single-toolchain diversity is still "
             "HONESTLY REPORTED (distinct_toolchains=1, cross_toolchain="
             "false) — recording never stops just because it doesn't "
             "gate (owner directive)",
             repro2 &&
             json_get_int(json_get(repro2, "distinct_toolchains")) == 1 &&
             !json_get_bool(json_get(repro2, "cross_toolchain")));
    bool solo_publishable =
        repro2 && json_get_bool(json_get(repro2, "publishable"));
    int solo_distinct =
        repro2 ? (int)json_get_int(json_get(repro2, "distinct_toolchains"))
               : -1;
    bool solo_flag =
        repro2 && json_get_bool(json_get(repro2, "cross_toolchain"));
    ZP_CHECK("owner directive: adding a second toolchain (distinct=1->2, "
             "cross_toolchain=false->true) changes NO publish verdict — "
             "same pass, strictly more evidence; diversity is a strength "
             "score, not a door (owner directive)",
             solo_publishable && cross_publishable &&
             solo_publishable == cross_publishable &&
             solo_distinct == 1 && !solo_flag &&
             cross_distinct == 2 && cross_flag);
    zp_cmd_free(&c2);
    free(r2_hex);
    free(m2_hex);
    zp_pkg_free(&p2);

    /* A release envelope not filed under its own id (renamed away) still
     * loads into the index — the loader keys on CONTENT, not filename — so
     * show finds the package, but the envelope re-read 404s and the
     * section degrades to an error string. Show itself stays a working
     * read-only view. */
    char envelope[600], envelope_off[600];
    snprintf(envelope, sizeof(envelope), "%s/zcode/releases/%s", dd,
             release_id);
    char off_id[65];
    snprintf(off_id, sizeof(off_id), "%s", release_id);
    off_id[0] = off_id[0] == '0' ? '1' : '0';
    snprintf(envelope_off, sizeof(envelope_off), "%s/zcode/releases/%s", dd,
             off_id);
    ZP_CHECK("show: release envelope renamed off its own id",
             rename(envelope, envelope_off) == 0);
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    ZP_CHECK("show: unreadable envelope degrades to reproduction.error",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_str(json_get(&c.reply.data, "reproduction.error")) !=
                 NULL &&
             !json_get(&c.reply.data, "reproduction"));
    zp_cmd_free(&c);

    /* Unknown root: FAILED naming UNKNOWN_PACKAGE. */
    char unknown[65];
    memset(unknown, '9', 64);
    unknown[64] = '\0';
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", unknown);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    ZP_CHECK("show: unknown root rejected",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "UNKNOWN_PACKAGE") == 0);
    zp_cmd_free(&c);

    /* Malformed root: FAILED naming BAD_ROOT. */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", "xyz");
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    ZP_CHECK("show: bad root hex rejected",
             c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(c.reply.error.code, "BAD_ROOT") == 0);
    zp_cmd_free(&c);

    free(r_hex);
    free(m_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 10: index rebuild from the CAS (simulated crash) ────────────────── */
static int t_index_rebuild(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "rebuild");
    ZP_CHECK("rebuild: two packages commit",
             zp_commit_one(dd, 0xaa, 1u, "rhett/alpha", "MIT", 11) &&
             zp_commit_one(dd, 0xbb, 1u, "bob/beta", "ISC", 12));

    char zcode_dir[512];
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);

    /* Build, discard (the "crash": every in-memory copy is gone), rebuild
     * from the persisted CAS bytes — the two projections must agree entry
     * for entry, because the index holds no truth of its own. */
    struct vcs_package_index *a = vcs_package_index_build(zcode_dir);
    ZP_CHECK("rebuild: first build", a != NULL);
    struct vcs_package_index *b = vcs_package_index_build(zcode_dir);
    ZP_CHECK("rebuild: post-crash build", b != NULL);
    if (a && b) {
        ZP_CHECK("rebuild: same entry count",
                 vcs_package_index_count(a) == 2 &&
                 vcs_package_index_count(b) == 2);
        bool same = vcs_package_index_count(a) ==
                    vcs_package_index_count(b);
        for (size_t i = 0;
             same && i < vcs_package_index_count(a); i++) {
            const struct vcs_package_index_entry *ea =
                vcs_package_index_at(a, i);
            const struct vcs_package_index_entry *eb =
                vcs_package_index_at(b, i);
            same = strcmp(ea->release_id_hex, eb->release_id_hex) == 0 &&
                   strcmp(ea->name, eb->name) == 0 &&
                   strcmp(ea->package_root_hex, eb->package_root_hex) == 0 &&
                   ea->file_count == eb->file_count &&
                   ea->total_bytes == eb->total_bytes &&
                   ea->manifest_present == eb->manifest_present;
        }
        ZP_CHECK("rebuild: projections agree entry for entry", same);
    }
    vcs_package_index_free(a);
    vcs_package_index_free(b);

    /* find_root on the rebuilt index (search-by-root used by show). */
    struct vcs_package_index *idx = vcs_package_index_build(zcode_dir);
    ZP_CHECK("rebuild: third build", idx != NULL);
    if (idx) {
        const struct vcs_package_index_entry *e0 =
            vcs_package_index_at(idx, 0);
        uint8_t root[32];
        bool decoded = false;
        if (e0 && strlen(e0->package_root_hex) == 64) {
            decoded = true;
            for (size_t i = 0; i < 32; i++) {
                unsigned v;
                (void)sscanf(e0->package_root_hex + 2 * i, "%2x", &v);
                root[i] = (uint8_t)v;
            }
        }
        const struct vcs_package_index_entry *found =
            decoded ? vcs_package_index_find_root(idx, root) : NULL;
        ZP_CHECK("rebuild: find_root round-trips",
                 found && e0 &&
                 strcmp(found->release_id_hex, e0->release_id_hex) == 0);
        vcs_package_index_free(idx);
    }

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 11: the CLI path — input_validate, then the BOUND handler ────────
 *
 * Every other case in this file calls the handler symbol directly, which is
 * exactly the hole that let `zcode package publish plan` ship uncallable:
 * the kernel rejects any input key the leaf does not declare
 * (zcl_command_registry_input_validate, lib/kernel/src/command_registry.c),
 * and a direct call never reaches that check. This case builds the operator's
 * real input object, runs it through input_validate FIRST, and only then
 * dispatches through spec->handler — the same two steps the CLI takes. It
 * asserts three things a direct call cannot:
 *   - the exact input the handler REQUIRES is accepted by the leaf;
 *   - the handler the leaf BINDS is the one the direct tests exercise;
 *   - an undeclared key is still refused (the check is real, not bypassed).
 */
static const struct zcl_command_spec *zp_leaf(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    if (!reg)
        return NULL;
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

/* Run one leaf the way the CLI does: validate the input against the leaf's
 * declared contract, then call the handler the leaf binds. `why` carries the
 * validator's refusal text so a failure names the rejected key. */
static bool zp_registry_run(const struct zcl_command_spec *spec,
                            struct zp_cmd *c, char *why, size_t why_size)
{
    if (!spec || !spec->handler)
        return false;
    if (!zcl_command_registry_input_validate(spec, &c->input, why, why_size))
        return false;
    c->request.spec = spec;
    c->request.invoked_name = spec->path;
    spec->handler(&c->request, &c->reply);
    return true;
}

static int t_registry_path(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_publish", "registry");
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);

    struct zp_pkg p;
    ZP_CHECK("registry: package fixture builds", zp_make_package(&p, pkgdir));
    ZP_CHECK("registry: recipe fixture builds", zp_use_recipe(&p.manifest));
    struct vcs_package_release r;
    ZP_CHECK("registry: release signs",
             zp_release(&r, 0x5a, 1u, "rhett/ring-cli", "MIT", p.root));
    char *release_hex = zp_release_hex(&r, NULL, NULL);
    char *manifest_hex = zp_hex(p.wire, p.wire_len);
    ZP_CHECK("registry: inputs encode",
             release_hex && manifest_hex && g_zp_recipe_hex);

    const struct zcl_command_spec *plan = zp_leaf("zcode.package.publish.plan");
    const struct zcl_command_spec *commit =
        zp_leaf("zcode.package.publish.commit");
    ZP_CHECK("registry: both publish leaves are registered", plan && commit);
    ZP_CHECK("registry: both publish leaves bind a handler",
             plan && commit && plan->handler && commit->handler);
    /* The CLI path and the direct-handler path must be the same code, or
     * cases 1-9 prove nothing about what an operator can actually run. */
    ZP_CHECK("registry: plan binds the handler the direct tests call",
             plan &&
             plan->handler == zcl_native_handle_zcode_package_publish_plan);
    ZP_CHECK("registry: commit binds the handler the direct tests call",
             commit &&
             commit->handler ==
                 zcl_native_handle_zcode_package_publish_commit);

    const struct zcl_command_spec *library = zp_leaf("zcode.package.library");
    ZP_CHECK("registry: library leaf is registered", library && library->handler);
    ZP_CHECK("registry: library binds the handler the direct tests call",
             library &&
             library->handler == zcl_native_handle_zcode_package_library);

    const struct zcl_command_spec *fetch = zp_leaf("zcode.package.fetch");
    ZP_CHECK("registry: fetch leaf is registered", fetch && fetch->handler);
    ZP_CHECK("registry: fetch binds the handler the direct tests call",
             fetch && fetch->handler == zcl_native_handle_zcode_package_fetch);
    ZP_CHECK("registry: fetch does not require root when name is allowed",
             fetch && fetch->positional_keys &&
             fetch->positional_keys[0] == '\0');

    char why[192] = {0};
    struct zp_cmd c;

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    bool library_ran = zp_registry_run(library, &c, why, sizeof(why));
    ZP_CHECK("registry: library accepts datadir-only input", library_ran);
    if (!library_ran)
        printf("    validator refused: %s\n", why);
    ZP_CHECK("registry: library empty store is a passed empty list",
             library_ran && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "count")) == 0);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "name", "rhett/ring-cli");
    why[0] = 0;
    bool fetch_name_ok =
        fetch && zcl_command_registry_input_validate(fetch, &c.input, why,
                                                     sizeof(why));
    ZP_CHECK("registry: fetch accepts name without root", fetch_name_ok);
    if (!fetch_name_ok)
        printf("    validator refused: %s\n", why);
    zp_cmd_free(&c);

    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", p.root_hex);
    why[0] = 0;
    ZP_CHECK("registry: fetch still accepts root without name",
             fetch && zcl_command_registry_input_validate(fetch, &c.input, why,
                                                          sizeof(why)));
    zp_cmd_free(&c);

    /* plan — the operator's exact input, through input_validate. */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_zp_recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    bool plan_ran = zp_registry_run(plan, &c, why, sizeof(why));
    ZP_CHECK("registry: plan accepts the input the handler requires",
             plan_ran);
    if (!plan_ran)
        printf("    validator refused: %s\n", why);
    ZP_CHECK("registry: plan validates the candidate through the CLI path",
             plan_ran && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "valid")));
    zp_cmd_free(&c);

    /* recipe_hex is REQUIRED by the handler: dropping it must reach the
     * handler and be named there, not be swallowed by the validator. */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    bool norecipe_ran = zp_registry_run(plan, &c, why, sizeof(why));
    ZP_CHECK("registry: plan without recipe_hex still reaches the handler",
             norecipe_ran);
    ZP_CHECK("registry: plan without recipe_hex names recipe-missing",
             norecipe_ran &&
             !json_get_bool(json_get(&c.reply.data, "valid")) &&
             zp_failure_rule(&c.reply, 0) &&
             strcmp(zp_failure_rule(&c.reply, 0), "recipe-missing") == 0);
    zp_cmd_free(&c);

    /* The validator is real, not bypassed: an undeclared key is refused. */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_zp_recipe_hex);
    (void)json_push_kv_str(&c.input, "not_a_publish_key", "x");
    why[0] = 0;
    ZP_CHECK("registry: an undeclared key is refused by input_validate",
             plan && !zcl_command_registry_input_validate(plan, &c.input, why,
                                                          sizeof(why)) &&
             strstr(why, "not_a_publish_key") != NULL);
    zp_cmd_free(&c);

    /* `day` is a commit-only window pin: the plan handler never reads it, so
     * the plan leaf must not advertise it (and the commit leaf must). */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_zp_recipe_hex);
    (void)json_push_kv_int(&c.input, "day", 20100);
    why[0] = 0;
    ZP_CHECK("registry: plan refuses day (it reads none)",
             plan && !zcl_command_registry_input_validate(plan, &c.input, why,
                                                          sizeof(why)));
    ZP_CHECK("registry: commit accepts day (it reads it)",
             commit && zcl_command_registry_input_validate(commit, &c.input,
                                                           why, sizeof(why)));
    zp_cmd_free(&c);

    /* commit — the full operator input, through input_validate, persisting
     * into this case's own throwaway datadir. */
    zp_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_zp_recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    (void)json_push_kv_int(&c.input, "day", 20100);
    why[0] = 0;
    bool commit_ran = zp_registry_run(commit, &c, why, sizeof(why));
    ZP_CHECK("registry: commit accepts the input the handler requires",
             commit_ran);
    if (!commit_ran)
        printf("    validator refused: %s\n", why);
    ZP_CHECK("registry: commit persists through the CLI path",
             commit_ran && c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_str(json_get(&c.reply.data, "result")) &&
             strcmp(json_get_str(json_get(&c.reply.data, "result")),
                    "committed") == 0);
    zp_cmd_free(&c);

    free(release_hex);
    free(manifest_hex);
    zp_pkg_free(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

int test_zcode_publish(void)
{
    printf("\n=== zcode_publish: publication + local search ===\n");
    int failures = 0;
    failures += t_plan_happy();
    failures += t_license_rules();
    failures += t_structure_rules();
    failures += t_chunk_rules();
    failures += t_commit_roundtrip();
    failures += t_acceptance_replay();
    failures += t_search();
    failures += t_library();
    failures += t_library_reproduction();
    failures += t_show();
    failures += t_index_rebuild();
    failures += t_registry_path();
    printf("=== zcode_publish complete: %d failure(s) ===\n", failures);
    return failures;
}
