/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_contributor — the ZCODE contributor identity + ZNAM pointer
 * gate (contexts/commons/modules/vcs/package_contributor.*, engine/services/zcode_pointer.*, and
 * the slice-4 handlers in tools/command/native_zcode_contributor_command.c).
 *
 * Coverage:
 *   1. contributor show: authoritative release facts from the signed
 *      envelopes, plus the ZNAM publisher-profile pointer with its binding
 *      proof (bound == znam-owner == P2PKH(claimed pubkey)); unknown keys
 *      report has_published=false and no profile; BAD_PUBKEY rejection.
 *   2. contributor packages: bounded rows from the index publisher filter,
 *      empty publisher, BAD_PUBKEY rejection.
 *   3. package resolve: pointer and identity in separate output objects,
 *      the binding proof fields, and every rejection — UNKNOWN_NAME,
 *      NOT_A_ZCODE_POINTER, WRONG_POINTER_KIND, POINTER_NOT_BOUND,
 *      RELEASE_NOT_HOSTED.
 *   4. pointer move: re-pointing the name at a second release's root moves
 *      resolution but leaves both signed releases hosted and unchanged.
 *   5. impersonation: a name bound to an ATTACKER key that points at a
 *      victim's package root resolves with matches_pointer_publisher=false
 *      and the identity still read from the signed release.
 *   6. rebuild equivalence: reopening node.db and rebuilding the package
 *      index yields the same profile output (the index holds no truth).
 *
 * Handlers run in-process on ./test-tmp datadirs; ZNAM rows are seeded into
 * a file-backed <datadir>/node.db through the canonical model (the same
 * upsert the on-chain fold performs). CHAIN_MAIN is pinned so the binding
 * P2PKH derivation is deterministic. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/znam.h"
#include "services/zcode_pointer.h"
#include "vcs/package_index.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/zcode_contributor_binding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZC4_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zcode_contributor: %s... OK\n", (name)); }  \
    else { printf("  zcode_contributor: %s... FAIL\n", (name)); \
        failures++; }                                                 \
} while (0)

/* ── fixtures (test_zcode_publish.c pattern) ────────────────────────── */

static bool zc4_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

/* ── declarative build recipe fixture (slice 5) ───────────────────────
 * Publication now requires a recipe whose root the envelope commits; the
 * commit fixture packages are all LICENSE + src/x.c, so one canonical
 * fixture recipe covers them. The globals feed zc4_release (the
 * committed recipe_root) and zc4_commit_one (the recipe wire hex). */
static char g_zc4_recipe_hex[2 * 1024 + 1];
static uint8_t g_zc4_recipe_root[32];
static bool g_zc4_recipe_ready;

static bool zc4_use_recipe(void)
{
    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    bool ok = vcs_package_recipe_add_source(&r, "src/x.c", NULL) &&
              vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
              vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                             NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, g_zc4_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok || !wire || 2 * wire_len + 1 > sizeof(g_zc4_recipe_hex)) {
        free(wire);
        return false;
    }
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < wire_len; i++) {
        g_zc4_recipe_hex[2 * i]     = hexd[(wire[i] >> 4) & 0xf];
        g_zc4_recipe_hex[2 * i + 1] = hexd[wire[i] & 0xf];
    }
    g_zc4_recipe_hex[2 * wire_len] = '\0';
    free(wire);
    g_zc4_recipe_ready = true;
    return true;
}

static bool zc4_pubkey_hex(uint8_t seed, char out[67])
{
    static const char hexd[] = "0123456789abcdef";
    struct privkey sk;
    struct pubkey pk;
    if (!zc4_keypair(seed, &sk, &pk))
        return false;
    for (size_t i = 0; i < pk.size; i++) {
        out[2 * i]     = hexd[(pk.vch[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[pk.vch[i] & 0xf];
    }
    out[2 * pk.size] = '\0';
    return true;
}

/* The P2PKH address of the key on the active chain — the ZNAM owner that
 * makes a pointer BOUND. */
static bool zc4_p2pkh_of_seed(uint8_t seed, char *out, size_t out_cap)
{
    struct privkey sk;
    struct pubkey pk;
    if (!zc4_keypair(seed, &sk, &pk))
        return false;
    return zcode_pointer_expected_owner(pk.vch, out, out_cap);
}

static bool zc4_sign(struct vcs_package_release *r, struct privkey *sk)
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

static bool zc4_t1_reward(char *out, size_t out_size)
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

static bool zc4_release(struct vcs_package_release *r, uint8_t key_seed,
                        uint64_t sequence, const char *name,
                        const char *license, const uint8_t package_root[32],
                        const char *znam)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zc4_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zc4_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "%s", license);
    memcpy(r->recipe_root, g_zc4_recipe_root, 32);
    r->has_znam = znam != NULL;
    if (znam)
        snprintf(r->znam, sizeof(r->znam), "%s", znam);
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zc4_sign(r, &sk);
}

static char *zc4_hex(const uint8_t *data, size_t len)
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

/* ── in-process command runner ──────────────────────────────────────── */

struct zc4_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zc4_cmd_init(struct zc4_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_contributor_test.v1");
}

static void zc4_cmd_free(struct zc4_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Commit one small package; root_hex_out (65) gets the package root. */
static bool zc4_commit_one(const char *dd, uint8_t key_seed, uint64_t seq,
                           const char *name, const char *license,
                           int content_seed, const char *znam,
                           char root_hex_out[65])
{
    if (!g_zc4_recipe_ready && !zc4_use_recipe())
        return false;
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/src-%d", dd, content_seed);
    mkdir(pkgdir, 0700);

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    char license_text[96];
    snprintf(license_text, sizeof(license_text),
             "%s\nsee the LICENSE file, variant %d\n", license,
             content_seed);
    char source[64];
    snprintf(source, sizeof(source), "int x_%d;\n", content_seed);
    char path[512];
    snprintf(path, sizeof(path), "%s/LICENSE", pkgdir);
    FILE *f = fopen(path, "wb");
    char srcdir[512];
    snprintf(srcdir, sizeof(srcdir), "%s/src", pkgdir);
    mkdir(srcdir, 0700);
    char srcpath[512];
    snprintf(srcpath, sizeof(srcpath), "%s/x.c", srcdir);
    FILE *g = fopen(srcpath, "wb");
    bool ok = f && g;
    uint8_t lic_hash[32];
    uint8_t src_hash[32];
    if (ok)
        ok = fwrite(license_text, 1, strlen(license_text), f) ==
             strlen(license_text);
    if (f)
        fclose(f);
    if (ok)
        ok = fwrite(source, 1, strlen(source), g) == strlen(source);
    if (g)
        fclose(g);
    if (ok)
        ok = vcs_package_chunk_hash((const uint8_t *)license_text,
                                    strlen(license_text), lic_hash) &&
             vcs_package_chunk_hash((const uint8_t *)source,
                                    strlen(source), src_hash) &&
             vcs_package_manifest_add(&manifest, "LICENSE",
                                      VCS_PACKAGE_MODE_FILE,
                                      strlen(license_text), lic_hash, 1) &&
             vcs_package_manifest_add(&manifest, "src/x.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      strlen(source), src_hash, 1);
    uint8_t *m_wire = NULL;
    size_t m_wire_len = 0;
    uint8_t root[32];
    if (ok)
        ok = vcs_package_manifest_serialize(&manifest, &m_wire,
                                            &m_wire_len) &&
             vcs_package_manifest_root(&manifest, root);
    vcs_package_manifest_free(&manifest);

    struct vcs_package_release r;
    if (ok)
        ok = zc4_release(&r, key_seed, seq, name, license, root, znam);
    char *r_hex = NULL;
    char *m_hex = NULL;
    uint8_t *r_wire = NULL;
    size_t r_wire_len = 0;
    if (ok)
        ok = vcs_package_release_serialize(&r, &r_wire, &r_wire_len) ==
             VCS_PACKAGE_RELEASE_OK;
    if (ok) {
        r_hex = zc4_hex(r_wire, r_wire_len);
        m_hex = zc4_hex(m_wire, m_wire_len);
        ok = r_hex && m_hex;
    }
    if (ok) {
        /* The `day` input advances one ISO week per commit: the slice-11
         * publish-frequency checkpoint (new user: 1 publication/week per
         * publisher key) counts same-week commits, and this test commits
         * several releases by one key to exercise contributor surfaces —
         * never the frequency gate — so each commit lands in its own
         * week. */
        static unsigned zc4_week_seq = 0;
        struct zc4_cmd c;
        zc4_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", dd);
        (void)json_push_kv_str(&c.input, "release_hex", r_hex);
        (void)json_push_kv_str(&c.input, "manifest_hex", m_hex);
        (void)json_push_kv_str(&c.input, "recipe_hex", g_zc4_recipe_hex);
        (void)json_push_kv_str(&c.input, "dir", pkgdir);
        (void)json_push_kv_int(&c.input, "day",
                               20000 + 7 * (int64_t)zc4_week_seq++);
        zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
        ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
        zc4_cmd_free(&c);
    }
    if (ok && root_hex_out) {
        static const char hexd[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            root_hex_out[2 * i]     = hexd[(root[i] >> 4) & 0xf];
            root_hex_out[2 * i + 1] = hexd[root[i] & 0xf];
        }
        root_hex_out[64] = '\0';
    }
    free(r_hex);
    free(m_hex);
    free(r_wire);
    free(m_wire);
    test_rm_rf_recursive(pkgdir);
    return ok;
}

/* ── ZNAM seeding through the canonical model ───────────────────────── */

/* Upsert one name with its ZCODE pointer records (the same rows the
 * on-chain fold writes). NULL/empty optional texts are skipped. */
static bool zc4_seed(const char *dd, const char *name, const char *owner,
                     uint8_t target_type, const char *target_value,
                     const char *kind, const char *pubkey,
                     const char *display, const char *description)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dd);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, path) || !ndb.open)
        return false;
    struct znam_entry e;
    memset(&e, 0, sizeof(e));
    snprintf(e.name, sizeof(e.name), "%s", name);
    snprintf(e.owner_address, sizeof(e.owner_address), "%s", owner);
    e.target_type = target_type;
    snprintf(e.target_value, sizeof(e.target_value), "%s", target_value);
    memset(e.reg_txid, 0x5A, sizeof(e.reg_txid));
    memset(e.last_update_txid, 0x5A, sizeof(e.last_update_txid));
    e.reg_height = 100;
    e.expiry_height = 100 + ZNAM_REGISTRATION_TERM_BLOCKS;
    bool ok = db_znam_save(&ndb, &e);
    if (ok && kind)
        ok = db_znam_text_save(&ndb, name, ZCODE_POINTER_KEY_KIND, kind);
    if (ok && pubkey)
        ok = db_znam_text_save(&ndb, name, ZCODE_POINTER_KEY_PUBKEY, pubkey);
    if (ok && display)
        ok = db_znam_text_save(&ndb, name, ZCODE_POINTER_KEY_DISPLAY,
                               display);
    if (ok && description)
        ok = db_znam_text_save(&ndb, name, ZCODE_POINTER_KEY_DESCRIPTION,
                               description);
    node_db_close(&ndb);
    return ok;
}

static void zc4_show(struct zc4_cmd *c, const char *dd, const char *pubkey)
{
    zc4_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "pubkey", pubkey);
    zcl_native_handle_zcode_contributor_show(&c->request, &c->reply);
}

static void zc4_packages(struct zc4_cmd *c, const char *dd,
                         const char *pubkey)
{
    zc4_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "pubkey", pubkey);
    zcl_native_handle_zcode_contributor_packages(&c->request, &c->reply);
}

static void zc4_resolve(struct zc4_cmd *c, const char *dd, const char *name)
{
    zc4_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "name", name);
    zcl_native_handle_zcode_package_resolve(&c->request, &c->reply);
}

/* ── 1: contributor show ────────────────────────────────────────────── */
static int t_show(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "show");
    char pk_a[67];
    char pk_c[67];
    char owner_a[64];
    ZC4_CHECK("show: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) && zc4_pubkey_hex(0xcc, pk_c) &&
              zc4_p2pkh_of_seed(0xaa, owner_a, sizeof(owner_a)));
    ZC4_CHECK("show: two releases commit",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 1,
                             NULL, NULL) &&
              zc4_commit_one(dd, 0xaa, 2u, "rhett/json-lite", "Apache-2.0",
                             2, "jsonlite", NULL));
    ZC4_CHECK("show: publisher profile seeded (bound)",
              zc4_seed(dd, "rhett", owner_a, ZNAM_TYPE_ONION,
                       "rhettzcode.onion", ZCODE_POINTER_KIND_PUBLISHER,
                       pk_a, "Rhett", NULL));

    struct zc4_cmd c;
    zc4_show(&c, dd, pk_a);
    ZC4_CHECK("show: passes with release facts",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              json_get_bool(json_get(&c.reply.data, "has_published")) &&
              json_get_int(json_get(&c.reply.data, "release_count")) == 2 &&
              json_get_int(json_get(&c.reply.data, "latest_sequence")) == 2);
    const char *latest = json_get_str(json_get(&c.reply.data, "latest_name"));
    const char *rzp =
        json_get_str(json_get(&c.reply.data, "release_znam_pointer"));
    ZC4_CHECK("show: latest release + its znam pointer",
              latest && strcmp(latest, "rhett/json-lite") == 0 &&
              rzp && strcmp(rzp, "jsonlite") == 0);
    const struct json_value *zp = json_get(&c.reply.data, "znam_profile");
    const struct json_value *binding = zp ? json_get(zp, "binding") : NULL;
    const char *zp_name = zp ? json_get_str(json_get(zp, "name")) : NULL;
    const char *zp_display =
        zp ? json_get_str(json_get(zp, "display_name")) : NULL;
    const char *b_owner =
        binding ? json_get_str(json_get(binding, "owner_address")) : NULL;
    const char *b_expected =
        binding ? json_get_str(json_get(binding, "expected_owner")) : NULL;
    ZC4_CHECK("show: bound profile with binding proof",
              zp && json_get_bool(json_get(zp, "found")) &&
              json_get_int(json_get(zp, "claimant_names")) == 1 &&
              zp_name && strcmp(zp_name, "rhett") == 0 &&
              zp_display && strcmp(zp_display, "Rhett") == 0 &&
              binding && json_get_bool(json_get(binding, "bound")) &&
              b_owner && b_expected && strcmp(b_owner, b_expected) == 0 &&
              strcmp(b_owner, owner_a) == 0);
    const struct json_value *roots = json_get(&c.reply.data, "package_roots");
    ZC4_CHECK("show: package roots page",
              roots && json_size(roots) == 2 &&
              !json_get_bool(
                  json_get(&c.reply.data, "package_roots_truncated")));
    zc4_cmd_free(&c);

    zc4_show(&c, dd, pk_c);
    const struct json_value *zp2 = json_get(&c.reply.data, "znam_profile");
    ZC4_CHECK("show: unknown key has neither releases nor profile",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              !json_get_bool(json_get(&c.reply.data, "has_published")) &&
              zp2 && !json_get_bool(json_get(zp2, "found")));
    zc4_cmd_free(&c);

    zc4_show(&c, dd, "zz");
    ZC4_CHECK("show: malformed pubkey rejected",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "BAD_PUBKEY") == 0);
    zc4_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 2: contributor packages ────────────────────────────────────────── */
static int t_packages(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "packages");
    char pk_a[67];
    char pk_c[67];
    ZC4_CHECK("packages: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) && zc4_pubkey_hex(0xcc, pk_c));
    ZC4_CHECK("packages: three releases commit (two publishers)",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/alpha", "MIT", 11, NULL,
                             NULL) &&
              zc4_commit_one(dd, 0xaa, 2u, "rhett/beta", "ISC", 12, NULL,
                             NULL) &&
              zc4_commit_one(dd, 0xbb, 1u, "bob/gamma", "Zlib", 13, NULL,
                             NULL));

    struct zc4_cmd c;
    zc4_packages(&c, dd, pk_a);
    const struct json_value *rows = json_get(&c.reply.data, "packages");
    ZC4_CHECK("packages: publisher rows bounded and complete",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              json_get_int(json_get(&c.reply.data, "total_matches")) == 2 &&
              json_get_int(json_get(&c.reply.data, "rendered")) == 2 &&
              !json_get_bool(json_get(&c.reply.data, "items_truncated")) &&
              rows && json_size(rows) == 2);
    const struct json_value *row0 = rows ? json_at(rows, 0) : NULL;
    ZC4_CHECK("packages: row carries identity facts",
              row0 && json_get_str(json_get(row0, "name")) &&
              json_get_str(json_get(row0, "package_root")) &&
              json_get_str(json_get(row0, "release_id")) &&
              json_get_str(json_get(row0, "license")));
    zc4_cmd_free(&c);

    zc4_packages(&c, dd, pk_c);
    ZC4_CHECK("packages: unknown publisher is empty",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              json_get_int(json_get(&c.reply.data, "total_matches")) == 0);
    zc4_cmd_free(&c);

    zc4_packages(&c, dd, "nope");
    ZC4_CHECK("packages: malformed pubkey rejected",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "BAD_PUBKEY") == 0);
    zc4_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 3: package resolve + rejections ────────────────────────────────── */
static int t_resolve(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "resolve");
    char pk_a[67];
    char owner_a[64];
    char owner_b[64];
    char root1[65];
    ZC4_CHECK("resolve: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) &&
              zc4_p2pkh_of_seed(0xaa, owner_a, sizeof(owner_a)) &&
              zc4_p2pkh_of_seed(0xbb, owner_b, sizeof(owner_b)));
    ZC4_CHECK("resolve: package commits",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 21,
                             NULL, root1));
    ZC4_CHECK("resolve: bound package pointer seeded",
              zc4_seed(dd, "ringbuffer", owner_a, ZNAM_TYPE_CONTENT, root1,
                       ZCODE_POINTER_KIND_PACKAGE, pk_a, NULL,
                       "a ring buffer"));

    struct zc4_cmd c;
    zc4_resolve(&c, dd, "ringbuffer");
    const struct json_value *zp = json_get(&c.reply.data, "pointer");
    const struct json_value *zi = json_get(&c.reply.data, "identity");
    const struct json_value *binding = zp ? json_get(zp, "binding") : NULL;
    const char *claimed =
        zp ? json_get_str(json_get(zp, "claimed_package_root")) : NULL;
    const char *id_pub =
        zi ? json_get_str(json_get(zi, "publisher")) : NULL;
    const char *id_root =
        zi ? json_get_str(json_get(zi, "package_root")) : NULL;
    const char *id_src = zi ? json_get_str(json_get(zi, "source")) : NULL;
    const char *p_src = zp ? json_get_str(json_get(zp, "source")) : NULL;
    ZC4_CHECK("resolve: pointer and identity separated",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED && zp && zi &&
              p_src && strcmp(p_src, "znam-record") == 0 &&
              id_src && strcmp(id_src, "signed-release") == 0 &&
              json_get_str(json_get(&c.reply.data, "identity_note")));
    ZC4_CHECK("resolve: binding proof and root match",
              binding && json_get_bool(json_get(binding, "bound")) &&
              claimed && strcmp(claimed, root1) == 0 &&
              id_pub && strcmp(id_pub, pk_a) == 0 &&
              id_root && strcmp(id_root, root1) == 0 &&
              json_get_bool(json_get(zi, "matches_pointer_root")) &&
              json_get_bool(json_get(zi, "matches_pointer_publisher")));
    zc4_cmd_free(&c);

    zc4_resolve(&c, dd, "nosuch");
    ZC4_CHECK("resolve: unknown name rejected",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "UNKNOWN_NAME") == 0);
    zc4_cmd_free(&c);

    ZC4_CHECK("resolve: plain name seeded",
              zc4_seed(dd, "plain", owner_a, ZNAM_TYPE_ONION, "plain.onion",
                       NULL, NULL, NULL, NULL));
    zc4_resolve(&c, dd, "plain");
    ZC4_CHECK("resolve: ordinary name is not a zcode pointer",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "NOT_A_ZCODE_POINTER") == 0);
    zc4_cmd_free(&c);

    ZC4_CHECK("resolve: publisher profile seeded",
              zc4_seed(dd, "rhett", owner_a, ZNAM_TYPE_ONION,
                       "rhettzcode.onion", ZCODE_POINTER_KIND_PUBLISHER,
                       pk_a, NULL, NULL));
    zc4_resolve(&c, dd, "rhett");
    ZC4_CHECK("resolve: publisher profile is the wrong kind",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "WRONG_POINTER_KIND") == 0);
    zc4_cmd_free(&c);

    ZC4_CHECK("resolve: wrong-key pointer seeded",
              zc4_seed(dd, "fake", owner_b, ZNAM_TYPE_CONTENT, root1,
                       ZCODE_POINTER_KIND_PACKAGE, pk_a, NULL, NULL));
    zc4_resolve(&c, dd, "fake");
    ZC4_CHECK("resolve: unbound pointer refused",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "POINTER_NOT_BOUND") == 0);
    zc4_cmd_free(&c);

    char ghost[65];
    memset(ghost, '9', 64);
    ghost[64] = '\0';
    ZC4_CHECK("resolve: dangling pointer seeded",
              zc4_seed(dd, "ghost", owner_a, ZNAM_TYPE_CONTENT, ghost,
                       ZCODE_POINTER_KIND_PACKAGE, pk_a, NULL, NULL));
    zc4_resolve(&c, dd, "ghost");
    ZC4_CHECK("resolve: pointer to a release we do not host",
              c.reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(c.reply.error.code, "RELEASE_NOT_HOSTED") == 0);
    zc4_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4: pointer move leaves the signed releases untouched ───────────── */
static int t_pointer_move(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "move");
    char pk_a[67];
    char owner_a[64];
    char root1[65];
    char root2[65];
    ZC4_CHECK("move: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) &&
              zc4_p2pkh_of_seed(0xaa, owner_a, sizeof(owner_a)));
    ZC4_CHECK("move: two sequences of one package commit",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 31,
                             NULL, root1) &&
              zc4_commit_one(dd, 0xaa, 2u, "rhett/ring-buffer", "MIT", 32,
                             NULL, root2));
    ZC4_CHECK("move: pointer seeded at the first root",
              zc4_seed(dd, "ringbuffer", owner_a, ZNAM_TYPE_CONTENT, root1,
                       ZCODE_POINTER_KIND_PACKAGE, pk_a, NULL, NULL));

    struct zc4_cmd c;
    zc4_resolve(&c, dd, "ringbuffer");
    const struct json_value *zi = json_get(&c.reply.data, "identity");
    const char *got1 = zi ? json_get_str(json_get(zi, "package_root")) : NULL;
    ZC4_CHECK("move: resolves to the first root",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED && got1 &&
              strcmp(got1, root1) == 0);
    zc4_cmd_free(&c);

    /* Move the pointer (the on-chain UPDATE upsert) to the second root. */
    ZC4_CHECK("move: pointer re-pointed at the second root",
              zc4_seed(dd, "ringbuffer", owner_a, ZNAM_TYPE_CONTENT, root2,
                       ZCODE_POINTER_KIND_PACKAGE, pk_a, NULL, NULL));
    zc4_resolve(&c, dd, "ringbuffer");
    zi = json_get(&c.reply.data, "identity");
    const char *got2 = zi ? json_get_str(json_get(zi, "package_root")) : NULL;
    ZC4_CHECK("move: resolves to the second root",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED && got2 &&
              strcmp(got2, root2) == 0);
    zc4_cmd_free(&c);

    /* The old release is still hosted and unchanged — identity lives in
     * the signed envelope, not in the pointer. */
    zc4_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", root1);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    const struct json_value *rel = json_get(&c.reply.data, "release");
    const char *rel_pub =
        rel ? json_get_str(json_get(rel, "publisher")) : NULL;
    ZC4_CHECK("move: old release still shows by root",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED && rel &&
              rel_pub && strcmp(rel_pub, pk_a) == 0);
    zc4_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 5: impersonation — a bound pointer at someone else's root ──────── */
static int t_impersonation(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "impersonate");
    char pk_a[67];
    char pk_b[67];
    char owner_b[64];
    char root1[65];
    ZC4_CHECK("impersonation: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) && zc4_pubkey_hex(0xbb, pk_b) &&
              zc4_p2pkh_of_seed(0xbb, owner_b, sizeof(owner_b)));
    ZC4_CHECK("impersonation: victim package commits",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 41,
                             NULL, root1));
    /* The attacker binds their own name (owner == their key) but points it
     * at the victim's package root. The binding is honestly the attacker's;
     * the identity must still read the VICTIM's signed release. */
    ZC4_CHECK("impersonation: attacker pointer seeded",
              zc4_seed(dd, "copycat", owner_b, ZNAM_TYPE_CONTENT, root1,
                       ZCODE_POINTER_KIND_PACKAGE, pk_b, NULL,
                       "totally the real ring buffer"));

    struct zc4_cmd c;
    zc4_resolve(&c, dd, "copycat");
    const struct json_value *zp = json_get(&c.reply.data, "pointer");
    const struct json_value *zi = json_get(&c.reply.data, "identity");
    const struct json_value *binding = zp ? json_get(zp, "binding") : NULL;
    const char *id_pub =
        zi ? json_get_str(json_get(zi, "publisher")) : NULL;
    ZC4_CHECK("impersonation: identity stays the signed release's",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED && binding &&
              json_get_bool(json_get(binding, "bound")) &&
              id_pub && strcmp(id_pub, pk_a) == 0 &&
              !json_get_bool(json_get(zi, "matches_pointer_publisher")) &&
              json_get_bool(json_get(zi, "matches_pointer_root")));
    zc4_cmd_free(&c);

    zc4_show(&c, dd, pk_a);
    const struct json_value *prof = json_get(&c.reply.data, "znam_profile");
    ZC4_CHECK("impersonation: victim profile untouched by the claim",
              c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              json_get_bool(json_get(&c.reply.data, "has_published")) &&
              prof && !json_get_bool(json_get(prof, "found")));
    zc4_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 6: rebuild equivalence (reopen node.db + rebuild index) ────────── */
static int t_rebuild_equivalence(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_contributor", "rebuild");
    char pk_a[67];
    char owner_a[64];
    ZC4_CHECK("rebuild: fixtures",
              zc4_pubkey_hex(0xaa, pk_a) &&
              zc4_p2pkh_of_seed(0xaa, owner_a, sizeof(owner_a)));
    ZC4_CHECK("rebuild: package commits and profile seeded",
              zc4_commit_one(dd, 0xaa, 1u, "rhett/ring-buffer", "MIT", 51,
                             NULL, NULL) &&
              zc4_seed(dd, "rhett", owner_a, ZNAM_TYPE_ONION,
                       "rhettzcode.onion", ZCODE_POINTER_KIND_PUBLISHER,
                       pk_a, "Rhett", NULL));

    /* Every handler run rebuilds the index from the CAS and reopens
     * node.db — two runs must agree field for field. */
    struct zc4_cmd a;
    struct zc4_cmd b;
    zc4_show(&a, dd, pk_a);
    zc4_show(&b, dd, pk_a);
    const struct json_value *pa = json_get(&a.reply.data, "znam_profile");
    const struct json_value *pb = json_get(&b.reply.data, "znam_profile");
    const char *na = pa ? json_get_str(json_get(pa, "name")) : NULL;
    const char *nb = pb ? json_get_str(json_get(pb, "name")) : NULL;
    const char *la = json_get_str(json_get(&a.reply.data, "latest_name"));
    const char *lb = json_get_str(json_get(&b.reply.data, "latest_name"));
    const char *ia = json_get_str(json_get(&a.reply.data, "latest_release_id"));
    const char *ib = json_get_str(json_get(&b.reply.data, "latest_release_id"));
    ZC4_CHECK("rebuild: profile output identical across rebuilds",
              a.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              b.reply.status == ZCL_COMMAND_STATUS_PASSED &&
              json_get_int(json_get(&a.reply.data, "release_count")) ==
                  json_get_int(json_get(&b.reply.data, "release_count")) &&
              la && lb && strcmp(la, lb) == 0 &&
              ia && ib && strcmp(ia, ib) == 0 &&
              na && nb && strcmp(na, nb) == 0);
    zc4_cmd_free(&a);
    zc4_cmd_free(&b);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── contributor_binding.v1 (ZCODE Scientific Metaverse slice S2) ──────
 * Pure codec/identity tests: exact KAT wires, malformed/trailing/
 * cross-network rejection, dual-signature verification, expiry, and the
 * rotation/revocation chain gate. No datadir, no chainparams dependency. */

#define ZCB_ISSUED 1754000000LL
#define ZCB_EXPIRES (ZCB_ISSUED + 30LL * 86400LL)

/* Pinned golden vectors for the ACTIVE fixture below (net[i]=0xA0+i, ZID
 * seed 0x11, ZCL seed 0x22, seq 1, ZCB_ISSUED/ZCB_EXPIRES). Empty strings
 * print the computed value and FAIL — a KAT is never a hollow pass. */
#define ZCB_KAT_BODY_HEX "5a4342494e440d0a0100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27531260aa2a199e228c537dfa42c82bea2c7c1f4d0000000000000000000000000000000000000000000000000000000000000000010000000000000080ea8b68000000008077b3680000000001"
#define ZCB_KAT_WIRE_HEX "5a4342494e440d0a0100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27531260aa2a199e228c537dfa42c82bea2c7c1f4d0000000000000000000000000000000000000000000000000000000000000000010000000000000080ea8b68000000008077b3680000000001167521230bb5def2533c04a8d6fc36f553f07e92c9681100274728dfe92a0f3d96b9e192254eccbadcc7187f67301f9b5315af35f9f358840c9cfdb56096b40c2aa234542b7b802b925e0a49096496c9826ac70b12521c15bcff13ceaf068d18285667c236707e5a0dced06ef8d9419d3e1b9f707b8674b26ceaf21fdbe9c8cd"
#define ZCB_KAT_BODY_ROOT_HEX "1b65c066ca8ac2adae2e3c8ecdc9ea36dfc21b6b185aaa5fd67fa2e2db31870a"
#define ZCB_KAT_FULL_ROOT_HEX "fddbaff8134182b5ad284f8ef48a5171ad48b36ec9815b6ab849a003886ea1f2"

static void zcb_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(bytes[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[bytes[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zcb_kat_pin(const char *name, const char *expect, const char *got)
{
    if (expect[0] == '\0') {
        printf("  zcode_contributor: KAT(%s)=%s\n", name, got);
        return false;
    }
    return strcmp(expect, got) == 0;
}

static void zcb_fixture_net(uint8_t net[32])
{
    for (size_t i = 0; i < 32; i++) net[i] = (uint8_t)(0xa0u + i);
}

static void zcb_fixture_zid(uint8_t pk[32], uint8_t sk[32])
{
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    ed25519_keypair(pk, sk, seed);
}

static bool zcb_fill_key(uint8_t zcl_seed, uint8_t pubkey33[33],
                         uint8_t key_id[20])
{
    struct privkey sk;
    struct pubkey pk;
    if (!zc4_keypair(zcl_seed, &sk, &pk)) return false;
    memcpy(pubkey33, pk.vch, 33);
    struct key_id kid = pubkey_get_id(&pk);
    memcpy(key_id, kid.id.data, 20);
    return true;
}

/* An unsigned ACTIVE binding with the canonical fixture fields. */
static bool zcb_active(struct vcs_zcode_contributor_binding_v1 *b,
                       const uint8_t net[32], const uint8_t zid_pk[32],
                       uint8_t zcl_seed)
{
    memset(b, 0, sizeof(*b));
    b->schema_version = VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION;
    memcpy(b->network_genesis_root, net, 32);
    memcpy(b->zid_pubkey, zid_pk, 32);
    if (!zcb_fill_key(zcl_seed, b->zcl_pubkey, b->zcl_key_id)) return false;
    b->sequence = 1;
    b->issued_unix = ZCB_ISSUED;
    b->expires_unix = ZCB_EXPIRES;
    b->operation = VCS_ZCODE_BINDING_ACTIVE;
    return true;
}

static bool zcb_seal(struct vcs_zcode_contributor_binding_v1 *b,
                     const uint8_t zid_sk[32], const uint8_t zid_pk[32],
                     uint8_t zcl_seed)
{
    uint8_t zcl_sk[32];
    memset(zcl_sk, zcl_seed, sizeof(zcl_sk));
    return vcs_zcode_contributor_binding_seal(b, zid_sk, zid_pk, zcl_sk) ==
           VCS_ZCODE_BINDING_OK;
}

/* A sealed ROTATE (new_zcl_seed != 0) or REVOKE (new_zcl_seed == 0, keeps
 * the prior key) successor of prior. */
static bool zcb_successor(struct vcs_zcode_contributor_binding_v1 *next,
                          const struct vcs_zcode_contributor_binding_v1 *prior,
                          uint8_t op, uint8_t new_zcl_seed,
                          const uint8_t zid_sk[32], int64_t issued)
{
    *next = *prior;
    memset(next->zid_signature, 0, sizeof(next->zid_signature));
    memset(next->zcl_signature, 0, sizeof(next->zcl_signature));
    next->operation = op;
    next->sequence = prior->sequence + 1;
    next->issued_unix = issued;
    next->expires_unix = issued + 30LL * 86400LL;
    if (vcs_zcode_contributor_binding_root(prior, next->predecessor_root) !=
        VCS_ZCODE_BINDING_OK)
        return false;
    /* ROTATE installs the fresh key derived from new_zcl_seed. REVOKE
     * retires the same key (already copied from prior above); the caller
     * passes the CURRENT zcl seed so the retire signature still verifies
     * under the embedded key. */
    if (op == VCS_ZCODE_BINDING_ROTATE &&
        !zcb_fill_key(new_zcl_seed, next->zcl_pubkey, next->zcl_key_id))
        return false;
    return zcb_seal(next, zid_sk, prior->zid_pubkey, new_zcl_seed);
}

static int t_binding_kat(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("kat: fixture seals", zcb_active(&b, net, zid_pk, 0x22) &&
              zcb_seal(&b, zid_sk, zid_pk, 0x22));

    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    uint8_t body[VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES];
    uint8_t body_root[32], full_root[32];
    char hex[2 * VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES + 1];
    bool ok = vcs_zcode_contributor_binding_serialize(&b, wire) ==
              VCS_ZCODE_BINDING_OK;
    ok = ok && vcs_zcode_contributor_binding_body_root(&b, body_root) ==
                   VCS_ZCODE_BINDING_OK;
    ok = ok && vcs_zcode_contributor_binding_root(&b, full_root) ==
                   VCS_ZCODE_BINDING_OK;
    ZC4_CHECK("kat: serialize + roots", ok);
    memcpy(body, wire, VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES);

    zcb_hex(body, sizeof(body), hex);
    ZC4_CHECK("kat: body wire golden",
              zcb_kat_pin("body", ZCB_KAT_BODY_HEX, hex));
    zcb_hex(wire, sizeof(wire), hex);
    ZC4_CHECK("kat: full wire golden",
              zcb_kat_pin("wire", ZCB_KAT_WIRE_HEX, hex));
    zcb_hex(body_root, sizeof(body_root), hex);
    ZC4_CHECK("kat: body root golden",
              zcb_kat_pin("body_root", ZCB_KAT_BODY_ROOT_HEX, hex));
    zcb_hex(full_root, sizeof(full_root), hex);
    ZC4_CHECK("kat: full root golden",
              zcb_kat_pin("full_root", ZCB_KAT_FULL_ROOT_HEX, hex));
    return failures;
}

static int t_binding_roundtrip(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("roundtrip: fixture seals", zcb_active(&b, net, zid_pk, 0x22) &&
              zcb_seal(&b, zid_sk, zid_pk, 0x22));
    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    ZC4_CHECK("roundtrip: serialize",
              vcs_zcode_contributor_binding_serialize(&b, wire) ==
                  VCS_ZCODE_BINDING_OK);

    struct vcs_zcode_contributor_binding_v1 back;
    ZC4_CHECK("roundtrip: parse == struct",
              vcs_zcode_contributor_binding_parse(wire, sizeof(wire),
                                                  &back) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(&b, &back, sizeof(b)) == 0);
    uint8_t wire2[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    ZC4_CHECK("roundtrip: reserialize == wire",
              vcs_zcode_contributor_binding_serialize(&back, wire2) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(wire, wire2, sizeof(wire)) == 0);

    /* Truncated wires are exact-size rejections, never partial parses. */
    static const size_t short_lens[] = {0u, 7u, 8u, 100u, 183u, 184u, 311u};
    bool all_short = true;
    for (size_t i = 0; i < sizeof(short_lens) / sizeof(short_lens[0]); i++)
        all_short = all_short &&
            vcs_zcode_contributor_binding_parse(wire, short_lens[i], &back) ==
                VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
    ZC4_CHECK("roundtrip: truncated wires rejected", all_short);
    /* A trailing byte is a wire-size rejection. */
    uint8_t long_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES + 1];
    memcpy(long_wire, wire, sizeof(wire));
    long_wire[sizeof(wire)] = 0x00;
    ZC4_CHECK("roundtrip: trailing byte rejected",
              vcs_zcode_contributor_binding_parse(long_wire,
                                                  sizeof(long_wire), &back) ==
                  VCS_ZCODE_BINDING_ERR_WIRE_SIZE);

    uint8_t bad[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    memcpy(bad, wire, sizeof(bad));
    bad[0] ^= 0x01;
    ZC4_CHECK("roundtrip: wrong magic",
              vcs_zcode_contributor_binding_parse(bad, sizeof(bad), &back) ==
                  VCS_ZCODE_BINDING_ERR_WIRE_MAGIC);
    memcpy(bad, wire, sizeof(bad));
    bad[8] = 0x02; /* schema_version 2 */
    ZC4_CHECK("roundtrip: wrong version",
              vcs_zcode_contributor_binding_parse(bad, sizeof(bad), &back) ==
                  VCS_ZCODE_BINDING_ERR_VERSION);
    ZC4_CHECK("roundtrip: null arguments",
              vcs_zcode_contributor_binding_parse(NULL, sizeof(wire),
                                                  &back) ==
                  VCS_ZCODE_BINDING_ERR_NULL &&
              vcs_zcode_contributor_binding_parse(wire, sizeof(wire), NULL) ==
                  VCS_ZCODE_BINDING_ERR_NULL);
    return failures;
}

static int t_binding_fields(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("fields: fixture", zcb_active(&b, net, zid_pk, 0x22));

    struct vcs_zcode_contributor_binding_v1 x = b;
    memset(x.network_genesis_root, 0, 32);
    ZC4_CHECK("fields: zero network root",
              vcs_zcode_contributor_binding_body_root(&x, (uint8_t[32]){0}) ==
                  VCS_ZCODE_BINDING_ERR_ROOT_ZERO);
    x = b; memset(x.zid_pubkey, 0, 32);
    ZC4_CHECK("fields: zero zid pubkey",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO);
    x = b; x.operation = 0;
    ZC4_CHECK("fields: operation 0",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_OPERATION);
    x = b; x.operation = 4;
    ZC4_CHECK("fields: operation 4",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_OPERATION);
    x = b; x.sequence = 0;
    ZC4_CHECK("fields: sequence 0",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_SEQUENCE);
    x = b; x.sequence = 2; /* ACTIVE must open at 1 */
    ZC4_CHECK("fields: ACTIVE sequence 2",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_SEQUENCE);
    x = b; x.predecessor_root[0] = 0x01; /* ACTIVE takes a zero predecessor */
    ZC4_CHECK("fields: ACTIVE nonzero predecessor",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_PREDECESSOR);
    x = b; x.operation = VCS_ZCODE_BINDING_ROTATE; /* successor with seq 1 */
    ZC4_CHECK("fields: ROTATE sequence 1",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_SEQUENCE);
    x = b; x.operation = VCS_ZCODE_BINDING_ROTATE; x.sequence = 2;
    /* predecessor stays zero -> rejected for a successor op */
    ZC4_CHECK("fields: ROTATE zero predecessor",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_PREDECESSOR);
    x = b; x.issued_unix = 0;
    ZC4_CHECK("fields: issued 0",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    x = b; x.expires_unix = x.issued_unix;
    ZC4_CHECK("fields: expires == issued",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    x = b; x.zcl_key_id[0] ^= 0x01;
    ZC4_CHECK("fields: key_id mismatch",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_KEY_ID_MISMATCH);
    x = b; memset(x.zcl_pubkey, 0xff, 33); /* not a curve point */
    ZC4_CHECK("fields: invalid zcl pubkey",
              vcs_zcode_contributor_binding_validate(&x) ==
                  VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID);
    /* validate() requires both signatures present. */
    ZC4_CHECK("fields: unsigned binding",
              vcs_zcode_contributor_binding_validate(&b) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);

    /* seal() pins the keys it signs under. */
    x = b;
    uint8_t other_pk[32], other_sk[32];
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    ed25519_keypair(other_pk, other_sk, seed);
    uint8_t zcl_sk[32];
    memset(zcl_sk, 0x22, sizeof(zcl_sk));
    ZC4_CHECK("fields: seal null args",
              vcs_zcode_contributor_binding_seal(NULL, zid_sk, zid_pk,
                                                 zcl_sk) ==
                  VCS_ZCODE_BINDING_ERR_NULL);
    ZC4_CHECK("fields: seal wrong zid key",
              vcs_zcode_contributor_binding_seal(&x, other_sk, other_pk,
                                                 zcl_sk) ==
                  VCS_ZCODE_BINDING_ERR_KEY_MISMATCH);
    /* A ZID secret that does not derive the claimed pubkey is rejected
     * BEFORE anything is signed — the body field agrees with the pubkey
     * arg here, so only the secret/pubkey derivation can fire. */
    x = b; memcpy(x.zid_pubkey, other_pk, 32);
    ZC4_CHECK("fields: seal zid secret/pubkey mismatch",
              vcs_zcode_contributor_binding_seal(&x, zid_sk, other_pk,
                                                 zcl_sk) ==
                  VCS_ZCODE_BINDING_ERR_KEY_MISMATCH);
    x = b;
    uint8_t wrong_zcl[32];
    memset(wrong_zcl, 0x23, sizeof(wrong_zcl));
    ZC4_CHECK("fields: seal wrong zcl secret",
              vcs_zcode_contributor_binding_seal(&x, zid_sk, zid_pk,
                                                 wrong_zcl) ==
                  VCS_ZCODE_BINDING_ERR_KEY_MISMATCH);
    memset(wrong_zcl, 0x00, sizeof(wrong_zcl));
    ZC4_CHECK("fields: seal invalid zcl secret",
              vcs_zcode_contributor_binding_seal(&x, zid_sk, zid_pk,
                                                 wrong_zcl) ==
                  VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID);
    return failures;
}

static int t_binding_dual_sig(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("dual: fixture seals", zcb_active(&b, net, zid_pk, 0x22) &&
              zcb_seal(&b, zid_sk, zid_pk, 0x22));
    ZC4_CHECK("dual: verify ok",
              vcs_zcode_contributor_binding_verify(&b, net, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_OK);

    struct vcs_zcode_contributor_binding_v1 x = b;
    x.zid_signature[0] ^= 0x01;
    ZC4_CHECK("dual: bad zid signature",
              vcs_zcode_contributor_binding_verify(&x, net, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);
    x = b; x.zcl_signature[0] ^= 0x01;
    ZC4_CHECK("dual: bad zcl signature r",
              vcs_zcode_contributor_binding_verify(&x, net, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);
    x = b; memset(x.zcl_signature + 32, 0xff, 32); /* high-S */
    ZC4_CHECK("dual: high-S zcl signature",
              vcs_zcode_contributor_binding_verify(&x, net, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);

    uint8_t other_net[32], other_pk[32], other_sk[32];
    zcb_fixture_net(other_net);
    other_net[0] ^= 0x01;
    ZC4_CHECK("dual: cross-network rejected",
              vcs_zcode_contributor_binding_verify(&b, other_net, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH);
    ZC4_CHECK("dual: null network pin rejected",
              vcs_zcode_contributor_binding_verify(&b, NULL, zid_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH);
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    ed25519_keypair(other_pk, other_sk, seed);
    ZC4_CHECK("dual: wrong zid pin rejected",
              vcs_zcode_contributor_binding_verify(&b, net, other_pk,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH);
    ZC4_CHECK("dual: null zid pin rejected",
              vcs_zcode_contributor_binding_verify(&b, net, NULL,
                                                   ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH);
    return failures;
}

static int t_binding_expiry(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("expiry: fixture seals", zcb_active(&b, net, zid_pk, 0x22) &&
              zcb_seal(&b, zid_sk, zid_pk, 0x22));
    ZC4_CHECK("expiry: live binding accepted",
              vcs_zcode_contributor_binding_validate_at(&b, ZCB_EXPIRES - 1) ==
                  VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("notyet: before issue rejected",
              vcs_zcode_contributor_binding_validate_at(&b, ZCB_ISSUED - 1) ==
                  VCS_ZCODE_BINDING_ERR_NOT_YET_VALID);
    ZC4_CHECK("notyet: at issue accepted",
              vcs_zcode_contributor_binding_validate_at(&b, ZCB_ISSUED) ==
                  VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("expiry: expired at boundary",
              vcs_zcode_contributor_binding_validate_at(&b, ZCB_EXPIRES) ==
                  VCS_ZCODE_BINDING_ERR_EXPIRED);
    ZC4_CHECK("expiry: expired after",
              vcs_zcode_contributor_binding_validate_at(&b,
                                                        ZCB_EXPIRES + 1000) ==
                  VCS_ZCODE_BINDING_ERR_EXPIRED);
    ZC4_CHECK("notyet: nonpositive now",
              vcs_zcode_contributor_binding_validate_at(&b, 0) ==
                  VCS_ZCODE_BINDING_ERR_NOT_YET_VALID);
    ZC4_CHECK("notyet: verify gates early use",
              vcs_zcode_contributor_binding_verify(&b, net, zid_pk,
                                                   ZCB_ISSUED - 1) ==
                  VCS_ZCODE_BINDING_ERR_NOT_YET_VALID);
    ZC4_CHECK("expiry: verify gates expiry",
              vcs_zcode_contributor_binding_verify(&b, net, zid_pk,
                                                   ZCB_EXPIRES) ==
                  VCS_ZCODE_BINDING_ERR_EXPIRED);
    return failures;
}

static int t_binding_chain(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    const int64_t now = ZCB_ISSUED + 100;
    bool seal_ok;
    struct vcs_zcode_contributor_binding_v1 active, rotate, revoke;
    ZC4_CHECK("chain: active seals", zcb_active(&active, net, zid_pk, 0x22) &&
              zcb_seal(&active, zid_sk, zid_pk, 0x22));
    ZC4_CHECK("chain: rotate seals",
              zcb_successor(&rotate, &active, VCS_ZCODE_BINDING_ROTATE, 0x33,
                            zid_sk, ZCB_ISSUED + 50));
    ZC4_CHECK("chain: revoke seals",
              zcb_successor(&revoke, &rotate, VCS_ZCODE_BINDING_REVOKE, 0x33,
                            zid_sk, ZCB_ISSUED + 60));
    ZC4_CHECK("chain: valid rotation",
              vcs_zcode_contributor_binding_validate_successor(&active,
                                                               &rotate, now) ==
                  VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("chain: valid revocation",
              vcs_zcode_contributor_binding_validate_successor(&rotate,
                                                               &revoke, now) ==
                  VCS_ZCODE_BINDING_OK);

    /* Replay: reusing the prior sequence is not a successor. */
    struct vcs_zcode_contributor_binding_v1 x = rotate;
    x.sequence = active.sequence;
    ZC4_CHECK("chain: replay sequence rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_SEQUENCE);
    /* A skip is equally not +1. */
    x = rotate; x.sequence = active.sequence + 2;
    ZC4_CHECK("chain: sequence skip rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_SEQUENCE);
    x = rotate; x.predecessor_root[0] ^= 0x01;
    ZC4_CHECK("chain: wrong predecessor root",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_PREDECESSOR);
    /* Issue time must strictly increase along the chain. */
    x = rotate; x.issued_unix = active.issued_unix;
    ZC4_CHECK("chain: equal issued_unix rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    x = rotate; x.issued_unix = active.issued_unix - 5;
    ZC4_CHECK("chain: regressed issued_unix rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    /* A structurally valid second ACTIVE cannot succeed a link: the chain
     * gate rejects re-genesis before any linkage check. */
    struct vcs_zcode_contributor_binding_v1 fresh;
    seal_ok = zcb_active(&fresh, net, zid_pk, 0x22) &&
              zcb_seal(&fresh, zid_sk, zid_pk, 0x22);
    ZC4_CHECK("chain: second active seals", seal_ok);
    ZC4_CHECK("chain: successor cannot be ACTIVE",
              vcs_zcode_contributor_binding_validate_successor(&active,
                                                               &fresh, now) ==
                  VCS_ZCODE_BINDING_ERR_OPERATION);
    ZC4_CHECK("chain: rotation after revoke terminal",
              vcs_zcode_contributor_binding_validate_successor(&revoke,
                                                               &rotate, now) ==
                  VCS_ZCODE_BINDING_ERR_REVOKED);

    /* A ROTATE that keeps the old key is not a rotation; a REVOKE that
     * names a new key is an implicit replacement. */
    struct vcs_zcode_contributor_binding_v1 y;
    seal_ok = zcb_successor(&y, &active, VCS_ZCODE_BINDING_REVOKE, 0x22,
                            zid_sk, ZCB_ISSUED + 50);
    y.operation = VCS_ZCODE_BINDING_ROTATE;
    seal_ok = seal_ok && zcb_seal(&y, zid_sk, zid_pk, 0x22);
    ZC4_CHECK("chain: same-key rotate seals", seal_ok);
    ZC4_CHECK("chain: same-key rotate rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &y,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_LINKAGE);
    seal_ok = zcb_successor(&y, &active, VCS_ZCODE_BINDING_ROTATE, 0x33,
                            zid_sk, ZCB_ISSUED + 50);
    y.operation = VCS_ZCODE_BINDING_REVOKE;
    seal_ok = seal_ok && zcb_seal(&y, zid_sk, zid_pk, 0x33);
    ZC4_CHECK("chain: new-key revoke seals", seal_ok);
    ZC4_CHECK("chain: new-key revoke rejected",
              vcs_zcode_contributor_binding_validate_successor(&active, &y,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_LINKAGE);

    x = rotate; x.network_genesis_root[0] ^= 0x01;
    ZC4_CHECK("chain: cross-network successor",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH);
    x = rotate; x.zid_pubkey[0] ^= 0x01;
    ZC4_CHECK("chain: cross-zid successor",
              vcs_zcode_contributor_binding_validate_successor(&active, &x,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH);

    /* A tampered predecessor whose signatures no longer verify is rejected
     * even when a successor honestly points at its (tampered) root. */
    x = active; x.zid_signature[0] ^= 0x01;
    seal_ok = zcb_successor(&y, &x, VCS_ZCODE_BINDING_ROTATE, 0x33, zid_sk,
                            ZCB_ISSUED + 50);
    ZC4_CHECK("chain: successor of tampered seals", seal_ok);
    ZC4_CHECK("chain: tampered predecessor rejected",
              vcs_zcode_contributor_binding_validate_successor(&x, &y,
                                                               now) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);

    /* An expired predecessor still anchors a later rotation: expiry gates
     * acceptance of the CURRENT head, not the historical chain. */
    struct vcs_zcode_contributor_binding_v1 short_active;
    seal_ok = zcb_active(&short_active, net, zid_pk, 0x22);
    short_active.expires_unix = ZCB_ISSUED + 10;
    seal_ok = seal_ok && zcb_seal(&short_active, zid_sk, zid_pk, 0x22);
    ZC4_CHECK("chain: short-lived active seals", seal_ok);
    struct vcs_zcode_contributor_binding_v1 late_rotate;
    ZC4_CHECK("chain: late rotate seals",
              zcb_successor(&late_rotate, &short_active,
                            VCS_ZCODE_BINDING_ROTATE, 0x33, zid_sk,
                            ZCB_ISSUED + 50));
    ZC4_CHECK("chain: expired predecessor still anchors",
              vcs_zcode_contributor_binding_validate_successor(
                  &short_active, &late_rotate, ZCB_ISSUED + 60) ==
                  VCS_ZCODE_BINDING_OK);
    return failures;
}

static int t_binding_root_commitment(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v1 b;
    ZC4_CHECK("roots: fixture seals", zcb_active(&b, net, zid_pk, 0x22) &&
              zcb_seal(&b, zid_sk, zid_pk, 0x22));
    uint8_t body_root[32], full_root[32];
    ZC4_CHECK("roots: compute",
              vcs_zcode_contributor_binding_body_root(&b, body_root) ==
                  VCS_ZCODE_BINDING_OK &&
              vcs_zcode_contributor_binding_root(&b, full_root) ==
                  VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("roots: body root != full root",
              memcmp(body_root, full_root, 32) != 0);

    /* The body root ignores the signatures; the full root commits them, so
     * a tampered signature keeps the statement but changes the binding id
     * (and fails verify, covered above). */
    struct vcs_zcode_contributor_binding_v1 x = b;
    x.zcl_signature[10] ^= 0x01;
    uint8_t r2[32];
    ZC4_CHECK("roots: body root stable under sig change",
              vcs_zcode_contributor_binding_body_root(&x, r2) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(body_root, r2, 32) == 0);
    ZC4_CHECK("roots: full root tracks sig change",
              vcs_zcode_contributor_binding_root(&x, r2) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(full_root, r2, 32) != 0);
    return failures;
}

/* ── contributor_binding.v2 ─────────────────────────────────────────────
 * Three-signature rotation, delayed RECOVER, retired-key reuse ban, and
 * byte-exact KATs. Same fixture style as the v1 tests above. */

/* Pinned golden vectors for the ACTIVE v2 fixture below (net[i]=0xA0+i,
 * ZID seed 0x11, ZCL seed 0x22 signing BOTH slots, seq 1,
 * ZCB_ISSUED/ZCB_EXPIRES, activation 0). Filled from the first real run
 * after the computed values proved byte-identical across three runs
 * (deterministic RFC6979 + Ed25519). */
#define ZCB2_KAT_BODY_HEX "5a43424e44320d0a0200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27531260aa2a199e228c537dfa42c82bea2c7c1f4d0000000000000000000000000000000000000000000000000000000000000000010000000000000080ea8b68000000008077b36800000000010000000000000000"
#define ZCB2_KAT_WIRE_HEX "5a43424e44320d0a0200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27531260aa2a199e228c537dfa42c82bea2c7c1f4d0000000000000000000000000000000000000000000000000000000000000000010000000000000080ea8b68000000008077b368000000000100000000000000008c0d6cc94e4d382ecd6ebdd7033e751cd5c64f61729a5bb2bcde12a204dd26efcaf856f7c557b9edb0974f3d915a23971dbd15e1dd4c89a51ee92dd8d00d6d0d9d0ee17b5880e0f5f78ccadab954a0a0015ccc3447ea72c8eb2309bb4e6694a5317d9b8e8c65e51a59b6435af5f61693d6597f705a8e202aff35912edf67d7589d0ee17b5880e0f5f78ccadab954a0a0015ccc3447ea72c8eb2309bb4e6694a5317d9b8e8c65e51a59b6435af5f61693d6597f705a8e202aff35912edf67d758"
#define ZCB2_KAT_BODY_ROOT_HEX "ebdbd8953d96472c19fc949f3f8e7e9077d12ba7a9b6c92cc49e43f94a81293e"
#define ZCB2_KAT_FULL_ROOT_HEX "6fe433f34dae5767bdf51322c929f7cdfba5e138b41671941a90486d54f88343"

/* An unsigned ACTIVE v2 binding with the canonical fixture fields. */
static bool zcb2_active(struct vcs_zcode_contributor_binding_v2 *b,
                        const uint8_t net[32], const uint8_t zid_pk[32],
                        uint8_t zcl_seed)
{
    memset(b, 0, sizeof(*b));
    b->schema_version = VCS_ZCODE_CONTRIBUTOR_BINDING_V2_VERSION;
    memcpy(b->network_genesis_root, net, 32);
    memcpy(b->zid_pubkey, zid_pk, 32);
    if (!zcb_fill_key(zcl_seed, b->zcl_pubkey, b->zcl_key_id)) return false;
    b->sequence = 1;
    b->issued_unix = ZCB_ISSUED;
    b->expires_unix = ZCB_EXPIRES;
    b->operation = VCS_ZCODE_BINDING_ACTIVE;
    b->activation_unix = 0;
    return true;
}

/* Seed 0 means "no secret" (NULL) — RECOVER has no current secret, REVOKE
 * has no new secret. */
static bool zcb2_seal(struct vcs_zcode_contributor_binding_v2 *b,
                      const uint8_t zid_sk[32], const uint8_t zid_pk[32],
                      uint8_t current_seed, uint8_t new_seed)
{
    uint8_t current_sk[32], new_sk[32];
    memset(current_sk, current_seed, sizeof(current_sk));
    memset(new_sk, new_seed, sizeof(new_sk));
    return vcs_zcode_contributor_binding_seal_v2(
               b, zid_sk, zid_pk, current_seed ? current_sk : NULL,
               new_seed ? new_sk : NULL) == VCS_ZCODE_BINDING_OK;
}

/* A sealed v2 successor of prior. ROTATE/RECOVER install the key derived
 * from new_zcl_seed; REVOKE keeps prior's. current_seed is the OLD zcl
 * seed for ROTATE, the retiring seed for REVOKE, 0 for RECOVER.
 * activation is only meaningful for RECOVER. */
static bool zcb2_successor(struct vcs_zcode_contributor_binding_v2 *next,
                           const struct vcs_zcode_contributor_binding_v2 *prior,
                           uint8_t op, uint8_t current_seed,
                           uint8_t new_zcl_seed, const uint8_t zid_sk[32],
                           int64_t issued, int64_t activation)
{
    *next = *prior;
    memset(next->zid_signature, 0, sizeof(next->zid_signature));
    memset(next->zcl_current_signature, 0,
           sizeof(next->zcl_current_signature));
    memset(next->zcl_new_signature, 0, sizeof(next->zcl_new_signature));
    next->operation = op;
    next->sequence = prior->sequence + 1;
    next->issued_unix = issued;
    next->expires_unix = issued + 30LL * 86400LL;
    next->activation_unix = activation;
    if (vcs_zcode_contributor_binding_root_v2(prior,
                                              next->predecessor_root) !=
        VCS_ZCODE_BINDING_OK)
        return false;
    if ((op == VCS_ZCODE_BINDING_ROTATE || op == VCS_ZCODE_BINDING_RECOVER) &&
        !zcb_fill_key(new_zcl_seed, next->zcl_pubkey, next->zcl_key_id))
        return false;
    return zcb2_seal(next, zid_sk, prior->zid_pubkey, current_seed,
                     new_zcl_seed);
}

static int t_binding_v2_kat(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v2 b;
    ZC4_CHECK("kat2: fixture seals", zcb2_active(&b, net, zid_pk, 0x22) &&
              zcb2_seal(&b, zid_sk, zid_pk, 0x22, 0x22));

    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES];
    uint8_t body[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES];
    uint8_t body_root[32], full_root[32];
    char hex[2 * VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES + 1];
    bool ok = vcs_zcode_contributor_binding_serialize_v2(&b, wire) ==
              VCS_ZCODE_BINDING_OK;
    ok = ok && vcs_zcode_contributor_binding_body_root_v2(&b, body_root) ==
                   VCS_ZCODE_BINDING_OK;
    ok = ok && vcs_zcode_contributor_binding_root_v2(&b, full_root) ==
                   VCS_ZCODE_BINDING_OK;
    ZC4_CHECK("kat2: serialize + roots", ok);
    memcpy(body, wire, VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES);

    zcb_hex(body, sizeof(body), hex);
    ZC4_CHECK("kat2: body wire golden",
              zcb_kat_pin("v2-body", ZCB2_KAT_BODY_HEX, hex));
    zcb_hex(wire, sizeof(wire), hex);
    ZC4_CHECK("kat2: full wire golden",
              zcb_kat_pin("v2-wire", ZCB2_KAT_WIRE_HEX, hex));
    zcb_hex(body_root, sizeof(body_root), hex);
    ZC4_CHECK("kat2: body root golden",
              zcb_kat_pin("v2-body_root", ZCB2_KAT_BODY_ROOT_HEX, hex));
    zcb_hex(full_root, sizeof(full_root), hex);
    ZC4_CHECK("kat2: full root golden",
              zcb_kat_pin("v2-full_root", ZCB2_KAT_FULL_ROOT_HEX, hex));
    return failures;
}

static int t_binding_v2_roundtrip(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v2 b;
    ZC4_CHECK("roundtrip2: fixture seals",
              zcb2_active(&b, net, zid_pk, 0x22) &&
              zcb2_seal(&b, zid_sk, zid_pk, 0x22, 0x22));
    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES];
    ZC4_CHECK("roundtrip2: serialize",
              vcs_zcode_contributor_binding_serialize_v2(&b, wire) ==
                  VCS_ZCODE_BINDING_OK);

    struct vcs_zcode_contributor_binding_v2 back;
    ZC4_CHECK("roundtrip2: parse == struct",
              vcs_zcode_contributor_binding_parse_v2(wire, sizeof(wire),
                                                     &back) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(&b, &back, sizeof(b)) == 0);
    uint8_t wire2[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES];
    ZC4_CHECK("roundtrip2: reserialize == wire",
              vcs_zcode_contributor_binding_serialize_v2(&back, wire2) ==
                  VCS_ZCODE_BINDING_OK &&
              memcmp(wire, wire2, sizeof(wire)) == 0);

    /* Exact-size only: 384 bytes, no shorter, no longer. */
    static const size_t bad_lens[] = {0u, 191u, 192u, 383u};
    bool all_bad = true;
    for (size_t i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++)
        all_bad = all_bad &&
            vcs_zcode_contributor_binding_parse_v2(wire, bad_lens[i],
                                                   &back) ==
                VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
    ZC4_CHECK("roundtrip2: short wires rejected", all_bad);
    uint8_t long_wire[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES + 1];
    memcpy(long_wire, wire, sizeof(wire));
    long_wire[sizeof(wire)] = 0x00;
    ZC4_CHECK("roundtrip2: trailing byte rejected (385)",
              vcs_zcode_contributor_binding_parse_v2(long_wire,
                                                     sizeof(long_wire),
                                                     &back) ==
                  VCS_ZCODE_BINDING_ERR_WIRE_SIZE);

    uint8_t bad[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES];
    memcpy(bad, wire, sizeof(bad));
    bad[0] ^= 0x01;
    ZC4_CHECK("roundtrip2: wrong magic",
              vcs_zcode_contributor_binding_parse_v2(bad, sizeof(bad),
                                                     &back) ==
                  VCS_ZCODE_BINDING_ERR_WIRE_MAGIC);
    memcpy(bad, wire, sizeof(bad));
    bad[8] = 0x01; /* schema_version 1 in a v2 wire */
    ZC4_CHECK("roundtrip2: wrong version",
              vcs_zcode_contributor_binding_parse_v2(bad, sizeof(bad),
                                                     &back) ==
                  VCS_ZCODE_BINDING_ERR_VERSION);
    ZC4_CHECK("roundtrip2: null arguments",
              vcs_zcode_contributor_binding_parse_v2(NULL, sizeof(wire),
                                                     &back) ==
                  VCS_ZCODE_BINDING_ERR_NULL &&
              vcs_zcode_contributor_binding_parse_v2(wire, sizeof(wire),
                                                     NULL) ==
                  VCS_ZCODE_BINDING_ERR_NULL);
    return failures;
}

static int t_binding_v2_active(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v2 b;
    ZC4_CHECK("active2: fixture seals", zcb2_active(&b, net, zid_pk, 0x22) &&
              zcb2_seal(&b, zid_sk, zid_pk, 0x22, 0x22));
    /* Both slots signed by the initial key, both verify standalone. */
    ZC4_CHECK("active2: verify ok",
              vcs_zcode_contributor_binding_verify_v2(&b, net, zid_pk,
                                                      ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_OK);

    struct vcs_zcode_contributor_binding_v2 x = b;
    memset(x.zcl_current_signature, 0, sizeof(x.zcl_current_signature));
    ZC4_CHECK("active2: zeroed current slot rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_SIG_SLOT);
    x = b;
    memset(x.zcl_new_signature, 0, sizeof(x.zcl_new_signature));
    ZC4_CHECK("active2: zeroed new slot rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_SIG_SLOT);
    x = b;
    x.activation_unix = ZCB_ISSUED + 1; /* only RECOVER carries one */
    ZC4_CHECK("active2: nonzero activation rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_OPERATION);
    x = b;
    x.zcl_new_signature[0] ^= 0x01;
    ZC4_CHECK("active2: tampered new slot rejected",
              vcs_zcode_contributor_binding_verify_v2(&x, net, zid_pk,
                                                      ZCB_ISSUED + 1) ==
                  VCS_ZCODE_BINDING_ERR_SIGNATURE);
    return failures;
}

static int t_binding_v2_rotate(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    const int64_t now = ZCB_ISSUED + 100;
    struct vcs_zcode_contributor_binding_v2 active = {0}, rotate = {0};
    ZC4_CHECK("rotate2: active seals",
              zcb2_active(&active, net, zid_pk, 0x22) &&
              zcb2_seal(&active, zid_sk, zid_pk, 0x22, 0x22));
    /* Normal rotation: current slot by the OLD key (0x22), new slot by the
     * NEW key (0x33), ZID over both. */
    ZC4_CHECK("rotate2: rotate seals",
              zcb2_successor(&rotate, &active, VCS_ZCODE_BINDING_ROTATE,
                             0x22, 0x33, zid_sk, ZCB_ISSUED + 50, 0));
    ZC4_CHECK("rotate2: valid rotation",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &rotate, now) == VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("rotate2: new key verifies standalone",
              vcs_zcode_contributor_binding_verify_v2(&rotate, net, zid_pk,
                                                      now) ==
                  VCS_ZCODE_BINDING_OK);

    /* Both slots sign the same body_root, so a slot swap plants each
     * signature in the wrong slot: the "old-key slot" now verifies under
     * the NEW key only, and vice versa. */
    struct vcs_zcode_contributor_binding_v2 x = rotate;
    memcpy(x.zcl_current_signature, rotate.zcl_new_signature, 64);
    ZC4_CHECK("rotate2: old-key slot signed by NEW key rejected",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &x, now) == VCS_ZCODE_BINDING_ERR_SIGNATURE);
    x = rotate;
    memcpy(x.zcl_new_signature, rotate.zcl_current_signature, 64);
    ZC4_CHECK("rotate2: new slot signed by OLD key rejected",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &x, now) == VCS_ZCODE_BINDING_ERR_SIGNATURE);
    x = rotate;
    memset(x.zcl_current_signature, 0, sizeof(x.zcl_current_signature));
    ZC4_CHECK("rotate2: zeroed current slot rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_SIG_SLOT);
    return failures;
}

static int t_binding_v2_recover(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    struct vcs_zcode_contributor_binding_v2 active, recover;
    ZC4_CHECK("recover2: active seals",
              zcb2_active(&active, net, zid_pk, 0x22) &&
              zcb2_seal(&active, zid_sk, zid_pk, 0x22, 0x22));
    /* Lost key 0x22: no current secret, new key 0x33, activation a full
     * recovery delay after issue. */
    const int64_t rec_issued = ZCB_ISSUED + 50;
    const int64_t rec_activation =
        rec_issued + VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS;
    ZC4_CHECK("recover2: recover seals",
              zcb2_successor(&recover, &active, VCS_ZCODE_BINDING_RECOVER,
                             0, 0x33, zid_sk, rec_issued, rec_activation));
    ZC4_CHECK("recover2: structurally valid",
              vcs_zcode_contributor_binding_validate_v2(&recover) ==
                  VCS_ZCODE_BINDING_OK);

    /* Activation too close to issue: the owner needs the full window. */
    struct vcs_zcode_contributor_binding_v2 x = recover;
    x.activation_unix =
        rec_issued + VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS - 1;
    ZC4_CHECK("recover2: short delay rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_RECOVERY_DELAY);

    /* A valid RECOVER is not effective before its activation time. */
    ZC4_CHECK("recover2: pending before activation",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &recover, rec_activation - 1) ==
                  VCS_ZCODE_BINDING_ERR_RECOVERY_PENDING);
    ZC4_CHECK("recover2: effective at activation",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &recover, rec_activation) ==
                  VCS_ZCODE_BINDING_OK);
    ZC4_CHECK("recover2: effective after activation",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &recover, rec_activation + 1000) ==
                  VCS_ZCODE_BINDING_OK);

    /* The current slot must stay zero — the old key is presumed lost, so
     * nothing may be presented on its behalf. */
    x = recover;
    x.zcl_current_signature[0] = 0x01;
    ZC4_CHECK("recover2: non-zero current slot rejected",
              vcs_zcode_contributor_binding_validate_v2(&x) ==
                  VCS_ZCODE_BINDING_ERR_SIG_SLOT);

    /* Recovering to the same key is not a recovery. */
    struct vcs_zcode_contributor_binding_v2 same;
    bool seal_ok = zcb2_successor(&same, &active, VCS_ZCODE_BINDING_RECOVER,
                                  0, 0x22, zid_sk, rec_issued,
                                  rec_activation);
    ZC4_CHECK("recover2: same-key recover seals", seal_ok);
    ZC4_CHECK("recover2: same-key recover rejected",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &same, rec_activation) ==
                  VCS_ZCODE_BINDING_ERR_LINKAGE);
    return failures;
}

static int t_binding_v2_time_order(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    const int64_t now = ZCB_ISSUED + 100;
    struct vcs_zcode_contributor_binding_v2 active = {0}, rotate = {0};
    ZC4_CHECK("time2: chain seals",
              zcb2_active(&active, net, zid_pk, 0x22) &&
              zcb2_seal(&active, zid_sk, zid_pk, 0x22, 0x22) &&
              zcb2_successor(&rotate, &active, VCS_ZCODE_BINDING_ROTATE,
                             0x22, 0x33, zid_sk, ZCB_ISSUED + 50, 0));
    /* Issue time must strictly increase: equal and regressed are both
     * reorderings, not rotations. */
    struct vcs_zcode_contributor_binding_v2 x = rotate;
    x.issued_unix = active.issued_unix;
    ZC4_CHECK("time2: equal issued_unix rejected",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &x, now) == VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    x = rotate;
    x.issued_unix = active.issued_unix - 5;
    ZC4_CHECK("time2: regressed issued_unix rejected",
              vcs_zcode_contributor_binding_validate_successor_v2(
                  &active, &x, now) == VCS_ZCODE_BINDING_ERR_TIME_ORDER);
    return failures;
}

static int t_binding_v2_chain(void)
{
    int failures = 0;
    uint8_t net[32], zid_pk[32], zid_sk[32];
    zcb_fixture_net(net);
    zcb_fixture_zid(zid_pk, zid_sk);
    const int64_t now = ZCB_ISSUED + 100;
    struct vcs_zcode_contributor_binding_v2 a, rot_b, rot_c;
    ZC4_CHECK("chain2: A seals",
              zcb2_active(&a, net, zid_pk, 0x22) &&
              zcb2_seal(&a, zid_sk, zid_pk, 0x22, 0x22));
    ZC4_CHECK("chain2: A->ROT(B) seals",
              zcb2_successor(&rot_b, &a, VCS_ZCODE_BINDING_ROTATE, 0x22,
                             0x33, zid_sk, ZCB_ISSUED + 50, 0));
    ZC4_CHECK("chain2: B->ROT(C) seals",
              zcb2_successor(&rot_c, &rot_b, VCS_ZCODE_BINDING_ROTATE, 0x33,
                             0x44, zid_sk, ZCB_ISSUED + 60, 0));
    {
        const struct vcs_zcode_contributor_binding_v2 chain[] = {a, rot_b,
                                                                 rot_c};
        ZC4_CHECK("chain2: A->ROT(B)->ROT(C) valid",
                  vcs_zcode_contributor_binding_validate_chain_v2(
                      chain, 3, now) == VCS_ZCODE_BINDING_OK);
    }

    /* The retired A key must never come back. */
    struct vcs_zcode_contributor_binding_v2 rot_a_again;
    ZC4_CHECK("chain2: B->ROT(A-key) seals",
              zcb2_successor(&rot_a_again, &rot_b, VCS_ZCODE_BINDING_ROTATE,
                             0x33, 0x22, zid_sk, ZCB_ISSUED + 60, 0));
    {
        const struct vcs_zcode_contributor_binding_v2 chain[] = {a, rot_b,
                                                                 rot_a_again};
        ZC4_CHECK("chain2: retired-key reuse banned",
                  vcs_zcode_contributor_binding_validate_chain_v2(
                      chain, 3, now) ==
                      VCS_ZCODE_BINDING_ERR_RETIRED_KEY_REUSE);
    }

    /* Revocation is terminal: nothing may follow, not even an honest
     * rotation sealed against the revoked link. */
    struct vcs_zcode_contributor_binding_v2 revoke = {0}, after = {0};
    bool seal_ok = zcb2_successor(&revoke, &a, VCS_ZCODE_BINDING_REVOKE,
                                  0x22, 0, zid_sk, ZCB_ISSUED + 50, 0) &&
                   zcb2_successor(&after, &revoke, VCS_ZCODE_BINDING_ROTATE,
                                  0x22, 0x33, zid_sk, ZCB_ISSUED + 60, 0);
    ZC4_CHECK("chain2: A->REVOKE(A)->ROT(B) seals", seal_ok);
    {
        const struct vcs_zcode_contributor_binding_v2 chain[] = {a, revoke,
                                                                 after};
        ZC4_CHECK("chain2: rotation after revoke terminal",
                  vcs_zcode_contributor_binding_validate_chain_v2(
                      chain, 3, now) == VCS_ZCODE_BINDING_ERR_REVOKED);
    }

    /* A chain must open with ACTIVE. */
    {
        const struct vcs_zcode_contributor_binding_v2 chain[] = {rot_b,
                                                                 rot_c};
        ZC4_CHECK("chain2: chain not starting with ACTIVE rejected",
                  vcs_zcode_contributor_binding_validate_chain_v2(
                      chain, 2, now) == VCS_ZCODE_BINDING_ERR_OPERATION);
    }
    ZC4_CHECK("chain2: null and empty chains rejected",
              vcs_zcode_contributor_binding_validate_chain_v2(NULL, 1,
                                                              now) ==
                  VCS_ZCODE_BINDING_ERR_NULL &&
              vcs_zcode_contributor_binding_validate_chain_v2(&a, 0, now) ==
                  VCS_ZCODE_BINDING_ERR_NULL);
    return failures;
}

int test_zcode_contributor(void)
{
    printf("\n=== zcode_contributor: identity + ZNAM pointers ===\n");
    int failures = 0;
    failures += t_show();
    failures += t_packages();
    failures += t_resolve();
    failures += t_pointer_move();
    failures += t_impersonation();
    failures += t_rebuild_equivalence();
    failures += t_binding_kat();
    failures += t_binding_roundtrip();
    failures += t_binding_fields();
    failures += t_binding_dual_sig();
    failures += t_binding_expiry();
    failures += t_binding_chain();
    failures += t_binding_root_commitment();
    failures += t_binding_v2_kat();
    failures += t_binding_v2_roundtrip();
    failures += t_binding_v2_active();
    failures += t_binding_v2_rotate();
    failures += t_binding_v2_recover();
    failures += t_binding_v2_time_order();
    failures += t_binding_v2_chain();
    printf("=== zcode_contributor complete: %d failure(s) ===\n", failures);
    return failures;
}
