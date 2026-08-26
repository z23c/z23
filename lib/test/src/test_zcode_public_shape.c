/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_public_shape — the adversarial gate on what a node will
 * announce and serve (lib/vcs/package_public_shape.*, enforced in
 * package_swarm_node.c). Public hosting default-refuses; every case here
 * is an attempt to get bytes out of a node that should not release them,
 * and every one must be refused BY NAME.
 *
 *   1. Unsigned release: a complete, correctly licensed package with no
 *      envelope is neither announced nor served.
 *   2. Wrong-root signature: an envelope that verifies for one package,
 *      re-pointed at another's bytes, is not that package's release. A
 *      signature-flipped envelope is refused the same way. Both are
 *      planted directly in releases/, so the store's own admission gate
 *      cannot be what does the refusing.
 *   3. License text: a LICENSE path is not license text. "MIT\n", a
 *      one-byte file and genuine Apache-2.0 text under an MIT envelope
 *      are each refused; only real MIT text under an MIT envelope passes.
 *   4. Unknown SPDX: identifiers off the frozen allowlist — and correct
 *      identifiers in the wrong case — cannot become a release at all.
 *   5. Stale envelope: editing one byte of a published package produces a
 *      root the existing envelope does not name. The old release does not
 *      carry forward to the new bytes.
 *   6. Mutated package: a package missing chunks is refused as
 *      incomplete, not served as "mostly there".
 *   7. PERMISSIVE-LICENSE CLOSURE: a valid, signed, correctly licensed
 *      top-level package is refused while any root in its transitive
 *      dependency graph is not itself publicly hostable — absent,
 *      unsigned, mis-licensed, incomplete, or a work object. Work and
 *      blob objects may move between peers, but they can never satisfy a
 *      dependency edge: private transfer and public discovery stay
 *      separate. A dependency cycle terminates instead of spinning.
 *   8. End to end through a real engine: the refused package is not in
 *      the announce sweep and its manifest WANT gets no reply, no
 *      penalty, and no uploaded bytes. Completing the graph flips it to
 *      served without the top package itself changing, and breaking the
 *      graph again flips it back — the verdict cache cannot outlive the
 *      facts it rests on. */

#include "test/test_core.h"

#include "test/public_shape_fixture.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "vcs/package_accept.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_release.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/source_package_transport.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_work_context.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PS_CHECK(name, expr) do {                                            \
    if (expr) { printf("  zcode_public_shape: %s... OK\n", (name)); }        \
    else { printf("  zcode_public_shape: %s... FAIL\n", (name));             \
           failures++; }                                                     \
} while (0)

#define PS_MAX_FILES 6u
#define PS_DAY 20500

/* Apache-2.0's own opening, which contains nothing MIT says. Enough to
 * prove the rule reads the text rather than the filename. */
#define PS_APACHE_HEAD                                                      \
    "                                 Apache License\n"                     \
    "                           Version 2.0, January 2004\n"                \
    "                        http://www.apache.org/licenses/\n"

/* ── fixture package ──────────────────────────────────────────────── */

struct ps_file {
    const char *path;
    const char *bytes;
    size_t len;
};

struct ps_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    struct ps_file files[PS_MAX_FILES];
    size_t count;
};

static void ps_pkg_free(struct ps_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* Build a manifest over exactly these files. Insertion order does not
 * matter: vcs_package_manifest_add inserts in canonical path order. */
static bool ps_pkg_build(struct ps_pkg *p, const struct ps_file *files,
                         size_t count)
{
    memset(p, 0, sizeof(*p));
    if (count == 0 || count > PS_MAX_FILES)
        return false;
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < count; i++) {
        size_t len = files[i].len ? files[i].len : strlen(files[i].bytes);
        uint8_t hash[32];
        if (!vcs_package_chunk_hash((const uint8_t *)files[i].bytes, len,
                                    hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1))
            return false;
        p->files[i] = files[i];
        p->files[i].len = len;
    }
    p->count = count;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire, &p->wire_len))
        return false;
    return vcs_package_manifest_root(&p->manifest, p->root);
}

/* Admit the manifest and, unless `hold_back` names a file, every chunk. */
static bool ps_pkg_store(struct vcs_package_store *store,
                         const struct ps_pkg *p, const char *hold_back)
{
    uint8_t root[32];
    if (vcs_package_store_put_manifest(store, p->wire, p->wire_len, root) !=
            VCS_PACKAGE_STORE_OK ||
        memcmp(root, p->root, 32) != 0)
        return false;
    for (size_t i = 0; i < p->count; i++) {
        if (hold_back && strcmp(p->files[i].path, hold_back) == 0)
            continue;
        if (vcs_package_store_put_chunk(
                store, p->root, p->files[i].path, 0,
                (const uint8_t *)p->files[i].bytes, p->files[i].len) !=
            VCS_PACKAGE_STORE_OK)
            return false;
    }
    return true;
}

/* ── fixture release envelope ─────────────────────────────────────── */

static bool ps_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static void ps_key(uint8_t seed, uint8_t out[33]);

static bool ps_lane_wire(uint8_t seed,
                         uint8_t wire[VCS_ZCODE_LANE_WIRE_BYTES])
{
    struct vcs_zcode_lane_receipt_v1 lane = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .lane = VCS_ZCODE_LANE_PROVEN,
        .created_unix = 1,
    };
    memset(lane.source_root, 0x11, sizeof(lane.source_root));
    memset(lane.task_root, 0x22, sizeof(lane.task_root));
    memset(lane.candidate_root, 0x33, sizeof(lane.candidate_root));
    memset(lane.proof_policy_root, 0x44, sizeof(lane.proof_policy_root));
    memset(lane.proof_set_root, 0x55, sizeof(lane.proof_set_root));
    memset(lane.prior_receipt_root, 0x66, sizeof(lane.prior_receipt_root));
    uint8_t key_seed[32], secret[32], pubkey[32];
    memset(key_seed, seed, sizeof(key_seed));
    ed25519_keypair(pubkey, secret, key_seed);
    bool ok = vcs_zcode_lane_receipt_seal(&lane, secret, pubkey) ==
                  VCS_ZCODE_DEV_OK &&
              vcs_zcode_lane_receipt_serialize(&lane, wire) ==
                  VCS_ZCODE_DEV_OK;
    memset(secret, 0, sizeof(secret));
    return ok;
}

static bool ps_reward_address(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    return encode_destination(&dest, pk, pk_len, sc, sc_len, out, out_size);
}

/* An envelope naming `root`, signed by the key `seed` picks. One key may
 * name only one package root per sequence, so distinct fixtures need
 * distinct seeds and namespaces. */
static bool ps_release_make(const uint8_t root[32], uint8_t seed,
                            const char *name, const char *license,
                            struct vcs_package_release *out)
{
    struct privkey sk;
    struct pubkey pk;
    memset(out, 0, sizeof(*out));
    if (!ps_keypair(seed, &sk, &pk))
        return false;
    out->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(out->name, sizeof(out->name), "%s", name);
    snprintf(out->semver, sizeof(out->semver), "1.0.0");
    memcpy(out->package_root, root, 32);
    for (int i = 0; i < 32; i++)
        out->recipe_root[i] = (uint8_t)(0x50 + i);
    memcpy(out->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    out->publisher_sequence = 1u;
    if (!ps_reward_address(out->reward_address, sizeof(out->reward_address)))
        return false;
    snprintf(out->license, sizeof(out->license), "%s", license);
    if (!vcs_package_accept_chain_id(out->chain_id, sizeof(out->chain_id)))
        return false;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(out, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(out->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool ps_publish(struct vcs_package_store *store, const uint8_t root[32],
                       uint8_t seed, const char *name, const char *license)
{
    struct vcs_package_release r;
    if (!ps_release_make(root, seed, name, license, &r))
        return false;
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    return vcs_package_store_put_release(store, &r, &ar) ==
               VCS_PACKAGE_STORE_OK &&
           (ar == VCS_PACKAGE_ACCEPT_OK || ar == VCS_PACKAGE_ACCEPT_DUPLICATE);
}

/* Write an envelope straight into releases/, bypassing the store's own
 * admission. The classifier must do its own verification. */
static bool ps_plant_envelope(const char *zcode_dir,
                              const struct vcs_package_release *r,
                              const char *stem)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(r, &wire, &wire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    char path[1400];
    snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir, stem);
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(wire, 1, wire_len, f) == wire_len;
    if (f)
        ok = fclose(f) == 0 && ok;
    free(wire);
    return ok;
}

static bool ps_unlink_releases(const char *zcode_dir, const char *stem)
{
    char path[1400];
    snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir, stem);
    return unlink(path) == 0;
}

/* ── the verdict under test ───────────────────────────────────────── */

struct ps_node {
    char datadir[1024];
    char zcode_dir[1100];
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
};

static bool ps_node_open(struct ps_node *n, const char *tag)
{
    memset(n, 0, sizeof(*n));
    test_make_tmpdir(n->datadir, sizeof(n->datadir), "zcode_public_shape",
                     tag);
    snprintf(n->zcode_dir, sizeof(n->zcode_dir), "%s/zcode", n->datadir);
    n->store = vcs_package_store_open(
        n->datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(n->zcode_dir);
    if (!n->store || !n->book)
        return false;
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir, NULL,
                                        NULL);
    return n->engine != NULL;
}

static void ps_node_close(struct ps_node *n)
{
    vcs_swarm_engine_free(n->engine);
    vcs_service_book_free(n->book);
    vcs_package_store_close(n->store);
    n->engine = NULL;
    n->book = NULL;
    n->store = NULL;
}

/* True when classify refuses `root` with exactly this rule. */
static bool ps_refused(struct vcs_package_store *store,
                       const uint8_t root[32], const char *rule)
{
    struct vcs_package_public_verdict v;
    enum vcs_package_public_shape shape =
        vcs_package_public_shape_classify(store, root, &v);
    if (shape != VCS_PACKAGE_PUBLIC_REFUSED)
        printf("    (expected refusal, got %s)\n",
               vcs_package_public_shape_string(shape));
    else if (strcmp(v.rule, rule) != 0)
        printf("    (expected rule %s, got %s)\n", rule, v.rule);
    return shape == VCS_PACKAGE_PUBLIC_REFUSED && strcmp(v.rule, rule) == 0;
}

static bool ps_is_shape(struct vcs_package_store *store,
                        const uint8_t root[32],
                        enum vcs_package_public_shape want)
{
    struct vcs_package_public_verdict v;
    enum vcs_package_public_shape shape =
        vcs_package_public_shape_classify(store, root, &v);
    if (shape != want)
        printf("    (expected %s, got %s: %s)\n",
               vcs_package_public_shape_string(want),
               vcs_package_public_shape_string(shape), v.rule);
    return shape == want;
}

/* ── 1-2. no envelope, and envelopes that do not verify ───────────── */

static int t_ps_release_binding(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "release-binding")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    const struct ps_file good[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/a.c", "int a(void) { return 23; }\n", 0},
    };
    struct ps_pkg a, b;
    PS_CHECK("package a builds", ps_pkg_build(&a, good, 2));
    PS_CHECK("package a stored", ps_pkg_store(n.store, &a, NULL));

    /* 1. Complete and correctly licensed, but nobody signed it. */
    PS_CHECK("unsigned package is refused by name",
             ps_refused(n.store, a.root, "no-verified-release"));

    /* A second package with different bytes, properly published. */
    const struct ps_file other[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/b.c", "int b(void) { return 24; }\n", 0},
    };
    PS_CHECK("package b builds", ps_pkg_build(&b, other, 2));
    PS_CHECK("package b stored", ps_pkg_store(n.store, &b, NULL));
    PS_CHECK("package b published",
             ps_publish(n.store, b.root, 0x21, "psb/fixture", "MIT"));
    PS_CHECK("package b is a public release",
             ps_is_shape(n.store, b.root, VCS_PACKAGE_PUBLIC_RELEASE));

    /* 2a. b's valid envelope, re-pointed at a's bytes after signing. The
     * package_root is inside the signed pre-image, so the id moves and the
     * signature stops verifying. */
    struct vcs_package_release forged;
    PS_CHECK("envelope for b builds",
             ps_release_make(b.root, 0x22, "psforge/fixture", "MIT", &forged));
    memcpy(forged.package_root, a.root, 32);
    PS_CHECK("re-pointed envelope planted",
             ps_plant_envelope(n.zcode_dir, &forged, "forged-root"));
    PS_CHECK("wrong-root signature does not release package a",
             ps_refused(n.store, a.root, "no-verified-release"));
    PS_CHECK("re-pointed envelope removed",
             ps_unlink_releases(n.zcode_dir, "forged-root"));

    /* 2b. Correct root, one flipped signature byte. */
    struct vcs_package_release flipped;
    PS_CHECK("envelope for a builds",
             ps_release_make(a.root, 0x23, "psflip/fixture", "MIT", &flipped));
    flipped.signature[7] ^= 0x01u;
    PS_CHECK("flipped envelope planted",
             ps_plant_envelope(n.zcode_dir, &flipped, "flipped-sig"));
    PS_CHECK("flipped signature does not release package a",
             ps_refused(n.store, a.root, "no-verified-release"));
    PS_CHECK("flipped envelope removed",
             ps_unlink_releases(n.zcode_dir, "flipped-sig"));

    /* The same envelope, unflipped, does release it — so the refusals
     * above were the signature and nothing else. */
    PS_CHECK("package a published",
             ps_publish(n.store, a.root, 0x23, "psflip/fixture", "MIT"));
    PS_CHECK("package a is a public release",
             ps_is_shape(n.store, a.root, VCS_PACKAGE_PUBLIC_RELEASE));

    ps_pkg_free(&a);
    ps_pkg_free(&b);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 3-4. the license is the text, not the filename ───────────────── */

static int t_ps_license_text(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "license-text")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    static const struct {
        const char *what;
        const char *license_bytes; /* NULL: no LICENSE file at all */
        const char *rule;          /* NULL: expected to be hostable */
        uint8_t seed;
        const char *name;
    } cases[] = {
        {"identifier where the text goes", TEST_LICENSE_TEXT_PLACEHOLDER,
         "license-text-mismatch", 0x31, "pslic-a/fixture"},
        {"one byte", "\n", "license-text-mismatch", 0x32, "pslic-b/fixture"},
        {"another license's text", PS_APACHE_HEAD, "license-text-mismatch",
         0x33, "pslic-c/fixture"},
        {"no LICENSE file", NULL, "license-text-missing", 0x34,
         "pslic-d/fixture"},
        {"the real thing", TEST_LICENSE_TEXT_MIT, NULL, 0x35,
         "pslic-e/fixture"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct ps_file files[2];
        size_t count = 0;
        char body[64];
        snprintf(body, sizeof(body), "int f%zu(void) { return %zu; }\n", i, i);
        if (cases[i].license_bytes)
            files[count++] = (struct ps_file){"LICENSE",
                                              cases[i].license_bytes, 0};
        files[count++] = (struct ps_file){"src/a.c", body, 0};
        struct ps_pkg p;
        char label[160];
        snprintf(label, sizeof(label), "%s: stored and published",
                 cases[i].what);
        PS_CHECK(label,
                 ps_pkg_build(&p, files, count) &&
                     ps_pkg_store(n.store, &p, NULL) &&
                     ps_publish(n.store, p.root, cases[i].seed,
                                cases[i].name, "MIT"));
        snprintf(label, sizeof(label), "%s: %s", cases[i].what,
                 cases[i].rule ? cases[i].rule : "hosted");
        PS_CHECK(label,
                 cases[i].rule
                     ? ps_refused(n.store, p.root, cases[i].rule)
                     : ps_is_shape(n.store, p.root,
                                   VCS_PACKAGE_PUBLIC_RELEASE));
        ps_pkg_free(&p);
    }

    /* 4. Off-allowlist and wrong-case identifiers cannot become a release
     * at all, so no package can ever carry one. */
    static const char *const rejected[] = {"GPL-3.0", "Proprietary", "mit",
                                           "APACHE-2.0", "MIT OR Apache-2.0",
                                           ""};
    bool all_rejected = true;
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        struct vcs_package_release r;
        uint8_t root[32];
        memset(root, (int)(0x60 + i), sizeof(root));
        all_rejected = all_rejected &&
                       !ps_release_make(root, 0x40, "psspdx/fixture",
                                        rejected[i], &r) &&
                       !vcs_package_release_license_allowed(rejected[i]) &&
                       !vcs_package_release_license_text_matches(
                           rejected[i], (const uint8_t *)TEST_LICENSE_TEXT_MIT,
                           strlen(TEST_LICENSE_TEXT_MIT));
    }
    PS_CHECK("SPDX identifiers off the frozen allowlist cannot be released",
             all_rejected);

    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* Source carriers do not have a release-envelope SPDX field. Their
 * root-committed LICENSE bytes must therefore match the same frozen
 * permissive policy directly; a valid self-signed lane receipt must not turn
 * proprietary or copyleft source into public swarm content. */
static int t_ps_source_bundle_license(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "source-license")) {
        printf("  zcode_public_shape: source-license node open... FAIL\n");
        return 1;
    }

    uint8_t lane_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    size_t marker_len = 0;
    const uint8_t *marker =
        vcs_source_package_transport_marker(&marker_len);
    PS_CHECK("source bundle: valid PROVEN lane fixture",
             ps_lane_wire(0x91, lane_wire));

    static const struct {
        const char *name;
        const char *text;
    } refused[] = {
        {"GPL", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"},
        {"proprietary", "Copyright 2026. All rights reserved.\n"},
        {"placeholder", "MIT\n"},
    };
    uint8_t refused_root[32] = {0};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        const struct ps_file files[] = {
            {VCS_SOURCE_PACKAGE_LICENSE_PATH, refused[i].text, 0},
            {VCS_SOURCE_PACKAGE_AUTHORITY_PATH, "authority", 0},
            {VCS_SOURCE_PACKAGE_LANE_PATH, (const char *)lane_wire,
             sizeof(lane_wire)},
            {VCS_SOURCE_PACKAGE_MARKER_PATH, (const char *)marker, marker_len},
        };
        struct ps_pkg p;
        char label[160];
        bool stored = ps_pkg_build(&p, files, 4) &&
                      ps_pkg_store(n.store, &p, NULL);
        if (i == 0 && stored)
            memcpy(refused_root, p.root, sizeof(refused_root));
        snprintf(label, sizeof(label),
                 "source bundle: %s LICENSE is refused by name",
                 refused[i].name);
        PS_CHECK(label, stored && ps_refused(
            n.store, p.root, "license-text-not-allowlisted"));
        ps_pkg_free(&p);
    }

    uint8_t key[33];
    ps_key(0x19, key);
    const uint64_t peer = 9019u;
    PS_CHECK("source bundle: engine peer added",
             vcs_swarm_engine_peer_add(n.engine, peer, key));
    PS_CHECK("source bundle: refused roots are absent from ANNOUNCE",
             vcs_swarm_engine_announce_to(n.engine, peer) == 0);

    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    memcpy(want.body.want.package_root, refused_root, sizeof(refused_root));
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    want.body.want.request_id = 0x616161u;
    uint8_t frame[256];
    size_t frame_len = 0;
    PS_CHECK("source bundle: refused WANT serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &frame_len));
    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, frame_len, PS_DAY, 1);
    PS_CHECK("source bundle: refused WANT yields no bytes and no peer penalty",
             res.reply == NULL && !res.disconnect_peer &&
                 res.penalty == VCS_SWARM_PENALTY_NONE && res.rule &&
                 strcmp(res.rule, "license-text-not-allowlisted") == 0);
    free(res.reply);

    const struct ps_file allowed_files[] = {
        {VCS_SOURCE_PACKAGE_LICENSE_PATH, TEST_LICENSE_TEXT_MIT, 0},
        {VCS_SOURCE_PACKAGE_AUTHORITY_PATH, "authority", 0},
        {VCS_SOURCE_PACKAGE_LANE_PATH, (const char *)lane_wire,
         sizeof(lane_wire)},
        {VCS_SOURCE_PACKAGE_MARKER_PATH, (const char *)marker, marker_len},
    };
    struct ps_pkg allowed;
    PS_CHECK("source bundle: allowlisted MIT carrier remains public",
             ps_pkg_build(&allowed, allowed_files, 4) &&
                 ps_pkg_store(n.store, &allowed, NULL) &&
                 ps_is_shape(n.store, allowed.root,
                             VCS_PACKAGE_PUBLIC_SOURCE_BUNDLE));
    PS_CHECK("source bundle: allowlisted carrier reaches ANNOUNCE",
             vcs_swarm_engine_announce_to(n.engine, peer) >= 1);
    ps_pkg_free(&allowed);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 5-6. stale envelopes and mutated packages ────────────────────── */

static int t_ps_stale_and_mutated(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "stale-mutated")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    const struct ps_file v1[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/a.c", "int a(void) { return 23; }\n", 0},
    };
    struct ps_pkg p1;
    PS_CHECK("v1 stored and published",
             ps_pkg_build(&p1, v1, 2) && ps_pkg_store(n.store, &p1, NULL) &&
                 ps_publish(n.store, p1.root, 0x51, "psstale/fixture", "MIT"));
    PS_CHECK("v1 is hostable",
             ps_is_shape(n.store, p1.root, VCS_PACKAGE_PUBLIC_RELEASE));

    /* 5. One edited byte is a different package. The publisher's existing
     * envelope names v1's root and says nothing about these bytes. */
    const struct ps_file v2[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/a.c", "int a(void) { return 24; }\n", 0},
    };
    struct ps_pkg p2;
    PS_CHECK("v2 builds to a different root",
             ps_pkg_build(&p2, v2, 2) && memcmp(p1.root, p2.root, 32) != 0);
    PS_CHECK("edited bytes are not tracked at all",
             ps_refused(n.store, p2.root, "not-tracked"));
    PS_CHECK("v2 stored", ps_pkg_store(n.store, &p2, NULL));
    PS_CHECK("the v1 envelope does not carry forward to v2",
             ps_refused(n.store, p2.root, "no-verified-release"));

    /* 6. Held back one chunk: incomplete, and refused as incomplete rather
     * than served as far as it goes. */
    const struct ps_file v3[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/a.c", "int a(void) { return 25; }\n", 0},
    };
    struct ps_pkg p3;
    PS_CHECK("v3 stored without one chunk",
             ps_pkg_build(&p3, v3, 2) &&
                 ps_pkg_store(n.store, &p3, "src/a.c") &&
                 ps_publish(n.store, p3.root, 0x52, "pspart/fixture", "MIT"));
    PS_CHECK("an incomplete package is refused as incomplete",
             ps_refused(n.store, p3.root, "package-incomplete"));
    PS_CHECK("the missing chunk arrives",
             vcs_package_store_put_chunk(
                 n.store, p3.root, "src/a.c", 0,
                 (const uint8_t *)v3[1].bytes, strlen(v3[1].bytes)) ==
                 VCS_PACKAGE_STORE_OK);
    PS_CHECK("completing the package makes it hostable",
             ps_is_shape(n.store, p3.root, VCS_PACKAGE_PUBLIC_RELEASE));

    ps_pkg_free(&p1);
    ps_pkg_free(&p2);
    ps_pkg_free(&p3);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 7. permissive-license closure ────────────────────────────────── */

/* A zcode-package.json declaring exactly these dependency roots. */
static void ps_deps_json(char *out, size_t cap, const uint8_t *const roots[],
                         size_t count)
{
    size_t used = (size_t)snprintf(out, cap,
                                   "{\"schema\":1,\"dependencies\":[");
    for (size_t i = 0; i < count; i++) {
        char hex[65];
        zcl_hex_encode(roots[i], 32, hex);
        used += (size_t)snprintf(out + used, cap - used, "%s{\"root\":\"%s\"}",
                                 i ? "," : "", hex);
    }
    snprintf(out + used, cap - used, "]}");
}

static int t_ps_dependency_closure(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "closure")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    /* The dependency, built first so the top package can name its root. */
    const struct ps_file dep_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/d.c", "int d(void) { return 1; }\n", 0},
    };
    struct ps_pkg dep;
    PS_CHECK("dependency builds", ps_pkg_build(&dep, dep_files, 2));

    const uint8_t *dep_roots[1] = {dep.root};
    char top_json[512];
    ps_deps_json(top_json, sizeof(top_json), dep_roots, 1);
    const struct ps_file top_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/t.c", "int t(void) { return 2; }\n", 0},
        {"zcode-package.json", top_json, 0},
    };
    struct ps_pkg top;
    PS_CHECK("top package stored and published",
             ps_pkg_build(&top, top_files, 3) &&
                 ps_pkg_store(n.store, &top, NULL) &&
                 ps_publish(n.store, top.root, 0x61, "pstop/fixture", "MIT"));

    /* The top package is itself flawless. It is refused anyway, because a
     * stranger cannot reproduce what this node cannot hand over. */
    struct vcs_package_public_verdict v;
    vcs_package_public_shape_classify(n.store, top.root, &v);
    PS_CHECK("a package whose dependency is absent is refused",
             v.shape == VCS_PACKAGE_PUBLIC_REFUSED &&
                 strcmp(v.rule, "dependency-not-public") == 0);
    PS_CHECK("the refusal is marked as resting on other packages",
             v.dep_scoped);
    PS_CHECK("the peer-facing rule hides which byte is missing",
             v.dependency_rule && strcmp(v.dependency_rule, "not-tracked") == 0);

    /* Present but unsigned: still not something a stranger could rebuild. */
    PS_CHECK("dependency stored", ps_pkg_store(n.store, &dep, NULL));
    vcs_package_public_shape_classify(n.store, top.root, &v);
    PS_CHECK("an unsigned dependency still refuses the dependent",
             v.shape == VCS_PACKAGE_PUBLIC_REFUSED &&
                 v.dependency_rule &&
                 strcmp(v.dependency_rule, "no-verified-release") == 0);

    /* Signed: the graph closes. */
    PS_CHECK("dependency published",
             ps_publish(n.store, dep.root, 0x62, "psdep/fixture", "MIT"));
    vcs_package_public_shape_classify(n.store, top.root, &v);
    PS_CHECK("a fully public graph is hostable",
             v.shape == VCS_PACKAGE_PUBLIC_RELEASE &&
                 v.dependencies_checked == 1u && v.dep_scoped);

    /* A work object is fetchable between peers that already accepted each
     * other's signed work — and is still not a licensed shape, so it can
     * never stand in for a dependency. */
    const char work_action[] =
        "{\"schema\":\"zcode-work-context.v1\",\"action\":\"build\"}\n";
    const struct ps_file work_files[] = {
        {VCS_ZCODE_WORK_CONTEXT_PATH, work_action, 0},
    };
    struct ps_pkg work;
    PS_CHECK("work object stored",
             ps_pkg_build(&work, work_files, 1) &&
                 ps_pkg_store(n.store, &work, NULL));
    PS_CHECK("a work object moves between peers on its own terms",
             ps_is_shape(n.store, work.root, VCS_PACKAGE_PUBLIC_WORK_CONTEXT));

    const uint8_t *work_roots[1] = {work.root};
    char work_json[512];
    ps_deps_json(work_json, sizeof(work_json), work_roots, 1);
    const struct ps_file wdep_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/w.c", "int w(void) { return 3; }\n", 0},
        {"zcode-package.json", work_json, 0},
    };
    struct ps_pkg wdep;
    PS_CHECK("package depending on a work object stored and published",
             ps_pkg_build(&wdep, wdep_files, 3) &&
                 ps_pkg_store(n.store, &wdep, NULL) &&
                 ps_publish(n.store, wdep.root, 0x63, "pswork/fixture",
                            "MIT"));
    vcs_package_public_shape_classify(n.store, wdep.root, &v);
    PS_CHECK("a work object cannot satisfy a dependency edge",
             v.shape == VCS_PACKAGE_PUBLIC_REFUSED &&
                 strcmp(v.rule, "dependency-not-public") == 0 &&
                 v.dependency_rule &&
                 strcmp(v.dependency_rule, "work-context") == 0);

    /* Transitive: the dependency's own dependency is absent. */
    uint8_t ghost[32];
    memset(ghost, 0x7e, sizeof(ghost));
    const uint8_t *ghost_roots[1] = {ghost};
    char mid_json[512];
    ps_deps_json(mid_json, sizeof(mid_json), ghost_roots, 1);
    const struct ps_file mid_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/m.c", "int m(void) { return 4; }\n", 0},
        {"zcode-package.json", mid_json, 0},
    };
    struct ps_pkg mid;
    PS_CHECK("middle package stored and published",
             ps_pkg_build(&mid, mid_files, 3) &&
                 ps_pkg_store(n.store, &mid, NULL) &&
                 ps_publish(n.store, mid.root, 0x64, "psmid/fixture", "MIT"));
    PS_CHECK("the middle package is itself refused",
             ps_refused(n.store, mid.root, "dependency-not-public"));

    const uint8_t *mid_roots[1] = {mid.root};
    char head_json[512];
    ps_deps_json(head_json, sizeof(head_json), mid_roots, 1);
    const struct ps_file head_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/h.c", "int h(void) { return 5; }\n", 0},
        {"zcode-package.json", head_json, 0},
    };
    struct ps_pkg head;
    PS_CHECK("head package stored and published",
             ps_pkg_build(&head, head_files, 3) &&
                 ps_pkg_store(n.store, &head, NULL) &&
                 ps_publish(n.store, head.root, 0x65, "pshead/fixture",
                            "MIT"));
    PS_CHECK("a hole two levels down still refuses the top",
             ps_refused(n.store, head.root, "dependency-not-public"));

    /* A mis-licensed dependency is refused for its own reason, reported to
     * the operator and not to the peer. */
    const struct ps_file fake_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_PLACEHOLDER, 0},
        {"src/f.c", "int f(void) { return 6; }\n", 0},
    };
    struct ps_pkg fake;
    PS_CHECK("mis-licensed dependency stored and published",
             ps_pkg_build(&fake, fake_files, 2) &&
                 ps_pkg_store(n.store, &fake, NULL) &&
                 ps_publish(n.store, fake.root, 0x66, "psfake/fixture",
                            "MIT"));
    const uint8_t *fake_roots[1] = {fake.root};
    char fdep_json[512];
    ps_deps_json(fdep_json, sizeof(fdep_json), fake_roots, 1);
    const struct ps_file fdep_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/g.c", "int g(void) { return 7; }\n", 0},
        {"zcode-package.json", fdep_json, 0},
    };
    struct ps_pkg fdep;
    PS_CHECK("dependent on the mis-licensed package stored and published",
             ps_pkg_build(&fdep, fdep_files, 3) &&
                 ps_pkg_store(n.store, &fdep, NULL) &&
                 ps_publish(n.store, fdep.root, 0x67, "psfdep/fixture",
                            "MIT"));
    vcs_package_public_shape_classify(n.store, fdep.root, &v);
    PS_CHECK("a mis-licensed dependency refuses the dependent",
             v.shape == VCS_PACKAGE_PUBLIC_REFUSED &&
                 v.dependency_rule &&
                 strcmp(v.dependency_rule, "license-text-mismatch") == 0);

    ps_pkg_free(&dep);
    ps_pkg_free(&top);
    ps_pkg_free(&work);
    ps_pkg_free(&wdep);
    ps_pkg_free(&mid);
    ps_pkg_free(&head);
    ps_pkg_free(&fake);
    ps_pkg_free(&fdep);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* A dependency cycle must terminate, not spin. Built in its own store so
 * the two roots can reference each other: each package's json is written
 * with the OTHER's root, which is only possible because the second
 * package's root is computed from bytes that already name the first. So
 * the cycle here is A -> B -> A, closed by giving B a declaration naming a
 * root that B itself is not. */
static int t_ps_dependency_cycle(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "cycle")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    /* B first, declaring a dependency on a placeholder root. */
    uint8_t placeholder[32];
    memset(placeholder, 0x11, sizeof(placeholder));
    const uint8_t *ph[1] = {placeholder};
    char b_json[512];
    ps_deps_json(b_json, sizeof(b_json), ph, 1);
    const struct ps_file b_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/b.c", "int b(void) { return 1; }\n", 0},
        {"zcode-package.json", b_json, 0},
    };
    struct ps_pkg b;
    PS_CHECK("cycle: b stored and published",
             ps_pkg_build(&b, b_files, 3) && ps_pkg_store(n.store, &b, NULL) &&
                 ps_publish(n.store, b.root, 0x71, "pscycb/fixture", "MIT"));

    /* A depends on B, and B depends on the placeholder — so the walk has
     * two distinct roots plus one it can never resolve. It must stop. */
    const uint8_t *b_roots[1] = {b.root};
    char a_json[512];
    ps_deps_json(a_json, sizeof(a_json), b_roots, 1);
    const struct ps_file a_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/a.c", "int a(void) { return 2; }\n", 0},
        {"zcode-package.json", a_json, 0},
    };
    struct ps_pkg a;
    PS_CHECK("cycle: a stored and published",
             ps_pkg_build(&a, a_files, 3) && ps_pkg_store(n.store, &a, NULL) &&
                 ps_publish(n.store, a.root, 0x72, "pscyca/fixture", "MIT"));
    PS_CHECK("an unresolvable root deep in the graph terminates in a refusal",
             ps_refused(n.store, a.root, "dependency-not-public"));

    /* Self-reference is rejected by the declaration grammar itself, so it
     * can never reach the walk. */
    const uint8_t *self[1] = {a.root};
    char self_json[512];
    ps_deps_json(self_json, sizeof(self_json), self, 1);
    struct vcs_package_deps parsed;
    PS_CHECK("a declaration is still well-formed JSON either way",
             vcs_package_deps_parse_meta((const uint8_t *)self_json,
                                         strlen(self_json), &parsed, NULL,
                                         0) == VCS_PACKAGE_DEPS_OK);

    ps_pkg_free(&a);
    ps_pkg_free(&b);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

/* ── 8. the same rule, through a real engine ──────────────────────── */

static void ps_key(uint8_t seed, uint8_t out[33])
{
    memset(out, 0, 33);
    out[0] = 0x02;
    out[32] = seed;
    out[1] = (uint8_t)(seed ^ 0x5a);
}

static int t_ps_engine_refuses(void)
{
    int failures = 0;
    struct ps_node n;
    if (!ps_node_open(&n, "engine")) {
        printf("  zcode_public_shape: node open... FAIL\n");
        return 1;
    }
    const struct ps_file dep_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/d.c", "int d(void) { return 1; }\n", 0},
    };
    struct ps_pkg dep;
    PS_CHECK("engine: dependency builds", ps_pkg_build(&dep, dep_files, 2));

    const uint8_t *dep_roots[1] = {dep.root};
    char json[512];
    ps_deps_json(json, sizeof(json), dep_roots, 1);
    const struct ps_file top_files[] = {
        {"LICENSE", TEST_LICENSE_TEXT_MIT, 0},
        {"src/t.c", "int t(void) { return 2; }\n", 0},
        {"zcode-package.json", json, 0},
    };
    struct ps_pkg top;
    PS_CHECK("engine: top stored and published",
             ps_pkg_build(&top, top_files, 3) &&
                 ps_pkg_store(n.store, &top, NULL) &&
                 ps_publish(n.store, top.root, 0x81, "psengine/fixture",
                            "MIT"));

    uint8_t key[33];
    ps_key(0x09, key);
    const uint64_t peer = 9009u;
    PS_CHECK("engine: peer added",
             vcs_swarm_engine_peer_add(n.engine, peer, key));

    /* The dependency is missing, so nothing is offered. */
    PS_CHECK("a package with an open dependency is not announced",
             vcs_swarm_engine_announce_to(n.engine, peer) == 0);

    struct vcs_package_swarm_message want;
    memset(&want, 0, sizeof(want));
    want.type = VCS_PACKAGE_SWARM_WANT;
    memcpy(want.body.want.package_root, top.root, 32);
    want.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    want.body.want.file_index = UINT32_MAX;
    want.body.want.chunk_index = UINT32_MAX;
    want.body.want.request_id = 0x515151u;
    uint8_t frame[256];
    size_t frame_len = 0;
    PS_CHECK("engine: want frame serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &frame_len));

    struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
        n.engine, peer, frame, frame_len, PS_DAY, 1);
    PS_CHECK("a WANT for it is answered with nothing, and no punishment",
             res.reply == NULL && !res.disconnect_peer &&
                 res.penalty == VCS_SWARM_PENALTY_NONE && res.rule != NULL &&
                 strcmp(res.rule, "dependency-not-public") == 0);
    free(res.reply);

    /* Completing the graph flips the verdict, though the top package's own
     * bytes never changed — the cache keys on the whole store for a
     * verdict that rests on the whole store. */
    PS_CHECK("engine: dependency stored and published",
             ps_pkg_store(n.store, &dep, NULL) &&
                 ps_publish(n.store, dep.root, 0x82, "psengdep/fixture",
                            "MIT"));
    PS_CHECK("closing the graph puts it back in the announce sweep",
             vcs_swarm_engine_announce_to(n.engine, peer) >= 1);

    want.body.want.request_id = 0x515152u;
    PS_CHECK("engine: second want frame serializes",
             vcs_package_swarm_serialize(&want, frame, sizeof(frame),
                                         &frame_len));
    res = vcs_swarm_engine_handle_frame(n.engine, peer, frame, frame_len,
                                        PS_DAY, 2);
    PS_CHECK("and the manifest is served", res.reply != NULL);
    free(res.reply);

    ps_pkg_free(&dep);
    ps_pkg_free(&top);
    ps_node_close(&n);
    test_rm_rf_recursive(n.datadir);
    return failures;
}

int test_zcode_public_shape(void)
{
    int failures = 0;
    failures += t_ps_release_binding();
    failures += t_ps_license_text();
    failures += t_ps_source_bundle_license();
    failures += t_ps_stale_and_mutated();
    failures += t_ps_dependency_closure();
    failures += t_ps_dependency_cycle();
    failures += t_ps_engine_refuses();
    return failures;
}
