/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_vcs_release — the signed ZCODE package release envelope gate
 * (contexts/commons/modules/vcs/package_release.*).
 *
 * Coverage:
 *   1. Golden KAT: a fixed release under a fixed test key commits to a
 *      frozen release id (domain "zcl.zcode_release.v1\0").
 *   2. Round-trip serialize -> parse -> reserialize fixed point.
 *   3. Signature verification: passes for the publisher key; fails for a
 *      wrong key, a corrupted signature, a high-S (malleated) signature,
 *      and every single-field mutation.
 *   4. Field grammars: SPDX allowlist, publisher/package name form,
 *      strict semver 2.0.0, reward/chain-id charsets, bounds.
 *   5. Wire strictness: magic, oversize, truncation, trailing bytes,
 *      presence flags, embedded NUL.
 *   6. Codec-level duplicate detection (publisher+sequence+root) and the
 *      parent-lineage presence helper.
 *
 * Pure codec: no filesystem, no wallet; signing uses two fixed test
 * private keys through the contexts/wallet/modules/keys primitives only. */

#include "test/test_core.h"

#include "vcs/package_release.h"

#include "keys/key.h"
#include "keys/pubkey.h"
#include "core/uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VR_CHECK(name, expr) do {                                     \
    if (expr) { printf("  vcs_release: %s... OK\n", (name)); }        \
    else { printf("  vcs_release: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* secp256k1 group order n, big-endian (for the high-S malleation test). */
static const uint8_t vr_group_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

static void vr_hex32(const uint8_t in[32], char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

static bool vr_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

/* Sign the release id in place with the given key (RFC6979, low-S, compact
 * r||s — privkey_sign_compact's bytes 1..65). */
static bool vr_sign(struct vcs_package_release *r, struct privkey *sk)
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

/* A fully populated, valid, signed release under the seed'd test key. */
static bool vr_fixture(struct vcs_package_release *r, uint8_t key_seed)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!vr_keypair(key_seed, &sk, &pk))
        return false;

    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "rhett/ring-buffer");
    snprintf(r->semver, sizeof(r->semver), "1.4.2");
    for (int i = 0; i < 32; i++) {
        r->package_root[i] = (uint8_t)i;
        r->parent_root[i]  = (uint8_t)(0x20 + i);
        r->recipe_root[i]  = (uint8_t)(0x40 + i);
    }
    r->has_parent = true;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = 7;
    snprintf(r->reward_address, sizeof(r->reward_address), "%s",
             "t1ZclassicRewardAddress9x");
    snprintf(r->license, sizeof(r->license), "Apache-2.0");
    r->has_znam = true;
    snprintf(r->znam, sizeof(r->znam), "ring-buffer");
    snprintf(r->chain_id, sizeof(r->chain_id), "zclassic-main");
    return vr_sign(r, &sk);
}

/* Offset of the parent-presence flag byte in the canonical wire for a
 * release with this fixture's name/semver lengths. */
static size_t vr_parent_flag_offset(const struct vcs_package_release *r)
{
    return VCS_PACKAGE_RELEASE_WIRE_MAGIC_BYTES + 2u +
           2u + strlen(r->name) + 2u + strlen(r->semver) + 32u;
}

/* Offset of the znam-presence flag byte (parent present in the fixture). */
static size_t vr_znam_flag_offset(const struct vcs_package_release *r)
{
    return vr_parent_flag_offset(r) + 1u + 32u +
           VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 8u +
           2u + strlen(r->reward_address) + 2u + strlen(r->license) +
           32u;
}

/* ── 1/2/3: KAT, round-trip, signature acceptance ─────────────────── */
static int t_release_kat_roundtrip_verify(void)
{
    int failures = 0;
    struct vcs_package_release r;
    VR_CHECK("release: fixture builds + signs", vr_fixture(&r, 0x11));

    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    VR_CHECK("release: id computes",
             vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK);
    char id_hex[65];
    vr_hex32(id, id_hex);
    printf("  vcs_release: KAT release id = %s\n", id_hex);
    /* Frozen golden: fields of vr_fixture() under test key 0x11.... */
    static const char *want_id_hex =
        "9f91360a486a1291533cad369861c371d4b5bc0682748ee768755c730f574eba";
    VR_CHECK("release: release id KAT", strcmp(id_hex, want_id_hex) == 0);

    VR_CHECK("release: valid envelope verifies",
             vcs_package_release_verify(&r) == VCS_PACKAGE_RELEASE_OK);

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    VR_CHECK("release: canonical serialize",
             vcs_package_release_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RELEASE_OK);
    VR_CHECK("release: bounded wire produced",
             wire && wire_len <= VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES);

    struct vcs_package_release parsed;
    VR_CHECK("release: canonical parse",
             vcs_package_release_parse(wire, wire_len, &parsed) ==
                 VCS_PACKAGE_RELEASE_OK);
    VR_CHECK("release: parsed fields round-trip",
             parsed.schema_version == r.schema_version &&
             strcmp(parsed.name, r.name) == 0 &&
             strcmp(parsed.semver, r.semver) == 0 &&
             memcmp(parsed.package_root, r.package_root, 32) == 0 &&
             parsed.has_parent == r.has_parent &&
             memcmp(parsed.parent_root, r.parent_root, 32) == 0 &&
             memcmp(parsed.publisher_pubkey, r.publisher_pubkey,
                    VCS_PACKAGE_RELEASE_PUBKEY_BYTES) == 0 &&
             parsed.publisher_sequence == r.publisher_sequence &&
             strcmp(parsed.reward_address, r.reward_address) == 0 &&
             strcmp(parsed.license, r.license) == 0 &&
             memcmp(parsed.recipe_root, r.recipe_root, 32) == 0 &&
             parsed.has_znam == r.has_znam &&
             strcmp(parsed.znam, r.znam) == 0 &&
             strcmp(parsed.chain_id, r.chain_id) == 0 &&
             memcmp(parsed.signature, r.signature,
                    VCS_PACKAGE_RELEASE_SIGNATURE_BYTES) == 0);

    uint8_t *wire2 = NULL;
    size_t wire2_len = 0;
    VR_CHECK("release: reserialize",
             vcs_package_release_serialize(&parsed, &wire2, &wire2_len) ==
                 VCS_PACKAGE_RELEASE_OK);
    VR_CHECK("release: serialization fixed point",
             wire_len == wire2_len && memcmp(wire, wire2, wire_len) == 0);

    /* The receive path: parse from wire, then verify. */
    VR_CHECK("release: parsed envelope verifies",
             vcs_package_release_verify(&parsed) == VCS_PACKAGE_RELEASE_OK);

    /* The signature the fixture produced is itself low-S canonical (the
     * top bit of s is clear whenever s <= n/2 < 2^255). */
    VR_CHECK("release: fixture signature is low-S",
             (r.signature[32] & 0x80u) == 0);

    /* Optional absence encoding: no parent, no znam. */
    struct vcs_package_release root_release = r;
    root_release.has_parent = false;
    memset(root_release.parent_root, 0, 32);
    root_release.has_znam = false;
    root_release.znam[0] = '\0';
    struct privkey sk;
    struct pubkey pk;
    VR_CHECK("release: root fixture key", vr_keypair(0x11, &sk, &pk));
    VR_CHECK("release: root release re-signs", vr_sign(&root_release, &sk));
    VR_CHECK("release: root release verifies",
             vcs_package_release_verify(&root_release) ==
                 VCS_PACKAGE_RELEASE_OK);
    uint8_t *root_wire = NULL;
    size_t root_wire_len = 0;
    struct vcs_package_release root_parsed;
    VR_CHECK("release: root release wire round-trip",
             vcs_package_release_serialize(&root_release, &root_wire,
                                           &root_wire_len) ==
                 VCS_PACKAGE_RELEASE_OK &&
             vcs_package_release_parse(root_wire, root_wire_len,
                                       &root_parsed) ==
                 VCS_PACKAGE_RELEASE_OK &&
             !root_parsed.has_parent && !root_parsed.has_znam &&
             vcs_package_release_verify(&root_parsed) ==
                 VCS_PACKAGE_RELEASE_OK);
    VR_CHECK("release: absent optional fields shrink the wire",
             root_wire_len < wire_len);

    free(root_wire);
    free(wire2);
    free(wire);
    return failures;
}

/* ── 3b: signature rejection matrix ───────────────────────────────── */
static int t_release_signature_rejections(void)
{
    int failures = 0;
    struct vcs_package_release base;
    VR_CHECK("sig: fixture", vr_fixture(&base, 0x11));

    struct privkey sk2;
    struct pubkey pk2;
    VR_CHECK("sig: second key", vr_keypair(0x22, &sk2, &pk2));

    /* Valid signature over the same release id, but from the WRONG key. */
    struct vcs_package_release r = base;
    VR_CHECK("sig: wrong-key signing", vr_sign(&r, &sk2));
    VR_CHECK("sig: wrong key rejected",
             vcs_package_release_verify(&r) ==
                 VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY);

    /* Embedded publisher pubkey swapped out from under a valid signature. */
    r = base;
    memcpy(r.publisher_pubkey, pk2.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    VR_CHECK("sig: swapped pubkey rejected",
             vcs_package_release_verify(&r) ==
                 VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY);

    /* Corrupted signature byte. */
    r = base;
    r.signature[0] ^= 0x01u;
    VR_CHECK("sig: corrupted r rejected",
             vcs_package_release_verify(&r) ==
                 VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY);

    /* High-S malleation: s' = n - s is the same mathematical signature in
     * non-canonical form; it must name the low-S rule, not just "bad sig". */
    r = base;
    uint8_t borrow = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t d = (uint16_t)vr_group_order[i] - r.signature[32 + i] -
                     borrow;
        r.signature[32 + i] = (uint8_t)(d & 0xffu);
        borrow = (uint16_t)(d >> 8) & 1u;
    }
    VR_CHECK("sig: high-S malleation rejected as low-S violation",
             vcs_package_release_verify(&r) ==
                 VCS_PACKAGE_RELEASE_ERR_SIG_LOW_S);

    /* Every single-field mutation invalidates the signature. */
    struct {
        const char *name;
        enum vcs_package_release_error want;
    } cases[] = {
        { "name", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "semver", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "package root", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "parent root", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "parent presence", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "sequence", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "reward", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "license", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "recipe root", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "znam", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "znam presence", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
        { "chain id", VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        r = base;
        char label[96];
        snprintf(label, sizeof(label), "sig: mutated %s rejected",
                 cases[i].name);
        if (strcmp(cases[i].name, "name") == 0)
            snprintf(r.name, sizeof(r.name), "rhett/other");
        else if (strcmp(cases[i].name, "semver") == 0)
            snprintf(r.semver, sizeof(r.semver), "1.4.3");
        else if (strcmp(cases[i].name, "package root") == 0)
            r.package_root[0] ^= 0x01u;
        else if (strcmp(cases[i].name, "parent root") == 0)
            r.parent_root[0] ^= 0x01u;
        else if (strcmp(cases[i].name, "parent presence") == 0)
            r.has_parent = false;
        else if (strcmp(cases[i].name, "sequence") == 0)
            r.publisher_sequence = 8;
        else if (strcmp(cases[i].name, "reward") == 0)
            snprintf(r.reward_address, sizeof(r.reward_address), "%s",
                     "t1OtherReward");
        else if (strcmp(cases[i].name, "license") == 0)
            snprintf(r.license, sizeof(r.license), "MIT");
        else if (strcmp(cases[i].name, "recipe root") == 0)
            r.recipe_root[0] ^= 0x01u;
        else if (strcmp(cases[i].name, "znam") == 0)
            snprintf(r.znam, sizeof(r.znam), "other-name");
        else if (strcmp(cases[i].name, "znam presence") == 0)
            r.has_znam = false;
        else if (strcmp(cases[i].name, "chain id") == 0)
            snprintf(r.chain_id, sizeof(r.chain_id), "zclassic-test");
        VR_CHECK(label, vcs_package_release_verify(&r) == cases[i].want);
    }
    return failures;
}

/* ── 4: field grammars ────────────────────────────────────────────── */
static int t_release_field_grammars(void)
{
    int failures = 0;
    struct vcs_package_release r;
    VR_CHECK("grammar: fixture", vr_fixture(&r, 0x11));

    /* package name form */
    const char *bad_names[] = {
        "noslash", "a/b/c", "/leadingslash", "rhett/", "Rhett/ring-buffer",
        "rhett/Ring-Buffer", "-rhett/x", "rhett-/x", "rhett/-x", "rhett/x-",
        "rhett/x y", "rhett/x_y", "rhett//x", "",
    };
    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        struct vcs_package_release m = r;
        snprintf(m.name, sizeof(m.name), "%s", bad_names[i]);
        VR_CHECK("grammar: bad package name rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_NAME);
    }
    char overlong[VCS_PACKAGE_RELEASE_NAME_MAX + 2];
    memset(overlong, 0, sizeof(overlong));
    memset(overlong, 'a', VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u);
    overlong[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u] = '/';
    overlong[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 2u] = 'x';
    overlong[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 3u] = '\0';
    {
        struct vcs_package_release m = r;
        memcpy(m.name, overlong, sizeof(overlong));
        VR_CHECK("grammar: overlong name half rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_NAME);
    }
    {
        struct vcs_package_release m = r;
        snprintf(m.name, sizeof(m.name), "%s", "a1/0z");
        VR_CHECK("grammar: minimal valid name accepted",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
    }

    /* semver 2.0.0 */
    const char *bad_semvers[] = {
        "1.0", "1.0.0.", "v1.0.0", "1.02.0", "01.0.0", "1.0.0-",
        "1.0.0+", "1.0.0-01", "1.0.0-alpha..1", "1.0.0-a_b", "1.0.0.0",
        "1", "", "1.0.0-+x",
    };
    for (size_t i = 0; i < sizeof(bad_semvers) / sizeof(bad_semvers[0]); i++) {
        struct vcs_package_release m = r;
        snprintf(m.semver, sizeof(m.semver), "%s", bad_semvers[i]);
        VR_CHECK("grammar: bad semver rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_SEMVER);
    }
    const char *good_semvers[] = {
        "0.0.0", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7",
        "1.0.0-x-y-z.-", "1.0.0+build.01", "1.0.0-rc.1+build.7",
        "1.4.2",
    };
    for (size_t i = 0; i < sizeof(good_semvers) / sizeof(good_semvers[0]);
         i++) {
        struct vcs_package_release m = r;
        snprintf(m.semver, sizeof(m.semver), "%s", good_semvers[i]);
        VR_CHECK("grammar: valid semver accepted",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
    }

    /* SPDX license allowlist — exact, no compounds, no unknowns. */
    const char *bad_licenses[] = {
        "MIT OR Apache-2.0", "GPL-3.0", "", "mit", "MIT ",
        "Apache-2.0 OR MIT", "BSD-4-Clause", "Unlicense",
    };
    for (size_t i = 0; i < sizeof(bad_licenses) / sizeof(bad_licenses[0]);
         i++) {
        struct vcs_package_release m = r;
        snprintf(m.license, sizeof(m.license), "%s", bad_licenses[i]);
        VR_CHECK("grammar: non-allowlisted license rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_LICENSE);
    }
    const char *good_licenses[] = {
        "0BSD", "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "Zlib",
    };
    for (size_t i = 0; i < sizeof(good_licenses) / sizeof(good_licenses[0]);
         i++) {
        struct vcs_package_release m = r;
        snprintf(m.license, sizeof(m.license), "%s", good_licenses[i]);
        VR_CHECK("grammar: allowlisted license accepted",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
    }

    /* reward address charset/bound */
    {
        struct vcs_package_release m = r;
        snprintf(m.reward_address, sizeof(m.reward_address), "%s",
                 "has space");
        VR_CHECK("grammar: reward space rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_REWARD);
        snprintf(m.reward_address, sizeof(m.reward_address), "%s", "");
        VR_CHECK("grammar: empty reward (none) accepted",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
    }

    /* chain id charset/bound */
    {
        struct vcs_package_release m = r;
        snprintf(m.chain_id, sizeof(m.chain_id), "%s", "ZClassic");
        VR_CHECK("grammar: uppercase chain id rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_CHAIN_ID);
        m.chain_id[0] = '\0';
        VR_CHECK("grammar: empty chain id rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_CHAIN_ID);
    }

    /* znam grammar (only when present) */
    {
        struct vcs_package_release m = r;
        snprintf(m.znam, sizeof(m.znam), "%s", "Upper");
        VR_CHECK("grammar: bad znam rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_ZNAM);
        m.has_znam = false;
        VR_CHECK("grammar: znam ignored when absent",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
    }

    /* schema version */
    {
        struct vcs_package_release m = r;
        m.schema_version = 2;
        VR_CHECK("grammar: unknown schema version rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_SCHEMA_VERSION);
    }

    /* cryptographic-field validity: zero roots and zero sequence are the
     * "no object" sentinel, never real commitments */
    {
        struct vcs_package_release m = r;
        memset(m.package_root, 0, 32);
        VR_CHECK("grammar: all-zero package root rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_PACKAGE_ROOT);
        m = r;
        memset(m.recipe_root, 0, 32);
        VR_CHECK("grammar: all-zero recipe root rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_RECIPE_ROOT);
        m = r;
        memset(m.parent_root, 0, 32);
        VR_CHECK("grammar: flagged all-zero parent root rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_PARENT_ROOT);
        m.has_parent = false;
        VR_CHECK("grammar: absent parent may be all-zero",
                 vcs_package_release_validate(&m) == VCS_PACKAGE_RELEASE_OK);
        m = r;
        m.publisher_sequence = 0;
        VR_CHECK("grammar: zero publisher sequence rejected",
                 vcs_package_release_validate(&m) ==
                     VCS_PACKAGE_RELEASE_ERR_SEQUENCE);
    }

    /* error strings are defined for every code */
    for (int e = 0; e <= VCS_PACKAGE_RELEASE_ERR_PARENT_ROOT; e++)
        VR_CHECK("grammar: error string defined",
                 vcs_package_release_error_string(
                     (enum vcs_package_release_error)e) != NULL);
    return failures;
}

/* ── 5: wire strictness ───────────────────────────────────────────── */
static int t_release_wire_strictness(void)
{
    int failures = 0;
    struct vcs_package_release r;
    VR_CHECK("wire: fixture", vr_fixture(&r, 0x11));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    VR_CHECK("wire: serialize",
             vcs_package_release_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RELEASE_OK);

    uint8_t *bad = malloc(VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES + 1u);
    VR_CHECK("wire: mutation buffer", bad != NULL);
    if (!bad) {
        free(wire);
        return failures;
    }
    struct vcs_package_release rejected;

    memcpy(bad, wire, wire_len);
    bad[wire_len] = 0;
    VR_CHECK("wire: trailing byte rejected",
             vcs_package_release_parse(bad, wire_len + 1, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_WIRE_TRAILING);
    VR_CHECK("wire: truncation rejected",
             vcs_package_release_parse(wire, wire_len - 1, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_WIRE_TRUNCATED);

    memcpy(bad, wire, wire_len);
    bad[0] ^= 0x01u;
    VR_CHECK("wire: bad magic rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_WIRE_MAGIC);

    memcpy(bad, wire, wire_len);
    bad[8] = 2;
    VR_CHECK("wire: unknown schema version rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_SCHEMA_VERSION);

    /* An over-limit input length is rejected before any byte is read. */
    memcpy(bad, wire, wire_len);
    VR_CHECK("wire: oversize input rejected",
             vcs_package_release_parse(
                 bad, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES + 1u, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_WIRE_OVERSIZE);

    /* Presence flags must be exactly 0 or 1. */
    memcpy(bad, wire, wire_len);
    bad[vr_parent_flag_offset(&r)] = 2;
    VR_CHECK("wire: bad parent flag rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_PARENT_FLAG);
    memcpy(bad, wire, wire_len);
    bad[vr_znam_flag_offset(&r)] = 7;
    VR_CHECK("wire: bad znam flag rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_ZNAM_FLAG);

    /* Grammar is enforced at parse, not only at validate: flip the name's
     * first byte to uppercase (lengths unchanged, signature irrelevant). */
    memcpy(bad, wire, wire_len);
    bad[VCS_PACKAGE_RELEASE_WIRE_MAGIC_BYTES + 2u + 2u] = 'R';
    VR_CHECK("wire: bad name rejected at parse",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_NAME);

    /* A bad license on the wire names the license rule. */
    memcpy(bad, wire, wire_len);
    bad[vr_parent_flag_offset(&r) + 1u + 32u +
        VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 8u + 2u +
        strlen(r.reward_address) + 2u] = 'g'; /* "gpache-2.0" */
    VR_CHECK("wire: bad license rejected at parse",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_LICENSE);

    /* Embedded NUL in a string field is non-canonical. */
    memcpy(bad, wire, wire_len);
    bad[VCS_PACKAGE_RELEASE_WIRE_MAGIC_BYTES + 2u + 2u + 2u] = 0;
    VR_CHECK("wire: embedded NUL rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_NAME);

    /* Off-curve pubkey on the wire. */
    memcpy(bad, wire, wire_len);
    bad[vr_parent_flag_offset(&r) + 1u + 32u] = 0x04u; /* uncompressed tag */
    VR_CHECK("wire: non-compressed pubkey rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_PUBKEY);

    /* Zeroed cryptographic fields on the wire. */
    memcpy(bad, wire, wire_len);
    memset(bad + vr_parent_flag_offset(&r) - 32u, 0, 32);
    VR_CHECK("wire: all-zero package root rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_PACKAGE_ROOT);
    memcpy(bad, wire, wire_len);
    memset(bad + vr_parent_flag_offset(&r) + 1u, 0, 32);
    VR_CHECK("wire: flagged all-zero parent root rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_PARENT_ROOT);
    memcpy(bad, wire, wire_len);
    memset(bad + vr_parent_flag_offset(&r) + 1u + 32u +
           VCS_PACKAGE_RELEASE_PUBKEY_BYTES, 0, 8);
    VR_CHECK("wire: zero publisher sequence rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_SEQUENCE);
    memcpy(bad, wire, wire_len);
    memset(bad + vr_znam_flag_offset(&r) - 32u, 0, 32);
    VR_CHECK("wire: all-zero recipe root rejected",
             vcs_package_release_parse(bad, wire_len, &rejected) ==
                 VCS_PACKAGE_RELEASE_ERR_RECIPE_ROOT);

    /* Rejection zeroes the output struct. */
    {
        struct vcs_package_release poisoned;
        memset(&poisoned, 0xa5, sizeof(poisoned));
        memcpy(bad, wire, wire_len);
        bad[0] ^= 0x01u;
        VR_CHECK("wire: rejection still returns an error",
                 vcs_package_release_parse(bad, wire_len, &poisoned) ==
                     VCS_PACKAGE_RELEASE_ERR_WIRE_MAGIC);
        uint8_t zero_check[sizeof(poisoned)];
        memset(zero_check, 0, sizeof(zero_check));
        VR_CHECK("wire: rejection zeroes the output",
                 memcmp(&poisoned, zero_check, sizeof(zero_check)) == 0);
    }

    free(bad);
    free(wire);
    return failures;
}

/* ── 6: duplicate detection + parent lineage ──────────────────────── */
static int t_release_duplicates_and_lineage(void)
{
    int failures = 0;
    struct vcs_package_release a;
    VR_CHECK("dup: fixture", vr_fixture(&a, 0x11));

    struct vcs_package_release b = a;
    VR_CHECK("dup: identical releases are duplicates",
             vcs_package_release_is_duplicate(&a, &b));

    b = a;
    b.publisher_sequence++;
    VR_CHECK("dup: different sequence is not a duplicate",
             !vcs_package_release_is_duplicate(&a, &b));

    b = a;
    b.package_root[0] ^= 0x01u;
    VR_CHECK("dup: different package root is not a duplicate",
             !vcs_package_release_is_duplicate(&a, &b));

    b = a;
    struct privkey sk2;
    struct pubkey pk2;
    VR_CHECK("dup: second key", vr_keypair(0x22, &sk2, &pk2));
    memcpy(b.publisher_pubkey, pk2.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    VR_CHECK("dup: different publisher is not a duplicate",
             !vcs_package_release_is_duplicate(&a, &b));

    /* A resigned copy of the same release (different nonce key, same
     * identity triple) is still the same release at the codec level. */
    b = a;
    memset(b.signature, 0, sizeof(b.signature));
    VR_CHECK("dup: signature bytes do not affect identity",
             vcs_package_release_is_duplicate(&a, &b));

    /* Parent lineage helper. */
    uint8_t root[32];
    VR_CHECK("lineage: parent root present",
             vcs_package_release_parent(&a, root) &&
             memcmp(root, a.parent_root, 32) == 0);
    struct vcs_package_release genesis = a;
    genesis.has_parent = false;
    memset(root, 0xaa, sizeof(root));
    VR_CHECK("lineage: absent parent reports false and zeroes",
             !vcs_package_release_parent(&genesis, root) &&
             memcmp(root, (uint8_t[32]){0}, 32) == 0);
    return failures;
}

int test_vcs_release(void)
{
    printf("\n=== vcs_release: signed ZCODE release envelope ===\n");
    int failures = 0;
    failures += t_release_kat_roundtrip_verify();
    failures += t_release_signature_rejections();
    failures += t_release_field_grammars();
    failures += t_release_wire_strictness();
    failures += t_release_duplicates_and_lineage();
    printf("=== vcs_release complete: %d failure(s) ===\n", failures);
    return failures;
}
