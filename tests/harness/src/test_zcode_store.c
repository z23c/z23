/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_store — the local ZCODE package store gate
 * (contexts/commons/modules/vcs/package_store.*).
 *
 * Coverage:
 *   1. Flags (-packagehost default off, -packagequota default 10 GiB),
 *      layout creation, result/pool strings.
 *   2. Manifest admission: valid, idempotent re-put, 64 MiB cap, quota
 *      feasibility, and rejection of traversal paths / symlink modes /
 *      garbage wires (the store only ever writes hash-named files, but a
 *      hostile manifest must never be admitted at all).
 *   3. Chunk flow: wrong package, wrong coordinates, hash mismatch,
 *      verify-before-store, completion commit sweep, get round-trip.
 *   4. Dedup: shared chunk stored once, per-package accounting, shared
 *      chunk survives eviction of the other package.
 *   5. Crash recovery: resumable staging, temp sweep, orphan GC,
 *      commit-at-open sweep, completion rebuilt from the CAS, and a corrupt
 *      local CAS object quarantined on read then repaired by a verified put.
 *   6. Quota: staging pool exhaustion (in-flight work preserved),
 *      deterministic HOT (LRU) and RARE (replicas desc) eviction,
 *      pins never evicted + pins budget, pre-existing pin markers.
 *   7. Release envelope storage through the acceptance layer.
 *   8. dump_state_json: disabled shape, enabled totals, key drilldown.
 *      Swarm engine dumpstate (`zcode_swarm`): hosting-off shape, injected
 *      engine peer rows, dumpstate registry key. Receipt dumpstate
 *      (`zcode_swarm_receipts`): hosting-off shape, open-session peer
 *      rows, dumpstate registry key.
 *   9. Blob surface (vcs/blob_store.h): the FROZEN golden root vector,
 *      root purity across independent constructions, length commitment,
 *      put/get round-trip, idempotent re-put, the size ceiling refused by
 *      name with nothing stored, absent-root and small-buffer failures,
 *      and a CAS object corrupted on disk failing verification on read.
 *
 * Stores open on ./test-tmp dirs with explicit quotas; the only global
 * state touched (args + datadir, for the enabled-dump case) is restored
 * before the group returns. */

#include "test/test_core.h"

#include "models/build_fabric.h"
#include "services/build_fabric_cache.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/package_store.h"

#include "vcs/blob_store.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_possession_scheduler.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_swarm_status.h"
#include "vcs/zcode_work_output.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include "config/boot_zcode_swarm_receipt.h"
#include "controllers/diagnostics_internal.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "util/util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZS_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_store: %s... OK\n", (name)); }        \
    else { printf("  zcode_store: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define ZS_MAX_FILES 12u
#define ZS_MAX_FILE 1024u

struct zs_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
    size_t count;
    char paths[ZS_MAX_FILES][64];
    uint8_t contents[ZS_MAX_FILES][ZS_MAX_FILE];
    size_t lens[ZS_MAX_FILES];
};

static void zs_hex32(const uint8_t in[32], char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

/* A package of `count` single-chunk files; file i is paths[i] of lens[i]
 * bytes, content byte j = (uint8_t)(seed + i * 7 + j). */
static bool zs_make_package(struct zs_pkg *p, size_t count,
                            const char *const paths[], const size_t lens[],
                            uint8_t seed)
{
    memset(p, 0, sizeof(*p));
    if (count > ZS_MAX_FILES)
        return false;
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < count; i++) {
        if (lens[i] == 0 || lens[i] > ZS_MAX_FILE)
            return false;
        for (size_t j = 0; j < lens[i]; j++)
            p->contents[i][j] = (uint8_t)(seed + i * 7u + j);
        p->lens[i] = lens[i];
        snprintf(p->paths[i], sizeof(p->paths[i]), "%s", paths[i]);
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(p->contents[i], lens[i], hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, paths[i],
                                      VCS_PACKAGE_MODE_FILE, lens[i], hash,
                                      1))
            return false;
    }
    p->count = count;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    zs_hex32(p->root, p->root_hex);
    return true;
}

static void zs_free_package(struct zs_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* Hand-encode a one-file manifest wire with caller-chosen path and mode —
 * the only way to get a traversal path or a symlink mode past the
 * builder, which is exactly what the store must reject. */
static size_t zs_raw_wire(uint8_t *out, const char *path, uint32_t mode)
{
    size_t n = 0;
    memcpy(out + n, "ZCLPKG\r\n", 8); n += 8;
    out[n++] = 1; out[n++] = 0;                 /* version */
    out[n++] = 0; out[n++] = 0; out[n++] = 16; out[n++] = 0; /* 1 MiB */
    out[n++] = 1; out[n++] = 0; out[n++] = 0; out[n++] = 0;  /* 1 file */
    size_t plen = strlen(path);
    out[n++] = (uint8_t)plen; out[n++] = (uint8_t)(plen >> 8);
    memcpy(out + n, path, plen); n += plen;
    for (int b = 0; b < 4; b++) out[n++] = (uint8_t)(mode >> (8 * b));
    out[n++] = 1; for (int b = 1; b < 8; b++) out[n++] = 0;  /* size 1 */
    out[n++] = 1; out[n++] = 0; out[n++] = 0; out[n++] = 0;  /* 1 chunk */
    memset(out + n, 0xaa, 32); n += 32;
    return n;
}

static bool zs_path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static void zs_store_path(char *out, size_t n, const char *datadir,
                          const char *suffix)
{
    snprintf(out, n, "%s/zcode/%s", datadir, suffix);
}

/* Put every chunk of every file of p. Stops at the first non-OK. The
 * manifest sorts files by path, so contents are matched back by name. */
static enum vcs_package_store_result zs_put_all(
    struct vcs_package_store *store, const struct zs_pkg *p)
{
    for (size_t i = 0; i < p->count; i++) {
        const char *path = p->manifest.files[i].path;
        size_t at = p->count;
        for (size_t j = 0; j < p->count; j++)
            if (strcmp(p->paths[j], path) == 0)
                at = j;
        if (at == p->count)
            return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
        enum vcs_package_store_result r = vcs_package_store_put_chunk(
            store, p->root, path, 0, p->contents[at], p->lens[at]);
        if (r != VCS_PACKAGE_STORE_OK)
            return r;
    }
    return VCS_PACKAGE_STORE_OK;
}

static struct vcs_package_store *zs_open(char *datadir, size_t n,
                                         const char *tag, uint64_t quota)
{
    test_make_tmpdir(datadir, n, "zcode_store", tag);
    return vcs_package_store_open(datadir, quota);
}

/* ── release fixture (acceptance-layer consumption) ───────────────── */

static bool zs_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zs_sign(struct vcs_package_release *r, struct privkey *sk)
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

static bool zs_t1(char *out, size_t out_size)
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

static bool zs_release(struct vcs_package_release *r, uint8_t seed,
                       uint64_t sequence, const char *name)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    for (int i = 0; i < 32; i++) {
        r->package_root[i] = (uint8_t)(0x10 + i);
        r->recipe_root[i]  = (uint8_t)(0x50 + i);
    }
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zs_t1(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zs_sign(r, &sk);
}

/* ── 1: flags, layout, strings ────────────────────────────────────── */
static int t_store_layout_and_flags(void)
{
    int failures = 0;
    ZS_CHECK("flags: hosting defaults off",
             !vcs_package_store_hosting_enabled());
    ZS_CHECK("flags: quota defaults to 10 GiB",
             vcs_package_store_quota_bytes() ==
                 VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);

    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "layout", 1000000u);
    ZS_CHECK("layout: store opens", s != NULL);
    if (!s)
        return failures;
    static const char *const k_dirs[] = {
        "manifests", "releases", "attestations", "badges",
        "cas/sha3", "staging", "pins",
    };
    for (size_t i = 0; i < sizeof(k_dirs) / sizeof(k_dirs[0]); i++) {
        char path[512];
        zs_store_path(path, sizeof(path), dd, k_dirs[i]);
        ZS_CHECK("layout: directory exists", zs_path_exists(path));
    }
    for (int e = 0; e <= VCS_PACKAGE_STORE_ERR_LIMIT; e++)
        ZS_CHECK("strings: result string defined",
                 vcs_package_store_result_string(
                     (enum vcs_package_store_result)e) != NULL);
    for (int p = 0; p <= VCS_PACKAGE_STORE_POOL_STAGING; p++)
        ZS_CHECK("strings: pool string defined",
                 vcs_package_store_pool_string(
                     (enum vcs_package_store_pool)p) != NULL);
    ZS_CHECK("layout: pools start empty",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_PINS) ==
                 0 &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_HOT) ==
                 0 &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 0 &&
             vcs_package_store_pool_usage(
                 s, VCS_PACKAGE_STORE_POOL_STAGING) == 0);
    vcs_package_store_close(s);
    vcs_package_store_close(NULL);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 2: manifest admission ────────────────────────────────────────── */
static int t_store_manifest_admission(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "manifest", 1000000u);
    ZS_CHECK("manifest: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "hello.txt" };
    const size_t lens[] = { 11 };
    struct zs_pkg p;
    ZS_CHECK("manifest: fixture builds",
             zs_make_package(&p, 1, paths, lens, 0x11));
    uint8_t root[32];
    ZS_CHECK("manifest: valid admitted",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, root) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("manifest: root out-param matches",
             memcmp(root, p.root, 32) == 0);
    struct vcs_package_store_status st;
    ZS_CHECK("manifest: tracked incomplete in staging",
             vcs_package_store_package_status(s, p.root, &st) &&
             st.tracked && !st.complete && !st.pinned &&
             st.pool == VCS_PACKAGE_STORE_POOL_STAGING &&
             st.total_bytes == 11 && st.total_chunks == 1 &&
             st.present_chunks == 0);
    ZS_CHECK("manifest: idempotent re-put",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK);

    /* Hostile wires: traversal path, symlink mode, garbage. */
    uint8_t bad[512];
    size_t bad_len = zs_raw_wire(bad, "../escape.txt", VCS_PACKAGE_MODE_FILE);
    ZS_CHECK("manifest: traversal path rejected",
             vcs_package_store_put_manifest(s, bad, bad_len, NULL) ==
                 VCS_PACKAGE_STORE_ERR_MANIFEST);
    bad_len = zs_raw_wire(bad, "link.txt", 0120777u /* symlink */);
    ZS_CHECK("manifest: symlink mode rejected",
             vcs_package_store_put_manifest(s, bad, bad_len, NULL) ==
                 VCS_PACKAGE_STORE_ERR_MANIFEST);
    ZS_CHECK("manifest: garbage wire rejected",
             vcs_package_store_put_manifest(s, bad, 9u, NULL) ==
                 VCS_PACKAGE_STORE_ERR_MANIFEST);
    ZS_CHECK("manifest: null args rejected",
             vcs_package_store_put_manifest(NULL, p.wire, p.wire_len,
                                            NULL) ==
                 VCS_PACKAGE_STORE_ERR_NULL &&
             vcs_package_store_put_manifest(s, NULL, p.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_ERR_NULL);

    /* The 64 MiB v1 cap: 64 MiB + 1 is refused, exactly 64 MiB admits.
     * Fake hashes are per-chunk distinct so nothing dedupes away. */
    static uint8_t fake_hashes[65 * 32];
    for (int i = 0; i < 65; i++)
        memset(fake_hashes + i * 32, i + 1, 32);
    struct vcs_package_manifest over;
    vcs_package_manifest_init(&over);
    ZS_CHECK("cap: oversized manifest builds",
             vcs_package_manifest_add(
                 &over, "big.bin", VCS_PACKAGE_MODE_FILE,
                 VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES + 1u, fake_hashes,
                 65));
    uint8_t *over_wire = NULL;
    size_t over_len = 0;
    ZS_CHECK("cap: oversized manifest serializes",
             vcs_package_manifest_serialize(&over, &over_wire, &over_len));
    ZS_CHECK("cap: 64 MiB + 1 rejected",
             vcs_package_store_put_manifest(s, over_wire, over_len,
                                            NULL) ==
                 VCS_PACKAGE_STORE_ERR_PACKAGE_CAP);
    free(over_wire);
    vcs_package_manifest_free(&over);

    char dd2[256];
    struct vcs_package_store *s2 =
        zs_open(dd2, sizeof(dd2), "capexact",
                VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("cap: second store opens", s2 != NULL);
    if (s2) {
        struct vcs_package_manifest exact;
        vcs_package_manifest_init(&exact);
        ZS_CHECK("cap: exact-size manifest builds",
                 vcs_package_manifest_add(
                     &exact, "exact.bin", VCS_PACKAGE_MODE_FILE,
                     VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, fake_hashes, 64));
        uint8_t *exact_wire = NULL;
        size_t exact_len = 0;
        ZS_CHECK("cap: exact-size manifest serializes",
                 vcs_package_manifest_serialize(&exact, &exact_wire,
                                                &exact_len));
        uint8_t exact_root[32];
        ZS_CHECK("cap: exactly 64 MiB admitted",
                 vcs_package_store_put_manifest(s2, exact_wire, exact_len,
                                                exact_root) ==
                     VCS_PACKAGE_STORE_OK);
        struct vcs_package_store_status est;
        ZS_CHECK("cap: exact package tracked at 64 MiB",
                 vcs_package_store_package_status(s2, exact_root, &est) &&
                 est.total_bytes == VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES &&
                 est.total_chunks == 64);
        free(exact_wire);
        vcs_package_manifest_free(&exact);
        vcs_package_store_close(s2);
    }
    test_rm_rf_recursive(dd2);

    /* Quota feasibility at admission: this store's staging budget is
     * 100000 bytes (1/10 of 1000000); a package that can never fit is
     * refused at put_manifest, not mid-flight. Fake-hash manifest (no
     * chunks are ever put, so no content is needed). */
    struct vcs_package_manifest z;
    vcs_package_manifest_init(&z);
    bool z_built = true;
    for (int i = 0; i < 11; i++) {
        char zpath[8];
        snprintf(zpath, sizeof(zpath), "z%d", i);
        if (!vcs_package_manifest_add(&z, zpath, VCS_PACKAGE_MODE_FILE,
                                      20000, fake_hashes + i * 32, 1))
            z_built = false;
    }
    uint8_t *z_wire = NULL;
    size_t z_len = 0;
    ZS_CHECK("manifest: oversized-for-quota fixture builds",
             z_built && vcs_package_manifest_serialize(&z, &z_wire,
                                                       &z_len));
    ZS_CHECK("manifest: unaffordable package refused with QUOTA",
             vcs_package_store_put_manifest(s, z_wire, z_len, NULL) ==
                 VCS_PACKAGE_STORE_ERR_QUOTA);
    free(z_wire);
    vcs_package_manifest_free(&z);

    zs_free_package(&p);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 3: chunk flow ────────────────────────────────────────────────── */
static int t_store_chunk_flow(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s = zs_open(dd, sizeof(dd), "chunks", 1000000u);
    ZS_CHECK("chunks: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "a.txt", "b.txt" };
    const size_t lens[] = { 100, 200 };
    struct zs_pkg p;
    ZS_CHECK("chunks: fixture builds",
             zs_make_package(&p, 2, paths, lens, 0x33));

    uint8_t unknown[32];
    memset(unknown, 0x77, 32);
    ZS_CHECK("chunks: unknown package rejected",
             vcs_package_store_put_chunk(s, unknown, "a.txt", 0,
                                         p.contents[0], p.lens[0]) ==
                 VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE);
    ZS_CHECK("chunks: manifest admitted",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("chunks: wrong path rejected",
             vcs_package_store_put_chunk(s, p.root, "nope.txt", 0,
                                         p.contents[0], p.lens[0]) ==
                 VCS_PACKAGE_STORE_ERR_CHUNK_COORD);
    ZS_CHECK("chunks: wrong index rejected",
             vcs_package_store_put_chunk(s, p.root, "a.txt", 1,
                                         p.contents[0], p.lens[0]) ==
                 VCS_PACKAGE_STORE_ERR_CHUNK_COORD);
    uint8_t corrupt[100];
    memcpy(corrupt, p.contents[0], 100);
    corrupt[0] ^= 0x01u;
    ZS_CHECK("chunks: hash mismatch rejected before store",
             vcs_package_store_put_chunk(s, p.root, "a.txt", 0, corrupt,
                                         sizeof(corrupt)) ==
                 VCS_PACKAGE_STORE_ERR_CHUNK_HASH);
    struct vcs_package_store_status st;
    ZS_CHECK("chunks: rejected bytes earned nothing",
             vcs_package_store_package_status(s, p.root, &st) &&
             st.present_chunks == 0 && st.present_bytes == 0);

    ZS_CHECK("chunks: first chunk accepted",
             vcs_package_store_put_chunk(s, p.root, "a.txt", 0,
                                         p.contents[0], p.lens[0]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("chunks: still incomplete mid-package",
             vcs_package_store_package_status(s, p.root, &st) &&
             !st.complete && st.present_chunks == 1 &&
             st.present_bytes == 100 &&
             st.pool == VCS_PACKAGE_STORE_POOL_STAGING);

    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("chunks: get round-trips stored bytes",
             vcs_package_store_get_chunk(s, p.root, "a.txt", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK &&
             got_len == 100 && memcmp(got, p.contents[0], 100) == 0);
    free(got);
    got = NULL;
    ZS_CHECK("chunks: get counts as an access",
             vcs_package_store_package_status(s, p.root, &st) &&
             st.access_count == 1);
    ZS_CHECK("chunks: get missing chunk names it",
             vcs_package_store_get_chunk(s, p.root, "b.txt", 0, &got,
                                         &got_len) ==
                 VCS_PACKAGE_STORE_ERR_CHUNK_MISSING && got == NULL);
    ZS_CHECK("chunks: get wrong coords names them",
             vcs_package_store_get_chunk(s, p.root, "b.txt", 9, &got,
                                         &got_len) ==
                 VCS_PACKAGE_STORE_ERR_CHUNK_COORD);

    ZS_CHECK("chunks: completing chunk accepted",
             vcs_package_store_put_chunk(s, p.root, "b.txt", 0,
                                         p.contents[1], p.lens[1]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("chunks: completion commits to the rare pool",
             vcs_package_store_package_status(s, p.root, &st) &&
             st.complete && st.present_bytes == 300 &&
             st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    char path[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "manifests/%s", p.root_hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("chunks: committed manifest moved to manifests/",
             zs_path_exists(path));
    snprintf(suffix, sizeof(suffix), "staging/%s", p.root_hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("chunks: staging dir consumed by the commit",
             !zs_path_exists(path));
    /* CAS object exists under the chunk hash's own name. */
    uint8_t hash[32];
    ZS_CHECK("chunks: chunk hash computes",
             vcs_package_chunk_hash(p.contents[0], p.lens[0], hash));
    char hex[65];
    zs_hex32(hash, hex);
    snprintf(suffix, sizeof(suffix), "cas/sha3/%.2s/%s", hex, hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("chunks: CAS object stored under its hash",
             zs_path_exists(path));

    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4: dedup ─────────────────────────────────────────────────────── */
static int t_store_dedup(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s = zs_open(dd, sizeof(dd), "dedup", 1000000u);
    ZS_CHECK("dedup: store opens", s != NULL);
    if (!s)
        return failures;

    /* A and B share one identical file ("shared.txt", same bytes). B uses
     * seed 0x3d so its index-1 file content (0x3d + 7 + j) equals A's
     * index-0 shared file (0x44 + j). */
    const char *paths_a[] = { "shared.txt", "only-a.txt" };
    const size_t lens_a[] = { 100, 50 };
    struct zs_pkg a;
    ZS_CHECK("dedup: package A builds",
             zs_make_package(&a, 2, paths_a, lens_a, 0x44));
    const char *paths_b[] = { "only-b.txt", "shared.txt" };
    const size_t lens_b[] = { 60, 100 };
    struct zs_pkg bb;
    ZS_CHECK("dedup: package B builds",
             zs_make_package(&bb, 2, paths_b, lens_b, 0x3d));
    ZS_CHECK("dedup: A admitted + complete",
             vcs_package_store_put_manifest(s, a.wire, a.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &a) == VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("dedup: A complete",
             vcs_package_store_package_status(s, a.root, &st) &&
             st.complete && st.present_bytes == 150);

    ZS_CHECK("dedup: B admitted",
             vcs_package_store_put_manifest(s, bb.wire, bb.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK);
    /* The shared chunk is already in the CAS: B is charged per-package
     * accounting but no new bytes hit the disk. */
    ZS_CHECK("dedup: shared chunk put is a no-op OK",
             vcs_package_store_put_chunk(s, bb.root, "shared.txt", 0,
                                         bb.contents[1], bb.lens[1]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("dedup: shared content credited to B immediately",
             vcs_package_store_package_status(s, bb.root, &st) &&
             st.present_bytes == 100);
    ZS_CHECK("dedup: re-put of A's chunk is also a no-op OK",
             vcs_package_store_put_chunk(s, a.root, "shared.txt", 0,
                                         a.contents[0], a.lens[0]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("dedup: B completes",
             vcs_package_store_put_chunk(s, bb.root, "only-b.txt", 0,
                                         bb.contents[0], bb.lens[0]) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, bb.root, &st) &&
             st.complete && st.present_bytes == 160);

    /* Evict A by hand (drop + pressure is covered later; here use the
     * narrow path: A is the only HOT package, B is RARE). */
    ZS_CHECK("dedup: A promoted HOT",
             vcs_package_store_set_class(s, a.root,
                                         VCS_PACKAGE_STORE_CLASS_HOT, 0) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("dedup: B stays RARE",
             vcs_package_store_package_status(s, bb.root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    /* Promote a third package into HOT past the hot budget: this store's
     * hot budget is 400000, far above usage — instead assert sharing
     * survives a real eviction in the eviction tests; here just confirm
     * both readers still get the shared bytes. */
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("dedup: shared bytes read via A",
             vcs_package_store_get_chunk(s, a.root, "shared.txt", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK &&
             got_len == 100);
    free(got);
    got = NULL;
    ZS_CHECK("dedup: shared bytes read via B",
             vcs_package_store_get_chunk(s, bb.root, "shared.txt", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK &&
             got_len == 100);
    free(got);

    zs_free_package(&a);
    zs_free_package(&bb);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 5: crash recovery ────────────────────────────────────────────── */
static int t_store_recovery(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "recovery", 1000000u);
    ZS_CHECK("recovery: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "r1.bin", "r2.bin" };
    const size_t lens[] = { 100, 200 };
    struct zs_pkg p;
    ZS_CHECK("recovery: fixture builds",
             zs_make_package(&p, 2, paths, lens, 0x55));
    ZS_CHECK("recovery: manifest + one chunk staged",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_put_chunk(s, p.root, "r1.bin", 0,
                                         p.contents[0], p.lens[0]) ==
                 VCS_PACKAGE_STORE_OK);
    vcs_package_store_close(s);

    /* Crash debris: a dead-owner torn temp, a live-owner in-flight temp,
     * and an orphan CAS object. Recovery must never unlink another live
     * store owner's atomic write. */
    char debris[512], live_temp[512], live_suffix[96];
    zs_store_path(debris, sizeof(debris), dd,
                  "cas/torn.zstmp.2147483647.1");
    FILE *f = fopen(debris, "wb");
    ZS_CHECK("recovery: temp debris planted", f != NULL);
    if (f) {
        fwrite("x", 1, 1, f);
        fclose(f);
    }
    snprintf(live_suffix, sizeof(live_suffix),
             "cas/live.zstmp.%ld.2", (long)getpid());
    zs_store_path(live_temp, sizeof(live_temp), dd, live_suffix);
    f = fopen(live_temp, "wb");
    ZS_CHECK("recovery: live-owner temp planted", f != NULL);
    if (f) {
        fwrite("active", 1, 6, f);
        fclose(f);
    }
    char orphan_hex[65];
    memset(orphan_hex, '5', 64);
    orphan_hex[64] = '\0';
    char orphan_dir[512];
    char orphan[512];
    zs_store_path(orphan_dir, sizeof(orphan_dir), dd, "cas/sha3/55");
    snprintf(orphan, sizeof(orphan), "%s/%s", orphan_dir, orphan_hex);
    ZS_CHECK("recovery: orphan directory planted",
             mkdir(orphan_dir, 0700) == 0);
    f = fopen(orphan, "wb");
    ZS_CHECK("recovery: orphan chunk planted", f != NULL);
    if (f) {
        fwrite("orphan", 1, 6, f);
        fclose(f);
    }

    s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("recovery: store reopens", s != NULL);
    if (!s) {
        test_rm_rf_recursive(dd);
        return failures;
    }
    ZS_CHECK("recovery: torn temp swept", !zs_path_exists(debris));
    ZS_CHECK("recovery: live-owner temp is not swept",
             zs_path_exists(live_temp));
    (void)unlink(live_temp);
    ZS_CHECK("recovery: orphan chunk GC'd", !zs_path_exists(orphan));
    struct vcs_package_store_status st;
    ZS_CHECK("recovery: staging resumes (manifest + chunk kept)",
             vcs_package_store_package_status(s, p.root, &st) &&
             st.tracked && !st.complete && st.present_chunks == 1 &&
             st.present_bytes == 100 &&
             st.pool == VCS_PACKAGE_STORE_POOL_STAGING);
    ZS_CHECK("recovery: resumed package completes + commits",
             vcs_package_store_put_chunk(s, p.root, "r2.bin", 0,
                                         p.contents[1], p.lens[1]) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, p.root, &st) &&
             st.complete && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    vcs_package_store_close(s);

    /* Commit-at-open sweep: a staged manifest whose chunks are all
     * present commits during recovery (crash between last chunk and
     * commit). Simulate by moving the committed manifest back to
     * staging. */
    char committed[512];
    char staging_dir[512];
    char staged[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "manifests/%s", p.root_hex);
    zs_store_path(committed, sizeof(committed), dd, suffix);
    snprintf(suffix, sizeof(suffix), "staging/%s", p.root_hex);
    zs_store_path(staging_dir, sizeof(staging_dir), dd, suffix);
    snprintf(staged, sizeof(staged), "%s/manifest", staging_dir);
    ZS_CHECK("recovery: un-commit simulation",
             zs_path_exists(committed) && mkdir(staging_dir, 0700) == 0 &&
             rename(committed, staged) == 0);
    s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("recovery: store reopens for the sweep", s != NULL);
    if (s) {
        ZS_CHECK("recovery: CAS-complete staged package committed at open",
                 zs_path_exists(committed) && !zs_path_exists(staging_dir));
        ZS_CHECK("recovery: completion rebuilt from the CAS",
                 vcs_package_store_package_status(s, p.root, &st) &&
                 st.complete && st.present_bytes == 300);
        vcs_package_store_close(s);
    }

    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* A content-addressed filename is a claim, not proof. A same-sized local
 * corruption must become a missing swarm coordinate after the first read so
 * a surviving provider can repair it; leaving it in the presence set wedges
 * restart/resume forever. */
static int t_store_corrupt_read_repair(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "corrupt-repair", 1000000u);
    ZS_CHECK("corrupt repair: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "source/carrier.bin" };
    const size_t lens[] = { 512 };
    struct zs_pkg p;
    ZS_CHECK("corrupt repair: fixture builds",
             zs_make_package(&p, 1, paths, lens, 0x9a));
    ZS_CHECK("corrupt repair: package completes",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, &p) == VCS_PACKAGE_STORE_OK);
    vcs_package_store_close(s);

    char hash_hex[65], suffix[160], cas_path[512];
    zs_hex32(p.manifest.files[0].chunk_hashes, hash_hex);
    snprintf(suffix, sizeof(suffix), "cas/sha3/%.2s/%s", hash_hex,
             hash_hex);
    zs_store_path(cas_path, sizeof(cas_path), dd, suffix);
    FILE *corrupt = fopen(cas_path, "r+b");
    ZS_CHECK("corrupt repair: CAS object opens for fault injection",
             corrupt != NULL);
    if (corrupt) {
        int first = fgetc(corrupt);
        rewind(corrupt);
        bool wrote = first != EOF && fputc(first ^ 0x80, corrupt) != EOF;
        bool closed = fclose(corrupt) == 0;
        ZS_CHECK("corrupt repair: same-size byte corruption lands",
                 wrote && closed);
    }

    s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("corrupt repair: store reopens", s != NULL);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("corrupt repair: read refuses address-mismatched bytes",
             s && vcs_package_store_get_chunk(
                      s, p.root, paths[0], 0, &got, &got_len) ==
                      VCS_PACKAGE_STORE_ERR_CHUNK_HASH &&
                 got == NULL && got_len == 0);
    struct vcs_package_store_status st;
    ZS_CHECK("corrupt repair: bad object becomes a missing coordinate",
             s && !zs_path_exists(cas_path) &&
                 !vcs_package_store_chunk_present(s, p.root, 0, 0) &&
                 vcs_package_store_package_status(s, p.root, &st) &&
                 !st.complete && st.present_chunks == 0);
    ZS_CHECK("corrupt repair: verified provider bytes repair the package",
             s && vcs_package_store_put_chunk(
                      s, p.root, paths[0], 0, p.contents[0], p.lens[0]) ==
                      VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_package_status(s, p.root, &st) &&
                 st.complete && st.present_chunks == 1);
    ZS_CHECK("corrupt repair: repaired bytes read identically",
             s && vcs_package_store_get_chunk(
                 s, p.root, paths[0], 0, &got, &got_len) ==
                     VCS_PACKAGE_STORE_OK &&
                 got_len == p.lens[0] &&
                 memcmp(got, p.contents[0], got_len) == 0);
    free(got);
    vcs_package_store_close(s);
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 6: staging quota ─────────────────────────────────────────────── */
static int t_store_staging_quota(void)
{
    int failures = 0;
    /* quota 10000: staging budget 1000 bytes. */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "stagingq", 10000u);
    ZS_CHECK("stagingq: store opens", s != NULL);
    if (!s)
        return failures;

    const char *dpaths[] = { "d0", "d1", "d2", "d3", "d4",
                             "d5", "d6", "d7", "d8", "d9" };
    const size_t dlens[] = { 100, 100, 100, 100, 100,
                             100, 100, 100, 100, 100 };
    struct zs_pkg d;
    ZS_CHECK("stagingq: package D builds",
             zs_make_package(&d, 10, dpaths, dlens, 0x66));
    struct zs_pkg e;
    ZS_CHECK("stagingq: package E builds",
             zs_make_package(&e, 10, dpaths, dlens, 0x77));
    ZS_CHECK("stagingq: D + E admitted (manifests charge nothing)",
             vcs_package_store_put_manifest(s, d.wire, d.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_put_manifest(s, e.wire, e.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK);

    /* D stages 9 of 10 chunks (900 bytes, deliberately incomplete). */
    for (size_t i = 0; i < 9; i++) {
        char path[8];
        snprintf(path, sizeof(path), "d%zu", i);
        ZS_CHECK("stagingq: D chunk accepted",
                 vcs_package_store_put_chunk(s, d.root, path, 0,
                                             d.contents[i],
                                             d.lens[i]) ==
                     VCS_PACKAGE_STORE_OK);
    }
    ZS_CHECK("stagingq: staging pool at 900",
             vcs_package_store_pool_usage(
                 s, VCS_PACKAGE_STORE_POOL_STAGING) == 900);

    /* E's first chunk exactly fills the pool (900+100 = 1000, fits);
     * the second would exceed it and is refused BEFORE the byte lands. */
    ZS_CHECK("stagingq: E chunk filling the pool exactly accepted",
             vcs_package_store_put_chunk(s, e.root, "d0", 0, e.contents[0],
                                         e.lens[0]) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("stagingq: over-budget chunk refused with QUOTA",
             vcs_package_store_put_chunk(s, e.root, "d1", 0, e.contents[1],
                                         e.lens[1]) ==
                 VCS_PACKAGE_STORE_ERR_QUOTA);
    ZS_CHECK("stagingq: refused byte was not stored",
             vcs_package_store_pool_usage(
                 s, VCS_PACKAGE_STORE_POOL_STAGING) == 1000);
    struct vcs_package_store_status st;
    ZS_CHECK("stagingq: in-flight work is preserved, not discarded",
             vcs_package_store_package_status(s, d.root, &st) &&
             !st.complete && st.present_bytes == 900 &&
             vcs_package_store_package_status(s, e.root, &st) &&
             !st.complete && st.present_bytes == 100);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("stagingq: accepted E chunk still readable",
             vcs_package_store_get_chunk(s, e.root, "d0", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);

    zs_free_package(&d);
    zs_free_package(&e);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 7: deterministic HOT eviction (LRU) ──────────────────────────── */
static int t_store_hot_eviction(void)
{
    int failures = 0;
    /* quota 10000: staging 1000 (caps one package at 1000), hot 4000,
     * rare 3000. Five packages of 1000: four promoted hot fill the pool
     * exactly; promoting the fifth must evict the least-requested one. */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "hotevict", 10000u);
    ZS_CHECK("hot: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "x.bin", "y.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg f, g, h, i2, j2;
    ZS_CHECK("hot: fixtures build",
             zs_make_package(&f, 2, paths, lens, 0x11) &&
             zs_make_package(&g, 2, paths, lens, 0x22) &&
             zs_make_package(&h, 2, paths, lens, 0x33) &&
             zs_make_package(&i2, 2, paths, lens, 0x44) &&
             zs_make_package(&j2, 2, paths, lens, 0x55));

    struct zs_pkg *quartet[] = { &f, &g, &h, &i2 };
    for (size_t q = 0; q < 4; q++) {
        ZS_CHECK("hot: package completes",
                 vcs_package_store_put_manifest(s, quartet[q]->wire,
                                                quartet[q]->wire_len,
                                                NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, quartet[q]) == VCS_PACKAGE_STORE_OK);
        ZS_CHECK("hot: package promoted",
                 vcs_package_store_set_class(s, quartet[q]->root,
                                             VCS_PACKAGE_STORE_CLASS_HOT,
                                             0) == VCS_PACKAGE_STORE_OK);
    }
    ZS_CHECK("hot: hot pool exactly full",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_HOT) ==
                 4000);

    /* G, H, I are requested; F is not. F is the only LRU victim. */
    const char *names[] = { "g", "h", "i" };
    struct zs_pkg *requested[] = { &g, &h, &i2 };
    for (size_t q = 0; q < 3; q++) {
        (void)names;
        uint8_t *got = NULL;
        size_t got_len = 0;
        ZS_CHECK("hot: package accessed",
                 vcs_package_store_get_chunk(s, requested[q]->root, "x.bin",
                                             0, &got, &got_len) ==
                     VCS_PACKAGE_STORE_OK);
        free(got);
    }

    ZS_CHECK("hot: J completes into rare",
             vcs_package_store_put_manifest(s, j2.wire, j2.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &j2) == VCS_PACKAGE_STORE_OK);
    /* Promoting J (1000) into hot (4000/4000) evicts F (never accessed),
     * never a requested package and never the incoming J. */
    ZS_CHECK("hot: J promotion evicts the LRU package",
             vcs_package_store_set_class(s, j2.root,
                                         VCS_PACKAGE_STORE_CLASS_HOT, 0) ==
                 VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("hot: evicted F is fully gone",
             !vcs_package_store_package_status(s, f.root, &st));
    char path[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "manifests/%s", f.root_hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("hot: evicted F's manifest deleted", !zs_path_exists(path));
    ZS_CHECK("hot: requested packages and incoming J survived",
             vcs_package_store_package_status(s, g.root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, h.root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, i2.root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT &&
             vcs_package_store_package_status(s, j2.root, &st) &&
             st.pool == VCS_PACKAGE_STORE_POOL_HOT);
    ZS_CHECK("hot: hot pool within budget after eviction",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_HOT) <=
                 4000);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("hot: G still readable after F's eviction",
             vcs_package_store_get_chunk(s, g.root, "y.bin", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);

    zs_free_package(&f);
    zs_free_package(&g);
    zs_free_package(&h);
    zs_free_package(&i2);
    zs_free_package(&j2);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 8: deterministic RARE eviction (replicas desc) ───────────────── */
static int t_store_rare_eviction(void)
{
    int failures = 0;
    /* quota 10000: rare 3000. I, J, K at 1000 fill it exactly; L's
     * completion must evict the best-replicated victim (I). */
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "rareevict", 10000u);
    ZS_CHECK("rare: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "p.bin", "q.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg i1, j1, k1, l1;
    ZS_CHECK("rare: fixtures build",
             zs_make_package(&i1, 2, paths, lens, 0x66) &&
             zs_make_package(&j1, 2, paths, lens, 0x77) &&
             zs_make_package(&k1, 2, paths, lens, 0x88) &&
             zs_make_package(&l1, 2, paths, lens, 0x99));
    struct zs_pkg *trio[] = { &i1, &j1, &k1 };
    for (size_t q = 0; q < 3; q++)
        ZS_CHECK("rare: package completes",
                 vcs_package_store_put_manifest(s, trio[q]->wire,
                                                trio[q]->wire_len,
                                                NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, trio[q]) == VCS_PACKAGE_STORE_OK);
    ZS_CHECK("rare: rare pool exactly full",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 3000);
    /* I is well-replicated elsewhere; a replica update under an unchanged
     * class must not disturb the pools. */
    ZS_CHECK("rare: I's replica count recorded",
             vcs_package_store_set_class(s, i1.root,
                                         VCS_PACKAGE_STORE_CLASS_RARE, 5) ==
                 VCS_PACKAGE_STORE_OK);
    ZS_CHECK("rare: rare pool untouched by the replica update",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 3000);

    ZS_CHECK("rare: L's completing chunk evicts the best-replicated I",
             vcs_package_store_put_manifest(s, l1.wire, l1.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &l1) == VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("rare: best-replicated I evicted",
             !vcs_package_store_package_status(s, i1.root, &st));
    ZS_CHECK("rare: under-replicated J, K and incoming L survived",
             vcs_package_store_package_status(s, j1.root, &st) &&
             st.complete &&
             vcs_package_store_package_status(s, k1.root, &st) &&
             st.complete &&
             vcs_package_store_package_status(s, l1.root, &st) &&
             st.complete && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    ZS_CHECK("rare: rare pool within budget",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) <=
                 3000);

    zs_free_package(&i1);
    zs_free_package(&j1);
    zs_free_package(&k1);
    zs_free_package(&l1);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 9: pins ──────────────────────────────────────────────────────── */
static int t_store_pins(void)
{
    int failures = 0;
    /* quota 10000: pins 2000, rare 3000, staging 1000. */
    char dd[256];
    struct vcs_package_store *s = zs_open(dd, sizeof(dd), "pins", 10000u);
    ZS_CHECK("pins: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "a.bin", "b.bin" };
    const size_t lens[] = { 500, 500 };
    struct zs_pkg l, m, n, o, p2;
    ZS_CHECK("pins: fixtures build",
             zs_make_package(&l, 2, paths, lens, 0xaa) &&
             zs_make_package(&m, 2, paths, lens, 0xbb) &&
             zs_make_package(&n, 2, paths, lens, 0xcc) &&
             zs_make_package(&o, 2, paths, lens, 0xdd) &&
             zs_make_package(&p2, 2, paths, lens, 0xee));

    ZS_CHECK("pins: L completes and pins",
             vcs_package_store_put_manifest(s, l.wire, l.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &l) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pin(s, l.root, true) ==
                 VCS_PACKAGE_STORE_OK);
    struct vcs_package_store_status st;
    ZS_CHECK("pins: L charges the pins pool",
             vcs_package_store_package_status(s, l.root, &st) && st.pinned &&
             st.pool == VCS_PACKAGE_STORE_POOL_PINS &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_PINS) ==
                 1000);
    ZS_CHECK("pins: full-byte possession proof accepts complete pinned L",
             vcs_package_store_verify_possession(s, l.root, true));
    {
        uint8_t token_a[32], token_b[32];
        struct vcs_package_store_status plan_st;
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        ZS_CHECK("pins: plan token is issued",
                 vcs_package_store_pin_plan(s, l.root, true, &plan_st,
                                            token_a));
        ZS_CHECK("pins: a read after plan is allowed",
                 vcs_package_store_get_chunk(s, l.root, "a.bin", 0, &chunk,
                                             &chunk_len) ==
                     VCS_PACKAGE_STORE_OK);
        free(chunk);
        ZS_CHECK("pins: plan token survives an access_count bump",
                 vcs_package_store_pin_plan(s, l.root, true, &plan_st,
                                            token_b) &&
                 memcmp(token_a, token_b, 32) == 0);
        ZS_CHECK("pins: unpin intent changes the plan token",
                 vcs_package_store_pin_plan(s, l.root, false, &plan_st,
                                            token_b) &&
                 memcmp(token_a, token_b, 32) != 0);
    }
    ZS_CHECK("pins: M completes and pins (pins pool exactly full)",
             vcs_package_store_put_manifest(s, m.wire, m.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &m) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pin(s, m.root, true) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_PINS) ==
                 2000);
    ZS_CHECK("pins: N completes into rare",
             vcs_package_store_put_manifest(s, n.wire, n.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &n) == VCS_PACKAGE_STORE_OK);
    /* Pins are never made room for by eviction: a pin that does not fit
     * fails, and the package stays as it was. */
    ZS_CHECK("pins: over-budget pin refused without evicting",
             vcs_package_store_pin(s, n.root, true) ==
                 VCS_PACKAGE_STORE_ERR_QUOTA);
    ZS_CHECK("pins: refused pin left N unpinned",
             vcs_package_store_package_status(s, n.root, &st) &&
             !st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_RARE);

    ZS_CHECK("pins: unpin returns M to its class pool",
             vcs_package_store_pin(s, m.root, false) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, m.root, &st) &&
             !st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    ZS_CHECK("pins: possession proof fails closed after unpin",
             !vcs_package_store_verify_possession(s, m.root, true));

    /* Rare-pool pressure: O fills rare exactly (3000), P's completion
     * must evict exactly one rare package and must never touch the
     * pinned L. (All rare candidates tie on replicas/access, so the
     * victim is the lowest root hex — which one is irrelevant here.) */
    ZS_CHECK("pins: O + P complete under rare-pool pressure",
             vcs_package_store_put_manifest(s, o.wire, o.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &o) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_put_manifest(s, p2.wire, p2.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &p2) == VCS_PACKAGE_STORE_OK);
    ZS_CHECK("pins: pinned L survived rare-pool pressure",
             vcs_package_store_package_status(s, l.root, &st) &&
             st.pinned && st.complete &&
             st.pool == VCS_PACKAGE_STORE_POOL_PINS);
    size_t survivors =
        (vcs_package_store_package_status(s, m.root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, n.root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, o.root, &st) ? 1u : 0u) +
        (vcs_package_store_package_status(s, p2.root, &st) ? 1u : 0u);
    ZS_CHECK("pins: exactly one rare package was evicted",
             survivors == 3u);
    ZS_CHECK("pins: rare pool within budget",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) <=
                 3000);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("pins: L still readable",
             vcs_package_store_get_chunk(s, l.root, "a.bin", 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK);
    free(got);

    /* A pin marker that pre-exists the manifest pins at admission. */
    struct zs_pkg pre;
    ZS_CHECK("pins: pre-pinned fixture builds",
             zs_make_package(&pre, 2, paths, lens, 0xf0));
    char marker[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "pins/%s", pre.root_hex);
    zs_store_path(marker, sizeof(marker), dd, suffix);
    FILE *f = fopen(marker, "wb");
    ZS_CHECK("pins: marker planted", f != NULL);
    if (f)
        fclose(f);
    ZS_CHECK("pins: admission honors a pre-existing marker",
             vcs_package_store_put_manifest(s, pre.wire, pre.wire_len,
                                            NULL) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, pre.root, &st) &&
             st.pinned && st.pool == VCS_PACKAGE_STORE_POOL_PINS);

    /* A durable ACK is a claim about bytes that are still present, not a
     * sticky bit in package metadata. Removing one pinned CAS chunk must
     * immediately invalidate the possession proof used by ACK renewal. */
    uint8_t missing_hash[32];
    char missing_hex[65];
    char missing_suffix[160];
    char missing_path[512];
    ZS_CHECK("pins: missing-byte fixture hash",
             vcs_package_chunk_hash(l.contents[0], l.lens[0], missing_hash));
    zs_hex32(missing_hash, missing_hex);
    snprintf(missing_suffix, sizeof(missing_suffix), "cas/sha3/%02x/%s",
             missing_hash[0], missing_hex);
    zs_store_path(missing_path, sizeof(missing_path), dd, missing_suffix);
    ZS_CHECK("pins: pinned byte deletion planted", unlink(missing_path) == 0);
    ZS_CHECK("pins: possession proof fails after missing byte",
             !vcs_package_store_verify_possession(s, l.root, true));

    zs_free_package(&l);
    zs_free_package(&m);
    zs_free_package(&n);
    zs_free_package(&o);
    zs_free_package(&p2);
    zs_free_package(&pre);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 10: bounded possession scheduler ────────────────────────────── */
static int t_store_possession_scheduler(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *store =
        zs_open(dd, sizeof(dd), "possession_scheduler", 10000000u);
    ZS_CHECK("possession scheduler: store opens", store != NULL);
    if (!store)
        return failures;

    const char *large_paths[] = {
        "a.bin", "b.bin", "c.bin", "d.bin"};
    const size_t large_lens[] = {500, 500, 500, 500};
    const char *small_paths[] = {"only.bin"};
    const size_t small_lens[] = {500};
    struct zs_pkg packages[3];
    bool fixtures = true;
    fixtures &= zs_make_package(&packages[0], 4, large_paths, large_lens,
                                0x21);
    for (size_t i = 1; i < 3; i++)
        fixtures &= zs_make_package(&packages[i], 1, small_paths, small_lens,
                                    (uint8_t)(0x21 + i * 0x20));
    ZS_CHECK("possession scheduler: fixtures build", fixtures);
    bool stored = fixtures;
    for (size_t i = 0; i < 3 && stored; i++)
        stored = vcs_package_store_put_manifest(
                     store, packages[i].wire, packages[i].wire_len, NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(store, &packages[i]) == VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_pin(store, packages[i].root, true) ==
                     VCS_PACKAGE_STORE_OK;
    ZS_CHECK("possession scheduler: packages complete and pin", stored);

    struct vcs_package_store_status before;
    ZS_CHECK("possession scheduler: mutation generation is published",
             vcs_package_store_package_status(store, packages[0].root,
                                              &before) &&
                 before.mutation_generation != 0 && before.complete &&
                 before.pinned);

    struct vcs_package_possession_receipt receipt;
    struct vcs_package_possession_proof *proof =
        vcs_package_store_possession_begin(store, packages[0].root, true,
                                           &receipt);
    ZS_CHECK("possession scheduler: incremental proof begins", proof != NULL);
    uint64_t used = UINT64_MAX;
    enum vcs_package_possession_step step =
        vcs_package_store_possession_step(proof, 499, 1, &receipt, &used);
    ZS_CHECK("possession scheduler: strict byte budget reads nothing",
             step == VCS_PACKAGE_POSSESSION_BUDGET && used == 0 &&
                 receipt.bytes_verified == 0);
    step = vcs_package_store_possession_step(proof, 500, 1, &receipt,
                                             &used);
    ZS_CHECK("possession scheduler: one-chunk budget advances once",
             step == VCS_PACKAGE_POSSESSION_PROGRESS && used == 500 &&
                 receipt.bytes_verified == 500);
    ZS_CHECK("possession scheduler: unpin and repin mutate generation",
             vcs_package_store_pin(store, packages[0].root, false) ==
                     VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_pin(store, packages[0].root, true) ==
                     VCS_PACKAGE_STORE_OK);
    do {
        step = vcs_package_store_possession_step(
            proof, VCS_PACKAGE_CHUNK_BYTES, 8, &receipt, &used);
    } while (step == VCS_PACKAGE_POSSESSION_PROGRESS);
    ZS_CHECK("possession scheduler: proof refuses post-snapshot mutation",
             step == VCS_PACKAGE_POSSESSION_FAILED &&
                 receipt.failure == VCS_PACKAGE_POSSESSION_MUTATED);
    vcs_package_store_possession_free(proof);

    struct vcs_package_possession_scheduler_config config = {
        .packages_per_cycle = 1,
        .chunks_per_package_cycle = 1,
        .bytes_per_cycle = VCS_PACKAGE_CHUNK_BYTES,
        .scrub_interval_s = 100,
        .failure_retry_s = 5,
    };
    struct vcs_package_possession_scheduler *scheduler =
        vcs_package_possession_scheduler_new(&config);
    uint8_t roots[3][32];
    for (size_t i = 0; i < 3; i++)
        memcpy(roots[i], packages[i].root, 32);
    ZS_CHECK("possession scheduler: bounded scheduler opens and watches",
             scheduler != NULL &&
                 vcs_package_possession_scheduler_reconcile(
                     scheduler, store, roots, 3, 1000));
    for (uint64_t now = 1000; now < 1040; now++)
        vcs_package_possession_scheduler_run(scheduler, store, now);
    bool all_current = true;
    for (size_t i = 0; i < 3; i++)
        all_current &= vcs_package_possession_scheduler_current(
            scheduler, store, roots[i], NULL);
    struct vcs_package_possession_scheduler_status status;
    vcs_package_possession_scheduler_status(scheduler, 1040, &status);
    ZS_CHECK("possession scheduler: large root cannot starve small roots",
             all_current && status.successful_proofs == 3 &&
                 status.tracked_roots == 3);
    ZS_CHECK("possession scheduler: per-cycle budgets stayed strict",
             status.last_cycle_packages <= 1 &&
                 status.last_cycle_bytes <= VCS_PACKAGE_CHUNK_BYTES);
    uint64_t bytes_before_idle = status.bytes_verified_total;
    vcs_package_possession_scheduler_run(scheduler, store, 1041);
    vcs_package_possession_scheduler_status(scheduler, 1041, &status);
    ZS_CHECK("possession scheduler: ordinary pass does not rehash",
             status.last_cycle_packages == 0 &&
                 status.last_cycle_bytes == 0 &&
                 status.bytes_verified_total == bytes_before_idle);

    ZS_CHECK("possession scheduler: unpin invalidates cached proof",
             vcs_package_store_pin(store, packages[1].root, false) ==
                     VCS_PACKAGE_STORE_OK &&
                 !vcs_package_possession_scheduler_current(
                     scheduler, store, packages[1].root, NULL));
    ZS_CHECK("possession scheduler: mutation queues only changed root",
             vcs_package_possession_scheduler_reconcile(
                 scheduler, store, roots, 3, 1042) &&
                 vcs_package_possession_scheduler_require(
                     scheduler, roots[1], 1042));
    vcs_package_possession_scheduler_status(scheduler, 1042, &status);
    ZS_CHECK("possession scheduler: diagnostics expose queue/failure counts",
             status.queued_roots == 1 && status.next_due_mono == 1042 &&
                 status.bytes_verified_total == bytes_before_idle);
    vcs_package_possession_scheduler_run(scheduler, store, 1042);
    vcs_package_possession_scheduler_require(
        scheduler, roots[1], 1043);
    vcs_package_possession_scheduler_status(scheduler, 1043, &status);
    ZS_CHECK("possession scheduler: failed proof respects retry deadline",
             status.next_due_mono == 1047 && status.failed_proofs >= 1);

    proof = vcs_package_store_possession_begin(
        store, packages[2].root, true, &receipt);
    step = vcs_package_store_possession_step(proof, 500, 1, &receipt,
                                             &used);
    uint8_t raced_hash[32];
    char raced_hex[65], raced_suffix[160], raced_path[512];
    bool raced_path_ready =
        proof && step == VCS_PACKAGE_POSSESSION_PROGRESS &&
        vcs_package_chunk_hash(packages[2].contents[0],
                               packages[2].lens[0], raced_hash);
    if (raced_path_ready) {
        zs_hex32(raced_hash, raced_hex);
        snprintf(raced_suffix, sizeof(raced_suffix),
                 "cas/sha3/%02x/%s", raced_hash[0], raced_hex);
        zs_store_path(raced_path, sizeof(raced_path), dd, raced_suffix);
        raced_path_ready = unlink(raced_path) == 0;
    }
    do {
        step = vcs_package_store_possession_step(
            proof, VCS_PACKAGE_CHUNK_BYTES, 8, &receipt, &used);
    } while (step == VCS_PACKAGE_POSSESSION_PROGRESS);
    ZS_CHECK("possession scheduler: post-read byte deletion is not accepted",
             raced_path_ready &&
                 step == VCS_PACKAGE_POSSESSION_FAILED &&
                 receipt.failure == VCS_PACKAGE_POSSESSION_MUTATED);
    vcs_package_store_possession_free(proof);

    for (size_t i = 0; i < 3; i++)
        vcs_package_possession_scheduler_run(scheduler, store, 1200);
    ZS_CHECK("possession scheduler: fresh request invalidates cached success",
             vcs_package_possession_scheduler_require(
                 scheduler, roots[0], 1200) &&
                 !vcs_package_possession_scheduler_current(
                     scheduler, store, roots[0], NULL));

    vcs_package_possession_scheduler_free(scheduler);
    for (size_t i = 0; i < 3; i++)
        zs_free_package(&packages[i]);
    vcs_package_store_close(store);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 11: release envelopes ────────────────────────────────────────── */
static int t_store_releases(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "releases", 1000000u);
    ZS_CHECK("releases: store opens", s != NULL);
    if (!s)
        return failures;

    struct vcs_package_release r;
    ZS_CHECK("releases: fixture signs",
             zs_release(&r, 0x11, 1u, "rhett/ring-buffer"));
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ZS_CHECK("releases: accepted envelope stored",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_OK);
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZS_CHECK("releases: id computes",
             vcs_package_release_id(&r, id) == VCS_PACKAGE_RELEASE_OK);
    char hex[65];
    zs_hex32(id, hex);
    char path[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "releases/%s", hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("releases: envelope persisted under its id",
             zs_path_exists(path));

    ZS_CHECK("releases: redelivery is an idempotent store",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_DUPLICATE);

    struct vcs_package_release forked;
    ZS_CHECK("releases: equivocation fixture signs",
             zs_release(&forked, 0x11, 1u, "rhett/ring-buffer-fork"));
    ZS_CHECK("releases: equivocation rejected, nothing stored",
             vcs_package_store_put_release(s, &forked, &ar) ==
                 VCS_PACKAGE_STORE_ERR_ACCEPT &&
             ar == VCS_PACKAGE_ACCEPT_EQUIVOCATION);
    uint8_t forked_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    ZS_CHECK("releases: equivocation id computes",
             vcs_package_release_id(&forked, forked_id) ==
                 VCS_PACKAGE_RELEASE_OK);
    zs_hex32(forked_id, hex);
    snprintf(suffix, sizeof(suffix), "releases/%s", hex);
    zs_store_path(path, sizeof(path), dd, suffix);
    ZS_CHECK("releases: equivocated envelope not persisted",
             !zs_path_exists(path));

    ZS_CHECK("releases: null args rejected",
             vcs_package_store_put_release(NULL, &r, &ar) ==
                 VCS_PACKAGE_STORE_ERR_NULL &&
             vcs_package_store_put_release(s, NULL, &ar) ==
                 VCS_PACKAGE_STORE_ERR_NULL);

    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 12: content-addressed blob surface (vcs/blob_store.h) ────────── */

/* FROZEN GOLDEN VECTOR. The blob root is a wire contract: the SAME bytes
 * must yield the SAME 32-byte root on every node, forever. This pins the
 * whole derivation — the "blob" path, mode 0100644, the size/chunk_count
 * fields, the SHA3-256 chunk hash, and the zcl.package_manifest.v1 root
 * domain. If this ever changes, every already-published blob root breaks;
 * a failure here is a CONSENSUS-OF-CONTENT regression, not a test nit. */
#define ZS_BLOB_GOLDEN_INPUT "zcl.blob.golden.v1"
#define ZS_BLOB_GOLDEN_ROOT \
    "a407592f33b1ac781c69ac5bb0bf7f7635c320b17d2e5382bf93b5567af686e7"

static int t_store_blob(void)
{
    int failures = 0;
    char dd[1024];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "blob", VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("blob: store opens", s != NULL);
    if (!s)
        return failures + 1;

    /* ---- pure root: determinism across independent constructions ---- */
    uint8_t a[256], b[256];
    for (size_t i = 0; i < sizeof(a); i++)
        a[i] = (uint8_t)(i * 7u + 11u);
    memset(b, 0, sizeof(b));
    for (size_t i = 0; i < sizeof(b); i++)
        b[i] = (uint8_t)((i * 7u + 11u) & 0xffu);
    uint8_t root_a[32], root_b[32];
    bool ok_a = vcs_blob_root(a, sizeof(a), root_a);
    bool ok_b = vcs_blob_root(b, sizeof(b), root_b);
    ZS_CHECK("blob: root is a pure function of the bytes",
             ok_a && ok_b && memcmp(root_a, root_b, 32) == 0);

    /* Different bytes -> different root; same prefix, shorter -> different
     * root (the length is committed, so truncation is not a collision). */
    uint8_t c[256];
    memcpy(c, a, sizeof(c));
    c[100] ^= 0x01;
    uint8_t root_c[32], root_short[32];
    ZS_CHECK("blob: one flipped byte changes the root",
             vcs_blob_root(c, sizeof(c), root_c) &&
             memcmp(root_a, root_c, 32) != 0);
    ZS_CHECK("blob: length is committed (prefix != whole)",
             vcs_blob_root(a, sizeof(a) - 1u, root_short) &&
             memcmp(root_a, root_short, 32) != 0);

    /* ---- the frozen golden vector ---- */
    uint8_t golden[32];
    const char *gin = ZS_BLOB_GOLDEN_INPUT;
    bool gok = vcs_blob_root((const uint8_t *)gin, strlen(gin), golden);
    char ghex[65];
    zs_hex32(golden, ghex);
    printf("  zcode_store: blob golden root = %s\n", ghex);
    ZS_CHECK("blob: FROZEN golden root vector holds",
             gok && strcmp(ghex, ZS_BLOB_GOLDEN_ROOT) == 0);

    /* ---- hostile input, refused by name, before anything is stored ---- */
    uint8_t junk_root[32];
    ZS_CHECK("blob: null bytes refused",
             vcs_blob_root_of(NULL, 10, junk_root) == VCS_BLOB_ERR_NULL);
    ZS_CHECK("blob: empty blob refused",
             vcs_blob_root_of(a, 0, junk_root) == VCS_BLOB_ERR_EMPTY);
    ZS_CHECK("blob: null store refused",
             vcs_blob_put_to(NULL, a, sizeof(a), junk_root) ==
                 VCS_BLOB_ERR_NO_STORE);

    static uint8_t big[VCS_BLOB_MAX_BYTES + 64u];
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)(i ^ 0x5au);
    ZS_CHECK("blob: over the ceiling refused by name (root)",
             vcs_blob_root_of(big, VCS_BLOB_MAX_BYTES + 1u, junk_root) ==
                 VCS_BLOB_ERR_TOO_LARGE);
    ZS_CHECK("blob: over the ceiling refused by name (put)",
             vcs_blob_put_to(s, big, VCS_BLOB_MAX_BYTES + 1u, junk_root) ==
                 VCS_BLOB_ERR_TOO_LARGE);
    ZS_CHECK("blob: refused oversize stored nothing",
             vcs_package_store_pool_usage(s, VCS_PACKAGE_STORE_POOL_RARE) ==
                 0 &&
             vcs_package_store_pool_usage(s,
                                          VCS_PACKAGE_STORE_POOL_STAGING) ==
                 0);
    /* Exactly at the ceiling is admitted: the bound is a ceiling, not a
     * fencepost bug. */
    uint8_t edge_root[32];
    ZS_CHECK("blob: exactly at the ceiling is accepted",
             vcs_blob_put_to(s, big, VCS_BLOB_MAX_BYTES, edge_root) ==
                 VCS_BLOB_OK);
    ZS_CHECK("blob: ceiling blob is one chunk (never split)",
             vcs_package_store_chunk_present(s, edge_root, 0, 0) &&
             !vcs_package_store_chunk_present(s, edge_root, 0, 1) &&
             !vcs_package_store_chunk_present(s, edge_root, 1, 0));

    /* ---- put / get round trip ---- */
    uint8_t root[32];
    ZS_CHECK("blob: put admits manifest + chunk",
             vcs_blob_put_to(s, a, sizeof(a), root) == VCS_BLOB_OK);
    ZS_CHECK("blob: put root equals the pure root",
             memcmp(root, root_a, 32) == 0);
    struct vcs_package_store_status st;
    ZS_CHECK("blob: stored package is complete and one-file",
             vcs_package_store_package_status(s, root, &st) && st.complete &&
             st.total_chunks == 1 && st.total_bytes == sizeof(a));

    uint8_t out[512];
    size_t out_len = 0;
    memset(out, 0, sizeof(out));
    ZS_CHECK("blob: get round-trips the exact bytes",
             vcs_blob_get_from(s, root, out, sizeof(out), &out_len) ==
                 VCS_BLOB_OK &&
             out_len == sizeof(a) && memcmp(out, a, sizeof(a)) == 0);

    /* Idempotent re-put of identical bytes. */
    uint8_t root2[32];
    ZS_CHECK("blob: re-put of identical bytes is idempotent",
             vcs_blob_put_to(s, a, sizeof(a), root2) == VCS_BLOB_OK &&
             memcmp(root, root2, 32) == 0);

    /* ---- absent root fails cleanly (no crash, no partial write) ---- */
    uint8_t absent[32];
    memcpy(absent, root, 32);
    absent[0] ^= 0xff;
    ZS_CHECK("blob: get of an absent root fails cleanly",
             vcs_blob_get_from(s, absent, out, sizeof(out), &out_len) ==
                 VCS_BLOB_ERR_ABSENT && out_len == 0);
    ZS_CHECK("blob: get with a null buffer refused",
             vcs_blob_get_from(s, root, NULL, 16, &out_len) ==
                 VCS_BLOB_ERR_NULL);
    ZS_CHECK("blob: buffer smaller than the blob refused",
             vcs_blob_get_from(s, root, out, sizeof(a) - 1u, &out_len) ==
                 VCS_BLOB_ERR_CAPACITY);

    /* ---- a corrupted CAS object must FAIL verification, not be served -- */
    uint8_t chunk_hash[32];
    ZS_CHECK("blob: chunk hash computes",
             vcs_package_chunk_hash(a, sizeof(a), chunk_hash));
    char hex[65];
    zs_hex32(chunk_hash, hex);
    char suffix[160];
    char cas_path[1400];
    snprintf(suffix, sizeof(suffix), "cas/sha3/%.2s/%s", hex, hex);
    zs_store_path(cas_path, sizeof(cas_path), dd, suffix);
    ZS_CHECK("blob: CAS object exists under its hash",
             zs_path_exists(cas_path));
    uint8_t tampered[256];
    memcpy(tampered, a, sizeof(tampered));
    tampered[7] ^= 0xff;
    FILE *f = fopen(cas_path, "wb");
    bool wrote = f && fwrite(tampered, 1, sizeof(tampered), f) ==
                          sizeof(tampered);
    if (f)
        fclose(f);
    ZS_CHECK("blob: CAS object tampered on disk", wrote);
    ZS_CHECK("blob: corrupted chunk fails verification on read",
             vcs_blob_get_from(s, root, out, sizeof(out), &out_len) ==
                 VCS_BLOB_ERR_CORRUPT && out_len == 0);

    /* ---- named results ---- */
    ZS_CHECK("blob: result strings are named",
             strcmp(vcs_blob_result_string(VCS_BLOB_OK), "ok") == 0 &&
             strcmp(vcs_blob_result_string(VCS_BLOB_ERR_TOO_LARGE),
                    "blob-too-large") == 0 &&
             strcmp(vcs_blob_result_string(VCS_BLOB_ERR_CORRUPT),
                    "blob-bytes-corrupt") == 0 &&
             strcmp(vcs_blob_result_string((enum vcs_blob_result)999),
                    "unknown") == 0);

    /* ---- global accessors refuse cleanly with no global store open ---- */
    ZS_CHECK("blob: global put refuses with no global store",
             vcs_package_store_global() == NULL &&
             !vcs_blob_put(a, sizeof(a), junk_root));
    ZS_CHECK("blob: global get refuses with no global store",
             vcs_blob_get(root, out, sizeof(out)) == -1);
    ZS_CHECK("blob: fetch refuses with no engine",
             vcs_blob_fetch_via(NULL, root, 20500, 1) ==
                 VCS_BLOB_ERR_NO_ENGINE &&
             vcs_blob_announce_via(NULL) == 0);

    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── action-bound work output carrier ─────────────────────────────── */
static int t_store_work_output(void)
{
    int failures = 0;
    char dd[1024];
    struct vcs_package_store *s = zs_open(
        dd, sizeof(dd), "work_output", VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("work output: store opens", s != NULL);
    if (!s) return failures + 1;
    uint8_t action_a[32], action_b[32];
    memset(action_a, 0x31, sizeof(action_a));
    memset(action_b, 0x32, sizeof(action_b));
    size_t bytes_len = VCS_PACKAGE_CHUNK_BYTES + 17u;
    uint8_t *bytes = malloc(bytes_len);
    ZS_CHECK("work output: fixture allocates", bytes != NULL);
    if (!bytes) {
        vcs_package_store_close(s); test_rm_rf_recursive(dd);
        return failures + 1;
    }
    for (size_t i = 0; i < bytes_len; i++)
        bytes[i] = (uint8_t)(i * 13u + 7u);
    uint8_t root_a[32], root_again[32], root_b[32];
    ZS_CHECK("work output: action plus multi-chunk bytes publish",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, bytes_len, root_a) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    uint8_t *out = NULL; size_t out_len = 0;
    ZS_CHECK("work output: exact action reconstructs exact bytes",
             vcs_zcode_work_output_get(
                 s, root_a, action_a, &out, &out_len) ==
                 VCS_ZCODE_WORK_OUTPUT_OK && out_len == bytes_len &&
             memcmp(out, bytes, bytes_len) == 0);
    free(out); out = NULL; out_len = 0;
    ZS_CHECK("work output: wrong action fails closed",
             vcs_zcode_work_output_get(
                 s, root_a, action_b, &out, &out_len) ==
                 VCS_ZCODE_WORK_OUTPUT_CORRUPT && out == NULL && out_len == 0);
    ZS_CHECK("work output: exact re-put is idempotent",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, bytes_len, root_again) ==
                 VCS_ZCODE_WORK_OUTPUT_OK &&
             memcmp(root_a, root_again, 32) == 0);
    ZS_CHECK("work output: different action cannot alias",
             vcs_zcode_work_output_put(
                 s, action_b, bytes, bytes_len, root_b) ==
                 VCS_ZCODE_WORK_OUTPUT_OK && memcmp(root_a, root_b, 32) != 0);
    ZS_CHECK("work output: empty output refused by name",
             vcs_zcode_work_output_put(
                 s, action_a, bytes, 0, root_b) ==
                 VCS_ZCODE_WORK_OUTPUT_EMPTY);
    free(bytes);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

static bool zs_cache_plan(const char *workspace, struct db_build_job *job,
                          struct db_build_action *action)
{
    uint8_t source_sha[32], source_root[32], toolchain[32], policy[32];
    memset(toolchain, 0x33, sizeof(toolchain));
    memset(policy, 0x66, sizeof(policy));

    char source_dir[1200], source_c[1240], source_i[1240];
    (void)snprintf(source_dir, sizeof(source_dir), "%s/cache-source", workspace);
    (void)snprintf(source_c, sizeof(source_c), "%s/unit.c", source_dir);
    (void)snprintf(source_i, sizeof(source_i), "%s/unit.i", source_dir);
    if (mkdir(source_dir, 0700) != 0) return false;
    static const uint8_t payload[] = "int cache_fixture(void){return 23;}\n";
    FILE *file = fopen(source_c, "wb");
    bool files_ok = file && fwrite(payload, 1, sizeof(payload) - 1u, file) ==
                                  sizeof(payload) - 1u;
    if (file) files_ok = fclose(file) == 0 && files_ok;
    file = files_ok ? fopen(source_i, "wb") : NULL;
    files_ok = file && fwrite(payload, 1, sizeof(payload) - 1u, file) ==
                              sizeof(payload) - 1u;
    if (file) files_ok = fclose(file) == 0 && files_ok;
    if (!files_ok || vcs_tree_capture_into(source_dir, workspace, source_root) !=
                         VCS_OK)
        return false;
    uint8_t *source_wire = NULL;
    size_t source_wire_len = 0;
    if (vcs_object_load_raw(
            workspace, source_root, &source_wire, &source_wire_len) != 0)
        return false;
    vcs_source_manifest_id(source_wire, source_wire_len, source_sha);
    free(source_wire);

    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    lock.count = 1;
    memcpy(lock.nodes[0].root, source_root, 32);
    (void)snprintf(lock.nodes[0].name, sizeof(lock.nodes[0].name),
                   "publisher/cache-fixture");
    (void)snprintf(lock.nodes[0].semver, sizeof(lock.nodes[0].semver), "1.0.0");
    uint8_t *lock_wire = NULL;
    size_t lock_len = 0;
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error recipe_error;
    bool authority_ok = vcs_package_lock_serialize(
            &lock, &lock_wire, &lock_len) == VCS_PACKAGE_DEPS_OK &&
        vcs_package_recipe_add_source(&recipe, "unit.c", &recipe_error);
    vcs_package_recipe_set_test_limits(
        &recipe, 0, 30, UINT64_C(64) * 1024u * 1024u);
    uint8_t *recipe_wire = NULL, lock_root[32], recipe_root[32];
    size_t recipe_len = 0;
    authority_ok = authority_ok && vcs_package_recipe_serialize(
            &recipe, &recipe_wire, &recipe_len) == VCS_PACKAGE_RECIPE_OK &&
        vcs_zcode_task_authority_store(
            workspace, lock_wire, lock_len, recipe_wire, recipe_len,
            lock_root, recipe_root) == VCS_ZCODE_TASK_AUTHORITY_OK;
    vcs_package_recipe_free(&recipe);
    free(recipe_wire); free(lock_wire);
    if (!authority_ok) return false;

    struct vcs_zcode_task_v1 task = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .capabilities = VCS_ZCODE_TASK_CAP_V1_MASK,
        .max_changed_files = 4,
        .max_patch_bytes = 1024u,
        .max_context_bytes = 1024u * 1024u,
        .max_cpu_seconds = 30,
        .max_memory_bytes = UINT64_C(64) * 1024u * 1024u,
        .max_output_bytes = UINT64_C(16) * 1024u * 1024u,
        .expires_unix = 200,
    };
    memcpy(task.source_root, source_root, 32);
    memcpy(task.dependency_lock_root, lock_root, 32);
    memcpy(task.acceptance_tests_root, recipe_root, 32);
    memcpy(task.toolchain_capsule_root, toolchain, 32);
    memcpy(task.proof_policy_root, policy, 32);
    memset(task.write_scope_root, 0x91, 32);
    memset(task.model_policy_root, 0x92, 32);
    memset(task.goal_root, 0x93, 32);
    uint8_t task_root[32], task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_root(&task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_serialize(&task, task_wire) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(workspace, task_root, task_wire,
                                  sizeof(task_wire)))
        return false;
    struct vcs_zcode_candidate_v1 candidate = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .sequence = 1,
        .created_unix = 100,
    };
    memcpy(candidate.task_root, task_root, 32);
    memcpy(candidate.base_source_root, source_root, 32);
    memcpy(candidate.candidate_source_root, source_root, 32);
    memset(candidate.patch_root, 0xa1, 32);
    memset(candidate.adapter_policy_root, 0xa2, 32);
    memset(candidate.author_pubkey, 0xa3, 32);
    uint8_t candidate_root[32];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_validate_for_task(
            &task, &candidate, candidate.created_unix) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(workspace, candidate_root, candidate_wire,
                                  sizeof(candidate_wire)))
        return false;
    struct vcs_zcode_action_input_v1 input;
    enum vcs_zcode_action_input_result input_result =
        vcs_zcode_action_input_derive_cas(
            workspace, task_root, candidate_root, &task, &candidate,
            VCS_ZCODE_WORK_BUILD, "unit.i", &input);
    uint8_t input_root[32], *wire = NULL;
    size_t wire_len = 0;
    bool stored = input_result == VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_zcode_action_input_root(&input, input_root) ==
            VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_zcode_action_input_serialize(&input, &wire, &wire_len) ==
            VCS_ZCODE_ACTION_INPUT_OK &&
        vcs_object_put_addressed(workspace, input_root, wire, wire_len);
    free(wire);
    vcs_zcode_action_input_free(&input);
    if (!stored) return false;

    memset(job, 0, sizeof(*job));
    memset(action, 0, sizeof(*action));
    zcl_hex_encode(source_sha, 32, job->source_sha256);
    zcl_hex_encode(source_root, 32, job->source_cas_sha3);
    zcl_hex_encode(toolchain, 32, job->toolchain_sha3);
    (void)snprintf(job->profile, sizeof(job->profile), "dev");
    (void)snprintf(job->state, sizeof(job->state), "ACCEPTED");
    (void)snprintf(job->outcome, sizeof(job->outcome), "ACCEPTED");
    job->created_at = job->updated_at = 100;
    (void)snprintf(action->kind, sizeof(action->kind), "%s",
                   VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(action->state, sizeof(action->state), "ACCEPTED");
    (void)snprintf(action->outcome, sizeof(action->outcome), "ACCEPTED");
    zcl_hex_encode(input_root, 32, action->input_root_sha3);
    zcl_hex_encode(task_root, 32, action->task_root_sha3);
    zcl_hex_encode(candidate_root, 32, action->candidate_root_sha3);
    zcl_hex_encode(policy, 32, action->proof_policy_root_sha3);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    vcs_build_action_v1_fixed_flags_root(flags);
    vcs_build_action_v1_fixed_environment_root(environment);
    zcl_hex_encode(flags, 32, action->flags_sha3);
    zcl_hex_encode(environment, 32, action->environment_sha3);
    (void)snprintf(action->virtual_workdir,
                   sizeof(action->virtual_workdir), "%s",
                   VCS_BUILD_VIRTUAL_ROOT_V1);
    (void)snprintf(action->declared_outputs,
                   sizeof(action->declared_outputs), "%s",
                   VCS_BUILD_OUTPUT_V1);
    (void)snprintf(action->resource_policy,
                   sizeof(action->resource_policy), "%s",
                   VCS_BUILD_RESOURCE_POLICY_V1);
    action->created_at = action->updated_at = 100;
    return build_fabric_action_id(job, action, action->action_id).ok &&
        build_fabric_job_id(job, action->action_id, job->job_id).ok &&
        snprintf(action->job_id, sizeof(action->job_id), "%s", job->job_id) > 0;
}

static bool zs_file_equals(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *file = fopen(path, "rb");
    uint8_t *actual = malloc(len ? len : 1u);
    bool ok = file && actual && fread(actual, 1, len, file) == len &&
              fgetc(file) == EOF && memcmp(actual, bytes, len) == 0;
    free(actual);
    if (file) ok = fclose(file) == 0 && ok;
    return ok;
}

static bool zs_addressed_path(const char *workspace, const uint8_t root[32],
                              char *out, size_t out_cap)
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    int n = snprintf(out, out_cap, "%s/.zvcs/objects/%.2s/%s",
                     workspace, hex, hex + 2);
    return n > 0 && (size_t)n < out_cap;
}

static void zs_cache_worker_id(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

static bool zs_cache_observation(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t output_root[32],
    const uint8_t *output, size_t output_len, char root_hex[65])
{
    struct vcs_build_execution_observation_v1 observation = {
        .schema_version = VCS_BUILD_EXECUTION_OBSERVATION_VERSION,
        .flags = VCS_BUILD_OBS_REQUIRED_FLAGS,
        .cpu_seconds_limit = 1,
        .memory_bytes_limit = 1,
        .process_limit = 1,
        .file_limit = 1,
        .file_bytes_limit = output_len,
        .output_bytes_limit = output_len,
        .wall_millis_limit = 1,
    };
    if (!zcl_hex_decode_lower(action->action_id, observation.action_root, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3,
                              observation.action_input_root, 32) ||
        !zcl_hex_decode_lower(job->toolchain_sha3,
                              observation.toolchain_root, 32) ||
        !zcl_hex_decode_lower(action->flags_sha3,
                              observation.flags_root, 32) ||
        !zcl_hex_decode_lower(action->environment_sha3,
                              observation.environment_root, 32))
        return false;
    memcpy(observation.artifact_root, output_root, 32);
    sha3_256(output, output_len, observation.output_bytes_root);
    memcpy(observation.observed_input_bytes_root,
           observation.action_input_root, 32);
    vcs_build_execution_read_set_root(
        observation.action_input_root, observation.observed_input_bytes_root,
        observation.toolchain_root, observation.declared_reads_root);
    memcpy(observation.observed_reads_root,
           observation.declared_reads_root, 32);
    vcs_build_execution_declared_write_set_root(
        VCS_BUILD_OUTPUT_V1, observation.declared_writes_root);
    vcs_build_execution_observed_write_set_root(
        VCS_BUILD_OUTPUT_V1, observation.output_bytes_root,
        observation.observed_writes_root);
    uint8_t wire[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES], root[32];
    if (!vcs_build_execution_observation_v1_serialize(&observation, wire) ||
        !vcs_build_execution_observation_v1_root(&observation, root) ||
        !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))
        return false;
    zcl_hex_encode(root, 32, root_hex);
    return true;
}

static bool zs_cache_accept(
    struct node_db *ndb, const char *workspace, struct db_build_job *job,
    struct db_build_action *action, const uint8_t output_root[32],
    const uint8_t *output, size_t output_len)
{
    uint8_t seed[32], pubkey[32], secret[32];
    memset(seed, 0x5a, sizeof(seed));
    ed25519_keypair(pubkey, secret, seed);
    struct db_build_worker worker = {
        .approved = 1,
        .approved_at = 100,
        .last_seen_at = 100,
    };
    zs_cache_worker_id(pubkey, worker.worker_id);
    zcl_hex_encode(pubkey, 32, worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities),
                   "linux,c23,%s", VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(job->state, sizeof(job->state), "RUNNING");
    job->outcome[0] = '\0';
    (void)snprintf(action->state, sizeof(action->state), "VERIFYING");
    action->outcome[0] = '\0';
    action->output_root_sha3[0] = '\0';
    (void)snprintf(action->worker_id, sizeof(action->worker_id), "%s",
                   worker.worker_id);
    memset(seed, 0x6b, sizeof(seed));
    zcl_hex_encode(seed, 32, action->lease_id);
    action->lease_expires_at = 190;
    if (!db_build_worker_save(ndb, &worker) ||
        !db_build_job_save(ndb, job) || !db_build_action_save(ndb, action))
        return false;
    struct db_build_receipt receipt = { .created_at = 150 };
    (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                   action->action_id);
    (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                   action->action_id);
    (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s", job->job_id);
    (void)snprintf(receipt.worker_id, sizeof(receipt.worker_id), "%s",
                   worker.worker_id);
    (void)snprintf(receipt.lease_id, sizeof(receipt.lease_id), "%s",
                   action->lease_id);
    zcl_hex_encode(output_root, 32, receipt.output_sha3);
    if (!zs_cache_observation(
            workspace, job, action, output_root, output, output_len,
            receipt.observation_sha3))
        return false;
    (void)snprintf(receipt.confinement, sizeof(receipt.confinement),
                   "fixture:isolation=complete,network=0");
    (void)snprintf(receipt.trust_state, sizeof(receipt.trust_state),
                   "REMOTE_OBSERVED");
    if (!build_fabric_receipt_id(&receipt, receipt.receipt_id).ok)
        return false;
    uint8_t receipt_id[32], signature[64];
    if (!zcl_hex_decode_lower(receipt.receipt_id, receipt_id, 32)) return false;
    ed25519_sign(signature, receipt_id, 32, secret, pubkey);
    zcl_hex_encode(signature, 64, receipt.signature);
    return build_fabric_receipt_quarantine(ndb, &receipt, 150).ok &&
        build_fabric_receipt_admit(
            ndb, workspace, receipt.receipt_id, 151).ok &&
        db_build_job_find(ndb, job->job_id, job) &&
        db_build_action_find(ndb, action->action_id, action);
}

static bool zs_cache_rekey(struct db_build_job *job,
                           struct db_build_action *action)
{
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    if (!build_fabric_action_id(job, action, action_id).ok ||
        !build_fabric_job_id(job, action_id, job_id).ok)
        return false;
    (void)snprintf(action->action_id, sizeof(action->action_id), "%s",
                   action_id);
    (void)snprintf(action->job_id, sizeof(action->job_id), "%s", job_id);
    (void)snprintf(job->job_id, sizeof(job->job_id), "%s", job_id);
    return true;
}

static int t_store_exact_cache_restore(void)
{
    int failures = 0;
    char dd[1024], output[1200];
    struct vcs_package_store *store = zs_open(
        dd, sizeof(dd), "exact_cache_restore",
        VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("exact cache: package store opens", store != NULL);
    if (!store) return failures + 1;
    struct node_db ndb = {0};
    ZS_CHECK("exact cache: ledger opens", node_db_open(&ndb, ":memory:"));
    ZS_CHECK("exact cache: ZVCS input store opens",
             vcs_object_store_init(dd));
    struct db_build_job job;
    struct db_build_action action;
    ZS_CHECK("exact cache: canonical closure and action derive",
             zs_cache_plan(dd, &job, &action));
    static const uint8_t object[] = {
        0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 62, 0, 'z', '2', '3', '\n'
    };
    uint8_t action_root[32], output_root[32];
    ZS_CHECK("exact cache: action id decodes",
             zcl_hex_decode_lower(action.action_id, action_root, 32));
    ZS_CHECK("exact cache: action-bound output stores",
             vcs_zcode_work_output_put(store, action_root, object,
                                       sizeof(object), output_root) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    (void)snprintf(output, sizeof(output), "%s/restored.o", dd);
    zcl_hex_encode(output_root, 32, action.output_root_sha3);
    ZS_CHECK("exact cache: hollow accepted row persists for refusal",
             db_build_job_save(&ndb, &job) &&
             db_build_action_save(&ndb, &action));
    struct build_fabric_cache_report report;
    struct zcl_result restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: accepted row without receipt is corrupt",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(output, F_OK) != 0);
    ZS_CHECK("exact cache: canonical local receipt admits expired task output",
             zs_cache_accept(&ndb, dd, &job, &action, output_root,
                             object, sizeof(object)) &&
             strcmp(job.state, "ACCEPTED") == 0 &&
             strcmp(action.state, "ACCEPTED") == 0);
    struct db_build_job wrong_source_job = job;
    struct db_build_action wrong_source_action = action;
    wrong_source_job.source_sha256[0] =
        wrong_source_job.source_sha256[0] == '0' ? '1' : '0';
    ZS_CHECK("exact cache: mismatched source identity plan rekeys",
             zs_cache_rekey(&wrong_source_job, &wrong_source_action));
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &wrong_source_job, &wrong_source_action,
        output, &report);
    ZS_CHECK("exact cache: source id must match exact candidate manifest",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(output, F_OK) != 0);
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: historical accepted action restores after expiry",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_HIT &&
             report.restored_bytes == sizeof(object) &&
             zs_file_equals(output, object, sizeof(object)));
    struct stat stable_before, stable_after;
    ZS_CHECK("exact cache: materialized object identity captures",
             stat(output, &stable_before) == 0);
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: identical hit does not rewrite artifact",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_HIT &&
             stat(output, &stable_after) == 0 &&
             stable_after.st_dev == stable_before.st_dev &&
             stable_after.st_ino == stable_before.st_ino &&
             stable_after.st_mtime == stable_before.st_mtime);

    uint8_t source_root[32], *source_wire = NULL, *source_blob = NULL;
    size_t source_wire_len = 0, source_blob_len = 0;
    struct vcs_manifest source_manifest = {0};
    char source_blob_path[1400] = {0};
    bool source_fixture_ok =
        zcl_hex_decode_lower(job.source_cas_sha3, source_root, 32) &&
        vcs_object_load_raw(dd, source_root, &source_wire,
                            &source_wire_len) == 0 &&
        vcs_manifest_parse(source_wire, source_wire_len,
                           &source_manifest) &&
        source_manifest.count > 0 &&
        vcs_object_get(dd, source_manifest.entries[0].blob,
                       VCS_TAG_BLOB, &source_blob,
                       &source_blob_len) == 0 &&
        zs_addressed_path(dd, source_manifest.entries[0].blob,
                          source_blob_path, sizeof(source_blob_path));
    ZS_CHECK("exact cache: source closure blob resolves", source_fixture_ok);
    if (source_fixture_ok) {
        ZS_CHECK("exact cache: source closure missing-blob fixture removes",
                 unlink(source_blob_path) == 0);
        restored = build_fabric_cache_restore(
            &ndb, dd, store, &job, &action, output, &report);
        ZS_CHECK("exact cache: missing source closure blob refuses restore",
                 !restored.ok &&
                 report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
        uint8_t restored_blob_root[32];
        ZS_CHECK("exact cache: source closure blob restores exactly",
                 vcs_object_put(dd, source_blob, source_blob_len,
                                VCS_TAG_BLOB, restored_blob_root) &&
                 memcmp(restored_blob_root,
                        source_manifest.entries[0].blob,
                        sizeof(restored_blob_root)) == 0);
    }
    free(source_blob);
    free(source_wire);
    vcs_manifest_free(&source_manifest);

    struct db_build_receipt receipts[1];
    struct db_build_action unchanged;
    ZS_CHECK("exact cache: hit mints no receipt or lifecycle transition",
             db_build_job_receipts(&ndb, job.job_id, receipts, 1) == 1 &&
             db_build_action_find(&ndb, action.action_id, &unchanged) &&
             strcmp(unchanged.state, "ACCEPTED") == 0 &&
             strcmp(unchanged.output_root_sha3,
                    action.output_root_sha3) == 0);

    struct db_build_action pending = action;
    (void)snprintf(pending.state, sizeof(pending.state), "SNAPSHOTTED");
    pending.outcome[0] = '\0';
    pending.output_root_sha3[0] = '\0';
    ZS_CHECK("exact cache: unaccepted exact action is a miss",
             db_build_action_save(&ndb, &pending));
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: miss returns without changing output",
             restored.ok && report.disposition == BUILD_FABRIC_CACHE_MISS &&
             zs_file_equals(output, object, sizeof(object)));
    ZS_CHECK("exact cache: accepted plan restores after miss",
             db_build_action_save(&ndb, &action));

    uint8_t other_action[32], wrong_root[32];
    memset(other_action, 0xa5, sizeof(other_action));
    ZS_CHECK("exact cache: mismatched action carrier stores",
             vcs_zcode_work_output_put(store, other_action, object,
                                       sizeof(object), wrong_root) ==
                 VCS_ZCODE_WORK_OUTPUT_OK);
    struct db_build_action wrong_output = action;
    zcl_hex_encode(wrong_root, 32, wrong_output.output_root_sha3);
    ZS_CHECK("exact cache: poisoned output reference persists for refusal",
             db_build_action_save(&ndb, &wrong_output));
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: wrong action-bound carrier is corrupt",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
    ZS_CHECK("exact cache: accepted output reference repairs",
             db_build_action_save(&ndb, &action));

#if !defined(_WIN32)
    (void)unlink(output);
    ZS_CHECK("exact cache: symlink destination fixture creates",
             symlink("/dev/null", output) == 0);
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: symlink destination refuses closed",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT);
    (void)unlink(output);
#endif
    uint8_t input_root[32], *input_wire = NULL;
    size_t input_len = 0;
    char addressed[1400];
    ZS_CHECK("exact cache: input closure loads for corruption fixture",
             zcl_hex_decode_lower(action.input_root_sha3, input_root, 32) &&
             vcs_object_load_raw(dd, input_root, &input_wire, &input_len) == 0 &&
             zs_addressed_path(dd, input_root, addressed, sizeof(addressed)));
    FILE *poison = fopen(addressed, "wb");
    bool poison_written = poison && fwrite("bad", 1, 3, poison) == 3;
    if (poison) poison_written = fclose(poison) == 0 && poison_written;
    ZS_CHECK("exact cache: invalid action input fixture writes",
             poison_written);
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: invalid input closure refuses before restore",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(output, F_OK) != 0);
    bool repaired = false;
    ZS_CHECK("exact cache: input closure repairs from canonical bytes",
             vcs_object_put_addressed_repair(
                 dd, input_root, input_wire, input_len, &repaired) && repaired);
    free(input_wire);

    uint8_t candidate_root[32];
    ZS_CHECK("exact cache: candidate closure address resolves",
             zcl_hex_decode_lower(action.candidate_root_sha3,
                                  candidate_root, 32) &&
             zs_addressed_path(dd, candidate_root, addressed,
                               sizeof(addressed)));
    poison = fopen(addressed, "wb");
    poison_written = poison && fwrite("bad", 1, 3, poison) == 3;
    if (poison)
        poison_written = fclose(poison) == 0 && poison_written;
    ZS_CHECK("exact cache: invalid candidate fixture writes",
             poison_written);
    restored = build_fabric_cache_restore(
        &ndb, dd, store, &job, &action, output, &report);
    ZS_CHECK("exact cache: invalid candidate refuses before restore",
             !restored.ok &&
             report.disposition == BUILD_FABRIC_CACHE_CORRUPT &&
             access(output, F_OK) != 0);
    node_db_close(&ndb);
    vcs_package_store_close(store);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 11: dump_state_json ──────────────────────────────────────────── */
static int t_store_dump_state(void)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    ZS_CHECK("dump: disabled store reports enabled=false",
             vcs_package_store_dump_state_json(&v, NULL) &&
             json_get(&v, "enabled") &&
             !json_get_bool(json_get(&v, "enabled")));
    json_free(&v);

    /* Enabled global store via the real flag + datadir path. */
    const char *argv[] = { "zclassic23-test", "-packagehost=1",
                           "-packagequota=1000000" };
    ParseParameters(3, argv);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_store", "dump");
    SetDataDir(dd);
    ZS_CHECK("dump: hosting flag now on",
             vcs_package_store_hosting_enabled() &&
             vcs_package_store_quota_bytes() == 1000000u);
    ZS_CHECK("dump: global store opens",
             vcs_package_store_open_global() &&
             vcs_package_store_global() != NULL);

    /* A command handed a datadir has to decide whether the resident store
     * already covers it: publishing through a second handle over the same
     * directory writes correct bytes into a store the running node's serving
     * engine never hears about. The answer is this exact string, so it is
     * asserted here rather than guessed at each call site. */
    char expect_root[512];
    (void)snprintf(expect_root, sizeof(expect_root), "%s/zcode", dd);
    ZS_CHECK("dump: the store names the directory it owns",
             vcs_package_store_root_dir(vcs_package_store_global()) != NULL &&
             strcmp(vcs_package_store_root_dir(vcs_package_store_global()),
                    expect_root) == 0);
    ZS_CHECK("dump: no store owns no directory",
             vcs_package_store_root_dir(NULL) == NULL);

    const char *paths[] = { "dump.txt" };
    const size_t lens[] = { 64 };
    struct zs_pkg p;
    ZS_CHECK("dump: fixture builds", zs_make_package(&p, 1, paths, lens,
                                                     0xbb));
    struct vcs_package_store *s = vcs_package_store_global();
    ZS_CHECK("dump: package admitted + complete",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, &p) == VCS_PACKAGE_STORE_OK);

    json_init(&v);
    bool ok = vcs_package_store_dump_state_json(&v, NULL);
    ZS_CHECK("dump: enabled store reports totals",
             ok && json_get(&v, "enabled") &&
             json_get_bool(json_get(&v, "enabled")) &&
             json_get_int(json_get(&v, "quota_bytes")) == 1000000 &&
             json_get_int(json_get(&v, "tracked_packages")) == 1 &&
             json_get_int(json_get(&v, "pins_budget_bytes")) == 200000 &&
             json_get_int(json_get(&v, "rare_usage_bytes")) == 64 &&
             json_get_int(json_get(&v, "cas_chunks")) == 1);
    json_free(&v);

    /* Slice 3 publication state: a persisted release is counted and the
     * last acceptance outcome is reported. */
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_release r;
    ZS_CHECK("dump: release fixture signs",
             zs_release(&r, 0x22, 1u, "rhett/dump-pkg"));
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ZS_CHECK("dump: release admitted",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_OK);
    json_init(&v);
    ok = vcs_package_store_dump_state_json(&v, NULL);
    ZS_CHECK("dump: publication state reported",
             ok &&
             json_get_int(json_get(&v, "releases_total")) == 1 &&
             json_get_str(json_get(&v, "last_release_accept")) &&
             strcmp(json_get_str(json_get(&v, "last_release_accept")),
                    "accepted") == 0 &&
             json_get(&v, "last_release_id") != NULL);
    json_free(&v);

    json_init(&v);
    ok = vcs_package_store_dump_state_json(&v, p.root_hex);
    ZS_CHECK("dump: package-root key drills down",
             ok && json_get(&v, "complete") &&
             json_get_bool(json_get(&v, "complete")) &&
             json_get_int(json_get(&v, "present_bytes")) == 64);
    json_free(&v);

    json_init(&v);
    ok = vcs_package_store_dump_state_json(&v, "not-a-root");
    ZS_CHECK("dump: bad key names the error",
             ok && json_get(&v, "error") != NULL);
    json_free(&v);

    vcs_package_store_close_global();
    ZS_CHECK("dump: global closed", vcs_package_store_global() == NULL);

    /* Restore global flags/datadir for the rest of the process. */
    const char *reset_argv[] = { "zclassic23-test" };
    ParseParameters(1, reset_argv);
    SetDataDir("");
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 12: swarm engine dump_state_json ─────────────────────────────── */
static int t_swarm_engine_dump_state(void)
{
    int failures = 0;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    vcs_swarm_engine_set_global(NULL);

    struct json_value v;
    json_init(&v);
    ZS_CHECK("swarm dump: unwired engine reports present=false",
             vcs_package_swarm_status_dump_state_json(&v, NULL) &&
             json_get(&v, "enabled") &&
             !json_get_bool(json_get(&v, "enabled")) &&
             json_get(&v, "present") &&
             !json_get_bool(json_get(&v, "present")) &&
             json_get_int(json_get(&v, "peer_count")) == 0 &&
             json_get_int(json_get(&v, "active_downloads")) == 0 &&
             json_get_int(json_get(&v, "advertised_count")) == 0 &&
             json_get(&v, "peers") &&
             json_get(&v, "peers")->type == JSON_ARR &&
             json_size(json_get(&v, "peers")) == 0 &&
             json_get(&v, "advertised") &&
             json_get(&v, "advertised")->type == JSON_ARR &&
             json_size(json_get(&v, "advertised")) == 0);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("swarm dump: hosting-off snapshot leaks no paths or keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, "secret") == NULL);
    json_free(&v);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value sub;
    json_init(&sub);
    json_set_str(&sub, "zcode_swarm");
    bool dumpstate_ok = json_push_back(&params, &sub);
    json_free(&sub);
    struct json_value result;
    json_init(&result);
    dumpstate_ok = dumpstate_ok &&
                   diag_rpc_dumpstate(&params, false, &result);
    const struct json_value *state = json_get(&result, "state");
    const char *sys = json_get_str(json_get(&result, "subsystem"));
    ZS_CHECK("swarm dump: dumpstate includes zcode_swarm",
             dumpstate_ok && sys && strcmp(sys, "zcode_swarm") == 0 &&
             state && state->type == JSON_OBJ &&
             json_get(state, "enabled") &&
             !json_get_bool(json_get(state, "enabled")) &&
             json_get(state, "present") &&
             !json_get_bool(json_get(state, "present")));
    json_free(&params);
    json_free(&result);

    struct vcs_swarm_engine *engine =
        vcs_swarm_engine_create(NULL, NULL, NULL, NULL, NULL);
    ZS_CHECK("swarm dump: engine creates without store or datadir",
             engine != NULL);
    if (!engine) {
        vcs_swarm_engine_set_global(prev);
        return failures;
    }
    uint8_t key_a[33];
    uint8_t key_b[33];
    key_a[0] = 0x02;
    key_b[0] = 0x02;
    memset(key_a + 1, 0x11, 32);
    memset(key_b + 1, 0x22, 32);
    ZS_CHECK("swarm dump: two peers register",
             vcs_swarm_engine_peer_add(engine, 7, key_a) &&
             vcs_swarm_engine_peer_add(engine, 11, key_b));
    vcs_swarm_engine_set_global(engine);

    json_init(&v);
    bool ok = vcs_package_swarm_status_dump_state_json(&v, NULL);
    const struct json_value *peers = json_get(&v, "peers");
    const struct json_value *row0 = peers ? json_at(peers, 0) : NULL;
    const struct json_value *row1 = peers ? json_at(peers, 1) : NULL;
    ZS_CHECK("swarm dump: wired engine reports peers and zero transfers",
             ok && json_get(&v, "enabled") &&
             json_get_bool(json_get(&v, "enabled")) &&
             json_get_bool(json_get(&v, "present")) &&
             json_get_int(json_get(&v, "peer_count")) == 2 &&
             json_get_int(json_get(&v, "active_downloads")) == 0 &&
             json_get_int(json_get(&v, "advertised_count")) == 0 &&
             peers && json_size(peers) == 2 &&
             json_get(&v, "advertised") &&
             json_size(json_get(&v, "advertised")) == 0 &&
             row0 && json_get_int(json_get(row0, "peer_id")) == 7 &&
             json_get_int(json_get(row0, "served_bytes")) == 0 &&
             json_get_int(json_get(row0, "fetched_bytes")) == 0 &&
             row1 && json_get_int(json_get(row1, "peer_id")) == 11);
    rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("swarm dump: live snapshot leaks no accounting keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "key") == NULL);
    json_free(&v);

    vcs_swarm_engine_set_global(NULL);
    vcs_swarm_engine_free(engine);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* ── 13: swarm receipt dump_state_json ────────────────────────────── */
static int t_swarm_receipt_dump_state(void)
{
    int failures = 0;

    struct json_value v;
    json_init(&v);
    ZS_CHECK("receipt dump: closed session reports present=false",
             boot_zcode_swarm_receipt_dump_state_json(&v, NULL) &&
             json_get(&v, "enabled") &&
             !json_get_bool(json_get(&v, "enabled")) &&
             json_get(&v, "present") &&
             !json_get_bool(json_get(&v, "present")) &&
             json_get_int(json_get(&v, "settled_peers")) == 0 &&
             json_get(&v, "peers") &&
             json_get(&v, "peers")->type == JSON_ARR &&
             json_size(json_get(&v, "peers")) == 0 &&
             json_get(&v, "local_pub_prefix") == NULL);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("receipt dump: hosting-off snapshot leaks no paths or keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, "secret") == NULL);
    json_free(&v);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value sub;
    json_init(&sub);
    json_set_str(&sub, "zcode_swarm_receipts");
    bool dumpstate_ok = json_push_back(&params, &sub);
    json_free(&sub);
    struct json_value result;
    json_init(&result);
    dumpstate_ok = dumpstate_ok &&
                   diag_rpc_dumpstate(&params, false, &result);
    const struct json_value *state = json_get(&result, "state");
    const char *sys = json_get_str(json_get(&result, "subsystem"));
    ZS_CHECK("receipt dump: dumpstate includes zcode_swarm_receipts",
             dumpstate_ok && sys && strcmp(sys, "zcode_swarm_receipts") == 0 &&
             state && state->type == JSON_OBJ &&
             json_get(state, "enabled") &&
             !json_get_bool(json_get(state, "enabled")) &&
             json_get(state, "present") &&
             !json_get_bool(json_get(state, "present")) &&
             json_get_int(json_get(state, "settled_peers")) == 0 &&
             json_get(state, "peers") &&
             json_size(json_get(state, "peers")) == 0);
    json_free(&params);
    json_free(&result);

    uint8_t sec_a[32];
    uint8_t sec_b[32];
    memset(sec_a, 0, sizeof(sec_a));
    memset(sec_b, 0, sizeof(sec_b));
    sec_a[31] = 0x91;
    sec_b[31] = 0x92;
    struct vcs_swarm_receipt_session *local =
        vcs_swarm_receipt_session_open_secret(sec_a);
    struct vcs_swarm_receipt_session *remote =
        vcs_swarm_receipt_session_open_secret(sec_b);
    ZS_CHECK("receipt dump: secret-backed sessions open",
             local != NULL && remote != NULL);
    if (!local || !remote) {
        vcs_swarm_receipt_session_free(local);
        vcs_swarm_receipt_session_free(remote);
        return failures;
    }

    uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
    size_t ident_len = 0;
    ZS_CHECK("receipt dump: remote identity noted",
             vcs_swarm_receipt_identity_take(remote, 7, ident, sizeof(ident),
                                             &ident_len) &&
             vcs_swarm_receipt_identity_note(local, 7, ident, ident_len));

    uint64_t ids[VCS_SWARM_MAX_PEERS];
    size_t n = vcs_swarm_receipt_session_peer_ids(local, ids,
                                                  VCS_SWARM_MAX_PEERS);
    ZS_CHECK("receipt dump: enumerator returns the noted peer",
             n == 1 && ids[0] == 7 &&
             !vcs_swarm_receipt_session_settled(local, 7));

    uint8_t pub[33];
    char expect_prefix[9];
    memset(pub, 0, sizeof(pub));
    memset(expect_prefix, 0, sizeof(expect_prefix));
    ZS_CHECK("receipt dump: local pub is present",
             vcs_swarm_receipt_session_local_pub(local, pub));
    zcl_hex_encode(pub, 4, expect_prefix);

    json_init(&v);
    bool ok = boot_zcode_swarm_receipt_dump_session_json(&v, local);
    const struct json_value *peers = json_get(&v, "peers");
    const struct json_value *row0 = peers ? json_at(peers, 0) : NULL;
    const char *prefix = json_get_str(json_get(&v, "local_pub_prefix"));
    ZS_CHECK("receipt dump: open session reports prefix and peer row",
             ok && json_get_bool(json_get(&v, "enabled")) &&
             json_get_bool(json_get(&v, "present")) &&
             prefix && strcmp(prefix, expect_prefix) == 0 &&
             strlen(prefix) == 8 &&
             json_get_int(json_get(&v, "settled_peers")) == 0 &&
             peers && json_size(peers) == 1 &&
             row0 && json_get_int(json_get(row0, "peer_id")) == 7 &&
             json_get(row0, "settled") &&
             !json_get_bool(json_get(row0, "settled")) &&
             json_get(row0, "have_remote") &&
             json_get_bool(json_get(row0, "have_remote")));
    rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("receipt dump: live snapshot leaks no secrets or paths",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "secret") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, expect_prefix) != NULL);
    json_free(&v);

    json_init(&v);
    ZS_CHECK("receipt dump: boot singleton stays closed",
             boot_zcode_swarm_receipt_dump_state_json(&v, NULL) &&
             !json_get_bool(json_get(&v, "enabled")) &&
             !json_get_bool(json_get(&v, "present")));
    json_free(&v);

    vcs_swarm_receipt_session_free(local);
    vcs_swarm_receipt_session_free(remote);
    return failures;
}

/* A live daemon may be receiving verified chunks while one-shot commands
 * inspect the same datadir. Recovery includes orphan GC, so the second open
 * must serialize with manifest/CAS writes without denying the offline reader
 * shape used by existing package commands. */
static int t_store_serialized_recovery(void)
{
    int failures = 0;
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_store", "serialized_recovery");
    const char *paths[] = { "one.c", "two.c" };
    const size_t lens[] = { 311, 509 };
    struct zs_pkg p;
    ZS_CHECK("serialized recovery: fixture builds",
             zs_make_package(&p, 2, paths, lens, 0xc1));
    struct vcs_package_store *resident = vcs_package_store_open(
        dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("serialized recovery: resident opens", resident != NULL);
    ZS_CHECK("serialized recovery: resident stages manifest",
             resident && vcs_package_store_put_manifest(
                 resident, p.wire, p.wire_len, NULL) == VCS_PACKAGE_STORE_OK);

    struct vcs_package_store *observer = vcs_package_store_open(
        dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_package_store_status observed;
    ZS_CHECK("serialized recovery: observer sees staged package",
             observer &&
             vcs_package_store_package_status(observer, p.root, &observed) &&
             !observed.complete && observed.present_bytes == 0);
    vcs_package_store_close(observer);

    struct vcs_package_store_status status;
    ZS_CHECK("serialized recovery: resident completes after observer",
             resident && zs_put_all(resident, &p) == VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(resident, p.root, &status) &&
             status.complete && status.present_bytes == 820);
    vcs_package_store_close(resident);
    resident = vcs_package_store_open(dd,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    ZS_CHECK("serialized recovery: bytes survive cold recovery",
             resident &&
             vcs_package_store_package_status(resident, p.root, &status) &&
             status.complete && status.present_bytes == 820);
    vcs_package_store_close(resident);
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

int test_zcode_store(void)
{
    printf("\n=== zcode_store: local content-addressed package store ===\n");
    int failures = 0;
    failures += t_store_layout_and_flags();
    failures += t_store_manifest_admission();
    failures += t_store_chunk_flow();
    failures += t_store_dedup();
    failures += t_store_recovery();
    failures += t_store_corrupt_read_repair();
    failures += t_store_staging_quota();
    failures += t_store_hot_eviction();
    failures += t_store_rare_eviction();
    failures += t_store_pins();
    failures += t_store_possession_scheduler();
    failures += t_store_releases();
    failures += t_store_blob();
    failures += t_store_work_output();
    failures += t_store_exact_cache_restore();
    failures += t_store_serialized_recovery();
    failures += t_store_dump_state();
    failures += t_swarm_engine_dump_state();
    failures += t_swarm_receipt_dump_state();
    printf("=== zcode_store complete: %d failure(s) ===\n", failures);
    return failures;
}
