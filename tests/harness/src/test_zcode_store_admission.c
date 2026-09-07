/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_store scenario checks: flags/layout, manifest admission, chunk
 * flow, dedup, crash recovery (resumable staging, temp sweep, orphan
 * GC, commit-at-open sweep), corrupt-read repair, and serialized
 * (concurrency-safe) recovery.
 *
 * Split out of test_zcode_store.c (which keeps the includes, the
 * fixture helpers shared across siblings, the dump_state scenarios,
 * and the group entry point) so no family member crosses the
 * 1,500-line ceiling. */

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

#include "test/test_zcode_store_priv.h"

/* ── 1: flags, layout, strings ────────────────────────────────────── */
int t_store_layout_and_flags(void)
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
static int store_case_manifest_hostile_wires(struct vcs_package_store *s,
                                             struct zs_pkg *p)
{
    int failures = 0;
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
             vcs_package_store_put_manifest(NULL, p->wire, p->wire_len,
                                            NULL) ==
                 VCS_PACKAGE_STORE_ERR_NULL &&
             vcs_package_store_put_manifest(s, NULL, p->wire_len, NULL) ==
                 VCS_PACKAGE_STORE_ERR_NULL);
    return failures;
}

static int store_case_manifest_oversized_cap(struct vcs_package_store *s,
                                              const uint8_t *fake_hashes)
{
    int failures = 0;
    /* The 64 MiB v1 cap: 64 MiB + 1 is refused. Fake hashes are
     * per-chunk distinct so nothing dedupes away. */
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
    return failures;
}

static int store_case_manifest_exact_cap(const uint8_t *fake_hashes)
{
    int failures = 0;
    /* Exactly 64 MiB admits. */
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
    return failures;
}

static int store_case_manifest_quota_infeasible(struct vcs_package_store *s,
                                                 const uint8_t *fake_hashes)
{
    int failures = 0;
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
    return failures;
}

int t_store_manifest_admission(void)
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

    failures += store_case_manifest_hostile_wires(s, &p);

    static uint8_t fake_hashes[65 * 32];
    for (int i = 0; i < 65; i++)
        memset(fake_hashes + i * 32, i + 1, 32);
    failures += store_case_manifest_oversized_cap(s, fake_hashes);
    failures += store_case_manifest_exact_cap(fake_hashes);
    failures += store_case_manifest_quota_infeasible(s, fake_hashes);

    zs_free_package(&p);
    vcs_package_store_close(s);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 3: chunk flow ────────────────────────────────────────────────── */
int t_store_chunk_flow(void)
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
int t_store_dedup(void)
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
struct store_recovery_debris {
    char debris[512];
    char live_temp[512];
    char orphan[512];
};

static int store_case_recovery_plant_debris(const char *dd,
                                             struct store_recovery_debris *out)
{
    int failures = 0;
    /* Crash debris: a dead-owner torn temp, a live-owner in-flight temp,
     * and an orphan CAS object. Recovery must never unlink another live
     * store owner's atomic write. */
    char live_suffix[96];
    zs_store_path(out->debris, sizeof(out->debris), dd,
                  "cas/torn.zstmp.2147483647.1");
    FILE *f = fopen(out->debris, "wb");
    ZS_CHECK("recovery: temp debris planted", f != NULL);
    if (f) {
        fwrite("x", 1, 1, f);
        fclose(f);
    }
    snprintf(live_suffix, sizeof(live_suffix),
             "cas/live.zstmp.%ld.2", (long)getpid());
    zs_store_path(out->live_temp, sizeof(out->live_temp), dd, live_suffix);
    f = fopen(out->live_temp, "wb");
    ZS_CHECK("recovery: live-owner temp planted", f != NULL);
    if (f) {
        fwrite("active", 1, 6, f);
        fclose(f);
    }
    char orphan_hex[65];
    memset(orphan_hex, '5', 64);
    orphan_hex[64] = '\0';
    char orphan_dir[512];
    zs_store_path(orphan_dir, sizeof(orphan_dir), dd, "cas/sha3/55");
    snprintf(out->orphan, sizeof(out->orphan), "%s/%s", orphan_dir,
             orphan_hex);
    ZS_CHECK("recovery: orphan directory planted",
             mkdir(orphan_dir, 0700) == 0);
    f = fopen(out->orphan, "wb");
    ZS_CHECK("recovery: orphan chunk planted", f != NULL);
    if (f) {
        fwrite("orphan", 1, 6, f);
        fclose(f);
    }
    return failures;
}

static int store_case_recovery_reopen_and_resume(
    const char *dd, struct zs_pkg *p, struct store_recovery_debris *deb,
    bool *reopened)
{
    int failures = 0;
    struct vcs_package_store *s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("recovery: store reopens", s != NULL);
    *reopened = (s != NULL);
    if (!s)
        return failures;
    ZS_CHECK("recovery: torn temp swept", !zs_path_exists(deb->debris));
    ZS_CHECK("recovery: live-owner temp is not swept",
             zs_path_exists(deb->live_temp));
    (void)unlink(deb->live_temp);
    ZS_CHECK("recovery: orphan chunk GC'd", !zs_path_exists(deb->orphan));
    struct vcs_package_store_status st;
    ZS_CHECK("recovery: staging resumes (manifest + chunk kept)",
             vcs_package_store_package_status(s, p->root, &st) &&
             st.tracked && !st.complete && st.present_chunks == 1 &&
             st.present_bytes == 100 &&
             st.pool == VCS_PACKAGE_STORE_POOL_STAGING);
    ZS_CHECK("recovery: resumed package completes + commits",
             vcs_package_store_put_chunk(s, p->root, "r2.bin", 0,
                                         p->contents[1], p->lens[1]) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_package_store_package_status(s, p->root, &st) &&
             st.complete && st.pool == VCS_PACKAGE_STORE_POOL_RARE);
    vcs_package_store_close(s);
    return failures;
}

static int store_case_recovery_commit_at_open_sweep(const char *dd,
                                                     struct zs_pkg *p)
{
    int failures = 0;
    /* Commit-at-open sweep: a staged manifest whose chunks are all
     * present commits during recovery (crash between last chunk and
     * commit). Simulate by moving the committed manifest back to
     * staging. */
    char committed[512];
    char staging_dir[512];
    char staged[512];
    char suffix[160];
    snprintf(suffix, sizeof(suffix), "manifests/%s", p->root_hex);
    zs_store_path(committed, sizeof(committed), dd, suffix);
    snprintf(suffix, sizeof(suffix), "staging/%s", p->root_hex);
    zs_store_path(staging_dir, sizeof(staging_dir), dd, suffix);
    snprintf(staged, sizeof(staged), "%s/manifest", staging_dir);
    ZS_CHECK("recovery: un-commit simulation",
             zs_path_exists(committed) && mkdir(staging_dir, 0700) == 0 &&
             rename(committed, staged) == 0);
    struct vcs_package_store *s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("recovery: store reopens for the sweep", s != NULL);
    if (s) {
        struct vcs_package_store_status st;
        ZS_CHECK("recovery: CAS-complete staged package committed at open",
                 zs_path_exists(committed) && !zs_path_exists(staging_dir));
        ZS_CHECK("recovery: completion rebuilt from the CAS",
                 vcs_package_store_package_status(s, p->root, &st) &&
                 st.complete && st.present_bytes == 300);
        vcs_package_store_close(s);
    }
    return failures;
}

int t_store_recovery(void)
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

    struct store_recovery_debris deb;
    failures += store_case_recovery_plant_debris(dd, &deb);
    bool reopened = false;
    failures += store_case_recovery_reopen_and_resume(dd, &p, &deb,
                                                       &reopened);
    if (!reopened) {
        test_rm_rf_recursive(dd);
        return failures;
    }
    failures += store_case_recovery_commit_at_open_sweep(dd, &p);

    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* A content-addressed filename is a claim, not proof. A same-sized local
 * corruption must become a missing swarm coordinate after the first read so
 * a surviving provider can repair it; leaving it in the presence set wedges
 * restart/resume forever. */
static int store_case_corrupt_repair_missing_coordinate(
    struct vcs_package_store *s, struct zs_pkg *p, const char *path0,
    const char *cas_path)
{
    int failures = 0;
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("corrupt repair: read refuses address-mismatched bytes",
             s && vcs_package_store_get_chunk(
                      s, p->root, path0, 0, &got, &got_len) ==
                      VCS_PACKAGE_STORE_ERR_CHUNK_HASH &&
                 got == NULL && got_len == 0);
    struct vcs_package_store_status st;
    ZS_CHECK("corrupt repair: bad object becomes a missing coordinate",
             s && !zs_path_exists(cas_path) &&
                 !vcs_package_store_chunk_present(s, p->root, 0, 0) &&
                 vcs_package_store_package_status(s, p->root, &st) &&
                 !st.complete && st.present_chunks == 0);
    return failures;
}

static int store_case_corrupt_repair_reads_identically(
    struct vcs_package_store *s, struct zs_pkg *p, const char *path0)
{
    int failures = 0;
    struct vcs_package_store_status st;
    ZS_CHECK("corrupt repair: verified provider bytes repair the package",
             s && vcs_package_store_put_chunk(
                      s, p->root, path0, 0, p->contents[0], p->lens[0]) ==
                      VCS_PACKAGE_STORE_OK &&
                 vcs_package_store_package_status(s, p->root, &st) &&
                 st.complete && st.present_chunks == 1);
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("corrupt repair: repaired bytes read identically",
             s && vcs_package_store_get_chunk(
                 s, p->root, path0, 0, &got, &got_len) ==
                     VCS_PACKAGE_STORE_OK &&
                 got_len == p->lens[0] &&
                 memcmp(got, p->contents[0], got_len) == 0);
    free(got);
    return failures;
}

static int store_case_corrupt_repair_reopen_and_repair(
    const char *dd, struct zs_pkg *p, const char *path0,
    const char *cas_path)
{
    int failures = 0;
    struct vcs_package_store *s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("corrupt repair: store reopens", s != NULL);
    failures += store_case_corrupt_repair_missing_coordinate(s, p, path0,
                                                              cas_path);
    failures += store_case_corrupt_repair_reads_identically(s, p, path0);
    vcs_package_store_close(s);
    return failures;
}

int t_store_corrupt_read_repair(void)
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

    failures += store_case_corrupt_repair_reopen_and_repair(dd, &p,
                                                             paths[0],
                                                             cas_path);
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* A live daemon may be receiving verified chunks while one-shot commands
 * inspect the same datadir. Recovery includes orphan GC, so the second open
 * must serialize with manifest/CAS writes without denying the offline reader
 * shape used by existing package commands. */
int t_store_serialized_recovery(void)
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

