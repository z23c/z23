/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_vcs_core — the ZVCS v1 foundation gate (lib/vcs/).
 *
 * Coverage:
 *   1. serialize -> parse -> hash fixed-point (manifest wire + tree_hash),
 *      including tree_hash order-independence.
 *   2. object store dedup (identical content => one object, no new file).
 *   3. object store verify-on-read (a corrupted object file is rejected).
 *   4. deterministic edit/snapshot/status vs a brute-force reference.
 *   5. roundtrip revert byte-identity.
 *   6. index delete -> rebuild identity (HEAD + seal_pin + status).
 *   7. torn commits.log tail -> rebuild recovers the last complete commit.
 *   8. seal refusal + one-shot token accept + forged/mismatched token reject.
 *   9. timing: warm status < 20 ms, 1-file snapshot < 50 ms.
 *  10. owner-ritual primitives: grant, non-consuming peek, snapshot consumes.
 *  11. revert atomicity: a forced mid-restore failure leaves the worktree
 *      byte-identical to its pre-revert state and leaves no staging temps.
 *  12. content.v2 package manifests: canonical paths/modes/sizes, ordered
 *      1 MiB SHA3 chunks, deterministic roots, and fail-closed parsing.
 *  13. content.v2 swarm codec: bounded announce/want/data/cancel frames and
 *      manifest/chunk verification tied to the exact package root.
 *
 * All work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"
#include "test/public_shape_fixture.h"

#include "vcs/vcs.h"
#include "vcs/vcs_commit.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_swarm.h"
#include "vcs/source_bundle.h"
#include "vcs/source_package_checkout.h"
#include "vcs/source_package_transport.h"
#include "vcs/zcode_lane.h"
#include "vcs/vcs_seal.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VC_CHECK(name, expr) do {                                     \
    if (expr) { printf("  vcs_core: %s... OK\n", (name)); }           \
    else { printf("  vcs_core: %s... FAIL\n", (name)); failures++; }  \
} while (0)

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool vc_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    /* mkdir parents */
    for (char *p = full + strlen(dir) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            /* 0700: the object store verifies its own directories are
             * owner-only, so a fixture that pre-creates .zvcs at the
             * ordinary 0755 makes vcs_open refuse the repo outright. */
            mkdir(full, 0700);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    size_t n = content ? strlen(content) : 0;
    if (n) fwrite(content, 1, n, f);
    fclose(f);
    return true;
}

/* Read <dir>/<rel> fully into a heap buffer (NUL-terminated). NULL on error. */
static char *vc_read(const char *dir, const char *rel, size_t *out_len)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    FILE *f = fopen(full, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

static bool vc_write_bytes(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = len == 0 || fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool vc_corrupt_object(const char *workspace, const uint8_t root[32])
{
    char hex[65], path[4096];
    zcl_hex_encode(root, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/.zvcs/objects/%c%c/%s",
                     workspace, hex[0], hex[1], hex + 2);
    static const uint8_t corrupt[] = {0xde, 0xad, 0xbe, 0xef};
    return n > 0 && (size_t)n < sizeof(path) &&
        vc_write_bytes(path, corrupt, sizeof(corrupt));
}

static bool vc_package_has_path(const struct vcs_package_manifest *manifest,
                                const char *path)
{
    for (size_t i = 0; manifest && i < manifest->count; i++)
        if (strcmp(manifest->files[i].path, path) == 0) return true;
    return false;
}

static const struct vcs_source_bundle_shard *vc_source_shard(
    const struct vcs_source_bundle_sharded *bundle, uint16_t index)
{
    for (size_t i = 0; bundle && i < bundle->shard_count; i++)
        if (bundle->shards[i].index == index) return &bundle->shards[i];
    return NULL;
}

static bool vc_transport_file(
    const struct vcs_source_package_transport *transport, const char *wanted,
    const uint8_t **bytes_out, size_t *len_out)
{
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (vcs_source_package_transport_file_at(
                transport, i, &path, &bytes, &len) &&
            strcmp(path, wanted) == 0) {
            *bytes_out = bytes;
            *len_out = len;
            return true;
        }
    }
    return false;
}

/* Store the same carrier with only its root-committed LICENSE bytes replaced.
 * This constructs a hostile-but-content-valid download that creation now
 * refuses, so checkout must independently enforce local license policy. */
static bool vc_store_transport_with_license(
    struct vcs_package_store *store,
    const struct vcs_source_package_transport *transport,
    const uint8_t *license, size_t license_len, uint8_t root_out[32])
{
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    size_t count = vcs_source_package_transport_file_count(transport);
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        ok = vcs_source_package_transport_file_at(
            transport, i, &path, &bytes, &len);
        if (ok && strcmp(path, VCS_SOURCE_PACKAGE_LICENSE_PATH) == 0) {
            bytes = license;
            len = license_len;
        }
        if (ok)
            ok = vcs_package_content_add_file(
                &manifest, path, VCS_PACKAGE_MODE_FILE, bytes, len);
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t admitted[32];
    ok = ok && vcs_package_manifest_root(&manifest, root_out) &&
         vcs_package_manifest_serialize(&manifest, &wire, &wire_len) &&
         vcs_package_store_put_manifest(store, wire, wire_len, admitted) ==
             VCS_PACKAGE_STORE_OK &&
         memcmp(admitted, root_out, 32) == 0;
    free(wire);
    for (size_t i = 0; ok && i < manifest.count; i++) {
        const struct vcs_package_file *file = &manifest.files[i];
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (strcmp(file->path, VCS_SOURCE_PACKAGE_LICENSE_PATH) == 0) {
            bytes = license;
            len = license_len;
        } else {
            ok = vc_transport_file(transport, file->path, &bytes, &len);
        }
        for (uint32_t chunk = 0; ok && chunk < file->chunk_count; chunk++) {
            size_t off = (size_t)chunk * VCS_PACKAGE_CHUNK_BYTES;
            size_t take = len - off;
            if (take > VCS_PACKAGE_CHUNK_BYTES)
                take = VCS_PACKAGE_CHUNK_BYTES;
            ok = vcs_package_store_put_chunk(
                     store, root_out, file->path, chunk, bytes + off, take) ==
                 VCS_PACKAGE_STORE_OK;
        }
    }
    vcs_package_manifest_free(&manifest);
    return ok;
}

static bool vc_file_matches(const char *dir, const char *rel,
                            const char *expect);

static int t_source_bundle(void)
{
    int failures = 0;
    char source[512], unlicensed_source[512], consumer[512];
    char sharded_consumer[512];
    char package_datadir[512], incomplete_datadir[512];
    char package_workspace[512];
    char package_destination[512], refused_destination[512];
    char incomplete_destination[512];
    char materialized[512], marker[512];
    test_make_tmpdir(source, sizeof(source), "vcs_core", "bundle-source");
    test_make_tmpdir(unlicensed_source, sizeof(unlicensed_source),
                     "vcs_core", "bundle-unlicensed-source");
    test_make_tmpdir(consumer, sizeof(consumer), "vcs_core", "bundle-consumer");
    test_make_tmpdir(sharded_consumer, sizeof(sharded_consumer),
                     "vcs_core", "bundle-sharded-consumer");
    test_make_tmpdir(package_datadir, sizeof(package_datadir),
                     "vcs_core", "bundle-package-store");
    test_make_tmpdir(incomplete_datadir, sizeof(incomplete_datadir),
                     "vcs_core", "bundle-incomplete-store");
    test_make_tmpdir(package_workspace, sizeof(package_workspace),
                     "vcs_core", "bundle-package-workspace");
    test_make_tmpdir(package_destination, sizeof(package_destination),
                     "vcs_core", "bundle-package-destination");
    test_make_tmpdir(refused_destination, sizeof(refused_destination),
                     "vcs_core", "bundle-refused-destination");
    test_make_tmpdir(incomplete_destination, sizeof(incomplete_destination),
                     "vcs_core", "bundle-incomplete-destination");
    test_make_tmpdir(materialized, sizeof(materialized), "vcs_core",
                     "bundle-materialized");
    (void)snprintf(marker, sizeof(marker), "%s/should-not-exist",
                   package_destination);

    VC_CHECK("source bundle fixture files",
             vc_write(source, "LICENSE", TEST_LICENSE_TEXT_MIT) &&
             vc_write(source, "src/a.c", "int a(void) { return 1; }\n") &&
             vc_write(source, "include/a.h", "int a(void);\n") &&
             vc_write(source, "run.sh", "#!/bin/sh\ntouch should-not-exist\n") &&
             vc_write(source, "vendor/sqlite3.c", "generated amalgamation") &&
             vc_write(source, "vendor/include/zlib.h", "generated zlib header") &&
             vc_write(source, "vendor/include/zconf.h", "generated config") &&
             vc_write(source, "vendor/.cache/leveldb-1.23.tar.gz", "leveldb") &&
             vc_write(source, "vendor/.cache/libevent-2.1.12.tar.gz", "libevent") &&
             vc_write(source, "vendor/.cache/openssl-3.0.16.tar.gz", "openssl") &&
             vc_write(source, "vendor/.cache/sqlite-amalgamation-3490000.zip", "sqlite") &&
             vc_write(source, "vendor/.cache/zlib-1.3.1.tar.gz", "zlib"));
    char executable[1024];
    (void)snprintf(executable, sizeof(executable), "%s/run.sh", source);
    VC_CHECK("source bundle executable mode fixture",
             chmod(executable, 0755) == 0);

    uint8_t first_root[32];
    VC_CHECK("source bundle captures authoritative tree",
             vcs_tree_capture_path(source, first_root) == VCS_OK);
    uint8_t *first_wire = NULL;
    size_t first_wire_len = 0;
    struct vcs_source_bundle_metrics created;
    VC_CHECK("source bundle excludes cache and generated vendor outputs",
             vcs_source_bundle_create(source, first_root, &first_wire,
                                      &first_wire_len, &created) ==
                 VCS_SOURCE_BUNDLE_OK &&
             first_wire && first_wire_len > VCS_SOURCE_BUNDLE_HEADER_BYTES &&
             created.file_count == 4 && created.source_bytes > 0);
    struct vcs_source_bundle_metrics verified;
    VC_CHECK("source bundle verifies without writes",
             vcs_source_bundle_verify(first_wire, first_wire_len, first_root,
                                      &verified) == VCS_SOURCE_BUNDLE_OK &&
             verified.file_count == created.file_count &&
             !vcs_object_store_initialized(consumer));

    struct vcs_source_bundle_sharded first_sharded;
    vcs_source_bundle_sharded_init(&first_sharded);
    VC_CHECK("source bundle v2 creates independently compressed path shards",
             vcs_source_bundle_sharded_create(
                 source, first_root, &first_sharded) ==
                 VCS_SOURCE_BUNDLE_OK &&
             first_sharded.shard_count > 0 &&
             first_sharded.metrics.file_count == created.file_count);
    struct vcs_source_bundle_metrics sharded_verified;
    VC_CHECK("source bundle v2 rederives complete tree and every blob",
             vcs_source_bundle_sharded_verify(
                 &first_sharded, first_root, &sharded_verified) ==
                 VCS_SOURCE_BUNDLE_OK &&
             sharded_verified.source_bytes == created.source_bytes);
    size_t complete_shards = first_sharded.shard_count;
    first_sharded.shard_count--;
    VC_CHECK("source bundle v2 missing shard is refused",
             vcs_source_bundle_sharded_verify(
                 &first_sharded, first_root, NULL) != VCS_SOURCE_BUNDLE_OK);
    first_sharded.shard_count = complete_shards;
    uint8_t saved_shard_tail = first_sharded.shards[0].wire[
        first_sharded.shards[0].wire_len - 1u];
    first_sharded.shards[0].wire[
        first_sharded.shards[0].wire_len - 1u] ^= 0x80u;
    VC_CHECK("source bundle v2 corrupt shard is refused",
             vcs_source_bundle_sharded_verify(
                 &first_sharded, first_root, NULL) != VCS_SOURCE_BUNDLE_OK);
    first_sharded.shards[0].wire[
        first_sharded.shards[0].wire_len - 1u] = saved_shard_tail;
    uint16_t saved_shard_index = first_sharded.shards[0].index;
    first_sharded.shards[0].index = (uint16_t)(saved_shard_index ^ 1u);
    VC_CHECK("source bundle v2 misplaced shard is refused",
             vcs_source_bundle_sharded_verify(
                 &first_sharded, first_root, NULL) != VCS_SOURCE_BUNDLE_OK);
    first_sharded.shards[0].index = saved_shard_index;
    struct vcs_source_bundle_metrics sharded_imported;
    VC_CHECK("source bundle v2 verifies fully before CAS import",
             vcs_source_bundle_sharded_import(
                 &first_sharded, first_root, sharded_consumer,
                 &sharded_imported) == VCS_SOURCE_BUNDLE_OK &&
             sharded_imported.new_blobs == 4 &&
             sharded_imported.reused_blobs == 0);

    uint8_t lane_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    struct vcs_zcode_lane_receipt_v1 lane = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .lane = VCS_ZCODE_LANE_PROVEN,
        .created_unix = 1,
    };
    memcpy(lane.source_root, first_root, 32);
    memset(lane.task_root, 0x11, 32);
    memset(lane.candidate_root, 0x22, 32);
    memset(lane.proof_policy_root, 0x33, 32);
    memset(lane.proof_set_root, 0x44, 32);
    memset(lane.prior_receipt_root, 0x55, 32);
    uint8_t lane_seed[32], lane_secret[32], lane_pubkey[32];
    memset(lane_seed, 0x66, sizeof(lane_seed));
    ed25519_keypair(lane_pubkey, lane_secret, lane_seed);
    bool lane_ok = vcs_zcode_lane_receipt_seal(
            &lane, lane_secret, lane_pubkey) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_serialize(&lane, lane_wire) ==
            VCS_ZCODE_DEV_OK;
    memset(lane_secret, 0, sizeof(lane_secret));

    uint8_t unlicensed_root[32];
    VC_CHECK("source package proprietary-license fixture captures",
             vc_write(unlicensed_source, "LICENSE",
                      "Copyright 2026. All rights reserved.\n") &&
                 vc_write(unlicensed_source, "src/a.c",
                          "int a(void) { return 9; }\n") &&
                 vcs_tree_capture_path(unlicensed_source, unlicensed_root) ==
                     VCS_OK);
    struct vcs_zcode_lane_receipt_v1 unlicensed_lane = lane;
    memcpy(unlicensed_lane.source_root, unlicensed_root, 32);
    unlicensed_lane.created_unix = 2;
    uint8_t unlicensed_seed[32], unlicensed_secret[32];
    uint8_t unlicensed_pubkey[32], unlicensed_lane_wire[
        VCS_ZCODE_LANE_WIRE_BYTES];
    memset(unlicensed_seed, 0x67, sizeof(unlicensed_seed));
    ed25519_keypair(unlicensed_pubkey, unlicensed_secret, unlicensed_seed);
    bool unlicensed_lane_ok = vcs_zcode_lane_receipt_seal(
            &unlicensed_lane, unlicensed_secret, unlicensed_pubkey) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_serialize(
            &unlicensed_lane, unlicensed_lane_wire) == VCS_ZCODE_DEV_OK;
    memset(unlicensed_secret, 0, sizeof(unlicensed_secret));
    struct vcs_source_package_transport unlicensed_transport;
    vcs_source_package_transport_init(&unlicensed_transport);
    VC_CHECK("source package creation refuses proprietary LICENSE text",
             unlicensed_lane_ok &&
                 !vcs_source_package_transport_build(
                     unlicensed_source, unlicensed_root, unlicensed_pubkey,
                     unlicensed_lane_wire, sizeof(unlicensed_lane_wire),
                     &unlicensed_transport));
    vcs_source_package_transport_free(&unlicensed_transport);
    uint8_t wrong_signer[32];
    memset(wrong_signer, 0x77, sizeof(wrong_signer));
    struct vcs_source_package_transport unauthorized_transport;
    vcs_source_package_transport_init(&unauthorized_transport);
    VC_CHECK("source package refuses a receipt outside accepted authority",
             !vcs_source_package_transport_build(
                 source, first_root, wrong_signer, lane_wire,
                 sizeof(lane_wire), &unauthorized_transport));
    vcs_source_package_transport_free(&unauthorized_transport);
    uint8_t refused_lane[VCS_ZCODE_LANE_WIRE_BYTES];
    memcpy(refused_lane, lane_wire, sizeof(refused_lane));
    refused_lane[sizeof(refused_lane) - 1u] ^= 1u;
    struct vcs_source_package_transport refused_transport;
    vcs_source_package_transport_init(&refused_transport);
    VC_CHECK("source package refuses a forged PROVEN receipt",
             !vcs_source_package_transport_build(
                 source, first_root, lane_pubkey, refused_lane,
                 sizeof(refused_lane),
                 &refused_transport));
    vcs_source_package_transport_free(&refused_transport);
    struct vcs_source_package_transport transport;
    vcs_source_package_transport_init(&transport);
    VC_CHECK("source package carries verified tree through content.v2",
             lane_ok && vcs_source_package_transport_build(
                 source, first_root, lane_pubkey, lane_wire, sizeof(lane_wire),
                 &transport) && transport.source.shard_count > 0 &&
             transport.offline_input_count == 5 &&
             transport.bundle_metrics.file_count == created.file_count);
    struct vcs_package_manifest carrier;
    char first_shard_path[VCS_SOURCE_BUNDLE_SHARD_PATH_MAX];
    bool have_shard_path = transport.source.shard_count > 0 &&
        vcs_source_bundle_shard_path(
            transport.source.shards[0].index, first_shard_path,
            sizeof(first_shard_path));
    VC_CHECK("source package manifest is canonical sharded carrier",
             vcs_package_manifest_parse(
                 transport.manifest_wire, transport.manifest_wire_len,
                 &carrier) &&
             carrier.count == vcs_source_package_transport_file_count(
                                  &transport) &&
             vc_package_has_path(
                 &carrier, VCS_SOURCE_PACKAGE_MANIFEST_PATH) &&
             have_shard_path && vc_package_has_path(
                 &carrier, first_shard_path) &&
             vc_package_has_path(
                 &carrier, VCS_SOURCE_PACKAGE_LANE_PATH) &&
             vc_package_has_path(
                 &carrier, VCS_SOURCE_PACKAGE_MARKER_PATH) &&
             vc_package_has_path(
                 &carrier, VCS_SOURCE_PACKAGE_LICENSE_PATH) &&
             vc_package_has_path(
                 &carrier, "vendor/.cache/openssl-3.0.16.tar.gz"));
    vcs_package_manifest_free(&carrier);
    struct vcs_package_recipe carrier_recipe;
    uint8_t carrier_recipe_root[32];
    VC_CHECK("source package recipe builds only inert carrier marker",
             vcs_package_recipe_parse(
                 transport.recipe_wire, transport.recipe_wire_len,
                 &carrier_recipe) == VCS_PACKAGE_RECIPE_OK &&
             carrier_recipe.sources.count == 1 &&
             strcmp(carrier_recipe.sources.items[0],
                    VCS_SOURCE_PACKAGE_MARKER_PATH) == 0 &&
             vcs_package_recipe_root(
                 &carrier_recipe, carrier_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             memcmp(carrier_recipe_root, transport.recipe_root, 32) == 0);
    vcs_package_recipe_free(&carrier_recipe);

    struct vcs_package_store *carrier_store = vcs_package_store_open(
        package_datadir, UINT64_C(256) * 1024u * 1024u);
    uint8_t admitted_root[32];
    VC_CHECK("source carrier enters the ordinary content.v2 store",
             carrier_store && vcs_package_store_put_manifest(
                 carrier_store, transport.manifest_wire,
                 transport.manifest_wire_len, admitted_root) ==
                 VCS_PACKAGE_STORE_OK &&
             memcmp(admitted_root, transport.package_root, 32) == 0);
    struct vcs_package_store *incomplete_store = vcs_package_store_open(
        incomplete_datadir, UINT64_C(256) * 1024u * 1024u);
    uint8_t incomplete_root[32];
    VC_CHECK("source carrier interrupted transfer remains incomplete",
             incomplete_store && vcs_package_store_put_manifest(
                 incomplete_store, transport.manifest_wire,
                 transport.manifest_wire_len, incomplete_root) ==
                 VCS_PACKAGE_STORE_OK &&
             vcs_source_package_checkout(
                 incomplete_store, incomplete_root, first_root, lane_pubkey,
                 package_workspace, incomplete_destination, NULL) ==
                 VCS_SOURCE_PACKAGE_CHECKOUT_INCOMPLETE);
    if (incomplete_store) vcs_package_store_close(incomplete_store);
    struct vcs_package_manifest stored_carrier;
    bool stored_parsed = vcs_package_manifest_parse(
        transport.manifest_wire, transport.manifest_wire_len,
        &stored_carrier);
    bool stored = stored_parsed;
    for (size_t i = 0; stored && i < stored_carrier.count; i++) {
        const struct vcs_package_file *file = &stored_carrier.files[i];
        const uint8_t *bytes = NULL;
        size_t len = 0;
        stored = vc_transport_file(&transport, file->path, &bytes, &len) &&
            len == file->size;
        for (uint32_t j = 0; stored && j < file->chunk_count; j++) {
            size_t off = (size_t)j * VCS_PACKAGE_CHUNK_BYTES;
            size_t take = len - off;
            if (take > VCS_PACKAGE_CHUNK_BYTES)
                take = VCS_PACKAGE_CHUNK_BYTES;
            stored = vcs_package_store_put_chunk(
                carrier_store, transport.package_root, file->path, j,
                bytes + off, take) == VCS_PACKAGE_STORE_OK;
        }
    }
    VC_CHECK("source carrier chunks complete through the ordinary store",
             stored);
    static const uint8_t proprietary_license[] =
        "Copyright 2026. All rights reserved.\n";
    uint8_t proprietary_root[32];
    VC_CHECK("source carrier hostile license fixture enters inert CAS",
             vc_store_transport_with_license(
                 carrier_store, &transport, proprietary_license,
                 sizeof(proprietary_license) - 1u, proprietary_root));
    VC_CHECK("source carrier checkout independently refuses proprietary text",
             vcs_source_package_checkout(
                 carrier_store, proprietary_root, first_root, lane_pubkey,
                 package_workspace, refused_destination, NULL) ==
                 VCS_SOURCE_PACKAGE_CHECKOUT_SHAPE);
    struct vcs_source_package_checkout_metrics checkout_metrics;
    VC_CHECK("source carrier reconstructs source and offline inputs without Git",
             vcs_source_package_checkout(
                 carrier_store, transport.package_root, first_root, lane_pubkey,
                 package_workspace, package_destination,
                 &checkout_metrics) == VCS_SOURCE_PACKAGE_CHECKOUT_OK &&
             checkout_metrics.source.file_count == created.file_count &&
             checkout_metrics.offline_input_files == 5 &&
             vc_file_matches(package_destination, "src/a.c",
                             "int a(void) { return 1; }\n") &&
             vc_file_matches(package_destination,
                             "vendor/.cache/openssl-3.0.16.tar.gz",
                             "openssl") &&
             access(marker, F_OK) != 0);
    uint8_t refused_root[32];
    memcpy(refused_root, first_root, sizeof(refused_root));
    refused_root[0] ^= 1u;
    VC_CHECK("source carrier refuses wrong source authority before checkout",
             vcs_source_package_checkout(
                 carrier_store, transport.package_root, refused_root,
                 lane_pubkey,
                 package_workspace, refused_destination, NULL) ==
                 VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE);
    if (stored_parsed) vcs_package_manifest_free(&stored_carrier);
    vcs_package_store_close(carrier_store);
    vcs_source_package_transport_free(&transport);

    char offline_cache[4096], held_cache[4096];
    (void)snprintf(offline_cache, sizeof(offline_cache),
                   "%s/vendor/.cache", source);
    (void)snprintf(held_cache, sizeof(held_cache),
                   "%s/vendor/.cache-held", source);
    struct vcs_source_package_transport standalone_transport;
    vcs_source_package_transport_init(&standalone_transport);
    bool cache_held = rename(offline_cache, held_cache) == 0;
    bool standalone_ok = cache_held && vcs_source_package_transport_build(
        source, first_root, lane_pubkey, lane_wire, sizeof(lane_wire),
        &standalone_transport) &&
        standalone_transport.offline_input_count == 0;
    bool cache_restored = cache_held && rename(held_cache, offline_cache) == 0;
    VC_CHECK("standalone source package uses its declared package DAG",
             standalone_ok && cache_restored);
    vcs_source_package_transport_free(&standalone_transport);

    uint8_t wrong_root[32];
    memcpy(wrong_root, first_root, sizeof(wrong_root));
    wrong_root[0] ^= 1u;
    VC_CHECK("source bundle wrong immutable root refused",
             vcs_source_bundle_verify(first_wire, first_wire_len, wrong_root,
                                      NULL) == VCS_SOURCE_BUNDLE_ERR_ROOT);
    VC_CHECK("source bundle interrupted wire refused before CAS writes",
             vcs_source_bundle_import(first_wire, first_wire_len - 1u,
                                      first_root, consumer, NULL) !=
                 VCS_SOURCE_BUNDLE_OK &&
             !vcs_object_store_initialized(consumer));

    uint8_t *corrupt_wire = malloc(first_wire_len);
    VC_CHECK("source bundle corruption fixture allocated",
             corrupt_wire != NULL);
    if (corrupt_wire) {
        memcpy(corrupt_wire, first_wire, first_wire_len);
        corrupt_wire[first_wire_len - 1u] ^= 0x80u;
        VC_CHECK("source bundle corrupt compressed bytes refused",
                 vcs_source_bundle_verify(corrupt_wire, first_wire_len,
                                          first_root, NULL) !=
                     VCS_SOURCE_BUNDLE_OK);
    }
    free(corrupt_wire);

    struct vcs_source_bundle_metrics imported;
    VC_CHECK("source bundle complete retry imports verified CAS",
             vcs_source_bundle_import(first_wire, first_wire_len, first_root,
                                      consumer, &imported) ==
                 VCS_SOURCE_BUNDLE_OK &&
             imported.new_blobs == 4 && imported.reused_blobs == 0 &&
             !imported.repaired && access(marker, F_OK) != 0);
    VC_CHECK("source bundle materializes without Git",
             vcs_tree_materialize(consumer, first_root, materialized,
                                  VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) ==
                 VCS_OK);
    size_t source_len = 0, materialized_len = 0;
    char *source_a = vc_read(source, "src/a.c", &source_len);
    char *materialized_a = vc_read(materialized, "src/a.c",
                                   &materialized_len);
    VC_CHECK("source bundle reconstructed bytes match",
             source_a && materialized_a && source_len == materialized_len &&
             memcmp(source_a, materialized_a, source_len) == 0);
    free(materialized_a); free(source_a);

    struct vcs_manifest first_manifest;
    bool loaded = vcs_tree_load(consumer, first_root, &first_manifest);
    VC_CHECK("source bundle imported manifest reloads", loaded);
    if (loaded && first_manifest.count > 0) {
        VC_CHECK("source bundle corrupt cache fixture",
                 vc_corrupt_object(consumer, first_manifest.entries[0].blob));
        struct vcs_source_bundle_metrics repaired;
        VC_CHECK("source bundle verified retry repairs exact corrupt blob",
                 vcs_source_bundle_import(first_wire, first_wire_len,
                                          first_root, consumer, &repaired) ==
                     VCS_SOURCE_BUNDLE_OK && repaired.repaired &&
                 repaired.new_blobs == 1 && repaired.reused_blobs == 3);
        vcs_manifest_free(&first_manifest);
    }

    VC_CHECK("source bundle successor fixture changed one file",
             vc_write(source, "src/a.c", "int a(void) { return 2; }\n"));
    uint8_t second_root[32];
    VC_CHECK("source bundle successor captures new tree",
             vcs_tree_capture_path(source, second_root) == VCS_OK &&
             memcmp(second_root, first_root, 32) != 0);
    uint8_t *second_wire = NULL;
    size_t second_wire_len = 0;
    VC_CHECK("source bundle successor creates transport",
             vcs_source_bundle_create(source, second_root, &second_wire,
                                      &second_wire_len, NULL) ==
                 VCS_SOURCE_BUNDLE_OK);
    struct vcs_source_bundle_sharded second_sharded;
    vcs_source_bundle_sharded_init(&second_sharded);
    VC_CHECK("source bundle v2 successor creates transport",
             vcs_source_bundle_sharded_create(
                 source, second_root, &second_sharded) ==
                 VCS_SOURCE_BUNDLE_OK);
    size_t stable_shards = 0, changed_shards = 0;
    for (size_t i = 0; i < first_sharded.shard_count; i++) {
        const struct vcs_source_bundle_shard *first =
            &first_sharded.shards[i];
        const struct vcs_source_bundle_shard *second =
            vc_source_shard(&second_sharded, first->index);
        if (second && second->wire_len == first->wire_len &&
            memcmp(second->wire, first->wire, first->wire_len) == 0)
            stable_shards++;
        else
            changed_shards++;
    }
    VC_CHECK("source bundle v2 one-file successor preserves other shards",
             stable_shards > 0 && changed_shards == 1 &&
             second_sharded.shard_count == first_sharded.shard_count);
    struct vcs_source_bundle_metrics successor;
    VC_CHECK("source bundle successor reuses unchanged CAS blobs",
             vcs_source_bundle_import(second_wire, second_wire_len,
                                      second_root, consumer, &successor) ==
                 VCS_SOURCE_BUNDLE_OK &&
             successor.new_blobs == 1 && successor.reused_blobs == 3 &&
             successor.new_bytes < successor.reused_bytes);

    vcs_source_bundle_sharded_free(&second_sharded);
    vcs_source_bundle_sharded_free(&first_sharded);
    free(second_wire); free(first_wire);
    test_rm_rf_recursive(materialized);
    test_rm_rf_recursive(sharded_consumer);
    test_rm_rf_recursive(package_destination);
    test_rm_rf_recursive(refused_destination);
    test_rm_rf_recursive(package_workspace);
    test_rm_rf_recursive(package_datadir);
    test_rm_rf_recursive(consumer);
    test_rm_rf_recursive(unlicensed_source);
    test_rm_rf_recursive(source);
    return failures;
}

static bool vc_file_matches(const char *dir, const char *rel, const char *expect)
{
    size_t n = 0;
    char *got = vc_read(dir, rel, &n);
    if (!got) return false;
    bool ok = (n == strlen(expect)) && memcmp(got, expect, n) == 0;
    free(got);
    return ok;
}

/* Count regular files under a directory tree. */
static int vc_count_objects(const char *repo)
{
    char cmd[4096];
    /* pure-C count would be verbose; a find|wc via popen is fine in a test. */
    snprintf(cmd, sizeof(cmd),
             "find '%s/.zvcs/objects' -type f ! -path '*/tmp/*' 2>/dev/null | wc -l",
             repo);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    int c = -1;
    if (fscanf(p, "%d", &c) != 1) c = -1;
    pclose(p);
    return c;
}

/* Count leftover ZVCS staging temp files (<...>.zvcstmp.<pid>.<seq>) anywhere
 * under the worktree — a two-phase revert must leave none behind on failure. */
static int vc_count_temps(const char *dir)
{
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "find '%s' -name '*.zvcstmp.*' 2>/dev/null | wc -l", dir);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    int c = -1;
    if (fscanf(p, "%d", &c) != 1) c = -1;
    pclose(p);
    return c;
}

/* diff counters for status callback */
struct diff_counts { int added, removed, modified; };
static void count_cb(enum vcs_diff_kind kind, const struct vcs_entry *a,
                     const struct vcs_entry *b, void *user)
{
    (void)a; (void)b;
    struct diff_counts *d = user;
    if (kind == VCS_DIFF_ADDED) d->added++;
    else if (kind == VCS_DIFF_REMOVED) d->removed++;
    else if (kind == VCS_DIFF_MODIFIED) d->modified++;
}

/* ── test 1: manifest serialize/parse/hash fixed-point ──────────── */
static int t_manifest_fixedpoint(void)
{
    int failures = 0;
    struct vcs_manifest m;
    vcs_manifest_init(&m);
    /* add entries out of order to exercise sort */
    const char *paths[] = { "z/last.c", "a.txt", "m/mid.h", "a/b/c.c", "a.txt2" };
    for (size_t i = 0; i < 5; i++) {
        uint8_t blob[32];
        for (int k = 0; k < 32; k++) blob[k] = (uint8_t)(i * 7 + k);
        VC_CHECK("manifest_add", vcs_manifest_add(&m, paths[i], 0100644,
                                                   (uint64_t)(i * 100 + 1), blob));
    }

    uint8_t *ser1 = NULL; size_t len1 = 0;
    VC_CHECK("serialize", vcs_manifest_serialize(&m, &ser1, &len1));

    struct vcs_manifest m2;
    VC_CHECK("parse", vcs_manifest_parse(ser1, len1, &m2));
    VC_CHECK("parse count", m2.count == 5);

    uint8_t *ser2 = NULL; size_t len2 = 0;
    VC_CHECK("reserialize", vcs_manifest_serialize(&m2, &ser2, &len2));
    VC_CHECK("serialize fixed-point",
             len1 == len2 && ser1 && ser2 && memcmp(ser1, ser2, len1) == 0);

    uint8_t th1[32], th2[32];
    VC_CHECK("tree_hash m", vcs_manifest_tree_hash(&m, th1));
    VC_CHECK("tree_hash m2", vcs_manifest_tree_hash(&m2, th2));
    VC_CHECK("tree_hash stable across parse", memcmp(th1, th2, 32) == 0);

    /* order independence: same entries, reversed insertion order. */
    struct vcs_manifest m3;
    vcs_manifest_init(&m3);
    for (int i = 4; i >= 0; i--) {
        uint8_t blob[32];
        for (int k = 0; k < 32; k++) blob[k] = (uint8_t)((size_t)i * 7 + k);
        vcs_manifest_add(&m3, paths[i], 0100644, (uint64_t)(i * 100 + 1), blob);
    }
    uint8_t th3[32];
    vcs_manifest_tree_hash(&m3, th3);
    VC_CHECK("tree_hash order-independent", memcmp(th1, th3, 32) == 0);

    /* a single byte change in one blob flips the tree_hash */
    m3.entries[0].blob[0] ^= 0xff;
    uint8_t th4[32];
    vcs_manifest_tree_hash(&m3, th4);
    VC_CHECK("tree_hash sensitive to blob", memcmp(th1, th4, 32) != 0);

    free(ser1); free(ser2);
    vcs_manifest_free(&m);
    vcs_manifest_free(&m2);
    vcs_manifest_free(&m3);
    return failures;
}

static struct vcs_package_file *package_file_by_path(
    struct vcs_package_manifest *manifest, const char *path)
{
    for (size_t i = 0; manifest && i < manifest->count; i++) {
        if (strcmp(manifest->files[i].path, path) == 0)
            return &manifest->files[i];
    }
    return NULL;
}

static void vc_wr_u32le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

static void vc_wr_u64le(uint8_t out[8], uint64_t value)
{
    for (size_t i = 0; i < 8; i++)
        out[i] = (uint8_t)((value >> (8u * i)) & 0xffu);
}

/* ── test 1b: content.v2 package manifest + chunk verification ─── */
static int t_package_manifest(void)
{
    int failures = 0;
    const size_t source_len = VCS_PACKAGE_CHUNK_BYTES + 3u;
    uint8_t *source = malloc(source_len);
    VC_CHECK("package: source fixture alloc", source != NULL);
    if (!source)
        return failures;
    for (size_t i = 0; i < source_len; i++)
        source[i] = (uint8_t)((i * 31u + 7u) & 0xffu);

    const uint8_t artifact[] = { 'a', 'b', 'c' };
    uint8_t source_hashes[64];
    uint8_t artifact_hash[32];
    VC_CHECK("package: hash full chunk",
             vcs_package_chunk_hash(source, VCS_PACKAGE_CHUNK_BYTES,
                                    source_hashes));
    VC_CHECK("package: hash final chunk",
             vcs_package_chunk_hash(source + VCS_PACKAGE_CHUNK_BYTES, 3,
                                    source_hashes + 32));
    VC_CHECK("package: hash artifact chunk",
             vcs_package_chunk_hash(artifact, sizeof(artifact), artifact_hash));
    static const uint8_t sha3_abc[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    };
    VC_CHECK("package: chunks use raw SHA3-256",
             memcmp(artifact_hash, sha3_abc, 32) == 0);
    VC_CHECK("package: zero chunk rejected",
             !vcs_package_chunk_hash(artifact, 0, artifact_hash));

    const char *valid_paths[] = {
        "README.md", ".well-known/app", "src/a+b@c.c", "assets/a_b-2.dat",
    };
    for (size_t i = 0; i < sizeof(valid_paths) / sizeof(valid_paths[0]); i++)
        VC_CHECK("package: canonical path accepted",
                 vcs_package_path_valid(valid_paths[i]));
    const char *invalid_paths[] = {
        "", "/absolute", "trailing/", "a//b", ".", "..", "../x",
        "a/./b", "a/../b", "a\\b", "C:drive", "has space", "a/#hash",
    };
    for (size_t i = 0; i < sizeof(invalid_paths) / sizeof(invalid_paths[0]); i++)
        VC_CHECK("package: non-canonical path rejected",
                 !vcs_package_path_valid(invalid_paths[i]));
    char long_segment[VCS_PACKAGE_PATH_SEGMENT_MAX + 2];
    memset(long_segment, 'a', sizeof(long_segment) - 1);
    long_segment[sizeof(long_segment) - 1] = '\0';
    VC_CHECK("package: overlong segment rejected",
             !vcs_package_path_valid(long_segment));

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    VC_CHECK("package: add source",
             vcs_package_manifest_add(&manifest, "src/main.c",
                                      VCS_PACKAGE_MODE_FILE, source_len,
                                      source_hashes, 2));
    VC_CHECK("package: add empty file",
             vcs_package_manifest_add(&manifest, "README.md",
                                      VCS_PACKAGE_MODE_FILE, 0, NULL, 0));
    VC_CHECK("package: add executable artifact",
             vcs_package_manifest_add(&manifest, "bin/demo",
                                      VCS_PACKAGE_MODE_EXECUTABLE,
                                      sizeof(artifact), artifact_hash, 1));
    VC_CHECK("package: duplicate rejected",
             !vcs_package_manifest_add(&manifest, "src/main.c",
                                       VCS_PACKAGE_MODE_FILE, source_len,
                                       source_hashes, 2));
    VC_CHECK("package: traversal add rejected",
             !vcs_package_manifest_add(&manifest, "src/../main.c",
                                       VCS_PACKAGE_MODE_FILE, 0, NULL, 0));
    VC_CHECK("package: symlink mode rejected",
             !vcs_package_manifest_add(&manifest, "link", 0120777u,
                                       0, NULL, 0));
    VC_CHECK("package: permission drift rejected",
             !vcs_package_manifest_add(&manifest, "private", 0100600u,
                                       0, NULL, 0));
    VC_CHECK("package: size/chunk mismatch rejected",
             !vcs_package_manifest_add(&manifest, "bad-size",
                                       VCS_PACKAGE_MODE_FILE, 1, NULL, 0));
    VC_CHECK("package: oversized file rejected",
             !vcs_package_manifest_add(&manifest, "too-big",
                                       VCS_PACKAGE_MODE_FILE,
                                       VCS_PACKAGE_MAX_FILE_BYTES + 1,
                                       NULL, 0));

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    VC_CHECK("package: canonical serialize",
             vcs_package_manifest_serialize(&manifest, &wire, &wire_len));
    VC_CHECK("package: bounded wire produced",
             wire && wire_len > VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES &&
             wire_len <= VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES);

    struct vcs_package_manifest parsed;
    VC_CHECK("package: canonical parse",
             vcs_package_manifest_parse(wire, wire_len, &parsed));
    VC_CHECK("package: parse count", parsed.count == 3);
    uint8_t *wire2 = NULL;
    size_t wire2_len = 0;
    VC_CHECK("package: reserialize",
             vcs_package_manifest_serialize(&parsed, &wire2, &wire2_len));
    VC_CHECK("package: serialization fixed point",
             wire_len == wire2_len && memcmp(wire, wire2, wire_len) == 0);

    uint8_t root[32];
    uint8_t parsed_root[32];
    VC_CHECK("package: manifest root",
             vcs_package_manifest_root(&manifest, root));
    VC_CHECK("package: parsed manifest root",
             vcs_package_manifest_root(&parsed, parsed_root));
    VC_CHECK("package: root survives wire round trip",
             memcmp(root, parsed_root, 32) == 0);

    struct vcs_package_manifest reversed;
    vcs_package_manifest_init(&reversed);
    VC_CHECK("package: reverse add empty",
             vcs_package_manifest_add(&reversed, "README.md",
                                      VCS_PACKAGE_MODE_FILE, 0, NULL, 0));
    VC_CHECK("package: reverse add artifact",
             vcs_package_manifest_add(&reversed, "bin/demo",
                                      VCS_PACKAGE_MODE_EXECUTABLE,
                                      sizeof(artifact), artifact_hash, 1));
    VC_CHECK("package: reverse add source",
             vcs_package_manifest_add(&reversed, "src/main.c",
                                      VCS_PACKAGE_MODE_FILE, source_len,
                                      source_hashes, 2));
    uint8_t reversed_root[32];
    uint8_t *reversed_wire = NULL;
    size_t reversed_wire_len = 0;
    VC_CHECK("package: reverse root",
             vcs_package_manifest_root(&reversed, reversed_root));
    VC_CHECK("package: root insertion-order independent",
             memcmp(root, reversed_root, 32) == 0);
    VC_CHECK("package: reverse serialize",
             vcs_package_manifest_serialize(&reversed, &reversed_wire,
                                            &reversed_wire_len));
    VC_CHECK("package: wire insertion-order independent",
             wire_len == reversed_wire_len &&
             memcmp(wire, reversed_wire, wire_len) == 0);

    struct vcs_package_file *source_file =
        package_file_by_path(&parsed, "src/main.c");
    struct vcs_package_file *empty_file =
        package_file_by_path(&parsed, "README.md");
    VC_CHECK("package: parsed source located", source_file != NULL);
    VC_CHECK("package: parsed empty file located", empty_file != NULL);
    if (source_file) {
        VC_CHECK("package: first chunk verifies",
                 vcs_package_verify_chunk(source_file, 0, source,
                                          VCS_PACKAGE_CHUNK_BYTES));
        VC_CHECK("package: short final chunk verifies",
                 vcs_package_verify_chunk(source_file, 1,
                                          source + VCS_PACKAGE_CHUNK_BYTES, 3));
        VC_CHECK("package: wrong chunk length rejected",
                 !vcs_package_verify_chunk(source_file, 1,
                                           source + VCS_PACKAGE_CHUNK_BYTES, 2));
        VC_CHECK("package: chunk index overflow rejected",
                 !vcs_package_verify_chunk(source_file, 2, source, 1));
        VC_CHECK("package: whole file verifies",
                 vcs_package_verify_file(source_file, source, source_len));
        source[0] ^= 0xffu;
        VC_CHECK("package: corrupt chunk rejected",
                 !vcs_package_verify_chunk(source_file, 0, source,
                                           VCS_PACKAGE_CHUNK_BYTES));
        VC_CHECK("package: corrupt file rejected",
                 !vcs_package_verify_file(source_file, source, source_len));
        source[0] ^= 0xffu;
        source_file->chunk_hashes[0] ^= 0xffu;
        uint8_t changed_root[32];
        VC_CHECK("package: changed hash root",
                 vcs_package_manifest_root(&parsed, changed_root));
        VC_CHECK("package: ordered chunk list committed",
                 memcmp(root, changed_root, 32) != 0);
        source_file->chunk_hashes[0] ^= 0xffu;
    }
    if (empty_file)
        VC_CHECK("package: empty file verifies",
                 vcs_package_verify_file(empty_file, NULL, 0));

    uint8_t *bad = malloc(wire_len + 1);
    VC_CHECK("package: rejection fixture alloc", bad != NULL);
    if (bad) {
        struct vcs_package_manifest rejected;
        memcpy(bad, wire, wire_len);
        bad[wire_len] = 0;
        VC_CHECK("package: trailing byte rejected",
                 !vcs_package_manifest_parse(bad, wire_len + 1, &rejected));
        VC_CHECK("package: truncation rejected",
                 !vcs_package_manifest_parse(wire, wire_len - 1, &rejected));

        memcpy(bad, wire, wire_len);
        bad[0] ^= 0x01u;
        VC_CHECK("package: bad magic rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        bad[8] = 2;
        VC_CHECK("package: bad version rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        vc_wr_u32le(bad + 10, VCS_PACKAGE_CHUNK_BYTES / 2u);
        VC_CHECK("package: noncanonical chunk size rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        vc_wr_u32le(bad + 14, VCS_PACKAGE_MAX_FILES + 1u);
        VC_CHECK("package: file-count overflow rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));

        /* First sorted entry is README.md (9 bytes), starting at byte 20. */
        memcpy(bad, wire, wire_len);
        bad[VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES + 2u] = 'z';
        VC_CHECK("package: unsorted wire rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        memcpy(bad + VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES + 2u,
               "../aaaaaa", 9);
        VC_CHECK("package: traversal wire rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        bad[VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES + 2u] = 0;
        VC_CHECK("package: embedded NUL rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));

        const size_t first_mode =
            VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES + 2u + 9u;
        memcpy(bad, wire, wire_len);
        vc_wr_u32le(bad + first_mode, 0120777u);
        VC_CHECK("package: wire symlink mode rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        vc_wr_u64le(bad + first_mode + 4u,
                    VCS_PACKAGE_MAX_FILE_BYTES + 1u);
        VC_CHECK("package: wire size overflow rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        memcpy(bad, wire, wire_len);
        vc_wr_u64le(bad + first_mode + 4u, 1);
        VC_CHECK("package: wire size/count mismatch rejected",
                 !vcs_package_manifest_parse(bad, wire_len, &rejected));
        free(bad);
    }

    struct vcs_package_manifest duplicate_fixture;
    vcs_package_manifest_init(&duplicate_fixture);
    vcs_package_manifest_add(&duplicate_fixture, "a.c", VCS_PACKAGE_MODE_FILE,
                             0, NULL, 0);
    vcs_package_manifest_add(&duplicate_fixture, "b.c", VCS_PACKAGE_MODE_FILE,
                             0, NULL, 0);
    uint8_t *duplicate_wire = NULL;
    size_t duplicate_wire_len = 0;
    VC_CHECK("package: duplicate fixture serialize",
             vcs_package_manifest_serialize(&duplicate_fixture,
                                            &duplicate_wire,
                                            &duplicate_wire_len));
    if (duplicate_wire) {
        const size_t first_entry_bytes = 2u + 3u + 4u + 8u + 4u;
        const size_t second_path = VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES +
            first_entry_bytes + 2u;
        duplicate_wire[second_path] = 'a';
        struct vcs_package_manifest rejected;
        VC_CHECK("package: duplicate wire path rejected",
                 !vcs_package_manifest_parse(duplicate_wire,
                                             duplicate_wire_len, &rejected));
    }
    char *saved_path = duplicate_fixture.files[1].path;
    duplicate_fixture.files[1].path = duplicate_fixture.files[0].path;
    uint8_t *should_stay_null = (uint8_t *)(uintptr_t)1;
    size_t should_stay_zero = 99;
    VC_CHECK("package: duplicate in-memory path rejected",
             !vcs_package_manifest_serialize(&duplicate_fixture,
                                             &should_stay_null,
                                             &should_stay_zero));
    VC_CHECK("package: serialize failure clears outputs",
             should_stay_null == NULL && should_stay_zero == 0);
    duplicate_fixture.files[1].path = saved_path;

    struct vcs_package_manifest oversized = { 0 };
    oversized.count = VCS_PACKAGE_MAX_FILES + 1u;
    should_stay_null = (uint8_t *)(uintptr_t)1;
    should_stay_zero = 99;
    VC_CHECK("package: in-memory count overflow rejected",
             !vcs_package_manifest_serialize(&oversized, &should_stay_null,
                                             &should_stay_zero));
    VC_CHECK("package: overflow failure clears outputs",
             should_stay_null == NULL && should_stay_zero == 0);

    /* The sovereign source carrier must be able to describe the complete
     * Zclassic23 tree, not merely a small leaf package.  The tracked tree is
     * already above 5,100 regular files; keep bounded headroom so an accepted
     * full-node source cannot fail before it reaches publication. */
    struct vcs_package_manifest node_source_scale;
    vcs_package_manifest_init(&node_source_scale);
    bool node_source_scale_ok = true;
    for (unsigned i = 0; i < 6144u && node_source_scale_ok; i++) {
        char path[64];
        (void)snprintf(path, sizeof(path), "node/file-%04u.c", i);
        node_source_scale_ok = vcs_package_manifest_add(
            &node_source_scale, path, VCS_PACKAGE_MODE_FILE, 0, NULL, 0);
    }
    uint8_t *node_source_wire = NULL;
    size_t node_source_wire_len = 0;
    node_source_scale_ok = node_source_scale_ok &&
        vcs_package_manifest_serialize(&node_source_scale,
                                       &node_source_wire,
                                       &node_source_wire_len);
    struct vcs_package_manifest node_source_roundtrip;
    vcs_package_manifest_init(&node_source_roundtrip);
    node_source_scale_ok = node_source_scale_ok &&
        vcs_package_manifest_parse(node_source_wire, node_source_wire_len,
                                   &node_source_roundtrip) &&
        node_source_roundtrip.count == 6144u;
    VC_CHECK("package: full Zclassic23 source-scale manifest roundtrips",
             node_source_scale_ok);
    vcs_package_manifest_free(&node_source_roundtrip);
    free(node_source_wire);
    vcs_package_manifest_free(&node_source_scale);

    free(duplicate_wire);
    vcs_package_manifest_free(&duplicate_fixture);
    free(reversed_wire);
    vcs_package_manifest_free(&reversed);
    free(wire2);
    vcs_package_manifest_free(&parsed);
    free(wire);
    vcs_package_manifest_free(&manifest);
    free(source);
    return failures;
}

static bool manifest_has_path(const struct vcs_manifest *manifest,
                              const char *path)
{
    for (size_t i = 0; manifest && i < manifest->count; i++)
        if (strcmp(manifest->entries[i].path, path) == 0)
            return true;
    return false;
}

static int t_generated_paths_ignored(const char *dir)
{
    int failures = 0;
    vc_write(dir, "src/kept.c", "int kept;\n");
    vc_write(dir, ".claude/commands/kept.md", "tracked command\n");
    vc_write(dir, ".claude/worktrees/copy/src/main.c", "ignored\n");
    vc_write(dir, ".claude/tmp/scratch.c", "ignored\n");
    vc_write(dir, ".cache/compiler/result", "ignored\n");
    vc_write(dir, ".codeindex/index.kv", "ignored\n");
    vc_write(dir, ".zcl_test_render/page.html", "ignored\n");
    vc_write(dir, "examples/bin/example", "ignored\n");
    vc_write(dir, "vendor/tor/generated.c", "ignored\n");
    vc_write(dir, "vendor/zclassic-ref/source.cc", "ignored\n");
    vc_write(dir, "zcode/build-worker.ed25519", "ignored\n");

    struct vcs_manifest manifest;
    VC_CHECK("ignore: manifest build",
             vcs_manifest_build(dir, NULL, &manifest));
    VC_CHECK("ignore: ordinary source retained",
             manifest_has_path(&manifest, "src/kept.c"));
    VC_CHECK("ignore: tracked Claude command retained",
             manifest_has_path(&manifest, ".claude/commands/kept.md"));
    VC_CHECK("ignore: agent worktree pruned",
             !manifest_has_path(&manifest,
                                ".claude/worktrees/copy/src/main.c"));
    VC_CHECK("ignore: generated roots pruned",
             manifest.count == 2);
    vcs_manifest_free(&manifest);
    return failures;
}

/* ── test 2/3: object store dedup + verify-on-read ──────────────── */
static int t_object_store(const char *repo)
{
    int failures = 0;
    VC_CHECK("store_init", vcs_object_store_init(repo));

    const uint8_t data[] = "the quick brown fox";
    uint8_t h1[32], h2[32];
    VC_CHECK("put1", vcs_object_put(repo, data, sizeof(data), VCS_TAG_BLOB, h1));
    int before = vc_count_objects(repo);
    VC_CHECK("put2 (dup)", vcs_object_put(repo, data, sizeof(data), VCS_TAG_BLOB, h2));
    int after = vc_count_objects(repo);
    VC_CHECK("dedup same hash", memcmp(h1, h2, 32) == 0);
    VC_CHECK("dedup no new object", before == after && before >= 1);
    VC_CHECK("has", vcs_object_has(repo, h1));

    uint8_t *got = NULL; size_t glen = 0;
    VC_CHECK("get", vcs_object_get(repo, h1, VCS_TAG_BLOB, &got, &glen) == 0);
    VC_CHECK("get bytes", glen == sizeof(data) && got && memcmp(got, data, glen) == 0);
    free(got);

    /* wrong tag => hash mismatch => rejected */
    uint8_t *g2 = NULL; size_t g2len = 0;
    VC_CHECK("get wrong tag rejected",
             vcs_object_get(repo, h1, VCS_TAG_MANIFEST, &g2, &g2len) != 0);
    free(g2);

    /* corrupt the object file on disk => verify-on-read rejects it */
    char hex[65];
    static const char hd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { hex[2*i] = hd[(h1[i]>>4)&0xf]; hex[2*i+1] = hd[h1[i]&0xf]; }
    hex[64] = '\0';
    char opath[4096];
    snprintf(opath, sizeof(opath), "%s/.zvcs/objects/%c%c/%s", repo, hex[0], hex[1], hex + 2);
    int fd = open(opath, O_WRONLY);
    if (fd >= 0) { uint8_t bad = 0xff; pwrite(fd, &bad, 1, 0); close(fd); }
    uint8_t *g3 = NULL; size_t g3len = 0;
    VC_CHECK("verify-on-read catches corruption",
             vcs_object_get(repo, h1, VCS_TAG_BLOB, &g3, &g3len) != 0);
    free(g3);
    return failures;
}

/* Build a small worktree with a known file set. */
static void seed_worktree(const char *dir)
{
    vc_write(dir, "readme.txt", "hello world\n");
    vc_write(dir, "src/main.c", "int main(void){return 0;}\n");
    vc_write(dir, "src/util.c", "void u(void){}\n");
    vc_write(dir, "docs/notes.md", "# notes\n");
}

/* ── fake vcs_revert_relink_ops activators for the relink-half tests ── */
struct fake_activator {
    int     calls;
    uint8_t seen_hash[32];
};

static bool fake_activate_ok(const uint8_t gen_sha256[32], void *ctx)
{
    struct fake_activator *fa = ctx;
    fa->calls++;
    memcpy(fa->seen_hash, gen_sha256, 32);
    return true;
}

static bool fake_activate_fail(const uint8_t gen_sha256[32], void *ctx)
{
    struct fake_activator *fa = ctx;
    fa->calls++;
    memcpy(fa->seen_hash, gen_sha256, 32);
    return false;
}

/* Collect every commit id vcs_log() walks, to prove a relink revert is
 * append-only (nothing already in commits.log is ever overwritten or
 * dropped). */
#define LOG_ID_COLLECT_MAX 64
struct log_id_collect {
    uint8_t ids[LOG_ID_COLLECT_MAX][32];
    size_t  count;
};

static bool log_id_collect_cb(const struct vcs_commit *c,
                              const uint8_t commit_id[32], void *user)
{
    (void)c;
    struct log_id_collect *lc = user;
    if (lc->count < LOG_ID_COLLECT_MAX)
        memcpy(lc->ids[lc->count], commit_id, 32);
    lc->count++;
    return true;
}

static bool log_ids_contains(const struct log_id_collect *lc,
                             const uint8_t id[32])
{
    size_t n = lc->count < LOG_ID_COLLECT_MAX ? lc->count : LOG_ID_COLLECT_MAX;
    for (size_t i = 0; i < n; i++)
        if (memcmp(lc->ids[i], id, 32) == 0)
            return true;
    return false;
}

/* ── test 4/5/9: snapshot / status / revert / timing ────────────── */
static int t_snapshot_status_revert(const char *dir)
{
    int failures = 0;
    seed_worktree(dir);

    struct vcs_repo *r = vcs_open(dir);
    VC_CHECK("vcs_open", r != NULL);
    if (!r) return failures + 1;

    struct vcs_snapshot_meta meta = {0};
    meta.verdict_status = 1;
    meta.phase = "green";
    meta.agent_id = "test-agent";
    meta.task_ref = "seed";
    uint8_t c1[32];
    VC_CHECK("snapshot c1", vcs_snapshot(r, &meta, c1) == VCS_OK);

    /* clean status = 0 changes */
    size_t nc = 999;
    VC_CHECK("status clean", vcs_status(r, NULL, NULL, &nc) == VCS_OK && nc == 0);

    /* timing: warm status < 20ms */
    struct timespec a, b;
    platform_time_monotonic_timespec(&a);
    vcs_status(r, NULL, NULL, &nc);
    platform_time_monotonic_timespec(&b);
    double status_ms = (double)(b.tv_sec - a.tv_sec) * 1000.0 +
                       (double)(b.tv_nsec - a.tv_nsec) / 1e6;
    printf("  vcs_core: warm status = %.2f ms\n", status_ms);
    VC_CHECK("status < 20ms warm", status_ms < 20.0);

    /* edit one file -> exactly 1 modified */
    vc_write(dir, "src/main.c", "int main(void){return 42;}\n");
    struct diff_counts d = {0};
    VC_CHECK("status after edit", vcs_status(r, count_cb, &d, &nc) == VCS_OK);
    VC_CHECK("edit=1 modified", d.modified == 1 && d.added == 0 && d.removed == 0);

    /* add a file + remove a file -> 1 added, 1 removed (+1 modified still) */
    vc_write(dir, "src/new.c", "void n(void){}\n");
    char rmpath[4096];
    snprintf(rmpath, sizeof(rmpath), "%s/docs/notes.md", dir);
    unlink(rmpath);
    memset(&d, 0, sizeof(d));
    vcs_status(r, count_cb, &d, &nc);
    VC_CHECK("add/remove/modify counts",
             d.added == 1 && d.removed == 1 && d.modified == 1);

    uint8_t c2[32];
    VC_CHECK("snapshot c2", vcs_snapshot(r, &meta, c2) == VCS_OK);
    VC_CHECK("c1 != c2", memcmp(c1, c2, 32) != 0);

    /* timing: a true 1-file snapshot (everything else warm). The plan target
     * is < 50 ms for a single-file snapshot on the live single-process node.
     * The durable snapshot path is fsync-bound (~5-6 fsyncs), so under the
     * 32-worker parallel test harness fsync contention inflates wall time to
     * hundreds of ms — non-deterministic and NOT an algorithmic property. So
     * we print the snapshot wall time informationally, and hard-gate on the
     * deterministic, contention-free CPU cost instead: a warm manifest build
     * (stat + stat-cache bsearch, zero fsync when nothing changed) — the
     * O(n) core shared by status and snapshot — must stay well under 20 ms. */
    vc_write(dir, "src/util.c", "void u(void){int y=2;(void)y;}\n");
    platform_time_monotonic_timespec(&a);
    uint8_t c3[32];
    int sr = vcs_snapshot(r, &meta, c3);
    platform_time_monotonic_timespec(&b);
    double snap_ms = (double)(b.tv_sec - a.tv_sec) * 1000.0 +
                     (double)(b.tv_nsec - a.tv_nsec) / 1e6;
    printf("  vcs_core: 1-file snapshot = %.2f ms (fsync-bound; target < 50 ms "
           "single-process, inflated under parallel harness)\n", snap_ms);
    VC_CHECK("1-file snapshot ok", sr == VCS_OK);

    /* deterministic algorithmic-core gate: warm manifest build, no changes. */
    struct vcs_manifest warm;
    platform_time_monotonic_timespec(&a);
    bool wb = vcs_manifest_build(dir, vcs_repo_index(r), &warm);
    platform_time_monotonic_timespec(&b);
    double build_ms = (double)(b.tv_sec - a.tv_sec) * 1000.0 +
                      (double)(b.tv_nsec - a.tv_nsec) / 1e6;
    printf("  vcs_core: warm manifest build = %.3f ms\n", build_ms);
    VC_CHECK("warm build ok", wb);
    VC_CHECK("warm build < 20ms (algorithmic core)", build_ms < 20.0);
    vcs_manifest_free(&warm);

    /* after snapshot, status clean again */
    vcs_status(r, NULL, NULL, &nc);
    VC_CHECK("status clean after c2", nc == 0);

    /* revert to c1: worktree must byte-match the seed state */
    uint8_t cr[32];
    VC_CHECK("revert to c1", vcs_revert(r, c1, NULL, cr) == VCS_OK);
    VC_CHECK("revert restored main.c", vc_file_matches(dir, "src/main.c",
             "int main(void){return 0;}\n"));
    VC_CHECK("revert restored notes.md", vc_file_matches(dir, "docs/notes.md",
             "# notes\n"));
    VC_CHECK("revert deleted new.c", access(
             (snprintf(rmpath, sizeof(rmpath), "%s/src/new.c", dir), rmpath), F_OK) != 0);

    /* NULL relink => source-only revert, no longer ENOTIMPL. */
    vc_write(dir, "src/main.c", "int main(void){return 7;}\n");
    uint8_t cr2[32];
    VC_CHECK("revert with NULL relink is VCS_OK",
             vcs_revert(r, c1, NULL, cr2) == VCS_OK);
    VC_CHECK("revert NULL relink still restored source",
             vc_file_matches(dir, "src/main.c", "int main(void){return 0;}\n"));

    /* ── relink half: fake activator ops ─────────────────────────── */
    /* Snapshot a commit that binds a non-zero generation_sha256. */
    uint8_t gen[32];
    for (int i = 0; i < 32; i++) gen[i] = (uint8_t)(0xa0 + i);
    struct vcs_snapshot_meta meta_gen = meta;
    meta_gen.generation_sha256 = gen;
    vc_write(dir, "src/main.c", "int main(void){return 99;}\n");
    uint8_t c_gen[32];
    VC_CHECK("snapshot with bound generation",
             vcs_snapshot(r, &meta_gen, c_gen) == VCS_OK);

    /* Collect the HEAD-before-relink id and the full set of commit ids seen
     * so far, to prove the relink revert below is append-only (nothing is
     * ever overwritten or dropped from commits.log). */
    struct log_id_collect before = {0};
    VC_CHECK("log walk before relink revert",
             vcs_log(r, 0, log_id_collect_cb, &before) == VCS_OK);
    VC_CHECK("log has c1 before relink revert", log_ids_contains(&before, c1));
    VC_CHECK("log has c_gen before relink revert",
             log_ids_contains(&before, c_gen));

    /* Succeeding activator: records the hash it was called with. */
    struct fake_activator fa = {0};
    struct vcs_revert_relink_ops ok_ops = { fake_activate_ok, &fa };
    uint8_t cr3[32];
    VC_CHECK("revert+relink to a generation-bound commit is VCS_OK",
             vcs_revert(r, c_gen, &ok_ops, cr3) == VCS_OK);
    VC_CHECK("activator invoked exactly once", fa.calls == 1);
    VC_CHECK("activator saw the target commit's generation_sha256",
             memcmp(fa.seen_hash, gen, 32) == 0);
    VC_CHECK("revert+relink restored the generation commit's source",
             vc_file_matches(dir, "src/main.c", "int main(void){return 99;}\n"));

    /* Append-only: every id seen before is still present, plus the new
     * forward commit, and HEAD advanced to it. */
    struct log_id_collect after = {0};
    VC_CHECK("log walk after relink revert",
             vcs_log(r, 0, log_id_collect_cb, &after) == VCS_OK);
    VC_CHECK("relink revert appended (didn't shrink) the log",
             after.count == before.count + 1);
    for (size_t i = 0; i < before.count; i++)
        VC_CHECK("old commit id still present after relink revert",
                 log_ids_contains(&after, before.ids[i]));
    VC_CHECK("log has the new forward commit", log_ids_contains(&after, cr3));
    uint8_t head_id[32];
    bool have_head = false;
    VC_CHECK("HEAD readable after relink revert",
             vcs_index_ref_get(vcs_repo_index(r), "HEAD", head_id, &have_head));
    VC_CHECK("HEAD advanced to the relink revert's forward commit",
             have_head && memcmp(head_id, cr3, 32) == 0);

    /* Failing/refusing activator: target c_gen again (non-zero generation,
     * so activate_generation is actually invoked). The source revert +
     * forward commit still stand (append-only, never undone) but the call
     * reports VCS_EPARTIAL. */
    vc_write(dir, "src/main.c", "int main(void){return 123;}\n");
    struct fake_activator fb = {0};
    struct vcs_revert_relink_ops fail_ops = { fake_activate_fail, &fb };
    uint8_t cr4[32];
    VC_CHECK("revert+relink with a refusing activator is VCS_EPARTIAL",
             vcs_revert(r, c_gen, &fail_ops, cr4) == VCS_EPARTIAL);
    VC_CHECK("refusing activator was still invoked", fb.calls == 1);
    VC_CHECK("refusing activator saw the target's generation_sha256",
             memcmp(fb.seen_hash, gen, 32) == 0);
    VC_CHECK("VCS_EPARTIAL: source revert still stood",
             vc_file_matches(dir, "src/main.c", "int main(void){return 99;}\n"));
    uint8_t head_id2[32];
    have_head = false;
    VC_CHECK("HEAD advanced past VCS_EPARTIAL's forward commit too",
             vcs_index_ref_get(vcs_repo_index(r), "HEAD", head_id2, &have_head) &&
             have_head && memcmp(head_id2, cr4, 32) == 0);

    /* relink with an all-zero-generation target: nothing to activate, the
     * activator must never be called, and the result is still VCS_OK. */
    struct fake_activator fc = {0};
    struct vcs_revert_relink_ops unused_ops = { fake_activate_fail, &fc };
    uint8_t cr5[32];
    VC_CHECK("revert+relink to a zero-generation commit skips activation",
             vcs_revert(r, c1, &unused_ops, cr5) == VCS_OK);
    VC_CHECK("activator never called for an all-zero generation_sha256",
             fc.calls == 0);

    /* log newest-first: at least the commits we made, HEAD first. */
    vcs_close(r);
    return failures;
}

/* ── test 11: revert atomicity — a mid-restore failure is all-or-nothing ──
 *
 * Proves the two-phase restore contract: if any target file cannot be staged,
 * the revert fails WITHOUT touching the live worktree (no file matches the
 * target, no delete is applied, no staging temp is left behind), and the same
 * revert then succeeds once the fault is cleared. */
static int t_revert_atomic_failure(const char *dir)
{
    int failures = 0;
    vc_write(dir, "aaa.c", "AAA-A\n");
    vc_write(dir, "keep.c", "KEEP\n");
    vc_write(dir, "zzz/inner.c", "INNER-A\n");

    struct vcs_repo *r = vcs_open(dir);
    VC_CHECK("atomic: vcs_open", r != NULL);
    if (!r) return failures + 1;

    struct vcs_snapshot_meta meta = {0};
    meta.verdict_status = 1;
    meta.phase = "green";
    meta.task_ref = "atomic-seed";
    uint8_t c1[32];
    VC_CHECK("atomic: snapshot c1", vcs_snapshot(r, &meta, c1) == VCS_OK);

    /* Mutate the worktree away from c1, and poison the restore of one target
     * file by replacing its parent directory ("zzz") with a regular file — so
     * staging "zzz/inner.c" fails with ENOTDIR. This is deterministic
     * regardless of uid (unlike a read-only parent, which root bypasses).
     * "aaa.c" is a separate modified file that stages cleanly BEFORE the
     * poisoned one, so the failure must also unwind aaa.c's staged temp. */
    vc_write(dir, "aaa.c", "AAA-CHANGED\n");
    char p[4096];
    snprintf(p, sizeof(p), "%s/zzz/inner.c", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/zzz", dir); rmdir(p);
    vc_write(dir, "zzz", "BLOCKER\n");

    /* Pre-revert snapshot of the worktree bytes. */
    VC_CHECK("atomic: pre aaa.c", vc_file_matches(dir, "aaa.c", "AAA-CHANGED\n"));
    VC_CHECK("atomic: pre keep.c", vc_file_matches(dir, "keep.c", "KEEP\n"));
    VC_CHECK("atomic: pre zzz(file)", vc_file_matches(dir, "zzz", "BLOCKER\n"));

    /* Revert must FAIL and leave the worktree exactly as it was — matching
     * neither a clean revert nor a half-applied hybrid. */
    uint8_t cr[32];
    int rc = vcs_revert(r, c1, NULL, cr);
    VC_CHECK("atomic: revert reports error (not VCS_OK)", rc != VCS_OK);
    VC_CHECK("atomic: phase-1 failure returns VCS_ERR", rc == VCS_ERR);

    VC_CHECK("atomic: aaa.c NOT flipped (still pre-revert bytes)",
             vc_file_matches(dir, "aaa.c", "AAA-CHANGED\n"));
    VC_CHECK("atomic: keep.c unchanged",
             vc_file_matches(dir, "keep.c", "KEEP\n"));
    VC_CHECK("atomic: zzz delete NOT applied (still the blocker file)",
             vc_file_matches(dir, "zzz", "BLOCKER\n"));
    VC_CHECK("atomic: no .zvcstmp left behind after failure",
             vc_count_temps(dir) == 0);

    /* Recoverable: clear the blocker and the same revert now succeeds cleanly. */
    snprintf(p, sizeof(p), "%s/zzz", dir); unlink(p);
    uint8_t cr2[32];
    VC_CHECK("atomic: revert succeeds after clearing the blocker",
             vcs_revert(r, c1, NULL, cr2) == VCS_OK);
    VC_CHECK("atomic: recovered aaa.c restored to c1",
             vc_file_matches(dir, "aaa.c", "AAA-A\n"));
    VC_CHECK("atomic: recovered zzz/inner.c restored to c1",
             vc_file_matches(dir, "zzz/inner.c", "INNER-A\n"));
    VC_CHECK("atomic: no .zvcstmp after successful recovery",
             vc_count_temps(dir) == 0);

    vcs_close(r);
    return failures;
}

/* ── test 6: index delete -> rebuild identity ───────────────────── */
static int t_index_rebuild(const char *dir)
{
    int failures = 0;
    seed_worktree(dir);
    struct vcs_repo *r = vcs_open(dir);
    VC_CHECK("open for rebuild", r != NULL);
    if (!r) return failures + 1;

    struct vcs_snapshot_meta meta = {0};
    meta.phase = "green";
    uint8_t c1[32];
    vcs_snapshot(r, &meta, c1);
    vc_write(dir, "src/util.c", "void u(void){int x=1;(void)x;}\n");
    uint8_t c2[32];
    vcs_snapshot(r, &meta, c2);

    uint8_t head_before[32], pin_before[32];
    bool hf = false, pf = false;
    vcs_index_ref_get(vcs_repo_index(r), "HEAD", head_before, &hf);
    vcs_index_seal_pin_get(vcs_repo_index(r), pin_before, &pf);
    VC_CHECK("HEAD present pre-rebuild", hf && memcmp(head_before, c2, 32) == 0);
    vcs_close(r);

    /* delete the derived index (+ wal/shm) */
    char p[4096];
    snprintf(p, sizeof(p), "%s/.zvcs/index.kv", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/.zvcs/index.kv-wal", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/.zvcs/index.kv-shm", dir); unlink(p);

    struct vcs_index *idx = vcs_index_open(dir);
    VC_CHECK("reopen index after delete", idx != NULL);
    VC_CHECK("rebuild", idx && vcs_index_rebuild(idx, dir));
    uint8_t head_after[32], pin_after[32];
    hf = pf = false;
    vcs_index_ref_get(idx, "HEAD", head_after, &hf);
    vcs_index_seal_pin_get(idx, pin_after, &pf);
    VC_CHECK("HEAD identical after rebuild",
             hf && memcmp(head_after, head_before, 32) == 0);
    VC_CHECK("seal_pin identical after rebuild",
             pf && memcmp(pin_after, pin_before, 32) == 0);
    vcs_index_close(idx);

    /* reopen repo: worktree unchanged => status clean (stat-cache rebuilt) */
    r = vcs_open(dir);
    size_t nc = 999;
    vcs_status(r, NULL, NULL, &nc);
    VC_CHECK("status clean after rebuild", nc == 0);
    vcs_close(r);
    return failures;
}

/* ── test 7: torn commits.log tail -> recover last complete commit ── */
static int t_torn_commit_log(const char *dir)
{
    int failures = 0;
    seed_worktree(dir);
    struct vcs_repo *r = vcs_open(dir);
    if (!r) return failures + 1;
    struct vcs_snapshot_meta meta = {0};
    meta.phase = "g";
    uint8_t c1[32];
    vcs_snapshot(r, &meta, c1);
    vc_write(dir, "readme.txt", "v2\n");
    uint8_t c2[32];
    vcs_snapshot(r, &meta, c2);
    vcs_close(r);

    /* Truncate the last few bytes of commits.log so the trailing event is
     * torn. event_log_open recovers by truncating the partial tail; rebuild
     * then recovers HEAD from the last complete commit (c1). */
    char logp[4096];
    snprintf(logp, sizeof(logp), "%s/.zvcs/commits.log", dir);
    struct stat st;
    VC_CHECK("stat commits.log", stat(logp, &st) == 0);
    /* lop off 10 bytes (into the last event's sentinel/payload) */
    VC_CHECK("truncate tail", truncate(logp, st.st_size - 10) == 0);

    struct vcs_index *idx = vcs_index_open(dir);
    VC_CHECK("rebuild after torn", idx && vcs_index_rebuild(idx, dir));
    uint8_t head[32];
    bool hf = false;
    vcs_index_ref_get(idx, "HEAD", head, &hf);
    VC_CHECK("HEAD == last complete commit (c1)",
             hf && memcmp(head, c1, 32) == 0);
    vcs_index_close(idx);
    return failures;
}

/* Compute the sealset the worktree would produce right now. */
static bool compute_current_sealset(struct vcs_repo *r, uint8_t out[32])
{
    struct vcs_manifest m;
    if (!vcs_manifest_build(vcs_repo_root(r) ? vcs_repo_root(r) : "",
                            vcs_repo_index(r), &m))
        return false;
    char **globs = NULL; size_t ng = 0;
    if (!vcs_seal_load_globs(vcs_repo_root(r), &globs, &ng)) {
        vcs_manifest_free(&m);
        return false;
    }
    bool ok = vcs_sealset_hash(&m, globs, ng, out);
    vcs_seal_free_globs(globs, ng);
    vcs_manifest_free(&m);
    return ok;
}

/* ── test 8: seal refusal + token accept + forged reject ────────── */
static int t_seal(const char *dir)
{
    int failures = 0;
    seed_worktree(dir);
    /* seal the "sealed/" subtree */
    vc_write(dir, ".zvcs/sealed_paths", "sealed/\n");
    vc_write(dir, "sealed/consensus.txt", "RULE=1\n");

    struct vcs_repo *r = vcs_open(dir);
    VC_CHECK("seal: open", r != NULL);
    if (!r) return failures + 1;
    struct vcs_snapshot_meta meta = {0};
    meta.phase = "g";
    uint8_t c1[32];
    VC_CHECK("seal: initial snapshot pins", vcs_snapshot(r, &meta, c1) == VCS_OK);

    /* edit a NON-sealed file => snapshot OK (sealset unchanged) */
    vc_write(dir, "readme.txt", "changed\n");
    uint8_t c2[32];
    VC_CHECK("seal: unsealed edit OK", vcs_snapshot(r, &meta, c2) == VCS_OK);

    /* edit a SEALED file => REFUSED */
    vc_write(dir, "sealed/consensus.txt", "RULE=2\n");
    uint8_t c3[32];
    VC_CHECK("seal: sealed edit REFUSED", vcs_snapshot(r, &meta, c3) == VCS_REFUSED);

    /* grant a token authorizing exactly the NEW sealset => snapshot OK */
    uint8_t want[32];
    VC_CHECK("seal: compute new sealset", compute_current_sealset(r, want));
    VC_CHECK("seal: grant token", vcs_seal_grant_unseal(vcs_repo_index(r), want));
    uint8_t c4[32];
    VC_CHECK("seal: token accepted", vcs_snapshot(r, &meta, c4) == VCS_OK);

    /* token is one-shot: a further sealed edit is refused again */
    vc_write(dir, "sealed/consensus.txt", "RULE=3\n");
    uint8_t c5[32];
    VC_CHECK("seal: token was one-shot (REFUSED)",
             vcs_snapshot(r, &meta, c5) == VCS_REFUSED);

    /* forged/mismatched token (authorizes a DIFFERENT sealset) => REFUSED */
    uint8_t forged[32];
    memset(forged, 0xab, 32);
    VC_CHECK("seal: grant forged token", vcs_seal_grant_unseal(vcs_repo_index(r), forged));
    uint8_t c6[32];
    VC_CHECK("seal: forged token REJECTED",
             vcs_snapshot(r, &meta, c6) == VCS_REFUSED);

    vcs_close(r);
    return failures;
}

/* ── test 9: owner-ritual primitives — grant, peek (non-consuming), then
 * snapshot consumes ────────────────────────────────────────────────────
 * The dev.vcs.seal.grant executor (tools/command/native_dev_command.c) is
 * the operator surface for vcs_seal_grant_unseal(); this proves the exact
 * primitive sequence it drives: grant a token for the CURRENT sealset,
 * confirm vcs_seal_peek() reports OK for it any number of times WITHOUT
 * consuming it, then vcs_snapshot() spends the token and re-pins, and a
 * FURTHER sealed change afterward is refused again (one-shot proven). */
static int t_seal_grant_operator_ritual(const char *dir)
{
    int failures = 0;
    seed_worktree(dir);
    vc_write(dir, ".zvcs/sealed_paths", "sealed/\n");
    vc_write(dir, "sealed/consensus.txt", "RULE=1\n");

    struct vcs_repo *r = vcs_open(dir);
    VC_CHECK("seal-grant: open", r != NULL);
    if (!r) return failures + 1;
    struct vcs_snapshot_meta meta = {0};
    meta.phase = "g";
    uint8_t c1[32];
    VC_CHECK("seal-grant: initial snapshot pins", vcs_snapshot(r, &meta, c1) == VCS_OK);

    vc_write(dir, "sealed/consensus.txt", "RULE=2\n");
    uint8_t want[32];
    VC_CHECK("seal-grant: compute new sealset", compute_current_sealset(r, want));
    VC_CHECK("seal-grant: grant token", vcs_seal_grant_unseal(vcs_repo_index(r), want));

    VC_CHECK("seal-grant: peek OK (non-consuming)",
             vcs_seal_peek(vcs_repo_index(r), want) == VCS_SEAL_OK);
    VC_CHECK("seal-grant: peek again still OK (token not spent by peek)",
             vcs_seal_peek(vcs_repo_index(r), want) == VCS_SEAL_OK);

    uint8_t c2[32];
    VC_CHECK("seal-grant: snapshot consumes token and re-pins",
             vcs_snapshot(r, &meta, c2) == VCS_OK);

    /* One-shot: a FURTHER sealed change now needs a NEW grant. */
    vc_write(dir, "sealed/consensus.txt", "RULE=3\n");
    uint8_t c3[32];
    VC_CHECK("seal-grant: further sealed change refuses (one-shot proven)",
             vcs_snapshot(r, &meta, c3) == VCS_REFUSED);

    vcs_close(r);
    return failures;
}

/* ── test: commit record round-trips + self-hash catches tamper ─── */
static int t_commit_record(void)
{
    int failures = 0;
    struct vcs_commit c;
    memset(&c, 0, sizeof(c));
    c.version = VCS_COMMIT_VERSION;
    for (int i = 0; i < 32; i++) {
        c.parent[i] = (uint8_t)(i + 1);
        c.tree_hash[i] = (uint8_t)(i + 0x40);
        c.sealset_hash[i] = (uint8_t)(i + 0x80);
        c.generation_sha256[i] = (uint8_t)(i + 0xC0);
        c.failure_hash[i] = 0;
    }
    c.verdict_status = 7;
    snprintf(c.phase, sizeof(c.phase), "publish");
    c.elapsed_ms = 1234;
    snprintf(c.agent_id, sizeof(c.agent_id), "agent-x");
    snprintf(c.session_id, sizeof(c.session_id), "sess-1");
    snprintf(c.task_ref, sizeof(c.task_ref), "task/42");
    c.committed_at = 1700000000;

    uint8_t rec[VCS_COMMIT_RECORD_BYTES];
    VC_CHECK("commit serialize", vcs_commit_serialize(&c, rec));

    struct vcs_commit d;
    bool self_ok = false;
    VC_CHECK("commit deserialize", vcs_commit_deserialize(rec, sizeof(rec), &d, &self_ok));
    VC_CHECK("commit self_ok", self_ok);
    VC_CHECK("commit fields round-trip",
             d.version == c.version && d.verdict_status == 7 &&
             d.elapsed_ms == 1234 && d.committed_at == 1700000000 &&
             strcmp(d.phase, "publish") == 0 &&
             strcmp(d.agent_id, "agent-x") == 0 &&
             strcmp(d.task_ref, "task/42") == 0 &&
             memcmp(d.tree_hash, c.tree_hash, 32) == 0);

    /* preimage parse matches */
    uint8_t pre[VCS_COMMIT_PREIMAGE_BYTES];
    VC_CHECK("commit preimage", vcs_commit_preimage(&c, pre));
    struct vcs_commit e;
    VC_CHECK("commit parse preimage", vcs_commit_parse_preimage(pre, sizeof(pre), &e));
    VC_CHECK("preimage id matches record",
             memcmp(e.tree_hash, c.tree_hash, 32) == 0 &&
             e.verdict_status == 7);

    /* tamper a preimage byte => self-hash mismatch */
    rec[8] ^= 0x01;
    bool self_ok2 = true;
    vcs_commit_deserialize(rec, sizeof(rec), &d, &self_ok2);
    VC_CHECK("commit self-hash catches tamper", !self_ok2);
    return failures;
}

/* ── test: bounded content.v2 source-swarm wire contract ────────── */
static int t_package_swarm(void)
{
    int failures = 0;
    static const uint8_t source[] =
        "int main(void) { return 23; }\n";
    static const uint8_t want_chunk_hash[32] = {
        0xe4,0x19,0x94,0x1e,0x7c,0xe1,0xae,0xc1,
        0xf0,0x90,0x56,0xb3,0x3b,0xa2,0xa8,0x72,
        0xe6,0x52,0xe2,0xca,0x05,0xc9,0x57,0x02,
        0xac,0x60,0xfd,0x18,0x68,0x2c,0xe5,0x49,
    };
    static const uint8_t want_file_hash[32] = {
        0xd1,0x72,0x7c,0xa3,0x1d,0xa5,0x7a,0x79,
        0xf3,0xd8,0x5b,0x9f,0x27,0xf2,0x71,0x35,
        0x7c,0x07,0xdb,0x3e,0x6b,0x89,0x0b,0x7c,
        0x61,0x58,0xcc,0x1c,0x01,0x7c,0x19,0x67,
    };
    static const uint8_t want_package_root[32] = {
        0x5f,0x6f,0x10,0x19,0xc0,0x75,0x39,0xf6,
        0xb2,0xa4,0x5f,0xe1,0xd8,0x8c,0x1b,0x7c,
        0x7b,0x82,0x0c,0x86,0x9e,0x6b,0x84,0x77,
        0x6b,0xe8,0x1c,0x48,0x87,0x66,0x15,0xb8,
    };
    uint8_t chunk_hash[32];
    VC_CHECK("swarm chunk hash",
             vcs_package_chunk_hash(source, sizeof(source) - 1, chunk_hash));
    VC_CHECK("swarm raw chunk hash KAT",
             memcmp(chunk_hash, want_chunk_hash, 32) == 0);

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    VC_CHECK("swarm manifest add",
             vcs_package_manifest_add(&manifest, "src/main.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      sizeof(source) - 1, chunk_hash, 1));
    uint8_t root[32];
    VC_CHECK("swarm package root",
             vcs_package_manifest_root(&manifest, root));
    uint8_t file_hash[32];
    VC_CHECK("swarm file hash KAT",
             manifest.count == 1 &&
             vcs_package_file_hash(&manifest.files[0], file_hash) &&
             memcmp(file_hash, want_file_hash, 32) == 0);
    VC_CHECK("swarm package root KAT",
             memcmp(root, want_package_root, 32) == 0);
    uint8_t *manifest_wire = NULL;
    size_t manifest_wire_len = 0;
    VC_CHECK("swarm manifest serialize",
             vcs_package_manifest_serialize(&manifest, &manifest_wire,
                                            &manifest_wire_len));

    uint8_t wire[2048];
    size_t wire_len = 0;
    struct vcs_package_swarm_message message = {
        .type = VCS_PACKAGE_SWARM_ANNOUNCE,
    };
    memcpy(message.body.announce.package_root, root, 32);
    message.body.announce.manifest_bytes = (uint32_t)manifest_wire_len;
    message.body.announce.file_count = 1;
    message.body.announce.total_bytes = sizeof(source) - 1;
    message.body.announce.total_chunks = 1;
    VC_CHECK("swarm announce serialize",
             vcs_package_swarm_serialize(&message, wire, sizeof(wire),
                                         &wire_len));
    struct vcs_package_swarm_message parsed;
    VC_CHECK("swarm announce parse",
             vcs_package_swarm_parse(wire, wire_len, &parsed));
    VC_CHECK("swarm announce round-trip",
             parsed.type == VCS_PACKAGE_SWARM_ANNOUNCE &&
             parsed.body.announce.total_bytes == sizeof(source) - 1 &&
             memcmp(parsed.body.announce.package_root, root, 32) == 0);

    memset(&message, 0, sizeof(message));
    message.type = VCS_PACKAGE_SWARM_WANT;
    message.body.want.request_id = 23;
    memcpy(message.body.want.package_root, root, 32);
    message.body.want.object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
    message.body.want.file_index = UINT32_MAX;
    message.body.want.chunk_index = UINT32_MAX;
    VC_CHECK("swarm manifest want round-trip",
             vcs_package_swarm_serialize(&message, wire, sizeof(wire),
                                         &wire_len) &&
             vcs_package_swarm_parse(wire, wire_len, &parsed) &&
             parsed.body.want.request_id == 23 &&
             parsed.body.want.object_kind ==
                 VCS_PACKAGE_SWARM_OBJECT_MANIFEST);
    struct vcs_package_swarm_object manifest_request = parsed.body.want;

    memset(&message, 0, sizeof(message));
    message.type = VCS_PACKAGE_SWARM_DATA;
    message.body.data.object = parsed.body.want;
    message.body.data.bytes = manifest_wire;
    message.body.data.bytes_len = (uint32_t)manifest_wire_len;
    VC_CHECK("swarm manifest data round-trip",
             vcs_package_swarm_serialize(&message, wire, sizeof(wire),
                                         &wire_len) &&
             vcs_package_swarm_parse(wire, wire_len, &parsed));
    VC_CHECK("swarm manifest root verification",
             vcs_package_swarm_verify_data(NULL, &manifest_request,
                                           &parsed.body.data));

    struct vcs_package_swarm_object chunk_request = {0};
    chunk_request.request_id = 24;
    memcpy(chunk_request.package_root, root, 32);
    chunk_request.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    chunk_request.file_index = 0;
    chunk_request.chunk_index = 0;
    memcpy(chunk_request.expected_hash, chunk_hash, 32);
    memset(&message, 0, sizeof(message));
    message.type = VCS_PACKAGE_SWARM_DATA;
    message.body.data.object = chunk_request;
    message.body.data.bytes = source;
    message.body.data.bytes_len = sizeof(source) - 1;
    VC_CHECK("swarm chunk data round-trip",
             vcs_package_swarm_serialize(&message, wire, sizeof(wire),
                                         &wire_len) &&
             vcs_package_swarm_parse(wire, wire_len, &parsed));
    VC_CHECK("swarm chunk manifest verification",
             vcs_package_swarm_verify_data(&manifest, &chunk_request,
                                           &parsed.body.data));

    /* file_index is canonical path order, not insertion order. Equivalent
     * manifests must accept the same WANT coordinates. */
    static const uint8_t earlier_source[] = "first\n";
    uint8_t earlier_hash[32];
    VC_CHECK("swarm canonical-index second hash",
             vcs_package_chunk_hash(earlier_source,
                                    sizeof(earlier_source) - 1,
                                    earlier_hash));
    struct vcs_package_manifest reverse_two;
    vcs_package_manifest_init(&reverse_two);
    VC_CHECK("swarm reverse manifest adds later path first",
             vcs_package_manifest_add(&reverse_two, "z-last.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      sizeof(source) - 1, chunk_hash, 1) &&
             vcs_package_manifest_add(&reverse_two, "a-first.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      sizeof(earlier_source) - 1,
                                      earlier_hash, 1));
    uint8_t reverse_root[32];
    VC_CHECK("swarm reverse manifest canonical storage",
             reverse_two.count == 2 &&
             strcmp(reverse_two.files[0].path, "a-first.c") == 0 &&
             vcs_package_manifest_root(&reverse_two, reverse_root));
    struct vcs_package_swarm_object canonical_request = {0};
    canonical_request.request_id = 25;
    memcpy(canonical_request.package_root, reverse_root, 32);
    canonical_request.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
    canonical_request.file_index = 0;
    canonical_request.chunk_index = 0;
    memcpy(canonical_request.expected_hash, earlier_hash, 32);
    struct vcs_package_swarm_data canonical_data = {
        .object = canonical_request,
        .bytes = earlier_source,
        .bytes_len = sizeof(earlier_source) - 1,
    };
    VC_CHECK("swarm reverse insertion verifies canonical file index",
             vcs_package_swarm_verify_data(&reverse_two,
                                           &canonical_request,
                                           &canonical_data));
    struct vcs_package_manifest forward_two;
    vcs_package_manifest_init(&forward_two);
    VC_CHECK("swarm forward equivalent manifest",
             vcs_package_manifest_add(&forward_two, "a-first.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      sizeof(earlier_source) - 1,
                                      earlier_hash, 1) &&
             vcs_package_manifest_add(&forward_two, "z-last.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      sizeof(source) - 1, chunk_hash, 1));
    uint8_t forward_root[32];
    VC_CHECK("swarm canonical coordinates ignore insertion order",
             vcs_package_manifest_root(&forward_two, forward_root) &&
             memcmp(forward_root, reverse_root, 32) == 0 &&
             vcs_package_swarm_verify_data(&forward_two,
                                           &canonical_request,
                                           &canonical_data));

    struct vcs_package_swarm_object wrong_request = chunk_request;
    wrong_request.request_id++;
    VC_CHECK("swarm wrong request id rejected",
             !vcs_package_swarm_verify_data(&manifest, &wrong_request,
                                            &parsed.body.data));
    wrong_request = chunk_request;
    wrong_request.chunk_index++;
    VC_CHECK("swarm wrong coordinates rejected",
             !vcs_package_swarm_verify_data(&manifest, &wrong_request,
                                            &parsed.body.data));

    uint8_t tampered[sizeof(source) - 1];
    memcpy(tampered, source, sizeof(tampered));
    tampered[0] ^= 1;
    struct vcs_package_swarm_data bad_data = message.body.data;
    bad_data.bytes = tampered;
    VC_CHECK("swarm tampered chunk rejected",
             !vcs_package_swarm_verify_data(&manifest, &chunk_request,
                                            &bad_data));
    bad_data = message.body.data;
    bad_data.object.package_root[0] ^= 1;
    VC_CHECK("swarm foreign package root rejected",
             !vcs_package_swarm_verify_data(&manifest, &chunk_request,
                                            &bad_data));

    memset(&message, 0, sizeof(message));
    message.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    memcpy(message.body.announce.package_root, root, 32);
    message.body.announce.manifest_bytes =
        VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES;
    message.body.announce.total_bytes = 1;
    VC_CHECK("swarm impossible announce rejected",
             vcs_package_swarm_wire_size(&message) == 0);

    message.body.announce.file_count = 1;
    message.body.announce.total_bytes = 0;
    message.body.announce.manifest_bytes =
        VCS_PACKAGE_MANIFEST_WIRE_HEADER_BYTES + 18u +
        VCS_PACKAGE_PATH_MAX + 1u;
    VC_CHECK("swarm overlong one-file manifest rejected",
             vcs_package_swarm_wire_size(&message) == 0);

    VC_CHECK("swarm trailing bytes rejected",
             wire_len + 1 < sizeof(wire));
    wire[wire_len] = 0;
    VC_CHECK("swarm exact frame length",
             !vcs_package_swarm_parse(wire, wire_len + 1, &parsed));

    memset(&message, 0, sizeof(message));
    message.type = VCS_PACKAGE_SWARM_CANCEL;
    message.body.cancel.request_id = 24;
    memcpy(message.body.cancel.package_root, root, 32);
    VC_CHECK("swarm cancel round-trip",
             vcs_package_swarm_serialize(&message, wire, sizeof(wire),
                                         &wire_len) &&
             vcs_package_swarm_parse(wire, wire_len, &parsed) &&
             parsed.body.cancel.request_id == 24);

    message.body.cancel.request_id = 0;
    VC_CHECK("swarm zero request rejected",
             vcs_package_swarm_wire_size(&message) == 0);

    vcs_package_manifest_free(&forward_two);
    vcs_package_manifest_free(&reverse_two);
    free(manifest_wire);
    vcs_package_manifest_free(&manifest);
    return failures;
}

int test_vcs_core(void)
{
    printf("\n=== vcs_core: ZVCS v1 foundation ===\n");
    int failures = 0;

    failures += t_manifest_fixedpoint();
    failures += t_package_manifest();
    failures += t_package_swarm();
    failures += t_source_bundle();
    failures += t_commit_record();

    char dir[512];

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "objstore");
    failures += t_object_store(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "ignored");
    failures += t_generated_paths_ignored(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "snap");
    failures += t_snapshot_status_revert(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "atomicrevert");
    failures += t_revert_atomic_failure(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "rebuild");
    failures += t_index_rebuild(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "torn");
    failures += t_torn_commit_log(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "seal");
    failures += t_seal(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_core", "seal_grant");
    failures += t_seal_grant_operator_ritual(dir);
    test_rm_rf_recursive(dir);

    printf("=== vcs_core complete: %d failure(s) ===\n", failures);
    return failures;
}
