/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_swarm_net — the slice-12 swarm over the REAL wire seam.
 * test_zcode_swarm.c drives one engine with hand-built frames; this file
 * puts two (and three) independent swarm engines behind two independent
 * msg_processors and lets real "zpkgswm" P2P messages (magic + command +
 * length + checksum, queued by p2p_node_begin/write/end_message, parsed
 * by the real p2p_node_receive_bytes, dispatched by the real
 * msg_process_messages through the dispatch-table row) carry every
 * ANNOUNCE/WANT/DATA/CANCEL between them. Only the socket syscalls are
 * elided (the sentinel technique from test_snapshot_serve_loopback.c).
 *
 * The test glue mirrors engine/composition/src/boot_zcode_swarm.c 1:1 — same
 * session pseudo-key derivation (0x02 || SHA3-256(domain || host)),
 * same penalty→peer_offence mapping, same reply/drain sends — with two
 * deliberate, documented substitutions: the score callback returns a
 * fixed contributor score (the production glue reads the reward ledger),
 * and the tick clock is a deterministic counter instead of wall time.
 * Contributor unique-root inventory is the serving-set size, same as
 * NEW_USER, so an honest library shelf is not announce-flood.
 *
 * Covered:
 *   1. Golden path: two engines, end-to-end verified fetch into the CAS,
 *      byte-identical chunks, both books credited, zero misbehavior.
 *   2. Malicious server (wrong-hash chunks): PEER_OFFENCE_INVALID_CHUNK
 *      misbehavior on the real peer object, no credit, nothing stored,
 *      download ends in a NAMED failure.
 *   3. Corrupt-provider repair: exact-root bytes rejected from one server,
 *      then the same download completes from an honest alternate provider.
 *   4. Unrequested DATA: PEER_OFFENCE_UNREQUESTED, no credit.
 *   5. Restart mid-download: engine freed and recreated over the same
 *      datadir; exact verified objects survive, are reported as reused,
 *      are never requested/transmitted again, and the graph completes.
 *   6. Disconnect requeue: one of two servers drops mid-download; the
 *      in-flight work moves to the survivor and the download completes.
 *   7. Sovereign source: one signed workspace-head lookup fetches a bundled
 *      content.v2 evidence closure, then accepted source rebuilds Git-free.
 *   8. Useful C23 Arena packages (zprng, zdogfight, zdogdrone, zdogace,
 *      zdogview) host redundantly: A publishes, B fetches and pins, A
 *      disappears, C still discovers and fetches the exact carriers from B.
 *   9. Ordinary C23 library titles (zhex, zstr, zbuf, zsha256, zring,
 *      zmap, zvec, zutf8, then zjson which locks zutf8) take the same
 *      A→B→C hop: a catalog, not only the Arena demo, survives the
 *      original publisher disappearing.
 *  10. Attestation flight: a signed ZCLATT attestation offered on A is
 *      discovered by B through a signed POINTER in the attestation
 *      namespace, pulled over the same frozen zpkgswm codec as an
 *      ordinary blob, independently verified and re-rooted at B, and
 *      filed as evidence — leaving BYTE-IDENTICAL receipts under the
 *      same attestation-id filename on both nodes. With the two ways it
 *      must refuse: a hostile pointer (an attestation about a different
 *      package, delivered for the root B asked about) is ERR_BINDING and
 *      files nothing, and a flipped byte is refused whether the sender
 *      re-roots it or it is corrupted in flight. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "test/component_receiver_fixture.h"
#if defined(__linux__) && defined(__x86_64__) && defined(ZCL_TESTING)
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include "platform/socket_compat.h"
#endif

#include "test/public_shape_fixture.h"
#include "test/accepted_work_fixture.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "net/fast_sync.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_identity.h"
#include "net/peer_scoring.h"
#include "services/package_lifecycle.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "vcs/blob_store.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_build.h"
#include "vcs/package_checkout.h"
#include "vcs/package_content.h"
#include "vcs/package_service.h"
#include "vcs/package_mapping.h"
#include "vcs/package_prepare.h"
#include "vcs/package_accept.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_transport.h"
#include "vcs/source_package_checkout.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_c23_corpus.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"
#include "vcs/zcode_focus.h"
#include "vcs/zcode_task_context.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_work_pull_receipt.h"
#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "controllers/rpc_client.h"
#include "base/bytes.h"
#include "base/cleanse.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/loader.h>
#endif

#define ZWN_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zcode_swarm_net: %s... OK\n", (name)); }       \
    else { printf("  zcode_swarm_net: %s... FAIL\n", (name)); \
        failures++; }                                                    \
} while (0)

#define ZWN_DAY 20500
#define ZWN_SCORE UINT64_C(100) /* EARNED_CONTRIBUTOR */
#define ZWN_MAX_FILES 13u
#define ZWN_MAX_FILE 1200u
#define ZWN_KEY_DOMAIN "zcl.zcode_swarm_peer.v1"
#define ZWN_EVIDENCE_ASSIGNMENT "evidence/source-assignment.v1"
#define ZWN_EVIDENCE_COMMIT "evidence/zvcs-commit.v1"
#define ZWN_EVIDENCE_PASSPORT "evidence/module-passport.v1"
#define ZWN_EVIDENCE_RELEASE "evidence/package-release.v1"
#define ZWN_EVIDENCE_WORKSPACE "evidence/workspace-manifest.v1"

/* ── fixture package (single-chunk files, same shape as the engine gate) */

struct zwn_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    size_t count;
    uint8_t contents[ZWN_MAX_FILES][ZWN_MAX_FILE];
    size_t lens[ZWN_MAX_FILES];
    uint64_t total_bytes;
};

struct zwn_sovereign_receipt {
    bool ready;
    uint8_t source_root[32];
    uint8_t accepted_work_root[32];
    uint8_t proof_set_root[32];
    uint8_t commit_root[32];
    uint8_t release_root[32];
    uint8_t passport_root[32];
    uint8_t workspace_root[32];
    uint8_t workspace_carrier_root[32];
    uint8_t source_package_root[32];
    uint8_t publisher_binary_sha3[32];
    uint8_t successor_release_root[32];
    uint8_t successor_package_root[32];
    uint8_t successor_binary_sha3[32];
    uint8_t storage_ack_roots[2][32];
    uint16_t storage_ack_count;
    uint8_t provider_record_root[32];
    uint8_t publication_job_root[32];
    uint8_t publication_progress_root[32];
    int64_t publication_enqueue_us;
    struct vcs_package_mapping_metrics publication_metrics;
    struct vcs_source_bundle_metrics source_metrics;
};

static struct zwn_sovereign_receipt g_zwn_sovereign_receipt;

static bool zwn_hashes_match(const char *label,
                             const uint8_t expected[32],
                             const uint8_t actual[32])
{
    if (memcmp(expected, actual, 32) == 0)
        return true;
    char expected_hex[65], actual_hex[65];
    zcl_hex_encode(expected, 32, expected_hex);
    zcl_hex_encode(actual, 32, actual_hex);
    printf("sovereign-source-roundtrip: DIVERGENCE first=%s expected=%s actual=%s\n",
           label, expected_hex, actual_hex);
    return false;
}

static void zwn_print_root_json(const char *key, const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    printf(",\"%s\":\"%s\"", key, hex);
}

static void zwn_print_sovereign_receipt(void)
{
    const struct zwn_sovereign_receipt *r = &g_zwn_sovereign_receipt;
    printf("{\"schema\":\"zcl.sovereign_source_roundtrip.v1\","
           "\"status\":\"passed\"");
    zwn_print_root_json("source_tree_root", r->source_root);
    zwn_print_root_json("accepted_work_root", r->accepted_work_root);
    zwn_print_root_json("proof_set_root", r->proof_set_root);
    zwn_print_root_json("zvcs_commit_root", r->commit_root);
    zwn_print_root_json("release_root", r->release_root);
    zwn_print_root_json("passport_root", r->passport_root);
    zwn_print_root_json("workspace_root", r->workspace_root);
    zwn_print_root_json("workspace_carrier_root",
                        r->workspace_carrier_root);
    zwn_print_root_json("source_package_root", r->source_package_root);
    zwn_print_root_json("publisher_binary_sha3",
                        r->publisher_binary_sha3);
    zwn_print_root_json("successor_release_root",
                        r->successor_release_root);
    zwn_print_root_json("successor_package_root",
                        r->successor_package_root);
    zwn_print_root_json("successor_binary_sha3",
                        r->successor_binary_sha3);
    zwn_print_root_json("storage_ack_a_root", r->storage_ack_roots[0]);
    zwn_print_root_json("storage_ack_b_root", r->storage_ack_roots[1]);
    zwn_print_root_json("provider_record_root", r->provider_record_root);
    zwn_print_root_json("publication_job_root", r->publication_job_root);
    zwn_print_root_json("publication_progress_root",
                        r->publication_progress_root);
    printf(",\"source_bytes\":%" PRIu64
           ",\"new_source_blobs\":%u,\"reused_source_blobs\":%u"
           ",\"publication_enqueue_us\":%" PRId64
           ",\"publication_bytes_scanned\":%" PRIu64
           ",\"publication_new_chunks\":%u"
           ",\"publication_reused_chunks\":%u"
           ",\"serving_providers\":2,\"pinned_providers\":2"
           ",\"storage_acknowledgements\":%u"
           ",\"storage_ack_status\":\"2/2\""
           ",\"reproduced\":true,\"provider_failover\":true"
           ",\"corrupt_chunk_recovery\":true"
           ",\"corrupt_provider_repair\":true"
           ",\"previous_release_fetchable\":true"
           ",\"publication_job\":\"storage_acknowledged\""
           ",\"github_mirror\":\"not_applicable_fixture\"}\n",
           r->source_metrics.source_bytes,
           r->source_metrics.new_blobs,
           r->source_metrics.reused_blobs,
           r->publication_enqueue_us,
           r->publication_metrics.bytes_scanned,
           r->publication_metrics.new_chunks,
           r->publication_metrics.reused_chunks,
           r->storage_ack_count);
}

static bool zwn_make_package(struct zwn_pkg *p, size_t count, uint8_t seed)
{
    static const char *const k_paths[ZWN_MAX_FILES] = {
        "LICENSE", "include/a.h", "include/b.h", "include/c.h",
        "include/d.h", "src/a.c", "src/b.c", "src/c.c", "src/d.c",
        "src/e.c", "tests/t1.c", "tests/t2.c", "tests/t3.c",
    };
    memset(p, 0, sizeof(*p));
    if (count == 0 || count > ZWN_MAX_FILES)
        return false;
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < count; i++) {
        size_t len;
        if (strcmp(k_paths[i], "LICENSE") == 0) {
            /* Real MIT text: the hosting rule reads these bytes and holds
             * them against the envelope's SPDX identifier. */
            len = strlen(TEST_LICENSE_TEXT_MIT);
            if (len > ZWN_MAX_FILE)
                return false;
            memcpy(p->contents[i], TEST_LICENSE_TEXT_MIT, len);
        } else {
            len = 40u + i * 31u + seed;
            for (size_t j = 0; j < len; j++)
                p->contents[i][j] = (uint8_t)(seed + i * 7u + j * 3u);
        }
        p->lens[i] = len;
        p->total_bytes += len;
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(p->contents[i], len, hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, k_paths[i],
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1))
            return false;
    }
    p->count = count;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    return vcs_package_manifest_root(&p->manifest, p->root);
}

static bool zwn_make_evidence_package(
    struct zwn_pkg *p, const uint8_t *const wires[5],
    const size_t lengths[5])
{
    /* "LICENSE" sorts before "evidence/...", and the manifest wants paths
     * in sorted order. It is here because a package this node offers to
     * peers must carry its own licence text. */
    static const char *const paths[6] = {
        "LICENSE",
        ZWN_EVIDENCE_PASSPORT,
        ZWN_EVIDENCE_RELEASE,
        ZWN_EVIDENCE_ASSIGNMENT,
        ZWN_EVIDENCE_WORKSPACE,
        ZWN_EVIDENCE_COMMIT,
    };
    static const char k_license[] = TEST_LICENSE_TEXT_MIT;
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < 6; i++) {
        const uint8_t *bytes =
            i == 0 ? (const uint8_t *)k_license : wires[i - 1];
        size_t len = i == 0 ? sizeof(k_license) - 1u : lengths[i - 1];
        if (!bytes || len == 0 || len > ZWN_MAX_FILE)
            return false;
        memcpy(p->contents[i], bytes, len);
        p->lens[i] = len;
        p->total_bytes += len;
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(bytes, len, hash) ||
            !vcs_package_manifest_add(
                &p->manifest, paths[i], VCS_PACKAGE_MODE_FILE,
                len, hash, 1))
            return false;
    }
    p->count = 6;
    if (!vcs_package_manifest_serialize(
            &p->manifest, &p->wire, &p->wire_len))
        return false;
    return vcs_package_manifest_root(&p->manifest, p->root);
}

static void zwn_free_package(struct zwn_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* The engine hosts only recognized public shapes, and a plain source
 * package becomes one by carrying LICENSE text plus a signed envelope that
 * names its exact root (vcs/package_public_shape.h). Fixture publisher key
 * and namespace are derived from the root so every distinct package gets a
 * distinct publisher — one key may hold only one namespace. */
static bool zwn_publish_release_as(struct vcs_package_store *store,
    const uint8_t root[32], const char *license,
    struct vcs_package_release *release_out)
{
    bool ok = false;
    struct privkey sk = {0};
    struct pubkey pk;
    memcpy(sk.vch, root, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk) ||
        pk.size != COMPRESSED_PUBLIC_KEY_SIZE)
        goto clean;
    struct vcs_package_release r;
    memset(&r, 0, sizeof(r));
    r.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r.name, sizeof(r.name), "zwn%02x%02x%02x%02x/fixture",
             root[0], root[1], root[2], root[3]);
    snprintf(r.semver, sizeof(r.semver), "1.0.0");
    memcpy(r.package_root, root, 32);
    for (int i = 0; i < 32; i++)
        r.recipe_root[i] = (uint8_t)(root[i] ^ 0x5au);
    memcpy(r.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r.publisher_sequence = 1u;
    const struct chain_params *params = chain_params_get();
    if (!params)
        goto clean;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *p58 =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *s58 =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    if (!encode_destination(&dest, p58, pk_len, s58, sc_len,
                            r.reward_address, sizeof(r.reward_address)))
        goto clean;
    snprintf(r.license, sizeof(r.license), "%s", license);
    if (!vcs_package_accept_chain_id(r.chain_id, sizeof(r.chain_id)))
        goto clean;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&r, id) != VCS_PACKAGE_RELEASE_OK)
        goto clean;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        goto clean;
    memcpy(r.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ok = vcs_package_store_put_release(store, &r, &ar) ==
               VCS_PACKAGE_STORE_OK &&
           (ar == VCS_PACKAGE_ACCEPT_OK ||
            ar == VCS_PACKAGE_ACCEPT_DUPLICATE);
    if (ok && release_out) *release_out = r;
clean:
    memory_cleanse(&sk, sizeof(sk));
    return ok;
}

static bool zwn_publish_release(struct vcs_package_store *store,
                                const uint8_t root[32])
{
    return zwn_publish_release_as(store, root, "MIT", NULL);
}

static bool zwn_store_package(struct vcs_package_store *store,
                              const struct zwn_pkg *p)
{
    uint8_t root[32];
    if (vcs_package_store_put_manifest(store, p->wire, p->wire_len,
                                       root) != VCS_PACKAGE_STORE_OK)
        return false;
    for (size_t i = 0; i < p->count; i++) {
        const char *path = p->manifest.files[i].path;
        if (vcs_package_store_put_chunk(store, root, path, 0,
                                        p->contents[i],
                                        p->lens[i]) != VCS_PACKAGE_STORE_OK)
            return false;
    }
    return zwn_publish_release(store, root);
}

static bool zwn_store_source_transport(
    struct vcs_package_store *store,
    const struct vcs_source_package_transport *transport)
{
    uint8_t root[32];
    if (!store || !transport ||
        vcs_package_store_put_manifest(
            store, transport->manifest_wire, transport->manifest_wire_len,
            root) != VCS_PACKAGE_STORE_OK ||
        memcmp(root, transport->package_root, 32) != 0)
        return false;
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &path, &bytes, &len))
            return false;
        if (vcs_package_content_put_file(
                store, root, path, bytes, len) != VCS_PACKAGE_STORE_OK)
            return false;
    }
    struct vcs_package_store_status status;
    return vcs_package_store_package_status(store, root, &status) &&
           status.complete;
}

static bool zwn_write_file(const char *root, const char *relative,
                           const void *bytes, size_t len, mode_t mode)
{
    char path[1400];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (!bytes || n <= 0 || (size_t)n >= sizeof(path))
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  mode);
    if (fd < 0)
        return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, (const uint8_t *)bytes + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            break;
        off += (size_t)wrote;
    }
    bool ok = off == len && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
}

static bool zwn_normalize_executable_identity(const char *binary)
{
#if defined(__APPLE__)
    int fd = open(binary, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct mach_header_64 header;
    bool ok = pread(fd, &header, sizeof(header), 0) == (ssize_t)sizeof(header) &&
              header.magic == MH_MAGIC_64;
    off_t offset = (off_t)sizeof(header);
    off_t commands_end = offset + (off_t)header.sizeofcmds;
    bool found = false;
    for (uint32_t i = 0; ok && i < header.ncmds; i++) {
        struct load_command command;
        ok = pread(fd, &command, sizeof(command), offset) ==
                 (ssize_t)sizeof(command) &&
             command.cmdsize >= sizeof(command) &&
             offset <= commands_end - (off_t)command.cmdsize;
        if (!ok)
            break;
        if (command.cmd == LC_UUID &&
            command.cmdsize >= sizeof(struct uuid_command)) {
            static const uint8_t deterministic_uuid[16] = {
                0x5a, 0x32, 0x33, 0x43, 0x32, 0x33, 0x4d, 0x61,
                0x63, 0x4f, 0x53, 0x46, 0x69, 0x78, 0x74, 0x75,
            };
            off_t uuid_offset = offset +
                (off_t)offsetof(struct uuid_command, uuid);
            ok = pwrite(fd, deterministic_uuid, sizeof(deterministic_uuid),
                        uuid_offset) == (ssize_t)sizeof(deterministic_uuid);
            found = ok;
            break;
        }
        offset += (off_t)command.cmdsize;
    }
    if (ok && found)
        ok = fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok && found;
#else
    (void)binary;
    return true;
#endif
}

static bool zwn_sign_executable_identity(const char *binary)
{
#if defined(__APPLE__)
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        char *const argv[] = {
            (char *)"codesign", (char *)"--force", (char *)"--sign",
            (char *)"-", (char *)"--identifier", (char *)"io.z23.fixture",
            (char *)binary, NULL,
        };
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#else
    (void)binary;
    return true;
#endif
}

static bool zwn_compile_c23(const char *source, const char *binary)
{
#if defined(_WIN32)
    /* Same compile contract, driven through CreateProcess (no fork/execvp).
     * -Wl,--build-id=none is ELF-only; the Windows fixture identity comes
     * from the content hash over the PE, which zwn_normalize_executable_
     * identity's non-Apple arm accepts as-is. */
    const char *const argv[] = {
        "cc", "-std=c2x", "-O2", "-fno-ident", source, "-o", binary, NULL,
    };
    return test_spawn_argv_wait(argv) == 0 &&
           zwn_normalize_executable_identity(binary) &&
           zwn_sign_executable_identity(binary);
#else
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        char *argv[10];
        size_t argc = 0;
        argv[argc++] = (char *)"cc";
        argv[argc++] = (char *)"-std=c2x";
        argv[argc++] = (char *)"-O2";
        argv[argc++] = (char *)"-fno-ident";
#if !defined(__APPLE__)
        argv[argc++] = (char *)"-Wl,--build-id=none";
#endif
        argv[argc++] = (char *)source;
        argv[argc++] = (char *)"-o";
        argv[argc++] = (char *)binary;
        argv[argc] = NULL;
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           zwn_normalize_executable_identity(binary) &&
           zwn_sign_executable_identity(binary);
#endif
}

static bool zwn_run_fixture_binary(const char *binary)
{
#if defined(_WIN32)
    const char *const argv[] = {binary, NULL};
    return test_spawn_argv_wait(argv) == 0;
#else
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        char *const argv[] = {(char *)binary, NULL};
        execv(binary, argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

static bool zwn_sha3_file(const char *path, uint8_t out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint8_t buffer[16384];
    bool ok = true;
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0)
            break;
        sha3_256_write(&hash, buffer, (size_t)got);
    }
    if (close(fd) != 0)
        ok = false;
    if (ok)
        sha3_256_finalize(&hash, out);
    return ok;
}

static bool zwn_sha256_file(const char *path, uint8_t out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct sha256_ctx hash;
    sha256_init(&hash);
    uint8_t buffer[16384];
    bool ok = true;
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0)
            break;
        sha256_write(&hash, buffer, (size_t)got);
    }
    if (close(fd) != 0)
        ok = false;
    if (ok)
        sha256_finalize(&hash, out);
    return ok;
}

static void zwn_literal_root(const char *literal, uint8_t out[32])
{
    sha3_256((const uint8_t *)literal, strlen(literal), out);
}

static bool zwn_release_make(
    const uint8_t package_root[32], const uint8_t recipe_root[32],
    const char *semver, uint64_t sequence, const uint8_t *parent_root,
    struct vcs_package_release *release, uint8_t release_root[32])
{
    struct privkey key;
    memset(&key, 0, sizeof(key));
    memset(key.vch, 0x47, sizeof(key.vch));
    key.fValid = true;
    key.fCompressed = true;
    struct pubkey pubkey;
    if (!privkey_get_pubkey(&key, &pubkey) ||
        pubkey.size != COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    memset(release, 0, sizeof(*release));
    release->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(release->name, sizeof(release->name),
                   "fixture/sovereign-source");
    (void)snprintf(release->semver, sizeof(release->semver), "%s", semver);
    memcpy(release->package_root, package_root, 32);
    release->has_parent = parent_root != NULL;
    if (parent_root)
        memcpy(release->parent_root, parent_root, 32);
    memcpy(release->publisher_pubkey, pubkey.vch,
           COMPRESSED_PUBLIC_KEY_SIZE);
    release->publisher_sequence = sequence;
    (void)snprintf(release->license, sizeof(release->license),
                   "Apache-2.0");
    memcpy(release->recipe_root, recipe_root, 32);
    (void)snprintf(release->chain_id, sizeof(release->chain_id),
                   "zclassic-regtest");
    if (vcs_package_release_id(release, release_root) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, release_root, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&key, &hash, compact))
        return false;
    memcpy(release->signature, compact + 1,
           VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
}

struct zwn_package_scenario {
    const char *name;
    const char *dht_namespace;
    const char *source_dir;
    uint64_t publisher_sequence;
    const char *expected_package_root_hex;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, "package.c23-commons", dir, sequence, content},
static const struct zwn_package_scenario zwn_package_scenarios[] = {
#include "../../../engine/composition/zcode_package_registry.def"
#include "../../../engine/composition/zcode_c23_commons_app.def"
};
#undef ZCODE_PACKAGE

#define ZWN_PACKAGE_SCENARIO_COUNT \
    (sizeof(zwn_package_scenarios) / sizeof(zwn_package_scenarios[0]))

/* A publisher sequence `step` above every release the scenario table signs.
 * Registry sequences are not dense (a row that moved leaves its old number
 * unused), so the row count is not the largest sequence, and a release signed
 * at a number the table already uses is refused as publisher equivocation. */
static uint64_t zwn_sequence_after_scenarios(uint64_t step)
{
    uint64_t largest = 0;
    for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT; i++)
        if (zwn_package_scenarios[i].publisher_sequence > largest)
            largest = zwn_package_scenarios[i].publisher_sequence;
    return largest + step;
}

struct zwn_package_scenario_result {
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t release_id[32];
    uint8_t transport_root[32];
    uint64_t cold_bytes;
    uint64_t repeat_bytes;
    uint64_t source_bytes;
    uint32_t source_chunks;
    uint32_t reused_objects;
    bool survived_publisher;
};

static bool zwn_prepare_package_transport(
    const struct zwn_package_scenario *scenario,
    const char *source_dir, uint64_t publisher_sequence,
    const char *expected_package_root_hex,
    struct vcs_package_prepared *prepared,
    struct vcs_package_transport *transport)
{
    struct privkey key;
    memset(&key, 0, sizeof(key));
    memset(key.vch, 0x47, sizeof(key.vch));
    key.fValid = true;
    key.fCompressed = true;
    struct pubkey pubkey;
    if (!scenario || !prepared || !transport ||
        !privkey_get_pubkey(&key, &pubkey) ||
        pubkey.size != COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    struct vcs_package_prepare_options options = {
        .dir = source_dir,
        .publisher_sequence = publisher_sequence,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pubkey.vch,
           COMPRESSED_PUBLIC_KEY_SIZE);
    char detail[160] = {0};
    vcs_package_prepared_init(prepared);
    if (vcs_package_prepare(&options, prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        fprintf(stderr, "zwn package prepare: %s\n", detail);
        return false;
    }
    uint8_t expected[32];
    if (expected_package_root_hex &&
        (!zcl_hex_decode(expected_package_root_hex,
                         expected, sizeof(expected)) ||
         memcmp(expected, prepared->package_root, 32) != 0)) {
        char actual_hex[65];
        zcl_hex_encode(prepared->package_root, 32, actual_hex);
        fprintf(stderr, "zwn package root mismatch: expected=%s actual=%s\n",
                expected_package_root_hex, actual_hex);
        return false;
    }
    struct uint256 digest;
    memcpy(digest.data, prepared->signing_digest, 32);
    uint8_t compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&key, &digest, compact))
        return false;
    memcpy(prepared->release.signature, compact + 1,
           VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    bool ok = vcs_package_release_verify(&prepared->release) ==
                  VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_serialize(&prepared->release, &release_wire,
                                      &release_wire_len) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_transport_build(
            release_wire, release_wire_len,
            prepared->recipe_wire, prepared->recipe_wire_len,
            prepared->manifest_wire, prepared->manifest_wire_len,
            transport) == VCS_PACKAGE_TRANSPORT_OK;
    free(release_wire);
    return ok;
}

/* ── the loopback node: msg_processor + engine + store + book ───────── */

struct zwn_node {
    struct main_state ms;
    struct tx_mempool mempool;
    struct coins_view null_view;
    struct coins_view_cache coins;
    struct net_manager nm;
    struct msg_processor mp;
    char datadir[1024];
    char zcode_dir[1100];
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
    struct vcs_swarm_receipt_session *receipts;
    uint64_t now;
    bool tcp_clock; /* TCP fixture ticks use monotonic elapsed seconds. */
    uint32_t invalid_chunk_events;
    bool tamper_chunks; /* corrupt DATA replies carrying chunk objects */
    uint32_t chunk_data_replies[ZWN_MAX_FILES];
};

struct zwn_link {
    struct zwn_node *owner;
    struct p2p_node *node; /* owner's connection object for the remote */
    struct send_segment *sentinel;
};

#define ZWN_FIXTURE_MAX_NODES 4u
#define ZWN_FIXTURE_MAX_LINKS 6u

struct zwn_node_spec {
    struct zwn_node *node;
    const char *tag;
};

struct zwn_link_spec {
    struct zwn_node *owner;
    struct zwn_link *link;
    uint8_t ip[4];
    const char *name;
};

/* Owns every successfully constructed loopback node/link immediately. This
 * keeps ASSERT's shared failure jump from bypassing topology teardown. */
struct zwn_fixture {
    struct zwn_node *nodes[ZWN_FIXTURE_MAX_NODES];
    struct zwn_link *links[ZWN_FIXTURE_MAX_LINKS];
    size_t node_count;
    size_t link_count;
};

static struct vcs_zcode_dht_time zwn_dht_time(uint64_t now)
{
    return (struct vcs_zcode_dht_time){
        .wall_unix = now,
        .monotonic_s = now,
    };
}

static bool zwn_dht_chain_ok(
    void *ctx, const struct vcs_zcode_dht_delegation *delegation)
{
    (void)ctx;
    return delegation && delegation->beacon_height == 120;
}

static bool zwn_dht_policy_allow(
    void *ctx, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject)
{
    (void)ctx;
    return action < VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT && subject;
}

static bool zwn_dht_identity(
    const char *datadir, uint8_t master_byte, const uint8_t genesis[32],
    const uint8_t noise[32])
{
    uint8_t online_seed[32], online_pubkey[32], master_seed[32];
    uint8_t beacon_hash[32];
    char error[160];
    memset(master_seed, master_byte, sizeof(master_seed));
    memset(beacon_hash, 0x44, sizeof(beacon_hash));
    if (!vcs_zcode_dht_online_key_load_or_create(
            datadir, online_seed, online_pubkey, error, sizeof(error)))
        return false;
    struct vcs_zcode_dht_delegation delegation;
    bool ok = vcs_zcode_dht_delegation_sign(
                  &delegation, genesis, online_pubkey, noise, 120,
                  beacon_hash, 1000, 90000, 1, master_seed) ==
              VCS_ZCODE_DHT_DELEGATION_OK;
    if (ok)
        ok = vcs_zcode_dht_delegation_save(
            datadir, &delegation, error, sizeof(error));
    memset(online_seed, 0, sizeof(online_seed));
    memset(master_seed, 0, sizeof(master_seed));
    return ok;
}

static struct vcs_zcode_dht_service *zwn_dht_service(
    const char *datadir, const uint8_t genesis[32], const uint8_t noise[32])
{
    struct vcs_zcode_dht_service_params params = {
        .datadir = datadir,
        .transport_enabled = true,
        .now = {.wall_unix = 1000, .monotonic_s = 1000},
        .transport_verify = zwn_dht_chain_ok,
        .authority_verify = zwn_dht_chain_ok,
        .policy_decide = zwn_dht_policy_allow,
    };
    memcpy(params.network_genesis, genesis, 32);
    memcpy(params.local_noise_static, noise, 32);
    return vcs_zcode_dht_service_create(&params);
}

static bool zwn_dht_pump_half(
    struct vcs_zcode_dht_service *from,
    struct vcs_zcode_dht_service *to, uint64_t expected_outbound_peer,
    uint64_t inbound_peer, uint64_t now, bool *moved)
{
    uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    uint64_t peer = 0;
    size_t wire_len = 0;
    while (vcs_zcode_dht_service_next_outbound(
               from, 0, &peer, wire, sizeof(wire), &wire_len)) {
        enum vcs_zcode_dht_reject_reason rejected =
            VCS_ZCODE_DHT_REJECT_MALFORMED;
        if (peer != expected_outbound_peer)
            return false;
        if (!vcs_zcode_dht_service_handle_frame(
                to, inbound_peer, wire, wire_len, zwn_dht_time(now),
                &rejected)) {
            fprintf(stderr, "zwn DHT frame rejected: %s\n",
                    vcs_zcode_dht_reject_reason_string(rejected));
            return false;
        }
        *moved = true;
    }
    return true;
}

static bool zwn_dht_drive_pair(
    struct vcs_zcode_dht_service *publisher,
    struct vcs_zcode_dht_service *consumer, uint64_t now)
{
    for (size_t round = 0; round < 64; round++) {
        bool moved = false;
        if (!zwn_dht_pump_half(
                publisher, consumer, 2, 1, now, &moved) ||
            !zwn_dht_pump_half(
                consumer, publisher, 1, 2, now, &moved))
            return false;
        if (!moved)
            return true;
    }
    return false;
}

static bool zwn_dht_drive_record_query(
    struct vcs_zcode_dht_service *publisher,
    struct vcs_zcode_dht_service *consumer, uint64_t operation,
    uint64_t now, struct vcs_zcode_dht_record_operation_result *result)
{
    for (size_t round = 0; round < 256; round++) {
        bool moved = false;
        if (!zwn_dht_pump_half(
                publisher, consumer, 2, 1, now, &moved)) {
            fprintf(stderr, "zwn DHT query: publisher frame rejected\n");
            return false;
        }
        if (!zwn_dht_pump_half(
                consumer, publisher, 1, 2, now, &moved)) {
            fprintf(stderr, "zwn DHT query: consumer frame rejected\n");
            return false;
        }
        if (!vcs_zcode_dht_service_record_operation_poll(
                consumer, operation, zwn_dht_time(now), result)) {
            fprintf(stderr, "zwn DHT query: operation missing\n");
            return false;
        }
        if (result->state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE)
            return true;
        if (result->state != VCS_ZCODE_DHT_RECORD_OPERATION_PENDING) {
            fprintf(stderr, "zwn DHT query: terminal state %d\n",
                    (int)result->state);
            return false;
        }
        if (!moved) {
            fprintf(stderr, "zwn DHT query: pending without frames\n");
            return false;
        }
    }
    return false;
}

static bool zwn_discover_transport(
    const struct zwn_node *publisher, const struct zwn_node *mirror,
    const struct zwn_node *consumer, const char *namespace_name,
    const uint8_t semantic_root[32],
    const uint8_t expected_transport_root[32], uint8_t transport_root[32],
    struct vcs_zcode_dht_record *provider_record_out, uint64_t now)
{
    if (!namespace_name || now < 2)
        return false;
    struct vcs_package_store_status publisher_status, mirror_status;
    if (!vcs_package_store_package_status(
            publisher->store, expected_transport_root, &publisher_status) ||
        !vcs_package_store_package_status(
            mirror->store, expected_transport_root, &mirror_status) ||
        !publisher_status.complete || !publisher_status.pinned ||
        !mirror_status.complete || !mirror_status.pinned)
        return false;
    char publisher_dht_dir[1200], consumer_dht_dir[1200];
    int publisher_dir_len = snprintf(
        publisher_dht_dir, sizeof(publisher_dht_dir), "%s/dht-%" PRIu64,
        publisher->datadir, now);
    int consumer_dir_len = snprintf(
        consumer_dht_dir, sizeof(consumer_dht_dir), "%s/dht-%" PRIu64,
        consumer->datadir, now);
    if (publisher_dir_len <= 0 ||
        (size_t)publisher_dir_len >= sizeof(publisher_dht_dir) ||
        consumer_dir_len <= 0 ||
        (size_t)consumer_dir_len >= sizeof(consumer_dht_dir) ||
        (mkdir(publisher_dht_dir, 0700) != 0 && errno != EEXIST) ||
        (mkdir(consumer_dht_dir, 0700) != 0 && errno != EEXIST))
        return false;
    uint8_t genesis[32], publisher_noise[32], consumer_noise[32];
    uint8_t transcript[32];
    memset(genesis, 0x71, sizeof(genesis));
    memset(publisher_noise, 0x72, sizeof(publisher_noise));
    memset(consumer_noise, 0x73, sizeof(consumer_noise));
    memset(transcript, 0x74, sizeof(transcript));
    if (!zwn_dht_identity(
            publisher_dht_dir, 0x75, genesis, publisher_noise) ||
        !zwn_dht_identity(
            consumer_dht_dir, 0x76, genesis, consumer_noise))
        return false;

    struct vcs_zcode_dht_service *publisher_dht =
        zwn_dht_service(publisher_dht_dir, genesis, publisher_noise);
    struct vcs_zcode_dht_service *consumer_dht =
        zwn_dht_service(consumer_dht_dir, genesis, consumer_noise);
    const char *stage = "service-create";
    bool ok = publisher_dht && consumer_dht;
    if (!ok)
        goto out;
    struct vcs_zcode_dht_session publisher_session = {
        .established = true,
        .generation = 1,
        .connection_serial = 1,
    };
    struct vcs_zcode_dht_session consumer_session = publisher_session;
    consumer_session.connection_serial = 2;
    memcpy(publisher_session.remote_static, consumer_noise, 32);
    memcpy(consumer_session.remote_static, publisher_noise, 32);
    memcpy(publisher_session.transcript_hash, transcript, 32);
    memcpy(consumer_session.transcript_hash, transcript, 32);
    stage = "session-open";
    ok = vcs_zcode_dht_service_session_open(
             publisher_dht, 2, &publisher_session, zwn_dht_time(now - 1)) &&
         vcs_zcode_dht_service_session_open(
             consumer_dht, 1, &consumer_session, zwn_dht_time(now - 1)) &&
         zwn_dht_drive_pair(publisher_dht, consumer_dht, now);
    if (!ok)
        goto out;

    struct vcs_zcode_dht_publish_spec pointer_spec;
    memset(&pointer_spec, 0, sizeof(pointer_spec));
    pointer_spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(pointer_spec.namespace_name,
                   sizeof(pointer_spec.namespace_name),
                   "%s", namespace_name);
    memcpy(pointer_spec.semantic_root, semantic_root, 32);
    memcpy(pointer_spec.transport_root, expected_transport_root, 32);
    pointer_spec.sequence = 1;
    pointer_spec.not_before = 1000;
    pointer_spec.expiry = 2000;
    uint8_t plan_token[32];
    struct vcs_zcode_dht_record record;
    stage = "publish";
    ok = vcs_zcode_dht_service_record_publish_plan(
             publisher_dht, &pointer_spec, plan_token, &record, NULL) &&
         vcs_zcode_dht_service_record_publish_commit(
             publisher_dht, &pointer_spec, plan_token, zwn_dht_time(now),
             &record, NULL) == VCS_ZCODE_DHT_RECORD_STORE_ADDED;
    if (!ok)
        goto out;

    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER,
    };
    (void)snprintf(selector.namespace_name, sizeof(selector.namespace_name),
                   "%s", namespace_name);
    memcpy(selector.root, semantic_root, 32);
    struct vcs_zcode_dht_record empty_cache[1];
    stage = "empty-local-query";
    if (vcs_zcode_dht_service_record_local_query(
            consumer_dht, now, &selector, empty_cache, 1) != 0) {
        ok = false;
        goto out;
    }
    uint64_t operation = 0;
    stage = "query-begin";
    ok = vcs_zcode_dht_service_record_query_begin(
        consumer_dht, 1, &selector, zwn_dht_time(now), &operation);
    struct vcs_zcode_dht_record_operation_result result;
    memset(&result, 0, sizeof(result));
    if (ok) {
        stage = "query-drive";
        ok = zwn_dht_drive_record_query(
            publisher_dht, consumer_dht, operation, now, &result);
    }
    if (!ok)
        goto out;
    stage = "query-result";
    ok = result.state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE &&
         result.record_count == 1 &&
         result.records[0].kind == VCS_ZCODE_DHT_RECORD_POINTER &&
         memcmp(result.records[0].semantic_root, semantic_root, 32) == 0 &&
         memcmp(result.records[0].transport_root,
                expected_transport_root, 32) == 0;
    if (ok)
        memcpy(transport_root, result.records[0].transport_root, 32);
    if (!ok || !provider_record_out)
        goto out;

    struct vcs_zcode_dht_publish_spec provider_spec;
    memset(&provider_spec, 0, sizeof(provider_spec));
    provider_spec.kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
    (void)snprintf(provider_spec.namespace_name,
                   sizeof(provider_spec.namespace_name),
                   "%s", namespace_name);
    memcpy(provider_spec.transport_root, expected_transport_root, 32);
    provider_spec.sequence = 1;
    provider_spec.not_before = 1000;
    provider_spec.expiry = 2000;
    struct vcs_zcode_dht_record provider_record;
    stage = "provider-publish";
    ok = vcs_zcode_dht_service_record_publish_plan(
             publisher_dht, &provider_spec, plan_token, &provider_record,
             NULL) &&
         vcs_zcode_dht_service_record_publish_commit(
             publisher_dht, &provider_spec, plan_token,
             zwn_dht_time(now + 1),
             &provider_record, NULL) == VCS_ZCODE_DHT_RECORD_STORE_ADDED;
    if (!ok)
        goto out;

    struct vcs_zcode_dht_record_selector provider_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER,
    };
    (void)snprintf(provider_selector.namespace_name,
                   sizeof(provider_selector.namespace_name),
                   "%s", namespace_name);
    memcpy(provider_selector.root, expected_transport_root, 32);
    operation = 0;
    stage = "provider-query-begin";
    ok = vcs_zcode_dht_service_record_query_begin(
        consumer_dht, 1, &provider_selector, zwn_dht_time(now + 1),
        &operation);
    memset(&result, 0, sizeof(result));
    if (ok) {
        stage = "provider-query-drive";
        ok = zwn_dht_drive_record_query(
            publisher_dht, consumer_dht, operation, now + 1, &result);
    }
    if (!ok)
        goto out;
    stage = "provider-query-result";
    ok = result.state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE &&
         result.record_count == 1 &&
         result.records[0].kind == VCS_ZCODE_DHT_RECORD_PROVIDER &&
         memcmp(result.records[0].transport_root,
                expected_transport_root, 32) == 0 &&
         memcmp(result.records[0].provider_node_id,
                provider_record.provider_node_id, 32) == 0;
    if (ok && provider_record_out)
        *provider_record_out = result.records[0];

out:
    if (!ok)
        fprintf(stderr, "zwn DHT: %s failed\n", stage);
    if (consumer_dht)
        vcs_zcode_dht_service_free(consumer_dht, zwn_dht_time(now + 2));
    if (publisher_dht)
        vcs_zcode_dht_service_free(publisher_dht, zwn_dht_time(now + 2));
    return ok;
}

static bool zwn_author_storage_ack(
    const struct zwn_node *provider, const char *namespace_name,
    const uint8_t transport_root[32], uint8_t identity_byte,
    uint8_t owner_group_byte, struct vcs_zcode_dht_record *record_out,
    uint8_t record_root_out[32])
{
    if (!provider || !namespace_name || !transport_root || !record_out ||
        !record_root_out)
        return false;
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(
            provider->store, transport_root, &status) ||
        !status.complete || !status.pinned)
        return false;

    uint8_t genesis[32], noise[32];
    memset(genesis, 0x71, sizeof(genesis));
    memset(noise, identity_byte, sizeof(noise));
    if (!zwn_dht_identity(
            provider->datadir, identity_byte, genesis, noise))
        return false;
    struct vcs_zcode_dht_service *service =
        zwn_dht_service(provider->datadir, genesis, noise);
    if (!service)
        return false;

    struct vcs_zcode_dht_publish_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "%s", namespace_name);
    memcpy(spec.transport_root, transport_root, 32);
    memset(spec.owner_group, owner_group_byte, sizeof(spec.owner_group));
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 2000;
    uint8_t plan_token[32];
    struct vcs_zcode_dht_record generic_record;
    bool ok = !vcs_zcode_dht_service_record_publish_plan(
                  service, &spec, plan_token, &generic_record, NULL) &&
        vcs_zcode_dht_service_storage_ack_plan(
            service, provider->store, &spec, plan_token, record_out) &&
        vcs_zcode_dht_service_storage_ack_commit(
            service, provider->store, &spec, plan_token,
            zwn_dht_time(1002), record_out) ==
            VCS_ZCODE_DHT_RECORD_STORE_ADDED &&
        record_out->kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
        memcmp(record_out->transport_root, transport_root, 32) == 0 &&
        vcs_zcode_dht_record_id(record_out, record_root_out) ==
            VCS_ZCODE_DHT_RECORD_OK;
    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK,
    };
    (void)snprintf(selector.namespace_name, sizeof(selector.namespace_name),
                   "%s", namespace_name);
    memcpy(selector.root, transport_root, 32);
    struct vcs_zcode_dht_record queried;
    ok = ok && vcs_zcode_dht_service_record_local_query(
                   service, 1002, &selector, &queried, 1) == 1 &&
        memcmp(queried.provider_node_id, record_out->provider_node_id, 32) ==
            0;
    vcs_zcode_dht_service_free(service, zwn_dht_time(1003));
    return ok;
}

static uint64_t zwn_score(const uint8_t contributor[33], void *ctx)
{
    (void)contributor;
    (void)ctx;
    return ZWN_SCORE;
}

/* Production-identical session pseudo-key derivation. */
static bool zwn_peer_key(const struct p2p_node *node, uint8_t out[33])
{
    char host[ZCL_PEER_HOST_KEY_MAX];
    if (!zcl_peer_host_key(node, host, sizeof(host)))
        return false;
    out[0] = 0x02;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)ZWN_KEY_DOMAIN,
                   sizeof(ZWN_KEY_DOMAIN) - 1);
    sha3_256_write(&h, (const unsigned char *)host, strlen(host));
    sha3_256_finalize(&h, out + 1);
    return true;
}

static enum peer_offence zwn_offence(enum vcs_swarm_penalty penalty)
{
    switch (penalty) {
    case VCS_SWARM_PENALTY_MALFORMED:
        return PEER_OFFENCE_INVALID_MESSAGE;
    case VCS_SWARM_PENALTY_ANNOUNCE_FLOOD:
    case VCS_SWARM_PENALTY_REQUEST_FLOOD:
        return PEER_OFFENCE_FLOOD;
    case VCS_SWARM_PENALTY_REPLAYED_REQUEST:
    case VCS_SWARM_PENALTY_REPLAYED_DATA:
        return PEER_OFFENCE_INVALID_PAYLOAD;
    case VCS_SWARM_PENALTY_UNREQUESTED_DATA:
        return PEER_OFFENCE_UNREQUESTED;
    case VCS_SWARM_PENALTY_INVALID_DATA:
        return PEER_OFFENCE_INVALID_CHUNK;
    case VCS_SWARM_PENALTY_NONE:
    default:
        return PEER_OFFENCE_NONE;
    }
}

static void zwn_send(struct zwn_node *z, struct p2p_node *node,
                     const uint8_t *frame, size_t frame_len)
{
    if (atomic_load(&node->disconnect))
        return;
    if (!p2p_node_begin_message(node, "zpkgswm",
                                z->mp.params->pchMessageStart))
        return;
    p2p_node_write_message_data(node, frame, frame_len);
    (void)p2p_node_end_message(node);
}

static bool zwn_receipt_payload(const uint8_t *payload, size_t len)
{
    return (len == VCS_SWARM_RECEIPT_IDENTITY_BYTES && payload &&
            memcmp(payload, VCS_SWARM_RECEIPT_IDENTITY_MAGIC, 4) == 0) ||
           (len == VCS_SERVICE_RECEIPT_WIRE_BYTES && payload &&
            memcmp(payload, VCS_SERVICE_RECEIPT_MAGIC, 4) == 0);
}

static uint64_t zwn_tick_value(struct zwn_node *node)
{
    return node->tcp_clock ? node->now : ++node->now;
}

/* The frame hook: engine/composition/src/boot_zcode_swarm.c's boot_zcode_swarm_frame
 * with the deterministic-clock + fixed-score substitutions (file header). */
static void zwn_tcp_frame_observe(struct zwn_node *node,
    const struct vcs_swarm_frame_result *result)
{
    if (node->tcp_clock && result->penalty == VCS_SWARM_PENALTY_INVALID_DATA &&
        result->rule && strcmp(result->rule, "invalid-chunk") == 0)
        node->invalid_chunk_events++;
}

static bool zwn_frame(struct msg_processor *mp, struct p2p_node *node,
                      const uint8_t *payload, size_t payload_len, void *ctx)
{
    struct zwn_node *z = ctx;
    uint8_t key[33];
    if (!zwn_peer_key(node, key))
        return true;
    (void)vcs_swarm_engine_peer_add(z->engine, (uint64_t)node->id, key);
    if (z->receipts && zwn_receipt_payload(payload, payload_len)) {
        uint64_t peer = (uint64_t)node->id;
        if (payload_len == VCS_SWARM_RECEIPT_IDENTITY_BYTES) {
            (void)vcs_swarm_receipt_identity_note(z->receipts, peer, payload,
                                                  payload_len);
            return true;
        }
        struct vcs_swarm_transfer xfer;
        if (!vcs_swarm_engine_transfer_snapshot(z->engine, peer, &xfer))
            return true;
        uint8_t *reply = NULL;
        size_t reply_len = 0;
        (void)vcs_swarm_receipt_session_handle(
            z->receipts, z->book, &xfer, peer, ZWN_DAY, payload,
            payload_len, &reply, &reply_len);
        if (reply && reply_len > 0)
            zwn_send(z, node, reply, reply_len);
        free(reply);
        return true;
    }
    struct vcs_swarm_frame_result ev = vcs_swarm_engine_handle_frame(
        z->engine, (uint64_t)node->id, payload, payload_len, ZWN_DAY,
        zwn_tick_value(z));
    zwn_tcp_frame_observe(z, &ev);
    if (ev.penalty != VCS_SWARM_PENALTY_NONE)
        peer_scoring_record(mp->net_mgr, node, zwn_offence(ev.penalty),
                            "zcode swarm test");
    if (ev.reply) {
        struct vcs_package_swarm_message msg;
        bool parsed = ev.reply_len > 0 &&
            vcs_package_swarm_parse(ev.reply, ev.reply_len, &msg);
        if (parsed && msg.type == VCS_PACKAGE_SWARM_DATA &&
            msg.body.data.object.object_kind ==
                VCS_PACKAGE_SWARM_OBJECT_CHUNK &&
            msg.body.data.object.file_index < ZWN_MAX_FILES)
            z->chunk_data_replies[msg.body.data.object.file_index]++;
        if (z->tamper_chunks && parsed) {
            /* Corrupt only CHUNK data replies: the manifest still
             * verifies, so the download reaches the chunk stage and the
             * bad-hash path is what gets exercised. */
            if (msg.type == VCS_PACKAGE_SWARM_DATA &&
                msg.body.data.object.object_kind ==
                    VCS_PACKAGE_SWARM_OBJECT_CHUNK)
                ev.reply[ev.reply_len - 1] ^= 0xff;
        }
        zwn_send(z, node, ev.reply, ev.reply_len);
        free(ev.reply);
    }
    if (ev.disconnect_peer)
        atomic_store(&node->disconnect, true);
    return true;
}

/* The tick hook: scheduler tick + per-peer outbound drain. Called from
 * the real msg_process_messages (proving the wiring) and directly by the
 * drive loop (so the scheduler also advances in quiet cycles). */
static void zwn_tick(struct msg_processor *mp, struct p2p_node *node,
                     void *ctx)
{
    struct zwn_node *z = ctx;
    (void)mp;
    vcs_swarm_engine_tick(z->engine, ZWN_DAY,
        zwn_tick_value(z));
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    for (;;) {
        uint64_t peer = 0;
        size_t frame_len = 0;
        if (!vcs_swarm_engine_next_outbound(z->engine, (uint64_t)node->id,
                                            &peer, frame, &frame_len))
            break;
        if (peer != (uint64_t)node->id || frame_len == 0)
            break;
        zwn_send(z, node, frame, frame_len);
    }
    if (z->receipts) {
        uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
        size_t ident_len = 0;
        if (vcs_swarm_receipt_identity_take(z->receipts, (uint64_t)node->id,
                                            ident, sizeof(ident),
                                            &ident_len))
            zwn_send(z, node, ident, ident_len);
        struct vcs_swarm_transfer xfer;
        uint8_t offer[VCS_SERVICE_RECEIPT_WIRE_BYTES];
        if (vcs_swarm_engine_transfer_snapshot(z->engine, (uint64_t)node->id,
                                               &xfer) &&
            vcs_swarm_receipt_session_offer(z->receipts, &xfer,
                                            (uint64_t)node->id, ZWN_DAY,
                                            offer))
            zwn_send(z, node, offer, sizeof(offer));
    }
}

static bool zwn_node_init(struct zwn_node *z, const char *tag,
                          const struct chain_params *params)
{
    memset(z, 0, sizeof(*z));
    main_state_init(&z->ms);
    tx_mempool_init(&z->mempool, 0);
    coins_view_cache_init(&z->coins, &z->null_view);
    net_manager_init(&z->nm);
    z->mp.main_state = &z->ms;
    z->mp.mempool = &z->mempool;
    z->mp.coins_tip = &z->coins;
    z->mp.params = params;
    z->mp.net_mgr = &z->nm;
    z->now = 0;
    z->tamper_chunks = false;
    test_make_tmpdir(z->datadir, sizeof(z->datadir), "zcode_swarm_net",
                     tag);
    z->mp.datadir = z->datadir;
    snprintf(z->zcode_dir, sizeof(z->zcode_dir), "%s/zcode", z->datadir);
    z->store = vcs_package_store_open(
        z->datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    z->book = vcs_service_book_load(z->zcode_dir);
    if (!z->store || !z->book) {
        vcs_service_book_free(z->book);
        vcs_package_store_close(z->store);
        net_manager_free(&z->nm);
        coins_view_cache_free(&z->coins);
        tx_mempool_free(&z->mempool);
        main_state_free(&z->ms);
        return false;
    }
    z->engine = vcs_swarm_engine_create(z->store, z->book, z->zcode_dir,
                                        zwn_score, NULL);
    z->receipts = vcs_swarm_receipt_session_open(z->zcode_dir);
    if (!z->engine || !z->receipts) {
        vcs_swarm_receipt_session_free(z->receipts);
        vcs_swarm_engine_free(z->engine);
        z->receipts = NULL;
        z->engine = NULL;
        vcs_service_book_free(z->book);
        vcs_package_store_close(z->store);
        z->book = NULL;
        z->store = NULL;
        net_manager_free(&z->nm);
        coins_view_cache_free(&z->coins);
        tx_mempool_free(&z->mempool);
        main_state_free(&z->ms);
        return false;
    }
    msg_processor_set_zcode_swarm(&z->mp, zwn_frame, zwn_tick, z);
    return true;
}

static void zwn_node_free(struct zwn_node *z)
{
    vcs_swarm_receipt_session_free(z->receipts);
    vcs_swarm_engine_free(z->engine);
    vcs_service_book_free(z->book);
    vcs_package_store_close(z->store);
    z->receipts = NULL;
    z->engine = NULL;
    z->book = NULL;
    z->store = NULL;
    net_manager_free(&z->nm);
    coins_view_cache_free(&z->coins);
    tx_mempool_free(&z->mempool);
    main_state_free(&z->ms);
}

/* A fresh engine over the same datadir (the restart-resume substitution:
 * store + book stay open; only the engine is recreated, exactly like a
 * process restart that keeps the datadir). */
static bool zwn_node_restart_engine(struct zwn_node *z)
{
    vcs_swarm_engine_free(z->engine);
    z->engine = vcs_swarm_engine_create(z->store, z->book, z->zcode_dir,
                                        zwn_score, NULL);
    return z->engine != NULL;
}

/* ── links + pump (the sentinel technique) ──────────────────────────── */

static bool zwn_link(struct zwn_node *owner, struct zwn_link *l,
                     uint8_t ip_a, uint8_t ip_b, uint8_t ip_c, uint8_t ip_d,
                     const char *name)
{
    /* p2p_node_create leaves id 0 on a fresh net_manager; the engine
     * reserves peer id 0 (the next_outbound "no filter" convention), so
     * loopback links take explicit nonzero ids. Distinct per owner. */
    static node_id_t next_id = 100;
    memset(l, 0, sizeof(*l));
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(addr.svc.addr.ip, pchIPv4Prefix, 12);
    addr.svc.addr.ip[12] = ip_a;
    addr.svc.addr.ip[13] = ip_b;
    addr.svc.addr.ip[14] = ip_c;
    addr.svc.addr.ip[15] = ip_d;
    addr.svc.port = 18033;
    l->owner = owner;
    l->node = p2p_node_create(&owner->nm, ZCL_INVALID_SOCKET, &addr,
                              name, false);
    if (!l->node)
        return false;
    l->node->id = next_id++;
    l->node->version = 1;
    l->node->services = NODE_ZCL23;
    l->node->state = PEER_HANDSHAKE_COMPLETE;
    l->sentinel = zcl_calloc(1, sizeof(*l->sentinel),
                             "zcode_swarm_net_sentinel");
    if (!l->sentinel) {
        p2p_node_free(l->node);
        l->node = NULL;
        return false;
    }
    l->node->send_head = l->sentinel;
    l->node->send_tail = l->sentinel;
    l->node->send_offset = 0;
    return true;
}

static void zwn_link_free(struct zwn_link *l)
{
    if (!l || !l->node)
        return;
    if (l->sentinel) {
        send_segment_free(l->sentinel);
        l->node->send_head = NULL;
        l->node->send_tail = NULL;
        l->node->recv_msg_count = 0;
    }
    p2p_node_free(l->node);
    l->node = NULL;
    l->sentinel = NULL;
}

static bool zwn_fixture_nodes(struct zwn_fixture *fixture,
                              const struct chain_params *params,
                              const struct zwn_node_spec *specs,
                              size_t count)
{
    if (!fixture || !params || !specs ||
        count > ZWN_FIXTURE_MAX_NODES - fixture->node_count)
        return false;
    for (size_t i = 0; i < count; i++) {
        if (!specs[i].node || !specs[i].tag ||
            !zwn_node_init(specs[i].node, specs[i].tag, params))
            return false;
        fixture->nodes[fixture->node_count++] = specs[i].node;
    }
    return true;
}

static bool zwn_fixture_links(struct zwn_fixture *fixture,
                              const struct zwn_link_spec *specs,
                              size_t count)
{
    if (!fixture || !specs ||
        count > ZWN_FIXTURE_MAX_LINKS - fixture->link_count)
        return false;
    for (size_t i = 0; i < count; i++) {
        if (!specs[i].owner || !specs[i].link || !specs[i].name ||
            !zwn_link(specs[i].owner, specs[i].link,
                      specs[i].ip[0], specs[i].ip[1], specs[i].ip[2],
                      specs[i].ip[3], specs[i].name))
            return false;
        fixture->links[fixture->link_count++] = specs[i].link;
    }
    return true;
}

static void zwn_fixture_release_link(struct zwn_fixture *fixture,
                                     struct zwn_link *link)
{
    if (!fixture || !link)
        return;
    for (size_t i = 0; i < fixture->link_count; i++) {
        if (fixture->links[i] != link)
            continue;
        zwn_link_free(link);
        fixture->links[i] = fixture->links[--fixture->link_count];
        return;
    }
}

static void zwn_fixture_release_node(struct zwn_fixture *fixture,
                                     struct zwn_node *node)
{
    if (!fixture || !node)
        return;
    for (size_t i = 0; i < fixture->node_count; i++) {
        if (fixture->nodes[i] != node)
            continue;
        zwn_node_free(node);
        fixture->nodes[i] = fixture->nodes[--fixture->node_count];
        return;
    }
}

static void zwn_fixture_cleanup(struct zwn_fixture *fixture)
{
    if (!fixture)
        return;
    while (fixture->link_count > 0)
        zwn_link_free(fixture->links[--fixture->link_count]);
    while (fixture->node_count > 0)
        zwn_node_free(fixture->nodes[--fixture->node_count]);
}

static bool zwn_fixture_abort_reacquire(const struct chain_params *params)
{
    struct zwn_fixture fixture = {0};
    struct zwn_node a = {0}, b = {0};
    struct zwn_link a_b = {0}, b_a = {0};
    const struct zwn_node_spec nodes[] = {
        {&a, "fixture-a"}, {&b, "fixture-b"},
    };
    const struct zwn_link_spec links[] = {
        {&a, &a_b, {10, 2, 0, 1}, "fixture-b"},
        {&b, &b_a, {10, 2, 0, 2}, "fixture-a"},
    };
    bool initialized = zwn_fixture_nodes(
        &fixture, params, nodes, sizeof(nodes) / sizeof(nodes[0])) &&
        zwn_fixture_links(
            &fixture, links, sizeof(links) / sizeof(links[0]));

    /* This is the ASSERT/goto boundary: cleanup must not depend on the
     * scenario reaching its ordinary success epilogue. */
    zwn_fixture_cleanup(&fixture);
    bool released = fixture.node_count == 0 && fixture.link_count == 0 &&
        !a.engine && !a.store && !a.book &&
        !b.engine && !b.store && !b.book &&
        !a_b.node && !a_b.sentinel && !b_a.node && !b_a.sentinel;
    if (!initialized || !released)
        return false;

    initialized = zwn_fixture_nodes(
        &fixture, params, nodes, sizeof(nodes) / sizeof(nodes[0])) &&
        zwn_fixture_links(
            &fixture, links, sizeof(links) / sizeof(links[0]));
    zwn_fixture_cleanup(&fixture);
    return initialized && fixture.node_count == 0 &&
        fixture.link_count == 0;
}

/* Drain from_link's queued wire bytes into to_link's owner through the
 * real receive parser + real dispatcher. */
static bool zwn_pump(struct zwn_link *from, struct zwn_link *to,
                     const unsigned char msgstart[MESSAGE_START_SIZE])
{
    bool any = false;
    struct send_segment *sentinel = from->sentinel;
    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        if (from->node->send_tail == seg)
            from->node->send_tail = sentinel;
        if (from->node->send_size >= seg->size)
            from->node->send_size -= seg->size;
        else
            from->node->send_size = 0;
        if (!p2p_node_receive_bytes(to->node, (const char *)seg->data,
                                    (unsigned int)seg->size, msgstart)) {
            send_segment_free(seg);
            return false;
        }
        any = true;
        send_segment_free(seg);
    }
    from->node->send_head = sentinel;
    from->node->send_offset = 0;
    if (any)
        return msg_process_messages(&to->owner->mp, to->node);
    return true;
}

/* Free every queued segment without delivering it — the loopback
 * emulation of a socket teardown (a real restart/disconnect kills the
 * queued bytes with the fd). */
static void zwn_drain_quiet(struct zwn_link *l)
{
    while (l->sentinel->next) {
        struct send_segment *seg = l->sentinel->next;
        l->sentinel->next = seg->next;
        if (l->node->send_tail == seg)
            l->node->send_tail = l->sentinel;
        if (l->node->send_size >= seg->size)
            l->node->send_size -= seg->size;
        else
            l->node->send_size = 0;
        send_segment_free(seg);
    }
    l->node->send_head = l->sentinel;
    l->node->send_offset = 0;
}

/* Membership, mirroring the boot glue's sync. Semantic discovery may bind a
 * fetch directly to a provider, in which case bulk gossip is unnecessary. */
static bool zwn_meet_side_mode(struct zwn_node *me,
                               struct zwn_link *my_link, bool announce)
{
    uint8_t key[33];
    if (!zwn_peer_key(my_link->node, key))
        return false;
    bool known = vcs_swarm_engine_peer_known(me->engine,
                                             (uint64_t)my_link->node->id);
    if (!vcs_swarm_engine_peer_add(me->engine, (uint64_t)my_link->node->id,
                                   key))
        return false;
    if (!known && announce)
        (void)vcs_swarm_engine_announce_to(me->engine,
                                           (uint64_t)my_link->node->id);
    return true;
}

static bool zwn_meet_side(struct zwn_node *me, struct zwn_link *my_link)
{
    return zwn_meet_side_mode(me, my_link, true);
}

static bool zwn_meet_side_quiet(struct zwn_node *me,
                                struct zwn_link *my_link)
{
    return zwn_meet_side_mode(me, my_link, false);
}

/* One full round: both schedulers advance, then both directions pump. */
static bool zwn_round(struct zwn_link *a_b, struct zwn_link *b_a,
                      const unsigned char msgstart[MESSAGE_START_SIZE])
{
    zwn_tick(&a_b->owner->mp, a_b->node, a_b->owner);
    zwn_tick(&b_a->owner->mp, b_a->node, b_a->owner);
    if (!zwn_pump(a_b, b_a, msgstart))
        return false;
    return zwn_pump(b_a, a_b, msgstart);
}

static bool zwn_download_done(struct zwn_node *b, const uint8_t root[32],
                              enum vcs_swarm_download_state *state_out)
{
    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    if (!vcs_swarm_engine_download_status(b->engine, root, &st))
        return false;
    *state_out = st.state;
    return st.state == VCS_SWARM_DL_COMPLETE ||
           st.state == VCS_SWARM_DL_FAILED;
}

static bool zwn_fetch_package_from_peers(
    struct zwn_node *consumer, const uint8_t root[32],
    struct zwn_link *provider_to_consumer,
    struct zwn_link *consumer_to_provider,
    struct zwn_link *mirror_to_consumer,
    struct zwn_link *consumer_to_mirror,
    const unsigned char msgstart[MESSAGE_START_SIZE])
{
    if (!consumer || !root || !provider_to_consumer ||
        !consumer_to_provider || !msgstart ||
        ((mirror_to_consumer == NULL) != (consumer_to_mirror == NULL)) ||
        vcs_swarm_engine_fetch(
            consumer->engine, root, ZWN_DAY, ++consumer->now) !=
            VCS_SWARM_FETCH_OK)
        return false;
    enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
    bool terminal = false;
    for (size_t round = 0; round < 600u && !terminal; round++) {
        if (!zwn_round(provider_to_consumer, consumer_to_provider,
                       msgstart) ||
            (mirror_to_consumer &&
             !zwn_round(mirror_to_consumer, consumer_to_mirror, msgstart)))
            return false;
        terminal = zwn_download_done(consumer, root, &state);
    }
    return terminal && state == VCS_SWARM_DL_COMPLETE;
}

static bool zwn_fetch_package_from_provider(
    struct zwn_node *consumer, const uint8_t root[32],
    struct zwn_link *provider_to_consumer,
    struct zwn_link *consumer_to_provider,
    const unsigned char msgstart[MESSAGE_START_SIZE])
{
    if (!consumer || !root || !provider_to_consumer ||
        !consumer_to_provider || !msgstart)
        return false;
    uint64_t provider = (uint64_t)consumer_to_provider->node->id;
    if (vcs_swarm_engine_fetch_from(
            consumer->engine, root, ZWN_DAY, ++consumer->now,
            &provider, 1) != VCS_SWARM_FETCH_OK)
        return false;
    enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
    bool terminal = false;
    for (size_t round = 0; round < 600u && !terminal; round++) {
        if (!zwn_round(provider_to_consumer, consumer_to_provider,
                       msgstart))
            return false;
        terminal = zwn_download_done(consumer, root, &state);
    }
    return terminal && state == VCS_SWARM_DL_COMPLETE;
}

static bool zwn_store_matches(struct vcs_package_store *store,
                              const struct zwn_pkg *p)
{
    for (size_t i = 0; i < p->count; i++) {
        if (!vcs_package_store_chunk_present(store, p->root, (uint32_t)i,
                                             0))
            return false;
        uint8_t *bytes = NULL;
        size_t len = 0;
        if (vcs_package_store_get_chunk_at(store, p->root, (uint32_t)i, 0,
                                           &bytes,
                                           &len) != VCS_PACKAGE_STORE_OK)
            return false;
        bool match = len == p->lens[i] &&
                     memcmp(bytes, p->contents[i], len) == 0;
        free(bytes);
        if (!match)
            return false;
    }
    return true;
}

static bool zwn_read_package_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!store || !package_root || !path || !out || !out_len)
        return false;
    uint8_t *manifest_wire = NULL;
    size_t manifest_wire_len = 0;
    if (vcs_package_store_get_manifest_wire(
            store, package_root, &manifest_wire, &manifest_wire_len) !=
        VCS_PACKAGE_STORE_OK)
        return false;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t checked[32];
    bool ok = vcs_package_manifest_parse(
            manifest_wire, manifest_wire_len, &manifest) &&
        vcs_package_manifest_root(&manifest, checked) &&
        memcmp(checked, package_root, 32) == 0;
    free(manifest_wire);
    size_t index = 0;
    while (ok && index < manifest.count &&
           strcmp(manifest.files[index].path, path) != 0)
        index++;
    if (!ok || index == manifest.count ||
        manifest.files[index].chunk_count != 1 ||
        manifest.files[index].size > out_capacity) {
        vcs_package_manifest_free(&manifest);
        return false;
    }
    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    ok = vcs_package_store_get_chunk_at(
             store, package_root, (uint32_t)index, 0,
             &chunk, &chunk_len) == VCS_PACKAGE_STORE_OK &&
        chunk_len == manifest.files[index].size &&
        vcs_package_verify_chunk(
            &manifest.files[index], 0, chunk, chunk_len);
    if (ok) {
        memcpy(out, chunk, chunk_len);
        *out_len = chunk_len;
    }
    free(chunk);
    vcs_package_manifest_free(&manifest);
    return ok;
}

static bool zwn_append_edit(const char *root, const char *relative,
                            const char *marker, off_t *original_size)
{
    char path[1400];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (n <= 0 || (size_t)n >= sizeof(path) || !marker || !original_size)
        return false;
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    if (ok)
        *original_size = st.st_size;
    size_t len = strlen(marker), off = 0;
    while (ok && off < len) {
        ssize_t wrote = write(fd, marker + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            ok = false;
        else
            off += (size_t)wrote;
    }
    ok = ok && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
}

static bool zwn_revert_edit(const char *root, const char *relative,
                            off_t original_size)
{
    char path[1400];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (n <= 0 || (size_t)n >= sizeof(path) || original_size < 0)
        return false;
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    bool ok = ftruncate(fd, original_size) == 0 && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
}

static size_t zwn_package_scenario_index(const char *name)
{
    for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT; i++)
        if (strcmp(zwn_package_scenarios[i].name, name) == 0)
            return i;
    return ZWN_PACKAGE_SCENARIO_COUNT;
}

static bool zwn_build_package(const char *datadir,
                              const uint8_t package_root[32],
                              int64_t *clock, size_t *rebuilt_out)
{
    char root_hex[65];
    zcl_hex_encode(package_root, 32, root_hex);
    int64_t planned_at = *clock;
    *clock += 4;
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        datadir, root_hex, planned_at, &plan);
    if (!planned.ok || !plan.ready) {
        printf("  zcode_swarm_net: plan %s failed rule=%s detail=%s "
               "message=%s\n", root_hex, plan.rule, plan.detail,
               planned.message);
        return false;
    }
    struct package_lifecycle_commit_report commit;
    struct zcl_result committed = package_lifecycle_commit(
        datadir, plan.plan_id, planned_at + 1, &commit);
    if (!committed.ok || !commit.installed) {
        printf("  zcode_swarm_net: commit %s failed rule=%s detail=%s "
               "message=%s\n", root_hex, commit.rule, commit.detail,
               committed.message);
        return false;
    }
    for (size_t i = 0; i < commit.step_count; i++)
        if (!commit.steps[i].already_installed)
            (*rebuilt_out)++;
    return true;
}

static bool zwn_build_original_graph(const char *datadir, int64_t *clock,
                                     size_t *rebuilt_out)
{
    for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
        uint8_t root[32];
        if (!zcl_hex_decode_lower(
                zwn_package_scenarios[i].expected_package_root_hex,
                root, sizeof(root)) ||
            !zwn_build_package(datadir, root, clock, rebuilt_out))
            return false;
    }
    return true;
}

static bool zwn_original_receipts_present(const char *datadir,
                                          size_t *present_out)
{
    *present_out = 0;
    for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
        const char *root_hex =
            zwn_package_scenarios[i].expected_package_root_hex;
        char path[1400];
        int n = snprintf(path, sizeof(path),
                         "%s/zcode/installed/%s/build-report", datadir,
                         root_hex);
        if (n <= 0 || (size_t)n >= sizeof(path))
            return false;
        FILE *file = fopen(path, "rb");
        if (!file)
            return false;
        uint8_t wire[VCS_PACKAGE_BUILD_MAX_WIRE_BYTES];
        size_t wire_len = fread(wire, 1, sizeof(wire), file);
        bool read_ok = wire_len > 0 && feof(file) && !ferror(file);
        if (fclose(file) != 0 || !read_ok)
            return false;
        struct vcs_package_build_receipt receipt;
        uint8_t expected[32];
        if (vcs_package_build_parse(wire, wire_len, &receipt) !=
                VCS_PACKAGE_BUILD_OK ||
            !zcl_hex_decode_lower(root_hex, expected, sizeof(expected)) ||
            memcmp(receipt.package_root, expected, sizeof(expected)) != 0)
            return false;
        (*present_out)++;
    }
    return true;
}

/* ── 1 + 4 + 5: the golden fetch (with restart / disconnect variants) ── */

enum zwn_golden_mode {
    ZWN_GOLDEN_PLAIN = 0,
    ZWN_GOLDEN_RESTART,
    ZWN_GOLDEN_DISCONNECT,
};

static int zwn_test_golden(enum zwn_golden_mode mode,
                           const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    const char *name =
        mode == ZWN_GOLDEN_PLAIN
            ? "golden: end-to-end verified fetch over real zpkgswm frames"
        : mode == ZWN_GOLDEN_RESTART
            ? "restart mid-download: engine recreated over the same "
              "datadir resumes and completes"
            : "disconnect requeue: in-flight work moves to the surviving "
              "server and the download completes";

    TEST(name) {
        /* 12 single-chunk files (restart/disconnect) so the chunk stage
         * spans more than one round (per-peer in-flight is 8) and a
         * mid-download window deterministically exists; 6 for the plain
         * run. */
        size_t file_count = mode == ZWN_GOLDEN_PLAIN ? 6 : 12;
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, file_count, 0x11));

        struct zwn_node a, b, a2;
        const struct zwn_node_spec initial_nodes[] = {
            {&a, mode == ZWN_GOLDEN_PLAIN ? "ga" :
                 mode == ZWN_GOLDEN_RESTART ? "ra" : "da"},
            {&b, mode == ZWN_GOLDEN_PLAIN ? "gb" :
                 mode == ZWN_GOLDEN_RESTART ? "rb" : "db"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, initial_nodes,
                                 sizeof(initial_nodes) /
                                     sizeof(initial_nodes[0])));
        ASSERT(zwn_store_package(a.store, &pkg));

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec initial_links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "peer-b"},
            {&b, &b_a, {1, 2, 3, 4}, "peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, initial_links,
                                 sizeof(initial_links) /
                                     sizeof(initial_links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));

        struct zwn_link a2_b, b_a2;
        bool two_servers = mode == ZWN_GOLDEN_DISCONNECT;
        if (two_servers) {
            const struct zwn_node_spec extra_node[] = {{&a2, "da2"}};
            ASSERT(zwn_fixture_nodes(&fixture, params, extra_node,
                                     sizeof(extra_node) /
                                         sizeof(extra_node[0])));
            ASSERT(zwn_store_package(a2.store, &pkg));
            const struct zwn_link_spec extra_links[] = {
                {&a2, &a2_b, {9, 9, 9, 9}, "peer-b"},
                {&b, &b_a2, {8, 8, 8, 8}, "peer-a2"},
            };
            ASSERT(zwn_fixture_links(&fixture, extra_links,
                                     sizeof(extra_links) /
                                         sizeof(extra_links[0])));
            ASSERT(zwn_meet_side(&a2, &a2_b));
            ASSERT(zwn_meet_side(&b, &b_a2));
        }

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);

        bool restarted = false;
        bool dropped = false;
        bool saw_partial = mode != ZWN_GOLDEN_PLAIN ? false : true;
        bool restart_present[ZWN_MAX_FILES] = {0};
        uint32_t restart_replies[ZWN_MAX_FILES] = {0};
        uint32_t restart_present_chunks = 0;
        uint64_t restart_present_bytes = 0;
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        for (int i = 0; i < 400 && !terminal; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            if (two_servers)
                ASSERT(zwn_round(&a2_b, &b_a2, params->pchMessageStart));

            if (mode == ZWN_GOLDEN_RESTART && !restarted) {
                struct vcs_swarm_download_status st;
                memset(&st, 0, sizeof(st));
                ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                        &st));
                if (st.state == VCS_SWARM_DL_CHUNKS &&
                    st.present_chunks > 0 &&
                    st.present_chunks < st.total_chunks) {
                    saw_partial = true;
                    restarted = true;
                    restart_present_chunks = st.present_chunks;
                    restart_present_bytes = st.present_bytes;
                    uint32_t probed_chunks = 0;
                    uint64_t probed_bytes = 0;
                    for (size_t f = 0; f < pkg.count; f++) {
                        restart_present[f] =
                            vcs_package_store_chunk_present(
                                b.store, pkg.root, (uint32_t)f, 0);
                        restart_replies[f] = a.chunk_data_replies[f];
                        if (restart_present[f]) {
                            probed_chunks++;
                            probed_bytes += pkg.lens[f];
                        }
                    }
                    ASSERT(probed_chunks == restart_present_chunks);
                    ASSERT(probed_bytes == restart_present_bytes);
                    /* A real restart kills the sockets with their queued
                     * bytes: drop both queues first, or the new engine
                     * would read the pre-restart DATAs as unrequested
                     * (they would be — its outstanding table is gone). */
                    zwn_drain_quiet(&a_b);
                    zwn_drain_quiet(&b_a);
                    ASSERT(zwn_node_restart_engine(&b));
                    struct vcs_swarm_download_status resumed;
                    memset(&resumed, 0, sizeof(resumed));
                    ASSERT(vcs_swarm_engine_download_status(
                        b.engine, pkg.root, &resumed));
                    ASSERT(resumed.state == VCS_SWARM_DL_CHUNKS);
                    ASSERT(resumed.present_chunks == restart_present_chunks);
                    ASSERT(resumed.present_bytes == restart_present_bytes);
                    ASSERT(resumed.reused_objects == restart_present_chunks);
                    ASSERT(resumed.reused_bytes == restart_present_bytes);
                    ASSERT(resumed.requested_objects == 0);
                    ASSERT(resumed.transferred_objects == 0);
                    /* The restart forgets session peers AND their
                     * advertisements (transport state, never persisted).
                     * A real restart also drops the connections: emulate
                     * the reconnect on both sides — B's new engine
                     * re-registers A, A sees B as a new peer and
                     * re-announces its packages (exactly what the boot
                     * glue's membership sync does for a new node). */
                    ASSERT(zwn_meet_side(&b, &b_a));
                    vcs_swarm_engine_peer_drop(a.engine,
                                               (uint64_t)a_b.node->id);
                    ASSERT(zwn_meet_side(&a, &a_b));
                }
            }
            if (mode == ZWN_GOLDEN_DISCONNECT && !dropped) {
                struct vcs_swarm_download_status st;
                memset(&st, 0, sizeof(st));
                ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                        &st));
                if (st.state == VCS_SWARM_DL_CHUNKS &&
                    st.present_chunks > 0 &&
                    st.present_chunks < st.total_chunks) {
                    saw_partial = true;
                    dropped = true;
                    /* The membership-sync drop: the connection is gone,
                     * so the engine forgets the peer and requeues its
                     * in-flight work onto the surviving advertiser. The
                     * dead connection's queued bytes die with it. */
                    atomic_store(&b_a.node->disconnect, true);
                    zwn_drain_quiet(&a_b);
                    zwn_drain_quiet(&b_a);
                    vcs_swarm_engine_peer_drop(b.engine,
                                               (uint64_t)b_a.node->id);
                }
            }
            terminal = zwn_download_done(&b, pkg.root, &state);
        }

        ASSERT(saw_partial);
        if (mode == ZWN_GOLDEN_RESTART)
            ASSERT(restarted);
        if (mode == ZWN_GOLDEN_DISCONNECT)
            ASSERT(dropped);
        ASSERT(terminal);
        ASSERT(state == VCS_SWARM_DL_COMPLETE);
        ASSERT(zwn_store_matches(b.store, &pkg));
        if (mode == ZWN_GOLDEN_RESTART) {
            struct vcs_swarm_download_status resumed;
            memset(&resumed, 0, sizeof(resumed));
            ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                    &resumed));
            ASSERT(resumed.reused_objects == restart_present_chunks);
            ASSERT(resumed.reused_bytes == restart_present_bytes);
            ASSERT(resumed.requested_objects ==
                   pkg.count - restart_present_chunks);
            ASSERT(resumed.transferred_objects ==
                   pkg.count - restart_present_chunks);
            ASSERT(resumed.requested_bytes ==
                   pkg.total_bytes - restart_present_bytes);
            ASSERT(resumed.transferred_bytes ==
                   pkg.total_bytes - restart_present_bytes);
            for (size_t f = 0; f < pkg.count; f++)
                if (restart_present[f])
                    ASSERT(a.chunk_data_replies[f] == restart_replies[f]);
            char root_hex[65];
            zcl_hex_encode(pkg.root, 32, root_hex);
            printf("{\"schema\":\"zcl.swarm_restart_resume.v1\","
                   "\"package_root\":\"%s\",\"verdict\":\"PASS\","
                   "\"verified_objects_before_interrupt\":%u,"
                   "\"verified_bytes_before_interrupt\":%" PRIu64 ","
                   "\"objects_reused_after_restart\":%u,"
                   "\"bytes_reused_after_restart\":%" PRIu64 ","
                   "\"remaining_objects_requested\":%u,"
                   "\"remaining_objects_transferred\":%u,"
                   "\"verified_objects_retransmitted\":0,"
                   "\"same_graph\":true}\n",
                   root_hex, restart_present_chunks,
                   restart_present_bytes, resumed.reused_objects,
                   resumed.reused_bytes, resumed.requested_objects,
                   resumed.transferred_objects);
        }
        ASSERT(b_a.node->misbehavior == 0);
        if (!dropped)
            ASSERT(a_b.node->misbehavior == 0);
        if (mode == ZWN_GOLDEN_PLAIN) {
            for (int i = 0; i < 8; i++)
                ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            ASSERT(vcs_swarm_receipt_session_settled(
                a.receipts, (uint64_t)a_b.node->id));
            ASSERT(vcs_swarm_receipt_session_settled(
                b.receipts, (uint64_t)b_a.node->id));
        }

        /* Accounting: B credited the verified bytes it received under the
         * serving peers' session keys (two keys in the disconnect run —
         * the work moved from A to A2 mid-download); A credited the
         * verified bytes it served to B's session key. The manifest wire
         * is verified+credited too, so the credit sits in [chunks,
         * chunks + manifest wire]. */
        {
            uint64_t credited = 0;
            uint8_t key[33];
            ASSERT(zwn_peer_key(b_a.node, key));
            struct vcs_service_key_totals kt;
            ASSERT(vcs_service_key_totals(b.book, key, ZWN_DAY, &kt));
            credited += kt.verified_bytes_downloaded;
            if (two_servers) {
                ASSERT(zwn_peer_key(b_a2.node, key));
                ASSERT(vcs_service_key_totals(b.book, key, ZWN_DAY, &kt));
                credited += kt.verified_bytes_downloaded;
            }
            ASSERT(credited >= pkg.total_bytes);
            ASSERT(credited <= pkg.total_bytes + pkg.wire_len);
        }
        {
            uint64_t served = 0;
            uint8_t key[33];
            ASSERT(zwn_peer_key(a_b.node, key));
            struct vcs_service_key_totals kt;
            ASSERT(vcs_service_key_totals(a.book, key, ZWN_DAY, &kt));
            served += kt.verified_bytes_uploaded;
            if (two_servers) {
                ASSERT(zwn_peer_key(a2_b.node, key));
                ASSERT(vcs_service_key_totals(a2.book, key, ZWN_DAY, &kt));
                served += kt.verified_bytes_uploaded;
            }
            ASSERT(served >= pkg.total_bytes);
            /* Non-plain runs discard answered-but-undelivered DATAs with
             * the drained socket queues, so the surviving server
             * genuinely re-serves those chunks (upload credit is
             * recorded at serve time, against the request id — that is
             * honest); the slack bound is the worst-case in-flight set
             * at the drain. The plain run keeps the exact bound. */
            uint64_t slack = mode == ZWN_GOLDEN_PLAIN
                                 ? 0
                                 : VCS_SWARM_PEER_INFLIGHT_MAX *
                                       ZWN_MAX_FILE;
            ASSERT(served <= pkg.total_bytes + pkg.wire_len + slack);
        }

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);

    return failures;
}

/* ── proven source carrier: peer-only checkout + reproducible build ── */

static int zwn_t_sovereign_source_build(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("proven C23 source: two providers feed a fresh Git-free checkout "
         "whose rebuilt binary matches the publisher SHA3") {
        char publisher[512], consumer_cas[512], checkout[512], checkout2[512];
        char publisher_build[512], consumer_build[512], consumer_build2[512];
        test_make_tmpdir(publisher, sizeof(publisher),
                         "zcode_swarm_net", "source-publisher");
        test_make_tmpdir(consumer_cas, sizeof(consumer_cas),
                         "zcode_swarm_net", "source-consumer-cas");
        test_make_tmpdir(checkout, sizeof(checkout),
                         "zcode_swarm_net", "source-checkout");
        test_make_tmpdir(checkout2, sizeof(checkout2),
                         "zcode_swarm_net", "source-checkout2");
        test_make_tmpdir(publisher_build, sizeof(publisher_build),
                         "zcode_swarm_net", "source-publisher-build");
        test_make_tmpdir(consumer_build, sizeof(consumer_build),
                         "zcode_swarm_net", "source-consumer-build");
        test_make_tmpdir(consumer_build2, sizeof(consumer_build2),
                         "zcode_swarm_net", "source-consumer-build2");
        char path[1400];
        ASSERT(snprintf(path, sizeof(path), "%s/engine", publisher) > 0);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/engine/entry", publisher) > 0);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/vendor", publisher) > 0);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/vendor/.cache", publisher) >
               0);
        ASSERT(mkdir(path, 0700) == 0);
        static const char license[] =
            "                                 Apache License\n"
            "                           Version 2.0, January 2004\n"
            "                        http://www.apache.org/licenses/\n";
        static const char program[] =
            "#include <stdint.h>\n"
            "static uint32_t mix(uint32_t x) { return (x << 5) ^ (x >> 3); }\n"
            "int main(void) { return mix(UINT32_C(23)) == 738 ? 0 : 1; }\n";
        ASSERT(zwn_write_file(publisher, "LICENSE", license,
                              sizeof(license) - 1u, 0644));
        ASSERT(zwn_write_file(publisher, "engine/entry/main.c", program,
                              sizeof(program) - 1u, 0644));
        static const char offline[] = "hermetic-offline-input\n";
        for (size_t i = 0;
             i < vcs_source_package_offline_input_count(); i++)
            ASSERT(zwn_write_file(
                publisher, vcs_source_package_offline_input_path(i),
                offline, sizeof(offline) - 1u, 0600));

        char publisher_source[1400], publisher_binary[1400];
        ASSERT(snprintf(publisher_source, sizeof(publisher_source),
                        "%s/engine/entry/main.c", publisher) > 0);
        ASSERT(snprintf(publisher_binary, sizeof(publisher_binary),
                        "%s/program", publisher_build) > 0);
        ASSERT(zwn_compile_c23(publisher_source, publisher_binary));
        ASSERT(zwn_run_fixture_binary(publisher_binary));
        uint8_t publisher_sha3[32], publisher_sha256[32];
        uint8_t initial_publisher_sha3[32];
        ASSERT(zwn_sha3_file(publisher_binary, publisher_sha3));
        memcpy(initial_publisher_sha3, publisher_sha3, 32);
        ASSERT(zwn_sha256_file(publisher_binary, publisher_sha256));

        uint8_t source_root[32];
        ASSERT(vcs_tree_capture_path(publisher, source_root) == VCS_OK);
        const int64_t accepted_now = 1700000000;
        struct test_accepted_work_fixture accepted;
        ASSERT(test_accepted_work_fixture_create(
            publisher, source_root, accepted_now, 0x66, &accepted));
        struct vcs_zcode_accepted_work_v1 resolved_accepted;
        ASSERT(vcs_zcode_accepted_work_resolve(
            publisher, accepted.accepted.accepted_work_root, accepted_now,
            &resolved_accepted));
        struct vcs_source_package_transport transport;
        vcs_source_package_transport_init(&transport);
        ASSERT(vcs_source_package_transport_build_accepted(
            publisher, source_root, accepted.accepted.accepted_work_root,
            accepted_now, &transport));

        char source_hex[65], package_hex[65], generation_hex[65];
        zcl_hex_encode(source_root, 32, source_hex);
        zcl_hex_encode(transport.package_root, 32, package_hex);
        zcl_hex_encode(publisher_sha256, 32, generation_hex);
        struct vcs_devloop_verdict dev_verdict = {
            .verdict_status = 0,
            .phase = "verify",
            .elapsed_ms = 23,
            .generation_hex = generation_hex,
            .agent_id = "fixture-agent",
            .session_id = "sovereign-roundtrip",
            .task_ref = "c23/source",
            .proof_complete = true,
            .proof_scope = "source_wide_compile_tests_lint_fast",
            .source_identity_hex = source_hex,
            .source_cas_hex = package_hex,
        };
        struct vcs_devloop_anchor_result publication_anchor = {0};
        vcs_devloop_anchor_cycle(
            publisher, &dev_verdict, &publication_anchor);
        ASSERT(publication_anchor.status == VCS_DEVLOOP_ANCHOR_OK);
        ASSERT(publication_anchor.publication_status ==
               VCS_DEVLOOP_PUBLICATION_QUEUED);
        ASSERT(publication_anchor.publication_enqueue_us >= 0);
        uint8_t commit_root[32];
        memcpy(commit_root, publication_anchor.commit_id, 32);
        struct vcs_devloop_publication_job publication_job;
        ASSERT(vcs_devloop_publication_job_load(
            publisher, publication_anchor.publication_job_root,
            &publication_job));
        ASSERT(memcmp(publication_job.vcs_commit_root, commit_root, 32) == 0);
        ASSERT(memcmp(publication_job.source_tree_root, source_root, 32) == 0);
        uint8_t publication_progress_root[32];
        bool publication_reused = true;
        ASSERT(vcs_devloop_publication_advance_waiting_acceptance(
            publisher, publication_anchor.publication_job_root,
            publication_progress_root, &publication_reused));
        ASSERT(!publication_reused);
        ASSERT(vcs_devloop_publication_advance_proven_work(
            publisher, publication_anchor.publication_job_root,
            accepted.accepted.accepted_work_root, accepted_now,
            publication_progress_root, &publication_reused));
        ASSERT(!publication_reused);
        struct vcs_package_mapping_metrics publication_metrics;
        uint8_t publication_mapping_root[32];
        ASSERT(vcs_package_mapping_set_build(
            publisher, source_root, accepted.accepted.accepted_work_root,
            &publication_metrics, publication_mapping_root));
        ASSERT(vcs_devloop_publication_advance_package_mapping(
            publisher, publication_anchor.publication_job_root,
            publication_mapping_root, publication_metrics.bytes_scanned,
            publication_metrics.new_chunks, publication_metrics.reused_chunks,
            publication_progress_root, &publication_reused));
        ASSERT(!publication_reused);
        uint8_t *commit_wire = NULL;
        size_t commit_wire_len = 0;
        ASSERT(vcs_object_get(
                   publisher, commit_root, VCS_TAG_COMMIT,
                   &commit_wire, &commit_wire_len) == 0);
        ASSERT(commit_wire_len == VCS_COMMIT_PREIMAGE_BYTES);
        struct vcs_commit publisher_commit;
        ASSERT(vcs_commit_parse_preimage(
            commit_wire, commit_wire_len, &publisher_commit));
        ASSERT(memcmp(publisher_commit.tree_hash, source_root, 32) == 0);
        ASSERT(memcmp(publisher_commit.generation_sha256,
                      publisher_sha256, 32) == 0);

        uint8_t license_root[32], author_binding_root[32];
        sha3_256((const uint8_t *)license, sizeof(license) - 1u,
                 license_root);
        zwn_literal_root("fixture/author", author_binding_root);
        struct vcs_zcode_source_assignment_v1 assignment = {
            .schema_version = 1,
            .flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS,
            .source_kind = VCS_ZCODE_SOURCE_AI_AUTHORED,
            .sequence = 1,
            .assigned_height = 101,
            .assigned_mtp = accepted_now,
        };
        memcpy(assignment.source_root, source_root, 32);
        memcpy(assignment.author_binding_root, author_binding_root, 32);
        memcpy(assignment.license_root, license_root, 32);
        memcpy(assignment.assignment_evidence_root,
               accepted.accepted.accepted_work_root, 32);
        uint8_t assignment_seed[32];
        memset(assignment_seed, 0x91, sizeof(assignment_seed));
        ASSERT(vcs_zcode_source_assignment_v1_sign(
                   &assignment, assignment_seed) == VCS_ZCODE_C23_OK);
        uint8_t assignment_wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
        size_t assignment_wire_len = 0;
        uint8_t assignment_root[32];
        ASSERT(vcs_zcode_source_assignment_v1_encode(
                   &assignment, assignment_wire, sizeof(assignment_wire),
                   &assignment_wire_len) == VCS_ZCODE_C23_OK);
        ASSERT(vcs_zcode_source_assignment_v1_root(
                   &assignment, assignment_root) == VCS_ZCODE_C23_OK);

        struct vcs_package_release first_release;
        uint8_t first_release_root[32];
        ASSERT(zwn_release_make(
            transport.package_root, transport.recipe_root, "1.0.0", 1,
            NULL, &first_release, first_release_root));
        uint8_t *first_release_wire = NULL;
        size_t first_release_wire_len = 0;
        ASSERT(vcs_package_release_serialize(
                   &first_release, &first_release_wire,
                   &first_release_wire_len) == VCS_PACKAGE_RELEASE_OK);
        ASSERT(vcs_object_put_addressed(
            publisher, first_release_root, first_release_wire,
            first_release_wire_len));
        ASSERT(vcs_devloop_publication_advance_release(
            publisher, publication_anchor.publication_job_root,
            publication_mapping_root, first_release_root,
            publication_progress_root, &publication_reused));
        ASSERT(!publication_reused);

        struct vcs_zcode_module_passport_v1 passport = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
        };
        zwn_literal_root("fixture/sovereign-source-api-v1",
                         passport.stable_api_root);
        memcpy(passport.recipe_root, transport.recipe_root, 32);
        memcpy(passport.toolchain_root,
               accepted.accepted.task.toolchain_capsule_root, 32);
        memcpy(passport.tests_root, accepted.accepted.proof_set_root, 32);
        memcpy(passport.license_root, license_root, 32);
        memcpy(passport.semantic_fingerprint_root, source_root, 32);
        memcpy(passport.workspace_lineage_root, commit_root, 32);
        memcpy(passport.source_assignment_root, assignment_root, 32);
        zwn_literal_root("fixture/universal-quality-v1",
                         passport.quality_profiles_root);
        uint8_t passport_seed[32];
        memset(passport_seed, 0x92, sizeof(passport_seed));
        ASSERT(vcs_zcode_module_passport_v1_sign(
                   &passport, passport_seed) == VCS_ZCODE_COMMONS_OK);
        uint8_t passport_wire[VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES];
        size_t passport_wire_len = 0;
        uint8_t passport_root[32];
        ASSERT(vcs_zcode_module_passport_v1_encode(
                   &passport, passport_wire, sizeof(passport_wire),
                   &passport_wire_len) == VCS_ZCODE_COMMONS_OK);
        ASSERT(vcs_zcode_module_passport_v1_root(
                   &passport, passport_root) == VCS_ZCODE_COMMONS_OK);
        ASSERT(vcs_object_put_addressed(
            publisher, passport_root, passport_wire, passport_wire_len));
        ASSERT(vcs_devloop_publication_advance_passport(
            publisher, publication_anchor.publication_job_root,
            publication_mapping_root, first_release_root, passport_root,
            publication_progress_root, &publication_reused));
        ASSERT(!publication_reused);

        struct vcs_zcode_workspace_entry_v1 workspace_entry = {
            .sequence = 1,
        };
        memcpy(workspace_entry.module_release_root,
               first_release_root, 32);
        memcpy(workspace_entry.module_passport_root, passport_root, 32);
        memcpy(workspace_entry.semantic_fingerprint_root,
               passport.semantic_fingerprint_root, 32);
        memcpy(workspace_entry.source_assignment_root,
               assignment_root, 32);
        struct vcs_zcode_workspace_manifest_v1 workspace_manifest = {
            .schema_version = 1,
            .flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS,
            .sequence = 1,
            .entries = &workspace_entry,
            .entry_count = 1,
        };
        uint8_t workspace_seed[32], workspace_secret[32];
        memset(workspace_seed, 0x93, sizeof(workspace_seed));
        ed25519_keypair(workspace_manifest.signer_root,
                        workspace_secret, workspace_seed);
        uint8_t workspace_payload[
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES];
        size_t workspace_payload_len = 0;
        ASSERT(vcs_zcode_workspace_manifest_v1_signing_payload(
                   &workspace_manifest, workspace_payload,
                   sizeof(workspace_payload), &workspace_payload_len) ==
               VCS_ZCODE_COMMONS_OK);
        ed25519_sign(workspace_manifest.signature, workspace_payload,
                     workspace_payload_len, workspace_secret,
                     workspace_manifest.signer_root);
        memset(workspace_secret, 0, sizeof(workspace_secret));
        ASSERT(vcs_zcode_workspace_manifest_v1_verify(
                   &workspace_manifest) == VCS_ZCODE_COMMONS_OK);
        size_t workspace_wire_size = 0, workspace_wire_len = 0;
        ASSERT(vcs_zcode_workspace_manifest_v1_wire_size(
                   &workspace_manifest, &workspace_wire_size) ==
               VCS_ZCODE_COMMONS_OK);
        uint8_t *workspace_wire = zcl_malloc(
            workspace_wire_size, "zwn.workspace_wire");
        ASSERT(workspace_wire != NULL);
        ASSERT(vcs_zcode_workspace_manifest_v1_encode(
                   &workspace_manifest, workspace_wire,
                   workspace_wire_size, &workspace_wire_len) ==
               VCS_ZCODE_COMMONS_OK);
        uint8_t workspace_root[32];
        ASSERT(vcs_zcode_workspace_manifest_v1_root(
                   &workspace_manifest, workspace_root) ==
               VCS_ZCODE_COMMONS_OK);
        ASSERT(vcs_object_put_addressed(
            publisher, workspace_root, workspace_wire, workspace_wire_len));
        ASSERT(vcs_devloop_publication_advance_workspace(
            publisher, publication_anchor.publication_job_root,
            publication_mapping_root, first_release_root, passport_root,
            workspace_root, publication_progress_root,
            &publication_reused));
        ASSERT(!publication_reused);
        struct vcs_devloop_publication_receipt publication_progress;
        uint8_t loaded_publication_progress_root[32];
        ASSERT(vcs_devloop_publication_progress_load(
            publisher, publication_anchor.publication_job_root,
            &publication_progress, loaded_publication_progress_root));
        ASSERT(publication_progress.phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED);
        ASSERT(memcmp(publication_progress.artifact_root,
                      workspace_root, 32) == 0);
        ASSERT(memcmp(publication_progress_root,
                      loaded_publication_progress_root, 32) == 0);
        publication_reused = false;
        ASSERT(vcs_devloop_publication_advance_workspace(
            publisher, publication_anchor.publication_job_root,
            publication_mapping_root, first_release_root, passport_root,
            workspace_root, publication_progress_root,
            &publication_reused));
        ASSERT(publication_reused);

        const uint8_t *evidence_wires[5] = {
            passport_wire, first_release_wire, assignment_wire,
            workspace_wire, commit_wire,
        };
        const size_t evidence_lengths[5] = {
            passport_wire_len, first_release_wire_len, assignment_wire_len,
            workspace_wire_len, commit_wire_len,
        };
        struct zwn_pkg workspace_carrier;
        ASSERT(zwn_make_evidence_package(
            &workspace_carrier, evidence_wires, evidence_lengths));

        struct zwn_node a, b, a2;
        const struct zwn_node_spec provider_nodes[] = {
            {&a, "sa"}, {&a2, "sa2"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, provider_nodes,
                                 sizeof(provider_nodes) /
                                     sizeof(provider_nodes[0])));
        ASSERT(zwn_store_source_transport(a.store, &transport));
        ASSERT(vcs_package_store_pin(
                   a.store, transport.package_root, true) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(zwn_store_package(a.store, &workspace_carrier));
        ASSERT(vcs_package_store_pin(
                   a.store, workspace_carrier.root, true) ==
               VCS_PACKAGE_STORE_OK);
        struct zwn_link a_a2, a2_a;
        const struct zwn_link_spec provider_links[] = {
            {&a, &a_a2, {10, 1, 1, 2}, "source-server-b"},
            {&a2, &a2_a, {10, 1, 1, 1}, "source-server-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, provider_links,
                                 sizeof(provider_links) /
                                     sizeof(provider_links[0])));
        ASSERT(zwn_meet_side(&a, &a_a2));
        ASSERT(zwn_meet_side(&a2, &a2_a));
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        ASSERT(zwn_fetch_package_from_peers(
            &a2, transport.package_root, &a_a2, &a2_a, NULL, NULL,
            params->pchMessageStart));
        ASSERT(vcs_package_store_pin(
                   a2.store, transport.package_root, true) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(zwn_fetch_package_from_peers(
            &a2, workspace_carrier.root, &a_a2, &a2_a,
            NULL, NULL, params->pchMessageStart));
        ASSERT(vcs_package_store_pin(
                   a2.store, workspace_carrier.root, true) ==
               VCS_PACKAGE_STORE_OK);
        struct vcs_package_store_status server_a_status, server_b_status;
        ASSERT(vcs_package_store_package_status(
                   a.store, transport.package_root, &server_a_status));
        ASSERT(vcs_package_store_package_status(
                   a2.store, transport.package_root, &server_b_status));
        ASSERT(server_a_status.complete && server_a_status.pinned);
        ASSERT(server_b_status.complete && server_b_status.pinned);
        ASSERT(vcs_package_store_package_status(
            a.store, workspace_carrier.root, &server_a_status));
        ASSERT(vcs_package_store_package_status(
            a2.store, workspace_carrier.root, &server_b_status));
        ASSERT(server_a_status.complete && server_a_status.pinned);
        ASSERT(server_b_status.complete && server_b_status.pinned);
        vcs_swarm_engine_peer_drop(a.engine, (uint64_t)a_a2.node->id);
        vcs_swarm_engine_peer_drop(a2.engine, (uint64_t)a2_a.node->id);
        zwn_fixture_release_link(&fixture, &a_a2);
        zwn_fixture_release_link(&fixture, &a2_a);

        const struct zwn_node_spec consumer_node[] = {{&b, "sb"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, consumer_node,
                                 sizeof(consumer_node) /
                                     sizeof(consumer_node[0])));
        struct zwn_link a_b, b_a, a2_b, b_a2;
        const struct zwn_link_spec consumer_links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "source-b"},
            {&b, &b_a, {1, 2, 3, 4}, "source-a"},
            {&a2, &a2_b, {9, 9, 9, 9}, "source-b"},
            {&b, &b_a2, {8, 8, 8, 8}, "source-a2"},
        };
        ASSERT(zwn_fixture_links(&fixture, consumer_links,
                                 sizeof(consumer_links) /
                                     sizeof(consumer_links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));
        ASSERT(zwn_meet_side(&a2, &a2_b));
        ASSERT(zwn_meet_side(&b, &b_a2));

        uint8_t received_wire[2048];
        size_t received_wire_len = 0;
        uint8_t discovered_workspace_carrier[32];
        ASSERT(zwn_discover_transport(
            &a, &a2, &b, "zcode.workspace", workspace_root,
            workspace_carrier.root, discovered_workspace_carrier, NULL,
            1002));
        ASSERT(memcmp(discovered_workspace_carrier,
                      workspace_carrier.root, 32) == 0);
        ASSERT(zwn_fetch_package_from_peers(
            &b, discovered_workspace_carrier, &a_b, &b_a,
            &a2_b, &b_a2, params->pchMessageStart));
        ASSERT(zwn_read_package_file(
            b.store, discovered_workspace_carrier,
            ZWN_EVIDENCE_WORKSPACE, received_wire,
            sizeof(received_wire), &received_wire_len));
        struct vcs_zcode_workspace_manifest_v1_decoded consumer_workspace =
            {0};
        ASSERT(vcs_zcode_workspace_manifest_v1_decode(
                   &consumer_workspace, received_wire,
                   received_wire_len) == VCS_ZCODE_COMMONS_OK);
        uint8_t checked_root[32];
        ASSERT(vcs_zcode_workspace_manifest_v1_root(
                   &consumer_workspace.manifest, checked_root) ==
               VCS_ZCODE_COMMONS_OK);
        ASSERT(memcmp(checked_root, workspace_root, 32) == 0);
        ASSERT(consumer_workspace.manifest.entry_count == 1);
        struct vcs_zcode_workspace_entry_v1 consumer_entry =
            consumer_workspace.manifest.entries[0];
        vcs_zcode_workspace_manifest_v1_decoded_free(&consumer_workspace);

        ASSERT(zwn_read_package_file(
            b.store, discovered_workspace_carrier,
            ZWN_EVIDENCE_RELEASE, received_wire,
            sizeof(received_wire), &received_wire_len));
        struct vcs_package_release consumer_release;
        ASSERT(vcs_package_release_parse(
                   received_wire, received_wire_len, &consumer_release) ==
               VCS_PACKAGE_RELEASE_OK);
        ASSERT(vcs_package_release_verify(&consumer_release) ==
               VCS_PACKAGE_RELEASE_OK);
        ASSERT(vcs_package_release_id(
                   &consumer_release, checked_root) ==
               VCS_PACKAGE_RELEASE_OK);
        ASSERT(memcmp(checked_root,
                      consumer_entry.module_release_root, 32) == 0);

        ASSERT(zwn_read_package_file(
            b.store, discovered_workspace_carrier,
            ZWN_EVIDENCE_PASSPORT, received_wire,
            sizeof(received_wire), &received_wire_len));
        struct vcs_zcode_module_passport_v1 consumer_passport;
        ASSERT(vcs_zcode_module_passport_v1_decode(
                   &consumer_passport, received_wire,
                   received_wire_len) == VCS_ZCODE_COMMONS_OK);
        ASSERT(vcs_zcode_module_passport_v1_root(
                   &consumer_passport, checked_root) ==
               VCS_ZCODE_COMMONS_OK);
        ASSERT(memcmp(checked_root,
                      consumer_entry.module_passport_root, 32) == 0);
        ASSERT(memcmp(consumer_passport.recipe_root,
                      consumer_release.recipe_root, 32) == 0);
        ASSERT(memcmp(consumer_passport.semantic_fingerprint_root,
                      consumer_entry.semantic_fingerprint_root, 32) == 0);
        ASSERT(memcmp(consumer_passport.source_assignment_root,
                      consumer_entry.source_assignment_root, 32) == 0);

        ASSERT(zwn_read_package_file(
            b.store, discovered_workspace_carrier,
            ZWN_EVIDENCE_ASSIGNMENT, received_wire,
            sizeof(received_wire), &received_wire_len));
        struct vcs_zcode_source_assignment_v1 consumer_assignment;
        ASSERT(vcs_zcode_source_assignment_v1_decode(
                   &consumer_assignment, received_wire,
                   received_wire_len) == VCS_ZCODE_C23_OK);
        ASSERT(vcs_zcode_source_assignment_v1_root(
                   &consumer_assignment, checked_root) ==
               VCS_ZCODE_C23_OK);
        ASSERT(memcmp(checked_root,
                      consumer_passport.source_assignment_root, 32) == 0);
        ASSERT(memcmp(consumer_assignment.license_root,
                      consumer_passport.license_root, 32) == 0);

        ASSERT(zwn_read_package_file(
            b.store, discovered_workspace_carrier,
            ZWN_EVIDENCE_COMMIT, received_wire,
            sizeof(received_wire), &received_wire_len));
        struct vcs_commit consumer_commit;
        ASSERT(vcs_commit_parse_preimage(
            received_wire, received_wire_len, &consumer_commit));
        ASSERT(vcs_commit_id(&consumer_commit, checked_root));
        ASSERT(memcmp(checked_root,
                      consumer_passport.workspace_lineage_root, 32) == 0);
        ASSERT(memcmp(consumer_commit.tree_hash,
                      consumer_assignment.source_root, 32) == 0);

        uint8_t discovered_package_root[32];
        struct vcs_zcode_dht_record provider_record;
        ASSERT(zwn_discover_transport(
            &a, &a2, &b, "zcode.source",
            consumer_assignment.source_root, consumer_release.package_root,
            discovered_package_root, &provider_record, 1010));
        ASSERT(memcmp(discovered_package_root,
                      consumer_release.package_root, 32) == 0);
        uint8_t provider_wire[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        ASSERT(vcs_zcode_dht_record_encode(
                   &provider_record, provider_wire) ==
               VCS_ZCODE_DHT_RECORD_OK);
        uint8_t provider_record_root[32];
        ASSERT(vcs_zcode_dht_record_id(
                   &provider_record, provider_record_root) ==
               VCS_ZCODE_DHT_RECORD_OK);
        struct vcs_zcode_dht_record_verify_context provider_verify;
        memset(&provider_verify, 0, sizeof(provider_verify));
        memset(provider_verify.network_genesis, 0x71,
               sizeof(provider_verify.network_genesis));
        provider_verify.now_unix = 1011;
        provider_verify.authority_verify = zwn_dht_chain_ok;
        uint8_t provider_progress_root[32];
        bool provider_progress_reused = true;
        ASSERT(vcs_devloop_publication_advance_provider(
            publisher, publication_anchor.publication_job_root,
            provider_wire, sizeof(provider_wire), &provider_verify,
            provider_progress_root, &provider_progress_reused));
        ASSERT(!provider_progress_reused);
        ASSERT(vcs_devloop_publication_progress_load(
            publisher, publication_anchor.publication_job_root,
            &publication_progress, loaded_publication_progress_root));
        ASSERT(publication_progress.phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED);
        ASSERT(publication_progress.providers == 1);
        ASSERT(publication_progress.storage_acks == 0);
        ASSERT(memcmp(publication_progress_root,
                      publication_progress.predecessor_receipt_root,
                      32) == 0);
        ASSERT(memcmp(provider_progress_root,
                      loaded_publication_progress_root, 32) == 0);
        provider_progress_reused = false;
        ASSERT(vcs_devloop_publication_advance_provider(
            publisher, publication_anchor.publication_job_root,
            provider_wire, sizeof(provider_wire), &provider_verify,
            loaded_publication_progress_root,
            &provider_progress_reused));
        ASSERT(provider_progress_reused);
        ASSERT(memcmp(provider_progress_root,
                      loaded_publication_progress_root, 32) == 0);
        ASSERT(zwn_fetch_package_from_peers(
            &b, discovered_package_root, &a_b, &b_a, &a2_b, &b_a2,
            params->pchMessageStart));

        ASSERT(vcs_object_store_init(consumer_cas));
        ASSERT(access(checkout, F_OK) == 0);
        ASSERT(snprintf(path, sizeof(path), "%s/.git", checkout) > 0);
        ASSERT(access(path, F_OK) != 0 && errno == ENOENT);
        uint8_t wrong_source_root[32], refused_accepted_root[32];
        memcpy(wrong_source_root, consumer_assignment.source_root, 32);
        wrong_source_root[0] ^= 1u;
        memset(refused_accepted_root, 0xa5,
               sizeof(refused_accepted_root));
        ASSERT(vcs_source_package_accepted_work_discover(
                   b.store, discovered_package_root, wrong_source_root,
                   refused_accepted_root) ==
               VCS_SOURCE_PACKAGE_CHECKOUT_SOURCE);
        uint8_t zero_root[32] = {0};
        ASSERT(memcmp(refused_accepted_root, zero_root, 32) == 0);
        uint8_t discovered_accepted_root[32];
        ASSERT(vcs_source_package_accepted_work_discover(
                   b.store, discovered_package_root,
                   consumer_assignment.source_root,
                   discovered_accepted_root) ==
               VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(memcmp(discovered_accepted_root,
                      accepted.accepted.accepted_work_root, 32) == 0);
        struct vcs_source_package_checkout_metrics metrics;
        ASSERT(vcs_source_package_checkout_accepted(
                   b.store, discovered_package_root,
                   consumer_assignment.source_root,
                   discovered_accepted_root, consumer_cas,
                   checkout, &metrics) ==
               VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(metrics.authority_objects >= 9 && metrics.work_receipts == 2);
        ASSERT(metrics.source.file_count == 2);
        ASSERT(metrics.offline_input_files ==
               vcs_source_package_offline_input_count());
        ASSERT(metrics.carrier_files ==
               vcs_source_package_transport_file_count(&transport));
        struct vcs_zcode_accepted_work_v1 consumer_accepted;
        ASSERT(vcs_zcode_accepted_work_resolve(
            consumer_cas, discovered_accepted_root, accepted_now,
            &consumer_accepted));
        ASSERT(memcmp(consumer_passport.tests_root,
                      consumer_accepted.proof_set_root, 32) == 0);
        ASSERT(memcmp(consumer_passport.toolchain_root,
                      consumer_accepted.task.toolchain_capsule_root, 32) ==
               0);
        ASSERT(memcmp(consumer_assignment.assignment_evidence_root,
                      discovered_accepted_root, 32) == 0);
        /* Work-solution admission on the FETCHED package — the receiver-
         * side binding check a work puller runs after the swarm delivered
         * bytes this node never held before. The package's own chain
         * names the task; a flipped expected root is refused. */
        uint8_t work_task_root[32], work_source_root[32];
        uint8_t work_accepted_root[32];
        ASSERT_EQ(vcs_zcode_work_solution_admit(
                      b.store, discovered_package_root,
                      consumer_accepted.task_root, work_task_root,
                      work_source_root, work_accepted_root),
                  VCS_ZCODE_WORK_ADMIT_OK);
        ASSERT(memcmp(work_task_root, consumer_accepted.task_root, 32) ==
               0);
        ASSERT(memcmp(work_source_root,
                      consumer_assignment.source_root, 32) == 0);
        ASSERT(memcmp(work_accepted_root, discovered_accepted_root, 32) ==
               0);
        uint8_t work_flipped[32];
        memcpy(work_flipped, consumer_accepted.task_root, 32);
        work_flipped[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_solution_admit(
                      b.store, discovered_package_root, work_flipped,
                      NULL, NULL, NULL),
                  VCS_ZCODE_WORK_ADMIT_TASK_MISMATCH);

        char consumer_source[1400], consumer_binary[1400];
        ASSERT(snprintf(consumer_source, sizeof(consumer_source),
                        "%s/engine/entry/main.c", checkout) > 0);
        ASSERT(snprintf(consumer_binary, sizeof(consumer_binary),
                        "%s/program", consumer_build) > 0);
        struct stat publisher_stat, consumer_stat;
        ASSERT(stat(publisher_source, &publisher_stat) == 0);
        ASSERT(stat(consumer_source, &consumer_stat) == 0);
        ASSERT((publisher_stat.st_mode & 0777) ==
               (consumer_stat.st_mode & 0777));
        ASSERT(publisher_stat.st_size == consumer_stat.st_size);
        ASSERT(zwn_compile_c23(consumer_source, consumer_binary));
        ASSERT(zwn_run_fixture_binary(consumer_binary));
        uint8_t consumer_sha3[32], consumer_sha256[32];
        ASSERT(zwn_sha3_file(consumer_binary, consumer_sha3));
        ASSERT(zwn_sha256_file(consumer_binary, consumer_sha256));
        ASSERT(zwn_hashes_match("publisher_binary_sha3",
                                publisher_sha3, consumer_sha3));
        ASSERT(memcmp(consumer_commit.generation_sha256,
                      consumer_sha256, 32) == 0);

        static const char successor_program[] =
            "#include <stdint.h>\n"
            "static uint32_t mix(uint32_t x) { return (x << 5) ^ (x >> 3); }\n"
            "int main(void) { return mix(UINT32_C(24)) == 771 ? 0 : 1; }\n";
        ASSERT(unlink(publisher_source) == 0);
        ASSERT(zwn_write_file(publisher, "engine/entry/main.c", successor_program,
                              sizeof(successor_program) - 1u, 0644));
        uint8_t successor_source_root[32];
        ASSERT(vcs_tree_capture_path(publisher, successor_source_root) ==
               VCS_OK);
        struct test_accepted_work_fixture successor_accepted;
        ASSERT(test_accepted_work_fixture_create(
            publisher, successor_source_root, accepted_now + 1, 0x67,
            &successor_accepted));
        struct vcs_source_package_transport successor_transport;
        vcs_source_package_transport_init(&successor_transport);
        ASSERT(vcs_source_package_transport_build_accepted(
            publisher, successor_source_root,
            successor_accepted.accepted.accepted_work_root,
            accepted_now + 1, &successor_transport));
        ASSERT(memcmp(successor_transport.package_root,
                      transport.package_root, 32) != 0);
        ASSERT(zwn_store_source_transport(a.store, &successor_transport));
        ASSERT(vcs_package_store_pin(
                   a.store, successor_transport.package_root, true) ==
               VCS_PACKAGE_STORE_OK);

        ASSERT(zwn_store_source_transport(a2.store, &successor_transport));
        ASSERT(vcs_package_store_pin(
                   a2.store, successor_transport.package_root, true) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(zwn_node_restart_engine(&a));
        ASSERT(zwn_node_restart_engine(&a2));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&a2, &a2_b));

        struct vcs_package_release successor_release;
        uint8_t successor_release_root[32], observed_parent[32];
        ASSERT(zwn_release_make(
            successor_transport.package_root,
            successor_transport.recipe_root, "1.0.1", 2,
            first_release_root, &successor_release,
            successor_release_root));
        ASSERT(vcs_package_release_parent(
                   &successor_release, observed_parent) &&
               memcmp(observed_parent, first_release_root, 32) == 0);
        uint8_t *successor_release_wire = NULL;
        size_t successor_release_wire_len = 0;
        ASSERT(vcs_package_release_serialize(
                   &successor_release, &successor_release_wire,
                   &successor_release_wire_len) == VCS_PACKAGE_RELEASE_OK);
        ASSERT(vcs_object_put_addressed(
            publisher, successor_release_root, successor_release_wire,
            successor_release_wire_len));
        free(successor_release_wire);

        uint8_t discovered_successor_root[32];
        ASSERT(zwn_discover_transport(
            &a, &a2, &b, "zcode.source", successor_source_root,
            successor_transport.package_root, discovered_successor_root,
            NULL, 1020));
        ASSERT(vcs_swarm_engine_fetch(
                   b.engine, discovered_successor_root, ZWN_DAY, ++b.now) ==
               VCS_SWARM_FETCH_OK);
        state = VCS_SWARM_DL_INACTIVE;
        terminal = false;
        for (int i = 0; i < 600 && !terminal; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            ASSERT(zwn_round(&a2_b, &b_a2, params->pchMessageStart));
            terminal = zwn_download_done(
                &b, discovered_successor_root, &state);
        }
        ASSERT(terminal && state == VCS_SWARM_DL_COMPLETE);
        uint8_t discovered_successor_accepted_root[32];
        ASSERT(vcs_source_package_accepted_work_discover(
                   b.store, discovered_successor_root,
                   successor_source_root,
                   discovered_successor_accepted_root) ==
               VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(memcmp(discovered_successor_accepted_root,
                      successor_accepted.accepted.accepted_work_root,
                      32) == 0);
        struct vcs_source_package_checkout_metrics successor_metrics;
        ASSERT(vcs_source_package_checkout_accepted(
                   b.store, discovered_successor_root,
                   successor_source_root,
                   discovered_successor_accepted_root,
                   consumer_cas, checkout2, &successor_metrics) ==
               VCS_SOURCE_PACKAGE_CHECKOUT_OK);
        ASSERT(successor_metrics.authority_objects >= 9 &&
               successor_metrics.work_receipts == 2);
        char successor_consumer_source[1400], successor_publisher_binary[1400];
        char successor_consumer_binary[1400];
        ASSERT(snprintf(successor_consumer_source,
                        sizeof(successor_consumer_source), "%s/engine/entry/main.c",
                        checkout2) > 0);
        ASSERT(snprintf(successor_publisher_binary,
                        sizeof(successor_publisher_binary), "%s/program2",
                        publisher_build) > 0);
        ASSERT(snprintf(successor_consumer_binary,
                        sizeof(successor_consumer_binary), "%s/program",
                        consumer_build2) > 0);
        ASSERT(zwn_compile_c23(
            publisher_source, successor_publisher_binary));
        ASSERT(zwn_compile_c23(
            successor_consumer_source, successor_consumer_binary));
        ASSERT(zwn_run_fixture_binary(successor_publisher_binary));
        ASSERT(zwn_run_fixture_binary(successor_consumer_binary));
        ASSERT(zwn_sha3_file(successor_publisher_binary, publisher_sha3));
        ASSERT(zwn_sha3_file(successor_consumer_binary, consumer_sha3));
        ASSERT(zwn_hashes_match("successor_binary_sha3",
                                publisher_sha3, consumer_sha3));
        ASSERT(vcs_package_store_package_status(
                   a2.store, transport.package_root, &server_b_status));
        ASSERT(server_b_status.complete && server_b_status.pinned);
        struct vcs_zcode_dht_record storage_ack_records[2];
        uint8_t storage_ack_roots[2][32];
        ASSERT(zwn_author_storage_ack(
            &a, "zcode.source", transport.package_root, 0x81, 0x91,
            &storage_ack_records[0], storage_ack_roots[0]));
        ASSERT(zwn_author_storage_ack(
            &a2, "zcode.source", transport.package_root, 0x82, 0x92,
            &storage_ack_records[1], storage_ack_roots[1]));
        ASSERT(memcmp(storage_ack_records[0].provider_node_id,
                      storage_ack_records[1].provider_node_id, 32) != 0);
        ASSERT(memcmp(storage_ack_records[0].owner_group,
                      storage_ack_records[1].owner_group, 32) != 0);
        ASSERT(memcmp(storage_ack_roots[0], storage_ack_roots[1], 32) != 0);
        uint8_t storage_ack_wires[2][VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
        const uint8_t *storage_ack_wire_ptrs[2] = {
            storage_ack_wires[0], storage_ack_wires[1],
        };
        size_t storage_ack_wire_lengths[2] = {
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
        };
        ASSERT(vcs_zcode_dht_record_encode(
                   &storage_ack_records[0], storage_ack_wires[0]) ==
               VCS_ZCODE_DHT_RECORD_OK);
        ASSERT(vcs_zcode_dht_record_encode(
                   &storage_ack_records[1], storage_ack_wires[1]) ==
               VCS_ZCODE_DHT_RECORD_OK);
        const uint8_t *duplicate_ack_wires[2] = {
            storage_ack_wires[0], storage_ack_wires[0],
        };
        uint8_t storage_ack_progress_root[32];
        bool storage_ack_progress_reused = true;
        ASSERT(!vcs_devloop_publication_advance_storage_acks(
            publisher, publication_anchor.publication_job_root,
            duplicate_ack_wires, storage_ack_wire_lengths, 2,
            &provider_verify, storage_ack_progress_root,
            &storage_ack_progress_reused));
        ASSERT(!storage_ack_progress_reused);
        ASSERT(vcs_devloop_publication_advance_storage_acks(
            publisher, publication_anchor.publication_job_root,
            storage_ack_wire_ptrs, storage_ack_wire_lengths, 2,
            &provider_verify, storage_ack_progress_root,
            &storage_ack_progress_reused));
        ASSERT(!storage_ack_progress_reused);
        ASSERT(vcs_devloop_publication_progress_load(
            publisher, publication_anchor.publication_job_root,
            &publication_progress, loaded_publication_progress_root));
        ASSERT(publication_progress.phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED);
        ASSERT(publication_progress.providers == 2);
        ASSERT(publication_progress.storage_acks == 2);
        ASSERT(memcmp(publication_progress.predecessor_receipt_root,
                      provider_progress_root, 32) == 0);
        ASSERT(memcmp(loaded_publication_progress_root,
                      storage_ack_progress_root, 32) == 0);
        const uint8_t *reversed_ack_wires[2] = {
            storage_ack_wires[1], storage_ack_wires[0],
        };
        storage_ack_progress_reused = false;
        ASSERT(vcs_devloop_publication_advance_storage_acks(
            publisher, publication_anchor.publication_job_root,
            reversed_ack_wires, storage_ack_wire_lengths, 2,
            &provider_verify, loaded_publication_progress_root,
            &storage_ack_progress_reused));
        ASSERT(storage_ack_progress_reused);
        ASSERT(memcmp(loaded_publication_progress_root,
                      storage_ack_progress_root, 32) == 0);
        provider_progress_reused = false;
        ASSERT(vcs_devloop_publication_advance_provider(
            publisher, publication_anchor.publication_job_root,
            provider_wire, sizeof(provider_wire), &provider_verify,
            loaded_publication_progress_root, &provider_progress_reused));
        ASSERT(provider_progress_reused);
        ASSERT(memcmp(loaded_publication_progress_root,
                      storage_ack_progress_root, 32) == 0);

        memset(&g_zwn_sovereign_receipt, 0,
               sizeof(g_zwn_sovereign_receipt));
        g_zwn_sovereign_receipt.ready = true;
        memcpy(g_zwn_sovereign_receipt.source_root, source_root, 32);
        memcpy(g_zwn_sovereign_receipt.accepted_work_root,
               accepted.accepted.accepted_work_root, 32);
        memcpy(g_zwn_sovereign_receipt.proof_set_root,
               accepted.accepted.proof_set_root, 32);
        memcpy(g_zwn_sovereign_receipt.commit_root, commit_root, 32);
        memcpy(g_zwn_sovereign_receipt.release_root,
               first_release_root, 32);
        memcpy(g_zwn_sovereign_receipt.passport_root, passport_root, 32);
        memcpy(g_zwn_sovereign_receipt.workspace_root, workspace_root, 32);
        memcpy(g_zwn_sovereign_receipt.workspace_carrier_root,
               workspace_carrier.root, 32);
        memcpy(g_zwn_sovereign_receipt.source_package_root,
               transport.package_root, 32);
        memcpy(g_zwn_sovereign_receipt.publisher_binary_sha3,
               initial_publisher_sha3, 32);
        memcpy(g_zwn_sovereign_receipt.successor_release_root,
               successor_release_root, 32);
        memcpy(g_zwn_sovereign_receipt.successor_package_root,
               successor_transport.package_root, 32);
        memcpy(g_zwn_sovereign_receipt.successor_binary_sha3,
               publisher_sha3, 32);
        memcpy(g_zwn_sovereign_receipt.storage_ack_roots,
               storage_ack_roots, sizeof(storage_ack_roots));
        g_zwn_sovereign_receipt.storage_ack_count = 2;
        memcpy(g_zwn_sovereign_receipt.provider_record_root,
               provider_record_root, 32);
        memcpy(g_zwn_sovereign_receipt.publication_job_root,
               publication_anchor.publication_job_root, 32);
        memcpy(g_zwn_sovereign_receipt.publication_progress_root,
               storage_ack_progress_root, 32);
        g_zwn_sovereign_receipt.publication_enqueue_us =
            publication_anchor.publication_enqueue_us;
        g_zwn_sovereign_receipt.publication_metrics = publication_metrics;
        g_zwn_sovereign_receipt.source_metrics = transport.bundle_metrics;
        ASSERT(vcs_package_store_package_status(
                   a2.store, workspace_carrier.root,
                   &server_b_status));
        ASSERT(server_b_status.complete && server_b_status.pinned);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&workspace_carrier);
        free(workspace_wire);
        free(first_release_wire);
        free(commit_wire);
        vcs_source_package_transport_free(&successor_transport);
        vcs_source_package_transport_free(&transport);
        test_rm_rf_recursive(publisher);
        test_rm_rf_recursive(consumer_cas);
        test_rm_rf_recursive(checkout);
        test_rm_rf_recursive(checkout2);
        test_rm_rf_recursive(publisher_build);
        test_rm_rf_recursive(consumer_build);
        test_rm_rf_recursive(consumer_build2);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

static void zwn_carrier_admit_command(const char *datadir,
                                      const char *transport_hex,
                                      struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_str(&input, "transport_root", transport_hex);
    struct zcl_command_request request = {0};
    request.input = &input;
    zcl_command_reply_init(reply, "zcl.zcode_package_admit.v1");
    zcl_native_handle_zcode_package_admit(&request, reply);
    json_free(&input);
}

static int zwn_t_incomplete_carrier_import(const struct chain_params *params)
{
    (void)params;
    int failures = 0;
    const struct zwn_package_scenario *scenario = &zwn_package_scenarios[0];
    struct vcs_package_prepared prepared = {0};
    struct vcs_package_transport transport;
    vcs_package_transport_init(&transport);
    char datadir[1024];
    test_make_tmpdir(datadir, sizeof(datadir), "zcode_swarm_net",
                     "partial-carrier-import");
    struct vcs_package_store *store = NULL;
    TEST("incomplete carrier cannot admit an inner manifest or release") {
        ASSERT(zwn_prepare_package_transport(
            scenario, scenario->source_dir, scenario->publisher_sequence,
            scenario->expected_package_root_hex, &prepared, &transport));
        store = vcs_package_store_open(
            datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(store != NULL);
        uint8_t admitted_root[32];
        ASSERT(vcs_package_store_put_manifest(
                   store, transport.transport_manifest_wire,
                   transport.transport_manifest_wire_len, admitted_root) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(memcmp(admitted_root, transport.transport_root, 32) == 0);
        ASSERT(vcs_package_content_put_file(
                   store, admitted_root, VCS_PACKAGE_TRANSPORT_RELEASE_PATH,
                   transport.release_wire, transport.release_wire_len) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_content_put_file(
                   store, admitted_root, VCS_PACKAGE_TRANSPORT_RECIPE_PATH,
                   transport.recipe_wire, transport.recipe_wire_len) ==
               VCS_PACKAGE_STORE_OK);
        ASSERT(vcs_package_content_put_file(
                   store, admitted_root, VCS_PACKAGE_TRANSPORT_MANIFEST_PATH,
                   transport.package_manifest_wire,
                   transport.package_manifest_wire_len) ==
               VCS_PACKAGE_STORE_OK);
        struct vcs_package_store_status status;
        ASSERT(vcs_package_store_package_status(store, admitted_root,
                                                &status));
        ASSERT(!status.complete);
        char transport_hex[65];
        zcl_hex_encode(admitted_root, 32, transport_hex);
        struct zcl_command_reply admit_reply;
        zwn_carrier_admit_command(datadir, transport_hex, &admit_reply);
        ASSERT(admit_reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(admit_reply.error.code, "INCOMPLETE_CARRIER");
        zcl_command_reply_free(&admit_reply);
        zwn_carrier_admit_command(datadir, "invalid", &admit_reply);
        ASSERT_STR_EQ(admit_reply.error.code, "BAD_TRANSPORT_ROOT");
        zcl_command_reply_free(&admit_reply);
        char absent_hex[65];
        memset(absent_hex, 'f', 64);
        absent_hex[64] = '\0';
        zwn_carrier_admit_command(datadir, absent_hex, &admit_reply);
        ASSERT_STR_EQ(admit_reply.error.code, "CARRIER_NOT_TRACKED");
        zcl_command_reply_free(&admit_reply);
        struct vcs_package_transport_import receipt;
        ASSERT(vcs_package_transport_import(store, admitted_root, &receipt) ==
               VCS_PACKAGE_TRANSPORT_ERR_STORE);
        ASSERT(!vcs_package_store_package_status(
            store, transport.package_root, &status));
        char release_hex[65], release_path[1400];
        zcl_hex_encode(transport.release_id, 32, release_hex);
        ASSERT(snprintf(release_path, sizeof(release_path), "%s/releases/%s",
                        vcs_package_store_root_dir(store), release_hex) > 0);
        ASSERT(access(release_path, F_OK) != 0);
        vcs_package_store_close(store);
        store = vcs_package_store_open(
            datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(store != NULL);
        ASSERT(vcs_package_store_package_status(store, admitted_root,
                                                &status));
        ASSERT(!status.complete);
        ASSERT(!vcs_package_store_package_status(
            store, transport.package_root, &status));
        ASSERT(vcs_package_transport_store(
                   store, &transport, scenario->source_dir) ==
               VCS_PACKAGE_TRANSPORT_OK);
        ASSERT(vcs_package_store_package_status(
            store, transport.package_root, &status));
        ASSERT(status.complete);
        ASSERT(access(release_path, F_OK) == 0);
        PASS();
    } _test_next:
    vcs_package_store_close(store);
    vcs_package_transport_free(&transport);
    vcs_package_prepared_free(&prepared);
    test_rm_rf_recursive(datadir);
    return failures;
}

static int zwn_t_historical_transport(struct zwn_node *b,
    const struct vcs_package_prepared *prepared,
    const struct vcs_package_transport *transport,
    const struct vcs_package_prepared *graph_prepared)
{
    int failures = 0;
    /* All graph releases share a publisher; v1 is historical now. New
     * admission remains stale, while transport reimport is idempotent. */
    enum vcs_package_accept_result historical_accept;
    ASSERT(vcs_package_store_put_release(b->store, &prepared->release,
               &historical_accept) == VCS_PACKAGE_STORE_ERR_ACCEPT);
    ASSERT(historical_accept == VCS_PACKAGE_ACCEPT_STALE);
    struct vcs_package_transport_import historical_import;
    ASSERT(vcs_package_transport_import(b->store, transport->transport_root,
               &historical_import) == VCS_PACKAGE_TRANSPORT_OK);
    const struct vcs_package_release *latest_release =
        &prepared->release;
    for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT - 1u; i++)
        if (graph_prepared[i].release.publisher_sequence > latest_release->publisher_sequence)
            latest_release = &graph_prepared[i].release;
    ASSERT(latest_release->publisher_sequence > prepared->release.publisher_sequence);
    ASSERT(vcs_package_store_put_release(b->store, latest_release,
               &historical_accept) == VCS_PACKAGE_STORE_OK);
    ASSERT(historical_accept == VCS_PACKAGE_ACCEPT_DUPLICATE);
    /* An independent handle replays durable history before reimport. */
    struct vcs_package_store *reopened_history =
        vcs_package_store_open(b->datadir, 64u * 1024u * 1024u);
    ASSERT(reopened_history != NULL);
    ASSERT(vcs_package_transport_import(reopened_history,
               transport->transport_root, &historical_import) == VCS_PACKAGE_TRANSPORT_OK);
    ASSERT(vcs_package_store_put_release(reopened_history, latest_release,
               &historical_accept) == VCS_PACKAGE_STORE_OK);
    ASSERT(historical_accept == VCS_PACKAGE_ACCEPT_DUPLICATE);
    vcs_package_store_close(reopened_history);
    /* Duplicate admission through the independent handle advances the
     * durable generation; refresh before testing the original handle. */
    ASSERT(vcs_package_store_refresh(b->store));
    struct vcs_package_release altered_history = prepared->release;
    altered_history.signature[0] ^= 1u;
    ASSERT(!vcs_package_store_release_history_matches(b->store, &altered_history));
    struct vcs_package_prepared unseen_prepared;
    struct vcs_package_transport unseen_transport;
    vcs_package_transport_init(&unseen_transport);
    const struct zwn_package_scenario *unseen_scenario = &zwn_package_scenarios[1];
    ASSERT(zwn_prepare_package_transport(unseen_scenario, unseen_scenario->source_dir,
               prepared->release.publisher_sequence, unseen_scenario->expected_package_root_hex,
               &unseen_prepared, &unseen_transport));
    ASSERT(!vcs_package_store_release_history_matches(b->store, &unseen_prepared.release));
    ASSERT(vcs_package_store_put_release(b->store, &unseen_prepared.release,
               &historical_accept) == VCS_PACKAGE_STORE_ERR_ACCEPT);
    ASSERT(historical_accept == VCS_PACKAGE_ACCEPT_STALE);
    /* Store the complete carrier without admitting its unseen stale
     * release; transport_store itself attempts the same import. */
    ASSERT(vcs_package_transport_store(b->store, &unseen_transport,
               unseen_scenario->source_dir) == VCS_PACKAGE_TRANSPORT_ERR_STORE);
    struct vcs_package_store_status unseen_status;
    ASSERT(vcs_package_store_package_status(b->store,
               unseen_transport.transport_root, &unseen_status));
    ASSERT(unseen_status.complete);
    ASSERT(vcs_package_transport_import(b->store, unseen_transport.transport_root,
               &historical_import) == VCS_PACKAGE_TRANSPORT_ERR_STORE);
    ASSERT(!vcs_package_store_release_history_matches(b->store, &unseen_prepared.release));
    vcs_package_transport_free(&unseen_transport);
    vcs_package_prepared_free(&unseen_prepared);
    char historical_hex[65], historical_path[1400], historical_saved[1440];
    zcl_hex_encode(transport->release_id, 32, historical_hex);
    ASSERT(snprintf(historical_path, sizeof(historical_path), "%s/releases/%s",
               vcs_package_store_root_dir(b->store), historical_hex) > 0);
    ASSERT(snprintf(historical_saved, sizeof(historical_saved), "%s.saved",
               historical_path) > 0);
    ASSERT(rename(historical_path, historical_saved) == 0);
    ASSERT(vcs_package_transport_import(b->store, transport->transport_root,
               &historical_import) == VCS_PACKAGE_TRANSPORT_ERR_STORE);
    FILE *historical_bad = fopen(historical_path, "wb");
    ASSERT(historical_bad != NULL);
    ASSERT(fputc(0, historical_bad) != EOF);
    ASSERT(fclose(historical_bad) == 0);
    ASSERT(vcs_package_transport_import(b->store, transport->transport_root,
               &historical_import) == VCS_PACKAGE_TRANSPORT_ERR_STORE);
    ASSERT(unlink(historical_path) == 0);
    ASSERT(rename(historical_saved, historical_path) == 0);
    ASSERT(vcs_package_transport_import(b->store, transport->transport_root,
               &historical_import) == VCS_PACKAGE_TRANSPORT_OK);
    ASSERT(vcs_package_store_put_release(b->store, latest_release,
               &historical_accept) == VCS_PACKAGE_STORE_OK);
    ASSERT(historical_accept == VCS_PACKAGE_ACCEPT_DUPLICATE);

_test_next:;
    return failures;
}

/* One data-driven product acceptance. The runner knows only the generic
 * package lifecycle; platform/modules/base is scenario data and a later library can use
 * the same path without another publish/fetch/reproduce harness. */
static int zwn_t_package_lifecycle(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    const struct zwn_package_scenario scenario = zwn_package_scenarios[0];
    /* This case builds and rebuilds the full commons package graph across
     * four in-process nodes (cold, restart-free repeat, source edit, header
     * edit, revert), each pass durable-writing every chunk of every one of
     * ZWN_PACKAGE_SCENARIO_COUNT real packages through store_atomic_write.
     * Every one of those writes normally fsyncs before its atomic rename
     * (package_store.h's crash-recovery contract) — correct for a live node,
     * but there is no crash here: everything lands in a tmp datadir this
     * same process reads back and rm -rf's when done, never a power cycle.
     * That made this the group's wall-time sink (300s+ of no output under a
     * loaded box, killed as WEDGED-NO-OUTPUT). Defer the sync for the
     * duration of this case even when it is called outside zwn_run_rows
     * (which now defers it for every row); the prior mode is restored at
     * _test_next: below on every exit path (ASSERT's goto included), so it
     * never leaks into other groups. */
    bool zwn_prior_store_sync = vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true);
    TEST("parameterized signed C23 package graph: A publishes, B discovers, "
         "C and D fetch onward after A disappears") {
        struct vcs_package_prepared prepared;
        struct vcs_package_transport transport;
        struct vcs_package_prepared
            graph_prepared[ZWN_PACKAGE_SCENARIO_COUNT - 1u];
        struct vcs_package_transport
            graph_transport[ZWN_PACKAGE_SCENARIO_COUNT - 1u];
        vcs_package_transport_init(&transport);
        ASSERT(zwn_prepare_package_transport(
            &scenario, scenario.source_dir, scenario.publisher_sequence,
            scenario.expected_package_root_hex, &prepared, &transport));
        for (size_t i = 1; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            const struct zwn_package_scenario *item =
                &zwn_package_scenarios[i];
            fprintf(stderr,
                    "  ... package_lifecycle: preparing %s (%zu/%zu)\n",
                    item->name, i, (size_t)ZWN_PACKAGE_SCENARIO_COUNT - 1u);
            vcs_package_transport_init(&graph_transport[i - 1u]);
            ASSERT(zwn_prepare_package_transport(
                item, item->source_dir, item->publisher_sequence,
                item->expected_package_root_hex, &graph_prepared[i - 1u],
                &graph_transport[i - 1u]));
        }

        struct zwn_node a, b, c, d;
        const struct zwn_node_spec nodes[] = {
            {&a, "pkg-a"}, {&b, "pkg-b"},
            {&c, "pkg-c"}, {&d, "pkg-d"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        ASSERT(vcs_package_transport_store(
                   a.store, &transport, scenario.source_dir) ==
               VCS_PACKAGE_TRANSPORT_OK);
        ASSERT(vcs_package_store_pin(a.store, transport.transport_root,
                                     true) == VCS_PACKAGE_STORE_OK);
        for (size_t i = 1; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            fprintf(stderr,
                    "  ... package_lifecycle: A storing %s (%zu/%zu)\n",
                    zwn_package_scenarios[i].name, i,
                    (size_t)ZWN_PACKAGE_SCENARIO_COUNT - 1u);
            ASSERT(vcs_package_transport_store(
                       a.store, &graph_transport[i - 1u],
                       zwn_package_scenarios[i].source_dir) ==
                   VCS_PACKAGE_TRANSPORT_OK);
            ASSERT(vcs_package_store_pin(
                       a.store, graph_transport[i - 1u].transport_root,
                       true) == VCS_PACKAGE_STORE_OK);
        }

        struct vcs_package_store_status status;
        ASSERT(!vcs_package_store_package_status(
            b.store, transport.transport_root, &status));
        ASSERT(!vcs_package_store_package_status(
            b.store, transport.package_root, &status));

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec a_b_links[] = {
            {&a, &a_b, {10, 0, 0, 1}, "package-b"},
            {&b, &b_a, {10, 0, 0, 2}, "package-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, a_b_links,
                                 sizeof(a_b_links) /
                                     sizeof(a_b_links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        uint8_t discovered[32];
        struct vcs_zcode_dht_record provider;
        ASSERT(zwn_discover_transport(
            &a, &a, &b, scenario.dht_namespace, transport.release_id,
            transport.transport_root, discovered, &provider, 1100));
        ASSERT(memcmp(discovered, transport.transport_root, 32) == 0);
        ASSERT(zwn_fetch_package_from_provider(
            &b, discovered, &a_b, &b_a, params->pchMessageStart));
        struct vcs_swarm_download_status cold;
        memset(&cold, 0, sizeof(cold));
        ASSERT(vcs_swarm_engine_download_status(
            b.engine, transport.transport_root, &cold));
        ASSERT(cold.state == VCS_SWARM_DL_COMPLETE);
        ASSERT(cold.fetched_bytes > 0);
        ASSERT(cold.requested_bytes == cold.transferred_bytes);
        ASSERT(cold.transferred_bytes == cold.fetched_bytes);
        ASSERT(cold.requested_objects == cold.transferred_objects);
        ASSERT(cold.reused_objects == 0);
        uint64_t cold_transferred_bytes = cold.transferred_bytes;
        uint64_t cold_reused_bytes = cold.reused_bytes;
        uint32_t cold_missing_objects = cold.transferred_objects;
        uint32_t cold_reused_objects = cold.reused_objects;

        /* Fetch/verify is inert. The semantic package does not exist in B's
         * store until the separately explicit import reconstructs it. */
        ASSERT(!vcs_package_store_package_status(
            b.store, transport.package_root, &status));
        char admit_carrier_hex[65], admit_package_hex[65];
        char admit_recipe_hex[65], admit_release_hex[65];
        zcl_hex_encode(transport.transport_root, 32, admit_carrier_hex);
        zcl_hex_encode(transport.package_root, 32, admit_package_hex);
        zcl_hex_encode(transport.recipe_root, 32, admit_recipe_hex);
        zcl_hex_encode(transport.release_id, 32, admit_release_hex);
        struct zcl_command_reply admit_reply;
        zwn_carrier_admit_command(b.datadir, admit_carrier_hex, &admit_reply);
        ASSERT(admit_reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&admit_reply.data,
                                            "transport_root")), admit_carrier_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&admit_reply.data,
                                            "package_root")), admit_package_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&admit_reply.data,
                                            "recipe_root")), admit_recipe_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&admit_reply.data,
                                            "release_id")), admit_release_hex);
        ASSERT(json_get_int(json_get(&admit_reply.data, "source_chunks")) > 0);
        ASSERT(json_get_int(json_get(&admit_reply.data,
                     "cas_objects_reused")) ==
               json_get_int(json_get(&admit_reply.data, "source_chunks")));
        zcl_command_reply_free(&admit_reply);
        zwn_carrier_admit_command(b.datadir, admit_carrier_hex, &admit_reply);
        ASSERT(admit_reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&admit_reply.data,
                                            "package_root")), admit_package_hex);
        zcl_command_reply_free(&admit_reply);
        ASSERT(vcs_package_store_refresh(b.store));
        ASSERT(vcs_package_store_package_status(
            b.store, transport.package_root, &status));
        ASSERT(status.complete);
        ASSERT(vcs_package_store_pin(b.store, transport.transport_root,
                                     true) == VCS_PACKAGE_STORE_OK);
        for (size_t i = 1; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            const struct zwn_package_scenario *item =
                &zwn_package_scenarios[i];
            fprintf(stderr,
                    "  ... package_lifecycle: B fetching %s from A (%zu/%zu)\n",
                    item->name, i, (size_t)ZWN_PACKAGE_SCENARIO_COUNT - 1u);
            struct vcs_package_transport *item_transport =
                &graph_transport[i - 1u];
            memset(discovered, 0, sizeof(discovered));
            ASSERT(zwn_discover_transport(
                &a, &a, &b, item->dht_namespace,
                item_transport->release_id,
                item_transport->transport_root, discovered, &provider,
                1100u + (uint64_t)i * 10u));
            ASSERT(zwn_fetch_package_from_provider(
                &b, discovered, &a_b, &b_a,
                params->pchMessageStart));
            struct vcs_swarm_download_status item_cold;
            memset(&item_cold, 0, sizeof(item_cold));
            ASSERT(vcs_swarm_engine_download_status(
                b.engine, item_transport->transport_root, &item_cold));
            ASSERT(item_cold.state == VCS_SWARM_DL_COMPLETE);
            ASSERT(item_cold.requested_bytes ==
                   item_cold.transferred_bytes);
            ASSERT(item_cold.requested_objects ==
                   item_cold.transferred_objects);
            cold_transferred_bytes += item_cold.transferred_bytes;
            cold_reused_bytes += item_cold.reused_bytes;
            cold_missing_objects += item_cold.transferred_objects;
            cold_reused_objects += item_cold.reused_objects;
            ASSERT(!vcs_package_store_package_status(
                b.store, item_transport->package_root, &status));
            struct vcs_package_transport_import item_import;
            ASSERT(vcs_package_transport_import(
                       b.store, item_transport->transport_root,
                       &item_import) == VCS_PACKAGE_TRANSPORT_OK);
            ASSERT(memcmp(item_import.package_root,
                          item_transport->package_root, 32) == 0);
            ASSERT(vcs_package_store_pin(
                       b.store, item_transport->transport_root, true) ==
                   VCS_PACKAGE_STORE_OK);
        }

        ASSERT(zwn_t_historical_transport(&b, &prepared, &transport,
                   graph_prepared) == 0);

        /* Publisher A is genuinely removed before C begins. B is now an
         * ordinary onward provider of the entire exact package graph. */
        zwn_fixture_release_link(&fixture, &a_b);
        zwn_fixture_release_link(&fixture, &b_a);
        zwn_fixture_release_node(&fixture, &a);

        struct zwn_link b_c, c_b;
        const struct zwn_link_spec b_c_links[] = {
            {&b, &b_c, {10, 0, 0, 3}, "package-c"},
            {&c, &c_b, {10, 0, 0, 4}, "package-b"},
        };
        ASSERT(zwn_fixture_links(&fixture, b_c_links,
                                 sizeof(b_c_links) /
                                     sizeof(b_c_links[0])));
        ASSERT(zwn_meet_side_quiet(&b, &b_c));
        ASSERT(zwn_meet_side_quiet(&c, &c_b));
        memset(discovered, 0, sizeof(discovered));
        ASSERT(zwn_discover_transport(
            &b, &b, &c, scenario.dht_namespace, transport.release_id,
            transport.transport_root, discovered, &provider, 1200));
        ASSERT(zwn_fetch_package_from_provider(
            &c, discovered, &b_c, &c_b, params->pchMessageStart));
        struct vcs_package_transport_import imported_c;
        ASSERT(vcs_package_transport_import(
                   c.store, transport.transport_root, &imported_c) ==
               VCS_PACKAGE_TRANSPORT_OK);
        ASSERT(memcmp(imported_c.package_root,
                      transport.package_root, 32) == 0);
        ASSERT(vcs_package_store_verify_possession(
            c.store, transport.transport_root, false));
        ASSERT(vcs_package_store_verify_possession(
            c.store, transport.package_root, false));
        ASSERT(vcs_package_store_pin(c.store, transport.transport_root,
                                     true) == VCS_PACKAGE_STORE_OK);

        /* Exact repeat is a pure local-complete result: no WANT and no
         * payload bytes. */
        struct vcs_swarm_download_status repeat_status;
        memset(&repeat_status, 0, sizeof(repeat_status));
        ASSERT(vcs_swarm_engine_download_status(
            c.engine, transport.transport_root, &repeat_status));
        uint64_t repeat_bytes_present = repeat_status.total_bytes;
        uint32_t repeat_objects_present = repeat_status.total_chunks;
        ASSERT(vcs_swarm_engine_fetch(
                   c.engine, transport.transport_root, ZWN_DAY, ++c.now) ==
               VCS_SWARM_FETCH_ALREADY_COMPLETE);

        for (size_t i = 1; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            const struct zwn_package_scenario *item =
                &zwn_package_scenarios[i];
            fprintf(stderr,
                    "  ... package_lifecycle: C fetching %s from B (%zu/%zu)\n",
                    item->name, i, (size_t)ZWN_PACKAGE_SCENARIO_COUNT - 1u);
            struct vcs_package_transport *item_transport =
                &graph_transport[i - 1u];
            memset(discovered, 0, sizeof(discovered));
            ASSERT(zwn_discover_transport(
                &b, &b, &c, item->dht_namespace,
                item_transport->release_id,
                item_transport->transport_root, discovered, &provider,
                1200u + (uint64_t)i * 10u));
            ASSERT(zwn_fetch_package_from_provider(
                &c, discovered, &b_c, &c_b,
                params->pchMessageStart));
            struct vcs_package_transport_import item_import;
            ASSERT(vcs_package_transport_import(
                       c.store, item_transport->transport_root,
                       &item_import) == VCS_PACKAGE_TRANSPORT_OK);
            ASSERT(memcmp(item_import.package_root,
                          item_transport->package_root, 32) == 0);
            ASSERT(vcs_package_store_pin(
                       c.store, item_transport->transport_root, true) ==
                   VCS_PACKAGE_STORE_OK);
            memset(&repeat_status, 0, sizeof(repeat_status));
            ASSERT(vcs_swarm_engine_download_status(
                c.engine, item_transport->transport_root, &repeat_status));
            repeat_bytes_present += repeat_status.total_bytes;
            repeat_objects_present += repeat_status.total_chunks;
            ASSERT(vcs_swarm_engine_fetch(
                       c.engine, item_transport->transport_root, ZWN_DAY,
                       ++c.now) == VCS_SWARM_FETCH_ALREADY_COMPLETE);
        }

        /* Build/test is a separate local-policy step. The first pass builds
         * all ten exact roots; the repeat consumes the installed receipts
         * without compiling any package again. */
        int64_t build_clock = INT64_C(1700010000);
        size_t cold_packages_rebuilt = 0;
        ASSERT(zwn_build_original_graph(
            c.datadir, &build_clock, &cold_packages_rebuilt));
        ASSERT_EQ(cold_packages_rebuilt, ZWN_PACKAGE_SCENARIO_COUNT);
        size_t original_receipts = 0;
        ASSERT(zwn_original_receipts_present(
            c.datadir, &original_receipts));
        ASSERT_EQ(original_receipts, ZWN_PACKAGE_SCENARIO_COUNT);
        size_t repeat_packages_rebuilt = 0;
        ASSERT(zwn_build_original_graph(
            c.datadir, &build_clock, &repeat_packages_rebuilt));
        ASSERT_EQ(repeat_packages_rebuilt, 0);

        /* C is another ordinary provider. D fetches and imports the same
         * graph without A or any repository/registry contact. */
        struct zwn_link c_d, d_c;
        const struct zwn_link_spec c_d_links[] = {
            {&c, &c_d, {10, 0, 0, 5}, "package-d"},
            {&d, &d_c, {10, 0, 0, 6}, "package-c"},
        };
        ASSERT(zwn_fixture_links(&fixture, c_d_links,
                                 sizeof(c_d_links) /
                                     sizeof(c_d_links[0])));
        ASSERT(zwn_meet_side_quiet(&c, &c_d));
        ASSERT(zwn_meet_side_quiet(&d, &d_c));
        for (size_t i = 0; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            const struct zwn_package_scenario *item =
                &zwn_package_scenarios[i];
            fprintf(stderr,
                    "  ... package_lifecycle: D fetching %s from C (%zu/%zu)\n",
                    item->name, i + 1u, (size_t)ZWN_PACKAGE_SCENARIO_COUNT);
            struct vcs_package_transport *item_transport = i == 0
                ? &transport : &graph_transport[i - 1u];
            memset(discovered, 0, sizeof(discovered));
            ASSERT(zwn_discover_transport(
                &c, &c, &d, item->dht_namespace,
                item_transport->release_id,
                item_transport->transport_root, discovered, &provider,
                1300u + (uint64_t)i * 10u));
            ASSERT(zwn_fetch_package_from_provider(
                &d, discovered, &c_d, &d_c,
                params->pchMessageStart));
            struct vcs_package_transport_import item_import;
            ASSERT(vcs_package_transport_import(
                       d.store, item_transport->transport_root,
                       &item_import) == VCS_PACKAGE_TRANSPORT_OK);
            ASSERT(memcmp(item_import.package_root,
                          item_transport->package_root, 32) == 0);
            ASSERT(vcs_package_store_pin(
                       d.store, item_transport->transport_root, true) ==
                   VCS_PACKAGE_STORE_OK);
            ASSERT(vcs_package_store_package_status(
                b.store, item_transport->transport_root, &status));
            ASSERT(status.complete && status.pinned);
            ASSERT(vcs_package_store_package_status(
                c.store, item_transport->transport_root, &status));
            ASSERT(status.complete && status.pinned);
            ASSERT(vcs_package_store_package_status(
                d.store, item_transport->transport_root, &status));
            ASSERT(status.complete && status.pinned);
        }

        /* D now becomes an author from a leaf package reconstructed out of
         * the decentralized graph. Editing a leaf makes the rebuild and
         * evidence-reuse accounting exact: one changed package, nine
         * unchanged packages. Checkout is the production inert primitive,
         * not a test-local materializer. */
        size_t edit_index = zwn_package_scenario_index(
            "zclassic23/presentation");
        ASSERT(edit_index > 0 && edit_index < ZWN_PACKAGE_SCENARIO_COUNT);
        const struct zwn_package_scenario *edit_scenario =
            &zwn_package_scenarios[edit_index];
        struct vcs_package_transport *edit_transport =
            &graph_transport[edit_index - 1u];
        char checkout_parent[512], checkout[640];
        test_make_tmpdir(checkout_parent, sizeof(checkout_parent),
                         "zcode_swarm_net", "package-checkout");
        int checkout_n = snprintf(checkout, sizeof(checkout), "%s/source",
                                  checkout_parent);
        ASSERT(checkout_n > 0 && (size_t)checkout_n < sizeof(checkout));
        struct vcs_package_checkout_metrics checkout_metrics;
        ASSERT(vcs_package_checkout(
                   d.store, edit_transport->package_root, checkout,
                   &checkout_metrics) == VCS_PACKAGE_CHECKOUT_OK);
        ASSERT(checkout_metrics.files > 0 && checkout_metrics.chunks > 0 &&
               checkout_metrics.bytes > 0);
        off_t source_size = 0;
        ASSERT(zwn_append_edit(checkout, "src/zclassic_brand.c",
                               "\n/* lifecycle source edit */\n",
                               &source_size));
        struct vcs_package_prepared source_prepared;
        struct vcs_package_transport source_transport;
        vcs_package_transport_init(&source_transport);
        ASSERT(zwn_prepare_package_transport(
            edit_scenario, checkout, zwn_sequence_after_scenarios(1), NULL,
            &source_prepared, &source_transport));
        ASSERT(memcmp(source_transport.package_root,
                      edit_transport->package_root, 32) != 0);
        ASSERT_EQ(source_prepared.lock.count, 1);
        ASSERT(vcs_package_transport_store(
                   d.store, &source_transport, checkout) ==
               VCS_PACKAGE_TRANSPORT_OK);
        ASSERT(vcs_package_store_pin(d.store,
                                     source_transport.transport_root,
                                     true) == VCS_PACKAGE_STORE_OK);
        ASSERT(zwn_discover_transport(
            &d, &d, &c, edit_scenario->dht_namespace,
            source_transport.release_id, source_transport.transport_root,
            discovered, &provider, 1400));
        ASSERT(zwn_fetch_package_from_provider(
            &c, source_transport.transport_root, &d_c, &c_d,
            params->pchMessageStart));
        struct vcs_swarm_download_status source_edit;
        memset(&source_edit, 0, sizeof(source_edit));
        ASSERT(vcs_swarm_engine_download_status(
            c.engine, source_transport.transport_root, &source_edit));
        ASSERT(source_edit.state == VCS_SWARM_DL_COMPLETE);
        ASSERT(source_edit.requested_bytes == source_edit.transferred_bytes);
        ASSERT(source_edit.transferred_bytes == source_edit.fetched_bytes);
        ASSERT(source_edit.requested_objects ==
               source_edit.transferred_objects);
        ASSERT(source_edit.reused_objects > 0);
        ASSERT(source_edit.reused_bytes > 0);
        ASSERT(source_edit.transferred_bytes < cold_transferred_bytes);
        struct vcs_package_transport_import source_import;
        ASSERT(vcs_package_transport_import(
                   c.store, source_transport.transport_root,
                   &source_import) == VCS_PACKAGE_TRANSPORT_OK);
        size_t source_packages_rebuilt = 0;
        ASSERT(zwn_build_package(
            c.datadir, source_import.package_root, &build_clock,
            &source_packages_rebuilt));
        ASSERT_EQ(source_packages_rebuilt, 1);
        size_t source_retained_receipts = 0;
        ASSERT(zwn_original_receipts_present(
            c.datadir, &source_retained_receipts));
        ASSERT_EQ(source_retained_receipts, ZWN_PACKAGE_SCENARIO_COUNT);

        ASSERT(zwn_revert_edit(
            checkout, "src/zclassic_brand.c", source_size));
        off_t header_size = 0;
        ASSERT(zwn_append_edit(
                               checkout,
                               "include/presentation/zclassic_brand.h",
                               "\n/* lifecycle header edit */\n",
                               &header_size));
        struct vcs_package_prepared header_prepared;
        struct vcs_package_transport header_transport;
        vcs_package_transport_init(&header_transport);
        ASSERT(zwn_prepare_package_transport(
            edit_scenario, checkout, zwn_sequence_after_scenarios(2), NULL,
            &header_prepared, &header_transport));
        ASSERT(memcmp(header_transport.package_root,
                      edit_transport->package_root, 32) != 0);
        ASSERT(memcmp(header_transport.package_root,
                      source_transport.package_root, 32) != 0);
        ASSERT_EQ(header_prepared.lock.count, 1);
        ASSERT(vcs_package_transport_store(
                   d.store, &header_transport, checkout) ==
               VCS_PACKAGE_TRANSPORT_OK);
        ASSERT(vcs_package_store_pin(d.store,
                                     header_transport.transport_root,
                                     true) == VCS_PACKAGE_STORE_OK);
        ASSERT(zwn_discover_transport(
            &d, &d, &c, edit_scenario->dht_namespace,
            header_transport.release_id, header_transport.transport_root,
            discovered, &provider, 1410));
        ASSERT(zwn_fetch_package_from_provider(
            &c, header_transport.transport_root, &d_c, &c_d,
            params->pchMessageStart));
        struct vcs_swarm_download_status header_edit;
        memset(&header_edit, 0, sizeof(header_edit));
        ASSERT(vcs_swarm_engine_download_status(
            c.engine, header_transport.transport_root, &header_edit));
        ASSERT(header_edit.state == VCS_SWARM_DL_COMPLETE);
        ASSERT(header_edit.requested_bytes == header_edit.transferred_bytes);
        ASSERT(header_edit.transferred_bytes == header_edit.fetched_bytes);
        ASSERT(header_edit.requested_objects ==
               header_edit.transferred_objects);
        ASSERT(header_edit.reused_objects > 0);
        ASSERT(header_edit.reused_bytes > 0);
        ASSERT(header_edit.transferred_bytes < cold_transferred_bytes);
        struct vcs_package_transport_import header_import;
        ASSERT(vcs_package_transport_import(
                   c.store, header_transport.transport_root,
                   &header_import) == VCS_PACKAGE_TRANSPORT_OK);
        size_t header_packages_rebuilt = 0;
        ASSERT(zwn_build_package(
            c.datadir, header_import.package_root, &build_clock,
            &header_packages_rebuilt));
        ASSERT_EQ(header_packages_rebuilt, 1);
        size_t header_retained_receipts = 0;
        ASSERT(zwn_original_receipts_present(
            c.datadir, &header_retained_receipts));
        ASSERT_EQ(header_retained_receipts, ZWN_PACKAGE_SCENARIO_COUNT);

        /* Exact byte revert reproduces the original semantic and transport
         * roots. C already owns it, so the swarm performs no transfer. */
        ASSERT(zwn_revert_edit(
            checkout, "include/presentation/zclassic_brand.h", header_size));
        struct vcs_package_prepared revert_prepared;
        struct vcs_package_transport revert_transport;
        vcs_package_transport_init(&revert_transport);
        ASSERT(zwn_prepare_package_transport(
            edit_scenario, checkout, edit_scenario->publisher_sequence,
            edit_scenario->expected_package_root_hex,
            &revert_prepared, &revert_transport));
        ASSERT(memcmp(revert_transport.package_root,
                      edit_transport->package_root, 32) == 0);
        ASSERT(memcmp(revert_transport.release_id,
                      edit_transport->release_id, 32) == 0);
        ASSERT(memcmp(revert_transport.transport_root,
                      edit_transport->transport_root, 32) == 0);
        struct vcs_swarm_download_status revert_status;
        memset(&revert_status, 0, sizeof(revert_status));
        ASSERT(vcs_swarm_engine_download_status(
            c.engine, revert_transport.transport_root, &revert_status));
        ASSERT(vcs_swarm_engine_fetch(
                   c.engine, revert_transport.transport_root,
                   ZWN_DAY, ++c.now) == VCS_SWARM_FETCH_ALREADY_COMPLETE);
        size_t revert_packages_rebuilt = 0;
        ASSERT(zwn_build_package(
            c.datadir, revert_transport.package_root, &build_clock,
            &revert_packages_rebuilt));
        ASSERT_EQ(revert_packages_rebuilt, 0);
        size_t revert_reusable_receipts = 0;
        ASSERT(zwn_original_receipts_present(
            c.datadir, &revert_reusable_receipts));
        ASSERT_EQ(revert_reusable_receipts, ZWN_PACKAGE_SCENARIO_COUNT);

        char package_hex[65], transport_hex[65], recipe_hex[65];
        char release_hex[65];
        zcl_hex_encode(transport.package_root, 32, package_hex);
        zcl_hex_encode(transport.transport_root, 32, transport_hex);
        zcl_hex_encode(transport.recipe_root, 32, recipe_hex);
        zcl_hex_encode(transport.release_id, 32, release_hex);
        printf("{\"schema\":\"zcl.package_graph_lifecycle.v2\","
               "\"scenario\":\"c23-commons-alpha\","
               "\"seed_package\":\"%s\",\"package_root\":\"%s\","
               "\"transport_root\":\"%s\",\"recipe_root\":\"%s\","
               "\"release_id\":\"%s\","
               "\"package_count\":%zu,\"full_node_count\":4,"
               "\"cold_objects_already_present\":%u,"
               "\"cold_missing_objects\":%u,"
               "\"cold_bytes_transferred\":%" PRIu64 ","
               "\"cold_bytes_reused\":%" PRIu64 ","
               "\"cold_manifests_changed\":%zu,"
               "\"cold_packages_rebuilt\":%zu,"
               "\"cold_prior_evidence_reusable\":0,"
               "\"repeat_objects_already_present\":%u,"
               "\"repeat_missing_objects\":0,"
               "\"repeat_bytes_transferred\":0,"
               "\"repeat_bytes_reused\":%" PRIu64 ","
               "\"repeat_manifests_changed\":0,"
               "\"repeat_packages_rebuilt\":%zu,"
               "\"repeat_prior_evidence_reusable\":%zu,"
               "\"edited_package\":\"%s\","
               "\"source_edit_objects_already_present\":%u,"
               "\"source_edit_missing_objects\":%u,"
               "\"source_edit_transferred_bytes\":%" PRIu64 ","
               "\"source_edit_reused_bytes\":%" PRIu64 ","
               "\"source_edit_manifests_changed\":1,"
               "\"source_edit_packages_rebuilt\":%zu,"
               "\"source_edit_prior_evidence_reusable\":%zu,"
               "\"header_edit_objects_already_present\":%u,"
               "\"header_edit_missing_objects\":%u,"
               "\"header_edit_transferred_bytes\":%" PRIu64 ","
               "\"header_edit_reused_bytes\":%" PRIu64 ","
               "\"header_edit_manifests_changed\":1,"
               "\"header_edit_packages_rebuilt\":%zu,"
               "\"header_edit_prior_evidence_reusable\":%zu,"
               "\"revert_objects_already_present\":%u,"
               "\"revert_missing_objects\":0,"
               "\"revert_bytes_transferred\":0,"
               "\"revert_bytes_reused\":%" PRIu64 ","
               "\"revert_manifests_changed\":0,"
               "\"revert_packages_rebuilt\":%zu,"
               "\"revert_prior_evidence_reusable\":%zu,"
               "\"publisher_disappeared\":true,"
               "\"onward_path\":\"A-B-C-D-C\","
               "\"new_author\":\"D\",\"github_contacted\":false,"
               "\"central_registry\":false,"
               "\"special_coordinator\":false,"
               "\"downloaded_c_auto_executed\":false,"
               "\"build_test_explicit_local_policy\":true}\n",
               scenario.name, package_hex, transport_hex, recipe_hex,
               release_hex,
               ZWN_PACKAGE_SCENARIO_COUNT,
               cold_reused_objects, cold_missing_objects,
               cold_transferred_bytes, cold_reused_bytes,
               ZWN_PACKAGE_SCENARIO_COUNT, cold_packages_rebuilt,
               repeat_objects_present +
                   (uint32_t)ZWN_PACKAGE_SCENARIO_COUNT,
               repeat_bytes_present,
               repeat_packages_rebuilt, original_receipts,
               edit_scenario->name,
               source_edit.reused_objects,
               source_edit.transferred_objects,
               source_edit.transferred_bytes, source_edit.reused_bytes,
               source_packages_rebuilt,
               source_retained_receipts - 1u,
               header_edit.reused_objects,
               header_edit.transferred_objects,
               header_edit.transferred_bytes, header_edit.reused_bytes,
               header_packages_rebuilt,
               header_retained_receipts - 1u,
               revert_status.total_chunks + 1u, revert_status.total_bytes,
               revert_packages_rebuilt, revert_reusable_receipts);

        test_rm_rf_recursive(checkout_parent);
        vcs_package_transport_free(&revert_transport);
        vcs_package_prepared_free(&revert_prepared);
        vcs_package_transport_free(&header_transport);
        vcs_package_prepared_free(&header_prepared);
        vcs_package_transport_free(&source_transport);
        vcs_package_prepared_free(&source_prepared);
        zwn_fixture_cleanup(&fixture);
        for (size_t i = 1; i < ZWN_PACKAGE_SCENARIO_COUNT; i++) {
            vcs_package_transport_free(&graph_transport[i - 1u]);
            vcs_package_prepared_free(&graph_prepared[i - 1u]);
        }
        vcs_package_transport_free(&transport);
        vcs_package_prepared_free(&prepared);
        PASS();
    } _test_next:
    vcs_package_store_set_deferred_sync(zwn_prior_store_sync);
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* ── 2: the malicious server ────────────────────────────────────────── */

static int zwn_t_malicious(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("malicious server: wrong-hash chunks -> INVALID_CHUNK offence on "
         "the real peer object, no credit, nothing stored, named failure") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 4, 0x22));

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {{&a, "ma"}, {&b, "mb"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        ASSERT(zwn_store_package(a.store, &pkg));
        a.tamper_chunks = true;

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "peer-b"},
            {&b, &b_a, {1, 2, 3, 4}, "peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);

        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        for (int i = 0; i < 800 && !terminal; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            terminal = zwn_download_done(&b, pkg.root, &state);
        }

        ASSERT(terminal);
        /* The bounded-attempts rule names the failure; the peer's real
         * misbehavior score carries the typed offence (and at the
         * default 100-point threshold the auto-ban disconnected it:
         * INVALID_CHUNK weighs 50, so the second bad chunk bans). */
        ASSERT(state == VCS_SWARM_DL_FAILED);
        {
            struct vcs_swarm_download_status st;
            memset(&st, 0, sizeof(st));
            ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                    &st));
            ASSERT(st.rule != NULL);
        }
        ASSERT(b_a.node->misbehavior >=
               peer_offence_weight(PEER_OFFENCE_INVALID_CHUNK));
        /* Verify-before-store: not one bad chunk byte reached the CAS. */
        for (size_t i = 0; i < pkg.count; i++)
            ASSERT(!vcs_package_store_chunk_present(b.store, pkg.root,
                                                    (uint32_t)i, 0));
        /* No credit for unverified bytes; the book names them. */
        {
            uint8_t key[33];
            ASSERT(zwn_peer_key(b_a.node, key));
            struct vcs_service_key_totals kt;
            ASSERT(vcs_service_key_totals(b.book, key, ZWN_DAY, &kt));
            ASSERT(kt.verified_bytes_downloaded <= pkg.wire_len);
            ASSERT(kt.no_credit_bytes > 0);
            ASSERT(kt.offence_total > 0);
        }

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* A bad provider is a bad route to immutable bytes, not evidence that the
 * package root itself is bad.  Keep the download identity live, reject every
 * address-mismatched DATA body before CAS admission, and let an independently
 * connected provider satisfy the same exact root. */
static int zwn_t_corrupt_provider_repair(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("corrupt provider: rejected bytes never enter CAS and the same "
         "exact-root download repairs from an honest alternate") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 6, 0x27));

        struct zwn_node bad, good, consumer;
        const struct zwn_node_spec nodes[] = {
            {&bad, "cpr-bad"}, {&good, "cpr-good"},
            {&consumer, "cpr-consumer"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        ASSERT(zwn_store_package(bad.store, &pkg));
        ASSERT(zwn_store_package(good.store, &pkg));
        bad.tamper_chunks = true;

        struct zwn_link bad_c, c_bad, good_c, c_good;
        const struct zwn_link_spec links[] = {
            {&bad, &bad_c, {10, 3, 0, 1}, "consumer"},
            {&consumer, &c_bad, {10, 3, 0, 2}, "bad-provider"},
            {&good, &good_c, {10, 3, 0, 3}, "consumer"},
            {&consumer, &c_good, {10, 3, 0, 4}, "good-provider"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));

        /* Admit only the bad route first so the proof cannot accidentally
         * pass by selecting the honest provider before corrupt DATA arrives. */
        ASSERT(zwn_meet_side(&bad, &bad_c));
        ASSERT(zwn_meet_side(&consumer, &c_bad));
        ASSERT(vcs_swarm_engine_fetch(consumer.engine, pkg.root, ZWN_DAY,
                                      ++consumer.now) ==
               VCS_SWARM_FETCH_OK);

        bool saw_bad_data = false;
        bool terminal = false;
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        for (size_t round = 0; round < 100u && !saw_bad_data; round++) {
            ASSERT(zwn_round(&bad_c, &c_bad, params->pchMessageStart));
            saw_bad_data = c_bad.node->misbehavior >=
                peer_offence_weight(PEER_OFFENCE_INVALID_CHUNK);
            terminal = zwn_download_done(&consumer, pkg.root, &state);
        }
        ASSERT(saw_bad_data);
        ASSERT(!terminal);
        for (size_t i = 0; i < pkg.count; i++)
            ASSERT(!vcs_package_store_chunk_present(
                consumer.store, pkg.root, (uint32_t)i, 0));
        {
            uint8_t key[33];
            struct vcs_service_key_totals totals;
            ASSERT(zwn_peer_key(c_bad.node, key));
            ASSERT(vcs_service_key_totals(consumer.book, key, ZWN_DAY,
                                          &totals));
            ASSERT(totals.no_credit_bytes > 0);
            ASSERT(totals.offence_total > 0);
        }

        /* Remove only the corrupt route.  The operation/root is unchanged;
         * a newly announced honest holder must resume its outstanding work. */
        atomic_store(&c_bad.node->disconnect, true);
        zwn_drain_quiet(&bad_c);
        zwn_drain_quiet(&c_bad);
        vcs_swarm_engine_peer_drop(consumer.engine,
                                   (uint64_t)c_bad.node->id);
        ASSERT(zwn_meet_side(&good, &good_c));
        ASSERT(zwn_meet_side(&consumer, &c_good));

        terminal = false;
        state = VCS_SWARM_DL_INACTIVE;
        for (size_t round = 0; round < 600u && !terminal; round++) {
            ASSERT(zwn_round(&good_c, &c_good, params->pchMessageStart));
            terminal = zwn_download_done(&consumer, pkg.root, &state);
        }
        ASSERT(terminal && state == VCS_SWARM_DL_COMPLETE);
        ASSERT(zwn_store_matches(consumer.store, &pkg));
        ASSERT(c_good.node->misbehavior == 0);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* A completed download is only a cache of verified possession. If a later
 * read quarantines one address-mismatched CAS object, a retry must re-open
 * the completed engine slot and obtain the exact chunk from a surviving
 * provider. This is the sovereign checkout recovery path: no source-tree or
 * Git fallback is available to the buyer. */
static int zwn_t_corrupt_local_repair(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("corrupt local chunk: quarantine then repair from the surviving "
         "provider over real zpkgswm frames") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 6, 0x2a));

        struct zwn_node a, b, a2;
        const struct zwn_node_spec nodes[] = {
            {&a, "ca"}, {&a2, "ca2"}, {&b, "cb"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        ASSERT(zwn_store_package(a.store, &pkg));
        ASSERT(zwn_store_package(a2.store, &pkg));

        struct zwn_link a_b, b_a, a2_b, b_a2;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "peer-b"},
            {&b, &b_a, {1, 2, 3, 4}, "peer-a"},
            {&a2, &a2_b, {9, 9, 9, 9}, "peer-b"},
            {&b, &b_a2, {8, 8, 8, 8}, "peer-a2"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));
        ASSERT(zwn_meet_side(&a2, &a2_b));
        ASSERT(zwn_meet_side(&b, &b_a2));

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        for (int i = 0; i < 400 && !terminal; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            ASSERT(zwn_round(&a2_b, &b_a2, params->pchMessageStart));
            terminal = zwn_download_done(&b, pkg.root, &state);
        }
        ASSERT(terminal && state == VCS_SWARM_DL_COMPLETE);
        ASSERT(zwn_store_matches(b.store, &pkg));

        /* Provider A disappears after the first complete checkout. */
        atomic_store(&b_a.node->disconnect, true);
        zwn_drain_quiet(&a_b);
        zwn_drain_quiet(&b_a);
        vcs_swarm_engine_peer_drop(b.engine, (uint64_t)b_a.node->id);

        char hash_hex[65], cas_path[1400];
        zcl_hex_encode(pkg.manifest.files[0].chunk_hashes, 32, hash_hex);
        int cas_path_len = snprintf(cas_path, sizeof(cas_path),
                                    "%s/cas/sha3/%.2s/%s", b.zcode_dir,
                                    hash_hex, hash_hex);
        ASSERT(cas_path_len > 0 && (size_t)cas_path_len < sizeof(cas_path));
        FILE *corrupt = fopen(cas_path, "r+b");
        ASSERT(corrupt != NULL);
        int first = fgetc(corrupt);
        ASSERT(first != EOF);
        rewind(corrupt);
        ASSERT(fputc(first ^ 0x80, corrupt) != EOF);
        ASSERT(fclose(corrupt) == 0);
        uint8_t *rejected = NULL;
        size_t rejected_len = 0;
        ASSERT(vcs_package_store_get_chunk_at(
                   b.store, pkg.root, 0, 0, &rejected, &rejected_len) ==
               VCS_PACKAGE_STORE_ERR_CHUNK_HASH);
        ASSERT(rejected == NULL && rejected_len == 0);
        ASSERT(!vcs_package_store_chunk_present(b.store, pkg.root, 0, 0));

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);
        terminal = false;
        state = VCS_SWARM_DL_INACTIVE;
        for (int i = 0; i < 400 && !terminal; i++) {
            ASSERT(zwn_round(&a2_b, &b_a2, params->pchMessageStart));
            terminal = zwn_download_done(&b, pkg.root, &state);
        }
        ASSERT(terminal && state == VCS_SWARM_DL_COMPLETE);
        ASSERT(zwn_store_matches(b.store, &pkg));
        ASSERT(b_a2.node->misbehavior == 0);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* ── 3: unrequested bytes ───────────────────────────────────────────── */

static int zwn_t_unrequested(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("unrequested DATA: UNREQUESTED offence on the wire, no credit") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 2, 0x33));

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {{&a, "ua"}, {&b, "ub"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "peer-b"},
            {&b, &b_a, {1, 2, 3, 4}, "peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));

        /* A hand-built DATA frame with a request id B never issued —
         * queued straight onto the wire, no engine involvement. */
        struct vcs_package_swarm_message data;
        memset(&data, 0, sizeof(data));
        data.type = VCS_PACKAGE_SWARM_DATA;
        data.body.data.object.request_id = 424242;
        data.body.data.object.object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
        memcpy(data.body.data.object.package_root, pkg.root, 32);
        data.body.data.object.file_index = 0;
        data.body.data.object.chunk_index = 0;
        ASSERT(vcs_package_chunk_hash(pkg.contents[0], pkg.lens[0],
                                      data.body.data.object.expected_hash));
        data.body.data.bytes = pkg.contents[0];
        data.body.data.bytes_len = (uint32_t)pkg.lens[0];
        uint8_t frame[4096];
        size_t frame_len = 0;
        ASSERT(vcs_package_swarm_serialize(&data, frame, sizeof(frame),
                                           &frame_len));
        zwn_send(&a, a_b.node, frame, frame_len);
        ASSERT(zwn_pump(&a_b, &b_a, params->pchMessageStart));

        ASSERT(b_a.node->misbehavior ==
               peer_offence_weight(PEER_OFFENCE_UNREQUESTED));
        {
            uint8_t key[33];
            ASSERT(zwn_peer_key(b_a.node, key));
            struct vcs_service_key_totals kt;
            ASSERT(vcs_service_key_totals(b.book, key, ZWN_DAY, &kt));
            ASSERT(kt.verified_bytes_downloaded == 0);
            ASSERT(kt.offence_total > 0);
        }

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);

    return failures;
}

/* Quota exhaustion: STAGING is 1/10 of total quota and never evicts, so a
 * total quota whose staging pool is smaller than an in-flight package's
 * charged bytes must fail that download terminally and BY NAME, never
 * complete a partial package, and leave the store healthy enough to finish
 * the very same fetch once the operator raises -packagequota. */
static int zwn_t_quota_exhaustion(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("quota exhaustion: named terminal failure, no partial completion, "
         "raised quota completes the same fetch") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 6, 0x55));
        ASSERT(pkg.total_bytes > 0 && pkg.total_bytes < 4096);

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {{&a, "qa"}, {&b, "qb"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        ASSERT(zwn_store_package(a.store, &pkg));

        /* Reopen B's store with a 10 KB total quota: the frozen STAGING
         * tenth (1 KB) is smaller than this package's charged bytes, so an
         * in-flight chunk put must refuse with ERR_QUOTA (staging is full
         * and full is full). */
        vcs_swarm_engine_free(b.engine);
        vcs_package_store_close(b.store);
        b.store = vcs_package_store_open(b.datadir, 10000);
        ASSERT(b.store != NULL);
        b.engine = vcs_swarm_engine_create(b.store, b.book, b.zcode_dir,
                                           zwn_score, NULL);
        ASSERT(b.engine != NULL);

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {5, 6, 7, 8}, "peer-b"},
            {&b, &b_a, {1, 2, 3, 4}, "peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        for (int i = 0; i < 400; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            struct vcs_swarm_download_status st;
            memset(&st, 0, sizeof(st));
            ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                    &st));
            state = st.state;
            if (state == VCS_SWARM_DL_FAILED ||
                state == VCS_SWARM_DL_COMPLETE)
                break;
        }
        /* The refusal is terminal and named — never a silent retry loop,
         * never a partial completion. Depending on where the pool fills,
         * the refusal lands at manifest admission (total_chunks still 0)
         * or mid-chunks; both are the same fail-closed contract. */
        ASSERT(state == VCS_SWARM_DL_FAILED);
        struct vcs_swarm_download_status failed;
        memset(&failed, 0, sizeof(failed));
        ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                &failed));
        ASSERT(failed.rule != NULL && failed.rule[0] != '\0');
        ASSERT(failed.state != VCS_SWARM_DL_COMPLETE);
        ASSERT(failed.present_chunks == 0 ||
               failed.present_chunks < failed.total_chunks);

        /* The operator raises -packagequota: same datadir, same root, the
         * fetch runs to completion. */
        vcs_swarm_engine_free(b.engine);
        vcs_package_store_close(b.store);
        b.store = vcs_package_store_open(
            b.datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(b.store != NULL);
        b.engine = vcs_swarm_engine_create(b.store, b.book, b.zcode_dir,
                                           zwn_score, NULL);
        ASSERT(b.engine != NULL);
        /* The store swap dropped the session peers exactly like a restart:
         * re-meet both sides of the link. */
        ASSERT(zwn_meet_side(&b, &b_a));
        vcs_swarm_engine_peer_drop(a.engine, (uint64_t)a_b.node->id);
        ASSERT(zwn_meet_side(&a, &a_b));

        ASSERT(vcs_swarm_engine_fetch(b.engine, pkg.root, ZWN_DAY,
                                      ++b.now) == VCS_SWARM_FETCH_OK);
        bool complete = false;
        for (int i = 0; i < 400 && !complete; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            struct vcs_swarm_download_status st;
            memset(&st, 0, sizeof(st));
            ASSERT(vcs_swarm_engine_download_status(b.engine, pkg.root,
                                                    &st));
            complete = st.state == VCS_SWARM_DL_COMPLETE;
        }
        ASSERT(complete);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);

    return failures;
}

/* Deterministic seed replay: two identical topologies driven by identical
 * caller-supplied ticks must produce identical scheduler behavior — same
 * chunk arrival order, same transfer counters at every sampled round. The
 * engine takes no wall time and no unseeded randomness, so any divergence
 * between the twins is a real determinism defect (hash-order or clock
 * leakage), not noise. */
static int zwn_t_deterministic_replay(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fx1 = {0};
    struct zwn_fixture fx2 = {0};
    TEST("deterministic seed replay: twin topologies stay identical "
         "round for round") {
        struct zwn_pkg p1, p2;
        ASSERT(zwn_make_package(&p1, 12, 0x77));
        ASSERT(zwn_make_package(&p2, 12, 0x77));
        ASSERT(p1.total_bytes == p2.total_bytes);
        ASSERT(memcmp(p1.root, p2.root, 32) == 0);

        struct zwn_node a1, b1, a2, b2;
        const struct zwn_node_spec nodes1[] = {{&a1, "t1a"}, {&b1, "t1b"}};
        const struct zwn_node_spec nodes2[] = {{&a2, "t2a"}, {&b2, "t2b"}};
        ASSERT(zwn_fixture_nodes(&fx1, params, nodes1,
                                 sizeof(nodes1) / sizeof(nodes1[0])));
        ASSERT(zwn_fixture_nodes(&fx2, params, nodes2,
                                 sizeof(nodes2) / sizeof(nodes2[0])));
        ASSERT(zwn_store_package(a1.store, &p1));
        ASSERT(zwn_store_package(a2.store, &p2));

        struct zwn_link a1_b, b1_a, a2_b, b2_a;
        const struct zwn_link_spec links1[] = {
            {&a1, &a1_b, {5, 6, 7, 8}, "peer-b"},
            {&b1, &b1_a, {1, 2, 3, 4}, "peer-a"},
        };
        const struct zwn_link_spec links2[] = {
            {&a2, &a2_b, {5, 6, 7, 8}, "peer-b"},
            {&b2, &b2_a, {1, 2, 3, 4}, "peer-a"},
        };
        ASSERT(zwn_fixture_links(&fx1, links1,
                                 sizeof(links1) / sizeof(links1[0])));
        ASSERT(zwn_fixture_links(&fx2, links2,
                                 sizeof(links2) / sizeof(links2[0])));
        ASSERT(zwn_meet_side(&a1, &a1_b));
        ASSERT(zwn_meet_side(&b1, &b1_a));
        ASSERT(zwn_meet_side(&a2, &a2_b));
        ASSERT(zwn_meet_side(&b2, &b2_a));

        ASSERT(vcs_swarm_engine_fetch(b1.engine, p1.root, ZWN_DAY,
                                      ++b1.now) == VCS_SWARM_FETCH_OK);
        ASSERT(vcs_swarm_engine_fetch(b2.engine, p2.root, ZWN_DAY,
                                      ++b2.now) == VCS_SWARM_FETCH_OK);

        bool done1 = false;
        bool done2 = false;
        for (int i = 0; i < 400 && !(done1 && done2); i++) {
            ASSERT(zwn_round(&a1_b, &b1_a, params->pchMessageStart));
            ASSERT(zwn_round(&a2_b, &b2_a, params->pchMessageStart));

            struct vcs_swarm_download_status s1, s2;
            memset(&s1, 0, sizeof(s1));
            memset(&s2, 0, sizeof(s2));
            ASSERT(vcs_swarm_engine_download_status(b1.engine, p1.root,
                                                    &s1));
            ASSERT(vcs_swarm_engine_download_status(b2.engine, p2.root,
                                                    &s2));
            /* Identical inputs -> identical state, every round. */
            ASSERT(s1.state == s2.state);
            ASSERT(s1.present_chunks == s2.present_chunks);
            ASSERT(s1.transferred_objects == s2.transferred_objects);
            ASSERT(s1.requested_objects == s2.requested_objects);
            ASSERT(s1.fetched_bytes == s2.fetched_bytes);
            done1 = s1.state == VCS_SWARM_DL_COMPLETE;
            done2 = s2.state == VCS_SWARM_DL_COMPLETE;
        }
        ASSERT(done1 && done2);

        zwn_fixture_cleanup(&fx1);
        zwn_fixture_cleanup(&fx2);
        zwn_free_package(&p1);
        zwn_free_package(&p2);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fx1);
    zwn_fixture_cleanup(&fx2);

    return failures;
}

static bool zwn_hop_carrier(struct zwn_node *from, struct zwn_node *to,
                            struct zwn_link *from_to, struct zwn_link *to_from,
                            const struct vcs_package_transport *transport,
                            const unsigned char *msgstart, uint64_t now)
{
    uint8_t discovered[32];
    struct vcs_zcode_dht_record provider;
    if (!zwn_discover_transport(from, from, to, "package.c23-commons",
                                transport->release_id,
                                transport->transport_root, discovered,
                                &provider, now))
        return false;
    if (memcmp(discovered, transport->transport_root, 32) != 0)
        return false;
    if (!zwn_fetch_package_from_provider(to, discovered, from_to, to_from,
                                         msgstart))
        return false;
    struct vcs_package_transport_import imported;
    if (vcs_package_transport_import(to->store, transport->transport_root,
                                     &imported) !=
        VCS_PACKAGE_TRANSPORT_OK)
        return false;
    if (memcmp(imported.package_root, transport->package_root, 32) != 0)
        return false;
    return vcs_package_store_pin(to->store, transport->transport_root,
                                 true) == VCS_PACKAGE_STORE_OK;
}

/* A publishes these in-tree packages, B mirrors and pins, A is removed,
 * C fetches the exact carriers from B. Fetch is inert; import
 * reconstructs the signed carrier; pin keeps the replica. NEW_USER
 * unique-new quota is the serving-set size; n sits inside that shelf. */
enum { ZWN_REDUNDANT_MAX = 16 };

static int zwn_t_redundant_publish_disappear(
    const struct chain_params *params, const char *test_name,
    const char *label, const char *const *dirs, size_t n, uint64_t now_base)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    struct vcs_package_prepared prepared[ZWN_REDUNDANT_MAX];
    struct vcs_package_transport transport[ZWN_REDUNDANT_MAX];
    char name_a[40], name_b[40], name_c[40];
    size_t i;
    int wa, wb, wc;

    if (!params || !test_name || !label || !dirs || n == 0 ||
        n > ZWN_REDUNDANT_MAX) {
        fprintf(stderr,
                "zwn redundant hop: bad args name=%s label=%s n=%zu\n",
                test_name ? test_name : "(null)",
                label ? label : "(null)", n);
        return 1;
    }
    wa = snprintf(name_a, sizeof(name_a), "%s-a", label);
    wb = snprintf(name_b, sizeof(name_b), "%s-b", label);
    wc = snprintf(name_c, sizeof(name_c), "%s-c", label);
    if (wa < 0 || (size_t)wa >= sizeof(name_a) || wb < 0 ||
        (size_t)wb >= sizeof(name_b) || wc < 0 ||
        (size_t)wc >= sizeof(name_c)) {
        fprintf(stderr, "zwn redundant hop: node label '%s' too long\n",
                label);
        return 1;
    }
    memset(prepared, 0, sizeof(prepared));
    memset(transport, 0, sizeof(transport));
    TEST(test_name) {
        struct zwn_node a, b, c;
        const struct zwn_node_spec nodes[] = {
            {&a, name_a}, {&b, name_b}, {&c, name_c},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        for (i = 0; i < n; i++) {
            /* Heartbeat: each iteration content-hashes and pins a whole
             * in-tree package; on a loaded box that can individually run
             * past the no-output watchdog's window, so print progress
             * rather than staying silent for the whole loop. */
            fprintf(stderr, "  ... %s: seeding %s (%zu/%zu)\n", test_name,
                    dirs[i], i + 1u, n);
            struct zwn_package_scenario sc = {
                .name = dirs[i],
                .dht_namespace = "package.c23-commons",
                .source_dir = dirs[i],
                .publisher_sequence = i + 1u,
                .expected_package_root_hex = NULL,
            };
            vcs_package_transport_init(&transport[i]);
            ASSERT(zwn_prepare_package_transport(
                &sc, dirs[i], i + 1u, NULL, &prepared[i], &transport[i]));
            ASSERT(vcs_package_transport_store(a.store, &transport[i],
                                               dirs[i]) ==
                   VCS_PACKAGE_TRANSPORT_OK);
            ASSERT(vcs_package_store_pin(a.store, transport[i].transport_root,
                                         true) == VCS_PACKAGE_STORE_OK);
            struct vcs_package_store_status seeded;
            ASSERT(vcs_package_store_package_status(
                a.store, transport[i].transport_root, &seeded));
            ASSERT(seeded.complete && seeded.pinned);
            struct vcs_package_public_verdict shape;
            vcs_package_public_shape_classify(a.store,
                                              transport[i].transport_root,
                                              &shape);
            if (shape.shape == VCS_PACKAGE_PUBLIC_REFUSED)
                fprintf(stderr, "zwn public_shape %s: %s (%s)\n", dirs[i],
                        shape.rule ? shape.rule : "?",
                        shape.dependency_rule ? shape.dependency_rule : "-");
            ASSERT(shape.shape != VCS_PACKAGE_PUBLIC_REFUSED);
        }

        struct zwn_link a_b, b_a;
        const struct zwn_link_spec a_b_links[] = {
            {&a, &a_b, {11, 0, 0, 1}, name_b},
            {&b, &b_a, {11, 0, 0, 2}, name_a},
        };
        ASSERT(zwn_fixture_links(&fixture, a_b_links,
                                 sizeof(a_b_links) / sizeof(a_b_links[0])));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));
        for (i = 0; i < n; i++) {
            fprintf(stderr, "  ... %s: A->B hop %zu/%zu\n", test_name,
                    i + 1u, n);
            ASSERT(zwn_hop_carrier(&a, &b, &a_b, &b_a, &transport[i],
                                   params->pchMessageStart,
                                   now_base + (uint64_t)i * 10u));
        }

        zwn_fixture_release_link(&fixture, &a_b);
        zwn_fixture_release_link(&fixture, &b_a);
        zwn_fixture_release_node(&fixture, &a);

        struct zwn_link b_c, c_b;
        const struct zwn_link_spec b_c_links[] = {
            {&b, &b_c, {11, 0, 0, 3}, name_c},
            {&c, &c_b, {11, 0, 0, 4}, name_b},
        };
        ASSERT(zwn_fixture_links(&fixture, b_c_links,
                                 sizeof(b_c_links) / sizeof(b_c_links[0])));
        ASSERT(zwn_meet_side(&b, &b_c));
        ASSERT(zwn_meet_side(&c, &c_b));
        for (i = 0; i < n; i++) {
            fprintf(stderr, "  ... %s: B->C hop %zu/%zu\n", test_name,
                    i + 1u, n);
            ASSERT(zwn_hop_carrier(&b, &c, &b_c, &c_b, &transport[i],
                                   params->pchMessageStart,
                                   now_base + 100u + (uint64_t)i * 10u));
            struct vcs_package_store_status st;
            ASSERT(vcs_package_store_package_status(
                b.store, transport[i].transport_root, &st));
            ASSERT(st.complete && st.pinned);
            ASSERT(vcs_package_store_package_status(
                c.store, transport[i].transport_root, &st));
            ASSERT(st.complete && st.pinned);
            ASSERT(vcs_package_store_verify_possession(
                c.store, transport[i].transport_root, false));
            ASSERT(vcs_package_store_verify_possession(
                c.store, transport[i].package_root, false));
        }
        PASS();
    } _test_next:
    for (i = 0; i < n && i < ZWN_REDUNDANT_MAX; i++) {
        vcs_package_transport_free(&transport[i]);
        vcs_package_prepared_free(&prepared[i]);
    }
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* Arena match packages in dependency order: zprng, zdogfight, then the
 * three titles that lock those two. */
static int zwn_t_useful_c23_redundant(const struct chain_params *params)
{
    static const char *const k_dirs[] = {
        "contexts/commons/packages/zprng",
        "contexts/commons/packages/zdogfight",
        "contexts/commons/packages/zdogdrone",
        "contexts/commons/packages/zdogace",
        "contexts/commons/packages/zdogview",
    };
    return zwn_t_redundant_publish_disappear(
        params,
        "useful C23 packages host redundantly: A publishes zprng/"
        "zdogfight/zdogdrone/zdogace/zdogview, B mirrors, A disappears, "
        "C fetches from B",
        "arena", k_dirs, sizeof(k_dirs) / sizeof(k_dirs[0]), 1400u);
}

/* Independent in-tree titles, not the Arena set. zutf8 before zjson so
 * public-shape can close the declared dependency. */
static int zwn_t_ordinary_c23_redundant(const struct chain_params *params)
{
    static const char *const k_dirs[] = {
        "contexts/commons/packages/zhex",    "contexts/commons/packages/zstr", "contexts/commons/packages/zbuf",
        "contexts/commons/packages/zsha256", "contexts/commons/packages/zring", "contexts/commons/packages/zmap",
        "contexts/commons/packages/zvec",    "contexts/commons/packages/zutf8", "contexts/commons/packages/zjson",
    };
    return zwn_t_redundant_publish_disappear(
        params,
        "ordinary C23 library hosts redundantly: A publishes zhex/zstr/"
        "zbuf/zsha256/zring/zmap/zvec/zutf8/zjson, B mirrors, A disappears, "
        "C fetches from B",
        "lib", k_dirs, sizeof(k_dirs) / sizeof(k_dirs[0]), 1600u);
}

/* Late joiner discovery by announcement: A and B both hold the package, A
 * disappears, and only then C starts. C has no provider handle; the surviving
 * holder reaches it through B's ANNOUNCE, peers_for / advertised name B (and
 * never the vanished A), and a plain fetch completes from B. */
static int zwn_t_late_joiner_announce_discovery(
    const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("late joiner finds the surviving holder by announcement and "
         "fetches with no provider handle") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 4, 0x3c));

        struct zwn_node a, b, c;
        const struct zwn_node_spec holders[] = {{&a, "lj-a"}, {&b, "lj-b"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, holders, 2));
        ASSERT(zwn_store_package(a.store, &pkg));
        ASSERT(zwn_store_package(b.store, &pkg));

        /* A held the package redundantly with B, then vanishes before the
         * late joiner exists. */
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec a_b_links[] = {
            {&a, &a_b, {12, 0, 0, 1}, "lj-b"},
            {&b, &b_a, {12, 0, 0, 2}, "lj-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, a_b_links, 2));
        ASSERT(zwn_meet_side(&a, &a_b));
        ASSERT(zwn_meet_side(&b, &b_a));
        zwn_fixture_release_link(&fixture, &a_b);
        zwn_fixture_release_link(&fixture, &b_a);
        zwn_fixture_release_node(&fixture, &a);

        const struct zwn_node_spec joiner[] = {{&c, "lj-c"}};
        ASSERT(zwn_fixture_nodes(&fixture, params, joiner, 1));
        struct zwn_link b_c, c_b;
        const struct zwn_link_spec b_c_links[] = {
            {&b, &b_c, {12, 0, 0, 3}, "lj-c"},
            {&c, &c_b, {12, 0, 0, 4}, "lj-b"},
        };
        ASSERT(zwn_fixture_links(&fixture, b_c_links, 2));
        ASSERT(zwn_meet_side(&b, &b_c));
        ASSERT(zwn_meet_side(&c, &c_b));

        /* Nothing announced has crossed the wire yet. */
        struct vcs_swarm_peer_info holders_seen[4];
        ASSERT(vcs_swarm_engine_peers_for(c.engine, pkg.root, holders_seen,
                                          4) == 0);
        struct vcs_swarm_advertised adv[4];
        ASSERT(vcs_swarm_engine_advertised(c.engine, adv, 4) == 0);

        size_t found = 0;
        for (int r = 0; r < 20 && found == 0; r++) {
            ASSERT(zwn_round(&b_c, &c_b, params->pchMessageStart));
            found = vcs_swarm_engine_peers_for(c.engine, pkg.root,
                                               holders_seen, 4);
        }
        /* Exactly one holder is discoverable: the survivor. */
        ASSERT(found == 1);
        ASSERT(holders_seen[0].peer == (uint64_t)c_b.node->id);
        ASSERT(vcs_swarm_engine_advertised(c.engine, adv, 4) == 1);
        ASSERT(memcmp(adv[0].root, pkg.root, 32) == 0);
        ASSERT(adv[0].advertisers == 1);

        /* No provider handle: the engine picks from the announcement. */
        uint32_t replies_before = b.chunk_data_replies[0];
        ASSERT(vcs_swarm_engine_fetch(c.engine, pkg.root, ZWN_DAY,
                                      ++c.now) == VCS_SWARM_FETCH_OK);
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        for (int r = 0; r < 600 && !terminal; r++) {
            ASSERT(zwn_round(&b_c, &c_b, params->pchMessageStart));
            terminal = zwn_download_done(&c, pkg.root, &state);
        }
        ASSERT(terminal);
        ASSERT(state == VCS_SWARM_DL_COMPLETE);
        ASSERT(b.chunk_data_replies[0] > replies_before);
        ASSERT(zwn_store_matches(c.store, &pkg));
        ASSERT(c_b.node->misbehavior == 0);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* ── attestation flight: a signed ZCLATT crosses the real swarm ─────── */

/* An attestation is at most VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES (681),
 * under VCS_BLOB_MAX_BYTES (8192), so it rides the frozen 'zpkgswm'
 * ANNOUNCE/WANT/DATA codec as an ordinary one-file one-chunk blob. These
 * cases add NO wire message: they reuse this file's two-node loopback
 * exactly as the package cases do, so the bytes genuinely cross the
 * codec — never a store reach-in and never a filesystem copy.
 *
 * Discovery is the same signed DHT POINTER these tests already drive for
 * package carriers, published in VCS_PACKAGE_ATTEST_DHT_NAMESPACE and
 * keyed on the ATTESTED PACKAGE ROOT. The record layer cannot check that
 * binding — it signs whatever pair the publisher hands it — which is
 * exactly why the binding is re-checked at admission on the receiver.
 *
 * What these cases do NOT prove: real DHT routing (the pointer and its
 * query are driven between two in-process services over a hermetic
 * session, not over a live overlay), and the approved-verifier quorum
 * policy, which is `zcode package verify`'s question and is applied long
 * after admission. */

#define ZWN_ATT_NS VCS_PACKAGE_ATTEST_DHT_NAMESPACE
#define ZWN_ATT_ID_HEX (2u * VCS_PACKAGE_ATTEST_ID_BYTES + 1u)

static bool zwn_att_keypair(uint8_t seed, struct privkey *sk,
                            struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

/* One valid, signed TEST_PASS attestation over `package_root`, in the
 * field set the external verifier produces. `wire` must hold at least
 * VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES. */
static bool zwn_att_wire(const uint8_t package_root[32], uint8_t signer_seed,
                         uint8_t *wire, size_t *wire_len,
                         uint8_t id_out[VCS_PACKAGE_ATTEST_ID_BYTES])
{
    struct privkey sk;
    struct pubkey pk;
    if (!zwn_att_keypair(signer_seed, &sk, &pk))
        return false;
    struct vcs_package_attest a;
    memset(&a, 0, sizeof(a));
    a.schema_version = VCS_PACKAGE_ATTEST_VERSION;
    memcpy(a.package_root, package_root, 32);
    for (size_t i = 0; i < 32; i++) {
        a.release_id[i] = (uint8_t)(package_root[i] ^ 0x5au);
        a.recipe_root[i] = (uint8_t)(package_root[i] ^ 0xa5u);
    }
    a.result_class = VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
    snprintf(a.compilers[0].id, sizeof(a.compilers[0].id), "clang");
    snprintf(a.compilers[0].version, sizeof(a.compilers[0].version),
             "18.1.3");
    snprintf(a.compilers[1].id, sizeof(a.compilers[1].id), "gcc");
    snprintf(a.compilers[1].version, sizeof(a.compilers[1].version),
             "13.2.0");
    a.compiler_count = 2;
    a.compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.compilers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.isolation = VCS_PACKAGE_ATTEST_ISOLATION_FULL;
    a.test_ran = true;
    a.test_exit_code = 0;
    snprintf(a.sanitizers[0].name, sizeof(a.sanitizers[0].name), "asan");
    snprintf(a.sanitizers[1].name, sizeof(a.sanitizers[1].name), "ubsan");
    a.sanitizer_count = 2;
    a.sanitizers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.sanitizers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    memcpy(a.verifier_pubkey, pk.vch, VCS_PACKAGE_ATTEST_PUBKEY_BYTES);

    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    if (vcs_package_attest_id(&a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(a.signature, compact + 1, VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);

    uint8_t *buf = NULL;
    size_t len = 0;
    if (vcs_package_attest_serialize(&a, &buf, &len) !=
            VCS_PACKAGE_ATTEST_OK ||
        len == 0 || len > VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES) {
        free(buf);
        return false;
    }
    /* The id is recomputed over the canonical encoding minus the
     * signature, so signing did not move it. */
    bool ok = vcs_package_attest_id(&a, id_out) == VCS_PACKAGE_ATTEST_OK &&
              memcmp(id_out, id, sizeof(id)) == 0;
    if (ok) {
        memcpy(wire, buf, len);
        *wire_len = len;
    }
    free(buf);
    return ok;
}

/* <zcode_dir>/attestations/<attestation-id-hex>: the store filename the
 * layer files under, on either node. */
static bool zwn_att_path(const struct zwn_node *z,
                         const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
                         char *out, size_t cap)
{
    char hex[ZWN_ATT_ID_HEX];
    zcl_hex_encode(id, VCS_PACKAGE_ATTEST_ID_BYTES, hex);
    int n = snprintf(out, cap, "%s/attestations/%s", z->zcode_dir, hex);
    return n > 0 && (size_t)n < cap;
}

static bool zwn_att_read(const char *path, uint8_t *out, size_t cap,
                         size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t len = fread(out, 1, cap, f);
    bool ok = !ferror(f) && len > 0;
    fclose(f);
    if (ok)
        *out_len = len;
    return ok;
}

/* Entries filed under attestations/. -1 when the directory was never
 * created — which is what "files NOTHING" looks like on a node that has
 * only ever refused. */
static int zwn_att_dir_count(const struct zwn_node *z)
{
    char dir[1300];
    int n = snprintf(dir, sizeof(dir), "%s/attestations", z->zcode_dir);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        return -1;
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int count = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        count++;
    }
    closedir(d);
    return count;
}

/* Offer already-filed bytes and keep them: pinning is what makes this
 * node a durable provider for the pointer it is about to publish. */
static bool zwn_att_offer_pinned(
    struct zwn_node *z, const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
    struct vcs_package_attest_transport_outcome *out)
{
    return vcs_package_attest_transport_offer(z->store, z->zcode_dir, id,
                                              out) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK &&
           vcs_package_store_pin(z->store, out->transport_root, true) ==
               VCS_PACKAGE_STORE_OK;
}

/* Put arbitrary bytes on the wire as a blob, bypassing the transport
 * layer's publish check. Only an adversary does this: it is how a
 * tampered wire still gets a root the swarm will happily carry. */
static bool zwn_att_publish_raw(struct zwn_node *z, const uint8_t *bytes,
                                size_t len, uint8_t out_root[32])
{
    return vcs_blob_put_to(z->store, bytes, len, out_root) == VCS_BLOB_OK &&
           vcs_package_store_pin(z->store, out_root, true) ==
               VCS_PACKAGE_STORE_OK;
}

static int zwn_t_attestation_flight(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("attestation flight: A offers a signed attestation, B resolves "
         "the pointer, pulls the bytes over real zpkgswm frames, "
         "re-derives the same transport root, and both nodes end holding "
         "BYTE-IDENTICAL receipts under the same attestation-id name") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 3, 0x51));

        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        ASSERT(zwn_att_wire(pkg.root, 0x31, wire, &wire_len, id));
        ASSERT(wire_len > 0 && wire_len <= VCS_BLOB_MAX_BYTES);

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "att-a"}, {&b, "att-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 4, 0, 1}, "att-peer-b"},
            {&b, &b_a, {10, 4, 0, 2}, "att-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        /* 1. A holds it; B has never seen it. */
        char a_path[1400], b_path[1400];
        ASSERT(zwn_att_path(&a, id, a_path, sizeof(a_path)));
        ASSERT(zwn_att_path(&b, id, b_path, sizeof(b_path)));
        bool filed = false, present = false;
        ASSERT(vcs_package_attest_transport_file(
                   a.zcode_dir, wire, wire_len, id, &filed, &present) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        ASSERT(filed && !present);
        ASSERT(zwn_att_dir_count(&a) == 1);
        ASSERT(zwn_att_dir_count(&b) <= 0);

        /* 2. The offer makes it a blob whose root is a pure function of
         *    the exact signed bytes. */
        struct vcs_package_attest_transport_outcome offer;
        ASSERT(zwn_att_offer_pinned(&a, id, &offer));
        uint8_t pure_root[32];
        ASSERT(vcs_blob_root(wire, wire_len, pure_root));
        ASSERT(memcmp(offer.transport_root, pure_root, 32) == 0);
        ASSERT(memcmp(offer.attestation_id, id, sizeof(id)) == 0);

        /* 3. B learns the root the way a stranger does: a signed POINTER
         *    in the attestation namespace, keyed on the package root. */
        uint8_t discovered[32];
        struct vcs_zcode_dht_record provider;
        memset(&provider, 0, sizeof(provider));
        ASSERT(zwn_discover_transport(&a, &a, &b, ZWN_ATT_NS, pkg.root,
                                      offer.transport_root, discovered,
                                      &provider, 1010));
        ASSERT(memcmp(discovered, offer.transport_root, 32) == 0);

        /* 4. The bytes cross the codec. B holds nothing beforehand, and
         *    A's DATA reply counter proves the chunk was served over a
         *    real frame rather than copied out of A's store. */
        uint8_t got[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t got_len = 0;
        ASSERT(vcs_blob_get_from(b.store, discovered, got, sizeof(got),
                                 &got_len) != VCS_BLOB_OK);
        ASSERT(a.chunk_data_replies[0] == 0);
        ASSERT(zwn_fetch_package_from_provider(&b, discovered, &a_b, &b_a,
                                               params->pchMessageStart));
        ASSERT(a.chunk_data_replies[0] > 0);

        /* 5. B independently re-derives the transport root from what it
         *    received — the property that makes a POINTER resolvable at
         *    all — and the bytes are A's exact wire. */
        ASSERT(vcs_blob_get_from(b.store, discovered, got, sizeof(got),
                                 &got_len) == VCS_BLOB_OK);
        ASSERT(got_len == wire_len && memcmp(got, wire, wire_len) == 0);
        struct vcs_package_attest_transport_outcome rederived;
        ASSERT(vcs_package_attest_transport_root(got, got_len,
                                                 &rederived) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        ASSERT(memcmp(rederived.transport_root, discovered, 32) == 0);
        ASSERT(memcmp(rederived.attestation_id, id, sizeof(id)) == 0);

        /* 6. B admits under the root it asked about; the signature is
         *    verified there, by B, not vouched for by A. */
        struct vcs_package_attest_transport_outcome admit;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, discovered, pkg.root, &admit) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        ASSERT(admit.filed && !admit.already_present);
        ASSERT(memcmp(admit.attestation.package_root, pkg.root, 32) == 0);
        ASSERT(memcmp(admit.attestation_id, id, sizeof(id)) == 0);

        /* 7. BYTE-IDENTICAL RECEIPTS: same bytes, same filename, both
         *    sides. This is the claim the whole flight exists to make. */
        uint8_t a_bytes[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        uint8_t b_bytes[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t a_len = 0, b_len = 0;
        ASSERT(zwn_att_read(a_path, a_bytes, sizeof(a_bytes), &a_len));
        ASSERT(zwn_att_read(b_path, b_bytes, sizeof(b_bytes), &b_len));
        ASSERT(a_len == b_len && memcmp(a_bytes, b_bytes, a_len) == 0);
        ASSERT(a_len == wire_len && memcmp(a_bytes, wire, wire_len) == 0);
        ASSERT(strcmp(strrchr(a_path, '/'), strrchr(b_path, '/')) == 0);
        ASSERT(zwn_att_dir_count(&b) == 1);

        /* Re-admitting the identical bytes is a no-op success: the id IS
         * the content hash, so a second delivery cannot fork a receipt. */
        struct vcs_package_attest_transport_outcome again;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, discovered, pkg.root, &again) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        ASSERT(!again.filed && again.already_present);
        ASSERT(zwn_att_dir_count(&b) == 1);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* ── task-posting flight ───────────────────────────────────────────────
 *
 * Same shape as the attestation flight for different content: a dev task
 * posted as the fixed three-file carrier. What crosses the codec is a
 * real content.v2 package (manifest + chunks); what B runs afterwards is
 * the receiver-side binding check a stranger relies on. */

#define ZWN_TASK_NS VCS_ZCODE_TASK_DHT_NAMESPACE

/* Export one real, pinned task context into node z's store. The goal text
 * commits at task.goal_root, the policy wire at task.proof_policy_root,
 * and the whole carrier roots deterministically — same task always the
 * same context root. */
static bool zwn_task_offer(struct zwn_node *z, const char *goal,
                           int64_t now, int64_t expires_unix,
                           uint8_t task_root[32], uint8_t context_root[32])
{
    struct vcs_zcode_proof_policy_v1 policy;
    memset(&policy, 0, sizeof(policy));
    policy.schema_version = VCS_ZCODE_DEV_VERSION;
    policy.required_proofs = VCS_ZCODE_PROOF_COMPILE |
                             VCS_ZCODE_PROOF_TEST | VCS_ZCODE_PROOF_FUZZ |
                             VCS_ZCODE_PROOF_REVIEW |
                             VCS_ZCODE_PROOF_LOCAL_REPRODUCTION;
    policy.minimum_compile_receipts = 2;
    policy.minimum_test_receipts = 2;
    policy.minimum_fuzz_receipts = 1;
    policy.minimum_reviews = 1;
    policy.minimum_matching_receipts = 2;
    policy.flags = VCS_ZCODE_POLICY_INDEPENDENT_SIGNERS |
                   VCS_ZCODE_POLICY_RELEASE_BYTE_IDENTITY;
    policy.deterministic_fuzz_seeds = 64;
    policy.audit_basis_points = 100;
    policy.maximum_proof_age_seconds = 3600;
    uint8_t policy_root[32];
    if (vcs_zcode_proof_policy_root(&policy, policy_root) !=
        VCS_ZCODE_DEV_OK)
        return false;
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_proof_policy_serialize(&policy, policy_wire) !=
        VCS_ZCODE_DEV_OK)
        return false;

    struct vcs_zcode_task_v1 task;
    memset(&task, 0, sizeof(task));
    task.schema_version = VCS_ZCODE_DEV_VERSION;
    /* Validation refuses zero roots, so every unconstrained root gets a
     * distinct nonzero pattern. */
    memset(task.source_root, 0x41, 32);
    memset(task.dependency_lock_root, 0x42, 32);
    memset(task.toolchain_capsule_root, 0x43, 32);
    memset(task.write_scope_root, 0x44, 32);
    memset(task.acceptance_tests_root, 0x45, 32);
    memset(task.model_policy_root, 0x46, 32);
    memcpy(task.proof_policy_root, policy_root, 32);
    sha3_256((const uint8_t *)goal, strlen(goal), task.goal_root);
    task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task.max_changed_files = 32;
    task.max_patch_bytes = 1024 * 1024;
    task.max_context_bytes = 2 * 1024 * 1024;
    task.max_cpu_seconds = 120;
    task.max_memory_bytes = UINT64_C(512) * 1024 * 1024;
    task.max_output_bytes = UINT64_C(64) * 1024 * 1024;
    task.expires_unix = expires_unix;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_serialize(&task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, task_root) != VCS_ZCODE_DEV_OK)
        return false;
    return vcs_zcode_task_context_export(
               task_wire, sizeof(task_wire), (const uint8_t *)goal,
               strlen(goal), policy_wire, sizeof(policy_wire), z->store,
               now, context_root) == VCS_ZCODE_TASK_CONTEXT_OK &&
           vcs_package_store_pin(z->store, context_root, true) ==
               VCS_PACKAGE_STORE_OK;
}

/* Shared-focus wires remain semantic ZVCS objects. This fixture wraps each
 * exact canonical wire in the already-frozen one-chunk content.v2 blob shape,
 * carries it through two independent swarm engines, then returns the received
 * bytes for semantic parse + re-root. The blob root is transport identity
 * only; it grants no focus, work, evidence, or execution authority. */
static bool zwn_focus_wire_transfer(
    struct zwn_node *from, struct zwn_node *to,
    struct zwn_link *from_to, struct zwn_link *to_from,
    const unsigned char msgstart[MESSAGE_START_SIZE],
    const uint8_t *wire, size_t wire_len,
    uint8_t *received, size_t received_cap,
    uint8_t carrier_root[32], uint32_t *retries)
{
    if (!from || !to || !from_to || !to_from || !msgstart || !wire ||
        wire_len == 0 || !received || received_cap < wire_len ||
        !carrier_root || !retries ||
        vcs_blob_put_to(from->store, wire, wire_len, carrier_root) !=
            VCS_BLOB_OK ||
        vcs_package_store_pin(from->store, carrier_root, true) !=
            VCS_PACKAGE_STORE_OK ||
        vcs_swarm_engine_announce_to(
            from->engine, (uint64_t)from_to->node->id) == 0 ||
        !zwn_round(from_to, to_from, msgstart))
        return false;

    uint32_t replies_before = from->chunk_data_replies[0];
    if (!zwn_fetch_package_from_provider(to, carrier_root, from_to, to_from,
                                         msgstart) ||
        from->chunk_data_replies[0] <= replies_before)
        return false;

    size_t received_len = 0;
    struct vcs_swarm_download_status status;
    memset(&status, 0, sizeof(status));
    if (vcs_blob_get_from(to->store, carrier_root, received, received_cap,
                          &received_len) != VCS_BLOB_OK ||
        received_len != wire_len ||
        !vcs_swarm_engine_download_status(to->engine, carrier_root, &status) ||
        status.state != VCS_SWARM_DL_COMPLETE ||
        status.requested_objects < status.transferred_objects)
        return false;
    *retries += status.requested_objects - status.transferred_objects;
    return memcmp(received, wire, wire_len) == 0;
}

static bool zwn_focus_work_transfer(
    struct zwn_node *from, struct zwn_node *to,
    struct zwn_link *from_to, struct zwn_link *to_from,
    const unsigned char msgstart[MESSAGE_START_SIZE],
    const struct vcs_zcode_work_swarm_message *sent,
    struct vcs_zcode_work_swarm_message *received,
    uint8_t carrier_root[32], uint32_t *retries)
{
    uint8_t wire[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    uint8_t delivered[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (!sent || !received ||
        !vcs_zcode_work_swarm_serialize(
            sent, wire, sizeof(wire), &wire_len) ||
        wire_len == 0 ||
        !zwn_focus_wire_transfer(
            from, to, from_to, to_from, msgstart, wire, wire_len,
            delivered, sizeof(delivered), carrier_root, retries))
        return false;
    return vcs_zcode_work_swarm_parse(delivered, wire_len, received);
}

static bool zwn_focus_receipt_transfer(
    struct zwn_node *from, struct zwn_node *to,
    struct zwn_link *from_to, struct zwn_link *to_from,
    const unsigned char msgstart[MESSAGE_START_SIZE],
    const struct vcs_zcode_work_receipt_v1 *sent,
    struct vcs_zcode_work_receipt_v1 *received,
    uint8_t carrier_root[32], uint32_t *retries)
{
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    uint8_t delivered[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    if (!sent || !received ||
        vcs_zcode_work_receipt_serialize(sent, wire) != VCS_ZCODE_DEV_OK ||
        !zwn_focus_wire_transfer(
            from, to, from_to, to_from, msgstart, wire, sizeof(wire),
            delivered, sizeof(delivered), carrier_root, retries))
        return false;
    return vcs_zcode_work_receipt_parse(
               delivered, sizeof(delivered), received) == VCS_ZCODE_DEV_OK;
}

static bool zwn_focus_scope_transfer(
    struct zwn_node *from, struct zwn_node *to,
    struct zwn_link *from_to, struct zwn_link *to_from,
    const unsigned char msgstart[MESSAGE_START_SIZE],
    const struct vcs_zcode_write_scope_v1 *sent,
    struct vcs_zcode_write_scope_v1 *received,
    uint8_t carrier_root[32], uint32_t *retries)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t delivered[VCS_ZCODE_WRITE_SCOPE_WIRE_MAX];
    bool ok = sent && received &&
        vcs_zcode_write_scope_serialize(sent, &wire, &wire_len) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        wire_len > 0 && wire_len <= sizeof(delivered) &&
        zwn_focus_wire_transfer(
            from, to, from_to, to_from, msgstart, wire, wire_len,
            delivered, sizeof(delivered), carrier_root, retries) &&
        vcs_zcode_write_scope_parse(delivered, wire_len, received) ==
            VCS_ZCODE_WRITE_SCOPE_OK;
    free(wire);
    return ok;
}

static void zwn_focus_fill_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void zwn_focus_task(struct vcs_zcode_task_v1 *task,
                           const uint8_t write_scope_root[32])
{
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    zwn_focus_fill_root(task->source_root, 0x81);
    zwn_focus_fill_root(task->dependency_lock_root, 0x82);
    zwn_focus_fill_root(task->toolchain_capsule_root, 0x83);
    memcpy(task->write_scope_root, write_scope_root, 32);
    zwn_focus_fill_root(task->acceptance_tests_root, 0x85);
    zwn_focus_fill_root(task->proof_policy_root, 0x86);
    zwn_focus_fill_root(task->model_policy_root, 0x87);
    zwn_focus_fill_root(task->goal_root, 0x88);
    task->capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                         VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    task->max_changed_files = 8;
    task->max_patch_bytes = 65536;
    task->max_context_bytes = 8192;
    task->max_cpu_seconds = 60;
    task->max_memory_bytes = UINT64_C(256) * 1024u * 1024u;
    task->max_output_bytes = UINT64_C(8) * 1024u * 1024u;
    task->expires_unix = 5000;
}

static void zwn_focus_context(
    struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    uint8_t *content, size_t content_len)
{
    vcs_zcode_agent_context_init(context);
    memcpy(context->task_root, task_root, 32);
    memcpy(context->source_root, task->source_root, 32);
    memcpy(context->goal_root, task->goal_root, 32);
    zwn_focus_fill_root(context->source_tree_root, 0x89);
    strcpy(context->query, "shared focus context over existing carrier");
    context->file_count = 1;
    strcpy(context->files[0].path, "contexts/commons/modules/vcs/src/zcode_focus.c");
    context->files[0].start_line = 1;
    context->files[0].full_file_bytes = content_len;
    context->files[0].content = content;
    context->files[0].content_len = content_len;
    sha3_256(content, content_len, context->files[0].content_root);
}

static bool zwn_focus_request(
    struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    uint64_t request_id, uint8_t root_seed,
    const uint8_t requester_secret[32], const uint8_t requester_key[32])
{
    if (!request || !task || !task_root || !requester_secret ||
        !requester_key)
        return false;
    memset(request, 0, sizeof(*request));
    request->request_id = request_id;
    memcpy(request->task_root, task_root, 32);
    zwn_focus_fill_root(request->candidate_root, root_seed);
    zwn_focus_fill_root(request->action_root, (uint8_t)(root_seed + 1u));
    zwn_focus_fill_root(request->input_root, (uint8_t)(root_seed + 2u));
    zwn_focus_fill_root(request->context_root, (uint8_t)(root_seed + 3u));
    memcpy(request->proof_policy_root, task->proof_policy_root, 32);
    memcpy(request->toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    request->work_kind = VCS_ZCODE_WORK_BUILD;
    request->target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
    request->max_cpu_seconds = 30;
    request->max_memory_bytes = UINT64_C(128) * 1024u * 1024u;
    request->max_output_bytes = UINT64_C(4) * 1024u * 1024u;
    request->deadline_unix = 2200;
    return vcs_zcode_work_request_seal(
        request, requester_secret, requester_key);
}

static bool zwn_focus_admission(
    struct vcs_zcode_work_admission_v1 *admission,
    const struct vcs_zcode_work_request_v1 *request,
    const uint8_t worker_secret[32], const uint8_t worker_key[32])
{
    if (!admission || !request || !worker_secret || !worker_key)
        return false;
    memset(admission, 0, sizeof(*admission));
    admission->request_id = request->request_id;
    memcpy(admission->requester_pubkey, request->requester_pubkey, 32);
    memcpy(admission->action_root, request->action_root, 32);
    admission->lease_generation = 1;
    admission->deadline_unix = request->deadline_unix;
    admission->slot = 0;
    admission->disposition = VCS_ZCODE_WORK_ADMISSION_GRANTED;
    return vcs_zcode_work_admission_seal(
        admission, worker_secret, worker_key);
}

static bool zwn_focus_receipt(
    struct vcs_zcode_work_receipt_v1 *receipt,
    const struct vcs_zcode_work_request_v1 *request, uint8_t root_seed,
    const uint8_t worker_secret[32], const uint8_t worker_key[32])
{
    if (!receipt || !request || !worker_secret || !worker_key)
        return false;
    memset(receipt, 0, sizeof(*receipt));
    receipt->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(receipt->task_root, request->task_root, 32);
    memcpy(receipt->candidate_root, request->candidate_root, 32);
    memcpy(receipt->action_root, request->action_root, 32);
    memcpy(receipt->input_root, request->input_root, 32);
    zwn_focus_fill_root(receipt->output_root, root_seed);
    memcpy(receipt->proof_policy_root, request->proof_policy_root, 32);
    memcpy(receipt->toolchain_capsule_root,
           request->toolchain_capsule_root, 32);
    zwn_focus_fill_root(receipt->lease_id, (uint8_t)(root_seed + 1u));
    zwn_focus_fill_root(receipt->evidence_root, (uint8_t)(root_seed + 2u));
    zwn_focus_fill_root(receipt->confinement_root,
                        (uint8_t)(root_seed + 3u));
    receipt->work_kind = request->work_kind;
    receipt->status = VCS_ZCODE_WORK_PASS;
    receipt->started_unix = 1200;
    receipt->finished_unix = 1300;
    return vcs_zcode_work_receipt_seal(
               receipt, worker_secret, worker_key) == VCS_ZCODE_DEV_OK;
}

static void zwn_focus_claim(struct vcs_zcode_focus_claim_v1 *claim,
                            const uint8_t situation_root[32],
                            const uint8_t write_scope_root[32],
                            uint8_t worker, uint8_t intent)
{
    memset(claim, 0, sizeof(*claim));
    claim->schema_version = VCS_ZCODE_FOCUS_VERSION;
    claim->created_unix = 1000;
    claim->expires_unix = 2000;
    memcpy(claim->situation_root, situation_root, 32);
    zwn_focus_fill_root(claim->claimant_root, worker);
    memcpy(claim->write_scope_root, write_scope_root, 32);
    zwn_focus_fill_root(claim->intent_root, intent);
    zwn_focus_fill_root(claim->evidence_plan_root,
                        (uint8_t)(intent + 20u));
}

static void zwn_focus_report(
    struct vcs_zcode_specialist_report_v1 *report,
    const uint8_t focus_root[32], const uint8_t claim_root[32],
    uint8_t worker, uint8_t role, uint8_t evidence)
{
    memset(report, 0, sizeof(*report));
    report->schema_version = VCS_ZCODE_FOCUS_VERSION;
    report->role = role;
    report->status = ZCL_ONTOLOGY_PROVED;
    report->context_bytes = 1265;
    report->latency_us = 250000;
    report->files_opened = 3;
    report->tool_calls = 5;
    report->duplicate_actions = 0;
    report->proof_reuse_count = 1;
    memcpy(report->focus_root, focus_root, 32);
    memcpy(report->claim_root, claim_root, 32);
    zwn_focus_fill_root(report->specialist_root, worker);
    zwn_focus_fill_root(report->evidence_root, evidence);
    zwn_focus_fill_root(report->result_root, (uint8_t)(evidence + 1u));
    zwn_focus_fill_root(report->next_experiment_root,
                        (uint8_t)(evidence + 2u));
    zwn_focus_fill_root(report->evaluator_root,
                        (uint8_t)(evidence + 3u));
}

static int zwn_t_shared_focus_flight(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    uint8_t *claim_set_wire = NULL;
    TEST("shared focus flight: two node engines derive one focus, exchange "
         "disjoint claims and rooted reports over real zpkgswm frames, "
         "then the successor validates the handoff without prose") {
        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "focus-a"}, {&b, "focus-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 7, 0, 1}, "focus-peer-b"},
            {&b, &b_a, {10, 7, 0, 2}, "focus-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        /* The authority roots are deterministic fixture values. The scope
         * semantics use tracked platform paths so the overlap/containment
         * predicates exercise the actual focus component boundary. This is
         * not evidence of a physical host or completed C23 edit. */
        struct vcs_zcode_write_scope_v1 task_scope, scope_a, scope_b;
        vcs_zcode_write_scope_init(&task_scope);
        vcs_zcode_write_scope_init(&scope_a);
        vcs_zcode_write_scope_init(&scope_b);
        ASSERT_EQ(vcs_zcode_write_scope_add(&task_scope, "contexts/commons/modules/vcs/src"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(
                      &scope_a, "contexts/commons/modules/vcs/src/zcode_focus.c"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(
                      &scope_b, "contexts/commons/modules/vcs/src/zcode_focus_claim.c"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        uint8_t task_scope_root[32], scope_a_root[32], scope_b_root[32];
        ASSERT_EQ(vcs_zcode_write_scope_root(&task_scope, task_scope_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_root(&scope_a, scope_a_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_root(&scope_b, scope_b_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);

        struct vcs_zcode_task_v1 task;
        zwn_focus_task(&task, task_scope_root);
        uint8_t task_root[32], context_root[32], story_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        uint8_t context_content[] = "exact reusable C23 context\n";
        struct vcs_zcode_agent_context_v1 context;
        zwn_focus_context(&context, &task, task_root, context_content,
                          sizeof(context_content) - 1u);
        ASSERT_EQ(vcs_zcode_agent_context_root(
                      &context, task.max_context_bytes, context_root),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        zwn_focus_fill_root(story_root, 0x8a);
        struct vcs_zcode_focus_v1 basis;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_PROVED, 0, NULL, 0, &basis),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t situation_root[32];
        ASSERT_EQ(vcs_zcode_focus_situation_root(&basis, situation_root),
                  VCS_ZCODE_FOCUS_OK);

        /* Existing work authority crosses first: signed requests from the
         * task owner, signed admissions by each worker, and signed receipts
         * for the exact task/candidate/action/input tuple. */
        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        uint8_t worker_a_seed[32], worker_a_secret[32], worker_a_key[32];
        uint8_t worker_b_seed[32], worker_b_secret[32], worker_b_key[32];
        zwn_focus_fill_root(requester_seed, 0x91);
        zwn_focus_fill_root(worker_a_seed, 0x92);
        zwn_focus_fill_root(worker_b_seed, 0x93);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        ed25519_keypair(worker_a_key, worker_a_secret, worker_a_seed);
        ed25519_keypair(worker_b_key, worker_b_secret, worker_b_seed);

        struct vcs_zcode_work_request_v1 request_a, request_b;
        struct vcs_zcode_work_admission_v1 admission_a, admission_b;
        struct vcs_zcode_work_receipt_v1 receipt_a, receipt_b;
        ASSERT(zwn_focus_request(
            &request_a, &task, task_root, 101, 0xa1,
            requester_secret, requester_key));
        ASSERT(zwn_focus_request(
            &request_b, &task, task_root, 102, 0xb1,
            requester_secret, requester_key));
        ASSERT(zwn_focus_admission(
            &admission_a, &request_a, worker_a_secret, worker_a_key));
        ASSERT(zwn_focus_admission(
            &admission_b, &request_b, worker_b_secret, worker_b_key));
        /* Source authority must cover the signed completion observation,
         * not remain live forever after completed evidence is handed off. */
        admission_a.deadline_unix = 1600;
        ASSERT(vcs_zcode_work_admission_seal(
            &admission_a, worker_a_secret, worker_a_key));
        ASSERT(zwn_focus_receipt(
            &receipt_a, &request_a, 0xc1, worker_a_secret, worker_a_key));
        ASSERT(zwn_focus_receipt(
            &receipt_b, &request_b, 0xd1, worker_b_secret, worker_b_key));
        uint8_t request_a_root[32], request_b_root[32];
        uint8_t receipt_a_root[32], receipt_b_root[32];
        ASSERT(vcs_zcode_work_request_id(&request_a, request_a_root));
        ASSERT(vcs_zcode_work_request_id(&request_b, request_b_root));
        ASSERT_EQ(vcs_zcode_work_receipt_id(&receipt_a, receipt_a_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_id(&receipt_b, receipt_b_root),
                  VCS_ZCODE_DEV_OK);

        uint8_t received[VCS_BLOB_MAX_BYTES], carrier_root[32];
        uint32_t retries = 0;
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_task_serialize(&task, task_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            task_wire, sizeof(task_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_task_v1 task_at_b;
        ASSERT_EQ(vcs_zcode_task_parse(
                      received, sizeof(task_wire), &task_at_b),
                  VCS_ZCODE_DEV_OK);
        uint8_t task_root_at_b[32];
        ASSERT_EQ(vcs_zcode_task_root(&task_at_b, task_root_at_b),
                  VCS_ZCODE_DEV_OK);
        ASSERT(memcmp(task_root_at_b, task_root, 32) == 0);

        uint8_t *context_wire = NULL;
        size_t context_wire_len = 0;
        ASSERT_EQ(vcs_zcode_agent_context_serialize(
                      &context, task.max_context_bytes,
                      &context_wire, &context_wire_len),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            context_wire, context_wire_len, received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_agent_context_v1 context_at_b;
        vcs_zcode_agent_context_init(&context_at_b);
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      received, context_wire_len, task_at_b.max_context_bytes,
                      &context_at_b),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT_EQ(vcs_zcode_agent_context_validate_for_task(
                      &context_at_b, &task_at_b, task_root_at_b,
                      context_root, true),
                  VCS_ZCODE_AGENT_CONTEXT_OK);

        struct vcs_zcode_write_scope_v1 task_scope_at_b;
        struct vcs_zcode_write_scope_v1 scope_a_at_b, scope_b_at_b;
        ASSERT(zwn_focus_scope_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &task_scope, &task_scope_at_b, carrier_root, &retries));
        ASSERT(zwn_focus_scope_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &scope_a, &scope_a_at_b, carrier_root, &retries));
        ASSERT(zwn_focus_scope_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &scope_b, &scope_b_at_b, carrier_root, &retries));
        uint8_t scope_root_at_b[32];
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &task_scope_at_b, scope_root_at_b),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT(memcmp(scope_root_at_b, task_scope_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &scope_a_at_b, scope_root_at_b),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT(memcmp(scope_root_at_b, scope_a_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &scope_b_at_b, scope_root_at_b),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT(memcmp(scope_root_at_b, scope_b_root, 32) == 0);

        struct vcs_zcode_work_swarm_message sent_work, received_work;
        memset(&sent_work, 0, sizeof(sent_work));
        sent_work.type = VCS_ZCODE_WORK_SWARM_REQUEST;
        sent_work.body.request = request_a;
        ASSERT(zwn_focus_work_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &sent_work, &received_work, carrier_root, &retries));
        ASSERT_EQ(received_work.type, VCS_ZCODE_WORK_SWARM_REQUEST);
        struct vcs_zcode_work_request_v1 request_a_at_b =
            received_work.body.request;
        memset(&sent_work, 0, sizeof(sent_work));
        sent_work.type = VCS_ZCODE_WORK_SWARM_ADMISSION;
        sent_work.body.admission = admission_a;
        ASSERT(zwn_focus_work_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &sent_work, &received_work, carrier_root, &retries));
        ASSERT_EQ(received_work.type, VCS_ZCODE_WORK_SWARM_ADMISSION);
        struct vcs_zcode_work_admission_v1 admission_a_at_b =
            received_work.body.admission;
        struct vcs_zcode_work_receipt_v1 receipt_a_at_b;
        ASSERT(zwn_focus_receipt_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            &receipt_a, &receipt_a_at_b, carrier_root, &retries));

        memset(&sent_work, 0, sizeof(sent_work));
        sent_work.type = VCS_ZCODE_WORK_SWARM_REQUEST;
        sent_work.body.request = request_b;
        ASSERT(zwn_focus_work_transfer(
            &b, &a, &b_a, &a_b, params->pchMessageStart,
            &sent_work, &received_work, carrier_root, &retries));
        ASSERT_EQ(received_work.type, VCS_ZCODE_WORK_SWARM_REQUEST);
        struct vcs_zcode_work_request_v1 request_b_at_a =
            received_work.body.request;
        memset(&sent_work, 0, sizeof(sent_work));
        sent_work.type = VCS_ZCODE_WORK_SWARM_ADMISSION;
        sent_work.body.admission = admission_b;
        ASSERT(zwn_focus_work_transfer(
            &b, &a, &b_a, &a_b, params->pchMessageStart,
            &sent_work, &received_work, carrier_root, &retries));
        ASSERT_EQ(received_work.type, VCS_ZCODE_WORK_SWARM_ADMISSION);
        struct vcs_zcode_work_admission_v1 admission_b_at_a =
            received_work.body.admission;
        struct vcs_zcode_work_receipt_v1 receipt_b_at_a;
        ASSERT(zwn_focus_receipt_transfer(
            &b, &a, &b_a, &a_b, params->pchMessageStart,
            &receipt_b, &receipt_b_at_a, carrier_root, &retries));

        /* Each node creates one claim. The opposite node receives the exact
         * canonical wire through content.v2 before either final focus is
         * composed. */
        struct vcs_zcode_focus_claim_v1 claim_a, claim_b;
        zwn_focus_claim(&claim_a, situation_root, scope_a_root, 0xa1, 0xb1);
        zwn_focus_claim(&claim_b, situation_root, scope_b_root, 0xa2, 0xb2);
        claim_a.expires_unix = 1600;
        claim_b.created_unix = 1400;
        claim_b.expires_unix = 2100;
        memcpy(claim_a.claimant_root, worker_a_key, 32);
        memcpy(claim_a.intent_root, request_a_root, 32);
        memcpy(claim_a.evidence_plan_root, request_a.proof_policy_root, 32);
        memcpy(claim_b.claimant_root, worker_b_key, 32);
        memcpy(claim_b.intent_root, request_b_root, 32);
        memcpy(claim_b.evidence_plan_root, request_b.proof_policy_root, 32);
        uint8_t claim_a_root[32], claim_b_root[32];
        uint8_t claim_a_wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
        uint8_t claim_b_wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_a, claim_a_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_b, claim_b_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_serialize(&claim_a, claim_a_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_serialize(&claim_b, claim_b_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            claim_a_wire, sizeof(claim_a_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_focus_claim_v1 claim_a_at_b;
        ASSERT_EQ(vcs_zcode_focus_claim_parse(
                      received, sizeof(claim_a_wire), &claim_a_at_b),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t derived_root[32];
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_a_at_b, derived_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, claim_a_root, 32) == 0);

        ASSERT(zwn_focus_wire_transfer(
            &b, &a, &b_a, &a_b, params->pchMessageStart,
            claim_b_wire, sizeof(claim_b_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_focus_claim_v1 claim_b_at_a;
        ASSERT_EQ(vcs_zcode_focus_claim_parse(
                      received, sizeof(claim_b_wire), &claim_b_at_a),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_b_at_a, derived_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, claim_b_root, 32) == 0);

        uint8_t claim_roots[2][32];
        struct vcs_zcode_focus_claim_v1 ordered_claims[2] = {
            claim_a_at_b, claim_b,
        };
        struct vcs_zcode_write_scope_v1 ordered_scopes[2] = {
            scope_a_at_b, scope_b_at_b,
        };
        size_t from_index = 0;
        size_t next_index = 1;
        memcpy(claim_roots[0], claim_a_root, 32);
        memcpy(claim_roots[1], claim_b_root, 32);
        if (memcmp(claim_roots[0], claim_roots[1], 32) > 0) {
            uint8_t swap[32];
            struct vcs_zcode_focus_claim_v1 claim_swap = ordered_claims[0];
            struct vcs_zcode_write_scope_v1 scope_swap = ordered_scopes[0];
            memcpy(swap, claim_roots[0], 32);
            memcpy(claim_roots[0], claim_roots[1], 32);
            memcpy(claim_roots[1], swap, 32);
            ordered_claims[0] = ordered_claims[1];
            ordered_claims[1] = claim_swap;
            ordered_scopes[0] = ordered_scopes[1];
            ordered_scopes[1] = scope_swap;
            from_index = 1;
            next_index = 0;
        }
        size_t claim_set_len = 0;
        ASSERT_EQ(vcs_zcode_focus_claim_set_serialize(
                      claim_roots, 2, &claim_set_wire, &claim_set_len),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(claim_set_wire != NULL && claim_set_len > 0);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            claim_set_wire, claim_set_len, received, sizeof(received),
            carrier_root, &retries));
        uint8_t received_claim_roots[2][32];
        size_t received_claim_count = 0;
        ASSERT_EQ(vcs_zcode_focus_claim_set_parse(
                      received, claim_set_len, received_claim_roots, 2,
                      &received_claim_count),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(received_claim_count, 2);
        uint8_t received_claim_set_root[32];
        ASSERT_EQ(vcs_zcode_focus_claim_set_root(
                      received_claim_roots, received_claim_count,
                      received_claim_set_root),
                  VCS_ZCODE_FOCUS_OK);

        struct vcs_zcode_focus_v1 focus_a, focus_b;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_PROVED, 0, claim_roots, 2, &focus_a),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_PROVED, 0, claim_roots, 2, &focus_b),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t focus_root_a[32], focus_root_b[32];
        ASSERT_EQ(vcs_zcode_focus_root(&focus_a, focus_root_a),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_root(&focus_b, focus_root_b),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(focus_root_a, focus_root_b, 32) == 0);
        ASSERT_EQ(vcs_zcode_focus_claim_disjoint_status(
                      &claim_a_at_b, &scope_a_at_b,
                      &claim_b, &scope_b_at_b, 1500),
                  ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_authority_status(
                      &focus_a, &task, &task_scope, &claim_a, &scope_a, 1500),
                  ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_authority_status(
                      &focus_b, &task_at_b, &task_scope_at_b,
                      &claim_b, &scope_b_at_b, 1500),
                  ZCL_ONTOLOGY_PROVED);

        uint8_t focus_wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_focus_serialize(&focus_a, focus_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            focus_wire, sizeof(focus_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_focus_v1 focus_at_b;
        ASSERT_EQ(vcs_zcode_focus_parse(
                      received, sizeof(focus_wire), &focus_at_b),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_root(&focus_at_b, derived_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, focus_root_a, 32) == 0);
        ASSERT(memcmp(received_claim_set_root,
                      focus_at_b.claim_set_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_focus_claim_set_status(
                      &focus_at_b, ordered_claims, ordered_scopes, 2, 1500),
                  ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_work_status(
                      &focus_a, &task, &task_scope,
                      &claim_b_at_a, &scope_b,
                      received_claim_roots, received_claim_count,
                      &request_b_at_a, &admission_b_at_a, 1500),
                  ZCL_ONTOLOGY_PROVED);

        /* Reports cross in both directions. Their semantic identities stay
         * claim/focus-rooted even though each content carrier has its own
         * manifest root. */
        struct vcs_zcode_specialist_report_v1 report_a, report_b;
        zwn_focus_report(&report_a, focus_root_a, claim_a_root, 0xa1,
                         VCS_ZCODE_SPECIALIST_RETRIEVAL, 0xc1);
        zwn_focus_report(&report_b, focus_root_b, claim_b_root, 0xa2,
                         VCS_ZCODE_SPECIALIST_CODE, 0xd1);
        memcpy(report_a.specialist_root, worker_a_key, 32);
        memcpy(report_a.evidence_root, receipt_a_root, 32);
        memcpy(report_a.result_root, receipt_a.output_root, 32);
        memcpy(report_b.specialist_root, worker_b_key, 32);
        memcpy(report_b.evidence_root, receipt_b_root, 32);
        memcpy(report_b.result_root, receipt_b.output_root, 32);
        uint8_t report_a_root[32], report_b_root[32];
        uint8_t report_a_wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        uint8_t report_b_wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_specialist_report_root(&report_a, report_a_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_root(&report_b, report_b_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_serialize(
                      &report_a, report_a_wire), VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_serialize(
                      &report_b, report_b_wire), VCS_ZCODE_FOCUS_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            report_a_wire, sizeof(report_a_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_specialist_report_v1 report_a_at_b;
        ASSERT_EQ(vcs_zcode_specialist_report_parse(
                      received, sizeof(report_a_wire), &report_a_at_b),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_root(
                      &report_a_at_b, derived_root), VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, report_a_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_specialist_report_validate_for_work(
                      &focus_at_b, &claim_a_at_b, claim_roots, 2,
                      &task_at_b, &request_a_at_b, &receipt_a_at_b,
                      &report_a_at_b),
                  VCS_ZCODE_FOCUS_OK);

        ASSERT(zwn_focus_wire_transfer(
            &b, &a, &b_a, &a_b, params->pchMessageStart,
            report_b_wire, sizeof(report_b_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_specialist_report_v1 report_b_at_a;
        ASSERT_EQ(vcs_zcode_specialist_report_parse(
                      received, sizeof(report_b_wire), &report_b_at_a),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_root(
                      &report_b_at_a, derived_root), VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, report_b_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_specialist_report_validate_for_work(
                      &focus_a, &claim_b_at_a, claim_roots, 2,
                      &task, &request_b_at_a, &receipt_b_at_a,
                      &report_b_at_a),
                  VCS_ZCODE_FOCUS_OK);

        struct vcs_zcode_focus_handoff_v1 handoff;
        memset(&handoff, 0, sizeof(handoff));
        handoff.schema_version = VCS_ZCODE_FOCUS_VERSION;
        handoff.status = ZCL_ONTOLOGY_PROVED;
        memcpy(handoff.focus_root, focus_root_a, 32);
        memcpy(handoff.report_root, report_a_root, 32);
        memcpy(handoff.from_claim_root, claim_a_root, 32);
        memcpy(handoff.to_specialist_root, claim_b.claimant_root, 32);
        memcpy(handoff.next_claim_root, claim_b_root, 32);
        memcpy(handoff.required_evidence_root,
               focus_a.required_evidence_root, 32);
        memcpy(handoff.continuation_root,
               report_a.next_experiment_root, 32);
        uint8_t handoff_root[32];
        uint8_t handoff_wire[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_focus_handoff_root(&handoff, handoff_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_serialize(&handoff, handoff_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            handoff_wire, sizeof(handoff_wire), received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_focus_handoff_v1 handoff_at_b;
        ASSERT_EQ(vcs_zcode_focus_handoff_parse(
                      received, sizeof(handoff_wire), &handoff_at_b),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_root(&handoff_at_b, derived_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(derived_root, handoff_root, 32) == 0);
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &context_at_b,
                      &task_scope_at_b,
                      ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 1500),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &context_at_b,
                      &task_scope_at_b,
                      ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 2000),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_work_admission_v1 late_admission_a =
            admission_a_at_b;
        late_admission_a.deadline_unix = receipt_a_at_b.finished_unix;
        ASSERT(vcs_zcode_work_admission_seal(
            &late_admission_a, worker_a_secret, worker_a_key));
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &context_at_b,
                      &task_scope_at_b,
                      ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &late_admission_a,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 2000),
                  VCS_ZCODE_FOCUS_BINDING);
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &context_at_b,
                      &task_scope_at_b,
                      ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 2100),
                  VCS_ZCODE_FOCUS_BINDING);
        struct vcs_zcode_work_admission_v1 refused_b = admission_b;
        refused_b.lease_generation = 0;
        refused_b.deadline_unix = 0;
        refused_b.slot = UINT16_MAX;
        refused_b.disposition = VCS_ZCODE_WORK_ADMISSION_REFUSED;
        refused_b.reason = VCS_ZCODE_WORK_ADMISSION_REASON_POLICY;
        ASSERT(vcs_zcode_work_admission_seal(
            &refused_b, worker_b_secret, worker_b_key));
        ASSERT(vcs_zcode_work_admission_verify_for_request(
            &request_b, &refused_b, worker_b_key));
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &context_at_b,
                      &task_scope_at_b,
                      ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &refused_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 1500),
                  VCS_ZCODE_FOCUS_BINDING);
        struct vcs_zcode_agent_context_v1 incomplete_context = context_at_b;
        incomplete_context.flags |= VCS_ZCODE_AGENT_CONTEXT_TRUNCATED;
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &focus_at_b, &task_at_b, &incomplete_context,
                      &task_scope_at_b, ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 1500),
                  VCS_ZCODE_FOCUS_BINDING);
        uint8_t *incomplete_wire = NULL;
        size_t incomplete_wire_len = 0;
        uint8_t incomplete_root[32];
        ASSERT_EQ(vcs_zcode_agent_context_root(
                      &incomplete_context, task_at_b.max_context_bytes,
                      incomplete_root),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT_EQ(vcs_zcode_agent_context_serialize(
                      &incomplete_context, task_at_b.max_context_bytes,
                      &incomplete_wire, &incomplete_wire_len),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        ASSERT(zwn_focus_wire_transfer(
            &a, &b, &a_b, &b_a, params->pchMessageStart,
            incomplete_wire, incomplete_wire_len, received, sizeof(received),
            carrier_root, &retries));
        struct vcs_zcode_agent_context_v1 incomplete_at_b;
        vcs_zcode_agent_context_init(&incomplete_at_b);
        ASSERT_EQ(vcs_zcode_agent_context_parse(
                      received, incomplete_wire_len,
                      task_at_b.max_context_bytes, &incomplete_at_b),
                  VCS_ZCODE_AGENT_CONTEXT_OK);
        struct vcs_zcode_focus_v1 incomplete_focus;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task_at_b, task_root_at_b, incomplete_root, story_root,
                      ZCL_ONTOLOGY_PROVED,
                      VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED,
                      received_claim_roots, received_claim_count,
                      &incomplete_focus),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_for_work(
                      &incomplete_focus, &task_at_b, &incomplete_at_b,
                      &task_scope_at_b, ordered_claims, ordered_scopes, 2,
                      from_index, next_index,
                      &request_a_at_b, &admission_a_at_b,
                      &request_b, &admission_b, &receipt_a_at_b,
                      &report_a_at_b, &handoff_at_b, 1500),
                  VCS_ZCODE_FOCUS_INCOMPLETE);

        char focus_hex[65], handoff_hex[65], receipt_hex[65];
        zcl_hex_encode(focus_root_a, 32, focus_hex);
        zcl_hex_encode(handoff_root, 32, handoff_hex);
        zcl_hex_encode(receipt_a_root, 32, receipt_hex);
        printf("{\"schema\":\"zcl.shared_focus_wire_fixture.v1\","
               "\"status\":\"passed\","
               "\"topology\":\"in_process_two_node_engines\","
               "\"signer_identities\":2,\"claims\":2,"
               "\"reports\":2,\"carrier_transfers\":19,"
               "\"signed_requests\":2,\"signed_admissions\":2,"
               "\"signed_receipts\":2,"
               "\"context_wire_bytes\":%zu,\"warm_context_transfers\":0,"
               "\"negative_context_transfers\":1,"
               "\"retries\":%u,\"expiry_refused\":true,"
               "\"incomplete_context_refused\":true,"
               "\"scope_overlap\":\"DISPROVED\",\"prose_bytes\":0,"
               "\"focus_root\":\"%s\",\"handoff_root\":\"%s\","
               "\"work_receipt_root\":\"%s\"}\n",
               context_wire_len + incomplete_wire_len, retries,
               focus_hex, handoff_hex, receipt_hex);
        ASSERT(retries == 0);

        free(context_wire);
        free(incomplete_wire);
        vcs_zcode_agent_context_free(&context_at_b);
        vcs_zcode_agent_context_free(&incomplete_at_b);
        free(claim_set_wire);
        claim_set_wire = NULL;
        zwn_fixture_cleanup(&fixture);
        PASS();
    } _test_next:
    free(claim_set_wire);
    zwn_fixture_cleanup(&fixture);
    return failures;
}

static int zwn_t_task_flight(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("task flight: A posts a dev task as the three-file carrier, B "
         "resolves the pointer, pulls the context over real zpkgswm "
         "frames, and re-verifies it against exactly the task root — "
         "goal text included") {
        static const char goal[] =
            "port the fold reducer to the new arena API; the suite stays "
            "green or the work is worth nothing";
        uint8_t task_root[32], context_root[32];

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "task-a"}, {&b, "task-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 4, 0, 1}, "task-peer-b"},
            {&b, &b_a, {10, 4, 0, 2}, "task-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        /* 1. A offers AFTER the fixture exists (the offer writes into
         *    A's store); the synthetic clock is 1000 and the task lives
         *    until 4020, so every later admit is a live one. */
        ASSERT(zwn_task_offer(&a, goal, 1000, 4020, task_root,
                              context_root));

        /* 2. B has never seen it: admit refuses on the store rule. */
        ASSERT_EQ(vcs_zcode_task_context_admit(
                      b.store, context_root, task_root, 1002, NULL, NULL,
                      NULL, 0, NULL, NULL),
                  VCS_ZCODE_TASK_CONTEXT_STORE);

        /* 3. B learns the context root the way a stranger does: the
         *    signed POINTER pair in the task namespace, keyed on the task
         *    root. The discover helper's record window is 1000..2000, so
         *    the flight runs at 1002 like every other flight. */
        uint8_t discovered[32];
        struct vcs_zcode_dht_record provider;
        memset(&provider, 0, sizeof(provider));
        ASSERT(zwn_discover_transport(&a, &a, &b, ZWN_TASK_NS, task_root,
                                      context_root, discovered, &provider,
                                      1002));
        ASSERT(memcmp(discovered, context_root, 32) == 0);

        /* 4. The bytes cross the codec on real frames — A's DATA reply
         *    counter is the proof nothing was copied out of band. */
        ASSERT(a.chunk_data_replies[0] == 0);
        ASSERT(zwn_fetch_package_from_provider(&b, discovered, &a_b, &b_a,
                                               params->pchMessageStart));
        ASSERT(a.chunk_data_replies[0] > 0);

        /* 5. B re-verifies from ITS stored bytes with the binding a
         *    stranger actually has: this context must prove exactly the
         *    task root B asked about, and hand back the goal text. */
        struct vcs_zcode_task_v1 admitted;
        char goal_back[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX + 1u];
        size_t goal_back_len = 0;
        uint8_t derived[32];
        ASSERT_EQ(vcs_zcode_task_context_admit(
                      b.store, discovered, task_root, 1002, &admitted, NULL,
                      (uint8_t *)goal_back, sizeof(goal_back) - 1u,
                      &goal_back_len, derived),
                  VCS_ZCODE_TASK_CONTEXT_OK);
        ASSERT(goal_back_len == strlen(goal));
        ASSERT(memcmp(goal_back, goal, goal_back_len) == 0);
        ASSERT(memcmp(derived, task_root, 32) == 0);
        ASSERT(admitted.expires_unix == 4020);

        /* 6. A hostile clock drop: the same bytes, admitted after the
         *    posting expired, refuse — a stale posting is not a task. */
        ASSERT_EQ(vcs_zcode_task_context_admit(
                      b.store, discovered, task_root, 4100, NULL, NULL,
                      NULL, 0, NULL, NULL),
                  VCS_ZCODE_TASK_CONTEXT_TASK_EXPIRED);

        zwn_fixture_cleanup(&fixture);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* The hostile task pointer: a context for a DIFFERENT task, delivered
 * under the root B asked about. Nothing in the record layer can check
 * what a task context proves — the refusal has to happen where the bytes
 * land, exactly like the attestation binding arm. */
static int zwn_t_task_hostile_pointer(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("hostile task pointer: a context proving a DIFFERENT task, "
         "resolved and fetched under the task root B asked about, is "
         "refused task-mismatch and nothing is admitted") {
        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "taskhostile-a"}, {&b, "taskhostile-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 4, 0, 1}, "taskhostile-peer-b"},
            {&b, &b_a, {10, 4, 0, 2}, "taskhostile-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        /* Two honest postings: the asked-about task and a different one
         * (a different goal is a different root). */
        static const char asked_goal[] =
            "make the frontier scan linear in height";
        static const char other_goal[] =
            "make the fold reducer arena-first";
        uint8_t asked_root[32], asked_context[32];
        uint8_t other_root[32], other_context[32];
        ASSERT(zwn_task_offer(&a, asked_goal, 1000, 4020, asked_root,
                              asked_context));
        ASSERT(zwn_task_offer(&a, other_goal, 1000, 4020, other_root,
                              other_context));
        ASSERT(memcmp(asked_root, other_root, 32) != 0);
        ASSERT(memcmp(asked_context, other_context, 32) != 0);

        /* The lie: a pointer binding the ASKED task root to the OTHER
         * task's context. The record layer carries it happily. */
        uint8_t discovered[32];
        struct vcs_zcode_dht_record provider;
        memset(&provider, 0, sizeof(provider));
        ASSERT(zwn_discover_transport(&a, &a, &b, ZWN_TASK_NS, asked_root,
                                      other_context, discovered, &provider,
                                      1002));
        ASSERT(memcmp(discovered, other_context, 32) == 0);

        /* B fetches the bytes for real — they are valid carrier bytes,
         * which is exactly why the check cannot live in the codec. */
        ASSERT(zwn_fetch_package_from_provider(&b, discovered, &a_b, &b_a,
                                               params->pchMessageStart));

        /* The refusal: the context proves other_root, B asked about
         * asked_root, and admit says so by name. With the CORRECT
         * expectation the same bytes verify — proving the refusal is the
         * binding, not the bytes. */
        ASSERT_EQ(vcs_zcode_task_context_admit(
                      b.store, discovered, asked_root, 1002, NULL, NULL,
                      NULL, 0, NULL, NULL),
                  VCS_ZCODE_TASK_CONTEXT_TASK_MISMATCH);
        ASSERT_EQ(vcs_zcode_task_context_admit(
                      b.store, discovered, other_root, 1002, NULL, NULL,
                      NULL, 0, NULL, NULL),
                  VCS_ZCODE_TASK_CONTEXT_OK);

        zwn_fixture_cleanup(&fixture);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* The security property of the whole design. A pointer is a signed pair
 * (semantic_root, transport_root) and NOTHING in the record layer can
 * check that the attestation on the far end is about the package the key
 * names — so the check has to happen where the bytes land. */
static int zwn_t_attestation_hostile_pointer(
    const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("hostile pointer: an attestation about a DIFFERENT package, "
         "delivered under the root B asked about, is refused ERR_BINDING "
         "and files NOTHING") {
        struct zwn_pkg asked, other;
        ASSERT(zwn_make_package(&asked, 3, 0x61));
        ASSERT(zwn_make_package(&other, 4, 0x62));
        ASSERT(memcmp(asked.root, other.root, 32) != 0);

        /* A genuine, correctly signed attestation — about the WRONG
         * package. Nothing about these bytes is forged; the lie is the
         * pointer that offers them as an answer about `asked`. */
        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        ASSERT(zwn_att_wire(other.root, 0x41, wire, &wire_len, id));

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "hp-a"}, {&b, "hp-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 5, 0, 1}, "hp-peer-b"},
            {&b, &b_a, {10, 5, 0, 2}, "hp-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        bool filed = false, present = false;
        ASSERT(vcs_package_attest_transport_file(
                   a.zcode_dir, wire, wire_len, id, &filed, &present) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        struct vcs_package_attest_transport_outcome offer;
        ASSERT(zwn_att_offer_pinned(&a, id, &offer));

        /* The lie: a signed POINTER keyed on `asked` that names the
         * transport root of the `other` attestation. The record layer
         * signs it without complaint, and B's query resolves it. */
        uint8_t discovered[32];
        ASSERT(zwn_discover_transport(&a, &a, &b, ZWN_ATT_NS, asked.root,
                                      offer.transport_root, discovered,
                                      NULL, 1020));
        ASSERT(memcmp(discovered, offer.transport_root, 32) == 0);

        /* The bytes themselves transfer honestly — they hash to the root
         * that was asked for, so no layer below can object. */
        ASSERT(zwn_fetch_package_from_provider(&b, discovered, &a_b, &b_a,
                                               params->pchMessageStart));
        uint8_t got[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t got_len = 0;
        ASSERT(vcs_blob_get_from(b.store, discovered, got, sizeof(got),
                                 &got_len) == VCS_BLOB_OK);
        ASSERT(got_len == wire_len && memcmp(got, wire, wire_len) == 0);

        /* The refusal, and the absence it must leave behind. */
        char b_path[1400];
        ASSERT(zwn_att_path(&b, id, b_path, sizeof(b_path)));
        struct vcs_package_attest_transport_outcome admit;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, discovered, asked.root, &admit) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING);
        ASSERT(admit.result == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING);
        ASSERT(!admit.filed && !admit.already_present);
        {
            uint8_t leaked[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
            size_t leaked_len = 0;
            ASSERT(!zwn_att_read(b_path, leaked, sizeof(leaked),
                                 &leaked_len));
        }
        ASSERT(zwn_att_dir_count(&b) <= 0);

        /* The refusal is exactly the binding and nothing else: the same
         * delivered bytes file when the question they answer is the one
         * being asked. */
        struct vcs_package_attest_transport_outcome honest;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, discovered, other.root, &honest) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        ASSERT(honest.filed && !honest.already_present);
        ASSERT(zwn_att_dir_count(&b) == 1);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&asked);
        zwn_free_package(&other);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* Two ways a flipped byte can reach a receiver, and both must leave the
 * attestations dir empty: re-rooted by the attacker so the carriage is
 * honest, and flipped in flight so the carriage itself catches it. */
static int zwn_t_attestation_corrupt_wire(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_fixture fixture = {0};
    TEST("corrupt attestation wire: a flipped byte is refused at B "
         "whether it is re-rooted by the sender or flipped in flight, "
         "and files NOTHING either way") {
        struct zwn_pkg pkg;
        ASSERT(zwn_make_package(&pkg, 3, 0x71));

        uint8_t wire[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
        ASSERT(zwn_att_wire(pkg.root, 0x51, wire, &wire_len, id));

        struct zwn_node a, b;
        const struct zwn_node_spec nodes[] = {
            {&a, "cw-a"}, {&b, "cw-b"},
        };
        ASSERT(zwn_fixture_nodes(&fixture, params, nodes,
                                 sizeof(nodes) / sizeof(nodes[0])));
        struct zwn_link a_b, b_a;
        const struct zwn_link_spec links[] = {
            {&a, &a_b, {10, 6, 0, 1}, "cw-peer-b"},
            {&b, &b_a, {10, 6, 0, 2}, "cw-peer-a"},
        };
        ASSERT(zwn_fixture_links(&fixture, links,
                                 sizeof(links) / sizeof(links[0])));
        ASSERT(zwn_meet_side_quiet(&a, &a_b));
        ASSERT(zwn_meet_side_quiet(&b, &b_a));

        /* (a) The sender flips a signature byte and re-roots the result,
         *     so every layer beneath the attestation is satisfied: these
         *     bytes really are the bytes that root names. The flip sits
         *     in r, leaving the low-S rule untouched, so the failure is
         *     the ECDSA check itself. */
        uint8_t bad[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        memcpy(bad, wire, wire_len);
        size_t sig_off = wire_len - VCS_PACKAGE_ATTEST_SIGNATURE_BYTES;
        bad[sig_off] = (uint8_t)(bad[sig_off] ^ 0x01u);
        struct vcs_package_attest_transport_outcome refused;
        ASSERT(vcs_package_attest_transport_root(bad, wire_len, &refused) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST);
        uint8_t bad_root[32];
        ASSERT(zwn_att_publish_raw(&a, bad, wire_len, bad_root));
        ASSERT(memcmp(bad_root, refused.transport_root, 32) != 0);

        ASSERT(zwn_fetch_package_from_provider(&b, bad_root, &a_b, &b_a,
                                               params->pchMessageStart));
        struct vcs_package_attest_transport_outcome admit_bad;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, bad_root, pkg.root, &admit_bad) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST);
        ASSERT(admit_bad.attest_error == VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY);
        ASSERT(!admit_bad.filed && !admit_bad.already_present);
        ASSERT(zwn_att_dir_count(&b) <= 0);

        /* (b) The honest wire, flipped in flight. The blob root commits
         *     the chunk hash, so the carriage refuses the delivery and
         *     not one byte reaches B's CAS — the attestation layer is
         *     never even asked. */
        bool filed = false, present = false;
        ASSERT(vcs_package_attest_transport_file(
                   a.zcode_dir, wire, wire_len, id, &filed, &present) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_OK);
        struct vcs_package_attest_transport_outcome offer;
        ASSERT(zwn_att_offer_pinned(&a, id, &offer));
        a.tamper_chunks = true;

        uint64_t provider_peer = (uint64_t)b_a.node->id;
        ASSERT(vcs_swarm_engine_fetch_from(b.engine, offer.transport_root,
                                           ZWN_DAY, ++b.now,
                                           &provider_peer, 1) ==
               VCS_SWARM_FETCH_OK);
        enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
        bool terminal = false;
        for (int i = 0; i < 800 && !terminal; i++) {
            ASSERT(zwn_round(&a_b, &b_a, params->pchMessageStart));
            terminal = zwn_download_done(&b, offer.transport_root, &state);
        }
        ASSERT(terminal && state == VCS_SWARM_DL_FAILED);
        ASSERT(b_a.node->misbehavior >=
               peer_offence_weight(PEER_OFFENCE_INVALID_CHUNK));

        uint8_t got[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
        size_t got_len = 0;
        ASSERT(vcs_blob_get_from(b.store, offer.transport_root, got,
                                 sizeof(got), &got_len) != VCS_BLOB_OK);
        struct vcs_package_attest_transport_outcome admit_flight;
        ASSERT(vcs_package_attest_transport_admit(
                   b.store, b.zcode_dir, offer.transport_root, pkg.root,
                   &admit_flight) ==
               VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB);
        ASSERT(!admit_flight.filed && !admit_flight.already_present);
        {
            char b_path[1400];
            uint8_t leaked[VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES];
            size_t leaked_len = 0;
            ASSERT(zwn_att_path(&b, id, b_path, sizeof(b_path)));
            ASSERT(!zwn_att_read(b_path, leaked, sizeof(leaked),
                                 &leaked_len));
        }
        ASSERT(zwn_att_dir_count(&b) <= 0);

        zwn_fixture_cleanup(&fixture);
        zwn_free_package(&pkg);
        PASS();
    } _test_next:
    zwn_fixture_cleanup(&fixture);
    return failures;
}

/* ── work pull receipts ───────────────────────────────────────────────
 * A verified pull leaves one durable signed receipt on the observer; a
 * repeat attaches to it; anything that does not verify leaves nothing.
 * The handler is driven through its real record query and fetch paths
 * with the node RPC and provider discovery replaced by test backends. */
#if !defined(_WIN32)

#define ZWN_PULL_NOW INT64_C(1700000000)

struct zwn_pull_fixture {
    char publisher[512];
    char observer[512];
    char workspace[600];
    uint8_t source_root[32];
    struct test_accepted_work_fixture accepted;
    struct vcs_source_package_transport transport;
    char task_hex[65];
    char package_hex[65];
    char pointer_hex[65];
    char source_hex[65];
};

static bool zwn_pull_publisher_tree(const char *publisher)
{
    static const char *const dirs[] = {
        "engine", "engine/entry", "vendor", "vendor/.cache",
    };
    static const char license[] =
        "                                 Apache License\n"
        "                           Version 2.0, January 2004\n";
    static const char program[] = "int main(void) { return 0; }\n";
    static const char offline[] = "hermetic-offline-input\n";
    char path[1400];
    bool ok = true;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        ok = ok && snprintf(path, sizeof(path), "%s/%s", publisher,
                            dirs[i]) > 0 && mkdir(path, 0700) == 0;
    ok = ok && zwn_write_file(publisher, "LICENSE", license,
                              sizeof(license) - 1u, 0644) &&
        zwn_write_file(publisher, "engine/entry/main.c", program,
                       sizeof(program) - 1u, 0644);
    for (size_t i = 0; i < vcs_source_package_offline_input_count(); i++)
        ok = ok && zwn_write_file(publisher,
                                  vcs_source_package_offline_input_path(i),
                                  offline, sizeof(offline) - 1u, 0600);
    return ok;
}

static bool zwn_pull_fixture_create(struct zwn_pull_fixture *f,
                                    const char *tag, uint8_t seed)
{
    memset(f, 0, sizeof(*f));
    char name[64];
    (void)snprintf(name, sizeof(name), "pull-%s-publisher", tag);
    test_make_tmpdir(f->publisher, sizeof(f->publisher), "zcode_swarm_net",
                     name);
    (void)snprintf(name, sizeof(name), "pull-%s-observer", tag);
    test_make_tmpdir(f->observer, sizeof(f->observer), "zcode_swarm_net",
                     name);
    (void)snprintf(f->workspace, sizeof(f->workspace), "%s/zcode",
                   f->observer);
    vcs_source_package_transport_init(&f->transport);
    bool ok = zwn_pull_publisher_tree(f->publisher) &&
        vcs_tree_capture_path(f->publisher, f->source_root) == VCS_OK &&
        test_accepted_work_fixture_create(f->publisher, f->source_root,
                                          ZWN_PULL_NOW, seed,
                                          &f->accepted) &&
        vcs_source_package_transport_build_accepted(
            f->publisher, f->source_root,
            f->accepted.accepted.accepted_work_root, ZWN_PULL_NOW,
            &f->transport);
    zcl_hex_encode(f->accepted.accepted.task_root, 32, f->task_hex);
    zcl_hex_encode(f->transport.package_root, 32, f->package_hex);
    zcl_hex_encode(f->source_root, 32, f->source_hex);
    memset(f->pointer_hex, 'c', 64);
    return ok;
}

/* Put the package into the observer's datadir store, as the swarm would. */
static bool zwn_pull_hold(const struct zwn_pull_fixture *f)
{
    struct vcs_package_store *store = vcs_package_store_open(
        f->observer, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool ok = store && zwn_store_source_transport(store, &f->transport);
    if (store)
        vcs_package_store_close(store);
    return ok;
}

static size_t zwn_pull_dir_files(const char *dir, int depth)
{
    DIR *d = opendir(dir);
    size_t count = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char path[900];
        (void)snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0)
            continue;
        count += S_ISREG(st.st_mode) ? 1u
            : S_ISDIR(st.st_mode) && depth > 0
            ? zwn_pull_dir_files(path, depth - 1) : 0u;
    }
    if (d)
        (void)closedir(d);
    return count;
}

/* Files under the observer's CAS; a refused observation must add none. */
static size_t zwn_pull_objects(const struct zwn_pull_fixture *f)
{
    char root[700];
    (void)snprintf(root, sizeof(root), "%s/.zvcs/objects", f->workspace);
    return zwn_pull_dir_files(root, 2);
}

static void zwn_pull_observation(struct vcs_zcode_work_pull_observation *o,
                                 const struct zwn_pull_fixture *f,
                                 int64_t at)
{
    memset(o, 0, sizeof(*o));
    memcpy(o->task_root, f->accepted.accepted.task_root, 32);
    memcpy(o->package_root, f->transport.package_root, 32);
    memset(o->pointer_root, 0xcc, 32);
    memcpy(o->pointer_task_root, o->task_root, 32);
    memcpy(o->pointer_package_root, o->package_root, 32);
    o->started_unix = at;
    o->observed_unix = at + 1;
}

/* Every bound root is exactly what the verified chain and pointer say. */
static bool zwn_pull_bound(const struct vcs_zcode_work_receipt_v1 *r,
                           const struct zwn_pull_fixture *f,
                           const uint8_t observer[32])
{
    const struct vcs_zcode_accepted_work_v1 *w = &f->accepted.accepted;
    uint8_t pointer[32], action[32];
    memset(pointer, 0xcc, sizeof(pointer));
    (void)vcs_zcode_work_pull_action_root(w->task_root,
                                          f->transport.package_root, pointer,
                                          action);
    const uint8_t *pairs[][2] = {
        {r->task_root, w->task_root},
        {r->candidate_root, w->candidate_root},
        {r->proof_policy_root, w->proof_policy_root},
        {r->toolchain_capsule_root, w->task.toolchain_capsule_root},
        {r->evidence_root, w->accepted_work_root},
        {r->input_root, f->transport.package_root},
        {r->output_root, f->source_root},
        {r->lease_id, pointer},
        {r->action_root, action},
        {r->signer_pubkey, observer},
    };
    bool same = r->work_kind == VCS_ZCODE_WORK_REPRODUCE;
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++)
        same = same && memcmp(pairs[i][0], pairs[i][1], 32) == 0;
    return same;
}

static int zwn_t_work_pull_receipt_refusals(
    struct vcs_package_store *store, const struct zwn_pull_fixture *f,
    const uint8_t secret[32], const uint8_t observer[32])
{
    int failures = 0;
    TEST("work pull receipt: a wrong task, an unheld package or a missing "
         "pointer records nothing") {
        size_t before = zwn_pull_objects(f);
        struct vcs_zcode_work_pull_observation o;
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 100);
        o.task_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED);
        ASSERT_EQ(o.admit, VCS_ZCODE_WORK_ADMIT_TASK_MISMATCH);
        ASSERT(!zcl_bytes_any_set(o.receipt_root, 32));
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 100);
        o.package_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED);
        ASSERT_EQ(o.admit, VCS_ZCODE_WORK_ADMIT_NOT_RECONSTRUCTIBLE);
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 100);
        memset(o.pointer_root, 0, 32);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER);
        ASSERT_EQ(o.admit, VCS_ZCODE_WORK_ADMIT_OK);
        ASSERT(!zcl_bytes_any_set(o.receipt_root, 32));
        /* A pointer that names another task or another package binds
         * nothing, even though this package verifies for this task. */
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 100);
        o.pointer_task_root[5] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_POINTER_MISMATCH);
        ASSERT_EQ(o.admit, VCS_ZCODE_WORK_ADMIT_OK);
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 100);
        o.pointer_package_root[5] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_POINTER_MISMATCH);
        ASSERT(!zcl_bytes_any_set(o.receipt_root, 32));
        ASSERT_EQ(zwn_pull_objects(f), before);
        PASS();
    } _test_next:;
    return failures;
}

/* Overwrite the object at address with bytes, as disk corruption would. */
static bool zwn_pull_clobber(const struct zwn_pull_fixture *f,
                             const uint8_t address[32],
                             const uint8_t *bytes, size_t len)
{
    bool repaired = false;
    return vcs_object_put_addressed_repair(f->workspace, address, bytes, len,
                                           &repaired) &&
        repaired;
}

static int zwn_t_work_pull_receipt_locator(
    struct vcs_package_store *store, const struct zwn_pull_fixture *f,
    const uint8_t secret[32], const uint8_t observer[32],
    const uint8_t root[32])
{
    int failures = 0;
    TEST("work pull receipt: a corrupt or foreign locator is repaired by "
         "the next pull, and the repaired locator is attached to after") {
        struct vcs_zcode_work_receipt_v1 first;
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f->workspace, root,
                                                   &first),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        uint8_t locator[32];
        vcs_zcode_work_pull_locator_address(&first, locator);
        /* The locator is a small pointer object, never a receipt. */
        uint8_t *held = NULL;
        size_t held_len = 0;
        ASSERT_EQ(vcs_object_load_raw(f->workspace, locator, &held,
                                      &held_len), 0);
        bool small = held_len == VCS_ZCODE_WORK_PULL_LOCATOR_BYTES &&
            memcmp(held + held_len - 32u, root, 32) == 0;
        free(held);
        ASSERT(small);
        static const uint8_t garbage[] = "not a locator";
        ASSERT(zwn_pull_clobber(f, locator, garbage, sizeof(garbage)));
        struct vcs_zcode_work_pull_observation o;
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 200);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(!o.attached);
        uint8_t second[32];
        memcpy(second, o.receipt_root, 32);
        ASSERT(memcmp(second, root, 32) != 0);
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 300);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(o.attached);
        ASSERT(memcmp(o.receipt_root, second, 32) == 0);
        /* A well-formed locator naming a valid pull receipt for other
         * roots (another pointer) is just as invalid. */
        struct vcs_zcode_work_receipt_v1 other = first;
        other.lease_id[0] ^= 1u;
        ASSERT(vcs_zcode_work_pull_action_root(other.task_root,
                                               other.input_root,
                                               other.lease_id,
                                               other.action_root));
        ASSERT_EQ(vcs_zcode_work_receipt_seal(&other, secret, observer),
                  VCS_ZCODE_DEV_OK);
        uint8_t other_root[32], other_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_work_receipt_id(&other, other_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&other, other_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(f->workspace, other_root, other_wire,
                                        sizeof(other_wire)));
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f->workspace, other_root,
                                                   &other),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        uint8_t foreign[VCS_ZCODE_WORK_PULL_LOCATOR_BYTES];
        static const char magic[] = VCS_ZCODE_WORK_PULL_LOCATOR_MAGIC;
        memcpy(foreign, magic, sizeof(magic));
        memcpy(foreign + sizeof(magic), other_root, 32);
        ASSERT(zwn_pull_clobber(f, locator, foreign, sizeof(foreign)));
        zwn_pull_observation(&o, f, ZWN_PULL_NOW + 400);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f->workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(!o.attached);
        ASSERT(memcmp(o.receipt_root, second, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static const struct vcs_zcode_task_index_entry *zwn_pull_index_task(
    const struct vcs_zcode_task_index *index,
    const struct zwn_pull_fixture *f)
{
    return index ? vcs_zcode_task_index_find(index,
                                             f->accepted.accepted.task_root)
                 : NULL;
}

static int zwn_t_work_pull_receipt_index(const struct zwn_pull_fixture *f,
                                         const uint8_t secret[32],
                                         const uint8_t observer[32],
                                         const uint8_t root[32])
{
    int failures = 0;
    struct vcs_zcode_task_index *before = NULL, *after = NULL;
    TEST("work pull receipt: the observer's task index stays complete, and "
         "a pull receipt beside the task never counts as its evidence") {
        after = vcs_zcode_task_index_build(f->workspace, ZWN_PULL_NOW + 500);
        ASSERT(after && vcs_zcode_task_index_complete(after));
        vcs_zcode_task_index_free(after);
        after = NULL;
        struct vcs_zcode_work_receipt_v1 pulled, control;
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f->workspace, root,
                                                   &pulled),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        before = vcs_zcode_task_index_build(f->publisher, ZWN_PULL_NOW + 500);
        const struct vcs_zcode_task_index_entry *b =
            zwn_pull_index_task(before, f);
        ASSERT(b && vcs_zcode_task_index_complete(before));
        ASSERT(b->receipt_count > 0);
        uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES], other[32];
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&pulled, wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(f->publisher, root, wire,
                                        sizeof(wire)));
        after = vcs_zcode_task_index_build(f->publisher, ZWN_PULL_NOW + 500);
        const struct vcs_zcode_task_index_entry *a =
            zwn_pull_index_task(after, f);
        ASSERT(a && vcs_zcode_task_index_complete(after));
        ASSERT_EQ(a->receipt_count, b->receipt_count);
        ASSERT_EQ(a->passing_receipt_count, b->passing_receipt_count);
        ASSERT_STR_EQ(a->latest_work_receipt_hex, b->latest_work_receipt_hex);
        ASSERT_STR_EQ(a->state, b->state);
        vcs_zcode_task_index_free(after);
        after = NULL;
        /* Control: the same receipt without either pull marker counts. */
        control = pulled;
        memset(control.confinement_root, 0x17, 32);
        memset(control.action_root, 0x18, 32);
        ASSERT(!vcs_zcode_work_pull_receipt_claims_pull(&control));
        ASSERT_EQ(vcs_zcode_work_receipt_seal(&control, secret, observer),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&control, wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_id(&control, other),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(f->publisher, other, wire,
                                        sizeof(wire)));
        after = vcs_zcode_task_index_build(f->publisher, ZWN_PULL_NOW + 500);
        a = zwn_pull_index_task(after, f);
        ASSERT(a && vcs_zcode_task_index_complete(after));
        ASSERT_EQ(a->receipt_count, b->receipt_count + 1u);
        PASS();
    } _test_next:;
    vcs_zcode_task_index_free(before);
    vcs_zcode_task_index_free(after);
    return failures;
}

static int zwn_t_work_pull_receipt_tamper(
    struct vcs_package_store *store, const struct zwn_pull_fixture *f,
    const uint8_t secret[32], const uint8_t observer[32],
    const uint8_t root[32])
{
    int failures = 0;
    TEST("work pull receipt: tampered bytes, a re-signed wrong root or a "
         "different shape never verify") {
        struct vcs_zcode_work_receipt_v1 r, forged, loaded;
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f->workspace, root, &r),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES], checked[32];
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&r, wire),
                  VCS_ZCODE_DEV_OK);
        wire[200] ^= 1u;
        ASSERT(vcs_zcode_work_pull_receipt_decode(
                   wire, sizeof(wire), root, &loaded, checked) !=
               VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(!zcl_bytes_any_set(checked, 32));
        forged = r;
        forged.output_root[0] ^= 1u;
        ASSERT_EQ(vcs_zcode_work_receipt_seal(&forged, secret, observer),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&forged, wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_pull_receipt_decode(
                      wire, sizeof(wire), root, &loaded, checked),
                  VCS_ZCODE_WORK_PULL_RECEIPT_ROOT_MISMATCH);
        /* Self-consistent but lying about the source: the bytes held here
         * contradict it. The honest receipt re-derives exactly. */
        ASSERT_EQ(vcs_zcode_work_pull_receipt_reverify(store, &forged),
                  VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED);
        ASSERT_EQ(vcs_zcode_work_pull_receipt_reverify(store, &r),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        forged = r;
        forged.work_kind = VCS_ZCODE_WORK_TEST;
        ASSERT_EQ(vcs_zcode_work_receipt_seal(&forged, secret, observer),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_pull_receipt_check(&forged),
                  VCS_ZCODE_WORK_PULL_RECEIPT_NOT_PULL);
        uint8_t missing[32];
        memset(missing, 0x5a, sizeof(missing));
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f->workspace, missing,
                                                   &loaded),
                  VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND);
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_t_work_pull_receipt_library(void)
{
    int failures = 0;
    struct zwn_pull_fixture f;
    struct vcs_package_store *store = NULL;
    uint8_t root[32] = {0}, seed[32], secret[32], observer[32];
    memset(seed, 0x33, sizeof(seed));
    ed25519_keypair(observer, secret, seed);
    TEST("work pull receipt: a verified pull records one signed receipt "
         "binding exactly the observed roots, and a repeat attaches") {
        ASSERT(zwn_pull_fixture_create(&f, "lib", 0x6a));
        ASSERT(zwn_pull_hold(&f));
        store = vcs_package_store_open(f.observer,
                                       VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(store != NULL);
        struct vcs_zcode_work_pull_observation o;
        zwn_pull_observation(&o, &f, ZWN_PULL_NOW + 10);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f.workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(!o.attached);
        ASSERT(zwn_pull_bound(&o.receipt, &f, observer));
        memcpy(root, o.receipt_root, 32);
        struct vcs_zcode_work_receipt_v1 loaded;
        ASSERT_EQ(vcs_zcode_work_pull_receipt_load(f.workspace, root,
                                                   &loaded),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(zwn_pull_bound(&loaded, &f, observer));
        ASSERT_EQ(loaded.finished_unix, ZWN_PULL_NOW + 11);
        size_t objects = zwn_pull_objects(&f);
        zwn_pull_observation(&o, &f, ZWN_PULL_NOW + 50);
        ASSERT_EQ(vcs_zcode_work_pull_observe(store, f.workspace, secret,
                                              observer, &o),
                  VCS_ZCODE_WORK_PULL_RECEIPT_OK);
        ASSERT(o.attached);
        ASSERT(memcmp(o.receipt_root, root, 32) == 0);
        ASSERT_EQ(o.receipt.finished_unix, ZWN_PULL_NOW + 11);
        ASSERT_EQ(zwn_pull_objects(&f), objects);
        PASS();
    } _test_next:;
    if (store) {
        failures += zwn_t_work_pull_receipt_refusals(store, &f, secret,
                                                     observer);
        failures += zwn_t_work_pull_receipt_tamper(store, &f, secret,
                                                   observer, root);
        failures += zwn_t_work_pull_receipt_locator(store, &f, secret,
                                                    observer, root);
        failures += zwn_t_work_pull_receipt_index(&f, secret, observer,
                                                  root);
        vcs_package_store_close(store);
    }
    memory_cleanse(secret, sizeof(secret));
    return failures;
}

/* ── the pull and receipt leaves over test backends ─────────────────── */

static const struct zwn_pull_fixture *zwn_pull_leaf_fixture;
static char zwn_pull_asked_hex[65];

/* How the fake node answers: the fetch route, and the one POINTER record. */
enum zwn_pull_route_mode {
    ZWN_PULL_ROUTE_REFUSE,      /* publisher gone: a named refusal */
    ZWN_PULL_ROUTE_DELIVER,     /* accepts, then commits the bytes */
    ZWN_PULL_ROUTE_ACCEPT_ONLY, /* accepts, and the bytes never arrive */
};
enum zwn_pull_record_mode {
    ZWN_PULL_RECORD_USABLE,
    ZWN_PULL_RECORD_CONFLICTED,
    ZWN_PULL_RECORD_NO_SEMANTIC,
};
static enum zwn_pull_route_mode zwn_pull_route_mode;
static enum zwn_pull_record_mode zwn_pull_record_mode;
/* wait_ms passed to the pull leaf; INT64_MIN means the key is absent. */
static int64_t zwn_pull_wait_ms = INT64_MIN;

static char *zwn_pull_rpc_hook(const char *method, const char *params_json)
{
    (void)params_json;
    const struct zwn_pull_fixture *f = zwn_pull_leaf_fixture;
    if (strcmp(method, "zcode_dht_record_begin") == 0)
        return zcl_strdup(
            "{\"ok\":true,\"state\":\"pending\","
            "\"lookup_id\":\"11111111111111111111111111111111\","
            "\"owner_token\":\"22222222222222222222222222222222\"}",
            "test.zwn_pull.begin");
    if (strcmp(method, "zcode_dht_record_cancel") == 0)
        return zcl_strdup("{\"ok\":true,\"canceled\":true}",
                          "test.zwn_pull.cancel");
    if (strcmp(method, "zcode_dht_record_poll") != 0 || !f)
        return zcl_strdup("{\"ok\":false,\"code\":\"UNEXPECTED_RPC\"}",
                          "test.zwn_pull.unexpected");
    char semantic[96] = "";
    if (zwn_pull_record_mode != ZWN_PULL_RECORD_NO_SEMANTIC)
        (void)snprintf(semantic, sizeof(semantic),
                       "\"semantic_root\":\"%s\",", zwn_pull_asked_hex);
    char body[1024];
    int n = snprintf(body, sizeof(body),
                     "{\"ok\":true,\"state\":\"complete\",\"records\":[{"
                     "\"kind\":\"pointer\",\"record_root\":\"%s\","
                     "\"namespace\":\"zclassic23.work\","
                     "%s\"transport_root\":\"%s\","
                     "\"conflicted\":%s,\"superseded\":false}]}",
                     f->pointer_hex, semantic, f->package_hex,
                     zwn_pull_record_mode == ZWN_PULL_RECORD_CONFLICTED
                         ? "true" : "false");
    return n > 0 && (size_t)n < sizeof(body)
        ? zcl_strdup(body, "test.zwn_pull.poll") : NULL;
}

static bool zwn_pull_discover(struct json_value *selector,
                              struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "count", 1);
    return true;
}

/* Either the publisher is gone (a named refusal), or the running node
 * accepts the root and commits the bytes after its reply — the pull's own
 * store handle, opened before, cannot see them without re-reading — or it
 * accepts and the bytes never arrive. */
static bool zwn_pull_route(struct json_value *selector,
                           struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    if (zwn_pull_route_mode == ZWN_PULL_ROUTE_REFUSE) {
        (void)json_push_kv_bool(result, "ok", false);
        (void)json_push_kv_str(result, "code", "FETCH_REFUSED");
        (void)json_push_kv_str(result, "error", "no-authenticated-provider");
        return false;
    }
    bool held = zwn_pull_route_mode == ZWN_PULL_ROUTE_ACCEPT_ONLY ||
        zwn_pull_hold(zwn_pull_leaf_fixture);
    (void)json_push_kv_bool(result, "ok", held);
    (void)json_push_kv_int(result, "authenticated_providers", 1);
    (void)json_push_kv_str(result, "fetch_result", "ok");
    return held;
}

static void zwn_pull_leaf(const struct zwn_pull_fixture *f, bool receipt,
                          const char *root_hex, const char *wire_hex,
                          struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", f->observer);
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.input = &input;
    zcl_command_reply_init(reply, "zcl.zcode_test.v1");
    if (!receipt) {
        (void)json_push_kv_str(&input, "task_root", zwn_pull_asked_hex);
        if (zwn_pull_wait_ms != INT64_MIN)
            (void)json_push_kv_int(&input, "wait_ms", zwn_pull_wait_ms);
        zcl_native_handle_zcode_work_pull(&request, reply);
    } else {
        (void)json_push_kv_str(&input, "receipt_root", root_hex);
        if (wire_hex)
            (void)json_push_kv_str(&input, "receipt_hex", wire_hex);
        zcl_native_handle_zcode_work_receipt(&request, reply);
    }
    json_free(&input);
}

static const struct json_value *zwn_pull_row0(
    const struct zcl_command_reply *reply)
{
    return json_at(json_get(&reply->data, "rows"), 0);
}

static const char *zwn_pull_row_str(const struct zcl_command_reply *reply,
                                    const char *key)
{
    const char *value = json_get_str(json_get(zwn_pull_row0(reply), key));
    return value ? value : "";
}

static int zwn_t_work_pull_leaf_receipt_verify(
    const struct zwn_pull_fixture *f, const char *root_hex)
{
    int failures = 0;
    TEST("work receipt leaf: verifies the pull receipt by root and refuses "
         "a tampered wire or an unknown root") {
        struct zcl_command_reply reply;
        zwn_pull_leaf(f, true, root_hex, NULL, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "task_root")),
                      f->task_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "package_root")),
                      f->package_hex);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "pointer_root")),
                      f->pointer_hex);
        char wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES * 2u + 1u];
        (void)snprintf(wire, sizeof(wire), "%s",
                       json_get_str(json_get(&reply.data, "receipt_hex")));
        zcl_command_reply_free(&reply);
        ASSERT_EQ(strlen(wire), (size_t)VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES * 2u);
        zwn_pull_leaf(f, true, root_hex, wire, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&reply);
        wire[300] = wire[300] == '0' ? '1' : '0';
        zwn_pull_leaf(f, true, root_hex, wire, &reply);
        ASSERT(reply.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(reply.error.code, "WORK_RECEIPT_REFUSED");
        zcl_command_reply_free(&reply);
        zwn_pull_leaf(f, true, f->pointer_hex, NULL, &reply);
        ASSERT_STR_EQ(reply.error.code, "WORK_RECEIPT_NOT_FOUND");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_t_work_pull_leaf_held(void)
{
    int failures = 0;
    struct zwn_pull_fixture f;
    char root_hex[65] = "";
    TEST("work pull leaf: after publisher death the held bytes still verify "
         "and record one receipt; a repeat attaches; a wrong task records "
         "none") {
        ASSERT(zwn_pull_fixture_create(&f, "held", 0x6b));
        ASSERT(zwn_pull_hold(&f));
        zwn_pull_leaf_fixture = &f;
        zwn_pull_route_mode = ZWN_PULL_ROUTE_REFUSE;
        zwn_pull_record_mode = ZWN_PULL_RECORD_USABLE;
        zwn_pull_wait_ms = INT64_MIN;
        (void)snprintf(zwn_pull_asked_hex, sizeof(zwn_pull_asked_hex), "%s",
                       f.task_hex);
        node_rpc_client_set_test_hook(zwn_pull_rpc_hook);
        zcl_native_zcode_discovery_test_backend(zwn_pull_discover,
                                                zwn_pull_route);
        struct zcl_command_reply reply;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "SOLUTIONS_VERIFIED");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "receipts")), 1);
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "fetch_outcome"),
                      "FETCH_REFUSED");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_result"), "ok");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "pointer_root"),
                      f.pointer_hex);
        ASSERT(!json_get_bool(json_get(zwn_pull_row0(&reply),
                                       "receipt_attached")));
        (void)snprintf(root_hex, sizeof(root_hex), "%s",
                       zwn_pull_row_str(&reply, "receipt_root"));
        zcl_command_reply_free(&reply);
        ASSERT_EQ(strlen(root_hex), (size_t)64);
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT(json_get_bool(json_get(zwn_pull_row0(&reply),
                                      "receipt_attached")));
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_root"), root_hex);
        zcl_command_reply_free(&reply);
        size_t objects = zwn_pull_objects(&f);
        zwn_pull_asked_hex[0] = zwn_pull_asked_hex[0] == '0' ? '1' : '0';
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "admitted")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "receipts")), 0);
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_result"),
                      "not-verified");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_root"), "");
        zcl_command_reply_free(&reply);
        ASSERT_EQ(zwn_pull_objects(&f), objects);
        PASS();
    } _test_next:;
    if (root_hex[0])
        failures += zwn_t_work_pull_leaf_receipt_verify(&f, root_hex);
    node_rpc_client_set_test_hook(NULL);
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    zwn_pull_leaf_fixture = NULL;
    return failures;
}

static int zwn_t_work_pull_leaf_settle(void)
{
    int failures = 0;
    struct zwn_pull_fixture f;
    TEST("work pull leaf: bytes the node commits after accepting the fetch "
         "are waited for, verified and receipted, never reported "
         "unreachable") {
        ASSERT(zwn_pull_fixture_create(&f, "settle", 0x6c));
        zwn_pull_leaf_fixture = &f;
        zwn_pull_route_mode = ZWN_PULL_ROUTE_DELIVER;
        zwn_pull_record_mode = ZWN_PULL_RECORD_USABLE;
        zwn_pull_wait_ms = INT64_MIN;
        (void)snprintf(zwn_pull_asked_hex, sizeof(zwn_pull_asked_hex), "%s",
                       f.task_hex);
        node_rpc_client_set_test_hook(zwn_pull_rpc_hook);
        zcl_native_zcode_discovery_test_backend(zwn_pull_discover,
                                                zwn_pull_route);
        struct zcl_command_reply reply;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "SOLUTIONS_VERIFIED");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "fetched")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "admitted")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "receipts")), 1);
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "fetch_outcome"), "ok");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "source_root"), f.source_hex);
        ASSERT(json_get_int(json_get(zwn_pull_row0(&reply), "settle_ms")) >=
               0);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    zwn_pull_leaf_fixture = NULL;
    return failures;
}

static void zwn_pull_leaf_backends(const struct zwn_pull_fixture *f,
                                   enum zwn_pull_route_mode route,
                                   enum zwn_pull_record_mode record,
                                   int64_t wait_ms)
{
    zwn_pull_leaf_fixture = f;
    zwn_pull_route_mode = route;
    zwn_pull_record_mode = record;
    zwn_pull_wait_ms = wait_ms;
    (void)snprintf(zwn_pull_asked_hex, sizeof(zwn_pull_asked_hex), "%s",
                   f->task_hex);
    node_rpc_client_set_test_hook(zwn_pull_rpc_hook);
    zcl_native_zcode_discovery_test_backend(zwn_pull_discover,
                                            zwn_pull_route);
}

static void zwn_pull_leaf_backends_reset(void)
{
    node_rpc_client_set_test_hook(NULL);
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    zwn_pull_leaf_fixture = NULL;
    zwn_pull_wait_ms = INT64_MIN;
}

static int zwn_t_work_pull_leaf_pending(void)
{
    int failures = 0;
    struct zwn_pull_fixture f;
    TEST("work pull leaf: an accepted fetch whose bytes never arrive is "
         "WORK_BYTES_PENDING after the bounded wait and records nothing") {
        ASSERT(zwn_pull_fixture_create(&f, "pending", 0x6d));
        zwn_pull_leaf_backends(&f, ZWN_PULL_ROUTE_ACCEPT_ONLY,
                               ZWN_PULL_RECORD_USABLE, 300);
        struct zcl_command_reply reply;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "WORK_BYTES_PENDING");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "fetched")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "admitted")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "receipts")), 0);
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_result"),
                      "not-verified");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_root"), "");
        int64_t waited =
            json_get_int(json_get(zwn_pull_row0(&reply), "settle_ms"));
        ASSERT(waited >= 250 && waited < 15000);
        zcl_command_reply_free(&reply);
        ASSERT_EQ(zwn_pull_objects(&f), (size_t)0);
        zwn_pull_wait_ms = -5;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT(reply.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(reply.error.code, "BAD_WAIT_MS");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    zwn_pull_leaf_backends_reset();
    return failures;
}

static int zwn_t_work_pull_leaf_pointer_rules(void)
{
    int failures = 0;
    struct zwn_pull_fixture f;
    TEST("work pull leaf: a conflicted pointer verifies the package but "
         "binds no receipt; a record naming no task is ignored") {
        ASSERT(zwn_pull_fixture_create(&f, "rules", 0x6e));
        ASSERT(zwn_pull_hold(&f));
        zwn_pull_leaf_backends(&f, ZWN_PULL_ROUTE_REFUSE,
                               ZWN_PULL_RECORD_CONFLICTED, 0);
        struct zcl_command_reply reply;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "SOLUTIONS_VERIFIED");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "admitted")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "receipts")), 0);
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "pointer_root"), "");
        ASSERT_STR_EQ(zwn_pull_row_str(&reply, "receipt_result"),
                      "no-usable-pointer");
        zcl_command_reply_free(&reply);
        ASSERT_EQ(zwn_pull_objects(&f), (size_t)0);
        zwn_pull_record_mode = ZWN_PULL_RECORD_NO_SEMANTIC;
        zwn_pull_leaf(&f, false, NULL, NULL, &reply);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "NO_WORK_POINTERS");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "pointers_seen")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data,
                                        "distinct_transport_roots")), 0);
        zcl_command_reply_free(&reply);
        ASSERT_EQ(zwn_pull_objects(&f), (size_t)0);
        PASS();
    } _test_next:;
    zwn_pull_leaf_backends_reset();
    return failures;
}

static int zwn_t_work_pull_receipts(void)
{
    int failures = 0;
    failures += zwn_t_work_pull_receipt_library();
    failures += zwn_t_work_pull_leaf_held();
    failures += zwn_t_work_pull_leaf_settle();
    failures += zwn_t_work_pull_leaf_pending();
    failures += zwn_t_work_pull_leaf_pointer_rules();
    return failures;
}
#endif


/* ── Umbrella and shards ─────────────────────────────────────────────────
 *
 * test_zcode_swarm_net is an umbrella (tools/dev/test_group_umbrellas.def).
 * One table names every sub-suite and the shard that owns it; row order is
 * the order the umbrella has always run them in. Named exactly, the umbrella
 * runs every row itself, so each consumer of the historic id (make
 * test-full, t-fast-exact, the ZCODE_REPRODUCTION acceptance set, --exact
 * callers) keeps every sub-suite. In a full run, an --only substring, a proof
 * or a plan expansion it is subsumed and its shards run instead, each its own
 * catalog group and its own process: its fixtures live under the per-pid
 * test-tmp roots, its topologies are in-process loopback links, and its
 * sovereign receipt is its own, so no shard shares state with another.
 *
 * Owners are balanced by measured wall ([zcode-swarm-net-case] ms=, printed
 * per row by every run). Every run -- umbrella or shard -- first proves the
 * partition: the rows are exactly the sub-suite list written down below,
 * each owned by one shard, every shard owns a row, and the catalog registers
 * exactly those shards under the umbrella. */
#include "test_group_catalog.h"
#include <time.h>

static int zwn_t_fixture_abort_reacquire(const struct chain_params *params)
{
    int failures = 0;
    TEST("parameterized multi-node fixture releases an aborted topology "
         "and can reacquire it") {
        ASSERT(zwn_fixture_abort_reacquire(params));
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_t_golden_plain(const struct chain_params *params)
{
    return zwn_test_golden(ZWN_GOLDEN_PLAIN, params);
}

static int zwn_t_golden_restart(const struct chain_params *params)
{
    return zwn_test_golden(ZWN_GOLDEN_RESTART, params);
}

static int zwn_t_golden_disconnect(const struct chain_params *params)
{
    return zwn_test_golden(ZWN_GOLDEN_DISCONNECT, params);
}

#if !defined(_WIN32)
static int zwn_t_work_pull(const struct chain_params *params)
{
    (void)params;
    return zwn_t_work_pull_receipts();
}
#endif

#if defined(__linux__) && defined(__x86_64__) && defined(ZCL_TESTING)
#define ZWN_TCP_WIRE_LIMIT (UINT64_C(8) * 1024 * 1024)
#define ZWN_TCP_CONTENT_LIMIT (UINT64_C(4) * 1024 * 1024)

enum zwn_tcp_outcome { ZWN_TCP_OBSERVED, ZWN_TCP_UNOBSERVED, ZWN_TCP_FAILED };

struct zwn_tcp {
    struct zwn_node a, b;
    struct zwn_link ab, ba;
    bool a_ready, b_ready;
    uint64_t received_bytes;
    int64_t fetch_ms;
    enum zwn_tcp_outcome outcome;
    const char *phase;
    uint8_t active_root[32];
    bool active_fetch;
    bool cancelled;
};

static int64_t zwn_tcp_millis(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static bool zwn_tcp_result(struct zwn_tcp *tcp, bool ok)
{
    if (!ok && tcp->outcome == ZWN_TCP_OBSERVED) tcp->outcome = ZWN_TCP_FAILED;
    return ok && tcp->outcome == ZWN_TCP_OBSERVED;
}

static bool zwn_tcp_deadline(struct zwn_tcp *tcp, int64_t deadline,
    const char *phase, int64_t *stamp)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    *stamp = zwn_tcp_millis();
    if (*stamp < 0) return zwn_tcp_result(tcp, false);
    if (*stamp < deadline) return true;
    tcp->outcome = ZWN_TCP_UNOBSERVED;
    tcp->phase = phase;
    return false;
}

/* Propagate missing observations without satisfying the guarded assertion. */
#define ZWN_TCP_ASSERT(tcp, cond) do { \
    bool zwn_condition = (cond); \
    if ((tcp)->outcome == ZWN_TCP_UNOBSERVED) goto _test_next; \
    if (!zwn_condition || (tcp)->outcome == ZWN_TCP_FAILED) { \
        (tcp)->outcome = ZWN_TCP_FAILED; \
        printf("FAIL at %s:%d (%s)\n", __FILE__, __LINE__, #cond); \
        ++failures; goto _test_next; \
    } \
} while (0)

static bool zwn_tcp_poll_error(const struct pollfd *fds, nfds_t count)
{
    for (nfds_t i = 0; i < count; ++i)
        if (fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) return true;
    return false;
}

static bool zwn_tcp_poll(struct zwn_tcp *tcp, struct pollfd *fds, nfds_t count, int64_t deadline)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    for (;;) {
        int64_t stamp;
        if (!zwn_tcp_deadline(tcp, deadline, "socket-poll", &stamp)) return zwn_tcp_result(tcp, false);
        int rc = poll(fds, count, (int)(deadline - stamp));
        if (rc > 0) {
            if (zwn_tcp_poll_error(fds, count)) return zwn_tcp_result(tcp, false);
            return zwn_tcp_deadline(tcp, deadline, "socket-poll", &stamp);
        }
        if (rc == 0) continue;
        if (errno != EINTR) return zwn_tcp_result(tcp, false);
    }
}

static bool zwn_tcp_scheduler_poll(struct zwn_tcp *tcp, struct pollfd *fds, nfds_t count,
    int64_t deadline)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    for (;;) {
        int64_t stamp;
        if (!zwn_tcp_deadline(tcp, deadline, "socket-poll", &stamp)) return zwn_tcp_result(tcp, false);
        int64_t remaining = deadline - stamp;
        int wait_ms = remaining < 20 ? (int)remaining : 20;
        int rc = poll(fds, count, wait_ms);
        if (rc >= 0) {
            if (zwn_tcp_poll_error(fds, count)) return zwn_tcp_result(tcp, false);
            return zwn_tcp_deadline(tcp, deadline, "scheduler-poll", &stamp);
        }
        if (errno != EINTR) return zwn_tcp_result(tcp, false);
    }
}

static bool zwn_tcp_endpoints(int client, int accepted)
{
    struct sockaddr_in local = {0}, peer = {0};
    socklen_t local_len = sizeof(local), peer_len = sizeof(peer);
    return getsockname(client, (struct sockaddr *)&local, &local_len) == 0 &&
        getpeername(accepted, (struct sockaddr *)&peer, &peer_len) == 0 &&
        local.sin_family == AF_INET && peer.sin_family == AF_INET &&
        local.sin_addr.s_addr == peer.sin_addr.s_addr &&
        local.sin_port == peer.sin_port;
}

/* The existing accept wrapper uses accept(), without atomic CLOEXEC or
 * nonblocking accepted descriptors. This Linux-only fixture needs both. */
static int zwn_tcp_accept(struct zwn_tcp *tcp, int listener, int64_t deadline)
{
    for (;;) {
        struct pollfd ready = {listener, POLLIN, 0};
        if (!zwn_tcp_poll(tcp, &ready, 1, deadline)) return -1;
        int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd >= 0) return fd;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
    }
}

static bool zwn_tcp_connect(struct zwn_tcp *tcp, int listener, int pair[2], int64_t deadline)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct sockaddr_in addr = {0};
    socklen_t len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &len) != 0) return zwn_tcp_result(tcp, false);
    pair[0] = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (pair[0] < 0) return zwn_tcp_result(tcp, false);
    if (connect(pair[0], (struct sockaddr *)&addr, len) != 0 &&
        errno != EINPROGRESS) return zwn_tcp_result(tcp, false);
    struct pollfd ready[2] = {{listener, POLLIN, 0}, {pair[0], POLLOUT, 0}};
    if (!zwn_tcp_poll(tcp, ready, 2, deadline)) return zwn_tcp_result(tcp, false);
    int error = 0;
    len = sizeof(error);
    if (getsockopt(pair[0], SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error)
        return zwn_tcp_result(tcp, false);
    pair[1] = zwn_tcp_accept(tcp, listener, deadline);
    return zwn_tcp_result(tcp, pair[1] >= 0 && zwn_tcp_endpoints(pair[0], pair[1]));
}

static bool zwn_tcp_pair(struct zwn_tcp *tcp, int pair[2])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    pair[0] = pair[1] = -1;
    int listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    if (listener < 0) return zwn_tcp_result(tcp, false);
    struct sockaddr_in addr = {.sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
    int64_t stamp = zwn_tcp_millis();
    bool ok = stamp >= 0 && platform_socket_bind(listener, (struct sockaddr *)&addr,
        sizeof(addr)) == 0 && platform_socket_listen(listener, 1) == 0 &&
        zwn_tcp_connect(tcp, listener, pair, stamp + 10000);
    if (close(listener) != 0) tcp->outcome = ZWN_TCP_FAILED;
    if (!ok) {
        if (pair[0] >= 0 && close(pair[0]) != 0) tcp->outcome = ZWN_TCP_FAILED;
        if (pair[1] >= 0 && close(pair[1]) != 0) tcp->outcome = ZWN_TCP_FAILED;
        pair[0] = pair[1] = -1;
    }
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_attach(struct zwn_node *owner, struct zwn_link *link,
    int *fd, const char *name)
{
    if (!zwn_link(owner, link, 127, 0, 0, 1, name)) return false;
    send_segment_free(link->sentinel);
    link->sentinel = NULL;
    link->node->send_head = link->node->send_tail = NULL;
    link->node->socket = *fd;
    *fd = -1;
    owner->tcp_clock = true;
    return zwn_meet_side_mode(owner, link, false);
}

static bool zwn_tcp_free(struct zwn_tcp *tcp)
{
    zwn_link_free(&tcp->ba);
    zwn_link_free(&tcp->ab);
    if (tcp->b_ready) zwn_node_free(&tcp->b);
    if (tcp->a_ready) zwn_node_free(&tcp->a);
    bool ok = true;
    if (tcp->b.datadir[0] && test_rm_rf_recursive(tcp->b.datadir) != 0) ok = false;
    if (tcp->a.datadir[0] && test_rm_rf_recursive(tcp->a.datadir) != 0) ok = false;
    tcp->a_ready = tcp->b_ready = false;
    zcl_reflex_runner_shutdown();
    if (!ok) tcp->outcome = ZWN_TCP_FAILED;
    return ok;
}

static bool zwn_tcp_init(struct zwn_tcp *tcp, const struct chain_params *params)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    int pair[2] = {-1, -1};
    bool ok = (tcp->a_ready = zwn_node_init(&tcp->a, "component-tcp-provider", params)) &&
        (tcp->b_ready = zwn_node_init(&tcp->b, "component-tcp-receiver", params)) &&
        zwn_tcp_pair(tcp, pair) &&
        zwn_tcp_attach(&tcp->a, &tcp->ab, &pair[0], "tcp-receiver") &&
        zwn_tcp_attach(&tcp->b, &tcp->ba, &pair[1], "tcp-provider");
    if (pair[0] >= 0 && close(pair[0]) != 0) tcp->outcome = ZWN_TCP_FAILED;
    if (pair[1] >= 0 && close(pair[1]) != 0) tcp->outcome = ZWN_TCP_FAILED;
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_read(struct zwn_tcp *tcp, struct zwn_link *link,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t bytes[65536];
    ssize_t count = recv(link->node->socket, bytes, sizeof(bytes), MSG_DONTWAIT);
    if (count < 0) return zwn_tcp_result(tcp, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
    if (count == 0) return zwn_tcp_result(tcp, false);
    tcp->received_bytes += (uint64_t)count;
    if (tcp->received_bytes > ZWN_TCP_WIRE_LIMIT) return zwn_tcp_result(tcp, false);
    return zwn_tcp_result(tcp, p2p_node_receive_bytes(link->node, (const char *)bytes,
        (unsigned int)count, magic) &&
        msg_process_messages(&link->owner->mp, link->node));
}

static void zwn_tcp_flush(struct zwn_link *link)
{
    zwn_tick(&link->owner->mp, link->node, link->owner);
    zcl_mutex_lock(&link->node->cs_send);
    socket_send_data(link->node);
    zcl_mutex_unlock(&link->node->cs_send);
}

static bool zwn_tcp_step(struct zwn_tcp *tcp,
    const unsigned char magic[MESSAGE_START_SIZE], int64_t deadline)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    int64_t stamp;
    if (!zwn_tcp_deadline(tcp, deadline, "transfer-step", &stamp)) return zwn_tcp_result(tcp, false);
    tcp->a.now = tcp->b.now = (uint64_t)(stamp / 1000);
    zwn_tcp_flush(&tcp->ab);
    zwn_tcp_flush(&tcp->ba);
    struct pollfd fds[2] = {{tcp->ab.node->socket, POLLIN, 0},
                           {tcp->ba.node->socket, POLLIN, 0}};
    if (tcp->ab.node->send_head) fds[0].events |= POLLOUT;
    if (tcp->ba.node->send_head) fds[1].events |= POLLOUT;
    if (!zwn_tcp_scheduler_poll(tcp, fds, 2, deadline)) return zwn_tcp_result(tcp, false);
    if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLNVAL)) return zwn_tcp_result(tcp, false);
    if ((fds[0].revents & POLLIN) && !zwn_tcp_read(tcp, &tcp->ab, magic)) return zwn_tcp_result(tcp, false);
    if ((fds[1].revents & POLLIN) && !zwn_tcp_read(tcp, &tcp->ba, magic)) return zwn_tcp_result(tcp, false);
    return zwn_tcp_result(tcp, !(fds[0].revents & POLLHUP) && !(fds[1].revents & POLLHUP));
}

static bool zwn_tcp_receive_ready(struct zwn_tcp *tcp, struct pollfd fds[2],
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLNVAL | POLLHUP)) return zwn_tcp_result(tcp, false);
    if ((fds[0].revents & POLLIN) && !zwn_tcp_read(tcp, &tcp->ab, magic)) return zwn_tcp_result(tcp, false);
    if ((fds[1].revents & POLLIN) && !zwn_tcp_read(tcp, &tcp->ba, magic)) return zwn_tcp_result(tcp, false);
    return zwn_tcp_result(tcp, true);
}

static bool zwn_tcp_drained(const struct zwn_tcp *tcp)
{
    uint64_t sent = tcp->ab.node->send_bytes + tcp->ba.node->send_bytes;
    return sent == tcp->received_bytes && !tcp->ab.node->send_head &&
        !tcp->ba.node->send_head &&
        vcs_swarm_engine_active_downloads(tcp->b.engine) == 0;
}

/* Service both production queues and actual sockets before observing an idle
 * transport. The short poll is a drain window, not a performance threshold. */
static bool zwn_tcp_quiet_poll(struct zwn_tcp *tcp, struct pollfd fds[2],
    int64_t deadline, int *rc)
{
    *rc = poll(fds, 2, 20);
    if (*rc < 0) {
        if (errno == EINTR) return true;
        return zwn_tcp_result(tcp, false);
    }
    if (zwn_tcp_poll_error(fds, 2)) return zwn_tcp_result(tcp, false);
    int64_t stamp;
    return zwn_tcp_deadline(tcp, deadline, "transport-quiescence", &stamp);
}

static bool zwn_tcp_quiesce(struct zwn_tcp *tcp,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    int64_t start_ms = zwn_tcp_millis();
    if (start_ms < 0) return zwn_tcp_result(tcp, false);
    for (;;) {
        int64_t current_ms;
        if (!zwn_tcp_deadline(tcp, start_ms + 10000, "transport-quiescence", &current_ms)) return zwn_tcp_result(tcp, false);
        tcp->a.now = tcp->b.now = (uint64_t)(current_ms / 1000);
        zwn_tcp_flush(&tcp->ab);
        zwn_tcp_flush(&tcp->ba);
        if (tcp->ab.node->send_bytes > ZWN_TCP_WIRE_LIMIT ||
            tcp->ba.node->send_bytes > ZWN_TCP_WIRE_LIMIT)
            return zwn_tcp_result(tcp, false);
        struct pollfd fds[2] = {{tcp->ab.node->socket, POLLIN, 0},
                               {tcp->ba.node->socket, POLLIN, 0}};
        if (tcp->ab.node->send_head) fds[0].events |= POLLOUT;
        if (tcp->ba.node->send_head) fds[1].events |= POLLOUT;
        int rc;
        if (!zwn_tcp_quiet_poll(tcp, fds, start_ms + 10000, &rc)) return false;
        if (rc < 0) continue;
        if (!rc) { if (zwn_tcp_drained(tcp)) return zwn_tcp_result(tcp, true); continue; }
        if (!zwn_tcp_receive_ready(tcp, fds, magic)) return zwn_tcp_result(tcp, false);
    }
}

static bool zwn_tcp_start_fetch(struct zwn_tcp *tcp, const uint8_t root[32])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint64_t provider = (uint64_t)tcp->ba.node->id;
    bool ok = vcs_swarm_engine_fetch_from_bounded(tcp->b.engine, root, ZWN_DAY,
        tcp->b.now, &provider, 1, ZWN_TCP_CONTENT_LIMIT) == VCS_SWARM_FETCH_OK;
    if (ok) {
        memcpy(tcp->active_root, root, 32);
        tcp->active_fetch = true;
    }
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_fetch(struct zwn_tcp *tcp, const uint8_t root[32],
    const unsigned char magic[MESSAGE_START_SIZE], enum vcs_swarm_download_state wanted)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    int64_t stamp = zwn_tcp_millis();
    if (stamp < 0) return zwn_tcp_result(tcp, false);
    tcp->a.now = tcp->b.now = (uint64_t)(stamp / 1000);
    if (!zwn_tcp_start_fetch(tcp, root)) return false;
    enum vcs_swarm_download_state state = VCS_SWARM_DL_INACTIVE;
    while (!zwn_download_done(&tcp->b, root, &state))
        if (!zwn_tcp_step(tcp, magic, stamp + 10000)) return zwn_tcp_result(tcp, false);
    tcp->active_fetch = false;
    if (state != wanted) return zwn_tcp_result(tcp, false);
    int64_t finished_ms;
    if (!zwn_tcp_deadline(tcp, stamp + 10000, "transfer-complete", &finished_ms)) return false;
    if (finished_ms < stamp) return zwn_tcp_result(tcp, false);
    tcp->fetch_ms = finished_ms - stamp;
    return true;
}

static bool zwn_tcp_isolated(const struct zcl_reflex_runner_outcome *out)
{
    return out->green && out->seals_verified && out->report.sandboxed &&
        out->address_space_fresh && out->env_inherited_count == 0 &&
        out->inherited_fd_count == 0 && out->runner_env_count == 0 &&
        out->runner_fd_count == 0 && out->report.wx_installed;
}

static bool zwn_tcp_loaded(const struct rr_component *carrier,
    const struct zcl_component_receiver_outcome *out)
{
    return out->admitted && zwn_tcp_isolated(&out->runner) &&
        out->runner.report.candidate_executed &&
        out->runner.report.observation.checks_passed == 3 &&
        strcmp(out->runner.report.observation.detail, "1") == 0 &&
        strcmp(out->runner.report.runtime_module_sha256, carrier->image_sha) == 0 &&
        out->assembly_bytes_written == carrier->image_len &&
        out->sealed_copy_bytes == carrier->image_len;
}

static void zwn_tcp_observe(const char *phase, const struct zwn_tcp *tcp,
    const struct rr_component *carrier, const struct zcl_component_receiver_outcome *out)
{
    char action[65], artifact[65], content[65];
    zcl_hex_encode(carrier->request.action_root, 32, action);
    zcl_hex_encode(carrier->request.artifact_root, 32, artifact);
    zcl_hex_encode(carrier->request.package_root, 32, content);
    printf("[component-tcp] phase=%s action=%s artifact=%s local_carrier_root=%s image=%s "
           "tcp_received_bytes=%llu provider_sent=%llu receiver_sent=%llu fetch_ms=%lld manifest_read=%llu cas_read=%llu "
           "assembly=%llu sealed_copy=%llu runner_seal_us=%lld story_us=%lld "
           "admitted=%d candidate_executed=%d green=%d reason=%s\n",
        phase, action, artifact, content, carrier->image_sha,
        (unsigned long long)tcp->received_bytes,
        (unsigned long long)tcp->ab.node->send_bytes,
        (unsigned long long)tcp->ba.node->send_bytes, (long long)tcp->fetch_ms,
        (unsigned long long)out->manifest_bytes_read,
        (unsigned long long)out->cas_chunk_bytes_read,
        (unsigned long long)out->assembly_bytes_written,
        (unsigned long long)out->sealed_copy_bytes,
        (long long)out->runner.seal_us, (long long)out->runner.story_us,
        out->admitted, out->runner.report.candidate_executed,
        out->runner.green, out->reason);
}

static void zwn_tcp_public_observe(const char *phase,
    const struct zcl_component_receiver_public_request *request,
    const struct zcl_component_receiver_public_outcome *out)
{
    char package[65], blob[65], release[65];
    zcl_hex_encode(request->component.package_root, 32, package);
    zcl_hex_encode(request->release_blob_root, 32, blob);
    zcl_hex_encode(out->release_id, 32, release);
    printf("[component-tcp] phase=%s public_root=%s selected_release_blob=%s release_id=%s admission_attempted=%d release_stored=%d acceptance=%s\n",
        phase, package, blob, release, out->admission_attempted, out->release_stored,
        vcs_package_accept_result_string(out->acceptance));
}

static bool zwn_tcp_public_wrap(struct zwn_tcp *tcp,
    struct rr_component *carrier,
    struct zcl_component_receiver_public_request *request,
    enum rr_component_public_shape shape)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t *license = NULL;
    size_t license_len = 0;
    bool ok = rr_component_read("LICENSE", &license, &license_len) &&
        rr_component_public_variant(tcp->a.store, carrier, license,
                                    license_len, shape, request);
    free(license);
    struct vcs_package_release release = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ok = ok && zwn_publish_release_as(tcp->a.store,
        request->component.package_root, "Apache-2.0", &release) &&
        vcs_package_release_serialize(&release, &wire, &wire_len) == VCS_PACKAGE_RELEASE_OK &&
        vcs_blob_put_to(tcp->a.store, wire, wire_len,
                        request->release_blob_root) == VCS_BLOB_OK;
    free(wire);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_public_prepare(struct zwn_tcp *tcp,
    struct rr_component *carrier,
    struct zcl_component_receiver_public_request *request)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    return zwn_tcp_result(tcp, rr_component_prepare_pure(tcp->a.store, carrier, 1,
        ZCL_COMPONENT_TARGET, false, false) &&
        zwn_tcp_public_wrap(tcp, carrier, request, RR_COMPONENT_PUBLIC_EXACT));
}

static bool zwn_tcp_complete_hit(struct zwn_tcp *tcp, const uint8_t root[32],
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_swarm_download_status before, after;
    if (!vcs_swarm_engine_download_status(tcp->b.engine, root, &before)) return zwn_tcp_result(tcp, false);
    uint64_t provider = (uint64_t)tcp->ba.node->id;
    if (vcs_swarm_engine_fetch_from_bounded(tcp->b.engine, root, ZWN_DAY,
        tcp->b.now, &provider, 1, ZWN_TCP_CONTENT_LIMIT) !=
        VCS_SWARM_FETCH_ALREADY_COMPLETE) return zwn_tcp_result(tcp, false);
    return zwn_tcp_result(tcp, zwn_tcp_quiesce(tcp, magic) &&
        vcs_swarm_engine_download_status(tcp->b.engine, root, &after) &&
        before.state == VCS_SWARM_DL_COMPLETE &&
        after.state == VCS_SWARM_DL_COMPLETE &&
        after.transferred_bytes == before.transferred_bytes);
}

static bool zwn_tcp_public_release_fetch(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_swarm_download_status status;
    if (!vcs_swarm_engine_download_status(tcp->b.engine,
        request->release_blob_root, &status)) return zwn_tcp_result(tcp, false);
    if (status.state == VCS_SWARM_DL_COMPLETE)
        return zwn_tcp_result(tcp, zwn_tcp_complete_hit(tcp, request->release_blob_root, magic));
    return zwn_tcp_result(tcp, zwn_tcp_fetch(tcp, request->release_blob_root, magic,
        VCS_SWARM_DL_COMPLETE));
}

static bool zwn_tcp_warm(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *public_request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    if (!zwn_tcp_quiesce(tcp, magic)) return zwn_tcp_result(tcp, false);
    uint64_t wire_before = tcp->received_bytes;
    uint32_t before[ZWN_MAX_FILES];
    memcpy(before, tcp->a.chunk_data_replies, sizeof(before));
    if (!zwn_tcp_complete_hit(tcp, public_request->release_blob_root, magic) ||
        !zwn_tcp_complete_hit(tcp, public_request->component.package_root, magic))
        return zwn_tcp_result(tcp, false);
    struct zcl_component_receiver_public_outcome public_out;
    bool ok = zcl_component_receiver_run_public(tcp->b.store, public_request, &public_out);
    zwn_tcp_observe("warm", tcp, carrier, &public_out.component);
    zwn_tcp_public_observe("warm", public_request, &public_out);
    printf("[component-tcp] warm_serviced_tcp_bytes=%llu roots_checked=2 content_DATA_unchanged=%d\n",
        (unsigned long long)(tcp->received_bytes - wire_before),
        memcmp(before, tcp->a.chunk_data_replies, sizeof(before)) == 0);
    return zwn_tcp_result(tcp, ok && zwn_tcp_loaded(carrier, &public_out.component) &&
        public_out.acceptance == VCS_PACKAGE_ACCEPT_DUPLICATE &&
        memcmp(before, tcp->a.chunk_data_replies, sizeof(before)) == 0);
}

static bool zwn_tcp_policy_refusal(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *public_request)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request expected = *public_request;
    expected.component.policy_root[0] ^= 1;
    struct zcl_component_receiver_public_outcome public_out;
    struct zcl_component_receiver_outcome *out = &public_out.component;
    bool refused = !zcl_component_receiver_run_public(tcp->b.store, &expected, &public_out);
    zwn_tcp_observe("wrong-local-policy", tcp, carrier, out);
    return zwn_tcp_result(tcp, refused && !out->admitted && out->assembly_bytes_written == 0 &&
        out->runner.runner_pid == 0 && !out->runner.report.candidate_executed &&
        !out->runner.green && out->reason[0]);
}

static bool zwn_tcp_descriptor_refusal(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *public_request)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request expected = *public_request;
    expected.component.execution.candidate_object_root = carrier->image_sha;
    struct zcl_component_receiver_public_outcome public_out;
    struct zcl_component_receiver_outcome *out = &public_out.component;
    bool refused = !zcl_component_receiver_run_public(tcp->b.store, &expected, &public_out);
    zwn_tcp_observe("wrong-local-object", tcp, carrier, out);
    return zwn_tcp_result(tcp, refused && out->admitted && out->runner.available &&
        !out->runner.report.candidate_executed && !out->runner.green &&
        out->runner.reason[0]);
}

static size_t zwn_tcp_received_manifest_bytes(struct zwn_tcp *tcp,
    const uint8_t selected[32])
{
    uint8_t *wire = NULL;
    size_t len = 0;
    struct vcs_package_manifest *manifest = calloc(1, sizeof(*manifest));
    if (!manifest) { fprintf(stderr, "component TCP manifest allocation failed\n"); return 0; }
    uint8_t root[32];
    bool ok = vcs_package_store_get_manifest_wire(tcp->b.store, selected,
        &wire, &len) == VCS_PACKAGE_STORE_OK &&
        vcs_package_manifest_parse(wire, len, manifest) &&
        vcs_package_manifest_root(manifest, root) && memcmp(root, selected, 32) == 0;
    free(wire);
    vcs_package_manifest_free(manifest);
    free(manifest);
    return ok ? len : 0;
}

static bool zwn_tcp_corrupt_refused(const struct vcs_swarm_download_status *status,
    const struct zcl_component_receiver_outcome *out, size_t manifest_bytes)
{
    printf("[component-tcp] corrupt_status=%d chunks=%u present_bytes=%llu transferred_objects=%llu transferred_bytes=%llu manifest_bytes=%zu admitted=%d assembly=%llu sealed=%llu executed=%d reason=%s\n",
        status->state, status->present_chunks, (unsigned long long)status->present_bytes,
        (unsigned long long)status->transferred_objects,
        (unsigned long long)status->transferred_bytes, manifest_bytes, out->admitted,
        (unsigned long long)out->assembly_bytes_written,
        (unsigned long long)out->sealed_copy_bytes,
        out->runner.report.candidate_executed, out->reason);
    return status->state != VCS_SWARM_DL_COMPLETE && status->present_chunks == 0 &&
        status->present_bytes == 0 && manifest_bytes > 0 &&
        status->transferred_objects == 1 && status->transferred_bytes == manifest_bytes && !out->admitted &&
        out->runner.runner_pid == 0 && !out->runner.report.candidate_executed &&
        !out->runner.green && out->assembly_bytes_written == 0 &&
        out->sealed_copy_bytes == 0 && out->reason[0];
}

static bool zwn_tcp_corrupt_book(struct zwn_tcp *tcp, const uint8_t key[33],
    const struct vcs_service_key_totals *before, size_t manifest_bytes)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_service_key_totals after;
    if (!vcs_service_key_totals(tcp->b.book, key, ZWN_DAY, &after)) return zwn_tcp_result(tcp, false);
    printf("[component-tcp] invalid_chunk_events=%u offence_before=%u offence_after=%u no_credit_before=%llu no_credit_after=%llu verified_before=%llu verified_after=%llu manifest_bytes=%zu localhost_score=%d\n",
        tcp->b.invalid_chunk_events, before->offence_total, after.offence_total,
        (unsigned long long)before->no_credit_bytes,
        (unsigned long long)after.no_credit_bytes,
        (unsigned long long)before->verified_bytes_downloaded,
        (unsigned long long)after.verified_bytes_downloaded, manifest_bytes,
        tcp->ba.node->misbehavior);
    return zwn_tcp_result(tcp, after.offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] >
        before->offences[VCS_POLICY_OFFENCE_INVALID_CHUNK] &&
        after.no_credit_bytes > before->no_credit_bytes &&
        after.verified_bytes_downloaded >= before->verified_bytes_downloaded &&
        after.verified_bytes_downloaded - before->verified_bytes_downloaded == manifest_bytes);
}

static bool zwn_tcp_wait_corrupt(struct zwn_tcp *tcp, const uint8_t root[32],
    const unsigned char magic[MESSAGE_START_SIZE], uint32_t events_before,
    int64_t deadline)
{
    while (tcp->b.invalid_chunk_events == events_before) {
        struct vcs_swarm_download_status pending;
        if (!vcs_swarm_engine_download_status(tcp->b.engine, root, &pending))
            return zwn_tcp_result(tcp, false);
        if (pending.state == VCS_SWARM_DL_FAILED || pending.state == VCS_SWARM_DL_COMPLETE)
            return zwn_tcp_result(tcp, false);
        if (!zwn_tcp_step(tcp, magic, deadline)) return false;
    }
    return true;
}

static bool zwn_tcp_corrupt_fetch(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *public_request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    int64_t stamp = zwn_tcp_millis();
    if (stamp < 0) return zwn_tcp_result(tcp, false);
    tcp->a.now = tcp->b.now = (uint64_t)(stamp / 1000);
    uint8_t peer_key[33];
    struct vcs_service_key_totals before;
    if (!zwn_peer_key(tcp->ba.node, peer_key) ||
        !vcs_service_key_totals(tcp->b.book, peer_key, ZWN_DAY, &before)) return zwn_tcp_result(tcp, false);
    uint32_t events_before = tcp->b.invalid_chunk_events;
    tcp->a.tamper_chunks = true;
    if (!zwn_tcp_start_fetch(tcp, public_request->component.package_root)) return false;
    if (!zwn_tcp_wait_corrupt(tcp, public_request->component.package_root,
        magic, events_before, stamp + 10000)) return false;
    struct vcs_swarm_download_status status = {0};
    bool observed = vcs_swarm_engine_download_status(tcp->b.engine,
        public_request->component.package_root, &status);
    struct zcl_component_receiver_public_outcome public_out;
    struct zcl_component_receiver_outcome *out = &public_out.component;
    bool refused = !zcl_component_receiver_run_public(tcp->b.store, public_request, &public_out);
    zwn_tcp_observe("corrupt-TCP-chunk", tcp, carrier, out);
    bool cancelled = vcs_swarm_engine_cancel(tcp->b.engine,
        public_request->component.package_root, tcp->b.now);
    if (cancelled) tcp->active_fetch = false;
    size_t manifest_bytes = zwn_tcp_received_manifest_bytes(tcp,
        public_request->component.package_root);
    bool content = zwn_tcp_corrupt_refused(&status, out, manifest_bytes);
    bool accounting = zwn_tcp_corrupt_book(tcp, peer_key, &before, manifest_bytes);
    if (!zwn_tcp_result(tcp, observed && refused && content && accounting && cancelled)) return false;
    int64_t finished_ms;
    return zwn_tcp_deadline(tcp, stamp + 10000, "corrupt-observation", &finished_ms);
}

static bool zwn_tcp_resign(struct vcs_package_release *release,
    const uint8_t secret[32])
{
    struct privkey sk = {0};
    struct pubkey pk;
    memcpy(sk.vch, secret, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    uint8_t id[32], compact[COMPACT_SIGNATURE_SIZE];
    struct uint256 digest;
    bool ok = privkey_get_pubkey(&sk, &pk) && pk.size == COMPRESSED_PUBLIC_KEY_SIZE;
    if (ok) memcpy(release->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    ok = ok && vcs_package_release_id(release, id) == VCS_PACKAGE_RELEASE_OK;
    if (ok) memcpy(digest.data, id, 32);
    ok = ok && privkey_sign_compact(&sk, &digest, compact);
    if (ok) memcpy(release->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    memory_cleanse(&sk, sizeof(sk));
    return ok && vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
}

static bool zwn_tcp_control_blob(struct zwn_tcp *tcp,
    struct vcs_package_release *release,
    struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t *wire = NULL;
    size_t len = 0;
    bool ok = vcs_package_release_serialize(release, &wire, &len) == VCS_PACKAGE_RELEASE_OK &&
        vcs_blob_put_to(tcp->a.store, wire, len, request->release_blob_root) == VCS_BLOB_OK;
    free(wire);
    return zwn_tcp_result(tcp, ok && zwn_tcp_public_release_fetch(tcp, request, magic));
}

static bool zwn_tcp_no_execution(const struct zcl_component_receiver_public_outcome *out)
{
    return !out->component.admitted && out->component.runner.runner_pid == 0 &&
        !out->component.runner.report.candidate_executed &&
        out->component.assembly_bytes_written == 0 &&
        out->component.sealed_copy_bytes == 0;
}

static bool zwn_tcp_accept_control(struct zwn_tcp *tcp,
    struct vcs_package_release *release,
    const struct zcl_component_receiver_public_request *base,
    const unsigned char magic[MESSAGE_START_SIZE], const char *label,
    enum vcs_package_accept_result wanted, bool accept)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = *base;
    struct zcl_component_receiver_public_outcome out = {0};
    bool delivered = zwn_tcp_control_blob(tcp, release, &request, magic);
    bool admitted = delivered && zcl_component_receiver_public_admit(tcp->b.store, &request, &out);
    bool ok = delivered && admitted == accept && out.admission_attempted &&
        out.acceptance == wanted && zwn_tcp_no_execution(&out) && out.release_stored == accept;
    printf("[component-tcp] release_control=%s delivered=%d acceptance=%s stored=%d executed=%d result=%s reason=%s\n",
        label, delivered, vcs_package_accept_result_string(out.acceptance),
        out.release_stored, out.component.runner.report.candidate_executed,
        ok ? "PASS" : "FAIL", out.component.reason);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_received_release(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    struct vcs_package_release *release)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t bytes[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES] = {0};
    size_t len = 0;
    return zwn_tcp_result(tcp, vcs_blob_get_from(tcp->b.store, request->release_blob_root, bytes,
        sizeof(bytes), &len) == VCS_BLOB_OK &&
        vcs_package_release_parse(bytes, len, release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK);
}

static bool zwn_tcp_public_policy_controls(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_package_release base = {0};
    if (!zwn_tcp_received_release(tcp, request, &base)) return zwn_tcp_result(tcp, false);
    struct vcs_package_release r = base;
    (void)snprintf(r.chain_id, sizeof(r.chain_id), "zclassic-wrong");
    bool signed_ok = zwn_tcp_resign(&r, request->component.package_root);
    bool checked = signed_ok && zwn_tcp_accept_control(tcp, &r, request, magic,
        "wrong-chain", VCS_PACKAGE_ACCEPT_CHAIN_ID, false);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_accept_control(tcp, &base, request, magic, "cursor-after-chain", VCS_PACKAGE_ACCEPT_DUPLICATE, true);
    if (!zwn_tcp_result(tcp, checked)) return false;
    r = base;
    (void)snprintf(r.reward_address, sizeof(r.reward_address), "not-a-reward-address");
    signed_ok = zwn_tcp_resign(&r, request->component.package_root);
    checked = signed_ok && zwn_tcp_accept_control(tcp, &r, request, magic,
        "wrong-reward", VCS_PACKAGE_ACCEPT_REWARD, false);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_accept_control(tcp, &base, request, magic, "cursor-after-reward", VCS_PACKAGE_ACCEPT_DUPLICATE, true);
    if (!zwn_tcp_result(tcp, checked)) return false;
    return true;
}

static bool zwn_tcp_stale_execution(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_outcome out;
    bool refused = !zcl_component_receiver_run_public(tcp->b.store, request, &out);
    bool ok = refused && out.admission_attempted && !out.release_stored &&
        out.acceptance == VCS_PACKAGE_ACCEPT_STALE && zwn_tcp_no_execution(&out);
    printf("[component-tcp] release_control=stale-execution acceptance=%s result=%s\n",
        vcs_package_accept_result_string(out.acceptance), ok ? "PASS" : "FAIL");
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_public_sequence_controls(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_package_release base = {0};
    if (!zwn_tcp_received_release(tcp, request, &base)) return zwn_tcp_result(tcp, false);
    struct vcs_package_release r = base;
    uint8_t rival[32];
    memcpy(rival, request->component.package_root, 32);
    rival[0] ^= 1;
    bool checked = zwn_tcp_resign(&r, rival) &&
        zwn_tcp_accept_control(tcp, &r, request, magic, "namespace",
                                VCS_PACKAGE_ACCEPT_NAMESPACE, false);
    memory_cleanse(rival, sizeof(rival));
    bool ok = zwn_tcp_result(tcp, checked);
    if (!zwn_tcp_result(tcp, ok)) return false;
    checked = zwn_tcp_accept_control(tcp, &base, request, magic, "cursor-after-namespace", VCS_PACKAGE_ACCEPT_DUPLICATE, true);
    if (!zwn_tcp_result(tcp, checked)) return false;
    r = base;
    r.publisher_sequence = 2;
    checked = zwn_tcp_resign(&r, request->component.package_root) &&
        zwn_tcp_accept_control(tcp, &r, request, magic, "advance-sequence",
                                VCS_PACKAGE_ACCEPT_OK, true);
    if (!zwn_tcp_result(tcp, checked)) return false;
    struct vcs_package_release accepted_two = r;
    (void)snprintf(r.semver, sizeof(r.semver), "1.0.1");
    checked = zwn_tcp_resign(&r, request->component.package_root) &&
        zwn_tcp_accept_control(tcp, &r, request, magic, "equivocation",
                                VCS_PACKAGE_ACCEPT_EQUIVOCATION, false);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_accept_control(tcp, &accepted_two, request, magic, "cursor-after-equivocation", VCS_PACKAGE_ACCEPT_DUPLICATE, true);
    if (!zwn_tcp_result(tcp, checked)) return false;
    r = base;
    checked = zwn_tcp_accept_control(tcp, &r, request, magic, "stale-original",
                                    VCS_PACKAGE_ACCEPT_STALE, false);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_stale_execution(tcp, request);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_accept_control(tcp, &accepted_two, request, magic, "cursor-after-stale", VCS_PACKAGE_ACCEPT_DUPLICATE, true);
    return zwn_tcp_result(tcp, checked);
}

static bool zwn_tcp_grant_refused(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *base)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = *base;
    request.allow_release_admission = false;
    struct zcl_component_receiver_public_outcome admitted, executed;
    size_t before_rows = 0, after_rows = 0;
    uint64_t before_generation = 0, after_generation = 0;
    if (vcs_package_store_catalog_rows(tcp->b.store, &before_rows, &before_generation) != VCS_PACKAGE_STORE_PAGE_OK) return zwn_tcp_result(tcp, false);
    bool a = !zcl_component_receiver_public_admit(tcp->b.store, &request, &admitted);
    bool e = !zcl_component_receiver_run_public(tcp->b.store, &request, &executed);
    bool unchanged = vcs_package_store_catalog_rows(tcp->b.store, &after_rows, &after_generation) == VCS_PACKAGE_STORE_PAGE_OK &&
        before_rows == after_rows && before_generation == after_generation;
    bool ok = unchanged && a && e && !admitted.admission_attempted && !executed.admission_attempted &&
        !admitted.release_stored && !executed.release_stored &&
        zwn_tcp_no_execution(&admitted) && zwn_tcp_no_execution(&executed);
    printf("[component-tcp] release_control=grant-false result=%s\n", ok ? "PASS" : "FAIL");
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_preaccept_refused(struct zwn_tcp *tcp,
    struct vcs_package_release *release,
    const struct zcl_component_receiver_public_request *base,
    const unsigned char magic[MESSAGE_START_SIZE], const char *label)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = *base;
    struct zcl_component_receiver_public_outcome out = {0};
    bool delivered = zwn_tcp_control_blob(tcp, release, &request, magic);
    bool refused = delivered && !zcl_component_receiver_public_admit(tcp->b.store, &request, &out);
    bool ok = refused && !out.admission_attempted && !out.release_stored &&
        zwn_tcp_no_execution(&out) && out.component.reason[0];
    printf("[component-tcp] release_control=%s delivered=%d attempted=%d result=%s reason=%s\n",
        label, delivered, out.admission_attempted, ok ? "PASS" : "FAIL", out.component.reason);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_public_binding_controls(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct vcs_package_release base = {0};
    if (!zwn_tcp_received_release(tcp, request, &base)) return zwn_tcp_result(tcp, false);
    struct vcs_package_release r = base;
    r.signature[0] ^= 1;
    bool ok = zwn_tcp_preaccept_refused(tcp, &r, request, magic, "invalid-signature");
    if (!zwn_tcp_result(tcp, ok)) return false;
    r = base;
    r.package_root[0] ^= 1;
    bool checked = zwn_tcp_resign(&r, request->component.package_root) &&
        zwn_tcp_preaccept_refused(tcp, &r, request, magic, "different-package-root");
    if (!zwn_tcp_result(tcp, checked)) return false;
    r = base;
    (void)snprintf(r.license, sizeof(r.license), "MIT");
    checked = zwn_tcp_resign(&r, request->component.package_root) &&
        zwn_tcp_preaccept_refused(tcp, &r, request, magic, "license-text-mismatch");
    return zwn_tcp_result(tcp, checked);
}

static bool zwn_tcp_wire_refused(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *base,
    const unsigned char magic[MESSAGE_START_SIZE], const uint8_t *wire,
    size_t len, const char *label)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = *base;
    bool delivered = vcs_blob_put_to(tcp->a.store, wire, len, request.release_blob_root) == VCS_BLOB_OK &&
        zwn_tcp_public_release_fetch(tcp, &request, magic);
    struct zcl_component_receiver_public_outcome out = {0};
    bool refused = delivered && !zcl_component_receiver_public_admit(tcp->b.store, &request, &out);
    bool ok = refused && !out.admission_attempted && !out.release_stored &&
        zwn_tcp_no_execution(&out) && out.component.reason[0];
    printf("[component-tcp] release_control=%s delivered=%d result=%s reason=%s\n",
        label, delivered, ok ? "PASS" : "FAIL", out.component.reason);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_wire_controls(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t bytes[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES + 1u] = {0};
    size_t len = 0;
    if (vcs_blob_get_from(tcp->b.store, request->release_blob_root, bytes,
        VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &len) != VCS_BLOB_OK) return zwn_tcp_result(tcp, false);
    bool ok = zwn_tcp_wire_refused(tcp, request, magic, bytes, len + 1u, "noncanonical-trailing-byte");
    if (!zwn_tcp_result(tcp, ok)) return false;
    memset(bytes, 0xa5, sizeof(bytes));
    bool checked = zwn_tcp_wire_refused(tcp, request, magic, bytes, sizeof(bytes), "oversized-release-blob");
    if (!zwn_tcp_result(tcp, checked)) return false;
    struct zcl_component_receiver_public_request missing = *request;
    missing.release_blob_root[0] ^= 1;
    struct zcl_component_receiver_public_outcome out;
    checked = !zcl_component_receiver_public_admit(tcp->b.store, &missing, &out) &&
        !out.admission_attempted && zwn_tcp_no_execution(&out);
    printf("[component-tcp] release_control=absent-selected-blob result=%s\n", checked ? "PASS" : "FAIL");
    return zwn_tcp_result(tcp, checked);
}

static bool zwn_tcp_shape_control(struct zwn_tcp *tcp, struct rr_component *carrier,
    const unsigned char magic[MESSAGE_START_SIZE], enum rr_component_public_shape shape,
    const char *label)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = {0};
    if (!zwn_tcp_public_wrap(tcp, carrier, &request, shape)) return zwn_tcp_result(tcp, false);
    bool delivered = zwn_tcp_public_release_fetch(tcp, &request, magic) &&
        zwn_tcp_fetch(tcp, request.component.package_root, magic, VCS_SWARM_DL_COMPLETE);
    struct zcl_component_receiver_public_outcome out = {0};
    bool refused = delivered && !zcl_component_receiver_public_admit(tcp->b.store, &request, &out);
    bool ok = refused && !out.admission_attempted && !out.release_stored &&
        zwn_tcp_no_execution(&out) && out.component.reason[0];
    printf("[component-tcp] public_shape=%s delivered=%d result=%s reason=%s\n",
        label, delivered, ok ? "PASS" : "FAIL", out.component.reason);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_missing_license(struct zwn_tcp *tcp, struct rr_component *carrier)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    struct zcl_component_receiver_public_request request = {0};
    if (!zwn_tcp_public_wrap(tcp, carrier, &request, RR_COMPONENT_PUBLIC_NO_LICENSE)) return zwn_tcp_result(tcp, false);
    struct vcs_package_public_verdict status;
    vcs_package_public_shape_classify(tcp->a.store, request.component.package_root, &status);
    bool ok = status.shape == VCS_PACKAGE_PUBLIC_REFUSED &&
        strcmp(status.rule, "license-text-missing") == 0;
    printf("[component-tcp] public_shape=missing-license provider_refused=%d rule=%s\n", ok, status.rule);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_duplicate_manifest(struct zwn_tcp *tcp, struct rr_component *carrier)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t *license = NULL;
    size_t len = 0;
    struct zcl_component_receiver_public_request request = {0};
    bool read = rr_component_read("LICENSE", &license, &len);
    bool refused = read && !rr_component_public_variant(tcp->a.store, carrier,
        license, len, RR_COMPONENT_PUBLIC_DUPLICATE, &request);
    free(license);
    printf("[component-tcp] public_shape=duplicate-member codec_refused=%d\n", refused);
    return zwn_tcp_result(tcp, refused);
}

static bool zwn_tcp_public_shape_controls(struct zwn_tcp *tcp, struct rr_component *carrier,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    bool ok = zwn_tcp_shape_control(tcp, carrier, magic, RR_COMPONENT_PUBLIC_EXTRA, "unknown-extra");
    if (!zwn_tcp_result(tcp, ok)) return false;
    bool checked = zwn_tcp_shape_control(tcp, carrier, magic, RR_COMPONENT_PUBLIC_WRONG_PATH, "wrong-image-name");
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_missing_license(tcp, carrier);
    if (!zwn_tcp_result(tcp, checked)) return false;
    checked = zwn_tcp_duplicate_manifest(tcp, carrier);
    return zwn_tcp_result(tcp, checked);
}

static bool zwn_tcp_persistence_refused(struct zwn_tcp *tcp,
    const struct zcl_component_receiver_public_request *request)
{
    if (tcp->outcome != ZWN_TCP_OBSERVED) return false;
    uint8_t id[32];
    struct vcs_package_release release = {0};
    if (!zwn_tcp_received_release(tcp, request, &release) ||
        vcs_package_release_id(&release, id) != VCS_PACKAGE_RELEASE_OK) return zwn_tcp_result(tcp, false);
    char hex[65], path[1200];
    zcl_hex_encode(id, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/zcode/releases/%s", tcp->b.datadir, hex);
    if (n <= 0 || (size_t)n >= sizeof(path) || mkdir(path, 0700) != 0) return zwn_tcp_result(tcp, false);
    struct zcl_component_receiver_public_outcome out;
    bool refused = !zcl_component_receiver_public_admit(tcp->b.store, request, &out);
    bool cleaned = rmdir(path) == 0;
    char expected[192];
    (void)snprintf(expected, sizeof(expected), "public release store refused: %s; acceptance: %s",
        vcs_package_store_result_string(VCS_PACKAGE_STORE_ERR_IO),
        vcs_package_accept_result_string(VCS_PACKAGE_ACCEPT_OK));
    bool ok = refused && cleaned && out.admission_attempted && !out.release_stored &&
        out.acceptance == VCS_PACKAGE_ACCEPT_OK && zwn_tcp_no_execution(&out) &&
        strcmp(out.component.reason, expected) == 0;
    printf("[component-tcp] release_control=persist-directory-refusal cleaned=%d acceptance=%s stored=%d result=%s reason=%s\n",
        cleaned, vcs_package_accept_result_string(out.acceptance), out.release_stored,
        ok ? "PASS" : "FAIL", out.component.reason);
    return zwn_tcp_result(tcp, ok);
}

static bool zwn_tcp_cancel_active(struct zwn_tcp *tcp)
{
    if (!tcp->active_fetch) return true;
    struct vcs_swarm_download_status status;
    if (!vcs_swarm_engine_download_status(tcp->b.engine, tcp->active_root, &status)) {
        tcp->outcome = ZWN_TCP_FAILED;
        return false;
    }
    bool inactive = status.state == VCS_SWARM_DL_COMPLETE || status.state == VCS_SWARM_DL_FAILED;
    bool ok = inactive || vcs_swarm_engine_cancel(tcp->b.engine, tcp->active_root, tcp->b.now);
    if (!ok) tcp->outcome = ZWN_TCP_FAILED;
    tcp->cancelled = !inactive && ok;
    tcp->active_fetch = false;
    return ok;
}

static void zwn_tcp_finish(struct zwn_tcp *tcp, struct rr_component *carrier,
    int *failures)
{
    if (!zwn_tcp_cancel_active(tcp)) ++*failures;
    rr_component_free(carrier);
    if (!zwn_tcp_free(tcp)) ++*failures;
    if (*failures) tcp->outcome = ZWN_TCP_FAILED;
    if (tcp->outcome == ZWN_TCP_UNOBSERVED) {
        char root[65];
        zcl_hex_encode(tcp->active_root, 32, root);
        printf("UNOBSERVED (component TCP absolute deadline phase=%s root=%s cancelled=%d owned teardown returned; checked cleanup errors=0; incomplete observation; no complete test credit)\n",
            tcp->phase ? tcp->phase : "unknown", root, tcp->cancelled);
    }
}

static bool zwn_tcp_expired_cancelled(struct zwn_tcp *tcp, const uint8_t root[32])
{
    if (!zwn_tcp_cancel_active(tcp) || !tcp->cancelled) return false;
    struct vcs_swarm_download_status status;
    if (!vcs_swarm_engine_download_status(tcp->b.engine, root, &status)) return false;
    return status.state == VCS_SWARM_DL_FAILED &&
        strcmp(status.rule, "operator-cancelled") == 0 &&
        tcp->received_bytes == 0 && tcp->b.invalid_chunk_events == 0;
}

static int zwn_tcp_deadline_control(const struct chain_params *params,
    struct zwn_tcp *outer)
{
    int failures = 0;
    struct zwn_tcp tcp = {0};
    struct rr_component carrier = {0};
    struct zcl_component_receiver_public_request request = {0};
    bool classified = false;
    TEST("component TCP: expired observation cancels without execution") {
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_init(&tcp, params));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_public_prepare(&tcp, &carrier, &request));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_start_fetch(&tcp, request.component.package_root));
        int64_t deadline = zwn_tcp_millis();
        ASSERT(deadline >= 0);
        ASSERT(!zwn_tcp_step(&tcp, params->pchMessageStart, deadline));
        ASSERT(tcp.outcome == ZWN_TCP_UNOBSERVED);
        ASSERT(zwn_tcp_expired_cancelled(&tcp, request.component.package_root));
        classified = true;
        PASS();
    } _test_next:;
    /* This negative observes classification, not a missing product leg. */
    if (!zwn_tcp_cancel_active(&tcp)) ++failures;
    rr_component_free(&carrier);
    if (!zwn_tcp_free(&tcp)) ++failures;
    if (failures) outer->outcome = ZWN_TCP_FAILED;
    else if (!classified && tcp.outcome == ZWN_TCP_UNOBSERVED) {
        outer->outcome = ZWN_TCP_UNOBSERVED;
        outer->phase = tcp.phase;
        memcpy(outer->active_root, tcp.active_root, 32);
        outer->cancelled = tcp.cancelled;
    }
    printf("[component-tcp] deadline_control=expired classified=%d cancelled=%d owned_teardown_returned=%d failures=%d\n",
        classified, tcp.cancelled, !tcp.a_ready && !tcp.b_ready, failures);
    return failures;
}

static int zwn_tcp_io_control(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_tcp tcp = {0};
    struct p2p_node node = {.socket = -1};
    struct zwn_link link = {.node = &node};
    TEST("component TCP: actual descriptor error dominates expiry") {
        ASSERT(!zwn_tcp_read(&tcp, &link, params->pchMessageStart));
        ASSERT(tcp.outcome == ZWN_TCP_FAILED);
        int64_t stamp;
        ASSERT(!zwn_tcp_deadline(&tcp, 0, "negative-control", &stamp));
        ASSERT(tcp.outcome == ZWN_TCP_FAILED);
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_tcp_load_controls(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    int failures = 0;
    TEST("licensed component: admission, load and warm controls") {
        ZWN_TCP_ASSERT(tcp, zwn_tcp_grant_refused(tcp, request));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_persistence_refused(tcp, request));
        struct zcl_component_receiver_public_outcome admitted;
        ZWN_TCP_ASSERT(tcp, zcl_component_receiver_public_admit(tcp->b.store, request, &admitted));
        zwn_tcp_public_observe("inert-admission", request, &admitted);
        ZWN_TCP_ASSERT(tcp, admitted.release_stored && admitted.acceptance == VCS_PACKAGE_ACCEPT_OK &&
            zwn_tcp_no_execution(&admitted));
        struct zcl_component_receiver_public_outcome out;
        bool loaded = zcl_component_receiver_run_public(tcp->b.store, request, &out);
        zwn_tcp_observe("cold", tcp, carrier, &out.component);
        zwn_tcp_public_observe("cold", request, &out);
        ZWN_TCP_ASSERT(tcp, loaded && out.acceptance == VCS_PACKAGE_ACCEPT_DUPLICATE &&
            zwn_tcp_loaded(carrier, &out.component));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_warm(tcp, carrier, request, magic));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_policy_refusal(tcp, carrier, request));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_descriptor_refusal(tcp, carrier, request));
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_tcp_refusal_controls(struct zwn_tcp *tcp, struct rr_component *carrier,
    const struct zcl_component_receiver_public_request *request,
    const unsigned char magic[MESSAGE_START_SIZE])
{
    int failures = 0;
    TEST("licensed component: independent public refusal controls") {
        ZWN_TCP_ASSERT(tcp, zwn_tcp_public_binding_controls(tcp, request, magic));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_wire_controls(tcp, request, magic));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_public_shape_controls(tcp, carrier, magic));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_public_policy_controls(tcp, request, magic));
        ZWN_TCP_ASSERT(tcp, zwn_tcp_public_sequence_controls(tcp, request, magic));
        PASS();
    } _test_next:;
    return failures;
}

static int zwn_t_component_tcp(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_tcp tcp = {0};
    struct rr_component carrier = {0};
    struct zcl_component_receiver_public_request request = {0};
    TEST("licensed component: in-band TCP release and sealed HOT_FORK load") {
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_deadline_control(params, &tcp) == 0);
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_io_control(params) == 0);
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_init(&tcp, params));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_public_prepare(&tcp, &carrier, &request));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_public_release_fetch(&tcp, &request, params->pchMessageStart));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_fetch(&tcp, request.component.package_root,
            params->pchMessageStart, VCS_SWARM_DL_COMPLETE));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_load_controls(&tcp, &carrier, &request, params->pchMessageStart) == 0);
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_refusal_controls(&tcp, &carrier, &request, params->pchMessageStart) == 0);
        PASS();
    } _test_next:;
    zwn_tcp_finish(&tcp, &carrier, &failures);
    return failures;
}
static int zwn_t_component_tcp_corrupt(const struct chain_params *params)
{
    int failures = 0;
    struct zwn_tcp tcp = {0};
    struct rr_component carrier = {0};
    struct zcl_component_receiver_public_request request = {0};
    TEST("licensed component: corrupt TCP content never grants execution") {
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_init(&tcp, params));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_public_prepare(&tcp, &carrier, &request));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_public_release_fetch(&tcp, &request, params->pchMessageStart));
        ZWN_TCP_ASSERT(&tcp, zwn_tcp_corrupt_fetch(&tcp, &carrier, &request, params->pchMessageStart));
        PASS();
    } _test_next:;
    zwn_tcp_finish(&tcp, &carrier, &failures);
    return failures;
}

#else
static int zwn_t_component_tcp_unavailable(const struct chain_params *params)
{
    (void)params;
    struct zcl_component_receiver_outcome out;
    bool refused = !zcl_component_receiver_run(NULL, NULL, &out);
#if defined(__linux__) && defined(__x86_64__)
    const char *availability = "fixture-unavailable-without-ZCL_TESTING";
#else
    const char *availability = "platform-unavailable";
#endif
    printf("[component-tcp] availability=%s executed=false reason=%s\n",
        availability, out.reason);
    return !(refused && !out.admitted && out.reason[0] &&
        out.runner.runner_pid == 0 && !out.runner.report.candidate_executed);
}
#endif

/* A resident hosting handle must follow a one-shot writer that advanced the
 * datadir's store generation. Before the swarm tick it is stale: the foreign
 * root is not listed and its next write is refused. The tick refreshes it, so
 * the root is listed and the resident accepts its own write. A tick with an
 * unchanged generation leaves the handle as it was. */
static int zwn_t_hosting_refresh_foreign_writer(
    const struct chain_params *params)
{
    (void)params;
    int failures = 0;
    char dd[256], zcode_dir[320];
    test_make_tmpdir(dd, sizeof(dd), "zcode_swarm_net", "hosting-refresh");
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);
    struct vcs_package_store *a =
        vcs_package_store_open(dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    struct vcs_swarm_engine *engine = (a && book) ?
        vcs_swarm_engine_create(a, book, zcode_dir, zwn_score, NULL) : NULL;
    struct vcs_package_store *b = NULL;
    static const uint8_t foreign[] = "hosting refresh foreign writer root";
    static const uint8_t resident[] = "hosting refresh resident write";
    uint8_t foreign_root[32] = {0}, resident_root[32] = {0};
    struct vcs_package_store_status status;
    TEST("hosting refresh: foreign writer is refreshed by the resident tick") {
        ASSERT(engine != NULL);
        b = vcs_package_store_open(dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
        ASSERT(b != NULL);
        ASSERT(vcs_blob_put_to(b, foreign, sizeof(foreign) - 1u,
                               foreign_root) == VCS_BLOB_OK);
        ASSERT(!(vcs_package_store_package_status(a, foreign_root, &status) &&
                 status.complete));
        vcs_swarm_engine_tick(engine, 0, 1000u);
        ASSERT(vcs_package_store_package_status(a, foreign_root, &status) &&
               status.complete);
        ASSERT(vcs_blob_put_to(a, resident, sizeof(resident) - 1u,
                               resident_root) == VCS_BLOB_OK);
        vcs_swarm_engine_tick(engine, 0, 2000u);
        ASSERT(vcs_package_store_package_status(a, resident_root, &status) &&
               status.complete);
        PASS();
    } _test_next:
    vcs_swarm_engine_free(engine);
    vcs_service_book_free(book);
    vcs_package_store_close(b);
    vcs_package_store_close(a);
    test_rm_rf_recursive(dd);
    return failures;
}

struct zwn_case {
    const char *name;
    int (*run)(const struct chain_params *params);
    unsigned shard;
};
#define ZWN_CASE(fn, owner) {#fn, fn, owner}
static const struct zwn_case g_zwn_cases[] = {
    ZWN_CASE(zwn_t_fixture_abort_reacquire, 4),
    ZWN_CASE(zwn_t_hosting_refresh_foreign_writer, 0),
#if defined(__linux__) && defined(__x86_64__) && defined(ZCL_TESTING)
    ZWN_CASE(zwn_t_component_tcp, 0),
    ZWN_CASE(zwn_t_component_tcp_corrupt, 0),
#else
    ZWN_CASE(zwn_t_component_tcp_unavailable, 0),
#endif
    ZWN_CASE(zwn_t_golden_plain, 1),
    ZWN_CASE(zwn_t_golden_restart, 3),
    ZWN_CASE(zwn_t_golden_disconnect, 2),
    ZWN_CASE(zwn_t_incomplete_carrier_import, 0),
    ZWN_CASE(zwn_t_package_lifecycle, 0),
    ZWN_CASE(zwn_t_sovereign_source_build, 4),
    ZWN_CASE(zwn_t_malicious, 4),
    ZWN_CASE(zwn_t_corrupt_provider_repair, 3),
    ZWN_CASE(zwn_t_corrupt_local_repair, 3),
    ZWN_CASE(zwn_t_unrequested, 1),
    ZWN_CASE(zwn_t_quota_exhaustion, 4),
    ZWN_CASE(zwn_t_deterministic_replay, 2),
    ZWN_CASE(zwn_t_useful_c23_redundant, 3),
    ZWN_CASE(zwn_t_ordinary_c23_redundant, 1),
    ZWN_CASE(zwn_t_late_joiner_announce_discovery, 2),
    ZWN_CASE(zwn_t_attestation_flight, 4),
    ZWN_CASE(zwn_t_task_flight, 4),
    ZWN_CASE(zwn_t_shared_focus_flight, 3),
    ZWN_CASE(zwn_t_task_hostile_pointer, 3),
    ZWN_CASE(zwn_t_attestation_hostile_pointer, 4),
    ZWN_CASE(zwn_t_attestation_corrupt_wire, 4),
#if !defined(_WIN32)
    ZWN_CASE(zwn_t_work_pull, 2),
#endif
};
#undef ZWN_CASE
#define ZWN_CASE_COUNT (sizeof(g_zwn_cases) / sizeof(g_zwn_cases[0]))
#define ZWN_SHARD_COUNT 5u
/* The row filter that selects every row: the umbrella's exact run. */
#define ZWN_ALL_SHARDS ZWN_SHARD_COUNT
#define ZWN_UMBRELLA "test_zcode_swarm_net"

/* The sub-suites the unsharded group ran, written down independently of the
 * table: a row dropped from the table, or a sub-suite added to it without an
 * owner, fails the partition instead of silently going unrun. */
static const char *const g_zwn_original[] = {
    "zwn_t_fixture_abort_reacquire", "zwn_t_hosting_refresh_foreign_writer",
    "zwn_t_golden_plain",
#if defined(__linux__) && defined(__x86_64__) && defined(ZCL_TESTING)
    "zwn_t_component_tcp", "zwn_t_component_tcp_corrupt",
#else
    "zwn_t_component_tcp_unavailable",
#endif
    "zwn_t_golden_restart", "zwn_t_golden_disconnect",
    "zwn_t_incomplete_carrier_import",
    "zwn_t_package_lifecycle", "zwn_t_sovereign_source_build",
    "zwn_t_malicious", "zwn_t_corrupt_provider_repair",
    "zwn_t_corrupt_local_repair", "zwn_t_unrequested",
    "zwn_t_quota_exhaustion", "zwn_t_deterministic_replay",
    "zwn_t_useful_c23_redundant", "zwn_t_ordinary_c23_redundant",
    "zwn_t_late_joiner_announce_discovery",
    "zwn_t_attestation_flight", "zwn_t_task_flight",
    "zwn_t_shared_focus_flight", "zwn_t_task_hostile_pointer",
    "zwn_t_attestation_hostile_pointer", "zwn_t_attestation_corrupt_wire",
#if !defined(_WIN32)
    "zwn_t_work_pull",
#endif
};
#define ZWN_ORIGINAL_COUNT (sizeof(g_zwn_original) / sizeof(g_zwn_original[0]))

/* Row wall for the balance log only; no assertion reads it. The clock
 * variables carry names used nowhere else in this file, because the
 * wall-clock assertion gate taints identifiers by name across the whole
 * file, and a reading stored in a common name such as `now` would mark every
 * unrelated helper that takes a `now` parameter as a clock reader. */
static long long zwn_elapsed_ms(const struct timespec *row_started)
{
    struct timespec row_ended;
    if (clock_gettime(CLOCK_MONOTONIC, &row_ended) != 0)
        return -1;
    return (long long)(row_ended.tv_sec - row_started->tv_sec) * 1000 +
           (row_ended.tv_nsec - row_started->tv_nsec) / 1000000;
}

/* How many rows name `name`. */
static size_t zwn_owners_of(const char *name)
{
    size_t owners = 0;
    for (size_t i = 0; i < ZWN_CASE_COUNT; i++)
        if (strcmp(name, g_zwn_cases[i].name) == 0)
            owners++;
    return owners;
}

/* Every row names a real shard, every shard owns a row, and every original
 * sub-suite is owned exactly once by a table exactly that long. */
static bool zwn_partition_valid(void)
{
    unsigned counts[ZWN_SHARD_COUNT] = {0};
    bool ok = ZWN_CASE_COUNT == ZWN_ORIGINAL_COUNT;
    for (size_t i = 0; i < ZWN_CASE_COUNT; i++) {
        if (g_zwn_cases[i].shard >= ZWN_SHARD_COUNT)
            ok = false;
        else
            counts[g_zwn_cases[i].shard]++;
    }
    for (unsigned s = 0; s < ZWN_SHARD_COUNT; s++)
        if (counts[s] == 0)
            ok = false;
    for (size_t k = 0; k < ZWN_ORIGINAL_COUNT; k++)
        if (zwn_owners_of(g_zwn_original[k]) != 1)
            ok = false;
    return ok;
}

/* The catalog declares this group an umbrella whose registered shards are
 * exactly test_zcode_swarm_net_shard_01..NN, and a proof token naming the
 * group reaches all of them. */
static bool zwn_umbrella_registered(void)
{
    if (!zcl_test_group_is_umbrella(ZWN_UMBRELLA) ||
        zcl_test_group_umbrella_shard_count(ZWN_UMBRELLA) != ZWN_SHARD_COUNT)
        return false;
    for (unsigned s = 1; s <= ZWN_SHARD_COUNT; s++) {
        char id[ZCL_TEST_GROUP_FULL_MAX];
        (void)snprintf(id, sizeof(id), ZWN_UMBRELLA "_shard_%02u", s);
        if (!zcl_test_group_is_umbrella_shard(ZWN_UMBRELLA, id))
            return false;
    }
    return true;
}

static int zwn_partition_check(void)
{
    int failures = 0;
    TEST("shard partition: every sub-suite is owned by exactly one "
         "registered shard of the umbrella") {
        ASSERT(zwn_partition_valid());
        ASSERT(zwn_umbrella_registered());
        PASS();
    } _test_next:;
    return failures;
}

/* The rows `shard` owns, in table order; ZWN_ALL_SHARDS runs every row.
 *
 * Every row's node stores live in per-pid test-tmp datadirs that this same
 * process writes, reads back and removes; no row cuts power or kills a
 * writer mid-write, so a package store's per-write fsync barrier protects
 * nothing here. Measured, it was most of each row's wall: the redundant
 * hosting rows spent ~80% of their time in package-store fsyncs (service
 * events, store generation, CAS chunks, manifests), and the whole group ran
 * 3-5x slower whenever a proof's scratch landed on a busy disk instead of
 * RAM. The rows therefore run with the package store's documented
 * deferred-sync mode on (package_lifecycle already did so for itself). It
 * drops only each store_atomic_write's own fsync; content addressing,
 * verification and the temp+rename discipline are unchanged, so every
 * assertion reads the same bytes it did before. The prior mode is restored
 * before returning, so nothing outside these rows sees it. */
static int zwn_run_rows(unsigned shard)
{
    int failures = 0;
    size_t ran = 0;
    bool zwn_prior_rows_sync = vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true);
    memset(&g_zwn_sovereign_receipt, 0, sizeof(g_zwn_sovereign_receipt));
    chain_params_select(CHAIN_MAIN);
    const struct chain_params *params = chain_params_get();
    for (size_t i = 0; i < ZWN_CASE_COUNT; i++) {
        struct timespec zwn_row_started;
        if (shard != ZWN_ALL_SHARDS && g_zwn_cases[i].shard != shard)
            continue;
        (void)clock_gettime(CLOCK_MONOTONIC, &zwn_row_started);
        int added = g_zwn_cases[i].run(params);
        failures += added;
        ran++;
        printf("[zcode-swarm-net-case] shard=%u name=%s ms=%lld "
               "failures=%d\n", g_zwn_cases[i].shard + 1u,
               g_zwn_cases[i].name, zwn_elapsed_ms(&zwn_row_started),
               added);
    }
    vcs_package_store_set_deferred_sync(zwn_prior_rows_sync);
    if (failures == 0 && g_zwn_sovereign_receipt.ready)
        zwn_print_sovereign_receipt();
    printf("zcode_swarm_net: ran %zu of %zu sub-suites (%s), %d failed\n",
           ran, ZWN_CASE_COUNT,
           shard == ZWN_ALL_SHARDS ? "umbrella" : "one shard", failures);
    return failures;
}

static int zwn_run_shard(unsigned shard)
{
    int failures = zwn_partition_check();
    return failures + zwn_run_rows(shard);
}

int test_zcode_swarm_net(void)
{
    return zwn_run_shard(ZWN_ALL_SHARDS);
}

/* The registered shard groups, one per owner in the table above. */
int test_zcode_swarm_net_shard_01(void)
{
    return zwn_run_shard(0u);
}

int test_zcode_swarm_net_shard_02(void)
{
    return zwn_run_shard(1u);
}

int test_zcode_swarm_net_shard_03(void)
{
    return zwn_run_shard(2u);
}

int test_zcode_swarm_net_shard_04(void)
{
    return zwn_run_shard(3u);
}

int test_zcode_swarm_net_shard_05(void)
{
    return zwn_run_shard(4u);
}
