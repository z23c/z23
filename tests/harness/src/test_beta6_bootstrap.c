/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Pin the beta6 bootstrap serve wire, chunk bounds, gating and quota.
 *
 * The two manifest byte vectors below are written out FIELD BY FIELD from the
 * beta6 serializer definitions in src/protocol.h, not captured from this
 * encoder — checking the encoder against its own decoder would pass just as
 * happily if both were wrong in the same direction, and this wire has to
 * satisfy a binary nobody here can change.
 *
 * Layout being pinned (CBootstrapSnapshotManifest, protocol.h:205-289):
 *   i32 nVersion | CompactSize+bytes strNetwork | i32 nHeight |
 *   32B hashBlock | 32B hashAnchorSha256 | 32B hashAnchorSha3 |
 *   u64 nSnapshotBytes | u32 nChunkSize |
 *   CompactSize count, then per file: CompactSize+bytes strPath, u64 nSize,
 *                                     32B hashSha256
 *   v2+: 32B hashChainstateSerialized
 *   v3+: i32 nBlockTipHeight, 32B hashBlockTip
 *
 * Everything here is hermetic: the on-disk cases build their own fixture tree
 * under test-tmp and never touch a datadir or a real snapshot.
 */

#include "test/test_core.h"

#include "services/beta6_bootstrap.h"

#include "chain/chainparams.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/protocol.h"
#include "net/version.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* v1, network "main", height 2, snapshot_bytes 5, chunk 1 MiB, NO files.
 * hashBlock/hashAnchorSha256/hashAnchorSha3 carry 0x11/0x22/0x33 in their
 * first internal byte, so two swapped fields show up as swapped tags. */
static const char *const k_manifest_v1_hex =
    "01000000"
    "046d61696e"
    "02000000"
    "1100000000000000000000000000000000000000000000000000000000000000"
    "2200000000000000000000000000000000000000000000000000000000000000"
    "3300000000000000000000000000000000000000000000000000000000000000"
    "0500000000000000"
    "00001000"
    "00";

/* v3, same header, snapshot_bytes 13, one file "blocks/a" of 13 bytes,
 * chainstate commitment 0x55, block-bundle tip height 7 / hash 0x66. */
static const char *const k_manifest_v3_hex =
    "03000000"
    "046d61696e"
    "02000000"
    "1100000000000000000000000000000000000000000000000000000000000000"
    "2200000000000000000000000000000000000000000000000000000000000000"
    "3300000000000000000000000000000000000000000000000000000000000000"
    "0d00000000000000"
    "00001000"
    "01"
    "08626c6f636b732f61"
    "0d00000000000000"
    "4400000000000000000000000000000000000000000000000000000000000000"
    "5500000000000000000000000000000000000000000000000000000000000000"
    "07000000"
    "6600000000000000000000000000000000000000000000000000000000000000";

/* check_hex() in test_helpers.c renders into a 256-byte buffer, which these
 * 122- and 239-byte payloads overrun, so compare in place instead. */
static bool wire_is(const unsigned char *data, size_t len, const char *hex)
{
    if (strlen(hex) != len * 2) {
        printf("\n  wire length %zu != expected %zu\n", len, strlen(hex) / 2);
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char pair[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        unsigned int want = 0;
        if (sscanf(pair, "%02x", &want) != 1 || (unsigned int)data[i] != want) {
            printf("\n  wire byte %zu is %02x, expected %s\n", i, data[i], pair);
            return false;
        }
    }
    return true;
}

static void tag_hash(struct uint256 *out, unsigned char tag)
{
    memset(out->data, 0, sizeof(out->data));
    out->data[0] = tag;
}

static void build_v1(struct beta6_bs_manifest *manifest)
{
    beta6_bs_manifest_init(manifest);
    manifest->version = 1;
    snprintf(manifest->network, sizeof(manifest->network), "main");
    manifest->height = 2;
    tag_hash(&manifest->hash_block, 0x11);
    tag_hash(&manifest->hash_anchor_sha256, 0x22);
    tag_hash(&manifest->hash_anchor_sha3, 0x33);
    manifest->snapshot_bytes = 5;
    manifest->chunk_size = BETA6_BS_CHUNK_SIZE;
}

static void build_v3(struct beta6_bs_manifest *manifest, struct beta6_bs_file *file)
{
    build_v1(manifest);
    manifest->version = 3;
    manifest->snapshot_bytes = 13;
    memset(file, 0, sizeof(*file));
    snprintf(file->path, sizeof(file->path), "blocks/a");
    file->size = 13;
    tag_hash(&file->sha256, 0x44);
    manifest->files = file;
    manifest->file_count = 1;
    tag_hash(&manifest->hash_chainstate, 0x55);
    manifest->block_tip_height = 7;
    tag_hash(&manifest->hash_block_tip, 0x66);
}

/* Write `bytes` copies of 0xAB into <dir>/<relative>, creating parents. */
static bool fixture_write(const char *dir, const char *relative, size_t bytes)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, relative);
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
        for (char *p = path + 1; *p; p++) {
            if (*p != '/')
                continue;
            *p = '\0';
            (void)mkdir(path, 0700);
            *p = '/';
        }
        (void)mkdir(path, 0700);
        *slash = '/';
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    for (size_t i = 0; i < bytes; i++)
        fputc(0xAB, f);
    return fclose(f) == 0;
}

static bool fixture_anchor(const char *dir, const char *line)
{
    char sidecar[1100];
    snprintf(sidecar, sizeof(sidecar), "%s.anchor", dir);
    FILE *f = fopen(sidecar, "w");
    if (!f)
        return false;
    fprintf(f, "%s\n", line);
    return fclose(f) == 0;
}

/* A serve tree whose .anchor names the compiled beta6 anchor, so arming it
 * exercises the real anchor resolution rather than a stub. */
static bool fixture_build(const char *dir)
{
    return fixture_write(dir, "blocks/blk00000.dat", 40) &&
           fixture_write(dir, "blocks/index/000005.ldb", 10) &&
           fixture_write(dir, "chainstate/000007.ldb", 20) &&
           fixture_anchor(dir, "3126937 00000663e40f1fe0bc32a7e7282fac25de5fe8ec"
                               "efd9c627e2fd948d388f7053");
}

/* ── in-band seam fixtures ───────────────────────────────────────────
 * The seam under test is core/modules/net's dispatch rows plus the engine
 * server they route to. Both halves are exercised without a socket: a
 * recording hook proves the ROUTING, and the real engine server proves the
 * FRAMING by leaving its reply on the peer's send queue, which
 * p2p_node_end_message fills without ever touching the file descriptor. */

static int g_seam_calls;
static char g_seam_command[16];
static unsigned char g_seam_payload[64];
static size_t g_seam_payload_len;

static bool seam_record(struct msg_processor *mp, struct p2p_node *node,
                        const char *command, const unsigned char *payload,
                        size_t payload_len)
{
    (void)mp;
    (void)node;
    g_seam_calls++;
    snprintf(g_seam_command, sizeof(g_seam_command), "%s", command);
    g_seam_payload_len = payload_len < sizeof(g_seam_payload) ? payload_len
                                                              : sizeof(g_seam_payload);
    if (g_seam_payload_len > 0)
        memcpy(g_seam_payload, payload, g_seam_payload_len);
    return true;
}

static bool seam_armed_true(void)
{
    return true;
}

/* Feed one message through the REAL dispatch table, the way
 * msg_process_messages does, so the test cannot pass on a row that is not
 * actually wired. */
static bool seam_dispatch(struct msg_processor *mp, struct p2p_node *node,
                          const char *command, const unsigned char *payload,
                          size_t payload_len)
{
    for (const struct msg_dispatch_entry *e = msg_get_dispatch_table(); e->handler;
         e++) {
        if (strcmp(e->command, command) != 0)
            continue;
        struct byte_stream s;
        stream_init_from_data(&s, payload, payload_len);
        bool ok = e->handler(mp, node, &s);
        stream_free(&s);
        return ok;
    }
    return false;
}

static void seam_addr_loopback(struct net_address *addr)
{
    net_address_init(addr);
    addr->svc.addr.ip[10] = 0xff;
    addr->svc.addr.ip[11] = 0xff;
    addr->svc.addr.ip[12] = 127;
    addr->svc.addr.ip[15] = 1;
    addr->svc.port = 38033;
}

static void seam_drain(struct p2p_node *node)
{
    while (node->send_head) {
        struct send_segment *next = node->send_head->next;
        send_segment_free(node->send_head);
        node->send_head = next;
    }
    node->send_tail = NULL;
    node->send_size = 0;
}

int test_beta6_bootstrap(void);
int test_beta6_bootstrap(void)
{
    int failures = 0;

    /* ─────────────────────────── wire codec ─────────────────────────── */

    TEST("manifest v1 encodes the beta6 field order byte for byte") {
        struct beta6_bs_manifest manifest;
        build_v1(&manifest);
        struct byte_stream out;
        stream_init(&out, 256);
        ASSERT(beta6_bs_manifest_encode(&manifest, &out).ok);
        ASSERT(wire_is(out.data, out.size, k_manifest_v1_hex));
        stream_free(&out);
        PASS();
    }

    TEST("manifest v3 appends the chainstate commitment and bundle tip") {
        struct beta6_bs_manifest manifest;
        struct beta6_bs_file file;
        build_v3(&manifest, &file);
        struct byte_stream out;
        stream_init(&out, 256);
        ASSERT(beta6_bs_manifest_encode(&manifest, &out).ok);
        ASSERT(wire_is(out.data, out.size, k_manifest_v3_hex));
        stream_free(&out);
        PASS();
    }

    TEST("a v1 manifest carries NO v2/v3 fields, so its bytes never grow") {
        struct beta6_bs_manifest manifest;
        build_v1(&manifest);
        /* Setting the later-version fields must change nothing on the wire:
         * the version gate, not the struct, decides what is serialized. */
        tag_hash(&manifest.hash_chainstate, 0x55);
        manifest.block_tip_height = 7;
        tag_hash(&manifest.hash_block_tip, 0x66);
        struct byte_stream out;
        stream_init(&out, 256);
        ASSERT(beta6_bs_manifest_encode(&manifest, &out).ok);
        ASSERT(wire_is(out.data, out.size, k_manifest_v1_hex));
        stream_free(&out);
        PASS();
    }

    TEST("manifest decode reads the hand-written v3 vector back") {
        uint8_t bytes[512];
        size_t len = strlen(k_manifest_v3_hex) / 2;
        test_hex_to_bytes(k_manifest_v3_hex, bytes, (int)len);
        struct byte_stream in;
        stream_init_from_data(&in, bytes, len);
        struct beta6_bs_manifest decoded;
        ASSERT(beta6_bs_manifest_decode(&in, &decoded).ok);
        ASSERT_EQ(decoded.version, 3);
        ASSERT_STR_EQ(decoded.network, "main");
        ASSERT_EQ(decoded.height, 2);
        ASSERT_EQ((int)decoded.snapshot_bytes, 13);
        ASSERT_EQ((int)decoded.chunk_size, (int)BETA6_BS_CHUNK_SIZE);
        ASSERT_EQ((int)decoded.file_count, 1);
        ASSERT_STR_EQ(decoded.files[0].path, "blocks/a");
        ASSERT_EQ((int)decoded.files[0].size, 13);
        ASSERT_EQ((int)decoded.hash_chainstate.data[0], 0x55);
        ASSERT_EQ(decoded.block_tip_height, 7);
        ASSERT_EQ((int)decoded.hash_block_tip.data[0], 0x66);
        ASSERT_EQ((int)stream_remaining(&in), 0);
        beta6_bs_manifest_free(&decoded);
        PASS();
    }

    TEST("chunk request is u32 index, u64 offset, u32 length little-endian") {
        struct beta6_bs_chunk_request request = {
            .file_index = 0x01020304, .offset = 0x1000, .length = 0x100000
        };
        struct byte_stream out;
        stream_init(&out, 32);
        ASSERT(beta6_bs_chunk_request_encode(&request, &out).ok);
        ASSERT(wire_is(out.data, out.size,
                       "04030201" "0010000000000000" "00001000"));
        stream_free(&out);
        PASS();
    }

    TEST("chunk reply is index, offset, then a CompactSize-prefixed payload") {
        const unsigned char data[3] = { 0xde, 0xad, 0xbe };
        struct byte_stream out;
        stream_init(&out, 32);
        ASSERT(beta6_bs_chunk_encode(7, 0, data, sizeof(data), &out).ok);
        ASSERT(wire_is(out.data, out.size,
                       "07000000" "0000000000000000" "03" "deadbe"));
        stream_free(&out);
        PASS();
    }

    /* ────────────────────────── chunk bounds ────────────────────────── */

    TEST("a chunk range must be aligned, in range, and exactly sized") {
        const uint64_t size = (uint64_t)BETA6_BS_CHUNK_SIZE + 100;
        /* A full leading chunk. */
        ASSERT(beta6_bs_validate_chunk_range(0, BETA6_BS_CHUNK_SIZE, size,
                                             BETA6_BS_CHUNK_SIZE, "t").ok);
        /* The short final chunk must be exactly the remainder. */
        ASSERT(beta6_bs_validate_chunk_range(BETA6_BS_CHUNK_SIZE, 100, size,
                                             BETA6_BS_CHUNK_SIZE, "t").ok);
        ASSERT(!beta6_bs_validate_chunk_range(BETA6_BS_CHUNK_SIZE, 99, size,
                                              BETA6_BS_CHUNK_SIZE, "t").ok);
        /* An unaligned offset. */
        ASSERT(!beta6_bs_validate_chunk_range(1, 100, size, BETA6_BS_CHUNK_SIZE,
                                              "t").ok);
        /* Past the end, and a length that would overflow offset+length. */
        ASSERT(!beta6_bs_validate_chunk_range(2 * (uint64_t)BETA6_BS_CHUNK_SIZE, 1,
                                              size, BETA6_BS_CHUNK_SIZE, "t").ok);
        ASSERT(!beta6_bs_validate_chunk_range(0, UINT64_MAX, size,
                                              BETA6_BS_CHUNK_SIZE, "t").ok);
        PASS();
    }

    /* ─────────────────── path safety / service gating ────────────────── */

    TEST("only blocks/ and chainstate/ relative paths are serve data paths") {
        ASSERT(beta6_bs_check_data_path("blocks/blk00000.dat").ok);
        ASSERT(beta6_bs_check_data_path("blocks/index/000005.ldb").ok);
        ASSERT(beta6_bs_check_data_path("chainstate/000007.ldb").ok);
        ASSERT(!beta6_bs_check_data_path("wallet.dat").ok);
        ASSERT(!beta6_bs_check_data_path("blocks/../../etc/passwd").ok);
        ASSERT(!beta6_bs_check_data_path("blocks/./x").ok);
        ASSERT(!beta6_bs_check_data_path("/etc/passwd").ok);
        ASSERT(!beta6_bs_check_data_path("blocks//x").ok);
        ASSERT(!beta6_bs_check_data_path("").ok);
        PASS();
    }

    TEST("a disarmed node serves no manifest, no chunk and no listener") {
        beta6_bs_disarm();
        unsigned char scratch[16];
        struct beta6_bs_chunk_request request = { .file_index = 0, .offset = 0,
                                                  .length = 16 };
        ASSERT(!beta6_bs_status().ok);
        ASSERT(beta6_bs_manifest() == NULL);
        ASSERT_STR_EQ(beta6_bs_source_dir(), "");
        struct zcl_result chunk =
            beta6_bs_read_chunk(&request, scratch, sizeof(scratch));
        ASSERT(!chunk.ok);
        /* The refusal names the service, not a generic failure. */
        ASSERT(strstr(chunk.message, "not armed") != NULL);

        const unsigned char magic[4] = { 0x24, 0xe9, 0x27, 0x64 };
        struct zcl_result started =
            beta6_bs_listen_start("127.0.0.1", 0, magic, "main", "");
        ASSERT(!started.ok);
        ASSERT(strstr(started.message, "not armed") != NULL);
        ASSERT(!beta6_bs_listen_status().ok);
        PASS();
    }

    TEST("arming refuses a relative path and an incomplete source tree") {
        struct zcl_result relative = beta6_bs_arm("relative/dir", "main");
        ASSERT(!relative.ok);
        ASSERT(strstr(relative.message, "ABSOLUTE") != NULL);
        struct zcl_result missing = beta6_bs_arm("/nonexistent-beta6-serve-dir", "main");
        ASSERT(!missing.ok);
        ASSERT(strstr(missing.message, "incomplete") != NULL);
        ASSERT(!beta6_bs_status().ok);
        PASS();
    }

    /* ───────────────────── compiled anchors + sidecars ───────────────── */

    TEST("the compiled beta6 anchor matches only its exact height and hash") {
        size_t count = 0;
        const struct beta6_bs_anchor *anchors = beta6_bs_anchors(&count);
        ASSERT(anchors != NULL);
        ASSERT(count >= 1);
        struct uint256 hash;
        uint256_set_hex(&hash, "00000663e40f1fe0bc32a7e7282fac25de5fe8ecefd9c627"
                               "e2fd948d388f7053");
        const struct beta6_bs_anchor *found = beta6_bs_find_anchor(3126937, &hash);
        ASSERT(found != NULL);
        ASSERT_EQ(found->height, 3126937);
        ASSERT(!uint256_is_null(&found->hash_chainstate));
        /* Right hash with the wrong height, and the reverse, both miss. */
        ASSERT(beta6_bs_find_anchor(3126938, &hash) == NULL);
        struct uint256 other;
        tag_hash(&other, 0x99);
        ASSERT(beta6_bs_find_anchor(3126937, &other) == NULL);
        PASS();
    }

    /* ───────────────────── arm against a real tree ───────────────────── */

    TEST("arming orders chainstate before blocks and totals the real bytes") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "beta6_bootstrap", "serve");
        ASSERT(fixture_build(dir));

        ASSERT(beta6_bs_arm(dir, "main").ok);
        const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
        ASSERT(manifest != NULL);
        /* No .blocktip sidecar, so this is a plain v1 anchor manifest. */
        ASSERT_EQ(manifest->version, 1);
        ASSERT_EQ(manifest->height, 3126937);
        ASSERT_EQ((int)manifest->file_count, 3);
        ASSERT_STR_EQ(manifest->files[0].path, "chainstate/000007.ldb");
        ASSERT_STR_EQ(manifest->files[1].path, "blocks/blk00000.dat");
        ASSERT_STR_EQ(manifest->files[2].path, "blocks/index/000005.ldb");
        ASSERT_EQ((int)manifest->snapshot_bytes, 70);
        ASSERT_EQ((int)manifest->chunk_size, (int)BETA6_BS_CHUNK_SIZE);

        /* A chunk of a known file comes back with exactly the fixture bytes. */
        unsigned char data[20];
        struct beta6_bs_chunk_request request = { .file_index = 0, .offset = 0,
                                                  .length = 20 };
        ASSERT(beta6_bs_read_chunk(&request, data, sizeof(data)).ok);
        for (size_t i = 0; i < sizeof(data); i++)
            ASSERT_EQ((int)data[i], 0xAB);

        /* An index past the manifest, and a misaligned offset, are refused by
         * name rather than silently short-served. */
        struct beta6_bs_chunk_request unknown = { .file_index = 99, .offset = 0,
                                                  .length = 20 };
        struct zcl_result out_of_range =
            beta6_bs_read_chunk(&unknown, data, sizeof(data));
        ASSERT(!out_of_range.ok);
        ASSERT(strstr(out_of_range.message, "out of range") != NULL);
        struct beta6_bs_chunk_request skewed = { .file_index = 0, .offset = 1,
                                                 .length = 19 };
        struct zcl_result unaligned = beta6_bs_read_chunk(&skewed, data, sizeof(data));
        ASSERT(!unaligned.ok);
        ASSERT(strstr(unaligned.message, "not aligned") != NULL);

        beta6_bs_disarm();
        test_rm_rf(dir);
        PASS();
    }

    TEST("a serve tree whose .anchor names no compiled anchor is refused") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "beta6_bootstrap", "badanchor");
        ASSERT(fixture_build(dir));
        ASSERT(fixture_anchor(dir, "12345 11111111111111111111111111111111"
                                   "11111111111111111111111111111111"));

        struct zcl_result armed = beta6_bs_arm(dir, "main");
        ASSERT(!armed.ok);
        ASSERT(strstr(armed.message, "no compiled fast-sync anchor") != NULL);
        ASSERT(!beta6_bs_status().ok);
        test_rm_rf(dir);
        PASS();
    }

    /* ───────────────── in-band P2P seam (the production path) ───────── */

    TEST("the dispatch table routes all eight beta6 commands after handshake") {
        static const char *const names[] = { "getbsman",  "bsman",     "getbschk",
                                             "bschk",     "getbspman", "bspman",
                                             "getbspchk", "bspchk" };
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            const struct msg_dispatch_entry *found = NULL;
            for (const struct msg_dispatch_entry *e = msg_get_dispatch_table();
                 e->handler; e++) {
                if (strcmp(e->command, names[i]) == 0)
                    found = e;
            }
            if (!found)
                printf("\n  no dispatch row for %s\n", names[i]);
            ASSERT(found != NULL);
            /* A beta6 client is by definition NOT a z23 node, so gating these
             * on NODE_ZCL23 would ignore every real client. */
            ASSERT(!found->zcl23_only);
            /* It completes an ordinary version/verack before it asks for
             * anything (bootstrap.cpp:1866-1937). */
            ASSERT(found->requires_handshake);
        }
        PASS();
    }

    TEST("with no beta6 server wired the commands are ignored and the bit clear") {
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        memset(&mp, 0, sizeof(mp));
        memset(&node, 0, sizeof(node));
        net_manager_init(&nm);
        nm.local_host_nonce = 7;
        mp.net_mgr = &nm;
        node.version = PROTOCOL_VERSION;
        seam_addr_loopback(&node.addr);
        g_seam_calls = 0;

        const unsigned char request[12] = { 0 };
        /* Dispatched, and dropped: the same thing this node did before the
         * seam existed. Nothing is enqueued for the peer. */
        ASSERT(seam_dispatch(&mp, &node, "getbschk", request, sizeof(request)));
        ASSERT_EQ(g_seam_calls, 0);
        ASSERT(node.send_head == NULL);

        struct version_message ver;
        msg_version_build(&ver, &mp, &node, 1);
        ASSERT((ver.services & NODE_BOOTSTRAP) == 0);
        net_manager_free(&nm);
        PASS();
    }

    TEST("an armed server receives the exact payload and puts the bit in version") {
        struct net_manager nm;
        struct msg_processor mp;
        struct p2p_node node;
        memset(&mp, 0, sizeof(mp));
        memset(&node, 0, sizeof(node));
        net_manager_init(&nm);
        nm.local_host_nonce = 7;
        mp.net_mgr = &nm;
        node.version = PROTOCOL_VERSION;
        seam_addr_loopback(&node.addr);
        msg_processor_set_beta6_bootstrap(&mp, seam_armed_true, seam_record);

        g_seam_calls = 0;
        const unsigned char request[8] = { 0x02, 0, 0, 0, 0x00, 0x00, 0x10, 0x00 };
        ASSERT(seam_dispatch(&mp, &node, "getbschk", request, sizeof(request)));
        ASSERT_EQ(g_seam_calls, 1);
        ASSERT_STR_EQ(g_seam_command, "getbschk");
        ASSERT_EQ((int)g_seam_payload_len, (int)sizeof(request));
        ASSERT(memcmp(g_seam_payload, request, sizeof(request)) == 0);

        struct version_message ver;
        msg_version_build(&ver, &mp, &node, 1);
        ASSERT((ver.services & NODE_BOOTSTRAP) != 0);
        /* And the ordinary bits are untouched. */
        ASSERT((ver.services & NODE_NETWORK) != 0);
        ASSERT((ver.services & NODE_ZCL23) != 0);

        /* Uninstalling restores the pre-seam behaviour exactly. */
        msg_processor_set_beta6_bootstrap(&mp, NULL, NULL);
        g_seam_calls = 0;
        ASSERT(seam_dispatch(&mp, &node, "getbsman", NULL, 0));
        ASSERT_EQ(g_seam_calls, 0);
        msg_version_build(&ver, &mp, &node, 1);
        ASSERT((ver.services & NODE_BOOTSTRAP) == 0);
        net_manager_free(&nm);
        PASS();
    }

    TEST("the in-band server answers getbsman with the cached manifest, framed") {
        char dir[512];
        struct chain_params params;
        struct msg_processor mp;
        struct p2p_node node;
        const unsigned char magic[4] = { 0x24, 0xe9, 0x27, 0x64 };

        beta6_bs_disarm();
        beta6_bs_inband_disarm();
        memset(&params, 0, sizeof(params));
        memcpy(params.pchMessageStart, magic, sizeof(magic));
        memset(&mp, 0, sizeof(mp));
        mp.params = &params;
        memset(&node, 0, sizeof(node));
        zcl_mutex_init(&node.cs_send);
        seam_addr_loopback(&node.addr);

        /* Nothing armed: a NAMED reject, promptly, never a stall — the client
         * aborts a stream that goes quiet for 60 s. */
        ASSERT(!beta6_bs_inband_status().ok);
        ASSERT(beta6_bs_inband_serve(&mp, &node, "getbsman", NULL, 0).ok);
        ASSERT(node.send_head != NULL);
        ASSERT(memcmp(node.send_head->data, magic, 4) == 0);
        ASSERT_STR_EQ((const char *)node.send_head->data + 4, "reject");
        seam_drain(&node);

        test_make_tmpdir(dir, sizeof(dir), "beta6_bootstrap", "inband");
        ASSERT(fixture_build(dir));
        ASSERT(beta6_bs_arm(dir, "main").ok);
        ASSERT(beta6_bs_inband_arm("main", "").ok);
        ASSERT(beta6_bs_inband_status().ok);

        ASSERT(beta6_bs_inband_serve(&mp, &node, "getbsman", NULL, 0).ok);
        ASSERT(node.send_head != NULL);
        const unsigned char *frame = node.send_head->data;
        ASSERT(node.send_head->size > 24);
        ASSERT(memcmp(frame, magic, 4) == 0);
        ASSERT_STR_EQ((const char *)frame + 4, "bsman");
        /* The framed payload is the real manifest: decode it back and read the
         * height a beta6 client would install from. */
        struct byte_stream body;
        stream_init_from_data(&body, frame + 24, node.send_head->size - 24);
        struct beta6_bs_manifest decoded;
        ASSERT(beta6_bs_manifest_decode(&body, &decoded).ok);
        stream_free(&body);
        ASSERT_EQ(decoded.height, 3126937);
        ASSERT_EQ((int)decoded.file_count, 3);
        beta6_bs_manifest_free(&decoded);
        seam_drain(&node);

        /* An unsolicited SERVER reply is dropped, not parsed and not answered. */
        ASSERT(beta6_bs_inband_serve(&mp, &node, "bschk", NULL, 0).ok);
        ASSERT(node.send_head == NULL);

        beta6_bs_inband_disarm();
        ASSERT(!beta6_bs_inband_status().ok);
        beta6_bs_disarm();
        zcl_mutex_destroy(&node.cs_send);
        test_rm_rf(dir);
        PASS();
    }

    /* ──────────────────────── per-address quota ─────────────────────── */

    TEST("quota buckets collapse to the IPv4 /24 and the IPv6 /64") {
        char key[80];
        ASSERT(beta6_bs_quota_key("203.0.113.7", key, sizeof(key)).ok);
        ASSERT_STR_EQ(key, "v4/24:203.0.113");
        ASSERT(beta6_bs_quota_key("203.0.113.250", key, sizeof(key)).ok);
        ASSERT_STR_EQ(key, "v4/24:203.0.113");
        ASSERT(beta6_bs_quota_key("2001:db8:1:2:3:4:5:6", key, sizeof(key)).ok);
        ASSERT_STR_EQ(key, "v6/64:2001:db8:1:2");
        /* Neither tagged form can alias the other, or a bare identity. */
        ASSERT(beta6_bs_quota_key("someonion.onion", key, sizeof(key)).ok);
        ASSERT_STR_EQ(key, "someonion.onion");
        PASS();
    }

    TEST("a bucket over its daily cap is throttled, then stopped when told to") {
        beta6_bs_quota_clear();
        beta6_bs_quota_configure(1000, 1024);
        /* Nothing served to this bucket yet: allowed. */
        ASSERT(beta6_bs_quota_check("v4/24:203.0.113", false, 0).ok);
        beta6_bs_quota_charge("v4/24:203.0.113", false, 0, 900);
        ASSERT(beta6_bs_quota_check("v4/24:203.0.113", false, 0).ok);
        /* Crossing the cap arms the spacing gap, which is a RETRY refusal,
         * never the hard stop. */
        beta6_bs_quota_charge("v4/24:203.0.113", false, 0, 200);
        struct zcl_result spaced = beta6_bs_quota_check("v4/24:203.0.113", false, 0);
        ASSERT(!spaced.ok);
        ASSERT_EQ(spaced.code, BETA6_BS_ERR_QUOTA_SPACING);
        /* Another bucket is unaffected, and the window rolls over. */
        ASSERT(beta6_bs_quota_check("v4/24:198.51.100", false, 0).ok);
        ASSERT(beta6_bs_quota_check("v4/24:203.0.113", false,
                                    BETA6_BS_QUOTA_WINDOW_MS).ok);

        /* Throttle off means a hard stop instead of a slow trickle. */
        beta6_bs_quota_clear();
        beta6_bs_quota_configure(1000, 0);
        beta6_bs_quota_charge("v4/24:203.0.113", false, 0, 1000);
        struct zcl_result stopped = beta6_bs_quota_check("v4/24:203.0.113", false, 0);
        ASSERT(!stopped.ok);
        ASSERT_EQ(stopped.code, BETA6_BS_ERR_QUOTA_STOPPED);

        /* A whitelisted peer and a zero cap both bypass the accounting. */
        ASSERT(beta6_bs_quota_check("v4/24:203.0.113", true, 0).ok);
        beta6_bs_quota_configure(0, 0);
        ASSERT(beta6_bs_quota_check("v4/24:203.0.113", false, 0).ok);

        beta6_bs_quota_clear();
        beta6_bs_quota_configure(BETA6_BS_DEFAULT_MAX_BYTES_PER_DAY,
                                 BETA6_BS_DEFAULT_THROTTLE_KBPS);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_beta6_bootstrap: all passed\n");
    else
        printf("test_beta6_bootstrap: %d FAILED\n", failures);
    return failures;
}
