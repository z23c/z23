/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity-free P2P source retrieval: zcode.workspace.source.bundle.fetch and
 * the service under it (engine/services/src/source_bundle_fetch.c).
 *
 * WHY THIS FILE'S CENTRAL TEST IS SUBSTITUTION, NOT CORRUPTION.
 *
 * A single-byte-flip test proves nothing about this path, and that is a
 * MEASURED claim, not a guess: three flips at offsets 120 / 14000 / 28950 of a
 * real 28,957-byte bundle were all rejected with "compression-codec" — the
 * framing layer — and never reached a hash comparison at all. A suite built on
 * flips would stay green with the entire content check deleted.
 *
 * The attack that actually reaches the content check is SUBSTITUTION: a
 * WELL-FORMED bundle of a tree that differs by one byte, which verifies
 * perfectly under its OWN root, offered in reply to a request for the HONEST
 * root. case (b) below builds exactly that, proves it is well-formed by
 * verifying it under its own root FIRST, and only then offers it under the
 * honest root — and pins the refusal reason to "tree-root-mismatch"
 * specifically, so a regression that let the framing layer catch it instead
 * would fail here rather than pass.
 *
 * Everything runs over the REAL serve path (fs_server_start on a fixture
 * datadir) against 127.0.0.1 — no mock transport, no external network, no real
 * datadir. Fixtures live under mkdtemp(). Every assertion is about a
 * RELATIONSHIP or an OUTCOME; none is about wall-clock duration, because this
 * fleet includes deliberately slow 7200 rpm boxes and an SSD-shaped timing
 * assertion would grade an honest node as broken. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "net/file_service.h"
#include "net/rom_fetch.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"
#include "services/source_bundle_fetch.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"

#include <fcntl.h>
#if !defined(_WIN32)
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#endif
#include <pthread.h>
#include <stdatomic.h>

#if !defined(_WIN32)

/* ── Fixtures ───────────────────────────────────────────────────────── */

static bool sbft_write(const char *dir, const char *name,
                       const void *bytes, size_t len)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    const uint8_t *p = bytes;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    return close(fd) == 0;
}

/* Two source trees that differ in exactly ONE byte. `flavor` selects that
 * byte, so the two capture to different ZVCS tree roots while every other
 * path, mode and length is identical — the shape a substitution attack needs
 * to be interesting. */
static bool sbft_make_tree(const char *dir, char flavor)
{
    char body[512];
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (char)('a' + (int)(i % 26));
    body[7] = flavor;                    /* the one differing byte */
    return sbft_write(dir, "alpha.c", body, sizeof(body)) &&
           sbft_write(dir, "beta.h", "#pragma once\n", 13) &&
           sbft_write(dir, "notes.txt", "z23 source transport\n", 21);
}

/* Capture `dir` into its own ZVCS CAS and build the compressed bundle. */
static bool sbft_bundle(const char *dir, uint8_t root_out[32],
                        uint8_t **wire_out, size_t *len_out)
{
    *wire_out = NULL;
    *len_out = 0;
    if (vcs_tree_capture_path(dir, root_out) != VCS_OK)
        return false;
    struct vcs_source_bundle_metrics m;
    return vcs_source_bundle_create(dir, root_out, wire_out, len_out, &m) ==
           VCS_SOURCE_BUNDLE_OK;
}

/* Start the real file service on `datadir` and return its OS-assigned port
 * (0 on failure). Port 0 everywhere: a fixed port would collide with a second
 * copy of this suite, or with anything else on the box.
 *
 * The leading stop is not decoration. fs_server_start() returns SILENTLY when
 * a server is already running (core/modules/net/src/file_service.c) and keeps the
 * datadir it was started with, so a case that exits early — an ASSERT jumps
 * straight to _test_next: and skips its own fs_server_stop() — would leave the
 * NEXT case serving chunk reads out of a stale, already-deleted directory.
 * That reads as "read_chunk: validated open failed" on every chunk and turns
 * one honest failure into a second, unrelated-looking one. Each case owns its
 * own server. */
static uint16_t sbft_serve(const char *datadir)
{
    fs_server_stop();
    fs_server_start(datadir, 0, NULL);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50);
    return fs_server_is_running() ? fs_server_get_port() : 0;
}

static void sbft_peer(struct rom_fetch_peer *p, uint16_t port)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->addr, sizeof(p->addr), "%s", "127.0.0.1");
    p->port = port;
}

/* Raise the free-tier byte-rate windows so a multi-case suite is not throttled
 * by its own previous case; rom_seed_reset() restores the defaults. */
static void sbft_open_caps(void)
{
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);
}

/* True when `dir` holds no file at all — the "materialized: 0" check. Used on
 * the fetch staging/output directory after every refusal. */
static bool sbft_dir_empty(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    bool empty = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    closedir(d);
    return empty;
}

/* ── An accept-then-drop seeder: a peer that STALLS ─────────────────────
 *
 * Distinct from "nothing listening" (immediate ECONNREFUSED): this endpoint
 * completes the TCP handshake, so the connect succeeds and the fetcher is
 * committed to it, then goes quiet and closes without ever answering. That is
 * the failure a real wedged or overloaded seeder produces. Mirrors the
 * rf_hang_seeder fixture in test_rom_fetch.c. */
struct sbft_stall_peer {
    int listen_fd;
    uint16_t port;
    pthread_t tid;
    _Atomic bool stop;
    _Atomic int accepts;
};

/* A deliberately incomplete file-service peer: it completes the real
 * handshake and serves exactly one caller-supplied RLS body, then closes every
 * RMF/chunk request. This is the useful adversary for candidate selection: its
 * directory claims are authenticated by the transport but remain untrusted,
 * while an independent honest fs_server supplies the actual artifact. */
struct sbft_directory_peer {
    int listen_fd;
    uint16_t port;
    pthread_t tid;
    _Atomic bool stop;
    _Atomic int listings;
    char body[9000]; /* over the fetcher's 8192-byte directory cap, on purpose */
};

static void *sbft_directory_thread(void *arg)
{
    static const uint8_t list_tag[32] = { 'R', 'L', 'S' };
    struct sbft_directory_peer *peer = arg;
    while (!atomic_load(&peer->stop)) {
        struct pollfd pfd = { .fd = peer->listen_fd, .events = POLLIN };
        if (poll(&pfd, 1, 100) <= 0)
            continue;
        int fd = accept(peer->listen_fd, NULL, NULL);
        if (fd < 0)
            continue;
        struct fs_session session;
        fs_session_init(&session, fd);
        uint8_t root[32] = {0};
        uint8_t type = 0;
        const uint8_t *payload = NULL;
        uint32_t payload_len = 0;
        if (fs_handshake(&session, root, false) &&
            fs_recv_frame(&session, &type, &payload, &payload_len) &&
            type == FS_REQUEST && payload_len == FS_ROM_LIST_REQUEST_SIZE &&
            memcmp(payload, "RLS", FS_ROM_LIST_REQUEST_SIZE) == 0) {
            size_t body_len = strlen(peer->body);
            if (body_len <= UINT32_MAX &&
                fs_send_chunk_fast(&session, (const uint8_t *)peer->body,
                                   (uint32_t)body_len, list_tag))
                atomic_fetch_add(&peer->listings, 1);
        }
        fs_session_cleanup(&session);
        close(fd);
    }
    return NULL;
}

static bool sbft_directory_start(struct sbft_directory_peer *peer,
                                 const char *body)
{
    if (!peer || !body || strlen(body) >= sizeof(peer->body))
        return false;
    memset(peer, 0, sizeof(*peer));
    snprintf(peer->body, sizeof(peer->body), "%s", body);
    peer->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer->listen_fd < 0)
        return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t addr_len = sizeof(addr);
    if (bind(peer->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(peer->listen_fd, 8) != 0 ||
        getsockname(peer->listen_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        close(peer->listen_fd);
        return false;
    }
    peer->port = ntohs(addr.sin_port);
    atomic_init(&peer->stop, false);
    atomic_init(&peer->listings, 0);
    if (peer->port == 0 ||
        pthread_create(&peer->tid, NULL, sbft_directory_thread, peer) != 0) {
        close(peer->listen_fd);
        return false;
    }
    return true;
}

static void sbft_directory_stop(struct sbft_directory_peer *peer)
{
    atomic_store(&peer->stop, true);
    pthread_join(peer->tid, NULL);
    close(peer->listen_fd);
}

static void *sbft_stall_thread(void *arg)
{
    struct sbft_stall_peer *h = arg;
    while (!atomic_load(&h->stop)) {
        struct pollfd pfd = { .fd = h->listen_fd, .events = POLLIN };
        if (poll(&pfd, 1, 100) <= 0)
            continue;
        int cfd = accept(h->listen_fd, NULL, NULL);
        if (cfd < 0)
            continue;
        atomic_fetch_add(&h->accepts, 1);
        platform_sleep_ms(150);
        close(cfd);
    }
    return NULL;
}

static bool sbft_stall_start(struct sbft_stall_peer *h)
{
    memset(h, 0, sizeof(*h));
    h->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (h->listen_fd < 0) return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    socklen_t alen = sizeof(addr);
    if (bind(h->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(h->listen_fd, 8) != 0 ||
        getsockname(h->listen_fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(h->listen_fd);
        return false;
    }
    h->port = ntohs(addr.sin_port);
    atomic_store(&h->stop, false);
    atomic_store(&h->accepts, 0);
    if (h->port == 0 ||
        pthread_create(&h->tid, NULL, sbft_stall_thread, h) != 0) {
        close(h->listen_fd);
        return false;
    }
    return true;
}

static void sbft_stall_stop(struct sbft_stall_peer *h)
{
    atomic_store(&h->stop, true);
    pthread_join(h->tid, NULL);
    close(h->listen_fd);
}

/* ── (0) The duplicated header constants must not drift ─────────────── */

/* core/modules/net may not include contexts/commons/modules/vcs, so rom_seed restates the ZVSB header shape.
 * This is the gate that keeps the restatement honest: a drift would silently
 * stop every source bundle being findable, which presents as "the swarm has
 * nothing" rather than as an error. */
static int test_header_shape_pinned(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: rom_seed's restated ZVSB header shape matches "
         "contexts/commons/modules/vcs, and reads the same root vcs committed") {
        ASSERT(ROM_SEED_SOURCE_BUNDLE_HEADER_BYTES ==
               VCS_SOURCE_BUNDLE_HEADER_BYTES);
        ASSERT(ROM_SEED_SOURCE_BUNDLE_MIN_BYTES ==
               VCS_SOURCE_BUNDLE_HEADER_BYTES + 1u);

        char troot[PATH_MAX];
        char *tdir = test_mkdtemp(troot, sizeof(troot), "zcl_sbfetch_hdr");
        ASSERT(tdir != NULL);
        ASSERT(sbft_make_tree(tdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(tdir, root, &wire, &wire_len));
        ASSERT(wire_len > VCS_SOURCE_BUNDLE_HEADER_BYTES);

        /* The independent reader lands on the SAME 32 bytes the writer put
         * there — the whole point of the restated offset. */
        uint8_t read_back[32];
        ASSERT(rom_seed_source_bundle_root(wire, wire_len, read_back));
        ASSERT(memcmp(read_back, root, 32) == 0);

        /* And it is strict: a short window, a wrong magic and a wrong version
         * are all refused rather than guessed at. */
        uint8_t probe[VCS_SOURCE_BUNDLE_HEADER_BYTES];
        memcpy(probe, wire, sizeof(probe));
        ASSERT(!rom_seed_source_bundle_root(wire, sizeof(probe) - 1,
                                            read_back));
        probe[0] ^= 0xFFu;
        ASSERT(!rom_seed_source_bundle_root(probe, sizeof(probe), read_back));
        memcpy(probe, wire, sizeof(probe));
        probe[8] = 0x7Fu;                       /* implausible version */
        ASSERT(!rom_seed_source_bundle_root(probe, sizeof(probe), read_back));

        /* A ".zvsb" name classifies as a source bundle; a bare ".zvsb"
         * dotfile does not, and neither do the ROM kinds' names. */
        ASSERT(rom_seed_classify("tree.zvsb") == ROM_ARTIFACT_SOURCE_BUNDLE);
        ASSERT(rom_seed_classify("bundles/tree.zvsb") ==
               ROM_ARTIFACT_SOURCE_BUNDLE);
        ASSERT(rom_seed_classify(".zvsb") == ROM_ARTIFACT_UNKNOWN);
        ASSERT(rom_seed_classify("block_index.bin") ==
               ROM_ARTIFACT_HEADER_SEED);
        ASSERT(rom_seed_kind_from_name("source_bundle") ==
               ROM_ARTIFACT_SOURCE_BUNDLE);

        free(wire);
        test_cleanup_tmpdir(tdir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (a) Fetch by root from a cooperating peer ──────────────────────── */

static int test_fetch_by_root(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a peer serving a source bundle delivers it by "
         "root, and the bytes rederive to that exact root") {
        sbft_open_caps();
        char troot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *tdir = test_mkdtemp(troot, sizeof(troot), "zcl_sbfetch_ok_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_ok_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_ok_cli");
        ASSERT(tdir && sdir && cdir);
        ASSERT(sbft_make_tree(tdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(tdir, root, &wire, &wire_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", wire, wire_len));

        /* The serve side advertises the root it read from the FILE. */
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, &art) == ROM_REG_OK);
        ASSERT(art.kind == ROM_ARTIFACT_SOURCE_BUNDLE);
        ASSERT(art.has_source_root);
        ASSERT(memcmp(art.source_root, root, 32) == 0);

        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(&peer, 1, root, cdir, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_OK);

        /* Byte-identical to what the seeder holds, and independently
         * re-provable against the root the caller started with. */
        ASSERT(got != NULL && got_len == wire_len);
        ASSERT(memcmp(got, wire, wire_len) == 0);
        struct vcs_source_bundle_metrics vm;
        ASSERT(vcs_source_bundle_verify(got, got_len, root, &vm) ==
               VCS_SOURCE_BUNDLE_OK);
        ASSERT(vm.file_count == 3);

        ASSERT(m.peers_asked == 1 && m.peers_offering == 1);
        ASSERT(m.candidates_tried == 1 && m.candidates_refused == 0);
        ASSERT(m.wire_bytes == (uint64_t)wire_len);
        /* Staging is left exactly as it was found — no .part, no .journal,
         * no staged copy. */
        ASSERT(sbft_dir_empty(cdir));

        free(got);
        free(wire);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(tdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) SUBSTITUTION — the test this file exists for ───────────────── */

static int test_substitution_refused(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a WELL-FORMED bundle of a one-byte-different "
         "tree, offered under the honest root, is refused as "
         "tree-root-mismatch with nothing materialized") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char eroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_sub_honest");
        char *edir = test_mkdtemp(eroot, sizeof(eroot), "zcl_sbfetch_sub_evil");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_sub_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_sub_cli");
        ASSERT(hdir && edir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));
        ASSERT(sbft_make_tree(edir, 'B'));   /* ONE byte apart */

        uint8_t honest_root[32], evil_root[32];
        uint8_t *honest = NULL, *evil = NULL;
        size_t honest_len = 0, evil_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));
        ASSERT(sbft_bundle(edir, evil_root, &evil, &evil_len));
        ASSERT(memcmp(honest_root, evil_root, 32) != 0);

        /* The evil bundle is WELL-FORMED — it verifies perfectly under its
         * own root. Anything this test later proves is therefore about the
         * CONTENT check, not about a malformed file. */
        struct vcs_source_bundle_metrics vm;
        ASSERT(vcs_source_bundle_verify(evil, evil_len, evil_root, &vm) ==
               VCS_SOURCE_BUNDLE_OK);

        /* Now offer it under the HONEST root. The seeder's advertisement is
         * read out of the bundle header, so relabelling that header is what
         * makes a peer claim these bytes are the honest tree — the same lie a
         * hand-written malicious seeder would tell in its directory reply,
         * expressed through the real serve path instead of a mock. */
        memcpy(evil + ROM_SEED_SOURCE_BUNDLE_ROOT_OFFSET, honest_root, 32);
        ASSERT(memcmp(evil + 12, honest_root, 32) == 0); /* root at offset 12 */

        /* The refusal must come from the ROOT comparison, not from framing.
         * A byte-flip test would stop at "compression-codec" and never reach
         * this line; pinning the reason is what keeps that distinction. */
        ASSERT(vcs_source_bundle_verify(evil, evil_len, honest_root, &vm) ==
               VCS_SOURCE_BUNDLE_ERR_ROOT);

        ASSERT(sbft_write(sdir, "impostor.zvsb", evil, evil_len));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "impostor.zvsb", NULL, &art) ==
               ROM_REG_OK);
        ASSERT(art.has_source_root);
        ASSERT(memcmp(art.source_root, honest_root, 32) == 0);  /* it lies */

        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        enum source_bundle_fetch_result r = source_bundle_fetch(
            &peer, 1, honest_root, cdir, &got, &got_len, &m);

        ASSERT(r == SOURCE_BUNDLE_FETCH_ERR_ROOT);
        ASSERT(got == NULL && got_len == 0);
        /* The peer WAS reached and its bytes WERE downloaded — this is a
         * content refusal, not a transport failure that never got there. */
        ASSERT(m.peers_offering == 1);
        ASSERT(m.candidates_tried == 1 && m.candidates_refused == 1);
        ASSERT(m.last_refusal == VCS_SOURCE_BUNDLE_ERR_ROOT);
        ASSERT(strcmp(vcs_source_bundle_result_string(m.last_refusal),
                      "tree-root-mismatch") == 0);
        /* Nothing materialized: no staged copy, no .part, no journal. */
        ASSERT(sbft_dir_empty(cdir));
        /* And the peer is abandoned, not retried forever. */
        ASSERT(rom_peer_is_deprioritized("127.0.0.1", port));

        free(honest);
        free(evil);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(edir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) A substitution does not bury the honest copy ───────────────── */

static int test_substitution_then_recovery(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: an impostor offered FIRST is refused and the "
         "search continues to the honest bundle behind it") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char eroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_rec_honest");
        char *edir = test_mkdtemp(eroot, sizeof(eroot), "zcl_sbfetch_rec_evil");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_rec_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_rec_cli");
        ASSERT(hdir && edir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));
        ASSERT(sbft_make_tree(edir, 'B'));

        uint8_t honest_root[32], evil_root[32];
        uint8_t *honest = NULL, *evil = NULL;
        size_t honest_len = 0, evil_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));
        ASSERT(sbft_bundle(edir, evil_root, &evil, &evil_len));
        memcpy(evil + 12, honest_root, 32);

        ASSERT(sbft_write(sdir, "impostor.zvsb", evil, evil_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", honest, honest_len));
        /* Registration order IS directory order, so registering the impostor
         * first makes the fetcher meet it first — deterministically, instead
         * of leaving the interesting ordering to readdir(). */
        ASSERT(rom_seed_register(sdir, "impostor.zvsb", NULL, NULL) ==
               ROM_REG_OK);
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, NULL) == ROM_REG_OK);

        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(&peer, 1, honest_root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_OK);
        ASSERT(got != NULL && got_len == honest_len);
        ASSERT(memcmp(got, honest, honest_len) == 0);
        /* Both were downloaded; exactly one was refused. A search that had
         * stopped at the first refusal would have returned ERR_ROOT above. */
        ASSERT(m.candidates_tried == 2 && m.candidates_refused == 1);
        ASSERT(sbft_dir_empty(cdir));

        free(got);
        free(honest);
        free(evil);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(edir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (d) Truncated / garbage payloads ───────────────────────────────── */

static int test_damaged_payload_refused(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a truncated and a garbage-payload bundle "
         "advertising the honest root are both refused, with distinct "
         "reasons and nothing materialized") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_dmg_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_dmg_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_dmg_cli");
        ASSERT(hdir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));

        uint8_t honest_root[32], *honest = NULL;
        size_t honest_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));
        ASSERT(honest_len > VCS_SOURCE_BUNDLE_HEADER_BYTES + 64);

        /* (1) Truncated: the header still claims the honest root and a
         * compressed length the file no longer has. */
        ASSERT(sbft_write(sdir, "short.zvsb", honest, honest_len - 32));
        ASSERT(rom_seed_register(sdir, "short.zvsb", NULL, NULL) ==
               ROM_REG_OK);
        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(&peer, 1, honest_root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_ERR_ROOT);
        ASSERT(got == NULL && got_len == 0);
        ASSERT(m.candidates_tried == 1 && m.candidates_refused == 1);
        ASSERT(m.last_refusal == VCS_SOURCE_BUNDLE_ERR_LIMIT);
        ASSERT(sbft_dir_empty(cdir));
        ASSERT(rom_peer_is_deprioritized("127.0.0.1", port));
        fs_server_stop();

        /* (2) Garbage payload behind an honest-looking header: the framing
         * layer catches this one, and it must report a DIFFERENT reason from
         * the substitution above — three attacks, three messages. */
        sbft_open_caps();
        uint8_t *junk = malloc(honest_len);
        ASSERT(junk != NULL);
        memcpy(junk, honest, honest_len);
        for (size_t i = VCS_SOURCE_BUNDLE_HEADER_BYTES; i < honest_len; i++)
            junk[i] = (uint8_t)(0xA5u ^ (i & 0xFFu));
        ASSERT(sbft_write(sdir, "junk.zvsb", junk, honest_len));
        ASSERT(rom_seed_register(sdir, "junk.zvsb", NULL, NULL) == ROM_REG_OK);
        port = sbft_serve(sdir);
        ASSERT(port != 0);
        sbft_peer(&peer, port);
        got = NULL;
        got_len = 0;
        ASSERT(source_bundle_fetch(&peer, 1, honest_root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_ERR_ROOT);
        ASSERT(got == NULL && got_len == 0);
        ASSERT(m.candidates_refused == 1);
        ASSERT(m.last_refusal == VCS_SOURCE_BUNDLE_ERR_CODEC);
        ASSERT(m.last_refusal != VCS_SOURCE_BUNDLE_ERR_ROOT);
        ASSERT(sbft_dir_empty(cdir));

        free(junk);
        free(honest);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (e) A stalling peer is abandoned, and the next one still runs ───── */

static int test_stalled_peer_failover(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a peer that accepts then goes quiet is "
         "abandoned and the honest peer behind it still delivers") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_stall_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_stall_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_stall_cli");
        ASSERT(hdir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(hdir, root, &wire, &wire_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", wire, wire_len));
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, NULL) == ROM_REG_OK);

        struct sbft_stall_peer stall;
        ASSERT(sbft_stall_start(&stall));
        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        /* The staller is asked FIRST, so the fetch only succeeds by getting
         * past it. Assertions are on OUTCOME and on the staller's own accept
         * counter — never on how long anything took, because a slow honest
         * box must never be graded as an attacker. */
        struct rom_fetch_peer peers[2];
        sbft_peer(&peers[0], stall.port);
        sbft_peer(&peers[1], port);

        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(peers, 2, root, cdir, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_OK);
        ASSERT(got != NULL && got_len == wire_len);
        ASSERT(memcmp(got, wire, wire_len) == 0);
        ASSERT(m.peers_asked == 2);
        ASSERT(m.peers_offering == 1);   /* the staller offered nothing */
        ASSERT(atomic_load(&stall.accepts) >= 1); /* it WAS contacted */
        ASSERT(sbft_dir_empty(cdir));

        /* Alone, the same staller is a clean named refusal — never a hang. */
        free(got);
        got = NULL;
        got_len = 0;
        ASSERT(source_bundle_fetch(&peers[0], 1, root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
        ASSERT(got == NULL && got_len == 0);
        ASSERT(sbft_dir_empty(cdir));

        sbft_stall_stop(&stall);
        free(wire);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (f) Nobody has it — a named refusal, not a hang ─────────────────── */

static int test_no_peer_named_refusal(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: an unknown root, a dead endpoint and an empty "
         "peer list each return a distinct named refusal") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_none_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_none_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_none_cli");
        ASSERT(hdir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(hdir, root, &wire, &wire_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", wire, wire_len));
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, NULL) == ROM_REG_OK);
        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;

        /* (1) A live peer that simply does not have this root. */
        uint8_t absent[32];
        memset(absent, 0x5C, sizeof(absent));
        ASSERT(source_bundle_fetch(&peer, 1, absent, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
        ASSERT(got == NULL && m.peers_asked == 1 && m.peers_offering == 0);

        /* (2) Nothing listening at all. */
        fs_server_stop();
        ASSERT(source_bundle_fetch(&peer, 1, root, cdir, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
        ASSERT(got == NULL && got_len == 0);

        /* (3) Malformed calls are refused as arguments, never attempted. */
        ASSERT(source_bundle_fetch(&peer, 0, root, cdir, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_ERR_ARGS);
        ASSERT(source_bundle_fetch(&peer, 1, root, NULL, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_ERR_ARGS);
        ASSERT(source_bundle_fetch(&peer, SOURCE_BUNDLE_FETCH_MAX_PEERS + 1u,
                                   root, cdir, &got, &got_len, &m) ==
               SOURCE_BUNDLE_FETCH_ERR_ARGS);
        ASSERT(got == NULL && got_len == 0);
        ASSERT(sbft_dir_empty(cdir));

        free(wire);
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Adversarial directory construction ─────────────────────────────── */

static void sbft_run_leaf(const char *root_hex, const char *out_path,
                          const char *peers, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "source_root", root_hex);
    (void)json_push_kv_str(&input, "output", out_path);
    (void)json_push_kv_str(&input, "peers", peers);
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, "zcl.zcode_source_bundle_fetch.v1");
    zcl_native_handle_zcode_source_bundle_fetch(&request, reply);
    json_free(&input);
}

static void sbft_hex32(const uint8_t v[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = d[v[i] >> 4];
        out[i * 2 + 1] = d[v[i] & 0x0F];
    }
    out[64] = '\0';
}

static bool sbft_append_offer(char *body, size_t cap, size_t *off,
                              bool comma, const uint8_t chunk_root[32],
                              const uint8_t whole_sha3[32],
                              const uint8_t source_root[32], uint64_t size,
                              uint32_t chunks)
{
    char chunk_hex[65], whole_hex[65], source_hex[65];
    sbft_hex32(chunk_root, chunk_hex);
    sbft_hex32(whole_sha3, whole_hex);
    sbft_hex32(source_root, source_hex);
    int n = snprintf(body + *off, cap - *off,
        "%s{\"kind\":\"source_bundle\",\"digest\":\"%s\","
        "\"whole_sha3\":\"%s\",\"size\":%llu,\"chunk_size\":%u,"
        "\"chunks\":%u,\"height\":0,\"source_root\":\"%s\"}",
        comma ? "," : "", chunk_hex, whole_hex,
        (unsigned long long)size, ROM_SEED_CHUNK_SIZE, chunks, source_hex);
    if (n <= 0 || (size_t)n >= cap - *off)
        return false;
    *off += (size_t)n;
    return true;
}

static bool sbft_finish_directory(char *body, size_t cap, size_t *off)
{
    int n = snprintf(body + *off, cap - *off, "]}");
    if (n <= 0 || (size_t)n >= cap - *off)
        return false;
    *off += (size_t)n;
    return true;
}

static int test_same_chunk_root_divergent_manifest(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: same chunk root with divergent whole-file "
         "metadata remains a separate candidate") {
        sbft_open_caps();
        char troot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *tdir = test_mkdtemp(troot, sizeof(troot), "zcl_sbfetch_tuple_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_tuple_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_tuple_cli");
        ASSERT(tdir && sdir && cdir);
        ASSERT(sbft_make_tree(tdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(tdir, root, &wire, &wire_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", wire, wire_len));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, &art) == ROM_REG_OK);

        uint8_t false_whole[32];
        memcpy(false_whole, art.whole_sha3, sizeof(false_whole));
        false_whole[0] ^= 0x80u;
        char body[8192] = "{\"artifacts\":[";
        size_t body_len = strlen(body);
        ASSERT(sbft_append_offer(body, sizeof(body), &body_len, false,
                                 art.chunk_root, false_whole, root,
                                 art.size_bytes, art.num_chunks));
        ASSERT(sbft_finish_directory(body, sizeof(body), &body_len));

        struct sbft_directory_peer liar;
        ASSERT(sbft_directory_start(&liar, body));
        uint16_t honest_port = sbft_serve(sdir);
        ASSERT(honest_port != 0);
        struct rom_fetch_peer peers[2];
        sbft_peer(&peers[0], liar.port);
        sbft_peer(&peers[1], honest_port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics metrics;
        ASSERT(source_bundle_fetch(peers, 2, root, cdir, &got, &got_len,
                                   &metrics) == SOURCE_BUNDLE_FETCH_OK);
        ASSERT(got && got_len == wire_len && memcmp(got, wire, wire_len) == 0);
        ASSERT(metrics.peers_offering == 2 && metrics.candidates_tried == 1);
        ASSERT(atomic_load(&liar.listings) == 1);
        ASSERT(sbft_dir_empty(cdir));

        free(got);
        sbft_directory_stop(&liar);
        free(wire);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(tdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

static int test_one_peer_cannot_fill_candidate_set(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: one peer cannot consume every candidate slot "
         "ahead of an honest peer") {
        sbft_open_caps();
        char troot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *tdir = test_mkdtemp(troot, sizeof(troot), "zcl_sbfetch_slots_tree");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_slots_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_slots_cli");
        ASSERT(tdir && sdir && cdir);
        ASSERT(sbft_make_tree(tdir, 'A'));

        uint8_t root[32], *wire = NULL;
        size_t wire_len = 0;
        ASSERT(sbft_bundle(tdir, root, &wire, &wire_len));
        ASSERT(sbft_write(sdir, "tree.zvsb", wire, wire_len));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, &art) == ROM_REG_OK);

        char body[8192] = "{\"artifacts\":[";
        size_t body_len = strlen(body);
        for (uint32_t i = 0; i < SOURCE_BUNDLE_FETCH_MAX_CANDIDATES; i++) {
            uint8_t fake_chunk[32], fake_whole[32];
            memcpy(fake_chunk, art.chunk_root, sizeof(fake_chunk));
            memcpy(fake_whole, art.whole_sha3, sizeof(fake_whole));
            fake_chunk[0] ^= (uint8_t)(i + 1u);
            fake_whole[1] ^= (uint8_t)(0x40u + i);
            ASSERT(sbft_append_offer(body, sizeof(body), &body_len, i != 0,
                                     fake_chunk, fake_whole, root,
                                     art.size_bytes, art.num_chunks));
        }
        ASSERT(sbft_finish_directory(body, sizeof(body), &body_len));

        struct sbft_directory_peer flooder;
        ASSERT(sbft_directory_start(&flooder, body));
        uint16_t honest_port = sbft_serve(sdir);
        ASSERT(honest_port != 0);
        struct rom_fetch_peer peers[2];
        sbft_peer(&peers[0], flooder.port);
        sbft_peer(&peers[1], honest_port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics metrics;
        ASSERT(source_bundle_fetch(peers, 2, root, cdir, &got, &got_len,
                                   &metrics) == SOURCE_BUNDLE_FETCH_OK);
        ASSERT(got && got_len == wire_len && memcmp(got, wire, wire_len) == 0);
        ASSERT(metrics.peers_asked == 2 && metrics.peers_offering == 2);
        ASSERT(atomic_load(&flooder.listings) == 1);
        ASSERT(sbft_dir_empty(cdir));

        free(got);
        sbft_directory_stop(&flooder);
        free(wire);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(tdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (i) The leaf itself: no output file on a refusal ────────────────── */

static int test_leaf_end_to_end(void)
{
    int failures = 0;
    TEST("zcode.workspace.source.bundle.fetch: writes the verified bundle on "
         "success and creates NO output file on a substitution refusal") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char eroot[PATH_MAX];
        char sroot[PATH_MAX];
        char oroot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_leaf_honest");
        char *edir = test_mkdtemp(eroot, sizeof(eroot), "zcl_sbfetch_leaf_evil");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_leaf_srv");
        char *odir = test_mkdtemp(oroot, sizeof(oroot), "zcl_sbfetch_leaf_out");
        ASSERT(hdir && edir && sdir && odir);
        ASSERT(sbft_make_tree(hdir, 'A'));
        ASSERT(sbft_make_tree(edir, 'B'));

        uint8_t honest_root[32], evil_root[32];
        uint8_t *honest = NULL, *evil = NULL;
        size_t honest_len = 0, evil_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));
        ASSERT(sbft_bundle(edir, evil_root, &evil, &evil_len));
        memcpy(evil + 12, honest_root, 32);

        char honest_hex[65];
        sbft_hex32(honest_root, honest_hex);
        char out_path[1100];
        snprintf(out_path, sizeof(out_path), "%s/fetched.zvsb", odir);

        /* (1) Only the impostor is served. */
        ASSERT(sbft_write(sdir, "impostor.zvsb", evil, evil_len));
        ASSERT(rom_seed_register(sdir, "impostor.zvsb", NULL, NULL) ==
               ROM_REG_OK);
        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);
        char peers[64];
        snprintf(peers, sizeof(peers), "127.0.0.1:%u", (unsigned)port);

        struct zcl_command_reply reply;
        sbft_run_leaf(honest_hex, out_path, peers, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "SOURCE_BUNDLE_FETCH_REFUSED") == 0);
        /* The operator is told WHICH refusal fired, not just "it failed". */
        ASSERT(strstr(reply.error.message, "tree-root-mismatch") != NULL);
        zcl_command_reply_free(&reply);
        /* THE property: zero files materialized. */
        ASSERT(access(out_path, F_OK) != 0);
        ASSERT(sbft_dir_empty(odir));

        /* (2) Add the honest bundle; the same call now succeeds and the file
         * on disk is byte-identical to the seeder's. */
        ASSERT(sbft_write(sdir, "tree.zvsb", honest, honest_len));
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, NULL) == ROM_REG_OK);
        sbft_run_leaf(honest_hex, out_path, peers, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&reply);

        int fd = open(out_path, O_RDONLY);
        ASSERT(fd >= 0);
        uint8_t *back = malloc(honest_len);
        ASSERT(back != NULL);
        ASSERT(read(fd, back, honest_len) == (ssize_t)honest_len);
        close(fd);
        ASSERT(memcmp(back, honest, honest_len) == 0);
        struct vcs_source_bundle_metrics vm;
        ASSERT(vcs_source_bundle_verify(back, honest_len, honest_root, &vm) ==
               VCS_SOURCE_BUNDLE_OK);
        free(back);

        /* (3) A malformed peer list is refused before any connection, and a
         * second write to an existing output is refused rather than
         * overwriting it. */
        sbft_run_leaf(honest_hex, out_path, "127.0.0.1", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "BAD_SOURCE_BUNDLE_FETCH_INPUT") == 0);
        zcl_command_reply_free(&reply);
        sbft_run_leaf(honest_hex, out_path, peers, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "SOURCE_BUNDLE_OUTPUT_REFUSED") == 0);
        zcl_command_reply_free(&reply);

        free(honest);
        free(evil);
        fs_server_stop();
        test_cleanup_tmpdir(odir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(edir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (h) A PRE-PLANTED resume state cannot substitute the answer ─────── */

/* ADVERSARIAL. Every case above attacks the WIRE. This one attacks the
 * staging directory, which is the other way bytes can reach the caller: the
 * download layer keeps a durable resume journal, and a set journal bit is
 * defined to mean "this chunk is already on disk AND digest-verified", so a
 * `.part` plus a journal that marks every chunk done is a claim that the
 * download is already finished. The fetch leaf hands the download layer the
 * OUTPUT'S OWN PARENT DIRECTORY as staging
 * (tools/command/native_zcode_source_bundle_command.c, zsb_parent_dir), so
 * anything that can write to the operator's scratch directory can plant that
 * claim — and the staging leaf name is derived from the artifact's chunk_root,
 * which is public in every peer's directory listing.
 *
 * So: plant a WELL-FORMED impostor bundle (one that verifies perfectly under
 * its own root, relabelled to the honest root — the same substitution case (b)
 * builds) under all three staging names, padded to the honest artifact's exact
 * byte length so nothing but a content digest can tell them apart, with a
 * journal that says every chunk is done and verified. Then ask for the honest
 * root.
 *
 * The requirement is not "the plant is detected" but the same one the whole
 * module rests on: the caller gets bytes that rederive to the root it asked
 * for, or it gets nothing. */
static int test_planted_resume_state_refused(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a staging directory pre-planted with a "
         "well-formed impostor and a journal claiming the download is already "
         "complete still yields only bytes that rederive to the asked-for "
         "root") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char eroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_plant_honest");
        char *edir = test_mkdtemp(eroot, sizeof(eroot), "zcl_sbfetch_plant_evil");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_plant_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_plant_cli");
        ASSERT(hdir && edir && sdir && cdir);
        ASSERT(sbft_make_tree(hdir, 'A'));
        ASSERT(sbft_make_tree(edir, 'B'));

        uint8_t honest_root[32], evil_root[32];
        uint8_t *honest = NULL, *evil = NULL;
        size_t honest_len = 0, evil_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));
        ASSERT(sbft_bundle(edir, evil_root, &evil, &evil_len));
        ASSERT(memcmp(honest_root, evil_root, 32) != 0);

        /* Well-formed under its OWN root before it is relabelled — so what
         * follows is about the content check, never about a malformed file. */
        struct vcs_source_bundle_metrics vm;
        ASSERT(vcs_source_bundle_verify(evil, evil_len, evil_root, &vm) ==
               VCS_SOURCE_BUNDLE_OK);
        memcpy(evil + ROM_SEED_SOURCE_BUNDLE_ROOT_OFFSET, honest_root, 32);

        /* The honest seeder, and the artifact identity a planter can read
         * straight out of its public directory listing. */
        ASSERT(sbft_write(sdir, "tree.zvsb", honest, honest_len));
        struct rom_artifact art;
        ASSERT(rom_seed_register(sdir, "tree.zvsb", NULL, &art) == ROM_REG_OK);
        ASSERT(art.num_chunks >= 1);
        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);

        /* The staging leaf the fetcher will use: the FULL 32-byte chunk_root
         * in hex, exactly as engine/services/src/source_bundle_fetch.c derives
         * it (sbf_download_candidate). The width is load-bearing on both
         * sides. If this name stops matching the one the fetcher picks, the
         * plant simply sits in a file the fetcher never looks at, and the test
         * quietly stops testing anything — which is how it last broke: the
         * service moved from an 8-byte stem to the whole root and this side
         * did not follow. The staging-directory-empty assertion below is what
         * catches that, because a plant the fetcher never named is also a
         * plant it never cleans up. */
        char stem[65];
        sbft_hex32(art.chunk_root, stem);
        char name[128], part[1200], jrnl[1300];
        snprintf(name, sizeof(name), "zvsb-stage-%s.stage", stem);
        snprintf(part, sizeof(part), "%s%s", name, ROM_FETCH_PART_SUFFIX);
        snprintf(jrnl, sizeof(jrnl), "%s.journal", part);

        /* Padded to the honest artifact's EXACT length, so size alone can
         * never be what rejects it. */
        uint8_t *plant = calloc(1, honest_len);
        ASSERT(plant != NULL);
        memcpy(plant, evil, evil_len < honest_len ? evil_len : honest_len);
        ASSERT(memcmp(plant, honest, honest_len) != 0);
        ASSERT(sbft_write(cdir, name, plant, honest_len));
        ASSERT(sbft_write(cdir, part, plant, honest_len));

        /* A journal that claims every chunk is durable AND digest-verified —
         * the strongest lie the resume format can tell. */
        char jpath[1400];
        snprintf(jpath, sizeof(jpath), "%s/%s", cdir, jrnl);
        struct rom_journal *j = rom_journal_open(jpath, art.chunk_root,
                                                 art.whole_sha3,
                                                 art.chunk_size,
                                                 art.num_chunks);
        ASSERT(j != NULL);
        for (uint32_t i = 0; i < art.num_chunks; i++)
            ASSERT(rom_journal_mark(j, i));
        ASSERT(rom_journal_count_done(j) == art.num_chunks);
        rom_journal_close(j);

        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);
        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(&peer, 1, honest_root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_OK);

        /* The planted bytes are NOT what came back; the honest ones are, and
         * they re-prove against the caller's own root. */
        ASSERT(got != NULL && got_len == honest_len);
        ASSERT(memcmp(got, plant, honest_len) != 0);
        ASSERT(memcmp(got, honest, honest_len) == 0);
        ASSERT(vcs_source_bundle_verify(got, got_len, honest_root, &vm) ==
               VCS_SOURCE_BUNDLE_OK);
        /* And the plant is gone rather than left to poison the next call. */
        ASSERT(sbft_dir_empty(cdir));

        free(plant);
        free(got);
        free(honest);
        free(evil);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(edir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}


/* ── (i) ONE seeder can consume the whole candidate budget ───────────── */

/* ADVERSARIAL, and this one is about a BOUND rather than about bytes. Every
 * case above proves the content check cannot be talked past. This one asks the
 * next question: what does a hostile seeder get to spend of the SEARCH?
 *
 * The arithmetic. A directory listing carries at most ROM_FETCH_MAX_ARTIFACTS
 * entries, the candidate set holds at most SOURCE_BUNDLE_FETCH_MAX_CANDIDATES,
 * and today those two numbers are equal. The advertised source_root is read
 * out of each file's OWN ZVSB header at registration (rom_seed_register), so a
 * seeder that writes the honest 32 bytes into the header of eight different
 * bundles advertises eight artifacts, with eight DIFFERENT chunk_roots, all
 * claiming the honest tree. sbf_candidate_add groups on the artifact's whole
 * identity — chunk_root, whole_sha3, size, chunk_size and chunk count, all
 * five — so those do not merge; they are eight separate candidates, and this
 * one peer is the only peer, so it fills the set.
 *
 * What this test pins, and why each half matters:
 *
 *   FAIL-CLOSED holds absolutely. Eight impostors buy the attacker nothing:
 *   every one is downloaded, every one is refused by the caller's own root,
 *   the refusal is the CONTENT check's ("tree-root-mismatch", not a transport
 *   error), and the staging directory is empty afterwards. That half must
 *   never change.
 *
 *   A SOLE SEEDER STILL GETS THE WHOLE BUDGET, and that is now correct rather
 *   than a finding. When this case was written, sbf_discover_peer had no
 *   per-peer share at all, so the first peer asked took every slot and a
 *   HONEST peer asked afterwards had its offer dropped by the cap rather than
 *   tried; the comment here said so and asked to be re-stated if fairness
 *   ever landed. Fairness landed: sbf_discover_peer now takes a
 *   candidate_limit and source_bundle_fetch reserves one slot for every peer
 *   not yet asked (limit = MAX_CANDIDATES - peers_after), which
 *   test_one_peer_cannot_fill_candidate_set pins end-to-end with a flooder
 *   ahead of an honest peer. This case is the OTHER side of that rule: with
 *   exactly one peer in the list there is nobody to reserve for, so the
 *   reservation is zero and the sole seeder may legitimately spend all
 *   MAX_CANDIDATES slots — and every one of them must still be downloaded,
 *   refused by the caller's own root, and left unmaterialized. The assertion
 *   below therefore pins the fairness arithmetic at peers_after == 0; a
 *   regression that made the reservation unconditional would starve an honest
 *   single-peer fetch and fail here.
 *
 *   RESIDUAL, stated so it is not mistaken for solved: the reservation
 *   saturates. limit is only reduced while peers_after < MAX_CANDIDATES, so a
 *   caller passing MORE than MAX_CANDIDATES peers gives the FIRST one the
 *   whole set again. That is not a regression — it is the old behaviour
 *   surviving in the tail — but it is the case per-peer fairness does not yet
 *   cover. */
static int test_one_seeder_fills_the_candidate_set(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a single seeder advertising the honest source "
         "root on SOURCE_BUNDLE_FETCH_MAX_CANDIDATES distinct artifacts is "
         "refused on every one of them with nothing materialized — and "
         "consumes the entire candidate budget by itself") {
        sbft_open_caps();
        char hroot[PATH_MAX];
        char sroot[PATH_MAX];
        char croot[PATH_MAX];
        char *hdir = test_mkdtemp(hroot, sizeof(hroot), "zcl_sbfetch_flood_honest");
        char *sdir = test_mkdtemp(sroot, sizeof(sroot), "zcl_sbfetch_flood_srv");
        char *cdir = test_mkdtemp(croot, sizeof(croot), "zcl_sbfetch_flood_cli");
        ASSERT(hdir && sdir && cdir);

        /* The tree the caller actually wants. It is never served by anyone in
         * this fixture: the point is what happens to the SEARCH, not whether
         * an honest copy would have verified. */
        ASSERT(sbft_make_tree(hdir, 'A'));
        uint8_t honest_root[32];
        uint8_t *honest = NULL;
        size_t honest_len = 0;
        ASSERT(sbft_bundle(hdir, honest_root, &honest, &honest_len));

        /* One impostor per candidate slot. Each is a WELL-FORMED bundle of a
         * different tree — proven well-formed under its own root first — then
         * relabelled so its header advertises the honest root. Distinct
         * contents mean distinct chunk_roots, which is what keeps them from
         * merging into a single candidate. */
        /* One listing carries at most ROM_FETCH_MAX_ARTIFACTS entries and the
         * registry holds ROM_SEED_MAX_ARTIFACTS, and both equal the candidate
         * cap today — which is exactly why one seeder is enough. */
        for (unsigned i = 0; i < SOURCE_BUNDLE_FETCH_MAX_CANDIDATES; i++) {
            char iroot[PATH_MAX];
            char *idir = test_mkdtemp(iroot, sizeof(iroot), "zcl_sbfetch_flood_tree");
            ASSERT(idir != NULL);
            ASSERT(sbft_make_tree(idir, (char)('a' + (int)i)));

            uint8_t evil_root[32];
            uint8_t *evil = NULL;
            size_t evil_len = 0;
            ASSERT(sbft_bundle(idir, evil_root, &evil, &evil_len));
            ASSERT(memcmp(evil_root, honest_root, 32) != 0);
            struct vcs_source_bundle_metrics vm;
            ASSERT(vcs_source_bundle_verify(evil, evil_len, evil_root, &vm) ==
                   VCS_SOURCE_BUNDLE_OK);
            memcpy(evil + ROM_SEED_SOURCE_BUNDLE_ROOT_OFFSET, honest_root, 32);

            char name[64];
            snprintf(name, sizeof(name), "impostor-%u.zvsb", i);
            ASSERT(sbft_write(sdir, name, evil, evil_len));
            ASSERT(rom_seed_register(sdir, name, NULL, NULL) == ROM_REG_OK);
            free(evil);
            test_cleanup_tmpdir(idir);
        }
        ASSERT(rom_seed_count() == (int)SOURCE_BUNDLE_FETCH_MAX_CANDIDATES);

        uint16_t port = sbft_serve(sdir);
        ASSERT(port != 0);
        struct rom_fetch_peer peer;
        sbft_peer(&peer, port);

        uint8_t *got = NULL;
        size_t got_len = 0;
        struct source_bundle_fetch_metrics m;
        ASSERT(source_bundle_fetch(&peer, 1, honest_root, cdir, &got, &got_len,
                                   &m) == SOURCE_BUNDLE_FETCH_ERR_ROOT);

        /* Fail-closed, on every one of them. */
        ASSERT(got == NULL && got_len == 0);
        ASSERT(m.candidates_refused == m.candidates_tried);
        ASSERT(m.last_refusal == VCS_SOURCE_BUNDLE_ERR_ROOT);
        ASSERT(sbft_dir_empty(cdir));
        ASSERT(rom_peer_is_deprioritized("127.0.0.1", port));

        /* One seeder, one directory listing, and the whole candidate budget
         * is spent — legitimately, because it is the ONLY peer and the
         * per-peer reservation (MAX_CANDIDATES - peers_after) is zero here.
         * Reserving a slot with nobody to reserve it for would starve an
         * honest single-peer fetch, so this is the arithmetic's lower edge and
         * it must hold. The upper edge — a flooder ahead of an honest peer
         * getting only its share — is test_one_peer_cannot_fill_candidate_set.
         * peers_offering counts a peer only when at least one of its offers
         * was actually taken, which for this seeder is all eight. */
        ASSERT(m.peers_asked == 1 && m.peers_offering == 1);
        ASSERT(m.candidates_tried == SOURCE_BUNDLE_FETCH_MAX_CANDIDATES);

        free(honest);
        fs_server_stop();
        test_cleanup_tmpdir(cdir);
        test_cleanup_tmpdir(sdir);
        test_cleanup_tmpdir(hdir);
        sbft_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Mutation-measured gaps: bounds, grouping, caps, staging, scoring ───
 *
 * Each helper below returns false on the first unmet requirement (printing the
 * line) so the TEST wrapper can always run its teardown. */

#define SBFT_REQ(cond) do { \
    if (!(cond)) { \
        printf("\n    sbft requirement failed at line %d: %s\n", __LINE__, \
               #cond); \
        return false; \
    } \
} while (0)

/* One honest seeder, one bundle, one client staging directory. Zero-initialised
 * so a close after a failed open touches only what was actually created. */
struct sbft_fx {
    char troot[PATH_MAX];
    char sroot[PATH_MAX];
    char croot[PATH_MAX];
    char *tdir;
    char *sdir;
    char *cdir;
    uint8_t root[32];
    uint8_t *wire;
    size_t wire_len;
    struct rom_artifact art;
    uint16_t port;
};

static bool sbft_fx_open(struct sbft_fx *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));
    sbft_open_caps();
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "zcl_sbfx_%s_t", tag);
    fx->tdir = test_mkdtemp(fx->troot, sizeof(fx->troot), prefix);
    snprintf(prefix, sizeof(prefix), "zcl_sbfx_%s_s", tag);
    fx->sdir = test_mkdtemp(fx->sroot, sizeof(fx->sroot), prefix);
    snprintf(prefix, sizeof(prefix), "zcl_sbfx_%s_c", tag);
    fx->cdir = test_mkdtemp(fx->croot, sizeof(fx->croot), prefix);
    if (!fx->tdir || !fx->sdir || !fx->cdir || !sbft_make_tree(fx->tdir, 'A') ||
        !sbft_bundle(fx->tdir, fx->root, &fx->wire, &fx->wire_len) ||
        !sbft_write(fx->sdir, "tree.zvsb", fx->wire, fx->wire_len) ||
        rom_seed_register(fx->sdir, "tree.zvsb", NULL, &fx->art) != ROM_REG_OK)
        return false;
    fx->port = sbft_serve(fx->sdir);
    return fx->port != 0;
}

static void sbft_fx_close(struct sbft_fx *fx)
{
    fs_server_stop();
    free(fx->wire);
    if (fx->cdir) test_cleanup_tmpdir(fx->cdir);
    if (fx->sdir) test_cleanup_tmpdir(fx->sdir);
    if (fx->tdir) test_cleanup_tmpdir(fx->tdir);
    memset(fx, 0, sizeof(*fx));
    sbft_open_caps();
}

/* One advertised artifact, every field a lying directory can vary. pad_to, when
 * non-zero, pads the JSON with blanks to exactly that many bytes. */
struct sbft_offer {
    uint8_t chunk_root[32];
    uint8_t whole[32];
    uint8_t source_root[32];
    uint64_t size;
    uint32_t chunks;
    size_t pad_to;
};

static void sbft_offer_true(const struct sbft_fx *fx, struct sbft_offer *o)
{
    memcpy(o->chunk_root, fx->art.chunk_root, 32);
    memcpy(o->whole, fx->art.whole_sha3, 32);
    memcpy(o->source_root, fx->root, 32);
    o->size = fx->art.size_bytes;
    o->chunks = fx->art.num_chunks;
    o->pad_to = 0;
}

static bool sbft_offer_body(const struct sbft_offer *o, char *body, size_t cap)
{
    int n = snprintf(body, cap, "{\"artifacts\":[");
    if (n <= 0)
        return false;
    size_t off = (size_t)n;
    if (!sbft_append_offer(body, cap, &off, false, o->chunk_root, o->whole,
                           o->source_root, o->size, o->chunks))
        return false;
    while (o->pad_to != 0 && off + 2u < o->pad_to) {
        if (off + 1u >= cap)
            return false;
        body[off++] = ' ';
    }
    return sbft_finish_directory(body, cap, &off) &&
           (o->pad_to == 0 || off == o->pad_to);
}

struct sbft_run {
    enum source_bundle_fetch_result rc;
    struct source_bundle_fetch_metrics m;
    bool same_bytes;
    bool dir_empty;
};

/* Ask [a peer that can only list `o`, the honest seeder]. The first peer can
 * never deliver, so the call succeeds only if the honest peer ends up in a
 * candidate that can reach it. */
static bool sbft_liar_first(const struct sbft_fx *fx, const struct sbft_offer *o,
                            struct sbft_run *out)
{
    memset(out, 0, sizeof(*out));
    char body[9000];
    SBFT_REQ(sbft_offer_body(o, body, sizeof(body)));
    struct sbft_directory_peer liar;
    SBFT_REQ(sbft_directory_start(&liar, body));
    struct rom_fetch_peer peers[2];
    sbft_peer(&peers[0], liar.port);
    sbft_peer(&peers[1], fx->port);
    uint8_t *got = NULL;
    size_t got_len = 0;
    out->rc = source_bundle_fetch(peers, 2, fx->root, fx->cdir, &got, &got_len,
                                  &out->m);
    out->same_bytes = got && got_len == fx->wire_len &&
                      memcmp(got, fx->wire, got_len) == 0;
    free(got);
    sbft_directory_stop(&liar);
    out->dir_empty = sbft_dir_empty(fx->cdir);
    return true;
}

static bool sbft_run_ok(const struct sbft_run *r, uint32_t offering)
{
    return r->rc == SOURCE_BUNDLE_FETCH_OK && r->same_bytes && r->dir_empty &&
           r->m.peers_asked == 2 && r->m.peers_offering == offering &&
           r->m.candidates_tried == 1;
}

static int test_fetch_result_strings(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: every result has its own stable name and an "
         "unknown value is named unknown") {
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_OK), "ok") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_ARGS), "bad-arguments") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_NO_PEER),
                   "no-peer-offers-this-root") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_TRANSPORT),
                   "no-candidate-delivered") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_ROOT), "tree-root-mismatch") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_STAGING),
                   "staging-unreadable") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_ALLOC), "allocation") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   SOURCE_BUNDLE_FETCH_ERR_BUDGET),
                   "time-budget-spent") == 0);
        ASSERT(strcmp(source_bundle_fetch_result_string(
                   (enum source_bundle_fetch_result)99), "unknown") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Peers that are never dialled (port 0), so only the argument contract and the
 * skip rules are exercised. */
static bool sbft_args_staging_length(void)
{
    struct rom_fetch_peer dead[SOURCE_BUNDLE_FETCH_MAX_PEERS];
    for (size_t i = 0; i < SOURCE_BUNDLE_FETCH_MAX_PEERS; i++)
        sbft_peer(&dead[i], 0);
    uint8_t root[32];
    memset(root, 0x5C, sizeof(root));
    char dir[1100];
    uint8_t *got = NULL;
    size_t got_len = 0;
    struct source_bundle_fetch_metrics m;

    /* The staging directory must be strictly shorter than 1024 bytes. */
    memset(dir, 'd', sizeof(dir));
    dir[1023] = '\0';
    SBFT_REQ(source_bundle_fetch(dead, 1, root, dir, &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    dir[1023] = 'd';
    dir[1024] = '\0';
    SBFT_REQ(source_bundle_fetch(dead, 1, root, dir, &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    dir[1024] = 'd';
    dir[1025] = '\0';
    SBFT_REQ(source_bundle_fetch(dead, 1, root, dir, &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);

    /* A one-character directory is a directory; an empty one is not. */
    SBFT_REQ(source_bundle_fetch(dead, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(source_bundle_fetch(dead, 1, root, "", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);

    /* The peer cap is inclusive. */
    SBFT_REQ(source_bundle_fetch(dead, SOURCE_BUNDLE_FETCH_MAX_PEERS, root, "x",
                                 &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(m.peers_asked == 0 && m.peers_offering == 0);
    return true;
}

static bool sbft_args_null_and_zeroed(void)
{
    struct rom_fetch_peer peer;
    sbft_peer(&peer, 1);
    uint8_t root[32] = {0};
    uint8_t sentinel = 0;
    uint8_t *got = &sentinel;
    size_t got_len = 77;
    struct source_bundle_fetch_metrics m;
    memset(&m, 0xAA, sizeof(m));

    /* A refused call still leaves every output defined. */
    SBFT_REQ(source_bundle_fetch(&peer, 1, root, "", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    SBFT_REQ(got == NULL && got_len == 0);
    SBFT_REQ(m.peers_asked == 0 && m.peers_offering == 0 &&
             m.candidates_tried == 0 && m.wire_bytes == 0);
    SBFT_REQ(source_bundle_fetch(NULL, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    SBFT_REQ(source_bundle_fetch(&peer, 1, NULL, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    SBFT_REQ(source_bundle_fetch(&peer, 1, root, "x", NULL, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    SBFT_REQ(source_bundle_fetch(&peer, 1, root, "x", &got, NULL, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_ARGS);
    return true;
}

/* Which peers count as "asked": an unusable entry (no address, or port 0) is
 * skipped without being counted; a usable one is counted even when it fails. */
static bool sbft_args_peer_skipping(void)
{
    uint8_t root[32];
    memset(root, 0x5C, sizeof(root));
    uint8_t *got = NULL;
    size_t got_len = 0;
    struct source_bundle_fetch_metrics m;
    struct rom_fetch_peer p;

    sbft_peer(&p, 1234);
    p.addr[0] = '\0';
    SBFT_REQ(source_bundle_fetch(&p, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(m.peers_asked == 0);
    sbft_peer(&p, 0);
    SBFT_REQ(source_bundle_fetch(&p, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(m.peers_asked == 0);
    sbft_peer(&p, 1);
    SBFT_REQ(source_bundle_fetch(&p, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(m.peers_asked == 1 && m.peers_offering == 0);
    snprintf(p.addr, sizeof(p.addr), "%s", "0");
    SBFT_REQ(source_bundle_fetch(&p, 1, root, "x", &got, &got_len, &m) ==
             SOURCE_BUNDLE_FETCH_ERR_NO_PEER);
    SBFT_REQ(m.peers_asked == 1);
    return true;
}

static int test_fetch_argument_bounds(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: the staging-length, peer-cap, one-character and "
         "unusable-peer boundaries of the argument contract") {
        sbft_open_caps();
        ASSERT(sbft_args_staging_length());
        ASSERT(sbft_args_null_and_zeroed());
        ASSERT(sbft_args_peer_skipping());
        PASS();
    } _test_next:;
    return failures;
}

/* The three names the fetcher stages under are derived from the advertised
 * chunk_root, so a planter can name them. A candidate whose peers cannot even
 * serve a plan must still leave the directory as it found it. */
static bool sbft_plan_failure_clears_staging(const struct sbft_fx *fx)
{
    char stem[65], name[128];
    sbft_hex32(fx->art.chunk_root, stem);
    snprintf(name, sizeof(name), "zvsb-stage-%s.stage", stem);
    char part[160], jrnl[200];
    snprintf(part, sizeof(part), "%s%s", name, ROM_FETCH_PART_SUFFIX);
    snprintf(jrnl, sizeof(jrnl), "%s.journal", part);
    SBFT_REQ(sbft_write(fx->cdir, name, "planted", 7));
    SBFT_REQ(sbft_write(fx->cdir, part, "planted", 7));
    SBFT_REQ(sbft_write(fx->cdir, jrnl, "planted", 7));

    struct sbft_offer o;
    sbft_offer_true(fx, &o);
    char body[9000];
    SBFT_REQ(sbft_offer_body(&o, body, sizeof(body)));
    struct sbft_directory_peer liar;
    SBFT_REQ(sbft_directory_start(&liar, body));
    struct rom_fetch_peer peer;
    sbft_peer(&peer, liar.port);
    uint8_t *got = NULL;
    size_t got_len = 0;
    struct source_bundle_fetch_metrics m;
    enum source_bundle_fetch_result rc =
        source_bundle_fetch(&peer, 1, fx->root, fx->cdir, &got, &got_len, &m);
    sbft_directory_stop(&liar);
    SBFT_REQ(rc == SOURCE_BUNDLE_FETCH_ERR_TRANSPORT);
    SBFT_REQ(got == NULL && got_len == 0);
    SBFT_REQ(m.peers_offering == 1 && m.candidates_tried == 0);
    SBFT_REQ(sbft_dir_empty(fx->cdir));
    return true;
}

static int test_fetch_plan_failure_clears_staging(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a candidate nobody can serve a plan for still "
         "clears the staged file, .part and journal planted under its name") {
        struct sbft_fx fx;
        bool ok = sbft_fx_open(&fx, "plan");
        ok = ok && sbft_plan_failure_clears_staging(&fx);
        sbft_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* A liar ahead of the honest peer whose advert differs from the real artifact
 * in exactly one field must stay a SEPARATE candidate: merged, the honest peer
 * would be asked for the liar's chunk_root / size and the call would fail. The
 * differing bytes sit at index 31 and in size, which a shortened comparison
 * cannot see. */
static bool sbft_divergent_adverts(const struct sbft_fx *fx)
{
    for (int variant = 0; variant < 3; variant++) {
        struct sbft_offer o;
        sbft_offer_true(fx, &o);
        if (variant == 0)
            o.chunk_root[31] ^= 0x01u;
        else if (variant == 1)
            o.whole[31] ^= 0x01u;
        else
            o.size += 1u;
        struct sbft_run r;
        SBFT_REQ(sbft_liar_first(fx, &o, &r));
        SBFT_REQ(sbft_run_ok(&r, 2));
    }
    return true;
}

/* Honest replicas of one artifact are failover for each other even when they
 * share an address and differ only in port, and one peer listed twice is
 * still counted as offering both times. */
static bool sbft_replicas_and_repeats(const struct sbft_fx *fx)
{
    struct sbft_offer o;
    sbft_offer_true(fx, &o);
    struct sbft_run r;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 2));

    struct rom_fetch_peer twice[2];
    sbft_peer(&twice[0], fx->port);
    sbft_peer(&twice[1], fx->port);
    uint8_t *got = NULL;
    size_t got_len = 0;
    struct source_bundle_fetch_metrics m;
    SBFT_REQ(source_bundle_fetch(twice, 2, fx->root, fx->cdir, &got, &got_len,
                                 &m) == SOURCE_BUNDLE_FETCH_OK);
    SBFT_REQ(got && got_len == fx->wire_len &&
             memcmp(got, fx->wire, got_len) == 0);
    free(got);
    SBFT_REQ(m.peers_asked == 2 && m.peers_offering == 2 &&
             m.candidates_tried == 1);
    return sbft_dir_empty(fx->cdir);
}

static int test_fetch_candidate_grouping(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: an advert differing in one late byte or in size "
         "is its own candidate, and same-address replicas stay failover") {
        struct sbft_fx fx;
        bool ok = sbft_fx_open(&fx, "group");
        ok = ok && sbft_divergent_adverts(&fx);
        ok = ok && sbft_replicas_and_repeats(&fx);
        sbft_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* What an offer must satisfy to be worth a connection: the wire cap and chunk
 * cap are inclusive (a 64 MiB, 8 chunk offer counts, 64 MiB + 1 does not), and
 * every one of the 32 source_root bytes must match. */
static bool sbft_offer_filters(const struct sbft_fx *fx)
{
    const uint64_t cap = VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES;
    struct sbft_offer o;
    struct sbft_run r;

    sbft_offer_true(fx, &o);
    o.chunk_root[0] ^= 0x40u;
    o.size = cap;
    o.chunks = SOURCE_BUNDLE_FETCH_MAX_CHUNKS;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 2));

    o.size = cap + 1u;
    o.chunks = SOURCE_BUNDLE_FETCH_MAX_CHUNKS + 1u;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 1));

    sbft_offer_true(fx, &o);
    o.source_root[31] ^= 0x01u;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 1));
    return true;
}

/* The directory reply is read into an 8192-byte buffer and refused at or over
 * that size: 8191 bytes is a listing, 8192 is not. */
static bool sbft_directory_cap_edge(const struct sbft_fx *fx)
{
    struct sbft_offer o;
    struct sbft_run r;
    sbft_offer_true(fx, &o);
    o.pad_to = 8191u;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 2));
    o.pad_to = 8192u;
    SBFT_REQ(sbft_liar_first(fx, &o, &r));
    SBFT_REQ(sbft_run_ok(&r, 1));
    return true;
}

static int test_fetch_offer_filters_and_directory_cap(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: wire-cap, chunk-cap, source-root and "
         "directory-size boundaries decide whether a peer counts as offering") {
        struct sbft_fx fx;
        bool ok = sbft_fx_open(&fx, "filter");
        ok = ok && sbft_offer_filters(&fx);
        ok = ok && sbft_directory_cap_edge(&fx);
        sbft_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* Serve ONLY a well-formed impostor under the honest root. */
static bool sbft_serve_impostor(struct sbft_fx *fx)
{
    SBFT_REQ(sbft_make_tree(fx->tdir, 'B'));
    uint8_t evil_root[32], *evil = NULL;
    size_t evil_len = 0;
    SBFT_REQ(sbft_bundle(fx->tdir, evil_root, &evil, &evil_len));
    memcpy(evil + ROM_SEED_SOURCE_BUNDLE_ROOT_OFFSET, fx->root, 32);
    bool wrote = sbft_write(fx->sdir, "impostor.zvsb", evil, evil_len);
    free(evil);
    SBFT_REQ(wrote);
    sbft_open_caps();
    SBFT_REQ(rom_seed_register(fx->sdir, "impostor.zvsb", NULL, NULL) ==
             ROM_REG_OK);
    return true;
}

/* A refused substitution is recorded against the peers that stood behind it
 * and against nothing else (no phantom entry for an empty address). */
static bool sbft_substitution_scoring(struct sbft_fx *fx)
{
    SBFT_REQ(sbft_serve_impostor(fx));
    struct rom_fetch_peer peer;
    sbft_peer(&peer, fx->port);
    uint8_t *got = NULL;
    size_t got_len = 0;
    struct source_bundle_fetch_metrics m;
    SBFT_REQ(!rom_peer_is_deprioritized("127.0.0.1", fx->port));
    SBFT_REQ(source_bundle_fetch(&peer, 1, fx->root, fx->cdir, &got, &got_len,
                                 &m) == SOURCE_BUNDLE_FETCH_ERR_ROOT);
    SBFT_REQ(got == NULL && got_len == 0);
    SBFT_REQ(m.candidates_tried == 1 && m.candidates_refused == 1);
    SBFT_REQ(m.last_refusal != VCS_SOURCE_BUNDLE_OK);
    SBFT_REQ(rom_peer_is_deprioritized("127.0.0.1", fx->port));
    SBFT_REQ(!rom_peer_is_deprioritized("", 0));
    return sbft_dir_empty(fx->cdir);
}

static int test_fetch_substitution_scores_only_its_peers(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: a refused substitution deprioritizes exactly "
         "the peer that served it") {
        struct sbft_fx fx;
        bool ok = sbft_fx_open(&fx, "score");
        ok = ok && sbft_substitution_scoring(&fx);
        sbft_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_bundle_fetch_platform_arm(void)
{
    int failures = 0;
    failures += test_fetch_result_strings();
    failures += test_fetch_argument_bounds();
    failures += test_fetch_plan_failure_clears_staging();
    failures += test_fetch_candidate_grouping();
    failures += test_fetch_offer_filters_and_directory_cap();
    failures += test_fetch_substitution_scores_only_its_peers();
    failures += test_header_shape_pinned();
    failures += test_fetch_by_root();
    failures += test_substitution_refused();
    failures += test_substitution_then_recovery();
    failures += test_damaged_payload_refused();
    failures += test_stalled_peer_failover();
    failures += test_no_peer_named_refusal();
    failures += test_same_chunk_root_divergent_manifest();
    failures += test_one_peer_cannot_fill_candidate_set();
    failures += test_leaf_end_to_end();
    failures += test_planted_resume_state_refused();
    failures += test_one_seeder_fills_the_candidate_set();
    return failures;
}
#else /* _WIN32 */

/* The production WinSock dialer, handshake, and frame/chunk transport are
 * native. This fixture's adversarial peer harness still uses POSIX listener
 * and fault-injection primitives, so it cannot yet provide Windows evidence. */
static int test_source_bundle_fetch_platform_arm(void)
{
    printf("source_bundle_fetch: SKIP (Windows): adversarial peer fixture "
           "still requires POSIX listener primitives\n");
    return 0;
}
#endif

int test_source_bundle_fetch(void)
{
    return test_source_bundle_fetch_platform_arm();
}
