/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity-free P2P source retrieval: zcode.workspace.source.bundle.fetch and
 * the service under it (app/services/src/source_bundle_fetch.c).
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
 * copy of this suite, or with anything else on the box. */
static uint16_t sbft_serve(const char *datadir)
{
    fs_server_start(datadir, 0);
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
    char body[8192];
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

/* lib/net may not include lib/vcs, so rom_seed restates the ZVSB header shape.
 * This is the gate that keeps the restatement honest: a drift would silently
 * stop every source bundle being findable, which presents as "the swarm has
 * nothing" rather than as an error. */
static int test_header_shape_pinned(void)
{
    int failures = 0;
    TEST("source_bundle_fetch: rom_seed's restated ZVSB header shape matches "
         "lib/vcs, and reads the same root vcs committed") {
        ASSERT(ROM_SEED_SOURCE_BUNDLE_HEADER_BYTES ==
               VCS_SOURCE_BUNDLE_HEADER_BYTES);
        ASSERT(ROM_SEED_SOURCE_BUNDLE_MIN_BYTES ==
               VCS_SOURCE_BUNDLE_HEADER_BYTES + 1u);

        char troot[] = "/tmp/zcl_sbfetch_hdr_XXXXXX";
        char *tdir = mkdtemp(troot);
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
        char troot[] = "/tmp/zcl_sbfetch_ok_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_ok_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_ok_cli_XXXXXX";
        char *tdir = mkdtemp(troot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_sub_honest_XXXXXX";
        char eroot[] = "/tmp/zcl_sbfetch_sub_evil_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_sub_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_sub_cli_XXXXXX";
        char *hdir = mkdtemp(hroot), *edir = mkdtemp(eroot),
             *sdir = mkdtemp(sroot), *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_rec_honest_XXXXXX";
        char eroot[] = "/tmp/zcl_sbfetch_rec_evil_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_rec_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_rec_cli_XXXXXX";
        char *hdir = mkdtemp(hroot), *edir = mkdtemp(eroot),
             *sdir = mkdtemp(sroot), *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_dmg_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_dmg_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_dmg_cli_XXXXXX";
        char *hdir = mkdtemp(hroot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_stall_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_stall_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_stall_cli_XXXXXX";
        char *hdir = mkdtemp(hroot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_none_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_none_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_none_cli_XXXXXX";
        char *hdir = mkdtemp(hroot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char troot[] = "/tmp/zcl_sbfetch_tuple_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_tuple_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_tuple_cli_XXXXXX";
        char *tdir = mkdtemp(troot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char troot[] = "/tmp/zcl_sbfetch_slots_tree_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_slots_srv_XXXXXX";
        char croot[] = "/tmp/zcl_sbfetch_slots_cli_XXXXXX";
        char *tdir = mkdtemp(troot), *sdir = mkdtemp(sroot),
             *cdir = mkdtemp(croot);
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
        char hroot[] = "/tmp/zcl_sbfetch_leaf_honest_XXXXXX";
        char eroot[] = "/tmp/zcl_sbfetch_leaf_evil_XXXXXX";
        char sroot[] = "/tmp/zcl_sbfetch_leaf_srv_XXXXXX";
        char oroot[] = "/tmp/zcl_sbfetch_leaf_out_XXXXXX";
        char *hdir = mkdtemp(hroot), *edir = mkdtemp(eroot),
             *sdir = mkdtemp(sroot), *odir = mkdtemp(oroot);
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

int test_source_bundle_fetch(void)
{
    int failures = 0;
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
    return failures;
}
#else /* _WIN32 */

/* Source-bundle fetch runs over the file-service transport, which is a
 * fail-closed refusal stub on native Windows (lib/net/src/file_service.c:26,
 * lib/net/src/rom_fetch.c:504): no case below can complete a real fetch on
 * this lane. */
int test_source_bundle_fetch(void)
{
    printf("source_bundle_fetch: SKIP (Windows): file-service transport is "
           "a refusal stub on native Windows (file_service.c:26)\n");
    return 0;
}
#endif
