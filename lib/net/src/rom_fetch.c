/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact fetching — the CLIENT half of docs/ROM_DELIVERY.md. See
 * net/rom_fetch.h for the contract, the trust model, and the wire protocol.
 * Wire/disk input is bounded and verified against caller-committed digests;
 * install/activation remains with the unified installer. */

#include "net/rom_fetch.h"
#include "net/file_service.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#define RF_SUBSYS "rom_fetch"

static void rf_session_close(struct fs_session *session, int fd)
{
    fs_session_cleanup(session);
    close(fd);
}
/* Connect timeout for one chunk-fetch connection (seconds). */
#define RF_CONNECT_TIMEOUT_SEC 10
/* Per-socket timeout: bound a stalled LAN/fast-WAN peer. */
#define RF_IO_TIMEOUT_SEC 120

/* Bounded per-chunk retry against the seeder's wall-clock-1s rate window
 * (rom_seed_rate_charge): 1100 ms always crosses a second boundary, and
 * 25 retries bound a persistently-refusing peer to ~28 s per chunk before
 * the download fails closed. Sized so a stock 8 MB/s seeder costs at most
 * one retry per chunk pair. */
#define ROM_FETCH_CHUNK_RETRIES  25u
#define ROM_FETCH_CHUNK_RETRY_MS 1100u

/* ── Small helpers ──────────────────────────────────────────────────── */

/* A fetchable filename is a bare basename: no separators, no traversal,
 * non-empty, and short enough to store. Mirrors the serve side's rule. */
static bool rf_filename_ok(const char *filename)
{
    if (!filename || !filename[0])
        return false;
    size_t n = strlen(filename);
    if (n >= ROM_FETCH_NAME_MAX)
        return false;
    if (strchr(filename, '/'))
        return false;
    if (strstr(filename, ".."))
        return false;
    return true;
}

/* Read exactly n bytes into buf. Returns false on EOF/error/timeout. */
static bool rf_recv_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (r == 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

/* ── Manifest validation + discovery parse ──────────────────────────── */

bool rom_fetch_manifest_sane(const struct rom_fetch_manifest *m)
{
    if (!m)
        return false;
    if (m->size_bytes < ROM_SEED_MIN_ARTIFACT_BYTES ||
        m->size_bytes > ROM_SEED_MAX_ARTIFACT_BYTES)
        return false;
    /* The serve side chunks at exactly ROM_SEED_CHUNK_SIZE; a peer claiming
     * any other layout is not speaking this protocol. */
    if (m->chunk_size != ROM_SEED_CHUNK_SIZE)
        return false;
    uint32_t expect_chunks =
        (uint32_t)((m->size_bytes + m->chunk_size - 1) / m->chunk_size);
    if (m->num_chunks == 0 || m->num_chunks > ROM_SEED_MAX_CHUNKS ||
        m->num_chunks != expect_chunks)
        return false;
    /* An empty filename is allowed at discovery time (the /directory.json
     * artifact entries carry no name); a NON-empty one must be a safe
     * basename before it is ever used as a sink path. */
    if (m->filename[0] && !rf_filename_ok(m->filename))
        return false;
    return true;
}

/* Parse one hex digest field: exactly 64 hex chars → 32 bytes. */
static bool rf_parse_digest(const struct json_value *obj, const char *key,
                            uint8_t out[32])
{
    const char *hex = json_get_str(json_get(obj, key));
    if (!hex || strlen(hex) != 64)
        return false;
    return ParseHex(hex, out, 32) == 32;
}

int rom_fetch_parse_directory(const char *json_body,
                              struct rom_fetch_manifest *out, size_t max)
{
    if (!json_body || !out || max == 0)
        return -1;
    if (max > ROM_FETCH_MAX_ARTIFACTS)
        max = ROM_FETCH_MAX_ARTIFACTS;

    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, json_body, strlen(json_body)) ||
        doc.type != JSON_OBJ) {
        json_free(&doc);
        return -1;
    }

    const struct json_value *arts = json_get(&doc, "artifacts");
    if (!arts || arts->type != JSON_ARR) {
        json_free(&doc);
        return 0; /* no artifacts advertised — not an error */
    }

    int n = 0;
    for (size_t i = 0; i < arts->num_children && (size_t)n < max; i++) {
        const struct json_value *e = json_at(arts, i);
        if (!e || e->type != JSON_OBJ)
            continue;

        struct rom_fetch_manifest m;
        memset(&m, 0, sizeof(m));
        /* directory.json entries carry digests + layout, no filename. */
        if (!rf_parse_digest(e, "digest", m.chunk_root) ||
            !rf_parse_digest(e, "whole_sha3", m.whole_sha3))
            continue;
        int64_t size = json_get_int(json_get(e, "size"));
        int64_t csize = json_get_int(json_get(e, "chunk_size"));
        int64_t chunks = json_get_int(json_get(e, "chunks"));
        if (size <= 0 || csize <= 0 || chunks <= 0)
            continue;
        m.size_bytes = (uint64_t)size;
        m.chunk_size = (uint32_t)csize;
        m.num_chunks = (uint32_t)chunks;
        /* Optional "kind" token (untrusted, cosmetic — the digests are the
         * trust anchor). Absent/unrecognized → ROM_ARTIFACT_UNKNOWN, the legacy
         * back-compat shape the size-based picker still handles. */
        m.kind = rom_seed_kind_from_name(json_get_str(json_get(e, "kind")));
        /* Optional "height" (untrusted, download-cosmetic — NOT part of the
         * manifest_sane trust check; see rom_fetch_manifest.height). Absent /
         * negative -> 0, the legacy no-height default the size-based picker
         * still handles. */
        int64_t height = json_get_int(json_get(e, "height"));
        m.height = height > 0 ? height : 0;
        if (!rom_fetch_manifest_sane(&m))
            continue;
        m.used = true;
        out[n++] = m;
    }

    json_free(&doc);
    return n;
}

/* ── Verified chunk fetch ───────────────────────────────────────────── */

/* Connect to peer_addr:port with a bounded connect timeout. Returns the fd
 * or -1 (logged). */
static int rf_connect(const char *peer_addr, uint16_t port)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(peer_addr, port_str, &hints, &res) != 0 || !res)
        LOG_ERR(RF_SUBSYS, "chunk: resolve failed for %s", peer_addr);

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        LOG_ERR(RF_SUBSYS, "chunk: socket() failed: %s", strerror(errno));
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    if (rc < 0 && errno == EINPROGRESS) {
        struct timeval tv = { .tv_sec = RF_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        int err = 0;
        socklen_t elen = sizeof(err);
        if (rc > 0)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (rc <= 0 || err != 0) {
            close(fd);
            freeaddrinfo(res);
            LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed/timed out",
                    peer_addr, (unsigned)port);
        }
    } else if (rc < 0) {
        close(fd);
        freeaddrinfo(res);
        LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed: %s",
                peer_addr, (unsigned)port, strerror(errno));
    }
    freeaddrinfo(res);
    fcntl(fd, F_SETFL, flags); /* restore blocking mode */

    struct timeval tv = { .tv_sec = RF_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Must byte-match FS_ROM_REFUSAL_MAC_TAG in file_service.c: the typed ROM
 * chunk refusal frame rides fs_send_chunk_refusal's MAC scheme with this
 * constant in the tag slot. "RREF" + zero padding. */
static const uint8_t RF_ROM_REFUSAL_MAC_TAG[32] = { 'R', 'R', 'E', 'F' };

/* Pure decode of the 4-byte chunk-reply size field: true iff it is the ROM
 * refusal sentinel (server declined this chunk). A real chunk size never
 * reaches the sentinel (it is bounded by ROM_SEED_CHUNK_SIZE), so this cleanly
 * separates a refusal from a data reply — and a corrupt/garbage size is NOT
 * mistaken for a refusal (only the exact sentinel is). */
bool rom_fetch_wire_is_refusal(const uint8_t hdr4[4])
{
    if (!hdr4)
        return false;
    uint32_t size = (uint32_t)hdr4[0] | ((uint32_t)hdr4[1] << 8) |
                    ((uint32_t)hdr4[2] << 16) | ((uint32_t)hdr4[3] << 24);
    return size == FS_ROM_REFUSAL_SENTINEL;
}

/* Human label for a refusal reason code (bounded; unknown codes fold to a
 * stable string). Used for clean "peer busy" logging and in tests. */
const char *rom_fetch_refusal_reason_name(uint8_t reason)
{
    switch (reason) {
    case FS_ROM_REFUSE_UNKNOWN:     return "unknown-artifact";
    case FS_ROM_REFUSE_CONN_BUDGET: return "conn-budget";
    case FS_ROM_REFUSE_INFLIGHT:    return "inflight-cap";
    case FS_ROM_REFUSE_RATE:        return "rate-window";
    case FS_ROM_REFUSE_IO:          return "server-io";
    default:                        return "declined";
    }
}

bool rom_fetch_chunk(const char *peer_addr, uint16_t port,
                     const uint8_t chunk_root[32], uint32_t idx,
                     uint8_t *buf, uint32_t buf_cap, uint32_t *out_sz)
{
    if (!peer_addr || !chunk_root || !buf || !out_sz)
        LOG_FAIL(RF_SUBSYS, "chunk: null arg");
    if (buf_cap < ROM_SEED_CHUNK_SIZE)
        LOG_FAIL(RF_SUBSYS, "chunk: buf_cap %u < ROM chunk size %u",
                 buf_cap, (unsigned)ROM_SEED_CHUNK_SIZE);

    int fd = rf_connect(peer_addr, port);
    if (fd < 0)
        return false;

    struct fs_session s;
    fs_session_init(&s, fd);
    /* The ROM serve path keys its sessions on an all-zero utxo_root (see
     * fs_handle_client_fd, file_service.c) — match it exactly. */
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&s, zero_root, true)) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: handshake failed with %s:%u",
                 peer_addr, (unsigned)port);
    }

    /* Request: ["ROM"(3)][chunk_root(32)][chunk_index(4 LE)]. */
    uint8_t req[FS_ROM_REQUEST_SIZE];
    memcpy(req, "ROM", 3);
    memcpy(req + 3, chunk_root, 32);
    req[35] = (uint8_t)(idx);
    req[36] = (uint8_t)(idx >> 8);
    req[37] = (uint8_t)(idx >> 16);
    req[38] = (uint8_t)(idx >> 24);
    if (!fs_send_frame(&s, FS_REQUEST, req, sizeof(req))) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: request send failed to %s:%u",
                 peer_addr, (unsigned)port);
    }

    /* Reply is raw size/data/MAC or a typed refusal sentinel. */
    uint8_t hdr[4];
    if (!rf_recv_exact(fd, hdr, 4)) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: size header read failed (peer %s:%u "
                 "refused or went away)", peer_addr, (unsigned)port);
    }
    if (rom_fetch_wire_is_refusal(hdr)) {
        /* Fixed-size authenticated refusal; never a peer-sized read. */
        uint8_t reason = 0;
        uint8_t rmac_wire[32];
        if (!rf_recv_exact(fd, &reason, 1) || !rf_recv_exact(fd, rmac_wire, 32)) {
            rf_session_close(&s, fd);
            LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u refused (truncated "
                     "refusal frame) — backing off", idx, peer_addr,
                     (unsigned)port);
            return false;
        }
        close(fd);
        uint8_t rmac_expect[32];
        struct sha3_256_ctx rmc;
        sha3_256_init(&rmc);
        sha3_256_write(&rmc, s.key, 32);
        sha3_256_write(&rmc, (const unsigned char *)&s.recv_counter, 8);
        sha3_256_write(&rmc, RF_ROM_REFUSAL_MAC_TAG, 32);
        sha3_256_write(&rmc, &reason, 1);
        sha3_256_finalize(&rmc, rmac_expect);
        memory_cleanse(&rmc, sizeof(rmc));
        fs_session_cleanup(&s);
        uint8_t rdiff = 0;
        for (int i = 0; i < 32; i++) rdiff |= rmac_wire[i] ^ rmac_expect[i];
        if (rdiff != 0) {
            LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u sent an unauthenticated "
                     "refusal (MAC mismatch) — backing off", idx, peer_addr,
                     (unsigned)port);
            return false;
        }
        LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u busy (%s) — backing off + "
                 "retry", idx, peer_addr, (unsigned)port,
                 rom_fetch_refusal_reason_name(reason));
        return false;
    }
    uint32_t size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                    ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (size == 0 || size > ROM_SEED_CHUNK_SIZE) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: implausible chunk size %u from %s:%u "
                 "(refusal or corrupt stream)", size, peer_addr,
                 (unsigned)port);
    }
    if (!rf_recv_exact(fd, buf, size)) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: data read failed (%u bytes) from %s:%u",
                 size, peer_addr, (unsigned)port);
    }
    uint8_t mac_wire[32];
    if (!rf_recv_exact(fd, mac_wire, 32)) {
        rf_session_close(&s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: MAC read failed from %s:%u",
                 peer_addr, (unsigned)port);
    }
    close(fd);

    /* The chunk's content digest is learned from the received bytes: the
     * serve side binds the true per-chunk SHA3 into the MAC, so a tampered
     * payload fails the MAC; content-vs-manifest verification is the
     * whole-file pass (rom_fetch_verify_file). */
    uint8_t data_sha3[32];
    sha3_256(buf, size, data_sha3);

    uint8_t mac_expect[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s.key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s.recv_counter, 8);
    sha3_256_write(&mctx, data_sha3, 32);
    sha3_256_write(&mctx, buf, size);
    sha3_256_finalize(&mctx, mac_expect);
    memory_cleanse(&mctx, sizeof(mctx));
    fs_session_cleanup(&s);

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= mac_wire[i] ^ mac_expect[i];
    if (diff != 0) {
        /* Scoring, not a content verdict: chunk-level whole-file content
         * proof is a separate later step. This only stops us from wasting
         * more retries on a peer whose transport MAC keeps failing. */
        (void)rom_peer_note_bad_chunk(peer_addr, port, idx, "mac");
        LOG_FAIL(RF_SUBSYS, "chunk: transport MAC mismatch on chunk %u "
                 "from %s:%u", idx, peer_addr, (unsigned)port);
    }

    *out_sz = size;
    return true;
}

/* ── Whole-file verification + download driver ──────────────────────── */

bool rom_fetch_verify_file(const char *path,
                           const struct rom_fetch_manifest *m)
{
    if (!path || !m)
        LOG_FAIL(RF_SUBSYS, "verify: null arg");
    if (!rom_fetch_manifest_sane(m))
        LOG_FAIL(RF_SUBSYS, "verify: manifest fails sanity checks");

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        LOG_FAIL(RF_SUBSYS, "verify: open '%s' failed errno=%d", path, errno);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        LOG_FAIL(RF_SUBSYS, "verify: fstat '%s' failed / not a file", path);
    }
    if ((uint64_t)st.st_size != m->size_bytes) {
        close(fd);
        LOG_FAIL(RF_SUBSYS, "verify: '%s' size %llu != committed %llu",
                 path, (unsigned long long)st.st_size,
                 (unsigned long long)m->size_bytes);
    }

    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_fetch_verify_buf");
    if (!buf) {
        close(fd);
        LOG_FAIL(RF_SUBSYS, "verify: alloc chunk buffer failed");
    }

    struct sha3_256_ctx whole_ctx;
    sha3_256_init(&whole_ctx);
    struct sha3_256_ctx root_ctx;
    sha3_256_init(&root_ctx);

    bool ok = true;
    uint64_t total = 0;
    for (uint32_t ci = 0; ci < m->num_chunks && ok; ci++) {
        uint32_t want = m->chunk_size;
        uint64_t remaining = m->size_bytes - total;
        if (remaining < want)
            want = (uint32_t)remaining;
        uint32_t got = 0;
        while (got < want) {
            ssize_t r = pread(fd, buf + got, want - got,
                              (off_t)(total + got));
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ok = false;
                break;
            }
            if (r == 0) { /* short file vs committed size */
                ok = false;
                break;
            }
            got += (uint32_t)r;
        }
        if (!ok)
            break;
        uint8_t chunk_h[32];
        sha3_256(buf, got, chunk_h);
        sha3_256_write(&root_ctx, chunk_h, 32);
        sha3_256_write(&whole_ctx, buf, got);
        total += got;
    }

    free(buf);
    close(fd);

    if (!ok || total != m->size_bytes)
        LOG_FAIL(RF_SUBSYS, "verify: read pass failed on '%s'", path);

    uint8_t whole[32], root[32];
    sha3_256_finalize(&whole_ctx, whole);
    sha3_256_finalize(&root_ctx, root);

    if (memcmp(root, m->chunk_root, 32) != 0)
        LOG_FAIL(RF_SUBSYS, "verify: '%s' chunk-root mismatch (content is "
                 "not the committed artifact)", path);
    if (memcmp(whole, m->whole_sha3, 32) != 0)
        LOG_FAIL(RF_SUBSYS, "verify: '%s' whole-file digest mismatch "
                 "(content is not the committed artifact)", path);
    return true;
}

/* ── Fetch status (observability) ───────────────────────────────────── */

static struct rom_fetch_status g_status;
static pthread_mutex_t g_status_mutex = PTHREAD_MUTEX_INITIALIZER;

static void rf_note_begin(const char *peer_addr, uint16_t port,
                          const struct rom_fetch_manifest *m)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.ever_attempted = true;
    g_status.in_progress = true;
    g_status.last_ok = false;
    snprintf(g_status.peer, sizeof(g_status.peer), "%s:%u",
             peer_addr, (unsigned)port);
    snprintf(g_status.filename, sizeof(g_status.filename), "%s", m->filename);
    g_status.detail[0] = '\0';
    g_status.size_bytes = m->size_bytes;
    g_status.num_chunks = m->num_chunks;
    g_status.chunks_done = 0;
    g_status.bytes_done = 0;
    g_status.started_unix = (int64_t)platform_time_wall_time_t();
    g_status.finished_unix = 0;
    g_status.attempts++;
    pthread_mutex_unlock(&g_status_mutex);
}

static void rf_note_progress(uint32_t chunks_done, uint64_t bytes_done)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.chunks_done = chunks_done;
    g_status.bytes_done = bytes_done;
    pthread_mutex_unlock(&g_status_mutex);
}

static void rf_note_end(bool ok, const char *detail)
{
    pthread_mutex_lock(&g_status_mutex);
    g_status.in_progress = false;
    g_status.last_ok = ok;
    g_status.finished_unix = (int64_t)platform_time_wall_time_t();
    snprintf(g_status.detail, sizeof(g_status.detail), "%s",
             detail ? detail : "");
    if (ok) {
        g_status.successes++;
        g_status.bytes_total += g_status.bytes_done;
    } else {
        g_status.failures++;
    }
    pthread_mutex_unlock(&g_status_mutex);
}

void rom_fetch_status_snapshot(struct rom_fetch_status *out)
{
    if (!out)
        return;
    pthread_mutex_lock(&g_status_mutex);
    *out = g_status;
    pthread_mutex_unlock(&g_status_mutex);
}

/* Shared install tail for both download drivers: content-prove the staged
 * .part against the committed digests, then rename it into place. A digest
 * mismatch UNLINKS the .part (no partial trust). Returns true on install;
 * *why gets a short static reason on failure. */
static bool rf_install_verified(const char *part_path, const char *final_path,
                                const struct rom_fetch_manifest *m,
                                const char **why)
{
    if (!rom_fetch_verify_file(part_path, m)) {
        LOG_WARN(RF_SUBSYS, "download: '%s' failed whole-file verification; "
                 "unlinking (seeder served non-committed content)", part_path);
        unlink(part_path);
        *why = "whole-file digest mismatch; download discarded";
        return false;
    }
    /* The delivered artifact is finalized by definition: it now matches the
     * committed digests byte-for-byte and will never be rewritten by this
     * engine. Drop every write bit so the unified installer's immutable
     * admission (immutable_regular_file_open,
     * config/src/consensus_state_snapshot_install.c) accepts the file
     * exactly as delivered — the fetch→install handoff must not need a
     * manual chmod. Fail-closed: a file we cannot finalize is not
     * installed. */
    if (chmod(part_path, S_IRUSR | S_IRGRP | S_IROTH) != 0) {
        *why = "finalize (make read-only) failed";
        LOG_FAIL(RF_SUBSYS, "download: chmod 0444 '%s' failed errno=%d",
                 part_path, errno);
    }
    if (rename(part_path, final_path) != 0) {
        *why = "rename into place failed";
        LOG_FAIL(RF_SUBSYS, "download: rename '%s' -> '%s' failed errno=%d",
                 part_path, final_path, errno);
    }
    return true;
}

/* ── Download driver ────────────────────────────────────────────────── */

bool rom_fetch_download(const char *peer_addr, uint16_t port,
                        const struct rom_fetch_manifest *m,
                        const char *out_dir,
                        rom_fetch_progress_cb cb, void *cb_ctx)
{
    if (!peer_addr || !m || !out_dir || !out_dir[0])
        LOG_FAIL(RF_SUBSYS, "download: null arg");

    struct rom_fetch_manifest mc = *m;
    if (mc.filename[0] && !rf_filename_ok(mc.filename))
        LOG_FAIL(RF_SUBSYS, "download: unsafe filename '%s'", mc.filename);
    if (!mc.filename[0]) {
        /* directory.json entries carry no name; derive a stable, safe one
         * from the committed digest. */
        char hex[17];
        HexStr(mc.chunk_root, 8, false, hex, sizeof(hex));
        snprintf(mc.filename, sizeof(mc.filename), "rom-artifact-%s", hex);
    }
    if (!rom_fetch_manifest_sane(&mc))
        LOG_FAIL(RF_SUBSYS, "download: manifest fails sanity checks");

    char part_path[1200];
    int pn = snprintf(part_path, sizeof(part_path), "%s/%s%s",
                      out_dir, mc.filename, ROM_FETCH_PART_SUFFIX);
    if (pn <= 0 || (size_t)pn >= sizeof(part_path))
        LOG_FAIL(RF_SUBSYS, "download: part path overflow");
    char final_path[1200];
    pn = snprintf(final_path, sizeof(final_path), "%s/%s",
                  out_dir, mc.filename);
    if (pn <= 0 || (size_t)pn >= sizeof(final_path))
        LOG_FAIL(RF_SUBSYS, "download: final path overflow");

    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_fetch_dl_buf");
    if (!buf)
        LOG_FAIL(RF_SUBSYS, "download: alloc chunk buffer failed");

    rf_note_begin(peer_addr, port, &mc);

    int fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        rf_note_end(false, "could not open staging file");
        free(buf);
        LOG_FAIL(RF_SUBSYS, "download: open '%s' failed errno=%d",
                 part_path, errno);
    }

    bool ok = true;
    const char *fail_reason = "";
    uint64_t bytes_done = 0;
    for (uint32_t ci = 0; ci < mc.num_chunks; ci++) {
        uint32_t want = mc.chunk_size;
        uint64_t remaining = mc.size_bytes - bytes_done;
        if (remaining < want)
            want = (uint32_t)remaining;

        /* Transient-refusal tolerance. A stock seeder gates each ROM chunk
         * on a per-peer wall-clock-1s byte window (default 8 MB/s) and a
         * small in-flight cap (rom_seed.h); on any link faster than the
         * window, a back-to-back chunk loop is refused (FS_DONE) every time
         * the window fills — that is pacing pressure, not a dead peer, and
         * it clears when the wall-second ticks over. Retry the SAME chunk a
         * bounded number of times with a fixed backoff before declaring it
         * failed. Fail-closed: a chunk still refused after
         * ROM_FETCH_CHUNK_RETRIES attempts fails the download exactly as
         * before, and wrong-size/write/digest failures never retry. */
        uint32_t got = 0;
        bool chunk_ok = false;
        for (uint32_t attempt = 0;; attempt++) {
            if (rom_fetch_chunk(peer_addr, port, mc.chunk_root, ci,
                                buf, ROM_SEED_CHUNK_SIZE, &got)) {
                chunk_ok = true;
                break;
            }
            if (attempt >= ROM_FETCH_CHUNK_RETRIES)
                break;
            LOG_INFO(RF_SUBSYS, "download: chunk %u/%u from %s:%u refused; "
                     "retry %u/%u in %u ms (seeder rate window)",
                     ci, mc.num_chunks, peer_addr, (unsigned)port,
                     attempt + 1, ROM_FETCH_CHUNK_RETRIES,
                     (unsigned)ROM_FETCH_CHUNK_RETRY_MS);
            platform_sleep_ms(ROM_FETCH_CHUNK_RETRY_MS);
        }
        if (!chunk_ok) {
            LOG_WARN(RF_SUBSYS, "download: chunk %u/%u from %s:%u failed "
                     "(leaving '%s' for resume)", ci, mc.num_chunks,
                     peer_addr, (unsigned)port, part_path);
            ok = false;
            fail_reason = "chunk fetch failed (peer refused/unreachable)";
            break;
        }
        if (got != want) {
            LOG_WARN(RF_SUBSYS, "download: chunk %u/%u length %u != expected "
                     "%u (peer served a wrong-sized chunk; leaving '%s' for "
                     "resume)", ci, mc.num_chunks, got, want, part_path);
            ok = false;
            fail_reason = "peer served a wrong-sized chunk";
            break;
        }
        ssize_t w = pwrite(fd, buf, got, (off_t)((uint64_t)ci * mc.chunk_size));
        if (w != (ssize_t)got) {
            LOG_WARN(RF_SUBSYS, "download: pwrite '%s' chunk %u failed "
                     "errno=%d", part_path, ci, errno);
            ok = false;
            fail_reason = "staging write failed";
            break;
        }
        bytes_done += got;
        rf_note_progress(ci + 1, bytes_done);
        if (cb && !cb(ci + 1, mc.num_chunks, bytes_done, cb_ctx)) {
            LOG_WARN(RF_SUBSYS, "download: aborted by caller at chunk %u/%u",
                     ci + 1, mc.num_chunks);
            ok = false;
            fail_reason = "aborted by caller";
            break;
        }
    }

    free(buf);

    if (!ok) {
        close(fd);
        rf_note_end(false, fail_reason);
        return false;
    }
    fdatasync(fd);
    close(fd);

    if (!rf_install_verified(part_path, final_path, &mc, &fail_reason)) {
        rf_note_end(false, fail_reason);
        return false;
    }

    rf_note_end(true, final_path);
    LOG_INFO(RF_SUBSYS, "download: fetched '%s' (%llu bytes, %u chunks) "
             "from %s:%u — verified against committed digests",
             final_path, (unsigned long long)mc.size_bytes, mc.num_chunks,
             peer_addr, (unsigned)port);
    return true;
}

/* ── Parallel multi-seeder download ─────────────────────────────────── */

struct rf_par_job {
    const struct rom_fetch_peer *peers;
    size_t npeers;
    struct rom_fetch_manifest m;      /* copy, filename already resolved   */
    int fd;                           /* .part; pwrite at disjoint offsets */
    _Atomic uint32_t next_chunk;
    _Atomic uint32_t chunks_done;
    _Atomic uint64_t bytes_done;
    _Atomic bool abort;               /* set on all-peers-failed / cb stop */
    _Atomic bool failed;              /* at least one chunk unrecoverable  */
    rom_fetch_progress_cb cb;
    void *cb_ctx;
    pthread_mutex_t cb_mutex;
};

static void *rf_par_worker(void *arg)
{
    struct rf_par_job *j = (struct rf_par_job *)arg;
    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_fetch_par_buf");
    if (!buf) {
        LOG_WARN(RF_SUBSYS, "par: worker alloc failed");
        atomic_store(&j->failed, true);
        atomic_store(&j->abort, true);
        return NULL;
    }

    for (;;) {
        if (atomic_load(&j->abort))
            break;
        uint32_t i = atomic_fetch_add(&j->next_chunk, 1);
        if (i >= j->m.num_chunks)
            break;

        uint64_t offset = (uint64_t)i * j->m.chunk_size;
        uint32_t want = j->m.chunk_size;
        uint64_t remaining = j->m.size_bytes - offset;
        if (remaining < want)
            want = (uint32_t)remaining;

        /* Try each peer in round-robin order starting at (i % npeers); the
         * chunk fails only when EVERY peer has failed it. */
        bool have = false;
        uint32_t got = 0;
        for (size_t a = 0; a < j->npeers; a++) {
            const struct rom_fetch_peer *p = &j->peers[(i + a) % j->npeers];
            if (rom_fetch_chunk(p->addr, p->port, j->m.chunk_root, i,
                                buf, ROM_SEED_CHUNK_SIZE, &got) &&
                got == want) {
                have = true;
                break;
            }
        }
        if (!have) {
            LOG_WARN(RF_SUBSYS, "par: chunk %u/%u failed on all %zu peer(s)",
                     i, j->m.num_chunks, j->npeers);
            atomic_store(&j->failed, true);
            atomic_store(&j->abort, true);
            break;
        }
        ssize_t w = pwrite(j->fd, buf, got, (off_t)offset);
        if (w != (ssize_t)got) {
            LOG_WARN(RF_SUBSYS, "par: pwrite chunk %u failed errno=%d",
                     i, errno);
            atomic_store(&j->failed, true);
            atomic_store(&j->abort, true);
            break;
        }
        uint64_t bytes =
            atomic_fetch_add(&j->bytes_done, got) + got;
        uint32_t done = atomic_fetch_add(&j->chunks_done, 1) + 1;
        rf_note_progress(done, bytes);
        if (j->cb) {
            pthread_mutex_lock(&j->cb_mutex);
            bool cont = j->cb(done, j->m.num_chunks, bytes, j->cb_ctx);
            pthread_mutex_unlock(&j->cb_mutex);
            if (!cont) {
                atomic_store(&j->abort, true);
                break;
            }
        }
    }
    free(buf);
    return NULL;
}

bool rom_fetch_download_parallel(const struct rom_fetch_peer *peers,
                                 size_t npeers,
                                 const struct rom_fetch_manifest *m,
                                 const char *out_dir, uint32_t workers,
                                 rom_fetch_progress_cb cb, void *cb_ctx)
{
    if (!peers || npeers == 0 || !m || !out_dir || !out_dir[0])
        LOG_FAIL(RF_SUBSYS, "par: null arg");

    struct rom_fetch_manifest mc = *m;
    if (mc.filename[0] && !rf_filename_ok(mc.filename))
        LOG_FAIL(RF_SUBSYS, "par: unsafe filename '%s'", mc.filename);
    if (!mc.filename[0]) {
        char hex[17];
        HexStr(mc.chunk_root, 8, false, hex, sizeof(hex));
        snprintf(mc.filename, sizeof(mc.filename), "rom-artifact-%s", hex);
    }
    if (!rom_fetch_manifest_sane(&mc))
        LOG_FAIL(RF_SUBSYS, "par: manifest fails sanity checks");
    for (size_t i = 0; i < npeers; i++) {
        if (!peers[i].addr[0] || peers[i].port == 0)
            LOG_FAIL(RF_SUBSYS, "par: peer %zu has empty addr/port", i);
    }

    if (workers == 0)
        workers = 1;
    if (workers > ROM_FETCH_MAX_WORKERS)
        workers = ROM_FETCH_MAX_WORKERS;
    if (workers > mc.num_chunks)
        workers = mc.num_chunks;

    char part_path[1200];
    int pn = snprintf(part_path, sizeof(part_path), "%s/%s%s",
                      out_dir, mc.filename, ROM_FETCH_PART_SUFFIX);
    if (pn <= 0 || (size_t)pn >= sizeof(part_path))
        LOG_FAIL(RF_SUBSYS, "par: part path overflow");
    char final_path[1200];
    pn = snprintf(final_path, sizeof(final_path), "%s/%s",
                  out_dir, mc.filename);
    if (pn <= 0 || (size_t)pn >= sizeof(final_path))
        LOG_FAIL(RF_SUBSYS, "par: final path overflow");

    int fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        LOG_FAIL(RF_SUBSYS, "par: open '%s' failed errno=%d",
                 part_path, errno);

    rf_note_begin(peers[0].addr, peers[0].port, &mc);

    struct rf_par_job job;
    memset(&job, 0, sizeof(job));
    job.peers = peers;
    job.npeers = npeers;
    job.m = mc;
    job.fd = fd;
    job.cb = cb;
    job.cb_ctx = cb_ctx;
    pthread_mutex_init(&job.cb_mutex, NULL);

    pthread_t tids[ROM_FETCH_MAX_WORKERS];
    uint32_t spawned = 0;
    for (uint32_t i = 0; i < workers; i++) {
        /* Bounded, joined worker pool: workers exit on queue-drain/abort,
         * chunk I/O is bounded by socket deadlines, and the driver
         * pthread_join()s every spawned worker before returning. */
        // thread-supervision-ok: bounded joined worker pool (see above).
        if (thread_registry_spawn("zcl_romfetch", rf_par_worker, &job,
                                  &tids[i]) == 0) {
            spawned++;
        } else {
            LOG_WARN(RF_SUBSYS, "par: failed to spawn worker %u", i);
            break;
        }
    }
    if (spawned == 0) {
        pthread_mutex_destroy(&job.cb_mutex);
        close(fd);
        rf_note_end(false, "could not spawn any fetch worker");
        LOG_FAIL(RF_SUBSYS, "par: no workers spawned");
    }
    for (uint32_t i = 0; i < spawned; i++)
        pthread_join(tids[i], NULL);
    pthread_mutex_destroy(&job.cb_mutex);

    uint32_t done = atomic_load(&job.chunks_done);
    if (atomic_load(&job.failed) || done < mc.num_chunks) {
        close(fd);
        rf_note_end(false, "chunk fetch failed on all peers (or aborted)");
        LOG_WARN(RF_SUBSYS, "par: download incomplete (%u/%u chunks); "
                 "leaving '%s' for resume", done, mc.num_chunks, part_path);
        return false;
    }

    fdatasync(fd);
    close(fd);

    const char *why = "";
    if (!rf_install_verified(part_path, final_path, &mc, &why)) {
        rf_note_end(false, why);
        return false;
    }

    rf_note_end(true, final_path);
    LOG_INFO(RF_SUBSYS, "par: fetched '%s' (%llu bytes, %u chunks, %u "
             "workers, %zu peer(s)) — verified against committed digests",
             final_path, (unsigned long long)mc.size_bytes, mc.num_chunks,
             spawned, npeers);
    return true;
}

/* ── Introspection ──────────────────────────────────────────────────── */

bool rom_fetch_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct rom_fetch_status s;
    rom_fetch_status_snapshot(&s);

    json_push_kv_bool(out, "ever_attempted", s.ever_attempted);
    json_push_kv_bool(out, "in_progress", s.in_progress);
    json_push_kv_bool(out, "last_ok", s.last_ok);
    json_push_kv_int(out, "attempts", (int64_t)s.attempts);
    json_push_kv_int(out, "successes", (int64_t)s.successes);
    json_push_kv_int(out, "failures", (int64_t)s.failures);
    json_push_kv_int(out, "bytes_installed_total", (int64_t)s.bytes_total);

    if (s.ever_attempted) {
        struct json_value last = {0};
        json_set_object(&last);
        json_push_kv_str(&last, "peer", s.peer);
        json_push_kv_str(&last, "filename", s.filename);
        json_push_kv_int(&last, "size_bytes", (int64_t)s.size_bytes);
        json_push_kv_int(&last, "num_chunks", (int64_t)s.num_chunks);
        json_push_kv_int(&last, "chunks_done", (int64_t)s.chunks_done);
        json_push_kv_int(&last, "bytes_done", (int64_t)s.bytes_done);
        json_push_kv_int(&last, "started_unix", s.started_unix);
        json_push_kv_int(&last, "finished_unix", s.finished_unix);
        if (s.detail[0])
            json_push_kv_str(&last, "detail", s.detail);
        json_push_kv(out, "last", &last);
        json_free(&last);
    }

    diag_push_health(out, true,
                     s.in_progress ? "fetch in progress"
                                   : "fetch engine idle");
    return true;
}

/* ── WF2 artifact-protocol: per-chunk manifest fetch + verified download ──
 *
 * The whole-file path above verifies content only at whole-file granularity;
 * these upgrade it to per-chunk verification so a resume can trust individual
 * chunks. Back-compat is the refusal: a legacy seeder that does not understand
 * the "RMF" request replies FS_DONE / goes silent, rom_fetch_get_manifest
 * returns false, and the caller falls back to the whole-file path — never an
 * offence. */

/* Must byte-match FS_ROM_MANIFEST_MAC_TAG in file_service.c: the manifest reply
 * rides fs_send_chunk_fast's MAC scheme with this constant in the 32-byte
 * binding slot. "RMF" + zero padding. */
static const uint8_t RF_ROM_MANIFEST_MAC_TAG[32] = { 'R', 'M', 'F' };

/* A stalled/absent manifest reply must fall back FAST, not sit on the 120 s
 * chunk-IO timeout — the manifest fetch precedes the whole download. */
#define RF_MANIFEST_IO_TIMEOUT_SEC 15

bool rom_fetch_verify_chunk(const uint8_t *data, uint32_t len,
                            const uint8_t expected_chunk_sha3[32])
{
    if (!data || !expected_chunk_sha3)
        return false; /* raw-return-ok: predicate — NULL is "not verified" */
    uint8_t h[32];
    sha3_256(data, len, h);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= h[i] ^ expected_chunk_sha3[i];
    return diff == 0;
}

bool rom_fetch_parse_manifest_blob(const uint8_t *blob, size_t len,
                                   const uint8_t chunk_root[32],
                                   uint8_t (*out_chunk_sha3)[32],
                                   uint32_t out_cap, uint32_t *out_num_chunks)
{
    if (!blob || !chunk_root || !out_chunk_sha3 || out_cap == 0 ||
        !out_num_chunks)
        return false; /* raw-return-ok: predicate; NULL is "not a manifest" */
    *out_num_chunks = 0;

    if (len < 8u || len > ROM_SEED_MANIFEST_BLOB_MAX || ((len - 8u) % 32u) != 0u)
        return false;

    uint32_t version = (uint32_t)blob[0] | ((uint32_t)blob[1] << 8) |
                       ((uint32_t)blob[2] << 16) | ((uint32_t)blob[3] << 24);
    uint32_t nc = (uint32_t)blob[4] | ((uint32_t)blob[5] << 8) |
                  ((uint32_t)blob[6] << 16) | ((uint32_t)blob[7] << 24);
    if (version != 1u)
        return false;
    if (nc == 0u || nc > ROM_SEED_MAX_CHUNKS || nc > out_cap ||
        (size_t)nc * 32u != (len - 8u))
        return false;

    /* Content bind: fold the per-chunk digests exactly as the seeder derived
     * chunk_root (SHA3 over the concatenated per-chunk digests). A mismatch
     * means these digests are not the committed artifact's. */
    struct sha3_256_ctx root_ctx;
    sha3_256_init(&root_ctx);
    for (uint32_t i = 0; i < nc; i++)
        sha3_256_write(&root_ctx, blob + 8u + (size_t)i * 32u, 32);
    uint8_t computed_root[32];
    sha3_256_finalize(&root_ctx, computed_root);
    if (memcmp(computed_root, chunk_root, 32) != 0)
        return false;

    for (uint32_t i = 0; i < nc; i++)
        memcpy(out_chunk_sha3[i], blob + 8u + (size_t)i * 32u, 32);
    *out_num_chunks = nc;
    return true;
}

bool rom_fetch_get_manifest(const char *peer_addr, uint16_t port,
                            const uint8_t chunk_root[32],
                            uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
                            uint32_t *out_num_chunks)
{
    if (!peer_addr || !peer_addr[0] || !chunk_root || !out_chunk_sha3 ||
        out_cap == 0 || !out_num_chunks)
        LOG_FAIL(RF_SUBSYS, "manifest: null/empty arg");
    *out_num_chunks = 0;

    int fd = rf_connect(peer_addr, port);
    if (fd < 0)
        return false; /* rf_connect logged; caller falls back to whole-file */

    /* Shorten the recv window: a legacy (RMF-unaware) seeder never replies, so
     * a fast timeout is the fall-back signal rather than a 120 s stall. */
    struct timeval tv = { .tv_sec = RF_MANIFEST_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct fs_session s;
    fs_session_init(&s, fd);
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&s, zero_root, true)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: handshake failed with %s:%u — falling "
                 "back to whole-file verify", peer_addr, (unsigned)port);
        return false;
    }

    /* Request: ["RMF"(3)][chunk_root(32)]. */
    uint8_t req[FS_ROM_MANIFEST_REQUEST_SIZE];
    memcpy(req, "RMF", 3);
    memcpy(req + 3, chunk_root, 32);
    if (!fs_send_frame(&s, FS_REQUEST, req, sizeof(req))) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: request send failed to %s:%u — falling "
                 "back", peer_addr, (unsigned)port);
        return false;
    }

    /* Reply is size/blob/MAC; FS_DONE parses as an invalid size and falls back. */
    uint8_t hdr[4];
    if (!rf_recv_exact(fd, hdr, 4)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: no reply from %s:%u (legacy seeder?) — "
                 "falling back", peer_addr, (unsigned)port);
        return false;
    }
    uint32_t size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                    ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    /* Strict bounds: [u32 version][u32 num_chunks][k × 32B]; size ≥ 8, well
     * within the blob cap, and (size − 8) a whole number of 32-byte digests. */
    if (size < 8u || size > ROM_SEED_MANIFEST_BLOB_MAX ||
        ((size - 8u) % 32u) != 0u) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: implausible blob size %u from %s:%u — "
                 "falling back", size, peer_addr, (unsigned)port);
        return false;
    }

    uint8_t blob[ROM_SEED_MANIFEST_BLOB_MAX];
    if (!rf_recv_exact(fd, blob, size)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: blob read failed from %s:%u — falling "
                 "back", peer_addr, (unsigned)port);
        return false;
    }
    uint8_t mac_wire[32];
    if (!rf_recv_exact(fd, mac_wire, 32)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: MAC read failed from %s:%u — falling "
                 "back", peer_addr, (unsigned)port);
        return false;
    }
    close(fd);

    /* Transport MAC: SHA3(key || recv_counter || "RMF"tag || blob), matching
     * the serve side's fs_send_chunk_fast(blob, tag). */
    uint8_t mac_expect[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s.key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s.recv_counter, 8);
    sha3_256_write(&mctx, RF_ROM_MANIFEST_MAC_TAG, 32);
    sha3_256_write(&mctx, blob, size);
    sha3_256_finalize(&mctx, mac_expect);
    memory_cleanse(&mctx, sizeof(mctx));
    fs_session_cleanup(&s);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= mac_wire[i] ^ mac_expect[i];
    if (diff != 0) {
        LOG_INFO(RF_SUBSYS, "manifest: MAC mismatch from %s:%u — falling back",
                 peer_addr, (unsigned)port);
        return false;
    }

    /* Parse + content-bind (version, length, num_chunks bounds, chunk-root
     * fold) in the pure, unit-tested core. Any inconsistency → fall back. */
    if (!rom_fetch_parse_manifest_blob(blob, size, chunk_root, out_chunk_sha3,
                                       out_cap, out_num_chunks)) {
        LOG_INFO(RF_SUBSYS, "manifest: blob failed parse/verify from %s:%u — "
                 "falling back to whole-file", peer_addr, (unsigned)port);
        return false;
    }
    LOG_INFO(RF_SUBSYS, "manifest: got %u per-chunk digests from %s:%u "
             "(chunk-root verified)", *out_num_chunks, peer_addr,
             (unsigned)port);
    return true;
}

/* ── Directory-listing fetch (clearnet peer discovery) ──────────────── */

/* Must byte-match FS_ROM_LIST_MAC_TAG in file_service.c: the listing reply
 * rides fs_send_chunk_fast's MAC scheme with this constant in the 32-byte
 * binding slot. "RLS" + zero padding. */
static const uint8_t RF_ROM_LIST_MAC_TAG[32] = { 'R', 'L', 'S' };

bool rom_fetch_get_directory(const char *peer_addr, uint16_t port,
                             char *buf, size_t cap)
{
    if (!peer_addr || !peer_addr[0] || !buf || cap == 0)
        LOG_FAIL(RF_SUBSYS, "directory: null/empty arg");

    int fd = rf_connect(peer_addr, port);
    if (fd < 0)
        return false; /* rf_connect logged; caller just skips this seed */

    /* Short recv window: a legacy (RLS-unaware) seeder never replies, so a fast
     * timeout is the fall-back signal rather than a 120 s stall. */
    struct timeval tv = { .tv_sec = RF_MANIFEST_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct fs_session s;
    fs_session_init(&s, fd);
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&s, zero_root, true)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: handshake failed with %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }

    /* Request: ["RLS"(3)]. */
    uint8_t req[FS_ROM_LIST_REQUEST_SIZE];
    memcpy(req, "RLS", 3);
    if (!fs_send_frame(&s, FS_REQUEST, req, sizeof(req))) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: request send failed to %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }

    /* Reply is size/body/MAC; FS_DONE parses as an invalid size and is skipped. */
    uint8_t hdr[4];
    if (!rf_recv_exact(fd, hdr, 4)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: no reply from %s:%u (legacy seeder?) — "
                 "skipping seed", peer_addr, (unsigned)port);
        return false;
    }
    uint32_t size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                    ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    /* Bounded by the caller's cap, leaving one byte for the NUL terminator. A
     * zero-length body or one at/over cap (incl. the FS_DONE refusal) fails. */
    if (size == 0 || size >= cap) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: implausible body size %u (cap %zu) from "
                 "%s:%u — skipping seed", size, cap, peer_addr, (unsigned)port);
        return false;
    }
    if (!rf_recv_exact(fd, (uint8_t *)buf, size)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: body read failed from %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }
    uint8_t mac_wire[32];
    if (!rf_recv_exact(fd, mac_wire, 32)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: MAC read failed from %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }
    close(fd);

    /* Transport MAC: SHA3(key || recv_counter || "RLS"tag || body), matching the
     * serve side's fs_send_chunk_fast(body, tag). */
    uint8_t mac_expect[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s.key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s.recv_counter, 8);
    sha3_256_write(&mctx, RF_ROM_LIST_MAC_TAG, 32);
    sha3_256_write(&mctx, (const uint8_t *)buf, size);
    sha3_256_finalize(&mctx, mac_expect);
    memory_cleanse(&mctx, sizeof(mctx));
    fs_session_cleanup(&s);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= mac_wire[i] ^ mac_expect[i];
    if (diff != 0) {
        LOG_INFO(RF_SUBSYS, "directory: MAC mismatch from %s:%u — skipping seed",
                 peer_addr, (unsigned)port);
        return false;
    }

    buf[size] = '\0';
    LOG_INFO(RF_SUBSYS, "directory: got %u-byte listing from %s:%u",
             size, peer_addr, (unsigned)port);
    return true;
}

/* ── Per-chunk-verified download with durable resume ────────────────── */

struct rf_ver_job {
    const struct rom_fetch_peer *peers; /* caller-owned, npeers entries      */
    size_t   npeers;
    struct rom_fetch_manifest m;      /* copy, filename already resolved   */
    const uint8_t (*chunk_sha3)[32];  /* caller-owned, num_chunks rows     */
    uint32_t num_chunks;
    int fd;                           /* .part; pwrite at disjoint offsets */
    struct rom_journal *jrnl;         /* shared; mark() is self-locked     */
    _Atomic uint32_t next_chunk;
    _Atomic uint64_t bytes_done;
    _Atomic bool abort;
    _Atomic bool failed;
    rom_fetch_progress_cb cb;
    void *cb_ctx;
    pthread_mutex_t cb_mutex;
};

/* One round tries every peer once (fast failover across seeders); a full-round
 * miss backs off before the next round to absorb a stock seeder's per-peer
 * wall-clock-1s rate window. Sized so a single-peer job (npeers==1) preserves
 * the whole-file driver's exact tolerance: ROM_FETCH_CHUNK_RETRIES backoffs. */
#define ROM_FETCH_VER_ROUNDS (ROM_FETCH_CHUNK_RETRIES + 1u)

/* Acquire + content-verify chunk `i` into `buf`, trying the job's peers in
 * round-robin (starting at i % npeers) so a corrupt/unreachable seeder fails
 * OVER to the next one. Two distinct failure classes are handled differently,
 * which is what keeps single-peer behaviour identical to the old driver:
 *
 *   - A TRANSIENT miss (unreachable / refused / wrong-size) is retryable — a
 *     stock seeder's per-peer wall-clock-1s rate window refuses back-to-back
 *     chunks and clears in ~1 s — so a full-ring miss backs off once and
 *     retries the whole ring, bounded by ROM_FETCH_VER_ROUNDS.
 *   - A CONTENT-verify failure (right-sized bytes, wrong digest) means that
 *     peer is serving non-committed content; it is scored bad
 *     (rom_peer_note_bad_chunk) and POISONED for this chunk — never re-fetched.
 *     Re-requesting the same bad bytes would only burn the seeder's rate window
 *     and the wire. When every peer is poisoned (no peer can still be retried),
 *     the chunk fails immediately — so a single-peer digest mismatch fails on
 *     the first attempt exactly as before, never looping.
 *
 * Returns true (with *out_got set) only on digest-verified bytes from some
 * peer; false when the chunk cannot be satisfied, or the job aborted. Peer
 * indices past 63 are not poison-tracked (a bounded bitmask); they degrade to
 * retryable, still bounded by the round cap. */
static bool rf_ver_acquire_chunk(struct rf_ver_job *j, uint32_t i,
                                  uint32_t want, uint8_t *buf, uint32_t *out_got)
{
    *out_got = 0;
    uint64_t poisoned = 0; /* bit p set => peers[p] served bad content here */
    for (uint32_t round = 0; round < ROM_FETCH_VER_ROUNDS; round++) {
        if (atomic_load(&j->abort))
            return false;
        bool any_retryable_miss = false;
        for (size_t a = 0; a < j->npeers; a++) {
            if (atomic_load(&j->abort))
                return false;
            size_t pi = (i + a) % j->npeers;
            if (pi < 64 && (poisoned & (1ull << pi)))
                continue; /* served bad content already — never re-fetch it */
            const struct rom_fetch_peer *p = &j->peers[pi];
            uint32_t got = 0;
            if (!rom_fetch_chunk(p->addr, p->port, j->m.chunk_root, i,
                                 buf, ROM_SEED_CHUNK_SIZE, &got) ||
                got != want) {
                any_retryable_miss = true; /* transient — may clear next round */
                continue;
            }
            /* CONTENT verify BEFORE this peer's bytes can be marked durable —
             * a set journal bit must always imply digest-verified data. */
            if (!rom_fetch_verify_chunk(buf, got, j->chunk_sha3[i])) {
                LOG_WARN(RF_SUBSYS, "ver: chunk %u/%u digest mismatch from "
                         "%s:%u (seeder served non-committed content) — "
                         "failing over", i, j->num_chunks, p->addr,
                         (unsigned)p->port);
                (void)rom_peer_note_bad_chunk(p->addr, p->port, i, "digest");
                if (pi < 64)
                    poisoned |= (1ull << pi);
                continue; /* corrupt bytes — poison + fail over to next peer */
            }
            *out_got = got;
            return true;
        }
        /* No peer can still be retried (all poisoned / exhausted) — fail now
         * rather than loop re-fetching content we already know is bad. */
        if (!any_retryable_miss)
            return false;
        /* Some peer had a transient miss (typically a per-peer rate-window
         * refusal) — back off once, then retry the ring (skip the sleep after
         * the final round). JITTER the backoff by a chunk-index-derived spread
         * so N parallel workers that all filled the same per-peer window this
         * second don't re-collide in lockstep the next round (thundering herd);
         * each worker holds a distinct chunk index i at any instant, so the
         * spread de-correlates them while staying bounded and deterministic. */
        if (round + 1u < ROM_FETCH_VER_ROUNDS && !atomic_load(&j->abort)) {
            uint32_t jitter = (i * 137u + round * 991u) %
                              (ROM_FETCH_CHUNK_RETRY_MS / 2u + 1u);
            platform_sleep_ms(ROM_FETCH_CHUNK_RETRY_MS + jitter);
        }
    }
    return false;
}

static void *rf_ver_worker(void *arg)
{
    struct rf_ver_job *j = (struct rf_ver_job *)arg;
    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_fetch_ver_buf");
    if (!buf) {
        LOG_WARN(RF_SUBSYS, "ver: worker alloc failed");
        atomic_store(&j->failed, true);
        atomic_store(&j->abort, true);
        return NULL;
    }

    for (;;) {
        if (atomic_load(&j->abort))
            break;
        uint32_t i = atomic_fetch_add(&j->next_chunk, 1);
        if (i >= j->num_chunks)
            break;

        /* Resume: a set journal bit means the chunk is already durable +
         * digest-verified — skip re-fetching it. */
        if (rom_journal_is_done(j->jrnl, i))
            continue;

        uint64_t offset = (uint64_t)i * j->m.chunk_size;
        uint32_t want = j->m.chunk_size;
        uint64_t remaining = j->m.size_bytes - offset;
        if (remaining < want)
            want = (uint32_t)remaining;

        /* Fetch + per-chunk content-verify with round-robin multi-seeder
         * failover (single-peer jobs pass npeers==1). */
        uint32_t got = 0;
        if (!rf_ver_acquire_chunk(j, i, want, buf, &got)) {
            if (!atomic_load(&j->abort))
                LOG_WARN(RF_SUBSYS, "ver: chunk %u/%u failed content-verify on "
                         "all %zu peer(s)", i, j->num_chunks, j->npeers);
            atomic_store(&j->failed, true);
            atomic_store(&j->abort, true);
            break;
        }

        ssize_t w = pwrite(j->fd, buf, got, (off_t)offset);
        if (w != (ssize_t)got) {
            LOG_WARN(RF_SUBSYS, "ver: pwrite chunk %u failed errno=%d",
                     i, errno);
            atomic_store(&j->failed, true);
            atomic_store(&j->abort, true);
            break;
        }
        /* Durability ordering: fdatasync(.part) → set bit → fdatasync(journal)
         * (rom_journal_mark does the last two). A set bit therefore always
         * implies durable, digest-verified data. */
        if (fdatasync(j->fd) != 0 || !rom_journal_mark(j->jrnl, i)) {
            LOG_WARN(RF_SUBSYS, "ver: durable-mark chunk %u failed errno=%d",
                     i, errno);
            atomic_store(&j->failed, true);
            atomic_store(&j->abort, true);
            break;
        }

        uint64_t bytes = atomic_fetch_add(&j->bytes_done, got) + got;
        uint32_t total_done = rom_journal_count_done(j->jrnl);
        rf_note_progress(total_done, bytes);
        if (j->cb) {
            pthread_mutex_lock(&j->cb_mutex);
            bool cont = j->cb(total_done, j->num_chunks, bytes, j->cb_ctx);
            pthread_mutex_unlock(&j->cb_mutex);
            if (!cont) {
                LOG_WARN(RF_SUBSYS, "ver: aborted by caller at chunk %u/%u",
                         total_done, j->num_chunks);
                atomic_store(&j->abort, true);
                break;
            }
        }
    }
    free(buf);
    return NULL;
}

/* Random spot-check: re-read a bounded sample of the journal's already-done
 * chunks from the .part and re-hash them against the committed digests. Guards
 * against a .part that no longer matches its journal (external truncation /
 * corruption). Returns false if any sampled chunk fails. */
static bool rf_ver_spotcheck_resume(int fd, const struct rom_fetch_manifest *m,
                                    const uint8_t (*chunk_sha3)[32],
                                    uint32_t num_chunks,
                                    const struct rom_journal *jrnl)
{
    uint32_t done = rom_journal_count_done(jrnl);
    if (done == 0)
        return true;

    /* Sample up to 8 done chunks (bounded, cheap). */
    uint8_t *buf = zcl_malloc(ROM_SEED_CHUNK_SIZE, "rom_fetch_spotcheck_buf");
    if (!buf)
        LOG_FAIL(RF_SUBSYS, "spotcheck: alloc failed");

    uint32_t samples = done < 8u ? done : 8u;
    uint64_t seed = (uint64_t)platform_time_wall_time_t() ^
                    ((uint64_t)num_chunks << 17);
    bool ok = true;
    for (uint32_t s = 0; s < samples && ok; s++) {
        /* xorshift step for a spread of indices without libc rand state. */
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint32_t start = (uint32_t)(seed % num_chunks);
        /* Walk forward to the next done chunk. */
        uint32_t idx = start, scanned = 0;
        while (scanned < num_chunks && !rom_journal_is_done(jrnl, idx)) {
            idx = (idx + 1u) % num_chunks;
            scanned++;
        }
        if (scanned >= num_chunks)
            break; /* nothing done (raced) — nothing to check */

        uint64_t offset = (uint64_t)idx * m->chunk_size;
        uint32_t want = m->chunk_size;
        uint64_t remaining = m->size_bytes - offset;
        if (remaining < want)
            want = (uint32_t)remaining;
        uint32_t got = 0;
        while (got < want) {
            ssize_t r = pread(fd, buf + got, want - got, (off_t)(offset + got));
            if (r < 0) {
                if (errno == EINTR) continue;
                ok = false; break;
            }
            if (r == 0) { ok = false; break; }
            got += (uint32_t)r;
        }
        if (!ok || got != want ||
            !rom_fetch_verify_chunk(buf, got, chunk_sha3[idx])) {
            LOG_WARN(RF_SUBSYS, "spotcheck: resumed chunk %u fails re-hash — "
                     "the .part no longer matches its journal", idx);
            ok = false;
        }
    }
    free(buf);
    return ok;
}

/* Shared per-chunk-verified download core for both the single-peer and
 * multi-seeder public entry points. `peers` holds npeers>=1 seeder endpoints;
 * the worker ring content-verifies every chunk and fails OVER across them
 * (rf_ver_acquire_chunk). Everything else — durable resume journal, spot-check
 * on resume, whole-file gate, atomic read-only install — is identical to the
 * single-peer contract, so a single-element ring reproduces it byte-for-byte. */
static bool rf_download_verified_core(const struct rom_fetch_peer *peers,
                                      size_t npeers,
                                      const struct rom_fetch_manifest *m,
                                      const uint8_t (*chunk_sha3)[32],
                                      uint32_t num_chunks, const char *out_dir,
                                      rom_fetch_progress_cb cb, void *cb_ctx)
{
    if (!peers || npeers == 0 || !m || !chunk_sha3 || !out_dir || !out_dir[0])
        LOG_FAIL(RF_SUBSYS, "ver: null arg");

    struct rom_fetch_manifest mc = *m;
    if (mc.filename[0] && !rf_filename_ok(mc.filename))
        LOG_FAIL(RF_SUBSYS, "ver: unsafe filename '%s'", mc.filename);
    if (!mc.filename[0]) {
        char hex[17];
        HexStr(mc.chunk_root, 8, false, hex, sizeof(hex));
        snprintf(mc.filename, sizeof(mc.filename), "rom-artifact-%s", hex);
    }
    if (!rom_fetch_manifest_sane(&mc))
        LOG_FAIL(RF_SUBSYS, "ver: manifest fails sanity checks");
    if (num_chunks != mc.num_chunks)
        LOG_FAIL(RF_SUBSYS, "ver: num_chunks %u != manifest %u",
                 num_chunks, mc.num_chunks);

    char part_path[1200];
    int pn = snprintf(part_path, sizeof(part_path), "%s/%s%s",
                      out_dir, mc.filename, ROM_FETCH_PART_SUFFIX);
    if (pn <= 0 || (size_t)pn >= sizeof(part_path))
        LOG_FAIL(RF_SUBSYS, "ver: part path overflow");
    char final_path[1200];
    pn = snprintf(final_path, sizeof(final_path), "%s/%s", out_dir, mc.filename);
    if (pn <= 0 || (size_t)pn >= sizeof(final_path))
        LOG_FAIL(RF_SUBSYS, "ver: final path overflow");
    char jrnl_path[1264];
    pn = snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);
    if (pn <= 0 || (size_t)pn >= sizeof(jrnl_path))
        LOG_FAIL(RF_SUBSYS, "ver: journal path overflow");

    rf_note_begin(peers[0].addr, peers[0].port, &mc);

    struct rom_journal *jrnl = rom_journal_open(jrnl_path, mc.chunk_root,
                                                mc.whole_sha3, mc.chunk_size,
                                                mc.num_chunks);
    if (!jrnl) {
        rf_note_end(false, "could not open resume journal");
        LOG_FAIL(RF_SUBSYS, "ver: rom_journal_open('%s') failed", jrnl_path);
    }

    /* A brand-new / discarded journal (count 0) means no trustworthy .part —
     * start the staging file clean. A resume (count > 0) preserves .part but
     * must pass a random spot-check re-hash first; on failure, discard both and
     * start fresh (no partial trust). */
    bool resume = rom_journal_count_done(jrnl) > 0;
    int fd = -1;
    if (resume) {
        fd = open(part_path, O_RDWR | O_CLOEXEC);
        if (fd < 0 ||
            !rf_ver_spotcheck_resume(fd, &mc, chunk_sha3, num_chunks, jrnl)) {
            if (fd >= 0) close(fd);
            LOG_WARN(RF_SUBSYS, "ver: resume rejected for '%s' — restarting "
                     "the download fresh", part_path);
            rom_journal_close(jrnl);
            (void)rom_journal_discard(jrnl_path);
            (void)unlink(part_path);
            jrnl = rom_journal_open(jrnl_path, mc.chunk_root, mc.whole_sha3,
                                    mc.chunk_size, mc.num_chunks);
            if (!jrnl) {
                rf_note_end(false, "could not reopen resume journal");
                LOG_FAIL(RF_SUBSYS, "ver: journal reopen failed");
            }
            resume = false;
        }
    }
    if (!resume) {
        fd = open(part_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) {
            rom_journal_close(jrnl);
            rf_note_end(false, "could not open staging file");
            LOG_FAIL(RF_SUBSYS, "ver: open '%s' failed errno=%d",
                     part_path, errno);
        }
    }

    uint32_t workers = ROM_FETCH_MAX_WORKERS;
    if (workers > mc.num_chunks)
        workers = mc.num_chunks;
    if (workers == 0)
        workers = 1;

    struct rf_ver_job job;
    memset(&job, 0, sizeof(job));
    job.peers = peers;
    job.npeers = npeers;
    job.m = mc;
    job.chunk_sha3 = chunk_sha3;
    job.num_chunks = num_chunks;
    job.fd = fd;
    job.jrnl = jrnl;
    job.cb = cb;
    job.cb_ctx = cb_ctx;
    atomic_store(&job.bytes_done,
                 (uint64_t)rom_journal_count_done(jrnl) * mc.chunk_size);
    pthread_mutex_init(&job.cb_mutex, NULL);

    pthread_t tids[ROM_FETCH_MAX_WORKERS];
    uint32_t spawned = 0;
    for (uint32_t i = 0; i < workers; i++) {
        // thread-supervision-ok: bounded joined worker pool (drain/abort exit).
        if (thread_registry_spawn("zcl_romver", rf_ver_worker, &job,
                                  &tids[i]) == 0)
            spawned++;
        else {
            LOG_WARN(RF_SUBSYS, "ver: failed to spawn worker %u", i);
            break;
        }
    }
    if (spawned == 0) {
        pthread_mutex_destroy(&job.cb_mutex);
        close(fd);
        rom_journal_close(jrnl);
        rf_note_end(false, "could not spawn any fetch worker");
        LOG_FAIL(RF_SUBSYS, "ver: no workers spawned");
    }
    for (uint32_t i = 0; i < spawned; i++)
        pthread_join(tids[i], NULL);
    pthread_mutex_destroy(&job.cb_mutex);

    uint32_t done = rom_journal_count_done(jrnl);
    if (atomic_load(&job.failed) || done < mc.num_chunks) {
        close(fd);
        rom_journal_close(jrnl);
        rf_note_end(false, "chunk fetch/verify failed (leaving .part + "
                    "journal for resume)");
        LOG_WARN(RF_SUBSYS, "ver: incomplete (%u/%u chunks); leaving '%s' + "
                 "journal for resume", done, mc.num_chunks, part_path);
        return false;
    }

    fdatasync(fd);
    close(fd);

    /* Whole-file content proof stays the final gate before install. */
    const char *why = "";
    if (!rf_install_verified(part_path, final_path, &mc, &why)) {
        rom_journal_close(jrnl);
        rf_note_end(false, why);
        return false;
    }
    /* Installed: the resume journal has served its purpose. */
    rom_journal_close(jrnl);
    (void)rom_journal_discard(jrnl_path);

    rf_note_end(true, final_path);
    LOG_INFO(RF_SUBSYS, "ver: fetched '%s' (%llu bytes, %u chunks) from %s:%u "
             "(+%zu failover peer(s)) — per-chunk + whole-file verified",
             final_path, (unsigned long long)mc.size_bytes, mc.num_chunks,
             peers[0].addr, (unsigned)peers[0].port, npeers - 1);
    return true;
}

bool rom_fetch_download_verified(const char *peer_addr, uint16_t port,
                                 const struct rom_fetch_manifest *m,
                                 const uint8_t (*chunk_sha3)[32],
                                 uint32_t num_chunks, const char *out_dir,
                                 rom_fetch_progress_cb cb, void *cb_ctx)
{
    if (!peer_addr || !peer_addr[0])
        LOG_FAIL(RF_SUBSYS, "ver: null/empty peer_addr");
    struct rom_fetch_peer p;
    memset(&p, 0, sizeof(p));
    snprintf(p.addr, sizeof(p.addr), "%s", peer_addr);
    p.port = port;
    return rf_download_verified_core(&p, 1, m, chunk_sha3, num_chunks, out_dir,
                                     cb, cb_ctx);
}

bool rom_fetch_download_verified_parallel(const struct rom_fetch_peer *peers,
                                          size_t npeers,
                                          const struct rom_fetch_manifest *m,
                                          const uint8_t (*chunk_sha3)[32],
                                          uint32_t num_chunks,
                                          const char *out_dir,
                                          rom_fetch_progress_cb cb,
                                          void *cb_ctx)
{
    if (!peers || npeers == 0)
        LOG_FAIL(RF_SUBSYS, "ver-par: null/empty peer list");
    for (size_t i = 0; i < npeers; i++) {
        if (!peers[i].addr[0] || peers[i].port == 0)
            LOG_FAIL(RF_SUBSYS, "ver-par: peer %zu has empty addr/port", i);
    }
    return rf_download_verified_core(peers, npeers, m, chunk_sha3, num_chunks,
                                     out_dir, cb, cb_ctx);
}
