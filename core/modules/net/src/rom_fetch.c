/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact fetching — the CLIENT half of docs/ROM_DELIVERY.md. See
 * net/rom_fetch.h for the contract, the trust model, and the wire protocol.
 * Wire/disk input is bounded and verified against caller-committed digests;
 * install/activation remains with the unified installer. */
#include "net/rom_fetch.h"
#include "rom_fetch_internal.h"
#include "net/file_service.h"
#include "net/rom_journal.h"
#include "net/rom_peer_scoring.h"
#include "rom_fetch_transport.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "platform/socket_compat.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "base/text_fit.h"
#include "util/thread_registry.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#include <process.h>
#define close _close
#define open _open
#define unlink _unlink
#define chmod _chmod
#define fstat _fstat64
#define stat _stat64
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef S_ISREG
#define S_ISREG(mode_) (((mode_) & _S_IFMT) == _S_IFREG)
#endif
static int64_t rf_windows_pread(int fd, void *data, size_t size,
                                int64_t offset)
{
    if (_lseeki64(fd, offset, SEEK_SET) < 0) return -1;
    return _read(fd, data, size > INT_MAX ? INT_MAX : (unsigned int)size);
}
static int64_t rf_windows_pwrite(int fd, const void *data, size_t size,
                                 int64_t offset)
{
    if (_lseeki64(fd, offset, SEEK_SET) < 0) return -1;
    return _write(fd, data, size > INT_MAX ? INT_MAX : (unsigned int)size);
}
#define pread(fd_, data_, size_, offset_) \
    rf_windows_pread((fd_), (data_), (size_), (int64_t)(offset_))
#define pwrite(fd_, data_, size_, offset_) \
    rf_windows_pwrite((fd_), (data_), (size_), (int64_t)(offset_))
#define fsync _commit
#else
#include <unistd.h>
#endif
#define RF_SUBSYS "rom_fetch"
/* Bounded per-chunk retry against the seeder's wall-clock-1s rate window
 * (rom_seed_rate_charge): 1100 ms always crosses a second boundary, and
 * 25 retries bound a persistently-refusing peer to ~28 s per chunk before
 * the download fails closed. Sized so a stock 8 MB/s seeder costs at most
 * one retry per chunk pair. */
#define ROM_FETCH_CHUNK_RETRIES  25u
#define ROM_FETCH_CHUNK_RETRY_MS 1100u
#if defined(_WIN32)
#define RF_MUTATION_ONLY __attribute__((unused))
#else
#define RF_MUTATION_ONLY
#endif

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

/* ── Manifest validation + discovery parse ──────────────────────────── */

bool rom_fetch_manifest_sane(const struct rom_fetch_manifest *m)
{
    if (!m)
        return false;
    /* Per-kind floor — a source bundle is legitimately under one SQLite page.
     * `kind` is a peer claim: PLAUSIBILITY, never trust. */
    if (m->size_bytes < rom_seed_kind_min_bytes(m->kind) ||
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
        /* "kind", "height" and "source_root" are OPTIONAL untrusted peer
         * claims, outside manifest_sane's trust check on purpose: the first
         * two steer the picker, source_root only lets a caller FIND a bundle
         * before re-proving it. Detail is on struct rom_fetch_manifest. */
        m.kind = rom_seed_kind_from_name(json_get_str(json_get(e, "kind")));
        int64_t height = json_get_int(json_get(e, "height"));
        m.height = height > 0 ? height : 0;
        m.has_source_root = rf_parse_digest(e, "source_root", m.source_root);
        if (!rom_fetch_manifest_sane(&m))
            continue;
        m.used = true;
        out[n++] = m;
    }

    json_free(&doc);
    return n;
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

/* Fetch status (observability): rf_note_begin/progress/end narrate every
 * driver below into the shared status record; rom_fetch_status_snapshot and
 * rom_fetch_dump_state_json read it back. Split out to rom_fetch_status.c —
 * see rom_fetch_internal.h for the rf_note_* declarations. */

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
     * engine/composition/src/consensus_state_snapshot_install.c) accepts the file
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
#if defined(_WIN32)
    (void)peer_addr; (void)port; (void)m; (void)out_dir;
    (void)cb; (void)cb_ctx;
    errno = ENOTSUP;
    return false;
#else
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
    platform_data_sync(fd);
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
#endif
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

static RF_MUTATION_ONLY void *rf_par_worker(void *arg)
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
#if defined(_WIN32)
    (void)peers; (void)npeers; (void)m; (void)out_dir;
    (void)workers; (void)cb; (void)cb_ctx;
    errno = ENOTSUP;
    return false;
#else
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

    platform_data_sync(fd);
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
#endif
}

/* rom_fetch_dump_state_json (JSON status introspection) moved to
 * rom_fetch_status.c alongside the rf_note_* helpers and g_status it
 * reads through rom_fetch_status_snapshot(). */

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

/* RF_MANIFEST_IO_TIMEOUT_SEC lives in rom_fetch_internal.h — the directory
 * fetch (rom_fetch_directory.c) uses the same budget. Both reach it through
 * rf_probe_io_timeout_ms(), which scales the window for the transport the
 * address implies: a stalled reply over a Tor circuit must not be read as a
 * legacy seeder just because circuits are slower than sockets. */

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

    platform_socket_t fd = rf_connect(peer_addr, port);
    if (fd == PLATFORM_SOCKET_INVALID)
        return false; /* rf_connect logged; caller falls back to whole-file */

    /* Shorten the recv window: a legacy (RMF-unaware) seeder never replies, so
     * a fast timeout is the fall-back signal rather than a 120 s stall. */
    const int64_t rmf_deadline_ms = platform_time_monotonic_ms() + rf_probe_io_timeout_ms(peer_addr);
    (void)platform_socket_set_receive_timeout(
        fd, rf_probe_io_timeout_ms(peer_addr));

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
    if (!rf_recv_exact_until(fd, hdr, 4, rmf_deadline_ms)) {
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
    if (!rf_recv_exact_until(fd, blob, size, rmf_deadline_ms)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: blob read failed from %s:%u — falling "
                 "back", peer_addr, (unsigned)port);
        return false;
    }
    uint8_t mac_wire[32];
    if (!rf_recv_exact_until(fd, mac_wire, 32, rmf_deadline_ms)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "manifest: MAC read failed from %s:%u — falling "
                 "back", peer_addr, (unsigned)port);
        return false;
    }
    platform_socket_close(fd);

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
    /* Bit p set => peers[p] could not be DIALLED at all earlier in this job.
     * Shared by every worker so the swarm pays that discovery once instead of
     * once per worker per chunk — see rf_ver_acquire_chunk. Peers past index
     * 63 are untracked and simply keep the old behaviour. */
    _Atomic uint64_t unreachable;
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
 * round-robin so a corrupt/unreachable seeder fails OVER to the next one.
 *
 * The ring STARTS at the peer this worker already holds a session with, and
 * falls back to `i % npeers` when it holds none — which is every worker's
 * first chunk, so the initial spread of workers across seeders is exactly
 * what it always was. Preferring the held session afterwards is what turns a
 * download into O(workers) dials instead of O(chunks); it changes only which
 * of the peers is asked FIRST, never which peers are tried (all of them, in
 * one round) nor on what terms.
 *
 * Two distinct failure classes are handled differently,
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
 * UNREACHABLE-PEER MEMORY, and why it is not a speed judgement.
 *
 * A peer that cannot be DIALLED — rf_connect comes back with no socket at all
 * — has already cost this job one whole connect budget. That budget is
 * transport-scaled on purpose: 10 s to a socket, 120 s to build a Tor circuit,
 * because a circuit is genuinely slower to establish and reading that as
 * "bad peer" would drop honest onion seeders. What it must NOT also mean is
 * that every worker, and every chunk, gets to spend that budget over again
 * rediscovering the same absence: eight workers walking past seven dead seeds
 * is fifty-six 120 s circuit attempts before the first byte arrives.
 *
 * So a failed DIAL is recorded once in j->unreachable, shared by the whole
 * job, and the ring skips those peers. Three properties keep this honest:
 *
 *   - Only a dial that returned NOTHING marks a peer. A peer that connects
 *     slowly, hands over bytes slowly, or refuses with a typed busy reply is
 *     never marked — slowness is not a verdict here, and no budget is
 *     shortened, sampled early, or scaled down to produce this signal.
 *   - The memory is JOB-scoped, not persisted and not a ban. A later download
 *     starts with a clean set and pays the full budget again.
 *   - It can never write a peer off. If skipping would leave a round with no
 *     peer left to try, the whole mask is cleared BEFORE that round runs and
 *     everyone is dialled again at full budget — so no round is ever spent
 *     asking nobody and the retry tolerance is exactly what it was. A
 *     shrinking swarm converges on retrying its last seed, not on giving up.
 *
 * Returns true (with *out_got set) only on digest-verified bytes from some
 * peer; false when the chunk cannot be satisfied, or the job aborted. Peer
 * indices past 63 are not poison-tracked (a bounded bitmask); they degrade to
 * retryable, still bounded by the round cap. */
static bool rf_ver_acquire_chunk(struct rf_ver_job *j, struct rf_peer_conn *c,
                                  uint32_t i,
                                  uint32_t want, uint8_t *buf, uint32_t *out_got)
{
    *out_got = 0;
    uint64_t poisoned = 0; /* bit p set => peers[p] served bad content here */
    /* Start the ring on the peer this worker is already talking to. */
    size_t start = i;
    if (c->is_open) {
        for (size_t k = 0; k < j->npeers; k++) {
            if (j->peers[k].port == c->port &&
                strcmp(j->peers[k].addr, c->addr) == 0) {
                start = k;
                break;
            }
        }
    }
    for (uint32_t round = 0; round < ROM_FETCH_VER_ROUNDS; round++) {
        if (atomic_load(&j->abort))
            return false;
        bool any_retryable_miss = false;
        /* Safety valve, evaluated BEFORE the ring so no round is ever spent
         * asking nobody and the retry tolerance is exactly what it was: if
         * every peer still eligible for this chunk has been marked
         * unreachable, forget the marks and dial them all again at full
         * budget. The mask is a cost memory, never a verdict. */
        {
            uint64_t unreach = atomic_load(&j->unreachable);
            bool eligible = false;
            for (size_t k = 0; k < j->npeers && !eligible; k++) {
                if (k < 64 && ((poisoned | unreach) & (1ull << k)))
                    continue;
                eligible = true;
            }
            if (!eligible)
                atomic_store(&j->unreachable, 0);
        }
        for (size_t a = 0; a < j->npeers; a++) {
            if (atomic_load(&j->abort))
                return false;
            size_t pi = (start + a) % j->npeers;
            if (pi < 64 && (poisoned & (1ull << pi)))
                continue; /* served bad content already — never re-fetch it */
            if (pi < 64 && (atomic_load(&j->unreachable) & (1ull << pi))) {
                /* Already paid this peer's full connect budget in this job and
                 * got no socket. Skip, but count it as retryable so the round
                 * cap still governs and the mask can be cleared below. */
                any_retryable_miss = true;
                continue;
            }
            const struct rom_fetch_peer *p = &j->peers[pi];
            uint32_t got = 0;
            enum rf_xchg x = RF_XCHG_BROKEN;
            if (rf_conn_ensure(c, p->addr, p->port))
                x = rf_chunk_exchange(c, j->m.chunk_root, i, buf, &got);
            else if (pi < 64)
                atomic_fetch_or(&j->unreachable, 1ull << pi);
            /* Only a clean, fully-accounted exchange may keep the session. */
            if (x == RF_XCHG_BROKEN)
                rf_conn_drop(c);
            if (x != RF_XCHG_OK || got != want) {
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
    /* This worker's seeder session, carried across chunks. Heap-held: struct
     * fs_session carries a 64 KB receive buffer, which has no business on a
     * worker stack. */
    struct rf_peer_conn *conn = zcl_malloc(sizeof(*conn), "rom_fetch_ver_conn");
    if (!conn) {
        LOG_WARN(RF_SUBSYS, "ver: worker session alloc failed");
        free(buf);
        atomic_store(&j->failed, true);
        atomic_store(&j->abort, true);
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->fd = PLATFORM_SOCKET_INVALID;

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
        if (!rf_ver_acquire_chunk(j, conn, i, want, buf, &got)) {
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
        if (platform_data_sync(j->fd) != 0 || !rom_journal_mark(j->jrnl, i)) {
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
    /* Hand the seeder's serve thread back the moment this worker is done with
     * it — never let a finished/aborted worker leave a session held open. */
    rf_conn_drop(conn);
    free(conn);
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
static RF_MUTATION_ONLY bool rf_download_verified_core(
    const struct rom_fetch_peer *peers,
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

    platform_data_sync(fd);
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
#if defined(_WIN32)
    (void)peer_addr; (void)port; (void)m; (void)chunk_sha3;
    (void)num_chunks; (void)out_dir; (void)cb; (void)cb_ctx;
    errno = ENOTSUP;
    return false;
#else
    if (!peer_addr || !peer_addr[0])
        LOG_FAIL(RF_SUBSYS, "ver: null/empty peer_addr");
    struct rom_fetch_peer p;
    memset(&p, 0, sizeof(p));
    snprintf(p.addr, sizeof(p.addr), "%s", peer_addr);
    p.port = port;
    return rf_download_verified_core(&p, 1, m, chunk_sha3, num_chunks, out_dir,
                                     cb, cb_ctx);
#endif
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
#if defined(_WIN32)
    (void)peers; (void)npeers; (void)m; (void)chunk_sha3;
    (void)num_chunks; (void)out_dir; (void)cb; (void)cb_ctx;
    errno = ENOTSUP;
    return false;
#else
    if (!peers || npeers == 0)
        LOG_FAIL(RF_SUBSYS, "ver-par: null/empty peer list");
    for (size_t i = 0; i < npeers; i++) {
        if (!peers[i].addr[0] || peers[i].port == 0)
            LOG_FAIL(RF_SUBSYS, "ver-par: peer %zu has empty addr/port", i);
    }
    return rf_download_verified_core(peers, npeers, m, chunk_sha3, num_chunks,
                                     out_dir, cb, cb_ctx);
#endif
}
