/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * params_fetch_session.c — the stateful half of proving-parameter
 * acquisition: the resumable download session, and the serve side.
 *
 * Split from params_fetch.c, which owns the trust root (the pin table, the
 * Merkle construction, and the pure "do these bytes match what is compiled
 * in?" predicates). That file can be read without thinking about a
 * filesystem; this one is where those answers get acted on. Nothing here
 * decides what is authentic — it only calls the other half and obeys.
 *
 * Two invariants this file exists to hold:
 *
 *   Nothing a peer sent is written before it is verified. A chunk is hashed
 *   and compared to the verified manifest leaf for its index, and only then
 *   does it reach pwrite. There is no path where unverified bytes touch the
 *   .part file.
 *
 *   Nothing half-finished is visible. The download lands in `<name>.part` in
 *   the same directory as the final file, and is renamed onto `<name>` only
 *   after the assembled bytes re-hash to the pinned SHA-256. The loader can
 *   never observe a partial parameter file.
 */

#include "sapling/params_fetch.h"
#include "params_fetch_internal.h"

#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── Fetch session ──────────────────────────────────────────────────── */

#define ZPART_MAGIC "ZPART001"
#define ZPART_MAGIC_LEN 8

struct zcl_param_fetch {
    int       file_idx;
    char      dir[1024];
    char      part_path[1200];
    char      state_path[1200];
    char      final_path[1200];
    int       part_fd;

    uint32_t  chunk_count;
    uint8_t  *manifest;      /* chunk_count * 32, verified against the pin */
    bool      have_manifest;

    uint8_t  *bitmap;        /* ceil(chunk_count/8) */
    uint32_t  have_count;

    uint8_t  *chunk_buf;     /* ZCL_PARAM_CHUNK_BYTES scratch */
    uint64_t  bytes_rejected;
    size_t    footprint;
};

static size_t bitmap_bytes(uint32_t n) { return (size_t)((n + 7u) / 8u); }
static bool bit_get(const uint8_t *bm, uint32_t i) { return (bm[i >> 3] >> (i & 7u)) & 1u; }
static void bit_set(uint8_t *bm, uint32_t i) { bm[i >> 3] |= (uint8_t)(1u << (i & 7u)); }

static void state_write(struct zcl_param_fetch *s)
{
    /* Best-effort progress hint. Its contents are re-verified on load, so a
     * torn write costs re-downloading, never correctness. Written to a temp
     * name and renamed so a crash mid-write cannot leave a truncated file
     * that looks structurally valid. */
    char tmp[1300];
    snprintf(tmp, sizeof(tmp), "%s.new", s->state_path);
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return;
    const struct zcl_param_pin *p = &zcl_param_pins[s->file_idx];
    uint8_t hdr[ZPART_MAGIC_LEN + 4 + 4 + 8 + ZCL_PARAM_HASH_BYTES];
    memcpy(hdr, ZPART_MAGIC, ZPART_MAGIC_LEN);
    uint32_t fi = (uint32_t)s->file_idx;
    memcpy(hdr + 8, &fi, 4);
    memcpy(hdr + 12, &s->chunk_count, 4);
    memcpy(hdr + 16, &p->bytes, 8);
    uint8_t pinned[ZCL_PARAM_HASH_BYTES];
    if (!zcl_pf_hex_to_32(p->sha256_hex, pinned)) {
        fclose(f);
        unlink(tmp);
        return;
    }
    memcpy(hdr + 24, pinned, ZCL_PARAM_HASH_BYTES);

    bool ok = fwrite(hdr, sizeof(hdr), 1, f) == 1;
    if (ok && s->have_manifest)
        ok = fwrite(s->manifest, (size_t)s->chunk_count * ZCL_PARAM_HASH_BYTES, 1, f) == 1;
    else if (ok) {
        /* No manifest yet: write zeros so the file is a fixed size and the
         * loader's structural check is a pure size comparison. */
        static const uint8_t zero[ZCL_PARAM_HASH_BYTES] = {0};
        for (uint32_t i = 0; ok && i < s->chunk_count; i++)
            ok = fwrite(zero, ZCL_PARAM_HASH_BYTES, 1, f) == 1;
    }
    if (ok)
        ok = fwrite(s->bitmap, bitmap_bytes(s->chunk_count), 1, f) == 1;
    if (ok)
        ok = fflush(f) == 0;
    fclose(f);
    if (ok)
        (void)rename(tmp, s->state_path);
    else
        unlink(tmp);
}

/* Load the state file, then PROVE it: the manifest must re-verify against the
 * compiled-in Merkle root, and every chunk the bitmap claims must re-hash to
 * its manifest leaf. Anything that fails is simply dropped — we keep the
 * chunks that survive and re-fetch the rest. */
static void state_load_and_reverify(struct zcl_param_fetch *s)
{
    const struct zcl_param_pin *p = &zcl_param_pins[s->file_idx];
    size_t bm_len = bitmap_bytes(s->chunk_count);
    size_t man_len = (size_t)s->chunk_count * ZCL_PARAM_HASH_BYTES;
    size_t hdr_len = ZPART_MAGIC_LEN + 4 + 4 + 8 + ZCL_PARAM_HASH_BYTES;
    size_t want_len = hdr_len + man_len + bm_len;

    struct stat st;
    if (stat(s->state_path, &st) != 0 || (size_t)st.st_size != want_len)
        return;

    FILE *f = fopen(s->state_path, "rb");
    if (!f)
        return;

    uint8_t hdr[64];
    bool ok = fread(hdr, hdr_len, 1, f) == 1;
    if (ok)
        ok = memcmp(hdr, ZPART_MAGIC, ZPART_MAGIC_LEN) == 0;
    if (ok) {
        uint32_t fi = 0, cc = 0;
        uint64_t bytes = 0;
        memcpy(&fi, hdr + 8, 4);
        memcpy(&cc, hdr + 12, 4);
        memcpy(&bytes, hdr + 16, 8);
        uint8_t pinned[ZCL_PARAM_HASH_BYTES];
        ok = fi == (uint32_t)s->file_idx && cc == s->chunk_count &&
             bytes == p->bytes && zcl_pf_hex_to_32(p->sha256_hex, pinned) &&
             memcmp(hdr + 24, pinned, ZCL_PARAM_HASH_BYTES) == 0;
    }

    uint8_t *man = NULL, *bm = NULL;
    if (ok) {
        man = zcl_malloc(man_len, "param_state_manifest");
        bm  = zcl_malloc(bm_len, "param_state_bitmap");
        ok = man && bm && fread(man, man_len, 1, f) == 1 &&
             fread(bm, bm_len, 1, f) == 1;
    }
    fclose(f);

    /* The manifest from our own state file gets exactly the same scrutiny a
     * peer's would: fold it and compare to the compiled-in root. */
    if (ok)
        ok = zcl_param_manifest_verify(s->file_idx, man, s->chunk_count);

    if (!ok) {
        free(man);
        free(bm);
        return;
    }

    memcpy(s->manifest, man, man_len);
    s->have_manifest = true;
    free(man);

    /* Re-hash every chunk the bitmap claims. An unclean shutdown can leave
     * the hint ahead of the data, and the cost of believing it wrongly is a
     * silently corrupt proving key. */
    uint32_t confirmed = 0;
    for (uint32_t i = 0; i < s->chunk_count; i++) {
        if (!bit_get(bm, i))
            continue;
        size_t want = zcl_param_chunk_len(s->file_idx, i);
        if (want == 0)
            continue;
        off_t off = (off_t)((uint64_t)i * ZCL_PARAM_CHUNK_BYTES);
        size_t got = 0;
        bool read_ok = true;
        while (got < want) {
            ssize_t r = pread(s->part_fd, s->chunk_buf + got, want - got,
                              off + (off_t)got);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                read_ok = false;
                break;
            }
            if (r == 0) {
                read_ok = false;
                break;
            }
            got += (size_t)r;
        }
        if (!read_ok)
            continue;
        uint8_t leaf[ZCL_PARAM_HASH_BYTES];
        zcl_param_leaf_hash(s->chunk_buf, want, leaf);
        if (!zcl_pf_digest_equal(leaf, s->manifest + (size_t)i * ZCL_PARAM_HASH_BYTES))
            continue;
        bit_set(s->bitmap, i);
        confirmed++;
    }
    s->have_count = confirmed;
    free(bm);

    LOG_INFO("crypto.params",
             "[crypto.params] resuming '%s': %u/%u chunks re-verified from disk",
             p->name, confirmed, s->chunk_count);
}

struct zcl_param_fetch *zcl_param_fetch_open(const char *dir, int file_idx)
{
    if (!zcl_pf_pin_valid(file_idx) || !dir)
        return NULL;
    const struct zcl_param_pin *p = &zcl_param_pins[file_idx];
    uint32_t n = zcl_pf_derived_chunk_count(p);
    if (n == 0 || n != p->chunk_count)
        LOG_NULL("crypto.params",
                        "pinned chunk count for '%s' is inconsistent with its "
                        "pinned length", p->name);

    struct zcl_param_fetch *s = zcl_calloc(1, sizeof(*s), "param_fetch_session");
    if (!s)
        return NULL;
    s->file_idx = file_idx;
    s->chunk_count = n;
    s->part_fd = -1;
    snprintf(s->dir, sizeof(s->dir), "%s", dir);
    zcl_pf_join_path(s->part_path, sizeof(s->part_path), dir, p->name, ".part");
    zcl_pf_join_path(s->state_path, sizeof(s->state_path), dir, p->name, ".zpart");
    zcl_pf_join_path(s->final_path, sizeof(s->final_path), dir, p->name, NULL);

    s->manifest  = zcl_malloc((size_t)n * ZCL_PARAM_HASH_BYTES, "param_manifest");
    s->bitmap    = zcl_calloc(1, bitmap_bytes(n), "param_bitmap");
    s->chunk_buf = zcl_malloc(ZCL_PARAM_CHUNK_BYTES, "param_chunk_buf");
    if (!s->manifest || !s->bitmap || !s->chunk_buf) {
        zcl_param_fetch_close(s);
        return NULL;
    }
    s->footprint = sizeof(*s) + (size_t)n * ZCL_PARAM_HASH_BYTES +
                   bitmap_bytes(n) + ZCL_PARAM_CHUNK_BYTES;

    /* The .part file lives in the same directory as the final file so the
     * rename at the end is same-filesystem and therefore atomic. */
    s->part_fd = open(s->part_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (s->part_fd < 0) {
        LOG_WARN("crypto.params", "[crypto.params] cannot open %s: %s",
                 s->part_path, strerror(errno));
        zcl_param_fetch_close(s);
        return NULL;
    }
    /* Preallocate to the pinned length. Sparse on every filesystem we target;
     * the point is that chunk N's offset is valid before chunk N-1 arrives,
     * which is what lets several peers feed us out of order. */
    if (ftruncate(s->part_fd, (off_t)p->bytes) != 0) {
        LOG_WARN("crypto.params", "[crypto.params] cannot size %s: %s",
                 s->part_path, strerror(errno));
        zcl_param_fetch_close(s);
        return NULL;
    }

    state_load_and_reverify(s);
    return s;
}

bool zcl_param_fetch_set_manifest(struct zcl_param_fetch *s,
                                  const uint8_t *leaves, uint32_t count)
{
    if (!s || !leaves)
        return false;
    if (!zcl_param_manifest_verify(s->file_idx, leaves, count))
        LOG_FAIL("crypto.params",
                        "[crypto.params] refusing manifest for '%s': chunk "
                        "root does not match the compiled-in root",
                        zcl_param_pins[s->file_idx].name);
    size_t len = (size_t)s->chunk_count * ZCL_PARAM_HASH_BYTES;
    if (s->have_manifest) {
        /* Both manifests verified against the same pinned root, so they must
         * be identical; if they are not, one of them broke the Merkle
         * assumption and we keep the one we already proved chunks against. */
        return memcmp(s->manifest, leaves, len) == 0;
    }
    memcpy(s->manifest, leaves, len);
    s->have_manifest = true;
    state_write(s);
    return true;
}

bool zcl_param_fetch_has_manifest(const struct zcl_param_fetch *s)
{
    return s && s->have_manifest;
}

uint32_t zcl_param_fetch_next_needed(const struct zcl_param_fetch *s)
{
    if (!s)
        return UINT32_MAX;
    for (uint32_t i = 0; i < s->chunk_count; i++)
        if (!bit_get(s->bitmap, i))
            return i;
    return UINT32_MAX;
}

uint32_t zcl_param_fetch_pick_missing(const struct zcl_param_fetch *s,
                                      uint32_t after, uint32_t *out,
                                      uint32_t max)
{
    if (!s || !out || max == 0)
        return 0;
    uint32_t w = 0;
    uint32_t start = (after == UINT32_MAX) ? 0 : after;
    for (uint32_t k = 0; k < s->chunk_count && w < max; k++) {
        uint32_t i = (start + k) % s->chunk_count;
        if (!bit_get(s->bitmap, i))
            out[w++] = i;
    }
    return w;
}

enum zcl_param_chunk_result
zcl_param_fetch_accept_chunk(struct zcl_param_fetch *s, uint32_t idx,
                             const uint8_t *data, size_t len)
{
    if (!s || !data)
        return ZCL_PARAM_CHUNK_BAD_INDEX;
    if (!s->have_manifest)
        return ZCL_PARAM_CHUNK_NO_MANIFEST;
    if (idx >= s->chunk_count)
        return ZCL_PARAM_CHUNK_BAD_INDEX;

    /* `len` is hostile. It is compared to the length this index MUST have —
     * derived from the pinned file size — before `data` is read at all. */
    size_t want = zcl_param_chunk_len(s->file_idx, idx);
    if (want == 0 || len != want) {
        s->bytes_rejected += len;
        return ZCL_PARAM_CHUNK_BAD_LENGTH;
    }
    if (bit_get(s->bitmap, idx)) {
        s->bytes_rejected += len;
        return ZCL_PARAM_CHUNK_DUPLICATE;
    }

    uint8_t leaf[ZCL_PARAM_HASH_BYTES];
    zcl_param_leaf_hash(data, len, leaf);
    if (!zcl_pf_digest_equal(leaf, s->manifest + (size_t)idx * ZCL_PARAM_HASH_BYTES)) {
        /* Nothing is written. This is the whole point of the per-chunk
         * check: a hostile peer cannot place one byte it authored into the
         * .part file, no matter how many chunks it sends. */
        s->bytes_rejected += len;
        return ZCL_PARAM_CHUNK_BAD_HASH;
    }

    off_t off = (off_t)((uint64_t)idx * ZCL_PARAM_CHUNK_BYTES);
    size_t done = 0;
    while (done < len) {
        ssize_t w = pwrite(s->part_fd, data + done, len - done, off + (off_t)done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return ZCL_PARAM_CHUNK_IO_ERROR;
        }
        if (w == 0)
            return ZCL_PARAM_CHUNK_IO_ERROR;
        done += (size_t)w;
    }

    bit_set(s->bitmap, idx);
    s->have_count++;
    state_write(s);
    return ZCL_PARAM_CHUNK_OK;
}

uint32_t zcl_param_fetch_chunks_have(const struct zcl_param_fetch *s)
{
    return s ? s->have_count : 0;
}

uint32_t zcl_param_fetch_chunks_total(const struct zcl_param_fetch *s)
{
    return s ? s->chunk_count : 0;
}

uint64_t zcl_param_fetch_bytes_rejected(const struct zcl_param_fetch *s)
{
    return s ? s->bytes_rejected : 0;
}

bool zcl_param_fetch_is_complete(const struct zcl_param_fetch *s)
{
    return s && s->have_manifest && s->have_count == s->chunk_count;
}

size_t zcl_param_fetch_session_footprint(const struct zcl_param_fetch *s)
{
    return s ? s->footprint : 0;
}

bool zcl_param_fetch_finalize(struct zcl_param_fetch *s)
{
    if (!zcl_param_fetch_is_complete(s))
        return false;
    const struct zcl_param_pin *p = &zcl_param_pins[s->file_idx];

    if (fsync(s->part_fd) != 0)
        LOG_FAIL("crypto.params", "[crypto.params] fsync %s: %s",
                        s->part_path, strerror(errno));

    /* Independent whole-file check. Per-chunk verification already proved
     * every byte against the manifest, and the manifest against the pinned
     * Merkle root — but the pinned SHA-256 is the digest that is actually
     * published by the ceremony, so it is the one that gets the last word. */
    uint64_t bytes = 0;
    uint8_t got[ZCL_PARAM_HASH_BYTES], want[ZCL_PARAM_HASH_BYTES];
    if (!zcl_param_pin_recompute_from_file(s->part_path, &bytes, got, NULL))
        LOG_FAIL("crypto.params",
                        "[crypto.params] cannot re-read %s for final check",
                        s->part_path);
    if (bytes != p->bytes || !zcl_pf_hex_to_32(p->sha256_hex, want) ||
        !zcl_pf_digest_equal(got, want))
        LOG_FAIL("crypto.params",
                        "[crypto.params] assembled '%s' does not match its "
                        "pinned SHA-256 — refusing to install; .part kept",
                        p->name);

    if (rename(s->part_path, s->final_path) != 0)
        LOG_FAIL("crypto.params", "[crypto.params] rename %s -> %s: %s",
                        s->part_path, s->final_path, strerror(errno));

    unlink(s->state_path);
    LOG_INFO("crypto.params",
             "[crypto.params] installed '%s' (%llu bytes) — verified against "
             "the compiled-in digest", p->name, (unsigned long long)p->bytes);
    return true;
}

void zcl_param_fetch_close(struct zcl_param_fetch *s)
{
    if (!s)
        return;
    if (s->part_fd >= 0)
        close(s->part_fd);
    free(s->manifest);
    free(s->bitmap);
    free(s->chunk_buf);
    free(s);
}

/* ── Serving ────────────────────────────────────────────────────────── */

struct served_file {
    int      fd;
    uint8_t *manifest;
    uint32_t count;
};

static struct served_file g_served[ZCL_PARAM_FILE_COUNT];
static _Atomic bool g_served_armed[ZCL_PARAM_FILE_COUNT];
static pthread_mutex_t g_serve_lock = PTHREAD_MUTEX_INITIALIZER;

/* Build the manifest for one already-verified local file by streaming it.
 * Expensive (it reads the whole file) and therefore only ever called from
 * zcl_param_serve_prepare, never from a message handler. */
static bool build_served_manifest(const char *path, int file_idx,
                                  uint8_t **out_manifest, uint32_t *out_count)
{
    const struct zcl_param_pin *p = &zcl_param_pins[file_idx];
    uint32_t n = zcl_pf_derived_chunk_count(p);
    if (n == 0)
        return false;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;

    uint8_t *man = zcl_malloc((size_t)n * ZCL_PARAM_HASH_BYTES, "param_serve_manifest");
    uint8_t *buf = zcl_malloc(ZCL_PARAM_CHUNK_BYTES, "param_serve_scratch");
    bool ok = man && buf;
    for (uint32_t i = 0; ok && i < n; i++) {
        size_t want = zcl_param_chunk_len(file_idx, i);
        off_t off = (off_t)((uint64_t)i * ZCL_PARAM_CHUNK_BYTES);
        size_t got = 0;
        while (got < want) {
            ssize_t r = pread(fd, buf + got, want - got, off + (off_t)got);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ok = false;
                break;
            }
            if (r == 0) {
                ok = false;
                break;
            }
            got += (size_t)r;
        }
        if (ok)
            zcl_param_leaf_hash(buf, want, man + (size_t)i * ZCL_PARAM_HASH_BYTES);
    }
    free(buf);

    /* A manifest we are about to hand to strangers must itself fold to the
     * compiled-in root, or our local copy is not the file we think it is. */
    if (ok)
        ok = zcl_param_manifest_verify(file_idx, man, n);

    if (!ok) {
        free(man);
        close(fd);
        return false;
    }
    *out_manifest = man;
    *out_count = n;
    /* fd stays open: pread on a shared descriptor is thread-safe and saves an
     * open() per chunk request. */
    if (g_served[file_idx].fd >= 0)
        close(g_served[file_idx].fd);
    g_served[file_idx].fd = fd;
    return true;
}

int zcl_param_serve_prepare(const char *dir)
{
    if (!dir)
        return 0;
    int armed = 0;
    pthread_mutex_lock(&g_serve_lock);
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++) {
        if (atomic_load(&g_served_armed[i])) {
            armed++;
            continue;
        }
        if (g_served[i].fd == 0)
            g_served[i].fd = -1;
        /* Verify our own copy first. We never serve bytes we have not proved
         * against the pin — a node that quietly relays a corrupt parameter
         * file is worse than a node that serves nothing. */
        if (!zcl_param_verify_installed(dir, i))
            continue;
        char path[1200];
        zcl_pf_join_path(path, sizeof(path), dir, zcl_param_pins[i].name, NULL);
        uint8_t *man = NULL;
        uint32_t n = 0;
        if (!build_served_manifest(path, i, &man, &n))
            continue;
        g_served[i].manifest = man;
        g_served[i].count = n;
        atomic_store(&g_served_armed[i], true);
        armed++;
        LOG_INFO("crypto.params",
                 "[crypto.params] serving '%s' to peers (%u chunks)",
                 zcl_param_pins[i].name, n);
    }
    pthread_mutex_unlock(&g_serve_lock);
    return armed;
}

bool zcl_param_serve_ready(int file_idx)
{
    return zcl_pf_pin_valid(file_idx) && atomic_load(&g_served_armed[file_idx]);
}

bool zcl_param_serve_manifest(int file_idx, uint8_t *out, size_t cap,
                              uint32_t *out_count)
{
    if (!zcl_param_serve_ready(file_idx) || !out)
        return false;
    uint32_t n = g_served[file_idx].count;
    size_t len = (size_t)n * ZCL_PARAM_HASH_BYTES;
    if (cap < len)
        return false;
    memcpy(out, g_served[file_idx].manifest, len);
    if (out_count)
        *out_count = n;
    return true;
}

bool zcl_param_serve_chunk(int file_idx, uint32_t idx, uint8_t *out,
                           size_t cap, size_t *out_len)
{
    if (!zcl_param_serve_ready(file_idx) || !out)
        return false;
    size_t want = zcl_param_chunk_len(file_idx, idx);
    if (want == 0 || cap < want)
        return false;

    int fd = g_served[file_idx].fd;
    if (fd < 0)
        return false;
    off_t off = (off_t)((uint64_t)idx * ZCL_PARAM_CHUNK_BYTES);
    size_t got = 0;
    while (got < want) {
        ssize_t r = pread(fd, out + got, want - got, off + (off_t)got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (r == 0)
            return false;
        got += (size_t)r;
    }
    if (out_len)
        *out_len = want;
    return true;
}

void zcl_param_serve_shutdown(void)
{
    pthread_mutex_lock(&g_serve_lock);
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++) {
        /* Disarm, unpublish, and only then release. A serve path that has
         * already passed the armed check must never be able to reach a
         * pointer or descriptor this loop has freed, so the flag is cleared
         * first and every field is detached before anything is handed back
         * to the allocator or to close(). */
        atomic_store(&g_served_armed[i], false);
        uint8_t *dying = g_served[i].manifest;
        int dying_fd = g_served[i].fd;
        g_served[i].manifest = NULL;
        g_served[i].count = 0;
        g_served[i].fd = -1;
        free(dying);
        if (dying_fd > 0)
            close(dying_fd);
    }
    pthread_mutex_unlock(&g_serve_lock);
}
