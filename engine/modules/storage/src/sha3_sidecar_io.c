/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sha3_sidecar_io — see storage/sha3_sidecar_io.h for the contract.
 *
 * This is the single source of truth for the body+sidecar hashing,
 * atomic-write, header-parse, and quarantine logic shared by
 * net/addrman_integrity (peers.dat) and block_index_sidecar_integrity
 * (block_index.bin). Those modules keep their public aii_* / bii_*
 * functions as thin wrappers that pass a `struct ssio_spec`.
 *
 * The streaming hash uses a 1 MiB window so we don't need to mmap or
 * load the whole file. The body files are tiny in practice but the
 * same code path is exercised by tests that synthesise larger inputs.
 */

#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "platform/private_file.h"
#include "storage/sha3_sidecar_io.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Path helpers ───────────────────────────────────────────── */

static void ssio_body_path(char *out, size_t cap,
                           const char *datadir, const struct ssio_spec *spec)
{
    snprintf(out, cap, "%s/%s", datadir, spec->body_name);
}

static void ssio_sidecar_path(char *out, size_t cap,
                              const char *datadir, const struct ssio_spec *spec)
{
    snprintf(out, cap, "%s/%s", datadir, spec->sidecar_name);
}

/* ── Streaming body hash ────────────────────────────────────── */

bool ssio_hash_body(const char *datadir, const struct ssio_spec *spec,
                    uint8_t out_hash[32], uint64_t *out_size)
{
    char body_path[1024];
    ssio_body_path(body_path, sizeof(body_path), datadir, spec);

    FILE *f = fopen(body_path, "rb");
    if (!f) return false;

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    enum { BUF_SIZE = 1u << 20 };  /* 1 MiB */
    uint8_t *buf = zcl_malloc(BUF_SIZE, spec->malloc_label);
    if (!buf) { fclose(f); return false; }

    uint64_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, BUF_SIZE, f)) > 0) {
        sha3_256_write(&ctx, buf, n);
        total += n;
    }
    bool io_err = ferror(f) != 0;
    free(buf);
    fclose(f);
    if (io_err) return false;

    sha3_256_finalize(&ctx, out_hash);
    if (out_size) *out_size = total;
    return true;
}

/* ── Sidecar writer ─────────────────────────────────────────── */

struct zcl_result ssio_write_sidecar_raw(const char *datadir,
                                         const struct ssio_spec *spec,
                                         uint64_t body_size,
                                         const uint8_t body_sha3[32])
{
    if (!datadir) return ZCL_ERR(-1, "%s: null datadir", spec->domain);
    if (!body_sha3) return ZCL_ERR(-1, "%s: null body_sha3", spec->domain);

    char side_path[1024];
    char tmp_path[1056];
    ssio_sidecar_path(side_path, sizeof(side_path), datadir, spec);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", side_path);

    struct ssio_sidecar_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, spec->magic, 4);
    hdr.version = spec->version;
    hdr.body_size = body_size;
    memcpy(hdr.body_sha3, body_sha3, 32);

    (void)platform_private_file_unlink_missing_ok(tmp_path);
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!platform_private_file_create(tmp_path, &staged))
        return ZCL_ERR(-5, "%s: private create %s failed", spec->domain,
                       tmp_path);
    if (!platform_private_file_write_at(&staged, &hdr, sizeof(hdr), 0) ||
        !platform_private_file_truncate(&staged, sizeof(hdr)) ||
        !platform_private_file_flush(&staged)) {
        platform_private_file_close(&staged);
        (void)platform_private_file_unlink_missing_ok(tmp_path);
        return ZCL_ERR(-6, "%s: fwrite failed", spec->domain);
    }
    if (!platform_private_file_replace(&staged, tmp_path, side_path)) {
        platform_private_file_close(&staged);
        struct zcl_result r = ZCL_ERR(-7,
            "%s: atomic replace %s -> %s failed",
            spec->domain, tmp_path, side_path);
        (void)platform_private_file_unlink_missing_ok(tmp_path);
        return r;
    }
    platform_private_file_close(&staged);
    if (!platform_private_parent_flush(datadir))
        return ZCL_ERR(-7, "%s: sidecar parent flush failed", spec->domain);
    return ZCL_OK;
}

struct zcl_result ssio_write_sidecar(const char *datadir,
                                     const struct ssio_spec *spec)
{
    if (!datadir) return ZCL_ERR(-1, "%s: null datadir", spec->domain);

    char body_path[1024];
    ssio_body_path(body_path, sizeof(body_path), datadir, spec);

    struct stat st;
    if (stat(body_path, &st) != 0)
        return ZCL_ERR(-2, "%s: stat %s: %s", spec->domain, body_path,
                       strerror(errno));

    uint8_t body_sha3[32];
    uint64_t hashed_size = 0;
    if (!ssio_hash_body(datadir, spec, body_sha3, &hashed_size))
        return ZCL_ERR(-3, "%s: hash body failed", spec->domain);
    /* stat size and streamed size must agree — disagreement means
     * something is truncating the file concurrently, which is a
     * bigger problem than this function can solve. */
    if (hashed_size != (uint64_t)st.st_size)
        return ZCL_ERR(-4, "%s: size drift stat=%llu hashed=%llu",
                       spec->domain,
                       (unsigned long long)st.st_size,
                       (unsigned long long)hashed_size);

    return ssio_write_sidecar_raw(datadir, spec, hashed_size, body_sha3);
}

/* ── Embedded single-file integrity ─────────────────────────── */

_Static_assert(sizeof(struct ssio_sidecar_header) == SSIO_EMBEDDED_HEADER_BYTES,
               "embedded header must reuse the 48-byte sidecar layout");

struct zcl_result ssio_write_embedded(
    const char *datadir, const struct ssio_spec *spec,
    bool (*emit_payload)(FILE *f, void *ctx,
                         uint64_t *out_payload_size,
                         uint8_t out_payload_sha3[32]),
    void *ctx)
{
    if (!datadir) return ZCL_ERR(-1, "%s: null datadir", spec->domain);
    if (!emit_payload) return ZCL_ERR(-1, "%s: null emit_payload", spec->domain);

    char body_path[1024];
    char tmp_path[1056];
    ssio_body_path(body_path, sizeof(body_path), datadir, spec);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", body_path);
    (void)unlink(tmp_path);

    FILE *f = fopen(tmp_path, "wb");
    if (!f)
        return ZCL_ERR(-5, "%s: fopen %s: %s", spec->domain, tmp_path,
                       strerror(errno));

    /* Reserve the 48-byte header slot; it is back-patched once the
     * payload (and its streamed hash) is known. */
    struct ssio_sidecar_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1) {
        fclose(f); unlink(tmp_path);
        return ZCL_ERR(-6, "%s: header placeholder write failed", spec->domain);
    }

    /* Caller streams the payload AND a SHA3 over exactly those bytes. */
    uint64_t payload_size = 0;
    uint8_t payload_sha3[32];
    if (!emit_payload(f, ctx, &payload_size, payload_sha3)) {
        fclose(f); unlink(tmp_path);
        return ZCL_ERR(-8, "%s: payload emit failed", spec->domain);
    }

    /* Back-patch the real header now that size + hash are known. The
     * digest commits to the PAYLOAD only (everything after offset 48)
     * so a verifier never has to hash the header that carries it. */
    memcpy(hdr.magic, spec->magic, 4);
    hdr.version = spec->version;
    hdr.body_size = payload_size;
    memcpy(hdr.body_sha3, payload_sha3, 32);

    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0 ||
        fwrite(&hdr, sizeof(hdr), 1, f) != 1) {
        fclose(f); unlink(tmp_path);
        return ZCL_ERR(-9, "%s: header back-patch failed: %s",
                       spec->domain, strerror(errno));
    }
    if (fflush(f) != 0) {
        fclose(f); unlink(tmp_path);
        return ZCL_ERR(-9, "%s: header flush failed: %s",
                       spec->domain, strerror(errno));
    }
    int fd = fileno(f);
    if (fd >= 0) (void)platform_file_sync(fd);
    fclose(f);

    /* ONE atomic rename publishes the body + its integrity header as an
     * indivisible unit — no second file, no inter-rename crash window. */
    if (rename(tmp_path, body_path) != 0) {
        struct zcl_result r = ZCL_ERR(-7, "%s: rename %s -> %s: %s",
            spec->domain, tmp_path, body_path, strerror(errno));
        unlink(tmp_path);
        return r;
    }

    /* The embedded header makes the legacy sidecar redundant. REMOVE it
     * (the simpler honest option vs. leaving a dangling file): once the
     * body carries its own integrity, a stale sidecar can only be a
     * source of future confusion, and the verifier checks the embedded
     * header BEFORE the sidecar so it would be ignored anyway. Best
     * effort — its absence is the correct steady state. */
    char side_path[1024];
    ssio_sidecar_path(side_path, sizeof(side_path), datadir, spec);
    (void)unlink(side_path);

    /* fsync the directory so the rename (the file's new identity) and the
     * sidecar removal are durable across power loss. */
#ifdef _WIN32
    (void)platform_private_parent_flush(datadir);
#else
    int dfd = open(datadir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        (void)platform_file_sync(dfd);
        close(dfd);
    }
#endif
    return ZCL_OK;
}

enum ssio_read_verdict ssio_verify_embedded(const char *datadir,
                                            const struct ssio_spec *spec,
                                            struct ssio_sidecar_header *out,
                                            uint64_t *out_payload_off)
{
    char body_path[1024];
    ssio_body_path(body_path, sizeof(body_path), datadir, spec);

    FILE *f = fopen(body_path, "rb");
    if (!f) {
        if (errno == ENOENT) return SSIO_READ_MISSING;
        return SSIO_READ_UNREADABLE;
    }

    /* Magic check FIRST and on the first 4 bytes ONLY: a legacy body
     * (whose first bytes are the "ZCLI" payload magic, not spec->magic,
     * and which may be shorter than the 48-byte header) must return
     * BAD_MAGIC so the caller falls back to the sidecar path — never a
     * short-read STALE that would masquerade as embedded corruption. */
    uint8_t lead4[4];
    if (fread(lead4, 1, 4, f) != 4) {
        fclose(f);
        return SSIO_READ_BAD_MAGIC;  /* too short to be embedded → legacy */
    }
    if (memcmp(lead4, spec->magic, 4) != 0) {
        fclose(f);
        return SSIO_READ_BAD_MAGIC;
    }

    /* Embedded magic confirmed — now the full 48-byte header is required. */
    struct ssio_sidecar_header hdr;
    if (fseek(f, 0, SEEK_SET) != 0 ||
        fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return SSIO_READ_STALE;  /* embedded magic but header truncated */
    }
    if (hdr.version != spec->version) {
        fclose(f);
        return SSIO_READ_UNSUPPORTED;
    }

    /* Re-hash the payload (bytes [48, EOF)) and confirm the on-disk size
     * is exactly header + declared payload — a truncated or extended file
     * is rejected before any payload byte is trusted. */
    struct sha3_256_ctx hctx;
    sha3_256_init(&hctx);

    enum { BUF_SIZE = 1u << 20 };  /* 1 MiB */
    uint8_t *buf = zcl_malloc(BUF_SIZE, spec->malloc_label);
    if (!buf) { fclose(f); return SSIO_READ_UNREADABLE; }

    uint64_t hashed = 0;
    size_t n;
    while ((n = fread(buf, 1, BUF_SIZE, f)) > 0) {
        sha3_256_write(&hctx, buf, n);
        hashed += n;
    }
    bool io_err = ferror(f) != 0;
    free(buf);
    fclose(f);
    if (io_err) return SSIO_READ_UNREADABLE;

    if (hashed != hdr.body_size)
        return SSIO_READ_STALE;  /* declared size != actual payload bytes */

    uint8_t actual[32];
    sha3_256_finalize(&hctx, actual);
    if (memcmp(actual, hdr.body_sha3, 32) != 0)
        return SSIO_READ_STALE;  /* payload corrupted */

    if (out) *out = hdr;
    if (out_payload_off) *out_payload_off = SSIO_EMBEDDED_HEADER_BYTES;
    return SSIO_READ_OK;
}

/* ── Sidecar reader ─────────────────────────────────────────── */

enum ssio_read_verdict ssio_read_sidecar(const char *datadir,
                                         const struct ssio_spec *spec,
                                         struct ssio_sidecar_header *out)
{
    char side_path[1024];
    ssio_sidecar_path(side_path, sizeof(side_path), datadir, spec);

    FILE *f = fopen(side_path, "rb");
    if (!f) {
        if (errno == ENOENT) return SSIO_READ_MISSING;
        return SSIO_READ_UNREADABLE;
    }
    size_t n = fread(out, 1, sizeof(*out), f);
    bool io_err = ferror(f) != 0;
    fclose(f);
    if (io_err || n != sizeof(*out))
        return SSIO_READ_STALE;
    if (memcmp(out->magic, spec->magic, 4) != 0)
        return SSIO_READ_BAD_MAGIC;
    if (out->version != spec->version)
        return SSIO_READ_UNSUPPORTED;
    return SSIO_READ_OK;
}

/* ── Quarantine ─────────────────────────────────────────────── */

static void ssio_rename_if_present(const char *src, int64_t ts,
                                   const char *domain, const char *label)
{
    struct stat st;
    if (stat(src, &st) != 0) return;  /* nothing to do */

    char dst[1200];
    snprintf(dst, sizeof(dst), "%s.corrupt.%lld", src, (long long)ts);
    char tag[64];
    snprintf(tag, sizeof(tag), "%s_quarantine", domain);
    if (rename(src, dst) != 0) {
        LOG_WARN(tag, "%s_quarantine: rename %s -> %s failed: %s",
                 domain, src, dst, strerror(errno));
        return;
    }
    printf("%s: quarantined %s -> %s (%s)\n", domain, src, dst, label);
}

void ssio_quarantine(const char *datadir, const struct ssio_spec *spec,
                     const char *verdict_name)
{
    if (!datadir) return;
    int64_t ts = (int64_t)platform_time_wall_time_t();

    char body_path[1024];
    char side_path[1024];
    ssio_body_path(body_path, sizeof(body_path), datadir, spec);
    ssio_sidecar_path(side_path, sizeof(side_path), datadir, spec);

    ssio_rename_if_present(body_path, ts, spec->domain, verdict_name);
    ssio_rename_if_present(side_path, ts, spec->domain, verdict_name);

    event_emitf(spec->corrupt_event, 0,
                "verdict=%s ts=%lld", verdict_name, (long long)ts);
}
