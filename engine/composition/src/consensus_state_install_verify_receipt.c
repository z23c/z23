/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contract + threat model: config/consensus_state_install_verify_receipt.h. */

#include "config/consensus_state_install_verify_receipt.h"

#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "platform/file_sync.h"
#include "platform/positioned_file.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#define IVR_SUBSYS "install_verify_receipt"

/* version(4) + bundle_sha3_256(32) + verifier_epoch(32) + verified_at_us(8) +
 * self_digest(32). Fixed-size, little-endian; self-verifying so a truncated
 * or bit-flipped record is detected as "no receipt", never trusted. */
#define IVR_OFF_VERSION   0u
#define IVR_OFF_BUNDLE    4u
#define IVR_OFF_EPOCH     36u
#define IVR_OFF_TIME      68u
#define IVR_OFF_DIGEST    76u
#define IVR_WIRE_SIZE     108u
#define IVR_VERSION       1u

#ifndef _WIN32
static _Atomic uint64_t g_temp_nonce;
#endif

static bool valid_dir_fd(int dir_fd)
{
    return dir_fd >= 0;
}

static bool receipt_args_valid(int dir_fd, const uint8_t bundle_sha3_256[32],
                               const uint8_t verifier_epoch[32])
{
    return valid_dir_fd(dir_fd) && bundle_sha3_256 && verifier_epoch;
}

#ifndef _WIN32
static void put_u32(uint8_t *b, size_t o, uint32_t v)
{
    for (size_t i = 0; i < 4; i++)
        b[o + i] = (uint8_t)(v >> (8u * i));
}
#endif

static uint32_t get_u32(const uint8_t *b, size_t o)
{
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++)
        v |= (uint32_t)b[o + i] << (8u * i);
    return v;
}

#ifndef _WIN32
static void put_u64(uint8_t *b, size_t o, uint64_t v)
{
    for (size_t i = 0; i < 8; i++)
        b[o + i] = (uint8_t)(v >> (8u * i));
}
#endif

static uint64_t get_u64(const uint8_t *b, size_t o)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)b[o + i] << (8u * i);
    return v;
}

static void ivr_digest(const uint8_t *wire_without_digest, uint8_t out[32])
{
    static const char domain[] =
        "zcl.consensus_state_install_verify_receipt.v1/record";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&ctx, wire_without_digest, IVR_OFF_DIGEST);
    sha3_256_finalize(&ctx, out);
}

#ifndef _WIN32
static void encode(const uint8_t bundle_sha3_256[32],
                   const uint8_t verifier_epoch[32], int64_t verified_at_us,
                   uint8_t out[IVR_WIRE_SIZE])
{
    memset(out, 0, IVR_WIRE_SIZE);
    put_u32(out, IVR_OFF_VERSION, IVR_VERSION);
    memcpy(out + IVR_OFF_BUNDLE, bundle_sha3_256, 32);
    memcpy(out + IVR_OFF_EPOCH, verifier_epoch, 32);
    put_u64(out, IVR_OFF_TIME, (uint64_t)verified_at_us);
    uint8_t digest[32];
    ivr_digest(out, digest);
    memcpy(out + IVR_OFF_DIGEST, digest, 32);
}

static bool write_all(int fd, const uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return false; /* raw-return-ok:short-write-reported-by-caller */
    }
    return true;
}
#endif

#ifndef _WIN32
/* Read-status codes from read_receipt_wire(); the caller logs per code so
 * every message keeps its exact wording and this file's function names. */
enum {
    IVR_READ_OK = 0,
    IVR_READ_OPEN_FAILED,
    IVR_READ_MALFORMED
};

/* Opens the receipt under dir_fd, reads up to the wire buffer size and
 * closes it. errno is left as set by openat when IVR_READ_OPEN_FAILED is
 * returned; *out_off always carries the bytes read otherwise. */
static int read_receipt_wire(int dir_fd, uint8_t wire[IVR_WIRE_SIZE + 1],
                             size_t *out_off)
{
    int fd = openat(dir_fd, CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_NAME,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return IVR_READ_OPEN_FAILED;
    size_t off = 0;
    bool read_ok = true;
    while (off < IVR_WIRE_SIZE + 1) {
        ssize_t r = read(fd, wire + off, (IVR_WIRE_SIZE + 1) - off);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            read_ok = false;
        break;
    }
    (void)close(fd);
    *out_off = off;
    if (!read_ok || off != IVR_WIRE_SIZE)
        return IVR_READ_MALFORMED;
    return IVR_READ_OK;
}

/* Check-status codes from check_receipt_wire(); the caller logs per code. */
enum {
    IVR_CHECK_OK = 0,
    IVR_CHECK_BAD_VERSION,
    IVR_CHECK_BAD_DIGEST,
    IVR_CHECK_DIFFERENT_KEY
};

/* Validates version, self-digest and bundle/epoch identity of a wire
 * record that already passed the size check. */
static int check_receipt_wire(const uint8_t wire[IVR_WIRE_SIZE],
                              const uint8_t bundle_sha3_256[32],
                              const uint8_t verifier_epoch[32])
{
    if (get_u32(wire, IVR_OFF_VERSION) != IVR_VERSION)
        return IVR_CHECK_BAD_VERSION;
    uint8_t expected_digest[32];
    ivr_digest(wire, expected_digest);
    if (memcmp(expected_digest, wire + IVR_OFF_DIGEST, 32) != 0)
        return IVR_CHECK_BAD_DIGEST;
    if (memcmp(wire + IVR_OFF_BUNDLE, bundle_sha3_256, 32) != 0 ||
        memcmp(wire + IVR_OFF_EPOCH, verifier_epoch, 32) != 0)
        return IVR_CHECK_DIFFERENT_KEY;
    return IVR_CHECK_OK;
}

/* Age of a validated wire record, clamped at zero for clock skew. */
static int64_t receipt_age_us(const uint8_t wire[IVR_WIRE_SIZE])
{
    int64_t verified_at_us = (int64_t)get_u64(wire, IVR_OFF_TIME);
    int64_t age_us = GetTimeMicros() - verified_at_us;
    if (age_us < 0)
        age_us = 0;
    return age_us;
}
#endif

bool consensus_state_install_verify_receipt_lookup(
    int dir_fd, const uint8_t bundle_sha3_256[32],
    const uint8_t verifier_epoch[32], int64_t *out_age_us)
{
    if (out_age_us)
        *out_age_us = 0;
    if (!receipt_args_valid(dir_fd, bundle_sha3_256, verifier_epoch))
        return false; /* raw-return-ok:no-receipt-store-available */

#ifdef _WIN32
    /* A POSIX integer dirfd cannot carry a Windows directory HANDLE. Native
     * callers must use lookup_root(), which performs handle-bound reads. */
    return false;
#else

    uint8_t wire[IVR_WIRE_SIZE + 1];
    size_t off = 0;
    int read_status = read_receipt_wire(dir_fd, wire, &off);
    if (read_status == IVR_READ_OPEN_FAILED) {
        /* ENOENT is the ordinary "never verified this datadir before" case
         * and is not worth logging; anything else (permissions, etc.) is
         * still fail-soft to a full verify, logged once for visibility. */
        if (errno != ENOENT)
            LOG_WARN(IVR_SUBSYS,
                     "receipt open failed (falling back to full verify): %s",
                     strerror(errno));
        return false; /* raw-return-ok:no-receipt-fail-soft */
    }
    if (read_status == IVR_READ_MALFORMED) {
        LOG_WARN(IVR_SUBSYS,
                 "receipt is unreadable/malformed (falling back to full "
                 "verify): bytes=%zu", off);
        return false; /* raw-return-ok:corrupt-receipt-fail-soft */
    }
    int check_status = check_receipt_wire(wire, bundle_sha3_256,
                                          verifier_epoch);
    if (check_status == IVR_CHECK_BAD_VERSION) {
        LOG_WARN(IVR_SUBSYS,
                 "receipt has an unknown version (falling back to full "
                 "verify)");
        return false; /* raw-return-ok:unknown-version-fail-soft */
    }
    if (check_status == IVR_CHECK_BAD_DIGEST) {
        LOG_WARN(IVR_SUBSYS,
                 "receipt failed self-digest verification (falling back to "
                 "full verify)");
        return false; /* raw-return-ok:tampered-receipt-fail-soft */
    }
    if (check_status == IVR_CHECK_DIFFERENT_KEY) {
        LOG_INFO(IVR_SUBSYS,
                 "receipt is for a different bundle hash or verifier build "
                 "epoch; content will be verified in full");
        return false; /* raw-return-ok:different-key-fail-soft */
    }
    int64_t age_us = receipt_age_us(wire);
    if (out_age_us)
        *out_age_us = age_us;
    return true;
#endif
}

#ifndef _WIN32
/* Temp-creation status codes from create_receipt_temp(); the caller logs
 * per code so every message keeps its exact wording. */
enum {
    IVR_TEMP_OK = 0,
    IVR_TEMP_NAME_OVERFLOW,
    IVR_TEMP_OPEN_FAILED,
    IVR_TEMP_EXHAUSTED
};

/* Creates the O_EXCL temp receipt next to the final name, retrying the
 * nonce suffix on EEXIST. On IVR_TEMP_OK, *out_fd holds the open fd and tmp
 * the chosen name; errno is kept for IVR_TEMP_OPEN_FAILED. */
static int create_receipt_temp(int dir_fd, char *tmp, size_t tmp_size,
                               int *out_fd)
{
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(&g_temp_nonce, 1,
                                                    memory_order_relaxed);
        int n = snprintf(tmp, tmp_size, "%s.tmp.%ld.%016llx",
                         CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_NAME,
                         (long)getpid(), (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= tmp_size)
            return IVR_TEMP_NAME_OVERFLOW;
        int fd = openat(dir_fd, tmp,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
        if (fd >= 0) {
            *out_fd = fd;
            return IVR_TEMP_OK;
        }
        if (errno != EEXIST)
            return IVR_TEMP_OPEN_FAILED;
    }
    return IVR_TEMP_EXHAUSTED;
}

/* Removes the temp receipt when nothing was renamed into place. */
static void discard_unrenamed_temp(int dir_fd, const char *tmp, bool ok,
                                   bool renamed)
{
    if (!ok && !renamed) {
        (void)unlinkat(dir_fd, tmp, 0);
        (void)fsync(dir_fd);
    }
}
#endif

void consensus_state_install_verify_receipt_store(
    int dir_fd, const uint8_t bundle_sha3_256[32],
    const uint8_t verifier_epoch[32])
{
    if (!receipt_args_valid(dir_fd, bundle_sha3_256, verifier_epoch))
        return;
#ifdef _WIN32
    LOG_WARN(IVR_SUBSYS,
             "receipt store refused: Windows directory-handle atomic "
             "replacement is not yet qualified");
    return;
#else
    uint8_t wire[IVR_WIRE_SIZE];
    encode(bundle_sha3_256, verifier_epoch, GetTimeMicros(), wire);

    char tmp[128];
    int fd = -1;
    int temp_status = create_receipt_temp(dir_fd, tmp, sizeof(tmp), &fd);
    if (temp_status == IVR_TEMP_NAME_OVERFLOW) {
        LOG_WARN(IVR_SUBSYS, "receipt store: temp name overflow");
        return;
    }
    if (temp_status == IVR_TEMP_OPEN_FAILED) {
        LOG_WARN(IVR_SUBSYS, "receipt store: openat temp failed: %s",
                 strerror(errno));
        return;
    }
    if (temp_status == IVR_TEMP_EXHAUSTED) {
        LOG_WARN(IVR_SUBSYS, "receipt store: could not allocate a temp name");
        return;
    }
    bool ok = write_all(fd, wire, sizeof(wire));
    if (ok && platform_data_sync(fd) != 0) {
        ok = false;
        LOG_WARN(IVR_SUBSYS, "receipt store: data sync failed: %s",
                 strerror(errno));
    }
    if (close(fd) != 0) {
        ok = false;
        LOG_WARN(IVR_SUBSYS, "receipt store: close failed: %s",
                 strerror(errno));
    }
    bool renamed = false;
    if (ok && renameat(dir_fd, tmp, dir_fd,
                       CONSENSUS_STATE_INSTALL_VERIFY_RECEIPT_NAME) != 0) {
        ok = false;
        LOG_WARN(IVR_SUBSYS, "receipt store: renameat into place failed: %s",
                 strerror(errno));
    } else if (ok) {
        renamed = true;
    }
    if (ok && fsync(dir_fd) != 0)
        LOG_WARN(IVR_SUBSYS, "receipt store: directory fsync failed: %s",
                 strerror(errno));
    discard_unrenamed_temp(dir_fd, tmp, ok, renamed);
    if (ok)
        LOG_INFO(IVR_SUBSYS,
                 "content-verify receipt persisted; a byte-identical bundle "
                 "under this exact binary will skip the deep content scan");
#endif
}
