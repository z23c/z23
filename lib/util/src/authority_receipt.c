/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_receipt.c — the reusable Law-7 privileged-transition idiom.
 * Contract + threat model: util/authority_receipt.h.
 *
 * Generalizes the four tangled pieces of config/src/consensus_state_replay_receipt.c
 * (running-binary digest, atomic keyed write, exact-length dirfd read, use-time
 * fail-closed authority check) so any new privileged transition — safe hotload,
 * deploy generation publish, signed off-chain contracts — binds authority the
 * same way instead of re-deriving it by hand. The replay receipt's own 344-byte
 * payload is intentionally NOT rewired onto this; it stays behaviorally frozen. */

#include "util/authority_receipt.h"

#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#define AR_SUBSYS "authority_receipt"

_Static_assert(AUTHORITY_RECEIPT_SCHEMA_FIELD + 5u * 32u ==
                   AUTHORITY_RECEIPT_HEADER_BYTES,
               "authority receipt header layout");
_Static_assert(AUTHORITY_RECEIPT_OFF_RECEIPT + 32u ==
                   AUTHORITY_RECEIPT_HEADER_BYTES,
               "authority receipt header offsets");

/* ── Idiom primitive: SHA3-256 of the running executable image ──────────────
 * Race-free direct open of /proc/self/exe (a path readlink reintroduces
 * TOCTOU); byte-identical to consensus_state_replay_receipt.c's original. */
bool authority_receipt_running_binary_digest(uint8_t out[32])
{
    if (!out)
        return false;
    char path[32768];
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!os_proc_exe_path(path, sizeof(path)) ||
        !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        LOG_WARN(AR_SUBSYS, "running executable validated open failed");
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buffer[32768];
    bool ok = true;
    uint64_t offset = 0;
    while (offset < before.size) {
        size_t wanted = before.size - offset > sizeof(buffer)
                            ? sizeof(buffer) : (size_t)(before.size - offset);
        int64_t n = platform_positioned_file_read(&file, buffer, wanted,
                                                   offset);
        if (n <= 0) { ok = false; break; }
        sha3_256_write(&ctx, buffer, (size_t)n);
        offset += (uint64_t)n;
    }
    ok = ok && offset == before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        before.size == after.size && before.volume == after.volume &&
        before.file_low == after.file_low && before.file_high == after.file_high &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!ok)
        LOG_FAIL(AR_SUBSYS, "running executable digest failed");
    sha3_256_finalize(&ctx, out);
    return true;
}

/* ── Idiom primitive: atomic keyed write ───────────────────────────────────
 * tmp -> fsync(file) -> rename -> fsync(dir), under `datadir`, keyed on `name`. */
bool authority_receipt_write_atomic(const char *datadir, const char *name,
                                    const uint8_t *payload, size_t len,
                                    char *final_out, size_t final_cap)
{
    if (!datadir || !datadir[0] || !name || !name[0] || !payload || len == 0)
        LOG_FAIL(AR_SUBSYS, "invalid write args");

#if defined(_WIN32)
    if (strchr(name, '/') || strchr(name, '\\') || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0)
        LOG_FAIL(AR_SUBSYS, "invalid receipt child name");
    uintptr_t directory = 0;
    if (!platform_private_directory_open_validated(datadir, &directory))
        LOG_FAIL(AR_SUBSYS, "private datadir validation failed");
    char final_path[32768], tmp_path[32768], resolved[32768], parent[32768];
    int fn = snprintf(final_path, sizeof(final_path), "%s/%s", datadir, name);
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp", datadir, name);
    struct platform_private_file staged;
    platform_private_file_init(&staged);
    bool ok = fn > 0 && (size_t)fn < sizeof(final_path) && tn > 0 &&
        (size_t)tn < sizeof(tmp_path) &&
        platform_private_path_resolve(final_path, resolved, sizeof(resolved),
                                      parent, sizeof(parent)) &&
        platform_private_file_create(tmp_path, &staged) &&
        platform_private_file_write_at(&staged, payload, len, 0) &&
        platform_private_file_flush(&staged) &&
        platform_private_file_replace(&staged, tmp_path, resolved) &&
        platform_private_parent_flush(parent);
    if (!ok && staged.native != (uintptr_t)-1) {
        (void)platform_private_file_retire(&staged, tmp_path);
        platform_private_file_close(&staged);
    }
    platform_private_directory_close(directory);
    if (!ok) LOG_FAIL(AR_SUBSYS, "durable receipt publication failed");
    if (final_out && final_cap > 0)
        snprintf(final_out, final_cap, "%s", resolved);
    return true;
#else
    char final_path[PATH_MAX], tmp_path[PATH_MAX];
    int fn = snprintf(final_path, sizeof(final_path), "%s/%s", datadir, name);
    if (fn <= 0 || (size_t)fn >= sizeof(final_path))
        LOG_FAIL(AR_SUBSYS, "receipt final path too long");
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%ld", datadir,
                      name, (long)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp_path))
        LOG_FAIL(AR_SUBSYS, "receipt tmp path too long");

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(AR_SUBSYS, "receipt tmp open failed: %s", strerror(errno));

    bool ok = true;
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, payload + written, len - written);
        if (w > 0) {
            written += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        ok = false;
        break;
    }
    if (ok && fsync(fd) != 0)
        ok = false;
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp_path, final_path) != 0) {
        LOG_WARN(AR_SUBSYS, "receipt rename failed: %s", strerror(errno));
        ok = false;
    }
    if (!ok) {
        (void)unlink(tmp_path);
        LOG_FAIL(AR_SUBSYS, "receipt persist (fsync'd) failed");
    }
    int dir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd >= 0) {
        (void)fsync(dir_fd);
        (void)close(dir_fd);
    }
    if (final_out && final_cap > 0)
        snprintf(final_out, final_cap, "%s", final_path);
    return true;
#endif
}

/* ── Idiom primitive: exact-length read through a datadir capability fd ──────
 * openat O_NOFOLLOW; returns true iff EXACTLY `len` bytes were present (a longer
 * OR shorter file is rejected). Pathnames are locators, never authority. */
bool authority_receipt_read_fixed(int datadir_fd, const char *name,
                                  uint8_t *out, size_t len)
{
#if defined(_WIN32)
    (void)datadir_fd; (void)name; (void)out; (void)len;
    return false;
#else
    if (datadir_fd < 0 || !name || !name[0] || !out || len == 0)
        return false;
    int fd = openat(datadir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;

    size_t got = 0;
    bool ok = true;
    while (got < len) {
        ssize_t n = read(fd, out + got, len - got);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            ok = false;
        break; /* EOF (short file) or read error */
    }
    /* Exactly `len` — a longer file is not our canonical receipt. */
    bool extra = false;
    if (ok && got == len) {
        for (;;) {
            uint8_t scratch;
            ssize_t n = read(fd, &scratch, 1);
            if (n > 0) {
                extra = true;
                break;
            }
            if (n < 0 && errno == EINTR)
                continue;
            break; /* EOF (exact length) or error */
        }
    }
    (void)close(fd);
    return ok && got == len && !extra;
#endif
}

/* ── Canonical HEADER: domain-separated self-binding digest ─────────────────
 * domain tag = schema followed by the literal "/binding"; then the fixed 48-byte
 * schema field + the four 32-byte digests (artifact, anchor, detail, verifier). */
void authority_receipt_header_digest(const struct authority_receipt_header *h,
                                     uint8_t out[32])
{
    if (!h || !out)
        return;
    size_t sl = strnlen(h->schema, AUTHORITY_RECEIPT_SCHEMA_FIELD);
    uint8_t domain[AUTHORITY_RECEIPT_SCHEMA_FIELD + 8];
    memcpy(domain, h->schema, sl);
    memcpy(domain + sl, "/binding", 8);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sl + 8);
    sha3_256_write(&ctx, (const uint8_t *)h->schema,
                   AUTHORITY_RECEIPT_SCHEMA_FIELD);
    sha3_256_write(&ctx, h->artifact_digest, 32);
    sha3_256_write(&ctx, h->context_anchor, 32);
    sha3_256_write(&ctx, h->detail_digest, 32);
    sha3_256_write(&ctx, h->verifier_binary_digest, 32);
    sha3_256_finalize(&ctx, out);
}

void authority_receipt_header_serialize(
    const struct authority_receipt_header *h,
    uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES])
{
    if (!h || !buf)
        return;
    memset(buf, 0, AUTHORITY_RECEIPT_HEADER_BYTES);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_SCHEMA, h->schema,
           AUTHORITY_RECEIPT_SCHEMA_FIELD);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_ARTIFACT, h->artifact_digest, 32);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_ANCHOR, h->context_anchor, 32);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_DETAIL, h->detail_digest, 32);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_VERIFIER, h->verifier_binary_digest, 32);
    memcpy(buf + AUTHORITY_RECEIPT_OFF_RECEIPT, h->receipt_digest, 32);
}

bool authority_receipt_header_deserialize(
    const uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES],
    struct authority_receipt_header *h)
{
    if (!buf || !h)
        return false;
    /* The schema field MUST be a non-empty NUL-terminated tag within 48 bytes. */
    size_t sl = strnlen((const char *)(buf + AUTHORITY_RECEIPT_OFF_SCHEMA),
                        AUTHORITY_RECEIPT_SCHEMA_FIELD);
    if (sl == 0 || sl >= AUTHORITY_RECEIPT_SCHEMA_FIELD)
        return false;

    struct authority_receipt_header t;
    memset(&t, 0, sizeof(t));
    memcpy(t.schema, buf + AUTHORITY_RECEIPT_OFF_SCHEMA,
           AUTHORITY_RECEIPT_SCHEMA_FIELD);
    memcpy(t.artifact_digest, buf + AUTHORITY_RECEIPT_OFF_ARTIFACT, 32);
    memcpy(t.context_anchor, buf + AUTHORITY_RECEIPT_OFF_ANCHOR, 32);
    memcpy(t.detail_digest, buf + AUTHORITY_RECEIPT_OFF_DETAIL, 32);
    memcpy(t.verifier_binary_digest, buf + AUTHORITY_RECEIPT_OFF_VERIFIER, 32);
    memcpy(t.receipt_digest, buf + AUTHORITY_RECEIPT_OFF_RECEIPT, 32);

    uint8_t recomputed[32];
    authority_receipt_header_digest(&t, recomputed);
    if (memcmp(recomputed, t.receipt_digest, 32) != 0)
        return false; /* byte-level tampering caught here */
    *h = t;
    return true;
}

bool authority_receipt_header_seal_and_write(struct authority_receipt_header *h,
                                             const char *datadir,
                                             const char *name, char *final_out,
                                             size_t final_cap)
{
    if (!h || !datadir || !name)
        LOG_FAIL(AR_SUBSYS, "NULL seal args");
    size_t sl = strnlen(h->schema, AUTHORITY_RECEIPT_SCHEMA_FIELD);
    if (sl == 0 || sl >= AUTHORITY_RECEIPT_SCHEMA_FIELD)
        LOG_FAIL(AR_SUBSYS, "schema tag must be a non-empty NUL-terminated "
                            "string within %u bytes",
                 AUTHORITY_RECEIPT_SCHEMA_FIELD);
    if (!authority_receipt_running_binary_digest(h->verifier_binary_digest))
        LOG_FAIL(AR_SUBSYS, "verifying-binary digest failed");
    authority_receipt_header_digest(h, h->receipt_digest);

    uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES];
    authority_receipt_header_serialize(h, buf);
    if (!authority_receipt_write_atomic(datadir, name, buf,
                                        AUTHORITY_RECEIPT_HEADER_BYTES,
                                        final_out, final_cap))
        return false; /* write_atomic already logged the failure */
    return true;
}

bool authority_receipt_header_authority_available(
    int datadir_fd, const char *name, const char *expect_schema,
    const uint8_t expect_artifact[32], const uint8_t expect_context_anchor[32],
    const uint8_t expect_detail_digest[32])
{
    if (datadir_fd < 0 || !name || !expect_schema || !expect_artifact ||
        !expect_context_anchor || !expect_detail_digest)
        return false;

    uint8_t buf[AUTHORITY_RECEIPT_HEADER_BYTES];
    if (!authority_receipt_read_fixed(datadir_fd, name, buf,
                                      AUTHORITY_RECEIPT_HEADER_BYTES)) {
        LOG_WARN(AR_SUBSYS, "no valid authority receipt '%s'; transition stays "
                            "contained",
                 name);
        return false;
    }

    struct authority_receipt_header r;
    if (!authority_receipt_header_deserialize(buf, &r)) {
        LOG_WARN(AR_SUBSYS, "authority receipt '%s' failed self-binding; "
                            "transition stays contained",
                 name);
        return false;
    }

    /* The transitioning binary must be the exact image that verified. */
    uint8_t running[32];
    if (!authority_receipt_running_binary_digest(running) ||
        memcmp(running, r.verifier_binary_digest, 32) != 0) {
        LOG_WARN(AR_SUBSYS, "authority receipt '%s' was written by a different "
                            "binary image; transition stays contained",
                 name);
        return false;
    }

    size_t esl = strlen(expect_schema);
    if (esl >= AUTHORITY_RECEIPT_SCHEMA_FIELD ||
        strncmp(r.schema, expect_schema, AUTHORITY_RECEIPT_SCHEMA_FIELD) != 0 ||
        memcmp(r.artifact_digest, expect_artifact, 32) != 0 ||
        memcmp(r.context_anchor, expect_context_anchor, 32) != 0 ||
        memcmp(r.detail_digest, expect_detail_digest, 32) != 0) {
        LOG_WARN(AR_SUBSYS, "authority receipt '%s' does not bind THIS "
                            "schema/artifact/anchor/detail; transition stays "
                            "contained",
                 name);
        return false;
    }
    return true;
}
