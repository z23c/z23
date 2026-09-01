/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_authority_receipt — the reusable Law-7 privileged-transition idiom.
 * Proves the four idiom pieces and the canonical header contract: a receipt
 * round-trips, the exact-length dirfd read rejects a longer/shorter file, a
 * sealed header verifies only for THIS binary + schema/artifact/anchor/detail,
 * and a foreign-binary / tampered / missing receipt is refused (fail closed). */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "util/authority_receipt.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AR_CHECK(label, expr) do {                       \
    printf("authority_receipt: %s... ", (label));        \
    if (expr) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static void ar_fill(struct authority_receipt_header *h, const char *schema,
                    uint8_t a, uint8_t c, uint8_t d)
{
    memset(h, 0, sizeof(*h));
    snprintf(h->schema, sizeof(h->schema), "%s", schema);
    memset(h->artifact_digest, a, 32);
    memset(h->context_anchor, c, 32);
    memset(h->detail_digest, d, 32);
}

/* Overwrite one on-disk byte of the keyed receipt file (tamper injection). */
static bool ar_flip_byte(const char *dir, const char *name, off_t off)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) <= 0)
        return false;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    uint8_t b = 0;
    bool ok = pread(fd, &b, 1, off) == 1;
    b = (uint8_t)(b ^ 0xFF);
    ok = ok && pwrite(fd, &b, 1, off) == 1;
    (void)close(fd);
    return ok;
}

int test_authority_receipt(void)
{
    int failures = 0;

    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof(dir), "authority_receipt", "main");
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    AR_CHECK("open datadir capability fd", dirfd >= 0);

    /* ── 1. Raw keyed write/read round-trips exact bytes. ── */
    uint8_t payload[97];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)(i * 7u + 3u);
    AR_CHECK("write_atomic persists a keyed payload",
             authority_receipt_write_atomic(dir, "rt.bin", payload,
                                            sizeof(payload), NULL, 0));
    uint8_t got[97];
    memset(got, 0, sizeof(got));
    AR_CHECK("read_fixed returns the same bytes",
             authority_receipt_read_fixed(dirfd, "rt.bin", got,
                                          sizeof(payload)) &&
                 memcmp(got, payload, sizeof(payload)) == 0);

    /* ── 2. Exact-length rule: a longer OR shorter file is rejected. ── */
    AR_CHECK("read_fixed rejects a shorter-than-expected read",
             !authority_receipt_read_fixed(dirfd, "rt.bin", got,
                                           sizeof(payload) + 1));
    AR_CHECK("read_fixed rejects a longer-than-expected read",
             !authority_receipt_read_fixed(dirfd, "rt.bin", got,
                                           sizeof(payload) - 1));
    AR_CHECK("read_fixed refuses a missing file",
             !authority_receipt_read_fixed(dirfd, "nope.bin", got, 16));

    /* ── 3. Header seal + use-time authority: the positive path. ── */
    const char *schema = "zcl.test_authority.v1";
    struct authority_receipt_header h;
    ar_fill(&h, schema, 0x11, 0x22, 0x33);
    AR_CHECK("seal_and_write binds the running binary + persists",
             authority_receipt_header_seal_and_write(&h, dir, "auth.receipt",
                                                     NULL, 0));
    uint8_t art[32], ctx[32], det[32];
    memset(art, 0x11, 32);
    memset(ctx, 0x22, 32);
    memset(det, 0x33, 32);
    AR_CHECK("authority_available == true for THIS binary + bound values",
             authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", schema, art, ctx, det));

    /* Any single flipped EXPECTED input refuses. */
    uint8_t bad[32];
    memset(bad, 0x99, 32);
    AR_CHECK("refuses a wrong expected artifact",
             !authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", schema, bad, ctx, det));
    AR_CHECK("refuses a wrong expected anchor",
             !authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", schema, art, bad, det));
    AR_CHECK("refuses a wrong expected detail",
             !authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", schema, art, ctx, bad));
    AR_CHECK("refuses a wrong expected schema",
             !authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", "zcl.other.v1", art, ctx, det));

    /* ── 3b. Tampered artifact byte on disk → self-binding catches it. ── */
    AR_CHECK("flip one on-disk artifact byte",
             ar_flip_byte(dir, "auth.receipt",
                          (off_t)AUTHORITY_RECEIPT_OFF_ARTIFACT));
    AR_CHECK("refuses a tampered receipt (self-binding digest mismatch)",
             !authority_receipt_header_authority_available(
                 dirfd, "auth.receipt", schema, art, ctx, det));

    /* ── 4. Foreign binary: a self-consistent receipt whose verifier digest is
     *      NOT the running image is refused. Build one by hand: fill fields,
     *      set a foreign verifier digest, compute a VALID self-binding over it,
     *      serialize, and write it raw. ── */
    struct authority_receipt_header f;
    ar_fill(&f, schema, 0x44, 0x55, 0x66);
    memset(f.verifier_binary_digest, 0xAB, 32); /* not the running binary */
    authority_receipt_header_digest(&f, f.receipt_digest);
    uint8_t fbuf[AUTHORITY_RECEIPT_HEADER_BYTES];
    authority_receipt_header_serialize(&f, fbuf);
    AR_CHECK("write a self-consistent foreign-binary receipt",
             authority_receipt_write_atomic(dir, "foreign.receipt", fbuf,
                                            sizeof(fbuf), NULL, 0));
    uint8_t fart[32], fctx[32], fdet[32];
    memset(fart, 0x44, 32);
    memset(fctx, 0x55, 32);
    memset(fdet, 0x66, 32);
    AR_CHECK("refuses a receipt written by a foreign binary image",
             !authority_receipt_header_authority_available(
                 dirfd, "foreign.receipt", schema, fart, fctx, fdet));

    /* ── 5. Missing receipt in a fresh datadir → fail closed. ── */
    char dir2[PATH_MAX];
    test_make_tmpdir(dir2, sizeof(dir2), "authority_receipt", "empty");
    int dirfd2 = open(dir2, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    AR_CHECK("open a fresh empty datadir fd", dirfd2 >= 0);
    AR_CHECK("refuses when no receipt exists (fail closed)",
             !authority_receipt_header_authority_available(
                 dirfd2, "auth.receipt", schema, art, ctx, det));

    /* ── 6. Running-binary digest is stable and non-zero. ── */
    uint8_t r1[32], r2[32], zero[32];
    memset(zero, 0, 32);
    bool det_ok = authority_receipt_running_binary_digest(r1) &&
                  authority_receipt_running_binary_digest(r2) &&
                  memcmp(r1, r2, 32) == 0 && memcmp(r1, zero, 32) != 0;
    AR_CHECK("running-binary digest is deterministic and non-zero", det_ok);

    if (dirfd >= 0)
        close(dirfd);
    if (dirfd2 >= 0)
        close(dirfd2);
    test_rm_rf_recursive(dir);
    test_rm_rf_recursive(dir2);
    return failures;
}
