/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Fresh isolated guests with fixed PUBLIC credentials and bounded execution. */
#include "test/test_core.h"
#include "test/test_timing_budget.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "platform/clock.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/spawn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#define GV_BYTES (UINT64_C(16) << 20)
#define GV_DATA_BYTE UINT64_C(544)
#define GMB_SB_DATA_BYTE UINT64_C(73760)

/* Per-child wall cap in ms. Set from the load-scaled budget in the test body;
 * 120 s is the idle-host nominal (see the deadline derivation there). */
static int g_gv_child_cap_ms = 120000;

static bool gv_hash(const char *path, char hex[65])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
        platform_positioned_file_snapshot(&file, &before) && before.size == GV_BYTES;
    struct sha256_ctx sha;
    sha256_init(&sha);
    uint8_t buf[4096], digest[32];
    for (uint64_t off = 0; ok && off < GV_BYTES; off += sizeof buf) {
        ok = platform_positioned_file_read(&file, buf, sizeof buf, off) == sizeof buf;
        if (ok) sha256_write(&sha, buf, sizeof buf);
    }
    if (ok) ok = platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    return ok;
}

static bool gv_identity(const char *path, struct platform_private_file_identity *identity)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_open_locked(path, &file) &&
        platform_private_file_identity(&file, identity);
    platform_private_file_close(&file);
    return ok;
}

static bool gv_same_identity(const char *path, const struct platform_private_file_identity *expected)
{
    struct platform_private_file_identity now;
    return gv_identity(path, &now) && now.volume == expected->volume && now.file == expected->file;
}

static bool gv_create(const char *path)
{
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(path, &file) &&
        platform_private_file_truncate(&file, GV_BYTES) &&
        platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    return ok;
}

/* Copy to a distinct owned inode; flip encrypted DATA, not GELI metadata/tag.
 * g_eli_integrity.c stores a SHA256 tag32 before data in each512-byte sector.
 * The first decrypted4096-byte extent maps from backing offset0; byte544 is
 * the first data byte in the second encrypted sector. Helper observes the
 * actual backend read/write range covering544 before qualifying each raw leg.
 * The mounted caller uses73760: provider65536 maps to outer73728, then
 * skip the32-byte authentication tag to mutate superblock DATA only. */
static bool gv_tamper(const char *source, const char *target, uint64_t data_byte)
{
    if (data_byte >= GV_BYTES) return false;
    struct platform_positioned_file in;
    struct platform_private_file owner;
    platform_positioned_file_init(&in);
    platform_private_file_init(&owner);
    bool ok = platform_positioned_file_open(&in, source) &&
        platform_private_file_create(target, &owner);
    uint8_t buf[4096];
    for (uint64_t off = 0; ok && off < GV_BYTES; off += sizeof buf) {
        ok = platform_positioned_file_read(&in, buf, sizeof buf, off) == sizeof buf;
        if (ok && off <= data_byte && data_byte - off < sizeof buf)
            buf[data_byte - off] ^= 1u;
        if (ok) ok = platform_private_file_write_at(&owner, buf, sizeof buf, off);
    }
    if (ok) ok = platform_private_file_authority_flush(&owner);
    /* Borrowed out is never closed independently. */
    platform_positioned_file_close(&in);
    platform_private_file_close(&owner);
    return ok;
}

static bool gv_proof(const char *phase, const char *output,
                      const struct zcl_spawn_binary_observation *observed)
{
    char proof[128];
    int n = snprintf(proof, sizeof proof, "%s phase=%s ",
        strncmp(phase, "mounted-", 8) == 0 ? "PUBLIC_MOUNTED_PROOF" : "PUBLIC_GELI_PROOF", phase);
    return !observed->timed_out && !observed->overflow && observed->eof &&
        observed->exit_observed && observed->exit_code == 0 && n > 0 &&
        (size_t)n < sizeof proof && strstr(output, proof) != NULL;
}

static bool gv_child(const char *phase, const char *kernel, const char *volume,
                     int64_t deadline)
{
    int64_t remaining = deadline - clock_now_monotonic_ns();
    if (remaining <= 0) {
        printf("UNOBSERVED: PUBLIC GELI phase=%s shared execution budget exhausted\n", phase);
        return false;
    }
    int timeout = remaining / 1000000 > g_gv_child_cap_ms ? g_gv_child_cap_ms
                                                          : (int)(remaining / 1000000);
    if (timeout <= 0) {
        printf("UNOBSERVED: PUBLIC GELI phase=%s execution budget below one millisecond\n", phase);
        return false;
    }
    char *output = calloc(1, 131073);
    if (output == NULL) return false;
    const char *argv[] = {"build/bin/z23-machine-geli-volume", phase, kernel, volume, NULL};
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary_merged(argv, output, 131072,
                                                              timeout, &observed);
    if (observed.timed_out)
        printf("UNOBSERVED: PUBLIC GELI phase=%s child execution cap=%d ms exhausted\n",
               phase, timeout);
    output[observed.output_len] = '\0';
    bool emitted = fwrite(output, 1, observed.output_len, stdout) == observed.output_len &&
        fflush(stdout) == 0;
    bool ok = emitted && result.ok && gv_proof(phase, output, &observed);
    free(output);
    return ok;
}
static bool gmb_unchanged(const char *volume,
                          const struct platform_private_file_identity *identity,
                          const char *before)
{
    char after[65];
    return gv_same_identity(volume, identity) && gv_hash(volume, after) &&
        strcmp(before, after) == 0;
}

static bool gmb_recovery(const char *phase, const char *kernel, const char *volume,
                         int64_t deadline,
                         const struct platform_private_file_identity *identity,
                         const char *before)
{
    return gv_child(phase, kernel, volume, deadline) &&
        gmb_unchanged(volume, identity, before);
}

static bool gmb_copy_test(const char *kernel, const char *volume, const char *tampered,
                          int64_t deadline,
                          const struct platform_private_file_identity *identity,
                          const char *before)
{
    char after[65];
    struct platform_private_file_identity copy;
    if (!gv_identity(tampered, &copy) ||
        (copy.volume == identity->volume && copy.file == identity->file) ||
        !gv_hash(tampered, after) || strcmp(before, after) == 0 ||
        !gv_child("mounted-tamper", kernel, tampered, deadline) ||
        !gv_same_identity(tampered, &copy)) return false;
    return gmb_unchanged(volume, identity, before);
}

static bool gmb_accept(const char *packet, const char *dir, int64_t deadline)
{
    char kernel[4096], volume[4096], tampered[4096], before[65];
    int n = snprintf(kernel, sizeof kernel, "%s/kernel-mounted", packet);
    if (n <= 0 || (size_t)n >= sizeof kernel) return false;
    n = snprintf(volume, sizeof volume, "%s/mounted", dir);
    if (n <= 0 || (size_t)n >= sizeof volume || !gv_create(volume)) return false;
    struct platform_private_file_identity identity;
    if (!gv_identity(volume, &identity) || !gv_child("mounted-write", kernel, volume, deadline) ||
        !gv_same_identity(volume, &identity) || !gv_hash(volume, before)) return false;
    if (!gmb_recovery("mounted-read", kernel, volume, deadline, &identity, before)) return false;
    if (!gmb_recovery("mounted-wrong", kernel, volume, deadline, &identity, before)) return false;
    n = snprintf(tampered, sizeof tampered, "%s/mounted-tampered", dir);
    if (n <= 0 || (size_t)n >= sizeof tampered || !gv_tamper(volume, tampered, GMB_SB_DATA_BYTE)) return false;
    return gmb_copy_test(kernel, volume, tampered, deadline, &identity, before);
}
#endif

int test_rvmachine_geli_volume(void);
int test_rvmachine_geli_volume(void)
{
#if defined(_WIN32)
    printf("UNOBSERVED: retained GELI guest fixture has no Windows qualification\n");
    return 1;
#else
    int failures = 0;
    const char *packet = getenv("ZCL_TEST_GELI_FIXTURE_PACKET");
    if (packet == NULL || *packet == '\0') {
        printf("UNOBSERVED: ZCL_TEST_GELI_FIXTURE_PACKET exact public packet required\n");
        return 1;
    }
    /* Clock availability and overflow are execution prerequisites, not a
     * storage-performance assertion. Capture enforces the shared budget;
     * the verdict below requires the observed guest and volume outcomes. */
    /* The guests are fixed-instruction emulations (work= counts in the proof
     * lines are deterministic), so their wall time is pure host speed: one
     * passing run took 114 s with the host at load average ~110 on 32 CPUs,
     * nearly half the 240 s idle-host budget, and a run twice as slow exhausts
     * it before the mounted phases (the failure of stacks 334, 353, 357). The nominal 240 s
     * shared and 120 s per-child budgets are therefore scaled by the measured
     * host calibration (floor 1x, cap 8x: beyond that the host is wedged).
     * Every outcome assertion below is unchanged. */
    struct test_budget total = test_budget_scale(UINT64_C(240) * 1000000u);
    struct test_budget child = test_budget_scale(UINT64_C(120) * 1000000u);
    g_gv_child_cap_ms = (int)(child.effective_us / 1000u);
    int64_t budget_ns = (int64_t)total.effective_us * 1000;
    printf("geli budget nominal_s=240 effective_s=%llu factor=%.2f\n",
           (unsigned long long)(total.effective_us / 1000000u), total.factor);
    int64_t now = clock_now_monotonic_ns();
    if (now <= 0 || now > INT64_MAX - budget_ns) {
        printf("UNOBSERVED: PUBLIC GELI execution clock unavailable or deadline overflow\n");
        return 1;
    }
    int64_t deadline = now + budget_ns;
    char dir[4096];
    char kernel[4096], original[4096], tampered[4096];
    bool created = false;
    TEST("rvmachine GELI: authenticated PUBLIC volume survives restart and refuses wrong key/data corruption") {
        int n = snprintf(kernel, sizeof kernel, "%s/kernel", packet);
        ASSERT(n > 0 && (size_t)n < sizeof kernel);
        ASSERT(test_mkdtemp(dir, sizeof dir, "geli_public") != NULL);
        created = true;
        ASSERT(snprintf(original, sizeof original, "%s/original", dir) > 0);
        ASSERT(snprintf(tampered, sizeof tampered, "%s/tampered", dir) > 0);
        ASSERT(gv_create(original));
        struct platform_private_file_identity identity;
        ASSERT(gv_identity(original, &identity));
        ASSERT(gv_child("write", kernel, original, deadline));
        ASSERT(gv_same_identity(original, &identity));
        char before[65], after[65];
        ASSERT(gv_hash(original, before));
        ASSERT(gv_child("read", kernel, original, deadline));
        ASSERT(gv_same_identity(original, &identity));
        ASSERT(gv_hash(original, after));
        ASSERT(strcmp(before, after) == 0);
        ASSERT(gv_child("wrong", kernel, original, deadline));
        ASSERT(gv_same_identity(original, &identity));
        ASSERT(gv_hash(original, after));
        ASSERT(strcmp(before, after) == 0);
        ASSERT(gv_tamper(original, tampered, GV_DATA_BYTE));
        ASSERT(gv_hash(tampered, after));
        ASSERT(strcmp(before, after) != 0);
        ASSERT(gv_child("tamper", kernel, tampered, deadline));
        ASSERT(gv_same_identity(original, &identity));
        ASSERT(gv_hash(original, after));
        ASSERT(strcmp(before, after) == 0);
        ASSERT(gmb_accept(packet, dir, deadline));
        PASS();
    } _test_next:;
    if (created && failures == 0) test_cleanup_tmpdir(dir);
    else if (created) printf("PUBLIC fixture evidence retained: %s\n", dir);
    return failures;
#endif
}
