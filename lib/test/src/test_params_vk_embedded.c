/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The compiled-in verifying keys, and the boundary between validating and
 * proving.
 *
 * What this pins down:
 *
 *   1. The embedded blobs are exactly the verifying-key prefix of the real
 *      parameter files — byte-for-byte, and exactly 868 + ic_len*96 long, so
 *      neither short (a truncated key) nor long (proving-key material that
 *      does not belong in the binary).
 *   2. Installing them arms shielded proof VALIDATION.
 *   3. Installing them does NOT arm proving. A node with no proving
 *      parameters must refuse to build a shielded output, never emit an
 *      unproven one.
 *   4. A planted bad blob is refused. This is the check that stands between
 *      a patched binary and proofs being verified against an attacker's key,
 *      so it is tested against the production comparison, not a copy of it.
 *
 * Test 1 needs a real parameter directory and SKIPs cleanly without one —
 * which is the normal case on a machine that never had them, and the whole
 * point of the change under test. Tests 2-4 need nothing.
 */

#include "test/test_core.h"

#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling_prover.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VK_CHECK(name, expr) do { \
    printf("params_vk_embedded: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Groth16 verifying-key layout, matching groth16_vk_read_raw(). */
#define VK_HEADER_BYTES   868
#define VK_IC_LEN_OFFSET  864
#define VK_IC_POINT_BYTES 96

static uint32_t be32_at(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* The parameter file each Groth16 blob was cut from. sprout-phgr is embedded
 * whole from sprout-verifying.key, so it has no prefix relationship to check
 * beyond equality. */
static const char *const vk_source_file[ZCL_EMBEDDED_VK_COUNT] = {
    "sapling-spend.params",
    "sapling-output.params",
    "sprout-groth16.params",
    "sprout-verifying.key",
};

int test_params_vk_embedded(void);
int test_params_vk_embedded(void)
{
    int failures = 0;

    /* ── 1. Each blob is exactly the verifying-key prefix ─────────────── */
    {
        /* The first three blobs are Groth16 keys and must be self-describing:
         * the ic_len they carry has to account for their own length exactly.
         * This runs with or without a parameter directory. */
        for (size_t i = 0; i < 3; i++) {
            const struct zcl_embedded_vk *e = &zcl_embedded_vks[i];
            char name[128];

            snprintf(name, sizeof(name),
                     "%s blob is long enough to carry an ic_len", e->name);
            VK_CHECK(name, e->len > VK_HEADER_BYTES);
            if (e->len <= VK_HEADER_BYTES) continue;

            uint32_t ic_len = be32_at(e->bytes + VK_IC_LEN_OFFSET);
            size_t want = (size_t)VK_HEADER_BYTES +
                          (size_t)ic_len * VK_IC_POINT_BYTES;

            snprintf(name, sizeof(name),
                     "%s is exactly 868+%u*96=%zu bytes (got %zu)",
                     e->name, ic_len, want, e->len);
            VK_CHECK(name, e->len == want);
        }

        /* Byte-for-byte against the real files, when this machine has them.
         * Read-only: never write into a parameter directory. */
        const char *home = getenv("HOME");
        char dir[1024];
        snprintf(dir, sizeof(dir), "%s/.zcash-params", home ? home : "");

        char probe[1200];
        snprintf(probe, sizeof(probe), "%s/%s", dir, vk_source_file[0]);
        if (!home || access(probe, R_OK) != 0) {
            printf("params_vk_embedded: prefix-equals-real-file... SKIP "
                   "(no readable %s — this is the ordinary case for a node "
                   "that never installed proving parameters)\n", dir);
        } else {
            for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++) {
                const struct zcl_embedded_vk *e = &zcl_embedded_vks[i];
                char path[1200], name[256];
                snprintf(path, sizeof(path), "%s/%s", dir, vk_source_file[i]);

                FILE *f = fopen(path, "rb");
                snprintf(name, sizeof(name), "%s: opened %s",
                         e->name, vk_source_file[i]);
                VK_CHECK(name, f != NULL);
                if (!f) continue;

                uint8_t *buf = malloc(e->len);
                snprintf(name, sizeof(name), "%s: allocated %zu bytes",
                         e->name, e->len);
                VK_CHECK(name, buf != NULL);
                if (!buf) { fclose(f); continue; }

                size_t got = fread(buf, 1, e->len, f);
                fclose(f);

                snprintf(name, sizeof(name),
                         "%s: read %zu bytes of prefix", e->name, e->len);
                VK_CHECK(name, got == e->len);

                snprintf(name, sizeof(name),
                         "%s: embedded blob equals the leading %zu bytes of %s",
                         e->name, e->len, vk_source_file[i]);
                VK_CHECK(name, got == e->len &&
                               memcmp(buf, e->bytes, e->len) == 0);
                free(buf);
            }
        }
    }

    /* ── 2. Installing the embedded keys arms validation ──────────────── */
    {
        VK_CHECK("install succeeds", sapling_install_embedded_vks());
        VK_CHECK("params report as loaded (proof validation armed)",
                 sapling_params_loaded());
        VK_CHECK("keys report as embedded, not from a parameter directory",
                 sapling_vks_are_embedded());
        VK_CHECK("install is idempotent", sapling_install_embedded_vks());
    }

    /* ── 3. Proving stays fail-closed ─────────────────────────────────── */
    {
        /* This is the safety property that lets the boot gate stand down.
         * No proving keys were loaded, so the prover must not claim to be
         * ready — sapling.c's build_output_description() writes a 192-byte
         * zero proof when no proving key is present, and the wallet's refusal
         * on this flag is what keeps that branch unreachable. */
        VK_CHECK("prover is NOT ready with verifying keys alone",
                 !zclassic_sapling_prover_is_ready());

        const char *status = zclassic_sapling_prover_status();
        VK_CHECK("prover status names the missing parameters",
                 status != NULL &&
                 strcmp(status, "params_not_initialized") == 0);
    }

    /* ── 4. A planted bad blob is refused ─────────────────────────────── */
    {
        const struct zcl_embedded_vk *e = &zcl_embedded_vks[0];

        /* Control: the genuine blob passes, so a later refusal means the
         * planted damage was detected and not that the check refuses
         * everything. */
        VK_CHECK("genuine blob passes its own digest",
                 sapling_test_embedded_vk_sha256_ok(e->name, e->bytes, e->len,
                                                    e->sha256_hex));

        uint8_t *bad = malloc(e->len);
        VK_CHECK("allocated planted-bad-blob copy", bad != NULL);
        if (bad) {
            /* One flipped bit, in the middle of the key material. */
            memcpy(bad, e->bytes, e->len);
            bad[e->len / 2] ^= 0x01u;
            VK_CHECK("one flipped bit is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            /* First byte, last byte, and a truncation: a length-only or
             * prefix-only comparison would let at least one of these pass. */
            memcpy(bad, e->bytes, e->len);
            bad[0] ^= 0xffu;
            VK_CHECK("a corrupt first byte is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            memcpy(bad, e->bytes, e->len);
            bad[e->len - 1] ^= 0xffu;
            VK_CHECK("a corrupt last byte is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            VK_CHECK("a truncated blob is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, e->bytes,
                                                         e->len - 1,
                                                         e->sha256_hex));
            free(bad);
        }

        /* Cross-wiring: the right bytes under the wrong name's digest must
         * fail, so the table cannot be reordered without being noticed. */
        VK_CHECK("spend bytes under the output digest are refused",
                 !sapling_test_embedded_vk_sha256_ok(
                     zcl_embedded_vks[0].name, zcl_embedded_vks[0].bytes,
                     zcl_embedded_vks[0].len, zcl_embedded_vks[1].sha256_hex));
    }

    printf("params_vk_embedded tests: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
