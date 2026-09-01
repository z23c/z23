/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * crc32c — shared Castagnoli CRC-32C implementation.
 *
 * Lifted verbatim from engine/modules/storage/src/event_log.c, where it had been the
 * only copy in the tree. The LevelDB reader needs the identical function
 * for its record and block trailers, and two independently maintained
 * spellings of a checksum that gates on-disk acceptance is exactly the
 * kind of cloned authority this codebase removes on sight.
 *
 * Hardware tier per ISA, always runtime-gated and self-checked before use:
 * SSE4.2 `_mm_crc32_u*` on x86, Arm C Language Extensions (FEAT_CRC32) on
 * arm64. See util/crc32c.h for the contract.
 */

#include "util/crc32c.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <nmmintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_acle.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#endif

static uint32_t g_crc32c_table[256];
static pthread_once_t g_crc32c_once = PTHREAD_ONCE_INIT;
static bool g_crc32c_use_hw = false;

static void crc32c_table_build(void)
{
    /* Castagnoli polynomial reflected: 0x82F63B78. */
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (0x82F63B78u & -(c & 1u));
        g_crc32c_table[i] = c;
    }
}

static uint32_t crc32c_sw(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ g_crc32c_table[(crc ^ p[i]) & 0xFFu];
    return crc ^ 0xFFFFFFFFu;
}

#if defined(__x86_64__) || defined(__i386__)
__attribute__((target("sse4.2")))
static uint32_t crc32c_hw(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
#if defined(__x86_64__)
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, p, sizeof(v));
        crc = (uint32_t)_mm_crc32_u64((uint64_t)crc, v);
        p += 8;
        len -= 8;
    }
#else
    while (len >= 4) {
        uint32_t v;
        memcpy(&v, p, sizeof(v));
        crc = _mm_crc32_u32(crc, v);
        p += 4;
        len -= 4;
    }
#endif
    while (len > 0) {
        crc = _mm_crc32_u8(crc, *p++);
        len--;
    }
    return crc ^ 0xFFFFFFFFu;
}
#endif

#if defined(__aarch64__)
/* The OS feature report, not a raw instruction probe: the kernel has to be
 * willing to save the CRC extension's register state for the instructions to
 * be usable at all. FEAT_CRC32 is the arm64 analogue of the x86
 * `__builtin_cpu_supports("sse4.2")` check below. Fail closed when the
 * report is absent or says anything but 1. */
static bool crc32c_arm_feat_crc32_present(void)
{
#if defined(__APPLE__)
    int present = 0;
    size_t plen = sizeof(present);
    if (sysctlbyname("hw.optional.arm.FEAT_CRC32", &present, &plen,
                     NULL, 0) != 0)
        return false;
    return present == 1;
#else
    /* No OS-level probe wired for non-Apple arm64 yet; stay on the software
     * table rather than guessing. */
    return false;
#endif
}

/* Mirror of the x86 SSE4.2 block above: same loop shape, the Castagnoli
 * instruction per width instead of `_mm_crc32_u*`. Compiled into every
 * arm64 build via the per-function target attribute and selected at
 * RUNTIME — never behind a compile-time feature predicate, which would
 * delete the hardware tier from the shipped binary on every CPU that has
 * the extension (the Darwin build passes no -march at all). */
__attribute__((target("+crc")))
static uint32_t crc32c_hw(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, p, sizeof(v));
        crc = __crc32cd(crc, v);
        p += 8;
        len -= 8;
    }
    while (len >= 4) {
        uint32_t v;
        memcpy(&v, p, sizeof(v));
        crc = __crc32cw(crc, v);
        p += 4;
        len -= 4;
    }
    while (len > 0) {
        crc = __crc32cb(crc, *p++);
        len--;
    }
    return crc ^ 0xFFFFFFFFu;
}
#endif

static void crc32c_init_once(void)
{
    crc32c_table_build();
#if defined(__aarch64__)
    if (crc32c_arm_feat_crc32_present()) {
        uint8_t buf[4099];
        for (size_t i = 0; i < sizeof(buf); i++)
            buf[i] = (uint8_t)(i * 31u + 7u);
        bool ok = true;
        for (size_t n = 0; n <= sizeof(buf); n += (n < 64 ? 1 : 257)) {
            if (crc32c_hw(buf, n) != crc32c_sw(buf, n)) {
                ok = false;
                break;
            }
        }
        g_crc32c_use_hw = ok;
        if (!ok) {
            fprintf(stderr,  // obs-ok:event-log-crc-selfcheck
                    "[crc32c] FEAT_CRC32 crc32c self-check failed; "
                    "using software crc32c\n");
        }
    }
#elif defined(__x86_64__) || defined(__i386__)
    if (__builtin_cpu_supports("sse4.2")) {
        uint8_t buf[4099];
        for (size_t i = 0; i < sizeof(buf); i++)
            buf[i] = (uint8_t)(i * 31u + 7u);
        bool ok = true;
        for (size_t n = 0; n <= sizeof(buf); n += (n < 64 ? 1 : 257)) {
            if (crc32c_hw(buf, n) != crc32c_sw(buf, n)) {
                ok = false;
                break;
            }
        }
        g_crc32c_use_hw = ok;
        if (!ok) {
            fprintf(stderr,  // obs-ok:event-log-crc-selfcheck
                    "[crc32c] SSE4.2 crc32c self-check failed; "
                    "using software crc32c\n");
        }
    }
#endif
}

uint32_t zcl_crc32c(const void *data, size_t len)
{
    pthread_once(&g_crc32c_once, crc32c_init_once);
#if defined(__aarch64__) || defined(__x86_64__) || defined(__i386__)
    if (g_crc32c_use_hw)
        return crc32c_hw(data, len);
#endif
    return crc32c_sw(data, len);
}

uint32_t zcl_crc32c_sw(const void *data, size_t len)
{
    pthread_once(&g_crc32c_once, crc32c_init_once);
    return crc32c_sw(data, len);
}

bool zcl_crc32c_hw_available(void)
{
    pthread_once(&g_crc32c_once, crc32c_init_once);
    return g_crc32c_use_hw;
}

const char *zcl_crc32c_impl_name(void)
{
    pthread_once(&g_crc32c_once, crc32c_init_once);
    if (!g_crc32c_use_hw)
        return "software-table";
#if defined(__aarch64__)
    return "hardware-armv8-crc32";
#else
    return "hardware-sse4.2";
#endif
}
