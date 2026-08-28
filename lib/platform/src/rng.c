/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Injectable RNG — implementation. See platform/rng.h for design. */

#ifndef _WIN32
#define _GNU_SOURCE  /* getrandom on glibc */
#endif

#include "platform/rng.h"

#include "util/log_macros.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#elif !defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#endif

/* ── Real-syscall implementation ─────────────────────────────────── */

/* /dev/urandom fallback for the unlikely case getrandom(2) is not
 * available (very old kernel or sandbox without the syscall). Opens
 * lazily on first failure, then cached. */
#if !defined(__APPLE__) && !defined(_WIN32)
static _Atomic int g_urandom_fd = -1;

static bool fallback_urandom_fill(uint8_t *out, size_t len)
{
    int fd = atomic_load(&g_urandom_fd);
    if (fd < 0) {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr,
                "[platform] %s:%d %s(): open(/dev/urandom) failed errno=%d\n",
                __FILE__, __LINE__, __func__, errno);
            return false;
        }
        int expected = -1;
        if (!atomic_compare_exchange_strong(&g_urandom_fd, &expected, fd)) {
            /* Lost the race; close ours, use the winner's. */
            close(fd);
            fd = expected;
        }
    }
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, out + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr,
                "[platform] %s:%d %s(): read(/dev/urandom) failed errno=%d\n",
                __FILE__, __LINE__, __func__, errno);
            return false;
        }
        if (r == 0) {
            fprintf(stderr,
                "[platform] %s:%d %s(): read(/dev/urandom) EOF\n",
                __FILE__, __LINE__, __func__);
            return false;
        }
        got += (size_t)r;
    }
    return true;
}
#endif

static bool real_fill(void *self, uint8_t *out, size_t len)
{
    (void)self;
    if (len == 0) return true;
    if (!out) return false;

#if defined(_WIN32)
    size_t filled = 0;
    while (filled < len) {
        size_t remaining = len - filled;
        ULONG part = remaining > ULONG_MAX ? ULONG_MAX : (ULONG)remaining;
        NTSTATUS status = BCryptGenRandom(
            NULL, out + filled, part, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            fprintf(stderr,
                    "[platform] %s:%d %s(): BCryptGenRandom failed "
                    "status=0x%08lx\n",
                    __FILE__, __LINE__, __func__, (unsigned long)status);
            return false;
        }
        filled += part;
    }
    return true;
#elif defined(__APPLE__)
    arc4random_buf(out, len);
    return true;
#else
    size_t got = 0;
    while (got < len) {
        ssize_t r = getrandom(out + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) {
                /* Ancient kernel — fall through to /dev/urandom. */
                return fallback_urandom_fill(out + got, len - got);
            }
            fprintf(stderr,
                "[platform] %s:%d %s(): getrandom failed errno=%d\n",
                __FILE__, __LINE__, __func__, errno);
            return false;
        }
        if (r == 0) {
            /* getrandom can't return 0 with flags=0 unless len=0, which
             * we filtered above. Treat as hard failure. */
            fprintf(stderr,
                "[platform] %s:%d %s(): getrandom returned 0 unexpectedly\n",
                __FILE__, __LINE__, __func__);
            return false;
        }
        got += (size_t)r;
    }
    return true;
#endif
}

static const rng_iface_t g_real_iface = {
    .fill = real_fill,
    .self = NULL,
};

/* ── Process-wide default ────────────────────────────────────────── */

static _Atomic(const rng_iface_t *) g_default = &g_real_iface;

/* Installed simulator/tape source. NULL in production (zero-overhead
 * fast path: one atomic_load + predictable branch). Set non-NULL by
 * `platform_rng_set_source` (e.g. by `seed_tape_install`). */
static _Atomic(struct platform_rng_source *) g_rng_source = NULL;

const rng_iface_t *rng_default(void)
{
    const rng_iface_t *p = atomic_load_explicit(&g_default,
                                                memory_order_acquire);
    return p ? p : &g_real_iface;
}

bool rng_fill(uint8_t *out, size_t len)
{
    const rng_iface_t *p = rng_default();
    return p->fill(p->self, out, len);
}

uint64_t rng_u64(void)
{
    /* Fast install-hook check. `relaxed` is enough here: a stale read
     * just means one extra call lands on the previous source, which
     * is exactly what set_source's release semantics already permit
     * across threads (callers requiring a barrier should use the
     * higher-level seed_tape API). Branch is predictable in the steady
     * state (always installed during simulation; always NULL otherwise). */
    struct platform_rng_source *src =
        atomic_load_explicit(&g_rng_source, memory_order_relaxed);
    if (src != NULL) {
        return src->u64(src->user);
    }

    uint64_t v = 0;
    if (!rng_fill((uint8_t *)&v, sizeof(v))) {
        /* Hard failure of the entropy source. Treat as fatal — there
         * is no safe fallback for callers that asked for cryptographic
         * randomness. abort() rather than return 0, which would silently
         * generate predictable keys. */
        fprintf(stderr,
            "[platform] %s:%d %s(): rng_fill failed; aborting\n",
            __FILE__, __LINE__, __func__);
        abort(); // abort-ok: no entropy; the uint64_t return has no error value, so continuing means returning a predictable 0
    }
    return v;
}

uint32_t rng_u32_range(uint32_t lo, uint32_t hi)
{
    if (lo >= hi) return lo;

    uint32_t span = hi - lo;
    /* Largest multiple of `span` that fits in uint32_t. Anything
     * strictly larger than `threshold` would bias the modulo. */
    uint32_t threshold = (uint32_t)(-span) % span;  /* (2^32 mod span) */

    for (;;) {
        uint32_t r;
        if (!rng_fill((uint8_t *)&r, sizeof(r))) {
            fprintf(stderr,
                "[platform] %s:%d %s(): rng_fill failed; aborting\n",
                __FILE__, __LINE__, __func__);
            abort(); // abort-ok: no entropy; the uint32_t return has no error value, so continuing means returning a predictable lo
        }
        if (r >= threshold) {
            return lo + (r % span);
        }
        /* else: rejection — try again. The expected number of retries
         * is < 2 for any practical range. */
    }
}

void rng_set_default(const rng_iface_t *iface)
{
    if (!iface) {
        fprintf(stderr,
            "[platform] %s:%d %s(): refusing to install NULL rng iface\n",
            __FILE__, __LINE__, __func__);
        return;
    }
    atomic_store_explicit(&g_default, iface, memory_order_release);
}

void rng_reset_default(void)
{
    atomic_store_explicit(&g_default, &g_real_iface, memory_order_release);
}

void platform_rng_set_source(struct platform_rng_source *src)
{
    if (!src) {
        fprintf(stderr,
            "[platform] %s:%d %s(): refusing NULL — use platform_rng_clear_source\n",
            __FILE__, __LINE__, __func__);
        return;
    }
    atomic_store_explicit(&g_rng_source, src, memory_order_release);
}

void platform_rng_clear_source(void)
{
    atomic_store_explicit(&g_rng_source, NULL, memory_order_release);
}
