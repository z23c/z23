/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ─────────────────────────────────────────────────────────────────
 * root-cause fix for the GetRandBytes fail-open that was
 * flagged during (see AGENT-3.md note at end for the original
 * writeup).
 *
 * The prior implementation opened /dev/urandom and silently
 * `memset(buf, 0, num)`-ed on open() failure (chroot/container
 * without /dev mounted, fd exhaustion, SELinux denial, early boot
 * before /dev is populated, ...). Every secret in the binary —
 * Sapling note randomness (rcm / rcv / esk / ar), RedJubjub signing
 * nonces, Groth16 proof blinding factors, ephemeral DH secrets,
 * HD wallet seeds, BIP39 entropy, P2P session keys, CSRF keys — is
 * ultimately sourced here, so a silent zero-fill becomes a same-key-
 * everywhere catastrophe with no log line and no caller-visible
 * signal.
 *
 * The public signature is left unchanged (void return, per the
 * AGENT-3 scope boundary that keeps core/modules/core/include/ off-limits).
 * Failure semantics are now strict: if we cannot fill the output
 * buffer with real entropy, we log to stderr and abort(). No caller
 * ever observes a zero-filled "success" — the process is dead before
 * the return. abort() is appropriate here because we cannot locally
 * distinguish secret from non-secret callers; the fatal policy is
 * correct for the secret case and merely noisy for the non-secret
 * case.
 *
 * Entropy source:
 *   platform.rng, whose production default wraps the kernel CSPRNG with
 *   /dev/urandom fallback while tests/simulators may inject a seeded
 *   deterministic RNG.
 * ───────────────────────────────────────────────────────────────── */

#include "core/random.h"
#include "platform/rng.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef ZCL_TESTING
#include <stdatomic.h>
/* Test-only fault injection: when set, GetRandBytes skips both
 * syscall paths and goes straight to the fatal log+abort. A failing-
 * RNG unit test fork()s a child, flips this, calls GetRandBytes,
 * and asserts WTERMSIG == SIGABRT in the parent. Not exported from
 * core/random.h (that header is off-limits for this fix); callers
 * forward-declare with `extern void zcl_random_test_force_fail(bool);`. */
static atomic_bool g_rng_force_fail = false;
void zcl_random_test_force_fail(bool on);
void zcl_random_test_force_fail(bool on)
{
    atomic_store_explicit(&g_rng_force_fail, on, memory_order_release);
}
#endif

void GetRandBytes(unsigned char *buf, size_t num)
{
    if (num == 0) return;

#ifdef ZCL_TESTING
    if (atomic_load_explicit(&g_rng_force_fail, memory_order_acquire)) {
        fprintf(stderr,  // obs-ok:helper-context-logged
            "[fatal] %s:%d GetRandBytes(): ZCL_TEST_FORCE_RNG_FAIL active "
            "— aborting to avoid zero-fill (num=%zu)\n",
            __FILE__, __LINE__, num);
        fflush(stderr);
        abort(); // abort-ok: the fault injector exists to prove this path dies; returning would hand the caller a zero-filled buffer
    }
#endif

    if (rng_fill(buf, num)) return;

    fprintf(stderr,  // obs-ok:helper-context-logged
        "[fatal] %s:%d GetRandBytes(): no entropy source available "
        "(platform.rng failed) for %zu bytes "
        "— aborting to avoid silent zero-fill\n",
        __FILE__, __LINE__, num);
    fflush(stderr);
    abort(); // abort-ok: no entropy and a void return; every caller would proceed on a zero-filled buffer and mint a guessable key
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0) return 0;
    uint64_t nRange = (UINT64_MAX / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char *)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return nRand % nMax;
}

int GetRandInt(int nMax)
{
    return (int)GetRand((uint64_t)nMax);
}

