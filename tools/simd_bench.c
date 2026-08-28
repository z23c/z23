/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simd_bench — per-ISA-tier microbenchmark for the node's crypto primitives.
 *
 * WHY THIS EXISTS
 * ---------------
 * This tree ships several "accelerated" code paths (SHA-NI, AVX2, AVX-512,
 * BMI2/MULX). Some are faster than the generic C they replace. At least one is
 * measurably SLOWER and is correctly switched off. Until a primitive has been
 * driven through every tier IN ONE PROCESS, on the SAME input, with the outputs
 * compared byte-for-byte, "accelerated" is a claim and not a fact.
 *
 * So this tool does exactly three things, and refuses to report a speed number
 * unless all three hold:
 *
 *   1. FORCE each tier explicitly through the primitive's *_select_impl hook
 *      (never by hoping the CPU dispatcher picks it). A tier that cannot run on
 *      this host is reported UNAVAILABLE, never silently folded into another.
 *   2. VERIFY every tier produced BIT-IDENTICAL output to the generic tier.
 *      A mismatch aborts the whole run with exit 2. A faster path that returns
 *      different bytes is a chain split, not an optimization, and this harness
 *      must never be the thing that reports it as a win.
 *   3. Only then TIME them, reporting median and p90 across repetitions rather
 *      than a mean — this box runs other workloads, and a mean is noise.
 *
 * METHODOLOGY NOTES (read before trusting a number)
 * -------------------------------------------------
 *  - CPU PINNING is mandatory, not advisory. This host class (7950X3D) is an
 *    asymmetric dual-CCD part: one CCD carries 3D V-Cache (large L3, lower
 *    clock), the other clocks higher with a third of the L3. A benchmark that
 *    migrates between them silently is worthless. We pin with
 *    sched_setaffinity and REPORT the CCD (derived from sysfs L3
 *    shared_cpu_list, not hardcoded) plus its L3 size in every header line.
 *  - Each measurement is a full independent repetition of `inner` operations.
 *    We take the median and p90 OF THE REPETITIONS. p90 above median is the
 *    honest signal for interference; the tool prints the spread so a reader can
 *    discount a contended run instead of being handed a clean-looking mean.
 *  - A warmup repetition is discarded (page faults, DVFS ramp, icache).
 *  - Loads are anti-optimized with a volatile sink so the compiler cannot
 *    delete the work being timed.
 *
 * Deliberately standalone: it links the real crypto sources directly (see the
 * `simd_bench` target in the Makefile) so it measures the SHIPPED code at the
 * SHIPPED flags, not a copy that has drifted.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "crypto/blake2b.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "sapling/bn254_accel.h"
#include "sapling/fr_accel.h"

#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── Configuration ───────────────────────────────────────────────── */

#define BENCH_REPS_DEFAULT   31    /* odd → median is a real sample */
#define BENCH_MAX_REPS       501
#define MAX_TIERS            4

static int      g_reps = BENCH_REPS_DEFAULT;
static int      g_pin_cpu = -1;
static bool     g_csv = false;
static unsigned g_failures = 0;

/* Anti-optimization sink: every timed body folds its result in here so the
 * compiler cannot prove the work is dead and delete it. */
static volatile uint64_t g_sink = 0;

/* ── Timing ──────────────────────────────────────────────────────── */

static uint64_t now_ns(void)
{
    struct timespec ts;
    /* Same exemption, and for the same reason, as
     * lib/test/differential/groth16_comb_bench.c: this is a standalone
     * benchmark that deliberately links only the crypto sources under test, so
     * it cannot call platform.clock. It also needs NANOSECOND resolution —
     * platform_time_monotonic_us() truncates to microseconds, which is coarser
     * than several of the primitives timed here. */
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:standalone-bench-links-no-platform-clock
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Percentile over an ALREADY SORTED array, nearest-rank. */
static uint64_t pct_sorted(const uint64_t *v, int n, double p)
{
    if (n <= 0) return 0;
    int idx = (int)(p * (double)(n - 1) + 0.5);
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return v[idx];
}

/* ── CPU pinning + CCD identification ────────────────────────────── */

struct cpu_topo {
    int  cpu;
    char l3_shared[128];   /* e.g. "0-7,16-23" */
    long l3_kb;
    int  ccd_index;        /* ordinal among distinct L3 domains */
    bool known;
};

static bool read_str_file(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    if (!fgets(out, (int)outsz, f)) { fclose(f); return false; }
    fclose(f);
    out[strcspn(out, "\n")] = '\0';
    return true;
}

/* Derive the CCD/L3 domain of `cpu` from sysfs. Nothing here is hardcoded to a
 * particular part — on a host with one uniform L3 this simply reports ccd 0. */
static void topo_probe(int cpu, struct cpu_topo *t)
{
    char path[256];
    memset(t, 0, sizeof(*t));
    t->cpu = cpu;
    t->ccd_index = -1;

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cache/index3/shared_cpu_list", cpu);
    if (!read_str_file(path, t->l3_shared, sizeof(t->l3_shared)))
        return;

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cache/index3/size", cpu);
    char sz[64];
    if (read_str_file(path, sz, sizeof(sz)))
        t->l3_kb = strtol(sz, NULL, 10);   /* sysfs prints e.g. "98304K" */

    /* Ordinal = number of DISTINCT L3 shared-lists seen before ours, scanning
     * CPUs in order. Gives a stable, self-describing "ccd0/ccd1" label. */
    long ncpu = sysconf(_SC_NPROCESSORS_CONF);
    char seen[16][128];
    int nseen = 0;
    for (long c = 0; c < ncpu && nseen < 16; c++) {
        char cur[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%ld/cache/index3/shared_cpu_list", c);
        if (!read_str_file(path, cur, sizeof(cur))) continue;
        int found = -1;
        for (int i = 0; i < nseen; i++)
            if (strcmp(seen[i], cur) == 0) { found = i; break; }
        if (found < 0) {
            snprintf(seen[nseen], sizeof(seen[nseen]), "%s", cur);
            found = nseen++;
        }
        if (strcmp(cur, t->l3_shared) == 0 && t->ccd_index < 0)
            t->ccd_index = found;
    }
    t->known = (t->ccd_index >= 0);
}

/* Pin to `cpu`. Returns false (and the caller must say so in the report) if the
 * pin did not take — an unpinned run on this host is not comparable. */
static bool pin_to_cpu(int cpu)
{
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        return false;
    /* Confirm the kernel actually moved us. */
    sched_yield();
    return sched_getcpu() == cpu;
#else
    /* No userspace affinity API here (Darwin exposes QoS classes, not a cpu
     * pin). Refusing honestly keeps an unpinned run visibly unpinned. */
    (void)cpu;
    return false;
#endif
}

/* ── Tier result plumbing ────────────────────────────────────────── */

struct tier_result {
    const char *name;
    bool        available;      /* tier exists AND runs on this host */
    bool        verified;       /* output byte-identical to reference tier */
    uint64_t    median_ns;      /* per repetition (inner ops) */
    uint64_t    p90_ns;
    uint64_t    min_ns;
    double      ops_per_sec;
    double      bytes_per_sec;  /* 0 when the primitive is not byte-oriented */
};

struct bench {
    const char        *primitive;
    const char        *unit;        /* what one "op" is */
    long               inner;       /* ops per repetition */
    double             bytes_per_op;/* 0 → do not report throughput in B/s */
    int                ntiers;
    struct tier_result tier[MAX_TIERS];
};

/* Run `fn` for g_reps repetitions (+1 discarded warmup) and fill `tr`. */
typedef void (*bench_fn)(long inner, void *ctx);

static void time_tier(struct tier_result *tr, const struct bench *b,
                      bench_fn fn, void *ctx)
{
    uint64_t samples[BENCH_MAX_REPS];

    fn(b->inner, ctx);   /* warmup, discarded */

    for (int r = 0; r < g_reps; r++) {
        uint64_t t0 = now_ns();
        fn(b->inner, ctx);
        uint64_t t1 = now_ns();
        samples[r] = t1 - t0;
    }
    qsort(samples, (size_t)g_reps, sizeof(samples[0]), cmp_u64);

    tr->min_ns    = samples[0];
    tr->median_ns = pct_sorted(samples, g_reps, 0.50);
    tr->p90_ns    = pct_sorted(samples, g_reps, 0.90);

    double per_op_ns = (double)tr->median_ns / (double)b->inner;
    tr->ops_per_sec  = per_op_ns > 0.0 ? 1e9 / per_op_ns : 0.0;
    tr->bytes_per_sec = b->bytes_per_op > 0.0
                      ? tr->ops_per_sec * b->bytes_per_op : 0.0;
}

static void human_bytes(double bps, char *out, size_t n)
{
    if (bps <= 0.0)              { snprintf(out, n, "%9s", "-"); return; }
    if (bps >= 1e9)              { snprintf(out, n, "%6.2f GB/s", bps / 1e9); return; }
    if (bps >= 1e6)              { snprintf(out, n, "%6.2f MB/s", bps / 1e6); return; }
    snprintf(out, n, "%6.2f KB/s", bps / 1e3);
}

static void report(const struct bench *b)
{
    /* Reference tier = tier 0, by construction the generic/portable one. */
    const struct tier_result *ref = &b->tier[0];

    if (!g_csv) {
        printf("\n%s  (%ld %s per repetition, %d repetitions)\n",
               b->primitive, b->inner, b->unit, g_reps);
        printf("  %-22s %12s %12s %10s %12s %9s  %s\n",
               "tier", "median ns/op", "p90 ns/op", "p90/med", "ops/s",
               "throughput", "vs generic");
        printf("  %.100s\n",
               "--------------------------------------------------------"
               "--------------------------------------------------");
    }

    for (int i = 0; i < b->ntiers; i++) {
        const struct tier_result *t = &b->tier[i];

        if (!t->available) {
            if (g_csv)
                printf("%s,%s,UNAVAILABLE,,,,,\n", b->primitive, t->name);
            else
                printf("  %-22s %12s   (not available on this host)\n",
                       t->name, "-");
            continue;
        }

        /* A diverged tier was never timed, so it has no numbers to print.
         * Saying "0.00x SLOWER" would read as a measurement; it is not one. */
        if (!t->verified) {
            if (g_csv)
                printf("%s,%s,DIVERGED,,,,,\n", b->primitive, t->name);
            else
                printf("  %-22s %12s   *** DIVERGED from generic — NOT TIMED ***\n",
                       t->name, "-");
            continue;
        }

        double med_op = (double)t->median_ns / (double)b->inner;
        double p90_op = (double)t->p90_ns / (double)b->inner;
        double spread = med_op > 0.0 ? p90_op / med_op : 0.0;
        double rel    = (ref->available && t->median_ns > 0)
                      ? (double)ref->median_ns / (double)t->median_ns : 0.0;

        if (g_csv) {
            printf("%s,%s,OK,%.4f,%.4f,%.0f,%.0f,%.4f\n",
                   b->primitive, t->name, med_op, p90_op,
                   t->ops_per_sec, t->bytes_per_sec, rel);
            continue;
        }

        char thr[32];
        human_bytes(t->bytes_per_sec, thr, sizeof(thr));

        char relbuf[32];
        if (i == 0)                 snprintf(relbuf, sizeof(relbuf), "reference");
        else if (rel >= 1.0)        snprintf(relbuf, sizeof(relbuf), "%.2fx FASTER", rel);
        else                        snprintf(relbuf, sizeof(relbuf), "%.2fx  SLOWER", rel);

        printf("  %-22s %12.2f %12.2f %9.2fx %12.3g %s  %s%s\n",
               t->name, med_op, p90_op, spread, t->ops_per_sec, thr, relbuf,
               t->verified ? "" : "  [UNVERIFIED]");
    }
}

/* Abort the whole run: a tier disagreed with the reference. */
static void parity_fail(const char *primitive, const char *tier,
                        const void *got, const void *want, size_t n)
{
    fprintf(stderr,
            "\nFATAL: %s tier '%s' is NOT bit-identical to the generic tier.\n"
            "  This is a consensus divergence, not a benchmark result.\n",
            primitive, tier);
    fprintf(stderr, "  want: ");
    for (size_t i = 0; i < n && i < 64; i++) fprintf(stderr, "%02x", ((const unsigned char *)want)[i]);
    fprintf(stderr, "\n  got : ");
    for (size_t i = 0; i < n && i < 64; i++) fprintf(stderr, "%02x", ((const unsigned char *)got)[i]);
    fprintf(stderr, "\n");
    g_failures++;
}

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 1 — SHA-256 (portable C vs SHA-NI)
 *
 * Consensus-critical: double-SHA256 is the block hash, the txid, and every
 * merkle combine (core/math/src/hash.c).
 * ═══════════════════════════════════════════════════════════════════ */

#define SHA_MSG_BYTES 1024

struct sha256_ctx_bench { const unsigned char *msg; };

static void sha256_body(long inner, void *vctx)
{
    struct sha256_ctx_bench *c = vctx;
    unsigned char out[32];
    for (long i = 0; i < inner; i++) {
        struct sha256_ctx s;
        sha256_init(&s);
        sha256_write(&s, c->msg, SHA_MSG_BYTES);
        sha256_finalize(&s, out);
        g_sink += out[0];
    }
}

static void bench_sha256(unsigned char *msg)
{
    struct bench b = {
        .primitive = "SHA-256 (1 KiB message)",
        .unit = "hashes",
        .inner = 20000,
        .bytes_per_op = SHA_MSG_BYTES,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (portable C)";
    b.tier[1].name = "SHA-NI";

    struct sha256_ctx_bench ctx = { .msg = msg };
    unsigned char digest[2][32];

    const enum sha256_impl want[2] = { SHA256_IMPL_PORTABLE, SHA256_IMPL_SHANI };
    for (int i = 0; i < 2; i++) {
        int got = sha256_select_impl(want[i]);
        /* SHANI falling back to PORTABLE means the host cannot supply it. */
        b.tier[i].available = (i == 0) || (got == SHA256_IMPL_SHANI);
        if (!b.tier[i].available) continue;

        struct sha256_ctx s;
        sha256_init(&s);
        sha256_write(&s, msg, SHA_MSG_BYTES);
        sha256_finalize(&s, digest[i]);

        if (i > 0 && memcmp(digest[i], digest[0], 32) != 0) {
            parity_fail(b.primitive, b.tier[i].name, digest[i], digest[0], 32);
            b.tier[i].verified = false;
            continue;
        }
        b.tier[i].verified = true;
        time_tier(&b.tier[i], &b, sha256_body, &ctx);
    }
    sha256_select_impl(SHA256_IMPL_AUTO);
    report(&b);
}

/* There is no single-stream SHA3-256 row here any more, and that is a result,
 * not an omission. This harness measured the tree's AVX-512 single-stream
 * Keccak-f at 0.70x the scalar path it would have replaced (10047 ns vs
 * 7012 ns, 4 KiB message, 101 reps, ccd0) — a cross-lane pi gather that costs
 * more than the vector width saves. It was also default-off, so nothing but
 * its own test ever ran it. It has been deleted, leaving one permutation and
 * nothing to compare. SHA3 vectorization pays only across INDEPENDENT streams,
 * which is what the next two rows measure.
 * ═══════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 2 — sha3_256_x4 (4 independent messages, scalar vs AVX-512)
 * Used by the snapshot manifest / merkle combine (lib/net/src/fast_sync.c).
 * ═══════════════════════════════════════════════════════════════════ */

#define X4_MSG_BYTES 1024

struct x4_ctx { const uint8_t *const *msgs; const size_t *lens; };

static void sha3_256_x4_body(long inner, void *vctx)
{
    struct x4_ctx *c = vctx;
    uint8_t out[4][32];
    for (long i = 0; i < inner; i++) {
        sha3_256_x4(c->msgs, c->lens, out);
        g_sink += out[0][0];
    }
}

static void bench_sha3_256_x4(unsigned char *msg)
{
    struct bench b = {
        .primitive = "SHA3-256 x4 batch (4 x 1 KiB independent messages)",
        .unit = "batches",
        .inner = 4000,
        .bytes_per_op = 4.0 * X4_MSG_BYTES,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (scalar x4)";
    b.tier[1].name = "AVX-512 (4-lane)";

    const uint8_t *msgs[4] = { msg, msg + 1024, msg + 2048, msg + 3072 };
    size_t lens[4] = { X4_MSG_BYTES, X4_MSG_BYTES, X4_MSG_BYTES, X4_MSG_BYTES };
    struct x4_ctx ctx = { .msgs = msgs, .lens = lens };
    uint8_t digest[2][4][32];

    const enum sha3_impl want[2] = { SHA3_IMPL_SCALAR, SHA3_IMPL_AVX512 };
    for (int i = 0; i < 2; i++) {
        int got = sha3_256_x4_select_impl(want[i]);
        b.tier[i].available = (i == 0) || (got == SHA3_IMPL_AVX512);
        if (!b.tier[i].available) continue;

        sha3_256_x4(msgs, lens, digest[i]);
        if (i > 0 && memcmp(digest[i], digest[0], sizeof(digest[0])) != 0) {
            parity_fail(b.primitive, b.tier[i].name, digest[i], digest[0], 128);
            b.tier[i].verified = false;
            continue;
        }
        b.tier[i].verified = true;
        time_tier(&b.tier[i], &b, sha3_256_x4_body, &ctx);
    }
    sha3_256_x4_select_impl(SHA3_IMPL_AUTO);
    report(&b);
}

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 4 — sha3_512_x4 keystream (scalar vs AVX-512)
 * Used by the file-service frame cipher (lib/net/src/file_service.c).
 * ═══════════════════════════════════════════════════════════════════ */

struct k4_ctx { const uint8_t *key; const uint8_t *nonce; };

static void sha3_512_x4_body(long inner, void *vctx)
{
    struct k4_ctx *c = vctx;
    uint8_t out[256];
    for (long i = 0; i < inner; i++) {
        sha3_512_x4(c->key, c->nonce, (uint64_t)i, out);
        g_sink += out[0];
    }
}

static void bench_sha3_512_x4(unsigned char *msg)
{
    struct bench b = {
        .primitive = "SHA3-512 x4 keystream (256 B per call)",
        .unit = "calls",
        .inner = 20000,
        .bytes_per_op = 256.0,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (scalar x4)";
    b.tier[1].name = "AVX-512 (4-lane)";

    const uint8_t *key = msg;
    const uint8_t *nonce = msg + 32;
    struct k4_ctx ctx = { .key = key, .nonce = nonce };
    uint8_t ks[2][256];

    const enum sha3_impl want[2] = { SHA3_IMPL_SCALAR, SHA3_IMPL_AVX512 };
    for (int i = 0; i < 2; i++) {
        int got = sha3_512_x4_select_impl(want[i]);
        b.tier[i].available = (i == 0) || (got == SHA3_IMPL_AVX512);
        if (!b.tier[i].available) continue;

        sha3_512_x4(key, nonce, 12345, ks[i]);
        if (i > 0 && memcmp(ks[i], ks[0], 256) != 0) {
            parity_fail(b.primitive, b.tier[i].name, ks[i], ks[0], 256);
            b.tier[i].verified = false;
            continue;
        }
        b.tier[i].verified = true;
        time_tier(&b.tier[i], &b, sha3_512_x4_body, &ctx);
    }
    sha3_512_x4_select_impl(SHA3_IMPL_AUTO);
    report(&b);
}

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 5 — Equihash BLAKE2b batch (scalar vs AVX2 4-way vs AVX-512 8-way)
 *
 * THE consensus PoW inner loop. This row pins the pre-Bubbles (200,9)
 * parameters, where one block header costs 512 independent BLAKE2b
 * finalizations; the parameters consensus uses are height-selected
 * (docs/EQUIHASH_PARAMS.md), and this benchmark deliberately measures the
 * larger, older shape rather than tracking the active epoch. Until now this
 * had NO tier selector, so no test in the tree could force
 * scalar-vs-AVX2-vs-AVX-512 on one input, and the 8-way path at these
 * parameters was verified only by the live chain. The selector added
 * alongside this harness is what makes the row below possible.
 *
 * Base state is built exactly as equihash.c does it: BLAKE2b personalized with
 * "ZcashPoW" || N || K, digest length 2n/8 per output.
 * ═══════════════════════════════════════════════════════════════════ */

#define EH_N 200
#define EH_K 9
/* (200,9): 512 indices, each hash 2*200/8 = 50 bytes, 2 outputs per call. */
#define EH_HASH_LEN  ((2 * EH_N / 8))          /* 50 */
#define EH_BATCH     8
#define EH_BATCHES   64                        /* 64 * 8 = 512 per block */

static void eh_base_state(struct blake2b_ctx *base)
{
    uint8_t personal[BLAKE2B_PERSONALBYTES] = {0};
    memcpy(personal, "ZcashPoW", 8);
    uint32_t n = EH_N, k = EH_K;
    memcpy(personal + 8, &n, 4);
    memcpy(personal + 12, &k, 4);

    /* Digest length as equihash_initialise_state computes it. */
    size_t outlen = (size_t)((512 / EH_N) * EH_N / 8);
    blake2b_init_salt_personal(base, outlen, NULL, 0, NULL, personal);

    /* Absorb a plausible header prefix so buflen is realistic (must leave
     * room for the 4-byte index, else the batch API falls to scalar). */
    unsigned char hdr[108];
    for (size_t i = 0; i < sizeof(hdr); i++) hdr[i] = (unsigned char)(i * 7 + 1);
    blake2b_update(base, hdr, sizeof(hdr));
}

struct eh_ctx { const struct blake2b_ctx *base; };

static void eh_body(long inner, void *vctx)
{
    struct eh_ctx *c = vctx;
    unsigned char out[EH_BATCH][64];
    unsigned char *hp[EH_BATCH];
    for (int i = 0; i < EH_BATCH; i++) hp[i] = out[i];

    for (long r = 0; r < inner; r++) {
        for (int bidx = 0; bidx < EH_BATCHES; bidx++) {
            uint32_t idx[EH_BATCH];
            for (int i = 0; i < EH_BATCH; i++)
                idx[i] = (uint32_t)(bidx * EH_BATCH + i);
            equihash_generate_hash_batch8(c->base, idx, hp, EH_HASH_LEN);
            g_sink += out[0][0];
        }
    }
}

static void bench_equihash_blake2b(void)
{
    struct bench b = {
        .primitive = "Equihash BLAKE2b batch, pre-Bubbles 200,9 — 512 hashes = 1 header",
        .unit = "block headers",
        .inner = 400,
        .bytes_per_op = 0.0,   /* op = a whole header's worth of hashing */
        .ntiers = 3,
    };
    b.tier[0].name = "generic (scalar)";
    b.tier[1].name = "4-way SIMD";
    b.tier[2].name = "8-way SIMD";

    struct blake2b_ctx base;
    eh_base_state(&base);
    struct eh_ctx ctx = { .base = &base };

    /* Reference digests: all 512 indices, captured per tier, compared whole. */
    static unsigned char digests[3][EH_BATCHES * EH_BATCH][64];

    const enum blake2b_batch_impl want[3] = {
        BLAKE2B_BATCH_IMPL_SCALAR,
        BLAKE2B_BATCH_IMPL_AVX2,
        BLAKE2B_BATCH_IMPL_AVX512
    };
    const int expect[3] = {
        BLAKE2B_BATCH_IMPL_SCALAR,
        BLAKE2B_BATCH_IMPL_AVX2,
        BLAKE2B_BATCH_IMPL_AVX512
    };

    for (int i = 0; i < 3; i++) {
        int got = equihash_blake2b_batch_select_impl(want[i]);
        b.tier[i].available = (got == expect[i]);
        if (!b.tier[i].available) continue;
        b.tier[i].name = equihash_blake2b_batch_implementation();

        for (int bidx = 0; bidx < EH_BATCHES; bidx++) {
            uint32_t idx[EH_BATCH];
            unsigned char *hp[EH_BATCH];
            for (int j = 0; j < EH_BATCH; j++) {
                idx[j] = (uint32_t)(bidx * EH_BATCH + j);
                hp[j] = digests[i][bidx * EH_BATCH + j];
            }
            equihash_generate_hash_batch8(&base, idx, hp, EH_HASH_LEN);
        }

        if (i > 0 && memcmp(digests[i], digests[0], sizeof(digests[0])) != 0) {
            /* Locate the first differing index for a useful message. */
            int bad = 0;
            for (int j = 0; j < EH_BATCHES * EH_BATCH; j++)
                if (memcmp(digests[i][j], digests[0][j], EH_HASH_LEN) != 0) { bad = j; break; }
            fprintf(stderr, "  (first divergence at Equihash index %d)\n", bad);
            parity_fail(b.primitive, b.tier[i].name,
                        digests[i][bad], digests[0][bad], EH_HASH_LEN);
            b.tier[i].verified = false;
            continue;
        }
        b.tier[i].verified = true;
        time_tier(&b.tier[i], &b, eh_body, &ctx);
    }
    equihash_blake2b_batch_select_impl(BLAKE2B_BATCH_IMPL_AUTO);
    report(&b);
}

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 6 — BN254 Fq Montgomery multiply (portable vs BMI2/MULX)
 * Sprout Groth16 JoinSplit verification bottoms out here.
 * ═══════════════════════════════════════════════════════════════════ */

/* Montgomery multiplies are measured in TWO regimes, because a single regime
 * can mislead in opposite directions:
 *
 *   chains == 1  LATENCY: r = r*b, a strict serial dependency chain. This is
 *                what a Montgomery ladder / sequential field expression looks
 *                like, and it exposes the critical path of one multiply.
 *   chains == 4  THROUGHPUT: four independent accumulators interleaved, giving
 *                the out-of-order engine room to overlap. This is what a
 *                multi-scalar multiplication or a pairing's Miller loop looks
 *                like, and it exposes instruction-level parallelism.
 *
 * A path that wins one and loses the other is a genuinely nuanced result and
 * must be reported as such. A path that loses BOTH has no regime in which it
 * pays for itself. */
#define MONT_MAX_CHAINS 4

struct mont4_ctx { const uint64_t *a; const uint64_t *b; int tier; int chains; };

static void bn254_body(long inner, void *vctx)
{
    struct mont4_ctx *c = vctx;
    uint64_t r[MONT_MAX_CHAINS][4];
    for (int k = 0; k < c->chains; k++) {
        memcpy(r[k], c->a, sizeof(r[k]));
        r[k][0] ^= (uint64_t)k;      /* de-correlate the chains */
    }
    for (long i = 0; i < inner; i += c->chains) {
        for (int k = 0; k < c->chains; k++) {
            if (c->tier == 0) bn254_accel_mont_mul_portable(r[k], r[k], c->b);
            else              (void)bn254_accel_mont_mul_adx(r[k], r[k], c->b);
        }
    }
    for (int k = 0; k < c->chains; k++) g_sink += r[k][0];
}

static void bench_bn254(int chains)
{
    struct bench b = {
        .primitive = chains == 1
            ? "BN254 Fq Montgomery multiply (Sprout Groth16) [LATENCY, 1 chain]"
            : "BN254 Fq Montgomery multiply (Sprout Groth16) [THROUGHPUT, 4 chains]",
        .unit = "multiplies",
        .inner = 300000,
        .bytes_per_op = 0.0,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (portable)";
    b.tier[1].name = "BMI2+ADX (MULX+ADCX+ADOX)";

    /* Two arbitrary field elements, both < q. */
    const uint64_t a[4] = { 0x1234567890abcdefULL, 0x0fedcba987654321ULL,
                            0x1122334455667788ULL, 0x0044556677889900ULL };
    const uint64_t bb[4] = { 0x0badc0ffee123456ULL, 0x00decafbad001122ULL,
                             0x0999888777666555ULL, 0x0011223344556677ULL };
    uint64_t out[2][4];

    bn254_accel_mont_mul_portable(out[0], a, bb);
    b.tier[0].available = true;
    b.tier[0].verified = true;

    b.tier[1].available = bn254_accel_mont_mul_adx(out[1], a, bb);
    if (b.tier[1].available) {
        if (memcmp(out[1], out[0], 32) != 0) {
            parity_fail(b.primitive, b.tier[1].name, out[1], out[0], 32);
            b.tier[1].verified = false;
        } else {
            b.tier[1].verified = true;
        }
    }

    for (int i = 0; i < 2; i++) {
        if (!b.tier[i].available || !b.tier[i].verified) continue;
        struct mont4_ctx ctx = { .a = a, .b = bb, .tier = i, .chains = chains };
        time_tier(&b.tier[i], &b, bn254_body, &ctx);
    }
    report(&b);
}

/* ═══════════════════════════════════════════════════════════════════
 * Primitive 7 — BLS12-381 Fr (4-limb) and Fp (6-limb) Montgomery multiply
 * Every Sapling/Groth16 field op routes through these.
 * ═══════════════════════════════════════════════════════════════════ */

static void fr_body(long inner, void *vctx)
{
    struct mont4_ctx *c = vctx;
    uint64_t r[MONT_MAX_CHAINS][4];
    for (int k = 0; k < c->chains; k++) {
        memcpy(r[k], c->a, sizeof(r[k]));
        r[k][0] ^= (uint64_t)k;
    }
    for (long i = 0; i < inner; i += c->chains) {
        for (int k = 0; k < c->chains; k++) {
            if (c->tier == 0) fr_accel_mont_mul_portable(r[k], r[k], c->b);
            else              (void)fr_accel_mont_mul_adx(r[k], r[k], c->b);
        }
    }
    for (int k = 0; k < c->chains; k++) g_sink += r[k][0];
}

static void bench_fr(int chains)
{
    struct bench b = {
        .primitive = chains == 1
            ? "BLS12-381 Fr Montgomery multiply (4 limb) [LATENCY, 1 chain]"
            : "BLS12-381 Fr Montgomery multiply (4 limb) [THROUGHPUT, 4 chains]",
        .unit = "multiplies",
        .inner = 300000,
        .bytes_per_op = 0.0,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (portable)";
    b.tier[1].name = "BMI2+ADX (MULX+ADCX+ADOX)";

    const uint64_t a[4] = { 0x0123456789abcdefULL, 0x00fedcba98765432ULL,
                            0x0011223344556677ULL, 0x0033445566778899ULL };
    const uint64_t bb[4] = { 0x0abcdef012345678ULL, 0x0055667788990011ULL,
                             0x0099aabbccddeeffULL, 0x0012345678901234ULL };
    uint64_t out[2][4];

    fr_accel_mont_mul_portable(out[0], a, bb);
    b.tier[0].available = true;
    b.tier[0].verified = true;

    b.tier[1].available = fr_accel_mont_mul_adx(out[1], a, bb);
    if (b.tier[1].available) {
        if (memcmp(out[1], out[0], 32) != 0) {
            parity_fail(b.primitive, b.tier[1].name, out[1], out[0], 32);
            b.tier[1].verified = false;
        } else {
            b.tier[1].verified = true;
        }
    }

    for (int i = 0; i < 2; i++) {
        if (!b.tier[i].available || !b.tier[i].verified) continue;
        struct mont4_ctx ctx = { .a = a, .b = bb, .tier = i, .chains = chains };
        time_tier(&b.tier[i], &b, fr_body, &ctx);
    }
    report(&b);
}

struct mont6_ctx { const uint64_t *a; const uint64_t *b; int tier; int chains; };

static void fp_body(long inner, void *vctx)
{
    struct mont6_ctx *c = vctx;
    uint64_t r[MONT_MAX_CHAINS][6];
    for (int k = 0; k < c->chains; k++) {
        memcpy(r[k], c->a, sizeof(r[k]));
        r[k][0] ^= (uint64_t)k;
    }
    for (long i = 0; i < inner; i += c->chains) {
        for (int k = 0; k < c->chains; k++) {
            if (c->tier == 0) fp_accel_mont_mul_portable(r[k], r[k], c->b);
            else              (void)fp_accel_mont_mul_adx(r[k], r[k], c->b);
        }
    }
    for (int k = 0; k < c->chains; k++) g_sink += r[k][0];
}

static void bench_fp(int chains)
{
    struct bench b = {
        .primitive = chains == 1
            ? "BLS12-381 Fp Montgomery multiply (6 limb) [LATENCY, 1 chain]"
            : "BLS12-381 Fp Montgomery multiply (6 limb) [THROUGHPUT, 4 chains]",
        .unit = "multiplies",
        .inner = 300000,
        .bytes_per_op = 0.0,
        .ntiers = 2,
    };
    b.tier[0].name = "generic (portable)";
    b.tier[1].name = "BMI2+ADX (MULX+ADCX+ADOX)";

    const uint64_t a[6] = { 0x0123456789abcdefULL, 0x00fedcba98765432ULL,
                            0x0011223344556677ULL, 0x0033445566778899ULL,
                            0x0044556677889900ULL, 0x0011002200330044ULL };
    const uint64_t bb[6] = { 0x0abcdef012345678ULL, 0x0055667788990011ULL,
                             0x0099aabbccddeeffULL, 0x0012345678901234ULL,
                             0x0022446688aaccddULL, 0x0005500660077008ULL };
    uint64_t out[2][6];

    fp_accel_mont_mul_portable(out[0], a, bb);
    b.tier[0].available = true;
    b.tier[0].verified = true;

    b.tier[1].available = fp_accel_mont_mul_adx(out[1], a, bb);
    if (b.tier[1].available) {
        if (memcmp(out[1], out[0], 48) != 0) {
            parity_fail(b.primitive, b.tier[1].name, out[1], out[0], 48);
            b.tier[1].verified = false;
        } else {
            b.tier[1].verified = true;
        }
    }

    for (int i = 0; i < 2; i++) {
        if (!b.tier[i].available || !b.tier[i].verified) continue;
        struct mont6_ctx ctx = { .a = a, .b = bb, .tier = i, .chains = chains };
        time_tier(&b.tier[i], &b, fp_body, &ctx);
    }
    report(&b);
}

/* ═══════════════════════════════════════════════════════════════════ */

static void usage(const char *argv0)
{
    printf("usage: %s [--cpu=N] [--reps=N] [--csv] [--self-test]\n\n", argv0);
    printf("  --cpu=N      pin to logical CPU N (default 0)\n");
    printf("  --reps=N     repetitions per tier (default %d, max %d)\n",
           BENCH_REPS_DEFAULT, BENCH_MAX_REPS);
    printf("  --csv        machine-readable output\n");
    printf("  --self-test  prove the parity checker can FAIL, then exit\n\n");
    printf("Every tier of every primitive is checked for BIT-IDENTICAL output\n");
    printf("against the generic tier before it is timed. Any mismatch exits 2.\n");
}

/* A "no divergence found" verdict is worthless unless the detector can be shown
 * to fire. This plants a one-bit divergence and asserts the checker catches it,
 * which is the only thing that makes the clean run above evidence rather than a
 * printf. Exits 0 when the detector works, 1 when it is broken. */
static int self_test(void)
{
    printf("simd_bench --self-test: planting a 1-bit divergence...\n\n");

    unsigned char good[32], bad[32];
    for (int i = 0; i < 32; i++) good[i] = bad[i] = (unsigned char)i;
    bad[17] ^= 0x01;

    unsigned before = g_failures;
    if (memcmp(bad, good, 32) != 0)
        parity_fail("SELF-TEST (synthetic)", "planted-divergence", bad, good, 32);

    if (g_failures != before + 1) {
        fprintf(stderr,
                "\nSELF-TEST FAILED: the parity checker did NOT record the "
                "planted divergence.\nEvery 'verified bit-identical' verdict "
                "this tool prints is therefore untrustworthy.\n");
        return 1;
    }
    printf("\nSELF-TEST PASSED: divergence detected and counted "
           "(a real run would exit 2).\n");

    /* Also prove the "identical input really is identical" direction, so the
     * checker cannot pass by always reporting failure. */
    g_failures = 0;
    if (memcmp(good, good, 32) != 0) {
        fprintf(stderr, "SELF-TEST FAILED: identical buffers compared unequal.\n");
        return 1;
    }
    printf("SELF-TEST PASSED: identical output is not falsely flagged.\n");
    return 0;
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--cpu=", 6) == 0)       g_pin_cpu = atoi(argv[i] + 6);
        else if (strncmp(argv[i], "--reps=", 7) == 0) g_reps = atoi(argv[i] + 7);
        else if (strcmp(argv[i], "--csv") == 0)       g_csv = true;
        else if (strcmp(argv[i], "--self-test") == 0) return self_test();
        else { usage(argv[0]); return 1; }
    }
    if (g_reps < 3) g_reps = 3;
    if (g_reps > BENCH_MAX_REPS) g_reps = BENCH_MAX_REPS;

    /* Default pin: CPU 0. Deliberately a fixed, documented choice rather than
     * "wherever we happen to be" — comparability across runs matters more than
     * picking the fastest core, and the header states which CCD that is. */
    if (g_pin_cpu < 0) g_pin_cpu = 0;

    bool pinned = pin_to_cpu(g_pin_cpu);
    struct cpu_topo topo;
    topo_probe(g_pin_cpu, &topo);

    if (!g_csv) {
        char running_cpu[32];
#if defined(__linux__)
        (void)snprintf(running_cpu, sizeof(running_cpu), "%d", sched_getcpu());
#else
        (void)snprintf(running_cpu, sizeof(running_cpu), "%s", "unknown");
#endif
        printf("zclassic23 simd_bench — per-ISA-tier crypto microbenchmark\n");
        printf("=========================================================\n");
        printf("  pinned          : %s (requested cpu %d, running on cpu %s)\n",
               pinned ? "YES" : "NO -- NUMBERS ARE NOT COMPARABLE",
               g_pin_cpu, running_cpu);
        if (topo.known)
            printf("  L3 domain (CCD) : ccd%d  [cpus %s]  L3 %ld KiB\n",
                   topo.ccd_index, topo.l3_shared, topo.l3_kb);
        else
            printf("  L3 domain (CCD) : unknown (sysfs cache info unavailable)\n");
        printf("  repetitions     : %d per tier (median + p90 reported)\n", g_reps);

        double la[3];
        if (getloadavg(la, 3) == 3)
            printf("  load average    : %.2f %.2f %.2f  (1m/5m/15m at start)\n",
                   la[0], la[1], la[2]);

        printf("\n  detected: sha256=%s  blake2b-batch=%s\n",
               sha256_implementation(), equihash_blake2b_batch_implementation());
        printf("            keccak-x4 (avx512f+vl+dq, XCR0) available=%s\n",
               keccak_x4_available() ? "yes" : "no");
        printf("            bn254=%s\n            bls12-381=%s\n",
               bn254_accel_implementation(), fr_accel_implementation());
    } else {
        printf("primitive,tier,status,median_ns_per_op,p90_ns_per_op,"
               "ops_per_sec,bytes_per_sec,speedup_vs_generic\n");
    }

    /* Shared random-ish input buffer, identical across every tier. */
    static unsigned char buf[8192];
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (unsigned char)(i * 131 + 17);

    bench_sha256(buf);
    bench_sha3_256_x4(buf);
    bench_sha3_512_x4(buf);
    bench_equihash_blake2b();
    bench_bn254(1);
    bench_bn254(MONT_MAX_CHAINS);
    bench_fr(1);
    bench_fr(MONT_MAX_CHAINS);
    bench_fp(1);
    bench_fp(MONT_MAX_CHAINS);

    if (!g_csv) {
        double la[3];
        if (getloadavg(la, 3) == 3)
            printf("\n  load average at end: %.2f %.2f %.2f\n", la[0], la[1], la[2]);
    }

    if (g_failures) {
        fprintf(stderr,
                "\n%u tier(s) produced output that differs from the generic path.\n"
                "Treat every speed number above as void until that is resolved.\n",
                g_failures);
        return 2;
    }
    if (!g_csv) printf("\nAll timed tiers verified bit-identical to generic.\n");
    return 0;
}
