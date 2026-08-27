/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * serial_bench — block-body deserialization measured against real chain bytes.
 *
 * WHY THIS EXISTS
 * ---------------
 * A ZClassic block off this chain averages 2954 wire bytes. Deserializing it
 * allocates ~119 KB of element array, because struct tx_in embeds a whole
 * MAX_SCRIPT_SIZE (10000-byte) script buffer inline and a real scriptSig is
 * ~107 bytes. That is a 41x amplification, and zero-filling all of it was the
 * single largest cost in the parse.
 *
 * transaction_alloc / coins_alloc now allocate WITHOUT the zero fill. This
 * tool is what licenses that claim, and it refuses to report a speed number
 * unless the safety property holds first:
 *
 *   1. FORCE each variant explicitly through transaction_alloc_poison_set()
 *      rather than hoping. "zero-filled" reproduces the exact former calloc
 *      behavior, so BEFORE and AFTER are measured in ONE process, on ONE
 *      input, in one run — not by diffing two builds against two moods of the
 *      machine.
 *   2. VERIFY every variant derives BIT-IDENTICAL output — block hash, merkle
 *      root, every txid, and the full re-serialized wire bytes. A mismatch
 *      aborts with exit 2. A parser that is faster because it read a byte of
 *      uninitialized memory into a consensus hash is a chain split, not an
 *      optimization, and this harness must never be what reports it as a win.
 *   3. Only then TIME them, reporting median and p90 across repetitions. This
 *      box runs other workloads and a mean is noise.
 *
 * METHODOLOGY (read before trusting a number)
 * -------------------------------------------
 *  - CPU PINNING is mandatory. This host class (7950X3D) is an asymmetric
 *    dual-CCD part: one CCD carries 3D V-Cache (large L3, lower clock), the
 *    other clocks higher with a third of the L3. We pin with
 *    sched_setaffinity, verify the pin took, and report the CCD derived from
 *    sysfs rather than hardcoded.
 *  - This benchmark is allocator-bound, so it is deliberately NOT run on a
 *    freshly warmed arena only: a warmup repetition is discarded, then each
 *    repetition re-parses the whole corpus, which churns the heap the way the
 *    reducer does.
 *  - `--corpus=FILE` takes one raw block hex per line (as produced by
 *    `zclassic-cli getblock <hash> 0`). With no corpus it falls back to a
 *    built-in synthetic block so the tool always runs; the synthetic number
 *    is NOT representative of the chain and is labeled as such.
 *
 * Deliberately standalone: it links the real primitives sources (see the
 * `serial_bench` target in the Makefile) so it measures the SHIPPED code at
 * the SHIPPED flags, not a copy that has drifted.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "base/hex.h"
#include "bloom/merkle.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BENCH_REPS_DEFAULT 31    /* odd -> median is a real sample */
#define BENCH_MAX_REPS     501
#define MAX_BLOCKS         4096

static int  g_reps = BENCH_REPS_DEFAULT;
static int  g_pin_cpu = 0;
static bool g_csv = false;

/* Anti-optimization sink: the timed body folds a result in here so the
 * compiler cannot prove the work is dead and delete it. */
static volatile uint64_t g_sink = 0;

/* ── Timing ──────────────────────────────────────────────────────── */

static uint64_t now_ns(void)
{
    struct timespec ts;
    /* Same exemption, and for the same reason, as tools/simd_bench.c: a
     * standalone benchmark that deliberately links only the sources under
     * test cannot call platform.clock, and it needs nanosecond resolution. */
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:standalone-bench-links-no-platform-clock
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

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
    char l3_shared[128];
    long l3_kb;
    int  ccd_index;
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

/* Derive the L3 domain of `cpu` from sysfs. Nothing is hardcoded to a part —
 * on a host with one uniform L3 this simply reports ccd 0. */
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
        t->l3_kb = strtol(sz, NULL, 10);

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

static bool pin_to_cpu(int cpu)
{
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        return false;
    sched_yield();
    return sched_getcpu() == cpu;
#else
    /* No userspace affinity API here; an unpinned run must stay visible. */
    (void)cpu;
    return false;
#endif
}

/* ── Corpus ──────────────────────────────────────────────────────── */

static unsigned char *g_blk[MAX_BLOCKS];
static size_t         g_blk_len[MAX_BLOCKS];
static int            g_nblk = 0;
static bool           g_synthetic = false;

static bool corpus_load_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    static char line[1 << 22];
    while (g_nblk < MAX_BLOCKS && fgets(line, sizeof line, f)) {
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        if (L < 2 || (L & 1)) continue;
        size_t cap = L / 2;
        unsigned char *b = zcl_malloc(cap, "serial_bench_block");
        if (!b) break;
        size_t got = 0;
        if (!zcl_hex_decode_n(line, b, cap, &got) || got != cap) {
            free(b);
            continue;
        }
        g_blk[g_nblk] = b;
        g_blk_len[g_nblk] = cap;
        g_nblk++;
    }
    fclose(f);
    return g_nblk > 0;
}

/* Fallback so the tool always runs. A synthetic block is NOT representative
 * of the chain's script-length mix; the report says so. */
static bool corpus_synthesize(void)
{
    struct transaction tx;
    transaction_init(&tx);
    if (!transaction_alloc(&tx, 4, 4)) return false;
    tx.version = 4;
    tx.overwintered = true;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    unsigned char ss[107], pk[25];
    memset(ss, 0x5a, sizeof ss);
    memset(pk, 0x76, sizeof pk);
    for (int i = 0; i < 4; i++) {
        memset(tx.vin[i].prevout.hash.data, 0x40 + i, 32);
        tx.vin[i].prevout.n = (uint32_t)i;
        script_set(&tx.vin[i].script_sig, ss, sizeof ss);
        tx.vout[i].value = 1000 + i;
        script_set(&tx.vout[i].script_pub_key, pk, sizeof pk);
    }
    struct block b;
    block_init(&b);
    b.num_vtx = 1;
    b.vtx = &tx;
    struct byte_stream s;
    stream_init(&s, 4096);
    bool ok = block_serialize(&b, &s);
    b.vtx = NULL;
    b.num_vtx = 0;
    if (ok) {
        g_blk[0] = zcl_malloc(s.size, "serial_bench_synth");
        if (g_blk[0]) { memcpy(g_blk[0], s.data, s.size); g_blk_len[0] = s.size; g_nblk = 1; }
        else ok = false;
    }
    stream_free(&s);
    transaction_free(&tx);
    g_synthetic = true;
    return ok && g_nblk > 0;
}

/* ── The observation under test ──────────────────────────────────── */

/* Everything a consumer derives from a parsed block, folded into one
 * SHA-256: the header hash, the merkle root, every txid, and the full
 * re-serialized wire bytes. If a variant read one byte past a script's
 * .size, this digest moves. Returns the number of transactions seen. */
static uint64_t observe_corpus(struct uint256 *digest)
{
    struct sha256_ctx h;
    sha256_init(&h);
    uint64_t ntx = 0;

    for (int i = 0; i < g_nblk; i++) {
        struct byte_stream s;
        stream_init_from_data(&s, g_blk[i], g_blk_len[i]);
        struct block b;
        if (!block_deserialize(&b, &s)) {
            unsigned char x = 'X';
            sha256_write(&h, &x, 1);
            continue;
        }
        struct uint256 bh;
        block_get_hash(&b, &bh);
        sha256_write(&h, bh.data, 32);

        /* Every txid, then the merkle root built from them — the two
         * consensus values a tail read would corrupt. */
        struct uint256 *txids = zcl_malloc(b.num_vtx * sizeof(*txids), "serial_bench_txids");
        for (size_t t = 0; t < b.num_vtx; t++) {
            transaction_compute_hash(&b.vtx[t]);
            sha256_write(&h, b.vtx[t].hash.data, 32);
            if (txids) txids[t] = b.vtx[t].hash;
            ntx++;
        }
        if (txids) {
            struct uint256 mr = compute_merkle_root(txids, b.num_vtx);
            sha256_write(&h, mr.data, 32);
            free(txids);
        }

        struct byte_stream re;
        stream_init(&re, g_blk_len[i] + 64);
        if (block_serialize(&b, &re))
            sha256_write(&h, re.data, re.size);
        stream_free(&re);

        block_free(&b);
    }
    sha256_finalize(&h, digest->data);
    return ntx;
}

/* The timed body: one full pass over the corpus. */
static void parse_corpus_once(void)
{
    for (int i = 0; i < g_nblk; i++) {
        struct byte_stream s;
        stream_init_from_data(&s, g_blk[i], g_blk_len[i]);
        struct block b;
        if (block_deserialize(&b, &s)) {
            g_sink += b.num_vtx;
            block_free(&b);
        }
    }
}

/* ── Variants ────────────────────────────────────────────────────── */

struct variant {
    const char *name;
    int         poison;        /* fill byte, or <0 for "leave indeterminate" */
    bool        verified;
    uint64_t    median_ns;
    uint64_t    p90_ns;
    uint64_t    min_ns;
};

static struct variant g_var[] = {
    { "zero-filled  (former calloc behavior)", 0x00, false, 0, 0, 0 },
    { "0xAA-filled  (poison control)",         0xAA, false, 0, 0, 0 },
    { "unfilled     (SHIPPED)",                  -1, false, 0, 0, 0 },
};
#define NVAR ((int)(sizeof(g_var) / sizeof(g_var[0])))

int main(int argc, char **argv)
{
    const char *corpus = NULL;
    bool self_test = false;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--corpus=", 9) == 0) corpus = argv[i] + 9;
        else if (strncmp(argv[i], "--reps=", 7) == 0) g_reps = atoi(argv[i] + 7);
        else if (strncmp(argv[i], "--cpu=", 6) == 0) g_pin_cpu = atoi(argv[i] + 6);
        else if (strcmp(argv[i], "--csv") == 0) g_csv = true;
        else if (strcmp(argv[i], "--self-test") == 0) self_test = true;
        else {
            fprintf(stderr,
                    "usage: %s [--corpus=FILE] [--reps=N] [--cpu=N] [--csv]"
                    " [--self-test]\n", argv[0]);
            return 1;
        }
    }
    if (g_reps < 3) g_reps = 3;
    if (g_reps > BENCH_MAX_REPS) g_reps = BENCH_MAX_REPS;

    if (!(corpus && corpus_load_file(corpus)) && !corpus_synthesize()) {
        fprintf(stderr, "serial_bench: could not build a corpus\n");
        return 1;
    }

    bool pinned = pin_to_cpu(g_pin_cpu);
    struct cpu_topo topo;
    topo_probe(g_pin_cpu, &topo);

    size_t total_bytes = 0;
    for (int i = 0; i < g_nblk; i++) total_bytes += g_blk_len[i];

    if (!g_csv) {
        printf("serial_bench — block-body deserialization\n");
        printf("  cpu=%d %s", g_pin_cpu, pinned ? "(pinned)" : "(PIN FAILED — numbers not comparable)");
        if (topo.known) printf("  ccd%d L3=%ldK cpus=%s", topo.ccd_index, topo.l3_kb, topo.l3_shared);
        printf("\n  corpus=%s  blocks=%d  bytes=%.1f KB  avg=%.0f B/block\n",
               g_synthetic ? "SYNTHETIC (not representative of the chain)" : corpus,
               g_nblk, total_bytes / 1024.0, (double)total_bytes / g_nblk);
        printf("  reps=%d (median + p90 of full corpus passes)\n\n", g_reps);
    }

    /* ── STEP 1+2: parity BEFORE timing. Every variant must derive
     *    bit-identical output from the same bytes. ── */
    struct uint256 ref;
    int prev = transaction_alloc_poison_set(g_var[0].poison);
    uint64_t ntx = observe_corpus(&ref);
    (void)transaction_alloc_poison_set(prev);
    g_var[0].verified = true;

    int mismatches = 0;
    for (int v = 1; v < NVAR; v++) {
        struct uint256 d;
        prev = transaction_alloc_poison_set(g_var[v].poison);
        (void)observe_corpus(&d);
        (void)transaction_alloc_poison_set(prev);
        g_var[v].verified = (memcmp(d.data, ref.data, 32) == 0);
        if (!g_var[v].verified) {
            mismatches++;
            fprintf(stderr,
                    "serial_bench: PARITY FAILURE — variant '%s' derived a "
                    "DIFFERENT digest from the same bytes.\n"
                    "  Something reads a script byte past .size. This is a "
                    "chain split, not a speed result.\n", g_var[v].name);
        }
    }

    /* --self-test proves the parity checker can actually fail: hash a value
     * that genuinely differs and confirm the comparison rejects it. */
    if (self_test) {
        struct uint256 tampered = ref;
        tampered.data[0] ^= 0x01;
        bool caught = (memcmp(tampered.data, ref.data, 32) != 0);
        printf("self-test: parity checker rejects a 1-bit difference: %s\n",
               caught ? "YES" : "NO");
        if (!caught) return 2;
    }

    if (mismatches) return 2;
    if (!g_csv)
        printf("parity: all %d variants derive the IDENTICAL digest over %d "
               "blocks / %llu txs\n\n", NVAR, g_nblk, (unsigned long long)ntx);

    /* ── STEP 3: only now, time them. ── */
    /* INTERLEAVED, not variant-by-variant. Timing all reps of variant A and
     * then all reps of variant B charges A for growing the heap arena and
     * lets any thermal or load drift over the run land entirely on one
     * variant — measured as a spurious 1.29x between two variants that do
     * the identical amount of work. Round-robin makes every variant see the
     * same drift. */
    uint64_t *samples = zcl_malloc((size_t)g_reps * NVAR * sizeof(uint64_t), "serial_bench_samples");
    if (!samples) return 1;

    for (int v = 0; v < NVAR; v++) {          /* warmups, all discarded */
        prev = transaction_alloc_poison_set(g_var[v].poison);
        parse_corpus_once();
        parse_corpus_once();
        (void)transaction_alloc_poison_set(prev);
    }
    for (int r = 0; r < g_reps; r++) {
        for (int v = 0; v < NVAR; v++) {
            prev = transaction_alloc_poison_set(g_var[v].poison);
            uint64_t t0 = now_ns();
            parse_corpus_once();
            samples[v * g_reps + r] = now_ns() - t0;
            (void)transaction_alloc_poison_set(prev);
        }
    }
    for (int v = 0; v < NVAR; v++) {
        uint64_t *s = samples + v * g_reps;
        qsort(s, (size_t)g_reps, sizeof(uint64_t), cmp_u64);
        g_var[v].median_ns = pct_sorted(s, g_reps, 0.50);
        g_var[v].p90_ns    = pct_sorted(s, g_reps, 0.90);
        g_var[v].min_ns    = s[0];
    }
    free(samples);

    double base = (double)g_var[0].median_ns;
    if (g_csv) {
        printf("variant,median_ns_per_block,p90_ns_per_block,min_ns_per_block,speedup_vs_zero_filled,verified\n");
        for (int v = 0; v < NVAR; v++)
            printf("\"%s\",%.1f,%.1f,%.1f,%.3f,%d\n", g_var[v].name,
                   (double)g_var[v].median_ns / g_nblk,
                   (double)g_var[v].p90_ns / g_nblk,
                   (double)g_var[v].min_ns / g_nblk,
                   base / (double)g_var[v].median_ns,
                   g_var[v].verified ? 1 : 0);
    } else {
        printf("%-40s %12s %12s %10s\n", "variant", "median", "p90", "vs zero");
        printf("%-40s %12s %12s %10s\n", "", "ns/block", "ns/block", "filled");
        for (int v = 0; v < NVAR; v++)
            printf("%-40s %12.1f %12.1f %9.2fx\n", g_var[v].name,
                   (double)g_var[v].median_ns / g_nblk,
                   (double)g_var[v].p90_ns / g_nblk,
                   base / (double)g_var[v].median_ns);
        /* One repetition parses the WHOLE corpus, so median_ns is per pass. */
        double pass_s = (double)g_var[NVAR - 1].median_ns / 1e9;
        double saved_ns = (double)g_var[0].median_ns - (double)g_var[NVAR - 1].median_ns;
        printf("\nthroughput (shipped): %.2f GB/s of wire bytes, %.0f blocks/s\n",
               (double)total_bytes / pass_s / 1e9,
               (double)g_nblk / pass_s);
        printf("saved vs zero-filled: %.1f ns/block", saved_ns / g_nblk);
        if (!g_synthetic)
            printf("  →  %.1f s over a 3.2M-block full-history replay",
                   saved_ns / g_nblk * 3.2e6 / 1e9);
        printf("\n");
    }
    return 0;
}
