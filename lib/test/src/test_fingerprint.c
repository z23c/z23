/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fingerprint — the contract behavioral fingerprinting has to hold, or
 * its whole index is untrustworthy.
 *
 * Four propositions, in the order they matter:
 *
 *   1. REPRODUCIBLE. The same function fingerprints to the same value twice
 *      in a row, and to the same value when the compiler is told to optimise
 *      it differently. A fingerprint that moves for a reason other than
 *      behavior is worse than no fingerprint, because every "your refactor
 *      changed behavior" answer built on it is then noise.
 *   2. DISCRIMINATING. Two deliberately different functions of the same shape
 *      do NOT collide. This is the false-positive direction, the one Google's
 *      Tricorder experience says decides whether anybody keeps reading the
 *      output.
 *   3. FAIL-CLOSED. An impure function is REFUSED as a candidate. Not
 *      fingerprinted-with-a-warning; refused, with a named reason.
 *   4. SENSITIVE. A one-character behavior change moves the fingerprint.
 *
 * The candidate-selection half runs the real scanner over a small fixture
 * tree written to the group's temp directory, so it exercises the same code
 * path the whole-tree run does rather than a mock.
 */

#include "test/test_core.h"

#include "fingerprint/fingerprint.h"
#include "fingerprint/fp_runtime.h"

/* ── fixtures for the fingerprint half ───────────────────────────────────
 *
 * Two spellings of ONE behavior, pinned to different optimisation levels,
 * plus a changed version and an unrelated one. The bodies are deliberately
 * written differently so that a fingerprint match is a behavioral claim and
 * not a textual one. */

__attribute__((optimize("O0")))
static uint32_t fx_rot_o0(uint32_t x, unsigned n)
{
    unsigned k = n & 31u;
    uint32_t hi;
    uint32_t lo;
    if (k == 0u)
        return x;
    hi = x << k;
    lo = x >> (32u - k);
    return hi | lo;
}

/* Same behavior, different text, and compiled at a different level. */
__attribute__((optimize("O2")))
static uint32_t fx_rot_o2(uint32_t x, unsigned n)
{
    uint32_t v = x;
    unsigned i;
    for (i = 0; i < (n & 31u); i++)
        v = (v << 1) | (v >> 31);
    return v;
}

/* One character different: rotates by n+1. */
static uint32_t fx_rot_changed(uint32_t x, unsigned n)
{
    unsigned k = (n + 1u) & 31u;
    if (k == 0u)
        return x;
    return (x << k) | (x >> (32u - k));
}

/* Same shape, unrelated behavior. */
static uint32_t fx_unrelated(uint32_t x, unsigned n)
{
    return x ^ (uint32_t)n;
}

typedef uint32_t (*fx_fn)(uint32_t, unsigned);

/* The same corpus discipline the generated probes use: every parameter slot
 * gets its own generator seeded from the SHAPE, never from the function. */
static void fx_fingerprint(fx_fn f, uint64_t shape, uint64_t *h1, uint64_t *h2)
{
    struct fp_acc acc;
    uint32_t k;
    fp_acc_init(&acc, shape);
    for (k = 0; k < FP_ITERATIONS; k++) {
        struct fp_rng r0;
        struct fp_rng r1;
        uint32_t a0;
        unsigned a1;
        fp_rng_seed(&r0, shape ^ 0ull, k, 0ull);
        fp_rng_seed(&r1, shape ^ 0xA24BAED4963EE407ull, k, 0ull);
        a0 = (uint32_t)fp_rng_scalar(&r0, (unsigned)sizeof a0, k, 0u);
        a1 = (unsigned)fp_rng_scalar(&r1, (unsigned)sizeof a1, k, 1u);
        fp_acc_u64(&acc, 0u, (uint64_t)f(a0, a1));
    }
    *h1 = acc.h1;
    *h2 = acc.h2;
}

/* ── fixture tree for the candidate-selection half ───────────────────── */

static bool fx_write(const char *dir, const char *name, const char *body)
{
    char path[PATH_MAX];
    FILE *fh;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    fh = fopen(path, "w");
    if (fh == NULL)
        return false;
    fputs(body, fh);
    return fclose(fh) == 0;
}

static const char *const k_fixture_h =
    "#ifndef FX_H\n#define FX_H\n"
    "#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n"
    "uint32_t fx_pure_double(uint32_t v);\n"
    "uint32_t fx_reads_global(uint32_t v);\n"
    "uint32_t fx_allocates(uint32_t v);\n"
    "uint32_t fx_has_static(uint32_t v);\n"
    "int fx_variadic(const char *fmt, ...);\n"
    "uint32_t fx_calls_pure(uint32_t v);\n"
    "#endif\n";

static const char *const k_fixture_c =
    "#include \"fx.h\"\n"
    "#include <stdlib.h>\n"
    "unsigned g_fx_counter;\n"
    "uint32_t fx_pure_double(uint32_t v) { return v * 2u; }\n"
    "uint32_t fx_calls_pure(uint32_t v) { return fx_pure_double(v) + 1u; }\n"
    "uint32_t fx_reads_global(uint32_t v) { return v + g_fx_counter; }\n"
    "uint32_t fx_allocates(uint32_t v) { void *p = malloc(v); free(p);"
    " return v; }\n"
    "uint32_t fx_has_static(uint32_t v) { static unsigned n; n += v;"
    " return n; }\n"
    "int fx_variadic(const char *fmt, ...) { return (int)fmt[0]; }\n"
    "static uint32_t fx_local_only(uint32_t v) { return v ^ 3u; }\n"
    "uint32_t fx_uses_local(uint32_t v) { return fx_local_only(v); }\n";

/* The verdict a named fixture function received, or -1 when the scanner never
 * saw it. Re-derives the verdict the same way fp_index_select does, by asking
 * whether the name is in the candidate list. */
static bool fx_is_candidate(const struct fp_candidate *c, long n,
                            const char *name)
{
    long i;
    for (i = 0; i < n; i++)
        if (strcmp(c[i].name, name) == 0)
            return true;
    return false;
}

int test_fingerprint(void)
{
    int failures = 0;
    const uint64_t shape = 0x0123456789ABCDEFull;
    uint64_t a1 = 0;
    uint64_t a2 = 0;
    uint64_t b1 = 0;
    uint64_t b2 = 0;
    uint64_t c1 = 0;
    uint64_t c2 = 0;
    uint64_t d1 = 0;
    uint64_t d2 = 0;

    printf("fingerprint reproducible across two computations... ");
    fx_fingerprint(fx_rot_o0, shape, &a1, &a2);
    fx_fingerprint(fx_rot_o0, shape, &b1, &b2);
    if (a1 == b1 && a2 == b2 && (a1 != 0u || a2 != 0u)) {
        printf("OK (%016llx%016llx)\n", (unsigned long long)a1,
               (unsigned long long)a2);
    } else {
        printf("FAIL (%016llx%016llx vs %016llx%016llx)\n",
               (unsigned long long)a1, (unsigned long long)a2,
               (unsigned long long)b1, (unsigned long long)b2);
        failures++;
    }

    printf("fingerprint identical at -O0 and -O2... ");
    fx_fingerprint(fx_rot_o2, shape, &b1, &b2);
    if (a1 == b1 && a2 == b2) {
        printf("OK (%016llx%016llx)\n", (unsigned long long)b1,
               (unsigned long long)b2);
    } else {
        printf("FAIL (O0=%016llx%016llx O2=%016llx%016llx)\n",
               (unsigned long long)a1, (unsigned long long)a2,
               (unsigned long long)b1, (unsigned long long)b2);
        failures++;
    }

    printf("a deliberate behavior change moves the fingerprint... ");
    fx_fingerprint(fx_rot_changed, shape, &c1, &c2);
    if (c1 != a1 || c2 != a2) {
        printf("OK\n");
    } else {
        printf("FAIL (a rotate-by-n+1 fingerprinted the same as rotate-by-n)\n");
        failures++;
    }

    printf("two different functions of one shape do not collide... ");
    fx_fingerprint(fx_unrelated, shape, &d1, &d2);
    if ((d1 != a1 || d2 != a2) && (d1 != c1 || d2 != c2)) {
        printf("OK\n");
    } else {
        printf("FAIL (unrelated functions produced an equal fingerprint)\n");
        failures++;
    }

    printf("the corpus is a function of the SHAPE, not of the function... ");
    {
        uint64_t e1 = 0;
        uint64_t e2 = 0;
        /* A different shape must reseed the corpus, so the same function
         * under a different shape must not fingerprint the same. If it did,
         * the shape would not be reaching the generator at all. */
        fx_fingerprint(fx_rot_o0, shape ^ 1ull, &e1, &e2);
        if (e1 != a1 || e2 != a2) {
            printf("OK\n");
        } else {
            printf("FAIL (the shape does not reach the input generator)\n");
            failures++;
        }
    }

    /* ── candidate selection over a real fixture tree ── */
    {
        char dir[PATH_MAX];
        const char *files[2];
        char fh[PATH_MAX];
        char fc[PATH_MAX];
        struct fp_index *ix = NULL;
        struct fp_candidate *cands = NULL;
        size_t tally[FP_V_COUNT];
        long n = -1;

        test_make_tmpdir(dir, sizeof dir, "fingerprint", "select");
        printf("fixture tree scans... ");
        if (!fx_write(dir, "fx.h", k_fixture_h) ||
            !fx_write(dir, "fx.c", k_fixture_c)) {
            printf("FAIL (could not write the fixture tree)\n");
            failures++;
        } else {
            snprintf(fh, sizeof fh, "fx.h");
            snprintf(fc, sizeof fc, "fx.c");
            files[0] = fh;
            files[1] = fc;
            ix = fp_index_build(dir, files, 2);
            cands = (struct fp_candidate *)calloc(64, sizeof *cands);
            if (ix == NULL || cands == NULL) {
                printf("FAIL (index build)\n");
                failures++;
            } else {
                n = fp_index_select(ix, cands, 64, tally);
                printf("OK (%zu definitions, %ld candidates)\n",
                       fp_index_function_count(ix), n);
            }
        }

        if (n >= 0) {
            printf("a pure function is a candidate... ");
            if (fx_is_candidate(cands, n, "fx_pure_double")) {
                printf("OK\n");
            } else {
                printf("FAIL (fx_pure_double was not selected)\n");
                failures++;
            }

            printf("a pure function calling a pure function is a candidate... ");
            if (fx_is_candidate(cands, n, "fx_calls_pure")) {
                printf("OK\n");
            } else {
                printf("FAIL (fx_calls_pure was not selected)\n");
                failures++;
            }

            printf("an impure function is REFUSED, not fingerprinted... ");
            {
                int bad = 0;
                if (fx_is_candidate(cands, n, "fx_reads_global")) bad++;
                if (fx_is_candidate(cands, n, "fx_allocates")) bad++;
                if (fx_is_candidate(cands, n, "fx_has_static")) bad++;
                if (fx_is_candidate(cands, n, "fx_variadic")) bad++;
                if (bad == 0) {
                    printf("OK (global read, allocation, function static and "
                           "variadic all refused)\n");
                } else {
                    printf("FAIL (%d impure function(s) were selected)\n", bad);
                    failures++;
                }
            }

            printf("each refusal names a specific reason... ");
            if (tally[FP_V_IMPURE_GLOBAL] >= 1u &&
                tally[FP_V_UNRESOLVED_CALL] >= 1u &&
                tally[FP_V_FUNCTION_STATIC] >= 1u &&
                tally[FP_V_VARIADIC] >= 1u) {
                printf("OK\n");
            } else {
                printf("FAIL (global=%zu unresolved=%zu fnstatic=%zu "
                       "variadic=%zu)\n", tally[FP_V_IMPURE_GLOBAL],
                       tally[FP_V_UNRESOLVED_CALL],
                       tally[FP_V_FUNCTION_STATIC], tally[FP_V_VARIADIC]);
                failures++;
            }

            printf("a static function is refused for linkage... ");
            if (!fx_is_candidate(cands, n, "fx_local_only") &&
                tally[FP_V_STATIC_LINKAGE] >= 1u) {
                printf("OK\n");
            } else {
                printf("FAIL (a static function reached the candidate set)\n");
                failures++;
            }

            printf("the verdicts partition every definition found... ");
            {
                size_t sum = 0;
                size_t i;
                for (i = 0; i < (size_t)FP_V_COUNT; i++)
                    sum += tally[i];
                if (sum == fp_index_function_count(ix)) {
                    printf("OK (%zu)\n", sum);
                } else {
                    printf("FAIL (verdicts %zu vs definitions %zu — the "
                           "coverage number would not be an accounting)\n",
                           sum, fp_index_function_count(ix));
                    failures++;
                }
            }
        }

        free(cands);
        fp_index_free(ix);
        test_cleanup_tmpdir(dir);
    }

    return failures;
}
