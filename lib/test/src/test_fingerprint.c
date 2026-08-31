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
 *   5. REACHES FILE-LOCAL CODE WITHOUT PAYING FOR IT IN PURITY. Most of a
 *      systems tree is `static`, and a probe reaches those by compiling
 *      against the DEFINING UNIT rather than a header. The two halves of
 *      that are pinned together on purpose: a pure `static` must now be a
 *      candidate AND route through its own .c, and a `static` that touches
 *      its unit's file-scope state must still be refused, by the same named
 *      reason an externally linkable one would get. Coverage bought by
 *      relaxing (3) would be worth nothing.
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

#if defined(__clang__)
#define FX_OPT_O0 __attribute__((optnone))
#define FX_OPT_O2
#elif defined(__GNUC__)
#define FX_OPT_O0 __attribute__((optimize("O0")))
#define FX_OPT_O2 __attribute__((optimize("O2")))
#else
#define FX_OPT_O0
#define FX_OPT_O2
#endif

FX_OPT_O0
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
FX_OPT_O2
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

#undef FX_OPT_O0
#undef FX_OPT_O2

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
    "uint32_t fx_uses_local(uint32_t v) { return fx_local_only(v); }\n"
    /* File-local and impure, three different ways. Reaching a `static` by
     * including its defining unit must not buy any of these a pass: the
     * purity judgement is the same judgement it always was, and a
     * file-local function that touches its unit's state is refused with the
     * SAME named reason an externally linkable one gets. */
    "static uint32_t fx_local_reads_global(uint32_t v)"
    " { return v + g_fx_counter; }\n"
    "uint32_t fx_uses_local_global(uint32_t v)"
    " { return fx_local_reads_global(v); }\n"
    "static uint32_t fx_local_has_static(uint32_t v)"
    " { static unsigned n; n += v; return n; }\n"
    "uint32_t fx_uses_local_static(uint32_t v)"
    " { return fx_local_has_static(v); }\n"
    "static uint32_t fx_local_allocates(uint32_t v)"
    " { void *p = malloc(v); free(p); return v; }\n"
    "uint32_t fx_uses_local_alloc(uint32_t v)"
    " { return fx_local_allocates(v); }\n";

/* A second unit that owns main(). Including it into a probe translation unit
 * would define main() twice and fail the WHOLE link rather than one probe,
 * so its file-local functions have no route at all and must be refused by
 * name — however pure they are. */
static const char *const k_fixture_main_c =
    "#include \"fx.h\"\n"
    "static uint32_t fx_unreachable_pure(uint32_t v) { return v * 3u; }\n"
    "int main(void) { return (int)fx_unreachable_pure(1u); }\n";

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

static const struct fp_candidate *fx_find(const struct fp_candidate *c, long n,
                                          const char *name)
{
    long i;
    for (i = 0; i < n; i++)
        if (strcmp(c[i].name, name) == 0)
            return &c[i];
    return NULL;
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
        const char *files[3];
        struct fp_index *ix = NULL;
        struct fp_candidate *cands = NULL;
        size_t tally[FP_V_COUNT];
        long n = -1;

        test_make_tmpdir(dir, sizeof dir, "fingerprint", "select");
        printf("fixture tree scans... ");
        if (!fx_write(dir, "fx.h", k_fixture_h) ||
            !fx_write(dir, "fx.c", k_fixture_c) ||
            !fx_write(dir, "fxmain.c", k_fixture_main_c)) {
            printf("FAIL (could not write the fixture tree)\n");
            failures++;
        } else {
            files[0] = "fx.h";
            files[1] = "fx.c";
            files[2] = "fxmain.c";
            ix = fp_index_build(dir, files, 3);
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

            /* The reach this lane added. A file-local function has no
             * external linkage, so the ONLY way to call it is to compile the
             * probe against its defining unit — and the candidate has to say
             * so, because emission, link-failure attribution and the
             * per-route accounting all key off that one flag. */
            printf("a pure static function is now a candidate, reached by "
                   "including its unit... ");
            {
                const struct fp_candidate *c =
                    fx_find(cands, n, "fx_local_only");
                if (c != NULL && c->via_source &&
                    strcmp(c->include, "fx.c") == 0) {
                    printf("OK (include \"%s\")\n", c->include);
                } else if (c == NULL) {
                    printf("FAIL (a pure static was not selected at all)\n");
                    failures++;
                } else {
                    printf("FAIL (selected but routed through \"%s\", "
                           "via_source=%d — a static is not callable that "
                           "way)\n", c->include, (int)c->via_source);
                    failures++;
                }
            }

            printf("an externally linkable function still goes through its "
                   "header, not its unit... ");
            {
                const struct fp_candidate *c =
                    fx_find(cands, n, "fx_pure_double");
                if (c != NULL && !c->via_source &&
                    strcmp(c->include, "fx.h") == 0) {
                    printf("OK\n");
                } else {
                    printf("FAIL (the header route was not preferred)\n");
                    failures++;
                }
            }

            /* The refusal that must NOT have been traded away for the reach
             * above. Impurity is judged identically on both routes: a
             * file-local function that reads its unit's mutable file-scope
             * object is refused, and refused for THAT reason by name. */
            printf("a static function touching file-scope state is still "
                   "REFUSED, with a named reason... ");
            {
                int bad = 0;
                if (fx_is_candidate(cands, n, "fx_local_reads_global")) bad++;
                if (fx_is_candidate(cands, n, "fx_local_has_static")) bad++;
                if (fx_is_candidate(cands, n, "fx_local_allocates")) bad++;
                /* And the refusal must propagate: a caller of an impure
                 * static is impure too. */
                if (fx_is_candidate(cands, n, "fx_uses_local_global")) bad++;
                if (fx_is_candidate(cands, n, "fx_uses_local_static")) bad++;
                if (fx_is_candidate(cands, n, "fx_uses_local_alloc")) bad++;
                if (bad != 0) {
                    printf("FAIL (%d impure file-local function(s) or their "
                           "callers reached the candidate set)\n", bad);
                    failures++;
                } else if (tally[FP_V_IMPURE_GLOBAL] < 2u ||
                           tally[FP_V_FUNCTION_STATIC] < 2u ||
                           tally[FP_V_UNRESOLVED_CALL] < 2u) {
                    printf("FAIL (refused, but the reasons were not counted: "
                           "global=%zu fnstatic=%zu unresolved=%zu)\n",
                           tally[FP_V_IMPURE_GLOBAL],
                           tally[FP_V_FUNCTION_STATIC],
                           tally[FP_V_UNRESOLVED_CALL]);
                    failures++;
                } else {
                    printf("OK\n");
                }
            }

            /* A unit that owns main() cannot be included at all — the
             * generated driver has its own main() and the whole link would
             * fail, costing every probe rather than one. A pure static in
             * such a unit is therefore still unreachable, and says so. */
            printf("a static in a unit that owns main() is still refused for "
                   "linkage... ");
            if (!fx_is_candidate(cands, n, "fx_unreachable_pure") &&
                tally[FP_V_STATIC_LINKAGE] >= 1u) {
                printf("OK\n");
            } else {
                printf("FAIL (a static in a main()-owning unit reached the "
                       "candidate set; STATIC_LINKAGE=%zu)\n",
                       tally[FP_V_STATIC_LINKAGE]);
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
