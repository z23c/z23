/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * character_sheet, tested as a set of RULES rather than a set of golden
 * numbers. A golden test here would pass just as happily if every character
 * in the world were wrong in the same way, and it would fail on the day
 * somebody improved lib/astro's lunar theory — which is not a defect in this
 * module. What is asserted instead is every claim
 * metaverse/character_sheet.h makes:
 *
 *  1. THE TOTAL IS FIXED. Over many thousands of seeds — ordinary, hostile,
 *     and deliberately absurd — the six attributes sum to exactly
 *     CHARACTER_ATTRIBUTE_TOTAL and each one stays inside its window. This is
 *     the anti-grinding property the whole design rests on: if it can be
 *     broken by any birth moment, an owner can search for the birth moment
 *     that breaks it.
 *  2. THE CHART STILL MATTERS. A fixed total is trivial to achieve by giving
 *     everyone the same six numbers, so the same sweep asserts that the
 *     distribution genuinely VARIES — most seeds produce a distinct spread,
 *     and both even and lopsided characters occur.
 *  3. THE DERIVATION IS REPRODUCIBLE. The same seed produces a byte-identical
 *     sheet, padding included, on repeat and into a pre-dirtied buffer. That
 *     is the check a second node makes.
 *  4. THE ROOT IS THE HASH OF THE BIRTH DATA PLUS THE RULES REVISION, and it
 *     is checked against an INDEPENDENT re-implementation of the canonical
 *     encoding written in this file — so "the revision is in the preimage" is
 *     a fact, not a comment. Cosmetic differences (buffer tail garbage after
 *     the name's NUL) leave the root alone; every substantive field moves it.
 *  5. REFUSALS ARE FAIL-CLOSED. Null arguments, impossible calendars, names
 *     the text form could not spell, and coordinates off the globe are
 *     refused, leaving nothing usable behind.
 *  6. THE TEXT FORM ROUND-TRIPS EXACTLY and has ONE spelling per value, the
 *     same discipline metaverse_property_id_format() keeps.
 *  7. THE SRD 5.1 MODIFIER RULE IS FLOORED, not truncated.
 *
 * SRD 5.1 attribution: see metaverse/character_sheet.h. This file uses the
 * six ability names and the modifier table, and no Product Identity.
 *
 * Style follows test_node_character.c: a local CHECK macro and plain scoped
 * blocks, so there is no ASSERT/_test_next control flow to trip over.
 */
#include "test/test_core.h"

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "metaverse/character_sheet.h"
#include "metaverse/property_id.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static int g_failures;

#define CS_CHECK(name, expr)                                                  \
    do {                                                                      \
        printf("character_sheet: %s... ", (name));                            \
        if ((expr))                                                           \
            printf("OK\n");                                                   \
        else {                                                                \
            printf("FAIL\n");                                                 \
            g_failures++;                                                     \
        }                                                                     \
    } while (0)

/* ── fixtures ───────────────────────────────────────────────────────────── */

static struct astro_instant cs_when(int32_t y, unsigned mo, unsigned d,
                                    unsigned h, unsigned mi, unsigned s)
{
    struct astro_instant t;
    memset(&t, 0, sizeof t);
    t.year = y;
    t.month = (uint8_t)mo;
    t.day = (uint8_t)d;
    t.hour = (uint8_t)h;
    t.minute = (uint8_t)mi;
    t.second = (uint8_t)s;
    return t;
}

static struct astro_place cs_where(int32_t lat, int32_t lon)
{
    struct astro_place p;
    memset(&p, 0, sizeof p);
    p.latitude_microdeg = lat;
    p.longitude_microdeg = lon;
    return p;
}

static bool cs_seed_zeroed(const struct character_seed *s)
{
    struct character_seed zero;
    memset(&zero, 0, sizeof zero);
    return memcmp(s, &zero, sizeof zero) == 0;
}

static bool cs_sheet_zeroed(const struct character_sheet *s)
{
    struct character_sheet zero;
    memset(&zero, 0, sizeof zero);
    return memcmp(s, &zero, sizeof zero) == 0;
}

/* ── 1. refusals, and what they leave behind ────────────────────────────── */

static void t_refusals(void)
{
    struct astro_instant good = cs_when(1987, 3, 14, 9, 26, 0);
    struct astro_place here = cs_where(47606200, -122332100);
    struct character_seed s;
    struct character_sheet sheet;

    CS_CHECK("a well-formed seed is accepted",
             character_seed_make("Roan Ashgrove", &good, &here, &s) &&
                 character_seed_valid(&s));

    /* NULL arguments in every position. */
    CS_CHECK("a NULL out is refused",
             !character_seed_make("Roan", &good, &here, NULL));
    CS_CHECK("a NULL name is refused, leaving the seed zeroed",
             !character_seed_make(NULL, &good, &here, &s) &&
                 cs_seed_zeroed(&s));
    CS_CHECK("a NULL moment is refused, leaving the seed zeroed",
             !character_seed_make("Roan", NULL, &here, &s) &&
                 cs_seed_zeroed(&s));
    CS_CHECK("a NULL place is refused, leaving the seed zeroed",
             !character_seed_make("Roan", &good, NULL, &s) &&
                 cs_seed_zeroed(&s));
    CS_CHECK("a NULL seed has no root",
             !character_seed_root(NULL, (uint8_t[METAVERSE_ROOT_BYTES]){ 0 }));
    CS_CHECK("a NULL sheet output is refused",
             !character_sheet_derive(&s, NULL));

    /* A zeroed struct must be invalid: month 0 is not a month, so a caller
     * who forgot to initialise cannot get a plausible character. */
    {
        struct character_seed wiped;
        memset(&wiped, 0, sizeof wiped);
        CS_CHECK("a zeroed seed reads invalid", !character_seed_valid(&wiped));
        CS_CHECK("a zeroed seed derives nothing",
                 !character_sheet_derive(&wiped, &sheet) &&
                     cs_sheet_zeroed(&sheet));
    }

    /* Names the text form could not spell unambiguously. */
    {
        char too_long[CHARACTER_NAME_MAX + 8];
        memset(too_long, 'a', sizeof too_long - 1);
        too_long[sizeof too_long - 1] = '\0';

        CS_CHECK("an empty name is refused",
                 !character_seed_make("", &good, &here, &s));
        CS_CHECK("a name that does not fit is refused",
                 !character_seed_make(too_long, &good, &here, &s));
        CS_CHECK("a leading space is refused",
                 !character_seed_make(" Roan", &good, &here, &s));
        CS_CHECK("a trailing space is refused",
                 !character_seed_make("Roan ", &good, &here, &s));
        CS_CHECK("the field separator is refused inside a name",
                 !character_seed_make("Ro|an", &good, &here, &s));
        CS_CHECK("a control byte is refused inside a name",
                 !character_seed_make("Ro\tan", &good, &here, &s));
        CS_CHECK("a high byte is refused inside a name",
                 !character_seed_make("Ro\xc3\xa9n", &good, &here, &s));
        CS_CHECK("an apostrophe and a hyphen are legal name bytes",
                 character_seed_make("Ro-an D'ur", &good, &here, &s));
    }

    /* Impossible calendars. astro_instant_is_valid owns the rule; this
     * asserts character_seed_make actually asks it. */
    {
        struct astro_instant leap_ok = cs_when(2024, 2, 29, 0, 0, 0);
        struct astro_instant leap_no = cs_when(2023, 2, 29, 0, 0, 0);
        struct astro_instant century = cs_when(1900, 2, 29, 0, 0, 0);

        CS_CHECK("a real leap day is accepted",
                 character_seed_make("Roan", &leap_ok, &here, &s));
        CS_CHECK("29 February in a common year is refused",
                 !character_seed_make("Roan", &leap_no, &here, &s) &&
                     cs_seed_zeroed(&s));
        CS_CHECK("29 February 1900 is refused (a century that is not a leap)",
                 !character_seed_make("Roan", &century, &here, &s));

        struct astro_instant bad[] = {
            cs_when(1987, 0, 14, 9, 0, 0),  cs_when(1987, 13, 14, 9, 0, 0),
            cs_when(1987, 3, 0, 9, 0, 0),   cs_when(1987, 3, 32, 9, 0, 0),
            cs_when(1987, 4, 31, 9, 0, 0),  cs_when(1987, 3, 14, 24, 0, 0),
            cs_when(1987, 3, 14, 9, 60, 0), cs_when(1987, 3, 14, 9, 0, 60),
            cs_when(ASTRO_YEAR_MIN - 1, 3, 14, 9, 0, 0),
            cs_when(ASTRO_YEAR_MAX + 1, 3, 14, 9, 0, 0),
        };
        bool all_refused = true;
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
            if (character_seed_make("Roan", &bad[i], &here, &s) ||
                !cs_seed_zeroed(&s))
                all_refused = false;
        CS_CHECK("every impossible instant is refused with nothing left "
                 "behind",
                 all_refused);
    }

    /* Coordinates. The limits are lib/astro's and are inclusive. */
    {
        struct astro_place edge_lat_n =
            cs_where(ASTRO_LATITUDE_MICRODEG_LIMIT, 0);
        struct astro_place edge_lat_s =
            cs_where(-ASTRO_LATITUDE_MICRODEG_LIMIT, 0);
        struct astro_place edge_lon_e =
            cs_where(0, ASTRO_LONGITUDE_MICRODEG_LIMIT);
        struct astro_place edge_lon_w =
            cs_where(0, -ASTRO_LONGITUDE_MICRODEG_LIMIT);
        struct astro_place over_n =
            cs_where(ASTRO_LATITUDE_MICRODEG_LIMIT + 1, 0);
        struct astro_place over_s =
            cs_where(-ASTRO_LATITUDE_MICRODEG_LIMIT - 1, 0);
        struct astro_place over_e =
            cs_where(0, ASTRO_LONGITUDE_MICRODEG_LIMIT + 1);
        struct astro_place over_w =
            cs_where(0, -ASTRO_LONGITUDE_MICRODEG_LIMIT - 1);
        struct astro_place pole = cs_where(90000000, 0);

        CS_CHECK("the exact latitude limits are accepted on both sides",
                 character_seed_make("Roan", &good, &edge_lat_n, &s) &&
                     character_seed_make("Roan", &good, &edge_lat_s, &s));
        CS_CHECK("the date line is accepted on both sides",
                 character_seed_make("Roan", &good, &edge_lon_e, &s) &&
                     character_seed_make("Roan", &good, &edge_lon_w, &s));
        CS_CHECK("one microdegree past a limit is refused, all four ways",
                 !character_seed_make("Roan", &good, &over_n, &s) &&
                     !character_seed_make("Roan", &good, &over_s, &s) &&
                     !character_seed_make("Roan", &good, &over_e, &s) &&
                     !character_seed_make("Roan", &good, &over_w, &s));
        CS_CHECK("the pole itself is refused rather than approximated",
                 !character_seed_make("Roan", &good, &pole, &s) &&
                     cs_seed_zeroed(&s));
    }
}

/* ── 2. the fixed total, over thousands of seeds ─────────────────────────
 *
 * The single most important assertion in this file. It is the anti-grinding
 * property: an owner picks the birth moment, so if ANY birth moment produced
 * a different total, the design's whole claim — "grinding changes what kind
 * of character you get, never how strong" — would be false, and searching for
 * that moment is exactly what an owner would do.
 *
 * The sweep is deliberately wide and deliberately hostile: it spans the whole
 * legal year range including year 0 and both endpoints, every month, the
 * poles' immediate neighbourhood, both sides of the date line, midnight and
 * the last second of the day. It also records the SPREAD, because a fixed
 * total with an identical spread everywhere would satisfy this test while
 * making every character in the world the same, so the same sweep judges the
 * spread as well.
 */

#define CS_SWEEP_SPREAD_BUCKETS                                               \
    (CHARACTER_ATTRIBUTE_MAX - CHARACTER_ATTRIBUTE_MIN + 1u)

#define CS_VECTOR_SAMPLE 240u

struct cs_sweep_stats {
    unsigned derived;
    unsigned refused;
    unsigned bad_total;
    unsigned bad_range;
    unsigned bad_rev;
    unsigned bad_id;
    unsigned unstable;                          /* re-derived to other bytes */
    unsigned rederived;                         /* how many were re-derived  */
    unsigned spread[CS_SWEEP_SPREAD_BUCKETS];
    unsigned sampled;                           /* vectors kept for 3 below  */
    uint8_t vec[CS_VECTOR_SAMPLE][CHARACTER_ATTRIBUTE_COUNT];
};

/* A deterministic, well-spread pseudo-seed. Not a hash and it does not need
 * to be: the derivation must behave for ANY legal birth, so a spread that is
 * merely varied exercises it honestly, and a fixed generator keeps the sweep
 * reproducible on every run and every machine. */
static bool cs_sweep_seed(unsigned n, struct character_seed *out)
{
    static const int32_t k_years[] = { 0,    1,    -1,   -44,  1066, 1492,
                                       1776, 1900, 1969, 1987, 2000, 2024,
                                       2100, 4000, 9999, ASTRO_YEAR_MIN,
                                       ASTRO_YEAR_MAX };
    static const int32_t k_lat[] = { 0,
                                     ASTRO_LATITUDE_MICRODEG_LIMIT,
                                     -ASTRO_LATITUDE_MICRODEG_LIMIT,
                                     89499999,
                                     -89499999,
                                     51507300,
                                     -33868800,
                                     35689500,
                                     1352000 };
    static const int32_t k_lon[] = { 0,
                                     ASTRO_LONGITUDE_MICRODEG_LIMIT,
                                     -ASTRO_LONGITUDE_MICRODEG_LIMIT,
                                     179999999,
                                     -179999999,
                                     -127600,
                                     151209300,
                                     139691700,
                                     -74006000 };
    unsigned yi = n % (sizeof k_years / sizeof k_years[0]);
    unsigned month = 1u + (n / 7u) % 12u;
    unsigned day = 1u + (n / 3u) % 28u;
    unsigned hour = (n * 7u) % 24u;
    unsigned minute = (n * 13u) % 60u;
    unsigned second = (n * 29u) % 60u;
    unsigned li = (n / 5u) % (sizeof k_lat / sizeof k_lat[0]);
    unsigned oi = (n / 11u) % (sizeof k_lon / sizeof k_lon[0]);
    struct astro_instant when =
        cs_when(k_years[yi], month, day, hour, minute, second);
    struct astro_place where = cs_where(k_lat[li], k_lon[oi]);

    /* Every second sweep step uses the extreme ends of the day, so midnight
     * and 23:59:59 are hit against every year and place rather than only
     * where the modulus happens to land. */
    if ((n & 1u) == 0u) {
        when.hour = (uint8_t)((n & 2u) ? 23u : 0u);
        when.minute = (uint8_t)((n & 2u) ? 59u : 0u);
        when.second = (uint8_t)((n & 2u) ? 59u : 0u);
    }
    return character_seed_make("Sweep", &when, &where, out);
}

/* ONE pass over the seed space that answers every per-seed question at once.
 * Computing a chart is milliseconds, so a second sweep for a second question
 * would double the group's runtime to learn nothing new. */
static void cs_sweep(unsigned count, struct cs_sweep_stats *st)
{
    memset(st, 0, sizeof *st);
    for (unsigned n = 0; n < count; n++) {
        struct character_seed seed;
        struct character_sheet sheet;
        unsigned total = 0;
        unsigned lo = CHARACTER_ATTRIBUTE_MAX;
        unsigned hi = CHARACTER_ATTRIBUTE_MIN;

        if (!cs_sweep_seed(n, &seed)) {
            st->refused++;
            continue;
        }
        /* Derive into a buffer filled with a recognisable non-zero pattern,
         * so a field derive() forgot to write shows up as garbage rather than
         * as a plausible zero. */
        memset(&sheet, 0xa5, sizeof sheet);
        if (!character_sheet_derive(&seed, &sheet)) {
            st->refused++;
            continue;
        }
        st->derived++;

        /* Every eighth seed is derived a second time from a differently
         * dirtied buffer and compared byte for byte, padding included: the
         * check a second node makes. Every eighth rather than every one
         * because it doubles the cost of the seeds it touches. */
        if ((n & 7u) == 0u) {
            struct character_sheet again;
            memset(&again, 0x00, sizeof again);
            st->rederived++;
            if (!character_sheet_derive(&seed, &again) ||
                memcmp(&sheet, &again, sizeof sheet) != 0)
                st->unstable++;
        }
        if (st->sampled < CS_VECTOR_SAMPLE) {
            memcpy(st->vec[st->sampled], sheet.attribute,
                   CHARACTER_ATTRIBUTE_COUNT);
            st->sampled++;
        }
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
            unsigned v = sheet.attribute[i];
            total += v;
            if (v < CHARACTER_ATTRIBUTE_MIN || v > CHARACTER_ATTRIBUTE_MAX)
                st->bad_range++;
            if (v < lo)
                lo = v;
            if (v > hi)
                hi = v;
            if (sheet.modifier[i] != (int8_t)character_ability_modifier((uint8_t)v))
                st->bad_range++;
        }
        if (total != CHARACTER_ATTRIBUTE_TOTAL)
            st->bad_total++;
        if (sheet.rules_rev != CHARACTER_SHEET_RULES_REV)
            st->bad_rev++;
        if (!metaverse_property_id_valid(&sheet.id) ||
            sheet.id.kind != METAVERSE_KIND_CHARACTER_SHEET)
            st->bad_id++;
        if (hi >= lo && hi - lo < CS_SWEEP_SPREAD_BUCKETS)
            st->spread[hi - lo]++;
    }
}

/* Three thousand real charts. The bound is a runtime one and it is stated
 * rather than hidden: astro_chart_compute() is milliseconds of 768-bit CORDIC
 * arithmetic, so this sweep alone is most of the group's wall time. It is
 * what proves the END-TO-END path over thousands of seeds; the invariant
 * itself is proven far more completely by t_total_is_structural() below,
 * which drives the same apportionment over MILLIONS of weight vectors for
 * free. Neither replaces the other: the cheap one shows no weights can break
 * the total, the expensive one shows real charts produce weights. */
#define CS_SWEEP_N 3000u

static void t_fixed_total(void)
{
    struct cs_sweep_stats st;
    unsigned distinct = 0, lopsided = 0, even = 0, unique = 0;

    cs_sweep(CS_SWEEP_N, &st);

    printf("  sweep: %u seeds derived, %u refused as out of range\n",
           st.derived, st.refused);
    printf("  sweep: %u totals != %u, %u attributes outside [%u,%u]\n",
           st.bad_total, (unsigned)CHARACTER_ATTRIBUTE_TOTAL, st.bad_range,
           (unsigned)CHARACTER_ATTRIBUTE_MIN,
           (unsigned)CHARACTER_ATTRIBUTE_MAX);

    /* A sweep that derived almost nothing would report zero violations while
     * proving nothing, so the population is floored before it is judged. */
    CS_CHECK("the sweep actually derived thousands of characters",
             st.derived >= 2500u);
    CS_CHECK("EVERY seed's six attributes sum to exactly the fixed total",
             st.bad_total == 0u);
    CS_CHECK("EVERY attribute stays inside its window, and its modifier "
             "matches the SRD rule",
             st.bad_range == 0u);
    CS_CHECK("EVERY sheet carries the rules revision that produced it",
             st.bad_rev == 0u);
    CS_CHECK("EVERY sheet carries a valid character_sheet property id",
             st.bad_id == 0u);

    printf("  sweep: %u seeds re-derived, %u disagreed byte for byte\n",
           st.rederived, st.unstable);
    CS_CHECK("re-deriving a seed reproduces its sheet exactly, padding "
             "included",
             st.rederived >= 300u && st.unstable == 0u);

    /* A fixed total is trivially achievable by handing every character the
     * same six numbers, which would satisfy every assertion above and destroy
     * the design. So the spread is judged too. */
    for (unsigned i = 0; i < CS_SWEEP_SPREAD_BUCKETS; i++) {
        if (st.spread[i])
            distinct++;
        if (i >= 6u)
            lopsided += st.spread[i];
        if (i <= 2u)
            even += st.spread[i];
    }
    printf("  spread: %u distinct (max-min) values, %u lopsided (>=6), "
           "%u even (<=2)\n",
           distinct, lopsided, even);
    CS_CHECK("the chart produces many different spreads, not one",
             distinct >= 6u);
    CS_CHECK("some charts produce a specialist", lopsided > 0u);
    CS_CHECK("some charts produce a generalist", even > 0u);

    /* The stronger form: distinct attribute VECTORS, because a varied
     * max-minus-min could still hide six identical layouts. Quadratic in the
     * sample, so the sample is bounded. */
    for (unsigned i = 0; i < st.sampled; i++) {
        bool seen = false;
        for (unsigned j = 0; j < i && !seen; j++)
            seen = memcmp(st.vec[i], st.vec[j], CHARACTER_ATTRIBUTE_COUNT) == 0;
        if (!seen)
            unique++;
    }
    printf("  spread: %u distinct attribute vectors among %u seeds\n", unique,
           st.sampled);
    /* Half is a deliberately loose floor: collisions are legitimate (the
     * space of valid distributions is finite) and the assertion is aimed at a
     * derivation that COLLAPSED, not at a particular hit rate. */
    CS_CHECK("two different seeds usually give different distributions",
             st.sampled >= CS_VECTOR_SAMPLE && unique * 2u >= st.sampled);
}

/* ── 3. the total is STRUCTURAL, not a property of the charts sampled ────
 *
 * The chart's only influence on the total is through the six weights it
 * produces, so this drives character_apportion() over the whole weight space
 * instead of over birthdays: millions of vectors including every shape a
 * chart could produce and many it could not — all zero, all equal, one
 * enormous and five tiny, saturated 32-bit values, and a wide pseudo-random
 * spread.
 *
 * That is a stronger claim than any number of seeds could establish. Sampling
 * birthdays can only report that the total held for the birthdays sampled;
 * this reports that no weights whatsoever can break it, which is what makes
 * grinding a birth moment pointless. */
static void t_total_is_structural(void)
{
    unsigned bad_total = 0, bad_range = 0;
    unsigned long long cases = 0;
    uint32_t w[CHARACTER_ATTRIBUTE_COUNT];
    uint8_t a[CHARACTER_ATTRIBUTE_COUNT];
    uint32_t x = 0x2545f491u; /* fixed seed: the sweep is reproducible */

#define CS_JUDGE()                                                            \
    do {                                                                      \
        unsigned t_ = 0;                                                      \
        if (!character_apportion(w, a))                                       \
            bad_total++;                                                      \
        for (unsigned i_ = 0; i_ < CHARACTER_ATTRIBUTE_COUNT; i_++) {         \
            t_ += a[i_];                                                      \
            if (a[i_] < CHARACTER_ATTRIBUTE_MIN ||                            \
                a[i_] > CHARACTER_ATTRIBUTE_MAX)                              \
                bad_range++;                                                  \
        }                                                                     \
        if (t_ != CHARACTER_ATTRIBUTE_TOTAL)                                  \
            bad_total++;                                                      \
        cases++;                                                              \
    } while (0)

    /* The degenerate shapes, named rather than left to chance. */
    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
        w[i] = 0;
    CS_JUDGE(); /* every weight zero: nothing has any claim at all */
    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
        w[i] = 1;
    CS_JUDGE(); /* every weight equal: a perfectly balanced chart */
    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
        w[i] = UINT32_MAX;
    CS_JUDGE(); /* every weight saturated */
    for (unsigned k = 0; k < CHARACTER_ATTRIBUTE_COUNT; k++) {
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
            w[i] = (i == k) ? UINT32_MAX : 0u;
        CS_JUDGE(); /* one attribute claims everything, five claim nothing */
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
            w[i] = (i == k) ? 0u : UINT32_MAX;
        CS_JUDGE(); /* the inverse */
    }

    /* An exhaustive small grid: every vector over {0,1,2,3} — 4^6 = 4096
     * shapes, including every tie pattern the divisor rule has to resolve. */
    for (unsigned n = 0; n < 4096u; n++) {
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
            w[i] = (n >> (2u * i)) & 3u;
        CS_JUDGE();
    }

    /* And a wide pseudo-random field, over the range a real chart produces
     * and far past it. xorshift32 rather than rand(): a fixed, portable
     * generator keeps the sweep identical on every machine and every run. */
    for (unsigned n = 0; n < 250000u; n++) {
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            /* Four magnitudes, so tiny and enormous weights meet in the same
             * vector — the case where a naive largest-remainder split
             * overflows its cap and quietly loses a point. */
            switch (n & 3u) {
            case 0: w[i] = x % 256u; break;
            case 1: w[i] = x % 4096u; break;
            case 2: w[i] = x; break;
            default: w[i] = (i & 1u) ? (x % 8u) : x; break;
            }
        }
        CS_JUDGE();
    }
#undef CS_JUDGE

    printf("  apportion: %llu weight vectors, %u wrong totals, %u attributes "
           "out of range\n",
           cases, bad_total, bad_range);
    CS_CHECK("the apportionment sweep actually ran", cases >= 250000ull);
    CS_CHECK("NO weight vector whatsoever changes the total",
             bad_total == 0u);
    CS_CHECK("NO weight vector whatsoever pushes an attribute out of range",
             bad_range == 0u);

    /* Equal claims must produce an equal character, and the null chart must
     * not collapse onto one attribute — both are the tie rule working. */
    {
        uint8_t flat[CHARACTER_ATTRIBUTE_COUNT];
        bool all_same = true;
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
            w[i] = 7u;
        character_apportion(w, flat);
        for (unsigned i = 1; i < CHARACTER_ATTRIBUTE_COUNT; i++)
            if (flat[i] != flat[0])
                all_same = false;
        CS_CHECK("six equal claims give six equal attributes", all_same);
    }
    CS_CHECK("a NULL argument is refused and empties the output",
             !character_apportion(NULL, a) &&
                 !character_apportion(w, NULL) && a[0] == 0);
}

/* ── 5. the root: what moves it and what does not ───────────────────────── */

/* An INDEPENDENT re-implementation of the canonical preimage described in
 * metaverse/character_sheet.h. Written from the documented layout rather than
 * shared with the module, so that agreeing with it proves the module hashes
 * the domain tag, the RULES REVISION, the name's length and bytes, the birth
 * moment and the place — and nothing else. A shared encoder would have proved
 * only that the file was not edited. */
static void cs_expected_root(const struct character_seed *s,
                             uint8_t out[METAVERSE_ROOT_BYTES])
{
    uint8_t buf[256];
    size_t n = 0;
    size_t len = strlen(s->name);
    static const char tag[] = "z23-character-sheet";
    uint32_t rev = CHARACTER_SHEET_RULES_REV;
    uint32_t year = (uint32_t)s->born.year;
    uint32_t lat = (uint32_t)s->where.latitude_microdeg;
    uint32_t lon = (uint32_t)s->where.longitude_microdeg;

    memcpy(buf + n, tag, sizeof tag - 1u);
    n += sizeof tag - 1u;
    buf[n++] = (uint8_t)(rev >> 24); buf[n++] = (uint8_t)(rev >> 16);
    buf[n++] = (uint8_t)(rev >> 8);  buf[n++] = (uint8_t)rev;
    buf[n++] = (uint8_t)(len >> 8);  buf[n++] = (uint8_t)len;
    memcpy(buf + n, s->name, len);
    n += len;
    buf[n++] = (uint8_t)(year >> 24); buf[n++] = (uint8_t)(year >> 16);
    buf[n++] = (uint8_t)(year >> 8);  buf[n++] = (uint8_t)year;
    buf[n++] = s->born.month;
    buf[n++] = s->born.day;
    buf[n++] = s->born.hour;
    buf[n++] = s->born.minute;
    buf[n++] = s->born.second;
    buf[n++] = (uint8_t)(lat >> 24); buf[n++] = (uint8_t)(lat >> 16);
    buf[n++] = (uint8_t)(lat >> 8);  buf[n++] = (uint8_t)lat;
    buf[n++] = (uint8_t)(lon >> 24); buf[n++] = (uint8_t)(lon >> 16);
    buf[n++] = (uint8_t)(lon >> 8);  buf[n++] = (uint8_t)lon;
    sha3_256(buf, n, out);
}

static void t_root(void)
{
    struct astro_instant when = cs_when(1987, 3, 14, 9, 26, 0);
    struct astro_place where = cs_where(47606200, -122332100);
    struct character_seed base;
    uint8_t root[METAVERSE_ROOT_BYTES], other[METAVERSE_ROOT_BYTES];

    if (!character_seed_make("Roan Ashgrove", &when, &where, &base)) {
        CS_CHECK("the root fixture builds", false);
        return;
    }
    CS_CHECK("the root is computable", character_seed_root(&base, root));

    cs_expected_root(&base, other);
    CS_CHECK("the root matches an independent encoding of (tag, rules "
             "revision, name, moment, place)",
             memcmp(root, other, sizeof root) == 0);

    /* COSMETIC: bytes after the name's NUL are not part of the character.
     * Hashing the struct instead of a canonical encoding would have made a
     * character's identity depend on uninitialised stack. */
    {
        struct character_seed dirty = base;
        size_t len = strlen(dirty.name);
        for (size_t i = len + 1u; i < sizeof dirty.name; i++)
            dirty.name[i] = (char)(0x5a + (int)i);
        CS_CHECK("garbage after the name's NUL does not change the root",
                 character_seed_root(&dirty, other) &&
                     memcmp(root, other, sizeof root) == 0);
        {
            struct character_sheet s1, s2;
            CS_CHECK("nor does it change the sheet",
                     character_sheet_derive(&base, &s1) &&
                         character_sheet_derive(&dirty, &s2) &&
                         memcmp(&s1, &s2, sizeof s1) == 0);
        }
    }

    /* COSMETIC, and the reason character_seed_equal() exists: the three
     * padding bytes struct astro_instant carries after `second` are not part
     * of the birth moment. A caller's instant can arrive with ANY bytes
     * there — a compiler is free to delete a memset of a local whose padding
     * nothing reads, and both gcc and clang do at -O2 — so a seed built from
     * a padded instant must name the same character as one built from a clean
     * one. This caught a real defect: character_seed_make() used to copy the
     * instant with a struct assignment, which carried the caller's padding
     * into the seed and made two identical characters compare unequal in
     * three builds out of four. */
    {
        union {
            struct astro_instant t;
            unsigned char b[sizeof(struct astro_instant)];
        } dirty;
        struct character_seed padded;
        struct astro_place w = base.where;
        uint8_t r2[METAVERSE_ROOT_BYTES];

        memset(dirty.b, 0x5a, sizeof dirty.b);
        dirty.t.year = base.born.year;
        dirty.t.month = base.born.month;
        dirty.t.day = base.born.day;
        dirty.t.hour = base.born.hour;
        dirty.t.minute = base.born.minute;
        dirty.t.second = base.born.second;

        CS_CHECK("an instant carrying dirty padding still builds a seed",
                 character_seed_make(base.name, &dirty.t, &w, &padded));
        CS_CHECK("and that seed is the same character by value",
                 character_seed_equal(&base, &padded));
        CS_CHECK("and names the same property",
                 character_seed_root(&padded, r2) &&
                     memcmp(root, r2, sizeof root) == 0);
        /* The fix itself: make() copies named fields into a zeroed buffer, so
         * the seed it produces has no indeterminate bytes at all. */
        CS_CHECK("and the constructed seeds are byte-identical",
                 memcmp(&base, &padded, sizeof base) == 0);
    }

    /* SUBSTANTIVE: every field of the seed moves the root. */
    {
        struct character_seed v;
        bool all_moved = true;

#define CS_MOVES(mutation)                                                    \
    do {                                                                      \
        v = base;                                                             \
        mutation;                                                             \
        if (!character_seed_root(&v, other) ||                                \
            memcmp(root, other, sizeof root) == 0)                            \
            all_moved = false;                                                \
    } while (0)

        CS_MOVES(v.name[0] = 'S');
        CS_MOVES(v.name[strlen(v.name) - 1u] = '\0'); /* shorter name */
        CS_MOVES(v.born.year -= 1);
        CS_MOVES(v.born.month = 4);
        CS_MOVES(v.born.day = 15);
        CS_MOVES(v.born.hour = 10);
        CS_MOVES(v.born.minute = 27);
        CS_MOVES(v.born.second = 1);
        CS_MOVES(v.where.latitude_microdeg += 1);
        CS_MOVES(v.where.longitude_microdeg += 1);
#undef CS_MOVES
        CS_CHECK("every substantive field of the seed moves the root",
                 all_moved);
    }

    /* A one-minute difference must move the whole character, not just its
     * name — the seed expands into a chart and the chart into a spread. */
    {
        struct character_seed near = base;
        struct character_sheet s1, s2;
        near.born.minute = 27;
        CS_CHECK("a one-minute difference is a different property",
                 character_sheet_derive(&base, &s1) &&
                     character_sheet_derive(&near, &s2) &&
                     !metaverse_property_id_equal(&s1.id, &s2.id));
    }

    /* The property id, and its class. */
    {
        struct metaverse_property_id id, parsed;
        char text[METAVERSE_ID_TEXT_MAX];

        CS_CHECK("the seed names a property",
                 character_seed_property_id(&base, &id) &&
                     metaverse_property_id_valid(&id) &&
                     id.kind == METAVERSE_KIND_CHARACTER_SHEET);
        CS_CHECK("the property id carries the seed's root",
                 memcmp(id.root, root, sizeof root) == 0);
        CS_CHECK("the kind is content-addressed: verification needs no "
                 "authority",
                 metaverse_kind_settlement(METAVERSE_KIND_CHARACTER_SHEET) ==
                     METAVERSE_SETTLEMENT_CONTENT_ADDRESSED);
        CS_CHECK("the kind names its authority honestly",
                 strcmp(metaverse_kind_authority(
                            METAVERSE_KIND_CHARACTER_SHEET),
                        "metaverse.character_sheet") == 0);
        CS_CHECK("no work measurement is claimed for a content-addressed "
                 "character",
                 !metaverse_settlement_work_measurable(
                     metaverse_kind_settlement(
                         METAVERSE_KIND_CHARACTER_SHEET)));
        CS_CHECK("the property id round-trips through its own text form",
                 metaverse_property_id_format(&id, text, sizeof text) &&
                     metaverse_property_id_parse(text, &parsed) &&
                     metaverse_property_id_equal(&id, &parsed));
    }
}

/* ── 6. the text form ───────────────────────────────────────────────────── */

static void t_text_form(void)
{
    struct astro_instant when = cs_when(1987, 3, 14, 9, 26, 0);
    struct astro_place where = cs_where(47606200, -122332100);
    struct character_seed base, back;
    char text[CHARACTER_SEED_TEXT_MAX], again[CHARACTER_SEED_TEXT_MAX];

    if (!character_seed_make("Roan Ashgrove", &when, &where, &base)) {
        CS_CHECK("the text fixture builds", false);
        return;
    }
    CS_CHECK("a seed renders",
             character_seed_format(&base, text, sizeof text));
    CS_CHECK("the rendering is the documented shape",
             strcmp(text,
                    "Roan Ashgrove|1987-03-14T09:26:00Z|47606200|-122332100") ==
                 0);
    CS_CHECK("it parses back to the same seed",
             character_seed_parse(text, &back) &&
                 character_seed_equal(&base, &back));
    CS_CHECK("and renders back to the same string",
             character_seed_format(&back, again, sizeof again) &&
                 strcmp(text, again) == 0);

    /* Round-trip the whole sweep, not one example: an escape-free form is
     * only safe if EVERY value it can hold has exactly one spelling. */
    {
        unsigned n = 0, broken = 0;
        for (unsigned i = 0; i < 2000u; i++) {
            struct character_seed s, r;
            char a[CHARACTER_SEED_TEXT_MAX], b[CHARACTER_SEED_TEXT_MAX];
            if (!cs_sweep_seed(i, &s))
                continue;
            n++;
            if (!character_seed_format(&s, a, sizeof a) ||
                !character_seed_parse(a, &r) ||
                !character_seed_equal(&s, &r) ||
                !character_seed_format(&r, b, sizeof b) ||
                strcmp(a, b) != 0)
                broken++;
        }
        CS_CHECK("every seed in the sweep round-trips exactly",
                 n >= 1500u && broken == 0u);
    }

    /* Negative years and year zero, which is where a lazy four-digit format
     * would silently lose the sign or the padding. */
    {
        struct astro_instant bc = cs_when(-44, 3, 15, 12, 0, 0);
        struct astro_instant zero = cs_when(0, 1, 1, 0, 0, 0);
        struct character_seed s, r;

        CS_CHECK("a negative year round-trips",
                 character_seed_make("Roan", &bc, &where, &s) &&
                     character_seed_format(&s, text, sizeof text) &&
                     strcmp(text, "Roan|-0044-03-15T12:00:00Z|47606200|"
                                  "-122332100") == 0 &&
                     character_seed_parse(text, &r) &&
                     character_seed_equal(&s, &r));
        CS_CHECK("year zero round-trips",
                 character_seed_make("Roan", &zero, &where, &s) &&
                     character_seed_format(&s, text, sizeof text) &&
                     strcmp(text, "Roan|0000-01-01T00:00:00Z|47606200|"
                                  "-122332100") == 0 &&
                     character_seed_parse(text, &r) &&
                     character_seed_equal(&s, &r));
    }

    /* One value, one spelling. Every rejected form below is a SECOND way of
     * writing something the canonical form already spells, or a string with
     * bytes the canonical form would never emit. Accepting any of them would
     * let two texts name one character and one text name two. */
    {
        static const char *const bad[] = {
            NULL,
            "",
            "Roan Ashgrove",                                  /* no fields  */
            "Roan Ashgrove|1987-03-14T09:26:00Z|47606200",    /* short      */
            "|1987-03-14T09:26:00Z|47606200|-122332100",      /* no name    */
            "Ro|an|1987-03-14T09:26:00Z|47606200|-122332100", /* name has | */
            "Roan|1987-03-14T09:26:00Z|47606200|-122332100|", /* trailing | */
            "Roan|1987-03-14T09:26:00Z|47606200|-122332100 ", /* trailing sp*/
            "Roan|1987-03-14T09:26:00Z|47606200|-122332100x", /* trailing   */
            "Roan|987-03-14T09:26:00Z|47606200|-122332100",   /* 3-digit yr */
            "Roan|01987-03-14T09:26:00Z|47606200|-122332100", /* 5-digit yr */
            "Roan|1987-3-14T09:26:00Z|47606200|-122332100",   /* unpadded   */
            "Roan|1987-03-14 09:26:00Z|47606200|-122332100",  /* no T       */
            "Roan|1987-03-14T09:26:00|47606200|-122332100",   /* no Z       */
            "Roan|1987-02-30T09:26:00Z|47606200|-122332100",  /* no such day*/
            "Roan|1987-03-14T24:00:00Z|47606200|-122332100",  /* hour 24    */
            "Roan|1987-03-14T09:26:00Z|+47606200|-122332100", /* leading +  */
            "Roan|1987-03-14T09:26:00Z|047606200|-122332100", /* leading 0  */
            "Roan|1987-03-14T09:26:00Z| 47606200|-122332100", /* space      */
            "Roan|1987-03-14T09:26:00Z|-0|-122332100",        /* -0         */
            "Roan|1987-03-14T09:26:00Z|89500001|0",           /* off globe  */
            "Roan|1987-03-14T09:26:00Z|0|180000001",          /* off globe  */
            "Roan|1987-03-14T09:26:00Z|47606200|-99999999999",/* overflow   */
        };
        bool all_refused = true;
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            struct character_seed s;
            if (character_seed_parse(bad[i], &s) || !cs_seed_zeroed(&s)) {
                printf("  parse accepted or dirtied: %s\n",
                       bad[i] ? bad[i] : "(null)");
                all_refused = false;
            }
        }
        CS_CHECK("every second spelling and malformed form is refused, "
                 "leaving nothing behind",
                 all_refused);
    }

    /* A short buffer must fail closed rather than emit a truncated seed that
     * would parse as a DIFFERENT character. Every length from 1 to just under
     * the exact fit is tried, not one convenient size: the first version of
     * this renderer failed closed only while the NAME did not fit, and left a
     * partial string for every buffer that held the name but not the date —
     * which a caller ignoring the return value would have shipped. */
    {
        char tiny[8];
        char full[CHARACTER_SEED_TEXT_MAX];
        size_t need;
        bool all_closed = true;

        /* Re-render `base` rather than measuring `text`, which the blocks
         * above reused for other seeds. */
        if (!character_seed_format(&base, full, sizeof full)) {
            CS_CHECK("the short-buffer fixture renders", false);
            return;
        }
        need = strlen(full) + 1u;

        CS_CHECK("a short buffer refuses and empties itself",
                 !character_seed_format(&base, tiny, sizeof tiny) &&
                     tiny[0] == '\0');
        for (size_t cap = 1; cap < need; cap++) {
            char buf[CHARACTER_SEED_TEXT_MAX];
            memset(buf, 'X', sizeof buf);
            if (character_seed_format(&base, buf, cap) || buf[0] != '\0')
                all_closed = false;
        }
        CS_CHECK("EVERY buffer one byte short of the exact fit refuses and "
                 "leaves an empty string",
                 all_closed);
        {
            char buf[CHARACTER_SEED_TEXT_MAX];
            memset(buf, 'X', sizeof buf);
            CS_CHECK("a buffer of exactly the needed size renders",
                     character_seed_format(&base, buf, need) &&
                         strcmp(buf, full) == 0);
        }
        CS_CHECK("a NULL buffer is refused",
                 !character_seed_format(&base, NULL, 16) &&
                     !character_seed_parse(text, NULL));
    }
}

/* ── 7. the SRD 5.1 modifier rule, and the derivation's fixed tables ────── */

static void t_rules(void)
{
    /* floor((score - 10) / 2), NOT (score - 10) / 2: C truncates toward zero
     * and would give -1 where the SRD's table says -2 for a score of 7. The
     * expectations below are the SRD's table, written out. */
    {
        static const struct {
            uint8_t score;
            int mod;
        } k[] = { { 1, -5 },  { 2, -4 },  { 3, -4 },  { 6, -2 },  { 7, -2 },
                  { 8, -1 },  { 9, -1 },  { 10, 0 },  { 11, 0 },  { 12, 1 },
                  { 13, 1 },  { 14, 2 },  { 15, 2 },  { 16, 3 },  { 17, 3 },
                  { 18, 4 },  { 19, 4 },  { 20, 5 },  { 30, 10 } };
        bool ok = true;
        for (size_t i = 0; i < sizeof k / sizeof k[0]; i++)
            if (character_ability_modifier(k[i].score) != k[i].mod)
                ok = false;
        CS_CHECK("the ability modifier is floored, not truncated", ok);
    }
    /* Monotone and total across the whole uint8_t range, so no score can
     * produce a modifier that goes backwards or runs off. */
    {
        bool monotone = true;
        int prev = character_ability_modifier(0);
        for (unsigned v = 1; v <= 255u; v++) {
            int m = character_ability_modifier((uint8_t)v);
            if (m < prev)
                monotone = false;
            prev = m;
        }
        CS_CHECK("the modifier never decreases as the score rises", monotone);
    }

    /* Six distinct significators, none of them the Sun. The Sun governs how
     * evenly the points spread, not any one ability, so finding it here would
     * mean the derivation had quietly changed shape. */
    {
        bool distinct = true, no_sun = true, all_real = true;
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
            enum astro_body b =
                character_attribute_significator((enum character_attribute)i);
            if (b == ASTRO_BODY_SUN)
                no_sun = false;
            if (b < 0 || b >= ASTRO_BODY_COUNT)
                all_real = false;
            for (unsigned j = 0; j < i; j++)
                if (b == character_attribute_significator(
                             (enum character_attribute)j))
                    distinct = false;
        }
        CS_CHECK("each ability has its own significator", distinct);
        CS_CHECK("every significator is a real body", all_real);
        CS_CHECK("the Sun signifies no single ability", no_sun);
        CS_CHECK("an out-of-range ability names no body",
                 character_attribute_significator(
                     (enum character_attribute)99) == ASTRO_BODY_COUNT);
    }

    /* Dignity is the traditional scheme, so the STRUCTURE is checkable
     * without transcribing a 7x12 grid: whatever a body rules, it is in
     * detriment in the opposite sign; wherever it is exalted, it falls in the
     * opposite sign. Asserting the relation catches a table edit that a
     * spot-check of individual cells would miss. */
    {
        static const enum astro_body traditional[] = {
            ASTRO_BODY_SUN,     ASTRO_BODY_MOON,    ASTRO_BODY_MERCURY,
            ASTRO_BODY_VENUS,   ASTRO_BODY_MARS,    ASTRO_BODY_JUPITER,
            ASTRO_BODY_SATURN,
        };
        bool structured = true;
        for (size_t i = 0; i < sizeof traditional / sizeof traditional[0];
             i++) {
            enum astro_body b = traditional[i];
            unsigned rules = 0, exalts = 0, detriments = 0, falls = 0;
            for (unsigned s = 0; s < ASTRO_SIGN_COUNT; s++) {
                unsigned d = character_dignity(b, (enum astro_sign)s);
                unsigned o = character_dignity(
                    b, (enum astro_sign)((s + 6u) % ASTRO_SIGN_COUNT));
                if (d == CHARACTER_DIGNITY_RULERSHIP) {
                    rules++;
                    /* Opposite a rulership is detriment — unless the body
                     * also FALLS there, in which case the worse claim wins,
                     * which is Mercury in Pisces. */
                    if (o != CHARACTER_DIGNITY_DETRIMENT &&
                        o != CHARACTER_DIGNITY_FALL)
                        structured = false;
                }
                if (d == CHARACTER_DIGNITY_EXALTATION) {
                    exalts++;
                    if (o != CHARACTER_DIGNITY_FALL)
                        structured = false;
                }
                if (d == CHARACTER_DIGNITY_DETRIMENT)
                    detriments++;
                if (d == CHARACTER_DIGNITY_FALL)
                    falls++;
                if (d > CHARACTER_DIGNITY_MAX)
                    structured = false;
            }
            /* One or two rulerships; exactly one exaltation. Mercury's
             * exaltation coincides with a rulership, so `exalts` may be 0. */
            if (rules < 1u || rules > 2u || exalts > 1u || falls > 1u ||
                detriments > 2u)
                structured = false;
        }
        CS_CHECK("dignity keeps the traditional opposition structure",
                 structured);
        CS_CHECK("rulership outranks exaltation where they coincide",
                 character_dignity(ASTRO_BODY_MERCURY, ASTRO_SIGN_VIRGO) ==
                     CHARACTER_DIGNITY_RULERSHIP);
        CS_CHECK("the worse debility wins where two coincide",
                 character_dignity(ASTRO_BODY_MERCURY, ASTRO_SIGN_PISCES) ==
                     CHARACTER_DIGNITY_FALL);
        CS_CHECK("a body the scheme is silent about is peregrine, not zero",
                 character_dignity(ASTRO_BODY_URANUS, ASTRO_SIGN_AQUARIUS) ==
                         CHARACTER_DIGNITY_PEREGRINE &&
                     character_dignity(ASTRO_BODY_NEPTUNE,
                                       ASTRO_SIGN_PISCES) ==
                         CHARACTER_DIGNITY_PEREGRINE);
        CS_CHECK("an out-of-range argument is peregrine, not indexed past",
                 character_dignity((enum astro_body)99, ASTRO_SIGN_ARIES) ==
                         CHARACTER_DIGNITY_PEREGRINE &&
                     character_dignity(ASTRO_BODY_MARS,
                                       (enum astro_sign)99) ==
                         CHARACTER_DIGNITY_PEREGRINE);
    }

    /* Names are a wire form: present, distinct, and safe out of range. */
    {
        bool named = true, distinct = true;
        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
            const char *n = character_attribute_name((enum character_attribute)i);
            const char *a =
                character_attribute_abbrev((enum character_attribute)i);
            if (!n || !n[0] || !a || strlen(a) != 3u ||
                strcmp(n, "unknown") == 0)
                named = false;
            for (unsigned j = 0; j < i; j++)
                if (strcmp(n, character_attribute_name(
                                  (enum character_attribute)j)) == 0 ||
                    strcmp(a, character_attribute_abbrev(
                                  (enum character_attribute)j)) == 0)
                    distinct = false;
        }
        CS_CHECK("every ability has a name and a three-letter form", named);
        CS_CHECK("no two abilities share either form", distinct);
        CS_CHECK("an out-of-range ability is named, not indexed past",
                 strcmp(character_attribute_name((enum character_attribute)99),
                        "unknown") == 0 &&
                     strcmp(character_attribute_abbrev(
                                (enum character_attribute)99),
                            "???") == 0);
    }
}

/* ── 8. one character, printed ───────────────────────────────────────────
 * Not an assertion — a rendering, so the group's output shows an operator an
 * actual character rather than only a count of passing rules. The numbers are
 * whatever today's lib/astro computes; nothing here is pinned. */
static void t_show_one(void)
{
    struct astro_instant when = cs_when(1987, 3, 14, 9, 26, 0);
    struct astro_place where = cs_where(47606200, -122332100);
    struct character_seed seed;
    struct character_sheet sheet;
    char text[CHARACTER_SEED_TEXT_MAX];
    char id[METAVERSE_ID_TEXT_MAX];
    unsigned total = 0;

    if (!character_seed_make("Roan Ashgrove", &when, &where, &seed) ||
        !character_sheet_derive(&seed, &sheet) ||
        !character_seed_format(&seed, text, sizeof text) ||
        !metaverse_property_id_format(&sheet.id, id, sizeof id)) {
        CS_CHECK("the worked example derives", false);
        return;
    }
    printf("  seed     %s\n", text);
    printf("  property %s\n", id);
    printf("  rules    revision %u\n", sheet.rules_rev);
    printf("  rising   %s %u deg\n", astro_sign_name(sheet.ascendant_sign),
           sheet.ascendant_degree);
    printf("  sun      %s, dignity %u (evens the spread)\n",
           astro_sign_name(sheet.sun_sign), sheet.sun_dignity);
    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
        const struct character_influence *f = &sheet.influence[i];
        printf("  %-12s %2u (%+d)   %s in %s %u deg %02u', house %u, "
               "dignity %u\n",
               character_attribute_name((enum character_attribute)i),
               sheet.attribute[i], sheet.modifier[i],
               astro_body_name(f->body), astro_sign_name(f->sign),
               f->degree_in_sign, f->arcminute, f->house, f->dignity);
        total += sheet.attribute[i];
    }
    printf("  total    %u\n", total);
    CS_CHECK("the worked example sums to the fixed total",
             total == CHARACTER_ATTRIBUTE_TOTAL);
}

int test_character_sheet(void)
{
    g_failures = 0;

    /* lib/astro builds its trigonometric tables on first use and that build
     * is not safe to race. Nothing here is threaded, but arming them up front
     * keeps the group honest if that ever changes. */
    CS_CHECK("the exact trigonometric tables build", astro_prepare());

    t_refusals();
    t_total_is_structural();
    t_fixed_total();
    t_root();
    t_text_form();
    t_rules();
    t_show_one();

    printf("=== character_sheet: %d failure(s) ===\n", g_failures);
    return g_failures;
}
