/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character_wire, tested as the set of PROPERTIES a receiving node relies
 * on when a stranger hands it 132 bytes. The claims worth defending are not
 * "this identity encodes to these bytes" — though one golden frame is here
 * too, and it is the cross-platform anchor — they are the rules that make a
 * received sheet safe to look at:
 *
 *   (a) the encoding round-trips EXACTLY, and re-encoding a decoded frame
 *       reproduces it byte for byte, so nothing is lost or invented in
 *       transit;
 *   (b) no struct padding reaches the wire — a sheet built over 0xAB stack
 *       garbage and one built over zeroed stack encode identically;
 *   (c) VERIFY ACCEPTS EXACTLY THE SELF-CONSISTENT FRAMES. This is asserted
 *       against an INDEPENDENT ORACLE over every single-bit mutation of a real
 *       frame: for each of the 1056 flips, the oracle rebuilds a sheet from
 *       the mutated root, birthday and counters and says whether the mutated
 *       derived fields still match; the verifier must agree with it every
 *       time. A tampered form byte, a tampered birthday and a tampered chart
 *       byte are all refused as consequences of that one property rather than
 *       as three hand-picked cases — and each is also asserted by name,
 *       because a named case is what a reader checks;
 *   (d) the STANDING BOUNDARY: what the receiver believes is derived from the
 *       receiver's own observations and never from the wire, so a sender
 *       cannot talk itself into energy; a claim covered by local observation
 *       is corroborated, and every other claim renders as unverified;
 *   (e) the derivation is total: no input, including a hostile one, yields an
 *       out-of-range field or a half-filled sheet.
 *
 * A golden-value test alone would pass while every one of (a)-(e) was broken.
 */
#include "test/test_core.h"

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "base/hex.h"
#include "metaverse/node_character.h"
#include "metaverse/node_character_wire.h"

#include <stdio.h>
#include <string.h>

#define NCW_CHECK(name, expr) do { \
    printf("node_character_wire: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* The worked example: one fixed identity root and one fixed genesis moment, so
 * a person can look at the whole character and so every platform has the same
 * frame to agree about. */
static const uint8_t k_example_root[32] = {
    0x9f, 0x2c, 0x4a, 0x18, 0x77, 0x03, 0xd1, 0x6b,
    0xe4, 0x55, 0x90, 0x2f, 0xbc, 0x11, 0x08, 0xa7,
    0x3d, 0x62, 0xf0, 0x49, 0x8e, 0x17, 0xcb, 0x5a,
    0x26, 0xd8, 0x71, 0x0c, 0xa3, 0x94, 0x6f, 0x30,
};

static const struct astro_instant k_example_born = {
    .year = 2026, .month = 8, .day = 24,
    .hour = 14, .minute = 52, .second = 31,
};

/* Claimed observed work for the worked example. Enough to be a real standing
 * without being absurd: 32 GiB served, 180k blocks validated, 40 proofs, 12
 * peers brought onto the network. */
static const struct node_work k_example_work = {
    .bytes_served = 34359738368ull,
    .blocks_validated = 180000ull,
    .proofs_produced = 40ull,
    .peers_bootstrapped = 12ull,
};

/* The exact 132 bytes the example encodes to. This is the ONE golden value in
 * the file and it earns its place: it is the anchor that says Linux, macOS and
 * Windows — and -O0 and -O2 on any of them — produce the same frame. A
 * property test cannot state that, because both sides of every property would
 * drift together. */
static const char k_example_hex[] =
    "5a323343485201019f2c4a187703d16be455902fbc1108a73d62f0498e17cb5a"
    "26d8710ca3946f30000007ea08180e341f00000044000001600b090200000008"
    "00000000000000000002bf200000000000000028000000000000000c0a150419"
    "05011c0c09141e02041c0d0b0611031a0308191e040b3226000d2c1c02050c01"
    "00031b0b";

/* A deterministic pseudo-identity: byte i of root n. Not a hash, and it does
 * not need to be — the encoding must behave for ANY 32 bytes. */
static void ncw_root(uint8_t out[32], unsigned n)
{
    for (unsigned i = 0; i < 32; i++)
        out[i] = (uint8_t)((n * 131u + i * 29u + (n >> 5)) & 0xffu);
}

/* A spread of valid birthdays, including the far ends of platform/modules/astro's range and
 * a leap day, so the year encoding is exercised on both sides of zero. */
static void ncw_born(struct astro_instant *out, unsigned n)
{
    static const struct astro_instant k[] = {
        { .year = 2026, .month = 8,  .day = 24, .hour = 14, .minute = 52,
          .second = 31 },
        { .year = 1970, .month = 1,  .day = 1,  .hour = 0,  .minute = 0,
          .second = 0 },
        { .year = 2024, .month = 2,  .day = 29, .hour = 23, .minute = 59,
          .second = 59 },
        { .year = -4000, .month = 1, .day = 1,  .hour = 12, .minute = 0,
          .second = 0 },
        { .year = 9999, .month = 12, .day = 31, .hour = 23, .minute = 59,
          .second = 59 },
        { .year = -1,   .month = 6,  .day = 15, .hour = 6,  .minute = 30,
          .second = 15 },
    };
    *out = k[n % (sizeof k / sizeof k[0])];
}

static void ncw_work(struct node_work *out, unsigned n)
{
    static const struct node_work k[] = {
        { 0, 0, 0, 0 },
        { 1024ull * 1024ull, 0, 0, 0 },
        { 0, 1, 0, 0 },
        { 0, 0, 1, 0 },
        { 0, 0, 0, 1 },
        { 34359738368ull, 180000ull, 40ull, 12ull },
        { UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX },
        { 7ull, 11ull, 13ull, 17ull },
    };
    *out = k[n % (sizeof k / sizeof k[0])];
}

/* Field-by-field equality. Never memcmp: struct node_character_sheet contains
 * struct astro_instant, which has three padding bytes after `second`, and a
 * struct assignment leaves a destination's padding undefined. */
static bool ncw_sheet_same(const struct node_character_sheet *a,
                           const struct node_character_sheet *b)
{
    if (memcmp(a->identity_root, b->identity_root, 32) != 0)
        return false;
    if (a->born.year != b->born.year || a->born.month != b->born.month ||
        a->born.day != b->born.day || a->born.hour != b->born.hour ||
        a->born.minute != b->born.minute || a->born.second != b->born.second)
        return false;
    if (a->work.bytes_served != b->work.bytes_served ||
        a->work.blocks_validated != b->work.blocks_validated ||
        a->work.proofs_produced != b->work.proofs_produced ||
        a->work.peers_bootstrapped != b->work.peers_bootstrapped)
        return false;
    if (a->character.hue_deg != b->character.hue_deg ||
        a->character.silhouette != b->character.silhouette ||
        a->character.marking != b->character.marking ||
        a->character.form_rev != b->character.form_rev ||
        a->character.archetype != b->character.archetype ||
        a->character.energy != b->character.energy)
        return false;
    if (a->chart.ascendant.sign != b->chart.ascendant.sign ||
        a->chart.ascendant.degree_in_sign != b->chart.ascendant.degree_in_sign ||
        a->chart.ascendant.arcminute != b->chart.ascendant.arcminute ||
        a->chart.ascendant.arcsecond != b->chart.ascendant.arcsecond)
        return false;
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++) {
        if (a->chart.body[i].sign != b->chart.body[i].sign ||
            a->chart.body[i].degree_in_sign != b->chart.body[i].degree_in_sign ||
            a->chart.body[i].arcminute != b->chart.body[i].arcminute ||
            a->chart.body[i].arcsecond != b->chart.body[i].arcsecond)
            return false;
    }
    return true;
}

/* The INDEPENDENT ORACLE the bit-flip property is asserted against: given a
 * frame, is it self-consistent? It rebuilds a sheet from the frame's claimed
 * root, birthday and counters and asks whether the frame's derived fields are
 * the ones that rebuild produces. It shares the structural decoder with the
 * verifier — that is what is being driven — but it reaches its verdict through
 * node_character_sheet_make(), which the verifier never calls. */
static bool ncw_oracle_consistent(const uint8_t *frame)
{
    struct node_character_sheet got, rebuilt;

    if (!node_character_sheet_decode(frame, NODE_CHARACTER_WIRE_BYTES, &got))
        return false;
    if (!node_character_sheet_make(got.identity_root, &got.born, &got.work,
                                   &rebuilt))
        return false;
    return ncw_sheet_same(&got, &rebuilt);
}

int test_node_character_wire(void)
{
    int failures = 0;

    /* ── the derived birthplace ─────────────────────────────────────────── */
    {
        struct astro_place p, q;
        uint8_t root[32];

        NCW_CHECK("a null output has no birthplace written through it",
                  !node_character_birth_place(k_example_root, NULL));

        memset(&p, 0x5a, sizeof p);
        NCW_CHECK("a null identity has no birthplace",
                  !node_character_birth_place(NULL, &p));
        NCW_CHECK("a refused birthplace is zeroed, not left stale",
                  p.latitude_microdeg == 0 && p.longitude_microdeg == 0);

        bool in_range = true, varies = false, stable = true;
        struct astro_place first;
        (void)node_character_birth_place(k_example_root, &first);
        for (unsigned n = 0; n < 512; n++) {
            ncw_root(root, n);
            if (!node_character_birth_place(root, &p)) { in_range = false; break; }
            if (p.latitude_microdeg > ASTRO_LATITUDE_MICRODEG_LIMIT ||
                p.latitude_microdeg < -ASTRO_LATITUDE_MICRODEG_LIMIT ||
                p.longitude_microdeg > ASTRO_LONGITUDE_MICRODEG_LIMIT ||
                p.longitude_microdeg < -ASTRO_LONGITUDE_MICRODEG_LIMIT) {
                in_range = false;
                break;
            }
            /* Same root, same place, every time. */
            (void)node_character_birth_place(root, &q);
            if (p.latitude_microdeg != q.latitude_microdeg ||
                p.longitude_microdeg != q.longitude_microdeg)
                stable = false;
            if (p.latitude_microdeg != first.latitude_microdeg ||
                p.longitude_microdeg != first.longitude_microdeg)
                varies = true;
        }
        NCW_CHECK("every identity's birthplace is inside platform/modules/astro's range",
                  in_range);
        NCW_CHECK("the birthplace is a function of the identity alone", stable);
        NCW_CHECK("different identities are not all born in one place", varies);
    }

    /* ── making a sheet: refusals are total and leave nothing behind ────── */
    {
        struct node_character_sheet s;
        struct astro_instant bad;

        NCW_CHECK("a null output is refused rather than written through",
                  !node_character_sheet_make(k_example_root, &k_example_born,
                                             NULL, NULL));

        memset(&s, 0xab, sizeof s);
        NCW_CHECK("a null identity is refused",
                  !node_character_sheet_make(NULL, &k_example_born, NULL, &s));
        NCW_CHECK("a refused make zeroes its output",
                  s.identity_root[0] == 0 && s.born.year == 0 &&
                  s.character.energy == 0 && s.chart.ascendant.sign == 0);

        NCW_CHECK("a null birthday is refused",
                  !node_character_sheet_make(k_example_root, NULL, NULL, &s));

        bad = k_example_born;
        bad.month = 13;
        NCW_CHECK("a month that is not a month is refused",
                  !node_character_sheet_make(k_example_root, &bad, NULL, &s));

        bad = k_example_born;
        bad.month = 2;
        bad.day = 30;
        NCW_CHECK("a day that does not exist in that month is refused",
                  !node_character_sheet_make(k_example_root, &bad, NULL, &s));

        bad = k_example_born;
        bad.year = 10000;
        NCW_CHECK("a year outside platform/modules/astro's range is refused",
                  !node_character_sheet_make(k_example_root, &bad, NULL, &s));

        NCW_CHECK("null work means nothing observed yet, not a refusal",
                  node_character_sheet_make(k_example_root, &k_example_born,
                                            NULL, &s) &&
                  s.character.archetype == NODE_ARCHETYPE_WANDERER &&
                  s.character.energy == 0);
    }

    /* ── the sheet agrees with the two modules it is built from ─────────── */
    {
        struct node_character_sheet s;
        struct node_character direct;
        struct astro_place place;
        struct astro_chart chart;
        bool form_agrees = true, chart_agrees = true;
        uint8_t root[32];
        struct astro_instant born;
        struct node_work work;

        for (unsigned n = 0; n < 24; n++) {
            ncw_root(root, n);
            ncw_born(&born, n);
            ncw_work(&work, n);
            if (!node_character_sheet_make(root, &born, &work, &s)) {
                form_agrees = chart_agrees = false;
                break;
            }
            if (!node_character_derive(root, &work, &direct) ||
                direct.hue_deg != s.character.hue_deg ||
                direct.silhouette != s.character.silhouette ||
                direct.marking != s.character.marking ||
                direct.archetype != s.character.archetype ||
                direct.energy != s.character.energy)
                form_agrees = false;

            /* The chart in the sheet must be the chart platform/modules/astro computes for
             * the derived place — asserted against astro_chart_compute()
             * directly, not against the module's own projection of it. */
            if (!node_character_birth_place(root, &place) ||
                !astro_chart_compute(&born, &place, &chart) ||
                (uint8_t)chart.ascendant.sign != s.chart.ascendant.sign ||
                (uint8_t)chart.ascendant.degree_in_sign !=
                    s.chart.ascendant.degree_in_sign ||
                (uint8_t)chart.ascendant.arcminute !=
                    s.chart.ascendant.arcminute ||
                (uint8_t)chart.ascendant.arcsecond !=
                    s.chart.ascendant.arcsecond)
                chart_agrees = false;
            for (unsigned b = 0; b < (unsigned)ASTRO_BODY_COUNT; b++)
                if ((uint8_t)chart.body[b].sign != s.chart.body[b].sign ||
                    (uint8_t)chart.body[b].degree_in_sign !=
                        s.chart.body[b].degree_in_sign ||
                    (uint8_t)chart.body[b].arcminute !=
                        s.chart.body[b].arcminute ||
                    (uint8_t)chart.body[b].arcsecond !=
                        s.chart.body[b].arcsecond)
                    chart_agrees = false;
        }
        NCW_CHECK("the sheet's form and standing are node_character's",
                  form_agrees);
        NCW_CHECK("the sheet's chart is platform/modules/astro's chart for the derived place",
                  chart_agrees);
    }

    /* ── (a) the round trip is exact ────────────────────────────────────── */
    {
        struct node_character_sheet made, back;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        uint8_t again[NODE_CHARACTER_WIRE_BYTES];
        uint8_t root[32];
        struct astro_instant born;
        struct node_work work;
        bool exact = true, reencodes = true;

        for (unsigned n = 0; n < 48; n++) {
            ncw_root(root, n);
            ncw_born(&born, n);
            ncw_work(&work, n);
            if (!node_character_sheet_make(root, &born, &work, &made) ||
                !node_character_sheet_encode(&made, frame) ||
                !node_character_sheet_decode(frame, sizeof frame, &back)) {
                exact = false;
                break;
            }
            if (!ncw_sheet_same(&made, &back))
                exact = false;
            if (!node_character_sheet_encode(&back, again) ||
                memcmp(frame, again, sizeof frame) != 0)
                reencodes = false;
        }
        NCW_CHECK("a sheet survives encode and decode field for field", exact);
        NCW_CHECK("re-encoding a decoded frame reproduces it byte for byte",
                  reencodes);
    }

    /* ── (b) no struct padding reaches the wire ─────────────────────────── */
    {
        /* Two sheets built over deliberately different stack garbage. If the
         * encoder ever copied a struct wholesale, the padding bytes — which C
         * leaves undefined and which gcc and clang really do leave
         * uninitialised at -O2 — would differ here. This is the exact shape of
         * a defect a previous lane found at -O2 and not at -O0. */
        struct node_character_sheet dirty, clean;
        uint8_t a[NODE_CHARACTER_WIRE_BYTES], b[NODE_CHARACTER_WIRE_BYTES];

        memset(&dirty, 0xab, sizeof dirty);
        memset(&clean, 0x00, sizeof clean);
        NCW_CHECK("a sheet built over garbage encodes like one built over zero",
                  node_character_sheet_make(k_example_root, &k_example_born,
                                            &k_example_work, &dirty) &&
                  node_character_sheet_make(k_example_root, &k_example_born,
                                            &k_example_work, &clean) &&
                  node_character_sheet_encode(&dirty, a) &&
                  node_character_sheet_encode(&clean, b) &&
                  memcmp(a, b, sizeof a) == 0);
    }

    /* ── the golden frame: the cross-platform, cross -O anchor ──────────── */
    {
        struct node_character_sheet s;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        char hex[2u * NODE_CHARACTER_WIRE_BYTES + 1u];

        if (node_character_sheet_make(k_example_root, &k_example_born,
                                      &k_example_work, &s) &&
            node_character_sheet_encode(&s, frame)) {
            zcl_hex_encode(frame, sizeof frame, hex);
            NCW_CHECK("the worked example encodes to its recorded 132 bytes",
                      strcmp(hex, k_example_hex) == 0);
            if (strcmp(hex, k_example_hex) != 0)
                printf("  frame %s\n", hex);
        } else {
            NCW_CHECK("the worked example encodes at all", false);
        }
    }

    /* ── (c) verify accepts exactly the self-consistent frames ──────────── */
    {
        struct node_character_sheet s;
        struct node_character_receipt r;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        uint8_t mutated[NODE_CHARACTER_WIRE_BYTES];
        bool agrees = true, any_refused = false, any_accepted = false;
        bool unverified_when_accepted = true;

        if (!node_character_sheet_make(k_example_root, &k_example_born,
                                       &k_example_work, &s) ||
            !node_character_sheet_encode(&s, frame)) {
            NCW_CHECK("the bit-flip sweep has a frame to work from", false);
        } else {
            NCW_CHECK("the untouched frame verifies",
                      node_character_sheet_verify(frame, sizeof frame, NULL,
                                                  &r));

            for (unsigned bit = 0; bit < 8u * NODE_CHARACTER_WIRE_BYTES;
                 bit++) {
                memcpy(mutated, frame, sizeof frame);
                mutated[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));

                bool accepted = node_character_sheet_verify(
                    mutated, sizeof mutated, NULL, &r);
                if (accepted != ncw_oracle_consistent(mutated)) {
                    agrees = false;
                    printf("  bit %u: verify=%d oracle=%d\n", bit,
                           (int)accepted, (int)ncw_oracle_consistent(mutated));
                    break;
                }
                if (accepted) {
                    any_accepted = true;
                    /* Whatever survived the flip, a stranger still believes
                     * nothing about the sender's standing. */
                    if (r.trust != NODE_STANDING_UNVERIFIED ||
                        r.believed.energy != 0 ||
                        r.believed.archetype != NODE_ARCHETYPE_WANDERER)
                        unverified_when_accepted = false;
                } else {
                    any_refused = true;
                }
            }
            NCW_CHECK("verify agrees with an independent oracle on all 1056 "
                      "single-bit mutations",
                      agrees);
            NCW_CHECK("some mutations are refused", any_refused);
            /* The frames a flip leaves self-consistent are the ones whose
             * mutated bytes nothing derives from — spare identity-root bytes,
             * and counter bits too low to move a doubling. They are accepted
             * as a DIFFERENT well-formed claim, never as a corroborated one.
             * A build where this went false would mean every flip was caught,
             * which would mean the sweep had stopped testing anything. */
            NCW_CHECK("some mutations stay self-consistent and are accepted",
                      any_accepted);
            NCW_CHECK("an accepted mutation still leaves standing unverified",
                      unverified_when_accepted);
        }
    }

    /* ── (c) the same refusals, named ───────────────────────────────────── */
    {
        struct node_character_sheet s;
        struct node_character_receipt r;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES], t[NODE_CHARACTER_WIRE_BYTES];

        (void)node_character_sheet_make(k_example_root, &k_example_born,
                                        &k_example_work, &s);
        (void)node_character_sheet_encode(&s, frame);

        /* offsets from the layout table in node_character_wire.c */
        const unsigned OFF_VERSION = 6, OFF_FORM_REV = 7, OFF_DAY = 45,
                       OFF_HUE = 49, OFF_ENERGY = 53, OFF_SILHOUETTE = 57,
                       OFF_MARKING = 58, OFF_ARCHETYPE = 59, OFF_WORK = 60,
                       OFF_CHART = 92;

#define NCW_TAMPER(off, op) (memcpy(t, frame, sizeof t), t[(off)] op, \
                             !node_character_sheet_verify(t, sizeof t, NULL, &r))

        NCW_CHECK("a tampered magic byte is refused", NCW_TAMPER(0u, ^= 0x01u));
        NCW_CHECK("an unknown wire version is refused",
                  NCW_TAMPER(OFF_VERSION, += 1u));
        NCW_CHECK("a sheet from another form revision is refused rather than "
                  "read", NCW_TAMPER(OFF_FORM_REV, += 1u));
        NCW_CHECK("a tampered form byte (silhouette) is refused",
                  NCW_TAMPER(OFF_SILHOUETTE, ^= 0x01u));
        NCW_CHECK("a tampered form byte (marking) is refused",
                  NCW_TAMPER(OFF_MARKING, ^= 0x01u));
        NCW_CHECK("a tampered hue is refused",
                  NCW_TAMPER(OFF_HUE + 3u, ^= 0x01u));
        NCW_CHECK("a hue too wide for its field is refused, not truncated",
                  NCW_TAMPER(OFF_HUE, = 0x01u));
        NCW_CHECK("an energy too wide for its field is refused, not truncated",
                  NCW_TAMPER(OFF_ENERGY, = 0x01u));
        NCW_CHECK("a tampered birthday byte (day) is refused",
                  NCW_TAMPER(OFF_DAY, += 1u));
        NCW_CHECK("a tampered chart byte (the rising sign) is refused",
                  NCW_TAMPER(OFF_CHART, ^= 0x01u));
        NCW_CHECK("a tampered chart byte (the Sun's arcsecond) is refused",
                  NCW_TAMPER(OFF_CHART + 7u, ^= 0x01u));
        NCW_CHECK("a tampered archetype is refused",
                  NCW_TAMPER(OFF_ARCHETYPE, ^= 0x01u));
        NCW_CHECK("an archetype no build has ever defined is refused",
                  NCW_TAMPER(OFF_ARCHETYPE, = 0xffu));
        NCW_CHECK("an energy raised by hand is refused",
                  NCW_TAMPER(OFF_ENERGY + 3u, ^= 0x40u));
        NCW_CHECK("a counter raised past its own doubling is refused",
                  NCW_TAMPER(OFF_WORK + 1u, ^= 0xffu));
#undef NCW_TAMPER

        /* An energy claim with nothing behind it: zero every counter and keep
         * the standing the real counters produced. Internal consistency is
         * what refuses this, and it is the reason the counters are on the wire
         * at all. */
        memcpy(t, frame, sizeof t);
        memset(t + OFF_WORK, 0, 32);
        NCW_CHECK("a large energy with no counters behind it is refused",
                  !node_character_sheet_verify(t, sizeof t, NULL, &r));

        /* Length is part of the frame, not a suggestion. */
        NCW_CHECK("a short frame is refused",
                  !node_character_sheet_verify(frame, sizeof frame - 1u, NULL,
                                               &r));
        NCW_CHECK("a long frame is refused",
                  !node_character_sheet_verify(frame, sizeof frame + 1u, NULL,
                                               &r));
        NCW_CHECK("a null frame is refused",
                  !node_character_sheet_verify(NULL, sizeof frame, NULL, &r));
        NCW_CHECK("a null receipt is refused rather than written through",
                  !node_character_sheet_verify(frame, sizeof frame, NULL,
                                               NULL));

        memset(&r, 0xcd, sizeof r);
        memcpy(t, frame, sizeof t);
        t[OFF_DAY] += 1u;
        (void)node_character_sheet_verify(t, sizeof t, NULL, &r);
        NCW_CHECK("a refused verify zeroes its receipt",
                  r.sheet.identity_root[0] == 0 && r.sheet.born.year == 0 &&
                  r.believed.energy == 0 &&
                  r.trust == NODE_STANDING_UNVERIFIED);
    }

    /* ── (d) the standing boundary ──────────────────────────────────────── */
    {
        struct node_character_sheet s;
        struct node_character_receipt r;
        struct node_character claimed;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        struct node_work more, less;

        (void)node_character_sheet_make(k_example_root, &k_example_born,
                                        &k_example_work, &s);
        (void)node_character_sheet_encode(&s, frame);
        (void)node_character_derive(k_example_root, &k_example_work, &claimed);

        NCW_CHECK("the example claims a real standing, so the boundary has "
                  "something to refuse",
                  claimed.energy > 0 &&
                  claimed.archetype != NODE_ARCHETYPE_WANDERER);

        /* A stranger. This is the case the whole module is for. */
        NCW_CHECK("a stranger accepts the sheet",
                  node_character_sheet_verify(frame, sizeof frame, NULL, &r));
        NCW_CHECK("a stranger believes no standing at all, whatever is claimed",
                  r.believed.energy == 0 &&
                  r.believed.archetype == NODE_ARCHETYPE_WANDERER &&
                  r.trust == NODE_STANDING_UNVERIFIED);
        NCW_CHECK("the stranger's receipt still carries the claim verbatim",
                  r.sheet.character.energy == claimed.energy &&
                  r.sheet.character.archetype == claimed.archetype);
        NCW_CHECK("a stranger still recomputes the form and believes it",
                  r.believed.hue_deg == r.sheet.character.hue_deg &&
                  r.believed.silhouette == r.sheet.character.silhouette &&
                  r.believed.marking == r.sheet.character.marking);

        /* A node that observed exactly what was claimed. */
        NCW_CHECK("a claim this node observed exactly is corroborated",
                  node_character_sheet_verify(frame, sizeof frame,
                                              &k_example_work, &r) &&
                  r.trust == NODE_STANDING_CORROBORATED &&
                  r.believed.energy == claimed.energy &&
                  r.believed.archetype == claimed.archetype);

        /* A node that observed more than was claimed. Believing MORE than the
         * claim is correct: the belief is our own observation, not a discount
         * of somebody's assertion. */
        more = k_example_work;
        more.bytes_served *= 4u;
        more.blocks_validated *= 4u;
        more.proofs_produced *= 4u;
        more.peers_bootstrapped *= 4u;
        NCW_CHECK("a claim covered with room to spare is corroborated",
                  node_character_sheet_verify(frame, sizeof frame, &more, &r) &&
                  r.trust == NODE_STANDING_CORROBORATED &&
                  r.believed.energy >= claimed.energy);

        /* One field short is not corroboration, and is not an accusation
         * either: the sheet is still accepted. */
        less = k_example_work;
        less.proofs_produced -= 1u;
        NCW_CHECK("a claim one counter short of what we saw is accepted but "
                  "unverified",
                  node_character_sheet_verify(frame, sizeof frame, &less, &r) &&
                  r.trust == NODE_STANDING_UNVERIFIED);
        NCW_CHECK("the partly-observed belief comes from our counters, not the "
                  "sheet's",
                  r.believed.energy > 0);

        /* The claim a node would forge if it could: everything saturated. The
         * frame verifies — it is internally consistent — and buys nothing. */
        {
            struct node_work maxed = { UINT64_MAX, UINT64_MAX, UINT64_MAX,
                                       UINT64_MAX };
            struct node_character_sheet big;
            uint8_t bigframe[NODE_CHARACTER_WIRE_BYTES];

            NCW_CHECK("a saturated claim is a well-formed sheet",
                      node_character_sheet_make(k_example_root,
                                                &k_example_born, &maxed,
                                                &big) &&
                      node_character_sheet_encode(&big, bigframe) &&
                      big.character.energy == NODE_ENERGY_MAX);
            NCW_CHECK("a node cannot talk a stranger into any energy at all",
                      node_character_sheet_verify(bigframe, sizeof bigframe,
                                                  NULL, &r) &&
                      r.sheet.character.energy == NODE_ENERGY_MAX &&
                      r.believed.energy == 0 &&
                      r.trust == NODE_STANDING_UNVERIFIED);
        }
    }

    /* ── (d) rendered, which is where a person meets the boundary ───────── */
    {
        struct node_character_sheet s;
        struct node_character_receipt r;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        char text[NODE_CHARACTER_SHEET_TEXT_MAX];
        char small[16];

        (void)node_character_sheet_make(k_example_root, &k_example_born,
                                        &k_example_work, &s);
        (void)node_character_sheet_encode(&s, frame);

        NCW_CHECK("a null receipt renders nothing",
                  !node_character_receipt_render(NULL, text, sizeof text));
        NCW_CHECK("a null buffer is refused",
                  !node_character_receipt_render(&r, NULL, sizeof text));

        (void)node_character_sheet_verify(frame, sizeof frame, NULL, &r);
        small[0] = 'x';
        NCW_CHECK("a short buffer refuses the whole render and empties it",
                  !node_character_receipt_render(&r, small, sizeof small) &&
                  small[0] == '\0');

        NCW_CHECK("a stranger's rendering says unverified",
                  node_character_receipt_render(&r, text, sizeof text) &&
                  strstr(text, "unverified") != NULL);
        NCW_CHECK("a stranger's rendering shows the believed standing too",
                  strstr(text, "believed") != NULL &&
                  strstr(text, "wanderer") != NULL);
        NCW_CHECK("a stranger's rendering marks the birthday as asserted",
                  strstr(text, "asserted") != NULL);

        printf("── the worked example, as a stranger sees it ──\n%s", text);

        (void)node_character_sheet_verify(frame, sizeof frame, &k_example_work,
                                          &r);
        NCW_CHECK("a corroborated rendering says so",
                  node_character_receipt_render(&r, text, sizeof text) &&
                  strstr(text, "corroborated") != NULL &&
                  strstr(text, "unverified") == NULL);

        printf("── the same character, to a node that watched it work ──\n%s",
               text);
    }

    /* ── trust names are a wire form ────────────────────────────────────── */
    {
        NCW_CHECK("the unverified state has its stable name",
                  strcmp(node_standing_trust_name(NODE_STANDING_UNVERIFIED),
                         "unverified") == 0);
        NCW_CHECK("the corroborated state has its stable name",
                  strcmp(node_standing_trust_name(NODE_STANDING_CORROBORATED),
                         "corroborated") == 0);
        NCW_CHECK("an out-of-range trust state is named, not indexed past",
                  strcmp(node_standing_trust_name(
                             (enum node_standing_trust)77), "unknown") == 0);
    }

    printf("=== node_character_wire: %d failure(s) ===\n", failures);
    return failures;
}
