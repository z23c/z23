/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character_wire, tested as the PROPERTIES a receiving node relies on
 * when a stranger hands it 132 bytes (plus one golden frame as the
 * cross-platform anchor):
 *
 *   (a) the encoding round-trips EXACTLY, and re-encoding a decoded frame
 *       reproduces it byte for byte;
 *   (b) no struct padding reaches the wire: a sheet built over 0xAB stack
 *       garbage and one over zeroed stack encode identically;
 *   (c) VERIFY ACCEPTS EXACTLY THE SELF-CONSISTENT FRAMES, asserted against
 *       an INDEPENDENT ORACLE over every single-bit mutation of a real
 *       frame (1056 flips): the oracle rebuilds a sheet from the mutated
 *       root, birthday and counters and says whether the derived fields
 *       still match; the verifier must agree every time. Tampered form,
 *       birthday and chart bytes are also asserted by name;
 *   (d) the STANDING BOUNDARY: what the receiver believes derives from its
 *       own observations, never from the wire; a claim covered by local
 *       observation is corroborated, every other claim renders as
 *       unverified;
 *   (e) the derivation is total: no input, including a hostile one, yields
 *       an out-of-range field or a half-filled sheet.
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

/* The exact 132 bytes the example encodes to: the ONE golden value, the
 * anchor that Linux, macOS and Windows (at any -O) produce the same frame. */
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

/* The six calendar fields, in the order a sheet compares them. Padding after
 * `second` is not part of the value. */
static bool ncw_born_fields_match(const struct astro_instant *a,
                                  const struct astro_instant *b)
{
    return a->year == b->year && a->month == b->month &&
           a->day == b->day && a->hour == b->hour &&
           a->minute == b->minute && a->second == b->second;
}

/* Form and standing, field by field. Early return keeps the original order. */
static bool ncw_character_fields_match(const struct node_character *a,
                                       const struct node_character *b)
{
    if (a->hue_deg != b->hue_deg)
        return false;
    if (a->silhouette != b->silhouette)
        return false;
    if (a->marking != b->marking)
        return false;
    if (a->form_rev != b->form_rev)
        return false;
    if (a->archetype != b->archetype)
        return false;
    if (a->energy != b->energy)
        return false;
    return true;
}

/* Rising degree, then each body. A mismatch stops the rest, as the sheet
 * comparison used to return at the first differing readout. */
static bool ncw_chart_fields_match(const struct node_star_chart *a,
                                   const struct node_star_chart *b)
{
    bool same = a->ascendant.sign == b->ascendant.sign &&
                a->ascendant.degree_in_sign == b->ascendant.degree_in_sign &&
                a->ascendant.arcminute == b->ascendant.arcminute &&
                a->ascendant.arcsecond == b->ascendant.arcsecond;
    for (unsigned i = 0; same && i < (unsigned)ASTRO_BODY_COUNT; i++)
        same = a->body[i].sign == b->body[i].sign &&
               a->body[i].degree_in_sign == b->body[i].degree_in_sign &&
               a->body[i].arcminute == b->body[i].arcminute &&
               a->body[i].arcsecond == b->body[i].arcsecond;
    return same;
}

/* Field-by-field equality. Never memcmp: struct node_character_sheet contains
 * struct astro_instant, which has three padding bytes after `second`, and a
 * struct assignment leaves a destination's padding undefined. */
static bool ncw_sheet_same(const struct node_character_sheet *a,
                           const struct node_character_sheet *b)
{
    return memcmp(a->identity_root, b->identity_root, 32) == 0 &&
           ncw_born_fields_match(&a->born, &b->born) &&
           a->work.bytes_served == b->work.bytes_served &&
           a->work.blocks_validated == b->work.blocks_validated &&
           a->work.proofs_produced == b->work.proofs_produced &&
           a->work.peers_bootstrapped == b->work.peers_bootstrapped &&
           ncw_character_fields_match(&a->character, &b->character) &&
           ncw_chart_fields_match(&a->chart, &b->chart);
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

/* Both microdegree fields cleared, which is what a refused birthplace writes. */
static bool ncw_place_both_zero(const struct astro_place *p)
{
    return p->latitude_microdeg == 0 && p->longitude_microdeg == 0;
}

/* True when a place sits outside platform/modules/astro's accepted box. */
static bool ncw_place_outside_limits(const struct astro_place *p)
{
    return p->latitude_microdeg > ASTRO_LATITUDE_MICRODEG_LIMIT ||
           p->latitude_microdeg < -ASTRO_LATITUDE_MICRODEG_LIMIT ||
           p->longitude_microdeg > ASTRO_LONGITUDE_MICRODEG_LIMIT ||
           p->longitude_microdeg < -ASTRO_LONGITUDE_MICRODEG_LIMIT;
}

/* 512 identities: every place in range, stable for one root, not all identical. */
static void ncw_scan_birthplaces(bool *in_range, bool *varies, bool *stable)
{
    struct astro_place p, q, first;
    uint8_t root[32];

    (void)node_character_birth_place(k_example_root, &first);
    for (unsigned n = 0; n < 512; n++) {
        ncw_root(root, n);
        if (!node_character_birth_place(root, &p)) { *in_range = false; break; }
        if (ncw_place_outside_limits(&p)) {
            *in_range = false;
            break;
        }
        /* Same root, same place, every time. */
        (void)node_character_birth_place(root, &q);
        if (p.latitude_microdeg != q.latitude_microdeg ||
            p.longitude_microdeg != q.longitude_microdeg)
            *stable = false;
        if (p.latitude_microdeg != first.latitude_microdeg ||
            p.longitude_microdeg != first.longitude_microdeg)
            *varies = true;
    }
}

/* The four bytes a refused make is required to clear. */
static bool ncw_refused_make_zeroed(const struct node_character_sheet *s)
{
    return s->identity_root[0] == 0 && s->born.year == 0 &&
           s->character.energy == 0 && s->chart.ascendant.sign == 0;
}

/* Null work is an empty observation: a wanderer with zero energy. */
static bool ncw_null_work_is_wanderer(struct node_character_sheet *s)
{
    return node_character_sheet_make(k_example_root, &k_example_born,
                                     NULL, s) &&
           s->character.archetype == NODE_ARCHETYPE_WANDERER &&
           s->character.energy == 0;
}

/* The sheet's form and standing equal node_character_derive for this root. */
static bool ncw_form_matches_direct(const uint8_t root[32],
                                    const struct node_work *work,
                                    const struct node_character *got)
{
    struct node_character direct;

    return node_character_derive(root, work, &direct) &&
           direct.hue_deg == got->hue_deg &&
           direct.silhouette == got->silhouette &&
           direct.marking == got->marking &&
           direct.archetype == got->archetype &&
           direct.energy == got->energy;
}

/* Every body readout, including ones past the first mismatch. */
static bool ncw_astro_bodies_match(const struct astro_chart *chart,
                                   const struct node_star_chart *got)
{
    bool match = true;

    for (unsigned b = 0; b < (unsigned)ASTRO_BODY_COUNT; b++)
        if ((uint8_t)chart->body[b].sign != got->body[b].sign ||
            (uint8_t)chart->body[b].degree_in_sign !=
                got->body[b].degree_in_sign ||
            (uint8_t)chart->body[b].arcminute != got->body[b].arcminute ||
            (uint8_t)chart->body[b].arcsecond != got->body[b].arcsecond)
            match = false;
    return match;
}

/* The chart in the sheet must be the chart platform/modules/astro computes for
 * the derived place — asserted against astro_chart_compute()
 * directly, not against the module's own projection of it. */
static bool ncw_chart_matches_astro(const uint8_t root[32],
                                    const struct astro_instant *born,
                                    const struct node_star_chart *got)
{
    struct astro_place place;
    struct astro_chart chart;
    bool matches = node_character_birth_place(root, &place) &&
                   astro_chart_compute(born, &place, &chart) &&
                   (uint8_t)chart.ascendant.sign == got->ascendant.sign &&
                   (uint8_t)chart.ascendant.degree_in_sign ==
                       got->ascendant.degree_in_sign &&
                   (uint8_t)chart.ascendant.arcminute ==
                       got->ascendant.arcminute &&
                   (uint8_t)chart.ascendant.arcsecond ==
                       got->ascendant.arcsecond;

    if (!ncw_astro_bodies_match(&chart, got))
        matches = false;
    return matches;
}

static void ncw_sheets_follow_sources(bool *form_agrees, bool *chart_agrees)
{
    struct node_character_sheet s;
    uint8_t root[32];
    struct astro_instant born;
    struct node_work work;

    for (unsigned n = 0; n < 24; n++) {
        ncw_root(root, n);
        ncw_born(&born, n);
        ncw_work(&work, n);
        if (!node_character_sheet_make(root, &born, &work, &s)) {
            *form_agrees = *chart_agrees = false;
            break;
        }
        if (!ncw_form_matches_direct(root, &work, &s.character))
            *form_agrees = false;
        if (!ncw_chart_matches_astro(root, &born, &s.chart))
            *chart_agrees = false;
    }
}

static void ncw_round_trips(bool *exact, bool *reencodes)
{
    struct node_character_sheet made, back;
    uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
    uint8_t again[NODE_CHARACTER_WIRE_BYTES];
    uint8_t root[32];
    struct astro_instant born;
    struct node_work work;

    for (unsigned n = 0; n < 48; n++) {
        ncw_root(root, n);
        ncw_born(&born, n);
        ncw_work(&work, n);
        if (!node_character_sheet_make(root, &born, &work, &made) ||
            !node_character_sheet_encode(&made, frame) ||
            !node_character_sheet_decode(frame, sizeof frame, &back)) {
            *exact = false;
            break;
        }
        if (!ncw_sheet_same(&made, &back))
            *exact = false;
        if (!node_character_sheet_encode(&back, again) ||
            memcmp(frame, again, sizeof frame) != 0)
            *reencodes = false;
    }
}

/* Two sheets built over different stack garbage. If the encoder
 * copied a struct wholesale, the undefined padding bytes (left
 * uninitialised by gcc and clang at -O2) would differ here. */
static bool ncw_garbage_encodes_like_zero(void)
{
    struct node_character_sheet dirty, clean;
    uint8_t a[NODE_CHARACTER_WIRE_BYTES], b[NODE_CHARACTER_WIRE_BYTES];

    memset(&dirty, 0xab, sizeof dirty);
    memset(&clean, 0x00, sizeof clean);
    return node_character_sheet_make(k_example_root, &k_example_born,
                                     &k_example_work, &dirty) &&
           node_character_sheet_make(k_example_root, &k_example_born,
                                     &k_example_work, &clean) &&
           node_character_sheet_encode(&dirty, a) &&
           node_character_sheet_encode(&clean, b) &&
           memcmp(a, b, sizeof a) == 0;
}

/* The worked example, encoded. False when make or encode refuses. */
static bool ncw_example_frame(uint8_t frame[NODE_CHARACTER_WIRE_BYTES])
{
    struct node_character_sheet s;

    return node_character_sheet_make(k_example_root, &k_example_born,
                                     &k_example_work, &s) &&
           node_character_sheet_encode(&s, frame);
}

struct ncw_flip_result {
    bool agrees;
    bool any_refused;
    bool any_accepted;
    bool unverified_when_accepted;
    unsigned bit;
    int verify_value;
};

static struct ncw_flip_result ncw_sweep_bit_flips(
    const uint8_t frame[NODE_CHARACTER_WIRE_BYTES],
    uint8_t mutated[NODE_CHARACTER_WIRE_BYTES],
    struct node_character_receipt *r)
{
    struct ncw_flip_result out = {
        .agrees = true,
        .any_refused = false,
        .any_accepted = false,
        .unverified_when_accepted = true,
        .bit = 0,
        .verify_value = 0,
    };

    for (unsigned bit = 0; bit < 8u * NODE_CHARACTER_WIRE_BYTES; bit++) {
        memcpy(mutated, frame, NODE_CHARACTER_WIRE_BYTES);
        mutated[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));

        bool accepted = node_character_sheet_verify(
            mutated, NODE_CHARACTER_WIRE_BYTES, NULL, r);
        if (accepted != ncw_oracle_consistent(mutated)) {
            out.agrees = false;
            out.bit = bit;
            out.verify_value = (int)accepted;
            return out;
        }
        if (accepted) {
            out.any_accepted = true;
            /* Whatever survived the flip, a stranger still believes
             * nothing about the sender's standing. */
            if (r->trust != NODE_STANDING_UNVERIFIED ||
                r->believed.energy != 0 ||
                r->believed.archetype != NODE_ARCHETYPE_WANDERER)
                out.unverified_when_accepted = false;
        } else {
            out.any_refused = true;
        }
    }
    return out;
}

/* A refused verify clears the receipt instead of leaving 0xcd behind. */
static bool ncw_receipt_cleared(const struct node_character_receipt *r)
{
    return r->sheet.identity_root[0] == 0 && r->sheet.born.year == 0 &&
           r->believed.energy == 0 &&
           r->trust == NODE_STANDING_UNVERIFIED;
}

struct ncw_stranger_result {
    bool claims_real;
    bool accepted;
    bool believes_nothing;
    bool claim_verbatim;
    bool form_believed;
    struct node_character claimed;
};

static struct ncw_stranger_result ncw_stranger_boundary(
    uint8_t frame[NODE_CHARACTER_WIRE_BYTES],
    struct node_character_receipt *r)
{
    struct node_character_sheet s;
    struct ncw_stranger_result out;

    (void)node_character_sheet_make(k_example_root, &k_example_born,
                                    &k_example_work, &s);
    (void)node_character_sheet_encode(&s, frame);
    (void)node_character_derive(k_example_root, &k_example_work, &out.claimed);

    out.claims_real = out.claimed.energy > 0 &&
                      out.claimed.archetype != NODE_ARCHETYPE_WANDERER;
    /* A stranger. This is the case the whole module is for. */
    out.accepted = node_character_sheet_verify(frame, NODE_CHARACTER_WIRE_BYTES,
                                               NULL, r);
    out.believes_nothing = r->believed.energy == 0 &&
                           r->believed.archetype == NODE_ARCHETYPE_WANDERER &&
                           r->trust == NODE_STANDING_UNVERIFIED;
    out.claim_verbatim = r->sheet.character.energy == out.claimed.energy &&
                         r->sheet.character.archetype == out.claimed.archetype;
    out.form_believed = r->believed.hue_deg == r->sheet.character.hue_deg &&
                        r->believed.silhouette == r->sheet.character.silhouette &&
                        r->believed.marking == r->sheet.character.marking;
    return out;
}

struct ncw_observed_result {
    bool exact;
    bool spare;
    bool one_short;
    bool from_our_counters;
};

static struct ncw_observed_result ncw_observed_boundary(
    const uint8_t frame[NODE_CHARACTER_WIRE_BYTES],
    const struct node_character *claimed,
    struct node_character_receipt *r)
{
    struct ncw_observed_result out;
    struct node_work more, less;

    /* A node that observed exactly what was claimed. */
    out.exact = node_character_sheet_verify(frame, NODE_CHARACTER_WIRE_BYTES,
                                            &k_example_work, r) &&
                r->trust == NODE_STANDING_CORROBORATED &&
                r->believed.energy == claimed->energy &&
                r->believed.archetype == claimed->archetype;

    /* A node that observed more than was claimed. Believing MORE than the
     * claim is correct: the belief is our own observation, not a discount
     * of somebody's assertion. */
    more = k_example_work;
    more.bytes_served *= 4u;
    more.blocks_validated *= 4u;
    more.proofs_produced *= 4u;
    more.peers_bootstrapped *= 4u;
    out.spare = node_character_sheet_verify(frame, NODE_CHARACTER_WIRE_BYTES,
                                            &more, r) &&
                r->trust == NODE_STANDING_CORROBORATED &&
                r->believed.energy >= claimed->energy;

    /* One field short is not corroboration, and is not an accusation
     * either: the sheet is still accepted. */
    less = k_example_work;
    less.proofs_produced -= 1u;
    out.one_short = node_character_sheet_verify(frame, NODE_CHARACTER_WIRE_BYTES,
                                                &less, r) &&
                    r->trust == NODE_STANDING_UNVERIFIED;
    out.from_our_counters = r->believed.energy > 0;
    return out;
}

struct ncw_saturated_result {
    bool well_formed;
    bool stranger_untouched;
};

/* The claim a node would forge if it could: everything saturated.
 * The frame verifies and buys nothing. */
static struct ncw_saturated_result ncw_saturated_claim(
    struct node_character_receipt *r)
{
    struct ncw_saturated_result out;
    struct node_work maxed = { UINT64_MAX, UINT64_MAX, UINT64_MAX,
                               UINT64_MAX };
    struct node_character_sheet big;
    uint8_t bigframe[NODE_CHARACTER_WIRE_BYTES];

    out.well_formed = node_character_sheet_make(k_example_root,
                                                &k_example_born, &maxed,
                                                &big) &&
                      node_character_sheet_encode(&big, bigframe) &&
                      big.character.energy == NODE_ENERGY_MAX;
    out.stranger_untouched =
        node_character_sheet_verify(bigframe, sizeof bigframe, NULL, r) &&
        r->sheet.character.energy == NODE_ENERGY_MAX &&
        r->believed.energy == 0 &&
        r->trust == NODE_STANDING_UNVERIFIED;
    return out;
}

static bool ncw_short_buffer_emptied(const struct node_character_receipt *r,
                                     char *small, size_t cap)
{
    return !node_character_receipt_render(r, small, cap) && small[0] == '\0';
}

struct ncw_stranger_render {
    bool says_unverified;
    bool shows_wanderer;
    bool birthday_asserted;
};

static struct ncw_stranger_render ncw_render_stranger(
    const struct node_character_receipt *r, char *text, size_t cap)
{
    struct ncw_stranger_render out;

    out.says_unverified = node_character_receipt_render(r, text, cap) &&
                          strstr(text, "unverified") != NULL;
    out.shows_wanderer = strstr(text, "believed") != NULL &&
                         strstr(text, "wanderer") != NULL;
    out.birthday_asserted = strstr(text, "asserted") != NULL;
    return out;
}

static bool ncw_render_corroborated(const struct node_character_receipt *r,
                                    char *text, size_t cap)
{
    return node_character_receipt_render(r, text, cap) &&
           strstr(text, "corroborated") != NULL &&
           strstr(text, "unverified") == NULL;
}

int test_node_character_wire(void)
{
    int failures = 0;

    /* ── the derived birthplace ─────────────────────────────────────────── */
    {
        struct astro_place p;
        bool in_range = true, varies = false, stable = true;

        NCW_CHECK("a null output has no birthplace written through it",
                  !node_character_birth_place(k_example_root, NULL));

        memset(&p, 0x5a, sizeof p);
        NCW_CHECK("a null identity has no birthplace",
                  !node_character_birth_place(NULL, &p));
        NCW_CHECK("a refused birthplace is zeroed, not left stale",
                  ncw_place_both_zero(&p));

        ncw_scan_birthplaces(&in_range, &varies, &stable);
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
                  ncw_refused_make_zeroed(&s));

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
                  ncw_null_work_is_wanderer(&s));
    }

    /* ── the sheet agrees with the two modules it is built from ─────────── */
    {
        bool form_agrees = true, chart_agrees = true;

        ncw_sheets_follow_sources(&form_agrees, &chart_agrees);
        NCW_CHECK("the sheet's form and standing are node_character's",
                  form_agrees);
        NCW_CHECK("the sheet's chart is platform/modules/astro's chart for the derived place",
                  chart_agrees);
    }

    /* ── (a) the round trip is exact ────────────────────────────────────── */
    {
        bool exact = true, reencodes = true;

        ncw_round_trips(&exact, &reencodes);
        NCW_CHECK("a sheet survives encode and decode field for field", exact);
        NCW_CHECK("re-encoding a decoded frame reproduces it byte for byte",
                  reencodes);
    }

    /* ── (b) no struct padding reaches the wire ─────────────────────────── */
    {
        NCW_CHECK("a sheet built over garbage encodes like one built over zero",
                  ncw_garbage_encodes_like_zero());
    }

    /* ── the golden frame: the cross-platform, cross -O anchor ──────────── */
    {
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        char hex[2u * NODE_CHARACTER_WIRE_BYTES + 1u];

        if (ncw_example_frame(frame)) {
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
        struct node_character_receipt r;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        uint8_t mutated[NODE_CHARACTER_WIRE_BYTES];

        if (!ncw_example_frame(frame)) {
            NCW_CHECK("the bit-flip sweep has a frame to work from", false);
        } else {
            NCW_CHECK("the untouched frame verifies",
                      node_character_sheet_verify(frame, sizeof frame, NULL,
                                                  &r));

            struct ncw_flip_result sw = ncw_sweep_bit_flips(frame, mutated, &r);
            if (!sw.agrees)
                printf("  bit %u: verify=%d oracle=%d\n", sw.bit,
                       sw.verify_value, (int)ncw_oracle_consistent(mutated));
            NCW_CHECK("verify agrees with an independent oracle on all 1056 "
                      "single-bit mutations",
                      sw.agrees);
            NCW_CHECK("some mutations are refused", sw.any_refused);
            /* Frames a flip leaves self-consistent are those whose mutated
             * bytes nothing derives from (spare root bytes, counter bits too
             * low to move a doubling). They are accepted as a DIFFERENT
             * well-formed claim, never a corroborated one; if this went
             * false the sweep would have stopped testing anything. */
            NCW_CHECK("some mutations stay self-consistent and are accepted",
                      sw.any_accepted);
            NCW_CHECK("an accepted mutation still leaves standing unverified",
                      sw.unverified_when_accepted);
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

        /* An energy claim with nothing behind it: zero every counter and
         * keep the standing the real counters produced. Internal
         * consistency refuses it. */
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
                  ncw_receipt_cleared(&r));
    }

    /* ── (d) the standing boundary ──────────────────────────────────────── */
    {
        struct node_character_receipt r;
        uint8_t frame[NODE_CHARACTER_WIRE_BYTES];
        struct ncw_stranger_result st = ncw_stranger_boundary(frame, &r);
        struct ncw_observed_result ob;
        struct ncw_saturated_result sat;

        NCW_CHECK("the example claims a real standing, so the boundary has "
                  "something to refuse",
                  st.claims_real);

        NCW_CHECK("a stranger accepts the sheet", st.accepted);
        NCW_CHECK("a stranger believes no standing at all, whatever is claimed",
                  st.believes_nothing);
        NCW_CHECK("the stranger's receipt still carries the claim verbatim",
                  st.claim_verbatim);
        NCW_CHECK("a stranger still recomputes the form and believes it",
                  st.form_believed);

        ob = ncw_observed_boundary(frame, &st.claimed, &r);
        NCW_CHECK("a claim this node observed exactly is corroborated",
                  ob.exact);
        NCW_CHECK("a claim covered with room to spare is corroborated",
                  ob.spare);
        NCW_CHECK("a claim one counter short of what we saw is accepted but "
                  "unverified",
                  ob.one_short);
        NCW_CHECK("the partly-observed belief comes from our counters, not the "
                  "sheet's",
                  ob.from_our_counters);

        sat = ncw_saturated_claim(&r);
        NCW_CHECK("a saturated claim is a well-formed sheet", sat.well_formed);
        NCW_CHECK("a node cannot talk a stranger into any energy at all",
                  sat.stranger_untouched);
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
                  ncw_short_buffer_emptied(&r, small, sizeof small));

        {
            struct ncw_stranger_render rr =
                ncw_render_stranger(&r, text, sizeof text);

            NCW_CHECK("a stranger's rendering says unverified",
                      rr.says_unverified);
            NCW_CHECK("a stranger's rendering shows the believed standing too",
                      rr.shows_wanderer);
            NCW_CHECK("a stranger's rendering marks the birthday as asserted",
                      rr.birthday_asserted);
        }

        printf("── the worked example, as a stranger sees it ──\n%s", text);

        (void)node_character_sheet_verify(frame, sizeof frame, &k_example_work,
                                          &r);
        NCW_CHECK("a corroborated rendering says so",
                  ncw_render_corroborated(&r, text, sizeof text));

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
