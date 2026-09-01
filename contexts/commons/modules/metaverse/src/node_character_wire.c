/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character_wire — the birthday, the derived birthplace, the fixed
 * 132-byte encoding, and the rule a receiving node applies to a sheet a
 * stranger handed it. metaverse/node_character_wire.h carries the reasoning;
 * this file is the arithmetic.
 *
 * No state of any kind: no statics, no allocation, no I/O, no locks, no clock.
 * Every function is total and depends only on its arguments, which is what
 * lets a test drive the whole thing without a node, a datadir or a network,
 * and what lets three platforms agree byte for byte.
 */

#include "metaverse/node_character_wire.h"

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "metaverse/node_character.h"

#include <stdio.h>
#include <string.h>

/* The exact/approximate boundary, made a compile error rather than a comment.
 * Naming either type below this line does not build. Placed AFTER the includes
 * on purpose: the astro headers declare a double-returning prototype
 * (astro_exact_to_double), and poisoning the identifier first would reject
 * them. Same rule, same spelling, and for the same reason as every exact-path
 * file in platform/modules/astro and contexts/commons/modules/metaverse. */
#pragma GCC poison double float

/* ── The wire layout ──────────────────────────────────────────────────────
 *
 * Written out as offsets rather than as a packed struct. A packed struct moves
 * the layout into the compiler's hands, is undefined to read through a
 * misaligned member pointer on some targets, and still says nothing about byte
 * order. Named offsets say exactly what the bytes are, and the static
 * assertions below make the total a checked fact instead of a comment.
 *
 *   off  len  field
 *     0    6  magic "Z23CHR"
 *     6    1  wire version
 *     7    1  form revision that produced the form fields
 *     8   32  identity root
 *    40    4  birth year        int32, two's complement, big-endian
 *    44    1  birth month
 *    45    1  birth day
 *    46    1  birth hour
 *    47    1  birth minute
 *    48    1  birth second
 *    49    4  hue degrees       big-endian
 *    53    4  energy            big-endian
 *    57    1  silhouette
 *    58    1  marking
 *    59    1  archetype
 *    60    8  bytes served      big-endian
 *    68    8  blocks validated  big-endian
 *    76    8  proofs produced   big-endian
 *    84    8  peers bootstrapped big-endian
 *    92    4  ascendant         sign, degree, arcminute, arcsecond
 *    96   36  nine bodies       four bytes each, in enum astro_body order
 *   132       total
 *
 * Hue and energy each hold a value that fits in sixteen bits and each get a
 * FULL 32-BIT SLOT. base/serialize_le.h offers big-endian codecs at 32 and 64
 * bits and none at 16, and hand-rolling one is exactly the duplication
 * `make lint`'s byte-order gate refuses. Four spare bytes in a frame this size
 * is a better trade than a private codec, and better than packing two unlike
 * scalars into one slot where a reader has to know which half is which.
 */
#define NCW_OFF_MAGIC      0u
#define NCW_MAGIC_LEN      6u
#define NCW_OFF_VERSION    6u
#define NCW_OFF_FORM_REV   7u
#define NCW_OFF_ROOT       8u
#define NCW_ROOT_LEN       32u
#define NCW_OFF_YEAR       40u
#define NCW_OFF_MONTH      44u
#define NCW_OFF_DAY        45u
#define NCW_OFF_HOUR       46u
#define NCW_OFF_MINUTE     47u
#define NCW_OFF_SECOND     48u
#define NCW_OFF_HUE        49u
#define NCW_OFF_ENERGY     53u
#define NCW_OFF_SILHOUETTE 57u
#define NCW_OFF_MARKING    58u
#define NCW_OFF_ARCHETYPE  59u
#define NCW_OFF_WORK       60u
#define NCW_WORK_LEN       32u
#define NCW_OFF_CHART      92u
#define NCW_POSITION_LEN   4u

static const char k_ncw_magic[NCW_MAGIC_LEN] = { 'Z', '2', '3', 'C', 'H', 'R' };

/* The chart occupies exactly the rest of the frame, and the frame is exactly
 * the declared size. Both are assertions rather than arithmetic a reader has
 * to redo, because an off-by-one here is a silent field shift rather than a
 * crash. */
_Static_assert(NCW_OFF_CHART +
                       (1u + (unsigned)ASTRO_BODY_COUNT) * NCW_POSITION_LEN ==
                   NODE_CHARACTER_WIRE_BYTES,
               "the wire layout must fill exactly NODE_CHARACTER_WIRE_BYTES");
_Static_assert(NCW_OFF_WORK + NCW_WORK_LEN == NCW_OFF_CHART,
               "the four work counters must fill the space before the chart");
_Static_assert(NCW_OFF_HUE + 4u == NCW_OFF_ENERGY,
               "hue must fill the 32-bit slot before energy");
_Static_assert(NODE_ENERGY_MAX <= UINT16_MAX,
               "energy must fit the uint16_t field the decoder narrows it to");
_Static_assert(NODE_ARCHETYPE_COUNT <= 256,
               "the archetype must fit the one byte the layout gives it");
_Static_assert(NODE_CHARACTER_FORM_REV <= 255u,
               "the form revision must fit the one byte the layout gives it");

/* Every multi-byte field goes through base/serialize_le.h's big-endian
 * codecs — zcl_write_u32_be / zcl_read_u32_be / zcl_write_u64_be /
 * zcl_read_u64_be. They are the tree's ONE such codec, they go through memcpy
 * so an unaligned offset is fine, and they cannot let the host's byte order
 * reach the wire, which is the one thing this encoding may never do. A private
 * pack/unpack here would be a second copy of that, and `make lint` refuses one
 * by name.
 */

/* ── The derived birthplace ───────────────────────────────────────────────
 *
 * Four bytes of the identity root become a latitude and four more a longitude,
 * each folded into platform/modules/astro's accepted range so a chart cast for the result is
 * never refused for its place.
 *
 * The byte windows are disjoint from the three the form derivation reads
 * (root[0..1], root[7], root[19]), for the same reason node_character.c spreads
 * those: an identity root is a hash, so its bytes are already unrelated, and
 * keeping the windows apart costs nothing and removes the question.
 *
 * The fold is a modulo and is very slightly biased — 2^32 is not a multiple of
 * either span, so some microdegrees are about 1 part in 24 likelier than
 * others. That is stated rather than corrected, exactly as node_character.c
 * states it for the hue: rejection sampling would make the derivation depend on
 * how many bytes it consumed, and nothing whatsoever is won by landing on a
 * particular birthplace, so the bias is not an attack surface. At microdegree
 * resolution it is also not perceptible.
 *
 * This is a FICTIONAL point on a globe. It is not where the machine is, no
 * input to it comes from the machine, and no operator geography reaches this
 * file. */
#define NCW_LAT_SPAN  (2u * (uint32_t)ASTRO_LATITUDE_MICRODEG_LIMIT + 1u)
#define NCW_LON_SPAN  (2u * (uint32_t)ASTRO_LONGITUDE_MICRODEG_LIMIT + 1u)

bool node_character_birth_place(const uint8_t identity_root[32],
                                struct astro_place *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!identity_root)
        return false;

    /* The subtraction is done in int64_t and then narrowed, so the negative
     * half of the range is produced by arithmetic that cannot overflow rather
     * than by a signed cast of a value that may not fit. */
    int64_t lat = (int64_t)(zcl_read_u32_be(identity_root + 24) % NCW_LAT_SPAN) -
                  (int64_t)ASTRO_LATITUDE_MICRODEG_LIMIT;
    int64_t lon = (int64_t)(zcl_read_u32_be(identity_root + 28) % NCW_LON_SPAN) -
                  (int64_t)ASTRO_LONGITUDE_MICRODEG_LIMIT;

    out->latitude_microdeg = (int32_t)lat;
    out->longitude_microdeg = (int32_t)lon;
    return true;
}

/* ── Range checks ─────────────────────────────────────────────────────────
 *
 * Every one of these is applied on the way IN from the wire and again on the
 * way OUT, so a malformed frame is refused at the door and a malformed sheet
 * built in this process is refused before it becomes somebody else's problem.
 */
static bool ncw_position_valid(const struct node_star_position *p)
{
    return p->sign < (uint8_t)ASTRO_SIGN_COUNT && p->degree_in_sign < 30u &&
           p->arcminute < 60u && p->arcsecond < 60u;
}

static bool ncw_chart_valid(const struct node_star_chart *c)
{
    if (!ncw_position_valid(&c->ascendant))
        return false;
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++)
        if (!ncw_position_valid(&c->body[i]))
            return false;
    return true;
}

static bool ncw_character_valid(const struct node_character *c)
{
    return c->hue_deg < 360u && c->silhouette < NODE_SILHOUETTE_COUNT &&
           c->marking < NODE_MARKING_COUNT &&
           c->form_rev == (uint8_t)NODE_CHARACTER_FORM_REV &&
           (unsigned)c->archetype < (unsigned)NODE_ARCHETYPE_COUNT &&
           c->energy <= NODE_ENERGY_MAX;
}

static bool ncw_sheet_valid(const struct node_character_sheet *s)
{
    return s && astro_instant_is_valid(&s->born) &&
           ncw_character_valid(&s->character) && ncw_chart_valid(&s->chart);
}

/* Compare BY VALUE, never with memcmp.
 *
 * struct node_character has padding after `marking` (three uint8_t fields
 * behind a uint16_t, then an enum), and C does not define what a struct
 * assignment leaves in a destination's padding. A caller builds one on the
 * stack, the compiler deletes the memset that zeroed it because nothing ever
 * reads the padding — legal, and both gcc and clang do it at -O2 — and a
 * memcmp then reports two identical characters as different. The recomputation
 * check below is the whole point of this module, so it compares exactly the
 * fields that mean something. */
static bool ncw_character_equal(const struct node_character *a,
                                const struct node_character *b)
{
    return a->hue_deg == b->hue_deg && a->silhouette == b->silhouette &&
           a->marking == b->marking && a->form_rev == b->form_rev &&
           a->archetype == b->archetype && a->energy == b->energy;
}

static bool ncw_position_equal(const struct node_star_position *a,
                               const struct node_star_position *b)
{
    return a->sign == b->sign && a->degree_in_sign == b->degree_in_sign &&
           a->arcminute == b->arcminute && a->arcsecond == b->arcsecond;
}

static bool ncw_chart_equal(const struct node_star_chart *a,
                            const struct node_star_chart *b)
{
    if (!ncw_position_equal(&a->ascendant, &b->ascendant))
        return false;
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++)
        if (!ncw_position_equal(&a->body[i], &b->body[i]))
            return false;
    return true;
}

/* ── Making a sheet ───────────────────────────────────────────────────────── */

/* Project one exact chart position onto the four integers that travel.
 * astro_position's fields are bounded by platform/modules/astro's own contract, so the
 * narrowing cannot lose information; the caller re-checks the range anyway,
 * because a platform/modules/astro defect should be refused here rather than encoded. */
static void ncw_project(const struct astro_position *in,
                        struct node_star_position *out)
{
    out->sign = (uint8_t)in->sign;
    out->degree_in_sign = (uint8_t)in->degree_in_sign;
    out->arcminute = (uint8_t)in->arcminute;
    out->arcsecond = (uint8_t)in->arcsecond;
}

/* The chart of one identity born at one moment. This is the function the
 * receiver runs too, so sender and receiver cannot drift apart by computing
 * "the same" chart two ways. */
static bool ncw_chart_of(const uint8_t identity_root[32],
                         const struct astro_instant *born,
                         struct node_star_chart *out)
{
    struct astro_place place;
    struct astro_chart chart;

    memset(out, 0, sizeof *out);
    if (!node_character_birth_place(identity_root, &place))
        return false;
    if (!astro_chart_compute(born, &place, &chart))
        return false;

    ncw_project(&chart.ascendant, &out->ascendant);
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++)
        ncw_project(&chart.body[i], &out->body[i]);
    return ncw_chart_valid(out);
}

bool node_character_sheet_make(const uint8_t identity_root[32],
                               const struct astro_instant *born,
                               const struct node_work *work,
                               struct node_character_sheet *out)
{
    if (!out)
        return false;
    /* Zero the WHOLE struct, padding included, before anything is written: a
     * refusal must leave nothing a caller could mistake for a character, and a
     * caller that compares two sheets byte for byte must not be reading
     * uninitialised stack. */
    memset(out, 0, sizeof *out);
    if (!identity_root || !born)
        return false;
    if (!astro_instant_is_valid(born))
        return false;

    memcpy(out->identity_root, identity_root, NCW_ROOT_LEN);
    out->born = *born;
    if (work)
        out->work = *work;

    if (!node_character_derive(identity_root, work, &out->character)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    if (!ncw_chart_of(identity_root, born, &out->chart)) {
        /* platform/modules/astro never returns a partially valid chart, and neither does
         * this: a poisoned intermediate becomes a refusal, not a plausible
         * character. */
        memset(out, 0, sizeof *out);
        return false;
    }
    if (!ncw_sheet_valid(out)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    return true;
}

/* ── Encode ───────────────────────────────────────────────────────────────── */

static void ncw_put_position(uint8_t *p, const struct node_star_position *pos)
{
    p[0] = pos->sign;
    p[1] = pos->degree_in_sign;
    p[2] = pos->arcminute;
    p[3] = pos->arcsecond;
}

static void ncw_get_position(const uint8_t *p, struct node_star_position *pos)
{
    pos->sign = p[0];
    pos->degree_in_sign = p[1];
    pos->arcminute = p[2];
    pos->arcsecond = p[3];
}

bool node_character_sheet_encode(const struct node_character_sheet *sheet,
                                 uint8_t out[NODE_CHARACTER_WIRE_BYTES])
{
    if (!out)
        return false;
    memset(out, 0, NODE_CHARACTER_WIRE_BYTES);
    if (!ncw_sheet_valid(sheet))
        return false;

    memcpy(out + NCW_OFF_MAGIC, k_ncw_magic, NCW_MAGIC_LEN);
    out[NCW_OFF_VERSION] = (uint8_t)NODE_CHARACTER_WIRE_VERSION;
    out[NCW_OFF_FORM_REV] = sheet->character.form_rev;
    memcpy(out + NCW_OFF_ROOT, sheet->identity_root, NCW_ROOT_LEN);

    /* The year is signed and can be negative (proleptic Gregorian). Cast
     * through uint32_t so the encoding is two's complement BY DEFINITION
     * rather than by whatever the platform does with a signed shift. */
    zcl_write_u32_be(out + NCW_OFF_YEAR, (uint32_t)sheet->born.year);
    out[NCW_OFF_MONTH] = sheet->born.month;
    out[NCW_OFF_DAY] = sheet->born.day;
    out[NCW_OFF_HOUR] = sheet->born.hour;
    out[NCW_OFF_MINUTE] = sheet->born.minute;
    out[NCW_OFF_SECOND] = sheet->born.second;

    zcl_write_u32_be(out + NCW_OFF_HUE, sheet->character.hue_deg);
    out[NCW_OFF_SILHOUETTE] = sheet->character.silhouette;
    out[NCW_OFF_MARKING] = sheet->character.marking;
    out[NCW_OFF_ARCHETYPE] = (uint8_t)sheet->character.archetype;
    zcl_write_u32_be(out + NCW_OFF_ENERGY, sheet->character.energy);

    zcl_write_u64_be(out + NCW_OFF_WORK + 0u, sheet->work.bytes_served);
    zcl_write_u64_be(out + NCW_OFF_WORK + 8u, sheet->work.blocks_validated);
    zcl_write_u64_be(out + NCW_OFF_WORK + 16u, sheet->work.proofs_produced);
    zcl_write_u64_be(out + NCW_OFF_WORK + 24u, sheet->work.peers_bootstrapped);

    ncw_put_position(out + NCW_OFF_CHART, &sheet->chart.ascendant);
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++)
        ncw_put_position(out + NCW_OFF_CHART + (1u + i) * NCW_POSITION_LEN,
                         &sheet->chart.body[i]);
    return true;
}

/* ── Decode ───────────────────────────────────────────────────────────────── */

bool node_character_sheet_decode(const uint8_t *wire, size_t len,
                                 struct node_character_sheet *out)
{
    uint32_t archetype, hue, energy;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!wire || len != (size_t)NODE_CHARACTER_WIRE_BYTES)
        return false;
    if (memcmp(wire + NCW_OFF_MAGIC, k_ncw_magic, NCW_MAGIC_LEN) != 0)
        return false;
    if (wire[NCW_OFF_VERSION] != (uint8_t)NODE_CHARACTER_WIRE_VERSION)
        return false;
    /* A sheet produced under a different form revision is REFUSED rather than
     * read: this build's derivation would disagree with it about a node that
     * did nothing wrong, and reporting that as a lie would be worse than
     * saying plainly that the two ends do not implement the same rules. */
    if (wire[NCW_OFF_FORM_REV] != (uint8_t)NODE_CHARACTER_FORM_REV)
        return false;

    memcpy(out->identity_root, wire + NCW_OFF_ROOT, NCW_ROOT_LEN);

    out->born.year = (int32_t)zcl_read_u32_be(wire + NCW_OFF_YEAR);
    out->born.month = wire[NCW_OFF_MONTH];
    out->born.day = wire[NCW_OFF_DAY];
    out->born.hour = wire[NCW_OFF_HOUR];
    out->born.minute = wire[NCW_OFF_MINUTE];
    out->born.second = wire[NCW_OFF_SECOND];

    /* Hue and energy travel in 32-bit slots and land in 16-bit fields, so a
     * frame carrying a wider value must be REFUSED here rather than truncated
     * into a plausible one: silently keeping the low half would turn a
     * malformed claim into a well-formed different claim. */
    hue = zcl_read_u32_be(wire + NCW_OFF_HUE);
    energy = zcl_read_u32_be(wire + NCW_OFF_ENERGY);
    archetype = wire[NCW_OFF_ARCHETYPE];
    /* Range-check every widened field before the narrowing casts, so an
     * unknown archetype is a refusal rather than an enum holding a value no
     * switch handles. */
    if (hue > UINT16_MAX || energy > UINT16_MAX ||
        archetype >= (uint32_t)NODE_ARCHETYPE_COUNT) {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->character.hue_deg = (uint16_t)hue;
    out->character.energy = (uint16_t)energy;
    out->character.archetype = (enum node_archetype)archetype;
    out->character.silhouette = wire[NCW_OFF_SILHOUETTE];
    out->character.marking = wire[NCW_OFF_MARKING];
    out->character.form_rev = wire[NCW_OFF_FORM_REV];

    out->work.bytes_served = zcl_read_u64_be(wire + NCW_OFF_WORK + 0u);
    out->work.blocks_validated = zcl_read_u64_be(wire + NCW_OFF_WORK + 8u);
    out->work.proofs_produced = zcl_read_u64_be(wire + NCW_OFF_WORK + 16u);
    out->work.peers_bootstrapped = zcl_read_u64_be(wire + NCW_OFF_WORK + 24u);

    ncw_get_position(wire + NCW_OFF_CHART, &out->chart.ascendant);
    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++)
        ncw_get_position(wire + NCW_OFF_CHART + (1u + i) * NCW_POSITION_LEN,
                         &out->chart.body[i]);

    if (!ncw_sheet_valid(out)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    return true;
}

/* ── Verify ───────────────────────────────────────────────────────────────── */

/* Does what this node observed already account for the claim, field by field?
 *
 * Every claimed counter must be covered. A single uncovered field leaves the
 * whole claim unverified rather than partly believed: the counters are combined
 * into ONE weighted total, so believing five of six fields would still produce
 * an energy this node cannot stand behind. */
static bool ncw_work_covered(const struct node_work *claimed,
                             const struct node_work *observed)
{
    return claimed->bytes_served <= observed->bytes_served &&
           claimed->blocks_validated <= observed->blocks_validated &&
           claimed->proofs_produced <= observed->proofs_produced &&
           claimed->peers_bootstrapped <= observed->peers_bootstrapped;
}

bool node_character_sheet_verify(const uint8_t *wire, size_t len,
                                 const struct node_work *observed,
                                 struct node_character_receipt *out)
{
    struct node_character recomputed;
    struct node_star_chart chart;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);

    if (!node_character_sheet_decode(wire, len, &out->sheet)) {
        memset(out, 0, sizeof *out);
        return false;
    }

    /* 1. Form AND the internal consistency of the standing. The claimed
     *    counters are re-derived, and the archetype and energy the sheet
     *    carries must be exactly what they produce. This is what stops a node
     *    shipping a bare high energy with nothing behind it: the only way to
     *    claim a large number is to claim the large counters that justify it,
     *    which is a specific assertion somebody else can check against their
     *    own records. It does not make the counters true. */
    if (!node_character_derive(out->sheet.identity_root, &out->sheet.work,
                               &recomputed)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    if (!ncw_character_equal(&recomputed, &out->sheet.character)) {
        memset(out, 0, sizeof *out);
        return false;
    }

    /* 2. The chart, recomputed from the identity root and the birthday alone.
     *    A tampered birthday, a tampered identity root, or a tampered chart
     *    byte all land here. */
    if (!ncw_chart_of(out->sheet.identity_root, &out->sheet.born, &chart)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    if (!ncw_chart_equal(&chart, &out->sheet.chart)) {
        memset(out, 0, sizeof *out);
        return false;
    }

    /* 3. What this node is willing to believe. Derived from ITS OWN
     *    observations and from nothing on the wire, so a sender cannot raise
     *    it by editing its own sheet. A stranger observing nothing believes a
     *    wanderer with zero energy — which is the honest description of a node
     *    it has never seen do anything. */
    if (!node_character_derive(out->sheet.identity_root, observed,
                               &out->believed)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->trust = (observed && ncw_work_covered(&out->sheet.work, observed))
                     ? NODE_STANDING_CORROBORATED
                     : NODE_STANDING_UNVERIFIED;
    return true;
}

const char *node_standing_trust_name(enum node_standing_trust trust)
{
    switch (trust) {
    case NODE_STANDING_UNVERIFIED:   return "unverified";
    case NODE_STANDING_CORROBORATED: return "corroborated";
    default:                         return "unknown";
    }
}

/* ── Text form ────────────────────────────────────────────────────────────
 *
 * A person-facing rendering, not a wire form: it is never parsed back, so
 * snprintf is fine here where character_sheet_text.c's round-tripping seed form
 * had to be written by hand. What is NOT negotiable is that a short buffer
 * refuses the whole render instead of emitting a truncated character — a sheet
 * that stops mid-line is a sheet whose standing line may be the part that went
 * missing. */
static bool ncw_emit(char *out, size_t cap, size_t *n, const char *text)
{
    size_t len = strlen(text);

    if (len >= cap - *n)
        return false;
    memcpy(out + *n, text, len + 1u);
    *n += len;
    return true;
}

#define NCW_LINE(...)                                                         \
    do {                                                                      \
        int wrote = snprintf(line, sizeof line, __VA_ARGS__);                 \
        if (wrote < 0 || (size_t)wrote >= sizeof line)                        \
            return false;                                                     \
        if (!ncw_emit(out, cap, &n, line))                                    \
            return false;                                                     \
    } while (0)

bool node_character_receipt_render(const struct node_character_receipt *receipt,
                                   char *out, size_t cap)
{
    char line[160];
    char hex[2u * NCW_ROOT_LEN + 1u];
    size_t n = 0;

    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!receipt || !ncw_sheet_valid(&receipt->sheet))
        return false;

    /* base/hex.h is the tree's one hex encoder; a private nibble ladder here
     * would be a second one, and `make lint` refuses it by name. */
    zcl_hex_encode(receipt->sheet.identity_root, NCW_ROOT_LEN, hex);

    NCW_LINE("  identity  %s\n", hex);
    NCW_LINE("  born      %04d-%02u-%02uT%02u:%02u:%02uZ (asserted)\n",
             (int)receipt->sheet.born.year, (unsigned)receipt->sheet.born.month,
             (unsigned)receipt->sheet.born.day,
             (unsigned)receipt->sheet.born.hour,
             (unsigned)receipt->sheet.born.minute,
             (unsigned)receipt->sheet.born.second);
    NCW_LINE("  form      hue %u deg, silhouette %u, marking %u "
             "(revision %u, recomputed)\n",
             (unsigned)receipt->sheet.character.hue_deg,
             (unsigned)receipt->sheet.character.silhouette,
             (unsigned)receipt->sheet.character.marking,
             (unsigned)receipt->sheet.character.form_rev);
    NCW_LINE("  rising    %s %u deg %02u'\n",
             astro_sign_name((enum astro_sign)receipt->sheet.chart.ascendant.sign),
             (unsigned)receipt->sheet.chart.ascendant.degree_in_sign,
             (unsigned)receipt->sheet.chart.ascendant.arcminute);

    for (unsigned i = 0; i < (unsigned)ASTRO_BODY_COUNT; i++) {
        const struct node_star_position *p = &receipt->sheet.chart.body[i];
        NCW_LINE("  %-9s %s %u deg %02u' %02u\"\n",
                 astro_body_name((enum astro_body)i),
                 astro_sign_name((enum astro_sign)p->sign),
                 (unsigned)p->degree_in_sign, (unsigned)p->arcminute,
                 (unsigned)p->arcsecond);
    }

    /* Both numbers, both labelled. Printing the claim alone would be exactly
     * the promotion this module exists to prevent, and printing only what we
     * believe would hide what the sender said it was. */
    NCW_LINE("  believed  %s, energy %u (from work THIS node observed)\n",
             node_archetype_name(receipt->believed.archetype),
             (unsigned)receipt->believed.energy);
    NCW_LINE("  claimed   %s, energy %u [%s]\n",
             node_archetype_name(receipt->sheet.character.archetype),
             (unsigned)receipt->sheet.character.energy,
             node_standing_trust_name(receipt->trust));
    NCW_LINE("  claimed   %llu bytes, %llu blocks, %llu proofs, %llu peers\n",
             (unsigned long long)receipt->sheet.work.bytes_served,
             (unsigned long long)receipt->sheet.work.blocks_validated,
             (unsigned long long)receipt->sheet.work.proofs_produced,
             (unsigned long long)receipt->sheet.work.peers_bootstrapped);
    return true;
}
