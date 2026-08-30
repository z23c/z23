/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * character_sheet — seed validation, the character's root, and the chart to
 * attributes derivation. Every rule and every constant that decides what a
 * character IS lives here; metaverse/character_sheet.h carries the reasoning
 * for why the total is fixed and only the spread is earned.
 *
 * SRD 5.1 attribution: see the module header. The material used here is the
 * six ability names, the modifier rule floor((score - 10) / 2), and the
 * standard array's total of 72. Nothing else, and no Product Identity.
 *
 * This file holds no state: no statics, no allocation, no I/O, no locks, no
 * clock. Every function is total and depends only on its arguments, which is
 * what lets a test drive the whole space without a node, a datadir or a
 * network, and what lets three platforms agree byte for byte.
 */

#include "metaverse/character_sheet.h"

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "base/serialize_le.h"
#include "metaverse/property_id.h"
#include "sha3/sha3.h"

#include <string.h>

/* The exact/approximate boundary, made a compile error rather than a comment.
 * Naming either type below this line does not build. Placed AFTER the
 * includes on purpose: the standard and astro headers declare double-returning
 * prototypes (astro_exact_to_double among them), and poisoning the identifier
 * first would reject them. Same rule, same spelling, and for the same reason
 * as every exact-path file in lib/astro — see lib/astro/src/astro_priv.h for
 * why the pragma rather than a `#define double`. */
#pragma GCC poison double float

/* ── The zodiac's own arithmetic ─────────────────────────────────────────
 *
 * Positions are compared in ARCSECONDS OF THE WHOLE ZODIAC, 0..1295999,
 * assembled from the integer readouts astro_position already carries. Two
 * reasons it is done this way rather than with astro_exact arithmetic here:
 *
 *   - those readouts were computed once inside lib/astro and stored in the
 *     chart precisely so that two nodes compare the SAME derived integers
 *     instead of each deriving them their own way (astro_chart.h says so);
 *   - it keeps this module's arithmetic to plain bounded integers, which is
 *     the strongest form of the determinism this file needs.
 *
 * The cost is stated rather than hidden: the readouts are truncated at the
 * arcsecond, so a body within one arcsecond of a house cusp could fall on the
 * far side of it from where an infinitely precise computation would put it.
 * That is a DETERMINISTIC truncation — every node truncates identically,
 * because every node reads the same stored integers — so it cannot make two
 * nodes disagree, which is the only property that matters here. */
#define CS_ARCSEC_PER_ZODIAC 1296000
#define CS_ARCSEC_PER_SIGN 108000

static int32_t cs_zodiac_arcsec(const struct astro_position *p)
{
    /* astro_position's fields are bounded by lib/astro's own contract (sign
     * < 12, degree 0..29, arcminute and arcsecond 0..59), so this cannot
     * exceed the zodiac. Clamping a value that cannot occur would hide a
     * lib/astro defect rather than report it, so the bound is asserted by the
     * caller's range checks on the finished sheet instead. */
    return (int32_t)p->sign * CS_ARCSEC_PER_SIGN +
           (int32_t)p->degree_in_sign * 3600 + (int32_t)p->arcminute * 60 +
           (int32_t)p->arcsecond;
}

/* Equal houses from the ascendant, 1..12 — the house system lib/astro
 * computes (astro_chart.h) and therefore the only one this module may claim.
 * The result is where the body sits RELATIVE to the rising degree, which is
 * what makes the birth place and the time of day matter at all: move the
 * place and the ascendant moves, and every body changes house. */
static unsigned cs_house_of(const struct astro_position *body,
                            const struct astro_position *ascendant)
{
    int32_t rel = cs_zodiac_arcsec(body) - cs_zodiac_arcsec(ascendant);

    rel %= CS_ARCSEC_PER_ZODIAC;
    if (rel < 0)
        rel += CS_ARCSEC_PER_ZODIAC;
    return (unsigned)(rel / CS_ARCSEC_PER_SIGN) + 1u;
}

/* Accidental dignity: how PROMINENT a placement is, by house. The traditional
 * three-tier rule, and the classical justification for each tier is the
 * observer's own horizon — angular houses hold the rising, setting and
 * culminating degrees, so a body there is visibly placed; cadent houses are
 * the ones falling away from those angles. */
static unsigned cs_house_rank(unsigned house)
{
    switch (house) {
    case 1: case 4: case 7: case 10: return 3u; /* angular   */
    case 2: case 5: case 8: case 11: return 2u; /* succedent */
    case 3: case 6: case 9: case 12: return 1u; /* cadent    */
    default: break;
    }
    /* cs_house_of() cannot produce this. Answering with the weakest tier
     * rather than indexing past a table keeps the function total. */
    return 1u;
}

/* ── Essential dignity ───────────────────────────────────────────────────
 *
 * The traditional scheme, encoded as the RULE rather than as a transcribed
 * 7x12 table: each body names the sign or signs it rules and the sign it is
 * exalted in, and the two debilities are the OPPOSITE signs — detriment
 * opposite a rulership, fall opposite the exaltation. Encoding the opposition
 * structurally rather than typing out eighty-four cells removes the whole
 * class of transcription error, and a test asserts the relation holds for
 * every body rather than spot-checking cells.
 *
 * Only the seven traditional bodies appear. Uranus and Neptune are ABSENT and
 * that is deliberate: they have no traditional rulership, the modern
 * assignments are contested, and inventing a dignity for them so the table
 * would look complete is exactly the move astro_chart.h refused for Pluto. A
 * body with no row is peregrine, which is the honest answer — "this scheme
 * says nothing about it" — and not a penalty. */
struct cs_dignity_rule {
    enum astro_body body;
    int8_t rules_a; /* sign, always present */
    int8_t rules_b; /* second rulership, or -1 */
    int8_t exalts;  /* sign, always present */
};

static const struct cs_dignity_rule k_dignity[] = {
    { ASTRO_BODY_SUN,     ASTRO_SIGN_LEO,         -1,
      ASTRO_SIGN_ARIES },
    { ASTRO_BODY_MOON,    ASTRO_SIGN_CANCER,      -1,
      ASTRO_SIGN_TAURUS },
    { ASTRO_BODY_MERCURY, ASTRO_SIGN_GEMINI,      ASTRO_SIGN_VIRGO,
      ASTRO_SIGN_VIRGO },
    { ASTRO_BODY_VENUS,   ASTRO_SIGN_TAURUS,      ASTRO_SIGN_LIBRA,
      ASTRO_SIGN_PISCES },
    { ASTRO_BODY_MARS,    ASTRO_SIGN_ARIES,       ASTRO_SIGN_SCORPIO,
      ASTRO_SIGN_CAPRICORN },
    { ASTRO_BODY_JUPITER, ASTRO_SIGN_SAGITTARIUS, ASTRO_SIGN_PISCES,
      ASTRO_SIGN_CANCER },
    { ASTRO_BODY_SATURN,  ASTRO_SIGN_CAPRICORN,   ASTRO_SIGN_AQUARIUS,
      ASTRO_SIGN_LIBRA },
};

static int8_t cs_opposite(int8_t sign)
{
    return (int8_t)((sign + 6) % (int)ASTRO_SIGN_COUNT);
}

unsigned character_dignity(enum astro_body body, enum astro_sign sign)
{
    if (body < 0 || body >= ASTRO_BODY_COUNT || sign < 0 ||
        sign >= ASTRO_SIGN_COUNT)
        return CHARACTER_DIGNITY_PEREGRINE;

    for (size_t i = 0; i < sizeof k_dignity / sizeof k_dignity[0]; i++) {
        const struct cs_dignity_rule *r = &k_dignity[i];
        if (r->body != body)
            continue;

        /* Order matters where two claims overlap, and both overlaps are
         * real. Mercury in Virgo both rules and is exalted — the stronger
         * claim wins. Mercury in Pisces is both its detriment and its fall —
         * the WORSE claim wins, because being doubly debilitated is not
         * better than being singly debilitated. Hence: dignities first,
         * strongest first; then debilities, worst first. */
        if ((int8_t)sign == r->rules_a || (int8_t)sign == r->rules_b)
            return CHARACTER_DIGNITY_RULERSHIP;
        if ((int8_t)sign == r->exalts)
            return CHARACTER_DIGNITY_EXALTATION;
        if ((int8_t)sign == cs_opposite(r->exalts))
            return CHARACTER_DIGNITY_FALL;
        if ((int8_t)sign == cs_opposite(r->rules_a) ||
            (r->rules_b >= 0 && (int8_t)sign == cs_opposite(r->rules_b)))
            return CHARACTER_DIGNITY_DETRIMENT;
        return CHARACTER_DIGNITY_PEREGRINE;
    }
    /* No row: Uranus and Neptune. Peregrine is "this scheme is silent about
     * it", which is true, rather than zero, which would be a judgement. */
    return CHARACTER_DIGNITY_PEREGRINE;
}

/* ── Which body signifies which ability ──────────────────────────────────
 *
 * One significator per attribute, taken from the classical significations
 * rather than invented, so a reader who knows the tradition can predict the
 * mapping instead of memorising it:
 *
 *   Strength     Mars     the martial planet; force, blood, iron
 *   Dexterity    Mercury  the swift messenger; the hands, quickness, sleight
 *   Constitution Saturn   ruler of the bones; endurance, what survives time
 *   Intelligence Jupiter  learning, philosophy, the expansive mind
 *   Wisdom       Moon     reflection, instinct, the inner tide
 *   Charisma     Venus    grace, attraction, what draws others in
 *
 * The Sun is deliberately NOT one of the six. Traditionally it signifies the
 * self as a whole rather than any single faculty, and that is exactly the job
 * it does below: it governs how EVENLY the points spread, not where they
 * land. Uranus and Neptune signify nothing here, for the reason the dignity
 * table gives. */
static const enum astro_body k_significator[CHARACTER_ATTRIBUTE_COUNT] = {
    [CHARACTER_ATTR_STRENGTH]     = ASTRO_BODY_MARS,
    [CHARACTER_ATTR_DEXTERITY]    = ASTRO_BODY_MERCURY,
    [CHARACTER_ATTR_CONSTITUTION] = ASTRO_BODY_SATURN,
    [CHARACTER_ATTR_INTELLIGENCE] = ASTRO_BODY_JUPITER,
    [CHARACTER_ATTR_WISDOM]       = ASTRO_BODY_MOON,
    [CHARACTER_ATTR_CHARISMA]     = ASTRO_BODY_VENUS,
};

enum astro_body character_attribute_significator(enum character_attribute a)
{
    if (a < 0 || a >= CHARACTER_ATTRIBUTE_COUNT)
        return ASTRO_BODY_COUNT;
    return k_significator[a];
}

/* ── The weights ─────────────────────────────────────────────────────────
 *
 * A significator's weight is the traditional assessment of how strong that
 * planet is IN THIS CHART, and nothing else. Four terms, each with its own
 * job, and the multipliers are the entire editorial content of this file:
 *
 *   floor            1        No attribute is ever mute. A weight of zero
 *                             would let one ability be excluded from the
 *                             apportionment entirely, and "this character has
 *                             no Wisdom at all" is not a distribution, it is
 *                             a hole.
 *   essential        16 x d   d in 0..5. The dominant term, because where a
 *                             planet sits in the zodiac is the tradition's
 *                             primary judgement of it. Spans 0..80.
 *   accidental        8 x r   r in 1..3, by house. Spans 8..24 — deliberately
 *                             smaller than essential, and deliberately never
 *                             zero: a cadent planet is weak, not absent.
 *   arc              m >> 5   m = arcminutes into the sign, 0..1799, so this
 *                             spans 0..56. The FINE term. It carries no
 *                             traditional meaning on its own and is not
 *                             pretending to: its job is to make two charts
 *                             that agree on every sign and house still
 *                             produce different characters, which a
 *                             coarse-only derivation would not.
 *
 * Range: 9 to 161, a ratio of about 18:1 before the Sun's term.
 *
 *   integration      12 x s   s = the Sun's own essential dignity, 0..5,
 *                             added IDENTICALLY to all six.
 *
 * That last term is the one worth explaining, because an additive constant
 * looks like it should do nothing. It does not shift the ranking — it
 * COMPRESSES it. Apportionment reads ratios, so adding 60 to weights that
 * spanned 9..161 turns an 18:1 spread into 3.2:1 and hands out a far more
 * even character; adding 0 leaves the spread at its sharpest. So a dignified
 * Sun produces someone broadly capable and a debilitated one produces a
 * specialist, which is very close to what the tradition says the Sun does,
 * and it is why the Sun earns a place without being one of the six.
 *
 * None of these multipliers can affect the TOTAL. They decide only the shape
 * of the split; see cs_apportion(). */
#define CS_W_FLOOR 1u
#define CS_W_ESSENTIAL 16u
#define CS_W_ACCIDENTAL 8u
#define CS_W_ARC_SHIFT 5u
#define CS_W_INTEGRATION 12u

/* The largest weight any chart can produce, used to bound the apportionment's
 * arithmetic below. */
#define CS_W_MAX                                                              \
    (CS_W_FLOOR + CS_W_ESSENTIAL * CHARACTER_DIGNITY_MAX +                    \
     CS_W_ACCIDENTAL * 3u + (1799u >> CS_W_ARC_SHIFT) +                       \
     CS_W_INTEGRATION * CHARACTER_DIGNITY_MAX)

/* ── Apportionment: the fixed total, by construction ─────────────────────
 *
 * Every attribute starts at CHARACTER_ATTRIBUTE_MIN. Exactly
 * CS_SPREAD_POINTS = TOTAL - COUNT*MIN further points are then handed out ONE
 * AT A TIME, each to whichever attribute currently has the strongest claim
 * and is not already at its ceiling.
 *
 * The invariant that the whole design rests on is therefore not asserted, it
 * is arithmetic: the loop runs exactly CS_SPREAD_POINTS times and each
 * iteration adds exactly one point, so the sum is COUNT*MIN + CS_SPREAD_POINTS
 * = TOTAL for ANY weights whatsoever — including all-equal, all-minimum, or a
 * set produced by a chart nobody anticipated. No weight, and no chart, can
 * change how many points exist.
 *
 * The claim is the divisor rule w[i] / (bonus[i] + 1): an attribute that has
 * already been given points has to be proportionally stronger to be given
 * another. Compared by CROSS-MULTIPLICATION in integers —
 * w[i]*(bonus[j]+1) > w[j]*(bonus[i]+1) — so there is no division and no
 * rounding anywhere in the decision. Ties go to the lower index: an arbitrary
 * rule, but a STABLE one, which is what two nodes need.
 *
 * A bucket at its ceiling is skipped. There is always an eligible bucket
 * because COUNT*(MAX-MIN) >= CS_SPREAD_POINTS, asserted below — without that,
 * the loop could find nothing to give a point to and the total would silently
 * come out short. */
#define CS_SPREAD_POINTS                                                      \
    (CHARACTER_ATTRIBUTE_TOTAL - CHARACTER_ATTRIBUTE_COUNT * CHARACTER_ATTRIBUTE_MIN)
#define CS_SPREAD_CAP (CHARACTER_ATTRIBUTE_MAX - CHARACTER_ATTRIBUTE_MIN)

_Static_assert(CHARACTER_ATTRIBUTE_COUNT * CS_SPREAD_CAP >= CS_SPREAD_POINTS,
               "the per-attribute ceiling must leave room to hand out every "
               "spread point, or the fixed total is unreachable");

/* The cross-multiplication above is bounded by CS_W_MAX * (CS_SPREAD_CAP + 1).
 * Pinned so that widening a multiplier or the attribute window cannot silently
 * put the comparison near a 32-bit edge. */
_Static_assert((uint64_t)CS_W_MAX * (CS_SPREAD_CAP + 1u) < 0x40000000ull,
               "the apportionment comparison must stay far inside uint32_t");

bool character_apportion(const uint32_t weight[CHARACTER_ATTRIBUTE_COUNT],
                         uint8_t out[CHARACTER_ATTRIBUTE_COUNT])
{
    uint32_t bonus[CHARACTER_ATTRIBUTE_COUNT] = { 0 };

    if (!out)
        return false;
    memset(out, 0, CHARACTER_ATTRIBUTE_COUNT);
    if (!weight)
        return false;

    for (unsigned given = 0; given < CS_SPREAD_POINTS; given++) {
        unsigned best = CHARACTER_ATTRIBUTE_COUNT;

        for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
            if (bonus[i] >= CS_SPREAD_CAP)
                continue;
            if (best == CHARACTER_ATTRIBUTE_COUNT) {
                best = i;
                continue;
            }
            /* strictly greater, so equal claims leave `best` where it is and
             * the lower index keeps the point. */
            if (weight[i] * (bonus[best] + 1u) >
                weight[best] * (bonus[i] + 1u))
                best = i;
        }
        /* The static assertion above makes this unreachable; leaving the
         * guard costs one comparison and turns a future constant change from
         * an out-of-bounds write into a short total a test can see. */
        if (best == CHARACTER_ATTRIBUTE_COUNT)
            break;
        bonus[best]++;
    }

    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
        out[i] = (uint8_t)(CHARACTER_ATTRIBUTE_MIN + bonus[i]);
    return true;
}

/* ── SRD 5.1 ability modifier ────────────────────────────────────────────
 *
 * floor((score - 10) / 2). C's `/` truncates TOWARD ZERO, so (7 - 10) / 2 is
 * -1 where the SRD's table says -2. The subtraction and the floor are written
 * out rather than divided, because getting this wrong produces a number that
 * looks entirely reasonable and is off by one for exactly the odd scores
 * below 10. */
int character_ability_modifier(uint8_t score)
{
    int delta = (int)score - 10;

    if (delta >= 0)
        return delta / 2;
    return -(((-delta) + 1) / 2);
}

/* ── Names ───────────────────────────────────────────────────────────────
 * A wire form: changing one of these strings is a compatibility break, not a
 * rename. Exhaustive switches with no default, so an attribute added to the
 * enum without a name here is a -Wswitch error rather than a silent
 * "unknown". */
const char *character_attribute_name(enum character_attribute a)
{
    switch (a) {
    case CHARACTER_ATTR_STRENGTH:     return "strength";
    case CHARACTER_ATTR_DEXTERITY:    return "dexterity";
    case CHARACTER_ATTR_CONSTITUTION: return "constitution";
    case CHARACTER_ATTR_INTELLIGENCE: return "intelligence";
    case CHARACTER_ATTR_WISDOM:       return "wisdom";
    case CHARACTER_ATTR_CHARISMA:     return "charisma";
    case CHARACTER_ATTRIBUTE_COUNT:
        break;
    }
    return "unknown";
}

const char *character_attribute_abbrev(enum character_attribute a)
{
    switch (a) {
    case CHARACTER_ATTR_STRENGTH:     return "str";
    case CHARACTER_ATTR_DEXTERITY:    return "dex";
    case CHARACTER_ATTR_CONSTITUTION: return "con";
    case CHARACTER_ATTR_INTELLIGENCE: return "int";
    case CHARACTER_ATTR_WISDOM:       return "wis";
    case CHARACTER_ATTR_CHARISMA:     return "cha";
    case CHARACTER_ATTRIBUTE_COUNT:
        break;
    }
    return "???";
}

/* ── Seed validation ─────────────────────────────────────────────────────
 *
 * The name charset is narrow ON PURPOSE. The text form uses '|' as its
 * separator and carries no escape syntax, so a name that could not be written
 * unambiguously must be refused at construction rather than mangled on
 * output — a round trip that silently changes a character's name changes its
 * root, which changes which property it is. */
static bool cs_name_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '\'';
}

static bool cs_name_ok(const char *name, size_t *len_out)
{
    size_t n = 0;

    if (!name || !name[0])
        return false;
    while (name[n]) {
        if (n + 1u >= CHARACTER_NAME_MAX)
            return false; /* no room for the NUL: too long */
        if (!cs_name_char_ok(name[n]))
            return false;
        n++;
    }
    /* Leading or trailing space would make two visibly different names look
     * identical in every rendering while hashing differently. */
    if (name[0] == ' ' || name[n - 1u] == ' ')
        return false;
    if (len_out)
        *len_out = n;
    return true;
}

static bool cs_place_ok(const struct astro_place *p)
{
    if (!p)
        return false;
    if (p->latitude_microdeg > ASTRO_LATITUDE_MICRODEG_LIMIT ||
        p->latitude_microdeg < -ASTRO_LATITUDE_MICRODEG_LIMIT)
        return false;
    if (p->longitude_microdeg > ASTRO_LONGITUDE_MICRODEG_LIMIT ||
        p->longitude_microdeg < -ASTRO_LONGITUDE_MICRODEG_LIMIT)
        return false;
    return true;
}

bool character_seed_valid(const struct character_seed *seed)
{
    if (!seed)
        return false;
    /* The name buffer must be NUL-terminated before anything reads it as a
     * string: a caller who filled the struct by hand may not have. */
    if (memchr(seed->name, '\0', sizeof seed->name) == NULL)
        return false;
    return cs_name_ok(seed->name, NULL) && astro_instant_is_valid(&seed->born) &&
           cs_place_ok(&seed->where);
}

bool character_seed_make(const char *name, const struct astro_instant *born,
                         const struct astro_place *where,
                         struct character_seed *out)
{
    size_t len = 0;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!name || !born || !where)
        return false;
    if (!cs_name_ok(name, &len))
        return false;
    if (!astro_instant_is_valid(born) || !cs_place_ok(where))
        return false;

    /* FIELD BY FIELD, not `out->born = *born`. A struct assignment is allowed
     * to leave the destination's PADDING holding whatever the source had, and
     * struct astro_instant has three padding bytes after `second`. The source
     * is usually a local the compiler filled field by field, and at -O2 both
     * gcc and clang legitimately delete a memset of such a local because
     * nothing ever reads its padding — so the padding arriving here is
     * genuinely indeterminate. Copying only the named fields keeps the zeros
     * this function's own memset just wrote, which is what makes a seed built
     * here reproducible byte for byte instead of reproducible-looking.
     *
     * The root never depended on this (it hashes a canonical encoding, not
     * the struct), and character_seed_equal() compares fields rather than
     * bytes for the same reason. This is belt and braces on a value type that
     * gets copied, shipped and compared. */
    memcpy(out->name, name, len); /* the rest stays zero from the memset */
    out->born.year = born->year;
    out->born.month = born->month;
    out->born.day = born->day;
    out->born.hour = born->hour;
    out->born.minute = born->minute;
    out->born.second = born->second;
    out->where.latitude_microdeg = where->latitude_microdeg;
    out->where.longitude_microdeg = where->longitude_microdeg;
    return true;
}

/* Compare seeds BY VALUE, never by bytes. See the note in
 * character_seed_make() for why memcmp on a struct that has padding is not a
 * sound identity test — and note that this function and the root agree by
 * construction: both read exactly the fields the canonical encoding carries,
 * so two seeds are equal here if and only if they name the same property. */
bool character_seed_equal(const struct character_seed *a,
                          const struct character_seed *b)
{
    if (!a || !b)
        return false;
    if (memchr(a->name, '\0', sizeof a->name) == NULL ||
        memchr(b->name, '\0', sizeof b->name) == NULL)
        return false;
    return strcmp(a->name, b->name) == 0 && a->born.year == b->born.year &&
           a->born.month == b->born.month && a->born.day == b->born.day &&
           a->born.hour == b->born.hour && a->born.minute == b->born.minute &&
           a->born.second == b->born.second &&
           a->where.latitude_microdeg == b->where.latitude_microdeg &&
           a->where.longitude_microdeg == b->where.longitude_microdeg;
}

/* ── The root ────────────────────────────────────────────────────────────
 *
 * A CANONICAL encoding, not the struct. Hashing `struct character_seed`
 * directly would hash its padding and the buffer tail after the name's NUL,
 * so a character's identity would depend on whatever was on the stack — two
 * nodes holding the same character would compute different roots, and the
 * same node would compute different roots on two runs. The encoding below is
 * explicit, length-prefixed and big-endian, and every byte in it is a fact
 * about the character.
 *
 * The rules revision is inside the preimage. That makes a revision bump
 * produce a DIFFERENT PROPERTY rather than the same property with silently
 * different attributes, which is the honest outcome: under new rules it is
 * not the same character. */
#define CS_ROOT_TAG "z23-character-sheet"
#define CS_ROOT_TAG_LEN (sizeof CS_ROOT_TAG - 1u)

/* tag + rev(4) + name_len(2) + name + year(4) + 5 date bytes + lat(4) + lon(4) */
#define CS_PREIMAGE_MAX (CS_ROOT_TAG_LEN + 4u + 2u + CHARACTER_NAME_MAX + 17u)

/* Big-endian through the tree's ONE byte-order codec (base/serialize_le.h),
 * never a private shift ladder. This file used to carry its own four-line
 * pack; check-byte-order-codec-single refused it, and rightly — twelve
 * divergent private hex codecs are what base/hex.h exists to remember, and a
 * preimage is exactly the place where one byte in the wrong order silently
 * changes every character's identity. */
static size_t cs_put_be32(uint8_t *p, uint32_t v)
{
    zcl_write_u32_be(p, v);
    return 4u;
}

bool character_seed_root(const struct character_seed *seed,
                         uint8_t out[METAVERSE_ROOT_BYTES])
{
    uint8_t buf[CS_PREIMAGE_MAX];
    size_t n = 0;
    size_t name_len = 0;

    if (!out)
        return false;
    memset(out, 0, METAVERSE_ROOT_BYTES);
    if (!character_seed_valid(seed))
        return false;
    name_len = strlen(seed->name);

    memcpy(buf + n, CS_ROOT_TAG, CS_ROOT_TAG_LEN);
    n += CS_ROOT_TAG_LEN;
    n += cs_put_be32(buf + n, CHARACTER_SHEET_RULES_REV);
    buf[n++] = (uint8_t)(name_len >> 8);
    buf[n++] = (uint8_t)name_len;
    memcpy(buf + n, seed->name, name_len);
    n += name_len;
    /* The year is signed and can be negative (proleptic Gregorian). Cast
     * through uint32_t so the encoding is two's complement by definition
     * rather than by whatever the platform does with a signed shift. */
    n += cs_put_be32(buf + n, (uint32_t)seed->born.year);
    buf[n++] = seed->born.month;
    buf[n++] = seed->born.day;
    buf[n++] = seed->born.hour;
    buf[n++] = seed->born.minute;
    buf[n++] = seed->born.second;
    n += cs_put_be32(buf + n, (uint32_t)seed->where.latitude_microdeg);
    n += cs_put_be32(buf + n, (uint32_t)seed->where.longitude_microdeg);

    sha3_256(buf, n, out);
    return true;
}

bool character_seed_property_id(const struct character_seed *seed,
                                struct metaverse_property_id *out)
{
    uint8_t root[METAVERSE_ROOT_BYTES];

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!character_seed_root(seed, root))
        return false;
    /* Refuses an all-zero root, which no hash will produce but which would
     * otherwise be indistinguishable from an uninitialised id. */
    return metaverse_property_id_make(METAVERSE_KIND_CHARACTER_SHEET, root,
                                      out);
}

/* ── Derivation ──────────────────────────────────────────────────────────── */

bool character_sheet_derive(const struct character_seed *seed,
                            struct character_sheet *out)
{
    struct astro_chart chart;
    uint32_t weight[CHARACTER_ATTRIBUTE_COUNT];
    unsigned integration;

    if (!out)
        return false;
    /* Zero the WHOLE struct, padding included, before anything is written.
     * Two nodes memcmp'ing a sheet compare padding too, and a refusal must
     * leave nothing a caller could mistake for a character. */
    memset(out, 0, sizeof *out);
    if (!character_seed_valid(seed))
        return false;
    if (!character_seed_property_id(seed, &out->id)) {
        memset(out, 0, sizeof *out);
        return false;
    }
    if (!astro_chart_compute(&seed->born, &seed->where, &chart)) {
        /* lib/astro never returns a partially valid chart, and neither does
         * this: a poisoned intermediate becomes a refusal, not a plausible
         * character. */
        memset(out, 0, sizeof *out);
        return false;
    }

    out->rules_rev = CHARACTER_SHEET_RULES_REV;
    out->ascendant_sign = chart.ascendant.sign;
    out->ascendant_degree = (uint8_t)chart.ascendant.degree_in_sign;
    out->sun_sign = chart.body[ASTRO_BODY_SUN].sign;
    out->sun_dignity = (uint8_t)character_dignity(
        ASTRO_BODY_SUN, chart.body[ASTRO_BODY_SUN].sign);
    integration = CS_W_INTEGRATION * out->sun_dignity;

    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++) {
        enum astro_body body = k_significator[i];
        const struct astro_position *p = &chart.body[body];
        unsigned house = cs_house_of(p, &chart.ascendant);
        unsigned dignity = character_dignity(body, p->sign);
        unsigned arcmin =
            (unsigned)p->degree_in_sign * 60u + (unsigned)p->arcminute;

        out->influence[i].body = body;
        out->influence[i].sign = p->sign;
        out->influence[i].degree_in_sign = (uint8_t)p->degree_in_sign;
        out->influence[i].arcminute = (uint8_t)p->arcminute;
        out->influence[i].house = (uint8_t)house;
        out->influence[i].dignity = (uint8_t)dignity;

        weight[i] = CS_W_FLOOR + CS_W_ESSENTIAL * dignity +
                    CS_W_ACCIDENTAL * cs_house_rank(house) +
                    (arcmin >> CS_W_ARC_SHIFT) + integration;
    }

    (void)character_apportion(weight, out->attribute);
    for (unsigned i = 0; i < CHARACTER_ATTRIBUTE_COUNT; i++)
        out->modifier[i] = (int8_t)character_ability_modifier(out->attribute[i]);
    return true;
}
