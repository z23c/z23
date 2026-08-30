/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * character_sheet — a role-playing character held as sovereign digital
 * property, whose six attributes are DERIVED from an astrological chart cast
 * for a fictional birth moment and place.
 *
 * The end this file is designed for: an owner sends this character to a node
 * that does not trust him. That node must be able to check the character
 * without asking anyone — including the owner — whether it is real. Every
 * decision below follows from that one requirement.
 *
 * ── SRD 5.1 ATTRIBUTION (Creative Commons Attribution 4.0) ───────────────
 * This work includes material taken from the System Reference Document 5.1
 * ("SRD 5.1") by Wizards of the Coast LLC and available at
 * https://dnd.wizards.com/resources/systems-reference-document. The SRD 5.1
 * is licensed under the Creative Commons Attribution 4.0 International
 * License available at https://creativecommons.org/licenses/by/4.0/legalcode.
 *
 * What is taken, exactly and exhaustively: the six ability names (Strength,
 * Dexterity, Constitution, Intelligence, Wisdom, Charisma), the ability
 * modifier rule floor((score - 10) / 2), and the standard array's point total
 * of 72 (15+14+13+12+10+8) used here as this module's fixed total. Nothing
 * else. No Product Identity: no class, monster, spell, deity, setting or
 * proper name from any non-SRD source appears anywhere in this module, and
 * the same restraint binds every file that extends it. The attribution is
 * also recorded in NOTICE and docs/ATTRIBUTIONS.md.
 *
 * ── 1. A CHARACTER IS A PROPERTY, AND ITS ROOT IS ITS OWN HASH ───────────
 * The kind is METAVERSE_KIND_CHARACTER_SHEET, settlement class
 * CONTENT_ADDRESSED (metaverse/property_id.h): the id IS the hash of the
 * character's birth data plus the rules revision that reads it. Verification
 * is "recompute and compare" — no registry, no chain, no peer, and no
 * question the owner gets to answer.
 *
 * Following property_id.h's rule, this layer MINTS NO IDENTIFIER OF ITS OWN.
 * There is no serial number, no UUID, no owner-chosen handle that a second
 * node would have to be told about. The seed is the whole name.
 *
 * ── 2. ATTRIBUTES ARE DERIVED, NEVER STORED AS TRUTH ─────────────────────
 * struct character_seed is what is held, transmitted and hashed. struct
 * character_sheet is what character_sheet_derive() COMPUTES from it, every
 * time, on every node. Nothing persists a sheet as authoritative, because a
 * stored attribute block is a second truth: the day it disagrees with the
 * derivation there is no way to tell which one is the character.
 *
 * ── 3. THE TOTAL IS FIXED; THE CHART DECIDES ONLY THE DISTRIBUTION ───────
 * This is the load-bearing decision, and it exists because the birth moment
 * is FICTIONAL AND OWNER-CHOSEN. If attributes were a power ladder, an owner
 * would search birthdays until he found the strongest one, everybody would
 * arrive at the same few birthdays, and astrology would have been converted
 * into a proof-of-search contest with a published answer.
 *
 * So CHARACTER_ATTRIBUTE_TOTAL is identical for every character that will
 * ever exist. The chart decides only how those points are SPREAD across the
 * six abilities. Grinding a birth moment therefore changes WHAT KIND of
 * character you get and never HOW STRONG it is — which is the same reasoning
 * that keeps node_character.h's form cosmetic, and the same reason nothing is
 * won by grinding it either.
 *
 * The invariant is not documentation. It is a property of the apportionment
 * in character_sheet.c: the six attributes start at CHARACTER_ATTRIBUTE_MIN
 * and exactly (TOTAL - COUNT*MIN) further points are handed out one at a
 * time, so the sum cannot be anything but TOTAL, for any chart, valid or
 * absurd.
 *
 * ── 4. PROGRESSION IS DELIBERATELY ABSENT, AND THE RULE FOR ADDING IT ────
 * There is no level, no experience, no deed counter and no field a character
 * can grow. That is not an oversight — it is this version staying small.
 *
 * The rule that binds the lane which adds it: anything that makes a character
 * stronger over time must rest on evidence held somewhere OTHER than the node
 * making the claim, exactly as struct node_work counts observed work and
 * deliberately has no field for claimed hardware. A progression struct holds
 * COMPLETED, WITNESSED deeds — a countersigned receipt, a peer's observation,
 * a proof someone else can check. It must not hold a number this character's
 * own node can simply assert, because a self-asserted number is worth
 * whatever its author wants it to be worth, which is nothing.
 *
 * ── 5. NEVER AUTHORITATIVE ───────────────────────────────────────────────
 * Consensus must not read anything here. Nothing here decides what a node or
 * a visiting character may DO — metaverse_grant_check() owns that and remains
 * the only answer. A sheet renders facts; it never becomes one. A change that
 * let a high attribute widen what its owner may do would convert a cosmetic
 * layer into an authority, and would put the grinding incentive back.
 *
 * ── 6. INTEGERS ONLY, AND THE CHART IS EXACT ─────────────────────────────
 * Every number here is an integer, and every chart quantity it reads is a
 * struct astro_exact readout (astro/astro_exact.h). Floating point is allowed
 * to differ in its last bits between compilers, optimisation levels and
 * machines, and two nodes disagreeing about a third party's character is
 * indistinguishable from one of them lying. Every .c file of this module
 * carries `#pragma GCC poison double float` after its includes, so naming a
 * floating-point type on this path is a compile error rather than a review
 * comment nobody made.
 *
 * This module reads the chart's INTEGER readouts (sign, degree, arcminute,
 * arcsecond) rather than doing astro_exact arithmetic of its own. Those
 * readouts are computed once, inside lib/astro, and stored in the chart, so
 * two nodes compare the same derived integers instead of each deriving them
 * their own way — the reason astro_position carries them at all.
 *
 * ── Threading ────────────────────────────────────────────────────────────
 * This module holds no state: no statics, no allocation, no I/O, no locks.
 * lib/astro builds its trigonometric tables on first use, though, so a
 * process deriving sheets from several threads calls astro_prepare() once
 * before any of them start. Everything else may ignore it.
 */

#ifndef ZCL_METAVERSE_CHARACTER_SHEET_H
#define ZCL_METAVERSE_CHARACTER_SHEET_H

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "metaverse/property_id.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bump when ANY derivation rule below changes. It is stamped into every sheet
 * AND hashed into the root, so a character derived under revision 1 and one
 * derived under revision 2 are different properties with different ids rather
 * than one property whose attributes silently moved. Same discipline as
 * NODE_CHARACTER_FORM_REV, one consequence stronger: form there is cosmetic,
 * so a revision only has to be TELLABLE; here the rules decide the identity,
 * so a revision must be SEPARABLE. */
#define CHARACTER_SHEET_RULES_REV 1u

/* The six SRD 5.1 abilities. The order is the SRD's own and is a wire order:
 * it indexes struct character_sheet's arrays and is hashed into nothing, but
 * a viewer on another node reads column 0 as Strength. */
enum character_attribute {
    CHARACTER_ATTR_STRENGTH = 0,
    CHARACTER_ATTR_DEXTERITY,
    CHARACTER_ATTR_CONSTITUTION,
    CHARACTER_ATTR_INTELLIGENCE,
    CHARACTER_ATTR_WISDOM,
    CHARACTER_ATTR_CHARISMA,
    CHARACTER_ATTRIBUTE_COUNT
};

/* The fixed total (SRD 5.1 standard array: 15+14+13+12+10+8), and the window
 * every individual attribute stays inside.
 *
 * These four constants are not independent, and the static assertions below
 * are what keep a future edit from quietly breaking the invariant that makes
 * this design work:
 *
 *   - COUNT*MIN <= TOTAL, or the floor alone already overshoots and no
 *     distribution can hit the total;
 *   - TOTAL <= COUNT*MAX, or the total cannot be reached even with every
 *     attribute at its ceiling.
 *
 * Between them sit exactly (TOTAL - COUNT*MIN) = 36 points of spread, which
 * is what the chart gets to decide. MIN and MAX sit inside the SRD's 3..18
 * creation range; the narrower floor exists so that no chart, however
 * lopsided, produces a character who is merely broken. */
#define CHARACTER_ATTRIBUTE_TOTAL 72u
#define CHARACTER_ATTRIBUTE_MIN   6u
#define CHARACTER_ATTRIBUTE_MAX   18u

_Static_assert(CHARACTER_ATTRIBUTE_COUNT * CHARACTER_ATTRIBUTE_MIN <=
                   CHARACTER_ATTRIBUTE_TOTAL,
               "the attribute floor alone must not exceed the fixed total");
_Static_assert(CHARACTER_ATTRIBUTE_TOTAL <=
                   CHARACTER_ATTRIBUTE_COUNT * CHARACTER_ATTRIBUTE_MAX,
               "the fixed total must be reachable within the attribute cap");
_Static_assert(CHARACTER_ATTRIBUTE_MIN < CHARACTER_ATTRIBUTE_MAX,
               "the attribute window must have room for a distribution");

/* Name bounds. The charset is deliberately narrow (see character_seed_make)
 * so that the text form needs no escape syntax at all: a name that cannot be
 * written unambiguously is refused at construction rather than mangled at
 * output. */
#define CHARACTER_NAME_MAX 48u /* including the NUL */

/* "<name>|<-YYYY-MM-DDThh:mm:ssZ>|<lat>|<lon>" — 47 + 1 + 21 + 1 + 9 + 1 + 10
 * + NUL = 91. 128 leaves room without a wire change. */
#define CHARACTER_SEED_TEXT_MAX 128u

/* Essential dignity: how well a body sits in the sign it occupies. The whole
 * traditional scale this module uses, worst to best. Values are a wire form —
 * a sheet carries them so a viewer can see WHY an attribute landed where it
 * did — so renumbering one is a compatibility break, not a rename. */
#define CHARACTER_DIGNITY_FALL       0u /* opposite its exaltation */
#define CHARACTER_DIGNITY_DETRIMENT  1u /* opposite a sign it rules */
#define CHARACTER_DIGNITY_PEREGRINE  2u /* no relationship either way */
#define CHARACTER_DIGNITY_EXALTATION 4u
#define CHARACTER_DIGNITY_RULERSHIP  5u
#define CHARACTER_DIGNITY_MAX        5u

/* ── The seed: everything a character IS ─────────────────────────────────
 *
 * A zeroed struct is INVALID, matching this tree's discipline everywhere
 * else, and it costs nothing to get: month 0 is not a month, so a forgotten
 * initialisation cannot read as a real birth. */
struct character_seed {
    /* NUL-terminated. The bytes after the NUL are NOT part of the character:
     * the root is computed over the canonical encoding in character_sheet.c,
     * which carries the name's LENGTH and then exactly that many bytes. Two
     * seeds differing only in buffer tail garbage are the same property, and
     * a test asserts it — hashing the struct itself would have made a
     * character's identity depend on uninitialised stack. */
    char name[CHARACTER_NAME_MAX];
    struct astro_instant born;  /* fictional; proleptic Gregorian, uniform */
    struct astro_place where;   /* fictional; exact integer microdegrees */
};

/* What one attribute's derivation looked at, kept so a viewer can see the
 * reasoning instead of being handed six numbers to believe. Every field is a
 * readout of the chart, not a second computation of it. */
struct character_influence {
    enum astro_body body;   /* this attribute's significator */
    enum astro_sign sign;   /* the sign it occupied */
    uint8_t degree_in_sign; /* 0..29 */
    uint8_t arcminute;      /* 0..59 */
    uint8_t house;          /* 1..12, equal houses from the ascendant */
    uint8_t dignity;        /* CHARACTER_DIGNITY_*, 0..5 */
};

/* The derived sheet. Recomputed, never stored as truth (decision 2). */
struct character_sheet {
    /* kind CHARACTER_SHEET; root = hash(canonical seed || rules revision). */
    struct metaverse_property_id id;

    /* The revision that produced this. Stamped into every result so a sheet
     * in hand can be told apart from one this build would compute. */
    uint32_t rules_rev;

    /* Each in [CHARACTER_ATTRIBUTE_MIN, CHARACTER_ATTRIBUTE_MAX]; the six
     * always sum to exactly CHARACTER_ATTRIBUTE_TOTAL. */
    uint8_t attribute[CHARACTER_ATTRIBUTE_COUNT];

    /* SRD 5.1 floor((score - 10) / 2). Stored rather than left to the caller
     * because C's `/` truncates toward zero and would give -1 where the SRD
     * says -2 for a score of 7 — a rounding difference two viewers could
     * disagree about. */
    int8_t modifier[CHARACTER_ATTRIBUTE_COUNT];

    struct character_influence influence[CHARACTER_ATTRIBUTE_COUNT];

    /* The rising degree. It is what makes the birth PLACE and the time of day
     * matter: every house in the chart, and therefore every attribute's
     * accidental dignity, is measured from here. */
    enum astro_sign ascendant_sign;
    uint8_t ascendant_degree; /* 0..29 */

    /* The Sun's placement drives the SPREAD rather than any one attribute:
     * see character_sheet.c. A dignified Sun evens the distribution, a
     * debilitated one sharpens it. */
    enum astro_sign sun_sign;
    uint8_t sun_dignity; /* CHARACTER_DIGNITY_*, 0..5 */
};

/* ── Seed construction and validation ──────────────────────────────────── */

/* Build a seed. Refuses, zeroing *out, when:
 *   - out, name, born or where is NULL;
 *   - the name is empty, does not fit CHARACTER_NAME_MAX, starts or ends with
 *     a space, or contains a byte outside [A-Za-z0-9], space, '-' or '\'';
 *   - astro_instant_is_valid() rejects the moment (a month, day, hour, minute
 *     or second out of range, a day that does not exist in that month, or a
 *     year outside ASTRO_YEAR_MIN..ASTRO_YEAR_MAX);
 *   - |latitude| exceeds ASTRO_LATITUDE_MICRODEG_LIMIT or |longitude| exceeds
 *     ASTRO_LONGITUDE_MICRODEG_LIMIT.
 *
 * The latitude limit is lib/astro's and is a refusal rather than an
 * approximation: the ascendant depends on tan(latitude), which is unbounded
 * at the pole, and no house system has an agreed answer there. */
bool character_seed_make(const char *name, const struct astro_instant *born,
                         const struct astro_place *where,
                         struct character_seed *out);

/* True for a seed character_seed_make() would have produced. Total: safe on
 * any bytes, including a struct that never went through make(). */
bool character_seed_valid(const struct character_seed *seed);

/* Compare two seeds BY VALUE. Use this, never memcmp.
 *
 * struct astro_instant has three padding bytes after `second`, and C does not
 * define what a struct assignment puts in a destination's padding. In
 * practice a caller builds an instant on the stack and the compiler DELETES
 * the memset that zeroed it, because nothing in that function ever reads the
 * padding — legal, and both gcc and clang do it at -O2. Two seeds naming the
 * same character can therefore differ in bytes nobody wrote, and a memcmp
 * would report them as different characters.
 *
 * This compares exactly the fields the canonical encoding hashes, so it and
 * character_seed_root() agree by construction: equal here means the same
 * property, and different here means a different root. */
bool character_seed_equal(const struct character_seed *a,
                          const struct character_seed *b);

/* ── Identity ───────────────────────────────────────────────────────────── */

/* The character's root: SHA3-256 over a canonical, length-prefixed encoding
 * of (domain tag, rules revision, name, birth moment, birth place). No struct
 * padding and no buffer tail is hashed. Refuses an invalid seed or a NULL
 * argument, zeroing *out. */
bool character_seed_root(const struct character_seed *seed,
                         uint8_t out[METAVERSE_ROOT_BYTES]);

/* The same root wrapped as the property it names. Refuses exactly when
 * character_seed_root() does, plus the astronomically unreachable case of a
 * root of 32 zero bytes, which metaverse_property_id_make() rejects so that
 * "uninitialised" can never read as "a real object". */
bool character_seed_property_id(const struct character_seed *seed,
                                struct metaverse_property_id *out);

/* ── Derivation ─────────────────────────────────────────────────────────── */

/* Compute the sheet. *out is fully zeroed first, so the struct — padding
 * included — is byte-identical for a given seed on every platform, and a
 * refusal leaves nothing usable behind.
 *
 * Returns false for a NULL argument, an invalid seed, a chart lib/astro
 * refuses to compute, or a root that will not make an id. It never returns a
 * partially filled sheet. */
bool character_sheet_derive(const struct character_seed *seed,
                            struct character_sheet *out);

/* The apportionment on its own: six non-negative weights in, six attributes
 * out. This is where the fixed total comes from, and it is public for one
 * reason — the invariant that the whole design rests on is a property of THIS
 * FUNCTION and of nothing else, so it should be checkable without computing a
 * chart first.
 *
 * The chart's only influence on the total is through the weights it produces,
 * so driving this over the whole weight space — including vectors no chart
 * could ever produce — proves the total is fixed more completely than
 * sampling birthdays ever could. Recomputing a chart costs milliseconds;
 * recomputing this costs nothing, which is the difference between checking
 * thousands of cases and checking millions.
 *
 * It is NOT a second way to build a character: it returns six numbers and no
 * identity, so nothing downstream can accept its output as a sheet.
 *
 * Guarantees for ANY weights, including all-zero and all-equal: the six
 * outputs sum to exactly CHARACTER_ATTRIBUTE_TOTAL and each lies in
 * [CHARACTER_ATTRIBUTE_MIN, CHARACTER_ATTRIBUTE_MAX]. Returns false only for
 * a NULL argument, zeroing *out. */
bool character_apportion(const uint32_t weight[CHARACTER_ATTRIBUTE_COUNT],
                         uint8_t out[CHARACTER_ATTRIBUTE_COUNT]);

/* ── Readouts ───────────────────────────────────────────────────────────── */

/* SRD 5.1: floor((score - 10) / 2), floored rather than truncated, for any
 * uint8_t score. */
int character_ability_modifier(uint8_t score);

/* Stable lowercase token ("strength", ...) and three-letter abbreviation
 * ("str", ...). Never NULL: an out-of-range value returns "unknown" / "???"
 * rather than indexing past the table. Both are a wire form. */
const char *character_attribute_name(enum character_attribute a);
const char *character_attribute_abbrev(enum character_attribute a);

/* The body that signifies an attribute. Returns ASTRO_BODY_COUNT for an
 * out-of-range attribute — a value astro_body_name() renders as "unknown"
 * rather than a plausible wrong planet. */
enum astro_body character_attribute_significator(enum character_attribute a);

/* Essential dignity of `body` in `sign`, CHARACTER_DIGNITY_*. Returns
 * CHARACTER_DIGNITY_PEREGRINE — "no relationship either way", the honest
 * answer — for a body this module holds no rulership table for, and for an
 * out-of-range argument. */
unsigned character_dignity(enum astro_body body, enum astro_sign sign);

/* ── Text form ──────────────────────────────────────────────────────────── */

/* Render the seed as "<name>|<YYYY-MM-DDThh:mm:ssZ>|<lat>|<lon>", where the
 * year is exactly four digits optionally preceded by '-', the other date
 * fields are zero-padded to two, and the two coordinates are signed decimal
 * microdegrees with no '+' and no leading zeros. One value has exactly one
 * spelling, so the form round-trips byte for byte — the same discipline
 * metaverse_property_id_format() keeps by emitting lowercase hex only.
 *
 * False (and out[0] = 0 when cap > 0) on a NULL out, a short buffer, or an
 * invalid seed. `cap` should be at least CHARACTER_SEED_TEXT_MAX. */
bool character_seed_format(const struct character_seed *seed, char *out,
                           size_t cap);

/* Parse the text form. Strict: exactly three '|' separators, the exact date
 * layout above, no leading '+', no leading zeros on a coordinate, no trailing
 * bytes, and the result must satisfy character_seed_make(). *out is zeroed on
 * every rejection. */
bool character_seed_parse(const char *text, struct character_seed *out);

#endif /* ZCL_METAVERSE_CHARACTER_SHEET_H */
