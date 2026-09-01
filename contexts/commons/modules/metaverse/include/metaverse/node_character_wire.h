/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character_wire — a node's character with a BIRTHDAY and a birth chart,
 * in the fixed 132-byte form it travels in, and the rule a receiving node
 * applies to it.
 *
 * metaverse/node_character.h derives what a node LOOKS LIKE and how strong it
 * is. It has no way to show that to anybody. This file is the other half: one
 * node hands a stranger 132 bytes, and the stranger decides — alone, with no
 * registry, no chain and no question the sender gets to answer — how much of
 * it to believe.
 *
 * ── A RECEIVED SHEET IS A CLAIM, NOT A FACT ──────────────────────────────
 *
 * That sentence is the whole design. The 132 bytes arrived from somebody with
 * an interest in how they read, so every field is treated as an assertion
 * until this node has recomputed it or corroborated it. The three answers are
 * different and are kept apart deliberately:
 *
 *   RECOMPUTED   form and chart. Both are pure functions of the identity root
 *                and the birthday, so the receiver derives them itself and
 *                REFUSES the whole sheet on any disagreement. Nothing here is
 *                taken on trust; a mismatch is a defect or a lie and either
 *                way the sheet does not arrive.
 *
 *   ASSERTED     the birthday. A node's genesis moment is not observable by a
 *                stranger, so there is nothing to check it against. It is
 *                accepted as the sender's word — see the note below on why
 *                that costs nothing.
 *
 *   UNVERIFIED   standing. Energy and archetype come from work OTHERS
 *                OBSERVED, and a stranger cannot see those counters. The
 *                claim is carried, is checked for INTERNAL consistency, and
 *                is never promoted to a fact. See the boundary below.
 *
 * ── THE STANDING BOUNDARY, DRAWN EXPLICITLY ──────────────────────────────
 *
 * A node must not be able to talk itself into a high energy. There are two
 * separate mechanisms here and each closes a different door.
 *
 * 1. INTERNAL CONSISTENCY IS ENFORCED. The sheet carries the raw work
 *    counters AND the archetype and energy derived from them, and
 *    node_character_sheet_verify() refuses the sheet unless the second is
 *    exactly what node_character_derive() computes from the first. So the
 *    only way to ship a large energy is to ship the large counters that
 *    justify it. A frame carrying "energy: 1024" over four zeroed counters is
 *    well-formed and is refused on the spot by the verifier, which is where
 *    that judgement belongs — the structural decoder's job is the layout, not
 *    the arithmetic.
 *    This does not make the claim true; it makes the claim SPECIFIC, which is
 *    what a corroborator needs in order to check it against its own records.
 *
 * 2. THE CLAIMED STANDING IS NEVER WHAT THE RECEIVER BELIEVES. The believed
 *    standing in a receipt is derived from the counters THIS node observed and
 *    from nothing on the wire. A stranger with no observations of the sender
 *    therefore believes NODE_ARCHETYPE_WANDERER and energy 0, no matter what
 *    the sheet says, and renders the claim beside it marked "unverified". A
 *    sender cannot raise the number the receiver believes by editing its own
 *    sheet, because the receiver never reads that number as an input.
 *
 * There are exactly TWO trust states, and the absence of a third is
 * deliberate. `CORROBORATED` means this node's own observations already
 * account for at least the claimed counters, field by field; `UNVERIFIED`
 * means they do not. There is no CONTRADICTED, because observing less work
 * than a node claims is not evidence that the node is lying — every node sees
 * only the part of the network it talks to, and a peer that served a terabyte
 * to somebody else served it whether or not we watched. Inventing a
 * "contradicted" verdict would be claiming a disproof this node cannot have,
 * which is the same error as claiming a proof it cannot have.
 *
 * ── WHAT THE SHEET DOES NOT PROVE ────────────────────────────────────────
 *
 * It does not prove WHO SENT IT. Anyone can take another node's identity root
 * and a birthday, compute the matching form and chart, and produce a sheet
 * that verifies perfectly — because verification proves CONSISTENCY, not
 * possession. Binding a sheet to the peer on the far end of a connection is a
 * signature over these bytes, or the authenticated identity the transport
 * already established, and it belongs to the layer that owns the socket. This
 * file produces and checks the bytes and claims nothing about their courier.
 * A caller that treats a verified sheet as an authenticated peer has read a
 * consistency check as an identity proof, and this paragraph exists so that
 * cannot happen by accident.
 *
 * The sharpest form of that, stated because a test drives it: only twelve of
 * the identity root's thirty-two bytes reach a derived field — four feed the
 * form (node_character.c reads root[0..1], root[7] and root[19]) and eight
 * feed the birthplace. Changing any of the other twenty produces a frame that
 * verifies perfectly and names a DIFFERENT identity. That is not a hole in the
 * checking; it is the same fact from the other side. Verification answers "are
 * these bytes self-consistent", and no amount of recomputation can turn that
 * into "did the holder of this identity send them".
 *
 * ── THE BIRTHDAY IS ASSERTED, AND GRINDING IT IS WORTHLESS ───────────────
 *
 * The node's genesis moment is supplied by the caller — this module never
 * reads a clock, for the reason astro/astro_time.h gives: a value that came
 * from a clock cannot be recomputed by anybody else. It is the one field a
 * node simply asserts.
 *
 * That is safe for the same reason character_sheet.h's fixed attribute total
 * is safe: the chart is COSMETIC and confers nothing. A node that searches
 * birthdays until it finds a chart it likes has changed what its character
 * LOOKS like and has not changed one thing it is allowed to do, so there is
 * nothing to win and no reason to grind. The day something here becomes worth
 * something, that reasoning fails and the birthday would need real evidence
 * behind it — a witnessed first block, a peer's first-seen record — exactly
 * as struct node_work counts observed work and has no field for claimed
 * hardware.
 *
 * ── THE BIRTHPLACE IS DERIVED, LIKE THE FORM ─────────────────────────────
 *
 * A chart needs a place as well as a moment, and a node has no location it
 * could honestly state (and every reason not to state one it could). So the
 * birthplace is DERIVED FROM THE IDENTITY ROOT, exactly as hue and silhouette
 * are: it is a fictional point on a fictional globe, unforgeable in the only
 * sense that matters, free for anybody to recompute, and worth nothing to
 * grind. It is emphatically NOT where the machine is, and nothing about the
 * operator's real geography reaches this file.
 *
 * That choice is what makes the receipt rule in this header possible at all:
 * with the place derived, the whole chart is a pure function of (identity
 * root, birthday), so a receiver holding those two can recompute it and refuse
 * a sheet that disagrees.
 *
 * ── BYTE-IDENTICAL ON EVERY PLATFORM ─────────────────────────────────────
 *
 * The property the design rests on: the same inputs produce the same 132 bytes
 * on Linux, macOS and Windows, at every optimisation level. Two nodes
 * disagreeing about a third node's appearance is indistinguishable from one of
 * them lying, so a divergence here would destroy the ability to refuse
 * anything.
 *
 * Three rules keep it. Every field is an integer — this file's .c carries
 * `#pragma GCC poison double float` after its includes, so naming a
 * floating-point type on this path is a compile error. Every multi-byte field
 * is written big-endian, byte by byte, so host byte order cannot reach the
 * wire. And the encoder never copies a struct: it writes named fields into a
 * flat buffer, so struct padding — which C leaves undefined and which both gcc
 * and clang really do leave uninitialised at -O2 — is not on the wire and
 * cannot be hashed, compared, or transmitted.
 *
 * ── NEVER AUTHORITATIVE ──────────────────────────────────────────────────
 *
 * Consensus must not read anything here, and nothing here decides what a node
 * is ALLOWED to do — metaverse_grant_check() owns that and stays the only
 * answer. A receipt renders what a stranger may believe; it never becomes a
 * permission. A change that let a visitor's energy widen what it may do would
 * convert a cosmetic layer into an authority, and would immediately make
 * grinding both the birthday and the counters worth something.
 *
 * ── Threading ────────────────────────────────────────────────────────────
 *
 * This module holds no state: no statics, no allocation, no I/O, no locks, no
 * clock. platform/modules/astro builds its trigonometric tables on first use, though, so a
 * process making or verifying sheets from several threads calls astro_prepare()
 * once before any of them start. Everything else may ignore it.
 */

#ifndef ZCL_METAVERSE_NODE_CHARACTER_WIRE_H
#define ZCL_METAVERSE_NODE_CHARACTER_WIRE_H

#include "astro/astro_chart.h"
#include "astro/astro_time.h"
#include "metaverse/node_character.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bump when the LAYOUT or any derivation rule reachable from it changes. It is
 * on the wire at a fixed offset, so a peer running an older or newer rule set
 * is told apart from a peer sending nonsense — the decoder refuses a version
 * it does not implement instead of reading familiar-looking bytes at the wrong
 * offsets. */
#define NODE_CHARACTER_WIRE_VERSION 1u

/* Fixed size. Not "at most": every sheet is exactly this long, so a reader
 * needs no length prefix and a short or long frame is refused rather than
 * padded or truncated into something that parses. */
#define NODE_CHARACTER_WIRE_BYTES 132u

/* One body's place on the ecliptic, as the four INTEGER readouts
 * astro_position already carries.
 *
 * The exact longitude (struct astro_exact, 800 bits) is deliberately NOT on
 * the wire. It is recomputable from the root and the birthday, so shipping it
 * would be shipping a derived value at ten times the size; and
 * astro_chart.h's own contract is that two nodes compare these stored
 * integers rather than each deriving them their own way, which is exactly
 * what a sender and a receiver are. */
struct node_star_position {
    uint8_t sign;           /* < ASTRO_SIGN_COUNT */
    uint8_t degree_in_sign; /* 0..29 */
    uint8_t arcminute;      /* 0..59 */
    uint8_t arcsecond;      /* 0..59 */
};

/* The chart a character carries: the rising degree and the nine bodies
 * platform/modules/astro computes. House cusps are absent because equal houses make every
 * cusp ascendant + 30n — a receiver that wants them derives them, and a
 * derived value on a wire is a second truth waiting to disagree. */
struct node_star_chart {
    struct node_star_position ascendant;
    struct node_star_position body[ASTRO_BODY_COUNT];
};

/* Everything a character is, in memory. `character` and `chart` are DERIVED
 * from the three fields above them and are held here only so a decoder can
 * report what it was handed before deciding whether to believe it. */
struct node_character_sheet {
    uint8_t identity_root[32];
    struct astro_instant born; /* the node's genesis moment; asserted */
    struct node_work work;     /* claimed observed work */

    struct node_character character; /* form (recomputable) + standing (claim) */
    struct node_star_chart chart;    /* recomputable */
};

/* How much of the claimed standing this node is willing to stand behind.
 * Zero is the weak answer, so a receipt that was never filled in reads as
 * "unverified" rather than as corroboration. */
enum node_standing_trust {
    /* This node's own observations do not account for the claim. The honest
     * default, and the answer for every stranger. NOT an accusation: see the
     * header note on why there is no CONTRADICTED. */
    NODE_STANDING_UNVERIFIED = 0,
    /* This node observed at least the claimed counters, field by field. */
    NODE_STANDING_CORROBORATED
};

/* The result of accepting a sheet. */
struct node_character_receipt {
    /* Exactly what arrived, after it passed every check. */
    struct node_character_sheet sheet;

    /* What this node believes. Form is recomputed (and therefore equals the
     * sheet's, or the sheet was refused). STANDING IS DERIVED FROM THIS NODE'S
     * OWN OBSERVATIONS AND FROM NOTHING ON THE WIRE — for a stranger with no
     * observations that is a wanderer with zero energy, whatever the sheet
     * claims. */
    struct node_character believed;

    enum node_standing_trust trust;
};

/* ── Derivation ──────────────────────────────────────────────────────────── */

/* The fictional birthplace derived from an identity root. Always inside
 * platform/modules/astro's accepted range, so a chart cast for it is never refused for its
 * place. False (leaving *out zeroed) only on a NULL argument. */
bool node_character_birth_place(const uint8_t identity_root[32],
                                struct astro_place *out);

/* Build a sheet. `work` may be NULL, meaning nothing observed yet.
 *
 * Returns false — zeroing *out — on a NULL root or output, an invalid
 * birthday (astro_instant_is_valid), or a chart platform/modules/astro refuses. It never
 * returns a partially filled sheet. */
bool node_character_sheet_make(const uint8_t identity_root[32],
                               const struct astro_instant *born,
                               const struct node_work *work,
                               struct node_character_sheet *out);

/* ── Wire form ───────────────────────────────────────────────────────────── */

/* Encode. The output is written field by field, big-endian, so it carries no
 * struct padding and no host byte order. False (leaving *out zeroed) for a
 * NULL argument or a sheet whose fields are out of range — an encoder that
 * emitted an unparseable frame would move a defect onto the network. */
bool node_character_sheet_encode(const struct node_character_sheet *sheet,
                                 uint8_t out[NODE_CHARACTER_WIRE_BYTES]);

/* Decode STRUCTURALLY: magic, version, revision, and every field's declared
 * range. It does NOT recompute anything, so a sheet it accepts is well-formed
 * and not yet checked — use node_character_sheet_verify() to decide whether to
 * believe it. Exposed separately so a test can tamper with a decoded sheet's
 * fields and prove the verifier, not the parser, is what refuses it.
 *
 * `len` must be exactly NODE_CHARACTER_WIRE_BYTES. *out is zeroed on every
 * rejection. */
bool node_character_sheet_decode(const uint8_t *wire, size_t len,
                                 struct node_character_sheet *out);

/* ── Receipt ─────────────────────────────────────────────────────────────── */

/* Decode, recompute, and decide. In order:
 *
 *   1. structural decode (above);
 *   2. recompute form and standing from the claimed identity root and claimed
 *      counters; REFUSE unless they match the sheet exactly;
 *   3. recompute the birthplace and the chart from the identity root and the
 *      birthday; REFUSE unless every one of the ten positions matches;
 *   4. set `believed` from `observed` alone, and `trust` to CORROBORATED only
 *      when every claimed counter is covered by an observed one.
 *
 * `observed` is what THIS node has seen the sender do; NULL means nothing,
 * which is the normal case for a stranger and yields a believed wanderer with
 * zero energy. *out is zeroed on every rejection, so a caller that ignores the
 * return value cannot read a refused sheet as a character. */
bool node_character_sheet_verify(const uint8_t *wire, size_t len,
                                 const struct node_work *observed,
                                 struct node_character_receipt *out);

/* ── Text form ───────────────────────────────────────────────────────────── */

/* Enough for the whole rendering with room to spare; the renderer refuses
 * rather than truncating, so a caller that passes less gets false and an empty
 * buffer instead of half a character. */
#define NODE_CHARACTER_SHEET_TEXT_MAX 1536u

/* Render a receipt for a person. The standing lines state BOTH numbers and
 * label them: what this node believes, and what the sheet claimed, marked
 * unverified until corroborated. Presenting only the claim would be exactly
 * the promotion this module exists to prevent.
 *
 * False (and out[0] = 0 when cap > 0) on a NULL argument, a short buffer, or a
 * receipt that does not hold a well-formed sheet. */
bool node_character_receipt_render(const struct node_character_receipt *receipt,
                                   char *out, size_t cap);

/* Stable lowercase token for a trust state ("unverified", "corroborated").
 * Never NULL; an out-of-range value renders as "unknown". A wire form:
 * changing one is a compatibility break, not a rename. */
const char *node_standing_trust_name(enum node_standing_trust trust);

#endif /* ZCL_METAVERSE_NODE_CHARACTER_WIRE_H */
