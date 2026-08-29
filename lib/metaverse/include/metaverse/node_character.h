/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character — what one full node LOOKS LIKE and how strong it is, as a
 * pure derivation from facts the network can already check. No I/O, no store,
 * no chain, no allocation, no statics, no locks.
 *
 * A node is a character. Its FORM comes from its identity; its STANDING comes
 * from work it has demonstrably done. Those two halves are deliberately fed by
 * different inputs, because they answer different questions and have different
 * failure modes.
 *
 * ── FORM comes from the identity root, and only from it ──────────────────
 *
 * Appearance is derived from the node's own 32-byte identity root. That makes
 * it UNFORGEABLE in the only sense that matters here: a node cannot choose to
 * look like another node without being that node. It is also free to verify —
 * anyone holding your identity root recomputes your form exactly — and it
 * conveys no advantage, so there is nothing to win by grinding for a
 * particular appearance. Form is cosmetic and permanent.
 *
 * ── STANDING comes from demonstrated work, NEVER from claimed capacity ───
 *
 * The obvious design is energy = the node's CPU. It is wrong. A node reports
 * its own hardware over the wire, so the moment energy is worth anything,
 * every node reports 128 cores and the number stops meaning anything. There is
 * no way to check a claim about a machine you cannot see.
 *
 * So energy is computed from work OTHERS OBSERVED this node do: bytes actually
 * served to peers, blocks actually validated, proofs actually produced, peers
 * actually bootstrapped. Each of those left evidence somewhere other than on
 * the node making the claim. `struct node_work` therefore holds counters of
 * completed work, and deliberately holds NO field for cores, RAM, or clock
 * speed. Do not add one.
 *
 * ── Energy is logarithmic on purpose ─────────────────────────────────────
 *
 * Every doubling of demonstrated work adds a FIXED amount of energy, and the
 * total saturates. A node that has served a thousand times more bytes than
 * another is about ten doublings ahead, not a thousand times stronger. This is
 * a network of sovereign peers, not a leaderboard: a large operator should be
 * visibly accomplished without making every small honest node look like
 * nothing. Saturation also means no counter, however large or however
 * dishonestly inflated, can produce an unbounded character.
 *
 * ── Integer arithmetic only, for a reason ────────────────────────────────
 *
 * Every value here is computed with integers. Floating point is permitted to
 * differ in the last bits between compilers, platforms and optimisation
 * levels, and two nodes disagreeing about a third node's appearance would be
 * indistinguishable from one of them lying. A character derived on Linux,
 * macOS and Windows from the same inputs is bit-identical, and that is a
 * property this file must keep.
 *
 * ── This layer is never authoritative ────────────────────────────────────
 *
 * Nothing here may be read by consensus, and nothing here decides what a node
 * is ALLOWED to do — `metaverse_grant_check()` owns that and stays the only
 * answer. A character renders facts; it never becomes one. If a future change
 * would let a character's energy widen what its node may do, that change is
 * wrong: it would turn a cosmetic layer into an authority, and make grinding
 * appearance worth something.
 */
#ifndef ZCL_METAVERSE_NODE_CHARACTER_H
#define ZCL_METAVERSE_NODE_CHARACTER_H

#include <stdbool.h>
#include <stdint.h>

/* Bump when a derivation rule changes, so a stored character can be told apart
 * from one this build would compute. Stamped into every result. */
#define NODE_CHARACTER_FORM_REV 1u

/* Silhouettes and markings are small closed sets: a viewer must be able to
 * recognise a shape across the network, which a continuous space defeats. */
#define NODE_SILHOUETTE_COUNT 12u
#define NODE_MARKING_COUNT    16u

/* Energy ceiling, and what one doubling of demonstrated work is worth.
 *
 * Weighted work is a uint64, so it spans exactly 64 doublings, and 64 x 16 is
 * the ceiling: attainable in principle by a node that has saturated its
 * counters, and out of reach in practice. The two constants must keep that
 * relationship — a ceiling nothing can reach is a wrong constant that stays
 * hidden until the day something saturates. */
#define NODE_ENERGY_MAX          1024u
#define NODE_ENERGY_PER_DOUBLING 16u

/* What a node mostly DOES, from the same observed counters as energy. The
 * archetype is the single largest weighted contribution, so a character's
 * class is earned by behaviour rather than chosen. */
enum node_archetype {
    /* Nothing demonstrated yet. The honest starting state of every new node,
     * and never a penalty — a node that has just joined has simply not been
     * seen doing anything yet. */
    NODE_ARCHETYPE_WANDERER = 0,
    NODE_ARCHETYPE_SEEDER,    /* moves bytes to peers */
    NODE_ARCHETYPE_VALIDATOR, /* checks blocks */
    NODE_ARCHETYPE_PROVER,    /* produces proofs */
    NODE_ARCHETYPE_BEACON,    /* brings other nodes onto the network */
    NODE_ARCHETYPE_COUNT
};

/* Work OTHERS OBSERVED. Every field is completed work that left evidence off
 * this node. There is deliberately no field for claimed hardware. */
struct node_work {
    uint64_t bytes_served;
    uint64_t blocks_validated;
    uint64_t proofs_produced;
    uint64_t peers_bootstrapped;
};

struct node_character {
    /* Form — from the identity root alone. */
    uint16_t hue_deg;    /* 0..359 */
    uint8_t  silhouette; /* < NODE_SILHOUETTE_COUNT */
    uint8_t  marking;    /* < NODE_MARKING_COUNT */
    uint8_t  form_rev;   /* NODE_CHARACTER_FORM_REV that produced this */

    /* Standing — from demonstrated work alone. */
    enum node_archetype archetype;
    uint16_t energy; /* 0..NODE_ENERGY_MAX */
};

/* Derive a character. `identity_root` is 32 bytes. `work` may be NULL, which
 * means "nothing observed yet" and yields a WANDERER with zero energy — the
 * same result as an all-zero struct, so a caller with no counters yet and a
 * caller with empty counters agree.
 *
 * Returns false only on a null identity or output, leaving *out zeroed.
 * Total, deterministic, and identical on every platform. */
bool node_character_derive(const uint8_t identity_root[32],
                           const struct node_work *work,
                           struct node_character *out);

/* Stable lowercase token for an archetype ("wanderer", "seeder", ...). Never
 * NULL: an out-of-range value returns "unknown" rather than indexing past the
 * table. These strings are a wire form — changing one is a compatibility
 * break, not a rename. */
const char *node_archetype_name(enum node_archetype a);

/* The weighted work total behind `energy`, exposed so a caller can show what
 * earned it. Saturating; `work` may be NULL (returns 0). */
uint64_t node_work_weighted_total(const struct node_work *work);

#endif /* ZCL_METAVERSE_NODE_CHARACTER_H */
