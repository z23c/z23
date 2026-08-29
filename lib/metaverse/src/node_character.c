/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character — the derivation. Every rule and every constant that decides
 * what a node looks like and how strong it is lives here, and the header
 * carries the reasoning for why the two halves have different inputs.
 *
 * This file holds no state of any kind: no statics, no allocation, no I/O, no
 * locks. Every function is total and depends only on its arguments, which is
 * what lets a test drive the whole space without a node, a datadir or a
 * network, and what lets three platforms agree byte for byte.
 */
#include "metaverse/node_character.h"

#include <string.h>

/* ── Form ────────────────────────────────────────────────────────────────── */

/* Read two bytes big-endian. Written out rather than cast through a uint16_t*
 * so the result does not depend on the host's byte order: a character must not
 * change shape when the same identity is rendered on a different machine. */
static uint16_t nc_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Distinct byte offsets feed the three form fields so that two identities
 * sharing a prefix still differ in shape. An identity root is a hash, so its
 * bytes are already unrelated to each other; the spread costs nothing and
 * removes the question.
 *
 * The modulo is very slightly biased (65536 is not a multiple of 360, so some
 * hues are ~0.2% likelier). That is stated rather than corrected: rejection
 * sampling would make the derivation depend on how many bytes it consumed,
 * which is a worse property here than a bias no viewer can perceive. Nothing
 * is won by landing on a particular hue, so the bias is not an attack surface.
 */
static void nc_form(const uint8_t root[32], struct node_character *out)
{
    out->hue_deg    = (uint16_t)(nc_be16(root) % 360u);
    out->silhouette = (uint8_t)(root[7] % NODE_SILHOUETTE_COUNT);
    out->marking    = (uint8_t)(root[19] % NODE_MARKING_COUNT);
    out->form_rev   = (uint8_t)NODE_CHARACTER_FORM_REV;
}

/* ── Demonstrated work ───────────────────────────────────────────────────── */

/* Add without ever wrapping. A wrapped total would let a node with absurd
 * counters land on a SMALL energy, which is a worse failure than saturating:
 * it would reward inflating a counter past the top. */
static uint64_t nc_add_sat(uint64_t a, uint64_t b)
{
    return (a > UINT64_MAX - b) ? UINT64_MAX : a + b;
}

static uint64_t nc_mul_sat(uint64_t a, uint64_t m)
{
    if (a == 0 || m == 0)
        return 0;
    return (a > UINT64_MAX / m) ? UINT64_MAX : a * m;
}

/* Weights convert four unlike units into one comparable quantity. They are
 * chosen so that a unit of each is roughly a comparable amount of real effort,
 * and they are the whole editorial content of this file:
 *
 *   bytes_served       one unit per MiB delivered — raw bytes would drown
 *                      every other contribution by six orders of magnitude.
 *   blocks_validated   16 — validating a block costs far more than moving a
 *                      megabyte, and it is the work the chain depends on.
 *   proofs_produced    256 — the most expensive thing a node can do.
 *   peers_bootstrapped 64 — bringing a new node onto the network compounds,
 *                      because that node then serves others.
 */
#define NC_W_BYTES_PER_UNIT (1024u * 1024u) /* divisor, not multiplier */
#define NC_W_BLOCK          16u
#define NC_W_PROOF          256u
#define NC_W_PEER           64u

uint64_t node_work_weighted_total(const struct node_work *work)
{
    if (!work)
        return 0;
    uint64_t total = work->bytes_served / NC_W_BYTES_PER_UNIT;
    total = nc_add_sat(total, nc_mul_sat(work->blocks_validated, NC_W_BLOCK));
    total = nc_add_sat(total, nc_mul_sat(work->proofs_produced, NC_W_PROOF));
    total = nc_add_sat(total, nc_mul_sat(work->peers_bootstrapped, NC_W_PEER));
    return total;
}

/* How many doublings of work `v` represents: its BIT LENGTH, so 0 -> 0,
 * 1 -> 1, and UINT64_MAX -> 64.
 *
 * The obvious choice is floor(log2(v)), and it is wrong here in two ways that
 * a test caught:
 *
 *   - floor(log2(1)) is 0, so a node observed doing a little work scored the
 *     same energy as a node nobody has seen at all. Archetype already refuses
 *     to collapse those two states — a node with any observed work is a SEEDER
 *     rather than a WANDERER — and energy contradicting archetype about the
 *     same node is a defect, not a rounding choice. Any observed work must be
 *     worth more than none.
 *
 *   - floor(log2(UINT64_MAX)) is 63, so the ceiling at 64 doublings was
 *     unreachable by exactly one doubling. A ceiling nothing can reach is not
 *     a ceiling; it is a wrong constant that hides until someone saturates.
 *
 * Bit length fixes both: the range is exactly 0..64 doublings, the top is
 * attainable, and the bottom distinguishes "seen doing something" from "not
 * seen".
 *
 * A plain loop rather than a builtin or <stdbit.h>: this must produce the same
 * answer under gcc, clang and the mingw cross-compiler, and it runs at most 64
 * times on a path nobody is timing. Correctness across three toolchains is
 * worth more here than the instructions saved. */
static unsigned nc_doublings(uint64_t v)
{
    unsigned n = 0;
    while (v) {
        v >>= 1;
        n++;
    }
    return n;
}

/* ── Archetype ───────────────────────────────────────────────────────────── */

/* The single largest weighted contribution wins. Ties resolve by the order
 * below, which is fixed so that the same counters always name the same
 * archetype on every machine — an arbitrary but STABLE rule beats one that
 * depends on iteration order. A node with no observed work is a WANDERER
 * rather than a weak SEEDER, because "not seen yet" and "seen doing very
 * little" are different states and collapsing them would misreport a node
 * that has only just joined. */
static enum node_archetype nc_archetype(const struct node_work *work)
{
    if (!work)
        return NODE_ARCHETYPE_WANDERER;

    const uint64_t scores[] = {
        work->bytes_served / NC_W_BYTES_PER_UNIT,
        nc_mul_sat(work->blocks_validated, NC_W_BLOCK),
        nc_mul_sat(work->proofs_produced, NC_W_PROOF),
        nc_mul_sat(work->peers_bootstrapped, NC_W_PEER),
    };
    static const enum node_archetype kinds[] = {
        NODE_ARCHETYPE_SEEDER,
        NODE_ARCHETYPE_VALIDATOR,
        NODE_ARCHETYPE_PROVER,
        NODE_ARCHETYPE_BEACON,
    };

    uint64_t best = 0;
    enum node_archetype winner = NODE_ARCHETYPE_WANDERER;
    for (unsigned i = 0; i < sizeof scores / sizeof scores[0]; i++) {
        if (scores[i] > best) {
            best = scores[i];
            winner = kinds[i];
        }
    }
    return winner;
}

/* ── Public entry points ─────────────────────────────────────────────────── */

bool node_character_derive(const uint8_t identity_root[32],
                           const struct node_work *work,
                           struct node_character *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!identity_root)
        return false;

    nc_form(identity_root, out);

    const uint64_t total = node_work_weighted_total(work);
    uint64_t energy = (uint64_t)nc_doublings(total) * NODE_ENERGY_PER_DOUBLING;
    if (energy > NODE_ENERGY_MAX)
        energy = NODE_ENERGY_MAX;
    out->energy = (uint16_t)energy;
    out->archetype = nc_archetype(work);
    return true;
}

const char *node_archetype_name(enum node_archetype a)
{
    switch (a) {
    case NODE_ARCHETYPE_WANDERER:  return "wanderer";
    case NODE_ARCHETYPE_SEEDER:    return "seeder";
    case NODE_ARCHETYPE_VALIDATOR: return "validator";
    case NODE_ARCHETYPE_PROVER:    return "prover";
    case NODE_ARCHETYPE_BEACON:    return "beacon";
    case NODE_ARCHETYPE_COUNT:
    default:                       return "unknown";
    }
}
