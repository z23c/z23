/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_character, tested as a set of PROPERTIES rather than a set of golden
 * values. The claims worth defending are not "this identity yields hue 214";
 * they are the rules that make a character trustworthy:
 *
 *   (a) form depends on the identity root and NOTHING else — the same node
 *       looks the same however much or little work it has done
 *   (b) standing depends on demonstrated work and NOTHING else — two nodes
 *       with identical counters have identical energy and archetype however
 *       different they look
 *   (c) the derivation is total: no input, including a hostile one, produces
 *       an out-of-range field, a wrapped total, or an unbounded energy
 *   (d) energy is monotone and logarithmic — more work is never worth less,
 *       and a thousand times the work is about ten doublings, not a thousand
 *       times the energy
 *   (e) archetype is earned: it names the largest observed contribution, and
 *       a node nobody has observed is a WANDERER rather than a weak SEEDER
 *
 * A golden-value test would pass while every one of those rules was broken.
 */
#include "test/test_core.h"

#include "metaverse/node_character.h"

#include <stdio.h>
#include <string.h>

#define NC_CHECK(name, expr) do { \
    printf("node_character: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* A deterministic pseudo-identity: byte i of root n. Not a hash, and it does
 * not need to be — the derivation must behave for ANY 32 bytes, so a spread
 * that is merely varied exercises it honestly. */
static void nc_root(uint8_t out[32], unsigned n)
{
    for (unsigned i = 0; i < 32; i++)
        out[i] = (uint8_t)((n * 31u + i * 7u + (n >> 3)) & 0xffu);
}

static bool nc_form_equal(const struct node_character *a,
                          const struct node_character *b)
{
    return a->hue_deg == b->hue_deg && a->silhouette == b->silhouette &&
           a->marking == b->marking && a->form_rev == b->form_rev;
}

int test_node_character(void)
{
    int failures = 0;

    /* ── (c) totality, including the refusals ───────────────────────────── */
    {
        struct node_character c;
        uint8_t root[32];
        nc_root(root, 1);

        NC_CHECK("a null output is refused rather than written through",
                 !node_character_derive(root, NULL, NULL));

        memset(&c, 0xab, sizeof c);
        NC_CHECK("a null identity is refused",
                 !node_character_derive(NULL, NULL, &c));
        /* The refusal must also leave nothing usable behind: a caller that
         * ignores the return value must not read stale bytes as a character. */
        NC_CHECK("a refused derivation zeroes its output",
                 c.hue_deg == 0 && c.silhouette == 0 && c.marking == 0 &&
                 c.form_rev == 0 && c.energy == 0 &&
                 c.archetype == NODE_ARCHETYPE_WANDERER);

        NC_CHECK("NULL work is accepted and means nothing observed yet",
                 node_character_derive(root, NULL, &c) &&
                 c.energy == 0 && c.archetype == NODE_ARCHETYPE_WANDERER);

        /* A caller holding zeroed counters and a caller holding none at all
         * must agree, or the same node renders two ways. */
        struct node_work zero = {0};
        struct node_character cz;
        NC_CHECK("zeroed counters and NULL counters agree",
                 node_character_derive(root, &zero, &cz) &&
                 cz.energy == c.energy && cz.archetype == c.archetype &&
                 nc_form_equal(&cz, &c));
    }

    /* ── every field in range, across many identities ───────────────────── */
    {
        bool in_range = true, rev_stamped = true;
        for (unsigned n = 0; n < 4096; n++) {
            uint8_t root[32];
            struct node_character c;
            nc_root(root, n);
            if (!node_character_derive(root, NULL, &c)) { in_range = false; break; }
            if (c.hue_deg > 359u ||
                c.silhouette >= NODE_SILHOUETTE_COUNT ||
                c.marking >= NODE_MARKING_COUNT ||
                c.energy > NODE_ENERGY_MAX ||
                c.archetype >= NODE_ARCHETYPE_COUNT) { in_range = false; break; }
            if (c.form_rev != NODE_CHARACTER_FORM_REV) { rev_stamped = false; break; }
        }
        NC_CHECK("every field stays in range over 4096 identities", in_range);
        NC_CHECK("every character stamps the derivation revision", rev_stamped);
    }

    /* ── (a) form is independent of work ────────────────────────────────── */
    {
        uint8_t root[32];
        nc_root(root, 77);
        struct node_character idle, busy;
        struct node_work heavy = {
            .bytes_served = 900ull * 1024 * 1024 * 1024,
            .blocks_validated = 2500000,
            .proofs_produced = 90000,
            .peers_bootstrapped = 4000,
        };
        NC_CHECK("form derives with no work",
                 node_character_derive(root, NULL, &idle));
        NC_CHECK("form derives with heavy work",
                 node_character_derive(root, &heavy, &busy));
        NC_CHECK("work never changes what a node LOOKS like",
                 nc_form_equal(&idle, &busy));
        NC_CHECK("...but it does change standing",
                 busy.energy > idle.energy);
    }

    /* ── (b) standing is independent of identity ────────────────────────── */
    {
        struct node_work w = { .blocks_validated = 4096 };
        uint8_t a[32], b[32];
        nc_root(a, 5);
        nc_root(b, 6);
        struct node_character ca, cb;
        bool derived = node_character_derive(a, &w, &ca) &&
                       node_character_derive(b, &w, &cb);
        NC_CHECK("two identities derive", derived);
        NC_CHECK("identical work yields identical standing",
                 ca.energy == cb.energy && ca.archetype == cb.archetype);
        NC_CHECK("...while the two nodes still look different",
                 !nc_form_equal(&ca, &cb));
    }

    /* ── determinism: the same inputs, again ────────────────────────────── */
    {
        uint8_t root[32];
        nc_root(root, 1234);
        struct node_work w = { .bytes_served = 777ull * 1024 * 1024,
                               .proofs_produced = 11 };
        struct node_character first, again;
        bool ok = node_character_derive(root, &w, &first) &&
                  node_character_derive(root, &w, &again);
        NC_CHECK("the derivation repeats exactly",
                 ok && memcmp(&first, &again, sizeof first) == 0);
    }

    /* ── (d) energy is monotone and logarithmic ─────────────────────────── */
    {
        uint8_t root[32];
        nc_root(root, 9);
        bool monotone = true;
        uint16_t prev = 0;
        for (unsigned i = 0; i < 40; i++) {
            struct node_work w = { .blocks_validated = 1ull << i };
            struct node_character c;
            if (!node_character_derive(root, &w, &c)) { monotone = false; break; }
            if (c.energy < prev) { monotone = false; break; }
            prev = c.energy;
        }
        NC_CHECK("more demonstrated work is never worth less energy", monotone);

        /* Monotonicity alone permits the smallest observed work to score zero,
         * which would make a node seen doing something indistinguishable from
         * a node nobody has seen — and would contradict archetype, which calls
         * the first a SEEDER and the second a WANDERER. The two halves of a
         * character must agree about the same node. */
        struct node_work least = { .blocks_validated = 1 };
        struct node_character cleast, cnone;
        NC_CHECK("the least observed work outscores no observed work",
                 node_character_derive(root, &least, &cleast) &&
                 node_character_derive(root, NULL, &cnone) &&
                 cnone.energy == 0 && cleast.energy > 0);

        /* 1000x the work must NOT be 1000x the energy. Each doubling is worth
         * a fixed amount, so ~2^10 more work is ~10 doublings. */
        struct node_work small = { .blocks_validated = 1000 };
        struct node_work large = { .blocks_validated = 1000000 };
        struct node_character cs, cl;
        bool ok = node_character_derive(root, &small, &cs) &&
                  node_character_derive(root, &large, &cl);
        NC_CHECK("a thousand times the work derives", ok);
        /* Subtract in unsigned: uint16_t operands promote to int, and
         * comparing that against an unsigned bound is a signedness mismatch
         * the build rejects. Guard the ordering first so the subtraction is
         * meaningful rather than merely well-typed. */
        const bool ordered = cl.energy > cs.energy;
        const unsigned gained = ordered
            ? (unsigned)cl.energy - (unsigned)cs.energy : 0u;
        NC_CHECK("a thousand times the work is ~10 doublings, not 1000x",
                 ordered &&
                 gained <= 11u * NODE_ENERGY_PER_DOUBLING &&
                 gained >= 9u * NODE_ENERGY_PER_DOUBLING);
    }

    /* ── saturation: no counter produces an unbounded character ─────────── */
    {
        uint8_t root[32];
        nc_root(root, 3);
        struct node_work absurd = {
            .bytes_served = UINT64_MAX,
            .blocks_validated = UINT64_MAX,
            .proofs_produced = UINT64_MAX,
            .peers_bootstrapped = UINT64_MAX,
        };
        struct node_character c;
        NC_CHECK("maximal counters derive rather than trapping",
                 node_character_derive(root, &absurd, &c));
        NC_CHECK("energy saturates at the ceiling",
                 c.energy == NODE_ENERGY_MAX);
        NC_CHECK("the weighted total saturates rather than wrapping",
                 node_work_weighted_total(&absurd) == UINT64_MAX);

        /* Wrapping would be worse than saturating: it would make inflating a
         * counter past the top REDUCE energy, rewarding the lie. Check the
         * boundary directly rather than trusting the ceiling above. */
        struct node_work near = { .blocks_validated = UINT64_MAX / 4 };
        struct node_character cn;
        NC_CHECK("a near-overflow count does not wrap to a small energy",
                 node_character_derive(root, &near, &cn) &&
                 cn.energy >= NODE_ENERGY_MAX / 2);
    }

    /* ── (e) archetype is earned ────────────────────────────────────────── */
    {
        uint8_t root[32];
        nc_root(root, 42);
        struct node_character c;

        struct node_work seeder = { .bytes_served = 64ull * 1024 * 1024 * 1024 };
        NC_CHECK("moving the most bytes makes a seeder",
                 node_character_derive(root, &seeder, &c) &&
                 c.archetype == NODE_ARCHETYPE_SEEDER);

        struct node_work validator = { .blocks_validated = 500000 };
        NC_CHECK("validating the most blocks makes a validator",
                 node_character_derive(root, &validator, &c) &&
                 c.archetype == NODE_ARCHETYPE_VALIDATOR);

        struct node_work prover = { .proofs_produced = 20000 };
        NC_CHECK("producing the most proofs makes a prover",
                 node_character_derive(root, &prover, &c) &&
                 c.archetype == NODE_ARCHETYPE_PROVER);

        struct node_work beacon = { .peers_bootstrapped = 5000 };
        NC_CHECK("bootstrapping the most peers makes a beacon",
                 node_character_derive(root, &beacon, &c) &&
                 c.archetype == NODE_ARCHETYPE_BEACON);

        /* A node seen doing a little is not the same as a node not seen. */
        struct node_work tiny = { .bytes_served = 4ull * 1024 * 1024 };
        NC_CHECK("a little observed work is a seeder, not a wanderer",
                 node_character_derive(root, &tiny, &c) &&
                 c.archetype == NODE_ARCHETYPE_SEEDER);
        NC_CHECK("no observed work at all is a wanderer",
                 node_character_derive(root, NULL, &c) &&
                 c.archetype == NODE_ARCHETYPE_WANDERER);
    }

    /* ── names are a wire form ──────────────────────────────────────────── */
    {
        bool named = true, distinct = true;
        for (unsigned i = 0; i < NODE_ARCHETYPE_COUNT; i++) {
            const char *n = node_archetype_name((enum node_archetype)i);
            if (!n || !n[0] || strcmp(n, "unknown") == 0) { named = false; break; }
            for (unsigned j = 0; j < i; j++)
                if (strcmp(n, node_archetype_name((enum node_archetype)j)) == 0)
                    distinct = false;
        }
        NC_CHECK("every archetype has a real name", named);
        NC_CHECK("no two archetypes share a name", distinct);
        NC_CHECK("an out-of-range archetype is named, not indexed past",
                 strcmp(node_archetype_name((enum node_archetype)999),
                        "unknown") == 0);
    }

    /* ── the exact values, pinned ────────────────────────────────────────
     *
     * Every check above constrains SHAPE — ordering, saturation, totality,
     * determinism — and a mutation run proved that is not enough: the four
     * weights and both byte offsets could each be changed and this file
     * still passed. The header calls those weights "the whole editorial
     * content of this file", so leaving them unpinned meant the one thing
     * most worth defending was the one thing nothing defended.
     *
     * These are deliberately golden values, which the rest of this file
     * avoids. That is the point: a rule cannot pin a constant. Changing a
     * weight is a policy decision about what a node's work is worth, and it
     * must break a test and be argued, not slip through as a typo. */
    {
        uint8_t root[32];
        nc_root(root, 555);

        /* One unit of each kind, weighed alone. A MiB served is the unit;
         * the other three are worth 16, 256 and 64 of it. */
        struct node_work one_mib   = { .bytes_served = 1024u * 1024u };
        struct node_work one_block = { .blocks_validated = 1 };
        struct node_work one_proof = { .proofs_produced = 1 };
        struct node_work one_peer  = { .peers_bootstrapped = 1 };

        NC_CHECK("a megabyte served weighs exactly one unit",
                 node_work_weighted_total(&one_mib) == 1u);
        NC_CHECK("a validated block weighs exactly 16",
                 node_work_weighted_total(&one_block) == 16u);
        NC_CHECK("a produced proof weighs exactly 256",
                 node_work_weighted_total(&one_proof) == 256u);
        NC_CHECK("a bootstrapped peer weighs exactly 64",
                 node_work_weighted_total(&one_peer) == 64u);

        /* Sub-unit traffic rounds DOWN to nothing rather than up to one:
         * otherwise a node could earn standing by serving a single byte
         * many times. */
        struct node_work crumb = { .bytes_served = 1024u * 1024u - 1u };
        NC_CHECK("less than a megabyte served weighs nothing",
                 node_work_weighted_total(&crumb) == 0u);

        /* Byte order and byte offsets. nc_be16 reads root[0..1] big-endian,
         * silhouette comes from root[7], marking from root[19]. A mutation
         * run showed all three could move undetected, in a file whose
         * header claims byte-order independence. */
        uint8_t probe[32];
        memset(probe, 0, sizeof probe);
        probe[0] = 0x01;   /* big-endian high byte -> 256 */
        probe[1] = 0x00;
        probe[7] = 5u;
        probe[19] = 9u;
        struct node_character pc;
        NC_CHECK("the probe identity derives", node_character_derive(probe, NULL, &pc));
        NC_CHECK("hue reads the first two bytes BIG-endian, not little",
                 pc.hue_deg == (uint16_t)(256u % 360u));
        NC_CHECK("silhouette comes from byte 7", pc.silhouette == 5u % NODE_SILHOUETTE_COUNT);
        NC_CHECK("marking comes from byte 19", pc.marking == 9u % NODE_MARKING_COUNT);

        /* If hue read the bytes the other way round it would be 1, not 256.
         * Assert the wrong answer is actually different, so this test cannot
         * pass by coincidence on a palindromic probe. */
        NC_CHECK("the little-endian reading would differ, so the check bites",
                 (uint16_t)(256u % 360u) != (uint16_t)(1u % 360u));
    }
    printf("=== node_character: %d failure(s) ===\n", failures);
    return failures;
}
