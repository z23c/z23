/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdogfight demo: run a match between two built-in trivial pilots and
 * print the final FNV-1a/64 checksum of the canonical state encoding.
 * The library has no hash dependency; callers that need a cryptographic
 * root hash zdog_state_encode's bytes.
 */
#include "zdogfight/zdogfight.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Trivial pilot A: full throttle straight ahead, always firing. */
static void pilot_straight(zdog_ctl *c)
{
    c->roll = 0;
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = 1;
}

/* Trivial pilot B: gentle weave, firing. */
static void pilot_weave(uint64_t tick, zdog_ctl *c)
{
    c->roll = (int16_t)((tick / 90u) % 2u ? 12000 : -12000);
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = (uint8_t)(tick % 6u == 0u);
}

static void usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  zdogfight play [--seed N] [--planes N]\n"
            "  zdogfight selftest\n");
}

static int play(uint64_t seed, unsigned planes)
{
    zdog_match m;

    if (planes < 1u || planes > 4u) {
        fprintf(stderr, "zdogfight: --planes must be 1..4\n");
        return 2;
    }
    zdog_match_init(&m, seed, (uint8_t)planes);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl ctls[ZDOG_MAX_PLANES] = {{0}};

        for (unsigned i = 0; i < m.num_planes; i++) {
            if (m.planes[i].team == 0)
                pilot_straight(&ctls[i]);
            else
                pilot_weave(m.tick, &ctls[i]);
        }
        zdog_tick(&m, ctls);
    }
    printf("tick=%" PRIu64 " winner=%s score=%" PRIu32 "-%" PRIu32
           " root=%016" PRIx64 " seed=%" PRIu64 " planes=%u\n",
           m.tick,
           m.winner == ZDOG_WINNER_RED    ? "red"
           : m.winner == ZDOG_WINNER_BLUE ? "blue"
                                          : "draw",
           m.score[0], m.score[1], zdog_state_checksum(&m), seed, planes);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "selftest") == 0)
        return play(42, 2);
    if (strcmp(argv[1], "play") != 0) {
        usage(stderr);
        return 2;
    }

    uint64_t seed = 7;
    unsigned planes = 2;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "zdogfight: missing value for --seed\n");
                return 2;
            }
            seed = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--planes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "zdogfight: missing value for --planes\n");
                return 2;
            }
            planes = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "zdogfight: unknown argument %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }
    return play(seed, planes);
}
