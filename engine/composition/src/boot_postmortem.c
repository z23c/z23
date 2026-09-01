/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_postmortem.h"

#include "platform/rng.h"
#include "platform/time_compat.h"
#include "sim/postmortem.h"
#include "sim/seed_tape.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BOOT_POSTMORTEM_MAX_AGE_SECONDS (30LL * 24LL * 60LL * 60LL)
#define BOOT_POSTMORTEM_KEEP_LATEST 100u
#define BOOT_POSTMORTEM_EVENT_TYPE 1u
#define BOOT_POSTMORTEM_EVENT_PAYLOAD "boot-postmortem-installed"

static seed_tape_t *g_boot_seed_tape = NULL;
static char g_boot_postmortem_dir[1024];

void boot_postmortem_stop(void)
{
    postmortem_uninstall();
    seed_tape_t *tape = g_boot_seed_tape;
    g_boot_seed_tape = NULL;
    g_boot_postmortem_dir[0] = '\0';
    if (tape)
        seed_tape_close(tape);
}

bool boot_postmortem_start(const char *datadir)
{
    if (!datadir || !*datadir)
        return false;

    if (g_boot_seed_tape)
        boot_postmortem_stop();

    int n = snprintf(g_boot_postmortem_dir, sizeof(g_boot_postmortem_dir),
                     "%s/postmortems", datadir);
    if (n < 0 || (size_t)n >= sizeof(g_boot_postmortem_dir)) {
        fprintf(stderr,  // obs-ok:boot-fatal-before-event-context
                "WARNING: postmortem path too long; crash capsules disabled\n");
        g_boot_postmortem_dir[0] = '\0';
        return false;
    }

    uint64_t seed = rng_u64();
    int64_t wall = platform_time_wall_time_t();
    seed_tape_t *tape = seed_tape_open(seed, wall);
    if (!tape) {
        fprintf(stderr,  // obs-ok:boot-fatal-before-event-context
                "WARNING: seed_tape_open failed; crash capsules disabled\n");
        return false;
    }
    (void)seed_tape_inject(tape, BOOT_POSTMORTEM_EVENT_TYPE,
                           BOOT_POSTMORTEM_EVENT_PAYLOAD,
                           strlen(BOOT_POSTMORTEM_EVENT_PAYLOAD));

    int rc = postmortem_install(tape, g_boot_postmortem_dir);
    if (rc != 0) {
        fprintf(stderr,  // obs-ok:boot-fatal-before-event-context
                "WARNING: postmortem_install failed rc=%d; crash capsules disabled\n",
                rc);
        seed_tape_close(tape);
        g_boot_postmortem_dir[0] = '\0';
        return false;
    }

    g_boot_seed_tape = tape;
    size_t compressed = 0;
    rc = postmortem_capsule_compress_unpacked(g_boot_postmortem_dir,
                                              &compressed);
    if (rc != 0) {
        fprintf(stderr,  // obs-ok:boot-fatal-before-event-context
                "WARNING: postmortem compression failed rc=%d\n", rc);
    } else if (compressed > 0) {
        printf("[boot] postmortem compressed %zu capsule(s)\n", compressed);
    }

    size_t pruned = 0;
    rc = postmortem_capsule_prune(g_boot_postmortem_dir,
                                  platform_time_wall_time_t(),
                                  BOOT_POSTMORTEM_MAX_AGE_SECONDS,
                                  BOOT_POSTMORTEM_KEEP_LATEST,
                                  &pruned);
    if (rc != 0) {
        fprintf(stderr,  // obs-ok:boot-fatal-before-event-context
                "WARNING: postmortem prune failed rc=%d\n", rc);
    } else if (pruned > 0) {
        printf("[boot] postmortem pruned %zu old capsule(s)\n", pruned);
    }
    printf("[boot] postmortem capsules: %s\n", g_boot_postmortem_dir);
    return true;
}

#ifdef ZCL_TESTING
bool boot_postmortem_init_for_testing(const char *datadir)
{
    return boot_postmortem_start(datadir);
}

void boot_postmortem_shutdown_for_testing(void)
{
    boot_postmortem_stop();
}

const char *boot_postmortem_dir_for_testing(void)
{
    return g_boot_postmortem_dir[0] ? g_boot_postmortem_dir : NULL;
}
#endif
