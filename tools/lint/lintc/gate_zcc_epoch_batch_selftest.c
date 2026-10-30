/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-zcc-epoch-batch --selftest. Proves the gate's inputs are
 * present and that the fixture still includes the codec header:
 * the codec test fixture, the codec source, its header and the allocator the
 * fixture links against. The compile-and-run path itself is the gate run.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char *const k_zebs_inputs[] = {
    "tools/lint/fixtures/zcc_epoch_batch_check.c.fixture",
    "tools/zcc_epoch_batch.c",
    "tools/zcc_epoch_batch.h",
    "platform/modules/base/src/safe_alloc.c",
    NULL,
};

static int zebs_fixture_marks(void)
{
    static char buf[65536];
    FILE *f = fopen(k_zebs_inputs[0], "r");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int bad = ferror(f) != 0;
    fclose(f);
    buf[n] = '\0';
    return bad || !strstr(buf, "#include \"zcc_epoch_batch.h\"");
}

int check_zcc_epoch_batch_selftest(void)
{
    for (const char *const *p = k_zebs_inputs; *p; p++) {
        if (access(*p, R_OK) != 0) {
            fprintf(stderr, "check_zcc_epoch_batch selftest: missing %s\n",
                    *p);
            return 1;
        }
    }
    if (zebs_fixture_marks()) {
        fprintf(stderr,
                "check_zcc_epoch_batch selftest: fixture lacks codec include\n");
        return 1;
    }
    printf("check_zcc_epoch_batch selftest: OK\n");
    return 0;
}
