/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_fuzz_artifact_replay
 * (gate_fuzz_artifact_replay.c). Plant / trip / recover proof that the gate
 * still fires: the clean tree must pass --ledger-only, a planted untriaged
 * artifact must trip it AND be named in the output, and removing the
 * fixture must recover. Ported from the --selftest half of
 * tools/lint/check_fuzz_artifact_replay.sh (deleted). Runs from the
 * repository root, like the script, and writes its fixture into the real
 * corpus under a name that cannot be mistaken for a real finding.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fuzz_artifact_replay_priv.h"

static const char k_fars_fixture[] =
    "tests/harness/fuzz_seeds/block/"
    "crash-selftest-planted-not-a-real-finding.bin";

static char k_fars_log[1u << 16];

/* One plain --ledger-only run with both streams captured. */
static int fars_run(FILE *o, FILE *e)
{
    char *av[2];
    int rc;
    av[0] = (char *)"--ledger-only";
    av[1] = NULL;
    rc = far_main(1, av, o, e);
    fflush(o);
    fflush(e);
    return rc;
}

/* Reads the whole captured err stream into k_fars_log. */
static int fars_slurp(FILE *e)
{
    size_t n = 0;
    rewind(e);
    for (;;) {
        int ch = fgetc(e);
        if (ch == EOF)
            break;
        if (n + 1 >= sizeof k_fars_log)
            break;
        k_fars_log[n++] = (char)ch;
    }
    k_fars_log[n] = '\0';
    return (int)n;
}

static void fars_dump(FILE *e)
{
    fars_slurp(e);
    fputs(k_fars_log, stderr);
}

static int fars_plant(void)
{
    static const unsigned char bytes[5] = { 0x4e, 0xfb, 0xff, 0xff, 0xff };
    FILE *f = fopen(k_fars_fixture, "wb");
    if (!f)
        return 1;
    if (fwrite(bytes, 1, sizeof bytes, f) != sizeof bytes) {
        fclose(f);
        return 1;
    }
    return fclose(f) != 0;
}

int check_fuzz_artifact_replay_selftest(void)
{
    FILE *o, *e;
    int rc;
    unsetenv("ZCL_FUZZ_REPLAY_SELFTEST");
    unsetenv("ZCL_FUZZ_REPLAY_LEDGER_ONLY");
    unlink(k_fars_fixture);
    o = tmpfile();
    e = tmpfile();
    if (!o || !e)
        return die("z23-lint: tmpfile failed\n", "");
    rc = fars_run(o, e);
    if (rc != 0) {
        fprintf(stderr, "%s --selftest: FAIL — the clean tree does not "
                        "pass\n", k_far_gate);
        fars_dump(e);
        return 1;
    }
    if (fars_plant() != 0) {
        fprintf(stderr, "%s --selftest: cannot write fixture %s\n",
                k_far_gate, k_fars_fixture);
        unlink(k_fars_fixture);
        return 1;
    }
    rewind(o);
    rewind(e);
    rc = fars_run(o, e);
    unlink(k_fars_fixture);
    if (rc == 0) {
        fprintf(stderr, "%s --selftest: FAIL — a planted untriaged artifact "
                        "did NOT trip the gate\n", k_far_gate);
        fars_dump(e);
        return 1;
    }
    fars_slurp(e);
    if (!strstr(k_fars_log, k_fars_fixture)) {
        fprintf(stderr, "%s --selftest: FAIL — the gate tripped but never "
                        "named %s\n", k_far_gate, k_fars_fixture);
        fputs("  Naming the exact file is the point: a red build must not "
              "send\n", stderr);
        fputs("  anyone hunting for which artifact broke.\n", stderr);
        fputs(k_fars_log, stderr);
        return 1;
    }
    rewind(o);
    rewind(e);
    rc = fars_run(o, e);
    if (rc != 0) {
        fprintf(stderr, "%s --selftest: FAIL — the gate stayed red after the "
                        "fixture was removed\n", k_far_gate);
        fars_dump(e);
        return 1;
    }
    printf("[%s] selftest: clean passes, planted artifact trips and is NAMED, "
           "removal recovers\n", k_far_gate);
    return 0;
}
