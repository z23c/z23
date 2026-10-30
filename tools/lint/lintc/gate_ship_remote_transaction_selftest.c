/* Copyright 2026 Rhett Creiton - Apache License 2.0
 *
 * purpose: --selftest for check_ship_remote_transaction
 * (gate_ship_remote_transaction.c). The shell original had no self-test
 * mode, so per the port rules this proves the shared helpers it leans on:
 * one passing case (the internal SHA-256 reproduces the published FIPS
 * vector for "abc", and the exact-line matcher finds a whole line) and one
 * failing case (a one-byte change to the input MUST be detected by the
 * digest comparison the gate's identity assertions depend on).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_ship_remote_transaction_priv.h"

static const char k_sts_abc_sha[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static int sts_scratch(char *out, size_t cap)
{
    const char *td = srt_tmpdir();
    if (ovf(snprintf(out, cap, "%s/z23-lint-ship-remote-st.XXXXXX", td), cap))
        return 2;
    if (!mkdtemp(out)) {
        fprintf(stderr, "%s selftest: mkdtemp failed\n", k_srt_gate);
        return 1;
    }
    return 0;
}

int check_ship_remote_transaction_selftest(void)
{
    char dir[SRT_PATH];
    int rc = sts_scratch(dir, sizeof dir);
    if (rc)
        return rc;
    char vec[SRT_PATH], lines[SRT_PATH];
    if (ovf(snprintf(vec, sizeof vec, "%s/vec", dir), sizeof vec))
        return 2;
    if (ovf(snprintf(lines, sizeof lines, "%s/lines", dir), sizeof lines))
        return 2;
    int bad = 0;
    char sha[SRT_SHA];
    /* passing case: known digest and a whole-line match */
    if (srt_write_file(vec, "abc") == 0 &&
        srt_sha256_file(vec, sha) == 0 && strcmp(sha, k_sts_abc_sha) == 0) {
        printf("  selftest ok: sha256 matches the published 'abc' vector\n");
    } else {
        fprintf(stderr, "%s selftest: sha256 vector mismatch\n", k_srt_gate);
        bad = 1;
    }
    if (srt_write_file(lines, "x\nprior ship selection\ny\n") == 0 &&
        srt_file_has_exact_line(lines, "prior ship selection") == 1) {
        printf("  selftest ok: exact-line matcher finds the whole line\n");
    } else {
        fprintf(stderr, "%s selftest: exact-line matcher failed\n",
                k_srt_gate);
        bad = 1;
    }
    /* failing case: a one-byte change must be caught, never silently pass */
    if (srt_write_file(vec, "abd") == 0 && srt_sha256_file(vec, sha) == 0 &&
        strcmp(sha, k_sts_abc_sha) != 0) {
        printf("  selftest ok: one-byte input change is detected (failing "
               "case caught)\n");
    } else {
        fprintf(stderr, "%s selftest: tampered input was NOT detected\n",
                k_srt_gate);
        bad = 1;
    }
    rap_rm_rf(dir);
    return st_ok(bad, "check_ship_remote_transaction selftest: OK\n");
}
