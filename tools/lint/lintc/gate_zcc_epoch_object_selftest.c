/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-zcc-epoch-object
 * (gate_zcc_epoch_object*.c). The shell original had no self-test mode,
 * so this exercises the ported helper layer directly in a throwaway
 * mkdtemp scratch dir (never a literal temp path): the in-C SHA-256
 * against the standard "abc" test vector (passing case), a corrupted
 * digest that must NOT match (failing case), launch-line counting, log
 * tail first-field and suffix probing, and byte-compare.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_epoch_object_priv.h"

static const char k_zs_vector[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static int zs_sha_known(void)
{
    char hex[ZEO_HASH];
    if (zeo_sha256_hex("abc", hex) != 0)
        return 0;
    return strcmp(hex, k_zs_vector) == 0;
}

static int zs_sha_corrupt(void)
{
    char hex[ZEO_HASH];
    if (zeo_sha256_hex("abc", hex) != 0)
        return 1;
    char bad[ZEO_HASH];
    strcpy(bad, k_zs_vector);
    bad[0] = bad[0] == '0' ? '1' : '0';
    return strcmp(hex, bad) == 0;
}

static char zs_dir[ZEO_PATH];

static int zs_scratch(void)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(td) != 0)
        return 2;
    char tpl[ZEO_PATH];
    if (ovf(snprintf(tpl, sizeof tpl, "%s/z23-lint-zcc-epoch.XXXXXX", td),
            sizeof tpl))
        return 2;
    if (!mkdtemp(tpl))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    if (ovf(snprintf(zs_dir, sizeof zs_dir, "%s", tpl), sizeof zs_dir))
        return 2;
    return 0;
}

static int zs_line_count(void)
{
    char path[ZEO_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/launches", zs_dir), sizeof path))
        return 0;
    if (zeo_write_file(path, "compile\npreprocess\ncompile\nother\n") != 0)
        return 0;
    return zeo_count_line_eq(path, "compile") == 2 &&
           zeo_count_line_eq(path, "preprocess") == 1 &&
           zeo_count_lines(path) == 4;
}

static int zs_log_tail(void)
{
    char path[ZEO_PATH], tail[ZEO_PATH];
    size_t n, s;
    if (ovf(snprintf(path, sizeof path, "%s/zcc.log", zs_dir), sizeof path))
        return 0;
    if (zeo_write_file(path,
                       "MISS probe src=1\nHIT dep src=1 out/no/such.o\n") !=
        0)
        return 0;
    if (zeo_tail1(path, tail, sizeof tail) != 0)
        return 0;
    if (!zeo_first_tok_is(tail, "HIT"))
        return 0;
    n = strlen(tail);
    s = strlen("out/no/such.o");
    return n >= s + 1 && tail[n - s - 1] == ' ' &&
           strcmp(tail + n - s, "out/no/such.o") == 0;
}

static int zs_files_equal(void)
{
    char a[ZEO_PATH], b[ZEO_PATH];
    if (ovf(snprintf(a, sizeof a, "%s/a.bin", zs_dir), sizeof a) ||
        ovf(snprintf(b, sizeof b, "%s/b.bin", zs_dir), sizeof b))
        return 0;
    if (zeo_write_file(a, "same bytes\n") != 0 ||
        zeo_write_file(b, "same bytes\n") != 0)
        return 0;
    if (!zeo_files_equal(a, b))
        return 0;
    if (zeo_write_file(b, "different bytes\n") != 0)
        return 0;
    return !zeo_files_equal(a, b);
}

struct zs_case {
    const char *name;
    int (*fn)(void);
    int want;
};

int check_zcc_epoch_object_selftest(void)
{
    static const struct zs_case cases[] = {
        { "sha256 matches the abc test vector", zs_sha_known, 1 },
        { "corrupted digest does not match", zs_sha_corrupt, 0 },
        { "launch line counting is exact", zs_line_count, 1 },
        { "log tail first field and suffix match", zs_log_tail, 1 },
        { "byte compare detects a difference", zs_files_equal, 1 },
    };
    int rc = zs_scratch();
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int got = cases[i].fn();
        if (got != cases[i].want) {
            fprintf(stderr, "check_zcc_epoch_object selftest: %s: want %d "
                    "got %d\n", cases[i].name, cases[i].want, got);
            bad = 1;
        } else {
            printf("  selftest ok: %s\n", cases[i].name);
        }
    }
    rap_rm_rf(zs_dir);
    return st_ok(bad, "check_zcc_epoch_object selftest: OK\n");
}
