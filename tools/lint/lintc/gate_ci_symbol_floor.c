/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — the hermetic MVP C1 portability floor
 * (check-ci-symbol-floor). Ported from tools/scripts/ci_symbol_floor_gate.sh.
 * The node must run on a clean OS, so the built artifact may require no
 * symbol version newer than GLIBC_2.38 and no C++ ABI at all (no GLIBCXX_ or
 * CXXABI_ family). The gate reads the artifact's own ELF version tables
 * (SHT_GNU_verneed / SHT_GNU_verdef) and runs `ldd` once, through
 * posix_spawnp and no shell, to prove every shared-library dependency
 * resolves.
 *
 * Artifact: ZCL_SYMBOL_FLOOR_BIN, else build/bin/zclassic23 (relative to the
 * working directory, which is the repository root under make).
 * Exit: 0 PASS · 2 SKIP (ldd absent, the only SKIP) · 1 FAIL (a floor
 * exceeded, an unresolved dependency, or an unparseable artifact). Every
 * internal error is FAIL, never SKIP: lintc's die() returns 2, so this gate
 * does not use it.
 * The parser lives in gate_ci_symbol_floor_elf.c; --selftest in
 * gate_ci_symbol_floor_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_ci_symbol_floor_priv.h"

/* The documented portability floor. Raise it only on purpose: that drops
 * support for older distributions. */
static const char k_csf_default[] = "build/bin/zclassic23";
static const char k_csf_floor[] = "2.38";
static const char k_csf_nf[] = "not found";

extern char **environ;

static void csf_reap(pid_t pid)
{
    int st;
    for (;;) {
        if (waitpid(pid, &st, 0) >= 0 || errno != EINTR)
            return;
    }
}

/* Spawn `ldd bin` with stdout on a pipe and stderr on /dev/null. On success
 * *fd is the read end and *pid the child. 0 ok, 1 ldd absent, -1 error. */
static int csf_spawn_ldd(const char *bin, int *fd, pid_t *pid)
{
    int p[2];
    if (pipe(p) != 0)
        return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    char *av[] = { (char *)"ldd", (char *)bin, NULL };
    int err = posix_spawnp(pid, "ldd", &fa, NULL, av, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(p[1]);
    if (err != 0) {
        close(p[0]);
        return err == ENOENT ? 1 : -1;
    }
    *fd = p[0];
    return 0;
}

/* Count occurrences of "not found" in a stream. The match runs over bytes,
 * so a split across buffer boundaries cannot hide one. -1 on a read error. */
static int csf_count_nf(FILE *f, int *count)
{
    size_t j = 0, n = sizeof k_csf_nf - 1;
    int c;
    *count = 0;
    while ((c = fgetc(f)) != EOF) {
        if (c == k_csf_nf[j]) {
            if (++j == n) {
                (*count)++;
                j = 0;
            }
        } else {
            j = c == k_csf_nf[0] ? 1 : 0;
        }
    }
    return ferror(f) ? -1 : 0;
}

/* The number of unresolved dependencies ldd reports for bin. ldd's own exit
 * status is not consulted, as in the script. 0 ok, 1 ldd absent, -1 error. */
static int csf_ldd_missing(const char *bin, int *missing)
{
    int fd = -1, rc;
    pid_t pid;
    rc = csf_spawn_ldd(bin, &fd, &pid);
    if (rc != 0)
        return rc;
    FILE *f = fdopen(fd, "r");
    if (!f) {
        close(fd);
        csf_reap(pid);
        return -1;
    }
    rc = csf_count_nf(f, missing);
    fclose(f);
    csf_reap(pid);
    return rc;
}

/* The GLIBC family must stay at or below the floor. */
static int csf_check_glibc(const struct csf_fam *g)
{
    char max[CSF_VER + 16];
    snprintf(max, sizeof max, "GLIBC_%s", g->max);
    if (csf_vcmp(g->max, k_csf_floor) <= 0) {
        printf("ci-symbol-floor: GLIBC max required = %s  <= floor GLIBC_%s  (OK)\n",
               max, k_csf_floor);
        return 0;
    }
    fprintf(stderr, "ci-symbol-floor: FAIL: GLIBC max required = %s EXCEEDS "
            "documented floor GLIBC_%s — this raises the clean-OS portability "
            "floor; either lower the build's symbol use or deliberately bump the "
            "floor in tools/lint/lintc/gate_ci_symbol_floor.c\n", max, k_csf_floor);
    return 1;
}

/* A C++ ABI family present at all is a failure: this node links no C++
 * runtime. */
static int csf_forbidden(const char *label, const struct csf_fam *f)
{
    if (!f->present)
        return 0;
    fprintf(stderr, "ci-symbol-floor: FAIL: forbidden C++ ABI family required "
            "by C23 node: %s%s\n", label, f->max);
    return 1;
}

/* Parse the artifact's version tables and judge them. Any unreadable or
 * unparseable artifact, or one with no GLIBC symbols, is refused. */
static int csf_elf_check(const char *bin)
{
    struct csf_floor fl;
    struct csf_src s;
    off_t end = 0;
    FILE *f = fopen(bin, "rb");
    if (!f) {
        fprintf(stderr, "ci-symbol-floor: FAIL: binary not readable: %s\n", bin);
        return 1;
    }
    if (fseeko(f, 0, SEEK_END) != 0 || (end = ftello(f)) < 0) {
        fclose(f);
        fprintf(stderr, "ci-symbol-floor: FAIL: cannot size %s\n", bin);
        return 1;
    }
    s.f = f;
    s.mem = NULL;
    s.size = (uint64_t)end;
    int bad = csf_scan(&s, &fl);
    fclose(f);
    if (bad || !fl.glibc.present) {
        fprintf(stderr, "ci-symbol-floor: FAIL: no GLIBC symbols found in %s — "
                "not a parseable dynamically-linked ELF (refusing to PASS a "
                "garbage artifact)\n", bin);
        return 1;
    }
    if (csf_check_glibc(&fl.glibc) != 0)
        return 1;
    if (csf_forbidden("GLIBCXX_", &fl.glibcxx) || csf_forbidden("CXXABI_", &fl.cxxabi))
        return 1;
    printf("=== ci-symbol-floor: PASSED (GLIBC_%s honored; no C++ ABI; all deps "
           "resolve) ===\n", k_csf_floor);
    return 0;
}

int check_ci_symbol_floor_run(int argc, char **argv)
{
    (void)argv;
    if (argc > 0) {
        fprintf(stderr, "check-ci-symbol-floor: takes no arguments; the artifact "
                "is ZCL_SYMBOL_FLOOR_BIN\n");
        return 1;
    }
    const char *bin = getenv("ZCL_SYMBOL_FLOOR_BIN");
    if (!bin || !*bin)
        bin = k_csf_default;
    FILE *probe = fopen(bin, "rb");
    if (!probe) {
        fprintf(stderr, "ci-symbol-floor: FAIL: binary not found/readable: %s\n", bin);
        return 1;
    }
    fclose(probe);
    int missing = 0;
    int rc = csf_ldd_missing(bin, &missing);
    if (rc == 1) {
        printf("ci-symbol-floor: SKIP (ldd absent)\n");
        return 2;
    }
    if (rc != 0) {
        fprintf(stderr, "ci-symbol-floor: FAIL: ldd could not inspect %s\n", bin);
        return 1;
    }
    if (missing > 0) {
        fprintf(stderr, "ci-symbol-floor: FAIL: %d shared-lib dependency(ies) "
                "unresolved (ldd '=> not found')\n", missing);
        return 1;
    }
    return csf_elf_check(bin);
}
