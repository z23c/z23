/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: The riscv64-link case of the check-object-reproducible gate: a
 * freestanding riscv64 FreeBSD program (the tracked fixture OR_XLINK_SRC) is
 * compiled with the cross compiler and linked with the cross linker (--xld,
 * mold on the build host; there is no lld there), and the gate compares the
 * SHA-256 of the two executables built under two checkout roots. This file
 * builds and runs the two steps, resolves the linker and checks that the
 * output is an ELF64 little-endian RISC-V ET_EXEC. The case table, the
 * verdict, the RED control (the same build without the prefix map must
 * differ) and the missing-tool refusal are shared with the other link case in
 * gate_object_reproducible.c. Split out only to keep each file under the
 * 1500-line ceiling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "gate_object_reproducible_priv.h"

enum {
    OR_ELF_CLASS64 = 2,
    OR_ELF_LE = 1,
    OR_ET_EXEC = 2,
    OR_EM_RISCV = 243,
};

/* Compile the fixture (as C, whatever its suffix) to hello.o. */
static bool or_xlink_compile_cmd(const struct or_ctx *x, const char *root,
                                 bool prefix_map, struct or_cmd *c)
{
    const struct or_cfg *cfg = x->cfg;
    return or_add(c, x->cc) && (!x->target[0] || or_add(c, x->target))
           && or_add_words(c, cfg, cfg->base, cfg->tree, true)
           && or_add(c, "-c")
           && or_add_words(c, cfg, cfg->xcc, cfg->tree, true)
           && or_add_words(c, cfg, cfg->repro, root, prefix_map)
           && or_add(c, "-x") && or_add(c, "c") && or_add(c, OR_XLINK_SRC)
           && or_add(c, "-o") && or_add(c, "hello.o");
}

/* Link hello.o to hello with the cross linker and its Makefile argv. */
static bool or_xlink_link_cmd(const struct or_ctx *x, struct or_cmd *c)
{
    return or_add(c, x->xldbuf[0] ? x->xldbuf : x->cfg->xld)
           && or_add_words(c, x->cfg, x->cfg->xld_flags, x->cfg->tree, true)
           && or_add(c, "-o") && or_add(c, "hello") && or_add(c, "hello.o");
}

/* Step 0 is the compile, step 1 the link. */
bool or_xlink_cmd(const struct or_ctx *x, const char *root, int step,
                  bool prefix_map, struct or_cmd *c)
{
    c->n = 0;
    return or_seal(c, step == 0 ? or_xlink_compile_cmd(x, root, prefix_map, c)
                                : or_xlink_link_cmd(x, c));
}

/* In the root as working directory: compile, link, read hello. Each output
 * is deleted first, so a step that fails or writes nothing cannot be
 * satisfied by a leftover. */
unsigned char *or_xlink_build(const struct or_ctx *x, const char *root,
                              bool prefix_map, struct or_cmd *c, char *diag,
                              size_t *len)
{
    static const char *const out[OR_XLINK_STEPS] = { "hello.o", "hello" };
    int tmo_ms = 0;
    for (int st = 0; st < OR_XLINK_STEPS; st++) {
        if ((unlink(out[st]) != 0 && errno != ENOENT)
            || !or_xlink_cmd(x, root, st, prefix_map, c)
            || !or_run_compiler(c, diag, &tmo_ms))
            return NULL;
    }
    return or_read_file("hello", len);
}

/* ELF64, little endian, ET_EXEC, EM_RISCV; sections and headers in bounds. */
bool or_xlink_elf_ok(const unsigned char *b, size_t len)
{
    if (!or_elf_linked(b, len) || len < 20)
        return false;
    return b[4] == OR_ELF_CLASS64 && b[5] == OR_ELF_LE
           && (b[16] | (b[17] << 8)) == OR_ET_EXEC
           && (b[18] | (b[19] << 8)) == OR_EM_RISCV;
}

/* Resolve and hash the cross linker. -1: go on; else the case's result: the
 * linker is missing (skipped by name when allowed) or unreadable (a refusal,
 * always). */
int or_xlink_tool(struct or_ctx *x)
{
    const char *want = x->cfg->xld;
    if (!or_find_exe(want, x->xldbuf, sizeof x->xldbuf)) {
        x->xldbuf[0] = '\0'; /* the failed search may leave a partial path */
        return or_case_missing(x, want, "linker");
    }
    if (or_hash_file(x->xldbuf, x->xldsha))
        return -1;
    printf("check-object-reproducible: REFUSED LINKER_UNREADABLE: case %s: "
           "%s was found but could not be read and hashed", x->cs->name,
           x->xldbuf);
    return OR_REFUSED;
}
