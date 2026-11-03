/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-ci-symbol-floor gate
 * (gate_ci_symbol_floor*.c). The ELF version-table reader works on a byte
 * source that is either a FILE or an in-memory image, so the selftest can
 * feed it fixtures without touching the disk.
 */
#ifndef GATE_CI_SYMBOL_FLOOR_PRIV_H
#define GATE_CI_SYMBOL_FLOOR_PRIV_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
    CSF_MAXSEC = 4096,   /* section headers a binary may carry */
    CSF_MAXVER = 4096,   /* verneed / verdef entries walked per section */
    CSF_NAME = 128,      /* one version name, prefix included */
    CSF_VER = 64         /* one dotted version token */
};

/* A byte source: a FILE (size known) or an in-memory image. */
struct csf_src {
    FILE *f;
    const unsigned char *mem;
    uint64_t size;
};

/* One symbol-version family (GLIBC_, GLIBCXX_, CXXABI_): the highest
 * dotted version the binary requires or defines in that family. */
struct csf_fam {
    int present;
    char max[CSF_VER];   /* dotted numeric part, e.g. "2.38" */
};

struct csf_floor {
    struct csf_fam glibc;
    struct csf_fam glibcxx;
    struct csf_fam cxxabi;
};

/* Read n bytes at off. 0 ok, -1 out of range or unreadable. */
int csf_read_at(const struct csf_src *s, uint64_t off, unsigned char *buf,
                size_t n);

/* Walk the ELF64/ELF32 section table and collect every version name in the
 * SHT_GNU_verneed and SHT_GNU_verdef sections. 0 ok, 1 not a parseable ELF
 * (bad magic, bad table, out-of-range offset, over-long name). */
int csf_scan(const struct csf_src *s, struct csf_floor *out);

/* Compare dotted numeric versions like sort -V: -1, 0 or 1. */
int csf_vcmp(const char *a, const char *b);

#endif
