/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the ELF probe's private cross-TU contract — the on-disk ELF64
 * encoding it enforces, the bounded-access primitives every read goes
 * through, and the dynamic string/hash table readers built on them.
 *
 * hotswap_elf_probe.c owns the WALK: whole-image read, PT_LOAD vaddr
 * mapping, the PT_DYNAMIC and section-header passes, the pre-map admission
 * policy, and the single `return true` at the bottom of the probe.
 * hotswap_elf_probe_tables.c owns the TABLE READS the walk asks for: a
 * bounded string fetch and compare out of .dynstr, and the two ways .dynsym's
 * entry count is derived (DT_HASH's nchain, DT_GNU_HASH's bucket + chain
 * walk). The split happened when the combined file passed the 800-line shape
 * ceiling. These declarations are all that crosses that seam, so they live
 * here and nowhere else — nothing outside those two translation units may
 * include this header.
 *
 * struct img and at() stay INLINE here rather than becoming a call across the
 * seam so that the invariant stated at at() still holds literally: every
 * dereference on either side of the split is one bounds check against ONE
 * known length, with no second copy of that check anywhere.
 */

#ifndef ZCL_HOTSWAP_ELF_PROBE_INTERNAL_H
#define ZCL_HOTSWAP_ELF_PROBE_INTERNAL_H

#include "base/serialize_le.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── on-disk ELF64 constants (little-endian x86-64 shared object only) ────
 * Spelled out here rather than pulled from <elf.h> so the values this parser
 * enforces are visible in the file that enforces them. */

#define EI_NIDENT_       16
#define ELFCLASS64_      2
#define ELFDATA2LSB_     1
#define EV_CURRENT_      1
#define ET_DYN_          3
#define EM_X86_64_       62

#define EHDR64_SIZE      64
#define PHDR64_SIZE      56
#define SHDR64_SIZE      64
#define DYN64_SIZE       16
#define SYM64_SIZE       24

#define PT_LOAD_         1
#define PT_DYNAMIC_      2

#define SHT_NOBITS_      8
#define SHT_INIT_ARRAY_  14
#define SHT_FINI_ARRAY_  15
#define SHT_PREINIT_ARRAY_ 16

#define SHN_UNDEF_       0
#define SHN_LORESERVE_   0xff00u

#define DT_NULL_             0
#define DT_NEEDED_           1
#define DT_HASH_             4
#define DT_STRTAB_           5
#define DT_SYMTAB_           6
#define DT_STRSZ_            10
#define DT_SYMENT_           11
#define DT_INIT_             12
#define DT_FINI_             13
#define DT_RPATH_            15
#define DT_INIT_ARRAY_       25
#define DT_FINI_ARRAY_       26
#define DT_INIT_ARRAYSZ_     27
#define DT_FINI_ARRAYSZ_     28
#define DT_RUNPATH_          29
#define DT_PREINIT_ARRAY_    32
#define DT_PREINIT_ARRAYSZ_  33
#define DT_GNU_HASH_         0x6ffffef5u

/* The pointer width the initialiser arrays are measured in. This parser only
 * ever accepts ELF64, so it is 8 by construction, not by host sizeof(). */
#define ELF64_PTR_SIZE   8u

/* Bound on the DT_GNU_HASH chain walk. The chain is a linked structure with
 * an attacker-chosen terminator bit, so the walk needs a hard iteration cap
 * on top of its bounds checks or a crafted table spins until the file ends. */
#define GNU_HASH_MAX_BUCKETS  (1u << 20)
#define GNU_HASH_MAX_MASKWORDS (1u << 16)

/* ── image + bounded access ─────────────────────────────────────────────── */

struct img {
    const unsigned char *b;
    uint64_t n;
};

/* THE bounds check. Every dereference in this file goes through here.
 * Written to be overflow-proof without relying on wraparound: `len > n` is
 * tested first so `n - len` cannot underflow, and `off > n - len` is the
 * addition-free form of `off + len > n`. */
static inline const unsigned char *at(const struct img *im, uint64_t off, uint64_t len)
{
    if (len > im->n)
        return NULL;
    if (off > im->n - len)
        return NULL;
    return im->b + off;
}

/* Fixed-width little-endian reads come from platform/modules/base, not from a private
 * shift loop: check-byte-order-codec-single requires one codec in the tree,
 * and the helpers there are memcpy-based, so they keep exactly the property
 * this parser needs — an unaligned, attacker-chosen offset can never create
 * an alignment fault or an aliasing hazard. Every call is still bounds-checked
 * by at() before the pointer reaches these. */
static inline uint16_t rd16(const unsigned char *p)
{
    return zcl_read_u16_le((const uint8_t *)p);
}

static inline uint32_t rd32(const unsigned char *p)
{
    return zcl_read_u32_le((const uint8_t *)p);
}

static inline uint64_t rd64(const unsigned char *p)
{
    return zcl_read_u64_le((const uint8_t *)p);
}

/* ── the table reads (hotswap_elf_probe_tables.c) ───────────────────────── */

/* Copies the NUL-terminated string at `idx` within [stroff, stroff+strsz)
 * into `dst`. See the definition for the terminated-vs-truncated contract. */
bool dynstr_copy(const struct img *im, uint64_t stroff, uint64_t strsz,
                 uint64_t idx, char *dst, size_t dst_cap, bool *truncated);

/* Compares the dynamic-string-table entry at `idx` to `want` without copying
 * it anywhere. */
bool dynstr_equals(const struct img *im, uint64_t stroff, uint64_t strsz,
                   uint64_t idx, const char *want);

/* The two ways .dynsym's entry count is derived — the same two the dynamic
 * linker uses, never the section header. */
bool dynsym_count_from_hash(const struct img *im, uint64_t hash_off,
                            uint64_t *out_count);
bool dynsym_count_from_gnu_hash(const struct img *im, uint64_t gh_off,
                                uint64_t *out_count);

#endif /* ZCL_HOTSWAP_ELF_PROBE_INTERNAL_H */
