/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the ELF probe's table reads — a bounded string fetch and compare
 * out of .dynstr, and the two ways .dynsym's entry count is derived.
 *
 * Split out of hotswap_elf_probe.c along the file-size ceiling seam at the
 * boundaries that file already declared with its `── bounded string read out
 * of the dynamic string table ──` and `── dynamic symbol table sizing ──`
 * banners. hotswap_elf_probe.c keeps the walk that calls in here and the
 * refusal path; nothing in this file allocates, and every read still goes
 * through the single at() bounds check in hotswap_elf_probe_internal.h
 * against the one image length. Why this parses by byte offset instead of
 * <elf.h>, and why the whole file is read into one buffer, are stated in
 * hotswap_elf_probe.c's header and apply unchanged here.
 *
 * The `#if !defined(_WIN32)` guard mirrors the one these functions sat inside
 * before the split: on native Windows the probe is a refusal stub, so none of
 * this is compiled there either.
 */

#include "hotswap/hotswap_elf_probe.h"

#include "hotswap_elf_probe_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(_WIN32)

/* ── bounded string read out of the dynamic string table ────────────────── */

/* Copies the NUL-terminated string at `idx` within the [stroff, stroff+strsz)
 * region into `dst`.
 *
 * The terminator must exist INSIDE strsz. A string running to the end of the
 * region without a NUL is a malformed file, not a string to be silently
 * clamped — `*terminated` reports that so the caller can refuse. Truncation
 * into a short dst is a separate, non-fatal outcome reported via
 * `*truncated`, because for DT_NEEDED display names the exact bytes past 63
 * characters do not change any decision. */
bool dynstr_copy(const struct img *im, uint64_t stroff, uint64_t strsz,
                 uint64_t idx, char *dst, size_t dst_cap,
                 bool *truncated)
{
    *truncated = false;
    if (dst_cap == 0)
        return false;
    dst[0] = '\0';
    if (idx >= strsz)
        return false;
    const unsigned char *p = at(im, stroff + idx, strsz - idx);
    if (!p)
        return false;
    uint64_t avail = strsz - idx;
    uint64_t len = 0;
    while (len < avail && p[len] != '\0')
        len++;
    if (len == avail)
        return false; /* no NUL before the string table ends */
    if (len >= dst_cap) {
        memcpy(dst, p, dst_cap - 1);
        dst[dst_cap - 1] = '\0';
        *truncated = true;
        return true;
    }
    memcpy(dst, p, (size_t)len);
    dst[len] = '\0';
    return true;
}

/* Compares the dynamic-string-table entry at `idx` to `want` without copying
 * it anywhere. Used for the two identity symbol names, whose lengths are
 * fixed and known, so a mismatch is decided without touching a byte past the
 * first difference. Returns false on an unterminated string too — the caller
 * treats that as "not this symbol", and the full walk refuses separately if a
 * name it must record cannot be read. */
bool dynstr_equals(const struct img *im, uint64_t stroff, uint64_t strsz,
                   uint64_t idx, const char *want)
{
    if (idx >= strsz)
        return false;
    size_t wlen = strlen(want);
    uint64_t avail = strsz - idx;
    if ((uint64_t)wlen + 1 > avail)
        return false; /* the name plus its NUL cannot fit in what remains */
    const unsigned char *p = at(im, stroff + idx, (uint64_t)wlen + 1);
    if (!p)
        return false;
    return memcmp(p, want, wlen) == 0 && p[wlen] == '\0';
}

/* ── dynamic symbol table sizing ────────────────────────────────────────── */

/* The number of entries in .dynsym is NOT recorded anywhere in the dynamic
 * segment. The dynamic linker derives it from the symbol hash table, and so
 * does this — rather than from the section header, which ld.so never reads
 * and a hostile file can therefore set to anything without affecting how the
 * artifact actually loads.
 *
 * DT_HASH: the second word is nchain, which the ELF spec defines as equal to
 * the symbol table entry count. Exact, one read.
 *
 * DT_GNU_HASH: no count is stored. The highest symbol index reachable is
 * max(buckets[]), and the chain array is walked from there until an entry
 * with bit 0 set marks the end of that bucket's chain; that final index + 1
 * is the table size. Every step is bounds-checked and the walk is capped at
 * ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS iterations so a crafted chain that never
 * sets its terminator bit cannot spin. */
bool dynsym_count_from_hash(const struct img *im, uint64_t hash_off,
                            uint64_t *out_count)
{
    const unsigned char *p = at(im, hash_off, 8);
    if (!p)
        return false;
    uint32_t nchain = rd32(p + 4);
    if (nchain == 0 || nchain > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        return false;
    *out_count = nchain;
    return true;
}

bool dynsym_count_from_gnu_hash(const struct img *im, uint64_t gh_off,
                                uint64_t *out_count)
{
    const unsigned char *h = at(im, gh_off, 16);
    if (!h)
        return false;
    uint32_t nbuckets  = rd32(h + 0);
    uint32_t symndx    = rd32(h + 4);  /* index of the first HASHED symbol */
    uint32_t maskwords = rd32(h + 8);
    /* h + 12 is shift2, unused for sizing. */

    if (nbuckets == 0 || nbuckets > GNU_HASH_MAX_BUCKETS)
        return false;
    if (maskwords == 0 || maskwords > GNU_HASH_MAX_MASKWORDS)
        return false;
    if ((maskwords & (maskwords - 1u)) != 0)
        return false; /* the bloom filter's mask requires a power of two */
    if (symndx > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        return false;

    /* All of these are bounded by the caps above, so the arithmetic cannot
     * overflow 64 bits: 16 + 2^16*8 + 2^20*4 is well under 2^24. */
    uint64_t buckets_off = gh_off + 16 + (uint64_t)maskwords * 8u;
    const unsigned char *buckets = at(im, buckets_off, (uint64_t)nbuckets * 4u);
    if (!buckets)
        return false;
    uint64_t chain_off = buckets_off + (uint64_t)nbuckets * 4u;

    uint32_t last = 0;
    bool any = false;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t v = rd32(buckets + (size_t)i * 4u);
        if (v == 0)
            continue; /* empty bucket */
        if (v < symndx || v > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
            return false; /* a bucket below symndx is structurally impossible */
        if (!any || v > last) {
            last = v;
            any = true;
        }
    }
    if (!any) {
        /* No hashed symbols at all: the table holds exactly the symndx
         * unhashed (local/undefined) entries and nothing more. */
        *out_count = symndx;
        return true;
    }

    /* Walk the chain from the highest bucket head to the end of its chain. */
    uint32_t idx = last;
    for (uint32_t steps = 0; ; steps++) {
        if (steps > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
            return false;
        if (idx < symndx || idx > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
            return false;
        uint64_t coff = chain_off + (uint64_t)(idx - symndx) * 4u;
        const unsigned char *c = at(im, coff, 4);
        if (!c)
            return false;
        uint32_t val = rd32(c);
        if (val & 1u)
            break; /* terminator bit: idx is the last symbol in this chain */
        if (idx == UINT32_MAX)
            return false;
        idx++;
    }
    if ((uint64_t)idx + 1u > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        return false;
    *out_count = (uint64_t)idx + 1u;
    return true;
}

#endif /* !_WIN32 */
