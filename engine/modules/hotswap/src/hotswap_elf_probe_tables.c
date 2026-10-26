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

/* The DT_GNU_HASH header's shape caps, checked before any of its arrays are
 * reached: nonzero bucket and maskword counts under their caps, a power-of-two
 * maskword count, and a first hashed index under the symbol cap. */
static bool gnu_hash_header_shape_ok(uint32_t nbuckets, uint32_t symndx,
                                     uint32_t maskwords)
{
    if (nbuckets == 0 || nbuckets > GNU_HASH_MAX_BUCKETS)
        return false;
    if (maskwords == 0 || maskwords > GNU_HASH_MAX_MASKWORDS)
        return false;
    if ((maskwords & (maskwords - 1u)) != 0)
        return false; /* the bloom filter's mask requires a power of two */
    if (symndx > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        return false;
    return true;
}

/* Scans the bucket array for the highest symbol index any bucket stores, so
 * the chain walk can start at the longest reach. *out_any stays false when
 * every bucket is empty; a head outside [symndx, the symbol cap] cannot occur
 * in a well-formed table. */
static bool gnu_hash_max_bucket_head(const unsigned char *buckets,
                                     uint32_t nbuckets, uint32_t symndx,
                                     uint32_t *out_last, bool *out_any)
{
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
    *out_last = last;
    *out_any = any;
    return true;
}

/* A chain walk step may only step on symbol indices from symndx up to the
 * symbol cap. */
static bool gnu_hash_chain_index_ok(uint32_t idx, uint32_t symndx)
{
    return idx >= symndx && idx <= ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS;
}

/* The terminator index + 1 is the table size, under the same symbol cap as
 * every other symbol count here. */
static bool gnu_hash_count_from_chain_end(uint32_t idx, uint64_t *out_count)
{
    if ((uint64_t)idx + 1u > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        return false;
    *out_count = (uint64_t)idx + 1u;
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

    if (!gnu_hash_header_shape_ok(nbuckets, symndx, maskwords))
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
    if (!gnu_hash_max_bucket_head(buckets, nbuckets, symndx, &last, &any))
        return false;
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
        if (!gnu_hash_chain_index_ok(idx, symndx))
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
    return gnu_hash_count_from_chain_end(idx, out_count);
}

#endif /* !_WIN32 */

#if defined(__linux__)
#include "hotswap/hotfork_capsule.h"
#include <stdio.h>

#define PURE_MAX_RELOCATIONS 7u
#define PURE_MAX_LOADS 16u
#define PURE_STRING_BYTES 256u

struct pure_relocations {
    uint64_t address;
    uint64_t bytes;
    uint64_t fast_count;
    uint64_t pointers[7];
    uint8_t pointer_mask;
    uint8_t hash_tables;
    uint64_t symbol_address;
    uint64_t string_address;
};

static bool pure_error(char *err, size_t cap, const char *reason)
{
    if (err && cap) (void)snprintf(err, cap, "%s", reason);
    return false;
}

static bool pure_tag_error(char *err, size_t cap, const char *reason, uint64_t tag)
{
    if (err && cap)
        (void)snprintf(err, cap, "%s 0x%llx", reason, (unsigned long long)tag);
    return false;
}

/* Permission-qualified range in one file-backed load, never a stitched read. */
static bool pure_range(const struct elf_pure_context *c, uint64_t address,
                       uint64_t bytes, uint32_t required, uint32_t forbidden)
{
    for (uint16_t i = 0; i < c->program_count; i++) {
        const unsigned char *p = c->programs + (size_t)i * PHDR64_SIZE;
        uint64_t start = rd64(p + 16), size = rd64(p + 32);
        uint32_t flags = rd32(p + 4);
        if (rd32(p) != PT_LOAD_ || (flags & required) != required ||
            (flags & forbidden) || address < start || bytes > size)
            continue;
        if (address - start <= size - bytes) return true;
    }
    return false;
}

static bool pure_segment_kind(uint32_t kind)
{
    return kind == PT_LOAD_ || kind == PT_DYNAMIC_ || kind == 4u ||
           kind == 6u || kind == 0x6474e550u || kind == 0x6474e551u ||
           kind == 0x6474e552u;
}

static bool pure_load_flags(const unsigned char *p)
{
    uint32_t flags = rd32(p + 4);
    uint64_t align = rd64(p + 48);
    return rd64(p + 32) && rd64(p + 40) &&
           (flags & 4u) && !(flags & ~7u) && (flags & 3u) != 3u &&
           align && align <= 4096u && !(align & (align - 1u)) &&
           rd64(p + 16) % align == rd64(p + 8) % align;
}

static bool pure_page_conflict(const unsigned char *p, const unsigned char *q)
{
    uint32_t a = rd32(p + 4), b = rd32(q + 4);
    bool mixed = ((a & 1u) && (b & 2u)) || ((b & 1u) && (a & 2u));
    uint64_t start = rd64(p + 16), other = rd64(q + 16);
    uint64_t end = start + rd64(p + 40), other_end = other + rd64(q + 40);
    return mixed && (start >> 12) <= ((other_end - 1u) >> 12) &&
           (other >> 12) <= ((end - 1u) >> 12);
}

static bool pure_loads_disjoint(const struct elf_pure_context *c, uint16_t index)
{
    const unsigned char *p = c->programs + (size_t)index * PHDR64_SIZE;
    uint64_t start = rd64(p + 16), end = start + rd64(p + 40);
    for (uint16_t i = 0; i < index; i++) {
        const unsigned char *q = c->programs + (size_t)i * PHDR64_SIZE;
        if (rd32(q) != PT_LOAD_) continue;
        uint64_t other = rd64(q + 16), other_end = other + rd64(q + 40);
        uint64_t file_start = rd64(p + 8), file_other = rd64(q + 8);
        if (file_start < file_other + rd64(q + 32) &&
            file_other < file_start + rd64(p + 32)) return false;
        if ((start < other_end && other < end) || pure_page_conflict(p, q))
            return false;
    }
    return true;
}

static bool pure_segments(const struct elf_pure_context *c, char *err, size_t cap)
{
    size_t loads = 0;
    for (uint16_t i = 0; i < c->program_count; i++) {
        const unsigned char *p = c->programs + (size_t)i * PHDR64_SIZE;
        uint32_t kind = rd32(p);
        if (!pure_segment_kind(kind))
            return pure_tag_error(err, cap, "unqualified program header or TLS", kind);
        if (kind == 0x6474e551u && (rd32(p + 4) & 1u))
            return pure_error(err, cap, "executable stack");
        if (kind != PT_LOAD_) continue;
        if (++loads > PURE_MAX_LOADS || !pure_load_flags(p) ||
            !pure_loads_disjoint(c, i))
            return pure_error(err, cap, "load bounds, alignment, overlap or W+X");
    }
    return loads > 0 || pure_error(err, cap, "no load segments");
}

static bool pure_surface(const struct elf_pure_context *c,
    const struct hotswap_elf_facts *f, char *err, size_t cap)
{
    if (c->image->b[7] || c->image->b[8] || rd32(c->image->b + 48) ||
        rd64(c->image->b + 24))
        return pure_error(err, cap, "unqualified ELF ABI, flags or entry point");
    if (f->needed_count || f->undefined_symbol_count || f->ifunc_symbol_count ||
        f->has_irelative_relocation)
        return pure_error(err, cap, "imports, DT_NEEDED or resolver");
    if (f->has_dt_init || f->has_dt_fini || f->init_array_entries ||
        f->fini_array_entries || f->preinit_array_entries || f->has_runpath)
        return pure_error(err, cap, "init, fini, preinit or runtime search path");
    return true;
}

static bool pure_sections(const struct elf_pure_context *c, char *err, size_t cap)
{
    uint64_t offset = rd64(c->image->b + 40);
    uint16_t count = rd16(c->image->b + 60);
    const unsigned char *table = at(c->image, offset, (uint64_t)count * SHDR64_SIZE);
    if (!table) return pure_error(err, cap, "section table bounds");
    for (uint16_t i = 0; i < count; i++) {
        const unsigned char *s = table + (size_t)i * SHDR64_SIZE;
        uint32_t kind = rd32(s + 4);
        uint64_t flags = rd64(s + 8);
        if ((flags & 0x400u) || (flags & 5u) == 5u ||
            kind == 14u || kind == 15u || kind == 16u)
            return pure_error(err, cap, "TLS, W+X or callback section");
    }
    return true;
}

static bool pure_dynamic_tag(uint64_t tag, uint64_t value,
                              struct pure_relocations *r)
{
    switch (tag) {
    case DT_RELA_: r->address = value; return true;
    case DT_RELASZ_: r->bytes = value; return true;
    case DT_RELAENT_: return value == 24u;
    case 30u: return value == 8u; /* DF_BIND_NOW only */
    case 0x6ffffffbu: return value == 1u; /* DF_1_NOW only */
    case 0x6ffffff9u: r->fast_count = value; return value <= PURE_MAX_RELOCATIONS;
    case DT_HASH_: case DT_GNU_HASH_: r->hash_tables++; return r->hash_tables == 1;
    case DT_SYMTAB_: r->symbol_address = value; return true;
    case DT_STRTAB_: r->string_address = value; return true;
    case DT_STRSZ_: case DT_SYMENT_: return true;
    default: return false;
    }
}

static bool pure_dynamic(const struct elf_pure_context *c,
                         struct pure_relocations *r, char *err, size_t cap)
{
    if (c->dynamic_bytes / DYN64_SIZE > 32u)
        return pure_error(err, cap, "pure dynamic table exceeds 32 entries");
    for (uint64_t i = 0; i < c->dynamic_bytes / DYN64_SIZE; i++) {
        const unsigned char *d = c->dynamic + (size_t)i * DYN64_SIZE;
        uint64_t tag = rd64(d);
        if (!tag) break;
        for (uint64_t j = 0; j < i; j++)
            if (rd64(c->dynamic + (size_t)j * DYN64_SIZE) == tag)
                return pure_error(err, cap, "duplicate pure dynamic tag");
        if (!pure_dynamic_tag(tag, rd64(d + 8), r))
            return pure_tag_error(err, cap, "unqualified dynamic-loader tag or flags", tag);
    }
    if (!r->address || !r->bytes || r->bytes % 24u ||
        r->bytes / 24u != PURE_MAX_RELOCATIONS ||
        r->fast_count > r->bytes / 24u)
        return pure_error(err, cap, "bounded RELA table required");
    if (!pure_range(c, r->symbol_address, c->symbol_count * SYM64_SIZE, 4u, 3u) ||
        !pure_range(c, r->string_address, c->strings_bytes, 4u, 3u))
        return pure_error(err, cap, "symbol metadata must be bounded read-only data");
    return true;
}

static bool pure_capsule_symbol(const struct elf_pure_context *c,
    const unsigned char *s, struct hotswap_elf_hotfork_pure_facts *out,
    char *err, size_t cap)
{
    if (s[4] != 0x11u || s[5] != 0u || rd16(s + 6) == 0u ||
        rd16(s + 6) >= SHN_LORESERVE_ || out->exported_symbols)
        return pure_error(err, cap, "capsule must be sole global object export");
    uint64_t address = rd64(s + 8), bytes = rd64(s + 16), off = 0;
    if (bytes != sizeof(struct zcl_hotfork_capsule_v1) ||
        !pure_range(c, address, bytes, 6u, 1u) ||
        !vaddr_to_off(c->image, c->programs, c->program_count, address, bytes, &off))
        return pure_error(err, cap, "capsule size or writable descriptor bounds");
    const unsigned char *descriptor = at(c->image, off, bytes);
    uint64_t dynamic_offset = (uint64_t)(c->dynamic - c->image->b);
    if (off < dynamic_offset + c->dynamic_bytes && dynamic_offset < off + bytes)
        return pure_error(err, cap, "capsule overlaps dynamic metadata");
    if (!descriptor || rd32(descriptor) != ZCL_HOTFORK_CAPSULE_ABI_V1 ||
        rd64(descriptor + offsetof(struct zcl_hotfork_capsule_v1, descriptor_size)) != bytes)
        return pure_error(err, cap, "capsule ABI or descriptor size mismatch");
    out->abi_version = ZCL_HOTFORK_CAPSULE_ABI_V1;
    out->descriptor_size = bytes;
    out->descriptor_vaddr = address;
    out->exported_symbols = 1;
    return true;
}

static bool pure_symbols(const struct elf_pure_context *c,
    struct hotswap_elf_hotfork_pure_facts *out, char *err, size_t cap)
{
    static const unsigned char zero_symbol[SYM64_SIZE];
    if (memcmp(c->symbols, zero_symbol, sizeof(zero_symbol)) != 0)
        return pure_error(err, cap, "reserved null symbol is not zero");
    for (uint64_t i = 1; i < c->symbol_count; i++) {
        const unsigned char *s = c->symbols + (size_t)i * SYM64_SIZE;
        if (!dynstr_equals(c->image, c->strings_offset, c->strings_bytes,
                           rd32(s), ZCL_HOTFORK_CAPSULE_SYMBOL))
            return pure_error(err, cap, "unexpected export, TLS or symbol");
        if (!pure_capsule_symbol(c, s, out, err, cap)) return false;
    }
    return out->exported_symbols == 1 ||
           pure_error(err, cap, "missing HOT_FORK capsule export");
}

static bool pure_relocation_unique(const unsigned char *table, uint64_t index,
                                   uint64_t address)
{
    for (uint64_t i = 0; i < index; i++)
        if (rd64(table + (size_t)i * 24u) == address) return false;
    return true;
}

static bool pure_relocation_descriptor(uint64_t address, uint64_t addend,
    const struct hotswap_elf_hotfork_pure_facts *out, struct pure_relocations *r)
{
    if (address < out->descriptor_vaddr ||
        address - out->descriptor_vaddr >= out->descriptor_size) return false;
    uint64_t offset = address - out->descriptor_vaddr;
    if (offset < offsetof(struct zcl_hotfork_capsule_v1, owner_id) ||
        offset % 8u) return false;
    size_t index = (size_t)((offset - offsetof(struct zcl_hotfork_capsule_v1, owner_id)) / 8u);
    if (index >= 7u) return false;
    r->pointers[index] = addend;
    r->pointer_mask |= (uint8_t)(1u << index);
    return true;
}

static bool pure_relocations_read(const struct elf_pure_context *c,
    struct pure_relocations *r, struct hotswap_elf_hotfork_pure_facts *out,
    char *err, size_t cap)
{
    uint64_t offset = 0;
    if (!pure_range(c, r->address, r->bytes, 4u, 3u) ||
        !vaddr_to_off(c->image, c->programs, c->program_count,
                      r->address, r->bytes, &offset))
        return pure_error(err, cap, "RELA table bounds");
    const unsigned char *table = at(c->image, offset, r->bytes);
    if (!table) return pure_error(err, cap, "RELA table bytes unavailable");
    for (uint64_t i = 0; i < r->bytes / 24u; i++) {
        const unsigned char *entry = table + (size_t)i * 24u;
        uint64_t address = rd64(entry), addend = rd64(entry + 16);
        if (rd64(entry + 8) != 8u || address % 8u ||
            !pure_range(c, address, 8u, 6u, 1u) ||
            !pure_range(c, addend, 1u, 4u, 0u) ||
            !pure_relocation_unique(table, i, address) ||
            !pure_relocation_descriptor(address, addend, out, r))
            return pure_error(err, cap, "unqualified RELATIVE relocation or target");
        out->relative_relocations++;
    }
    return r->pointer_mask == 0x7fu ||
           pure_error(err, cap, "capsule pointers lack exact internal relocations");
}

static bool pure_capsule_pointers(const struct elf_pure_context *c,
    const struct pure_relocations *r, char *err, size_t cap)
{
    for (size_t i = 0; i < 6u; i++) {
        uint64_t off = 0;
        if (!vaddr_to_off(c->image, c->programs, c->program_count,
                          r->pointers[i], 1u, &off))
            return pure_error(err, cap, "capsule string pointer bounds");
        uint64_t available = c->image->n - off;
        size_t bound = available < PURE_STRING_BYTES ? (size_t)available : PURE_STRING_BYTES;
        const unsigned char *s = at(c->image, off, bound);
        const unsigned char *end = s ? memchr(s, 0, bound) : NULL;
        if (!end || end == s || !pure_range(c, r->pointers[i],
                (uint64_t)(end - s) + 1u, 4u, 3u))
            return pure_error(err, cap, "capsule strings must be bounded read-only data");
    }
    return pure_range(c, r->pointers[6], 1u, 5u, 2u) ||
           pure_error(err, cap, "story pointer must name internal executable bytes");
}

bool elf_hotfork_pure_inspect(const struct elf_pure_context *c,
    const struct hotswap_elf_facts *generic,
    struct hotswap_elf_hotfork_pure_facts *out, char *err, size_t cap)
{
    struct hotswap_elf_hotfork_pure_facts facts = {0};
    struct pure_relocations relocations = {0};
    if (!pure_surface(c, generic, err, cap) || !pure_segments(c, err, cap) ||
        !pure_sections(c, err, cap) ||
        !pure_dynamic(c, &relocations, err, cap) ||
        !pure_symbols(c, &facts, err, cap) ||
        !pure_relocations_read(c, &relocations, &facts, err, cap) ||
        !pure_capsule_pointers(c, &relocations, err, cap)) return false;
    *out = facts;
    if (err && cap) err[0] = '\0';
    return true;
}
#endif /* __linux__ */
