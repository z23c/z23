/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — ELF fact extraction from a descriptor, before any map.
 *
 * See hotswap/hotswap_elf_probe.h for WHY this exists (dlsym-after-dlopen
 * means constructors have already run before admission), for what it does and
 * does not prove, and for the ⛔ init_array baseline trap.
 *
 * ── WHY THIS PARSES BY BYTE OFFSET AND NOT VIA <elf.h> ─────────────────────
 * Nothing here includes <elf.h> or casts the image to Elf64_Ehdr. The input
 * is hostile and unaligned by construction: a pointer cast into a malloc'd
 * image is a strict-aliasing and alignment hazard the moment an attacker
 * picks the offsets, and struct layouts are a promise the compiler makes to
 * us, not a promise the FILE makes. Every field is loaded with an explicit
 * little-endian byte read from a bounds-checked slice, so the on-disk
 * encoding is stated in this file rather than inherited from a header. The
 * spec-mandated offsets are written next to each read.
 *
 * ── WHY THE WHOLE FILE IS READ INTO ONE BUFFER ─────────────────────────────
 * Every bounds check in this file is `off + len <= image.n` against ONE known
 * length. The alternative — a pread per field — spreads that invariant across
 * dozens of call sites, and one forgotten check is a read of hostile bytes.
 * The single allocation is the only attacker-influenced size in the file and
 * it is hard-capped at ZCL_HOTSWAP_ELF_PROBE_MAX_FILE_BYTES before malloc is
 * ever called. No other allocation happens: every table is walked in place,
 * and every enumeration is bounded by a compile-time cap.
 *
 * ── FAIL CLOSED ────────────────────────────────────────────────────────────
 * The public probe returns success only after every structure has been
 * validated. Every other exit runs through fail(),
 * which zeroes *out and writes a reason. A malformed file can therefore never
 * be mistaken for a file that legitimately claims nothing.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "hotswap/hotswap_elf_probe.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include "hotswap/hotswap_module.h"

#include "hotswap_elf_probe_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

static bool fail(struct hotswap_elf_facts *out, char *err, size_t err_cap,
                 const char *fmt, ...)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (err && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        (void)vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return false;
}

#if !defined(_WIN32)

/* The on-disk ELF64 constants, `struct img`, and the bounded-access
 * primitives at()/rd16()/rd32()/rd64() live in
 * hotswap_elf_probe_internal.h, shared with the table reads in
 * hotswap_elf_probe_tables.c. */

/* Reads the descriptor's full contents into a fresh buffer. Returns NULL and
 * fills `why` on any refusal.
 *
 * S_ISREG is REQUIRED, deliberately. A character device (/dev/null, /dev/zero)
 * or a pipe has no meaningful size to bound reads against, and /dev/zero would
 * otherwise read forever. "Not a regular file" is a refusal with a reason, not
 * a special case. */
static unsigned char *read_all(int fd, uint64_t *out_len, char *why, size_t why_cap)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        (void)snprintf(why, why_cap, "fstat failed (errno %d)", errno);
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        (void)snprintf(why, why_cap, "not a regular file");
        return NULL;
    }
    if (st.st_size <= 0) {
        (void)snprintf(why, why_cap, "empty file");
        return NULL;
    }
    uint64_t size = (uint64_t)st.st_size;
    if (size > ZCL_HOTSWAP_ELF_PROBE_MAX_FILE_BYTES) {
        (void)snprintf(why, why_cap,
                       "file is %llu bytes, over the %llu byte probe ceiling",
                       (unsigned long long)size,
                       (unsigned long long)ZCL_HOTSWAP_ELF_PROBE_MAX_FILE_BYTES);
        return NULL;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        (void)snprintf(why, why_cap, "cannot seek to start (errno %d)", errno);
        return NULL;
    }
    unsigned char *buf = zcl_malloc((size_t)size, "hotswap-elf-probe-image");
    if (!buf) {
        (void)snprintf(why, why_cap, "out of memory for a %llu byte image",
                       (unsigned long long)size);
        return NULL;
    }
    uint64_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buf + got, (size_t)(size - got));
        if (n > 0) {
            got += (uint64_t)n;
            continue;
        }
        if (n == 0)
            break; /* short: the file shrank under us — refused below */
        if (errno == EINTR)
            continue;
        (void)snprintf(why, why_cap, "read failed at offset %llu (errno %d)",
                       (unsigned long long)got, errno);
        free(buf);
        return NULL;
    }
    if (got != size) {
        /* The file changed size between fstat and read. Parsing a partial
         * image would mean reporting facts about bytes that no longer
         * describe the artifact. Refuse. */
        (void)snprintf(why, why_cap,
                       "short read: %llu of %llu bytes (file changed under the probe)",
                       (unsigned long long)got, (unsigned long long)size);
        free(buf);
        return NULL;
    }
    *out_len = size;
    return buf;
}

/* ── vaddr -> file offset, through PT_LOAD only ─────────────────────────── */

/* Converts a virtual address the file's own structures refer to into a file
 * offset, exactly the way the dynamic linker's segment mapping does: find the
 * PT_LOAD whose [p_vaddr, p_vaddr + p_filesz) window contains the whole
 * requested range.
 *
 * p_filesz, not p_memsz, on purpose: the tail between filesz and memsz is
 * .bss, which has NO file bytes. A hostile file pointing a symbol into that
 * gap must not be resolved to some arbitrary offset — it has no on-disk
 * value, and a request landing there is refused by returning false.
 *
 * A range that straddles two segments is also refused rather than stitched:
 * the linker would map those to non-adjacent addresses, so a stitched read
 * would not be what the process sees. */
bool vaddr_to_off(const struct img *im, const unsigned char *phtab,
                         uint16_t phnum, uint64_t vaddr, uint64_t len,
                         uint64_t *out_off)
{
    if (len == 0)
        return false;
    for (uint16_t i = 0; i < phnum; i++) {
        const unsigned char *ph = phtab + (size_t)i * PHDR64_SIZE;
        if (rd32(ph + 0) != PT_LOAD_)
            continue;
        uint64_t p_offset = rd64(ph + 8);
        uint64_t p_vaddr  = rd64(ph + 16);
        uint64_t p_filesz = rd64(ph + 32);
        if (vaddr < p_vaddr)
            continue;
        uint64_t delta = vaddr - p_vaddr;
        if (len > p_filesz || delta > p_filesz - len)
            continue; /* not wholly inside this segment's FILE bytes */
        /* p_offset + p_filesz was already proven <= im->n when the program
         * headers were validated, so this cannot overflow or escape. */
        uint64_t off = p_offset + delta;
        if (!at(im, off, len))
            return false; /* belt and braces; unreachable given the above */
        *out_off = off;
        return true;
    }
    return false;
}

/* A local IRELATIVE resolver is called by ld.so while applying relocations,
 * before dlopen returns. Inspect both the ordinary and PLT RELA tables. */
static bool rela_has_irelative(const struct img *im,
                               const unsigned char *phtab, uint16_t phnum,
                               uint64_t vaddr, uint64_t size,
                               uint64_t symcount, bool *found)
{
    if (size == 0) return true;
    if (size > im->n || size % RELA64_SIZE != 0) return false;
    uint64_t off = 0;
    if (!vaddr_to_off(im, phtab, phnum, vaddr, size, &off)) return false;
    const unsigned char *rela = at(im, off, size);
    if (!rela) return false;
    for (uint64_t i = 0; i < size; i += RELA64_SIZE) {
        uint64_t info = rd64(rela + i + 8);
        if ((info >> 32) >= symcount) return false;
        if ((uint32_t)info == R_X86_64_IRELATIVE_)
            *found = true;
    }
    return true;
}

struct reloc_dynamic {
    uint64_t rela, relasz, relaent, jmprel, pltrelsz, pltrel;
    bool have_rela, have_relasz, have_relaent;
    bool have_jmprel, have_pltrelsz, have_pltrel;
};

static bool reloc_unique(uint64_t *slot, bool *seen, uint64_t value)
{
    if (*seen) return false;
    *slot = value;
    *seen = true;
    return true;
}

static bool reloc_dynamic_tag(struct reloc_dynamic *r,
                              uint64_t tag, uint64_t value)
{
    switch (tag) {
    case DT_RELA_:
        return reloc_unique(&r->rela, &r->have_rela, value);
    case DT_RELASZ_:
        return reloc_unique(&r->relasz, &r->have_relasz, value);
    case DT_RELAENT_:
        return reloc_unique(&r->relaent, &r->have_relaent, value);
    case DT_JMPREL_:
        return reloc_unique(&r->jmprel, &r->have_jmprel, value);
    case DT_PLTRELSZ_:
        return reloc_unique(&r->pltrelsz, &r->have_pltrelsz, value);
    case DT_PLTREL_:
        return reloc_unique(&r->pltrel, &r->have_pltrel, value);
    case DT_REL_:
    case DT_RELSZ_:
    case DT_RELENT_:
        return false; /* unsupported table could hide a resolver */
    default:
        return true;
    }
}

static bool reloc_dynamic_inspect(const struct img *im,
                                  const unsigned char *phtab, uint16_t phnum,
                                  const struct reloc_dynamic *r,
                                  uint64_t symcount, bool *found)
{
    if (r->have_rela != r->have_relasz ||
        r->have_rela != r->have_relaent ||
        (r->have_rela && r->relaent != RELA64_SIZE))
        return false;
    if (r->have_rela && !rela_has_irelative(
            im, phtab, phnum, r->rela, r->relasz, symcount, found))
        return false;
    if (r->have_jmprel != r->have_pltrelsz ||
        r->have_jmprel != r->have_pltrel ||
        (r->have_jmprel && r->pltrel != DT_RELA_))
        return false;
    if (r->have_jmprel && !rela_has_irelative(
            im, phtab, phnum, r->jmprel, r->pltrelsz, symcount, found))
        return false;
    return true;
}

static const char *dynamic_segment_reason(bool present, uint64_t size)
{
    if (!present)
        return "no PT_DYNAMIC segment: not a dynamically linked shared object";
    if (size == 0 || size % DYN64_SIZE != 0)
        return "PT_DYNAMIC size is not a positive multiple of 16";
    return NULL;
}

static const char *relocation_reason(
    const struct img *im, const unsigned char *phtab, uint16_t phnum,
    const struct reloc_dynamic *reloc, uint64_t symcount, bool *irelative)
{
    if (!reloc_dynamic_inspect(im, phtab, phnum, reloc, symcount, irelative))
        return "relocation tables are incomplete, unsupported, or out of bounds";
    return NULL;
}

/* ── section header cross-check ─────────────────────────────────────────── */

/* Validates the section header table and, where it overlaps the dynamic
 * segment's account of the same region, requires the two to AGREE.
 *
 * This is not defensive redundancy. tools/dev/hotswap-package.sh, nm, readelf
 * and gdb all describe an artifact through section headers; ld.so describes
 * it through PT_DYNAMIC. A file that sets .init_array's sh_size to 8 while
 * DT_INIT_ARRAYSZ says 800 shows one constructor to every auditor and runs a
 * hundred. Refusing that disagreement is the whole point.
 *
 * `dyn_off` is the file offset of PT_DYNAMIC, used only for a sanity read of
 * the section name table; the array sizes come in via the two *_sz arguments
 * as read from the dynamic segment. */
static bool sections_agree(const struct img *im, const unsigned char *shtab,
                           uint32_t shnum, uint32_t shstrndx,
                           uint64_t dyn_init_array, uint64_t dyn_init_off,
                           uint64_t dyn_init_arraysz,
                           uint64_t dyn_fini_array, uint64_t dyn_fini_off,
                           uint64_t dyn_fini_arraysz,
                           uint64_t dyn_preinit_array, uint64_t dyn_preinit_off,
                           uint64_t dyn_preinit_arraysz,
                           struct hotswap_elf_facts *out,
                           char *err, size_t err_cap)
{
    /* Locate the section header string table so section names can be read.
     * shstrndx == SHN_UNDEF means "no names"; that is legal ELF but it means
     * the section table cannot be cross-checked at all, which is exactly the
     * state a deceptive file would choose. Refuse. */
    if (shstrndx == SHN_UNDEF_ || shstrndx >= shnum)
        return fail(out, err, err_cap,
                    "section header string table index %u is absent or out of range (shnum %u)",
                    shstrndx, shnum);

    const unsigned char *shstr_sh = shtab + (size_t)shstrndx * SHDR64_SIZE;
    uint64_t shstr_off  = rd64(shstr_sh + 24);
    uint64_t shstr_size = rd64(shstr_sh + 32);
    if (rd32(shstr_sh + 4) == SHT_NOBITS_ || !at(im, shstr_off, shstr_size))
        return fail(out, err, err_cap,
                    "section name table at offset %llu size %llu is out of bounds",
                    (unsigned long long)shstr_off, (unsigned long long)shstr_size);

    bool saw_init_array = false, saw_fini_array = false;
    bool saw_preinit_array = false;
    uint64_t sh_init_addr = 0, sh_init_off = 0, sh_init_arraysz = 0;
    uint64_t sh_fini_addr = 0, sh_fini_off = 0, sh_fini_arraysz = 0;
    uint64_t sh_preinit_addr = 0, sh_preinit_off = 0;
    uint64_t sh_preinit_arraysz = 0;

    for (uint32_t i = 0; i < shnum; i++) {
        const unsigned char *sh = shtab + (size_t)i * SHDR64_SIZE;
        uint32_t sh_name   = rd32(sh + 0);
        uint32_t sh_type   = rd32(sh + 4);
        uint64_t sh_addr   = rd64(sh + 16);
        uint64_t sh_offset = rd64(sh + 24);
        uint64_t sh_size   = rd64(sh + 32);

        /* SHT_NOBITS (.bss and friends) occupies no file bytes, so its
         * sh_offset is not a range to validate. Everything else must lie
         * wholly inside the file. Section 0 is the reserved null entry and is
         * all zeroes; at(im, 0, 0) is fine for it. */
        if (sh_type != SHT_NOBITS_ && sh_size != 0 && !at(im, sh_offset, sh_size))
            return fail(out, err, err_cap,
                        "section header %u claims offset %llu size %llu, past the %llu byte file",
                        i, (unsigned long long)sh_offset,
                        (unsigned long long)sh_size, (unsigned long long)im->n);

        char name[32];
        bool trunc = false;
        if (!dynstr_copy(im, shstr_off, shstr_size, sh_name, name, sizeof(name), &trunc)) {
            /* Section 0's sh_name is 0, which indexes the leading NUL of a
             * well-formed name table and copies as "". A failure here means
             * the index is out of range or the name never terminates. */
            return fail(out, err, err_cap,
                        "section header %u has an unreadable name (index %u into a %llu byte name table)",
                        i, sh_name, (unsigned long long)shstr_size);
        }
        if (!trunc && strcmp(name, ".init_array") == 0) {
            if (saw_init_array)
                return fail(out, err, err_cap,
                            "more than one .init_array section");
            if (sh_type != SHT_INIT_ARRAY_)
                return fail(out, err, err_cap,
                            ".init_array has section type %u, want %u",
                            sh_type, SHT_INIT_ARRAY_);
            saw_init_array = true;
            sh_init_addr = sh_addr;
            sh_init_off = sh_offset;
            sh_init_arraysz = sh_size;
        } else if (!trunc && strcmp(name, ".fini_array") == 0) {
            if (saw_fini_array)
                return fail(out, err, err_cap,
                            "more than one .fini_array section");
            if (sh_type != SHT_FINI_ARRAY_)
                return fail(out, err, err_cap,
                            ".fini_array has section type %u, want %u",
                            sh_type, SHT_FINI_ARRAY_);
            saw_fini_array = true;
            sh_fini_addr = sh_addr;
            sh_fini_off = sh_offset;
            sh_fini_arraysz = sh_size;
        } else if (!trunc && strcmp(name, ".preinit_array") == 0) {
            if (saw_preinit_array)
                return fail(out, err, err_cap,
                            "more than one .preinit_array section");
            if (sh_type != SHT_PREINIT_ARRAY_)
                return fail(out, err, err_cap,
                            ".preinit_array has section type %u, want %u",
                            sh_type, SHT_PREINIT_ARRAY_);
            saw_preinit_array = true;
            sh_preinit_addr = sh_addr;
            sh_preinit_off = sh_offset;
            sh_preinit_arraysz = sh_size;
        }
    }

    if (saw_init_array &&
        (sh_init_addr != dyn_init_array || sh_init_off != dyn_init_off ||
         sh_init_arraysz != dyn_init_arraysz))
        return fail(out, err, err_cap,
                    "section .init_array (addr 0x%llx off %llu size %llu) "
                    "disagrees with dynamic array (addr 0x%llx off %llu size %llu)",
                    (unsigned long long)sh_init_addr,
                    (unsigned long long)sh_init_off,
                    (unsigned long long)sh_init_arraysz,
                    (unsigned long long)dyn_init_array,
                    (unsigned long long)dyn_init_off,
                    (unsigned long long)dyn_init_arraysz);
    if (!saw_init_array && dyn_init_arraysz != 0)
        return fail(out, err, err_cap,
                    "DT_INIT_ARRAYSZ is %llu but there is no .init_array section "
                    "(constructors hidden from every section-header reader)",
                    (unsigned long long)dyn_init_arraysz);
    if (saw_fini_array &&
        (sh_fini_addr != dyn_fini_array || sh_fini_off != dyn_fini_off ||
         sh_fini_arraysz != dyn_fini_arraysz))
        return fail(out, err, err_cap,
                    "section .fini_array disagrees with its dynamic pointer/size");
    if (!saw_fini_array && dyn_fini_arraysz != 0)
        return fail(out, err, err_cap,
                    "DT_FINI_ARRAYSZ is %llu but there is no .fini_array section",
                    (unsigned long long)dyn_fini_arraysz);
    if (saw_preinit_array &&
        (sh_preinit_addr != dyn_preinit_array ||
         sh_preinit_off != dyn_preinit_off ||
         sh_preinit_arraysz != dyn_preinit_arraysz))
        return fail(out, err, err_cap,
                    "section .preinit_array disagrees with its dynamic pointer/size");
    if (!saw_preinit_array && dyn_preinit_arraysz != 0)
        return fail(out, err, err_cap,
                    "DT_PREINIT_ARRAYSZ is %llu but there is no .preinit_array section",
                    (unsigned long long)dyn_preinit_arraysz);

    return true;
}

/* ── the probe ──────────────────────────────────────────────────────────── */

struct elf_probe_state {
    struct img im;
    uint64_t n;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint64_t dyn_off;
    uint64_t dyn_size;
    uint64_t dyn_vaddr;
    uint64_t d_symtab;
    uint64_t d_strtab;
    uint64_t d_strsz;
    uint64_t d_syment;
    uint64_t d_hash;
    uint64_t d_gnu_hash;
    uint64_t d_init_array;
    uint64_t d_fini_array;
    uint64_t d_preinit_array;
    uint64_t d_init_arraysz;
    uint64_t d_fini_arraysz;
    uint64_t d_preinit_arraysz;
    uint64_t d_init_off;
    uint64_t d_fini_off;
    uint64_t d_preinit_off;
    uint64_t stroff;
    uint64_t symcount;
    uint64_t needed_idx[ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED];
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
    bool have_dyn;
    bool have_symtab;
    bool have_strtab;
    bool have_strsz;
    bool have_syment;
    bool have_hash;
    bool have_gnu_hash;
    bool have_init_array;
    bool have_fini_array;
    bool have_preinit_array;
    bool have_init_arraysz;
    bool have_fini_arraysz;
    bool have_preinit_arraysz;
    bool seen_seal;
    bool seen_abi;
    const unsigned char *phtab;
    const unsigned char *dyn;
    const unsigned char *symtab;
    struct reloc_dynamic reloc;
    size_t needed_seen;
    size_t err_cap;
    struct hotswap_elf_facts *out;
    char *err;
};

/* Format errors while the image is live; the caller owns its release. */
#define REFUSE(...) return fail(s->out, s->err, s->err_cap, __VA_ARGS__)

static bool elf_dynamic_symbol_tag(struct elf_probe_state *s, uint64_t tag, uint64_t val, bool *handled)
{
    switch (tag) {
    case DT_NEEDED_:
        if (s->out->needed_count < ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED)
            s->needed_idx[s->needed_seen++] = val;
        else
            s->out->needed_truncated = true;
        s->out->needed_count++;
        break;
    case DT_SYMTAB_:
        if (s->have_symtab) REFUSE("duplicate DT_SYMTAB");
        s->d_symtab = val; s->have_symtab = true; break;
    case DT_STRTAB_:
        if (s->have_strtab) REFUSE("duplicate DT_STRTAB");
        s->d_strtab = val; s->have_strtab = true; break;
    case DT_STRSZ_:
        if (s->have_strsz) REFUSE("duplicate DT_STRSZ");
        s->d_strsz = val; s->have_strsz = true; break;
    case DT_SYMENT_:
        if (s->have_syment) REFUSE("duplicate DT_SYMENT");
        s->d_syment = val; s->have_syment = true; break;
    case DT_HASH_:
        if (s->have_hash) REFUSE("duplicate DT_HASH");
        s->d_hash = val; s->have_hash = true; break;
    case DT_GNU_HASH_:
        if (s->have_gnu_hash) REFUSE("duplicate DT_GNU_HASH");
        s->d_gnu_hash = val; s->have_gnu_hash = true; break;
    default: *handled = false; break;
    }
    return true;
}

static bool elf_dynamic_initializer_tag(struct elf_probe_state *s, uint64_t tag, uint64_t val, bool *handled)
{
    switch (tag) {
    case DT_INIT_:
        if (s->out->has_dt_init) REFUSE("duplicate DT_INIT");
        s->out->has_dt_init = true; break;
    case DT_FINI_:
        if (s->out->has_dt_fini) REFUSE("duplicate DT_FINI");
        s->out->has_dt_fini = true; break;
    case DT_INIT_ARRAY_:
        if (s->have_init_array)
            REFUSE("duplicate DT_INIT_ARRAY");
        s->d_init_array = val; s->have_init_array = true; break;
    case DT_FINI_ARRAY_:
        if (s->have_fini_array)
            REFUSE("duplicate DT_FINI_ARRAY");
        s->d_fini_array = val; s->have_fini_array = true; break;
    case DT_PREINIT_ARRAY_:
        if (s->have_preinit_array)
            REFUSE("duplicate DT_PREINIT_ARRAY");
        s->d_preinit_array = val; s->have_preinit_array = true; break;
    default: *handled = false; break;
    }
    return true;
}

static bool elf_dynamic_auxiliary_tag(struct elf_probe_state *s, uint64_t tag, uint64_t val)
{
    switch (tag) {
    case DT_INIT_ARRAYSZ_:
        if (s->have_init_arraysz) REFUSE("duplicate DT_INIT_ARRAYSZ");
        s->d_init_arraysz = val; s->have_init_arraysz = true; break;
    case DT_FINI_ARRAYSZ_:
        if (s->have_fini_arraysz) REFUSE("duplicate DT_FINI_ARRAYSZ");
        s->d_fini_arraysz = val; s->have_fini_arraysz = true; break;
    case DT_PREINIT_ARRAYSZ_:
        if (s->have_preinit_arraysz) REFUSE("duplicate DT_PREINIT_ARRAYSZ");
        s->d_preinit_arraysz = val; s->have_preinit_arraysz = true; break;
    case DT_RPATH_:
    case DT_RUNPATH_:
        if (s->out->has_runpath)
            REFUSE("duplicate or combined DT_RPATH/DT_RUNPATH");
        s->out->has_runpath = true;
        break;
    default:
        if (!reloc_dynamic_tag(&s->reloc, tag, val))
            REFUSE("malformed or unsupported relocation dynamic tag %llu",
                   (unsigned long long)tag);
        break;
    }
    return true;
}

static bool elf_seal(struct elf_probe_state *s, uint64_t st_value, uint64_t st_size)
{
    /* The symbol is `const char zcl_hotswap_module_core_seal_root[]`
     * initialised from ZCL_CORE_SEAL_ROOT: 64 hex characters plus the
     * terminating NUL, so st_size is 65 in every artifact measured.
     * Require at least that much rather than exactly it, so a future
     * longer pin does not silently break the read — but validate the
     * SHAPE of the 65 bytes we take, because a caller will
     * string-compare this value against the resident's own seal. */
    if (st_size < 65)
        REFUSE("%s has st_size %llu, too small for 64 hex characters plus NUL",
               ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL,
               (unsigned long long)st_size);
    uint64_t off = 0;
    if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, st_value, 65, &off))
        REFUSE("%s at vaddr 0x%llx has no file bytes (points outside every PT_LOAD's file range)",
               ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL,
               (unsigned long long)st_value);
    const unsigned char *p = at(&s->im, off, 65);
    if (!p)
        REFUSE("%s contents out of bounds",
               ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    for (int k = 0; k < 64; k++) {
        unsigned char c = p[k];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex)
            REFUSE("%s byte %d is 0x%02x, not a lowercase hex digit",
                   ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL, k, c);
    }
    if (p[64] != '\0')
        REFUSE("%s is not NUL-terminated at 64 characters (byte 64 is 0x%02x)",
               ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL, p[64]);
    memcpy(s->out->core_seal_root, p, 64);
    s->out->core_seal_root[64] = '\0';
    s->out->core_seal_root_present = true;

    return true;
}

static bool elf_abi(struct elf_probe_state *s, uint64_t st_value, uint64_t st_size)
{
    /* struct zcl_hotswap_module's FIRST named member is
     * `uint32_t abi_version`, and C puts the first member at offset 0
     * with no leading padding. That is the only layout fact that does
     * not depend on the compiler, so reading 4 little-endian bytes at
     * the symbol's own address is a precise read of that field and
     * not a struct parser that could drift. Same reasoning, and the
     * same lockstep-with-hotswap_module.h caveat, as
     * tools/dev/hotswap-package.sh. */
    if (st_size < 4)
        REFUSE("%s has st_size %llu, too small to hold abi_version",
               ZCL_HOTSWAP_MODULE_SYMBOL, (unsigned long long)st_size);
    uint64_t off = 0;
    if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, st_value, 4, &off))
        REFUSE("%s at vaddr 0x%llx has no file bytes",
               ZCL_HOTSWAP_MODULE_SYMBOL, (unsigned long long)st_value);
    const unsigned char *p = at(&s->im, off, 4);
    if (!p)
        REFUSE("%s contents out of bounds", ZCL_HOTSWAP_MODULE_SYMBOL);
    s->out->abi_version = rd32(p);
    s->out->abi_version_present = true;
    return true;
}

static bool elf_undefined(struct elf_probe_state *s, uint64_t i, uint32_t st_name, bool is_seal, bool is_abi)
{
    if (is_seal || is_abi)
        REFUSE("identity symbol '%s' is undefined",
               is_seal ? ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL
                       : ZCL_HOTSWAP_MODULE_SYMBOL);
    /* st_name == 0 is the reserved null symbol at index 0, and any
     * other unnamed entry; neither is an import from the host. */
    if (st_name != 0) {
        size_t imported = s->out->undefined_symbol_count;
        s->out->undefined_symbol_count++;
        if (imported < ZCL_HOTSWAP_ELF_PROBE_MAX_UNDEFINED) {
            bool trunc = false;
            if (!dynstr_copy(
                    &s->im, s->stroff, s->d_strsz, st_name,
                    s->out->undefined_symbols[imported],
                    ZCL_HOTSWAP_ELF_PROBE_SYMBOL_NAME_CAP, &trunc))
                REFUSE("undefined symbol %llu has an unreadable name",
                       (unsigned long long)i);
            if (trunc)
                s->out->undefined_symbols_truncated = true;
        } else {
            s->out->undefined_symbols_truncated = true;
        }
    }
    return true;
}

static bool elf_symbol(struct elf_probe_state *s, uint64_t i)
{
    const unsigned char *sy = s->symtab + (size_t)(i * SYM64_SIZE);
    uint32_t st_name  = rd32(sy + 0);
    s->out->ifunc_symbol_count +=
        (size_t)((sy[4] & 0x0fu) == STT_GNU_IFUNC_);
    uint16_t st_shndx = rd16(sy + 6);
    uint64_t st_value = rd64(sy + 8);
    uint64_t st_size  = rd64(sy + 16);

    /* An st_name outside the dynamic string table is malformed — no
     * linker emits one — and silently skipping such an entry would let a
     * hostile file hide a symbol from this walk by pointing its name off
     * the end. Refuse instead of ignoring. */
    if (st_name >= s->d_strsz)
        REFUSE("dynamic symbol %llu has name index %u, past the %llu byte string table",
               (unsigned long long)i, st_name, (unsigned long long)s->d_strsz);

    bool is_seal = dynstr_equals(
        &s->im, s->stroff, s->d_strsz, st_name,
        ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    bool is_abi = dynstr_equals(
        &s->im, s->stroff, s->d_strsz, st_name, ZCL_HOTSWAP_MODULE_SYMBOL);
    if (is_seal) {
        if (s->seen_seal)
            REFUSE("duplicate %s dynamic symbol",
                   ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
        s->seen_seal = true;
    }
    if (is_abi) {
        if (s->seen_abi)
            REFUSE("duplicate %s dynamic symbol",
                   ZCL_HOTSWAP_MODULE_SYMBOL);
        s->seen_abi = true;
    }

    if (st_shndx == SHN_UNDEF_) return elf_undefined(s, i, st_name, is_seal, is_abi);
    /* A defined symbol in the reserved index range (SHN_ABS, SHN_COMMON,
     * ...) has an st_value that is not a virtual address, so it can never
     * be one of the two identity objects we read bytes out of. */
    if (st_shndx >= SHN_LORESERVE_) {
        if (is_seal || is_abi)
            REFUSE("identity symbol '%s' has reserved section index %u",
                   is_seal ? ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL
                           : ZCL_HOTSWAP_MODULE_SYMBOL,
                   st_shndx);
        return true;
    }

    if (is_seal) return elf_seal(s, st_value, st_size);
    if (is_abi) return elf_abi(s, st_value, st_size);
    return true;
}

static bool elf_header(struct elf_probe_state *s)
{
    /* ── ELF identification, before any table is walked ────────────────── */
    const unsigned char *eh = at(&s->im, 0, EHDR64_SIZE);
    if (!eh)
        REFUSE("file is %llu bytes, shorter than a 64 byte ELF64 header",
               (unsigned long long)s->n);
    if (!(eh[0] == 0x7f && eh[1] == 'E' && eh[2] == 'L' && eh[3] == 'F'))
        REFUSE("not an ELF file (magic %02x %02x %02x %02x)",
               eh[0], eh[1], eh[2], eh[3]);
    if (eh[4] != ELFCLASS64_)
        REFUSE("not ELF64 (EI_CLASS %u)", eh[4]);
    if (eh[5] != ELFDATA2LSB_)
        REFUSE("not little-endian (EI_DATA %u)", eh[5]);
    if (eh[6] != EV_CURRENT_)
        REFUSE("unsupported ELF ident version %u", eh[6]);

    uint16_t e_type = rd16(eh + 16);
    uint16_t e_machine = rd16(eh + 18);
    uint32_t e_version = rd32(eh + 20);
    s->e_phoff = rd64(eh + 32);
    s->e_shoff = rd64(eh + 40);
    uint16_t e_ehsize = rd16(eh + 52);
    s->e_phentsize = rd16(eh + 54);
    s->e_phnum = rd16(eh + 56);
    s->e_shentsize = rd16(eh + 58);
    s->e_shnum = rd16(eh + 60);
    s->e_shstrndx = rd16(eh + 62);

    if (e_type != ET_DYN_)
        REFUSE("not a shared object (e_type %u, want ET_DYN %u)", e_type, ET_DYN_);
    if (e_machine != EM_X86_64_)
        REFUSE("not x86-64 (e_machine %u, want %u)", e_machine, EM_X86_64_);
    if (e_version != EV_CURRENT_)
        REFUSE("unsupported ELF version %u", e_version);
    if (e_ehsize != EHDR64_SIZE)
        REFUSE("e_ehsize %u, want %u", e_ehsize, EHDR64_SIZE);

    return true;
}

static bool elf_programs(struct elf_probe_state *s)
{
    /* ── program headers ───────────────────────────────────────────────── */
    if (s->e_phnum == 0)
        REFUSE("no program headers: a shared object with nothing to map");
    if (s->e_phentsize != PHDR64_SIZE)
        REFUSE("e_phentsize %u, want %u", s->e_phentsize, PHDR64_SIZE);
    if (s->e_phnum > ZCL_HOTSWAP_ELF_PROBE_MAX_PHNUM)
        REFUSE("e_phnum %u exceeds the %u program header cap",
               s->e_phnum, ZCL_HOTSWAP_ELF_PROBE_MAX_PHNUM);
    s->phtab = at(&s->im, s->e_phoff, (uint64_t)s->e_phnum * PHDR64_SIZE);
    if (!s->phtab)
        REFUSE("program header table at offset %llu (%u x %u bytes) is past the %llu byte file",
               (unsigned long long)s->e_phoff, s->e_phnum, PHDR64_SIZE,
               (unsigned long long)s->n);

    return true;
}

static bool elf_program_segments(struct elf_probe_state *s)
{
    /* Validate every loadable segment's file range up front. vaddr_to_off()
     * relies on this having been done: it adds a within-segment delta to
     * p_offset and would otherwise have to re-derive the same bound. */
    for (uint16_t i = 0; i < s->e_phnum; i++) {
        const unsigned char *ph = s->phtab + (size_t)i * PHDR64_SIZE;
        uint32_t p_type   = rd32(ph + 0);
        uint64_t p_offset = rd64(ph + 8);
        uint64_t p_vaddr  = rd64(ph + 16);
        uint64_t p_filesz = rd64(ph + 32);
        uint64_t p_memsz  = rd64(ph + 40);
        if (p_type == PT_LOAD_ || p_type == PT_DYNAMIC_) {
            if (!at(&s->im, p_offset, p_filesz))
                REFUSE("program header %u (type %u) claims offset %llu size %llu, past the %llu byte file",
                       i, p_type, (unsigned long long)p_offset,
                       (unsigned long long)p_filesz, (unsigned long long)s->n);
        }
        if (p_type == PT_LOAD_) {
            if (p_filesz > p_memsz)
                REFUSE("PT_LOAD %u has p_filesz %llu > p_memsz %llu", i,
                       (unsigned long long)p_filesz, (unsigned long long)p_memsz);
            if (p_vaddr > UINT64_MAX - p_memsz)
                REFUSE("PT_LOAD %u vaddr range overflows", i);
        }
        if (p_type == PT_DYNAMIC_) {
            if (s->have_dyn)
                REFUSE("more than one PT_DYNAMIC segment");
            s->dyn_off   = p_offset;
            s->dyn_size  = p_filesz;
            s->dyn_vaddr = p_vaddr;
            s->have_dyn  = true;
        }
    }
    return true;
}

static bool elf_program_dynamic(struct elf_probe_state *s)
{
    const char *dynamic_problem = dynamic_segment_reason(s->have_dyn, s->dyn_size);
    if (dynamic_problem)
        REFUSE("%s", dynamic_problem);
    if (s->dyn_size / DYN64_SIZE > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNAMIC)
        REFUSE("PT_DYNAMIC holds %llu entries, over the %u cap",
               (unsigned long long)(s->dyn_size / DYN64_SIZE),
               ZCL_HOTSWAP_ELF_PROBE_MAX_DYNAMIC);

    /* PT_DYNAMIC carries BOTH a file offset and a virtual address. The linker
     * reaches it through the vaddr; readelf -d reaches it through the offset.
     * If those two do not name the same bytes, the file is again describing
     * itself differently to the auditor and to the loader. Require agreement. */
    {
        uint64_t mapped = 0;
        if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->dyn_vaddr, s->dyn_size, &mapped))
            REFUSE("PT_DYNAMIC vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)s->dyn_vaddr);
        if (mapped != s->dyn_off)
            REFUSE("PT_DYNAMIC p_offset %llu disagrees with its vaddr-mapped offset %llu",
                   (unsigned long long)s->dyn_off, (unsigned long long)mapped);
    }

    return true;
}

static bool elf_dynamic(struct elf_probe_state *s)
{
    /* ── walk the dynamic array ────────────────────────────────────────── */
    s->dyn = at(&s->im, s->dyn_off, s->dyn_size);
    if (!s->dyn)
        REFUSE("PT_DYNAMIC contents out of bounds"); /* unreachable; kept explicit */

    /* DT_NEEDED holds string-table INDICES, and the string table's location
     * arrives as another dynamic tag that may appear later in the array. So
     * the needed indices are collected in this pass and resolved to names in
     * a second pass, once DT_STRTAB/DT_STRSZ are known. The array is
     * fixed-size and never attacker-sized; overflow past it only sets
     * needed_truncated. */

    uint64_t nent = s->dyn_size / DYN64_SIZE;
    bool saw_null = false;
    for (uint64_t i = 0; i < nent; i++) {
        const unsigned char *d = s->dyn + (size_t)(i * DYN64_SIZE);
        uint64_t tag = rd64(d + 0);
        uint64_t val = rd64(d + 8);
        if (tag == DT_NULL_) {
            saw_null = true;
            break;
        }
        bool handled = true;
        if (!elf_dynamic_symbol_tag(s, tag, val, &handled)) return false;
        if (!handled) {
            handled = true;
            if (!elf_dynamic_initializer_tag(s, tag, val, &handled)) return false;
            if (!handled && !elf_dynamic_auxiliary_tag(s, tag, val)) return false;
        }
    }
    if (!saw_null)
        REFUSE("the dynamic array has no DT_NULL terminator within PT_DYNAMIC");

    return true;
}

static bool elf_arrays(struct elf_probe_state *s)
{
    /* An array size without its array pointer (or vice versa) is incoherent;
     * one of the two is a lie and there is no way to tell which. */
    if (s->have_init_array != s->have_init_arraysz ||
        (s->have_init_array && s->d_init_arraysz == 0))
        REFUSE("DT_INIT_ARRAY and DT_INIT_ARRAYSZ disagree about whether an init array exists");
    if (s->have_fini_array != s->have_fini_arraysz ||
        (s->have_fini_array && s->d_fini_arraysz == 0))
        REFUSE("DT_FINI_ARRAY and DT_FINI_ARRAYSZ disagree about whether a fini array exists");
    if (s->have_preinit_array != s->have_preinit_arraysz ||
        (s->have_preinit_array && s->d_preinit_arraysz == 0))
        REFUSE("DT_PREINIT_ARRAY and DT_PREINIT_ARRAYSZ disagree about whether a preinit array exists");

    /* A size that is not a whole number of 8-byte function pointers cannot be
     * what the linker will iterate. Refuse rather than round. */
    if (s->d_init_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_INIT_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)s->d_init_arraysz, ELF64_PTR_SIZE);
    if (s->d_fini_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_FINI_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)s->d_fini_arraysz, ELF64_PTR_SIZE);
    if (s->d_preinit_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_PREINIT_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)s->d_preinit_arraysz, ELF64_PTR_SIZE);
    return true;
}

static bool elf_array_maps(struct elf_probe_state *s)
{
    /* Each array must fit in the file where it claims to live; an array that
     * does not map is a count nobody can substantiate. */
    if (s->d_init_arraysz > s->n || s->d_fini_arraysz > s->n || s->d_preinit_arraysz > s->n)
        REFUSE("an initialiser array is larger than the whole %llu byte file",
               (unsigned long long)s->n);

    if (s->d_init_arraysz != 0 &&
        !vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_init_array,
                      s->d_init_arraysz, &s->d_init_off))
        REFUSE("DT_INIT_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)s->d_init_array,
               (unsigned long long)s->d_init_arraysz);
    if (s->d_fini_arraysz != 0 &&
        !vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_fini_array,
                      s->d_fini_arraysz, &s->d_fini_off))
        REFUSE("DT_FINI_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)s->d_fini_array,
               (unsigned long long)s->d_fini_arraysz);
    if (s->d_preinit_arraysz != 0 &&
        !vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_preinit_array,
                      s->d_preinit_arraysz, &s->d_preinit_off))
        REFUSE("DT_PREINIT_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)s->d_preinit_array,
               (unsigned long long)s->d_preinit_arraysz);

    s->out->init_array_entries    = (size_t)(s->d_init_arraysz / ELF64_PTR_SIZE);
    s->out->fini_array_entries    = (size_t)(s->d_fini_arraysz / ELF64_PTR_SIZE);
    s->out->preinit_array_entries = (size_t)(s->d_preinit_arraysz / ELF64_PTR_SIZE);

    return true;
}

static bool elf_strings(struct elf_probe_state *s)
{
    /* ── string table ──────────────────────────────────────────────────── */
    if (!s->have_strtab || !s->have_strsz)
        REFUSE("no DT_STRTAB/DT_STRSZ: the dynamic string table is missing");
    if (s->d_strsz == 0)
        REFUSE("DT_STRSZ is zero");
    if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_strtab, s->d_strsz, &s->stroff))
        REFUSE("DT_STRTAB vaddr 0x%llx size %llu is not covered by any PT_LOAD's file bytes",
               (unsigned long long)s->d_strtab, (unsigned long long)s->d_strsz);

    /* Resolve the DT_NEEDED names now that the string table is located. */
    for (size_t i = 0; i < s->needed_seen; i++) {
        bool trunc = false;
        if (!dynstr_copy(&s->im, s->stroff, s->d_strsz, s->needed_idx[i], s->out->needed[i],
                         ZCL_HOTSWAP_ELF_PROBE_NEEDED_NAME_CAP, &trunc))
            REFUSE("DT_NEEDED[%zu] names string index %llu, which is out of range or unterminated",
                   i, (unsigned long long)s->needed_idx[i]);
        if (trunc)
            s->out->needed_truncated = true;
    }

    return true;
}

static bool elf_symcount(struct elf_probe_state *s)
{
    /* ── dynamic symbol table ──────────────────────────────────────────── */
    if (!s->have_symtab)
        REFUSE("no DT_SYMTAB: the dynamic symbol table is missing");
    if (s->d_syment != SYM64_SIZE)
        REFUSE("DT_SYMENT %llu, want %u", (unsigned long long)s->d_syment, SYM64_SIZE);

    if (s->have_hash) {
        /* DT_HASH's value is a virtual address like every other pointer tag,
         * so it is mapped through PT_LOAD before a byte is read. */
        uint64_t hoff = 0;
        if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_hash, 8, &hoff))
            REFUSE("DT_HASH vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)s->d_hash);
        if (!dynsym_count_from_hash(&s->im, hoff, &s->symcount))
            REFUSE("DT_HASH at vaddr 0x%llx does not yield a usable symbol count",
                   (unsigned long long)s->d_hash);
    } else if (s->have_gnu_hash) {
        uint64_t ghoff = 0;
        if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_gnu_hash, 16, &ghoff))
            REFUSE("DT_GNU_HASH vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)s->d_gnu_hash);
        if (!dynsym_count_from_gnu_hash(&s->im, ghoff, &s->symcount))
            REFUSE("DT_GNU_HASH at vaddr 0x%llx is malformed or oversized",
                   (unsigned long long)s->d_gnu_hash);
    } else {
        /* ld.so cannot resolve a single symbol without one of these, so a DSO
         * without either is not loadable anyway — and, more to the point, its
         * symbol table has no stated size, which means we could not enumerate
         * it without trusting a section header. Refuse; fail closed. */
        REFUSE("neither DT_HASH nor DT_GNU_HASH: the dynamic symbol table has no derivable size");
    }

    return true;
}

static bool elf_symtab(struct elf_probe_state *s)
{
    if (s->symcount == 0 || s->symcount > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        REFUSE("dynamic symbol count %llu is zero or over the %u cap",
               (unsigned long long)s->symcount, ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS);
    const char *dynamic_problem = relocation_reason(
        &s->im, s->phtab, s->e_phnum, &s->reloc, s->symcount,
        &s->out->has_irelative_relocation);
    if (dynamic_problem)
        REFUSE("%s", dynamic_problem);

    uint64_t symoff = 0;
    if (!vaddr_to_off(&s->im, s->phtab, s->e_phnum, s->d_symtab, s->symcount * SYM64_SIZE, &symoff))
        REFUSE("DT_SYMTAB vaddr 0x%llx with %llu entries is not covered by any PT_LOAD's file bytes",
               (unsigned long long)s->d_symtab, (unsigned long long)s->symcount);
    s->symtab = at(&s->im, symoff, s->symcount * SYM64_SIZE);
    if (!s->symtab)
        REFUSE("dynamic symbol table out of bounds"); /* unreachable; kept explicit */

    return true;
}

static bool elf_symbols(struct elf_probe_state *s)
{
    s->out->dynamic_symbol_count = (size_t)s->symcount;

    for (uint64_t i = 0; i < s->symcount; i++) {
        if (!elf_symbol(s, i)) return false;
    }

    return true;
}

static bool elf_sections(struct elf_probe_state *s)
{
    /* ── section headers: validate, and require they agree ─────────────── */
    if (s->e_shoff == 0 || s->e_shnum == 0)
        /* A stripped-section DSO still loads, but nothing that inspects it —
         * not readelf, not nm, not tools/dev/hotswap-package.sh — can
         * describe it, and the two-readers-agree check below becomes vacuous.
         * That is exactly the shape a deceptive artifact would choose, so it
         * is refused here even though the linker would accept it.
         * e_shnum == 0 with a nonzero e_shoff additionally means extended
         * section numbering (the real count lives in section 0's sh_size),
         * which is deliberately not supported. */
        REFUSE("no section header table (e_shoff %llu, e_shnum %u); refusing an artifact "
               "no auditing tool can describe",
               (unsigned long long)s->e_shoff, s->e_shnum);
    if (s->e_shentsize != SHDR64_SIZE)
        REFUSE("e_shentsize %u, want %u", s->e_shentsize, SHDR64_SIZE);
    if (s->e_shnum > ZCL_HOTSWAP_ELF_PROBE_MAX_SHNUM)
        REFUSE("e_shnum %u exceeds the %u section header cap",
               s->e_shnum, ZCL_HOTSWAP_ELF_PROBE_MAX_SHNUM);
    const unsigned char *shtab = at(&s->im, s->e_shoff, (uint64_t)s->e_shnum * SHDR64_SIZE);
    if (!shtab)
        REFUSE("section header table at offset %llu (%u x %u bytes) is past the %llu byte file",
               (unsigned long long)s->e_shoff, s->e_shnum, SHDR64_SIZE,
               (unsigned long long)s->n);
    if (!sections_agree(&s->im, shtab, s->e_shnum, s->e_shstrndx,
                        s->d_init_array, s->d_init_off, s->d_init_arraysz,
                        s->d_fini_array, s->d_fini_off, s->d_fini_arraysz,
                        s->d_preinit_array, s->d_preinit_off, s->d_preinit_arraysz,
                        s->out, s->err, s->err_cap)) {
        return false; /* sections_agree already set the error */
    }

    return true;
}

static bool elf_parse(struct elf_probe_state *s)
{
    return elf_header(s) && elf_programs(s) && elf_program_segments(s) &&
           elf_program_dynamic(s) && elf_dynamic(s) && elf_arrays(s) &&
           elf_array_maps(s) && elf_strings(s) && elf_symcount(s) &&
           elf_symtab(s) && elf_symbols(s) && elf_sections(s);
}

#undef REFUSE

bool hotswap_elf_probe_fd(int fd, struct hotswap_elf_facts *out,
                          char *err, size_t err_cap)
{
    if (err && err_cap > 0) err[0] = '\0';
    if (!out) return fail(out, err, err_cap, "no output struct");
    memset(out, 0, sizeof(*out));
    if (fd < 0) return fail(out, err, err_cap, "invalid descriptor");
    char why[160] = {0};
    uint64_t n = 0;
    unsigned char *buf = read_all(fd, &n, why, sizeof(why));
    if (!buf) return fail(out, err, err_cap, "%s", why[0] ? why : "cannot read the artifact");
    struct elf_probe_state state = { .im = { .b = buf, .n = n }, .n = n,
                                     .out = out, .err = err, .err_cap = err_cap };
    bool ok = elf_parse(&state);
    if (!ok) { free(buf); return false; }
    out->file_size = n;
#if defined(__linux__)
    const struct elf_pure_context pure_context = {
        .image = &state.im, .programs = state.phtab, .program_count = state.e_phnum,
        .dynamic = state.dyn, .dynamic_bytes = state.dyn_size, .symbols = state.symtab,
        .symbol_count = state.symcount, .strings_offset = state.stroff,
        .strings_bytes = state.d_strsz,
    };
    out->hotfork_pure_qualified = elf_hotfork_pure_inspect(
        &pure_context, out, &out->hotfork_pure,
        out->hotfork_pure_reason, sizeof(out->hotfork_pure_reason));
#endif
    free(buf);
    if (lseek(fd, 0, SEEK_SET) < 0)
        return fail(out, err, err_cap, "cannot restore the descriptor offset (errno %d)", errno);
    if (err && err_cap > 0) err[0] = '\0';
    return true;
}

#endif

static bool runtime_import_allowed(const char *name)
{
#define HOTSWAP_MODULE_IMPORT(symbol_, group_) \
    if (strcmp(name, (symbol_)) == 0) return true;
#include "../../../engine/composition/hotswap_module_imports.def"
#undef HOTSWAP_MODULE_IMPORT
    return false;
}

static const char *pre_map_early_code_reason(
    const struct hotswap_elf_facts *facts)
{
    if (facts->has_dt_init)
        return "module carries DT_INIT; code would run before admission";
    if (facts->ifunc_symbol_count != 0)
        return "module carries an IFUNC resolver symbol that may run at dlopen";
    if (facts->has_irelative_relocation)
        return "module carries an IRELATIVE resolver relocation that runs at dlopen";
    return NULL;
}

bool hotswap_elf_pre_map_admit(const struct hotswap_elf_facts *facts,
                               const char expected_core_seal_root[65],
                               uint32_t expected_abi,
                               char *err, size_t err_cap)
{
    if (err && err_cap > 0)
        err[0] = '\0';
    if (!facts || !expected_core_seal_root)
        return fail(NULL, err, err_cap, "missing pre-map policy input");

    const char *early_code = pre_map_early_code_reason(facts);
    if (early_code)
        return fail(NULL, err, err_cap, "%s", early_code);
    if (facts->init_array_entries != 0 ||
        facts->preinit_array_entries != 0)
        return fail(NULL, err, err_cap,
                    "module carries pre-map callbacks (.init_array %zu, .preinit_array %zu)",
                    facts->init_array_entries,
                    facts->preinit_array_entries);

    if (facts->has_runpath)
        return fail(NULL, err, err_cap,
                    "module carries DT_RPATH/DT_RUNPATH");
    if (facts->needed_truncated)
        return fail(NULL, err, err_cap,
                    "module dependency list cannot be enumerated exactly");
    static const char *const allowed_needed[] = {
        "libc.so.6", "libm.so.6",
    };
    for (size_t i = 0; i < facts->needed_count; i++) {
        bool allowed = false;
        for (size_t k = 0;
             k < sizeof(allowed_needed) / sizeof(allowed_needed[0]); k++) {
            if (strcmp(facts->needed[i], allowed_needed[k]) == 0) {
                allowed = true;
                break;
            }
        }
        if (!allowed)
            return fail(NULL, err, err_cap,
                        "module depends on unapproved library '%s'",
                        facts->needed[i]);
    }

    if (!facts->core_seal_root_present)
        return fail(NULL, err, err_cap,
                    "module does not export its consensus core seal");
    if (strncmp(facts->core_seal_root, expected_core_seal_root, 65) != 0)
        return fail(NULL, err, err_cap,
                    "module consensus core seal does not match this node");
    if (!facts->abi_version_present)
        return fail(NULL, err, err_cap,
                    "module does not export its ABI descriptor");
    if (facts->abi_version != expected_abi)
        return fail(NULL, err, err_cap,
                    "module ABI %u does not match required ABI %u",
                    facts->abi_version, expected_abi);

    if (facts->undefined_symbols_truncated ||
        facts->undefined_symbol_count > ZCL_HOTSWAP_ELF_PROBE_MAX_UNDEFINED)
        return fail(NULL, err, err_cap,
                    "module import set cannot be enumerated exactly");
    for (size_t i = 0; i < facts->undefined_symbol_count; i++) {
        if (!runtime_import_allowed(facts->undefined_symbols[i]))
            return fail(NULL, err, err_cap,
                        "module imports undeclared resident symbol '%s'",
                        facts->undefined_symbols[i]);
    }
    return true;
}

bool hotswap_elf_probe_and_admit_fd(int fd,
                                    const char expected_core_seal_root[65],
                                    uint32_t expected_abi,
                                    char *err, size_t err_cap)
{
    struct hotswap_elf_facts facts;
    if (!hotswap_elf_probe_fd(fd, &facts, err, err_cap))
        return false;
    return hotswap_elf_pre_map_admit(&facts, expected_core_seal_root,
                                     expected_abi, err, err_cap);
}

bool hotswap_elf_hotfork_pure_fd(int fd,
    struct hotswap_elf_hotfork_pure_facts *out, char *err, size_t err_cap)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out) return fail(NULL, err, err_cap, "pure profile needs output facts");
#if defined(__linux__) && defined(__x86_64__)
    int seals = fcntl(fd, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;
    if (seals < 0 || (seals & required) != required)
        return fail(NULL, err, err_cap, "pure profile requires kernel-sealed image");
    struct hotswap_elf_facts facts;
    if (!hotswap_elf_probe_fd(fd, &facts, err, err_cap)) return false;
    if (!facts.hotfork_pure_qualified)
        return fail(NULL, err, err_cap, "pure HOT_FORK profile: %s",
                    facts.hotfork_pure_reason);
    *out = facts.hotfork_pure;
    return true;
#else
    (void)fd;
    return fail(NULL, err, err_cap, "pure HOT_FORK ELF profile requires Linux x86-64");
#endif
}
