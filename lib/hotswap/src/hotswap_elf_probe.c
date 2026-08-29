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
 * There is exactly one `return true` in this file, at the very bottom, after
 * every structure has been validated. Every other exit runs through fail(),
 * which zeroes *out and writes a reason. A malformed file can therefore never
 * be mistaken for a file that legitimately claims nothing.
 */

#include "hotswap/hotswap_elf_probe.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include "hotswap/hotswap_module.h"

#include "hotswap_elf_probe_internal.h"

#include <errno.h>
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
 * primitives at()/rd16()/rd32()/rd64() now live in
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
static bool vaddr_to_off(const struct img *im, const unsigned char *phtab,
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

bool hotswap_elf_probe_fd(int fd, struct hotswap_elf_facts *out,
                          char *err, size_t err_cap)
{
    if (err && err_cap > 0)
        err[0] = '\0';
    if (!out)
        return fail(out, err, err_cap, "no output struct");
    memset(out, 0, sizeof(*out));
    if (fd < 0)
        return fail(out, err, err_cap, "invalid descriptor");

    char why[160];
    why[0] = '\0';
    uint64_t n = 0;
    unsigned char *buf = read_all(fd, &n, why, sizeof(why));
    if (!buf)
        return fail(out, err, err_cap, "%s", why[0] ? why : "cannot read the artifact");

    struct img im = { .b = buf, .n = n };

/* Every refusal past this point must release the image.
 *
 * ORDER MATTERS AND IS NOT COSMETIC: several refusal messages interpolate
 * bytes read out of the image itself (the ELF magic, an offending seal-root
 * byte). fail() must therefore run — evaluating its arguments — BEFORE the
 * buffer is freed. The obvious spelling, `do { free(buf); return fail(...); }`,
 * is a use-after-free at every such call site; gcc's -Wuse-after-free caught
 * it here, which is precisely the class of bug this parser cannot afford. */
#define REFUSE(...)                                        \
    do {                                                   \
        bool refuse_r_ = fail(out, err, err_cap, __VA_ARGS__); \
        free(buf);                                         \
        buf = NULL;                                        \
        return refuse_r_;                                  \
    } while (0)

    /* ── ELF identification, before any table is walked ────────────────── */
    const unsigned char *eh = at(&im, 0, EHDR64_SIZE);
    if (!eh)
        REFUSE("file is %llu bytes, shorter than a 64 byte ELF64 header",
               (unsigned long long)n);
    if (!(eh[0] == 0x7f && eh[1] == 'E' && eh[2] == 'L' && eh[3] == 'F'))
        REFUSE("not an ELF file (magic %02x %02x %02x %02x)",
               eh[0], eh[1], eh[2], eh[3]);
    if (eh[4] != ELFCLASS64_)
        REFUSE("not ELF64 (EI_CLASS %u)", eh[4]);
    if (eh[5] != ELFDATA2LSB_)
        REFUSE("not little-endian (EI_DATA %u)", eh[5]);
    if (eh[6] != EV_CURRENT_)
        REFUSE("unsupported ELF ident version %u", eh[6]);

    uint16_t e_type      = rd16(eh + 16);
    uint16_t e_machine   = rd16(eh + 18);
    uint32_t e_version   = rd32(eh + 20);
    uint64_t e_phoff     = rd64(eh + 32);
    uint64_t e_shoff     = rd64(eh + 40);
    uint16_t e_ehsize    = rd16(eh + 52);
    uint16_t e_phentsize = rd16(eh + 54);
    uint16_t e_phnum     = rd16(eh + 56);
    uint16_t e_shentsize = rd16(eh + 58);
    uint16_t e_shnum     = rd16(eh + 60);
    uint16_t e_shstrndx  = rd16(eh + 62);

    if (e_type != ET_DYN_)
        REFUSE("not a shared object (e_type %u, want ET_DYN %u)", e_type, ET_DYN_);
    if (e_machine != EM_X86_64_)
        REFUSE("not x86-64 (e_machine %u, want %u)", e_machine, EM_X86_64_);
    if (e_version != EV_CURRENT_)
        REFUSE("unsupported ELF version %u", e_version);
    if (e_ehsize != EHDR64_SIZE)
        REFUSE("e_ehsize %u, want %u", e_ehsize, EHDR64_SIZE);

    /* ── program headers ───────────────────────────────────────────────── */
    if (e_phnum == 0)
        REFUSE("no program headers: a shared object with nothing to map");
    if (e_phentsize != PHDR64_SIZE)
        REFUSE("e_phentsize %u, want %u", e_phentsize, PHDR64_SIZE);
    if (e_phnum > ZCL_HOTSWAP_ELF_PROBE_MAX_PHNUM)
        REFUSE("e_phnum %u exceeds the %u program header cap",
               e_phnum, ZCL_HOTSWAP_ELF_PROBE_MAX_PHNUM);
    const unsigned char *phtab = at(&im, e_phoff, (uint64_t)e_phnum * PHDR64_SIZE);
    if (!phtab)
        REFUSE("program header table at offset %llu (%u x %u bytes) is past the %llu byte file",
               (unsigned long long)e_phoff, e_phnum, PHDR64_SIZE,
               (unsigned long long)n);

    /* Validate every loadable segment's file range up front. vaddr_to_off()
     * relies on this having been done: it adds a within-segment delta to
     * p_offset and would otherwise have to re-derive the same bound. */
    uint64_t dyn_off = 0, dyn_size = 0, dyn_vaddr = 0;
    bool have_dyn = false;
    for (uint16_t i = 0; i < e_phnum; i++) {
        const unsigned char *ph = phtab + (size_t)i * PHDR64_SIZE;
        uint32_t p_type   = rd32(ph + 0);
        uint64_t p_offset = rd64(ph + 8);
        uint64_t p_vaddr  = rd64(ph + 16);
        uint64_t p_filesz = rd64(ph + 32);
        uint64_t p_memsz  = rd64(ph + 40);
        if (p_type == PT_LOAD_ || p_type == PT_DYNAMIC_) {
            if (!at(&im, p_offset, p_filesz))
                REFUSE("program header %u (type %u) claims offset %llu size %llu, past the %llu byte file",
                       i, p_type, (unsigned long long)p_offset,
                       (unsigned long long)p_filesz, (unsigned long long)n);
        }
        if (p_type == PT_LOAD_) {
            if (p_filesz > p_memsz)
                REFUSE("PT_LOAD %u has p_filesz %llu > p_memsz %llu", i,
                       (unsigned long long)p_filesz, (unsigned long long)p_memsz);
            if (p_vaddr > UINT64_MAX - p_memsz)
                REFUSE("PT_LOAD %u vaddr range overflows", i);
        }
        if (p_type == PT_DYNAMIC_) {
            if (have_dyn)
                REFUSE("more than one PT_DYNAMIC segment");
            dyn_off   = p_offset;
            dyn_size  = p_filesz;
            dyn_vaddr = p_vaddr;
            have_dyn  = true;
        }
    }
    if (!have_dyn)
        REFUSE("no PT_DYNAMIC segment: not a dynamically linked shared object");
    if (dyn_size == 0 || dyn_size % DYN64_SIZE != 0)
        REFUSE("PT_DYNAMIC size %llu is not a positive multiple of %u",
               (unsigned long long)dyn_size, DYN64_SIZE);
    if (dyn_size / DYN64_SIZE > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNAMIC)
        REFUSE("PT_DYNAMIC holds %llu entries, over the %u cap",
               (unsigned long long)(dyn_size / DYN64_SIZE),
               ZCL_HOTSWAP_ELF_PROBE_MAX_DYNAMIC);

    /* PT_DYNAMIC carries BOTH a file offset and a virtual address. The linker
     * reaches it through the vaddr; readelf -d reaches it through the offset.
     * If those two do not name the same bytes, the file is again describing
     * itself differently to the auditor and to the loader. Require agreement. */
    {
        uint64_t mapped = 0;
        if (!vaddr_to_off(&im, phtab, e_phnum, dyn_vaddr, dyn_size, &mapped))
            REFUSE("PT_DYNAMIC vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)dyn_vaddr);
        if (mapped != dyn_off)
            REFUSE("PT_DYNAMIC p_offset %llu disagrees with its vaddr-mapped offset %llu",
                   (unsigned long long)dyn_off, (unsigned long long)mapped);
    }

    /* ── walk the dynamic array ────────────────────────────────────────── */
    const unsigned char *dyn = at(&im, dyn_off, dyn_size);
    if (!dyn)
        REFUSE("PT_DYNAMIC contents out of bounds"); /* unreachable; kept explicit */

    uint64_t d_symtab = 0, d_strtab = 0, d_strsz = 0, d_syment = 0;
    uint64_t d_hash = 0, d_gnu_hash = 0;
    uint64_t d_init_array = 0, d_fini_array = 0, d_preinit_array = 0;
    uint64_t d_init_arraysz = 0, d_fini_arraysz = 0, d_preinit_arraysz = 0;
    bool have_symtab = false, have_strtab = false, have_strsz = false;
    bool have_syment = false;
    bool have_hash = false, have_gnu_hash = false;
    bool have_init_array = false, have_fini_array = false, have_preinit_array = false;
    bool have_init_arraysz = false, have_fini_arraysz = false;
    bool have_preinit_arraysz = false;

    /* DT_NEEDED holds string-table INDICES, and the string table's location
     * arrives as another dynamic tag that may appear later in the array. So
     * the needed indices are collected in this pass and resolved to names in
     * a second pass, once DT_STRTAB/DT_STRSZ are known. The array is
     * fixed-size and never attacker-sized; overflow past it only sets
     * needed_truncated. */
    uint64_t needed_idx[ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED];
    size_t needed_seen = 0;

    uint64_t nent = dyn_size / DYN64_SIZE;
    bool saw_null = false;
    for (uint64_t i = 0; i < nent; i++) {
        const unsigned char *d = dyn + (size_t)(i * DYN64_SIZE);
        uint64_t tag = rd64(d + 0);
        uint64_t val = rd64(d + 8);
        if (tag == DT_NULL_) {
            saw_null = true;
            break;
        }
        switch (tag) {
        case DT_NEEDED_:
            if (out->needed_count < ZCL_HOTSWAP_ELF_PROBE_MAX_NEEDED)
                needed_idx[needed_seen++] = val;
            else
                out->needed_truncated = true;
            out->needed_count++;
            break;
        case DT_SYMTAB_:
            if (have_symtab) REFUSE("duplicate DT_SYMTAB");
            d_symtab = val; have_symtab = true; break;
        case DT_STRTAB_:
            if (have_strtab) REFUSE("duplicate DT_STRTAB");
            d_strtab = val; have_strtab = true; break;
        case DT_STRSZ_:
            if (have_strsz) REFUSE("duplicate DT_STRSZ");
            d_strsz = val; have_strsz = true; break;
        case DT_SYMENT_:
            if (have_syment) REFUSE("duplicate DT_SYMENT");
            d_syment = val; have_syment = true; break;
        case DT_HASH_:
            if (have_hash) REFUSE("duplicate DT_HASH");
            d_hash = val; have_hash = true; break;
        case DT_GNU_HASH_:
            if (have_gnu_hash) REFUSE("duplicate DT_GNU_HASH");
            d_gnu_hash = val; have_gnu_hash = true; break;
        case DT_INIT_:
            if (out->has_dt_init) REFUSE("duplicate DT_INIT");
            out->has_dt_init = true; break;
        case DT_FINI_:
            if (out->has_dt_fini) REFUSE("duplicate DT_FINI");
            out->has_dt_fini = true; break;
        case DT_INIT_ARRAY_:
            if (have_init_array)
                REFUSE("duplicate DT_INIT_ARRAY");
            d_init_array = val; have_init_array = true; break;
        case DT_FINI_ARRAY_:
            if (have_fini_array)
                REFUSE("duplicate DT_FINI_ARRAY");
            d_fini_array = val; have_fini_array = true; break;
        case DT_PREINIT_ARRAY_:
            if (have_preinit_array)
                REFUSE("duplicate DT_PREINIT_ARRAY");
            d_preinit_array = val; have_preinit_array = true; break;
        case DT_INIT_ARRAYSZ_:
            if (have_init_arraysz) REFUSE("duplicate DT_INIT_ARRAYSZ");
            d_init_arraysz = val; have_init_arraysz = true; break;
        case DT_FINI_ARRAYSZ_:
            if (have_fini_arraysz) REFUSE("duplicate DT_FINI_ARRAYSZ");
            d_fini_arraysz = val; have_fini_arraysz = true; break;
        case DT_PREINIT_ARRAYSZ_:
            if (have_preinit_arraysz) REFUSE("duplicate DT_PREINIT_ARRAYSZ");
            d_preinit_arraysz = val; have_preinit_arraysz = true; break;
        case DT_RPATH_:
        case DT_RUNPATH_:
            if (out->has_runpath)
                REFUSE("duplicate or combined DT_RPATH/DT_RUNPATH");
            out->has_runpath = true;
            break;
        default:
            break;
        }
    }
    if (!saw_null)
        REFUSE("the dynamic array has no DT_NULL terminator within PT_DYNAMIC");

    /* An array size without its array pointer (or vice versa) is incoherent;
     * one of the two is a lie and there is no way to tell which. */
    if (have_init_array != have_init_arraysz ||
        (have_init_array && d_init_arraysz == 0))
        REFUSE("DT_INIT_ARRAY and DT_INIT_ARRAYSZ disagree about whether an init array exists");
    if (have_fini_array != have_fini_arraysz ||
        (have_fini_array && d_fini_arraysz == 0))
        REFUSE("DT_FINI_ARRAY and DT_FINI_ARRAYSZ disagree about whether a fini array exists");
    if (have_preinit_array != have_preinit_arraysz ||
        (have_preinit_array && d_preinit_arraysz == 0))
        REFUSE("DT_PREINIT_ARRAY and DT_PREINIT_ARRAYSZ disagree about whether a preinit array exists");

    /* A size that is not a whole number of 8-byte function pointers cannot be
     * what the linker will iterate. Refuse rather than round. */
    if (d_init_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_INIT_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)d_init_arraysz, ELF64_PTR_SIZE);
    if (d_fini_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_FINI_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)d_fini_arraysz, ELF64_PTR_SIZE);
    if (d_preinit_arraysz % ELF64_PTR_SIZE != 0)
        REFUSE("DT_PREINIT_ARRAYSZ %llu is not a multiple of %u",
               (unsigned long long)d_preinit_arraysz, ELF64_PTR_SIZE);
    /* Each array must fit in the file where it claims to live; an array that
     * does not map is a count nobody can substantiate. */
    if (d_init_arraysz > n || d_fini_arraysz > n || d_preinit_arraysz > n)
        REFUSE("an initialiser array is larger than the whole %llu byte file",
               (unsigned long long)n);

    uint64_t d_init_off = 0, d_fini_off = 0, d_preinit_off = 0;
    if (d_init_arraysz != 0 &&
        !vaddr_to_off(&im, phtab, e_phnum, d_init_array,
                      d_init_arraysz, &d_init_off))
        REFUSE("DT_INIT_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)d_init_array,
               (unsigned long long)d_init_arraysz);
    if (d_fini_arraysz != 0 &&
        !vaddr_to_off(&im, phtab, e_phnum, d_fini_array,
                      d_fini_arraysz, &d_fini_off))
        REFUSE("DT_FINI_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)d_fini_array,
               (unsigned long long)d_fini_arraysz);
    if (d_preinit_arraysz != 0 &&
        !vaddr_to_off(&im, phtab, e_phnum, d_preinit_array,
                      d_preinit_arraysz, &d_preinit_off))
        REFUSE("DT_PREINIT_ARRAY vaddr 0x%llx size %llu is not covered by PT_LOAD file bytes",
               (unsigned long long)d_preinit_array,
               (unsigned long long)d_preinit_arraysz);

    out->init_array_entries    = (size_t)(d_init_arraysz / ELF64_PTR_SIZE);
    out->fini_array_entries    = (size_t)(d_fini_arraysz / ELF64_PTR_SIZE);
    out->preinit_array_entries = (size_t)(d_preinit_arraysz / ELF64_PTR_SIZE);

    /* ── string table ──────────────────────────────────────────────────── */
    if (!have_strtab || !have_strsz)
        REFUSE("no DT_STRTAB/DT_STRSZ: the dynamic string table is missing");
    if (d_strsz == 0)
        REFUSE("DT_STRSZ is zero");
    uint64_t stroff = 0;
    if (!vaddr_to_off(&im, phtab, e_phnum, d_strtab, d_strsz, &stroff))
        REFUSE("DT_STRTAB vaddr 0x%llx size %llu is not covered by any PT_LOAD's file bytes",
               (unsigned long long)d_strtab, (unsigned long long)d_strsz);

    /* Resolve the DT_NEEDED names now that the string table is located. */
    for (size_t i = 0; i < needed_seen; i++) {
        bool trunc = false;
        if (!dynstr_copy(&im, stroff, d_strsz, needed_idx[i], out->needed[i],
                         ZCL_HOTSWAP_ELF_PROBE_NEEDED_NAME_CAP, &trunc))
            REFUSE("DT_NEEDED[%zu] names string index %llu, which is out of range or unterminated",
                   i, (unsigned long long)needed_idx[i]);
        if (trunc)
            out->needed_truncated = true;
    }

    /* ── dynamic symbol table ──────────────────────────────────────────── */
    if (!have_symtab)
        REFUSE("no DT_SYMTAB: the dynamic symbol table is missing");
    if (d_syment != SYM64_SIZE)
        REFUSE("DT_SYMENT %llu, want %u", (unsigned long long)d_syment, SYM64_SIZE);

    uint64_t symcount = 0;
    if (have_hash) {
        /* DT_HASH's value is a virtual address like every other pointer tag,
         * so it is mapped through PT_LOAD before a byte is read. */
        uint64_t hoff = 0;
        if (!vaddr_to_off(&im, phtab, e_phnum, d_hash, 8, &hoff))
            REFUSE("DT_HASH vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)d_hash);
        if (!dynsym_count_from_hash(&im, hoff, &symcount))
            REFUSE("DT_HASH at vaddr 0x%llx does not yield a usable symbol count",
                   (unsigned long long)d_hash);
    } else if (have_gnu_hash) {
        uint64_t ghoff = 0;
        if (!vaddr_to_off(&im, phtab, e_phnum, d_gnu_hash, 16, &ghoff))
            REFUSE("DT_GNU_HASH vaddr 0x%llx is not covered by any PT_LOAD's file bytes",
                   (unsigned long long)d_gnu_hash);
        if (!dynsym_count_from_gnu_hash(&im, ghoff, &symcount))
            REFUSE("DT_GNU_HASH at vaddr 0x%llx is malformed or oversized",
                   (unsigned long long)d_gnu_hash);
    } else {
        /* ld.so cannot resolve a single symbol without one of these, so a DSO
         * without either is not loadable anyway — and, more to the point, its
         * symbol table has no stated size, which means we could not enumerate
         * it without trusting a section header. Refuse; fail closed. */
        REFUSE("neither DT_HASH nor DT_GNU_HASH: the dynamic symbol table has no derivable size");
    }
    if (symcount == 0 || symcount > ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS)
        REFUSE("dynamic symbol count %llu is zero or over the %u cap",
               (unsigned long long)symcount, ZCL_HOTSWAP_ELF_PROBE_MAX_DYNSYMS);

    uint64_t symoff = 0;
    if (!vaddr_to_off(&im, phtab, e_phnum, d_symtab, symcount * SYM64_SIZE, &symoff))
        REFUSE("DT_SYMTAB vaddr 0x%llx with %llu entries is not covered by any PT_LOAD's file bytes",
               (unsigned long long)d_symtab, (unsigned long long)symcount);
    const unsigned char *symtab = at(&im, symoff, symcount * SYM64_SIZE);
    if (!symtab)
        REFUSE("dynamic symbol table out of bounds"); /* unreachable; kept explicit */

    out->dynamic_symbol_count = (size_t)symcount;

    bool seen_seal = false, seen_abi = false;
    for (uint64_t i = 0; i < symcount; i++) {
        const unsigned char *sy = symtab + (size_t)(i * SYM64_SIZE);
        uint32_t st_name  = rd32(sy + 0);
        uint16_t st_shndx = rd16(sy + 6);
        uint64_t st_value = rd64(sy + 8);
        uint64_t st_size  = rd64(sy + 16);

        /* An st_name outside the dynamic string table is malformed — no
         * linker emits one — and silently skipping such an entry would let a
         * hostile file hide a symbol from this walk by pointing its name off
         * the end. Refuse instead of ignoring. */
        if (st_name >= d_strsz)
            REFUSE("dynamic symbol %llu has name index %u, past the %llu byte string table",
                   (unsigned long long)i, st_name, (unsigned long long)d_strsz);

        bool is_seal = dynstr_equals(
            &im, stroff, d_strsz, st_name,
            ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
        bool is_abi = dynstr_equals(
            &im, stroff, d_strsz, st_name, ZCL_HOTSWAP_MODULE_SYMBOL);
        if (is_seal) {
            if (seen_seal)
                REFUSE("duplicate %s dynamic symbol",
                       ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
            seen_seal = true;
        }
        if (is_abi) {
            if (seen_abi)
                REFUSE("duplicate %s dynamic symbol",
                       ZCL_HOTSWAP_MODULE_SYMBOL);
            seen_abi = true;
        }

        if (st_shndx == SHN_UNDEF_) {
            if (is_seal || is_abi)
                REFUSE("identity symbol '%s' is undefined",
                       is_seal ? ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL
                               : ZCL_HOTSWAP_MODULE_SYMBOL);
            /* st_name == 0 is the reserved null symbol at index 0, and any
             * other unnamed entry; neither is an import from the host. */
            if (st_name != 0) {
                size_t imported = out->undefined_symbol_count;
                out->undefined_symbol_count++;
                if (imported < ZCL_HOTSWAP_ELF_PROBE_MAX_UNDEFINED) {
                    bool trunc = false;
                    if (!dynstr_copy(
                            &im, stroff, d_strsz, st_name,
                            out->undefined_symbols[imported],
                            ZCL_HOTSWAP_ELF_PROBE_SYMBOL_NAME_CAP, &trunc))
                        REFUSE("undefined symbol %llu has an unreadable name",
                               (unsigned long long)i);
                    if (trunc)
                        out->undefined_symbols_truncated = true;
                } else {
                    out->undefined_symbols_truncated = true;
                }
            }
            continue;
        }
        /* A defined symbol in the reserved index range (SHN_ABS, SHN_COMMON,
         * ...) has an st_value that is not a virtual address, so it can never
         * be one of the two identity objects we read bytes out of. */
        if (st_shndx >= SHN_LORESERVE_) {
            if (is_seal || is_abi)
                REFUSE("identity symbol '%s' has reserved section index %u",
                       is_seal ? ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL
                               : ZCL_HOTSWAP_MODULE_SYMBOL,
                       st_shndx);
            continue;
        }

        if (is_seal) {
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
            if (!vaddr_to_off(&im, phtab, e_phnum, st_value, 65, &off))
                REFUSE("%s at vaddr 0x%llx has no file bytes (points outside every PT_LOAD's file range)",
                       ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL,
                       (unsigned long long)st_value);
            const unsigned char *p = at(&im, off, 65);
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
            memcpy(out->core_seal_root, p, 64);
            out->core_seal_root[64] = '\0';
            out->core_seal_root_present = true;
            continue;
        }

        if (is_abi) {
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
            if (!vaddr_to_off(&im, phtab, e_phnum, st_value, 4, &off))
                REFUSE("%s at vaddr 0x%llx has no file bytes",
                       ZCL_HOTSWAP_MODULE_SYMBOL, (unsigned long long)st_value);
            const unsigned char *p = at(&im, off, 4);
            if (!p)
                REFUSE("%s contents out of bounds", ZCL_HOTSWAP_MODULE_SYMBOL);
            out->abi_version = rd32(p);
            out->abi_version_present = true;
            continue;
        }
    }

    /* ── section headers: validate, and require they agree ─────────────── */
    if (e_shoff == 0 || e_shnum == 0)
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
               (unsigned long long)e_shoff, e_shnum);
    if (e_shentsize != SHDR64_SIZE)
        REFUSE("e_shentsize %u, want %u", e_shentsize, SHDR64_SIZE);
    if (e_shnum > ZCL_HOTSWAP_ELF_PROBE_MAX_SHNUM)
        REFUSE("e_shnum %u exceeds the %u section header cap",
               e_shnum, ZCL_HOTSWAP_ELF_PROBE_MAX_SHNUM);
    const unsigned char *shtab = at(&im, e_shoff, (uint64_t)e_shnum * SHDR64_SIZE);
    if (!shtab)
        REFUSE("section header table at offset %llu (%u x %u bytes) is past the %llu byte file",
               (unsigned long long)e_shoff, e_shnum, SHDR64_SIZE,
               (unsigned long long)n);
    if (!sections_agree(&im, shtab, e_shnum, e_shstrndx,
                        d_init_array, d_init_off, d_init_arraysz,
                        d_fini_array, d_fini_off, d_fini_arraysz,
                        d_preinit_array, d_preinit_off, d_preinit_arraysz,
                        out, err, err_cap)) {
        free(buf);
        return false; /* sections_agree already zeroed *out and set err */
    }

#undef REFUSE

    out->file_size = n;
    free(buf);

    /* Restore the descriptor to offset 0 so this composes with
     * hotswap_artifact_sha3_fd() over the same fd. A failure to seek back is
     * not a reason to distrust facts already read from bytes we hold, but the
     * caller is entitled to the documented offset, so it is a refusal. */
    if (lseek(fd, 0, SEEK_SET) < 0)
        return fail(out, err, err_cap, "cannot restore the descriptor offset (errno %d)", errno);

    if (err && err_cap > 0)
        err[0] = '\0';
    return true;
}

#endif

static bool runtime_import_allowed(const char *name)
{
#define HOTSWAP_MODULE_IMPORT(symbol_, group_) \
    if (strcmp(name, (symbol_)) == 0) return true;
#include "../../../config/hotswap_module_imports.def"
#undef HOTSWAP_MODULE_IMPORT
    return false;
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

    if (facts->has_dt_init)
        return fail(NULL, err, err_cap,
                    "module carries DT_INIT; code would run before admission");
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
