/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — Mach-O probe (macOS DEV-ONLY).
 *
 * Reads a Mach-O 64-bit bundle/dylib from a descriptor and extracts the
 * identity and execution-surface facts the resident needs BEFORE mapping the
 * artifact.  No code from the artifact runs; no dlopen/dlsym is performed.
 */

/* Read the same inert descriptor bytes in native and non-Windows test builds.
 * Only the full Apple parser can produce successful Mach-O facts. */
#if defined(__APPLE__) || (defined(ZCL_TESTING) && !defined(_WIN32))

#include "hotswap/hotswap_macho_probe.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Existing 32-bit fat encoding, independently checked against the Apple SDK
 * below. Byte copies avoid relying on the alignment of candidate offsets. */
#define MP_FAT_MAGIC UINT32_C(0xcafebabe)
#define MP_FAT_CIGAM UINT32_C(0xbebafeca)
#define MP_ARM64 UINT32_C(0x0100000c)
#define MP_ARM64_ALL UINT32_C(0)
#define MP_FAT_HEADER_BYTES (2u * sizeof(uint32_t))
#define MP_FAT_ARCH_BYTES (5u * sizeof(uint32_t))

static void mp_zero(struct hotswap_macho_facts *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
}

static bool mp_fail(char *err, size_t err_cap, const char *fmt, ...)
{
    if (err && err_cap) {
        va_list ap;
        va_start(ap, fmt);
        (void)vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return false;
}

static uint32_t swap32(bool swap, uint32_t v)
{
    return swap ? zcl_bswap32(v) : v;
}

static bool read_all(int fd, uint8_t *buf, size_t want)
{
    size_t off = 0;
    while (off < want) {
        ssize_t n = read(fd, buf + off, want - off);
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool seek_to(int fd, off_t off)
{
    return lseek(fd, off, SEEK_SET) == off;
}

static const uint8_t *ptr_at(const uint8_t *image, size_t image_size,
                             size_t offset, size_t need)
{
    if (offset > image_size || need > image_size - offset)
        return NULL;
    return image + offset;
}

/* The caller owns the single image allocation even when a read fails. */
static bool mp_read_image(int fd, uint8_t **image, size_t *image_size,
                           char *err, size_t err_cap)
{
    if (fd < 0)
        return mp_fail(err, err_cap, "macho probe: invalid descriptor");
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        return mp_fail(err, err_cap, "macho probe: not a regular file");
    if (st.st_size <= 0)
        return mp_fail(err, err_cap, "macho probe: empty file");
    if ((uint64_t)st.st_size > ZCL_HOTSWAP_MACHO_PROBE_MAX_FILE_BYTES)
        return mp_fail(err, err_cap, "macho probe: file exceeds size ceiling");
    *image_size = (size_t)st.st_size;
    *image = zcl_malloc(*image_size, "macho_probe_image");
    if (!*image)
        return mp_fail(err, err_cap, "macho probe: could not allocate image buffer");
    if (!seek_to(fd, 0) || !read_all(fd, *image, *image_size))
        return mp_fail(err, err_cap, "macho probe: could not read image");
    (void)lseek(fd, 0, SEEK_SET);
    return true;
}

static bool mp_pick_fat(const uint8_t *image, size_t image_size, bool swap,
                         size_t magic_width, size_t *header_off,
                         char *err, size_t err_cap)
{
    if (image_size < MP_FAT_HEADER_BYTES)
        return mp_fail(err, err_cap, "macho probe: truncated fat header");
    uint32_t count;
    memcpy(&count, image + sizeof(uint32_t), sizeof(count));
    count = swap32(swap, count);
    if (count > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS)
        return mp_fail(err, err_cap, "macho probe: fat arch count too large");
    if (count > (image_size - MP_FAT_HEADER_BYTES) / MP_FAT_ARCH_BYTES)
        return mp_fail(err, err_cap, "macho probe: truncated fat arch list");
    for (uint32_t i = 0; i < count; i++) {
        uint32_t arch[5];
        memcpy(arch, image + MP_FAT_HEADER_BYTES +
                     (size_t)i * MP_FAT_ARCH_BYTES, sizeof(arch));
        if (swap32(swap, arch[0]) != MP_ARM64 ||
            swap32(swap, arch[1]) != MP_ARM64_ALL)
            continue;
        size_t off = swap32(swap, arch[2]);
        size_t size = swap32(swap, arch[3]);
        if (size < magic_width || !ptr_at(image, image_size, off, size))
            return mp_fail(err, err_cap,
                           "macho probe: fat arch extends past file");
        *header_off = off;
        return true;
    }
    return mp_fail(err, err_cap,
                   "macho probe: no matching architecture in fat binary");
}

static bool mp_select_magic(const uint8_t *image, size_t image_size,
                             size_t *header_off, uint32_t *magic,
                             char *err, size_t err_cap)
{
    if (image_size < sizeof(*magic))
        return mp_fail(err, err_cap, "macho probe: file too small for magic");
    memcpy(magic, image, sizeof(*magic));
    if (*magic != MP_FAT_MAGIC && *magic != MP_FAT_CIGAM)
        return true;
    if (!mp_pick_fat(image, image_size, *magic == MP_FAT_CIGAM, sizeof(*magic),
                      header_off, err, err_cap))
        return false; // raw-return-ok:propagates_probe_diagnostic
    /* Bound the physical word independently of the declared-slice policy. */
    const uint8_t *p = ptr_at(image, image_size, *header_off, sizeof(*magic));
    if (!p)
        return mp_fail(err, err_cap, "macho probe: fat arch extends past file");
    memcpy(magic, p, sizeof(*magic));
    return true;
}

#if defined(__APPLE__)
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/swap.h>

_Static_assert(MP_FAT_MAGIC == FAT_MAGIC && MP_FAT_CIGAM == FAT_CIGAM,
               "fat magic encoding matches the Apple SDK");
_Static_assert(MP_ARM64 == CPU_TYPE_ARM64 && MP_ARM64_ALL == CPU_SUBTYPE_ARM64_ALL,
               "fat target matches the native probe");
_Static_assert(MP_FAT_HEADER_BYTES == sizeof(struct fat_header) &&
               MP_FAT_ARCH_BYTES == sizeof(struct fat_arch),
               "fat record widths match the Apple SDK");
_Static_assert(offsetof(struct fat_arch, offset) == 2u * sizeof(uint32_t) &&
               offsetof(struct fat_arch, size) == 3u * sizeof(uint32_t),
               "fat range fields match the Apple SDK");

#define HOTSWAP_MACHO_HOST_CPU_TYPE CPU_TYPE_ARM64
#define HOTSWAP_MODULE_SYMBOL "_zcl_hotswap_module"
#define HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL "_zcl_hotswap_module_core_seal_root"

static uint64_t swap64(bool swap, uint64_t v)
{
    return swap ? OSSwapInt64(v) : v;
}

static const char *str_at(const uint8_t *image, size_t image_size,
                          size_t stroff, size_t strsize, uint32_t strx)
{
    if (strx >= strsize)
        return NULL;
    if (stroff + strsize > image_size)
        return NULL;
    const char *base = (const char *)(image + stroff);
    const char *p = base + strx;
    const char *end = base + strsize;
    while (p < end && *p)
        p++;
    if (p >= end)
        return NULL;
    return (const char *)(image + stroff + strx);
}

static bool is_hex64(const char *s)
{
    if (!s)
        return false;
    size_t n = 0;
    for (; s[n]; n++) {
        if (n >= 64)
            return false;
        char c = s[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return n == 64;
}

static bool read_dylib_name(const uint8_t *image, size_t image_size,
                            size_t cmd_offset, uint32_t name_offset,
                            char *out, size_t out_cap)
{
    size_t name_abs = cmd_offset + name_offset;
    if (name_abs >= image_size)
        return false;
    const char *p = (const char *)(image + name_abs);
    const char *end = (const char *)(image + image_size);
    size_t i = 0;
    while (p < end && *p && i + 1 < out_cap) {
        out[i++] = *p++;
    }
    if (p >= end || *p != '\0')
        return false;
    out[i] = '\0';
    return true;
}

static void record_dylib(struct hotswap_macho_facts *facts, const char *name)
{
    if (facts->needed_count < ZCL_HOTSWAP_MACHO_PROBE_MAX_DYLIBS) {
        char *slot = facts->needed[facts->needed_count];
        size_t cap = ZCL_HOTSWAP_MACHO_PROBE_DYLIB_NAME_CAP;
        snprintf(slot, cap, "%s", name ? name : "");
    } else {
        facts->needed_truncated = true;
    }
    facts->needed_count++;
}

static void record_undefined(struct hotswap_macho_facts *facts, const char *name)
{
    if (facts->undefined_symbol_count <
        ZCL_HOTSWAP_MACHO_PROBE_MAX_UNDEFINED) {
        char *slot = facts->undefined_symbols[facts->undefined_symbol_count];
        size_t cap = ZCL_HOTSWAP_MACHO_PROBE_SYMBOL_NAME_CAP;
        snprintf(slot, cap, "%s", name ? name : "");
    } else {
        facts->undefined_symbols_truncated = true;
    }
    facts->undefined_symbol_count++;
}

/* Locate the segment/section that contains `addr` and return its file offset
 * and size.  Used to map a symbol n_value back to bytes in the image. */
static bool addr_to_file(const struct segment_command_64 **segs,
                         size_t seg_count, uint64_t addr,
                         size_t *file_off_out, size_t *file_size_out)
{
    for (size_t i = 0; i < seg_count; i++) {
        const struct segment_command_64 *seg = segs[i];
        if (addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize) {
            uint64_t seg_off = addr - seg->vmaddr;
            if (seg_off < seg->filesize) {
                *file_off_out = (size_t)(seg->fileoff + seg_off);
                *file_size_out = (size_t)(seg->filesize - seg_off);
                return true;
            }
        }
    }
    return false;
}

struct mp_thin {
    const uint8_t *image;
    size_t image_size;
    bool swap;
    struct hotswap_macho_facts *out;
    char *err;
    size_t err_cap;
    const struct segment_command_64 *segs[128];
    size_t seg_count;
    uint32_t symoff, nsyms, stroff, strsize;
    bool has_symtab;
};

static bool mp_thin_magic(struct mp_thin *p, uint32_t magic)
{
    if (magic == MH_MAGIC_64) {
        p->swap = false;
        return true;
    }
    if (magic == MH_CIGAM_64) {
        p->swap = true;
        return true;
    }
    if (magic == MH_MAGIC || magic == MH_CIGAM)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: 32-bit Mach-O is not supported");
    return mp_fail(p->err, p->err_cap, "macho probe: not a Mach-O image");
}

static bool mp_thin_header(struct mp_thin *p, size_t header_off,
                            struct mach_header_64 *hdr)
{
    const uint8_t *bytes = ptr_at(p->image, p->image_size, header_off, sizeof(*hdr));
    if (!bytes)
        return mp_fail(p->err, p->err_cap, "macho probe: truncated Mach-O header");
    memcpy(hdr, bytes, sizeof(*hdr));
    hdr->cputype = swap32(p->swap, hdr->cputype);
    hdr->cpusubtype = swap32(p->swap, hdr->cpusubtype);
    hdr->filetype = swap32(p->swap, hdr->filetype);
    hdr->ncmds = swap32(p->swap, hdr->ncmds);
    hdr->sizeofcmds = swap32(p->swap, hdr->sizeofcmds);
    hdr->flags = swap32(p->swap, hdr->flags);
    if (hdr->cputype != HOTSWAP_MACHO_HOST_CPU_TYPE)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: cputype %d does not match host", hdr->cputype);
    if (hdr->filetype != MH_BUNDLE && hdr->filetype != MH_DYLIB)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: filetype %u is not a loadable bundle/dylib",
                       hdr->filetype);
    if (hdr->ncmds > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: too many load commands (%u)", hdr->ncmds);
    /* The complete header check proves this addition fits inside the image. */
    size_t cmds_off = header_off + sizeof(*hdr);
    if (hdr->sizeofcmds > p->image_size - cmds_off)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: load commands extend past file");
    return true;
}

static void mp_section(struct mp_thin *p, const struct section_64 *sec)
{
    char sectname[17] = {0};
    memcpy(sectname, sec->sectname, 16);
    uint64_t size = swap64(p->swap, sec->size);
    uint32_t elem_size = (uint32_t)sizeof(uintptr_t);
    if (strcmp(sectname, "__mod_init_func") == 0 ||
        strcmp(sectname, "__init_array") == 0)
        p->out->init_section_entries = (size_t)(size / elem_size);
    else if (strcmp(sectname, "__mod_term_func") == 0 ||
             strcmp(sectname, "__fini_array") == 0)
        p->out->term_section_entries = (size_t)(size / elem_size);
}

static bool mp_segment(struct mp_thin *p, const uint8_t *cmds, uint32_t cmdsize)
{
    if (cmdsize < sizeof(struct segment_command_64))
        return mp_fail(p->err, p->err_cap, "macho probe: truncated LC_SEGMENT_64");
    const struct segment_command_64 *seg = (const struct segment_command_64 *)cmds;
    if (p->seg_count < sizeof(p->segs) / sizeof(p->segs[0]))
        p->segs[p->seg_count++] = seg;
    uint32_t nsects = swap32(p->swap, seg->nsects);
    /* Division bounds file-supplied counts before multiplying or indexing. */
    size_t sections_bytes = cmdsize - sizeof(*seg);
    if (nsects > sections_bytes / sizeof(struct section_64))
        return mp_fail(p->err, p->err_cap, "macho probe: segment sections truncated");
    const struct section_64 *sec =
        (const struct section_64 *)(cmds + sizeof(*seg));
    for (uint32_t s = 0; s < nsects; s++)
        mp_section(p, &sec[s]);
    return true;
}

static bool mp_symtab_command(struct mp_thin *p, const uint8_t *cmds,
                               uint32_t cmdsize)
{
    if (cmdsize < sizeof(struct symtab_command))
        return mp_fail(p->err, p->err_cap, "macho probe: truncated LC_SYMTAB");
    const struct symtab_command *sym = (const struct symtab_command *)cmds;
    p->symoff = swap32(p->swap, sym->symoff);
    p->nsyms = swap32(p->swap, sym->nsyms);
    p->stroff = swap32(p->swap, sym->stroff);
    p->strsize = swap32(p->swap, sym->strsize);
    p->has_symtab = true;
    return true;
}

static bool mp_dylib_command(struct mp_thin *p, const uint8_t *cmds,
                              uint32_t cmdsize)
{
    if (cmdsize < sizeof(struct dylib_command))
        return mp_fail(p->err, p->err_cap, "macho probe: truncated dylib command");
    const struct dylib_command *dc = (const struct dylib_command *)cmds;
    uint32_t name_off = swap32(p->swap, dc->dylib.name.offset);
    char name[ZCL_HOTSWAP_MACHO_PROBE_DYLIB_NAME_CAP] = {0};
    if (!read_dylib_name(p->image, p->image_size, (size_t)(cmds - p->image),
                          name_off, name, sizeof(name)))
        return mp_fail(p->err, p->err_cap, "macho probe: malformed dylib name");
    record_dylib(p->out, name);
    return true;
}

static bool mp_command(struct mp_thin *p, const uint8_t *cmds,
                        const struct load_command *lc)
{
    switch (lc->cmd) {
    case LC_SEGMENT_64:
        return mp_segment(p, cmds, lc->cmdsize);
    case LC_SYMTAB:
        return mp_symtab_command(p, cmds, lc->cmdsize);
    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB:
    case LC_REEXPORT_DYLIB:
        return mp_dylib_command(p, cmds, lc->cmdsize);
    case LC_RPATH:
        p->out->has_rpath = true;
        return true;
    case LC_ROUTINES_64:
        return mp_fail(p->err, p->err_cap,
                       "macho probe: LC_ROUTINES_64 initialiser present");
    default:
        return true;
    }
}

static bool mp_commands(struct mp_thin *p, size_t cmds_off,
                         const struct mach_header_64 *hdr)
{
    const uint8_t *cmds = p->image + cmds_off;
    size_t remaining = hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (remaining < sizeof(struct load_command))
            return mp_fail(p->err, p->err_cap,
                           "macho probe: truncated load command list");
        struct load_command lc;
        memcpy(&lc, cmds, sizeof(lc));
        lc.cmd = swap32(p->swap, lc.cmd);
        lc.cmdsize = swap32(p->swap, lc.cmdsize);
        if (lc.cmdsize < sizeof(lc) || lc.cmdsize > remaining)
            return mp_fail(p->err, p->err_cap,
                           "macho probe: malformed load command size");
        if (!mp_command(p, cmds, &lc))
            return false; // raw-return-ok:propagates_probe_diagnostic
        cmds += lc.cmdsize;
        remaining -= lc.cmdsize;
    }
    return true;
}

static bool mp_symbol_bounds(struct mp_thin *p)
{
    if (!p->has_symtab)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: no LC_SYMTAB — cannot verify symbols");
    if (p->nsyms > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS)
        return mp_fail(p->err, p->err_cap,
                       "macho probe: symbol count too large (%u)", p->nsyms);
    p->out->dynamic_symbol_count = p->nsyms;
    size_t symtab_size = (size_t)p->nsyms * sizeof(struct nlist_64);
    if (!ptr_at(p->image, p->image_size, p->symoff, symtab_size))
        return mp_fail(p->err, p->err_cap, "macho probe: symbol table out of bounds");
    if (!ptr_at(p->image, p->image_size, p->stroff, p->strsize))
        return mp_fail(p->err, p->err_cap, "macho probe: string table out of bounds");
    return true;
}

static const uint8_t *mp_identity_bytes(struct mp_thin *p, uint64_t value,
                                        size_t want, const char *symbol)
{
    size_t file_off = 0, avail = 0;
    if (!addr_to_file(p->segs, p->seg_count, value, &file_off, &avail)) {
        (void)mp_fail(p->err, p->err_cap,
                       "macho probe: %s symbol address unresolved", symbol);
        return NULL;
    }
    if (avail < want) {
        (void)mp_fail(p->err, p->err_cap,
                       "macho probe: %s symbol data too small", symbol);
        return NULL;
    }
    const uint8_t *bytes = ptr_at(p->image, p->image_size, file_off, want);
    if (!bytes)
        (void)mp_fail(p->err, p->err_cap,
                       "macho probe: %s symbol out of bounds", symbol);
    return bytes;
}

static bool mp_abi_symbol(struct mp_thin *p, uint64_t value)
{
    const uint8_t *bytes = mp_identity_bytes(p, value, sizeof(uint32_t),
                                             HOTSWAP_MODULE_SYMBOL);
    if (!bytes)
        return false; // raw-return-ok:propagates_probe_diagnostic
    uint32_t abi;
    memcpy(&abi, bytes, sizeof(abi));
    p->out->abi_version = swap32(p->swap, abi);
    p->out->abi_version_present = true;
    return true;
}

static bool mp_root_symbol(struct mp_thin *p, uint64_t value)
{
    const uint8_t *bytes = mp_identity_bytes(p, value, 64,
                                             HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    if (!bytes)
        return false; // raw-return-ok:propagates_probe_diagnostic
    memcpy(p->out->core_seal_root, bytes, 64);
    p->out->core_seal_root[64] = '\0';
    if (!is_hex64(p->out->core_seal_root))
        return mp_fail(p->err, p->err_cap,
                       "macho probe: %s is not 64 lowercase hex",
                       HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    p->out->core_seal_root_present = true;
    return true;
}

static bool mp_symbol(struct mp_thin *p, const struct nlist_64 *sym)
{
    const char *name = str_at(p->image, p->image_size, p->stroff, p->strsize,
                               sym->n_un.n_strx);
    if (!name)
        return true;
    uint8_t type = sym->n_type & N_TYPE;
    bool ext = (sym->n_type & N_EXT) != 0;
    if (ext && type == N_UNDF) {
        record_undefined(p->out, name);
        return true;
    }
    if (!ext || type != N_SECT)
        return true;
    if (strcmp(name, HOTSWAP_MODULE_SYMBOL) == 0)
        return mp_abi_symbol(p, sym->n_value);
    if (strcmp(name, HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL) == 0)
        return mp_root_symbol(p, sym->n_value);
    return true;
}

static bool mp_symbols(struct mp_thin *p)
{
    if (!mp_symbol_bounds(p))
        return false; // raw-return-ok:propagates_probe_diagnostic
    for (uint32_t i = 0; i < p->nsyms; i++) {
        struct nlist_64 sym;
        memcpy(&sym, p->image + p->symoff + (size_t)i * sizeof(sym), sizeof(sym));
        sym.n_un.n_strx = swap32(p->swap, sym.n_un.n_strx);
        sym.n_value = swap64(p->swap, sym.n_value);
        if (!mp_symbol(p, &sym))
            return false; // raw-return-ok:propagates_probe_diagnostic
    }
    return true;
}

static bool mp_probe_thin(const uint8_t *image, size_t image_size,
                           size_t header_off, uint32_t magic,
                           struct hotswap_macho_facts *out,
                           char *err, size_t err_cap)
{
    struct mp_thin p = {.image = image, .image_size = image_size,
                        .out = out, .err = err, .err_cap = err_cap};
    struct mach_header_64 hdr;
    if (!mp_thin_magic(&p, magic) || !mp_thin_header(&p, header_off, &hdr))
        return false; // raw-return-ok:propagates_probe_diagnostic
    return mp_commands(&p, header_off + sizeof(hdr), &hdr) && mp_symbols(&p);
}
#endif /* __APPLE__: full thin-image facts */

bool hotswap_macho_probe_fd(int fd, struct hotswap_macho_facts *out,
                            char *err, size_t err_cap)
{
    mp_zero(out);
    uint8_t *image = NULL;
    size_t image_size = 0, header_off = 0;
    uint32_t magic = 0;
    bool ok = mp_read_image(fd, &image, &image_size, err, err_cap);
    if (ok)
        ok = mp_select_magic(image, image_size, &header_off, &magic, err, err_cap);
    if (ok) {
#if defined(__APPLE__)
        ok = mp_probe_thin(image, image_size, header_off, magic, out, err, err_cap);
#else
        ok = mp_fail(err, err_cap, "macho probe: full probe requires macOS");
#endif
    }
    if (ok) {
        out->file_size = image_size;
        if (err && err_cap)
            err[0] = '\0';
    }
    free(image);
    return ok;
}

#if defined(__APPLE__)
static bool mp_admit_structure(const struct hotswap_macho_facts *facts,
                               char *err, size_t err_cap)
{
    if (facts->init_section_entries !=
        ZCL_HOTSWAP_MACHO_PROBE_CLEAN_INIT_SECTION_ENTRIES) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: init section has %zu entries (want 0)",
                     facts->init_section_entries);
        return false;
    }

    if (facts->has_rpath) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: LC_RPATH present — library resolution is mutable");
        return false;
    }

    if (facts->needed_truncated) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: dependency list exceeds probe capacity");
        return false;
    }

    if (facts->undefined_symbols_truncated) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: undefined symbol list exceeds probe capacity");
        return false;
    }
    return true;
}

static bool mp_admit_abi(const struct hotswap_macho_facts *facts,
                         uint32_t expected_abi, char *err, size_t err_cap)
{
    if (!facts->abi_version_present) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: artifact exports no %s — rebuild it",
                     HOTSWAP_MODULE_SYMBOL);
        return false;
    }
    if (facts->abi_version != expected_abi) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: abi_version %u != required %u",
                     facts->abi_version, expected_abi);
        return false;
    }
    return true;
}

static bool mp_admit_seal_root(const struct hotswap_macho_facts *facts,
                               const char expected_core_seal_root[65],
                               char *err, size_t err_cap)
{
    if (!facts->core_seal_root_present) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: artifact exports no %s — rebuild it",
                     HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
        return false;
    }
    if (strncmp(facts->core_seal_root, expected_core_seal_root, 65) != 0) {
        if (err && err_cap)
            snprintf(err, err_cap,
                     "macho admit: sealed-core ROOT mismatch: artifact=%.64s "
                     "resident=%s (rebuild the module)",
                     facts->core_seal_root, expected_core_seal_root);
        return false;
    }
    return true;
}

bool hotswap_macho_pre_map_admit(const struct hotswap_macho_facts *facts,
                                 const char expected_core_seal_root[65],
                                 uint32_t expected_abi,
                                 char *err, size_t err_cap)
{
    if (!facts) {
        if (err && err_cap)
            snprintf(err, err_cap, "macho admit: no facts");
        return false;
    }

    if (!mp_admit_structure(facts, err, err_cap))
        return false; // raw-return-ok:propagates_admit_diagnostic

    if (!mp_admit_abi(facts, expected_abi, err, err_cap))
        return false; // raw-return-ok:propagates_admit_diagnostic

    if (expected_core_seal_root && expected_core_seal_root[0] &&
        !mp_admit_seal_root(facts, expected_core_seal_root, err, err_cap))
        return false; // raw-return-ok:propagates_admit_diagnostic

    if (err && err_cap)
        err[0] = '\0';
    return true;
}

bool hotswap_macho_probe_and_admit_fd(int fd,
                                      const char expected_core_seal_root[65],
                                      uint32_t expected_abi,
                                      char *err, size_t err_cap)
{
    struct hotswap_macho_facts facts;
    if (!hotswap_macho_probe_fd(fd, &facts, err, err_cap))
        return false;
    return hotswap_macho_pre_map_admit(&facts, expected_core_seal_root,
                                       expected_abi, err, err_cap);
}

void hotswap_macho_pinned_path(int fd, char buf[64])
{
    (void)snprintf(buf, 64, "/dev/fd/%d", fd);
}

#endif /* __APPLE__: native admission and loading interfaces */

#else
typedef int hotswap_macho_probe_not_on_this_platform;
#endif
