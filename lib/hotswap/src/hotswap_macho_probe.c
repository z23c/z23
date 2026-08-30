/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — Mach-O probe (macOS DEV-ONLY).
 *
 * Reads a Mach-O 64-bit bundle/dylib from a descriptor and extracts the
 * identity and execution-surface facts the resident needs BEFORE mapping the
 * artifact.  No code from the artifact runs; no dlopen/dlsym is performed.
 */

#include "hotswap/hotswap_macho_probe.h"

/* The mach-o headers below exist only on Darwin, and hotswap_activate.c —
 * the sole consumer — already selects this probe under the same guard,
 * falling back to the ELF probe elsewhere. Without this the file breaks the
 * Linux build outright. Mirrors the guard in hotswap_elf_probe_windows.c;
 * every C file under lib/hotswap/src is compiled on every platform. */
#if defined(__APPLE__)

#include "util/safe_alloc.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/swap.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HOTSWAP_MACHO_HOST_CPU_TYPE CPU_TYPE_ARM64
#define HOTSWAP_MACHO_HOST_CPU_SUBTYPE CPU_SUBTYPE_ARM64_ALL

/* Symbol names this probe reads directly. */
#define HOTSWAP_MODULE_SYMBOL "_zcl_hotswap_module"
#define HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL \
    "_zcl_hotswap_module_core_seal_root"

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
    return swap ? OSSwapInt32(v) : v;
}

static uint64_t swap64(bool swap, uint64_t v)
{
    return swap ? OSSwapInt64(v) : v;
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

/* Return a pointer into `image` at `offset`, or NULL if out of bounds. */
static const uint8_t *ptr_at(const uint8_t *image, size_t image_size,
                             size_t offset, size_t need)
{
    if (offset > image_size || need > image_size - offset)
        return NULL;
    return image + offset;
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

bool hotswap_macho_probe_fd(int fd, struct hotswap_macho_facts *out,
                            char *err, size_t err_cap)
{
    mp_zero(out);

    if (fd < 0)
        return mp_fail(err, err_cap, "macho probe: invalid descriptor");

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        return mp_fail(err, err_cap, "macho probe: not a regular file");
    if (st.st_size <= 0)
        return mp_fail(err, err_cap, "macho probe: empty file");
    if ((uint64_t)st.st_size > ZCL_HOTSWAP_MACHO_PROBE_MAX_FILE_BYTES)
        return mp_fail(err, err_cap, "macho probe: file exceeds size ceiling");

    size_t image_size = (size_t)st.st_size;
    uint8_t *image = zcl_malloc(image_size, "macho_probe_image");
    if (!image)
        return mp_fail(err, err_cap, "macho probe: could not allocate image buffer");

    if (!seek_to(fd, 0) || !read_all(fd, image, image_size)) {
        free(image);
        return mp_fail(err, err_cap, "macho probe: could not read image");
    }
    (void)lseek(fd, 0, SEEK_SET);

    if (image_size < sizeof(uint32_t)) {
        free(image);
        return mp_fail(err, err_cap, "macho probe: file too small for magic");
    }

    uint32_t magic = *(const uint32_t *)image;
    bool swap = false;
    size_t header_off = 0;

    /* Universal binaries: pick the native architecture. */
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        if (image_size < sizeof(struct fat_header)) {
            free(image);
            return mp_fail(err, err_cap, "macho probe: truncated fat header");
        }
        bool fat_swap = (magic == FAT_CIGAM);
        struct fat_header fh;
        memcpy(&fh, image, sizeof(fh));
        uint32_t nfat_arch = fat_swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
        if (nfat_arch > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS) {
            free(image);
            return mp_fail(err, err_cap, "macho probe: fat arch count too large");
        }
        size_t archs_size = (size_t)nfat_arch * sizeof(struct fat_arch);
        if (image_size - sizeof(struct fat_header) < archs_size) {
            free(image);
            return mp_fail(err, err_cap, "macho probe: truncated fat arch list");
        }
        bool found = false;
        for (uint32_t i = 0; i < nfat_arch; i++) {
            struct fat_arch fa;
            memcpy(&fa, image + sizeof(struct fat_header) +
                         i * sizeof(struct fat_arch), sizeof(fa));
            cpu_type_t cputype = fat_swap ? OSSwapInt32(fa.cputype) : fa.cputype;
            cpu_subtype_t cpusubtype = fat_swap ? OSSwapInt32(fa.cpusubtype)
                                                : fa.cpusubtype;
            if (cputype == HOTSWAP_MACHO_HOST_CPU_TYPE &&
                cpusubtype == HOTSWAP_MACHO_HOST_CPU_SUBTYPE) {
                header_off = fat_swap ? OSSwapInt32(fa.offset) : fa.offset;
                uint32_t size = fat_swap ? OSSwapInt32(fa.size) : fa.size;
                if (header_off > image_size || size > image_size - header_off) {
                    free(image);
                    return mp_fail(err, err_cap,
                                   "macho probe: fat arch extends past file");
                }
                found = true;
                break;
            }
        }
        if (!found) {
            free(image);
            return mp_fail(err, err_cap,
                           "macho probe: no matching architecture in fat binary");
        }
        /* The thin header inside the fat determines its own endianness. */
        magic = *(const uint32_t *)(image + header_off);
    }

    if (magic == MH_MAGIC_64) {
        swap = false;
    } else if (magic == MH_CIGAM_64) {
        swap = true;
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: 32-bit Mach-O is not supported");
    } else {
        free(image);
        return mp_fail(err, err_cap, "macho probe: not a Mach-O image");
    }

    if (image_size - header_off < sizeof(struct mach_header_64)) {
        free(image);
        return mp_fail(err, err_cap, "macho probe: truncated Mach-O header");
    }
    struct mach_header_64 hdr;
    memcpy(&hdr, image + header_off, sizeof(hdr));
    hdr.cputype = swap32(swap, hdr.cputype);
    hdr.cpusubtype = swap32(swap, hdr.cpusubtype);
    hdr.filetype = swap32(swap, hdr.filetype);
    hdr.ncmds = swap32(swap, hdr.ncmds);
    hdr.sizeofcmds = swap32(swap, hdr.sizeofcmds);
    hdr.flags = swap32(swap, hdr.flags);

    if (hdr.cputype != HOTSWAP_MACHO_HOST_CPU_TYPE) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: cputype %d does not match host", hdr.cputype);
    }

    if (hdr.filetype != MH_BUNDLE && hdr.filetype != MH_DYLIB) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: filetype %u is not a loadable bundle/dylib",
                       hdr.filetype);
    }

    if (hdr.ncmds > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: too many load commands (%u)", hdr.ncmds);
    }

    size_t max_cmds_off = header_off + sizeof(struct mach_header_64);
    if (hdr.sizeofcmds > image_size - max_cmds_off) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: load commands extend past file");
    }

    const size_t max_segs = 128;
    const struct segment_command_64 *segs[128] = {0};
    size_t seg_count = 0;

    uint32_t symoff = 0;
    uint32_t nsyms = 0;
    uint32_t stroff = 0;
    uint32_t strsize = 0;
    bool has_symtab = false;

    const uint8_t *cmds = image + max_cmds_off;
    size_t cmds_remaining = hdr.sizeofcmds;

    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        if (cmds_remaining < sizeof(struct load_command)) {
            free(image);
            return mp_fail(err, err_cap,
                           "macho probe: truncated load command list");
        }
        struct load_command lc;
        memcpy(&lc, cmds, sizeof(lc));
        lc.cmd = swap32(swap, lc.cmd);
        lc.cmdsize = swap32(swap, lc.cmdsize);
        if (lc.cmdsize < sizeof(struct load_command) ||
            lc.cmdsize > cmds_remaining) {
            free(image);
            return mp_fail(err, err_cap,
                           "macho probe: malformed load command size");
        }

        size_t cmd_off = (size_t)(cmds - image);
        switch (lc.cmd) {
        case LC_SEGMENT_64: {
            if (lc.cmdsize < sizeof(struct segment_command_64)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: truncated LC_SEGMENT_64");
            }
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cmds;
            if (seg_count < max_segs)
                segs[seg_count++] = seg;

            uint32_t nsects = swap32(swap, seg->nsects);
            size_t expected = sizeof(struct segment_command_64) +
                              (size_t)nsects * sizeof(struct section_64);
            if (lc.cmdsize < expected) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: segment sections truncated");
            }
            const struct section_64 *sec =
                (const struct section_64 *)(cmds + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < nsects; s++) {
                char sectname[17] = {0};
                char segname[17] = {0};
                memcpy(sectname, sec[s].sectname, 16);
                memcpy(segname, sec[s].segname, 16);
                uint64_t size = swap64(swap, sec[s].size);
                uint32_t elem_size = (uint32_t)sizeof(uintptr_t);
                if (strcmp(sectname, "__mod_init_func") == 0 ||
                    strcmp(sectname, "__init_array") == 0) {
                    out->init_section_entries =
                        (size_t)(size / elem_size);
                } else if (strcmp(sectname, "__mod_term_func") == 0 ||
                           strcmp(sectname, "__fini_array") == 0) {
                    out->term_section_entries =
                        (size_t)(size / elem_size);
                }
            }
            break;
        }
        case LC_SYMTAB: {
            if (lc.cmdsize < sizeof(struct symtab_command)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: truncated LC_SYMTAB");
            }
            const struct symtab_command *sym =
                (const struct symtab_command *)cmds;
            symoff = swap32(swap, sym->symoff);
            nsyms = swap32(swap, sym->nsyms);
            stroff = swap32(swap, sym->stroff);
            strsize = swap32(swap, sym->strsize);
            has_symtab = true;
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB: {
            if (lc.cmdsize < sizeof(struct dylib_command)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: truncated dylib command");
            }
            const struct dylib_command *dc =
                (const struct dylib_command *)cmds;
            uint32_t name_off = swap32(swap, dc->dylib.name.offset);
            char name[ZCL_HOTSWAP_MACHO_PROBE_DYLIB_NAME_CAP] = {0};
            if (!read_dylib_name(image, image_size, cmd_off, name_off,
                                 name, sizeof(name))) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: malformed dylib name");
            }
            record_dylib(out, name);
            break;
        }
        case LC_RPATH:
            out->has_rpath = true;
            break;
        case LC_ROUTINES_64:
            free(image);
            return mp_fail(err, err_cap,
                           "macho probe: LC_ROUTINES_64 initialiser present");
        default:
            break;
        }

        cmds += lc.cmdsize;
        cmds_remaining -= lc.cmdsize;
    }

    if (!has_symtab) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: no LC_SYMTAB — cannot verify symbols");
    }

    if (nsyms > ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS) {
        free(image);
        return mp_fail(err, err_cap,
                       "macho probe: symbol count too large (%u)", nsyms);
    }

    out->dynamic_symbol_count = nsyms;

    size_t symtab_size = (size_t)nsyms * sizeof(struct nlist_64);
    if (symoff > image_size || symtab_size > image_size - symoff) {
        free(image);
        return mp_fail(err, err_cap, "macho probe: symbol table out of bounds");
    }
    if (stroff > image_size || strsize > image_size - stroff) {
        free(image);
        return mp_fail(err, err_cap, "macho probe: string table out of bounds");
    }

    const struct nlist_64 *symtab =
        (const struct nlist_64 *)(image + symoff);

    for (uint32_t i = 0; i < nsyms; i++) {
        struct nlist_64 sym;
        memcpy(&sym, &symtab[i], sizeof(sym));
        sym.n_un.n_strx = swap32(swap, sym.n_un.n_strx);
        sym.n_value = swap64(swap, sym.n_value);
        /* n_type and n_sect are bytes; no swap needed on any host. */

        const char *name = str_at(image, image_size, stroff, strsize,
                                  sym.n_un.n_strx);
        if (!name)
            continue;

        uint8_t type = sym.n_type & N_TYPE;
        bool ext = (sym.n_type & N_EXT) != 0;

        if (ext && type == N_UNDF) {
            record_undefined(out, name);
            continue;
        }

        if (!ext || type != N_SECT)
            continue;

        if (strcmp(name, HOTSWAP_MODULE_SYMBOL) == 0) {
            size_t file_off = 0, avail = 0;
            if (!addr_to_file(segs, seg_count, sym.n_value, &file_off, &avail)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol address unresolved",
                               HOTSWAP_MODULE_SYMBOL);
            }
            if (avail < sizeof(uint32_t)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol data too small",
                               HOTSWAP_MODULE_SYMBOL);
            }
            const uint8_t *p = ptr_at(image, image_size, file_off, sizeof(uint32_t));
            if (!p) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol out of bounds",
                               HOTSWAP_MODULE_SYMBOL);
            }
            uint32_t abi = *(const uint32_t *)p;
            /* Mach-O bundles produced by the build are host-endian. */
            out->abi_version = swap ? OSSwapInt32(abi) : abi;
            out->abi_version_present = true;
        } else if (strcmp(name, HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL) == 0) {
            size_t file_off = 0, avail = 0;
            if (!addr_to_file(segs, seg_count, sym.n_value, &file_off, &avail)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol address unresolved",
                               HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
            }
            size_t want = 64;
            if (avail < want) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol data too small",
                               HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
            }
            const char *p = (const char *)ptr_at(image, image_size, file_off, want);
            if (!p) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s symbol out of bounds",
                               HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
            }
            memcpy(out->core_seal_root, p, 64);
            out->core_seal_root[64] = '\0';
            if (!is_hex64(out->core_seal_root)) {
                free(image);
                return mp_fail(err, err_cap,
                               "macho probe: %s is not 64 lowercase hex",
                               HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
            }
            out->core_seal_root_present = true;
        }
    }

    out->file_size = image_size;
    free(image);

    if (err && err_cap)
        err[0] = '\0';
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

    if (expected_core_seal_root && expected_core_seal_root[0]) {
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
    }

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

#endif /* __APPLE__ */
