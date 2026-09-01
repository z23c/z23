/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — READ WHAT THE ARTIFACT CLAIMS, BEFORE IT IS MAPPED.
 * macOS Mach-O counterpart to hotswap/hotswap_elf_probe.h.
 *
 * The same ordering defect exists on macOS as on Linux: dlopen runs the
 * dynamic linker and module initialisers before any admission stage has seen
 * the artifact's claims. This probe reads the Mach-O load commands and symbol
 * tables from a descriptor, extracts identity and execution-surface facts, and
 * reports them without mapping or executing any artifact code.
 *
 * The same fail-closed discipline applies: malformed or unexpected structures
 * are refused with a specific reason, and the caller (hotswap_activate.c)
 * treats false as "refuse this artifact".
 */
#ifndef ZCL_HOTSWAP_MACHO_PROBE_H
#define ZCL_HOTSWAP_MACHO_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hotswap/hotswap_sealed_image.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_HOTSWAP_MACHO_PROBE_MAX_FILE_BYTES ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES
#define ZCL_HOTSWAP_MACHO_PROBE_MAX_LOAD_COMMANDS 4096u
#define ZCL_HOTSWAP_MACHO_PROBE_MAX_DYLIBS       8u
#define ZCL_HOTSWAP_MACHO_PROBE_DYLIB_NAME_CAP   64u
#define ZCL_HOTSWAP_MACHO_PROBE_MAX_UNDEFINED    256u
#define ZCL_HOTSWAP_MACHO_PROBE_SYMBOL_NAME_CAP  128u
#define ZCL_HOTSWAP_MACHO_PROBE_ERR_CAP          256u

/* Secure module builds omit crt startup files, leaving no pre-map callback. */
#define ZCL_HOTSWAP_MACHO_PROBE_CLEAN_INIT_SECTION_ENTRIES ((size_t)0)

struct hotswap_macho_facts {
    /* Identity claims: contents of the exported string symbols. */
    char     core_seal_root[65];
    bool     core_seal_root_present;
    uint32_t abi_version;
    bool     abi_version_present;

    /* Pre-map code-execution surface. */
    size_t   init_section_entries;   /* __mod_init_func / .init_array entries */
    size_t   term_section_entries;   /* __mod_term_func / .fini_array entries */
    size_t   needed_count;
    char     needed[ZCL_HOTSWAP_MACHO_PROBE_MAX_DYLIBS]
                   [ZCL_HOTSWAP_MACHO_PROBE_DYLIB_NAME_CAP];
    bool     needed_truncated;
    bool     has_rpath;              /* LC_RPATH can redirect LC_LOAD_DYLIB */

    /* Symbol table shape. */
    size_t   dynamic_symbol_count;
    size_t   undefined_symbol_count;
    char     undefined_symbols[ZCL_HOTSWAP_MACHO_PROBE_MAX_UNDEFINED]
                              [ZCL_HOTSWAP_MACHO_PROBE_SYMBOL_NAME_CAP];
    bool     undefined_symbols_truncated;

    /* Bytes actually read from the descriptor. */
    uint64_t file_size;
};

/* Probe the Mach-O image on descriptor `fd` without mapping or executing it.
 * Leaves the descriptor offset at 0 on success.  Returns true only when the
 * file is a well-formed Mach-O 64-bit image this host can load. */
bool hotswap_macho_probe_fd(int fd, struct hotswap_macho_facts *out,
                            char *err, size_t err_cap);

/* The one pre-map policy shared by resident activation and offline verify. */
bool hotswap_macho_pre_map_admit(const struct hotswap_macho_facts *facts,
                                 const char expected_core_seal_root[65],
                                 uint32_t expected_abi,
                                 char *err, size_t err_cap);

/* Probe `fd` and immediately run the pre-map admission policy. */
bool hotswap_macho_probe_and_admit_fd(int fd,
                                      const char expected_core_seal_root[65],
                                      uint32_t expected_abi,
                                      char *err, size_t err_cap);

/* The pinned path this platform uses to dlopen a descriptor we already hold. */
void hotswap_macho_pinned_path(int fd, char buf[64]);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_MACHO_PROBE_H */
