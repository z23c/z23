/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable discovery of the canonical native C toolchain and the
 * files whose bytes identify it for reproducible build receipts.
 *
 * The rest of the tree consumes the descriptor without knowing the host OS.
 * Platform specifics (GCC on Linux, Apple Clang on Darwin, MSVC/Clang-CL on
 * Windows) live inside this implementation. */
#ifndef ZCL_PLATFORM_TOOLCHAIN_H
#define ZCL_PLATFORM_TOOLCHAIN_H

#include <stdbool.h>
#include <stddef.h>

#define ZCL_TOOLCHAIN_TARGET_SIZE   64
#define ZCL_TOOLCHAIN_CONTRACT_SIZE 64
#define ZCL_TOOLCHAIN_PATH_SIZE     4096
#define ZCL_TOOLCHAIN_VERSION_SIZE  256
#define ZCL_TOOLCHAIN_SYSROOT_COUNT 3
#define ZCL_TOOLCHAIN_ABI_COUNT     3

struct platform_toolchain_descriptor {
    /* Canonical target identity used in build receipts and toolchain capsules,
     * e.g. "linux-x86_64-v3", "darwin-arm64", "windows-x86_64". */
    char target[ZCL_TOOLCHAIN_TARGET_SIZE];

    /* Platform release contract that affects produced bytes but is not
     * implied by the compiler/SDK identity. Empty where no contract exists;
     * darwin-arm64 binds "macos-min=14.0" into target probes. */
    char platform_contract[ZCL_TOOLCHAIN_CONTRACT_SIZE];

    /* Resolved paths to the compiler driver, its backend, and the assembler. */
    char compiler_driver[ZCL_TOOLCHAIN_PATH_SIZE];
    char compiler_backend[ZCL_TOOLCHAIN_PATH_SIZE];
    char assembler[ZCL_TOOLCHAIN_PATH_SIZE];

    /* Startup/runtime objects whose bytes vary by OS/libc version. */
    char sysroot_files[ZCL_TOOLCHAIN_SYSROOT_COUNT][ZCL_TOOLCHAIN_PATH_SIZE];

    /* ABI/runtime libraries whose bytes vary by compiler/OS version. */
    char abi_files[ZCL_TOOLCHAIN_ABI_COUNT][ZCL_TOOLCHAIN_PATH_SIZE];

    /* Target triple and version strings reported by the driver. */
    char host_triple[ZCL_TOOLCHAIN_VERSION_SIZE];
    char full_version[ZCL_TOOLCHAIN_VERSION_SIZE];
    char short_version[ZCL_TOOLCHAIN_VERSION_SIZE];
};

/* Return the canonical build target for this process, independent of the
 * compiler the host happens to have installed today. */
bool platform_toolchain_canonical_target(char *out, size_t cap);

/* Return the platform-specific architecture flag used in fixed build actions.
 * Empty string when no such flag is required for the canonical target
 * (e.g. generic Linux x86_64-v3). */
bool platform_toolchain_architecture_flag(char *out, size_t cap);

/* Return the platform-specific architecture flag used in Commons package
 * builds.  On Linux this is the historical AMD64/SSE2 floor; on macOS it is
 * the native architecture baseline. */
bool platform_toolchain_commons_architecture_flag(char *out, size_t cap);

/* Return the archive creation flags for this platform.  GNU ar supports the
 * deterministic "D" flag; Apple ar does not, so macOS uses plain "rcs" and
 * relies on the caller to handle determinism if needed. */
const char *platform_toolchain_archive_flags(void);

/* Prepare object files for deterministic static archiving.  On GNU ar this is
 * a no-op because the archive flags handle determinism; on Apple ar it
 * normalizes the object mtimes so two archives of the same bytes hash
 * identically. */
bool platform_toolchain_prepare_archive_objects(const char *const paths[],
                                                size_t count);

/* Post-process a static archive to make it byte-deterministic.  On GNU ar this
 * is a no-op because the archive flags handle determinism; on Apple ar it
 * zeroes the modification-time field of every archive member header. */
bool platform_toolchain_normalize_archive(const char *path);

/* Return the linker "start group" token, or NULL when the platform linker does
 * not require/accept one.  GNU ld needs -Wl,--start-group; Apple ld does not. */
const char *platform_toolchain_linker_group_start(void);

/* Return the linker "end group" token, or NULL. */
const char *platform_toolchain_linker_group_end(void);

/* Return additional feature-test macro definitions that must precede every
 * Commons package compile on this platform.  Empty on Linux; on macOS this is
 * -D_DARWIN_C_SOURCE so POSIX.1-2008 interfaces such as O_NOFOLLOW remain
 * visible when -D_POSIX_C_SOURCE=200809L is set.  Thread-local. */
const char *platform_toolchain_commons_feature_macros(void);

/* Return the receipt-bound Commons quick build flags for this platform.
 * The string is exactly what the verifier records in a quick-profile receipt.
 * Thread-local: safe for direct use in expression contexts. */
const char *platform_toolchain_commons_flags_quick(void);

/* Return the receipt-bound Commons standard build flags (without the observed
 * sanitizer segment) for this platform.  Thread-local. */
const char *platform_toolchain_commons_flags_standard_base(void);

/* Return the full Commons standard build flags including the observed
 * "clean" sanitizer segment.  Thread-local. */
const char *platform_toolchain_commons_flags_standard(void);

/* Thread-local convenience accessor for the canonical target string.
 * Safe for use in expression contexts that expect a const char *. */
const char *platform_toolchain_canonical_target_string(void);

/* Query callback: execute argv, capture up to cap-1 bytes of stdout into out,
 * NUL-terminate, and return true only on clean exit 0 with non-empty output.
 * The implementation lives in the caller (lib/vcs uses zcl_spawn_capture). */
typedef bool (*platform_toolchain_query_fn)(
    void *ctx, const char *const argv[], char *out, size_t cap);

/* Capture the toolchain descriptor for the current platform.
 *
 * Returns false if a required component cannot be resolved.  On Linux this
 * describes a GCC-style driver; on macOS it describes Apple Clang; on Windows
 * the path is currently unimplemented and returns false. */
bool platform_toolchain_capture_descriptor(
    platform_toolchain_query_fn query_fn,
    void *query_ctx,
    struct platform_toolchain_descriptor *out);

#endif
