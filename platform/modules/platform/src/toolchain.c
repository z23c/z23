/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable discovery of the canonical native C toolchain.
 *
 * Platform specifics (GCC on Linux, Apple Clang on Darwin) live here; the
 * rest of the tree consumes a neutral descriptor. */
/* realpath() is declared in <stdlib.h> only under a POSIX feature-test
 * macro. Without one, glibc still supplies it through the fortify inline,
 * which is enabled only when optimising — so the omission is invisible at
 * -O1 and up and only shows as an implicit declaration at -O0. The guard
 * must precede every include, or the first header pulled in fixes the
 * feature set before this is seen. */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif


#include "platform/toolchain.h"

#include "util/safe_alloc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(__APPLE__) && !defined(ZCL_MACOS_DEPLOYMENT_TARGET)
#define ZCL_MACOS_DEPLOYMENT_TARGET "14.0"
#endif

static bool tc_copy_string(char *dst, size_t dst_cap, const char *src)
{
    if (!dst || dst_cap == 0 || !src)
        return false;
    size_t n = strlen(src);
    if (n >= dst_cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

#if defined(__linux__) || defined(__APPLE__)
static bool tc_query(platform_toolchain_query_fn query_fn, void *query_ctx,
                     const char *compiler, const char *arg,
                     char *out, size_t cap)
{
    const char *const argv[] = { compiler, arg, NULL };
    if (!query_fn(query_ctx, argv, out, cap))
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static bool tc_path_has_separator(const char *path)
{
    return path && (strchr(path, '/') || strchr(path, '\\'));
}

static bool tc_resolve_tool(const char *candidate, char *out, size_t cap)
{
    if (!candidate || !out || cap == 0)
        return false;
#if !defined(_WIN32)
    char canonical[PATH_MAX];
    if (!realpath(candidate, canonical))
        return false;
    candidate = canonical;
#endif
    return tc_copy_string(out, cap, candidate);
}
#endif

#if defined(__APPLE__)
static bool tc_macos_sdk_path(platform_toolchain_query_fn query_fn,
                              void *query_ctx, char *out, size_t cap)
{
    static const char *const argv[] = { "xcrun", "--show-sdk-path", NULL };
    if (!query_fn(query_ctx, argv, out, cap))
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    if (out[0] == '\0')
        return false;
    /* Accept only absolute paths. */
    if (out[0] != '/')
        return false;
    return true;
}

static bool tc_macos_sdk_file(const char *sdk, const char *name,
                              char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/usr/lib/%s", sdk, name);
    return n > 0 && (size_t)n < cap && access(out, F_OK) == 0;
}
#endif

bool platform_toolchain_canonical_target(char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
#if defined(__linux__)
    return tc_copy_string(out, cap, "linux-x86_64-v3");
#elif defined(__APPLE__)
#if defined(__arm64__) || defined(__aarch64__)
    return tc_copy_string(out, cap, "darwin-arm64");
#elif defined(__x86_64__)
    return tc_copy_string(out, cap, "darwin-x86_64");
#else
    return tc_copy_string(out, cap, "darwin");
#endif
#elif defined(_WIN32)
#if defined(_M_X64) || defined(__x86_64__)
    return tc_copy_string(out, cap, "windows-x86_64");
#else
    return tc_copy_string(out, cap, "windows");
#endif
#else
    return tc_copy_string(out, cap, "unknown");
#endif
}

const char *platform_toolchain_canonical_target_string(void)
{
    static _Thread_local char buf[ZCL_TOOLCHAIN_TARGET_SIZE];
    if (!platform_toolchain_canonical_target(buf, sizeof(buf)))
        return "unknown";
    return buf;
}

bool platform_toolchain_architecture_flag(char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
#if defined(__linux__)
    return tc_copy_string(out, cap, "-march=x86-64-v3");
#elif defined(__APPLE__)
#if defined(__arm64__) || defined(__aarch64__)
    return tc_copy_string(out, cap, "-march=armv8-a");
#elif defined(__x86_64__)
    return tc_copy_string(out, cap, "-march=x86-64");
#else
    return true;
#endif
#else
    return true;
#endif
}

bool platform_toolchain_commons_architecture_flag(char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
#if defined(__linux__)
    return tc_copy_string(out, cap, "-march=x86-64 -mtune=generic");
#elif defined(__APPLE__)
#if defined(__arm64__) || defined(__aarch64__)
    return tc_copy_string(out, cap, "-march=armv8-a");
#elif defined(__x86_64__)
    return tc_copy_string(out, cap, "-march=x86-64");
#else
    return true;
#endif
#else
    return true;
#endif
}

const char *platform_toolchain_commons_feature_macros(void)
{
#if defined(__APPLE__)
    return "-D_DARWIN_C_SOURCE";
#else
    return "";
#endif
}

const char *platform_toolchain_commons_flags_quick(void)
{
    static _Thread_local char buf[256];
    char arch[128];
    if (!platform_toolchain_commons_architecture_flag(arch, sizeof(arch)))
        arch[0] = '\0';
#if defined(__linux__)
    /* Preserve the historical Linux V2 flags string byte-for-byte so existing
     * receipts and gates keep the same identity. */
    (void)snprintf(buf, sizeof(buf),
                   "-std=c23 -O1 -march=x86-64 -mtune=generic "
                   "-fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L "
                   "-ffile-prefix-map=SOURCE=. -c");
#elif defined(__APPLE__)
    (void)snprintf(buf, sizeof(buf),
                   "-std=c23 -O1 %s -mmacosx-version-min=%s "
                   "-fno-omit-frame-pointer "
                   "-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE "
                   "-ffile-prefix-map=SOURCE=. -c",
                   arch[0] ? arch : "", ZCL_MACOS_DEPLOYMENT_TARGET);
#else
    buf[0] = '\0';
#endif
    return buf;
}

const char *platform_toolchain_commons_flags_standard_base(void)
{
    static _Thread_local char buf[256];
    char arch[128];
    if (!platform_toolchain_commons_architecture_flag(arch, sizeof(arch)))
        arch[0] = '\0';
#if defined(__linux__)
    (void)snprintf(buf, sizeof(buf),
                   "-std=c23 -O1 -march=x86-64 -mtune=generic "
                   "-fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L "
                   "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror");
#elif defined(__APPLE__)
    (void)snprintf(buf, sizeof(buf),
                   "-std=c23 -O1 %s -mmacosx-version-min=%s "
                   "-fno-omit-frame-pointer "
                   "-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE "
                   "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror",
                   arch[0] ? arch : "", ZCL_MACOS_DEPLOYMENT_TARGET);
#else
    buf[0] = '\0';
#endif
    return buf;
}

const char *platform_toolchain_commons_flags_standard(void)
{
    static _Thread_local char buf[320];
#if defined(__APPLE__)
    (void)snprintf(buf, sizeof(buf),
                   "%s;asan,ubsan=clean;sanitizer_pie=off;sanitizer_aslr=on",
                   platform_toolchain_commons_flags_standard_base());
#else
    (void)snprintf(buf, sizeof(buf),
                   "%s;asan,ubsan=clean;sanitizer_pie=off;sanitizer_aslr=off",
                   platform_toolchain_commons_flags_standard_base());
#endif
    return buf;
}

const char *platform_toolchain_archive_flags(void)
{
#if defined(__linux__)
    return "rcsD";
#elif defined(__APPLE__)
    return "rcs";
#else
    return "rcs";
#endif
}

bool platform_toolchain_prepare_archive_objects(const char *const paths[],
                                                size_t count)
{
#if defined(__APPLE__)
    for (size_t i = 0; i < count; i++) {
        if (!paths[i])
            return false;
        struct timespec times[2] = {{0, 0}, {0, 0}};
        if (utimensat(AT_FDCWD, paths[i], times, 0) != 0)
            return false;
    }
#else
    (void)paths;
    (void)count;
#endif
    return true;
}

bool platform_toolchain_normalize_archive(const char *path)
{
#if defined(__APPLE__)
    if (!path)
        return false;
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }
    static const char magic[] = "!<arch>\n";
    if (st.st_size < (off_t)(sizeof(magic) - 1)) {
        close(fd);
        return false;
    }
    char *buf = zcl_malloc((size_t)st.st_size, "archive-normalize");
    if (!buf) {
        close(fd);
        return false;
    }
    ssize_t total = 0;
    while (total < st.st_size) {
        ssize_t got = read(fd, buf + total, (size_t)(st.st_size - total));
        if (got <= 0) {
            free(buf);
            close(fd);
            return false;
        }
        total += got;
    }
    if ((size_t)total < sizeof(magic) - 1 ||
        memcmp(buf, magic, sizeof(magic) - 1) != 0) {
        free(buf);
        close(fd);
        return false;
    }
    /* Zero the 12-byte modification-time field and normalize the 8-byte
     * mode field in every member header. Apple ar otherwise copies the mode
     * from its input object, so a read-only cached object and an identical
     * freshly compiled object produce different archive bytes.
     * Header layout: name[16] date[12] uid[6] gid[6] mode[8] size[10] `\n[2]. */
    off_t off = (off_t)(sizeof(magic) - 1);
    while (off < total) {
        if (total - off < 60) {
            free(buf);
            close(fd);
            return false;
        }
        char *hdr = buf + off;
        if (hdr[58] != '`' || hdr[59] != '\n') {
            free(buf);
            close(fd);
            return false;
        }
        unsigned long long member_size = 0;
        bool saw_digit = false;
        bool saw_padding = false;
        for (size_t i = 0; i < 10; i++) {
            unsigned char ch = (unsigned char)hdr[48 + i];
            if (ch >= '0' && ch <= '9' && !saw_padding) {
                unsigned digit = (unsigned)(ch - '0');
                if (member_size > (ULLONG_MAX - digit) / 10) {
                    free(buf);
                    close(fd);
                    return false;
                }
                member_size = member_size * 10 + digit;
                saw_digit = true;
            } else if (ch == ' ' && saw_digit) {
                saw_padding = true;
            } else {
                free(buf);
                close(fd);
                return false;
            }
        }
        off += 60;
        if (member_size > (unsigned long long)(total - off)) {
            free(buf);
            close(fd);
            return false;
        }
        /* date field starts at offset 16 and is 12 bytes. */
        memset(hdr + 16, ' ', 12);
        hdr[16] = '0';
        memcpy(hdr + 40, "100644  ", 8);
        off_t payload_size = (off_t)member_size;
        off += payload_size;
        if (payload_size % 2 != 0) {
            if (off >= total) {
                free(buf);
                close(fd);
                return false;
            }
            off++;
        }
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        free(buf);
        close(fd);
        return false;
    }
    off_t written = 0;
    while (written < total) {
        ssize_t w = write(fd, buf + written, (size_t)(total - written));
        if (w <= 0) {
            free(buf);
            close(fd);
            return false;
        }
        written += w;
    }
    free(buf);
    close(fd);
    return true;
#else
    (void)path;
    return true;
#endif
}

const char *platform_toolchain_linker_group_start(void)
{
#if defined(__linux__)
    return "-Wl,--start-group";
#else
    return NULL;
#endif
}

const char *platform_toolchain_linker_group_end(void)
{
#if defined(__linux__)
    return "-Wl,--end-group";
#else
    return NULL;
#endif
}

bool platform_toolchain_capture_descriptor(
    platform_toolchain_query_fn query_fn,
    void *query_ctx,
    struct platform_toolchain_descriptor *out)
{
    if (!query_fn || !out)
        return false;
    memset(out, 0, sizeof(*out));

    if (!platform_toolchain_canonical_target(
            out->target, sizeof(out->target)))
        return false;

#if defined(__linux__)
    const char *compiler = "/usr/bin/cc";
    if (!tc_resolve_tool(compiler, out->compiler_driver,
                         sizeof(out->compiler_driver)))
        return false;

    if (!tc_query(query_fn, query_ctx, compiler,
                  "-print-prog-name=cc1", out->compiler_backend,
                  sizeof(out->compiler_backend)) ||
        !tc_path_has_separator(out->compiler_backend))
        return false;

    if (!tc_query(query_fn, query_ctx, compiler,
                  "-print-prog-name=as", out->assembler,
                  sizeof(out->assembler)))
        return false;
    if (!tc_path_has_separator(out->assembler)) {
        if (!tc_resolve_tool("/usr/bin/as", out->assembler,
                             sizeof(out->assembler)))
            return false;
    }

    static const char *const sysroot_args[ZCL_TOOLCHAIN_SYSROOT_COUNT] = {
        "-print-file-name=crt1.o",
        "-print-file-name=crti.o",
        "-print-file-name=crtn.o",
    };
    for (size_t i = 0; i < ZCL_TOOLCHAIN_SYSROOT_COUNT; i++) {
        if (!tc_query(query_fn, query_ctx, compiler, sysroot_args[i],
                      out->sysroot_files[i],
                      sizeof(out->sysroot_files[i])) ||
            !tc_path_has_separator(out->sysroot_files[i]))
            return false;
    }

    static const char *const abi_args[ZCL_TOOLCHAIN_ABI_COUNT] = {
        "-print-libgcc-file-name",
        "-print-file-name=crtbegin.o",
        "-print-file-name=libc.so.6",
    };
    for (size_t i = 0; i < ZCL_TOOLCHAIN_ABI_COUNT; i++) {
        if (!tc_query(query_fn, query_ctx, compiler, abi_args[i],
                      out->abi_files[i], sizeof(out->abi_files[i])) ||
            !tc_path_has_separator(out->abi_files[i]))
            return false;
    }

    if (!tc_query(query_fn, query_ctx, compiler, "-dumpmachine",
                  out->host_triple, sizeof(out->host_triple)))
        return false;
    if (!tc_query(query_fn, query_ctx, compiler, "-dumpfullversion",
                  out->full_version, sizeof(out->full_version)))
        return false;
    if (!tc_query(query_fn, query_ctx, compiler, "-dumpversion",
                  out->short_version, sizeof(out->short_version)))
        return false;

    return true;

#elif defined(__APPLE__)
    const char *compiler = "/usr/bin/cc";
    if (!tc_copy_string(out->platform_contract,
                        sizeof(out->platform_contract),
                        "macos-min=" ZCL_MACOS_DEPLOYMENT_TARGET))
        return false;
    if (!tc_resolve_tool(compiler, out->compiler_driver,
                         sizeof(out->compiler_driver)))
        return false;

    /* Apple Clang is integrated; the "backend" is the clang binary itself. */
    if (!tc_query(query_fn, query_ctx, compiler, "-print-prog-name=clang",
                  out->compiler_backend, sizeof(out->compiler_backend)) ||
        !tc_path_has_separator(out->compiler_backend))
        return false;

    if (!tc_query(query_fn, query_ctx, compiler, "-print-prog-name=as",
                  out->assembler, sizeof(out->assembler)) ||
        !tc_path_has_separator(out->assembler))
        return false;

    char sdk[PATH_MAX];
    if (!tc_macos_sdk_path(query_fn, query_ctx, sdk, sizeof(sdk)))
        return false;

    static const char *const sysroot_names[ZCL_TOOLCHAIN_SYSROOT_COUNT] = {
        "crt1.o", "dylib1.o", "bundle1.o",
    };
    for (size_t i = 0; i < ZCL_TOOLCHAIN_SYSROOT_COUNT; i++) {
        if (!tc_macos_sdk_file(sdk, sysroot_names[i],
                               out->sysroot_files[i],
                               sizeof(out->sysroot_files[i])))
            return false;
    }

    /* ABI/runtime: compiler runtime from the driver, plus SDK text-based stubs
     * that pin the libc/libc++ interface this binary was linked against. */
    if (!tc_query(query_fn, query_ctx, compiler, "-print-libgcc-file-name",
                  out->abi_files[0], sizeof(out->abi_files[0])) ||
        !tc_path_has_separator(out->abi_files[0]))
        return false;
    static const char *const abi_sdk_names[ZCL_TOOLCHAIN_ABI_COUNT - 1] = {
        "libSystem.tbd", "libc++.tbd",
    };
    for (size_t i = 0; i < ZCL_TOOLCHAIN_ABI_COUNT - 1; i++) {
        if (!tc_macos_sdk_file(sdk, abi_sdk_names[i],
                               out->abi_files[i + 1],
                               sizeof(out->abi_files[i + 1])))
            return false;
    }

    if (!tc_query(query_fn, query_ctx, compiler, "-dumpmachine",
                  out->host_triple, sizeof(out->host_triple)))
        return false;

    /* Apple Clang does not support -dumpfullversion.  Use the same version
     * string for both slots; the short version still distinguishes releases. */
    if (!tc_query(query_fn, query_ctx, compiler, "--version",
                  out->full_version, sizeof(out->full_version)))
        return false;
    if (!tc_query(query_fn, query_ctx, compiler, "-dumpversion",
                  out->short_version, sizeof(out->short_version)))
        return false;

    return true;
#else
    (void)query_fn;
    (void)query_ctx;
    return false;
#endif
}
