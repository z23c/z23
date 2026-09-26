/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact host executable and dynamic-loader identity for fixed compile attachment. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#elif !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_attach.h"
#include "build_fabric_attach_identity_internal.h"
#include "build_fabric_worker_internal.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "platform/os_proc.h"
#include "util/spawn.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/mman.h>
#endif

#if !defined(_WIN32)
#if defined(__linux__)
/* A worker cannot replace any component of this path. Root/package-manager
 * mutation remains an explicit host trust boundary for physical compiles. */
static bool bfat_root_owned_component(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && st.st_uid == 0 &&
           (S_ISLNK(st.st_mode) || (st.st_mode & 022) == 0);
}

static bool bfat_append_path_component(char prefix[4096], size_t *used,
                                        const char *part, size_t len)
{
    if (len == 0 || (len == 1 && part[0] == '.') ||
        (len == 2 && part[0] == '.' && part[1] == '.') ||
        *used + len + 1 >= 4096)
        return false; // raw-return-ok: caller reports the refused tool path
    if (*used > 1) prefix[(*used)++] = '/';
    memcpy(prefix + *used, part, len);
    *used += len;
    prefix[*used] = '\0';
    return bfat_root_owned_component(prefix);
}

static bool bfat_root_owned_path_components(const char *path)
{
    if (!path || path[0] != '/' || strlen(path) >= 4096) return false;
    char prefix[4096] = "/";
    size_t used = 1;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t len = end ? (size_t)(end - part) : strlen(part);
        if (!bfat_append_path_component(prefix, &used, part, len))
            return false; // raw-return-ok: caller names untrusted tool path
        part = end ? end + 1 : part + len;
    }
    return true;
}

static bool bfat_root_owned_path(const char *path)
{
    char resolved[4096];
    struct stat st;
    return os_proc_unprivileged_no_capabilities() &&
           bfat_root_owned_path_components(path) &&
           realpath(path, resolved) != NULL &&
           bfat_root_owned_path_components(resolved) &&
           stat(resolved, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & 022) == 0;
}
#endif

#if defined(__linux__)
static bool bfat_copy_to_memfd(const struct platform_positioned_file *source,
                                uint64_t size, int fd)
{
    uint8_t buf[65536];
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = size - offset > sizeof(buf)
            ? sizeof(buf) : (size_t)(size - offset);
        int64_t got = platform_positioned_file_read(source, buf, want, offset);
        if (got <= 0) return false;
        size_t written = 0;
        while (written < (size_t)got) {
            ssize_t n = pwrite(fd, buf + written, (size_t)got - written,
                               (off_t)(offset + written));
            if (n <= 0) return false;
            written += (size_t)n;
        }
        offset += (uint64_t)got;
    }
    return true;
}

static bool bfat_hash_sealed_memfd(int fd, uint64_t size, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[65536];
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = size - offset > sizeof(buf)
            ? sizeof(buf) : (size_t)(size - offset);
        ssize_t n = pread(fd, buf, want, (off_t)offset);
        if (n <= 0) return false;
        sha3_256_write(&sha, buf, (size_t)n);
        offset += (uint64_t)n;
    }
    sha3_256_finalize(&sha, out);
    return true;
}

static struct zcl_result bfat_verifier_snapshot_open_linux(
    const char *path, struct bfat_verifier_snapshot *out)
{
    if (!path || !out)
        return ZCL_ERR(-1, "verifier snapshot needs path and output");
    out->fd = -1;
    memset(out->bytes, 0, sizeof(out->bytes));
    struct platform_positioned_file source;
    struct platform_positioned_file_snapshot stamp;
    platform_positioned_file_init(&source);
    if (!platform_positioned_file_open_resolved(&source, path) ||
        !platform_positioned_file_is_executable(&source) ||
        !platform_positioned_file_snapshot(&source, &stamp) ||
        stamp.size == 0 || stamp.size > UINT64_C(256) * 1024u * 1024u) {
        platform_positioned_file_close(&source);
        return ZCL_ERR(-1, "verifier snapshot source unavailable");
    }
    int fd = memfd_create("z23-build-verifier",
                          MFD_ALLOW_SEALING | MFD_CLOEXEC);
    if (fd < 0) {
        platform_positioned_file_close(&source);
        return ZCL_ERR(-1, "verifier snapshot memfd unavailable");
    }
    bool ok = bfat_copy_to_memfd(&source, stamp.size, fd);
    platform_positioned_file_close(&source);
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (!ok || fcntl(fd, F_ADD_SEALS, seals) != 0 ||
        (fcntl(fd, F_GET_SEALS) & seals) != seals ||
        !bfat_hash_sealed_memfd(fd, stamp.size, out->bytes))
        ok = false;
    if (!ok) {
        close(fd);
        return ZCL_ERR(-1, "verifier snapshot copy or seal failed");
    }
    out->fd = fd;
    return ZCL_OK;
}

#endif

struct zcl_result bfat_verifier_snapshot_open(
    const char *path, struct bfat_verifier_snapshot *out)
{
#if defined(__linux__)
    return bfat_verifier_snapshot_open_linux(path, out);
#else
    (void)path; (void)out;
    return ZCL_ERR(-1, "verifier snapshot unavailable on this platform");
#endif
}

void bfat_verifier_snapshot_close(struct bfat_verifier_snapshot *snapshot)
{
    if (!snapshot) return;
    if (snapshot->fd >= 0) close(snapshot->fd);
    snapshot->fd = -1;
}

static bool bfat_sha3_file(const char *path, uint8_t out[32])
{
#if defined(__linux__)
    if (!bfat_root_owned_path(path)) return false;
#endif
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_resolved(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        return false;
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[65536];
    uint64_t offset = 0;
    bool ok = true;
    while (offset < before.size) {
        size_t want = before.size - offset > sizeof(buf)
            ? sizeof(buf) : (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&file, buf, want, offset);
        if (got <= 0) { ok = false; break; }
        sha3_256_write(&sha, buf, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) return false;
    sha3_256_finalize(&sha, out);
    return true;
}

#if defined(__linux__)
static bool bfat_hash_loader_line(struct sha3_256_ctx *sha, char *line,
                                  size_t *count)
{
    while (*line == ' ' || *line == '\t') line++;
    if (strncmp(line, "linux-vdso.", 11) == 0) return true;
    char *path = strstr(line, "=>");
    if (path) {
        path += 2;
        while (*path == ' ' || *path == '\t') path++;
    } else {
        path = line;
    }
    if (*path != '/' || ++*count > 64) return false;
    char *end = path;
    while (*end && *end != ' ' && *end != '\t') end++;
    char saved = *end;
    *end = '\0';
    uint8_t digest[32];
    bool ok = bfat_sha3_file(path, digest);
    if (ok) {
        sha3_256_write(sha, (const uint8_t *)path, strlen(path) + 1);
        sha3_256_write(sha, digest, sizeof(digest));
    }
    *end = saved;
    return ok;
}
#endif

/* Bind every resolved DT_NEEDED path and bytes. Unknown loader output
 * refuses attachment rather than leaving an unrecorded dependency. */
static bool bfat_linux_runtime_files(struct sha3_256_ctx *sha,
                                     const char *executable, bool fixed_env)
{
#if defined(__linux__)
    if (!bfat_root_owned_path("/usr/bin/env") ||
        !bfat_root_owned_path("/usr/bin/ldd") ||
        (fixed_env && !bfat_root_owned_path(executable))) return false;
    char output[16384];
    const char *const fixed_argv[] = {
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "/usr/bin/ldd", executable, NULL
    };
    const char *const ambient_argv[] = {
        "/usr/bin/ldd", executable, NULL
    };
    const char *const *argv = fixed_env ? fixed_argv : ambient_argv;
    if (zcl_spawn_capture(argv, output, sizeof(output), 10000) != 0 ||
        !output[0] || strlen(output) >= sizeof(output) - 1)
        return false;
    char *save = NULL;
    size_t count = 0;
    for (char *line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (!bfat_hash_loader_line(sha, line, &count)) return false;
    }
    return count != 0;
#else
    (void)sha;
    (void)executable;
    (void)fixed_env;
    return false;
#endif
}

static bool bfat_loader_environment_clean(void)
{
#if defined(__linux__)
    const char *const ambient[] = { "LD_PRELOAD", "LD_AUDIT",
                                    "LD_LIBRARY_PATH" };
    for (size_t i = 0; i < sizeof(ambient) / sizeof(ambient[0]); i++) {
        const char *value = getenv(ambient[i]);
        if (value && value[0]) return false;
    }
#endif
    return true;
}

static bool bfat_hash_compiler_runtime(
    struct sha3_256_ctx *sha, const struct platform_toolchain_descriptor *desc)
{
    const char *const tools[] = { desc->compiler_driver,
                                  desc->compiler_backend, desc->assembler };
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++)
        if (!bfat_linux_runtime_files(sha, tools[i], true)) return false;
    return true;
}

static bool bfat_hash_verifier_environment(struct sha3_256_ctx *sha)
{
#if defined(__linux__)
    extern char **environ;
    static const char domain[] = "zcl.executor.verifier_environment.v1";
    sha3_256_write(sha, (const uint8_t *)domain, sizeof(domain));
    for (char **entry = environ; entry && *entry; entry++) {
        size_t len = strnlen(*entry, 65536);
        if (len == 65536) return false;
        sha3_256_write(sha, (const uint8_t *)*entry, len + 1);
    }
#else
    (void)sha;
#endif
    return true;
}

struct zcl_result bfat_runtime_roots_snapshot(
    const char *workspace, const struct platform_toolchain_descriptor *desc,
    struct bfat_verifier_snapshot *snapshot,
    uint8_t runtime_root[32], uint8_t verifier_root[32])
{
    if (!workspace || !desc || !snapshot || snapshot->fd < 0)
        return ZCL_ERR(-1, "executor-runtime-closure-missing");
    if (!bfat_loader_environment_clean())
        return ZCL_ERR(-1, "executor-runtime-closure-missing: loader environment");
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.executor.runtime_closure.v1";
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    if (!bfat_hash_compiler_runtime(&sha, desc))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: compiler");
    char verifier[4096];
    ZCL_CHECK(bfw_worker_path(workspace, verifier, sizeof(verifier)));
    char pinned_path[64];
    if (snprintf(pinned_path, sizeof(pinned_path), "/proc/%ld/fd/%d",
                 (long)getpid(), snapshot->fd) >= (int)sizeof(pinned_path))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: verifier");
    if (!bfat_linux_runtime_files(&sha, pinned_path, false))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: verifier");
    if (!bfat_hash_verifier_environment(&sha))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: environment");
    struct sha3_256_ctx verifier_sha;
    sha3_256_init(&verifier_sha);
    static const char verifier_domain[] = "zcl.executor.verifier_identity.v1";
    sha3_256_write(&verifier_sha, (const uint8_t *)verifier_domain,
                   sizeof(verifier_domain));
    sha3_256_write(&verifier_sha, (const uint8_t *)verifier,
                   strlen(verifier) + 1);
    sha3_256_write(&verifier_sha, snapshot->bytes,
                   sizeof(snapshot->bytes));
    sha3_256_finalize(&verifier_sha, verifier_root);
    sha3_256_finalize(&sha, runtime_root);
    return ZCL_OK;
}

struct zcl_result bfat_runtime_roots(
    const char *workspace, const struct platform_toolchain_descriptor *desc,
    uint8_t runtime_root[32], uint8_t verifier_root[32])
{
    char path[4096];
    ZCL_CHECK(bfw_worker_path(workspace, path, sizeof(path)));
    struct bfat_verifier_snapshot snapshot = { .fd = -1 };
    if (!bfat_verifier_snapshot_open(path, &snapshot).ok)
        return ZCL_ERR(-1, "executor-runtime-closure-missing: verifier snapshot");
    struct zcl_result result = bfat_runtime_roots_snapshot(
        workspace, desc, &snapshot, runtime_root, verifier_root);
    bfat_verifier_snapshot_close(&snapshot);
    return result;
}

struct zcl_result build_fabric_executor_host_runtime_roots(
    const char *workspace, uint8_t runtime_root[32],
    uint8_t verifier_root[32])
{
    struct vcs_toolchain_capsule_v1 capsule;
    struct platform_toolchain_descriptor descriptor;
    if (!runtime_root || !verifier_root ||
        !vcs_toolchain_capsule_v1_cached(&capsule, &descriptor))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: capsule");
    return bfat_runtime_roots(workspace, &descriptor, runtime_root,
                              verifier_root);
}

static bool bfat_toolchain_query(void *ctx, const char *const argv[],
                                 char *out, size_t cap)
{
    (void)ctx;
#if defined(__linux__)
    if (!argv || !argv[0] || !argv[1] || argv[2]) return false;
    const char *const fixed_argv[] = {
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        argv[0], argv[1], NULL
    };
    const char *const *query_argv = fixed_argv;
#else
    const char *const *query_argv = argv;
#endif
    if (zcl_spawn_capture(query_argv, out, cap, 10000) != 0 || !out[0])
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

struct zcl_result build_fabric_executor_host_tool_hashes(
    uint8_t driver_sha3[32], uint8_t backend_sha3[32],
    uint8_t assembler_sha3[32])
{
    if (!driver_sha3 || !backend_sha3 || !assembler_sha3)
        return ZCL_ERR(-1, "executor tool hashes require output buffers");
    struct platform_toolchain_descriptor desc;
    if (!platform_toolchain_capture_descriptor(bfat_toolchain_query, NULL,
                                               &desc))
        return ZCL_ERR(-1, "executor-toolchain-capture-failed: descriptor");
    if (!bfat_sha3_file(desc.compiler_driver, driver_sha3) ||
        !bfat_sha3_file(desc.compiler_backend, backend_sha3) ||
        !bfat_sha3_file(desc.assembler, assembler_sha3))
        return ZCL_ERR(-1, "executor-toolchain-capture-failed: tool bytes");
    return ZCL_OK;
}

struct zcl_result bfat_cached_tool_hashes(
    const struct platform_toolchain_descriptor *desc,
    uint8_t driver_sha3[32], uint8_t backend_sha3[32],
    uint8_t assembler_sha3[32])
{
    if (!bfat_sha3_file(desc->compiler_driver, driver_sha3) ||
        !bfat_sha3_file(desc->compiler_backend, backend_sha3) ||
        !bfat_sha3_file(desc->assembler, assembler_sha3))
        return ZCL_ERR(-1, "executor-toolchain-cache-stale: tool bytes");
    return ZCL_OK;
}

#endif
