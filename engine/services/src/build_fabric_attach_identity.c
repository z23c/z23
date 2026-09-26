/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact host executable and dynamic-loader identity for fixed compile attachment. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_attach.h"
#include "build_fabric_attach_identity_internal.h"
#include "build_fabric_worker_internal.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "util/spawn.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
static bool bfat_sha3_file(const char *path, uint8_t out[32])
{
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

struct zcl_result bfat_runtime_roots(
    const char *workspace, const struct platform_toolchain_descriptor *desc,
    uint8_t runtime_root[32], uint8_t verifier_root[32])
{
    if (!workspace || !desc)
        return ZCL_ERR(-1, "executor-runtime-closure-missing");
#if defined(__linux__)
    const char *const ambient[] = { "LD_PRELOAD", "LD_AUDIT",
                                    "LD_LIBRARY_PATH" };
    for (size_t i = 0; i < sizeof(ambient) / sizeof(ambient[0]); i++) {
        const char *value = getenv(ambient[i]);
        if (value && value[0])
            return ZCL_ERR(-1, "executor-runtime-closure-missing: loader environment");
    }
#endif
    const char *const tools[] = { desc->compiler_driver,
                                  desc->compiler_backend, desc->assembler };
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.executor.runtime_closure.v1";
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
        if (!bfat_linux_runtime_files(&sha, tools[i], true))
            return ZCL_ERR(-1, "executor-runtime-closure-missing: compiler");
    }
    char verifier[4096];
    ZCL_CHECK(bfw_worker_path(workspace, verifier, sizeof(verifier)));
    uint8_t verifier_bytes[32];
    if (!bfat_sha3_file(verifier, verifier_bytes) ||
        !bfat_linux_runtime_files(&sha, verifier, false))
        return ZCL_ERR(-1, "executor-runtime-closure-missing: verifier");
#if defined(__linux__)
    extern char **environ;
    static const char env_domain[] = "zcl.executor.verifier_environment.v1";
    sha3_256_write(&sha, (const uint8_t *)env_domain, sizeof(env_domain));
    for (char **entry = environ; entry && *entry; entry++) {
        size_t len = strnlen(*entry, 65536);
        if (len == 65536)
            return ZCL_ERR(-1, "executor-runtime-closure-missing: environment");
        sha3_256_write(&sha, (const uint8_t *)*entry, len + 1);
    }
#endif
    struct sha3_256_ctx verifier_sha;
    sha3_256_init(&verifier_sha);
    static const char verifier_domain[] = "zcl.executor.verifier_identity.v1";
    sha3_256_write(&verifier_sha, (const uint8_t *)verifier_domain,
                   sizeof(verifier_domain));
    sha3_256_write(&verifier_sha, (const uint8_t *)verifier,
                   strlen(verifier) + 1);
    sha3_256_write(&verifier_sha, verifier_bytes, sizeof(verifier_bytes));
    sha3_256_finalize(&verifier_sha, verifier_root);
    sha3_256_finalize(&sha, runtime_root);
    return ZCL_OK;
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
