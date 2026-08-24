/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical SHA3 identities for toolchains and fixed C23 actions. */

#include "vcs/build_action.h"

#include "crypto/sha3.h"
#include "util/spawn.h"
#include "vcs/zcode_dev.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BUILD_TOOLCHAIN_FILE_COUNT 9

struct build_toolchain_file {
    char path[PATH_MAX];
    struct stat stamp;
};

struct build_toolchain_cache {
    struct vcs_toolchain_capsule_v1 capsule;
    struct build_toolchain_file files[BUILD_TOOLCHAIN_FILE_COUNT];
    uint8_t environment_root[32];
    uint64_t fresh_captures;
    uint64_t cache_hits;
    bool valid;
};

static pthread_mutex_t g_toolchain_cache_mu = PTHREAD_MUTEX_INITIALIZER;
static struct build_toolchain_cache g_toolchain_cache;

void vcs_source_manifest_id(const uint8_t *wire, size_t len, uint8_t out[32])
{
    static const char domain[] = VCS_SOURCE_MANIFEST_ID_SCHEMA;
    struct sha3_256_ctx sha;

    if (!out)
        return;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    if (wire && len > 0)
        sha3_256_write(&sha, wire, len);
    sha3_256_finalize(&sha, out);
}

static void build_hash_text(struct sha3_256_ctx *sha, const char *value)
{
    uint64_t length = value ? strlen(value) : 0;
    uint8_t le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)((length >> (8U * i)) & 0xffU);
    sha3_256_write(sha, le, sizeof(le));
    if (length)
        sha3_256_write(sha, (const uint8_t *)value, (size_t)length);
}

static void build_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)((value >> (8U * i)) & 0xffU);
    sha3_256_write(sha, le, sizeof(le));
}

static bool build_text_valid(const char *value, size_t cap)
{
    return value && value[0] && strnlen(value, cap) < cap;
}

static bool build_stat_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool build_sha3_file(const char *path, uint8_t out[32],
                            struct stat *stable_stamp)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct stat before, after;
    if (fstat(fileno(f), &before) != 0 || !S_ISREG(before.st_mode)) {
        fclose(f);
        return false;
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[65536];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&sha, buf, got);
    bool ok = ferror(f) == 0 && fstat(fileno(f), &after) == 0 &&
              build_stat_equal(&before, &after);
    fclose(f);
    if (!ok) return false;
    sha3_256_finalize(&sha, out);
    if (stable_stamp) *stable_stamp = after;
    return true;
}

static bool build_gcc_query(const char *arg, char *out, size_t cap)
{
    const char *const argv[] = { VCS_BUILD_COMPILER_V1, arg, NULL };
    if (zcl_spawn_capture(argv, out, cap, 10000) != 0 || !out[0])
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static bool build_gcc_file(const char *arg, const char *fallback,
                           uint8_t out[32],
                           struct build_toolchain_file *file)
{
    char named[4096];
    if (!build_gcc_query(arg, named, sizeof(named))) return false;
    const char *candidate = strchr(named, '/') ? named : fallback;
    char resolved[4096];
    if (!candidate || !file || !realpath(candidate, resolved) ||
        strlen(resolved) >= sizeof(file->path))
        return false;
    (void)snprintf(file->path, sizeof(file->path), "%s", resolved);
    return build_sha3_file(resolved, out, &file->stamp);
}

/* Assembler identity is GNU as --version, not the assembler file bytes.
 * Distro patch levels of the same GNU as version change the binary and
 * would otherwise refuse an independent worker on an ordinary second
 * machine. The file stamp still participates in the capture cache so an
 * assembler upgrade recaptures. */
static bool build_assembler_identity(uint8_t out[32],
                                     struct build_toolchain_file *file)
{
    char named[4096];
    if (!build_gcc_query("-print-prog-name=as", named, sizeof(named)))
        return false;
    const char *candidate = strchr(named, '/') ? named : "/usr/bin/as";
    char resolved[4096];
    if (!file || !realpath(candidate, resolved) ||
        strlen(resolved) >= sizeof(file->path))
        return false;
    (void)snprintf(file->path, sizeof(file->path), "%s", resolved);
    if (stat(resolved, &file->stamp) != 0 || !S_ISREG(file->stamp.st_mode))
        return false;
    char version[512];
    const char *const argv[] = { resolved, "--version", NULL };
    if (zcl_spawn_capture(argv, version, sizeof(version), 10000) != 0 ||
        !version[0])
        return false;
    version[strcspn(version, "\r\n")] = '\0';
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.toolchain.assembler_identity.v1";
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    build_hash_text(&sha, version);
    sha3_256_finalize(&sha, out);
    return true;
}

static void build_hash_pair(struct sha3_256_ctx *sha, const char *label,
                            const uint8_t digest[32])
{
    build_hash_text(sha, label);
    sha3_256_write(sha, digest, 32);
}

static bool build_gcc_aggregate(const char *domain,
                                const char *const args[],
                                const char *const fallbacks[], size_t count,
                                uint8_t out[32],
                                struct build_toolchain_file files[],
                                size_t *file_count)
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    for (size_t i = 0; i < count; i++) {
        uint8_t digest[32];
        if (!files || !file_count ||
            *file_count >= BUILD_TOOLCHAIN_FILE_COUNT ||
            !build_gcc_file(args[i], fallbacks ? fallbacks[i] : NULL,
                            digest, &files[*file_count]))
            return false;
        (*file_count)++;
        build_hash_pair(&sha, args[i], digest);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

static void build_toolchain_environment_root(uint8_t out[32])
{
    static const char *const names[] = {
        "PATH", "LANG", "LC_ALL", "LC_MESSAGES", "GCC_EXEC_PREFIX",
        "COMPILER_PATH", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH", "GCC_SPECS",
    };
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = "zcl.toolchain.capture_environment.v1";
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        build_hash_text(&sha, names[i]);
        build_hash_text(&sha, getenv(names[i]));
    }
    sha3_256_finalize(&sha, out);
}

static bool build_toolchain_cache_current(
    const struct build_toolchain_cache *cache,
    const uint8_t environment_root[32])
{
    if (!cache->valid ||
        memcmp(cache->environment_root, environment_root, 32) != 0)
        return false;
    for (size_t i = 0; i < BUILD_TOOLCHAIN_FILE_COUNT; i++) {
        struct stat current;
        if (stat(cache->files[i].path, &current) != 0 ||
            !build_stat_equal(&cache->files[i].stamp, &current))
            return false;
    }
    return true;
}

static bool build_toolchain_capture_uncached(
    struct vcs_toolchain_capsule_v1 *out,
    struct build_toolchain_file files[BUILD_TOOLCHAIN_FILE_COUNT])
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    memset(files, 0,
           sizeof(struct build_toolchain_file) * BUILD_TOOLCHAIN_FILE_COUNT);
    size_t file_count = 0;
    char driver[4096];
    if (!realpath(VCS_BUILD_COMPILER_V1, driver) ||
        strlen(driver) >= sizeof(files[file_count].path))
        return false;
    (void)snprintf(files[file_count].path, sizeof(files[file_count].path),
                   "%s", driver);
    if (!build_sha3_file(driver, out->compiler_driver_sha3,
                         &files[file_count].stamp))
        return false;
    file_count++;
    if (!build_gcc_file("-print-prog-name=cc1", NULL,
                        out->compiler_backend_sha3, &files[file_count++]) ||
        !build_assembler_identity(out->assembler_sha3, &files[file_count++]))
        return false;
    static const char *const sysroot_args[] = {
        "-print-file-name=crt1.o", "-print-file-name=crti.o",
        "-print-file-name=crtn.o",
    };
    if (!build_gcc_aggregate("zcl.toolchain.sysroot.v1", sysroot_args,
                             NULL, 3, out->sysroot_sha3, files,
                             &file_count))
        return false;
    char machine[256], full_version[256], version[256];
    if (!build_gcc_query("-dumpmachine", machine, sizeof(machine)) ||
        !build_gcc_query("-dumpfullversion", full_version,
                         sizeof(full_version)) ||
        !build_gcc_query("-dumpversion", version, sizeof(version)))
        return false;
    struct sha3_256_ctx probes;
    sha3_256_init(&probes);
    static const char probe_domain[] = "zcl.toolchain.target_probes.v1";
    sha3_256_write(&probes, (const uint8_t *)probe_domain,
                   sizeof(probe_domain));
    build_hash_text(&probes, machine);
    build_hash_text(&probes, full_version);
    build_hash_text(&probes, version);
    build_hash_text(&probes, VCS_BUILD_TARGET_V1);
    sha3_256_finalize(&probes, out->target_probes_sha3);
    static const char *const abi_args[] = {
        "-print-libgcc-file-name", "-print-file-name=crtbegin.o",
        "-print-file-name=libc.so.6",
    };
    if (!build_gcc_aggregate("zcl.toolchain.abi_files.v1", abi_args, NULL, 3,
                             out->abi_files_sha3, files, &file_count) ||
        file_count != BUILD_TOOLCHAIN_FILE_COUNT)
        return false;
    (void)snprintf(out->target, sizeof(out->target), "%s",
                   VCS_BUILD_TARGET_V1);
    return true;
}

bool vcs_toolchain_capsule_v1_capture_gcc(
    struct vcs_toolchain_capsule_v1 *out)
{
    if (!out) return false;
    uint8_t environment_root[32];
    build_toolchain_environment_root(environment_root);
    pthread_mutex_lock(&g_toolchain_cache_mu);
    if (build_toolchain_cache_current(&g_toolchain_cache,
                                      environment_root)) {
        *out = g_toolchain_cache.capsule;
        g_toolchain_cache.cache_hits++;
        pthread_mutex_unlock(&g_toolchain_cache_mu);
        return true;
    }
    struct vcs_toolchain_capsule_v1 captured;
    struct build_toolchain_file files[BUILD_TOOLCHAIN_FILE_COUNT];
    bool ok = build_toolchain_capture_uncached(&captured, files);
    g_toolchain_cache.valid = false;
    if (ok) {
        g_toolchain_cache.capsule = captured;
        memcpy(g_toolchain_cache.files, files, sizeof(files));
        memcpy(g_toolchain_cache.environment_root, environment_root, 32);
        g_toolchain_cache.fresh_captures++;
        g_toolchain_cache.valid = true;
        *out = captured;
    }
    pthread_mutex_unlock(&g_toolchain_cache_mu);
    return ok;
}

#ifdef ZCL_TESTING
void vcs_toolchain_capsule_v1_cache_reset_for_test(void)
{
    pthread_mutex_lock(&g_toolchain_cache_mu);
    memset(&g_toolchain_cache, 0, sizeof(g_toolchain_cache));
    pthread_mutex_unlock(&g_toolchain_cache_mu);
}

void vcs_toolchain_capsule_v1_cache_stats_for_test(
    uint64_t *fresh_captures, uint64_t *cache_hits)
{
    pthread_mutex_lock(&g_toolchain_cache_mu);
    if (fresh_captures)
        *fresh_captures = g_toolchain_cache.fresh_captures;
    if (cache_hits)
        *cache_hits = g_toolchain_cache.cache_hits;
    pthread_mutex_unlock(&g_toolchain_cache_mu);
}
#endif

void vcs_build_action_v1_fixed_flags_root(uint8_t out[32])
{
    static const char domain[] = "zcl.build_action.fixed_flags.v1";
    static const char *const values[] = {
        VCS_BUILD_COMPILER_V1, "-x", "cpp-output", "-std=c23", "-O2",
        "-march=x86-64-v3", "-fno-ident", "-c", "/zbuild/src/unit.i",
        "-o", "/zbuild/out/unit.o",
    };
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        build_hash_text(&sha, values[i]);
    sha3_256_finalize(&sha, out);
}

void vcs_build_action_v1_fixed_environment_root(uint8_t out[32])
{
    static const char domain[] = "zcl.build_action.fixed_environment.v1";
    static const char *const values[] = {
        "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C",
        "LANG=C", "TZ=UTC", "HOME=/zbuild/home",
        "SOURCE_DATE_EPOCH=0", "TMPDIR=/zbuild/out",
    };
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        build_hash_text(&sha, values[i]);
    sha3_256_finalize(&sha, out);
}

uint8_t vcs_build_action_v1_work_kind(const char *kind)
{
    if (!kind) return 0;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0)
        return VCS_ZCODE_WORK_BUILD;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0)
        return VCS_ZCODE_WORK_BUILD;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_TEST_V1) == 0)
        return VCS_ZCODE_WORK_TEST;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0)
        return VCS_ZCODE_WORK_FUZZ;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_BENCHMARK_V1) == 0)
        return VCS_ZCODE_WORK_TEST;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1) == 0)
        return VCS_ZCODE_WORK_REPRODUCE;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_REVIEW_V1) == 0)
        return VCS_ZCODE_WORK_REVIEW;
    return 0;
}

bool vcs_build_action_v1_descriptors(
    const char *kind, const char **workdir, const char **output,
    const char **resource)
{
    if (vcs_build_action_v1_work_kind(kind) == 0) return false;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        *workdir = VCS_BUILD_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_OUTPUT_V1;
        *resource = VCS_BUILD_RESOURCE_POLICY_V1;
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0) {
        *workdir = VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_PACKAGE_OUTPUT_V1;
        *resource = VCS_BUILD_PACKAGE_RESOURCE_POLICY_V1;
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_TEST_V1) == 0) {
        *workdir = VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_TEST_OUTPUT_V1;
        *resource = VCS_BUILD_TEST_RESOURCE_POLICY_V1;
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0) {
        *workdir = VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_FUZZ_OUTPUT_V1;
        *resource = VCS_BUILD_FUZZ_RESOURCE_POLICY_V1;
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_BENCHMARK_V1) == 0) {
        *workdir = VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_BENCHMARK_OUTPUT_V1;
        *resource = VCS_BUILD_BENCHMARK_RESOURCE_POLICY_V1;
    } else if (strcmp(kind,
                      VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1) == 0) {
        *workdir = VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_BENCHMARK_REPRODUCE_OUTPUT_V1;
        *resource = VCS_BUILD_BENCHMARK_REPRODUCE_RESOURCE_POLICY_V1;
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_REVIEW_V1) == 0) {
        *workdir = VCS_BUILD_REVIEW_VIRTUAL_ROOT_V1;
        *output = VCS_BUILD_REVIEW_OUTPUT_V1;
        *resource = VCS_BUILD_REVIEW_RESOURCE_POLICY_V1;
    } else {
        return false;
    }
    return true;
}

static void build_action_kind_descriptor_root(
    const char *domain, const char *kind, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    build_hash_text(&sha, kind);
    sha3_256_finalize(&sha, out);
}

bool vcs_build_action_v1_fixed_flags_root_for_kind(
    const char *kind, uint8_t out[32])
{
    if (!out || vcs_build_action_v1_work_kind(kind) == 0) return false;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        vcs_build_action_v1_fixed_flags_root(out);
        return true;
    }
    build_action_kind_descriptor_root(
        "zcl.build_action.fixed_flags.v1", kind, out);
    return true;
}

bool vcs_build_action_v1_fixed_environment_root_for_kind(
    const char *kind, uint8_t out[32])
{
    if (!out || vcs_build_action_v1_work_kind(kind) == 0) return false;
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        vcs_build_action_v1_fixed_environment_root(out);
        return true;
    }
    build_action_kind_descriptor_root(
        "zcl.build_action.fixed_environment.v1", kind, out);
    return true;
}

bool vcs_toolchain_capsule_v1_root(
    const struct vcs_toolchain_capsule_v1 *capsule, uint8_t out[32])
{
    if (!capsule || !out ||
        !build_text_valid(capsule->target, sizeof(capsule->target)) ||
        strcmp(capsule->target, VCS_BUILD_TARGET_V1) != 0)
        return false;
    static const char domain[] = "zcl.toolchain_capsule.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, capsule->compiler_driver_sha3, 32);
    sha3_256_write(&sha, capsule->compiler_backend_sha3, 32);
    sha3_256_write(&sha, capsule->assembler_sha3, 32);
    sha3_256_write(&sha, capsule->sysroot_sha3, 32);
    sha3_256_write(&sha, capsule->target_probes_sha3, 32);
    sha3_256_write(&sha, capsule->abi_files_sha3, 32);
    build_hash_text(&sha, capsule->target);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_build_action_v1_root_for_kind(
    const char *kind, const struct vcs_build_action_v1 *action,
    uint8_t out[32])
{
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!action || !out ||
        !vcs_build_action_v1_descriptors(
            kind, &workdir, &output, &resource) ||
        !build_text_valid(action->target, sizeof(action->target)) ||
        !build_text_valid(action->profile, sizeof(action->profile)) ||
        !build_text_valid(action->virtual_workdir,
                          sizeof(action->virtual_workdir)) ||
        !build_text_valid(action->declared_outputs,
                          sizeof(action->declared_outputs)) ||
        !build_text_valid(action->resource_policy,
                          sizeof(action->resource_policy)) ||
        strcmp(action->target, VCS_BUILD_TARGET_V1) != 0 ||
        strcmp(action->virtual_workdir, workdir) != 0 ||
        strcmp(action->declared_outputs, output) != 0 ||
        strcmp(action->resource_policy, resource) != 0)
        return false;
    static const char domain[] = "zcl.build_action.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    build_hash_text(&sha, kind);
    sha3_256_write(&sha, action->source_sha256, 32);
    sha3_256_write(&sha, action->source_cas_sha3, 32);
    sha3_256_write(&sha, action->input_root_sha3, 32);
    sha3_256_write(&sha, action->toolchain_capsule_sha3, 32);
    sha3_256_write(&sha, action->flags_sha3, 32);
    sha3_256_write(&sha, action->environment_sha3, 32);
    build_hash_text(&sha, action->target);
    build_hash_text(&sha, action->profile);
    build_hash_text(&sha, action->virtual_workdir);
    build_hash_text(&sha, action->declared_outputs);
    build_hash_text(&sha, action->resource_policy);
    build_hash_u64(&sha, action->sequence);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_build_action_v1_root(const struct vcs_build_action_v1 *action,
                              uint8_t out[32])
{
    return vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_V1, action, out);
}
