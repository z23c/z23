/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical SHA3 identities for toolchains and fixed C23 actions. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "vcs/build_action.h"

#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "util/spawn.h"
#include "util/sync.h"
#include "vcs/zcode_dev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BUILD_TOOLCHAIN_FILE_COUNT 9

struct build_toolchain_file {
    char path[PATH_MAX];
    struct platform_positioned_file_snapshot stamp;
};

struct build_toolchain_cache {
    struct vcs_toolchain_capsule_v1 capsule;
    struct build_toolchain_file files[BUILD_TOOLCHAIN_FILE_COUNT];
    uint8_t environment_root[32];
    uint64_t fresh_captures;
    uint64_t cache_hits;
    bool valid;
};

static zcl_mutex_t g_toolchain_cache_mu;
static zcl_once_t g_toolchain_cache_once = ZCL_ONCE_INIT;
static struct build_toolchain_cache g_toolchain_cache;

static void build_toolchain_cache_init(void)
{
    zcl_mutex_init(&g_toolchain_cache_mu);
}

static bool build_toolchain_cache_lock(void)
{
    if (!zcl_once_call(&g_toolchain_cache_once, build_toolchain_cache_init))
        return false;
    zcl_mutex_lock(&g_toolchain_cache_mu);
    return true;
}

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

static bool build_stat_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool build_sha3_file(const char *path, uint8_t out[32],
                            struct platform_positioned_file_snapshot *stable_stamp)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
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
        size_t want = before.size - offset > sizeof(buf) ? sizeof(buf) :
                      (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&file, buf, want, offset);
        if (got <= 0) { ok = false; break; }
        sha3_256_write(&sha, buf, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
         build_stat_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) return false;
    sha3_256_finalize(&sha, out);
    if (stable_stamp) *stable_stamp = after;
    return true;
}

/* Resolve a TOOL path to the real file it names, and report that file's
 * canonical path and handle-bound stamp.
 *
 * This must FOLLOW symlinks. Every path reaching here is a compiled-in or
 * compiler-reported tool location, and on a Debian-family host those are
 * links by design: /usr/bin/cc points into /etc/alternatives, and the
 * assembler fallback /usr/bin/as points at x86_64-linux-gnu-as. This used
 * to be realpath(), which followed them. Binding the identity to a handle
 * swapped in platform_positioned_file_open(), whose O_NOFOLLOW refuses a
 * symlink outright — so the very first step of a capture, resolving
 * VCS_BUILD_COMPILER_V1, returned ELOOP and NO host with an alternatives-
 * managed cc could capture a toolchain capsule at all.
 *
 * platform_positioned_file_open_resolved() restores realpath()'s reach
 * without touching the no-follow refusal that datadir and market content
 * depend on. The bytes hashed and the stamp compared still come from the
 * handle this opened, so the identity stays handle-bound. */
static bool build_resolve_file(const char *candidate, char resolved[PATH_MAX],
                               struct platform_positioned_file_snapshot *stamp)
{
    if (!candidate)
        return false;
#if !defined(_WIN32)
    char canonical[PATH_MAX];
    if (!realpath(candidate, canonical))
        return false;
    candidate = canonical;
#endif
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool ok = candidate &&
              platform_positioned_file_open_resolved(&file, candidate) &&
              platform_positioned_file_path(&file, resolved, PATH_MAX) &&
              (!stamp || platform_positioned_file_snapshot(&file, stamp));
    platform_positioned_file_close(&file);
    return ok;
}

static bool build_toolchain_query(void *ctx, const char *const argv[],
                                  char *out, size_t cap)
{
    (void)ctx;
    if (zcl_spawn_capture(argv, out, cap, 10000) != 0 || !out[0])
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static void build_hash_pair(struct sha3_256_ctx *sha, const char *label,
                            const uint8_t digest[32])
{
    build_hash_text(sha, label);
    sha3_256_write(sha, digest, 32);
}

static bool build_hash_aggregate(const char *domain,
                                 const char *const labels[], size_t count,
                                 const char paths[][ZCL_TOOLCHAIN_PATH_SIZE],
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
            !build_resolve_file(paths[i], files[*file_count].path,
                                &files[*file_count].stamp) ||
            !build_sha3_file(files[*file_count].path, digest,
                             &files[*file_count].stamp))
            return false;
        (*file_count)++;
        build_hash_pair(&sha, labels[i], digest);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

/* Assembler identity is the driver's --version output, not the assembler file
 * bytes.  Distro patch levels of the same GNU as / Apple Clang assembler
 * change the binary and would otherwise refuse an independent worker on an
 * ordinary second machine.  The file stamp still participates in the capture
 * cache so an assembler upgrade recaptures. */
static bool build_assembler_identity(const char *assembler, uint8_t out[32],
                                     struct build_toolchain_file *file)
{
    if (!file || !build_resolve_file(assembler, file->path, &file->stamp))
        return false;
    char version[512];
    const char *const argv[] = { file->path, "--version", NULL };
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
        struct platform_positioned_file_snapshot current;
        if (!build_resolve_file(cache->files[i].path, (char[PATH_MAX]){0},
                                &current) ||
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

    struct platform_toolchain_descriptor desc;
    if (!platform_toolchain_capture_descriptor(
            build_toolchain_query, NULL, &desc))
        return false;

    size_t file_count = 0;
    if (!build_resolve_file(desc.compiler_driver, files[file_count].path,
                            &files[file_count].stamp) ||
        !build_sha3_file(files[file_count].path, out->compiler_driver_sha3,
                         &files[file_count].stamp))
        return false;
    file_count++;

    if (!build_resolve_file(desc.compiler_backend, files[file_count].path,
                            &files[file_count].stamp) ||
        !build_sha3_file(files[file_count].path, out->compiler_backend_sha3,
                         &files[file_count].stamp))
        return false;
    file_count++;

    if (!build_assembler_identity(desc.assembler, out->assembler_sha3,
                                  &files[file_count]))
        return false;
    file_count++;

    static const char *const sysroot_labels[ZCL_TOOLCHAIN_SYSROOT_COUNT] = {
        "sysroot0", "sysroot1", "sysroot2",
    };
    if (!build_hash_aggregate("zcl.toolchain.sysroot.v1", sysroot_labels,
                              ZCL_TOOLCHAIN_SYSROOT_COUNT,
                              desc.sysroot_files,
                              out->sysroot_sha3, files, &file_count))
        return false;

    struct sha3_256_ctx probes;
    sha3_256_init(&probes);
    static const char probe_domain[] = "zcl.toolchain.target_probes.v1";
    sha3_256_write(&probes, (const uint8_t *)probe_domain,
                   sizeof(probe_domain));
    build_hash_text(&probes, desc.host_triple);
    build_hash_text(&probes, desc.full_version);
    build_hash_text(&probes, desc.short_version);
    build_hash_text(&probes, desc.target);
    if (desc.platform_contract[0] != '\0') {
        static const char contract_label[] = "platform-contract";
        build_hash_text(&probes, contract_label);
        build_hash_text(&probes, desc.platform_contract);
    }
    sha3_256_finalize(&probes, out->target_probes_sha3);

    static const char *const abi_labels[ZCL_TOOLCHAIN_ABI_COUNT] = {
        "abi0", "abi1", "abi2",
    };
    if (!build_hash_aggregate("zcl.toolchain.abi_files.v1", abi_labels,
                              ZCL_TOOLCHAIN_ABI_COUNT,
                              desc.abi_files,
                              out->abi_files_sha3, files, &file_count) ||
        file_count != BUILD_TOOLCHAIN_FILE_COUNT)
        return false;

    (void)snprintf(out->target, sizeof(out->target), "%s", desc.target);
    return true;
}

bool vcs_toolchain_capsule_v1_capture(
    struct vcs_toolchain_capsule_v1 *out)
{
    if (!out) return false;
    uint8_t environment_root[32];
    build_toolchain_environment_root(environment_root);
    if (!build_toolchain_cache_lock()) return false;
    if (build_toolchain_cache_current(&g_toolchain_cache,
                                      environment_root)) {
        *out = g_toolchain_cache.capsule;
        g_toolchain_cache.cache_hits++;
        zcl_mutex_unlock(&g_toolchain_cache_mu);
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
    zcl_mutex_unlock(&g_toolchain_cache_mu);
    return ok;
}

#ifdef ZCL_TESTING
void vcs_toolchain_capsule_v1_cache_reset_for_test(void)
{
    if (!build_toolchain_cache_lock()) return;
    memset(&g_toolchain_cache, 0, sizeof(g_toolchain_cache));
    zcl_mutex_unlock(&g_toolchain_cache_mu);
}

void vcs_toolchain_capsule_v1_cache_stats_for_test(
    uint64_t *fresh_captures, uint64_t *cache_hits)
{
    if (!build_toolchain_cache_lock()) return;
    if (fresh_captures)
        *fresh_captures = g_toolchain_cache.fresh_captures;
    if (cache_hits)
        *cache_hits = g_toolchain_cache.cache_hits;
    zcl_mutex_unlock(&g_toolchain_cache_mu);
}
#endif

void vcs_build_action_v1_fixed_flags_root(uint8_t out[32])
{
    static const char domain[] = "zcl.build_action.fixed_flags.v1";
    char arch_flag[64];
    if (!platform_toolchain_architecture_flag(arch_flag, sizeof(arch_flag)))
        arch_flag[0] = '\0';
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    build_hash_text(&sha, VCS_BUILD_COMPILER_V1);
    build_hash_text(&sha, "-x");
    build_hash_text(&sha, "cpp-output");
    build_hash_text(&sha, "-std=c23");
    build_hash_text(&sha, "-O2");
    if (arch_flag[0])
        build_hash_text(&sha, arch_flag);
    build_hash_text(&sha, "-fno-ident");
    build_hash_text(&sha, "-c");
    build_hash_text(&sha, "/zbuild/src/unit.i");
    build_hash_text(&sha, "-o");
    build_hash_text(&sha, "/zbuild/out/unit.o");
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
