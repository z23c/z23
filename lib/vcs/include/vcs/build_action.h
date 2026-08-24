/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Project-neutral toolchain and preprocessed-C23 action identities. */

#ifndef ZCL_VCS_BUILD_ACTION_H
#define ZCL_VCS_BUILD_ACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_BUILD_TARGET_V1 "linux-x86_64-v3"
#define VCS_BUILD_COMPILER_V1 "/usr/bin/cc"
#define VCS_BUILD_ACTION_KIND_V1 "c23.compile.preprocessed.v1"
#define VCS_BUILD_ACTION_KIND_PACKAGE_V1 "c23.package.recipe.v1"
#define VCS_BUILD_ACTION_KIND_TEST_V1 "c23.package.test.v1"
#define VCS_BUILD_ACTION_KIND_FUZZ_V1 "c23.package.fuzz.v1"
#define VCS_BUILD_ACTION_KIND_BENCHMARK_V1 "c23.benchmark.v1"
#define VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1 \
    "c23.benchmark.reproduce.v1"
#define VCS_BUILD_ACTION_KIND_REVIEW_V1 "c23.review.v1"
#define VCS_BUILD_PACKAGE_PROFILE_LEGACY_V1 "zcode-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_QUICK_V1 "zcode-quick-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_STANDARD_A_V1 "zcode-standard-a-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1 "zcode-standard-b-v0.1"
#define VCS_BUILD_PROFILE_SECURE_CANDIDATE_V1 "secure-candidate-v1"
#define VCS_BUILD_PROFILE_CLEAN_SHADOW_V1 "clean-shadow-v1"
#define VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1 "physical-reproduction-v1"
#define VCS_BUILD_VIRTUAL_ROOT_V1 "/zbuild/src"
#define VCS_BUILD_OUTPUT_V1 "unit.o"
#define VCS_BUILD_RESOURCE_POLICY_V1 \
    "cpu=1,cpu_s=120,memory_mb=2048,processes=16,files=64," \
    "file_bytes=268435456,output_bytes=268435456,timeout_s=120,network=0"
#define VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1 "/zbuild/package"
#define VCS_BUILD_PACKAGE_OUTPUT_V1 "build-report"
#define VCS_BUILD_PACKAGE_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=16384,timeout_s=600,network=0"
#define VCS_BUILD_TEST_OUTPUT_V1 "test.evidence.v1"
#define VCS_BUILD_FUZZ_OUTPUT_V1 "fuzz.evidence.v1"
#define VCS_BUILD_BENCHMARK_OUTPUT_V1 "benchmark_result.v1"
#define VCS_BUILD_BENCHMARK_REPRODUCE_OUTPUT_V1 "reproduction.v1"
#define VCS_BUILD_REVIEW_VIRTUAL_ROOT_V1 "/zbuild/review"
#define VCS_BUILD_REVIEW_OUTPUT_V1 "review.v1"
#define VCS_BUILD_TEST_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=2048,timeout_s=120,network=0"
#define VCS_BUILD_FUZZ_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=2048,timeout_s=600,network=0"
#define VCS_BUILD_BENCHMARK_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=4096,timeout_s=600,network=0"
#define VCS_BUILD_BENCHMARK_REPRODUCE_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=4096,timeout_s=600,network=0"
#define VCS_BUILD_REVIEW_RESOURCE_POLICY_V1 \
    "cpu=1,memory_mb=1024,timeout_s=300,network=0"

struct vcs_toolchain_capsule_v1 {
    uint8_t compiler_driver_sha3[32];
    uint8_t compiler_backend_sha3[32];
    uint8_t assembler_sha3[32];
    uint8_t sysroot_sha3[32];
    uint8_t target_probes_sha3[32];
    uint8_t abi_files_sha3[32];
    char target[64];
};

struct vcs_build_action_v1 {
    uint8_t source_sha256[32];
    uint8_t source_cas_sha3[32];
    uint8_t input_root_sha3[32];
    uint8_t toolchain_capsule_sha3[32];
    uint8_t flags_sha3[32];
    uint8_t environment_sha3[32];
    char target[64];
    char profile[32];
    char virtual_workdir[256];
    char declared_outputs[256];
    char resource_policy[256];
    uint64_t sequence;
};

bool vcs_toolchain_capsule_v1_root(
    const struct vcs_toolchain_capsule_v1 *capsule, uint8_t out[32]);
/* Capture the fixed Linux V1 GCC capsule by content: driver, cc1 backend,
 * GNU as --version identity, startup/sysroot objects, target probe output,
 * and ABI libraries. Assembler identity is the version string, not the
 * assembler file bytes, so two ordinary hosts with the same GNU as version
 * can independently compile. No mtime participates. */
bool vcs_toolchain_capsule_v1_capture_gcc(
    struct vcs_toolchain_capsule_v1 *out);
#ifdef ZCL_TESTING
void vcs_toolchain_capsule_v1_cache_reset_for_test(void);
void vcs_toolchain_capsule_v1_cache_stats_for_test(
    uint64_t *fresh_captures, uint64_t *cache_hits);
#endif
/* Domain-tagged SHA3-256 of exact source-manifest bytes. The action slot
 * is still named source_sha256 for existing wires; new identities use SHA3. */
#define VCS_SOURCE_MANIFEST_ID_SCHEMA "zcl.zcode.source_manifest_sha3.v1"
void vcs_source_manifest_id(const uint8_t *wire, size_t len, uint8_t out[32]);

void vcs_build_action_v1_fixed_flags_root(uint8_t out[32]);
void vcs_build_action_v1_fixed_environment_root(uint8_t out[32]);
/* Closed fixed-action registry. The returned work kind uses the canonical
 * vcs_zcode_work_kind wire ids; zero means the kind is not registered. */
uint8_t vcs_build_action_v1_work_kind(const char *kind);
bool vcs_build_action_v1_descriptors(
    const char *kind, const char **workdir, const char **output,
    const char **resource_policy);
bool vcs_build_action_v1_fixed_flags_root_for_kind(
    const char *kind, uint8_t out[32]);
bool vcs_build_action_v1_fixed_environment_root_for_kind(
    const char *kind, uint8_t out[32]);
bool vcs_build_action_v1_root_for_kind(
    const char *kind, const struct vcs_build_action_v1 *action,
    uint8_t out[32]);
bool vcs_build_action_v1_root(const struct vcs_build_action_v1 *action,
                              uint8_t out[32]);

#endif /* ZCL_VCS_BUILD_ACTION_H */
