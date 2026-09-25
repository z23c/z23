/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Project-neutral toolchain and preprocessed-C23 action identities. */

#ifndef ZCL_VCS_BUILD_ACTION_H
#define ZCL_VCS_BUILD_ACTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform/toolchain.h"
#include "vcs/proof_ticket.h"

#define VCS_BUILD_TARGET_V1 (platform_toolchain_canonical_target_string())
#define VCS_BUILD_COMPILER_V1 "/usr/bin/cc"
#define VCS_BUILD_ACTION_KIND_V1 "c23.compile.preprocessed.v1"
#define VCS_BUILD_ACTION_KIND_PACKAGE_V1 "c23.package.recipe.v1"
#define VCS_BUILD_ACTION_KIND_TEST_V1 "c23.package.test.v1"
#define VCS_BUILD_ACTION_KIND_FUZZ_V1 "c23.package.fuzz.v1"
#define VCS_BUILD_ACTION_KIND_BENCHMARK_V1 "c23.benchmark.v1"
#define VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1 \
    "c23.benchmark.reproduce.v1"
#define VCS_BUILD_ACTION_KIND_REVIEW_V1 "c23.review.v1"
#define VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1 \
    "z23.resident-proof-child.v1"
#define VCS_BUILD_PACKAGE_PROFILE_LEGACY_V1 "zcode-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_QUICK_V1 "zcode-quick-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_STANDARD_A_V1 "zcode-standard-a-v0.1"
#define VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1 "zcode-standard-b-v0.1"
#define VCS_BUILD_PROFILE_SECURE_CANDIDATE_V1 "secure-candidate-v1"
#define VCS_BUILD_PROFILE_CLEAN_SHADOW_V1 "clean-shadow-v1"
#define VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1 "physical-reproduction-v1"
#define VCS_BUILD_VIRTUAL_ROOT_V1 "/zbuild/src"
#define VCS_BUILD_OUTPUT_V1 "unit.o"
/* Fixed compile child runs with cwd at the isolated build directory. These
 * are the argv/env bytes it receives, independent of the lease locator. */
#define VCS_BUILD_INPUT_ARG_V1 "../src/unit.i"
#define VCS_BUILD_OUTPUT_ARG_V1 "unit.o"
#define VCS_BUILD_ENV_PATH_VALUE_V1 "/usr/bin:/bin"
#define VCS_BUILD_ENV_LC_ALL_VALUE_V1 "C"
#define VCS_BUILD_ENV_TMPDIR_V1 "TMPDIR=."
#define VCS_BUILD_ENV_HOME_V1 "HOME=../src/.home"
#define VCS_BUILD_ENV_LANG_V1 "LANG=C"
#define VCS_BUILD_ENV_TZ_V1 "TZ=UTC"
#define VCS_BUILD_ENV_SOURCE_DATE_EPOCH_V1 "SOURCE_DATE_EPOCH=0"
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
#define VCS_BUILD_RESIDENT_PROOF_VIRTUAL_ROOT_V1 "/zbuild/resident-proof"
#define VCS_BUILD_RESIDENT_PROOF_OUTPUT_V1 "dev-proof-child.v2"
#define VCS_BUILD_RESIDENT_PROOF_RESOURCE_POLICY_V1 \
    "jobs_max=16,wall_timeout_s=900,stack=unlimited,network=ambient,rlimits=none"

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

/* The exact input closure for a local compile or proof action. Callers must
 * derive every root from observed bytes and searches; a missing root refuses
 * the action rather than silently omitting that input class. Negative closure
 * binds searched names that were absent, including __has_include probes. */
struct vcs_build_input_closure_v1 {
    uint8_t positive_sha3[32];
    uint8_t negative_sha3[32];
    uint8_t generated_sha3[32];
    uint8_t build_graph_sha3[32];
    uint8_t harness_sha3[32];
    uint8_t policy_sha3[32];
};

/* Actual ordered argv of the fixed, already-preprocessed compiler action.
 * arch_flag owns any architecture tokens referenced by argv. */
bool vcs_build_action_v1_compile_argv(char arch_flag[128],
                                      const char *argv[14], size_t *argc);

/* The fixed compiler action admits only preprocessed C that cannot inject
 * assembler file reads. Conservative rejection is intentional: inline asm,
 * pragmas, line splices and non-line-marker directives need a read trace. */
struct vcs_build_input_screen_v1 {
    char tail[7];
    size_t tail_len;
    bool line_start;
    bool after_hash;
    bool marker_line;
    bool refused;
};
void vcs_build_input_screen_v1_init(struct vcs_build_input_screen_v1 *screen);
bool vcs_build_input_screen_v1_update(struct vcs_build_input_screen_v1 *screen,
                                      const uint8_t *bytes, size_t len);
bool vcs_build_input_screen_v1_finish(
    const struct vcs_build_input_screen_v1 *screen);

/* Build only the compiler action's canonical proof key. The input is the
 * already-preprocessed unit, so preprocessing searches and generators are
 * outside this action and have named empty roots. It must not be presented
 * as a source-to-binary build key. */
struct vcs_fixed_compile_proof_inputs {
    const struct vcs_toolchain_capsule_v1 *capsule;
    const uint8_t *driver_bytes_sha3;
    const uint8_t *backend_bytes_sha3;
    const uint8_t *assembler_bytes_sha3;
    const uint8_t *runtime_bytes_sha3;
    const uint8_t *verifier_bytes_sha3;
    const uint8_t *input_bytes_sha3;
    const uint8_t *proof_policy_root;
    const char *target;
    const char *resource_policy;
};

bool vcs_build_action_v1_compile_proof_key(
    const struct vcs_fixed_compile_proof_inputs *inputs,
    struct vcs_component_proof_key_v1 *out);

bool vcs_build_input_closure_v1_root(
    const struct vcs_build_input_closure_v1 *closure, uint8_t out[32]);

bool vcs_toolchain_capsule_v1_root(
    const struct vcs_toolchain_capsule_v1 *capsule, uint8_t out[32]);
/* Capture the toolchain capsule by content for the current platform:
 * driver, compiler backend, assembler --version identity, startup/sysroot
 * objects, target probe output, and ABI/runtime libraries.  The set of files
 * is platform-specific (GCC on Linux, Apple Clang on Darwin) and is supplied
 * by lib/platform; this function consumes it without OS-specific branches.
 * Assembler identity is the version string, not the assembler file bytes, so
 * two ordinary hosts with the same assembler version can independently
 * compile.  No mtime participates. */
bool vcs_toolchain_capsule_v1_capture(
    struct vcs_toolchain_capsule_v1 *out);
/* Return a previously captured capsule and its resolved tool paths only when
 * its environment and file stamps are still current. Never probes a compiler
 * or refreshes a stale cache; callers can refuse a speculative reuse. */
bool vcs_toolchain_capsule_v1_cached(
    struct vcs_toolchain_capsule_v1 *out,
    struct platform_toolchain_descriptor *descriptor);
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

/* ---- Action preimage v2: the exact inputs of one build action ----------
 *
 * v1 above names a sealed, fixed action: flags and environment are registry
 * constants. v2 records what one real action actually consumed, as a
 * self-describing byte string that can be stored as a content-addressed
 * object and re-derived by any receiver:
 *
 *   preimage = MAGIC || field(1) || field(2) || ... || field(13)
 *   field    = u8 tag || u32le payload_len || payload
 *   root     = SHA3-256(VCS_ACTION_ROOT_V2_DOMAIN || preimage)
 *
 * Every field is present exactly once, in tag order. Inside a payload, text
 * is u32le length || bytes, counts are u32le, digests are 32 raw bytes. An
 * absent optional field (harness/fixtures/policy root, a stage that does not
 * link) is a zero-length payload under its tag, never 32 zero bytes.
 * Encoding is canonical: the decoder refuses any byte string the encoder
 * would not produce (order, duplicates, trailing bytes, environment names
 * outside the allowlist, and any absolute host path). Where order carries
 * meaning (argv, include search dirs, lookups) it is kept exactly; where it
 * does not (inputs, includer dirs, environment, ABI names) the list must be
 * strictly sorted and a duplicate is refused, never normalized.
 *
 * Paths are repo-relative ("a/b.h", "." for the checkout root) or
 * system-relative ("@sys/usr/include"). Text may name the virtual tokens
 * "@root" (the checkout root), "@out/..." (declared outputs) and the fixed
 * virtual roots in VCS_ACTION_V2_VIRTUAL_ROOTS; nothing else absolute is
 * accepted. No field carries a hostname, uid, pid or timestamp.
 *
 * Tags 14 and 15 are reserved for callee contract roots and an invariants
 * root. v2 framing is closed, so a preimage carrying either is a later
 * schema (a new MAGIC); a v2 decoder refuses it. */
#define VCS_ACTION_PREIMAGE_V2_MAGIC "zcl.action_preimage.v2"
#define VCS_ACTION_ROOT_V2_DOMAIN "zcl.action_root.v2"
#define VCS_ACTION_FIELD_ROOT_V2_DOMAIN "zcl.action_field_root.v2"
#define VCS_ACTION_PREIMAGE_V2_MAX_BYTES (16u * 1024u * 1024u)
#define VCS_ACTION_PREIMAGE_V2_MAX_ITEMS 65536u
#define VCS_ACTION_PREIMAGE_V2_MAX_TEXT 4096u
/* Absolute spellings that name the same virtual location on every host. */
#define VCS_ACTION_V2_VIRTUAL_ROOTS "/zbuild", "/zclassic23"

enum vcs_action_field_v2 {
    VCS_ACTION_FIELD_V2_NONE = 0,
    VCS_ACTION_FIELD_V2_STAGE = 1,
    VCS_ACTION_FIELD_V2_SOURCE = 2,
    VCS_ACTION_FIELD_V2_GENERATED = 3,
    VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP = 4,
    VCS_ACTION_FIELD_V2_TOOLCHAIN = 5,
    VCS_ACTION_FIELD_V2_SYSROOT = 6,
    VCS_ACTION_FIELD_V2_LINKER = 7,
    VCS_ACTION_FIELD_V2_FLAGS = 8,
    VCS_ACTION_FIELD_V2_ENV = 9,
    VCS_ACTION_FIELD_V2_ABI = 10,
    VCS_ACTION_FIELD_V2_HARNESS = 11,
    VCS_ACTION_FIELD_V2_FIXTURES = 12,
    VCS_ACTION_FIELD_V2_POLICY = 13,
    VCS_ACTION_FIELD_V2_COUNT = 14,
    /* Reserved, never emitted by v2 (see above). */
    VCS_ACTION_FIELD_V2_RESERVED_CALLEE_CONTRACTS = 14,
    VCS_ACTION_FIELD_V2_RESERVED_INVARIANTS = 15,
};

/* "stage", "source", "generated", "negative_lookup", "toolchain",
 * "sysroot", "linker", "flags", "env", "abi", "harness", "fixtures",
 * "policy"; NULL for anything else. */
const char *vcs_action_field_v2_name(enum vcs_action_field_v2 field);

/* One source file: canonical path plus SHA3-256 of its bytes. */
struct vcs_action_input_v2 {
    const char *path;
    uint8_t sha3[32];
};

/* One generated input: canonical path, SHA3-256 of its content (with the
 * checkout root spelled "@root"), and the action key of the action that
 * produced it. producer_known=false is the explicit "unknown-producer"
 * marker on the wire (u8 0); it is never an omitted entry. */
struct vcs_action_generated_v2 {
    const char *path;
    uint8_t sha3[32];
    bool producer_known;
    uint8_t producer_action_key[32];
};

enum vcs_action_present_kind_v2 {
    VCS_ACTION_PRESENT_V2_REGULAR = 1, /* followed by the file's SHA3 */
    VCS_ACTION_PRESENT_V2_OTHER = 2,   /* directory, device, dangling link */
};

/* A probed location of one lookup that was observed to exist. `slot`
 * indexes that lookup's probe sequence (see vcs_action_lookup_v2). */
struct vcs_action_present_v2 {
    uint32_t slot;
    uint8_t kind;
    uint8_t sha3[32];
};

/* One include lookup that resolved `name` to hit_dir/name, which must be a
 * source or generated input. Its probe sequence, in order, is:
 *   slots 0 .. I-1        includer_dirs[i]/name for every includer dir
 *                         (the hit's own dir is the hit, never a probe);
 *   slots I .. I+P-1      search_dirs[j]/name for j < search_prefix,
 * with I = includer_dir_count and P = search_prefix. Every probed location
 * is asserted ABSENT unless it is listed in `present` (strictly increasing
 * slots). A search hit has search_dirs[search_prefix] == hit_dir; an
 * includer hit has search_prefix == 0. Lookups keep derivation order (the
 * compiler's inclusion order); a repeated (hit_dir, name) is refused. */
struct vcs_action_lookup_v2 {
    const char *name;
    const char *hit_dir;
    uint32_t search_prefix;
    const struct vcs_action_present_v2 *present;
    size_t present_count;
};

/* The linker as the compiler driver resolves it. links=false (a stage
 * that stops at an object) is a zero-length payload. Otherwise: the ld the
 * driver runs and, for a GCC driver, collect2 (NULL when the driver has
 * none), each by canonical path and SHA3-256 of its bytes, then the link
 * argv in order. */
struct vcs_action_linker_v2 {
    bool links;
    const char *ld;
    uint8_t ld_sha3[32];
    const char *collect2;
    uint8_t collect2_sha3[32];
    const char *const *argv;
    size_t argc;
};

/* The target system root: the driver's --sysroot answer (NULL when it
 * reports none), its built-in include dirs in search order, and the SHA3 of
 * the sysroot/startup object set the toolchain capsule captured. */
struct vcs_action_sysroot_v2 {
    const char *sysroot;
    const char *const *builtin_dirs;
    size_t builtin_dir_count;
    uint8_t objects_sha3[32];
};

/* One allowlisted environment name, in allowlist order. set=false is the
 * explicit "unset" marker (u8 0); set=true carries the value, which may be
 * empty. */
struct vcs_action_env_v2 {
    const char *name;
    bool set;
    const char *value;
};

struct vcs_action_abi_v2 {
    const char *name;
    uint32_t version;
};

struct vcs_action_root_ref_v2 {
    bool present;
    uint8_t root[32];
};

/* Field order of the wire, and the order the table test iterates. */
struct vcs_action_preimage_v2 {
    const char *stage_kind;
    uint32_t stage_version;
    const struct vcs_action_input_v2 *sources;       /* strictly sorted */
    size_t source_count;
    const struct vcs_action_generated_v2 *generated; /* strictly sorted */
    size_t generated_count;
    const char *const *search_dirs;                  /* compiler order */
    size_t search_dir_count;
    const char *const *includer_dirs;                /* strictly sorted */
    size_t includer_dir_count;
    const struct vcs_action_lookup_v2 *lookups;      /* inclusion order */
    size_t lookup_count;
    uint8_t toolchain_root[32];
    struct vcs_action_sysroot_v2 sysroot;
    struct vcs_action_linker_v2 linker;
    const char *const *argv;                         /* order preserved */
    size_t argc;
    const struct vcs_action_env_v2 *env;             /* whole allowlist */
    size_t env_count;
    uint32_t abi_generation;
    const struct vcs_action_abi_v2 *abi;             /* strictly sorted */
    size_t abi_count;
    struct vcs_action_root_ref_v2 harness;
    struct vcs_action_root_ref_v2 fixtures;
    struct vcs_action_root_ref_v2 policy;
};

/* A decoded preimage owns its storage; `view` points into it. */
struct vcs_action_preimage_v2_decoded {
    struct vcs_action_preimage_v2 view;
    void *storage;
};

/* Canonical token checks shared by the encoder, decoder, and derivers. */
bool vcs_action_v2_path_canonical(const char *path, bool allow_dot);
bool vcs_action_v2_name_canonical(const char *name);
bool vcs_action_v2_text_canonical(const char *text);
/* True when a path spelled at text[i] would be read as a path start: the
 * beginning of the text, after one of `=,:;"' ` or after a glued option
 * such as -I/-isystem/-o. Derivers use this to rewrite host spellings to
 * @root/@sys tokens by exactly the rule the canonical check enforces. */
bool vcs_action_v2_path_boundary(const char *text, size_t i);
/* The closed, sorted environment allowlist for v2 compile actions. The ENV
 * field names exactly these, in this order. Anything outside it can never
 * enter a preimage, so it cannot change a root. Changing the list is a new
 * preimage schema. */
const char *const *vcs_action_v2_env_allowlist(size_t *count);
bool vcs_action_v2_env_allowlisted(const char *name, size_t name_len);

/* Encode `in` canonically into a fresh zcl_malloc buffer (free() it). Any
 * non-canonical input is refused with a reason in `why`. */
bool vcs_action_preimage_v2_encode(const struct vcs_action_preimage_v2 *in,
                                   uint8_t **out, size_t *out_len,
                                   char *why, size_t why_len);
/* Strictly parse and validate stored bytes. Release with _decoded_free. */
bool vcs_action_preimage_v2_decode(
    const uint8_t *bytes, size_t len,
    struct vcs_action_preimage_v2_decoded *out, char *why, size_t why_len);
void vcs_action_preimage_v2_decoded_free(
    struct vcs_action_preimage_v2_decoded *decoded);
/* Validate, then SHA3-256(domain || bytes). A non-canonical byte string is
 * refused rather than given a root. */
bool vcs_action_root_v2_from_bytes(const uint8_t *bytes, size_t len,
                                   uint8_t out[32], char *why, size_t why_len);
/* Validate, then SHA3-256(VCS_ACTION_FIELD_ROOT_V2_DOMAIN || u8 tag ||
 * payload) for one field: a per-field root a consumer can bind (flags,
 * environment, toolchain, ...) without the rest of the preimage. */
bool vcs_action_preimage_v2_field_root(const uint8_t *bytes, size_t len,
                                       enum vcs_action_field_v2 field,
                                       uint8_t out[32]);
/* First field (in tag order) whose payload differs between two valid
 * preimages; VCS_ACTION_FIELD_V2_NONE when identical. False when either
 * input is not a valid preimage. */
bool vcs_action_preimage_v2_first_diff(const uint8_t *a, size_t a_len,
                                       const uint8_t *b, size_t b_len,
                                       enum vcs_action_field_v2 *out);

#endif /* ZCL_VCS_BUILD_ACTION_H */
