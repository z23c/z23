/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier 1 in-process hot-swap loader (DEV-ONLY).
 *
 * An AI agent edits an eligible native-command controller, `make hotswap-so`
 * compiles it into a generation .so, and this loader dlopen's it into the
 * RUNNING dev node and re-points the affected native command leaves atomically
 * — no restart. The release binary stays 100% static:
 * every dlopen/dlsym here lives inside `#ifdef ZCL_DEV_BUILD`, so a
 * release build links zero dynamic-loading code (the whole load path
 * compiles down to a stub that returns "hotswap unavailable in release").
 *
 * Generations are NEVER dlclose'd (a deliberate leak): an in-flight call
 * that already entered old code stays valid because the old .so text is
 * never unmapped.
 *
 * See docs/work/HOTSWAP.md for the end-to-end recipe + the ephemerality
 * warning (hot-swaps revert on restart; persist via a normal rebuild).
 */

#ifndef ZCL_HOTSWAP_H
#define ZCL_HOTSWAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration keeps the full JSON header out of consumers that only
 * need the dump signature. */
struct json_value;

/* Resident native-image activation is currently proved only for Linux DEV
 * builds. Other platforms retain the pure admission and status surfaces but
 * fail closed before dynamic loading. */
#if defined(ZCL_DEV_BUILD) && defined(__linux__) && !defined(_WIN32)
#define ZCL_HOTSWAP_NATIVE_AVAILABLE 1
#else
#define ZCL_HOTSWAP_NATIVE_AVAILABLE 0
#endif

static inline bool hotswap_native_activation_available(void)
{
    return ZCL_HOTSWAP_NATIVE_AVAILABLE != 0;
}

static inline const char *hotswap_native_unavailable_stage(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "release";
#endif
}

static inline const char *hotswap_native_unavailable_reason(void)
{
#if defined(_WIN32)
    return "native Windows DLL hot-swap is disabled pending sandbox and "
           "validated immutable PE loading";
#elif defined(__APPLE__)
    return "native macOS hot-swap is disabled pending validated Mach-O "
           "imports and immutable executable-image staging";
#else
    return "hotswap unavailable in release build";
#endif
}

/* Forward decls only — the native command surface (kernel/app types) is never
 * pulled into lib/hotswap. A `native.leaves` generation stages replacement
 * command handlers by dotted path; the concrete request/reply structs are
 * complete only in the controller TU that invokes ZCL_HOTSWAP_EXPORT_LEAVES. */
struct zcl_command_request;
struct zcl_command_reply;
typedef void (*zcl_command_handler_fn)(const struct zcl_command_request *,
                                       struct zcl_command_reply *);

/* The manifest schema stays stable while the host ABI is bumped whenever its
 * vtable layout changes. V4 deliberately admits only native command leaves;
 * artifacts built against the retired layouts fail closed during validation. */
#define ZCL_HOTSWAP_MANIFEST_SCHEMA_V2 2u
#define ZCL_HOTSWAP_HOST_ABI_V4        4u

enum zcl_hotswap_host_capability {
    ZCL_HOTSWAP_CAP_ATOMIC_COMMIT      = UINT64_C(1) << 1,
    ZCL_HOTSWAP_CAP_LEAF_STAGE         = UINT64_C(1) << 2,
};

#define ZCL_HOTSWAP_V4_HOST_CAPABILITIES \
    (ZCL_HOTSWAP_CAP_LEAF_STAGE | ZCL_HOTSWAP_CAP_ATOMIC_COMMIT)

enum zcl_hotswap_quiescence {
    ZCL_HOTSWAP_QUIESCENCE_NONE = 0,
};

/* Host vtable handed to a generation's zcl_hotswap_gen_init(). leaf_stage only
 * appends to the loader-owned transaction; it never publishes. The resident
 * host validates the complete batch and commits one immutable command snapshot
 * only after gen_init and the generation self-test succeed. */
struct zcl_hotswap_host {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t gen;
    uint64_t capabilities;
    bool (*leaf_stage)(const char *path, zcl_command_handler_fn handler);
};

#define ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4 \
    ((uint32_t)sizeof(struct zcl_hotswap_host))

/* The symbol every generation .so must export. */
typedef bool (*zcl_hotswap_gen_init_fn)(const struct zcl_hotswap_host *host);

typedef bool (*zcl_hotswap_self_test_fn)(
    const struct zcl_hotswap_host *host, char *why, size_t why_sz);

/* Exported as the data symbol `zcl_hotswap_manifest_v2`.  It is resolved and
 * validated before gen_init or any other generation function is called. */
struct zcl_hotswap_manifest_v2 {
    uint32_t schema_version;
    uint32_t struct_size;
    uint32_t host_abi_version;
    uint32_t host_struct_size;
    uint64_t required_host_capabilities;
    const char *provider_id;
    const char *build_identity;
    const char *source_identity;
    const char *input_digest;       /* exact inputs, SHA-256 lowercase hex */
    uint32_t state_schema_version;
    bool stateless;
    enum zcl_hotswap_quiescence quiescence;
    const char *mapped_tests_csv;
    const char *probe_tools_csv;
    zcl_hotswap_self_test_fn self_test;
};

#define ZCL_HOTSWAP_GEN_MAX_REPLACED 64

/* Result of a load attempt. Always fully populated (even on failure). */
struct hotswap_load_report {
    bool     ok;                  /* full transaction committed */
    uint32_t gen;                 /* assigned generation id (0 if not loaded) */
    char     error[256];          /* human-readable failure reason ("" on ok) */
    char     replaced[ZCL_HOTSWAP_GEN_MAX_REPLACED][64]; /* tool names published */
    size_t   replaced_count;
    bool     replaced_overflow;   /* reserved; v2 rejects oversized batches */
    char     rejection_stage[64]; /* precheck/manifest/init/self_test/commit */
    char     provider_id[96];
    char     build_identity[96];
    char     source_identity[256];
    char     input_digest[128];
    char     artifact_sha256[65]; /* resident hash of the .so bytes */
};

/* A dotted command path bound to the generation's freshly-compiled handler. */
struct zcl_hotswap_leaf_replacement {
    const char *path;
    zcl_command_handler_fn handler;
};

/* All-or-zero publication callback supplied by the resident native command
 * router. Signature is depended on verbatim by downstream (W1-B/C) code. */
typedef bool (*zcl_hotswap_leaf_commit_cb)(
    void *ctx,
    uint32_t gen,
    const struct zcl_hotswap_leaf_replacement *reps,
    size_t n,
    char *why,
    size_t why_sz);

/* Load a `native.leaves` generation .so and stage its command-handler
 * replacements. The V4 host stages only native leaves and invokes a single
 * all-or-zero commit callback. DEV-ONLY: without ZCL_DEV_BUILD this refuses
 * with an "unavailable" error and performs no dlopen. */
bool hotswap_load_leaves(const char *so_path,
                         const char *datadir,
                         const char *probe_leaf,
                         zcl_hotswap_leaf_commit_cb commit_cb,
                         void *ctx,
                         struct hotswap_load_report *report);

/* ── Pure predicates (compiled in ALL builds; unit-tested w/o dlopen) ── */

/* True if so_path is safe to load: absolute, ends ".so", exists, and its
 * realpath sits under /tmp or a repo build/hotswap dir. On false, `why`
 * (if non-NULL) gets a short reason. */
bool hotswap_path_is_acceptable(const char *so_path, char *why, size_t why_sz);

/* True only for the exact registered worker datadir ~/.zclassic-c23-dev.
 * NULL, empty, canonical, soak, test/copy, and arbitrary paths fail closed. */
bool hotswap_datadir_is_dev(const char *resolved_datadir);

/* Pure fail-closed v2 manifest validation. Does not call generation code. */
bool hotswap_manifest_v2_validate(
    const struct zcl_hotswap_manifest_v2 *manifest,
    char *why,
    size_t why_sz);

/* Number of generations loaded this process (monotone; never decremented). */
size_t hotswap_generation_count(void);

/* `z23 dumpstate hotswap` (dump-state convention).
 * Reentrant-safe; `out` is initialized (json_set_object) by this function. */
bool hotswap_dump_state_json(struct json_value *out, const char *key);

/* ── Generation entrypoint emitter ─────────────────────────────────────
 *
 * Invoke once at file scope in a swap-eligible native command controller TU.
 * Under a generation .so build (-DZCL_HOTSWAP_GEN) it emits the manifest plus
 * zcl_hotswap_gen_init, which stages the controller's freshly-compiled command
 * handlers. In node and release builds it expands to nothing. */
#ifdef ZCL_HOTSWAP_GEN
#ifndef ZCL_HOTSWAP_BUILD_IDENTITY
/* The generation build must bind this independently of the host's runtime
 * getter. Empty fails manifest validation instead of freezing the host build
 * macro into another production translation unit. */
#define ZCL_HOTSWAP_BUILD_IDENTITY ""
#endif
#ifndef ZCL_HOTSWAP_SOURCE_ID
#define ZCL_HOTSWAP_SOURCE_ID __FILE__
#endif
#ifndef ZCL_HOTSWAP_INPUT_DIGEST
/* Fail closed until the generation build supplies a SHA-256 over its exact
 * source/header/flag inputs. The loader rejects this empty sentinel. */
#define ZCL_HOTSWAP_INPUT_DIGEST ""
#endif
#ifndef ZCL_HOTSWAP_MAPPED_TESTS
#define ZCL_HOTSWAP_MAPPED_TESTS "hotswap_loader,hotswap_simnet"
#endif
#ifndef ZCL_HOTSWAP_PROBE_LEAF
#define ZCL_HOTSWAP_PROBE_LEAF "node.status"
#endif

/* The self-test validates the same ABI, size, and capability contract declared
 * by the manifest. A TU invokes exactly one exporter, so its symbols do not
 * collide with another generation provider. */
#define ZCL_HOTSWAP_EXPORT_MANIFEST(host_abi_, host_size_, required_caps_,   \
                                    provider_id_, probe_csv_)                \
    static bool zcl_hotswap_default_self_test(                              \
        const struct zcl_hotswap_host *host, char *why, size_t why_sz)       \
    {                                                                        \
        if (!host || host->abi_version != (host_abi_) ||                    \
            host->struct_size != (host_size_) ||                             \
            (host->capabilities & (required_caps_)) != (required_caps_)) {   \
            if (why && why_sz)                                               \
                (void)snprintf(why, why_sz, "generation host contract mismatch"); \
            return false;                                                    \
        }                                                                    \
        if (why && why_sz) why[0] = '\0';                                   \
        return true;                                                         \
    }                                                                        \
    const struct zcl_hotswap_manifest_v2 zcl_hotswap_manifest_v2 = {        \
        .schema_version = ZCL_HOTSWAP_MANIFEST_SCHEMA_V2,                   \
        .struct_size = sizeof(struct zcl_hotswap_manifest_v2),              \
        .host_abi_version = (host_abi_),                                    \
        .host_struct_size = (host_size_),                                   \
        .required_host_capabilities = (required_caps_),                     \
        .provider_id = (provider_id_),                                      \
        .build_identity = ZCL_HOTSWAP_BUILD_IDENTITY,                       \
        .source_identity = ZCL_HOTSWAP_SOURCE_ID,                           \
        .input_digest = ZCL_HOTSWAP_INPUT_DIGEST,                           \
        .state_schema_version = 0,                                          \
        .stateless = true,                                                   \
        .quiescence = ZCL_HOTSWAP_QUIESCENCE_NONE,                          \
        .mapped_tests_csv = ZCL_HOTSWAP_MAPPED_TESTS,                       \
        .probe_tools_csv = (probe_csv_),                                    \
        .self_test = zcl_hotswap_default_self_test,                         \
    };

/* ── native.leaves (V4 host) generation entrypoint emitter ─────────────
 *
 * Invoke ONCE at file scope in a swap-eligible native command controller TU,
 * passing the controller's static {path,handler} table and its element count:
 *
 *     ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, PARAM_COUNT(k_leaves))
 *
 * (no trailing semicolon). Under a generation .so build it emits the manifest
 * plus zcl_hotswap_gen_init, which stages every command leaf the controller
 * owns via the host's leaf_stage vtable entry — the handlers resolve to the
 * .so's OWN freshly-compiled copies. In node/release builds it expands to
 * nothing. struct zcl_command_request/reply are complete only here, which is
 * why lib/hotswap needs only a forward declaration. */
#define ZCL_HOTSWAP_EXPORT_LEAVES(leaves_arr, leaves_count)                  \
    ZCL_HOTSWAP_EXPORT_MANIFEST(ZCL_HOTSWAP_HOST_ABI_V4,                     \
                                ZCL_HOTSWAP_HOST_STRUCT_SIZE_V4,             \
                                ZCL_HOTSWAP_V4_HOST_CAPABILITIES,            \
                                "native.leaves", ZCL_HOTSWAP_PROBE_LEAF)     \
    bool zcl_hotswap_gen_init(const struct zcl_hotswap_host *host);          \
    bool zcl_hotswap_gen_init(const struct zcl_hotswap_host *host)           \
    {                                                                        \
        if (!host || !host->leaf_stage) return false;                        \
        bool zcl__all = true;                                                \
        for (size_t zcl__i = 0; zcl__i < (size_t)(leaves_count); zcl__i++) { \
            if (!host->leaf_stage((leaves_arr)[zcl__i].path,                 \
                                  (leaves_arr)[zcl__i].handler))             \
                zcl__all = false;                                            \
        }                                                                    \
        return zcl__all;                                                     \
    }
#else
#define ZCL_HOTSWAP_EXPORT_LEAVES(leaves_arr, leaves_count) /* node/release: omitted */
#endif

/* Source compatibility for reload-required controller markers. It never emits
 * a provider, including in generation builds; native leaves are the sole
 * generation-provider class. */
#define ZCL_HOTSWAP_EXPORT_PROVIDER(install_expr) /* node/release: omitted */

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_H */
