/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Derive the zcl.action_preimage.v2 identity (vcs/build_action.h) of one
 * real compile: the exact source closure a compiler depfile names, the
 * include lookups that had to MISS for that closure to be chosen, the
 * normalized argv, the allowlisted environment, the toolchain capsule root,
 * the sysroot, the linker, and the ABI generation. The derivation reads
 * files and stats paths; it runs no compiler and never changes what the
 * build does.
 *
 * Negative lookups. For every dependency, in depfile (inclusion) order,
 * each way the compiler could have reached it is one lookup: rel below
 * search dir K probes search dirs 0..K-1 first; the dependency's own dir
 * (a quote include beside its includer) needs no search dir. Every lookup
 * also probes every other directory of a file in the closure (a
 * conservative superset of "the including file's own dir"). Each probed
 * location is asserted absent, or what is there is recorded. A header that
 * later appears earlier in the search order therefore changes the root
 * before anything recompiles.
 *
 * Conditional tests. __has_include, __has_include_next and __has_embed can
 * change what compiles without adding a dependency. Every closure file that
 * spells one is re-read; each literal name it asks about is one conditional
 * lookup probed at every includer and search dir. A test whose argument is
 * not a literal name misses (conditional_lookup_unbound).
 *
 * Climbing names. A lookup name is the depfile path below a dir, so an
 * #include whose name climbs ("../x.h") is only bound when it is a quote
 * name found beside its includer; any other climbing route misses
 * (include_climb_unbound).
 *
 * Argv is an allowlist: every word must be a flag, a valued option whose
 * value names no unbound file, a compile input in the closure or a
 * declared output. Anything else misses (argv_unrecognised). Environment
 * variables that add search dirs (CPATH, LIBRARY_PATH, ...) miss
 * (env_search_unbound) whenever present.
 */

#ifndef ZCL_DEVLOOP_ACTION_ROOT_H
#define ZCL_DEVLOOP_ACTION_ROOT_H

#include "vcs/build_action.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ZCL_ACTION_ROOT_STAGE_HOTSWAP "c23.compile.hotswap-module"
#define ZCL_ACTION_ROOT_STAGE_HOTSWAP_VERSION 1u
#define ZCL_ACTION_ROOT_STAGE_HOTFORK "c23.compile.hotfork-capsule"
#define ZCL_ACTION_ROOT_STAGE_HOTFORK_VERSION 1u
/* Directory under the dev-artifact content store holding preimage objects
 * (<root hex>.preimage) and the last root per unit (last/<unit>.root). */
#define ZCL_ACTION_ROOT_STORE_LANE "action-preimage-v2"
#define ZCL_ACTION_ROOT_MAX_DEPS 4096u

/* The action key of the action that produced one generated input. */
struct zcl_action_root_producer {
    const char *path;       /* canonical token, e.g. "build/gen/x.h" */
    uint8_t action_key[32];
};

/* The link step of the same action, as the compiler driver resolves it. */
struct zcl_action_root_linker {
    bool links;
    const char *ld;          /* absolute, as `cc -print-prog-name=ld` */
    const char *collect2;    /* absolute, or NULL when the driver has none */
    const char *const *argv; /* link argv exactly as executed */
    size_t argc;
};

struct zcl_action_root_request {
    /* Canonical absolute checkout root (realpath, no trailing slash). */
    const char *root;
    const char *stage_kind;
    uint32_t stage_version;
    /* argv exactly as executed. Host spellings of `root` become "@root",
     * of system prefixes "@sys"; exact matches of virtual_from[i] become
     * virtual_to[i] (declared outputs such as "@out/object"). */
    const char *const *argv;
    size_t argc;
    const char *const *virtual_from;
    const char *const *virtual_to;
    size_t virtual_count;
    /* Compiler depfile (-MD) naming the dependency closure. */
    const char *depfile;
    /* A generated main input the depfile names only by a temporary
     * spelling (the HOT_FORK unity under build/hotswap-fast/.resident-*):
     * recorded first, under the stable repo-relative `virtual_input_token`
     * (which must lie under build/), hashed from `virtual_input_path`. */
    const char *virtual_input_token;
    const char *virtual_input_path;
    /* The compiler's built-in #include <...> dirs, absolute, in order. */
    const char *const *system_dirs;
    size_t system_dir_count;
    /* `cc -print-sysroot`, absolute; NULL or "" when the driver has none. */
    const char *sysroot;
    uint8_t sysroot_objects_sha3[32];
    struct zcl_action_root_linker linker;
    /* Known producers of generated inputs; any other generated input is
     * recorded with the explicit unknown-producer marker. */
    const struct zcl_action_root_producer *producers;
    size_t producer_count;
    /* When set, a generated input with no known producer is a miss
     * (producer_unknown) instead of carrying the unknown-producer marker. */
    bool require_producers;
    /* NULL-terminated NAME=value list; only allowlisted names are kept. */
    const char *const *environ;
    uint8_t toolchain_root[32];
    uint32_t abi_generation;
    const struct vcs_action_abi_v2 *abi;
    size_t abi_count;
    struct vcs_action_root_ref_v2 harness;
    struct vcs_action_root_ref_v2 fixtures;
    struct vcs_action_root_ref_v2 policy;
};

/* Miss codes. An incomplete or non-canonical closure yields no root and
 * exactly one of: request_incomplete, depfile_missing, depfile_unreadable,
 * depfile_malformed, closure_empty, closure_too_large,
 * dependency_outside_repo, dependency_missing, dependency_unreadable,
 * dependency_duplicate, producer_unknown, include_dir_outside_repo,
 * search_class_conflict, search_too_large, search_flag_unsupported,
 * includer_unavailable, lookup_unavailable, conditional_lookup_unbound,
 * include_climb_unbound, argv_unrecognised, env_search_unbound,
 * probe_unreadable,
 * probe_overflow, argv_noncanonical, env_duplicate, env_noncanonical,
 * builtin_dir_noncanonical, sysroot_noncanonical, linker_unavailable,
 * linker_missing, encode_refused, out_of_memory. The hooks add
 * closure_unobserved (the build did not complete), toolchain_unavailable,
 * builtin_dir_overflow (the driver's built-in search list will not fit the
 * hook's capacity), driver_facts_unavailable, argv_unavailable and
 * store_unavailable. */
struct zcl_action_root_result {
    uint8_t root[32];
    char root_hex[65];
    uint8_t *preimage;   /* canonical bytes; zcl_action_root_result_free */
    size_t preimage_len;
    int64_t derive_us;
    uint32_t source_count;
    uint32_t generated_count;
    uint32_t lookups;    /* include lookups recorded */
    uint32_t probes;     /* probed locations actually examined */
    uint32_t present;    /* probed locations that exist */
    /* When derive returns false: a stable miss code (above) and detail.
     * No root is ever produced for an incomplete closure. */
    char miss[40];
    char why[256];
};

bool zcl_action_root_derive(const struct zcl_action_root_request *req,
                            struct zcl_action_root_result *out);
void zcl_action_root_result_free(struct zcl_action_root_result *out);
/* SHA3-256 of a regular file's bytes, memoized by its stat identity once
 * settled (the same digest the derivation records). */
bool zcl_action_root_file_sha3(const char *path, uint8_t out[32]);

/* <ZCL_DEV_ARTIFACT_CACHE or ~/.cache/zclassic23/dev-artifacts>/
 * action-preimage-v2, created if absent. */
bool zcl_action_root_store_dir(char *out, size_t cap);
/* Store the preimage as <root hex>.preimage (content-addressed: the name is
 * the root re-derived from the bytes) and record it as the latest root for
 * `unit`. `cause` receives "first", "hit", the first differing field name
 * (vcs_action_field_v2_name), or "previous_unreadable". */
bool zcl_action_root_record(const char *store_dir, const char *unit,
                            const struct zcl_action_root_result *result,
                            char *cause, size_t cause_len,
                            char *why, size_t why_len);
/* Load a stored preimage and prove its name: the bytes must re-derive the
 * requested root. The caller frees *bytes. */
bool zcl_action_root_load(const char *store_dir, const char *root_hex,
                          uint8_t **bytes, size_t *len,
                          char *why, size_t why_len);

/* The hotload compile hook. Fills the action_root* fields of `receipt` for
 * the module compile and link that zcl_devloop_hotswap_build() runs for
 * `owner` (argv rebuilt by the same recipe as its compile and link steps,
 * closure from the published depfile, or NULL when the build did not
 * complete). Never fails the build: an incomplete closure is recorded as
 * receipt->action_root_miss (a code above) and never as a root. */
struct zcl_devloop_hotswap_build_receipt;
void zcl_devloop_action_root_hotswap(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *ldflags, const char *depfile,
    struct zcl_devloop_hotswap_build_receipt *receipt);
/* The same for a HOT_FORK capsule build (hs_hotfork_build): `unity` is the
 * live capsule unity file, recorded under a stable generated token;
 * `depfile` is the published candidate depfile, or NULL on failure. */
void zcl_devloop_action_root_hotfork(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *unity, const char *depfile,
    struct zcl_devloop_hotswap_build_receipt *receipt);
/* The root the hot-swap / HOT_FORK artifact cache key binds: the same
 * derivation as the hooks above (`unity` NULL for a hot-swap module, the
 * live capsule unity for HOT_FORK), over the given depfile, never stored.
 * False with a stable miss code (above) whenever any input cannot be bound
 * completely; the caller then compiles and caches nothing, never keys. */
bool zcl_devloop_action_root_key(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *ldflags, const char *unity, const char *depfile,
    char root_hex[65], char miss[40]);
/* Append the action_root* fields to a zcl.hotswap_build_receipt.v1 object. */
struct json_value;
void zcl_devloop_action_root_emit(
    struct json_value *receipt_json,
    const struct zcl_devloop_hotswap_build_receipt *build);

/* True when `dir` may be recorded as a built-in include dir by its exact
 * spelling: absolute, shorter than PATH_MAX, and already lexically normal
 * (no "." or ".." segment, no doubled or trailing slash). */
bool zcl_action_root_builtin_dir_canonical(const char *dir);

/* Parse `cc -xc -E -v /dev/null` output between its two search-list
 * markers into up to `dirs_cap` built-in #include <...> directories.
 * Every entry must satisfy zcl_action_root_builtin_dir_canonical, and the
 * list must fit `dirs_cap` entries of PATH_MAX bytes each. A noncanonical
 * entry sets `miss` to "builtin_dir_noncanonical"; an entry longer than a
 * path buffer or more entries than `dirs_cap` set "builtin_dir_overflow".
 * Either is refused (false, *count_out 0), never truncated or filtered
 * while still returning a usable list. `miss` is a 40-byte buffer (may be
 * NULL). Exposed so a captured driver transcript can be replayed by a test
 * without invoking a compiler. */
bool zcl_action_root_parse_builtin_dirs(const char *cc_dash_e_v_output,
                                        char dirs[][PATH_MAX],
                                        size_t dirs_cap, size_t *count_out,
                                        char *miss);

#endif /* ZCL_DEVLOOP_ACTION_ROOT_H */
