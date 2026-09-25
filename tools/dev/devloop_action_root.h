/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Derive the zcl.action_preimage.v2 identity (vcs/build_action.h) of one
 * real compile: the exact source closure a compiler depfile names, the
 * include lookups that had to MISS for that closure to be chosen, the
 * normalized argv, the allowlisted environment, the toolchain capsule root,
 * and the ABI generation. The derivation reads files and stats paths; it
 * runs no compiler and never changes what the build does.
 *
 * Negative lookups. For a dependency found as dirK/rel, every search dir J
 * before K, and every directory of a file in the closure (a conservative
 * superset of "the including file's own dir" for quote includes), is a
 * probed location (dirJ, rel). The preimage asserts each probed location
 * absent, or records what is there. A header that later appears earlier in
 * the search order therefore changes the root before anything recompiles.
 */

#ifndef ZCL_DEVLOOP_ACTION_ROOT_H
#define ZCL_DEVLOOP_ACTION_ROOT_H

#include "vcs/build_action.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_ACTION_ROOT_STAGE_HOTSWAP "c23.compile.hotswap-module"
#define ZCL_ACTION_ROOT_STAGE_HOTSWAP_VERSION 1u
/* Directory under the dev-artifact content store holding preimage objects
 * (<root hex>.preimage) and the last root per unit (last/<unit>.root). */
#define ZCL_ACTION_ROOT_STORE_LANE "action-preimage-v2"
#define ZCL_ACTION_ROOT_MAX_DEPS 4096u

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
    /* The compiler's built-in #include <...> dirs, absolute, in order. */
    const char *const *system_dirs;
    size_t system_dir_count;
    /* NULL-terminated NAME=value list; only allowlisted names are kept. */
    const char *const *environ;
    uint8_t toolchain_root[32];
    const struct vcs_action_abi_v2 *abi;
    size_t abi_count;
    struct vcs_action_root_ref_v2 harness;
    struct vcs_action_root_ref_v2 fixtures;
    struct vcs_action_root_ref_v2 policy;
};

struct zcl_action_root_result {
    uint8_t root[32];
    char root_hex[65];
    uint8_t *preimage;   /* canonical bytes; zcl_action_root_result_free */
    size_t preimage_len;
    int64_t derive_us;
    uint32_t source_count;
    uint32_t generated_count;
    uint32_t probe_names;
    uint32_t probes;     /* probed locations actually examined */
    uint32_t present;    /* probed locations that exist */
    char why[256];       /* refusal reason when derive returns false */
};

bool zcl_action_root_derive(const struct zcl_action_root_request *req,
                            struct zcl_action_root_result *out);
void zcl_action_root_result_free(struct zcl_action_root_result *out);

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
 * the module compile that zcl_devloop_hotswap_build() runs for `owner`
 * (argv rebuilt by the same recipe as its compile step, closure from the
 * published depfile). Never fails the build: a refusal is recorded in
 * receipt->action_root_refused. */
struct zcl_devloop_hotswap_build_receipt;
void zcl_devloop_action_root_hotswap(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *depfile, struct zcl_devloop_hotswap_build_receipt *receipt);
/* Append the action_root* fields to a zcl.hotswap_build_receipt.v1 object. */
struct json_value;
void zcl_devloop_action_root_emit(
    struct json_value *receipt_json,
    const struct zcl_devloop_hotswap_build_receipt *build);

#endif /* ZCL_DEVLOOP_ACTION_ROOT_H */
