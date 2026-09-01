/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_publish — ZCODE package publication validation (slice 3: LOCAL
 * publication only — no P2P gossip, no reward credit, no install, build, or
 * execution of published content). A candidate release + manifest + chunk
 * source is checked against every publication rule BEFORE anything
 * persists; every rejection names the exact failed rule.
 *
 * Rule order (the plan report collects every failure, bounded):
 *   1. Envelope: the release wire must parse canonically and verify
 *      (vcs_package_release_verify — field grammars, the v1 SPDX license
 *      allowlist, low-S, ECDSA against the embedded publisher key).
 *   2. The manifest wire must parse canonically (content.v2 grammar already
 *      rejects absolute paths, traversal, symlink/device/socket/unknown
 *      modes, duplicate canonical paths, and oversized wires — those are
 *      one named rule here: the manifest grammar).
 *   3. The manifest root must equal the release's package_root.
 *   4. The package must fit the v1 64 MiB cap (the store re-enforces).
 *   5. The manifest must carry a top-level LICENSE file (the license text;
 *      the allowlist identity lives in the envelope, rule 1).
 *   6. No hidden executable payload: a file under a dot-prefixed path
 *      segment may not carry the executable mode.
 *   7. Acceptance: replayed against every persisted release envelope
 *      (chain id, reward address, publisher-namespace binding, sequence
 *      classification) — OK and DUPLICATE both pass; anything else fails
 *      with the acceptance result named.
 *   8. Chunks (when a source directory is given): every file exists at its
 *      exact manifest size and every chunk hashes to the committed value.
 *      Plan runs this WITHOUT persisting; commit re-runs it and persists
 *      through the store's verify-before-store discipline.
 *   9. The build recipe (slice 5): a recipe wire is REQUIRED. It must
 *      parse canonically, its fields must validate (the closed declarative
 *      grammar — vcs/package_recipe.h), its root must equal the release
 *      envelope's recipe_root, and every path it references must resolve
 *      in the manifest. The recipe is declarative only: nothing here
 *      compiles or executes anything.
 *
 * The release id is the plan token: it commits to the envelope and through
 * the package root to the manifest and every chunk. Commit re-validates
 * everything; the token is correlation, never authorization.
 *
 * This layer has no wallet, network, chain-write, or node-state authority.
 * Chain binding (chain id, reward address) happens inside the slice-1
 * acceptance layer, which requires chain_params_select() to have run. */

#ifndef ZCL_VCS_PACKAGE_PUBLISH_H
#define ZCL_VCS_PACKAGE_PUBLISH_H

#include "vcs/package_accept.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h" /* VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* v1 package layout constants. */
#define VCS_PACKAGE_PUBLISH_LICENSE_PATH "LICENSE"
#define VCS_PACKAGE_PUBLISH_MAX_FAILURES 24u
/* Persisted releases replayed/loaded from disk (matches the store's
 * VCS_PACKAGE_STORE_MAX_TRACKED bound). */
#define VCS_PACKAGE_PUBLISH_MAX_RELEASES 4096u

enum vcs_package_publish_rule {
    VCS_PACKAGE_PUBLISH_OK = 0,
    VCS_PACKAGE_PUBLISH_RULE_RELEASE_PARSE,  /* release wire not canonical */
    VCS_PACKAGE_PUBLISH_RULE_RELEASE_VERIFY, /* envelope/signature/license */
    VCS_PACKAGE_PUBLISH_RULE_MANIFEST_PARSE, /* manifest grammar rejected */
    VCS_PACKAGE_PUBLISH_RULE_ROOT_MATCH,     /* release root != manifest root */
    VCS_PACKAGE_PUBLISH_RULE_PACKAGE_CAP,    /* package over the 64 MiB cap */
    VCS_PACKAGE_PUBLISH_RULE_LICENSE_TEXT,   /* no LICENSE file in manifest */
    VCS_PACKAGE_PUBLISH_RULE_HIDDEN_EXECUTABLE, /* dot-segment + exec mode */
    VCS_PACKAGE_PUBLISH_RULE_CHUNK_MISSING,  /* source file absent/unreadable */
    VCS_PACKAGE_PUBLISH_RULE_CHUNK_SIZE,     /* source size != manifest size */
    VCS_PACKAGE_PUBLISH_RULE_CHUNK_HASH,     /* chunk bytes != committed hash */
    VCS_PACKAGE_PUBLISH_RULE_ACCEPT,         /* acceptance classification */
    VCS_PACKAGE_PUBLISH_RULE_RECIPE_MISSING, /* no recipe given (required) */
    VCS_PACKAGE_PUBLISH_RULE_RECIPE_PARSE,   /* recipe wire not canonical */
    VCS_PACKAGE_PUBLISH_RULE_RECIPE_VALIDATE,/* recipe field grammar/bound */
    VCS_PACKAGE_PUBLISH_RULE_RECIPE_ROOT_MATCH, /* recipe root != envelope's */
    VCS_PACKAGE_PUBLISH_RULE_RECIPE_PATH,    /* recipe path not in manifest */
    VCS_PACKAGE_PUBLISH_RULE_IO,             /* filesystem failure */
    VCS_PACKAGE_PUBLISH_RULE_ALLOC,          /* allocation failure */
};

const char *vcs_package_publish_rule_string(
    enum vcs_package_publish_rule rule);

struct vcs_package_publish_failure {
    enum vcs_package_publish_rule rule;
    char detail[160]; /* codec error, path, path#chunk, or accept result */
};

struct vcs_package_publish_report {
    struct vcs_package_publish_failure
        failures[VCS_PACKAGE_PUBLISH_MAX_FAILURES];
    size_t failure_count;    /* capped at MAX_FAILURES */
    bool failures_truncated; /* more failures than the cap */
    /* Set when the envelope verifies (rule 1 passed): */
    bool release_ok;
    uint8_t release_id[VCS_PACKAGE_RELEASE_ID_BYTES]; /* the plan token */
    /* Set when a parsed manifest was validated (rules 2-6 ran): */
    bool manifest_ok;
    uint64_t total_bytes;
    uint32_t file_count;
    uint32_t chunk_count;    /* chunks committed by the manifest */
    uint32_t chunks_verified;/* set by verify_chunks */
    bool chunks_checked;     /* verify_chunks ran */
    /* Set by classification (rule 7), valid when release_ok: */
    enum vcs_package_accept_result accept;
    /* Set when the recipe validated (rule 9): root equals the envelope's
     * recipe_root and every referenced path resolves in the manifest. */
    bool recipe_ok;
    uint8_t recipe_root[32];
};

void vcs_package_publish_report_init(struct vcs_package_publish_report *r);

/* Append one failure (bounded; sets failures_truncated past the cap). */
void vcs_package_publish_fail(struct vcs_package_publish_report *r,
                              enum vcs_package_publish_rule rule,
                              const char *detail);

/* Rules 1 and 3-6 over a PARSED release + PARSED manifest (no filesystem).
 * Rule 2 (manifest wire parse) and the release wire parse are the caller's
 * step so the wire-level rejection can be reported with the codec's own
 * error string. release_ok/manifest_ok and the summary fields are filled. */
void vcs_package_publish_validate(
    const struct vcs_package_release *release,
    const struct vcs_package_manifest *manifest,
    struct vcs_package_publish_report *report);

/* Rule 8: verify every chunk of every manifest file against the bytes under
 * <dir>/<path> WITHOUT persisting anything. Appends CHUNK_MISSING /
 * CHUNK_SIZE / CHUNK_HASH / IO failures (bounded). */
void vcs_package_publish_verify_chunks(
    const struct vcs_package_manifest *manifest, const char *dir,
    struct vcs_package_publish_report *report);

/* Read one chunk of one manifest file from <dir>/<path> into buf (must hold
 * VCS_PACKAGE_CHUNK_BYTES). The file's on-disk size must equal the manifest
 * size. Used by commit to feed the store. False with *rule_out set on any
 * failure. */
bool vcs_package_publish_read_chunk(
    const char *dir, const struct vcs_package_file *file,
    uint32_t chunk_index, uint8_t *buf, size_t *len_out,
    enum vcs_package_publish_rule *rule_out);

/* Load every parseable persisted release envelope under
 * <zcode_dir>/releases (bounded at VCS_PACKAGE_PUBLISH_MAX_RELEASES),
 * sorted by (publisher pubkey, publisher sequence, release id) so a
 * stateless caller (a one-shot CLI) sees deterministic classification.
 * `out` must hold out_cap entries. A missing releases/ directory is an
 * empty load, not an error. False on hard I/O or allocation failure. */
bool vcs_package_publish_load_releases(const char *zcode_dir,
                                       struct vcs_package_release *out,
                                       size_t out_cap, size_t *count_out,
                                       size_t *skipped_out);

/* Rule 7 support: replay every persisted release through a fresh acceptance
 * context (deterministic order via load_releases) so a candidate classifies
 * against the same state the store persists, then classify the candidate.
 * The store's own in-memory cursors start empty at open — this replay is
 * what makes a fresh process agree with the persisted history. */
bool vcs_package_publish_replay(const char *zcode_dir,
                                struct vcs_package_accept *accept,
                                size_t *replayed_out);

/* Rule 9 (field validation, root match, manifest membership) over a PARSED
 * release + PARSED manifest + PARSED recipe. The recipe wire parse is the
 * caller's step so the wire-level rejection is reported with the codec's
 * own error string (rule RECIPE_PARSE), and a missing recipe is reported
 * by the caller as RECIPE_MISSING. */
void vcs_package_publish_validate_recipe(
    const struct vcs_package_release *release,
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_recipe *recipe,
    struct vcs_package_publish_report *report);

#endif /* ZCL_VCS_PACKAGE_PUBLISH_H */
