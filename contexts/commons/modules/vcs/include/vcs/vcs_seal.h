/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_seal — the ZVCS sealed-path guard. "code fearlessly, not recklessly":
 * a defined set of paths (the consensus core and its neighbours) is pinned by
 * a SHA3 commitment; a snapshot that would change any sealed file is REFUSED
 * unless a one-shot unseal token authorizing exactly that new sealset is
 * present. An agent cannot silently mutate consensus.
 *
 * sealset_hash = SHA3(0x24 || concat over the BYTEWISE-SORTED entry hashes of
 * every manifest entry whose path matches a sealed glob). Sorting the entry
 * hashes makes it order-independent and stable.
 *
 * v1 unseal = a one-shot token (this file). v1.1 upgrades the token to an
 * ed25519 owner signature (in-tree crypto) so consent cannot be forged. */

#ifndef ZCL_VCS_SEAL_H
#define ZCL_VCS_SEAL_H

#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum vcs_seal_result {
    VCS_SEAL_OK      = 0,   /* unchanged, or a valid one-shot token was consumed */
    VCS_SEAL_REFUSED = 3,   /* changed with no valid token — maps to CLI exit 3 */
    VCS_SEAL_ERROR   = -1,  /* internal error */
};

/* Load the sealed glob set. From <repo>/.zvcs/sealed_paths (one glob per line,
 * '#' comments and blank lines skipped) if present, else the compiled default
 * set {core/, domain/consensus/, lib/consensus/, core/modules/validation/, core/modules/chain/,
 * core/modules/mining/, engine/jobs/}. *out_globs is a heap array of heap strings. */
bool vcs_seal_load_globs(const char *repo_root, char ***out_globs, size_t *out_n);
void vcs_seal_free_globs(char **globs, size_t n);

/* True iff `path` matches a sealed glob. A glob ending in '/' is a directory
 * prefix; otherwise it is an fnmatch pattern (FNM_PATHNAME). */
bool vcs_seal_path_matches(const char *path, char *const *globs, size_t nglobs);

/* sealset_hash over the entries of m matching any glob. */
bool vcs_sealset_hash(const struct vcs_manifest *m, char *const *globs,
                      size_t nglobs, uint8_t out[32]);

/* Grant a one-shot token authorizing exactly `authorized_sealset`. Own txn. */
bool vcs_seal_grant_unseal(struct vcs_index *idx,
                           const uint8_t authorized_sealset[32]);

/* Check a proposed sealset against the pin. OK when new==pin, or when a token
 * authorizing exactly new_sealset exists (which is then CONSUMED). REFUSED
 * otherwise. When no pin exists yet (first snapshot) returns OK. */
enum vcs_seal_result vcs_seal_check(struct vcs_index *idx,
                                    const uint8_t new_sealset[32]);

/* Read-only variant of vcs_seal_check: identical OK/REFUSED decision (same
 * pin-vs-new_sealset comparison, same token-match rule) but NEVER consumes a
 * matching one-shot token, and never mutates the index. Intended for a
 * caller that must decide whether an operation WOULD be refused before it
 * has done anything irreversible (vcs_revert uses this to refuse a
 * sealed-path change before touching a single worktree file, leaving the
 * later, authoritative — and consuming — vcs_seal_check() inside
 * vcs_snapshot() to actually spend the token once the change really lands).
 * Calling vcs_seal_peek() any number of times has no side effects. */
enum vcs_seal_result vcs_seal_peek(struct vcs_index *idx,
                                   const uint8_t new_sealset[32]);

#define VCS_SEAL_TOKEN_KEY "vcs_unseal_token"

#endif /* ZCL_VCS_SEAL_H */
