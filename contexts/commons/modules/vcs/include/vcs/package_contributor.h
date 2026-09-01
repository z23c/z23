/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_contributor — the ZCODE contributor profile projection (slice 4).
 *
 * IDENTITY RULE: the secp256k1 publisher public key is the ONLY
 * authoritative contributor identity. Everything else here is derived or
 * claimed:
 *   - Release facts (release count, latest release, reward address) come
 *     from the SIGNED release envelopes through the package index — they
 *     are authoritative because the envelopes are signed by the key.
 *   - Display names and ZNAM names are POINTERS ONLY (see
 *     services/zcode_pointer.h); they never change who a contributor is or
 *     what a release is. This layer deliberately knows nothing about ZNAM:
 *     pointer facts are attached by the caller so the identity core stays
 *     free of name-registry state.
 *
 * The profile is a REBUILDABLE PROJECTION over the package index (itself a
 * projection over the persisted CAS release wires — the wires stay the
 * truth). Nothing here persists; nothing here mutates. ZCODE Score,
 * rewards, badges, and leaderboard history are later slices that hang off
 * the pubkey identity established here — the struct carries no scoring
 * fields yet on purpose. */

#ifndef ZCL_VCS_PACKAGE_CONTRIBUTOR_H
#define ZCL_VCS_PACKAGE_CONTRIBUTOR_H

#include "vcs/package_index.h"
#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_zcode_contributor {
    char publisher_hex[2u * VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 1u];
    /* Authoritative (from signed releases): */
    uint32_t release_count;
    uint64_t latest_sequence;
    char latest_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char latest_semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char latest_release_id_hex[65];
    char latest_license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    char reward_address[VCS_PACKAGE_RELEASE_REWARD_MAX + 1u]; /* "" = none */
    bool has_znam_pointer; /* latest release carries a ZNAM pointer name */
    char znam_pointer[VCS_PACKAGE_RELEASE_ZNAM_MAX + 1u];
};

/* Project the contributor profile for one publisher pubkey (66 lowercase
 * hex chars) out of the package index: every release signed by the key is
 * counted; the latest-sequence release supplies the name, semver, license,
 * release id, reward address, and optional ZNAM pointer name. Returns true
 * when at least one release by this key is indexed; false (with *out
 * zeroed except publisher_hex) when the key has never published here. */
bool vcs_zcode_contributor_from_index(
    const struct vcs_package_index *index, const char *publisher_hex,
    struct vcs_zcode_contributor *out);

#endif /* ZCL_VCS_PACKAGE_CONTRIBUTOR_H */
