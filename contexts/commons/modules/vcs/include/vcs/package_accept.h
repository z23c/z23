/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_accept — the node-bound acceptance layer for signed ZCODE
 * package releases. The pure codec (vcs/package_release.h) proves an
 * envelope is well-formed and correctly signed; THIS layer decides whether
 * a verified envelope may enter this node's view of the package network.
 * It is stateful (publisher sequence cursors and publisher-namespace
 * bindings, in-memory) and node-bound (the active chain's params), so it
 * lives outside the pure codec. It still has no filesystem, network,
 * wallet, build, execution, or publication authority: callers own
 * persistence, replay, and any storage consequence of an accept.
 *
 * Acceptance order (the first failed rule names the result):
 *   1. The envelope itself must verify (vcs_package_release_verify —
 *      fields, release id, low-S, ECDSA against the embedded publisher
 *      key). Anything else is ACCEPT_INVALID.
 *   2. chain_id must equal the canonical id of the ACTIVE chain
 *      ("zclassic-" + chainparams strNetworkID, e.g. "zclassic-main").
 *   3. reward_address, when non-empty, must decode as a transparent
 *      address (t1 P2PKH or t3 P2SH, Base58Check version + checksum) of
 *      the active chain. Empty ("no reward") is allowed.
 *   4. The publisher namespace (the part before '/' in the package name)
 *      is bound first-come to a publisher key: the first accepted release
 *      binds it; a later release from a DIFFERENT key claiming the same
 *      namespace is ACCEPT_NAMESPACE.
 *   5. Publisher sequence, per publisher key:
 *        same sequence + same release id  -> ACCEPT_DUPLICATE
 *          (idempotent accept: state is unchanged and this is not an
 *          error — redelivery of an already-accepted release is a no-op);
 *        same sequence + different id     -> ACCEPT_EQUIVOCATION
 *          (the publisher signed two different releases with one
 *          sequence number — a conflict, rejected and never recorded);
 *        lower sequence than the latest   -> ACCEPT_STALE (rejected);
 *        higher sequence                  -> ACCEPT_OK, cursor advances.
 *      Only an ACCEPT_OK release records: it advances the publisher's
 *      sequence cursor and binds its namespace if unbound. A release
 *      rejected at any step records nothing. */

#ifndef ZCL_VCS_PACKAGE_ACCEPT_H
#define ZCL_VCS_PACKAGE_ACCEPT_H

#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Hard bounds on the in-memory state (per open acceptance context). */
#define VCS_PACKAGE_ACCEPT_MAX_PUBLISHERS 4096u
#define VCS_PACKAGE_ACCEPT_MAX_NAMESPACES 4096u

enum vcs_package_accept_result {
    VCS_PACKAGE_ACCEPT_OK = 0,       /* accepted and recorded */
    VCS_PACKAGE_ACCEPT_DUPLICATE,    /* same sequence + same id (no-op) */
    VCS_PACKAGE_ACCEPT_EQUIVOCATION, /* same sequence + different id */
    VCS_PACKAGE_ACCEPT_STALE,        /* below the publisher's cursor */
    VCS_PACKAGE_ACCEPT_CHAIN_ID,     /* not the active chain's id */
    VCS_PACKAGE_ACCEPT_REWARD,       /* not a transparent address here */
    VCS_PACKAGE_ACCEPT_NAMESPACE,    /* namespace owned by another key */
    VCS_PACKAGE_ACCEPT_INVALID,      /* envelope itself does not verify */
    VCS_PACKAGE_ACCEPT_ERR_NULL,     /* null argument */
    VCS_PACKAGE_ACCEPT_ERR_ALLOC,    /* allocation failed */
    VCS_PACKAGE_ACCEPT_ERR_LIMIT,    /* state bound reached */
};

struct vcs_package_accept; /* opaque */

const char *vcs_package_accept_result_string(
    enum vcs_package_accept_result result);

/* The canonical chain id a release must carry on the currently selected
 * chain ("zclassic-" + strNetworkID, e.g. "zclassic-main"). */
bool vcs_package_accept_chain_id(char *out, size_t out_capacity);

struct vcs_package_accept *vcs_package_accept_new(void);
void vcs_package_accept_free(struct vcs_package_accept *accept);

/* Classify one signed release against the node rules and the recorded
 * state, in the frozen order above. ACCEPT_OK advances the publisher's
 * sequence cursor and binds its namespace if unbound; every other result
 * leaves the state untouched. */
enum vcs_package_accept_result vcs_package_accept(
    struct vcs_package_accept *accept,
    const struct vcs_package_release *release);

/* Read-only view of the recorded cursor for one publisher key: the latest
 * accepted sequence and its release id. Returns false when this publisher
 * has never been accepted. */
bool vcs_package_accept_lookup(const struct vcs_package_accept *accept,
                               const uint8_t publisher_pubkey[33],
                               uint64_t *sequence_out,
                               uint8_t release_id_out[32]);

#endif /* ZCL_VCS_PACKAGE_ACCEPT_H */
