/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_public_shape — the admission rule for offering a locally held
 * content.v2 root to strangers. Hosting is opt-in (-packagehost=1); this
 * decides what an opted-in host may announce and serve once it is on.
 *
 * DEFAULT REFUSE. The store tracks every root the node has ever admitted:
 * packages it published, carriers it fetched, in-flight downloads, work
 * exchanged with peers, and the inner package roots reconstructed out of a
 * carrier. Completeness alone used to make all of them announceable and
 * serveable. It does not any more. A root reaches the public swarm only by
 * matching one of the closed set of shapes below; everything else is
 * refused by name.
 *
 *   TRANSPORT     a zcode package transport carrier. Its own
 *                 zcl.zcode_release.v1 envelope must verify against the
 *                 publisher key it names, its SPDX identifier must be on
 *                 the frozen v1 allowlist, its sources must carry LICENSE
 *                 text that IS that license, and release, recipe and
 *                 inner manifest must bind to each other and to this
 *                 exact root. That whole closure is re-derived here from
 *                 the stored bytes with vcs_package_transport_build();
 *                 nothing is taken on trust from the fetch that
 *                 delivered it.
 *   RELEASE       the inner package a carrier reconstructs into: a plain
 *                 content.v2 root that a persisted zcl.zcode_release.v1
 *                 envelope names and signs. Same requirements as
 *                 TRANSPORT, proved against the envelope rather than
 *                 against a carrier, because the manifest root the store
 *                 filed these bytes under IS the root the publisher
 *                 signed.
 *   SOURCE_BUNDLE the ZVCS source carrier an accepted work publishes. It
 *                 carries root-committed top-level LICENSE text matching
 *                 the frozen permissive allowlist and a lane receipt signed
 *                 by the key that receipt names, both checked here. The full
 *                 accepted-work authority chain is
 *                 NOT re-derived at serve time — proving it means
 *                 reconstructing the tree
 *                 (vcs_source_package_reconstruct_verify), which is the
 *                 consumer's step on checkout, not a per-WANT one.
 *   BLOB          the frozen one-file 8 KiB blob shape. Bytes only, by
 *                 contract: it carries no authorship claim and cannot
 *                 carry a source tree. lib/zid asks whether the document
 *                 inside is genuine, after the bytes arrive.
 *   WORK_CONTEXT  one fixed build action a requester sent to a worker.
 *   WORK_OUTPUT   the action-bound output a worker returned.
 *   TASK_CONTEXT  one posted dev task: the unsigned three-file carrier
 *                 (task.wire / goal.bin / proof-policy.wire). Like the
 *                 work shapes, the serve-time proof is the consumer's own
 *                 admit (vcs_zcode_task_context_admit): the fetched bytes
 *                 re-derive the task root and hash-check the goal and
 *                 policy, and the signed POINTER that led here is what
 *                 carries authorship.
 *   FASTOBJ_CARRIER
 *                 a zcl.fastobj.v1 object-set carrier: DERIVED
 *                 compile-cache artifacts, not authored source, and
 *                 content-addressed end to end. It carries no authorship
 *                 claim and cannot carry a source tree. The serve-time
 *                 proof is exactly the consumer's own admit proof
 *                 (vcs_fastobj_carrier_verify): every entry re-derives —
 *                 each sidecar re-hashes to the key it is filed under,
 *                 each object re-hashes to its sidecar's object_sha3 — so
 *                 a stranger that fetches one re-proves every byte
 *                 independently before any cache trusts it. It is NOT
 *                 licensed content and carries no dependency graph, so
 *                 neither license rule nor closure applies.
 *
 * The two work shapes are admitted because they move between peers that
 * have already accepted each other's SIGNED work frames, and are fetched
 * directly from that authenticated sender rather than off a broadcast.
 * They are NOT licensed content and this layer does not claim they are:
 * the work node's own admission is what governs them. Stated plainly so
 * nobody reads this rule as more than it is.
 *
 * TWO RULES APPLY TO BOTH ENVELOPE-LICENSED PACKAGE SHAPES.
 *
 * The license text must be the license. A LICENSE path in a manifest is
 * not license text: an empty file, a placeholder, or a proprietary EULA
 * all satisfy "the path exists". The bytes are read and held against the
 * identifier the signed envelope declares
 * (vcs_package_release_license_text_matches). That does not prove the
 * copy is unmodified — no substring test could — but "declares MIT,
 * ships something that cannot be MIT" no longer passes. SOURCE_BUNDLE has
 * no separate envelope SPDX field, so its committed LICENSE bytes must match
 * at least one profile from that same authority.
 *
 * PERMISSIVE-LICENSE CLOSURE. Offering an application publicly is a claim
 * that a stranger can reproduce it, and nobody can reproduce what this
 * node may not hand over. So the transitive dependency graph — read from
 * the root-committed zcode-package.json, never from a second uncommitted
 * database — must be public all the way down: every dependency root must
 * itself be held here, complete, signed and permissively licensed, or the
 * top package is refused. The walk is iterative and bounded by the
 * dependency lock's node budget, so shared dependencies cost one
 * evaluation and a cycle cannot spin.
 *
 * That is deliberately not "every node stores every package". It is "a
 * node offers only what it can actually deliver in full".
 *
 * A refusal is never silence. Every REFUSED verdict comes with a static
 * rule string naming which requirement failed. A dependency failure is
 * reported as the class `dependency-not-public` rather than the
 * dependency's own rule: the asking peer learns that the graph is not
 * wholly public, not which private byte this node happens to hold. The
 * detail goes to the local log. */

#ifndef ZCL_VCS_PACKAGE_PUBLIC_SHAPE_H
#define ZCL_VCS_PACKAGE_PUBLIC_SHAPE_H

#include <stdbool.h>
#include <stdint.h>

struct vcs_package_store;

enum vcs_package_public_shape {
    VCS_PACKAGE_PUBLIC_REFUSED = 0,  /* never announce, never serve */
    VCS_PACKAGE_PUBLIC_TRANSPORT,    /* signed, permissively licensed */
    VCS_PACKAGE_PUBLIC_RELEASE,      /* the inner package a release names */
    VCS_PACKAGE_PUBLIC_SOURCE_BUNDLE, /* signed ZVCS accepted-work carrier */
    VCS_PACKAGE_PUBLIC_BLOB,         /* one-file bytes-only object */
    VCS_PACKAGE_PUBLIC_WORK_CONTEXT, /* one fixed build action */
    VCS_PACKAGE_PUBLIC_WORK_OUTPUT,  /* action-bound work output */
    VCS_PACKAGE_PUBLIC_TASK_CONTEXT, /* one posted dev task, unsigned */
    VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER, /* derived compile-cache objects */
};

const char *vcs_package_public_shape_string(
    enum vcs_package_public_shape shape);

/* The two dependency-bearing package shapes. Source bundles enforce the same
 * permissive text authority but do not satisfy package dependency edges. */
bool vcs_package_public_shape_licensed(enum vcs_package_public_shape shape);

struct vcs_package_public_verdict {
    enum vcs_package_public_shape shape;
    const char *rule; /* static; never NULL after a classify call */
    /* True when the verdict also rests on OTHER packages in the store, so
     * a caller caching it must invalidate on any store mutation, not only
     * on this package's own. False for every self-contained verdict. */
    bool dep_scoped;
    uint32_t dependencies_checked; /* distinct roots in the closure walk */
    /* On `dependency-not-public`, the dependency's own failed rule — for
     * the operator on this side of the wire. NULL otherwise. Never sent to
     * the peer that asked. */
    const char *dependency_rule;
};

/* Classify one tracked root against the rule above, reading only bytes the
 * store already holds. Returns REFUSED for an untracked, incomplete or
 * unrecognized root, for a carrier whose closure does not re-derive, and
 * for a licensed package whose dependency graph is not public here.
 * `*out` (when non-NULL) receives the full verdict. */
enum vcs_package_public_shape vcs_package_public_shape_classify(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_public_verdict *out);

#endif /* ZCL_VCS_PACKAGE_PUBLIC_SHAPE_H */
