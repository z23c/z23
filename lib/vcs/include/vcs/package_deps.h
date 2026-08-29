/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_deps — the ZCODE dependency declaration + root-pinned lock. This
 * layer is PURE: it parses declaration bytes, walks a bounded acyclic
 * dependency DAG through a caller-supplied loader, and serializes/hashes
 * the resulting lock. It has no filesystem, network, SQLite, compiler, or
 * node-state authority — the install lifecycle service owns all of that.
 *
 * WHERE A DECLARATION COMES FROM, AND WHY IT IS ROOT-COMMITTED: the
 * declaration is the package's own `zcode-package.json` file, which is a
 * MEMBER of the content.v2 manifest. The package root therefore commits to
 * the dependency declaration exactly as it commits to every source byte —
 * there is no second, uncommitted dependency database, and editing a
 * declaration changes the package root.
 *
 * IDENTITY IS THE ROOT, NEVER THE NAME. Each declared dependency MUST
 * carry a 64-hex `root` — that is the identity the lock pins. `name` and
 * `semver`, when present, are advisory LABELS: the resolver reads the real
 * name/semver from the release envelope that the root resolves to and
 * rejects a declaration whose labels disagree (ERR_LABEL_MISMATCH). A name
 * or a version range can therefore only ever SELECT a root that was
 * already written down; it can never become identity.
 *
 * Declaration grammar (bounded JSON, display-shaped but strictly
 * validated; unknown members are ignored so a future field cannot smuggle
 * meaning through a v1 reader, but every member this reader DOES consume
 * is fully checked):
 *
 *   { "schema": 1,
 *     "dependencies": [
 *        { "root": "<64 lowercase hex>",
 *          "name": "publisher/package",     (optional label)
 *          "semver": "1.2.3" }              (optional label)
 *     ] }
 *
 * A missing file, a missing "dependencies" member, and an empty array are
 * all "no dependencies" — never an error. A present-but-malformed member
 * is always a named rejection.
 *
 * Canonical lock wire (all integers little-endian, exactly one legal
 * encoding per lock):
 *   [8  magic = "ZCLLCK\r\n"]
 *   [2  schema_version = 1]
 *   [2  node_count]  count x ([32 root][2 name_len][name][2 semver_len]
 *                             [semver][2 depth][2 direct_deps])
 *
 * Node order is BUILD ORDER: every dependency appears strictly before the
 * dependent that needs it, and the target package is the LAST node. Within
 * one dependent, dependencies are walked in ascending root order (the
 * declaration list is sorted at parse time), so the whole walk — and hence
 * the wire and the lock root — is deterministic.
 *
 * DEPTH IS THE LONGEST PATH FROM THE TARGET, not the shortest and not the
 * distance the walk first reached the node by. It is therefore a valid
 * LAYERING of the DAG: depth(dependency) > depth(dependent) holds on every
 * edge, so a node at level k needs nothing above level k, and max(depth) + 1
 * is the true number of build levels. A shortest-path rule would place a
 * package that is BOTH a direct dependency and a dependency of another
 * dependency at level 1 beside the thing that needs it, which is not a
 * layering and understates the chain. Depth is a pure function of the graph,
 * so two nodes that resolve the same closure agree on it byte for byte.
 *
 * The lock root is SHA3-256 over the frozen domain (hashed WITH its
 * trailing 0x00 byte, the package_manifest convention) followed by the
 * canonical wire. It is the value a build receipt commits, so a build can
 * never be replayed against a different dependency set. */

#ifndef ZCL_VCS_PACKAGE_DEPS_H
#define ZCL_VCS_PACKAGE_DEPS_H

#include "vcs/package_release.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The declaration file's canonical package-relative path (a manifest
 * member, so the package root commits it). */
#define VCS_PACKAGE_DEPS_META_PATH "zcode-package.json"
#define VCS_PACKAGE_DEPS_META_MAX_BYTES (64u * 1024u)
#define VCS_PACKAGE_DEPS_SCHEMA 1
#define VCS_PACKAGE_DEPS_MAX_DIRECT 32u

#define VCS_PACKAGE_LOCK_VERSION 1u
#define VCS_PACKAGE_LOCK_ROOT_DOMAIN "zcl.zcode_lock.v1"
#define VCS_PACKAGE_LOCK_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_LOCK_MAX_NODES 64u
#define VCS_PACKAGE_LOCK_MAX_DEPTH 8u
#define VCS_PACKAGE_LOCK_MAX_WIRE_BYTES (64u * 1024u)

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_package_deps_error {
    VCS_PACKAGE_DEPS_OK = 0,
    VCS_PACKAGE_DEPS_ERR_NULL,           /* null argument */
    VCS_PACKAGE_DEPS_ERR_ALLOC,          /* allocation failure */
    VCS_PACKAGE_DEPS_ERR_META_OVERSIZE,  /* declaration exceeds the cap */
    VCS_PACKAGE_DEPS_ERR_META_JSON,      /* not a JSON object */
    VCS_PACKAGE_DEPS_ERR_META_SCHEMA,    /* "schema" present and != 1 */
    VCS_PACKAGE_DEPS_ERR_DEP_SHAPE,      /* dependencies[] not array/objects */
    VCS_PACKAGE_DEPS_ERR_DEP_ROOT,       /* missing/!64-lowercase-hex/zero */
    VCS_PACKAGE_DEPS_ERR_DEP_NAME,       /* label fails the release grammar */
    VCS_PACKAGE_DEPS_ERR_DEP_SEMVER,     /* label fails the semver grammar */
    VCS_PACKAGE_DEPS_ERR_DEP_DUPLICATE,  /* the same root declared twice */
    VCS_PACKAGE_DEPS_ERR_DEP_COUNT,      /* > MAX_DIRECT direct entries */
    VCS_PACKAGE_DEPS_ERR_SELF,           /* a package depends on itself */
    VCS_PACKAGE_DEPS_ERR_CYCLE,          /* the DAG is not acyclic */
    VCS_PACKAGE_DEPS_ERR_DEPTH,          /* deeper than MAX_DEPTH */
    VCS_PACKAGE_DEPS_ERR_NODE_COUNT,     /* closure exceeds MAX_NODES */
    VCS_PACKAGE_DEPS_ERR_UNRESOLVED,     /* a root the loader cannot resolve */
    VCS_PACKAGE_DEPS_ERR_LABEL_MISMATCH, /* label != the resolved release */
    VCS_PACKAGE_DEPS_ERR_WIRE_MAGIC,     /* bad lock magic */
    VCS_PACKAGE_DEPS_ERR_WIRE_VERSION,   /* lock schema_version != 1 */
    VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED, /* a field runs past the end */
    VCS_PACKAGE_DEPS_ERR_WIRE_TRAILING,  /* bytes after the last node */
    VCS_PACKAGE_DEPS_ERR_WIRE_OVERSIZE,  /* lock wire exceeds the cap */
    VCS_PACKAGE_DEPS_ERR_WIRE_ORDER,     /* nodes not in canonical order */
};

const char *vcs_package_deps_error_string(enum vcs_package_deps_error error);

/* One declared dependency edge. `root` is identity; the labels are
 * advisory and are cross-checked against the resolved release. */
struct vcs_package_dep {
    uint8_t root[32];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];     /* "" when absent */
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u]; /* "" when absent */
};

/* One package's direct dependency list, sorted strictly ascending by
 * root (so it is duplicate-free and the DAG walk is deterministic). */
struct vcs_package_deps {
    struct vcs_package_dep items[VCS_PACKAGE_DEPS_MAX_DIRECT];
    size_t count;
};

void vcs_package_deps_init(struct vcs_package_deps *deps);

/* Parse a `zcode-package.json` declaration. A zero-length declaration (the
 * file is absent) is OK with count 0. *out is cleared on every rejection.
 * `detail` (optional) names the offending entry, bounded. */
enum vcs_package_deps_error vcs_package_deps_parse_meta(
    const uint8_t *text, size_t len, struct vcs_package_deps *out,
    char *detail, size_t detail_cap);

/* ── the lock ───────────────────────────────────────────────────────── */

struct vcs_package_lock_node {
    uint8_t root[32];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    uint16_t depth;       /* longest path from the target; 0 = the target */
    uint16_t direct_deps; /* declared edges out of this node */
};

struct vcs_package_lock {
    /* Build order: dependencies strictly before dependents; the target
     * package is nodes[count - 1]. */
    struct vcs_package_lock_node nodes[VCS_PACKAGE_LOCK_MAX_NODES];
    size_t count;
};

void vcs_package_lock_init(struct vcs_package_lock *lock);

/* The loader the resolver reads the DAG through. It must report the
 * package's REAL name/semver (from its release envelope) and its declared
 * direct dependencies. Returning false means "this root is not resolvable
 * here" and becomes ERR_UNRESOLVED — never a silent skip. */
struct vcs_package_deps_source {
    void *ctx;
    bool (*load)(void *ctx, const uint8_t root[32],
                 char name_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u],
                 char semver_out[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u],
                 struct vcs_package_deps *deps_out);
};

/* Resolve the transitive closure of `target_root` into a build-ordered
 * lock. Rejects self-dependency, every cycle (never silently breaking
 * one), depth/count overflow, an unresolvable root, and a label that
 * disagrees with the resolved release. `detail` (optional) names the
 * offending root/edge. */
enum vcs_package_deps_error vcs_package_lock_resolve(
    const uint8_t target_root[32], const struct vcs_package_deps_source *src,
    struct vcs_package_lock *out, char *detail, size_t detail_cap);

/* Canonical wire + root. serialize allocates *out (caller frees). parse
 * accepts only the exact canonical form and re-checks build order. */
enum vcs_package_deps_error vcs_package_lock_serialize(
    const struct vcs_package_lock *lock, uint8_t **out, size_t *out_len);
enum vcs_package_deps_error vcs_package_lock_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_lock *out);
enum vcs_package_deps_error vcs_package_lock_root(
    const struct vcs_package_lock *lock, uint8_t out[32]);

/* Index of `root` in the lock, or SIZE_MAX when absent. */
size_t vcs_package_lock_find(const struct vcs_package_lock *lock,
                             const uint8_t root[32]);

#endif /* ZCL_VCS_PACKAGE_DEPS_H */
