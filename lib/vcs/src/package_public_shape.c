/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_public_shape — see vcs/package_public_shape.h. Reads only the
 * public package_store API (no store internals, no store lock held), so a
 * caller may classify while holding its own lock. */

#include "vcs/package_public_shape.h"

#include "base/safe_alloc.h"
#include "vcs/blob_store.h"
#include "vcs/fastobj_carrier.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/package_transport.h"
#include "vcs/source_package_transport.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_output.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHAPE_LOG "vcs.package.public"
#define STORE_SHAPE_PATH_MAX 4400u

/* The carrier's own source copies of the two files the licensed shapes are
 * judged on: the license text, and the root-committed dependency list. */
#define SHAPE_TRANSPORT_LICENSE_PATH \
    VCS_PACKAGE_TRANSPORT_SOURCE_PREFIX VCS_PACKAGE_PUBLISH_LICENSE_PATH
#define SHAPE_TRANSPORT_DEPS_PATH \
    VCS_PACKAGE_TRANSPORT_SOURCE_PREFIX VCS_PACKAGE_DEPS_META_PATH

/* The fastobj carrier is one fixed directory of derived objects; every
 * manifest path must live under it before the carrier proof is run. */
#define SHAPE_FASTOBJ_DIR VCS_FASTOBJ_CARRIER_DIR "/"

/* The closure walk is bounded by the same node budget the dependency lock
 * resolver uses, so a package that can be locked can also be classified. */
#define SHAPE_MAX_CLOSURE VCS_PACKAGE_LOCK_MAX_NODES

const char *vcs_package_public_shape_string(
    enum vcs_package_public_shape shape)
{
    switch (shape) {
    case VCS_PACKAGE_PUBLIC_REFUSED: return "refused";
    case VCS_PACKAGE_PUBLIC_TRANSPORT: return "transport";
    case VCS_PACKAGE_PUBLIC_RELEASE: return "release";
    case VCS_PACKAGE_PUBLIC_SOURCE_BUNDLE: return "source-bundle";
    case VCS_PACKAGE_PUBLIC_BLOB: return "blob";
    case VCS_PACKAGE_PUBLIC_WORK_CONTEXT: return "work-context";
    case VCS_PACKAGE_PUBLIC_WORK_OUTPUT: return "work-output";
    case VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER: return "fastobj-carrier";
    }
    return "unknown";
}

bool vcs_package_public_shape_licensed(enum vcs_package_public_shape shape)
{
    return shape == VCS_PACKAGE_PUBLIC_TRANSPORT ||
           shape == VCS_PACKAGE_PUBLIC_RELEASE;
}

/* Index of `path` in the manifest, or -1. Paths are unique per manifest. */
static long shape_find(const struct vcs_package_manifest *m, const char *path)
{
    for (size_t i = 0; i < m->count; i++)
        if (strcmp(m->files[i].path, path) == 0)
            return (long)i;
    return -1;
}

/* Reassemble one manifest file from the CAS, refusing anything larger than
 * the grammar that will read it allows. Every caller passes the cap of its
 * own wire format, so a hostile manifest cannot make this allocate more
 * than that format could ever legitimately need. NULL on any gap. */
static uint8_t *shape_read_file(struct vcs_package_store *store,
                                const uint8_t root[32],
                                const struct vcs_package_manifest *m,
                                size_t index, uint64_t max_bytes,
                                size_t *out_len)
{
    *out_len = 0;
    const struct vcs_package_file *file = &m->files[index];
    if (file->size == 0 || file->size > max_bytes)
        return NULL;
    uint8_t *buf = zcl_malloc((size_t)file->size, "vcs_public_shape_file");
    if (!buf)
        return NULL;
    size_t written = 0;
    for (uint32_t c = 0; c < file->chunk_count; c++) {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        if (vcs_package_store_get_chunk_at(store, root, (uint32_t)index, c,
                                           &chunk, &chunk_len) !=
                VCS_PACKAGE_STORE_OK ||
            chunk_len > (size_t)file->size - written) {
            free(chunk);
            free(buf);
            return NULL;
        }
        memcpy(buf + written, chunk, chunk_len);
        written += chunk_len;
        free(chunk);
    }
    if (written != (size_t)file->size) {
        free(buf);
        return NULL;
    }
    *out_len = written;
    return buf;
}

/* What one root is, before its dependencies are considered. */
struct shape_eval {
    enum vcs_package_public_shape shape;
    const char *rule;
    struct vcs_package_deps deps; /* declared direct edges; empty otherwise */
};

/* The tail both licensed shapes share.
 *
 * A LICENSE path in the manifest is not license text — an empty file, a
 * placeholder, or someone else's proprietary terms all satisfy "the path
 * exists". So the bytes are read and held against the identifier the signed
 * envelope declares. And the dependency declaration is a manifest member,
 * so the package root already commits it: parsing it here reads exactly the
 * edges the publisher signed, never a second uncommitted database. */
static bool shape_licensed_tail(struct vcs_package_store *store,
                                const uint8_t root[32],
                                const struct vcs_package_manifest *m,
                                const char *license, const char *license_path,
                                const char *deps_path,
                                struct vcs_package_deps *deps_out,
                                const char **rule_out)
{
    vcs_package_deps_init(deps_out);

    long license_index = shape_find(m, license_path);
    if (license_index < 0 || m->files[license_index].size == 0) {
        *rule_out = "license-text-missing";
        return false;
    }
    size_t license_len = 0;
    uint8_t *license_text =
        shape_read_file(store, root, m, (size_t)license_index,
                        VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES,
                        &license_len);
    if (!license_text) {
        *rule_out = "license-text-unreadable";
        return false;
    }
    bool text_ok = vcs_package_release_license_text_matches(
        license, license_text, license_len);
    free(license_text);
    if (!text_ok) {
        *rule_out = "license-text-mismatch";
        return false;
    }

    long deps_index = shape_find(m, deps_path);
    if (deps_index < 0)
        return true; /* no declaration is no dependencies, never an error */
    size_t deps_len = 0;
    uint8_t *deps_wire =
        shape_read_file(store, root, m, (size_t)deps_index,
                        VCS_PACKAGE_DEPS_META_MAX_BYTES, &deps_len);
    if (!deps_wire) {
        *rule_out = "dependency-declaration-unreadable";
        return false;
    }
    enum vcs_package_deps_error derr =
        vcs_package_deps_parse_meta(deps_wire, deps_len, deps_out, NULL, 0);
    free(deps_wire);
    if (derr != VCS_PACKAGE_DEPS_OK) {
        vcs_package_deps_init(deps_out);
        *rule_out = "dependency-declaration-invalid";
        return false;
    }
    return true;
}

/* Re-derive the whole carrier closure from the bytes we hold and require it
 * to hash back to this exact root. vcs_package_transport_build() verifies
 * the signature, enforces the frozen SPDX allowlist, runs the publication
 * rules, and binds release <-> recipe <-> inner manifest; the root
 * comparison binds all of that to the bytes a peer would actually receive.
 * A stapled envelope therefore proves nothing. */
static bool shape_transport_closes(struct vcs_package_store *store,
                                   const uint8_t root[32],
                                   const struct vcs_package_manifest *m,
                                   long release_index,
                                   struct vcs_package_deps *deps_out,
                                   const char **rule_out)
{
    long recipe_index = shape_find(m, VCS_PACKAGE_TRANSPORT_RECIPE_PATH);
    long manifest_index = shape_find(m, VCS_PACKAGE_TRANSPORT_MANIFEST_PATH);
    if (recipe_index < 0 || manifest_index < 0) {
        *rule_out = "carrier-metadata-missing";
        return false;
    }
    size_t release_len = 0, recipe_len = 0, inner_len = 0;
    uint8_t *release =
        shape_read_file(store, root, m, (size_t)release_index,
                        VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, &release_len);
    uint8_t *recipe =
        shape_read_file(store, root, m, (size_t)recipe_index,
                        VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &recipe_len);
    uint8_t *inner =
        shape_read_file(store, root, m, (size_t)manifest_index,
                        VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &inner_len);
    bool closed = false;
    const char *rule = "carrier-metadata-unreadable";
    if (release && recipe && inner) {
        struct vcs_package_transport transport;
        vcs_package_transport_init(&transport);
        enum vcs_package_transport_result r = vcs_package_transport_build(
            release, release_len, recipe, recipe_len, inner, inner_len,
            &transport);
        if (r != VCS_PACKAGE_TRANSPORT_OK) {
            rule = r == VCS_PACKAGE_TRANSPORT_ERR_RELEASE
                       ? "release-unverified"
                       : r == VCS_PACKAGE_TRANSPORT_ERR_BINDING
                             ? "release-binding-failed"
                             : "carrier-closure-failed";
        } else if (memcmp(transport.transport_root, root, 32) != 0) {
            rule = "carrier-root-mismatch";
        } else if (!vcs_package_release_license_allowed(
                       transport.release.license)) {
            /* Unreachable while the envelope grammar owns the allowlist;
             * asserted anyway so the license rule is stated where it is
             * enforced rather than inherited silently. */
            rule = "spdx-license-not-allowlisted";
        } else {
            closed = shape_licensed_tail(
                store, root, m, transport.release.license,
                SHAPE_TRANSPORT_LICENSE_PATH, SHAPE_TRANSPORT_DEPS_PATH,
                deps_out, &rule);
        }
        vcs_package_transport_free(&transport);
    }
    free(release);
    free(recipe);
    free(inner);
    if (!closed)
        *rule_out = rule;
    return closed;
}

/* Does a persisted release envelope name and sign exactly these bytes?
 *
 * The store files a committed manifest under manifests/<root-hex> only
 * after re-deriving that root from the wire, so "the envelope's
 * package_root equals this root" is already the statement that the
 * publisher signed the bytes a peer would receive — no second binding
 * step is needed here. Verification (signature, low-S, and the frozen
 * SPDX allowlist the envelope grammar owns) runs on the candidate itself.
 * Scans releases/ and stops at the first envelope that matches and
 * verifies, copying out the license it declares. */
static bool shape_release_signs(struct vcs_package_store *store,
                                const uint8_t root[32],
                                char license_out[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u])
{
    license_out[0] = '\0';
    const char *zcode_dir = vcs_package_store_root_dir(store);
    if (!zcode_dir)
        return false;
    char dir[STORE_SHAPE_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/releases", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return false;
    DIR *d = opendir(dir);
    if (!d)
        return false; /* no releases yet: nothing is publicly releasable */
    uint8_t *wire = zcl_malloc(VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                               "vcs_public_shape_release");
    bool signed_here = false;
    struct dirent *de;
    while (wire && !signed_here && (de = readdir(d)) != NULL) {
        char path[STORE_SHAPE_PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path))
            continue;
        FILE *f = fopen(path, "rb");
        if (!f)
            continue;
        size_t len = fread(wire, 1, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, f);
        bool trailing = !feof(f);
        fclose(f);
        struct vcs_package_release release;
        if (trailing ||
            vcs_package_release_parse(wire, len, &release) !=
                VCS_PACKAGE_RELEASE_OK ||
            memcmp(release.package_root, root, 32) != 0)
            continue;
        signed_here =
            vcs_package_release_verify(&release) == VCS_PACKAGE_RELEASE_OK &&
            vcs_package_release_license_allowed(release.license);
        if (signed_here)
            memcpy(license_out, release.license, sizeof(release.license));
    }
    free(wire);
    closedir(d);
    return signed_here;
}

/* The ZVCS source carrier: permissive LICENSE text plus a lane receipt signed
 * by the key it names. Signature-against-embedded-key is the same standard
 * the release envelope is held to; what this does NOT do is walk the
 * accepted-work authority chain, which the consumer verifies on checkout. */
static bool shape_source_bundle(struct vcs_package_store *store,
                                const uint8_t root[32],
                                const struct vcs_package_manifest *m,
                                const char **rule_out)
{
    long lane = shape_find(m, VCS_SOURCE_PACKAGE_LANE_PATH);
    if (lane < 0 || shape_find(m, VCS_SOURCE_PACKAGE_AUTHORITY_PATH) < 0) {
        *rule_out = "source-bundle-authority-missing";
        return false;
    }
    long license = shape_find(m, VCS_SOURCE_PACKAGE_LICENSE_PATH);
    if (license < 0 || m->files[license].size == 0) {
        *rule_out = "license-text-missing";
        return false;
    }
    size_t license_len = 0;
    uint8_t *license_text = shape_read_file(
        store, root, m, (size_t)license,
        VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES, &license_len);
    if (!license_text) {
        *rule_out = "license-text-unreadable";
        return false;
    }
    bool license_ok = vcs_package_release_license_text_allowed(
        license_text, license_len);
    free(license_text);
    if (!license_ok) {
        *rule_out = "license-text-not-allowlisted";
        return false;
    }
    size_t lane_len = 0;
    uint8_t *lane_wire =
        shape_read_file(store, root, m, (size_t)lane,
                        VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, &lane_len);
    if (!lane_wire) {
        *rule_out = "lane-receipt-unreadable";
        return false;
    }
    struct vcs_zcode_lane_receipt_v1 receipt;
    memset(&receipt, 0, sizeof(receipt));
    bool signed_ok =
        vcs_zcode_lane_receipt_parse(lane_wire, lane_len, &receipt) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_validate(&receipt) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_verify(&receipt, receipt.signer_pubkey) ==
            VCS_ZCODE_DEV_OK;
    free(lane_wire);
    if (!signed_ok)
        *rule_out = "lane-receipt-unverified";
    return signed_ok;
}

static bool shape_is_blob(const struct vcs_package_manifest *m)
{
    return m->count == 1 && strcmp(m->files[0].path, VCS_BLOB_PATH) == 0 &&
           m->files[0].chunk_count == 1 &&
           m->files[0].size <= (uint64_t)VCS_BLOB_MAX_BYTES;
}

static bool shape_is_work_output(const struct vcs_package_manifest *m)
{
    return m->count == 2 &&
           shape_find(m, VCS_ZCODE_WORK_OUTPUT_ACTION_PATH) >= 0 &&
           shape_find(m, VCS_ZCODE_WORK_OUTPUT_BYTES_PATH) >= 0;
}

/* Every path under the fixed carrier directory picks the carrier branch.
 * The scan is only the dispatch: the bytes are then judged by the
 * consumer's own admit proof, so what this node announces is exactly what
 * a stranger that fetches it re-proves pair by pair. */
static bool shape_is_fastobj_carrier(const struct vcs_package_manifest *m)
{
    if (m->count == 0)
        return false;
    for (size_t i = 0; i < m->count; i++)
        if (strncmp(m->files[i].path, SHAPE_FASTOBJ_DIR,
                    sizeof(SHAPE_FASTOBJ_DIR) - 1u) != 0)
            return false;
    return true;
}

/* Classify one root on its own bytes. Never consults another package, so
 * the closure walk below can call it per node without recursing. */
static void shape_eval_local(struct vcs_package_store *store,
                             const uint8_t root[32], struct shape_eval *out)
{
    out->shape = VCS_PACKAGE_PUBLIC_REFUSED;
    out->rule = "not-tracked";
    vcs_package_deps_init(&out->deps);

    /* Incomplete first: a partial download must never leave this node, not
     * even as the manifest that names what is still missing. */
    struct vcs_package_store_status status;
    if (!vcs_package_store_package_status(store, root, &status) ||
        !status.tracked)
        return;
    if (!status.complete) {
        out->rule = "package-incomplete";
        return;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(store, root, &wire, &wire_len) !=
        VCS_PACKAGE_STORE_OK) {
        free(wire);
        out->rule = "manifest-unreadable";
        return;
    }
    struct vcs_package_manifest m;
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &m);
    free(wire);
    if (!parsed) {
        out->rule = "manifest-unparseable";
        return;
    }

    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    long release_index = shape_find(&m, VCS_PACKAGE_TRANSPORT_RELEASE_PATH);
    if (release_index >= 0) {
        out->rule = "release-unverified";
        if (shape_transport_closes(store, root, &m, release_index, &out->deps,
                                   &out->rule))
            out->shape = VCS_PACKAGE_PUBLIC_TRANSPORT;
    } else if (shape_find(&m, VCS_SOURCE_PACKAGE_MARKER_PATH) >= 0) {
        out->rule = "source-bundle-authority-missing";
        if (shape_source_bundle(store, root, &m, &out->rule))
            out->shape = VCS_PACKAGE_PUBLIC_SOURCE_BUNDLE;
    } else if (shape_is_blob(&m)) {
        out->shape = VCS_PACKAGE_PUBLIC_BLOB;
    } else if (shape_find(&m, VCS_ZCODE_WORK_CONTEXT_PATH) >= 0) {
        out->shape = VCS_PACKAGE_PUBLIC_WORK_CONTEXT;
    } else if (shape_is_work_output(&m)) {
        out->shape = VCS_PACKAGE_PUBLIC_WORK_OUTPUT;
    } else if (shape_is_fastobj_carrier(&m)) {
        char detail[256]; /* verify's refusal text; the rule names the class */
        out->rule = "fastobj-carrier-unverified";
        if (vcs_fastobj_carrier_verify(store, root, detail, sizeof(detail)))
            out->shape = VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER;
    } else if (!shape_release_signs(store, root, license)) {
        out->rule = "no-verified-release";
    } else {
        out->rule = "license-text-missing";
        if (shape_licensed_tail(store, root, &m, license,
                                VCS_PACKAGE_PUBLISH_LICENSE_PATH,
                                VCS_PACKAGE_DEPS_META_PATH, &out->deps,
                                &out->rule))
            out->shape = VCS_PACKAGE_PUBLIC_RELEASE;
    }
    if (out->shape != VCS_PACKAGE_PUBLIC_REFUSED)
        out->rule = vcs_package_public_shape_string(out->shape);
    vcs_package_manifest_free(&m);
}

/* Permissive-license closure. Offering an application publicly is a claim
 * that a stranger can reproduce it, and a stranger cannot reproduce what
 * this node may not hand over. So every root in the transitive dependency
 * graph must itself be a licensed public shape here — held, complete,
 * signed and permissively licensed — or the top package is refused.
 *
 * Iterative, with `walk` doubling as the visited set, so a graph that
 * revisits a shared dependency costs one evaluation and a cycle cannot
 * spin. The budget is the dependency lock's node budget: a package that
 * cannot be locked was never reproducible anyway. */
static bool shape_closure_public(struct vcs_package_store *store,
                                 const uint8_t root[32],
                                 const struct vcs_package_deps *direct,
                                 uint32_t *checked_out, const char **rule_out,
                                 const char **detail_out)
{
    uint8_t walk[SHAPE_MAX_CLOSURE][32];
    size_t walk_n = 0;
    memcpy(walk[walk_n++], root, 32);

    size_t cursor = walk_n;
    const struct vcs_package_deps *edges = direct;
    struct shape_eval node;
    for (;;) {
        for (size_t i = 0; i < edges->count; i++) {
            bool seen = false;
            for (size_t j = 0; j < walk_n && !seen; j++)
                seen = memcmp(walk[j], edges->items[i].root, 32) == 0;
            if (seen)
                continue;
            if (walk_n == SHAPE_MAX_CLOSURE) {
                *rule_out = "dependency-graph-too-large";
                return false;
            }
            memcpy(walk[walk_n++], edges->items[i].root, 32);
        }
        if (cursor == walk_n)
            break;
        shape_eval_local(store, walk[cursor], &node);
        if (!vcs_package_public_shape_licensed(node.shape)) {
            /* The peer-facing rule names the class of failure, not the
             * dependency's own: an asking stranger learns that the graph
             * is not wholly public, never which private byte this node
             * happens to hold. The detail rides the verdict instead, for
             * the operator on this side of the wire. */
            *rule_out = "dependency-not-public";
            *detail_out = node.rule;
            return false;
        }
        cursor++;
        edges = &node.deps;
    }
    *checked_out = (uint32_t)(walk_n - 1);
    return true;
}

enum vcs_package_public_shape vcs_package_public_shape_classify(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_public_verdict *out)
{
    struct vcs_package_public_verdict verdict;
    memset(&verdict, 0, sizeof(verdict));
    verdict.shape = VCS_PACKAGE_PUBLIC_REFUSED;
    verdict.rule = "null-input";

    if (store && package_root) {
        struct shape_eval eval;
        shape_eval_local(store, package_root, &eval);
        verdict.shape = eval.shape;
        verdict.rule = eval.rule;
        if (vcs_package_public_shape_licensed(eval.shape) &&
            eval.deps.count > 0) {
            verdict.dep_scoped = true;
            if (!shape_closure_public(store, package_root, &eval.deps,
                                      &verdict.dependencies_checked,
                                      &verdict.rule,
                                      &verdict.dependency_rule)) {
                verdict.shape = VCS_PACKAGE_PUBLIC_REFUSED;
            }
        }
    }
    if (out)
        *out = verdict;
    return verdict.shape;
}
