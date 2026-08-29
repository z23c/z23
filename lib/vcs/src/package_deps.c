/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_deps — implementation of the ZCODE dependency declaration + the
 * root-pinned lock declared in vcs/package_deps.h. Pure bytes and a
 * caller-supplied loader: no filesystem, no network, no compiler, no
 * process. Identity is always the 32-byte package root; a name or a
 * version only ever SELECTS a root that was already written down. */

#include "vcs/package_deps.h"

#include "base/hex.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEPS_LOG "vcs.deps"

static const uint8_t lock_wire_magic[VCS_PACKAGE_LOCK_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'L', 'C', 'K', '\r', '\n' };
static const uint8_t lock_root_domain[] = VCS_PACKAGE_LOCK_ROOT_DOMAIN;

const char *vcs_package_deps_error_string(enum vcs_package_deps_error error)
{
    switch (error) {
    case VCS_PACKAGE_DEPS_OK: return "ok";
    case VCS_PACKAGE_DEPS_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_DEPS_ERR_ALLOC: return "allocation-failure";
    case VCS_PACKAGE_DEPS_ERR_META_OVERSIZE: return "declaration-oversize";
    case VCS_PACKAGE_DEPS_ERR_META_JSON: return "declaration-not-json-object";
    case VCS_PACKAGE_DEPS_ERR_META_SCHEMA: return "declaration-schema";
    case VCS_PACKAGE_DEPS_ERR_DEP_SHAPE: return "dependency-entry-shape";
    case VCS_PACKAGE_DEPS_ERR_DEP_ROOT: return "dependency-root";
    case VCS_PACKAGE_DEPS_ERR_DEP_NAME: return "dependency-name-label";
    case VCS_PACKAGE_DEPS_ERR_DEP_SEMVER: return "dependency-semver-label";
    case VCS_PACKAGE_DEPS_ERR_DEP_DUPLICATE: return "dependency-duplicate-root";
    case VCS_PACKAGE_DEPS_ERR_DEP_COUNT: return "dependency-count-bound";
    case VCS_PACKAGE_DEPS_ERR_SELF: return "dependency-self";
    case VCS_PACKAGE_DEPS_ERR_CYCLE: return "dependency-cycle";
    case VCS_PACKAGE_DEPS_ERR_DEPTH: return "dependency-depth-bound";
    case VCS_PACKAGE_DEPS_ERR_NODE_COUNT: return "dependency-node-bound";
    case VCS_PACKAGE_DEPS_ERR_UNRESOLVED: return "dependency-unresolved-root";
    case VCS_PACKAGE_DEPS_ERR_LABEL_MISMATCH: return "dependency-label-mismatch";
    case VCS_PACKAGE_DEPS_ERR_WIRE_MAGIC: return "lock-wire-magic";
    case VCS_PACKAGE_DEPS_ERR_WIRE_VERSION: return "lock-wire-version";
    case VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED: return "lock-wire-truncated";
    case VCS_PACKAGE_DEPS_ERR_WIRE_TRAILING: return "lock-wire-trailing";
    case VCS_PACKAGE_DEPS_ERR_WIRE_OVERSIZE: return "lock-wire-oversize";
    case VCS_PACKAGE_DEPS_ERR_WIRE_ORDER: return "lock-wire-order";
    }
    return "unknown-error";
}

void vcs_package_deps_init(struct vcs_package_deps *deps)
{
    if (deps)
        memset(deps, 0, sizeof(*deps));
}

void vcs_package_lock_init(struct vcs_package_lock *lock)
{
    if (lock)
        memset(lock, 0, sizeof(*lock));
}

static void deps_detail(char *detail, size_t cap, const char *fmt, ...)
{
    if (!detail || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(detail, cap, fmt, ap);
    va_end(ap);
}

static bool deps_root_is_zero(const uint8_t root[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= root[i];
    return acc == 0;
}

/* A label is printable ASCII within its field bound. The real grammar is
 * enforced transitively: the label must EQUAL the resolved release's field,
 * and that release already passed vcs_package_release_validate(). */
static bool deps_label_ok(const char *s, size_t cap)
{
    size_t n = strlen(s);
    if (n == 0 || n >= cap)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21u || c > 0x7eu)
            return false;
    }
    return true;
}

/* Insert one edge in strictly ascending root order; a duplicate root is a
 * rejection, never a silent merge. */
static enum vcs_package_deps_error deps_insert(struct vcs_package_deps *deps,
                                              const struct vcs_package_dep *e)
{
    if (deps->count >= VCS_PACKAGE_DEPS_MAX_DIRECT)
        return VCS_PACKAGE_DEPS_ERR_DEP_COUNT;
    size_t pos = 0;
    while (pos < deps->count) {
        int cmp = memcmp(e->root, deps->items[pos].root, 32);
        if (cmp == 0)
            return VCS_PACKAGE_DEPS_ERR_DEP_DUPLICATE;
        if (cmp < 0)
            break;
        pos++;
    }
    for (size_t i = deps->count; i > pos; i--)
        deps->items[i] = deps->items[i - 1];
    deps->items[pos] = *e;
    deps->count++;
    return VCS_PACKAGE_DEPS_OK;
}

enum vcs_package_deps_error vcs_package_deps_parse_meta(
    const uint8_t *text, size_t len, struct vcs_package_deps *out,
    char *detail, size_t detail_cap)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null dependency-declaration output");
    vcs_package_deps_init(out);
    if (len == 0)
        return VCS_PACKAGE_DEPS_OK; /* no declaration file: no dependencies */
    if (!text)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null dependency-declaration text with len %zu", len);
    if (len > VCS_PACKAGE_DEPS_META_MAX_BYTES) {
        deps_detail(detail, detail_cap, "%zu bytes > %u cap", len,
                    VCS_PACKAGE_DEPS_META_MAX_BYTES);
        return VCS_PACKAGE_DEPS_ERR_META_OVERSIZE;
    }

    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, (const char *)text, len) || doc.type != JSON_OBJ) {
        json_free(&doc);
        return VCS_PACKAGE_DEPS_ERR_META_JSON;
    }
    enum vcs_package_deps_error err = VCS_PACKAGE_DEPS_OK;
    const struct json_value *schema = json_get(&doc, "schema");
    if (schema && (schema->type != JSON_INT ||
                   json_get_int(schema) != VCS_PACKAGE_DEPS_SCHEMA))
        err = VCS_PACKAGE_DEPS_ERR_META_SCHEMA;

    const struct json_value *deps = err == VCS_PACKAGE_DEPS_OK
                                        ? json_get(&doc, "dependencies")
                                        : NULL;
    if (err == VCS_PACKAGE_DEPS_OK && deps && deps->type != JSON_ARR)
        err = VCS_PACKAGE_DEPS_ERR_DEP_SHAPE;
    if (err == VCS_PACKAGE_DEPS_OK && deps) {
        size_t n = json_size(deps);
        if (n > VCS_PACKAGE_DEPS_MAX_DIRECT) {
            deps_detail(detail, detail_cap, "%zu entries > %u cap", n,
                        VCS_PACKAGE_DEPS_MAX_DIRECT);
            err = VCS_PACKAGE_DEPS_ERR_DEP_COUNT;
        }
        for (size_t i = 0; i < n && err == VCS_PACKAGE_DEPS_OK; i++) {
            const struct json_value *row = json_at(deps, i);
            if (!row || row->type != JSON_OBJ) {
                deps_detail(detail, detail_cap, "dependencies[%zu]", i);
                err = VCS_PACKAGE_DEPS_ERR_DEP_SHAPE;
                break;
            }
            struct vcs_package_dep edge;
            memset(&edge, 0, sizeof(edge));
            const struct json_value *rv = json_get(row, "root");
            const char *rhex = rv && rv->type == JSON_STR ? json_get_str(rv)
                                                          : NULL;
            if (!rhex || !zcl_hex_decode_lower(rhex, edge.root, 32) ||
                deps_root_is_zero(edge.root)) {
                deps_detail(detail, detail_cap, "dependencies[%zu].root=%s", i,
                            rhex ? rhex : "(missing)");
                err = VCS_PACKAGE_DEPS_ERR_DEP_ROOT;
                break;
            }
            const struct json_value *nv = json_get(row, "name");
            if (nv) {
                const char *s = nv->type == JSON_STR ? json_get_str(nv) : NULL;
                if (!s || strlen(s) >= sizeof(edge.name)) {
                    deps_detail(detail, detail_cap, "dependencies[%zu].name",
                                i);
                    err = VCS_PACKAGE_DEPS_ERR_DEP_NAME;
                    break;
                }
                (void)snprintf(edge.name, sizeof(edge.name), "%s", s);
                if (!deps_label_ok(edge.name, sizeof(edge.name))) {
                    deps_detail(detail, detail_cap, "dependencies[%zu].name",
                                i);
                    err = VCS_PACKAGE_DEPS_ERR_DEP_NAME;
                    break;
                }
            }
            const struct json_value *sv = json_get(row, "semver");
            if (sv) {
                const char *s = sv->type == JSON_STR ? json_get_str(sv) : NULL;
                if (!s || strlen(s) >= sizeof(edge.semver)) {
                    deps_detail(detail, detail_cap, "dependencies[%zu].semver",
                                i);
                    err = VCS_PACKAGE_DEPS_ERR_DEP_SEMVER;
                    break;
                }
                (void)snprintf(edge.semver, sizeof(edge.semver), "%s", s);
                if (!deps_label_ok(edge.semver, sizeof(edge.semver))) {
                    deps_detail(detail, detail_cap, "dependencies[%zu].semver",
                                i);
                    err = VCS_PACKAGE_DEPS_ERR_DEP_SEMVER;
                    break;
                }
            }
            err = deps_insert(out, &edge);
            if (err != VCS_PACKAGE_DEPS_OK)
                deps_detail(detail, detail_cap, "dependencies[%zu]", i);
        }
    }
    json_free(&doc);
    if (err != VCS_PACKAGE_DEPS_OK)
        vcs_package_deps_init(out);
    return err;
}

/* ── resolution ─────────────────────────────────────────────────────── */

size_t vcs_package_lock_find(const struct vcs_package_lock *lock,
                             const uint8_t root[32])
{
    if (!lock || !root)
        return SIZE_MAX;
    for (size_t i = 0; i < lock->count; i++)
        if (memcmp(lock->nodes[i].root, root, 32) == 0)
            return i;
    return SIZE_MAX;
}

struct deps_frame {
    uint8_t root[32];
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    struct vcs_package_deps deps;
    size_t next; /* index of the next child to descend into */
    uint16_t depth;
};

static void deps_hexify(const uint8_t root[32], char out[65])
{
    zcl_hex_encode(root, 32, out);
}

/* Push one root onto the DFS stack: load it, cross-check the declared
 * labels, and reject self-dependency. */
static enum vcs_package_deps_error deps_push(
    struct deps_frame *stack, size_t *sp, const uint8_t root[32],
    uint16_t depth, const struct vcs_package_dep *edge,
    const struct vcs_package_deps_source *src, char *detail,
    size_t detail_cap)
{
    char hex[65];
    deps_hexify(root, hex);
    struct deps_frame *f = &stack[*sp];
    memset(f, 0, sizeof(*f));
    memcpy(f->root, root, 32);
    f->depth = depth;
    if (!src->load(src->ctx, root, f->name, f->semver, &f->deps)) {
        deps_detail(detail, detail_cap, "root %s", hex);
        return VCS_PACKAGE_DEPS_ERR_UNRESOLVED;
    }
    if (edge) {
        if (edge->name[0] && strcmp(edge->name, f->name) != 0) {
            deps_detail(detail, detail_cap,
                        "root %s declared name '%s', release says '%s'", hex,
                        edge->name, f->name);
            return VCS_PACKAGE_DEPS_ERR_LABEL_MISMATCH;
        }
        if (edge->semver[0] && strcmp(edge->semver, f->semver) != 0) {
            deps_detail(detail, detail_cap,
                        "root %s declared semver '%s', release says '%s'", hex,
                        edge->semver, f->semver);
            return VCS_PACKAGE_DEPS_ERR_LABEL_MISMATCH;
        }
    }
    for (size_t i = 0; i < f->deps.count; i++) {
        if (memcmp(f->deps.items[i].root, root, 32) == 0) {
            deps_detail(detail, detail_cap, "root %s depends on itself", hex);
            return VCS_PACKAGE_DEPS_ERR_SELF;
        }
    }
    (*sp)++;
    return VCS_PACKAGE_DEPS_OK;
}

/* One emitted node's outgoing edges, parallel to lock->nodes. The DFS pops
 * its frames as it goes, so the graph would otherwise be unavailable by the
 * time the depth pass needs to see all of it at once. */
static enum vcs_package_deps_error deps_emit(struct vcs_package_lock *out,
                                             const struct deps_frame *f,
                                             struct vcs_package_deps *graph,
                                             char *detail, size_t detail_cap)
{
    if (out->count >= VCS_PACKAGE_LOCK_MAX_NODES) {
        deps_detail(detail, detail_cap, "closure > %u nodes",
                    VCS_PACKAGE_LOCK_MAX_NODES);
        return VCS_PACKAGE_DEPS_ERR_NODE_COUNT;
    }
    graph[out->count] = f->deps;
    struct vcs_package_lock_node *n = &out->nodes[out->count++];
    memset(n, 0, sizeof(*n));
    memcpy(n->root, f->root, 32);
    (void)snprintf(n->name, sizeof(n->name), "%s", f->name);
    (void)snprintf(n->semver, sizeof(n->semver), "%s", f->semver);
    n->depth = f->depth;
    n->direct_deps = (uint16_t)f->deps.count;
    return VCS_PACKAGE_DEPS_OK;
}

/* DEPTH IS THE LONGEST PATH FROM THE TARGET -- never the shortest, and never
 * whatever distance the traversal happened to reach a node by first.
 *
 * The DFS stamps each node with the length of the FIRST path that reached it
 * and then skips a root it has already emitted, so a node that is BOTH a
 * direct dependency and a dependency-of-a-dependency keeps whichever distance
 * the walk saw first. That is a property of the traversal, not of the graph,
 * and it silently flattens a real multi-level DAG into a one-level star:
 * commons-demo -> {base, codec, json} with codec -> base and json -> base is a
 * three-level graph, but the walk reaches base directly first and reports two.
 *
 * Longest path is the only assignment under which the number is a valid
 * LAYERING of the DAG: it guarantees depth(dependency) > depth(dependent) for
 * EVERY edge, so a reader that has built every node below level k can build
 * level k. Shortest path breaks exactly that -- it puts base at level 1
 * alongside codec, which needs base -- and so cannot be used to stage a build
 * or to state how deep the dependency chain actually runs.
 *
 * One reverse pass settles it. Emit order is build order (every node appears
 * after all of its dependencies), so walking it backwards visits every
 * dependent BEFORE the dependency it needs; a node's own depth is therefore
 * already final when its outgoing edges are relaxed. Each dependency's index
 * must be strictly earlier than its dependent's (WIRE_ORDER) or that
 * finality assumption is false. */
static enum vcs_package_deps_error deps_normalize_depths(
    struct vcs_package_lock *lock, const struct vcs_package_deps *graph,
    char *detail, size_t detail_cap)
{
    for (size_t i = 0; i < lock->count; i++)
        lock->nodes[i].depth = 0;
    for (size_t i = lock->count; i-- > 0;) {
        struct vcs_package_lock_node *node = &lock->nodes[i];
        const struct vcs_package_deps *deps = &graph[i];
        if (node->depth >= VCS_PACKAGE_LOCK_MAX_DEPTH && deps->count > 0) {
            char hex[65];
            deps_hexify(node->root, hex);
            deps_detail(detail, detail_cap,
                        "root %s sits %u levels under the target, past %u",
                        hex, (unsigned)node->depth,
                        VCS_PACKAGE_LOCK_MAX_DEPTH);
            return VCS_PACKAGE_DEPS_ERR_DEPTH;
        }
        uint16_t dependency_depth = (uint16_t)(node->depth + 1u);
        for (size_t d = 0; d < deps->count; d++) {
            size_t dependency = vcs_package_lock_find(lock,
                                                       deps->items[d].root);
            if (dependency == SIZE_MAX) {
                char hex[65];
                deps_hexify(deps->items[d].root, hex);
                deps_detail(detail, detail_cap,
                            "root %s is an edge with no node in the closure",
                            hex);
                return VCS_PACKAGE_DEPS_ERR_UNRESOLVED;
            }
            if (dependency >= i) {
                char hex[65];
                deps_hexify(deps->items[d].root, hex);
                deps_detail(detail, detail_cap,
                            "root %s is not ordered before its dependent in "
                            "the closure", hex);
                return VCS_PACKAGE_DEPS_ERR_WIRE_ORDER;
            }
            if (lock->nodes[dependency].depth < dependency_depth)
                lock->nodes[dependency].depth = dependency_depth;
        }
    }
    return VCS_PACKAGE_DEPS_OK;
}

// long-function-ok:one-dfs-state-machine — the iterative DFS (push, descend,
// cycle check, post-order emit) is one state machine; splitting it would put
// the stack, the visited set, and the cycle test in three places.
enum vcs_package_deps_error vcs_package_lock_resolve(
    const uint8_t target_root[32], const struct vcs_package_deps_source *src,
    struct vcs_package_lock *out, char *detail, size_t detail_cap)
{
    if (!target_root || !src || !src->load || !out)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null argument to lock resolve");
    vcs_package_lock_init(out);
    if (deps_root_is_zero(target_root)) {
        deps_detail(detail, detail_cap, "all-zero target root");
        return VCS_PACKAGE_DEPS_ERR_DEP_ROOT;
    }

    struct deps_frame *stack = zcl_malloc(
        sizeof(*stack) * (VCS_PACKAGE_LOCK_MAX_DEPTH + 1u), "deps.stack");
    if (!stack)
        return VCS_PACKAGE_DEPS_ERR_ALLOC;
    struct vcs_package_deps *graph = zcl_calloc(
        VCS_PACKAGE_LOCK_MAX_NODES, sizeof(*graph), "deps.graph");
    if (!graph) {
        free(stack);
        return VCS_PACKAGE_DEPS_ERR_ALLOC;
    }
    size_t sp = 0;
    enum vcs_package_deps_error err =
        deps_push(stack, &sp, target_root, 0, NULL, src, detail, detail_cap);
    while (err == VCS_PACKAGE_DEPS_OK && sp > 0) {
        struct deps_frame *top = &stack[sp - 1];
        if (top->next >= top->deps.count) {
            err = deps_emit(out, top, graph, detail, detail_cap);
            sp--;
            continue;
        }
        const struct vcs_package_dep *edge = &top->deps.items[top->next++];
        if (vcs_package_lock_find(out, edge->root) != SIZE_MAX)
            continue; /* already emitted: a shared dependency, not a cycle */
        bool on_stack = false;
        for (size_t i = 0; i < sp; i++)
            if (memcmp(stack[i].root, edge->root, 32) == 0)
                on_stack = true;
        if (on_stack) {
            char hex[65];
            deps_hexify(edge->root, hex);
            deps_detail(detail, detail_cap, "root %s is already being resolved",
                        hex);
            err = VCS_PACKAGE_DEPS_ERR_CYCLE;
            break;
        }
        if (sp > VCS_PACKAGE_LOCK_MAX_DEPTH) {
            deps_detail(detail, detail_cap, "deeper than %u levels",
                        VCS_PACKAGE_LOCK_MAX_DEPTH);
            err = VCS_PACKAGE_DEPS_ERR_DEPTH;
            break;
        }
        err = deps_push(stack, &sp, edge->root, (uint16_t)(top->depth + 1u),
                        edge, src, detail, detail_cap);
    }
    free(stack);
    if (err == VCS_PACKAGE_DEPS_OK)
        err = deps_normalize_depths(out, graph, detail, detail_cap);
    free(graph);
    if (err != VCS_PACKAGE_DEPS_OK)
        vcs_package_lock_init(out);
    return err;
}

/* ── canonical wire ─────────────────────────────────────────────────── */

/* Build order is a wire rule, not merely a resolver habit: every node's
 * declared dependencies must already appear earlier, and the target is
 * last. Verified on parse so a hand-edited lock cannot reorder a build. */
static enum vcs_package_deps_error lock_order_ok(
    const struct vcs_package_lock *lock)
{
    for (size_t i = 0; i < lock->count; i++)
        for (size_t j = i + 1; j < lock->count; j++)
            if (memcmp(lock->nodes[i].root, lock->nodes[j].root, 32) == 0)
                return VCS_PACKAGE_DEPS_ERR_WIRE_ORDER;
    /* The target (depth 0) is unique and last. */
    size_t zero_depth = 0;
    for (size_t i = 0; i < lock->count; i++)
        if (lock->nodes[i].depth == 0)
            zero_depth++;
    if (lock->count > 0 &&
        (zero_depth != 1 || lock->nodes[lock->count - 1].depth != 0))
        return VCS_PACKAGE_DEPS_ERR_WIRE_ORDER;
    return VCS_PACKAGE_DEPS_OK;
}

static size_t lock_wire_size(const struct vcs_package_lock *lock)
{
    size_t n = VCS_PACKAGE_LOCK_WIRE_MAGIC_BYTES + 2u + 2u;
    for (size_t i = 0; i < lock->count; i++)
        n += 32u + 2u + strlen(lock->nodes[i].name) + 2u +
             strlen(lock->nodes[i].semver) + 2u + 2u;
    return n;
}

enum vcs_package_deps_error vcs_package_lock_serialize(
    const struct vcs_package_lock *lock, uint8_t **out, size_t *out_len)
{
    if (!lock || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null argument to lock serialize");
    *out = NULL;
    *out_len = 0;
    if (lock->count > VCS_PACKAGE_LOCK_MAX_NODES)
        return VCS_PACKAGE_DEPS_ERR_NODE_COUNT;
    enum vcs_package_deps_error oerr = lock_order_ok(lock);
    if (oerr != VCS_PACKAGE_DEPS_OK)
        return oerr;
    size_t need = lock_wire_size(lock);
    if (need > VCS_PACKAGE_LOCK_MAX_WIRE_BYTES)
        return VCS_PACKAGE_DEPS_ERR_WIRE_OVERSIZE;
    uint8_t *buf = zcl_malloc(need, "deps.lock.wire");
    if (!buf)
        return VCS_PACKAGE_DEPS_ERR_ALLOC;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, buf, need);
    bool ok = zcl_codec_write_bytes(&writer, lock_wire_magic,
                                    sizeof(lock_wire_magic)) &&
        zcl_codec_write_u16le(&writer, (uint16_t)VCS_PACKAGE_LOCK_VERSION) &&
        zcl_codec_write_u16le(&writer, (uint16_t)lock->count);
    for (size_t i = 0; i < lock->count; i++) {
        const struct vcs_package_lock_node *n = &lock->nodes[i];
        size_t nl = strlen(n->name);
        size_t sl = strlen(n->semver);
        ok = ok && zcl_codec_write_bytes(&writer, n->root, 32) &&
            zcl_codec_write_u16_string(&writer, n->name, nl) &&
            zcl_codec_write_u16_string(&writer, n->semver, sl) &&
            zcl_codec_write_u16le(&writer, n->depth) &&
            zcl_codec_write_u16le(&writer, n->direct_deps);
    }
    size_t written = 0;
    ok = ok && zcl_codec_writer_finish(&writer, &written) && written == need;
    if (!ok) {
        free(buf);
        return VCS_PACKAGE_DEPS_ERR_WIRE_OVERSIZE;
    }
    *out = buf;
    *out_len = written;
    return VCS_PACKAGE_DEPS_OK;
}

enum vcs_package_deps_error vcs_package_lock_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_lock *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null argument to lock parse");
    vcs_package_lock_init(out);
    if (wire_len > VCS_PACKAGE_LOCK_MAX_WIRE_BYTES)
        return VCS_PACKAGE_DEPS_ERR_WIRE_OVERSIZE;
    if (wire_len < VCS_PACKAGE_LOCK_WIRE_MAGIC_BYTES + 4u)
        return VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, wire_len);
    uint8_t magic[VCS_PACKAGE_LOCK_WIRE_MAGIC_BYTES];
    uint16_t version = 0, count = 0;
    if (!zcl_codec_read_bytes(&reader, magic, sizeof(magic)) ||
        memcmp(magic, lock_wire_magic, sizeof(magic)) != 0)
        return VCS_PACKAGE_DEPS_ERR_WIRE_MAGIC;
    if (!zcl_codec_read_u16le(&reader, &version))
        return VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED;
    if (version != VCS_PACKAGE_LOCK_VERSION)
        return VCS_PACKAGE_DEPS_ERR_WIRE_VERSION;
    if (!zcl_codec_read_u16le(&reader, &count))
        return VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED;
    if (count > VCS_PACKAGE_LOCK_MAX_NODES)
        return VCS_PACKAGE_DEPS_ERR_NODE_COUNT;
    for (uint16_t i = 0; i < count; i++) {
        struct vcs_package_lock_node n;
        memset(&n, 0, sizeof(n));
        uint16_t nl = 0, sl = 0;
        if (!zcl_codec_read_bytes(&reader, n.root, 32) ||
            !zcl_codec_read_u16_string(&reader, n.name, sizeof(n.name),
                                       &nl) ||
            !zcl_codec_read_u16_string(&reader, n.semver, sizeof(n.semver),
                                       &sl) ||
            !zcl_codec_read_u16le(&reader, &n.depth) ||
            !zcl_codec_read_u16le(&reader, &n.direct_deps))
            return VCS_PACKAGE_DEPS_ERR_WIRE_TRUNCATED;
        if (deps_root_is_zero(n.root) || !deps_label_ok(n.name, sizeof(n.name)) ||
            !deps_label_ok(n.semver, sizeof(n.semver)) ||
            n.depth > VCS_PACKAGE_LOCK_MAX_DEPTH ||
            n.direct_deps > VCS_PACKAGE_DEPS_MAX_DIRECT) {
            vcs_package_lock_init(out);
            return VCS_PACKAGE_DEPS_ERR_WIRE_ORDER;
        }
        out->nodes[out->count++] = n;
    }
    if (!zcl_codec_reader_finish(&reader)) {
        vcs_package_lock_init(out);
        return VCS_PACKAGE_DEPS_ERR_WIRE_TRAILING;
    }
    enum vcs_package_deps_error oerr = lock_order_ok(out);
    if (oerr != VCS_PACKAGE_DEPS_OK) {
        vcs_package_lock_init(out);
        return oerr;
    }
    return VCS_PACKAGE_DEPS_OK;
}

enum vcs_package_deps_error vcs_package_lock_root(
    const struct vcs_package_lock *lock, uint8_t out[32])
{
    if (!lock || !out)
        LOG_RETURN(VCS_PACKAGE_DEPS_ERR_NULL, DEPS_LOG,
                        "null argument to lock root");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_deps_error err =
        vcs_package_lock_serialize(lock, &wire, &wire_len);
    if (err != VCS_PACKAGE_DEPS_OK)
        return err;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, lock_root_domain, sizeof(lock_root_domain));
    sha3_256_write(&ctx, wire, wire_len);
    sha3_256_finalize(&ctx, out);
    free(wire);
    return VCS_PACKAGE_DEPS_OK;
}
