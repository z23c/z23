/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_install — implementation of the ZCODE add-plan and generation-log
 * codecs declared in vcs/package_install.h. Pure bytes: no filesystem, no
 * process, no install authority. */

#include "vcs/package_install.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "vcs_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INSTALL_LOG "vcs.install"

static const uint8_t plan_wire_magic[VCS_PACKAGE_PLAN_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'A', 'P', 'L', '\r', '\n' };
static const uint8_t plan_id_domain[] = VCS_PACKAGE_PLAN_ID_DOMAIN;
static const uint8_t gen_wire_magic[VCS_PACKAGE_GENERATION_WIRE_MAGIC_BYTES] =
    { 'Z', 'C', 'L', 'G', 'E', 'N', '\r', '\n' };

const char *vcs_package_lifecycle_state_string(
    enum vcs_package_lifecycle_state state)
{
    switch (state) {
    case VCS_PACKAGE_LIFECYCLE_DISCOVERED: return "discovered";
    case VCS_PACKAGE_LIFECYCLE_FETCHING: return "fetching";
    case VCS_PACKAGE_LIFECYCLE_VERIFIED: return "verified";
    case VCS_PACKAGE_LIFECYCLE_BUILT: return "built";
    case VCS_PACKAGE_LIFECYCLE_TESTED: return "tested";
    case VCS_PACKAGE_LIFECYCLE_INSTALLED: return "installed";
    case VCS_PACKAGE_LIFECYCLE_PINNED: return "pinned";
    }
    return "unknown-state";
}

const char *vcs_package_install_error_string(
    enum vcs_package_install_error error)
{
    switch (error) {
    case VCS_PACKAGE_INSTALL_OK: return "ok";
    case VCS_PACKAGE_INSTALL_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_INSTALL_ERR_ALLOC: return "allocation-failure";
    case VCS_PACKAGE_INSTALL_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_PACKAGE_INSTALL_ERR_WIRE_VERSION: return "wire-version";
    case VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED: return "wire-truncated";
    case VCS_PACKAGE_INSTALL_ERR_WIRE_TRAILING: return "wire-trailing";
    case VCS_PACKAGE_INSTALL_ERR_WIRE_OVERSIZE: return "wire-oversize";
    case VCS_PACKAGE_INSTALL_ERR_ROOT: return "all-zero-root";
    case VCS_PACKAGE_INSTALL_ERR_STEP_COUNT: return "step-count-bound";
    case VCS_PACKAGE_INSTALL_ERR_STEP_ORDER: return "steps-not-build-order";
    case VCS_PACKAGE_INSTALL_ERR_FIELD: return "field-grammar";
    case VCS_PACKAGE_INSTALL_ERR_STATE: return "lifecycle-state";
    case VCS_PACKAGE_INSTALL_ERR_EXPIRY: return "plan-expiry";
    case VCS_PACKAGE_INSTALL_ERR_GEN_COUNT: return "generation-count-bound";
    }
    return "unknown-error";
}

void vcs_package_plan_init(struct vcs_package_plan *plan)
{
    if (plan)
        memset(plan, 0, sizeof(*plan));
}

void vcs_package_generations_init(struct vcs_package_generations *g)
{
    if (g)
        memset(g, 0, sizeof(*g));
}

static bool install_root_is_zero(const uint8_t root[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= root[i];
    return acc == 0;
}

static bool install_field_ok(const char *s, size_t cap, bool allow_empty)
{
    size_t n = strlen(s);
    if (n >= cap)
        return false;
    if (n == 0)
        return allow_empty;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21u || c > 0x7eu)
            return false;
    }
    return true;
}

enum vcs_package_install_error vcs_package_plan_validate(
    const struct vcs_package_plan *plan)
{
    if (!plan)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null add plan to validate");
    if (install_root_is_zero(plan->target_root) ||
        install_root_is_zero(plan->lock_root))
        return VCS_PACKAGE_INSTALL_ERR_ROOT;
    if (plan->step_count == 0 ||
        plan->step_count > VCS_PACKAGE_LOCK_MAX_NODES)
        return VCS_PACKAGE_INSTALL_ERR_STEP_COUNT;
    if (plan->expires_unix <= plan->created_unix)
        return VCS_PACKAGE_INSTALL_ERR_EXPIRY;
    size_t depth_zero = 0;
    for (size_t i = 0; i < plan->step_count; i++) {
        const struct vcs_package_plan_step *s = &plan->steps[i];
        if (install_root_is_zero(s->root))
            return VCS_PACKAGE_INSTALL_ERR_ROOT;
        for (size_t j = i + 1; j < plan->step_count; j++)
            if (memcmp(s->root, plan->steps[j].root, 32) == 0)
                return VCS_PACKAGE_INSTALL_ERR_STEP_ORDER;
        if (!install_field_ok(s->name, sizeof(s->name), false) ||
            !install_field_ok(s->semver, sizeof(s->semver), false) ||
            !install_field_ok(s->license, sizeof(s->license), false) ||
            s->depth > VCS_PACKAGE_LOCK_MAX_DEPTH)
            return VCS_PACKAGE_INSTALL_ERR_FIELD;
        if (s->state > (uint8_t)VCS_PACKAGE_LIFECYCLE_PINNED)
            return VCS_PACKAGE_INSTALL_ERR_STATE;
        if (s->depth == 0)
            depth_zero++;
    }
    /* Build order: exactly one target, and it is last (the lock's rule). */
    const struct vcs_package_plan_step *last =
        &plan->steps[plan->step_count - 1u];
    if (depth_zero != 1 || last->depth != 0 ||
        memcmp(last->root, plan->target_root, 32) != 0)
        return VCS_PACKAGE_INSTALL_ERR_STEP_ORDER;
    return VCS_PACKAGE_INSTALL_OK;
}

bool vcs_package_plan_expired(const struct vcs_package_plan *plan,
                              int64_t now_unix)
{
    if (!plan)
        return true;
    return now_unix >= plan->expires_unix;
}

static size_t plan_wire_size(const struct vcs_package_plan *plan)
{
    size_t n = VCS_PACKAGE_PLAN_WIRE_MAGIC_BYTES + 2u + 64u + 16u + 2u;
    for (size_t i = 0; i < plan->step_count; i++)
        n += 32u + 2u + strlen(plan->steps[i].name) + 2u +
             strlen(plan->steps[i].semver) + 2u +
             strlen(plan->steps[i].license) + 2u + 1u + 1u + 8u + 4u;
    return n;
}

enum vcs_package_install_error vcs_package_plan_serialize(
    const struct vcs_package_plan *plan, uint8_t **out, size_t *out_len)
{
    if (!plan || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument serializing an add plan");
    *out = NULL;
    *out_len = 0;
    enum vcs_package_install_error verr = vcs_package_plan_validate(plan);
    if (verr != VCS_PACKAGE_INSTALL_OK)
        return verr;
    size_t need = plan_wire_size(plan);
    if (need > VCS_PACKAGE_PLAN_MAX_WIRE_BYTES)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_OVERSIZE;
    uint8_t *buf = zcl_malloc(need, "vcs.plan.wire");
    if (!buf)
        return VCS_PACKAGE_INSTALL_ERR_ALLOC;
    size_t o = 0;
    memcpy(buf + o, plan_wire_magic, sizeof(plan_wire_magic));
    o += sizeof(plan_wire_magic);
    vcs_wr_u16le(buf + o, (uint16_t)VCS_PACKAGE_PLAN_VERSION);
    o += 2;
    memcpy(buf + o, plan->target_root, 32);
    o += 32;
    memcpy(buf + o, plan->lock_root, 32);
    o += 32;
    vcs_wr_u64le(buf + o, (uint64_t)plan->created_unix);
    o += 8;
    vcs_wr_u64le(buf + o, (uint64_t)plan->expires_unix);
    o += 8;
    vcs_wr_u16le(buf + o, (uint16_t)plan->step_count);
    o += 2;
    for (size_t i = 0; i < plan->step_count; i++) {
        const struct vcs_package_plan_step *s = &plan->steps[i];
        memcpy(buf + o, s->root, 32);
        o += 32;
        const char *strs[3] = { s->name, s->semver, s->license };
        for (size_t k = 0; k < 3; k++) {
            size_t l = strlen(strs[k]);
            vcs_wr_u16le(buf + o, (uint16_t)l);
            o += 2;
            memcpy(buf + o, strs[k], l);
            o += l;
        }
        vcs_wr_u16le(buf + o, s->depth);
        o += 2;
        buf[o++] = s->state;
        buf[o++] = (uint8_t)((s->complete ? 1u : 0u) |
                             (s->installed ? 2u : 0u));
        vcs_wr_u64le(buf + o, s->total_bytes);
        o += 8;
        vcs_wr_u32le(buf + o, s->total_chunks);
        o += 4;
    }
    *out = buf;
    *out_len = o;
    return VCS_PACKAGE_INSTALL_OK;
}

static bool install_rd_str(const uint8_t *wire, size_t wire_len, size_t *o,
                           char *dst, size_t cap)
{
    if (wire_len - *o < 2u)
        return false;
    uint16_t l = vcs_rd_u16le(wire + *o);
    *o += 2;
    if (l >= cap || wire_len - *o < (size_t)l)
        return false;
    memcpy(dst, wire + *o, l);
    dst[l] = '\0';
    *o += l;
    return true;
}

enum vcs_package_install_error vcs_package_plan_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_plan *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument parsing an add plan");
    vcs_package_plan_init(out);
    if (wire_len > VCS_PACKAGE_PLAN_MAX_WIRE_BYTES)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_OVERSIZE;
    const size_t head = VCS_PACKAGE_PLAN_WIRE_MAGIC_BYTES + 2u + 64u + 16u + 2u;
    if (wire_len < head)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED;
    if (memcmp(wire, plan_wire_magic, sizeof(plan_wire_magic)) != 0)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_MAGIC;
    size_t o = sizeof(plan_wire_magic);
    if (vcs_rd_u16le(wire + o) != VCS_PACKAGE_PLAN_VERSION)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_VERSION;
    o += 2;
    memcpy(out->target_root, wire + o, 32);
    o += 32;
    memcpy(out->lock_root, wire + o, 32);
    o += 32;
    out->created_unix = (int64_t)vcs_rd_u64le(wire + o);
    o += 8;
    out->expires_unix = (int64_t)vcs_rd_u64le(wire + o);
    o += 8;
    uint16_t count = vcs_rd_u16le(wire + o);
    o += 2;
    if (count > VCS_PACKAGE_LOCK_MAX_NODES) {
        vcs_package_plan_init(out);
        return VCS_PACKAGE_INSTALL_ERR_STEP_COUNT;
    }
    for (uint16_t i = 0; i < count; i++) {
        struct vcs_package_plan_step s;
        memset(&s, 0, sizeof(s));
        if (wire_len - o < 32u) {
            vcs_package_plan_init(out);
            return VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED;
        }
        memcpy(s.root, wire + o, 32);
        o += 32;
        if (!install_rd_str(wire, wire_len, &o, s.name, sizeof(s.name)) ||
            !install_rd_str(wire, wire_len, &o, s.semver, sizeof(s.semver)) ||
            !install_rd_str(wire, wire_len, &o, s.license,
                            sizeof(s.license)) ||
            wire_len - o < 2u + 1u + 1u + 8u + 4u) {
            vcs_package_plan_init(out);
            return VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED;
        }
        s.depth = vcs_rd_u16le(wire + o);
        o += 2;
        s.state = wire[o++];
        uint8_t flags = wire[o++];
        if ((flags & ~0x03u) != 0) {
            vcs_package_plan_init(out);
            return VCS_PACKAGE_INSTALL_ERR_FIELD;
        }
        s.complete = (flags & 1u) != 0;
        s.installed = (flags & 2u) != 0;
        s.total_bytes = vcs_rd_u64le(wire + o);
        o += 8;
        s.total_chunks = vcs_rd_u32le(wire + o);
        o += 4;
        out->steps[out->step_count++] = s;
    }
    if (o != wire_len) {
        vcs_package_plan_init(out);
        return VCS_PACKAGE_INSTALL_ERR_WIRE_TRAILING;
    }
    enum vcs_package_install_error verr = vcs_package_plan_validate(out);
    if (verr != VCS_PACKAGE_INSTALL_OK) {
        vcs_package_plan_init(out);
        return verr;
    }
    return VCS_PACKAGE_INSTALL_OK;
}

enum vcs_package_install_error vcs_package_plan_id(
    const struct vcs_package_plan *plan, uint8_t out[32])
{
    if (!plan || !out)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument hashing an add plan");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_install_error err =
        vcs_package_plan_serialize(plan, &wire, &wire_len);
    if (err != VCS_PACKAGE_INSTALL_OK)
        return err;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, plan_id_domain, sizeof(plan_id_domain));
    sha3_256_write(&ctx, wire, wire_len);
    sha3_256_finalize(&ctx, out);
    free(wire);
    return VCS_PACKAGE_INSTALL_OK;
}

/* ── generation log ─────────────────────────────────────────────────── */

size_t vcs_package_generations_trim(struct vcs_package_generations *g,
                                    size_t keep)
{
    if (!g)
        return 0;
    if (keep < 1u)
        keep = 1u;
    if (g->count <= keep)
        return 0;
    size_t drop = g->count - keep;
    memmove(g->items, g->items + drop, keep * sizeof(g->items[0]));
    g->count = keep;
    return drop;
}

enum vcs_package_install_error vcs_package_generations_append(
    struct vcs_package_generations *g, const uint8_t root[32],
    int64_t activated_unix)
{
    if (!g || !root)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument appending a generation");
    if (install_root_is_zero(root))
        return VCS_PACKAGE_INSTALL_ERR_ROOT;
    /* Rejections leave the log untouched, so the duplicate check comes
     * before any eviction. */
    if (g->count > 0 &&
        memcmp(g->items[g->count - 1u].root, root, 32) == 0)
        return VCS_PACKAGE_INSTALL_ERR_ROOT; /* already active: no-op */
    /* Make room by evicting the OLDEST entries rather than refusing. A
     * refusal here would deny both the next install and the next rollback
     * — bricking the package at the moment going back matters most. */
    (void)vcs_package_generations_trim(g, VCS_PACKAGE_GENERATION_KEEP - 1u);
    g->items[g->count].activated_unix = activated_unix;
    memcpy(g->items[g->count].root, root, 32);
    g->count++;
    return VCS_PACKAGE_INSTALL_OK;
}

enum vcs_package_install_error vcs_package_generations_serialize(
    const struct vcs_package_generations *g, uint8_t **out, size_t *out_len)
{
    if (!g || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument serializing the generation log");
    *out = NULL;
    *out_len = 0;
    if (g->count > VCS_PACKAGE_GENERATION_MAX)
        return VCS_PACKAGE_INSTALL_ERR_GEN_COUNT;
    size_t need = sizeof(gen_wire_magic) + 4u + g->count * 40u;
    uint8_t *buf = zcl_malloc(need, "vcs.generations.wire");
    if (!buf)
        return VCS_PACKAGE_INSTALL_ERR_ALLOC;
    size_t o = 0;
    memcpy(buf + o, gen_wire_magic, sizeof(gen_wire_magic));
    o += sizeof(gen_wire_magic);
    vcs_wr_u16le(buf + o, (uint16_t)VCS_PACKAGE_GENERATION_VERSION);
    o += 2;
    vcs_wr_u16le(buf + o, (uint16_t)g->count);
    o += 2;
    for (size_t i = 0; i < g->count; i++) {
        if (install_root_is_zero(g->items[i].root)) {
            free(buf);
            return VCS_PACKAGE_INSTALL_ERR_ROOT;
        }
        memcpy(buf + o, g->items[i].root, 32);
        o += 32;
        vcs_wr_u64le(buf + o, (uint64_t)g->items[i].activated_unix);
        o += 8;
    }
    *out = buf;
    *out_len = o;
    return VCS_PACKAGE_INSTALL_OK;
}

enum vcs_package_install_error vcs_package_generations_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_generations *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_PACKAGE_INSTALL_ERR_NULL, INSTALL_LOG,
                   "null argument parsing the generation log");
    vcs_package_generations_init(out);
    if (wire_len > VCS_PACKAGE_GENERATION_MAX_WIRE_BYTES)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_OVERSIZE;
    if (wire_len < sizeof(gen_wire_magic) + 4u)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED;
    if (memcmp(wire, gen_wire_magic, sizeof(gen_wire_magic)) != 0)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_MAGIC;
    size_t o = sizeof(gen_wire_magic);
    if (vcs_rd_u16le(wire + o) != VCS_PACKAGE_GENERATION_VERSION)
        return VCS_PACKAGE_INSTALL_ERR_WIRE_VERSION;
    o += 2;
    uint16_t count = vcs_rd_u16le(wire + o);
    o += 2;
    if (count > VCS_PACKAGE_GENERATION_MAX)
        return VCS_PACKAGE_INSTALL_ERR_GEN_COUNT;
    if (wire_len - o != (size_t)count * 40u)
        return wire_len - o < (size_t)count * 40u
                   ? VCS_PACKAGE_INSTALL_ERR_WIRE_TRUNCATED
                   : VCS_PACKAGE_INSTALL_ERR_WIRE_TRAILING;
    for (uint16_t i = 0; i < count; i++) {
        struct vcs_package_generation e;
        memset(&e, 0, sizeof(e));
        memcpy(e.root, wire + o, 32);
        o += 32;
        e.activated_unix = (int64_t)vcs_rd_u64le(wire + o);
        o += 8;
        if (install_root_is_zero(e.root)) {
            vcs_package_generations_init(out);
            return VCS_PACKAGE_INSTALL_ERR_ROOT;
        }
        out->items[out->count++] = e;
    }
    return VCS_PACKAGE_INSTALL_OK;
}

bool vcs_package_generations_previous(const struct vcs_package_generations *g,
                                      uint8_t out_root[32])
{
    if (!g || !out_root || g->count < 2)
        return false;
    const uint8_t *active = g->items[g->count - 1u].root;
    for (size_t i = g->count - 1u; i > 0; i--) {
        const uint8_t *cand = g->items[i - 1u].root;
        if (memcmp(cand, active, 32) != 0) {
            memcpy(out_root, cand, 32);
            return true;
        }
    }
    return false;
}

bool vcs_package_name_split(
    const char *name,
    char publisher_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u],
    char package_out[VCS_PACKAGE_RELEASE_NAME_MAX + 1u])
{
    if (!publisher_out || !package_out)
        return false;
    publisher_out[0] = '\0';
    package_out[0] = '\0';
    if (!name)
        return false;
    const char *slash = strchr(name, '/');
    if (!slash || slash == name || slash[1] == '\0' ||
        strchr(slash + 1, '/') != NULL)
        return false;
    size_t pl = (size_t)(slash - name);
    if (pl > VCS_PACKAGE_RELEASE_NAME_MAX ||
        strlen(slash + 1) > VCS_PACKAGE_RELEASE_NAME_MAX)
        return false;
    /* The release name grammar is [a-z0-9-]; anything else never becomes a
     * path component here. */
    for (const char *p = name; *p; p++) {
        if (p == slash)
            continue;
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '-'))
            return false;
    }
    memcpy(publisher_out, name, pl);
    publisher_out[pl] = '\0';
    (void)snprintf(package_out, VCS_PACKAGE_RELEASE_NAME_MAX + 1u, "%s",
                   slash + 1);
    return true;
}
