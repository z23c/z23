/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge_commit — the badge issuance commit record (slice 10),
 * split out of package_badge.c. The commit record is the idempotence
 * authority: it is written LAST, after every badge wire in a plan is
 * durable, so a crash mid-issue leaves a resumable partial state and a
 * completed issue is a named duplicate, never a double-issue. See
 * vcs/package_badge.h for the frozen contract; the codec, policy lens,
 * and the badge/plan store live in package_badge.c, and the struct
 * vcs_badge_store shape + filesystem/id-set primitives this file reuses
 * live in package_badge_priv.h. */

#include "vcs/package_badge.h"

#include "base/hex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "vcs_priv.h"
#include "package_badge_priv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BADGE_LOG "vcs.badge"

static const uint8_t badge_commit_magic[8] =
    { 'Z', 'C', 'L', 'B', 'C', 'M', '\r', '\n' };

/* ── the commit record ──────────────────────────────────────────────── */

bool vcs_badge_commit_known(const struct vcs_badge_store *s,
                            const uint8_t plan_id[32])
{
    if (!s || !plan_id)
        return false;
    return badge_id_set_contains(s->commits, s->commit_count, plan_id);
}

#define BADGE_COMMIT_HEADER_BYTES (8u + 2u + 32u + 4u)

bool vcs_badge_commit_record_write(struct vcs_badge_store *s,
                                   const uint8_t plan_id[32],
                                   const uint8_t (*badge_ids)[32],
                                   size_t badge_count)
{
    if (!s || !plan_id || (badge_count > 0 && !badge_ids))
        LOG_RETURN(false, BADGE_LOG, "null commit record write");
    if (badge_count > VCS_BADGE_MAX_PLAN_ROWS)
        LOG_RETURN(false, BADGE_LOG, "commit rows %zu over bound",
                   badge_count);
    char dir[4400];
    int dn = snprintf(dir, sizeof(dir), "%s/commits", s->root);
    if (dn <= 0 || (size_t)dn >= sizeof(dir))
        LOG_RETURN(false, BADGE_LOG, "commit dir path too long");
    if (!badge_mkdir_p(dir))
        LOG_RETURN(false, BADGE_LOG, "mkdir %s: %s", dir, strerror(errno));
    size_t wire_len = BADGE_COMMIT_HEADER_BYTES + badge_count * 32u;
    uint8_t *wire = zcl_malloc(wire_len, "badge_commit_wire");
    if (!wire)
        LOG_RETURN(false, BADGE_LOG, "alloc %zu commit wire", wire_len);
    uint8_t *p = wire;
    memcpy(p, badge_commit_magic, 8);
    p += 8;
    vcs_wr_u16le(p, VCS_PACKAGE_BADGE_VERSION);
    p += 2;
    memcpy(p, plan_id, 32);
    p += 32;
    vcs_wr_u32le(p, (uint32_t)badge_count);
    p += 4;
    for (size_t i = 0; i < badge_count; i++) {
        memcpy(p, badge_ids[i], 32);
        p += 32;
    }
    char id_hex[65];
    zcl_hex_encode(plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
              badge_atomic_write(path, wire, wire_len);
    free(wire);
    if (!ok)
        LOG_RETURN(false, BADGE_LOG, "commit record write failed for %s",
                   id_hex);
    bool inserted = false;
    if (badge_id_set_insert(&s->commits, &s->commit_count, &s->commit_cap,
                            plan_id, &inserted) == (size_t)-1)
        return false;
    return true;
}

size_t vcs_badge_commit_record_badges(const struct vcs_badge_store *s,
                                      const uint8_t plan_id[32],
                                      uint8_t (*out)[32], size_t cap)
{
    if (!s || !plan_id)
        return 0;
    char id_hex[65];
    zcl_hex_encode(plan_id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/commits/%s", s->root, id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return 0;
    size_t wire_len = 0;
    uint8_t *wire =
        badge_read_file(path, VCS_BADGE_MAX_COMMIT_WIRE_BYTES, &wire_len);
    if (!wire)
        return 0;
    size_t total = 0;
    if (wire_len >= BADGE_COMMIT_HEADER_BYTES &&
        memcmp(wire, badge_commit_magic, 8) == 0 &&
        vcs_rd_u16le(wire + 8) == VCS_PACKAGE_BADGE_VERSION &&
        memcmp(wire + 10, plan_id, 32) == 0) {
        uint32_t rows = vcs_rd_u32le(wire + 42);
        if ((size_t)rows <= VCS_BADGE_MAX_PLAN_ROWS &&
            BADGE_COMMIT_HEADER_BYTES + (size_t)rows * 32u == wire_len) {
            total = rows;
            size_t render = total < cap ? total : cap;
            if (out)
                for (size_t i = 0; i < render; i++)
                    memcpy(out[i],
                           wire + BADGE_COMMIT_HEADER_BYTES + i * 32u, 32);
        } else {
            LOG_ERROR(BADGE_LOG, "commit record %s row count invalid",
                      id_hex);
            total = 0;
        }
    } else {
        LOG_ERROR(BADGE_LOG, "commit record %s corrupt", id_hex);
    }
    free(wire);
    return total;
}
