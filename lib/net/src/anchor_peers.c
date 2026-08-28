/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Anchor peers — see net/anchor_peers.h for rationale.
 *
 * The body is a tiny fixed-layout binary blob (at most
 * 2 + ANCHOR_PEERS_MAX*71 = 570 bytes), so serialization uses a stack buffer
 * and needs no heap. The SHA3 body+sidecar integrity, atomic sidecar write,
 * and quarantine-rename all reuse storage/sha3_sidecar_io — the SAME machinery
 * peers.dat uses (net/addrman_integrity.c) — so anchors.dat and peers.dat
 * behave identically on corruption.
 */

#include "net/anchor_peers.h"
#include "storage/sha3_sidecar_io.h"

#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── On-disk layout ─────────────────────────────────────────────
 *
 *   body[0]        u8  format version (ANCHOR_FORMAT_VERSION)
 *   body[1]        u8  count (0..ANCHOR_PEERS_MAX)
 *   then `count` records, each ANCHOR_RECORD_BYTES:
 *       16  net_addr.ip
 *       32  net_addr.torv3
 *        1  net_addr.has_torv3 (0/1)
 *        2  port           (little-endian u16)
 *        8  services       (little-endian u64)
 *        4  last_height    (little-endian, int32 stored as u32)
 *        8  last_success   (little-endian, int64 stored as u64)
 */
#define ANCHOR_FORMAT_VERSION 1u
#define ANCHOR_RECORD_BYTES   (16 + 32 + 1 + 2 + 8 + 4 + 8)
#define ANCHOR_BODY_MAX       (2 + ANCHOR_PEERS_MAX * ANCHOR_RECORD_BYTES)

/* Reuse EV_ADDRMAN_CORRUPT: anchors.dat is peer-persistence data of the same
 * family as peers.dat, and the event payload is a generic "verdict=..." string. */
static const struct ssio_spec anchors_spec = {
    .body_name     = "anchors.dat",
    .sidecar_name  = "anchors.dat.sha3",
    .magic         = "ANIX",
    .version       = ANCHOR_FORMAT_VERSION,
    .domain        = "anchor_peers",
    .malloc_label  = "anchor_hash_buf",
    .corrupt_event = EV_ADDRMAN_CORRUPT,
};

const char *anchor_load_status_name(enum anchor_load_status s)
{
    switch (s) {
    case ANCHOR_LOAD_OK:          return "ok";
    case ANCHOR_LOAD_EMPTY:       return "empty";
    case ANCHOR_LOAD_QUARANTINED: return "quarantined";
    default:                      return "unknown";
    }
}

/* ── Little-endian pack/unpack (no alignment/endianness assumptions) ── */

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
static void put_u32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}
static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}
static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Serialize `set` into `buf` (capacity ANCHOR_BODY_MAX). Returns byte count. */
static size_t anchor_serialize(const struct anchor_peer_set *set, uint8_t *buf)
{
    size_t n = set->count > ANCHOR_PEERS_MAX ? ANCHOR_PEERS_MAX : set->count;
    size_t off = 0;
    buf[off++] = (uint8_t)ANCHOR_FORMAT_VERSION;
    buf[off++] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        const struct anchor_peer *a = &set->peers[i];
        memcpy(buf + off, a->addr.ip, 16);            off += 16;
        memcpy(buf + off, a->addr.torv3, 32);         off += 32;
        buf[off++] = a->addr.has_torv3 ? 1 : 0;
        put_u16(buf + off, a->port);                   off += 2;
        put_u64(buf + off, a->services);               off += 8;
        put_u32(buf + off, (uint32_t)a->last_height);  off += 4;
        put_u64(buf + off, (uint64_t)a->last_success); off += 8;
    }
    return off;
}

static bool anchor_deserialize(const uint8_t *buf, size_t len,
                               struct anchor_peer_set *out)
{
    out->count = 0;
    if (len < 2)
        LOG_FAIL("anchor_peers", "deserialize: body too small (%zu bytes)", len);
    uint8_t ver = buf[0];
    if (ver != ANCHOR_FORMAT_VERSION)
        LOG_FAIL("anchor_peers", "deserialize: bad version %u", (unsigned)ver);
    uint8_t count = buf[1];
    if (count > ANCHOR_PEERS_MAX)
        LOG_FAIL("anchor_peers", "deserialize: count %u > max %u",
                 (unsigned)count, ANCHOR_PEERS_MAX);
    size_t need = 2 + (size_t)count * ANCHOR_RECORD_BYTES;
    if (len < need)
        LOG_FAIL("anchor_peers", "deserialize: short body %zu < %zu", len, need);

    size_t off = 2;
    for (uint8_t i = 0; i < count; i++) {
        struct anchor_peer *a = &out->peers[i];
        net_addr_init(&a->addr);
        memcpy(a->addr.ip, buf + off, 16);        off += 16;
        memcpy(a->addr.torv3, buf + off, 32);     off += 32;
        a->addr.has_torv3 = buf[off++] ? true : false;
        a->port = get_u16(buf + off);             off += 2;
        a->services = get_u64(buf + off);         off += 8;
        a->last_height = (int32_t)get_u32(buf + off); off += 4;
        a->last_success = (int64_t)get_u64(buf + off);off += 8;
    }
    out->count = count;
    return true;
}

/* Atomic body write: tmp → fflush → fsync → rename. Mirrors
 * connman_save_addrman's peers.dat write. */
static bool anchor_write_body(const char *datadir,
                              const uint8_t *buf, size_t len)
{
    char path[512], tmp_path[540];
    snprintf(path, sizeof(path), "%s/%s", datadir, anchors_spec.body_name);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    struct platform_private_file staged;
    platform_private_file_init(&staged);
    if (!platform_private_file_unlink_missing_ok(tmp_path) ||
        !platform_private_file_create(tmp_path, &staged))
        LOG_FAIL("anchor_peers", "create private staging file %s failed",
                 tmp_path);
    if (!platform_private_file_write_at(&staged, buf, len, 0) ||
        !platform_private_file_truncate(&staged, len) ||
        !platform_private_file_replace(&staged, tmp_path, path)) {
        platform_private_file_close(&staged);
        (void)platform_private_file_unlink_missing_ok(tmp_path);
        LOG_FAIL("anchor_peers", "durable replace %s -> %s failed",
                 tmp_path, path);
    }
    if (!platform_private_parent_flush(datadir))
        LOG_FAIL("anchor_peers", "flush datadir %s failed", datadir);
    return true;
}

struct zcl_result anchor_peers_save(const char *datadir,
                                    const struct anchor_peer_set *set)
{
    if (!datadir || !set)
        return ZCL_ERR(-1, "anchor_peers_save: null %s",
                       !datadir ? "datadir" : "set");
    if (set->count > ANCHOR_PEERS_MAX)
        return ZCL_ERR(-1, "anchor_peers_save: count %zu > max %u",
                       set->count, ANCHOR_PEERS_MAX);

    uint8_t buf[ANCHOR_BODY_MAX];
    size_t len = anchor_serialize(set, buf);

    if (!anchor_write_body(datadir, buf, len))
        return ZCL_ERR(-1, "anchor_peers_save: body write failed");

    /* Sidecar over the on-disk body — the SAME integrity commitment peers.dat
     * uses. A sidecar-write failure is logged inside ssio_write_sidecar and
     * surfaced here; the next load then sees SIDECAR_MISSING and starts empty. */
    struct zcl_result sr = ssio_write_sidecar(datadir, &anchors_spec);
    if (!sr.ok)
        return sr;

    return ZCL_OK;
}

/* Verify the body against its sidecar (mirrors aii_verify). Fills *deser_ok
 * only when the body is safe to deserialize. Returns an anchor_load_status. */
enum anchor_load_status anchor_peers_load(const char *datadir,
                                          struct anchor_peer_set *out)
{
    if (out) { memset(out, 0, sizeof(*out)); out->count = 0; }
    if (!datadir || !out)
        return ANCHOR_LOAD_EMPTY;

    struct platform_positioned_file body;
    platform_positioned_file_init(&body);
    if (!platform_positioned_file_open_beneath(
            &body, datadir, anchors_spec.body_name))
        return ANCHOR_LOAD_EMPTY; /* no anchors yet — normal first run */
    uint64_t body_size = 0;
    if (!platform_positioned_file_size(&body, &body_size)) {
        platform_positioned_file_close(&body);
        return ANCHOR_LOAD_EMPTY;
    }

    struct ssio_sidecar_header hdr;
    enum ssio_read_verdict rv = ssio_read_sidecar(datadir, &anchors_spec, &hdr);
    if (rv == SSIO_READ_MISSING) {
        /* Body without a sidecar: a torn write. We cannot integrity-check it,
         * so we do not trust it for outbound steering. Start empty; the next
         * save rewrites both files. */
        LOG_WARN("anchor_peers", "anchors.dat present but sidecar missing — starting empty");
        platform_positioned_file_close(&body);
        return ANCHOR_LOAD_EMPTY;
    }
    if (rv != SSIO_READ_OK) {
        LOG_WARN("anchor_peers", "anchors sidecar read verdict=%d — quarantining", (int)rv);
        platform_positioned_file_close(&body);
        ssio_quarantine(datadir, &anchors_spec, "sidecar_read");
        return ANCHOR_LOAD_QUARANTINED;
    }

    if (hdr.body_size != body_size) {
        LOG_WARN("anchor_peers", "anchors size drift sidecar=%llu actual=%lld — quarantining",
                 (unsigned long long)hdr.body_size, (long long)body_size);
        platform_positioned_file_close(&body);
        ssio_quarantine(datadir, &anchors_spec, "size_drift");
        return ANCHOR_LOAD_QUARANTINED;
    }

    uint8_t actual_hash[32];
    uint64_t hashed_size = 0;
    if (!ssio_hash_body(datadir, &anchors_spec, actual_hash, &hashed_size)) {
        LOG_WARN("anchor_peers", "anchors body unreadable — quarantining");
        platform_positioned_file_close(&body);
        ssio_quarantine(datadir, &anchors_spec, "body_unreadable");
        return ANCHOR_LOAD_QUARANTINED;
    }
    if (hashed_size != hdr.body_size ||
        memcmp(actual_hash, hdr.body_sha3, 32) != 0) {
        LOG_WARN("anchor_peers", "anchors body sha3 mismatch — quarantining");
        platform_positioned_file_close(&body);
        ssio_quarantine(datadir, &anchors_spec, "hash_mismatch");
        return ANCHOR_LOAD_QUARANTINED;
    }

    /* Body integrity proven — read + deserialize it (bounded, ≤ 570 bytes). */
    if (body_size == 0 || body_size > ANCHOR_BODY_MAX) {
        LOG_WARN("anchor_peers", "anchors body size %lld out of range — quarantining",
                 (long long)body_size);
        platform_positioned_file_close(&body);
        ssio_quarantine(datadir, &anchors_spec, "size_range");
        return ANCHOR_LOAD_QUARANTINED;
    }
    uint8_t buf[ANCHOR_BODY_MAX];
    int64_t rd = platform_positioned_file_read(&body, buf, (size_t)body_size, 0);
    platform_positioned_file_close(&body);
    if (rd < 0 || (uint64_t)rd != body_size) {
        LOG_WARN("anchor_peers", "anchors body short read %zu/%lld",
                 rd < 0 ? 0u : (size_t)rd, (long long)body_size);
        return ANCHOR_LOAD_EMPTY;
    }
    if (!anchor_deserialize(buf, (size_t)rd, out)) {
        /* Sidecar matched but the payload is structurally invalid — treat as
         * corrupt so a hostile-but-hash-consistent body cannot steer us. */
        ssio_quarantine(datadir, &anchors_spec, "deserialize_failed");
        out->count = 0;
        return ANCHOR_LOAD_QUARANTINED;
    }
    return ANCHOR_LOAD_OK;
}
