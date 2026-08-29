/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM seeding REPORTING surface — how a registered artifact is described to
 * somebody else: the market offer, the served directory JSON, and the
 * introspection dump.
 *
 * Split out of rom_seed.c along the file-size ceiling seam. This file owns no
 * process-wide state at all — it holds no statics, takes no mutex, and opens
 * no file descriptor. Every artifact it reports on is read through
 * rom_seed_list(), which snapshots the registry under rom_seed.c's own
 * registry mutex, and every serve cap it reports comes from
 * rom_seed_throttle_push_json(), which snapshots the counters under the caps
 * mutex in rom_seed_throttle.c. So the split moves no locking here: this file
 * never holds a lock, which is precisely why it cannot change a lock order.
 *
 * Both artifact snapshots are HEAP buffers (zcl_calloc/free), not stack
 * arrays: ROM_SEED_MAX_ARTIFACTS × sizeof(struct rom_artifact) is ~1 MB and a
 * 512 KB darwin thread stack SIGBUSes on it.
 *
 * The public entry points stay declared in net/rom_seed.h; the private names
 * this file reaches back for are in rom_seed_internal.h.
 */
#include "rom_seed_internal.h"

#include "net/rom_seed.h"
#include "net/file_market.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROM_SUBSYS "rom_seed"

/* ── Announce ───────────────────────────────────────────────────────── */

/* The wire token for a kind. rom_seed_kind_from_name (rom_seed_classify.c) is
 * the inverse and must mirror these exact strings. */
static const char *kind_name(enum rom_artifact_kind k)
{
    switch (k) {
    case ROM_ARTIFACT_CONSENSUS_BUNDLE: return "consensus_bundle";
    case ROM_ARTIFACT_HEADER_SEED:      return "header_seed";
    case ROM_ARTIFACT_UNKNOWN:
    default:                            return "unknown";
    }
}

bool rom_seed_build_offer(const struct rom_artifact *a,
                          const uint8_t self_ip[16], uint16_t fs_port,
                          struct file_offer *out)
{
    if (!a || !out)
        LOG_FAIL(ROM_SUBSYS, "build_offer: null arg");
    memset(out, 0, sizeof(*out));
    memcpy(out->root_hash, a->chunk_root, 32);
    snprintf(out->filename, sizeof(out->filename), "%s", a->filename);
    out->size_bytes = a->size_bytes;
    out->num_chunks = a->num_chunks;
    out->price_per_mb = 0;              /* free tier — no payment gate */
    if (self_ip) memcpy(out->peer_ip, self_ip, 16);
    out->peer_port = fs_port;
    out->ttl = FILE_MARKET_MAX_TTL;
    out->last_seen = (int64_t)platform_time_wall_time_t();
    return true;
}

/* Parse the height out of a canonical bundle name
 * "consensus-state-bundle-<N>.sqlite" (matched on the bare basename, so the
 * "bundles/<name>" shape resolves the same). Returns 0 for the header seed, an
 * unknown kind, or any non-canonical name — the download-cosmetic default that
 * a legacy directory (no "height" field) also parses to. Pure, no I/O. */
static int64_t rom_bundle_height_from_name(const char *filename)
{
    if (!filename || !filename[0])
        return 0;
    const char *base = rom_basename(filename);
    static const char pfx[] = "consensus-state-bundle-";
    static const char sfx[] = ".sqlite";
    size_t bl = strlen(base), pl = sizeof(pfx) - 1, sl = sizeof(sfx) - 1;
    if (bl <= pl + sl || strncmp(base, pfx, pl) != 0 ||
        strcmp(base + bl - sl, sfx) != 0)
        return 0;
    const char *d = base + pl;
    size_t dcount = bl - pl - sl;
    if (dcount == 0 || dcount >= 19) /* fits int64 without overflow */
        return 0;
    int64_t h = 0;
    for (size_t i = 0; i < dcount; i++) {
        if (d[i] < '0' || d[i] > '9')
            return 0;
        h = h * 10 + (d[i] - '0');
    }
    return h;
}

size_t rom_seed_directory_json(char *buf, size_t max)
{
    if (!buf || max == 0) return 0;
    /* Heap: 8 × ~131KB = ~1MB — exceeds the 512KB darwin thread stack. */
    struct rom_artifact *arts = zcl_calloc(
        ROM_SEED_MAX_ARTIFACTS, sizeof(*arts), "rom-seed-directory");
    if (!arts) return 0;
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);

    size_t off = 0;
    int w = snprintf(buf + off, max - off, "[");
    if (w < 0 || (size_t)w >= max - off) return 0;
    off += (size_t)w;

    int emitted = 0;
    for (int i = 0; i < n; i++) {
        char digest_hex[65];
        HexStr(arts[i].chunk_root, 32, false, digest_hex, sizeof(digest_hex));
        char whole_hex[65];
        HexStr(arts[i].whole_sha3, 32, false, whole_hex, sizeof(whole_hex));
        w = snprintf(buf + off, max - off,
                     "%s{\"kind\":\"%s\",\"digest\":\"%s\",\"whole_sha3\":\"%s\","
                     "\"size\":%llu,\"chunk_size\":%u,\"chunks\":%u,"
                     "\"height\":%lld}",
                     emitted ? "," : "", kind_name(arts[i].kind),
                     digest_hex, whole_hex,
                     (unsigned long long)arts[i].size_bytes,
                     arts[i].chunk_size, arts[i].num_chunks,
                     (long long)rom_bundle_height_from_name(arts[i].filename));
        if (w < 0 || (size_t)w >= max - off) {
            /* Overflow — close the array at what we have so the JSON stays
             * well-formed rather than truncating mid-object. */
            break;
        }
        off += (size_t)w;
        emitted++;
    }

    w = snprintf(buf + off, max - off, "]");
    free(arts);
    if (w < 0 || (size_t)w >= max - off) return 0;
    off += (size_t)w;
    return off;
}

/* ── Introspection ──────────────────────────────────────────────────── */

bool rom_seed_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    /* Enable flag, the three cap knobs, then the four serve counters —
     * emitted by the translation unit that owns them, in the order the dump
     * has always emitted them. */
    rom_seed_throttle_push_json(out);

    /* Heap: 8 × ~131KB = ~1MB — exceeds the 512KB darwin thread stack. */
    struct rom_artifact *arts = zcl_calloc(
        ROM_SEED_MAX_ARTIFACTS, sizeof(*arts), "rom-seed-dump");
    if (!arts) {
        diag_push_health(out, false, "rom seed: allocation failed");
        return false;
    }
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    json_push_kv_int(out, "artifact_count", n);

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value o = {0};
        json_set_object(&o);
        char digest_hex[65];
        HexStr(arts[i].chunk_root, 32, false, digest_hex, sizeof(digest_hex));
        json_push_kv_str(&o, "kind", kind_name(arts[i].kind));
        json_push_kv_str(&o, "filename", arts[i].filename);
        json_push_kv_str(&o, "digest", digest_hex);
        json_push_kv_int(&o, "size", (int64_t)arts[i].size_bytes);
        json_push_kv_int(&o, "chunk_size", (int64_t)arts[i].chunk_size);
        json_push_kv_int(&o, "chunks", (int64_t)arts[i].num_chunks);
        json_push_kv_int(&o, "registered_at", arts[i].registered_at);
        json_push_back(&arr, &o);
        json_free(&o);
    }
    json_push_kv(out, "artifacts", &arr);
    json_free(&arr);

    bool ok = rom_seed_enabled();
    diag_push_health(out, ok,
                     ok ? "seeding enabled" : "seeding disabled by config");
    free(arts);
    return true;
}
