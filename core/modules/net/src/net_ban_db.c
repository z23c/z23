/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * net_ban_db.c — banlist.dat persistence (ban_db_write / ban_db_read and
 * the flush-state accessor). Split out of net.c so that file stays under
 * its shrink-only file-size pin; the code below moved verbatim. */

#include "net/net.h"
#include "net/peer_scoring.h"
#include "net_internal.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "core/hash.h"
#include "core/utiltime.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "storage/sha3_sidecar_io.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif

/* ── Ban persistence: <datadir>/banlist.dat ──────────────────────────
 * One self-verifying file — see the doc comment on ban_db_write()/
 * ban_db_read() in net.h for the format rationale. Reuses
 * EV_ADDRMAN_CORRUPT for the (rare) quarantine event since a corrupt
 * banlist.dat is the same class of datadir-tampering concern as a
 * corrupt peers.dat, and adding a dedicated event type would require
 * touching engine/modules/event/src (outside this module's file set). */
#define BAN_DB_MAGIC "ZBAN"
#define BAN_DB_VERSION 1u

static const struct ssio_spec g_ban_db_spec = {
    .body_name     = "banlist.dat",
    .sidecar_name  = "banlist.dat.sha3", /* unused on the embedded path;
                                          * kept so ssio_quarantine() can
                                          * sweep aside a stray legacy
                                          * sidecar if one is ever found */
    .magic         = BAN_DB_MAGIC,
    .version       = BAN_DB_VERSION,
    .domain        = "net_ban",
    .malloc_label  = "ban_db_hash_buf",
    .corrupt_event = EV_ADDRMAN_CORRUPT,
};

struct ban_db_payload_ctx {
    const uint8_t *data;
    size_t size;
};

static bool ban_db_emit_payload(FILE *f, void *ctx_, uint64_t *out_payload_size,
                                uint8_t out_payload_sha3[32])
{
    struct ban_db_payload_ctx *ctx = (struct ban_db_payload_ctx *)ctx_;
    if (ctx->size > 0 && fwrite(ctx->data, 1, ctx->size, f) != ctx->size)
        return false;
    zcl_sha3_256(ctx->data, ctx->size, out_payload_sha3);
    *out_payload_size = (uint64_t)ctx->size;
    return true;
}

bool ban_db_write(struct net_manager *nm, const char *datadir)
{
    if (!nm || !datadir) return false;

    /* Lock before cs_banned so an older snapshot cannot land after a newer
     * one; see cs_ban_db_write in net.h. */
    zcl_mutex_lock(&nm->cs_ban_db_write);
    /* Serialize entries before prepending their count; patching raw stream
     * bytes would be endian-fragile. */
    struct byte_stream entries;
    stream_init(&entries, 4096);

    int64_t now = GetTime();
    uint32_t live = 0;
    uint64_t gen_snapshot;
    zcl_mutex_lock(&nm->cs_banned);
    gen_snapshot = nm->ban_db_generation;
    for (size_t i = 0; i < nm->num_banned; i++) {
        const struct ban_entry *b = &nm->banned[i];
        if (b->ban_until <= now)
            continue; /* lazy prune: never persist an already-expired ban */
        stream_write(&entries, b->addr.ip, 16);
        stream_write(&entries, b->addr.torv3, TORV3_ADDR_SIZE);
        stream_write_u8(&entries, b->addr.has_torv3 ? 1 : 0);
        stream_write_u8(&entries, b->prefix_len);
        stream_write_i64_le(&entries, b->ban_until);
        stream_write_i32_le(&entries, b->score_at_ban);
        stream_write(&entries, (const unsigned char *)b->reason, sizeof(b->reason));
        live++;
    }
    zcl_mutex_unlock(&nm->cs_banned);
#ifdef ZCL_TESTING
    if (nm->ban_db_after_snapshot_test_hook)
        nm->ban_db_after_snapshot_test_hook(nm->ban_db_after_snapshot_test_ctx);
#endif
    struct byte_stream s;
    stream_init(&s, entries.size + 8);
    stream_write_u32_le(&s, live);
    stream_write(&s, entries.data, entries.size);
    stream_free(&entries);

    struct ban_db_payload_ctx ctx = { .data = s.data, .size = s.size };
    struct zcl_result wr = ssio_write_embedded(datadir, &g_ban_db_spec,
                                               ban_db_emit_payload, &ctx);
    stream_free(&s);
    if (!wr.ok) {
        LOG_WARN("net", "ban_db_write: %s", wr.message);
        zcl_mutex_unlock(&nm->cs_ban_db_write);
        return false;
    }
    /* Success restarts the AUTO-write debounce clock — so unban_addr()/
     * clear_banned(), which always write, keep the file immediately
     * consistent. The dirty flag, though, is cleared only when the table is
     * still exactly what was serialized above: a mutation that landed
     * between the snapshot and this line set ban_db_dirty itself, and the
     * file just written does not contain it. Clearing the flag anyway would
     * drop that mutation until some later mutation happened to rewrite the
     * file — a restart in between amnesties the ban. Leaving it set costs
     * one extra rewrite: the next debounced write, or the destroy flush,
     * serializes the newer table. Under cs_banned: all three fields are
     * declared cs_banned-guarded. */
    zcl_mutex_lock(&nm->cs_banned);
    nm->ban_db_last_write_unix = now;
    if (nm->ban_db_generation == gen_snapshot)
        nm->ban_db_dirty = false;
    zcl_mutex_unlock(&nm->cs_banned);

    zcl_mutex_unlock(&nm->cs_ban_db_write);
    return true;
}

struct ban_db_flush_state ban_db_flush_state_read(struct net_manager *nm)
{
    struct ban_db_flush_state st = { .generation = 0, .dirty = false };
    if (!nm) return st;
    zcl_mutex_lock(&nm->cs_banned);
    st.generation = nm->ban_db_generation;
    st.dirty = nm->ban_db_dirty;
    zcl_mutex_unlock(&nm->cs_banned);
    return st;
}

/* Reads the verified banlist payload at path into a fresh buffer and stores
 * its length in *payload_size. Returns NULL on any I/O failure, with the file
 * closed and nothing allocated. */
static uint8_t *ban_db_read_payload(const char *path, uint64_t payload_off,
                                    size_t *payload_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long total = ftell(f);
    if (total < 0 || (uint64_t)total < payload_off) { fclose(f); return NULL; }
    size_t size = (size_t)total - (size_t)payload_off;
    if (fseek(f, (long)payload_off, SEEK_SET) != 0) { fclose(f); return NULL; }

    uint8_t *buf = zcl_malloc(size > 0 ? size : 1, "ban_db_read_buf");
    if (!buf) { fclose(f); return NULL; }
    size_t rd = size > 0 ? fread(buf, 1, size, f) : 0;
    fclose(f);
    if (rd != size) { free(buf); return NULL; }
    *payload_size = size;
    return buf;
}

/* Reads one serialized ban entry. Returns false when the stream runs short
 * or a read fails; the caller stops parsing and keeps what already loaded. */
static bool ban_db_read_record(struct byte_stream *s, struct ban_entry *b)
{
    bool ok = true;
    uint8_t has_torv3 = 0;
    memset(b, 0, sizeof(*b));
    ok = ok && stream_read(s, b->addr.ip, 16);
    ok = ok && stream_read(s, b->addr.torv3, TORV3_ADDR_SIZE);
    ok = ok && stream_read_u8(s, &has_torv3);
    ok = ok && stream_read_u8(s, &b->prefix_len);
    ok = ok && stream_read_i64_le(s, &b->ban_until);
    ok = ok && stream_read_i32_le(s, &b->score_at_ban);
    ok = ok && stream_read(s, (unsigned char *)b->reason, sizeof(b->reason));
    if (!ok) return false;
    b->addr.has_torv3 = has_torv3 != 0;
    b->reason[sizeof(b->reason) - 1] = '\0';
    return true;
}

/* Appends a loaded entry if the in-memory table can take it, growing the
 * table first when needed. Returns false when the entry was not stored. */
static bool ban_db_read_insert(struct net_manager *nm, const struct ban_entry *b)
{
    zcl_mutex_lock(&nm->cs_banned);
    if (nm->num_banned >= nm->banned_cap) {
        size_t newcap = nm->banned_cap ? nm->banned_cap * 2 : 64;
        struct ban_entry *tmp = zcl_realloc(nm->banned, newcap * sizeof(*tmp), "ban_list");
        if (tmp) { nm->banned = tmp; nm->banned_cap = newcap; }
    }
    bool inserted = nm->num_banned < nm->banned_cap;
    if (inserted)
        nm->banned[nm->num_banned++] = *b;
    zcl_mutex_unlock(&nm->cs_banned);
    return inserted;
}

bool ban_db_read(struct net_manager *nm, const char *datadir)
{
    if (!nm || !datadir) return false;

    struct ssio_sidecar_header hdr;
    uint64_t payload_off = 0;
    enum ssio_read_verdict v = ssio_verify_embedded(datadir, &g_ban_db_spec,
                                                    &hdr, &payload_off);
    if (v == SSIO_READ_MISSING)
        return false; /* clean first-run/no persisted bans yet */
    if (v != SSIO_READ_OK) {
        LOG_WARN("net", "ban_db_read: integrity check failed (verdict=%d) — "
                 "quarantining banlist.dat and starting with no persisted bans",
                 (int)v);
        ssio_quarantine(datadir, &g_ban_db_spec, "verify_failed");
        return false;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", datadir, g_ban_db_spec.body_name);
    size_t payload_size = 0;
    uint8_t *buf = ban_db_read_payload(path, payload_off, &payload_size);
    if (!buf) return false;

    struct byte_stream s;
    stream_init_from_data(&s, buf, payload_size);

    uint32_t count = 0;
    bool ok = stream_read_u32_le(&s, &count);
    if (ok && count > MAX_BAN_ENTRIES) {
        LOG_WARN("net", "ban_db_read: count %u exceeds MAX_BAN_ENTRIES (%d) — refusing",
                 count, MAX_BAN_ENTRIES);
        ok = false;
    }

    int64_t now = GetTime();
    uint32_t loaded = 0, expired_skipped = 0, cap_dropped = 0;
    for (uint32_t i = 0; ok && i < count; i++) {
        struct ban_entry b;
        ok = ban_db_read_record(&s, &b);
        if (!ok) break;

        if (b.ban_until <= now) {
            expired_skipped++;
            continue; /* lazy prune at load time too */
        }
        if (nm->num_banned >= NET_BAN_TABLE_MAX) {
            /* The in-memory table is hard-capped; a persisted table larger
             * than the cap keeps its first NET_BAN_TABLE_MAX rows (file
             * order). The file is a snapshot, not a promise about which
             * rows matter most — the live eviction policy is what keeps
             * the table useful after this. */
            cap_dropped++;
            continue;
        }

        if (ban_db_read_insert(nm, &b))
            loaded++;
    }

    stream_free(&s);
    free(buf);

    if (!ok) {
        LOG_WARN("net", "ban_db_read: malformed payload (loaded %u entries "
                 "before the parse error) — keeping what loaded", loaded);
    }
    LOG_INFO("net", "ban_db_read: loaded %u bans (%u expired skipped, "
             "%u dropped at the %d-entry cap) from %s",
             loaded, expired_skipped, cap_dropped, NET_BAN_TABLE_MAX, path);
    return true;
}
