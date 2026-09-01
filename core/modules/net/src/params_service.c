/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* params_service.c — the six zparam* P2P commands.
 *
 * Serve side: answers only for files this node has verified against the
 * compiled-in digests, rate limited per peer and globally, reading one
 * bounded chunk per request. A node with no parameter files answers nothing
 * and costs nothing.
 *
 * Fetch side: a single-file-at-a-time requester that hands every arriving
 * byte to core/modules/sapling's verifier before it touches the disk. Peers are
 * sources of candidate bytes and nothing more — the requester keeps a waste
 * budget per peer and writes off a peer that spends it.
 *
 * Both sides are message-thread work only. There is no blocking I/O here
 * beyond a single bounded pread on the serve path; the expensive local
 * verification (streaming ~777 MB) happens once in param_service_arm_serving,
 * which the caller runs on a background thread.
 */

#include "net/params_service.h"

#include "msgprocessor_internal.h"

#include "net/fast_sync.h"
#include "net/connman.h"
#include "net/msg_bounds_guard.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "sapling/params_fetch.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Serve side ─────────────────────────────────────────────────────── */

static _Atomic bool g_serving = false;
static struct fast_sync_rate_limiter g_param_chunk_limiter;
static struct fast_sync_rate_limiter g_param_manifest_limiter;
static pthread_mutex_t g_serve_limiter_lock = PTHREAD_MUTEX_INITIALIZER;

/* fast_sync_rate_limiter accepts an opaque 16-byte bucket key despite its
 * historical `ip` spelling. Onion peers have an all-zero IP placeholder, so
 * key them by the stable torv3 identity head, matching the peer census. */
static void serve_rate_key(const struct net_addr *addr, uint8_t out[16])
{
    if (addr->has_torv3)
        memcpy(out, addr->torv3, 16);
    else
        memcpy(out, addr->ip, 16);
}

int param_service_arm_serving(const char *params_dir)
{
#if defined(_WIN32)
    (void)params_dir;
    /* params_fetch_session still uses path-based POSIX descriptors. Do not
     * expose parameter bytes until its retained-handle verifier is ported. */
    atomic_store(&g_serving, false);
    return 0;
#else
    int armed = zcl_param_serve_prepare(params_dir);
    atomic_store(&g_serving, armed > 0);
    return armed;
#endif
}

bool param_service_is_serving(void)
{
    return atomic_load(&g_serving);
}

static bool serve_rate_ok(struct fast_sync_rate_limiter *rl,
                          const struct p2p_node *node, uint32_t per_ip,
                          uint64_t global)
{
    bool ok;
    uint8_t key[16];
    serve_rate_key(&node->addr.svc.addr, key);
    pthread_mutex_lock(&g_serve_limiter_lock);
    ok = fast_sync_rate_check_n(rl, key, per_ip, global);
    pthread_mutex_unlock(&g_serve_limiter_lock);
    return ok;
}

static void push_msg(struct msg_processor *mp, struct p2p_node *node,
                     const char *cmd, const uint8_t *body, size_t len)
{
    if (!mp || !mp->params)
        return;
    if (!p2p_node_begin_message(node, cmd, mp->params->pchMessageStart))
        return;
    if (body && len)
        p2p_node_write_message_data(node, body, len);
    (void)p2p_node_end_message(node);
}

static void wire_entry_encode(uint8_t idx, uint64_t bytes, uint32_t chunks,
                              uint8_t out[13])
{
    out[0] = idx;
    zcl_write_u64_le(out + 1, bytes);
    zcl_write_u32_le(out + 9, chunks);
}

static void wire_chunk_request_encode(uint8_t idx, uint32_t chunk,
                                      uint8_t out[5])
{
    out[0] = idx;
    zcl_write_u32_le(out + 1, chunk);
}

/* "Which parameter files can you serve?" — answered with the pinned index,
 * length and chunk count of everything armed. A node that is not serving
 * replies with an empty list rather than staying silent, so the requester
 * can stop asking it. */
bool mp_handle_param_info_req(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s)
{
    (void)s;
    uint8_t body[1 + ZCL_PARAM_FILE_COUNT * (1 + 8 + 4)];
    size_t w = 1;
    uint8_t count = 0;
    for (int i = 0; i < ZCL_PARAM_FILE_COUNT; i++) {
        if (!zcl_param_serve_ready(i))
            continue;
        const struct zcl_param_pin *p = &zcl_param_pins[i];
        wire_entry_encode((uint8_t)i, p->bytes, p->chunk_count, body + w);
        w += 13;
        count++;
    }
    body[0] = count;
    push_msg(mp, node, MSG_PARAM_INFO, body, w);
    return true;
}

/* "Manifest for file N." Bounded: N is validated against the pin table, so
 * no wire byte ever becomes a path or an allocation size. */
bool mp_handle_param_man_req(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s)
{
    uint8_t idx8 = 0;
    if (!stream_read_u8(s, &idx8))
        return true;
    int idx = (int)idx8;
    if (!zcl_param_serve_ready(idx))
        return true;
    if (!serve_rate_ok(&g_param_manifest_limiter, node,
                       PARAM_SERVE_MAX_MANIFESTS_PER_HOUR,
                       PARAM_SERVE_MAX_MANIFESTS_PER_HOUR * 64ull))
        return true;

    /* Heap, not a per-thread static: this file is reached from every peer's
     * message thread, and a 128 KiB thread-local would be charged to every
     * thread in the process whether or not it ever serves a parameter. The
     * allocation is bounded by the compiled-in cap and this path is rate
     * limited to PARAM_SERVE_MAX_MANIFESTS_PER_HOUR. */
    uint32_t count = 0;
    uint8_t *man = zcl_malloc(ZCL_PARAM_MANIFEST_MAX_BYTES, "param_serve_man_out");
    if (!man)
        return true;
    if (!zcl_param_serve_manifest(idx, man, ZCL_PARAM_MANIFEST_MAX_BYTES, &count)) {
        free(man);
        return true;
    }

    struct byte_stream out;
    stream_init(&out, (size_t)count * ZCL_PARAM_HASH_BYTES + 8);
    stream_write_u8(&out, idx8);
    stream_write_u32_le(&out, count);
    stream_write(&out, man, (size_t)count * ZCL_PARAM_HASH_BYTES);
    if (!out.error)
        push_msg(mp, node, MSG_PARAM_MANIFEST, out.data, out.size);
    stream_free(&out);
    free(man);
    return true;
}

/* "Chunk C of file N." One bounded pread; never more than
 * ZCL_PARAM_CHUNK_BYTES leaves this node per request. */
bool mp_handle_param_chunk_req(struct msg_processor *mp, struct p2p_node *node,
                               struct byte_stream *s)
{
    uint8_t idx8 = 0;
    uint32_t chunk = 0;
    if (!stream_read_u8(s, &idx8) || !stream_read_u32_le(s, &chunk))
        return true;
    int idx = (int)idx8;
    if (!zcl_param_serve_ready(idx))
        return true;
    /* Refuse an out-of-range index before allocating anything. */
    size_t want = zcl_param_chunk_len(idx, chunk);
    if (want == 0)
        return true;
    if (!serve_rate_ok(&g_param_chunk_limiter, node,
                       PARAM_SERVE_MAX_CHUNKS_PER_HOUR,
                       PARAM_SERVE_MAX_GLOBAL_CHUNKS_PER_HOUR))
        return true;

    uint8_t *buf = zcl_malloc(ZCL_PARAM_CHUNK_BYTES, "param_serve_chunk_out");
    if (!buf)
        return true;
    size_t got = 0;
    if (zcl_param_serve_chunk(idx, chunk, buf, ZCL_PARAM_CHUNK_BYTES, &got)) {
        struct byte_stream out;
        stream_init(&out, got + 16);
        stream_write_u8(&out, idx8);
        stream_write_u32_le(&out, chunk);
        stream_write_u32_le(&out, (uint32_t)got);
        stream_write(&out, buf, got);
        if (!out.error)
            push_msg(mp, node, MSG_PARAM_CHUNK, out.data, out.size);
        stream_free(&out);
    }
    free(buf);
    return true;
}

/* ── Fetch side ─────────────────────────────────────────────────────── */

struct peer_waste {
    node_id_t id;
    uint64_t  wasted;
    bool      used;
};

struct inflight {
    node_id_t id;
    uint32_t  chunk;
    int64_t   deadline;
    bool      used;
};

static struct {
    bool                     active;
    char                     dir[1024];
    int                      file_idx;      /* pinned index in flight, -1 idle */
    struct zcl_param_fetch  *session;
    struct peer_waste        waste[PARAM_PEER_ACCOUNTING_SLOTS];
    struct inflight          inflight[64];
    int64_t                  manifest_deadline;
} g_fetch = { .file_idx = -1 };

static_assert(PARAM_PEER_ACCOUNTING_SLOTS >= REACTOR_MAX_FDS,
              "parameter peer accounting must cover reactor capacity");

static pthread_mutex_t g_fetch_lock = PTHREAD_MUTEX_INITIALIZER;

static int64_t now_secs(void)
{
    return (int64_t)platform_time_wall_time_t();
}

/* Advance to the next pinned file that is not already installed-and-verified.
 * Caller holds g_fetch_lock. */
static bool fetch_advance_locked(void)
{
    if (g_fetch.session) {
        /* Unpublish, THEN free. Nothing may hold a pointer into a session
         * that is being torn down — the same ordering core/modules/sapling's parameter
         * loader is held to for its verifying-key globals, for the same
         * reason: a reader that observes the pointer after the free reads
         * freed heap. Everything here is under g_fetch_lock, so this is
         * belt-and-braces rather than the only thing preventing it, which is
         * exactly how it should read. */
        struct zcl_param_fetch *dying = g_fetch.session;
        g_fetch.session = NULL;
        zcl_param_fetch_close(dying);
    }
    memset(g_fetch.inflight, 0, sizeof(g_fetch.inflight));
    g_fetch.manifest_deadline = 0;

    for (int i = g_fetch.file_idx + 1; i < ZCL_PARAM_FILE_COUNT; i++) {
        if (zcl_param_verify_installed(g_fetch.dir, i))
            continue;
        struct zcl_param_fetch *s = zcl_param_fetch_open(g_fetch.dir, i);
        if (!s)
            continue;
        g_fetch.file_idx = i;
        g_fetch.session = s;
        return true;
    }
    g_fetch.file_idx = ZCL_PARAM_FILE_COUNT;
    g_fetch.active = false;
    return false;
}

bool param_service_begin_fetch(const char *params_dir)
{
    if (!params_dir)
        return false;
#if defined(_WIN32)
    /* Fetch persists partial/state/final generations. Refuse before copying
     * the path or opening a session until private atomic replacement is used. */
    return false;
#else
    pthread_mutex_lock(&g_fetch_lock);
    snprintf(g_fetch.dir, sizeof(g_fetch.dir), "%s", params_dir);
    g_fetch.file_idx = -1;
    memset(g_fetch.waste, 0, sizeof(g_fetch.waste));
    bool any = fetch_advance_locked();
    g_fetch.active = any;
    pthread_mutex_unlock(&g_fetch_lock);
    if (!any)
        LOG_INFO("crypto.params",
                 "[crypto.params] proving parameters already complete and "
                 "verified in %s — nothing to fetch", params_dir);
    return any;
#endif
}

bool param_service_fetch_active(void)
{
    pthread_mutex_lock(&g_fetch_lock);
    bool a = g_fetch.active;
    pthread_mutex_unlock(&g_fetch_lock);
    return a;
}

void param_service_end_fetch(void)
{
    pthread_mutex_lock(&g_fetch_lock);
    if (g_fetch.session) {
        /* Unpublish, THEN free. Nothing may hold a pointer into a session
         * that is being torn down — the same ordering core/modules/sapling's parameter
         * loader is held to for its verifying-key globals, for the same
         * reason: a reader that observes the pointer after the free reads
         * freed heap. Everything here is under g_fetch_lock, so this is
         * belt-and-braces rather than the only thing preventing it, which is
         * exactly how it should read. */
        struct zcl_param_fetch *dying = g_fetch.session;
        g_fetch.session = NULL;
        zcl_param_fetch_close(dying);
    }
    g_fetch.active = false;
    g_fetch.file_idx = -1;
    pthread_mutex_unlock(&g_fetch_lock);
}

void param_service_progress(int *out_file, uint32_t *out_have,
                            uint32_t *out_total)
{
    pthread_mutex_lock(&g_fetch_lock);
    if (out_file)
        *out_file = g_fetch.session ? g_fetch.file_idx : -1;
    if (out_have)
        *out_have = zcl_param_fetch_chunks_have(g_fetch.session);
    if (out_total)
        *out_total = zcl_param_fetch_chunks_total(g_fetch.session);
    pthread_mutex_unlock(&g_fetch_lock);
}

/* Caller holds g_fetch_lock. */
static struct peer_waste *waste_slot_locked(node_id_t id)
{
    struct peer_waste *free_slot = NULL;
    for (size_t i = 0; i < sizeof(g_fetch.waste) / sizeof(g_fetch.waste[0]); i++) {
        if (g_fetch.waste[i].used && g_fetch.waste[i].id == id)
            return &g_fetch.waste[i];
        if (!g_fetch.waste[i].used && !free_slot)
            free_slot = &g_fetch.waste[i];
    }
    if (free_slot) {
        free_slot->used = true;
        free_slot->id = id;
        free_slot->wasted = 0;
    }
    return free_slot;
}

static bool peer_written_off_locked(node_id_t id)
{
    struct peer_waste *w = waste_slot_locked(id);
    /* The table covers every admitted connection. If that invariant is ever
     * broken, fail closed rather than grant an unaccounted peer free hashing. */
    return !w || w->wasted >= PARAM_PEER_WASTE_BUDGET_BYTES;
}

static void peer_charge_locked(node_id_t id, uint64_t bytes)
{
    struct peer_waste *w = waste_slot_locked(id);
    if (w)
        w->wasted += bytes;
}

static uint32_t inflight_count_locked(node_id_t id)
{
    uint32_t n = 0;
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++)
        if (g_fetch.inflight[i].used && g_fetch.inflight[i].id == id)
            n++;
    return n;
}

static bool inflight_has_locked(uint32_t chunk)
{
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++)
        if (g_fetch.inflight[i].used && g_fetch.inflight[i].chunk == chunk)
            return true;
    return false;
}

static bool inflight_has_peer_locked(node_id_t id, uint32_t chunk)
{
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++)
        if (g_fetch.inflight[i].used && g_fetch.inflight[i].id == id &&
            g_fetch.inflight[i].chunk == chunk)
            return true;
    return false;
}

/* The last gate before zcl_param_fetch_accept_chunk hashes or writes bytes. */
static bool chunk_admitted_locked(node_id_t id, uint32_t chunk)
{
    return !peer_written_off_locked(id) &&
           inflight_has_peer_locked(id, chunk);
}

static bool inflight_add_locked(node_id_t id, uint32_t chunk, int64_t now)
{
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++) {
        if (g_fetch.inflight[i].used)
            continue;
        g_fetch.inflight[i].used = true;
        g_fetch.inflight[i].id = id;
        g_fetch.inflight[i].chunk = chunk;
        g_fetch.inflight[i].deadline = now + PARAM_REQUEST_TIMEOUT_SECS;
        return true;
    }
    return false;
}

static void inflight_clear_locked(uint32_t chunk)
{
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++)
        if (g_fetch.inflight[i].used && g_fetch.inflight[i].chunk == chunk)
            g_fetch.inflight[i].used = false;
}

/* Queue up to PARAM_MAX_INFLIGHT_PER_PEER chunk requests to one peer, skipping
 * chunks already in flight elsewhere so several peers make progress on
 * different parts of the same file. Caller holds g_fetch_lock. */
static void request_chunks_locked(struct msg_processor *mp,
                                  struct p2p_node *node)
{
    if (!g_fetch.session || !zcl_param_fetch_has_manifest(g_fetch.session))
        return;
    uint32_t budget = PARAM_MAX_INFLIGHT_PER_PEER - inflight_count_locked(node->id);
    if (budget == 0 || budget > PARAM_MAX_INFLIGHT_PER_PEER)
        return;

    uint32_t total = zcl_param_fetch_chunks_total(g_fetch.session);
    uint32_t picks[PARAM_MAX_INFLIGHT_PER_PEER * 8];
    uint32_t start = total ? (uint32_t)((uint64_t)node->id % total) : 0;
    uint32_t n = zcl_param_fetch_pick_missing(g_fetch.session, start, picks,
                                              (uint32_t)(sizeof(picks) / sizeof(picks[0])));
    int64_t now = now_secs();
    uint32_t sent = 0;
    for (uint32_t i = 0; i < n && sent < budget; i++) {
        if (inflight_has_locked(picks[i]))
            continue;
        uint8_t body[5];
        wire_chunk_request_encode((uint8_t)g_fetch.file_idx, picks[i], body);
        if (!inflight_add_locked(node->id, picks[i], now))
            break;
        push_msg(mp, node, MSG_PARAM_CHUNK_REQ, body, sizeof(body));
        sent++;
    }
}

void param_service_offer_peer(struct msg_processor *mp, struct p2p_node *node)
{
    if (!mp || !node)
        return;
    if (!param_service_fetch_active())
        return;
    push_msg(mp, node, MSG_PARAM_INFO_REQ, NULL, 0);
}

/* A peer's answer to zparaminfo. Every field is a hint, and a hint that
 * disagrees with the compiled-in pin means we simply do not ask this peer —
 * it is never a reason to change what we believe the file is. */
bool mp_handle_param_info(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s)
{
    uint8_t count = 0;
    if (!stream_read_u8(s, &count))
        return true;
    if (msg_count_exceeds("net", "zparamhave", count, ZCL_PARAM_FILE_COUNT,
                          node->addr_name))
        return true;

    bool serves_ours = false;
    pthread_mutex_lock(&g_fetch_lock);
    int want = g_fetch.active ? g_fetch.file_idx : -1;
    pthread_mutex_unlock(&g_fetch_lock);

    for (uint8_t i = 0; i < count; i++) {
        uint8_t idx8 = 0;
        uint64_t bytes = 0;
        uint32_t cc = 0;
        if (!stream_read_u8(s, &idx8) || !stream_read_u64_le(s, &bytes) ||
            !stream_read_u32_le(s, &cc))
            return true;
        if ((int)idx8 >= ZCL_PARAM_FILE_COUNT)
            continue;
        const struct zcl_param_pin *p = &zcl_param_pins[idx8];
        /* Disagreement with the pin is the peer's problem, not ours. */
        if (bytes != p->bytes || cc != p->chunk_count)
            continue;
        if ((int)idx8 == want)
            serves_ours = true;
    }
    if (!serves_ours)
        return true;

    pthread_mutex_lock(&g_fetch_lock);
    if (g_fetch.active && g_fetch.session && !peer_written_off_locked(node->id)) {
        if (!zcl_param_fetch_has_manifest(g_fetch.session)) {
            uint8_t body[1] = { (uint8_t)g_fetch.file_idx };
            push_msg(mp, node, MSG_PARAM_MAN_REQ, body, 1);
            g_fetch.manifest_deadline = now_secs() + PARAM_REQUEST_TIMEOUT_SECS;
        } else {
            request_chunks_locked(mp, node);
        }
    }
    pthread_mutex_unlock(&g_fetch_lock);
    return true;
}

bool mp_handle_param_manifest(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s)
{
    uint8_t idx8 = 0;
    uint32_t count = 0;
    if (!stream_read_u8(s, &idx8) || !stream_read_u32_le(s, &count))
        return true;
    if ((int)idx8 >= ZCL_PARAM_FILE_COUNT)
        return true;

    /* The claimed count is checked against the compiled-in pin BEFORE any
     * buffer is sized or read. A peer claiming 4 billion chunks gets refused
     * here having caused one comparison. */
    if (count == 0 || count > ZCL_PARAM_MAX_CHUNKS ||
        count != zcl_param_pins[idx8].chunk_count)
        return true;
    size_t need = (size_t)count * ZCL_PARAM_HASH_BYTES;
    if (stream_remaining(s) < need)
        return true;

    /* Verify in place out of the receive buffer. The bounds check above is
     * what makes this safe, and it means a hostile manifest costs us one
     * Merkle fold and not one byte of copying or allocation. */
    const uint8_t *leaves = (const uint8_t *)(s->data + s->read_pos);
    s->read_pos += need;

    pthread_mutex_lock(&g_fetch_lock);
    if (g_fetch.active && g_fetch.session && (int)idx8 == g_fetch.file_idx &&
        !peer_written_off_locked(node->id)) {
        if (zcl_param_fetch_set_manifest(g_fetch.session, leaves, count)) {
            g_fetch.manifest_deadline = 0;
            request_chunks_locked(mp, node);
        } else {
            /* A manifest that does not fold to the compiled-in root is the
             * clearest possible signal about a peer. Charge the whole budget
             * at once: there is no innocent explanation. */
            peer_charge_locked(node->id, PARAM_PEER_WASTE_BUDGET_BYTES);
            LOG_WARN("crypto.params",
                     "[crypto.params] peer %s sent a parameter manifest that "
                     "does not match the compiled-in chunk root — written off",
                     node->addr_name);
        }
    }
    pthread_mutex_unlock(&g_fetch_lock);
    return true;
}

bool mp_handle_param_chunk(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    uint8_t idx8 = 0;
    uint32_t chunk = 0, len = 0;
    if (!stream_read_u8(s, &idx8) || !stream_read_u32_le(s, &chunk) ||
        !stream_read_u32_le(s, &len))
        return true;
    if ((int)idx8 >= ZCL_PARAM_FILE_COUNT)
        return true;

    /* `len` is hostile. Compare it to the exact length this chunk index MUST
     * have — a value derived from the compiled-in pin — before reading a
     * byte. An oversized field is refused here, with no allocation. */
    size_t want = zcl_param_chunk_len((int)idx8, chunk);
    if (want == 0 || (size_t)len != want)
        return true;
    if (stream_remaining(s) < want)
        return true;

    /* Hash and verify straight out of the receive buffer — no copy, no
     * allocation. The bounds check above is what makes this safe. A chunk
     * that fails its manifest hash therefore costs exactly one SHA-256 and
     * never reaches an allocator or the disk. */
    const uint8_t *buf = (const uint8_t *)(s->data + s->read_pos);
    s->read_pos += want;

    pthread_mutex_lock(&g_fetch_lock);
    if (!g_fetch.active || !g_fetch.session || (int)idx8 != g_fetch.file_idx) {
        pthread_mutex_unlock(&g_fetch_lock);
        return true;
    }
    /* A response has authority to consume CPU and touch the partial file only
     * when this node requested this exact chunk from this exact peer. Check
     * both predicates before the chunk hash in zcl_param_fetch_accept_chunk.
     * Unsolicited traffic and peers that exhausted their waste budget are
     * discarded at constant cost. */
    if (!chunk_admitted_locked(node->id, chunk)) {
        pthread_mutex_unlock(&g_fetch_lock);
        return true;
    }
    enum zcl_param_chunk_result r =
        zcl_param_fetch_accept_chunk(g_fetch.session, chunk, buf, want);
    if (r == ZCL_PARAM_CHUNK_OK) {
        inflight_clear_locked(chunk);
    } else {
        peer_charge_locked(node->id, want);
        if (r == ZCL_PARAM_CHUNK_BAD_HASH)
            LOG_WARN("crypto.params",
                     "[crypto.params] peer %s sent chunk %u of '%s' that does "
                     "not match the verified manifest — discarded unwritten",
                     node->addr_name, chunk, zcl_param_pins[idx8].name);
        inflight_clear_locked(chunk);
    }

    if (zcl_param_fetch_is_complete(g_fetch.session)) {
        if (zcl_param_fetch_finalize(g_fetch.session)) {
            (void)fetch_advance_locked();
            if (!g_fetch.session)
                LOG_INFO("crypto.params",
                         "[crypto.params] proving parameter set complete and "
                         "verified — shielded send can be armed");
        }
    } else if (r == ZCL_PARAM_CHUNK_OK) {
        request_chunks_locked(mp, node);
    }
    pthread_mutex_unlock(&g_fetch_lock);
    return true;
}

void param_service_tick(struct msg_processor *mp, int64_t now)
{
    (void)mp;
    pthread_mutex_lock(&g_fetch_lock);
    for (size_t i = 0; i < sizeof(g_fetch.inflight) / sizeof(g_fetch.inflight[0]); i++) {
        if (!g_fetch.inflight[i].used)
            continue;
        if (g_fetch.inflight[i].deadline <= now) {
            /* Expire the slot; the chunk goes back into the missing set and
             * the next peer that answers a zparaminfo will be asked for it. */
            g_fetch.inflight[i].used = false;
        }
    }
    if (g_fetch.manifest_deadline && g_fetch.manifest_deadline <= now)
        g_fetch.manifest_deadline = 0;
    pthread_mutex_unlock(&g_fetch_lock);
}

#ifdef ZCL_TESTING
void param_service_test_rate_key(const uint8_t ip[16], bool has_torv3,
                                 const uint8_t torv3[32], uint8_t out[16])
{
    struct net_addr addr = {0};
    memcpy(addr.ip, ip, 16);
    addr.has_torv3 = has_torv3;
    memcpy(addr.torv3, torv3, 32);
    serve_rate_key(&addr, out);
}

void param_service_test_wire_entry(uint8_t idx, uint64_t bytes,
                                   uint32_t chunks, uint8_t out[13])
{
    wire_entry_encode(idx, bytes, chunks, out);
}

void param_service_test_wire_chunk_request(uint8_t idx, uint32_t chunk,
                                           uint8_t out[5])
{
    wire_chunk_request_encode(idx, chunk, out);
}

void param_service_test_peer_guard_reset(void)
{
    pthread_mutex_lock(&g_fetch_lock);
    memset(g_fetch.waste, 0, sizeof(g_fetch.waste));
    memset(g_fetch.inflight, 0, sizeof(g_fetch.inflight));
    pthread_mutex_unlock(&g_fetch_lock);
}

bool param_service_test_mark_requested(int32_t id, uint32_t chunk)
{
    pthread_mutex_lock(&g_fetch_lock);
    bool ok = inflight_add_locked(id, chunk, now_secs());
    pthread_mutex_unlock(&g_fetch_lock);
    return ok;
}

void param_service_test_charge_peer(int32_t id, uint64_t bytes)
{
    pthread_mutex_lock(&g_fetch_lock);
    peer_charge_locked(id, bytes);
    pthread_mutex_unlock(&g_fetch_lock);
}

bool param_service_test_chunk_admitted(int32_t id, uint32_t chunk)
{
    pthread_mutex_lock(&g_fetch_lock);
    bool ok = chunk_admitted_locked(id, chunk);
    pthread_mutex_unlock(&g_fetch_lock);
    return ok;
}

int param_service_test_accept_chunk(uint32_t file_idx, uint32_t chunk_idx,
                                    const uint8_t *data, size_t len)
{
    int r;
    pthread_mutex_lock(&g_fetch_lock);
    if (!g_fetch.session || (int)file_idx != g_fetch.file_idx)
        r = (int)ZCL_PARAM_CHUNK_BAD_INDEX;
    else
        r = (int)zcl_param_fetch_accept_chunk(g_fetch.session, chunk_idx, data, len);
    pthread_mutex_unlock(&g_fetch_lock);
    return r;
}
#endif
