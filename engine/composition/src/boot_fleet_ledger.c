/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "ledger" mesh stream service and its pull lane (see the
 * header). One registration serves both halves; the primitive tells them
 * apart by which side opened the stream.
 */

// one-result-type-ok:closed-security-verdict — the callbacks return the
// stream primitive's bounded refusal enum; no diagnostic text crosses the
// wire. Failure logging happens here, with the refusal named.

#include "config/boot_fleet_ledger.h"

#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "boot_mesh_status_internal.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "fleetledger/fleet_ledger.h"
#include "models/mesh_pairing.h"
#include "net/net.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_LEDGER_PAIRINGS_MAX 64u

/* The initiator's per-stream state: who we asked, and what came back. */
struct fleet_pull_state {
    uint8_t peer_box_id[32];
    uint8_t peer_signer[32];
    size_t len;
    uint8_t rows[FLEET_LEDGER_ANSWER_MAX];
};

/* The acceptor's per-stream state: one bounded answer, read once at open. */
struct fleet_serve_state {
    size_t len;
    size_t sent;
    uint8_t rows[FLEET_LEDGER_ANSWER_MAX];
};

/* A verified-nothing batch waiting for the tick to commit it. The stream
 * lane only ever moves a pointer into here; every byte of verification and
 * every fsync happens in the tick, with no lock held. */
struct fleet_inbox_slot {
    bool used;
    uint8_t peer_box_id[32];
    uint8_t peer_signer[32];
    size_t len;
    uint8_t *rows;
};

static zcl_mutex_t g_ledger_lock;
static _Atomic int g_ledger_lock_state;
static struct boot_svc_ctx *g_ledger_svc; /* borrowed; set by wire() */
static struct zcl_fleet_ledger *g_ledger;
static uint8_t g_self_box_id[32];
static uint8_t g_self_signer[32];
static struct fleet_inbox_slot g_inbox[FLEET_LEDGER_INBOX_MAX];
static struct liveness_contract g_ledger_contract;
static supervisor_child_id g_ledger_child = SUPERVISOR_INVALID_ID;
static int64_t g_last_pull;

static void ledger_lock(void)
{
    if (atomic_load_explicit(&g_ledger_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_ledger_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_ledger_lock);
            atomic_store_explicit(&g_ledger_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_ledger_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_ledger_lock);
}

/* ── the PULL frame ──────────────────────────────────────────────────── */

static size_t pull_encode(uint64_t since_seq, uint8_t out[FLEET_LEDGER_PULL_BYTES])
{
    out[0] = (uint8_t)FLEET_LEDGER_MSG_PULL;
    out[1] = 1u; /* protocol version */
    zcl_write_u64_be(out + 2, since_seq);
    return FLEET_LEDGER_PULL_BYTES;
}

static bool pull_decode(const uint8_t *in, size_t len, uint64_t *since_out)
{
    if (!in || len != FLEET_LEDGER_PULL_BYTES ||
        in[0] != (uint8_t)FLEET_LEDGER_MSG_PULL || in[1] != 1u)
        return false;
    *since_out = zcl_read_u64_be(in + 2);
    return true;
}

/* ── the service callbacks ───────────────────────────────────────────── */

/* An inbound OPEN. The primitive has already proven an established Noise
 * session and a pairing row granting the capability; what is left is to
 * read the answer once, here, so the tick never has to touch a file. */
static enum mesh_stream_refusal ledger_service_open(struct mesh_stream *st,
                                                    const uint8_t *payload,
                                                    size_t len, uint8_t *reply,
                                                    size_t reply_cap,
                                                    size_t *reply_len,
                                                    void *ctx)
{
    (void)ctx;
    (void)reply;
    (void)reply_cap;
    if (reply_len)
        *reply_len = 0;
    uint64_t since = 0;
    if (!pull_decode(payload, len, &since))
        return MESH_STREAM_REFUSED_MALFORMED;

    ledger_lock();
    struct zcl_fleet_ledger *ledger = g_ledger;
    uint8_t self[32];
    memcpy(self, g_self_box_id, 32);
    zcl_mutex_unlock(&g_ledger_lock);
    if (!ledger)
        return MESH_STREAM_REFUSED_UNAVAILABLE;

    struct fleet_serve_state *s =
        zcl_calloc(1, sizeof *s, "fleet_ledger_serve");
    if (!s)
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    uint64_t last = 0;
    if (zcl_fleet_ledger_read_since(ledger, self, since, s->rows,
                                    sizeof s->rows, &s->len,
                                    &last) != ZCL_FLEET_OK) {
        free(s);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    st->service_state = s;
    return MESH_STREAM_OK;
}

/* The initiator receives the answer. Bytes are copied and credit is given
 * back; nothing is verified and nothing is written here. */
static void ledger_service_data(struct mesh_stream *st, const uint8_t *payload,
                                size_t len, void *ctx)
{
    (void)ctx;
    if (!st->local_initiator)
        return; /* the acceptor is a writer on this stream, never a reader */
    struct fleet_pull_state *p = st->service_state;
    if (!p || !payload || len == 0)
        return;
    if (p->len + len > sizeof p->rows) {
        /* More than one answer's worth. The peer is not following the
         * protocol, so the stream ends rather than the buffer growing. */
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        return;
    }
    memcpy(p->rows + p->len, payload, len);
    p->len += len;
    (void)mesh_stream_grant(st, (uint32_t)len);
}

/* The acceptor's drain: one answer, within the credit it holds, then the
 * stream is done. A pull that had nothing to say closes immediately, which
 * is what makes a second pull free. */
static void ledger_service_tick(struct mesh_stream *st, int64_t now, void *ctx)
{
    (void)now;
    (void)ctx;
    if (st->local_initiator)
        return;
    struct fleet_serve_state *s = st->service_state;
    if (!s) {
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        return;
    }
    size_t remaining = s->len - s->sent;
    if (remaining == 0) {
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
        return;
    }
    if (st->send_credit < remaining)
        return; /* wait for the window; never split a batch across frames */
    if (mesh_stream_send(st, s->rows + s->sent, remaining))
        s->sent += remaining;
}

/* The stream ended. The initiator hands its buffer to the tick by moving a
 * pointer into the inbox — no verification and no I/O under this lock. */
static void ledger_service_close(struct mesh_stream *st,
                                 enum mesh_stream_refusal reason,
                                 const uint8_t *payload, size_t len, void *ctx)
{
    (void)payload;
    (void)len;
    (void)ctx;
    if (!st->local_initiator)
        return;
    struct fleet_pull_state *p = st->service_state;
    if (!p || p->len == 0)
        return;
    if (reason != MESH_STREAM_CLOSED_BY_SERVICE && reason != MESH_STREAM_OK) {
        /* An answer that did not finish is not a short answer: the rows
         * that did arrive may be a prefix of a batch, and a prefix has no
         * standing. The next pull asks for the same range again. */
        return;
    }
    uint8_t *rows = zcl_malloc(p->len, "fleet_ledger_inbox");
    if (!rows)
        return;
    memcpy(rows, p->rows, p->len);

    ledger_lock();
    struct fleet_inbox_slot *slot = NULL;
    for (size_t i = 0; i < FLEET_LEDGER_INBOX_MAX && !slot; i++)
        if (!g_inbox[i].used)
            slot = &g_inbox[i];
    if (slot) {
        slot->used = true;
        memcpy(slot->peer_box_id, p->peer_box_id, 32);
        memcpy(slot->peer_signer, p->peer_signer, 32);
        slot->len = p->len;
        slot->rows = rows;
    }
    zcl_mutex_unlock(&g_ledger_lock);
    if (!slot)
        free(rows); /* the inbox is full; the next pull asks again */
}

static void ledger_service_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    free(st->service_state);
    st->service_state = NULL;
}

bool boot_fleet_ledger_register_service(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof(service));
    service.name = FLEET_LEDGER_SERVICE_NAME;
    /* The same grant a mesh status read needs. A ledger pull asks a paired
     * machine about itself, which is what that capability already means;
     * demanding a new bit would leave the service dead on every pairing
     * this fleet has already committed, and a pairing record is
     * insert-only, so those bits can never be added afterwards. */
    service.required_pairing_capability = MESH_PAIRING_CAP_STATUS_READ;
    service.on_open = ledger_service_open;
    service.on_data = ledger_service_data;
    service.on_close = ledger_service_close;
    service.on_tick = ledger_service_tick;
    service.on_release = ledger_service_release;
    return mesh_stream_service_register(&service);
}

/* ── the pull lane ───────────────────────────────────────────────────── */

/* Commit whatever the streams left behind. Runs on this lane's own tick
 * with no lock held over the file work, so two fsyncs per row cannot stall
 * the stream pump every service shares. */
static void ledger_drain_inbox(struct zcl_fleet_ledger *ledger)
{
    for (size_t i = 0; i < FLEET_LEDGER_INBOX_MAX; i++) {
        ledger_lock();
        struct fleet_inbox_slot slot = g_inbox[i];
        if (slot.used) {
            g_inbox[i].used = false;
            g_inbox[i].rows = NULL;
            g_inbox[i].len = 0;
        }
        zcl_mutex_unlock(&g_ledger_lock);
        if (!slot.used)
            continue;
        size_t accepted = 0;
        enum zcl_fleet_status st =
            zcl_fleet_ledger_replicate(ledger, slot.peer_box_id,
                                       slot.peer_signer, slot.rows, slot.len,
                                       &accepted);
        if (st != ZCL_FLEET_OK) {
            /* The refusal is named, and NOTHING about the rows is: this is
             * the owner's private data and a log is not private. */
            LOG_WARN("fleet.ledger", "replica batch refused: %s",
                     zcl_fleet_status_label(st));
        }
        (void)accepted;
        free(slot.rows);
    }
}

/* Is a ledger stream to this peer already live? Two pulls to one peer at
 * once would ask the same question twice and answer it twice. */
struct fleet_live_probe {
    uint8_t peer_static[32];
    bool found;
};

static bool ledger_live_visitor(struct mesh_stream *st, void *ctx)
{
    struct fleet_live_probe *probe = ctx;
    if (st->local_initiator && !st->ended &&
        memcmp(st->peer_static, probe->peer_static, 32) == 0) {
        probe->found = true;
        return false;
    }
    return true;
}

/* Open one pull toward every paired peer that is due one. The pairing check
 * is this lane's own: the primitive would refuse an inbound open from an
 * unpaired peer, but nothing would stop this side dialing one, and a row
 * must never be asked for over a link that is not a pairing. */
static void ledger_pull_paired_peers(struct zcl_fleet_ledger *ledger,
                                     int64_t now)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return;
    struct db_mesh_pairing *rows =
        zcl_calloc(FLEET_LEDGER_PAIRINGS_MAX, sizeof *rows,
                   "fleet_ledger_pairings");
    if (!rows)
        return;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_LEDGER_PAIRINGS_MAX);
    for (int i = 0; i < count; i++) {
        if (!mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ, now))
            continue;
        /* The peer's own delegation names both halves of its identity. A
         * peer whose delegation cannot be resolved is not asked: an answer
         * we could not attribute is an answer we could not accept. */
        struct vcs_zcode_dht_delegation peer;
        if (!boot_mesh_peer_delegation(&rows[i], &peer))
            continue;
        struct fleet_live_probe probe;
        memset(&probe, 0, sizeof probe);
        memcpy(probe.peer_static, rows[i].peer_noise_pubkey, 32);
        mesh_stream_visit(FLEET_LEDGER_SERVICE_NAME, ledger_live_visitor,
                          &probe);
        if (probe.found)
            continue;

        struct fleet_pull_state *p =
            zcl_calloc(1, sizeof *p, "fleet_ledger_pull");
        if (!p)
            break;
        memcpy(p->peer_box_id, peer.doc.master_pubkey, 32);
        memcpy(p->peer_signer, peer.online_pubkey, 32);
        uint8_t frame[FLEET_LEDGER_PULL_BYTES];
        size_t frame_len = pull_encode(
            zcl_fleet_ledger_peer_seq(ledger, p->peer_box_id), frame);
        uint64_t stream_id = 0;
        enum mesh_stream_refusal refusal =
            mesh_stream_open(FLEET_LEDGER_SERVICE_NAME,
                             rows[i].peer_noise_pubkey, 0, frame, frame_len,
                             p, &stream_id);
        if (refusal != MESH_STREAM_OK) {
            /* A peer that is simply not connected is the ordinary case on a
             * mesh and is not worth a line; anything else is. */
            if (refusal != MESH_STREAM_REFUSED_PEER_NOT_CONNECTED)
                LOG_WARN("fleet.ledger", "pull not opened: %s",
                          mesh_stream_refusal_string(refusal));
            free(p);
        }
    }
    free(rows);
}

static void ledger_tick(struct liveness_contract *contract)
{
    (void)contract;
    ledger_lock();
    struct zcl_fleet_ledger *ledger = g_ledger;
    struct boot_svc_ctx *svc = g_ledger_svc;
    int64_t last = g_last_pull;
    zcl_mutex_unlock(&g_ledger_lock);
    if (!ledger || !svc) {
        supervisor_progress_idle(g_ledger_child);
        return;
    }
    ledger_drain_inbox(ledger);

    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0 || (last != 0 && now - last < FLEET_LEDGER_PULL_INTERVAL_S)) {
        supervisor_progress_idle(g_ledger_child);
        return;
    }
    ledger_lock();
    g_last_pull = now;
    zcl_mutex_unlock(&g_ledger_lock);
    ledger_pull_paired_peers(ledger, now);
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

void boot_fleet_ledger_wire(struct boot_svc_ctx *svc)
{
    if (!svc || !svc->datadir) {
        LOG_ERROR("fleet.ledger", "wire: no datadir");
        return;
    }
    ledger_lock();
    bool already = g_ledger_svc != NULL;
    zcl_mutex_unlock(&g_ledger_lock);
    if (already) {
        LOG_ERROR("fleet.ledger", "wire: already wired");
        return;
    }

    /* This node's own identity, from the one place the mesh lanes already
     * take it: the filed delegation plus its ACTIVE master and online key.
     * Without it this box has nothing to sign with and no name to write
     * under, so the lane stays dark rather than inventing one. */
    struct node_db *ndb = app_runtime_node_db();
    uint8_t master[32];
    uint8_t online_pub[32];
    uint8_t online_seed[32];
    if (!ndb || !app_runtime_node_db_handle_open(ndb) ||
        !boot_mesh_local_identity(ndb, svc->datadir, master, online_pub,
                                  online_seed)) {
        LOG_WARN("fleet.ledger",
                 "identity unavailable; the fleet ledger stays closed");
        return;
    }
    memset(online_seed, 0, sizeof online_seed); /* this lane never signs */

    char dir[512];
    if ((size_t)snprintf(dir, sizeof dir, "%s/fleet_ledger", svc->datadir) >=
        sizeof dir) {
        LOG_ERROR("fleet.ledger", "wire: datadir path too long");
        return;
    }
    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger =
        zcl_fleet_ledger_open(dir, master, online_pub, &report);
    if (!ledger) {
        LOG_ERROR("fleet.ledger", "store refused to open: %s",
                  zcl_fleet_status_label(report.status));
        return;
    }

    ledger_lock();
    g_ledger_svc = svc;
    g_ledger = ledger;
    memcpy(g_self_box_id, master, 32);
    memcpy(g_self_signer, online_pub, 32);
    memset(g_inbox, 0, sizeof g_inbox);
    g_last_pull = 0;
    zcl_mutex_unlock(&g_ledger_lock);

    if (!boot_fleet_ledger_register_service()) {
        LOG_ERROR("fleet.ledger", "ledger stream service refused");
        return;
    }

    liveness_contract_init(&g_ledger_contract, "fleet.ledger_pull");
    g_ledger_contract.on_tick = ledger_tick;
    supervisor_domains_init();
    g_ledger_child = supervisor_register_in_domain(g_net_sup,
                                                   &g_ledger_contract);
    if (g_ledger_child == SUPERVISOR_INVALID_ID) {
        LOG_ERROR("fleet.ledger", "pull supervisor register failed");
        return;
    }
    supervisor_set_period(g_ledger_child, 1);
    g_ledger_contract.period_us = 1000000;
    supervisor_set_deadline(g_ledger_child, 120);
    supervisor_set_progress_exempt(g_ledger_child,
                                   "paired peers may have nothing new to say");
}

void boot_fleet_ledger_shutdown(void)
{
    mesh_stream_service_unregister(FLEET_LEDGER_SERVICE_NAME);
    supervisor_child_id child;
    ledger_lock();
    child = g_ledger_child;
    g_ledger_child = SUPERVISOR_INVALID_ID;
    struct zcl_fleet_ledger *ledger = g_ledger;
    g_ledger = NULL;
    g_ledger_svc = NULL;
    for (size_t i = 0; i < FLEET_LEDGER_INBOX_MAX; i++) {
        free(g_inbox[i].rows);
        g_inbox[i].rows = NULL;
        g_inbox[i].used = false;
    }
    zcl_mutex_unlock(&g_ledger_lock);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_unregister(child);
    /* Barrier with a callback the supervisor already snapshotted, so the
     * store is closed only once nothing can still be reading it. */
    ledger_lock();
    zcl_mutex_unlock(&g_ledger_lock);
    zcl_fleet_ledger_close(ledger);
}
