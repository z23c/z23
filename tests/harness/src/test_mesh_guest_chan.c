/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the guest byte-channel adapter against a FAKE device over the
 * two-peer stream loopback (two real p2p nodes, production Noise sealing,
 * production frame decoder). The fake device scripts accept results and the
 * number of bytes each write takes, and records every call. Nothing here
 * runs a real emulator, a real secure shell or a real network.
 *
 * Covered: default-off and the kill switch, the pairing bit, revocation
 * racing a delivery / a send / a credit grant, session loss, partial writes,
 * backpressure, bounds and protocol faults, stale tokens, idle, an outbound
 * open with no session, the forbidden-call source scan, and the pairing
 * capability bit itself.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "config/mesh_guest_chan.h"
#include "config/mesh_guest_service.h"
#include "crypto/sha256.h"
#include <time.h>
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/mesh_term_fixture.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "net/protocol.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#endif

/* Source twin: one local clock refusal, with real runner ownership/accounting. */
#include "platform/time_compat.h"
static bool gct_retry_clock_fail;
static bool gct_protected_ready_clock_live;
static int64_t gct_protected_ready_clock_ms;
static unsigned gct_protected_ready_clock_reads;
static unsigned gct_protected_ready_enable_calls;
static bool gct_protected_ready_enable(bool on)
{
    if(gct_protected_ready_clock_live&&on)gct_protected_ready_enable_calls++;
    return mesh_guest_chan_set_enabled(on);
}
static int64_t gct_protected_ready_clock(void)
{
    if(!gct_protected_ready_clock_live)return platform_time_monotonic_ms();
    gct_protected_ready_clock_reads++;
    return gct_protected_ready_clock_ms;
}
static unsigned gct_retry_clock_failures, gct_retry_destroy_calls;
static bool gct_retry_destroy_pending;
static uint64_t gct_retry_destroy_retired;
static unsigned gct_enrollment_factory_calls;
/* Synthetic loader fixture digest, solely for this actual-manager source twin.
 * This does not qualify any FreeBSD receiver or production image. */
static uint8_t gct_public_consumer_digest[32];
static uintptr_t gct_public_credential_native = UINTPTR_MAX;
static unsigned gct_public_credential_reads;
static int64_t gct_public_read(const struct platform_positioned_file *file, void *bytes,
    size_t length, uint64_t offset)
{
    if (file->native == gct_public_credential_native) gct_public_credential_reads++;
    return platform_positioned_file_read(file, bytes, length, offset);
}
static enum rvmachine_status gct_enrollment_runner_create(struct guest_service_runner **out,
    const struct rvmachine_config *config, const uint8_t *kernel, size_t length,
    const struct guest_limits *limits, bool *consumed)
{
    gct_enrollment_factory_calls++;
    return guest_service_runner_create(out, config, kernel, length, limits, consumed);
}
static int64_t gct_retry_clock(void)
{
    if (gct_retry_clock_fail) {
        gct_retry_clock_fail = false;
        gct_retry_clock_failures++;
        return -1;
    }
    return platform_time_monotonic_us();
}
static bool gct_retry_runner_destroy(struct guest_service_runner *runner)
{
    struct guest_service_runner_snapshot snapshot;
    if (!guest_service_runner_snapshot(runner, &snapshot)) return false;
    gct_retry_destroy_calls++;
    gct_retry_destroy_pending = snapshot.accounting_pending;
    struct rvmachine *machine = guest_service_runner_device(runner);
    if (!machine) return false;
    gct_retry_destroy_retired = rvmachine_retired(machine);
    return guest_service_runner_destroy(runner);
}
#define mesh_guest_service_create gct_retry_create
#define mesh_guest_service_attach gct_retry_attach
#define mesh_guest_service_enable gct_retry_enable
#define mesh_guest_service_pump gct_retry_pump
#define mesh_guest_service_slice gct_retry_slice
#define mesh_guest_service_stop gct_retry_stop
#define mesh_guest_service_destroy gct_retry_destroy
#define mesh_guest_service_snapshot gct_retry_snapshot
#define mesh_guest_service_test_machine gct_retry_test_machine
#define mesh_guest_service_manager_create gct_retry_manager_create
#define mesh_guest_service_manager_event gct_retry_manager_event
#define mesh_guest_service_manager_instance gct_retry_manager_instance
#define mesh_guest_service_manager_storage_synced gct_retry_manager_storage_synced
#define mesh_guest_service_manager_unlock_public gct_retry_manager_unlock_public
#define mesh_guest_service_manager_protected_tuple gct_retry_manager_protected_tuple
#define mesh_guest_service_manager_unlock_protected gct_retry_manager_unlock_protected
#define mesh_guest_service_manager_identity_finish gct_retry_manager_identity_finish
#define mesh_guest_service_manager_ready gct_retry_manager_ready
#define mesh_guest_service_manager_drive gct_retry_manager_drive
#define mesh_guest_service_manager_snapshot gct_retry_manager_snapshot
#define mesh_guest_service_manager_destroy gct_retry_manager_destroy
#define platform_time_monotonic_us gct_retry_clock
#define platform_time_monotonic_ms(...) gct_protected_ready_clock(__VA_ARGS__)
#define mesh_guest_chan_set_enabled(...) gct_protected_ready_enable(__VA_ARGS__)
#define guest_service_runner_destroy gct_retry_runner_destroy
#define guest_service_runner_create gct_enrollment_runner_create
#define SGM_PUBLIC_SOURCE_TWIN gct_public_consumer_digest
#define platform_positioned_file_read gct_public_read
#include "../../../engine/composition/src/mesh_guest_service.c"
#undef platform_positioned_file_read
#undef SGM_PUBLIC_SOURCE_TWIN
#undef guest_service_runner_create
#undef guest_service_runner_destroy
#undef platform_time_monotonic_us
#undef platform_time_monotonic_ms
#undef mesh_guest_chan_set_enabled
#undef mesh_guest_service_create
#undef mesh_guest_service_attach
#undef mesh_guest_service_enable
#undef mesh_guest_service_pump
#undef mesh_guest_service_slice
#undef mesh_guest_service_stop
#undef mesh_guest_service_destroy
#undef mesh_guest_service_snapshot
#undef mesh_guest_service_test_machine
#undef mesh_guest_service_manager_create
#undef mesh_guest_service_manager_event
#undef mesh_guest_service_manager_instance
#undef mesh_guest_service_manager_storage_synced
#undef mesh_guest_service_manager_unlock_public
#undef mesh_guest_service_manager_protected_tuple
#undef mesh_guest_service_manager_unlock_protected
#undef mesh_guest_service_manager_identity_finish
#undef mesh_guest_service_manager_ready
#undef mesh_guest_service_manager_drive
#undef mesh_guest_service_manager_snapshot
#undef mesh_guest_service_manager_destroy
extern int repo_path(char *out, size_t outsz, const char *rel);

#define GCT_NAME MESH_GUEST_CHAN_SERVICE_NAME
#define GCT_WINDOW 65536u
#define GCT_NOW INT64_C(1000000)
#define GCT_PAIRED_AT INT64_C(1)
#define GCT_EXPIRES INT64_C(4102444800)
#define GCT_ROWS_MAX 160u
#define GCT_FRAME_MAX 70000u

/* ── The fake device ─────────────────────────────────────────────────── */

#define FD_REC_MAX 140000u
#define FD_SCRIPT_MAX 8u

struct fake_dev {
    size_t accept_calls;
    size_t write_calls;
    size_t resume_calls;
    size_t end_calls;
    struct guest_chan_port script[FD_SCRIPT_MAX];
    bool script_ok[FD_SCRIPT_MAX];
    size_t script_len;
    size_t script_pos;
    size_t take_limit; /* bytes one write takes; SIZE_MAX takes all */
    bool take_over;    /* return n + 1 */
    bool revoke_in_write; /* commit a real pairing revocation inside write */
    uint8_t rec[FD_REC_MAX];
    size_t rec_len;
    size_t last_write_n;
    enum guest_chan_end last_end;
    struct guest_chan_port last_end_port;
    /* What each port index was given, in order (the first 64 bytes). */
    uint8_t port_rec[GUEST_CHAN_PORTS_MAX][64];
    size_t port_rec_len[GUEST_CHAN_PORTS_MAX];
};

static struct fake_dev fd;

static bool gct_revoke_last(void);

static bool fd_accept(void *dev, struct guest_chan_port *out)
{
    struct fake_dev *d = dev;
    d->accept_calls++;
    if (d->script_pos >= d->script_len)
        return false;
    *out = d->script[d->script_pos];
    return d->script_ok[d->script_pos++];
}

static size_t fd_write(void *dev, struct guest_chan_port port,
                       const uint8_t *bytes, size_t n)
{
    struct fake_dev *d = dev;
    d->write_calls++;
    d->last_write_n = n;
    if (d->take_over)
        return n + 1u;
    if (d->revoke_in_write)
        (void)gct_revoke_last();
    size_t k = n < d->take_limit ? n : d->take_limit;
    if (k > FD_REC_MAX - d->rec_len)
        k = FD_REC_MAX - d->rec_len;
    memcpy(d->rec + d->rec_len, bytes, k);
    d->rec_len += k;
    if (port.index < GUEST_CHAN_PORTS_MAX) {
        size_t room = sizeof(d->port_rec[0]) - d->port_rec_len[port.index];
        size_t keep = k < room ? k : room;
        memcpy(d->port_rec[port.index] + d->port_rec_len[port.index], bytes,
               keep);
        d->port_rec_len[port.index] += keep;
    }
    return k;
}

static void fd_resume(void *dev, struct guest_chan_port port)
{
    (void)port;
    ((struct fake_dev *)dev)->resume_calls++;
}

static void fd_end(void *dev, struct guest_chan_port port,
                   enum guest_chan_end why)
{
    struct fake_dev *d = dev;
    d->end_calls++;
    d->last_end = why;
    d->last_end_port = port;
}

static const struct guest_chan_device_ops fd_ops = {
    .accept = fd_accept,
    .write = fd_write,
    .resume = fd_resume,
    .end = fd_end,
};

static const struct guest_chan_host_ops *g_host;
static void *g_hostctx;

static const struct guest_chan_port TOK0 = {0, 1};
static const struct guest_chan_port TOK1 = {1, 1};
static const struct guest_chan_port TOK2 = {2, 1};
static const struct guest_chan_port TOK3 = {3, 1};

static void fd_reset(void)
{
    memset(&fd, 0, sizeof(fd));
    fd.take_limit = SIZE_MAX;
}

static void fd_script(struct guest_chan_port tok, bool ok)
{
    fd.script[fd.script_len] = tok;
    fd.script_ok[fd.script_len++] = ok;
}

/* ── The loopback and the pairing rows ───────────────────────────────── */

static struct mesh_term_fixture *g_f;
static struct p2p_node *g_a;
static struct p2p_node *g_b;
static struct send_segment *g_aq;
static struct send_segment *g_bq;
static struct msg_processor *g_mp;
static struct net_manager *g_nm;
static uint8_t g_frame[GCT_FRAME_MAX];
static uint8_t g_payload[GCT_FRAME_MAX];
static char g_rows[GCT_ROWS_MAX][MESH_PAIRING_ID_HEX + 1];
static size_t g_rows_n;
static uint8_t g_variant;

static void gct_drain(void)
{
    mesh_loop_discard(g_a, g_aq, g_f->res_term);
    mesh_loop_discard(g_b, g_bq, g_f->term_peer.ini);
}

/* Files one live row for `noise` granting `caps`. Each call varies the
 * bound identities so the derived id is new; the peer key stays. */
static bool gct_pair_at(const uint8_t noise[32], uint64_t caps,
                        int64_t paired_at)
{
    if (g_rows_n >= GCT_ROWS_MAX)
        return false;
    struct db_mesh_pairing row;
    memset(&row, 0, sizeof(row));
    const struct mesh_term_peer *peer = &g_f->term_peer;
    memcpy(row.network_genesis, peer->delegation.network_genesis, 32);
    memcpy(row.peer_master_pubkey, peer->delegation.doc.master_pubkey, 32);
    memcpy(row.peer_noise_pubkey, noise, 32);
    g_variant++;
    row.network_genesis[31] ^= g_variant;
    row.peer_master_pubkey[31] ^= g_variant;
    row.capability_mask = caps;
    row.delegation_sequence = peer->delegation.doc.seq;
    row.paired_at = paired_at;
    row.expires_at = GCT_EXPIRES;
    if (!mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                row.peer_noise_pubkey, row.pairing_id))
        return false;
    if (!db_mesh_pairing_insert(&g_f->ndb, &row))
        return false;
    memcpy(g_rows[g_rows_n++], row.pairing_id, sizeof(row.pairing_id));
    return true;
}

static bool gct_pair_for(const uint8_t noise[32], uint64_t caps)
{
    return gct_pair_at(noise, caps, GCT_PAIRED_AT);
}

static bool gct_pair(uint64_t caps)
{
    return gct_pair_for(g_f->term_peer.delegation.noise_static_pubkey, caps);
}

static bool gct_revoke_last(void)
{
    return g_rows_n > 0 &&
           db_mesh_pairing_revoke(&g_f->ndb, g_rows[g_rows_n - 1], 100);
}

static void gct_revoke_all(void)
{
    for (size_t i = 0; i < g_rows_n; i++)
        (void)db_mesh_pairing_revoke(&g_f->ndb, g_rows[i], 100);
}

/* A fresh case: no live rows, empty stream table, a new fake device and an
 * attached adapter. `caps` 0 files no row. */
static bool gct_begin(const struct mesh_guest_chan_limits *lim, uint64_t caps)
{
    gct_revoke_all();
    mesh_stream_test_reset();
    gct_drain();
    fd_reset();
    if (caps && !gct_pair(caps))
        return false;
    return mesh_guest_chan_attach(&fd_ops, &fd, lim, &g_host, &g_hostctx);
}

static void gct_end(void)
{
    mesh_guest_chan_detach();
    mesh_stream_test_reset();
    gct_drain();
}

/* ── Wire helpers ────────────────────────────────────────────────────── */

struct gct_wire {
    size_t opens, datas, windows, closes, others;
    uint32_t window_total;
    uint8_t close_reason;
};

/* Everything one node put on the wire, in order, opened on the peer's
 * transport. */
static struct gct_wire gct_take_node(struct p2p_node *from,
                                     struct send_segment *queue,
                                     struct noise_transport *to)
{
    struct gct_wire w;
    memset(&w, 0, sizeof(w));
    uint8_t buf[MESH_LOOP_WIRE_MAX];
    bool more = true;
    while (more) {
        size_t n = mesh_loop_take(from, queue, to, buf, sizeof(buf), &more);
        uint8_t kind = 0;
        if (!more)
            break;
        if (!mesh_stream_test_read_header(buf, n, &kind, NULL)) {
            w.others++;
            continue;
        }
        size_t head = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
        if (kind == MESH_STREAM_KIND_OPEN) {
            w.opens++;
        } else if (kind == MESH_STREAM_KIND_DATA) {
            w.datas++;
        } else if (kind == MESH_STREAM_KIND_WINDOW && n >= head + 4u) {
            w.windows++;
            w.window_total += zcl_read_u32_le(buf + head);
        } else if (kind == MESH_STREAM_KIND_CLOSE && n > head) {
            w.closes++;
            w.close_reason = buf[head];
        } else {
            w.others++;
        }
    }
    return w;
}

/* Node b (the answering side). */
static struct gct_wire gct_take_b(void)
{
    return gct_take_node(g_b, g_bq, g_f->term_peer.ini);
}

/* Node a (the dialling side). */
static struct gct_wire gct_take_a(void)
{
    return gct_take_node(g_a, g_aq, g_f->res_term);
}

static size_t gct_wire_total(const struct gct_wire *w)
{
    return w->opens + w->datas + w->windows + w->closes + w->others;
}

static bool gct_frame_in(size_t len)
{
    return len != 0 && mesh_stream_frame(g_mp, g_b, g_frame, len, NULL);
}

/* An OPEN as the dialling peer composes it, delivered to the answering
 * side. Even ids are the dialler's. */
static bool gct_open_hand(uint64_t id)
{
    return gct_frame_in(mesh_stream_test_open_frame(
        id, GCT_WINDOW, GCT_NAME, NULL, 0, g_frame, sizeof(g_frame)));
}

/* `n` bytes of the repeating pattern starting at `offset`. */
static void gct_pattern(uint8_t *out, size_t offset, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((offset + i) % 251u);
}

static bool gct_data_hand(uint64_t id, size_t offset, size_t n)
{
    gct_pattern(g_payload, offset, n);
    return gct_frame_in(mesh_stream_test_data_frame(id, g_payload, n, g_frame,
                                                    sizeof(g_frame)));
}

static bool gct_close_hand(uint64_t id, uint8_t reason)
{
    return gct_frame_in(mesh_stream_test_close_frame(id, reason, NULL, 0,
                                                     g_frame, sizeof(g_frame)));
}

/* A session with one inbound port: pairing row, enabled adapter, the open
 * accepted as token 0. */
static bool gct_up(const struct mesh_guest_chan_limits *lim, uint64_t caps)
{
    if (!gct_begin(lim, caps))
        return false;
    fd_script(TOK0, true);
    return mesh_guest_chan_set_enabled(true) && gct_open_hand(0) &&
           fd.accept_calls == 1;
}

static struct mesh_guest_chan_stats gct_stats(void)
{
    struct mesh_guest_chan_stats s;
    mesh_guest_chan_stats(&s);
    return s;
}

/* ── Visitors ────────────────────────────────────────────────────────── */

struct gct_visit {
    uint64_t id;
    bool local_initiator;
    bool found;
    bool ok;
    const uint8_t *bytes;
    size_t len;
    uint32_t send_credit;
    uint32_t recv_credit;
    size_t live;
};

static bool gct_visit_fn(struct mesh_stream *st, void *ctx)
{
    struct gct_visit *v = ctx;
    v->live++;
    if (st->id != v->id || st->local_initiator != v->local_initiator)
        return true;
    v->found = true;
    v->send_credit = st->send_credit;
    v->recv_credit = st->recv_credit;
    if (v->bytes)
        v->ok = mesh_stream_send(st, v->bytes, v->len);
    return false;
}

static struct gct_visit gct_look(uint64_t id, bool initiator,
                                 const uint8_t *bytes, size_t len)
{
    struct gct_visit v;
    memset(&v, 0, sizeof(v));
    v.id = id;
    v.local_initiator = initiator;
    v.bytes = bytes;
    v.len = len;
    mesh_stream_visit(GCT_NAME, gct_visit_fn, &v);
    return v;
}

static size_t gct_streams(void)
{
    return gct_look(UINT64_MAX, false, NULL, 0).live;
}

/* ── The forbidden-call scan ─────────────────────────────────────────── */

static const char *const k_forbidden[] = {
    "socket", "connect", "bind",  "listen",   "accept", "fork",
    "vfork",  "system",  "popen", "posix_spawn", "spawn", "fopen",
    "open",   "openat",  "creat",
};

static bool gct_forbidden_name(const char *ident)
{
    for (size_t i = 0; i < sizeof(k_forbidden) / sizeof(k_forbidden[0]); i++)
        if (strcmp(ident, k_forbidden[i]) == 0)
            return true;
    return strncmp(ident, "exec", 4) == 0;
}

/* Blank out comments, string literals and character literals, keeping
 * newlines, so the identifier scan sees code only. */
static size_t gct_blank_block(char *s, size_t n, size_t i)
{
    s[i++] = ' ';
    s[i++] = ' ';
    while (i < n && !(s[i] == '*' && i + 1 < n && s[i + 1] == '/')) {
        if (s[i] != '\n')
            s[i] = ' ';
        i++;
    }
    if (i < n) {
        s[i++] = ' ';
        s[i++] = ' ';
    }
    return i;
}

static size_t gct_blank_line(char *s, size_t n, size_t i)
{
    while (i < n && s[i] != '\n')
        s[i++] = ' ';
    return i;
}

static size_t gct_blank_literal(char *s, size_t n, size_t i)
{
    char q = s[i];
    s[i++] = ' ';
    while (i < n && s[i] != q) {
        if (s[i] == '\\' && i + 1 < n)
            s[i++] = ' ';
        if (s[i] != '\n')
            s[i] = ' ';
        i++;
    }
    if (i < n)
        s[i++] = ' ';
    return i;
}

static void gct_strip(char *s)
{
    size_t n = strlen(s);
    size_t i = 0;
    while (i < n) {
        bool slash = s[i] == '/' && i + 1 < n;
        if (slash && s[i + 1] == '*')
            i = gct_blank_block(s, n, i);
        else if (slash && s[i + 1] == '/')
            i = gct_blank_line(s, n, i);
        else if (s[i] == '"' || s[i] == '\'')
            i = gct_blank_literal(s, n, i);
        else
            i++;
    }
}

static bool gct_member_access(const char *s, size_t start)
{
    while (start > 0 && isspace((unsigned char)s[start - 1]))
        start--;
    return (start >= 1 && s[start - 1] == '.') ||
           (start >= 2 && s[start - 1] == '>' && s[start - 2] == '-');
}

/* The first forbidden call in `src` (a mutable copy), or NULL. A call is a
 * bare identifier followed by `(`; member access (`->accept(`) is allowed. */
static const char *gct_find_forbidden(char *src, char *ident_out,
                                      size_t ident_cap)
{
    gct_strip(src);
    size_t n = strlen(src);
    for (size_t i = 0; i < n;) {
        if (!isalpha((unsigned char)src[i]) && src[i] != '_') {
            i++;
            continue;
        }
        size_t start = i;
        while (i < n && (isalnum((unsigned char)src[i]) || src[i] == '_'))
            i++;
        size_t len = i - start;
        size_t j = i;
        while (j < n && isspace((unsigned char)src[j]))
            j++;
        if (len >= ident_cap || j >= n || src[j] != '(')
            continue;
        memcpy(ident_out, src + start, len);
        ident_out[len] = '\0';
        if (gct_forbidden_name(ident_out) && !gct_member_access(src, start))
            return ident_out;
    }
    return NULL;
}

static bool gct_scan_hits(const char *text)
{
    char *copy = zcl_malloc(strlen(text) + 1u, "gct_scan_copy");
    if (!copy)
        return true;
    memcpy(copy, text, strlen(text) + 1u);
    char ident[64];
    bool hit = gct_find_forbidden(copy, ident, sizeof(ident)) != NULL;
    free(copy);
    return hit;
}

static char *gct_read_source(void)
{
    char path[1024];
    if (repo_path(path, sizeof(path),
                  "engine/composition/src/mesh_guest_chan.c") != 0)
        return NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    char *buf = NULL;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long size = ftell(fp);
        if (size > 0 && fseek(fp, 0, SEEK_SET) == 0) {
            buf = zcl_malloc((size_t)size + 1u, "gct_source");
            if (buf && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
                free(buf);
                buf = NULL;
            } else if (buf) {
                buf[size] = '\0';
            }
        }
    }
    fclose(fp);
    return buf;
}

/* ── Outbound, grant failure and refusal mapping ─────────────────────── */

/* The loopback is one process, so the far end of an outbound stream is this
 * same adapter: port 0 dials the answering peer, and the OPEN arrives back
 * as an inbound port (token 1) for the dialling peer's pairing row. */
static int gct_case_outbound_happy(void)
{
    int failures = 0;
    TEST("guest chan: outbound to a connected, granted peer: the OPEN goes "
         "out, bytes flow both ways, a clean close ends both ports NORMAL") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_pair_for(g_f->resp_noise_pub, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK1, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(g_host->opened(g_hostctx, TOK0, g_f->resp_noise_pub));
        ASSERT_EQ(fd.end_calls, (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(mesh_loop_pump(g_a, g_aq, g_f->res_term, g_mp, g_b),
                  (size_t)1);
        ASSERT_EQ(fd.accept_calls, (size_t)1);
        ASSERT_EQ(gct_stats().opened, (uint64_t)2);
        ASSERT_EQ(gct_streams(), (size_t)2);
        ASSERT_EQ(fd.end_calls, (size_t)0);

        uint8_t up[16];
        gct_pattern(up, 0, sizeof(up));
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, up, sizeof(up)),
                  sizeof(up));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(mesh_loop_pump(g_a, g_aq, g_f->res_term, g_mp, g_b),
                  (size_t)1);
        ASSERT_EQ(fd.port_rec_len[1], sizeof(up));
        ASSERT(memcmp(fd.port_rec[1], up, sizeof(up)) == 0);

        uint8_t down[12];
        gct_pattern(down, 100, sizeof(down));
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK1, down, sizeof(down)),
                  sizeof(down));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(mesh_loop_pump(g_b, g_bq, g_f->term_peer.ini, g_mp, g_a),
                  (size_t)1);
        ASSERT_EQ(fd.port_rec_len[0], sizeof(down));
        ASSERT(memcmp(fd.port_rec[0], down, sizeof(down)) == 0);

        g_host->closed(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_NORMAL);
        ASSERT_EQ(fd.last_end_port.index, (uint32_t)0);
        ASSERT_EQ(mesh_loop_pump(g_a, g_aq, g_f->res_term, g_mp, g_b),
                  (size_t)1);
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_NORMAL);
        ASSERT_EQ(fd.last_end_port.index, (uint32_t)1);
        ASSERT_EQ(gct_streams(), (size_t)0);
        ASSERT_EQ(gct_stats().ended_revoked, (uint64_t)0);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)0);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)0);
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

/* The same fixture as the happy path with ONE change: the connected peer's
 * row has no guest-channel bit. */
static int gct_case_outbound_unauthorised(void)
{
    int failures = 0;
    TEST("guest chan: outbound to a connected peer whose row lacks the bit "
         "is refused UNAVAILABLE in the pump, nothing reaches the wire, no "
         "slot stays held, and either order of from_guest agrees") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_pair_for(g_f->resp_noise_pub, MESH_PAIRING_CAP_STATUS_READ));
        ASSERT(mesh_guest_chan_set_enabled(true));
        uint8_t out[8];
        gct_pattern(out, 0, sizeof(out));

        /* Order A: the guest sends before the open is decided. */
        ASSERT(g_host->opened(g_hostctx, TOK0, g_f->resp_noise_pub));
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, out, sizeof(out)),
                  sizeof(out));
        ASSERT_EQ(fd.end_calls, (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_UNAVAILABLE);
        struct gct_wire wa = gct_take_a();
        struct gct_wire wb = gct_take_b();
        ASSERT_EQ(gct_wire_total(&wa), (size_t)0);
        ASSERT_EQ(gct_wire_total(&wb), (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)0);
        ASSERT_EQ(mesh_stream_test_live_count(GCT_NAME), (size_t)0);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)0);
        ASSERT_EQ(gct_stats().ended_revoked, (uint64_t)0);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)0);

        /* Order B: the pump decides first, then the guest sends. The slot
         * is free again (the same index opens with the next generation). */
        struct guest_chan_port next = {0, 2};
        ASSERT(g_host->opened(g_hostctx, next, g_f->resp_noise_pub));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_UNAVAILABLE);
        ASSERT_EQ(g_host->from_guest(g_hostctx, next, out, sizeof(out)),
                  (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(gct_stats().ended_revoked, (uint64_t)0);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)0);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)1);
        wa = gct_take_a();
        ASSERT_EQ(gct_wire_total(&wa), (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

static int gct_case_grant_failure(void)
{
    int failures = 0;
    TEST("guest chan: a failed grant keeps the credit owed and the next "
         "pass grants exactly it") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 100));
        g_host->drained(g_hostctx, TOK0, 40);
        /* No session to the peer: the grant cannot go out. */
        g_nm->num_nodes = 0;
        mesh_guest_chan_pump(GCT_NOW);
        g_nm->num_nodes = 2;
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        ASSERT_EQ(gct_look(0, false, NULL, 0).recv_credit,
                  GCT_WINDOW - (uint32_t)100);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)1);
        ASSERT_EQ(w.window_total, (uint32_t)40);
        ASSERT_EQ(gct_look(0, false, NULL, 0).recv_credit,
                  GCT_WINDOW - (uint32_t)100 + 40u);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    g_nm->num_nodes = 2;
    return failures;
}

/* One port with a held inbound suffix (a short write), ten bytes owed back,
 * twenty outbound bytes buffered and the device writable again, so the next
 * pump pass re-offers the suffix through the device write callback. */
static bool gct_stage_callback_pass(bool revoke)
{
    if (!gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN))
        return false;
    fd.take_limit = 10;
    if (!gct_data_hand(0, 0, 100))
        return false;
    fd.take_limit = SIZE_MAX;
    uint8_t out[20];
    gct_pattern(out, 0, sizeof(out));
    if (g_host->from_guest(g_hostctx, TOK0, out, sizeof(out)) != sizeof(out))
        return false;
    g_host->drained(g_hostctx, TOK0, 10);
    (void)gct_take_b();
    g_host->writable(g_hostctx, TOK0);
    fd.revoke_in_write = revoke;
    return fd.write_calls == 1 && fd.rec_len == 10;
}

static int gct_case_revoke_in_callback(void)
{
    int failures = 0;
    TEST("guest chan: a revocation committed inside the device write "
         "callback stops the same pump pass: no WINDOW, no DATA, one REVOKED "
         "end, stream released") {
        ASSERT(gct_stage_callback_pass(true));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.write_calls, (size_t)2);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        ASSERT_EQ(w.datas, (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_REVOKED);
        ASSERT_EQ(gct_stats().ended_revoked, (uint64_t)1);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)0);
        ASSERT_EQ(gct_streams(), (size_t)0);
        ASSERT_EQ(mesh_stream_test_live_count(GCT_NAME), (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        w = gct_take_b();
        ASSERT_EQ(w.windows + w.datas, (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: the same pass without a revocation still moves the "
         "held bytes, the owed credit and the outbound buffer") {
        ASSERT(gct_stage_callback_pass(false));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.write_calls, (size_t)2);
        ASSERT_EQ(fd.rec_len, (size_t)100);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)1);
        ASSERT_EQ(w.window_total, (uint32_t)10);
        ASSERT_EQ(w.datas, (size_t)1);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)20);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)1);
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

struct gct_map {
    uint8_t reason;
    enum guest_chan_end want;
};

static const struct gct_map k_close_map[] = {
    {MESH_STREAM_OK, GUEST_CHAN_END_NORMAL},
    {MESH_STREAM_REFUSED_LINK_NOT_NOISE, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_PEER_UNPAIRED, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_SERVICE_UNKNOWN, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_CAP, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_CREDIT_EXCEEDED, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_MALFORMED, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_ID_PARITY, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_ID_IN_USE, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_RATE, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_UNAVAILABLE, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_REFUSED_PEER_NOT_CONNECTED, GUEST_CHAN_END_UNAVAILABLE},
    {MESH_STREAM_ENDED_IDLE, GUEST_CHAN_END_IDLE},
    {MESH_STREAM_ENDED_SESSION_LOST, GUEST_CHAN_END_SESSION_LOST},
    {MESH_STREAM_ENDED_SHUTDOWN, GUEST_CHAN_END_SHUTDOWN},
    {MESH_STREAM_CLOSED_BY_SERVICE, GUEST_CHAN_END_NORMAL},
};

static int gct_case_close_mapping(void)
{
    int failures = 0;
    TEST("guest chan: every stream-layer close reason reaches the device as "
         "its own end reason; refusals are UNAVAILABLE, a clean close is "
         "NORMAL") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(mesh_guest_chan_set_enabled(true));
        size_t count = sizeof(k_close_map) / sizeof(k_close_map[0]);
        for (size_t i = 0; i < count; i++) {
            mesh_stream_test_reset();
            struct guest_chan_port tok = {0, (uint32_t)i + 1u};
            fd.script_len = 0;
            fd.script_pos = 0;
            fd_script(tok, true);
            ASSERT(gct_open_hand(0));
            ASSERT(gct_close_hand(0, k_close_map[i].reason));
            if (fd.last_end != k_close_map[i].want)
                printf("close reason %u ended %d, wanted %d\n",
                       (unsigned)k_close_map[i].reason, (int)fd.last_end,
                       (int)k_close_map[i].want);
            ASSERT_EQ(fd.end_calls, i + 1u);
            ASSERT_EQ(fd.last_end, k_close_map[i].want);
            ASSERT_EQ(fd.last_end_port.generation, (uint32_t)i + 1u);
            ASSERT_EQ(gct_streams(), (size_t)0);
        }
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

/* The end reason rule: the first end to arrive wins and the device hears
 * exactly one end() per port, whichever path the second one takes. */
static int gct_case_end_reason_order(void)
{
    int failures = 0;
    TEST("guest chan: first end wins, local closed() then a remote CLOSE "
         "frame: exactly one end, NORMAL") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        g_host->closed(g_hostctx, TOK0);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        ASSERT(gct_close_hand(0, MESH_STREAM_ENDED_SESSION_LOST));
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_NORMAL);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }
    TEST("guest chan: first end wins, a remote CLOSE frame then local "
         "closed(): exactly one end, SESSION_LOST, the late closed() is a "
         "stale token") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_close_hand(0, MESH_STREAM_ENDED_SESSION_LOST));
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_SESSION_LOST);
        g_host->closed(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_SESSION_LOST);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)1);
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

/* KNOWN STAGE-1 CLIFF: the pairing list is ordered by paired_at and holds
 * 64 rows, revoked and expired ones included. With 64 stale rows ahead of
 * it, a valid newer row is never seen and its peer is denied. Fail-closed;
 * behaviour deliberately unchanged. */
static int gct_case_pairing_cliff(void)
{
    int failures = 0;
    TEST("guest chan: 64 stale pairing rows ahead of a valid 65th deny that "
         "peer (known fail-closed limit)") {
        ASSERT(gct_begin(NULL, 0));
        uint8_t other[32];
        memset(other, 0x31, sizeof(other));
        while (g_rows_n < 64)
            ASSERT(gct_pair_for(other, MESH_PAIRING_CAP_GUEST_CHAN));
        gct_revoke_all();
        /* The 65th row is valid, granted, and newer than every stale one. */
        ASSERT(gct_pair_at(g_f->resp_noise_pub, MESH_PAIRING_CAP_GUEST_CHAN,
                           GCT_PAIRED_AT + 1));
        ASSERT(g_rows_n >= 65);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(g_host->opened(g_hostctx, TOK0, g_f->resp_noise_pub));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_UNAVAILABLE);
        struct gct_wire wa = gct_take_a();
        ASSERT_EQ(gct_wire_total(&wa), (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    return failures;
}

/* ── The group ───────────────────────────────────────────────────────── */

/* The fixture owns both authenticated Noise transports. No direct plaintext
 * delivery bypass is used for the accepted factory case. */
static bool gct_s6_noise_frame_in(size_t length)
{
    if (length == 0 || !mesh_term_frame_roundtrip(g_f->term_peer.ini,
            g_f->res_term, g_frame, length, g_payload, sizeof(g_payload)))
        return false;
    return mesh_stream_frame(g_mp, g_b, g_payload, length, NULL);
}

/* Read actual outgoing Noise records in order, preserving binary DATA bytes.
 * Other production frames remain observable rather than becoming echo data. */
static bool gct_s6_take_echo(uint8_t *out, size_t capacity, size_t *used,
    size_t *windows, size_t *closes, uint64_t expected_stream)
{
    uint8_t frame[MESH_LOOP_WIRE_MAX];
    bool more = true;
    while (more) {
        size_t length = mesh_loop_take(g_b, g_bq, g_f->term_peer.ini,
            frame, sizeof(frame), &more);
        if (!more) break;
        uint8_t kind = 0; uint64_t stream = 0;
        if (!mesh_stream_test_read_header(frame, length, &kind, &stream) ||
            stream != expected_stream) return false;
        size_t head = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
        if (kind == MESH_STREAM_KIND_DATA) {
            if (length < head + 2u) return false;
            size_t payload_length = zcl_read_u16_le(frame + head);
            head += 2u;
            if (payload_length != length - head || *used > capacity ||
                payload_length > capacity - *used) return false;
            memcpy(out + *used, frame + head, payload_length);
            *used += payload_length;
        } else if (kind == MESH_STREAM_KIND_WINDOW) {
            if (length != head + 4u) return false;
            *windows += zcl_read_u32_le(frame + head);
        } else if (kind == MESH_STREAM_KIND_CLOSE) {
            (*closes)++;
        }
    }
    return true;
}

/* Admission callback recorder, not an S7 binding implementation. Identity is
 * supplied by the production adapter from the real Noise session snapshot. */
static struct {
    size_t calls, payload_length, reply_capacity;
    uint8_t peer[32], payload[16];
    bool overreply, revoke;
} gct_peer_v2;
static const uint8_t gct_peer_open_bytes[] = {0x00, 0xff, 0x5a, 0x00, 0x91};
static const uint8_t gct_peer_reply_bytes[] = {0x06, 0x00, 0xa9};

static bool gct_peer_accept_v2(void *device, const uint8_t peer[32],
    const uint8_t *payload, size_t length, uint8_t *reply, size_t capacity,
    size_t *reply_length, struct guest_chan_port *token)
{
    (void)device;
    gct_peer_v2.calls++;
    memcpy(gct_peer_v2.peer, peer, sizeof(gct_peer_v2.peer));
    gct_peer_v2.payload_length = length;
    gct_peer_v2.reply_capacity = capacity;
    if (length <= sizeof(gct_peer_v2.payload) && length)
        memcpy(gct_peer_v2.payload, payload, length);
    *reply_length = 0;
    if (length != sizeof(gct_peer_open_bytes) ||
        memcmp(payload, gct_peer_open_bytes, length) != 0 ||
        capacity < sizeof(gct_peer_reply_bytes)) return false;
    if (gct_peer_v2.revoke && !gct_revoke_last()) return false;
    *token = TOK0;
    if (gct_peer_v2.overreply) {
        *reply_length = capacity + 1u;
        return true;
    }
    memcpy(reply, gct_peer_reply_bytes, sizeof(gct_peer_reply_bytes));
    *reply_length = sizeof(gct_peer_reply_bytes);
    return true;
}

static int gct_case_peer_attach_v2(void)
{
    int failures = 0;
    struct noise_transport_snapshot session;
    uint8_t reply[16];
    size_t used = 0, windows = 0, closes = 0;
    TEST("guest chan peer v2: actual Noise identity and opaque OPEN reach only the required handler") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(g_rows_n < 64u);
        mesh_guest_chan_detach();
        ASSERT(!mesh_guest_chan_attach_peer_v2(&fd_ops, NULL, &fd, NULL,
            &g_host, &g_hostctx));
        memset(&gct_peer_v2, 0, sizeof(gct_peer_v2));
        ASSERT(mesh_guest_chan_attach_peer_v2(&fd_ops, gct_peer_accept_v2,
            &fd, NULL, &g_host, &g_hostctx));
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(noise_transport_snapshot(g_b->transport, &session));
        ASSERT(session.established);
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            gct_peer_open_bytes, sizeof(gct_peer_open_bytes), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        ASSERT_EQ(gct_peer_v2.calls, (size_t)1); ASSERT_EQ(fd.accept_calls, (size_t)0);
        ASSERT(!memcmp(gct_peer_v2.peer, session.remote_static, 32));
        ASSERT_EQ(gct_peer_v2.payload_length, sizeof(gct_peer_open_bytes));
        ASSERT(!memcmp(gct_peer_v2.payload, gct_peer_open_bytes, sizeof(gct_peer_open_bytes)));
        ASSERT_EQ(gct_streams(), (size_t)1);
        ASSERT(gct_s6_take_echo(reply, sizeof(reply), &used, &windows, &closes, 2));
        ASSERT_EQ(used, sizeof(gct_peer_reply_bytes));
        ASSERT(!memcmp(reply, gct_peer_reply_bytes, used)); ASSERT_EQ(closes, (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    gct_end();
    return failures;
}

static int gct_case_peer_attach_v2_refusal(void)
{
    int failures = 0;
    uint8_t byte = 0x5a;
    TEST("guest chan peer v2: overreported reply releases token once and rejects its stale callbacks") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(g_rows_n < 64u);
        mesh_guest_chan_detach();
        memset(&gct_peer_v2, 0, sizeof(gct_peer_v2)); gct_peer_v2.overreply = true;
        ASSERT(mesh_guest_chan_attach_peer_v2(&fd_ops, gct_peer_accept_v2,
            &fd, NULL, &g_host, &g_hostctx));
        ASSERT(mesh_guest_chan_set_enabled(true));
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            gct_peer_open_bytes, sizeof(gct_peer_open_bytes), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        ASSERT_EQ(gct_peer_v2.calls, (size_t)1); ASSERT_EQ(fd.accept_calls, (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)1); ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(gct_streams(), (size_t)0);
        uint64_t stale = gct_stats().stale_token_dropped;
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, &byte, 1), (size_t)0);
        ASSERT_EQ(gct_stats().stale_token_dropped, stale + 1u);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1); ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    gct_end();
    return failures;
}

static int gct_case_peer_attach_v2_opaque_refusal(void)
{
    int failures = 0;
    const uint8_t unrecognized[] = {0x5a};
    TEST("guest chan peer v2: arbitrary OPEN cannot fall back to legacy accept") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(g_rows_n < 64u);
        mesh_guest_chan_detach();
        memset(&gct_peer_v2, 0, sizeof(gct_peer_v2));
        ASSERT(mesh_guest_chan_attach_peer_v2(&fd_ops, gct_peer_accept_v2,
            &fd, NULL, &g_host, &g_hostctx));
        ASSERT(mesh_guest_chan_set_enabled(true));
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            unrecognized, sizeof(unrecognized), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        ASSERT_EQ(gct_peer_v2.calls, (size_t)1); ASSERT_EQ(fd.accept_calls, (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)0); ASSERT_EQ(gct_streams(), (size_t)0);
        struct gct_wire wire = gct_take_b();
        ASSERT_EQ(wire.datas, (size_t)0); ASSERT_EQ(wire.closes, (size_t)1);
        ASSERT_EQ(wire.close_reason, MESH_STREAM_REFUSED_UNAVAILABLE);
        gct_end();
        PASS();
    }
_test_next:
    gct_end();
    return failures;
}

static int gct_case_peer_attach_v2_revoke(void)
{
    int failures = 0;
    TEST("guest chan peer v2: committed pairing revocation inside handler prevents claim and reply") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(g_rows_n < 64u);
        mesh_guest_chan_detach();
        memset(&gct_peer_v2, 0, sizeof(gct_peer_v2)); gct_peer_v2.revoke = true;
        ASSERT(mesh_guest_chan_attach_peer_v2(&fd_ops, gct_peer_accept_v2,
            &fd, NULL, &g_host, &g_hostctx));
        ASSERT(mesh_guest_chan_set_enabled(true));
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            gct_peer_open_bytes, sizeof(gct_peer_open_bytes), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        ASSERT_EQ(gct_peer_v2.calls, (size_t)1); ASSERT_EQ(fd.accept_calls, (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)1); ASSERT_EQ(fd.last_end, GUEST_CHAN_END_REVOKED);
        ASSERT_EQ(gct_stats().opened, UINT64_C(0)); ASSERT_EQ(gct_streams(), (size_t)0);
        struct gct_wire wire = gct_take_b();
        ASSERT_EQ(wire.datas, (size_t)0); ASSERT_EQ(wire.closes, (size_t)1);
        ASSERT_EQ(wire.close_reason, MESH_STREAM_REFUSED_UNAVAILABLE);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1); ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }
_test_next:
    gct_end();
    return failures;
}

/* Requires crypto/sha256.h. Paths are fixed test fixtures, never operator input. */
static bool gct_s6_fixture_file(const char *relative, uint8_t *bytes,
    size_t capacity, size_t *length, const char *expected)
{
    char path[4096], hex[65];
    uint8_t digest[32];
    *length = 0;
    if (repo_path(path, sizeof(path), relative) != 0) {
        fprintf(stderr, "guest test: fixture locator refused\n"); return false;
    }
    FILE *file = fopen(path, "rb");
    if (!file) { fprintf(stderr, "guest test: fixture open failed\n"); return false; }
    size_t n = fread(bytes, 1, capacity, file);
    bool complete = fgetc(file) == EOF && !ferror(file);
    if (fclose(file) != 0 || !complete || !n) {
        fprintf(stderr, "guest test: incomplete fixture read\n"); return false;
    }
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, bytes, n); sha256_finalize(&hash, digest);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); i++) {
        hex[2 * i] = digits[digest[i] >> 4]; hex[2 * i + 1] = digits[digest[i] & 15u];
    }
    hex[64] = '\0';
    if (strcmp(hex, expected)) {
        fprintf(stderr, "guest test: exact fixture hash mismatch\n"); return false;
    }
    *length = n; return true;
}

static bool gct_s6_verified_conport(uint8_t image[65536], size_t *length)
{
    uint8_t manifest[8192]; size_t manifest_length = 0;
    *length = 0;
    return gct_s6_fixture_file("tests/fixtures/rvmachine/MANIFEST", manifest,
        sizeof(manifest), &manifest_length,
        "133e97e4e9293e6c859b63c18e71f3ddd6bbaf90d4e7e69fc0896886cd62d1f7") &&
        gct_s6_fixture_file("tests/fixtures/rvmachine/conport.bin", image, 65536,
        length, "a04cef28c8311513de009646c45be44c866211efb0d0e801f8fc10d56221f06d");
}
/* CLOCK_MONOTONIC measures the actual synchronous call. A sub-microsecond
 * sample rounds up to one microsecond under the explicit runner contract. */
static enum rvmachine_status gct_s6_measured_slice(struct mesh_guest_service *service,
    uint64_t now, bool startup, uint64_t *owed_us,
    struct guest_gov_decision *decision, struct rvmachine_result *result)
{
    struct timespec begin, end;
    struct guest_service_runner_snapshot before;
    if (!mesh_guest_service_snapshot(service, &before)) return RVMACHINE_ERR_STATE;
    if (clock_gettime(CLOCK_MONOTONIC, &begin) != 0) {
        fprintf(stderr, "guest test: monotonic clock unavailable before slice\n");
        return RVMACHINE_ERR_STATE;
    }
    enum rvmachine_status status = mesh_guest_service_slice(service, now,
        *owed_us, startup, decision, result);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0 || end.tv_sec < begin.tv_sec ||
        (end.tv_sec == begin.tv_sec && end.tv_nsec < begin.tv_nsec)) {
        fprintf(stderr, "guest test: monotonic clock unavailable or reversed after slice\n");
        return RVMACHINE_ERR_STATE;
    }
    uint64_t seconds = (uint64_t)(end.tv_sec - begin.tv_sec);
    int64_t nanoseconds = end.tv_nsec - begin.tv_nsec;
    if (nanoseconds < 0) { seconds--; nanoseconds += INT64_C(1000000000); }
    if (seconds > (UINT64_MAX - UINT64_C(1000000)) / UINT64_C(1000000)) {
        fprintf(stderr, "guest test: measured slice duration overflow\n");
        return RVMACHINE_ERR_STATE;
    }
    uint64_t microseconds = seconds * UINT64_C(1000000) +
        (uint64_t)nanoseconds / 1000u + ((uint64_t)nanoseconds % 1000u != 0);
    if (!microseconds) microseconds = 1;
    struct guest_service_runner_snapshot snapshot;
    if (!mesh_guest_service_snapshot(service, &snapshot)) return RVMACHINE_ERR_STATE;
    if (!snapshot.accounting_pending) *owed_us = 0;
    else if (snapshot.slices != before.slices) *owed_us = microseconds;
    return status;
}
static bool gct_s6_test_binding(void *context, const uint8_t peer[32],
    const uint8_t *payload, size_t length, uint8_t *reply, size_t capacity,
    size_t *produced, uint32_t *slot, uint32_t *role)
{
    (void)context;
    struct noise_transport_snapshot session;
    *produced = 0;
    if (!noise_transport_snapshot(g_b->transport, &session) ||
        !session.established || memcmp(peer, session.remote_static, 32) ||
        length != sizeof(gct_peer_open_bytes) ||
        memcmp(payload, gct_peer_open_bytes, length)) return false;
    (void)reply; (void)capacity;
    *slot = 0; *role = 0;
    return true;
}

/* kernel/length must come from the receiver-verified conport fixture tuple.
 * This assembly guest owns device queues; no host queue construction occurs. */
static int gct_s6_credit(struct mesh_guest_service **owned,
    const uint8_t *kernel, size_t length, uint64_t *remaining_us)
{
    int failures = 0;
    struct mesh_guest_service *service = NULL;
    struct mesh_guest_service_config config = {
        .machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true},
        .kernel = kernel, .kernel_length = length,
        .binding = gct_s6_test_binding
    };
    config.limits = guest_limits_default();
    config.limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    struct guest_gov_decision decision;
    struct rvmachine_result result;
    struct guest_service_runner_snapshot snapshot;
    uint8_t input[8192], echo[8192];
    size_t used = 0, windows = 0, closes = 0;
    bool disk_consumed = true; uint64_t owed_us = 0;
    TEST("guest factory TEST binding: real assembly port echo grants cumulative consumption only once") {
        gct_revoke_all(); mesh_stream_test_reset(); gct_drain();
        ASSERT(gct_pair(MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT_EQ(mesh_guest_service_create(&service, &config, &disk_consumed), RVMACHINE_OK);
        *owned = service;
        ASSERT(!disk_consumed);
        ASSERT(mesh_guest_service_attach(service));
        ASSERT(mesh_guest_service_enable(service, true));
        /* One million work is a hard bound, not a scheduler timeout. */
        ASSERT_EQ(gct_s6_measured_slice(service, 1000, true, &owed_us, &decision, &result), RVMACHINE_OK);
        ASSERT_EQ(decision.kind, GUEST_GOV_RUN_SLICE);
        ASSERT(mesh_guest_service_snapshot(service, &snapshot));
        ASSERT(snapshot.returned); ASSERT(!snapshot.in_slice);
        mesh_guest_service_pump(service, GCT_NOW);
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            gct_peer_open_bytes, sizeof(gct_peer_open_bytes), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n)); ASSERT_EQ(gct_streams(), (size_t)1);
        gct_pattern(input, 0, sizeof(input)); zcl_write_u16_le(input, sizeof(input));
        n = mesh_stream_test_data_frame(2, input, sizeof(input), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        for (unsigned i = 0; i < 128 && used < sizeof(input); i++) {
            mesh_guest_service_pump(service, GCT_NOW + i);
            ASSERT_EQ(gct_s6_measured_slice(service, 1010 + 10u * i,
                false, &owed_us, &decision, &result), RVMACHINE_OK);
            mesh_guest_service_pump(service, GCT_NOW + i);
            ASSERT(gct_s6_take_echo(echo, sizeof(echo), &used, &windows, &closes, 2));
        }
        ASSERT_EQ(used, sizeof(input)); ASSERT(!memcmp(echo, input, used));
        ASSERT_EQ(windows, sizeof(input)); ASSERT_EQ(closes, (size_t)0);
        for (unsigned i = 0; i < 3; i++) {
            size_t before = windows;
            mesh_guest_service_pump(service, GCT_NOW + 128 + i);
            ASSERT(gct_s6_take_echo(echo, sizeof(echo), &used, &windows, &closes, 2));
            ASSERT_EQ(windows, before); ASSERT_EQ(used, sizeof(input));
        }
        ASSERT(mesh_guest_service_stop(service));
        ASSERT_EQ(gct_streams(), (size_t)0);
        ASSERT_EQ(mesh_guest_service_slice(service, 3000, owed_us, false,
            &decision, &result), RVMACHINE_ERR_STATE);
        ASSERT(mesh_guest_service_snapshot(service, &snapshot));
        ASSERT(snapshot.stopping); ASSERT(!snapshot.in_slice); ASSERT(!snapshot.returned);
        ASSERT(!snapshot.accounting_pending);
        PASS();
    }
_test_next:;
    struct guest_service_runner_snapshot final;
    *remaining_us = service && mesh_guest_service_snapshot(service, &final) && final.accounting_pending ? owed_us : 0;
    return failures;
}

static int gct_s6_epoch(struct mesh_guest_service **owned,
    const uint8_t *kernel, size_t length, bool reset, uint64_t *remaining_us)
{
    int failures = 0;
    struct mesh_guest_service *service = NULL;
    struct mesh_guest_service_config config = {
        .machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true},
        .kernel = kernel, .kernel_length = length,
        .binding = gct_s6_test_binding
    };
    config.limits = guest_limits_default();
    config.limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    struct guest_gov_decision decision;
    struct rvmachine_result result;
    uint8_t input[8192];
    bool disk_consumed = true; uint64_t owed_us = 0;
    TEST("guest factory TEST binding: actual device epoch discards queued RX/TX and invalidates old stream") {
        gct_revoke_all(); mesh_stream_test_reset(); gct_drain();
        ASSERT(gct_pair(MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT_EQ(mesh_guest_service_create(&service, &config, &disk_consumed), RVMACHINE_OK);
        *owned = service; ASSERT(!disk_consumed);
        ASSERT(mesh_guest_service_attach(service)); ASSERT(mesh_guest_service_enable(service, true));
        ASSERT_EQ(gct_s6_measured_slice(service, 1000, true, &owed_us, &decision, &result), RVMACHINE_OK);
        mesh_guest_service_pump(service, GCT_NOW);
        size_t n = mesh_stream_test_open_frame(2, GCT_WINDOW, GCT_NAME,
            gct_peer_open_bytes, sizeof(gct_peer_open_bytes), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n)); ASSERT_EQ(gct_streams(), (size_t)1);
        gct_pattern(input, 0, sizeof(input)); zcl_write_u16_le(input, sizeof(input));
        n = mesh_stream_test_data_frame(2, input, sizeof(input), g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        mesh_guest_service_pump(service, GCT_NOW);
        struct rvmachine *machine = mesh_guest_service_test_machine(service);
        ASSERT(machine != NULL);
        uint16_t tx_before = machine->con.dev.queues[1].used_idx;
        ASSERT_EQ(gct_s6_measured_slice(service, 1010, false, &owed_us, &decision, &result), RVMACHINE_OK);
        ASSERT(rvmachine_conport_consumed(machine, 0) > 0);
        ASSERT_EQ((uint16_t)(machine->con.dev.queues[1].used_idx - tx_before), 1u);
        ASSERT(machine->con.dev.queues[1].num > 0);
        uint64_t used_address = machine->con.dev.queues[1].device + 4u +
            8u * (tx_before % machine->con.dev.queues[1].num);
        ASSERT(used_address >= RVMACHINE_RAM_BASE && used_address - RVMACHINE_RAM_BASE <= machine->ram_bytes - 8u);
        const uint8_t *entry = machine->mem.bytes + (used_address - RVMACHINE_RAM_BASE);
        ASSERT_EQ(zcl_read_u32_le(entry), 0u);
        ASSERT_EQ(zcl_read_u32_le(entry + 4), 0u);
        uint64_t descriptor = machine->con.dev.queues[1].desc;
        ASSERT(descriptor >= RVMACHINE_RAM_BASE && descriptor - RVMACHINE_RAM_BASE <= machine->ram_bytes - 16u);
        const uint8_t *desc = machine->mem.bytes + (descriptor - RVMACHINE_RAM_BASE);
        ASSERT_EQ(zcl_read_u32_le(desc + 8), 512u);
        uint64_t payload = zcl_read_u64_le(desc);
        ASSERT(payload >= RVMACHINE_RAM_BASE && payload - RVMACHINE_RAM_BASE <= machine->ram_bytes - 512u);
        ASSERT(!memcmp(machine->mem.bytes + (payload - RVMACHINE_RAM_BASE), input, 512));
        /* The returned slice queued guest TX; no service pump has sent it. */
        uint32_t epoch = rvmachine_conport_generation(machine, 0);
        if (reset) {
            uint64_t address = RVMACHINE_VIRTIO_BASE + RVMACHINE_VIRTIO_SLOT_CONSOLE *
                RVMACHINE_VIRTIO_STRIDE + RVVIRTIO_REG_STATUS;
            ASSERT_EQ(machine->mem.io_store(machine->mem.io_ctx, address, 4, 0), 0);
        } else {
            ASSERT(rvmachine_conport_close(machine, 0));
        }
        mesh_guest_service_pump(service, GCT_NOW + 1);
        ASSERT(rvmachine_conport_generation(machine, 0) != epoch);
        ASSERT_EQ(rvmachine_conport_queued(machine, 0), (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)0);
        struct gct_wire wire = gct_take_b();
        ASSERT_EQ(wire.datas, (size_t)0); ASSERT_EQ(wire.closes, (size_t)1);
        n = mesh_stream_test_data_frame(2, input, 32, g_frame, sizeof(g_frame));
        ASSERT(gct_s6_noise_frame_in(n));
        for (unsigned i = 0; i < 3; i++) {
            mesh_guest_service_pump(service, GCT_NOW + 2 + i);
            ASSERT_EQ(rvmachine_conport_queued(machine, 0), (size_t)0);
            ASSERT_EQ(gct_streams(), (size_t)0);
        }
        wire = gct_take_b(); ASSERT_EQ(wire.datas, (size_t)0); ASSERT_EQ(wire.opens, (size_t)0);
        ASSERT(mesh_guest_service_stop(service));
        ASSERT_EQ(mesh_guest_service_slice(service, 3000, owed_us, false,
            &decision, &result), RVMACHINE_ERR_STATE);
        PASS();
    }
_test_next:;
    struct guest_service_runner_snapshot final;
    *remaining_us = service && mesh_guest_service_snapshot(service, &final) && final.accounting_pending ? owed_us : 0;
    return failures;
}
static bool gct_s6_release_fixture(struct mesh_guest_service **owned, uint64_t owed_us)
{
    if (!*owned) return true;
    struct guest_service_runner_snapshot snapshot;
    struct guest_gov_decision decision;
    struct rvmachine_result result;
    if (!mesh_guest_service_stop(*owned) || !mesh_guest_service_snapshot(*owned, &snapshot))
        return false;
    if (snapshot.accounting_pending && (!owed_us ||
        mesh_guest_service_slice(*owned, 100000, owed_us, false, &decision, &result) != RVMACHINE_ERR_STATE))
        return false;
    if (!mesh_guest_service_snapshot(*owned, &snapshot) || snapshot.accounting_pending ||
        !mesh_guest_service_destroy(*owned)) return false;
    *owned = NULL;
    return true;
}

static int gct_s6_private_factory_refused(const uint8_t *kernel, size_t length)
{
    int failures = 0;
    struct mesh_guest_service *service = NULL;
    struct mesh_guest_service_config config = {
        .machine = {.ram_bytes = UINT64_C(64) << 20,
            .wait_stops = true, .cleanse_on_destroy = true,
            .private_keyfile_port_plus_one = 1},
        .kernel = kernel, .kernel_length = length,
        .binding = gct_s6_test_binding
    };
    config.limits = guest_limits_default();
    bool disk_consumed = true;
    TEST("public guest factory refuses private keyfile mode before assigning T/P ports") {
        ASSERT_EQ(config.machine.conport_count, (size_t)0);
        ASSERT_EQ(mesh_guest_service_create(&service, &config, &disk_consumed),
            RVMACHINE_ERR_ARG);
        ASSERT(service == NULL);
        ASSERT(!disk_consumed);
        PASS();
    }
_test_next:
    if (service && !mesh_guest_service_destroy(service)) failures++;
    return failures;
}

static int gct_s6_factory_suite(void)
{
    int failures = 0;
    static uint8_t image[65536];
    size_t length = 0;
    struct mesh_guest_service *owned = NULL;
    uint64_t owed_us = 0;
    TEST("guest factory: verified signed conport fixture and terminal resource release") {
        ASSERT(gct_s6_verified_conport(image, &length));
        failures += gct_s6_private_factory_refused(image, length);
        failures += gct_s6_credit(&owned, image, length, &owed_us);
        ASSERT(gct_s6_release_fixture(&owned, owed_us));
        failures += gct_s6_epoch(&owned, image, length, false, &owed_us);
        ASSERT(gct_s6_release_fixture(&owned, owed_us));
        failures += gct_s6_epoch(&owned, image, length, true, &owed_us);
        ASSERT(gct_s6_release_fixture(&owned, owed_us));
        if (!failures) PASS();
    }
_test_next:
    if (owned && !gct_s6_release_fixture(&owned, owed_us)) failures++;
    return failures;
}
static int gct_s6_runner_accounting(bool terminal)
{
    int failures = 0;
    struct guest_service_runner *runner = NULL;
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct rvmachine_config config = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true};
    struct guest_limits limits = guest_limits_default();
    limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    limits.max_slices_per_second = 1;
    struct guest_gov_decision decision;
    struct rvmachine_result result, zero = {0};
    struct guest_service_runner_snapshot snapshot;
    bool disk_consumed = true;
    uint64_t measured_us = 0;
    TEST("guest runner: actual run charge survives invalid retry and settles once without another run") {
        ASSERT_EQ(guest_service_runner_create(&runner, &config, loop, sizeof(loop),
            &limits, &disk_consumed), RVMACHINE_OK);
        ASSERT(!disk_consumed);
        struct timespec begin, end;
        ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &begin), 0);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, 0, false,
            &decision, &result), RVMACHINE_OK);
        ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &end), 0);
        if (end.tv_sec < begin.tv_sec ||
            (end.tv_sec == begin.tv_sec && end.tv_nsec < begin.tv_nsec)) {
            fprintf(stderr, "UNOBSERVED: real invocation clock reversed; pending charge retained\n");
            failures++;
            goto _test_next;
        }
        uint64_t seconds = (uint64_t)(end.tv_sec - begin.tv_sec);
        int64_t nanos = end.tv_nsec - begin.tv_nsec;
        if (nanos < 0) { seconds--; nanos += INT64_C(1000000000); }
        if (seconds > (UINT64_MAX - UINT64_C(1000000)) / UINT64_C(1000000)) {
            fprintf(stderr, "UNOBSERVED: real invocation measurement unrepresentable; pending charge retained\n");
            failures++;
            goto _test_next;
        }
        measured_us = seconds * UINT64_C(1000000) + (uint64_t)nanos / 1000u +
            ((uint64_t)nanos % 1000u != 0);
        if (!measured_us) measured_us = 1; /* explicit resolution-up contract */
        ASSERT_EQ(decision.kind, GUEST_GOV_RUN_SLICE);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot));
        ASSERT(snapshot.returned); ASSERT(snapshot.accounting_pending); ASSERT_EQ(snapshot.slices, UINT64_C(1));
        const struct rvmachine *machine = guest_service_runner_device(runner);
        ASSERT(machine != NULL); uint64_t retired = rvmachine_retired(machine);
        ASSERT(retired > 0);
        ASSERT(!guest_service_runner_destroy(runner));
        ASSERT(guest_service_runner_snapshot(runner, &snapshot)); ASSERT(snapshot.accounting_pending);
        if (terminal) guest_service_runner_request_stop(runner);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, measured_us, false,
            NULL, &result), RVMACHINE_ERR_ARG);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot));
        ASSERT(!snapshot.returned); ASSERT(snapshot.accounting_pending);
        ASSERT_EQ(guest_service_runner_slice(runner, 999, measured_us, false,
            &decision, &result), RVMACHINE_ERR_ARG);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot)); ASSERT(snapshot.accounting_pending);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, 0, false,
            &decision, &result), RVMACHINE_ERR_ARG);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot)); ASSERT(snapshot.accounting_pending);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, measured_us, false,
            &decision, &result), terminal ? RVMACHINE_ERR_STATE : RVMACHINE_OK);
        ASSERT_EQ(decision.kind, GUEST_GOV_SLEEP);
        ASSERT(!memcmp(&result, &zero, sizeof(result)));
        ASSERT(guest_service_runner_snapshot(runner, &snapshot));
        ASSERT(!snapshot.returned); ASSERT(!snapshot.accounting_pending);
        ASSERT_EQ(snapshot.slices, UINT64_C(1)); ASSERT_EQ(rvmachine_retired(machine), retired);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, measured_us, false,
            &decision, &result), RVMACHINE_ERR_ARG);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot)); ASSERT(!snapshot.accounting_pending);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, 0, false,
            &decision, &result), terminal ? RVMACHINE_ERR_STATE : RVMACHINE_OK);
        ASSERT(guest_service_runner_snapshot(runner, &snapshot));
        ASSERT(!snapshot.accounting_pending); ASSERT_EQ(snapshot.slices, UINT64_C(1));
        ASSERT_EQ(rvmachine_retired(machine), retired);
        ASSERT(guest_service_runner_destroy(runner)); runner = NULL;
        PASS();
    }
_test_next:
    if (runner) {
        guest_service_runner_request_stop(runner);
        if (guest_service_runner_snapshot(runner, &snapshot) && snapshot.accounting_pending && measured_us)
            (void)guest_service_runner_slice(runner, 1000, measured_us, false, &decision, &result);
        if (!guest_service_runner_destroy(runner)) failures++;
    }
    return failures;
}
static size_t gct_s6_refused_binding_calls;
static bool gct_s6_refused_binding(void *context, const uint8_t peer[32],
    const uint8_t *payload, size_t length, uint8_t *reply, size_t capacity,
    size_t *produced, uint32_t *slot, uint32_t *role)
{
    (void)context; (void)peer; (void)payload; (void)length;
    (void)reply; (void)capacity; (void)slot; (void)role;
    *produced = 0; gct_s6_refused_binding_calls++; return false;
}

static struct mesh_guest_service_launch_config gct_resource_config(void)
{
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct mesh_guest_service_launch_config config = {
        .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
        .disk_mode = MESH_GUEST_DISK_NONE,
        .service = {
            .machine = {.wait_stops = true},
            .kernel = loop, .kernel_length = sizeof(loop),
            .binding = gct_s6_refused_binding
        }
    };
    config.service.limits = guest_limits_default();
    return config;
}
/* PUBLIC deterministic sources for disk ownership fixtures, not entropy health. */
static size_t gct_enrollment_entropy(void *context, uint8_t *bytes, size_t length)
{
    (void)context;
    memset(bytes, 0x35, length);
    return length;
}
static bool gct_enrollment_seed(void *context, uint8_t *bytes, size_t length, size_t *given)
{
    *given = gct_enrollment_entropy(context, bytes, length);
    return true;
}
static void gct_enrollment_disk_config(struct mesh_guest_service_launch_config *config)
{
    static uint8_t image[0x1040];
    memset(image, 0, sizeof(image));
    memcpy(image, "\177ELF", 4); image[4] = 2; image[5] = 1; image[6] = 1;
    zcl_write_u16_le(image + 16, 2); zcl_write_u16_le(image + 18, 243);
    zcl_write_u32_le(image + 20, 1);
    const uint64_t linked = UINT64_C(0xffffffc000000000);
    zcl_write_u64_le(image + 24, linked + 0x30);
    zcl_write_u64_le(image + 32, 64);
    zcl_write_u16_le(image + 52, 64); zcl_write_u16_le(image + 54, 56);
    zcl_write_u16_le(image + 56, 1);
    zcl_write_u32_le(image + 64, 1); zcl_write_u32_le(image + 68, 5);
    zcl_write_u64_le(image + 72, 0x1000); zcl_write_u64_le(image + 80, linked);
    zcl_write_u64_le(image + 88, RVMACHINE_KERNEL_BASE);
    zcl_write_u64_le(image + 96, 64); zcl_write_u64_le(image + 104, 64);
    zcl_write_u64_le(image + 112, 0x1000);
    image[0x1030] = 0x6f; /* actual loader-entry loop */
    config->policy = MESH_GUEST_LAUNCH_SECRET_REQUIRED;
    config->disk_mode = MESH_GUEST_DISK_RETAINED_BACKEND;
    config->disk_bytes = config->enrollment.expected.volume_bytes;
    config->service.kernel = image; config->service.kernel_length = sizeof(image);
    config->service.machine.cleanse_on_destroy = true;
    config->service.machine.entropy_fail_closed = true;
    config->service.machine.entropy = gct_enrollment_entropy;
    config->service.machine.boot_seed = gct_enrollment_seed;
}


struct gct_public_owner {
    struct platform_private_file *credential;
    bool accepted, receiver;
};
static bool gct_public_accepted(void *context, const uint8_t digest[32])
{
    struct gct_public_owner *owner = context;
    return owner->accepted && memcmp(digest, gct_public_consumer_digest, 32) == 0;
}
static bool gct_public_keyfile(void *context, const struct platform_private_file *file)
{
    struct gct_public_owner *owner = context;
    struct platform_positioned_file view = {.native = file->native};
    struct platform_positioned_file_snapshot snapshot;
    return file == owner->credential && file->locked &&
        platform_positioned_file_is_current_user_only(&view) &&
        platform_positioned_file_snapshot(&view, &snapshot) && snapshot.size == 32;
}
static bool gct_public_receiver(void *context, const struct rvmachine *machine,
    uint64_t instance, uint32_t epoch)
{
    struct gct_public_owner *owner = context;
    return owner->receiver && machine && instance && epoch;
}
static void gct_public_console(void *context, const struct rvmachine *machine,
    uint64_t instance, const uint8_t *bytes, size_t length)
{
    (void)context; (void)machine; (void)instance; (void)bytes; (void)length;
    /* Synthetic loop emits no console. Actual called-owner matcher is tested separately. */
}

static void gct_public_bad_policy(struct mesh_guest_service_launch_config *bad,
    struct gct_public_owner *owner, unsigned mode)
{
    if (mode == 0) bad->unlock.authorized_kernel[0] ^= 1;
    if (mode == 1) bad->unlock.purpose = MESH_GUEST_UNLOCK_PURPOSE_NONE;
    if (mode == 2) bad->unlock.receiver_revision = 2;
    if (mode == 3) bad->unlock.accepted_current = NULL;
    if (mode == 4) owner->accepted = false;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Metadata-only controls of the included actual manager image chooser.
 * This does not load a V7 kernel, create a manager, or grant guest execution. */
static void gct_public_tuple_label(uint8_t digest[32], const char *label)
{
    struct sha256_ctx hash;
    sha256_init(&hash);
    sha256_write(&hash, (const uint8_t *)label, strlen(label));
    sha256_finalize(&hash, digest);
}
static bool gct_public_profile_tuple(struct mesh_guest_service_launch_config *c,
    bool v3)
{
    memset(c, 0, sizeof *c);
    c->service.kernel_length=UINT64_C(43407928);
    c->disk_bytes=UINT64_C(16)<<20;
    c->enrollment.expected.volume_bytes=c->disk_bytes;
    c->enrollment.expected.generation=1;
    struct mesh_guest_enrollment_record *r=&c->enrollment.expected;
    if (!zcl_hex_decode_lower(v3 ?
        "ac1dd2f5260aa64d2ba9cf30c13927709ff7f427709571dd65521051cf44b57c" :
        "db2440c0ce534decbac8aac94fade789c8978e5d145f1795fa216603a7404af5",
        c->unlock.authorized_kernel,32) ||
        !zcl_hex_decode_lower(v3 ?
        "ae126a37ac11db4203992f905c5a4a14ceb2668bb67fd3b861f704cdcde0e7a8" :
        "66298db371101e5085cd88abfaf4b5835208ae75b441d4fdd3a325fa72741ae9",r->root,32) ||
        !zcl_hex_decode_lower(v3 ?
        "716e739adbd37ca284765790267cc1e973f82686359a6cbe7993d060ac91e9f4" :
        "274880bbfd8a46a278d78c5e765a76c4299d107ced67f583e676993b826c8e5f",r->helper,32)) return false;
    memcpy(r->kernel,c->unlock.authorized_kernel,32);
    gct_public_tuple_label(r->guest_id,v3 ? "z23.PUBLIC.geli.owner.guest.v3" : "z23.PUBLIC.geli.owner.guest.v2");
    gct_public_tuple_label(r->profile,v3 ? "z23.PUBLIC.geli.owner.profile.v3" : "z23.PUBLIC.geli.owner.profile.v2");
    gct_public_tuple_label(r->owner_grant,v3 ? "local.operator.PUBLIC.geli.keyfile.v3" : "local.operator.PUBLIC.geli.keyfile.v2");
    return true;
}
static int gct_public_v3_tuple_controls(void)
{
    int failures=0;
    TEST("PUBLIC V3 image choice requires every exact tuple field") {
        struct mesh_guest_service_launch_config original,changed;
        uint8_t legacy[32]={0},selected[32];
        ASSERT(gct_public_profile_tuple(&original,true));
        const uint8_t *chosen=sgm_unlock_image(&original,legacy,selected);
        ASSERT(chosen && chosen==selected);
        ASSERT(memcmp(chosen,original.unlock.authorized_kernel,32)==0);
        for (unsigned mode=0;mode<10;mode++) {
            changed=original;
            if(mode==0) changed.service.kernel_length++;
            if(mode==1) changed.disk_bytes++;
            if(mode==2) changed.enrollment.expected.volume_bytes++;
            if(mode==3) changed.enrollment.expected.generation=0;
            if(mode==4) changed.enrollment.expected.root[0]^=1;
            if(mode==5) changed.enrollment.expected.helper[0]^=1;
            if(mode==6) changed.enrollment.expected.guest_id[0]^=1;
            if(mode==7) changed.enrollment.expected.profile[0]^=1;
            if(mode==8) changed.enrollment.expected.owner_grant[0]^=1;
            if(mode==9) changed.unlock.authorized_kernel[0]^=1;
            ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
            ASSERT(sgm_unlock_image(&original,legacy,selected)!=NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int gct_public_v3_mixed_controls(void)
{
    int failures=0;
    TEST("PUBLIC V2 and V3 images cannot borrow the other profile tuple") {
        struct mesh_guest_service_launch_config v2,v3,changed;
        uint8_t legacy[32]={0},selected[32];
        ASSERT(gct_public_profile_tuple(&v2,false));
        ASSERT(gct_public_profile_tuple(&v3,true));
        ASSERT(sgm_unlock_image(&v2,legacy,selected)!=NULL);
        ASSERT(sgm_unlock_image(&v3,legacy,selected)!=NULL);
        changed=v3;
        memcpy(changed.unlock.authorized_kernel,v2.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=v2;
        memcpy(changed.unlock.authorized_kernel,v3.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        PASS();
    } _test_next:;
    return failures;
}
static bool gct_public_paired_tuple(struct mesh_guest_service_launch_config *c, bool zbb)
{
    if (!gct_public_profile_tuple(c,true)) return false;
    c->service.kernel_length=zbb ? UINT64_C(43406744) : UINT64_C(43408024);
    if (!zcl_hex_decode_lower(zbb ?
        "c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7" :
        "fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e",
        c->unlock.authorized_kernel,32)) return false;
    struct mesh_guest_enrollment_record *r=&c->enrollment.expected;
    memcpy(r->kernel,c->unlock.authorized_kernel,32);
    gct_public_tuple_label(r->guest_id,zbb ? "z23.PUBLIC.geli.owner.guest.v5" : "z23.PUBLIC.geli.owner.guest.v4");
    gct_public_tuple_label(r->profile,zbb ? "z23.PUBLIC.geli.owner.profile.v5" : "z23.PUBLIC.geli.owner.profile.v4");
    gct_public_tuple_label(r->owner_grant,zbb ? "local.operator.PUBLIC.geli.keyfile.v5" : "local.operator.PUBLIC.geli.keyfile.v4");
    return true;
}
static int gct_public_paired_tuple_controls(void)
{
    int failures=0;
    TEST("PUBLIC paired kernels require every exact image selection tuple field") {
        struct mesh_guest_service_launch_config original,changed;
        uint8_t legacy[32]={0},selected[32];
        for (unsigned arm=0;arm<2;arm++) {
            ASSERT(gct_public_paired_tuple(&original,arm!=0));
            const uint8_t *chosen=sgm_unlock_image(&original,legacy,selected);
            ASSERT(chosen && chosen==selected);
            ASSERT(memcmp(chosen,original.unlock.authorized_kernel,32)==0);
            for (unsigned mode=0;mode<10;mode++) {
                changed=original;
                if(mode==0) changed.service.kernel_length++;
                if(mode==1) changed.disk_bytes++;
                if(mode==2) changed.enrollment.expected.volume_bytes++;
                if(mode==3) changed.enrollment.expected.generation=0;
                if(mode==4) changed.enrollment.expected.root[0]^=1;
                if(mode==5) changed.enrollment.expected.helper[0]^=1;
                if(mode==6) changed.enrollment.expected.guest_id[0]^=1;
                if(mode==7) changed.enrollment.expected.profile[0]^=1;
                if(mode==8) changed.enrollment.expected.owner_grant[0]^=1;
                if(mode==9) changed.unlock.authorized_kernel[0]^=1;
                ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
                ASSERT(sgm_unlock_image(&original,legacy,selected)!=NULL);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}
static int gct_public_paired_mixed_controls(void)
{
    int failures=0;
    TEST("PUBLIC paired images cannot borrow another paired or V3 tuple") {
        struct mesh_guest_service_launch_config baseline,zbb,v3,changed;
        uint8_t legacy[32]={0},selected[32];
        ASSERT(gct_public_paired_tuple(&baseline,false));
        ASSERT(gct_public_paired_tuple(&zbb,true));
        ASSERT(gct_public_profile_tuple(&v3,true));
        changed=baseline;
        memcpy(changed.unlock.authorized_kernel,zbb.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=zbb;
        memcpy(changed.unlock.authorized_kernel,baseline.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=v3;
        memcpy(changed.unlock.authorized_kernel,zbb.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=zbb;
        memcpy(changed.unlock.authorized_kernel,v3.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=baseline;
        changed.enrollment.expected=zbb.enrollment.expected;
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=zbb;
        changed.enrollment.expected=baseline.enrollment.expected;
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        PASS();
    } _test_next:;
    return failures;
}
static bool gct_public_combined_tuple(struct mesh_guest_service_launch_config *c, bool optimized)
{
    if (!gct_public_profile_tuple(c,true)) return false;
    c->service.kernel_length=UINT64_C(43412608);
    const char *kernel=optimized ?
        "f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d" :
        "82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562";
    if (!zcl_hex_decode_lower(kernel,c->unlock.authorized_kernel,32)) return false;
    struct mesh_guest_enrollment_record *r=&c->enrollment.expected;
    memcpy(r->kernel,c->unlock.authorized_kernel,32);
    gct_public_tuple_label(r->guest_id,optimized ? "z23.PUBLIC.geli.owner.guest.v7" : "z23.PUBLIC.geli.owner.guest.v6");
    gct_public_tuple_label(r->profile,optimized ? "z23.PUBLIC.geli.owner.profile.v7" : "z23.PUBLIC.geli.owner.profile.v6");
    gct_public_tuple_label(r->owner_grant,optimized ? "local.operator.PUBLIC.geli.keyfile.v7" : "local.operator.PUBLIC.geli.keyfile.v6");
    if (optimized && !zcl_hex_decode_lower("9541a135ed646af120c182fb19b7586a8f3ead63b1edd1cc880d8f584c674cac",r->root,32)) return false;
    return true;
}
static int gct_public_combined_mixed_controls(void)
{
    int failures=0;
    TEST("combined PUBLIC kernel cannot borrow original Zbb profile tuple") {
        struct mesh_guest_service_launch_config combined,zbb,changed;
        uint8_t legacy[32]={0},selected[32];
        ASSERT(gct_public_combined_tuple(&combined,false));
        ASSERT(gct_public_paired_tuple(&zbb,true));
        changed=combined;memcpy(changed.unlock.authorized_kernel,zbb.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=zbb;memcpy(changed.unlock.authorized_kernel,combined.unlock.authorized_kernel,32);
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        changed=combined;changed.enrollment.expected=zbb.enrollment.expected;
        ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        PASS();
    } _test_next:;
    return failures;
}
static int gct_public_combined_tuple_controls(void)
{
    int failures=0;
    TEST("PUBLIC combined kernel require every exact image selection tuple field") {
        struct mesh_guest_service_launch_config original,changed;
        uint8_t legacy[32]={0},selected[32];

        for (unsigned side=0;side<2;side++) {
            ASSERT(gct_public_combined_tuple(&original,side!=0));
            const uint8_t *chosen=sgm_unlock_image(&original,legacy,selected);
            ASSERT(chosen && chosen==selected);
            ASSERT(memcmp(chosen,original.unlock.authorized_kernel,32)==0);
            for (unsigned mode=0;mode<10;mode++) {
                changed=original;
                if(mode==0) changed.service.kernel_length++;
                if(mode==1) changed.disk_bytes++;
                if(mode==2) changed.enrollment.expected.volume_bytes++;
                if(mode==3) changed.enrollment.expected.generation=0;
                if(mode==4) changed.enrollment.expected.root[0]^=1;
                if(mode==5) changed.enrollment.expected.helper[0]^=1;
                if(mode==6) changed.enrollment.expected.guest_id[0]^=1;
                if(mode==7) changed.enrollment.expected.profile[0]^=1;
                if(mode==8) changed.enrollment.expected.owner_grant[0]^=1;
                if(mode==9) changed.unlock.authorized_kernel[0]^=1;
                ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
                ASSERT(sgm_unlock_image(&original,legacy,selected)!=NULL);
            }
            struct mesh_guest_service_launch_config other;
            ASSERT(gct_public_combined_tuple(&other,side==0));
            changed=original;
            memcpy(changed.unlock.authorized_kernel,other.unlock.authorized_kernel,32);
            ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
            changed=original;changed.enrollment.expected=other.enrollment.expected;
            ASSERT(sgm_unlock_image(&changed,legacy,selected)==NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}
static int gct_public_owner_admission(void)
{
    int failures = 0;
    static char dir[256], volume_path[320], credential_path[320], record_path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_guest_chan", "PUBLIC-owner");
    snprintf(volume_path, sizeof volume_path, "%s/volume", dir);
    snprintf(credential_path, sizeof credential_path, "%s/credential", dir);
    snprintf(record_path, sizeof record_path, "%s/record", dir);
    static struct platform_private_file volume, credential;
    platform_private_file_init(&volume); platform_private_file_init(&credential);
    static struct mesh_guest_service_manager *manager;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    static struct gct_public_owner owner;
    owner = (struct gct_public_owner){.credential = &credential, .accepted = true, .receiver = true};
    uint8_t public_bytes[32];
    for (size_t i = 0; i < 32; i++) public_bytes[i] = (uint8_t)(i + 1);
    struct mesh_guest_enrollment_record *expected = &config.enrollment.expected;
    memset(expected->guest_id, 1, 32); memset(expected->root, 3, 32);
    memset(expected->helper, 4, 32); memset(expected->profile, 5, 32);
    memset(expected->owner_grant, 6, 32); expected->generation = 1; expected->volume_bytes = 512;
    config.enrollment.mode = MESH_GUEST_ENROLLMENT_INITIAL;
    config.enrollment.volume = &volume; config.enrollment.credential = &credential;
    config.enrollment.initial_destination = record_path;
    gct_enrollment_disk_config(&config);
    config.service.machine.ram_bytes = UINT64_C(64) << 20;
    config.service.limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, config.service.kernel, config.service.kernel_length);
    sha256_finalize(&hash, gct_public_consumer_digest);
    memcpy(expected->kernel, gct_public_consumer_digest, 32);
    config.unlock = (struct mesh_guest_unlock_admission){
        .policy = MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE,
        .purpose = MESH_GUEST_UNLOCK_PUBLIC_GELI_KEYFILE, .receiver_revision = 1,
        .accepted_current = gct_public_accepted, .public_keyfile_current = gct_public_keyfile,
        .receiver_current = gct_public_receiver, .receiver_console = gct_public_console,
        .owner_context = &owner
    };
    memcpy(config.unlock.authorized_kernel, gct_public_consumer_digest, 32);
    TEST("actual manager local PUBLIC admission precedes factory and keyfile reads") {
        ASSERT(platform_private_file_create_locked(volume_path, &volume));
        ASSERT(platform_private_file_truncate(&volume, 512));
        ASSERT(platform_private_file_create_locked(credential_path, &credential));
        ASSERT(platform_private_file_write_at(&credential, public_bytes, 32, 0));
        struct platform_private_file_identity identity;
        ASSERT(platform_private_file_identity(&volume, &identity));
        expected->volume_device = identity.volume; expected->volume_file = identity.file;
        gct_public_credential_native = credential.native;
        gct_public_credential_reads = 0;
        unsigned factories = gct_enrollment_factory_calls;
        for (unsigned mode = 0; mode < 5; mode++) {
            struct mesh_guest_service_launch_config bad = config;
            gct_public_bad_policy(&bad, &owner, mode);
            ASSERT(!gct_retry_manager_create(&manager, &bad));
            ASSERT(manager == NULL);
            ASSERT_EQ(gct_enrollment_factory_calls, factories);
            ASSERT_EQ(gct_public_credential_reads, 0u);
            owner.accepted = true;
        }
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT_EQ(gct_public_credential_reads, 0u);
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        struct guest_action action;
        owner.accepted = false;
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 0, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 0, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT_EQ(gct_public_credential_reads, 0u);
        ASSERT(manager->enrollment_failed);
        owner.accepted = true;
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, UINT64_C(3600000), &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT(gct_retry_manager_destroy(manager, UINT64_C(3600001))); manager = NULL;
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 0, &action));
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 0, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories + 1);
        struct guest_gov_decision decision;
        struct rvmachine_result result;
        ASSERT(gct_retry_manager_drive(manager, 1000, 1, &decision, &result) == RVMACHINE_OK);
        struct guest_service_runner_snapshot returned;
        ASSERT(gct_retry_snapshot(manager->instance, &returned));
        ASSERT(returned.slices > 0 && returned.accounting_pending);
        ASSERT(manager->pending_measured && manager->pending_us > 0);
        struct rvmachine *machine = gct_retry_test_machine(manager->instance);
        uint64_t instance = gct_retry_manager_instance(manager);
        ASSERT(machine && instance && machine->conport_count == 5);
        uint32_t epoch = rvmachine_conport_generation(machine, 4);
        ASSERT(!gct_retry_manager_unlock_public(manager, instance + 1, epoch, 1001));
        ASSERT(!gct_retry_manager_unlock_public(manager, instance, epoch + 1, 1001));
        ASSERT(!manager->unlock_attempted);
        ASSERT_EQ(gct_public_credential_reads, 0u);
        /* PUBLIC native model setup, not guest initialization/raw-tty evidence. */
        ASSERT(machine->seed_addr >= RVMACHINE_RAM_BASE);
        ASSERT(machine->seed_addr - RVMACHINE_RAM_BASE <= machine->ram_bytes - RVMACHINE_BOOT_SEED_BYTES);
        memset(machine->mem.bytes + (machine->seed_addr - RVMACHINE_RAM_BASE), 0, RVMACHINE_BOOT_SEED_BYTES);
        machine->con.ports[4].guest_open = true;
        machine->conports[4].seen_generation = machine->con.ports[4].generation;
        ASSERT(gct_retry_manager_unlock_public(manager, instance, epoch, 1001));
        ASSERT(manager->unlock_attempted && manager->unlock_delivered);
        ASSERT_EQ(gct_public_credential_reads, 2u); /* Actual32 read and actual EOF read. */
        ASSERT_EQ(machine->conports[4].count, (size_t)32);
        ASSERT(memcmp(machine->conports[4].bytes, public_bytes, 32) == 0);
        /* Actual clock refusal keeps the real pending charge and borrowed contexts alive. */
        gct_retry_clock_fail = true;
        ASSERT(!gct_retry_manager_unlock_public(manager, instance, epoch, 1002));
        ASSERT(manager->instance != NULL && manager->config.unlock.owner_context == &owner);
        ASSERT(manager->pending_measured && manager->unlock_attempted);
        ASSERT_EQ(gct_public_credential_reads, 2u);
        ASSERT(machine->conport_fault && machine->conports[4].count == 0);
        for (size_t i = 0; i < sizeof machine->conports[4].bytes; i++) ASSERT(machine->conports[4].bytes[i] == 0);
        ASSERT(credential.locked && volume.locked);
        ASSERT(gct_retry_manager_destroy(manager, 1003)); manager = NULL;
        PASS();
    } _test_next:;
    gct_retry_clock_fail = false;
    if (manager && !gct_retry_manager_destroy(manager, 1004)) {
        failures++;
        return failures; /* Static callback/FD capsule remains alive on unexpected join refusal. */
    }
    manager = NULL;
    gct_public_credential_native = UINTPTR_MAX;
    platform_private_file_close(&credential); platform_private_file_close(&volume);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int gct_enrollment_owner_lifecycle(void)
{
    int failures = 0;
    char dir[256], volume_path[320], credential_path[320], record_path[320];
    test_make_tmpdir(dir, sizeof(dir), "mesh_guest_chan", "enrollment");
    snprintf(volume_path, sizeof(volume_path), "%s/public-volume", dir);
    snprintf(credential_path, sizeof(credential_path), "%s/public-credential", dir);
    snprintf(record_path, sizeof(record_path), "%s/public-enrollment", dir);
    struct platform_private_file volume, credential, record;
    platform_private_file_init(&volume); platform_private_file_init(&credential);
    platform_private_file_init(&record);
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    config.service.machine.ram_bytes = UINT64_C(64) << 20;
    config.service.limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    struct mesh_guest_enrollment_record *expected = &config.enrollment.expected;
    uint8_t public_key[32], public_material[32];
    for (size_t i = 0; i < 32; i++) public_key[i] = public_material[i] = (uint8_t)(i + 1);
    memset(expected->guest_id, 1, 32); memset(expected->kernel, 2, 32);
    memset(expected->root, 3, 32); memset(expected->helper, 4, 32);
    memset(expected->profile, 5, 32); memset(expected->owner_grant, 6, 32);
    expected->generation = 7; expected->volume_bytes = 512;
    config.enrollment.mode = MESH_GUEST_ENROLLMENT_INITIAL;
    config.enrollment.volume = &volume; config.enrollment.credential = &credential;
    config.enrollment.initial_destination = record_path;
    struct guest_action action;
    TEST("guest enrollment: actual owner publishes once before READY and recovery retains exact binding") {
        ASSERT(platform_private_file_create_locked(volume_path, &volume));
        ASSERT(platform_private_file_truncate(&volume, 512));
        ASSERT(platform_private_file_create_locked(credential_path, &credential));
        ASSERT(platform_private_file_write_at(&credential, public_material, 32, 0));
        struct platform_private_file_identity identity;
        ASSERT(platform_private_file_identity(&volume, &identity));
        expected->volume_device = identity.volume; expected->volume_file = identity.file;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        gct_enrollment_disk_config(&config);
        config.disk_context = &credential;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL); config.disk_context = NULL;
        config.disk_bytes++;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL); config.disk_bytes--;
        unsigned factories = gct_enrollment_factory_calls;
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 0, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 0, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories + 1);
        ASSERT(gct_retry_manager_instance(manager) != 0);
        struct rvmachine *actual = gct_retry_test_machine(manager->instance);
        const uint8_t stored[8] = {0x21,0x43,0x65,0x87,0xa9,0xcb,0xed,0x0f};
        uint8_t seen[32];
        ASSERT(actual && actual->disk);
        uint64_t storage_instance = gct_retry_manager_instance(manager);
        ASSERT(!gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(rvmachine_disk_write(actual->disk, 7, stored, sizeof(stored)));
        ASSERT(!gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(rvmachine_disk_flush(actual->disk));
        ASSERT(gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(!gct_retry_manager_storage_synced(manager, storage_instance + 1));
        ASSERT(!gct_retry_manager_storage_synced(manager, 0));
        ASSERT(gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(rvmachine_disk_write(actual->disk, 7, stored, sizeof(stored)));
        ASSERT(!gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(rvmachine_disk_flush(actual->disk));
        ASSERT(gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(rvmachine_disk_read(actual->disk, 7, seen, sizeof(stored)));
        ASSERT(!memcmp(seen, stored, sizeof(stored)));
        ASSERT(platform_private_file_read_at(&volume, seen, sizeof(stored), 7));
        ASSERT(!memcmp(seen, stored, sizeof(stored)));
        ASSERT(platform_private_file_read_at(&credential, seen, sizeof(seen), 0));
        ASSERT(!memcmp(seen, public_material, sizeof(seen)));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = false}, 1, &action));
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT(!gct_retry_manager_storage_synced(manager, storage_instance));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 2, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 2, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories + 1);
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT(platform_private_path_absent(record_path));
        ASSERT(gct_retry_manager_destroy(manager, 3)); manager = NULL;
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 1000, &action));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 1000, &action));
        uint64_t instance = mesh_guest_service_manager_instance(manager);
        ASSERT(instance != 0);
        ASSERT(!mesh_guest_service_manager_ready(manager, instance, 1000, &action));
        ASSERT(platform_private_path_absent(record_path));
        ASSERT(mesh_guest_service_manager_identity_finish(manager, instance, 7, public_key, true));
        ASSERT(manager->owned_record.locked);
        ASSERT(!platform_private_path_absent(record_path));
        ASSERT(mesh_guest_service_manager_ready(manager, instance, 1000, &action));
        ASSERT(!mesh_guest_service_manager_identity_finish(manager, instance, 7, public_key, true));
        ASSERT(!manager->enrollment_failed);
        ASSERT(mesh_guest_service_manager_destroy(manager, 2000)); manager = NULL;
        char initial_drift[384];
        int drift_n = snprintf(initial_drift, sizeof(initial_drift), "%s.drift", record_path);
        ASSERT(drift_n > 0 && (size_t)drift_n < sizeof(initial_drift));
        config.enrollment.initial_destination = initial_drift;
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 2100, &action));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 2100, &action));
        uint64_t drift_instance = mesh_guest_service_manager_instance(manager);
        ASSERT(mesh_guest_service_manager_identity_finish(manager, drift_instance, 7, public_key, true));
        ASSERT(manager->owned_record.locked);
        uint8_t initial_changed = public_key[0] ^ 1;
        ASSERT(platform_private_file_write_at(&manager->owned_record, &initial_changed, 1, 40));
        ASSERT(!mesh_guest_service_manager_ready(manager, drift_instance, 2100, &action));
        ASSERT(platform_private_file_write_at(&manager->owned_record, public_key, 32, 40));
        ASSERT(!mesh_guest_service_manager_ready(manager, drift_instance, 2100, &action));
        ASSERT(mesh_guest_service_manager_destroy(manager, 2200)); manager = NULL;
        config.enrollment.initial_destination = record_path;
        ASSERT(platform_private_file_open_locked(record_path, &record));
        struct mesh_guest_enrollment_record recovered;
        ASSERT(mesh_guest_enrollment_read(&record, &recovered));
        memcpy(expected->ssh_fingerprint, public_key, 32);
        ASSERT(mesh_guest_enrollment_equal(expected, &recovered));
        config.enrollment.mode = MESH_GUEST_ENROLLMENT_RECOVER;
        config.enrollment.record = &record; config.enrollment.initial_destination = NULL;
        factories = gct_enrollment_factory_calls;
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT(platform_private_file_truncate(&credential, 31));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 2500, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 2500, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        ASSERT_EQ(gct_retry_manager_instance(manager), UINT64_C(0));
        ASSERT(platform_private_file_write_at(&credential, public_material, 32, 0));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 100000, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        ASSERT(gct_retry_manager_destroy(manager, 100001)); manager = NULL;
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 3000, &action));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 3000, &action));
        uint64_t next = mesh_guest_service_manager_instance(manager);
        ASSERT(next != 0 && next != instance);
        ASSERT(!mesh_guest_service_manager_identity_finish(manager, instance, 7, public_key, true));
        ASSERT(!mesh_guest_service_manager_identity_finish(manager, next, 7, public_key, true));
        ASSERT(!mesh_guest_service_manager_ready(manager, next, 3000, &action));
        ASSERT(mesh_guest_service_manager_destroy(manager, 4000)); manager = NULL;
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 5000, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 5000, &action));
        next = gct_retry_manager_instance(manager);
        ASSERT(gct_retry_manager_identity_finish(manager, next, 7, public_key, true));
        ASSERT(gct_retry_manager_ready(manager, next, 5000, &action));
#if !defined(_WIN32)
        actual = gct_retry_test_machine(manager->instance);
        ASSERT(actual && actual->disk);
        ASSERT(chmod(volume_path, 0640) == 0);
        ASSERT(!rvmachine_disk_flush(actual->disk));
        ASSERT(manager->volume.failed);
        ASSERT(chmod(volume_path, 0600) == 0);
        ASSERT(!rvmachine_disk_read(actual->disk, 7, seen, sizeof(stored)));
        struct guest_gov_decision decision;
        struct rvmachine_result result;
        unsigned joins = gct_retry_destroy_calls;
        uint64_t before_retired = rvmachine_retired(actual);
        ASSERT_EQ(gct_retry_manager_drive(manager, 5001, 0, &decision, &result),
            RVMACHINE_ERR_DISK);
        ASSERT(manager->enrollment_failed && manager->instance == NULL);
        ASSERT_EQ(result.retired, UINT64_C(0));
        ASSERT_EQ(gct_retry_destroy_calls, joins + 1);
        ASSERT(!gct_retry_destroy_pending);
        ASSERT_EQ(gct_retry_destroy_retired, before_retired);
        struct guest_service_snapshot stopped;
        ASSERT(gct_retry_manager_snapshot(manager, 5001, &stopped));
        ASSERT_EQ(stopped.state, GUEST_STATE_ABSENT);
        ASSERT_EQ(stopped.last_failure, GUEST_REASON_GUEST_CRASHED);
        ASSERT_EQ(stopped.ports, 0); ASSERT_EQ(stopped.sessions, 0);
        factories = gct_enrollment_factory_calls;
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 1000000, &action));
        ASSERT_EQ(gct_enrollment_factory_calls, factories);
        ASSERT(manager->instance == NULL);
#endif
        ASSERT(gct_retry_manager_destroy(manager, 6000)); manager = NULL;
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 7000, &action));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 7000, &action));
        next = mesh_guest_service_manager_instance(manager);
        ASSERT(mesh_guest_service_manager_identity_finish(manager, next, 7, public_key, true));
        ASSERT(platform_private_file_truncate(&credential, 31));
        ASSERT(!mesh_guest_service_manager_ready(manager, next, 7000, &action));
        ASSERT(platform_private_file_write_at(&credential, public_material, 32, 0));
        ASSERT(!mesh_guest_service_manager_ready(manager, next, 7000, &action));
        ASSERT(mesh_guest_service_manager_destroy(manager, 8000)); manager = NULL;
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 9000, &action));
        ASSERT(mesh_guest_service_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 9000, &action));
        next = mesh_guest_service_manager_instance(manager);
        ASSERT(mesh_guest_service_manager_identity_finish(manager, next, 7, public_key, true));
        uint8_t changed_key = public_key[0] ^ 1;
        ASSERT(platform_private_file_write_at(&record, &changed_key, 1, 40));
        ASSERT(!mesh_guest_service_manager_ready(manager, next, 9000, &action));
        ASSERT(platform_private_file_write_at(&record, public_key, 32, 40));
        ASSERT(!mesh_guest_service_manager_ready(manager, next, 9000, &action));
        ASSERT(mesh_guest_service_manager_destroy(manager, 10000)); manager = NULL;
        expected->root[0] ^= 1;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL); expected->root[0] ^= 1;
        uint8_t version = 2;
        ASSERT(platform_private_file_write_at(&record, &version, 1, 0));
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        version = 1;
        ASSERT(platform_private_file_write_at(&record, &version, 1, 0));
        ASSERT(platform_private_file_truncate(&record, 265));
        ASSERT(!mesh_guest_enrollment_read(&record, &recovered));
        ASSERT(platform_private_file_truncate(&record, 263));
        ASSERT(!mesh_guest_enrollment_read(&record, &recovered));
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 11000)) failures++;
    platform_private_file_close(&record); platform_private_file_close(&credential);
    platform_private_file_close(&volume);
    return failures;
}
static int gct_s6_ready_deadline(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    config.service.machine.ram_bytes = UINT64_C(64) << 20;
    TEST("guest manager: late readiness reports refusal after stopping the actual owned guest") {
        for (unsigned offset = 0; offset < 3; offset++) {
            struct guest_action action;
            ASSERT(mesh_guest_service_manager_create(&manager, &config));
            ASSERT(mesh_guest_service_manager_event(manager,
                &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 1000, &action));
            ASSERT(mesh_guest_service_manager_event(manager,
                &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 1000, &action));
            uint64_t instance = mesh_guest_service_manager_instance(manager);
            ASSERT(instance != 0);
            uint64_t observed = 1000 + GUEST_SERVICE_START_DEADLINE_MS - 1 + offset;
            ASSERT(mesh_guest_service_manager_ready(manager, instance, observed, &action) == (offset == 0));
            struct guest_service_snapshot snapshot;
            ASSERT(mesh_guest_service_manager_snapshot(manager, observed, &snapshot));
            if (offset == 0) ASSERT_EQ(snapshot.state, GUEST_STATE_READY);
            else {
                ASSERT(snapshot.state != GUEST_STATE_READY);
                ASSERT_EQ(snapshot.last_failure, GUEST_REASON_STARTUP_DEADLINE);
            }
            ASSERT(mesh_guest_service_manager_destroy(manager, observed + 1));
            manager = NULL;
        }
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 200000)) failures++;
    return failures;
}

static int gct_s6_resource_ram_preflight(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    const uint64_t refused[] = {
        UINT64_C(63) << 20, RVMACHINE_RAM_MIN + 1,
        RVMACHINE_RAM_MAX + (UINT64_C(2) << 20)
    };
    TEST("guest manager resource preflight refuses invalid RAM before staging") {
        gct_s6_refused_binding_calls = 0;
        for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
            config.service.machine.ram_bytes = refused[i];
            ASSERT(!mesh_guest_service_manager_create(&manager, &config));
            ASSERT(manager == NULL);
        }
        ASSERT_EQ(gct_s6_refused_binding_calls, (size_t)0);
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_enrollment_missing_recovery(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    TEST("guest manager recovery without enrollment refuses before staging") {
        config.enrollment.mode = MESH_GUEST_ENROLLMENT_RECOVER;
        gct_s6_refused_binding_calls = 0;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        ASSERT_EQ(gct_s6_refused_binding_calls, (size_t)0);
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_unlock_missing_admission(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    TEST("PUBLIC keyfile owner refuses missing local admission before staging") {
        config.unlock.policy = MESH_GUEST_UNLOCK_PUBLIC_KEYFILE_FIXTURE;
        gct_s6_refused_binding_calls = 0;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        ASSERT_EQ(gct_s6_refused_binding_calls, (size_t)0);
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_s6_resource_bootargs_preflight(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    char bootargs[RVMACHINE_BOOTARGS_MAX + 1];
    memset(bootargs, 'x', sizeof(bootargs) - 1);
    bootargs[sizeof(bootargs) - 1] = '\0';
    config.service.machine.bootargs = bootargs;
    TEST("guest manager resource preflight refuses bootargs at the fixed bound") {
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_s6_resource_valid_staging(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    struct mesh_guest_service_launch_config config = gct_resource_config();
    const uint64_t allowed[] = {0, RVMACHINE_RAM_MIN, RVMACHINE_RAM_MAX};
    char bootargs[RVMACHINE_BOOTARGS_MAX];
    memset(bootargs, 'x', sizeof(bootargs) - 1);
    bootargs[sizeof(bootargs) - 1] = '\0';
    config.service.machine.bootargs = bootargs;
    TEST("guest manager resource preflight preserves default and boundaries without launching") {
        for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
            config.service.machine.ram_bytes = allowed[i];
            ASSERT(mesh_guest_service_manager_create(&manager, &config));
            ASSERT_EQ(mesh_guest_service_manager_instance(manager), UINT64_C(0));
            struct guest_service_snapshot snapshot;
            ASSERT(mesh_guest_service_manager_snapshot(manager, 0, &snapshot));
            ASSERT_EQ(snapshot.state, GUEST_STATE_ABSENT);
            ASSERT(mesh_guest_service_manager_destroy(manager, 0));
            manager = NULL;
        }
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_s6_launch_preflight_refused(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct mesh_guest_service_launch_config config = {
        .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
        .disk_mode = MESH_GUEST_DISK_NONE,
        .service = {
            .machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true},
            .kernel = loop, .kernel_length = sizeof(loop),
            .binding = gct_s6_refused_binding
        }
    };
    config.service.limits = guest_limits_default();
    TEST("guest manager preflight: unspecified policy/storage and partial disk inputs refuse before manager creation") {
        gct_s6_refused_binding_calls = 0;
        config.policy = MESH_GUEST_LAUNCH_UNSPECIFIED;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        config.policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE;
        config.disk_mode = MESH_GUEST_DISK_UNSPECIFIED;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        config.disk_mode = MESH_GUEST_DISK_NONE;
        config.disk_bytes = 512;
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        config.disk_mode = MESH_GUEST_DISK_EPHEMERAL_OVERLAY;
        /* A declared disk size without its reader is not an overlay backend. */
        ASSERT(!mesh_guest_service_manager_create(&manager, &config));
        ASSERT(manager == NULL);
        ASSERT_EQ(gct_s6_refused_binding_calls, (size_t)0);
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 0)) failures++;
    return failures;
}

static int gct_s6_stopping_clock_retry(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct mesh_guest_service_launch_config config = {
        .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
        .disk_mode = MESH_GUEST_DISK_NONE,
        .service = {.machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true},
            .kernel = loop, .kernel_length = sizeof(loop), .binding = gct_s6_refused_binding}
    };
    config.service.limits = guest_limits_default();
    struct guest_action action;
    struct guest_service_runner_snapshot before, retained;
    struct guest_service_snapshot lifecycle;
    struct guest_gov_decision decision;
    struct rvmachine_result result, zero = {0};
    uint64_t retired = 0;
    TEST("guest manager: proposed normal-drive retry settles retained STOPPING charge after one clock refusal") {
        gct_retry_clock_fail = false;
        gct_retry_clock_failures = 0;
        gct_retry_destroy_calls = 0;
        ASSERT(gct_retry_manager_create(&manager, &config));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = true}, 1000, &action));
        ASSERT(gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_OPERATOR_START}, 1000, &action));
        ASSERT(manager->instance != NULL);
        struct mesh_guest_service *instance = manager->instance;
        ASSERT(gct_retry_snapshot(instance, &before));
        ASSERT(before.accounting_pending);
        ASSERT(before.slices > 0);
        ASSERT(manager->pending_measured);
        ASSERT(manager->pending_us > 0);
        retired = rvmachine_retired(guest_service_runner_device(instance->runner));
        ASSERT(retired > 0);
        uint64_t owed = manager->pending_us;
        gct_retry_clock_fail = true;
        ASSERT(!gct_retry_manager_event(manager,
            &(struct guest_event){.kind = GUEST_EV_ENABLE, .enable = false}, 1001, &action));
        ASSERT_EQ(gct_retry_clock_failures, 1u);
        ASSERT(!gct_retry_clock_fail);
        ASSERT(manager->instance == instance);
        ASSERT_EQ(manager->pending_us, owed);
        ASSERT(manager->pending_measured);
        ASSERT(gct_retry_snapshot(instance, &retained));
        ASSERT(retained.stopping);
        ASSERT(retained.accounting_pending);
        ASSERT_EQ(retained.slices, before.slices);
        ASSERT_EQ(rvmachine_retired(guest_service_runner_device(instance->runner)), retired);
        ASSERT(gct_retry_manager_snapshot(manager, 1001, &lifecycle));
        ASSERT_EQ(lifecycle.state, GUEST_STATE_STOPPING);
        ASSERT(!lifecycle.enabled);
        ASSERT_EQ(gct_retry_destroy_calls, 0u);
        /* Existing destroy retries; the failsafe owner also needs a normal
         * drive to join after the host clock becomes available again. */
        ASSERT_EQ(gct_retry_manager_drive(manager, 1002, 0, &decision, &result), RVMACHINE_OK);
        ASSERT_EQ(decision.kind, GUEST_GOV_SLEEP);
        ASSERT(decision.sleep_ms > 0);
        ASSERT(decision.sleep_ms <= GUEST_GOV_MAX_SLEEP_MS);
        ASSERT_EQ(decision.work, UINT64_C(0));
        ASSERT(!memcmp(&result, &zero, sizeof(result)));
        ASSERT(manager->instance == NULL);
        ASSERT_EQ(gct_retry_destroy_calls, 1u);
        ASSERT(!gct_retry_destroy_pending);
        ASSERT_EQ(gct_retry_destroy_retired, retired);
        ASSERT(gct_retry_manager_snapshot(manager, 1002, &lifecycle));
        ASSERT_EQ(lifecycle.state, GUEST_STATE_ABSENT);
        PASS();
    }
_test_next:
    gct_retry_clock_fail = false;
    if (manager && !gct_retry_manager_destroy(manager, 1003)) failures++;
    return failures;
}
static int gct_s6_disabled_sleep(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct mesh_guest_service_launch_config config = {
        .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
        .disk_mode = MESH_GUEST_DISK_NONE,
        .service = {.machine = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true},
            .kernel = loop, .kernel_length = sizeof(loop), .binding = gct_s6_refused_binding}
    };
    config.service.limits = guest_limits_default();
    TEST("guest manager: disabled absent drives sleep without creating or running a guest") {
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        for (uint64_t now = 0; now < 3000; now += 1000) {
            struct guest_gov_decision decision;
            struct rvmachine_result result;
            struct guest_service_snapshot snapshot;
            ASSERT_EQ(mesh_guest_service_manager_drive(manager, now, 0, &decision, &result), RVMACHINE_OK);
            ASSERT_EQ(decision.kind, GUEST_GOV_SLEEP);
            ASSERT(decision.sleep_ms > 0);
            ASSERT(decision.sleep_ms <= GUEST_GOV_MAX_SLEEP_MS);
            ASSERT_EQ(decision.work, UINT64_C(0));
            ASSERT_EQ(result.retired, UINT64_C(0));
            ASSERT_EQ(result.fw_calls, UINT64_C(0));
            ASSERT_EQ(result.device_work, UINT64_C(0));
            ASSERT_EQ(mesh_guest_service_manager_instance(manager), UINT64_C(0));
            ASSERT(mesh_guest_service_manager_snapshot(manager, now, &snapshot));
            ASSERT_EQ(snapshot.state, GUEST_STATE_ABSENT);
            ASSERT(!snapshot.enabled);
        }
        PASS();
    }
_test_next:
    if (manager && !mesh_guest_service_manager_destroy(manager, 3000)) failures++;
    return failures;
}

static int gct_s6_factory_refused(void)
{
    int failures = 0;
    struct mesh_guest_service_manager *manager = NULL;
    static const uint8_t refused_image[64] = {0x7f, 'E', 'L', 'F', 2, 1, 1, [16] = 2, [18] = 62, [20] = 1};
    struct mesh_guest_service_launch_config config = {
        .policy = MESH_GUEST_LAUNCH_EPHEMERAL_FIXTURE,
        .disk_mode = MESH_GUEST_DISK_NONE,
        .service = {
            /* Valid resources; the actual loader refuses this non-RISC-V ELF. */
            .machine = {.ram_bytes = RVMACHINE_RAM_MIN, .wait_stops = true},
            .kernel = refused_image, .kernel_length = sizeof(refused_image),
            .binding = gct_s6_refused_binding
        }
    };
    config.service.limits = guest_limits_default();
    struct guest_service_snapshot snapshot;
    struct guest_action action;
    struct guest_event enable = {.kind = GUEST_EV_ENABLE, .enable = true};
    struct guest_event start = {.kind = GUEST_EV_OPERATOR_START};
    uint64_t now = 1000;
    TEST("guest manager: actual image factory refusal counts once without a guest or join") {
        gct_s6_refused_binding_calls = 0;
        ASSERT_EQ(rvmachine_config_resources_validate(&config.service.machine), RVMACHINE_OK);
        ASSERT(mesh_guest_service_manager_create(&manager, &config));
        ASSERT(mesh_guest_service_manager_event(manager, &enable, now, &action));
        for (unsigned attempt = 1; attempt <= 4; attempt++) {
            memset(&action, 0xa5, sizeof(action));
            ASSERT(mesh_guest_service_manager_event(manager, &start, now, &action));
            ASSERT(action.kind != GUEST_ACTION_START_GUEST);
            ASSERT(action.kind != GUEST_ACTION_STOP_GUEST);
            ASSERT_EQ(action.reason, GUEST_REASON_BOOT_FAILED);
            ASSERT_EQ(mesh_guest_service_manager_instance(manager), UINT64_C(0));
            ASSERT_EQ(gct_s6_refused_binding_calls, (size_t)0);
            ASSERT(mesh_guest_service_manager_snapshot(manager, now, &snapshot));
            ASSERT_EQ(snapshot.generation, attempt);
            ASSERT_EQ(snapshot.failures_in_hour, attempt < 4 ? attempt : 3u);
            ASSERT_EQ(snapshot.last_failure, GUEST_REASON_BOOT_FAILED);
            ASSERT_EQ(snapshot.ports, 0u); ASSERT_EQ(snapshot.sessions, 0u);
            if (attempt < 4) {
                uint64_t delay = guest_service_backoff_ms(attempt);
                ASSERT_EQ(snapshot.state, GUEST_STATE_ABSENT);
                ASSERT_EQ(snapshot.backoff_left_ms, delay);
                ASSERT(mesh_guest_service_manager_event(manager, &start, now + 1, &action));
                ASSERT_EQ(action.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
                ASSERT_EQ(action.reason, GUEST_REASON_BACKOFF);
                ASSERT_EQ(action.retry_after_ms, delay - 1);
                ASSERT(mesh_guest_service_manager_snapshot(manager, now + 1, &snapshot));
                ASSERT_EQ(snapshot.generation, attempt);
                ASSERT_EQ(snapshot.failures_in_hour, attempt);
                now += delay;
            } else {
                ASSERT_EQ(snapshot.state, GUEST_STATE_FAILED);
                ASSERT(mesh_guest_service_manager_event(manager, &start, now + 1, &action));
                ASSERT_EQ(action.kind, GUEST_ACTION_ANSWER_UNAVAILABLE);
                ASSERT_EQ(action.reason, GUEST_REASON_FAILED);
            }
        }
        /* Public callers cannot manufacture a join for the absent instance. */
        struct guest_event fabricated = {.kind = GUEST_EV_GUEST_STOPPED};
        ASSERT(!mesh_guest_service_manager_event(manager, &fabricated, now + 2, &action));
        ASSERT(mesh_guest_service_manager_snapshot(manager, now + 2, &snapshot));
        ASSERT_EQ(snapshot.state, GUEST_STATE_FAILED); ASSERT_EQ(snapshot.generation, 4u);
        ASSERT(mesh_guest_service_manager_destroy(manager, now + 3)); manager = NULL;
        PASS();
    }
_test_next:;
    if (manager && !mesh_guest_service_manager_destroy(manager, now + 3)) failures++;
    return failures;
}

static int gct_s6_runner_cpu_debit(void)
{
    int failures = 0;
    struct guest_service_runner *runner = NULL;
    static const uint8_t loop[] = {0x6f, 0, 0, 0};
    struct rvmachine_config config = {.ram_bytes = UINT64_C(64) << 20, .wait_stops = true};
    struct guest_limits limits = guest_limits_default();
    limits.slice_work = GUEST_GOV_SLICE_WORK_MIN;
    limits.max_slices_per_second = GUEST_GOV_SLICES_PER_SECOND_MAX;
    limits.duty_percent = 1; limits.window_ms = 1000; limits.short_budget_ms = 1;
    struct guest_gov_decision decision;
    struct rvmachine_result result;
    struct guest_service_runner_snapshot before, after;
    uint64_t owed_us = 0, charged_us = 0;
    bool disk_consumed = true, ceiling = false;
    TEST("guest runner: measured real run costs reach the duty ceiling before the slice rate ceiling") {
        ASSERT_EQ(guest_service_runner_create(&runner, &config, loop, sizeof(loop),
            &limits, &disk_consumed), RVMACHINE_OK);
        ASSERT(!disk_consumed);
        /* Controlled scheduler time keeps charges in one bucket. Invocation
         * costs come only from the real monotonic clock, rounded up to one us.
         * At most 1000 actual minimum-work runs precede the ceiling poll. */
        for (unsigned i = 0; i <= GUEST_GOV_SLICES_PER_SECOND_MAX; i++) {
            ASSERT(guest_service_runner_snapshot(runner, &before));
            ASSERT(before.accounting_pending == (owed_us != 0));
            ASSERT(charged_us <= UINT64_MAX - owed_us);
            charged_us += owed_us;
            struct timespec begin, end;
            ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &begin), 0);
            enum rvmachine_status status = guest_service_runner_slice(runner,
                1000, owed_us, false, &decision, &result);
            ASSERT_EQ(clock_gettime(CLOCK_MONOTONIC, &end), 0);
            ASSERT(guest_service_runner_snapshot(runner, &after));
            owed_us = 0;
            if (after.slices != before.slices) {
                if (end.tv_sec < begin.tv_sec ||
                    (end.tv_sec == begin.tv_sec && end.tv_nsec < begin.tv_nsec)) {
                    fprintf(stderr, "UNOBSERVED: real duty-charge clock reversed; pending charge retained\n");
                    failures++;
                    goto _test_next;
                }
                uint64_t seconds = (uint64_t)(end.tv_sec - begin.tv_sec);
                int64_t nanos = end.tv_nsec - begin.tv_nsec;
                if (nanos < 0) { seconds--; nanos += INT64_C(1000000000); }
                if (seconds > (UINT64_MAX - UINT64_C(1000000)) / UINT64_C(1000000)) {
                    fprintf(stderr, "UNOBSERVED: real duty-charge measurement unrepresentable; pending charge retained\n");
                    failures++;
                    goto _test_next;
                }
                owed_us = seconds * UINT64_C(1000000) + (uint64_t)nanos / 1000u +
                    ((uint64_t)nanos % 1000u != 0);
                if (!owed_us) owed_us = 1;
            }
            ASSERT_EQ(status, RVMACHINE_OK);
            if (charged_us >= 1000) {
                /* Dropping previous_us at the production governor call fails
                 * here before pending-state or shutdown checks can mask it. */
                ASSERT_EQ(decision.kind, GUEST_GOV_SLEEP);
                ASSERT_EQ(decision.reason, GUEST_SLEEP_DUTY_CEILING);
                ASSERT_EQ(decision.sleep_ms, UINT64_C(1000));
                ASSERT_EQ(decision.work, UINT64_C(0));
                ASSERT_EQ(after.slices, before.slices);
                ASSERT(!after.returned); ASSERT(!after.accounting_pending);
                ASSERT_EQ(owed_us, UINT64_C(0));
                ceiling = true; break;
            }
            ASSERT_EQ(decision.kind, GUEST_GOV_RUN_SLICE);
            ASSERT(after.returned); ASSERT(after.accounting_pending);
            ASSERT_EQ(after.slices, before.slices + 1);
            ASSERT(owed_us > 0);
        }
        ASSERT(ceiling);
        ASSERT_EQ(guest_service_runner_slice(runner, 1000, 0, false,
            &decision, &result), RVMACHINE_OK);
        ASSERT_EQ(decision.reason, GUEST_SLEEP_DUTY_CEILING);
        ASSERT_EQ(decision.sleep_ms, UINT64_C(1000));
        ASSERT(guest_service_runner_destroy(runner)); runner = NULL;
        PASS();
    }
_test_next:
    if (runner) {
        guest_service_runner_request_stop(runner);
        if (guest_service_runner_snapshot(runner, &after) && after.accounting_pending && owed_us)
            (void)guest_service_runner_slice(runner, 1000, owed_us, false, &decision, &result);
        if (!guest_service_runner_destroy(runner)) failures++;
    }
    return failures;
}

/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Actual linked durable APIs + real isolated private files, no source override,
 * provider/image/guest admission. Fixed PUBLIC metadata only, no key read/hash.
 * Insert before test_mesh_guest_chan; call three controls in registered group. */
struct gct_protected_files {
    char dir[256],volume_path[320],final[320],stage[6][320];
    struct platform_private_file volume,record;
    struct mesh_guest_protected_enrollment_operation op;
};
static void gct_protected_files_zero(struct gct_protected_files *f)
{
    memset(f,0,sizeof(*f));platform_private_file_init(&f->volume);platform_private_file_init(&f->record);
}
static bool gct_protected_files_init(struct gct_protected_files *f)
{
    gct_protected_files_zero(f);
    test_make_tmpdir(f->dir,sizeof f->dir,"mesh_guest_chan","protected-durable");
    if(!f->dir[0])return false;
    if(snprintf(f->volume_path,sizeof f->volume_path,"%s/volume",f->dir)<=0||
        snprintf(f->final,sizeof f->final,"%s/extension",f->dir)<=0)return false;
    for(size_t i=0;i<6;i++)if(snprintf(f->stage[i],sizeof f->stage[i],"%s/stage%zu",f->dir,i)<=0)return false;
    if(!platform_private_file_create_locked(f->volume_path,&f->volume)||
        !platform_private_file_truncate(&f->volume,512)||!platform_private_file_authority_flush(&f->volume))return false;
    struct platform_private_file_identity identity;
    if(!platform_private_file_identity(&f->volume,&identity))return false;
    f->op.volume=&f->volume;
    struct mesh_guest_enrollment_record *r=&f->op.expected;
    memset(r->guest_id,1,32);memset(r->kernel,2,32);memset(r->root,3,32);
    memset(r->helper,4,32);memset(r->profile,5,32);memset(r->owner_grant,6,32);
    r->generation=7;r->volume_device=identity.volume;r->volume_file=identity.file;r->volume_bytes=512;
    return true;
}
static void gct_protected_files_close(struct gct_protected_files *f)
{
    platform_private_file_close(&f->record);platform_private_file_close(&f->volume);
    if(f->dir[0])test_cleanup_tmpdir(f->dir);
}
static bool gct_protected_read_state(struct gct_protected_files *f,
    struct mesh_guest_protected_enrollment_extension *state)
{
    platform_private_file_close(&f->record);
    return mesh_guest_protected_enrollment_read_current(&f->op,f->final,&f->record,state);
}
static bool gct_protected_make_ready(struct gct_protected_files *f)
{
    uint8_t fingerprint[32];memset(fingerprint,0x31,sizeof fingerprint);
    if(!mesh_guest_protected_enrollment_initial(&f->op,f->final,f->stage[0],&f->record))return false;
    platform_private_file_close(&f->record);
    return mesh_guest_protected_enrollment_ready(&f->op,f->final,f->stage[1],fingerprint,&f->record);
}
static int gct_protected_initial_persistence(void)
{
    int failures=0;struct gct_protected_files f;gct_protected_files_zero(&f);
    TEST("protected durable API: INITIAL_ATTEMPTED real328 publication reopen and no-clobber refusal") {
        struct mesh_guest_protected_enrollment_extension state,decoded;
        struct mesh_guest_enrollment_record public_record;
        uint8_t before[328],after[328];uint64_t size=0;
        ASSERT(gct_protected_files_init(&f));
        ASSERT(mesh_guest_protected_enrollment_initial(&f.op,f.final,f.stage[0],&f.record));
        ASSERT(f.record.locked);ASSERT(!f.op.unknown);ASSERT(platform_private_path_absent(f.stage[0]));
        ASSERT(platform_private_file_size(&f.record,&size));ASSERT_EQ(size,328);
        ASSERT(platform_private_file_read_at(&f.record,before,sizeof before,0));
        ASSERT(mesh_guest_protected_enrollment_decode(before,sizeof before,&decoded));
        ASSERT_EQ(decoded.phase,MESH_GUEST_PROTECTED_INITIAL_ATTEMPTED);
        ASSERT_EQ(decoded.highest_reserved,1);ASSERT_EQ(decoded.revoked_through,0);
        ASSERT(mesh_guest_enrollment_equal(&decoded.enrollment,&f.op.expected));
        ASSERT(!mesh_guest_enrollment_read(&f.record,&public_record)); /* PUBLIC264 stays distinct. */
        ASSERT(gct_protected_read_state(&f,&state));
        ASSERT(mesh_guest_enrollment_equal(&state.enrollment,&decoded.enrollment));
        platform_private_file_close(&f.record);
        ASSERT(!mesh_guest_protected_enrollment_initial(&f.op,f.final,f.stage[1],&f.record));
        ASSERT(f.op.unknown);ASSERT(!f.record.locked);
        /* Reconstruct metadata owner, preserving actual held volume identity.
         * UNKNOWN old operation is not reset into authority or retried. */
        struct mesh_guest_protected_enrollment_operation fresh={.volume=&f.volume,.expected=decoded.enrollment};
        ASSERT(mesh_guest_protected_enrollment_read_current(&fresh,f.final,&f.record,&state));
        ASSERT(platform_private_file_read_at(&f.record,after,sizeof after,0));
        ASSERT(memcmp(before,after,sizeof before)==0);
        platform_private_file_close(&f.record);
        uint64_t reserved=99;
        ASSERT(!mesh_guest_protected_enrollment_reserve(&f.op,f.final,f.stage[2],&f.record,&reserved));
        ASSERT_EQ(reserved,0);ASSERT(platform_private_path_absent(f.stage[2]));PASS();
    } _test_next:;
    gct_protected_files_close(&f);return failures;
}
static int gct_protected_ready_persistence(void)
{
    int failures=0;struct gct_protected_files f;gct_protected_files_zero(&f);
    TEST("protected durable API: READY actual replace preserves tuple and adds only verified-public fingerprint") {
        struct mesh_guest_protected_enrollment_extension state,decoded;
        uint8_t wire[328],roundtrip[328];
        ASSERT(gct_protected_files_init(&f));
        struct mesh_guest_enrollment_record original=f.op.expected;
        ASSERT(gct_protected_make_ready(&f));
        ASSERT(f.record.locked);ASSERT(!f.op.unknown);ASSERT(platform_private_path_absent(f.stage[1]));
        ASSERT(gct_protected_read_state(&f,&state));
        ASSERT_EQ(state.phase,MESH_GUEST_PROTECTED_READY);ASSERT_EQ(state.highest_reserved,1);
        ASSERT_EQ(state.revoked_through,0);memset(original.ssh_fingerprint,0x31,32);
        ASSERT(mesh_guest_enrollment_equal(&state.enrollment,&original));
        ASSERT(mesh_guest_enrollment_equal(&f.op.expected,&original));
        ASSERT(platform_private_file_read_at(&f.record,wire,sizeof wire,0));
        ASSERT(mesh_guest_protected_enrollment_decode(wire,sizeof wire,&decoded));
        ASSERT(mesh_guest_protected_enrollment_encode(&decoded,roundtrip,sizeof roundtrip));
        ASSERT(memcmp(wire,roundtrip,sizeof wire)==0);
        ASSERT(!mesh_guest_protected_enrollment_decode(wire,sizeof wire-1,&decoded));
        roundtrip[12]^=1; /* Reserved framing byte: checksum also invalid, no invented acceptance. */
        ASSERT(!mesh_guest_protected_enrollment_decode(roundtrip,sizeof roundtrip,&decoded));
        PASS();
    } _test_next:;
    gct_protected_files_close(&f);return failures;
}
static int gct_protected_recovery_generations(void)
{
    int failures=0;struct gct_protected_files f;gct_protected_files_zero(&f);
    TEST("protected durable API: reconstructed RECOVER reserves R+1 and persists exact revocation floor") {
        struct mesh_guest_protected_enrollment_extension state;
        uint64_t reserved=0;
        ASSERT(gct_protected_files_init(&f));ASSERT(gct_protected_make_ready(&f));
        ASSERT(gct_protected_read_state(&f,&state));platform_private_file_close(&f.record);
        struct mesh_guest_protected_enrollment_operation recovery={.volume=&f.volume,.expected=state.enrollment};
        ASSERT(mesh_guest_protected_enrollment_reserve(&recovery,f.final,f.stage[2],&f.record,&reserved));
        ASSERT_EQ(reserved,2);platform_private_file_close(&f.record);
        /* A later failed/abandoned attempt does not roll back this successful
         * persisted reservation. Reconstruct next owner without a guest claim. */
        struct mesh_guest_protected_enrollment_operation next={.volume=&f.volume,.expected=state.enrollment};
        ASSERT(mesh_guest_protected_enrollment_read_current(&next,f.final,&f.record,&state));
        ASSERT_EQ(state.highest_reserved,2);ASSERT_EQ(state.phase,MESH_GUEST_PROTECTED_READY);
        platform_private_file_close(&f.record);
        ASSERT(mesh_guest_protected_enrollment_reserve(&next,f.final,f.stage[3],&f.record,&reserved));
        ASSERT_EQ(reserved,3);platform_private_file_close(&f.record);
        ASSERT(mesh_guest_protected_enrollment_revoke(&next,f.final,f.stage[4],3,&f.record));
        platform_private_file_close(&f.record);
        ASSERT(mesh_guest_protected_enrollment_read_current(&next,f.final,&f.record,&state));
        ASSERT_EQ(state.highest_reserved,3);ASSERT_EQ(state.revoked_through,3);
        ASSERT(mesh_guest_enrollment_equal(&state.enrollment,&next.expected));
        platform_private_file_close(&f.record);
        ASSERT(!mesh_guest_protected_enrollment_revoke(&next,f.final,f.stage[5],2,&f.record));
        ASSERT(next.unknown);ASSERT(platform_private_path_absent(f.stage[5]));
        ASSERT(!mesh_guest_protected_enrollment_reserve(&next,f.final,f.stage[5],&f.record,&reserved));
        ASSERT_EQ(reserved,0);PASS();
    } _test_next:;
    gct_protected_files_close(&f);return failures;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
static int gct_protected_trailing_record_refusal(void)
{
    int failures=0;struct gct_protected_files f;gct_protected_files_zero(&f);
    TEST("protected durable API: actual trailing byte refuses reservation without mutation or retry") {
        uint8_t before[329],after[329],extra=0x57;uint64_t reserved=99,size=0;
        ASSERT(gct_protected_files_init(&f));ASSERT(gct_protected_make_ready(&f));
        ASSERT(platform_private_file_write_at(&f.record,&extra,1,328));
        ASSERT(platform_private_file_authority_flush(&f.record));
        ASSERT(platform_private_file_read_at(&f.record,before,sizeof before,0));
        platform_private_file_close(&f.record);
        ASSERT(!mesh_guest_protected_enrollment_reserve(&f.op,f.final,f.stage[2],&f.record,&reserved));
        ASSERT(f.op.unknown);ASSERT_EQ(reserved,0);ASSERT(!f.record.locked);
        ASSERT(platform_private_path_absent(f.stage[2]));
        /* Observation of retained PUBLIC bytes is not reconstruction of grant
         * authority and does not clear this operation's sticky UNKNOWN. */
        ASSERT(platform_private_file_open_locked(f.final,&f.record));
        ASSERT(platform_private_file_size(&f.record,&size));ASSERT_EQ(size,329);
        ASSERT(platform_private_file_read_at(&f.record,after,sizeof after,0));
        ASSERT(memcmp(before,after,sizeof before)==0);
        platform_private_file_close(&f.record);
        reserved=99;
        ASSERT(!mesh_guest_protected_enrollment_reserve(&f.op,f.final,f.stage[3],&f.record,&reserved));
        ASSERT_EQ(reserved,0);ASSERT(f.op.unknown);ASSERT(!f.record.locked);
        ASSERT(platform_private_path_absent(f.stage[3]));PASS();
    } _test_next:;
    gct_protected_files_close(&f);return failures;
}
/* Explicit post-admission lifecycle model using a real tiny owned guest.
 * No protected image admission override, credential or provider delivery. */
static unsigned gct_protected_ready_invalidations;
static bool gct_protected_ready_grant(void *context,
    const struct mesh_guest_enrollment_record *record,uint64_t now)
{
    (void)context;(void)record;(void)now;return false;
}
static void gct_protected_ready_invalidate(void *context)
{
    (void)context;gct_protected_ready_invalidations++;
}
static int gct_protected_ready_authority(void)
{
    int failures=0;struct mesh_guest_service_manager *manager=NULL;
    struct mesh_guest_service_launch_config config=gct_resource_config();
    config.service.machine.ram_bytes=UINT64_C(64)<<20;
    TEST("protected readiness model: expired or revoked current grant never enables actual owned service") {
        for(unsigned expired=0;expired<2;expired++){
            struct guest_action action;
            ASSERT(gct_retry_manager_create(&manager,&config));
            ASSERT(gct_retry_manager_event(manager,&(struct guest_event){.kind=GUEST_EV_ENABLE,.enable=true},1000,&action));
            ASSERT(gct_retry_manager_event(manager,&(struct guest_event){.kind=GUEST_EV_OPERATOR_START},1000,&action));
            uint64_t instance=gct_retry_manager_instance(manager);ASSERT(instance!=0);
            /* Model only the already-admitted protected metadata boundary.
             * The actual public/off creation admission was not weakened. */
            manager->config.unlock.policy=MESH_GUEST_UNLOCK_PROTECTED_HOST;
            manager->unlock_delivered=true;
            manager->config.protected_admitted_ms=1;
            manager->config.protected_authority_expires_ms=expired?1:UINT64_MAX;
            manager->config.protected_enrollment.grant_current=gct_protected_ready_grant;
            manager->config.protected_enrollment.context=&gct_protected_ready_invalidations;
            manager->config.protected_invalidate=gct_protected_ready_invalidate;
            manager->config.protected_provider.context=&gct_protected_ready_invalidations;
            gct_protected_ready_invalidations=0;
            bool ready=gct_retry_manager_ready(manager,instance,1001,&action);
            bool was_ready=manager->lifecycle.state==GUEST_STATE_READY;
            unsigned invalidations=gct_protected_ready_invalidations;
            /* Always settle actual ownership, including the behavioral RED. */
            ASSERT(gct_retry_manager_destroy(manager,1002));manager=NULL;
            ASSERT(!ready);ASSERT(!was_ready);ASSERT(invalidations>0);
        }
        PASS();
    } _test_next:;
    if(manager&&!gct_retry_manager_destroy(manager,200000))failures++;
    return failures;
}
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Explicit post-admission lifecycle/resource model. Actual tiny runner/manager,
 * real private PUBLIC-metadata handles and existing currentness checks; no
 * protected image admission override, key/provider delivery or identity claim. */
struct gct_ready_deadline_grant {
    struct mesh_guest_enrollment_record expected;
    uint64_t after_ms;
    unsigned calls;
};
static bool gct_ready_deadline_current(void *context,
    const struct mesh_guest_enrollment_record *record,uint64_t now)
{
    struct gct_ready_deadline_grant *grant=context;
    if(!grant||!record||now!=1001||!mesh_guest_enrollment_equal(record,&grant->expected))return false;
    grant->calls++;
    /* Model time consumed by the currentness/readback interval. The production
     * READY observer must call the clock AFTER it, never accept this old now. */
    gct_protected_ready_clock_ms=(int64_t)grant->after_ms;
    return true;
}
static int gct_protected_ready_fresh_deadline(void)
{
    int failures=0;static struct mesh_guest_service_manager *manager;
    static struct gct_protected_files f;static struct gct_ready_deadline_grant grant;
    gct_protected_files_zero(&f);
    struct mesh_guest_service_launch_config config=gct_resource_config();
    config.service.machine.ram_bytes=UINT64_C(64)<<20;
    TEST("protected READY resource model: actual fresh clock enforces before/equal/after120s before any enable") {
        for(unsigned offset=0;offset<3;offset++){
            char credential_path[320];uint8_t public_bytes[32];memset(public_bytes,0x5a,sizeof public_bytes);
            ASSERT(gct_protected_files_init(&f));
            ASSERT(snprintf(credential_path,sizeof credential_path,"%s/credential",f.dir)>0);
            ASSERT(platform_private_file_create_locked(credential_path,&f.record));
            ASSERT(platform_private_file_write_at(&f.record,public_bytes,sizeof public_bytes,0));
            memory_cleanse(public_bytes,sizeof public_bytes);
            ASSERT(platform_private_file_authority_flush(&f.record));
            struct guest_action action;
            ASSERT(gct_retry_manager_create(&manager,&config));
            ASSERT(gct_retry_manager_event(manager,&(struct guest_event){.kind=GUEST_EV_ENABLE,.enable=true},1000,&action));
            ASSERT(gct_retry_manager_event(manager,&(struct guest_event){.kind=GUEST_EV_OPERATOR_START},1000,&action));
            uint64_t instance=gct_retry_manager_instance(manager);ASSERT(instance!=0);
            /* OFF creation is untouched. Only this explicitly modeled already-
             * admitted protected metadata boundary is supplied to READY. */
            manager->config.unlock.policy=MESH_GUEST_UNLOCK_PROTECTED_HOST;
            manager->unlock_delivered=true;
            manager->config.enrollment.volume=&f.volume;manager->config.enrollment.credential=&f.record;
            manager->config.enrollment.expected=f.op.expected;manager->enrollment=f.op.expected;
            struct platform_positioned_file view={.native=f.record.native};
            ASSERT(platform_positioned_file_snapshot(&view,&manager->credential));
            manager->config.protected_admitted_ms=1;manager->config.protected_authority_expires_ms=UINT64_MAX;
            grant=(struct gct_ready_deadline_grant){.expected=f.op.expected,
                .after_ms=1000+GUEST_SERVICE_START_DEADLINE_MS-1+offset};
            manager->config.protected_enrollment.grant_current=gct_ready_deadline_current;
            manager->config.protected_enrollment.context=&grant;
            manager->config.protected_invalidate=gct_protected_ready_invalidate;
            manager->config.protected_provider.context=&gct_protected_ready_invalidations;
            gct_protected_ready_clock_ms=1001;gct_protected_ready_clock_reads=0;
            gct_protected_ready_enable_calls=0;gct_protected_ready_clock_live=true;
            bool ready=gct_retry_manager_ready(manager,instance,1001,&action);
            bool was_ready=manager->lifecycle.state==GUEST_STATE_READY;
            unsigned enable_calls=gct_protected_ready_enable_calls,clock_reads=gct_protected_ready_clock_reads;
            unsigned grant_calls=grant.calls;
            gct_protected_ready_clock_live=false;
            /* Real destroy before result assertions, including born RED. */
            ASSERT(gct_retry_manager_destroy(manager,grant.after_ms+1));manager=NULL;
            gct_protected_files_close(&f);f.dir[0]=0;
            ASSERT_EQ(grant_calls,1);ASSERT(clock_reads>=1);
            ASSERT_EQ(ready,offset==0);ASSERT_EQ(was_ready,offset==0);
            ASSERT_EQ(enable_calls,offset==0?1:0);
            if(offset)ASSERT(clock_reads>=2);
        }
        PASS();
    } _test_next:;
    gct_protected_ready_clock_live=false;
    /* If actual destruction refuses, retain the whole static fixture custody;
     * never close borrowed descriptors or pretend the instance joined. */
    if(manager&&!gct_retry_manager_destroy(manager,200000))return failures+1;
    manager=NULL;gct_protected_files_close(&f);return failures;
}
int test_mesh_guest_chan(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mesh_guest_chan", "loopback");
    struct mesh_term_fixture f;
    bool fixture_open = false;

    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *a = NULL;
    struct p2p_node *b = NULL;
    struct p2p_node *nodes[2];
    struct send_segment *a_queue = NULL, *b_queue = NULL;
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    char *source = NULL;
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));

    TEST("guest chan: fixture, and the service is off by default: an OPEN is "
         "refused as unknown, enabling admits it, disabling ends the port "
         "with SHUTDOWN and releases the stream") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;
        zcl_mutex_init(&nm.cs_nodes);
        zcl_mutex_init(&nm.cs_last_node_id);
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        addr.svc.port = 18034;
        a = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "chan-a", false);
        b = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "chan-b", true);
        ASSERT(a && b);
        a->transport = f.term_peer.ini;
        b->transport = f.res_term;
        a->state = PEER_HANDSHAKE_COMPLETE;
        b->state = PEER_HANDSHAKE_COMPLETE;
        nodes[0] = a;
        nodes[1] = b;
        nm.nodes = nodes;
        nm.num_nodes = 2;
        a_queue = mesh_loop_sentinel(a);
        b_queue = mesh_loop_sentinel(b);
        ASSERT(a_queue && b_queue);
        mp.net_mgr = &nm;
        mp.params = chain_params_get();
        ASSERT(mp.params != NULL);
        svc.msg_processor = &mp;
        dbsvc.node_db = &f.ndb;
        dbsvc.started = true;
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);
        mesh_stream_test_bind(&svc);
        g_f = &f;
        g_a = a;
        g_b = b;
        g_aq = a_queue;
        g_bq = b_queue;
        g_mp = &mp;
        g_nm = &nm;

        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(!mesh_guest_chan_enabled());
        ASSERT(gct_open_hand(0));
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(w.close_reason, MESH_STREAM_REFUSED_SERVICE_UNKNOWN);
        ASSERT_EQ(fd.accept_calls, (size_t)0);

        fd_script(TOK0, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(mesh_guest_chan_enabled());
        ASSERT(gct_open_hand(2));
        ASSERT_EQ(fd.accept_calls, (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(GCT_NAME), (size_t)1);
        ASSERT_EQ(gct_stats().opened, (uint64_t)1);
        ASSERT(gct_data_hand(2, 0, 64));
        ASSERT_EQ(fd.rec_len, (size_t)64);

        ASSERT(mesh_guest_chan_set_enabled(false));
        ASSERT(!mesh_guest_chan_enabled());
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_SHUTDOWN);
        w = gct_take_b();
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(w.close_reason, MESH_STREAM_CLOSED_BY_SERVICE);
        /* Registered again, the table holds no stream of this service:
         * the slot was released, not left half-closed. */
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: a peer whose row lacks the guest-chan bit is refused "
         "before the device sees accept") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_STATUS_READ));
        fd_script(TOK0, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(gct_open_hand(0));
        ASSERT_EQ(fd.accept_calls, (size_t)0);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(w.close_reason, MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: revocation mid-stream delivers nothing to the device "
         "on the next data frame") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 100));
        ASSERT_EQ(fd.rec_len, (size_t)100);
        ASSERT(gct_revoke_last());
        size_t writes = fd.write_calls;
        size_t recorded = fd.rec_len;
        ASSERT(gct_data_hand(0, 100, 50));
        ASSERT_EQ(fd.write_calls, writes);
        ASSERT_EQ(fd.rec_len, recorded);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_REVOKED);
        ASSERT_EQ(gct_stats().ended_revoked, (uint64_t)1);
        ASSERT_EQ(gct_stats().bytes_to_guest, (uint64_t)100);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: revocation mid-stream sends nothing from the guest") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        uint8_t out[20];
        gct_pattern(out, 0, sizeof(out));
        /* Control: before the revoke the same bytes do cross. */
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, out, sizeof(out)),
                  sizeof(out));
        mesh_guest_chan_pump(GCT_NOW);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.datas, (size_t)1);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)20);
        ASSERT(gct_revoke_last());
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, out, sizeof(out)),
                  (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.datas, (size_t)0);
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)20);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_REVOKED);
        gct_end();
        PASS();
    }

    TEST("guest chan: revocation mid-stream grants nothing on drained") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 100));
        /* Control: before the revoke a drain report returns credit. */
        g_host->drained(g_hostctx, TOK0, 40);
        mesh_guest_chan_pump(GCT_NOW);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)1);
        ASSERT_EQ(w.window_total, (uint32_t)40);
        ASSERT(gct_revoke_last());
        g_host->drained(g_hostctx, TOK0, 60);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        ASSERT_EQ(w.window_total, (uint32_t)0);
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_REVOKED);
        gct_end();
        PASS();
    }

    TEST("guest chan: session loss ends the port with SESSION_LOST and the "
         "adapter never reopens") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 10));
        /* FRAME-LEVEL witness, not a session-level one. The harness cannot
         * produce a real peer session loss: the stream layer detects it in
         * its supervised tick (stream_pump_tick, static, needs the
         * supervisor), which this loopback does not run. So the session-lost
         * verdict is delivered as a hand-built CLOSE frame whose reason byte
         * is SESSION_LOST, which reaches the adapter's on_close exactly as
         * the tick's own close would. This proves the reason mapping, the
         * single device end, the release and the absence of a reopen; it
         * does not prove the tick detects a lost session. */
        ASSERT(gct_close_hand(0, MESH_STREAM_ENDED_SESSION_LOST));
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_SESSION_LOST);
        ASSERT_EQ(gct_streams(), (size_t)0);
        for (int i = 0; i < 3; i++)
            mesh_guest_chan_pump(GCT_NOW + i);
        ASSERT_EQ(fd.accept_calls, (size_t)1);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(gct_stats().opened, (uint64_t)1);
        ASSERT_EQ(gct_streams(), (size_t)0);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.opens, (size_t)0);
        ASSERT_EQ(w.datas, (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: a short write keeps one suffix, offers nothing more "
         "until writable, then re-offers it once with no loss") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(gct_open_hand(0));
        fd.take_limit = 10;
        ASSERT(gct_data_hand(0, 0, 100));
        ASSERT_EQ(fd.write_calls, (size_t)1);
        ASSERT_EQ(fd.last_write_n, (size_t)100);
        ASSERT_EQ(fd.rec_len, (size_t)10);
        ASSERT(gct_data_hand(0, 100, 50));
        ASSERT_EQ(fd.write_calls, (size_t)1);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.write_calls, (size_t)1);
        ASSERT_EQ(mesh_guest_chan_test_buffered(), (size_t)140);
        fd.take_limit = SIZE_MAX;
        g_host->writable(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.write_calls, (size_t)2);
        ASSERT_EQ(fd.last_write_n, (size_t)140);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.write_calls, (size_t)2);
        ASSERT_EQ(fd.rec_len, (size_t)150);
        gct_pattern(g_payload, 0, 150);
        ASSERT(memcmp(fd.rec, g_payload, 150) == 0);
        ASSERT_EQ(mesh_guest_chan_test_buffered(), (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: backpressure stops the sender at the window and drain "
         "reports return credit by exactly the drained amount") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(GCT_NAME, f.resp_noise_pub, GCT_WINDOW,
                                   NULL, 0, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b), (size_t)1);
        ASSERT_EQ(fd.accept_calls, (size_t)1);
        /* The device takes every byte and never reports drained. */
        uint8_t chunk[8192];
        for (size_t i = 0; i < GCT_WINDOW / sizeof(chunk); i++) {
            gct_pattern(chunk, i * sizeof(chunk), sizeof(chunk));
            ASSERT(gct_look(id, true, chunk, sizeof(chunk)).ok);
            ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                      (size_t)1);
            ASSERT(mesh_guest_chan_test_buffered() <= GUEST_CHAN_RUN_MAX);
        }
        ASSERT_EQ(fd.rec_len, (size_t)GCT_WINDOW);
        ASSERT_EQ(gct_look(id, true, NULL, 0).send_credit, (uint32_t)0);
        ASSERT(!gct_look(id, true, chunk, 1).ok);
        /* Writable and pump grant no credit by themselves. */
        g_host->writable(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        (void)mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a);
        ASSERT_EQ(gct_look(id, true, NULL, 0).send_credit, (uint32_t)0);
        /* Drained 1000 returns exactly 1000, then 4000 more. */
        g_host->drained(g_hostctx, TOK0, 1000);
        mesh_guest_chan_pump(GCT_NOW);
        (void)mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a);
        ASSERT_EQ(gct_look(id, true, NULL, 0).send_credit, (uint32_t)1000);
        g_host->drained(g_hostctx, TOK0, 4000);
        mesh_guest_chan_pump(GCT_NOW);
        (void)mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a);
        ASSERT_EQ(gct_look(id, true, NULL, 0).send_credit, (uint32_t)5000);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        gct_end();

        /* A device that takes nothing: the adapter holds at most one
         * frame, and the sender is still stopped at the window. */
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        fd.take_limit = 0;
        ASSERT(mesh_guest_chan_set_enabled(true));
        id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(GCT_NAME, f.resp_noise_pub, GCT_WINDOW,
                                   NULL, 0, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b), (size_t)1);
        for (size_t i = 0; i < GCT_WINDOW / sizeof(chunk); i++) {
            ASSERT(gct_look(id, true, chunk, sizeof(chunk)).ok);
            ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                      (size_t)1);
            ASSERT(mesh_guest_chan_test_buffered() <= GUEST_CHAN_RUN_MAX);
        }
        ASSERT_EQ(mesh_guest_chan_test_buffered(), (size_t)GCT_WINDOW);
        ASSERT_EQ(gct_look(id, true, NULL, 0).send_credit, (uint32_t)0);
        ASSERT_EQ(fd.rec_len, (size_t)0);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: no credit is granted while the aggregate buffered "
         "bytes exceed the pump bound") {
        struct mesh_guest_chan_limits lim;
        memset(&lim, 0, sizeof(lim));
        lim.pump_bytes_max = 100;
        ASSERT(gct_up(&lim, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 50));
        fd.take_limit = 0;
        ASSERT(gct_data_hand(0, 50, 300));
        ASSERT_EQ(mesh_guest_chan_test_buffered(), (size_t)300);
        g_host->drained(g_hostctx, TOK0, 50);
        mesh_guest_chan_pump(GCT_NOW);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        fd.take_limit = SIZE_MAX;
        g_host->writable(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)1);
        ASSERT_EQ(w.window_total, (uint32_t)50);
        gct_end();
        PASS();
    }

    TEST("guest chan: bounds refuse the third stream from one peer and the "
         "fifth in total") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        fd_script(TOK1, true);
        fd_script(TOK2, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(gct_open_hand(0));
        ASSERT(gct_open_hand(2));
        ASSERT_EQ(fd.accept_calls, (size_t)2);
        ASSERT(gct_open_hand(4));
        ASSERT_EQ(fd.accept_calls, (size_t)2);
        ASSERT_EQ(gct_stats().refused_bound, (uint64_t)1);
        ASSERT_EQ(gct_streams(), (size_t)2);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(w.close_reason, MESH_STREAM_REFUSED_CAP);
        gct_end();

        struct mesh_guest_chan_limits lim;
        memset(&lim, 0, sizeof(lim));
        lim.per_peer_max = 4;
        ASSERT(gct_begin(&lim, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        fd_script(TOK1, true);
        fd_script(TOK2, true);
        fd_script(TOK3, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        for (uint64_t i = 0; i < 4; i++)
            ASSERT(gct_open_hand(i * 2u));
        ASSERT_EQ(fd.accept_calls, (size_t)4);
        ASSERT(gct_open_hand(8));
        ASSERT_EQ(fd.accept_calls, (size_t)4);
        ASSERT_EQ(gct_stats().refused_bound, (uint64_t)1);
        ASSERT_EQ(gct_streams(), (size_t)4);
        gct_end();
        PASS();
    }

    TEST("guest chan: oversize runs, over-long writes and drain over-reports "
         "end the port with PROTOCOL and change no accounting") {
        /* from_guest above RUN_MAX. */
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        gct_pattern(g_payload, 0, GUEST_CHAN_RUN_MAX + 1u);
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, g_payload,
                                     GUEST_CHAN_RUN_MAX + 1u),
                  (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)1);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)0);
        gct_end();

        /* write returning n + 1. */
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd.take_over = true;
        ASSERT(gct_data_hand(0, 0, 10));
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(gct_stats().bytes_to_guest, (uint64_t)0);
        gct_end();

        /* drained above what was delivered: no clamp, no credit. */
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_data_hand(0, 0, 100));
        g_host->drained(g_hostctx, TOK0, 40);
        mesh_guest_chan_pump(GCT_NOW);
        struct gct_wire w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)1);
        ASSERT_EQ(w.window_total, (uint32_t)40);
        g_host->drained(g_hostctx, TOK0, 1000);
        mesh_guest_chan_pump(GCT_NOW);
        w = gct_take_b();
        ASSERT_EQ(w.windows, (size_t)0);
        ASSERT_EQ(w.closes, (size_t)1);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        gct_end();

        /* Invalid accept tokens: index 4, generation 0, a live token. */
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        struct guest_chan_port bad_index = {4, 1};
        struct guest_chan_port bad_gen = {1, 0};
        fd_script(bad_index, true);
        fd_script(bad_gen, true);
        fd_script(TOK0, true);
        /* The header says each of these ends the port with PROTOCOL: the
         * device is told, with the token it handed over. */
        ASSERT(gct_open_hand(2));
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(fd.last_end_port.index, (uint32_t)4);
        ASSERT(gct_open_hand(4));
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(fd.last_end_port.index, (uint32_t)1);
        ASSERT_EQ(fd.last_end_port.generation, (uint32_t)0);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)2);
        /* A live token is the same port: it is the live port that ends
         * (queued, settled by the pump), once. */
        ASSERT(gct_open_hand(6));
        ASSERT_EQ(fd.accept_calls, (size_t)4);
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(gct_stats().opened, (uint64_t)1);
        w = gct_take_b();
        ASSERT_EQ(w.closes, (size_t)3);
        ASSERT_EQ(w.close_reason, MESH_STREAM_REFUSED_UNAVAILABLE);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)3);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_PROTOCOL);
        ASSERT_EQ(fd.last_end_port.index, (uint32_t)0);
        ASSERT_EQ(fd.last_end_port.generation, (uint32_t)1);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)3);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: a stale token changes nothing and is counted") {
        ASSERT(gct_up(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        /* Port 0 generation 1 ends; the same index is reused as 2. */
        g_host->closed(g_hostctx, TOK0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_NORMAL);
        struct guest_chan_port fresh = {0, 2};
        fd_script(fresh, true);
        ASSERT(gct_open_hand(2));
        ASSERT_EQ(fd.accept_calls, (size_t)2);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)0);
        ASSERT(gct_data_hand(2, 0, 30));
        ASSERT_EQ(fd.rec_len, (size_t)30);

        uint8_t out[16] = {0};
        struct guest_chan_port never = {3, 5};
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK0, out, sizeof(out)),
                  (size_t)0);
        g_host->drained(g_hostctx, TOK0, 5);
        g_host->writable(g_hostctx, TOK0);
        g_host->closed(g_hostctx, TOK0);
        g_host->drained(g_hostctx, never, 5);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)5);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(gct_stats().ended_protocol, (uint64_t)0);
        ASSERT_EQ(gct_stats().bytes_from_guest, (uint64_t)0);
        ASSERT(gct_data_hand(2, 30, 30));
        ASSERT_EQ(fd.rec_len, (size_t)60);
        /* opened() with a token that cannot become live (index out of
         * range, generation 0, an index in use) is dropped and counted as
         * a drop; no other counter moves and no port is claimed. */
        {
            struct mesh_guest_chan_stats before = gct_stats();
            size_t streams = gct_streams();
            uint8_t far_peer[32];
            memset(far_peer, 0x66, sizeof(far_peer));
            struct guest_chan_port bad_index = {4, 1};
            struct guest_chan_port bad_gen = {1, 0};
            ASSERT(!g_host->opened(g_hostctx, bad_index, far_peer));
            ASSERT(!g_host->opened(g_hostctx, bad_gen, far_peer));
            ASSERT(!g_host->opened(g_hostctx, fresh, far_peer));
            struct mesh_guest_chan_stats after = gct_stats();
            ASSERT_EQ(after.stale_token_dropped,
                      before.stale_token_dropped + 3u);
            ASSERT_EQ(after.ended_protocol, before.ended_protocol);
            ASSERT_EQ(after.opened, before.opened);
            ASSERT_EQ(after.refused_bound, before.refused_bound);
            ASSERT_EQ(after.refused_disabled, before.refused_disabled);
            ASSERT_EQ(after.refused_unpaired, before.refused_unpaired);
            ASSERT_EQ(after.ended_revoked, before.ended_revoked);
            ASSERT_EQ(after.ended_idle, before.ended_idle);
            ASSERT_EQ(gct_streams(), streams);
            mesh_guest_chan_pump(GCT_NOW);
            ASSERT_EQ(fd.end_calls, (size_t)1);
        }
        /* The live generation still works. */
        ASSERT_EQ(g_host->from_guest(g_hostctx, fresh, out, sizeof(out)),
                  sizeof(out));
        gct_end();
        PASS();
    }

    TEST("guest chan: a port idle for exactly idle_seconds ends with IDLE, "
         "not a second earlier") {
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        fd_script(TOK0, true);
        ASSERT(mesh_guest_chan_set_enabled(true));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT(gct_open_hand(0));
        mesh_guest_chan_pump(GCT_NOW + 119);
        ASSERT_EQ(fd.end_calls, (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)1);
        mesh_guest_chan_pump(GCT_NOW + 120);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_IDLE);
        ASSERT_EQ(gct_stats().ended_idle, (uint64_t)1);
        ASSERT_EQ(gct_streams(), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: an outbound open with no session ends with "
         "UNAVAILABLE and does nothing else") {
        uint8_t far_peer[32];
        memset(far_peer, 0x77, sizeof(far_peer));
        ASSERT(gct_begin(NULL, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(gct_pair_for(far_peer, MESH_PAIRING_CAP_GUEST_CHAN));
        ASSERT(mesh_guest_chan_set_enabled(true));
        ASSERT(g_host->opened(g_hostctx, TOK2, far_peer));
        ASSERT_EQ(fd.end_calls, (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_UNAVAILABLE);
        ASSERT_EQ(fd.accept_calls, (size_t)0);
        ASSERT_EQ(fd.write_calls, (size_t)0);
        ASSERT_EQ(mesh_stream_test_live_count(GCT_NAME), (size_t)0);
        ASSERT_EQ(gct_streams(), (size_t)0);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b), (size_t)0);
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)1);
        /* The token is stale now. */
        uint8_t out[4] = {0};
        ASSERT_EQ(g_host->from_guest(g_hostctx, TOK2, out, sizeof(out)),
                  (size_t)0);
        ASSERT_EQ(gct_stats().stale_token_dropped, (uint64_t)1);
        /* A peer with no row is refused before any open is tried. */
        uint8_t stranger[32];
        memset(stranger, 0x55, sizeof(stranger));
        ASSERT(g_host->opened(g_hostctx, TOK3, stranger));
        mesh_guest_chan_pump(GCT_NOW);
        ASSERT_EQ(fd.end_calls, (size_t)2);
        ASSERT_EQ(fd.last_end, GUEST_CHAN_END_UNAVAILABLE);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b), (size_t)0);
        gct_end();
        PASS();
    }

    TEST("guest chan: the adapter source calls no socket, process or file "
         "function (scanner self-check, then the source)") {
        /* The scanner itself: what it must catch and what it must allow. */
        ASSERT(gct_scan_hits("int x = socket(1, 2, 3);"));
        ASSERT(gct_scan_hits("accept (fd, 0, 0);"));
        ASSERT(gct_scan_hits("pid_t p = fork();"));
        ASSERT(gct_scan_hits("execve(a, b, c);"));
        ASSERT(gct_scan_hits("FILE *f = fopen(\"x\", \"r\");"));
        ASSERT(gct_scan_hits("fd = open(path, 0);"));
        ASSERT(!gct_scan_hits("ok = g.ops.accept(g.dev, &tok);"));
        ASSERT(!gct_scan_hits("ok = ops->accept(dev, &tok);"));
        ASSERT(!gct_scan_hits("/* socket(1) and accept(2) in a comment */"));
        ASSERT(!gct_scan_hits("// connect(x)\nint y;"));
        ASSERT(!gct_scan_hits("puts(\"socket(\");"));
        ASSERT(!gct_scan_hits("r = mesh_stream_open(a, b);"));
        source = gct_read_source();
        ASSERT(source != NULL);
        char ident[64];
        const char *hit = gct_find_forbidden(source, ident, sizeof(ident));
        if (hit)
            printf("forbidden call `%s(`\n", hit);
        ASSERT(hit == NULL);
        PASS();
    }

    TEST("guest chan: pairing capability bit 8 validates, bit 4 stays "
         "reserved, and allows grades revoked and expired rows") {
        ASSERT_EQ(MESH_PAIRING_CAP_GUEST_CHAN, UINT64_C(8));
        ASSERT_EQ(MESH_PAIRING_CAP_KNOWN, UINT64_C(11));
        struct db_mesh_pairing row;
        memset(&row, 0, sizeof(row));
        memset(row.network_genesis, 1, 32);
        memset(row.peer_master_pubkey, 2, 32);
        memset(row.peer_noise_pubkey, 3, 32);
        ASSERT(mesh_pairing_id_derive(row.network_genesis,
                                      row.peer_master_pubkey,
                                      row.peer_noise_pubkey, row.pairing_id));
        row.delegation_sequence = 1;
        row.paired_at = 1000;
        row.expires_at = 5000;
        struct ar_errors errors;
        row.capability_mask = MESH_PAIRING_CAP_GUEST_CHAN;
        ASSERT(db_mesh_pairing_validate(&row, &errors));
        row.capability_mask = MESH_PAIRING_CAP_STATUS_READ |
                              MESH_PAIRING_CAP_TERMINAL_EXEC |
                              MESH_PAIRING_CAP_GUEST_CHAN;
        ASSERT(db_mesh_pairing_validate(&row, &errors));
        row.capability_mask = UINT64_C(4);
        ASSERT(!db_mesh_pairing_validate(&row, &errors));
        row.capability_mask = UINT64_C(4) | MESH_PAIRING_CAP_GUEST_CHAN;
        ASSERT(!db_mesh_pairing_validate(&row, &errors));

        row.capability_mask = MESH_PAIRING_CAP_GUEST_CHAN;
        ASSERT(mesh_pairing_allows(&row, MESH_PAIRING_CAP_GUEST_CHAN, 2000));
        ASSERT(!mesh_pairing_allows(&row, UINT64_C(4), 2000));
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_STATUS_READ, 2000));
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_GUEST_CHAN, 5000));
        row.revoked_at = 3000;
        row.revocation_generation = 1;
        ASSERT(!mesh_pairing_allows(&row, MESH_PAIRING_CAP_GUEST_CHAN, 2000));
        PASS();
    }

    failures += gct_case_outbound_happy();
    failures += gct_case_outbound_unauthorised();
    failures += gct_case_grant_failure();
    failures += gct_case_revoke_in_callback();
    failures += gct_case_close_mapping();
    failures += gct_case_end_reason_order();
    failures += gct_case_peer_attach_v2();
    failures += gct_case_peer_attach_v2_refusal();
    failures += gct_case_peer_attach_v2_opaque_refusal();
    failures += gct_case_peer_attach_v2_revoke();
    failures += gct_s6_launch_preflight_refused();
    failures += gct_s6_resource_ram_preflight();
    failures += gct_enrollment_missing_recovery();
    failures += gct_unlock_missing_admission();
    failures += gct_public_owner_admission();
    failures += gct_public_v3_tuple_controls();
    failures += gct_public_v3_mixed_controls();
    failures += gct_public_paired_tuple_controls();
    failures += gct_public_paired_mixed_controls();
    failures += gct_public_combined_tuple_controls();
    failures += gct_public_combined_mixed_controls();
    failures += gct_enrollment_owner_lifecycle();
    failures += gct_protected_initial_persistence();
    failures += gct_protected_ready_persistence();
    failures += gct_protected_recovery_generations();
    failures += gct_protected_trailing_record_refusal();
    failures += gct_s6_ready_deadline();
    failures += gct_protected_ready_authority();
    failures += gct_protected_ready_fresh_deadline();
    failures += gct_s6_resource_bootargs_preflight();
    failures += gct_s6_resource_valid_staging();
    failures += gct_s6_disabled_sleep();
    failures += gct_s6_stopping_clock_retry();
    failures += gct_s6_factory_refused();
    failures += gct_s6_runner_accounting(false);
    failures += gct_s6_runner_accounting(true);
    failures += gct_s6_runner_cpu_debit();
    failures += gct_s6_factory_suite();
    failures += gct_case_pairing_cliff();

_test_next:
    free(source);
    mesh_guest_chan_detach();
    mesh_stream_test_reset();
    mesh_stream_service_unregister(GCT_NAME);
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    if (a) {
        mesh_loop_free_queue(a, a_queue);
        p2p_node_free(a);
    }
    if (b) {
        mesh_loop_free_queue(b, b_queue);
        p2p_node_free(b);
    }
    free(a_queue);
    free(b_queue);
    if (nm.nodes) {
        zcl_mutex_destroy(&nm.cs_nodes);
        zcl_mutex_destroy(&nm.cs_last_node_id);
    }
    if (fixture_open)
        mesh_term_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
