/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for board-carried agent mail
 * (tools/command/native_devagent_boardmail.c and its seams in
 * native_devagent_receive.c, native_devagent_mail.c, native_fleet_steer.c):
 * a directive sent on one box reaches another over the signed FLEET board,
 * becomes queued work there exactly once, and a modeled worker result returns.
 * This fixture models RPC and carriage; it does not execute a worker.
 *
 * Two boxes, one process: isolated state roots (XDG_STATE_HOME switched per
 * step), each with mail dir, queue, steer grants, receiver cursors and a
 * roster sealed by one operator key. Each box's node is an in-process model
 * of the `fleet_board` RPC (post, fleet_page, show) via the rpc client test
 * hook; carriage between nodes is an explicit copy by id.
 *
 * Cases: the A->B->answer->A round trip; re-gossip and re-read deliver once;
 * a crash between export and import delivers once; forged inbox line
 * MISMATCH; wrong signer UNENROLLED/UNGRANTED; partial board fields
 * UNSIGNED; expired post never delivered; unanswered node defers; an
 * oversized directive is refused at send. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "base/hex.h"
#include "base/log_level.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

int test_devagent_boardmail(void);
void zcl_devagent_boardmail_test_io(int (*hook)(const char *, int));

#if !defined(_WIN32)

#define BMX_A 0
#define BMX_B 1
#define BMX_POSTS 64
#define BMX_TEXT 2200

/* ── the two boxes' state roots ────────────────────────────────────────── */

static char g_bmx_base[1024];
static char g_bmx_state[2][1200];
static char g_bmx_ws[1200];
static char g_bmx_saved_xdg[4096];
static bool g_bmx_had_xdg;
static const char *const g_bmx_name[2] = {"node-a", "node-b"};

static void bmx_use(int box)
{
    setenv("XDG_STATE_HOME", g_bmx_state[box], 1);
}

/* ── one board node per box: the fleet_board RPC, modelled ─────────────── */

struct bmx_post {
    char id[65];
    uint8_t signature[64];
    char host[65];
    char text[BMX_TEXT];
    char agent[80];
    char receipt[FLEET_BOARD_RECEIPT_MAX + 1];
    long long created, ttl, arrival;
    /* The post call's `push_to` delivery hint, as the exporter sent it ("-"
     * when it sent none). Recorded beside the post, never part of its id:
     * the hint is not signed. */
    char push_to[80];
};

enum bmx_page_fault {
    BMX_PAGE_OK, BMX_PAGE_MISSING_POSTS, BMX_PAGE_WRONG_POSTS,
    BMX_PAGE_MISSING_EPOCH, BMX_PAGE_MISSING_SCANNED, BMX_PAGE_BAD_EPOCH,
    BMX_PAGE_BAD_SCANNED, BMX_PAGE_NEGATIVE_SCANNED, BMX_PAGE_SHORT_RETURN,
    BMX_PAGE_BACKWARD, BMX_PAGE_STALLED, BMX_PAGE_EMPTY_ADVANCE
};

struct bmx_node {
    struct bmx_post p[BMX_POSTS];
    size_t n;
    long long next_arrival;
    unsigned post_calls, page_calls;
    char epoch[33];
    bool down;      /* no node answers at all */
    bool refuse;    /* fleet_page returns a typed refusal */
    bool show_down; /* the node answers everything but show */
    enum bmx_page_fault page_fault; /* malformed successful fleet_page response */
};

static struct bmx_node g_bmx_node[2];
static int g_bmx_active;
static struct {
    bool enabled;
    char ack[65], result[65];
    unsigned zero_pages, ack_seen, result_seen;
} g_bmx_replay;
static int g_bmx_io_phase = -1;
static bool g_bmx_ref_fault;

static int bmx_io_fault(const char *path, int phase)
{
    if (phase == g_bmx_io_phase && strstr(path, g_bmx_ref_fault ? "boardmail.refs" : "inbox.node-a.jsonl")) {
        g_bmx_io_phase = -1;
        return -1;
    }
    return 0;
}

/* The three signing keys: A's node, B's node, and a third enrolled box C
 * that nobody granted anything to. */
static char g_bmx_host[4][65];

static void bmx_key(uint8_t byte, uint8_t seed[32], uint8_t pub[32])
{
    uint8_t secret[32];
    memset(seed, byte, 32);
    ed25519_keypair(pub, secret, seed);
    memset(secret, 0, sizeof(secret));
}

static void bmx_hex(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = '\0';
}

/* Reconstruct the signed fields from the modeled RPC record. */
static bool bmx_post_wire(const struct bmx_post *p,
                          struct fleet_board_post *wire)
{
    size_t agent_len = strlen(p->agent), receipt_len = strlen(p->receipt);
    size_t text_len = strlen(p->text);
    if (agent_len >= sizeof(wire->agent) || receipt_len >= sizeof(wire->receipt) ||
        text_len > FLEET_BOARD_TEXT_MAX || p->created < 0 || p->ttl < 0 ||
        (unsigned long long)p->ttl > UINT32_MAX)
        return false;
    memset(wire, 0, sizeof(*wire));
    if (!zcl_hex_decode(p->host, wire->host_pubkey, sizeof(wire->host_pubkey)) ||
        !zcl_hex_decode(p->id, wire->id, sizeof(wire->id)))
        return false;
    wire->kind = FLEET_BOARD_KIND_NOTE;
    wire->scope = FLEET_BOARD_SCOPE_FLEET;
    wire->created_at = (uint64_t)p->created;
    wire->ttl = (uint32_t)p->ttl;
    memcpy(wire->agent, p->agent, agent_len + 1);
    memcpy(wire->receipt, p->receipt, receipt_len + 1);
    memcpy(wire->text, p->text, text_len + 1);
    wire->text_len = (uint32_t)text_len;
    memcpy(wire->signature, p->signature, sizeof(wire->signature));
    return true;
}

static bool bmx_sign(struct bmx_post *p, int host)
{
    struct fleet_board_post wire;
    uint8_t seed[32], pub[32];
    /* The ID is filled by the signer; use a zero placeholder initially. */
    if (!p->id[0]) memset(p->id, '0', 64);
    if (!bmx_post_wire(p, &wire)) return false;
    bmx_key((uint8_t)(0x61 + host), seed, pub);
    if (fleet_board_post_sign(&wire, seed, pub) != FLEET_BOARD_OK)
        return false;
    memcpy(p->signature, wire.signature, sizeof(p->signature));
    bmx_hex(wire.id, sizeof(wire.id), p->id);
    return true;
}

/* Verify the modeled record's identity and signed payload independently. */
static bool bmx_verified_result(const struct bmx_post *p)
{
    struct fleet_board_post wire;
    struct json_value row;
    uint8_t computed[32];
    if (strcmp(p->host, g_bmx_host[BMX_B]) || !bmx_post_wire(p, &wire) ||
        fleet_board_post_compute_id(&wire, computed) != FLEET_BOARD_OK ||
        memcmp(computed, wire.id, sizeof(computed)) != 0 ||
        fleet_board_post_verify(&wire) != FLEET_BOARD_OK)
        return false;
    json_init(&row);
    bool ok = json_read(&row, p->text, strlen(p->text)) &&
        strcmp(json_get_str(json_get(&row, "ref")), "job-1") == 0 &&
        strcmp(json_get_str(json_get(&row, "kind")), "result") == 0 &&
        strcmp(json_get_str(json_get(&row, "body")),
               "worker=node-b\nstate=done\nverdict=pass\n") == 0;
    json_free(&row);
    if (!ok) return false;
    wire.text[0] ^= 1;
    return fleet_board_post_verify(&wire) != FLEET_BOARD_OK;
}

static struct bmx_post *bmx_find(struct bmx_node *n, const char *id)
{
    for (size_t i = 0; i < n->n; i++) {
        if (strcmp(n->p[i].id, id) == 0)
            return &n->p[i];
    }
    return NULL;
}

/* Store one post on `node` unless its id is already held (the board's
 * known-id no-op). Returns the stored or already-held post. */
static struct bmx_post *bmx_store(int node, const struct bmx_post *in)
{
    struct bmx_node *n = &g_bmx_node[node];
    struct bmx_post *have = bmx_find(n, in->id);
    if (have || n->n >= BMX_POSTS)
        return have;
    n->p[n->n] = *in;
    n->p[n->n].arrival = ++n->next_arrival;
    return &n->p[n->n++];
}

/* A post signed by `host` placed straight on `node`, as a paired pull
 * would leave it. */
static struct bmx_post *bmx_inject(int node, int host, const char *text,
                                   long long created, long long ttl)
{
    struct bmx_post p;
    if (!text || strlen(text) > FLEET_BOARD_TEXT_MAX) return NULL;
    memset(&p, 0, sizeof(p));
    (void)snprintf(p.host, sizeof(p.host), "%s", g_bmx_host[host]);
    (void)snprintf(p.text, sizeof(p.text), "%s", text);
    (void)snprintf(p.receipt, sizeof(p.receipt), "z23.mail.v1");
    p.created = created;
    p.ttl = ttl;
    if (!bmx_sign(&p, host)) return NULL;
    return bmx_store(node, &p);
}

/* A fixture stamp `seconds` before a caller-supplied wall-clock reading. */
static long long bmx_stamp_before(long long base, long long seconds)
{
    return base - seconds;
}

/* What the paired fleet pull does between two boxes: every post one node
 * holds and the other does not, copied by id. */
static void bmx_carry(int from, int to)
{
    for (size_t i = 0; i < g_bmx_node[from].n; i++)
        (void)bmx_store(to, &g_bmx_node[from].p[i]);
}

/* Posts on `node` signed by `host`'s node key. */
static long long bmx_signed_by(int node, int host)
{
    long long hits = 0;
    for (size_t i = 0; i < g_bmx_node[node].n; i++)
        hits += strcmp(g_bmx_node[node].p[i].host, g_bmx_host[host]) == 0;
    return hits;
}

static void bmx_render(struct json_value *o, const struct bmx_post *p)
{
    (void)json_push_kv_str(o, "id", p->id);
    (void)json_push_kv_str(o, "kind", "note");
    (void)json_push_kv_int(o, "created_at", p->created);
    (void)json_push_kv_int(o, "ttl", p->ttl);
    (void)json_push_kv_int(o, "expires_at", p->created + p->ttl);
    (void)json_push_kv_str(o, "host", p->host);
    (void)json_push_kv_str(o, "agent", p->agent);
    (void)json_push_kv_str(o, "scope", "fleet");
    (void)json_push_kv_str(o, "text", p->text);
    (void)json_push_kv_str(o, "receipt", p->receipt);
    (void)json_push_kv_int(o, "arrival", p->arrival);
}

static void bmx_refuse(struct json_value *out, const char *code)
{
    (void)json_push_kv_bool(out, "ok", false);
    (void)json_push_kv_str(out, "code", code);
}

static void bmx_op_post(const struct json_value *in, struct json_value *out,
                        long long now)
{
    struct bmx_post p, *stored;
    const char *text = json_get_str(json_get(in, "text"));
    const char *agent = json_get_str(json_get(in, "agent"));
    const char *receipt = json_get_str(json_get(in, "receipt"));
    memset(&p, 0, sizeof(p));
    p.created = json_get_int(json_get(in, "created_at"));
    p.ttl = json_get_int(json_get(in, "ttl"));
    if (!text || strlen(text) > FLEET_BOARD_TEXT_MAX) {
        bmx_refuse(out, "TEXT_TOO_LONG");
        return;
    }
    if (!agent || !receipt || strlen(agent) > FLEET_BOARD_AGENT_MAX ||
        strlen(receipt) > FLEET_BOARD_RECEIPT_MAX) {
        bmx_refuse(out, "BOARD_REFUSED");
        return;
    }
    if (p.created + p.ttl <= now) {
        bmx_refuse(out, "CREATED_AT_EXPIRED");
        return;
    }
    (void)snprintf(p.host, sizeof(p.host), "%s", g_bmx_host[g_bmx_active]);
    (void)snprintf(p.text, sizeof(p.text), "%s", text);
    (void)snprintf(p.agent, sizeof(p.agent), "%s",
                   agent);
    (void)snprintf(p.receipt, sizeof(p.receipt), "%s",
                   receipt);
    if (!bmx_sign(&p, g_bmx_active)) {
        bmx_refuse(out, "BOARD_REFUSED");
        return;
    }
    const struct json_value *hint = json_get(in, "push_to");
    (void)snprintf(p.push_to, sizeof(p.push_to), "%s",
                   hint ? json_get_str(hint) : "-");
    stored = bmx_store(g_bmx_active, &p);
    if (!stored) {
        bmx_refuse(out, "BOARD_REFUSED");
        return;
    }
    (void)json_push_kv_bool(out, "ok", true);
    (void)json_push_kv_str(out, "id", stored->id);
}

static void bmx_bad_page(struct bmx_node *n, struct json_value *out, long long after)
{
    struct json_value posts, item;
    (void)json_push_kv_bool(out, "ok", true);
    if (n->page_fault == BMX_PAGE_WRONG_POSTS) {
        (void)json_push_kv_str(out, "posts", "not an array");
    } else if (n->page_fault != BMX_PAGE_MISSING_POSTS) {
        json_init(&posts); json_set_array(&posts);
        if (n->page_fault == BMX_PAGE_STALLED && n->n) {
            json_init(&item); json_set_object(&item);
            bmx_render(&item, &n->p[0]);
            (void)json_push_back(&posts, &item); json_free(&item);
        }
        (void)json_push_kv(out, "posts", &posts); json_free(&posts);
    }
    if (n->page_fault != BMX_PAGE_MISSING_EPOCH) {
        const char *epoch = n->epoch;
        if (n->page_fault == BMX_PAGE_WRONG_POSTS)
            epoch = "00000000000000000000000000000003";
        if (n->page_fault == BMX_PAGE_BAD_EPOCH) epoch = "invalid";
        (void)json_push_kv_str(out, "epoch", epoch);
    }
    if (n->page_fault == BMX_PAGE_SHORT_RETURN)
        (void)json_push_kv_int(out, "returned", 1);
    switch (n->page_fault) {
    case BMX_PAGE_MISSING_SCANNED: break;
    case BMX_PAGE_BAD_SCANNED: (void)json_push_kv_bool(out, "scanned", true); break;
    case BMX_PAGE_NEGATIVE_SCANNED: (void)json_push_kv_int(out, "scanned", -1); break;
    case BMX_PAGE_BACKWARD: (void)json_push_kv_int(out, "scanned", 0); break;
    case BMX_PAGE_STALLED: (void)json_push_kv_int(out, "scanned", after); break;
    case BMX_PAGE_EMPTY_ADVANCE: (void)json_push_kv_int(out, "scanned", after + 1); break;
    default: (void)json_push_kv_int(out, "scanned", 1); break;
    }
}

static void bmx_op_page(const struct json_value *in, struct json_value *out,
                        long long now)
{
    struct bmx_node *n = &g_bmx_node[g_bmx_active];
    long long after = json_get_int(json_get(in, "after"));
    if (n->page_fault != BMX_PAGE_OK) {
        bmx_bad_page(n, out, after);
        return;
    }
    long long limit = json_get_int(json_get(in, "limit"));
    long long scanned = after;
    bool trace = g_bmx_replay.enabled && g_bmx_active == BMX_A && after == 0;
    if (trace) g_bmx_replay.zero_pages++;
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n->n && (long long)json_size(&arr) < limit; i++) {
        const struct bmx_post *p = &n->p[i];
        if (p->arrival <= after || p->created + p->ttl <= now)
            continue;
        json_init(&item);
        json_set_object(&item);
        bmx_render(&item, p);
        bool pushed = json_push_back(&arr, &item);
        if (trace && pushed) {
            if (strcmp(p->id, g_bmx_replay.ack) == 0) g_bmx_replay.ack_seen++;
            if (strcmp(p->id, g_bmx_replay.result) == 0) g_bmx_replay.result_seen++;
        }
        json_free(&item);
        scanned = p->arrival;
    }
    (void)json_push_kv_bool(out, "ok", true);
    (void)json_push_kv(out, "posts", &arr);
    json_free(&arr);
    (void)json_push_kv_int(out, "scanned", scanned);
    (void)json_push_kv_str(out, "epoch", n->epoch);
}

static void bmx_op_show(const struct json_value *in, struct json_value *out)
{
    struct bmx_post *p = bmx_find(&g_bmx_node[g_bmx_active],
                                  json_get_str(json_get(in, "id")));
    if (!p) {
        bmx_refuse(out, "NOT_FOUND");
        return;
    }
    (void)json_push_kv_bool(out, "ok", true);
    bmx_render(out, p);
}

static char *bmx_rpc(const char *method, const char *params)
{
    struct json_value arr, out;
    const struct json_value *in;
    const char *op;
    long long now = (long long)platform_time_wall_time_t();
    struct bmx_node *n = &g_bmx_node[g_bmx_active];
    char *wire = NULL;
    size_t len;
    json_init(&arr);
    json_init(&out);
    json_set_object(&out);
    op = "";
    if (strcmp(method, "fleet_board") == 0 &&
        json_read(&arr, params, strlen(params)) && json_size(&arr) == 1) {
        in = json_at(&arr, 0);
        op = json_get_str(json_get(in, "op"));
        if (n->down || (n->show_down && strcmp(op, "show") == 0))
            op = "";
        else if (n->refuse && strcmp(op, "fleet_page") == 0)
            bmx_refuse(&out, "TEST_REFUSED");
        else if (strcmp(op, "post") == 0) {
            n->post_calls++;
            bmx_op_post(in, &out, now);
        } else if (strcmp(op, "fleet_page") == 0) {
            n->page_calls++;
            bmx_op_page(in, &out, now);
        }
        else if (strcmp(op, "show") == 0)
            bmx_op_show(in, &out);
    }
    if (!op[0]) {
        json_free(&out);
        json_init(&out);
        json_set_object(&out);
        (void)json_push_kv_str(&out, "error", "connection refused");
    }
    len = json_write(&out, NULL, 0);
    wire = malloc(len + 1);
    if (wire)
        (void)json_write(&out, wire, len + 1);
    json_free(&arr);
    json_free(&out);
    return wire;
}

/* ── the fleet roster both boxes hold ──────────────────────────────────── */

#define BMX_OP_BYTE 0x51
#define BMX_NOW 1790000000LL

/* One operator-sealed roster line for `name`: box key from `box_byte`,
 * signing (node) key from `signer_byte`, or no signing key when zero. */
static bool bmx_roster_line(const char *name, uint8_t box_byte,
                            uint8_t signer_byte, uint16_t port, char *out,
                            size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_signing_key signer;
    struct fleet_box_facts facts;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    memset(&facts, 0, sizeof(facts));
    (void)snprintf(facts.os, sizeof(facts.os), "Linux");
    bmx_key(BMX_OP_BYTE, op_seed, op_pub);
    bmx_key(box_byte, box_seed, box_pub);
    if (signer_byte) bmx_key(signer_byte, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, 24, "", op_seed, op_pub, BMX_NOW, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire,
                              sizeof(invite_wire), &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                              box_seed, box_pub, signer_byte ? &signer : NULL, receipt,
                              sizeof(receipt), &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof(receipt_wire), &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, BMX_NOW, port,
                              op_seed, op_pub, out, cap, &why);
}

/* Both boxes trust the operator and hold the same three roster lines:
 * node-a and node-b, and node-c, enrolled but granted nothing. */
static bool bmx_roster(int box)
{
    static const char *const names[3] = {"node-a", "node-b", "node-c"};
    uint8_t op_seed[32], op_pub[32];
    char line[FLEET_ENROL_MACHINE_TEXT_MAX];
    const char *why = NULL;
    bmx_use(box);
    bmx_key(BMX_OP_BYTE, op_seed, op_pub);
    if (!fleet_enrol_operator_write(op_pub, &why))
        return false;
    for (int i = 0; i < 3; i++) {
        if (!bmx_roster_line(names[i], (uint8_t)(0x41 + i),
                             (uint8_t)(0x61 + i),
                             (uint16_t)(FLEET_ENROL_PORT_FIRST + i), line,
                             sizeof(line)) ||
            !fleet_roster_append(line, &why))
            return false;
    }
    return true;
}

/* ── one in-process leaf call ──────────────────────────────────────────── */

struct bmx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void bmx_begin(struct bmx_call *c, const char *path,
                      const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    c->request.view = "normal";
    zcl_command_reply_init(&c->reply, schema);
}

static void bmx_end(struct bmx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool bmx_ok(const struct bmx_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* Mint one steer grant on the current box; `peer` NULL mints a local one. */
static bool bmx_grant(const char *label, const char *peer, char *id,
                      size_t cap)
{
    struct bmx_call c;
    bool ok;
    bmx_begin(&c, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&c.input, "action", "mint");
    (void)json_push_kv_str(&c.input, "scopes", "send");
    (void)json_push_kv_str(&c.input, "label", label);
    if (peer)
        (void)json_push_kv_str(&c.input, "peer", peer);
    zcl_native_handle_fleet_steer_grant(&c.request, &c.reply);
    ok = bmx_ok(&c);
    if (ok && id)
        (void)snprintf(id, cap, "%s",
                       json_get_str(json_get(&c.reply.data, "id")));
    bmx_end(&c);
    return ok;
}

/* fleet.steer.send one directive from box A as `chatgpt`. Returns the
 * item's state ("queued" or "refused") and its error through `error`. */
static char g_bmx_route[160], g_bmx_route_hint[1024];
static bool g_bmx_duplicate;
static bool bmx_send(const char *grant, const char *to, const char *ref,
                     const char *body, char *error, size_t cap)
{
    struct bmx_call c;
    struct json_value items, item;
    const struct json_value *r;
    bool queued;
    bmx_begin(&c, "fleet.steer.send", "zcl.fleet_steer_send.v1");
    (void)json_push_kv_str(&c.input, "grant", grant);
    (void)json_push_kv_str(&c.input, "from", "chatgpt");
    json_init(&items);
    json_set_array(&items);
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_str(&item, "to", to);
    (void)json_push_kv_str(&item, "body", body);
    (void)json_push_kv_str(&item, "ref", ref);
    (void)json_push_kv_str(&item, "idempotency_key", ref);
    (void)json_push_back(&items, &item);
    json_free(&item);
    (void)json_push_kv(&c.input, "items", &items);
    json_free(&items);
    zcl_native_handle_fleet_steer_send(&c.request, &c.reply);
    r = json_at(json_get(&c.reply.data, "items"), 0);
    queued = bmx_ok(&c) && r &&
             strcmp(json_get_str(json_get(r, "state")), "queued") == 0;
    (void)snprintf(g_bmx_route, sizeof(g_bmx_route), "%s", r ? json_get_str(json_get(r, "route_snapshot")) : "");
    (void)snprintf(g_bmx_route_hint, sizeof(g_bmx_route_hint), "%s", r ? json_get_str(json_get(r, "route_hint")) : "");
    g_bmx_duplicate = r && json_get_bool(json_get(r, "duplicate"));
    if (error)
        (void)snprintf(error, cap, "%s",
                       r ? json_get_str(json_get(r, "error"))
                         : c.reply.error.code);
    bmx_end(&c);
    return queued;
}

/* Post one mail row on the current box, as the worker's result would. */
static bool bmx_mail(const char *from, const char *to, const char *kind,
                     const char *ref, const char *body)
{
    struct bmx_call c;
    bool ok;
    bmx_begin(&c, "dev.agent.mail", "zcl.agent_mail.v1");
    (void)json_push_kv_str(&c.input, "action", "post");
    (void)json_push_kv_str(&c.input, "from", from);
    (void)json_push_kv_str(&c.input, "to", to);
    (void)json_push_kv_str(&c.input, "kind", kind);
    (void)json_push_kv_str(&c.input, "ref", ref);
    (void)json_push_kv_str(&c.input, "body", body);
    zcl_native_handle_dev_agent_mail(&c.request, &c.reply);
    ok = bmx_ok(&c);
    bmx_end(&c);
    return ok;
}

/* Queue rows naming `ref` on the current box, queued or running. */
static long long bmx_queued(const char *ref)
{
    static const char *const buckets[2] = {"queued", "running"};
    struct bmx_call c;
    long long hits = 0;
    bmx_begin(&c, "dev.agent.queue", "zcl.agent_queue.v1");
    (void)json_push_kv_str(&c.input, "action", "status");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_dev_agent_queue(&c.request, &c.reply);
    for (int b = 0; b < 2; b++) {
        const struct json_value *arr = json_get(&c.reply.data, buckets[b]);
        if (!bmx_ok(&c) || !arr || arr->type != JSON_ARR) {
            hits = -1;
            break;
        }
        for (size_t i = 0; i < json_size(arr); i++) {
            if (strcmp(json_get_str(json_get(json_at(arr, i), "name")),
                       ref) == 0)
                hits++;
        }
    }
    bmx_end(&c);
    return hits;
}

/* Lines of one of `box`'s state files carrying every given needle. */
static long long bmx_lines(int box, const char *rel, const char *n1,
                           const char *n2)
{
    char path[1600], line[16384];
    long long hits = 0;
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_bmx_state[box], rel);
    f = fopen(path, "rb");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    while (fgets(line, sizeof(line), f)) {
        if ((!n1 || strstr(line, n1)) && (!n2 || strstr(line, n2)))
            hits++;
    }
    if (ferror(f))
        hits = -1;
    (void)fclose(f);
    return hits;
}

static bool bmx_write(int box, const char *rel, const char *text,
                      const char *mode)
{
    static const char *const dirs[] = {"/z23", "/z23/dev", "/z23/dev/mail"};
    char path[1600];
    FILE *f;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s%s", g_bmx_state[box], dirs[i]);
        (void)mkdir(path, 0700);
    }
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_bmx_state[box], rel);
    f = fopen(path, mode);
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static long long bmx_size(int box, const char *rel)
{
    char path[1600];
    struct stat st;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_bmx_state[box], rel);
    return stat(path, &st) == 0 ? (long long)st.st_size : -1;
}

static void bmx_forget(int box, const char *rel)
{
    char path[1600];
    (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_bmx_state[box], rel);
    (void)remove(path);
}

/* One receiver beat on `box`, with that box's node answering the RPC. */
static long long bmx_drive(int box, struct rcv_beat_stats *st)
{
    struct rcv_drive_opts o;
    memset(&o, 0, sizeof(o));
    memset(st, 0, sizeof(*st));
    (void)snprintf(o.receiver, sizeof(o.receiver), "%s", g_bmx_name[box]);
    if (box == BMX_B)
        (void)snprintf(o.workspace, sizeof(o.workspace), "%s", g_bmx_ws);
    o.deadline_s = 30;
    o.wait_ms = 50;
    o.max_beats = 1;
    bmx_use(box);
    g_bmx_active = box;
    return zcl_devagent_receive_drive(&o, st);
}

/* ── a checkout for B's receiver to resolve the selector against ───────── */

static bool bmx_put(const char *dir, const char *rel, const char *text)
{
    char path[1600];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static void bmx_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* A .git with a symbolic HEAD, its loose ref, one tracked file, and a DIRC
 * v2 index whose stat data matches that file: a clean pre-state. */
static bool bmx_checkout(const char *ws)
{
    static const char *const dirs[] = {"", "/.git", "/.git/refs",
                                       "/.git/refs/heads", "/src"};
    unsigned char buf[512];
    char path[1600];
    struct stat st;
    size_t esz = (62u + 7u + 8u) & ~(size_t)7u;
    FILE *f;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s%s", ws, dirs[i]);
        (void)mkdir(path, 0700);
    }
    if (!bmx_put(ws, ".git/HEAD", "ref: refs/heads/x\n") ||
        !bmx_put(ws, ".git/refs/heads/x",
                 "2222222222222222222222222222222222222222\n") ||
        !bmx_put(ws, "src/x.c", "int zx(void) { return 0; }\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/src/x.c", ws);
    if (lstat(path, &st) != 0)
        return false;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "DIRC", 4);
    bmx_be32(buf + 4, 2);
    bmx_be32(buf + 8, 1);
    bmx_be32(buf + 12 + 8, (uint32_t)st.st_mtime);
    bmx_be32(buf + 12 + 24, 0100644u);
    bmx_be32(buf + 12 + 36, (uint32_t)st.st_size);
    buf[12 + 61] = 7;
    memcpy(buf + 12 + 62, "src/x.c", 7);
    (void)snprintf(path, sizeof(path), "%s/.git/index", ws);
    f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(buf, 1, 12u + esz + 20u, f) == 12u + esz + 20u;
    return fclose(f) == 0 && ok;
}

/* ── the rig ───────────────────────────────────────────────────────────── */

static const char g_bmx_body[] =
    "muse-workspace: receiver\nmuse-scope: src/x.c\nmuse-gate: hex_codec\n"
    "\nMake zx return one.\n";

static bool bmx_setup(const char *tag)
{
    char real[PATH_MAX];
    uint8_t seed[32], pub[32];
    test_make_tmpdir(g_bmx_base, sizeof(g_bmx_base), "devagent_boardmail",
                     tag);
    if (realpath(g_bmx_base, real) != NULL)
        (void)snprintf(g_bmx_base, sizeof(g_bmx_base), "%s", real);
    g_bmx_had_xdg = getenv("XDG_STATE_HOME") != NULL;
    if (g_bmx_had_xdg)
        (void)snprintf(g_bmx_saved_xdg, sizeof(g_bmx_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    for (int b = 0; b < 2; b++) {
        (void)snprintf(g_bmx_state[b], sizeof(g_bmx_state[b]), "%s/%s",
                       g_bmx_base, b == BMX_A ? "a" : "b");
        (void)mkdir(g_bmx_state[b], 0700);
    }
    (void)snprintf(g_bmx_ws, sizeof(g_bmx_ws), "%s/ws", g_bmx_base);
    memset(g_bmx_node, 0, sizeof(g_bmx_node));
    (void)snprintf(g_bmx_node[BMX_A].epoch, 33, "%032d", 1);
    (void)snprintf(g_bmx_node[BMX_B].epoch, 33, "%032d", 2);
    for (int k = 0; k < 4; k++) {
        bmx_key((uint8_t)(0x61 + k), seed, pub);
        bmx_hex(pub, 32, g_bmx_host[k]);
    }
    node_rpc_client_set_test_hook(bmx_rpc);
    zcl_devagent_boardmail_test_io(bmx_io_fault);
    return bmx_checkout(g_bmx_ws) && bmx_roster(BMX_A) && bmx_roster(BMX_B);
}

static void bmx_teardown(void)
{
    g_bmx_replay.enabled = false;
    g_bmx_io_phase = -1;
    zcl_devagent_boardmail_test_io(NULL);
    node_rpc_client_set_test_hook(NULL);
    if (g_bmx_had_xdg)
        setenv("XDG_STATE_HOME", g_bmx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

/* A sends `ref` to node-b as chatgpt, B has granted chatgpt to node-a,
 * and A's receiver has put the row on A's board. */
static bool bmx_sent(const char *ref)
{
    char grant[64], error[64];
    struct rcv_beat_stats st;
    bmx_use(BMX_A);
    if (!bmx_grant("chatgpt", NULL, grant, sizeof(grant)) ||
        !bmx_send(grant, "node-b", ref, g_bmx_body, error, sizeof(error)))
        return false;
    bmx_use(BMX_B);
    if (!bmx_grant("chatgpt", "node-a", NULL, 0))
        return false;
    return bmx_drive(BMX_A, &st) == 1 && st.board_out == 1;
}

static bool bmx_sent_unbound(const char *ref)
{
    struct rcv_beat_stats st;
    bmx_use(BMX_A);
    if (!bmx_mail("chatgpt", "node-b", "directive", ref, g_bmx_body))
        return false;
    bmx_use(BMX_B);
    if (!bmx_grant("chatgpt", "node-a", NULL, 0))
        return false;
    return bmx_drive(BMX_A, &st) == 1 && st.board_out == 1;
}

/* One row line as A's outbox wrote it for `ref` (the carried text). */
static bool bmx_outbox_row(const char *ref, char *out, size_t cap)
{
    char path[1600], needle[128];
    FILE *f;
    bool found = false;
    (void)snprintf(path, sizeof(path), "%s/z23/dev/mail/outbox.jsonl",
                   g_bmx_state[BMX_A]);
    (void)snprintf(needle, sizeof(needle), "\"ref\":\"%s\"", ref);
    f = fopen(path, "rb");
    while (f && !found && fgets(out, (int)cap, f))
        found = strstr(out, needle) != NULL;
    if (f)
        (void)fclose(f);
    if (found)
        out[strcspn(out, "\n")] = '\0';
    return found;
}

/* An inbox line on B: `row` with the given carrier fields appended. */
static bool bmx_inbox_forge(const char *stream, const char *row,
                            const char *post, const char *signer)
{
    char line[8192], rel[128];
    size_t n = strlen(row);
    int w;
    if (n < 2)
        return false;
    w = snprintf(line, sizeof(line), "%.*s", (int)(n - 1), row);
    if (post)
        w += snprintf(line + w, sizeof(line) - (size_t)w,
                      ",\"board_post\":\"%s\"", post);
    if (signer)
        w += snprintf(line + w, sizeof(line) - (size_t)w,
                      ",\"board_signer\":\"%s\"", signer);
    (void)snprintf(line + w, sizeof(line) - (size_t)w, "}\n");
    (void)snprintf(rel, sizeof(rel), "mail/inbox.%s.jsonl", stream);
    return bmx_write(BMX_B, rel, line, "ab");
}

/* A row naming node-b, with its own ts, from chatgpt under `ref`. */
static void bmx_row(char *out, size_t cap, const char *ts, const char *ref,
                    const char *prompt)
{
    (void)snprintf(out, cap,
                   "{\"seq\":9,\"ts\":\"%s\",\"from\":\"chatgpt\","
                   "\"to\":\"node-b\",\"kind\":\"directive\",\"body\":"
                   "\"muse-workspace: receiver\\nmuse-scope: src/x.c\\n"
                   "muse-gate: hex_codec\\n\\n%s\\n\",\"ref\":\"%s\"}",
                   ts, prompt, ref);
}

static void bmx_ts(long long unix_s, char *out, size_t cap)
{
    time_t t = (time_t)unix_s;
    struct tm tm;
    (void)gmtime_r(&t, &tm);
    (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ── cases ─────────────────────────────────────────────────────────────── */

static int bmx_t_round_trip(void)
{
    int failures = 0;
    TEST("boardmail: A sends, B queues and answers, A reads the answers — "
         "over the signed board, no script") {
        struct rcv_beat_stats st;
        char ack_post[96], result_post[96];
        ASSERT(bmx_setup("round-trip"));
        ASSERT(bmx_sent("job-1"));
        /* The directive is on A's board, signed by A's node key. */
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        ASSERT_STR_EQ(g_bmx_node[BMX_A].p[0].host, g_bmx_host[BMX_A]);
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(bmx_queued("job-1"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-1\"",
                            "\"board_signer\""), 1);
        /* The accept went back onto B's board under the same ref. */
        ASSERT_EQ(st.board_out, 1);
        /* A modeled worker result, posted to everyone. */
        ASSERT(bmx_mail("node-b", "*", "result", "job-1",
                        "worker=node-b\nstate=done\nverdict=pass\n"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_B].n, 3);
        (void)snprintf(ack_post, sizeof(ack_post), "\"board_post\":\"%s\"",
                       g_bmx_node[BMX_B].p[1].id);
        (void)snprintf(result_post, sizeof(result_post), "\"board_post\":\"%s\"",
                       g_bmx_node[BMX_B].p[2].id);
        ASSERT(strcmp(ack_post, result_post) != 0);
        bmx_carry(BMX_B, BMX_A);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_in, 2);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl",
                            "state=accepted", "\"job-1\""), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "state=done",
                            "\"job-1\""), 1);
        /* Verify the returned modeled result and its signed identity. */
        const struct bmx_post *verified = NULL;
        for (size_t i = 0; i < g_bmx_node[BMX_A].n; i++) {
            const struct bmx_post *candidate = &g_bmx_node[BMX_A].p[i];
            if (bmx_verified_result(candidate)) verified = candidate;
        }
        ASSERT(verified != NULL);
        /* A complete valid post under another signer is still not B's. */
        struct bmx_post counterfeit = *verified;
        struct fleet_board_post counterfeit_wire;
        (void)snprintf(counterfeit.host, sizeof(counterfeit.host), "%s", g_bmx_host[2]);
        ASSERT(bmx_sign(&counterfeit, 2));
        ASSERT(bmx_post_wire(&counterfeit, &counterfeit_wire));
        ASSERT_EQ(fleet_board_post_verify(&counterfeit_wire), FLEET_BOARD_OK);
        ASSERT(!bmx_verified_result(&counterfeit));
        /* Nothing local-only is left: A signed one post, B two, and
         * carriage left the same three on both nodes. */
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_A), 1);
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_B), 2);
        ASSERT_EQ((long long)g_bmx_node[BMX_B].n, 3);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", ack_post,
                            "state=accepted"), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", result_post,
                            "state=done"), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "\"job-1\"",
                            NULL), 2);
        /* A loses its board cursor and reads both return posts again. */
        bmx_carry(BMX_B, BMX_A);
        memset(&g_bmx_replay, 0, sizeof(g_bmx_replay));
        (void)snprintf(g_bmx_replay.ack, sizeof(g_bmx_replay.ack), "%s",
                       g_bmx_node[BMX_B].p[1].id);
        (void)snprintf(g_bmx_replay.result, sizeof(g_bmx_replay.result), "%s",
                       g_bmx_node[BMX_B].p[2].id);
        g_bmx_replay.enabled = true;
        bmx_forget(BMX_A, "receive/boardmail.state");
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        g_bmx_replay.enabled = false;
        ASSERT_EQ(g_bmx_replay.zero_pages, 1);
        ASSERT_EQ(g_bmx_replay.ack_seen, 1);
        ASSERT_EQ(g_bmx_replay.result_seen, 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", ack_post,
                            "state=accepted"), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", result_post,
                            "state=done"), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "\"job-1\"",
                            NULL), 2);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_unbound_operator(void)
{
    int failures = 0;
    TEST("boardmail: an operator row needs no binding when a peer grant admits it") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("unbound-operator"));
        ASSERT(bmx_sent_unbound("job-unbound"));
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 0);
        ASSERT_EQ(bmx_queued("job-unbound"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/brief/job-unbound.evidence",
                            "sender_binding=\n", NULL), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/brief/job-unbound.evidence",
                            "board_signer=", NULL), 1);
        ASSERT_EQ(st.board_out, 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_regossip(void)
{
    int failures = 0;
    TEST("boardmail: a re-gossiped post, a re-read page and a twin post of "
         "the same row deliver once") {
        struct rcv_beat_stats st;
        char row[4096];
        ASSERT(bmx_setup("regossip"));
        ASSERT(bmx_sent("job-2"));
        bmx_carry(BMX_A, BMX_B);
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ((long long)g_bmx_node[BMX_B].n, 1);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* The node restarted: a new epoch sends the reader back to 0. */
        (void)snprintf(g_bmx_node[BMX_B].epoch, 33, "%032d", 3);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        /* The cursor itself is lost: the whole page is read again. */
        bmx_forget(BMX_B, "receive/boardmail.state");
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        /* The same row carried again under a different created_at is a
         * different post id; the identical row is still refused. */
        ASSERT(bmx_outbox_row("job-2", row, sizeof(row)));
        long long inject_now = (long long)platform_time_wall_time_t();
        ASSERT(bmx_inject(BMX_B, BMX_A, row, bmx_stamp_before(inject_now, 5),
                          3600) != NULL);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-2\"",
                            NULL), 1);
        ASSERT_EQ(bmx_queued("job-2"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "state=accepted",
                            "\"job-2\""), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

/* Phase 2 runs after file sync and before parent-directory sync. */
static int bmx_exit_after_inbox_sync(const char *path, int phase)
{
    if (phase == 2 && strstr(path, "inbox.node-a.jsonl"))
        _exit(77);
    return 0;
}

static bool bmx_interrupt_import(void)
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        struct rcv_beat_stats stats;
        zcl_devagent_boardmail_test_io(bmx_exit_after_inbox_sync);
        (void)bmx_drive(BMX_B, &stats);
        _exit(1);
    }
    int status;
    pid_t done;
    do {
        done = waitpid(child, &status, 0);
    } while (done < 0 && errno == EINTR);
    return done == child && WIFEXITED(status) && WEXITSTATUS(status) == 77;
}

static int bmx_t_crash_between(void)
{
    int failures = 0;
    TEST("boardmail: a crash between export and import delivers once on "
         "restart") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("crash"));
        ASSERT(bmx_sent("job-3"));
        /* A died before recording the export: same bytes, same post. */
        bmx_forget(BMX_A, "receive/boardmail.state");
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        bmx_carry(BMX_A, BMX_B);
        ASSERT(bmx_interrupt_import());
        bmx_use(BMX_B);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-3\"", NULL), 1);
        ASSERT_EQ(bmx_queued("job-3"), 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "state=accepted", "\"job-3\""), 0);
        /* Recover the already synced row and finish admission once. */
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 1);
        /* Lose both cursors after admission and read the same page again. */
        bmx_forget(BMX_B, "receive/boardmail.state");
        bmx_forget(BMX_B, "receive/intake.state");
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-3\"",
                            NULL), 1);
        ASSERT_EQ(bmx_queued("job-3"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "state=accepted",
                            "\"job-3\""), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_forged(void)
{
    int failures = 0;
    TEST("boardmail: a forged inbox line naming a real post is refused "
         "MISMATCH") {
        struct rcv_beat_stats st;
        char row[4096], forged[4096];
        ASSERT(bmx_setup("forged"));
        ASSERT(bmx_sent("job-4"));
        bmx_carry(BMX_A, BMX_B);
        ASSERT(bmx_outbox_row("job-4", row, sizeof(row)));
        /* Genuine post id and signer under a different ref and body, written
         * before the genuine row: neither admits the forgery nor blocks it. */
        bmx_row(forged, sizeof(forged), "2026-09-19T00:00:00Z", "job-4x",
                "Something else entirely.");
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-a", forged, g_bmx_node[BMX_B].p[0].id,
                               g_bmx_host[BMX_A]));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(bmx_queued("job-4"), 1);
        ASSERT_EQ(bmx_queued("job-4x"), 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_POST_MISMATCH", "job-4x"),
                  1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_wrong_signer(void)
{
    int failures = 0;
    TEST("boardmail: a signer no roster names is UNENROLLED; an enrolled box "
         "nobody granted is UNGRANTED") {
        struct rcv_beat_stats st;
        char row[4096], ts[32];
        struct bmx_post *fwd;
        long long now = (long long)platform_time_wall_time_t();
        ASSERT(bmx_setup("signer"));
        bmx_use(BMX_B);
        ASSERT(bmx_grant("chatgpt", "node-a", NULL, 0));
        bmx_ts(now, ts, sizeof(ts));
        /* node-c is enrolled, but chatgpt was granted to node-a only. */
        bmx_row(row, sizeof(row), ts, "job-5c", "From the wrong box.");
        ASSERT(bmx_inject(BMX_B, 2, row, now, 3600) != NULL);
        /* A key no roster line names: never carried in, so the line is
         * written by hand, the way only a forger could. */
        bmx_row(row, sizeof(row), ts, "job-5d", "From nobody.");
        fwd = bmx_inject(BMX_B, 3, row, now, 3600);
        ASSERT(fwd != NULL);
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-d.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-d", row, fwd->id, g_bmx_host[3]));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 2);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_UNGRANTED", "job-5c"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_UNENROLLED", "job-5d"), 1);
        ASSERT_EQ(bmx_queued("job-5c"), 0);
        ASSERT_EQ(bmx_queued("job-5d"), 0);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_unsigned(void)
{
    int failures = 0;
    TEST("boardmail: one board field without the other is refused UNSIGNED, "
         "and a local grant does not rescue it") {
        struct rcv_beat_stats st;
        char row[4096];
        ASSERT(bmx_setup("unsigned"));
        bmx_use(BMX_B);
        ASSERT(bmx_grant("chatgpt", NULL, NULL, 0));
        ASSERT(bmx_grant("chatgpt", "node-a", NULL, 0));
        bmx_row(row, sizeof(row), "2026-09-19T00:00:01Z", "job-6",
                "Half signed.");
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-a", row,
                               "1111111111111111111111111111111111111111"
                               "111111111111111111111111",
                               NULL));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(bmx_queued("job-6"), 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_UNSIGNED", "job-6"), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_expired(void)
{
    int failures = 0;
    TEST("boardmail: an expired row is never posted, never paged, and never "
         "admitted late") {
        struct rcv_beat_stats st;
        char row[4096], ts[32], line[4200];
        struct bmx_post *fwd;
        long long now = (long long)platform_time_wall_time_t();
        ASSERT(bmx_setup("expired"));
        bmx_use(BMX_B);
        ASSERT(bmx_grant("chatgpt", "node-a", NULL, 0));
        /* A row on A's outbox eight days old: past the week-long ttl. */
        bmx_ts(now - 8LL * 86400, ts, sizeof(ts));
        bmx_row(row, sizeof(row), ts, "job-7a", "Too old to send.");
        (void)snprintf(line, sizeof(line), "%s\n", row);
        bmx_use(BMX_A);
        ASSERT(bmx_mail("node-a", "node-a", "note", "prime", "prime"));
        ASSERT(bmx_write(BMX_A, "mail/outbox.jsonl", line, "ab"));
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 0);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 0);
        /* A post that expired on the way is never paged to B. */
        bmx_ts(now - 7200, ts, sizeof(ts));
        bmx_row(row, sizeof(row), ts, "job-7b", "Expired in flight.");
        fwd = bmx_inject(BMX_B, BMX_A, row, now - 7200, 3600);
        ASSERT(fwd != NULL);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        /* And a line naming it is refused, not admitted late. */
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-a", row, fwd->id, g_bmx_host[BMX_A]));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 1);
        ASSERT_EQ(bmx_queued("job-7b"), 0);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_POST_GONE", "job-7b"), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_deferred(void)
{
    int failures = 0;
    TEST("boardmail: a node that cannot vouch leaves the row undecided, and "
         "a later beat admits it once") {
        struct rcv_beat_stats st;
        char row[4096];
        ASSERT(bmx_setup("deferred"));
        ASSERT(bmx_sent("job-8"));
        bmx_carry(BMX_A, BMX_B);
        g_bmx_node[BMX_B].show_down = true;
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT(st.board_deferred >= 1);
        ASSERT_EQ(st.admitted + st.refused, 0);
        ASSERT_EQ(bmx_queued("job-8"), 0);
        /* No answer, so nothing was marked: the row is decided later. */
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "\"job-8\"", NULL),
                  0);
        g_bmx_node[BMX_B].show_down = false;
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(bmx_queued("job-8"), 1);
        ASSERT(bmx_outbox_row("job-8", row, sizeof(row)));
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

/* One dev.agent.mail post from this box; copies its delivery label and hint
 * out. False when the post itself is refused. */
static bool bmx_post_where(const char *to, const char *ref, char *label,
                           size_t lcap, char *hint, size_t hcap)
{
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    const struct json_value *v;
    bool ok;
    json_init(&in);
    json_set_object(&in);
    memset(&req, 0, sizeof(req));
    req.input = &in;
    zcl_command_reply_init(&reply, "zcl.agent_mail.v1");
    (void)json_push_kv_str(&in, "action", "post");
    (void)json_push_kv_str(&in, "from", "node-a");
    (void)json_push_kv_str(&in, "to", to);
    (void)json_push_kv_str(&in, "kind", "note");
    (void)json_push_kv_str(&in, "body", "where does this go");
    if (ref)
        (void)json_push_kv_str(&in, "ref", ref);
    zcl_native_handle_dev_agent_mail(&req, &reply);
    ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
    label[0] = '\0';
    hint[0] = '\0';
    v = json_get(&reply.data, "delivery");
    if (v && v->type == JSON_STR && json_get_str(v))
        (void)snprintf(label, lcap, "%s", json_get_str(v));
    v = json_get(&reply.data, "hint");
    if (v && v->type == JSON_STR && json_get_str(v))
        (void)snprintf(hint, hcap, "%s", json_get_str(v));
    zcl_command_reply_free(&reply);
    json_free(&in);
    return ok;
}

static bool bmx_own_key(void)
{
    char path[1600]; uint8_t seed[32];
    memset(seed, 0x41, sizeof(seed));
    if (!fleet_enrol_state_path("box.ed25519", path, sizeof(path))) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    bool ok = write(fd, seed, sizeof(seed)) == (ssize_t)sizeof(seed);
    return close(fd) == 0 && ok;
}

static bool bmx_oversize_refs(void)
{
    char path[1600];
    int n = snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.refs", g_bmx_state[BMX_A]);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < 1025; ++i)
        if (fprintf(f, "in job-%zu node-b\n", i) < 0) { ok = false; break; }
    return fclose(f) == 0 && ok;
}

static bool bmx_directory_result(bool known, size_t count, bool truncated)
{
    struct json_value names; json_init(&names); bool cut = false;
    bool got = zcl_devagent_boardmail_directory(&names, &cut);
    bool b = false, c = false, self = false;
    for (size_t i = 0; i < json_size(&names); ++i) {
        const char *name = json_get_str(json_at(&names, i));
        if (!name) { json_free(&names); return false; }
        b |= !strcmp(name, "node-b"); c |= !strcmp(name, "node-c");
        self |= !strcmp(name, "node-a");
    }
    bool ok = got == known && json_size(&names) == count && cut == truncated &&
              !self && (!known || (b && c));
    json_free(&names); return ok;
}

static bool bmx_brief_directory(void)
{
    struct bmx_call c; bmx_begin(&c, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
    (void)json_push_kv_bool(&c.input, "json", true);
    zcl_native_handle_fleet_steer_brief(&c.request, &c.reply);
    const struct json_value *dir = json_get(&c.reply.data, "mailbox_directory");
    const char *state = json_get_str(json_get(dir, "state"));
    const struct json_value *labels = json_get(dir, "labels");
    bool b = false, d = false;
    for (size_t i = 0; labels && i < json_size(labels); ++i) {
        const char *name = json_get_str(json_at(labels, i));
        if (name) { b |= !strcmp(name, "node-b"); d |= !strcmp(name, "node-c"); }
    }
    bool ok = bmx_ok(&c) && state && !strcmp(state, "complete") &&
        labels && json_size(labels) == 2u && b && d && json_size(dir) == 5u &&
        json_get(&c.reply.data, "agents") != NULL;
    bmx_end(&c); return ok;
}

static bool bmx_grant_directory(const char *scopes, const char *expected, size_t count)
{
    struct bmx_call grant, brief; char id[64] = "";
    bmx_begin(&grant, "fleet.steer.grant", "zcl.fleet_steer_grant.v1");
    (void)json_push_kv_str(&grant.input, "action", "mint");
    (void)json_push_kv_str(&grant.input, "scopes", scopes);
    (void)json_push_kv_str(&grant.input, "label", "chatgpt");
    zcl_native_handle_fleet_steer_grant(&grant.request, &grant.reply);
    const char *value = json_get_str(json_get(&grant.reply.data, "id"));
    bool ok = bmx_ok(&grant) && value && strlen(value) < sizeof(id);
    if (ok) (void)snprintf(id, sizeof(id), "%s", value);
    bmx_end(&grant);
    if (!ok) return false;
    bmx_begin(&brief, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
    (void)json_push_kv_str(&brief.input, "grant", id);
    (void)json_push_kv_bool(&brief.input, "json", true);
    zcl_native_handle_fleet_steer_brief(&brief.request, &brief.reply);
    const struct json_value *dir = json_get(&brief.reply.data, "mailbox_directory");
    const char *state = json_get_str(json_get(dir, "state"));
    const struct json_value *labels = json_get(dir, "labels");
    ok = bmx_ok(&brief) && state && !strcmp(state, expected) && labels && json_size(labels) == count;
    bmx_end(&brief); return ok;
}

static bool bmx_directory_expand(void)
{
    char line[FLEET_ENROL_MACHINE_TEXT_MAX], name[25]; const char *why = NULL;
    for (unsigned i = 0; i < 32u; ++i) {
        (void)snprintf(name, sizeof(name), "node-%02u", i);
        if (!bmx_roster_line(name, (uint8_t)(0x80u + i), (uint8_t)(0xa0u + i),
                             (uint16_t)(FLEET_ENROL_PORT_FIRST + 3u + i), line, sizeof(line)) ||
            !fleet_roster_append(line, &why)) return false;
    }
    return true;
}

/* Probe a forward page with the real sealed roster and a fixed output budget. */
static int bmx_directory_budget_probe(size_t budget, bool *cut)
{
    struct bmx_call c; bmx_begin(&c, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
    (void)json_push_kv_str(&c.input, "since", "0|");
    (void)json_push_kv_int(&c.input, "limit", 1);
    (void)json_push_kv_bool(&c.input, "json", true);
    c.request.budget_bytes = budget;
    zcl_native_handle_fleet_steer_brief(&c.request, &c.reply);
    int result = 0;
    if (bmx_ok(&c)) {
        const struct json_value *dir = json_get(&c.reply.data, "mailbox_directory");
        const char *state = json_get_str(json_get(dir, "state"));
        const char *token = json_get_str(json_get(&c.reply.data, "cursor_token"));
        const struct json_value *changes = json_get(&c.reply.data, "changes");
        const struct json_value *cuts = json_get(&c.reply.data, "budget_truncated");
        *cut = state && !strcmp(state, "truncated") &&
            json_get_int(json_get(cuts, "mailbox_directory")) > 0;
        result = changes && json_size(changes) == 1 && token && token[0] && strcmp(token, "0|") != 0 &&
                 json_write(&c.reply.data, NULL, 0) <= budget - 1024u ? 1 : -1;
    } else if (strcmp(c.reply.error.code, "BRIEF_PAGE_STALLED")) result = -1;
    bmx_end(&c); return result;
}

static bool bmx_model_expendable_cuts(struct json_value *data, struct json_value *cuts)
{
    static const char *const expendable[] = {"workers", "candidates", "work", "agents", "sessions", "blockers", "tasks"};
    for (size_t i = 0; i < sizeof(expendable) / sizeof(expendable[0]); ++i) {
        struct json_value *arr = (struct json_value *)json_get(data, expendable[i]);
        size_t n = arr && arr->type == JSON_ARR ? arr->num_children : 0;
        while (arr && arr->type == JSON_ARR && arr->num_children) json_free(&arr->children[--arr->num_children]);
        if (n && !json_push_kv_int(cuts, expendable[i], (long long)n)) return false;
    }
    return true;
}

static bool bmx_directory_metadata_boundary(void)
{
    struct bmx_call c; bmx_begin(&c, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
    (void)json_push_kv_str(&c.input, "since", "0|");
    (void)json_push_kv_int(&c.input, "limit", 1);
    (void)json_push_kv_bool(&c.input, "json", true);
    c.request.budget_bytes = 8192;
    zcl_native_handle_fleet_steer_brief(&c.request, &c.reply);
    struct json_value *dir = (struct json_value *)json_get(&c.reply.data, "mailbox_directory");
    struct json_value *labels = (struct json_value *)json_get(dir, "labels");
    struct json_value *cuts = (struct json_value *)json_get(&c.reply.data, "budget_truncated");
    bool ok = bmx_ok(&c) && labels && labels->type == JSON_ARR && labels->num_children > 2 && cuts;
    size_t before = 0, after = 0;
    if (ok) {
        ok = bmx_model_expendable_cuts(&c.reply.data, cuts);
        json_free(&labels->children[--labels->num_children]);
        before = json_write(&c.reply.data, NULL, 0);
        ok = ok && json_push_kv_int(cuts, "mailbox_directory", 1);
        after = json_write(&c.reply.data, NULL, 0);
    }
    bmx_end(&c);
    bool cut = false;
    return ok && after > before && bmx_directory_budget_probe(before + 1024u, &cut) == 1 && cut;
}

static bool bmx_directory_tight_page(void)
{
    static const char row[] = "{\"seq\":1,\"ts\":\"2026-09-20T00:00:00Z\",\"from\":\"node-b\",\"to\":\"node-a\",\"kind\":\"note\",\"body\":\"retained\",\"ref\":\"budget-row\"}\n";
    if (!bmx_write(BMX_A, "mail/inbox.node-b.jsonl", row, "wb")) return false;
    if (!bmx_directory_metadata_boundary()) return false;
    size_t low = 1024, high = 8192; bool cut = false;
    if (bmx_directory_budget_probe(high, &cut) != 1) return false;
    while (high - low > 1) {
        size_t mid = low + (high - low) / 2;
        int result = bmx_directory_budget_probe(mid, &cut);
        if (result < 0) return false;
        if (result) high = mid; else low = mid;
    }
    return bmx_directory_budget_probe(high, &cut) == 1 && cut;
}

static bool bmx_seed_crowded_history(void)
{
    char path[1600], quotes[301];
    for (size_t i = 0; i < 150; ++i) memcpy(quotes + 2 * i, "\\\"", 2);
    quotes[300] = 0;
    for (unsigned stream = 0; stream < 8; ++stream) {
        char rel[80];
        (void)snprintf(rel, sizeof(rel), "mail/inbox.bulk-%u.jsonl", stream);
        if (!bmx_write(BMX_A, rel, "", "wb")) return false;
        (void)snprintf(path, sizeof(path), "%s/z23/dev/%s", g_bmx_state[BMX_A], rel);
        FILE *f = fopen(path, "ab");
        if (!f) return false;
        bool ok = true;
        for (unsigned i = stream; i < 3000; i += 8) {
            if (fprintf(f, "{\"seq\":%u,\"ts\":\"2026-09-16T%02u:%02u:%02uZ\",\"from\":\"box-%03u\",\"to\":\"node-a\",\"kind\":\"claim\",\"body\":\"note=%s\\nstate=accepted\",\"ref\":\"job-%04u\"}\n",
                        i + 1, (i / 3600) % 24, (i / 60) % 60, i % 60, i % 200, quotes, i) < 0) { ok = false; break; }
        }
        if (fclose(f) != 0 || !ok) return false;
    }
    return true;
}

static int bmx_t_directory_crowded(void)
{
    int failures = 0;
    TEST("boardmail: crowded default brief retains configured labels") {
        ASSERT(bmx_setup("directory_crowded")); bmx_use(BMX_A); ASSERT(bmx_own_key());
        ASSERT(bmx_seed_crowded_history());
        struct bmx_call c; bmx_begin(&c, "fleet.steer.brief", "zcl.fleet_steer_brief.v1");
        (void)json_push_kv_int(&c.input, "limit", 100);
        zcl_native_handle_fleet_steer_brief(&c.request, &c.reply);
        const struct json_value *dir = json_get(&c.reply.data, "mailbox_directory");
        const struct json_value *labels = json_get(dir, "labels");
        const struct json_value *cut = json_get(&c.reply.data, "budget_truncated");
        ASSERT(bmx_ok(&c));
        ASSERT_STR_EQ(json_get_str(json_get(dir, "state")), "complete");
        ASSERT_EQ(json_size(labels), 2u);
        ASSERT(json_get_int(json_get(cut, "changes")) > 0);
        bmx_end(&c); bmx_teardown(); PASS();
    } _test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_directory(void)
{
    int failures = 0;
    TEST("boardmail: verified directory names and bounded truncation") {
        ASSERT(bmx_setup("directory")); bmx_use(BMX_A); ASSERT(bmx_own_key());
        ASSERT(bmx_directory_result(true, 2u, false));
        ASSERT(bmx_brief_directory());
        ASSERT(bmx_grant_directory("brief", "withheld", 0u));
        ASSERT(bmx_grant_directory("brief,send", "complete", 2u));
        ASSERT(bmx_directory_expand());
        ASSERT(bmx_directory_result(true, 32u, true));
        ASSERT(bmx_directory_tight_page());
        bmx_teardown(); PASS();
    } _test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_delivery(void)
{
    int failures = 0;
    TEST("boardmail: a posted row says where the exporter will carry it") {
        char label[160], hint[1024], path[1600];
        char line[FLEET_ENROL_MACHINE_TEXT_MAX];
        const char *why = NULL;
        ASSERT(bmx_setup("delivery"));
        bmx_use(BMX_A);
        ASSERT(bmx_own_key());
        ASSERT(bmx_roster_line("node-d", 0x44, 0,
                               FLEET_ENROL_PORT_FIRST + 3, line, sizeof(line)));
        ASSERT(fleet_roster_append(line, &why));
        /* Broadcast: this box only, nothing carried. */
        ASSERT(bmx_post_where("*", NULL, label, sizeof(label), hint,
                              sizeof(hint)));
        ASSERT_STR_EQ(label, "local");
        ASSERT_STR_EQ(hint, "");
        /* Another enrolled box, named by its roster name. */
        ASSERT(bmx_post_where("node-b", NULL, label, sizeof(label), hint,
                              sizeof(hint)));
        ASSERT_STR_EQ(label, "export_eligible");
        ASSERT_STR_EQ(hint, "");
        /* An agent id no roster box holds: local, with a hint that
         * names the roster boxes cross-host mail can be addressed to. */
        ASSERT(bmx_post_where("someagent", NULL, label, sizeof(label), hint,
                              sizeof(hint)));
        ASSERT_STR_EQ(label, "local");
        ASSERT(strstr(hint, "no roster box named someagent") != NULL);
        ASSERT(strstr(hint, "node-b") != NULL);
        ASSERT(bmx_post_where("node-d", NULL, label, sizeof(label), hint,
                              sizeof(hint)));
        ASSERT_STR_EQ(label, "local");
        ASSERT(strstr(hint, "roster box node-d has no node signing key") != NULL);
        ASSERT(strstr(hint, "fleet join") != NULL);
        struct zcl_boardmail_delivery route;
        zcl_devagent_boardmail_observe(NULL, NULL, &route);
        ASSERT_STR_EQ(route.label, "unknown");
        zcl_devagent_boardmail_observe("node-b", NULL, &route);
        ASSERT_STR_EQ(route.label, "export_eligible");
        zcl_devagent_boardmail_observe("someagent", NULL, &route);
        ASSERT_STR_EQ(route.label, "local");
        ASSERT(strstr(route.hint, "node-b") != NULL);
        zcl_devagent_boardmail_observe("node-d", NULL, &route);
        ASSERT_STR_EQ(route.label, "local");
        ASSERT(strstr(route.hint, "node-d has no node signing key") != NULL);
        char grant[64], error[64];
        ASSERT(bmx_grant("chatgpt", NULL, grant, sizeof(grant)));
        ASSERT(bmx_send(grant, "node-d", "route-signerless", g_bmx_body,
                        error, sizeof(error)));
        ASSERT_STR_EQ(g_bmx_route, "local");
        ASSERT(strstr(g_bmx_route_hint, "fleet join") != NULL);
        ASSERT(bmx_send(grant, "someagent", "route-test", g_bmx_body, error, sizeof(error)));
        ASSERT_STR_EQ(g_bmx_route, "local");
        ASSERT(strstr(g_bmx_route_hint, "node-b") && !g_bmx_duplicate);
        ASSERT(bmx_send(grant, "someagent", "route-test", g_bmx_body, error, sizeof(error)));
        ASSERT_STR_EQ(g_bmx_route, "local");
        ASSERT(strstr(g_bmx_route_hint, "node-b") && g_bmx_duplicate);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/outbox.jsonl", "route-test", NULL), 1);
        /* A reply under a ref this box imported from node-b goes back to
         * node-b, whatever `to` names. Lay down the refs ledger the receive
         * beat keeps under <state>/receive. */
        (void)snprintf(path, sizeof(path), "%s/z23/dev/receive",
                       g_bmx_state[BMX_A]);
        (void)mkdir(path, 0700);
        ASSERT(bmx_write(BMX_A, "receive/boardmail.refs", "in job-9 node-b\n",
                         "wb"));
        ASSERT(bmx_post_where("someagent", "job-9", label, sizeof(label),
                              hint, sizeof(hint)));
        ASSERT_STR_EQ(label, "export_eligible");
        ASSERT_STR_EQ(hint, "");
        zcl_devagent_boardmail_observe("someagent", "job-9", &route);
        ASSERT_STR_EQ(route.label, "export_eligible");
        zcl_devagent_boardmail_observe("*", "job-9", &route);
        ASSERT_STR_EQ(route.label, "export_eligible");
        ASSERT(bmx_write(BMX_A, "receive/boardmail.refs", "broken", "wb"));
        zcl_devagent_boardmail_observe("someagent", "job-9", &route);
        ASSERT_STR_EQ(route.label, "unknown");
        ASSERT(bmx_oversize_refs());
        zcl_devagent_boardmail_observe("someagent", "job-9", &route);
        ASSERT_STR_EQ(route.label, "unknown");
        ASSERT(bmx_send(grant, "someagent", "route-overflow", g_bmx_body, error, sizeof(error)));
        ASSERT_STR_EQ(g_bmx_route, "unknown");
        ASSERT_EQ(bmx_lines(BMX_A, "mail/outbox.jsonl", "route-overflow", NULL), 1);
        ASSERT(bmx_write(BMX_A, "receive/boardmail.refs", "", "wb"));
        ASSERT(fleet_enrol_state_path("machines.roster", path, sizeof(path)));
        FILE *roster = fopen(path, "ab");
        ASSERT(roster != NULL);
        ASSERT(fputs("unverifiable roster row\n", roster) >= 0);
        ASSERT(fclose(roster) == 0);
        ASSERT(bmx_directory_result(false, 0u, false));
        zcl_devagent_boardmail_observe("someagent", NULL, &route);
        ASSERT_STR_EQ(route.label, "unknown");
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

/* Posts on `node` signed by `host` whose post call carried `push_to`. */
static long long bmx_hinted(int node, int host, const char *push_to)
{
    long long hits = 0;
    for (size_t i = 0; i < g_bmx_node[node].n; i++) {
        const struct bmx_post *p = &g_bmx_node[node].p[i];
        hits += strcmp(p->host, g_bmx_host[host]) == 0 &&
                strcmp(p->push_to, push_to) == 0;
    }
    return hits;
}

static bool bmx_fill_refs(void)
{
    char path[1600];
    (void)snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.refs", g_bmx_state[BMX_A]);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fprintf(f, "in evicted node-b\n") > 0;
    for (int i = 0; ok && i < 1022; i++)
        ok = fprintf(f, "in filler-%04d node-b\n", i) > 0;
    if (ok) ok = fprintf(f, "in choice node-b\nin choice node-c\n") > 0;
    return fclose(f) == 0 && ok;
}

static bool bmx_advance_refs(void)
{
    char path[1600];
    (void)snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.refs", g_bmx_state[BMX_A]);
    FILE *f = fopen(path, "ab");
    if (!f) return false;
    bool ok = true;
    for (int i = 0; ok && i < 1023; i++)
        ok = fprintf(f, "in newest-%04d node-b\n", i) > 0;
    return fclose(f) == 0 && ok;
}

static int bmx_t_refs_wrap(void)
{
    int failures = 0;
    TEST("boardmail: retained references route by oldest surviving match across wrap") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("refs-wrap"));
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT(bmx_fill_refs());
        bmx_use(BMX_A);
        ASSERT(bmx_mail("node-a", "*", "result", "evicted", "evicted\n"));
        ASSERT(bmx_mail("node-a", "*", "result", "choice", "first\n"));
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        ASSERT_STR_EQ(g_bmx_node[BMX_A].p[0].push_to, g_bmx_host[BMX_B]);
        /* Another wrap evicts the first match; reload must keep the next. */
        ASSERT(bmx_advance_refs());
        ASSERT(bmx_mail("node-a", "*", "result", "choice", "second\n"));
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 2);
        ASSERT_STR_EQ(g_bmx_node[BMX_A].p[1].push_to, g_bmx_host[2]);
        bmx_teardown(); PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_push_hint(void)
{
    int failures = 0;
    TEST("boardmail: a box-addressed row and every answer to an imported "
         "directive name their box's board key as the push hint; alias and "
         "broadcast rows are still not exported") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("push-hint"));
        /* A's directive to node-b: hinted to node-b's board key. */
        ASSERT(bmx_sent("job-h"));
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_A), 1);
        ASSERT_EQ(bmx_hinted(BMX_A, BMX_A, g_bmx_host[BMX_B]), 1);
        /* B's accept, and the worker's result posted to everyone, answer
         * the directive A sent: both hinted back to node-a. */
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT(bmx_mail("node-b", "*", "result", "job-h",
                        "worker=node-b\nstate=done\nverdict=pass\n"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ(bmx_signed_by(BMX_B, BMX_B), 2);
        ASSERT_EQ(bmx_hinted(BMX_B, BMX_B, g_bmx_host[BMX_A]), 2);
        /* Alias and broadcast rows that answer nothing stay local. */
        bmx_use(BMX_A);
        ASSERT(bmx_mail("chatgpt", "*", "note", "bcast-1", "to everyone\n"));
        ASSERT(bmx_mail("chatgpt", "someagent", "note", "alias-1",
                        "to an agent alias\n"));
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 0);
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_A), 1);
        /* No carried post went without its hint. */
        ASSERT_EQ(bmx_hinted(BMX_A, BMX_A, "-"), 0);
        ASSERT_EQ(bmx_hinted(BMX_B, BMX_B, "-"), 0);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_incomplete_page(void)
{
    int failures = 0;
    TEST("boardmail: incomplete page holds cursor until a healthy retry") {
        for (int fault = BMX_PAGE_MISSING_POSTS; fault <= BMX_PAGE_SHORT_RETURN; fault++) {
            struct rcv_beat_stats st;
            char tag[64];
            (void)snprintf(tag, sizeof(tag), "incomplete-page-%d", fault);
            ASSERT(bmx_setup(tag));
            ASSERT(bmx_sent("job-page"));
            /* A valid empty page establishes B's current epoch and cursor. */
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                                "import_epoch=00000000000000000000000000000002", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state", "import_after=0", NULL), 1);
            bmx_carry(BMX_A, BMX_B);
            g_bmx_node[BMX_B].page_fault = (enum bmx_page_fault)fault;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT(st.board_deferred >= 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                                "import_epoch=00000000000000000000000000000002", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state", "import_after=0", NULL), 1);
            g_bmx_node[BMX_B].page_fault = BMX_PAGE_OK;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 1);
            ASSERT_EQ(st.admitted, 1);
            ASSERT_EQ(bmx_queued("job-page"), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-page\"", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "state=accepted", "job-page"), 1);
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_queued("job-page"), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "\"job-page\"", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl", "state=accepted", "job-page"), 1);
            /* A same-epoch backward scan must not rewind a saved cursor. */
            g_bmx_node[BMX_B].page_fault = BMX_PAGE_BACKWARD;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT(st.board_deferred >= 1);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state", "import_after=2", NULL), 1);
            g_bmx_node[BMX_B].page_fault = BMX_PAGE_STALLED;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT(st.board_deferred >= 1);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state", "import_after=2", NULL), 1);
            /* An empty page may scan past an unexportable stored row. */
            g_bmx_node[BMX_B].page_fault = BMX_PAGE_EMPTY_ADVANCE;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_deferred, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state", "import_after=3", NULL), 1);
            g_bmx_node[BMX_B].page_fault = BMX_PAGE_OK;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_queued("job-page"), 1);
            bmx_teardown();
        }
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static bool bmx_state_text(int box, char out[256])
{
    char path[1600];
    int n = snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.state", g_bmx_state[box]);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "rb"); if (!f) return false;
    size_t used = fread(out, 1, 255, f);
    bool ok = !ferror(f) && feof(f);
    if (fclose(f) != 0) ok = false;
    out[used] = 0; return ok;
}
static bool bmx_signed_peer_post(const struct bmx_post *p)
{
    struct fleet_board_post wire; uint8_t id[32];
    return p && !strcmp(p->host, g_bmx_host[BMX_B]) && bmx_post_wire(p, &wire) &&
        fleet_board_post_compute_id(&wire, id) == FLEET_BOARD_OK && !memcmp(id, wire.id, 32) &&
        fleet_board_post_verify(&wire) == FLEET_BOARD_OK;
}
static bool bmx_post_target(const struct bmx_post *p, const char *target)
{
    struct json_value row; json_init(&row);
    bool ok = p && json_read(&row, p->text, strlen(p->text));
    const char *to = ok ? json_get_str(json_get(&row, "to")) : NULL;
    ok = to && !strcmp(to, target); json_free(&row); return ok;
}
static int bmx_t_refs_unreadable(void)
{
    int failures = 0;
    TEST("boardmail: unreadable refs hold cursor until signed returns can be routed") {
        struct rcv_beat_stats st; char path[1600], saved[1650], before[256], after[256];
        ASSERT(bmx_setup("unreadable-refs"));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.refs", g_bmx_state[BMX_A]);
        ASSERT(access(path, F_OK) != 0 && errno == ENOENT);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_deferred, 0);
        ASSERT(bmx_sent("job-1"));
        ASSERT_EQ(bmx_lines(BMX_A, "receive/boardmail.refs", "out job-1 node-b", NULL), 1);
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT(bmx_mail("node-b", "*", "result", "job-1", "worker=node-b\nstate=done\nverdict=pass\n"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(g_bmx_node[BMX_B].n, (size_t)3);
        ASSERT(bmx_signed_peer_post(&g_bmx_node[BMX_B].p[1]));
        ASSERT(bmx_post_target(&g_bmx_node[BMX_B].p[1], "chatgpt"));
        ASSERT(bmx_verified_result(&g_bmx_node[BMX_B].p[2]));
        ASSERT(bmx_post_target(&g_bmx_node[BMX_B].p[2], "*"));
        bmx_carry(BMX_B, BMX_A);
        const char *unrelated = "{\"seq\":8,\"ts\":\"2026-01-01T00:00:00Z\",\"from\":\"node-b\",\"to\":\"*\",\"kind\":\"result\",\"body\":\"unrelated\",\"ref\":\"other-ref\"}";
        ASSERT(bmx_signed_peer_post(bmx_inject(BMX_A, BMX_B, unrelated, (long long)time(NULL), 3600)));
        ASSERT(bmx_state_text(BMX_A, before));
        (void)snprintf(saved, sizeof(saved), "%s.saved", path);
        bool moved = rename(path, saved) == 0;
        bool blocked = moved && mkdir(path, 0700) == 0;
        if (moved && !blocked) (void)rename(saved, path);
        ASSERT(blocked);
        unsigned before_page = g_bmx_node[BMX_A].page_calls;
        long long result = bmx_drive(BMX_A, &st);
        unsigned page_calls = g_bmx_node[BMX_A].page_calls - before_page;
        bool restored = rmdir(path) == 0 && rename(saved, path) == 0;
        bool deferred = st.board_deferred >= 1;
        ASSERT(restored);
        bool cursor_same = bmx_state_text(BMX_A, after) && !strcmp(before, after);
        long long before_rows = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", NULL);
        long long resumed = bmx_drive(BMX_A, &st), delivered = st.board_in;
        long long ack = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", "state=accepted");
        long long done = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", "state=done");
        long long other = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "other-ref", NULL);
        printf("REFS_READ_PROBE page_calls=%u deferred=%d cursor_same=%d before=%lld resumed=%lld in=%lld ack=%lld result=%lld unrelated=%lld\n",
               page_calls, deferred, cursor_same, before_rows, resumed, delivered, ack, done, other);
        ASSERT(result == 1 && page_calls == 0 && deferred && cursor_same && before_rows == 0);
        ASSERT(resumed == 1 && delivered == 2 && ack == 1 && done == 1 && other == 0);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", NULL), 2);
        bmx_teardown(); PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_state_unreadable(void)
{
    int failures = 0;
    TEST("boardmail: unreadable checkpoint holds import and export") {
        struct rcv_beat_stats st;
        char path[1600], saved[1650];
        ASSERT(bmx_setup("unreadable-state"));
        ASSERT(bmx_sent("job-state"));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.state", g_bmx_state[BMX_A]);
        (void)snprintf(saved, sizeof(saved), "%s.saved", path);
        ASSERT(rename(path, saved) == 0);
        ASSERT(mkdir(path, 0700) == 0);
        unsigned before_post = g_bmx_node[BMX_A].post_calls;
        unsigned before_page = g_bmx_node[BMX_A].page_calls;
        long long result = bmx_drive(BMX_A, &st);
        unsigned post_calls = g_bmx_node[BMX_A].post_calls - before_post;
        unsigned page_calls = g_bmx_node[BMX_A].page_calls - before_page;
        bool restored = rmdir(path) == 0 && rename(saved, path) == 0;
        printf("STATE_READ_PROBE post_calls=%u page_calls=%u deferred=%lld\n",
               post_calls, page_calls, (long long)st.board_deferred);
        ASSERT(restored);
        ASSERT_EQ(result, 1);
        ASSERT_EQ(post_calls, 0);
        ASSERT_EQ(page_calls, 0);
        ASSERT(st.board_deferred >= 1);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(g_bmx_node[BMX_A].post_calls, before_post);
        ASSERT(bmx_sent("job-state-next"));
        ASSERT_EQ(g_bmx_node[BMX_A].post_calls, before_post + 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 2);
        bmx_teardown(); PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_oversize(void)
{
    int failures = 0;
    TEST("boardmail: a directive for another box too large for one board "
         "note is refused at send, and nothing is written") {
        char grant[64], error[64], body[2100];
        size_t i;
        ASSERT(bmx_setup("oversize"));
        bmx_use(BMX_A);
        ASSERT(bmx_grant("chatgpt", NULL, grant, sizeof(grant)));
        (void)snprintf(body, sizeof(body), "%s", g_bmx_body);
        for (i = strlen(body); i < 1990; i++)
            body[i] = (i % 16 == 15) ? ' ' : 'a';
        body[i] = '\0';
        /* Within the steer body ceiling, so only the carriage refuses. */
        ASSERT(strlen(body) <= 2048);
        ASSERT(!bmx_send(grant, "node-b", "job-9", body, error,
                         sizeof(error)));
        ASSERT_STR_EQ(error, "STEER_REMOTE_BODY_TOO_LARGE");
        ASSERT_EQ(bmx_lines(BMX_A, "mail/outbox.jsonl", "\"job-9\"", NULL),
                  0);
        /* The same body to a local agent needs no board note. */
        ASSERT(bmx_send(grant, "helper", "job-9l", body, error,
                        sizeof(error)));
        /* And a body that fits still goes to the other box. */
        ASSERT(bmx_send(grant, "node-b", "job-9s", g_bmx_body, error,
                        sizeof(error)));
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_append_retry(void)
{
    int failures = 0;
    TEST("boardmail: partial append and sync failures hold intake and replay "
         "exactly once without losing another writer's bytes") {
        for (int phase = 0; phase < 3; phase++) {
            struct rcv_beat_stats st;
            char ref[64], tag[64];
            (void)snprintf(ref, sizeof(ref), "job-durable-%d", phase);
            (void)snprintf(tag, sizeof(tag), "append-retry-%d", phase);
            ASSERT(bmx_setup(tag));
            ASSERT(bmx_sent(ref));
            bmx_carry(BMX_A, BMX_B);
            ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl",
                             "other-writer\n", "wb"));
            g_bmx_io_phase = phase;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            ASSERT(st.board_deferred >= 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl",
                                "other-writer", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", ref, NULL),
                      phase == 0 ? 0 : 1);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                                "import_after=1", NULL), 0);
            ASSERT_EQ(bmx_queued(ref), 0);
            g_bmx_io_phase = -1;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.admitted, 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", ref,
                                "\"board_signer\""), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl",
                                "other-writer", NULL), 1);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                                "import_after=1", NULL), 1);
            ASSERT_EQ(bmx_queued(ref), 1);
            bmx_forget(BMX_B, "receive/boardmail.state");
            bmx_forget(BMX_B, "receive/intake.state");
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", ref,
                                "\"board_signer\""), 1);
            ASSERT_EQ(bmx_queued(ref), 1);
            bmx_teardown();
        }
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_partial_row(void)
{
    int failures = 0;
    TEST("boardmail: a partial JSON row defers, then its completed carrier "
         "row dedupes and admits once") {
        struct rcv_beat_stats st;
        char row[4096], stored[8192], partial[8192];
        size_t cut = 100;
        ASSERT(bmx_setup("partial-row"));
        ASSERT(bmx_sent("job-partial"));
        bmx_carry(BMX_A, BMX_B);
        ASSERT(bmx_outbox_row("job-partial", row, sizeof(row)));
        (void)snprintf(stored, sizeof(stored),
                       "%.*s,\"board_post\":\"%s\",\"board_signer\":\"%s\"}\n",
                       (int)(strlen(row) - 1), row, g_bmx_node[BMX_B].p[0].id,
                       g_bmx_host[BMX_A]);
        (void)snprintf(partial, cut + 1, "%s", stored);
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", partial, "wb"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 0);
        ASSERT(st.board_deferred >= 1);
        ASSERT_EQ(bmx_size(BMX_B, "mail/inbox.node-a.jsonl"), (long long)cut);
        ASSERT_EQ(bmx_queued("job-partial"), 0);
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", stored + cut, "ab"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_size(BMX_B, "mail/inbox.node-a.jsonl"),
                  (long long)strlen(stored));
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-partial",
                            "\"board_signer\""), 1);
        ASSERT_EQ(bmx_queued("job-partial"), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

struct bmx_ref_append_probe {
    long long in, admitted, queued, inbox, ref, ack_local, result_local;
    long long sent_before, sent_after, delivered, ack_received, result_received;
    long long import_before, import_after, export_before, export_after, ref_after;
    bool signed_ack, signed_result;
};

static long long bmx_ref_probe_cursor(int box, const char *key)
{
    char path[1600], line[256];
    (void)snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.state", g_bmx_state[box]);
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    long long value = -1; size_t len = strlen(key);
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, key, len) && line[len] == '=') value = strtoll(line + len + 1, NULL, 10);
    if (ferror(f)) value = -1;
    if (fclose(f) != 0) value = -1;
    return value;
}

struct bmx_log_capture {
    int fd, saved;
    enum zcl_log_level prior;
    bool redirected;
    char path[PATH_MAX];
};

static bool bmx_log_capture_open(struct bmx_log_capture *c)
{
    memset(c, 0, sizeof(*c));
    c->fd = c->saved = -1;
    c->prior = zcl_log_level_get();
    if (fflush(stderr) != 0)
        return false;
    c->saved = dup(STDERR_FILENO);
    if (c->saved < 0)
        return false;
    c->fd = test_mkstemp(c->path, sizeof(c->path), "boardmail_export_log");
    if (c->fd < 0 || dup2(c->fd, STDERR_FILENO) != STDERR_FILENO)
        return false;
    c->redirected = true;
    zcl_log_level_set(ZCL_LOG_WARN);
    return true;
}

static bool bmx_log_capture_read(struct bmx_log_capture *c, char *out,
                                 size_t cap)
{
    ssize_t n;
    if (!c->redirected || cap < 2u || fflush(stderr) != 0 ||
        lseek(c->fd, 0, SEEK_SET) != 0)
        return false;
    n = read(c->fd, out, cap - 1u);
    if (n < 0 || (size_t)n >= cap - 1u)
        return false;
    out[n] = '\0';
    return true;
}

static bool bmx_log_capture_close(struct bmx_log_capture *c)
{
    bool ok = true;
    zcl_log_level_set(c->prior);
    if (c->saved >= 0 && dup2(c->saved, STDERR_FILENO) != STDERR_FILENO)
        ok = false;
    if (c->saved >= 0 && close(c->saved) != 0)
        ok = false;
    if (c->fd >= 0 && close(c->fd) != 0)
        ok = false;
    if (c->path[0] && unlink(c->path) != 0)
        ok = false;
    return ok;
}

static bool bmx_capture_drive_log(int box, struct rcv_beat_stats *st,
                                  char *out, size_t cap)
{
    struct bmx_log_capture c;
    bool opened = bmx_log_capture_open(&c);
    bool drove = opened && bmx_drive(box, st) == 1;
    bool captured = opened && bmx_log_capture_read(&c, out, cap);
    bool closed = bmx_log_capture_close(&c);
    return opened && drove && captured && closed;
}

static int bmx_t_export_rpc_down(void)
{
    int failures = 0;
    const char *saved_datadir = node_rpc_client_datadir();
    int saved_port = node_rpc_client_port();
    char datadir_copy[PATH_MAX], grant[64], error[128];
    (void)snprintf(datadir_copy, sizeof(datadir_copy), "%s", saved_datadir);
    TEST("boardmail: an unanswered export names its held cursor and read-only RPC check") {
        struct rcv_beat_stats st;
        char before[4096], after[4096], log[8192];
        ASSERT(bmx_setup("export-rpc-down"));
        node_rpc_client_init(g_bmx_base, 19381);
        ASSERT_EQ(node_rpc_client_port(), 19381);
        /* Establish a saved zero cursor before adding the row to be held. */
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(bmx_ref_probe_cursor(BMX_A, "export_offset"), 0);
        bmx_use(BMX_A);
        ASSERT(bmx_grant("chatgpt", NULL, grant, sizeof(grant)));
        ASSERT(bmx_send(grant, "node-b", "job-rpc-down", g_bmx_body,
                        error, sizeof(error)));
        ASSERT(bmx_outbox_row("job-rpc-down", before, sizeof(before)));
        g_bmx_node[BMX_A].down = true;
        ASSERT(bmx_capture_drive_log(BMX_A, &st, log, sizeof(log)));
        ASSERT(st.board_deferred >= 1);
        ASSERT_EQ(st.board_out, 0);
        ASSERT_EQ(bmx_ref_probe_cursor(BMX_A, "export_offset"), 0);
        ASSERT(bmx_outbox_row("job-rpc-down", after, sizeof(after)));
        ASSERT_STR_EQ(before, after);
        ASSERT(strstr(log, "board response unverified") != NULL);
        ASSERT(strstr(log, "rpcport=19381") != NULL);
        ASSERT(strstr(log, "stage=export/post") != NULL);
        ASSERT(strstr(log, "export_offset=0") != NULL);
        ASSERT(strstr(log,
                      "fleet board status on this receiver's selected "
                      "datadir, rpcport=19381") != NULL);
        g_bmx_node[BMX_A].down = false;
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ(bmx_ref_probe_cursor(BMX_A, "export_offset"),
                  (long long)strlen(before) + 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        ASSERT(bmx_outbox_row("job-rpc-down", after, sizeof(after)));
        ASSERT_STR_EQ(before, after);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 0);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        bmx_teardown();
        node_rpc_client_init(datadir_copy, saved_port);
        PASS();
    }
_test_next:
    bmx_teardown();
    node_rpc_client_init(datadir_copy, saved_port);
    return failures;
}

static bool bmx_ref_probe_signature(const struct bmx_post *post)
{
    struct fleet_board_post wire; uint8_t id[32];
    return post && !strcmp(post->host, g_bmx_host[BMX_B]) && bmx_post_wire(post, &wire) &&
        fleet_board_post_compute_id(&wire, id) == FLEET_BOARD_OK && !memcmp(id, wire.id, 32) &&
        fleet_board_post_verify(&wire) == FLEET_BOARD_OK;
}

static bool bmx_ref_probe_result(void)
{
    struct rcv_beat_stats st;
    return bmx_mail("node-b", "*", "result", "job-1", "worker=node-b\nstate=done\nverdict=pass\n") &&
        bmx_drive(BMX_B, &st) == 1;
}

static bool bmx_ref_probe_unrelated(void)
{
    struct rcv_beat_stats st;
    return bmx_mail("node-b", "*", "result", "unrelated", "worker=node-b\nstate=done\nverdict=pass\n") &&
        bmx_drive(BMX_B, &st) == 1;
}

static bool bmx_ref_probe_prepare(bool deny)
{
    struct rcv_beat_stats st;
    if (!bmx_setup(deny ? "ref-append-denied" : "ref-append-control") ||
        !bmx_sent("job-1") || bmx_drive(BMX_B, &st) != 1 ||
        !bmx_write(BMX_B, "receive/boardmail.refs", "", "wb")) return false;
    return geteuid() != 0;
}

static bool bmx_ref_probe_restore(bool deny, struct bmx_ref_append_probe *p)
{
    struct rcv_beat_stats st;
    if (bmx_drive(BMX_B, &st) != 1) return false;
    if (deny && (!bmx_ref_probe_result() || !bmx_ref_probe_unrelated())) return false;
    p->sent_after = bmx_signed_by(BMX_B, BMX_B);
    p->import_after = bmx_ref_probe_cursor(BMX_B, "import_after");
    p->export_after = bmx_ref_probe_cursor(BMX_B, "export_offset");
    p->ref_after = bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL);
    if (p->sent_after == 2) {
        p->signed_ack = bmx_ref_probe_signature(&g_bmx_node[BMX_B].p[1]);
        p->signed_result = bmx_verified_result(&g_bmx_node[BMX_B].p[2]);
    }
    bmx_carry(BMX_B, BMX_A);
    if (bmx_drive(BMX_A, &st) != 1) return false;
    p->delivered = st.board_in;
    p->ack_received = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", "state=accepted");
    p->result_received = bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "job-1", "state=done");
    return true;
}

static bool bmx_ref_append_probe(bool deny, struct bmx_ref_append_probe *p)
{
    struct rcv_beat_stats st; char path[1600]; bool restricted = false;
    bool ok = bmx_ref_probe_prepare(deny);
    int n = snprintf(path, sizeof(path), "%s/z23/dev/receive/boardmail.refs", g_bmx_state[BMX_B]);
    ok = ok && n > 0 && (size_t)n < sizeof(path) && geteuid() != 0;
    if (ok && deny) { restricted = chmod(path, 0400) == 0; ok = restricted; }
    if (ok) {
        bmx_carry(BMX_A, BMX_B);
        ok = bmx_drive(BMX_B, &st) == 1;
        p->in = st.board_in; p->admitted = st.admitted; p->queued = bmx_queued("job-1");
        p->inbox = bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-1", "board_signer");
        p->ref = bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL);
        p->ack_local = bmx_lines(BMX_B, "mail/outbox.jsonl", "job-1", "state=accepted");
        if (!deny)
            ok = ok && bmx_ref_probe_result();
        p->result_local = bmx_lines(BMX_B, "mail/outbox.jsonl", "job-1", "state=done");
        p->sent_before = bmx_signed_by(BMX_B, BMX_B);
        p->import_before = bmx_ref_probe_cursor(BMX_B, "import_after");
        p->export_before = bmx_ref_probe_cursor(BMX_B, "export_offset");
    }
    if (restricted && chmod(path, 0600) != 0) ok = false;
    if (ok) ok = bmx_ref_probe_restore(deny, p);
    bmx_teardown(); return ok;
}

static int bmx_t_refs_append_observation(void)
{
    int failures = 0; struct bmx_ref_append_probe control = {0}, denied = {0};
    TEST("boardmail: observe return routing after a reference append refusal") {
        ASSERT(bmx_ref_append_probe(false, &control));
        ASSERT(bmx_ref_append_probe(true, &denied));
        printf("REFS_APPEND_CONTROL in=%lld admitted=%lld queued=%lld inbox=%lld ref=%lld/%lld ack_local=%lld result_local=%lld sent=%lld/%lld delivered=%lld ack=%lld result=%lld signed=%d/%d cursor=%lld/%lld,%lld/%lld\n",
            control.in, control.admitted, control.queued, control.inbox, control.ref, control.ref_after,
            control.ack_local, control.result_local, control.sent_before, control.sent_after, control.delivered,
            control.ack_received, control.result_received, control.signed_ack, control.signed_result,
            control.import_before, control.import_after, control.export_before, control.export_after);
        printf("REFS_APPEND_DENIED in=%lld admitted=%lld queued=%lld inbox=%lld ref=%lld/%lld ack_local=%lld result_local=%lld sent=%lld/%lld delivered=%lld ack=%lld result=%lld signed=%d/%d cursor=%lld/%lld,%lld/%lld\n",
            denied.in, denied.admitted, denied.queued, denied.inbox, denied.ref, denied.ref_after,
            denied.ack_local, denied.result_local, denied.sent_before, denied.sent_after, denied.delivered,
            denied.ack_received, denied.result_received, denied.signed_ack, denied.signed_result,
            denied.import_before, denied.import_after, denied.export_before, denied.export_after);
        ASSERT_EQ(control.in, 1); ASSERT_EQ(control.admitted, 1); ASSERT_EQ(control.queued, 1); ASSERT_EQ(control.ref, 1);
        ASSERT_EQ(control.sent_after, 2); ASSERT_EQ(control.delivered, 2); ASSERT(control.signed_ack); ASSERT(control.signed_result);
        ASSERT_EQ(denied.in, 0); ASSERT_EQ(denied.admitted, 0); ASSERT_EQ(denied.queued, 0); ASSERT_EQ(denied.ref, 0); ASSERT_EQ(denied.ref_after, 1);
        ASSERT_EQ(denied.sent_before, 0); ASSERT_EQ(denied.sent_after, 2); ASSERT_EQ(denied.delivered, 2);
        ASSERT(denied.signed_ack); ASSERT(denied.signed_result); ASSERT_EQ(denied.ack_received, 1); ASSERT_EQ(denied.result_received, 1);
        PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_refs_durable_retry(void)
{
    int failures = 0;
    TEST("boardmail: incoming ref append and sync failures defer and retry once") {
        for (int phase = 0; phase < 3; phase++) {
            struct rcv_beat_stats st;
            ASSERT(bmx_setup("refs-durable-retry"));
            ASSERT(bmx_sent("job-1"));
            bmx_carry(BMX_A, BMX_B);
            g_bmx_ref_fault = true;
            g_bmx_io_phase = phase;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(g_bmx_io_phase, -1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-1", NULL), 0);
            g_bmx_ref_fault = false;
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 1);
            ASSERT_EQ(st.admitted, 1);
            ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL), 1);
            ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
            ASSERT_EQ(st.board_in, 0);
            ASSERT_EQ(st.admitted, 0);
            bmx_teardown();
        }
        PASS();
    }
_test_next:;
    g_bmx_ref_fault = false; g_bmx_io_phase = -1;
    bmx_teardown(); return failures;
}

static int bmx_exit_before_inbox(const char *path, int phase)
{
    if (phase == 0 && strstr(path, "inbox.node-a.jsonl")) _exit(78);
    return 0;
}

static bool bmx_inbox_alloc_log(struct rcv_beat_stats *st)
{
    FILE *capture = tmpfile();
    int saved = -1;
    bool ok = false;
    if (!capture || (saved = dup(STDERR_FILENO)) < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) goto done;
    zcl_alloc_fault_fail_next("boardmail.inbox_append");
    int drove = bmx_drive(BMX_B, st);
    zcl_alloc_fault_clear();
    fflush(stderr);
    if (dup2(saved, STDERR_FILENO) < 0) goto done;
    close(saved);
    saved = -1;
    if (fseek(capture, 0, SEEK_SET)) goto done;
    char line[2048];
    while (fgets(line, sizeof(line), capture)) {
        if (strstr(line, "inbox stage=allocation") && strstr(line, "inspect available memory") &&
            strstr(line, "receiver retries on a later beat") && !strstr(line, "inspect inbox access")) ok = true;
    }
    ok = ok && drove == 1;
done:
    zcl_alloc_fault_clear();
    if (saved >= 0) {
        (void)dup2(saved, STDERR_FILENO);
        close(saved);
    }
    if (capture) fclose(capture);
    return ok;
}
static int bmx_t_inbox_alloc_diagnostic(void)
{
    int failures = 0;
    TEST("boardmail: inbox allocation failure reports memory and retries") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("inbox-allocation-guidance"));
        ASSERT(bmx_sent("job-1")); bmx_carry(BMX_A, BMX_B);
        long long before = bmx_ref_probe_cursor(BMX_B, "import_after");
        ASSERT(bmx_inbox_alloc_log(&st));
        ASSERT(st.board_deferred >= 1); ASSERT_EQ(st.board_in, 0); ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(bmx_ref_probe_cursor(BMX_B, "import_after"), before);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-1", NULL), 0);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1); ASSERT_EQ(st.board_in, 1); ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1); ASSERT_EQ(st.board_in, 0);
        PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}
static int bmx_t_refs_before_inbox_crash(void)
{
    int failures = 0, status = 0;
    pid_t child = -1;
    TEST("boardmail: restart after durable incoming ref before inbox admits once") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("refs-before-inbox-crash"));
        ASSERT(bmx_sent("job-1"));
        bmx_carry(BMX_A, BMX_B);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            zcl_devagent_boardmail_test_io(bmx_exit_before_inbox);
            (void)bmx_drive(BMX_B, &st);
            _exit(1);
        }
        ASSERT_EQ(waitpid(child, &status, 0), child);
        child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 78);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-1", NULL), 0);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL), 1);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 0);
        PASS();
    }
_test_next:;
    if (child > 0) (void)waitpid(child, NULL, 0);
    bmx_teardown(); return failures;
}

static int bmx_t_refs_invalid_successor(void)
{
    int failures = 0;
    TEST("boardmail: unroutable ref does not pin a valid successor") {
        struct rcv_beat_stats st;
        char row[4096], ts[32];
        long long now = (long long)platform_time_wall_time_t();
        ASSERT(bmx_setup("refs-invalid-successor"));
        bmx_ts(now, ts, sizeof(ts));
        bmx_row(row, sizeof(row), ts, "", "No return reference.");
        ASSERT(bmx_inject(BMX_B, BMX_A, row, now, 3600) != NULL);
        ASSERT(bmx_sent("job-1"));
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 2);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_queued("job-1"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.refs", "in job-1 node-a", NULL), 1);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        PASS();
    }
_test_next:;
    bmx_teardown(); return failures;
}

static int bmx_t_locked_append(void)
{
    int failures = 0;
    TEST("boardmail: a concurrent inbox lock defers the cursor, then another "
         "writer's completed row is preserved and deduped") {
        struct rcv_beat_stats st;
        struct platform_private_file lock;
        char row[4096], path[1600];
        ASSERT(bmx_setup("locked-append"));
        ASSERT(bmx_sent("job-locked"));
        bmx_carry(BMX_A, BMX_B);
        ASSERT(bmx_outbox_row("job-locked", row, sizeof(row)));
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", "", "wb"));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/mail/inbox.node-a.jsonl",
                       g_bmx_state[BMX_B]);
        platform_private_file_init(&lock);
        ASSERT(platform_private_file_open_locked_create(path, &lock));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT(st.board_deferred >= 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                            "import_after=1", NULL), 0);
        ASSERT(bmx_inbox_forge("node-a", row, g_bmx_node[BMX_B].p[0].id,
                               g_bmx_host[BMX_A]));
        platform_private_file_close(&lock);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        ASSERT_EQ(st.admitted, 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/inbox.node-a.jsonl", "job-locked",
                            "\"board_signer\""), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "receive/boardmail.state",
                            "import_after=1", NULL), 1);
        ASSERT_EQ(bmx_queued("job-locked"), 1);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

static int bmx_t_transport_observation(void)
{
    int failures = 0;
    TEST("boardmail: transport observation distinguishes ready, down and malformed") {
        struct json_value out;
        ASSERT(bmx_setup("transport-observation"));
        json_init(&out);
        json_set_object(&out);
        zcl_devagent_boardmail_observe_transport(&out);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_state")), "ready");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_detail")), "");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_epoch")), "00000000000000000000000000000001");
        ASSERT_EQ(json_get_int(json_get(&out, "board_scanned")), 0);
        ASSERT_EQ(json_get_int(json_get(&out, "board_returned")), 0);
        json_free(&out);
        g_bmx_node[BMX_A].down = true;
        json_init(&out);
        json_set_object(&out);
        zcl_devagent_boardmail_observe_transport(&out);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_state")), "unavailable");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_detail")), "node_rpc_client_call");
        json_free(&out);
        g_bmx_node[BMX_A].down = false;
        g_bmx_node[BMX_A].page_fault = BMX_PAGE_MISSING_EPOCH;
        json_init(&out);
        json_set_object(&out);
        zcl_devagent_boardmail_observe_transport(&out);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_state")), "invalid-response");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_detail")), "epoch");
        json_free(&out);
        g_bmx_node[BMX_A].page_fault = BMX_PAGE_OK;
        g_bmx_node[BMX_A].refuse = true;
        json_init(&out);
        json_set_object(&out);
        zcl_devagent_boardmail_observe_transport(&out);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_state")), "refused");
        ASSERT_STR_EQ(json_get_str(json_get(&out, "board_detail")), "TEST_REFUSED");
        json_free(&out);
        bmx_teardown();
        PASS();
    }
_test_next:;
    bmx_teardown();
    return failures;
}

#endif /* !defined(_WIN32) */

int test_devagent_boardmail(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += bmx_t_round_trip();
    failures += bmx_t_unbound_operator();
    failures += bmx_t_regossip();
    failures += bmx_t_incomplete_page();
    failures += bmx_t_crash_between();
    failures += bmx_t_forged();
    failures += bmx_t_wrong_signer();
    failures += bmx_t_unsigned();
    failures += bmx_t_expired();
    failures += bmx_t_deferred();
    failures += bmx_t_state_unreadable();
    failures += bmx_t_refs_unreadable();
    failures += bmx_t_oversize();
    failures += bmx_t_delivery();
    failures += bmx_t_push_hint();
    failures += bmx_t_refs_wrap();
    failures += bmx_t_directory();
    failures += bmx_t_directory_crowded();
    failures += bmx_t_append_retry();
    failures += bmx_t_partial_row();
    failures += bmx_t_locked_append();
    failures += bmx_t_refs_append_observation();
    failures += bmx_t_refs_durable_retry();
    failures += bmx_t_inbox_alloc_diagnostic();
    failures += bmx_t_refs_before_inbox_crash();
    failures += bmx_t_refs_invalid_successor();
    failures += bmx_t_export_rpc_down();
    failures += bmx_t_transport_observation();
#endif
    if (failures == 0)
        printf("test_devagent_boardmail: all passed\n");
    else
        printf("test_devagent_boardmail: %d FAILED\n", failures);
    return failures;
}
