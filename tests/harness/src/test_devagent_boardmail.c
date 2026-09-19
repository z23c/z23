/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for board-carried agent mail
 * (tools/command/native_devagent_boardmail.c, and its seams in
 * native_devagent_receive.c, native_devagent_mail.c and
 * native_fleet_steer.c): a directive sent on one box reaches the receiver
 * on another box over the signed FLEET board, becomes queued work there
 * exactly once, and its answers come back — with no script and no SSH.
 *
 * TWO BOXES, ONE PROCESS. Box A and box B are two isolated state roots
 * (XDG_STATE_HOME switched per step), each with its own mail dir, queue,
 * steer grants, receiver cursors and a fleet roster sealed by one test
 * operator key. Each box's node is a small in-process model of the
 * `fleet_board` RPC (post, fleet_page, show) installed through the rpc
 * client's test hook: a post's id is a digest of its signed fields, so a
 * re-post of the same content is the same post, an expired post is never
 * paged, and show answers NOT_FOUND for an unknown id. Carriage between the
 * two nodes (what the paired fleet pull does, proven in the fleet_board
 * group) is an explicit copy by id. No model, no network, no spawn.
 *
 * Cases: the A->B->answer->A round trip; a re-gossiped post and a re-read
 * page deliver once; a crash between export and import delivers once on
 * restart; a forged inbox line is refused MISMATCH; a wrong signer is
 * refused UNENROLLED or UNGRANTED; partial board fields are refused
 * UNSIGNED; an expired post is never delivered late; a node that does not
 * answer defers without a marker and the row is decided later; a directive
 * for another box too large for one board note is refused at send.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

int test_devagent_boardmail(void);

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
    char host[65];
    char text[BMX_TEXT];
    char agent[80];
    char receipt[64];
    long long created, ttl, arrival;
};

struct bmx_node {
    struct bmx_post p[BMX_POSTS];
    size_t n;
    long long next_arrival;
    char epoch[33];
    bool down;      /* no node answers at all */
    bool show_down; /* the node answers everything but show */
};

static struct bmx_node g_bmx_node[2];
static int g_bmx_active;
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

/* A post id: a digest of every field the real board signs, so the same
 * content at the same created_at is the same post, as with Ed25519. */
static void bmx_post_id(const struct bmx_post *p, char out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char sum[SHA3_256_OUTPUT_SIZE];
    char head[256];
    (void)snprintf(head, sizeof(head), "%s|%lld|%lld|%s|%s|", p->host,
                   p->created, p->ttl, p->agent, p->receipt);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)head, strlen(head));
    sha3_256_write(&ctx, (const unsigned char *)p->text, strlen(p->text));
    sha3_256_finalize(&ctx, sum);
    bmx_hex(sum, sizeof(sum), out);
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
    memset(&p, 0, sizeof(p));
    (void)snprintf(p.host, sizeof(p.host), "%s", g_bmx_host[host]);
    (void)snprintf(p.text, sizeof(p.text), "%s", text);
    (void)snprintf(p.receipt, sizeof(p.receipt), "z23.mail.v1");
    p.created = created;
    p.ttl = ttl;
    bmx_post_id(&p, p.id);
    return bmx_store(node, &p);
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
    memset(&p, 0, sizeof(p));
    p.created = json_get_int(json_get(in, "created_at"));
    p.ttl = json_get_int(json_get(in, "ttl"));
    if (strlen(text) > 2048) {
        bmx_refuse(out, "TEXT_TOO_LONG");
        return;
    }
    if (p.created + p.ttl <= now) {
        bmx_refuse(out, "CREATED_AT_EXPIRED");
        return;
    }
    (void)snprintf(p.host, sizeof(p.host), "%s", g_bmx_host[g_bmx_active]);
    (void)snprintf(p.text, sizeof(p.text), "%s", text);
    (void)snprintf(p.agent, sizeof(p.agent), "%s",
                   json_get_str(json_get(in, "agent")));
    (void)snprintf(p.receipt, sizeof(p.receipt), "%s",
                   json_get_str(json_get(in, "receipt")));
    bmx_post_id(&p, p.id);
    stored = bmx_store(g_bmx_active, &p);
    if (!stored) {
        bmx_refuse(out, "BOARD_REFUSED");
        return;
    }
    (void)json_push_kv_bool(out, "ok", true);
    (void)json_push_kv_str(out, "id", stored->id);
}

static void bmx_op_page(const struct json_value *in, struct json_value *out,
                        long long now)
{
    struct bmx_node *n = &g_bmx_node[g_bmx_active];
    long long after = json_get_int(json_get(in, "after"));
    long long limit = json_get_int(json_get(in, "limit"));
    long long scanned = after;
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
        (void)json_push_back(&arr, &item);
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
        else if (strcmp(op, "post") == 0)
            bmx_op_post(in, &out, now);
        else if (strcmp(op, "fleet_page") == 0)
            bmx_op_page(in, &out, now);
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
 * signing (node) key from `signer_byte`. */
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
    bmx_key(signer_byte, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, 24, "", op_seed, op_pub, BMX_NOW, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire,
                              sizeof(invite_wire), &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                              box_seed, box_pub, &signer, receipt,
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
    for (int b = 0; bmx_ok(&c) && b < 2; b++) {
        const struct json_value *arr = json_get(&c.reply.data, buckets[b]);
        size_t n = (arr && arr->type == JSON_ARR) ? json_size(arr) : 0u;
        for (size_t i = 0; i < n; i++) {
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
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if ((!n1 || strstr(line, n1)) && (!n2 || strstr(line, n2)))
            hits++;
    }
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
    return bmx_checkout(g_bmx_ws) && bmx_roster(BMX_A) && bmx_roster(BMX_B);
}

static void bmx_teardown(void)
{
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
        /* The worker's result, which it posts to everyone. */
        ASSERT(bmx_mail("node-b", "*", "result", "job-1",
                        "worker=node-b\nstate=done\nverdict=pass\n"));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        bmx_carry(BMX_B, BMX_A);
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_in, 2);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl",
                            "state=accepted", "\"job-1\""), 1);
        ASSERT_EQ(bmx_lines(BMX_A, "mail/inbox.node-b.jsonl", "state=done",
                            "\"job-1\""), 1);
        /* Nothing local-only left either box: A signed one post (the
         * directive), B signed two (its accept and the result), and the
         * carriage left the same three on both nodes. */
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_A), 1);
        ASSERT_EQ(bmx_signed_by(BMX_A, BMX_B), 2);
        ASSERT_EQ((long long)g_bmx_node[BMX_B].n, 3);
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
        ASSERT(bmx_inject(BMX_B, BMX_A, row,
                          (long long)platform_time_wall_time_t() - 5,
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

static int bmx_t_crash_between(void)
{
    int failures = 0;
    TEST("boardmail: a crash between export and import delivers once on "
         "restart") {
        struct rcv_beat_stats st;
        ASSERT(bmx_setup("crash"));
        ASSERT(bmx_sent("job-3"));
        /* A died before it recorded the export: it posts again on restart,
         * the same bytes, the same post. */
        bmx_forget(BMX_A, "receive/boardmail.state");
        ASSERT_EQ(bmx_drive(BMX_A, &st), 1);
        ASSERT_EQ(st.board_out, 1);
        ASSERT_EQ((long long)g_bmx_node[BMX_A].n, 1);
        bmx_carry(BMX_A, BMX_B);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.admitted, 1);
        /* B died after the inbox append but before either cursor was
         * saved: the page is carried again and the intake replayed. */
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
        /* The genuine post id and signer, under a different ref and body,
         * written BEFORE the genuine row is imported: naming a post id must
         * neither admit the forgery nor stop the genuine row arriving. */
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
        struct bmx_post *p;
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
        p = bmx_inject(BMX_B, 3, row, now, 3600);
        ASSERT(p != NULL);
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-d.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-d", row, p->id, g_bmx_host[3]));
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 1);
        ASSERT_EQ(st.admitted, 0);
        ASSERT_EQ(st.refused, 2);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_UNGRANTED", "job-5c"), 1);
        ASSERT_EQ(bmx_lines(BMX_B, "mail/outbox.jsonl",
                            "reason=RECEIVE_PEER_UNENROLLED", "job-5d"), 1);
        ASSERT_EQ(bmx_queued("job-5c") + bmx_queued("job-5d"), 0);
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
        struct bmx_post *p;
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
        p = bmx_inject(BMX_B, BMX_A, row, now - 7200, 3600);
        ASSERT(p != NULL);
        ASSERT_EQ(bmx_drive(BMX_B, &st), 1);
        ASSERT_EQ(st.board_in, 0);
        /* And a line naming it is refused, not admitted late. */
        ASSERT(bmx_write(BMX_B, "mail/inbox.node-a.jsonl", "", "ab"));
        ASSERT(bmx_inbox_forge("node-a", row, p->id, g_bmx_host[BMX_A]));
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

#endif /* !defined(_WIN32) */

int test_devagent_boardmail(void)
{
    int failures = 0;
#if !defined(_WIN32)
    failures += bmx_t_round_trip();
    failures += bmx_t_regossip();
    failures += bmx_t_crash_between();
    failures += bmx_t_forged();
    failures += bmx_t_wrong_signer();
    failures += bmx_t_unsigned();
    failures += bmx_t_expired();
    failures += bmx_t_deferred();
    failures += bmx_t_oversize();
#endif
    if (failures == 0)
        printf("test_devagent_boardmail: all passed\n");
    else
        printf("test_devagent_boardmail: %d FAILED\n", failures);
    return failures;
}
