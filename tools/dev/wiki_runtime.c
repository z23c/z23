/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: bounded native wiki propagation evidence using production signatures. */
#include "wiki_runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "util/spawn.h"
#include "platform/private_file.h"
#include "platform/clock.h"
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

bool wr_read_regular(const char *path, void *bytes, size_t cap, size_t *length)
{
    if (length) *length = 0;
    if (!path || !bytes || !length) return false;
    struct platform_private_file file; platform_private_file_init(&file);
    if (!platform_private_file_open_observation(path, &file)) return false;
    uint64_t size = 0, after = 0;
    bool ok = platform_private_file_size(&file, &size) && size <= cap &&
        platform_private_file_read_at(&file, bytes, (size_t)size, 0) &&
        platform_private_file_size(&file, &after) && after == size;
    platform_private_file_close(&file);
    if (ok) *length = (size_t)size;
    return ok;
}

static bool wr_fail(const char **why, const char *reason)
{
    if (why) *why = reason;
    return false;
}
static bool wr_unique(const struct json_value *v)
{
    if (!v || v->type != JSON_OBJ) return false;
    for (size_t i = 0; i < v->num_children; i++)
        for (size_t j = 0; j < i; j++)
            if (!strcmp(v->keys[i], v->keys[j])) return false;
    return true;
}
static bool wr_str(const struct json_value *v, const char *key,
    char *out, size_t cap, bool optional)
{
    const struct json_value *item = json_get(v, key);
    if (!item && optional) { out[0] = 0; return true; }
    const char *s = json_get_str(item);
    if (!s || strlen(s) >= cap) return false;
    memcpy(out, s, strlen(s) + 1); return true;
}
static bool wr_num(const struct json_value *v, const char *key,
    int64_t low, int64_t high, int64_t *out)
{
    const struct json_value *item = json_get(v, key);
    if (!item || item->type != JSON_INT) return false;
    *out = json_get_int(item);
    return *out >= low && *out <= high;
}
static bool wr_hex(const struct json_value *v, const char *key,
    uint8_t *out, size_t count)
{
    return zcl_hex_decode_lower(json_get_str(json_get(v, key)), out, count);
}
static bool wr_label(const char *s)
{
    size_t n = strlen(s);
    if (!n || n > 24) return false;
    for (size_t i = 0; i < n; i++)
        if (!(s[i] >= 'a' && s[i] <= 'z') &&
            !(s[i] >= '0' && s[i] <= '9') && s[i] != '-') return false;
    return s[0] != '-' && s[n-1] != '-';
}
static enum wr_role wr_role_read(const struct json_value *v)
{
    const char *s = json_get_str(json_get(v, "role"));
    if (!s) return 0;
    if (!strcmp(s, "writer")) return WR_WRITER;
    if (!strcmp(s, "reader")) return WR_READER;
    return !strcmp(s, "both") ? WR_BOTH : 0;
}
static bool wr_peer_identity(const struct json_value *v, struct wr_participant *p)
{
    uint8_t source[20], artifact[32];
    return wr_str(v, "name", p->name, sizeof(p->name), false) && wr_label(p->name) &&
        wr_str(v, "platform", p->platform, sizeof(p->platform), false) && wr_label(p->platform) &&
        wr_str(v, "source", p->source, sizeof(p->source), false) &&
        zcl_hex_decode_lower(p->source, source, sizeof(source)) &&
        wr_str(v, "artifact", p->artifact, sizeof(p->artifact), false) &&
        zcl_hex_decode_lower(p->artifact, artifact, sizeof(artifact)) && wr_hex(v, "host", p->host, 32);
}
static bool wr_peer_scope(const struct json_value *v, struct wr_participant *p)
{
    int64_t scope;
    if (!wr_num(v, "signed_scope", 0, 2, &scope) ||
        !wr_str(v, "signed_room", p->room, sizeof(p->room), false)) return false;
    p->scope = (uint8_t)scope;
    if ((scope == FLEET_BOARD_SCOPE_PUBLIC && !fleet_board_room_valid(p->room)) ||
        (scope != FLEET_BOARD_SCOPE_PUBLIC && p->room[0])) return false;
    return true;
}
static bool wr_fixture_path(const char *dd)
{
    const char *const roots[] = {"-datadir=/tmp/zcl23-", "-datadir=/private/tmp/zcl23-"};
    for (size_t i = 0; i < sizeof(roots)/sizeof(roots[0]); i++) {
        size_t n = strlen(roots[i]);
        if (!strncmp(dd, roots[i], n) && dd[n] && !strchr(dd+n, '/')) return true;
    }
    return false;
}
static bool wr_native_prefix(const struct wr_participant *p)
{
    if (p->argv[0][0] != '/' || p->argc != 3) return false;
    const char *base = strrchr(p->argv[0], '/');
    base = base ? base+1 : p->argv[0];
    if (strcmp(base, "z23") && strcmp(base, "z23-dev") && strcmp(base, "zclassic23")) return false;
    if (!wr_fixture_path(p->argv[1])) return false;
    const char *port = p->argv[2];
    if (strncmp(port, "-rpcport=", 9)) return false;
    char *end = NULL;
    long n = strtol(port+9, &end, 10);
    return end && !*end && n >= 39000 && n <= 39999;
}
static bool wr_peer_read(const struct json_value *v, struct wr_participant *p)
{
    if (!wr_unique(v) || !wr_peer_identity(v, p) || !wr_peer_scope(v, p)) return false;
    p->role = wr_role_read(v);
    const struct json_value *args = json_get(v, "argv");
    if (!p->role || !args || args->type != JSON_ARR ||
        !(p->argc = json_size(args)) || p->argc > WR_ARGS) return false;
    for (size_t i = 0; i < p->argc; i++) {
        const char *arg = json_get_str(json_at(args, i));
        if (!arg) return false;
        size_t arg_len = strlen(arg);
        if (arg_len >= WR_ARG_CAP) return false;
        memcpy(p->argv[i], arg, arg_len + 1);
    }
    return wr_native_prefix(p);
}
static bool wr_required_valid(const struct json_value *required, const char **why)
{
    for (size_t j = 0; j < json_size(required); j++) {
        const struct json_value *r = json_at(required, j);
        const char *name = json_get_str(json_get(r, "name"));
        if (!wr_unique(r) || !name || !wr_label(name) || !wr_role_read(r))
            return wr_fail(why, "invalid-required-participant");
        for (size_t k = 0; k < j; k++) {
            const char *before = json_get_str(json_get(json_at(required, k), "name"));
            if (!strcmp(name, before)) return wr_fail(why, "duplicate-required-participant");
        }
    }
    return true;
}
static bool wr_required_matches(const struct json_value *required,
    const struct wr_participant *p)
{
    for (size_t j = 0; j < json_size(required); j++) {
        const struct json_value *r = json_at(required, j);
        if (!strcmp(json_get_str(json_get(r, "name")), p->name) && wr_role_read(r) == p->role)
            return true;
    }
    return false;
}
static bool wr_peer_duplicate(const struct wr_plan *plan, size_t index)
{
    const struct wr_participant *p = &plan->participants[index];
    for (size_t j = 0; j < index; j++)
        if (!strcmp(p->name, plan->participants[j].name) ||
            !memcmp(p->host, plan->participants[j].host, 32)) return true;
    return false;
}
static bool wr_plan_arrays(const struct json_value *in, struct wr_plan *out,
    const struct json_value **required, const struct json_value **peers, const char **why)
{
    int64_t ttl;
    if (!wr_unique(in) || !wr_str(in, "run", out->run, sizeof(out->run), false) ||
        !wr_label(out->run) || !wr_num(in, "ttl_seconds", 1, 60, &ttl))
        return wr_fail(why, "invalid-run-or-ttl");
    out->ttl_seconds = (uint32_t)ttl;
    *required = json_get(in, "required"); *peers = json_get(in, "participants");
    if (!*required || (*required)->type != JSON_ARR || !*peers || (*peers)->type != JSON_ARR ||
        json_size(*required) < 2 || json_size(*required) > WR_MAX ||
        json_size(*required) != json_size(*peers)) return wr_fail(why, "required-set");
    return wr_required_valid(*required, why);
}
bool wr_plan_read(const struct json_value *in, struct wr_plan *out, const char **why)
{
    if (!out) return wr_fail(why, "missing-plan-output");
    memset(out, 0, sizeof(*out));
    const struct json_value *required, *peers;
    if (!wr_plan_arrays(in, out, &required, &peers, why)) return false;
    out->count = json_size(peers);
    unsigned roles = 0;
    for (size_t i = 0; i < out->count; i++) {
        struct wr_participant *p = &out->participants[i];
        if (!wr_peer_read(json_at(peers, i), p)) return wr_fail(why, "invalid-participant");
        roles |= (unsigned)p->role;
        if (!wr_required_matches(required, p)) return wr_fail(why, "required-set");
        if (wr_peer_duplicate(out, i)) return wr_fail(why, "duplicate-participant");
    }
    return roles == WR_BOTH || wr_fail(why, "missing-role");
}
static bool wr_post_ids(const struct json_value *v, struct fleet_board_post *p)
{
    return wr_hex(v, "id", p->id, 32) && wr_hex(v, "host", p->host_pubkey, 32) &&
        wr_hex(v, "signature", p->signature, 64) && wr_hex(v, "ref", p->ref, 32) &&
        wr_hex(v, "supersedes", p->supersedes, 32);
}
static bool wr_post_strings(const struct json_value *v, struct fleet_board_post *p)
{
    return wr_str(v, "agent", p->agent, sizeof(p->agent), false) &&
        wr_str(v, "slug", p->slug, sizeof(p->slug), false) &&
        wr_str(v, "title", p->title, sizeof(p->title), false) &&
        wr_str(v, "receipt", p->receipt, sizeof(p->receipt), true) &&
        wr_str(v, "signed_room", p->room, sizeof(p->room), false);
}
static bool wr_post_numbers(const struct json_value *v, struct fleet_board_post *p)
{
    int64_t scope, created, ttl, length;
    if (!wr_num(v, "signed_scope", 0, 2, &scope) ||
        !wr_num(v, "created_at", 0, INT64_MAX, &created) ||
        !wr_num(v, "ttl", 1, FLEET_BOARD_TTL_MAX, &ttl) ||
        !wr_num(v, "text_len", 1, 200, &length)) return false;
    p->kind = FLEET_BOARD_KIND_WIKI; p->scope = (uint8_t)scope;
    p->created_at = (uint64_t)created; p->ttl = (uint32_t)ttl; p->text_len = (uint32_t)length;
    return true;
}
static bool wr_post_chunk(const struct json_value *v, struct fleet_board_post *p)
{
    int64_t offset, next;
    if (!wr_num(v, "offset", 0, 0, &offset) ||
        !wr_num(v, "next_offset", p->text_len, p->text_len, &next)) return false;
    const struct json_value *complete = json_get(v, "complete");
    if (!complete || complete->type != JSON_BOOL || !json_get_bool(complete) ||
        !wr_hex(v, "data_hex", (uint8_t *)p->text, p->text_len)) return false;
    return true;
}
static bool wr_post_fields(const struct json_value *v, struct fleet_board_post *p)
{
    const char *kind = json_get_str(json_get(v, "kind"));
    return kind && !strcmp(kind, "wiki") && wr_unique(v) && wr_post_ids(v, p) &&
        wr_post_strings(v, p) && wr_post_numbers(v, p) && wr_post_chunk(v, p);
}
bool wr_post_read(const struct json_value *reply, struct fleet_board_post *out,
    const char **why)
{
    if (!out) return wr_fail(why, "missing-post-output");
    memset(out, 0, sizeof(*out));
    if (!wr_unique(reply)) return wr_fail(why, "invalid-envelope");
    const struct json_value *ok = json_get(reply, "ok");
    if (!ok || ok->type != JSON_BOOL || !json_get_bool(ok))
        return wr_fail(why, "native-refusal");
    if (!wr_post_fields(json_get(reply, "data"), out)) {
        memset(out, 0, sizeof(*out)); return wr_fail(why, "incomplete-signed-post");
    }
    if (fleet_board_post_verify(out) != FLEET_BOARD_OK) {
        memset(out, 0, sizeof(*out)); return wr_fail(why, "post-crypto-refused");
    }
    return true;
}
int64_t wr_monotonic_ms(void)
{
#ifdef _WIN32
    return -1; /* POSIX coordinator first; Windows owner is separate. */
#else
    int64_t now = clock_now_monotonic_ns();
    return now > 0 ? now / 1000000 : -1;
#endif
}
enum wr_call_state wr_capture(const char *const argv[], int remaining_ms,
    struct json_value *reply)
{
    json_init(reply);
#ifdef _WIN32
    (void)argv; (void)remaining_ms;
    return WR_LAUNCH_FAILED;
#else
    if (remaining_ms <= 0) return WR_TIMEOUT;
    char *bytes = zcl_malloc(WR_REPLY_CAP + 1, "wiki-runtime.capture");
    if (!bytes) return WR_LAUNCH_FAILED;
    struct zcl_spawn_binary_observation observed = {0};
    (void)zcl_spawn_capture_binary(argv, bytes, WR_REPLY_CAP, remaining_ms, &observed);
    enum wr_call_state state = WR_CALL_OK;
    if (observed.timed_out) state = WR_TIMEOUT;
    else if (observed.overflow) state = WR_TRUNCATED;
    else if (!observed.exit_observed) state = WR_UNKNOWN_EXIT;
    else if (!observed.eof) state = WR_LAUNCH_FAILED;
    else {
        bytes[observed.output_len] = 0;
        if (!json_read(reply, bytes, observed.output_len))
            state = observed.exit_code ? WR_EXIT_FAILED : WR_INVALID_JSON;
        else if (observed.exit_code != 0) state = WR_EXIT_FAILED;
    }
    free(bytes);
    if (state != WR_CALL_OK && state != WR_EXIT_FAILED) {
        json_free(reply); json_init(reply);
    }
    return state;
#endif
}
static bool wr_invoke(const struct wr_plan *plan, const struct wr_backend *b,
    size_t peer, const char *op, const struct json_value *input, int64_t deadline,
    struct json_value *reply, const char **why)
{
    json_init(reply);
    int64_t now = b->now_ms(b->ctx);
    if (now < 0 || now >= deadline) return wr_fail(why, "shared-deadline");
    enum wr_call_state state = b->call(b->ctx, &plan->participants[peer],
        op, plan->run, input, deadline, reply);
    static const char *const names[] = {"ok", "timeout", "truncated", "unknown-exit",
        "cancelled", "launch-failed", "exit-failed", "invalid-json"};
    const struct json_value *error = json_get(reply, "error");
    const char *code = json_get_str(json_get(error, "code"));
    bool missing = !strcmp(op, "read") && state == WR_EXIT_FAILED &&
        code && !strcmp(code, "NOT_FOUND") &&
        json_get(reply, "ok") && json_get(reply, "ok")->type == JSON_BOOL &&
        !json_get_bool(json_get(reply, "ok"));
    if (state != WR_CALL_OK && !missing) {
        json_free(reply); json_init(reply);
        return wr_fail(why, (unsigned)state < sizeof(names)/sizeof(names[0]) ?
            names[state] : "invalid-process-observation");
    }
    now = b->now_ms(b->ctx);
    if (now < 0 || now >= deadline) {
        json_free(reply); json_init(reply); return wr_fail(why, "shared-deadline");
    }
    return true;
}
static bool wr_read_exact(const struct wr_plan *plan, const struct wr_backend *b,
    size_t peer, const uint8_t id[32], int64_t deadline, struct fleet_board_post *post,
    const char **why)
{
    char hex[65]; fleet_board_id_to_hex(id, hex);
    struct json_value input; json_init(&input); json_set_object(&input);
    bool built = json_push_kv_str(&input, "id", hex) &&
        json_push_kv_int(&input, "offset", 0) && json_push_kv_int(&input, "bytes", 1024);
    if (!built) { json_free(&input); return wr_fail(why, "allocation"); }
    bool ok = false;
    while (b->now_ms(b->ctx) < deadline) {
        struct json_value reply;
        if (!wr_invoke(plan, b, peer, "read", &input, deadline, &reply, why)) break;
        ok = wr_post_read(&reply, post, why);
        json_free(&reply);
        if (ok || !why || !*why || strcmp(*why, "native-refusal")) break;
#ifndef _WIN32
        struct timespec pause = {.tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
#endif
    }
    json_free(&input);
    if (!ok) return wr_fail(why, why && *why ? *why : "shared-deadline");
    return !memcmp(post->id, id, 32) || wr_fail(why, "wrong-exact-id");
}
struct wr_publication { char slug[65], title[129], text[201]; };
static bool wr_publication_input(const struct wr_plan *plan, size_t writer,
    unsigned revision, const struct fleet_board_post *posts,
    struct wr_publication *request, struct json_value *input)
{
    const struct wr_participant *peer = &plan->participants[writer];
    (void)snprintf(request->slug, sizeof(request->slug), "g4-%s-%s", plan->run, peer->name);
    (void)snprintf(request->title, sizeof(request->title), "G4 %s", peer->name);
    (void)snprintf(request->text, sizeof(request->text), "G4 %s %s-v%u", plan->run, peer->name, revision+1);
    json_set_object(input);
    bool ok = json_push_kv_str(input, "slug", request->slug) &&
        json_push_kv_str(input, "title", request->title) &&
        json_push_kv_str(input, "text", request->text) && json_push_kv_int(input, "ttl", plan->ttl_seconds);
    if (revision) {
        char parent[65];
        fleet_board_id_to_hex(posts[writer*2].id, parent);
        ok = ok && json_push_kv_str(input, "supersedes", parent);
    }
    return ok;
}
static bool wr_write_ack(const struct json_value *reply, uint8_t id[32])
{
    const struct json_value *accepted = json_get(reply, "ok");
    return accepted && accepted->type == JSON_BOOL && json_get_bool(accepted) &&
        wr_hex(json_get(reply, "data"), "id", id, 32);
}
static bool wr_requested_matches(const struct wr_plan *plan, size_t writer,
    const struct wr_publication *request, const struct fleet_board_post *post)
{
    const struct wr_participant *peer = &plan->participants[writer];
    return !strcmp(post->slug, request->slug) && !strcmp(post->title, request->title) &&
        !strcmp(post->text, request->text) && post->text_len == strlen(request->text) &&
        !memcmp(post->host_pubkey, peer->host, 32) && post->scope == peer->scope &&
        !strcmp(post->room, peer->room) && post->ttl == plan->ttl_seconds;
}
static bool wr_publish(const struct wr_plan *plan, const struct wr_backend *b,
    size_t writer, unsigned revision, struct fleet_board_post *posts,
    int64_t deadline, const char **why)
{
    struct wr_publication request;
    struct json_value input, reply; json_init(&input);
    if (!wr_publication_input(plan, writer, revision, posts, &request, &input)) {
        json_free(&input); return wr_fail(why, "allocation");
    }
    /* One invocation only: uncertain writes are never automatically replayed. */
    bool ok = wr_invoke(plan, b, writer, "write", &input, deadline, &reply, why);
    json_free(&input);
    if (!ok) return false;
    uint8_t id[32]; ok = wr_write_ack(&reply, id); json_free(&reply);
    if (!ok) return wr_fail(why, "write-refused-or-uncertain");
    struct fleet_board_post *post = &posts[writer*2+revision];
    if (!wr_read_exact(plan, b, writer, id, deadline, post, why)) return false;
    if (!wr_requested_matches(plan, writer, &request, post))
        return wr_fail(why, "requested-content-mismatch");
    uint8_t zero[32] = {0};
    const uint8_t *expected = revision ? posts[writer*2].id : zero;
    if (memcmp(post->supersedes, expected, 32)) return wr_fail(why, "supersedes-mismatch");
    return !revision || memcmp(id, expected, 32) || wr_fail(why, "replayed-revision");
}
static bool wr_pair_record(struct json_value *pairs, const char *phase,
    const char *writer, const char *reader, unsigned revision, int64_t start,
    int64_t end, bool verified)
{
    struct json_value row; json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "phase", phase) &&
        json_push_kv_str(&row, "writer", writer) &&
        json_push_kv_str(&row, "reader", reader) &&
        json_push_kv_int(&row, "revision", revision+1) &&
        json_push_kv_int(&row, "start_ms_from_dispatch", start) &&
        json_push_kv_int(&row, "end_ms_from_dispatch", end) &&
        json_push_kv_bool(&row, "verified", verified) && json_push_back(pairs, &row);
    json_free(&row); return ok;
}
static bool wr_matrix(const struct wr_plan *plan, const struct wr_backend *b,
    struct fleet_board_post *posts, int64_t deadline, struct json_value *pairs,
    const char **why)
{
    for (size_t w = 0; w < plan->count; w++) {
        if (!(plan->participants[w].role & WR_WRITER)) continue;
        for (unsigned revision = 0; revision < 2; revision++) {
            int64_t before = b->now_ms(b->ctx);
            bool ok = wr_publish(plan, b, w, revision, posts, deadline, why);
            if (!wr_pair_record(pairs, "publish-and-source-read", plan->participants[w].name,
                plan->participants[w].name, revision, before-(deadline-10000),
                b->now_ms(b->ctx)-(deadline-10000), ok)) return wr_fail(why, "receipt-allocation");
            if (!ok) return false;
        }
    }
    for (size_t r = 0; r < plan->count; r++) {
        if (!(plan->participants[r].role & WR_READER)) continue;
        for (size_t w = 0; w < plan->count; w++) {
            if (!(plan->participants[w].role & WR_WRITER)) continue;
            for (unsigned v = 0; v < 2; v++) {
                struct fleet_board_post received;
                const struct fleet_board_post *expected = &posts[w*2+v];
                int64_t before = b->now_ms(b->ctx);
                bool ok = wr_read_exact(plan, b, r, expected->id, deadline, &received, why);
                if (!wr_pair_record(pairs, "reader-exact-revision", plan->participants[w].name,
                    plan->participants[r].name, v, before-(deadline-10000),
                    b->now_ms(b->ctx)-(deadline-10000), ok)) return wr_fail(why, "receipt-allocation");
                if (!ok) return false;
                /* Verified canonical IDs bind every signed byte. */
                if (memcmp(expected->id, received.id, 32)) return wr_fail(why, "reader-content-mismatch");
            }
        }
    }
    return true;
}
static bool wr_revision_record(struct json_value *rows, const char *writer,
    unsigned revision, const struct fleet_board_post *post)
{
    if (!post->kind) return true;
    size_t length = 0;
    (void)fleet_board_post_canonical(post, NULL, 0, &length);
    if (!length || length > FLEET_BOARD_BODY_MAX) return false;
    uint8_t *bytes = zcl_malloc(length*3+1, "wiki-runtime.receipt-canonical");
    if (!bytes) return false;
    char *hex = (char *)bytes+length;
    bool ok = fleet_board_post_canonical(post, bytes, length, &length) == FLEET_BOARD_OK;
    if (ok) zcl_hex_encode(bytes, length, hex);
    char id[65], signature[129];
    fleet_board_id_to_hex(post->id, id); zcl_hex_encode(post->signature, 64, signature);
    struct json_value row; json_init(&row); json_set_object(&row);
    ok = ok && json_push_kv_str(&row, "writer", writer) &&
        json_push_kv_int(&row, "revision", revision+1) &&
        json_push_kv_str(&row, "id", id) && json_push_kv_str(&row, "signature", signature) &&
        json_push_kv_str(&row, "canonical_hex", hex) && json_push_back(rows, &row);
    json_free(&row); free(bytes); return ok;
}
static bool wr_vector_record(const struct wr_plan *plan, struct json_value *rows)
{
    for (size_t i = 0; i < plan->count; i++) {
        const struct wr_participant *p = &plan->participants[i];
        char host[65]; zcl_hex_encode(p->host, 32, host);
        struct json_value row; json_init(&row); json_set_object(&row);
        bool ok = json_push_kv_str(&row, "name", p->name) &&
            json_push_kv_str(&row, "platform", p->platform) &&
            json_push_kv_str(&row, "declared_git_source", p->source) &&
            json_push_kv_str(&row, "owner_qualified_artifact", p->artifact) &&
            json_push_kv_str(&row, "expected_signing_key", host) &&
            json_push_kv_int(&row, "required_role", p->role) &&
            json_push_kv_int(&row, "signed_scope", p->scope) &&
            json_push_kv_str(&row, "signed_room", p->room) && json_push_back(rows, &row);
        json_free(&row); if (!ok) return false;
    }
    return true;
}
static bool wr_run_prepare(const struct wr_plan *plan, const struct wr_backend *b,
    int64_t *start, const char **why)
{
    if (!plan || plan->count < 2 || plan->count > WR_MAX ||
        !b || !b->call || !b->now_ms) return wr_fail(why, "invalid-backend");
    for (size_t i = 0; i < plan->count; i++)
        if (plan->participants[i].scope != FLEET_BOARD_SCOPE_PUBLIC ||
            strcmp(plan->participants[i].room, FLEET_BOARD_ROOM_DEFAULT))
            return wr_fail(why, "native-write-supports-public-general-only");
    *start = b->now_ms(b->ctx);
    return (*start >= 0 && *start <= INT64_MAX-10000) || wr_fail(why, "monotonic-unavailable");
}
static bool wr_verification_end(bool passed, int64_t start, int64_t end, const char **why)
{
    if (!passed) return false;
    if (end < start) return wr_fail(why, "monotonic-unavailable");
    return end < start+10000 || wr_fail(why, "verification-deadline");
}
static bool wr_record_snapshots(const struct wr_plan *plan, const struct fleet_board_post *posts,
    struct json_value *vector, struct json_value *revisions)
{
    if (!wr_vector_record(plan, vector)) return false;
    for (size_t i = 0; i < plan->count; i++)
        for (unsigned v = 0; v < 2; v++)
            if (!wr_revision_record(revisions, plan->participants[i].name, v, &posts[i*2+v])) return false;
    return true;
}
static bool wr_receipt_policy(const struct wr_plan *plan, bool passed,
    const char **why, struct json_value *receipt)
{
    return json_push_kv_str(receipt, "schema", "zcl.wiki_runtime.propagation.v1") &&
        json_push_kv_bool(receipt, "propagation_verified", passed) &&
        json_push_kv_bool(receipt, "full_qualification", false) &&
        json_push_kv_bool(receipt, "lifecycle_required", true) &&
        json_push_kv_str(receipt, "run", plan->run) &&
        json_push_kv_int(receipt, "participants", (int64_t)plan->count) &&
        json_push_kv_str(receipt, "artifact_observation", "owner-provenance-only; endpoint-artifact-not-probed") &&
        json_push_kv_str(receipt, "scope", "two superseding revisions; no CAS/fork/lifecycle qualification") &&
        json_push_kv_str(receipt, "reason", passed ? "owner-lifecycle-acceptance-required" :
            (why && *why ? *why : "failed"));
}
static bool wr_receipt_timing(const struct wr_plan *plan, int64_t start,
    int64_t end, struct json_value *receipt)
{
    return json_push_kv_int(receipt, "elapsed_ms", end >= start ? end-start : -1) &&
        json_push_kv_int(receipt, "deadline_ms", 10000) &&
        json_push_kv_int(receipt, "requested_ttl_seconds", plan->ttl_seconds) &&
        json_push_kv_str(receipt, "timing_scope", "before first write through final signature and binding verification; receipt build/export excluded");
}
static bool wr_receipt_vectors(struct json_value *receipt, const struct json_value *vector,
    const struct json_value *revisions, const struct json_value *pairs)
{
    return json_push_kv(receipt, "required_participants", vector) &&
        json_push_kv(receipt, "verified_revisions", revisions) && json_push_kv(receipt, "pairs", pairs);
}
bool wr_run(const struct wr_plan *plan, const struct wr_backend *b,
    struct json_value *receipt, const char **why)
{
    json_init(receipt); json_set_object(receipt);
    const char *local_why = NULL;
    if (!why) why = &local_why;
    *why = NULL;
    int64_t start;
    if (!wr_run_prepare(plan, b, &start, why)) return false;
    struct fleet_board_post *posts = zcl_calloc(plan->count*2, sizeof(*posts), "wiki-runtime.posts");
    if (!posts) return wr_fail(why, "allocation");
    struct json_value pairs, vector, revisions;
    json_init(&pairs); json_set_array(&pairs);
    json_init(&vector); json_set_array(&vector);
    json_init(&revisions); json_set_array(&revisions);
    bool passed = wr_matrix(plan, b, posts, start+10000, &pairs, why);
    int64_t end = b->now_ms(b->ctx);
    passed = wr_verification_end(passed, start, end, why);
    bool rendered = wr_record_snapshots(plan, posts, &vector, &revisions) &&
        wr_receipt_policy(plan, passed, why, receipt) && wr_receipt_timing(plan, start, end, receipt) &&
        wr_receipt_vectors(receipt, &vector, &revisions, &pairs);
    free(posts);
    json_free(&pairs); json_free(&vector); json_free(&revisions);
    int64_t built = b->now_ms(b->ctx);
    rendered = rendered && json_push_kv_int(receipt, "receipt_build_elapsed_ms",
        end >= 0 && built >= end ? built-end : -1);
    if (!rendered) { json_free(receipt); json_init(receipt); return wr_fail(why, "receipt-allocation"); }
    return passed;
}
