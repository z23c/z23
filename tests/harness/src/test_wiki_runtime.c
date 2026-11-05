/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
/* Purpose: hermetic native wiki qualification refusals, not live acceptance. */
#include "test/test_core.h"
#include "wiki_runtime.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include <string.h>
#include <stdlib.h>

static bool wrt_hex(struct json_value *out, const char *name,
    const uint8_t *bytes, size_t count)
{
    char hex[401];
    if (count > 200) return false;
    zcl_hex_encode(bytes, count, hex);
    return json_push_kv_str(out, name, hex);
}
static bool wrt_render_identity(const struct fleet_board_post *post, struct json_value *data)
{
    return wrt_hex(data, "id", post->id, 32) && wrt_hex(data, "host", post->host_pubkey, 32) &&
        wrt_hex(data, "signature", post->signature, 64) && wrt_hex(data, "ref", post->ref, 32) &&
        wrt_hex(data, "supersedes", post->supersedes, 32) &&
        wrt_hex(data, "data_hex", (const uint8_t *)post->text, post->text_len) &&
        json_push_kv_str(data, "kind", "wiki") && json_push_kv_str(data, "agent", post->agent) &&
        json_push_kv_str(data, "slug", post->slug) && json_push_kv_str(data, "title", post->title) &&
        json_push_kv_str(data, "signed_room", post->room);
}
static bool wrt_render_bounds(const struct fleet_board_post *post, struct json_value *data)
{
    return json_push_kv_int(data, "signed_scope", post->scope) &&
        json_push_kv_int(data, "created_at", (int64_t)post->created_at) &&
        json_push_kv_int(data, "ttl", post->ttl) && json_push_kv_int(data, "text_len", post->text_len) &&
        json_push_kv_int(data, "offset", 0) && json_push_kv_int(data, "next_offset", post->text_len) &&
        json_push_kv_bool(data, "complete", true);
}
static bool wrt_render(const struct fleet_board_post *post, struct json_value *out)
{
    struct json_value data; json_init(&data); json_set_object(&data);
    bool ok = wrt_render_identity(post, &data) && wrt_render_bounds(post, &data);
    json_set_object(out);
    ok = ok && json_push_kv_bool(out, "ok", true) &&
        json_push_kv(out, "data", &data);
    json_free(&data); return ok;
}
static int wrt_signed_projection(void)
{
    int failures = 0;
    TEST_CASE("wiki runtime signed reconstruction and tamper")
    struct fleet_board_post post = {0}, decoded;
    uint8_t seed[32] = {4}, pk[32], sk[64];
    ed25519_keypair(pk, sk, seed);
    post.kind = FLEET_BOARD_KIND_WIKI;
    post.scope = FLEET_BOARD_SCOPE_FLEET;
    post.created_at = 100; post.ttl = 1;
    strcpy(post.slug, "fixture"); strcpy(post.title, "Fixture");
    strcpy(post.agent, "fixture"); strcpy(post.text, "exact");
    post.text_len = 5;
    ASSERT(fleet_board_post_sign(&post, seed, pk) == FLEET_BOARD_OK);
    struct json_value reply; json_init(&reply);
    const char *why = NULL;
    ASSERT(wrt_render(&post, &reply));
    ASSERT(wr_post_read(&reply, &decoded, &why));
    ASSERT(memcmp(decoded.id, post.id, 32) == 0);
    json_free(&reply);
    /* Structurally valid signed metadata with changed bytes is rejected. */
    post.signature[0] ^= 1;
    ASSERT(wrt_render(&post, &reply));
    ASSERT(!wr_post_read(&reply, &decoded, &why));
    ASSERT(decoded.kind == 0);
    json_free(&reply); post.signature[0] ^= 1;
    post.text[0] = 'X';
    ASSERT(wrt_render(&post, &reply));
    ASSERT(!wr_post_read(&reply, &decoded, &why));
    json_free(&reply);
    TEST_END
    return failures;
}
static int wrt_capture(void)
{
    int failures = 0;
    TEST_CASE("wiki runtime real bounded child capture")
#ifndef _WIN32
    struct json_value reply; json_init(&reply);
    /* Trusted system fixture executable, explicit argv, never a shell. */
    const char *const good[] = {"/usr/bin/printf", "%s", "{\"ok\":true}", NULL};
    ASSERT(wr_capture(good, 1000, &reply) == WR_CALL_OK);
    ASSERT(json_get_bool(json_get(&reply, "ok")));
    json_free(&reply);
    const char *const malformed[] = {"/usr/bin/printf", "%s", "{", NULL};
    ASSERT(wr_capture(malformed, 1000, &reply) == WR_INVALID_JSON);
    ASSERT(wr_capture(good, 0, &reply) == WR_TIMEOUT);
#ifdef __linux__
    const char *const sleeper[] = {"/proc/self/exe", "--supervised-fixture-hold", NULL};
    ASSERT(wr_capture(sleeper, 10, &reply) == WR_TIMEOUT);
#endif
    const char *const overflow[] = {"/usr/bin/printf", "%20000s", "x", NULL};
    ASSERT(wr_capture(overflow, 1000, &reply) == WR_TRUNCATED);
    const char *const trailing[] = {"/usr/bin/printf", "%s", "\"owned\" trailing", NULL};
    ASSERT(wr_capture(trailing, 1000, &reply) == WR_INVALID_JSON);
    ASSERT(reply.type == JSON_NULL); json_free(&reply);
    const char *const scalar[] = {"/usr/bin/printf", "%s", "\"owned\"", NULL};
    ASSERT(wr_capture(scalar, 1000, &reply) == WR_CALL_OK);
    ASSERT(reply.type == JSON_STR); json_free(&reply); json_init(&reply);
    const char *const nonzero[] = {"/usr/bin/false", NULL};
    ASSERT(wr_capture(nonzero, 1000, &reply) == WR_EXIT_FAILED);
    json_free(&reply); json_init(&reply);
#ifdef __linux__
    const char *const string_nonzero[] = {"/usr/bin/printf", "%s%Q", "\"owned\"", NULL};
    ASSERT(wr_capture(string_nonzero, 1000, &reply) == WR_EXIT_FAILED);
    ASSERT(reply.type == JSON_STR); json_free(&reply); json_init(&reply);
#endif
#endif
    TEST_END
    return failures;
}
static int wrt_matrix(void);
static int wrt_plan_refusals(void);
static int wrt_regular_files(void);
static int wrt_final_clock(unsigned mode);
int test_wiki_runtime(void)
{
    return wrt_signed_projection() + wrt_capture() + wrt_matrix() + wrt_plan_refusals() + wrt_regular_files() + wrt_final_clock(5) + wrt_final_clock(6) + wrt_final_clock(7);
}

struct wrt_context {
    int64_t clock;
    unsigned writes[2], mode, calls, final_samples;
    struct fleet_board_post posts[4];
};
static int64_t wrt_now(void *opaque)
{
    struct wrt_context *ctx = opaque;
    if (ctx->mode >= 5 && ctx->mode <= 7 && ctx->calls == 16) {
        if (++ctx->final_samples == 1) return 9999;
        return ctx->mode == 5 ? 10001 : ctx->mode == 6 ? -1 : 10000;
    }
    return ctx->clock;
}
static bool wrt_plan_args(struct json_value *args)
{
    struct json_value arg; json_init(&arg);
    const char *argv[] = {"/fixture/z23-dev", "-datadir=/tmp/zcl23-fixture", "-rpcport=39001"};
    bool ok = true;
    for (unsigned j = 0; j < 3; j++) {
        json_set_str(&arg, argv[j]);
        ok = ok && json_push_back(args, &arg); json_free(&arg); json_init(&arg);
    }
    return ok;
}
static bool wrt_peer_json(struct json_value *row, unsigned i, const struct json_value *args)
{
    char name[2] = {(char)('a'+i), 0}, host[65], source[41], artifact[65];
    uint8_t seed[32] = {0}, pk[32], sk[64]; seed[0] = (uint8_t)(i+1);
    ed25519_keypair(pk, sk, seed); zcl_hex_encode(pk, 32, host);
    memset(source, '0', 40); source[40] = 0; memset(artifact, '0', 64); artifact[64] = 0;
    return json_push_kv_str(row, "name", name) && json_push_kv_str(row, "role", "both") &&
        json_push_kv_str(row, "platform", "fixture") && json_push_kv_str(row, "source", source) &&
        json_push_kv_str(row, "artifact", artifact) && json_push_kv_str(row, "host", host) &&
        json_push_kv_str(row, "signed_room", "general") &&
        json_push_kv_int(row, "signed_scope", FLEET_BOARD_SCOPE_PUBLIC) && json_push_kv(row, "argv", args);
}
static bool wrt_plan_entry(struct json_value *required, struct json_value *participants, unsigned i)
{
    char name[2] = {(char)('a'+i), 0};
    struct json_value row, request, args;
    json_init(&row); json_set_object(&row); json_init(&request); json_set_object(&request);
    json_init(&args); json_set_array(&args);
    bool ok = wrt_plan_args(&args) && wrt_peer_json(&row, i, &args) &&
        json_push_kv_str(&request, "name", name) && json_push_kv_str(&request, "role", "both") &&
        json_push_back(required, &request) && json_push_back(participants, &row);
    json_free(&args); json_free(&request); json_free(&row); return ok;
}
static bool wrt_plan_json(struct json_value *in)
{
    struct json_value required, participants;
    json_init(&required); json_set_array(&required); json_init(&participants); json_set_array(&participants);
    bool ok = true;
    for (unsigned i = 0; i < 2 && ok; i++) ok = wrt_plan_entry(&required, &participants, i);
    json_set_object(in);
    ok = ok && json_push_kv_str(in, "run", "fixture") &&
        json_push_kv(in, "required", &required) && json_push_kv(in, "participants", &participants);
    ok = ok && json_push_kv_int(in, "ttl_seconds", 30);
    json_free(&required); json_free(&participants); return ok;
}
static bool wrt_compose(struct wrt_context *ctx, unsigned revision,
    const struct json_value *input, struct fleet_board_post *post)
{
    post->kind = FLEET_BOARD_KIND_WIKI; post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    strcpy(post->room, "general"); strcpy(post->agent, "fixture");
    post->created_at = 100; post->ttl = (uint32_t)json_get_int(json_get(input, "ttl"));
    if (ctx->mode == 8) post->ttl++;
    const char *text = json_get_str(json_get(input, "text"));
    const char *slug = json_get_str(json_get(input, "slug"));
    const char *title = json_get_str(json_get(input, "title"));
    if (!text || !slug || !title) return false;
    snprintf(post->text, sizeof(post->text), "%s", text);
    snprintf(post->slug, sizeof(post->slug), "%s", slug);
    snprintf(post->title, sizeof(post->title), "%s", title);
    post->text_len = (uint32_t)strlen(text);
    if (revision && !zcl_hex_decode_lower(json_get_str(json_get(input, "supersedes")), post->supersedes, 32))
        return false;
    if (ctx->mode == 2 && revision) memset(post->supersedes, 0, 32);
    if (ctx->mode == 3) post->scope = FLEET_BOARD_SCOPE_FLEET, post->room[0] = 0;
    return true;
}
static enum wr_call_state wrt_write(struct wrt_context *ctx, unsigned writer,
    const struct json_value *input, struct json_value *reply)
{
    unsigned v = ctx->writes[writer]++;
    if (v > 1) return WR_EXIT_FAILED;
    struct fleet_board_post *post = &ctx->posts[writer*2+v];
    if (!wrt_compose(ctx, v, input, post)) return WR_INVALID_JSON;
    uint8_t seed[32] = {0}, pk[32], sk[64]; seed[0] = (uint8_t)(writer+1);
    ed25519_keypair(pk, sk, seed);
    if (fleet_board_post_sign(post, seed, pk) != FLEET_BOARD_OK) return WR_INVALID_JSON;
    char id[65]; fleet_board_id_to_hex(post->id, id);
    struct json_value data; json_init(&data); json_set_object(&data);
    json_set_object(reply);
    bool ok = json_push_kv_str(&data, "id", id) && json_push_kv_bool(reply, "ok", true) &&
        json_push_kv(reply, "data", &data);
    json_free(&data); return ok ? WR_CALL_OK : WR_INVALID_JSON;
}
static enum wr_call_state wrt_answer(struct wrt_context *ctx, unsigned reader,
    unsigned index, struct json_value *reply)
{
    if (ctx->mode == 1 && reader == 1 && index < 2) {
        ctx->clock = 10001; return WR_TIMEOUT;
    }
    if (ctx->mode == 4 && reader == 1 && index < 2) {
        struct fleet_board_post tampered = ctx->posts[index]; tampered.signature[0] ^= 1;
        return wrt_render(&tampered, reply) ? WR_CALL_OK : WR_INVALID_JSON;
    }
    return wrt_render(&ctx->posts[index], reply) ? WR_CALL_OK : WR_INVALID_JSON;
}
static enum wr_call_state wrt_read(struct wrt_context *ctx, unsigned reader,
    const struct json_value *input, struct json_value *reply)
{
    uint8_t id[32];
    if (!zcl_hex_decode_lower(json_get_str(json_get(input, "id")), id, 32)) return WR_INVALID_JSON;
    for (unsigned i = 0; i < 4; i++) {
        if (!ctx->posts[i].kind || memcmp(ctx->posts[i].id, id, 32)) continue;
        return wrt_answer(ctx, reader, i, reply);
    }
    return WR_EXIT_FAILED;
}
static enum wr_call_state wrt_call(void *opaque, const struct wr_participant *peer,
    const char *operation, const char *run, const struct json_value *input,
    int64_t deadline, struct json_value *reply)
{
    (void)run; (void)deadline;
    struct wrt_context *ctx = opaque; json_init(reply);
    ctx->calls++; ctx->clock++;
    if (ctx->mode >= 10) {
        json_set_str(reply, "owned failed reply");
        /* Includes valid root-string cancellation: wr_invoke alone disposes. */
        return (enum wr_call_state)(ctx->mode-10);
    }
    unsigned index = peer->name[0] == 'a' ? 0 : 1;
    if (!strcmp(operation, "write")) return wrt_write(ctx, index, input, reply);
    if (!strcmp(operation, "read")) return wrt_read(ctx, index, input, reply);
    return WR_EXIT_FAILED;
}
static int wrt_matrix(void)
{
    int failures = 0;
    TEST_CASE("wiki runtime required matrix and shared deadline")
    struct json_value input, receipt; json_init(&input); json_init(&receipt);
    ASSERT(wrt_plan_json(&input));
    struct wr_plan *plan = calloc(1, sizeof(*plan));
    struct wrt_context *ctx = calloc(1, sizeof(*ctx));
    ASSERT(plan && ctx);
    const char *why = NULL;
    ASSERT(wr_plan_read(&input, plan, &why));
    struct wr_backend b = {.ctx=ctx, .now_ms=wrt_now, .call=wrt_call};
    ASSERT(wr_run(plan, &b, &receipt, &why));
    ASSERT(!json_get_bool(json_get(&receipt, "full_qualification")));
    ASSERT(json_size(json_get(&receipt, "verified_revisions")) == 4);
    ASSERT(json_size(json_get(&receipt, "pairs")) == 12);
    json_free(&receipt);
    for (unsigned mode = 1; mode <= 8; mode++) {
        memset(ctx, 0, sizeof(*ctx)); ctx->mode = mode;
        ASSERT(!wr_run(plan, &b, &receipt, &why));
        ASSERT(!json_get_bool(json_get(&receipt, "propagation_verified")));
        ASSERT(json_size(json_get(&receipt, "pairs")) > 0);
        json_free(&receipt);
    }
    /* Distinct process failures remain distinct, never successful JSON. */
    for (unsigned mode = WR_TIMEOUT; mode <= WR_INVALID_JSON; mode++) {
        memset(ctx, 0, sizeof(*ctx)); ctx->mode = mode+10;
        ASSERT(!wr_run(plan, &b, &receipt, NULL));
        json_free(&receipt);
    }
    json_free(&input); free(ctx); free(plan);
    TEST_END
    return failures;
}
static int wrt_plan_refusals(void)
{
    int failures = 0;
    TEST_CASE("wiki runtime plan refuses partial and ambiguous targets")
    struct json_value input; json_init(&input);
    struct wr_plan *plan = calloc(1, sizeof(*plan));
    ASSERT(plan);
    const char *why = NULL;
    const char *empty = "{\"run\":\"fixture\",\"required\":[],\"participants\":[]}";
    ASSERT(json_read(&input, empty, strlen(empty)));
    ASSERT(!wr_plan_read(&input, plan, &why));
    json_free(&input);
    ASSERT(wrt_plan_json(&input));
    /* Deliberately mismatch the independently declared required role. */
    struct json_value *required = &input.children[1];
    json_set_str(&required->children[0].children[1], "reader");
    ASSERT(!wr_plan_read(&input, plan, &why));
    json_free(&input);
    ASSERT(wrt_plan_json(&input));
    struct json_value *peers = &input.children[2];
    /* Fixture schema position 5 is host; clone key under another alias. */
    json_set_str(&peers->children[1].children[5],
        json_get_str(&peers->children[0].children[5]));
    ASSERT(!wr_plan_read(&input, plan, &why));
    json_free(&input);
    ASSERT(wrt_plan_json(&input));
    peers = &input.children[2];
    json_set_str(&peers->children[0].children[8].children[0], "/usr/bin/ssh");
    ASSERT(!wr_plan_read(&input, plan, &why));
    json_free(&input);
    ASSERT(wrt_plan_json(&input));
    peers = &input.children[2];
    json_set_str(&peers->children[0].children[8].children[1], "-datadir=/private/tmp/zcl23-fixture");
    ASSERT(wr_plan_read(&input, plan, &why));
    struct json_value extra; json_init(&extra); json_set_object(&extra);
    ASSERT(json_push_kv_str(&extra, "name", "c") && json_push_kv_str(&extra, "role", "both"));
    ASSERT(json_push_back(&input.children[1], &extra)); json_free(&extra);
    ASSERT(!wr_plan_read(&input, plan, &why));
    json_free(&input); free(plan);
    TEST_END
    return failures;
}
static int wrt_regular_files(void)
{
    int failures = 0;
    TEST_CASE("wiki runtime bounded opened-file refuses FIFO device symlink")
#ifndef _WIN32
    char path[PATH_MAX], bytes[8]; size_t n = 0;
    int fd = test_mkstemp(path, sizeof(path), "wiki-runtime");
    ASSERT(fd >= 0);
    ASSERT(write(fd, "test", 4) == 4); ASSERT(close(fd) == 0);
    ASSERT(wr_read_regular(path, bytes, sizeof(bytes), &n)); ASSERT_EQ(n, 4);
    ASSERT(!wr_read_regular(path, bytes, 2, &n));
    ASSERT(unlink(path) == 0);
    ASSERT(mkfifo(path, 0600) == 0);
    ASSERT(!wr_read_regular(path, bytes, sizeof(bytes), &n));
    ASSERT(unlink(path) == 0);
    ASSERT(symlink("/dev/null", path) == 0);
    ASSERT(!wr_read_regular(path, bytes, sizeof(bytes), &n));
    ASSERT(unlink(path) == 0);
    ASSERT(!wr_read_regular("/dev/zero", bytes, sizeof(bytes), &n));
#endif
    TEST_END
    return failures;
}
static int wrt_final_clock(unsigned mode)
{
    int failures = 0;
    TEST_CASE(mode == 5 ? "wiki runtime final verification exceeds deadline" : mode == 6 ? "wiki runtime final monotonic observation fails" : "wiki runtime exact deadline refuses")
    struct json_value input, receipt; json_init(&input); json_init(&receipt);
    ASSERT(wrt_plan_json(&input));
    struct wr_plan *plan = calloc(1, sizeof(*plan));
    struct wrt_context *ctx = calloc(1, sizeof(*ctx));
    ASSERT(plan && ctx);
    const char *why = NULL;
    ASSERT(wr_plan_read(&input, plan, &why)); ctx->mode = mode;
    struct wr_backend b = {.ctx=ctx, .now_ms=wrt_now, .call=wrt_call};
    ASSERT(!wr_run(plan, &b, &receipt, &why));
    ASSERT(!json_get_bool(json_get(&receipt, "propagation_verified")));
    ASSERT(ctx->calls == 16);
    ASSERT_STR_EQ(why, mode == 6 ? "monotonic-unavailable" : "verification-deadline");
    json_free(&receipt); json_free(&input); free(ctx); free(plan);
    TEST_END
    return failures;
}
