/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scripted v=1 playtest session over resident_launch (see header). */
#include "command/app_playtest_session.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include "util/path_util.h"
#include "zbase64/zbase64.h"

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
extern char **environ;
#endif

/* Grace a cooperative child gets after STOP before its group is killed. */
#define APS_STOP_GRACE_MS 1000u
#define APS_TRACE_LINE_MAX 1024u

static const char *const aps_code_names[] = {
    [APP_PLAYTEST_OK] = "OK",
    [APP_PLAYTEST_INVALID_REQUEST] = "INVALID_REQUEST",
    [APP_PLAYTEST_DUPLICATE_STEP_ID] = "DUPLICATE_STEP_ID",
    [APP_PLAYTEST_IMAGE_UNAVAILABLE] = "IMAGE_UNAVAILABLE",
    [APP_PLAYTEST_IMAGE_HASH_MISMATCH] = "IMAGE_HASH_MISMATCH",
    [APP_PLAYTEST_SPAWN_REFUSED] = "SPAWN_REFUSED",
    [APP_PLAYTEST_TIMEOUT] = "PLAYTEST_TIMEOUT",
    [APP_PLAYTEST_REPLY_TOO_LARGE] = "REPLY_TOO_LARGE",
    [APP_PLAYTEST_CHILD_EXITED] = "CHILD_EXITED",
    [APP_PLAYTEST_PROTOCOL_ERROR] = "PROTOCOL_ERROR",
    [APP_PLAYTEST_ALLOC_FAILED] = "ALLOC_FAILED",
    [APP_PLAYTEST_UNSUPPORTED_PLATFORM] = "UNSUPPORTED_PLATFORM",
};

const char *app_playtest_code_name(enum app_playtest_code code)
{
    size_t n = sizeof(aps_code_names) / sizeof(aps_code_names[0]);
    return (size_t)code < n && aps_code_names[code] ? aps_code_names[code] : "UNKNOWN";
}

[[gnu::format(printf, 3, 4)]]
static bool aps_fail(struct app_playtest_result *out, enum app_playtest_code code,
                     const char *fmt, ...)
{
    out->code = code;
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(out->error, sizeof(out->error), fmt, args);
    va_end(args);
    return false;
}

size_t app_playtest_display_env(char *env[APP_PLAYTEST_ENV_MAX + 1u])
{
    static const char *const names[] = {"DISPLAY", "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR", "XAUTHORITY", "XDG_SESSION_TYPE"};
    static_assert(sizeof(names) / sizeof(names[0]) <= APP_PLAYTEST_ENV_MAX,
                  "display allowlist fits the env vector");
    size_t n = 0;
#if !defined(_WIN32) /* no exact launch there: the child never exists */
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        size_t len = strlen(names[i]);
        for (char **entry = environ; entry && *entry; entry++) {
            if (strncmp(*entry, names[i], len) == 0 && (*entry)[len] == '=') {
                env[n++] = *entry;
                break;
            }
        }
    }
#endif
    env[n] = NULL;
    return n;
}

/* ── Request validation: everything here runs before any process exists ── */

static bool aps_axis_valid(float axis)
{
    return isfinite(axis) && axis >= -1.0f && axis <= 1.0f;
}

static bool aps_step_valid(const struct app_playtest_step *step)
{
    if (step->op == APP_PLAYTEST_OBSERVE)
        return step->frames == 0;
    return step->op == APP_PLAYTEST_STEP && step->frames >= 1 &&
           step->frames <= APP_PLAYTEST_STEP_FRAMES_MAX &&
           aps_axis_valid(step->input.move_x) &&
           aps_axis_valid(step->input.move_y) &&
           aps_axis_valid(step->input.camera_x);
}

static bool aps_script_valid(const struct app_playtest_request *request,
                             struct app_playtest_result *out)
{
    if (!request->steps || request->n_steps == 0 ||
        request->n_steps > APP_PLAYTEST_STEP_MAX)
        return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST,
                        "app playtest: a script needs 1..%u steps, got %zu",
                        APP_PLAYTEST_STEP_MAX, request->n_steps);
    for (size_t i = 0; i < request->n_steps; i++) {
        const struct app_playtest_step *step = &request->steps[i];
        for (size_t j = 0; j < i; j++)
            if (request->steps[j].id == step->id)
                return aps_fail(out, APP_PLAYTEST_DUPLICATE_STEP_ID,
                                "app playtest: step id %u appears at steps %zu and %zu",
                                step->id, j, i);
        if (!aps_step_valid(step))
            return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST,
                            "app playtest: step %u needs observe with 0 frames, or step"
                            " with 1..%u frames and finite axes in [-1,1]",
                            step->id, APP_PLAYTEST_STEP_FRAMES_MAX);
    }
    return true;
}

static bool aps_request_valid(const struct app_playtest_request *request,
                              struct app_playtest_result *out)
{
    if (!request)
        return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST, "app playtest: no request");
    if (!aps_script_valid(request, out))
        return false;
    if (!request->image_path || !request->image_path[0])
        return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST, "app playtest: no image path");
    if (!zcl_is_lower_hex(request->image_sha3_hex, RESIDENT_LAUNCH_DIGEST_HEX))
        return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST,
                        "app playtest: image_sha3 must be 64 lowercase hex digits");
    return true;
}

/* ── Reply decoding ── */

static bool aps_number(const struct json_value *value, double *out)
{
    if (!value || (value->type != JSON_INT && value->type != JSON_REAL))
        return false;
    *out = value->type == JSON_INT ? (double)json_get_int(value) : json_get_real(value);
    return isfinite(*out);
}

static bool aps_u32(const struct json_value *value, uint32_t *out)
{
    if (!value || value->type != JSON_INT || json_get_int(value) < 0 ||
        json_get_int(value) > UINT32_MAX)
        return false;
    *out = (uint32_t)json_get_int(value);
    return true;
}

static bool aps_player(const struct json_value *player,
                       struct app_playtest_step_state *state)
{
    if (!player)
        return false;
    state->player_present = player->type != JSON_NULL;
    if (!state->player_present)
        return true;
    return player->type == JSON_OBJ &&
           aps_number(json_get(player, "x"), &state->x) &&
           aps_number(json_get(player, "y"), &state->y) &&
           aps_number(json_get(player, "z"), &state->z) &&
           aps_number(json_get(player, "yaw"), &state->yaw) &&
           aps_number(json_get(player, "speed"), &state->speed) &&
           aps_number(json_get(player, "health"), &state->health);
}

/* The child's error is a protocol name: [A-Z0-9_], shorter than the field. */
static bool aps_child_error(const struct json_value *value,
                            struct app_playtest_step_state *state)
{
    if (!value)
        return state->ok;
    const char *text = json_get_str(value);
    if (value->type != JSON_STR || !text || !text[0] ||
        strlen(text) >= sizeof(state->error))
        return false;
    for (const char *c = text; *c; c++)
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '_'))
            return false;
    (void)snprintf(state->error, sizeof(state->error), "%s", text);
    return true;
}

static bool aps_capture_bytes(const char *base64, size_t declared,
                              struct app_playtest_capture *capture)
{
    size_t length = strlen(base64), decoded = 0;
    if (declared == 0 || declared > APP_PLAYTEST_PNG_MAX ||
        zbase64_decode_cap(length) > APP_PLAYTEST_PNG_MAX + 3u)
        return false;
    capture->png = zcl_malloc(zbase64_decode_cap(length) + 1u, "app-playtest-png");
    if (!capture->png)
        return false;
    if (!zbase64_decode(base64, length, capture->png, zbase64_decode_cap(length) + 1u,
                        &decoded) || decoded != declared)
        return false;
    uint8_t digest[32];
    zcl_sha3_256(capture->png, decoded, digest);
    zcl_hex_encode(digest, sizeof(digest), capture->sha3_hex);
    capture->bytes = decoded;
    capture->present = true;
    return true;
}

static bool aps_capture(const struct json_value *png, struct app_playtest_capture *capture)
{
    if (!png)
        return true;
    uint32_t bytes = 0;
    const struct json_value *base64 = json_get(png, "base64");
    return png->type == JSON_OBJ && base64 && base64->type == JSON_STR &&
           aps_u32(json_get(png, "width"), &capture->width) && capture->width &&
           aps_u32(json_get(png, "height"), &capture->height) && capture->height &&
           aps_u32(json_get(png, "bytes"), &bytes) &&
           aps_capture_bytes(json_get_str(base64), bytes, capture);
}

static bool aps_reply_fields(const struct json_value *doc, uint32_t wire_id,
                             struct app_playtest_step_state *state)
{
    uint32_t version = 0, id = 0;
    const struct json_value *ok = json_get(doc, "ok");
    if (doc->type != JSON_OBJ || !aps_u32(json_get(doc, "v"), &version) ||
        version != 1 || !aps_u32(json_get(doc, "id"), &id) || id != wire_id ||
        !ok || ok->type != JSON_BOOL)
        return false;
    state->ok = json_get_bool(ok);
    return aps_u32(json_get(doc, "frame"), &state->frame) &&
           aps_number(json_get(doc, "time"), &state->time) &&
           aps_player(json_get(doc, "player"), state) &&
           aps_child_error(json_get(doc, "error"), state) &&
           aps_capture(json_get(doc, "png"), &state->capture);
}

static bool aps_reply_parse(char *reply, size_t length, uint32_t wire_id,
                            struct app_playtest_step_state *state)
{
    while (length && (reply[length - 1] == '\n' || reply[length - 1] == '\r'))
        length--;
    reply[length] = '\0';
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, reply, length) && aps_reply_fields(&doc, wire_id, state);
    json_free(&doc);
    return ok;
}

/* ── Trace: one deterministic line per step, whole lines only ── */

static void aps_trace_append(struct app_playtest_result *out,
                             const struct app_playtest_step *step,
                             const struct app_playtest_step_state *state)
{
    char line[APS_TRACE_LINE_MAX], player[320] = "null";
    if (state->player_present)
        (void)snprintf(player, sizeof(player),
            "{\"x\":%.9g,\"y\":%.9g,\"z\":%.9g,\"yaw\":%.9g,\"speed\":%.9g,\"health\":%.9g}",
            state->x, state->y, state->z, state->yaw, state->speed, state->health);
    int n = snprintf(line, sizeof(line),
        "{\"id\":%u,\"op\":\"%s\",\"frames\":%u,\"ok\":%s,\"frame\":%u,"
        "\"time\":%.17g,\"player\":%s,\"error\":%s%s%s,\"capture\":%s%s%s}\n",
        step->id, step->op == APP_PLAYTEST_STEP ? "step" : "observe", step->frames,
        state->ok ? "true" : "false", state->frame, state->time, player,
        state->error[0] ? "\"" : "", state->error[0] ? state->error : "null",
        state->error[0] ? "\"" : "",
        state->capture.present ? "\"" : "",
        state->capture.present ? state->capture.sha3_hex : "null",
        state->capture.present ? "\"" : "");
    if (out->trace_truncated || n < 0 || (size_t)n >= sizeof(line) ||
        out->trace_len + (size_t)n > APP_PLAYTEST_TRACE_MAX) {
        out->trace_truncated = true;
        return;
    }
    memcpy(out->trace + out->trace_len, line, (size_t)n);
    out->trace_len += (size_t)n;
    out->trace[out->trace_len] = '\0';
}

/* ── Session ── */

static int aps_request_json(const struct app_playtest_step *step, uint32_t wire_id,
                            char text[APP_PLAYTEST_REQUEST_MAX])
{
    const char *capture = step->capture ? "true" : "false";
    if (step->op == APP_PLAYTEST_OBSERVE)
        return snprintf(text, APP_PLAYTEST_REQUEST_MAX,
                        "{\"v\":1,\"id\":%u,\"op\":\"observe\",\"capture\":%s}",
                        wire_id, capture);
    const struct app_playtest_input *in = &step->input;
    return snprintf(text, APP_PLAYTEST_REQUEST_MAX,
        "{\"v\":1,\"id\":%u,\"op\":\"step\",\"frames\":%u,\"input\":{\"move_x\":%.9g,"
        "\"move_y\":%.9g,\"camera_x\":%.9g,\"fire_guns\":%s,\"speed_boost\":%s,"
        "\"throttle\":%s},\"capture\":%s}",
        wire_id, step->frames, (double)in->move_x, (double)in->move_y,
        (double)in->camera_x, in->fire_guns ? "true" : "false",
        in->speed_boost ? "true" : "false", in->throttle ? "true" : "false", capture);
}

static enum app_playtest_code aps_read_code(int err)
{
    if (err == EMSGSIZE)
        return APP_PLAYTEST_REPLY_TOO_LARGE;
    if (err == ETIMEDOUT || err == EAGAIN)
        return APP_PLAYTEST_TIMEOUT;
    if (err == ECONNRESET || err == EPIPE)
        return APP_PLAYTEST_CHILD_EXITED;
    return APP_PLAYTEST_PROTOCOL_ERROR;
}

struct aps_session {
    struct resident_launch launch;
    struct resident_startup startup;
    char *reply;
    uint32_t timeout_ms;
};

static bool aps_exchange(struct aps_session *s, const struct app_playtest_step *step,
                         uint32_t wire_id, struct app_playtest_result *out)
{
    char text[APP_PLAYTEST_REQUEST_MAX], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    int length = aps_request_json(step, wire_id, text);
    if (length <= 0 || (size_t)length >= sizeof(text))
        return aps_fail(out, APP_PLAYTEST_INVALID_REQUEST,
                        "app playtest: step %u request does not fit", step->id);
    if (!resident_launch_send_frame(&s->launch, text, (uint32_t)length, s->timeout_ms,
                                    error, sizeof(error)))
        return aps_fail(out, aps_read_code(errno), "app playtest: step %u: %s",
                        step->id, error);
    struct resident_result_header header;
    if (!resident_result_read(&s->launch, &header, s->reply, APP_PLAYTEST_REPLY_MAX,
                              s->timeout_ms, error, sizeof(error)))
        return aps_fail(out, aps_read_code(errno), "app playtest: step %u reply: %s",
                        step->id, error);
    struct app_playtest_step_state *state = &out->steps[out->n_steps];
    memset(state, 0, sizeof(*state));
    state->id = step->id;
    state->wire_id = wire_id;
    if (!aps_reply_parse(s->reply, header.payload_len, wire_id, state)) {
        free(state->capture.png);
        memset(&state->capture, 0, sizeof(state->capture));
        return aps_fail(out, APP_PLAYTEST_PROTOCOL_ERROR,
                        "app playtest: step %u reply is not a v=1 reply to wire id %u",
                        step->id, wire_id);
    }
    out->n_steps++;
    aps_trace_append(out, step, state);
    return true;
}

static bool aps_accept(const struct app_playtest_request *request,
                       struct resident_launch_accepted *accepted,
                       struct app_playtest_result *out)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, request->image_path) &&
              platform_positioned_file_snapshot(&file, &snap);
    int saved = errno;
    platform_positioned_file_close(&file);
    if (!ok)
        return aps_fail(out, APP_PLAYTEST_IMAGE_UNAVAILABLE,
                        "app playtest: cannot open image %s: %s",
                        request->image_path, strerror(saved));
    memset(accepted, 0, sizeof(*accepted));
    (void)snprintf(accepted->image_sha3_hex, sizeof(accepted->image_sha3_hex), "%s",
                   request->image_sha3_hex);
    accepted->image_volume = snap.volume;
    accepted->image_low = snap.file_low;
    accepted->image_high = snap.file_high;
    accepted->image_size = snap.size;
    return true;
}

static bool aps_prepare(struct aps_session *s, const struct app_playtest_request *request,
                        struct app_playtest_result *out)
{
    struct resident_launch_accepted accepted;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!aps_accept(request, &accepted, out))
        return false;
    if (!resident_launch_prepare(&s->launch, request->image_path, &accepted,
                                 error, sizeof(error))) {
        int saved = errno;
        return aps_fail(out, saved == ESTALE ? APP_PLAYTEST_IMAGE_HASH_MISMATCH
                             : saved == ENOTSUP ? APP_PLAYTEST_UNSUPPORTED_PLATFORM
                             : APP_PLAYTEST_IMAGE_UNAVAILABLE,
                        "app playtest: %s", error);
    }
    return true;
}

static bool aps_start(struct aps_session *s, const struct app_playtest_request *request,
                      struct app_playtest_result *out)
{
    char seed[32], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    char *env[APP_PLAYTEST_ENV_MAX + 1u];
    (void)snprintf(seed, sizeof(seed), "--seed=%u", request->seed);
    (void)app_playtest_display_env(env);
    char *argv[] = {(char *)request->image_path, "--resident", s->launch.nonce,
                    "--agent", seed, NULL};
    struct resident_receipt receipt;
    if (!resident_startup_begin(&s->startup, RESIDENT_STARTUP_PLATFORM_MS,
                                RESIDENT_STARTUP_PROTOCOL_MS, error, sizeof(error)))
        return aps_fail(out, APP_PLAYTEST_SPAWN_REFUSED, "app playtest: %s", error);
    if (!resident_launch_spawn(&s->launch, argv, env, &receipt, error, sizeof(error)))
        return aps_fail(out, APP_PLAYTEST_SPAWN_REFUSED, "app playtest: %s", error);
    out->spawned = true;
    out->pid = receipt.pid;
    out->start_token = receipt.start_token;
    (void)snprintf(out->mapped_proof, sizeof(out->mapped_proof), "%s",
                   receipt.mapped_proof);
    if (!resident_startup_read(&s->launch, &s->startup, error, sizeof(error)))
        return aps_fail(out, aps_read_code(errno), "app playtest: no READY: %s", error);
    return true;
}

static bool aps_session_run(struct aps_session *s, const struct app_playtest_request *request,
                            struct app_playtest_result *out)
{
    if (!aps_prepare(s, request, out) || !aps_start(s, request, out))
        return false;
    s->reply = zcl_malloc(APP_PLAYTEST_REPLY_MAX + 1u, "app-playtest-reply");
    if (!s->reply)
        return aps_fail(out, APP_PLAYTEST_ALLOC_FAILED,
                        "app playtest: reply buffer allocation failed");
    for (size_t i = 0; i < request->n_steps; i++)
        if (!aps_exchange(s, &request->steps[i], (uint32_t)i + 1u, out))
            return false;
    return true;
}

bool app_playtest_run(const struct app_playtest_request *request,
                      struct app_playtest_result *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!aps_request_valid(request, out))
        return false;
    /* Windows: resident_launch_prepare refuses by name (ENOTSUP). */
    struct aps_session s = {.timeout_ms = request->step_timeout_ms
                                ? request->step_timeout_ms : RESIDENT_RESULT_DEADLINE_MS};
    resident_launch_init(&s.launch);
    bool ok = aps_session_run(&s, request, out);
    if (s.launch.spawned) {
        char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
        /* A failed session gets no grace: its group is killed and reaped now. */
        if (!resident_launch_cancel(&s.launch, ok ? APS_STOP_GRACE_MS : 0u,
                                    error, sizeof(error)) && ok)
            ok = aps_fail(out, APP_PLAYTEST_CHILD_EXITED,
                          "app playtest: cancel failed: %s", error);
    }
    resident_launch_close(&s.launch);
    free(s.reply);
    return ok;
}

void app_playtest_result_free(struct app_playtest_result *out)
{
    if (!out)
        return;
    for (size_t i = 0; i < out->n_steps && i < APP_PLAYTEST_STEP_MAX; i++) {
        free(out->steps[i].capture.png);
        out->steps[i].capture.png = NULL;
    }
}
