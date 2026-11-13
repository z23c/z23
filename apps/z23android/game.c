/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "game.h"
#include "bridge_client.h"
#include "json/json.h"
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define PNG_CAP 1048576u
#define RESPONSE_CAP 1950000u
static struct {
    pthread_mutex_t lock;
    atomic_bool cancel;
    bool running, wanted;
    char files[640], pending_files[640], status[160];
    float x, y;
    bool fire, boost;
    unsigned char png[PNG_CAP];
    size_t png_len;
    uint64_t version;
} game = {.lock = PTHREAD_MUTEX_INITIALIZER};
typedef void (*notify_fn)(void);
static _Atomic(notify_fn) game_notify;
void zapp_game_set_notify(void (*notify)(void)) { atomic_store(&game_notify, notify); }
static void notify_view(void) { notify_fn fn = atomic_load(&game_notify); if (fn) fn(); }

static int b64digit(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static uint32_t big_endian(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static bool valid_quad(size_t i, size_t n, int a, int b, int c, int d)
{
    return a >= 0 && b >= 0 && c != -1 && d != -1 && !(c == -2 && d != -2) &&
        !((c == -2 || d == -2) && i + 4 != n) && !(c == -2 && (b & 15)) && !(d == -2 && c >= 0 && (c & 3));
}
static size_t decode(const char *s, unsigned char *out, size_t cap)
{
    size_t n = strlen(s), used = 0;
    if (!n || n % 4) return 0;
    for (size_t i = 0; i < n; i += 4) {
        int a = b64digit((unsigned char)s[i]), b = b64digit((unsigned char)s[i+1]);
        int c = s[i+2] == '=' ? -2 : b64digit((unsigned char)s[i+2]);
        int d = s[i+3] == '=' ? -2 : b64digit((unsigned char)s[i+3]);
        if (!valid_quad(i, n, a, b, c, d)) return 0;
        size_t count = c == -2 ? 1 : d == -2 ? 2 : 3;
        if (count > cap - used) return 0;
        out[used++] = (unsigned char)((a << 2) | (b >> 4));
        if (count > 1) out[used++] = (unsigned char)((b << 4) | (c >> 2));
        if (count > 2) out[used++] = (unsigned char)((c << 6) | d);
    }
    return used;
}
static bool valid_observation(const struct json_value *root, unsigned expected, uint32_t last_frame)
{
    const struct json_value *v = json_get(root, "v"), *id = json_get(root, "id"), *success = json_get(root, "ok");
    const struct json_value *frame = json_get(root, "frame");
    return v && v->type == JSON_INT && json_get_int(v) == 1 && id && id->type == JSON_INT &&
        json_get_int(id) == expected && success && success->type == JSON_BOOL && json_get_bool(success)
        && frame && frame->type == JSON_INT && json_get_int(frame) >= 0 && json_get_int(frame) <= UINT32_MAX &&
        (expected == 0 ? json_get_int(frame) == 0 : (uint64_t)json_get_int(frame) == (uint64_t)last_frame + 4);
}
static bool png_dimensions(const struct json_value *width, const struct json_value *height, const struct json_value *bytes)
{
    return width && width->type == JSON_INT && json_get_int(width) > 0 && json_get_int(width) <= 640 &&
        height && height->type == JSON_INT && json_get_int(height) > 0 && json_get_int(height) <= 360 &&
        bytes && bytes->type == JSON_INT && json_get_int(bytes) > 0 && json_get_int(bytes) <= PNG_CAP;
}
static size_t decode_png(const struct json_value *root, unsigned char *buf)
{
    const struct json_value *png = json_get(root, "png"), *width = json_get(png, "width"), *height = json_get(png, "height"), *bytes = json_get(png, "bytes");
    const char *encoded = json_get_str(json_get(png, "base64"));
    bool ok = png && png->type == JSON_OBJ && png_dimensions(width, height, bytes) && encoded;
    if (!ok) return 0;
    size_t count = decode(encoded, buf, PNG_CAP);
    static const unsigned char magic[] = {137,80,78,71,13,10,26,10};
    ok = count == (size_t)json_get_int(bytes) && count >= 33 && !memcmp(buf, magic, sizeof(magic)) &&
        big_endian(buf + 8) == 13 && !memcmp(buf + 12, "IHDR", 4) &&
        big_endian(buf + 16) == (uint32_t)json_get_int(width) && big_endian(buf + 20) == (uint32_t)json_get_int(height);
    return ok ? count : 0;
}
static bool consume(const char *wire, unsigned expected, uint32_t *last_frame)
{
    struct json_value root = {0};
    bool ok = json_read(&root, wire, strlen(wire)) && root.type == JSON_OBJ && valid_observation(&root, expected, *last_frame);
    unsigned char *buf = ok ? malloc(PNG_CAP) : NULL;
    size_t count = buf ? decode_png(&root, buf) : 0;
    ok = ok && count > 0;
    if (ok) {
        pthread_mutex_lock(&game.lock);
        bool publish = game.wanted && !atomic_load(&game.cancel);
        if (publish) {
            memcpy(game.png, buf, count); game.png_len = count; ++game.version;
            snprintf(game.status, sizeof(game.status), "Playing");
        }
        pthread_mutex_unlock(&game.lock);
        if (publish) notify_view();
    }
    if (ok) *last_frame = (uint32_t)json_get_int(json_get(&root, "frame"));
    free(buf); json_free(&root); return ok;
}
static bool response(const char *wire, char token[65], char image[65], unsigned id, uint32_t *last_frame)
{
    struct json_value root = {0};
    bool ok = json_read(&root, wire, strlen(wire)) && root.type == JSON_OBJ;
    const char *session = json_get_str(json_get(&root, "session"));
    const char *reply = json_get_str(json_get(&root, "reply"));
    const char *actual_image = json_get_str(json_get(&root, "image_sha256"));
    ok = ok && actual_image && strlen(actual_image) == 64 && strspn(actual_image, "0123456789abcdef") == 64;
    if (ok && id == 0) memcpy(image, actual_image, 65);
    else if (ok) ok = !strcmp(image, actual_image);
    if (id == 0) {
        ok = ok && session && strlen(session) == 64 && strspn(session, "0123456789abcdef") == 64;
        if (ok) memcpy(token, session, 65);
    }
    ok = ok && reply && consume(reply, id, last_frame);
    json_cleanse_strings(&root); json_free(&root); return ok;
}
static bool request(const char *op, const char *token, const char *cmd, char *out, size_t cap, const atomic_bool *cancel)
{
    struct json_value root = {0}; json_set_object(&root);
    bool ok = json_push_kv_str(&root, "schema", "z23.game/1") && json_push_kv_str(&root, "op", op);
    if (token) ok = ok && json_push_kv_str(&root, "session", token);
    if (cmd) ok = ok && json_push_kv_str(&root, "request", cmd);
    char wire[8192];
    ok = ok && json_write(&root, wire, sizeof(wire)) < sizeof(wire);
    if (ok) ok = zapp_bridge_speech(game.files, wire, out, cap, cancel);
    json_cleanse_strings(&root); json_free(&root); return ok;
}
static void pace_frame(const struct timespec *began, bool timed)
{
    struct timespec ended;
    if (!timed || clock_gettime(CLOCK_MONOTONIC, &ended)) return;
    int64_t elapsed = (int64_t)(ended.tv_sec - began->tv_sec) * 1000000000 + ended.tv_nsec - began->tv_nsec;
    if (elapsed >= 0 && elapsed < 66666667) {
        struct timespec pause = {.tv_nsec = (long)(66666667 - elapsed)};
        (void)nanosleep(&pause, NULL);
    }
}
static bool step_game(char token[65], char image[65], unsigned id, uint32_t *last_frame, char *out)
{
    pthread_mutex_lock(&game.lock);
    float x = game.x, y = game.y; bool fire = game.fire, boost = game.boost;
    pthread_mutex_unlock(&game.lock);
    char cmd[512];
    int n = snprintf(cmd, sizeof(cmd), "{\"v\":1,\"id\":%u,\"op\":\"step\",\"frames\":4,\"capture\":true,\"input\":{\"move_x\":%.3f,\"move_y\":%.3f,\"camera_x\":0,\"fire_guns\":%s,\"speed_boost\":%s,\"throttle\":false}}", id, (double)x, (double)y, fire ? "true" : "false", boost ? "true" : "false");
    return n > 0 && (size_t)n < sizeof(cmd) && request("step", token, cmd, out, RESPONSE_CAP, &game.cancel) && response(out, token, image, id, last_frame);
}
static const char *failure_text(bool allocated, bool started)
{
    if (!allocated) return "Could not start Play on this phone. Go Back and try again.";
    if (started) return "Game disconnected. Check laptop game host and USB. Back > Play to retry. If pairing changed: Back > Scan QR, compare codes and Accept.";
    return "Start your laptop's Z23 game host and connect USB. For pairing: Back > Scan its QR code, compare the codes and Accept. Then open More > Play.";
}
static void *run(void *unused)
{
    (void)unused;
    for (;;) {
    char token[65] = "", image[65] = "", *out = malloc(RESPONSE_CAP);
    bool allocated = out != NULL;
    uint32_t last_frame = 0;
    bool ok = out && request("start", NULL, NULL, out, RESPONSE_CAP, &game.cancel) && response(out, token, image, 0, &last_frame);
    bool started = ok;
    unsigned id = 1;
    while (ok && !atomic_load(&game.cancel) && id < UINT32_MAX) {
        struct timespec began;
        bool timed = clock_gettime(CLOCK_MONOTONIC, &began) == 0;
        ok = step_game(token, image, id, &last_frame, out);
        ++id;
        pace_frame(&began, timed);
    }
    if (token[0] && out) (void)request("close", token, NULL, out, RESPONSE_CAP, NULL);
    free(out);
    pthread_mutex_lock(&game.lock);
    if (game.wanted && atomic_load(&game.cancel)) {
        memcpy(game.files, game.pending_files, sizeof(game.files));
        atomic_store(&game.cancel, false);
        snprintf(game.status, sizeof(game.status), "Connecting to the paired game host…");
        pthread_mutex_unlock(&game.lock);
        notify_view();
        continue;
    }
    if (game.wanted) snprintf(game.status, sizeof(game.status), "%s", failure_text(allocated, started));
    game.running = false;
    pthread_mutex_unlock(&game.lock);
    notify_view();
    return NULL;
    }
}
bool zapp_game_open(const char *files)
{
    if (!files || strlen(files) >= sizeof(game.files)) return false;
    pthread_mutex_lock(&game.lock);
    if (game.running) {
        if (atomic_load(&game.cancel)) {
            snprintf(game.pending_files, sizeof(game.pending_files), "%s", files);
            game.wanted = true; game.png_len = 0; ++game.version;
            game.x = game.y = 0; game.fire = game.boost = false;
            snprintf(game.status, sizeof(game.status), "Finishing the previous game…");
        }
        pthread_mutex_unlock(&game.lock); notify_view(); return true;
    }
    memcpy(game.files, files, strlen(files) + 1); game.running = true; game.wanted = true; game.png_len = 0; ++game.version;
    game.x = game.y = 0; game.fire = game.boost = false; atomic_store(&game.cancel, false);
    snprintf(game.status, sizeof(game.status), "Connecting to the paired game host…");
    pthread_t thread;
    bool ok = pthread_create(&thread, NULL, run, NULL) == 0;
    if (ok) pthread_detach(thread);
    else { game.running = false; game.wanted = false; snprintf(game.status, sizeof(game.status), "%s", failure_text(false, false)); }
    pthread_mutex_unlock(&game.lock); notify_view(); return ok;
}
void zapp_game_close(void)
{
    pthread_mutex_lock(&game.lock);
    game.wanted = false; atomic_store(&game.cancel, true);
    game.x = game.y = 0; game.fire = game.boost = false; game.png_len = 0; ++game.version;
    pthread_mutex_unlock(&game.lock);
}
void zapp_game_controls(float x, float y, bool fire, bool boost)
{
    pthread_mutex_lock(&game.lock);
    game.x = isfinite(x) ? fmaxf(-1, fminf(1, x)) : 0; game.y = isfinite(y) ? fmaxf(-1, fminf(1, y)) : 0;
    game.fire = fire; game.boost = boost;
    pthread_mutex_unlock(&game.lock);
}
size_t zapp_game_frame(unsigned char *out, size_t cap, uint64_t *version)
{
    if (!out || !version) return 0;
    pthread_mutex_lock(&game.lock);
    size_t n = game.version != *version && game.png_len <= cap ? game.png_len : 0;
    if (n) { memcpy(out, game.png, n); *version = game.version; }
    pthread_mutex_unlock(&game.lock); return n;
}
void zapp_game_status(char *out, size_t cap)
{
    if (!out || !cap) return;
    pthread_mutex_lock(&game.lock); snprintf(out, cap, "%s", game.status); pthread_mutex_unlock(&game.lock);
}
