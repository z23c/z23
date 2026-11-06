/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <string.h>
/* Exercise the actual bounded decoder and response checks without a network. */
#include "../game.c"
static atomic_int starts;
static atomic_bool step_entered, close_entered, release_close;
static const char *first = "{\"v\":1,\"id\":0,\"ok\":true,\"frame\":0,\"png\":{\"width\":1,\"height\":1,\"bytes\":68,\"base64\":\"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=\"}}";
static void nap(void) { struct timespec t = {.tv_nsec = 1000000}; (void)nanosleep(&t, NULL); }
bool zapp_bridge_speech(const char *files, const char *request, char *out, size_t cap, const atomic_bool *cancel)
{
    (void)files;
    if (strstr(request, "\"op\":\"start\"")) {
        if (atomic_fetch_add(&starts, 1) != 0) return false; /* Second start fails visibly. */
        struct json_value result = {0}; json_set_object(&result);
        bool ok = json_push_kv_str(&result, "session", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") &&
            json_push_kv_str(&result, "image_sha256", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") &&
            json_push_kv_str(&result, "reply", first) && json_write(&result, out, cap) < cap;
        json_free(&result); return ok;
    }
    if (strstr(request, "\"op\":\"step\"")) {
        atomic_store(&step_entered, true);
        while (!atomic_load(cancel)) nap();
        return false;
    }
    if (strstr(request, "\"op\":\"close\"")) {
        atomic_store(&close_entered, true);
        while (!atomic_load(&release_close)) nap();
    }
    return false;
}
static void wait_flag(const atomic_bool *flag)
{
    for (int i = 0; i < 5000 && !atomic_load(flag); i++) nap();
    assert(atomic_load(flag));
}
static void check_codec(void)
{
    unsigned char out[8];
    assert(decode("AQID", out, sizeof(out)) == 3 && out[0] == 1 && out[1] == 2 && out[2] == 3);
    assert(decode("AQ==", out, sizeof(out)) == 1 && out[0] == 1);
    assert(decode("AR==", out, sizeof(out)) == 0);
    assert(decode("AQ=A", out, sizeof(out)) == 0);
    assert(decode("AQID", out, 2) == 0);
    uint32_t frame = 0;
    const char *step = "{\"v\":1,\"id\":1,\"ok\":true,\"frame\":4,\"png\":{\"width\":1,\"height\":1,\"bytes\":68,\"base64\":\"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=\"}}";
    atomic_store(&game.cancel, false);
    assert(consume(first, 0, &frame));
    assert(!consume(step, 2, &frame));
    assert(consume(step, 1, &frame) && frame == 4);
    assert(!consume(step, 1, &frame));
    zapp_game_controls(4, -4, true, true);
    assert(game.x == 1 && game.y == -1 && game.fire && game.boost);
    zapp_game_close(); assert(game.x == 0 && game.y == 0 && !game.fire && !game.boost);
}
int main(void)
{
    check_codec();
    assert(zapp_game_open("/fixture"));
    wait_flag(&step_entered);
    zapp_game_close();
    wait_flag(&close_entered);
    assert(zapp_game_open("/fixture"));
    uint32_t frame = 0;
    assert(consume(first, 0, &frame)); /* A late old reply must not republish its image. */
    pthread_mutex_lock(&game.lock);
    assert(game.wanted && game.png_len == 0 && strstr(game.status, "Finishing"));
    pthread_mutex_unlock(&game.lock);
    assert(atomic_load(&starts) == 1);
    atomic_store(&release_close, true);
    for (int i = 0; i < 5000 && atomic_load(&starts) < 2; i++) nap();
    assert(atomic_load(&starts) == 2);
    bool done = false;
    for (int i = 0; i < 5000 && !done; i++) {
        pthread_mutex_lock(&game.lock); done = !game.running; pthread_mutex_unlock(&game.lock);
        if (!done) nap();
    }
    assert(done);
    char status[160]; zapp_game_status(status, sizeof(status));
    assert(strstr(status, "Could not start") && !strstr(status, "SHA-256"));
    puts("game control and decode passed"); return 0;
}
