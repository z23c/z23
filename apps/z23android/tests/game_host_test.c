/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "game_host.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static atomic_bool alive = true;
bool zapp_relay_client_alive(int fd) { (void)fd; return atomic_load(&alive); }
bool zapp_auth_random(unsigned char *out, size_t n)
{
    static unsigned char value;
    memset(out, ++value, n); return true;
}
void zapp_auth_hex(const unsigned char *in, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = h[in[i] >> 4]; out[i*2+1] = h[in[i] & 15]; }
    out[2*n] = 0;
}
static void script(const char *path, const char *tag)
{
    FILE *f = fopen(path, "w"); assert(f);
    assert(fprintf(f, "#!/bin/sh\nwhile IFS= read -r line; do printf '%%s\\n' '%s'; done\n", tag) > 0);
    assert(fclose(f) == 0); assert(chmod(path, 0700) == 0);
}
int main(void)
{
    char dir[] = "/tmp/z23-game-test-XXXXXX", path[256]; assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/game", dir); script(path, "first");
    assert(zapp_game_host_configure(path));
    char token[65], image[65], other_token[65], other_image[65], reply[128];
    assert(zapp_game_host_start(-1, token, image, reply, sizeof(reply)) && !strcmp(reply, "first"));
    assert(!zapp_game_host_start(-1, other_token, other_image, reply, sizeof(reply)));
    assert(!zapp_game_host_call(-1, "wrong", "{}", other_image, reply, sizeof(reply)));
    assert(zapp_game_host_call(-1, token, "{}", other_image, reply, sizeof(reply)) && !strcmp(image, other_image));
    assert(!zapp_game_host_close("wrong")); assert(zapp_game_host_close(token));
    script(path, "second");
    assert(zapp_game_host_start(-1, other_token, other_image, reply, sizeof(reply)) && !strcmp(reply, "second"));
    assert(strcmp(image, other_image));
    assert(!zapp_game_host_call(-1, token, "{}", image, reply, sizeof(reply)));
    atomic_store(&alive, false);
    assert(!zapp_game_host_call(-1, other_token, "{}", image, reply, sizeof(reply)));
    atomic_store(&alive, true);
    assert(!zapp_game_host_close(other_token));
    assert(zapp_game_host_start(-1, token, image, reply, sizeof(reply)));
    struct timespec wait = {.tv_sec = 16}; nanosleep(&wait, NULL);
    assert(!zapp_game_host_call(-1, token, "{}", image, reply, sizeof(reply)));
    zapp_game_host_shutdown(); unlink(path); rmdir(dir);
    puts("game host lifecycle passed"); return 0;
}
