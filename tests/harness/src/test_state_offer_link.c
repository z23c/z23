/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "config/state_offer_link.h"
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include "config/state_offer_link_session.h"
#include "net/rom_seed.h"
#include "test/test_core.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); return 1; } } while (0)

static int test_codec(void)
{
    uint8_t wire[STATE_OFFER_LINK_FRAME_MAX], data[] = {1, 2, 3};
    struct state_offer_link_frame f = {.kind = STATE_OFFER_LINK_CHUNK_PART, .nonce = 7,
        .index = 9, .offset = 3, .total = 6, .size = sizeof(data), .data = data}, got = {0};
    f.digest[0] = 42;
    size_t n = 0;
    CHECK(state_offer_link_encode(&f, wire, sizeof(wire), &n));
    CHECK(state_offer_link_decode(wire, n, &got));
    CHECK(got.kind == f.kind && got.nonce == 7 && got.digest[0] == 42 && got.index == 9 &&
           got.offset == 3 && got.total == 6 && got.size == 3 && !memcmp(got.data, data, 3));
    CHECK(!state_offer_link_decode(wire, n - 1, &got));
    wire[6] = 1; CHECK(!state_offer_link_decode(wire, n, &got)); wire[6] = 0;
    f.offset = 4; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    f.kind = STATE_OFFER_LINK_MANIFEST_REQUEST; f.index = 0; f.offset = 65535; f.total = 65000; f.size = 0;
    CHECK(state_offer_link_encode(&f, wire, sizeof(wire), &n));
    CHECK(state_offer_link_decode(wire, n, &got) && got.offset == 65535 && got.total == 65000);
    f.total = 131081; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    f.total = 1; f.nonce = 0; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    static uint8_t payload[STATE_OFFER_LINK_PAYLOAD_MAX];
    f = (struct state_offer_link_frame){.kind = STATE_OFFER_LINK_CHUNK_PART, .nonce = 1,
        .total = sizeof(payload), .size = sizeof(payload), .data = payload};
    CHECK(state_offer_link_encode(&f, wire, sizeof(wire), &n) && n == sizeof(wire));
    CHECK(state_offer_link_decode(wire, n, &got) && got.size == sizeof(payload));
    f.index = 4096; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    f.index = 0; f.offset = UINT32_MAX; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    f = (struct state_offer_link_frame){.kind = STATE_OFFER_LINK_OFFER_REQUEST, .nonce = 2};
    CHECK(state_offer_link_encode(&f, wire, sizeof(wire), &n) && state_offer_link_decode(wire, n, &got));
    f = (struct state_offer_link_frame){.kind = STATE_OFFER_LINK_OFFER_REPLY, .nonce = 2,
        .total = sizeof(data), .size = sizeof(data), .data = data};
    CHECK(state_offer_link_encode(&f, wire, sizeof(wire), &n) && state_offer_link_decode(wire, n, &got));
    f.offset = 1; CHECK(!state_offer_link_encode(&f, wire, sizeof(wire), &n));
    puts("state_offer_link codec: ok");
    return 0;
}

#if !defined(_WIN32)
struct link_read_test {
    uint64_t peer;
    uint8_t root[32], *body;
    uint32_t size;
    enum sol_read_result result;
    atomic_bool done;
};
static void test_wake(void *ctx) { (void)ctx; }
static void *test_read(void *ctx)
{
    struct link_read_test *t = ctx;
    t->result = sol_client_read(&t->peer, SOL_OBJECT_CHUNK, t->root, 0, t->body, ROM_SEED_CHUNK_SIZE, &t->size);
    atomic_store(&t->done, true);
    return NULL;
}
static void test_wait(void) { struct timespec t = {0, 1000000}; (void)nanosleep(&t, NULL); }

struct window_fixture {
    char dir[256], path[512];
    int fd;
    bool sender, client, thread_started;
    pthread_t thread;
    struct link_read_test read;
    struct rom_artifact *artifact;
    uint8_t *wire;
    struct state_offer_link_frame request;
};
static bool window_setup(struct window_fixture *f)
{
    f->fd = -1; f->read.peer = 19;
    test_make_tmpdir(f->dir, sizeof(f->dir), "state_offer_link", "window");
    snprintf(f->path, sizeof(f->path), "%s/consensus-state-bundle-100.sqlite", f->dir);
    f->artifact = calloc(1, sizeof(*f->artifact));
    f->wire = malloc(STATE_OFFER_LINK_FRAME_MAX);
    f->read.body = malloc(ROM_SEED_CHUNK_SIZE);
    if (!f->artifact || !f->wire || !f->read.body) return false;
    f->fd = open(f->path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (f->fd < 0 || write(f->fd, "SQLite format 3", 16) != 16 || ftruncate(f->fd, ROM_SEED_CHUNK_SIZE)) return false;
    close(f->fd); f->fd = -1;
    rom_seed_reset(); rom_seed_set_enabled(true);
    if (rom_seed_register(f->dir, "consensus-state-bundle-100.sqlite", NULL, f->artifact) != ROM_REG_OK) return false;
    memcpy(f->read.root, f->artifact->chunk_root, 32);
    if (!state_offer_link_server_start(f->dir, NULL)) return false;
    f->sender = true;
    if (!sol_client_start(f->read.peer, test_wake, NULL)) return false;
    f->client = true;
    return true;
}
static bool window_request(struct window_fixture *f)
{
    atomic_store(&f->read.done, false);
    if (pthread_create(&f->thread, NULL, test_read, &f->read)) return false;
    f->thread_started = true;
    for (int i = 0; i < 5000; ++i) {
        if (sol_client_poll(f->read.peer, &f->request)) return true;
        test_wait();
    }
    return false;
}
static bool window_join(struct window_fixture *f, enum sol_read_result result)
{
    if (pthread_join(f->thread, NULL)) return false;
    f->thread_started = false;
    return f->read.result == result;
}
static bool window_first_part(struct window_fixture *f, const struct state_offer_link_frame *part)
{
    if (sol_client_consume(f->read.peer + 1, part)) return false;
    struct state_offer_link_frame wrong = *part;
    wrong.nonce++;
    if (sol_client_consume(f->read.peer, &wrong)) return false;
    wrong = *part; wrong.digest[0] ^= 1;
    return !sol_client_consume(f->read.peer, &wrong);
}
static bool window_transfer(struct window_fixture *f)
{
    if (!window_request(f)) return false;
    uint8_t ip[16] = {0};
    if (!state_offer_link_server_request(f->read.peer, ip, &f->request)) return false;
    unsigned frames = 0;
    for (int i = 0; i < 10000 && !atomic_load(&f->read.done); ++i) {
        size_t n = 0;
        if (!state_offer_link_server_next(f->read.peer, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n)) { test_wait(); continue; }
        struct state_offer_link_frame part;
        if (!state_offer_link_decode(f->wire, n, &part) || (!frames && !window_first_part(f, &part)) ||
            !sol_client_consume(f->read.peer, &part)) return false;
        frames++;
    }
    return atomic_load(&f->read.done) && window_join(f, SOL_READ_OK) && f->read.size == ROM_SEED_CHUNK_SIZE &&
        frames == 129 && !memcmp(f->read.body, "SQLite format 3", 16);
}
static bool window_rate_limit(struct window_fixture *f)
{
    uint8_t ip[16] = {0}; ip[15] = 1;
    rom_seed_set_peer_bps_cap(1);
    if (!state_offer_link_server_request(f->read.peer, ip, &f->request)) return false;
    for (int i = 0; i < 5000; ++i) {
        size_t n = 0; struct state_offer_link_frame part;
        if (state_offer_link_server_next(f->read.peer, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n))
            return state_offer_link_decode(f->wire, n, &part) && part.kind == STATE_OFFER_LINK_REFUSAL;
        test_wait();
    }
    return false;
}
static bool window_duplicate(struct window_fixture *f)
{
    if (!window_request(f)) return false;
    uint8_t byte = 0;
    struct state_offer_link_frame part = {.kind = STATE_OFFER_LINK_CHUNK_PART, .nonce = f->request.nonce,
        .offset = 0, .total = 2, .size = 1, .data = &byte};
    memcpy(part.digest, f->read.root, 32);
    return sol_client_consume(f->read.peer, &part) && sol_client_consume(f->read.peer, &part) &&
        window_join(f, SOL_READ_BAD_DATA);
}
static bool window_cancel(struct window_fixture *f)
{
    if (!window_request(f)) return false;
    sol_client_drop(f->read.peer);
    return window_join(f, SOL_READ_CANCELLED);
}
static void window_cleanup(struct window_fixture *f)
{
    if (f->client) sol_client_shutdown();
    if (f->thread_started) (void)pthread_join(f->thread, NULL);
    if (f->sender) state_offer_link_server_shutdown();
    if (f->fd >= 0) close(f->fd);
    rom_seed_set_peer_bps_cap(ROM_SEED_DEFAULT_PEER_BPS_CAP);
    rom_seed_reset(); (void)unlink(f->path); (void)rmdir(f->dir);
    free(f->read.body); free(f->wire); free(f->artifact);
}
/* Real registry and ROM reader: one object request crosses 129 bounded frames. */
static int test_window(void)
{
    struct window_fixture f = {0};
    bool ok = window_setup(&f) && window_transfer(&f) && window_rate_limit(&f) &&
        window_duplicate(&f) && window_cancel(&f);
    window_cleanup(&f);
    if (!ok) fprintf(stderr, "state_offer_link: live window failed\n");
    return ok ? 0 : 1;
}
#else
static int test_window(void) { return 0; }
#endif

int test_state_offer_link(void) { return test_codec() + test_window(); }
#ifdef STATE_OFFER_LINK_STANDALONE
int main(void) { return test_state_offer_link(); }
#endif
