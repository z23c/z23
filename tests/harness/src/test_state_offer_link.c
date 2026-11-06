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
/* Several downloaders share the server: each owns one object stream. */
#define SLOT_TEST_PEERS 4u
struct slot_fixture {
    char dir[256], path[512];
    struct rom_artifact *artifact;
    uint8_t *wire;
    bool registered, started;
    uint32_t got[SLOT_TEST_PEERS + 2];
};
static bool slot_setup(struct slot_fixture *f)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "state_offer_link", "slots");
    snprintf(f->path, sizeof(f->path), "%s/consensus-state-bundle-200.sqlite", f->dir);
    f->artifact = calloc(1, sizeof(*f->artifact));
    f->wire = malloc(STATE_OFFER_LINK_FRAME_MAX);
    if (!f->artifact || !f->wire) return false;
    int fd = open(f->path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    bool ok = write(fd, "SQLite format 3", 16) == 16 && !ftruncate(fd, ROM_SEED_CHUNK_SIZE);
    close(fd);
    rom_seed_reset(); rom_seed_set_enabled(true);
    rom_seed_set_global_bps_cap(UINT64_C(1) << 40);
    if (!ok || rom_seed_register(f->dir, "consensus-state-bundle-200.sqlite", NULL, f->artifact) != ROM_REG_OK)
        return false;
    f->registered = true;
    f->started = state_offer_link_server_start(f->dir, NULL);
    return f->started;
}
/* Each peer has its own address so the per-address throttle stays out of the way. */
static bool slot_ask(struct slot_fixture *f, uint64_t peer, uint64_t nonce)
{
    struct state_offer_link_frame req = {.kind = STATE_OFFER_LINK_CHUNK_REQUEST, .nonce = nonce,
        .total = ROM_SEED_CHUNK_SIZE};
    memcpy(req.digest, f->artifact->chunk_root, 32);
    uint8_t ip[16] = {0};
    ip[14] = (uint8_t)(peer >> 8); ip[15] = (uint8_t)peer;
    return state_offer_link_server_request(peer, ip, &req);
}
/* Take one frame for peer index i; false when nothing is ready yet. */
static bool slot_take(struct slot_fixture *f, uint64_t peer, unsigned i, uint64_t nonce, bool *bad)
{
    size_t n = 0; struct state_offer_link_frame part;
    if (!state_offer_link_server_next(peer, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n)) return false;
    *bad |= !state_offer_link_decode(f->wire, n, &part) || part.kind != STATE_OFFER_LINK_CHUNK_PART ||
        part.nonce != nonce || part.offset != f->got[i] || part.total != ROM_SEED_CHUNK_SIZE ||
        (!part.offset && memcmp(part.data, "SQLite format 3", 16));
    f->got[i] += part.size;
    return true;
}
/* Wait until every listed peer has received its first frame. */
static bool slot_all_started(struct slot_fixture *f, uint64_t first, unsigned count, uint64_t nonce)
{
    bool bad = false;
    for (int round = 0; round < 20000 && !bad; ++round) {
        unsigned started = 0;
        for (unsigned i = 0; i < count; ++i)
            started += f->got[i] || slot_take(f, first + i, i, nonce, &bad);
        if (started == count) return !bad;
        test_wait();
    }
    return false;
}
/* Round-robin drain one frame per peer per pass until each object is complete. */
static bool slot_finish(struct slot_fixture *f, uint64_t first, unsigned count, uint64_t nonce)
{
    bool bad = false;
    for (int round = 0; round < 20000 && !bad; ++round) {
        unsigned done = 0;
        for (unsigned i = 0; i < count; ++i) {
            if (f->got[i] < ROM_SEED_CHUNK_SIZE) (void)slot_take(f, first + i, i, nonce, &bad);
            done += f->got[i] == ROM_SEED_CHUNK_SIZE;
        }
        if (done == count) return !bad;
        test_wait();
    }
    return false;
}
/* Peers 1..4 stream at once while peer 99 has asked and then stopped reading. */
static bool slot_parallel(struct slot_fixture *f)
{
    if (!slot_ask(f, 99, 990)) return false;
    for (unsigned pass = 0; pass < 2; ++pass) {
        memset(f->got, 0, sizeof(f->got));
        for (uint64_t p = 1; p <= SLOT_TEST_PEERS; ++p)
            if (!slot_ask(f, p, 100 + pass)) return false;
        if (!slot_all_started(f, 1, SLOT_TEST_PEERS, 100 + pass) ||
            !slot_finish(f, 1, SLOT_TEST_PEERS, 100 + pass)) return false;
    }
    /* The stalled reader kept its own stream and can still finish it. */
    memset(f->got, 0, sizeof(f->got));
    return slot_finish(f, 99, 1, 990);
}
/* Answer one client object request the way the peer adapter does: serve it
 * when a slot admits it, otherwise send the retryable refusal. */
static bool slot_serve(struct slot_fixture *f, struct link_read_test *r,
                       const struct state_offer_link_frame *req, bool admit)
{
    uint8_t ip[16] = {0}; ip[15] = (uint8_t)r->peer;
    bool admitted = state_offer_link_server_request(r->peer, ip, req);
    for (int i = 0; admit && !admitted && i < 5000; ++i) {
        test_wait();
        admitted = state_offer_link_server_request(r->peer, ip, req);
    }
    if (admitted != admit) return false;
    if (!admitted) {
        struct state_offer_link_frame refusal = {.kind = STATE_OFFER_LINK_REFUSAL, .nonce = req->nonce};
        memcpy(refusal.digest, req->digest, 32);
        return sol_client_consume(r->peer, &refusal);
    }
    for (int i = 0; i < 20000 && !atomic_load(&r->done); ++i) {
        size_t n = 0; struct state_offer_link_frame part;
        if (!state_offer_link_server_next(r->peer, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n)) { test_wait(); continue; }
        if (!state_offer_link_decode(f->wire, n, &part) || !sol_client_consume(r->peer, &part)) return false;
    }
    return true;
}
/* One blocking client read against the server; the reader is always joined. */
static bool slot_read_once(struct slot_fixture *f, struct link_read_test *r, bool admit)
{
    pthread_t t; struct state_offer_link_frame req;
    atomic_store(&r->done, false);
    if (pthread_create(&t, NULL, test_read, r)) return false;
    bool ok = false;
    for (int i = 0; i < 5000 && !ok; ++i) { ok = sol_client_poll(r->peer, &req); if (!ok) test_wait(); }
    ok = ok && slot_serve(f, r, &req, admit);
    if (!ok) sol_client_shutdown();
    (void)pthread_join(t, NULL);
    return ok;
}
/* Fill every slot, refuse a further connection and a second object on a busy
 * one, free a slot by disconnect and let the refused reader retry. */
static bool slot_full_retry(struct slot_fixture *f)
{
    for (uint64_t p = 201; p < 201 + STATE_OFFER_LINK_SERVER_SLOTS; ++p)
        if (!slot_ask(f, p, 200)) return false;
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS + 1];
    if (state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS + 1) != STATE_OFFER_LINK_SERVER_SLOTS ||
        slot_ask(f, 201, 201)) return false;
    struct link_read_test r = {.peer = 300};
    memcpy(r.root, f->artifact->chunk_root, 32);
    r.body = malloc(ROM_SEED_CHUNK_SIZE);
    bool client = r.body && sol_client_start(r.peer, test_wake, NULL);
    bool ok = client && slot_read_once(f, &r, false) && r.result == SOL_READ_UNAVAILABLE;
    state_offer_link_server_drop(201);
    ok = ok && slot_read_once(f, &r, true) && r.result == SOL_READ_OK && r.size == ROM_SEED_CHUNK_SIZE &&
        !memcmp(r.body, "SQLite format 3", 16);
    if (client) sol_client_shutdown();
    free(r.body);
    return ok;
}
/* Shutdown with ready and working slots joins every reader and frees every
 * buffer; the server then restarts empty and serves again. */
static bool slot_shutdown_restart(struct slot_fixture *f)
{
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS];
    if (!slot_ask(f, 400, 400)) return false;
    state_offer_link_server_shutdown();
    f->started = false;
    if (state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS) || slot_ask(f, 401, 401)) return false;
    f->started = state_offer_link_server_start(f->dir, NULL);
    memset(f->got, 0, sizeof(f->got));
    return f->started && slot_ask(f, 402, 402) && slot_finish(f, 402, 1, 402);
}
static bool slot_wait_gate(unsigned waiting)
{
    for (int i = 0; i < 5000; ++i) {
        if (state_offer_link_test_gate_waiting() == waiting) return true;
        test_wait();
    }
    return false;
}
static bool slot_wait_idle(void)
{
    for (int i = 0; i < 5000; ++i) {
        if (!state_offer_link_test_working()) return true;
        test_wait();
    }
    return false;
}
/* Every slot admits a new connection and is released again. */
static bool slot_fill_all(struct slot_fixture *f, uint64_t first)
{
    bool ok = true;
    for (uint64_t p = first; ok && p < first + STATE_OFFER_LINK_SERVER_SLOTS; ++p) ok = slot_ask(f, p, first);
    for (uint64_t p = first; p < first + STATE_OFFER_LINK_SERVER_SLOTS; ++p) state_offer_link_server_drop(p);
    return slot_wait_idle() && ok;
}
/* A disconnect while the worker is mid-read releases the connection at once;
 * the late result is discarded and the slot returns to service. */
static bool slot_disconnect_mid_read(struct slot_fixture *f)
{
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS]; size_t n = 0;
    state_offer_link_test_gate(true);
    bool ok = slot_ask(f, 600, 600) && slot_wait_gate(1);
    state_offer_link_server_drop(600);
    ok = ok && !state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS);
    state_offer_link_test_gate(false);
    ok = ok && slot_wait_idle() && !state_offer_link_server_next(600, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n);
    return ok && slot_fill_all(f, 700);
}
static void *slot_shutdown_thread(void *arg)
{
    state_offer_link_server_shutdown();
    atomic_store((atomic_bool *)arg, true);
    return NULL;
}
/* Shutdown while a worker is mid-read waits for it, discards its result and
 * leaves no worker unjoined; the server restarts with every slot usable. */
static bool slot_shutdown_mid_read(struct slot_fixture *f)
{
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS]; size_t n = 0;
    atomic_bool done = false; pthread_t t;
    state_offer_link_test_gate(true);
    bool ok = slot_ask(f, 610, 610) && slot_wait_gate(1) && !pthread_create(&t, NULL, slot_shutdown_thread, &done);
    bool spawned = ok;
    for (int i = 0; ok && i < 5000 && state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS); ++i)
        test_wait();
    ok = ok && !state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS) && !atomic_load(&done) &&
        state_offer_link_test_gate_waiting() == 1;
    state_offer_link_test_gate(false);
    if (spawned) { (void)pthread_join(t, NULL); f->started = false; }
    ok = ok && atomic_load(&done) && state_offer_link_test_all_joined() &&
        !state_offer_link_server_next(610, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n);
    if (!ok || f->started) return false;
    f->started = state_offer_link_server_start(f->dir, NULL);
    return f->started && slot_fill_all(f, 720);
}
/* The client abandons an object after the client idle interval; a request
 * on the same connection before then is refused, after it replaces the
 * abandoned stream from offset 0. */
static bool slot_stale_replace(struct slot_fixture *f)
{
    memset(f->got, 0, sizeof(f->got));
    bool ok = slot_ask(f, 620, 620) && slot_all_started(f, 620, 1, 620) && !slot_ask(f, 620, 621);
    state_offer_link_test_advance_ms((int64_t)STATE_OFFER_LINK_CLIENT_IDLE_SECONDS * 1000);
    memset(f->got, 0, sizeof(f->got));
    return ok && slot_ask(f, 620, 621) && slot_finish(f, 620, 1, 621);
}
/* A silent connection's slot is swept after 45 s without progress. */
static bool slot_idle_sweep(struct slot_fixture *f)
{
    uint64_t held[STATE_OFFER_LINK_SERVER_SLOTS]; size_t n = 0;
    memset(f->got, 0, sizeof(f->got));
    bool ok = slot_ask(f, 630, 630) && slot_all_started(f, 630, 1, 630);
    state_offer_link_test_advance_ms(44000);
    state_offer_link_server_tick();
    ok = ok && state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS) == 1;
    state_offer_link_test_advance_ms(1000);
    state_offer_link_server_tick();
    return ok && !state_offer_link_server_peers(held, STATE_OFFER_LINK_SERVER_SLOTS) &&
        !state_offer_link_server_next(630, f->wire, STATE_OFFER_LINK_FRAME_MAX, &n);
}
static void slot_cleanup(struct slot_fixture *f)
{
    if (f->started) state_offer_link_server_shutdown();
    rom_seed_reset();
    if (f->registered) (void)unlink(f->path);
    (void)rmdir(f->dir);
    free(f->wire); free(f->artifact);
}
static int test_slots(void)
{
    struct slot_fixture f = {0};
    static const struct { const char *name; bool (*run)(struct slot_fixture *); } phases[] = {
        {"parallel", slot_parallel}, {"full_retry", slot_full_retry},
        {"shutdown_restart", slot_shutdown_restart}, {"disconnect_mid_read", slot_disconnect_mid_read},
        {"shutdown_mid_read", slot_shutdown_mid_read}, {"stale_replace", slot_stale_replace},
        {"idle_sweep", slot_idle_sweep}};
    bool ok = slot_setup(&f);
    const char *failed = ok ? NULL : "setup";
    for (size_t i = 0; ok && i < sizeof(phases) / sizeof(phases[0]); ++i)
        if (!(ok = phases[i].run(&f))) failed = phases[i].name;
    state_offer_link_test_gate(false);
    slot_cleanup(&f);
    if (!ok) fprintf(stderr, "state_offer_link: concurrent serve slots failed in %s\n", failed);
    else puts("state_offer_link slots: ok");
    return ok ? 0 : 1;
}
#else
static int test_window(void) { return 0; }
static int test_slots(void) { return 0; }
#endif

int test_state_offer_link(void) { return test_codec() + test_window() + test_slots(); }
#ifdef STATE_OFFER_LINK_STANDALONE
int main(void) { return test_state_offer_link(); }
#endif
