/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the smoke round trip of a renewed pairing: the real HOST receiver
 * and client runtimes, each holding its own grant, are run on loopback and the
 * target's first bytes must come back through the authenticated tunnel. This
 * is the native equivalent of the rollout's 40-smoke; it mutates nothing. */
#include "command/native_pair_common.h"
#include "services/device_host_runtime.h"
#include "services/device_identity.h"
#include "platform/clock.h"
#include "util/log_macros.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#define SMOKE_TAG "native.pair_smoke"
#define SMOKE_BANNER "SSH-"
#define SMOKE_DRAIN_MS 3000

struct smoke_rx {
    struct device_host_runtime_receiver_spec spec;
    struct device_host_runtime_observation obs;
    struct zcl_result result;
    atomic_uint port;
    atomic_bool cancel, done;
    pthread_t thread;
    bool started;
};
struct smoke_cl {
    struct device_host_runtime_client_spec spec;
    struct device_host_runtime_observation obs;
    struct zcl_result result;
    atomic_bool cancel, done;
    pthread_t thread;
    bool started;
};
struct smoke_side {
    struct device_identity identity;
    struct device_pairing_store store;
    bool open;
};

static void smoke_ready(void *context, const struct device_host_runtime_observation *observation)
{
    atomic_store(&((struct smoke_rx *)context)->port, observation->listen_port);
}
static void *smoke_rx_main(void *opaque)
{
    struct smoke_rx *rx = opaque;
    rx->result = device_host_runtime_receiver_run(&rx->spec, &rx->obs);
    atomic_store(&rx->done, true);
    return NULL;
}
static void *smoke_cl_main(void *opaque)
{
    struct smoke_cl *cl = opaque;
    cl->result = device_host_runtime_client_run(&cl->spec, &cl->obs);
    atomic_store(&cl->done, true);
    return NULL;
}

static bool smoke_side_open(struct smoke_side *side, const char *profile, const uint8_t peer[32])
{
    struct device_identity_publication_report report;
    side->open = device_identity_open(&side->identity, profile, false, &report).ok;
    return side->open && device_identity_pair_store(&side->identity, peer, &side->store).ok;
}
static void smoke_side_close(struct smoke_side *side)
{
    if (side->open) device_identity_close(&side->identity);
    side->open = false;
}

static void smoke_common(struct device_host_runtime_common *common, struct smoke_side *side, const uint8_t peer[32],
                         const uint8_t root[32], uint16_t target, uint32_t budget_ms, const atomic_bool *cancel)
{
    common->store = &side->store;
    memcpy(common->peer, peer, 32);
    memcpy(common->approved_root, root, 32);
    common->target_port = target;
    common->handshake_ms = 5000;
    common->session_ms = budget_ms;
    common->idle_ms = 5000;
    common->cancelled = cancel;
}

static int64_t smoke_deadline(uint32_t ms) { return clock_now_monotonic_ns() + (int64_t)ms * INT64_C(1000000); }

static bool smoke_pipe(int fds[2])
{
    int raw[2];
    if (pipe(raw) != 0) return false;
    for (int i = 0; i < 2; ++i) {
        fds[i] = fcntl(raw[i], F_DUPFD_CLOEXEC, 3);
        if (fds[i] < 0 || fcntl(fds[i], F_SETFL, O_NONBLOCK) != 0) {
            close(raw[0]); close(raw[1]);
            if (fds[i] >= 0) close(fds[i]);
            return false;
        }
    }
    close(raw[0]); close(raw[1]);
    return true;
}

static bool smoke_wait_ready(struct smoke_rx *rx, int64_t deadline)
{
    while (clock_now_monotonic_ns() < deadline && !atomic_load(&rx->done) && !atomic_load(&rx->port))
        (void)poll(NULL, 0, 5);
    return atomic_load(&rx->port) != 0;
}

static size_t smoke_read_banner(int fd, const struct smoke_cl *cl, char *buffer, size_t cap, int64_t deadline)
{
    size_t got = 0;
    while (got < cap && clock_now_monotonic_ns() < deadline) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        (void)poll(&ready, 1, 10);
        ssize_t n = read(fd, buffer + got, cap - got);
        if (n > 0) got += (size_t)n;
        else if (n == 0 || (errno != EAGAIN && errno != EINTR)) break;
        if (got >= strlen(SMOKE_BANNER) || (atomic_load(&cl->done) && n <= 0)) break;
    }
    return got;
}

static void smoke_finish_client(struct smoke_cl *cl, int input_write)
{
    if (input_write >= 0) close(input_write); /* EOF lets the tunnel drain and close ordinarily */
    int64_t drain = smoke_deadline(SMOKE_DRAIN_MS);
    while (!atomic_load(&cl->done) && clock_now_monotonic_ns() < drain) (void)poll(NULL, 0, 5);
    atomic_store(&cl->cancel, true);
    pthread_join(cl->thread, NULL);
}

struct smoke_run {
    struct smoke_side hub, client;
    struct smoke_rx rx;
    struct smoke_cl cl;
    int input[2], output[2];
};

static void smoke_run_close(struct smoke_run *run)
{
    if (run->rx.started) { atomic_store(&run->rx.cancel, true); pthread_join(run->rx.thread, NULL); }
    if (!run->cl.started || !run->cl.obs.io_taken) {
        if (run->input[0] >= 0) close(run->input[0]);
        if (run->output[1] >= 0) close(run->output[1]);
    }
    if (run->output[0] >= 0) close(run->output[0]);
    smoke_side_close(&run->hub);
    smoke_side_close(&run->client);
}

static bool smoke_start_receiver(struct smoke_run *run, const struct pair_smoke_in *in)
{
    struct device_host_runtime_receiver_spec *spec = &run->rx.spec;
    smoke_common(&spec->common, &run->hub, in->client_key, in->hub_root, in->target_port, in->budget_ms, &run->rx.cancel);
    spec->listen_address_be = htonl(INADDR_LOOPBACK);
    spec->lifetime_ms = in->budget_ms + 5000;
    spec->max_sessions = 1;
    spec->max_active = 1;
    spec->ready = smoke_ready;
    spec->ready_context = &run->rx;
    /* raw-pthread-ok: bounded receiver joined by smoke_run_close before the smoke returns */
    run->rx.started = pthread_create(&run->rx.thread, NULL, smoke_rx_main, &run->rx) == 0;
    return run->rx.started;
}

static bool smoke_start_client(struct smoke_run *run, const struct pair_smoke_in *in)
{
    uint8_t root[32];
    memcpy(root, in->client_root, 32);
    if (in->corrupt) root[0] ^= 0x01u;
    struct device_host_runtime_client_spec *spec = &run->cl.spec;
    smoke_common(&spec->common, &run->client, in->hub_key, root, in->target_port, in->budget_ms, &run->cl.cancel);
    spec->route_address_be = htonl(INADDR_LOOPBACK);
    spec->route_port = (uint16_t)atomic_load(&run->rx.port);
    spec->connect_ms = 3000;
    spec->input_fd = run->input[0];
    spec->output_fd = run->output[1];
    /* raw-pthread-ok: bounded client joined by smoke_finish_client before the smoke returns */
    run->cl.started = pthread_create(&run->cl.thread, NULL, smoke_cl_main, &run->cl) == 0;
    return run->cl.started;
}

static void smoke_set(struct pair_smoke_out *out, bool passed, const char *reason)
{
    out->passed = passed;
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
}

static void smoke_exchange(struct smoke_run *run, const struct pair_smoke_in *in, struct pair_smoke_out *out)
{
    char banner[8] = {0};
    int64_t deadline = smoke_deadline(in->budget_ms);
    size_t got = smoke_read_banner(run->output[0], &run->cl, banner, strlen(SMOKE_BANNER), deadline);
    bool banner_ok = got >= strlen(SMOKE_BANNER) && !memcmp(banner, SMOKE_BANNER, strlen(SMOKE_BANNER));
    int input_write = run->input[1];
    run->input[1] = -1;
    smoke_finish_client(&run->cl, input_write);
    out->accepted = run->rx.obs.accepted;
    smoke_set(out, banner_ok, banner_ok ? "ok" : atomic_load(&run->cl.done) && run->cl.obs.result == DEVICE_HOST_BRIDGE_REFUSED ? "client_refused" : "no_banner");
}

void pair_smoke_run(const struct pair_smoke_in *in, struct pair_smoke_out *out)
{
    struct smoke_run run = {.input = {-1, -1}, .output = {-1, -1}};
    memset(out, 0, sizeof(*out));
    smoke_set(out, false, "setup_failed");
    if (!smoke_side_open(&run.hub, in->hub_profile, in->client_key) ||
        !smoke_side_open(&run.client, in->client_profile, in->hub_key) ||
        !smoke_pipe(run.input) || !smoke_pipe(run.output)) {
        LOG_ERROR(SMOKE_TAG, "smoke setup failed: grants or descriptors unavailable");
        smoke_run_close(&run);
        return;
    }
    /* The client reads input[0] and writes output[1]; this thread writes input[1] (EOF only) and reads output[0]. */
    if (!smoke_start_receiver(&run, in) || !smoke_wait_ready(&run.rx, smoke_deadline(in->budget_ms))) {
        smoke_set(out, false, "receiver_not_ready");
        smoke_run_close(&run);
        return;
    }
    out->listen_port = (uint16_t)atomic_load(&run.rx.port);
    if (!smoke_start_client(&run, in)) smoke_set(out, false, "client_not_started");
    else smoke_exchange(&run, in, out);
    if (run.input[1] >= 0) close(run.input[1]);
    smoke_run_close(&run);
}
