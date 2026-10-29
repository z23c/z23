/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: bounded isolated socket acceptance; no identity bootstrap/runtime. */
#include "test/test_core.h"
#include "services/device_connection.h"
#include "services/device_connection_io.h"
static_assert(_Generic(device_io_transfer(PLATFORM_SOCKET_INVALID, NULL, 0, false, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_io_record(PLATFORM_SOCKET_INVALID, NULL, NULL, false, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_io_record_granted(PLATFORM_SOCKET_INVALID, NULL, NULL, false, 0, 0, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
static_assert(_Generic(device_io_handshake(PLATFORM_SOCKET_INVALID, NULL, 0), struct zcl_result: 1, default: 0),
    "fallible device API returns canonical zcl_result");
#include "crypto/curve25519.h"
#include "net/v2_identity.h"
#include "platform/clock.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static void fixture_identity_close(struct device_identity *identity)
{
    memory_cleanse(identity, sizeof(*identity));
}

static bool fixture_identity(struct device_identity *identity, uint8_t seed)
{
    memset(identity, 0, sizeof(*identity));
    if (!test_mkdtemp(identity->directory, sizeof(identity->directory), "device-socket"))
        return false;
    identity->private_key[0] = seed;
    return curve25519_scalarmult_base(identity->public_key, identity->private_key);
}

/* Pure wait ceilings: nothing asserts elapsed time; generous so a loaded host
 * (hundreds of concurrent builds) cannot expire a handshake or child reap. */
static const int64_t DEVICE_TEST_REAP_US = INT64_C(60000000);
static const int64_t DEVICE_TEST_REVOKE_NS = INT64_C(30000000000);

static bool reap_bounded(pid_t child)
{
    int status = 0;
    int64_t deadline = platform_time_monotonic_us() + DEVICE_TEST_REAP_US;
    while (platform_time_monotonic_us() < deadline) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (result < 0 && errno != EINTR) return false;
        platform_sleep_ms(5);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return false;
}
static bool grant_peer(struct device_identity *local, struct device_identity *peer)
{
    struct device_pairing_store store;
    struct zcl_result opened = device_identity_pair_store(local, peer->public_key, &store);
    if (!opened.ok) return false;
    struct db_device_pairing row = {0};
    memcpy(row.profile, store.profile, 32);
    memcpy(row.local_key, local->public_key, 32);
    memcpy(row.peer_key, peer->public_key, 32);
    row.paired_at = (uint64_t)clock_now_wall_ms() / 1000;
    row.expires_at = row.paired_at + 600;
    uint8_t fingerprint[32];
    enum device_pairing_publication publication;
    return v2_identity_public_fingerprint(peer->public_key, fingerprint) &&
           db_device_pairing_insert(&store, &row, fingerprint, &publication) &&
           publication == DEVICE_PAIRING_DURABLE;
}

static bool socket_exchange(struct device_identity *client,
                             struct device_identity *server, bool expect)
{
    platform_socket_t sockets[2];
    if (!platform_socket_pair(sockets)) return false;
    pid_t child = fork();
    if (child < 0) {
        platform_socket_close(sockets[0]);
        platform_socket_close(sockets[1]);
        return false;
    }
    if (!child) {
        platform_socket_close(sockets[0]);
        struct zcl_result result = device_connection_respond(server, sockets[1],
            clock_now_monotonic_ns() + INT64_C(2000000000),
            server->directory, server->directory);
        fixture_identity_close(client);
        fixture_identity_close(server);
        platform_socket_close(sockets[1]);
        _exit(result.ok == expect ? 0 : 1);
    }
    platform_socket_close(sockets[1]);
    struct device_disk_status status;
    struct zcl_result result = device_connection_probe(client, server->public_key,
        sockets[0], clock_now_monotonic_ns() + INT64_C(2000000000), &status);
    platform_socket_close(sockets[0]);
    bool reaped = reap_bounded(child);
    return reaped && result.ok == expect &&
           (!expect || (status.sampled_at && status.home_total && status.root_total));
}

static int deadline_and_frame(void)
{
    int failures = 0;
    platform_socket_t sockets[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    TEST_CASE("device_connection: silent peer deadline and oversized outer frame refuse") {
        ASSERT(platform_socket_pair(sockets));
        ASSERT(platform_socket_set_nonblocking(sockets[0], true));
        ASSERT(platform_socket_set_nonblocking(sockets[1], true));
        uint8_t wire[NOISE_MAX_MESSAGE];
        size_t size = 0;
        int64_t start = clock_now_monotonic_ns();
        ASSERT(!device_io_record(sockets[0], wire, &size, false,
                                  start + INT64_C(20000000)).ok);
        ASSERT_EQ(platform_socket_peek(sockets[1], wire, 1), -1);
        ASSERT(platform_socket_error_would_block(platform_socket_last_error()));
        uint8_t excessive[2] = {0xff, 0xff};
        ASSERT_EQ(platform_socket_send(sockets[1], excessive, 2), 2);
        ASSERT(!device_io_record(sockets[0], wire, &size, false,
                                  clock_now_monotonic_ns() + INT64_C(100000000)).ok);
        errno = EIO; /* Invalid deadline must not inherit an unrelated errno. */
        struct zcl_result expired = device_io_transfer(sockets[0], wire, 1, false, INT64_MIN);
        ASSERT(!expired.ok); ASSERT_EQ(expired.code, -2);
        ASSERT(expired.source_file != NULL); ASSERT(expired.source_line > 0);
        ASSERT(strstr(expired.message, "deadline") != NULL);
    } TEST_END
    if (sockets[0] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[0]);
    if (sockets[1] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[1]);
    return failures;
}


struct late_clock { unsigned mono_calls, wall_calls; bool expire; };
static int64_t late_mono(void *context)
{
    struct late_clock *clock = context;
    ++clock->mono_calls;
    return !clock->expire && clock->mono_calls > 1 ? INT64_C(3000000000) :
                                                        INT64_C(1000000000);
}
static int64_t late_wall(void *context)
{
    struct late_clock *clock = context;
    return ++clock->wall_calls > 1 ? 2000 : 1999;
}

static int late_ready_and_expiry(void)
{
    int failures = 0;
    const clock_iface_t *previous = clock_default();
    platform_socket_t sockets[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    TEST_CASE("device_connection: late writable readiness and grant expiry release no bytes") {
        ASSERT(platform_socket_pair(sockets));
        ASSERT(platform_socket_set_nonblocking(sockets[0], true));
        ASSERT(platform_socket_set_nonblocking(sockets[1], true));
        for (unsigned expiry = 0; expiry < 2; ++expiry) {
            struct late_clock clock = {.expire = expiry != 0};
            clock_iface_t fake = {.now_monotonic_ns = late_mono,
                .now_wall_ms = late_wall, .self = &clock};
            clock_set_default(&fake);
            uint8_t wire[NOISE_MAX_MESSAGE] = {1, 2};
            size_t size = 2;
            bool ok = device_io_record_granted(sockets[0], wire, &size, true,
                INT64_C(2000000000), expiry ? 1 : 0, expiry ? 2 : 0).ok;
            clock_set_default(previous);
            ASSERT(!ok);
            ASSERT_EQ(platform_socket_peek(sockets[1], wire, 1), -1);
            ASSERT(platform_socket_error_would_block(platform_socket_last_error()));
        }
    } TEST_END
    clock_set_default(previous);
    if (sockets[0] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[0]);
    if (sockets[1] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[1]);
    return failures;
}

static bool finish_revoked_exchange(struct device_channel *channel,
                                      struct device_pairing_store *server_store,
                                      const uint8_t peer[32], platform_socket_t socket,
                                      int64_t deadline)
{
    uint8_t wire[NOISE_MAX_MESSAGE];
    size_t size = 0;
    enum device_pairing_publication publication;
    bool ok = db_device_pairing_revoke(server_store, peer,
        (uint64_t)clock_now_wall_ms() / 1000, &publication);
    ok = ok && device_channel_handshake_write(channel, wire, &size).ok &&
        device_io_record(socket, wire, &size, true, deadline).ok &&
        device_channel_request(channel, wire, &size).ok &&
        device_io_record(socket, wire, &size, true, deadline).ok &&
        !device_io_record(socket, wire, &size, false, deadline).ok;
    return ok;
}

static bool perform_revoked_exchange(struct device_identity *client,
                                      struct device_identity *server, platform_socket_t socket)
{
    struct device_pairing_store client_store, server_store;
    struct zcl_result a = device_identity_pair_store(client, server->public_key, &client_store);
    struct zcl_result b = device_identity_pair_store(server, client->public_key, &server_store);
    struct device_channel channel = {0};
    uint8_t hello[40] = {'Z','2','3','D','E','V',1,0}, wire[NOISE_MAX_MESSAGE];
    memcpy(hello + 8, client->public_key, 32);
    size_t size = 0;
    int64_t deadline = clock_now_monotonic_ns() + DEVICE_TEST_REVOKE_NS;
    bool ok = a.ok && b.ok && platform_socket_set_nonblocking(socket, true) &&
        device_channel_init(&channel, true, client_store.profile, client->private_key,
                             client->public_key, server->public_key).ok &&
        device_io_transfer(socket, hello, sizeof(hello), true, deadline).ok &&
        device_channel_handshake_write(&channel, wire, &size).ok &&
        device_io_record(socket, wire, &size, true, deadline).ok &&
        device_io_record(socket, wire, &size, false, deadline).ok &&
        device_channel_handshake_read(&channel, wire, size).ok;
    if (ok) ok = finish_revoked_exchange(&channel, &server_store,
        client->public_key, socket, deadline);
    device_channel_close(&channel);
    return ok;
}

static bool revoke_mid_handshake(struct device_identity *client,
                                  struct device_identity *server)
{
    platform_socket_t sockets[2];
    if (!platform_socket_pair(sockets)) return false;
    pid_t child = fork();
    if (child < 0) {
        platform_socket_close(sockets[0]);
        platform_socket_close(sockets[1]);
        return false;
    }
    if (!child) {
        platform_socket_close(sockets[0]);
        struct zcl_result result = device_connection_respond(server, sockets[1],
            clock_now_monotonic_ns() + DEVICE_TEST_REVOKE_NS,
            server->directory, server->directory);
        platform_socket_close(sockets[1]);
        _exit(result.ok ? 1 : 0);
    }
    platform_socket_close(sockets[1]);
    bool ok = perform_revoked_exchange(client, server, sockets[0]);
    platform_socket_close(sockets[0]);
    bool reaped = reap_bounded(child);
    return ok && reaped;
}

static int real_socket_pair(void)
{
    int failures = 0;
    struct device_identity client = {0}, server = {0};
    TEST_CASE("device_connection: explicit fixture identities and reciprocal grants exchange native bytes") {
        ASSERT(fixture_identity(&client, 7));
        ASSERT(fixture_identity(&server, 9));
        ASSERT(socket_exchange(&client, &server, false));
        ASSERT(grant_peer(&client, &server));
        ASSERT(socket_exchange(&client, &server, false));
        ASSERT(grant_peer(&server, &client));
        ASSERT(socket_exchange(&client, &server, true));
        ASSERT(revoke_mid_handshake(&client, &server));
        ASSERT(socket_exchange(&client, &server, false));
    } TEST_END
    if (client.directory[0]) test_rm_rf(client.directory);
    if (server.directory[0]) test_rm_rf(server.directory);
    fixture_identity_close(&client);
    fixture_identity_close(&server);
    return failures;
}

struct rewind_clock { unsigned wall_calls; };
static int64_t rewind_mono(void *context)
{
    (void)context;
    return INT64_C(1000000000);
}
static int64_t rewind_wall(void *context)
{
    struct rewind_clock *clock = context;
    return ++clock->wall_calls == 1 ? INT64_C(150000) : INT64_C(99000);
}

static int grant_not_before_release(void)
{
    int failures = 0;
    const clock_iface_t *previous = clock_default();
    platform_socket_t sockets[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    char directory[1024] = {0};
    struct device_pairing_guard guard = {0};
    struct rewind_clock clock = {0};
    clock_iface_t fake = {.now_monotonic_ns = rewind_mono,
        .now_wall_ms = rewind_wall, .self = &clock};
    TEST_CASE("device_connection: wall rewind below held grant not-before releases no prefix or payload") {
        ASSERT(test_mkdtemp(directory, sizeof(directory), "device-not-before"));
        struct device_pairing_store store;
        struct db_device_pairing row = {.profile = {1}, .local_key = {2},
            .peer_key = {3}, .paired_at = 100, .expires_at = 200};
        uint8_t fingerprint[32];
        enum device_pairing_publication publication;
        ASSERT(v2_identity_public_fingerprint(row.peer_key, fingerprint));
        ASSERT(device_pairing_store_open(&store, directory, row.profile, row.local_key));
        ASSERT(db_device_pairing_insert(&store, &row, fingerprint, &publication));
        ASSERT(device_pairing_guard_acquire(&store, row.peer_key, 150, &guard));
        ASSERT(platform_socket_pair(sockets));
        ASSERT(platform_socket_set_nonblocking(sockets[0], true));
        ASSERT(platform_socket_set_nonblocking(sockets[1], true));
        uint8_t wire[NOISE_MAX_MESSAGE] = {1, 2};
        size_t size = 2;
        clock_set_default(&fake);
        bool sent = device_io_record_granted(sockets[0], wire, &size, true,
            INT64_C(2000000000), guard.row.paired_at, guard.row.expires_at).ok;
        clock_set_default(previous);
        ASSERT(clock.wall_calls >= 2);
        ASSERT_EQ(platform_socket_peek(sockets[1], wire, 1), -1);
        ASSERT(platform_socket_error_would_block(platform_socket_last_error()));
        ASSERT(!sent);
    } TEST_END
    clock_set_default(previous);
    device_pairing_guard_release(&guard);
    if (sockets[0] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[0]);
    if (sockets[1] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[1]);
    if (directory[0]) test_rm_rf(directory);
    return failures;
}

static int64_t interval_wall(void *context)
{
    (void)context;
    return INT64_C(150000);
}

static int invalid_grant_intervals(void)
{
    int failures = 0;
    const clock_iface_t *previous = clock_default();
    platform_socket_t sockets[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    clock_iface_t fake = {.now_monotonic_ns = rewind_mono,
        .now_wall_ms = interval_wall};
    static const uint64_t intervals[][2] = {
        {0, 200}, {100, 0}, {200, 100}, {100, 100},
        {100, (uint64_t)INT64_MAX / 1000 + 1},
        {UINT64_MAX - 1, UINT64_MAX}
    };
    TEST_CASE("device_connection: zero-sided reversed and overflowing grants release no bytes") {
        ASSERT(platform_socket_pair(sockets));
        ASSERT(platform_socket_set_nonblocking(sockets[0], true));
        ASSERT(platform_socket_set_nonblocking(sockets[1], true));
        for (size_t i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i) {
            uint8_t wire[NOISE_MAX_MESSAGE] = {1, 2};
            size_t size = 2;
            clock_set_default(&fake);
            bool sent = device_io_record_granted(sockets[0], wire, &size, true,
                INT64_C(2000000000), intervals[i][0], intervals[i][1]).ok;
            clock_set_default(previous);
            ASSERT_EQ(platform_socket_peek(sockets[1], wire, 1), -1);
            ASSERT(platform_socket_error_would_block(platform_socket_last_error()));
            ASSERT(!sent);
        }
    } TEST_END
    clock_set_default(previous);
    if (sockets[0] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[0]);
    if (sockets[1] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[1]);
    return failures;
}

static bool grant_fixed_interval(struct device_identity *local, struct device_identity *peer)
{
    struct device_pairing_store store;
    if (!device_identity_pair_store(local, peer->public_key, &store).ok) return false;
    struct db_device_pairing row = {.paired_at = 100, .expires_at = 200};
    memcpy(row.profile, store.profile, 32);
    memcpy(row.local_key, local->public_key, 32);
    memcpy(row.peer_key, peer->public_key, 32);
    uint8_t fingerprint[32];
    enum device_pairing_publication publication;
    return v2_identity_public_fingerprint(peer->public_key, fingerprint) &&
        db_device_pairing_insert(&store, &row, fingerprint, &publication) &&
        publication == DEVICE_PAIRING_DURABLE;
}

struct decode_clock {
    const clock_iface_t *previous;
    const struct device_disk_status *watched;
    unsigned after_decode;
};
static int64_t decode_mono(void *context)
{
    struct decode_clock *clock = context;
    return clock->previous->now_monotonic_ns(clock->previous->self);
}
static int64_t decode_wall(void *context)
{
    struct decode_clock *clock = context;
    if (!clock->watched->sampled_at) return INT64_C(150000);
    return clock->after_decode++ == 0 ? INT64_C(99000) : INT64_C(150000);
}

static int post_decode_clock_refusal(void)
{
    int failures = 0;
    struct device_identity client = {0}, server = {0};
    struct device_disk_status status = {0};
    const clock_iface_t *previous = clock_default();
    struct decode_clock clock = {.previous = previous, .watched = &status};
    clock_iface_t fake = {.now_monotonic_ns = decode_mono,
        .now_wall_ms = decode_wall, .self = &clock};
    platform_socket_t sockets[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    pid_t child = -1;
    TEST_CASE("device_connection: one post-decode wall sample must authorize the complete interval") {
        ASSERT(fixture_identity(&client, 7));
        ASSERT(fixture_identity(&server, 9));
        ASSERT(grant_fixed_interval(&client, &server));
        ASSERT(grant_fixed_interval(&server, &client));
        ASSERT(platform_socket_pair(sockets));
        clock_set_default(&fake);
        child = fork();
        ASSERT(child >= 0);
        if (!child) {
            platform_socket_close(sockets[0]);
            struct zcl_result response = device_connection_respond(&server, sockets[1],
                clock_now_monotonic_ns() + INT64_C(2000000000), server.directory, server.directory);
            platform_socket_close(sockets[1]);
            fixture_identity_close(&client);
            fixture_identity_close(&server);
            _exit(response.ok ? 0 : 1);
        }
        platform_socket_close(sockets[1]);
        sockets[1] = PLATFORM_SOCKET_INVALID;
        struct zcl_result result = device_connection_probe(&client, server.public_key,
            sockets[0], clock_now_monotonic_ns() + INT64_C(2000000000), &status);
        platform_socket_close(sockets[0]);
        sockets[0] = PLATFORM_SOCKET_INVALID;
        bool reaped = reap_bounded(child);
        child = -1;
        clock_set_default(previous);
        ASSERT(reaped);
        ASSERT(clock.after_decode > 0);
        ASSERT(!result.ok);
        struct device_disk_status zero = {0};
        ASSERT_EQ(status.sampled_at, zero.sampled_at);
        ASSERT_EQ(status.root_total, zero.root_total);
        ASSERT_EQ(status.root_available, zero.root_available);
        ASSERT_EQ(status.home_total, zero.home_total);
        ASSERT_EQ(status.home_available, zero.home_available);
    } TEST_END
    clock_set_default(previous);
    if (sockets[0] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[0]);
    if (sockets[1] != PLATFORM_SOCKET_INVALID) platform_socket_close(sockets[1]);
    if (child > 0) (void)reap_bounded(child);
    if (client.directory[0]) test_rm_rf(client.directory);
    if (server.directory[0]) test_rm_rf(server.directory);
    fixture_identity_close(&client);
    fixture_identity_close(&server);
    return failures;
}
#endif

int test_device_connection(void);
int test_device_connection(void)
{
#if defined(_WIN32)
    fprintf(stderr, "device_connection: Windows socket/process acceptance unqualified; refused\n");
    return 1;
#else
    return real_socket_pair() + deadline_and_frame() +
        late_ready_and_expiry() + grant_not_before_release() + invalid_grant_intervals() +
        post_decode_clock_refusal();
#endif
}
