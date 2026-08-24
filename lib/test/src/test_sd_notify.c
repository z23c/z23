/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the direct-socket systemd notify client
 * (lib/util/src/sd_notify.c). No libsystemd — this exercises the real
 * AF_UNIX datagram wire protocol against a socket this test binds
 * itself, standing in for systemd's NOTIFY_SOCKET.
 *
 * Coverage:
 *   - silent no-op when NOTIFY_SOCKET is unset (init returns false, no
 *     send attempted, no datagram observed)
 *   - path-mode NOTIFY_SOCKET: READY=1 then WATCHDOG=1 datagrams arrive
 *     byte-for-byte on the bound socket; WATCHDOG_USEC round-trips;
 *     EXTEND_TIMEOUT_USEC is sent for long Type=notify boots
 *   - abstract-namespace NOTIFY_SOCKET (leading '@'): same protocol,
 *     translated to the Linux abstract-socket wire form (leading NUL)
 *   - the sd_notify_watchdog_ping() health-check gate: a fake
 *     root-health callback reporting unhealthy suppresses the
 *     WATCHDOG=1 send entirely (no datagram observed); reporting
 *     healthy again resumes it
 *
 *   - the boot_sd_watchdog_pet_decide() decision table (via the
 *     ZCL_TESTING seam): supervisor-frozen always suppresses; fresh
 *     healthy verdict, body-gap posture, startup grace, and recent boot
 *     progress each permit; stale/unhealthy without progress suppresses
 *   - the real dedicated pet thread continues emitting WATCHDOG=1 while
 *     the shared health-ring sweeper is deliberately absent, reproducing
 *     the collector-starvation boundary that caused the live restart loop
 *
 * Each scenario calls sd_notify_reset_for_testing() first so the
 * module's process-global latch (NOTIFY_SOCKET is read once, matching
 * real systemd semantics) doesn't leak state between scenarios. */

#include "test/test_core.h"
#include "support/pagelocker.h"
#include "platform/time_compat.h"
#include "util/sd_notify.h"
#include "config/boot_internal.h"   /* boot_sd_watchdog_test_pet_decide */
#include "net/tor_integration.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SDN_CHECK(name, expr) do { \
    printf("sd_notify: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Bind a fresh non-blocking AF_UNIX datagram socket at a unique
 * path-mode address under /tmp. Returns the bound fd (>=0) and writes
 * the path into `path_out` (size >= sizeof(struct sockaddr_un.sun_path)).
 * Caller unlinks + closes. */
static int sdn_bind_path_socket(char *path_out, size_t path_out_len)
{
    snprintf(path_out, path_out_len,
             "/tmp/zcl_test_sd_notify_%d_%ld.sock",
             (int)getpid(), (long)time(NULL)); // platform-ok: test-fixture unique path, not production timing
    unlink(path_out);

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, path_out, sizeof(sa.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Bind a fresh non-blocking AF_UNIX datagram socket in the Linux
 * abstract namespace (no filesystem entry). Writes the '@'-prefixed
 * NOTIFY_SOCKET-style name (what a caller would export) into
 * `name_out`. Caller only needs to close (no unlink — abstract sockets
 * have no filesystem path to remove). */
static int sdn_bind_abstract_socket(char *name_out, size_t name_out_len)
{
    snprintf(name_out, name_out_len, "@zcl_test_sd_notify_abs_%d",
             (int)getpid());

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    /* Abstract form: leading NUL, then the name bytes (no NUL
     * terminator required on the wire). */
    size_t name_len = strlen(name_out + 1); /* skip the '@' */
    sa.sun_path[0] = '\0';
    memcpy(sa.sun_path + 1, name_out + 1, name_len);
    socklen_t sa_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                    + 1 + name_len);
    if (bind(fd, (struct sockaddr *)&sa, sa_len) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Poll fd for one datagram with a short bound (the sender is
 * synchronous local IPC, so this never has to wait for real network
 * latency — a few retries against EAGAIN is enough to absorb scheduler
 * jitter without a real sleep-based race). Returns the byte count read
 * (>=0) or -1 if nothing arrived. */
static ssize_t sdn_try_recv(int fd, char *buf, size_t buf_len)
{
    for (int attempt = 0; attempt < 200; attempt++) {
        ssize_t n = recv(fd, buf, buf_len - 1, 0);
        if (n >= 0) {
            buf[n] = '\0';
            return n;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* True iff nothing arrives within the same short polling bound above —
 * used to prove a suppressed send produced NO datagram, not just a
 * different one. */
static bool sdn_confirm_silence(int fd)
{
    char buf[64];
    return sdn_try_recv(fd, buf, sizeof(buf)) < 0;
}

/* ── fake root-health callback used by the gate test ────────────── */
static bool g_fake_health_healthy = true;
static bool fake_health_check(void) { return g_fake_health_healthy; }

/* Observe the actual boot watchdog thread, not just its pure decision seam.
 * The health sweeper is intentionally not started: before 60b989ffa that
 * meant no second WATCHDOG=1 could arrive because collection and petting
 * shared the same ring. Returns the number of watchdog datagrams observed. */
static int sdn_observe_pet_thread(int fd, int64_t deadline_us,
                                  int *ready_count, int *status_count,
                                  int64_t *first_watchdog_us,
                                  int64_t *second_watchdog_us)
{
    int watchdog_count = 0;
    while (platform_time_monotonic_us() < deadline_us) {
        int64_t remaining_us = deadline_us - platform_time_monotonic_us();
        int timeout_ms = (int)((remaining_us + 999) / 1000);
        if (timeout_ms < 1)
            timeout_ms = 1;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc <= 0)
            continue;

        char buf[128];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n < 0)
            continue;
        buf[n] = '\0';
        if (strcmp(buf, "WATCHDOG=1\n") == 0) {
            int64_t received_us = platform_time_monotonic_us();
            if (watchdog_count == 0)
                *first_watchdog_us = received_us;
            else if (watchdog_count == 1)
                *second_watchdog_us = received_us;
            watchdog_count++;
        } else if (strcmp(buf, "READY=1\n") == 0) {
            (*ready_count)++;
        } else if (strncmp(buf, "STATUS=", 7) == 0) {
            (*status_count)++;
        }

        if (watchdog_count >= 2 && *ready_count >= 1 && *status_count >= 1)
            break;
    }
    return watchdog_count;
}

int test_sd_notify(void)
{
    int failures = 0;

    /* ── onion requested but not running must block READY=1 ─────── */
    {
        tor_integration_stop();
        SDN_CHECK("READY not blocked when onion was never requested",
            !boot_sd_watchdog_onion_blocks_ready());
        tor_integration_mark_requested();
        SDN_CHECK("READY blocked when -tor was requested but Tor is down",
            boot_sd_watchdog_onion_blocks_ready());
        tor_integration_stop();
        SDN_CHECK("READY unblocked after stop clears the request latch",
            !boot_sd_watchdog_onion_blocks_ready());
    }

    /* ── silent no-op without NOTIFY_SOCKET ──────────────────────── */
    {
        sd_notify_reset_for_testing();
        unsetenv("NOTIFY_SOCKET");
        unsetenv("WATCHDOG_USEC");

        SDN_CHECK("init returns false with no NOTIFY_SOCKET",
            !sd_notify_init());
        SDN_CHECK("is_active false with no NOTIFY_SOCKET",
            !sd_notify_is_active());
        SDN_CHECK("ready() is a silent no-op (returns false)",
            !sd_notify_ready());
        SDN_CHECK("watchdog_ping() is a silent no-op (returns false)",
            !sd_notify_watchdog_ping());
        SDN_CHECK("status() is a silent no-op (returns false)",
            !sd_notify_status("hello"));
        SDN_CHECK("extend_timeout() is a silent no-op (returns false)",
            !sd_notify_extend_timeout_usec(3600000000ULL));
        SDN_CHECK("watchdog_usec is 0 with nothing configured",
            sd_notify_watchdog_usec() == 0);

        sd_notify_reset_for_testing();
    }

    /* ── path-mode NOTIFY_SOCKET: READY=1 + WATCHDOG=1 arrive ────── */
    {
        char path[108];
        int fd = sdn_bind_path_socket(path, sizeof(path));
        SDN_CHECK("path-mode socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", path, 1);
            setenv("WATCHDOG_USEC", "60000000", 1); /* 60s */
            sd_notify_reset_for_testing();

            SDN_CHECK("init returns true with NOTIFY_SOCKET set",
                sd_notify_init());
            SDN_CHECK("is_active true after init",
                sd_notify_is_active());
            SDN_CHECK("watchdog_usec round-trips WATCHDOG_USEC",
                sd_notify_watchdog_usec() == 60000000ULL);

            SDN_CHECK("ready() reports success", sd_notify_ready());
            char buf[64];
            ssize_t n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("READY=1 datagram observed on the bound socket",
                n > 0 && strcmp(buf, "READY=1\n") == 0);

            SDN_CHECK("watchdog_ping() reports success (no gate set)",
                sd_notify_watchdog_ping());
            n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("WATCHDOG=1 datagram observed on the bound socket",
                n > 0 && strcmp(buf, "WATCHDOG=1\n") == 0);

            SDN_CHECK("status() delivers a STATUS= line",
                sd_notify_status("h=100 peers=8"));
            n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("STATUS= datagram observed",
                n > 0 && strcmp(buf, "STATUS=h=100 peers=8\n") == 0);

            SDN_CHECK("zero extend_timeout is a no-op",
                !sd_notify_extend_timeout_usec(0));
            SDN_CHECK("extend_timeout() reports success",
                sd_notify_extend_timeout_usec(3600000000ULL));
            n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("EXTEND_TIMEOUT_USEC datagram observed",
                n > 0 && strcmp(buf, "EXTEND_TIMEOUT_USEC=3600000000\n") == 0);

            SDN_CHECK("stopping() delivers STOPPING=1",
                sd_notify_stopping("bye"));
            n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("STOPPING=1 datagram observed",
                n > 0 && strncmp(buf, "STOPPING=1", 10) == 0);

            close(fd);
            unlink(path);
            unsetenv("NOTIFY_SOCKET");
            unsetenv("WATCHDOG_USEC");
            sd_notify_reset_for_testing();
        }
    }

    /* ── abstract-namespace NOTIFY_SOCKET (leading '@') ──────────── */
    {
        char name[64];
        int fd = sdn_bind_abstract_socket(name, sizeof(name));
        SDN_CHECK("abstract-namespace socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", name, 1);
            sd_notify_reset_for_testing();

            SDN_CHECK("init succeeds with abstract-namespace NOTIFY_SOCKET",
                sd_notify_init());
            SDN_CHECK("watchdog_ping() reaches the abstract socket",
                sd_notify_watchdog_ping());
            char buf[64];
            ssize_t n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("WATCHDOG=1 observed via abstract-namespace socket",
                n > 0 && strcmp(buf, "WATCHDOG=1\n") == 0);

            close(fd);
            unsetenv("NOTIFY_SOCKET");
            sd_notify_reset_for_testing();
        }
    }

    /* ── health-check gate suppresses WATCHDOG=1 when unhealthy ──── */
    {
        char path[108];
        int fd = sdn_bind_path_socket(path, sizeof(path));
        SDN_CHECK("gate-test socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", path, 1);
            sd_notify_reset_for_testing();
            SDN_CHECK("init succeeds for gate test", sd_notify_init());

            g_fake_health_healthy = false;
            sd_notify_set_health_check(fake_health_check);
            bool ping_rc = sd_notify_watchdog_ping();
            SDN_CHECK("ping() reports failure when the fake gate is unhealthy",
                !ping_rc);
            SDN_CHECK("no WATCHDOG=1 datagram arrives while unhealthy",
                sdn_confirm_silence(fd));

            g_fake_health_healthy = true;
            SDN_CHECK("ping() resumes once the fake gate reports healthy",
                sd_notify_watchdog_ping());
            char buf[64];
            ssize_t n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("WATCHDOG=1 observed once the gate clears",
                n > 0 && strcmp(buf, "WATCHDOG=1\n") == 0);

            /* Clearing the gate (NULL) restores the pre-existing
             * always-allow behavior. */
            sd_notify_set_health_check(NULL);
            SDN_CHECK("ping() still succeeds after clearing the gate",
                sd_notify_watchdog_ping());
            n = sdn_try_recv(fd, buf, sizeof(buf));
            SDN_CHECK("WATCHDOG=1 observed with the gate cleared",
                n > 0 && strcmp(buf, "WATCHDOG=1\n") == 0);

            close(fd);
            unlink(path);
            unsetenv("NOTIFY_SOCKET");
            sd_notify_reset_for_testing();
        }
    }

    /* ── pet decision table (boot_sd_watchdog_pet_decide via seam) ──
     * The dedicated pet thread's pure gate: supervisor liveness, verdict
     * verdict freshness (not verdict content), startup grace, and the
     * boot_progress escape hatch. */
    {
        const int64_t BOUND = 600LL * 1000000;
        SDN_CHECK("pet: frozen supervisor always stops the ping",
            !boot_sd_watchdog_test_pet_decide(false, true,
                                              0, true, BOUND, BOUND));
        SDN_CHECK("pet: fresh verdict pings regardless of health content",
            boot_sd_watchdog_test_pet_decide(true, true,
                                             1000, false, 0, BOUND));
        SDN_CHECK("pet: stale verdict without progress does not ping",
            !boot_sd_watchdog_test_pet_decide(true, true,
                                              BOUND + 1, false, 0, BOUND));
        SDN_CHECK("pet: negative-age verdict is rejected",
            !boot_sd_watchdog_test_pet_decide(true, true,
                                              -1, false, 0, BOUND));
        SDN_CHECK("pet: stale verdict + recent boot progress pings",
            boot_sd_watchdog_test_pet_decide(true, true,
                                             BOUND + 1, true, 0, BOUND));
        SDN_CHECK("pet: no verdict inside startup grace pings",
            boot_sd_watchdog_test_pet_decide(true, false,
                                             0, false, BOUND, BOUND));
        SDN_CHECK("pet: no verdict past grace without progress does not ping",
            !boot_sd_watchdog_test_pet_decide(true, false,
                                              0, false, 0, BOUND));
        SDN_CHECK("pet: no verdict past grace + progress pings",
            boot_sd_watchdog_test_pet_decide(true, false,
                                             0, true, 0, BOUND));
        SDN_CHECK("keepalive: frozen sweep still stops even with progress",
            !boot_sd_watchdog_test_keepalive_supervisor(false, false, true));
        SDN_CHECK("keepalive: stale connman + IBD progress + live sweep",
            boot_sd_watchdog_test_keepalive_supervisor(false, true, true));
        SDN_CHECK("keepalive: stale connman without progress does not keep",
            !boot_sd_watchdog_test_keepalive_supervisor(false, true, false));
        SDN_CHECK("keepalive: runtime-alive keeps without progress",
            boot_sd_watchdog_test_keepalive_supervisor(true, true, false));
    }

    /* ── real dedicated pet thread, health ring deliberately idle ── */
    {
        char path[108];
        int fd = sdn_bind_path_socket(path, sizeof(path));
        SDN_CHECK("pet-thread socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", path, 1);
            /* The production thread clamps its cadence to five seconds.
             * Eight seconds keeps startup grace valid through the second
             * expected ping while still making the test tightly bounded. */
            setenv("WATCHDOG_USEC", "8000000", 1);
            sd_notify_reset_for_testing();

            struct boot_svc_ctx svc = {0};
            bool started = boot_sd_watchdog_start(&svc);
            SDN_CHECK("dedicated pet thread starts", started);

            int ready_count = 0;
            int status_count = 0;
            int watchdog_count = 0;
            int64_t first_watchdog_us = 0;
            int64_t second_watchdog_us = 0;
            if (started) {
                int64_t deadline_us = platform_time_monotonic_us()
                                    + 12000LL * 1000;
                watchdog_count = sdn_observe_pet_thread(
                    fd, deadline_us, &ready_count, &status_count,
                    &first_watchdog_us, &second_watchdog_us);
            }
            SDN_CHECK("watchdog start emits READY while health ring is idle",
                      ready_count >= 1);
            SDN_CHECK("watchdog start emits STATUS while health ring is idle",
                      status_count >= 1);
            SDN_CHECK("pet thread emits two independent watchdog pings",
                      watchdog_count >= 2);
            SDN_CHECK("second watchdog ping follows the five-second cadence",
                      first_watchdog_us > 0 && second_watchdog_us > 0 &&
                      second_watchdog_us - first_watchdog_us >= 4500LL * 1000);

            boot_sd_watchdog_stop(&svc);
            close(fd);
            unlink(path);
            unsetenv("NOTIFY_SOCKET");
            unsetenv("WATCHDOG_USEC");
            sd_notify_reset_for_testing();
        }
    }

    return failures;
}
