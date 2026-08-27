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
 *     ZCL_TESTING seam): the independently computed runtime gate alone
 *     decides whether the pet thread may send
 *   - the real dedicated pet thread continues emitting WATCHDOG=1 while
 *     the shared health-ring sweeper is deliberately absent, reproducing
 *     the collector-starvation boundary that caused the live restart loop
 *
 * Each scenario calls sd_notify_reset_for_testing() first so the
 * module's process-global latch (NOTIFY_SOCKET is read once, matching
 * real systemd semantics) doesn't leak state between scenarios. */

#include "test/test_core.h"
#include "platform/socket_compat.h"
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
#include <string.h>
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

    int fd = platform_socket_open(AF_UNIX, SOCK_DGRAM, 0, true, true);
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

    int fd = platform_socket_open(AF_UNIX, SOCK_DGRAM, 0, true, true);
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
                                  int64_t *second_watchdog_us,
                                  int64_t *third_watchdog_us)
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
            else if (watchdog_count == 2)
                *third_watchdog_us = received_us;
            watchdog_count++;
        } else if (strcmp(buf, "READY=1\n") == 0) {
            (*ready_count)++;
        } else if (strncmp(buf, "STATUS=", 7) == 0) {
            (*status_count)++;
        }

        if (watchdog_count >= 3 && *ready_count >= 1 && *status_count >= 1)
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
     * Collection freshness is intentionally absent. The runtime gate already
     * combines the sweep, tick runner, connman, and bounded progress escape. */
    {
        SDN_CHECK("pet: frozen runtime gate always stops the ping",
            !boot_sd_watchdog_test_pet_decide(false));
        SDN_CHECK("pet: live runtime gate pings without collector evidence",
            boot_sd_watchdog_test_pet_decide(true));
        SDN_CHECK("keepalive: frozen sweep still stops even with progress",
            !boot_sd_watchdog_test_keepalive_supervisor(false, false, true));
        SDN_CHECK("keepalive: stale connman + IBD progress + live sweep",
            boot_sd_watchdog_test_keepalive_supervisor(false, true, true));
        SDN_CHECK("keepalive: stale connman without progress does not keep",
            !boot_sd_watchdog_test_keepalive_supervisor(false, true, false));
        SDN_CHECK("keepalive: runtime-alive keeps without progress",
            boot_sd_watchdog_test_keepalive_supervisor(true, true, false));
        SDN_CHECK("runtime pillars: all three live",
            boot_sd_watchdog_test_runtime_pillars(true, true, true));
        SDN_CHECK("runtime pillars: wedged tick runner stops the ping",
            !boot_sd_watchdog_test_runtime_pillars(true, false, true));
        SDN_CHECK("runtime pillars: frozen sweep stops the ping",
            !boot_sd_watchdog_test_runtime_pillars(false, true, true));
        SDN_CHECK("runtime pillars: stale connman stops the ping",
            !boot_sd_watchdog_test_runtime_pillars(true, true, false));
    }

    /* ── the backstop must be WEAKER than the policy it backs ──
     *
     * The pet decides with the disjunction above and then calls
     * sd_notify_watchdog_ping(), which consults whatever predicate
     * sd_notify_set_health_check() registered and sends nothing when it says
     * no. So the registered predicate is ANDed onto the pet's decision, and
     * registering a STRONGER one silently replaces the policy: with
     * boot_sd_watchdog_runtime_alive registered, the effective gate was
     * `A || B` outside and `A` inside, which is `A`. The
     * (recent_progress && sweep_alive) carve-out — the one that exists so a
     * snapshot import, a catchup or a UTXO replay is not killed mid-write —
     * could never fire, and a node writing at full rate was SIGABRTed anyway.
     *
     * This drives the real send path with the real registration contract: for
     * every triple the pet keeps alive, a WATCHDOG=1 datagram must actually
     * leave the process. The row that fails when the strong predicate is
     * registered is (runtime=0, sweep=1, progress=1). */
    {
        char path[128];
        int fd = sdn_bind_path_socket(path, sizeof(path));
        SDN_CHECK("backstop-test socket bound", fd >= 0);
        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", path, 1);
            sd_notify_reset_for_testing();
            SDN_CHECK("init succeeds for backstop test", sd_notify_init());

            static const struct {
                bool runtime, sweep, progress;
                const char *why;
            } rows[] = {
                { true,  true,  false, "runtime alive, no progress" },
                { false, true,  true,  "stale connman, bulk write in flight" },
                { true,  true,  true,  "everything live" },
            };
            for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
                bool keep = boot_sd_watchdog_test_keepalive_supervisor(
                    rows[i].runtime, rows[i].sweep, rows[i].progress);
                if (!keep)
                    continue;
                /* Register the SWEEP leg, which is what production registers
                 * and what this file's guarantee is about. */
                g_fake_health_healthy = rows[i].sweep;
                sd_notify_set_health_check(fake_health_check);
                bool sent = boot_sd_watchdog_test_pet_decide(keep) &&
                            sd_notify_watchdog_ping();
                char buf[64];
                ssize_t n = sent ? sdn_try_recv(fd, buf, sizeof(buf)) : -1;
                SDN_CHECK(rows[i].why,
                    sent && n > 0 && strcmp(buf, "WATCHDOG=1\n") == 0);
            }

            /* And the backstop still bites when the thing it backs is gone:
             * a stale sweep silences the ping no matter what the pet said. */
            g_fake_health_healthy = false;
            sd_notify_set_health_check(fake_health_check);
            SDN_CHECK("a stale sweep still silences the ping",
                !sd_notify_watchdog_ping() && sdn_confirm_silence(fd));

            sd_notify_set_health_check(NULL);
            close(fd);
            unlink(path);
            unsetenv("NOTIFY_SOCKET");
            sd_notify_reset_for_testing();
        }
    }

    /* ── earned readiness: every leg confirmed on its own evidence ──
     *
     * The defect under regression: READY=1 rested on onion descriptor
     * publication alone (and on nothing at all when onion was never
     * requested), so a node whose message pump was dead, whose dial
     * scheduler was dead, or whose supervisor sweep was frozen still
     * told systemd it was ready. Readiness is now a conjunction of four
     * independently-confirmed legs, and a single unconfirmed leg must
     * withhold it. */
    {
        struct boot_ready_legs legs = {
            .descriptor = true, .listener = true,
            .pump = true, .sweep = true,
        };
        SDN_CHECK("ready: all four legs confirmed is ready",
            boot_ready_legs_all_confirmed(&legs));

        /* One leg at a time. Each must be sufficient to withhold READY,
         * which is what "independently confirmed" means — no leg may be
         * carried by its neighbours. */
        for (int missing = 0; missing < 4; missing++) {
            struct boot_ready_legs one = {
                .descriptor = true, .listener = true,
                .pump = true, .sweep = true,
            };
            switch (missing) {
            case 0: one.descriptor = false; break;
            case 1: one.listener   = false; break;
            case 2: one.pump       = false; break;
            case 3: one.sweep      = false; break;
            default: break;
            }
            SDN_CHECK("ready: one unconfirmed leg withholds READY",
                !boot_ready_legs_all_confirmed(&one));
        }

        /* The exact shape a descriptor-only claim would have produced:
         * onion published, socket bound, pump dead. Must NOT read ready. */
        struct boot_ready_legs dead_pump = {
            .descriptor = true, .listener = true,
            .pump = false, .sweep = true,
        };
        SDN_CHECK("ready: published descriptor does not carry a dead pump",
            !boot_ready_legs_all_confirmed(&dead_pump));

        SDN_CHECK("ready: NULL legs are not confirmed",
            !boot_ready_legs_all_confirmed(NULL));

        char desc[192];
        boot_ready_legs_describe(&dead_pump, desc, sizeof(desc));
        SDN_CHECK("ready: the hold names the unconfirmed leg",
            strstr(desc, "pump=no") != NULL);
        SDN_CHECK("ready: the hold names the confirmed legs too",
            strstr(desc, "descriptor=yes") != NULL &&
            strstr(desc, "listener=yes") != NULL &&
            strstr(desc, "sweep=yes") != NULL);
        /* Rendezvous has no observable in this tree. It must be reported
         * as unconfirmed and never inferred from the descriptor. */
        SDN_CHECK("ready: rendezvous is reported unconfirmed, not inferred",
            strstr(desc, "rendezvous=unconfirmed") != NULL);

        boot_ready_legs_describe(NULL, desc, sizeof(desc));
        SDN_CHECK("ready: NULL legs describe as unavailable",
            strstr(desc, "unavailable") != NULL);
    }

    /* ── real dedicated pet thread, health ring deliberately idle ── */
    {
        char path[108];
        int fd = sdn_bind_path_socket(path, sizeof(path));
        SDN_CHECK("pet-thread socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", path, 1);
            /* The production thread clamps its cadence to five seconds. The
             * third ping lands after the former eight-second collector grace,
             * proving an idle health ring cannot suppress a live runtime. */
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
            int64_t third_watchdog_us = 0;
            int64_t pet_started_us = platform_time_monotonic_us();
            if (started) {
                int64_t deadline_us = platform_time_monotonic_us()
                                    + 13000LL * 1000;
                watchdog_count = sdn_observe_pet_thread(
                    fd, deadline_us, &ready_count, &status_count,
                    &first_watchdog_us, &second_watchdog_us,
                    &third_watchdog_us);
            }
            SDN_CHECK("watchdog start emits READY while health ring is idle",
                      ready_count >= 1);
            SDN_CHECK("watchdog start emits STATUS while health ring is idle",
                      status_count >= 1);
            SDN_CHECK("pet thread emits three independent watchdog pings",
                      watchdog_count >= 3);
            SDN_CHECK("second watchdog ping follows the five-second cadence",
                      first_watchdog_us > 0 && second_watchdog_us > 0 &&
                      second_watchdog_us - first_watchdog_us >= 4500LL * 1000);
            SDN_CHECK("pet thread continues beyond former collector grace",
                      third_watchdog_us >= pet_started_us + 8000LL * 1000);

            boot_sd_watchdog_stop(&svc);
            close(fd);
            unlink(path);
            unsetenv("NOTIFY_SOCKET");
            unsetenv("WATCHDOG_USEC");
            sd_notify_reset_for_testing();
        }
    }

    /* ── The READY hold buys time only when a leg newly confirms ──
     * Holding READY extends TimeoutStartSec. Extending on every pet
     * period made the deadline unreachable, so a leg that could never
     * confirm — a failed bind, a pump that never started — hung the boot
     * forever instead of letting Restart=always retry it.
     *
     * The hold uses this count as a MONOTONIC high-water mark, so the
     * property that matters is that it rises only with real
     * confirmations. A leg that flaps yes/no/yes returns to a count it
     * has already reached and therefore buys nothing. */
    {
        struct boot_ready_legs l = {0};
        SDN_CHECK("legs: none confirmed counts 0",
                  boot_ready_legs_confirmed_count(&l) == 0);
        SDN_CHECK("legs: NULL counts 0",
                  boot_ready_legs_confirmed_count(NULL) == 0);

        l.descriptor = true;
        SDN_CHECK("legs: one confirmed counts 1",
                  boot_ready_legs_confirmed_count(&l) == 1);
        l.listener = true;
        l.pump = true;
        SDN_CHECK("legs: three confirmed counts 3",
                  boot_ready_legs_confirmed_count(&l) == 3);
        SDN_CHECK("legs: three confirmed is NOT all confirmed",
                  !boot_ready_legs_all_confirmed(&l));

        l.sweep = true;
        SDN_CHECK("legs: four confirmed counts 4 and is all confirmed",
                  boot_ready_legs_confirmed_count(&l) == 4 &&
                  boot_ready_legs_all_confirmed(&l));

        /* Flap: a leg dropping and returning revisits a count already
         * seen, so a high-water mark cannot be pushed up by oscillation. */
        unsigned high = boot_ready_legs_confirmed_count(&l);
        l.pump = false;
        unsigned dipped = boot_ready_legs_confirmed_count(&l);
        l.pump = true;
        unsigned back = boot_ready_legs_confirmed_count(&l);
        SDN_CHECK("legs: a flapping leg never exceeds its previous high",
                  dipped < high && back == high);
    }

    return failures;
}
