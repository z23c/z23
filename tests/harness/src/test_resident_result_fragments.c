/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Deterministic regression compiling the actual shared codec under a narrow
 * recv observation wrapper. No sleeps, child processes or production hook.
 * Define RLF_SOURCE as the absolute production .c path; RLF_STANDALONE adds main.
 */
/* Self-identify the production source when the build does not pass -DRLF_SOURCE. Quote-include
 * resolves relative to this file (tests/harness/src -> repo root is ../../..). */
#ifndef RLF_SOURCE
#define RLF_SOURCE "../../../platform/modules/platform/src/resident_launch.c"
#endif
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>

static int rlf_target = -1, rlf_writer = -1;
static const unsigned char *rlf_wire;
static size_t rlf_offset, rlf_sizes[3], rlf_piece;
static unsigned rlf_eagain;
static bool rlf_send_failed;
static bool rlf_virtual_time;
static uint64_t rlf_now_ns, rlf_advance_ns;
static unsigned rlf_recv_count, rlf_advance_recv;
static bool rlf_interrupt_poll;

static int rlf_clock_gettime(clockid_t clock, struct timespec *value)
{
    if (!rlf_virtual_time) return clock_gettime(clock, value);
    value->tv_sec = (time_t)(rlf_now_ns / UINT64_C(1000000000));
    value->tv_nsec = (long)(rlf_now_ns % UINT64_C(1000000000));
    return 0;
}

static int rlf_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (!rlf_virtual_time) return poll(fds, count, timeout);
    if (rlf_interrupt_poll) {
        rlf_interrupt_poll = false;
        rlf_now_ns += UINT64_C(100000000);
        errno = EINTR;
        return -1;
    }
    int ready = poll(fds, count, 0);
    if (ready == 0 && timeout > 0) rlf_now_ns += (uint64_t)timeout * UINT64_C(1000000);
    return ready;
}

static ssize_t rlf_recv(int fd, void *data, size_t size, int flags)
{
    if (rlf_virtual_time && ++rlf_recv_count == rlf_advance_recv)
        rlf_now_ns += rlf_advance_ns;
    ssize_t got = recv(fd, data, size, flags);
    int saved = errno;
    if (fd == rlf_target && got < 0 && (saved == EAGAIN || saved == EWOULDBLOCK)) {
        ++rlf_eagain;
        if (rlf_piece < 3 && rlf_sizes[rlf_piece]) {
            size_t count = rlf_sizes[rlf_piece++];
            ssize_t sent = send(rlf_writer, rlf_wire + rlf_offset, count, MSG_NOSIGNAL);
            if (sent != (ssize_t)count) rlf_send_failed = true;
            else rlf_offset += count;
        }
    }
    errno = saved; /* Return the actual empty-socket EAGAIN, never fabricated data. */
    return got;
}

/* A second test-only instantiation of actual source, with private symbol names.
 * Normal production TU and its API remain entirely unchanged. */
#define resident_launch_revalidate rlf_launch_revalidate
#define resident_startup_begin rlf_startup_begin
#define resident_startup_check rlf_startup_check
#define resident_startup_read rlf_startup_read
#define resident_launch_init rlf_launch_init
#define resident_launch_prepare rlf_launch_prepare
#define resident_launch_spawn rlf_launch_spawn
#define resident_launch_spawn_confined rlf_launch_spawn_confined
#define resident_launch_cancel rlf_launch_cancel
#define resident_result_read rlf_result_read
#define resident_launch_close rlf_launch_close
#include "platform/resident_launch.h"
#define recv rlf_recv
#define clock_gettime rlf_clock_gettime
#define poll rlf_poll
#ifndef RLF_SOURCE
#error "RLF_SOURCE must identify the actual shared resident_launch.c"
#endif
#include RLF_SOURCE
#undef recv
#undef clock_gettime
#undef poll
#undef resident_launch_revalidate
#undef resident_startup_begin
#undef resident_startup_check
#undef resident_startup_read
#undef resident_launch_init
#undef resident_launch_prepare
#undef resident_launch_spawn
#undef resident_launch_spawn_confined
#undef resident_launch_cancel
#undef resident_result_read
#undef resident_launch_close

/* Piece sizes the recv wrapper releases on later empty reads, so one frame
 * arrives as several drip-fed fragments. */
static void rlf_fragment_feed_sizes(bool split_header, size_t first)
{
    rlf_sizes[0] = split_header ? sizeof(struct resident_result_header) - first : 2;
    rlf_sizes[1] = split_header ? 2 : 3;
    rlf_sizes[2] = split_header ? 3 : 0;
}

/* An accepted result is exactly the five-byte READY payload. */
static bool rlf_payload_is_ready(const struct resident_result_header *out, const char *payload)
{
    return out->payload_len == 5 && memcmp(payload, "READY", 5) == 0;
}

/* A green fragment run: the read was accepted, no drip-feed send failed and the
 * expected number of empty reads was observed. */
static bool rlf_fragment_passed(bool ok, unsigned expected,
    const struct resident_result_header *out, const char *payload)
{
    return ok && !rlf_send_failed && rlf_eagain == expected &&
        rlf_payload_is_ready(out, payload);
}

/* Zero only when the run passed and both channel fds closed cleanly. */
static int rlf_exit_code(bool passed, bool closed_read, bool closed_write)
{
    return passed && closed_read && closed_write ? 0 : 1;
}

static int rlf_case(bool split_header)
{
    int peer[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, peer) != 0) { perror("fragment socketpair"); return 1; }
    int flags = fcntl(peer[0], F_GETFL);
    if (flags < 0 || fcntl(peer[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        perror("fragment nonblocking"); (void)close(peer[0]); (void)close(peer[1]); return 1;
    }
    struct resident_result_header wire = {0};
    memcpy(wire.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memset(wire.nonce, 'a', 64); wire.nonce[64] = 0; wire.payload_len = 5;
    unsigned char frame[sizeof(wire) + 5];
    memcpy(frame, &wire, sizeof(wire)); memcpy(frame + sizeof(wire), "READY", 5);
    size_t first = split_header ? 7 : sizeof(wire);
    bool queued = send(peer[1], frame, first, MSG_NOSIGNAL) == (ssize_t)first;
    rlf_target = peer[0]; rlf_writer = peer[1]; rlf_wire = frame;
    rlf_offset = first; rlf_piece = 0; rlf_eagain = 0; rlf_send_failed = false;
    rlf_fragment_feed_sizes(split_header, first);
    struct resident_launch launch = {.ipc_native = (uintptr_t)peer[0]};
    memcpy(launch.nonce, wire.nonce, sizeof(launch.nonce));
    struct resident_result_header out = {0};
    char payload[5] = {0}, error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    bool ok = queued && rlf_result_read(&launch, &out, payload, sizeof(payload), 1000,
                                       error, sizeof(error));
    unsigned expected = split_header ? 3 : 2;
    bool passed = rlf_fragment_passed(ok, expected, &out, payload);
    printf("resident_fragment %s: %s actual_empty_reads=%u expected=%u error=%s\n",
        split_header ? "header_and_payload" : "payload_only", passed ? "GREEN" : "RED",
        rlf_eagain, expected, error);
    rlf_target = rlf_writer = -1; rlf_wire = NULL;
    bool closed_read = close(peer[0]) == 0;
    bool closed_write = close(peer[1]) == 0;
    return rlf_exit_code(passed, closed_read, closed_write);
}

struct rlf_boundary {
    const char *name;
    size_t queued;
    bool eof, stale, accepted;
    uint32_t timeout;
    int error_number;
    const char *error_text;
};

/* Judge one boundary run against its expectation: acceptance and payload when a
 * result was required, errno and error text when refusal was required. */
static bool rlf_boundary_matches(const struct rlf_boundary *test, bool setup, bool accepted,
    const struct resident_result_header *out, const char *payload, int observed_errno,
    const char *error)
{
    bool passed = setup && accepted == test->accepted;
    if (accepted) passed = passed && rlf_payload_is_ready(out, payload);
    else passed = passed && observed_errno == test->error_number &&
        strstr(error, test->error_text) != NULL;
    return passed;
}

static int rlf_boundary_case(const struct rlf_boundary *test)
{
    int peer[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, peer) != 0) { perror("boundary socketpair"); return 1; }
    int flags = fcntl(peer[0], F_GETFL);
    if (flags < 0 || fcntl(peer[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        perror("boundary nonblocking"); (void)close(peer[0]); (void)close(peer[1]); return 1;
    }
    struct resident_result_header wire = {0};
    memcpy(wire.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memset(wire.nonce, test->stale ? 'b' : 'a', 64);
    wire.payload_len = 5;
    unsigned char frame[sizeof(wire) + 5];
    memcpy(frame, &wire, sizeof(wire)); memcpy(frame + sizeof(wire), "READY", 5);
    bool setup = send(peer[1], frame, test->queued, MSG_NOSIGNAL) == (ssize_t)test->queued;
    if (test->eof && shutdown(peer[1], SHUT_WR) != 0) setup = false;
    struct resident_launch launch = {.ipc_native = (uintptr_t)peer[0]};
    memset(launch.nonce, 'a', 64);
    struct resident_result_header out = {0};
    char payload[5] = {0}, error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    errno = 0;
    bool accepted = setup && rlf_result_read(&launch, &out, payload, sizeof(payload),
                                            test->timeout, error, sizeof(error));
    int observed_errno = errno;
    bool passed = rlf_boundary_matches(test, setup, accepted, &out, payload, observed_errno, error);
    printf("resident_fragment %s: %s errno=%d error=%s\n", test->name, passed ? "GREEN" : "RED",
           observed_errno, error);
    bool closed_read = close(peer[0]) == 0;
    bool closed_write = close(peer[1]) == 0;
    return rlf_exit_code(passed, closed_read, closed_write);
}

static int rlf_boundaries(void)
{
    const size_t h = sizeof(struct resident_result_header);
    const struct rlf_boundary tests[] = {
        {"timeout0_complete", h + 5, false, false, true, 0, 0, ""},
        {"timeout0_header_withheld", 7, false, false, false, 0, ETIMEDOUT, "timed out after 0 ms"},
        {"timeout0_payload_withheld", h, false, false, false, 0, ETIMEDOUT, "timed out after 0 ms"},
        {"header_EOF", 7, true, false, false, 1000, ECONNRESET, "resident closed the channel"},
        {"payload_EOF", h + 2, true, false, false, 1000, ECONNRESET, "truncated result payload"},
        {"stale_nonce", h + 5, false, true, false, 1000, ESTALE, "result_stale_launch"}
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        failures += rlf_boundary_case(&tests[i]);
    return failures;
}

static size_t rlf_startup_wire(unsigned char *bytes, const char *text, bool stale)
{
    struct resident_result_header header = {0};
    memcpy(header.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memset(header.nonce, stale ? 'b' : 'a', 64);
    header.payload_len = (uint32_t)strlen(text);
    memcpy(bytes, &header, sizeof(header));
    memcpy(bytes + sizeof(header), text, header.payload_len);
    return sizeof(header) + header.payload_len;
}

struct rlf_startup_case {
    const char *name, *first, *second;
    uint32_t elapsed_ms, advance_ms;
    unsigned advance_recv;
    bool split, stale, pass;
    int error_number;
    unsigned flags; /* 1: silent; 2: EOF; 4: stale second; 8: withhold; 16: EINTR */
};

static bool rlf_startup_setup(const struct rlf_startup_case *test,
                              const int peer[2], unsigned char bytes[320])
{
    size_t length = rlf_startup_wire(bytes, test->first, test->stale);
    if (test->second) length += rlf_startup_wire(bytes + length, test->second, (test->flags & 4u) != 0);
    size_t initial = (test->flags & 1u) ? 0 : (test->flags & 8u) ? 1 : test->split ? 3 : length;
    bool setup = send(peer[1], bytes, initial, MSG_NOSIGNAL) == (ssize_t)initial;
    if (test->flags & 2u) setup = setup && shutdown(peer[1], SHUT_WR) == 0;
    rlf_target = peer[0]; rlf_writer = peer[1]; rlf_wire = bytes; rlf_offset = initial;
    rlf_piece = 0; rlf_eagain = 0; rlf_send_failed = false;
    memset(rlf_sizes, 0, sizeof(rlf_sizes));
    if (test->split) {
        rlf_sizes[0] = sizeof(struct resident_result_header) - initial;
        rlf_sizes[1] = length - sizeof(struct resident_result_header);
    }
    rlf_virtual_time = true; rlf_now_ns = UINT64_C(10000000000);
    rlf_interrupt_poll = (test->flags & 16u) != 0;
    rlf_recv_count = 0; rlf_advance_recv = test->advance_recv;
    rlf_advance_ns = (uint64_t)test->advance_ms * UINT64_C(1000000);
    return setup;
}

static bool rlf_startup_assert(const struct rlf_startup_case *test,
    struct resident_launch *launch, struct resident_startup *startup,
    bool accepted, int observed_errno, uint64_t total)
{
    if (accepted != test->pass || startup->total_end_ns != total) return false;
    if (!accepted && observed_errno != test->error_number) return false;
    if (accepted && (startup->ready_ns >= total ||
        startup->ready_ns - startup->entry_observed_ns >= UINT64_C(100000000) ||
        startup->child_entry_ns != (test->second ? 123u : 0u))) return false;
    /* Success and partial failure both consume the observed entry boundary. */
    if (startup->entry_observed_ns) {
        char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
        return !rlf_startup_read(launch, startup, error, sizeof(error)) && errno == EINVAL;
    }
    return true;
}

static int rlf_startup_case_run(const struct rlf_startup_case *test)
{
    int peer[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, peer) != 0) { perror("startup socketpair"); return 1; }
    unsigned char bytes[320];
    bool setup = rlf_startup_setup(test, peer, bytes);
    struct resident_launch launch;
    rlf_launch_init(&launch);
    launch.ipc_native = (uintptr_t)peer[0];
    memset(launch.nonce, 'a', 64); launch.nonce[64] = 0;
    struct resident_startup startup = {0};
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    setup = setup && rlf_startup_begin(&startup, 4000, 100, error, sizeof(error));
    uint64_t total = startup.total_end_ns;
    rlf_now_ns += (uint64_t)test->elapsed_ms * UINT64_C(1000000);
    bool accepted = setup && rlf_startup_read(&launch, &startup, error, sizeof(error));
    int observed_errno = errno;
    bool passed = setup && !rlf_send_failed &&
        rlf_startup_assert(test, &launch, &startup, accepted, observed_errno, total);
    printf("resident_startup %s: %s accepted=%d errno=%d total_unchanged=%d\n",
        test->name, passed ? "GREEN" : "RED", accepted, observed_errno, startup.total_end_ns == total);
    rlf_virtual_time = false; rlf_target = -1; rlf_writer = -1;
    bool closed_read = close(peer[0]) == 0;
    bool closed_write = close(peer[1]) == 0;
    return passed && closed_read && closed_write ? 0 : 1;
}

static int rlf_startup_cases(void)
{
    const struct rlf_startup_case tests[] = {
        {"legacy_ready", "READY", NULL, 0, 0, 0, false, false, true, 0, 0},
        {"entry_ready", "ENTRY 123", "READY", 0, 0, 0, false, false, true, 0, 0},
        {"fragmented_entry_ready", "ENTRY 123", "READY", 0, 0, 0, true, false, true, 0, 0},
        {"loader_tail_3126ms", "ENTRY 123", "READY", 3126, 0, 0, false, false, true, 0, 0},
        {"prepare_exhausted", "READY", NULL, 4000, 0, 0, false, false, false, ETIMEDOUT, 0},
        {"late_buffered_entry", "READY", NULL, 3999, 2, 1, false, false, false, ETIMEDOUT, 0},
        {"legacy_protocol_late", "READY", NULL, 0, 101, 2, false, false, false, ETIMEDOUT, 0},
        {"ready_late_after_entry", "ENTRY 123", "READY", 0, 101, 4, false, false, false, ETIMEDOUT, 0},
        {"fragment_trickle", "ENTRY 123", "READY", 0, 101, 3, true, false, false, ETIMEDOUT, 0},
        {"total_boundary", "ENTRY 123", "READY", 3999, 102, 4, false, false, false, ETIMEDOUT, 0},
        {"duplicate_entry", "ENTRY 123", "ENTRY 123", 0, 0, 0, false, false, false, EBADMSG, 0},
        {"malformed_entry", "ENTRY 12x", "READY", 0, 0, 0, false, false, false, EBADMSG, 0},
        {"overflow_entry", "ENTRY 18446744073709551615", "READY", 0, 0, 0, false, false, false, EBADMSG, 0},
        {"stale_entry", "ENTRY 123", "READY", 0, 0, 0, false, true, false, ESTALE, 0},
        {"silent_platform_timeout", "READY", NULL, 0, 0, 0, false, false, false, ETIMEDOUT, 1},
        {"EOF_before_entry", "READY", NULL, 0, 0, 0, false, false, false, ECONNRESET, 3},
        {"EOF_after_entry", "ENTRY 123", NULL, 0, 0, 0, false, false, false, ECONNRESET, 2},
        {"stale_ready_after_entry", "ENTRY 123", "READY", 0, 0, 0, false, false, false, ESTALE, 4},
        {"exact_100ms_after_final_recv", "READY", NULL, 0, 100, 3, false, false, false, ETIMEDOUT, 0},
        {"partial_reentry_refused", "READY", NULL, 0, 0, 0, false, false, false, ETIMEDOUT, 8},
        {"EINTR_does_not_renew", "ENTRY 123", "READY", 0, 0, 0, true, false, false, ETIMEDOUT, 16}
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        failures += rlf_startup_case_run(&tests[i]);
    return failures;
}

int resident_result_fragments_run(void)
{
    int failures = rlf_case(false) + rlf_case(true);
    return failures + rlf_boundaries() + rlf_startup_cases();
}
#ifdef RLF_STANDALONE
int main(void) { return resident_result_fragments_run(); }
#endif
