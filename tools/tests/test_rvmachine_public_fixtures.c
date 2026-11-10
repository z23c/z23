/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Exercise public fixture controls on isolated host pipes and PTYs. */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "../guest_port.h"
#include "platform/clock.h"

static char fixture_paths[2][256];
static unsigned fixture_opens;
static int fixture_fd = -1;
enum fixture_fault { FIXTURE_OK, FIXTURE_READ, FIXTURE_WRITE, FIXTURE_CLOSE, FIXTURE_OPEN };
static enum fixture_fault fixture_fault;
static int fixture_open_raw(const char *path)
{
    if (strcmp(path, "/dev/vtcon/z23.l0.t") && strcmp(path, "/dev/vtcon/z23.l0.p")) return -1;
    if (fixture_fault == FIXTURE_OPEN) return -1;
    const char *mapped = fixture_paths[fixture_opens++ ? 1 : 0];
    fixture_fd = open_raw(mapped);
    return fixture_fd;
}
static ssize_t fixture_read(int fd, void *buf, size_t size)
{
    if (fd == fixture_fd && fixture_fault == FIXTURE_READ) { errno = EIO; return -1; }
    return read(fd, buf, size);
}
static ssize_t fixture_write(int fd, const void *buf, size_t size)
{
    if (fd == fixture_fd && fixture_fault == FIXTURE_WRITE) { errno = EIO; return -1; }
    return write(fd, buf, size);
}
static int fixture_close(int fd)
{
    if (fd == fixture_fd && fixture_fault == FIXTURE_CLOSE) {
        int rc = close(fd); fixture_fd = -1;
        if (rc == 0) { errno = EIO; return -1; }
        return rc;
    }
    if (fd == fixture_fd) fixture_fd = -1;
    return close(fd);
}
#define open_raw fixture_open_raw
#define read fixture_read
#define write fixture_write
#define close fixture_close
#define main public_port_fixture_main
#include "../../tests/fixtures/rvmachine/src/freebsd_port_bytes.c"
#undef main
#undef close
#undef write
#undef read
#undef open_raw
#define main public_bootstrap_fixture_main
#include "../../tests/fixtures/rvmachine/src/geli_bootstrap_public.c"
#undef main

static pid_t owned_child = -1, owned_group = -1;
static bool child_still_owned(void)
{
    if (owned_child <= 0) return false;
    siginfo_t info = {0};
    int rc;
    do { rc = waitid(P_PID, (id_t)owned_child, &info, WEXITED | WNOHANG | WNOWAIT); }
    while (rc != 0 && errno == EINTR);
    if (rc == 0) return true;
    owned_child = -1; owned_group = -1;
    return false;
}
static void fail(const char *what)
{
    fprintf(stderr, "FAIL public fixtures: %s\n", what);
    if (child_still_owned()) {
        if (owned_group > 0) (void)kill(-owned_group, SIGKILL);
        (void)kill(owned_child, SIGKILL);
        (void)waitpid(owned_child, NULL, 0);
    }
    exit(1);
}
static void transfer(int fd, void *buffer, size_t length, bool writing)
{
    unsigned char *p = buffer;
    while (length) {
        struct pollfd event = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        if (poll(&event, 1, 5000) <= 0) fail("transfer deadline");
        ssize_t n = writing ? write(fd, p, length) : read(fd, p, length);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) fail("transfer failed");
        p += n; length -= (size_t)n;
    }
}
static void line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    do {
        if (n + 1 >= cap) fail("line capacity");
        transfer(fd, out + n, 1, false);
    } while (out[n++] != '\n');
    out[n] = '\0';
}
static void expect_line(int fd, const char *expected)
{
    char got[256]; line(fd, got, sizeof got);
    if (strcmp(got, expected)) { fprintf(stderr, "expected %s got %s", expected, got); fail("stderr line"); }
}
static void observe_child_exit(void)
{
    for (int i = 0; i < 1000; ++i) {
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)owned_child, &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) { owned_child = -1; owned_group = -1; }
            fail("waitid");
        }
        if (info.si_pid == owned_child) return;
        (void)poll(NULL, 0, 10);
    }
    fail("child deadline");
}
static int make_pty(char path[256])
{
    int fd = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0 || grantpt(fd) || unlockpt(fd)) fail("pty setup");
    const char *name = ptsname(fd);
    if (!name) fail("pty name");
    int n = snprintf(path, 256, "%s", name);
    if (n < 0 || n >= 256) fail("pty name");
    return fd;
}
struct child_pipes { int input, output, error; };
static bool bootstrap_control_allowed(const char *arg)
{
    static const char *const allowed[] = {
        "--public-pipe-control", "--public-pipe-short", "--public-pipe-extra",
        "--public-pipe-wrong", "--public-child-failure", "--public-child-cancel",
        "--public-lost-custody", "--public-postreap-expired", "--public-postreap-clockfail"
    };
    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; ++i)
        if (!strcmp(arg, allowed[i])) return true;
    return false;
}
static void fixture_descendant_control(void)
{
    int ready[2];
    if (pipe(ready) != 0) _exit(120);
    pid_t child = fork();
    if (child < 0) _exit(121);
    if (!child) {
        close(ready[0]);
        if (write(ready[1], "R", 1) != 1) _exit(122);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1 || byte != 'R') _exit(122);
    close(ready[0]);
    _exit(0);
}
static void fixture_child(bool bootstrap, const char *arg, enum fixture_fault fault,
                          int input[2], int output[2], int error[2])
{
    if (setpgid(0, 0) != 0) _exit(124);
    if (dup2(input[0], 0) < 0 || dup2(output[1], 1) < 0 || dup2(error[1], 2) < 0) _exit(125);
    close(input[0]); close(input[1]); close(output[0]); close(output[1]); close(error[0]); close(error[1]);
    fixture_fault = fault; fixture_opens = 0; fixture_fd = -1;
    if (!bootstrap && !strcmp(arg, "--harness-descendant")) fixture_descendant_control();
    if (bootstrap && !bootstrap_control_allowed(arg)) _exit(123);
    char *args[] = {bootstrap ? "bootstrap" : "port", (char *)arg, NULL};
    int rc = bootstrap ? public_bootstrap_fixture_main(2, args) : public_port_fixture_main(2, args);
    if (fflush(stdout) || fflush(stderr)) _exit(126);
    _exit(rc);
}
static struct child_pipes launch(bool bootstrap, const char *arg, enum fixture_fault fault)
{
    int input[2], output[2], error[2];
    if (pipe(input) || pipe(output) || pipe(error)) fail("pipes");
    if (fflush(NULL) != 0) fail("flush before fork");
    owned_child = fork();
    if (owned_child < 0) fail("fork");
    if (!owned_child) fixture_child(bootstrap, arg, fault, input, output, error);
    owned_group = owned_child;
    if (setpgid(owned_child, owned_child) != 0 && errno != EACCES && errno != ESRCH) fail("child process group");
    close(input[0]); close(output[1]); close(error[1]);
    return (struct child_pipes){input[1], output[0], error[0]};
}
static void expect_eof(int fd)
{
    struct pollfd event = {.fd = fd, .events = POLLIN};
    int64_t start = clock_now_monotonic_ns(), last = start;
    if (start <= 0) fail("output clock");
    int rc = -1;
    for (;;) {
        int64_t now = clock_now_monotonic_ns();
        if (now <= 0 || now < last) fail("output clock");
        last = now;
        int64_t elapsed = (now - start) / INT64_C(1000000);
        if (elapsed >= 5000) fail("output EOF deadline");
        rc = poll(&event, 1, (int)(5000 - elapsed));
        if (rc < 0 && errno == EINTR) continue;
        break;
    }
    if (rc <= 0) fail("output EOF deadline");
    char c;
    if (read(fd, &c, 1) != 0) fail("unexpected output");
}
static void finish(struct child_pipes p, int expected)
{
    close(p.input);
    observe_child_exit();
    if (kill(-owned_group, SIGKILL) != 0 && errno != ESRCH) fail("child group cleanup");
    expect_eof(p.output); expect_eof(p.error);
    close(p.output); close(p.error);
    int status = 0;
    pid_t reaped;
    do { reaped = waitpid(owned_child, &status, 0); } while (reaped < 0 && errno == EINTR);
    if (reaped < 0 && errno == ECHILD) { owned_child = -1; owned_group = -1; fail("waitpid ownership"); }
    if (reaped != owned_child) fail("waitpid");
    owned_child = -1; owned_group = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) fail("exit status");
}
static void pattern(unsigned char *bytes, unsigned bias)
{
    for (size_t i = 0; i < PB_BYTES; ++i) bytes[i] = (unsigned char)(i * 73u + 19u + bias);
}
static void port_transfer(int master, unsigned bias)
{
    unsigned char sent[PB_BYTES], received[PB_BYTES];
    pattern(sent, bias); transfer(master, sent, sizeof sent, true);
    transfer(master, received, sizeof received, false);
    for (size_t i = 0; i < sizeof sent; ++i)
        if (received[i] != (unsigned char)(sent[i] ^ 0xa5u)) fail("byte mismatch");
}
static void port_success(const char *role)
{
    fprintf(stderr, "public port case %s\n", role);
    int first = make_pty(fixture_paths[0]), second = make_pty(fixture_paths[1]);
    struct child_pipes p = launch(false, role, FIXTURE_OK);
    bool closing = !strcmp(role, "CLOSE"), peer = !strcmp(role, "P");
    expect_line(p.error, peer ? "PUBLIC_PORT_RAW_READY_P\n" : "PUBLIC_PORT_RAW_READY_T\n");
    if (closing) {
        unsigned char initial[PB_BYTES]; pattern(initial, 0); transfer(first, initial, 32, true);
        char message[256]; line(p.error, message, sizeof message);
        int unread = 0, consumed = 0;
        if (sscanf(message, "PUBLIC_PORT_CLOSE_SETUP read=1 unread=%d%n", &unread, &consumed) != 1 ||
            unread <= 0 || strcmp(message + consumed, "\n")) fail("close setup");
        char go[] = "g\n"; transfer(p.input, go, 2, true);
        expect_line(p.error, "PUBLIC_PORT_CLOSED_T\n");
        char rebind[] = "r\n"; transfer(p.input, rebind, 2, true);
        expect_line(p.error, "PUBLIC_PORT_RAW_READY_T\n");
    }
    port_transfer(closing ? second : first, closing ? 53u : peer ? 31u : 0u);
    expect_line(p.error, peer ? "PUBLIC_PORT_RX_EXACT_P:4097\n" : "PUBLIC_PORT_RX_EXACT_T:4097\n");
    expect_line(p.error, peer ? "PUBLIC_PORT_EXACT_P:4097\n" : "PUBLIC_PORT_EXACT_T:4097\n");
    finish(p, 0); close(first); close(second);
}
static void port_refusal(enum fixture_fault fault, const char *message)
{
    fprintf(stderr, "public port refusal %d\n", (int)fault);
    int first = make_pty(fixture_paths[0]), second = make_pty(fixture_paths[1]);
    struct child_pipes p = launch(false, "T", fault);
    if (fault != FIXTURE_OPEN) {
        expect_line(p.error, "PUBLIC_PORT_RAW_READY_T\n");
        if (fault == FIXTURE_READ) {
            unsigned char one = 19; transfer(first, &one, 1, true);
        } else {
            unsigned char sent[PB_BYTES]; pattern(sent, 0); transfer(first, sent, sizeof sent, true);
            if (fault == FIXTURE_CLOSE) {
                unsigned char received[PB_BYTES]; transfer(first, received, sizeof received, false);
                expect_line(p.error, "PUBLIC_PORT_RX_EXACT_T:4097\n");
                expect_line(p.error, "PUBLIC_PORT_EXACT_T:4097\n");
            } else expect_line(p.error, "PUBLIC_PORT_RX_EXACT_T:4097\n");
        }
    }
    expect_line(p.error, message); finish(p, 1); close(first); close(second);
}
static void bootstrap_controls(void)
{
    static const struct { const char *arg; int status; const char *message; } cases[] = {
        {"--public-pipe-control", 0, "PUBLIC_PIPE_CONTROL_EXACT32\n"},
        {"--public-pipe-short", 6, NULL}, {"--public-pipe-extra", 6, NULL},
        {"--public-pipe-wrong", 6, NULL}, {"--public-child-failure", 6, NULL},
        {"--public-child-cancel", 6, "PUBLIC_OWNED_CHILD_CANCELLED_REAPED\n"},
        {"--public-lost-custody", 0, "PUBLIC_LOST_CUSTODY_NO_SIGNAL\n"},
        {"--public-postreap-expired", 0, "PUBLIC_POSTREAP_REFUSED_CUSTODY_PRESERVED\n"},
        {"--public-postreap-clockfail", 0, "PUBLIC_POSTREAP_REFUSED_CUSTODY_PRESERVED\n"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        struct child_pipes p = launch(true, cases[i].arg, FIXTURE_OK);
        if (cases[i].message) expect_line(p.error, cases[i].message);
        finish(p, cases[i].status);
        printf("PASS bootstrap %s\n", cases[i].arg);
    }
}
int main(void)
{
    struct child_pipes descendant = launch(false, "--harness-descendant", FIXTURE_OK);
    finish(descendant, 0);
    puts("PASS descendant holding output is cleaned before leader reap");
    port_success("T"); port_success("P"); port_success("CLOSE");
    port_refusal(FIXTURE_OPEN, "PUBLIC_PORT_REFUSED:RAW\n");
    port_refusal(FIXTURE_READ, "PUBLIC_PORT_REFUSED:READ\n");
    port_refusal(FIXTURE_WRITE, "PUBLIC_PORT_REFUSED:WRITE\n");
    port_refusal(FIXTURE_CLOSE, "PUBLIC_PORT_REFUSED:CLOSE\n");
    puts("PASS public port T/P/CLOSE and refusals");
    bootstrap_controls();
    return 0;
}
