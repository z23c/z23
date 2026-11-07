/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * purpose: a stand-in desktop app for the app_launch test group. It needs no
 * display. Registered through a temporary apps.tsv, it behaves like the
 * launcher expects a real game to:
 *
 *   z23-app-launch-fixture ready  <raise-file>  print the ready marker, append
 *                                               "raised" to raise-file on each
 *                                               SIGUSR1, exit on SIGTERM
 *   z23-app-launch-fixture exit   <raise-file>  print a display error, exit 3
 *   z23-app-launch-fixture silent <raise-file>  never print the marker
 *   z23-app-launch-fixture nohandler <raise-file>  like ready, but installs no
 *                                               SIGUSR1 handler, so a stray
 *                                               SIGUSR1 ends it (as it would
 *                                               a game without a raise hook)
 *
 * Every mode exits by itself after FIXTURE_LIFETIME_S so a failed test can
 * never leave it running for long. */

#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FIXTURE_LIFETIME_S 60
#define FIXTURE_MARKER "FIXTURE: Device initialized successfully"

static volatile sig_atomic_t g_raise;

static void on_usr1(int sig)
{
    (void)sig;
    g_raise = 1;
}

static void record_raise(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    static const char line[] = "raised\n";
    (void)!write(fd, line, sizeof(line) - 1);
    (void)close(fd);
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    if (strcmp(argv[1], "exit") == 0) {
        fprintf(stderr, "FIXTURE: cannot open display: no such display\n");
        return 3;
    }
    if (strcmp(argv[1], "readydie") == 0) {
        /* The marker, then a lost display shortly after (a game whose X
         * connection breaks once its window is up). */
        printf("INFO: " FIXTURE_MARKER "\n");
        fflush(stdout);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
        fprintf(stderr, "FIXTURE: X connection broken\n");
        return 1;
    }
    bool handler = strcmp(argv[1], "nohandler") != 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    if (handler && sigaction(SIGUSR1, &sa, NULL) != 0)
        return 4;
    if (strcmp(argv[1], "ready") == 0 || !handler) {
        printf("INFO: " FIXTURE_MARKER "\n");
        fflush(stdout);
    } else if (strcmp(argv[1], "silent") != 0) {
        return 2;
    }
    time_t end = time(NULL) + FIXTURE_LIFETIME_S;
    while (time(NULL) < end) {
        struct timespec ts = {0, 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
        if (g_raise) {
            g_raise = 0;
            record_raise(argv[2]);
        }
    }
    return 0;
}
