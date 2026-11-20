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
 *   z23-app-launch-fixture app tasks open [--datadir=DIR]
 *                                               record the Tasks argv in DIR,
 *                                               then stay alive like ready
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

static int tasks_launch(int argc, char **argv)
{
    const char *datadir = NULL;
    if (argc == 5) {
        if (strncmp(argv[4], "--datadir=", 10) != 0) return 2;
        datadir = argv[4] + 10;
    } else if (argc != 4) return 2;
    if (datadir) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%s/tasks-argv", datadir);
        if (n <= 0 || (size_t)n >= sizeof(path)) return 2;
        FILE *args = fopen(path, "we");
        if (!args) return 5;
        for (int i = 1; i < argc; ++i) fprintf(args, "%s\n", argv[i]);
        if (fclose(args) != 0) return 5;
    }
    argv[1] = (char *)"ready";
    return 0;
}

static int special_mode(const char *mode)
{
    if (strcmp(mode, "exit") == 0) {
        fprintf(stderr, "FIXTURE: cannot open display: no such display\n");
        return 3;
    }
    if (strcmp(mode, "readydie") == 0) {
        printf("INFO: " FIXTURE_MARKER "\n");
        fflush(stdout);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
        fprintf(stderr, "FIXTURE: X connection broken\n");
        return 1;
    }
    return -1;
}

static int announce_ready(const char *mode, bool handler)
{
    if (strcmp(mode, "ready") == 0 || !handler) {
        printf("INFO: " FIXTURE_MARKER "\n");
        fflush(stdout);
        return 0;
    }
    return strcmp(mode, "silent") == 0 ? 0 : 2;
}

static void await_signal(bool tasks, const char *raise_path)
{
    time_t end = time(NULL) + FIXTURE_LIFETIME_S;
    while (time(NULL) < end) {
        struct timespec ts = {0, 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
        if (g_raise) {
            g_raise = 0;
            if (!tasks) record_raise(raise_path);
        }
    }
}

int main(int argc, char **argv)
{
    bool tasks = argc >= 4 && strcmp(argv[1], "app") == 0 &&
        strcmp(argv[2], "tasks") == 0 && strcmp(argv[3], "open") == 0;
    if (tasks) {
        int rc = tasks_launch(argc, argv);
        if (rc) return rc;
    } else if (argc != 3) return 2;
    int special = tasks ? -1 : special_mode(argv[1]);
    if (special >= 0) return special;
    bool handler = strcmp(argv[1], "nohandler") != 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    if (handler && sigaction(SIGUSR1, &sa, NULL) != 0)
        return 4;
    int rc = announce_ready(argv[1], handler);
    if (rc) return rc;
    await_signal(tasks, argv[2]);
    return 0;
}
