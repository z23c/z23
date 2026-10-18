/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Ask the kernel to deliver SIGKILL to `victim` when a pipe becomes readable. */
static const char *sigio_owner(pid_t victim)
{
    int p[2];
    if (pipe(p) != 0)
        return "failed";
    if (fcntl(p[0], F_SETOWN, victim) != 0 || fcntl(p[0], F_SETSIG, SIGKILL) != 0)
        return "failed";
    (void)fcntl(p[0], F_SETFL, O_ASYNC | O_NONBLOCK);
    return write(p[1], "x", 1) == 1 ? "set" : "failed";
}

int main(int argc, char **argv)
{
    char line[32] = "";
    if (argc <= 1 && !fgets(line, sizeof(line), stdin))
        line[0] = '0';
    const char *digits = argc > 1 ? argv[1] : line;
    while (*digits && (*digits < '0' || *digits > '9'))
        digits++;
    pid_t outside = (pid_t)atoi(digits);
    printf("own_pid_small=%s\n", getpid() < 16 ? "yes" : "no");
    printf("self_signal=%s\n", kill(getpid(), 0) == 0 ? "ok" : "failed");
    printf("outside_kill=%s\n", kill(outside, SIGKILL) == 0 ? "sent" : "failed");
    printf("parent_kill=%s\n", kill(getppid(), 0) == 0 ? "sent" : "failed");
    printf("group_kill=%s\n", kill(-1, SIGKILL) == 0 ? "sent" : "failed");
    printf("sigio_owner=%s\n", sigio_owner(outside));
    DIR *d = opendir("/proc");
    printf("proc_scan=%s\n", d ? "allowed" : "denied");
    if (d)
        closedir(d);
    return 0;
}
