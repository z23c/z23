/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#define _POSIX_C_SOURCE 200809L
#include "ship_lane_guard.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static bool manager_read(int fd, pid_t child, char *out, size_t cap)
{
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status) || !used || used + 1 == cap)
        return false;
    if (out[used - 1] == '\n') used--;
    out[used] = '\0';
    return used > 0 && !strchr(out, '\n');
}
static bool manager_value(const char *unit, const char *property, char *out, size_t cap)
{
    int fds[2];
    if (pipe(fds)) return false;
    pid_t child = fork();
    if (child < 0) { close(fds[0]); close(fds[1]); return false; }
    if (child == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execlp("systemctl", "systemctl", "--user", "show", unit,
               "--property", property, "--value", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    return manager_read(fds[0], child, out, cap);
}

static bool manager_subject(const char *unit, struct ship_lane_subject *subject,
                            struct ship_lane_proc_snapshot *snapshot)
{
    char load[64], state[64], pid_text[64], *end;
    subject->unit = unit;
    if (!manager_value(unit, "LoadState", load, sizeof load)) return false;
    if (!strcmp(load, "not-found")) { subject->observed = true; return true; }
    if (strcmp(load, "loaded") ||
        !manager_value(unit, "ActiveState", state, sizeof state)) return false;
    subject->observed = true;
    if (!strcmp(state, "inactive") || !strcmp(state, "failed")) return true;
    if (strcmp(state, "active") ||
        !manager_value(unit, "MainPID", pid_text, sizeof pid_text)) return false;
    errno = 0;
    unsigned long long pid = strtoull(pid_text, &end, 10);
    if (errno || end == pid_text || *end || !pid ||
        !ship_lane_read_process(pid, snapshot)) return false;
    subject->active = true;
    subject->pid = pid;
    subject->start_token = snapshot->start_token;
    subject->executable = snapshot->executable;
    subject->datadir = snapshot->datadir;
    subject->p2p_port = snapshot->p2p_port;
    subject->rpc_port = snapshot->rpc_port;
    subject->lane = snapshot->declared_dev ? "dev" : "unknown";
    return true;
}

static bool known_pid(uint64_t pid, const struct ship_lane_subject *selected,
                      const struct ship_lane_subject *others, size_t count,
                      const uint64_t clients[3])
{
    if (pid == selected->pid || pid == (uint64_t)getpid() ||
        pid == clients[0] || pid == clients[1] || pid == clients[2]) return true;
    for (size_t i = 0; i < count; i++)
        if (others[i].active && others[i].pid == pid) return true;
    return false;
}

static bool potentially_node(const char *args, size_t size)
{
    if (strnlen(args, size) == size) return true;
    const char *base = strrchr(args, 47);
    base = base ? base + 1 : args;
    if (!strcmp(base, "z23") || !strcmp(base, "zclassic23")) return true;
    for (size_t pos = 0; pos < size;) {
        const char *arg = args + pos;
        size_t n = strnlen(arg, size - pos);
        if (n == size - pos) return true;
        if (!strncmp(arg, "-datadir", 8) || !strncmp(arg, "--datadir", 9) ||
            !strncmp(arg, "-rpcport", 8) || !strncmp(arg, "--rpcport", 9))
            return true;
        pos += n + 1;
    }
    return false;
}

static bool unknown_candidate_safe(unsigned long long pid,
                                   const struct ship_lane_subject *selected)
{
    {
        struct ship_lane_proc_snapshot snapshot;
        struct ship_lane_subject subject = {.pid = pid, .observed = true, .active = true};
        if (ship_lane_read_process(pid, &snapshot)) {
            subject.start_token = snapshot.start_token;
            subject.executable = snapshot.executable;
            subject.datadir = snapshot.datadir;
            subject.p2p_port = snapshot.p2p_port;
            subject.rpc_port = snapshot.rpc_port;
            unsigned actual_other;
            if (!ship_lane_listeners_disjoint(pid, selected->pid, selected->p2p_port,
                                              selected->rpc_port, subject.p2p_port,
                                              subject.rpc_port, &actual_other)) return false;
            if (!subject.rpc_port) subject.rpc_port = actual_other;
            if (!ship_lane_subjects_disjoint(selected, &subject)) return false;
        } else if (!ship_lane_read_mcp_client(pid)) return false;
    }
    return true;
}

static bool unknown_pid_safe(const char *proc_root, unsigned long long pid,
                             const struct ship_lane_subject *selected)
{
    char path[128];
    struct stat st;
    if (snprintf(path, sizeof path, "%s/%llu", proc_root, pid) >= (int)sizeof path)
        return false;
    if (stat(path, &st)) { return errno == ENOENT; }
    if (st.st_uid != getuid()) return true;
    if (snprintf(path, sizeof path, "%s/%llu/cmdline", proc_root, pid) >= (int)sizeof path)
        return false;
    FILE *fp = fopen(path, "rb");
    if (!fp) { return errno == ENOENT; }
    char args[65536];
    size_t used = fread(args, 1, sizeof args, fp);
    bool read_ok = !ferror(fp) && feof(fp);
    if (fclose(fp)) read_ok = false;
    if (!read_ok) return false;
    if (used && potentially_node(args, used)) return unknown_candidate_safe(pid, selected);
    return true;
}

static bool no_unknown_node(const char *proc_root,
                            const struct ship_lane_subject *selected,
                            const struct ship_lane_subject *others, size_t count,
                            const uint64_t clients[3])
{
    DIR *dir = opendir(proc_root);
    if (!dir) return false;
    bool safe = true;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) safe = false; break; }
        char *end;
        errno = 0;
        unsigned long long pid = strtoull(entry->d_name, &end, 10);
        if (errno || end == entry->d_name || *end || !pid ||
            known_pid(pid, selected, others, count, clients)) continue;
        if (!unknown_pid_safe(proc_root, pid, selected)) { safe = false; break; }
    }
    if (closedir(dir)) safe = false;
    return safe;
}

static bool client_subject(const char *unit, const char *datadir, bool worker,
                           uint64_t *pid_out, uint64_t *start)
{
    char load[64], state[64], text[64], *end;
    *pid_out = 0;
    *start = 0;
    if (!manager_value(unit, "LoadState", load, sizeof load)) return false;
    if (!strcmp(load, "not-found")) return true;
    if (strcmp(load, "loaded") || !manager_value(unit, "ActiveState", state, sizeof state))
        return false;
    if (!strcmp(state, "inactive") || !strcmp(state, "failed")) return true;
    if (strcmp(state, "active") || !manager_value(unit, "MainPID", text, sizeof text))
        return false;
    errno = 0;
    unsigned long long pid = strtoull(text, &end, 10);
    if (errno || end == text || *end || !pid ||
        !ship_lane_read_client(pid, datadir, worker, start)) return false;
    *pid_out = pid;
    return true;
}

static bool tunnel_subject(const struct ship_lane_subject *selected, uint64_t *pid_out,
                           uint64_t *start)
{
    const char *unit = "z23-tunnel-receiver@r1.service";
    char load[64], state[64], text[64], *end;
    *pid_out = 0;
    *start = 0;
    if (!manager_value(unit, "LoadState", load, sizeof load)) return false;
    if (!strcmp(load, "not-found")) return true;
    if (strcmp(load, "loaded") || !manager_value(unit, "ActiveState", state, sizeof state))
        return false;
    if (!strcmp(state, "inactive") || !strcmp(state, "failed")) return true;
    if (strcmp(state, "active") || !manager_value(unit, "MainPID", text, sizeof text))
        return false;
    errno = 0;
    unsigned long long pid = strtoull(text, &end, 10);
    unsigned other;
    if (errno || end == text || *end || !pid || !ship_lane_read_tunnel(pid, start) ||
        !ship_lane_listeners_disjoint(pid, selected->pid, selected->p2p_port,
                                      selected->rpc_port, 0, 0, &other)) return false;
    *pid_out = pid;
    return true;
}

static bool collect_clients(const char *expected, const struct ship_lane_subject *selected,
                            uint64_t clients[3], uint64_t starts[3])
{
    return client_subject("z23-devfleet-receiver.service", expected, false, &clients[0], &starts[0]) &&
        client_subject("z23-devfleet-worker.service", expected, true, &clients[1], &starts[1]) &&
        tunnel_subject(selected, &clients[2], &starts[2]);
}

static bool clients_stable(const char *root, const char *expected,
                           const struct ship_lane_subject *selected,
                           const struct ship_lane_subject *others)
{
    uint64_t clients[3], starts[3], again[3], again_starts[3];
    if (!collect_clients(expected, selected, clients, starts) ||
        !no_unknown_node(root, selected, others, 4, clients) ||
        !collect_clients(expected, selected, again, again_starts)) return false;
    for (size_t i = 0; i < 3; i++)
        if (clients[i] != again[i] || starts[i] != again_starts[i]) return false;
    return true;
}

static bool subject_unchanged(const struct ship_lane_subject *now,
                              const struct ship_lane_subject *before)
{
    return now->active == before->active && now->pid == before->pid &&
        (!now->active || (now->start_token == before->start_token &&
         !strcmp(now->executable, before->executable) &&
         !strcmp(now->datadir, before->datadir) &&
         now->p2p_port == before->p2p_port && now->rpc_port == before->rpc_port));
}

static bool managed_listeners_disjoint(const struct ship_lane_subject *selected,
                                        const struct ship_lane_subject *others)
{
    for (size_t i = 0; i < 4; i++) {
        unsigned other;
        if (others[i].active &&
            !ship_lane_listeners_disjoint(others[i].pid, selected->pid,
                                          selected->p2p_port, selected->rpc_port,
                                          others[i].p2p_port, others[i].rpc_port,
                                          &other)) return false;
    }
    return true;
}

static bool coexistence_safe(const char *root, const char *expected,
                             const struct ship_lane_subject *selected,
                             const struct ship_lane_subject *others)
{
    unsigned other;
    return ship_lane_listeners_disjoint(selected->pid, selected->pid, 0, 0,
                                        selected->p2p_port, selected->rpc_port, &other) &&
           managed_listeners_disjoint(selected, others) &&
           clients_stable(root, expected, selected, others);
}

static bool selected_unchanged(const struct ship_lane_subject *selected)
{
    struct ship_lane_proc_snapshot verify = {0};
    struct ship_lane_subject subject = {0};
    return manager_subject("z23-devfleet-node.service", &subject, &verify) &&
        subject.pid == selected->pid && verify.start_token == selected->start_token &&
        !strcmp(verify.executable, selected->executable) &&
        !strcmp(verify.datadir, selected->datadir) &&
        verify.p2p_port == selected->p2p_port && verify.rpc_port == selected->rpc_port &&
        verify.declared_dev;
}

static bool guard_args(int argc, char **argv, char *expected, size_t cap,
                       unsigned long long *pid, unsigned long long *start)
{
    const char *home = getenv("HOME");
    char *end;
    if (argc != 3 || !home || home[0] != '/' ||
        snprintf(expected, cap, "%s/.zclassic-c23-devfleet", home) >= (int)cap)
        return false;
    errno = 0;
    *pid = strtoull(argv[1], &end, 10);
    if (errno || end == argv[1] || *end) return false;
    *start = strtoull(argv[2], &end, 10);
    return !errno && end != argv[2] && !*end;
}

static int guard_run(const char *proc_root, int argc, char **argv)
{
    static const char *const units[] = {"z23-node.service", "zclassic23.service",
        "z23-soak.service", "zcl23-dev.service"};
    char expected[4096];
    unsigned long long want_pid, want_start;
    if (!guard_args(argc, argv, expected, sizeof expected, &want_pid, &want_start)) return 2;
    struct ship_lane_subject selected = {0}, others[4] = {0};
    struct ship_lane_proc_snapshot snap = {0}, other_snap[4] = {0};
    if (!manager_subject("z23-devfleet-node.service", &selected, &snap)) return 1;
    for (size_t i = 0; i < 4; i++)
        if (!manager_subject(units[i], &others[i], &other_snap[i])) return 1;
    if (!ship_lane_devfleet_allowed(&selected, expected, others, 4) ||
        (want_pid && selected.pid != want_pid) ||
        (want_start && selected.start_token != want_start)) return 1;
    if (!coexistence_safe(proc_root, expected, &selected, others)) return 1;
    for (size_t i = 0; i < 4; i++) {
        struct ship_lane_subject now = {0};
        struct ship_lane_proc_snapshot now_snap = {0};
        if (!manager_subject(units[i], &now, &now_snap) ||
            !subject_unchanged(&now, &others[i])) return 1;
    }
    if (!selected_unchanged(&selected)) return 1;
    printf("%llu %llu\n", (unsigned long long)selected.pid,
           (unsigned long long)selected.start_token);
    return 0;
}

int main(int argc, char **argv)
{
    return guard_run("/proc", argc, argv);
}
