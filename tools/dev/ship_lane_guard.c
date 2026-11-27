/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate isolated ship subjects and their fixture evidence. */
#define _XOPEN_SOURCE 700
#include "ship_lane_guard.h"
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool absolute_path(const char *s)
{
    return s && s[0] == '/' && s[1] && !strstr(s, "/../") &&
           !strstr(s, "/./") && !strstr(s, "//") &&
           s[strlen(s) - 1] != '/';
}

static bool devfleet_path(const char *path)
{
    static const char suffix[] = "/.zclassic-c23-devfleet";
    size_t len = strlen(path), slen = sizeof suffix - 1;
    return len > slen && !strcmp(path + len - slen, suffix);
}

static bool ancestry_has_inode(const char *path, const struct stat *target)
{
    char copy[4096];
    if (strlen(path) >= sizeof copy) return true;
    memcpy(copy, path, strlen(path) + 1);
    for (;;) {
        struct stat item;
        if (stat(copy, &item)) return true;
        if (item.st_dev == target->st_dev && item.st_ino == target->st_ino)
            return true;
        char *slash = strrchr(copy, '/');
        if (!slash || slash == copy) break;
        *slash = '\0';
    }
    return false;
}

static bool overlaps(const char *a, const char *b)
{
    struct stat sa, sb;
    if (stat(a, &sa) || stat(b, &sb)) return true;
    return ancestry_has_inode(a, &sb) || ancestry_has_inode(b, &sa);
}

static bool subject_complete(const struct ship_lane_subject *s)
{
    return s && s->observed && s->active && s->pid && s->start_token &&
           absolute_path(s->executable) && absolute_path(s->datadir) &&
           s->p2p_port > 0 && s->p2p_port <= 65535 &&
           s->rpc_port > 0 && s->rpc_port <= 65535 &&
           s->p2p_port != s->rpc_port;
}

bool ship_lane_subjects_disjoint(const struct ship_lane_subject *a,
                                  const struct ship_lane_subject *b)
{
    return subject_complete(a) && subject_complete(b) && a->pid != b->pid &&
           !overlaps(a->datadir, b->datadir) && a->p2p_port != b->p2p_port &&
           a->p2p_port != b->rpc_port && a->rpc_port != b->p2p_port &&
           a->rpc_port != b->rpc_port;
}

static bool selected_allowed(const struct ship_lane_subject *s, const char *dir)
{
    return subject_complete(s) && absolute_path(dir) && devfleet_path(dir) &&
           s->unit && !strcmp(s->unit, "z23-devfleet-node.service") &&
           s->lane && !strcmp(s->lane, "dev") && !strcmp(s->datadir, dir) &&
           s->p2p_port == 8053 && s->rpc_port == 18260;
}

bool ship_lane_devfleet_allowed(const struct ship_lane_subject *s,
                               const char *expected_datadir,
                               const struct ship_lane_subject *others,
                               size_t count)
{
    if (!selected_allowed(s, expected_datadir) || !others || count != 4) return false;
    static const char *const names[] = {"z23-node.service", "zclassic23.service",
                                        "z23-soak.service", "zcl23-dev.service"};
    for (size_t i = 0; i < count; i++) {
        const struct ship_lane_subject *o = &others[i];
        if (!o->observed || !o->unit || strcmp(o->unit, names[i])) return false;
        if (!o->active) continue;
        if (!ship_lane_subjects_disjoint(s, o)) return false;
    }
    return true;
}

static bool read_proc_file(uint64_t pid, const char *name, char *buf, size_t cap,
                           size_t *len)
{
    char path[96];
    if (!pid || snprintf(path, sizeof path, "/proc/%llu/%s",
                         (unsigned long long)pid, name) >= (int)sizeof path)
        return false;
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    *len = fread(buf, 1, cap - 1, fp);
    bool ok = !ferror(fp) && feof(fp);
    if (fclose(fp) != 0) ok = false;
    buf[*len] = '\0';
    return ok;
}

static bool read_start(uint64_t pid, uint64_t *start)
{
    char data[8192];
    size_t len;
    if (!read_proc_file(pid, "stat", data, sizeof data, &len)) return false;
    char *end = strrchr(data, ')');
    if (!end || end[1] != ' ') return false;
    char *p = end + 2;
    for (unsigned field = 3; field < 22; field++) {
        p = strchr(p, ' ');
        if (!p) return false;
        while (*p == ' ') p++;
    }
    errno = 0;
    unsigned long long n = strtoull(p, &end, 10);
    if (errno || end == p || (*end != ' ' && *end != '\n') || !n) return false;
    *start = (uint64_t)n;
    return true;
}

static bool parse_port(const char *s, unsigned *out)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || end == s || *end || n == 0 || n > 65535) return false;
    *out = (unsigned)n;
    return true;
}

struct node_flags { bool datadir, p2p, rpc, lane; };

static bool unsupported_node_flag(const char *arg)
{
    static const char *const names[] = {"datadir", "rpcport", "port", "operator-lane"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        char double_flag[32], bare_flag[32];
        (void)snprintf(double_flag, sizeof double_flag, "--%s", names[i]);
        (void)snprintf(bare_flag, sizeof bare_flag, "-%s", names[i]);
        if (!strncmp(arg, double_flag, strlen(double_flag)) || !strcmp(arg, bare_flag))
            return true;
    }
    return false;
}

static bool parse_node_flag(const char *arg, struct ship_lane_proc_snapshot *s,
                            struct node_flags *f)
{
    if (!strncmp(arg, "-datadir=", 9)) {
        if (f->datadir || !absolute_path(arg + 9) || !realpath(arg + 9, s->datadir)) return false;
        f->datadir = true;
    } else if (!strncmp(arg, "-port=", 6)) {
        if (f->p2p || !parse_port(arg + 6, &s->p2p_port)) return false;
        f->p2p = true;
    } else if (!strncmp(arg, "-rpcport=", 9)) {
        if (f->rpc || !parse_port(arg + 9, &s->rpc_port)) return false;
        f->rpc = true;
    } else if (!strncmp(arg, "-operator-lane=", 15)) {
        if (f->lane) return false;
        f->lane = true;
        s->declared_dev = !strcmp(arg + 15, "dev");
    } else if (unsupported_node_flag(arg)) return false;
    return true;
}

static bool parse_argv(char *buf, size_t len, struct ship_lane_proc_snapshot *s)
{
    struct node_flags flags = {0};
    for (size_t pos = 0; pos < len;) {
        char *arg = buf + pos;
        size_t remain = len - pos, n = strnlen(arg, remain);
        if (n == remain || !parse_node_flag(arg, s, &flags)) return false;
        pos += n + 1;
    }
    return flags.datadir && flags.p2p;
}


struct proc_capture {
    char path[96], exe[4096], args[65536];
    size_t len;
    struct stat stat;
    uint64_t start;
};

static bool capture_begin(uint64_t pid, struct proc_capture *c)
{
    if (!read_start(pid, &c->start) ||
        snprintf(c->path, sizeof c->path, "/proc/%llu/exe", (unsigned long long)pid) >= (int)sizeof c->path ||
        stat(c->path, &c->stat) || !realpath(c->path, c->exe)) return false;
    return read_proc_file(pid, "cmdline", c->args, sizeof c->args, &c->len) && c->len;
}

static bool capture_end(uint64_t pid, const struct proc_capture *c)
{
    struct stat after_stat;
    char args[65536];
    size_t len;
    uint64_t start;
    if (!read_start(pid, &start) || start != c->start || stat(c->path, &after_stat) ||
        c->stat.st_dev != after_stat.st_dev || c->stat.st_ino != after_stat.st_ino)
        return false;
    return read_proc_file(pid, "cmdline", args, sizeof args, &len) &&
           len == c->len && !memcmp(c->args, args, len);
}

static bool capture_named(const struct proc_capture *c, const char *name)
{
    const char *base = strrchr(c->exe, '/');
    return base && !strcmp(base + 1, name);
}

bool ship_lane_read_process(uint64_t pid, struct ship_lane_proc_snapshot *out)
{
    if (!out) return false;
    struct ship_lane_proc_snapshot s = {0};
    struct proc_capture c = {0};
    if (!capture_begin(pid, &c) || !parse_argv(c.args, c.len, &s) ||
        !capture_end(pid, &c)) return false;
    s.start_token = c.start;
    memcpy(s.executable, c.exe, sizeof s.executable);
    *out = s;
    return true;
}


static bool option_value(const char *arg, const char *prefix, bool numeric)
{
    size_t n = strlen(prefix);
    if (strncmp(arg, prefix, n) || !arg[n]) return false;
    if (numeric) for (const char *p = arg + n; *p; p++)
        if (*p < '0' || *p > '9') return false;
    return true;
}

static size_t split_args(char *buf, size_t len, const char **parts, size_t cap)
{
    size_t count = 0;
    for (size_t pos = 0; pos < len;) {
        size_t n = strnlen(buf + pos, len - pos);
        if (n == len - pos || count == cap) return 0;
        parts[count++] = buf + pos;
        pos += n + 1;
    }
    return count;
}

static bool worker_options(const char *const *a)
{
    return !strcmp(a[0], "--worker=p0-r2") && option_value(a[1], "--deadline_s=", true) &&
           option_value(a[2], "--idle_limit_s=", true) && option_value(a[3], "--max_jobs=", true) &&
           option_value(a[4], "--time_cap_s=", true) && option_value(a[5], "--cpu_s=", true) &&
           option_value(a[6], "--mem_mb=", true) && option_value(a[7], "--token_cap=", true);
}

static bool receiver_options(const char *const *a)
{
    return !strcmp(a[0], "--receiver=r2-devfleet") && option_value(a[1], "--workspace=", false) &&
           option_value(a[2], "--wait_ms=", true) && option_value(a[3], "--deadline_s=", true);
}

static bool client_argv(char *buf, size_t len, const char *datadir, bool worker)
{
    const char *args[16];
    size_t count = split_args(buf, len, args, 16);
    if (count != (worker ? 15u : 11u) || strcmp(args[1], "dev") ||
        strcmp(args[2], "agent") || strcmp(args[3], worker ? "worker" : "receive") ||
        strcmp(args[4], "run")) return false;
    if (worker ? !worker_options(args + 5) : !receiver_options(args + 5)) return false;
    size_t i = worker ? 13 : 9;
    return !strncmp(args[i], "-datadir=", 9) &&
           !strcmp(args[i] + 9, datadir) && !strcmp(args[i + 1], "-rpcport=18260");
}


bool ship_lane_read_client(uint64_t pid, const char *datadir, bool worker, uint64_t *start)
{
    struct proc_capture c = {0};
    if (!datadir || !start || !capture_begin(pid, &c) || !capture_named(&c, "z23-dev") ||
        !client_argv(c.args, c.len, datadir, worker) || !capture_end(pid, &c)) return false;
    *start = c.start;
    return true;
}


bool ship_lane_read_mcp_client(uint64_t pid)
{
    struct proc_capture c = {0};
    const char *parts[6];
    if (!capture_begin(pid, &c) || !capture_named(&c, "z23") ||
        split_args(c.args, c.len, parts, 6) != 6) return false;
    if (strcmp(parts[1], "mcp") || strcmp(parts[2], "serve") ||
        !option_value(parts[3], "--datadir=", false) ||
        !option_value(parts[4], "--rpcport=", true) ||
        !option_value(parts[5], "--checkout=", false)) return false;
    return capture_end(pid, &c);
}


static bool socket_inodes(uint64_t pid, unsigned long long *ids, size_t *count)
{
    char path[96];
    if (snprintf(path, sizeof path, "/proc/%llu/fd", (unsigned long long)pid) >= (int)sizeof path)
        return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    struct dirent *entry;
    bool ok = true;
    *count = 0;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (entry->d_name[0] == '.') continue;
        char link_path[4096], target[128];
        if (snprintf(link_path, sizeof link_path, "%s/%s", path, entry->d_name) >= (int)sizeof link_path)
            { ok = false; break; }
        ssize_t n = readlink(link_path, target, sizeof target - 1);
        if (n < 0) { if (errno == ENOENT) continue; ok = false; break; }
        target[n] = '\0';
        unsigned long long id;
        char tail;
        if (sscanf(target, "socket:[%llu]%c", &id, &tail) == 1) {
            if (*count == 4096) { ok = false; break; }
            ids[(*count)++] = id;
        }
    }
    if (closedir(dir)) ok = false;
    return ok;
}

struct listener_scan {
    const unsigned long long *ids;
    size_t count;
    unsigned p2p, rpc, required, required2, *other;
    bool *have_required, *have_required2;
};

static bool listener_owned(const struct listener_scan *s, unsigned long long inode)
{
    for (size_t i = 0; i < s->count; i++) if (s->ids[i] == inode) return true;
    return false;
}

static bool listener_accept_port(const char *local, struct listener_scan *s)
{
    const char *colon = strrchr(local, ':');
    char *end;
    if (!colon) return false;
    unsigned long port = strtoul(colon + 1, &end, 16);
    if (*end || !port || port > 65535 || port == s->p2p || port == s->rpc) return false;
    if (port == s->required) *s->have_required = true;
    if (port == s->required2) *s->have_required2 = true;
    if (port != s->required) *s->other = (unsigned)port;
    return true;
}


static bool listener_line(char *line, struct listener_scan *s)
{
    char *save = NULL, *fields[10];
    size_t n = 0;
    for (char *p = strtok_r(line, " \t\n", &save); p && n < 10;
         p = strtok_r(NULL, " \t\n", &save)) fields[n++] = p;
    if (n < 10 || strcmp(fields[3], "0A")) return true;
    char *end;
    errno = 0;
    unsigned long long inode = strtoull(fields[9], &end, 10);
    if (errno || *end) return false;
    if (!listener_owned(s, inode)) return true;
    return listener_accept_port(fields[1], s);
}

static bool scan_listeners(uint64_t pid, const char *family, struct listener_scan *s)
{
    char path[96], *line = NULL;
    size_t cap = 0;
    if (snprintf(path, sizeof path, "/proc/%llu/net/%s", (unsigned long long)pid, family) >= (int)sizeof path)
        return false;
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    bool ok = true;
    while (getline(&line, &cap, fp) >= 0)
        if (!listener_line(line, s)) { ok = false; break; }
    if (ferror(fp)) ok = false;
    if (fclose(fp)) ok = false;
    free(line);
    return ok;
}

static bool same_network_namespace(uint64_t a_pid, uint64_t b_pid)
{
    char a[96], b[96];
    struct stat sa, sb;
    if (snprintf(a, sizeof a, "/proc/%llu/ns/net", (unsigned long long)a_pid) >= (int)sizeof a ||
        snprintf(b, sizeof b, "/proc/%llu/ns/net", (unsigned long long)b_pid) >= (int)sizeof b ||
        stat(a, &sa) || stat(b, &sb)) return false;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}


bool ship_lane_listeners_disjoint(uint64_t pid, uint64_t selected_pid, unsigned p2p,
                                  unsigned rpc, unsigned required, unsigned required2, unsigned *other)
{
    uint64_t before, after;
    unsigned long long ids[4096];
    size_t count;
    bool have_required = required == 0, have_required2 = required2 == 0;
    if (!other) return false;
    *other = 0;
    if (!read_start(pid, &before) || !same_network_namespace(pid, selected_pid) ||
        !socket_inodes(pid, ids, &count) || !count) return false;
    struct listener_scan scan = {ids, count, p2p, rpc, required, required2, other, &have_required, &have_required2};
    if (!scan_listeners(pid, "tcp", &scan) || !scan_listeners(pid, "tcp6", &scan) ||
        !have_required || !have_required2 || !*other || !read_start(pid, &after) || before != after) return false;
    return true;
}

bool ship_lane_read_tunnel(uint64_t pid, uint64_t *start)
{
    struct proc_capture c = {0};
    const char *parts[7];
    if (!start || !capture_begin(pid, &c) || !capture_named(&c, "z23") ||
        split_args(c.args, c.len, parts, 7) != 7) return false;
    if (strcmp(parts[1], "ops") || strcmp(parts[2], "mesh") ||
        strcmp(parts[3], "device") || strcmp(parts[4], "host") ||
        strcmp(parts[5], "receiver") || !option_value(parts[6], "--input-file=", false) ||
        !capture_end(pid, &c)) return false;
    *start = c.start;
    return true;
}
