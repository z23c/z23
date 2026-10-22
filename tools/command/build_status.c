/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: report the running and queued build jobs of command/build_admit.h
 *          as JSON. Holders come from /proc/locks, which lists every flock
 *          with its owner and inode. The installed broker's bounded records
 *          are observed separately, with PID/start-tick and scope liveness.
 *          The read takes no lock and changes nothing.
 */

#include "command/build_admit.h"
#include "base/safe_alloc.h"
#include "platform/device_compat.h"

#ifdef __linux__

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum { BS_TEXT_MAX = 240 };

struct bs_record {
    int pid, cpu, ram, io, priority, width;
    unsigned long long tick, queued;
    char scope[128], project[16], class_name[16];
};

static bool bs_one_of(const char *value, const char *csv)
{
    char pattern[64];
    (void)snprintf(pattern, sizeof(pattern), ",%s,", value);
    return strstr(csv, pattern) != NULL;
}

static bool bs_numeric_fields(const char *text)
{
    unsigned field = 0;
    const char *at = text;
    while (*at) {
        at += strspn(at, " \t\r\n");
        if (!*at) break;
        size_t n = strcspn(at, " \t\r\n");
        bool numeric = field == 0 || field == 1 ||
                       (field >= 5 && field <= 9) || field == 11;
        size_t limit = field == 1 || field == 9 ? 19 : 8;
        if (numeric && (n > limit || strspn(at, "0123456789") < n))
            return false;
        at += n;
        field++;
    }
    return field == 12;
}

static bool bs_between(int value, int low, int high)
{
    return value >= low && value <= high;
}

static bool bs_record_bounds(const struct bs_record *r)
{
    /* Observation format bound, not admission policy: scalar int tokens are
     * at most eight decimal digits (bs_numeric_fields), safely below INT_MAX.
     * The observer does not enforce current CPU/memory/I/O reservation caps. */
    return r->pid > 0 && r->tick > 0 && r->queued > 0 && r->queued <= LLONG_MAX &&
        bs_between(r->cpu, 1, 99999999) && bs_between(r->ram, 1, 99999999) &&
        bs_between(r->io, 1, 99999999) && bs_between(r->priority, 0, 99999999) &&
        bs_between(r->width, 1, 99999999);
}

static bool bs_record_parse(const char *text, const char *name,
                             struct bs_record *r)
{
    char version[32], tail, expected[128], scope[160];
    if (!bs_numeric_fields(text) || sscanf(text,
        "%d %llu %127s %15s %15s %d %d %d %d %llu %31s %d %c",
        &r->pid, &r->tick, r->scope, r->project, r->class_name,
        &r->cpu, &r->ram, &r->io, &r->priority, &r->queued,
        version, &r->width, &tail) != 12)
        return false;
    (void)snprintf(expected, sizeof(expected), "%d-%llu-%llu",
                   r->pid, r->tick, r->queued);
    (void)snprintf(scope, sizeof(scope), "devbuild-%s.scope", expected);
    return strcmp(name, expected) == 0 && strcmp(r->scope, scope) == 0 &&
        strcmp(version, "broker-v5") == 0 && bs_record_bounds(r) &&
        bs_one_of(r->project, ",z23,qedc,exclusive,") &&
        bs_one_of(r->class_name, ",legacy,hotload,release,normal,compact,background,exclusive,");
}

static int bs_wrapper_live(const struct bs_record *r, uid_t uid)
{
    char path[64], text[4096];
    struct stat st;
    (void)snprintf(path, sizeof(path), "/proc/%d/stat", r->pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    bool read_ok = fstat(fileno(f), &st) == 0 && st.st_uid == uid &&
                   fgets(text, sizeof(text), f) != NULL;
    fclose(f);
    if (!read_ok)
        return -1;
    char *at = strrchr(text, ')');
    if (!at)
        return -1;
    at += 2;
    for (int field = 3; field < 22; field++) {
        at = strchr(at, ' ');
        if (!at) return -1;
        at++;
    }
    char *end;
    unsigned long long tick = strtoull(at, &end, 10);
    return end != at && tick == r->tick;
}

static int bs_scope_local(const char *scope, uid_t uid, void *context)
{
    char path[512], line[128];
    (void)context;
    (void)snprintf(path, sizeof(path),
        "/sys/fs/cgroup/user.slice/user-%lu.slice/user@%lu.service/development.slice/%s/cgroup.events",
        (unsigned long)uid, (unsigned long)uid, scope);
    FILE *f = fopen(path, "r");
    int result = -1, populated;
    while (f && fgets(line, sizeof(line), f))
        if (sscanf(line, "populated %d", &populated) == 1)
            result = populated == 1 ? 1 : -1;
    if (f) fclose(f);
    return result;
}

static bool bs_read_record(int dir, const char *name, uid_t uid, struct bs_record *r)
{
    char text[512];
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    ssize_t n = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == uid
        ? read(fd, text, sizeof(text) - 1) : -1;
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(text) - 1 || memchr(text, 0, (size_t)n))
        return false;
    text[n] = 0;
    return bs_record_parse(text, name, r);
}

struct bs_broker_view {
    char ids[4096][64];
    size_t count, displayed, omitted, unknown;
};

static bool bs_seen(const struct bs_broker_view *view, const char *name)
{
    for (size_t i = 0; i < view->count; i++)
        if (strcmp(view->ids[i], name) == 0)
            return true;
    return false;
}

static bool bs_broker_row(struct json_value *rows, const char *name,
                           const struct bs_record *r, const char *live)
{
    struct json_value row = {0};
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "source", "broker-v5") &&
        json_push_kv_str(&row, "id", name) && json_push_kv_int(&row, "pid", r->pid) &&
        json_push_kv_str(&row, "project", r->project) &&
        json_push_kv_str(&row, "class", r->class_name) &&
        json_push_kv_str(&row, "liveness", live) &&
        json_push_kv_int(&row, "cpu_tokens", r->cpu) &&
        json_push_kv_int(&row, "ram_gib", r->ram) &&
        json_push_kv_int(&row, "io_tokens", r->io) &&
        json_push_kv_int(&row, "priority", r->priority) &&
        json_push_kv_int(&row, "qualification_width", r->width) &&
        json_push_kv_int(&row, "queued_ns", (int64_t)r->queued) &&
        json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static bool bs_broker_entry(int fd, const char *name, bool is_running,
    uid_t uid, ba_scope_probe probe, void *context, struct json_value *rows,
    struct bs_broker_view *view)
{
    struct bs_record r;
    if (!bs_read_record(fd, name, uid, &r)) {
        view->unknown++;
        return true;
    }
    if (!is_running && bs_seen(view, name)) return true;
    int live = bs_wrapper_live(&r, uid);
    if (is_running && live != 1) live = probe(r.scope, uid, context);
    if (live == 0) return true;
    if (live < 0) view->unknown++;
    if (is_running) {
        (void)snprintf(view->ids[view->count], sizeof(view->ids[0]), "%s", name);
        view->count++;
    }
    if (view->displayed == BA_BROKER_DISPLAY_MAX) {
        view->omitted++;
        return true;
    }
    view->displayed++;
    return bs_broker_row(rows, name, &r, live == 1 ? "live" : "unknown");
}

static bool bs_broker_scan(const char *root, const char *part, uid_t uid,
    ba_scope_probe probe, void *context, struct json_value *rows,
    struct bs_broker_view *view)
{
    char path[BA_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", root, part) >= (int)sizeof(path))
        return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *dir = fd < 0 ? NULL : fdopendir(fd);
    if (!dir) {
        if (fd >= 0) close(fd);
        view->unknown++;
        return true;
    }
    size_t count = 0;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) {
            if (errno) view->unknown++;
            break;
        }
        if (e->d_name[0] == '.') continue;
        if (++count > 4096) { ok = false; break; }
        if (!bs_broker_entry(dirfd(dir), e->d_name, strcmp(part, "running") == 0,
                             uid, probe, context, rows, view)) {
            ok = false; break;
        }
    }
    closedir(dir);
    return ok;
}

static bool bs_broker_coverage(struct json_value *out, const struct bs_broker_view *v, bool ok)
{
    const char *coverage = !ok || v->unknown ? "unknown" : v->omitted ? "partial" : "observed";
    return json_push_kv_str(out, "observation", "unlocked; transitions may race") &&
        json_push_kv_str(out, "broker_coverage", coverage) &&
        json_push_kv_int(out, "broker_displayed", (int64_t)v->displayed) &&
        json_push_kv_int(out, "broker_omitted", (int64_t)v->omitted) &&
        json_push_kv_bool(out, "broker_scan_complete", ok) &&
        json_push_kv_int(out, "broker_unknown_records", (int64_t)v->unknown) && ok;
}

bool ba_status_broker(const char *root, uid_t uid, ba_scope_probe probe,
                      void *context, struct json_value *out)
{
    struct json_value *running = NULL, *queued = NULL;
    if (!out || out->type != JSON_OBJ) return false;
    for (size_t i = 0; i < out->num_children; i++) {
        if (strcmp(out->keys[i], "running") == 0) running = &out->children[i];
        if (strcmp(out->keys[i], "queued") == 0) queued = &out->children[i];
    }
    if (!root || root[0] != '/' || !running || !queued) return false;
    if (running->type != JSON_ARR || queued->type != JSON_ARR) return false;
    struct bs_broker_view *view =
        zcl_calloc(1, sizeof(*view), "build_status_broker_view");
    if (!view) return false;
    if (!probe) probe = bs_scope_local;
    bool ok = bs_broker_scan(root, "running", uid, probe, context,
                             running, view);
    ok = bs_broker_scan(root, "queue-v5", uid, probe, context,
                        queued, view) && ok;
    bool result = bs_broker_coverage(out, view, ok);
    free(view);
    return result;
}

struct bs_lock {
    int pid, owner;
    unsigned dev_major, dev_minor;
    unsigned long inode;
    bool write;
};

/* Every flock of the host, and for each one whose recorded pid has exited
 * the live process that still holds its open file description (0: none
 * found). The owners are looked up once per status call. */
struct bs_view {
    struct bs_lock *locks;
    size_t count, capacity;
    bool scanned;
    uid_t uid;                       /* whose processes may be scanned */
};

static bool bs_lock_append(struct bs_view *v, struct bs_lock lock)
{
    if (v->count == v->capacity) {
        size_t capacity = v->capacity ? v->capacity * 2 : 64;
        if (capacity < v->capacity || capacity > SIZE_MAX / sizeof(*v->locks))
            return false;
        void *grown = zcl_realloc(v->locks, capacity * sizeof(*v->locks),
                                  "build status locks");
        if (!grown) return false;
        v->locks = grown;
        v->capacity = capacity;
    }
    v->locks[v->count++] = lock;
    return true;
}

static bool bs_load_locks(struct bs_view *v)
{
    char line[256];
    FILE *f = fopen("/proc/locks", "r");
    if (!f) return false;
    bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        char kind[16], mode[16];
        struct bs_lock l = {0};
        if (!strchr(line, '\n') && !feof(f)) { ok = false; break; }
        if (sscanf(line, "%*d: %15s %*s %15s %d %x:%x:%lu", kind, mode,
                   &l.pid, &l.dev_major, &l.dev_minor, &l.inode) == 6 &&
            strcmp(kind, "FLOCK") == 0) {
            l.write = strcmp(mode, "WRITE") == 0;
            if (!bs_lock_append(v, l)) { ok = false; break; }
        }
    }
    if (ferror(f)) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool bs_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

static bool bs_pid_visible(int pid)
{
    char path[64];
    struct stat sb;
    (void)snprintf(path, sizeof(path), "/proc/%d", pid);
    return pid > 0 && stat(path, &sb) == 0;
}

/* Record `pid` as the owner of one orphaned lock on this file, at most once
 * per process so descriptors duplicated by dup or fork count once. */
static void bs_claim(struct bs_view *v, unsigned maj, unsigned min,
                     unsigned long inode, int pid)
{
    size_t slot = v->count;
    for (size_t i = 0; i < v->count; i++) {
        if (v->locks[i].inode != inode || v->locks[i].dev_major != maj ||
            v->locks[i].dev_minor != min)
            continue;
        if (v->locks[i].owner == pid)
            return;
        if (v->locks[i].owner == 0 && slot == v->count &&
            !bs_pid_visible(v->locks[i].pid))
            slot = i;
    }
    if (slot < v->count)
        v->locks[slot].owner = pid;
}

/* The kernel reports a flock under the pid that first took it, and the
 * wrapper takes its locks through a short-lived flock(1) child. The open
 * file description that holds the lock lists it in /proc/<pid>/fdinfo, so
 * the process that still owns it is found by device and inode. */
static void bs_scan_file(struct bs_view *v, const char *path, int pid)
{
    char line[256];
    unsigned maj, min;
    unsigned long ino;
    FILE *f = fopen(path, "r");
    while (f && fgets(line, sizeof(line), f))
        if (sscanf(line, "lock:\t%*d: FLOCK ADVISORY %*s %*d %x:%x:%lu",
                   &maj, &min, &ino) == 3)
            bs_claim(v, maj, min, ino, pid);
    if (f)
        fclose(f);
}

static void bs_scan_process(struct bs_view *v, const char *name)
{
    char dir[64], path[128];
    DIR *fds;
    (void)snprintf(dir, sizeof(dir), "/proc/%s/fdinfo", name);
    fds = opendir(dir);
    for (struct dirent *e = fds ? readdir(fds) : NULL; e; e = readdir(fds))
        if (e->d_name[0] != '.' && bs_join(path, sizeof(path), dir, e->d_name))
            bs_scan_file(v, path, atoi(name));
    if (fds)
        closedir(fds);
}

/* Only processes of user `me` are read: the listing never looks into another
 * account's descriptors. */
static void bs_scan_owners(struct bs_view *v, uid_t me)
{
    DIR *proc = opendir("/proc");
    v->scanned = true;
    for (struct dirent *p = proc ? readdir(proc) : NULL; p; p = readdir(proc)) {
        char path[64];
        struct stat sb;
        if (p->d_name[0] < '1' || p->d_name[0] > '9' ||
            !bs_join(path, sizeof(path), "/proc", p->d_name) ||
            stat(path, &sb) != 0 || sb.st_uid != me)
            continue;
        bs_scan_process(v, p->d_name);
    }
    if (proc)
        closedir(proc);
}

/* Holders of `path`: pids written to `pids` (0 when the holder cannot be
 * named), any WRITE flagged. */
static size_t bs_holders(struct bs_view *v, const char *path, int *pids,
                         size_t max, bool *write)
{
    struct stat sb;
    size_t n = 0;
    *write = false;
    if (stat(path, &sb) != 0)
        return 0;
    for (size_t i = 0; i < v->count; i++) {
        if (v->locks[i].inode != (unsigned long)sb.st_ino ||
            v->locks[i].dev_major != platform_device_major(sb.st_dev) ||
            v->locks[i].dev_minor != platform_device_minor(sb.st_dev))
            continue;
        if (n < max) {
            if (!bs_pid_visible(v->locks[i].pid) && !v->scanned)
                bs_scan_owners(v, v->uid);
            pids[n++] = bs_pid_visible(v->locks[i].pid) ? v->locks[i].pid
                                                       : v->locks[i].owner;
        }
        *write = *write || v->locks[i].write;
    }
    return n;
}

static void bs_push_process(struct json_value *row, int pid)
{
    char path[64], text[BS_TEXT_MAX], cwd[BS_TEXT_MAX];
    ssize_t n = 0;
    FILE *f;
    if (pid <= 0)
        return;
    (void)json_push_kv_int(row, "pid", pid);
    text[0] = cwd[0] = '\0';
    (void)snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = pid > 0 ? fopen(path, "r") : NULL;
    if (f) {
        n = (ssize_t)fread(text, 1, sizeof(text) - 1u, f);
        fclose(f);
    }
    for (ssize_t i = 0; i < n; i++)
        if (text[i] == '\0')
            text[i] = ' ';
    text[n > 0 ? n : 0] = '\0';
    (void)snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    n = pid > 0 ? readlink(path, cwd, sizeof(cwd) - 1u) : -1;
    cwd[n > 0 ? n : 0] = '\0';
    (void)json_push_kv_str(row, "cmd", text);
    (void)json_push_kv_str(row, "cwd", cwd);
}

static void bs_push_lanes(struct json_value *out, const char *state_dir,
                          struct bs_view *view)
{
    static const char *const name[BA_MAX_LANES] = {
        "z23.lock", "z23.lock.1", "z23.lock.2", "z23.lock.3"
    };
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (int i = 0; i < BA_MAX_LANES; i++) {
        char path[BA_PATH_MAX];
        int pids[8];
        bool write;
        size_t n = bs_join(path, sizeof(path), state_dir, name[i])
                       ? bs_holders(view, path, pids, 8, &write) : 0;
        for (size_t k = 0; k < n && write; k++) {
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_str(&row, "source", "legacy-locks");
            (void)json_push_kv_int(&row, "lane", i + 1);
            bs_push_process(&row, pids[k]);
            (void)json_push_back(&rows, &row);
            json_free(&row);
        }
    }
    (void)json_push_kv(out, "running", &rows);
    json_free(&rows);
}

/* /proc/locks is paged by position, so a lock dropped elsewhere on the host
 * while it is read can shift entries out of the listing. A ticket the
 * listing does not show is therefore asked directly: a live waiter holds a
 * shared flock, which an exclusive try-lock cannot take. */
static bool bs_ticket_held(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool held;
    if (fd < 0)
        return false;
    held = flock(fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK;
    close(fd);
    return held;
}

/* The waiter that registered a ticket names itself in its suffix; used when
 * the lock listing dropped the ticket and only the try-lock saw it held. */
static int bs_ticket_pid(const char *name)
{
    const char *dash = strchr(name, '-');
    char *end = NULL;
    long pid;
    if (!dash)
        return 0;
    errno = 0;
    pid = strtol(dash + 1, &end, 10);
    if (errno != 0 || end == dash + 1 || *end != '\0' || pid <= 0 ||
        pid > INT_MAX)
        return 0;
    return (int)pid;
}

/* Waiters of one directory in ticket order; entries nobody holds are stale
 * and skipped. A ticket name is <seconds><9-digit ns>-<pid>. */
static size_t bs_push_waiters(struct json_value *out, const char *key,
                              const char *dir, struct bs_view *view)
{
    char (*names)[BA_NAME_MAX];
    size_t n, live = 0;
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    if (!ba_list_names(dir, &names, &n))
        n = 0;
    for (size_t i = 0; i < n; i++) {
        char path[BA_PATH_MAX];
        int pids[4] = {0};
        bool write;
        size_t digits = strcspn(names[i], "-");
        struct json_value row;
        if (!bs_join(path, sizeof(path), dir, names[i]))
            continue;
        if (bs_holders(view, path, pids, 4, &write) == 0) {
            if (!bs_ticket_held(path))
                continue;
            pids[0] = bs_ticket_pid(names[i]);
        }
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "source", "legacy-locks");
        (void)json_push_kv_int(&row, "position", (int64_t)++live);
        (void)json_push_kv_str(&row, "ticket", names[i]);
        (void)json_push_kv_int(&row, "enqueued",
                               digits > 9 ? strtoll(names[i], NULL, 10) /
                                   1000000000LL : 0);
        bs_push_process(&row, pids[0]);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    free(names);
    (void)json_push_kv(out, key, &rows);
    json_free(&rows);
    return live;
}

#endif /* __linux__ */

#ifndef _WIN32
#ifdef __linux__
static bool bs_status_as(const char *state_dir, uid_t uid, struct json_value *out,
                          struct bs_view *snapshot)
{
    struct bs_view view = *snapshot;
    char dir[BA_PATH_MAX], heavy[BA_PATH_MAX];
    int pids[4];
    bool exclusive = false;
    (void)json_push_kv_str(out, "state_dir", state_dir);
    view.uid = uid;
    bs_push_lanes(out, state_dir, &view);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.fifo") ||
        !bs_join(heavy, sizeof(heavy), state_dir, "heavy.lock"))
        return false;
    (void)bs_push_waiters(out, "queued", dir, &view);
    if (!bs_join(dir, sizeof(dir), state_dir, "z23.prio"))
        return false;
    (void)bs_push_waiters(out, "landing", dir, &view);
    (void)bs_holders(&view, heavy, pids, 4, &exclusive);
    (void)json_push_kv_bool(out, "exclusive_build", exclusive);
    const char *broker = getenv("DEVBUILD_BROKER_STATE");
    if (!broker || !broker[0]) {
        if (!bs_join(dir, sizeof(dir), state_dir, "broker-v1")) return false;
        broker = dir;
    }
    return ba_status_broker(broker, uid, NULL, NULL, out);
}
#endif

bool ba_status_as(const char *state_dir, uid_t uid, struct json_value *out)
{
#ifdef __linux__
    struct bs_view view = {0};
    bool ok = bs_load_locks(&view) && bs_status_as(state_dir, uid, out, &view);
    free(view.locks);
    return ok;
#else
    (void)state_dir;
    (void)uid;
    (void)out;
    return false;
#endif
}

bool ba_status(const char *state_dir, struct json_value *out)
{
#ifdef __linux__
    return ba_status_as(state_dir, geteuid(), out);
#else
    (void)state_dir;
    (void)out;
    return false;
#endif
}
#endif
