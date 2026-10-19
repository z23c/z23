/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.slot.activate - move service instances onto an installed
 *          binary slot, one instance at a time, with automatic rollback.
 *          Per instance, in order: record last-good, write a systemd --user
 *          drop-in (<unit>.d/z23-slot.conf, temp + rename) that points
 *          ExecStart's binary at <slots>/<slot>/z23, daemon-reload, restart
 *          that one instance, require MainPID's /proc exe to be the slot,
 *          then run the health check (a listen port, or a probe argv with
 *          no shell). The first failure restores every instance moved so
 *          far plus the failing one (same checks) and returns
 *          SLOT_ACTIVATE_ROLLED_BACK naming the instance and the phase.
 *          A running exe whose bytes differ from the install record is
 *          SLOT_RUNNING_DIGEST_MISMATCH (phase running_digest), rolled back.
 *
 *          Only the allow-listed classes tunnel-receiver and gateway can be
 *          activated; the canonical node unit and ~/.local/bin are never
 *          touched. systemctl is injectable (ZCL_SLOT_SYSTEMCTL_BIN) and so
 *          are the unit directory, state directory and /proc root, which is
 *          how the tests run a fake systemd.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif

#if defined(_WIN32)
static void osa_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED_PLATFORM",
                               "normalize", false, false,
                               "slot activate needs systemd and POSIX files",
                               "ops.slot.activate");
}
#else

#define OSA_CMD "ops.slot.activate"
#define OSA_MAX_INSTANCES 8u
#define OSA_MAX_PROBE_ARGS 12u
#define OSA_ARG_MAX 256u
#define OSA_TEXT_MAX 4096u
#define OSA_TIMEOUT_DEFAULT_MS 30000
#define OSA_TIMEOUT_MAX_MS 300000

enum osa_health_kind { OSA_HEALTH_LISTEN, OSA_HEALTH_PROBE };

struct osa_inst {
    char name[SLOT_NAME_MAX + 1];
    char unit[160];
    char dropin_dir[SLOT_PATH_MAX];
    char dropin[SLOT_PATH_MAX];
    char state[SLOT_PATH_MAX];
    char prior[OSA_TEXT_MAX];
    char prior_bin[SLOT_PATH_MAX];
    char prior_args[OSA_TEXT_MAX];
    char last_good[SLOT_NAME_MAX + 2];
    bool had_prior;
    bool touched;
    int port;
    const char *failed_phase;
    const char *rollback_phase;
    const char *outcome;
};

struct osa {
    const char *service_class, *slot;
    char exec_args[OSA_TEXT_MAX];
    bool dry_run;
    struct slot_paths sp;
    char want_hex[65]; /* the install record digest the running exe must match */
    char unit_dir[SLOT_PATH_MAX];
    char state_dir[SLOT_PATH_MAX];
    char systemctl[SLOT_PATH_MAX];
    char proc_root[SLOT_PATH_MAX];
    enum osa_health_kind kind;
    int default_port;
    int64_t timeout_ms;
    char probe[OSA_MAX_PROBE_ARGS][OSA_ARG_MAX];
    size_t probe_n;
    struct osa_inst inst[OSA_MAX_INSTANCES];
    size_t n;
};

static void osa_invalid(struct zcl_command_reply *reply, const char *code,
                        const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, evidence);
}

static const char *osa_str(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    const char *s = v ? json_get_str(v) : NULL;
    return (s && s[0]) ? s : NULL;
}

static bool osa_copy(char *dst, size_t cap, const char *src)
{
    int n = snprintf(dst, cap, "%s", src);
    return n >= 0 && (size_t)n < cap;
}

/* ---- parsing ----------------------------------------------------------- */

static bool osa_add_instance(struct osa *a, const struct json_value *item,
                             struct zcl_command_reply *reply)
{
    const char *name = NULL;
    const struct json_value *port = NULL;
    struct osa_inst *in = &a->inst[a->n];
    if (item->type == JSON_STR)
        name = json_get_str(item);
    else if (item->type == JSON_OBJ) {
        name = osa_str(item, "name");
        port = json_get(item, "port");
    }
    if (!slot_name_ok(name) ||
        !slot_unit_name(a->service_class, name, in->unit, sizeof(in->unit))) {
        osa_invalid(reply, "BAD_INSTANCE",
                    "an instance is a name of 1-64 characters of a-z 0-9 . _ "
                    "- (or {name, port})", name ? name : "");
        return false;
    }
    for (size_t i = 0; i < a->n; i++)
        if (strcmp(a->inst[i].name, name) == 0) {
            osa_invalid(reply, "BAD_INSTANCE", "duplicate instance", name);
            return false;
        }
    osa_copy(in->name, sizeof(in->name), name);
    in->port = port && port->type == JSON_INT ? (int)json_get_int(port) : 0;
    a->n++;
    return true;
}

static bool osa_parse_instances(const struct json_value *in, struct osa *a,
                                struct zcl_command_reply *reply)
{
    const struct json_value *arr = json_get(in, "instances");
    size_t count = arr && arr->type == JSON_ARR ? json_size(arr) : 0;
    if (count == 0 || count > OSA_MAX_INSTANCES) {
        osa_invalid(reply, "MISSING_INPUT",
                    "instances must be a non-empty array of at most 8 "
                    "instance names", OSA_CMD);
        return false;
    }
    for (size_t i = 0; i < count; i++)
        if (!osa_add_instance(a, json_at(arr, i), reply))
            return false;
    return true;
}

static bool osa_parse_probe(const struct json_value *argv, struct osa *a,
                            struct zcl_command_reply *reply)
{
    size_t count = argv && argv->type == JSON_ARR ? json_size(argv) : 0;
    bool ok = count > 0 && count <= OSA_MAX_PROBE_ARGS;
    for (size_t i = 0; ok && i < count; i++) {
        const char *s = json_get_str(json_at(argv, i));
        ok = s && osa_copy(a->probe[i], OSA_ARG_MAX, s);
    }
    if (!ok || a->probe[0][0] != '/') {
        osa_invalid(reply, "BAD_HEALTH",
                    "a probe is health.argv: an array of up to 12 strings "
                    "whose first is an absolute program path (no shell)",
                    OSA_CMD);
        return false;
    }
    a->probe_n = count;
    return true;
}

static bool osa_parse_listen(const struct json_value *h, const char *kind,
                             struct osa *a, struct zcl_command_reply *reply)
{
    const struct json_value *p = json_get(h, "port");
    a->kind = OSA_HEALTH_LISTEN;
    a->default_port = p && p->type == JSON_INT ? (int)json_get_int(p) : 0;
    for (size_t i = 0; i < a->n; i++) {
        int port = a->inst[i].port ? a->inst[i].port : a->default_port;
        if (strcmp(kind, "listen") != 0 || port < 1 || port > 65535) {
            osa_invalid(reply, "BAD_HEALTH",
                        "a listen check needs a port 1..65535 per instance "
                        "(instance {name, port} or health.port)",
                        a->inst[i].name);
            return false;
        }
        a->inst[i].port = port;
    }
    return true;
}

static bool osa_parse_health(const struct json_value *in, struct osa *a,
                             struct zcl_command_reply *reply)
{
    const struct json_value *h = json_get(in, "health");
    const char *kind = h ? osa_str(h, "kind") : NULL;
    const struct json_value *t = h ? json_get(h, "timeout_ms") : NULL;
    a->timeout_ms = OSA_TIMEOUT_DEFAULT_MS;
    if (t && t->type == JSON_INT)
        a->timeout_ms = json_get_int(t);
    if (!kind || a->timeout_ms < 0 || a->timeout_ms > OSA_TIMEOUT_MAX_MS) {
        osa_invalid(reply, "BAD_HEALTH",
                    "health needs kind=listen|probe and a timeout_ms of "
                    "0..300000", OSA_CMD);
        return false;
    }
    if (strcmp(kind, "probe") == 0) {
        a->kind = OSA_HEALTH_PROBE;
        return osa_parse_probe(json_get(h, "argv"), a, reply);
    }
    return osa_parse_listen(h, kind, a, reply);
}

static bool osa_parse_exec_args(const struct json_value *in, struct osa *a,
                                struct zcl_command_reply *reply)
{
    const char *s = osa_str(in, "exec_args");
    if (s && !osa_copy(a->exec_args, sizeof(a->exec_args), s)) {
        osa_invalid(reply, "BAD_EXEC_ARGS", "exec_args is too long", OSA_CMD);
        return false;
    }
    for (const char *c = a->exec_args; *c; c++)
        if ((unsigned char)*c < 0x20 || *c == 0x7f) {
            osa_invalid(reply, "BAD_EXEC_ARGS",
                        "exec_args must be one line of printable text",
                        OSA_CMD);
            return false;
        }
    return true;
}

static bool osa_env_path(const char *v, const char *dflt, char *out,
                         size_t cap)
{
    return osa_copy(out, cap, (v && v[0]) ? v : dflt);
}

static bool osa_resolve_dirs(struct osa *a, struct zcl_command_reply *reply)
{
    enum slot_path_status ps = slot_paths_resolve(&a->sp, a->slot);
    if (ps != SLOT_PATH_OK) {
        osa_invalid(reply,
                    ps == SLOT_PATH_NO_ROOT ? "NO_SLOTS_DIR"
                                            : "SLOT_PATH_TOO_LONG",
                    "cannot resolve the slots directory", OSA_CMD);
        return false;
    }
    if (!slot_unit_dir(a->unit_dir, sizeof(a->unit_dir)) ||
        !slot_state_dir(a->state_dir, sizeof(a->state_dir))) {
        osa_invalid(reply, "NO_UNIT_DIR",
                    "cannot locate the systemd user unit or state directory: "
                    "set ZCL_SLOT_UNIT_DIR / ZCL_SLOT_STATE_DIR to absolute "
                    "paths or ensure HOME is set", OSA_CMD);
        return false;
    }
    (void)osa_env_path(getenv("ZCL_SLOT_SYSTEMCTL_BIN"), "systemctl", a->systemctl,
                       sizeof(a->systemctl));
    (void)osa_env_path(getenv("ZCL_SLOT_PROC_ROOT"), "/proc", a->proc_root,
                       sizeof(a->proc_root));
    return true;
}

static bool osa_set_paths(struct osa_inst *in, const char *unit_dir,
                          const char *state_dir)
{
    int x = snprintf(in->dropin_dir, sizeof(in->dropin_dir), "%s/%s.d",
                     unit_dir, in->unit);
    int z = snprintf(in->state, sizeof(in->state), "%s/%s.last-good",
                     state_dir, in->unit);
    int y = snprintf(in->dropin, sizeof(in->dropin), "%s/z23-slot.conf",
                     in->dropin_dir);
    return x > 0 && y > 0 && z > 0 && (size_t)x < sizeof(in->dropin_dir) &&
           (size_t)y < sizeof(in->dropin) && (size_t)z < sizeof(in->state);
}

static bool osa_inst_paths(struct osa *a, struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < a->n; i++) {
        if (!osa_set_paths(&a->inst[i], a->unit_dir, a->state_dir)) {
            osa_invalid(reply, "SLOT_PATH_TOO_LONG", "a path is too long",
                        a->inst[i].name);
            return false;
        }
    }
    return true;
}

static bool osa_slot_installed(struct osa *a,
                               struct zcl_command_reply *reply)
{
    struct stat sb;
    if (stat(a->sp.final_path, &sb) != 0 || !S_ISREG(sb.st_mode) ||
        (sb.st_mode & 0100) == 0) {
        osa_invalid(reply, "SLOT_NOT_INSTALLED",
                    "the slot is not an installed executable "
                    "<slots>/<slot>/z23; run ops.slot.install first", a->slot);
        return false;
    }
    switch (slot_verify_installed(a->sp.name_dir)) {
    case SLOT_VERIFY_OK:
        if (slot_record_hex(a->sp.name_dir, a->want_hex))
            return true;
        osa_invalid(reply, "SLOT_DIGEST_MISMATCH",
                    "the slot digest record cannot be read; nothing was "
                    "moved, reinstall the slot", a->slot);
        return false;
    case SLOT_VERIFY_WRITABLE:
        osa_invalid(reply, "SLOT_DIR_WRITABLE",
                    "the slot directory or the slots root is writable by "
                    "group or others; nothing was moved, chmod go-w it",
                    a->slot);
        return false;
    case SLOT_VERIFY_MISMATCH:
        osa_invalid(reply, "SLOT_DIGEST_MISMATCH",
                    "the slot binary no longer matches the digest recorded "
                    "at install; nothing was moved, reinstall the slot",
                    a->slot);
        break;
    case SLOT_VERIFY_NO_RECORD:
        osa_invalid(reply, "SLOT_DIGEST_MISMATCH",
                    "the slot has no digest record from ops.slot.install; "
                    "nothing was moved, reinstall the slot", a->slot);
        break;
    default:
        osa_invalid(reply, "SLOT_DIGEST_MISMATCH",
                    "the slot is a symlink, not a plain directory and file, "
                    "or not owned by this user; nothing was moved", a->slot);
        break;
    }
    return false;
}

static bool osa_parse(const struct zcl_command_request *request,
                      struct osa *a, struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const struct json_value *dry = json_get(in, "dry_run");
    a->service_class = osa_str(in, "service_class");
    a->slot = osa_str(in, "slot");
    a->dry_run = dry && dry->type == JSON_BOOL && json_get_bool(dry);
    if (!a->service_class || !a->slot) {
        osa_invalid(reply, "MISSING_INPUT",
                    "ops slot activate needs service_class, slot, instances "
                    "and health", OSA_CMD);
        return false;
    }
    if (!slot_class_ok(a->service_class)) {
        osa_invalid(reply, "BAD_SERVICE_CLASS",
                    "service_class must be tunnel-receiver or gateway; the "
                    "canonical node is never activated here",
                    a->service_class);
        return false;
    }
    if (!slot_name_ok(a->slot)) {
        osa_invalid(reply, "BAD_SLOT_NAME",
                    "a slot name is 1-64 characters of a-z 0-9 . _ -, not "
                    "starting with - or .", a->slot);
        return false;
    }
    return osa_parse_instances(in, a, reply) &&
           osa_parse_health(in, a, reply) &&
           osa_parse_exec_args(in, a, reply) && osa_resolve_dirs(a, reply) &&
           osa_inst_paths(a, reply) && osa_slot_installed(a, reply);
}

/* ---- processes ---------------------------------------------------------- */

/* Run argv (no shell, no PATH games beyond execvp of argv[0]); optionally
 * capture stdout. Returns the exit status, or -1 when it could not run. */
static int osa_run(char *const argv[], char *out, size_t cap)
{
    int fds[2] = { -1, -1 };
    int status = 0, devnull;
    pid_t pid;
    size_t got = 0;
    if (out && cap)
        out[0] = '\0';
    if (out && pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)dup2(devnull, 0);
            (void)dup2(devnull, 2);
            (void)dup2(out ? fds[1] : devnull, 1);
        }
        if (out) {
            close(fds[0]);
            close(fds[1]);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (out) {
        close(fds[1]);
        for (ssize_t r; cap - got > 1 &&
                        (r = read(fds[0], out + got, cap - got - 1)) > 0;)
            got += (size_t)r;
        out[got] = '\0';
        close(fds[0]);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int osa_systemctl(const struct osa *a, const char *verb,
                         const char *unit, char *out, size_t cap)
{
    char *argv[7];
    size_t n = 0;
    argv[n++] = (char *)a->systemctl;
    argv[n++] = (char *)"--user";
    if (strcmp(verb, "show") == 0) {
        argv[n++] = (char *)"show";
        argv[n++] = (char *)"-p";
        argv[n++] = (char *)"MainPID";
        argv[n++] = (char *)"--value";
    } else {
        argv[n++] = (char *)verb;
    }
    if (unit && n < 6)
        argv[n++] = (char *)unit;
    argv[n] = NULL;
    return osa_run(argv, out, cap);
}

static void osa_sleep_ms(int ms)
{
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

/* ---- files -------------------------------------------------------------- */

static bool osa_mkdir_p(const char *path)
{
    char tmp[SLOT_PATH_MAX];
    if (!osa_copy(tmp, sizeof(tmp), path))
        return false;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

/* Temp file in the same directory, fsync, rename: a reader sees the whole
 * old file or the whole new one. */
static bool osa_write_atomic(const char *dir, const char *path,
                             const char *text)
{
    char tmp[SLOT_PATH_MAX];
    size_t len = strlen(text);
    int fd;
    bool ok;
    if (!osa_mkdir_p(dir) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
            (int)sizeof(tmp))
        return false;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    ok = write(fd, text, len) == (ssize_t)len && fsync(fd) == 0;
    close(fd);
    if (!ok || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return false;
    }
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) {
        (void)fsync(fd);
        close(fd);
    }
    return true;
}

static bool osa_dropin_text(const char *bin, const char *args, char *out,
                            size_t cap)
{
    int n = snprintf(out, cap,
                     "# managed by ops.slot.activate; delete this file to "
                     "return to the unit's own ExecStart\n[Service]\n"
                     "ExecStart=\nExecStart=%s%s%s\n",
                     bin, args[0] ? " " : "", args);
    return n > 0 && (size_t)n < cap;
}

/* Remember what is there now: the prior drop-in bytes (restored verbatim on
 * rollback) and the slot name the state file records as last-good. */
static void osa_read_prior(struct osa_inst *in)
{
    char name[SLOT_NAME_MAX + 2];
    long got = slot_read_file(in->dropin, in->prior, sizeof(in->prior));
    in->had_prior = got >= 0;
    in->prior_bin[0] = in->prior_args[0] = '\0';
    snprintf(in->last_good, sizeof(in->last_good), "-");
    if (in->had_prior &&
        slot_dropin_exec(in->prior, in->prior_bin, sizeof(in->prior_bin),
                         in->prior_args, sizeof(in->prior_args)) &&
        slot_name_from_binary(in->prior_bin, name, sizeof(name)))
        snprintf(in->last_good, sizeof(in->last_good), "%s", name);
}

static const char *osa_record_last_good(const struct osa *a,
                                        const struct osa_inst *in)
{
    char text[SLOT_NAME_MAX + 16];
    if (strcmp(in->last_good, a->slot) == 0)
        return NULL; /* already on this slot: keep the older last-good */
    snprintf(text, sizeof(text), "slot=%s\n", in->last_good);
    return osa_write_atomic(a->state_dir, in->state, text) ? NULL
                                                           : "last_good";
}

/* ---- checks ------------------------------------------------------------- */

static bool osa_exe_is(const struct osa *a, long pid, const char *expected)
{
    char link[SLOT_PATH_MAX], target[SLOT_PATH_MAX], real[PATH_MAX];
    ssize_t n;
    if (snprintf(link, sizeof(link), "%s/%ld/exe", a->proc_root, pid) >=
        (int)sizeof(link))
        return false;
    n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return false;
    target[n] = '\0';
    if (strcmp(target, expected) == 0)
        return true;
    return realpath(expected, real) && strcmp(target, real) == 0;
}

/* The bytes of the RUNNING process, not of the path it was started from: open
 * /proc/<pid>/exe and hash that fd against the install record. */
static bool osa_running_digest_ok(const struct osa *a, long pid,
                                  const char *want_hex)
{
    char link[SLOT_PATH_MAX];
    if (snprintf(link, sizeof(link), "%s/%ld/exe", a->proc_root, pid) >=
        (int)sizeof(link))
        return false;
    return slot_exe_matches_hex(link, want_hex);
}

static long osa_main_pid(const struct osa *a, const struct osa_inst *in)
{
    int64_t deadline = platform_time_monotonic_ms() + a->timeout_ms;
    char out[64];
    do {
        long pid;
        if (osa_systemctl(a, "show", in->unit, out, sizeof(out)) == 0 &&
            (pid = strtol(out, NULL, 10)) > 0)
            return pid;
        osa_sleep_ms(100);
    } while (platform_time_monotonic_ms() < deadline);
    return 0;
}

static bool osa_port_open(int port)
{
    struct sockaddr_in sa;
    bool open_now;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    open_now = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
    close(fd);
    return open_now;
}

static void osa_subst(const char *src, const struct osa_inst *in, char *out,
                      size_t cap)
{
    size_t o = 0;
    while (*src && o + 1 < cap) {
        const char *rep = NULL;
        if (strncmp(src, "{instance}", 10) == 0)
            rep = in->name;
        else if (strncmp(src, "{unit}", 6) == 0)
            rep = in->unit;
        if (rep) {
            size_t n = strlen(rep);
            if (o + n + 1 >= cap)
                break;
            memcpy(out + o, rep, n);
            o += n;
            src += rep == in->name ? 10 : 6;
        } else {
            out[o++] = *src++;
        }
    }
    out[o] = '\0';
}

static bool osa_probe_once(const struct osa *a, const struct osa_inst *in)
{
    char args[OSA_MAX_PROBE_ARGS][OSA_ARG_MAX];
    char *argv[OSA_MAX_PROBE_ARGS + 1];
    for (size_t i = 0; i < a->probe_n; i++) {
        osa_subst(a->probe[i], in, args[i], OSA_ARG_MAX);
        argv[i] = args[i];
    }
    argv[a->probe_n] = NULL;
    return osa_run(argv, NULL, 0) == 0;
}

static bool osa_healthy(const struct osa *a, const struct osa_inst *in)
{
    int64_t deadline = platform_time_monotonic_ms() + a->timeout_ms;
    do {
        if (a->kind == OSA_HEALTH_LISTEN ? osa_port_open(in->port)
                                         : osa_probe_once(a, in))
            return true;
        osa_sleep_ms(200);
    } while (platform_time_monotonic_ms() < deadline);
    return false;
}

/* daemon-reload, restart this one instance, require MainPID to run
 * `expected` (NULL: no expectation, a restored unit's own binary), then the
 * health check. Returns the failing phase, or NULL. */
static const char *osa_apply(const struct osa *a, const struct osa_inst *in,
                             const char *expected, const char *want_hex)
{
    long pid;
    if (osa_systemctl(a, "daemon-reload", NULL, NULL, 0) != 0)
        return "daemon_reload";
    if (osa_systemctl(a, "restart", in->unit, NULL, 0) != 0)
        return "restart";
    pid = osa_main_pid(a, in);
    if (pid <= 0)
        return "main_pid";
    if (expected && !osa_exe_is(a, pid, expected))
        return "exe";
    if (want_hex && !osa_running_digest_ok(a, pid, want_hex))
        return "running_digest";
    return osa_healthy(a, in) ? NULL : "health";
}

/* ---- the rolling move --------------------------------------------------- */

static const char *osa_forward(struct osa *a, struct osa_inst *in)
{
    char text[OSA_TEXT_MAX + 512];
    const char *args;
    const char *phase;
    in->touched = true;
    osa_read_prior(in);
    args = a->exec_args[0] ? a->exec_args : in->prior_args;
    phase = osa_record_last_good(a, in);
    if (phase)
        return phase;
    if (!osa_dropin_text(a->sp.final_path, args, text, sizeof(text)) ||
        !osa_write_atomic(in->dropin_dir, in->dropin, text))
        return "dropin";
    return osa_apply(a, in, a->sp.final_path, a->want_hex);
}

/* Put the instance back exactly as it was: prior drop-in bytes, or none. */
static const char *osa_restore(struct osa *a, struct osa_inst *in)
{
    if (in->had_prior) {
        if (!osa_write_atomic(in->dropin_dir, in->dropin, in->prior))
            return "dropin";
    } else if (unlink(in->dropin) != 0 && errno != ENOENT) {
        return "dropin";
    }
    return osa_apply(a, in, in->prior_bin[0] ? in->prior_bin : NULL, NULL);
}

static void osa_push_results(const struct osa *a, struct json_value *out)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < a->n; i++) {
        const struct osa_inst *in = &a->inst[i];
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "instance", in->name);
        json_push_kv_str(&row, "unit", in->unit);
        json_push_kv_str(&row, "outcome", in->outcome ? in->outcome : "");
        json_push_kv_str(&row, "last_good", in->last_good);
        json_push_kv_str(&row, "failed_phase",
                         in->failed_phase ? in->failed_phase : "");
        json_push_kv_str(&row, "rollback_phase",
                         in->rollback_phase ? in->rollback_phase : "");
        json_push_back(&arr, &row);
        json_free(&row);
    }
    json_push_kv(out, "instances", &arr);
    json_free(&arr);
}

static void osa_reply_common(const struct osa *a, struct zcl_command_reply *r)
{
    json_push_kv_str(&r->data, "service_class", a->service_class);
    json_push_kv_str(&r->data, "slot", a->slot);
    json_push_kv_bool(&r->data, "dry_run", a->dry_run);
    json_push_kv_int(&r->data, "zcl_spent", 0);
    osa_push_results(a, &r->data);
}

static void osa_rollback(struct osa *a, size_t failed,
                         struct zcl_command_reply *reply)
{
    bool all_ok = true;
    char msg[320], ev[160];
    for (size_t i = 0; i <= failed; i++) {
        struct osa_inst *in = &a->inst[i];
        if (!in->touched)
            continue;
        in->rollback_phase = osa_restore(a, in);
        in->outcome = in->rollback_phase ? "rollback_failed" : "rolled_back";
        all_ok = all_ok && !in->rollback_phase;
    }
    osa_reply_common(a, reply);
    snprintf(ev, sizeof(ev), "instance=%s phase=%s", a->inst[failed].name,
             a->inst[failed].failed_phase);
    snprintf(msg, sizeof(msg),
             "instance %s failed at %s; %s", a->inst[failed].name,
             a->inst[failed].failed_phase,
             all_ok ? "every moved instance was switched back to its "
                      "previous slot"
                    : "a rollback step also failed: manual attention");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED,
                           !all_ok ? "SLOT_ROLLBACK_FAILED"
                           : strcmp(a->inst[failed].failed_phase,
                                    "running_digest") == 0
                               ? "SLOT_RUNNING_DIGEST_MISMATCH"
                               : "SLOT_ACTIVATE_ROLLED_BACK",
                           a->inst[failed].failed_phase, false, true, msg, ev);
}

static void osa_dry(struct osa *a, struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < a->n; i++) {
        osa_read_prior(&a->inst[i]);
        a->inst[i].outcome = "would_move";
    }
    osa_reply_common(a, reply);
    json_push_kv_str(&reply->data, "note",
                     "dry run: every check passed and nothing was written or "
                     "restarted");
}

static void osa_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    struct osa *a = zcl_calloc(1, sizeof(*a), "slot_activate");
    if (!a) {
        osa_invalid(reply, "OUT_OF_MEMORY", "cannot allocate", OSA_CMD);
        return;
    }
    if (osa_parse(request, a, reply)) {
        if (a->dry_run) {
            osa_dry(a, reply);
        } else {
            size_t i;
            for (i = 0; i < a->n; i++) {
                a->inst[i].failed_phase = osa_forward(a, &a->inst[i]);
                a->inst[i].outcome = a->inst[i].failed_phase ? "failed"
                                                             : "moved";
                if (a->inst[i].failed_phase)
                    break;
            }
            if (i < a->n) {
                osa_rollback(a, i, reply);
            } else {
                osa_reply_common(a, reply);
                json_push_kv_str(&reply->data, "note",
                                 "every instance runs the new slot and "
                                 "passed its health check");
            }
        }
    }
    free(a);
}

#endif /* _WIN32 */

void zcl_native_handle_ops_slot_activate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    osa_execute(request, reply);
}
