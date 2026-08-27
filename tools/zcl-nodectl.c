/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _POSIX_C_SOURCE 200809L

#include "platform/time_compat.h"
#include "platform/os_binary_slots.h"
#include "platform/process_compat.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "util/rpc_paths.h"

extern char **environ;

enum { MAX_BUF = 1024 * 1024, SMALL_BUF = 4096 };

struct rpc_auth {
    char user[256];
    char pass[256];
};

struct rpc_target {
    const char *name;
    const char *datadir;
    const char *conf_path;
    const char *cookie_path;
    int port;
    struct rpc_auth auth;
};

struct node_status {
    int blocks;
    int headers;
    int legacy_tip;
    bool healthy;
    bool rpc_ok;
    bool service_active;
    char sync_state[64];
    char degraded_reason[128];
};

struct verify_opts {
    bool restart_first;
    int timeout_secs;
    int poll_secs;
    int stable_samples;
};

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static const char *env_or_default(const char *name, const char *fallback)
{
    const char *val = getenv(name);
    return (val && *val) ? val : fallback;
}

static int64_t now_secs(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static void trim_line(char *s)
{
    size_t len;
    if (!s) return;
    while (*s && isspace((unsigned char)*s)) memmove(s, s + 1, strlen(s));
    len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

static void copy_cstr(char *dst, size_t dst_sz, const char *src)
{
    size_t len;
    if (!dst || dst_sz == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    len = strnlen(src, dst_sz - 1);
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static bool read_line_file(const char *path, char *out, size_t out_sz)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    if (!fgets(out, (int)out_sz, fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    trim_line(out);
    return out[0] != '\0';
}

static bool load_auth_from_cookie(const char *cookie_path, struct rpc_auth *auth)
{
    char line[512];
    char *colon;
    if (!read_line_file(cookie_path, line, sizeof(line))) return false;
    colon = strchr(line, ':');
    if (!colon) return false;
    *colon = '\0';
    copy_cstr(auth->user, sizeof(auth->user), line);
    copy_cstr(auth->pass, sizeof(auth->pass), colon + 1);
    return auth->user[0] && auth->pass[0];
}

static bool load_auth_from_conf(const char *conf_path, struct rpc_auth *auth)
{
    FILE *fp = fopen(conf_path, "r");
    char line[512];
    if (!fp) return false;
    auth->user[0] = '\0';
    auth->pass[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        trim_line(line);
        if (strncmp(line, "rpcuser=", 8) == 0) {
            copy_cstr(auth->user, sizeof(auth->user), line + 8);
        } else if (strncmp(line, "rpcpassword=", 12) == 0) {
            copy_cstr(auth->pass, sizeof(auth->pass), line + 12);
        }
    }
    fclose(fp);
    return auth->user[0] && auth->pass[0];
}

static void load_auth(struct rpc_target *target)
{
    target->auth.user[0] = '\0';
    target->auth.pass[0] = '\0';
    if (load_auth_from_cookie(target->cookie_path, &target->auth)) return;
    (void)load_auth_from_conf(target->conf_path, &target->auth);
}

static bool auth_ready(struct rpc_target *target)
{
    if (target->auth.user[0] && target->auth.pass[0]) return true;
    load_auth(target);
    return target->auth.user[0] && target->auth.pass[0];
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *src, size_t len,
                          char *out, size_t out_sz)
{
    size_t i = 0, o = 0;
    while (i < len && o + 4 < out_sz) {
        uint32_t v = (uint32_t)src[i] << 16;
        int remain = (int)(len - i);
        if (remain > 1) v |= (uint32_t)src[i + 1] << 8;
        if (remain > 2) v |= src[i + 2];
        out[o++] = b64_table[(v >> 18) & 0x3f];
        out[o++] = b64_table[(v >> 12) & 0x3f];
        out[o++] = (remain > 1) ? b64_table[(v >> 6) & 0x3f] : '=';
        out[o++] = (remain > 2) ? b64_table[v & 0x3f] : '=';
        i += 3;
    }
    out[o] = '\0';
}

static int connect_local(int port)
{
    int fd;
    struct sockaddr_in addr;
    struct timeval tv;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool recv_all(int fd, char *out, size_t out_sz)
{
    size_t used = 0;
    ssize_t n;
    while (used + 1 < out_sz) {
        n = recv(fd, out + used, out_sz - used - 1, 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        used += (size_t)n;
    }
    out[used] = '\0';
    return true;
}

static bool rpc_call_json(struct rpc_target *target,
                          const char *method,
                          const char *params_json,
                          char *body_out,
                          size_t body_out_sz)
{
    int fd;
    char auth_raw[512];
    char auth_b64[768];
    char body[SMALL_BUF];
    char request[SMALL_BUF * 2];
    char response[MAX_BUF];
    char *body_start;

    if (!auth_ready(target)) return false;
    snprintf(auth_raw, sizeof(auth_raw), "%s:%s", target->auth.user, target->auth.pass);
    base64_encode((const unsigned char *)auth_raw, strlen(auth_raw), auth_b64, sizeof(auth_b64));
    snprintf(body, sizeof(body),
             "{\"method\":\"%s\",\"params\":%s,\"id\":1}",
             method, params_json ? params_json : "[]");
    snprintf(request, sizeof(request),
             "POST / HTTP/1.1\r\n"
             "Host: 127.0.0.1:%d\r\n"
             "Authorization: Basic %s\r\n"
             "Content-Type: text/plain;\r\n"
             "Connection: close\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s",
             target->port, auth_b64, strlen(body), body);

    fd = connect_local(target->port);
    if (fd < 0) return false;
    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return false;
    }
    if (!recv_all(fd, response, sizeof(response))) {
        close(fd);
        return false;
    }
    close(fd);

    body_start = strstr(response, "\r\n\r\n");
    if (!body_start) return false;
    body_start += 4;
    snprintf(body_out, body_out_sz, "%s", body_start);
    return true;
}

static bool rpc_ready(struct rpc_target *target, int tries)
{
    char body[SMALL_BUF];
    int i;
    for (i = 0; i < tries; i++) {
        if (rpc_call_json(target, "getinfo", "[]", body, sizeof(body))) return true;
        sleep_ms(1000);
    }
    return false;
}

static const char *json_find_key(const char *json, const char *key)
{
    static char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    return strstr(json, needle);
}

static bool json_get_int(const char *json, const char *key, int *out)
{
    const char *p = json_find_key(json, key);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    *out = atoi(p);
    return true;
}

static bool json_get_bool(const char *json, const char *key, bool *out)
{
    const char *p = json_find_key(json, key);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool json_get_string(const char *json, const char *key, char *out, size_t out_sz)
{
    const char *p = json_find_key(json, key);
    const char *start;
    const char *end;
    size_t len;
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    start = strchr(p, '"');
    if (!start) return false;
    start++;
    end = strchr(start, '"');
    if (!end) return false;
    len = (size_t)(end - start);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static int run_cmd_capture(const char *const argv[], char *out, size_t out_sz)
{
    int pipefd[2];
    pid_t pid;
    int status;
    ssize_t n;
    size_t used = 0;

    if (pipe(pipefd) != 0) return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execvp(argv[0], (char * const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    while ((n = read(pipefd[0], out + used, out_sz - used - 1)) > 0) {
        used += (size_t)n;
        if (used + 1 >= out_sz) break;
    }
    close(pipefd[0]);
    out[used] = '\0';
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int run_cmd(const char *const argv[])
{
    char discard[256];
    return run_cmd_capture(argv, discard, sizeof(discard));
}

static bool service_is_active(void)
{
    const char *argv[] = {"systemctl", "--user", "is-active", "zclassic23", NULL};
    char out[256];
    int rc = run_cmd_capture(argv, out, sizeof(out));
    trim_line(out);
    return rc == 0 && strcmp(out, "active") == 0;
}

static pid_t service_main_pid(void)
{
    const char *argv[] = {"systemctl", "--user", "show", "-p", "MainPID", "--value", "zclassic23", NULL};
    char out[256];
    if (run_cmd_capture(argv, out, sizeof(out)) != 0) return -1;
    trim_line(out);
    if (!out[0]) return -1;
    return (pid_t)atoi(out);
}

static void systemctl_start(void)
{
    const char *reset_argv[] = {"systemctl", "--user", "reset-failed", "zclassic23", NULL};
    const char *start_argv[] = {"systemctl", "--user", "start", "zclassic23", NULL};
    (void)run_cmd(reset_argv);
    if (run_cmd(start_argv) != 0) die("systemctl start zclassic23 failed");
}

static void systemctl_stop(void)
{
    const char *stop_argv[] = {"systemctl", "--user", "stop", "zclassic23", NULL};
    (void)run_cmd(stop_argv);
}

static bool wait_for_service_state(bool active, int timeout_secs)
{
    int64_t deadline = now_secs() + timeout_secs;
    while (now_secs() < deadline) {
        if (service_is_active() == active) return true;
        sleep_ms(500);
    }
    return service_is_active() == active;
}

static bool stop_via_rpc(struct rpc_target *c23)
{
    char body[SMALL_BUF];
    return rpc_call_json(c23, "stop", "[]", body, sizeof(body));
}

static void force_kill_service(void)
{
    pid_t pid = service_main_pid();
    if (pid > 1) {
        kill(pid, SIGKILL);
    }
    sleep_ms(1000);
    systemctl_stop();
    {
        const char *reset_argv[] = {"systemctl", "--user", "reset-failed", "zclassic23", NULL};
        (void)run_cmd(reset_argv);
    }
}

static void stop_service_gracefully(struct rpc_target *c23, int timeout_secs)
{
    if (!service_is_active()) return;

    if (rpc_ready(c23, 1)) {
        (void)stop_via_rpc(c23);
        if (wait_for_service_state(false, timeout_secs)) return;
    }

    systemctl_stop();
    if (wait_for_service_state(false, timeout_secs)) return;

    fprintf(stderr, "zclassic23 did not stop cleanly; forcing SIGKILL\n");
    force_kill_service();
}

static bool fetch_status(struct rpc_target *legacy,
                         struct rpc_target *c23,
                         struct node_status *status)
{
    char legacy_body[SMALL_BUF];
    char chain_body[SMALL_BUF];
    char health_body[SMALL_BUF];
    char sync_body[SMALL_BUF];

    memset(status, 0, sizeof(*status));
    status->blocks = -1;
    status->headers = -1;
    status->legacy_tip = -1;
    status->rpc_ok = false;
    status->service_active = service_is_active();
    snprintf(status->sync_state, sizeof(status->sync_state), "unknown");
    snprintf(status->degraded_reason, sizeof(status->degraded_reason), "unknown");

    if (!rpc_call_json(c23, "getblockchaininfo", "[]", chain_body, sizeof(chain_body))) {
        snprintf(status->sync_state, sizeof(status->sync_state), "rpc_unresponsive");
        snprintf(status->degraded_reason, sizeof(status->degraded_reason), "rpc_unresponsive");
        return false;
    }
    status->rpc_ok = true;

    if (!rpc_call_json(legacy, "getinfo", "[]", legacy_body, sizeof(legacy_body))) return false;
    if (!rpc_call_json(c23, "healthcheck", "[]", health_body, sizeof(health_body))) return false;
    if (!rpc_call_json(c23, "syncstate", "[]", sync_body, sizeof(sync_body))) return false;

    (void)json_get_int(legacy_body, "blocks", &status->legacy_tip);
    (void)json_get_int(chain_body, "blocks", &status->blocks);
    (void)json_get_int(chain_body, "headers", &status->headers);
    (void)json_get_bool(health_body, "healthy", &status->healthy);
    (void)json_get_string(sync_body, "state", status->sync_state, sizeof(status->sync_state));
    (void)json_get_string(health_body, "degraded_reason",
                          status->degraded_reason, sizeof(status->degraded_reason));
    return true;
}

static void print_status_line(const struct node_status *status)
{
    int lag = 0;
    if (status->legacy_tip > 0 && status->blocks >= 0) {
        lag = status->legacy_tip - status->blocks;
        if (lag < 0) lag = 0;
    }
    printf("%ld service=%s rpc=%s chain=%d headers=%d legacy=%d lag=%d state=%s healthy=%s degraded=%s\n",
           (long)now_secs(),
           status->service_active ? "active" : "inactive",
           status->rpc_ok ? "ok" : "down",
           status->blocks,
           status->headers,
           status->legacy_tip,
           lag,
           status->sync_state,
           status->healthy ? "true" : "false",
           status->degraded_reason[0] ? status->degraded_reason : "none");
}

static bool status_is_good(const struct node_status *status)
{
    return status->legacy_tip >= 0 &&
           status->blocks >= status->legacy_tip &&
           status->headers >= status->legacy_tip &&
           strcmp(status->sync_state, "at_tip") == 0 &&
           status->healthy;
}

static int cmd_status(struct rpc_target *legacy, struct rpc_target *c23)
{
    struct node_status status;
    if (!fetch_status(legacy, c23, &status)) {
        print_status_line(&status);
        return 1;
    }
    print_status_line(&status);
    return 0;
}

static int cmd_stop(struct rpc_target *c23)
{
    stop_service_gracefully(c23, 30);
    printf("zclassic23 stopped\n");
    return 0;
}

static int cmd_start(struct rpc_target *c23)
{
    systemctl_start();
    if (!rpc_ready(c23, 90)) die("zclassic23 RPC did not become ready");
    printf("zclassic23 started and RPC is ready\n");
    return 0;
}

static int cmd_restart(struct rpc_target *c23)
{
    stop_service_gracefully(c23, 30);
    systemctl_start();
    if (!rpc_ready(c23, 90)) die("zclassic23 RPC did not become ready");
    printf("zclassic23 restarted and RPC is ready\n");
    return 0;
}

static int cmd_verify_follow(struct rpc_target *legacy,
                             struct rpc_target *c23,
                             const struct verify_opts *opts)
{
    int stable = 0;
    int64_t deadline;
    struct node_status status;

    if (opts->restart_first) {
        stop_service_gracefully(c23, 30);
        systemctl_start();
    }
    if (!rpc_ready(c23, 90)) die("zclassic23 RPC did not become ready");

    deadline = now_secs() + opts->timeout_secs;
    while (now_secs() < deadline) {
        if (!fetch_status(legacy, c23, &status)) {
            print_status_line(&status);
            sleep_ms(opts->poll_secs * 1000);
            continue;
        }
        print_status_line(&status);
        if (status_is_good(&status)) {
            stable++;
            if (stable >= opts->stable_samples) {
                printf("PASS: zclassic23 reached legacy tip and stayed healthy for %d samples.\n",
                       stable);
                return 0;
            }
        } else {
            stable = 0;
        }
        sleep_ms(opts->poll_secs * 1000);
    }

    fprintf(stderr, "FAIL: zclassic23 did not prove catch-up to legacy tip within %d seconds.\n",
            opts->timeout_secs);
    return 1;
}

static int cmd_launch(int argc, char **argv)
{
    if (argc < 3 || !argv[2] || !argv[2][0]) {
        fprintf(stderr, "zcl-nodectl launch: usage: zcl-nodectl launch "
                        "<node-binary> [node args...]\n");
        return 64;
    }
    const char *slots = getenv("ZCL_BINARY_SLOTS_DIR");
    char default_slots[OS_BINARY_SLOTS_PATH_MAX];
    if (!slots || !slots[0]) {
        const char *home = getenv("HOME");
        int slots_len = home && home[0]
            ? snprintf(default_slots, sizeof(default_slots),
                       "%s/.local/lib/zclassic23-slots", home)
            : -1;
        if (slots_len < 0 || (size_t)slots_len >= sizeof(default_slots)) {
            fprintf(stderr, "zcl-nodectl launch: HOME is missing or too long\n");
            return 64;
        }
        slots = default_slots;
    }
    uint32_t threshold = 3;
    const char *threshold_text = getenv("ZCL_BINARY_FALLBACK_THRESHOLD");
    if (threshold_text &&
        !os_binary_slots_parse_threshold(threshold_text, &threshold)) {
        fprintf(stderr, "zcl-nodectl launch: invalid "
                        "ZCL_BINARY_FALLBACK_THRESHOLD\n");
        return 64;
    }

    char error[OS_BINARY_SLOTS_ERROR_MAX];
    if (!os_binary_slots_ensure_directory(slots, error, sizeof(error))) {
        fprintf(stderr, "zcl-nodectl launch: %s\n",
                error[0] ? error : "could not create slots directory");
        return 1;
    }
    struct os_binary_slots_launch launch;
    if (!os_binary_slots_prepare_launch(slots, argv[2], threshold, &launch)) {
        fprintf(stderr, "zcl-nodectl launch: REFUSE: %s\n",
                launch.error[0] ? launch.error : "launch decision failed");
        return 1;
    }

    if (setenv("ZCL_BINARY_SLOTS_DIR", slots, 1) != 0) {
        fprintf(stderr, "zcl-nodectl launch: setenv slots failed: %s\n",
                strerror(errno));
        os_binary_slots_close_launch(&launch);
        return 1;
    }
    if (launch.fallback_active) {
        if (setenv("ZCL_BINARY_FALLBACK_ACTIVE", "1", 1) != 0 ||
            unsetenv("ZCL_BINARY_CURRENT") != 0) {
            fprintf(stderr, "zcl-nodectl launch: fallback environment failed: %s\n",
                    strerror(errno));
            os_binary_slots_close_launch(&launch);
            return 1;
        }
    } else {
        if (unsetenv("ZCL_BINARY_FALLBACK_ACTIVE") != 0 ||
            setenv("ZCL_BINARY_CURRENT", argv[2], 1) != 0) {
            fprintf(stderr, "zcl-nodectl launch: current environment failed: %s\n",
                    strerror(errno));
            os_binary_slots_close_launch(&launch);
            return 1;
        }
    }

    fprintf(stderr,
            "zcl-nodectl launch: target=%s fallback=%d streak_before=%u "
            "streak_after=%u written=%d corrupt=%d\n",
            launch.target_path, launch.fallback_active,
            launch.streak_before, launch.streak_after,
            launch.streak_written, launch.streak_corrupt);

    const char *test_echo = getenv("ZCL_LAUNCH_TEST_ECHO");
    if (test_echo && strcmp(test_echo, "1") == 0) {
        printf("EXEC %s\n", launch.target_path);
        printf("FALLBACK_ACTIVE=%s\n",
               launch.fallback_active ? "1" : "");
        printf("CURRENT=%s\n", launch.fallback_active ? "" : argv[2]);
        if (launch.streak_written)
            printf("STREAK_WRITTEN=%u\n", launch.streak_after);
        else
            printf("STREAK_WRITTEN=\n");
        printf("STREAK_CORRUPT=%s\n", launch.streak_corrupt ? "1" : "0");
        for (int i = 3; i < argc; i++)
            printf("ARGV[%d]=%s\n", i - 3, argv[i]);
        os_binary_slots_close_launch(&launch);
        return 0;
    }

    argv[2] = launch.target_path;
#if defined(__APPLE__)
    /* No fexecve(2) on this host and process_compat refuses the
     * F_GETPATH indirection by contract. The slot directory is 0700 and the
     * authority decision already happened against executable_fd; re-verify
     * that the named path is still that exact inode immediately before the
     * exec so a last-instant swap cannot change what runs. The residual
     * window is the same class the hot-swap dlopen identity check accepts. */
    struct stat fd_st;
    if (fstat(launch.executable_fd, &fd_st) == 0) {
        struct stat path_st;
        if (stat(launch.target_path, &path_st) == 0 &&
            path_st.st_dev == fd_st.st_dev &&
            path_st.st_ino == fd_st.st_ino) {
            execve(launch.target_path, &argv[2], environ);
        } else {
            errno = ESTALE;
        }
    }
    int saved_errno = errno;
#else
    platform_execve_fd(launch.executable_fd, &argv[2], environ);
    int saved_errno = errno;
#endif
    fprintf(stderr, "zcl-nodectl launch: execute pinned %s failed: %s\n",
            launch.target_path, strerror(saved_errno));
    os_binary_slots_close_launch(&launch);
    return saved_errno == ENOENT ? 127 : 126;
}

static void usage(void)
{
    puts("Usage: zcl-nodectl <status|stop|start|restart|verify-follow|launch> [options]");
    puts("");
    puts("Options for verify-follow:");
    puts("  --restart          stop/start zclassic23 before polling");
    puts("  --timeout N        total wait budget in seconds (default 900)");
    puts("  --poll N           poll interval in seconds (default 10)");
    puts("  --stable N         required consecutive healthy samples (default 3)");
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "launch") == 0)
        return cmd_launch(argc, argv);

    static char legacy_dd[512], legacy_conf[512], legacy_cookie[512];
    static char c23_dd[512], c23_conf[512], c23_cookie[512];
    zcl_nodectl_build_default_paths(
        getenv("HOME"),
        legacy_dd, sizeof(legacy_dd),
        legacy_conf, sizeof(legacy_conf),
        legacy_cookie, sizeof(legacy_cookie),
        c23_dd, sizeof(c23_dd),
        c23_conf, sizeof(c23_conf),
        c23_cookie, sizeof(c23_cookie));

    struct rpc_target legacy = {
        .name = "legacy",
        .datadir = env_or_default("LEGACY_DATADIR", legacy_dd),
        .conf_path = env_or_default("LEGACY_CONF", legacy_conf),
        .cookie_path = env_or_default("LEGACY_COOKIE", legacy_cookie),
        .port = atoi(env_or_default("LEGACY_RPC_PORT", "8232"))
    };
    struct rpc_target c23 = {
        .name = "zclassic23",
        .datadir = env_or_default("C23_DATADIR", c23_dd),
        .conf_path = env_or_default("C23_CONF", c23_conf),
        .cookie_path = env_or_default("C23_COOKIE", c23_cookie),
        .port = atoi(env_or_default("C23_RPC_PORT", "18232"))
    };
    struct verify_opts opts = {
        .restart_first = false,
        .timeout_secs = 900,
        .poll_secs = 10,
        .stable_samples = 3
    };
    int i;

    if (argc < 2) {
        usage();
        return 1;
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--restart") == 0) {
            opts.restart_first = true;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            opts.timeout_secs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--poll") == 0 && i + 1 < argc) {
            opts.poll_secs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--stable") == 0 && i + 1 < argc) {
            opts.stable_samples = atoi(argv[++i]);
        } else {
            usage();
            return 1;
        }
    }

    if (strcmp(argv[1], "status") == 0) return cmd_status(&legacy, &c23);
    if (strcmp(argv[1], "stop") == 0) return cmd_stop(&c23);
    if (strcmp(argv[1], "start") == 0) return cmd_start(&c23);
    if (strcmp(argv[1], "restart") == 0) return cmd_restart(&c23);
    if (strcmp(argv[1], "verify-follow") == 0) return cmd_verify_follow(&legacy, &c23, &opts);

    usage();
    return 1;
}
