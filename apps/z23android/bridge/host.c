/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "host.h"
#include "http.h"
#include "pairing.h"
#include "base/cleanse.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct model_role { const char *name, *model, *mmproj, *context; };
static const struct model_role roles[ZAPP_HOST_SERVERS] = {
    {"chat", "Qwen3.5-4B-Q4_K_M.gguf", NULL, "8192"},
    {"asr", "Qwen3-ASR-0.6B-Q8_0.gguf", "mmproj-Qwen3-ASR-0.6B-Q8_0.gguf", "4096"},
    {"tts", "Qwen3-TTS-12Hz-1.7B-Base-Q8_0.gguf", "mmproj-Qwen3-TTS-12Hz-1.7B-Base-Q8_0.gguf", "4096"},
};
static void pause_ms(long ms)
{
    struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static bool path_join(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}
static pid_t spawn_server(const char *exe, const char *models, const char *dir,
                          const struct model_role *role, uint16_t port)
{
    char model[1024], mmproj[1024], log[1024], port_text[8], logname[32];
    snprintf(port_text, sizeof(port_text), "%u", port);
    snprintf(logname, sizeof(logname), "%s.log", role->name);
    if (!path_join(model, sizeof(model), models, role->model) || access(model, R_OK) ||
        (role->mmproj && (!path_join(mmproj, sizeof(mmproj), models, role->mmproj) || access(mmproj, R_OK))) ||
        !path_join(log, sizeof(log), dir, logname)) return -1;
    char *argv[] = {(char *)exe, "-m", model, "--host", "127.0.0.1", "--port", port_text,
        "-ngl", "99", "-c", (char *)role->context, "-np", "1",
        role->mmproj ? "--mmproj" : NULL, mmproj, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY | O_CLOEXEC);
        int out = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGTERM) || nul < 0 || out < 0 ||
            dup2(nul, 0) < 0 || dup2(out, 1) < 0 || dup2(out, 2) < 0) _exit(127);
        execv(exe, argv);
        _exit(127);
    }
    if (pid > 0) (void)setpgid(pid, pid);
    return pid;
}
static bool healthy(uint16_t port)
{
    struct zapp_http_request r = {.port = port, .method = "GET", .path = "/health",
        .response_cap = 4096, .timeout_ms = 2000, .alive_fd = -1};
    unsigned char *body = NULL; size_t size = 0;
    bool ok = zapp_http_exchange(&r, &body, &size);
    free(body);
    return ok;
}
static bool alive(pid_t pid)
{
    int status;
    return pid > 0 && waitpid(pid, &status, WNOHANG) == 0;
}
bool zapp_host_start(const char *exe, const char *models, const char *dir,
                     uint16_t base_port, struct zapp_host_servers *s)
{
    for (int i = 0; i < ZAPP_HOST_SERVERS; i++) s->pid[i] = -1;
    if (!exe || exe[0] != '/' || access(exe, X_OK) || !models || !dir || base_port > 65530) return false;
    for (int i = 0; i < ZAPP_HOST_SERVERS; i++) {
        s->port[i] = (uint16_t)(base_port + 1 + i);
        s->pid[i] = spawn_server(exe, models, dir, &roles[i], s->port[i]);
        if (s->pid[i] < 0) { fprintf(stderr, "Could not start the %s model; check %s.\n", roles[i].name, models); goto fail; }
    }
    for (int i = 0; i < ZAPP_HOST_SERVERS; i++) {
        int waited = 0;
        while (!healthy(s->port[i]) && waited < 600) {
            if (!alive(s->pid[i])) { fprintf(stderr, "The %s model exited; see %s/%s.log.\n", roles[i].name, dir, roles[i].name); goto fail; }
            pause_ms(500); waited++;
        }
        if (waited >= 600) { fprintf(stderr, "The %s model did not become ready.\n", roles[i].name); goto fail; }
        fprintf(stderr, "%s model ready on 127.0.0.1:%u\n", roles[i].name, s->port[i]);
    }
    return true;
fail:
    zapp_host_stop(s);
    return false;
}
void zapp_host_stop(struct zapp_host_servers *s)
{
    for (int i = 0; i < ZAPP_HOST_SERVERS; i++) {
        if (s->pid[i] <= 0) continue;
        (void)kill(-s->pid[i], SIGTERM);
        for (int t = 0; t < 50 && alive(s->pid[i]); t++) pause_ms(100);
        (void)kill(-s->pid[i], SIGKILL);
        while (waitpid(s->pid[i], NULL, 0) < 0 && errno == EINTR) {}
        s->pid[i] = -1;
    }
}
bool zapp_host_read_file(const char *path, size_t cap, unsigned char **bytes, size_t *size)
{
    *bytes = NULL; *size = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    bool ok = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
        st.st_size > 0 && (size_t)st.st_size <= cap;
    size_t n = ok ? (size_t)st.st_size : 0, used = 0;
    unsigned char *buf = ok ? malloc(n + 1) : NULL;
    ok = buf != NULL;
    while (ok && used < n) {
        ssize_t r = read(fd, buf + used, n - used);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) ok = false; else used += (size_t)r;
    }
    if (fd >= 0) close(fd);
    if (ok) { buf[n] = 0; *bytes = buf; *size = n; }
    else if (buf) { memory_cleanse(buf, n + 1); free(buf); }
    return ok;
}
static bool run_adb(const char *adb, char *const argv[], const char *input)
{
    int in[2];
    if (pipe2(in, O_CLOEXEC)) return false;
    pid_t pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nul < 0 || dup2(in[0], 0) < 0 || dup2(nul, 1) < 0 || dup2(nul, 2) < 0) _exit(127);
        execv(adb, argv);
        _exit(127);
    }
    close(in[0]);
    bool ok = pid > 0;
    for (size_t used = 0, n = input ? strlen(input) : 0; ok && used < n;) {
        ssize_t w = write(in[1], input + used, n - used);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) ok = false; else used += (size_t)w;
    }
    close(in[1]);
    int status = 0;
    while (pid > 0 && waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
bool zapp_host_route(const char *adb, const char *serial, uint16_t port)
{
    char route[16];
    snprintf(route, sizeof(route), "tcp:%u", port);
    char *reverse[] = {(char *)adb, "-s", (char *)serial, "reverse", route, route, NULL};
    return run_adb(adb, reverse, NULL);
}
bool zapp_host_offer_pairing(const char *adb, const char *serial, const char *app, uint16_t port, const char *dir)
{
    char path[1024], command[512];
    char *shell[] = {(char *)adb, "-s", (char *)serial, "shell", NULL};
    unsigned char *descriptor = NULL; size_t size = 0;
    bool ok = path_join(path, sizeof(path), dir, "codex-bridge.json") &&
        zapp_host_read_file(path, 256, &descriptor, &size) && !strchr((char *)descriptor, '\'') &&
        zapp_host_route(adb, serial, port);
    if (ok) {
        descriptor[strcspn((char *)descriptor, "\n")] = 0;
        int n = snprintf(command, sizeof(command), "am start -n %s/android.app.NativeActivity "
            "-f 0x10008000 --es org.z23.pair '%s'\nexit\n", app, (char *)descriptor);
        ok = n > 0 && (size_t)n < sizeof(command) && run_adb(adb, shell, command);
        char code[7];
        if (ok && zapp_pair_code((const char *)descriptor, code))
            fprintf(stderr, "Pairing code %s. Accept on the phone only if it shows the same code.\n", code);
    }
    memory_cleanse(command, sizeof(command));
    if (descriptor) { memory_cleanse(descriptor, size); free(descriptor); }
    return ok;
}
