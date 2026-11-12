/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Service pid and active-state discovery. Execs systemctl,
 *          launchctl, plutil, and id from PATH. */

#define _POSIX_C_SOURCE 200809L

#include "service_args.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)
static int svc_digits(const char *text)
{
    if (!text || text[0] < '1' || text[0] > '9')
        return 0;
    for (const char *p = text + 1; *p; p++)
        if (*p < '0' || *p > '9')
            return 0;
    return 1;
}

static void svc_read(int fd, char *out, size_t cap)
{
    size_t used = 0;
    char buf[64];
    if (cap == 0)
        return;
    while (used + 1 < cap) {
        ssize_t step = read(fd, buf, sizeof buf);
        size_t take;
        if (step < 0 && errno == EINTR)
            continue;
        if (step <= 0)
            break;
        take = (size_t)step;
        if (take > cap - 1 - used)
            take = cap - 1 - used;
        memcpy(out + used, buf, take);
        used += take;
    }
    out[used] = '\0';
}

static int svc_reap(pid_t pid)
{
    for (;;) {
        int status = 0;
        if (waitpid(pid, &status, 0) == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        if (errno != EINTR)
            return 1;
    }
}

static int svc_exec(char *const argv[], char *out, size_t cap, int *status)
{
    int pipefd[2];
    pid_t pid;
    int devnull;
    if (cap == 0 || pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            (void)dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    svc_read(pipefd[0], out, cap);
    close(pipefd[0]);
    *status = svc_reap(pid);
    return 0;
}

static void svc_chomp(char *text)
{
    size_t n = strlen(text);
    while (n > 0 && isspace((unsigned char)text[n - 1]))
        text[--n] = '\0';
}

static int svc_prop(const char *unit, const char *prop, char *out, size_t cap)
{
    char *argv[] = {"systemctl", "--user", "show", (char *)unit, "-p",
                    (char *)prop, "--value", NULL};
    int status = 1;
    if (svc_exec(argv, out, cap, &status) != 0)
        return -1;
    svc_chomp(out);
    return status;
}

static int svc_copy(char *out, size_t cap, const char *text)
{
    if (strlen(text) + 1 > cap)
        return -1;
    memcpy(out, text, strlen(text) + 1);
    return 0;
}

static const char *svc_skip(const char *text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    return text;
}

static int svc_field(const char *body, const char *key, char *out, size_t cap)
{
    const char *line = body;
    size_t key_len = strlen(key);
    while (*line) {
        const char *start = svc_skip(line);
        const char *end = strchr(start, '\n');
        const char *value;
        size_t n = 0;
        if (!end)
            end = start + strlen(start);
        if (strncmp(start, key, key_len) == 0 &&
            strncmp(start + key_len, " = ", 3) == 0) {
            value = start + key_len + 3;
            while (value + n < end && value[n] != ' ' && value[n] != '\t' &&
                   value[n] != '\r')
                n++;
            if (n == 0 || n + 1 > cap)
                return -1;
            memcpy(out, value, n);
            out[n] = '\0';
            return 1;
        }
        if (*end == '\0')
            break;
        line = end + 1;
    }
    return 0;
}

static int svc_label(const char *plist, char *out, size_t cap)
{
    char *argv[] = {"plutil", "-extract", "Label", "raw", "-o", "-",
                    (char *)plist, NULL};
    int status = 1;
    if (svc_exec(argv, out, cap, &status) != 0 || status != 0)
        return -1;
    svc_chomp(out);
    return out[0] ? 0 : -1;
}

static int svc_uid(char *out, size_t cap)
{
    char *argv[] = {"id", "-u", NULL};
    int status = 1;
    if (svc_exec(argv, out, cap, &status) != 0 || status != 0)
        return -1;
    svc_chomp(out);
    return out[0] ? 0 : -1;
}

static int svc_print(const char *domain, const char *uid, const char *label,
                     char *out, size_t cap)
{
    char target[512];
    char *argv[] = {"launchctl", "print", target, NULL};
    int status = 1;
    int n = strcmp(domain, "gui") == 0
                ? snprintf(target, sizeof target, "gui/%s/%s", uid, label)
                : snprintf(target, sizeof target, "user/%s/%s", uid, label);
    if (n < 0 || n >= (int)sizeof target)
        return -1;
    if (svc_exec(argv, out, cap, &status) != 0 || status != 0) {
        out[0] = '\0';
        return 0;
    }
    return out[0] ? 1 : 0;
}

static int svc_launchd(const char *plist, char *body, size_t cap)
{
    char label[256];
    char uid[64];
    char gui[4096];
    char user[4096];
    int have_gui;
    int have_user;
    if (svc_label(plist, label, sizeof label) != 0 ||
        svc_uid(uid, sizeof uid) != 0)
        return -1;
    have_gui = svc_print("gui", uid, label, gui, sizeof gui);
    have_user = svc_print("user", uid, label, user, sizeof user);
    if (have_gui < 0 || have_user < 0)
        return -1;
    if (have_gui && have_user) {
        fprintf(stderr,
                "z23-service: ambiguous launchd job in GUI and Background domains\n");
        return -1;
    }
    if (have_gui)
        return svc_copy(body, cap, gui);
    if (have_user)
        return svc_copy(body, cap, user);
    return -1;
}

#endif

int zcl_service_query_pid(const char *unit, const char *plist, char *out,
                          size_t cap)
{
#if defined(_WIN32)
    (void)unit;
    (void)plist;
    if (out && cap)
        out[0] = '\0';
    return 1;
#else
    char prop[256];
    char body[4096];
    if (!unit || !plist || !out || cap == 0)
        return 1;
    out[0] = '\0';
    if (svc_prop(unit, "MainPID", prop, sizeof prop) == 0 && svc_digits(prop))
        return svc_copy(out, cap, prop) == 0 ? 0 : 1;
    if (svc_launchd(plist, body, sizeof body) != 0)
        return 1;
    if (svc_field(body, "pid", out, cap) != 1 || !svc_digits(out))
        return 1;
    return 0;
#endif
}

int zcl_service_query_active(const char *unit, const char *plist, char *out,
                             size_t cap)
{
#if defined(_WIN32)
    (void)unit;
    (void)plist;
    if (out && cap)
        out[0] = '\0';
    return 1;
#else
    char prop[256];
    char body[4096];
    char state[64];
    if (!unit || !plist || !out || cap == 0)
        return 1;
    out[0] = '\0';
    if (svc_prop(unit, "ActiveState", prop, sizeof prop) == 0 && prop[0])
        return svc_copy(out, cap, prop) == 0 ? 0 : 1;
    if (svc_launchd(plist, body, sizeof body) != 0)
        return 1;
    if (svc_field(body, "state", state, sizeof state) != 1)
        return 1;
    if (strcmp(state, "running") == 0)
        return svc_copy(out, cap, "active") == 0 ? 0 : 1;
    return svc_copy(out, cap, state) == 0 ? 0 : 1;
#endif
}

#if !defined(_WIN32)
static int svc_rm(const char *path)
{
    struct stat st;
    DIR *dir;
    struct dirent *ent;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0 ? 0 : -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        char child[512];
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof child, "%s/%s", path, ent->d_name) >=
            (int)sizeof child) {
            closedir(dir);
            return -1;
        }
        if (svc_rm(child) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return rmdir(path) == 0 ? 0 : -1;
}
#endif

static int svc_write(const char *path, const char *text);

static int svc_write_stubs(const char *dir)
{
    char path[512];
    if (snprintf(path, sizeof path, "%s/systemctl", dir) >= (int)sizeof path ||
        svc_write(path, "#!/bin/sh\nexit 1\n") != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/plutil", dir) >= (int)sizeof path ||
        svc_write(path, "#!/bin/sh\nprintf 'org.z23.fixture\\n'\nexit 0\n") != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/launchctl", dir) >= (int)sizeof path)
        return -1;
    return svc_write(path,
                     "#!/bin/sh\n"
                     "[ \"$1\" = print ] || exit 2\n"
                     "case \"$ZCL_FIXTURE_DOMAIN:$2\" in\n"
                     "  gui:gui/*|both:gui/*) printf 'state = running\\npid = 123\\n' ;;\n"
                     "  background:user/*|both:user/*) printf 'state = running\\npid = 456\\n' ;;\n"
                     "  *) exit 1 ;;\n"
                     "esac\n");
}

static int svc_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (!file)
        return -1;
    if (fputs(text, file) < 0 || fclose(file) != 0)
        return -1;
    return chmod(path, 0755);
}

static int svc_expect(const char *domain, const char *want_pid, int want_ok)
{
    char pid[64];
    char state[64];
    int pid_rc;
    int state_rc;
    if (setenv("ZCL_FIXTURE_DOMAIN", domain, 1) != 0)
        return -1;
    pid_rc = zcl_service_query_pid("fixture", "fixture.plist", pid, sizeof pid);
    state_rc = zcl_service_query_active("fixture", "fixture.plist", state,
                                        sizeof state);
    if (!want_ok)
        return (pid_rc != 0 && state_rc != 0) ? 0 : -1;
    if (pid_rc != 0 || state_rc != 0 || strcmp(pid, want_pid) != 0 ||
        strcmp(state, "active") != 0)
        return -1;
    return 0;
}

int zcl_service_args_selftest(void)
{
#if defined(_WIN32)
    return 0;
#else
    char dir[512];
    char saved[4096];
    char path_env[4600];
    const char *tmp = getenv("TMPDIR");
    const char *old = getenv("PATH");
    int rc = 0;
    if (!tmp || !tmp[0])
        tmp = "/tmp";
    if (!old)
        old = "/usr/bin:/bin";
    if (snprintf(saved, sizeof saved, "%s", old) >= (int)sizeof saved ||
        snprintf(dir, sizeof dir, "%s/zcl-service-args.XXXXXX", tmp) >=
            (int)sizeof dir ||
        mkdtemp(dir) == NULL)
        return 1;
    if (snprintf(path_env, sizeof path_env, "%s:%s", dir, old) >=
        (int)sizeof path_env)
        rc = 1;
    else if (svc_write_stubs(dir) != 0 || setenv("PATH", path_env, 1) != 0)
        rc = 1;
    else if (svc_expect("gui", "123", 1) != 0 ||
             svc_expect("background", "456", 1) != 0 ||
             svc_expect("both", NULL, 0) != 0 ||
             svc_expect("missing", NULL, 0) != 0)
        rc = 1;
    else
        printf("service-args selftest: PASS gui=true background=true "
               "ambiguity_refused=true absent_refused=true\n");
    (void)setenv("PATH", saved, 1);
    unsetenv("ZCL_FIXTURE_DOMAIN");
    (void)svc_rm(dir);
    return rc;
#endif
}
