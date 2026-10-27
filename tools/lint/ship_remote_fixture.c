/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Isolated process and filesystem adapter for the actual remote ship programs. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

struct fixture {
    char root[PATH_MAX], unit[64], binding[32], source[80];
    char once[32], always[32], manifest[80];
    char home[PATH_MAX], pidfile[PATH_MAX], old[PATH_MAX], newer[PATH_MAX];
    char release[PATH_MAX], incoming[PATH_MAX], dropin[PATH_MAX];
};

[[noreturn]] static void fail(const char *what)
{
    fprintf(stderr, "ship remote fixture: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void path(char *out, size_t cap, const char *left, const char *right)
{
    int n = snprintf(out, cap, "%s/%s", left, right);
    if (n < 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; fail("path"); }
}

static void append(char *out, size_t cap, const char *left, const char *right)
{
    size_t a = strlen(left), b = strlen(right);
    if (a >= cap || b >= cap - a) { errno = ENAMETOOLONG; fail("suffix"); }
    memcpy(out, left, a);
    memcpy(out + a, right, b + 1);
}

static void write_text(const char *name, const char *text)
{
    FILE *f = fopen(name, "w");
    if (!f) fail(name);
    bool ok = fputs(text, f) >= 0;
    if (fclose(f) != 0 || !ok) fail(name);
}

static void read_line(FILE *f, char *out, size_t cap)
{
    if (!fgets(out, (int)cap, f)) fail("state field");
    char *end = strchr(out, '\n');
    if (!end) { errno = EINVAL; fail("unterminated state field"); }
    *end = '\0';
}

static void owned_root(const char *root)
{
    char resolved[PATH_MAX], marker[PATH_MAX], recorded[PATH_MAX];
    struct stat st;
    if (!realpath(root, resolved) || strcmp(root, resolved) != 0 ||
        lstat(root, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077) != 0)
        fail("fixture root ownership");
    const char *leaf = strrchr(root, '/');
    if (!leaf || strncmp(leaf + 1, "zcl-ship-remote-test.", 21) != 0) {
        errno = EINVAL; fail("fixture root name");
    }
    path(marker, sizeof(marker), root, ".fixture-owner");
    FILE *f = fopen(marker, "r");
    if (!f) fail(marker);
    read_line(f, recorded, sizeof(recorded));
    if (fclose(f) != 0 || strcmp(recorded, root) != 0) fail("fixture marker");
}

static void init_root(const char *root)
{
    char resolved[PATH_MAX], marker[PATH_MAX], text[PATH_MAX + 2];
    struct stat st;
    if (!realpath(root, resolved) || strcmp(root, resolved) != 0 ||
        lstat(root, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077) != 0)
        fail("new fixture root");
    const char *leaf = strrchr(root, '/');
    if (!leaf || strncmp(leaf + 1, "zcl-ship-remote-test.", 21) != 0) {
        errno = EINVAL; fail("new fixture root name");
    }
    path(marker, sizeof(marker), root, ".fixture-owner");
    (void)snprintf(text, sizeof(text), "%s\n", root);
    write_text(marker, text);
}

static void fixture_paths(struct fixture *s)
{
    char directory[PATH_MAX], suffix[160];
    path(s->home, sizeof(s->home), s->root, "home");
    path(s->pidfile, sizeof(s->pidfile), s->root, "service.pid");
    path(s->old, sizeof(s->old), s->root, "old");
    path(s->newer, sizeof(s->newer), s->root, "new");
    (void)snprintf(suffix, sizeof(suffix), ".local/lib/z23/releases/%s", s->manifest);
    path(s->release, sizeof(s->release), s->home, suffix);
    append(s->incoming, sizeof(s->incoming), s->release, ".incoming.test-run");
    (void)snprintf(suffix, sizeof(suffix), ".config/systemd/user/%s.d", s->unit);
    path(directory, sizeof(directory), s->home, suffix);
    path(s->dropin, sizeof(s->dropin), directory, "zzzzz-z23-ship-release.conf");
}

static void load_fixture(const char *name, struct fixture *s)
{
    FILE *f = fopen(name, "r");
    if (!f) fail(name);
    read_line(f, s->root, sizeof(s->root));
    read_line(f, s->unit, sizeof(s->unit));
    read_line(f, s->binding, sizeof(s->binding));
    read_line(f, s->source, sizeof(s->source));
    read_line(f, s->once, sizeof(s->once));
    read_line(f, s->always, sizeof(s->always));
    read_line(f, s->manifest, sizeof(s->manifest));
    if (fgetc(f) != EOF || fclose(f) != 0) fail("extra state fields");
    owned_root(s->root);
    if (strcmp(s->unit, "z23-node.service") && strcmp(s->unit, "zclassic23.service")) {
        errno = EINVAL; fail("fixture unit");
    }
    if (strlen(s->manifest) != 64 ||
        strspn(s->manifest, "0123456789abcdef") != 64) {
        errno = EINVAL; fail("manifest identity");
    }
    fixture_paths(s);
}

static void mkdirs(const char *name)
{
    char buf[PATH_MAX];
    if (strlen(name) >= sizeof(buf)) { errno = ENAMETOOLONG; fail("mkdir"); }
    strcpy(buf, name);
    for (char *p = buf + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) fail(buf);
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) fail(buf);
}

static void remove_tree(const char *name)
{
    struct stat st;
    if (lstat(name, &st) != 0) {
        if (errno == ENOENT) return;
        fail(name);
    }
    if (!S_ISDIR(st.st_mode)) {
        if (unlink(name) != 0) fail(name);
        return;
    }
    if (chmod(name, 0700) != 0) fail(name);
    DIR *d = opendir(name);
    if (!d) fail(name);
    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[PATH_MAX];
        path(child, sizeof(child), name, entry->d_name);
        remove_tree(child);
    }
    if (closedir(d) != 0 || rmdir(name) != 0) fail(name);
}

static pid_t recorded_pid(const char *name)
{
    FILE *f = fopen(name, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        fail(name);
    }
    long value = 0;
    int fields = fscanf(f, "%ld", &value);
    if (fclose(f) != 0) fail(name);
    if (fields == EOF) return 0;
    if (fields != 1 || value <= 1 || value > INT_MAX) {
        errno = EINVAL; fail("fixture PID");
    }
    return (pid_t)value;
}

static int control_socket(const char *root, bool server)
{
    owned_root(root);
    if (chdir(root) != 0) fail("fixture control directory");
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) fail("fixture socket");
    struct sockaddr_un address = { .sun_family = AF_UNIX };
#if defined(__APPLE__)
    address.sun_len = sizeof(address);
#endif
    strcpy(address.sun_path, "c");
    if (server) {
        if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(fd, 1) != 0) fail("fixture listen");
    } else if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        if (close(fd) != 0) fail("fixture connect close");
        if (saved == ENOENT || saved == ECONNREFUSED) return -1;
        errno = saved; fail("fixture connect");
    }
    return fd;
}

static void stop_fixture(const char *root)
{
    int fd = control_socket(root, false);
    if (fd >= 0) {
        if (write(fd, "S", 1) != 1) fail("fixture stop request");
        struct pollfd event = { .fd = fd, .events = POLLIN };
        int ready = poll(&event, 1, 10000);
        if (ready == 0) { errno = ETIMEDOUT; fail("fixture stop deadline"); }
        if (ready < 0) fail("fixture stop poll");
        char byte;
        if (read(fd, &byte, 1) != 0) { errno = EPROTO; fail("fixture stop EOF"); }
        if (close(fd) != 0) fail("fixture stop close");
    }
    if (unlink("c") != 0 && errno != ENOENT) fail("fixture socket removal");
}

static bool owned_executable(const char *root, const char *executable)
{
    char old[PATH_MAX], newer[PATH_MAX], releases[PATH_MAX];
    path(old, sizeof(old), root, "old");
    path(newer, sizeof(newer), root, "new");
    if (!strcmp(executable, old) || !strcmp(executable, newer)) return true;
    path(releases, sizeof(releases), root, "home/.local/lib/z23/releases");
    size_t n = strlen(releases);
    if (strncmp(executable, releases, n) || executable[n] != '/') return false;
    const char *identity = executable + n + 1;
    return strlen(identity) == 68 && strspn(identity, "0123456789abcdef") == 64 &&
           !strcmp(identity + 64, "/z23");
}

/* An unreaped direct child cannot have its PID reused before waitpid. */
static void settle_child(pid_t child)
{
    int status;
    pid_t observed;
    do { observed = waitpid(child, &status, WNOHANG); } while (observed < 0 && errno == EINTR);
    if (observed == child) return;
    if (observed < 0) fail("fixture child ownership");
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) fail("fixture child stop");
    do { observed = waitpid(child, &status, 0); } while (observed < 0 && errno == EINTR);
    if (observed != child) fail("fixture child reap");
}

static void node_control(void)
{
    if (write(4, "R", 1) != 1 || close(4) != 0) _exit(2);
    int client;
    do { client = accept(3, NULL, NULL); } while (client < 0 && errno == EINTR);
    char command;
    if (client < 0 || read(client, &command, 1) != 1 || command != 'S') _exit(2);
    /* Keep the accepted endpoint open until exit, so the stopper observes EOF. */
    _exit(0);
}

static void copy_file(const char *from, const char *to, mode_t mode)
{
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    if (!in || !out) fail("fixture copy");
    char buffer[16384];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), in)) != 0)
        if (fwrite(buffer, 1, n, out) != n) fail("fixture copy write");
    if (ferror(in)) fail("fixture copy read");
    if (fclose(in) != 0 || fclose(out) != 0 || chmod(to, mode) != 0)
        fail("fixture copy close");
}

static void stage(struct fixture *s)
{
    static const char *const files[] = { "z23", "z23-package-verify",
        "z23-package-verify-dev", "zclassic23-package-verify",
        "zclassic23-package-verify-dev" };
    remove_tree(s->release);
    remove_tree(s->incoming);
    mkdirs(s->incoming);
    char to[PATH_MAX], from[PATH_MAX];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        path(to, sizeof(to), s->incoming, files[i]);
        copy_file(s->newer, to, 0755);
    }
    path(from, sizeof(from), s->root, "MANIFEST.sha256");
    path(to, sizeof(to), s->incoming, "MANIFEST.sha256");
    copy_file(from, to, 0644);
}

static void child_channels(int listener, int ready, int reader)
{
    int channel_copy = fcntl(listener, F_DUPFD, 10);
    int ready_copy = fcntl(ready, F_DUPFD, 10);
    if (channel_copy < 0 || ready_copy < 0) _exit(2);
    close(reader);
    if (dup2(channel_copy, 3) < 0 || dup2(ready_copy, 4) < 0 ||
        fcntl(3, F_SETFD, 0) != 0 || fcntl(4, F_SETFD, 0) != 0) _exit(2);
    close(channel_copy); close(ready_copy);
    if (listener != 3 && listener != 4) close(listener);
    if (ready != 3 && ready != 4) close(ready);
}

static void child_exec(struct fixture *s, const char *target, bool identity,
                       int listener, const int ready[2])
{
    child_channels(listener, ready[1], ready[0]);
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, STDOUT_FILENO) < 0 ||
        dup2(null, STDERR_FILENO) < 0) _exit(2);
    close(null);
    if (identity && (setenv("ZCL_AGENT_EXPECT_SOURCE_ID", s->source, 1) ||
        setenv("ZCL_AGENT_EXPECT_BUILD_COMMIT", "candidate-commit", 1) ||
        setenv("ZCL_AGENT_EXPECT_BUILD_SOURCE", "ship", 1))) _exit(2);
    execl(target, target, "-fixture-node", (char *)NULL);
    _exit(2);
}

static bool child_ready(int fd)
{
    struct pollfd event = { .fd = fd, .events = POLLIN };
    int ready = poll(&event, 1, 10000);
    if (ready == 0) { errno = ETIMEDOUT; return false; }
    if (ready < 0) return false;
    char byte;
    if (read(fd, &byte, 1) == 1 && byte == 'R') return true;
    errno = EPROTO;
    return false;
}

static void publish_child(const char *pidfile, pid_t child)
{
    FILE *f = fopen(pidfile, "w");
    bool ok = f && fprintf(f, "%ld\n", (long)child) > 0;
    if (f && fclose(f) != 0) ok = false;
    if (ok) return;
    int saved = errno;
    settle_child(child);
    if (unlink("c") != 0 && errno != ENOENT) fail("failed fixture socket");
    errno = saved; fail("fixture PID publication");
}

static void spawn_node(struct fixture *s, const char *target, bool identity)
{
    char resolved[PATH_MAX];
    if (!realpath(target, resolved) || !owned_executable(s->root, resolved)) {
        errno = EPERM; fail("refuse foreign fixture executable");
    }
    int listener = control_socket(s->root, true), ready[2];
    if (pipe(ready) != 0) fail("fixture ready pipe");
    if (fcntl(ready[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(ready[1], F_SETFD, FD_CLOEXEC) != 0) fail("fixture pipe flags");
    pid_t child = fork();
    if (child < 0) fail("fixture fork");
    if (child == 0) child_exec(s, target, identity, listener, ready);
    close(ready[1]); close(listener);
    bool started = child_ready(ready[0]);
    int saved = errno;
    if (close(ready[0]) != 0) {
        settle_child(child);
        if (unlink("c") != 0 && errno != ENOENT) fail("failed fixture socket");
        fail("fixture ready close");
    }
    if (!started) {
        settle_child(child);
        if (unlink("c") != 0 && errno != ENOENT) fail("failed fixture socket");
        errno = saved; fail("fixture post-exec readiness");
    }
    publish_child(s->pidfile, child);
}

static void reset(struct fixture *s)
{
    char name[PATH_MAX];
    stop_fixture(s->root);
    write_text(s->pidfile, "");
    path(name, sizeof(name), s->root, "fail.marker");
    if (unlink(name) != 0 && errno != ENOENT) fail(name);
    const char *const suffix[] = { ".ship.rollback.test-run", ".ship.absent.test-run" };
    for (size_t i = 0; i < 2; ++i) {
        append(name, sizeof(name), s->dropin, suffix[i]);
        if (unlink(name) != 0 && errno != ENOENT) fail(name);
    }
    path(name, sizeof(name), s->home, ".cache/z23/ship-activation.lock");
    if (rmdir(name) != 0 && errno != ENOENT) fail(name);
    write_text(s->dropin, "prior ship selection\n");
    stage(s);
    spawn_node(s, s->old, false);
}

static bool loaded(const struct fixture *s, const char *unit)
{
    return !strcmp(s->binding, "both") ||
        (!strcmp(unit, s->unit) && strcmp(s->binding, "missing"));
}

static int conf_filter(const struct dirent *entry)
{
    size_t n = strlen(entry->d_name);
    return n > 5 && !strcmp(entry->d_name + n - 5, ".conf");
}

static void selected_exec(const struct fixture *s, char *selected, bool list)
{
    char directory[PATH_MAX], suffix[120], name[PATH_MAX], line[PATH_MAX + 80];
    (void)snprintf(suffix, sizeof(suffix), ".config/systemd/user/%s.d", s->unit);
    path(directory, sizeof(directory), s->home, suffix);
    strcpy(selected, s->old);
    struct dirent **entries = NULL;
    int count = scandir(directory, &entries, conf_filter, alphasort);
    if (count < 0) fail("fixture drop-in scan");
    for (int i = 0; i < count; ++i) {
        path(name, sizeof(name), directory, entries[i]->d_name);
        FILE *f = fopen(name, "r");
        if (!f) fail(name);
        if (list) printf("%s%s", i ? " " : "", name);
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "ExecStart=\"", 11)) continue;
            char *end = strchr(line + 11, '"');
            if (!end) continue;
            *end = '\0';
            if (strlen(line + 11) >= PATH_MAX) {
                errno = ENAMETOOLONG; fail("fixture ExecStart");
            }
            strcpy(selected, line + 11);
        }
        if (ferror(f) || fclose(f) != 0) fail(name);
        free(entries[i]);
    }
    free(entries);
    if (list) putchar('\n');
}

static bool injected(struct fixture *s, const char *operation)
{
    if (!strcmp(s->always, operation)) return true;
    if (strcmp(s->once, operation)) return false;
    char marker[PATH_MAX];
    path(marker, sizeof(marker), s->root, "fail.marker");
    if (access(marker, F_OK) == 0) return false;
    write_text(marker, "");
    return true;
}

static int show(struct fixture *s, const char *unit, const char *property, bool value)
{
    if (!strcmp(property, "LoadState")) {
        puts(loaded(s, unit) ? "loaded" : "not-found");
        return 0;
    }
    if (!strcmp(property, "ActiveState") && value) {
        puts(loaded(s, unit) ? "active" : "inactive");
        return 0;
    }
    if (strcmp(unit, s->unit)) return 2;
    if (!strcmp(property, "ActiveState"))
        puts("ActiveState=active\nSubState=running\nNRestarts=0");
    else if (!strcmp(property, "ExecStart")) {
        char selected[PATH_MAX];
        selected_exec(s, selected, false);
        printf("{ path=%s ; argv[]=%s -fixture-node ; ignore_errors=no }\n", selected, selected);
    } else if (!strcmp(property, "DropInPaths")) {
        char selected[PATH_MAX];
        selected_exec(s, selected, true);
    } else {
        printf("%ld\n", (long)recorded_pid(s->pidfile));
    }
    return 0;
}

static int restart(struct fixture *s, const char *unit)
{
    if (strcmp(unit, s->unit)) return 2;
    char log[PATH_MAX], target[PATH_MAX];
    append(log, sizeof(log), s->pidfile, ".restarts");
    FILE *f = fopen(log, "a");
    if (!f || fprintf(f, "%s\n", unit) < 0 || fclose(f) != 0) fail("restart log");
    if (injected(s, "restart")) return 1;
    stop_fixture(s->root);
    selected_exec(s, target, false);
    spawn_node(s, target, true);
    return 0;
}

static int service_operation(struct fixture *s, const char *operation,
                             const char *unit, const char *property, bool value)
{
    if (!strcmp(operation, "show")) return show(s, unit, property, value);
    if (!strcmp(operation, "restart")) return restart(s, unit);
    if (!strcmp(operation, "daemon-reload")) return injected(s, "reload") ? 1 : 0;
    return 2;
}

static int systemctl(struct fixture *s, int argc, char **argv)
{
    const char *operation = argc ? argv[0] : "";
    if (!strcmp(operation, "--user")) { --argc; ++argv; }
    operation = argc ? argv[0] : "";
    const char *unit = "", *property = "";
    bool value = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "z23-node") || !strcmp(argv[i], "z23-node.service"))
            unit = "z23-node.service";
        if (!strcmp(argv[i], "zclassic23.service")) unit = "zclassic23.service";
        if (!strcmp(argv[i], "LoadState") || !strcmp(argv[i], "ActiveState") ||
            !strcmp(argv[i], "ExecStart") || !strcmp(argv[i], "DropInPaths"))
            property = argv[i];
        if (!strcmp(argv[i], "--value")) value = true;
    }
    return service_operation(s, operation, unit, property, value);
}

static void extract(const char *source, const char *begin, const char *end)
{
    FILE *f = fopen(source, "r");
    if (!f) fail(source);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    bool copying = false, complete = false;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (!copying && strstr(line, begin)) { copying = true; continue; }
        if (!copying) continue;
        size_t length = (size_t)n;
        if (length && line[length - 1] == '\n') --length;
        if (strlen(end) == length && !strncmp(line, end, length)) {
            complete = true; break;
        }
        if (fwrite(line, 1, (size_t)n, stdout) != (size_t)n) fail("extract write");
    }
    free(line);
    if (ferror(f) || fclose(f) != 0 || !complete) {
        errno = EINVAL; fail("remote program markers");
    }
}

static void cleanup(const char *root)
{
    struct stat st;
    if (lstat(root, &st) != 0) {
        if (errno == ENOENT) return;
        fail("fixture cleanup root");
    }
    owned_root(root);
    stop_fixture(root);
    remove_tree(root);
}

static int controller(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "init")) { init_root(argv[2]); return 0; }
    if (argc == 3 && !strcmp(argv[1], "cleanup")) { cleanup(argv[2]); return 0; }
    if (argc == 5 && !strcmp(argv[1], "extract")) {
        extract(argv[2], argv[3], argv[4]); return 0;
    }
    if (argc < 3) return 2;
    struct fixture s = {0};
    load_fixture(argv[2], &s);
    if (!strcmp(argv[1], "stage")) stage(&s);
    else if (!strcmp(argv[1], "reset")) reset(&s);
    else if (!strcmp(argv[1], "stop")) { stop_fixture(s.root); write_text(s.pidfile, ""); }
    else if (!strcmp(argv[1], "systemctl")) return systemctl(&s, argc - 3, argv + 3);
    else return 2;
    return 0;
}

int main(int argc, char **argv)
{
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || signal(SIGCHLD, SIG_DFL) == SIG_ERR)
        fail("fixture signal policy");
    if (argc == 2 && !strcmp(argv[1], "status")) return 0;
    if (argc == 2 && !strcmp(argv[1], "-fixture-node"))
        node_control();
    return controller(argc, argv);
}
