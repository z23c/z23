/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "test/test_core.h"
int test_portfwd(void);
#if defined(__linux__)
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include "util/spawn.h"
[[maybe_unused]] static int portfwd_fixture_main(int argc, char **argv);
#define main portfwd_fixture_main
#include "../../../tools/zcl_portfwd.c"
#undef main

enum { PORTFWD_SIZE = 2 * BUF_SZ };
struct portfwd_fixture {
    int left[2], right[2];
    struct endpoint *a, *b;
    unsigned char *data, *received;
};

static void portfwd_init(struct portfwd_fixture *f)
{
    *f = (struct portfwd_fixture){.left = {-1, -1}, .right = {-1, -1}};
}

static void portfwd_cleanup(struct portfwd_fixture *f)
{
    if (f->a && f->b && f->a->peer && !f->a->dead) close_pair(f->a);
    else if (f->a && !f->a->peer && !f->a->dead) { free(f->a); free(f->b); }
    else if (!f->a || !f->b) { free(f->a); free(f->b); }
    drain_free_list();
    for (int i = 0; i < 2; i++) {
        if (f->left[i] >= 0) close(f->left[i]);
        if (f->right[i] >= 0) close(f->right[i]);
    }
    free(f->data); free(f->received);
}

static bool portfwd_endpoints(struct portfwd_fixture *f, int *left, int *right)
{
    f->a = calloc(1, sizeof(*f->a)); f->b = calloc(1, sizeof(*f->b));
    if (!f->a || !f->b) return false;
    f->a->fd = *left; f->b->fd = *right; *left = *right = -1;
    f->a->peer = f->b; f->b->peer = f->a;
    return true;
}

static bool portfwd_socketpairs(struct portfwd_fixture *f)
{
    return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->left) == 0 &&
           socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->right) == 0;
}

/* Drive the real epoll dispatcher without a child, listener, or network. */
static int portfwd_pump(int timeout)
{
    struct epoll_event events[16];
    int n = epoll_wait(g_epfd, events, 16, timeout);
    if (n < 0) return -1;
    for (int i = 0; i < n; i++)
        dispatch_epoll_event(events[i].data.ptr, events[i].events);
    return n;
}

#ifdef PORTFWD_MANAGED_INTEREST
/* Hold upstream completion until after the client request and EOF are read. */
static bool portfwd_order_exchange(struct portfwd_fixture *f)
{
    struct endpoint *a = f->a, *b = f->b;
    char reply[4];
    b->connecting = true;
    if (write(f->left[0], "abc", 3) != 3 || shutdown(f->left[0], SHUT_WR) < 0)
        return false;
    dispatch_epoll_event(a, EPOLLIN | EPOLLRDHUP);
    if (a->dead || !a->read_eof || b->buf_len != 3 || b->write_shutdown || !b->connecting)
        return false;
    dispatch_epoll_event(b, EPOLLOUT);
    if (a->dead || b->connecting || !b->write_shutdown) return false;
    return read(f->right[1], reply, sizeof(reply)) == 3 && !memcmp(reply, "abc", 3) &&
           read(f->right[1], reply, sizeof(reply)) == 0;
}

static bool portfwd_connect_order(void)
{
    struct portfwd_fixture f;
    portfwd_init(&f);
    bool ok = portfwd_socketpairs(&f) && portfwd_endpoints(&f, &f.left[1], &f.right[0]) &&
              portfwd_order_exchange(&f);
    portfwd_cleanup(&f);
    return ok;
}

/* A bound but non-listening local port deterministically refuses the connect. */
static int portfwd_reserve_port(uint16_t *port)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) < 0) { close(fd); return -1; }
    *port = ntohs(sa.sin_port);
    return fd;
}

static bool portfwd_refusal_dispatch(struct portfwd_fixture *f)
{
    f->b->connecting = true;
    if (!ep_update(f->a) || !ep_update(f->b)) return false;
    for (int i = 0; i < 10 && !f->a->dead; i++)
        if (portfwd_pump(100) < 0) return false;
    return f->a->dead && f->b->dead;
}

static bool portfwd_connect_failure(void)
{
    struct portfwd_fixture f;
    uint16_t port = 0;
    int reservation = -1, upstream = -1;
    bool ok = false;
    portfwd_init(&f);
    reservation = portfwd_reserve_port(&port);
    if (reservation < 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f.left) < 0)
        goto done;
    upstream = connect_target(port);
    if (upstream < 0) { ok = true; goto done; } /* synchronous refusal */
    if (!portfwd_endpoints(&f, &f.left[1], &upstream)) goto done;
    ok = portfwd_refusal_dispatch(&f);
done:
    portfwd_cleanup(&f);
    if (reservation >= 0) close(reservation);
    if (upstream >= 0) close(upstream);
    return ok;
}
#endif

static bool portfwd_prepare(struct portfwd_fixture *f)
{
    int large = 1024 * 1024, small = 4096;
    if (!portfwd_socketpairs(f)) return false;
    if (setsockopt(f->left[0], SOL_SOCKET, SO_SNDBUF, &large, sizeof(large)) < 0 ||
        setsockopt(f->right[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) < 0) return false;
    f->data = malloc(PORTFWD_SIZE); f->received = malloc(PORTFWD_SIZE);
    if (!f->data || !f->received || !portfwd_endpoints(f, &f->left[1], &f->right[0]))
        return false;
    for (size_t i = 0; i < PORTFWD_SIZE; i++)
        f->data[i] = (unsigned char)(i * 37u + i / 251u);
    size_t sent = 0;
    while (sent < PORTFWD_SIZE) {
        ssize_t n = write(f->left[0], f->data + sent, PORTFWD_SIZE - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    if (shutdown(f->left[0], SHUT_WR) < 0) return false;
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.ptr = f->a};
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, f->a->fd, &event) < 0) return false;
    event.data.ptr = f->b;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, f->b->fd, &event) < 0) return false;
#ifdef PORTFWD_MANAGED_INTEREST
    f->a->registered = f->b->registered = true;
#endif
    return true;
}

/* The sender queued >64 KiB and FIN; do not drain the recipient yet. */
static bool portfwd_backpressure(struct portfwd_fixture *f)
{
    for (int i = 0; i < 100 && f->b->buf_len < BUF_SZ; i++)
        if (portfwd_pump(0) < 0 || f->a->dead) return false;
    if (f->b->buf_len != BUF_SZ || f->a->read_eof) return false;
    /* Full backpressure must not turn the persistent hangup into a busy loop. */
    return portfwd_pump(0) == 0;
}

static bool portfwd_receive_request(struct portfwd_fixture *f)
{
    size_t got = 0;
    bool eof = false;
    for (int i = 0; i < 10000 && !eof; i++) {
        unsigned char extra;
        ssize_t n = read(f->right[1], got < PORTFWD_SIZE ? f->received + got : &extra,
                         got < PORTFWD_SIZE ? PORTFWD_SIZE - got : 1);
        if (n > 0) { if (got == PORTFWD_SIZE) return false; got += (size_t)n; }
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (portfwd_pump(0) < 0) return false;
    }
    return eof && got == PORTFWD_SIZE && !memcmp(f->data, f->received, PORTFWD_SIZE) && !f->a->dead;
}

/* A response after seeing request EOF must still cross the reverse path. */
static bool portfwd_receive_response(struct portfwd_fixture *f)
{
    size_t got = 0;
    bool eof = false;
    if (write(f->right[1], "response", 8) != 8 || shutdown(f->right[1], SHUT_WR) < 0)
        return false;
    for (int i = 0; i < 10000 && !eof; i++) {
        ssize_t n = read(f->left[0], f->received + got, PORTFWD_SIZE - got);
        if (n > 0) got += (size_t)n;
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (portfwd_pump(0) < 0) return false;
    }
    return eof && got == 8 && !memcmp(f->received, "response", 8) && f->a->dead && f->b->dead;
}

/* Run the real setup script under an isolated HOME and command shims. */
struct pf_setup {
    char root[PATH_MAX], home[PATH_MAX], bin[PATH_MAX], log[PATH_MAX];
    char legacy[PATH_MAX], unit[PATH_MAX], dropin[PATH_MAX], qualified[PATH_MAX];
};
static bool pf_path(char *out, size_t cap, const char *base, const char *tail)
{
    int n = snprintf(out, cap, "%s/%s", base, tail);
    return n > 0 && (size_t)n < cap;
}
static bool pf_dir(const char *base, const char *tail)
{
    char path[PATH_MAX];
    return pf_path(path, sizeof(path), base, tail) && mkdir(path, 0700) == 0;
}
static bool pf_write(const char *path, const char *body, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) return false;
    size_t n = strlen(body); bool ok = write(fd, body, n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}
static bool pf_same(const char *path, const char *expected)
{
    char data[256]; int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t n = read(fd, data, sizeof(data)); close(fd);
    return n >= 0 && (size_t)n == strlen(expected) && !memcmp(data, expected, (size_t)n);
}
static bool pf_mode(const char *path, mode_t mode)
{
    struct stat st;
    return lstat(path, &st) == 0 && (st.st_mode & 0777) == mode;
}
static bool pf_shim(const struct pf_setup *f, const char *name, const char *body)
{
    char path[PATH_MAX];
    return pf_path(path, sizeof(path), f->bin, name) && pf_write(path, body, 0700);
}
static bool pf_shims(const struct pf_setup *f)
{
    const char *id = "#!/bin/sh\ncase \"$1\" in -un) echo z23_test_no_such_user_91;; -u) echo 1000;; *) exit 1;; esac\n";
    const char *ctl = "#!/bin/sh\nif [ \"$2\" = show ]; then case \"$PF_STATE\" in fail) exit 1;; *) echo \"$PF_STATE\";; esac; exit; fi\necho systemctl >> \"$PF_LOG\"\n";
    const char *mkdir_sh = "#!/bin/sh\nfor a do case \"$a\" in -p|\"$HOME\"/*|~z23_test_no_such_user_91/*) :;; *) exit 1;; esac; done\nexec /bin/mkdir \"$@\"\n";
    const char *install_sh = "#!/bin/sh\necho install >> \"$PF_LOG\"\nfor a do last=$a; done\ncase \"$last\" in \"$HOME\"/*) exec /usr/bin/install \"$@\";; *) exit 1;; esac\n";
    const char *cc = "#!/bin/sh\necho compiler >> \"$PF_LOG\"\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then shift; out=$1; fi; shift; done\ncase \"$out\" in \"$HOME\"/*) printf '#!/bin/sh\\nexit 0\\n' > \"$out\"; /bin/chmod 700 \"$out\";; *) exit 1;; esac\n";
    const char *block = "#!/bin/sh\necho blocked-command >> \"$PF_LOG\"\nexit 1\n";
    return pf_shim(f, "id", id) && pf_shim(f, "systemctl", ctl) &&
        pf_shim(f, "mkdir", mkdir_sh) && pf_shim(f, "install", install_sh) &&
        pf_shim(f, "cc", cc) && pf_shim(f, "gcc", block) &&
        pf_shim(f, "setcap", block) && pf_shim(f, "sudo", block) && pf_shim(f, "loginctl", block);
}
static bool pf_dirs(struct pf_setup *f)
{
    return pf_dir(f->root, "home") && pf_dir(f->root, "bin") &&
        pf_dir(f->home, ".local") && pf_dir(f->home, ".local/bin") &&
        pf_dir(f->home, ".local/lib") && pf_dir(f->home, ".local/lib/z23") &&
        pf_dir(f->home, ".local/lib/z23/portfwd") && pf_dir(f->home, ".local/lib/z23/portfwd/qualified") &&
        pf_dir(f->home, ".config") && pf_dir(f->home, ".config/systemd") &&
        pf_dir(f->home, ".config/systemd/user");
}
static bool pf_setup_init(struct pf_setup *f)
{
    if (getpwnam("z23_test_no_such_user_91")) return false;
    if (!test_mkdtemp(f->root, sizeof(f->root), "portfwd_setup")) return false;
    if (!pf_path(f->home, sizeof(f->home), f->root, "home") ||
        !pf_path(f->bin, sizeof(f->bin), f->root, "bin") ||
        !pf_path(f->log, sizeof(f->log), f->root, "mutations") || !pf_dirs(f)) return false;
    return pf_path(f->legacy, sizeof(f->legacy), f->home, ".local/bin/zcl-portfwd") &&
        pf_path(f->unit, sizeof(f->unit), f->home, ".config/systemd/user/zcl-portfwd.service") &&
        pf_path(f->dropin, sizeof(f->dropin), f->home, ".config/systemd/user/zcl-portfwd.service.d") &&
        pf_path(f->qualified, sizeof(f->qualified), f->home, ".local/lib/z23/portfwd/qualified/zcl-portfwd") && pf_shims(f);
}
static int pf_run(const struct pf_setup *f, const char *state, char *output, size_t cap)
{
    char script[PATH_MAX], home[PATH_MAX + 8], path[PATH_MAX + 32], log[PATH_MAX + 16], mode[64];
    if (!realpath("tools/scripts/zcl-portfwd-setup.sh", script) ||
        snprintf(home, sizeof(home), "HOME=%s", f->home) >= (int)sizeof(home) ||
        snprintf(path, sizeof(path), "PATH=%s:/usr/bin:/bin", f->bin) >= (int)sizeof(path) ||
        snprintf(log, sizeof(log), "PF_LOG=%s", f->log) >= (int)sizeof(log) ||
        snprintf(mode, sizeof(mode), "PF_STATE=%s", state) >= (int)sizeof(mode)) return -1;
    const char *argv[] = {"/usr/bin/env", "-u", "SUDO_USER", home, path, log, mode,
        "/bin/bash", script, "--install", NULL};
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->root, output, cap, 30000, &timed_out);
    return timed_out ? -1 : rc;
}
enum pf_case { PF_CONFIGURED, PF_ORPHAN, PF_DANGLING, PF_DROPIN, PF_UNKNOWN, PF_UNAVAILABLE, PF_LOADED, PF_FRESH };
static bool pf_artifact(struct pf_setup *f, enum pf_case which)
{
    if (which == PF_CONFIGURED) {
        char override[PATH_MAX];
        return mkdir(f->dropin, 0700) == 0 && pf_path(override, sizeof(override), f->dropin, "90-qualified-image.conf") &&
            pf_write(f->unit, "unit sentinel\n", 0600) && pf_write(override, "override sentinel\n", 0600) &&
            pf_write(f->qualified, "qualified sentinel\n", 0700);
    }
    if (which == PF_ORPHAN) return pf_write(f->legacy, "legacy sentinel\n", 0700);
    if (which == PF_DANGLING) return symlink("missing", f->unit) == 0;
    if (which == PF_DROPIN) return mkdir(f->dropin, 0700) == 0;
    return true;
}
static bool pf_preserved(const struct pf_setup *f, enum pf_case which)
{
    if (which == PF_CONFIGURED) {
        char override[PATH_MAX];
        return pf_path(override, sizeof(override), f->dropin, "90-qualified-image.conf") &&
            pf_same(f->unit, "unit sentinel\n") && pf_mode(f->unit, 0600) &&
            pf_same(override, "override sentinel\n") && pf_mode(override, 0600) &&
            pf_same(f->qualified, "qualified sentinel\n") && pf_mode(f->qualified, 0700);
    }
    if (which == PF_ORPHAN) return pf_same(f->legacy, "legacy sentinel\n") && pf_mode(f->legacy, 0700);
    if (which == PF_DANGLING) { struct stat st; return lstat(f->unit, &st) == 0 && S_ISLNK(st.st_mode); }
    if (which == PF_DROPIN) { struct stat st; return lstat(f->dropin, &st) == 0 && S_ISDIR(st.st_mode); }
    return true;
}
static bool pf_fresh_log(const char *path)
{
    char text[256]; int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof(text) - 1); close(fd);
    if (n < 0) return false;
    text[n] = 0;
    return strstr(text, "compiler\n") && strstr(text, "install\n") &&
        strstr(text, "systemctl\n") && !strstr(text, "blocked-command");
}
static bool pf_setup_case(enum pf_case which)
{
    struct pf_setup f = {0}; char output[4096] = {0};
    if (!pf_setup_init(&f) || !pf_artifact(&f, which)) return false;
    const char *state = which == PF_UNKNOWN ? "unknown" : which == PF_UNAVAILABLE ? "fail" :
        which == PF_LOADED ? "loaded" : "not-found";
    int rc = pf_run(&f, state, output, sizeof(output));
    bool fresh = which == PF_FRESH;
    bool ok = fresh ? rc == 0 && strstr(output, "ONE privileged step remains") &&
        access(f.legacy, X_OK) == 0 && access(f.unit, F_OK) == 0 && pf_fresh_log(f.log) :
        rc != 0 && strstr(output, "preserved") && access(f.log, F_OK) != 0 && pf_preserved(&f, which);
    if (!ok) fprintf(stderr, "portfwd setup case=%d rc=%d output=%s\n", (int)which, rc, output);
    return ok;
}
static bool pf_setup_cases(void)
{
    bool ok = true;
    for (int i = PF_CONFIGURED; i <= PF_FRESH; ++i)
        if (!pf_setup_case((enum pf_case)i)) ok = false;
    return ok;
}

int test_portfwd(void)
{
    struct portfwd_fixture f;
    int failures = 1;
    struct sigaction old_pipe, ignore_pipe = {0};
    portfwd_init(&f);
    ignore_pipe.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &ignore_pipe, &old_pipe) < 0) return 1;
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) goto done;
#ifdef PORTFWD_MANAGED_INTEREST
    if (!portfwd_connect_order() || !portfwd_connect_failure()) goto done;
#endif
    if (portfwd_prepare(&f) && portfwd_backpressure(&f) &&
        portfwd_receive_request(&f) && portfwd_receive_response(&f)) failures = 0;
done:
    portfwd_cleanup(&f);
    if (g_epfd >= 0) close(g_epfd);
    g_epfd = -1;
    if (sigaction(SIGPIPE, &old_pipe, NULL) < 0) failures = 1;
    printf("portfwd: backpressure and half-close: %s\n", failures ? "FAIL" : "OK");
    if (!pf_setup_cases()) { puts("portfwd: setup preservation: FAIL"); failures = 1; }
    else puts("portfwd: setup preservation: OK");
    return failures;
}
#else
int test_portfwd(void)
{
    printf("UNOBSERVED (portfwd: Linux epoll required)\n");
    return 0;
}
#endif
