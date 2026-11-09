/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stopwatch_peer_gate — executed regression for the C3 stopwatch's
 * pre-flight peer gate (tools/scripts/cold_start_to_tip_stopwatch.sh +
 * build/bin/p2p_version_probe, built from tools/p2p_version_probe.c).
 *
 * The defect: a silent or stale named peer let the stopwatch burn its whole
 * 600 s budget and label the run "stalled-named", indistinguishable from a
 * node sync regression. The gate must instead end the run in seconds with the
 * classification ENVIRONMENT_BLOCKED and the exact token naming WHY:
 *
 *   peer closes at accept   -> peer_no_handshake
 *   peer never answers      -> peer_no_handshake
 *   nothing listening       -> peer_unreachable
 *   peer answers version    -> start_height recorded; below the expected tip
 *                              (minus tolerance) -> peer_tip_stale, otherwise
 *                              the gate passes
 *
 * Every peer is a local loopback listener this test owns. The script runs with
 * ZCL_CS_PEER_PRECHECK_ONLY / a private artifact root, so no node is launched
 * and no datadir is touched. */

#include "test/test_core.h"

#if !defined(_WIN32)

#include "crypto/sha256.h"
#include "platform/os_proc.h"
#include "platform/supervised_process.h"
#include "util/spawn.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif

#define GATE_SCRIPT_REL "tools/scripts/cold_start_to_tip_stopwatch.sh"
/* macOS ships no /bin/true; its stand-in node binary lives in /usr/bin. */
#if defined(__APPLE__)
#define SPG_TRUE_BIN "ZCL_CS_NODE_BIN=/usr/bin/true"
#else
#define SPG_TRUE_BIN "ZCL_CS_NODE_BIN=/bin/true"
#endif

#define SPG_CHECK(name, expr) do { \
    printf("stopwatch_peer_gate: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

enum fake_mode { FAKE_CLOSE, FAKE_SILENT, FAKE_VERSION };

struct fake_peer {
    int lfd;
    int port;
    enum fake_mode mode;
    int start_height;
    pthread_t thr;
    bool threaded;
};

static const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached;
    if (cached) return root[0] ? root : NULL;
    cached = 1;
    char exe[PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe))) return NULL;
    for (int depth = 0; depth < 8; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';
        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/%s", exe, GATE_SCRIPT_REL)
                >= (int)sizeof(probe)) break;
        if (stat(probe, &st) == 0) {
            snprintf(root, sizeof(root), "%s", exe);
            return root;
        }
    }
    return NULL;
}

static void put_le(uint8_t *p, uint64_t v, int n)
{
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* A well-formed mainnet `version` message advertising start_height. */
static size_t build_version(uint8_t *out, int start_height)
{
    uint8_t pl[128];
    size_t n = 0;
    memset(pl, 0, sizeof(pl));
    put_le(pl + n, 170011, 4); n += 4;
    n += 8;                     /* services */
    put_le(pl + n, 1700000000, 8); n += 8;
    n += 26 + 26;               /* addr_recv, addr_from */
    n += 8;                     /* nonce */
    pl[n++] = 4;
    memcpy(pl + n, "/fk/", 4); n += 4;
    put_le(pl + n, (uint32_t)start_height, 4); n += 4;
    pl[n++] = 0;                /* relay */

    uint8_t d1[SHA256_OUTPUT_SIZE], d2[SHA256_OUTPUT_SIZE];
    struct sha256_ctx c;
    sha256_init(&c); sha256_write(&c, pl, n); sha256_finalize(&c, d1);
    sha256_init(&c); sha256_write(&c, d1, sizeof(d1)); sha256_finalize(&c, d2);

    static const uint8_t magic[4] = { 0x24, 0xe9, 0x27, 0x64 };
    memcpy(out, magic, 4);
    memset(out + 4, 0, 12);
    memcpy(out + 4, "version", 7);
    put_le(out + 16, n, 4);
    memcpy(out + 20, d2, 4);
    memcpy(out + 24, pl, n);
    return 24 + n;
}

static void *fake_peer_main(void *arg)
{
    struct fake_peer *fp = arg;
    int c = accept(fp->lfd, NULL, NULL);
    if (c < 0) return NULL;
    if (fp->mode == FAKE_VERSION) {
        uint8_t in[512], msg[256];
        ssize_t got = recv(c, in, sizeof(in), 0);   /* the client's version */
        if (got > 0) {
            size_t len = build_version(msg, fp->start_height);
            if (send(c, msg, len, MSG_NOSIGNAL) < 0) { /* peer gone */ }
        }
    }
    close(c);
    return NULL;
}

static bool fake_peer_start(struct fake_peer *fp, enum fake_mode mode,
                            int start_height)
{
    memset(fp, 0, sizeof(*fp));
    fp->mode = mode;
    fp->start_height = start_height;
    fp->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (fp->lfd < 0) return false;
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (bind(fp->lfd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(fp->lfd, 4) != 0 ||
        getsockname(fp->lfd, (struct sockaddr *)&a, &al) != 0)
        return false;
    fp->port = ntohs(a.sin_port);
    /* FAKE_SILENT never accepts: the kernel backlog completes the connect and
     * the peer then says nothing at all. */
    if (mode != FAKE_SILENT)
        fp->threaded = pthread_create(&fp->thr, NULL, fake_peer_main, fp) == 0;
    return true;
}

static void fake_peer_stop(struct fake_peer *fp)
{
    if (fp->threaded) {
        shutdown(fp->lfd, SHUT_RDWR);
        /* Unblock an accept() nobody reached (gate short-circuited). */
        int k = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = { .sin_family = AF_INET,
                                 .sin_port = htons((uint16_t)fp->port) };
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (k >= 0) {
            if (connect(k, (struct sockaddr *)&a, sizeof(a)) != 0) { /* ok */ }
            close(k);
        }
        pthread_join(fp->thr, NULL);
    }
    close(fp->lfd);
}

/* Run the stopwatch against one stated peer. *out gets merged stdout+stderr;
 * returns the script's exit code (-1 if it could not be observed). */
static int run_gate(const char *root, const char *artifacts, int port,
                    const char *expected_tip, bool only, char *out, size_t cap)
{
    char script[PATH_MAX], peer[64], art[PATH_MAX + 32], tip[64];
    snprintf(script, sizeof(script), "%s/%s", root, GATE_SCRIPT_REL);
    snprintf(peer, sizeof(peer), "ZCL_CS_PEER=127.0.0.1:%d", port);
    snprintf(art, sizeof(art), "ZCL_CS_ARTIFACT_ROOT=%s", artifacts);
    snprintf(tip, sizeof(tip), "ZCL_CS_EXPECTED_TIP=%s", expected_tip);
    const char *argv[16];
    int n = 0;
    argv[n++] = "/usr/bin/env";
    argv[n++] = peer;
    argv[n++] = art;
    argv[n++] = SPG_TRUE_BIN;
    argv[n++] = "ZCL_CS_PEER_HANDSHAKE_SECS=3";
    argv[n++] = "ZCL_CS_PEER_TIP_TOLERANCE=1000";
    if (expected_tip[0]) argv[n++] = tip;
    if (only) argv[n++] = "ZCL_CS_PEER_PRECHECK_ONLY=1";
    argv[n++] = "bash";
    argv[n++] = script;
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, cap, 60000);
}

struct gate_env {
    const char *root;
    const char *artifacts;
    char *out;
    size_t cap;
};

static int case_closes_immediately(const struct gate_env *g)
{
    int failures = 0;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_CLOSE, 0)) {
        SPG_CHECK("closing listener started", false);
        return failures;
    }
    int rc = run_gate(g->root, g->artifacts, fp.port, "", false, g->out, g->cap);
    SPG_CHECK("closes-immediately -> ENVIRONMENT_BLOCKED=peer_no_handshake, exit 2",
              rc == 2 && strstr(g->out, "ENVIRONMENT_BLOCKED=peer_no_handshake\n") &&
              strstr(g->out, "SKIP (ENVIRONMENT_BLOCKED peer_no_handshake:") &&
              !strstr(g->out, "stalled-named") && !strstr(g->out, "FAIL"));
    fake_peer_stop(&fp);
    return failures;
}

static int case_never_answers(const struct gate_env *g)
{
    int failures = 0;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_SILENT, 0)) {
        SPG_CHECK("silent listener started", false);
        return failures;
    }
    int rc = run_gate(g->root, g->artifacts, fp.port, "", false, g->out, g->cap);
    SPG_CHECK("never-answers -> ENVIRONMENT_BLOCKED=peer_no_handshake, exit 2",
              rc == 2 && strstr(g->out, "ENVIRONMENT_BLOCKED=peer_no_handshake\n") &&
              !strstr(g->out, "stalled-named") && !strstr(g->out, "FAIL"));
    fake_peer_stop(&fp);
    return failures;
}

static int case_refused(const struct gate_env *g)
{
    int failures = 0;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_SILENT, 0)) return failures;
    int dead = fp.port;
    fake_peer_stop(&fp);
    int rc = run_gate(g->root, g->artifacts, dead, "", false, g->out, g->cap);
    SPG_CHECK("refused -> ENVIRONMENT_BLOCKED=peer_unreachable, exit 2",
              rc == 2 && strstr(g->out, "ENVIRONMENT_BLOCKED=peer_unreachable\n") &&
              !strstr(g->out, "stalled-named"));
    return failures;
}

static int case_stale_tip(const struct gate_env *g)
{
    int failures = 0;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_VERSION, 100)) {
        SPG_CHECK("version listener started", false);
        return failures;
    }
    int rc = run_gate(g->root, g->artifacts, fp.port, "3000000", false, g->out, g->cap);
    SPG_CHECK("stale tip -> ENVIRONMENT_BLOCKED=peer_tip_stale, height recorded",
              rc == 2 && strstr(g->out, "ENVIRONMENT_BLOCKED=peer_tip_stale\n") &&
              strstr(g->out, "start_height=100 ") && !strstr(g->out, "stalled-named"));
    fake_peer_stop(&fp);
    return failures;
}

static int case_healthy(const struct gate_env *g)
{
    int failures = 0;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_VERSION, 2999500)) {
        SPG_CHECK("healthy listener started", false);
        return failures;
    }
    int rc = run_gate(g->root, g->artifacts, fp.port, "3000000", true, g->out, g->cap);
    SPG_CHECK("healthy peer -> peer_gate=ok with start_height=2999500, exit 0",
              rc == 0 && strstr(g->out, "peer_gate=ok\n") &&
              strstr(g->out, "start_height=2999500 ") &&
              !strstr(g->out, "ENVIRONMENT_BLOCKED"));
    fake_peer_stop(&fp);
    return failures;
}

#if defined(__linux__)
static bool spg_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 10000) <= 0 || read(fd, out + n, 1) != 1) return false;
        if (out[n++] == '\n') { out[n] = 0; return true; }
    }
    return false;
}

static bool spg_clean_exit(int status, const char *start, const char *done)
{
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           !strcmp(start, "START\n") && !strcmp(done, "DONE CLEAN 0\n");
}

static int case_owned_exit(const struct gate_env *g)
{
    int failures = 0;
    char owner[PATH_MAX], launcher[PATH_MAX], log[PATH_MAX], start[128], done[128];
    if (snprintf(owner, sizeof(owner), "%s/build/bin/c3-supervised-owner", g->root) >= (int)sizeof(owner) ||
        snprintf(launcher, sizeof(launcher), "%s/build/bin/process-group-exec", g->root) >= (int)sizeof(launcher) ||
        snprintf(log, sizeof(log), "%s/owned.log", g->artifacts) >= (int)sizeof(log)) return 1;
    int control[2], result[2];
    if (pipe(control) || pipe(result)) return 1;
    pid_t child = fork();
    if (child == 0) {
        (void)dup2(control[0], 0); (void)dup2(result[1], 1);
        close(control[0]); close(control[1]); close(result[0]); close(result[1]);
        execl(owner, owner, launcher, log, "/bin/true", (char *)NULL);
        _exit(127);
    }
    close(control[0]); close(result[1]);
    bool ok = child > 0 && spg_line(result[0], start, sizeof(start)) &&
              write(control[1], "R", 1) == 1 &&
              spg_line(result[0], done, sizeof(done));
    close(control[1]); close(result[0]);
    int status = -1;
    if (child > 0) ok = waitpid(child, &status, 0) == child && ok;
    SPG_CHECK("owned launch returns clean completion", ok && spg_clean_exit(status, start, done));
    return failures;
}

struct spg_tree {
    char owner[PATH_MAX], launcher[PATH_MAX], log[PATH_MAX], self[PATH_MAX], fifo[PATH_MAX];
    int file, events, control[2], result[2];
    pid_t child;
};

static bool spg_tree_open(const struct gate_env *g, int mode, struct spg_tree *t)
{
    if (snprintf(t->owner, sizeof(t->owner), "%s/build/bin/c3-supervised-owner", g->root) >= (int)sizeof(t->owner) ||
        snprintf(t->launcher, sizeof(t->launcher), "%s/build/bin/process-group-exec", g->root) >= (int)sizeof(t->launcher) ||
        snprintf(t->log, sizeof(t->log), "%s/tree-%d.log", g->artifacts, mode) >= (int)sizeof(t->log) ||
        snprintf(t->fifo, sizeof(t->fifo), "%s/release-%d", g->artifacts, mode) >= (int)sizeof(t->fifo) ||
        !os_proc_exe_path(t->self, sizeof(t->self))) return false;
    if (mode == 2 && mkfifo(t->fifo, 0600) != 0) return false;
    t->file = open(t->log, O_RDWR | O_CREAT | O_EXCL, 0600);
    t->events = inotify_init1(IN_CLOEXEC);
    if (t->file < 0 || t->events < 0 || inotify_add_watch(t->events, t->log, IN_MODIFY) < 0) return false;
    if (pipe(t->control) || pipe(t->result)) return false;
    t->child = fork();
    if (t->child == 0) {
        (void)dup2(t->control[0], 0); (void)dup2(t->result[1], 1);
        close(t->control[0]); close(t->control[1]); close(t->result[0]); close(t->result[1]);
        if (mode == 2) execl(t->owner, t->owner, t->launcher, t->log, t->self, "--supervised-fixture-tree-natural", t->fifo, (char *)NULL);
        else execl(t->owner, t->owner, t->launcher, t->log, t->self, "--supervised-fixture-tree", (char *)NULL);
        _exit(127);
    }
    close(t->control[0]); close(t->result[1]);
    return t->child > 0;
}

static int spg_tree_leaf(struct spg_tree *t)
{
    char start[128];
    bool ok = spg_line(t->result[0], start, sizeof(start)) && !strcmp(start, "START\n") &&
              write(t->control[1], "R", 1) == 1;
    struct pollfd event = {t->events, POLLIN, 0};
    pid_t leaf = -1;
    ok = ok && poll(&event, 1, 10000) > 0 && read(t->file, &leaf, sizeof(leaf)) == (ssize_t)sizeof(leaf);
    return ok ? platform_supervised_fixture_pidfd_open(leaf) : -1;
}

static bool spg_tree_release(struct spg_tree *t, int mode)
{
    bool ok = true;
    if (mode == 0) ok = write(t->control[1], "S", 1) == 1;
    if (mode == 2) {
        int release = open(t->fifo, O_WRONLY | O_NONBLOCK);
        ok = release >= 0 && write(release, "R", 1) == 1 && ok;
        if (release >= 0) close(release);
    }
    if (mode == 1) { close(t->control[1]); t->control[1] = -1; }
    return ok;
}

static bool spg_tree_finish(struct spg_tree *t, int mode, int leaf_fd)
{
    char done[128];
    bool ok = spg_tree_release(t, mode) && leaf_fd >= 0;
    bool got_done = spg_line(t->result[0], done, sizeof(done));
    if (t->control[1] >= 0) close(t->control[1]);
    struct pollfd exited = {leaf_fd, POLLIN, 0};
    bool leaf_exited = leaf_fd >= 0 && poll(&exited, 1, 10000) > 0;
    if (!leaf_exited && leaf_fd >= 0) (void)platform_supervised_fixture_pidfd_kill(leaf_fd);
    int status = -1;
    if (t->child > 0) ok = waitpid(t->child, &status, 0) == t->child && ok;
    bool result = ok && got_done && !strncmp(done, "DONE CLEAN ", 11) && leaf_exited &&
                  WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (leaf_fd >= 0) close(leaf_fd);
    close(t->result[0]); close(t->events); close(t->file);
    return result;
}

static int case_owned_tree(const struct gate_env *g, int mode)
{
    int failures = 0;
    struct spg_tree t;
    if (!spg_tree_open(g, mode, &t)) return 1;
    int leaf_fd = spg_tree_leaf(&t);
    bool result = spg_tree_finish(&t, mode, leaf_fd);
    SPG_CHECK(mode == 2 ? "natural exit cleans escaped descendant" :
              mode == 1 ? "EOF cleans escaped descendant" : "STOP cleans escaped descendant",
              result);
    return failures;
}

static bool spg_script(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(body, f) >= 0;
    return fclose(f) == 0 && ok && chmod(path, 0700) == 0;
}

static bool spg_retained(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return false;
    struct dirent *entry;
    bool found = false;
    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, "zcl-c3-stopwatch.", 17) || strstr(entry->d_name, "-home")) continue;
        char node[PATH_MAX], home[PATH_MAX];
        struct stat a, b;
        if (snprintf(node, sizeof(node), "%s/%s", path, entry->d_name) >= (int)sizeof(node) ||
            snprintf(home, sizeof(home), "%s-home", node) >= (int)sizeof(home)) continue;
        if (!stat(node, &a) && S_ISDIR(a.st_mode) && !stat(home, &b) && S_ISDIR(b.st_mode)) found = true;
    }
    closedir(d);
    return found;
}

static bool spg_wait_signal_marker(int events)
{
    char buf[4096];
    struct pollfd p = {events, POLLIN, 0};
    while (poll(&p, 1, 10000) > 0) {
        ssize_t n = read(events, buf, sizeof(buf));
        if (n <= 0) break;
        for (size_t at = 0; at + sizeof(struct inotify_event) <= (size_t)n;) {
            const struct inotify_event *e = (const struct inotify_event *)(const void *)(buf + at);
            if (e->len && !strcmp(e->name, "signal-ready")) return true;
            at += sizeof(*e) + e->len;
        }
    }
    return false;
}

static bool spg_signal_child(pid_t child, int sig)
{
    siginfo_t info = {0};
    return child > 0 && waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
           !info.si_pid && kill(child, sig) == 0;
}

/* The unreaped direct child anchors this signal; no process-name lookup. */
static int spg_interrupt(const char *const argv[], const char *dir, char *out, size_t cap, int sig)
{
    char path[PATH_MAX], marker[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/signal-output-%d", dir, sig) >= (int)sizeof(path) ||
        snprintf(marker, sizeof(marker), "%s/signal-ready", dir) >= (int)sizeof(marker)) return -1;
    (void)unlink(marker);
    int log = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    int events = inotify_init1(IN_CLOEXEC);
    if (log < 0 || events < 0 || inotify_add_watch(events, dir, IN_CREATE) < 0) return -1;
    pid_t child = fork();
    if (child == 0) {
        (void)dup2(log, 1); (void)dup2(log, 2);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    bool ready = child > 0 && spg_wait_signal_marker(events);
    bool sent = spg_signal_child(child, sig);
    int status = -1;
    if (child > 0) (void)waitpid(child, &status, 0);
    (void)lseek(log, 0, SEEK_SET);
    ssize_t n = read(log, out, cap - 1);
    out[n > 0 ? (size_t)n : 0] = 0;
    close(log); close(events);
    return ready && sent && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

struct spg_cleanup {
    char node[PATH_MAX], owner[PATH_MAX], scratch[PATH_MAX], script[PATH_MAX], proof[PATH_MAX];
    char env_node[PATH_MAX + 32], env_owner[PATH_MAX + 32], env_root[PATH_MAX + 32], env_art[PATH_MAX + 32], peer[64], run_id[64];
};

static const char *spg_fake_owner(int mode)
{
    if (mode == 0) return "#!/bin/sh\nprintf 'START\\n'\ndd bs=1 count=2 of=/dev/null 2>/dev/null\n";
    if (mode == 1) return "#!/bin/sh\nprintf 'START\\n'\ndd bs=1 count=2 of=/dev/null 2>/dev/null\nprintf 'BAD\\n'\n";
    if (mode == 2) return "#!/bin/sh\nprintf 'START\\n'\ndd bs=1 count=2 of=/dev/null 2>/dev/null\nprintf 'DONE INCOMPLETE 0\\n'\n";
    if (mode == 3) return "#!/bin/sh\nprintf 'START\\n'\ndd bs=1 count=2 of=/dev/null 2>/dev/null\nprintf 'DONE CLEAN 0\\n'\n";
    if (mode >= 5) return "#!/bin/sh\nprintf 'START\\n'\ndd bs=1 count=1 of=/dev/null 2>/dev/null\n: >\"${0%/*}/signal-ready\"\ndd bs=1 count=1 of=/dev/null 2>/dev/null\nprintf 'DONE CLEAN 0\\n'\n";
    return "#!/bin/sh\nd=${2%/*}\nprintf 'START\\n'\ndd bs=1 count=1 of=/dev/null 2>/dev/null\nif [ ! -f \"$d/.seen\" ]; then : >\"$d/.seen\"; printf 'reason=self_respawn_fixture\\n' >\"$d/boot-exit-reason.v1\"; else : >\"$d/.ready\"; dd bs=1 count=1 of=/dev/null 2>/dev/null; fi\nprintf 'DONE CLEAN 0\\n'\n";
}

static bool spg_cleanup_paths(const struct gate_env *g, int mode, struct spg_cleanup *c)
{
    return snprintf(c->node, sizeof(c->node), "%s/fake-node-%d", g->artifacts, mode) < (int)sizeof(c->node) &&
        snprintf(c->owner, sizeof(c->owner), "%s/fake-owner-%d", g->artifacts, mode) < (int)sizeof(c->owner) &&
        snprintf(c->scratch, sizeof(c->scratch), "%s/private-%d", g->artifacts, mode) < (int)sizeof(c->scratch) &&
        snprintf(c->script, sizeof(c->script), "%s/%s", g->root, GATE_SCRIPT_REL) < (int)sizeof(c->script) &&
        snprintf(c->proof, sizeof(c->proof), "%s/cleanupfixture-%d/proof.json", g->artifacts, mode) < (int)sizeof(c->proof);
}

static bool spg_cleanup_prepare(const struct gate_env *g, int mode, struct spg_cleanup *c)
{
    if (!spg_cleanup_paths(g, mode, c) || mkdir(c->scratch, 0700)) return false;
    return spg_script(c->node, mode >= 4 ?
            "#!/bin/sh\nfor a do case $a in -datadir=*) d=${a#-datadir=};; esac; done\nif [ -f \"${d:-/nonexistent}/.ready\" ]; then h=2; else h=0; fi\nprintf '{\"hstar\":%s,\"network_tip\":1,\"network_tip_read_ok\":true,\"active_count\":0}\\n' \"$h\"\n" :
            "#!/bin/sh\nprintf '%s\\n' '{\"hstar\":2,\"network_tip\":1,\"network_tip_read_ok\":true,\"active_count\":0}'\n") &&
        spg_script(c->owner, spg_fake_owner(mode));
}

static bool spg_cleanup_success(int mode, int rc, bool retained, const char *out, const char *body)
{
    return rc == 0 && !retained && strstr(body, "\"cpu_seconds\":-1") &&
        strstr(body, "owner-supervised launch does not expose an identity-safe node PID") &&
        strstr(body, "\"scratch_datadir_removed\": true") && strstr(body, "\"verdict\": \"pass\"") &&
        strstr(out, "stopwatch: PASS") && (mode != 4 || strstr(out, "FOLLOWED self-respawn"));
}

static bool spg_cleanup_verdict(int mode, int rc, bool retained, const char *out, const char *body)
{
    if (mode >= 5) return rc == (mode == 5 ? 143 : 130) && !retained &&
        strstr(body, "\"scratch_datadir_removed\": true") && strstr(body, "\"verdict\": \"fail\"") &&
        !strstr(out, "stopwatch: PASS");
    if (!strstr(body, "\"final_hstar\": 2") || !strstr(body, "\"final_network_tip\": 1")) return false;
    if (mode >= 3) return spg_cleanup_success(mode, rc, retained, out, body);
    return rc == 1 && retained && strstr(body, "owned cleanup unconfirmed") &&
        strstr(body, "\"scratch_datadir_removed\": false") && strstr(body, "\"verdict\": \"fail\"") &&
        !strstr(out, "stopwatch: PASS");
}

static int case_cleanup_unknown(const struct gate_env *g, int mode)
{
    int failures = 0;
    struct spg_cleanup c;
    if (!spg_cleanup_prepare(g, mode, &c)) return 1;
    struct fake_peer fp;
    if (!fake_peer_start(&fp, FAKE_CLOSE, 0)) return 1;
    snprintf(c.env_node, sizeof(c.env_node), "ZCL_CS_NODE_BIN=%s", c.node);
    snprintf(c.env_owner, sizeof(c.env_owner), "ZCL_CS_OWNER=%s", c.owner);
    snprintf(c.env_root, sizeof(c.env_root), "ZCL_CS_ROOT=%s", c.scratch);
    snprintf(c.env_art, sizeof(c.env_art), "ZCL_CS_ARTIFACT_ROOT=%s", g->artifacts);
    snprintf(c.peer, sizeof(c.peer), "ZCL_CS_PEER=127.0.0.1:%d", fp.port);
    snprintf(c.run_id, sizeof(c.run_id), "ZCL_CS_RUN_ID=cleanupfixture-%d", mode);
    const char *argv[] = {"/usr/bin/env", c.env_node, c.env_owner, c.env_root, c.env_art, c.peer,
        c.run_id, "ZCL_CS_PEER_PRECHECK=0", "ZCL_CS_FILE_PEER=",
        "ZCL_CS_BUDGET_SECS=5", "ZCL_CS_SAMPLE_SECS=1", "bash", c.script, NULL};
    int rc = mode >= 5 ? spg_interrupt(argv, g->artifacts, g->out, g->cap, mode == 5 ? SIGTERM : SIGINT) :
                         zcl_spawn_capture(argv, g->out, g->cap, 60000);
    fake_peer_stop(&fp);
    FILE *f = fopen(c.proof, "r");
    char body[32768] = {0};
    if (f) { size_t n = fread(body, 1, sizeof(body) - 1, f); body[n] = 0; fclose(f); }
    bool retained = spg_retained(c.scratch);
    bool ok = spg_cleanup_verdict(mode, rc, retained, g->out, body);
    if (!ok) printf("cleanup fixture mode=%d rc=%d retained=%d output=%.3000s proof=%.1500s\n", mode, rc, (int)retained, g->out, body);
    SPG_CHECK(mode == 6 ? "INT exits nonzero and cleans the fixture" :
              mode == 5 ? "TERM exits nonzero and cleans the fixture" :
              mode == 4 ? "clean second generation records PASS and removes fixture" :
              mode == 3 ? "clean ACK records PASS and removes fixture" :
              mode == 2 ? "incomplete ACK refuses PASS and retains fixture" :
              mode == 1 ? "malformed ACK refuses PASS and retains fixture" :
                          "missing ACK refuses PASS and retains fixture", ok);
    return failures;
}
#endif

static bool make_artifact_dir(const char *root, char *artifacts, size_t cap)
{
    snprintf(artifacts, cap, "%s/build/scratch/peergate_XXXXXX", root);
    if (mkdtemp(artifacts)) return true;
    char mk[PATH_MAX + 16];
    snprintf(mk, sizeof(mk), "%s/build/scratch", root);
    (void)mkdir(mk, 0755);
    snprintf(artifacts, cap, "%s/build/scratch/peergate_XXXXXX", root);
    return mkdtemp(artifacts) != NULL;
}

static int stopwatch_peer_gate_run(void)
{
    int failures = 0;
    printf("\n=== stopwatch_peer_gate tests ===\n");
    const char *root = repo_root();
    if (!root) { printf("stopwatch_peer_gate: repo root not found FAIL\n"); return 1; }

    char artifacts[PATH_MAX];
    if (!make_artifact_dir(root, artifacts, sizeof(artifacts))) {
        printf("stopwatch_peer_gate: mkdtemp FAIL\n");
        return 1;
    }

    static char out[16384];
    const struct gate_env g = { root, artifacts, out, sizeof(out) };
    int (*const cases[])(const struct gate_env *) = {
        case_closes_immediately, case_never_answers, case_refused,
        case_stale_tip, case_healthy,
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += cases[i](&g);

#if defined(__linux__)
    failures += case_owned_exit(&g);
    failures += case_owned_tree(&g, 0);
    failures += case_owned_tree(&g, 1);
    failures += case_owned_tree(&g, 2);
    failures += case_cleanup_unknown(&g, 0);
    failures += case_cleanup_unknown(&g, 1);
    failures += case_cleanup_unknown(&g, 2);
    failures += case_cleanup_unknown(&g, 3);
    failures += case_cleanup_unknown(&g, 4);
    failures += case_cleanup_unknown(&g, 5);
    failures += case_cleanup_unknown(&g, 6);
#endif

    const char *rm[] = { "/bin/rm", "-rf", artifacts, NULL };
    char rmout[256];
    (void)zcl_spawn_capture(rm, rmout, sizeof(rmout), 10000);
    return failures;
}

#endif

int test_stopwatch_peer_gate(void)
{
#if defined(_WIN32)
    return 0;
#else
    return stopwatch_peer_gate_run();
#endif
}
