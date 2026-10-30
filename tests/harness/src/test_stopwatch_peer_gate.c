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
#include "util/spawn.h"

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define GATE_SCRIPT_REL "tools/scripts/cold_start_to_tip_stopwatch.sh"

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
    argv[n++] = "ZCL_CS_NODE_BIN=/bin/true";
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
