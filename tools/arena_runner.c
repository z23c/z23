/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * arena_runner: deterministic 2-team zdogfight match driver (dev tool).
 *
 * Runs one zdogfight match between two CONFINED pilot processes (one per
 * team) and emits replay/final-state roots for cross-node, byte-identical
 * replay verification. This is a standalone developer tool — NOT a native
 * command (the engine/composition/commands def files are deliberately untouched).
 *
 * Usage:
 *   arena_runner --seed <u64> --planes-per-team <1..4>
 *       --pilot-red <path> --pilot-blue <path>
 *       [--replay-out <file>] [--no-sandbox]
 *   arena_runner --verify-replay <file>
 *       [--expect-replay-root <64hex>]
 *
 * PILOT PROTOCOL (fixed; the pilots implement it): per tick, for each
 * LIVING plane of the pilot's team in ascending plane-index order, the
 * runner writes one ZDOG_OBS_WIRE_LEN (82) byte obs frame to the pilot's
 * stdin, then reads one ZDOG_CTL_WIRE_LEN (7) byte ctl frame back from its
 * stdout. At match end the runner closes the pilot's stdin (a well-behaved
 * pilot exits 0 on EOF). A pilot that dies, stalls past its CPU budget, or
 * sends a short frame is marked dead; FROM THAT TICK ONWARD its whole team
 * gets deterministic NEUTRAL controls {0,0,0,0} — a dead pilot can never
 * abort the match or alter it nondeterministically, and the neutral frames
 * are part of the replay.
 *
 * CONFINEMENT: each pilot child gets os_sandbox_session_child_profile whose
 * ONLY filesystem grant is read+execute on the pilot binary itself
 * (Landlock's exec open check requires READ_FILE on the image, so a literal
 * zero-grant domain makes the loading execve EACCES — every other path on
 * the filesystem is denied; pre-opened pipe fds survive Landlock), the
 * session rlimits with RLIMIT_CPU=AR_PILOT_CPU_SECONDS, and the session
 * seccomp deny-list with W^X — MINUS execve/execveat, exactly the
 * package_verify.c child pattern (g_pv_child_denied omits them for the same
 * reason): the child must exec the pilot binary AFTER the filter is
 * installed. Re-exec gains a pilot nothing: the Landlock domain denies
 * every file read a fresh image (or its dynamic loader) would need, and the
 * filter survives exec. Pilots are linked -static so the W^X PROT_EXEC
 * mmap/mprotect denial does not kill the dynamic loader.
 *
 * NO WALL CLOCK IN THE AUTHORITATIVE PATH: a stuck pilot is bounded by its
 * RLIMIT_CPU budget (SIGXCPU kill -> EOF on the runner's read -> dead ->
 * neutral controls), never by a wall-clock timeout, so scheduling jitter on
 * any host cannot change the match. Blocking reads are safe because the
 * protocol pilots are pure functions that always answer; the CPU rlimit
 * guarantees a looping pilot dies and is then detected.
 *
 * If Landlock or seccomp is unavailable on this host the runner FAILS
 * LOUDLY at startup (exit 3) unless --no-sandbox is passed (dev debugging
 * only; a prominent warning is printed).
 *
 * REPLAY FILE (canonical, all little-endian):
 *   magic "ZDOGREPL" (8) | u32 version=1 | u64 seed | u8 planes_per_team
 *   then per tick: one 7-byte ctl frame per plane, ascending index order,
 *   for every tick until match end (dead planes' neutral frames included)
 *   then the ZDOG_STATE_WIRE_MAX (2163) byte final zdog_state_encode.
 * Worst case is bounded: 21 + 36000*8*7 + 2163 = 2,018,184 bytes.
 *
 * ROOTS:
 *   replay_root      sha3-256 over the full replay file bytes
 *   final_state_root sha3-256 over the 2163-byte final state encoding
 *   state_root_chain sha3-256 chain, folded every 600 completed ticks:
 *                      chain0 = sha3("zdogfight-replay-v1" || seed_le64 || planes_u8)
 *                      chainK = sha3(chainK-1 || zdog_state_checksum_le64)
 *
 * --verify-replay re-applies the recorded ctl frames with NO pilots and
 * checks the match goes DONE at the exact recorded tick count and that the
 * re-encoded final state byte-equals the file's trailing state block, then
 * prints the recomputed roots and verify=ok (exit 0) or
 * verify=MISMATCH <what> (exit 1).  --expect-replay-root additionally binds
 * an otherwise valid replay to the exact accepted replay identity.
 *
 * Exit codes: 0 ok / verify ok; 1 verify mismatch; 2 usage; 3 sandbox
 * unavailable; 4 runtime failure (spawn/io/allocation, logged to stderr).
 */

#include "base/hex.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/clock.h"
#include "platform/os_sandbox.h"
#include "sha3/sha3.h"
#include "zdogfight/zdogfight.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h> /* __NR_execve/__NR_execveat filter-out */
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define AR_REPLAY_MAGIC "ZDOGREPL" /* 8 bytes */
#define AR_REPLAY_MAGIC_LEN 8u
#define AR_REPLAY_VERSION 1u
#define AR_HEADER_LEN (AR_REPLAY_MAGIC_LEN + 4u + 8u + 1u)
#define AR_MAX_REPLAY_BYTES                                              \
    (AR_HEADER_LEN + (size_t)ZDOG_TICK_LIMIT * ZDOG_MAX_PLANES *         \
                         ZDOG_CTL_WIRE_LEN +                             \
     (size_t)ZDOG_STATE_WIRE_MAX)

#define AR_CHAIN_DOMAIN "zdogfight-replay-v1" /* 19 bytes, no NUL */
#define AR_CHAIN_DOMAIN_LEN 19u
#define AR_CHAIN_FOLD_INTERVAL 600u

/* CPU-seconds budget per pilot. A sane pilot answers each 82-byte obs in
 * microseconds of CPU; 30 s is generous headroom and still guarantees a
 * looping pilot is SIGXCPU-killed and then detected via EOF. */
#define AR_PILOT_CPU_SECONDS 30u

/* Child exit codes (match the package_verify.c child convention). */
#define AR_CHILD_SANDBOX_FAIL 70
#define AR_CHILD_EXEC_FAIL 127

struct ar_pilot {
    const char *path;
    pid_t pid;
    int fd_in;  /* runner writes obs frames here (child's stdin)  */
    int fd_out; /* runner reads ctl frames here (child's stdout) */
    bool dead;
    uint64_t dead_tick; /* m.tick at the moment death was detected */
    /* KPI (M7): cumulative wall ns inside the obs->ctl exchange loop and
     * the number of per-plane exchanges attempted. Runner-side wall clock
     * only; never enters match state. */
    uint64_t wait_ns;
    uint64_t exchanges;
};

static void ar_log_err(const char *what, const char *detail)
{
    fprintf(stderr, "arena_runner: error: %s%s%s\n", what,
            detail ? ": " : "", detail ? detail : "");
}

static void ar_usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  arena_runner --seed <u64> --planes-per-team <1..4>\n"
            "      --pilot-red <path> --pilot-blue <path>\n"
            "      [--replay-out <file>] [--no-sandbox]\n"
            "  arena_runner --verify-replay <file>\n"
            "      [--expect-replay-root <64hex>]\n");
}

/* Write exactly len bytes; false on any error/short write (EPIPE when the
 * pilot is gone — SIGPIPE is ignored in main). */
static bool ar_write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, buf + done, len - done);
        if (w <= 0)
            return false;
        done += (size_t)w;
    }
    return true;
}

/* Read exactly len bytes; 1 ok, 0 on EOF or error (pilot gone). */
static int ar_read_full(int fd, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, buf + done, len - done);
        if (r <= 0)
            return 0;
        done += (size_t)r;
    }
    return 1;
}

/* Child entry: wire the pipes onto stdin/stdout, confine, exec the pilot.
 * Never returns. extra_close lists parent-side fds of the OTHER pilot that
 * this child inherited across fork and must not hold. Matches the
 * package_verify.c pv_run_child ordering: rlimits, no_new_privs, Landlock,
 * seccomp, exec. */
static void ar_pilot_child(const char *path, int in_fd, int out_fd,
                           const int *extra_close, size_t n_extra,
                           bool sandbox)
{
    if (dup2(in_fd, STDIN_FILENO) < 0 || dup2(out_fd, STDOUT_FILENO) < 0)
        _exit(AR_CHILD_EXEC_FAIL);
    if (in_fd != STDIN_FILENO && in_fd != STDOUT_FILENO)
        close(in_fd);
    if (out_fd != STDIN_FILENO && out_fd != STDOUT_FILENO)
        close(out_fd);
    for (size_t i = 0; i < n_extra; i++)
        close(extra_close[i]);

    /* RLIMIT_CPU (plus the session resource caps) in BOTH modes: the CPU
     * budget is what bounds a stuck pilot without any wall clock, sandbox
     * or not. In the sandboxed mode os_sandbox_enter applies this same set
     * as profile step 2. */
    if (sandbox) {
        /* Single read+execute grant on the pilot binary ITSELF: Landlock's
         * exec open check requires READ_FILE (and EXECUTE once handled) on
         * the image, so a literal zero-grant domain makes the execve below
         * EACCES. Everything else on the filesystem is denied; the
         * pre-opened pipe fds (now stdin/stdout) survive Landlock. */
        struct os_sandbox_path_rule rules[] = {
            { .path = path, .allow_read = true, .allow_execute = true },
        };
        struct os_sandbox_profile profile =
            os_sandbox_session_child_profile(rules, 1);
        profile.rlimits.cpu_seconds = AR_PILOT_CPU_SECONDS;
        /* The session deny-list kills execve/execveat, which would kill
         * the ONE exec this child exists to perform (package_verify's
         * g_pv_child_denied omits them for the same reason). Filter the
         * blessed session set instead of hand-rolling a parallel one;
         * after the exec, re-exec of anything else is EACCES under the
         * one-file Landlock grant. */
        size_t n_session = 0;
        const int *session = os_sandbox_session_denied_syscalls(&n_session);
        int denied[64];
        size_t n_denied = 0;
        for (size_t i = 0; i < n_session; i++) {
#ifdef __NR_execve
            if (session[i] == __NR_execve)
                continue;
#endif
#ifdef __NR_execveat
            if (session[i] == __NR_execveat)
                continue;
#endif
            if (n_denied < sizeof(denied) / sizeof(denied[0]))
                denied[n_denied++] = session[i];
        }
        profile.denied_syscalls = denied;
        profile.n_denied = n_denied;
        struct zcl_result r = os_sandbox_enter(&profile);
        if (!zcl_result_is_ok(r)) {
            fprintf(stderr, "arena_runner: pilot sandbox enter failed: %s\n",
                    r.message);
            _exit(AR_CHILD_SANDBOX_FAIL);
        }
    } else {
        struct os_sandbox_rlimits lim = os_sandbox_session_rlimits();
        lim.cpu_seconds = AR_PILOT_CPU_SECONDS;
        struct zcl_result r = os_sandbox_set_rlimits(&lim);
        if (!zcl_result_is_ok(r)) {
            fprintf(stderr, "arena_runner: pilot rlimits failed: %s\n",
                    r.message);
            _exit(AR_CHILD_SANDBOX_FAIL);
        }
    }

    /* Scrub the inherited environment (the operator's shell env can carry
     * credentials untrusted pilot code must never see) — same rule as
     * package_verify's child. */
    char *const child_argv[] = { (char *)path, NULL };
    char *const child_envp[] = {
        (char *)"PATH=/usr/local/bin:/usr/bin:/bin",
        (char *)"LC_ALL=C",
        NULL,
    };
    execve(path, child_argv, child_envp);
    fprintf(stderr, "arena_runner: execve %s failed: errno=%d (%s)\n", path,
            errno, strerror(errno));
    _exit(AR_CHILD_EXEC_FAIL);
}

/* Fork and exec one confined pilot with interactive stdin/stdout pipes.
 * The pipes are created (pre-opened) BEFORE the child applies confinement;
 * fds survive Landlock. */
static bool ar_pilot_spawn(struct ar_pilot *p, const char *path, bool sandbox,
                           const int *extra_close, size_t n_extra)
{
    int in_pipe[2] = { -1, -1 };  /* runner -> pilot */
    int out_pipe[2] = { -1, -1 }; /* pilot -> runner */
    if (pipe(in_pipe) != 0) {
        ar_log_err("pipe(stdin) failed for pilot", path);
        return false;
    }
    if (pipe(out_pipe) != 0) {
        ar_log_err("pipe(stdout) failed for pilot", path);
        close(in_pipe[0]);
        close(in_pipe[1]);
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        ar_log_err("fork failed for pilot", path);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return false;
    }
    if (pid == 0) {
        /* Child: single-threaded dev tool, no other thread holds a lock. */
        close(in_pipe[1]);
        close(out_pipe[0]);
        ar_pilot_child(path, in_pipe[0], out_pipe[1], extra_close, n_extra,
                       sandbox);
        /* not reached */
        _exit(AR_CHILD_EXEC_FAIL);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    p->path = path;
    p->pid = pid;
    p->fd_in = in_pipe[1];
    p->fd_out = out_pipe[0];
    p->dead = false;
    p->dead_tick = 0;
    return true;
}

/* Close a pilot's pipes and reap it. Cleanup only — the match outcome is
 * already decided, so a short bounded grace then SIGKILL is fine here. */
static void ar_pilot_reap(struct ar_pilot *p)
{
    if (p->fd_in >= 0) {
        close(p->fd_in); /* EOF: a live well-behaved pilot exits 0 */
        p->fd_in = -1;
    }
    if (p->fd_out >= 0) {
        close(p->fd_out);
        p->fd_out = -1;
    }
    if (p->pid <= 0)
        return;
    int status = 0;
    for (unsigned i = 0; i < 200; i++) {
        if (waitpid(p->pid, &status, WNOHANG) == p->pid) {
            p->pid = -1;
            return;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        nanosleep(&ts, NULL);
    }
    /* Still alive (e.g. CPU-looping until its rlimit kill): stop waiting. */
    kill(p->pid, SIGKILL);
    (void)waitpid(p->pid, &status, 0);
    p->pid = -1;
}

static const zdog_ctl AR_NEUTRAL_CTL = { 0, 0, 0, 0 };

/* Gather one team's per-plane controls for the current tick. Living planes
 * of a live pilot get the obs->ctl exchange; everything else (dead planes,
 * dead pilot) gets neutral. If the pilot dies mid-team, the WHOLE team
 * reverts to neutral from this tick onward so the death tick itself is
 * fully deterministic. */
static void ar_gather_team_ctls(zdog_match *m, struct ar_pilot *p,
                                unsigned team, unsigned planes_per_team,
                                zdog_ctl *ctls)
{
    const unsigned first = team * planes_per_team;
    bool failed = false;
    for (unsigned k = 0; k < planes_per_team; k++) {
        const unsigned idx = first + k;
        if (!m->planes[idx].alive || p->dead) {
            ctls[idx] = AR_NEUTRAL_CTL;
            continue;
        }
        zdog_obs obs;
        zdog_observe(m, idx, &obs);
        uint8_t obs_wire[ZDOG_OBS_WIRE_LEN];
        if (zdog_obs_encode(&obs, obs_wire, sizeof(obs_wire)) !=
            sizeof(obs_wire)) {
            /* Codec failure on a fixed-size frame is a runner bug, not a
             * pilot fault; fail the pilot deterministically. */
            ar_log_err("zdog_obs_encode short frame", p->path);
            failed = true;
        } else if (!ar_write_full(p->fd_in, obs_wire, sizeof(obs_wire))) {
            failed = true;
        } else {
            uint8_t ctl_wire[ZDOG_CTL_WIRE_LEN];
            if (ar_read_full(p->fd_out, ctl_wire, sizeof(ctl_wire)) != 1 ||
                !zdog_ctl_decode(ctl_wire, sizeof(ctl_wire), &ctls[idx]))
                failed = true;
        }
        if (failed) {
            p->dead = true;
            p->dead_tick = m->tick;
            fprintf(stderr,
                    "arena_runner: pilot team %u (%s) died at tick %llu; "
                    "neutral controls from this tick onward\n",
                    team, p->path, (unsigned long long)m->tick);
            for (unsigned j = 0; j < planes_per_team; j++)
                ctls[first + j] = AR_NEUTRAL_CTL;
            return;
        }
    }
}

/* sha3-256 one-shot into a 32-byte digest. */static void ar_sha3(const uint8_t *data, size_t len,
                    uint8_t out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, out);
}

/* chain = sha3(chain || checksum_le64) */
static void ar_chain_fold(uint8_t chain[SHA3_256_OUTPUT_SIZE],
                          uint64_t checksum)
{
    uint8_t buf[SHA3_256_OUTPUT_SIZE + 8u];
    memcpy(buf, chain, SHA3_256_OUTPUT_SIZE);
    zcl_write_u64_le(buf + SHA3_256_OUTPUT_SIZE, checksum);
    ar_sha3(buf, sizeof(buf), chain);
}

static void ar_print_hex(const char *label,
                         const uint8_t digest[SHA3_256_OUTPUT_SIZE])
{
    char hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    zcl_hex_encode(digest, SHA3_256_OUTPUT_SIZE, hex);
    printf("%s=%s\n", label, hex);
}

static const char *ar_winner_name(uint8_t winner)
{
    switch (winner) {
    case ZDOG_WINNER_RED:  return "red";
    case ZDOG_WINNER_BLUE: return "blue";
    default:               return "draw";
    }
}

static void ar_print_pilot_status(const char *label, const struct ar_pilot *p)
{
    if (p->dead)
        printf("%s=dead@%llu", label, (unsigned long long)p->dead_tick);
    else
        printf("%s=ok", label);
}

static bool ar_parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s || s[0] == '-' || s[0] == '+')
        return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return false;
    *out = (uint64_t)v;
    return true;
}

/* Initialise the rolling state-root chain:
 * chain0 = sha3("zdogfight-replay-v1" || seed_le64 || planes_u8). */
static void ar_chain_init(uint8_t chain[SHA3_256_OUTPUT_SIZE], uint64_t seed,
                          uint8_t planes_per_team)
{
    uint8_t hdr[AR_CHAIN_DOMAIN_LEN + 8u + 1u];
    memcpy(hdr, AR_CHAIN_DOMAIN, AR_CHAIN_DOMAIN_LEN);
    zcl_write_u64_le(hdr + AR_CHAIN_DOMAIN_LEN, seed);
    hdr[AR_CHAIN_DOMAIN_LEN + 8u] = planes_per_team;
    ar_sha3(hdr, sizeof(hdr), chain);
}

/* Write the replay header (magic, version, seed, planes) into buf. */
static void ar_replay_header(uint8_t *buf, uint64_t seed,
                             uint8_t planes_per_team)
{
    memcpy(buf, AR_REPLAY_MAGIC, AR_REPLAY_MAGIC_LEN);
    zcl_write_u32_le(buf + AR_REPLAY_MAGIC_LEN, AR_REPLAY_VERSION);
    zcl_write_u64_le(buf + AR_REPLAY_MAGIC_LEN + 4u, seed);
    buf[AR_REPLAY_MAGIC_LEN + 4u + 8u] = planes_per_team;
}

static int ar_run_match(uint64_t seed, unsigned planes_per_team,
                        const char *pilot_red_path, const char *pilot_blue_path,
                        const char *replay_out, bool sandbox)
{
    if (sandbox &&
        (os_sandbox_landlock_abi() < 0 || !os_sandbox_seccomp_supported())) {
        fprintf(stderr,
                "arena_runner: FATAL: sandbox unavailable on this host "
                "(landlock_abi=%d seccomp_supported=%d); rerun with "
                "--no-sandbox for dev debugging (UNCONFINED)\n",
                os_sandbox_landlock_abi(),
                os_sandbox_seccomp_supported() ? 1 : 0);
        return 3;
    }
    if (!sandbox)
        fprintf(stderr,
                "arena_runner: WARNING: --no-sandbox in effect — pilots run "
                "UNCONFINED (no Landlock/seccomp); dev debugging only\n");

    /* Writes to a dead pilot must return EPIPE, not kill the runner. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        ar_log_err("signal(SIGPIPE, SIG_IGN) failed", strerror(errno));

    /* Bounded replay buffer, sized for the absolute worst case; the cap is
     * a hard limit, never silently truncated. */
    uint8_t *replay = zcl_malloc(AR_MAX_REPLAY_BYTES, "arena.replay");
    if (!replay) {
        ar_log_err("malloc replay buffer failed", "size capped at ~2 MiB");
        return 4;
    }
    ar_replay_header(replay, seed, (uint8_t)planes_per_team);
    size_t replay_len = AR_HEADER_LEN;

    zdog_match m;
    zdog_match_init(&m, seed, planes_per_team);
    const unsigned num_planes = 2u * planes_per_team;

    struct ar_pilot red = { .pid = -1, .fd_in = -1, .fd_out = -1 };
    struct ar_pilot blue = { .pid = -1, .fd_in = -1, .fd_out = -1 };
    if (!ar_pilot_spawn(&red, pilot_red_path, sandbox, NULL, 0)) {
        free(replay);
        return 4;
    }
    int red_fds[2] = { red.fd_in, red.fd_out };
    if (!ar_pilot_spawn(&blue, pilot_blue_path, sandbox, red_fds, 2)) {
        ar_pilot_reap(&red);
        free(replay);
        return 4;
    }

    uint8_t chain[SHA3_256_OUTPUT_SIZE];
    ar_chain_init(chain, seed, (uint8_t)planes_per_team);

    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < num_planes; i++)
            ctls[i] = AR_NEUTRAL_CTL;
        /* Runner-side KPI timing via the platform clock (never enters
         * match state). */
        uint64_t t0 = (uint64_t)clock_now_monotonic_ns();
        ar_gather_team_ctls(&m, &red, 0, planes_per_team, ctls);
        red.wait_ns += (uint64_t)clock_now_monotonic_ns() - t0;
        red.exchanges++;
        t0 = (uint64_t)clock_now_monotonic_ns();
        ar_gather_team_ctls(&m, &blue, 1, planes_per_team, ctls);
        blue.wait_ns += (uint64_t)clock_now_monotonic_ns() - t0;
        blue.exchanges++;
        zdog_tick(&m, ctls);

        /* Append every plane's ctl frame (index order; dead planes' neutral
         * frames included) to the replay. */
        const size_t tick_bytes = num_planes * ZDOG_CTL_WIRE_LEN;
        if (replay_len + tick_bytes + ZDOG_STATE_WIRE_MAX >
            AR_MAX_REPLAY_BYTES) {
            ar_log_err("replay buffer cap exceeded", "refusing to truncate");
            ar_pilot_reap(&red);
            ar_pilot_reap(&blue);
            free(replay);
            return 4;
        }
        for (unsigned i = 0; i < num_planes; i++) {
            size_t n = zdog_ctl_encode(&ctls[i], replay + replay_len,
                                       ZDOG_CTL_WIRE_LEN);
            if (n != ZDOG_CTL_WIRE_LEN) {
                ar_log_err("zdog_ctl_encode short frame", "runner bug");
                ar_pilot_reap(&red);
                ar_pilot_reap(&blue);
                free(replay);
                return 4;
            }
            replay_len += n;
        }
        if (m.tick % AR_CHAIN_FOLD_INTERVAL == 0)
            ar_chain_fold(chain, zdog_state_checksum(&m));
    }

    /* Trailing final state encoding, exactly ZDOG_STATE_WIRE_MAX bytes. */
    size_t state_len =
        zdog_state_encode(&m, replay + replay_len, ZDOG_STATE_WIRE_MAX);
    if (state_len != ZDOG_STATE_WIRE_MAX) {
        ar_log_err("zdog_state_encode short", "runner bug");
        ar_pilot_reap(&red);
        ar_pilot_reap(&blue);
        free(replay);
        return 4;
    }
    replay_len += state_len;

    /* Match over: close pilot stdins (EOF -> pilots exit 0), reap. */
    ar_pilot_reap(&red);
    ar_pilot_reap(&blue);

    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t final_state_root[SHA3_256_OUTPUT_SIZE];
    ar_sha3(replay, replay_len, replay_root);
    ar_sha3(replay + replay_len - ZDOG_STATE_WIRE_MAX, ZDOG_STATE_WIRE_MAX,
            final_state_root);

    if (replay_out) {
        FILE *f = fopen(replay_out, "wb");
        if (!f) {
            ar_log_err("open replay-out failed", replay_out);
            free(replay);
            return 4;
        }
        if (fwrite(replay, 1, replay_len, f) != replay_len) {
            ar_log_err("write replay-out failed", replay_out);
            fclose(f);
            free(replay);
            return 4;
        }
        if (fclose(f) != 0) {
            ar_log_err("close replay-out failed", replay_out);
            free(replay);
            return 4;
        }
    }

    printf("seed=%llu planes_per_team=%u ticks=%llu\n",
           (unsigned long long)seed, planes_per_team,
           (unsigned long long)m.tick);
    printf("score_red=%u score_blue=%u winner=%s\n", m.score[0], m.score[1],
           ar_winner_name(m.winner));
    ar_print_hex("replay_root", replay_root);
    ar_print_hex("final_state_root", final_state_root);
    ar_print_hex("state_root_chain", chain);
    ar_print_pilot_status("pilot_red_status", &red);
    putchar(' ');
    ar_print_pilot_status("pilot_blue_status", &blue);
    putchar('\n');
    printf("pilot_red_avg_response_us=%llu pilot_blue_avg_response_us=%llu\n",
           (unsigned long long)(red.exchanges ? red.wait_ns / 1000ull /
                                                red.exchanges
                                              : 0ull),
           (unsigned long long)(blue.exchanges ? blue.wait_ns / 1000ull /
                                                  blue.exchanges
                                               : 0ull));

    free(replay);
    return 0;
}

/* Read an entire file (bounded by AR_MAX_REPLAY_BYTES) into a fresh heap
 * buffer. NULL on failure (logged). */
static uint8_t *ar_read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        ar_log_err("open failed", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        ar_log_err("fseek failed", path);
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || (unsigned long)sz > AR_MAX_REPLAY_BYTES) {
        ar_log_err("bad size (0 or above replay cap)", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        ar_log_err("fseek(set) failed", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = zcl_malloc((size_t)sz ? (size_t)sz : 1u, "arena.verify");
    if (!buf) {
        ar_log_err("malloc failed for replay file", path);
        fclose(f);
        return NULL;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        ar_log_err("short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

static int ar_verify_mismatch(const char *what)
{
    printf("verify=MISMATCH %s\n", what);
    return 1;
}

static int ar_verify_replay(const char *path, const char *expected_root_hex)
{
    size_t len = 0;
    uint8_t *buf = ar_read_file(path, &len);
    if (!buf)
        return 1;

    int rc = 1;
    if (len < AR_HEADER_LEN + ZDOG_STATE_WIRE_MAX) {
        rc = ar_verify_mismatch("truncated");
        goto out;
    }
    if (memcmp(buf, AR_REPLAY_MAGIC, AR_REPLAY_MAGIC_LEN) != 0) {
        rc = ar_verify_mismatch("header-magic");
        goto out;
    }
    if (zcl_read_u32_le(buf + AR_REPLAY_MAGIC_LEN) != AR_REPLAY_VERSION) {
        rc = ar_verify_mismatch("header-version");
        goto out;
    }
    const uint64_t seed = zcl_read_u64_le(buf + AR_REPLAY_MAGIC_LEN + 4u);
    const uint8_t planes_per_team = buf[AR_REPLAY_MAGIC_LEN + 4u + 8u];
    if (planes_per_team < 1 || planes_per_team > 4) {
        rc = ar_verify_mismatch("header-planes");
        goto out;
    }
    const unsigned num_planes = 2u * planes_per_team;
    const size_t tick_bytes = num_planes * ZDOG_CTL_WIRE_LEN;
    const size_t frames_len = len - AR_HEADER_LEN - ZDOG_STATE_WIRE_MAX;
    if (frames_len % tick_bytes != 0) {
        rc = ar_verify_mismatch("size");
        goto out;
    }
    const uint64_t recorded_ticks = frames_len / tick_bytes;

    /* Re-apply the recorded ctl frames tick by tick with NO pilots. */
    zdog_match m;
    zdog_match_init(&m, seed, planes_per_team);
    uint8_t chain[SHA3_256_OUTPUT_SIZE];
    ar_chain_init(chain, seed, planes_per_team);
    const uint8_t *fp = buf + AR_HEADER_LEN;
    for (uint64_t t = 0; t < recorded_ticks; t++) {
        zdog_ctl ctls[ZDOG_MAX_PLANES];
        for (unsigned i = 0; i < num_planes; i++) {
            if (!zdog_ctl_decode(fp, ZDOG_CTL_WIRE_LEN, &ctls[i])) {
                rc = ar_verify_mismatch("ctl-frame");
                goto out;
            }
            fp += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(&m, ctls);
        if (m.tick % AR_CHAIN_FOLD_INTERVAL == 0)
            ar_chain_fold(chain, zdog_state_checksum(&m));
    }
    /* The match must have gone DONE at EXACTLY the recorded tick count:
     * if it finished early, zdog_tick no-ops and m.tick stops short; if it
     * never finished, phase is still RUNNING. */
    if (m.phase != ZDOG_PHASE_DONE) {
        rc = ar_verify_mismatch("match-incomplete");
        goto out;
    }
    if (m.tick != recorded_ticks) {
        rc = ar_verify_mismatch("tick-count");
        goto out;
    }
    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&m, state, sizeof(state)) != sizeof(state)) {
        ar_log_err("zdog_state_encode short", "runner bug");
        rc = 4;
        goto out;
    }
    /* Byte-exact comparison against the file's trailing state block — this
     * subsumes comparing the two roots. */
    if (memcmp(state, fp, ZDOG_STATE_WIRE_MAX) != 0) {
        rc = ar_verify_mismatch("final-state");
        goto out;
    }

    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t final_state_root[SHA3_256_OUTPUT_SIZE];
    ar_sha3(buf, len, replay_root);
    ar_sha3(state, sizeof(state), final_state_root);
    if (expected_root_hex) {
        uint8_t expected_root[SHA3_256_OUTPUT_SIZE];
        if (!zcl_hex_decode(expected_root_hex, expected_root,
                            sizeof(expected_root))) {
            ar_log_err("bad --expect-replay-root (want 64 hex)",
                       expected_root_hex);
            rc = 2;
            goto out;
        }
        if (memcmp(replay_root, expected_root, sizeof(replay_root)) != 0) {
            rc = ar_verify_mismatch("replay-root");
            goto out;
        }
    }

    printf("seed=%llu planes_per_team=%u ticks=%llu\n",
           (unsigned long long)seed, (unsigned)planes_per_team,
           (unsigned long long)m.tick);
    printf("score_red=%u score_blue=%u winner=%s\n", m.score[0], m.score[1],
           ar_winner_name(m.winner));
    ar_print_hex("replay_root", replay_root);
    ar_print_hex("final_state_root", final_state_root);
    ar_print_hex("state_root_chain", chain);
    printf("verify=ok\n");
    rc = 0;
out:
    free(buf);
    return rc;
}

int main(int argc, char **argv)
{
    const char *seed_s = NULL;
    const char *planes_s = NULL;
    const char *pilot_red = NULL;
    const char *pilot_blue = NULL;
    const char *replay_out = NULL;
    const char *verify_replay = NULL;
    const char *expected_replay_root = NULL;
    bool no_sandbox = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = NULL;
        /* --name value  and  --name=value  are both accepted. */
        char name[64];
        const char *eq = strchr(a, '=');
        size_t nl = eq ? (size_t)(eq - a) : strlen(a);
        if (nl == 0 || nl >= sizeof(name)) {
            ar_log_err("bad argument", a);
            ar_usage(stderr);
            return 2;
        }
        memcpy(name, a, nl);
        name[nl] = '\0';
        if (eq)
            v = eq + 1;
        else if (i + 1 < argc)
            v = argv[i + 1];
        bool takes_value = true;
        if (strcmp(name, "--seed") == 0)
            seed_s = v;
        else if (strcmp(name, "--planes-per-team") == 0)
            planes_s = v;
        else if (strcmp(name, "--pilot-red") == 0)
            pilot_red = v;
        else if (strcmp(name, "--pilot-blue") == 0)
            pilot_blue = v;
        else if (strcmp(name, "--replay-out") == 0)
            replay_out = v;
        else if (strcmp(name, "--verify-replay") == 0)
            verify_replay = v;
        else if (strcmp(name, "--expect-replay-root") == 0)
            expected_replay_root = v;
        else if (strcmp(name, "--no-sandbox") == 0)
            takes_value = false, no_sandbox = true;
        else if (strcmp(name, "--help") == 0) {
            ar_usage(stdout);
            return 0;
        } else {
            ar_log_err("unknown argument", a);
            ar_usage(stderr);
            return 2;
        }
        if (takes_value) {
            if (!v) {
                ar_log_err("missing value for", name);
                ar_usage(stderr);
                return 2;
            }
            if (!eq)
                i++; /* consume the separate value token */
        }
    }

    if (verify_replay) {
        /* Fail closed on mixed modes. */
        if (seed_s || planes_s || pilot_red || pilot_blue || replay_out ||
            no_sandbox) {
            ar_log_err("--verify-replay does not combine with match args",
                       NULL);
            ar_usage(stderr);
            return 2;
        }
        return ar_verify_replay(verify_replay, expected_replay_root);
    }

    if (expected_replay_root) {
        ar_log_err("--expect-replay-root requires --verify-replay", NULL);
        ar_usage(stderr);
        return 2;
    }

    if (!seed_s || !planes_s || !pilot_red || !pilot_blue) {
        ar_log_err("missing required argument(s)",
                   "--seed --planes-per-team --pilot-red --pilot-blue");
        ar_usage(stderr);
        return 2;
    }
    uint64_t seed = 0;
    uint64_t planes = 0;
    if (!ar_parse_u64(seed_s, &seed)) {
        ar_log_err("bad --seed (want decimal u64)", seed_s);
        return 2;
    }
    if (!ar_parse_u64(planes_s, &planes) || planes < 1 || planes > 4) {
        ar_log_err("bad --planes-per-team (want 1..4)", planes_s);
        return 2;
    }
    return ar_run_match(seed, (unsigned)planes, pilot_red, pilot_blue,
                        replay_out, !no_sandbox);
}
