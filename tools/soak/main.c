/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 7-day soak runner (MVP criterion #6).
 *
 * Separate binary that polls a running z23 every 60 s for
 * a configured duration (default 7 days), feeds each sample
 * through the soak_harness analyzer, writes a timestamped log,
 * and exits non-zero if the run tripped any verdict rule (crash,
 * tip stall, RSS walk, too-short, no-samples).
 *
 * Intentionally minimal — bounded RPC envelope parsing, no libevent, no
 * threads. Every signal the verdict cares about comes from
 * either /proc (/proc/<pid>/status → VmRSS) or one-shot fork/exec
 * of `build/bin/zcl-rpc getblockcount` (integer result is trivial to
 * extract from a complete success envelope). The runner doesn't try to
 * recover from a dead node — if the node goes down, the runner
 * keeps polling, records the crash sample, and lets the verdict
 * logic flip to FAIL_CRASH.
 *
 * Two run modes
 * -------------
 *
 *   PIDOF (default, operational): poll a *live, externally-managed*
 *   node found by `pidof <service>` — this is the `make soak-7day` /
 *   `make soak-smoke` path against the installed systemd node. The
 *   runner does NOT own that process; it samples and scores only.
 *
 *   SPAWN (`--node-datadir=DIR`, hermetic): the runner OWNS an
 *   isolated regtest node it forks/execs itself, samples ITS OWN
 *   child pid directly (never `pidof`, which would hit the live
 *   node), and — with `--load=generate:N` — injects synthetic load by
 *   mining one block every N seconds via `zcl-rpc generate 1`. This is
 *   the `make soak-ci` compressed-soak proxy. Isolation (the /tmp
 *   datadir, 39xxx ports, refuse-on-live preflight, process-group kill
 *   and cleanup trap) is provided by the *make target* via
 *   tools/scripts/isolated_node_env.sh; this runner is handed an
 *   already-validated datadir + rpcport.
 *
 * CRITICAL isolation rule (spawn mode): EVERY zcl-rpc invocation is
 * made with ZCL_DATADIR + ZCL_RPCPORT pinned to the isolated node, so
 * zcl-rpc can never fall through to the live default RPC port (18232).
 *
 * Usage:
 *     make soak-7day                   (7 days, against installed z23)
 *     make soak-ci                     (compressed hermetic proxy)
 *     build/bin/soak_runner --help
 *
 * Flags:
 *     --duration-sec=N      total run length (default 7d = 604800)
 *     --interval-sec=N      poll interval (default 60)
 *     --service=NAME        process name to pidof (pidof mode, default z23)
 *     --rpc=PATH            zcl-rpc binary (default build/bin/zcl-rpc)
 *     --log=PATH            output log (default ./soak-YYYYMMDD-HHMM.log)
 *     --stall-sec=N         tip stall threshold (default 1800)
 *     --rss-growth-mib=N    RSS walk threshold (default 512)
 *     --warmup-sec=N        RSS baseline warmup (default 1800)
 *   Spawn-mode (hermetic CI proxy):
 *     --node-datadir=DIR    spawn+own an isolated node on this datadir
 *     --rpcport=N           isolated node RPC port (pinned on every zcl-rpc)
 *     --p2p-port=N          isolated node P2P port
 *     --fs-port=N           isolated node file-service port
 *     --https-port=N        isolated node HTTPS port
 *     --connect=HOST:PORT   single -connect peer (dead sink → no peers)
 *     --load=generate:N     mine 1 block every N seconds (synthetic load)
 *     --ci-proxy            use the accelerated CI-proxy thresholds
 */

#if !defined(SOAK_CLEANUP_TEST)
#define _POSIX_C_SOURCE 200809L

#include "platform/time_compat.h"
#include "test/soak_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

#endif

/* ── Spawn-mode config (the hermetic CI-proxy path) ──────────────
 *
 * When node_datadir is non-empty the runner OWNS the node: it forks
 * an isolated regtest node, samples that child's pid directly, and
 * (optionally) injects generate-load. Every zcl-rpc call is pinned to
 * (datadir, rpcport) so it can never touch the live node. */
struct spawn_cfg {
    bool  enabled;
    char  datadir[512];
    int   rpcport;
    int   p2p_port;
    int   fs_port;
    int   https_port;
    char  connect[128];
    int   load_interval; /* >0: `generate 1` every N seconds; 0: off */
    pid_t pid;           /* the owned child (the ONLY pid we sample) */
};

#if !defined(SOAK_CLEANUP_TEST)
static const char *rpc_space(const char *p)
{
    return p + strspn(p, " \t\n\r");
}

/* Read a nonnegative result value; the caller validates the envelope. */
static bool scan_decimal_result(const char *p, int64_t *out)
{
    p = rpc_space(p);
    if (*p < '0' || *p > '9') return false;
    if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(p, &end, 10);
    if (end == p || errno == ERANGE || v < 0) return false;
    end += strspn(end, " \t\n\r");
    if (*end != ',' && *end != '}') return false;
    *out = (int64_t)v;
    return true;
}

/* Only the integer-height success envelope is needed. ID 1 is sent by
 * zcl-rpc; optional error/id fields retain the minimal result-only form.
 * No output is assigned until the entire record has been accepted. */
static unsigned rpc_height_member(const char **cursor, int64_t *height)
{
    const char *p = *cursor;
    unsigned field;
    if (strncmp(p, "\"result\"", 8) == 0) { field = 1; p += 8; }
    else if (strncmp(p, "\"error\"", 7) == 0) { field = 2; p += 7; }
    else if (strncmp(p, "\"id\"", 4) == 0) { field = 4; p += 4; }
    else return 0;
    p = rpc_space(p);
    if (*p != ':') return 0;
    p = rpc_space(p + 1);
    if (field == 1) {
        if (!scan_decimal_result(p, height)) return 0;
        char *end = NULL;
        (void)strtoll(p, &end, 10);
        p = end;
    } else if (field == 2) {
        if (strncmp(p, "null", 4) != 0) return 0;
        p += 4;
    } else {
        if (*p != '1') return 0;
        p++;
    }
    *cursor = rpc_space(p);
    return field;
}

static bool scan_result_int(const char *buf, int64_t *out)
{
    const char *p = rpc_space(buf);
    if (*p != '{') return false;
    unsigned seen = 0;
    int64_t height = 0;
    do {
        p = rpc_space(p + 1);
        unsigned field = rpc_height_member(&p, &height);
        if (!field || (seen & field)) return false;
        seen |= field;
    } while (*p == ',');
    if (*p != '}' || *rpc_space(p + 1) != '\0' || !(seen & 1)) return false;
    *out = height;
    return true;
}

static void capture_child_exec(int write_fd, const char *program,
                               char *const argv[], const struct spawn_cfg *sp)
{
    if (dup2(write_fd, STDOUT_FILENO) < 0) _exit(127);
    close(write_fd);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        (void)dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
    if (sp && sp->enabled) {
        char port[16];
        snprintf(port, sizeof(port), "%d", sp->rpcport);
        if (setenv("ZCL_DATADIR", sp->datadir, 1) != 0 ||
            setenv("ZCL_RPCPORT", port, 1) != 0)
            _exit(127);
    }
    execvp(program, argv);
    _exit(127);
}

static bool capture_read_all(int fd, char *out, size_t cap)
{
    size_t used = 0;
    bool complete = false;
    while (used < cap - 1) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n > 0) { used += (size_t)n; continue; }
        if (n == 0) { complete = true; break; }
        if (errno != EINTR) break;
    }
    if (!complete && used == cap - 1) {
        char extra;
        ssize_t n;
        do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
        complete = n == 0;
    }
    bool text_only = memchr(out, '\0', used) == NULL;
    out[used] = '\0';
    return complete && used > 0 && text_only;
}

/* Capture one child without invoking a shell. A full buffer is an error:
 * accepting a truncated prefix could turn malformed RPC output into a height. */
static bool capture_argv(const char *program, char *const argv[],
                         const struct spawn_cfg *sp, char *out, size_t cap)
{
    if (!program || !program[0] || !out || cap < 2) return false;
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (child == 0) {
        close(fds[0]);
        capture_child_exec(fds[1], program, argv, sp);
    }
    close(fds[1]);
    bool complete = capture_read_all(fds[0], out, cap);
    close(fds[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    return complete && waited == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static pid_t pidof_service(const char *service)
{
    char line[64];
    char *const argv[] = {"pidof", "-s", (char *)service, NULL};
    if (!capture_argv("pidof", argv, NULL, line, sizeof(line))) return 0;
    char *end = NULL;
    long pid = strtol(line, &end, 10);
    if (pid <= 0 || end == line) return 0;
    return (pid_t)pid;
}

static uint64_t rss_bytes_for(pid_t pid)
{
    if (pid <= 0) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    uint64_t rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            /* "VmRSS:\t   123456 kB" — kB to bytes. */
            char *p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            rss = (uint64_t)strtoull(p, NULL, 10) * 1024ULL;
            break;
        }
    }
    fclose(f);
    return rss;
}

/* Run `<rpc_bin> <method> [arg]` and return its stdout. In spawn mode the
 * ZCL_DATADIR + ZCL_RPCPORT env is PINNED to the isolated node so the
 * call can never reach the live node's default RPC port. `sp` may be
 * NULL (pidof mode) — then no env is forced and zcl-rpc uses its
 * defaults (the operator's live node). */
static bool rpc_capture(const struct spawn_cfg *sp, const char *rpc_bin,
                        const char *method, const char *arg,
                        char *out, size_t out_cap)
{
    char *const argv[] = {(char *)rpc_bin, (char *)method, (char *)arg, NULL};
    return capture_argv(rpc_bin, argv, sp, out, out_cap);
}

static bool height_via_rpc(const struct spawn_cfg *sp, const char *rpc_bin,
                          int64_t *out)
{
    char buf[8192];
    if (!rpc_capture(sp, rpc_bin, "getblockcount", NULL, buf, sizeof(buf)))
        return false;
    return scan_result_int(buf, out);
}

/* ── Spawn-mode node management ─────────────────────────────────── */

/* Fork+exec an isolated regtest node in its OWN process group (setsid),
 * recording the child pid in sp->pid. Mirrors the crash harness spawn:
 * -connect=<sink> blocks the auto-addnode-to-zclassicd trap, -fsport
 * overrides the live FS port, -nobgvalidation/-nolegacyimport keep it
 * lean and offline. */
static bool spawn_node(struct spawn_cfg *sp)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (setsid() < 0) (void)setpgid(0, 0);

        char dd[600], rpcp[64], p2p[64], fsp[64], httpsp[64], conn[160];
        snprintf(dd,    sizeof(dd),    "-datadir=%s", sp->datadir);
        snprintf(rpcp,  sizeof(rpcp),  "-rpcport=%d", sp->rpcport);
        snprintf(p2p,   sizeof(p2p),   "-port=%d", sp->p2p_port);
        snprintf(fsp,   sizeof(fsp),   "-fsport=%d", sp->fs_port);
        snprintf(httpsp,sizeof(httpsp),"-httpsport=%d", sp->https_port);
        snprintf(conn,  sizeof(conn),  "-connect=%s",
                 sp->connect[0] ? sp->connect : "127.0.0.1:39999");

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl("build/bin/zclassic23", "zclassic23",
              dd, "-regtest", rpcp, p2p, fsp, httpsp, conn,
              "-nobgvalidation", "-nolegacyimport", "-showmetrics=0",
              (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    sp->pid = pid;
    return true;
}

#endif

/* Send SIGKILL to the spawned node's process group, falling back on ESRCH.
 * Clear the owned pid only after reap or confirmed absence of a child. */
static void kill_spawned_node(struct spawn_cfg *sp)
{
    if (!sp || sp->pid <= 0) return;
    if (kill(-sp->pid, SIGKILL) != 0 && errno == ESRCH)
        kill(sp->pid, SIGKILL);
    int status;
    pid_t waited;
    do { waited = waitpid(sp->pid, &status, 0); }
    while (waited < 0 && errno == EINTR);
    if (waited == sp->pid || (waited < 0 && errno == ECHILD))
        sp->pid = 0;
    else
        fprintf(stderr, "soak: waitpid(%d) failed: %s\n",
                (int)sp->pid, strerror(errno));
}

#if !defined(SOAK_CLEANUP_TEST)
/* Poll the isolated RPC until getblockcount answers, or timeout. */
static bool spawn_wait_ready(struct spawn_cfg *sp, const char *rpc_bin,
                            int timeout_sec)
{
    time_t deadline = platform_time_wall_time_t() + timeout_sec;
    while (platform_time_wall_time_t() < deadline) {
        if (sp->pid > 0 && kill(sp->pid, 0) != 0) return false; /* died */
        int64_t h = 0;
        if (height_via_rpc(sp, rpc_bin, &h)) return true;
        platform_sleep_ms(250);
    }
    return false;
}

/* Inject synthetic load: mine one regtest block. Best-effort. */
static void spawn_generate_one(struct spawn_cfg *sp, const char *rpc_bin)
{
    char buf[16384];
    (void)rpc_capture(sp, rpc_bin, "generate", "1", buf, sizeof(buf));
}

static void default_log_path(char *out, size_t n)
{
    time_t t = platform_time_wall_time_t();
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(out, n, "soak-%04d%02d%02d-%02d%02d.log",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --duration-sec=N    total run length (default 604800 = 7d)\n"
        "  --interval-sec=N    poll interval (default 60)\n"
        "  --service=NAME      pidof target (pidof mode, default zclassic23)\n"
        "  --rpc=PATH          zcl-rpc binary (default build/bin/zcl-rpc)\n"
        "  --log=PATH          output log (default soak-YYYYMMDD-HHMM.log)\n"
        "  --stall-sec=N       tip-stall threshold (default 1800)\n"
        "  --rss-growth-mib=N  RSS-walk threshold MiB (default 512)\n"
        "  --warmup-sec=N      RSS baseline warmup (default 1800)\n"
        "  --ci-proxy          accelerated CI-proxy thresholds (180s/30s/96MiB)\n"
        " spawn mode (hermetic CI proxy — isolated /tmp regtest node):\n"
        "  --node-datadir=DIR  own+spawn an isolated node on this datadir\n"
        "  --rpcport=N         isolated RPC port (REQUIRED; pinned on every rpc)\n"
        "  --p2p-port=N        isolated P2P port (default rpcport-1)\n"
        "  --fs-port=N         isolated file-service port (default rpcport+1)\n"
        "  --https-port=N      isolated HTTPS port (default rpcport+2)\n"
        "  --connect=HOST:PORT single -connect peer (dead sink → 0 peers)\n"
        "  --load=generate:N   mine 1 block every N seconds (synthetic load)\n"
        "Exit status: 0 = SOAK_OK, else verdict ordinal.\n",
        argv0);
}

static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s) return false;
    *out = (uint64_t)v;
    return true;
}

/* Copy a --flag=PATH argument into its fixed buffer, refusing truncation
 * with exit status 2. snprintf discards the tail silently when the source
 * outgrows the buffer; an unchecked copy then reaches fopen or the spawned
 * node with a different argument. A truncated log basename may still be
 * valid and open a different file. All callers supply a nonzero capacity. */
static int soak_copy_path(const char *flag, char *dst, size_t cap,
                          const char *src)
{
    int n = snprintf(dst, cap, "%s", src);
    if (n < 0 || (size_t)n >= cap) {
        dst[0] = '\0';
        fprintf(stderr, "path argument too long: %s (max %zu characters)\n",
                flag, cap - 1);
        return 2;
    }
    return 0;
}

/* Post-parse validation the argument loop defers to: copy the three
 * path arguments under refusal-on-truncation, then the checks that used
 * to live inline in main. Returns 0, or the process exit status. */
static int soak_validate_args(uint64_t interval_sec, soak_thresholds_t *cfg,
                              struct spawn_cfg *sp, const char *log_src,
                              const char *datadir_src, const char *connect_src,
                              char *log_path, size_t log_cap)
{
    int rc;
    if (log_src) {
        rc = soak_copy_path("--log", log_path, log_cap, log_src);
        if (rc) return rc;
    }
    if (datadir_src) {
        rc = soak_copy_path("--node-datadir", sp->datadir,
                            sizeof(sp->datadir), datadir_src);
        if (rc) return rc;
    }
    if (connect_src) {
        rc = soak_copy_path("--connect", sp->connect,
                            sizeof(sp->connect), connect_src);
        if (rc) return rc;
    }
    if (interval_sec == 0 || interval_sec > cfg->min_duration_sec) {
        fprintf(stderr, "interval-sec (%" PRIu64 ") out of range\n",
                interval_sec);
        return 2;
    }
    if (sp->enabled) {
        if (sp->rpcport <= 0) {
            fprintf(stderr, "spawn mode: --rpcport is required with "
                            "--node-datadir\n");
            return 2;
        }
        if (sp->p2p_port <= 0)  sp->p2p_port  = sp->rpcport - 1;
        if (sp->fs_port <= 0)   sp->fs_port   = sp->rpcport + 1;
        if (sp->https_port <= 0)sp->https_port= sp->rpcport + 2;
    }
    return 0;
}

/* Threshold routing: 0 unmatched, 1 accepted, -1 malformed numeric value.
 * A parse refusal leaves the associated configuration value unchanged. */
static int soak_parse_threshold(const char *a, soak_thresholds_t *cfg,
                                  uint64_t *interval_sec)
{
    struct { const char *flag; uint64_t *dst; } rows[] = {
        {"--duration-sec=", &cfg->min_duration_sec},
        {"--interval-sec=", interval_sec},
        {"--stall-sec=", &cfg->max_tip_stall_sec},
        {"--warmup-sec=", &cfg->rss_walk_warmup_sec},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        size_t n = strlen(rows[i].flag);
        if (strncmp(a, rows[i].flag, n) == 0) {
            if (!parse_u64(a + n, rows[i].dst)) {
                fprintf(stderr, "invalid numeric argument: %s\n", a);
                return -1;
            }
            return 1;
        }
    }
    if (strncmp(a, "--rss-growth-mib=", 17) == 0) {
        uint64_t mib = 0;
        if (!parse_u64(a + 17, &mib)) {
            fprintf(stderr, "invalid numeric argument: %s\n", a);
            return -1;
        }
        cfg->max_rss_growth_bytes = mib * 1024ULL * 1024ULL;
        return 1;
    }
    return 0;
}

static bool soak_parse_spawn(const char *a, struct spawn_cfg *sp,
                              const char **datadir_src, const char **connect_src)
{
    if (strncmp(a, "--node-datadir=", 15) == 0) {
        *datadir_src = a + 15;
        sp->enabled = true;
        return true;
    }
    if (strncmp(a, "--connect=", 10) == 0) {
        *connect_src = a + 10;
        return true;
    }
    struct { const char *flag; int *dst; } rows[] = {
        {"--rpcport=", &sp->rpcport}, {"--p2p-port=", &sp->p2p_port},
        {"--fs-port=", &sp->fs_port}, {"--https-port=", &sp->https_port},
        {"--load=generate:", &sp->load_interval},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        size_t n = strlen(rows[i].flag);
        if (strncmp(a, rows[i].flag, n) == 0) {
            *rows[i].dst = atoi(a + n);
            return true;
        }
    }
    return false;
}

/* -1 means continue to validation; 0 and 2 are terminal CLI exits. */
static int soak_parse_args(int argc, char **argv, soak_thresholds_t *cfg,
                           uint64_t *interval_sec, const char **service,
                           const char **rpc_bin, struct spawn_cfg *sp,
                           const char **log_src, const char **datadir_src,
                           const char **connect_src)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]); return 0;
        }
        if (strcmp(a, "--ci-proxy") == 0) {
            soak_thresholds_ci_proxy(cfg); continue;
        }
        if (strncmp(a, "--service=", 10) == 0) { *service = a + 10; continue; }
        if (strncmp(a, "--rpc=",      6) == 0) { *rpc_bin = a + 6; continue; }
        if (strncmp(a, "--log=",      6) == 0) { *log_src = a + 6; continue; }
        int threshold = soak_parse_threshold(a, cfg, interval_sec);
        if (threshold < 0) return 2;
        if (threshold > 0) continue;
        if (soak_parse_spawn(a, sp, datadir_src, connect_src)) continue;
        fprintf(stderr, "unknown flag: %s\n", a);
        usage(argv[0]);
        return 2;
    }
    return -1;
}

static void soak_sample_one(struct spawn_cfg *sp, const char *service,
                             const char *rpc_bin, FILE *log, soak_state_t *st,
                             time_t now, time_t *last_load)
{
    pid_t pid = sp->enabled ? sp->pid : pidof_service(service);
    bool alive = pid > 0 && (sp->enabled ? kill(pid, 0) == 0 : true);
    uint64_t rss = alive ? rss_bytes_for(pid) : 0;
    int64_t h = 0;
    if (alive && !height_via_rpc(sp->enabled ? sp : NULL, rpc_bin, &h))
        alive = false;
    soak_record_sample(st, (uint64_t)now, alive, h, rss);
    fprintf(log, "%ld\t%d\t%" PRId64 "\t%" PRIu64 "\n",
            (long)now, alive ? 1 : 0, h, rss);
    if (sp->enabled && sp->load_interval > 0 && alive &&
        now - *last_load >= sp->load_interval) {
        spawn_generate_one(sp, rpc_bin);
        *last_load = now;
    }
}

static void soak_sample_loop(struct spawn_cfg *sp, const char *service,
                              const char *rpc_bin, FILE *log,
                              soak_state_t *st, const soak_thresholds_t *cfg,
                              uint64_t interval_sec, time_t started)
{
    /* Sample for at least min_duration_sec of SPAN. The verdict requires
     * last_sample_ts - first_sample_ts >= min_duration_sec; samples are taken
     * at the top of the loop every interval_sec, so the last sample lands one
     * interval before a `started + min_duration` deadline and the span falls
     * short by ~interval_sec. Extend the deadline by one interval so the final
     * sample's span reaches min_duration. */
    time_t deadline = started + (time_t)cfg->min_duration_sec +
                      (time_t)interval_sec;
    time_t last_load = started;
    while (!g_stop) {
        time_t now = platform_time_wall_time_t();
        if (now >= deadline) break;

        soak_sample_one(sp, service, rpc_bin, log, st, now, &last_load);

        /* Wake fractions of interval_sec to stay responsive to SIGTERM;
         * using `sleep()` rounds up and can sit in the syscall for the
         * full 60 s even after the flag is set. */
        for (uint64_t slept = 0; slept < interval_sec && !g_stop; slept++)
            sleep(1);
    }
}

int main(int argc, char **argv)
{
    soak_thresholds_t cfg;
    soak_thresholds_default_7d(&cfg);

    uint64_t interval_sec = 60;
    const char *service   = "zclassic23";
    const char *rpc_bin   = "build/bin/zcl-rpc";
    char log_path[256] = {0};
    /* Path arguments are recorded here and copied under truncation
     * refusal by soak_validate_args after the loop. */
    const char *log_src = NULL, *datadir_src = NULL, *connect_src = NULL;
    struct spawn_cfg sp;
    memset(&sp, 0, sizeof(sp));

    int parsed = soak_parse_args(argc, argv, &cfg, &interval_sec, &service,
                                  &rpc_bin, &sp, &log_src, &datadir_src,
                                  &connect_src);
    if (parsed >= 0) return parsed;
    /* Deferred copies (refuse truncation) plus the interval and spawn-mode
     * checks that used to live inline here. */
    {
        int vrc = soak_validate_args(interval_sec, &cfg, &sp, log_src,
                                     datadir_src, connect_src, log_path,
                                     sizeof(log_path));
        if (vrc) return vrc;
    }

    /* Invalid arguments and help exit before consulting the wall clock. */
    if (!log_src) default_log_path(log_path, sizeof(log_path));

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    FILE *log = fopen(log_path, "w");
    if (!log) {
        fprintf(stderr, "cannot open log %s: %s\n", log_path, strerror(errno));
        return 2;
    }
    setvbuf(log, NULL, _IOLBF, 0);

    /* Spawn mode: bring the isolated node up and wait for RPC BEFORE
     * the sampling loop, so the first sample sees a live node and the
     * tip-HWM clock starts from a real height. The make target owns the
     * /tmp datadir + cleanup trap; we own the node process lifecycle. */
    if (sp.enabled) {
        fprintf(stderr, "soak: spawn mode — datadir=%s rpcport=%d load=%s\n",
                sp.datadir, sp.rpcport,
                sp.load_interval > 0 ? "generate" : "none");
        if (!spawn_node(&sp) || !spawn_wait_ready(&sp, rpc_bin, 60)) {
            fprintf(stderr, "soak: isolated node never came up — aborting\n");
            kill_spawned_node(&sp);
            fclose(log);
            return 2;
        }
    }

    soak_state_t st;
    soak_state_init(&st, &cfg);

    time_t started = platform_time_wall_time_t();
    fprintf(log,
        "# soak runner\n"
        "# duration_sec=%" PRIu64 " interval_sec=%" PRIu64 "\n"
        "# stall_sec=%" PRIu64 " warmup_sec=%" PRIu64 " rss_growth_bytes=%" PRIu64 "\n"
        "# service=%s rpc=%s\n"
        "# started=%ld\n"
        "# ts\talive\theight\trss_bytes\n",
        cfg.min_duration_sec, interval_sec,
        cfg.max_tip_stall_sec, cfg.rss_walk_warmup_sec,
        cfg.max_rss_growth_bytes,
        service, rpc_bin, (long)started);

    fprintf(stderr,
        "soak: logging to %s; will run %" PRIu64 "s (SIGINT/TERM to stop early)\n",
        log_path, cfg.min_duration_sec);

    soak_sample_loop(&sp, service, rpc_bin, log, &st, &cfg, interval_sec,
                      started);

    soak_verdict_t v = soak_compute_verdict(&st);
    time_t ended = platform_time_wall_time_t();
    fprintf(log,
        "# ended=%ld verdict=%s samples=%zu crashes=%" PRIu32 "\n"
        "# tip_hwm=%" PRId64 " rss_max=%" PRIu64 " rss_baseline=%" PRIu64 "\n",
        (long)ended, soak_verdict_str(v),
        st.n_samples, st.crash_count,
        st.tip_hwm, st.rss_max_seen, st.rss_baseline);
    fclose(log);

    fprintf(stderr,
        "soak: verdict=%s samples=%zu crashes=%" PRIu32 " tip_hwm=%" PRId64
        " rss_max=%" PRIu64 "\n",
        soak_verdict_str(v), st.n_samples, st.crash_count,
        st.tip_hwm, st.rss_max_seen);

    /* Diagnostic: in spawn mode with generate-load configured, a
     * TIP_STALL with tip_hwm==0 means the synthetic miner never
     * advanced the chain — i.e. the regtest `generate` RPC did not
     * mine a valid block on this build (a NODE miner issue, not a
     * harness bug). Name it explicitly so operators do not chase the
     * harness. */
    if (sp.enabled && sp.load_interval > 0 &&
        v == SOAK_FAIL_TIP_STALL && st.tip_hwm == 0) {
        fprintf(stderr,
            "soak: NOTE — tip_hwm stayed at 0 under generate-load: the "
            "regtest `generate` RPC produced no valid block on this build "
            "(node miner does not solve Equihash on the generate path). "
            "The soak machinery (spawn/sample/RSS/verdict) ran correctly; "
            "this verdict reflects a non-functional synthetic-load source, "
            "not a harness defect.\n");
    }

    /* In spawn mode the runner owns the node — reap it (process-group
     * SIGKILL). The make target's cleanup trap is the backstop that
     * also removes the /tmp datadir; this just ensures we don't leave
     * our own child running between the loop end and trap fire. */
    if (sp.enabled)
        kill_spawned_node(&sp);

    return (int)v;
}
#endif
