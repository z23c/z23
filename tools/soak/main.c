/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 7-day soak runner (MVP criterion #6).
 *
 * Separate binary that polls a running zclassic23 every 60 s for
 * a configured duration (default 7 days), feeds each sample
 * through the soak_harness analyzer, writes a timestamped log,
 * and exits non-zero if the run tripped any verdict rule (crash,
 * tip stall, RSS walk, too-short, no-samples).
 *
 * Intentionally minimal — no JSON parser, no libevent, no
 * threads. Every signal the verdict cares about comes from
 * either /proc (/proc/<pid>/status → VmRSS) or one-shot fork/exec
 * of `build/bin/zcl-rpc getblockcount` (integer result is trivial to
 * extract by scanning for "result"). The runner doesn't try to
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
 *     make soak-7day                   (7 days, against installed zclassic23)
 *     make soak-ci                     (compressed hermetic proxy)
 *     build/bin/soak_runner --help
 *
 * Flags:
 *     --duration-sec=N      total run length (default 7d = 604800)
 *     --interval-sec=N      poll interval (default 60)
 *     --service=NAME        process name to pidof (pidof mode, default zclassic23)
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

/* Pull the first non-whitespace integer value that follows the
 * literal "result" key in a JSON-RPC response body. Accepts the
 * minimal shape the node emits ({"result":3081601,"error":null,
 * "id":1}) without dragging a full JSON parser into the runner. */
static bool scan_result_int(const char *buf, int64_t *out)
{
    const char *p = strstr(buf, "\"result\"");
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == 'n') return false; /* "result": null */
    char *end = NULL;
    errno = 0;
    long long v = strtoll(p, &end, 10);
    if (end == p || errno == ERANGE || v < 0) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') end++;
    if (*end != ',' && *end != '}') return false;
    *out = (int64_t)v;
    return true;
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
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
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
    close(fds[1]);
    size_t used = 0;
    bool complete = false;
    while (used < cap - 1) {
        ssize_t n = read(fds[0], out + used, cap - 1 - used);
        if (n > 0) { used += (size_t)n; continue; }
        if (n == 0) { complete = true; break; }
        if (errno != EINTR) break;
    }
    if (!complete && used == cap - 1) {
        char extra;
        ssize_t n;
        do { n = read(fds[0], &extra, 1); } while (n < 0 && errno == EINTR);
        complete = n == 0;
    }
    close(fds[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    out[used] = '\0';
    return complete && used > 0 && waited == child &&
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

/* SIGKILL the spawned node's whole process group (no orphan survives).
 * Idempotent: safe to call when sp->pid is already reaped. */
static void kill_spawned_node(struct spawn_cfg *sp)
{
    if (!sp || sp->pid <= 0) return;
    if (kill(-sp->pid, SIGKILL) != 0 && errno == ESRCH)
        kill(sp->pid, SIGKILL);
    int status;
    (void)waitpid(sp->pid, &status, 0);
    sp->pid = 0;
}

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

int main(int argc, char **argv)
{
    soak_thresholds_t cfg;
    soak_thresholds_default_7d(&cfg);

    uint64_t interval_sec = 60;
    const char *service   = "zclassic23";
    const char *rpc_bin   = "build/bin/zcl-rpc";
    char log_path[256] = {0};
    default_log_path(log_path, sizeof(log_path));

    struct spawn_cfg sp;
    memset(&sp, 0, sizeof(sp));

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]); return 0;
        }
        if (strcmp(a, "--ci-proxy") == 0) {
            soak_thresholds_ci_proxy(&cfg); continue;
        }
        if (strncmp(a, "--duration-sec=", 15) == 0) {
            parse_u64(a + 15, &cfg.min_duration_sec); continue;
        }
        if (strncmp(a, "--interval-sec=", 15) == 0) {
            parse_u64(a + 15, &interval_sec); continue;
        }
        if (strncmp(a, "--service=", 10) == 0) { service = a + 10; continue; }
        if (strncmp(a, "--rpc=",      6) == 0) { rpc_bin = a + 6;  continue; }
        if (strncmp(a, "--log=",      6) == 0) {
            snprintf(log_path, sizeof(log_path), "%s", a + 6); continue;
        }
        if (strncmp(a, "--stall-sec=", 12) == 0) {
            parse_u64(a + 12, &cfg.max_tip_stall_sec); continue;
        }
        if (strncmp(a, "--rss-growth-mib=", 17) == 0) {
            uint64_t mib = 0;
            if (parse_u64(a + 17, &mib))
                cfg.max_rss_growth_bytes = mib * 1024ULL * 1024ULL;
            continue;
        }
        if (strncmp(a, "--warmup-sec=", 13) == 0) {
            parse_u64(a + 13, &cfg.rss_walk_warmup_sec); continue;
        }
        /* ── Spawn-mode (hermetic CI-proxy) flags ── */
        if (strncmp(a, "--node-datadir=", 15) == 0) {
            snprintf(sp.datadir, sizeof(sp.datadir), "%s", a + 15);
            sp.enabled = true; continue;
        }
        if (strncmp(a, "--rpcport=", 10) == 0)   { sp.rpcport    = atoi(a + 10); continue; }
        if (strncmp(a, "--p2p-port=", 11) == 0)  { sp.p2p_port   = atoi(a + 11); continue; }
        if (strncmp(a, "--fs-port=", 10) == 0)   { sp.fs_port    = atoi(a + 10); continue; }
        if (strncmp(a, "--https-port=", 13) == 0){ sp.https_port = atoi(a + 13); continue; }
        if (strncmp(a, "--connect=", 10) == 0) {
            snprintf(sp.connect, sizeof(sp.connect), "%s", a + 10); continue;
        }
        if (strncmp(a, "--load=generate:", 16) == 0) {
            sp.load_interval = atoi(a + 16); continue;
        }
        fprintf(stderr, "unknown flag: %s\n", a);
        usage(argv[0]);
        return 2;
    }

    if (interval_sec == 0 || interval_sec > cfg.min_duration_sec) {
        fprintf(stderr, "interval-sec (%" PRIu64 ") out of range\n", interval_sec);
        return 2;
    }

    /* Spawn-mode validation: a datadir REQUIRES a real isolated rpcport
     * so a misconfigured invocation can never fall through to live. */
    if (sp.enabled) {
        if (sp.rpcport <= 0) {
            fprintf(stderr, "spawn mode: --rpcport is required with "
                            "--node-datadir\n");
            return 2;
        }
        if (sp.p2p_port <= 0)  sp.p2p_port  = sp.rpcport - 1;
        if (sp.fs_port <= 0)   sp.fs_port   = sp.rpcport + 1;
        if (sp.https_port <= 0)sp.https_port= sp.rpcport + 2;
    }

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

    /* Sample for at least min_duration_sec of SPAN. The verdict requires
     * last_sample_ts - first_sample_ts >= min_duration_sec; samples are taken
     * at the top of the loop every interval_sec, so the last sample lands one
     * interval before a `started + min_duration` deadline and the span falls
     * short by ~interval_sec. Extend the deadline by one interval so the final
     * sample's span reaches min_duration. */
    time_t deadline = started + (time_t)cfg.min_duration_sec +
                      (time_t)interval_sec;
    time_t last_load = started;
    while (!g_stop) {
        time_t now = platform_time_wall_time_t();
        if (now >= deadline) break;

        /* In spawn mode sample OUR OWN child pid directly — never
         * pidof, which would resolve the LIVE node. In pidof mode the
         * runner watches the externally-managed live node. */
        pid_t pid = sp.enabled ? sp.pid : pidof_service(service);
        bool alive = pid > 0 && (sp.enabled ? kill(pid, 0) == 0 : true);
        uint64_t rss = alive ? rss_bytes_for(pid) : 0;
        int64_t h = 0;
        if (alive) {
            /* RPC pinned to the isolated node in spawn mode (sp.enabled);
             * NULL in pidof mode so zcl-rpc uses live defaults. */
            if (!height_via_rpc(sp.enabled ? &sp : NULL, rpc_bin, &h)) {
                /* RPC failed but process exists → treat as crash: a
                 * node that can't answer getblockcount is, from the
                 * user's perspective, not up. */
                alive = false;
            }
        }
        soak_record_sample(&st, (uint64_t)now, alive, h, rss);
        fprintf(log, "%ld\t%d\t%" PRId64 "\t%" PRIu64 "\n",
                (long)now, alive ? 1 : 0, h, rss);

        /* Synthetic load: mine one block every load_interval seconds so
         * the tip-stall HWM clock is genuinely exercised (not a frozen
         * empty chain) and real connect_block/coins/WAL writes churn. */
        if (sp.enabled && sp.load_interval > 0 && alive &&
            now - last_load >= sp.load_interval) {
            spawn_generate_one(&sp, rpc_bin);
            last_load = now;
        }

        /* Wake fractions of interval_sec to stay responsive to SIGTERM;
         * using `sleep()` rounds up and can sit in the syscall for the
         * full 60 s even after the flag is set. */
        for (uint64_t slept = 0; slept < interval_sec && !g_stop; slept++)
            sleep(1);
    }

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
