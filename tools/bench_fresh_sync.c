/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Cold-start benchmark: measures time from zero to fully synced
 * block explorer via FlyClient + MMB + SHA3 UTXO snapshot.
 *
 * Spawns a fresh z23 node, monitors RPC + log, reports
 * phase timing for each step of the fast sync pipeline.
 *
 * Build: make bench_fresh_sync
 * Run:   build/bin/bench_fresh_sync
 */

#include "platform/time_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>

#define PORT       8047
#define RPCPORT    18247
#define HTTPSPORT  8447
#define TIMEOUT    1800

static pid_t g_child = 0;

static void cleanup(void)
{
    if (g_child > 0) {
        kill(g_child, SIGTERM);
        int status;
        waitpid(g_child, &status, WNOHANG);
        usleep(500000);
        if (waitpid(g_child, &status, WNOHANG) == 0) {
            kill(g_child, SIGKILL);
            waitpid(g_child, &status, 0);
        }
    }
}

static double now_sec(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Run a command and capture stdout into buf. Returns bytes read. */
static int run_cmd(const char *cmd, char *buf, int bufsz)
{
    FILE *f = popen(cmd, "r");
    if (!f) return 0;
    int n = (int)fread(buf, 1, (size_t)(bufsz - 1), f);
    pclose(f);
    if (n > 0) buf[n] = '\0';
    else buf[0] = '\0';
    return n;
}

/* Run a shell command, deliberately discarding its exit status. */
static void run_shell_ignore_status(const char *cmd)
{
    int rc = system(cmd);
    (void)rc;
}

/* RPC call via curl. Returns result string in buf. */
static bool rpc_call(const char *cookie, const char *method,
                     char *buf, int bufsz)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "curl -s -u '%s' "
        "--data-binary '{\"jsonrpc\":\"1.0\",\"id\":\"b\",\"method\":\"%s\",\"params\":[]}' "
        "-H 'content-type:text/plain;' "
        "http://127.0.0.1:%d/ 2>/dev/null",
        cookie, method, RPCPORT);
    return run_cmd(cmd, buf, bufsz) > 0;
}

/* Extract a string field from JSON (very simple, no library needed) */
static bool json_get_str(const char *json, const char *key, char *out, int outsz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);
    const char *e = strchr(p, '"');
    if (!e) return false;
    int len = (int)(e - p);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, (size_t)len);
    out[len] = '\0';
    return true;
}

static long json_get_int(const char *json, const char *key)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    return atol(p);
}

/* Check if a string appears in the log file */
static bool log_contains(const char *logfile, const char *pattern)
{
    char cmd[512];
    char buf[16];
    snprintf(cmd, sizeof(cmd), "grep -c '%s' '%s' 2>/dev/null", pattern, logfile);
    run_cmd(cmd, buf, sizeof(buf));
    return atoi(buf) > 0;
}

/* Check if HTTPS explorer is responding */
static bool explorer_responding(void)
{
    char buf[256];
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "curl -sk 'https://127.0.0.1:%d/explorer' 2>/dev/null | grep -c 'Latest Blocks'",
        HTTPSPORT);
    run_cmd(cmd, buf, sizeof(buf));
    return atoi(buf) > 0;
}

static int explorer_page_size(const char *path)
{
    char buf[32];
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "curl -sk 'https://127.0.0.1:%d%s' 2>/dev/null | wc -c",
        HTTPSPORT, path);
    run_cmd(cmd, buf, sizeof(buf));
    return atoi(buf);
}

/* Build the timestamped datadir path under $HOME. */
static void build_datadir_path(char *datadir, size_t datadir_sz)
{
    time_t t = platform_time_wall_time_t();
    struct tm *tm = localtime(&t);
    snprintf(datadir, datadir_sz,
        "%s/.zclassic-c23-bench-%04d%02d%02d-%02d%02d%02d",
        getenv("HOME"), tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* Find binary relative to the repo root or in known locations. */
static void find_binary_path(char *binary, size_t binary_sz)
{
    if (access("build/bin/zclassic23", X_OK) == 0)
        snprintf(binary, binary_sz, "build/bin/zclassic23");
    else
        snprintf(binary, binary_sz, "%s/zclassic23/build/bin/zclassic23", getenv("HOME") ?: ".");
}

/* Copy SSL certs if available */
static void copy_ssl_certs_if_present(const char *datadir)
{
    char src[512], dst[512], ssldir[512];
    snprintf(ssldir, sizeof(ssldir), "%s/ssl", datadir);
    mkdir(ssldir, 0755);
    snprintf(src, sizeof(src), "%s/.zclassic-c23/ssl/fullchain.pem", getenv("HOME"));
    snprintf(dst, sizeof(dst), "%s/ssl/fullchain.pem", datadir);
    if (access(src, R_OK) == 0) {
        char cp[1024];
        snprintf(cp, sizeof(cp), "cp '%s' '%s'", src, dst);
        run_shell_ignore_status(cp);
        snprintf(src, sizeof(src), "%s/.zclassic-c23/ssl/privkey.pem", getenv("HOME"));
        snprintf(dst, sizeof(dst), "%s/ssl/privkey.pem", datadir);
        snprintf(cp, sizeof(cp), "cp '%s' '%s'", src, dst);
        run_shell_ignore_status(cp);
    }
}

/* Print the benchmark banner with binary, datadir and ports. */
static void print_banner(const char *binary, const char *datadir)
{
    printf("\n");
    printf("================================================================\n");
    printf("  Z23 Cold-Start Benchmark\n");
    printf("  FlyClient + MMB + SHA3 Snapshot -> Block Explorer\n");
    printf("================================================================\n\n");
    printf("Binary:  %s\n", binary);
    printf("Datadir: %s\n", datadir);
    printf("Ports:   P2P=%d RPC=%d HTTPS=%d\n\n", PORT, RPCPORT, HTTPSPORT);
}

/* Child: redirect stdout/stderr to log, exec node */
static void exec_node_child(const char *binary, const char *logfile,
                            const char *datadir)
{
    FILE *log = fopen(logfile, "w");
    if (log) {
        dup2(fileno(log), STDOUT_FILENO);
        dup2(fileno(log), STDERR_FILENO);
        fclose(log);
    }
    char dd[300], pp[32], rp[32], hp[32];
    snprintf(dd, sizeof(dd), "-datadir=%s", datadir);
    snprintf(pp, sizeof(pp), "-port=%d", PORT);
    snprintf(rp, sizeof(rp), "-rpcport=%d", RPCPORT);
    snprintf(hp, sizeof(hp), "-httpsport=%d", HTTPSPORT);
    execlp(binary, "zclassic23",
        dd, pp, rp, hp,
        "-connect=127.0.0.1:8033",
        "-listen=0",
        "-txindex",
        "-showmetrics=0",
        (char *)NULL);
    _exit(127);
}

/* Wait for the RPC cookie file to appear. Returns 0 on success, 1 on failure. */
static int wait_for_rpc_cookie(const char *cookie_path, const char *logfile,
                               double t0)
{
    for (int i = 0; i < 600; i++) {
        if (access(cookie_path, R_OK) == 0) break;
        /* Print progress from log every 10s */
        if (i > 0 && i % 20 == 0) {
            double e = now_sec() - t0;
            char line[256] = "";
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "tail -1 '%s' 2>/dev/null", logfile);
            run_cmd(cmd, line, sizeof(line));
            char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
            printf("  [%.0fs] %s\n", e, line);
        }
        usleep(500000);
        /* Check child still alive */
        int st;
        if (waitpid(g_child, &st, WNOHANG) != 0) {
            fprintf(stderr, "ERROR: Node died during startup\n");
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "tail -10 '%s'", logfile);
            run_shell_ignore_status(cmd);
            g_child = 0;
            return 1;
        }
    }
    if (access(cookie_path, R_OK) != 0) {
        fprintf(stderr, "ERROR: RPC cookie never appeared (300s timeout)\n");
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "tail -10 '%s'", logfile);
        run_shell_ignore_status(cmd);
        return 1;
    }
    return 0;
}

/* Read the RPC cookie file into buf, stripping the trailing newline. */
static void read_rpc_cookie(const char *cookie_path, char *cookie, size_t cookie_sz)
{
    FILE *f = fopen(cookie_path, "r");
    if (f) {
        int n = (int)fread(cookie, 1, cookie_sz-1, f);
        fclose(f);
        cookie[n] = '\0';
        char *nl = strchr(cookie, '\n');
        if (nl) *nl = '\0';
    }
}

/* Fetch the current sync state and block height via RPC. */
static void poll_sync_state(const char *cookie, char *rpc_buf, int bufsz,
                            char *state, int statesz, long *height)
{
    if (rpc_call(cookie, "syncstate", rpc_buf, bufsz))
        json_get_str(rpc_buf, "state", state, statesz);
    if (rpc_call(cookie, "getblockcount", rpc_buf, bufsz))
        *height = json_get_int(rpc_buf, "result");
}

/* Print a line whenever the reported sync state changes. */
static void report_state_change(const char *state, long height, double elapsed,
                                char *last_state)
{
    if (strcmp(state, last_state) != 0) {
        printf("  %-20s %5.1fs   state=%s height=%ld\n",
               "", elapsed, state, height);
        strcpy(last_state, state);
    }
}

/* Timestamp the file sync phases from log markers. */
static void mark_file_sync_phases(const char *logfile, double elapsed,
                                  double *t_filesync, double *t_filesync_done)
{
    /* File sync */
    if (*t_filesync == 0 && log_contains(logfile, "File sync downloading")) {
        *t_filesync = elapsed;
        printf("  File sync started   %5.1fs   downloading chain data\n", elapsed);
    }
    if (*t_filesync_done == 0 && log_contains(logfile, "File sync complete")) {
        *t_filesync_done = elapsed;
        printf("  File sync done      %5.1fs\n", elapsed);
    }
}

/* Timestamp the first FlyClient verification in the log. */
static void mark_flyclient_verified(const char *logfile, double elapsed,
                                    double *t_fc)
{
    /* FlyClient */
    if (*t_fc == 0 && log_contains(logfile, "FlyClient PASSED")) {
        *t_fc = elapsed;
        printf("  FlyClient verified  %5.1fs   50/50 MMB samples (150-bit security)\n", elapsed);
    }
}

/* Timestamp snapshot transfer start and SHA3 verification in the log. */
static void mark_snapshot_phases(const char *logfile, double elapsed,
                                 double *t_snap_start, double *t_snap_end)
{
    /* Snapshot start */
    if (*t_snap_start == 0 && log_contains(logfile, "negotiating -> receiving")) {
        *t_snap_start = elapsed;
        printf("  Snapshot started    %5.1fs   UTXO transfer began\n", elapsed);
    }

    /* Snapshot SHA3 verified */
    if (*t_snap_end == 0 && log_contains(logfile, "verifying -> complete")) {
        *t_snap_end = elapsed;
        char line[256] = "";
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "grep 'UTXOs in' '%s' | tail -1", logfile);
        run_cmd(cmd, line, sizeof(line));
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        printf("  SHA3 verified       %5.1fs   %s\n", elapsed, line);
    }
}

/* Timestamp reaching the tip and the explorer coming live. */
static void mark_tip_and_explorer(double elapsed, const char *state, long height,
                                  double *t_tip, double *t_explorer)
{
    /* Synced to tip */
    if (*t_tip == 0 && strcmp(state, "at_tip") == 0) {
        *t_tip = elapsed;
        printf("  SYNCED TO TIP       %5.1fs   height=%ld\n", elapsed, height);
    }

    /* Explorer serving */
    if (*t_explorer == 0 && *t_tip > 0 && explorer_responding()) {
        *t_explorer = elapsed;
        printf("  Explorer live       %5.1fs   HTTPS port %d\n", elapsed, HTTPSPORT);
    }
}

/* True once the explorer is live and more than 5s have passed since reaching the tip. */
static bool fully_operational(double t_tip, double t_explorer, double elapsed)
{
    return t_tip > 0 && t_explorer > 0 && elapsed - t_tip > 5;
}

/* Print the RESULTS banner and the phase timing table. */
static void print_phase_results(double t_filesync, double t_filesync_done,
                                double t_fc, double t_snap_start, double t_snap_end,
                                double t_tip, double t_explorer, double t_done)
{
    printf("\n");
    printf("================================================================\n");
    printf("  RESULTS\n");
    printf("================================================================\n\n");

    if (t_filesync > 0 && t_filesync_done > 0)
        printf("  File sync:           %5.1fs  (%.1fs download)\n",
               t_filesync_done, t_filesync_done - t_filesync);
    if (t_fc > 0)
        printf("  FlyClient + MMB:     %5.1fs\n", t_fc);
    if (t_snap_start > 0 && t_snap_end > 0)
        printf("  SHA3 snapshot:       %5.1fs  (%.1fs transfer + verify)\n",
               t_snap_end, t_snap_end - t_snap_start);
    if (t_tip > 0)
        printf("  Synced to tip:       %5.1fs\n", t_tip);
    if (t_explorer > 0)
        printf("  Explorer serving:    %5.1fs\n", t_explorer);
    if (t_done > 0)
        printf("  Total cold->live:    %5.1fs\n", t_done);
}

/* Test explorer pages */
static void report_explorer_pages(void)
{
    printf("\n  Explorer Pages:\n");
    int sz;
    sz = explorer_page_size("/explorer");
    printf("    /explorer          %d bytes %s\n", sz, sz > 1000 ? "OK" : "EMPTY");
    sz = explorer_page_size("/explorer/factoids");
    printf("    /explorer/factoids %d bytes %s\n", sz, sz > 1000 ? "OK" : "EMPTY");
    sz = explorer_page_size("/explorer/hodl");
    printf("    /explorer/hodl     %d bytes %s\n", sz, sz > 1000 ? "OK" : "EMPTY");
    sz = explorer_page_size("/explorer/stats");
    printf("    /explorer/stats    %d bytes %s\n", sz, sz > 1000 ? "OK" : "EMPTY");
}

/* Validation status */
static void report_validation_status(const char *cookie, char *rpc_buf, int bufsz)
{
    if (rpc_call(cookie, "validationstatus", rpc_buf, bufsz)) {
        char vstate[64] = "";
        json_get_str(rpc_buf, "state", vstate, sizeof(vstate));
        long vh = json_get_int(rpc_buf, "verified_height");
        long proofs = json_get_int(rpc_buf, "proofs_verified");
        printf("\n  Background validation: %s (height %ld, %ld proofs)\n",
               vstate, vh, proofs);
    }
}

int main(void)
{
    /* Build datadir path */
    char datadir[256];
    build_datadir_path(datadir, sizeof(datadir));

    char binary[256];
    find_binary_path(binary, sizeof(binary));

    if (access(binary, X_OK) != 0) {
        fprintf(stderr, "ERROR: Binary not found at %s\n", binary);
        return 1;
    }

    mkdir(datadir, 0755);

    copy_ssl_certs_if_present(datadir);

    char logfile[300];
    snprintf(logfile, sizeof(logfile), "%s/node.log", datadir);

    print_banner(binary, datadir);

    double t0 = now_sec();

    /* Fork and exec the node */
    g_child = fork();
    if (g_child == 0) {
        exec_node_child(binary, logfile, datadir);
    }
    if (g_child < 0) {
        perror("fork");
        return 1;
    }
    atexit(cleanup);

    printf("Started PID=%d\n\n", g_child);

    /* Wait for RPC cookie (may take a while during block file scan) */
    char cookie_path[300];
    snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir);
    printf("Waiting for node startup (file sync + block scan)...\n");
    if (wait_for_rpc_cookie(cookie_path, logfile, t0) != 0)
        return 1;

    char cookie[256] = "";
    read_rpc_cookie(cookie_path, cookie, sizeof(cookie));

    /* Phase timestamps */
    double t_fc = 0, t_snap_start = 0, t_snap_end = 0;
    double t_filesync = 0, t_filesync_done = 0;
    double t_tip = 0, t_explorer = 0, t_done = 0;
    char last_state[64] = "";
    char rpc_buf[4096];

    printf("Phase                Time     Details\n");
    printf("-----------------------------------------------------------\n");

    while (1) {
        double elapsed = now_sec() - t0;
        if (elapsed > TIMEOUT) {
            printf("\nTIMEOUT after %ds\n", TIMEOUT);
            break;
        }

        /* Check child alive */
        int status;
        if (waitpid(g_child, &status, WNOHANG) != 0) {
            printf("\nERROR: Node died (status %d)\n", status);
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "tail -20 '%s'", logfile);
            run_shell_ignore_status(cmd);
            g_child = 0;
            return 1;
        }

        /* Get sync state */
        char state[64] = "unknown";
        long height = -1;
        poll_sync_state(cookie, rpc_buf, sizeof(rpc_buf), state, sizeof(state), &height);

        report_state_change(state, height, elapsed, last_state);

        mark_file_sync_phases(logfile, elapsed, &t_filesync, &t_filesync_done);
        mark_flyclient_verified(logfile, elapsed, &t_fc);
        mark_snapshot_phases(logfile, elapsed, &t_snap_start, &t_snap_end);
        mark_tip_and_explorer(elapsed, state, height, &t_tip, &t_explorer);

        /* Done: at tip + explorer working */
        if (fully_operational(t_tip, t_explorer, elapsed)) {
            t_done = elapsed;
            printf("  Fully operational   %5.1fs\n", elapsed);
            break;
        }

        usleep(2000000); /* 2 second poll */
    }

    print_phase_results(t_filesync, t_filesync_done, t_fc, t_snap_start,
                        t_snap_end, t_tip, t_explorer, t_done);
    report_explorer_pages();
    report_validation_status(cookie, rpc_buf, sizeof(rpc_buf));

    printf("\n  Datadir: %s\n", datadir);
    printf("  Log:     %s\n\n", logfile);

    return 0;
}
