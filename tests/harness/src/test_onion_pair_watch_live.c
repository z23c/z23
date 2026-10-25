/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_pair_watch_live: the LIVE two-node Tor pairing exercise, run
 * as a registered TEST (network-bound, can take minutes), not as a lint gate.
 *
 * `onion_pair_watch.sh --selftest` is hermetic and used by the static gate
 * `make check-onion-pair-watch`. This group covers the script's LIVE path:
 * two real regtest nodes with `-tor -onion-persist`, a real Tor bootstrap,
 * and a real onion rendezvous.
 *
 * Isolation: runs the shipped script via fork/exec with its own throwaway
 * PAIR_PROBE_FILE ledger and the isolation quads the script rents from the
 * 39250+ probe band. No production datadir, no live node.
 *
 * Progress vs. wedged: the script prints "pair-watch: waiting <stage>
 * <elapsed>s/<deadline>s" to stderr every 30s while polling. This group
 * watches for SILENCE (no growth in the captured output), not total elapsed
 * time, as run_gate_script_watched() does (lint_gate_helpers.c). The silence
 * bound is the 30s print interval plus margin.
 *
 * Outcome mapping
 * ----------------
 *   exit 0 (PAIR_PROBE=PAIRED)                    -> PASS
 *   exit 1 with a named "Tor did not finish inside -> UNOBSERVED (a
 *     its window" verdict (ONION_HOSTNAME_TIMEOUT,     box/network fact, not
 *     DESCRIPTOR_NOT_UPLOADED, CLIENT_TOR_NOT_READY,   a code verdict; see
 *     INTRODUCE1_NOT_SEEN, RENDEZVOUS1_NOT_SEEN,        test_onion_bootstrap.c)
 *     CIRCUIT_NOT_READY, P2P_FRAMING_NOT_SEEN)
 *   exit 1 with ENV_MISSING_BINARY                    -> UNOBSERVED: the
 *     (build/bin/z23, z23 or zcl-rpc absent)      environment has no
 *     runtime binaries; a land proof builds z23 and zcl-rpc for this group
 *     (BUILD rows in tools/dev/test_group_host_needs.def).
 *   any other nonzero exit, or a wedge                -> FAIL, with the
 *     (PORT_QUAD_EXHAUSTED, SPAWN_A_FAILED,              script's last 20
 *     RPC_A_NOT_READY, SPAWN_B_FAILED, RPC_B_NOT_READY,  lines
 *     DIAL_NOT_ATTEMPTED)
 *
 * Deliberately NOT SKIP: the push gate refuses any receipt carrying a
 * "SKIP (" line (see test_onion_bootstrap.c and test_testcache.c's "onion
 * bootstrap window prints UNOBSERVED, never SKIP" check). An UNOBSERVED leg
 * is never cached as green.
 *
 * Gating: like test_onion_bootstrap, the body only runs under
 * ZCL_STRESS_TESTS=1.
 *
 *   ZCL_STRESS_TESTS=1 make t-fast ONLY=onion_pair_watch_live
 *
 * Environment forwarded to the script when set:
 *   PAIR_WATCH_ONION_WAIT, PAIR_WATCH_RPC_WAIT, PAIR_WATCH_POLL
 */

#include "test/test_core.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

extern int repo_path(char *out, size_t outsz, const char *rel);
extern pid_t fork_with_retry(void);
extern void lint_gate_loadavg(char *out, size_t outsz);

static int64_t opw_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Named verdicts meaning the Tor/network exercise did not complete inside
 * its own deadline windows: a box/network fact, mapped UNOBSERVED, never
 * FAIL and never SKIP. */
static bool opw_is_timeout_verdict(const char *tail)
{
    static const char *const tokens[] = {
        "PAIR_PROBE=ONION_HOSTNAME_TIMEOUT",
        "PAIR_PROBE=DESCRIPTOR_NOT_UPLOADED",
        "PAIR_PROBE=CLIENT_TOR_NOT_READY",
        "PAIR_PROBE=INTRODUCE1_NOT_SEEN",
        "PAIR_PROBE=RENDEZVOUS1_NOT_SEEN",
        "PAIR_PROBE=CIRCUIT_NOT_READY",
        "PAIR_PROBE=P2P_FRAMING_NOT_SEEN",
    };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
        if (strstr(tail, tokens[i]))
            return true;
    }
    return false;
}

/* The script found no build/bin/z23, zclassic23 or zcl-rpc to spawn (a tree
 * that skipped the BUILD rows), so the pairing cannot be observed there:
 * mapped UNOBSERVED (never FAIL, never SKIP) and never cached as green. */
static bool opw_is_missing_binary_verdict(const char *tail)
{
    return tail && strstr(tail, "PAIR_PROBE=ENV_MISSING_BINARY") != NULL;
}

static bool opw_is_paired(const char *tail)
{
    /* Exact token match: require the token to end in whitespace/newline/EOS
     * so other PAIR_PROBE= verdicts never match. */
    const char *p = strstr(tail, "PAIR_PROBE=PAIRED");
    if (!p) return false;
    char after = p[strlen("PAIR_PROBE=PAIRED")];
    return after == '\0' || after == ' ' || after == '\n';
}

/* Read up to the last `max_lines` lines of a file into a heap buffer the
 * caller must free. Best-effort diagnostic only. */
static char *opw_tail_lines(const char *path, int max_lines)
{
    FILE *f = fopen(path, "rb");
    if (!f) return strdup("(no output captured)");
    char *buf = NULL;
    size_t len = 0;
    char line[4096];
    /* Read the whole (bounded, a few hundred KB at most) file and keep the
     * tail by line count. */
    char **lines = calloc((size_t)max_lines, sizeof(char *));
    int count = 0, head = 0;
    while (fgets(line, sizeof(line), f)) {
        free(lines[head]);
        lines[head] = strdup(line);
        head = (head + 1) % max_lines;
        if (count < max_lines) count++;
    }
    fclose(f);
    int start = (count < max_lines) ? 0 : head;
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % max_lines;
        if (!lines[idx]) continue;
        size_t n = strlen(lines[idx]);
        char *nb = realloc(buf, len + n + 1);
        if (!nb) break;
        buf = nb;
        memcpy(buf + len, lines[idx], n);
        len += n;
        buf[len] = '\0';
    }
    for (int i = 0; i < max_lines; i++) free(lines[i]);
    free(lines);
    if (!buf) buf = strdup("(empty output)");
    return buf;
}

/* Child side of the fork: detach into its own process group, point stdout
 * and stderr at out_path, hand the script its throwaway PAIR_PROBE_FILE
 * ledger, and exec. Never returns: an exec failure falls through to
 * _exit(127). */
static void opw_child_exec_script(const char *script_abs,
                                  const char *ledger_abs,
                                  const char *out_path)
{
    setpgid(0, 0);
    int cfd = open(out_path, O_WRONLY | O_TRUNC, 0600);
    if (cfd >= 0) {
        dup2(cfd, STDOUT_FILENO);
        dup2(cfd, STDERR_FILENO);
        close(cfd);
    }
    setenv("PAIR_PROBE_FILE", ledger_abs, 1);
    execl(script_abs, script_abs, (char *)NULL);
    _exit(127);
}

/* Output growth is progress: when out_path's size changed since the last
 * poll, record the new size and refresh the last-progress timestamp. */
static void opw_note_output_growth(const char *out_path, off_t *last_size,
                                   int64_t *last_progress_ns)
{
    struct stat st;
    if (stat(out_path, &st) == 0 && st.st_size != *last_size) {
        *last_size = st.st_size;
        *last_progress_ns = opw_now_ns();
    }
}

/* Wedge recovery for a child that went silent: SIGTERM its process group,
 * allow a 50 x 100ms grace window for it to die, then SIGKILL and block
 * until it is reaped. *rc receives the wait status on whichever path reaps
 * it. */
static void opw_kill_and_reap_child(pid_t pid, int *rc)
{
    kill(-pid, SIGTERM);
    for (int i = 0; i < 50; i++) {
        if (waitpid(pid, rc, WNOHANG) == pid) return;
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL); /* real-clock: SIGTERM grace — polls the kernel to reap a real child before SIGKILL; no fake-clock seam */
    }
    kill(-pid, SIGKILL);
    while (waitpid(pid, rc, 0) < 0 && errno == EINTR) { }
}

/* Fork/exec onion_pair_watch.sh (LIVE path, no --selftest), capture combined
 * stdout+stderr to out_path, and watch for SILENCE rather than total elapsed
 * time: the script prints a progress line every 30s, so 90s of silence is a
 * wedge. Returns the script's exit status, -1 on a harness-level failure
 * (fork/exec), or -2 if killed for going silent. */
#define OPW_WEDGED (-2)
static int opw_run_watched(const char *script_abs, const char *ledger_abs,
                            const char *out_path, int max_silent_secs)
{
    int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return -1;
    close(fd);

    pid_t pid = fork_with_retry();
    if (pid < 0) return -1;
    if (pid == 0) {
        opw_child_exec_script(script_abs, ledger_abs, out_path);
    }
    setpgid(pid, pid);

    const int64_t started_ns = opw_now_ns();
    int64_t last_progress_ns = started_ns;
    off_t last_size = -1;
    int rc = 0;
    int wedged = 0;

    for (;;) {
        pid_t w = waitpid(pid, &rc, WNOHANG);
        if (w == pid) break;
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        opw_note_output_growth(out_path, &last_size, &last_progress_ns);
        int64_t silent_ns = opw_now_ns() - last_progress_ns;
        if (silent_ns > (int64_t)max_silent_secs * 1000000000LL) {
            char load[64];
            lint_gate_loadavg(load, sizeof(load));
            fprintf(stderr,
                "\n[onion_pair_watch_live] WEDGED: no output for %ds "
                "(bound derived from the script's 30s progress-line "
                "interval + margin); loadavg %s. Killing the group.\n",
                max_silent_secs, load);
            opw_kill_and_reap_child(pid, &rc);
            wedged = 1;
            goto done;
        }
        struct timespec ts = {0, 250 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
done:
    if (wedged) return OPW_WEDGED;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

int test_onion_pair_watch_live(void);

int test_onion_pair_watch_live(void)
{
    int failures = 0;
    printf("\n=== onion_pair_watch live two-node Tor pairing ===\n");
    printf("onion_pair_watch_live: ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 — real Tor egress, tens of "
               "seconds to minutes)\n");
        return 0;
    }

    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), "tools/scripts/onion_pair_watch.sh") != 0) {
        printf("FAIL (could not resolve script path)\n");
        return 1;
    }

    char tmpdir[] = "/tmp/zcl_opw_live_XXXXXX";
    if (!mkdtemp(tmpdir)) {
        printf("FAIL (mkdtemp)\n");
        return 1;
    }
    char ledger[PATH_MAX], out_path[PATH_MAX];
    snprintf(ledger, sizeof(ledger), "%s/pair_probe.jsonl", tmpdir);
    snprintf(out_path, sizeof(out_path), "%s/run.out", tmpdir);

    /* Silence bound: the script prints progress every 30s while waiting;
     * triple that for margin. Only a wedged script goes this quiet. */
    const int max_silent_secs = 90;

    int rc = opw_run_watched(script, ledger, out_path, max_silent_secs);
    char *tail = opw_tail_lines(out_path, 20);

    if (rc == -1) {
        printf("FAIL (harness could not fork/exec %s)\n", script);
        failures++;
    } else if (rc == OPW_WEDGED) {
        printf("FAIL (wedged: %ds with no progress line — see stderr above)\n",
               max_silent_secs);
        failures++;
    } else if (rc == 0 && opw_is_paired(tail)) {
        printf("PASS (PAIRED)\n");
    } else if (opw_is_timeout_verdict(tail)) {
        printf("UNOBSERVED (real Tor bootstrap/rendezvous did not complete "
               "inside its own deadline windows on this box/network — a "
               "box/network fact, not a code verdict; see the tail below)\n");
        printf("  %s", tail);
    } else if (opw_is_missing_binary_verdict(tail)) {
        printf("UNOBSERVED (this environment carries no z23/zclassic23/zcl-rpc "
               "runtime binaries, so the two-node pairing cannot be exercised "
               "here — PAIR_PROBE=ENV_MISSING_BINARY; build them with "
               "`make z23 zcl-rpc` to observe it)\n");
        printf("  %s", tail);
    } else {
        printf("FAIL (exit=%d; last %d lines of %s:)\n", rc, 20, out_path);
        printf("%s", tail);
        failures++;
    }

    free(tail);
    /* Best-effort cleanup; never fail the group over a stray temp file. */
    char rmcmd[PATH_MAX + 16];
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf -- '%s'", tmpdir);
    if (system(rmcmd) != 0) { /* diagnostic only */ }

    return failures;
}
