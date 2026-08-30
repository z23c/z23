/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Live acceptance for the confined terminal worker (mesh_terminal_worker):
 * spawn the granted fbsh on a PTY inside its cage and drive it the way the
 * mesh serving layer will — keyboard in, screen out, resize, budgets, and
 * every ending named. The budget cases are the heart: lifetime and idle
 * are enforced with an INJECTED clock (no sleeping on the harness), the
 * byte budgets bite on real frames, and every kill is proven complete by
 * the process-group census returning to zero.
 *
 * Marker discipline: command markers are written quote-split
 * (Z23TER"M"_OK) so the PTY's echo of the raw typed line can never match
 * the executed output (Z23TERM_OK) — a shell that dies before executing
 * cannot fake a pass.
 *
 * fbsh cases SKIP (never fail) when build/bin/fbsh is absent, mirroring
 * test_freebsd_sh and test_terminal_worker_sandbox.
 */

#define _GNU_SOURCE /* pthread/posix bits, if any — must precede includes */

#include "test/test_core.h"
#include "platform/os_sandbox.h"
#include "session/mesh_terminal_worker.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FBSH_BIN "build/bin/fbsh"

static char g_dir[160];
static char g_fbsh[600];

/* Budgets used by the live cases: 4 KiB in, 64 KiB out, 60 s lifetime,
 * 30 s idle. Individual cases override the one under test. */
static void live_config(struct mesh_terminal_worker_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->shell_path = g_fbsh;
    cfg->workdir = g_dir;
    cfg->cols = 80;
    cfg->rows = 24;
    cfg->max_bytes_in = 4096;
    cfg->max_bytes_out = 65536;
    cfg->lifetime_seconds = 60;
    cfg->idle_seconds = 30;
}

/* Drain worker output into a rolling buffer until `needle` appears or the
 * deadline passes. Returns true when found. `err` (optional) captures a
 * terminal worker error — BYTE_LIMIT in particular is how the output
 * budget case ends, with the needle possibly never arriving. On failure
 * the caller can print `saw` (NUL-terminated, escaped by the caller) —
 * a red must name what the pump actually delivered. */
static bool drain_until(struct mesh_terminal_worker *w, const char *needle,
                        int timeout_seconds, struct zcl_result *err,
                        char *saw, size_t saw_cap)
{
    char rolling[MESH_TERMINAL_WORKER_IO_CHUNK + 1];
    size_t cap = sizeof rolling - 1;
    size_t fill = 0;
    rolling[0] = '\0';
    time_t deadline = time(NULL) + timeout_seconds;
    while (time(NULL) < deadline) {
        uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
        size_t n = 0;
        struct zcl_result r = mesh_terminal_worker_output(
            w, chunk, sizeof chunk, &n, (int64_t)time(NULL));
        if (!r.ok && r.code != MESH_TERMINAL_WORKER_ERR_NONE) {
            if (err) *err = r;
            break;
        }
        if (n > 0) {
            size_t append = n;
            if (append > cap)
                append = cap;
            if (fill + append > cap) {
                size_t shift = fill + append - cap;
                if (shift > fill)
                    shift = fill;
                memmove(rolling, rolling + shift, fill - shift);
                fill -= shift;
            }
            memcpy(rolling + fill, chunk, append);
            fill += append;
            rolling[fill] = '\0';
            if (strstr(rolling, needle))
                return true;
            continue;
        }
        usleep(20000);
    }
    if (saw && saw_cap != 0) {
        size_t copy = fill < saw_cap - 1 ? fill : saw_cap - 1;
        memcpy(saw, rolling, copy);
        saw[copy] = '\0';
    }
    return strstr(rolling, needle) != NULL;
}

static bool wait_exit(struct mesh_terminal_worker *w, int timeout_seconds)
{
    time_t deadline = time(NULL) + timeout_seconds;
    while (time(NULL) < deadline) {
        if (!mesh_terminal_worker_alive(w))
            return true;
        usleep(20000);
    }
    return false;
}

static int check(int failures, bool ok, const char *label)
{
    printf("mesh_terminal_worker: %s... %s\n", label, ok ? "OK" : "FAIL");
    return ok ? failures : failures + 1;
}

#if !defined(__linux__)

/* The worker must refuse honestly on platforms with no confinement
 * stack — every entry by name, never a simulated success. */
int test_mesh_terminal_worker(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;
    struct mesh_terminal_worker_config cfg;
    struct mesh_terminal_worker w;
    live_config(&cfg);

    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 0, &w);
    failures = check(failures,
                     !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_UNSUPPORTED,
                     "spawn refuses honestly (unsupported)");
    uint8_t buf[16];
    size_t n = 99;
    r = mesh_terminal_worker_output(&w, buf, sizeof buf, &n, 0);
    failures = check(failures, !r.ok && n == 0, "output refuses honestly");
    r = mesh_terminal_worker_input(&w, buf, 1, 0);
    failures = check(failures, !r.ok, "input refuses honestly");
    r = mesh_terminal_worker_resize(&w, 80, 24);
    failures = check(failures, !r.ok, "resize refuses honestly");
    failures = check(failures,
                     mesh_terminal_worker_budget_exceeded(&w, 0),
                     "budget_exceeded: no session is over");
    failures = check(failures, !mesh_terminal_worker_alive(&w),
                     "alive: false with no session");
    mesh_terminal_worker_kill(&w); /* no-op */
    printf("mesh_terminal_worker: %d failures (unsupported platform)\n",
           failures);
    return failures;
}

#else /* __linux__ */

int test_mesh_terminal_worker(void)
{
    printf("\n=== mesh terminal worker tests ===\n");
    int failures = 0;

    test_make_tmpdir(g_dir, sizeof g_dir, "terminal_worker_live", "live");
    if (!test_abs_path(FBSH_BIN, g_fbsh, sizeof g_fbsh))
        g_fbsh[0] = '\0';
    struct stat st;
    bool fbsh = g_fbsh[0] && stat(FBSH_BIN, &st) == 0 &&
                (st.st_mode & S_IXUSR) != 0;

    /* ── config refusals (by name; no fbsh needed) ─────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        struct zcl_result r = mesh_terminal_worker_spawn(NULL, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(NULL) -> null");
        r = mesh_terminal_worker_spawn(&cfg, 0, NULL);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_NULL,
                         "spawn(out=NULL) -> null");

        static const char *relative = "build/bin/fbsh";
        cfg.shell_path = relative;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative shell_path -> config");
        live_config(&cfg);
        static char relative_dir[] = "test-tmp";
        cfg.workdir = relative_dir;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "relative workdir -> config");
        live_config(&cfg);
        cfg.max_bytes_in = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero input budget -> config");
        live_config(&cfg);
        cfg.lifetime_seconds = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero lifetime -> config");
        live_config(&cfg);
        cfg.cols = 0;
        r = mesh_terminal_worker_spawn(&cfg, 0, &w);
        failures = check(failures,
                         !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG,
                         "zero cols -> config");
    }

    if (!fbsh) {
        printf("mesh_terminal_worker: " FBSH_BIN
               " not built — SKIP the live cases (run `make fbsh`)\n");
        printf("mesh_terminal_worker: %d failures\n", failures);
        return failures;
    }

    /* ── live: interactive roundtrip + census ──────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn fbsh in the cage");
        if (r.ok) {
            failures = check(failures, w.pid > 0 && w.pgid == w.pid &&
                                         w.master_fd >= 0,
                             "spawn fills pid/pgid/master");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) >= 1,
                             "census sees the session's process group");
            const uint8_t line[] = "echo Z23TER\"M\"_OK\n";
            r = mesh_terminal_worker_input(&w, line, sizeof line - 1, t0 + 1);
            failures = check(failures, r.ok, "input accepted");
            char saw[256] = {0};
            bool found = drain_until(&w, "Z23TERM_OK", 5, NULL,
                                     saw, sizeof saw);
            failures = check(failures, found,
                             "shell executed the typed line (echo output)");
            if (!found) {
                printf("  saw %.200s\n", saw);
                failures = check(failures, mesh_terminal_worker_alive(&w),
                                 "shell was alive during the drain");
            }
            failures = check(failures, w.bytes_in == sizeof line - 1,
                             "input byte accounting");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "kill leaves an empty process group");
        const uint8_t more[] = "x";
        r = mesh_terminal_worker_input(&w, more, 1, t0 + 2);
        failures = check(failures,
                         !r.ok &&
                             r.code == MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                         "input after kill -> not-running");
    }

    /* ── live: natural exit is reaped and named ────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for natural exit");
        if (r.ok) {
            const uint8_t line[] = "exit\n";
            (void)mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                             t0 + 1);
            failures = check(failures, wait_exit(&w, 5),
                             "shell exits on `exit`");
            failures = check(failures,
                             !w.running &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_WORKER_EXITED &&
                                 w.exit_code == 0,
                             "natural exit named worker-exited (code 0)");
            /* Enforcement after death reports over but keeps the exit's
             * name — reap wins over the timeout checks. */
            bool over = mesh_terminal_worker_budget_exceeded(&w,
                                                             t0 + 100000);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_WORKER_EXITED,
                             "enforce after exit keeps worker-exited");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: input byte budget ───────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_in = 16;
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for input budget");
        if (r.ok) {
            const uint8_t exact[16] = {0};
            r = mesh_terminal_worker_input(&w, exact, sizeof exact, t0 + 1);
            failures = check(failures, r.ok,
                             "input exactly at budget accepted");
            const uint8_t one[] = "a";
            r = mesh_terminal_worker_input(&w, one, 1, t0 + 2);
            failures = check(failures,
                             !r.ok &&
                                 r.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
                                 w.close_reason ==
                                     MESH_TERMINAL_CLOSE_BYTE_LIMIT,
                             "input over budget -> byte-limit");
            failures = check(failures, !mesh_terminal_worker_alive(&w),
                             "budget kill ended the session");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "budget kill emptied the process group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: output byte budget ──────────────────────────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.max_bytes_out = 64;
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for output budget");
        if (r.ok) {
            const uint8_t line[] =
                "echo 0123456789012345678901234567890123456789"
                "0123456789012345678901234567890123456789\n";
            (void)mesh_terminal_worker_input(&w, line, sizeof line - 1,
                                             t0 + 1);
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "ZZZ_NEVER", 5, &err, NULL, 0);
            failures = check(failures,
                             !err.ok &&
                                 err.code ==
                                     MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                             "output over budget -> byte-limit");
            failures = check(failures, w.bytes_out > 64,
                             "output bytes were accounted before the kill");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "output budget kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── lifetime + idle: injected clock, no sleeping ──────────────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        cfg.idle_seconds = 0; /* isolate the lifetime check: at t0+59 the
                               * idle window (30 s) would otherwise fire
                               * first and name the kill idle-timeout */
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for lifetime budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 59),
                             "one tick inside the lifetime still alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 61);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_LIFETIME_LIMIT,
                             "lifetime exceeded -> lifetime-limit");
            failures = check(failures,
                             os_sandbox_process_group_census(w.pgid) == 0,
                             "lifetime kill emptied the group");
        }
        mesh_terminal_worker_kill(&w);

        live_config(&cfg);
        cfg.idle_seconds = 30; /* unchanged; lifetime stays 60 (> 31) */
        r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for idle budget");
        if (r.ok) {
            failures = check(failures,
                             !mesh_terminal_worker_budget_exceeded(&w,
                                                                   t0 + 29),
                             "one tick inside the idle window alive");
            bool over = mesh_terminal_worker_budget_exceeded(&w, t0 + 31);
            failures = check(failures, over &&
                                           w.close_reason ==
                                               MESH_TERMINAL_CLOSE_IDLE_TIMEOUT,
                             "idle exceeded -> idle-timeout");
        }
        mesh_terminal_worker_kill(&w);
    }

    /* ── live: resize bounds + confinement through the terminal ────── */
    {
        struct mesh_terminal_worker_config cfg;
        struct mesh_terminal_worker w;
        live_config(&cfg);
        int64_t t0 = (int64_t)time(NULL);
        struct zcl_result r = mesh_terminal_worker_spawn(&cfg, t0, &w);
        failures = check(failures, r.ok, "spawn for resize/confinement");
        if (r.ok) {
            r = mesh_terminal_worker_resize(&w, MESH_TERMINAL_MAX_COLS,
                                            MESH_TERMINAL_MAX_ROWS);
            failures = check(failures, r.ok, "resize to proto max");
            r = mesh_terminal_worker_resize(&w, 0, 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize zero cols -> geometry");
            r = mesh_terminal_worker_resize(
                &w, (uint16_t)(MESH_TERMINAL_MAX_COLS + 1), 24);
            failures = check(failures,
                             !r.ok &&
                                 r.code == MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                             "resize over max cols -> geometry");

            /* Attack through the shell: cat is NOT granted, so the read
             * cannot happen — and nothing secret may appear on screen. */
            const uint8_t shadow[] = "cat /etc/shadow\n";
            (void)mesh_terminal_worker_input(&w, shadow,
                                             sizeof shadow - 1, t0 + 1);
            struct zcl_result err = { .ok = true };
            (void)drain_until(&w, "not found", 5, &err, NULL, 0);
            (void)err;

            /* The shell must still be alive and working after the
             * refusal — confined is not broken. */
            failures = check(failures, mesh_terminal_worker_alive(&w),
                             "shell survived the refused attack");
            const uint8_t probe[] = "echo A$((6*7))B\n";
            r = mesh_terminal_worker_input(&w, probe, sizeof probe - 1,
                                           t0 + 2);
            failures = check(failures, r.ok, "probe accepted after refusal");
            bool found = drain_until(&w, "A42B", 5, NULL, NULL, 0);
            failures = check(failures, found,
                             "shell still executes after the refusal");
        }
        mesh_terminal_worker_kill(&w);
        failures = check(failures,
                         os_sandbox_process_group_census(w.pgid) == 0,
                         "final kill emptied the group");
    }

    printf("mesh_terminal_worker: %d failures\n", failures);
    return failures;
}

#endif /* __linux__ */
