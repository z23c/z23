/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: layer (2) of the `-cold-start` staged driver — the LIVE half.
 * Fork/exec of each existing prep verb as a child with its stderr teed and a
 * bounded tail captured, DECISION-vs-TRANSIENT classification of the child's
 * outcome, the per-stage argv construction, the `-cold-start` entry point,
 * and the final exec of the plain serving boot.
 *
 * Split out of boot_cold_start.c along the file-size ceiling seam (E1) at the
 * layer boundary that file already declared. boot_cold_start.c keeps layer
 * (1), the PURE helpers — stage naming, receipt path/write/read/match, and
 * the resume decision — which have no child spawn and no global state and are
 * unit tested directly. Contract + rationale live in
 * config/boot_cold_start.h; the two symbols that cross the seam live in
 * boot_cold_start_internal.h.
 */


#include "config/boot_cold_start.h"

#include "platform/os_proc.h"    /* os_proc_exe_path */
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/file_tree_ops.h"  /* zcl_mkdir_p */
#include "util/log_macros.h"
#include "util/safe_alloc.h"     /* zcl_malloc */
#include "util/write_all.h"      /* zcl_write_all */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "boot_cold_start_internal.h"

/* ── (2) Live driver ──────────────────────────────────────────────────── */

/* Resolve this process's executable path, stripping any kernel " (deleted)"
 * suffix a mid-deploy readlink can append. */
static bool cold_start_self_exe(char *buf, size_t n)
{
    if (!os_proc_exe_path(buf, n))
        return false;
    size_t len = strlen(buf);
    static const char del[] = " (deleted)";
    size_t dl = sizeof(del) - 1;
    if (len >= dl && strcmp(buf + len - dl, del) == 0)
        buf[len - dl] = '\0';
    return buf[0] != '\0';
}

/* The token an existing verb (e.g. -install-consensus-bundle) prints to stderr
 * to signal a DECISION refusal, as opposed to a transient error/crash. */
#define COLD_START_REFUSAL_TOKEN "REFUSED:"

/* Bounded tail of a child's stderr, big enough to hold the final REFUSED line
 * plus surrounding context. */
#define COLD_START_TAIL_CAP 4096

/* Append `n` bytes of `chunk` to the fixed-capacity tail, discarding the oldest
 * bytes on overflow (only the END of the child's stderr matters — verbs print
 * their terminal REFUSED/INSTALLED line last). The copy length is always <= n
 * (bounded by the caller's read), so it never reads past `chunk`. */
static void cold_start_tail_append(char *tail, size_t *tail_len, size_t cap,
                                   const char *chunk, size_t n)
{
    /* Only the final `cap` bytes of the stream ever matter — if a single chunk
     * already exceeds cap, keep just its tail. */
    if (n > cap) {
        chunk += (n - cap);
        n = cap;
    }
    if (*tail_len + n > cap) {
        size_t drop = *tail_len + n - cap;
        memmove(tail, tail + drop, *tail_len - drop);
        *tail_len -= drop;
    }
    memcpy(tail + *tail_len, chunk, n);
    *tail_len += n;
}

/* Extract the verbatim REFUSED line (from the token to end-of-line) out of the
 * child's stderr tail into `reason`. Returns true iff the token was present. */
static bool cold_start_extract_refusal(const char *tail, char *reason,
                                       size_t reason_n)
{
    const char *hit = strstr(tail, COLD_START_REFUSAL_TOKEN);
    if (!hit)
        return false;
    /* Take the LAST occurrence — the terminal refusal is what matters. */
    const char *next;
    while ((next = strstr(hit + 1, COLD_START_REFUSAL_TOKEN)) != NULL)
        hit = next;
    const char *end = strchr(hit, '\n');
    size_t len = end ? (size_t)(end - hit) : strlen(hit);
    cold_start_singleline_bounded(hit, len, reason, reason_n);
    return true;
}

/* Fork/exec a child (argv NULL-terminated), teeing its stderr to ours while
 * capturing a bounded tail, then classify: OK (exit 0); BLOCKED (non-zero exit
 * AND a printed REFUSED line — a decision, `reason` = that verbatim line);
 * TRANSIENT (any other non-zero/signal/spawn failure, `reason` = a short note). */
static enum cold_start_result cold_start_spawn_classify(char *const child_argv[],
                                                        char *reason,
                                                        size_t reason_n)
{
    if (reason && reason_n)
        reason[0] = '\0';

    char exe[PATH_MAX];
    if (!cold_start_self_exe(exe, sizeof(exe))) {
        cold_start_reason_copy(reason, reason_n,
                               "cannot resolve own executable path");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: cannot resolve own executable path");
        return COLD_START_TRANSIENT;
    }

#ifdef _WIN32
#include "boot_cold_start_spawn_windows.inc"
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        cold_start_reason_copy(reason, reason_n, "stderr pipe creation failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: pipe failed: %s", strerror(errno));
        return COLD_START_TRANSIENT;
    }

    pid_t pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        cold_start_reason_copy(reason, reason_n, "fork failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: fork failed: %s", strerror(errno));
        return COLD_START_TRANSIENT;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        (void)close(pipefd[1]);
        execv(exe, child_argv);
        /* Only reached on exec failure — goes down the captured stderr. */
        fprintf(stderr, "cold_start: execv %s failed: %s\n", exe,
                strerror(errno));
        _exit(127);
    }

    (void)close(pipefd[1]);
    char tail[COLD_START_TAIL_CAP + 1];
    size_t tail_len = 0;
    char chunk[1024];
    for (;;) {
        ssize_t m = read(pipefd[0], chunk, sizeof(chunk));
        if (m < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (m == 0)
            break;
        /* Operator tee, discarded on purpose: the refusal/exit-code decision
         * below reads `tail`, never the terminal, so a dead stderr cannot
         * change it. The loop is the part that matters — an unlooped write(2)
         * short-writes the transcript the operator is reading. */
        (void)zcl_write_all(STDERR_FILENO, chunk, (size_t)m);
        cold_start_tail_append(tail, &tail_len, COLD_START_TAIL_CAP, chunk,
                               (size_t)m);
    }
    (void)close(pipefd[0]);
    tail[tail_len] = '\0';

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        cold_start_reason_copy(reason, reason_n, "waitpid failed");
        LOG_ERROR(COLD_START_SUBSYS, "spawn: waitpid failed: %s",
                  strerror(errno));
        return COLD_START_TRANSIENT;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return COLD_START_OK;

    /* Non-zero / abnormal: a printed REFUSED line makes it a decision. */
    char refusal[COLD_START_REASON_MAX];
    if (cold_start_extract_refusal(tail, refusal, sizeof(refusal))) {
        cold_start_reason_copy(reason, reason_n, refusal);
        return COLD_START_BLOCKED;
    }
    if (WIFEXITED(status)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "child exited with code %d",
                 WEXITSTATUS(status));
        cold_start_reason_copy(reason, reason_n, msg);
        LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    } else if (WIFSIGNALED(status)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "child killed by signal %d",
                 WTERMSIG(status));
        cold_start_reason_copy(reason, reason_n, msg);
        LOG_WARN(COLD_START_SUBSYS, "%s", msg);
    } else {
        cold_start_reason_copy(reason, reason_n, "child ended abnormally");
        LOG_WARN(COLD_START_SUBSYS, "child ended abnormally (status=0x%x)",
                 status);
    }
    return COLD_START_TRANSIENT;
#endif
}

/* Live stage runner: fork/exec the existing verb for each prep stage, classifying
 * the child's outcome. The BUNDLE stage dispatches the EXISTING
 * -install-consensus-bundle verb path unchanged (a black box to this driver). */
static enum cold_start_result cold_start_run_stage_live(
    const struct cold_start_plan *plan, enum cold_start_stage stage, void *user,
    char *reason, size_t reason_n)
{
    char exe[PATH_MAX];
    (void)user;
    if (!cold_start_self_exe(exe, sizeof(exe))) {
        cold_start_reason_copy(reason, reason_n, "cannot resolve executable");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: cannot resolve executable");
        return COLD_START_TRANSIENT;
    }

    char datadir_arg[PATH_MAX + 16];
    if (snprintf(datadir_arg, sizeof(datadir_arg), "-datadir=%s",
                 plan->datadir) >= (int)sizeof(datadir_arg)) {
        cold_start_reason_copy(reason, reason_n, "datadir path too long");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: datadir too long");
        return COLD_START_TRANSIENT;
    }

    switch (stage) {
    case COLD_START_STAGE_HEADERS: {
        /* --importblockindex MUST be argv[1] or it silently no-ops; we build
         * argv so it always is. Target db = <datadir>/node.db. */
        char db_path[PATH_MAX + 16];
        if (snprintf(db_path, sizeof(db_path), "%s/node.db", plan->datadir) >=
            (int)sizeof(db_path)) {
            cold_start_reason_copy(reason, reason_n, "node.db path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: node.db path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, (char *)"--importblockindex",
                         (char *)plan->header_source, db_path, NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_SEED: {
        /* Seed as a clean one-shot: -coldstart-seed-oneshot makes app_init apply
         * the seed then exit before services (engine/composition/src/boot.c). Headers are
         * already imported (previous stage), so the snapshot gate binds. */
        char seed_arg[PATH_MAX + 40];
        if (snprintf(seed_arg, sizeof(seed_arg),
                     "-load-snapshot-at-own-height=%s", plan->seed_snapshot) >=
            (int)sizeof(seed_arg)) {
            cold_start_reason_copy(reason, reason_n, "seed path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: seed path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, datadir_arg, seed_arg,
                         (char *)"-coldstart-seed-oneshot", NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_BUNDLE: {
        /* -install-consensus-bundle is terminal (installs then _exit()s). Runs
         * after the seed so the bundle installs onto the seeded datadir. Its
         * REFUSED lines are classified by cold_start_spawn_classify as a
         * decision (blocked, never auto-retried). */
        char bundle_arg[PATH_MAX + 40];
        if (snprintf(bundle_arg, sizeof(bundle_arg),
                     "-install-consensus-bundle=%s", plan->install_bundle) >=
            (int)sizeof(bundle_arg)) {
            cold_start_reason_copy(reason, reason_n, "bundle path too long");
            LOG_ERROR(COLD_START_SUBSYS, "run stage: bundle path too long");
            return COLD_START_TRANSIENT;
        }
        char *argv[] = { exe, datadir_arg, bundle_arg, NULL };
        return cold_start_spawn_classify(argv, reason, reason_n);
    }
    case COLD_START_STAGE_SERVE:
        cold_start_reason_copy(reason, reason_n, "SERVE is not a spawned stage");
        LOG_ERROR(COLD_START_SUBSYS, "run stage: SERVE is not a spawned prep "
                  "stage");
        return COLD_START_TRANSIENT;
    }
    cold_start_reason_copy(reason, reason_n, "unknown stage");
    LOG_ERROR(COLD_START_SUBSYS, "run stage: unknown stage %d", (int)stage);
    return COLD_START_TRANSIENT;
}

/* Exec a plain serving boot: the original argv minus the cold-start-only flags
 * (-cold-start, -cold-start-source=, -cold-start-seed=, -cold-start-bundle=) and
 * minus a raw -install-consensus-bundle= (defensive — the driver dispatches that
 * terminal verb itself via the BUNDLE stage; letting it reach the serving boot
 * would re-trigger a terminal install). Does not return on success. */
static int cold_start_exec_serve(int argc, char **argv)
{
    char exe[PATH_MAX];
    if (!cold_start_self_exe(exe, sizeof(exe)))
        LOG_ERR(COLD_START_SUBSYS, "serve: cannot resolve executable");

    char **serve_argv =
        zcl_malloc(((size_t)argc + 1) * sizeof(*serve_argv), "coldstart_serve_argv");
    if (!serve_argv)
        LOG_ERR(COLD_START_SUBSYS, "serve: argv alloc failed");
    int n = 0;
    serve_argv[n++] = exe;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cold-start") == 0 ||
            strncmp(argv[i], "-cold-start-source=", 19) == 0 ||
            strncmp(argv[i], "-cold-start-seed=", 17) == 0 ||
            strncmp(argv[i], "-cold-start-bundle=", 19) == 0 ||
            strncmp(argv[i], "-install-consensus-bundle=", 26) == 0)
            continue;
        serve_argv[n++] = argv[i];
    }
    serve_argv[n] = NULL;

    LOG_INFO(COLD_START_SUBSYS, "all prep stages complete — exec serving boot");
#ifdef _WIN32
    enum cold_start_result served =
        cold_start_spawn_classify(serve_argv, NULL, 0);
    free(serve_argv);
    return served == COLD_START_OK ? 0 : 1;
#else
    execv(exe, serve_argv);
    int e = errno;
    free(serve_argv);
    LOG_ERR(COLD_START_SUBSYS, "serve: execv failed: %s", strerror(e));
#endif
}

int boot_cold_start_run(int argc, char **argv)
{
    struct cold_start_plan plan = {0};
    plan.datadir = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-datadir=", 9) == 0)
            plan.datadir = argv[i] + 9;
        else if (strncmp(argv[i], "-cold-start-source=", 19) == 0)
            plan.header_source = argv[i] + 19;
        else if (strncmp(argv[i], "-cold-start-seed=", 17) == 0)
            plan.seed_snapshot = argv[i] + 17;
        else if (strncmp(argv[i], "-cold-start-bundle=", 19) == 0)
            plan.install_bundle = argv[i] + 19;
    }

    /* Default datadir mirrors the rest of the binary. */
    static char default_datadir[PATH_MAX];
    if (!plan.datadir || !plan.datadir[0]) {
        const char *home = getenv("HOME");
        if (snprintf(default_datadir, sizeof(default_datadir),
                     "%s/.zclassic-c23", home ? home : ".") >=
            (int)sizeof(default_datadir))
            LOG_ERR(COLD_START_SUBSYS, "default datadir path too long");
        plan.datadir = default_datadir;
    }

    /* Default header source: a co-located legacy zclassicd datadir with a block
     * index. Absent => skip the header stage and let the serving boot P2P-sync
     * headers. */
    static char default_source[PATH_MAX];
    if (!plan.header_source || !plan.header_source[0]) {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            char idx[PATH_MAX];
            if (snprintf(idx, sizeof(idx), "%s/.zclassic/blocks/index", home) <
                (int)sizeof(idx)) {
                struct platform_directory_list probe = {0};
                if (platform_directory_list_regular_sorted(idx, &probe)) {
                    platform_directory_list_free(&probe);
                    if (snprintf(default_source, sizeof(default_source),
                                 "%s/.zclassic", home) <
                        (int)sizeof(default_source))
                        plan.header_source = default_source;
                }
            }
        }
    }

    LOG_INFO(COLD_START_SUBSYS,
             "cold-start: datadir=%s source=%s seed=%s bundle=%s",
             plan.datadir,
             plan.header_source ? plan.header_source : "(P2P)",
             plan.seed_snapshot ? plan.seed_snapshot : "(none)",
             plan.install_bundle ? plan.install_bundle : "(none)");
    printf("=== ZClassic cold-start driver ===\n"
           "  datadir : %s\n"
           "  headers : %s\n"
           "  seed    : %s\n"
           "  bundle  : %s\n\n",
           plan.datadir,
           plan.header_source ? plan.header_source : "(P2P header sync)",
           plan.seed_snapshot ? plan.seed_snapshot : "(none)",
           plan.install_bundle ? plan.install_bundle : "(none)");

    enum cold_start_stage reached = COLD_START_STAGE_SERVE;
    char reason[COLD_START_REASON_MAX];
    reason[0] = '\0';
    enum cold_start_result rc =
        cold_start_drive(&plan, cold_start_run_stage_live, NULL, &reached,
                         reason, sizeof(reason));

    if (rc == COLD_START_BLOCKED) {
        /* A DECISION refusal — sticky, never auto-retried. The refusal receipt
         * under <datadir>/coldstart/ records the reason verbatim. */
        const char *stage = cold_start_stage_name(reached);
        printf("COLD-START: BLOCKED:%s:%s\n", stage, reason);
        fflush(stdout);
        LOG_ERROR(COLD_START_SUBSYS, "COLD-START: BLOCKED:%s:%s", stage, reason);
        fprintf(stderr,
                "cold-start: BLOCKED at stage '%s' by a decision refusal — NOT "
                "retried. Re-running the SAME -cold-start command stays blocked; "
                "resolve the cause and change/clear the bundle parameter, or "
                "remove %s/coldstart/%s.receipt to re-evaluate.\n",
                stage, plan.datadir, stage);
        return 2;
    }
    if (rc != COLD_START_OK) {
        /* Transient — resumable; a rerun continues at this same stage. */
        const char *stage = cold_start_stage_name(reached);
        printf("COLD-START: INCOMPLETE:%s:%s\n", stage, reason);
        fflush(stdout);
        LOG_WARN(COLD_START_SUBSYS, "COLD-START: INCOMPLETE:%s:%s", stage,
                 reason);
        fprintf(stderr,
                "cold-start: stopped at stage '%s' (transient). Fix the cause "
                "and re-run the SAME -cold-start command; completed stages are "
                "skipped via their receipts under %s/coldstart/.\n",
                stage, plan.datadir);
        return 1;
    }

    /* Every configured prep stage is receipted — announce completion, then
     * become the serving node. */
    printf("COLD-START: COMPLETE\n");
    fflush(stdout);
    LOG_INFO(COLD_START_SUBSYS, "COLD-START: COMPLETE");
    return cold_start_exec_serve(argc, argv);
}
