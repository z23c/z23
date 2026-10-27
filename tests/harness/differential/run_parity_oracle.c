/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * run_parity_oracle - Sapling Groth16 differential parity oracle, build + replay.
 *
 *   run_parity_oracle check    (default) rebuild verifier + assert every
 *                              verdict matches the frozen golden AND every
 *                              pairing Fp12 matches the frozen values.
 *                              Exit status is non-zero on ANY mismatch (a
 *                              consensus-affecting change).
 *   run_parity_oracle record   re-freeze the golden + the pairing values from
 *                              the CURRENT verifier (only after an INTENTIONAL,
 *                              replay-approved consensus change - never to
 *                              paper over a diff).
 *   run_parity_oracle list     print the vector manifest.
 *   run_parity_oracle bench [n]
 *                              time naive vs fixed-base public-input paths
 *                              over n iterations (default 30).
 *   run_parity_oracle pairing [n]
 *                              differential the PAIRING itself: baseline vs
 *                              bls12_381_pairing_candidate, asserting Fp12 BIT
 *                              equality on every vector.
 *   run_parity_oracle profile [n]
 *                              exact Fp-multiply counts per phase plus
 *                              per-phase wall time. Builds TWICE: once
 *                              linker-interposed for exact counts, once clean
 *                              for absolute times.
 *
 * Builds the CURRENT in-tree consensus verifier
 * (core/modules/sapling/src/bls12_381.c) from source on every run. Temporary
 * binaries live under $TMPDIR (default P_tmpdir) and are removed on exit, SIGINT,
 * SIGTERM and SIGHUP. Compiled with -DPARITY_DIR="<absolute differential dir>".
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PARITY_DIR
#error "compile with -DPARITY_DIR=\"<absolute path of tests/harness/differential>\""
#endif

#define ARGV_MAX 48
#define PATH_BUF (PATH_MAX + 64)

enum { SIGNAL_COUNT = 3 };
static const int k_signals[SIGNAL_COUNT] = {SIGINT, SIGTERM, SIGHUP};

static char g_bin[PATH_BUF];
static char g_binc[PATH_BUF];
static volatile sig_atomic_t g_cleaned;
static volatile sig_atomic_t g_sig;

static void po_signal_mask(int how)
{
    sigset_t set;
    sigemptyset(&set);
    for (int i = 0; i < SIGNAL_COUNT; i++) sigaddset(&set, k_signals[i]);
    sigprocmask(how, &set, nullptr);
}

/* Removes both temporary binaries exactly once, with the termination signals
 * blocked. */
static void po_cleanup(void)
{
    po_signal_mask(SIG_BLOCK);
    if (g_cleaned) return;
    g_cleaned = 1;
    if (g_bin[0]) unlink(g_bin);
    if (g_binc[0]) unlink(g_binc);
}

/* The handler only records the signal; the main path acts on it. */
static void po_on_signal(int sig)
{
    g_sig = (sig_atomic_t)sig;
}

static void po_on_child(int sig)
{
    (void)sig;
}

static void po_install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = po_on_signal;
    sa.sa_flags = SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < SIGNAL_COUNT; i++) sigaction(k_signals[i], &sa, nullptr);
    sa.sa_handler = po_on_child;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, nullptr);
}

/* Delivers any pending termination signal to the handler. */
static void po_poll_signals(void)
{
    po_signal_mask(SIG_UNBLOCK);
    po_signal_mask(SIG_BLOCK);
}

static void po_child_exec(char *const argv[])
{
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    for (int i = 0; i < SIGNAL_COUNT; i++) sigaction(k_signals[i], &dfl, nullptr);
    po_signal_mask(SIG_UNBLOCK);
    execvp(argv[0], argv);
    _exit(127);
}

/* Waits for pid; a recorded signal is forwarded to it once. Signals are
 * delivered only inside sigsuspend. */
static int po_reap(pid_t pid)
{
    sigset_t chld, open;
    int st = 0;
    bool forwarded = false;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigemptyset(&open);
    sigprocmask(SIG_BLOCK, &chld, nullptr);
    while (waitpid(pid, &st, WNOHANG) != pid) {
        if (g_sig && !forwarded) {
            kill(pid, g_sig);
            forwarded = true;
        }
        sigsuspend(&open);
    }
    sigprocmask(SIG_UNBLOCK, &chld, nullptr);
    return st;
}

/* Runs argv with inherited stdio; returns the shell-style status (exit code,
 * or 128+signal when the child was killed). Termination signals stay blocked
 * across fork; the child resets them to SIG_DFL before exec. */
static int po_run(char *const argv[])
{
    po_poll_signals();
    if (g_sig) return 128 + g_sig;
    pid_t pid = fork();
    if (pid < 0) {
        perror("run_parity_oracle: fork");
        return 126;
    }
    if (pid == 0) po_child_exec(argv);
    int st = po_reap(pid);
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 1;
}

struct po_argvec {
    char *v[ARGV_MAX];
    int n;
    int overflow;
};

static void po_push(struct po_argvec *a, const char *s)
{
    if (a->n >= ARGV_MAX - 1) { a->overflow = 1; return; }
    a->v[a->n++] = (char *)s;
}

static int po_fmt(char *dst, size_t cap, const char *f, const char *a, const char *b)
{
    int n = snprintf(dst, cap, f, a, b);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

struct po_paths {
    char here[PATH_BUF];
    char inc_here[PATH_BUF];
    char inc[4][PATH_BUF];
    char src[6][PATH_BUF];
    char main_src[PATH_BUF];
};

static const char *const k_incs[4] = {
    "core/modules/sapling/include", "core/modules/crypto/include",
    "platform/modules/util/include", "platform/modules/base/include"};
static const char *const k_srcs[6] = {
    "core/modules/sapling/src/bls12_381.c", "core/modules/sapling/src/fr_avx512.c",
    "core/modules/crypto/src/blake2b.c", "core/modules/crypto/src/simd_dispatch.c",
    "platform/modules/base/src/safe_alloc.c",
    "platform/modules/base/src/log_level.c"};

static int po_make_paths(struct po_paths *p, const char *mode)
{
    static const char root[] = PARITY_DIR "/../../..";
    int bad = po_fmt(p->here, sizeof p->here, "%s%s", PARITY_DIR, "");
    bad |= po_fmt(p->inc_here, sizeof p->inc_here, "-I%s%s", PARITY_DIR, "");
    bool counted_main = !strcmp(mode, "bench") || !strcmp(mode, "pairing") ||
                        !strcmp(mode, "profile");
    bad |= po_fmt(p->main_src, sizeof p->main_src, "%s/%s", PARITY_DIR,
               counted_main ? "groth16_comb_bench.c" : "groth16_parity_oracle.c");
    for (int i = 0; i < 4; i++) bad |= po_fmt(p->inc[i], sizeof p->inc[i], "-I%s/%s", root, k_incs[i]);
    for (int i = 0; i < 6; i++) bad |= po_fmt(p->src[i], sizeof p->src[i], "%s/%s", root, k_srcs[i]);
    return bad;
}

static void po_compile_argv(struct po_argvec *a, const struct po_paths *p, const char *out, bool counted)
{
    static const char *const flags[] = {
        "cc", "-std=c23", "-O2",
#if !defined(__APPLE__) && (defined(__x86_64__) || defined(_M_X64))
        /* Match the shipped x86 baseline; Darwin uses its portable target. */
        "-march=x86-64-v3",
#endif
        "-DZCL_TESTING",
#if defined(__APPLE__)
        /* Permit only the corpus header's explicitly optional weak import. */
        "-Wl,-U,_bls12_381_pairing_candidate",
#endif
        "-D_POSIX_C_SOURCE=200809L", "-D_DEFAULT_SOURCE"};
    for (size_t i = 0; i < sizeof flags / sizeof *flags; i++) po_push(a, flags[i]);
    po_push(a, p->inc_here);
    for (int i = 0; i < 4; i++) po_push(a, p->inc[i]);
    if (counted) {
        po_push(a, "-DZCL_FPMUL_COUNT");
        po_push(a, "-Wl,--wrap=fp_mont_mul_accel");
    }
    po_push(a, p->main_src);
    for (int i = 0; i < 6; i++) po_push(a, p->src[i]);
    po_push(a, "-o");
    po_push(a, out);
    a->v[a->n] = nullptr;
}

static int po_compile(const struct po_paths *p, const char *out, bool counted)
{
    struct po_argvec a = {.n = 0, .overflow = 0};
    po_compile_argv(&a, p, out, counted);
    if (a.overflow) return 126;
    return po_run(a.v);
}

static int po_exec_oracle(const char *bin, const char *a1, const char *a2)
{
    char *argv[] = {(char *)bin, (char *)a1, (char *)a2, nullptr};
    return po_run(argv);
}

static int po_run_profile(const struct po_paths *p, const char *n)
{
    puts("=== profile pass 1/2: uninstrumented (absolute times) ===");
    fflush(stdout);
    int rc = po_exec_oracle(g_bin, "profile", n);
    if (rc != 0) return rc;
    puts("\n=== profile pass 2/2: instrumented (exact Fp-multiply counts) ===");
    fflush(stdout);
    rc = po_compile(p, g_binc, true);
    return rc != 0 ? rc : po_exec_oracle(g_binc, "profile", n);
}

static int po_dispatch(const struct po_paths *p, const char *mode, const char *n)
{
    if (!strcmp(mode, "bench")) return po_exec_oracle(g_bin, "comb", n);
    if (!strcmp(mode, "pairing")) return po_exec_oracle(g_bin, "pairing", n);
    if (!strcmp(mode, "profile")) return po_run_profile(p, n);
    return po_exec_oracle(g_bin, mode, p->here);
}

static int po_temp_names(void)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = P_tmpdir;
    long pid = (long)getpid();
    int a = snprintf(g_bin, sizeof g_bin, "%s/g16_parity_oracle.%ld", tmp, pid);
    int b = snprintf(g_binc, sizeof g_binc, "%s/g16_parity_oracle_counted.%ld", tmp, pid);
    return a > 0 && b > 0 && (size_t)a < sizeof g_bin && (size_t)b < sizeof g_binc ? 0 : -1;
}

static const char *po_arg_or(int argc, char **argv, int i, const char *dflt)
{
    return (i < argc && argv[i][0]) ? argv[i] : dflt;
}

/* Removes the temporaries; a recorded signal is re-raised with its default
 * action so the caller sees the signal status. */
static int po_finish(int rc)
{
    po_poll_signals();
    int sig = g_sig;
    po_cleanup();
    if (!sig) return rc;
    signal(sig, SIG_DFL);
    po_signal_mask(SIG_UNBLOCK);
    raise(sig);
    return 128 + sig;
}

int main(int argc, char **argv)
{
    const char *mode = po_arg_or(argc, argv, 1, "check");
    const char *n = po_arg_or(argc, argv, 2, "30");
    struct po_paths p;
    if (po_make_paths(&p, mode) != 0 || po_temp_names() != 0) {
        fprintf(stderr, "run_parity_oracle: path too long\n");
        return 2;
    }
    po_install_handlers();
    po_signal_mask(SIG_BLOCK);
    int rc = po_compile(&p, g_bin, false);
    if (rc == 0) rc = po_dispatch(&p, mode, n);
    return po_finish(rc);
}
